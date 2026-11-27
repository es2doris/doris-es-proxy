// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const taskLocalNodeID = "doris-fe-1"

type taskEntryContextKey struct{}

type taskEntry struct {
	id           int64
	fullID       string
	node         string
	taskType     string
	action       string
	description  string
	startTime    time.Time
	startTimeMs  int64
	cancellable  bool
	parentTaskID string
	headers      map[string]string

	mu               sync.Mutex
	completed        bool
	cancelled        bool
	endTime          time.Time
	requestsPerSec   float64
	total            int
	updated          int
	created          int
	deleted          int
	batches          int
	versionConflicts int
	noops            int
	throttledMillis  int64
	response         map[string]any
	errObj           map[string]any
	slices           []any
	activeWaiters    int
	cancelFn         context.CancelFunc
	rethrottleCh     chan struct{}
	rethrottleNotify chan struct{}
	doneCh           chan struct{}
}

func (t *taskEntry) notifyRethrottle(newRPS float64) {
	t.mu.Lock()
	t.requestsPerSec = newRPS
	ch := t.rethrottleCh
	nch := t.rethrottleNotify
	nextCh := make(chan struct{})
	t.rethrottleCh = nextCh
	t.rethrottleNotify = nextCh
	t.mu.Unlock()
	if ch != nil {
		close(ch)
	} else if nch != nil {
		close(nch)
	}
}

func (t *taskEntry) cancel() bool {
	t.mu.Lock()
	if t.completed {
		t.mu.Unlock()
		return false
	}
	alreadyCancelled := t.cancelled
	t.cancelled = true
	cancelFn := t.cancelFn
	t.mu.Unlock()
	if cancelFn != nil {
		cancelFn()
	}
	return !alreadyCancelled
}

func (t *taskEntry) markDone(resp map[string]any, errObj map[string]any) {
	t.mu.Lock()
	if t.completed {
		t.mu.Unlock()
		return
	}
	t.completed = true
	t.endTime = time.Now()
	if resp != nil {
		t.response = resp
		if v, ok := toInt64(resp["total"]); ok {
			t.total = int(v)
		}
		if v, ok := toInt64(resp["updated"]); ok {
			t.updated = int(v)
		}
		if v, ok := toInt64(resp["created"]); ok {
			t.created = int(v)
		}
		if v, ok := toInt64(resp["deleted"]); ok {
			t.deleted = int(v)
		}
		if v, ok := toInt64(resp["batches"]); ok {
			t.batches = int(v)
		}
		if v, ok := toInt64(resp["version_conflicts"]); ok {
			t.versionConflicts = int(v)
		}
		if v, ok := toInt64(resp["noops"]); ok {
			t.noops = int(v)
		}
	}
	if errObj != nil {
		t.errObj = errObj
	}
	doneCh := t.doneCh
	t.mu.Unlock()
	close(doneCh)
}

func (t *taskEntry) toTaskInfoMap(detailed bool) map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()

	endRef := time.Now()
	if t.completed && !t.endTime.IsZero() {
		endRef = t.endTime
	}
	runNanos := endRef.Sub(t.startTime).Nanoseconds()
	if runNanos < 1000 {
		runNanos = 1000
	}
	hdrs := make(map[string]string, len(t.headers))
	for k, v := range t.headers {
		hdrs[k] = v
	}
	m := map[string]any{
		"node":                  t.node,
		"id":                    t.id,
		"type":                  t.taskType,
		"action":                t.action,
		"start_time_in_millis":  t.startTimeMs,
		"running_time_in_nanos": runNanos,
		"cancellable":           t.cancellable,
		"cancelled":             t.cancelled,
		"headers":               hdrs,
	}
	if t.parentTaskID != "" {
		m["parent_task_id"] = t.parentTaskID
	}
	if detailed {
		m["description"] = t.description
		statusMap := map[string]any{
			"total":                  t.total,
			"updated":                t.updated,
			"created":                t.created,
			"deleted":                t.deleted,
			"batches":                t.batches,
			"version_conflicts":      t.versionConflicts,
			"noops":                  t.noops,
			"retries":                map[string]any{"bulk": 0, "search": 0},
			"throttled_millis":       t.throttledMillis,
			"requests_per_second":    t.requestsPerSec,
			"throttled_until_millis": 0,
			"canceled":               boolReasonString(t.cancelled),
		}
		if len(t.slices) > 0 {
			cp := make([]any, len(t.slices))
			copy(cp, t.slices)
			statusMap["slices"] = cp
		}
		m["status"] = statusMap
	}
	return m
}

func boolReasonString(cancelled bool) string {
	if cancelled {
		return "by user request"
	}
	return ""
}

const (
	maxCompletedTasks = 4096
	completedTaskTTL  = 30 * time.Minute
)

type taskRegistry struct {
	mu     sync.RWMutex
	nextID atomic.Int64
	tasks  map[string]*taskEntry
}

func newTaskRegistry() *taskRegistry {
	tr := &taskRegistry{
		tasks: make(map[string]*taskEntry),
	}
	tr.nextID.Store(100)
	return tr
}

func (s *Server) getTaskRegistry() *taskRegistry {
	s.mu.RLock()
	tr := s.taskReg
	s.mu.RUnlock()
	if tr != nil {
		return tr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taskReg == nil {
		s.taskReg = newTaskRegistry()
	}
	return s.taskReg
}

func (tr *taskRegistry) evictCompletedLocked(now time.Time) {
	type completedCandidate struct {
		fullID  string
		endTime time.Time
		id      int64
	}
	var keep []completedCandidate
	for fullID, e := range tr.tasks {
		e.mu.Lock()
		done := e.completed
		waiters := e.activeWaiters
		endT := e.endTime
		id := e.id
		e.mu.Unlock()
		if !done || waiters > 0 {
			continue
		}
		if !endT.IsZero() && now.Sub(endT) > completedTaskTTL {
			delete(tr.tasks, fullID)
			continue
		}
		keep = append(keep, completedCandidate{fullID: fullID, endTime: endT, id: id})
	}
	if len(keep) > maxCompletedTasks {
		sort.Slice(keep, func(i, j int) bool {
			if keep[i].endTime.Equal(keep[j].endTime) {
				return keep[i].id < keep[j].id
			}
			return keep[i].endTime.Before(keep[j].endTime)
		})
		excess := len(keep) - maxCompletedTasks
		for i := 0; i < excess; i++ {
			delete(tr.tasks, keep[i].fullID)
		}
	}
}

func (tr *taskRegistry) pruneCompletedTasks() {
	tr.mu.Lock()
	tr.evictCompletedLocked(time.Now())
	tr.mu.Unlock()
}

func (tr *taskRegistry) unregisterSyncCompleted(fullID string) {
	tr.mu.Lock()
	if e, ok := tr.tasks[fullID]; ok {
		e.mu.Lock()
		waiters := e.activeWaiters
		e.mu.Unlock()
		if waiters == 0 {
			delete(tr.tasks, fullID)
		}
	}
	tr.mu.Unlock()
}

func (tr *taskRegistry) register(action, description string, rps float64, headers map[string]string, cancelFn context.CancelFunc) *taskEntry {
	id := tr.nextID.Add(1)
	now := time.Now()
	fullID := fmt.Sprintf("%s:%d", taskLocalNodeID, id)
	rch := make(chan struct{})
	entry := &taskEntry{
		id:               id,
		fullID:           fullID,
		node:             taskLocalNodeID,
		taskType:         "transport",
		action:           action,
		description:      description,
		startTime:        now,
		startTimeMs:      now.UnixMilli(),
		cancellable:      true,
		headers:          headers,
		requestsPerSec:   rps,
		cancelFn:         cancelFn,
		rethrottleCh:     rch,
		rethrottleNotify: rch,
		doneCh:           make(chan struct{}),
	}
	tr.mu.Lock()
	tr.evictCompletedLocked(now)
	tr.tasks[fullID] = entry
	tr.mu.Unlock()
	return entry
}

func (tr *taskRegistry) lookup(taskID string) (*taskEntry, bool) {
	now := time.Now()
	tr.mu.RLock()
	e, ok := tr.tasks[taskID]
	tr.mu.RUnlock()
	if !ok {
		return nil, false
	}
	e.mu.Lock()
	expired := e.completed && e.activeWaiters == 0 && !e.endTime.IsZero() && now.Sub(e.endTime) > completedTaskTTL
	e.mu.Unlock()
	if expired {
		tr.mu.Lock()
		tr.evictCompletedLocked(now)
		tr.mu.Unlock()
		return nil, false
	}
	return e, true
}

func (tr *taskRegistry) activeEntries() []*taskEntry {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	out := make([]*taskEntry, 0, len(tr.tasks))
	for _, e := range tr.tasks {
		e.mu.Lock()
		done := e.completed
		e.mu.Unlock()
		if !done {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].id < out[j].id
	})
	return out
}

func taskFromContextRound60(ctx context.Context) *taskEntry {
	if ctx == nil {
		return nil
	}
	e, _ := ctx.Value(taskEntryContextKey{}).(*taskEntry)
	return e
}

// applyTaskThrottleAndProgressRound60 updates progress counters and enforces dynamic requests_per_second throttling.
func applyTaskThrottleAndProgressRound60(ctx context.Context, batchDocs int, rpsFallback float64) error {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	entry := taskFromContextRound60(ctx)
	if entry == nil {
		return nil
	}
	entry.mu.Lock()
	entry.batches++
	entry.mu.Unlock()

	var alreadySlept time.Duration
	for {
		entry.mu.Lock()
		rps := entry.requestsPerSec
		rethrottleCh := entry.rethrottleCh
		entry.mu.Unlock()
		if rps == 0 {
			rps = rpsFallback
		}
		if rps <= 0 || batchDocs <= 0 {
			return nil
		}
		secNeeded := float64(batchDocs) / rps
		if secNeeded <= 0 {
			return nil
		}
		if secNeeded > 30 {
			secNeeded = 30
		}
		neededDur := time.Duration(secNeeded * float64(time.Second))
		waitDur := neededDur - alreadySlept
		if waitDur <= 0 {
			return nil
		}
		waitStart := time.Now()
		timer := time.NewTimer(waitDur)
		select {
		case <-ctx.Done():
			timer.Stop()
			slept := time.Since(waitStart)
			entry.mu.Lock()
			entry.throttledMillis += slept.Milliseconds()
			entry.mu.Unlock()
			return ctx.Err()
		case <-rethrottleCh:
			timer.Stop()
			slept := time.Since(waitStart)
			alreadySlept += slept
			entry.mu.Lock()
			entry.throttledMillis += slept.Milliseconds()
			newRPS := entry.requestsPerSec
			entry.mu.Unlock()
			if newRPS <= 0 {
				return nil
			}
			// Recompute remaining sleep under updated requests_per_second.
			continue
		case <-timer.C:
			entry.mu.Lock()
			entry.throttledMillis += waitDur.Milliseconds()
			entry.mu.Unlock()
			return nil
		}
	}
}

func parseTaskIDComponents(taskID string) (string, int64, bool) {
	taskID = strings.TrimSpace(taskID)
	colonIdx := strings.IndexByte(taskID, ':')
	if colonIdx <= 0 || colonIdx == len(taskID)-1 {
		return "", 0, false
	}
	nodeID := taskID[:colonIdx]
	numID, err := strconv.ParseInt(taskID[colonIdx+1:], 10, 64)
	if err != nil || numID < 0 {
		return "", 0, false
	}
	return nodeID, numID, true
}

func isKnownLocalTaskNode(nodeID string) bool {
	switch nodeID {
	case taskLocalNodeID, "doris-node-1", "local-node-1":
		return true
	default:
		return false
	}
}

func matchesNodeFilterList(rawNodes string) bool {
	rawNodes = strings.TrimSpace(rawNodes)
	if rawNodes == "" || rawNodes == "*" || rawNodes == "_all" {
		return true
	}
	for _, tok := range strings.Split(rawNodes, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if tok == "_local" || tok == "_master" || tok == "master:true" || tok == "data:true" || tok == "ingest:true" {
			return true
		}
		if matchWildcardPattern(tok, taskLocalNodeID) || matchWildcardPattern(tok, "doris-node-1") || matchWildcardPattern(tok, "127.0.0.1") {
			return true
		}
	}
	return false
}

func matchesTaskActionFilter(action, rawActions string) bool {
	rawActions = strings.TrimSpace(rawActions)
	if rawActions == "" || rawActions == "*" {
		return true
	}
	return matchMultiWildcardWithExclusions(rawActions, action)
}

func extractTaskHeadersFromRequest(r *http.Request) map[string]string {
	hdrs := map[string]string{}
	if r != nil {
		if opaque := r.Header.Get("X-Opaque-Id"); opaque != "" {
			hdrs["X-Opaque-Id"] = opaque
		}
	}
	return hdrs
}

func buildLocalTaskNodeEnvelope(tasksMap map[string]any) map[string]any {
	return map[string]any{
		"name":              taskLocalNodeID,
		"transport_address": "127.0.0.1:9300",
		"host":              "127.0.0.1",
		"ip":                "127.0.0.1:9300",
		"roles":             []string{"data", "ingest", "master"},
		"attributes": map[string]any{
			"ml.machine_memory": "8589934592",
			"xpack.installed":   "true",
		},
		"tasks": tasksMap,
	}
}

func (s *Server) handleTasksList(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	groupBy := "nodes"
	detailed := false
	waitForCompletion := false
	timeoutDur := 30 * time.Second
	var rawNodes, rawActions, rawParent string

	if r != nil && r.URL != nil {
		q := r.URL.Query()
		if gb := strings.TrimSpace(q.Get("group_by")); gb != "" {
			switch strings.ToLower(gb) {
			case "nodes", "none", "parents":
				groupBy = strings.ToLower(gb)
			default:
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("group_by must be one of [nodes, none, parents] but was [%s]", gb))
				return
			}
		}
		if dv, present, err := parseStrictQueryBoolParamRound59(r, "detailed"); present {
			if err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
				return
			}
			detailed = dv
		}
		if wv, present, err := parseStrictQueryBoolParamRound59(r, "wait_for_completion"); present {
			if err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
				return
			}
			waitForCompletion = wv
		}
		if rawTO := strings.TrimSpace(q.Get("timeout")); rawTO != "" {
			dur, err := parseESPositiveDuration(rawTO)
			if err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("failed to parse setting [timeout] with value [%s]", rawTO))
				return
			}
			timeoutDur = dur
		}
		rawNodes = q.Get("nodes")
		rawActions = q.Get("actions")
		rawParent = strings.TrimSpace(q.Get("parent_task_id"))
		if rawParent != "" && rawParent != "-" && rawParent != "none" {
			if _, _, ok := parseTaskIDComponents(rawParent); !ok {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("malformed task id %s", rawParent))
				return
			}
		}
	}

	reg := s.getTaskRegistry()
	if waitForCompletion {
		deadline := time.Now().Add(timeoutDur)
		for _, e := range reg.activeEntries() {
			if !matchesTaskActionFilter(e.action, rawActions) {
				continue
			}
			rem := time.Until(deadline)
			if rem <= 0 {
				break
			}
			timer := time.NewTimer(rem)
			select {
			case <-e.doneCh:
				timer.Stop()
			case <-timer.C:
			}
		}
	}

	var matchedMaps []map[string]any
	var matchedIDs []string
	if matchesNodeFilterList(rawNodes) {
		nowMs := time.Now().UnixMilli()
		selfTask := map[string]any{
			"node":                  taskLocalNodeID,
			"id":                    int64(1),
			"type":                  "transport",
			"action":                "cluster:monitor/tasks/lists",
			"start_time_in_millis":  nowMs,
			"running_time_in_nanos": int64(1000),
			"cancellable":           false,
			"headers":               extractTaskHeadersFromRequest(r),
		}
		if detailed {
			selfTask["description"] = ""
		}
		if matchesTaskActionFilter("cluster:monitor/tasks/lists", rawActions) && (rawParent == "" || rawParent == "-" || rawParent == "none") {
			matchedMaps = append(matchedMaps, selfTask)
			matchedIDs = append(matchedIDs, taskLocalNodeID+":1")
		}
		for _, e := range reg.activeEntries() {
			if !matchesTaskActionFilter(e.action, rawActions) {
				continue
			}
			if rawParent != "" {
				if (rawParent == "-" || rawParent == "none") && e.parentTaskID != "" {
					continue
				}
				if rawParent != "-" && rawParent != "none" && e.parentTaskID != rawParent {
					continue
				}
			}
			matchedMaps = append(matchedMaps, e.toTaskInfoMap(detailed))
			matchedIDs = append(matchedIDs, e.fullID)
		}
	}

	switch groupBy {
	case "none":
		outList := make([]any, 0, len(matchedMaps))
		for _, tm := range matchedMaps {
			outList = append(outList, tm)
		}
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"tasks": outList,
		})
	case "parents":
		tasksObj := make(map[string]any, len(matchedMaps))
		for i, tm := range matchedMaps {
			cp := deepCloneDocMap(tm)
			cp["children"] = []any{}
			tasksObj[matchedIDs[i]] = cp
		}
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"tasks": tasksObj,
		})
	default:
		nodesObj := map[string]any{}
		if len(matchedMaps) > 0 {
			tasksObj := make(map[string]any, len(matchedMaps))
			for i, tm := range matchedMaps {
				tasksObj[matchedIDs[i]] = tm
			}
			nodesObj[taskLocalNodeID] = buildLocalTaskNodeEnvelope(tasksObj)
		}
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"nodes": nodesObj,
		})
	}
}

func (s *Server) handleTasksGet(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	taskID := strings.TrimSpace(r.PathValue("task_id"))
	nodeID, _, ok := parseTaskIDComponents(taskID)
	if !ok {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("malformed task id %s", taskID))
		return
	}
	waitForCompletion := false
	timeoutDur := 30 * time.Second
	if r != nil && r.URL != nil {
		if wv, present, err := parseStrictQueryBoolParamRound59(r, "wait_for_completion"); present {
			if err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
				return
			}
			waitForCompletion = wv
		}
		if rawTO := strings.TrimSpace(r.URL.Query().Get("timeout")); rawTO != "" {
			dur, err := parseESPositiveDuration(rawTO)
			if err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("failed to parse setting [timeout] with value [%s]", rawTO))
				return
			}
			timeoutDur = dur
		}
	}

	entry, found := s.getTaskRegistry().lookup(taskID)
	if !found {
		if !isKnownLocalTaskNode(nodeID) {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("task [%s] belongs to the node [%s] which isn't part of the cluster and there is no record of the task", taskID, nodeID))
			return
		}
		writeESError(w, http.StatusNotFound, "resource_not_found_exception",
			fmt.Sprintf("task [%s] isn't running and hasn't stored its results", taskID))
		return
	}

	if waitForCompletion {
		entry.mu.Lock()
		entry.activeWaiters++
		entry.mu.Unlock()
		timer := time.NewTimer(timeoutDur)
		select {
		case <-entry.doneCh:
			timer.Stop()
		case <-timer.C:
		}
		entry.mu.Lock()
		entry.activeWaiters--
		entry.mu.Unlock()
	}

	entry.mu.Lock()
	completed := entry.completed
	respCopy := deepCloneDocMap(entry.response)
	errCopy := deepCloneDocMap(entry.errObj)
	entry.mu.Unlock()

	out := map[string]any{
		"completed": completed,
		"task":      entry.toTaskInfoMap(true),
	}
	if completed {
		if errCopy != nil {
			out["error"] = errCopy
		}
		if respCopy != nil {
			out["response"] = respCopy
		}
	}
	writeJSONWithRequest(w, r, http.StatusOK, out)
}

func (s *Server) handleTasksCancel(w http.ResponseWriter, r *http.Request) {
	if r != nil && r.Method != "" && r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	waitForCompletion := false
	if r != nil {
		if wv, present, err := parseStrictQueryBoolParamRound59(r, "wait_for_completion"); present {
			if err != nil {
				writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
				return
			}
			waitForCompletion = wv
		}
	}

	reg := s.getTaskRegistry()
	if taskID := strings.TrimSpace(r.PathValue("task_id")); taskID != "" {
		nodeID, _, ok := parseTaskIDComponents(taskID)
		if !ok {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("malformed task id %s", taskID))
			return
		}
		entry, found := reg.lookup(taskID)
		if !found {
			if !isKnownLocalTaskNode(nodeID) {
				writeESError(w, http.StatusNotFound, "resource_not_found_exception",
					fmt.Sprintf("task [%s] belongs to the node [%s] which isn't part of the cluster", taskID, nodeID))
				return
			}
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("task [%s] isn't running", taskID))
			return
		}
		entry.cancel()
		if waitForCompletion {
			<-entry.doneCh
		}
		tasksObj := map[string]any{
			entry.fullID: entry.toTaskInfoMap(true),
		}
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"nodes": map[string]any{
				taskLocalNodeID: buildLocalTaskNodeEnvelope(tasksObj),
			},
		})
		return
	}

	rawNodes := ""
	rawActions := ""
	if r != nil && r.URL != nil {
		rawNodes = r.URL.Query().Get("nodes")
		rawActions = r.URL.Query().Get("actions")
	}
	cancelledMap := map[string]any{}
	if matchesNodeFilterList(rawNodes) {
		for _, e := range reg.activeEntries() {
			if !e.cancellable || !matchesTaskActionFilter(e.action, rawActions) {
				continue
			}
			e.cancel()
			if waitForCompletion {
				<-e.doneCh
			}
			cancelledMap[e.fullID] = e.toTaskInfoMap(true)
		}
	}
	nodesOut := map[string]any{}
	if len(cancelledMap) > 0 {
		nodesOut[taskLocalNodeID] = buildLocalTaskNodeEnvelope(cancelledMap)
	}
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"nodes": nodesOut,
	})
}

func parseStrictRequestsPerSecondRound60(raw any, hasVal bool) (float64, error) {
	if !hasVal || raw == nil {
		return -1, nil
	}
	switch v := raw.(type) {
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return -1, fmt.Errorf("requests_per_second cannot be empty")
		}
		if strings.EqualFold(s, "unlimited") || strings.EqualFold(s, "infinity") {
			return -1, nil
		}
		fv, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
			return 0, fmt.Errorf("failed to parse [requests_per_second] value [%s]", s)
		}
		if fv == -1 {
			return -1, nil
		}
		if fv <= 0 {
			return 0, fmt.Errorf("requests_per_second must be -1 or positive, got [%s]", s)
		}
		return fv, nil
	case json.Number:
		fv, err := v.Float64()
		if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
			return 0, fmt.Errorf("failed to parse [requests_per_second] value [%s]", v.String())
		}
		if fv == -1 {
			return -1, nil
		}
		if fv <= 0 {
			return 0, fmt.Errorf("requests_per_second must be -1 or positive, got [%s]", v.String())
		}
		return fv, nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, fmt.Errorf("invalid [requests_per_second] value [%v]", v)
		}
		if v == -1 {
			return -1, nil
		}
		if v <= 0 {
			return 0, fmt.Errorf("requests_per_second must be -1 or positive, got [%v]", v)
		}
		return v, nil
	case int:
		if v == -1 {
			return -1, nil
		}
		if v <= 0 {
			return 0, fmt.Errorf("requests_per_second must be -1 or positive, got [%d]", v)
		}
		return float64(v), nil
	case int64:
		if v == -1 {
			return -1, nil
		}
		if v <= 0 {
			return 0, fmt.Errorf("requests_per_second must be -1 or positive, got [%d]", v)
		}
		return float64(v), nil
	default:
		return 0, fmt.Errorf("failed to parse [requests_per_second] value [%v]", raw)
	}
}

func (s *Server) handleTaskRethrottleRound60(w http.ResponseWriter, r *http.Request, rawIndex, taskID string) {
	if r.Method != http.MethodPost {
		writeESError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "unsupported method ["+r.Method+"]")
		return
	}
	nodeID, _, ok := parseTaskIDComponents(taskID)
	if !ok {
		writeESError(w, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("malformed task id [%s]", taskID))
		return
	}
	rps := float64(-1)
	if r.URL != nil && r.URL.Query().Has("requests_per_second") {
		parsed, err := parseStrictRequestsPerSecondRound60(r.URL.Query().Get("requests_per_second"), true)
		if err != nil {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception", err.Error())
			return
		}
		rps = parsed
	}
	if rawIndex != "" && rawIndex != "*" && rawIndex != "_all" {
		if _, okIdx := s.resolveMaintenanceTargetIndices(w, rawIndex); !okIdx {
			return
		}
	}
	entry, found := s.getTaskRegistry().lookup(strings.TrimSpace(taskID))
	if !found {
		if !isKnownLocalTaskNode(nodeID) {
			writeESError(w, http.StatusNotFound, "resource_not_found_exception",
				fmt.Sprintf("task [%s] belongs to the node [%s] which isn't part of the cluster", taskID, nodeID))
			return
		}
		writeESError(w, http.StatusNotFound, "resource_not_found_exception",
			fmt.Sprintf("task [%s] isn't running", taskID))
		return
	}
	entry.notifyRethrottle(rps)
	tasksObj := map[string]any{
		entry.fullID: entry.toTaskInfoMap(true),
	}
	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"nodes": map[string]any{
			taskLocalNodeID: buildLocalTaskNodeEnvelope(tasksObj),
		},
	})
}

func parseSlicesCountRound60(r *http.Request, bodySlices any) (int, error) {
	var raw any
	if r != nil && r.URL != nil && r.URL.Query().Has("slices") {
		raw = r.URL.Query().Get("slices")
	} else if bodySlices != nil {
		raw = bodySlices
	}
	if raw == nil {
		return 1, nil
	}
	switch v := raw.(type) {
	case string:
		st := strings.TrimSpace(v)
		if st == "auto" {
			return 2, nil
		}
		n, err := strconv.Atoi(st)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("slices must be a positive integer or \"auto\", got [%s]", v)
		}
		return n, nil
	case json.Number:
		n, err := v.Int64()
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("slices must be a positive integer or \"auto\", got [%s]", v.String())
		}
		return int(n), nil
	case float64:
		if v != math.Trunc(v) || v <= 0 {
			return 0, fmt.Errorf("slices must be a positive integer or \"auto\", got [%v]", v)
		}
		return int(v), nil
	case int:
		if v <= 0 {
			return 0, fmt.Errorf("slices must be a positive integer or \"auto\", got [%d]", v)
		}
		return v, nil
	default:
		return 0, fmt.Errorf("slices must be a positive integer or \"auto\", got [%v]", raw)
	}
}

func buildByQuerySlicesBreakdown(numSlices, total, updated, created, deleted, versionConflicts, noops, batches int, rps float64) []any {
	if numSlices <= 1 {
		return nil
	}
	slices := make([]any, 0, numSlices)
	for i := 0; i < numSlices; i++ {
		st, su, sc, sd, svc, sn, sb := 0, 0, 0, 0, 0, 0, 0
		if i == 0 {
			st, su, sc, sd, svc, sn, sb = total, updated, created, deleted, versionConflicts, noops, batches
		}
		slices = append(slices, map[string]any{
			"slice_id":               i,
			"total":                  st,
			"updated":                su,
			"created":                sc,
			"deleted":                sd,
			"batches":                sb,
			"version_conflicts":      svc,
			"noops":                  sn,
			"retries":                map[string]any{"bulk": 0, "search": 0},
			"throttled_millis":       0,
			"requests_per_second":    rps,
			"throttled_until_millis": 0,
		})
	}
	return slices
}

// validateByQueryPreflightRound60 validates 400 request/body constraints BEFORE 404 index lookup
// on _update_by_query and _delete_by_query.
func validateByQueryPreflightRound60(r *http.Request, bodyBytes []byte, isDeleteByQuery bool) (rps float64, slicesCount int, waitForCompletion bool, status int, errType, errReason string) {
	waitForCompletion = true
	rps = -1

	var rawMap map[string]any
	if len(bytes.TrimSpace(bodyBytes)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.UseNumber()
		if err := dec.Decode(&rawMap); err != nil {
			return 0, 0, true, http.StatusBadRequest, "parse_exception", err.Error()
		}
	}

	if r != nil && r.URL != nil {
		q := r.URL.Query()
		if wv, present, err := parseStrictQueryBoolParamRound59(r, "wait_for_completion"); present {
			if err != nil {
				return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", err.Error()
			}
			waitForCompletion = wv
		}
		if q.Has("scroll_size") {
			ssStr := strings.TrimSpace(q.Get("scroll_size"))
			ssVal, err := strconv.Atoi(ssStr)
			if err != nil {
				return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("Failed to parse int parameter [scroll_size] with value [%s]", ssStr)
			}
			if ssVal <= 0 {
				return 0, 0, true, http.StatusBadRequest, "action_request_validation_exception",
					fmt.Sprintf("Validation Failed: 1: scroll_size must be greater than 0 but was [%d];", ssVal)
			}
		}
		if q.Has("max_docs") {
			mdStr := strings.TrimSpace(q.Get("max_docs"))
			mdVal, err := strconv.Atoi(mdStr)
			if err != nil || mdVal <= 0 {
				return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("max_docs must be >= 1, got [%s]", mdStr)
			}
		}
		if q.Has("from") {
			return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", "from is not supported in this context"
		}
		if q.Has("_source") && strings.EqualFold(strings.TrimSpace(q.Get("_source")), "false") {
			return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", " disabling [_source] is not supported for by-query operations"
		}
		if q.Has("stored_fields") {
			return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", "[stored_fields] is not supported for by-query operations"
		}
		if q.Has("requests_per_second") {
			parsedRPS, err := parseStrictRequestsPerSecondRound60(q.Get("requests_per_second"), true)
			if err != nil {
				return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", err.Error()
			}
			rps = parsedRPS
		}
		if q.Has("conflicts") {
			cf := strings.TrimSpace(q.Get("conflicts"))
			if cf != "" && cf != "abort" && cf != "proceed" {
				return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("Invalid conflicts value [%s], must be [abort] or [proceed]", cf)
			}
		}
	}

	if rawMap != nil {
		if _, hasFrom := rawMap["from"]; hasFrom {
			return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", "from is not supported in this context"
		}
		if srcVal, hasSrc := rawMap["_source"]; hasSrc {
			if bv, okB := srcVal.(bool); okB && !bv {
				return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", "disabling [_source] is not supported for by-query operations"
			}
			if sv, okS := srcVal.(string); okS && strings.EqualFold(strings.TrimSpace(sv), "false") {
				return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", "disabling [_source] is not supported for by-query operations"
			}
		}
		if _, hasSF := rawMap["stored_fields"]; hasSF {
			return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", "[stored_fields] is not supported for by-query operations"
		}
		if bodyRPS, hasRPS := rawMap["requests_per_second"]; hasRPS && (r == nil || r.URL == nil || !r.URL.Query().Has("requests_per_second")) {
			parsedRPS, err := parseStrictRequestsPerSecondRound60(bodyRPS, true)
			if err != nil {
				return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", err.Error()
			}
			rps = parsedRPS
		}
		if bodySz, hasSz := rawMap["size"]; hasSz {
			if szN, okN := toInt64(bodySz); !okN || szN <= 0 {
				return 0, 0, true, http.StatusBadRequest, "action_request_validation_exception",
					fmt.Sprintf("Validation Failed: 1: scroll_size/size must be greater than 0 but was [%v];", bodySz)
			}
		}
		if bodyMD, hasMD := rawMap["max_docs"]; hasMD {
			if mdN, okN := toInt64(bodyMD); !okN || mdN <= 0 {
				return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("max_docs must be >= 1, got [%v]", bodyMD)
			}
		}
		if cfRaw, hasCF := rawMap["conflicts"].(string); hasCF && cfRaw != "" && cfRaw != "abort" && cfRaw != "proceed" {
			return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Invalid conflicts value [%s], must be [abort] or [proceed]", cfRaw)
		}
	}

	var bodySlices any
	if rawMap != nil {
		bodySlices = rawMap["slices"]
	}
	sc, sErr := parseSlicesCountRound60(r, bodySlices)
	if sErr != nil {
		return 0, 0, true, http.StatusBadRequest, "illegal_argument_exception", sErr.Error()
	}
	slicesCount = sc

	if isDeleteByQuery {
		hasQueryInBody := rawMap != nil && rawMap["query"] != nil
		hasQParam := r != nil && r.URL != nil && strings.TrimSpace(r.URL.Query().Get("q")) != ""
		if !hasQueryInBody && !hasQParam {
			return 0, 0, true, http.StatusBadRequest, "action_request_validation_exception",
				"Validation Failed: 1: query is missing;"
		}
	}

	return rps, slicesCount, waitForCompletion, 0, "", ""
}

func (s *Server) getClusterSettingStringLocked(key string) (string, bool) {
	lookupIn := func(m map[string]any) (string, bool) {
		if m == nil {
			return "", false
		}
		if v, exists := m[key]; exists && v != nil {
			switch tv := v.(type) {
			case string:
				return tv, true
			case []any:
				parts := make([]string, 0, len(tv))
				for _, el := range tv {
					parts = append(parts, fmt.Sprintf("%v", el))
				}
				return strings.Join(parts, ","), true
			case []string:
				return strings.Join(tv, ","), true
			default:
				return fmt.Sprintf("%v", tv), true
			}
		}
		parts := strings.Split(key, ".")
		cur := m
		for i, p := range parts {
			val, ok := cur[p]
			if !ok {
				return "", false
			}
			if i == len(parts)-1 {
				if val == nil {
					return "", false
				}
				switch tv := val.(type) {
				case string:
					return tv, true
				case []any:
					sp := make([]string, 0, len(tv))
					for _, el := range tv {
						sp = append(sp, fmt.Sprintf("%v", el))
					}
					return strings.Join(sp, ","), true
				default:
					return fmt.Sprintf("%v", tv), true
				}
			}
			sub, okM := val.(map[string]any)
			if !okM {
				return "", false
			}
			cur = sub
		}
		return "", false
	}
	if v, ok := lookupIn(s.clusterTransientSettings); ok {
		return v, true
	}
	if v, ok := lookupIn(s.clusterPersistentSettings); ok {
		return v, true
	}
	return "", false
}

// IsStaticOnlyClusterSettingRound62 returns true when `key` is a node-static setting
// that cannot be updated dynamically via `PUT /_cluster/settings` (`reindex.remote.whitelist`,
// `path.repo`, `repositories.url.allowed_urls`, and any dotted sub-keys).
func IsStaticOnlyClusterSettingRound62(key string) bool {
	k := strings.TrimSpace(key)
	return k == "reindex.remote.whitelist" || strings.HasPrefix(k, "reindex.remote.whitelist.") ||
		k == "path.repo" || strings.HasPrefix(k, "path.repo.") ||
		k == "repositories.url.allowed_urls" || strings.HasPrefix(k, "repositories.url.allowed_urls.")
}

// ValidateDynamicClusterSettingsSectionRound62 inspects a `transient` or `persistent` cluster
// settings map (supporting both flat dotted keys and nested objects) and rejects static-only
// settings such as `reindex.remote.whitelist` with HTTP 400 `illegal_argument_exception`.
func ValidateDynamicClusterSettingsSectionRound62(tier string, section map[string]any) (int, string, string) {
	if len(section) == 0 {
		return 0, "", ""
	}
	if strings.TrimSpace(tier) == "" {
		tier = "transient"
	}
	var walk func(prefix string, m map[string]any) (int, string, string)
	walk = func(prefix string, m map[string]any) (int, string, string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fullKey := k
			if prefix != "" {
				fullKey = prefix + "." + k
			}
			if IsStaticOnlyClusterSettingRound62(fullKey) {
				return http.StatusBadRequest, "illegal_argument_exception",
					fmt.Sprintf("%s setting [%s], not dynamically updateable", tier, fullKey)
			}
			if sub, ok := m[k].(map[string]any); ok {
				if st, et, er := walk(fullKey, sub); st != 0 {
					return st, et, er
				}
			}
		}
		return 0, "", ""
	}
	return walk("", section)
}

func (s *Server) validateReindexRemoteWhitelistRound60(remoteObj map[string]any) (int, string, string) {
	if remoteObj == nil {
		return 0, "", ""
	}
	rawHost, _ := remoteObj["host"].(string)
	rawHost = strings.TrimSpace(rawHost)
	if rawHost == "" {
		return http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: remote host is missing;"
	}
	u, err := url.Parse(rawHost)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("invalid remote host [%s]", rawHost)
	}
	hostPort := u.Host
	if u.Port() == "" {
		defaultPort := "80"
		if u.Scheme == "https" {
			defaultPort = "443"
		}
		hostPort = net.JoinHostPort(u.Hostname(), defaultPort)
	}

	wlRaw, hasWL := s.getStaticRemoteReindexWhitelistRound62()
	if !hasWL || strings.TrimSpace(wlRaw) == "" {
		st := getOrCreateServerStateR61CRUD(s)
		st.mu.RLock()
		if st.testRemoteWhitelist != "" {
			wlRaw = st.testRemoteWhitelist
			hasWL = true
		}
		st.mu.RUnlock()
	}

	allowed := false
	if hasWL && strings.TrimSpace(wlRaw) != "" {
		for _, pat := range strings.Split(wlRaw, ",") {
			pat = strings.TrimSpace(pat)
			if pat == "" {
				continue
			}
			if matchWildcardPattern(pat, hostPort) || matchWildcardPattern(pat, u.Host) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("[%s] not whitelisted in reindex.remote.whitelist", hostPort)
	}
	return 0, "", ""
}

// launchAsyncTaskRound60 spawns a background task for wait_for_completion=false on _reindex,
// _update_by_query, or _delete_by_query after synchronous pre-flight validation has passed.
func (s *Server) launchAsyncTaskRound60(w http.ResponseWriter, r *http.Request, bodyBytes []byte, action, description string, rps float64, execSync func(http.ResponseWriter, *http.Request)) {
	if !s.acquireAsyncTaskSlot() {
		writeESError(w, http.StatusTooManyRequests, "es_rejected_execution_exception", "rejected execution of async task: maximum concurrent async tasks reached")
		return
	}
	bgCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	if meta, ok := TraceMetaFromContext(r.Context()); ok {
		bgCtx = WithTraceMeta(bgCtx, meta)
	}
	headers := extractTaskHeadersFromRequest(r)
	entry := s.getTaskRegistry().register(action, description, rps, headers, cancel)
	bgCtx = context.WithValue(bgCtx, taskEntryContextKey{}, entry)

	clonedReq := r.Clone(bgCtx)
	if clonedReq.URL != nil {
		q := clonedReq.URL.Query()
		q.Del("wait_for_completion")
		clonedReq.URL.RawQuery = q.Encode()
	}
	clonedReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	clonedReq.ContentLength = int64(len(bodyBytes))

	go func() {
		defer s.releaseAsyncTaskSlot()
		defer cancel()
		defer func() {
			if recErr := recover(); recErr != nil {
				cleanMsg := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(fmt.Sprintf("%v", recErr))
				if len(cleanMsg) > 512 {
					cleanMsg = cleanMsg[:512]
				}
				log.Printf("[async-task] recovered panic in task %q (%q): %s", entry.fullID, action, cleanMsg)
				entry.markDone(nil, map[string]any{
					"type":   "internal_server_error",
					"reason": "async task failed unexpectedly: " + cleanMsg,
				})
				s.getTaskRegistry().pruneCompletedTasks()
			}
		}()
		rec := &bufferResponseWriter{}
		execSync(rec, clonedReq)

		var parsed map[string]any
		if rec.buf.Len() > 0 {
			dec := json.NewDecoder(bytes.NewReader(rec.buf.Bytes()))
			dec.UseNumber()
			_ = dec.Decode(&parsed)
		}

		entry.mu.Lock()
		wasCancelled := entry.cancelled
		entry.mu.Unlock()

		if wasCancelled {
			entry.markDone(parsed, map[string]any{
				"type":   "task_cancelled_exception",
				"reason": "Task cancelled by user request",
			})
			s.getTaskRegistry().pruneCompletedTasks()
			return
		}
		if rec.status >= 400 && parsed["failures"] == nil {
			var errObj map[string]any
			if parsed != nil {
				errObj, _ = parsed["error"].(map[string]any)
			}
			if errObj == nil {
				errObj = map[string]any{
					"type":   "exception",
					"reason": fmt.Sprintf("task failed with status %d", rec.status),
				}
			}
			entry.markDone(nil, errObj)
			s.getTaskRegistry().pruneCompletedTasks()
			return
		}
		entry.markDone(parsed, nil)
		s.getTaskRegistry().pruneCompletedTasks()
	}()

	writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
		"task": entry.fullID,
	})
}
