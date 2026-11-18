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
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newRound60CovServer(t *testing.T, esVer string) (*Server, http.Handler) {
	t.Helper()
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	if esVer != "" {
		srv.SetTargetESVersion(esVer)
	}
	return srv, srv.Handler()
}

func doRound60CovReq(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) (int, http.Header, map[string]any, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	if len(strings.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
		dec.UseNumber()
		_ = dec.Decode(&parsed)
	}
	return rec.Code, rec.Header(), parsed, raw
}

func TestRound60CoverageTasksEndpointsAndLifecycle(t *testing.T) {
	srv, h := newRound60CovServer(t, "8.17.0")
	reg := srv.getTaskRegistry()

	// Seed an index and documents for async reindex / by-query tasks
	code, _, _, raw := doRound60CovReq(t, h, http.MethodPut, "/r60-task-src", `{"mappings":{"properties":{"k":{"type":"keyword"},"n":{"type":"long"}}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", code, raw)
	}
	code, _, _, raw = doRound60CovReq(t, h, http.MethodPost, "/r60-task-src/_doc/1?refresh=true", `{"k":"a","n":10}`, nil)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index doc failed: %d %s", code, raw)
	}

	// Register deterministic active, child, and completed-with-error tasks
	ctxParent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	parentEntry := reg.register("indices:data/write/reindex", "reindex from [r60-task-src]", 500, map[string]string{"X-Opaque-Id": "op-1"}, cancelParent)
	go func() {
		<-ctxParent.Done()
		parentEntry.markDone(nil, nil)
	}()

	ctxChild, cancelChild := context.WithCancel(context.Background())
	defer cancelChild()
	childEntry := reg.register("indices:data/write/reindex", "child slice", -1, nil, cancelChild)
	childEntry.parentTaskID = parentEntry.fullID
	go func() {
		<-ctxChild.Done()
		childEntry.markDone(nil, nil)
	}()

	_, cancelErrTask := context.WithCancel(context.Background())
	errEntry := reg.register("indices:data/write/delete/byquery", "failed task", -1, nil, cancelErrTask)
	errEntry.markDone(map[string]any{
		"total": 5, "updated": 1, "created": 1, "deleted": 1, "batches": 2, "version_conflicts": 1, "noops": 1,
	}, map[string]any{"type": "script_exception", "reason": "boom"})
	// Second markDone & cancel after completion should be safe no-ops
	errEntry.markDone(nil, nil)
	if errEntry.cancel() {
		t.Fatal("expected cancel() on completed task to return false")
	}

	// Throttle helper coverage: nil task ctx, fast timer, rethrottle wakeup, cancelled ctx
	if err := applyTaskThrottleAndProgressRound60(context.Background(), 5, 100); err != nil {
		t.Fatalf("unexpected nil-entry throttle error: %v", err)
	}
	tCtx := context.WithValue(ctxParent, taskEntryContextKey{}, parentEntry)
	parentEntry.notifyRethrottle(100000) // 0.01ms sleep -> exercises timer.C branch
	if err := applyTaskThrottleAndProgressRound60(tCtx, 1, 0); err != nil {
		t.Fatalf("unexpected fast-timer throttle error: %v", err)
	}
	parentEntry.notifyRethrottle(0.5) // long sleep, woken immediately by notifyRethrottle(-1)
	doneWake := make(chan error, 1)
	go func() {
		doneWake <- applyTaskThrottleAndProgressRound60(tCtx, 10, 0)
	}()
	parentEntry.notifyRethrottle(-1)
	if err := <-doneWake; err != nil {
		t.Fatalf("unexpected rethrottle wakeup error: %v", err)
	}
	closedCtx, closedCancel := context.WithCancel(tCtx)
	closedCancel()
	if err := applyTaskThrottleAndProgressRound60(closedCtx, 1, 100); err == nil {
		t.Fatal("expected error on cancelled context")
	}

	// GET /_tasks list matrix
	listCases := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodPost, "/_tasks", http.StatusMethodNotAllowed},
		{http.MethodGet, "/_tasks", http.StatusOK},
		{http.MethodGet, "/_tasks?detailed=true&group_by=nodes&actions=*reindex*&nodes=_local", http.StatusOK},
		{http.MethodGet, "/_tasks?detailed=true&group_by=none&nodes=data:true,doris-fe*", http.StatusOK},
		{http.MethodGet, "/_tasks?detailed=true&group_by=parents&parent_task_id=" + parentEntry.fullID, http.StatusOK},
		{http.MethodGet, "/_tasks?parent_task_id=-&nodes=nonexistent-node", http.StatusOK},
		{http.MethodGet, "/_tasks?wait_for_completion=true&timeout=5ms", http.StatusOK},
		{http.MethodGet, "/_tasks?group_by=bogus", http.StatusBadRequest},
		{http.MethodGet, "/_tasks?detailed=notabool", http.StatusBadRequest},
		{http.MethodGet, "/_tasks?wait_for_completion=notabool", http.StatusBadRequest},
		{http.MethodGet, "/_tasks?wait_for_completion=true&timeout=bad", http.StatusBadRequest},
		{http.MethodGet, "/_tasks?parent_task_id=malformed", http.StatusBadRequest},
	}
	for _, tc := range listCases {
		c, _, _, rBody := doRound60CovReq(t, h, tc.method, tc.path, "", nil)
		if c != tc.want {
			t.Fatalf("%s %s: got %d, want %d (%s)", tc.method, tc.path, c, tc.want, rBody)
		}
	}

	// GET /_tasks/{task_id} matrix
	getCases := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodDelete, "/_tasks/" + parentEntry.fullID, http.StatusMethodNotAllowed},
		{http.MethodGet, "/_tasks/bad-task-id", http.StatusBadRequest},
		{http.MethodGet, "/_tasks/other-node:123", http.StatusNotFound},
		{http.MethodGet, "/_tasks/doris-fe-1:999999", http.StatusNotFound},
		{http.MethodGet, "/_tasks/" + parentEntry.fullID + "?wait_for_completion=notbool", http.StatusBadRequest},
		{http.MethodGet, "/_tasks/" + parentEntry.fullID + "?wait_for_completion=true&timeout=bad", http.StatusBadRequest},
		{http.MethodGet, "/_tasks/" + parentEntry.fullID + "?wait_for_completion=true&timeout=5ms", http.StatusOK},
		{http.MethodGet, "/_tasks/" + errEntry.fullID + "?wait_for_completion=true", http.StatusOK},
	}
	for _, tc := range getCases {
		c, _, _, rBody := doRound60CovReq(t, h, tc.method, tc.path, "", nil)
		if c != tc.want {
			t.Fatalf("%s %s: got %d, want %d (%s)", tc.method, tc.path, c, tc.want, rBody)
		}
	}

	// Rethrottle endpoints & RPS parser
	rethrottleCases := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/_reindex/" + parentEntry.fullID + "/_rethrottle", http.StatusMethodNotAllowed},
		{http.MethodPost, "/_reindex/malformed/_rethrottle", http.StatusBadRequest},
		{http.MethodPost, "/_reindex/" + parentEntry.fullID + "/_rethrottle?requests_per_second=0", http.StatusBadRequest},
		{http.MethodPost, "/_reindex/unknown-node:1/_rethrottle?requests_per_second=10", http.StatusNotFound},
		{http.MethodPost, "/_reindex/doris-fe-1:999998/_rethrottle?requests_per_second=10", http.StatusNotFound},
		{http.MethodPost, "/_reindex/" + parentEntry.fullID + "/_rethrottle?requests_per_second=unlimited", http.StatusOK},
		{http.MethodPost, "/r60-task-src/_update_by_query/" + parentEntry.fullID + "/_rethrottle?requests_per_second=250", http.StatusOK},
	}
	for _, tc := range rethrottleCases {
		c, _, _, rBody := doRound60CovReq(t, h, tc.method, tc.path, "", nil)
		if c != tc.want {
			t.Fatalf("%s %s: got %d, want %d (%s)", tc.method, tc.path, c, tc.want, rBody)
		}
	}
	for _, goodRPS := range []any{"unlimited", "infinity", "-1", "25.5", json.Number("100"), float64(-1), float64(50), int(10), int64(-1)} {
		if _, err := parseStrictRequestsPerSecondRound60(goodRPS, true); err != nil {
			t.Fatalf("expected valid RPS %#v, got %v", goodRPS, err)
		}
	}
	for _, badRPS := range []any{"", "0", "-5", "abc", json.Number("0"), math.NaN(), float64(0), int(0), int64(-2), []string{"x"}} {
		if _, err := parseStrictRequestsPerSecondRound60(badRPS, true); err == nil {
			t.Fatalf("expected error for RPS %#v", badRPS)
		}
	}

	// Cancel endpoints (single & bulk)
	cancelCases := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/_tasks/_cancel", http.StatusMethodNotAllowed},
		{http.MethodPost, "/_tasks/_cancel?wait_for_completion=bad", http.StatusBadRequest},
		{http.MethodPost, "/_tasks/bad-id/_cancel", http.StatusBadRequest},
		{http.MethodPost, "/_tasks/other-node:1/_cancel", http.StatusNotFound},
		{http.MethodPost, "/_tasks/doris-fe-1:999997/_cancel", http.StatusNotFound},
		{http.MethodPost, "/_tasks/" + childEntry.fullID + "/_cancel?wait_for_completion=true&timeout=5ms", http.StatusOK},
		{http.MethodPost, "/_tasks/_cancel?actions=*reindex*&nodes=_local&wait_for_completion=true&timeout=5ms", http.StatusOK},
	}
	for _, tc := range cancelCases {
		c, _, _, rBody := doRound60CovReq(t, h, tc.method, tc.path, "", nil)
		if c != tc.want {
			t.Fatalf("%s %s: got %d, want %d (%s)", tc.method, tc.path, c, tc.want, rBody)
		}
	}

	// Preflight validators, slices breakdown, remote whitelist & async task launcher
	_ = buildByQuerySlicesBreakdown(1, 5, 1, 1, 1, 0, 0, 1, -1)
	if sl := buildByQuerySlicesBreakdown(3, 5, 2, 1, 1, 0, 1, 1, 100); len(sl) != 3 {
		t.Fatalf("expected 3 slices, got %d", len(sl))
	}
	for _, goodSl := range []any{nil, "auto", "4", json.Number("3"), float64(2), int(5)} {
		if _, err := parseSlicesCountRound60(nil, goodSl); err != nil {
			t.Fatalf("expected valid slices %#v, got %v", goodSl, err)
		}
	}
	for _, badSl := range []any{"0", "bad", json.Number("0"), float64(1.5), int(0), true} {
		if _, err := parseSlicesCountRound60(nil, badSl); err == nil {
			t.Fatalf("expected error on slices %#v", badSl)
		}
	}

	byQueryErrors := []struct {
		path  string
		body  string
		isDel bool
	}{
		{"/r60-task-src/_update_by_query", `{bad`, false},
		{"/r60-task-src/_update_by_query?wait_for_completion=bad", `{}`, false},
		{"/r60-task-src/_update_by_query?scroll_size=abc", `{}`, false},
		{"/r60-task-src/_update_by_query?scroll_size=0", `{}`, false},
		{"/r60-task-src/_update_by_query?max_docs=0", `{}`, false},
		{"/r60-task-src/_update_by_query?_source=false", `{}`, false},
		{"/r60-task-src/_update_by_query?stored_fields=_none_", `{}`, false},
		{"/r60-task-src/_update_by_query?requests_per_second=0", `{}`, false},
		{"/r60-task-src/_update_by_query?conflicts=bogus", `{}`, false},
		{"/r60-task-src/_update_by_query", `{"_source":false}`, false},
		{"/r60-task-src/_update_by_query", `{"_source":"false"}`, false},
		{"/r60-task-src/_update_by_query", `{"stored_fields":["a"]}`, false},
		{"/r60-task-src/_update_by_query", `{"requests_per_second":0}`, false},
		{"/r60-task-src/_update_by_query", `{"size":0}`, false},
		{"/r60-task-src/_update_by_query", `{"max_docs":0}`, false},
		{"/r60-task-src/_update_by_query", `{"conflicts":"bogus"}`, false},
		{"/r60-task-src/_update_by_query?slices=0", `{}`, false},
		{"/r60-task-src/_delete_by_query", `{}`, true},
	}
	for _, bq := range byQueryErrors {
		req := httptest.NewRequest(http.MethodPost, bq.path, nil)
		if _, _, _, st, _, _ := validateByQueryPreflightRound60(req, []byte(bq.body), bq.isDel); st != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s %s, got %d", bq.path, bq.body, st)
		}
	}

	// Remote reindex whitelist & cluster settings
	srv.SetStaticRemoteReindexWhitelist("example.org:443,127.0.0.1:*,backup.org:80")
	srv.mu.Lock()
	srv.clusterTransientSettings = map[string]any{
		"reindex.remote.whitelist": []any{"example.org:443", "127.0.0.1:*"},
	}
	srv.clusterPersistentSettings = map[string]any{
		"reindex": map[string]any{
			"remote": map[string]any{
				"whitelist": []any{"backup.org:80"},
			},
		},
	}
	srv.mu.Unlock()
	for _, rem := range []map[string]any{
		{"host": ""},
		{"host": "ftp://bad.host"},
		{"host": "http://unlisted.example.com"},
	} {
		if st, _, _ := srv.validateReindexRemoteWhitelistRound60(rem); st != http.StatusBadRequest {
			t.Fatalf("expected 400 for remote %v, got %d", rem, st)
		}
	}
	if st, _, _ := srv.validateReindexRemoteWhitelistRound60(map[string]any{"host": "https://example.org"}); st != 0 {
		t.Fatalf("expected whitelisted https://example.org, got %d", st)
	}
	srv.mu.Lock()
	srv.clusterTransientSettings = nil
	srv.mu.Unlock()
	if st, _, _ := srv.validateReindexRemoteWhitelistRound60(map[string]any{"host": "http://backup.org"}); st != 0 {
		t.Fatalf("expected nested persistent whitelisted http://backup.org, got %d", st)
	}

	reindexErrBodies := []struct {
		path string
		body string
	}{
		{"/_reindex", `{bad`},
		{"/_reindex?wait_for_completion=bad", `{}`},
		{"/_reindex?scroll_size=0", `{}`},
		{"/_reindex?requests_per_second=0", `{}`},
		{"/_reindex", `{"requests_per_second":0}`},
		{"/_reindex", `{"source":{"index":"a","size":0},"dest":{"index":"b"}}`},
		{"/_reindex", `{"source":{"index":"a","remote":{"host":"http://denied.local"}},"dest":{"index":"b"}}`},
		{"/_reindex?slices=0", `{"source":{"index":"a"},"dest":{"index":"b"}}`},
	}
	for _, rc := range reindexErrBodies {
		c, _, _, rBody := doRound60CovReq(t, h, http.MethodPost, rc.path, rc.body, nil)
		if c != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s %s, got %d (%s)", rc.path, rc.body, c, rBody)
		}
	}

	// Async task execution via wait_for_completion=false + polling to completion
	cAsync, _, asyncResp, rBody := doRound60CovReq(t, h, http.MethodPost, "/r60-task-src/_update_by_query?wait_for_completion=false&slices=2", `{"query":{"match_all":{}}}`, map[string]string{"X-Opaque-Id": "async-ubq"})
	if cAsync != http.StatusOK || asyncResp["task"] == nil {
		t.Fatalf("async update_by_query failed: %d %s", cAsync, rBody)
	}
	taskID, _ := asyncResp["task"].(string)
	cPoll, _, _, pBody := doRound60CovReq(t, h, http.MethodGet, "/_tasks/"+taskID+"?wait_for_completion=true&timeout=2s", "", nil)
	if cPoll != http.StatusOK {
		t.Fatalf("waiting for async task %s failed: %d %s", taskID, cPoll, pBody)
	}
}

func TestRound60CoverageFeaturesClusterNodesRefreshBulkMGet(t *testing.T) {
	srv, h := newRound60CovServer(t, "8.17.0")

	// 1. Wire compatibility headers
	compatCases := []struct {
		headers map[string]string
		want    int
	}{
		{map[string]string{"Accept": "application/vnd.elasticsearch+json; compatible-with=6"}, http.StatusNotAcceptable},
		{map[string]string{"Content-Type": "application/vnd.elasticsearch+json; compatible-with=9"}, http.StatusNotAcceptable},
		{map[string]string{
			"Accept":       "application/vnd.elasticsearch+json; compatible-with=8",
			"Content-Type": "application/vnd.elasticsearch+json; compatible-with=7",
		}, http.StatusNotAcceptable},
		{map[string]string{"Accept": "application/vnd.elasticsearch+json"}, http.StatusNotAcceptable},
		{map[string]string{"Accept": "image/png"}, http.StatusNotAcceptable},
		{map[string]string{"Accept": "application/vnd.elasticsearch+json; compatible-with=8"}, http.StatusOK},
		{map[string]string{"Accept": "application/vnd.elasticsearch+json; compatible-with=7"}, http.StatusOK},
	}
	for _, tc := range compatCases {
		c, _, _, rBody := doRound60CovReq(t, h, http.MethodGet, "/", "", tc.headers)
		if c != tc.want {
			t.Fatalf("headers %v: got %d, want %d (%s)", tc.headers, c, tc.want, rBody)
		}
	}

	// 2. Refresh interval -1 & unrefreshed document visibility + refresh policies
	code, _, _, raw := doRound60CovReq(t, h, http.MethodPut, "/r60-unref", `{
		"settings":{"refresh_interval":"-1","number_of_shards":2,"number_of_replicas":0},
		"mappings":{"properties":{"title":{"type":"keyword"},"val":{"type":"long"}}}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create r60-unref failed: %d %s", code, raw)
	}
	if c, _, _, _ := doRound60CovReq(t, h, http.MethodPost, "/r60-unref/_doc/1?refresh=invalid", `{"title":"a","val":1}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid refresh param, got %d", c)
	}
	// Seed refreshed doc 1, then unrefreshed create doc 2, update doc 1, delete doc 1
	_, _, _, _ = doRound60CovReq(t, h, http.MethodPut, "/r60-unref/_doc/1?refresh=wait_for", `{"title":"v1","val":1}`, nil)
	_, _, _, _ = doRound60CovReq(t, h, http.MethodPut, "/r60-unref/_doc/2?refresh=false", `{"title":"v2","val":2}`, nil)
	_, _, _, _ = doRound60CovReq(t, h, http.MethodPut, "/r60-unref/_doc/1?refresh=false", `{"title":"v1-updated","val":10}`, nil)
	// Search with size=10 and size=0 while unrefreshed state is active
	if c, _, _, rB := doRound60CovReq(t, h, http.MethodPost, "/r60-unref/_search", `{"size":10,"query":{"match_all":{}}}`, nil); c != http.StatusOK {
		t.Fatalf("search unrefreshed size=10 failed: %d %s", c, rB)
	}
	if c, _, _, rB := doRound60CovReq(t, h, http.MethodPost, "/r60-unref/_search", `{"size":0,"query":{"match_all":{}}}`, nil); c != http.StatusOK {
		t.Fatalf("search unrefreshed size=0 failed: %d %s", c, rB)
	}
	_, _, _, _ = doRound60CovReq(t, h, http.MethodDelete, "/r60-unref/_doc/1?refresh=false", "", nil)
	if c, _, _, rB := doRound60CovReq(t, h, http.MethodPost, "/r60-unref/_search", `{"size":10,"query":{"match_all":{}}}`, nil); c != http.StatusOK {
		t.Fatalf("search after unrefreshed delete failed: %d %s", c, rB)
	}
	_, _, _, _ = doRound60CovReq(t, h, http.MethodPost, "/r60-unref/_refresh", "", nil)

	// 3. MGet, MLT & Bulk normalizers
	mgetBad := []string{``, `{bad`, `{}`, `{"ids":"not-arr"}`, `{"ids":[{}]}`, `{"docs":"not-arr"}`, `{"docs":["not-obj"]}`}
	for _, b := range mgetBad {
		if _, st, _, _ := normalizeMGetBodyRound60([]byte(b)); st != http.StatusBadRequest {
			t.Fatalf("expected 400 for mget body %q, got %d", b, st)
		}
	}
	if normB, st, _, _ := normalizeMGetBodyRound60([]byte(`{"ids":[1,true,2.5,null],"docs":[{"_index":"r60-unref","_id":2,"routing":99}]}`)); st != 0 || len(normB) == 0 {
		t.Fatalf("expected valid normalized mget body, got st=%d", st)
	}
	mltOut := normalizeMLTDocIDsInRawJSONRound60([]byte(`{"query":{"bool":{"must":[{"more_like_this":{"fields":["title"],"like":[{"_index":"r60-unref","_id":1,"routing":true},{"doc":{"_index":"r60-unref","_id":2}}],"unlike":{"_index":"r60-unref","_id":3}}}]}}}`))
	if !bytes.Contains(mltOut, []byte(`"1"`)) {
		t.Fatalf("expected stringified MLT _id, got %s", string(mltOut))
	}

	bulkBad := []string{
		"{bad\n",
		"[]\n",
		"{}\n",
		`{"index":{},"delete":{}}` + "\n",
		`{"bogus":{"_id":"1"}}` + "\n",
		`{"index":"not-obj"}` + "\n",
		`{"index":{"_id":"1","op_type":"invalid"}}` + "\n" + `{"a":1}` + "\n",
		`{"index":{"_id":[]}}` + "\n" + `{"a":1}` + "\n",
	}
	for _, bb := range bulkBad {
		if _, _, st, _, _ := preprocessBulkNDJSONRound60([]byte(bb)); st != http.StatusBadRequest {
			t.Fatalf("expected 400 on bulk body %q, got %d", bb, st)
		}
	}
	validBulk := strings.Join([]string{
		`{"index":{"_index":"r60-unref","_id":10,"op_type":"create","routing":5}}`,
		`{"title":"ten","val":10}`,
		`{"index":{"_index":"r60-unref","_id":11,"op_type":"index"}}`,
		`{"title":"eleven","val":11}`,
		`{"create":{"_index":"r60-unref"}}`,
		`{"title":"auto-create","val":12}`,
		`{"index":{"_index":"r60-unref","_id":""}}`,
		`{"title":"empty-id","val":13}`,
		`{"delete":{"_index":"r60-unref"}}`,
		"",
	}, "\n")
	if c, _, _, rB := doRound60CovReq(t, h, http.MethodPost, "/_bulk", validBulk, nil); c != http.StatusOK {
		t.Fatalf("POST /_bulk failed: %d %s", c, rB)
	}

	// 4. Aliases, require_alias, and action.auto_create_index
	if c, _, _, rB := doRound60CovReq(t, h, http.MethodPost, "/_aliases", `{
		"actions":[{"add":{"indices":"r60-unref","aliases":"r60-alias","routing":1,"index_routing":2,"search_routing":3}}]
	}`, nil); c != http.StatusOK {
		t.Fatalf("POST /_aliases failed: %d %s", c, rB)
	}
	if st, _, _ := srv.validateRequireAliasForWriteRound60(context.Background(), ""); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty target, got %d", st)
	}
	if st, _, _ := srv.validateRequireAliasForWriteRound60(context.Background(), "r60-alias"); st != 0 {
		t.Fatalf("expected 0 on valid alias, got %d", st)
	}
	if st, _, _ := srv.validateRequireAliasForWriteRound60(context.Background(), "r60-unref"); st != http.StatusNotFound {
		t.Fatalf("expected 404 on concrete index with require_alias=true, got %d", st)
	}
	if st, _, _ := srv.validateRequireAliasForWriteRound60(context.Background(), "no-such-alias"); st != http.StatusNotFound {
		t.Fatalf("expected 404 on missing alias, got %d", st)
	}

	_, _, _, _ = doRound60CovReq(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"action.auto_create_index":"+allow-*,-block-*"}}`, nil)
	if st, _, _ := srv.checkAutoCreateIndexClusterSettingRound60("allow-ok"); st != 0 {
		t.Fatalf("expected allow-ok to pass, got %d", st)
	}
	if st, _, _ := srv.checkAutoCreateIndexClusterSettingRound60("block-bad"); st != http.StatusNotFound {
		t.Fatalf("expected block-bad to fail 404, got %d", st)
	}
	if st, _, _ := srv.checkAutoCreateIndexClusterSettingRound60("unmatched-idx"); st != http.StatusNotFound {
		t.Fatalf("expected unmatched-idx to fail 404, got %d", st)
	}
	_, _, _, _ = doRound60CovReq(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"action.auto_create_index":"true"}}`, nil)

	// 5. _stats, _nodes, _cluster/state, _cluster/stats
	diagEndpoints := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodPost, "/_stats", http.StatusMethodNotAllowed},
		{http.MethodGet, "/_stats/bad_metric", http.StatusBadRequest},
		{http.MethodGet, "/_stats?level=bad", http.StatusBadRequest},
		{http.MethodGet, "/_stats?include_segment_file_sizes=bad", http.StatusBadRequest},
		{http.MethodGet, "/r60-unref/_stats/docs,store,indexing,search,segments?level=shards&include_segment_file_sizes=true&groups=g1,g2", http.StatusOK},
		{http.MethodGet, "/_stats/fielddata,query_cache,request_cache,completion,translog?level=cluster", http.StatusOK},
		{http.MethodGet, "/_nodes/_none", http.StatusOK},
		{http.MethodGet, "/_nodes/jvm,os,process,settings,http,transport,thread_pool,plugins,modules,ingest,aggregations?flat_settings=true", http.StatusOK},
		{http.MethodGet, "/_nodes/_local/bad_metric", http.StatusBadRequest},
		{http.MethodGet, "/_nodes/-doris-fe-1", http.StatusOK},
		{http.MethodGet, "/_nodes/master:true,coordinating_only:false", http.StatusOK},
		{http.MethodGet, "/_nodes/stats", http.StatusOK},
		{http.MethodGet, "/_nodes/stats/os,process,jvm,thread_pool,fs,transport,http,breaker,script,discovery,ingest,adaptive_selection,script_cache,indexing_pressure", http.StatusOK},
		{http.MethodGet, "/_nodes/stats/bad_metric", http.StatusBadRequest},
		{http.MethodGet, "/_nodes/doris-fe-1/stats/indices/docs,store,search", http.StatusOK},
		{http.MethodGet, "/_nodes/stats/indices/bad_idx_metric", http.StatusBadRequest},
		{http.MethodPost, "/_cluster/state", http.StatusMethodNotAllowed},
		{http.MethodGet, "/_cluster/state/bad_metric", http.StatusBadRequest},
		{http.MethodGet, "/_cluster/state/metadata,routing_table,nodes,blocks/r60-unref?flat_settings=true", http.StatusOK},
		{http.MethodPost, "/_cluster/stats", http.StatusMethodNotAllowed},
		{http.MethodGet, "/_cluster/stats/nodes/_local", http.StatusOK},
		{http.MethodGet, "/_cluster/stats/nodes/nonexistent-node", http.StatusOK},
	}
	for _, ep := range diagEndpoints {
		c, _, _, rB := doRound60CovReq(t, h, ep.method, ep.path, "", nil)
		if c != ep.want {
			t.Fatalf("%s %s: got %d, want %d (%s)", ep.method, ep.path, c, ep.want, rB)
		}
	}

	// 6. track_total_hits + rest_total_hits_as_int, scroll validation, and ES7 vs ES8 _type patching
	for _, qPath := range []string{
		"/r60-unref/_search?rest_total_hits_as_int=true&track_total_hits=10",
		"/r60-unref/_search?track_total_hits=0",
		"/r60-unref/_search?track_total_hits=abc",
	} {
		if c, _, _, _ := doRound60CovReq(t, h, http.MethodPost, qPath, `{}`, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on %s, got %d", qPath, c)
		}
	}
	for _, sBody := range []string{
		`{"track_total_hits":10}`,
		`{"track_total_hits":0}`,
		`{"track_total_hits":"10"}`,
		`{"track_total_hits":"0"}`,
		`{"track_total_hits":"bad"}`,
	} {
		if c, _, _, _ := doRound60CovReq(t, h, http.MethodPost, "/r60-unref/_search?rest_total_hits_as_int=true", sBody, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 on body %s, got %d", sBody, c)
		}
	}
	_, _, _, _ = doRound60CovReq(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"search.max_keep_alive":"5m"}}`, nil)
	if has, _, reason := srv.extractAndValidateScrollParamRound60(nil, []byte(`{"scroll":"10m"}`)); !has || reason == "" {
		t.Fatalf("expected scroll max_keep_alive error, got has=%v reason=%q", has, reason)
	}
	if has, _, reason := srv.extractAndValidateScrollParamRound60(nil, []byte(`{"scroll":"bad"}`)); !has || reason == "" {
		t.Fatalf("expected invalid scroll duration error, got has=%v reason=%q", has, reason)
	}
	if has, ttl, reason := srv.extractAndValidateScrollParamRound60(nil, []byte(`{"scroll":"1m"}`)); !has || ttl == 0 || reason != "" {
		t.Fatalf("expected valid 1m scroll, got has=%v ttl=%v reason=%q", has, ttl, reason)
	}

	sampleResp := map[string]any{
		"hits": map[string]any{
			"hits": []any{
				map[string]any{
					"_id": "1",
					"inner_hits": map[string]any{
						"comments": map[string]any{
							"hits": map[string]any{"hits": []map[string]any{{"_id": "c1"}}},
						},
					},
				},
			},
		},
		"aggregations": map[string]any{
			"by_t": map[string]any{
				"buckets": []any{
					map[string]any{"top": map[string]any{"hits": map[string]any{"hits": []map[string]any{{"_id": "2"}}}}},
				},
			},
			"keyed_t": map[string]any{
				"buckets": map[string]any{
					"a": map[string]any{"top": map[string]any{"hits": map[string]any{"hits": []map[string]any{{"_id": "3"}}}}},
				},
			},
		},
	}
	req7 := httptest.NewRequest(http.MethodPost, "/r60-unref/_search", nil)
	req7.Header.Set("Accept", "application/vnd.elasticsearch+json; compatible-with=7")
	srv.applyDocTypeToSearchResponseRound60(sampleResp, req7)
	req8 := httptest.NewRequest(http.MethodPost, "/r60-unref/_search", nil)
	req8.Header.Set("Accept", "application/vnd.elasticsearch+json; compatible-with=8")
	srv.applyDocTypeToSearchResponseRound60(sampleResp, req8)
}

func TestRound60CoverageSearchPainlessAndExplain(t *testing.T) {
	// 1. Unit coverage of formatting, source extraction, emit contexts, moving_fn, and explain boost
	dblCases := map[float64]string{
		math.NaN():   "NaN",
		math.Inf(1):  "Infinity",
		math.Inf(-1): "-Infinity",
		0.0:          "0.0",
		-9.0:         "-9.0",
		1.5:          "1.5",
		1e-5:         "1.0E-5",
		1e9:          "1.0E9",
		-2.5e-6:      "-2.5E-6",
	}
	for in, want := range dblCases {
		if got := formatJavaDoubleRound60(in); got != want {
			t.Fatalf("formatJavaDoubleRound60(%v): got %q, want %q", in, got, want)
		}
	}

	if got := formatTermsScriptScalarKeyRound60(nil, nil, false, schema.FieldBinding{}); got != "" {
		t.Fatalf("expected empty key for nil, got %q", got)
	}
	if got := formatTermsScriptScalarKeyRound60(float64(42), &esast.TermsAggSpec{ValueType: "long"}, false, schema.FieldBinding{}); got != "42" {
		t.Fatalf("expected integer key '42', got %q", got)
	}
	if got := formatTermsScriptScalarKeyRound60(float64(-9), &esast.TermsAggSpec{}, false, schema.FieldBinding{}); got != "-9.0" {
		t.Fatalf("expected Java double '-9.0', got %q", got)
	}

	if formatSearchShardScriptFailureReasonRound60(nil) != "" {
		t.Fatal("expected empty reason for nil err")
	}
	if !strings.Contains(formatSearchShardScriptFailureReasonRound60(painless.ErrSelfReferencingIterable), "self-referencing") {
		t.Fatal("expected self-referencing message")
	}
	compErr := painless.CompileValidate("if (")
	if !strings.Contains(formatSearchShardScriptFailureReasonRound60(compErr), "compile error") {
		t.Fatal("expected compile error message")
	}
	if !strings.Contains(formatSearchShardScriptFailureReasonRound60(errors.New("all_shards_failed|custom|x")), "custom") {
		t.Fatal("expected passthrough all_shards_failed")
	}

	srcInputs := []any{
		&esast.ScriptSpec{Source: "1+1"},
		esast.ScriptSpec{Source: "2+2", Lang: "painless"},
		"3+3",
		map[string]any{"script": map[string]any{"inline": "4+4"}},
		map[string]any{"code": "5+5"},
	}
	for _, in := range srcInputs {
		if s, ok := extractPainlessSourceIfApplicableRound60(in); !ok || s == "" {
			t.Fatalf("expected painless source from %#v", in)
		}
	}
	for _, nonP := range []any{nil, (*esast.ScriptSpec)(nil), &esast.ScriptSpec{Source: "1", Lang: "expression"}, map[string]any{"lang": "mustache", "source": "x"}} {
		if _, ok := extractPainlessSourceIfApplicableRound60(nonP); ok {
			t.Fatalf("expected false for %#v", nonP)
		}
	}

	for _, esT := range []string{"boolean", "long", "double", "keyword", "date", "ip", "geo_point"} {
		if _, ok := runtimeFieldTypeToEmitContextRound60(esT); !ok {
			t.Fatalf("expected emit context for %s", esT)
		}
	}
	if _, ok := runtimeFieldTypeToEmitContextRound60("text"); ok {
		t.Fatal("expected false for text emit context")
	}

	// evalMovingFnWindowNullableRound60 empty & non-empty windows
	if v, ok := evalMovingFnWindowNullableRound60(nil, &esast.MovingAvgAggSpec{Script: "return MovingFunctions.sum(values);"}); !ok || v != 0 {
		t.Fatalf("expected 0.0 for empty MovingFunctions.sum, got %v %v", v, ok)
	}
	if _, ok := evalMovingFnWindowNullableRound60(nil, &esast.MovingAvgAggSpec{Script: "return MovingFunctions.max(values);"}); ok {
		t.Fatal("expected null (ok=false) for empty MovingFunctions.max")
	}

	// extractExplainTopBoostRound60 across all query variants
	boostQueries := []string{
		`{"query":{"match_all":{"boost":2.5}}}`,
		`{"query":{"term":{"k":{"value":"a","boost":2.5}}}}`,
		`{"query":{"match":{"txt":{"query":"a","boost":2.5}}}}`,
		`{"query":{"terms":{"k":["a"],"boost":2.5}}}`,
		`{"query":{"query_string":{"query":"a","boost":2.5}}}`,
		`{"query":{"simple_query_string":{"query":"a","boost":2.5}}}`,
		`{"query":{"multi_match":{"query":"a","fields":["txt"],"boost":2.5}}}`,
		`{"query":{"ids":{"values":["1"],"boost":2.5}}}`,
		`{"query":{"exists":{"field":"k","boost":2.5}}}`,
		`{"query":{"constant_score":{"filter":{"match_all":{}},"boost":2.5}}}`,
		`{"query":{"bool":{"must":[{"match_all":{}}],"boost":2.5}}}`,
		`{"query":{"dis_max":{"queries":[{"match_all":{}}],"boost":2.5}}}`,
		`{"query":{"boosting":{"positive":{"match_all":{}},"negative":{"term":{"k":"z"}},"negative_boost":0.2,"boost":2.5}}}`,
		`{"query":{"function_score":{"query":{"match_all":{}},"boost":2.5}}}`,
		`{"query":{"script_score":{"query":{"match_all":{}},"script":{"source":"1.0"},"boost":2.5}}}`,
	}
	for _, bq := range boostQueries {
		var sr esast.SearchRequest
		if err := json.Unmarshal([]byte(bq), &sr); err != nil {
			t.Fatalf("unmarshal %s failed: %v", bq, err)
		}
		if b, ok := extractExplainTopBoostRound60(sr.Query); !ok || b != 2.5 {
			t.Fatalf("expected boost 2.5 for %s, got %v (ok=%v)", bq, b, ok)
		}
	}

	// 2. End-to-end Search Painless, Aggregations, Runtime Fields, Intervals, _execute, and Ingest _simulate
	_, h := newRound60CovServer(t, "8.17.0")
	code, _, _, raw := doRound60CovReq(t, h, http.MethodPut, "/r60-sp", `{
		"mappings":{
			"properties":{
				"tag":{"type":"keyword"},
				"body":{"type":"text"},
				"price":{"type":"double"},
				"qty":{"type":"long"},
				"ts":{"type":"date"}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create r60-sp failed: %d %s", code, raw)
	}
	_, _, _, _ = doRound60CovReq(t, h, http.MethodPost, "/_bulk?refresh=true", strings.Join([]string{
		`{"index":{"_index":"r60-sp","_id":"1"}}`,
		`{"tag":"alpha","body":"quick brown fox","price":10.5,"qty":2,"ts":"2024-03-01T00:00:00Z"}`,
		`{"index":{"_index":"r60-sp","_id":"2"}}`,
		`{"tag":"beta","body":"quick lazy dog","price":25.0,"qty":4,"ts":"2024-03-02T00:00:00Z"}`,
		"",
	}, "\n"), nil)

	richSearch := `{
		"runtime_mappings":{
			"rt_long":{"type":"long","script":{"source":"emit(doc['qty'].value * 10);"}},
			"rt_kw":{"type":"keyword","script":{"source":"emit(doc['tag'].value + '-rt');"}}
		},
		"query":{
			"script_score":{
				"query":{
					"bool":{
						"must":[{"intervals":{"body":{"match":{"query":"quick","filter":{"script":{"source":"interval.start >= 0"}}}}}}],
						"filter":[{"script":{"script":{"source":"doc['qty'].value >= 1"}}}]
					}
				},
				"script":{"source":"_score + saturation(doc['price'].value, 5.0)"}
			}
		},
		"fields":["rt_long","rt_kw"],
		"script_fields":{
			"sf_ok":{"script":{"source":"doc['price'].value * doc['qty'].value"}},
			"sf_ignored":{"script":{"source":"1 / 0"},"ignore_failure":true}
		},
		"sort":[{"_script":{"type":"number","order":"desc","script":{"source":"doc['price'].value"}}}],
		"aggs":{
			"by_tag":{
				"terms":{"script":{"source":"doc['tag'].value"}},
				"aggs":{
					"w_avg":{"weighted_avg":{"value":{"script":{"source":"doc['price'].value"}},"weight":{"script":{"source":"doc['qty'].value"}}}},
					"bs":{"bucket_script":{"buckets_path":{"w":"w_avg"},"script":{"source":"params.w * 2"}}},
					"sel":{"bucket_selector":{"buckets_path":{"w":"w_avg"},"script":{"source":"params.w > 0"}}}
				}
			},
			"sm":{
				"scripted_metric":{
					"init_script":"state.nums = [];",
					"map_script":"state.nums.add(doc['qty'].value);",
					"combine_script":"long s = 0; for (v in state.nums) { s += v; } return s;",
					"reduce_script":"long total = 0; for (a in states) { total += a; } return total;"
				}
			}
		}
	}`
	if c, _, _, rB := doRound60CovReq(t, h, http.MethodPost, "/r60-sp/_search", richSearch, nil); c != http.StatusOK {
		t.Fatalf("rich Painless search failed: %d %s", c, rB)
	}

	// Compile-error and cyclic-return error searches must return 400
	badSearches := []string{
		`{"query":{"script":{"script":{"source":"if ("}}}}`,
		`{"aggs":{"bad":{"terms":{"script":{"source":"while (true) {}"}}}}}`,
		`{"script_fields":{"cyc":{"script":{"source":"Map m = [:]; m.put('s', m); return m;"}}}}`,
		`{"aggs":{"sm":{"scripted_metric":{"init_script":"state.x = 1;","map_script":"Map m = [:]; m.put('s', m); state.m = m;","combine_script":"return state;","reduce_script":"return states;"}}}}`,
	}
	for _, bs := range badSearches {
		if c, _, _, rB := doRound60CovReq(t, h, http.MethodPost, "/r60-sp/_search", bs, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 for bad Painless search %s, got %d (%s)", bs, c, rB)
		}
	}

	// Exhaustive compile & runtime script error matrix across all query and aggregation types
	_ = validateSearchRequestScriptsRound60(nil)
	sampleHits := []HitRow{{ID: "1", Index: "r60-sp", Score: 1.0, Source: json.RawMessage(`{"tag":"alpha","body":"quick brown fox","price":10.5,"qty":2}`)}}
	scriptBearerTemplates := []string{
		`{"post_filter":{"script":{"script":{"source":"__S__"}}}}`,
		`{"runtime_mappings":{"rt":{"type":"keyword","script":{"source":"__S__"}}}}`,
		`{"sort":[{"_script":{"type":"number","script":{"source":"__S__"}}}]}`,
		`{"rescore":{"query":{"rescore_query":{"script":{"script":{"source":"__S__"}}}}}}`,
		`{"query":{"constant_score":{"filter":{"script":{"script":{"source":"__S__"}}}}}}`,
		`{"query":{"boosting":{"positive":{"script":{"script":{"source":"__S__"}}},"negative":{"match_all":{}},"negative_boost":0.2}}}`,
		`{"query":{"boosting":{"positive":{"match_all":{}},"negative":{"script":{"script":{"source":"__S__"}}},"negative_boost":0.2}}}`,
		`{"query":{"dis_max":{"queries":[{"script":{"script":{"source":"__S__"}}}]}}}`,
		`{"query":{"nested":{"path":"p","query":{"script":{"script":{"source":"__S__"}}}}}}`,
		`{"query":{"has_child":{"type":"c","query":{"script":{"script":{"source":"__S__"}}}}}}`,
		`{"query":{"has_parent":{"parent_type":"p","query":{"script":{"script":{"source":"__S__"}}}}}}`,
		`{"query":{"pinned":{"ids":["1"],"organic":{"script":{"script":{"source":"__S__"}}}}}}`,
		`{"query":{"function_score":{"query":{"match_all":{}},"functions":[{"filter":{"match_all":{}},"script_score":{"script":{"source":"__S__"}}}]}}}`,
		`{"query":{"intervals":{"body":{"prefix":{"prefix":"qu","filter":{"script":{"source":"__S__"}}}}}}}`,
		`{"query":{"intervals":{"body":{"wildcard":{"pattern":"qu*","filter":{"script":{"source":"__S__"}}}}}}}`,
		`{"query":{"intervals":{"body":{"fuzzy":{"term":"quik","filter":{"script":{"source":"__S__"}}}}}}}`,
		`{"query":{"intervals":{"body":{"all_of":{"intervals":[{"match":{"query":"quick"}}],"filter":{"script":{"source":"__S__"}}}}}}}`,
		`{"query":{"intervals":{"body":{"any_of":{"intervals":[{"match":{"query":"quick"}}],"filter":{"script":{"source":"__S__"}}}}}}}`,
		`{"aggs":{"a":{"histogram":{"interval":5,"script":{"source":"__S__"}}}}}`,
		`{"aggs":{"a":{"date_histogram":{"calendar_interval":"1d","script":{"source":"__S__"}}}}}`,
		`{"aggs":{"a":{"range":{"ranges":[{"to":10}],"script":{"source":"__S__"}}}}}`,
		`{"aggs":{"a":{"avg":{"script":{"source":"__S__"}}}}}`,
		`{"aggs":{"a":{"weighted_avg":{"value":{"script":{"source":"__S__"}},"weight":{"field":"qty"}}}}}`,
		`{"aggs":{"a":{"weighted_avg":{"value":{"field":"price"},"weight":{"script":{"source":"__S__"}}}}}`,
		`{"aggs":{"a":{"percentiles":{"script":{"source":"__S__"}}}}}`,
		`{"aggs":{"a":{"percentile_ranks":{"values":[10],"script":{"source":"__S__"}}}}}`,
		`{"aggs":{"a":{"boxplot":{"script":{"source":"__S__"}}}}}`,
		`{"aggs":{"a":{"string_stats":{"script":{"source":"__S__"}}}}}`,
		`{"aggs":{"a":{"scripted_metric":{"init_script":"__S__","map_script":"1","combine_script":"1","reduce_script":"1"}}}}`,
		`{"aggs":{"a":{"scripted_metric":{"init_script":"1","map_script":"__S__","combine_script":"1","reduce_script":"1"}}}}`,
		`{"aggs":{"a":{"scripted_metric":{"init_script":"1","map_script":"1","combine_script":"__S__","reduce_script":"1"}}}}`,
		`{"aggs":{"a":{"scripted_metric":{"init_script":"1","map_script":"1","combine_script":"1","reduce_script":"__S__"}}}}`,
		`{"aggs":{"t":{"terms":{"field":"tag"},"aggs":{"bs":{"bucket_script":{"buckets_path":{"c":"_count"},"script":{"source":"__S__"}}}}}}}`,
		`{"aggs":{"t":{"terms":{"field":"tag"},"aggs":{"bs":{"bucket_selector":{"buckets_path":{"c":"_count"},"script":{"source":"__S__"}}}}}}}`,
		`{"aggs":{"t":{"histogram":{"field":"qty","interval":1},"aggs":{"mf":{"moving_fn":{"buckets_path":"_count","window":2,"script":"__S__"}}}}}}`,
		`{"aggs":{"f":{"filter":{"script":{"script":{"source":"__S__"}}}}}}`,
		`{"aggs":{"fs":{"filters":{"filters":{"f1":{"script":{"script":{"source":"__S__"}}}}}}}}`,
	}
	for _, tmpl := range scriptBearerTemplates {
		var srComp esast.SearchRequest
		if err := json.Unmarshal([]byte(strings.ReplaceAll(tmpl, "__S__", "if (")), &srComp); err == nil {
			if cErr := validateSearchRequestScriptsRound60(&srComp); cErr == nil {
				t.Fatalf("expected compile error for template %s", tmpl)
			}
		}
		var srRun esast.SearchRequest
		if err := json.Unmarshal([]byte(strings.ReplaceAll(tmpl, "__S__", "int z = 0; return 1 / z;")), &srRun); err == nil {
			_ = validateRuntimeSearchScriptsOnHitsRound60(nil, &srRun, sampleHits)
		}
	}

	// _scripts/painless/_execute + _ingest/pipeline/_simulate with Processors.*
	execBody := `{
		"script":{"source":"emit(doc['qty'].value * 3);"},
		"context":"long_field",
		"context_setup":{"index":"r60-sp","document":{"qty":7}}
	}`
	if c, _, _, rB := doRound60CovReq(t, h, http.MethodPost, "/_scripts/painless/_execute", execBody, nil); c != http.StatusOK {
		t.Fatalf("_scripts/painless/_execute failed: %d %s", c, rB)
	}
	simBody := `{
		"pipeline":{
			"processors":[
				{"script":{"source":"Processors.uppercase(ctx, 'tag'); Processors.bytes(ctx, 'sz');"}}
			]
		},
		"docs":[{"_index":"r60-sp","_id":"1","_source":{"tag":"ingest","sz":"4kb"}}]
	}`
	if c, _, _, rB := doRound60CovReq(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", simBody, nil); c != http.StatusOK {
		t.Fatalf("_ingest/pipeline/_simulate failed: %d %s", c, rB)
	}
}

func TestRound60CoverageTranspilerHooksMappingsTypedKeysHDRMaxBuckets(t *testing.T) {
	srv, h := newRound60CovServer(t, "8.17.0")

	// 1. Field mapping defaults & metadata across all types
	applyFieldMappingEntryRound60(nil, schema.FieldBinding{}, true)
	fieldTypes := []string{
		"text", "match_only_text", "annotated-text", "search_as_you_type",
		"keyword", "constant_keyword", "long", "date", "date_nanos",
		"boolean", "ip", "object",
	}
	for _, ft := range fieldTypes {
		fd := map[string]any{"type": ft}
		fb := schema.FieldBinding{
			ESType:              ft,
			Meta:                map[string]string{"unit": "ms"},
			Analyzer:            "standard",
			SearchAnalyzer:      "standard",
			LowercaseNormalizer: ft == "keyword",
			IgnoreAbove:         256,
			ScalingFactor:       100,
			HasConstantValue:    ft == "constant_keyword",
			ConstantValue:       "const",
			Relations:           map[string]any{"p": "c"},
		}
		applyFieldMappingEntryRound60(fd, fb, true)
	}

	code, _, _, raw := doRound60CovReq(t, h, http.MethodPut, "/r60-hooks", `{
		"mappings":{
			"properties":{
				"k":{"type":"keyword","meta":{"env":"prod"}},
				"t":{"type":"text"},
				"mot":{"type":"match_only_text"},
				"ck":{"type":"constant_keyword","value":"v"},
				"latency":{"type":"double"},
				"dt":{"type":"date"},
				"flag":{"type":"boolean"}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create r60-hooks failed: %d %s", code, raw)
	}
	if c, _, _, rB := doRound60CovReq(t, h, http.MethodGet, "/r60-hooks/_mapping/field/*?include_defaults=true", "", nil); c != http.StatusOK {
		t.Fatalf("GET _mapping/field/*?include_defaults=true failed: %d %s", c, rB)
	}

	// 2. Seed docs and run HDR percentiles, percentile_ranks, typed_keys, agg meta, and terms partitions
	_, _, _, _ = doRound60CovReq(t, h, http.MethodPost, "/_bulk?refresh=true", strings.Join([]string{
		`{"index":{"_index":"r60-hooks","_id":"1"}}`,
		`{"k":"g1","t":"hello","ck":"v","latency":12.5,"dt":"2024-05-01T00:00:00Z","flag":true}`,
		`{"index":{"_index":"r60-hooks","_id":"2"}}`,
		`{"k":"g2","t":"world","ck":"v","latency":45.0,"dt":"2024-05-02T00:00:00Z","flag":false}`,
		`{"index":{"_index":"r60-hooks","_id":"3"}}`,
		`{"k":"g1","t":"again","ck":"v","latency":80.0,"dt":"2024-05-03T00:00:00Z","flag":true}`,
		"",
	}, "\n"), nil)

	hdrAndTypedSearch := `{
		"size":0,
		"aggs":{
			"p_keyed":{
				"meta":{"owner":"sre"},
				"percentiles":{"field":"latency","percents":[50,95],"hdr":{"number_of_significant_value_digits":3}}
			},
			"p_unkeyed":{
				"percentiles":{"script":{"source":"doc['latency'].value"},"keyed":false,"hdr":{"number_of_significant_value_digits":2}}
			},
			"pr":{
				"percentile_ranks":{"field":"latency","values":[20,60],"keyed":false,"hdr":{"number_of_significant_value_digits":3}}
			},
			"filtered_hdr":{
				"filter":{"term":{"flag":true}},
				"aggs":{
					"sub_p":{"percentiles":{"field":"latency","hdr":{"number_of_significant_value_digits":2}}}
				}
			},
			"part_terms":{
				"terms":{"field":"k","include":{"partition":0,"num_partitions":2}}
			}
		}
	}`
	if c, _, resp, rB := doRound60CovReq(t, h, http.MethodPost, "/r60-hooks/_search?typed_keys=true", hdrAndTypedSearch, nil); c != http.StatusOK || resp["aggregations"] == nil {
		t.Fatalf("HDR + typed_keys search failed: %d %s", c, rB)
	}

	// 3. Direct helper edge branches in round60_transpiler_hooks.go
	idxSch := srv.resolvePrimarySchemaForTypedKeysRound60(context.Background(), "r60-hooks")
	for _, v := range []any{nil, float64(1.5), math.NaN(), float32(2.5), int(3), int64(4), uint64(5), json.Number("6.5"), true, false, "7.25", "2024-05-01T00:00:00Z", "not-num"} {
		_, _ = coerceHDRFloatRound60(v, idxSch, "dt")
	}

	for _, dt := range []schema.DorisScalarType{schema.DorisLargeInt, schema.DorisBigInt, schema.DorisDouble, schema.DorisBoolean} {
		customSch := &schema.IndexSchema{
			Fields: map[string]schema.FieldBinding{
				"f": {ESFieldPath: "f", DorisType: dt},
			},
		}
		_ = termsFieldTypeRound60(&esast.TermsAggSpec{Field: "f"}, customSch)
	}
	if termsFieldTypeRound60(nil, nil) != "" {
		t.Fatal("expected empty string for nil TermsAggSpec")
	}
	if termsFieldTypeRound60(&esast.TermsAggSpec{Script: "1"}, nil) != "keyword" {
		t.Fatal("expected keyword for script-only TermsAggSpec")
	}
	_ = matchesTermsFilterPrecompiledWithSchemaRound60("g1", map[string]any{"partition": 0, "num_partitions": 2}, nil, "keyword")
	_ = matchesTermsFilterPrecompiledWithSchemaRound60("g1", map[string]any{"partition": 5, "num_partitions": 2}, nil, "keyword")
	_ = formatDateHistogramKeyAsStringRound60(1700000000000, nil)
	_ = formatDateHistogramKeyAsStringRound60(1700000000000, &esast.DateHistogramAggSpec{TimeZone: "+02:00"})
	_ = formatDateHistogramKeyAsStringRound60(1700000000000, &esast.DateHistogramAggSpec{Format: "yyyy-MM-dd"})

	// Exercise applyTypedKeysToAggregationsWithSchemaRound60 & attachAllAggMetasRound60 across []map, []any, and map buckets
	var sr esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"aggs":{
			"a1":{"meta":{"m":1},"terms":{"field":"k"},"aggs":{"sub":{"avg":{"field":"latency"}}}},
			"a2":{"meta":{"m":2},"terms":{"field":"k"},"aggs":{"sub":{"avg":{"field":"latency"}}}},
			"a3":{"meta":{"m":3},"filters":{"filters":{"f1":{"match_all":{}}}},"aggs":{"sub":{"avg":{"field":"latency"}}}},
			"a4":{"meta":{"m":4},"filter":{"match_all":{}},"aggs":{"sub":{"avg":{"field":"latency"}}}}
		}
	}`), &sr)
	aggsOut := map[string]any{
		"a1": map[string]any{"buckets": []map[string]any{{"key": "x", "sub": map[string]any{"value": 1.0}}}},
		"a2": map[string]any{"buckets": []any{map[string]any{"key": "x", "sub": map[string]any{"value": 1.0}}}},
		"a3": map[string]any{"buckets": map[string]any{"f1": map[string]any{"sub": map[string]any{"value": 1.0}}}},
		"a4": map[string]any{"doc_count": 1, "sub": map[string]any{"value": 1.0}},
	}
	attachAllAggMetasRound60(aggsOut, sr.Aggs)

	// search.max_buckets enforcement (countAggBucketsRecursiveRound60 + too_many_buckets_exception)
	_, _, _, _ = doRound60CovReq(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"search.max_buckets":"2"}}`, nil)
	if err := srv.validateSearchMaxBucketsRound60(map[string]any{"aggregations": aggsOut}, sr.Aggs); err == nil || !strings.Contains(err.Error(), "too_many_buckets_exception") {
		t.Fatalf("expected too_many_buckets_exception, got %v", err)
	}
	applyTypedKeysToAggregationsWithSchemaRound60(aggsOut, sr.Aggs, idxSch)
}
