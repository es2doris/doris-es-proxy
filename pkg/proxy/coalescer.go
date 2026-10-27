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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

const (
	// DefaultBulkCoalesceMaxBytes is the default per-table byte threshold (8 MiB) at which a
	// coalesced Stream Load batch is flushed immediately before its time window expires.
	DefaultBulkCoalesceMaxBytes = 8 * 1024 * 1024
	// DefaultQueryCacheMaxEntries bounds the number of cached search responses when --query-cache-ttl > 0.
	DefaultQueryCacheMaxEntries = 512
	// DefaultQueryCacheMaxEntryBytes bounds the serialized size (1 MiB) of a single cached search response.
	DefaultQueryCacheMaxEntryBytes = 1 * 1024 * 1024
)

type coalesceBatch struct {
	buf   bytes.Buffer
	done  chan struct{}
	err   error
	timer *time.Timer
}

// StreamLoadCoalescer implements group-commit micro-batching across concurrent `/_bulk` and
// single-document `PUT /{index}/_doc/{id}` requests targeting the same Apache Doris table,
// preventing tablet version exhaustion (`-235 TOO_MANY_VERSIONS`) under high-concurrency writes.
type StreamLoadCoalescer struct {
	mu                sync.Mutex
	window            time.Duration
	maxBytes          int
	closed            bool
	batches           map[string]*coalesceBatch
	inflight          map[*coalesceBatch]string
	loadFn            func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error
	coalescedRequests int64
	coalescedFlushes  int64
}

func newStreamLoadCoalescer(loadFn func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error) *StreamLoadCoalescer {
	return &StreamLoadCoalescer{
		maxBytes: DefaultBulkCoalesceMaxBytes,
		batches:  make(map[string]*coalesceBatch),
		inflight: make(map[*coalesceBatch]string),
		loadFn:   loadFn,
	}
}

// Configure sets the group-commit time window and maximum batch byte threshold.
// Setting `window <= 0` disables micro-batch coalescing (each write executes immediately).
func (c *StreamLoadCoalescer) Configure(window time.Duration, maxBytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.window = window
	if maxBytes <= 0 {
		maxBytes = DefaultBulkCoalesceMaxBytes
	}
	c.maxBytes = maxBytes
}

// Stats returns the total number of coalesced write requests and executed backend Stream Load flushes.
func (c *StreamLoadCoalescer) Stats() (requests, flushes int64) {
	return atomic.LoadInt64(&c.coalescedRequests), atomic.LoadInt64(&c.coalescedFlushes)
}

// Submit enqueues `ndjson` for `table`. When coalescing is disabled (`window <= 0`), it executes
// `loadFn` directly. When coalescing is enabled, concurrent callers within `window` share a single
// Doris Stream Load transaction and receive the shared commit result.
func (c *StreamLoadCoalescer) Submit(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
	if len(bytes.TrimSpace(ndjson)) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	window := c.window
	maxBytes := c.maxBytes
	if window <= 0 || c.closed {
		c.mu.Unlock()
		return c.loadFn(ctx, table, ndjson, syncRefresh)
	}

	atomic.AddInt64(&c.coalescedRequests, 1)
	b, exists := c.batches[table]
	if !exists {
		b = &coalesceBatch{
			done: make(chan struct{}),
		}
		c.batches[table] = b
	}
	b.buf.Write(ndjson)
	if ndjson[len(ndjson)-1] != '\n' {
		b.buf.WriteByte('\n')
	}

	if syncRefresh || b.buf.Len() >= maxBytes {
		if b.timer != nil {
			b.timer.Stop()
		}
		delete(c.batches, table)
		c.inflight[b] = table
		c.mu.Unlock()
		defer func() {
			c.mu.Lock()
			delete(c.inflight, b)
			c.mu.Unlock()
		}()
		flushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c.executeBatch(flushCtx, table, b, syncRefresh)
		return b.err
	}
	if b.timer == nil {
		batchRef := b
		b.timer = time.AfterFunc(window, func() {
			c.onTimerFlush(table, batchRef)
		})
	}
	doneCh := b.done
	c.mu.Unlock()

	select {
	case <-doneCh:
		return b.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// FlushTable stops any pending group-commit timer for `table`, synchronously flushes its buffered
// batch, and waits for any in-flight flush to complete so subsequent point-lookups observe all
// previously submitted writes.
func (c *StreamLoadCoalescer) FlushTable(ctx context.Context, table string) error {
	c.mu.Lock()
	var waitChs []chan struct{}
	for ib, tbl := range c.inflight {
		if tbl == table {
			waitChs = append(waitChs, ib.done)
		}
	}
	b, exists := c.batches[table]
	if exists {
		if b.timer != nil {
			b.timer.Stop()
		}
		delete(c.batches, table)
		c.inflight[b] = table
	}
	c.mu.Unlock()

	if exists {
		func() {
			defer func() {
				c.mu.Lock()
				delete(c.inflight, b)
				c.mu.Unlock()
			}()
			flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			c.executeBatch(flushCtx, table, b, true)
		}()
	}
	for _, ch := range waitChs {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if exists {
		return b.err
	}
	return nil
}

// FlushAll stops any pending group-commit timers and synchronously flushes all buffered batches.
func (c *StreamLoadCoalescer) FlushAll(ctx context.Context) error {
	c.mu.Lock()
	var waitChs []chan struct{}
	for ib := range c.inflight {
		waitChs = append(waitChs, ib.done)
	}
	if len(c.batches) == 0 {
		c.mu.Unlock()
		for _, ch := range waitChs {
			select {
			case <-ch:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	pending := make(map[string]*coalesceBatch, len(c.batches))
	for tbl, b := range c.batches {
		if b.timer != nil {
			b.timer.Stop()
		}
		pending[tbl] = b
		c.inflight[b] = tbl
	}
	c.batches = make(map[string]*coalesceBatch)
	c.mu.Unlock()

	var firstErr error
	for tbl, b := range pending {
		flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		c.executeBatch(flushCtx, tbl, b, true)
		cancel()
		c.mu.Lock()
		delete(c.inflight, b)
		c.mu.Unlock()
		if b.err != nil && firstErr == nil {
			firstErr = b.err
		}
	}
	for _, ch := range waitChs {
		select {
		case <-ch:
		case <-ctx.Done():
			if firstErr == nil {
				firstErr = ctx.Err()
			}
		}
	}
	return firstErr
}

// Close marks the coalescer as closed, flushes all pending batches, and waits for any in-flight
// timer or byte-threshold flushes to finish before returning.
func (c *StreamLoadCoalescer) Close(ctx context.Context) error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.FlushAll(ctx)
}

func (c *StreamLoadCoalescer) onTimerFlush(table string, target *coalesceBatch) {
	c.mu.Lock()
	cur, ok := c.batches[table]
	if !ok || cur != target {
		c.mu.Unlock()
		return
	}
	delete(c.batches, table)
	c.inflight[target] = table
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.inflight, target)
		c.mu.Unlock()
	}()

	flushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c.executeBatch(flushCtx, table, target, false)
}

func (c *StreamLoadCoalescer) executeBatch(ctx context.Context, table string, b *coalesceBatch, syncRefresh bool) {
	atomic.AddInt64(&c.coalescedFlushes, 1)
	b.err = c.loadFn(ctx, table, b.buf.Bytes(), syncRefresh)
	close(b.done)
}

type queryCacheEntry struct {
	raw             []byte
	unindexedFields []string
	expiresAt       time.Time
}

// QueryResultCache caches compiled Elasticsearch `/_search` responses for a configurable TTL
// and automatically invalidates all cached entries whenever any write or DDL operation occurs.
type QueryResultCache struct {
	mu         sync.RWMutex
	ttl        time.Duration
	maxEntries int
	entries    map[string]queryCacheEntry
	hits       int64
	misses     int64
}

func newQueryResultCache() *QueryResultCache {
	return &QueryResultCache{
		maxEntries: DefaultQueryCacheMaxEntries,
		entries:    make(map[string]queryCacheEntry),
	}
}

// Configure sets the cache TTL and maximum entry capacity. Setting `ttl <= 0` disables caching.
func (qc *QueryResultCache) Configure(ttl time.Duration, maxEntries int) {
	qc.mu.Lock()
	defer qc.mu.Unlock()
	qc.ttl = ttl
	if maxEntries <= 0 {
		maxEntries = DefaultQueryCacheMaxEntries
	}
	qc.maxEntries = maxEntries
	if ttl <= 0 {
		qc.entries = make(map[string]queryCacheEntry)
	}
}

// Enabled reports whether the query cache is active (`ttl > 0`).
func (qc *QueryResultCache) Enabled() bool {
	qc.mu.RLock()
	defer qc.mu.RUnlock()
	return qc.ttl > 0
}

// Stats returns the cumulative number of query cache hits and misses.
func (qc *QueryResultCache) Stats() (hits, misses int64) {
	return atomic.LoadInt64(&qc.hits), atomic.LoadInt64(&qc.misses)
}

// InvalidateAll clears all cached query responses (invoked on StreamLoad and DDL writes).
func (qc *QueryResultCache) InvalidateAll() {
	qc.mu.Lock()
	if len(qc.entries) > 0 {
		qc.entries = make(map[string]queryCacheEntry)
	}
	qc.mu.Unlock()
}

func containsNowDateMath(req *esast.SearchRequest, reqBytes []byte) bool {
	lowerBytes := bytes.ToLower(reqBytes)
	for _, pat := range [][]byte{
		[]byte(`"now`),
		[]byte("now-"),
		[]byte("now+"),
		[]byte("now/"),
		[]byte("to now"),
		[]byte(":now"),
		[]byte(">now"),
		[]byte("<now"),
		[]byte("=now"),
		[]byte("(now"),
	} {
		if bytes.Contains(lowerBytes, pat) {
			return true
		}
	}
	if req != nil {
		if queryContainsNow(req.Query) || queryContainsNow(req.PostFilter) {
			return true
		}
		for i := range req.KNN {
			for j := range req.KNN[i].Filter {
				if queryContainsNow(&req.KNN[i].Filter[j]) {
					return true
				}
			}
		}
		if aggsContainNow(req.EffectiveAggs()) {
			return true
		}
	}
	return false
}

func aggsContainNow(aggs map[string]esast.AggSpec) bool {
	for _, agg := range aggs {
		if queryContainsNow(agg.Filter) {
			return true
		}
		if agg.Filters != nil {
			for k := range agg.Filters.Filters {
				fq := agg.Filters.Filters[k]
				if queryContainsNow(&fq) {
					return true
				}
			}
			for i := range agg.Filters.AnonymousFilters {
				fq := agg.Filters.AnonymousFilters[i]
				if queryContainsNow(&fq) {
					return true
				}
			}
		}
		if agg.DateHistogram != nil {
			if boundsContainNow(agg.DateHistogram.ExtendedBounds) || boundsContainNow(agg.DateHistogram.HardBounds) {
				return true
			}
		}
		if agg.DateRange != nil {
			for _, r := range agg.DateRange.Ranges {
				if boundValContainsNow(r.From) || boundValContainsNow(r.To) {
					return true
				}
			}
		}
		if aggsContainNow(agg.SubAggs()) {
			return true
		}
	}
	return false
}

func boundsContainNow(b *esast.HistogramBoundsSpec) bool {
	if b == nil {
		return false
	}
	return boundValContainsNow(b.Min) || boundValContainsNow(b.Max)
}

func boundValContainsNow(v any) bool {
	if s, ok := v.(string); ok {
		return strings.Contains(strings.ToLower(s), "now")
	}
	return false
}

func queryContainsNow(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.QueryString != nil && strings.Contains(strings.ToLower(q.QueryString.Query), "now") {
		return true
	}
	if q.SimpleQueryString != nil && strings.Contains(strings.ToLower(q.SimpleQueryString.Query), "now") {
		return true
	}
	for _, rc := range q.Range {
		if boundValContainsNow(rc.GT) || boundValContainsNow(rc.GTE) || boundValContainsNow(rc.LT) || boundValContainsNow(rc.LTE) || boundValContainsNow(rc.From) || boundValContainsNow(rc.To) {
			return true
		}
	}
	if q.ConstantScore != nil && queryContainsNow(&q.ConstantScore.Filter) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryContainsNow(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil && (queryContainsNow(&q.Boosting.Positive) || queryContainsNow(&q.Boosting.Negative)) {
		return true
	}
	if q.Nested != nil && queryContainsNow(&q.Nested.Query) {
		return true
	}
	if q.FunctionScore != nil {
		if queryContainsNow(q.FunctionScore.Query) {
			return true
		}
		for i := range q.FunctionScore.Functions {
			if queryContainsNow(q.FunctionScore.Functions[i].Filter) {
				return true
			}
		}
	}
	if q.ScriptScore != nil && queryContainsNow(q.ScriptScore.Query) {
		return true
	}
	if q.KNN != nil {
		for i := range q.KNN.Filter {
			if queryContainsNow(&q.KNN.Filter[i]) {
				return true
			}
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryContainsNow(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryContainsNow(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryContainsNow(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryContainsNow(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	return false
}

func buildQueryCacheKey(targets []string, req *esast.SearchRequest) (string, bool) {
	if req == nil || req.PIT != nil {
		return "", false
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return "", false
	}
	if containsNowDateMath(req, reqBytes) {
		return "", false
	}
	return strings.Join(targets, ",") + "\x00" + string(reqBytes), true
}

// Get looks up a cached search response for `(targets, req)` and returns a fresh unmarshaled copy.
func (qc *QueryResultCache) Get(targets []string, req *esast.SearchRequest) (map[string]any, bool) {
	resp, _, ok := qc.GetWithMeta(targets, req)
	return resp, ok
}

// GetWithMeta looks up a cached search response and its associated unindexed fields for `(targets, req)`.
func (qc *QueryResultCache) GetWithMeta(targets []string, req *esast.SearchRequest) (map[string]any, []string, bool) {
	if !qc.Enabled() {
		return nil, nil, false
	}
	key, ok := buildQueryCacheKey(targets, req)
	if !ok {
		return nil, nil, false
	}
	qc.mu.RLock()
	if qc.ttl <= 0 {
		qc.mu.RUnlock()
		return nil, nil, false
	}
	entry, found := qc.entries[key]
	qc.mu.RUnlock()

	if !found || time.Now().After(entry.expiresAt) {
		atomic.AddInt64(&qc.misses, 1)
		return nil, nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(entry.raw))
	dec.UseNumber()
	var decoded map[string]any
	if err := dec.Decode(&decoded); err != nil {
		atomic.AddInt64(&qc.misses, 1)
		return nil, nil, false
	}
	normalized, _ := normalizeCacheJSONValue(decoded).(map[string]any)
	atomic.AddInt64(&qc.hits, 1)
	return normalized, append([]string(nil), entry.unindexedFields...), true
}

// Put stores a serialized snapshot of `resp` in the cache for `(targets, req)`.
func (qc *QueryResultCache) Put(targets []string, req *esast.SearchRequest, resp map[string]any) {
	qc.PutWithMeta(targets, req, resp, nil)
}

// PutWithMeta stores a serialized snapshot of `resp` and its unindexed fields in the cache for `(targets, req)`.
func (qc *QueryResultCache) PutWithMeta(targets []string, req *esast.SearchRequest, resp map[string]any, unindexedFields []string) {
	if resp == nil || !qc.Enabled() {
		return
	}
	key, ok := buildQueryCacheKey(targets, req)
	if !ok {
		return
	}
	raw, err := json.Marshal(resp)
	if err != nil || len(raw) > DefaultQueryCacheMaxEntryBytes {
		return
	}
	unindexedCopy := append([]string(nil), unindexedFields...)

	qc.mu.Lock()
	defer qc.mu.Unlock()
	if qc.ttl <= 0 {
		return
	}
	now := time.Now()
	if len(qc.entries) >= qc.maxEntries {
		for k, v := range qc.entries {
			if now.After(v.expiresAt) {
				delete(qc.entries, k)
			}
		}
		if len(qc.entries) >= qc.maxEntries {
			for k := range qc.entries {
				delete(qc.entries, k)
				break
			}
		}
	}
	qc.entries[key] = queryCacheEntry{
		raw:             raw,
		unindexedFields: unindexedCopy,
		expiresAt:       now.Add(qc.ttl),
	}
}

func normalizeCacheJSONValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		for k, val := range typed {
			typed[k] = normalizeCacheJSONValue(val)
		}
		return typed
	case []any:
		for i, elem := range typed {
			typed[i] = normalizeCacheJSONValue(elem)
		}
		return typed
	case json.Number:
		if iv, err := typed.Int64(); err == nil {
			return iv
		}
		if strings.ContainsAny(typed.String(), ".eE") {
			if fv, err := typed.Float64(); err == nil {
				return fv
			}
		}
		return typed
	default:
		return v
	}
}
