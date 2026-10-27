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
	batches           map[string]*coalesceBatch
	loadFn            func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error
	coalescedRequests int64
	coalescedFlushes  int64
}

func newStreamLoadCoalescer(loadFn func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error) *StreamLoadCoalescer {
	return &StreamLoadCoalescer{
		maxBytes: DefaultBulkCoalesceMaxBytes,
		batches:  make(map[string]*coalesceBatch),
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
	if window <= 0 {
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
		if !syncRefresh {
			batchRef := b
			b.timer = time.AfterFunc(window, func() {
				c.onTimerFlush(table, batchRef)
			})
		}
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
		c.mu.Unlock()
		flushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c.executeBatch(flushCtx, table, b, syncRefresh)
		return b.err
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

// FlushAll stops any pending group-commit timers and synchronously flushes all buffered batches.
func (c *StreamLoadCoalescer) FlushAll(ctx context.Context) error {
	c.mu.Lock()
	if len(c.batches) == 0 {
		c.mu.Unlock()
		return nil
	}
	pending := make(map[string]*coalesceBatch, len(c.batches))
	for tbl, b := range c.batches {
		if b.timer != nil {
			b.timer.Stop()
		}
		pending[tbl] = b
	}
	c.batches = make(map[string]*coalesceBatch)
	c.mu.Unlock()

	var firstErr error
	for tbl, b := range pending {
		c.executeBatch(ctx, tbl, b, true)
		if b.err != nil && firstErr == nil {
			firstErr = b.err
		}
	}
	return firstErr
}

func (c *StreamLoadCoalescer) onTimerFlush(table string, target *coalesceBatch) {
	c.mu.Lock()
	cur, ok := c.batches[table]
	if !ok || cur != target {
		c.mu.Unlock()
		return
	}
	delete(c.batches, table)
	c.mu.Unlock()

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
	raw       []byte
	expiresAt time.Time
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

func buildQueryCacheKey(targets []string, req *esast.SearchRequest) (string, bool) {
	if req == nil {
		return "", false
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return "", false
	}
	return strings.Join(targets, ",") + "\x00" + string(reqBytes), true
}

// Get looks up a cached search response for `(targets, req)` and returns a fresh unmarshaled copy.
func (qc *QueryResultCache) Get(targets []string, req *esast.SearchRequest) (map[string]any, bool) {
	qc.mu.RLock()
	ttl := qc.ttl
	if ttl <= 0 {
		qc.mu.RUnlock()
		return nil, false
	}
	key, ok := buildQueryCacheKey(targets, req)
	if !ok {
		qc.mu.RUnlock()
		return nil, false
	}
	entry, found := qc.entries[key]
	qc.mu.RUnlock()

	if !found || time.Now().After(entry.expiresAt) {
		atomic.AddInt64(&qc.misses, 1)
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(entry.raw))
	dec.UseNumber()
	var decoded map[string]any
	if err := dec.Decode(&decoded); err != nil {
		atomic.AddInt64(&qc.misses, 1)
		return nil, false
	}
	normalized, _ := normalizeCacheJSONValue(decoded).(map[string]any)
	atomic.AddInt64(&qc.hits, 1)
	return normalized, true
}

// Put stores a serialized snapshot of `resp` in the cache for `(targets, req)`.
func (qc *QueryResultCache) Put(targets []string, req *esast.SearchRequest, resp map[string]any) {
	qc.mu.Lock()
	defer qc.mu.Unlock()
	if qc.ttl <= 0 || resp == nil {
		return
	}
	key, ok := buildQueryCacheKey(targets, req)
	if !ok {
		return
	}
	raw, err := json.Marshal(resp)
	if err != nil {
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
		raw:       raw,
		expiresAt: now.Add(qc.ttl),
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
		if fv, err := typed.Float64(); err == nil {
			return fv
		}
		return typed.String()
	default:
		return v
	}
}
