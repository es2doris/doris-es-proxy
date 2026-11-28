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
	"net/url"
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

const maxConcurrentCoalescerFlushes = 16

type coalesceSubmission struct {
	data     []byte
	canceled bool
	docIDs   []string
}

type coalesceBatch struct {
	buf           bytes.Buffer
	submissions   []*coalesceSubmission
	pendingDocIDs map[string]int
	totalBytes    int
	flushing      bool
	done          chan struct{}
	err           error
	timer         *time.Timer
	activeWaiters int64
}

type tableCoalesceShard struct {
	mu       sync.Mutex
	batch    *coalesceBatch
	inflight map[*coalesceBatch]struct{}
}

// StreamLoadCoalescer implements per-table sharded group-commit micro-batching across concurrent
// `/_bulk` and single-document `PUT /{index}/_doc/{id}` requests targeting Apache Doris tables,
// preventing tablet version exhaustion (`-235 TOO_MANY_VERSIONS`) without cross-table lock contention.
type StreamLoadCoalescer struct {
	shardsMu sync.RWMutex
	shards   map[string]*tableCoalesceShard

	// Legacy lock and maps retained only so white-box unit tests (e.g. round8_test.go) setting
	// c.batches directly continue to work; hot-path operations lock only the target table shard.
	mu                sync.Mutex
	window            time.Duration
	maxBytes          int
	closed            bool
	batches           map[string]*coalesceBatch
	inflight          map[*coalesceBatch]string
	windowNs          atomic.Int64
	maxBytesAtom      atomic.Int64
	closedFlag        atomic.Bool
	loadFn            func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error
	coalescedRequests int64
	coalescedFlushes  int64
}

func newStreamLoadCoalescer(loadFn func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error) *StreamLoadCoalescer {
	c := &StreamLoadCoalescer{
		shards:   make(map[string]*tableCoalesceShard),
		maxBytes: DefaultBulkCoalesceMaxBytes,
		batches:  make(map[string]*coalesceBatch),
		inflight: make(map[*coalesceBatch]string),
		loadFn:   loadFn,
	}
	c.maxBytesAtom.Store(int64(DefaultBulkCoalesceMaxBytes))
	return c
}

// Configure sets the group-commit time window and maximum batch byte threshold.
// Setting `window <= 0` disables micro-batch coalescing (each write executes immediately).
func (c *StreamLoadCoalescer) Configure(window time.Duration, maxBytes int) {
	if maxBytes <= 0 {
		maxBytes = DefaultBulkCoalesceMaxBytes
	}
	c.windowNs.Store(int64(window))
	c.maxBytesAtom.Store(int64(maxBytes))
	c.mu.Lock()
	c.window = window
	c.maxBytes = maxBytes
	c.mu.Unlock()
}

// Stats returns the total number of coalesced write requests and executed backend Stream Load flushes.
func (c *StreamLoadCoalescer) Stats() (requests, flushes int64) {
	return atomic.LoadInt64(&c.coalescedRequests), atomic.LoadInt64(&c.coalescedFlushes)
}

func (c *StreamLoadCoalescer) getShard(table string) *tableCoalesceShard {
	c.shardsMu.RLock()
	sh := c.shards[table]
	c.shardsMu.RUnlock()
	return sh
}

func (c *StreamLoadCoalescer) getOrCreateShard(table string) *tableCoalesceShard {
	c.shardsMu.RLock()
	sh := c.shards[table]
	c.shardsMu.RUnlock()
	if sh != nil {
		return sh
	}
	c.shardsMu.Lock()
	defer c.shardsMu.Unlock()
	if c.shards == nil {
		c.shards = make(map[string]*tableCoalesceShard)
	}
	if sh = c.shards[table]; sh == nil {
		sh = &tableCoalesceShard{
			inflight: make(map[*coalesceBatch]struct{}),
		}
		c.shards[table] = sh
	}
	return sh
}

type coalesceShardSnapshot struct {
	table string
	shard *tableCoalesceShard
}

func (c *StreamLoadCoalescer) snapshotShards() []coalesceShardSnapshot {
	c.shardsMu.RLock()
	defer c.shardsMu.RUnlock()
	if len(c.shards) == 0 {
		return nil
	}
	out := make([]coalesceShardSnapshot, 0, len(c.shards))
	for tbl, sh := range c.shards {
		out = append(out, coalesceShardSnapshot{table: tbl, shard: sh})
	}
	return out
}

func extractDocIDsFromNDJSON(ndjson []byte) []string {
	var docIDs []string
	var probe struct {
		ID string `json:"_id"`
	}
	start := 0
	for start < len(ndjson) {
		end := bytes.IndexByte(ndjson[start:], '\n')
		var line []byte
		if end < 0 {
			line = ndjson[start:]
			start = len(ndjson)
		} else {
			line = ndjson[start : start+end]
			start += end + 1
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || !bytes.Contains(line, []byte(`"_id"`)) {
			continue
		}
		probe.ID = ""
		if json.Unmarshal(line, &probe) == nil && probe.ID != "" {
			docIDs = append(docIDs, probe.ID)
		}
	}
	return docIDs
}

func deriveCoalescerFlushContext(ctx context.Context) (context.Context, context.CancelFunc) {
	now := time.Now()
	defaultDL := now.Add(30 * time.Second)
	if dl, hasDL := ctx.Deadline(); hasDL {
		if dl.Before(defaultDL) {
			defaultDL = dl
		}
		return context.WithDeadline(context.WithoutCancel(ctx), defaultDL)
	}
	return context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
}

// Submit enqueues `ndjson` for `table`. When coalescing is disabled (`window <= 0`), it executes
// `loadFn` directly. When coalescing is enabled, concurrent callers within `window` share a single
// Doris Stream Load transaction and receive the shared commit result without blocking other tables.
func (c *StreamLoadCoalescer) Submit(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
	if len(bytes.TrimSpace(ndjson)) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	window := time.Duration(c.windowNs.Load())
	maxBytes := int(c.maxBytesAtom.Load())
	if maxBytes <= 0 {
		maxBytes = DefaultBulkCoalesceMaxBytes
	}
	if window <= 0 || c.closedFlag.Load() {
		return c.loadFn(ctx, table, ndjson, syncRefresh)
	}

	docIDs := extractDocIDsFromNDJSON(ndjson)
	entryBytes := make([]byte, len(ndjson), len(ndjson)+1)
	copy(entryBytes, ndjson)
	if entryBytes[len(entryBytes)-1] != '\n' {
		entryBytes = append(entryBytes, '\n')
	}

	sh := c.getOrCreateShard(table)
	sh.mu.Lock()
	if c.closedFlag.Load() {
		sh.mu.Unlock()
		return c.loadFn(ctx, table, ndjson, syncRefresh)
	}

	atomic.AddInt64(&c.coalescedRequests, 1)
	b := sh.batch
	if b == nil {
		b = &coalesceBatch{
			pendingDocIDs: make(map[string]int),
			done:          make(chan struct{}),
		}
		sh.batch = b
	}
	if b.pendingDocIDs == nil {
		b.pendingDocIDs = make(map[string]int)
	}
	sub := &coalesceSubmission{data: entryBytes, docIDs: docIDs}
	b.submissions = append(b.submissions, sub)
	b.totalBytes += len(entryBytes)
	for _, id := range docIDs {
		b.pendingDocIDs[id]++
	}

	if syncRefresh || b.totalBytes >= maxBytes {
		if b.timer != nil {
			b.timer.Stop()
		}
		b.flushing = true
		sh.batch = nil
		sh.inflight[b] = struct{}{}
		sh.mu.Unlock()
		defer func() {
			sh.mu.Lock()
			delete(sh.inflight, b)
			sh.mu.Unlock()
		}()
		flushCtx, cancel := deriveCoalescerFlushContext(ctx)
		defer cancel()
		c.executeBatch(flushCtx, sh, table, b, syncRefresh)
		return b.err
	}
	atomic.AddInt64(&b.activeWaiters, 1)
	if b.timer == nil {
		batchRef := b
		shardRef := sh
		b.timer = time.AfterFunc(window, func() {
			c.onTimerFlush(shardRef, table, batchRef)
		})
	}
	doneCh := b.done
	sh.mu.Unlock()

	select {
	case <-doneCh:
		return b.err
	case <-ctx.Done():
		sh.mu.Lock()
		if !b.flushing && !sub.canceled {
			sub.canceled = true
			b.totalBytes -= len(sub.data)
			for _, id := range sub.docIDs {
				if cnt := b.pendingDocIDs[id]; cnt <= 1 {
					delete(b.pendingDocIDs, id)
				} else {
					b.pendingDocIDs[id] = cnt - 1
				}
			}
		}
		atomic.AddInt64(&b.activeWaiters, -1)
		sh.mu.Unlock()
		return ctx.Err()
	}
}

func batchContainsDocID(b *coalesceBatch, docID string) bool {
	if b == nil || docID == "" {
		return false
	}
	if b.pendingDocIDs != nil {
		return b.pendingDocIDs[docID] > 0
	}
	// Legacy fallback only when a synthetic batch bypassed Submit.
	idNeedle, err := json.Marshal(docID)
	if err != nil {
		return true
	}
	for _, sub := range b.submissions {
		if sub == nil || sub.canceled || !bytes.Contains(sub.data, idNeedle) {
			continue
		}
		for _, line := range bytes.Split(sub.data, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 || !bytes.Contains(line, idNeedle) {
				continue
			}
			var probe struct {
				ID string `json:"_id"`
			}
			if json.Unmarshal(line, &probe) == nil && probe.ID == docID {
				return true
			}
		}
	}
	return false
}

// FlushTableIfDocPending flushes any buffered or in-flight batch for `table` only when `docID`
// is present in that batch, using O(1) tracked `_id` membership under the table's shard lock.
func (c *StreamLoadCoalescer) FlushTableIfDocPending(ctx context.Context, table, docID string) error {
	if docID == "" {
		return c.FlushTable(ctx, table)
	}
	sh := c.getShard(table)
	if sh == nil {
		return nil
	}
	needFlush := false
	sh.mu.Lock()
	if sh.batch != nil && batchContainsDocID(sh.batch, docID) {
		needFlush = true
	}
	if !needFlush {
		for ib := range sh.inflight {
			if batchContainsDocID(ib, docID) {
				needFlush = true
				break
			}
		}
	}
	sh.mu.Unlock()
	if !needFlush {
		return nil
	}
	return c.FlushTable(ctx, table)
}

// FlushTable stops any pending group-commit timer for `table`, synchronously flushes its buffered
// batch, and waits for any in-flight flush to complete so subsequent point-lookups observe all
// previously submitted writes.
func (c *StreamLoadCoalescer) FlushTable(ctx context.Context, table string) error {
	var firstErr error
	var waitBatches []*coalesceBatch

	if sh := c.getShard(table); sh != nil {
		sh.mu.Lock()
		for ib := range sh.inflight {
			waitBatches = append(waitBatches, ib)
		}
		b := sh.batch
		if b != nil {
			if b.timer != nil {
				b.timer.Stop()
			}
			b.flushing = true
			sh.batch = nil
			sh.inflight[b] = struct{}{}
		}
		sh.mu.Unlock()

		if b != nil {
			flushCtx, cancel := deriveCoalescerFlushContext(ctx)
			c.executeBatch(flushCtx, sh, table, b, true)
			cancel()
			sh.mu.Lock()
			delete(sh.inflight, b)
			sh.mu.Unlock()
			if b.err != nil {
				firstErr = b.err
			}
		}
	}

	// Drain any legacy direct test batch (e.g. round8_test.go).
	c.mu.Lock()
	for ib, tbl := range c.inflight {
		if tbl == table {
			waitBatches = append(waitBatches, ib)
		}
	}
	legacyBatch, legacyExists := c.batches[table]
	if legacyExists {
		if legacyBatch.timer != nil {
			legacyBatch.timer.Stop()
		}
		legacyBatch.flushing = true
		delete(c.batches, table)
		c.inflight[legacyBatch] = table
	}
	c.mu.Unlock()

	if legacyExists {
		flushCtx, cancel := deriveCoalescerFlushContext(ctx)
		c.executeBatch(flushCtx, nil, table, legacyBatch, true)
		cancel()
		c.mu.Lock()
		delete(c.inflight, legacyBatch)
		c.mu.Unlock()
		if legacyBatch.err != nil && firstErr == nil {
			firstErr = legacyBatch.err
		}
	}

	for _, ib := range waitBatches {
		select {
		case <-ib.done:
			if ib.err != nil && firstErr == nil {
				firstErr = ib.err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return firstErr
}

type pendingFlushWork struct {
	shard *tableCoalesceShard
	table string
	batch *coalesceBatch
}

// FlushAll stops all pending group-commit timers and flushes all pending table batches concurrently
// with a bounded worker pool while respecting `ctx`'s deadline when set.
func (c *StreamLoadCoalescer) FlushAll(ctx context.Context) error {
	_, hasDL := ctx.Deadline()
	if hasDL && ctx.Err() != nil {
		return ctx.Err()
	}

	var pending []pendingFlushWork
	var waitBatches []*coalesceBatch

	for _, item := range c.snapshotShards() {
		sh := item.shard
		sh.mu.Lock()
		for ib := range sh.inflight {
			waitBatches = append(waitBatches, ib)
		}
		if b := sh.batch; b != nil {
			if b.timer != nil {
				b.timer.Stop()
			}
			b.flushing = true
			sh.batch = nil
			sh.inflight[b] = struct{}{}
			pending = append(pending, pendingFlushWork{shard: sh, table: item.table, batch: b})
		}
		sh.mu.Unlock()
	}

	// Also drain any legacy test batches in c.batches.
	c.mu.Lock()
	for ib := range c.inflight {
		waitBatches = append(waitBatches, ib)
	}
	for tbl, b := range c.batches {
		if b.timer != nil {
			b.timer.Stop()
		}
		b.flushing = true
		c.inflight[b] = tbl
		pending = append(pending, pendingFlushWork{shard: nil, table: tbl, batch: b})
	}
	if len(c.batches) > 0 {
		c.batches = make(map[string]*coalesceBatch)
	}
	c.mu.Unlock()

	var (
		errMu    sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	recordErr := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}

	if len(pending) > 0 {
		sem := make(chan struct{}, maxConcurrentCoalescerFlushes)
	flushLoop:
		for _, w := range pending {
			if hasDL {
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					recordErr(ctx.Err())
					w.batch.err = ctx.Err()
					if w.batch.done != nil {
						close(w.batch.done)
					}
					if w.shard != nil {
						w.shard.mu.Lock()
						delete(w.shard.inflight, w.batch)
						w.shard.mu.Unlock()
					} else {
						c.mu.Lock()
						delete(c.inflight, w.batch)
						c.mu.Unlock()
					}
					continue flushLoop
				}
			} else {
				sem <- struct{}{}
			}

			wg.Add(1)
			go func(work pendingFlushWork) {
				defer wg.Done()
				defer func() { <-sem }()
				flushCtx, cancel := deriveCoalescerFlushContext(ctx)
				c.executeBatch(flushCtx, work.shard, work.table, work.batch, true)
				cancel()
				if work.shard != nil {
					work.shard.mu.Lock()
					delete(work.shard.inflight, work.batch)
					work.shard.mu.Unlock()
				} else {
					c.mu.Lock()
					delete(c.inflight, work.batch)
					c.mu.Unlock()
				}
				recordErr(work.batch.err)
			}(w)
		}
		wg.Wait()
	}

	for _, ib := range waitBatches {
		select {
		case <-ib.done:
			recordErr(ib.err)
		case <-ctx.Done():
			recordErr(ctx.Err())
		}
	}
	return firstErr
}

// Close marks the coalescer as closed, flushes all pending batches, and waits for any in-flight
// timer or byte-threshold flushes to finish before returning.
func (c *StreamLoadCoalescer) Close(ctx context.Context) error {
	c.closedFlag.Store(true)
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.FlushAll(ctx)
}

func (c *StreamLoadCoalescer) onTimerFlush(sh *tableCoalesceShard, table string, target *coalesceBatch) {
	sh.mu.Lock()
	if sh.batch != target {
		sh.mu.Unlock()
		return
	}
	sh.batch = nil
	if atomic.LoadInt64(&target.activeWaiters) <= 0 {
		target.err = context.Canceled
		close(target.done)
		sh.mu.Unlock()
		return
	}
	target.flushing = true
	sh.inflight[target] = struct{}{}
	sh.mu.Unlock()
	defer func() {
		sh.mu.Lock()
		delete(sh.inflight, target)
		sh.mu.Unlock()
	}()

	flushCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c.executeBatch(flushCtx, sh, table, target, false)
}

func (c *StreamLoadCoalescer) executeBatch(ctx context.Context, sh *tableCoalesceShard, table string, b *coalesceBatch, syncRefresh bool) {
	if b.done != nil {
		defer close(b.done)
	}
	if sh != nil {
		sh.mu.Lock()
	} else {
		c.mu.Lock()
	}
	var buf bytes.Buffer
	if b.buf.Len()+b.totalBytes > 0 {
		buf.Grow(b.buf.Len() + b.totalBytes)
	}
	if b.buf.Len() > 0 {
		buf.Write(b.buf.Bytes())
	}
	for _, sub := range b.submissions {
		if !sub.canceled {
			buf.Write(sub.data)
		}
	}
	if sh != nil {
		sh.mu.Unlock()
	} else {
		c.mu.Unlock()
	}
	if buf.Len() == 0 {
		return
	}
	atomic.AddInt64(&c.coalescedFlushes, 1)
	b.err = c.loadFn(ctx, table, buf.Bytes(), syncRefresh)
}

type queryCacheEntry struct {
	raw             []byte
	unindexedFields []string
	expiresAt       time.Time
}

// QueryResultCache caches compiled Elasticsearch `/_search` responses for a configurable TTL
// and automatically invalidates all cached entries whenever any write or DDL operation occurs.
type QueryResultCache struct {
	mu              sync.RWMutex
	ttl             time.Duration
	maxEntries      int
	entries         map[string]queryCacheEntry
	hits            int64
	misses          int64
	securityEpochFn func() uint64
}

func newQueryResultCache() *QueryResultCache {
	return &QueryResultCache{
		maxEntries: DefaultQueryCacheMaxEntries,
		entries:    make(map[string]queryCacheEntry),
	}
}

// SetSecurityEpochFunc registers a provider returning the current security state epoch
// so QueryResultCache keys stay isolated across security configuration mutations.
func (qc *QueryResultCache) SetSecurityEpochFunc(fn func() uint64) {
	if qc == nil {
		return
	}
	qc.mu.Lock()
	qc.securityEpochFn = fn
	qc.mu.Unlock()
}

func (qc *QueryResultCache) currentSecurityEpoch() uint64 {
	if qc == nil {
		return 0
	}
	qc.mu.RLock()
	fn := qc.securityEpochFn
	qc.mu.RUnlock()
	if fn == nil {
		return 0
	}
	return fn()
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

func isWordByteNowCheck(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func isNowDateMathString(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return false
	}
	checkPart := func(part string) bool {
		part = strings.TrimSpace(part)
		return part == "now" || strings.HasPrefix(part, "now+") || strings.HasPrefix(part, "now-") || strings.HasPrefix(part, "now/")
	}
	if idx := strings.Index(s, "||"); idx >= 0 {
		return checkPart(s[:idx]) || checkPart(s[idx+2:])
	}
	return checkPart(s)
}

func containsStandaloneNowToken(s string) bool {
	lower := strings.ToLower(s)
	offset := 0
	for {
		idx := strings.Index(lower[offset:], "now")
		if idx < 0 {
			return false
		}
		pos := offset + idx
		prevWord := pos > 0 && isWordByteNowCheck(lower[pos-1])
		nextPos := pos + 3
		nextWord := nextPos < len(lower) && isWordByteNowCheck(lower[nextPos])
		if !prevWord && !nextWord {
			return true
		}
		offset = pos + 3
	}
}

func containsNowDateMath(req *esast.SearchRequest, reqBytes []byte) bool {
	if req != nil {
		if queryContainsNow(req.Query) || queryContainsNow(req.PostFilter) || queryContainsNow(req.AliasFilter) {
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
		for i := range req.Rescore {
			if req.Rescore[i].Query != nil && queryContainsNow(req.Rescore[i].Query.RescoreQuery) {
				return true
			}
		}
		if req.Highlight != nil {
			if queryContainsNow(req.Highlight.HighlightQuery) {
				return true
			}
			for field := range req.Highlight.Fields {
				spec := req.Highlight.FieldSpec(field)
				if queryContainsNow(spec.HighlightQuery) {
					return true
				}
			}
		}
		for i := range req.Sort {
			if req.Sort[i].Entry.Nested != nil && queryContainsNow(req.Sort[i].Entry.Nested.Filter) {
				return true
			}
		}
	}
	if len(reqBytes) > 0 {
		lowerBytes := bytes.ToLower(reqBytes)
		for _, pat := range [][]byte{
			[]byte(`"now"`),
			[]byte(`"now-`),
			[]byte(`"now+`),
			[]byte(`"now/`),
			[]byte(`" now"`),
			[]byte(`" now-`),
			[]byte(`" now+`),
			[]byte(`" now/`),
			[]byte(`||now`),
			[]byte("to now]"),
			[]byte("to now}"),
			[]byte("to now-"),
			[]byte("to now+"),
			[]byte("to now/"),
			[]byte("[now "),
			[]byte("{now "),
			[]byte("[now-"),
			[]byte("{now-"),
			[]byte("[now+"),
			[]byte("{now+"),
			[]byte("[now/"),
			[]byte("{now/"),
			[]byte(":now-"),
			[]byte(":now+"),
			[]byte(":now/"),
			[]byte(">now"),
			[]byte("<now"),
			[]byte("=now"),
			[]byte("system.currenttimemillis"),
			[]byte("instant.now"),
			[]byte("zoneddatetime.now"),
			[]byte("localdatetime.now"),
			[]byte("offsetdatetime.now"),
			[]byte("localdate.now"),
			[]byte("new date("),
			[]byte("math.random"),
			[]byte("randomuuid"),
		} {
			if bytes.Contains(lowerBytes, pat) {
				return true
			}
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
		if agg.Range != nil {
			for _, r := range agg.Range.Ranges {
				if boundValContainsNow(r.From) || boundValContainsNow(r.To) {
					return true
				}
			}
		}
		if tSpec := agg.EffectiveTerms(); tSpec != nil && queryContainsNow(tSpec.BackgroundFilter) {
			return true
		}
		if agg.Composite != nil {
			for _, srcMap := range agg.Composite.Sources {
				for _, src := range srcMap {
					if src.Terms != nil && boundValContainsNow(src.Terms.Missing) {
						return true
					}
					if src.DateHistogram != nil && boundValContainsNow(src.DateHistogram.Missing) {
						return true
					}
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
		return isNowDateMathString(s)
	}
	return false
}

func queryContainsNow(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.QueryString != nil && containsStandaloneNowToken(q.QueryString.Query) {
		return true
	}
	if q.SimpleQueryString != nil && containsStandaloneNowToken(q.SimpleQueryString.Query) {
		return true
	}
	for _, tc := range q.Term {
		if boundValContainsNow(tc.Value) {
			return true
		}
	}
	for _, mc := range q.Match {
		if boundValContainsNow(mc.Query) {
			return true
		}
	}
	for _, mp := range q.MatchPhrase {
		if boundValContainsNow(mp.Query) {
			return true
		}
	}
	for _, mpp := range q.MatchPhrasePrefix {
		if boundValContainsNow(mpp.Query) {
			return true
		}
	}
	for _, mbp := range q.MatchBoolPrefix {
		if boundValContainsNow(mbp.Query) {
			return true
		}
	}
	if q.MultiMatch != nil && boundValContainsNow(q.MultiMatch.Query) {
		return true
	}
	if q.CombinedFields != nil && boundValContainsNow(q.CombinedFields.Query) {
		return true
	}
	if q.Terms != nil {
		for _, vals := range q.Terms.Fields {
			for _, v := range vals {
				if boundValContainsNow(v) {
					return true
				}
			}
		}
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
		if q.FunctionScore.RandomScore != nil && q.FunctionScore.RandomScore.Seed == nil {
			return true
		}
		if queryContainsNow(q.FunctionScore.Query) {
			return true
		}
		for i := range q.FunctionScore.Functions {
			if q.FunctionScore.Functions[i].RandomScore != nil && q.FunctionScore.Functions[i].RandomScore.Seed == nil {
				return true
			}
			if queryContainsNow(q.FunctionScore.Functions[i].Filter) {
				return true
			}
		}
	}
	if q.ScriptScore != nil && queryContainsNow(q.ScriptScore.Query) {
		return true
	}
	if q.Wrapper != nil && queryContainsNow(q.Wrapper.Decoded) {
		return true
	}
	if q.Pinned != nil && queryContainsNow(q.Pinned.Organic) {
		return true
	}
	if q.HasChild != nil && queryContainsNow(&q.HasChild.Query) {
		return true
	}
	if q.HasParent != nil && queryContainsNow(&q.HasParent.Query) {
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

var queryCacheResponseShapingURLParamsR67 = []string{
	"typed_keys",
	"rest_total_hits_as_int",
	"search_type",
	"preference",
	"filter_path",
	"pretty",
	"human",
	"format",
	"source",
	"source_content_type",
}

func formatResponseShapingQueryParamsForCacheR67(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, k := range queryCacheResponseShapingURLParamsR67 {
		if vals, has := q[k]; has {
			sb.WriteString("qp:")
			sb.WriteString(k)
			sb.WriteByte('=')
			sb.WriteString(strings.Join(vals, "\x1f"))
			sb.WriteByte(';')
		}
	}
	return sb.String()
}

func buildQueryCacheKey(targets []string, req *esast.SearchRequest) (string, bool) {
	return buildQueryCacheKeyWithAuth(targets, req, "")
}

func buildQueryCacheKeyWithAuth(targets []string, req *esast.SearchRequest, authScope string) (string, bool) {
	return buildQueryCacheKeyWithAuthAndParams(targets, req, authScope, 0, nil)
}

func buildQueryCacheKeyWithAuthAndParams(
	targets []string,
	req *esast.SearchRequest,
	authScope string,
	securityEpoch uint64,
	urlParams url.Values,
) (string, bool) {
	if req == nil || req.PIT != nil {
		return "", false
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return "", false
	}
	var afSuffix string
	checkBytes := reqBytes
	if req.AliasFilter != nil {
		afBytes, err := json.Marshal(req.AliasFilter)
		if err != nil {
			return "", false
		}
		afSuffix = "\x00af:" + string(afBytes)
		checkBytes = append(append([]byte(nil), reqBytes...), afBytes...)
	}
	if containsNowDateMath(req, checkBytes) {
		return "", false
	}
	var rtSuffix string
	if strings.TrimSpace(req.Routing) != "" {
		rtSuffix = "\x00rt:" + strings.TrimSpace(req.Routing)
	}
	var authSuffix string
	if authScope != "" {
		authSuffix = "\x00auth:" + authScope
	}
	var epochSuffix string
	if securityEpoch > 0 {
		epochSuffix = fmt.Sprintf("\x00se:%d", securityEpoch)
	}
	var qpSuffix string
	if qp := formatResponseShapingQueryParamsForCacheR67(urlParams); qp != "" {
		qpSuffix = "\x00qp:" + qp
	}
	return strings.Join(targets, ",") + "\x00" + string(reqBytes) + afSuffix + rtSuffix + authSuffix + epochSuffix + qpSuffix, true
}

// Get looks up a cached search response for `(targets, req)` and returns a fresh unmarshaled copy.
func (qc *QueryResultCache) Get(targets []string, req *esast.SearchRequest) (map[string]any, bool) {
	resp, _, ok := qc.GetWithMeta(targets, req)
	return resp, ok
}

// GetWithMeta looks up a cached search response and its associated unindexed fields for `(targets, req)`.
func (qc *QueryResultCache) GetWithMeta(targets []string, req *esast.SearchRequest) (map[string]any, []string, bool) {
	return qc.GetWithMetaForAuth(targets, req, "")
}

// GetWithMetaForAuth looks up a cached search response isolated by resolved auth scope.
func (qc *QueryResultCache) GetWithMetaForAuth(targets []string, req *esast.SearchRequest, authScope string) (map[string]any, []string, bool) {
	return qc.GetWithMetaForAuthWithParams(targets, req, authScope, nil)
}

// GetWithMetaForAuthWithParams looks up a cached search response isolated by auth scope, security epoch, and response-shaping URL parameters.
func (qc *QueryResultCache) GetWithMetaForAuthWithParams(targets []string, req *esast.SearchRequest, authScope string, urlParams url.Values) (map[string]any, []string, bool) {
	if !qc.Enabled() {
		return nil, nil, false
	}
	key, ok := buildQueryCacheKeyWithAuthAndParams(targets, req, authScope, qc.currentSecurityEpoch(), urlParams)
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
	qc.PutWithMetaForAuth(targets, req, "", resp, unindexedFields)
}

// PutWithMetaForAuth stores a serialized snapshot of `resp` isolated by resolved auth scope.
func (qc *QueryResultCache) PutWithMetaForAuth(targets []string, req *esast.SearchRequest, authScope string, resp map[string]any, unindexedFields []string) {
	qc.PutWithMetaForAuthWithParams(targets, req, authScope, nil, resp, unindexedFields)
}

// PutWithMetaForAuthWithParams stores a serialized snapshot of `resp` isolated by auth scope, security epoch, and response-shaping URL parameters.
func (qc *QueryResultCache) PutWithMetaForAuthWithParams(targets []string, req *esast.SearchRequest, authScope string, urlParams url.Values, resp map[string]any, unindexedFields []string) {
	if resp == nil || !qc.Enabled() {
		return
	}
	key, ok := buildQueryCacheKeyWithAuthAndParams(targets, req, authScope, qc.currentSecurityEpoch(), urlParams)
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
