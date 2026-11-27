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
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

type mockProdExtBackendR67 struct {
	*MemoryBackend

	mu                sync.Mutex
	pingErr           error
	pingCalls         atomic.Int64
	aliveBEs          int
	feHTTPOK          bool
	healthErr         error
	healthCalls       atomic.Int64
	version           string
	versionErr        error
	dbStats           sql.DBStats
	hasDBStats        bool
	loadSinceCalls    atomic.Int64
	loadSinceErr      error
	deletedCatalogLog []string

	sqlMu        sync.Mutex
	sqlQueries   []string
	sqlTotalRows int64
	sqlRowsHook  func(sqlStr string) ([]map[string]any, error)
	ddlErr       error
	capturedDDLs []string
}

func newMockProdExtBackendR67() *mockProdExtBackendR67 {
	return &mockProdExtBackendR67{
		MemoryBackend: NewMemoryBackend(false),
		aliveBEs:      2,
		feHTTPOK:      true,
		version:       "4.1.4",
		sqlTotalRows:  5,
		dbStats: sql.DBStats{
			MaxOpenConnections: 25,
			OpenConnections:    4,
			InUse:              1,
			Idle:               3,
			WaitCount:          2,
			WaitDuration:       150 * time.Millisecond,
		},
		hasDBStats: true,
	}
}

func (m *mockProdExtBackendR67) Ping(ctx context.Context) error {
	m.pingCalls.Add(1)
	m.mu.Lock()
	err := m.pingErr
	m.mu.Unlock()
	if err != nil {
		return err
	}
	return m.MemoryBackend.Ping(ctx)
}

func (m *mockProdExtBackendR67) CheckClusterHealth(_ context.Context) (int, bool, error) {
	m.healthCalls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.aliveBEs, m.feHTTPOK, m.healthErr
}

func (m *mockProdExtBackendR67) ProbeDorisVersion(_ context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.version, m.versionErr
}

func (m *mockProdExtBackendR67) DBStats() (sql.DBStats, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dbStats, m.hasDBStats
}

func (m *mockProdExtBackendR67) LoadCatalogEntriesSince(ctx context.Context, db string, sinceEpochMs int64) ([]CatalogEntry, error) {
	m.loadSinceCalls.Add(1)
	m.mu.Lock()
	err := m.loadSinceErr
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	all, err := m.LoadCatalogEntries(ctx, db)
	if err != nil {
		return nil, err
	}
	var out []CatalogEntry
	for _, e := range all {
		if e.UpdatedEpochMs >= sinceEpochMs {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *mockProdExtBackendR67) DeleteCatalogEntry(ctx context.Context, db, entityType, entityKey string) error {
	m.mu.Lock()
	m.deletedCatalogLog = append(m.deletedCatalogLog, entityType+":"+entityKey)
	m.mu.Unlock()
	return m.MemoryBackend.DeleteCatalogEntry(ctx, db, entityType, entityKey)
}

func (m *mockProdExtBackendR67) ExecDDL(ctx context.Context, ddl string) error {
	m.mu.Lock()
	m.capturedDDLs = append(m.capturedDDLs, ddl)
	err := m.ddlErr
	m.mu.Unlock()
	if err != nil {
		return err
	}
	return m.MemoryBackend.ExecDDL(ctx, ddl)
}

func (m *mockProdExtBackendR67) QueryRows(_ context.Context, sqlStr string) ([]map[string]any, error) {
	m.sqlMu.Lock()
	m.sqlQueries = append(m.sqlQueries, sqlStr)
	hook := m.sqlRowsHook
	totalRows := m.sqlTotalRows
	m.sqlMu.Unlock()
	if hook != nil {
		return hook(sqlStr)
	}
	row := map[string]any{
		"__bm25_total_rows": totalRows,
		"__bm25_n_0":        totalRows,
		"__bm25_avgdl_0":    4.0,
		"__bm25_n_1":        totalRows,
		"__bm25_avgdl_1":    3.0,
	}
	for j := 0; j < 260; j++ {
		row[fmt.Sprintf("__bm25_df_0_%d", j)] = int64(2)
		row[fmt.Sprintf("__bm25_df_1_%d", j)] = int64(1)
	}
	return []map[string]any{row}, nil
}

func doR67HTTPReq(t *testing.T, h http.Handler, method, path, body string, hdrs map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRound67_ServerExtensionsAndDDLOptions(t *testing.T) {
	mb := newMockProdExtBackendR67()
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})

	// Optional interface assertions compile and work as expected.
	var _ IncrementalCatalogBackend = mb
	var _ VersionProbeBackend = mb
	var _ ClusterHealthBackend = mb
	var _ DBStatsBackend = mb

	if srv.AllowTestFixtureAuth() {
		t.Fatalf("expected AllowTestFixtureAuth to default to false")
	}
	ep0 := srv.SecurityEpoch()
	srv.SetAllowTestFixtureAuth(true)
	if !srv.AllowTestFixtureAuth() || srv.SecurityEpoch() <= ep0 {
		t.Fatalf("expected SetAllowTestFixtureAuth(true) to update flag and bump SecurityEpoch")
	}

	// SetDorisDDLOptions propagates to create index, _doris_ddl, _doris/explain, _rollover, _clone.
	storeRowFalse := false
	srv.SetDorisDDLOptions(schema.DorisDDLOptions{
		CloudMode:      true,
		BucketsAuto:    true,
		StoreRowColumn: &storeRowFalse,
		TableKeyModel:  "duplicate",
	})
	h := srv.Handler()
	if rec := doR67HTTPReq(t, h, http.MethodPut, "/ddl_opts_idx", `{
		"aliases":{"ddl_roll_alias":{"is_write_index":true}},
		"mappings":{"properties":{"msg":{"type":"text"}}}
	}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("PUT /ddl_opts_idx failed: %d %s", rec.Code, rec.Body.String())
	}
	mb.mu.Lock()
	lastDDL := mb.capturedDDLs[len(mb.capturedDDLs)-1]
	mb.mu.Unlock()
	if !strings.Contains(lastDDL, "DUPLICATE KEY") || strings.Contains(lastDDL, `"replication_num"`) || !strings.Contains(lastDDL, `"store_row_column" = "false"`) {
		t.Fatalf("expected CloudMode + StoreRowColumn=false + DUPLICATE KEY in CreateTableDDL, got:\n%s", lastDDL)
	}
	ddlResp := doR67HTTPReq(t, h, http.MethodGet, "/ddl_opts_idx/_doris/ddl?format=txt", "", nil)
	if ddlResp.Code != http.StatusOK || !strings.Contains(ddlResp.Body.String(), "DUPLICATE KEY") {
		t.Fatalf("expected custom DDL options in _doris/ddl, got %d %s", ddlResp.Code, ddlResp.Body.String())
	}
	expResp := doR67HTTPReq(t, h, http.MethodPost, "/ddl_opts_idx/_doris/explain", `{"query":{"match":{"msg":"hi"}}}`, nil)
	if expResp.Code != http.StatusOK || !strings.Contains(expResp.Body.String(), "DUPLICATE KEY") {
		t.Fatalf("expected custom DDL options in _doris/explain, got %d %s", expResp.Code, expResp.Body.String())
	}
	if rec := doR67HTTPReq(t, h, http.MethodPost, "/ddl_opts_idx/_clone/ddl_opts_clone", `{}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("clone failed: %d %s", rec.Code, rec.Body.String())
	}

	// Async task semaphore bounds at 16.
	acquired := 0
	for i := 0; i < 20; i++ {
		if srv.acquireAsyncTaskSlot() {
			acquired++
		}
	}
	if acquired != 16 {
		t.Fatalf("expected asyncTaskSem cap=16, acquired=%d", acquired)
	}
	srv.releaseAsyncTaskSlot()
	if !srv.acquireAsyncTaskSlot() {
		t.Fatalf("expected slot available after release")
	}
	for i := 0; i < 16; i++ {
		srv.releaseAsyncTaskSlot()
	}

	// Background sync ticker stops cleanly on Close().
	srv.SetCatalogSyncInterval(10 * time.Millisecond)
	time.Sleep(35 * time.Millisecond)
	if err := srv.Close(context.Background()); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestRound67_BM25ModesCacheSingleflightAndRowCap(t *testing.T) {
	mb := newMockProdExtBackendR67()
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	t.Cleanup(func() { _ = srv.Close(context.Background()) })

	idxSchema := schema.CompileIndexSchema("es_db", "articles", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":  {Type: "text"},
			"body":   {Type: "text"},
			"tenant": {Type: "keyword"},
		},
	})
	idxSchema.DorisTable = "articles"

	// 1. doris-score & approx skip scanning completely.
	srv.SetBM25Mode(BM25ModeDorisScore)
	optsScore := transpiler.TranspilerOptions{}
	req := &esast.SearchRequest{
		Query: &esast.Query{Match: map[string]esast.MatchEntry{"title": {Query: "hello world"}}},
	}
	srv.populateCorpusBM25StatsIfNeededR66(context.Background(), idxSchema, req, &optsScore)
	if !optsScore.UseDoris4SearchFunc {
		t.Fatalf("expected UseDoris4SearchFunc=true in doris-score mode")
	}
	if len(mb.sqlQueries) != 0 {
		t.Fatalf("expected 0 SQL queries in doris-score mode, got %d", len(mb.sqlQueries))
	}

	srv.SetBM25Mode(BM25ModeApprox)
	optsApprox := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsIfNeededR66(context.Background(), idxSchema, req, &optsApprox)
	if len(mb.sqlQueries) != 0 || optsApprox.UseDoris4SearchFunc {
		t.Fatalf("expected 0 SQL queries in approx mode")
	}

	// 2. auto mode: deduplicates & caps terms <= 256, uses singleflight under concurrency, and caches hits.
	srv.SetBM25Mode(BM25ModeAuto)
	terms := make([]string, 0, 320)
	for i := 0; i < 320; i++ {
		terms = append(terms, fmt.Sprintf("w%03d", i))
	}
	bigReq := &esast.SearchRequest{
		Query: &esast.Query{MultiMatch: &esast.MultiMatchQuery{
			Query:  strings.Join(terms, " "),
			Fields: []string{"title", "body"},
		}},
		AliasFilter: &esast.Query{
			Term: map[string]esast.TermEntry{"tenant": {Value: "acme"}},
		},
	}

	mb.sqlMu.Lock()
	mb.sqlRowsHook = func(sqlStr string) ([]map[string]any, error) {
		time.Sleep(25 * time.Millisecond)
		return []map[string]any{{
			"__bm25_total_rows": int64(10),
			"__bm25_n_0":        int64(10),
			"__bm25_avgdl_0":    5.0,
			"__bm25_df_0_0":     int64(3),
		}}, nil
	}
	mb.sqlMu.Unlock()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o := transpiler.TranspilerOptions{}
			srv.populateCorpusBM25StatsIfNeededR66(context.Background(), idxSchema, bigReq, &o)
			if len(o.CorpusBM25Stats) == 0 {
				t.Errorf("expected populated CorpusBM25Stats from singleflight/cache")
			}
		}()
	}
	wg.Wait()

	mb.sqlMu.Lock()
	qCount := len(mb.sqlQueries)
	firstSQL := ""
	if qCount > 0 {
		firstSQL = mb.sqlQueries[0]
	}
	mb.sqlRowsHook = nil
	mb.sqlMu.Unlock()
	if qCount != 1 {
		t.Fatalf("expected 8 concurrent identical BM25 requests to coalesce into 1 scan, got %d", qCount)
	}
	if dfCount := strings.Count(firstSQL, "__bm25_df_"); dfCount > maxBM25TermsR67 {
		t.Fatalf("expected BM25 term DF count capped <= %d, got %d", maxBM25TermsR67, dfCount)
	}
	if !strings.Contains(firstSQL, "f__tenant") {
		t.Fatalf("expected alias filter predicate forwarded into statsSQL, got: %s", firstSQL)
	}

	// Cache hit avoids second query, then table invalidation forces fresh query.
	o2 := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsIfNeededR66(context.Background(), idxSchema, bigReq, &o2)
	mb.sqlMu.Lock()
	qAfterCache := len(mb.sqlQueries)
	mb.sqlMu.Unlock()
	if qAfterCache != 1 {
		t.Fatalf("expected BM25 cache hit (still 1 SQL query), got %d", qAfterCache)
	}

	srv.invalidateBM25ForTableR67("es_db", "articles")
	srv.SetBM25MaxRows(100)
	mb.sqlMu.Lock()
	mb.sqlTotalRows = 500
	mb.sqlMu.Unlock()

	smallReq := &esast.SearchRequest{
		Query: &esast.Query{Match: map[string]esast.MatchEntry{"title": {Query: "alpha"}}},
	}
	oLarge1 := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsIfNeededR66(context.Background(), idxSchema, smallReq, &oLarge1)
	oLarge2 := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsIfNeededR66(context.Background(), idxSchema, smallReq, &oLarge2)
	mb.sqlMu.Lock()
	qAfterOverCap := len(mb.sqlQueries)
	mb.sqlMu.Unlock()
	if qAfterOverCap != 2 {
		t.Fatalf("expected overRowCap (30s TTL) to skip second full-table scan (total 2), got %d", qAfterOverCap)
	}

	// exact-corpus-scan bypasses overRowCap check cleanly.
	srv.SetBM25Mode(BM25ModeExactCorpusScan)
	oExact := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsIfNeededR66(context.Background(), idxSchema, smallReq, &oExact)
	mb.sqlMu.Lock()
	qAfterExact := len(mb.sqlQueries)
	mb.sqlMu.Unlock()
	if qAfterExact != 3 {
		t.Fatalf("expected exact-corpus-scan to execute SQL even above row cap (total 3), got %d", qAfterExact)
	}
}

func TestRound67_CatalogSyncerIncrementalLockAndBounds(t *testing.T) {
	mb := newMockProdExtBackendR67()
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	srv.SetQueryCacheTTL(30*time.Second, 64)
	t.Cleanup(func() { _ = srv.Close(context.Background()) })

	var logBuf bytes.Buffer
	srv.SetLogger(slog.New(slog.NewJSONHandler(&logBuf, nil)))

	h := srv.Handler()
	if rec := doR67HTTPReq(t, h, http.MethodPut, "/sync_idx", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("create sync_idx failed: %d %s", rec.Code, rec.Body.String())
	}
	if err := srv.syncCatalogFromBackend(context.Background()); err != nil {
		t.Fatalf("initial syncCatalogFromBackend failed: %v", err)
	}

	// Populate queryCache entry, then verify no-op incremental poll does NOT invalidate queryCache!
	sReq := &esast.SearchRequest{}
	srv.queryCache.Put([]string{"sync_idx"}, sReq, map[string]any{"took": 1})
	futureEpoch := time.Now().UnixMilli() + 60000
	srv.catalogSyncer.lastEpochMs.Store(futureEpoch)
	if err := srv.syncCatalogFromBackend(context.Background()); err != nil {
		t.Fatalf("noop sync failed: %v", err)
	}
	if mb.loadSinceCalls.Load() == 0 {
		t.Fatalf("expected IncrementalCatalogBackend.LoadCatalogEntriesSince to be called")
	}
	if _, ok := srv.queryCache.Get([]string{"sync_idx"}, sReq); !ok {
		t.Fatalf("expected unchanged catalog poll NOT to invalidate queryCache")
	}

	// Expired tombstone gets purged cleanly when synced.
	oldEpoch := time.Now().Add(-10 * time.Minute).UnixMilli()
	_ = mb.UpsertCatalogEntry(context.Background(), "es_db", CatalogEntry{
		EntityType:     "index",
		EntityKey:      "dead_idx",
		PayloadJSON:    "__DELETED__",
		UpdatedEpochMs: oldEpoch,
	})
	srv.catalogSyncer.lastEpochMs.Store(oldEpoch)
	if err := srv.syncCatalogFromBackend(context.Background()); err != nil {
		t.Fatalf("tombstone purge sync failed: %v", err)
	}
	mb.mu.Lock()
	deletedLog := append([]string(nil), mb.deletedCatalogLog...)
	mb.mu.Unlock()
	if len(deletedLog) == 0 || deletedLog[0] != "index:dead_idx" {
		t.Fatalf("expected expired tombstone index:dead_idx purged, got %v", deletedLog)
	}

	// Per-index DDL lock serializes same-index DDL safely under -race.
	var active int32
	var ddlWG sync.WaitGroup
	for i := 0; i < 6; i++ {
		ddlWG.Add(1)
		go func() {
			defer ddlWG.Done()
			unlock := srv.LockIndexDDL("sync_idx")
			if atomic.AddInt32(&active, 1) != 1 {
				t.Errorf("concurrent entry inside LockIndexDDL")
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt32(&active, -1)
			unlock()
		}()
	}
	ddlWG.Wait()

	// applyArrayPromotionDelta logs warning when ExecDDL returns error.
	mb.mu.Lock()
	mb.ddlErr = errors.New("mock ddl boom")
	mb.mu.Unlock()
	srv.mu.RLock()
	curSc := srv.indices["sync_idx"]
	srv.mu.RUnlock()
	_ = srv.applyArrayPromotionDelta(context.Background(), "sync_idx", curSc, &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{"arr": {Type: "keyword", MultiValued: true}},
	})
	if !strings.Contains(logBuf.String(), "array promotion ALTER TABLE failed") {
		t.Fatalf("expected logged DDL warning via slog, got: %s", logBuf.String())
	}
	mb.mu.Lock()
	mb.ddlErr = nil
	mb.mu.Unlock()

	// Bounded FIFO eviction on setDocRouting and setDocVersion (> 50000).
	for i := 0; i < maxDocMetaPerIndexR62Admin+25; i++ {
		id := fmt.Sprintf("d-%05d", i)
		srv.setDocRouting("bound_idx", id, "r1")
		srv.setDocVersion("bound_idx", id, int64(i+1))
	}
	srv.mu.RLock()
	rLen := len(srv.docRouting["bound_idx"])
	vLen := len(srv.docVersions["bound_idx"])
	oldestStillRouting := srv.docRouting["bound_idx"]["d-00000"]
	srv.mu.RUnlock()
	if rLen > maxDocMetaPerIndexR62Admin || vLen > maxDocMetaPerIndexR62Admin {
		t.Fatalf("expected bounded doc metadata <= %d, got routing=%d versions=%d", maxDocMetaPerIndexR62Admin, rLen, vLen)
	}
	if oldestStillRouting != "" {
		t.Fatalf("expected oldest routing key d-00000 evicted by FIFO")
	}
}

func TestRound67_ObservabilityReadyzMetricsAndHeadFix(t *testing.T) {
	mb := newMockProdExtBackendR67()
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	t.Cleanup(func() { _ = srv.Close(context.Background()) })

	var logBuf bytes.Buffer
	srv.SetLogger(slog.New(slog.NewJSONHandler(&logBuf, nil)))
	srv.SetReadyzCacheTTL(5 * time.Second)
	h := srv.Handler()

	// 1. Deep /readyz checks Ping + ClusterHealthBackend + Catalog + 2s cache coalescing.
	for i := 0; i < 4; i++ {
		rec := doR67HTTPReq(t, h, http.MethodGet, "/readyz", "", nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ready"`) {
			t.Fatalf("readyz failed: %d %s", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-Request-ID") == "" {
			t.Fatalf("expected X-Request-ID header set on response")
		}
	}
	if mb.healthCalls.Load() != 1 {
		t.Fatalf("expected cached readyz probe to call CheckClusterHealth once, got %d", mb.healthCalls.Load())
	}

	// Unhealthy FE HTTP -> 503
	srv.SetReadyzCacheTTL(time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	mb.mu.Lock()
	mb.feHTTPOK = false
	mb.mu.Unlock()
	if rec := doR67HTTPReq(t, h, http.MethodGet, "/readyz", "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when feHTTPOK=false, got %d %s", rec.Code, rec.Body.String())
	}

	// 0 alive BEs -> 503
	mb.mu.Lock()
	mb.feHTTPOK = true
	mb.aliveBEs = 0
	mb.mu.Unlock()
	srv.SetReadyzCacheTTL(time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	if rec := doR67HTTPReq(t, h, http.MethodGet, "/readyz", "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when aliveBEs=0, got %d %s", rec.Code, rec.Body.String())
	}

	// Restore healthy, record SQL/StreamLoad/BM25 metrics, inspect /metrics.
	mb.mu.Lock()
	mb.aliveBEs = 2
	mb.mu.Unlock()
	srv.RecordSQLMetrics(25*time.Millisecond, nil)
	srv.RecordStreamLoadMetrics(40*time.Millisecond, 1024, 1, nil)
	srv.RecordBM25ScanMetric("scanned")
	srv.RecordCatalogSyncMetric("applied")

	mRec := doR67HTTPReq(t, h, http.MethodGet, "/metrics", "", nil)
	if mRec.Code != http.StatusOK {
		t.Fatalf("GET /metrics failed: %d", mRec.Code)
	}
	metricsBody := mRec.Body.String()
	for _, want := range []string{
		"doris_es_proxy_http_requests_total",
		"doris_es_proxy_query_cache_hits_total",
		"doris_es_proxy_bulk_coalesced_requests_total",
		"doris_es_proxy_http_request_duration_seconds_bucket",
		"doris_es_proxy_http_requests_by_route_total",
		"doris_es_proxy_doris_sql_duration_seconds_count",
		"doris_es_proxy_stream_load_duration_seconds_count",
		"doris_es_proxy_stream_load_bytes_total 1024",
		"doris_es_proxy_bm25_corpus_scans_total{outcome=\"scanned\"} 1",
		"doris_es_proxy_catalog_syncs_total{outcome=\"applied\"} 1",
		"doris_es_proxy_db_pool_connections{state=\"open\"} 4",
		"doris_es_proxy_go_goroutines",
		"doris_es_proxy_go_mem_heap_inuse_bytes",
		"doris_es_proxy_go_gc_pause_total_seconds",
	} {
		if !strings.Contains(metricsBody, want) {
			t.Fatalf("expected %q in /metrics output, got:\n%s", want, metricsBody)
		}
	}

	// Verify HEAD suppresses response body via fixed wireW (P2-4) and structured access logging ran.
	headRec := doR67HTTPReq(t, h, http.MethodHead, "/_cluster/health", "", map[string]string{"X-Request-ID": "custom-req-99"})
	if headRec.Code != http.StatusOK || headRec.Body.Len() != 0 {
		t.Fatalf("expected HEAD /_cluster/health empty body 200, got %d len=%d (%q)", headRec.Code, headRec.Body.Len(), headRec.Body.String())
	}
	if headRec.Header().Get("X-Request-ID") != "custom-req-99" {
		t.Fatalf("expected preserved custom X-Request-ID, got %q", headRec.Header().Get("X-Request-ID"))
	}
	if !strings.Contains(logBuf.String(), `"request_id":"custom-req-99"`) {
		t.Fatalf("expected structured access log with custom-req-99, got:\n%s", logBuf.String())
	}

	// Request query cache helper parses once cleanly.
	reqQ := httptest.NewRequest(http.MethodGet, "/_search?format=json&size=5", nil)
	reqQ, qv1 := withCachedQueryValuesR67(reqQ)
	qv2 := requestQueryValuesR67(reqQ)
	if qv1.Get("size") != "5" || qv2.Get("format") != "json" {
		t.Fatalf("query context cache mismatch: %v %v", qv1, qv2)
	}
}

func TestRound67_InternalClusterRoutesF19(t *testing.T) {
	srv := NewServer("es_db", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	// 1. desired_balance empty & populated + DELETE
	rec := doR67HTTPReq(t, h, http.MethodGet, "/_internal/desired_balance", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"routing_table":{}`) {
		t.Fatalf("empty desired_balance mismatch: %d %s", rec.Code, rec.Body.String())
	}
	_ = doR67HTTPReq(t, h, http.MethodPut, "/bal_idx", `{"settings":{"number_of_shards":1,"number_of_replicas":0}}`, nil)
	recPop := doR67HTTPReq(t, h, http.MethodGet, "/_internal/desired_balance", "", nil)
	if recPop.Code != http.StatusOK || !strings.Contains(recPop.Body.String(), `"bal_idx"`) || !strings.Contains(recPop.Body.String(), `"cluster_balance_stats"`) {
		t.Fatalf("populated desired_balance mismatch: %d %s", recPop.Code, recPop.Body.String())
	}
	if delRec := doR67HTTPReq(t, h, http.MethodDelete, "/_internal/desired_balance", "", nil); delRec.Code != http.StatusOK {
		t.Fatalf("DELETE /_internal/desired_balance failed: %d", delRec.Code)
	}

	// 2. desired_nodes CRUD, dry_run, idempotency, conflict 409, different def 400, validation errors.
	if rec404 := doR67HTTPReq(t, h, http.MethodGet, "/_internal/desired_nodes/_latest", "", nil); rec404.Code != http.StatusNotFound {
		t.Fatalf("expected 404 before any desired_nodes, got %d", rec404.Code)
	}
	node1 := `{"nodes":[{"settings":{"node.name":"n1"},"processors":8.5,"memory":"64gb","storage":"128gb"}]}`
	if recDry := doR67HTTPReq(t, h, http.MethodPut, "/_internal/desired_nodes/h1/1?dry_run=true", node1, nil); recDry.Code != http.StatusOK || !strings.Contains(recDry.Body.String(), `"dry_run":true`) {
		t.Fatalf("dry_run put failed: %d %s", recDry.Code, recDry.Body.String())
	}
	if recStill404 := doR67HTTPReq(t, h, http.MethodGet, "/_internal/desired_nodes/_latest", "", nil); recStill404.Code != http.StatusNotFound {
		t.Fatalf("dry_run mutated desired_nodes state: %d", recStill404.Code)
	}

	twoNodesA := `{"nodes":[{"settings":{"node.external_id":"ext1"},"processors":8,"memory":"64gb","storage":"128gb"},{"settings":{"node.external_id":"ext2"},"processors_range":{"min":4,"max":8},"memory":"32gb","storage":"64gb"}]}`
	twoNodesB := `{"nodes":[{"settings":{"node.external_id":"ext2"},"processors_range":{"min":4,"max":8},"memory":"32gb","storage":"64gb"},{"settings":{"node.external_id":"ext1"},"processors":8,"memory":"64gb","storage":"128gb"}]}`
	if rPut := doR67HTTPReq(t, h, http.MethodPut, "/_internal/desired_nodes/h1/1", twoNodesA, nil); rPut.Code != http.StatusOK {
		t.Fatalf("PUT desired_nodes h1/1 failed: %d %s", rPut.Code, rPut.Body.String())
	}
	// Idempotent with reordered nodes succeeds 200; different definition returns 400.
	if rIdem := doR67HTTPReq(t, h, http.MethodPut, "/_internal/desired_nodes/h1/1", twoNodesB, nil); rIdem.Code != http.StatusOK {
		t.Fatalf("expected idempotent reordered PUT to succeed, got %d %s", rIdem.Code, rIdem.Body.String())
	}
	if rDiff := doR67HTTPReq(t, h, http.MethodPut, "/_internal/desired_nodes/h1/1", node1, nil); rDiff.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for same version different definition, got %d %s", rDiff.Code, rDiff.Body.String())
	}
	if rV2 := doR67HTTPReq(t, h, http.MethodPut, "/_internal/desired_nodes/h1/2", node1, nil); rV2.Code != http.StatusOK {
		t.Fatalf("PUT desired_nodes h1/2 failed: %d %s", rV2.Code, rV2.Body.String())
	}
	if r409 := doR67HTTPReq(t, h, http.MethodPut, "/_internal/desired_nodes/h1/1", twoNodesA, nil); r409.Code != http.StatusConflict || !strings.Contains(r409.Body.String(), "version_conflict_exception") {
		t.Fatalf("expected 409 version_conflict_exception going backwards, got %d %s", r409.Code, r409.Body.String())
	}
	// Invalid payloads
	for _, badBody := range []string{
		`{"nodes":[]}`,
		`{"nodes":[{"settings":{"node.name":"n1","node.roles":"data_hot"},"processors":8,"memory":"64gb","storage":"128gb"}]}`,
		`{"nodes":[{"settings":{"node.external_id":"dup"},"processors":4,"memory":"8gb","storage":"10gb"},{"settings":{"node.external_id":"dup"},"processors":4,"memory":"8gb","storage":"10gb"}]}`,
		`{"nodes":[{"settings":{"node.name":"n1"},"processors":"NaN","memory":"64gb","storage":"128gb"}]}`,
		`{"nodes":[{"settings":{"node.name":"n1"},"processors":4,"processors_range":{"min":1},"memory":"64gb","storage":"128gb"}]}`,
		`{"nodes":[{"settings":{"node.name":"n1","node.roles":"bogus_role"},"processors":4,"memory":"64gb","storage":"128gb"}]}`,
	} {
		if rBad := doR67HTTPReq(t, h, http.MethodPut, "/_internal/desired_nodes/h2/1", badBody, nil); rBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for bad desired_nodes body %s, got %d %s", badBody, rBad.Code, rBad.Body.String())
		}
	}
	if rDel := doR67HTTPReq(t, h, http.MethodDelete, "/_internal/desired_nodes", "", nil); rDel.Code != http.StatusOK {
		t.Fatalf("DELETE /_internal/desired_nodes failed: %d", rDel.Code)
	}

	// 3. prevalidate_node_removal
	if rMiss := doR67HTTPReq(t, h, http.MethodPost, "/_internal/prevalidate_node_removal", "", nil); rMiss.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when missing node params, got %d", rMiss.Code)
	}
	if rMulti := doR67HTTPReq(t, h, http.MethodPost, "/_internal/prevalidate_node_removal?names=doris-fe-1&ids=doris-fe-1", "", nil); rMulti.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when both names & ids passed, got %d", rMulti.Code)
	}
	if rUnknown := doR67HTTPReq(t, h, http.MethodPost, "/_internal/prevalidate_node_removal?external_ids=nope", "", nil); rUnknown.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown external_id, got %d", rUnknown.Code)
	}
	rPre := doR67HTTPReq(t, h, http.MethodPost, "/_internal/prevalidate_node_removal?ids=doris-fe-1", "", nil)
	if rPre.Code != http.StatusOK || !strings.Contains(rPre.Body.String(), `"is_safe":true`) {
		t.Fatalf("prevalidate_node_removal failed: %d %s", rPre.Code, rPre.Body.String())
	}
}

func TestRound67_SecurityAuthPBKDF2RBACDLSFLS(t *testing.T) {
	srv := NewServer("es_db", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	// Open cluster allows _authenticate anonymously.
	if rec := doR67HTTPReq(t, h, http.MethodGet, "/_security/_authenticate", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("open _authenticate failed: %d %s", rec.Code, rec.Body.String())
	}

	// Seed index + docs
	_ = doR67HTTPReq(t, h, http.MethodPut, "/sec_docs", `{"mappings":{"properties":{"tenant":{"type":"keyword"},"public_msg":{"type":"keyword"},"secret_ssn":{"type":"keyword"}}}}`, nil)
	_ = doR67HTTPReq(t, h, http.MethodPut, "/sec_docs/_doc/1?refresh=true", `{"tenant":"acme","public_msg":"hello-acme","secret_ssn":"999"}`, nil)
	_ = doR67HTTPReq(t, h, http.MethodPut, "/sec_docs/_doc/2?refresh=true", `{"tenant":"globex","public_msg":"hello-globex","secret_ssn":"888"}`, nil)
	_ = doR67HTTPReq(t, h, http.MethodPut, "/other_docs", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, nil)

	// Build real PBKDF2-HMAC-SHA256 password entry for a user
	salt := []byte("r67-salt-16bytes")
	dk := pbkdf2HMACSHA256R67([]byte("pbkdf2-pw"), salt, 1000, 32)
	pbkdf2Hash := "$pbkdf2-sha256$1000$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(dk)
	shaSum := sha256.Sum256([]byte("svc-secret"))
	_ = shaSum

	srv.mu.Lock()
	srv.securityRoles["acme_reader"] = map[string]any{
		"indices": []any{
			map[string]any{
				"names":          []any{"sec_docs"},
				"privileges":     []any{"read"},
				"query":          map[string]any{"term": map[string]any{"tenant": "acme"}},
				"field_security": map[string]any{"grant": []any{"public_*", "tenant"}, "except": []any{"secret_*"}},
			},
		},
	}
	srv.securityUsers["alice"] = map[string]any{
		"username":          "alice",
		"roles":             []string{"acme_reader"},
		"full_name":         "Alice Smith",
		"email":             "alice@example.com",
		"metadata":          map[string]any{"team": "core"},
		"enabled":           true,
		"__password_pbkdf2": pbkdf2Hash,
	}
	srv.securityUsers["disabled_user"] = map[string]any{
		"username": "disabled_user",
		"roles":    []string{"superuser"},
		"enabled":  false,
		"password": "pw",
	}
	srv.securityAPIKeys["k_valid"] = map[string]any{
		"id":              "k_valid",
		"username":        "alice",
		"invalidated":     false,
		"__secret_sha256": hashSecuritySecretR66("sec-123"),
	}
	srv.securityAPIKeys["k_revoked"] = map[string]any{
		"id":              "k_revoked",
		"username":        "alice",
		"invalidated":     true,
		"__secret_sha256": hashSecuritySecretR66("sec-123"),
	}
	srv.securityServiceTokens["elastic/fleet-server/t1"] = map[string]any{
		"name":           "t1",
		"__token_pbkdf2": hashSecuritySecretPBKDF2R67("aae_r67_real_tok_1"),
	}
	srv.mu.Unlock()

	basicHdr := func(u, p string) map[string]string {
		return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))}
	}

	// _authenticate and core routes must fail closed (401) once dynamic security is configured.
	if rec := doR67HTTPReq(t, h, http.MethodGet, "/_security/_authenticate", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated _authenticate when security users exist, got %d", rec.Code)
	}
	if rec := doR67HTTPReq(t, h, http.MethodPost, "/sec_docs/_search", `{}`, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /sec_docs/_search when security users exist, got %d", rec.Code)
	}
	if rec := doR67HTTPReq(t, h, http.MethodGet, "/_cat/indices", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /_cat/indices when security users exist, got %d", rec.Code)
	}
	for _, badHdr := range []map[string]string{
		basicHdr("alice", "wrong"),
		basicHdr("disabled_user", "pw"),
		basicHdr("test_admin", "x-pack-test-password"), // AllowTestFixtureAuth defaults to false
		{"Authorization": "ApiKey " + base64.StdEncoding.EncodeToString([]byte("k_revoked:sec-123"))},
		{"Authorization": "Bearer wrong-token"},
		{"Authorization": "Bearer aae_doris_service_token_t1"}, // predictable fallback removed
	} {
		if rec := doR67HTTPReq(t, h, http.MethodGet, "/_security/_authenticate", "", badHdr); rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on _authenticate for %v, got %d %s", badHdr, rec.Code, rec.Body.String())
		}
	}

	// Valid PBKDF2 Basic auth returns resolved user metadata/roles.
	authOK := doR67HTTPReq(t, h, http.MethodGet, "/_security/_authenticate", "", basicHdr("alice", "pbkdf2-pw"))
	if authOK.Code != http.StatusOK || !strings.Contains(authOK.Body.String(), `"username":"alice"`) || !strings.Contains(authOK.Body.String(), `"acme_reader"`) || strings.Contains(authOK.Body.String(), `"superuser"`) {
		t.Fatalf("unexpected _authenticate payload for alice: %d %s", authOK.Code, authOK.Body.String())
	}

	// Service token Bearer auth succeeds with the hashed cryptographic token.
	svcOK := doR67HTTPReq(t, h, http.MethodGet, "/_security/_authenticate", "", map[string]string{"Authorization": "Bearer aae_r67_real_tok_1"})
	if svcOK.Code != http.StatusOK || !strings.Contains(svcOK.Body.String(), `"service_account":"elastic/fleet-server"`) {
		t.Fatalf("expected 200 for service token, got %d %s", svcOK.Code, svcOK.Body.String())
	}

	// RBAC: alice denied writing sec_docs & reading other_docs (403 security_exception).
	if r403Write := doR67HTTPReq(t, h, http.MethodPut, "/sec_docs/_doc/99", `{"public_msg":"hack"}`, basicHdr("alice", "pbkdf2-pw")); r403Write.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for read-only alice writing doc, got %d %s", r403Write.Code, r403Write.Body.String())
	}
	if r403Idx := doR67HTTPReq(t, h, http.MethodPost, "/other_docs/_search", `{}`, basicHdr("alice", "pbkdf2-pw")); r403Idx.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for alice reading other_docs, got %d %s", r403Idx.Code, r403Idx.Body.String())
	}

	// DLS + FLS: alice searching sec_docs only sees tenant=acme AND secret_ssn is stripped.
	searchRec := doR67HTTPReq(t, h, http.MethodPost, "/sec_docs/_search", `{"query":{"match_all":{}}}`, basicHdr("alice", "pbkdf2-pw"))
	if searchRec.Code != http.StatusOK {
		t.Fatalf("alice search failed: %d %s", searchRec.Code, searchRec.Body.String())
	}
	var searchBody map[string]any
	_ = json.Unmarshal(searchRec.Body.Bytes(), &searchBody)
	hitsSlice := searchBody["hits"].(map[string]any)["hits"].([]any)
	if len(hitsSlice) != 1 {
		t.Fatalf("expected DLS to filter sec_docs to 1 acme hit, got %d (%s)", len(hitsSlice), searchRec.Body.String())
	}
	src := hitsSlice[0].(map[string]any)["_source"].(map[string]any)
	if src["public_msg"] != "hello-acme" || src["secret_ssn"] != nil {
		t.Fatalf("expected FLS to allow public_msg and strip secret_ssn, got %+v", src)
	}

	// AllowTestFixtureAuth toggled on allows test_admin when !hasStaticAuth.
	srv.SetAllowTestFixtureAuth(true)
	taOK := doR67HTTPReq(t, h, http.MethodGet, "/_security/_authenticate", "", basicHdr("test_admin", "x-pack-test-password"))
	if taOK.Code != http.StatusOK || !strings.Contains(taOK.Body.String(), `"username":"test_admin"`) {
		t.Fatalf("expected test_admin allowed when SetAllowTestFixtureAuth(true), got %d %s", taOK.Code, taOK.Body.String())
	}
}

func TestRound67_ErrorPrecisionUnmergedCapsHistogramBudgetMSearchAndRegex(t *testing.T) {
	srv := NewServer("es_db", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	// 1. MySQL codes & precision in isTableNotFoundError.
	for _, pos := range []error{
		errors.New("Error 1146 (42S02): Table 'db.idx' doesn't exist"),
		errors.New("Error 1049 (42000): Unknown database 'es_db'"),
		errors.New("Table 't' doesn't exist"),
	} {
		if !isTableNotFoundError(pos) {
			t.Fatalf("expected isTableNotFoundError(%v) == true", pos)
		}
	}
	for _, neg := range []error{
		errors.New("Index [foo] doesn't exist in plugin cache"),
		errors.New("Column 'a' doesn't exist"),
	} {
		if isTableNotFoundError(neg) {
			t.Fatalf("expected isTableNotFoundError(%v) == false", neg)
		}
	}

	// 2. Unmerged overwritten source per-index (1000 docs / 16 MiB) & global (64 MiB) FIFO caps.
	for i := 0; i < 1050; i++ {
		srv.recordUnmergedOverwrittenSourceR66("cap_idx", []byte(fmt.Sprintf(`{"i":%d}`, i)))
	}
	if list := srv.getUnmergedOverwrittenSourcesR66("cap_idx"); len(list) != maxUnmergedDocsPerIndexR67 {
		t.Fatalf("expected 1000 cap on unmergedDeletedSources, got %d", len(list))
	} else if !strings.Contains(string(list[0]), `"i":50`) {
		t.Fatalf("expected FIFO eviction keeping i=50 first, got %s", string(list[0]))
	}
	bigDoc := bytes.Repeat([]byte("a"), 5*1024*1024)
	for i := 0; i < 16; i++ {
		srv.recordUnmergedOverwrittenSourceR66(fmt.Sprintf("big_idx_%d", i), bigDoc)
	}
	srv.mu.RLock()
	totalBytes := srv.unmergedTotalBytes
	srv.mu.RUnlock()
	if totalBytes > maxUnmergedTotalBytesR67 {
		t.Fatalf("expected global unmergedTotalBytes <= 64MiB, got %d", totalBytes)
	}

	// 3. Histogram shared search.max_buckets budget + math.MaxInt64 overflow guard.
	_ = doR67HTTPReq(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"search.max_buckets":20}}`, nil)
	_ = doR67HTTPReq(t, h, http.MethodPut, "/hist_idx", `{"mappings":{"properties":{"grp":{"type":"keyword"},"ts":{"type":"date"}}}}`, nil)
	for g := 0; g < 5; g++ {
		_ = doR67HTTPReq(t, h, http.MethodPut, fmt.Sprintf("/hist_idx/_doc/a%d?refresh=true", g), fmt.Sprintf(`{"grp":"g%d","ts":"2026-01-01T00:00:00Z"}`, g), nil)
		_ = doR67HTTPReq(t, h, http.MethodPut, fmt.Sprintf("/hist_idx/_doc/b%d?refresh=true", g), fmt.Sprintf(`{"grp":"g%d","ts":"2026-01-10T00:00:00Z"}`, g), nil)
	}
	histRes := doR67HTTPReq(t, h, http.MethodPost, "/hist_idx/_search", `{
		"size":0,
		"aggs":{"g":{"terms":{"field":"grp"},"aggs":{"d":{"date_histogram":{"field":"ts","calendar_interval":"day","min_doc_count":0}}}}}
	}`, nil)
	if histRes.Code != http.StatusBadRequest || !strings.Contains(histRes.Body.String(), "too_many_buckets_exception") {
		t.Fatalf("expected 400 too_many_buckets_exception for nested histogram > max_buckets, got %d %s", histRes.Code, histRes.Body.String())
	}

	// MaxInt64 step overflow guard does not wrap to MinInt64 or hang.
	zeroMin := 0
	maxIntRows := synthesizeHistogramBucketsWithBudgetR67(
		[]AggRow{{BucketKey: strconv.FormatInt(math.MaxInt64, 10), DocCount: 1}},
		&esast.HistogramAggSpec{Field: "v", Interval: 1, MinDocCount: &zeroMin},
		newHistBucketBudgetR67(10),
	)
	if len(maxIntRows) != 1 {
		t.Fatalf("expected 1 safe row at MaxInt64 without overflow loop, got %d", len(maxIntRows))
	}

	// 4. _msearch capped at 1024 NDJSON sub-requests.
	var msBuf strings.Builder
	for i := 0; i < 1025; i++ {
		msBuf.WriteString("{}\n{\"size\":0}\n")
	}
	msRec := doR67HTTPReq(t, h, http.MethodPost, "/_msearch", msBuf.String(), nil)
	if msRec.Code != http.StatusBadRequest || !strings.Contains(msRec.Body.String(), "too many sub-requests") {
		t.Fatalf("expected 400 on 1025 _msearch requests, got %d %s", msRec.Code, msRec.Body.String())
	}

	// 5. Auto-promote skips phantom absent fields, enforces TotalFieldsLimit, and copies settings.
	_ = doR67HTTPReq(t, h, http.MethodPut, "/promo_guard", `{
		"settings":{"index.mapping.total_fields.limit":2},
		"mappings":{"properties":{"a":{"type":"keyword"}}}
	}`, nil)
	srv.mu.RLock()
	promoTbl := srv.indices["promo_guard"].DorisTable
	srv.mu.RUnlock()
	if err := srv.backend.StreamLoad(context.Background(), promoTbl, []byte("{\"_id\":\"1\",\"_version\":1,\"__DORIS_DELETE_SIGN__\":0,\"_source\":\"{\\\"a\\\":\\\"v1\\\",\\\"real_dyn\\\":\\\"v2\\\",\\\"third_dyn\\\":\\\"v3\\\"}\",\"_doc\":\"{\\\"real_dyn\\\":\\\"v2\\\",\\\"third_dyn\\\":\\\"v3\\\"}\",\"f__a\":\"v1\"}\n"), true); err != nil {
		t.Fatalf("streamload promo_guard doc failed: %v", err)
	}
	ddlsAbsent, errAbsent := srv.promoteFieldInternal(context.Background(), "promo_guard", "phantom_field", "keyword")
	if errAbsent != nil || len(ddlsAbsent) != 0 {
		t.Fatalf("expected absent phantom field NOT to be promoted automatically, got ddls=%v err=%v", ddlsAbsent, errAbsent)
	}
	ddlsReal, errReal := srv.promoteFieldInternal(context.Background(), "promo_guard", "real_dyn", "keyword")
	if errReal != nil || len(ddlsReal) == 0 {
		t.Fatalf("expected present dynamic field to promote cleanly, got ddls=%v err=%v", ddlsReal, errReal)
	}
	// Promoting third field hits TotalFieldsLimit=2
	if _, errLim := srv.promoteFieldInternal(context.Background(), "promo_guard", "a", "keyword"); errLim != nil {
		t.Fatalf("already-mapped field should be noop: %v", errLim)
	}
	if _, errLim := srv.promoteFieldInternal(context.Background(), "promo_guard", "third_dyn", "keyword"); errLim == nil || !strings.Contains(errLim.Error(), "total fields") {
		t.Fatalf("expected TotalFieldsLimit rejection on 3rd promoted field, got err=%v", errLim)
	}

	// 6. Runtime regex compilation enforces MaxRegexPatternLen.
	longPat := strings.Repeat("a", 5000)
	if matchesTermsFilterPrecompiled("a", longPat, nil) {
		t.Fatalf("expected oversized regex pattern to fail closed")
	}
}

func TestRound67_CatalogSyncer_PreservesRequestCacheOnLocalWrites(t *testing.T) {
	mb := newMockProdExtBackendR67()
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	// 1. Local index creation + doc write + _stats must NOT cause CatalogSyncer to flush ShardRequestCache!
	if rec := doR67HTTPReq(t, h, http.MethodPut, "/rc_sync", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("create rc_sync failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doR67HTTPReq(t, h, http.MethodPut, "/rc_sync/_doc/1?refresh=true", `{"tag":"alpha"}`, nil); rec.Code != http.StatusCreated {
		t.Fatalf("index doc failed: %d %s", rec.Code, rec.Body.String())
	}
	aggBody := `{"size":0,"aggs":{"tags":{"terms":{"field":"tag"}}}}`
	if rec := doR67HTTPReq(t, h, http.MethodPost, "/rc_sync/_search?request_cache=true", aggBody, nil); rec.Code != http.StatusOK {
		t.Fatalf("search #1 failed: %d %s", rec.Code, rec.Body.String())
	}
	// GET _stats calls syncCatalogFromBackend, which hits the newly created catalog row via Sync.
	stRec := doR67HTTPReq(t, h, http.MethodGet, "/rc_sync/_stats/request_cache", "", nil)
	if stRec.Code != http.StatusOK {
		t.Fatalf("stats failed: %d %s", stRec.Code, stRec.Body.String())
	}
	if rec := doR67HTTPReq(t, h, http.MethodPost, "/rc_sync/_search?request_cache=true", aggBody, nil); rec.Code != http.StatusOK {
		t.Fatalf("search #2 failed: %d %s", rec.Code, rec.Body.String())
	}
	hits, misses, _, _ := srv.getShardRequestCacheStatsR63("rc_sync")
	if hits != 1 || misses != 1 {
		t.Fatalf("expected request_cache hits=1 misses=1 across local catalog sync, got hits=%d misses=%d", hits, misses)
	}

	// 2. Real out-of-band catalog schema mutation MUST invalidate both QueryResultCache and ShardRequestCache!
	srv.SetQueryCacheTTL(30*time.Second, 64)
	sReq := &esast.SearchRequest{}
	srv.queryCache.Put([]string{"rc_sync"}, sReq, map[string]any{"took": 1})
	curEntries, err := mb.LoadCatalogEntries(context.Background(), "es_db")
	if err != nil {
		t.Fatalf("LoadCatalogEntries failed: %v", err)
	}
	var updatedIdxEntry *CatalogEntry
	for i := range curEntries {
		if curEntries[i].EntityType == "index" && curEntries[i].EntityKey == "rc_sync" {
			cp := curEntries[i]
			updatedIdxEntry = &cp
			break
		}
	}
	if updatedIdxEntry == nil {
		t.Fatalf("missing rc_sync catalog entry")
	}
	origPayload := updatedIdxEntry.PayloadJSON
	var rawMap map[string]any
	if err := json.Unmarshal([]byte(origPayload), &rawMap); err != nil {
		t.Fatalf("unmarshal rc_sync payload failed: %v", err)
	}
	props, _ := rawMap["properties"].(map[string]any)
	if props == nil {
		props = make(map[string]any)
	}
	props["extra"] = map[string]any{"type": "long"}
	rawMap["properties"] = props
	mutatedBytes, err := json.Marshal(rawMap)
	if err != nil {
		t.Fatalf("marshal mutated rc_sync payload failed: %v", err)
	}
	updatedIdxEntry.PayloadJSON = string(mutatedBytes)
	if updatedIdxEntry.PayloadJSON == origPayload {
		t.Fatalf("expected mutated PayloadJSON to differ from original")
	}
	if nextEp := srv.catalogSyncer.lastEpochMs.Load() + 1000; nextEp > updatedIdxEntry.UpdatedEpochMs {
		updatedIdxEntry.UpdatedEpochMs = nextEp
	} else {
		updatedIdxEntry.UpdatedEpochMs += 1000
	}
	if err := mb.UpsertCatalogEntry(context.Background(), "es_db", *updatedIdxEntry); err != nil {
		t.Fatalf("UpsertCatalogEntry failed: %v", err)
	}
	if err := srv.syncCatalogFromBackend(context.Background()); err != nil {
		t.Fatalf("remote syncCatalogFromBackend failed: %v", err)
	}
	if _, ok := srv.queryCache.Get([]string{"rc_sync"}, sReq); ok {
		t.Fatalf("expected out-of-band schema change to invalidate queryCache")
	}
	scAfter := srv.getOrCompileReadOnlySchema(context.Background(), "rc_sync")
	if scAfter == nil || scAfter.Fields["extra"].ESType != "long" {
		t.Fatalf("expected out-of-band schema change to compile new field 'extra', got %+v", scAfter.Fields["extra"])
	}
}

func BenchmarkWithWireMiddleware(b *testing.B) {
	srv := NewServer("bench_db", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/_cluster/health", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rec.Code)
		}
	}
}

func BenchmarkSyncCatalog_NIndices(b *testing.B) {
	mb := newMockProdExtBackendR67()
	srv := NewServer("bench_db", mb, transpiler.TranspilerOptions{})
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/bench_idx_%02d", i), strings.NewReader(`{"mappings":{"properties":{"msg":{"type":"text"},"ts":{"type":"date"}}}}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("seed index %d failed: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if err := srv.syncCatalogFromBackend(context.Background()); err != nil {
		b.Fatalf("initial sync failed: %v", err)
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := srv.syncCatalogFromBackend(ctx); err != nil {
			b.Fatalf("incremental sync failed: %v", err)
		}
	}
}
