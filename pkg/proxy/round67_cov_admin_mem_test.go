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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// Keep all Round-67 W4 shared helpers & mocks strictly prefixed with r67AM / R67AM.

type r67AMRoundTripFunc func(*http.Request) (*http.Response, error)

func (f r67AMRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type r67AMPlainBackend struct{}

func (b *r67AMPlainBackend) Ping(context.Context) error                          { return nil }
func (b *r67AMPlainBackend) ExecDDL(context.Context, string) error               { return nil }
func (b *r67AMPlainBackend) QueryHits(context.Context, string) ([]HitRow, error) { return nil, nil }
func (b *r67AMPlainBackend) QueryAggs(context.Context, string) ([]AggRow, error) { return nil, nil }
func (b *r67AMPlainBackend) GetDocByID(context.Context, string, string, string) (*HitRow, bool, error) {
	return nil, false, nil
}
func (b *r67AMPlainBackend) GetDocsByIDs(context.Context, string, string, []string) (map[string]HitRow, error) {
	return nil, nil
}
func (b *r67AMPlainBackend) StreamLoad(context.Context, string, []byte, bool) error { return nil }

type r67AMMockBackend struct {
	*MemoryBackend
	mu             sync.Mutex
	loadErr        error
	sinceErr       error
	deleteErr      error
	extraEntries   []CatalogEntry
	sinceOverrides []CatalogEntry
	useSinceSlice  bool
	loadCalls      atomic.Int64
	sinceCalls     atomic.Int64
	deleteCalls    atomic.Int64
	queryRowsFn    func(ctx context.Context, sqlStr string) ([]map[string]any, error)
	backendsTel    []DorisBackendNodeTelemetry
	backendsTelErr error
	tablesTel      map[string]DorisTableDataTelemetry
	tablesTelErr   error
	clusterTel     *DorisClusterTelemetry
	aliveBEs       int
	feOK           bool
	healthErr      error
}

func newR67AMMockBackend() *r67AMMockBackend {
	return &r67AMMockBackend{
		MemoryBackend: NewMemoryBackend(false),
		aliveBEs:      3,
		feOK:          true,
		backendsTel: []DorisBackendNodeTelemetry{
			{
				BackendID:             "1001",
				Host:                  "10.0.1.11",
				HttpPort:              8040,
				Alive:                 true,
				TabletNum:             24,
				DataUsedCapacityBytes: 2048,
				AvailCapacityBytes:    1024 * 1024 * 1024,
				TotalCapacityBytes:    2048 * 1024 * 1024,
				CpuCores:              8,
				MemLimitBytes:         16 * 1024 * 1024 * 1024,
				Version:               "4.1.3",
			},
			{
				BackendID:             "1002",
				Host:                  "10.0.1.12",
				HttpPort:              8040,
				Alive:                 false,
				TabletNum:             12,
				DataUsedCapacityBytes: 1024,
				AvailCapacityBytes:    1024 * 1024 * 1024,
				TotalCapacityBytes:    2048 * 1024 * 1024,
				CpuCores:              8,
				MemLimitBytes:         16 * 1024 * 1024 * 1024,
				Version:               "4.1.3",
			},
		},
		tablesTel: map[string]DorisTableDataTelemetry{
			"r67_idx": {
				TableName:       "r67_idx",
				SizeBytes:       4096,
				RemoteSizeBytes: 512,
				ReplicaCount:    3,
				RowCount:        10,
			},
		},
	}
}

func (b *r67AMMockBackend) DeleteCatalogEntry(ctx context.Context, db, entityType, entityKey string) error {
	b.deleteCalls.Add(1)
	b.mu.Lock()
	err := b.deleteErr
	b.mu.Unlock()
	if err != nil {
		return err
	}
	return b.MemoryBackend.DeleteCatalogEntry(ctx, db, entityType, entityKey)
}

func (b *r67AMMockBackend) LoadCatalogEntries(ctx context.Context, db string) ([]CatalogEntry, error) {
	b.loadCalls.Add(1)
	b.mu.Lock()
	err := b.loadErr
	extra := append([]CatalogEntry(nil), b.extraEntries...)
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	base, err := b.MemoryBackend.LoadCatalogEntries(ctx, db)
	if err != nil {
		return nil, err
	}
	return append(base, extra...), nil
}

func (b *r67AMMockBackend) LoadCatalogEntriesSince(ctx context.Context, db string, sinceEpochMs int64) ([]CatalogEntry, error) {
	b.sinceCalls.Add(1)
	b.mu.Lock()
	err := b.sinceErr
	useCustom := b.useSinceSlice
	custom := append([]CatalogEntry(nil), b.sinceOverrides...)
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if useCustom {
		return custom, nil
	}
	all, err := b.LoadCatalogEntries(ctx, db)
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

func (b *r67AMMockBackend) QueryRows(ctx context.Context, sqlStr string) ([]map[string]any, error) {
	b.mu.Lock()
	fn := b.queryRowsFn
	b.mu.Unlock()
	if fn != nil {
		return fn(ctx, sqlStr)
	}
	return b.MemoryBackend.QueryRows(ctx, sqlStr)
}

func (b *r67AMMockBackend) ShowBackendsTelemetry(context.Context) ([]DorisBackendNodeTelemetry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.backendsTelErr != nil {
		return nil, b.backendsTelErr
	}
	return append([]DorisBackendNodeTelemetry(nil), b.backendsTel...), nil
}

func (b *r67AMMockBackend) ShowDataTelemetry(context.Context, string) (map[string]DorisTableDataTelemetry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tablesTelErr != nil {
		return nil, b.tablesTelErr
	}
	out := make(map[string]DorisTableDataTelemetry, len(b.tablesTel))
	for k, v := range b.tablesTel {
		out[k] = v
	}
	return out, nil
}

func (b *r67AMMockBackend) CollectClusterTelemetry(ctx context.Context, dbName string) *DorisClusterTelemetry {
	b.mu.Lock()
	ct := b.clusterTel
	b.mu.Unlock()
	if ct != nil {
		return ct
	}
	bes, _ := b.ShowBackendsTelemetry(ctx)
	tabs, _ := b.ShowDataTelemetry(ctx, dbName)
	var totCap, dataUsed, avail, totTablets int64
	alive := 0
	for _, be := range bes {
		totCap += be.TotalCapacityBytes
		dataUsed += be.DataUsedCapacityBytes
		avail += be.AvailCapacityBytes
		totTablets += be.TabletNum
		if be.Alive {
			alive++
		}
	}
	return &DorisClusterTelemetry{
		Backends:           bes,
		Tables:             tabs,
		AliveNodes:         alive,
		TotalNodes:         len(bes),
		TotalCapacityBytes: totCap,
		DataUsedBytes:      dataUsed,
		AvailCapacityBytes: avail,
		TotalTablets:       totTablets,
	}
}

func (b *r67AMMockBackend) CheckClusterHealth(context.Context) (int, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.aliveBEs, b.feOK, b.healthErr
}

func r67AMNewServer(t *testing.T, esVer string, b DorisBackend, opts transpiler.TranspilerOptions) (*Server, http.Handler) {
	t.Helper()
	srv := NewServer("es_r67am", b, opts)
	if esVer != "" {
		srv.SetTargetESVersion(esVer)
	}
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	return srv, srv.Handler()
}

func r67AMDoHTTP(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" && (headers == nil || headers["Content-Type"] == "") {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var m map[string]any
	if len(rec.Body.Bytes()) > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
	}
	return rec, m
}

func r67AMMustHTTP(t *testing.T, h http.Handler, method, path, body string, wantCode int) map[string]any {
	t.Helper()
	rec, m := r67AMDoHTTP(t, h, method, path, body, nil)
	if rec.Code != wantCode {
		t.Fatalf("%s %s status = %d, want %d; body=%s", method, path, rec.Code, wantCode, rec.Body.String())
	}
	return m
}

// ---------------------------------------------------------------------------
// Group A: Round-67 core modules (catalog_syncer.go, internal_routes.go,
// bm25_cache.go, streamload.go)
// ---------------------------------------------------------------------------

func TestRound67Cov_AdminMem_CatalogSyncerAndBoundedMaps(t *testing.T) {
	// 1. Bounded map helpers + catalogJSONEqualR67 + isEmptyCatalogAnyR67 + nil syncer guards
	strOuter := make(map[string]map[string]string)
	appendBoundedStringMapEntry(strOuter, "idx", "doc1", "r1", 0)
	appendBoundedStringMapEntry(strOuter, "idx", "doc2", "r2", 2)
	appendBoundedStringMapEntry(strOuter, "idx", "doc2", "r2b", 2) // update existing
	appendBoundedStringMapEntry(strOuter, "idx", "doc3", "r3", 2)  // beyond cap
	if len(strOuter["idx"]) != 2 {
		t.Fatalf("unexpected strOuter map: %#v", strOuter["idx"])
	}

	intOuter := make(map[string]map[string]int64)
	appendBoundedInt64MapEntry(intOuter, "idx", "d1", 10, 0)
	appendBoundedInt64MapEntry(intOuter, "idx", "d2", 20, 2)
	appendBoundedInt64MapEntry(intOuter, "idx", "d2", 25, 2) // update existing
	appendBoundedInt64MapEntry(intOuter, "idx", "d3", 30, 2) // beyond cap
	if len(intOuter["idx"]) != 2 {
		t.Fatalf("unexpected intOuter map: %#v", intOuter["idx"])
	}

	if !catalogJSONEqualR67(map[string]any{}, nil) {
		t.Fatalf("expected empty map and nil equal via isEmptyCatalogAnyR67")
	}
	if catalogJSONEqualR67(map[string]any{"a": 1}, map[string]any{"a": 2}) {
		t.Fatalf("expected different maps not equal")
	}
	if !isEmptyCatalogAnyR67(nil) || !isEmptyCatalogAnyR67([]string{}) || !isEmptyCatalogAnyR67(map[string]any{}) || isEmptyCatalogAnyR67(42) {
		t.Fatalf("unexpected isEmptyCatalogAnyR67 results")
	}

	var nilSyncer *CatalogSyncer
	if nilSyncer.LastEpochMs() != 0 {
		t.Fatalf("nil syncer LastEpochMs should be 0")
	}
	nilUnlock := nilSyncer.LockIndexDDL("x")
	nilUnlock()
	if err := nilSyncer.Sync(context.Background()); err != nil {
		t.Fatalf("nil syncer Sync should return nil, got %v", err)
	}
	nilSyncer.Start(10 * time.Millisecond)
	nilSyncer.Stop()

	var nilSrv *Server
	uNil := nilSrv.LockIndexDDL("x")
	uNil()
	nilSrv.SetCatalogSyncInterval(10 * time.Millisecond)

	// Non-CatalogBackend server -> Sync is no-op
	plainSrv, _ := r67AMNewServer(t, "8.15.0", &r67AMPlainBackend{}, transpiler.TranspilerOptions{})
	if err := plainSrv.catalogSyncer.Sync(context.Background()); err != nil {
		t.Fatalf("plain backend sync error: %v", err)
	}

	// 2. Populate shared CatalogBackend from srv1 across ALL 11 entity types
	mb := newR67AMMockBackend()
	srv1, h1 := r67AMNewServer(t, "8.15.0", mb, transpiler.TranspilerOptions{})
	_ = srv1

	r67AMMustHTTP(t, h1, http.MethodPut, "/_component_template/r67_comp", `{"template":{"mappings":{"properties":{"comp_f":{"type":"keyword"}}}}}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/_index_template/r67_tpl", `{"index_patterns":["r67_*"],"composed_of":["r67_comp"],"template":{"settings":{"number_of_shards":1},"mappings":{"properties":{"title":{"type":"text"},"ts":{"type":"date"}}}}}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/_template/r67_leg", `{"index_patterns":["r67leg_*"],"mappings":{"properties":{"v":{"type":"long"}}}}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/_ingest/pipeline/r67_pipe", `{"processors":[{"set":{"field":"tagged","value":true}}]}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/_ingest/pipeline/r67_final", `{"processors":[{"set":{"field":"finalized","value":true}}]}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/_ilm/policy/r67_ilm", `{"policy":{"phases":{"hot":{"actions":{}}}}}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/_scripts/r67_scr", `{"script":{"lang":"painless","source":"doc['v'].value + 1"}}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/r67_idx", `{
		"settings":{"index":{"default_pipeline":"r67_pipe","final_pipeline":"r67_final","custom_k":"custom_v"}},
		"mappings":{"properties":{"title":{"type":"text"},"v":{"type":"long"}}}
	}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/r67_idx/_doc/1?refresh=true", `{"title":"hello","v":5}`, http.StatusCreated)
	r67AMMustHTTP(t, h1, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"r67_idx","alias":"r67_al","is_write_index":true,"filter":{"term":{"v":5}}}}]}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/r67_src_enr", `{"mappings":{"properties":{"k":{"type":"keyword"},"val":{"type":"keyword"}}}}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/_enrich/policy/r67_enr", `{"match":{"indices":"r67_src_enr","match_field":"k","enrich_fields":["val"]}}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/_index_template/r67_ds_tpl", `{"index_patterns":["r67ds-*"],"data_stream":{},"priority":200,"template":{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}}`, http.StatusOK)
	r67AMMustHTTP(t, h1, http.MethodPut, "/_data_stream/r67ds-logs", "", http.StatusOK)

	// 3. Replica srv2 syncs from empty, then exercises incremental + bad JSON + unknown + tombstones + ticker error
	srv2, _ := r67AMNewServer(t, "8.15.0", mb, transpiler.TranspilerOptions{})
	if err := srv2.catalogSyncer.Sync(context.Background()); err != nil {
		t.Fatalf("replica initial sync failed: %v", err)
	}
	if srv2.catalogSyncer.LastEpochMs() == 0 {
		t.Fatalf("expected non-zero LastEpochMs after sync")
	}

	// Verify LockIndexDDL normal + empty fallback
	un1 := srv2.LockIndexDDL("")
	un1()
	un2 := srv2.LockIndexDDL("r67_idx")
	un2()

	// Exercise incremental path: stale epoch entries skipped + malformed JSON across all entity types + deletions + unknown type
	nowMs := time.Now().UnixMilli()
	oldExpired := nowMs - int64(24*time.Hour/time.Millisecond)
	srv2.catalogSyncer.lastEpochMs.Store(nowMs - 5000)

	validIdxPayload, _ := json.Marshal(map[string]any{
		"properties":               map[string]any{"msg": map[string]any{"type": "text"}},
		"_default_pipeline":        "r67_pipe",
		"_final_pipeline":          "r67_final",
		"_custom_settings":         map[string]any{"refresh_interval": "5s"},
		"_adopted_constant_fields": []string{"msg"},
		"_closed":                  true,
	})
	mb.mu.Lock()
	mb.useSinceSlice = true
	mb.sinceOverrides = []CatalogEntry{
		{EntityType: "template", EntityKey: "stale_tpl", PayloadJSON: `{}`, UpdatedEpochMs: 1}, // skipped (< lastEpochMs)
		{EntityType: "template", EntityKey: "bad_tpl", PayloadJSON: `{bad`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "legacy_template", EntityKey: "bad_leg", PayloadJSON: `{bad`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "component_template", EntityKey: "bad_comp", PayloadJSON: `{bad`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "pipeline", EntityKey: "bad_pipe", PayloadJSON: `{bad`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "enrich_policy", EntityKey: "bad_enr", PayloadJSON: `{bad`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "alias", EntityKey: "bad_al", PayloadJSON: `{bad`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "data_stream", EntityKey: "bad_ds", PayloadJSON: `{bad`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "ilm_policy", EntityKey: "bad_ilm", PayloadJSON: `{bad`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "script", EntityKey: "bad_scr", PayloadJSON: `{bad`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "index_seq_state", EntityKey: "bad_seq", PayloadJSON: `{bad`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "unknown_entity", EntityKey: "unk", PayloadJSON: `{}`, UpdatedEpochMs: nowMs + 10},
		{EntityType: "index", EntityKey: "r67_delta_idx", PayloadJSON: string(validIdxPayload), UpdatedEpochMs: nowMs + 11},
		{EntityType: "alias", EntityKey: "r67_al_str", PayloadJSON: `["r67_idx"]`, UpdatedEpochMs: nowMs + 11},
		{EntityType: "template", EntityKey: "r67_tpl", PayloadJSON: "__DELETED__", UpdatedEpochMs: nowMs + 12},
		{EntityType: "legacy_template", EntityKey: "r67_leg", PayloadJSON: "__DELETED__", UpdatedEpochMs: nowMs + 12},
		{EntityType: "component_template", EntityKey: "r67_comp", PayloadJSON: "__DELETED__", UpdatedEpochMs: nowMs + 12},
		{EntityType: "pipeline", EntityKey: "r67_pipe", PayloadJSON: "__DELETED__", UpdatedEpochMs: nowMs + 12},
		{EntityType: "enrich_policy", EntityKey: "r67_enr", PayloadJSON: "__DELETED__", UpdatedEpochMs: nowMs + 12},
		{EntityType: "alias", EntityKey: "r67_al", PayloadJSON: "__DELETED__", UpdatedEpochMs: nowMs + 12},
		{EntityType: "data_stream", EntityKey: "r67ds-logs", PayloadJSON: "__DELETED__", UpdatedEpochMs: nowMs + 12},
		{EntityType: "ilm_policy", EntityKey: "r67_ilm", PayloadJSON: "__DELETED__", UpdatedEpochMs: nowMs + 12},
		{EntityType: "script", EntityKey: "r67_scr", PayloadJSON: "__DELETED__", UpdatedEpochMs: nowMs + 12},
		{EntityType: "index_seq_state", EntityKey: "r67_idx", PayloadJSON: "__DELETED__", UpdatedEpochMs: nowMs + 12},
		{EntityType: "index", EntityKey: "r67_src_enr", PayloadJSON: "__DELETED__", UpdatedEpochMs: oldExpired},
	}
	mb.deleteErr = errors.New("purge err simulated")
	mb.mu.Unlock()

	if err := srv2.catalogSyncer.Sync(context.Background()); err != nil {
		t.Fatalf("incremental sync failed: %v", err)
	}
	if mb.deleteCalls.Load() == 0 {
		t.Fatalf("expected tombstone DeleteCatalogEntry call")
	}

	// Re-sync with deleteErr cleared -> should purge tombstone cleanly; then inject sinceErr + Start/Stop ticker
	mb.mu.Lock()
	mb.deleteErr = nil
	mb.sinceOverrides = []CatalogEntry{
		{EntityType: "index", EntityKey: "r67_idx", PayloadJSON: "__DELETED__", UpdatedEpochMs: oldExpired},
	}
	mb.mu.Unlock()
	if err := srv2.catalogSyncer.Sync(context.Background()); err != nil {
		t.Fatalf("tombstone purge sync failed: %v", err)
	}

	mb.mu.Lock()
	mb.sinceErr = errors.New("incremental query boom")
	mb.mu.Unlock()
	if err := srv2.catalogSyncer.Sync(context.Background()); err == nil {
		t.Fatalf("expected error from incremental backend")
	}

	// Exercise background Start / restart / Stop error logging
	srv2.SetCatalogSyncInterval(10 * time.Millisecond)
	time.Sleep(35 * time.Millisecond)
	srv2.SetCatalogSyncInterval(15 * time.Millisecond) // restarts previous ticker
	srv2.SetCatalogSyncInterval(0)                     // stops ticker
}

func TestRound67Cov_AdminMem_InternalRoutesDesiredAndPrevalidate(t *testing.T) {
	mb := newR67AMMockBackend()
	srv, h := r67AMNewServer(t, "8.15.0", mb, transpiler.TranspilerOptions{})
	r67AMMustHTTP(t, h, http.MethodPut, "/r67_idx", `{"mappings":{"properties":{"msg":{"type":"text"}}}}`, http.StatusOK)

	// 1. Direct helper checks
	if got := cloneJSONValueR67(map[string]any{"k": []any{"v1", map[string]any{"n": 2}}}); got == nil {
		t.Fatalf("cloneJSONValueR67 returned nil")
	}
	if cloned := cloneDesiredNodesSliceR67([]map[string]any{{"node_id": "n1", "nested": map[string]any{"a": 1}}}); len(cloned) != 1 {
		t.Fatalf("cloneDesiredNodesSliceR67 failed: %#v", cloned)
	}
	if len(cloneDesiredNodesSliceR67(nil)) != 0 {
		t.Fatalf("cloneDesiredNodesSliceR67(nil) should be empty")
	}
	if list, ok := extractPrevalidateStringListR67([]any{"a", " ", "a", "b"}); !ok || len(list) != 3 {
		t.Fatalf("extractPrevalidateStringListR67 unexpected: %v %v", list, ok)
	}
	if _, ok := extractPrevalidateStringListR67([]any{123}); ok {
		t.Fatalf("expected extractPrevalidateStringListR67 to reject non-string elements")
	}
	if _, ok := extractPrevalidateStringListR67(123); ok {
		t.Fatalf("expected extractPrevalidateStringListR67 to reject non-list/string")
	}
	for _, bad := range []any{"NaN", math.NaN(), math.Inf(1), -1.0, "0", true} {
		if _, err := parseStrictPositiveFiniteFloatR67(bad, "test_f"); err == nil {
			t.Fatalf("expected parseStrictPositiveFiniteFloatR67 to reject %v", bad)
		}
	}
	if v, err := parseStrictPositiveFiniteFloatR67(2.5, "test_f"); err != nil || v != 2.5 {
		t.Fatalf("expected 2.5, got %v err=%v", v, err)
	}
	if _, err := parseStrictPositiveFiniteFloatR67("2.5", "test_f"); err == nil {
		t.Fatalf("expected parseStrictPositiveFiniteFloatR67 to reject string 2.5")
	}

	// 2. Unknown /_internal subroutes & method rejections
	r67AMMustHTTP(t, h, http.MethodGet, "/_internal/nope", "", http.StatusNotFound)
	r67AMMustHTTP(t, h, http.MethodPost, "/_internal/desired_balance", "", http.StatusMethodNotAllowed)
	r67AMMustHTTP(t, h, http.MethodPost, "/_internal/desired_nodes/bad_only_one", "", http.StatusNotFound)

	// 3. desired_balance GET/HEAD (ES 8 and ES 7) + index stats + TelemetryBackend fallback + DELETE
	recHead, _ := r67AMDoHTTP(t, h, http.MethodHead, "/_internal/desired_balance", "", nil)
	if recHead.Code != http.StatusOK {
		t.Fatalf("HEAD desired_balance failed: %d", recHead.Code)
	}
	srv.mu.Lock()
	stLive := &indexLiveStats{}
	stLive.indexTotal.Store(5)
	srv.indexStats["r67_idx"] = stLive
	srv.mu.Unlock()
	bal8 := r67AMMustHTTP(t, h, http.MethodGet, "/_internal/desired_balance?timeout=5s", "", http.StatusOK)
	if bal8["routing_table"] == nil {
		t.Fatalf("expected routing_table in desired_balance response: %#v", bal8)
	}
	srv7, h7 := r67AMNewServer(t, "7.17.10", mb, transpiler.TranspilerOptions{})
	_ = srv7
	r67AMMustHTTP(t, h7, http.MethodGet, "/_internal/desired_balance", "", http.StatusOK)
	r67AMMustHTTP(t, h, http.MethodDelete, "/_internal/desired_balance", "", http.StatusOK)

	// 4. desired_nodes: GET empty -> 404, POST/invalid method -> 405, PUT validation error matrix
	r67AMMustHTTP(t, h, http.MethodGet, "/_internal/desired_nodes/_latest", "", http.StatusNotFound)
	r67AMMustHTTP(t, h, http.MethodPost, "/_internal/desired_nodes/_latest", "", http.StatusMethodNotAllowed)
	r67AMMustHTTP(t, h, http.MethodPost, "/_internal/desired_nodes/h1/1", "", http.StatusNotFound)

	invalidPayloads := []string{
		`{`,
		`{"nodes":"bad"}`,
		`{"nodes":[123]}`,
		`{"nodes":[{"external_id":"ext1"}]}`, // no node_id/node_name
		`{"nodes":[{"node_id":"n1"},{"node_id":"n1"}]}`,                                                                       // duplicate node_id
		`{"nodes":[{"node_name":"a"},{"node_name":"a"}]}`,                                                                     // duplicate node_name
		`{"nodes":[{"node_id":"n1","node_name":"a","external_id":"e1"},{"node_id":"n2","node_name":"b","external_id":"e1"}]}`, // dup ext
		`{"nodes":[{"node_id":"n1","settings":{"node.roles":["bad_role"]}}]}`,
		`{"nodes":[{"node_id":"n1","processors":2,"processors_range":{"min":1,"max":4}}]}`,
		`{"nodes":[{"node_id":"n1","processors":0}]}`,
		`{"nodes":[{"node_id":"n1","processors_range":"bad"}]}`,
		`{"nodes":[{"node_id":"n1","processors_range":{"min":4,"max":2}}]}`,
		`{"nodes":[{"node_id":"n1","memory":0}]}`,
		`{"nodes":[{"node_id":"n1","storage":-5}]}`,
		`{"nodes":[{"node_id":"n1","node_version":"8.15.0"}]}`,
		`{"nodes":[{"node_id":"n1","settings":{"a.b":"x","a":"conflict"}}]}`,
	}
	for i, bad := range invalidPayloads {
		rec, _ := r67AMDoHTTP(t, h, http.MethodPut, "/_internal/desired_nodes/hist1/1", bad, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("case %d expected 400, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	// ES 7 rejects node.roles=[] empty + non-object settings
	r67AMMustHTTP(t, h7, http.MethodPut, "/_internal/desired_nodes/hist1/1", `{"nodes":[{"node_id":"n1","settings":{"node.roles":[]}}]}`, http.StatusBadRequest)
	r67AMMustHTTP(t, h, http.MethodPut, "/_internal/desired_nodes/hist1/1", `{"nodes":[{"node_id":"n1","node_name":"node-1","node_version":"8.15.0"}],"extra":1}`, http.StatusBadRequest)

	// Valid dry_run then real write + idempotent replay + digest mismatch + version conflict + new history_id
	validDesiredBody := `{
		"nodes":[
			{"processors":4,"memory":"4gb","storage":"100gb","settings":{"node.name":"node-1","node.external_id":"ext-1","node.roles":["master","data_hot","ingest"],"node.attr.rack":"r1"}},
			{"processors_range":{"min":1.5,"max":4},"memory":"1gb","storage":"2gb","node_version":"8.15.0","settings":{"node":{"name":"node-2","external_id":"ext-2","roles":["data_warm"]}}}
		]
	}`
	dryRes := r67AMMustHTTP(t, h, http.MethodPut, "/_internal/desired_nodes/hist1/1?dry_run=true", validDesiredBody, http.StatusOK)
	if dryRes["dry_run"] != true {
		t.Fatalf("expected dry_run=true in dry_run response, got %#v", dryRes)
	}
	r67AMMustHTTP(t, h, http.MethodPut, "/_internal/desired_nodes/hist1/1", validDesiredBody, http.StatusOK)
	r67AMMustHTTP(t, h, http.MethodPut, "/_internal/desired_nodes/hist1/1", validDesiredBody, http.StatusOK) // idempotent replay
	r67AMMustHTTP(t, h, http.MethodPut, "/_internal/desired_nodes/hist1/1", `{"nodes":[{"node_id":"n3"}]}`, http.StatusBadRequest)
	r67AMMustHTTP(t, h, http.MethodPut, "/_internal/desired_nodes/hist1/9", validDesiredBody, http.StatusOK)
	r67AMMustHTTP(t, h, http.MethodPut, "/_internal/desired_nodes/hist1/5", validDesiredBody, http.StatusConflict)
	r67AMMustHTTP(t, h, http.MethodPut, "/_internal/desired_nodes/hist2/5", validDesiredBody, http.StatusOK) // replaces historyID

	latest := r67AMMustHTTP(t, h, http.MethodGet, "/_internal/desired_nodes/_latest", "", http.StatusOK)
	if latest["history_id"] != "hist2" {
		t.Fatalf("expected hist2, got %#v", latest)
	}
	recHN, _ := r67AMDoHTTP(t, h, http.MethodHead, "/_internal/desired_nodes/_latest", "", nil)
	if recHN.Code != http.StatusOK {
		t.Fatalf("HEAD desired_nodes/_latest failed: %d", recHN.Code)
	}
	r67AMMustHTTP(t, h, http.MethodDelete, "/_internal/desired_nodes/_latest", "", http.StatusMethodNotAllowed)

	// 5. prevalidate_node_removal: method guard, query params, JSON body params, unknown nodes -> 404, bad JSON -> 400
	r67AMMustHTTP(t, h, http.MethodGet, "/_internal/prevalidate_node_removal", "", http.StatusMethodNotAllowed)
	r67AMMustHTTP(t, h, http.MethodPost, "/_internal/prevalidate_node_removal", "", http.StatusBadRequest)
	r67AMMustHTTP(t, h, http.MethodPost, "/_internal/prevalidate_node_removal", `{bad`, http.StatusBadRequest)
	r67AMMustHTTP(t, h, http.MethodPost, "/_internal/prevalidate_node_removal?names=a&ids=b", "", http.StatusBadRequest)
	r67AMMustHTTP(t, h, http.MethodPost, "/_internal/prevalidate_node_removal?names=nonexistent", "", http.StatusNotFound)
	prevOK := r67AMMustHTTP(t, h, http.MethodPost, "/_internal/prevalidate_node_removal?names="+taskLocalNodeID, "", http.StatusOK)
	if len(prevOK) == 0 {
		t.Fatalf("expected non-empty prevalidate response")
	}
	r67AMMustHTTP(t, h, http.MethodPost, "/_internal/prevalidate_node_removal", fmt.Sprintf(`{"ids":[%q]}`, taskLocalNodeID), http.StatusOK)
	r67AMMustHTTP(t, h, http.MethodPost, "/_internal/prevalidate_node_removal", fmt.Sprintf(`{"external_ids":[%q]}`, taskLocalNodeID), http.StatusOK)
}

func TestRound67Cov_AdminMem_BM25CacheModesAndCorpusScan(t *testing.T) {
	// 1. Mode normalization, nil receiver guards, metric summary formatting
	var nilSrv *Server
	if nilSrv.BM25Mode() != BM25ModeAuto {
		t.Fatalf("nil Server BM25Mode should be auto")
	}
	nilSrv.SetBM25Mode(BM25ModeApprox)
	if nilSrv.BM25MaxRows() != defaultBM25MaxRowsR67 {
		t.Fatalf("nil Server BM25MaxRows unexpected: %d", nilSrv.BM25MaxRows())
	}
	nilSrv.SetBM25MaxRows(123)
	if nilSrv.formatBM25MetricLabelsSummary() != "50000" {
		t.Fatalf("nil formatBM25MetricLabelsSummary unexpected: %q", nilSrv.formatBM25MetricLabelsSummary())
	}
	for _, tc := range []struct{ in, want string }{
		{"", BM25ModeAuto},
		{"AUTO", BM25ModeAuto},
		{"doris-score", BM25ModeDorisScore},
		{"exact-corpus-scan", BM25ModeExactCorpusScan},
		{"approx", BM25ModeApprox},
		{"unknown-mode", BM25ModeAuto},
	} {
		if got := normalizeBM25ModeR67(tc.in); got != tc.want {
			t.Fatalf("normalizeBM25ModeR67(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// 2. Cache eviction, over-row cap, table invalidation, cloning
	c := newBM25CorpusCacheR67()
	now := time.Now()
	c.invalidateAll()
	c.invalidateTable("", "t1")
	c.invalidateTable("db", "t1")
	if _, ok := c.getOverRowCap("k", now); ok {
		t.Fatalf("unexpected hit on empty overCap")
	}
	for i := 0; i < maxBM25CacheEntriesR67+5; i++ {
		c.markOverRowCap(fmt.Sprintf("db|t|%d", i), int64(i+100), now)
		c.put(fmt.Sprintf("db|t|%d", i), map[string]*transpiler.BM25FieldTermStats{
			"f": {TotalDocs: 10, AvgDL: 2.5, TermDocFreq: map[string]int64{"foo": 3}},
		}, now)
	}
	if _, ok := c.get("db|t|0", now.Add(time.Hour)); ok {
		t.Fatalf("expected expired cache miss")
	}
	c.invalidateTable("db", "t")
	if cloneBM25StatsMapR67(nil) != nil {
		t.Fatalf("cloneBM25StatsMapR67(nil) should be nil")
	}

	// 3. Helper functions: dedup/cap, merge, SQL keyword & alias WHERE extraction, approx stats
	reqs := dedupAndCapBM25ReqsR67([]transpiler.BM25QueryRequirement{
		{Field: "title", ColExpr: "`t1`", CaseSensitive: true, Terms: []string{"Alpha", "Beta", ""}},
		{Field: "title", ColExpr: "`t1`", CaseSensitive: true, Terms: []string{"Gamma", "Alpha"}},
		{Field: "", ColExpr: "", Terms: []string{"skip"}},
	}, 2)
	if len(reqs) != 1 || len(reqs[0].Terms) != 2 {
		t.Fatalf("unexpected dedup/cap reqs: %#v", reqs)
	}
	if dedupAndCapBM25ReqsR67(reqs, 0) != nil {
		t.Fatalf("capTerms<=0 should return nil")
	}

	opts := transpiler.TranspilerOptions{}
	mergeBM25StatsIntoOptsR67(&opts, reqs, map[string]*transpiler.BM25FieldTermStats{
		"`t1`": {TotalDocs: 100, AvgDL: 4.0, TermDocFreq: map[string]int64{"Alpha": 10}},
	})
	if opts.CorpusBM25Stats["title"] == nil || opts.CorpusBM25Stats["`t1`"] == nil {
		t.Fatalf("expected merged BM25 stats under both Field and ColExpr: %#v", opts.CorpusBM25Stats)
	}

	approx := buildApproxBM25StatsR67(reqs, 50)
	if approx["`t1`"] == nil || approx["`t1`"].TotalDocs != 50 {
		t.Fatalf("unexpected approx stats: %#v", approx)
	}

	if !matchesSQLKeywordAtR67("SELECT * FROM T WHERE A=1", 16, "WHERE") || matchesSQLKeywordAtR67("WHERE_X", 0, "WHERE") {
		t.Fatalf("matchesSQLKeywordAtR67 failed")
	}
	if got := extractOuterWherePredicateR67("SELECT * FROM (SELECT 1 WHERE x=1) t WHERE `tenant` = 'a' AND status = 'ok' ORDER BY `_score` DESC LIMIT 10"); !strings.Contains(got, "`tenant`") {
		t.Fatalf("extractOuterWherePredicateR67 unexpected: %q", got)
	}
	if extractOuterWherePredicateR67("SELECT 'WHERE ignored' FROM t") != "" {
		t.Fatalf("expected quoted WHERE ignored")
	}

	// 4. populateCorpusBM25StatsWithCacheR67 across backends & modes
	memSrv, memH := r67AMNewServer(t, "8.15.0", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	r67AMMustHTTP(t, memH, http.MethodPut, "/articles", `{"mappings":{"properties":{"title":{"type":"text"},"tenant":{"type":"keyword"}}}}`, http.StatusOK)
	memIdx := memSrv.indices["articles"]
	sReq := &esast.SearchRequest{
		Query:       &esast.Query{Match: map[string]esast.MatchEntry{"title": {Query: "hello world"}}},
		AliasFilter: &esast.Query{Term: map[string]esast.TermEntry{"tenant": {Value: "t1"}}},
	}
	if pred := extractAliasWherePredicateR67(memIdx, sReq, transpiler.TranspilerOptions{}); !strings.Contains(pred, "f__tenant") {
		t.Fatalf("expected extracted alias predicate, got %q", pred)
	}
	// MemoryBackend returns early in populateCorpusBM25StatsWithCacheR67
	memOpts := transpiler.TranspilerOptions{}
	memSrv.populateCorpusBM25StatsWithCacheR67(context.Background(), memIdx, sReq, &memOpts)

	// Plain non-SQLRowsBackend triggers approx fallback
	plainSrv, _ := r67AMNewServer(t, "8.15.0", &r67AMPlainBackend{}, transpiler.TranspilerOptions{})
	plainOpts := transpiler.TranspilerOptions{}
	plainSrv.populateCorpusBM25StatsWithCacheR67(context.Background(), memIdx, sReq, &plainOpts)

	// Full SQLRowsBackend tests
	mb := newR67AMMockBackend()
	srv, _ := r67AMNewServer(t, "8.15.0", mb, transpiler.TranspilerOptions{})
	srv.SetBM25Mode(BM25ModeDorisScore)
	dsOpts := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsWithCacheR67(context.Background(), memIdx, sReq, &dsOpts)
	if !dsOpts.UseDoris4SearchFunc {
		t.Fatalf("expected UseDoris4SearchFunc=true in doris-score mode")
	}

	srv.SetBM25Mode(BM25ModeApprox)
	appOpts := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsWithCacheR67(context.Background(), memIdx, sReq, &appOpts)

	// Auto mode with QueryRows error, empty rows, over-cap, and full hit + cache hit + invalidation
	srv.SetBM25Mode(BM25ModeAuto)
	srv.SetBM25MaxRows(100)

	mb.mu.Lock()
	mb.queryRowsFn = func(context.Context, string) ([]map[string]any, error) {
		return nil, errors.New("query rows failed")
	}
	mb.mu.Unlock()
	errOpts := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsWithCacheR67(context.Background(), memIdx, sReq, &errOpts)

	mb.mu.Lock()
	mb.queryRowsFn = func(context.Context, string) ([]map[string]any, error) {
		return nil, nil
	}
	mb.mu.Unlock()
	emptyOpts := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsWithCacheR67(context.Background(), memIdx, sReq, &emptyOpts)

	// Success scan -> populate cache -> invalidateBM25ForIndexR67
	var sqlCount atomic.Int64
	mb.mu.Lock()
	mb.queryRowsFn = func(context.Context, string) ([]map[string]any, error) {
		sqlCount.Add(1)
		return []map[string]any{{
			"__bm25_total_rows": int64(25),
			"__bm25_n_0":        int64(20),
			"__bm25_avgdl_0":    float64(3.5),
			"__bm25_df_0_0":     int64(5),
			"__bm25_df_0_1":     int64(8),
		}}, nil
	}
	mb.mu.Unlock()
	okOpts := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsWithCacheR67(context.Background(), memIdx, sReq, &okOpts)
	if okOpts.CorpusBM25Stats["title"] == nil || okOpts.CorpusBM25Stats["title"].TotalDocs != 20 {
		t.Fatalf("expected populated CorpusBM25Stats, got %#v", okOpts.CorpusBM25Stats)
	}
	// Cache hit
	okOpts2 := transpiler.TranspilerOptions{}
	srv.populateCorpusBM25StatsWithCacheR67(context.Background(), memIdx, sReq, &okOpts2)
	if sqlCount.Load() != 1 {
		t.Fatalf("expected 1 SQL scan due to cache hit, got %d", sqlCount.Load())
	}

	srv.mu.Lock()
	srv.indices["articles"] = memIdx
	srv.mu.Unlock()
	srv.invalidateBM25ForIndexR67("articles")
	srv.invalidateBM25ForIndexR67("nonexistent")

	// Summary labels helper
	_ = srv.formatBM25MetricLabelsSummary()
}

func TestRound67Cov_AdminMem_StreamLoadClientEdgePaths(t *testing.T) {
	// 1. Pure helpers: extractStreamLoadHost, parseNormalizedStreamLoadIP, jitter, nonRetryable, userinfo, trustedHost
	if extractStreamLoadHost("http://[::1]:8030/x") != "::1" || extractStreamLoadHost("[fe80::1]:8030") != "fe80::1" || extractStreamLoadHost("") != "" {
		t.Fatalf("unexpected extractStreamLoadHost result")
	}
	if _, ok := parseNormalizedStreamLoadIP("not-an-ip"); ok {
		t.Fatalf("expected false for non-IP")
	}
	if addr, ok := parseNormalizedStreamLoadIP("[::1]"); !ok || !addr.IsLoopback() {
		t.Fatalf("expected parsed loopback IPv6, got %v %v", addr, ok)
	}
	if d := jitteredStreamLoadDelay(3, 10*time.Millisecond, 5*time.Millisecond); d < 0 || d > 5*time.Millisecond {
		t.Fatalf("jitteredStreamLoadDelay exceeded cap: %v", d)
	}
	if jitteredStreamLoadDelay(0, 0, 0) != time.Millisecond {
		t.Fatalf("expected 1ms floor delay when base<=0")
	}
	if isNonRetryableStreamLoadErr(nil) || !isNonRetryableStreamLoadErr(context.Canceled) || !isNonRetryableStreamLoadErr(errors.New("stream load rejected scheme")) || isNonRetryableStreamLoadErr(errors.New("temporary reset")) {
		t.Fatalf("isNonRetryableStreamLoadErr classification mismatch")
	}

	// 2. Host/URL/Redirect validation on HTTPS non-loopback FE client + DialContext allow/deny + lookupNetIP hooks
	nonLoopClient := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint:       "https://fe1.prod.local:8030",
		User:                 "doris_u",
		Password:             "secret",
		Database:             "es_db",
		Timeout:              time.Second,
		MaxBatchBytes:        64,
		MaxRetries:           1,
		BaseBackoff:          time.Millisecond,
		MaxBackoff:           2 * time.Millisecond,
		MaxConcurrentUploads: 1,
	})
	if nonLoopClient.isConfiguredFELoopback() {
		t.Fatalf("expected non-loopback FE client")
	}
	nonLoopClient.AllowBEHosts([]string{"10.1.2.3:8040", "http://10.1.2.4:8040", "169.254.169.254:8040", ""})
	nonLoopClient.SetDiscoveredBEs([]string{
		"http://10.1.2.5:8040",  // scheme downgrade from HTTPS FE -> rejected
		"https://10.1.2.5:8040", // valid HTTPS BE
		"https://169.254.169.254:8040",
		"https://10.1.2.6:8040?x=1", // query rejected
		"https://user:pw@10.1.2.7:8040",
	})
	if len(nonLoopClient.AllowedBEHosts()) == 0 || !nonLoopClient.hasAllowedBEHost("10.1.2.5") {
		t.Fatalf("expected 10.1.2.5 in AllowedBEHosts: %v", nonLoopClient.AllowedBEHosts())
	}

	uGood, _ := url.Parse("https://10.1.2.5:8040/api/db/tbl/_stream_load")
	if _, err := nonLoopClient.validateStreamLoadTargetHostAndScheme(uGood); err != nil {
		t.Fatalf("expected valid target URL, got %v", err)
	}
	for _, badRaw := range []string{
		"ftp://fe1.prod.local:8030/x",
		"http://fe1.prod.local:8030/x",
		"https://u:p@fe1.prod.local:8030/x",
		"https://169.254.169.254:8040/x",
		"https://evil.other.local:8040/x",
	} {
		uBad, _ := url.Parse(badRaw)
		if _, err := nonLoopClient.validateStreamLoadTargetHostAndScheme(uBad); err == nil {
			t.Fatalf("expected validation rejection for %s", badRaw)
		}
	}
	if _, err := nonLoopClient.validateStreamLoadTargetHostAndScheme(nil); err == nil {
		t.Fatalf("expected nil URL rejection")
	}

	if !nonLoopClient.matchesConfiguredRedirectUserinfo(url.UserPassword("doris_u", "secret")) ||
		nonLoopClient.matchesConfiguredRedirectUserinfo(url.UserPassword("doris_u", "wrong")) {
		t.Fatalf("matchesConfiguredRedirectUserinfo mismatch")
	}
	if !nonLoopClient.isTrustedTargetHost(uGood, "fe1.prod.local") {
		t.Fatalf("expected trusted FE host")
	}
	feURLs, err := nonLoopClient.parseConfiguredFEURLs()
	if err != nil || !nonLoopClient.isTrustedTargetHostAnyFE(feURLs, "10.1.2.5") || nonLoopClient.isTrustedTargetHostAnyFE(nil, "x") {
		t.Fatalf("isTrustedTargetHostAnyFE check failed: %v", err)
	}
	if nonLoopClient.isTrustedTargetHost(nil, "x") {
		t.Fatalf("isTrustedTargetHost(nil) should be false")
	}

	// validateErrorDetailURL branches
	for _, badErr := range []string{
		"http://fe1.prod.local:8030/api/_load_error_log?file=x", // scheme downgrade
		"https://u:p@fe1.prod.local:8030/api/_load_error_log",   // userinfo
		"https://fe1.prod.local:8030/api/other",                 // missing _load_error
		"https://untrusted.local:8040/api/_load_error_log",      // untrusted host
		"https://169.254.169.254:8040/api/_load_error_log",      // blocked IP
	} {
		uErr, _ := url.Parse(badErr)
		if _, ok := nonLoopClient.validateErrorDetailURL(uErr); ok {
			t.Fatalf("expected validateErrorDetailURL false for %s", badErr)
		}
	}
	uErrOK, _ := url.Parse("https://fe1.prod.local:8030/api/_load_error_log?file=abc")
	if _, ok := nonLoopClient.validateErrorDetailURL(uErrOK); !ok {
		t.Fatalf("expected validateErrorDetailURL true for %s", uErrOK)
	}
	if _, ok := nonLoopClient.validateErrorDetailURL(nil); ok {
		t.Fatalf("expected false for nil error detail URL")
	}

	// Exercise DialContext checks + lookupNetIP hooks without network
	tr := nonLoopClient.httpClient.Transport.(*http.Transport)
	nonLoopClient.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, errors.New("dns boom")
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "fe1.prod.local:8030"); err == nil {
		t.Fatalf("expected DNS lookup error")
	}
	nonLoopClient.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "fe1.prod.local:8030"); err == nil {
		t.Fatalf("expected blocked resolved IP error")
	}
	nonLoopClient.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "fe1.prod.local:8030"); err == nil {
		t.Fatalf("expected non-loopback FE rejecting loopback DNS resolution")
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "badhostport"); err == nil {
		t.Fatalf("expected SplitHostPort error")
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "127.0.0.1:8030"); err == nil {
		t.Fatalf("expected blocked loopback IP on non-loopback client")
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "evil.local:8030"); err == nil {
		t.Fatalf("expected untrusted target host error")
	}
	if addrs, err := nonLoopClient.resolveNetIPs(context.Background(), "ip", "fe1.prod.local"); err != nil || len(addrs) != 1 {
		t.Fatalf("resolveNetIPs unexpected: %v %v", addrs, err)
	}

	// acquireUploadSlot cancellation when slot full
	releaseSlot, err := nonLoopClient.acquireUploadSlot(context.Background())
	if err != nil {
		t.Fatalf("acquireUploadSlot failed: %v", err)
	}
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if _, err := nonLoopClient.acquireUploadSlot(cctx); err == nil {
		t.Fatalf("expected acquireUploadSlot error when canceled")
	}
	releaseSlot()

	// recordDiscoveredRedirectBE skipping FE base + storing new BE
	nonLoopClient.recordDiscoveredRedirectBE("", nil)
	nonLoopClient.recordDiscoveredRedirectBE("https://fe1.prod.local:8030", map[string]struct{}{"https://fe1.prod.local:8030": {}})
	nonLoopClient.recordDiscoveredRedirectBE("https://10.1.2.5:8040", map[string]struct{}{"https://fe1.prod.local:8030": {}})

	// 3. httptest BE & FE exercising ProbeFEHealth + LoadNDJSON batch splitting + status handling + ErrorURL fetch
	var errDetailHits atomic.Int64
	beSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "_load_error"):
			errDetailHits.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("line 1 malformed column"))
		case strings.Contains(r.URL.Path, "_stream_load"):
			lbl := r.Header.Get("label")
			switch {
			case strings.Contains(lbl, "fail_"):
				_, _ = fmt.Fprintf(w, `{"Status":"Fail","Message":"TOO_MANY_VERSIONS","NumberFilteredRows":2,"ErrorURL":"http://%s/api/_load_error_log?file=1"}`, r.Host)
			case strings.Contains(lbl, "aborted_"):
				_, _ = fmt.Fprintf(w, `{"Status":"Label Already Exists","ExistingJobStatus":"ABORTED","Message":"aborted job","ErrorURL":"http://%s/api/_load_error_log?file=2"}`, r.Host)
			case strings.Contains(lbl, "visible_"):
				_, _ = w.Write([]byte(`{"Status":"Label Already Exists","ExistingJobStatus":"VISIBLE","Message":"already visible"}`))
			case strings.Contains(lbl, "pubtimeout_"):
				_, _ = w.Write([]byte(`{"Status":"Publish Timeout","Message":"publish timeout"}`))
			default:
				_, _ = w.Write([]byte(`{"Status":"Success","Message":"OK","NumberLoadedRows":2,"NumberTotalRows":2}`))
			}
		}
	}))
	defer beSrv.Close()

	var healthStep atomic.Int64
	feSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			if healthStep.Add(1) == 1 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		case "/api/bootstrap":
			_, _ = w.Write([]byte(`{"status":0}`))
		default:
			if strings.Contains(r.URL.Path, "_stream_load") {
				target := beSrv.URL + r.URL.Path
				http.Redirect(w, r, target, http.StatusTemporaryRedirect)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer feSrv.Close()

	loopClient := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: feSrv.URL,
		User:           "root",
		Password:       "pw",
		Database:       "es_db",
		Timeout:        2 * time.Second,
		MaxBatchBytes:  45, // forces chunk splitting on multi-line NDJSON
		MaxRetries:     1,
		BaseBackoff:    time.Millisecond,
		MaxBackoff:     2 * time.Millisecond,
	})

	// First probe hits /api/health (404) -> /api/bootstrap (200) -> true
	if !loopClient.ProbeFEHealth(context.Background()) {
		t.Fatalf("expected ProbeFEHealth true via /api/bootstrap fallback")
	}
	// Second probe hits /api/health (200) -> true
	if !loopClient.ProbeFEHealth(context.Background()) {
		t.Fatalf("expected ProbeFEHealth true via /api/health")
	}
	// Unreachable FE -> false
	deadClient := NewStreamLoadClient(StreamLoadConfig{FEHTTPEndpoint: "http://127.0.0.1:1", Timeout: 100 * time.Millisecond})
	if deadClient.ProbeFEHealth(context.Background()) {
		t.Fatalf("expected ProbeFEHealth false for closed port")
	}
	badEPClient := NewStreamLoadClient(StreamLoadConfig{FEHTTPEndpoint: ""})
	if badEPClient.ProbeFEHealth(context.Background()) {
		t.Fatalf("expected ProbeFEHealth false for empty FEHTTPEndpoint")
	}

	// LoadNDJSON empty & invalid table & oversized line
	if err := loopClient.LoadNDJSON(context.Background(), "tbl", []byte("   "), false); err != nil {
		t.Fatalf("empty NDJSON should succeed: %v", err)
	}
	if err := badEPClient.LoadNDJSON(context.Background(), "bad_tbl", []byte(`{"_id":"1"}`+"\n"), false); err == nil {
		t.Fatalf("expected FEHTTPEndpoint error on empty endpoint client")
	}
	// Single-line larger than MaxBatchBytes (45 bytes) still loads in one batch, multi-line splits into 2+ batches
	traceCtx := WithTraceMeta(context.Background(), TraceMeta{
		Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		OpaqueID:    "op-r67",
		RequestID:   "req-r67",
	})
	payload := []byte(`{"_id":"1","msg":"alpha-one-2345"}` + "\n" + `{"_id":"2","msg":"beta-two-67890"}` + "\n")
	if err := loopClient.LoadNDJSON(traceCtx, "r67_tbl", payload, true); err != nil {
		t.Fatalf("LoadNDJSON split batch failed: %v", err)
	}

	// Test loadSingleNDJSONBatch with Publish Timeout -> error when syncRefresh=true
	beHostPort := strings.TrimPrefix(beSrv.URL, "http://")
	_ = beHostPort
	pubClient := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: feSrv.URL,
		User:           "root",
		Database:       "es_db",
		MaxRetries:     -1,
	})
	pubClient.httpClient.Transport = r67AMRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       http.NoBody,
			Header:     make(http.Header),
		}, errors.New("not reached")
	})
	// Route directly via httptest BE custom mux for deterministic Label Already Exists / Fail / Publish Timeout branches
	var modeAtomic atomic.Int32
	var attemptCounter atomic.Int32
	modeBE := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "_load_error") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("filtered detail msg"))
			return
		}
		switch modeAtomic.Load() {
		case 1:
			_, _ = w.Write([]byte(`{"Status":"Publish Timeout","Message":"pub timeout"}`))
		case 2:
			if attemptCounter.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"Status":"Label Already Exists","ExistingJobStatus":"VISIBLE","Message":"ok"}`))
		case 3:
			_, _ = fmt.Fprintf(w, `{"Status":"Label Already Exists","ExistingJobStatus":"ABORTED","Message":"aborted","ErrorURL":"http://%s/api/_load_error_log?f=1"}`, r.Host)
		case 4:
			_, _ = fmt.Fprintf(w, `{"Status":"Fail","Message":"TOO_MANY_VERSIONS","NumberFilteredRows":1,"ErrorURL":"http://%s/api/_load_error_log?f=2"}`, r.Host)
		}
	}))
	defer modeBE.Close()

	statusClient := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: modeBE.URL,
		User:           "root",
		Database:       "es_db",
		Timeout:        time.Second,
		MaxRetries:     1,
		BaseBackoff:    time.Millisecond,
		MaxBackoff:     time.Millisecond,
	})
	modeAtomic.Store(1)
	if err := statusClient.loadSingleNDJSONBatch(context.Background(), "t1", []byte(`{"_id":"1"}`+"\n"), true); err == nil {
		t.Fatalf("expected error on Publish Timeout with syncRefresh=true")
	}
	if err := statusClient.loadSingleNDJSONBatch(context.Background(), "t1", []byte(`{"_id":"1"}`+"\n"), false); err != nil {
		t.Fatalf("Publish Timeout with syncRefresh=false should succeed, got %v", err)
	}
	attemptCounter.Store(0)
	modeAtomic.Store(2)
	if err := statusClient.loadSingleNDJSONBatch(context.Background(), "t1", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("Label Already Exists VISIBLE should succeed, got %v", err)
	}
	modeAtomic.Store(3)
	if err := statusClient.loadSingleNDJSONBatch(context.Background(), "t1", []byte(`{"_id":"1"}`+"\n"), true); err == nil {
		t.Fatalf("Label Already Exists ABORTED should error")
	}
	modeAtomic.Store(4)
	if err := statusClient.loadSingleNDJSONBatch(context.Background(), "t1", []byte(`{"_id":"1"}`+"\n"), true); err == nil {
		t.Fatalf("Fail status should error after retry")
	}
	if det := statusClient.fetchErrorURLDetail(context.Background(), modeBE.URL+"/api/_load_error_log?f=1"); !strings.Contains(det, "filtered detail msg") {
		t.Fatalf("fetchErrorURLDetail unexpected: %q", det)
	}
	if statusClient.fetchErrorURLDetail(context.Background(), "://bad-url") != "" {
		t.Fatalf("expected empty detail for bad URL")
	}

	_ = net.IPv4(127, 0, 0, 1)
	_ = base64.StdEncoding
	_ = painless.UpdateRequest{}
}
