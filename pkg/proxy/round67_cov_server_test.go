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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// r67CovSrvMinimalBackend implements ONLY DorisBackend (intentionally omitting DorisPhysicalDeleteBackend)
// so tests cover non-physical-delete tombstone fallback paths as well as injectable backend error paths.
type r67CovSrvMinimalBackend struct {
	mem           *MemoryBackend
	mu            sync.Mutex
	ddlErr        error
	streamLoadErr error
	queryHitsErr  error
	queryAggsErr  error
	getDocErr     error
	onQueryHits   func(sqlStr string, hits []HitRow) ([]HitRow, error)
}

func newR67CovSrvMinimalBackend() *r67CovSrvMinimalBackend {
	return &r67CovSrvMinimalBackend{mem: NewMemoryBackend(false)}
}

func (b *r67CovSrvMinimalBackend) Ping(ctx context.Context) error {
	return b.mem.Ping(ctx)
}

func (b *r67CovSrvMinimalBackend) ExecDDL(ctx context.Context, ddl string) error {
	b.mu.Lock()
	err := b.ddlErr
	b.mu.Unlock()
	if err != nil {
		return err
	}
	return b.mem.ExecDDL(ctx, ddl)
}

func (b *r67CovSrvMinimalBackend) QueryHits(ctx context.Context, sqlStr string) ([]HitRow, error) {
	b.mu.Lock()
	err := b.queryHitsErr
	hook := b.onQueryHits
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	hits, qErr := b.mem.QueryHits(ctx, sqlStr)
	if qErr != nil {
		return nil, qErr
	}
	if hook != nil {
		return hook(sqlStr, hits)
	}
	return hits, nil
}

func (b *r67CovSrvMinimalBackend) QueryAggs(ctx context.Context, sqlStr string) ([]AggRow, error) {
	b.mu.Lock()
	err := b.queryAggsErr
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return b.mem.QueryAggs(ctx, sqlStr)
}

func (b *r67CovSrvMinimalBackend) GetDocByID(ctx context.Context, db, table, id string) (*HitRow, bool, error) {
	b.mu.Lock()
	err := b.getDocErr
	b.mu.Unlock()
	if err != nil {
		return nil, false, err
	}
	return b.mem.GetDocByID(ctx, db, table, id)
}

func (b *r67CovSrvMinimalBackend) GetDocsByIDs(ctx context.Context, db, table string, ids []string) (map[string]HitRow, error) {
	return b.mem.GetDocsByIDs(ctx, db, table, ids)
}

func (b *r67CovSrvMinimalBackend) StreamLoad(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
	b.mu.Lock()
	err := b.streamLoadErr
	b.mu.Unlock()
	if err != nil {
		return err
	}
	return b.mem.StreamLoad(ctx, table, ndjson, syncRefresh)
}

// r67CovSrvPhysDelErrBackend embeds MemoryBackend to inject DeleteDocsByIDs errors.
type r67CovSrvPhysDelErrBackend struct {
	*MemoryBackend
	mu         sync.Mutex
	physDelErr error
}

func (b *r67CovSrvPhysDelErrBackend) DeleteDocsByIDs(ctx context.Context, db, table string, ids []string) error {
	b.mu.Lock()
	err := b.physDelErr
	b.mu.Unlock()
	if err != nil {
		return err
	}
	return b.MemoryBackend.DeleteDocsByIDs(ctx, db, table, ids)
}

// r67CovSrvTelemetrySQLBackend embeds MemoryBackend and implements TelemetryBackend + SQLRowsBackend.
type r67CovSrvTelemetrySQLBackend struct {
	*MemoryBackend
	mu       sync.Mutex
	tables   map[string]DorisTableDataTelemetry
	rowsHook func(sqlStr string) ([]map[string]any, error)
}

func (b *r67CovSrvTelemetrySQLBackend) ShowBackendsTelemetry(_ context.Context) ([]DorisBackendNodeTelemetry, error) {
	return []DorisBackendNodeTelemetry{{BackendID: "be1", Host: "127.0.0.1", HttpPort: 8040, Alive: true}}, nil
}

func (b *r67CovSrvTelemetrySQLBackend) ShowDataTelemetry(_ context.Context, _ string) (map[string]DorisTableDataTelemetry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]DorisTableDataTelemetry, len(b.tables))
	for k, v := range b.tables {
		out[k] = v
	}
	return out, nil
}

func (b *r67CovSrvTelemetrySQLBackend) CollectClusterTelemetry(_ context.Context, _ string) *DorisClusterTelemetry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]DorisTableDataTelemetry, len(b.tables))
	for k, v := range b.tables {
		out[k] = v
	}
	return &DorisClusterTelemetry{
		AliveNodes: 1,
		TotalNodes: 1,
		Tables:     out,
	}
}

func (b *r67CovSrvTelemetrySQLBackend) QueryRows(_ context.Context, sqlStr string) ([]map[string]any, error) {
	b.mu.Lock()
	hook := b.rowsHook
	b.mu.Unlock()
	if hook != nil {
		return hook(sqlStr)
	}
	return []map[string]any{{"_overall_max_score": 4.25}}, nil
}

type r67CovSrvErrReader struct{}

func (r67CovSrvErrReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated body read failure")
}

func (r67CovSrvErrReader) Close() error { return nil }

func newR67CovSrv(t *testing.T, ver string) (*Server, http.Handler) {
	t.Helper()
	mem := NewMemoryBackend(false)
	srv := NewServer("es_r67cov", mem, transpiler.TranspilerOptions{})
	if ver != "" {
		srv.SetTargetESVersion(ver)
	}
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, srv.Handler()
}

func newR67CovSrvWithBackend(t *testing.T, ver string, be DorisBackend) (*Server, http.Handler) {
	t.Helper()
	srv := NewServer("es_r67cov", be, transpiler.TranspilerOptions{})
	if ver != "" {
		srv.SetTargetESVersion(ver)
	}
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, srv.Handler()
}

func doR67CovSrvHTTP(t *testing.T, h http.Handler, method, path, body string, hdrs map[string]string) (int, http.Header, map[string]any, string) {
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
	raw := rec.Body.String()
	var parsed map[string]any
	if trimmed := strings.TrimSpace(raw); strings.HasPrefix(trimmed, "{") {
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.UseNumber()
		_ = dec.Decode(&parsed)
	}
	return rec.Code, rec.Header(), parsed, raw
}

func mustR67CovSrvHTTP(t *testing.T, h http.Handler, method, path, body string, want int) map[string]any {
	t.Helper()
	code, _, parsed, raw := doR67CovSrvHTTP(t, h, method, path, body, nil)
	if code != want {
		t.Fatalf("%s %s: expected status %d, got %d body=%s", method, path, want, code, raw)
	}
	return parsed
}

func TestRound67Cov_Server_BulkBranchesAndDocPutDeleteGet(t *testing.T) {
	_, h := newR67CovSrv(t, "8.15.5")

	// Setup indices: multi-shard routing index, single-shard routing index, disabled _source, date_nanos, closed, write-blocked, alias partitions, data stream + failure store.
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ms", `{"settings":{"number_of_shards":3},"mappings":{"dynamic_templates":[{"keyword":{"match_mapping_type":"string","mapping":{"type":"keyword"}}}],"properties":{"tag":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ss", `{"settings":{"number_of_shards":1},"mappings":{"properties":{"tag":{"type":"keyword"},"cnt":{"type":"long"},"dt_ns":{"type":"date_nanos"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_rt_req", `{"mappings":{"_routing":{"required":true},"properties":{"tag":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_nosrc", `{"mappings":{"_source":{"enabled":false},"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_closed", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/r67_closed/_close", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_wblock", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_wblock/_settings", `{"index":{"blocks.write":true}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_rblock", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_rblock/_settings", `{"index":{"blocks.read":true}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_part_a", `{"mappings":{"properties":{"tenant":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_part_b", `{"mappings":{"properties":{"tenant":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)

	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[
		{"add":{"index":"r67_part_a","alias":"r67_ambig_alias"}},
		{"add":{"index":"r67_part_b","alias":"r67_ambig_alias"}},
		{"add":{"index":"r67_part_a","alias":"r67_wa_a","filter":{"term":{"tenant":"a"}},"is_write_index":true,"routing":"ra"}}
	]}`, http.StatusOK)

	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_index_template/r67_ds_fs_tpl", `{
		"index_patterns":["r67-ds-fs-*"],
		"data_stream":{"failure_store":{"enabled":true}},
		"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"cnt":{"type":"long"},"tag":{"type":"keyword"}}}}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_data_stream/r67-ds-fs-1", "", http.StatusOK)

	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_index_template/r67_ds_nofs_tpl", `{
		"index_patterns":["r67-ds-nofs-*"],
		"data_stream":{},
		"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"cnt":{"type":"long"}}}}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_data_stream/r67-ds-nofs-1", "", http.StatusOK)

	// Ingest pipelines covering: drop, fail, meta mutations (_version, _if_seq_no, _dynamic_templates), reroute _index/_id, stored script error
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r67_pipe_meta", `{
		"processors":[
			{"set":{"field":"_version","value":10}},
			{"set":{"field":"_version_type","value":"external"}},
			{"set":{"field":"_dynamic_templates","value":{"dyn_tag":"keyword"}}},
			{"set":{"field":"stamped","value":true}}
		]
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r67_pipe_ifseq", `{
		"processors":[
			{"set":{"field":"_if_seq_no","value":0}},
			{"set":{"field":"_if_primary_term","value":1}}
		]
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r67_pipe_drop", `{
		"processors":[{"drop":{"if":"ctx.tag == 'drop'"}}]
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r67_pipe_fail", `{
		"processors":[{"fail":{"message":"forced failure"}}]
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r67_pipe_reroute", `{
		"processors":[
			{"set":{"if":"ctx.move == true","field":"_index","value":"r67_ms"}},
			{"set":{"if":"ctx.move == true","field":"_id","value":"moved-{{_id}}"}}
		]
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r67_pipe_badscript", `{
		"processors":[{"script":{"id":"missing_stored_script_r67"}}]
	}`, http.StatusOK)

	// 1. Bulk request-level validation errors
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_bulk?pipeline=", "{}\n", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_bulk?refresh=bogus", "{}\n", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_bulk?require_data_stream=bogus", "{}\n", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_bulk?type=doc", `{"index":{"_index":"r67_ms","_id":"1"}}`+"\n"+`{"tag":"a"}`+"\n", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/r67_ms/mytype/_bulk", `{"index":{"_id":"1"}}`+"\n"+`{"tag":"a"}`+"\n", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_bulk", `{"index":{"_index":"r67_ms","_id":"1"}`+"\n", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/r67_ambig_alias/_bulk", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_bulk", `{"index":{"_id":"1"}}`+"\n"+`{"tag":"a"}`+"\n", http.StatusBadRequest)

	// Body read error on handleBulk & MaxBytesError (413)
	reqErrBody := httptest.NewRequest(http.MethodPost, "/_bulk", r67CovSrvErrReader{})
	recErrBody := httptest.NewRecorder()
	h.ServeHTTP(recErrBody, reqErrBody)
	if recErrBody.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on body read err, got %d", recErrBody.Code)
	}
	srvLimit, hLimit := newR67CovSrv(t, "8.15.5")
	srvLimit.SetMaxRequestBodyBytes(16)
	mustR67CovSrvHTTP(t, hLimit, http.MethodPost, "/_bulk", `{"index":{"_index":"r67_ms","_id":"1"}}`+"\n"+`{"tag":"too_big"}`+"\n", http.StatusRequestEntityTooLarge)
	srvLimit.SetMaxRequestBodyBytes(0)

	// Seed docs for routing, alias partitions, and updates
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ms/_doc/ms1?routing=r1&refresh=true", `{"tag":"k1","cnt":1}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ss/_doc/ss1?routing=sr1&refresh=true", `{"tag":"k1","cnt":1}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ss/_doc/ss_nort?refresh=true", `{"tag":"k1","cnt":1}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_part_a/_doc/pa_other?refresh=true", `{"tenant":"b","cnt":5}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_part_a/_doc/pa_keep?refresh=true", `{"tenant":"a","cnt":5}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ms/_doc/moved-ss1?refresh=true", `{"tag":"pre","cnt":99}`, http.StatusCreated)

	longID := strings.Repeat("x", 513)

	// 2. Comprehensive multi-item bulk covering ~25 per-item branches in one deterministic call
	bulk1 := strings.Join([]string{
		`{"index":{"_index":"r67_ms","_id":"b_rds","require_data_stream":"bogus"}}`,
		`{"tag":"x"}`,
		`{"index":{"_index":"r67_ms","_id":"b_rds2","require_data_stream":true}}`,
		`{"tag":"x"}`,
		`{"create":{"_index":".ds-r67-ds-fs-1-000001","_id":"d1"}}`,
		`{"@timestamp":"2026-01-01T00:00:00Z"}`,
		`{"index":{"_index":"r67_ms","_id":"b_ra","require_alias":true}}`,
		`{"tag":"x"}`,
		`{"delete":{"_index":"r67_ms"}}`,
		`{"index":{"_index":"r67_ms","_id":""}}`,
		`{"tag":"x"}`,
		`{"index":{"_index":"r67_ms","_id":"` + longID + `"}}`,
		`{"tag":"x"}`,
		`{"create":{"_index":"r67_ms","_id":"ext_cr","version":1,"version_type":"external"}}`,
		`{"tag":"x"}`,
		`{"index":{"_index":"r67_closed","_id":"c1"}}`,
		`{"tag":"x"}`,
		`{"index":{"_index":"r67_wblock","_id":"w1"}}`,
		`{"tag":"x"}`,
		`{"index":{"_index":"r67_ambig_alias","_id":"amb1"}}`,
		`{"tag":"x"}`,
		`{"index":{"_index":"r67_ms","_id":"badjson"}}`,
		`[1,2,3]`,
		`{"index":{"_index":"r67_ms","_id":"p_meta","pipeline":"r67_pipe_meta"}}`,
		`{"dyn_tag":"alpha"}`,
		`{"index":{"_index":"r67_ms","_id":"p_ifseq","pipeline":"r67_pipe_ifseq"}}`,
		`{"tag":"beta"}`,
		`{"index":{"_index":"r67_ms","_id":"p_drop","pipeline":"r67_pipe_drop"}}`,
		`{"tag":"drop"}`,
		`{"index":{"_index":"r67_ms","_id":"b_dt","dynamic_templates":{"dyn_dt":"keyword"}}}`,
		`{"dyn_dt":"v1"}`,
		`{"create":{"_index":"r67-ds-fs-1","_id":"fs_pipe_fail","pipeline":"r67_pipe_fail"}}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","tag":"err"}`,
		`{"create":{"_index":"r67-ds-fs-1"}}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","cnt":"not_a_long"}`,
		`{"create":{"_index":"r67-ds-nofs-1"}}`,
		`{"cnt":1}`,
		`{"index":{"_index":"r67_ss","_id":"ns_err"}}`,
		`{"dt_ns":"1969-10-28T12:12:12.123456789Z"}`,
		`{"index":{"_index":"r67_rt_req","_id":"rt_missing"}}`,
		`{"tag":"x"}`,
		`{"index":{"_index":"r67_wa_a","_id":"pa_other"}}`,
		`{"tenant":"a","cnt":1}`,
		`{"create":{"_index":"r67_wa_a","_id":"pa_new_bad"}}`,
		`{"tenant":"b","cnt":1}`,
		`{"delete":{"_index":"r67_ms","_id":"ms1","routing":"wrong_r1,wrong_r2"}}`,
		`{"delete":{"_index":"r67_ss","_id":"ss1","routing":"wrong_sr"}}`,
		`{"delete":{"_index":"r67_ss","_id":"ss_nort","routing":"wrong_id"}}`,
		`{"delete":{"_index":"r67_ss","_id":"ext_tomb_1","version":5,"version_type":"external"}}`,
		`{"delete":{"_index":"r67_wa_a","_id":"pa_other"}}`,
		"",
	}, "\n")
	resp1 := mustR67CovSrvHTTP(t, h, http.MethodPost, "/_bulk?refresh=true&list_executed_pipelines=true", bulk1, http.StatusOK)
	if resp1["errors"] != true {
		t.Fatalf("expected errors=true in bulk1, got %v", resp1)
	}

	// 3. Bulk update branches + external tombstone checks
	bulk2 := strings.Join([]string{
		`{"update":{"_index":"r67_ms","_id":"ms1"}}`,
		`{"unknown_upd_field":1}`,
		`{"update":{"_index":"r67_nosrc","_id":"n1"}}`,
		`{"doc":{"tag":"x"}}`,
		`{"update":{"_index":"r67_ms","_id":"ms1"}}`,
		`{"bad":`,
		`{"update":{"_index":"r67_ms","_id":"ms1"}}`,
		`{}`,
		`{"update":{"_index":"r67_ms","_id":"ms1","version":2,"version_type":"external"}}`,
		`{"doc":{"tag":"x"}}`,
		`{"update":{"_index":"r67_wa_a","_id":"pa_other"}}`,
		`{"doc":{"cnt":9}}`,
		`{"update":{"_index":"r67_wa_a","_id":"pa_other"}}`,
		`{"doc":{"cnt":9},"doc_as_upsert":true}`,
		`{"update":{"_index":"r67_wa_a","_id":"pa_keep"}}`,
		`{"doc":{"tenant":"b"}}`,
		`{"update":{"_index":"r67_ms","_id":"missing_del_noop"}}`,
		`{"script":{"source":"ctx.op = 'delete'"},"scripted_upsert":true}`,
		`{"update":{"_index":"r67_ms","_id":"ms1"}}`,
		`{"script":{"source":"ctx.op = 'create'"}}`,
		`{"update":{"_index":"r67_ms","_id":"ms1","_source":true}}`,
		`{"doc":{"tag":"k1"}}`,
		`{"update":{"_index":"r67_ms","_id":"missing_src","_source":true}}`,
		`{"doc":{"tag":"k1"}}`,
		`{"update":{"_index":"r67_ms","_id":"ms1","pipeline":"r67_pipe_meta","_source":true}}`,
		`{"script":{"source":"ctx.op = 'none'"}}`,
		`{"update":{"_index":"r67_ms","_id":"ms1","pipeline":"r67_pipe_drop","_source_includes":["tag"]}}`,
		`{"doc":{"tag":"drop"}}`,
		`{"update":{"_index":"r67_ms","_id":"ms_up_drop","pipeline":"r67_pipe_drop","_source":true}}`,
		`{"doc":{"tag":"drop"},"doc_as_upsert":true}`,
		`{"update":{"_index":"r67_ms","_id":"ms1","pipeline":"r67_pipe_fail"}}`,
		`{"doc":{"tag":"changed"}}`,
		`{"update":{"_index":"r67_ss","_id":"ss1","pipeline":"r67_pipe_reroute"}}`,
		`{"doc":{"move":true}}`,
		`{"delete":{"_index":"r67_ms","_id":"moved-ss1"}}`,
		`{"update":{"_index":"r67_rt_req","_id":"rt_defer"}}`,
		`{"script":{"source":"ctx._routing = 'rr1'; ctx._source.tag = 'ok'"},"upsert":{"tag":"ok"}}`,
		`{"index":{"_index":"r67_ss","_id":"ext_tomb_1","version":3,"version_type":"external"}}`,
		`{"tag":"conflict"}`,
		`{"index":{"_index":"r67_ss","_id":"ext_tomb_1","version":6,"version_type":"external"}}`,
		`{"tag":"ok"}`,
		"",
	}, "\n")
	resp2 := mustR67CovSrvHTTP(t, h, http.MethodPost, "/_bulk?refresh=true&list_executed_pipelines=true", bulk2, http.StatusOK)
	if resp2["errors"] != true {
		t.Fatalf("expected errors=true in bulk2, got %v", resp2)
	}

	// 4. ES7 legacy doc type conflict & valid typed bulk
	_, h7 := newR67CovSrv(t, "7.10.2")
	mustR67CovSrvHTTP(t, h7, http.MethodPut, "/r67_v7?include_type_name=true", `{"mappings":{"t1":{"properties":{"a":{"type":"keyword"}}}}}`, http.StatusOK)
	bulkV7 := strings.Join([]string{
		`{"index":{"_index":"r67_v7","_type":"t1","_id":"1"}}`,
		`{"a":"one"}`,
		`{"index":{"_index":"r67_v7","_type":"t2","_id":"2"}}`,
		`{"a":"two"}`,
		"",
	}, "\n")
	mustR67CovSrvHTTP(t, h7, http.MethodPost, "/_bulk?refresh=true", bulkV7, http.StatusOK)
	mustR67CovSrvHTTP(t, h7, http.MethodPost, "/r67_v7/t1?refresh=true", `{"a":"auto"}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h7, http.MethodPost, "/r67_v7/t2?refresh=true", `{"a":"badtype"}`, http.StatusBadRequest)

	// 5. handlePutDoc, handleHeadDoc, handleGetSource, handleDeleteDoc edge cases
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ms/_doc/p1?pipeline=", `{"tag":"x"}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ms/_doc/p1?require_data_stream=bad", `{"tag":"x"}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/.ds-r67-ds-fs-1-000001/_create/d1", `{"@timestamp":"2026-01-01T00:00:00Z"}`, http.StatusConflict)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/.ds-r67-ds-fs-1-000001/_doc/d1", `{"@timestamp":"2026-01-01T00:00:00Z"}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ms/_doc/"+longID, `{"tag":"x"}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ms/_doc/p1?pipeline=r67_pipe_badscript", `{"tag":"x"}`, http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/r67_ms/_doc?pipeline=r67_pipe_drop", `{"tag":"drop"}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ms/_doc/p_meta_put?pipeline=r67_pipe_meta&refresh=true", `{"dyn_tag":"v"}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_ms/_doc/p_ifseq?pipeline=r67_pipe_ifseq", `{"tag":"v"}`, http.StatusConflict)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67-ds-fs-1/_doc/bad_id", `{"@timestamp":"2026-01-01T00:00:00Z"}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/r67-ds-nofs-1/_doc", `{"cnt":1}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_wa_a/_doc/pa_other", `{"tenant":"a"}`, http.StatusConflict)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_wa_a/_doc/pa_bad", `{"tenant":"b"}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_closed/_doc/c1", `{"tag":"x"}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_wblock/_doc/w1", `{"tag":"x"}`, http.StatusForbidden)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_rt_req/_doc/r1", `{"tag":"x"}`, http.StatusBadRequest)

	// HEAD _doc & GET/HEAD _source & _mget branches
	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodHead, "/r67_ambig_alias/_doc/1", http.StatusBadRequest},
		{http.MethodHead, "/r67_closed/_doc/1", http.StatusBadRequest},
		{http.MethodHead, "/r67_rblock/_doc/1", http.StatusForbidden},
		{http.MethodHead, "/r67_rt_req/_doc/1", http.StatusBadRequest},
		{http.MethodHead, "/r67_ms/_doc/ms1?version=bad", http.StatusBadRequest},
		{http.MethodHead, "/r67_ms/_doc/ms1?routing=r1&version=999", http.StatusConflict},
		{http.MethodHead, "/r67_ms/_doc/missing_doc", http.StatusNotFound},
		{http.MethodHead, "/r67_ms/_doc/ms1?routing=r1", http.StatusOK},
		{http.MethodHead, "/r67_ambig_alias/_source/1", http.StatusBadRequest},
		{http.MethodGet, "/r67_ambig_alias/_source/1", http.StatusBadRequest},
		{http.MethodHead, "/r67_closed/_source/1", http.StatusBadRequest},
		{http.MethodGet, "/r67_closed/_source/1", http.StatusBadRequest},
		{http.MethodHead, "/r67_rblock/_source/1", http.StatusForbidden},
		{http.MethodGet, "/r67_rblock/_source/1", http.StatusForbidden},
		{http.MethodHead, "/r67_rt_req/_source/1", http.StatusBadRequest},
		{http.MethodGet, "/r67_rt_req/_source/1", http.StatusBadRequest},
		{http.MethodHead, "/r67_ms/_source/missing_doc", http.StatusNotFound},
		{http.MethodHead, "/r67_ms/_source/ms1?routing=r1", http.StatusOK},
		{http.MethodGet, "/r67_ms/_source/ms1?routing=r1&_source=false", http.StatusBadRequest},
		{http.MethodGet, "/r67_ms/_source/ms1?routing=r1&pretty=true&filter_path=tag", http.StatusOK},
		{http.MethodGet, "/r67_ms/_source/ms1?routing=r1&version=999", http.StatusConflict},
		{http.MethodHead, "/r67_ms/_source/ms1?routing=r1&version=999", http.StatusConflict},
	} {
		st, _, _, raw := doR67CovSrvHTTP(t, h, tc.method, tc.path, "", nil)
		if st != tc.want {
			t.Fatalf("%s %s: want %d, got %d body=%s", tc.method, tc.path, tc.want, st, raw)
		}
	}
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/r67_nosrc/_doc/ns1?refresh=true", `{"tag":"n"}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodHead, "/r67_nosrc/_source/ns1", "", http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/r67_nosrc/_source/ns1", "", http.StatusNotFound)

	// _mget error & block & filter branches
	mgetResp := mustR67CovSrvHTTP(t, h, http.MethodPost, "/_mget?force_synthetic_source=true", `{
		"docs":[
			{"_index":"r67_ambig_alias","_id":"1"},
			{"_index":"r67_rblock","_id":"1"},
			{"_index":"r67_ms","_id":"ms1","routing":"r1"},
			{"_index":"r67_ms","_id":"ms1","routing":"r1","version":999,"version_type":"internal"},
			{"_index":"r67_nosrc","_id":"ns1","_source":true}
		]
	}`, http.StatusOK)
	if docs, ok := mgetResp["docs"].([]any); !ok || len(docs) != 5 {
		t.Fatalf("expected 5 mget docs, got %v", mgetResp)
	}
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/r67_ambig_alias/_mget", `{"ids":["1"]}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_mget?force_synthetic_source=bad", `{"docs":[]}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_mget", `{bad`, http.StatusBadRequest)

	// handleDeleteDoc error branches
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/r67_ms/_doc/ms1?refresh=bogus", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/r67_ms/_doc/ms1?require_alias=true", "", http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/r67-ds-fs-1/_doc/d1", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/r67_closed/_doc/c1", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/r67_wblock/_doc/w1", "", http.StatusForbidden)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/r67_ms/_doc/ms1?if_seq_no=bad", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/r67_ms/_doc/"+longID, "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/r67_rt_req/_doc/r1", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/r67_ms/_doc/del_ext_nf?version=4&version_type=external", "", http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/r67_ms/_doc/del_ext_nf?version=2&version_type=external", "", http.StatusConflict)
}

func TestRound67Cov_Server_UpdateDocAndNonPhysDelFallbacks(t *testing.T) {
	// Part A: standard server for handleUpdateDoc branches
	_, h := newR67CovSrv(t, "8.15.5")
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_idx", `{"mappings":{"properties":{"tag":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_dst", `{"mappings":{"properties":{"tag":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_closed", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/u_closed/_close", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_block", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_block/_settings", `{"index":{"blocks.write":true}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_nosrc", `{"mappings":{"_source":{"enabled":false},"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_rt", `{"mappings":{"_routing":{"required":true},"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_ts", `{"settings":{"index.mode":"time_series","index.routing_path":["h"]},"mappings":{"properties":{"@timestamp":{"type":"date"},"h":{"type":"keyword","time_series_dimension":true},"v":{"type":"long","time_series_metric":"gauge"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_index_template/u_ds_tpl", `{"index_patterns":["u-ds-*"],"data_stream":{}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_data_stream/u-ds-1", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[
		{"add":{"index":"u_idx","alias":"u_alias_a","filter":{"term":{"tag":"a"}},"is_write_index":true}},
		{"add":{"index":"u_dst","alias":"u_alias_dst","filter":{"term":{"tag":"dst"}},"is_write_index":true}}
	]}`, http.StatusOK)

	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/u_pipe_drop", `{"processors":[{"drop":{"if":"ctx.tag == 'drop'"}}]}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/u_pipe_fail", `{"processors":[{"fail":{"message":"upd pipe fail"}}]}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/u_pipe_move", `{"processors":[{"set":{"field":"_index","value":"u_dst"}},{"set":{"field":"_id","value":"moved-{{_id}}"}}]}`, http.StatusOK)

	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_idx/_doc/1?refresh=true", `{"tag":"a","cnt":10}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_idx/_doc/other_part?refresh=true", `{"tag":"b","cnt":1}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/u_dst/_doc/moved-1?refresh=true", `{"tag":"dst","cnt":2}`, http.StatusCreated)

	longID := strings.Repeat("u", 513)
	for _, tc := range []struct {
		path string
		body string
		want int
	}{
		{"/u_idx/_update/1?pipeline=", `{"doc":{"cnt":2}}`, http.StatusBadRequest},
		{"/u_idx/_update/1?refresh=bogus", `{"doc":{"cnt":2}}`, http.StatusBadRequest},
		{"/u_idx/_update/1?require_alias=true", `{"doc":{"cnt":2}}`, http.StatusNotFound},
		{"/u-ds-1/_update/1", `{"doc":{"cnt":2}}`, http.StatusBadRequest},
		{"/u_closed/_update/1", `{"doc":{"cnt":2}}`, http.StatusBadRequest},
		{"/u_block/_update/1", `{"doc":{"cnt":2}}`, http.StatusForbidden},
		{"/u_idx/_update/1?if_seq_no=bad", `{"doc":{"cnt":2}}`, http.StatusBadRequest},
		{"/u_idx/_update/1?version=1&version_type=external", `{"doc":{"cnt":2}}`, http.StatusBadRequest},
		{"/u_idx/_update/" + longID, `{"doc":{"cnt":2}}`, http.StatusBadRequest},
		{"/u_idx/_update/1", `{"bad_field":1}`, http.StatusBadRequest},
		{"/u_idx/_update/1", `{"script":{"id":"missing_script_r67"}}`, http.StatusNotFound},
		{"/u_idx/_update/1", `{}`, http.StatusBadRequest},
		{"/u_idx/_update/1", `{"script":{"source":"return ("}}`, http.StatusBadRequest},
		{"/u_ts/_update/1", `{"doc":{"v":2}}`, http.StatusBadRequest},
		{"/u_rt/_update/1", `{"doc":{"tag":"x"}}`, http.StatusBadRequest},
		{"/u_alias_a/_update/other_part", `{"doc":{"cnt":2}}`, http.StatusNotFound},
		{"/u_alias_a/_update/other_part", `{"doc":{"cnt":2},"doc_as_upsert":true}`, http.StatusConflict},
		{"/u_nosrc/_update/ns1", `{"doc":{"tag":"x"},"doc_as_upsert":true}`, http.StatusBadRequest},
		{"/u_idx/_update/1", `{"script":{"source":"ctx.op = 'create'"}}`, http.StatusBadRequest},
		{"/u_idx/_update/missing_del", `{"script":{"source":"ctx.op = 'delete'"},"scripted_upsert":true}`, http.StatusOK},
		{"/u_idx/_update/1?pipeline=u_pipe_fail", `{"doc":{"tag":"a"}}`, http.StatusBadRequest},
		{"/u_idx/_update/1?pipeline=u_pipe_fail", `{"doc":{"cnt":11}}`, http.StatusBadRequest},
		{"/u_idx/_update/1?pipeline=u_pipe_drop&_source=true", `{"doc":{"tag":"drop"}}`, http.StatusOK},
		{"/u_alias_a/_update/1", `{"doc":{"tag":"b"}}`, http.StatusBadRequest},
		{"/u_idx/_update/1?pipeline=u_pipe_move&refresh=true", `{"doc":{"cnt":15}}`, http.StatusOK},
		{"/u_idx/_update/1_nf?pipeline=u_pipe_move&refresh=true", `{"doc":{"tag":"a","cnt":20},"doc_as_upsert":true}`, http.StatusCreated},
		{"/u_rt/_update/r_defer?routing=rt1&refresh=true", `{"script":{"source":"ctx._routing = 'rt1'; ctx._source.tag = 'ok'"},"upsert":{"tag":"ok"}}`, http.StatusCreated},
	} {
		st, _, _, raw := doR67CovSrvHTTP(t, h, http.MethodPost, tc.path, tc.body, nil)
		if st != tc.want {
			t.Fatalf("POST %s: want %d, got %d body=%s", tc.path, tc.want, st, raw)
		}
	}

	// Part B: Non-physical-delete backend (r67CovSrvMinimalBackend) + injectable errors
	minBe := newR67CovSrvMinimalBackend()
	_, hMin := newR67CovSrvWithBackend(t, "8.15.5", minBe)
	mustR67CovSrvHTTP(t, hMin, http.MethodPut, "/m_idx", `{"mappings":{"properties":{"tag":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, hMin, http.MethodPut, "/m_dst", `{"mappings":{"properties":{"tag":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, hMin, http.MethodPut, "/_ingest/pipeline/m_move", `{"processors":[{"set":{"field":"_index","value":"m_dst"}},{"set":{"field":"_id","value":"moved-{{_id}}"}}]}`, http.StatusOK)
	mustR67CovSrvHTTP(t, hMin, http.MethodPut, "/m_idx/_doc/1?refresh=true", `{"tag":"k","cnt":1}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, hMin, http.MethodPut, "/m_idx/_doc/2?refresh=true", `{"tag":"k","cnt":2}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, hMin, http.MethodPut, "/m_idx/_doc/3?refresh=true", `{"tag":"k","cnt":3}`, http.StatusCreated)

	// Non-phys-del tombstone branches in handleUpdateDoc (reroute + script delete) & handleDeleteDoc
	mustR67CovSrvHTTP(t, hMin, http.MethodPost, "/m_idx/_update/1?pipeline=m_move&refresh=true", `{"doc":{"cnt":10}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, hMin, http.MethodPost, "/m_idx/_update/2?refresh=true", `{"script":{"source":"ctx.op = 'delete'"}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, hMin, http.MethodDelete, "/m_idx/_doc/3?refresh=true", "", http.StatusOK)

	// Inject backend errors on StreamLoad, GetDocByID, ExecDDL
	minBe.mu.Lock()
	minBe.streamLoadErr = errors.New("streamload failed")
	minBe.mu.Unlock()
	mustR67CovSrvHTTP(t, hMin, http.MethodPut, "/m_idx/_doc/err_sl?refresh=true", `{"tag":"x"}`, http.StatusInternalServerError)
	mustR67CovSrvHTTP(t, hMin, http.MethodPost, "/_bulk?refresh=true", `{"index":{"_index":"m_idx","_id":"err_sl2"}}`+"\n"+`{"tag":"x"}`+"\n", http.StatusInternalServerError)
	mustR67CovSrvHTTP(t, hMin, http.MethodPost, "/m_dst/_update/moved-1?refresh=true", `{"doc":{"cnt":99}}`, http.StatusInternalServerError)

	minBe.mu.Lock()
	minBe.streamLoadErr = nil
	minBe.getDocErr = errors.New("getdoc failed")
	minBe.mu.Unlock()
	mustR67CovSrvHTTP(t, hMin, http.MethodGet, "/m_idx/_source/1", "", http.StatusInternalServerError)
	mustR67CovSrvHTTP(t, hMin, http.MethodDelete, "/m_dst/_doc/moved-1", "", http.StatusInternalServerError)
	mustR67CovSrvHTTP(t, hMin, http.MethodPost, "/m_dst/_update/moved-1", `{"doc":{"cnt":1}}`, http.StatusInternalServerError)

	minBe.mu.Lock()
	minBe.getDocErr = nil
	minBe.ddlErr = errors.New("ddl failed")
	minBe.mu.Unlock()
	mustR67CovSrvHTTP(t, hMin, http.MethodPut, "/m_ddl_err", `{"mappings":{"properties":{"a":{"type":"keyword"}}}}`, http.StatusInternalServerError)

	// Part C: DorisPhysicalDeleteBackend error paths
	pdBe := &r67CovSrvPhysDelErrBackend{MemoryBackend: NewMemoryBackend(false)}
	_, hPD := newR67CovSrvWithBackend(t, "8.15.5", pdBe)
	mustR67CovSrvHTTP(t, hPD, http.MethodPut, "/pd_idx", `{"mappings":{"properties":{"a":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, hPD, http.MethodPut, "/pd_idx/_doc/1?refresh=true", `{"a":"x"}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, hPD, http.MethodPut, "/pd_idx/_doc/2?refresh=true", `{"a":"y"}`, http.StatusCreated)
	pdBe.mu.Lock()
	pdBe.physDelErr = errors.New("phys delete boom")
	pdBe.mu.Unlock()
	mustR67CovSrvHTTP(t, hPD, http.MethodDelete, "/pd_idx/_doc/1", "", http.StatusInternalServerError)
	mustR67CovSrvHTTP(t, hPD, http.MethodPost, "/pd_idx/_update/1", `{"script":{"source":"ctx.op = 'delete'"}}`, http.StatusInternalServerError)
	mustR67CovSrvHTTP(t, hPD, http.MethodPost, "/_bulk?refresh=true", `{"delete":{"_index":"pd_idx","_id":"2"}}`+"\n", http.StatusInternalServerError)
}

func TestRound67Cov_Server_UpdateByQueryDeleteByQueryAndSlice(t *testing.T) {
	minBe := newR67CovSrvMinimalBackend()
	srv, h := newR67CovSrvWithBackend(t, "8.15.5", minBe)

	mustR67CovSrvHTTP(t, h, http.MethodPut, "/bq_src", `{"mappings":{"properties":{"tag":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/bq_dst", `{"mappings":{"properties":{"tag":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/bq_closed", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_closed/_close", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/bq_rblock", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/bq_rblock/_settings", `{"index":{"blocks.read":true}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/bq_wblock", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/bq_wblock/_settings", `{"index":{"blocks.write":true}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/bq_ts", `{"settings":{"index.mode":"time_series","index.routing_path":["dim"]},"mappings":{"properties":{"@timestamp":{"type":"date"},"dim":{"type":"keyword","time_series_dimension":true},"m":{"type":"long","time_series_metric":"gauge"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_ts/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","dim":"d1","m":1}`, http.StatusCreated)

	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/bq_pipe_drop", `{"processors":[{"drop":{"if":"ctx.tag == 'dropme'"}}]}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/bq_pipe_fail", `{"processors":[{"fail":{"message":"bq fail"}}]}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ingest/pipeline/bq_pipe_move", `{"processors":[{"set":{"field":"_index","value":"bq_dst"}},{"set":{"field":"_id","value":"p-{{_id}}"}}]}`, http.StatusOK)

	for i := 1; i <= 5; i++ {
		rt := "r1"
		if i%2 == 0 {
			rt = "r2"
		}
		mustR67CovSrvHTTP(t, h, http.MethodPut, fmt.Sprintf("/bq_src/_doc/%d?routing=%s&refresh=true", i, rt), fmt.Sprintf(`{"tag":"t%d","cnt":%d}`, i, i*10), http.StatusCreated)
	}

	// 1. Validation & slice param error branches on _update_by_query and _delete_by_query
	for _, tc := range []struct {
		method string
		path   string
		body   string
		want   int
	}{
		{http.MethodGet, "/bq_src/_update_by_query", "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/bq_src/_delete_by_query", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "/bq_src/_update_by_query?refresh=bad", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_delete_by_query?refresh=bad", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_update_by_query", `{bad`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_delete_by_query", `{bad`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_update_by_query?slices=0", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_update_by_query", `{"slices":"bad"}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_update_by_query", `{"slices":1.5}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_update_by_query", `{"slice":{"id":0}}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_update_by_query", `{"slice":{"id":2,"max":2}}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_delete_by_query", `{"slice":{"id":0,"max":1}}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_update_by_query?conflicts=bogus", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_delete_by_query?conflicts=bogus", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_*/_update_by_query?expand_wildcards=none&allow_no_indices=false", `{"query":{"match_all":{}}}`, http.StatusNotFound},
		{http.MethodPost, "/bq_*/_delete_by_query?expand_wildcards=none&allow_no_indices=false", `{"query":{"match_all":{}}}`, http.StatusNotFound},
		{http.MethodPost, "/bq_closed/_update_by_query", `{"query":{"match_all":{}}}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_closed/_delete_by_query", `{"query":{"match_all":{}}}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_rblock/_update_by_query", `{"query":{"match_all":{}}}`, http.StatusForbidden},
		{http.MethodPost, "/bq_rblock/_delete_by_query", `{"query":{"match_all":{}}}`, http.StatusForbidden},
		{http.MethodPost, "/bq_wblock/_update_by_query", `{"query":{"match_all":{}}}`, http.StatusForbidden},
		{http.MethodPost, "/bq_wblock/_delete_by_query", `{"query":{"match_all":{}}}`, http.StatusForbidden},
		{http.MethodPost, "/bq_src/_update_by_query?slices=3&max_docs=2", `{"query":{"match_all":{}}}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_delete_by_query?slices=3&max_docs=2", `{"query":{"match_all":{}}}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_update_by_query", `{"script":{"id":"missing_script_r67"}}`, http.StatusNotFound},
		{http.MethodPost, "/bq_src/_update_by_query", `{"query":{"script":{"script":{"id":"missing_script_r67"}}}}`, http.StatusNotFound},
		{http.MethodPost, "/bq_src/_delete_by_query", `{"query":{"script":{"script":{"id":"missing_script_r67"}}}}`, http.StatusNotFound},
		{http.MethodPost, "/bq_src/_update_by_query", `{"script":{"source":"return ("}}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_update_by_query", `{"query":{"script":{"script":"return ("}}}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_delete_by_query", `{"query":{"script":{"script":"return ("}}}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_update_by_query?q=tag:+(", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_src/_delete_by_query?q=tag:+(", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/bq_ts/_update_by_query", `{"script":{"source":"ctx._source.dim = 'd2'"}}`, http.StatusBadRequest},
	} {
		st, _, _, raw := doR67CovSrvHTTP(t, h, tc.method, tc.path, tc.body, nil)
		if st != tc.want {
			t.Fatalf("%s %s: want %d, got %d body=%s", tc.method, tc.path, tc.want, st, raw)
		}
	}

	// 2. Multi-batch scroll_size=2, slices=2, URI q=, routing=, slice{id,max,field}, script ctx.op='create' conflict, version=true
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query?scroll_size=2&slices=2&routing=r1&version=true&refresh=true", `{
		"query":{"match_all":{}},
		"script":{"source":"ctx._source.cnt += 1"}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query?q=tag:t1&refresh=true", `{
		"slice":{"id":0,"max":2,"field":"tag"},
		"script":{"source":"ctx.op = 'none'"}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query", `{"script":{"source":"ctx.op = 'create'"}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query?conflicts=proceed", `{"script":{"source":"ctx.op = 'noop'"}}`, http.StatusOK)

	// Pipeline in UBQ: drop, fail, reroute (both via ctx._index/ctx._id and pipeline)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query?refresh=true&pipeline=bq_pipe_drop", `{
		"query":{"term":{"_id":"1"}},
		"script":{"source":"ctx._source.tag = 'dropme'"}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query?pipeline=bq_pipe_fail", `{
		"query":{"term":{"_id":"1"}},
		"script":{"source":"ctx._source.cnt += 1"}
	}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query?refresh=true&pipeline=bq_pipe_move", `{
		"query":{"term":{"_id":"2"}}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query?refresh=true", `{
		"query":{"term":{"_id":"3"}},
		"script":{"source":"ctx._index = 'bq_dst'"}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query?refresh=true", `{
		"query":{"term":{"_id":"4"}},
		"script":{"source":"ctx.op = 'delete'"}
	}`, http.StatusOK)

	// Async wait_for_completion=false on UBQ and DBQ, then block on /_tasks/<id>?wait_for_completion=true
	ubqTask := mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query?wait_for_completion=false", `{"script":{"source":"ctx._source.cnt += 1"}}`, http.StatusOK)
	if tid, _ := ubqTask["task"].(string); tid != "" {
		mustR67CovSrvHTTP(t, h, http.MethodGet, "/_tasks/"+tid+"?wait_for_completion=true&timeout=5s", "", http.StatusOK)
	}
	dbqTask := mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_dst/_delete_by_query?wait_for_completion=false&slices=2&scroll_size=1", `{"query":{"term":{"_id":"s-3"}}}`, http.StatusOK)
	if tid, _ := dbqTask["task"].(string); tid != "" {
		mustR67CovSrvHTTP(t, h, http.MethodGet, "/_tasks/"+tid+"?wait_for_completion=true&timeout=5s", "", http.StatusOK)
	}

	// Simulate mid-flight version conflict during UBQ & DBQ via onQueryHits hook
	var bumpSeq int64 = 10
	minBe.mu.Lock()
	minBe.onQueryHits = func(sqlStr string, hits []HitRow) ([]HitRow, error) {
		if len(hits) > 0 {
			bumpSeq += 10
			targetIdx := "bq_src"
			if strings.Contains(sqlStr, "bq_dst") {
				targetIdx = "bq_dst"
			}
			srv.setDocVersion(targetIdx, hits[0].ID, hits[0].Version+bumpSeq)
		}
		return hits, nil
	}
	minBe.mu.Unlock()
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query", `{"query":{"match_all":{}},"script":{"source":"ctx._source.cnt += 1"}}`, http.StatusConflict)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_delete_by_query?conflicts=proceed&refresh=true", `{"query":{"match_all":{}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_dst/_delete_by_query", `{"query":{"match_all":{}}}`, http.StatusConflict)
	minBe.mu.Lock()
	minBe.onQueryHits = nil
	minBe.queryHitsErr = errors.New("query hits error")
	minBe.mu.Unlock()
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_update_by_query", `{"query":{"match_all":{}}}`, http.StatusInternalServerError)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/bq_src/_delete_by_query", `{"query":{"match_all":{}}}`, http.StatusInternalServerError)
}

func TestRound67Cov_Server_HandlerRoutesIndicesSettingsILMAndScroll(t *testing.T) {
	telBe := &r67CovSrvTelemetrySQLBackend{
		MemoryBackend: NewMemoryBackend(false),
		tables: map[string]DorisTableDataTelemetry{
			"cat_open": {TableName: "cat_open", SizeBytes: 4096, RowCount: 7},
		},
	}
	_, h := newR67CovSrvWithBackend(t, "8.15.5", telBe)

	// 1. Setup open, closed, hidden, data stream, alias for _cat / HEAD / resolveTargetIndicesWithOptionsOnce
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cat_open", `{"settings":{"number_of_replicas":1},"mappings":{"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cat_closed", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/cat_closed/_close", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cat_hidden", `{"settings":{"index":{"hidden":true}},"mappings":{"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_index_template/cat_ds_tpl", `{"index_patterns":["cat-ds-*"],"data_stream":{}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_data_stream/cat-ds-1", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_index_template/cat_hds_tpl", `{"index_patterns":[".cat-hds-*"],"data_stream":{"hidden":true}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_data_stream/.cat-hds-1", "", http.StatusOK)

	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[
		{"add":{"index":"cat_open","alias":"al_open","index_routing":"ir1","search_routing":"sr1"}},
		{"add":{"index":"cat_hidden","alias":"al_hidden","is_hidden":true}},
		{"add":{"index":"cat-ds-1","alias":"al_ds"}}
	]}`, http.StatusOK)

	// 2. Handler dispatch routes that had 0 coverage
	routeChecks := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/_xpack/monitoring/bulk", ""},
		{http.MethodGet, "/_xpack", ""},
		{http.MethodGet, "/_cluster/allocation/explain", ""},
		{http.MethodGet, "/_search/template/t1", ""},
		{http.MethodGet, "/_slm/policy", ""},
		{http.MethodGet, "/_cat/data_streams?format=json", ""},
		{http.MethodGet, "/_doris/metrics", ""},
		{http.MethodGet, "/_resolve/index", ""},
		{http.MethodPost, "/_flush/synced", ""},
		{http.MethodPost, "/cat_open/_flush/synced", ""},
		{http.MethodGet, "/_security/_authenticate", ""},
		{http.MethodGet, "/_mapping/_doc", ""},
		{http.MethodPut, "/_mapping/_doc", `{"properties":{"a":{"type":"keyword"}}}`},
		{http.MethodDelete, "/_mapping/_doc", ""},
		{http.MethodDelete, "/_field_caps", ""},
		{http.MethodPost, "/cat_open/_knn_search", `{"knn":{"field":"k","query_vector":[1],"k":1,"num_candidates":1}}`},
		{http.MethodGet, "/cat_open/_search_shards", ""},
		{http.MethodGet, "/cat_open/_termvectors/1", ""},
		{http.MethodPost, "/cat_open/_rank_eval", `{}`},
		{http.MethodGet, "/cat_open/_recovery", ""},
		{http.MethodGet, "/cat_open/_segments", ""},
		{http.MethodGet, "/_cluster/stats/nodes", ""},
		{http.MethodPost, "/_watcher/watch/_execute", `{}`},
		{http.MethodHead, "/_cat/indices", ""},
		{http.MethodHead, "/_cat/aliases", ""},
		{http.MethodHead, "/_script_context", ""},
		{http.MethodHead, "/_script_languages", ""},
	}
	for _, rc := range routeChecks {
		st, _, _, raw := doR67CovSrvHTTP(t, h, rc.method, rc.path, rc.body, nil)
		if st >= 500 {
			t.Fatalf("route %s %s returned 5xx: %d body=%s", rc.method, rc.path, st, raw)
		}
	}

	// 3. handleCatIndices & handleCatAliases branches
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_cat/indices?format=json&health=yellow", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_cat/indices/.cat-hds-*?format=json&expand_wildcards=hidden", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_cat/indices/cat-ds-1,al_open?format=json", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_cat/indices/missing_cat_idx", "", http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_cat/aliases?format=json&local=true", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_cat/aliases/al_open?format=json&expand_wildcards=open", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_cat/aliases?expand_wildcards=none", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_cat/aliases?expand_wildcards=bad", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_cat/aliases", "", http.StatusMethodNotAllowed)

	// 4. handleHeadIndex & resolveValidatedReadTargets & resolveTargetIndicesWithOptionsOnce
	for _, hc := range []struct {
		path string
		want int
	}{
		{"/cat_open,missing_x?ignore_unavailable=false", http.StatusNotFound},
		{"/cat_closed?expand_wildcards=open", http.StatusOK},
		{"/cat_*,cat_closed?expand_wildcards=open", http.StatusOK},
		{"/cat_closed*?expand_wildcards=open", http.StatusNotFound},
		{"/cat_hidden*?expand_wildcards=open", http.StatusNotFound},
		{"/cat_*?expand_wildcards=bad", http.StatusBadRequest},
		{"/cat_*?expand_wildcards=none", http.StatusNotFound},
		{"/al_open", http.StatusOK},
		{"/cat-ds-1", http.StatusOK},
	} {
		st, _, _, _ := doR67CovSrvHTTP(t, h, http.MethodHead, hc.path, "", nil)
		if st != hc.want {
			t.Fatalf("HEAD %s: want %d, got %d", hc.path, hc.want, st)
		}
	}
	mustR67CovSrvHTTP(t, h, http.MethodHead, "/cat_*,-cat_hidden/_settings?expand_wildcards=bad", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodHead, "/cat_*,-cat_hidden/_settings?expand_wildcards=none", "", http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodHead, "/missing_concrete/_settings", "", http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/cat_*,al_*,-cat_closed,.ds-cat-ds-1-000001/_search?expand_wildcards=open", `{"query":{"match_all":{}}}`, http.StatusOK)

	// 5. handleCreateIndex validation branches
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_bad_name", `{}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/ci_badjson", `{bad`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/ci_emptyprop", `{"mappings":{"properties":{"":{"type":"keyword"}}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cat-ds-new", `{}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/al_open", `{}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/ci_badalias", `{"aliases":{"cat_open":{}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/ci_badrt", `{"mappings":{"runtime":{"r":{"type":"keyword","script":{"source":"emit(("}}}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/ci_rt_cycle", `{"mappings":{"runtime":{"a":{"type":"keyword","script":{"source":"emit(doc['b'].value)"}},"b":{"type":"keyword","script":{"source":"emit(doc['a'].value)"}}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/ci_rt_cycle/_doc/1?refresh=true", `{"msg":"cycle"}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/ci_rt_cycle/_search", `{"query":{"term":{"a":"x"}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/ci_ts_bad_rt", `{"settings":{"index.mode":"time_series","index.routing_path":["h"]},"mappings":{"runtime":{"h":{"type":"keyword","script":{"source":"emit('x')"}}},"properties":{"@timestamp":{"type":"date"},"h":{"type":"keyword","time_series_dimension":true},"m":{"type":"long","time_series_metric":"gauge"}}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/ci_ts_bad_al", `{"settings":{"index.mode":"time_series","index.routing_path":["h"]},"aliases":{"ts_al":{"routing":"r"}},"mappings":{"properties":{"@timestamp":{"type":"date"},"h":{"type":"keyword","time_series_dimension":true},"m":{"type":"long","time_series_metric":"gauge"}}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/ci_ts_bad_src", `{"settings":{"index.mode":"time_series","index.routing_path":["h"]},"mappings":{"_source":{"enabled":false},"properties":{"@timestamp":{"type":"date"},"h":{"type":"keyword","time_series_dimension":true},"m":{"type":"long","time_series_metric":"gauge"}}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/ci_logsdb", `{"settings":{"index.mode":"logsdb"},"mappings":{"properties":{"msg":{"type":"keyword"}}}}`, http.StatusOK)

	// 6. handleIndexSettings branches (blocks, translog in ES7/ES8, preserve_existing, TSDB end_time, include_defaults, filter)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cat_open/_settings", `{"index":{"translog.retention.age":"1h"}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cat_open/_settings", `{"index":{"top_metrics_max_size":0}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cat_open/_settings", `{"index":{"mode":"time_series"}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cat_closed/_settings", `{"index":{"mode":"time_series"}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cat_open/_settings?preserve_existing=true", `{"index":{"refresh_interval":"5s","number_of_replicas":2}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/cat_open/_settings/index.refresh*?flat_settings=true&include_defaults=true", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/cat_open/_settings", `{}`, http.StatusMethodNotAllowed)

	mustR67CovSrvHTTP(t, h, http.MethodPut, "/set_ts", `{"settings":{"index.mode":"time_series","index.routing_path":["h"],"index.time_series.start_time":"2026-01-01T00:00:00Z","index.time_series.end_time":"2026-02-01T00:00:00Z"},"mappings":{"properties":{"@timestamp":{"type":"date"},"h":{"type":"keyword","time_series_dimension":true},"m":{"type":"long","time_series_metric":"gauge"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/set_ts/_settings", `{"index":{"time_series.end_time":"2026-03-01T00:00:00Z"}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/set_ts/_settings?preserve_existing=true", `{"index":{"time_series.end_time":"2026-04-01T00:00:00Z"}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/set_ts/_settings", `{"index":{"time_series.end_time":null}}`, http.StatusOK)

	_, h7 := newR67CovSrv(t, "7.10.2")
	mustR67CovSrvHTTP(t, h7, http.MethodPut, "/v7_set", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h7, http.MethodPut, "/v7_set/_settings", `{"index":{"translog.retention.age":"1h"}}`, http.StatusOK)

	// 7. handleILMPolicy CRUD + wildcard + in-use error + handleILMExplain
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ilm/policy/ilm_pol_1", `{"policy":{"phases":{"hot":{"actions":{"rollover":{"max_age":"7d"}}}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ilm/policy/ilm_pol_2", `{"phases":{"hot":{}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_ilm/policy/ilm_bad", `{"policy":"not_an_obj"}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_ilm/policy/ilm_pol_*", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_ilm/policy/ilm_pol_1,ilm_missing", "", http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodHead, "/_ilm/policy/ilm_pol_*", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodHead, "/_ilm/policy/ilm_none_*", "", http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodHead, "/_ilm/policy/ilm_a*,ilm_b*", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_ilm/policy/ilm_a*,ilm_b*", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cat_open/_settings", `{"index":{"lifecycle.name":"ilm_pol_1"}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_ilm/policy/ilm_pol_1", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_ilm/explain?only_managed=true", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/_ilm/explain?only_errors=true", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_ilm/policy/ilm_pol_2", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_ilm/policy/ilm_no_such", "", http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodPatch, "/_ilm/policy/ilm_pol_1", "", http.StatusMethodNotAllowed)

	// 8. handleScroll validation & DELETE variants
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/_search/scroll", `{}`, http.StatusMethodNotAllowed)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_search/scroll", `{bad`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_search/scroll", `[]`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_search/scroll", `{"scroll_id":123}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_search/scroll", `{"scroll_id":"s1","scroll":"bad_dur"}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_search/scroll", `{"scroll_id":"s1","scroll":"48h"}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_search/scroll", `{}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_search/scroll", `{bad`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_search/scroll", `{"scroll_id":[123]}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_search/scroll", `{"scroll_id":123}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_search/scroll", `[123]`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_search/scroll", `{}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_search/scroll", `"missing_sid"`, http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_search/scroll?scroll_id=s_a,s_b", "", http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_search/scroll", `{"scroll_id":["_all"]}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodDelete, "/_search/scroll/_all", "", http.StatusOK)
}

func mustUnmarshalR67CovSrvSearchReq(t *testing.T, raw string) esast.SearchRequest {
	t.Helper()
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal SearchRequest failed: %v\nraw=%s", err, raw)
	}
	return req
}

func mustUnmarshalR67CovSrvQuery(t *testing.T, raw string) esast.Query {
	t.Helper()
	var q esast.Query
	if err := json.Unmarshal([]byte(raw), &q); err != nil {
		t.Fatalf("unmarshal Query failed: %v\nraw=%s", err, raw)
	}
	return q
}

func mustUnmarshalR67CovSrvAggs(t *testing.T, raw string) map[string]esast.AggSpec {
	t.Helper()
	var aggs map[string]esast.AggSpec
	if err := json.Unmarshal([]byte(raw), &aggs); err != nil {
		t.Fatalf("unmarshal Aggs failed: %v\nraw=%s", err, raw)
	}
	return aggs
}

func TestRound67Cov_Server_SearchMSearchExplainSuggestCollapseRescore(t *testing.T) {
	// 1. Standard multi-shard index + secondary index + downsampled TSDB index + collapse telemetry backend
	telemBE := &r67CovSrvTelemetrySQLBackend{
		MemoryBackend: NewMemoryBackend(false),
		tables:        map[string]DorisTableDataTelemetry{},
	}
	srv, h := newR67CovSrvWithBackend(t, "7.10.2", telemBE)
	srv.SetQueryCacheTTL(time.Minute, 128)
	srv.SetAutoPromoteThreshold(2)

	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_main", `{
		"settings":{"number_of_shards":3,"index.max_result_window":10000,"index.highlight.max_analyzed_offset":32},
		"mappings":{
			"properties":{
				"title":{"type":"text","term_vector":"with_positions_offsets"},
				"tag":{"type":"keyword"},
				"grp":{"type":"keyword"},
				"flag":{"type":"boolean"},
				"num":{"type":"long"},
				"unum":{"type":"unsigned_long"},
				"ts":{"type":"date"},
				"tsn":{"type":"date_nanos"},
				"ip":{"type":"ip"},
				"loc":{"type":"geo_point"},
				"score_v":{"type":"double"},
				"comp_f":{"type":"completion"},
				"nested_items":{
					"type":"nested",
					"properties":{
						"k":{"type":"keyword"},
						"v":{"type":"long"},
						"sub":{"type":"nested","properties":{"sk":{"type":"keyword"}}}
					}
				},
				"rel":{"type":"join","relations":{"parent":["child"]}}
			}
		}
	}`, http.StatusOK)

	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_sec", `{
		"settings":{"number_of_shards":1},
		"mappings":{
			"properties":{
				"title":{"type":"text"},
				"tag":{"type":"long"},
				"grp":{"type":"keyword"},
				"num":{"type":"long"},
				"ts":{"type":"date"}
			}
		}
	}`, http.StatusOK)

	// Alias with search routing + filter
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_aliases", `{
		"actions":[
			{"add":{"index":"s_main","alias":"al_routed","search_routing":"r1","filter":{"term":{"grp":"g1"}}}},
			{"add":{"index":"s_sec","alias":"al_sec_only","routing":"r2"}}
		]
	}`, http.StatusOK)

	// TSDB source + downsampled index for partial search failure tests
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_ts_src", `{
		"settings":{"index.mode":"time_series","index.routing_path":["host"]},
		"mappings":{
			"properties":{
				"@timestamp":{"type":"date"},
				"host":{"type":"keyword","time_series_dimension":true},
				"cpu":{"type":"double","time_series_metric":"gauge"}
			}
		}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_ts_src/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:10:00Z","host":"h1","cpu":42.5}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_ts_src/_downsample/s_ts_ds", `{"fixed_interval":"1h"}`, http.StatusOK)

	// Index documents into s_main (including join parent/child, nested items, completion, routing) and s_sec
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_main/_doc/p1?routing=r1&refresh=true", `{
		"title":"alpha beta quick brown fox",
		"tag":"k1",
		"grp":"g1",
		"flag":true,
		"num":10,
		"unum":18446744073709551600,
		"ts":"2026-01-01T00:00:00Z",
		"tsn":"2026-01-01T00:00:00.123456789Z",
		"ip":"10.0.0.1",
		"loc":{"lat":37.77,"lon":-122.41},
		"score_v":2.5,
		"comp_f":"alpha completion",
		"nested_items":[
			{"k":"n1","v":5,"sub":[{"sk":"s1"}]},
			{"k":"n2","v":15,"sub":[{"sk":"s2"}]}
		],
		"rel":"parent",
		"dyn_promote":"dv1"
	}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_main/_doc/p2?routing=r1&refresh=true", `{
		"title":"alpha gamma lazy dog runs fast across the huge open field beyond",
		"tag":"k2",
		"grp":"g1",
		"flag":false,
		"num":20,
		"unum":42,
		"ts":"2026-01-02T00:00:00Z",
		"tsn":"2026-01-02T00:00:00.000000001Z",
		"ip":"10.0.0.2",
		"loc":{"lat":37.78,"lon":-122.42},
		"score_v":4.5,
		"comp_f":"alpha second",
		"nested_items":[{"k":"n1","v":25,"sub":[{"sk":"s3"}]}],
		"rel":"parent",
		"dyn_promote":"dv2"
	}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_main/_doc/c1?routing=r1&refresh=true", `{
		"title":"child fox item",
		"tag":"k3",
		"grp":"g1",
		"num":30,
		"ts":"2026-01-03T00:00:00Z",
		"rel":{"name":"child","parent":"p1"}
	}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_sec/_doc/s1?refresh=true", `{
		"title":"sec alpha",
		"tag":999,
		"grp":"g1",
		"num":5,
		"ts":"2026-01-01T12:00:00Z"
	}`, http.StatusCreated)

	// Also seed a lookup index for valid & missing terms_lookup tests
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_lookup", `{"mappings":{"properties":{"allowed":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_lookup/_doc/lk1?refresh=true", `{"allowed":["k1","k2"]}`, http.StatusCreated)

	// 2. .tasks search, ignore_unavailable empty shards, date math pattern, force_synthetic_source
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/.tasks/_search", `{"query":{"match_all":{}}}`, http.StatusNotFound)
	emptyShardsResp := mustR67CovSrvHTTP(t, h, http.MethodPost, "/nonexist_pat_*/_search?ignore_unavailable=true", `{"query":{"match_all":{}}}`, http.StatusOK)
	if sh, ok := emptyShardsResp["_shards"].(map[string]any); !ok || fmt.Sprintf("%v", sh["total"]) != "0" {
		t.Fatalf("expected total=0 shards for ignore_unavailable empty wildcard, got %v", emptyShardsResp["_shards"])
	}
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/%3Cs_main-%7Bnow/d%7D%3E/_search?ignore_unavailable=true", `{"query":{"match_all":{}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search?force_synthetic_source=true", `{"size":2,"query":{"match_all":{}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_syn", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/s_syn/_doc/1?refresh=true", `{"tag":"k1"}`, http.StatusCreated)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_syn/_search?force_synthetic_source=true", `{"size":2,"query":{"match_all":{}}}`, http.StatusOK)

	// 3. Search validation & option branches inside handleSearch / executeSearchRequest
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search?include_named_queries_score=bad_bool", `{}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"stored_fields":"_none_","fields":["tag"]}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search?include_named_queries_score=true&profile=true&batched_reduce_size=2&pre_filter_shard_size=1&rest_total_hits_as_int=true", `{
		"track_total_hits":-1,
		"docvalue_fields":[{"field":"ts","format":"use_field_mapping"}],
		"fields":["tag","unum","ts"],
		"script_fields":{"dbl":{"script":{"source":"doc['num'].value * 2"}}},
		"indices_boost":{"s_main":1.5},
		"query":{"bool":{"must":[{"term":{"grp":{"value":"g1","_name":"named_grp"}}}]}},
		"aggregations":{"cnt_tag":{"value_count":{"field":"tag"}}}
	}`, http.StatusOK)

	// Direct executeSearchRequest slice error & empty targets paths
	badSliceReq := esast.SearchRequest{Slice: &esast.SliceSpec{ID: 0, Max: 1}}
	if _, st, _, _ := srv.executeSearchRequest(context.Background(), "s_main", &badSliceReq); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on slice.max<=1, got %d", st)
	}
	missReq := mustUnmarshalR67CovSrvSearchReq(t, `{"query":{"match_all":{}}}`)
	_, _, _, _ = srv.executeSearchRequest(context.Background(), "uncreated_direct_idx", &missReq)

	// TerminateAfter branches: from >= terminate_after and from + len(hits) > terminate_after
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"from":3,"terminate_after":1,"query":{"match_all":{}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"from":0,"size":5,"terminate_after":1,"query":{"match_all":{}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{
		"from":0,"size":5,"terminate_after":1,
		"runtime_mappings":{"rt_num":{"type":"long","script":{"source":"emit(doc['num'].value + 1)"}}},
		"query":{"term":{"rt_num":11}}
	}`, http.StatusOK)

	// Rescore + Collapse: rejected in ES7 mode, allowed in ES8 mode
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{
		"size":1,
		"collapse":{"field":"grp"},
		"rescore":{"window_size":5,"query":{"rescore_query":{"term":{"tag":"k2"}}}}
	}`, http.StatusBadRequest)
	srv.SetTargetESVersion("8.15.5")
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{
		"size":1,
		"track_scores":true,
		"indices_boost":[{"s_main":2.0}],
		"collapse":{"field":"grp","inner_hits":{"name":"top_grp","size":2,"from":0,"sort":[{"num":"desc"}]}},
		"rescore":{"window_size":5,"query":{"rescore_query":{"term":{"tag":"k2"}}}},
		"query":{"match_all":{}}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{
		"size":1,
		"rescore":{"window_size":50000,"query":{"rescore_query":{"term":{"tag":"k2"}}}}
	}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{
		"size":1,
		"rescore":{"window_size":5,"query":{"rescore_query":{"term":{"tag":"k2"}}}},
		"post_filter":{"term":{"tag":"k1"}}
	}`, http.StatusOK)

	// Cross-index search, SearchAfter, AutoPromoteThreshold, QueryCache + ShardRequestCache
	if st, _, _, raw := doR67CovSrvHTTP(t, h, http.MethodPost, "/s_main,s_sec/_search", `{
		"size":2,
		"sort":[{"num":"asc"},{"_id":"asc"}],
		"search_after":[10,"p1"],
		"query":{"match_all":{}},
		"aggs":{"g_terms":{"terms":{"field":"tag"}}}
	}`, nil); st >= 500 {
		t.Fatalf("cross-index s_main,s_sec returned 5xx: %d body=%s", st, raw)
	}

	// Partial failure on downsampled TSDB index mixed with regular index
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_ts_ds,s_main/_search?allow_partial_search_results=true", `{
		"size":1,
		"aggs":{"dh_cal":{"date_histogram":{"field":"@timestamp","calendar_interval":"1d"}}}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_ts_ds,s_main/_search?allow_partial_search_results=false", `{
		"size":1,
		"aggs":{"dh_cal":{"date_histogram":{"field":"@timestamp","calendar_interval":"1d"}}}
	}`, http.StatusBadRequest)

	// AutoPromoteThreshold=2: search on unindexed dyn_promote field repeatedly (uncached + queryCache + shardRequestCache paths)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search?request_cache=true", `{"size":0,"query":{"term":{"dyn_promote":"dv1"}},"aggs":{"dyn_t":{"terms":{"field":"dyn_promote"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search?request_cache=true", `{"size":0,"query":{"term":{"dyn_promote":"dv1"}},"aggs":{"dyn_t":{"terms":{"field":"dyn_promote"}}}}`, http.StatusOK)
	for i := 0; i < 3; i++ {
		mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"size":2,"query":{"term":{"dyn_promote":"dv1"}}}`, http.StatusOK)
	}
	// ShardRequestCache (size=0) & QueryCache hits
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search?request_cache=true", `{"size":0,"aggs":{"grp_t":{"terms":{"field":"grp"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search?request_cache=true", `{"size":0,"aggs":{"grp_t":{"terms":{"field":"grp"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search?request_cache=false", `{"size":0,"aggs":{"grp_t":{"terms":{"field":"grp"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"size":2,"query":{"term":{"grp":"g1"}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"size":2,"query":{"term":{"grp":"g1"}}}`, http.StatusOK)

	// Alias search routing & multi-routing query param
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/al_routed/_search", `{"query":{"match_all":{}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/s_main/_search?routing=r1,r2", `{"query":{"match_all":{}}}`, http.StatusOK)

	// Highlight max_analyzed_offset error (p2 title > 32 chars with plain highlighter)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"query":{"match":{"title":"alpha"}},"highlight":{"fields":{"title":{"type":"plain"}}}}`, http.StatusBadRequest)
	// ExtractUnifiedFields on 0 hits
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"query":{"term":{"tag":"no_such_tag"}},"fields":["tag","ts"]}`, http.StatusOK)

	// Terms lookup error in query / highlight / collapse.inner_hits / knn.filter
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"query":{"terms":{"tag":{"index":"missing_lk_idx","id":"lk1","path":"allowed"}}}}`, http.StatusNotFound)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"query":{"terms":{"tag":{"index":"s_lookup","id":"lk1","path":"allowed"}}},"highlight":{"highlight_query":{"terms":{"tag":{"index":"missing_lk_idx","id":"lk1","path":"allowed"}}},"fields":{"tag":{}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"collapse":{"field":"grp","inner_hits":{"name":"ih_lk","query":{"terms":{"tag":{"index":"missing_lk_idx","id":"lk1","path":"allowed"}}}}}}`, http.StatusBadRequest)

	// Runtime mappings + global agg + bad script + TSDB runtime shadowing
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{"runtime_mappings":{"bad_rt":{"type":"keyword","script":{"source":"emit(("}}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_ts_src/_search", `{"runtime_mappings":{"host":{"type":"keyword","script":{"source":"emit('x')"}}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{
		"runtime_mappings":{"rt_grp":{"type":"keyword","script":{"source":"emit(doc['grp'].value + '_rt')"}}},
		"query":{"term":{"tag":"k1"}},
		"aggs":{
			"g_all":{"global":{},"aggs":{"rt_cnt":{"terms":{"field":"rt_grp"}}}},
			"ss_dist":{"string_stats":{"field":"tag","show_distribution":true}}
		}
	}`, http.StatusOK)

	// Nested + Join inner_hits + Same-name nested merge + Script/Nested/CustomScore branches
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{
		"query":{
			"bool":{
				"should":[
					{"nested":{"path":"nested_items","query":{"term":{"nested_items.k":"n1"}},"inner_hits":{"name":"ni_hit","highlight":{"fields":{"nested_items.k":{}}},"fields":["nested_items.k"],"docvalue_fields":[{"field":"nested_items.v"}],"script_fields":{"nv2":{"script":{"source":"doc['nested_items.v'].value + 1"}}}}}},
					{"nested":{"path":"nested_items","query":{"range":{"nested_items.v":{"gte":10}}},"inner_hits":{"name":"ni_hit","from":0,"size":2,"sort":[{"nested_items.v":"desc"}]}}},
					{"has_child":{"type":"child","query":{"match_all":{}},"inner_hits":{"name":"ch_hits"}}},
					{"has_parent":{"parent_type":"parent","query":{"match_all":{}},"inner_hits":{"name":"pa_hits"}}}
				]
			}
		}
	}`, http.StatusOK)

	// Suggest: term (missing, popular, always), phrase, completion with _source filter and _source disabled
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{
		"size":0,
		"_source":["tag"],
		"suggest":{
			"text":"alpa quickk",
			"term_miss":{"term":{"field":"title","suggest_mode":"missing","max_edits":2,"size":3}},
			"term_pop":{"term":{"field":"title","suggest_mode":"popular"}},
			"term_all":{"term":{"field":"title","suggest_mode":"always"}},
			"phr":{"phrase":{"field":"title"}},
			"cmp":{"prefix":"alp","completion":{"field":"comp_f","size":3}}
		}
	}`, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_search", `{
		"size":0,
		"_source":false,
		"suggest":{"cmp_nosrc":{"prefix":"alp","completion":{"field":"comp_f","size":2}}}
	}`, http.StatusOK)

	// 4. handleMSearch edge branches
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_msearch", "{bad_hdr\n{}\n", http.StatusBadRequest)
	msearchErrBody := strings.Join([]string{
		`{"indices":["s_main","s_sec"],"routing":["r1","r2"],"search_type":"count"}`, `{"knn":{"field":"vec","query_vector":[1,2],"k":1,"num_candidates":2}}`,
		`{"index":"s_main","routing":123,"terminate_after":0}`, `{}`,
		`{"index":"s_main","rest_total_hits_as_int":true}`, `{"track_total_hits":false}`,
		`{"index":"s_main"}`, `{"retriever":{"standard":{"query":{"match_all":{}}}}}`,
		`{"index":"s_main"}`, `{"query":{"rule":{"match_all":{}}}}`,
		`{"index":"s_main"}`, `{"aggs":{"rs":{"random_sampler":{"probability":0.5}}}}`,
		`{"index":"s_main"}`, `{"aggs":{"es":{"extended_stats":{"field":"num","sigma":"bad"}}}}`,
		`{"index":"s_main"}`, `{"rank":{"rrf":{"window_size":5,"rank_window_size":5}}}`,
		`{"index":"s_main"}`, `{bad_query_json`,
		`{"index":"s_main"}`, `{}`,
	}, "\n") + "\n"
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_msearch?typed_keys=true&filter_path=responses.hits.hits._id,responses.error", msearchErrBody, http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_msearch?rest_total_hits_as_int=true", "{\"index\":\"s_main\"}\n{\"track_total_hits\":false}\n", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_msearch", "{\"index\":\"s_main\"}\n", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/_msearch", "\n\n", http.StatusOK)

	// 5. handleCount branches
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/s_main/_count?q=grp:g1&terminate_after=1", "", http.StatusOK)
	mustR67CovSrvHTTP(t, h, http.MethodGet, "/s_main/_count?terminate_after=0", "", http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_count", `{"unknown_count_field":true}`, http.StatusBadRequest)

	// 6. handleDorisExplain error, deprecation, ES8 rewrite & caused_by branches
	srv.SetTargetESVersion("7.10.2")
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_doris/explain", `{"aggs":{"b":{"boxplot":{"field":"num","compression":-1}}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_doris/explain", `{"aggs":{"m":{"median_absolute_deviation":{"field":"num","execution_hint":"bad"}}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_doris/explain", `{"collapse":{"field":"grp"},"rescore":{"query":{"rescore_query":{"match_all":{}}}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_doris/explain?from=-1", `{}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_doris/explain", `{
		"indices_boost":{"s_main":1.5},
		"docvalue_fields":[{"field":"ts","format":"use_field_mapping"}],
		"query":{"match_all":{}}
	}`, http.StatusOK)
	srv.SetTargetESVersion("8.15.5")
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_doris/explain?from=-1", `{}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_doris/explain", `{"collapse":{"field":"grp","inner_hits":{"size":1}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_doris/explain", `{"query":{"multi_match":{"query":"hi","type":"bool_prefix","fields":["title"],"cutoff_frequency":0.5}}}`, http.StatusBadRequest)
	mustR67CovSrvHTTP(t, h, http.MethodPost, "/s_main/_doris/explain", `{"aggs":{"t":{"terms":{"field":"tag"},"aggs":{"top_m":{"top_metrics":{"metrics":[{"field":"num"}],"sort":{"num":"desc"}}}}}}}`, http.StatusOK)

	// 7. Backend QueryHits / QueryAggs 500 error propagation in executeSearchRequest
	errBE := newR67CovSrvMinimalBackend()
	_, eh := newR67CovSrvWithBackend(t, "8.15.5", errBE)
	mustR67CovSrvHTTP(t, eh, http.MethodPut, "/err_idx", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67CovSrvHTTP(t, eh, http.MethodPut, "/err_idx/_doc/1?refresh=true", `{"tag":"x"}`, http.StatusCreated)
	errBE.mu.Lock()
	errBE.queryHitsErr = errors.New("simulated Doris BE hits failure")
	errBE.mu.Unlock()
	mustR67CovSrvHTTP(t, eh, http.MethodPost, "/err_idx/_search", `{"size":5,"query":{"match_all":{}}}`, http.StatusInternalServerError)
	errBE.mu.Lock()
	errBE.queryHitsErr = nil
	errBE.queryAggsErr = errors.New("simulated Doris BE aggs failure")
	errBE.mu.Unlock()
	mustR67CovSrvHTTP(t, eh, http.MethodPost, "/err_idx/_search", `{"size":0,"aggs":{"t":{"terms":{"field":"tag"}}}}`, http.StatusInternalServerError)
}

func TestRound67Cov_Server_AggsPipelineRuntimeScoringAndHistograms(t *testing.T) {
	ctx := context.Background()
	srv, h := newR67CovSrv(t, "8.15.5")

	// Compile rich schema with unsigned_long, boolean, date, date_nanos, lowercase keyword, ip, geo_point, nested, join
	mustR67CovSrvHTTP(t, h, http.MethodPut, "/cov_agg", `{
		"settings":{
			"analysis":{"normalizer":{"lc_norm":{"type":"custom","filter":["lowercase"]}}}
		},
		"mappings":{
			"properties":{
				"tag":{"type":"keyword","normalizer":"lc_norm"},
				"title":{"type":"text"},
				"flag":{"type":"boolean"},
				"num":{"type":"long","null_value":0},
				"unum":{"type":"unsigned_long"},
				"dbl":{"type":"double"},
				"dt":{"type":"date","format":"strict_date_optional_time||epoch_millis"},
				"dt_ns":{"type":"date_nanos"},
				"ip":{"type":"ip"},
				"loc":{"type":"geo_point"},
				"nested_items":{
					"type":"nested",
					"properties":{
						"k":{"type":"keyword"},
						"v":{"type":"long"},
						"sub":{"type":"nested","properties":{"sk":{"type":"keyword"}}}
					}
				},
				"rel":{"type":"join","relations":{"parent":["child"]}}
			}
		}
	}`, http.StatusOK)

	idxSchema := srv.getOrCompileReadOnlySchema(ctx, "cov_agg")
	doc1JSON := []byte(`{"tag":"Alpha","title":"quick brown","flag":true,"num":10,"unum":18446744073709551610,"dbl":12.5,"dt":"2026-01-01T00:00:00Z","dt_ns":"2026-01-01T00:00:00.123456789Z","ip":"10.0.0.1","loc":{"lat":37.7,"lon":-122.4},"nested_items":[{"k":"a","v":3,"sub":[{"sk":"s1"}]},{"k":"b","v":9,"sub":[{"sk":"s2"}]}],"rel":"parent"}`)
	doc2JSON := []byte(`{"tag":"Beta","title":"lazy dog","flag":false,"unum":5,"dbl":25.0,"dt":1767312000000,"dt_ns":"2026-01-02T00:00:00.000000001Z","ip":"10.0.0.10","nested_items":[{"k":"a","v":1,"sub":[{"sk":"s0"}]}],"rel":{"name":"child","parent":"h1"}}`)

	h1 := HitRow{Index: "cov_agg", ID: "h1", Version: 1, Score: 2.0, Source: doc1JSON, RawSource: doc1JSON, Schema: idxSchema}
	h2 := HitRow{Index: "cov_agg", ID: "h2", Version: 2, Score: 1.5, Source: doc2JSON, RawSource: doc2JSON, Schema: idxSchema}

	// 1. evalRuntimeMappingsOnHitRows across all supported ES runtime types + fallback emit
	rtReq := mustUnmarshalR67CovSrvSearchReq(t, `{
		"runtime_mappings":{
			"rt_ulong":{"type":"unsigned_long","script":{"source":"emit(18446744073709551605L)"}},
			"rt_long":{"type":"long","script":{"source":"emit(doc['num'].value + 2)"}},
			"rt_dbl":{"type":"double","script":{"source":"emit(doc['dbl'].value * 1.5)"}},
			"rt_bool":{"type":"boolean","script":{"source":"emit(doc['flag'].value)"}},
			"rt_dtns":{"type":"date_nanos","script":{"source":"emit('2026-01-01T00:00:00.000000500Z')"}},
			"rt_dt":{"type":"date","script":{"source":"emit('2026-01-01T01:00:00Z')"}},
			"rt_ip":{"type":"ip","script":{"source":"emit('192.168.1.5')"}},
			"rt_geo":{"type":"geo_point","script":{"source":"emit(37.75, -122.45)"}},
			"rt_ret":{"type":"keyword","script":{"source":"return 'ok';"}}
		}
	}`)
	rtHits := []HitRow{h1, h2}
	srv.evalRuntimeMappingsOnHitRows(idxSchema, rtReq.RuntimeMappings, rtHits)

	// 2. extractHitSortValues, hitIsAfterSearchAfter, compareHitRowsBySortWithSchemas, normalizeCollapseGroupKey, collectCollapseCandidateValues
	sortReq := mustUnmarshalR67CovSrvSearchReq(t, `{
		"sort":[
			{"_score":"desc"},
			{"_tsid":"asc"},
			{"_version":"desc"},
			{"unum":{"order":"desc","missing":"_last"}},
			{"num":{"order":"asc","missing":"_first"}},
			{"flag":"desc"},
			{"dt_ns":"asc"},
			{"tag":"asc"},
			{"ip":"asc"},
			{"nested_items.v":{"order":"asc","mode":"median","nested":{"path":"nested_items"}}},
			{"_script":{"type":"number","order":"asc","script":{"source":"doc['num'].value + 1"}}},
			{"_script":{"type":"string","order":"asc","script":{"source":"doc['tag'].value"}}}
		]
	}`)
	sv1 := extractHitSortValues(rtHits[0], sortReq.Sort, idxSchema)
	sv2 := extractHitSortValues(rtHits[1], sortReq.Sort, idxSchema)
	if len(sv1) != len(sortReq.Sort) || len(sv2) != len(sortReq.Sort) {
		t.Fatalf("unexpected sort value lengths: %d / %d", len(sv1), len(sv2))
	}
	_ = compareHitRowsBySortWithSchemas(rtHits[0], rtHits[1], sortReq.Sort, idxSchema, idxSchema)
	_ = hitIsAfterSearchAfter(rtHits[1], sortReq.Sort, sv1, idxSchema)
	_ = hitIsAfterSearchAfter(rtHits[0], sortReq.Sort, sv1, idxSchema)

	_ = normalizeCollapseGroupKey("true", "flag", idxSchema, idxSchema)
	_ = normalizeCollapseGroupKey("2026-01-01T00:00:00Z", "dt", idxSchema, idxSchema)
	_ = normalizeCollapseGroupKey("2026-01-01T00:00:00.123456789Z", "dt_ns", idxSchema, idxSchema)
	_ = normalizeCollapseGroupKey("Alpha", "tag", idxSchema, idxSchema)
	_ = collectCollapseCandidateValues(h1, "flag", idxSchema)
	_ = collectCollapseCandidateValues(h1, "unum", idxSchema)
	_ = collectCollapseCandidateValues(h1, "dt_ns", idxSchema)
	_ = collectCollapseCandidateValues(h1, "tag", idxSchema)

	// 3. buildNestedInnerHitsForHitWithOpts + finalizeMergedNestedInnerHits + evalHitRescoreQuery
	nq := mustUnmarshalR67CovSrvQuery(t, `{
		"nested":{
			"path":"nested_items",
			"query":{"term":{"nested_items.k":"a"}},
			"inner_hits":{"name":"ih1","from":0,"size":2,"sort":[{"nested_items.v":"desc"}],"highlight":{"fields":{"nested_items.k":{}}},"fields":["nested_items.k"],"docvalue_fields":[{"field":"nested_items.v"}],"script_fields":{"v2":{"script":{"source":"doc['nested_items.v'].value * 10"}}}}
		}
	}`)
	ihEnv := buildNestedInnerHitsForHitWithOpts(h1, "cov_agg", idxSchema, nq.Nested, false)
	_ = finalizeMergedNestedInnerHits(ihEnv, nq.Nested.InnerHits, idxSchema, "nested_items")

	rq1 := mustUnmarshalR67CovSrvQuery(t, `{"script_score":{"query":{"match_all":{}},"script":{"source":"_score * 2"}}}`)
	rq2 := mustUnmarshalR67CovSrvQuery(t, `{"function_score":{"query":{"term":{"flag":true}},"random_score":{"seed":7,"field":"num"},"weight":3}}`)
	_, _ = srv.evalHitRescoreQuery(h1, &rq1, idxSchema)
	_, _ = srv.evalHitRescoreQuery(h1, &rq2, idxSchema)

	// 4. scoreNonScriptDocWithCorpusR66 & evalQueryScriptScoreOnDocWithSchema
	var doc1Map, doc2Map map[string]any
	dec1 := json.NewDecoder(bytes.NewReader(doc1JSON))
	dec1.UseNumber()
	_ = dec1.Decode(&doc1Map)
	dec2 := json.NewDecoder(bytes.NewReader(doc2JSON))
	dec2.UseNumber()
	_ = dec2.Decode(&doc2Map)

	for _, rawQ := range []string{
		`{"pinned":{"ids":["h1"],"organic":{"term":{"tag":"alpha"}}}}`,
		`{"constant_score":{"filter":{"term":{"flag":true}},"boost":2.5}}`,
		`{"function_score":{"query":{"term":{"tag":"alpha"}},"functions":[{"random_score":{"seed":42}},{"field_value_factor":{"field":"num","modifier":"log1p","missing":1}}],"boost_mode":"sum","score_mode":"avg"}}`,
		`{"script_score":{"query":{"match_all":{}},"script":{"source":"doc['num'].value + params.k","params":{"k":5}}}}`,
		`{"bool":{"must":[{"term":{"flag":true}}],"should":[{"range":{"num":{"gte":5}}}]}}`,
	} {
		q := mustUnmarshalR67CovSrvQuery(t, rawQ)
		sc := srv.scoreNonScriptDocWithCorpusR66(ctx, "cov_agg", idxSchema, doc1Map, &q, nil, nil)
		_ = evalQueryScriptScoreOnDocWithSchema(idxSchema, doc1Map, &q, sc)
	}

	// 5. buildAggsMapWithSchema + attachSubAggsToBucketWithSchema + filterAndSortTermsRowsWithSubAggs + buildTopHitsList + Composite
	aggReq := mustUnmarshalR67CovSrvSearchReq(t, `{
		"aggs":{
			"t_ord_std":{"terms":{"field":"tag","size":5,"show_term_doc_count_error":true,"order":{"sub_ext['std_deviation_bounds.upper']":"desc"}},"aggs":{
				"sub_ext":{"extended_stats":{"field":"num"}},
				"sub_dt_min":{"min":{"field":"dt"}},
				"sub_pct_arr":{"percentiles":{"field":"num","percents":[25,50,95],"keyed":false}},
				"sub_ranks_arr":{"percentile_ranks":{"field":"num","values":[10,20],"keyed":false}},
				"sub_box":{"boxplot":{"field":"num"}},
				"sub_str":{"string_stats":{"field":"tag"}},
				"sub_th":{"top_hits":{"size":1,"_source":["tag"],"sort":[{"num":"desc"}]}},
				"sub_rng":{"range":{"field":"num","keyed":true,"ranges":[{"to":15},{"from":15}]},"aggs":{"m_sum":{"sum":{"field":"num"}}}},
				"sub_drng":{"date_range":{"field":"dt","format":"yyyy-MM-dd","ranges":[{"from":"2026-01-01","to":"2026-01-02"}]},"aggs":{"cnt":{"value_count":{"field":"num"}}}},
				"sub_ipr":{"ip_range":{"field":"ip","ranges":[{"mask":"10.0.0.0/24"}]}},
				"sub_flt_anon":{"filters":{"other_bucket":true,"filters":[{"term":{"flag":true}},{"term":{"flag":false}}]},"aggs":{"f_avg":{"avg":{"field":"num"}}}},
				"sub_flt_named":{"filters":{"other_bucket":true,"keyed":false,"filters":{"yes":{"term":{"flag":true}},"no":{"term":{"flag":false}}}},"aggs":{"f_avg":{"avg":{"field":"num"}}}},
				"sub_dh":{"date_histogram":{"field":"dt","calendar_interval":"1d","min_doc_count":0},"aggs":{"d_sum":{"sum":{"field":"num"}}}},
				"sub_h":{"histogram":{"field":"num","interval":10,"min_doc_count":0},"aggs":{"h_sum":{"sum":{"field":"num"}}}},
				"sub_sig":{"significant_terms":{"field":"tag"}}
			}},
			"t_ord_box":{"terms":{"field":"tag","order":{"sub_box.lower":"asc"}},"aggs":{"sub_box":{"boxplot":{"field":"num"}}}},
			"t_ord_sos":{"terms":{"field":"tag","order":{"sub_ext.sum_of_squares":"desc"}},"aggs":{"sub_ext":{"extended_stats":{"field":"num"}}}},
			"t_ord_tm":{"terms":{"field":"tag","order":{"sub_tm.num":"desc"}},"aggs":{"sub_tm":{"top_metrics":{"metrics":[{"field":"num"}],"sort":{"num":"desc"}}}}},
			"comp":{"composite":{"size":10,"sources":[
				{"s_tag":{"terms":{"field":"tag","missing_bucket":true,"order":"desc"}}},
				{"s_dt":{"date_histogram":{"field":"dt","fixed_interval":"1d"}}},
				{"s_h":{"histogram":{"field":"num","interval":10}}}
			]},"aggs":{"c_sum":{"sum":{"field":"num"}}}}
		}
	}`)
	bucketsByAgg := map[string][]AggRow{
		"t_ord_std": {
			{AggName: "t_ord_std", BucketKey: "alpha", DocCount: 2, Weight: 1},
			{AggName: "t_ord_std", BucketKey: "beta", DocCount: 1, Weight: 0},
		},
		"t_ord_std.sub_ext": {
			{AggName: "t_ord_std.sub_ext", BucketKey: "alpha\x1f_stats_count", DocCount: 2, Value: 2},
			{AggName: "t_ord_std.sub_ext", BucketKey: "alpha\x1f_stats_avg", Value: 15},
			{AggName: "t_ord_std.sub_ext", BucketKey: "alpha\x1f_stats_std", Value: 5},
			{AggName: "t_ord_std.sub_ext", BucketKey: "beta\x1f_stats_count", DocCount: 1, Value: 1},
			{AggName: "t_ord_std.sub_ext", BucketKey: "beta\x1f_stats_avg", Value: 5},
			{AggName: "t_ord_std.sub_ext", BucketKey: "beta\x1f_stats_std", Value: 1},
		},
		"t_ord_std.sub_dt_min": {
			{AggName: "t_ord_std.sub_dt_min", BucketKey: "alpha", DocCount: 1, Value: 1767225600000, Weight: 1},
		},
		"t_ord_std.sub_pct_arr": {
			{AggName: "t_ord_std.sub_pct_arr", BucketKey: "alpha\x1f50.0", Value: 10, Weight: 1},
		},
		"t_ord_std.sub_ranks_arr": {
			{AggName: "t_ord_std.sub_ranks_arr", BucketKey: "alpha\x1f10.0", Value: 50, Weight: 1},
		},
		"t_ord_std.sub_box": {
			{AggName: "t_ord_std.sub_box", BucketKey: "alpha\x1f0.0", Value: 5, Weight: 1},
			{AggName: "t_ord_std.sub_box", BucketKey: "alpha\x1f25.0", Value: 8, Weight: 1},
			{AggName: "t_ord_std.sub_box", BucketKey: "alpha\x1f50.0", Value: 10, Weight: 1},
			{AggName: "t_ord_std.sub_box", BucketKey: "alpha\x1f75.0", Value: 15, Weight: 1},
			{AggName: "t_ord_std.sub_box", BucketKey: "alpha\x1f100.0", Value: 20, Weight: 1},
		},
		"t_ord_std.sub_str": {
			{AggName: "t_ord_std.sub_str", BucketKey: "alpha\x1f_sstats_count", DocCount: 2},
			{AggName: "t_ord_std.sub_str", BucketKey: "alpha\x1f_sstats_min", Value: 4},
			{AggName: "t_ord_std.sub_str", BucketKey: "alpha\x1f_sstats_max", Value: 5},
			{AggName: "t_ord_std.sub_str", BucketKey: "alpha\x1f_sstats_avg", Value: 4.5},
			{AggName: "t_ord_std.sub_str", BucketKey: "alpha\x1f_sstats_entropy", Value: 2.1},
		},
		"t_ord_std.sub_th": {
			{AggName: "t_ord_std.sub_th", BucketKey: "alpha\x1fh1", Value: 2.0},
		},
		"t_ord_std.sub_rng": {
			{AggName: "t_ord_std.sub_rng", BucketKey: "alpha\x1f*-15.0", DocCount: 1},
		},
		"t_ord_std.sub_drng": {
			{AggName: "t_ord_std.sub_drng", BucketKey: "alpha\x1f2026-01-01-2026-01-02", DocCount: 1},
		},
		"t_ord_std.sub_ipr": {
			{AggName: "t_ord_std.sub_ipr", BucketKey: "alpha\x1f10.0.0.0/24", DocCount: 2},
		},
		"t_ord_std.sub_flt_anon": {
			{AggName: "t_ord_std.sub_flt_anon", BucketKey: "alpha\x1f0", DocCount: 1},
			{AggName: "t_ord_std.sub_flt_anon", BucketKey: "alpha\x1f_other_", DocCount: 1},
		},
		"t_ord_std.sub_flt_named": {
			{AggName: "t_ord_std.sub_flt_named", BucketKey: "alpha\x1fyes", DocCount: 1},
			{AggName: "t_ord_std.sub_flt_named", BucketKey: "alpha\x1fno", DocCount: 1},
		},
		"t_ord_std.sub_dh": {
			{AggName: "t_ord_std.sub_dh", BucketKey: "alpha\x1f1767225600000", DocCount: 2},
		},
		"t_ord_std.sub_h": {
			{AggName: "t_ord_std.sub_h", BucketKey: "alpha\x1f10", DocCount: 2},
		},
		"t_ord_std.sub_sig": {
			{AggName: "t_ord_std.sub_sig", BucketKey: "alpha\x1fa", DocCount: 2},
		},
		"t_ord_box.sub_box": {
			{AggName: "t_ord_box.sub_box", BucketKey: "alpha\x1f0.0", Value: 5, Weight: 1},
			{AggName: "t_ord_box.sub_box", BucketKey: "alpha\x1f25.0", Value: 8, Weight: 1},
			{AggName: "t_ord_box.sub_box", BucketKey: "alpha\x1f75.0", Value: 15, Weight: 1},
			{AggName: "t_ord_box.sub_box", BucketKey: "alpha\x1f100.0", Value: 20, Weight: 1},
		},
		"t_ord_tm.sub_tm": {
			{AggName: "t_ord_tm.sub_tm", BucketKey: "alpha\x1f__tm__\x00num\x0010", DocCount: 1, Value: 10},
		},
		"comp": {
			{AggName: "comp", BucketKey: "alpha\x1f1767225600000\x1f10", DocCount: 1},
			{AggName: "comp", BucketKey: "\x00NULL\x1f1767312000000\x1f20", DocCount: 1},
		},
		"comp.c_sum": {
			{AggName: "comp.c_sum", BucketKey: "alpha\x1f1767225600000\x1f10", Value: 10, Weight: 1},
		},
	}
	bucketsByAgg["t_ord_box"] = bucketsByAgg["t_ord_std"]
	bucketsByAgg["t_ord_sos"] = bucketsByAgg["t_ord_std"]
	bucketsByAgg["t_ord_sos.sub_ext"] = bucketsByAgg["t_ord_std.sub_ext"]
	bucketsByAgg["t_ord_tm"] = bucketsByAgg["t_ord_std"]
	docLookup := func(id string) *HitRow {
		if id == "h1" {
			return &h1
		}
		if id == "h2" {
			return &h2
		}
		return nil
	}
	effAggs := aggReq.EffectiveAggs()
	builtAggs := buildAggsMapWithSchema("cov_agg", "", effAggs, bucketsByAgg, 2, docLookup, idxSchema)
	if len(builtAggs) == 0 {
		t.Fatalf("expected non-empty built aggs")
	}
	tSpec := effAggs["t_ord_std"]
	_, _ = filterAndSortTermsRowsWithSubAggs(bucketsByAgg["t_ord_std"], tSpec.EffectiveTerms(), "t_ord_std", "", bucketsByAgg, tSpec.SubAggs(), "cov_agg", docLookup, idxSchema)
	thSpec := tSpec.SubAggs()["sub_th"].TopHits
	_ = buildTopHitsList("cov_agg", []AggRow{{BucketKey: "h1", Value: 2.0}}, thSpec, docLookup)
	compSpec := effAggs["comp"]
	_ = buildCompositeAggObjectWithSchema("cov_agg", "comp", "", compSpec.Composite, compSpec.SubAggs(), bucketsByAgg["comp"], bucketsByAgg, docLookup, idxSchema)
	if len(compSpec.Composite.Sources) > 0 {
		sEntry := compSpec.Composite.Sources[0]["s_tag"]
		_ = compareCompositeSourceValWithSchema(nil, "alpha", sEntry, idxSchema)
		_ = compareCompositeSourceValWithSchema("alpha", "beta", sEntry, idxSchema)
		dtEntry := compSpec.Composite.Sources[1]["s_dt"]
		_ = compareCompositeSourceValWithSchema(int64(1767225600000), int64(1767312000000), dtEntry, idxSchema)
	}

	// 6. Pipeline validation, terms order validation, script errors, child/sibling evaluation, moving_percentiles, cumulative_cardinality
	for _, badPipeRaw := range []string{
		`{"dh":{"date_histogram":{"field":"dt","fixed_interval":"1d"},"aggs":{"b1":{"bucket_script":{"buckets_path":{"a":"b2.value"},"script":"params.a"}},"b2":{"bucket_script":{"buckets_path":{"b":"b1.value"},"script":"params.b"}}}}}`,
		`{"t":{"terms":{"field":"tag"},"aggs":{"s":{"sum":{"field":"num"}}}},"s2":{"avg_bucket":{"buckets_path":"t"}}}`,
	} {
		ag := mustUnmarshalR67CovSrvAggs(t, badPipeRaw)
		if msg := validatePipelineAggs(ag); msg == "" {
			t.Fatalf("expected validatePipelineAggs error for %s", badPipeRaw)
		}
	}
	badNormAgg := map[string]esast.AggSpec{
		"dh": {
			DateHistogram: &esast.DateHistogramAggSpec{Field: "dt", FixedInterval: "1d"},
			Aggs: map[string]esast.AggSpec{
				"n1":    {Normalize: &esast.NormalizeAggSpec{BucketsPath: "sum_n", Method: "unknown_m"}},
				"sum_n": {Sum: &esast.MetricAggSpec{Field: "num"}},
			},
		},
	}
	if msg := validatePipelineAggs(badNormAgg); msg == "" {
		t.Fatalf("expected validatePipelineAggs error for normalize unknown_m")
	}
	badScriptAgg := map[string]esast.AggSpec{
		"dh": {
			DateHistogram: &esast.DateHistogramAggSpec{Field: "dt", FixedInterval: "1d"},
			Aggs: map[string]esast.AggSpec{
				"bs":    {BucketScript: &esast.BucketSelectorAggSpec{BucketsPath: map[string]string{}}},
				"sum_n": {Sum: &esast.MetricAggSpec{Field: "num"}},
			},
		},
	}
	if msg := validatePipelineAggs(badScriptAgg); msg == "" {
		t.Fatalf("expected validatePipelineAggs error for bucket_script without buckets_path")
	}
	subPipeAggs := mustUnmarshalR67CovSrvAggs(t, `{"tm":{"top_metrics":{"metrics":[{"field":"num"}],"sort":{"num":"desc"}}},"d":{"derivative":{"buckets_path":"tm"}}}`)
	_ = validateChildBucketMetricDep("p", "d", "tm", subPipeAggs)

	badTermsOrd := mustUnmarshalR67CovSrvAggs(t, `{"t":{"terms":{"field":"tag","order":{"tm.bad_metric":"desc"}},"aggs":{"tm":{"top_metrics":{"metrics":[{"field":"num"}],"sort":{"num":"desc"}}}}}}`)
	_, _, _ = validateTermsOrderPathsR65(srv, badTermsOrd)
	tOrdAgg := badTermsOrd["t"]
	_ = topMetricsHasMetricFieldR65(tOrdAgg.SubAggs()["tm"].TopMetrics, "num")
	_ = topMetricsHasMetricFieldR65(nil, "num")

	srcErrAggs := mustUnmarshalR67CovSrvAggs(t, `{"dh":{"date_histogram":{"field":"dt","fixed_interval":"1d"},"aggs":{"s":{"sum":{"field":"num"}},"bs":{"bucket_script":{"buckets_path":{"x":"s"},"script":"params._source.tag"}}}}}`)
	_ = validateTopHitsAndPipelineScriptErrorsR65(srcErrAggs, nil, map[string]any{"dh": map[string]any{"buckets": []map[string]any{{"key": int64(1), "doc_count": int64(1), "s": map[string]any{"value": 1.0}}}}}, docLookup)
	_ = unboundNullParamInBucketScriptR65("params.x + 1", map[string]any{"x": nil})

	_, _ = evalBucketSelectorExprDepth("params.a > 5 && (params.b <= 10 || !(params.a == 0))", map[string]float64{"a": 8, "b": 4}, 0)
	_, _ = evalBucketSelectorExprDepth("params.a > 0", map[string]float64{"a": 1}, 70)
	_, _ = evalBucketArithmeticExprDepth("(params.a + params.b) * 2 - -1 / 1 % 2", map[string]float64{"a": 3, "b": 4}, 0)
	_, _ = evalBucketArithmeticExprDepth("params.a / 0", map[string]float64{"a": 3}, 0)
	_, _ = evalBucketArithmeticExprDepth("params.a", map[string]float64{"a": 3}, 70)

	pipeTree := mustUnmarshalR67CovSrvAggs(t, `{
		"dh":{"date_histogram":{"field":"dt","fixed_interval":"1d"},"aggs":{
			"s":{"sum":{"field":"num"}},
			"ext":{"extended_stats":{"field":"num"}},
			"pct":{"percentiles":{"field":"num","percents":[50]}},
			"d":{"derivative":{"buckets_path":"s"}},
			"cs":{"cumulative_sum":{"buckets_path":"s"}},
			"sd":{"serial_diff":{"buckets_path":"s","lag":1}},
			"ma":{"moving_avg":{"buckets_path":"s","window":2,"model":"simple"}},
			"mf":{"moving_fn":{"buckets_path":"s","window":2,"script":"MovingFunctions.sum(values)"}},
			"mp":{"moving_percentiles":{"buckets_path":"pct","window":2}},
			"bs":{"bucket_script":{"buckets_path":{"x":"s"},"script":"params.x * 2"}},
			"sel":{"bucket_selector":{"buckets_path":{"x":"s"},"script":"params.x > 0"}},
			"norm":{"normalize":{"buckets_path":"s","method":"percent_of_sum"}},
			"bsort":{"bucket_sort":{"sort":[{"_key":"asc"},{"s":"desc"}],"from":0,"size":2,"gap_policy":"insert_zeros"}}
		}},
		"avg_s":{"avg_bucket":{"buckets_path":"dh>s"}},
		"sum_s":{"sum_bucket":{"buckets_path":"dh>bs"}},
		"min_s":{"min_bucket":{"buckets_path":"dh>s"}},
		"max_s":{"max_bucket":{"buckets_path":"dh>s"}},
		"st_s":{"stats_bucket":{"buckets_path":"dh>s"}},
		"est_s":{"extended_stats_bucket":{"buckets_path":"dh>s"}},
		"pct_s":{"percentiles_bucket":{"buckets_path":"dh>s","percents":[50,95]}}
	}`)
	dhBuckets := []map[string]any{
		{"key": int64(1767225600000), "key_as_string": "2026-01-01", "doc_count": int64(2), "s": map[string]any{"value": 10.0}, "ext": map[string]any{"std_deviation_bounds": map[string]any{"upper": 20.0}}, "pct": map[string]any{"values": map[string]any{"50.0": 10.0}}},
		{"key": int64(1767312000000), "key_as_string": "2026-01-02", "doc_count": int64(1), "s": map[string]any{"value": 20.0}, "ext": map[string]any{"std_deviation_bounds": map[string]any{"upper": 30.0}}, "pct": map[string]any{"values": map[string]any{"50.0": 20.0}}},
	}
	dhAgg := pipeTree["dh"]
	dhSub := dhAgg.SubAggs()
	dhBuckets = evaluateChildPipelineAggsWithoutBucketSort(dhBuckets, dhSub)
	evalMovingPercentilesFallbackWithTargetR65(dhBuckets, "mp", dhSub["mp"].MovingPercentiles, dhSub["pct"].Percentiles)
	dhBuckets = evaluateBucketSortPipelineAggs(dhBuckets, dhSub)
	aggsOutPipe := map[string]any{"dh": map[string]any{"buckets": dhBuckets}}
	evaluateSiblingPipelineAggsWithStrict(true, pipeTree, aggsOutPipe)
	_, _ = extractBucketMetricBySegs(dhBuckets[0], []string{"ext", "std_deviation_bounds", "upper"})
	_, _ = extractBucketMetricBySegs(dhBuckets[0], []string{"pct", "50.0"})
	var kvVals []float64
	var kvKeys []string
	collectKeyedValuesFromAggContainerWithZeroPolicy(aggsOutPipe["dh"].(map[string]any), []string{"s"}, true, true, "", &kvVals, &kvKeys)

	cumCardAggs := mustUnmarshalR67CovSrvAggs(t, `{"dh":{"date_histogram":{"field":"dt","fixed_interval":"1d"},"aggs":{"cc":{"cumulative_cardinality":{"buckets_path":"dc"}},"dc":{"cardinality":{"field":"tag"}}}}}`)
	applyTrueCumulativeCardinalityWithHitsR65(cumCardAggs, map[string]any{"dh": map[string]any{"buckets": dhBuckets}}, []HitRow{h1, h2}, idxSchema)

	// 7. synthesizeFixedTZDateHistogramBucketsWithBudgetR67 & synthesizeHistogramBucketsWithBudgetR67
	nyLoc, _ := time.LoadLocation("America/New_York")
	if nyLoc == nil {
		nyLoc = time.FixedZone("EST", -5*3600)
	}
	dhSyntSpec := dhAgg.DateHistogram
	dhSyntRows := []AggRow{
		{AggName: "dh", BucketKey: "1767225600000", DocCount: 1},
		{AggName: "dh", BucketKey: "1767571200000", DocCount: 2},
	}
	_ = synthesizeFixedTZDateHistogramBucketsWithBudgetR67(dhSyntRows, dhSyntSpec, nyLoc, newHistBucketBudgetR67(100))
	_ = synthesizeFixedTZDateHistogramBucketsWithBudgetR67(dhSyntRows, dhSyntSpec, time.UTC, newHistBucketBudgetR67(2))

	hSpecAgg := mustUnmarshalR67CovSrvAggs(t, `{"h":{"histogram":{"field":"num","interval":10,"offset":0,"min_doc_count":0,"hard_bounds":{"min":0,"max":100},"extended_bounds":{"min":0,"max":50}}}}`)
	_ = synthesizeHistogramBucketsWithBudgetR67([]AggRow{{AggName: "h", BucketKey: "0", DocCount: 1}, {AggName: "h", BucketKey: "30", DocCount: 2}}, hSpecAgg["h"].Histogram, newHistBucketBudgetR67(100))
	_ = synthesizeHistogramBucketsWithBudgetR67([]AggRow{{AggName: "h", BucketKey: "0", DocCount: 1}, {AggName: "h", BucketKey: "100", DocCount: 2}}, hSpecAgg["h"].Histogram, newHistBucketBudgetR67(2))

	// 8. Runtime MatrixStats, MultiTerms, FormatRuntimeBucketAggObjectWithSchema, EmitRuntimeAllSubAggRowsWithGlobal
	rtAggTree := mustUnmarshalR67CovSrvAggs(t, `{
		"ms":{"matrix_stats":{"fields":["num","dbl"],"mode":"avg"}},
		"mt":{"multi_terms":{"terms":[{"field":"tag"},{"field":"num","missing":0}]},"aggs":{
			"ch":{"children":{"type":"child"},"aggs":{"c_cnt":{"value_count":{"field":"num"}}}},
			"hist":{"histogram":{"field":"num","interval":10}},
			"dh":{"date_histogram":{"field":"dt","fixed_interval":"1d"}},
			"mt_sub":{"multi_terms":{"terms":[{"field":"grp"},{"field":"flag"}]}}
		}}
	}`)
	mDocs := []runtimeMatchedDoc{
		{hit: h1, doc: doc1Map, rootDoc: doc1Map, rootSchema: idxSchema},
		{hit: h2, doc: doc2Map, rootDoc: doc2Map, rootSchema: idxSchema},
	}
	var rtOutRows []AggRow
	emitRuntimeMatrixStatsAggRowsWithServerWave3R63(srv, "ms", "b1", rtAggTree["ms"].MatrixStats, mDocs, &rtOutRows)
	emitRuntimeMatrixStatsAggRowsWithServerWave3R63(srv, "ms_empty", "b1", rtAggTree["ms"].MatrixStats, nil, &rtOutRows)
	rtMT := rtAggTree["mt"]
	emitRuntimeMultiTermsAggRowsWithOptionsR65("mt", "", rtMT, mDocs, mDocs, &rtOutRows, idxSchema, nil)
	emitRuntimeAllSubAggRowsWithGlobal("p", "b1", rtMT.SubAggs(), mDocs, mDocs, &rtOutRows, idxSchema)
	_ = formatRuntimeBucketAggObjectWithSchema("cov_agg", "mt", "", rtMT, rtOutRows, map[string][]AggRow{"mt": rtOutRows}, docLookup, idxSchema)

	// 9. applySearchRoutingToAliasFilters direct branch check (multi-shard seenCandidates)
	_ = srv.applySearchRoutingToAliasFilters("s_main", []string{"s_main"}, "r1", map[string]*esast.Query{})
}
