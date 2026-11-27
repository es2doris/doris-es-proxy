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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newR67T2PServer(t *testing.T, esVer string) (*Server, *MemoryBackend) {
	t.Helper()
	be := NewMemoryBackend(false)
	srv := NewServer("es_r67t2p", be, transpiler.TranspilerOptions{})
	if esVer != "" {
		srv.SetTargetESVersion(esVer)
	}
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, be
}

func doR67T2PHTTP(t *testing.T, srv *Server, method, path, body string, headers ...[2]string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		hasCT := false
		for _, h := range headers {
			if strings.EqualFold(h[0], "Content-Type") {
				hasCT = true
				break
			}
		}
		if !hasCT {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func mustR67T2PHTTP(t *testing.T, srv *Server, method, path, body string, wantCode int, headers ...[2]string) map[string]any {
	t.Helper()
	rec := doR67T2PHTTP(t, srv, method, path, body, headers...)
	if rec.Code != wantCode {
		t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, rec.Code, wantCode, rec.Body.String())
	}
	if rec.Body.Len() == 0 {
		return nil
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

type r67T2PCustomUnwrapWriter struct {
	http.ResponseWriter
}

func (w *r67T2PCustomUnwrapWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

type r67T2PMarshalFailVal struct{}

func (r67T2PMarshalFailVal) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("r67t2p marshal error")
}

// TestRound67TopUp2Proxy_YAMLWireAndFormat covers features.go YAML serialization branches (L330-486).
func TestRound67TopUp2Proxy_YAMLWireAndFormat(t *testing.T) {
	type customStruct struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	// Build a deeply nested map (> maxYAMLMarshalDepth) to exercise depth fallback.
	deep := map[string]any{"leaf": "v"}
	for i := 0; i < maxYAMLMarshalDepth+2; i++ {
		deep = map[string]any{"n": deep}
	}

	payload := map[string]any{
		"nil_val":         nil,
		"bool_val":        true,
		"num_val":         json.Number("42"),
		"int_val":         7,
		"str_val":         "hello",
		"special:key":     "quoted",
		"empty_map":       map[string]any{},
		"empty_slice":     []any{},
		"empty_map_slice": []map[string]any{},
		"nonempty_map_slice": []map[string]any{
			{},
			{"a": "b", "c": 1},
		},
		"any_slice": []any{
			map[string]any{},
			map[string]any{"k": "v"},
			[]any{},
			[]any{"x", 2},
			[]map[string]any{},
			[]map[string]any{{"m": 1}},
			customStruct{Name: "cs", Count: 3},
			r67T2PMarshalFailVal{},
		},
		"deep": deep,
	}

	yamlBytes := marshalGenericYAMLWireR64(payload)
	yamlStr := string(yamlBytes)
	if !strings.HasPrefix(yamlStr, "---\n") {
		t.Fatalf("expected YAML header, got: %s", yamlStr)
	}
	if !strings.Contains(yamlStr, "nonempty_map_slice:") || !strings.Contains(yamlStr, "\"special:key\":") {
		t.Fatalf("expected nested slice and quoted key in YAML output: %s", yamlStr)
	}

	// Empty top-level slices
	if got := string(marshalGenericYAMLWireR64([]map[string]any{})); got != "---\n[]\n" {
		t.Fatalf("unexpected empty []map YAML: %q", got)
	}
	if got := string(marshalGenericYAMLWireR64([]any{})); got != "---\n[]\n" {
		t.Fatalf("unexpected empty []any YAML: %q", got)
	}

	// extractESResponseFormatOptions across all wrapper types
	baseRec := httptest.NewRecorder()
	fmtW := &esFormatResponseWriter{
		ResponseWriter: baseRec,
		opts:           esResponseFormatOptions{pretty: true, errorTrace: true},
	}
	wrapped := &translogWarningFilterWriterR63{
		ResponseWriter: &headResponseWriterR64{
			ResponseWriter: &gzipResponseWriter{
				ResponseWriter: &r67T2PCustomUnwrapWriter{
					ResponseWriter: fmtW,
				},
			},
		},
	}
	opts, ok := extractESResponseFormatOptions(wrapped)
	if !ok || !opts.pretty || !opts.errorTrace {
		t.Fatalf("expected extracted format options, got ok=%v opts=%+v", ok, opts)
	}
	if _, okNone := extractESResponseFormatOptions(httptest.NewRecorder()); okNone {
		t.Fatal("expected false when no esFormatResponseWriter is wrapped")
	}

	// Exercise HTTP ?format=yaml on _cat/health
	srv, _ := newR67T2PServer(t, "8.15.0")
	rec := doR67T2PHTTP(t, srv, http.MethodGet, "/_cat/health?format=yaml", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "application/yaml") {
		t.Fatalf("expected 200 YAML response, got code=%d ct=%s body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
}

// TestRound67TopUp2Proxy_ResolveClusterAndDynamicRBAC covers features.go L12378-12403, L1451-1600 and round49_features.go L8489-8522.
func TestRound67TopUp2Proxy_ResolveClusterAndDynamicRBAC(t *testing.T) {
	srv, _ := newR67T2PServer(t, "8.15.0")

	// 1. Nested & flat cluster.remote settings + /_resolve/cluster/*
	mustR67T2PHTTP(t, srv, http.MethodPut, "/_cluster/settings", `{
		"persistent": {
			"cluster": {
				"remote": {
					"rem_a": {"skip_unavailable": true, "connected": false},
					"rem_b": {"skip_unavailable": "true"},
					"rem_drop": null,
					"rem_nil_seeds": {"seeds": null}
				}
			}
		},
		"transient": {
			"cluster.remote.rem_flat.seeds": null,
			"cluster.remote.rem_c.skip_unavailable": "true"
		}
	}`, http.StatusOK)

	res := mustR67T2PHTTP(t, srv, http.MethodGet, "/_resolve/cluster/*:*", "", http.StatusOK)
	if res["rem_a"] == nil || res["rem_b"] == nil || res["rem_c"] == nil {
		t.Fatalf("expected rem_a, rem_b, rem_c in resolve cluster response, got %+v", res)
	}
	if _, hasDrop := res["rem_drop"]; hasDrop {
		t.Fatalf("expected rem_drop to be deleted, got %+v", res["rem_drop"])
	}
	if _, hasNilSeeds := res["rem_nil_seeds"]; hasNilSeeds {
		t.Fatalf("expected rem_nil_seeds to be deleted, got %+v", res["rem_nil_seeds"])
	}

	// 2. resolveRBACTargetsLockedR67
	indices := map[string]*schema.IndexSchema{
		"logs-1":    {},
		"logs-2":    {},
		"metrics-1": {},
	}
	aliases := map[string][]string{
		"logs_alias": {"logs-1", "logs-2"},
	}
	gotAll := resolveRBACTargetsLockedR67(indices, aliases, "*")
	if len(gotAll) != 3 {
		t.Fatalf("expected 3 targets for *, got %v", gotAll)
	}
	gotMix := resolveRBACTargetsLockedR67(indices, aliases, " , -logs-2, logs_*, logs_alias, plain_idx, _all ")
	if len(gotMix) < 4 {
		t.Fatalf("expected wildcard/alias/all targets, got %v", gotMix)
	}
	gotDirect := resolveRBACTargetsLockedR67(indices, aliases, "logs_alias")
	if len(gotDirect) != 2 {
		t.Fatalf("expected 2 targets for logs_alias, got %v", gotDirect)
	}

	// 3. Dynamic RBAC & principal helpers (round49_features.go L8488-8526, features.go L1486-1600)
	if !isDynamicRBACSelfAllowedPathR67(http.MethodGet, "/_security/_authenticate") ||
		!isDynamicRBACSelfAllowedPathR67(http.MethodPost, "/_security/user/_has_privileges") ||
		!isDynamicRBACSelfAllowedPathR67(http.MethodGet, "/_security/user/_privileges") ||
		!isDynamicRBACSelfAllowedPathR67(http.MethodPost, "/_security/api_key") ||
		!isDynamicRBACSelfAllowedPathR67(http.MethodGet, "/idx/_terms_enum") ||
		!isDynamicRBACSelfAllowedPathR67(http.MethodPost, "/_monitoring/bulk") ||
		isDynamicRBACSelfAllowedPathR67(http.MethodGet, "/_cluster/settings") {
		t.Fatal("unexpected result from isDynamicRBACSelfAllowedPathR67")
	}

	mustR67T2PHTTP(t, srv, http.MethodPut, "/logs-1", `{}`, http.StatusOK)

	srv.mu.Lock()
	srv.securityRoles["reader_role"] = map[string]any{
		"cluster": []any{"monitor"},
		"run_as":  []any{"svc_*"},
		"indices": []any{
			map[string]any{
				"names":      []any{"logs-*"},
				"privileges": []any{"read"},
			},
		},
	}
	srv.securityRoles["super_role"] = map[string]any{
		"cluster": []any{"all"},
	}
	srv.mu.Unlock()

	readerP := &securityPrincipalR67{username: "alice", roles: []string{"reader_role"}}
	noRoleP := &securityPrincipalR67{username: "bob", roles: nil}
	superP := &securityPrincipalR67{username: "admin", roles: []string{"superuser", "super_role"}}
	staticP := &securityPrincipalR67{username: "elastic", isStaticAdmin: true}

	srv.mu.RLock()
	if !srv.principalHasClusterPrivLockedR67(staticP, "manage") ||
		!srv.principalHasClusterPrivLockedR67(superP, "manage") ||
		!srv.principalHasClusterPrivLockedR67(readerP, "monitor") ||
		srv.principalHasClusterPrivLockedR67(readerP, "manage") ||
		srv.principalHasClusterPrivLockedR67(nil, "monitor") {
		srv.mu.RUnlock()
		t.Fatal("unexpected principalHasClusterPrivLockedR67 result")
	}
	if !srv.principalRunAsAllowedLockedR67(staticP, "anyone") ||
		!srv.principalRunAsAllowedLockedR67(superP, "anyone") ||
		!srv.principalRunAsAllowedLockedR67(readerP, "svc_worker") ||
		srv.principalRunAsAllowedLockedR67(readerP, "other") ||
		srv.principalRunAsAllowedLockedR67(nil, "anyone") {
		srv.mu.RUnlock()
		t.Fatal("unexpected principalRunAsAllowedLockedR67 result")
	}
	srv.mu.RUnlock()

	// checkDynamicRBACR67 HTTP enforcement branches
	if !srv.checkDynamicRBACR67(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_security/_authenticate", nil), readerP) {
		t.Fatal("expected self-allowed path to pass")
	}
	recNoRole := httptest.NewRecorder()
	if srv.checkDynamicRBACR67(recNoRole, httptest.NewRequest(http.MethodGet, "/logs-1/_search", nil), noRoleP) || recNoRole.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for no-role user, got code=%d", recNoRole.Code)
	}
	recDenyPostCluster := httptest.NewRecorder()
	if srv.checkDynamicRBACR67(recDenyPostCluster, httptest.NewRequest(http.MethodPost, "/_cluster/reroute", nil), readerP) || recDenyPostCluster.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for POST /_cluster/reroute by monitor role, got code=%d", recDenyPostCluster.Code)
	}
	recAllowGetCluster := httptest.NewRecorder()
	if !srv.checkDynamicRBACR67(recAllowGetCluster, httptest.NewRequest(http.MethodGet, "/_cluster/settings", nil), readerP) {
		t.Fatal("expected GET /_cluster/settings allowed for monitor role")
	}
	recAllowSearch := httptest.NewRecorder()
	if !srv.checkDynamicRBACR67(recAllowSearch, httptest.NewRequest(http.MethodPost, "/_search", nil), readerP) {
		t.Fatal("expected POST /_search allowed for reader role")
	}
	// Role with no read index privilege -> 403 on /_search
	srv.mu.Lock()
	srv.securityRoles["empty_priv_role"] = map[string]any{"cluster": []string{}}
	srv.mu.Unlock()
	emptyPrivP := &securityPrincipalR67{username: "carol", roles: []string{"empty_priv_role"}}
	recDenySearch := httptest.NewRecorder()
	if srv.checkDynamicRBACR67(recDenySearch, httptest.NewRequest(http.MethodPost, "/_search", nil), emptyPrivP) || recDenySearch.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on /_search for empty_priv_role, got code=%d", recDenySearch.Code)
	}
}

// TestRound67TopUp2Proxy_ReindexAutoCreateAndErrors covers features.go L13728-13782.
func TestRound67TopUp2Proxy_ReindexAutoCreateAndErrors(t *testing.T) {
	srv, _ := newR67T2PServer(t, "8.15.0")

	mustR67T2PHTTP(t, srv, http.MethodPut, "/ridx_src", `{
		"mappings": {"properties": {"name": {"type": "keyword"}, "val": {"type": "integer"}}}
	}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ridx_src/_doc/1?refresh=true", `{"name":"a","val":1}`, http.StatusCreated)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ridx_src/_doc/2?refresh=true", `{"name":"b","val":2}`, http.StatusCreated)

	// 1. Reindex with script setting ctx.op = "noop" hits len(prepared)==0 branch
	noopResp := mustR67T2PHTTP(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "ridx_src", "size": 1},
		"dest": {"index": "ridx_noop_dest"},
		"script": {"source": "ctx.op = 'noop'"}
	}`, http.StatusOK)
	if noops, _ := toInt64(noopResp["noops"]); noops != 2 {
		t.Fatalf("expected 2 noops, got %v", noopResp["noops"])
	}

	// 2. Reindex into non-existent data stream with op_type != create -> 400
	mustR67T2PHTTP(t, srv, http.MethodPut, "/_index_template/r67_ds_tpl", `{
		"index_patterns": ["r67_ds_*"],
		"data_stream": {},
		"priority": 500
	}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_reindex", `{
		"source": {"index": "ridx_src"},
		"dest": {"index": "r67_ds_auto"}
	}`, http.StatusBadRequest)

	// 3. Reindex into closed / write-blocked / alias destination -> exercises destAlreadyExisted==false branch
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ridx_write_real", `{}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_aliases", `{
		"actions": [{"add": {"index": "ridx_write_real", "alias": "ridx_write_alias", "is_write_index": true}}]
	}`, http.StatusOK)
	okAliasReindex := mustR67T2PHTTP(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "ridx_src"},
		"dest": {"index": "ridx_write_alias"}
	}`, http.StatusOK)
	if created, _ := toInt64(okAliasReindex["created"]); created != 2 {
		t.Fatalf("expected 2 created via write alias, got %+v", okAliasReindex)
	}

	// 4. Reindex into closed dest resolved via template/alias
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ridx_closed_real", `{}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/ridx_closed_real/_close", `{}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_reindex", `{
		"source": {"index": "ridx_src"},
		"dest": {"index": "ridx_closed_real"}
	}`, http.StatusBadRequest)
}

// TestRound67TopUp2Proxy_TSDBBulkSingleDocAndCreateValidation covers server.go L4771-4791, L5695-5735, L9794-9838.
func TestRound67TopUp2Proxy_TSDBBulkSingleDocAndCreateValidation(t *testing.T) {
	srv, _ := newR67T2PServer(t, "8.15.0")

	// 1. Create time_series index validation errors (server.go L4771-4798)
	// Runtime field matching routing_path
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ts_bad_rt", `{
		"settings": {
			"index.mode": "time_series",
			"index.routing_path": ["host"]
		},
		"mappings": {
			"runtime": {
				"host": {"type": "keyword", "script": {"source": "emit('h1')"}}
			},
			"properties": {
				"@timestamp": {"type": "date"}
			}
		}
	}`, http.StatusBadRequest)

	// Alias with routing on time_series index
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ts_bad_alias", `{
		"settings": {
			"index.mode": "time_series",
			"index.routing_path": ["host"]
		},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"host": {"type": "keyword", "time_series_dimension": true}
			}
		},
		"aliases": {
			"ts_bad_al": {"routing": "r1"}
		}
	}`, http.StatusBadRequest)

	// 2. Auto-create time_series index on single-doc POST (hits server.go L5691-5738 idxSchema == nil branch)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/_index_template/r67_ts_auto_tpl", `{
		"index_patterns": ["ts_auto_*"],
		"priority": 400,
		"template": {
			"settings": {
				"index.mode": "time_series",
				"index.routing_path": ["host"]
			},
			"mappings": {
				"properties": {
					"@timestamp": {"type": "date"},
					"host": {"type": "keyword", "time_series_dimension": true},
					"cpu": {"type": "double", "time_series_metric": "gauge"}
				}
			}
		}
	}`, http.StatusOK)

	// Missing routing_path dimension triggers prepareTSDBDocWriteR61CRUD error
	mustR67T2PHTTP(t, srv, http.MethodPost, "/ts_auto_1/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","cpu":0.5}`, http.StatusBadRequest)

	// Valid TSDB auto-create write
	mustR67T2PHTTP(t, srv, http.MethodPost, "/ts_auto_2/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","cpu":0.5}`, http.StatusCreated)

	// Auto-create data stream with failure_store + strict mapping error (hits server.go L5695-5701)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/_index_template/r67_fs_tpl", `{
		"index_patterns": ["fs_auto_*"],
		"priority": 500,
		"data_stream": {"failure_store": {"enabled": true}},
		"template": {
			"mappings": {
				"dynamic": "strict",
				"properties": {
					"@timestamp": {"type": "date"}
				}
			}
		}
	}`, http.StatusOK)
	fsResp := mustR67T2PHTTP(t, srv, http.MethodPost, "/fs_auto_logs/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","unmapped_field":"boom"}`, http.StatusCreated)
	if fsResp["_index"] == nil {
		t.Fatalf("expected failure store redirect response, got %+v", fsResp)
	}

	// 3. Bulk writes on time_series index (hits server.go L9794-9840)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ts_bulk_idx", `{
		"settings": {
			"index.mode": "time_series",
			"index.routing_path": ["host"]
		},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"host": {"type": "keyword", "time_series_dimension": true},
				"cpu": {"type": "double", "time_series_metric": "gauge"}
			}
		}
	}`, http.StatusOK)

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"ts_bulk_idx"}}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","cpu":1.1}`,
		`{"create":{"_index":"ts_bulk_idx","_id":"explicit_ts_id"}}`,
		`{"@timestamp":"2026-01-01T00:00:01Z","host":"h2","cpu":2.2}`,
		`{"index":{"_index":"ts_bulk_idx"}}`,
		`{"@timestamp":"2026-01-01T00:00:02Z","cpu":3.3}`,
		``,
	}, "\n")
	bulkRes1 := mustR67T2PHTTP(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody, http.StatusOK)
	if errs, _ := bulkRes1["errors"].(bool); !errs {
		t.Fatalf("expected bulk errors=true due to missing host dimension on 3rd item, got %+v", bulkRes1)
	}

	// Second bulk with duplicate create on same TSDB doc -> hits GetDocByID + 409 version_conflict_engine_exception
	bulkDup := strings.Join([]string{
		`{"create":{"_index":"ts_bulk_idx"}}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","cpu":1.1}`,
		`{"index":{"_index":"ts_bulk_idx"}}`,
		`{"@timestamp":"2026-01-01T00:00:03Z","host":"h3","cpu":{"nested":1}}`,
		``,
	}, "\n")
	bulkRes2 := mustR67T2PHTTP(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkDup, http.StatusOK)
	if errs, _ := bulkRes2["errors"].(bool); !errs {
		t.Fatalf("expected bulk errors=true for TSDB duplicate create & mapping error, got %+v", bulkRes2)
	}
}

// TestRound67TopUp2Proxy_PutMappingAndAutoCreateEvolution covers round61_server_crud_indices.go L2062-2114 and L4151-4250.
func TestRound67TopUp2Proxy_PutMappingAndAutoCreateEvolution(t *testing.T) {
	srv, _ := newR67T2PServer(t, "8.15.0")

	// Create TSDB index for _mapping validation branches
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ts_map_val", `{
		"settings": {
			"index.mode": "time_series",
			"index.routing_path": ["host"]
		},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"host": {"type": "keyword", "time_series_dimension": true},
				"metric_a": {"type": "long", "time_series_metric": "gauge"}
			}
		}
	}`, http.StatusOK)

	// Runtime field matching routing_path -> 400
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ts_map_val/_mapping", `{
		"runtime": {"host": {"type": "keyword", "script": {"source": "emit('x')"}}}
	}`, http.StatusBadRequest)

	// Runtime field shadowing existing metric -> 400
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ts_map_val/_mapping", `{
		"runtime": {"metric_a": {"type": "long", "script": {"source": "emit(1)"}}}
	}`, http.StatusBadRequest)

	// Adding routing: {required: true} on TSDB index -> 400
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ts_map_val/_mapping", `{
		"routing": {"required": true}
	}`, http.StatusBadRequest)

	// Invalid TSDB mapping (nested dimension and synthetic text field) -> 400
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ts_map_val/_mapping", `{
		"properties": {"bad_nested": {"type": "nested", "time_series_dimension": true, "properties": {"x": {"type": "keyword"}}}}
	}`, http.StatusBadRequest)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/ts_map_val/_mapping", `{
		"properties": {"bad_dim": {"type": "text", "synthetic_source_keep": "none"}}
	}`, http.StatusBadRequest)

	// Synthetic source validation error on normal index
	mustR67T2PHTTP(t, srv, http.MethodPut, "/norm_syn_val", `{
		"mappings": {"_source": {"mode": "synthetic"}, "properties": {"k": {"type": "keyword"}}}
	}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/norm_syn_val/_mapping", `{
		"properties": {"bad_sub": {"type": "text", "fields": {"sub": {"type": "keyword", "synthetic_source_keep": "none"}}}}
	}`, http.StatusBadRequest)

	// Legacy template (ES7 mode) + empty index evolution + array promotion (L4151-4250)
	srv7, _ := newR67T2PServer(t, "")
	mustR67T2PHTTP(t, srv7, http.MethodPut, "/_template/r67_legacy_tpl?include_type_name=true", `{
		"index_patterns": ["leg_ts_*"],
		"settings": {
			"index.mode": "time_series",
			"index.routing_path": ["host"]
		},
		"mappings": {
			"custom_type": {
				"properties": {
					"@timestamp": {"type": "date"},
					"host": {"type": "keyword", "time_series_dimension": true},
					"val": {"type": "long", "time_series_metric": "gauge"}
				}
			}
		}
	}`, http.StatusOK)
	mustR67T2PHTTP(t, srv7, http.MethodPost, "/leg_ts_1/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","val":5}`, http.StatusCreated)

	// Empty index created with no fields, then evolved via sample doc with array field
	mustR67T2PHTTP(t, srv7, http.MethodPut, "/empty_evolve_idx", `{}`, http.StatusOK)
	mustR67T2PHTTP(t, srv7, http.MethodPost, "/empty_evolve_idx/_doc?refresh=true", `{"tags":["a","b"],"nums":[1,2]}`, http.StatusCreated)
}

// TestRound67TopUp2Proxy_RuntimeFieldsCoercionAndSorting covers server.go L26432-26487, L13796-13823, L19329-19398.
func TestRound67TopUp2Proxy_RuntimeFieldsCoercionAndSorting(t *testing.T) {
	srv, _ := newR67T2PServer(t, "8.15.0")

	idxSchema := schema.CompileIndexSchema("es_r67t2p", "rt_coerce_idx", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"name": {Type: "keyword"},
		},
	})
	rtMappings := map[string]esast.FieldProperty{
		"ul_emit": {
			Type:   "unsigned_long",
			Script: map[string]any{"source": "emit(9223372036854775807L)"},
		},
		"ul_str_big": {
			Type:   "unsigned_long",
			Script: map[string]any{"source": "return '18446744073709551614'"},
		},
		"ul_str_signed": {
			Type:   "unsigned_long",
			Script: map[string]any{"source": "return '42'"},
		},
		"ul_float_big": {
			Type:   "unsigned_long",
			Script: map[string]any{"source": "return 1e19"},
		},
		"ul_float_small": {
			Type:   "unsigned_long",
			Script: map[string]any{"source": "return 123.0"},
		},
		"ul_int": {
			Type:   "unsigned_long",
			Script: map[string]any{"source": "return 7"},
		},
		"long_rt": {
			Type:   "long",
			Script: map[string]any{"source": "return 99.0"},
		},
		"dbl_rt": {
			Type:   "double",
			Script: map[string]any{"source": "return 3.5"},
		},
		"bool_rt": {
			Type:   "boolean",
			Script: map[string]any{"source": "return 'true'"},
		},
	}
	hits := []HitRow{
		{ID: "1", Index: "rt_coerce_idx", Version: 1, Source: json.RawMessage(`{"name":"alice"}`)},
	}
	srv.evalRuntimeMappingsOnHitRows(idxSchema, rtMappings, hits)
	var rtOut map[string]any
	if err := json.Unmarshal(hits[0].RawSource, &rtOut); err != nil {
		t.Fatalf("failed to unmarshal runtime-enriched RawSource %q: %v", string(hits[0].RawSource), err)
	}
	if rtOut["long_rt"] == nil || rtOut["dbl_rt"] == nil || rtOut["bool_rt"] != true {
		t.Fatalf("expected runtime fields evaluated in RawSource, got %+v", rtOut)
	}

	// compareHitRowsBySortWithSchemas branches (L13796-13825)
	a := HitRow{ID: "a", Source: json.RawMessage(`{"ver":"1.2.0","ip":"10.0.0.1"}`)}
	b := HitRow{ID: "b", Source: json.RawMessage(`{"ver":"1.10.0","ip":"10.0.0.2"}`)}
	missing := HitRow{ID: "m", Source: json.RawMessage(`{}`)}

	if cmp := compareHitRowsBySortWithSchemas(missing, a, []esast.SortSpec{{Entry: esast.SortFieldSpec{Field: "ver", Missing: "_first"}}}, nil, nil); cmp >= 0 {
		t.Fatalf("expected missing _first < a, got %d", cmp)
	}
	if cmp := compareHitRowsBySortWithSchemas(a, missing, []esast.SortSpec{{Entry: esast.SortFieldSpec{Field: "ver", Missing: "_first"}}}, nil, nil); cmp <= 0 {
		t.Fatalf("expected a > missing _first, got %d", cmp)
	}
	if cmp := compareHitRowsBySortWithSchemas(a, b, []esast.SortSpec{{Entry: esast.SortFieldSpec{Field: "ver", Type: "version", Order: "desc"}}}, nil, nil); cmp <= 0 {
		t.Fatalf("expected 1.2.0 after 1.10.0 in desc semver sort, got %d", cmp)
	}
	if cmp := compareHitRowsBySortWithSchemas(a, b, []esast.SortSpec{{Entry: esast.SortFieldSpec{Field: "ip"}}}, nil, nil); cmp >= 0 {
		t.Fatalf("expected 10.0.0.1 < 10.0.0.2, got %d", cmp)
	}

	// evaluateBucketSortPipelineAggs branches (L19329-19398)
	bucketsMapKey := []map[string]any{
		{"key": map[string]any{"b": "z", "a": 2}, "doc_count": int64(2), "m": map[string]any{"value": 10.0}},
		{"key": map[string]any{"b": "a", "a": 1}, "doc_count": int64(1), "m": map[string]any{"value": 5.0}},
		{"key": map[string]any{"b": "c", "a": 3}, "doc_count": int64(3)},
	}
	sortedSubKey := evaluateBucketSortPipelineAggs(bucketsMapKey, map[string]esast.AggSpec{
		"bs": {BucketSort: &esast.BucketSortAggSpec{
			Sort: esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_key.b", Order: "asc"}}},
		}},
	})
	if len(sortedSubKey) != 3 {
		t.Fatalf("expected 3 buckets sorted by _key.b, got %d", len(sortedSubKey))
	}
	sortedFullKey := evaluateBucketSortPipelineAggs(bucketsMapKey, map[string]esast.AggSpec{
		"bs": {BucketSort: &esast.BucketSortAggSpec{
			Sort: esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "_key", Order: "desc"}}},
		}},
	})
	if len(sortedFullKey) != 3 {
		t.Fatalf("expected 3 buckets sorted by _key map, got %d", len(sortedFullKey))
	}
	sortedMissing := evaluateBucketSortPipelineAggs(bucketsMapKey, map[string]esast.AggSpec{
		"bs": {BucketSort: &esast.BucketSortAggSpec{
			GapPolicy: "insert_zeros",
			Sort:      esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "m", Missing: "7"}}},
		}},
	})
	if len(sortedMissing) != 3 {
		t.Fatalf("expected 3 buckets with gap_policy/missing, got %d", len(sortedMissing))
	}
	bucketsMissingFirst := []map[string]any{
		{"key": "k1", "doc_count": int64(1), "lbl": "z"},
		{"key": "k2", "doc_count": int64(1), "lbl": "a"},
	}
	sortedLbl := evaluateBucketSortPipelineAggs(bucketsMissingFirst, map[string]esast.AggSpec{
		"bs": {BucketSort: &esast.BucketSortAggSpec{
			GapPolicy: "insert_zeros",
			Sort:      esast.SortSlice{{Entry: esast.SortFieldSpec{Field: "lbl", Missing: "_first", Order: "desc"}}},
		}},
	})
	if sortedLbl[0]["key"] != "k1" {
		t.Fatalf("expected k1 first on desc lbl sort, got %+v", sortedLbl[0])
	}
}

// TestRound67TopUp2Proxy_TermsLookupAndSearchValidation covers server.go L12019-12041, L13342-13361,
// round62_search_aggs_runtime.go L8981-9044, and round61_server_search.go L2707-2727, L4786-4812, L5423-5444.
func TestRound67TopUp2Proxy_TermsLookupAndSearchValidation(t *testing.T) {
	srv, _ := newR67T2PServer(t, "8.15.0")

	// Setup lookup doc for terms lookup resolution
	mustR67T2PHTTP(t, srv, http.MethodPut, "/tl_lookup", `{}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/tl_lookup/_doc/ref1?refresh=true", `{"ids":["u1","u2"]}`, http.StatusCreated)

	// 1. resolveTermsLookupsInAggSpec covering adjacency_matrix, top_hits, top_metrics, composite, filters, aggs & aggregations
	tlAggJSON := `{
		"aggs": {
			"adj": {
				"adjacency_matrix": {
					"filters": {
						"grpA": {"terms": {"user": {"index": "tl_lookup", "id": "ref1", "path": "ids"}}}
					}
				}
			},
			"comp": {
				"composite": {
					"sources": [{"u": {"terms": {"field": "user"}}}]
				},
				"aggs": {
					"th": {
						"top_hits": {
							"sort": [{"nested_f.v": {"nested": {"path": "nested_f", "filter": {"terms": {"nested_f.k": {"index": "tl_lookup", "id": "ref1", "path": "ids"}}}}}}],
							"highlight": {
								"highlight_query": {"terms": {"user": {"index": "tl_lookup", "id": "ref1", "path": "ids"}}},
								"fields": {
									"body": {"highlight_query": {"terms": {"user": {"index": "tl_lookup", "id": "ref1", "path": "ids"}}}}
								}
							}
						}
					},
					"tm": {
						"top_metrics": {
							"metrics": {"field": "score"},
							"sort": [{"nested_f.v": {"nested": {"path": "nested_f", "filter": {"terms": {"nested_f.k": {"index": "tl_lookup", "id": "ref1", "path": "ids"}}}}}}]
						}
					}
				}
			}
		},
		"aggregations": {
			"flt": {
				"filters": {
					"filters": [{"terms": {"user": {"index": "tl_lookup", "id": "ref1", "path": "ids"}}}]
				}
			}
		}
	}`
	var tlReq esast.SearchRequest
	if err := json.Unmarshal([]byte(tlAggJSON), &tlReq); err != nil {
		t.Fatalf("unmarshal tlReq: %v", err)
	}
	resolvedReq := srv.resolveTermsLookupsInSearchRequest(context.Background(), &tlReq)
	if resolvedReq == nil || len(resolvedReq.Aggs["adj"].AdjacencyMatrix.Filters["grpA"].Terms.Fields["user"]) != 2 {
		t.Fatalf("expected adjacency_matrix terms lookup resolved, got %+v", resolvedReq.Aggs["adj"])
	}

	// 2. script_fields error & script_score custom score validation with size=0 (server.go L12019-12041)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/sv_idx", `{
		"mappings": {
			"properties": {
				"name": {"type": "keyword"},
				"score_v": {"type": "double"},
				"items": {
					"type": "nested",
					"properties": {
						"tag": {"type": "keyword"},
						"title": {"type": "token_count", "analyzer": "standard"},
						"const_tag": {"type": "constant_keyword", "value": "fixed_val"}
					}
				}
			}
		}
	}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/sv_idx/_doc/1?refresh=true", `{
		"name": "d1",
		"score_v": -5.0,
		"items": [{"tag": "t1", "title": "hello world three words"}]
	}`, http.StatusCreated)

	// script_fields runtime error -> 400
	mustR67T2PHTTP(t, srv, http.MethodPost, "/sv_idx/_search", `{
		"script_fields": {"bad": {"script": {"source": "1 / 0"}}}
	}`, http.StatusBadRequest)

	// script_score returning negative score with size: 0 -> 400 via validateCustomSearchScoresOnSQLHitsRound59
	mustR67T2PHTTP(t, srv, http.MethodPost, "/sv_idx/_search", `{
		"size": 0,
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"script": {"source": "doc['score_v'].value"}
			}
		}
	}`, http.StatusBadRequest)

	// Nested top_hits with _routing, version, seq_no_primary_term, _source includes, and nested fields token_count/constant_keyword
	nestedRes := mustR67T2PHTTP(t, srv, http.MethodPost, "/sv_idx/_search", `{
		"size": 0,
		"aggs": {
			"by_items": {
				"nested": {"path": "items"},
				"aggs": {
					"th": {
						"top_hits": {
							"size": 1,
							"version": true,
							"seq_no_primary_term": true,
							"_source": {"includes": ["items.tag"]},
							"fields": ["items.title", "items.const_tag"]
						}
					}
				}
			}
		}
	}`, http.StatusOK)
	if nestedRes["aggregations"] == nil {
		t.Fatalf("expected nested aggregations response, got %+v", nestedRes)
	}

	// 3. validateRemovedES8SearchConstructsR65 across all query branches (round62_search_aggs_runtime.go L8963-9084)
	badCases := []string{
		`{"query":{"common":{"body":{"query":"foo"}}}}`,
		`{"query":{"match":{"body":{"query":"foo","cutoff_frequency":0.1}}}}`,
		`{"query":{"multi_match":{"query":"foo","fields":["body"],"cutoff_frequency":0.1}}}`,
		`{"query":{"constant_score":{"filter":{"common":{"body":{"query":"foo"}}}}}}`,
		`{"query":{"boosting":{"positive":{"match_all":{}},"negative":{"common":{"body":{"query":"foo"}}},"negative_boost":0.2}}}`,
		`{"query":{"dis_max":{"queries":[{"common":{"body":{"query":"foo"}}}]}}}`,
		`{"query":{"function_score":{"query":{"match_all":{}},"functions":[{"filter":{"common":{"body":{"query":"foo"}}},"weight":2}]}}}`,
		`{"query":{"script_score":{"query":{"common":{"body":{"query":"foo"}}},"script":{"source":"1"}}}}`,
		`{"query":{"nested":{"path":"items","query":{"common":{"items.tag":{"query":"foo"}}}}}}`,
		`{"query":{"has_child":{"type":"c","query":{"common":{"body":{"query":"foo"}}}}}}`,
		`{"query":{"has_parent":{"parent_type":"p","query":{"common":{"body":{"query":"foo"}}}}}}`,
		`{"query":{"pinned":{"ids":["1"],"organic":{"common":{"body":{"query":"foo"}}}}}}`,
		`{"query":{"wrapper":{"query":"` + base64.StdEncoding.EncodeToString([]byte(`{"common":{"body":{"query":"foo"}}}`)) + `"}}}` + ``,
		`{"query":{"bool":{"must":[{"common":{"body":{"query":"foo"}}}]}}}`,
		`{"post_filter":{"common":{"body":{"query":"foo"}}}}`,
		`{"aggs":{"f":{"filter":{"match_all":{}},"aggs":{"ma":{"moving_avg":{"buckets_path":"x"}}}}}}`,
	}
	for i, raw := range badCases {
		var req esast.SearchRequest
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			t.Fatalf("case %d unmarshal failed: %v", i, err)
		}
		st, et, _ := validateRemovedES8SearchConstructsR65(&req)
		if st != http.StatusBadRequest || et != "parsing_exception" {
			t.Fatalf("case %d expected 400 parsing_exception, got st=%d et=%s", i, st, et)
		}
	}

	// 4. evalMovingFnWindowR61Search edge branches (round61_server_search.go L4721-4813)
	if v, err := evalMovingFnWindowR61Search([]float64{1, 2}, &esast.MovingAvgAggSpec{Script: "if (values.length > 10) { return 5.0; }"}); err != nil || v != 0.0 {
		t.Fatalf("expected 0.0 for if-without-else nil, got v=%v err=%v", v, err)
	}
	if v, err := evalMovingFnWindowR61Search([]float64{1, 2}, &esast.MovingAvgAggSpec{Script: "if (values.length > 0) { return null; }"}); err != nil || v != nil {
		t.Fatalf("expected nil for explicit return null, got v=%v err=%v", v, err)
	}
	if v, err := evalMovingFnWindowR61Search([]float64{1, 2}, &esast.MovingAvgAggSpec{Script: "Double.NaN"}); err != nil || v != nil {
		t.Fatalf("expected nil for NaN, got v=%v err=%v", v, err)
	}
	if v, err := evalMovingFnWindowR61Search([]float64{1, 2}, &esast.MovingAvgAggSpec{Script: "return 3;"}); err != nil || v != 3.0 {
		t.Fatalf("expected 3.0 for int return, got v=%v err=%v", v, err)
	}
	_, _ = evalMovingFnWindowR61Search([]float64{1}, &esast.MovingAvgAggSpec{Script: "MovingFunctions.unweightedAvg([])"})
	if _, err := evalMovingFnWindowR61Search([]float64{1}, &esast.MovingAvgAggSpec{Script: `Integer.parseInt("bad")`}); err == nil {
		t.Fatal("expected error for invalid moving_fn script")
	}
}

// TestRound67TopUp2Proxy_AdminMLSecurityConnectorILM covers round56_features.go L2167-2196, L2882-2931,
// round49_features.go L9888-9911, L10951-10987, round63_modules_ingest.go L1728-1754,
// round62_admin_features.go L591-612, round61_admin_cat_stats.go L4213-4250,
// round60_features.go L3046-3084, L3463-3478, round48_features.go L4616-4652, L4820-4862, L4951-4976.
func TestRound67TopUp2Proxy_AdminMLSecurityConnectorILM(t *testing.T) {
	srv, _ := newR67T2PServer(t, "8.15.0")

	// 1. ML model snapshot upgrade stats (round56_features.go L2165-2215)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/_ml/anomaly_detectors/job_r67", `{
		"analysis_config": {"bucket_span": "1h", "detectors": [{"function": "count"}]},
		"data_description": {"time_field": "@timestamp"}
	}`, http.StatusOK)
	srv.mu.Lock()
	srv.mlJobs["job_r67"]["_snapshots"] = map[string]any{
		"snap1": map[string]any{"snapshot_id": "snap1"},
	}
	srv.mu.Unlock()

	mustR67T2PHTTP(t, srv, http.MethodPost, "/_ml/anomaly_detectors/job_r67/model_snapshots/snap1/_upgrade/_stats", `{}`, http.StatusMethodNotAllowed)
	mustR67T2PHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/missing_job/model_snapshots/snap1/_upgrade/_stats", "", http.StatusNotFound)
	mustR67T2PHTTP(t, srv, http.MethodHead, "/_ml/anomaly_detectors/missing_job/model_snapshots/snap1/_upgrade/_stats", "", http.StatusNotFound)
	mustR67T2PHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job_r67/model_snapshots/missing_snap/_upgrade/_stats", "", http.StatusNotFound)
	mustR67T2PHTTP(t, srv, http.MethodHead, "/_ml/anomaly_detectors/job_r67/model_snapshots/missing_snap/_upgrade/_stats", "", http.StatusNotFound)
	mustR67T2PHTTP(t, srv, http.MethodHead, "/_ml/anomaly_detectors/job_r67/model_snapshots/snap1/_upgrade/_stats", "", http.StatusOK)
	upStats := mustR67T2PHTTP(t, srv, http.MethodGet, "/_ml/anomaly_detectors/job_r67/model_snapshots/snap1/_upgrade/_stats", "", http.StatusOK)
	if count, _ := toInt64(upStats["count"]); count != 1 {
		t.Fatalf("expected count=1, got %+v", upStats)
	}

	// 2. Security profile normalize & _has_privileges (round56_features.go L2880-2965)
	normNil := normalizeSecurityUserProfileR66("u_nil", nil)
	if normNil["uid"] != "u_nil" || normNil["_doc"] == nil {
		t.Fatalf("unexpected normalized nil profile: %+v", normNil)
	}
	mustR67T2PHTTP(t, srv, http.MethodDelete, "/_security/profile/_has_privileges", "", http.StatusMethodNotAllowed)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/profile/_has_privileges", `{bad`, http.StatusBadRequest)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/profile/_has_privileges", `{"uids":["u1","u2"]}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/profile/_has_privileges", `{"uids":"u1,u2"}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/profile/_has_privileges", `{"uid":"u1"}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodGet, "/_security/profile/_has_privileges?uids=u1,u2", "", http.StatusOK)

	// 3. Connector secrets (round49_features.go L10950-11005)
	mustR67T2PHTTP(t, srv, http.MethodGet, "/_connector/_secret", "", http.StatusMethodNotAllowed)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_connector/_secret", `{}`, http.StatusBadRequest)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_connector/_secret", `{"id":"__secrets__","value":"s1"}`, http.StatusBadRequest)
	secRes := mustR67T2PHTTP(t, srv, http.MethodPost, "/_connector/_secret", `{"name":"my_secret","value":"s1"}`, http.StatusCreated)
	secID, _ := secRes["id"].(string)
	if secID == "" {
		t.Fatalf("expected generated secret id, got %+v", secRes)
	}
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_connector/_secret", fmt.Sprintf(`{"id":%q,"value":"s2"}`, secID), http.StatusConflict)

	// 4. OAuth2 password grant (round49_features.go L9884-9925)
	srv.SetAuth("elastic", "secret123", "")
	authHdr := [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:secret123"))}
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/user/u_ok", `{"password":"pw1","roles":["superuser"],"full_name":"U OK","email":"u@x.io","metadata":{"k":"v"}}`, http.StatusOK, authHdr)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/user/u_off", `{"password":"pw1","roles":["superuser"],"enabled":false}`, http.StatusOK, authHdr)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"password"}`, http.StatusBadRequest, authHdr)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"password","username":"elastic","password":"wrong"}`, http.StatusUnauthorized, authHdr)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"password","username":"no_such","password":"pw1"}`, http.StatusUnauthorized, authHdr)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"password","username":"u_off","password":"pw1"}`, http.StatusUnauthorized, authHdr)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"password","username":"u_ok","password":"wrong"}`, http.StatusUnauthorized, authHdr)
	tokRes := mustR67T2PHTTP(t, srv, http.MethodPost, "/_security/oauth2/token", `{"grant_type":"password","username":"u_ok","password":"pw1"}`, http.StatusOK, authHdr)
	if tokRes["access_token"] == nil {
		t.Fatalf("expected access_token, got %+v", tokRes)
	}

	// 5. ILM retry (round63_modules_ingest.go L1727-1765)
	srv7, _ := newR67T2PServer(t, "")
	mustR67T2PHTTP(t, srv7, http.MethodGet, "/idx_ilm/_ilm/retry", "", http.StatusMethodNotAllowed)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/missing_ilm_idx/_ilm/retry", `{}`, http.StatusBadRequest, authHdr)
	srv.SetAuth("", "", "")
	srv.mu.Lock()
	srv.securityUsers = nil
	srv.mu.Unlock()
	mustR67T2PHTTP(t, srv7, http.MethodPost, "/missing_ilm_idx/_ilm/retry", `{}`, http.StatusNotFound)
	mustR67T2PHTTP(t, srv7, http.MethodPut, "/idx_ilm_ok", `{}`, http.StatusOK)
	mustR67T2PHTTP(t, srv7, http.MethodPost, "/idx_ilm_ok/_ilm/retry", `{}`, http.StatusOK)

	// 6. _analyze field resolution & _field_caps (round62_admin_features.go L591-612, round61_admin_cat_stats.go L4213-4250)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/an_caps_idx", `{
		"settings": {
			"analysis": {
				"analyzer": {
					"default_search": {"type": "whitespace"},
					"default": {"type": "simple"}
				}
			}
		},
		"mappings": {
			"properties": {
				"sayt": {"type": "search_as_you_type"},
				"kw_norm": {"type": "keyword", "normalizer": "lowercase"},
				"created_time": {"type": "long"},
				"ratio": {"type": "double"},
				"flag": {"type": "boolean"},
				"msg": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
				"al_kw": {"type": "alias", "path": "kw_norm"}
			}
		}
	}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/an_caps_idx/_doc/1?refresh=true", `{"dyn_str":"hello world","sayt":"abc","created_time":123}`, http.StatusCreated)
	if _, _, err := srv.resolveAnalyzeFieldTargetCheckedR63Admin(context.Background(), "an_caps_idx", "al_kw", analysis.DefaultIndexAnalysisConfig(), map[string]bool{"kw_norm": true}, 0); err == nil {
		t.Fatalf("expected alias cycle error from resolveAnalyzeFieldTargetCheckedR63Admin")
	}
	mustR67T2PHTTP(t, srv, http.MethodPost, "/an_caps_idx/_analyze", `{"field":"kw_norm","text":"Hi"}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/an_caps_idx/_analyze", `{"field":"unmapped_f","text":"hi there"}`, http.StatusOK)

	cfg := &analysis.IndexAnalysisConfig{
		AnalyzerDefs: map[string]map[string]any{"default": {"type": "simple"}},
	}
	if an, _, err := srv.resolveAnalyzeFieldTargetCheckedR63Admin(context.Background(), "an_caps_idx", "unmapped_x", cfg, nil, 0); err != nil || an != "default" {
		t.Fatalf("expected default analyzer fallback, got an=%s err=%v", an, err)
	}
	if an, _, err := srv.resolveAnalyzeFieldTargetCheckedR63Admin(context.Background(), "an_caps_idx", "unmapped_x", nil, nil, 0); err != nil || an != "standard" {
		t.Fatalf("expected standard analyzer fallback, got an=%s err=%v", an, err)
	}

	fc := mustR67T2PHTTP(t, srv, http.MethodGet, "/an_caps_idx/_field_caps?fields=*", "", http.StatusOK)
	if fc["fields"] == nil {
		t.Fatalf("expected fields in _field_caps, got %+v", fc)
	}

	// 7. /_nodes/stats/http & /_cluster/state (round60_features.go L3046-3084, L3463-3478)
	adminSt := getOrCreateRound61AdminState(srv)
	adminSt.mu.Lock()
	adminSt.httpClients = []*round61HTTPClientInfo{{
		id:                    9,
		agent:                 "r67-agent",
		localAddress:          "127.0.0.1:9200",
		remoteAddress:         "127.0.0.1:50001",
		lastURI:               "/_nodes/stats",
		openedTimeMillis:      time.Now().UnixMilli() - 1000,
		lastRequestTimeMillis: time.Now().UnixMilli(),
		requestCount:          3,
		xOpaqueID:             "op-99",
	}}
	adminSt.mu.Unlock()
	mustR67T2PHTTP(t, srv, http.MethodGet, "/_nodes/stats/http", "", http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodGet, "/_cluster/state/_all?expand_wildcards=open,closed,hidden", "", http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodGet, "/_cluster/state/_all?expand_wildcards=none", "", http.StatusOK)

	// 8. /_data_stream/_migrate/{name} (round48_features.go L4616-4652)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/_index_template/mig_ds_tpl", `{"index_patterns":["al_*"],"data_stream":{}}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/mig_idx_1", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/mig_idx_2", `{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)

	mustR67T2PHTTP(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"mig_idx_1","alias":"al_nowrite","is_write_index":false}}]}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_data_stream/_migrate/al_nowrite", `{}`, http.StatusBadRequest)

	mustR67T2PHTTP(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"mig_idx_1","alias":"al_multi"}},{"add":{"index":"mig_idx_2","alias":"al_multi"}}]}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_data_stream/_migrate/al_multi", `{}`, http.StatusBadRequest)

	mustR67T2PHTTP(t, srv, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"mig_idx_1","alias":"al_ok_ds","is_write_index":false}},{"add":{"index":"mig_idx_2","alias":"al_ok_ds","is_write_index":true}}]}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_data_stream/_migrate/al_ok_ds", `{}`, http.StatusOK)

	// 9. queryHasNamedClauses & evalTopLevelKNNMatchesDocR63 (round48_features.go L4820-4862, L4951-4976)
	namedQueries := []esast.Query{
		{Nested: &esast.NestedQuery{Path: "items", Query: esast.Query{Name: "n1"}}},
		{Wrapper: &esast.WrapperQuery{Decoded: &esast.Query{Name: "w1"}}},
		{Pinned: &esast.PinnedQuery{Organic: &esast.Query{Name: "p1"}}},
		{KNN: &esast.KNNQuery{Filter: []esast.Query{{Name: "k1"}}}},
		{SpanNear: &esast.SpanNearQuery{Clauses: []esast.Query{{Name: "sn1"}}}},
		{SpanOr: &esast.SpanOrQuery{Clauses: []esast.Query{{Name: "so1"}}}},
		{SpanNot: &esast.SpanNotQuery{Include: &esast.Query{Name: "sni"}, Exclude: &esast.Query{}}},
		{SpanFirst: &esast.SpanFirstQuery{Match: &esast.Query{Name: "sf1"}, End: 3}},
		{SpanMulti: &esast.SpanMultiQuery{Match: &esast.Query{Name: "sm1"}}},
		{SpanContaining: &esast.SpanPairQuery{Little: &esast.Query{Name: "sc1"}, Big: &esast.Query{}}},
		{SpanWithin: &esast.SpanPairQuery{Little: &esast.Query{}, Big: &esast.Query{Name: "sw1"}}},
		{FieldMaskingSpan: &esast.FieldMaskingSpanQuery{Field: "f", Query: &esast.Query{Name: "fms1"}}},
	}
	for i := range namedQueries {
		if !queryHasNamedClauses(&namedQueries[i]) {
			t.Fatalf("expected queryHasNamedClauses=true for case %d", i)
		}
	}
	vecSchema := schema.CompileIndexSchema("es_r67t2p", "vec_nested", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"vec": {Type: "dense_vector", Dims: 2, Similarity: "cosine", ElementType: "float"},
				},
			},
		},
	})
	vecDoc := map[string]any{
		"items": []any{map[string]any{"vec": []any{1.0, 0.0}}},
	}
	if !evalTopLevelKNNMatchesDocR63(vecSchema, vecDoc, &esast.KNNQuery{
		Field:       "items.vec",
		QueryVector: []float64{1.0, 0.0},
		Similarity:  func() *float64 { v := 0.5; return &v }(),
	}) {
		t.Fatal("expected nested dense_vector KNN match")
	}
}

// TestRound67TopUp2Proxy_ESQLRollupSpatialAndMemBackend covers round56_features.go L4740-4765,
// round57_features.go L3840-3866, L5701-5729, round58_features.go L3466-3506, L5135-5158,
// round63_modules_ingest.go L7029-7078, round64_spatial_search_aggs.go L1732-1750, L3212-3259,
// membackend.go L3255-3276, L7067-7095, and server.go L20503-20578, L33584-33599, L34611-34640.
func TestRound67TopUp2Proxy_ESQLRollupSpatialAndMemBackend(t *testing.T) {
	srv, _ := newR67T2PServer(t, "8.15.0")

	// 1. ES|QL FROM with multifields, dynamic mapping + array unwrapping + _ignored (round56_features.go L4740-4765)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/esql_dyn_idx", `{"mappings":{"properties":{"title":{"type":"text","fields":{"raw":{"type":"keyword"}}}}}}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/esql_dyn_idx/_doc/1?refresh=true", `{"title":"hello","dyn_arr":["only_one"]}`, http.StatusCreated)
	esqlRes := mustR67T2PHTTP(t, srv, http.MethodPost, "/_query", `{"query":"FROM esql_dyn_idx METADATA _ignored | LIMIT 10"}`, http.StatusOK)
	if esqlRes["columns"] == nil {
		t.Fatalf("expected columns in ES|QL response, got %+v", esqlRes)
	}

	// ES|QL ENRICH with multiple matching enrich docs (round57_features.go L3840-3866)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/enr_src_idx", `{"mappings":{"properties":{"k":{"type":"keyword"},"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/enr_src_idx/_doc/1?refresh=true", `{"k":"a","tag":"t1"}`, http.StatusCreated)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/enr_src_idx/_doc/2?refresh=true", `{"k":"b","tag":"t2"}`, http.StatusCreated)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/_enrich/policy/r67_pol", `{
		"match": {"indices": "enr_src_idx", "match_field": "k", "enrich_fields": ["tag"]}
	}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/_enrich/policy/r67_pol/_execute", `{}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/enr_main_idx", `{"mappings":{"properties":{"keys":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/enr_main_idx/_doc/1?refresh=true", `{"keys":["a","b"]}`, http.StatusCreated)
	enrRes := mustR67T2PHTTP(t, srv, http.MethodPost, "/_query", `{"query":"FROM enr_main_idx | ENRICH r67_pol ON keys WITH tag"}`, http.StatusOK)
	if enrRes["values"] == nil {
		t.Fatalf("expected enriched ES|QL values, got %+v", enrRes)
	}

	// 2. collectSourceDocsWithRuntimeForJob with date runtime mapping (round58_features.go L3440-3524)
	mustR67T2PHTTP(t, srv, http.MethodPut, "/xf_src", `{"mappings":{"properties":{"ts":{"type":"date"}}}}`, http.StatusOK)
	mustR67T2PHTTP(t, srv, http.MethodPost, "/xf_src/_doc/1?refresh=true", `{"ts":"2026-01-01T00:00:00Z"}`, http.StatusCreated)
	evalDocs, srcDocs, err := srv.collectSourceDocsWithRuntimeForJob(
		context.Background(),
		[]string{"xf_src"},
		map[string]any{"match_all": map[string]any{}},
		map[string]esast.FieldProperty{
			"rt_dt": {Type: "date", Script: map[string]any{"source": "emit(doc['ts'].value.toInstant().toEpochMilli())"}},
		},
	)
	if err != nil || len(evalDocs) != 1 || len(srcDocs) != 1 {
		t.Fatalf("collectSourceDocsWithRuntimeForJob failed: err=%v eval=%d src=%d", err, len(evalDocs), len(srcDocs))
	}

	// 3. selectSingleRollupJobDocsR65 (round58_features.go L5120-5163)
	srv.mu.Lock()
	srv.rollupJobs["j_big"] = map[string]any{"config": map[string]any{"groups": map[string]any{"date_histogram": map[string]any{"fixed_interval": "1h"}}}}
	srv.rollupJobs["j_small"] = map[string]any{"config": map[string]any{"groups": map[string]any{"date_histogram": map[string]any{"fixed_interval": "5m"}}}}
	srv.rollupJobs["j_nocov"] = map[string]any{"config": map[string]any{"groups": map[string]any{"date_histogram": map[string]any{"fixed_interval": "10m"}}}}
	srv.mu.Unlock()
	rollupDocs := []map[string]any{
		{"_rollup": map[string]any{"id": "j_big"}, "ts": map[string]any{"date_histogram": map[string]any{"timestamp": int64(1000)}}},
		{"_rollup": map[string]any{"id": "j_small"}, "ts": map[string]any{"date_histogram": map[string]any{"timestamp": int64(1000)}}},
		{"_rollup": map[string]any{"id": "j_nocov"}},
	}
	aggsRollup := map[string]esast.AggSpec{
		"dh": {DateHistogram: &esast.DateHistogramAggSpec{Field: "ts", FixedInterval: "10m"}},
	}
	chosen := srv.selectSingleRollupJobDocsR65(rollupDocs, nil, aggsRollup)
	if len(chosen) != 1 {
		t.Fatalf("expected 1 chosen rollup doc, got %d", len(chosen))
	}

	// 4. restoreSnapshotIndexArtifacts pipeline restore & overrides (round57_features.go L5681-5730)
	restoredSchema := schema.CompileIndexSchema("es_r67t2p", "restored_t", &esast.MappingSpec{})
	rawSnap := map[string]any{
		"__default_pipelines": map[string]any{"src_t": "dp1"},
		"__final_pipelines":   map[string]any{"src_t": "fp1"},
		"__aliases": map[string]any{
			"src_t": map[string]any{
				"al_restored": map[string]any{"is_write_index": true},
			},
		},
	}
	srv.restoreSnapshotIndexArtifacts(context.Background(), rawSnap, "src_t", "restored_t", restoredSchema, map[string]any{
		"index_settings": map[string]any{"default_pipeline": "_none", "final_pipeline": "fp_override"},
	}, false)
	if srv.indexDefaultPipelines["restored_t"] != "" || srv.indexFinalPipelines["restored_t"] != "fp_override" {
		t.Fatalf("unexpected restored pipelines: def=%q fin=%q", srv.indexDefaultPipelines["restored_t"], srv.indexFinalPipelines["restored_t"])
	}

	// 5. lookupConstantKeywordValueR64 & extractTermsEnumRoleStringSliceR65 (round63_modules_ingest.go L7032-7079)
	ckSchema := schema.CompileIndexSchema("es_r67t2p", "ck_idx", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"obj": {Properties: map[string]esast.FieldProperty{"ck": {Type: "constant_keyword", Value: "const_v"}}},
		},
	})
	if v := lookupConstantKeywordValueR64(ckSchema, "obj.ck"); v != "const_v" {
		t.Fatalf("expected const_v, got %v", v)
	}
	if v := lookupConstantKeywordValueR64(ckSchema, "obj.ck.deep"); v != nil {
		t.Fatalf("expected nil for missing nested path, got %v", v)
	}
	if _, ok := extractTermsEnumRoleStringSliceR65(nil); !ok {
		t.Fatal("expected nil ok")
	}
	if _, ok := extractTermsEnumRoleStringSliceR65(" "); !ok {
		t.Fatal("expected blank string ok")
	}
	if s, ok := extractTermsEnumRoleStringSliceR65([]string{"a"}); !ok || len(s) != 1 {
		t.Fatal("expected []string ok")
	}
	if s, ok := extractTermsEnumRoleStringSliceR65([]any{"a", "b"}); !ok || len(s) != 2 {
		t.Fatal("expected []any string ok")
	}
	if _, ok := extractTermsEnumRoleStringSliceR65([]any{123}); ok {
		t.Fatal("expected non-string []any to fail")
	}
	if _, ok := extractTermsEnumRoleStringSliceR65(123); ok {
		t.Fatal("expected int to fail")
	}

	// 6. Spatial intersections & queryNeedsRuntimeSpatialEvalR64 (round64_spatial_search_aggs.go L1715-1750, L3210-3260)
	polyA := parsedGeomR64{kind: geomPolygonR64, outer: [][2]float64{{0, 0}, {0, 10}, {10, 10}, {10, 0}}}
	polyB := parsedGeomR64{kind: geomPolygonR64, outer: [][2]float64{{5, 5}, {5, 15}, {15, 15}, {15, 5}}}
	polyInside := parsedGeomR64{kind: geomPolygonR64, outer: [][2]float64{{2, 2}, {2, 4}, {4, 4}, {4, 2}}}
	lineCross := parsedGeomR64{kind: geomLineR64, line: [][2]float64{{-2, 5}, {12, 5}}}
	if !geomIntersectsQueryShapeR64(polyA, polyB) || !geomIntersectsQueryShapeR64(polyInside, polyA) || !geomIntersectsQueryShapeR64(lineCross, polyA) {
		t.Fatal("expected polygon/line intersections to be true")
	}
	gsQ := esast.Query{GeoShape: &esast.GeoShapeQuery{Field: "loc"}}
	spatialWrappers := []esast.Query{
		{Bool: &esast.BoolQuery{Must: []esast.Query{gsQ}}},
		{Bool: &esast.BoolQuery{Filter: []esast.Query{gsQ}}},
		{Bool: &esast.BoolQuery{MustNot: []esast.Query{gsQ}}},
		{Bool: &esast.BoolQuery{Should: []esast.Query{gsQ}}},
		{ConstantScore: &esast.ConstantScoreQuery{Filter: gsQ}},
		{DisMax: &esast.DisMaxQuery{Queries: []esast.Query{gsQ}}},
		{Boosting: &esast.BoostingQuery{Positive: gsQ, Negative: esast.Query{}}},
		{Nested: &esast.NestedQuery{Path: "n", Query: gsQ}},
		{ScriptScore: &esast.ScriptScoreQuery{Query: &gsQ}},
		{FunctionScore: &esast.FunctionScoreQuery{Query: &gsQ}},
		{Wrapper: &esast.WrapperQuery{Decoded: &gsQ}},
		{Pinned: &esast.PinnedQuery{Organic: &gsQ}},
	}
	for i := range spatialWrappers {
		if !queryNeedsRuntimeSpatialEvalR64(&spatialWrappers[i], nil) {
			t.Fatalf("expected queryNeedsRuntimeSpatialEvalR64=true for case %d", i)
		}
	}

	// 7. membackend.go evalBucketKeyExprs & memEvalSecondsAdd (L3253-3282, L7064-7098)
	if out := evalBucketKeyExprs(map[string]any{"tags": []any{"x", "y"}}, "tags"); len(out) != 2 {
		t.Fatalf("expected 2 tags from []any, got %v", out)
	}
	if out := evalBucketKeyExprs(map[string]any{"tags": []string{"p", "q"}}, "tags"); len(out) != 2 {
		t.Fatalf("expected 2 tags from []string, got %v", out)
	}
	if v := memEvalSecondsAdd(map[string]any{"dt": nil, "sec": 5}, "dt", "sec"); v != nil {
		t.Fatalf("expected nil for null dt, got %v", v)
	}
	if v := memEvalSecondsAdd(map[string]any{"dt": "2026-01-01 00:00:00", "sec": 10.6}, "dt", "sec"); v != "2026-01-01 00:00:10.000000" {
		t.Fatalf("expected truncated +10s, got %v", v)
	}
	if v := memEvalSecondsAdd(map[string]any{"dt": "2026-01-01 00:00:00", "sec": "bad"}, "dt", "sec"); v != nil {
		t.Fatalf("expected nil for non-numeric sec, got %v", v)
	}
	if v := memEvalSecondsAdd(map[string]any{"dt": "2026-01-01 00:00:00", "a": 2}, "dt", "a + 3"); v != "2026-01-01 00:00:05.000000" {
		t.Fatalf("expected +5s for arithmetic expr, got %v", v)
	}
	if v := memEvalSecondsAdd(map[string]any{"dt": "2026-01-01 00:00:00", "sec": math.NaN()}, "dt", "sec"); v != nil {
		t.Fatalf("expected nil for NaN sec, got %v", v)
	}

	// 8. server.go extractBucketMetricBySegs, evalMovingPercentilesFallbackWithTargetR65, resolveTermsOrderTargetSubAggWithNameR65
	bkt := map[string]any{
		"doc_count": int64(0),
		"pct_zero":  map[string]any{"values": map[string]any{"50.0": 1.0}},
	}
	if _, ok := extractBucketMetricBySegs(bkt, []string{"pct_zero", "50"}); ok {
		t.Fatal("expected false for doc_count==0 percentile")
	}
	bktNZ := map[string]any{
		"doc_count": int64(2),
		"m_val":     map[string]any{"value": map[string]any{"inner": 9.5}},
		"m_f64":     map[string]any{"values": map[string]float64{"99.0": 42.0}},
		"m_any":     map[string]any{"values": map[string]any{"95.0": 33.0}},
		"m_arr":     map[string]any{"values": []map[string]any{{"key": 50.0, "value": 12.5}}},
		"th":        map[string]any{"hits": map[string]any{"total": map[string]any{"value": int64(4)}}},
	}
	if v, ok := extractBucketMetricBySegs(bktNZ, []string{"m_val", "value", "inner"}); !ok || v != 9.5 {
		t.Fatalf("expected 9.5, got v=%v ok=%v", v, ok)
	}
	if v, ok := extractBucketMetricBySegs(bktNZ, []string{"m_f64", "99"}); !ok || v != 42.0 {
		t.Fatalf("expected 42.0, got v=%v ok=%v", v, ok)
	}
	if v, ok := extractBucketMetricBySegs(bktNZ, []string{"m_any", "95"}); !ok || v != 33.0 {
		t.Fatalf("expected 33.0, got v=%v ok=%v", v, ok)
	}
	if v, ok := extractBucketMetricBySegs(bktNZ, []string{"m_arr", "50"}); !ok || v != 12.5 {
		t.Fatalf("expected 12.5, got v=%v ok=%v", v, ok)
	}
	if v, ok := extractBucketMetricBySegs(bktNZ, []string{"th", "_count"}); !ok || v != 4 {
		t.Fatalf("expected 4, got v=%v ok=%v", v, ok)
	}

	mpBuckets := []map[string]any{
		{"key": 1, "pct": map[string]any{"values": []any{map[string]any{"key": 50.0, "value": 10.0}}}},
		{"key": 2, "pct": map[string]any{"values": []map[string]any{{"key": 50.0, "value": 20.0}}}},
	}
	evalMovingPercentilesFallbackWithTargetR65(mpBuckets, "mp", &esast.MovingPercentilesAggSpec{
		BucketsPath: "pct",
		Format:      "0.0",
	}, nil)
	if mpBuckets[1]["mp"] == nil {
		t.Fatalf("expected moving_percentiles output on bucket 1, got %+v", mpBuckets[1])
	}

	subAggs := map[string]esast.AggSpec{
		"flt": {
			Filter: &esast.Query{MatchAll: map[string]any{}},
			Aggs: map[string]esast.AggSpec{
				"tm": {TopMetrics: &esast.TopMetricsAggSpec{}},
			},
		},
	}
	if name, _, prop, isTM, ok := resolveTermsOrderTargetSubAggWithNameR65(subAggs, "flt>tm.metrics.cpu"); !ok || !isTM || name != "tm" || prop != "cpu" {
		t.Fatalf("unexpected resolveTermsOrderTargetSubAggWithNameR65: name=%s prop=%s isTM=%v ok=%v", name, prop, isTM, ok)
	}
}
