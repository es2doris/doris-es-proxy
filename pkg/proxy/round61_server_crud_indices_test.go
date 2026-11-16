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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

type mockTelemetryBackendR61CRUDTest struct {
	*MemoryBackend
	telemetry *DorisClusterTelemetry
}

func (m *mockTelemetryBackendR61CRUDTest) ShowBackendsTelemetry(_ context.Context) ([]DorisBackendNodeTelemetry, error) {
	if m.telemetry == nil {
		return nil, nil
	}
	return m.telemetry.Backends, nil
}

func (m *mockTelemetryBackendR61CRUDTest) ShowDataTelemetry(_ context.Context, _ string) (map[string]DorisTableDataTelemetry, error) {
	if m.telemetry == nil {
		return nil, nil
	}
	return m.telemetry.Tables, nil
}

func (m *mockTelemetryBackendR61CRUDTest) CollectClusterTelemetry(_ context.Context, _ string) *DorisClusterTelemetry {
	return m.telemetry
}

func newServerR61CRUDTest(t *testing.T, esVer string) (*Server, http.Handler) {
	t.Helper()
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	if esVer != "" {
		srv.SetTargetESVersion(esVer)
	}
	t.Cleanup(func() {
		resetRound61AdminState(srv)
	})
	return srv, srv.Handler()
}

func doReqR61CRUDTest(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) (int, http.Header, map[string]any, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		if strings.Contains(path, "/_bulk") || strings.Contains(path, "/_msearch") {
			req.Header.Set("Content-Type", "application/x-ndjson")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
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

func TestRound61ServerCRUD_F1_RouterInfoCapabilitiesSnapshotsPainlessUpgradeFieldCapsComponentTemplate(t *testing.T) {
	_, h := newServerR61CRUDTest(t, "8.15.5")

	// Send 1 warmup request with custom User-Agent, then verify /_info/http,ingest tracks HTTP client requests without double-counting.
	code, _, _, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/", "", map[string]string{"User-Agent": "r61-test-agent/1.0"})
	if code != http.StatusOK {
		t.Fatalf("GET / failed (%d): %s", code, raw)
	}
	code, _, infoResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_info/http,ingest", "", map[string]string{"User-Agent": "r61-test-agent/1.0"})
	if code != http.StatusOK {
		t.Fatalf("GET /_info/http,ingest failed (%d): %s", code, raw)
	}
	httpSec, _ := infoResp["http"].(map[string]any)
	clients, _ := httpSec["clients"].([]any)
	if len(clients) == 0 {
		t.Fatalf("expected non-empty http.clients in /_info/http,ingest: %s", raw)
	}
	c0, _ := clients[0].(map[string]any)
	if fmt.Sprintf("%v", c0["request_count"]) != "2" {
		t.Fatalf("expected request_count=2 (no double count on /_info), got %v: %s", c0["request_count"], raw)
	}
	if _, ok := infoResp["ingest"].(map[string]any); !ok {
		t.Fatalf("expected ingest section in /_info/http,ingest: %s", raw)
	}
	code, _, _, _ = doReqR61CRUDTest(t, h, http.MethodHead, "/_info", "", nil)
	if code != http.StatusOK {
		t.Fatalf("HEAD /_info expected 200, got %d", code)
	}

	// GET & POST /_capabilities
	code, _, capResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_capabilities", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_capabilities failed (%d): %s", code, raw)
	}
	if capResp["supported"] != true {
		t.Fatalf("expected supported=true in GET /_capabilities: %s", raw)
	}
	if _, ok := capResp["capabilities"].(map[string]any); !ok {
		t.Fatalf("expected capabilities map in GET /_capabilities: %s", raw)
	}
	code, _, postCapResp, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/_capabilities?method=POST&path=/_search&parameters=typed_keys,batched_reduce_size", "", nil)
	if code != http.StatusOK || postCapResp["supported"] != true {
		t.Fatalf("POST /_capabilities failed (%d): %s", code, raw)
	}

	// /_cat/snapshots & /_cat/snapshots/{repository}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPut, "/_snapshot/repo_r61", `{"type":"fs","settings":{"location":"/tmp/repo_r61"}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /_snapshot/repo_r61 failed (%d): %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPut, "/_snapshot/repo_r61/snap_1?wait_for_completion=true", `{}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT snapshot failed (%d): %s", code, raw)
	}
	for _, p := range []string{"/_cat/snapshots?format=json", "/_cat/snapshots/repo_r61?format=json"} {
		code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodGet, p, "", nil)
		if code != http.StatusOK || !strings.Contains(raw, "snap_1") {
			t.Fatalf("GET %s failed (%d): %s", p, code, raw)
		}
	}

	// /_scripts/painless/_context & /_scripts/painless/_context/score
	code, _, ctxResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_scripts/painless/_context", "", nil)
	if code != http.StatusOK || ctxResp["contexts"] == nil {
		t.Fatalf("GET /_scripts/painless/_context failed (%d): %s", code, raw)
	}
	code, _, scoreCtxResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_scripts/painless/_context/score", "", nil)
	if code != http.StatusOK || scoreCtxResp["name"] != "score" || scoreCtxResp["classes"] == nil {
		t.Fatalf("GET /_scripts/painless/_context/score failed (%d): %s", code, raw)
	}

	// /_upgrade & /{index}/_upgrade + /_field_caps
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPut, "/upg_idx", `{"mappings":{"properties":{"k":{"type":"keyword","index":false},"t":{"type":"text"}}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /upg_idx failed (%d): %s", code, raw)
	}
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/_upgrade"},
		{http.MethodGet, "/_upgrade"},
		{http.MethodPost, "/upg_idx/_upgrade"},
		{http.MethodGet, "/upg_idx/_upgrade"},
	} {
		code, _, _, raw = doReqR61CRUDTest(t, h, tc.method, tc.path, "", nil)
		if code != http.StatusOK {
			t.Fatalf("%s %s failed (%d): %s", tc.method, tc.path, code, raw)
		}
	}

	code, _, fcResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/upg_idx/_field_caps?fields=k,t", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /upg_idx/_field_caps failed (%d): %s", code, raw)
	}
	fieldsMap, _ := fcResp["fields"].(map[string]any)
	kMap, _ := fieldsMap["k"].(map[string]any)
	kwCap, _ := kMap["keyword"].(map[string]any)
	if kwCap["searchable"] != true {
		t.Fatalf("expected ES 8 index:false keyword with doc_values to be searchable in _field_caps: %s", raw)
	}

	// DELETE /_component_template/{name} in-use guard
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPut, "/_component_template/ct_r61", `{"template":{"settings":{"number_of_shards":1}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT component_template failed (%d): %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPut, "/_index_template/it_r61", `{"index_patterns":["ct-*"],"composed_of":["ct_r61"]}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT index_template failed (%d): %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodDelete, "/_component_template/ct_r61", "", nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "in use") {
		t.Fatalf("expected 400 in-use error on DELETE /_component_template/ct_r61, got %d: %s", code, raw)
	}
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodDelete, "/_index_template/it_r61", "", nil)
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodDelete, "/_component_template/ct_r61", "", nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 deleting unused component template, got %d: %s", code, raw)
	}
}

func TestRound61ServerCRUD_F2_F3_CatExpandWildcardsFlushAndTypedDocStats(t *testing.T) {
	_, h := newServerR61CRUDTest(t, "7.10.2")

	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/visible_idx", `{"aliases":{"vis_alias":{}}}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/.hidden_idx", `{"aliases":{".hid_alias":{},"vis_on_hid":{}}}`, nil)

	// _cat/indices?expand_wildcards=hidden excludes visible_idx
	code, _, _, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_cat/indices?format=json&expand_wildcards=hidden", "", nil)
	if code != http.StatusOK || strings.Contains(raw, "visible_idx") || !strings.Contains(raw, ".hidden_idx") {
		t.Fatalf("unexpected _cat/indices?expand_wildcards=hidden (%d): %s", code, raw)
	}

	// _cat/aliases default includes hidden aliases; expand_wildcards=hidden excludes vis_alias on visible_idx
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodGet, "/_cat/aliases?format=json", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, ".hid_alias") || !strings.Contains(raw, "vis_alias") {
		t.Fatalf("expected default _cat/aliases to include both hidden and visible aliases (%d): %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodGet, "/_cat/aliases?format=json&expand_wildcards=hidden", "", nil)
	if code != http.StatusOK || strings.Contains(raw, `"vis_alias"`) || !strings.Contains(raw, ".hid_alias") {
		t.Fatalf("expected _cat/aliases?expand_wildcards=hidden to exclude vis_alias (%d): %s", code, raw)
	}

	// ES 7 typed doc stats + _flush translog mark
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPut, "/visible_idx/custom_doc/1?refresh=true", `{"k":"v"}`, nil)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("typed PUT failed (%d): %s", code, raw)
	}
	code, _, statsBefore, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/visible_idx/_stats/indexing,translog?types=custom_doc", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, "custom_doc") {
		t.Fatalf("expected custom_doc type stats in /_stats (%d): %s", code, raw)
	}
	_ = statsBefore
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPost, "/visible_idx/_flush", "", nil)
	if code != http.StatusOK {
		t.Fatalf("POST /visible_idx/_flush failed (%d): %s", code, raw)
	}
	code, _, statsAfter, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/visible_idx/_stats/translog", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET translog stats after flush failed (%d): %s", code, raw)
	}
	allMap, _ := statsAfter["_all"].(map[string]any)
	totMap, _ := allMap["total"].(map[string]any)
	tlogMap, _ := totMap["translog"].(map[string]any)
	if fmt.Sprintf("%v", tlogMap["uncommitted_operations"]) != "0" {
		t.Fatalf("expected uncommitted_operations=0 after _flush, got %v: %s", tlogMap["uncommitted_operations"], raw)
	}
}

func TestRound61ServerCRUD_F4_F9_FilterPathDeprecationsClusterHealthAndTelemetry(t *testing.T) {
	mem := NewMemoryBackend(false)
	tb := &mockTelemetryBackendR61CRUDTest{
		MemoryBackend: mem,
		telemetry: &DorisClusterTelemetry{
			TotalNodes:         2,
			AliveNodes:         2,
			TotalCapacityBytes: 200 * 1024 * 1024 * 1024,
			DataUsedBytes:      50 * 1024 * 1024 * 1024,
			AvailCapacityBytes: 150 * 1024 * 1024 * 1024,
			Backends: []DorisBackendNodeTelemetry{
				{BackendID: "be-1001", Host: "10.0.0.1", HttpPort: 8040, Alive: true, TotalCapacityBytes: 100 << 30, AvailCapacityBytes: 75 << 30, DataUsedCapacityBytes: 25 << 30, CpuCores: 8},
				{BackendID: "be-1002", Host: "10.0.0.2", HttpPort: 8040, Alive: true, TotalCapacityBytes: 100 << 30, AvailCapacityBytes: 75 << 30, DataUsedCapacityBytes: 25 << 30, CpuCores: 8},
			},
			Tables: map[string]DorisTableDataTelemetry{},
		},
	}
	srv := NewServer("es_db", tb, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	t.Cleanup(func() { resetRound61AdminState(srv) })
	h := srv.Handler()

	// Repeated ?filter_path= composition
	code, _, fpResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_cluster/health?filter_path=cluster_name,status&filter_path=-status", "", nil)
	if code != http.StatusOK || fpResp["cluster_name"] == nil || fpResp["status"] != nil {
		t.Fatalf("repeated filter_path failed (%d): %s", code, raw)
	}

	// /_migration/deprecations
	code, _, depResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_migration/deprecations", "", nil)
	if code != http.StatusOK || depResp["migration_status"] != "NO_MIGRATION_NEEDED" {
		t.Fatalf("expected migration_status=NO_MIGRATION_NEEDED (%d): %s", code, raw)
	}

	// cluster.health validation, yellow status when replicas exceed node count (2 replicas on 2-node cluster), levels, and 408 timeout
	code, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/_cluster/health?bogus_param=1", "", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown cluster.health param, got %d", code)
	}
	code, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/_cluster/health?level=bogus", "", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid cluster.health level, got %d", code)
	}
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/rep_idx", `{"settings":{"number_of_shards":2,"number_of_replicas":2}}`, nil)
	code, _, chResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_cluster/health/rep_idx?level=shards", "", nil)
	if code != http.StatusOK || chResp["status"] != "yellow" {
		t.Fatalf("expected yellow status on 2-node cluster with number_of_replicas=2 (%d): %s", code, raw)
	}
	indicesMap, _ := chResp["indices"].(map[string]any)
	repHealth, _ := indicesMap["rep_idx"].(map[string]any)
	if repHealth["shards"] == nil {
		t.Fatalf("expected shards map at level=shards: %s", raw)
	}
	code, _, toResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_cluster/health/rep_idx?wait_for_status=green&timeout=1ms", "", nil)
	if code != http.StatusRequestTimeout || toResp["timed_out"] != true {
		t.Fatalf("expected 408 timed_out on wait_for_status=green for yellow index (%d): %s", code, raw)
	}

	// Ingest pipeline + telemetry wiring in cluster.stats, nodes.stats, nodes.info
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_ingest/pipeline/p_tel", `{"processors":[{"set":{"field":"tagged","value":true}}]}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPost, "/rep_idx/_doc/1?pipeline=p_tel&refresh=true", `{"msg":"hi"}`, nil)

	code, _, csResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_cluster/stats", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_cluster/stats failed (%d): %s", code, raw)
	}
	csIndices, _ := csResp["indices"].(map[string]any)
	if csIndices["analysis"] == nil || csIndices["mappings"] == nil || csIndices["segments"] == nil {
		t.Fatalf("expected indices.analysis, mappings, segments in cluster.stats: %s", raw)
	}
	csNodes, _ := csResp["nodes"].(map[string]any)
	csCnt, _ := csNodes["count"].(map[string]any)
	if fmt.Sprintf("%v", csCnt["total"]) != "2" {
		t.Fatalf("expected cluster.stats nodes.count.total=2 from TelemetryBackend, got %v", csCnt["total"])
	}

	code, _, nsResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_nodes/stats", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_nodes/stats failed (%d): %s", code, raw)
	}
	nodesMap, _ := nsResp["nodes"].(map[string]any)
	if len(nodesMap) != 2 {
		t.Fatalf("expected 2 Doris BE nodes in /_nodes/stats, got %d: %s", len(nodesMap), raw)
	}
	for _, v := range nodesMap {
		nm, _ := v.(map[string]any)
		httpMap, _ := nm["http"].(map[string]any)
		if httpMap["routes"] == nil {
			t.Fatalf("expected http.routes in nodes.stats: %s", raw)
		}
		ingMap, _ := nm["ingest"].(map[string]any)
		pipesMap, _ := ingMap["pipelines"].(map[string]any)
		if pipesMap["p_tel"] == nil {
			t.Fatalf("expected live ingest pipeline p_tel in nodes.stats: %s", raw)
		}
	}

	code, _, niResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_nodes", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, `"reroute"`) {
		t.Fatalf("expected live ingest processor types in GET /_nodes (%d): %v", code, niResp)
	}
}

func TestRound61ServerCRUD_F5_CreateIndexGuardsAndIncludeTypeNameParity(t *testing.T) {
	_, h8 := newServerR61CRUDTest(t, "8.15.5")

	// Duplicate PUT /{index} -> 400 resource_already_exists_exception with index & index_uuid
	code, _, _, raw := doReqR61CRUDTest(t, h8, http.MethodPut, "/dup_r61", `{}`, nil)
	if code != http.StatusOK {
		t.Fatalf("initial PUT /dup_r61 failed (%d): %s", code, raw)
	}
	code, _, dupErrResp, raw := doReqR61CRUDTest(t, h8, http.MethodPut, "/dup_r61", `{}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on duplicate PUT /dup_r61, got %d: %s", code, raw)
	}
	errObj, _ := dupErrResp["error"].(map[string]any)
	if errObj["type"] != "resource_already_exists_exception" || errObj["index"] != "dup_r61" || errObj["index_uuid"] == nil {
		t.Fatalf("expected resource_already_exists_exception with index & index_uuid: %s", raw)
	}

	// Unknown root JSON key in PUT /{index} -> 400 parsing_exception
	code, _, _, raw = doReqR61CRUDTest(t, h8, http.MethodPut, "/bad_root_r61", `{"bogus_key":{}}`, nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "parsing_exception") {
		t.Fatalf("expected 400 parsing_exception on unknown root key, got %d: %s", code, raw)
	}

	// Missing synonyms_set -> shards_acknowledged: false
	code, _, synResp, raw := doReqR61CRUDTest(t, h8, http.MethodPut, "/syn_missing_r61", `{
		"settings":{"analysis":{"filter":{"my_syn":{"type":"synonym_graph","synonyms_set":"missing_set_id","updateable":true}},"analyzer":{"my_an":{"tokenizer":"standard","filter":["my_syn"]}}}}
	}`, nil)
	if code != http.StatusOK || synResp["acknowledged"] != true || synResp["shards_acknowledged"] != false {
		t.Fatalf("expected acknowledged=true, shards_acknowledged=false for missing synonyms_set (%d): %s", code, raw)
	}

	// ES 8 rejects include_type_name across endpoints
	for _, tc := range []struct{ m, p, b string }{
		{http.MethodPut, "/es8_t?include_type_name=true", `{}`},
		{http.MethodGet, "/dup_r61?include_type_name=true", ""},
		{http.MethodGet, "/dup_r61/_mapping?include_type_name=true", ""},
		{http.MethodPut, "/dup_r61/_mapping?include_type_name=true", `{"properties":{}}`},
		{http.MethodGet, "/dup_r61/_mapping/field/_id?include_type_name=true", ""},
		{http.MethodPut, "/_template/t8?include_type_name=true", `{"index_patterns":["x*"]}`},
	} {
		c, _, _, rw := doReqR61CRUDTest(t, h8, tc.m, tc.p, tc.b, nil)
		if c != http.StatusBadRequest || !strings.Contains(rw, "include_type_name") {
			t.Fatalf("ES 8 expected 400 for %s %s, got %d: %s", tc.m, tc.p, c, rw)
		}
	}

	// ES 7 full include_type_name parity
	_, h7 := newServerR61CRUDTest(t, "7.10.2")
	code, _, _, raw = doReqR61CRUDTest(t, h7, http.MethodPut, "/v7_typed?include_type_name=true", `{
		"mappings":{"book":{"properties":{"title":{"type":"text"}}}}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("ES 7 PUT /v7_typed?include_type_name=true failed (%d): %s", code, raw)
	}
	code, _, getIdxResp, raw := doReqR61CRUDTest(t, h7, http.MethodGet, "/v7_typed?include_type_name=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("ES 7 GET /v7_typed?include_type_name=true failed (%d): %s", code, raw)
	}
	idxEntry, _ := getIdxResp["v7_typed"].(map[string]any)
	mappingsObj, _ := idxEntry["mappings"].(map[string]any)
	if mappingsObj["book"] == nil {
		t.Fatalf("expected mappings.book wrapper in GET /v7_typed?include_type_name=true: %s", raw)
	}

	// GET /{index}/_mapping/{type}?include_type_name=true: match vs missing type 404
	code, _, _, raw = doReqR61CRUDTest(t, h7, http.MethodGet, "/v7_typed/_mapping/book?include_type_name=true", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, `"book"`) {
		t.Fatalf("expected 200 for matching type book (%d): %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h7, http.MethodGet, "/v7_typed/_mapping/wrong_type?include_type_name=true", "", nil)
	if code != http.StatusNotFound || !strings.Contains(raw, "type_missing_exception") {
		t.Fatalf("expected 404 type_missing_exception for wrong_type (%d): %s", code, raw)
	}

	// PUT /{index}/_mapping/{type} conflicting type -> 400; matching type -> 200
	code, _, _, raw = doReqR61CRUDTest(t, h7, http.MethodPut, "/v7_typed/_mapping/author?include_type_name=true", `{"properties":{"name":{"type":"keyword"}}}`, nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "more than 1 type") {
		t.Fatalf("expected 400 more than 1 type conflict (%d): %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h7, http.MethodPut, "/v7_typed/_mapping/book?include_type_name=true", `{"properties":{"pages":{"type":"integer"}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 updating matching type book (%d): %s", code, raw)
	}

	// GET /{index}/_mapping/field/_id,_source,title?include_type_name=true
	code, _, fmResp, raw := doReqR61CRUDTest(t, h7, http.MethodGet, "/v7_typed/_mapping/book/field/_id,_source,title?include_type_name=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET field mapping failed (%d): %s", code, raw)
	}
	v7Entry, _ := fmResp["v7_typed"].(map[string]any)
	v7Map, _ := v7Entry["mappings"].(map[string]any)
	bookMap, _ := v7Map["book"].(map[string]any)
	if bookMap["_id"] == nil || bookMap["_source"] == nil || bookMap["title"] == nil {
		t.Fatalf("expected _id, _source, and title under mappings.book: %s", raw)
	}

	// PUT & GET /_template/{name}?include_type_name=true
	code, _, _, raw = doReqR61CRUDTest(t, h7, http.MethodPut, "/_template/tpl_v7?include_type_name=true", `{
		"index_patterns":["tpl7-*"],
		"mappings":{"article":{"properties":{"headline":{"type":"text"}}}}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /_template/tpl_v7?include_type_name=true failed (%d): %s", code, raw)
	}
	code, _, tplGetResp, raw := doReqR61CRUDTest(t, h7, http.MethodGet, "/_template/tpl_v7?include_type_name=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_template/tpl_v7?include_type_name=true failed (%d): %s", code, raw)
	}
	tplObj, _ := tplGetResp["tpl_v7"].(map[string]any)
	tplMappings, _ := tplObj["mappings"].(map[string]any)
	if tplMappings["article"] == nil {
		t.Fatalf("expected mappings.article in GET /_template/tpl_v7?include_type_name=true: %s", raw)
	}
}

func TestRound61ServerCRUD_F6_DeleteIndexAndAliasesParity(t *testing.T) {
	_, h := newServerR61CRUDTest(t, "8.15.5")

	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/idx_a", `{"aliases":{"alias_only":{}}}`, nil)

	// Concrete alias DELETE -> 400 (and 200 with ignore_unavailable=true); wildcard matching only alias -> 200 (404 when allow_no_indices=false)
	code, _, _, raw := doReqR61CRUDTest(t, h, http.MethodDelete, "/alias_only", "", nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "alias") {
		t.Fatalf("expected 400 deleting concrete alias, got %d: %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodDelete, "/alias_only?ignore_unavailable=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 deleting concrete alias with ignore_unavailable=true, got %d: %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodDelete, "/alias_on*", "", nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on wildcard DELETE matching only alias, got %d: %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodDelete, "/alias_on*?allow_no_indices=false", "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 on wildcard DELETE matching only alias with allow_no_indices=false, got %d: %s", code, raw)
	}

	// action.destructive_requires_name=true blocks wildcard/_all DELETE
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_cluster/settings", `{"persistent":{"action.destructive_requires_name":true}}`, nil)
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodDelete, "/idx_*", "", nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "Wildcard expressions or all indices are not allowed") {
		t.Fatalf("expected 400 from destructive_requires_name, got %d: %s", code, raw)
	}

	// get_alias 404 string formats & ?local=true Warning + delete_alias 404
	code, hdr, _, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/_alias/no_such_alias?local=true", "", nil)
	if code != http.StatusNotFound || !strings.Contains(raw, `"alias [no_such_alias] missing"`) {
		t.Fatalf("expected 404 'alias [no_such_alias] missing', got %d: %s", code, raw)
	}
	if !strings.Contains(hdr.Get("Warning"), "local") {
		t.Fatalf("expected deprecation Warning for ?local=true, got %q", hdr.Get("Warning"))
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodGet, "/idx_a/_alias/-no_such_excl,alias_*", "", nil)
	if code != http.StatusNotFound || !strings.Contains(raw, `"alias [-no_such_excl] missing"`) {
		t.Fatalf("expected 404 'alias [-no_such_excl] missing', got %d: %s", code, raw)
	}
	code, _, emptyAliasMap, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/idx_a/_alias/*,-*", "", nil)
	if code != http.StatusOK || len(emptyAliasMap) != 0 {
		t.Fatalf("expected 200 {} on wildcard exclusion '*,-*', got %d: %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodDelete, "/idx_a/_alias/no_such_alias", "", nil)
	if code != http.StatusNotFound || !strings.Contains(raw, "aliases_not_found_exception") {
		t.Fatalf("expected 404 aliases_not_found_exception on DELETE _alias, got %d: %s", code, raw)
	}
}

func TestRound61ServerCRUD_F7_CRUD512ByteIDVersionRealtimeStoredFieldsAndMGet(t *testing.T) {
	_, h := newServerR61CRUDTest(t, "8.15.5")

	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/crud_idx", `{
		"settings":{"index":{"refresh_interval":"-1"}},
		"mappings":{
			"properties":{
				"stored_kw":{"type":"keyword","store":true},
				"plain_kw":{"type":"keyword"},
				"short_str":{"type":"keyword","ignore_above":5}
			}
		}
	}`, nil)

	// 512-byte _id guard across PUT, UPDATE, DELETE, BULK
	longID := strings.Repeat("x", 513)
	for _, tc := range []struct{ m, p, b string }{
		{http.MethodPut, "/crud_idx/_doc/" + longID, `{"plain_kw":"a"}`},
		{http.MethodPost, "/crud_idx/_update/" + longID, `{"doc":{"plain_kw":"b"}}`},
		{http.MethodDelete, "/crud_idx/_doc/" + longID, ""},
	} {
		c, _, _, rw := doReqR61CRUDTest(t, h, tc.m, tc.p, tc.b, nil)
		if c != http.StatusBadRequest || !strings.Contains(rw, "512") {
			t.Fatalf("expected 400 512-byte _id error on %s, got %d: %s", tc.m, c, rw)
		}
	}
	bulkLong := fmt.Sprintf("{\"index\":{\"_index\":\"crud_idx\",\"_id\":%q}}\n{\"plain_kw\":\"a\"}\n", longID)
	code, _, bulkResp, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/_bulk", bulkLong, nil)
	if code != http.StatusOK || bulkResp["errors"] != true || !strings.Contains(raw, "512") {
		t.Fatalf("expected per-item 512-byte _id error in _bulk (%d): %s", code, raw)
	}

	// Unrefreshed write + ?realtime=false across HEAD, GET _doc, GET _source, _mget
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPut, "/crud_idx/_doc/d1?refresh=false", `{
		"stored_kw":"sv1",
		"plain_kw":"pv1",
		"short_str":"too_long_for_ignore_above"
	}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("PUT d1 failed (%d): %s", code, raw)
	}
	if c, _, _, _ := doReqR61CRUDTest(t, h, http.MethodHead, "/crud_idx/_doc/d1?realtime=false", "", nil); c != http.StatusNotFound {
		t.Fatalf("HEAD ?realtime=false before refresh expected 404, got %d", c)
	}
	if c, _, _, _ := doReqR61CRUDTest(t, h, http.MethodGet, "/crud_idx/_doc/d1?realtime=false", "", nil); c != http.StatusNotFound {
		t.Fatalf("GET _doc ?realtime=false before refresh expected 404, got %d", c)
	}
	if c, _, _, _ := doReqR61CRUDTest(t, h, http.MethodGet, "/crud_idx/_source/d1?realtime=false", "", nil); c != http.StatusNotFound {
		t.Fatalf("GET _source ?realtime=false before refresh expected 404, got %d", c)
	}
	code, _, mgetUnref, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/crud_idx/_mget?realtime=false", `{"ids":["d1"]}`, nil)
	if code != http.StatusOK || !strings.Contains(raw, `"found":false`) {
		t.Fatalf("_mget ?realtime=false before refresh expected found:false (%d, %v): %s", code, mgetUnref, raw)
	}
	// ?realtime=false&refresh=true refreshes first and returns 200
	code, _, getRef, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/crud_idx/_doc/d1?realtime=false&refresh=true", "", nil)
	if code != http.StatusOK || getRef["found"] != true {
		t.Fatalf("GET ?realtime=false&refresh=true expected 200 found:true (%d): %s", code, raw)
	}
	// _ignored returned when stored_fields=_ignored (`get/120_stored_fields_ignored.yml`)
	code, _, getIgn, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/crud_idx/_doc/d1?stored_fields=_ignored", "", nil)
	if code != http.StatusOK || getIgn["_ignored"] == nil {
		t.Fatalf("expected top-level _ignored array when stored_fields=_ignored on doc exceeding ignore_above (%d): %s", code, raw)
	}

	// Read version + version_type=external exact equality
	code, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/crud_idx/_doc/d1?version=5&version_type=external", "", nil)
	if code != http.StatusConflict {
		t.Fatalf("expected 409 on read version mismatch with version_type=external, got %d", code)
	}
	code, _, _, _ = doReqR61CRUDTest(t, h, http.MethodGet, "/crud_idx/_doc/d1?version=1&version_type=external", "", nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on read version match with version_type=external, got %d", code)
	}

	// stored_fields suppresses default _source, filters to store:true, handles _none_, and records field usage
	code, _, sfResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/crud_idx/_doc/d1?stored_fields=stored_kw,plain_kw", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET stored_fields failed (%d): %s", code, raw)
	}
	if sfResp["_source"] != nil {
		t.Fatalf("expected _source suppressed when stored_fields specified without _source: %s", raw)
	}
	fMap, _ := sfResp["fields"].(map[string]any)
	if fMap["stored_kw"] == nil || fMap["plain_kw"] != nil {
		t.Fatalf("expected only store:true field stored_kw in fields: %s", raw)
	}
	code, _, noneResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/crud_idx/_doc/d1?stored_fields=_none_", "", nil)
	if code != http.StatusOK || noneResp["_source"] != nil || noneResp["fields"] != nil {
		t.Fatalf("expected stored_fields=_none_ to omit both _source and fields (%d): %s", code, raw)
	}

	// stored_fields=_ignored on doc without ignored fields -> top-level _ignored: null
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/crud_idx/_doc/d2?refresh=true", `{"short_str":"ok"}`, nil)
	code, _, ignNullResp, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/crud_idx/_doc/d2?stored_fields=_ignored", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET d2 stored_fields=_ignored failed (%d): %s", code, raw)
	}
	if val, exists := ignNullResp["_ignored"]; !exists || val != nil {
		t.Fatalf("expected top-level _ignored=null when doc has no ignored fields: %s", raw)
	}

	// ES 8 _mget rejects removed _type / _routing / _version
	for _, badBody := range []string{
		`{"docs":[{"_index":"crud_idx","_type":"_doc","_id":"d1"}]}`,
		`{"docs":[{"_index":"crud_idx","_id":"d1","_routing":"r1"}]}`,
		`{"docs":[{"_index":"crud_idx","_id":"d1","_version":1}]}`,
	} {
		c, _, _, rw := doReqR61CRUDTest(t, h, http.MethodPost, "/_mget", badBody, nil)
		if c != http.StatusBadRequest {
			t.Fatalf("expected 400 on ES 8 _mget body %s, got %d: %s", badBody, c, rw)
		}
	}
}

func TestRound61ServerCRUD_F8_StatefulScrollAndMSearchErrorMetadata(t *testing.T) {
	_, h := newServerR61CRUDTest(t, "8.15.5")

	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/scr_idx", `{"mappings":{"properties":{"n":{"type":"integer"}}}}`, nil)
	for i := 1; i <= 5; i++ {
		_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, fmt.Sprintf("/scr_idx/_doc/%d?refresh=true", i), fmt.Sprintf(`{"n":%d}`, i), nil)
	}

	// Keep alive > max_keep_alive (5m) formatted as (5m) not (5m0s)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_cluster/settings", `{"persistent":{"search.max_keep_alive":"5m"}}`, nil)
	code, _, _, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/scr_idx/_search?scroll=10m", `{"size":2}`, nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "(5m)") || strings.Contains(raw, "5m0s") {
		t.Fatalf("expected Keep alive error with (5m), got (%d): %s", code, raw)
	}

	// Start scroll (size=2 over 5 docs), then index doc 6 AFTER scroll started -> must NOT appear in scroll pages!
	code, _, p1, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/scr_idx/_search?scroll=1m", `{"size":2,"sort":[{"n":"asc"}]}`, nil)
	if code != http.StatusOK {
		t.Fatalf("initial scroll search failed (%d): %s", code, raw)
	}
	initialScrollID, _ := p1["_scroll_id"].(string)
	if initialScrollID == "" {
		t.Fatalf("missing _scroll_id: %s", raw)
	}
	// Index post-snapshot doc 6
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/scr_idx/_doc/6?refresh=true", `{"n":6}`, nil)

	// Reuse the EXACT SAME initialScrollID across pages 2, 3, and 4!
	var seenIDs []string
	collectHits := func(resp map[string]any) int {
		hm, _ := resp["hits"].(map[string]any)
		hl, _ := hm["hits"].([]any)
		for _, item := range hl {
			m, _ := item.(map[string]any)
			seenIDs = append(seenIDs, fmt.Sprintf("%v", m["_id"]))
		}
		return len(hl)
	}
	if n := collectHits(p1); n != 2 {
		t.Fatalf("page 1 expected 2 hits, got %d", n)
	}
	code, _, p2, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll":"1m","scroll_id":%q}`, initialScrollID), nil)
	if code != http.StatusOK || collectHits(p2) != 2 {
		t.Fatalf("page 2 reusing initialScrollID expected 2 hits (%d): %s", code, raw)
	}
	code, _, p3, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll":"1m","scroll_id":%q}`, initialScrollID), nil)
	if code != http.StatusOK || collectHits(p3) != 1 {
		t.Fatalf("page 3 reusing initialScrollID expected 1 hit (doc 6 excluded by snapshot!) (%d): %s", code, raw)
	}
	code, _, p4, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll":"1m","scroll_id":%q}`, initialScrollID), nil)
	if code != http.StatusOK || collectHits(p4) != 0 {
		t.Fatalf("page 4 reusing initialScrollID expected 0 hits (%d): %s", code, raw)
	}
	if strings.Join(seenIDs, ",") != "1,2,3,4,5" {
		t.Fatalf("expected exact snapshot pages 1,2,3,4,5, got %v", seenIDs)
	}

	// _msearch per-item error index & index_uuid metadata
	msearchBody := "{\"index\":\"no_such_msearch_idx\"}\n{\"query\":{\"match_all\":{}}}\n"
	code, _, msResp, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/_msearch", msearchBody, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_msearch failed (%d): %s", code, raw)
	}
	resps, _ := msResp["responses"].([]any)
	firstErrItem, _ := resps[0].(map[string]any)
	msErrObj, _ := firstErrItem["error"].(map[string]any)
	if msErrObj["index"] != "no_such_msearch_idx" || msErrObj["index_uuid"] != "_na_" {
		t.Fatalf("expected index & index_uuid=_na_ on _msearch error: %s", raw)
	}
}

func TestRound61ServerCRUD_F12_F14_DenseVectorAutoDimsAndTSDBWriteSearchGuards(t *testing.T) {
	_, h := newServerR61CRUDTest(t, "8.15.5")

	// ES 8 dynamic [128] float array -> dense_vector; AutoDims locks dims on explicit dimless dense_vector
	vec128 := make([]string, 128)
	for i := range vec128 {
		vec128[i] = "0.125"
	}
	code, _, _, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/vec_dyn/_doc/1?refresh=true", fmt.Sprintf(`{"emb":[%s]}`, strings.Join(vec128, ",")), nil)
	if code != http.StatusCreated {
		t.Fatalf("dynamic 128-float doc failed (%d): %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodGet, "/vec_dyn/_mapping", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, `"dense_vector"`) {
		t.Fatalf("expected ES 8 dynamic 128-float array mapped to dense_vector (%d): %s", code, raw)
	}

	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/vec_auto", `{"mappings":{"properties":{"v":{"type":"dense_vector"}}}}`, nil)
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPut, "/vec_auto/_doc/1?refresh=true", `{"v":[0.1,0.2,0.3]}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("AutoDims first 3-dim doc failed (%d): %s", code, raw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPut, "/vec_auto/_doc/2?refresh=true", `{"v":[0.1,0.2]}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 when indexing 2-dim vector into AutoDims-locked 3-dim field, got %d: %s", code, raw)
	}

	// TSDB index creation, deterministic _id, op_type=create 409, and unsupported operations
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPut, "/ts_metrics", `{
		"settings":{
			"index":{
				"mode":"time_series",
				"routing_path":["host"],
				"time_series":{
					"start_time":"2026-01-01T00:00:00Z",
					"end_time":"2026-01-02T00:00:00Z"
				}
			}
		},
		"mappings":{
			"properties":{
				"@timestamp":{"type":"date"},
				"host":{"type":"keyword","time_series_dimension":true},
				"cpu":{"type":"double","time_series_metric":"gauge"}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /ts_metrics failed (%d): %s", code, raw)
	}

	// Explicit _id, explicit routing, alias routing, and _update rejected on time_series
	if c, _, _, rw := doReqR61CRUDTest(t, h, http.MethodPut, "/ts_metrics/_doc/custom_id", `{"@timestamp":"2026-01-01T01:00:00Z","host":"h1","cpu":0.5}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for explicit _id on TSDB, got %d: %s", c, rw)
	}
	if c, _, _, rw := doReqR61CRUDTest(t, h, http.MethodPost, "/ts_metrics/_doc?routing=r1", `{"@timestamp":"2026-01-01T01:00:00Z","host":"h1","cpu":0.5}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for explicit routing on TSDB write, got %d: %s", c, rw)
	}
	if c, _, _, rw := doReqR61CRUDTest(t, h, http.MethodPut, "/ts_metrics/_alias/a_rot", `{"routing":"r1"}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for alias routing on TSDB, got %d: %s", c, rw)
	}

	// POST /ts_metrics/_doc (index) succeeds; POST /ts_metrics/_create (or bulk create) on same series+@timestamp returns 409!
	tsDoc := `{"@timestamp":"2026-01-01T01:00:00Z","host":"h1","cpu":0.5}`
	code, _, w1, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/ts_metrics/_doc?refresh=true", tsDoc, nil)
	if code != http.StatusCreated {
		t.Fatalf("POST /ts_metrics/_doc failed (%d): %s", code, raw)
	}
	detID := fmt.Sprintf("%v", w1["_id"])
	bulkCreateDup := fmt.Sprintf("{\"create\":{\"_index\":\"ts_metrics\"}}\n%s\n", tsDoc)
	code, _, bcResp, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/_bulk", bulkCreateDup, nil)
	if code != http.StatusOK || bcResp["errors"] != true || !strings.Contains(raw, "409") {
		t.Fatalf("expected 409 duplicate series+timestamp on bulk create (%d): %s", code, raw)
	}
	if c, _, _, rw := doReqR61CRUDTest(t, h, http.MethodPost, "/ts_metrics/_update/"+detID, `{"doc":{"cpu":0.9}}`, nil); c != http.StatusBadRequest || !strings.Contains(rw, "time series mode") {
		t.Fatalf("expected 400 on TSDB _update, got %d: %s", c, rw)
	}

	// TSDB search restrictions: routing, sort by _id, terms agg on _id
	for _, tc := range []struct{ p, b string }{
		{"/ts_metrics/_search?routing=r1", `{}`},
		{"/ts_metrics/_search", `{"sort":"_id"}`},
		{"/ts_metrics/_search", `{"aggs":{"by_id":{"terms":{"field":"_id"}}}}`},
	} {
		if c, _, _, rw := doReqR61CRUDTest(t, h, http.MethodPost, tc.p, tc.b, nil); c != http.StatusBadRequest {
			t.Fatalf("expected 400 for TSDB search %s %s, got %d: %s", tc.p, tc.b, c, rw)
		}
	}

	// TSDB UBQ dimension / @timestamp immutability -> 400
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPost, "/ts_metrics/_update_by_query", `{"script":{"source":"ctx._source.host = 'h2'"}}`, nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "time_series_dimension") {
		t.Fatalf("expected 400 mutating TSDB dimension in UBQ, got %d: %s", code, raw)
	}
}

func TestRound61ServerCRUD_F20_To_F28_ReindexWhitelistByQueryRuntimeCyclesUpdateAndBulk(t *testing.T) {
	srv, h := newServerR61CRUDTest(t, "8.15.5")

	// SetRemoteReindexWhitelistForTest: default empty whitelist rejects remote host; setting whitelist permits past whitelist check
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/re_dst", `{}`, nil)
	code, _, _, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/_reindex", `{
		"source":{"remote":{"host":"http://conformance.local:9200"},"index":"src"},
		"dest":{"index":"re_dst"}
	}`, nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "whitelisted") {
		t.Fatalf("expected default empty reindex.remote.whitelist to reject remote host (%d): %s", code, raw)
	}
	srv.SetRemoteReindexWhitelistForTest("127.0.0.1:*,conformance.local:*")
	srv.SetRemoteReindexTransport(roundTripperFuncR61CRUDTest(func(req *http.Request) (*http.Response, error) {
		body := `{"_scroll_id":"s1","hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}))
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPost, "/_reindex", `{
		"source":{"remote":{"host":"http://conformance.local:9200"},"index":"src"},
		"dest":{"index":"re_dst"}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected whitelisted remote _reindex to succeed (%d): %s", code, raw)
	}

	// Runtime mappings Painless cycle rejected in PUT /{index} and PUT /{index}/_mapping
	cycBody := `{"mappings":{"runtime":{"a":{"type":"keyword","script":"emit(doc['b'].value)"},"b":{"type":"keyword","script":"emit(doc['a'].value)"}}}}`
	if c, _, _, rw := doReqR61CRUDTest(t, h, http.MethodPut, "/rt_cyc", cycBody, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on runtime mapping cycle in create_index, got %d: %s", c, rw)
	}
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/rt_ok", `{}`, nil)
	if c, _, _, rw := doReqR61CRUDTest(t, h, http.MethodPut, "/rt_ok/_mapping", `{"runtime":{"a":{"type":"keyword","script":"emit(doc['b'].value)"},"b":{"type":"keyword","script":"emit(doc['a'].value)"}}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on runtime mapping cycle in put_mapping, got %d: %s", c, rw)
	}

	// _update unknown field validation + Painless field(...) API in _update & UBQ + UBQ FieldAddedAtSeqNo (30_new_fields)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/ubq_idx", `{"mappings":{"properties":{"a":{"type":"keyword"}}}}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/ubq_idx/_doc/1?refresh=true", `{"a":"v1","late_f":"before_mapping"}`, nil)
	// Add late_f via PUT _mapping AFTER doc 1 was indexed -> without UBQ, term query on late_f misses doc 1; after UBQ, doc 1 is reindexed and matches!
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/ubq_idx/_mapping", `{"properties":{"late_f":{"type":"keyword"},"cnt":{"type":"integer"}}}`, nil)

	if c, _, _, rw := doReqR61CRUDTest(t, h, http.MethodPost, "/ubq_idx/_update/1", `{"scrip":{"source":"ctx._op='noop'"}}`, nil); c != http.StatusBadRequest || !strings.Contains(rw, "did you mean [script]") {
		t.Fatalf("expected UpdateRequest unknown field did-you-mean error, got %d: %s", c, rw)
	}
	code, _, _, raw = doReqR61CRUDTest(t, h, http.MethodPost, "/ubq_idx/_update/1?refresh=true", `{"script":{"source":"field('cnt').set(42)"}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("_update with field('cnt').set(42) failed (%d): %s", code, raw)
	}
	code, _, ubqResp, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/ubq_idx/_update_by_query?refresh=true&slices=auto", `{"script":{"source":"field('cnt').set(field('cnt').get(0) + 8)"}}`, nil)
	if code != http.StatusOK || fmt.Sprintf("%v", ubqResp["updated"]) != "1" {
		t.Fatalf("UBQ with field(...) API failed (%d): %s", code, raw)
	}
	code, _, getAfterUBQ, raw := doReqR61CRUDTest(t, h, http.MethodGet, "/ubq_idx/_doc/1", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET after UBQ failed (%d): %s", code, raw)
	}
	srcAfter, _ := getAfterUBQ["_source"].(map[string]any)
	if fmt.Sprintf("%v", srcAfter["cnt"]) != "50" {
		t.Fatalf("expected cnt=50 after _update (42) + UBQ (+8), got %v: %s", srcAfter["cnt"], raw)
	}

	// _bulk: deprecated ?type= in ES 8 -> 400; post-ingest reroute + require_alias; list_executed_pipelines=true on failure; upsert ingest drop -> noop; dynamic mapping per-item error isolation
	if c, _, _, rw := doReqR61CRUDTest(t, h, http.MethodPost, "/_bulk?type=_doc", "{\"index\":{\"_index\":\"ubq_idx\",\"_id\":\"2\"}}\n{\"a\":\"x\"}\n", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on ES 8 _bulk?type=_doc, got %d: %s", c, rw)
	}
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/alias_target_idx", `{"aliases":{"valid_alias":{}},"mappings":{"dynamic":"strict","properties":{"ok_field":{"type":"keyword"}}}}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_ingest/pipeline/reroute_to_alias", `{"processors":[{"set":{"field":"_index","value":"valid_alias"}}]}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_ingest/pipeline/fail_pipe", `{"processors":[{"fail":{"message":"boom_pipe"}}]}`, nil)
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/_ingest/pipeline/drop_pipe", `{"processors":[{"drop":{}}]}`, nil)

	bulkComplex := strings.Join([]string{
		`{"index":{"_index":"not_an_alias_yet","_id":"r1","pipeline":"reroute_to_alias","require_alias":true}}`,
		`{"ok_field":"yes"}`,
		`{"index":{"_index":"alias_target_idx","_id":"f1","pipeline":"fail_pipe"}}`,
		`{"ok_field":"fail_me"}`,
		`{"update":{"_index":"alias_target_idx","_id":"u_drop"}}`,
		`{"doc":{"ok_field":"dropped"},"doc_as_upsert":true}`,
		`{"index":{"_index":"alias_target_idx","_id":"bad_dyn"}}`,
		`{"explode_field":"bad"}`,
		`{"index":{"_index":"alias_target_idx","_id":"good_sibling"}}`,
		`{"ok_field":"survived"}`,
	}, "\n") + "\n"
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/alias_target_idx/_settings", `{"index.default_pipeline":"drop_pipe"}`, nil)
	// Clear default_pipeline for non-drop test first, test drop separately:
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/alias_target_idx/_settings", `{"index.default_pipeline":"_none"}`, nil)

	code, _, bResp, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/_bulk?list_executed_pipelines=true&refresh=true", bulkComplex, nil)
	if code != http.StatusOK {
		t.Fatalf("complex _bulk failed (%d): %s", code, raw)
	}
	bItems, _ := bResp["items"].([]any)
	if len(bItems) != 5 {
		t.Fatalf("expected 5 bulk items, got %d: %s", len(bItems), raw)
	}
	it0, _ := bItems[0].(map[string]any)["index"].(map[string]any)
	if fmt.Sprintf("%v", it0["status"]) != "201" || it0["_index"] != "alias_target_idx" {
		t.Fatalf("item 0 (post-ingest reroute to valid_alias with require_alias=true) expected 201 on alias_target_idx: %v", it0)
	}
	it1, _ := bItems[1].(map[string]any)["index"].(map[string]any)
	if it1["error"] == nil || it1["executed_pipelines"] == nil {
		t.Fatalf("item 1 (failed pipeline with list_executed_pipelines=true) expected executed_pipelines: %v", it1)
	}
	it3, _ := bItems[3].(map[string]any)["index"].(map[string]any)
	if fmt.Sprintf("%v", it3["status"]) != "400" {
		t.Fatalf("item 3 (dynamic_template error) expected per-item 400, got %v", it3)
	}
	it4, _ := bItems[4].(map[string]any)["index"].(map[string]any)
	if fmt.Sprintf("%v", it4["status"]) != "201" {
		t.Fatalf("item 4 (good sibling after dynamic_template error) expected 201, got %v", it4)
	}

	// Bulk upsert with default_pipeline drop -> 200 noop
	_, _, _, _ = doReqR61CRUDTest(t, h, http.MethodPut, "/drop_upsert_idx", `{"settings":{"index.default_pipeline":"drop_pipe"}}`, nil)
	code, _, dropBulkResp, raw := doReqR61CRUDTest(t, h, http.MethodPost, "/_bulk", "{\"update\":{\"_index\":\"drop_upsert_idx\",\"_id\":\"1\"}}\n{\"doc\":{\"x\":1},\"doc_as_upsert\":true}\n", nil)
	if code != http.StatusOK || dropBulkResp["errors"] != false || !strings.Contains(raw, `"noop"`) {
		t.Fatalf("expected bulk upsert drop pipeline to return 200 noop (%d): %s", code, raw)
	}
}

type roundTripperFuncR61CRUDTest func(*http.Request) (*http.Response, error)

func (f roundTripperFuncR61CRUDTest) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
