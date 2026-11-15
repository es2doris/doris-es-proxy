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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newRound60MemoryServer(t *testing.T, esVer string) (*Server, http.Handler) {
	t.Helper()
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	if esVer != "" {
		srv.SetTargetESVersion(esVer)
	}
	return srv, srv.Handler()
}

func doRound60Req(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) (int, http.Header, map[string]any, string) {
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

func mustInt64Round60(t *testing.T, v any) int64 {
	t.Helper()
	switch tv := v.(type) {
	case json.Number:
		n, err := tv.Int64()
		if err != nil {
			t.Fatalf("expected int64 json.Number, got %v (%v)", tv, err)
		}
		return n
	case float64:
		return int64(tv)
	case int64:
		return tv
	case int:
		return int64(tv)
	default:
		t.Fatalf("expected integer value, got %T (%v)", v, v)
		return 0
	}
}

func TestRound60_F2_MonotonicVersionSeqNoDeleteResetForcedRefreshAndRouting(t *testing.T) {
	_, h := newRound60MemoryServer(t, "7.10.2")

	// Create index with 3 shards to test custom Murmur3 UTF-16LE shard routing isolation.
	code, _, _, raw := doRound60Req(t, h, http.MethodPut, "/r60_crud", `{
		"settings": {"number_of_shards": 3, "number_of_replicas": 0}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", code, raw)
	}

	// 1. Create doc "1": _version=1, _seq_no=0, forced_refresh=true when refresh=true
	code, _, m, raw := doRound60Req(t, h, http.MethodPut, "/r60_crud/_doc/1?refresh=true", `{"msg":"v1"}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", code, raw)
	}
	if mustInt64Round60(t, m["_version"]) != 1 || mustInt64Round60(t, m["_seq_no"]) != 0 || m["forced_refresh"] != true || m["_type"] != "_doc" {
		t.Fatalf("unexpected create meta: %s", raw)
	}

	// 2. Overwrite doc "1" with refresh=wait_for -> _version=2, _seq_no=1, forced_refresh=false
	code, _, m, raw = doRound60Req(t, h, http.MethodPut, "/r60_crud/_doc/1?refresh=wait_for", `{"msg":"v2"}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", code, raw)
	}
	if mustInt64Round60(t, m["_version"]) != 2 || mustInt64Round60(t, m["_seq_no"]) != 1 || m["forced_refresh"] != false {
		t.Fatalf("unexpected overwrite meta: %s", raw)
	}

	// 3. Update doc "1" (noop) with refresh=true -> forced_refresh=false, version stays 2
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/r60_crud/_update/1?refresh=true", `{"doc":{"msg":"v2"}}`, nil)
	if code != http.StatusOK || m["result"] != "noop" || m["forced_refresh"] != false || mustInt64Round60(t, m["_version"]) != 2 {
		t.Fatalf("unexpected noop update meta: %d %s", code, raw)
	}

	// 4. Delete doc "1" with refresh=true -> _version=3, _seq_no=2, forced_refresh=true
	code, _, m, raw = doRound60Req(t, h, http.MethodDelete, "/r60_crud/_doc/1?refresh=true", "", nil)
	if code != http.StatusOK || m["result"] != "deleted" || mustInt64Round60(t, m["_version"]) != 3 || mustInt64Round60(t, m["_seq_no"]) != 2 || m["forced_refresh"] != true {
		t.Fatalf("unexpected delete meta: %d %s", code, raw)
	}

	// 5. Re-create deleted doc "1" -> _version resets to 1, _seq_no advances to 3!
	code, _, m, raw = doRound60Req(t, h, http.MethodPut, "/r60_crud/_doc/1?refresh=true", `{"msg":"reborn"}`, nil)
	if code != http.StatusCreated || mustInt64Round60(t, m["_version"]) != 1 || mustInt64Round60(t, m["_seq_no"]) != 3 {
		t.Fatalf("expected re-created doc _version=1 and _seq_no=3, got %d %s", code, raw)
	}
	code, _, m, raw = doRound60Req(t, h, http.MethodGet, "/r60_crud/_doc/1", "", nil)
	if code != http.StatusOK || mustInt64Round60(t, m["_version"]) != 1 || mustInt64Round60(t, m["_seq_no"]) != 3 {
		t.Fatalf("GET after re-create failed: %d %s", code, raw)
	}

	// 6. _bulk delete + re-create of same _id in single batch resets _version=1 and remains visible in GET & _search
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"r60_crud","_id":"1"}}`,
		`{"msg":"v2_before_bulk_del"}`,
		`{"delete":{"_index":"r60_crud","_id":"1"}}`,
		`{"index":{"_index":"r60_crud","_id":"1"}}`,
		`{"msg":"bulk_reborn"}`,
	}, "\n") + "\n"
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/_bulk?refresh=true", bulkBody, nil)
	if code != http.StatusOK || m["errors"] != false {
		t.Fatalf("bulk delete+recreate failed: %d %s", code, raw)
	}
	items := m["items"].([]any)
	lastIdxItem := items[2].(map[string]any)["index"].(map[string]any)
	if mustInt64Round60(t, lastIdxItem["_version"]) != 1 || lastIdxItem["result"] != "created" {
		t.Fatalf("expected bulk re-created doc _version=1 created, got %v", lastIdxItem)
	}
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/r60_crud/_search", `{"query":{"term":{"_id":"1"}}}`, nil)
	if code != http.StatusOK || mustInt64Round60(t, m["hits"].(map[string]any)["total"].(map[string]any)["value"]) != 1 {
		t.Fatalf("expected bulk re-created doc visible in _search, got %d %s", code, raw)
	}

	// 7. version=0 with external/external_gte allowed; op_type=create + external rejected (400)
	code, _, m, raw = doRound60Req(t, h, http.MethodPut, "/r60_crud/_doc/ext0?version=0&version_type=external", `{"v":0}`, nil)
	if code != http.StatusCreated || mustInt64Round60(t, m["_version"]) != 0 {
		t.Fatalf("expected version=0 external to succeed, got %d %s", code, raw)
	}
	code, _, _, raw = doRound60Req(t, h, http.MethodPut, "/r60_crud/_create/ext_bad?version=1&version_type=external", `{"v":1}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for _create + version_type=external, got %d %s", code, raw)
	}

	// 8. Custom routing shard isolation on 3-shard index: find a routing value landing on a different shard than docID "rt_doc"
	docShard := esMurmur3Shard("rt_doc", 3, defaultESRoutingNumShards(3))
	customRouting := ""
	for i := 0; i < 50; i++ {
		cand := fmt.Sprintf("route_%d", i)
		if esMurmur3Shard(cand, 3, defaultESRoutingNumShards(3)) != docShard {
			customRouting = cand
			break
		}
	}
	if customRouting == "" {
		t.Fatal("failed to find distinct shard routing")
	}
	code, _, _, raw = doRound60Req(t, h, http.MethodPut, "/r60_crud/_doc/rt_doc?routing="+customRouting+"&refresh=true", `{"k":"routed"}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("routed put failed: %d %s", code, raw)
	}
	if c, _, _, _ := doRound60Req(t, h, http.MethodGet, "/r60_crud/_doc/rt_doc", "", nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 GET without routing on multi-shard index, got %d", c)
	}
	if c, _, _, _ := doRound60Req(t, h, http.MethodGet, "/r60_crud/_doc/rt_doc?routing="+customRouting, "", nil); c != http.StatusOK {
		t.Fatalf("expected 200 GET with matching routing, got %d", c)
	}

	// 9. 404-before-400 on _source when _source.enabled=false, and 404-before-409 on _update missing doc with if_seq_no
	doRound60Req(t, h, http.MethodPut, "/r60_nosrc", `{"mappings":{"_source":{"enabled":false}}}`, nil)
	if c, _, _, _ := doRound60Req(t, h, http.MethodGet, "/r60_nosrc/_source/missing", "", nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 before 400 on missing doc _source, got %d", c)
	}
	if c, _, _, _ := doRound60Req(t, h, http.MethodPost, "/r60_crud/_update/missing_upd?if_seq_no=0&if_primary_term=1", `{"doc":{"a":1}}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 before 409 on missing doc _update with if_seq_no, got %d", c)
	}

	// 10. refresh_interval: -1 unrefreshed buffer overlay
	doRound60Req(t, h, http.MethodPut, "/r60_norefresh", `{"settings":{"refresh_interval":"-1"}}`, nil)
	doRound60Req(t, h, http.MethodPut, "/r60_norefresh/_doc/u1", `{"x":1}`, nil)
	code, _, m, _ = doRound60Req(t, h, http.MethodPost, "/r60_norefresh/_search", `{}`, nil)
	if code != http.StatusOK || mustInt64Round60(t, m["hits"].(map[string]any)["total"].(map[string]any)["value"]) != 0 {
		t.Fatalf("expected 0 search hits before _refresh on refresh_interval=-1, got %v", m)
	}
	doRound60Req(t, h, http.MethodPost, "/r60_norefresh/_refresh", "", nil)
	code, _, m, _ = doRound60Req(t, h, http.MethodPost, "/r60_norefresh/_search", `{}`, nil)
	if code != http.StatusOK || mustInt64Round60(t, m["hits"].(map[string]any)["total"].(map[string]any)["value"]) != 1 {
		t.Fatalf("expected 1 search hit after _refresh on refresh_interval=-1, got %v", m)
	}
}

func TestRound60_F3_MGetNumericIDsBulkValidationAndAliasWriteErrors(t *testing.T) {
	_, h := newRound60MemoryServer(t, "8.15.5")

	doRound60Req(t, h, http.MethodPut, "/r60_mget", `{}`, nil)
	doRound60Req(t, h, http.MethodPut, "/r60_mget/_doc/1?refresh=true", `{"title":"hello world"}`, nil)
	doRound60Req(t, h, http.MethodPut, "/r60_mget/_doc/2?refresh=true", `{"title":"hello there"}`, nil)

	// Numeric IDs in _mget ids and docs
	code, _, m, raw := doRound60Req(t, h, http.MethodPost, "/r60_mget/_mget", `{"ids":[1, 2]}`, nil)
	if code != http.StatusOK || len(m["docs"].([]any)) != 2 {
		t.Fatalf("_mget numeric ids failed: %d %s", code, raw)
	}
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/_mget", `{"docs":[{"_index":"r60_mget","_id":1,"routing":2}]}`, nil)
	if code != http.StatusOK || m["docs"].([]any)[0].(map[string]any)["found"] != true {
		t.Fatalf("_mget numeric _id/routing failed: %d %s", code, raw)
	}
	// ES8 mode omits _type
	if _, hasType := m["docs"].([]any)[0].(map[string]any)["_type"]; hasType {
		t.Fatalf("expected ES8 mode to omit _type in _mget response, got %s", raw)
	}

	// _bulk empty _id: "" -> 200 with per-item 400 error (upstream bulk/10_basic.yml); empty {} metadata -> 400 Malformed action/metadata line
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/_bulk", "{\"index\":{\"_index\":\"r60_mget\",\"_id\":\"\"}}\n{\"a\":1}\n", nil)
	if code != http.StatusOK || m["errors"] != true || !strings.Contains(raw, "if _id is specified it must not be empty") {
		t.Fatalf("expected 200 with per-item 400 error on explicit empty _id in _bulk, got %d %s", code, raw)
	}
	code, _, _, raw = doRound60Req(t, h, http.MethodPost, "/_bulk", "{}\n{\"a\":1}\n", nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "Malformed action/metadata line [1]") {
		t.Fatalf("expected 400 Malformed action/metadata line [1], got %d %s", code, raw)
	}

	// ?require_alias=true on missing target & concrete index -> 404; multi-index alias without write index -> 400
	if c, _, _, _ := doRound60Req(t, h, http.MethodPut, "/missing_al/_doc/1?require_alias=true", `{"a":1}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 for require_alias=true on missing alias, got %d", c)
	}
	if c, _, _, _ := doRound60Req(t, h, http.MethodPut, "/r60_mget/_doc/1?require_alias=true", `{"a":1}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 for require_alias=true on concrete index, got %d", c)
	}
	doRound60Req(t, h, http.MethodPut, "/r60_mget_2", `{}`, nil)
	doRound60Req(t, h, http.MethodPost, "/_aliases", `{"actions":[{"add":{"indices":["r60_mget","r60_mget_2"],"alias":"r60_multi_al"}}]}`, nil)
	code, _, _, raw = doRound60Req(t, h, http.MethodPost, "/r60_multi_al/_doc", `{"a":1}`, nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "no write index is defined for alias [r60_multi_al]") {
		t.Fatalf("expected 400 no write index for multi-index alias, got %d %s", code, raw)
	}
}

func TestRound60_F4_F5_F6_CatTextDefaultTemplatesAliasesStatsAndNodes(t *testing.T) {
	_, h := newRound60MemoryServer(t, "8.15.5")

	doRound60Req(t, h, http.MethodPut, "/vis_idx", `{}`, nil)
	doRound60Req(t, h, http.MethodPut, "/.hidden_sys", `{}`, nil)

	// F4: Default _cat/indices is text/plain, space-padded, excludes .hidden by default
	code, hdr, _, raw := doRound60Req(t, h, http.MethodGet, "/_cat/indices?v=true", "", nil)
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/plain") {
		t.Fatalf("expected text/plain default on _cat/indices, got %d %v", code, hdr.Get("Content-Type"))
	}
	if !strings.Contains(raw, "vis_idx") || strings.Contains(raw, ".hidden_sys") {
		t.Fatalf("expected vis_idx and excluded .hidden_sys in default _cat/indices, got:\n%s", raw)
	}
	// ?help returns full column table
	code, _, _, raw = doRound60Req(t, h, http.MethodGet, "/_cat/nodes?help=true", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, "heap.percent") || !strings.Contains(raw, "uptime") {
		t.Fatalf("unexpected _cat/nodes?help=true output:\n%s", raw)
	}
	// Wildcard column selection ?h=heap.*
	code, _, _, raw = doRound60Req(t, h, http.MethodGet, "/_cat/nodes?h=heap.*&v=true", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, "heap.percent") || !strings.Contains(raw, "heap.max") {
		t.Fatalf("expected heap.* columns in _cat/nodes?h=heap.*, got:\n%s", raw)
	}
	// _cat/health?ts=false omits epoch/timestamp; invalid health -> 400
	code, _, _, raw = doRound60Req(t, h, http.MethodGet, "/_cat/health?ts=false&v=true", "", nil)
	if code != http.StatusOK || strings.Contains(raw, "epoch") || !strings.Contains(raw, "cluster") {
		t.Fatalf("expected epoch omitted when ts=false, got:\n%s", raw)
	}
	if c, _, _, _ := doRound60Req(t, h, http.MethodGet, "/_cat/health?health=purple", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid health param, got %d", c)
	}

	// F5: String index_patterns in _template and _index_template, canonical settings.index, action.auto_create_index
	code, _, _, raw = doRound60Req(t, h, http.MethodPut, "/_template/tpl_str", `{
		"index_patterns": "logs-*",
		"settings": {"number_of_shards": 2}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT _template with string index_patterns failed: %d %s", code, raw)
	}
	code, _, m, raw := doRound60Req(t, h, http.MethodGet, "/_template/tpl_str", "", nil)
	tplSettings, _ := m["tpl_str"].(map[string]any)["settings"].(map[string]any)["index"].(map[string]any)
	if code != http.StatusOK || tplSettings["number_of_shards"] != "2" {
		t.Fatalf("expected canonical settings.index.number_of_shards=\"2\", got %d %s", code, raw)
	}
	doRound60Req(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"action.auto_create_index":"false"}}`, nil)
	if c, _, _, _ := doRound60Req(t, h, http.MethodPost, "/blocked_auto/_doc", `{"a":1}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 index_not_found_exception when action.auto_create_index=false, got %d", c)
	}
	doRound60Req(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"action.auto_create_index":null}}`, nil)

	// F6: /_stats/{metric} filtering, /_nodes/{node_id}/{metric}, /_cluster/state/{metric}/{index}
	code, _, m, raw = doRound60Req(t, h, http.MethodGet, "/vis_idx/_stats/docs?human=true", "", nil)
	allPrim, _ := m["_all"].(map[string]any)["primaries"].(map[string]any)
	if code != http.StatusOK || allPrim["docs"] == nil || allPrim["indexing"] != nil {
		t.Fatalf("expected only docs metric in /_stats/docs, got %d %s", code, raw)
	}
	code, _, m, raw = doRound60Req(t, h, http.MethodGet, "/_nodes/nonexistent_node", "", nil)
	if code != http.StatusOK || len(m["nodes"].(map[string]any)) != 0 {
		t.Fatalf("expected empty nodes map for nonexistent node filter, got %d %s", code, raw)
	}
	code, _, m, raw = doRound60Req(t, h, http.MethodGet, "/_cluster/state/metadata/vis_idx", "", nil)
	mdIndices, _ := m["metadata"].(map[string]any)["indices"].(map[string]any)
	if code != http.StatusOK || mdIndices["vis_idx"] == nil || m["routing_table"] != nil {
		t.Fatalf("unexpected /_cluster/state/metadata/vis_idx: %d %s", code, raw)
	}
}

func TestRound60_F7_F8_F9_AsyncTasksSearchTotalHitsScrollAndWireCompat(t *testing.T) {
	_, h := newRound60MemoryServer(t, "7.10.2")

	doRound60Req(t, h, http.MethodPut, "/r60_src", `{}`, nil)
	doRound60Req(t, h, http.MethodPut, "/r60_src/_doc/1?refresh=true", `{"k":"v1"}`, nil)
	doRound60Req(t, h, http.MethodPut, "/r60_src/_doc/2?refresh=true", `{"k":"v2"}`, nil)

	// F7: Preflight 400 before 404 on _reindex / _delete_by_query
	if c, _, _, _ := doRound60Req(t, h, http.MethodPost, "/missing_idx/_delete_by_query?scroll_size=0", `{"query":{"match_all":{}}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 before 404 on scroll_size=0, got %d", c)
	}
	if c, _, _, raw := doRound60Req(t, h, http.MethodPost, "/_reindex", `{"source":{"remote":{"host":"http://evil.example.com:9200"},"index":"a"},"dest":{"index":"b"}}`, nil); c != http.StatusBadRequest || !strings.Contains(raw, "not whitelisted") {
		t.Fatalf("expected 400 remote not whitelisted, got %d %s", c, raw)
	}

	// Async task lifecycle: launch -> GET /_tasks/{id}?wait_for_completion=true ->slices
	code, _, m, raw := doRound60Req(t, h, http.MethodPost, "/_reindex?wait_for_completion=false&slices=2", `{
		"source": {"index": "r60_src"},
		"dest":   {"index": "r60_dst"}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("async _reindex launch failed: %d %s", code, raw)
	}
	taskID, _ := m["task"].(string)
	if !strings.HasPrefix(taskID, "doris-fe-1:") {
		t.Fatalf("expected taskID starting with doris-fe-1:, got %q", taskID)
	}
	code, _, m, raw = doRound60Req(t, h, http.MethodGet, "/_tasks/"+taskID+"?wait_for_completion=true", "", nil)
	if code != http.StatusOK || m["completed"] != true {
		t.Fatalf("GET /_tasks/%s?wait_for_completion=true failed: %d %s", taskID, code, raw)
	}
	taskResp, _ := m["response"].(map[string]any)
	if mustInt64Round60(t, taskResp["created"]) != 2 || len(taskResp["slices"].([]any)) != 2 {
		t.Fatalf("unexpected async reindex task response: %s", raw)
	}
	if c, _, _, _ := doRound60Req(t, h, http.MethodGet, "/_tasks/doris-fe-1:9999999", "", nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent task id, got %d", c)
	}

	// F8: uncreated index -> 404; rest_total_hits_as_int=true + track_total_hits=false -> -1; scroll validation
	if c, _, _, _ := doRound60Req(t, h, http.MethodPost, "/never_created_idx/_search", `{}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on uncreated concrete index _search, got %d", c)
	}
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/r60_src/_search?rest_total_hits_as_int=true", `{"track_total_hits":false}`, nil)
	if code != http.StatusOK || mustInt64Round60(t, m["hits"].(map[string]any)["total"]) != -1 {
		t.Fatalf("expected hits.total == -1 when rest_total_hits_as_int=true & track_total_hits=false, got %d %s", code, raw)
	}
	if c, _, _, _ := doRound60Req(t, h, http.MethodPost, "/r60_src/_search?scroll=0m", `{}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on scroll=0m, got %d", c)
	}
	if c, _, _, _ := doRound60Req(t, h, http.MethodPost, "/_search/scroll", `{"scroll":"1m","scroll_id":"bogus_scroll_id"}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on unknown scroll_id, got %d", c)
	}

	// F9: X-elastic-product header, compatible-with=8 negotiation & _type suppression, compatible-with=6 -> 406
	var hdr http.Header
	code, hdr, m, raw = doRound60Req(t, h, http.MethodGet, "/", "", map[string]string{
		"Accept": "application/vnd.elasticsearch+json; compatible-with=8",
	})
	if code != http.StatusOK || hdr.Get("X-elastic-product") != "Elasticsearch" || !strings.Contains(hdr.Get("Content-Type"), "compatible-with=8") || m["tagline"] != "You Know, for Search" {
		t.Fatalf("unexpected root wire negotiation: %d hdr=%v body=%s", code, hdr, raw)
	}
	if c, errHdr, _, _ := doRound60Req(t, h, http.MethodGet, "/", "", map[string]string{
		"Accept": "application/vnd.elasticsearch+json; compatible-with=6",
	}); c != http.StatusNotAcceptable || errHdr.Get("X-elastic-product") != "Elasticsearch" {
		t.Fatalf("expected 406 with X-elastic-product header for compatible-with=6, got %d %v", c, errHdr)
	}
}

func TestRound60_F26_F27_F28_F29_MustacheAndIngestConformance(t *testing.T) {
	srv, h := newRound60MemoryServer(t, "7.10.2")

	// F26: Mustache compile-time validation & lambdas (#toJson, #join, #url) & _msearch/template
	if c, _, _, _ := doRound60Req(t, h, http.MethodPost, "/_scripts/bad_mustache", `{
		"script": {"lang": "mustache", "source": "{{#unclosed}}hello"}
	}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on unclosed Mustache section at PUT _scripts, got %d", c)
	}
	doRound60Req(t, h, http.MethodPut, "/r60_tmpl_idx", `{}`, nil)
	doRound60Req(t, h, http.MethodPut, "/r60_tmpl_idx/_doc/1?refresh=true", `{"tags":["a","b"],"msg":"hello"}`, nil)
	code, _, m, raw := doRound60Req(t, h, http.MethodPost, "/r60_tmpl_idx/_search/template", `{
		"source": "{\"query\":{\"terms\":{\"tags\":{{#toJson}}tags{{/toJson}}}}}",
		"params": {"tags": ["a", "c"]}
	}`, nil)
	if code != http.StatusOK || mustInt64Round60(t, m["hits"].(map[string]any)["total"].(map[string]any)["value"]) != 1 {
		t.Fatalf("mustache #toJson search template failed: %d %s", code, raw)
	}
	if c, _, _, _ := doRound60Req(t, h, http.MethodPost, "/r60_tmpl_idx/_msearch/template", "{}\n{\"source\":\"\",\"params\":{}}\n", nil); c != http.StatusBadRequest {
		t.Fatalf("expected top-level 400 on empty source in _msearch/template, got %d", c)
	}

	// F27: Structured ingest config error header + pipeline_substitutions + /{index}/_ingest/_simulate + ES7 vs ES8 grok count
	code, _, m, raw = doRound60Req(t, h, http.MethodPut, "/_ingest/pipeline/bad_cfg", `{
		"processors": [{"set": {"tag": "t1", "value": "x"}}]
	}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing field in set processor, got %d %s", code, raw)
	}
	errHdr, _ := m["error"].(map[string]any)["header"].(map[string]any)
	if errHdr["processor_type"] != "set" || errHdr["processor_tag"] != "t1" || errHdr["property_name"] != "field" {
		t.Fatalf("expected structured error.header {set, t1, field}, got %s", raw)
	}

	// Grok builtin pattern count: 312 in ES 7.10.2, 318 in ES 8.15.5
	code, _, m, _ = doRound60Req(t, h, http.MethodGet, "/_ingest/processor/grok", "", nil)
	if code != http.StatusOK || len(m["patterns"].(map[string]any)) != 312 {
		t.Fatalf("expected 312 grok patterns in ES7 mode, got %d", len(m["patterns"].(map[string]any)))
	}
	srv.SetTargetESVersion("8.15.5")
	code, _, m, _ = doRound60Req(t, h, http.MethodGet, "/_ingest/processor/grok", "", nil)
	if code != http.StatusOK || len(m["patterns"].(map[string]any)) != 318 {
		t.Fatalf("expected 318 grok patterns in ES8 mode, got %d", len(m["patterns"].(map[string]any)))
	}

	// Pipeline cycle: PUT succeeds (200), verbose _simulate returns 200 with processor_results.0.error.reason == "Cycle detected for pipeline: outer"
	doRound60Req(t, h, http.MethodPut, "/_ingest/pipeline/inner", `{"processors":[{"pipeline":{"name":"outer"}}]}`, nil)
	code, _, _, _ = doRound60Req(t, h, http.MethodPut, "/_ingest/pipeline/outer", `{"processors":[{"pipeline":{"name":"inner"}}]}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on PUT cyclic pipeline, got %d", code)
	}
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/_ingest/pipeline/outer/_simulate?verbose=true", `{"docs":[{"_source":{"a":1}}]}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on verbose simulate of cyclic pipeline, got %d %s", code, raw)
	}
	pr := m["docs"].([]any)[0].(map[string]any)["processor_results"].([]any)
	if len(pr) != 1 || pr[0].(map[string]any)["error"].(map[string]any)["reason"] != "Cycle detected for pipeline: outer" {
		t.Fatalf("expected single cycle error in verbose simulate, got %s", raw)
	}

	// F28 & F29: processors (date .000Z + ISO week-year, html_strip \n, attachment base64, grok _grok_match_index string, missing nested path error)
	b64Hello := base64.StdEncoding.EncodeToString([]byte("Hello PDF World"))
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", fmt.Sprintf(`{
		"pipeline": {
			"processors": [
				{"date": {"field": "wy", "formats": ["YYYY-'W'ww-e"], "target_field": "wy_ts"}},
				{"html_strip": {"field": "html", "target_field": "stripped"}},
				{"attachment": {"field": "data", "indexed_chars": 5}},
				{"grok": {"field": "line", "patterns": ["NOPE", "%%{NUMBER:num:int}"], "trace_match": true}},
				{"pipeline": {"name": "sub_subst"}}
			]
		},
		"pipeline_substitutions": {
			"sub_subst": {
				"processors": [{"set": {"field": "active_pipe", "value": "{{_ingest.pipeline}}"}}]
			}
		},
		"docs": [
			{"_source": {"wy": "2020-W01-1", "html": "<p>Hi &amp; Bye</p>", "data": %q, "line": "42"}}
		]
	}`, b64Hello), nil)
	if code != http.StatusOK {
		t.Fatalf("processor suite simulate failed: %d %s", code, raw)
	}
	simDoc := m["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)
	simSrc := simDoc["_source"].(map[string]any)
	simIng := simDoc["_ingest"].(map[string]any)
	if simSrc["wy_ts"] != "2019-12-30T00:00:00.000Z" {
		t.Fatalf("expected ISO week-year 2020-W01-1 -> 2019-12-30T00:00:00.000Z, got %v", simSrc["wy_ts"])
	}
	if simSrc["stripped"] != "\nHi & Bye\n" {
		t.Fatalf("expected html_strip '\\nHi & Bye\\n', got %q", simSrc["stripped"])
	}
	if simSrc["attachment"].(map[string]any)["content"] != "Hello" {
		t.Fatalf("expected attachment content 'Hello', got %v", simSrc["attachment"])
	}
	if mustInt64Round60(t, simSrc["num"]) != 42 || simIng["_grok_match_index"] != "1" {
		t.Fatalf("expected typed grok num=42 and _grok_match_index=\"1\", got src=%v ing=%v", simSrc, simIng)
	}
	if simSrc["active_pipe"] != "sub_subst" {
		t.Fatalf("expected {{_ingest.pipeline}} == 'sub_subst', got %v", simSrc["active_pipe"])
	}
	if _, leakedPipe := simIng["pipeline"]; leakedPipe {
		t.Fatalf("expected non-verbose _ingest not to contain 'pipeline', got %v", simIng)
	}
}

func TestRound60_F10_to_F25_SchemaTranspilerAggsAndSearchPainless(t *testing.T) {
	_, h := newRound60MemoryServer(t, "8.15.5")

	// 1. F11: Empty index mapping returns `{}` (no forced `"properties": {}`).
	code, _, _, raw := doRound60Req(t, h, http.MethodPut, "/empty_idx", `{}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create empty_idx failed: %d %s", code, raw)
	}
	code, _, m, raw := doRound60Req(t, h, http.MethodGet, "/empty_idx/_mapping", "", nil)
	if code != http.StatusOK {
		t.Fatalf("get empty_idx mapping failed: %d %s", code, raw)
	}
	emptyMap := m["empty_idx"].(map[string]any)["mappings"].(map[string]any)
	if _, hasProps := emptyMap["properties"]; hasProps {
		t.Fatalf("expected empty mappings {} without properties, got %v", emptyMap)
	}

	// 2. F10 + F11 + F19: Synthetic _source, dotted properties, field meta, include_defaults, _field_caps, and dynamic evolution.
	code, _, _, raw = doRound60Req(t, h, http.MethodPut, "/syn_idx", `{
		"settings": {
			"index.max_result_window": 5
		},
		"mappings": {
			"_source": {"mode": "synthetic"},
			"properties": {
				"price": {"type": "long", "meta": {"unit": "usd"}},
				"nested_obj.label": {"type": "keyword"},
				"body": {"type": "text"}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create syn_idx failed: %d %s", code, raw)
	}

	// Index document with unsorted scalar array + new dynamic field `dyn_tag`.
	code, _, _, raw = doRound60Req(t, h, http.MethodPost, "/syn_idx/_doc/1?refresh=true", `{
		"price": [30, 10, 20],
		"nested_obj": {"label": "alpha"},
		"body": "quick brown fox jumps over lazy dog",
		"dyn_tag": "evolved"
	}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("index doc 1 failed: %d %s", code, raw)
	}
	code, _, _, raw = doRound60Req(t, h, http.MethodPost, "/syn_idx/_doc/2?refresh=true", `{
		"price": 50,
		"nested_obj": {"label": "beta"},
		"body": "quick fox jumps",
		"dyn_tag": "second"
	}`, nil)
	if code != http.StatusCreated {
		t.Fatalf("index doc 2 failed: %d %s", code, raw)
	}

	// GET _doc/1 -> synthetic _source sorts scalar array `[10, 20, 30]`.
	code, _, m, raw = doRound60Req(t, h, http.MethodGet, "/syn_idx/_doc/1", "", nil)
	if code != http.StatusOK {
		t.Fatalf("get syn_idx/1 failed: %d %s", code, raw)
	}
	src1 := m["_source"].(map[string]any)
	prices := src1["price"].([]any)
	if len(prices) != 3 || mustInt64Round60(t, prices[0]) != 10 || mustInt64Round60(t, prices[1]) != 20 || mustInt64Round60(t, prices[2]) != 30 {
		t.Fatalf("expected synthetic _source sorted price [10,20,30], got %v", prices)
	}

	// F10: Dynamic field `dyn_tag` evolved into mapping on pre-mapped index!
	code, _, m, raw = doRound60Req(t, h, http.MethodGet, "/syn_idx/_mapping/field/price?include_defaults=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("get field mapping failed: %d %s", code, raw)
	}
	priceDef := m["syn_idx"].(map[string]any)["mappings"].(map[string]any)["price"].(map[string]any)["mapping"].(map[string]any)["price"].(map[string]any)
	if priceDef["coerce"] != true || priceDef["doc_values"] != true || priceDef["meta"].(map[string]any)["unit"] != "usd" {
		t.Fatalf("expected include_defaults + meta on price field mapping, got %v", priceDef)
	}

	// F19: _field_caps includes `meta` and `include_unmapped` `indices`.
	code, _, m, raw = doRound60Req(t, h, http.MethodGet, "/syn_idx/_field_caps?fields=price,missing_f&include_unmapped=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("field_caps failed: %d %s", code, raw)
	}
	fcFields := m["fields"].(map[string]any)
	priceMeta := fcFields["price"].(map[string]any)["long"].(map[string]any)["meta"].(map[string]any)
	if priceMeta["unit"].([]any)[0] != "usd" {
		t.Fatalf("expected _field_caps meta unit=[usd], got %v", priceMeta)
	}
	unmappedEntry := fcFields["missing_f"].(map[string]any)["unmapped"].(map[string]any)
	if len(unmappedEntry["indices"].([]any)) != 1 {
		t.Fatalf("expected unmapped entry indices=[syn_idx], got %v", unmappedEntry)
	}

	// F19: index.max_result_window=5 rejects from+size=6 with 400.
	code, _, _, _ = doRound60Req(t, h, http.MethodPost, "/syn_idx/_search", `{"from": 2, "size": 4}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 when exceeding index.max_result_window=5, got %d", code)
	}

	// F17: URI _source_includes overrides body _source: false.
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/syn_idx/_search?_source_includes=dyn_tag", `{"size": 5, "_source": false, "query": {"term": {"dyn_tag.keyword": "evolved"}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("URI _source_includes override search failed: %d %s", code, raw)
	}
	hitsArr := m["hits"].(map[string]any)["hits"].([]any)
	if len(hitsArr) != 1 || hitsArr[0].(map[string]any)["_source"].(map[string]any)["dyn_tag"] != "evolved" {
		t.Fatalf("expected URI _source_includes=dyn_tag to override body _source:false, got %s", raw)
	}

	// F12 + F14 + F25: typed_keys (`lterms#`, `hdr_percentiles#`, `simple_value#`), agg `meta`, HDR percentiles, and moving_fn default shift=0.
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/syn_idx/_search?typed_keys=true", `{
		"size": 0,
		"aggs": {
			"by_price": {
				"meta": {"owner": "analytics"},
				"terms": {"field": "price"},
				"aggs": {
					"s": {"sum": {"field": "price"}},
					"mov": {"moving_fn": {"buckets_path": "s", "window": 2, "script": "MovingFunctions.sum(values)"}}
				}
			},
			"p_hdr": {
				"percentiles": {
					"field": "price",
					"percents": [50, 99],
					"hdr": {"number_of_significant_value_digits": 3}
				}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("typed_keys + HDR + moving_fn search failed: %d %s", code, raw)
	}
	aggsOut := m["aggregations"].(map[string]any)
	lterms, hasLTerms := aggsOut["lterms#by_price"].(map[string]any)
	if !hasLTerms {
		t.Fatalf("expected lterms#by_price in typed_keys response, got keys %v", aggsOut)
	}
	if lterms["meta"].(map[string]any)["owner"] != "analytics" {
		t.Fatalf("expected agg meta echoed, got %v", lterms["meta"])
	}
	b0 := lterms["buckets"].([]any)[0].(map[string]any)
	// F25: bucket 0 moving_fn with default shift=0 receives [] -> MovingFunctions.sum([]) == 0.0!
	if mustInt64Round60(t, b0["simple_value#mov"].(map[string]any)["value"]) != 0 {
		t.Fatalf("expected bucket 0 moving_fn sum([]) == 0 with shift=0, got %v", b0["simple_value#mov"])
	}
	if _, hasHDR := aggsOut["hdr_percentiles#p_hdr"]; !hasHDR {
		t.Fatalf("expected hdr_percentiles#p_hdr in typed_keys response, got %v", aggsOut)
	}

	// F20: Cyclic Painless container in _search returns 400 without stack overflow!
	code, _, _, raw = doRound60Req(t, h, http.MethodPost, "/syn_idx/_search", `{
		"size": 5,
		"script_fields": {
			"cyc": {
				"script": "Map m = new HashMap(); m.put('self', m); return m;"
			}
		}
	}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on cyclic Painless map in script_fields, got %d: %s", code, raw)
	}

	// F24: intervals query with filter.script (interval.gaps).
	code, _, m, raw = doRound60Req(t, h, http.MethodPost, "/syn_idx/_search", `{
		"size": 5,
		"query": {
			"intervals": {
				"body": {
					"match": {
						"query": "quick jumps",
						"max_gaps": 5,
						"filter": {
							"script": {
								"source": "interval.gaps == 1"
							}
						}
					}
				}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("intervals filter.script search failed: %d %s", code, raw)
	}
	if len(m["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("expected exactly doc 2 ('quick fox jumps', gaps=1) to match intervals filter.script, got %s", raw)
	}

	// F15: cluster setting search.max_buckets enforces 400 too_many_buckets_exception.
	code, _, _, raw = doRound60Req(t, h, http.MethodPut, "/_cluster/settings", `{
		"transient": {"search.max_buckets": 2}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("put cluster settings search.max_buckets failed: %d %s", code, raw)
	}
	code, _, _, raw = doRound60Req(t, h, http.MethodPost, "/syn_idx/_search", `{
		"size": 0,
		"aggs": {"by_price": {"terms": {"field": "price"}}}
	}`, nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "Trying to create too many buckets") {
		t.Fatalf("expected 400 too_many_buckets_exception when exceeding search.max_buckets=2, got %d: %s", code, raw)
	}
}
