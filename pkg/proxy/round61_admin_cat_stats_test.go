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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newRound61AdminTestServer(t *testing.T, esVer string) (*Server, http.Handler) {
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

func doRound61AdminReq(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) (int, http.Header, map[string]any, string) {
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

func doDirectHandlerReqRound61(t *testing.T, fn func(http.ResponseWriter, *http.Request), method, path, body string, pathVals map[string]string, headers map[string]string) (int, http.Header, map[string]any, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range pathVals {
		req.SetPathValue(k, v)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	fn(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	if len(strings.TrimSpace(raw)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
		dec.UseNumber()
		_ = dec.Decode(&parsed)
	}
	return rec.Code, rec.Header(), parsed, raw
}

func TestRound61AdminCatStats_F0_NodesHotThreads(t *testing.T) {
	_, h := newRound61AdminTestServer(t, "8.15.5")

	// 1. Default `/_nodes/hot_threads` returns text/plain with ES `::: {node_name}{node_id}...` header
	code, hdr, _, raw := doRound61AdminReq(t, h, http.MethodGet, "/_nodes/hot_threads", "", nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on /_nodes/hot_threads, got %d: %s", code, raw)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; charset=UTF-8") {
		t.Fatalf("expected Content-Type text/plain; charset=UTF-8, got %q", ct)
	}
	if !strings.HasPrefix(raw, "::: {doris-es-proxy}{") || !strings.Contains(raw, "Hot threads at ") {
		t.Fatalf("unexpected hot_threads output:\n%s", raw)
	}

	// 2. `/_nodes/_local/hot_threads` with valid params + `ignore_idle_threads=false`
	code, _, _, raw = doRound61AdminReq(t, h, http.MethodGet, "/_nodes/_local/hot_threads?type=wait&threads=5&interval=200ms&snapshots=3&ignore_idle_threads=false&timeout=5s", "", nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on /_nodes/_local/hot_threads, got %d: %s", code, raw)
	}
	if !strings.Contains(raw, "busiestThreads=5, ignoreIdleThreads=false") || !strings.Contains(raw, "wait usage") {
		t.Fatalf("expected busiestThreads=5 & wait usage in output:\n%s", raw)
	}

	// 3. Non-matching node filter returns 200 with empty body
	code, _, _, raw = doRound61AdminReq(t, h, http.MethodGet, "/_nodes/nonexistent_node_xyz/hot_threads", "", nil)
	if code != http.StatusOK || raw != "" {
		t.Fatalf("expected 200 and empty body for non-matching node filter, got %d %q", code, raw)
	}

	// 4. Deprecated `type=mem` succeeds with RFC 7234 Warning header
	code, hdr, _, raw = doRound61AdminReq(t, h, http.MethodGet, "/_nodes/hot_threads?type=mem", "", nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for deprecated type=mem, got %d: %s", code, raw)
	}
	if warn := hdr.Get("Warning"); !strings.Contains(warn, "299 Elasticsearch-") || !strings.Contains(warn, "[mem]") {
		t.Fatalf("expected RFC 7234 deprecation Warning header for type=mem, got %q", warn)
	}

	// 5. Invalid parameters return 400 illegal_argument_exception
	badURLs := []string{
		"/_nodes/hot_threads?type=bogus",
		"/_nodes/hot_threads?threads=0",
		"/_nodes/hot_threads?snapshots=-2",
		"/_nodes/hot_threads?interval=notadur",
		"/_nodes/hot_threads?ignore_idle_threads=maybe",
		"/_nodes/hot_threads?timeout=invalid",
	}
	for _, u := range badURLs {
		c, _, m, body := doRound61AdminReq(t, h, http.MethodGet, u, "", nil)
		if c != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d: %s", u, c, body)
		}
		errObj, _ := m["error"].(map[string]any)
		if errObj["type"] != "illegal_argument_exception" {
			t.Fatalf("expected illegal_argument_exception for %s, got %v", u, m)
		}
	}
}

func TestRound61AdminCatStats_F1_ClusterInfoAndHealthReport(t *testing.T) {
	srv, h := newRound61AdminTestServer(t, "8.15.5")

	// 1. `GET /_info` (all sections)
	code, _, m, raw := doDirectHandlerReqRound61(t, srv.handleClusterInfoRound61, http.MethodGet, "/_info", "", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_info failed: %d %s", code, raw)
	}
	for _, key := range []string{"cluster_name", "http", "ingest", "thread_pool", "script", "aggregations", "plugins"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("expected key %q in /_info response, got %s", key, raw)
		}
	}
	aggsMap, _ := m["aggregations"].(map[string]any)
	if aggsMap["terms"] == nil || aggsMap["date_histogram"] == nil {
		t.Fatalf("expected terms and date_histogram in /_info aggregations, got %v", aggsMap)
	}
	ingestProcs, _ := m["ingest"].(map[string]any)["processors"].([]any)
	if len(ingestProcs) < 20 {
		t.Fatalf("expected rich ingest processors list in /_info, got %d", len(ingestProcs))
	}

	// 2. `GET /_info/aggregations,ingest` selects only requested targets
	code, _, m, raw = doDirectHandlerReqRound61(t, srv.handleClusterInfoRound61, http.MethodGet, "/_info/aggregations,ingest", "", map[string]string{"target": "aggregations,ingest"}, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_info/aggregations,ingest failed: %d %s", code, raw)
	}
	if m["aggregations"] == nil || m["ingest"] == nil || m["plugins"] != nil || m["http"] != nil {
		t.Fatalf("expected only aggregations & ingest in filtered /_info, got %s", raw)
	}

	// 3. Reject `_all` mixed with named targets and unknown target names with 400 illegal_argument_exception
	code, _, m, raw = doDirectHandlerReqRound61(t, srv.handleClusterInfoRound61, http.MethodGet, "/_info/_all,ingest", "", map[string]string{"target": "_all,ingest"}, nil)
	if code != http.StatusBadRequest || m["error"].(map[string]any)["type"] != "illegal_argument_exception" {
		t.Fatalf("expected 400 illegal_argument_exception for _all,ingest, got %d %s", code, raw)
	}
	code, _, m, raw = doDirectHandlerReqRound61(t, srv.handleClusterInfoRound61, http.MethodGet, "/_info/bogus_section", "", map[string]string{"target": "bogus_section"}, nil)
	if code != http.StatusBadRequest || m["error"].(map[string]any)["type"] != "illegal_argument_exception" {
		t.Fatalf("expected 400 illegal_argument_exception for unknown /_info target, got %d %s", code, raw)
	}

	// 4. `/_health_report` basic: exact repository symptom + flattened shards_availability.details
	code, _, m, raw = doRound61AdminReq(t, h, http.MethodGet, "/_health_report", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_health_report failed: %d %s", code, raw)
	}
	inds := m["indicators"].(map[string]any)
	repoInd := inds["repository_integrity"].(map[string]any)
	if repoInd["symptom"] != "No snapshot repositories configured." {
		t.Fatalf("expected exact symptom 'No snapshot repositories configured.', got %q", repoInd["symptom"])
	}
	saDetails := inds["shards_availability"].(map[string]any)["details"].(map[string]any)
	for _, flatKey := range []string{
		"initializing_replicas", "creating_primaries", "restarting_replicas", "unassigned_primaries",
		"started_replicas", "creating_replicas", "initializing_primaries", "restarting_primaries",
		"started_primaries", "unassigned_replicas",
	} {
		if _, exists := saDetails[flatKey]; !exists {
			t.Fatalf("missing flattened shards_availability.details.%s in %s", flatKey, raw)
		}
	}

	// 5. `?verbose=false` omits details/impacts/diagnosis
	code, _, m, raw = doRound61AdminReq(t, h, http.MethodGet, "/_health_report/master_is_stable?verbose=false", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_health_report/master_is_stable?verbose=false failed: %d %s", code, raw)
	}
	msInd := m["indicators"].(map[string]any)["master_is_stable"].(map[string]any)
	if _, hasDetails := msInd["details"]; hasDetails {
		t.Fatalf("expected details omitted when verbose=false, got %s", raw)
	}

	// 6. Yellow status with impacts + diagnosis when `index.routing.allocation.enable` is `"none"` on active index
	doRound61AdminReq(t, h, http.MethodPut, "/yellow_idx", `{"settings":{"number_of_shards":1,"number_of_replicas":1}}`, nil)
	doRound61AdminReq(t, h, http.MethodPut, "/yellow_idx/_settings", `{"index.routing.allocation.enable":"none"}`, nil)
	code, _, m, raw = doRound61AdminReq(t, h, http.MethodGet, "/_health_report", "", nil)
	if code != http.StatusOK || m["status"] != "yellow" {
		t.Fatalf("expected yellow health_report when allocation.enable=none, got %d %s", code, raw)
	}
	saInd := m["indicators"].(map[string]any)["shards_availability"].(map[string]any)
	if saInd["status"] != "yellow" || len(saInd["impacts"].([]any)) == 0 || len(saInd["diagnosis"].([]any)) == 0 {
		t.Fatalf("expected yellow shards_availability with impacts & diagnosis, got %s", raw)
	}
	doRound61AdminReq(t, h, http.MethodDelete, "/yellow_idx", "", nil)

	// 7. ES8 `40_diagnosis.yml`: newly created 0-replica index with `index.routing.allocation.enable: none` -> red diagnosis
	doRound61AdminReq(t, h, http.MethodPut, "/red_index", `{
		"settings": {
			"number_of_shards": 1,
			"number_of_replicas": 0,
			"index.routing.allocation.enable": "none"
		}
	}`, nil)
	code, _, m, raw = doRound61AdminReq(t, h, http.MethodGet, "/_health_report/shards_availability", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_health_report/shards_availability failed: %d %s", code, raw)
	}
	saRed := m["indicators"].(map[string]any)["shards_availability"].(map[string]any)
	if saRed["status"] != "red" || saRed["symptom"] != "This cluster has 1 unavailable primary shard." {
		t.Fatalf("unexpected red shards_availability indicator: %s", raw)
	}
}

func TestRound61AdminCatStats_F2_CatTrailingEmptyCellSeparatorAndTemplates(t *testing.T) {
	_, h := newRound61AdminTestServer(t, "8.15.5")

	// 1. Legacy `/_template` emits `composed_of=""` (NOT `"[]"`) and preserves column-separator space before trailing empty cell!
	code, _, _, raw := doRound61AdminReq(t, h, http.MethodPut, "/_template/test_leg", `{"index_patterns":["t*"]}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /_template/test_leg failed: %d %s", code, raw)
	}
	code, _, _, raw = doRound61AdminReq(t, h, http.MethodGet, "/_cat/templates/test_leg", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_cat/templates/test_leg failed: %d %s", code, raw)
	}
	line := strings.TrimSuffix(raw, "\n")
	if strings.Contains(line, "[]") {
		t.Fatalf("expected legacy template composed_of to be empty (not []), got %q", line)
	}
	if !strings.HasSuffix(line, " ") {
		t.Fatalf("expected trailing column-separator space before empty final composed_of cell, got %q", line)
	}

	// 2. Comma-separated template name patterns return 400 per cat.templates YAML spec
	code, _, m, raw := doRound61AdminReq(t, h, http.MethodGet, "/_cat/templates/test_leg,other_tpl", "", nil)
	if code != http.StatusBadRequest || m["error"].(map[string]any)["type"] != "illegal_argument_exception" {
		t.Fatalf("expected 400 illegal_argument_exception for comma-separated _cat/templates pattern, got %d %s", code, raw)
	}

	// 3. `_cat/aliases` preserves separator spaces before empty trailing routing / is_write_index cells
	doRound61AdminReq(t, h, http.MethodPut, "/cat_al_idx", `{}`, nil)
	doRound61AdminReq(t, h, http.MethodPut, "/cat_al_idx/_alias/al1", `{}`, nil)
	code, _, _, raw = doRound61AdminReq(t, h, http.MethodGet, "/_cat/aliases/al1?h=alias,index,routing.index", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_cat/aliases/al1 failed: %d %s", code, raw)
	}
	alLine := strings.TrimSuffix(raw, "\n")
	// routing.index defaults to "-" in _cat/aliases unless empty; test `?h=alias,is_write_index` where is_write_index is "-" or test writeCatResponseWithHelpCols directly!
	buf := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_cat/test", nil)
	writeCatResponse(buf, req, []string{"col1", "col2"}, []map[string]any{
		{"col1": "test [t*]", "col2": ""},
	})
	if got := buf.Body.String(); got != "test [t*] \n" {
		t.Fatalf("expected exact 'test [t*] \\n' preserving separator before empty final cell, got %q (aliases=%q)", got, alLine)
	}
}

func TestRound61AdminCatStats_F3_IndicesStatsDiskUsageAndFieldUsage(t *testing.T) {
	srv7, h7 := newRound61AdminTestServer(t, "7.10.2")
	srv8, h8 := newRound61AdminTestServer(t, "8.15.5")

	// 1. Unrefreshed docs subtracted from `docs.count` before `_refresh`, visible after `_refresh`
	doRound61AdminReq(t, h8, http.MethodPut, "/st_idx", `{"settings":{"refresh_interval":"-1"},"mappings":{"properties":{"title":{"type":"text"},"suggest":{"type":"completion"}}}}`, nil)
	doRound61AdminReq(t, h8, http.MethodPut, "/st_idx/_doc/1", `{"title":"hello world"}`, nil) // no ?refresh=true!

	code, _, m, raw := doRound61AdminReq(t, h8, http.MethodGet, "/st_idx/_stats/docs", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /st_idx/_stats/docs failed: %d %s", code, raw)
	}
	preRefreshDocs := mustInt64Round60(t, m["_all"].(map[string]any)["primaries"].(map[string]any)["docs"].(map[string]any)["count"])
	if preRefreshDocs != 0 {
		t.Fatalf("expected docs.count == 0 before _refresh, got %d (%s)", preRefreshDocs, raw)
	}

	doRound61AdminReq(t, h8, http.MethodPost, "/st_idx/_refresh", "", nil)
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodGet, "/st_idx/_stats/docs", "", nil)
	postRefreshDocs := mustInt64Round60(t, m["_all"].(map[string]any)["primaries"].(map[string]any)["docs"].(map[string]any)["count"])
	if code != http.StatusOK || postRefreshDocs != 1 {
		t.Fatalf("expected docs.count == 1 after _refresh, got %d (%s)", postRefreshDocs, raw)
	}

	// 2. Search groups wildcard expansion (`?groups=grp_*`), fielddata_fields & completion_fields filtering
	recordSearchStatsGroupsRound61(srv8, []string{"st_idx"}, []string{"grp_alpha", "grp_beta", "other"})
	recordFieldAccessesRound61(srv8, "st_idx", []string{"title", "suggest"})

	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodGet, "/st_idx/_stats/search,fielddata,completion?groups=grp_*&fielddata_fields=ti*&completion_fields=sug*", "", nil)
	if code != http.StatusOK {
		t.Fatalf("filtered stats failed: %d %s", code, raw)
	}
	prim := m["_all"].(map[string]any)["primaries"].(map[string]any)
	groupsMap, _ := prim["search"].(map[string]any)["groups"].(map[string]any)
	if groupsMap["grp_alpha"] == nil || groupsMap["grp_beta"] == nil || groupsMap["other"] != nil {
		t.Fatalf("expected grp_alpha & grp_beta (and not other) in search.groups, got %v", groupsMap)
	}
	fdFields, _ := prim["fielddata"].(map[string]any)["fields"].(map[string]any)
	compFields, _ := prim["completion"].(map[string]any)["fields"].(map[string]any)
	if fdFields["title"] == nil || compFields["suggest"] == nil {
		t.Fatalf("expected fielddata.fields.title and completion.fields.suggest, got fd=%v comp=%v", fdFields, compFields)
	}

	// 3. `merge` -> `merges` alias & Levenshtein <= 2 `" -> did you mean [...]?"` error
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodGet, "/st_idx/_stats/merge", "", nil)
	if code != http.StatusOK || m["_all"].(map[string]any)["primaries"].(map[string]any)["merges"] == nil {
		t.Fatalf("expected merge alias to populate merges section, got %d %s", code, raw)
	}
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodGet, "/st_idx/_stats/docz", "", nil)
	errReason, _ := m["error"].(map[string]any)["reason"].(string)
	if code != http.StatusBadRequest || !strings.Contains(errReason, "-> did you mean [docs]?") {
		t.Fatalf("expected 400 with Levenshtein '-> did you mean [docs]?', got %d reason=%q raw=%s", code, errReason, raw)
	}

	// 4. Shard-level `commit`, `seq_no`, `retention_leases`, `shard_path`, `segments.file_sizes`, `total_data_set_size_in_bytes`, `indexing.write_load`
	markIndexFlushedRound61(srv8, "st_idx")
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodGet, "/st_idx/_stats?level=shards&include_segment_file_sizes=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("shard-level stats failed: %d %s", code, raw)
	}
	sh0 := m["indices"].(map[string]any)["st_idx"].(map[string]any)["shards"].(map[string]any)["0"].([]any)[0].(map[string]any)
	for _, k := range []string{"commit", "seq_no", "retention_leases", "shard_path"} {
		if sh0[k] == nil {
			t.Fatalf("missing shard key %q in %s", k, raw)
		}
	}
	if sh0["store"].(map[string]any)["total_data_set_size_in_bytes"] == nil {
		t.Fatalf("missing store.total_data_set_size_in_bytes in %s", raw)
	}
	if sh0["segments"].(map[string]any)["file_sizes"] == nil {
		t.Fatalf("missing segments.file_sizes when include_segment_file_sizes=true in %s", raw)
	}
	if sh0["indexing"].(map[string]any)["write_load"] == nil {
		t.Fatalf("missing indexing.write_load in %s", raw)
	}

	// 5. ES 7 `indexing.types` present vs ES 8 omitted
	doRound61AdminReq(t, h7, http.MethodPut, "/v7_idx", `{}`, nil)
	recordDocTypeIndexingRound61(srv7, "v7_idx", "_doc", false)
	code, _, m, raw = doRound61AdminReq(t, h7, http.MethodGet, "/v7_idx/_stats/indexing?types=_doc", "", nil)
	if code != http.StatusOK {
		t.Fatalf("ES7 indexing stats failed: %d %s", code, raw)
	}
	v7Indexing := m["indices"].(map[string]any)["v7_idx"].(map[string]any)["primaries"].(map[string]any)["indexing"].(map[string]any)
	if v7Indexing["types"] == nil {
		t.Fatalf("expected ES7 indexing.types to be present, got %s", raw)
	}
	if _, hasES8Types := sh0["indexing"].(map[string]any)["types"]; hasES8Types {
		t.Fatalf("expected ES8 indexing.types to be omitted, got %v", sh0["indexing"])
	}

	// 6. `_disk_usage` & `_field_usage_stats`: require `run_expensive_tasks=true` (400 otherwise in ES8), live byte estimates, synthetic _source -> 0 bytes
	if c, _, _, _ := doRound61AdminReq(t, h8, http.MethodPost, "/st_idx/_disk_usage", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 when run_expensive_tasks=true is missing on _disk_usage in ES8 mode, got %d", c)
	}
	if c, _, _, _ := doRound61AdminReq(t, h8, http.MethodGet, "/st_idx/_field_usage_stats", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 when run_expensive_tasks=true is missing on _field_usage_stats in ES8 mode, got %d", c)
	}
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodPost, "/st_idx/_disk_usage?run_expensive_tasks=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("_disk_usage?run_expensive_tasks=true failed: %d %s", code, raw)
	}
	stDisk := m["st_idx"].(map[string]any)
	if mustInt64Round60(t, stDisk["store_size_in_bytes"]) <= 0 {
		t.Fatalf("expected positive store_size_in_bytes for st_idx, got %s", raw)
	}

	// Synthetic `_source` index reports 0 bytes for `_source` and `_recovery_source`
	doRound61AdminReq(t, h8, http.MethodPut, "/synth_du", `{
		"mappings": {
			"_source": {"mode": "synthetic"},
			"properties": {"host": {"type": "keyword"}}
		}
	}`, nil)
	doRound61AdminReq(t, h8, http.MethodPut, "/synth_du/_doc/1?refresh=true", `{"host":"node-a"}`, nil)
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodPost, "/synth_du/_disk_usage?run_expensive_tasks=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("synthetic _disk_usage failed: %d %s", code, raw)
	}
	duAll := m["synth_du"].(map[string]any)["all_fields"].(map[string]any)
	if mustInt64Round60(t, duAll["total_in_bytes"]) <= 0 {
		t.Fatalf("expected positive all_fields.total_in_bytes in synthetic _source index, got %s", raw)
	}
	duFields := m["synth_du"].(map[string]any)["fields"].(map[string]any)
	if duFields["_source"] != nil ||
		duFields["_recovery_source"] == nil ||
		mustInt64Round60(t, duFields["_recovery_source"].(map[string]any)["total_in_bytes"]) != 0 ||
		mustInt64Round60(t, duFields["host"].(map[string]any)["total_in_bytes"]) <= 0 {
		t.Fatalf("unexpected per-field bytes on synthetic _source index: %s", raw)
	}

	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodGet, "/st_idx/_field_usage_stats?run_expensive_tasks=true", "", nil)
	if code != http.StatusOK || m["st_idx"] == nil {
		t.Fatalf("_field_usage_stats?run_expensive_tasks=true failed: %d %s", code, raw)
	}
}

func TestRound61AdminCatStats_F4_NodesInfoStatsFilterPathAndFeatures(t *testing.T) {
	_, h := newRound61AdminTestServer(t, "8.15.5")

	// 1. `/_nodes` vs `/_nodes/settings` vs `/_nodes/indices?human=true` (`total_indexing_buffer_in_bytes` + `total_indexing_buffer`)
	code, _, m, raw := doRound61AdminReq(t, h, http.MethodGet, "/_nodes", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_nodes failed: %d %s", code, raw)
	}
	nodeObj := m["nodes"].(map[string]any)[taskLocalNodeID].(map[string]any)
	if nodeObj["total_indexing_buffer_in_bytes"] == nil || nodeObj["total_indexing_buffer"] == nil {
		t.Fatalf("expected total_indexing_buffer_in_bytes & total_indexing_buffer on /_nodes, got %s", raw)
	}
	if len(nodeObj["roles"].([]any)) != 11 {
		t.Fatalf("expected 11 sorted ES8 node roles, got %v", nodeObj["roles"])
	}

	code, _, m, raw = doRound61AdminReq(t, h, http.MethodGet, "/_nodes/settings", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_nodes/settings failed: %d %s", code, raw)
	}
	nodeSettingsOnly := m["nodes"].(map[string]any)[taskLocalNodeID].(map[string]any)
	if nodeSettingsOnly["settings"] == nil || nodeSettingsOnly["total_indexing_buffer"] != nil {
		t.Fatalf("expected settings present and total_indexing_buffer omitted on /_nodes/settings, got %s", raw)
	}

	code, _, m, raw = doRound61AdminReq(t, h, http.MethodGet, "/_nodes/indices?human=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_nodes/indices?human=true failed: %d %s", code, raw)
	}
	nodeHuman := m["nodes"].(map[string]any)[taskLocalNodeID].(map[string]any)
	if _, isStr := nodeHuman["total_indexing_buffer"].(string); !isStr || nodeHuman["total_indexing_buffer_in_bytes"] == nil {
		t.Fatalf("expected human string total_indexing_buffer + numeric total_indexing_buffer_in_bytes, got %v", nodeHuman)
	}

	// 2. `/_nodes/stats` includes `repositories`, `allocations`, forwarded `indices` params, and live `ingest` stats
	doRound61AdminReq(t, h, http.MethodPut, "/_ingest/pipeline/p_live", `{"processors":[{"lowercase":{"field":"msg"}}]}`, nil)
	doRound61AdminReq(t, h, http.MethodPut, "/ns_idx", `{"mappings":{"properties":{"msg":{"type":"text"}}}}`, nil)
	doRound61AdminReq(t, h, http.MethodPut, "/ns_idx/_doc/1?pipeline=p_live&refresh=true", `{"msg":"HELLO"}`, nil)

	code, _, m, raw = doRound61AdminReq(t, h, http.MethodGet, "/_nodes/stats/repositories,allocations,ingest,indices?level=shards&include_segment_file_sizes=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_nodes/stats failed: %d %s", code, raw)
	}
	nsNode := m["nodes"].(map[string]any)[taskLocalNodeID].(map[string]any)
	for _, k := range []string{"repositories", "allocations", "ingest", "indices"} {
		if nsNode[k] == nil {
			t.Fatalf("missing %q in /_nodes/stats response: %s", k, raw)
		}
	}
	if nsNode["indices"].(map[string]any)["shards"] == nil {
		t.Fatalf("expected level=shards forwarded into nodes.stats.indices, got %s", raw)
	}
	ingTotal := nsNode["ingest"].(map[string]any)["total"].(map[string]any)
	if mustInt64Round60(t, ingTotal["count"]) < 1 {
		t.Fatalf("expected live ingest.total.count >= 1 after pipeline doc write, got %v", ingTotal)
	}

	// 3. Mixed positive + negative `filter_path=nodes.*.os,-nodes.*.os.cpu` and multi-param `?filter_path=...&filter_path=-...`
	code, _, m, raw = doRound61AdminReq(t, h, http.MethodGet, "/_nodes/stats/os?filter_path=nodes.*.os,-nodes.*.os.cpu", "", nil)
	if code != http.StatusOK {
		t.Fatalf("filter_path mixed pos/neg failed: %d %s", code, raw)
	}
	fpOS := m["nodes"].(map[string]any)[taskLocalNodeID].(map[string]any)["os"].(map[string]any)
	if fpOS["mem"] == nil || fpOS["cpu"] != nil {
		t.Fatalf("expected os.mem retained and os.cpu pruned by -nodes.*.os.cpu, got %s", raw)
	}

	code, _, m, raw = doRound61AdminReq(t, h, http.MethodGet, "/_nodes/stats/os?filter_path=nodes.*.os&filter_path=-nodes.*.os.mem", "", nil)
	if code != http.StatusOK {
		t.Fatalf("multi-param filter_path failed: %d %s", code, raw)
	}
	fpOS2 := m["nodes"].(map[string]any)[taskLocalNodeID].(map[string]any)["os"].(map[string]any)
	if fpOS2["cpu"] == nil || fpOS2["mem"] != nil {
		t.Fatalf("expected os.cpu retained and os.mem pruned by multi-param filter_path, got %s", raw)
	}

	// 4. `/_features` includes `tasks` feature entry
	code, _, m, raw = doRound61AdminReq(t, h, http.MethodGet, "/_features", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_features failed: %d %s", code, raw)
	}
	foundTasks := false
	for _, item := range m["features"].([]any) {
		if fm, ok := item.(map[string]any); ok && fm["name"] == "tasks" {
			foundTasks = true
			break
		}
	}
	if !foundTasks {
		t.Fatalf("expected 'tasks' feature in /_features response, got %s", raw)
	}
}

func TestRound61AdminCatStats_F6_SimulateTemplateOverrideAndComponentInUse(t *testing.T) {
	srv, h := newRound61AdminTestServer(t, "8.15.5")

	// 1. Create component templates & index template referencing `ct_in_use`
	doRound61AdminReq(t, h, http.MethodPut, "/_component_template/ct_in_use", `{
		"template": {"settings": {"number_of_shards": 2}}
	}`, nil)
	doRound61AdminReq(t, h, http.MethodPut, "/_component_template/ct_unused", `{
		"template": {"settings": {"number_of_replicas": 0}}
	}`, nil)
	doRound61AdminReq(t, h, http.MethodPut, "/_index_template/it_main", `{
		"index_patterns": ["sim-*"],
		"composed_of": ["ct_in_use"],
		"priority": 10,
		"template": {
			"settings": {"number_of_replicas": 1},
			"mappings": {"properties": {"base_f": {"type": "keyword"}}}
		}
	}`, nil)

	// 2. Inline JSON body override on `POST /_index_template/_simulate/it_main`
	code, _, m, raw := doRound61AdminReq(t, h, http.MethodPost, "/_index_template/_simulate/it_main", `{
		"index_patterns": ["sim-*"],
		"composed_of": ["ct_in_use"],
		"template": {
			"settings": {"number_of_replicas": 3},
			"mappings": {"properties": {"override_f": {"type": "long"}}}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("POST /_index_template/_simulate/it_main with body override failed: %d %s", code, raw)
	}
	simTpl := m["template"].(map[string]any)
	simIdxSettings := simTpl["settings"].(map[string]any)["index"].(map[string]any)
	if simIdxSettings["number_of_shards"] != "2" || simIdxSettings["number_of_replicas"] != "3" {
		t.Fatalf("expected merged stringified settings shards=2, replicas=3, got %s", raw)
	}
	simProps := simTpl["mappings"].(map[string]any)["properties"].(map[string]any)
	if simProps["override_f"] == nil {
		t.Fatalf("expected override_f from inline body override, got %s", raw)
	}

	// 3. Reject `DELETE /_component_template/{name}` (400) when referenced by `_index_template` (exact and wildcard!)
	rec1 := httptest.NewRecorder()
	srv.handleDeleteComponentTemplateRound61(rec1, httptest.NewRequest(http.MethodDelete, "/_component_template/ct_in_use", nil), "ct_in_use")
	if rec1.Code != http.StatusBadRequest || !strings.Contains(rec1.Body.String(), "it_main") {
		t.Fatalf("expected 400 when deleting component template in use, got %d %s", rec1.Code, rec1.Body.String())
	}

	recWild := httptest.NewRecorder()
	srv.handleDeleteComponentTemplateRound61(recWild, httptest.NewRequest(http.MethodDelete, "/_component_template/ct_*", nil), "ct_*")
	if recWild.Code != http.StatusBadRequest || !strings.Contains(recWild.Body.String(), "ct_in_use") {
		t.Fatalf("expected 400 when wildcard DELETE matches in-use component template, got %d %s", recWild.Code, recWild.Body.String())
	}

	recUnused := httptest.NewRecorder()
	srv.handleDeleteComponentTemplateRound61(recUnused, httptest.NewRequest(http.MethodDelete, "/_component_template/ct_unused", nil), "ct_unused")
	if recUnused.Code != http.StatusOK {
		t.Fatalf("expected 200 when deleting unused component template, got %d %s", recUnused.Code, recUnused.Body.String())
	}
}

func TestRound61AdminCatStats_F8_F11_F12_SynonymsSnapshotsRetrieverAndFieldCaps(t *testing.T) {
	srv7, _ := newRound61AdminTestServer(t, "7.10.2")
	srv8, h8 := newRound61AdminTestServer(t, "8.15.5")

	// ---- F8: Synonyms ----
	// 1. Empty `synonyms_set: []` allowed
	code, _, m, raw := doRound61AdminReq(t, h8, http.MethodPut, "/_synonyms/empty_set", `{"synonyms_set":[]}`, nil)
	if code != http.StatusOK || m["result"] != "created" {
		t.Fatalf("expected 200 result=created for empty synonyms_set, got %d %s", code, raw)
	}

	// 2. Missing synonym set matches exact `"synonyms set [missing_set] not found"`
	code, _, _, raw = doRound61AdminReq(t, h8, http.MethodGet, "/_synonyms/missing_set", "", nil)
	if code != http.StatusNotFound || !strings.Contains(raw, "synonyms set [missing_set] not found") {
		t.Fatalf("expected 404 'synonyms set [missing_set] not found', got %d %s", code, raw)
	}

	// 3. Rule insertion order preserved & `"result": "created"|"updated"`, `from`/`size` validation
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodPut, "/_synonyms/my_syns", `{
		"synonyms_set": [
			{"id": "r2", "synonyms": "quick, fast"},
			{"id": "r1", "synonyms": "jumps => leaps"}
		]
	}`, nil)
	if code != http.StatusOK || m["result"] != "created" {
		t.Fatalf("PUT /_synonyms/my_syns failed: %d %s", code, raw)
	}
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodPut, "/_synonyms/my_syns/r2", `{"synonyms": "quick, rapid, fast"}`, nil)
	if code != http.StatusOK || m["result"] != "updated" {
		t.Fatalf("expected result=updated on existing synonym rule, got %d %s", code, raw)
	}
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodGet, "/_synonyms/my_syns?from=0&size=10", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /_synonyms/my_syns failed: %d %s", code, raw)
	}
	synArr := m["synonyms_set"].([]any)
	if len(synArr) != 2 || synArr[0].(map[string]any)["id"] != "r1" || synArr[1].(map[string]any)["id"] != "r2" {
		t.Fatalf("expected id-sorted order [r1, r2], got %s", raw)
	}
	if c, _, _, _ := doRound61AdminReq(t, h8, http.MethodGet, "/_synonyms/my_syns?from=-1", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on negative from, got %d", c)
	}
	if c, _, _, _ := doRound61AdminReq(t, h8, http.MethodGet, "/_synonyms/my_syns?size=10001", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on size > 10000, got %d", c)
	}

	// 4. `indexHasMissingSynonymsSetRound61`, `_reload_search_analyzers`, and `expandSearchBodySynonymsRound61`
	if !indexHasMissingSynonymsSetRound61(srv8, map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"syn_f": map[string]any{"type": "synonym_graph", "synonyms_set": "not_created_yet", "updateable": true},
			},
		},
	}) {
		t.Fatalf("expected indexHasMissingSynonymsSetRound61=true for uncreated synonyms_set")
	}

	doRound61AdminReq(t, h8, http.MethodPut, "/syn_search_idx", `{
		"settings": {
			"analysis": {
				"filter": {
					"my_syn_filter": {"type": "synonym_graph", "synonyms_set": "my_syns", "updateable": true}
				},
				"analyzer": {
					"my_syn_analyzer": {"tokenizer": "standard", "filter": ["lowercase", "my_syn_filter"]}
				}
			}
		},
		"mappings": {
			"properties": {
				"headline": {"type": "text", "search_analyzer": "my_syn_analyzer"}
			}
		}
	}`, nil)
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodPost, "/syn_search_idx/_reload_search_analyzers", "", nil)
	if code != http.StatusOK || len(m["reload_details"].([]any)) != 1 {
		t.Fatalf("expected reload_details on _reload_search_analyzers, got %d %s", code, raw)
	}
	expanded := expandSearchBodySynonymsRound61(srv8, []string{"syn_search_idx"}, []byte(`{"query":{"match":{"headline":"quick"}}}`))
	if !bytes.Contains(expanded, []byte(`"rapid"`)) || !bytes.Contains(expanded, []byte(`"fast"`)) {
		t.Fatalf("expected query-time synonym expansion to include rapid & fast, got %s", string(expanded))
	}

	// ---- F8: Snapshots ----
	doRound61AdminReq(t, h8, http.MethodPut, "/_snapshot/repo1", `{"type":"fs","settings":{"location":"/tmp/repo1"}}`, nil)
	// Default wait_for_completion=false returns `{"accepted": true}` WITHOUT `"snapshot"`
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodPut, "/_snapshot/repo1/snap_async", `{}`, nil)
	if code != http.StatusOK || m["accepted"] != true || m["snapshot"] != nil {
		t.Fatalf("expected {\"accepted\":true} without snapshot when wait_for_completion omitted, got %d %s", code, raw)
	}
	// wait_for_completion=true returns `{"snapshot": ...}`
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodPut, "/_snapshot/repo1/snap_sync?wait_for_completion=true", `{}`, nil)
	if code != http.StatusOK || m["snapshot"] == nil {
		t.Fatalf("expected snapshot object when wait_for_completion=true, got %d %s", code, raw)
	}
	// ignore_unavailable=true on GET and DELETE missing snapshot
	code, _, m, raw = doRound61AdminReq(t, h8, http.MethodGet, "/_snapshot/repo1/missing_snap?ignore_unavailable=true", "", nil)
	if code != http.StatusOK || len(m["snapshots"].([]any)) != 0 {
		t.Fatalf("expected 200 empty snapshots for GET missing_snap?ignore_unavailable=true, got %d %s", code, raw)
	}
	code, _, _, raw = doRound61AdminReq(t, h8, http.MethodDelete, "/_snapshot/repo1/missing_snap?ignore_unavailable=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for DELETE missing_snap?ignore_unavailable=true, got %d %s", code, raw)
	}

	// ---- F11: `retriever.standard` ----
	rewritten, errSt, errType, _ := srv8.validateAndRewriteStandardRetrieverRound61([]byte(`{
		"retriever": {
			"standard": {
				"query": {"match": {"headline": "quick"}},
				"filter": {"term": {"tag": "news"}},
				"sort": [{"seq": "asc"}],
				"search_after": [1],
				"collapse": {"field": "tag"},
				"terminate_after": 5
			}
		}
	}`))
	if errSt != 0 || errType != "" {
		t.Fatalf("unexpected error rewriting valid standard retriever: %d %s", errSt, errType)
	}
	var rwMap map[string]any
	_ = json.Unmarshal(rewritten, &rwMap)
	if rwMap["query"] == nil || rwMap["sort"] == nil || rwMap["search_after"] == nil || rwMap["collapse"] == nil || rwMap["terminate_after"] == nil || rwMap["retriever"] != nil {
		t.Fatalf("expected standard retriever fields promoted and retriever deleted, got %s", string(rewritten))
	}
	_, dupSt, dupType, _ := srv8.validateAndRewriteStandardRetrieverRound61([]byte(`{
		"query": {"match_all": {}},
		"retriever": {"standard": {"query": {"match_all": {}}}}
	}`))
	if dupSt != http.StatusBadRequest || dupType != "parsing_exception" {
		t.Fatalf("expected 400 parsing_exception when both top-level query and retriever are set, got %d %s", dupSt, dupType)
	}

	// ---- F12: `_field_caps` (`handleFieldCapsRound61`) ----
	// Setup ES7 & ES8 indices with `index: false` keyword, runtime field, multifield, object parent, and empty field
	mappingJSON := `{
		"mappings": {
			"runtime": {
				"rt_day": {"type": "keyword"}
			},
			"properties": {
				"unindexed_kw": {"type": "keyword", "index": false},
				"populated_txt": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
				"empty_num": {"type": "long"},
				"nested_grp": {"type": "object", "properties": {"sub": {"type": "integer"}}},
				"year": {"type": "integer"}
			}
		}
	}`
	doRound61AdminReq(t, srv7.Handler(), http.MethodPut, "/fc_idx", mappingJSON, nil)
	doRound61AdminReq(t, h8, http.MethodPut, "/fc_idx_1", mappingJSON, nil)
	doRound61AdminReq(t, h8, http.MethodPut, "/fc_idx_2", mappingJSON, nil)
	doRound61AdminReq(t, h8, http.MethodPut, "/fc_idx_1/_doc/1?refresh=true", `{"unindexed_kw":"v","populated_txt":"hi","year":2024}`, nil)
	doRound61AdminReq(t, h8, http.MethodPut, "/fc_idx_2/_doc/1?refresh=true", `{"unindexed_kw":"v","populated_txt":"yo","year":2020}`, nil)

	// 1. ES7 marks `index: false` keyword `searchable: false`; ES8 marks it `searchable: true` + includes `_seq_no` & `rt_day`
	code, _, m7, raw := doDirectHandlerReqRound61(t, srv7.handleFieldCapsRound61, http.MethodGet, "/fc_idx/_field_caps?fields=unindexed_kw,_seq_no,rt_day", "", map[string]string{"index": "fc_idx"}, nil)
	if code != http.StatusOK {
		t.Fatalf("ES7 handleFieldCapsRound61 failed: %d %s", code, raw)
	}
	f7 := m7["fields"].(map[string]any)
	if f7["unindexed_kw"].(map[string]any)["keyword"].(map[string]any)["searchable"] != false {
		t.Fatalf("expected ES7 index:false keyword searchable=false, got %s", raw)
	}

	code, _, m8, raw := doDirectHandlerReqRound61(t, srv8.handleFieldCapsRound61, http.MethodGet, "/fc_idx_1/_field_caps?fields=*", "", map[string]string{"index": "fc_idx_1"}, nil)
	if code != http.StatusOK {
		t.Fatalf("ES8 handleFieldCapsRound61 failed: %d %s", code, raw)
	}
	f8 := m8["fields"].(map[string]any)
	if f8["unindexed_kw"].(map[string]any)["keyword"].(map[string]any)["searchable"] != true {
		t.Fatalf("expected ES8 index:false doc_values keyword searchable=true, got %s", raw)
	}
	if f8["_seq_no"] == nil || f8["rt_day"] == nil {
		t.Fatalf("expected _seq_no and runtime field rt_day in _field_caps, got %s", raw)
	}

	// 2. Category filters (`-parent,-metadata,-multifield` and `+runtime`) + invalid type -> 400
	code, _, mFlt, raw := doDirectHandlerReqRound61(t, srv8.handleFieldCapsRound61, http.MethodGet, "/fc_idx_1/_field_caps?fields=*&filters=-parent,-metadata,-multifield", "", map[string]string{"index": "fc_idx_1"}, nil)
	if code != http.StatusOK {
		t.Fatalf("category filters failed: %d %s", code, raw)
	}
	fFlt := mFlt["fields"].(map[string]any)
	if fFlt["_id"] != nil || fFlt["nested_grp"] != nil || fFlt["populated_txt.raw"] != nil || fFlt["populated_txt"] == nil {
		t.Fatalf("expected metadata, parent, and multifield excluded while standard field retained, got %s", raw)
	}

	code, _, mRT, raw := doDirectHandlerReqRound61(t, srv8.handleFieldCapsRound61, http.MethodGet, "/fc_idx_1/_field_caps?fields=*&filters=%2Bruntime", "", map[string]string{"index": "fc_idx_1"}, nil)
	if code != http.StatusOK || mRT["fields"].(map[string]any)["rt_day"] == nil || mRT["fields"].(map[string]any)["year"] != nil {
		t.Fatalf("expected +runtime filter to return only runtime fields, got %d %s", code, raw)
	}

	code, _, _, raw = doDirectHandlerReqRound61(t, srv8.handleFieldCapsRound61, http.MethodGet, "/fc_idx_1/_field_caps?fields=*&types=not_a_real_es_type", "", map[string]string{"index": "fc_idx_1"}, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid field_caps types token, got %d %s", code, raw)
	}

	// 3. POST `index_filter` + `?include_empty_fields=false`
	code, _, mPost, raw := doDirectHandlerReqRound61(t, srv8.handleFieldCapsRound61, http.MethodPost, "/fc_idx_*/_field_caps?include_empty_fields=false", `{
		"fields": ["*"],
		"index_filter": {"range": {"year": {"gte": 2023}}},
		"runtime_mappings": {"req_rt": {"type": "long"}}
	}`, map[string]string{"index": "fc_idx_*"}, nil)
	if code != http.StatusOK {
		t.Fatalf("POST _field_caps with index_filter & include_empty_fields=false failed: %d %s", code, raw)
	}
	matchedIndices := mPost["indices"].([]any)
	if len(matchedIndices) != 1 || matchedIndices[0] != "fc_idx_1" {
		t.Fatalf("expected index_filter year>=2023 to select only [fc_idx_1], got %v", matchedIndices)
	}
	fPost := mPost["fields"].(map[string]any)
	if fPost["empty_num"] != nil {
		t.Fatalf("expected empty_num omitted when include_empty_fields=false, got %s", raw)
	}
	if fPost["req_rt"] == nil || fPost["year"] == nil {
		t.Fatalf("expected req_rt and populated year present when include_empty_fields=false, got %s", raw)
	}
}
