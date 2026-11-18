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
	"sync"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newR62AdminTestServer(t *testing.T, dbName, esVer string) (*Server, http.Handler) {
	t.Helper()
	if dbName == "" {
		dbName = "es_compat"
	}
	srv := NewServer(dbName, NewMemoryBackend(false), transpiler.TranspilerOptions{})
	if esVer != "" {
		srv.SetTargetESVersion(esVer)
	}
	t.Cleanup(func() {
		CleanupAdminAndCRUDRegistriesOnCloseR62Admin(srv)
		_ = srv.Close(context.Background())
	})
	return srv, srv.Handler()
}

func doR62AdminReq(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) (int, http.Header, map[string]any, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Host = "127.0.0.1:9200"
	if body != "" && req.Header.Get("Content-Type") == "" {
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

func TestRound62Admin_F20_AnalyzeAndIndexAnalysisConfig(t *testing.T) {
	srv, h := newR62AdminTestServer(t, "es_compat", "8.15.5")

	// 1. Cluster-wide /_analyze: standard, inline tokenizer + char_filter + predicate script + explain + attributes
	code, _, m, raw := doR62AdminReq(t, h, http.MethodPost, "/_analyze", `{
		"tokenizer": "standard",
		"char_filter": ["html_strip", {"type": "mapping", "mappings": ["& => and"]}],
		"filter": [
			"lowercase",
			{"type": "condition", "filter": ["uppercase"], "script": {"source": "token.getTerm().length() > 3"}}
		],
		"text": ["<b>Fast & Easy</b>"],
		"explain": true,
		"attributes": ["term"]
	}`, nil)
	if code != http.StatusOK || m["detail"] == nil {
		t.Fatalf("expected 200 with explain detail on /_analyze, got %d: %s", code, raw)
	}

	// 2. Synonym set + custom index analysis + max_token_count + field resolution
	code, _, _, raw = doR62AdminReq(t, h, http.MethodPut, "/_synonyms/r62-syn-set", `{
		"synonyms_set": [
			{"id": "s1", "synonyms": "ny, new york"}
		]
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /_synonyms/r62-syn-set failed: %d %s", code, raw)
	}
	code, _, _, raw = doR62AdminReq(t, h, http.MethodPut, "/an_idx", `{
		"settings": {
			"index.analyze.max_token_count": 3,
			"analysis": {
				"analyzer": {
					"my_syn_an": {
						"tokenizer": "whitespace",
						"filter": ["lowercase", "my_syn_flt"]
					}
				},
				"filter": {
					"my_syn_flt": {
						"type": "synonym_graph",
						"synonyms_set": "r62-syn-set",
						"updateable": true
					}
				},
				"normalizer": {
					"my_norm": {
						"type": "custom",
						"filter": ["lowercase", "asciifolding"]
					}
				}
			}
		},
		"mappings": {
			"properties": {
				"city": {"type": "text", "analyzer": "my_syn_an"},
				"code": {"type": "keyword", "normalizer": "my_norm"}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT /an_idx failed: %d %s", code, raw)
	}

	code, _, _, raw = doR62AdminReq(t, h, http.MethodPost, "/an_idx/_analyze", `{"field":"city","text":"NY"}`, nil)
	if code != http.StatusOK || !strings.Contains(raw, "york") {
		t.Fatalf("expected synonym expansion on field city, got %d: %s", code, raw)
	}
	code, _, _, raw = doR62AdminReq(t, h, http.MethodPost, "/an_idx/_analyze", `{"field":"code","text":"CAFÉ"}`, nil)
	if code != http.StatusOK || !strings.Contains(raw, `"cafe"`) {
		t.Fatalf("expected normalizer cafe on field code, got %d: %s", code, raw)
	}
	_ = m

	// max_token_count exceeded -> 400 illegal_argument_exception
	code, _, _, raw = doR62AdminReq(t, h, http.MethodPost, "/an_idx/_analyze", `{"analyzer":"whitespace","text":"one two three four"}`, nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "max_token_count") {
		t.Fatalf("expected 400 max_token_count error, got %d: %s", code, raw)
	}

	// Missing index -> 404; closed index -> 400
	if c, _, _, _ := doR62AdminReq(t, h, http.MethodPost, "/missing_an_idx/_analyze", `{"text":"hi"}`, nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on missing index _analyze, got %d", c)
	}
	_, _, _, _ = doR62AdminReq(t, h, http.MethodPost, "/an_idx/_close", "", nil)
	if c, _, _, rB := doR62AdminReq(t, h, http.MethodPost, "/an_idx/_analyze", `{"text":"hi"}`, nil); c != http.StatusBadRequest || !strings.Contains(rB, "index_closed_exception") {
		t.Fatalf("expected 400 index_closed_exception on closed index _analyze, got %d: %s", c, rB)
	}
	_, _, _, _ = doR62AdminReq(t, h, http.MethodPost, "/an_idx/_open", "", nil)

	cfg, opts := srv.buildIndexAnalysisConfigR62Admin("an_idx")
	if cfg == nil || opts.ResolveSynonymSet == nil || opts.EvalPredicateScript == nil {
		t.Fatalf("expected populated buildIndexAnalysisConfigR62Admin")
	}
}

func TestRound62Admin_F0_F1_BulkEOFAndDeprecationWarnings(t *testing.T) {
	_, h8 := newR62AdminTestServer(t, "es_compat", "8.15.5")
	_, h7 := newR62AdminTestServer(t, "es_compat", "7.10.2")

	// F0: Bulk with trailing action metadata line at EOF & require_data_stream
	bulkEOF := strings.Join([]string{
		`{"index":{"_index":"b_eof","_id":"1","require_data_stream":false}}`,
		`{"msg":"ok"}`,
		`{"index":{"_index":"b_eof","_id":"2"}}`,
		"",
	}, "\n")
	code, _, m, raw := doR62AdminReq(t, h8, http.MethodPost, "/_bulk?refresh=true", bulkEOF, map[string]string{"Content-Type": "application/x-ndjson"})
	if code != http.StatusOK || m["errors"] != false {
		t.Fatalf("expected 200 on bulk with trailing action metadata EOF, got %d: %s", code, raw)
	}

	// F1: .tasks delete warning + admin state purge
	var hdr http.Header
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/.tasks", `{}`, nil)
	code, hdr, _, raw = doR62AdminReq(t, h8, http.MethodDelete, "/.tasks", "", nil)
	if code != http.StatusOK || !strings.Contains(hdr.Get("Warning"), ".tasks") {
		t.Fatalf("expected .tasks deprecation Warning on DELETE /.tasks, got %d warn=%q body=%s", code, hdr.Get("Warning"), raw)
	}

	// F1: ES7 synced flush warning, copy_settings warning vs ES8 400, ES8 open/close wait_for_active_shards=index-setting, hot_threads
	_, _, _, _ = doR62AdminReq(t, h7, http.MethodPut, "/f1_v7", `{"settings":{"index.blocks.write":true}}`, nil)
	code, hdr, _, _ = doR62AdminReq(t, h7, http.MethodPost, "/f1_v7/_flush/synced", "", nil)
	if code != http.StatusOK || !strings.Contains(hdr.Get("Warning"), "Synced flush is deprecated") {
		t.Fatalf("expected ES7 synced flush warning, got %d warn=%q", code, hdr.Get("Warning"))
	}
	code, hdr, _, raw = doR62AdminReq(t, h7, http.MethodPost, "/f1_v7/_clone/f1_v7_cloned?copy_settings=true", `{}`, nil)
	if code != http.StatusOK || !strings.Contains(hdr.Get("Warning"), "parameter [copy_settings] is deprecated") {
		t.Fatalf("expected ES7 copy_settings warning, got %d warn=%q body=%s", code, hdr.Get("Warning"), raw)
	}

	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/f1_v8", `{"settings":{"index.blocks.write":true}}`, nil)
	if c, _, _, _ := doR62AdminReq(t, h8, http.MethodPost, "/f1_v8/_clone/f1_v8_cloned?copy_settings=true", `{}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected ES8 copy_settings to fail with 400, got %d", c)
	}
	code, hdr, _, _ = doR62AdminReq(t, h8, http.MethodPost, "/f1_v8/_close?wait_for_active_shards=index-setting", "", nil)
	if code != http.StatusOK || !strings.Contains(hdr.Get("Warning"), "wait_for_active_shards=index-setting") {
		t.Fatalf("expected ES8 close wait_for_active_shards=index-setting warning, got %d warn=%q", code, hdr.Get("Warning"))
	}
	code, hdr, _, _ = doR62AdminReq(t, h8, http.MethodPost, "/f1_v8/_open?wait_for_active_shards=index-setting", "", nil)
	if code != http.StatusOK || !strings.Contains(hdr.Get("Warning"), "wait_for_active_shards=index-setting") {
		t.Fatalf("expected ES8 open wait_for_active_shards=index-setting warning, got %d warn=%q", code, hdr.Get("Warning"))
	}

	code, hdr, _, _ = doR62AdminReq(t, h8, http.MethodGet, "/_nodes/hot_threads?type=mem", "", nil)
	if code != http.StatusOK || hdr.Get("Warning") != "" {
		t.Fatalf("expected clean 200 without Warning on ES8 hot_threads?type=mem, got %d warn=%q", code, hdr.Get("Warning"))
	}
	code, _, _, raw = doR62AdminReq(t, h8, http.MethodGet, "/_nodes/hot_threads?type=gpu", "", nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, "type not supported [gpu]") {
		t.Fatalf("expected 'type not supported [gpu]', got %d: %s", code, raw)
	}
}

func TestRound62Admin_F2_F3_CatClusterNodesAndSnapshots(t *testing.T) {
	srv8, h8 := newR62AdminTestServer(t, "es_compat", "8.15.5")
	_, h7 := newR62AdminTestServer(t, "es_compat", "7.10.2")

	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/cat_idx", `{
		"settings": {"number_of_shards": 1, "number_of_replicas": 1},
		"mappings": {"properties": {"tag": {"type": "keyword"}, "txt_fd": {"type": "text", "fielddata": true}, "vec": {"type": "dense_vector", "dims": 3}}}
	}`, nil)
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPost, "/cat_idx/_doc/1?refresh=true", `{"tag":"a","txt_fd":"hello","vec":[1.0,2.0,3.0]}`, nil)
	recordFieldUsageAccessRound61(srv8, []string{"cat_idx"}, []string{"tag", "txt_fd"})

	// F2: _cat endpoints
	for _, catPath := range []string{
		"/_cat/segments?v=true",
		"/_cat/allocation/_master?v=true&bytes=b",
		"/_cat/allocation/_local?v=true",
		"/_cat/fielddata?v=true&fields=txt_fd",
		"/_cat/nodeattrs?v=true",
		"/_cat/recovery?v=true",
		"/_cat/shards?v=true",
		"/_cat/shards?help=true",
		"/_cat/thread_pool?h=pid,id,h,i,po&v=true",
		"/_cat/nodes?h=node.role",
	} {
		c, _, _, body := doR62AdminReq(t, h8, http.MethodGet, catPath, "", nil)
		if c != http.StatusOK || len(strings.TrimSpace(body)) == 0 {
			t.Fatalf("GET %s failed: %d %q", catPath, c, body)
		}
	}
	_, _, _, roles7 := doR62AdminReq(t, h7, http.MethodGet, "/_cat/nodes?h=node.role", "", nil)
	if strings.Contains(strings.TrimSpace(roles7), "f") {
		t.Fatalf("expected ES7 cat.nodes role string to omit 'f', got %q", roles7)
	}

	// F3: _cluster/allocation/explain, _cluster/reroute, _cluster/state, _cluster/stats, reload_secure_settings, _snapshot
	code, _, m, raw := doR62AdminReq(t, h8, http.MethodGet, "/_cluster/allocation/explain?include_disk_info=true", "", nil)
	if code != http.StatusOK || m["cluster_info"] == nil || m["current_state"] != "unassigned" {
		t.Fatalf("expected unassigned replica allocation explain with cluster_info, got %d: %s", code, raw)
	}
	code, _, m, raw = doR62AdminReq(t, h8, http.MethodPost, "/_cluster/allocation/explain", `{"index":"cat_idx","shard":0,"primary":true}`, nil)
	if code != http.StatusOK || m["can_remain_on_current_node"] != "yes" {
		t.Fatalf("expected primary allocation explain can_remain_on_current_node=yes, got %d: %s", code, raw)
	}

	code, hdr, m, raw := doR62AdminReq(t, h8, http.MethodPost, "/_cluster/reroute?explain=true", `{"commands":[{"cancel":{"index":"cat_idx","shard":0,"node":"doris-node-1"}}]}`, nil)
	if code != http.StatusOK || m["explanations"] == nil || m["state"] == nil || hdr.Get("Warning") == "" {
		t.Fatalf("expected reroute?explain=true with state + Warning, got %d warn=%q: %s", code, hdr.Get("Warning"), raw)
	}

	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/cat_idx/_settings", `{"index.blocks.write":true}`, nil)
	code, _, _, raw = doR62AdminReq(t, h8, http.MethodGet, "/_cluster/state/blocks/cat_idx", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, `"indices"`) {
		t.Fatalf("expected blocks.indices in cluster state, got %d: %s", code, raw)
	}
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/cat_idx/_settings", `{"index.blocks.write":false}`, nil)
	if c, _, _, _ := doR62AdminReq(t, h8, http.MethodGet, "/_cluster/state/metadata/missing_cs_idx?ignore_unavailable=false", "", nil); c != http.StatusNotFound {
		t.Fatalf("expected 404 on missing index in _cluster/state with ignore_unavailable=false, got %d", c)
	}

	code, _, m, raw = doR62AdminReq(t, h8, http.MethodPost, "/_nodes/reload_secure_settings", `{"secure_settings_password":"wrong"}`, nil)
	if code != http.StatusOK || !strings.Contains(raw, "Provided keystore password was incorrect") {
		t.Fatalf("expected 200 with reload_exception on wrong keystore password, got %d: %s", code, raw)
	}
	_ = m

	// Snapshots: repo uuid, clone acknowledged, restore SNAPSHOT recovery source
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/_snapshot/r62_repo", `{"type":"fs","settings":{"location":"/tmp/r62_snap"}}`, nil)
	code, _, _, raw = doR62AdminReq(t, h8, http.MethodGet, "/_snapshot/r62_repo", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, `"uuid"`) {
		t.Fatalf("expected uuid in GET /_snapshot/r62_repo, got %d: %s", code, raw)
	}
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/_snapshot/r62_repo/snap1?wait_for_completion=true", `{"indices":"cat_idx"}`, nil)
	code, _, m, raw = doR62AdminReq(t, h8, http.MethodPost, "/_snapshot/r62_repo/snap1/_clone/snap2", `{"indices":"cat_idx"}`, nil)
	if code != http.StatusOK || m["acknowledged"] != true {
		t.Fatalf("expected acknowledged:true on snapshot _clone, got %d: %s", code, raw)
	}
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPost, "/_snapshot/r62_repo/snap2/_restore?wait_for_completion=true", `{"indices":"cat_idx","rename_pattern":"cat_idx","rename_replacement":"cat_restored"}`, nil)
	code, _, _, raw = doR62AdminReq(t, h8, http.MethodGet, "/cat_restored/_recovery?human=true", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, `"SNAPSHOT"`) {
		t.Fatalf("expected SNAPSHOT recovery type after restore, got %d: %s", code, raw)
	}

	code, _, _, raw = doR62AdminReq(t, h8, http.MethodGet, "/_cluster/stats?human=true", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, `"dense_vector"`) || !strings.Contains(raw, `"indexing_pressure"`) {
		t.Fatalf("expected enriched /_cluster/stats, got %d: %s", code, raw)
	}
}

func TestRound62Admin_F4_F5_F7_F25_IndicesFieldCapsSyntheticSourceAndSQLIdent(t *testing.T) {
	_, h8 := newR62AdminTestServer(t, "es_compat", "8.15.5")
	_, h7 := newR62AdminTestServer(t, "es_compat", "7.10.2")

	// escapeDorisDBIdent preserves hyphens/dots verbatim while doubling embedded backticks (matching sanitizeAndEscapeDorisIdent contract)
	if got := escapeDorisDBIdent("tenant-a.prod`1"); got != "tenant-a.prod``1" {
		t.Fatalf("unexpected escapeDorisDBIdent result: %q", got)
	}
	if got := redactShadowURLR62Admin("https://admin:s3cr3t@es.internal:9200"); strings.Contains(got, "s3cr3t") {
		t.Fatalf("expected redacted shadow URL, got %q", got)
	}

	// ES7 unfiltered wildcard alias delete vs filtered wildcard alias delete
	_, _, _, _ = doR62AdminReq(t, h7, http.MethodPut, "/base_v7", `{"aliases":{"unfilt_alias":{},"filt_alias":{"filter":{"term":{"k":"v"}}}}}`, nil)
	if c, _, _, rB := doR62AdminReq(t, h7, http.MethodDelete, "/unfilt_alia*", "", nil); c != http.StatusOK {
		t.Fatalf("expected 200 on ES7 unfiltered wildcard alias delete, got %d: %s", c, rB)
	}
	if c, _, _, _ := doR62AdminReq(t, h7, http.MethodDelete, "/filt_alia*", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on ES7 filtered wildcard alias delete, got %d", c)
	}

	// get_mapping expand_wildcards=none & ES8 put_mapping typed error
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/gm_1", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, nil)
	code, _, m, raw := doR62AdminReq(t, h8, http.MethodGet, "/gm_*/_mapping?expand_wildcards=none", "", nil)
	if code != http.StatusOK || len(m) != 0 {
		t.Fatalf("expected empty 200 {} on expand_wildcards=none, got %d: %s", code, raw)
	}
	code, _, _, raw = doR62AdminReq(t, h8, http.MethodPut, "/gm_1/_mapping", `{"_doc":{"properties":{"x":{"type":"keyword"}}}}`, nil)
	if code != http.StatusBadRequest || !strings.Contains(raw, `"Types cannot be provided in put mapping requests"`) {
		t.Fatalf("expected ES8 put_mapping _doc error message, got %d: %s", code, raw)
	}

	// force_synthetic_source on get & mget (and no internal marker leak)
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/fs_ok", `{"mappings":{"properties":{"host":{"type":"keyword"},"n":{"type":"long"}}}}`, nil)
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/fs_bad", `{"mappings":{"properties":{"body":{"type":"text"}}}}`, nil)
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/fs_ok/_doc/1?refresh=true", `{"host":"srv-1","n":42}`, nil)
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/fs_bad/_doc/1?refresh=true", `{"body":"raw text"}`, nil)

	code, _, _, raw = doR62AdminReq(t, h8, http.MethodGet, "/fs_ok/_doc/1?force_synthetic_source=true", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, `"srv-1"`) || strings.Contains(raw, forceSynSourceMarkerKeyR62Admin) {
		t.Fatalf("GET ?force_synthetic_source=true failed or leaked marker: %d %s", code, raw)
	}
	if c, _, _, rB := doR62AdminReq(t, h8, http.MethodGet, "/fs_ok/_doc/999?force_synthetic_source=true", "", nil); c != http.StatusNotFound || strings.Contains(rB, forceSynSourceMarkerKeyR62Admin) {
		t.Fatalf("404 GET ?force_synthetic_source=true failed or leaked marker: %d %s", c, rB)
	}
	if c, _, _, _ := doR62AdminReq(t, h8, http.MethodGet, "/fs_bad/_doc/1?force_synthetic_source=true", "", nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on unstored text GET ?force_synthetic_source=true, got %d", c)
	}
	code, _, _, raw = doR62AdminReq(t, h8, http.MethodPost, "/_mget?force_synthetic_source=true", `{
		"docs": [
			{"_index": "fs_ok", "_id": "1"},
			{"_index": "fs_bad", "_id": "1"}
		]
	}`, nil)
	if code != http.StatusOK || !strings.Contains(raw, `"srv-1"`) || !strings.Contains(raw, `"illegal_argument_exception"`) || strings.Contains(raw, forceSynSourceMarkerKeyR62Admin) {
		t.Fatalf("POST /_mget?force_synthetic_source=true unexpected response: %d %s", code, raw)
	}

	// field_caps: searchable/aggregatable merge, non_searchable_indices, include_unmapped, composite runtime, invalid Painless
	_, _, _, _ = doR62AdminReq(t, h7, http.MethodPut, "/fc1", `{"mappings":{"properties":{"txt":{"type":"text","index":false},"only1":{"type":"keyword"}}}}`, nil)
	_, _, _, _ = doR62AdminReq(t, h7, http.MethodPut, "/fc2", `{"mappings":{"properties":{"txt":{"type":"text","index":true}}}}`, nil)
	code, _, m, raw = doR62AdminReq(t, h7, http.MethodGet, "/fc1,fc2/_field_caps?fields=txt,only1&include_unmapped=true", "", nil)
	if code != http.StatusOK {
		t.Fatalf("GET _field_caps failed: %d %s", code, raw)
	}
	fieldsMap := m["fields"].(map[string]any)
	txtEntry := fieldsMap["txt"].(map[string]any)["text"].(map[string]any)
	if txtEntry["searchable"] != false || txtEntry["non_searchable_indices"] == nil {
		t.Fatalf("expected searchable=false & non_searchable_indices=[fc1], got %s", raw)
	}
	only1Map := fieldsMap["only1"].(map[string]any)
	if only1Map["keyword"] == nil || only1Map["unmapped"] == nil {
		t.Fatalf("expected both keyword and unmapped entries for only1, got %s", raw)
	}

	code, _, _, raw = doR62AdminReq(t, h8, http.MethodPost, "/gm_1/_field_caps?fields=comp.*", `{
		"runtime_mappings": {
			"comp": {
				"type": "composite",
				"script": "emit(Map.of('subk', 'v'))",
				"fields": {"subk": {"type": "keyword"}}
			}
		}
	}`, nil)
	if code != http.StatusOK || !strings.Contains(raw, `"comp.subk"`) {
		t.Fatalf("expected composite runtime subfield comp.subk, got %d: %s", code, raw)
	}
	if c, _, _, _ := doR62AdminReq(t, h8, http.MethodPost, "/gm_1/_field_caps?fields=*", `{
		"runtime_mappings": {"bad_rt": {"type": "keyword", "script": "if ("}}
	}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid Painless script in field_caps runtime_mappings, got %d", c)
	}

	// _validate/query ("did you mean [bool]?", unknown body key -> 200 valid:false) & _rollover min_*-only 400 in ES8
	code, _, m, raw = doR62AdminReq(t, h8, http.MethodPost, "/gm_1/_validate/query?explain=true", `{"query":{"boool":{}}}`, nil)
	if code != http.StatusOK || m["valid"] != false || !strings.Contains(raw, "did you mean [bool]?") {
		t.Fatalf("expected did you mean [bool]? on _validate/query?explain=true, got %d: %s", code, raw)
	}
	code, _, m, raw = doR62AdminReq(t, h8, http.MethodPost, "/gm_1/_validate/query", `{"bogus_top": 1}`, nil)
	if code != http.StatusOK || m["valid"] != false || m["error"] != nil {
		t.Fatalf("expected 200 {valid:false} without error when explain=false, got %d: %s", code, raw)
	}

	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPut, "/ro-000001", `{"aliases":{"ro_alias":{"is_write_index":true}}}`, nil)
	if c, _, _, _ := doR62AdminReq(t, h8, http.MethodPost, "/ro_alias/_rollover", `{"conditions":{"min_docs":1}}`, nil); c != http.StatusBadRequest {
		t.Fatalf("expected ES8 rollover with only min_* condition to fail with 400, got %d", c)
	}

	// field_usage_stats knn_vectors & default run_expensive_tasks=true in ES8
	_, _, _, _ = doR62AdminReq(t, h8, http.MethodPost, "/gm_1/_search", `{"knn":{"field":"vec","query_vector":[1,2,3],"k":1,"num_candidates":2},"fields":["k"],"_source":false}`, nil)
	code, _, _, raw = doR62AdminReq(t, h8, http.MethodGet, "/gm_1/_field_usage_stats", "", nil)
	if code != http.StatusOK || !strings.Contains(raw, `"knn_vectors"`) {
		t.Fatalf("expected 200 with knn_vectors on /gm_1/_field_usage_stats, got %d: %s", code, raw)
	}
}

func TestRound62Admin_F28_ScrollBoundsExpiryAndStateCaps(t *testing.T) {
	srv, h := newR62AdminTestServer(t, "es_compat", "8.15.5")

	_, _, _, _ = doR62AdminReq(t, h, http.MethodPut, "/scr_idx", `{"mappings":{"properties":{"n":{"type":"long"}}}}`, nil)
	var bulk strings.Builder
	for i := 1; i <= 6; i++ {
		fmt.Fprintf(&bulk, "{\"index\":{\"_index\":\"scr_idx\",\"_id\":\"%d\"}}\n{\"n\":%d}\n", i, i)
	}
	_, _, _, _ = doR62AdminReq(t, h, http.MethodPost, "/_bulk?refresh=true", bulk.String(), map[string]string{"Content-Type": "application/x-ndjson"})

	// 1. Cap max_open_scroll_context = 2 -> 3rd open scroll fails with 429 too_many_requests
	_, _, _, _ = doR62AdminReq(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"search.max_open_scroll_context":2}}`, nil)

	c1, _, m1, r1 := doR62AdminReq(t, h, http.MethodPost, "/scr_idx/_search?scroll=60ms", `{"size":1,"sort":[{"n":"asc"}]}`, nil)
	c2, _, m2, r2 := doR62AdminReq(t, h, http.MethodPost, "/scr_idx/_search?scroll=60ms", `{"size":1,"sort":[{"n":"asc"}]}`, nil)
	if c1 != http.StatusOK || c2 != http.StatusOK {
		t.Fatalf("expected first 2 scroll contexts to succeed: c1=%d (%s) c2=%d (%s)", c1, r1, c2, r2)
	}
	c3, _, _, r3 := doR62AdminReq(t, h, http.MethodPost, "/scr_idx/_search?scroll=1m", `{"size":1}`, nil)
	if c3 != http.StatusTooManyRequests || !strings.Contains(r3, "max_open_scroll_context") {
		t.Fatalf("expected 429 too_many_requests on 3rd scroll context, got %d: %s", c3, r3)
	}

	// Wait for 60ms TTL to expire; lazy sweep must reclaim both and allow opening a new scroll!
	time.Sleep(90 * time.Millisecond)
	c4, _, m4, r4 := doR62AdminReq(t, h, http.MethodPost, "/scr_idx/_search?scroll=5m", `{"size":1,"sort":[{"n":"asc"}]}`, nil)
	if c4 != http.StatusOK {
		t.Fatalf("expected lazy expiry sweep to allow new scroll after TTL, got %d: %s", c4, r4)
	}

	// 2. Probing expired initial token (m1["_scroll_id"]) must return 404 WITHOUT leaking into scrollSessions!
	expiredTok, _ := m1["_scroll_id"].(string)
	_ = m2
	st := getOrCreateServerStateR61CRUD(srv)
	st.mu.RLock()
	beforeLen := len(st.scrollSessions)
	st.mu.RUnlock()

	cExp, _, _, _ := doR62AdminReq(t, h, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll":"1m","scroll_id":%q}`, expiredTok), nil)
	if cExp != http.StatusNotFound {
		t.Fatalf("expected 404 on expired scroll token, got %d", cExp)
	}
	st.mu.RLock()
	afterLen := len(st.scrollSessions)
	st.mu.RUnlock()
	if afterLen > beforeLen {
		t.Fatalf("expired stateless scroll probe leaked session entry: before=%d after=%d", beforeLen, afterLen)
	}

	// 3. Multi-page scroll bounds Tokens <= 3 and EOF token stays idempotent across repeated EOF calls!
	curTok, _ := m4["_scroll_id"].(string)
	for step := 0; step < 7; step++ {
		code, _, mp, raw := doR62AdminReq(t, h, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll":"5m","scroll_id":%q}`, curTok), nil)
		if code != http.StatusOK {
			t.Fatalf("scroll step %d failed: %d %s", step, code, raw)
		}
		curTok, _ = mp["_scroll_id"].(string)
	}
	codeEOF, _, mpEOF, _ := doR62AdminReq(t, h, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll":"5m","scroll_id":%q}`, curTok), nil)
	if codeEOF != http.StatusOK || mpEOF["_scroll_id"] != curTok {
		t.Fatalf("expected idempotent EOF _scroll_id=%q, got code=%d id=%v", curTok, codeEOF, mpEOF["_scroll_id"])
	}
	st.mu.RLock()
	sess := st.scrollSessions[curTok]
	tokCount := 0
	if sess != nil {
		tokCount = len(sess.Tokens)
	}
	st.mu.RUnlock()
	if tokCount == 0 || tokCount > 3 {
		t.Fatalf("expected bounded sess.Tokens <= 3, got %d", tokCount)
	}

	// 4. Concurrent atomic async IDs, bounded async registry eviction, and cleanup on Close
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = nextAsyncSearchIDR62Admin()
				_ = nextESQLAsyncQueryIDR62Admin()
				_ = nextEQLSearchIDR62Admin()
			}
		}()
	}
	wg.Wait()

	reg := make(map[string]map[string]any)
	for i := 0; i < maxAsyncRegistryEntriesR62Admin+10; i++ {
		evictBoundedAsyncRegistryLockedR62Admin(reg)
		reg[fmt.Sprintf("id-%d", i)] = map[string]any{"start_time_in_millis": int64(i)}
	}
	if len(reg) > maxAsyncRegistryEntriesR62Admin {
		t.Fatalf("expected bounded async registry <= %d, got %d", maxAsyncRegistryEntriesR62Admin, len(reg))
	}

	CleanupAdminAndCRUDRegistriesOnCloseR62Admin(srv)
	_ = srv.Close(context.Background())
	round61AdminRegistryMu.RLock()
	_, inAdmin := round61AdminRegistry[srv]
	round61AdminRegistryMu.RUnlock()
	serverStateRegistryMuR61CRUD.RLock()
	_, inCRUD := serverStateRegistryR61CRUD[srv]
	serverStateRegistryMuR61CRUD.RUnlock()
	if inAdmin || inCRUD {
		t.Fatalf("expected srv removed from global registries, got inAdmin=%v inCRUD=%v", inAdmin, inCRUD)
	}
}

func TestRound62Admin_ES8SDKClientMetaNodesStatsSchema(t *testing.T) {
	srv := NewServer("es_compat", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	code, _, _, raw := doR62AdminReq(t, h, http.MethodPut, "/_ingest/pipeline/sdk_v8_pipe", `{"processors":[{"lowercase":{"field":"category"}}]}`, nil)
	if code != http.StatusOK {
		t.Fatalf("PUT pipeline failed (%d): %s", code, raw)
	}

	code, _, _, raw = doR62AdminReq(t, h, http.MethodGet, "/_nodes/stats", "", map[string]string{
		"X-Elastic-Client-Meta": "es=8.15.0p,go=1.25",
		"User-Agent":            "go-elasticsearch/8.15.0",
	})
	if code != http.StatusOK || !strings.Contains(raw, `"ingested_as_first_pipeline_in_bytes"`) {
		t.Fatalf("expected ES8 IngestStats fields via X-Elastic-Client-Meta es=8.*, got %d: %s", code, raw)
	}
}
