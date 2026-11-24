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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newR66CovServer(t *testing.T, ver string) (*Server, http.Handler) {
	t.Helper()
	mem := NewMemoryBackend(false)
	srv := NewServer("es_r66", mem, transpiler.TranspilerOptions{})
	if ver != "" {
		srv.SetTargetESVersion(ver)
	}
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, srv.Handler()
}

func doR66CovHTTP(t *testing.T, h http.Handler, method, path, body string, hdrs map[string]string) (int, http.Header, map[string]any, string) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		if hdrs["Content-Type"] == "" {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req = httptest.NewRequest(method, path, nil)
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

func mustR66CovHTTP(t *testing.T, h http.Handler, method, path, body string, want int) map[string]any {
	t.Helper()
	code, _, parsed, raw := doR66CovHTTP(t, h, method, path, body, nil)
	if code != want {
		t.Fatalf("%s %s: expected %d, got %d body=%s", method, path, want, code, raw)
	}
	return parsed
}

func TestRound66CovServer_BulkUpdateByQueryDeleteByQueryAndDocOps(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.5")

	// Setup regular indices, reroute index, routing-required index, TSDB index, and data stream with failure store.
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_src", `{"mappings":{"properties":{"title":{"type":"text"},"tag":{"type":"keyword"},"cnt":{"type":"long"},"flag":{"type":"boolean"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_dst", `{"mappings":{"properties":{"title":{"type":"text"},"tag":{"type":"keyword"},"cnt":{"type":"long"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_rt", `{"mappings":{"_routing":{"required":true},"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_ts", `{
		"settings":{"index":{"mode":"time_series","routing_path":["host"]}},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true},"val":{"type":"long","time_series_metric":"gauge"}}}
	}`, http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/r66_ds_tpl", `{
		"index_patterns":["r66-ds-*"],
		"data_stream":{"failure_store":{"enabled":true}},
		"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"msg":{"type":"keyword"}}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_data_stream/r66-ds-logs", "", http.StatusOK)

	// Ingest pipelines: one that drops when tag=="drop", one that reroutes _index/_id, one that fails.
	mustR66CovHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r66_drop_or_reroute", `{
		"processors": [
			{"drop": {"if": "ctx.tag == 'drop'"}},
			{"set": {"if": "ctx.tag == 'move'", "field": "_index", "value": "r66_dst"}},
			{"set": {"if": "ctx.tag == 'move'", "field": "_id", "value": "{{_id}}-moved"}},
			{"set": {"field": "processed", "value": true}}
		]
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r66_fail", `{
		"processors": [{"fail": {"message": "forced pipeline error"}}]
	}`, http.StatusOK)

	// 1. Bulk errors & branches: data stream explicit index/update/delete, failure store timestamp, TSDB bulk update/delete/conflict, bulk update+upsert+pipeline drop/reroute
	bulkNDJSON := strings.Join([]string{
		`{"index":{"_index":"r66-ds-logs","_id":"bad1"}}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","msg":"explicit-index-rejected"}`,
		`{"create":{"_index":"r66-ds-logs"}}`,
		`{"msg":"missing-ts-goes-to-failure-store"}`,
		`{"update":{"_index":"r66-ds-logs","_id":"u1"}}`,
		`{"doc":{"msg":"u"}}`,
		`{"delete":{"_index":"r66-ds-logs","_id":"d1"}}`,
		`{"update":{"_index":"r66_ts","_id":"t1"}}`,
		`{"doc":{"val":1}}`,
		`{"delete":{"_index":"r66_ts","_id":"bad_tsdb_id"}}`,
		`{"create":{"_index":"r66_ts"}}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","val":10}`,
		`{"create":{"_index":"r66_ts"}}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","val":20}`,
		`{"index":{"_index":"r66_src","_id":"1"}}`,
		`{"title":"alpha one","tag":"keep","cnt":1,"flag":true}`,
		`{"index":{"_index":"r66_src","_id":"2"}}`,
		`{"title":"alpha two","tag":"keep","cnt":2,"flag":true}`,
		`{"index":{"_index":"r66_src","_id":"3"}}`,
		`{"title":"beta three","tag":"keep","cnt":3,"flag":false}`,
		`{"update":{"_index":"r66_src","_id":"upsert_drop","pipeline":"r66_drop_or_reroute"}}`,
		`{"doc":{"tag":"drop"},"doc_as_upsert":true}`,
		`{"update":{"_index":"r66_src","_id":"1","pipeline":"r66_drop_or_reroute"}}`,
		`{"script":{"source":"ctx.op = 'none'"}}`,
		`{"update":{"_index":"r66_src","_id":"2","pipeline":"r66_drop_or_reroute"}}`,
		`{"doc":{"tag":"move"}}`,
		`{"update":{"_index":"r66_src","_id":"upsert_fail","pipeline":"r66_fail"}}`,
		`{"doc":{"tag":"x"},"doc_as_upsert":true}`,
		"",
	}, "\n")
	bulkResp := mustR66CovHTTP(t, h, http.MethodPost, "/_bulk?refresh=true&list_executed_pipelines=true", bulkNDJSON, http.StatusOK)
	if bulkResp["errors"] != true {
		t.Fatalf("expected bulk errors=true for intentional invalid items, got %v", bulkResp)
	}
	if got := mustR66CovHTTP(t, h, http.MethodGet, "/r66_dst/_doc/2-moved", "", http.StatusOK); got["found"] != true {
		t.Fatalf("expected rerouted doc 2-moved in r66_dst, got %v", got)
	}
	mustR66CovHTTP(t, h, http.MethodGet, "/r66_src/_doc/2", "", http.StatusNotFound)

	// 2. handleUpdateDoc: noop+pipeline modify/drop/reroute, script delete, TSDB put/delete, _source/_explain routes
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_update/1?pipeline=r66_drop_or_reroute&refresh=true", `{"script":{"source":"ctx.op = 'none'"}}`, http.StatusOK)
	dropUpd := mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_update/drop_me?pipeline=r66_drop_or_reroute&_source=true", `{"doc":{"tag":"drop"},"doc_as_upsert":true}`, http.StatusOK)
	if dropUpd["result"] != "noop" {
		t.Fatalf("expected noop on pipeline drop, got %v", dropUpd)
	}
	rerouteUpd := mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_update/1?pipeline=r66_drop_or_reroute&refresh=true", `{"doc":{"tag":"move"}}`, http.StatusOK)
	if rerouteUpd["_index"] != "r66_dst" || rerouteUpd["_id"] != "1-moved" {
		t.Fatalf("expected rerouted update to r66_dst/1-moved, got %v", rerouteUpd)
	}
	// Script delete via _update
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_src/_doc/del_script?refresh=true", `{"title":"to delete","tag":"x","cnt":5}`, http.StatusCreated)
	delScriptResp := mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_update/del_script?refresh=true", `{"script":{"source":"ctx.op = 'delete'"}}`, http.StatusOK)
	if delScriptResp["result"] != "deleted" {
		t.Fatalf("expected deleted via update script, got %v", delScriptResp)
	}
	// _all/_source in ES7 & 405 method errors on 4-segment doc routes
	_, h7 := newR66CovServer(t, "7.10.2")
	mustR66CovHTTP(t, h7, http.MethodPut, "/r66_v7/_doc/1?refresh=true", `{"a":"b"}`, http.StatusCreated)
	mustR66CovHTTP(t, h7, http.MethodGet, "/r66_v7/_all/1/_source", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/r66_src/_doc/3/_update", "", http.StatusMethodNotAllowed)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_doc/3/_source", "", http.StatusMethodNotAllowed)
	mustR66CovHTTP(t, h, http.MethodGet, "/r66_src/_doc/3/_create", "", http.StatusMethodNotAllowed)
	mustR66CovHTTP(t, h, http.MethodGet, "/r66_src/_doc/3/_explain", `{"query":{"match":{"title":"beta"}}}`, http.StatusOK)

	// TSDB delete missing/not-found & OCC external tombstone delete
	mustR66CovHTTP(t, h, http.MethodDelete, "/r66_ts/_doc/nonexistent_ts_id", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_src/_doc/ext1?version=5&version_type=external&refresh=true", `{"tag":"v5"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodDelete, "/r66_src/_doc/ext1?version=6&version_type=external&refresh=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/r66_src/_doc/ext_missing?version=2&version_type=external", "", http.StatusNotFound)

	// 3. handleUpdateByQuery: scroll_size, runtime script filter, slices, routing, pipeline drop/reroute, script delete, conflicts, async task
	for i := 10; i < 16; i++ {
		mustR66CovHTTP(t, h, http.MethodPut, fmt.Sprintf("/r66_src/_doc/%d?routing=r1&refresh=true", i),
			fmt.Sprintf(`{"title":"ubq doc %d","tag":"ubq","cnt":%d,"flag":true}`, i, i), http.StatusCreated)
	}
	ubqResp := mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_update_by_query?scroll_size=2&routing=r1&slices=2&conflicts=proceed&refresh=true", `{
		"query": {
			"bool": {
				"must": [{"term": {"tag": "ubq"}}],
				"filter": [{"script": {"script": {"source": "doc['cnt'].value >= 10"}}}]
			}
		},
		"script": {
			"source": "if (ctx._source.cnt == 10) { ctx.op = 'delete'; } else if (ctx._source.cnt == 11) { ctx._index = 'r66_dst'; } else if (ctx._source.cnt == 12) { ctx.op = 'noop'; } else { ctx._source.cnt += 100; }"
		}
	}`, http.StatusOK)
	if ubqResp["deleted"] == nil || ubqResp["slices"] == nil {
		t.Fatalf("unexpected _update_by_query response: %v", ubqResp)
	}
	// _update_by_query with pipeline dropping doc & TSDB immutability failure
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_update_by_query?pipeline=r66_drop_or_reroute&refresh=true", `{
		"query":{"term":{"tag":"ubq"}},
		"script":{"source":"ctx._source.tag = 'drop'"}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_ts/_update_by_query", `{
		"query":{"match_all":{}},
		"script":{"source":"ctx._source.host = 'mutated'"}
	}`, http.StatusBadRequest)
	// Async _update_by_query task
	asyncUBQ := mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_update_by_query?wait_for_completion=false", `{"query":{"term":{"tag":"none"}}}`, http.StatusOK)
	ubqTaskID, _ := asyncUBQ["task"].(string)
	if ubqTaskID == "" {
		t.Fatalf("expected async task id, got %v", asyncUBQ)
	}
	waitR66CovTaskDone(t, h, ubqTaskID)

	// 4. handleDeleteByQuery: error branches + slice + runtime script + scroll_size + async
	mustR66CovHTTP(t, h, http.MethodGet, "/r66_src/_delete_by_query", "", http.StatusMethodNotAllowed)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_nomatch_*/_delete_by_query?expand_wildcards=none&allow_no_indices=false", `{"query":{"match_all":{}}}`, http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_delete_by_query?max_docs=1&slices=2", `{"query":{"match_all":{}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_delete_by_query", `{"query":{"script":{"script":{"id":"missing_stored_script"}}}}`, http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_delete_by_query", `{"query":{"script":{"script":{"source":"return ("}}}}`, http.StatusBadRequest)
	dbqResp := mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_delete_by_query?scroll_size=2&slices=auto&conflicts=proceed&refresh=true", `{
		"query":{"bool":{"filter":[{"script":{"script":{"source":"doc['cnt'].value > 100"}}}]}}
	}`, http.StatusOK)
	if dbqResp["deleted"] == nil {
		t.Fatalf("expected deleted count in DBQ response: %v", dbqResp)
	}
	asyncDBQ := mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_delete_by_query?wait_for_completion=false", `{"query":{"term":{"tag":"none"}}}`, http.StatusOK)
	dbqTaskID, _ := asyncDBQ["task"].(string)
	if dbqTaskID == "" {
		t.Fatalf("expected async DBQ task id, got %v", asyncDBQ)
	}
	waitR66CovTaskDone(t, h, dbqTaskID)
	// Closed and blocked DBQ checks
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_close", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_src/_delete_by_query", `{"query":{"match_all":{}}}`, http.StatusBadRequest)
	_ = srv // keep used
}

func waitR66CovTaskDone(t *testing.T, h http.Handler, taskID string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		code, _, body, _ := doR66CovHTTP(t, h, http.MethodGet, "/_tasks/"+taskID, "", nil)
		if code == http.StatusOK && body["completed"] == true {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("async task %s did not complete in time", taskID)
}

func TestRound66CovServer_MSearchScrollAndUnifiedMatchedFieldsHighlight(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.5")

	mustR66CovHTTP(t, h, http.MethodPut, "/r66_ms1", `{
		"settings":{
			"analysis":{
				"analyzer":{"my_en":{"type":"standard"}}
			}
		},
		"mappings":{
			"properties":{
				"title":{
					"type":"text",
					"fields":{"en":{"type":"text","analyzer":"my_en"}}
				},
				"tag":{"type":"keyword"},
				"vec":{"type":"dense_vector","dims":2,"index":true,"similarity":"cosine"},
				"items":{"type":"nested","properties":{"name":{"type":"text"}}}
			}
		}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_ms2", `{"mappings":{"properties":{"title":{"type":"text"},"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_ms_closed", `{}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_ms_closed/_close", "", http.StatusOK)

	bulk := strings.Join([]string{
		`{"index":{"_index":"r66_ms1","_id":"1"}}`,
		`{"title":"The quick brown fox jumps over the lazy dog and <escaped> words near running foxes","tag":"a","vec":[1.0,0.0],"items":[{"name":"nested fox"}]}`,
		`{"index":{"_index":"r66_ms1","_id":"2"}}`,
		`{"title":"Another document without fox match here","tag":"b","vec":[0.0,1.0],"items":[{"name":"other"}]}`,
		`{"index":{"_index":"r66_ms2","_id":"3"}}`,
		`{"title":"Second index fox document","tag":"a"}`,
		"",
	}, "\n")
	mustR66CovHTTP(t, h, http.MethodPost, "/_bulk?refresh=true", bulk, http.StatusOK)

	// 1. Unified highlight matched_fields covering collectMatchedFieldClausesR66, extractLuceneClausesForMatchedFieldsR66, buildHighlightedSnippetsFromByteSpansR66
	b64Wrapper := base64.StdEncoding.EncodeToString([]byte(`{"match":{"title.en":"foxes"}}`))
	hlQueries := []string{
		fmt.Sprintf(`{
			"query":{
				"bool":{
					"must":[
						{"match":{"title":"quick"}},
						{"match_phrase":{"title":{"query":"brown fox","slop":1}}},
						{"match_phrase_prefix":{"title":"lazy d"}},
						{"match_bool_prefix":{"title":"over t"}},
						{"multi_match":{"query":"quick brown","type":"phrase","fields":["title","title.en"]}},
						{"combined_fields":{"query":"jumps","fields":["title"]}},
						{"query_string":{"default_field":"title","query":"title:(+quick \"brown fox\"~2 OR la*y) AND words"}},
						{"simple_query_string":{"fields":["title"],"query":"dog"}},
						{"wildcard":{"title":"qu*ck"}},
						{"prefix":{"title":"bro"}}
					],
					"should":[
						{"term":{"title":"fox"}},
						{"terms":{"title":["dog","fox"]}},
						{"dis_max":{"queries":[{"match":{"title":"fox"}}]}},
						{"boosting":{"positive":{"match":{"title":"fox"}},"negative":{"term":{"tag":"z"}},"negative_boost":0.2}},
						{"constant_score":{"filter":{"match":{"title":"fox"}}}},
						{"function_score":{"query":{"match":{"title":"fox"}},"boost":1.5}},
						{"script_score":{"query":{"match":{"title":"fox"}},"script":{"source":"1.0"}}},
						{"wrapper":{"query":%q}},
						{"pinned":{"ids":["1"],"organic":{"match":{"title":"fox"}}}}
					]
				}
			},
			"highlight":{
				"type":"unified",
				"encoder":"html",
				"pre_tags":["<em>"],
				"post_tags":["</em>"],
				"fields":{
					"title":{
						"matched_fields":["title","title.en"],
						"fragment_size":24,
						"number_of_fragments":2,
						"no_match_size":10,
						"max_analyzed_offset":80,
						"require_field_match":true
					}
				}
			}
		}`, b64Wrapper),
		`{
			"query":{"nested":{"path":"items","query":{"match":{"items.name":"fox"}}}},
			"highlight":{"type":"unified","fields":{"title":{"matched_fields":["title","title.en"],"no_match_size":12,"require_field_match":true,"number_of_fragments":0}}}
		}`,
	}
	for _, q := range hlQueries {
		res := mustR66CovHTTP(t, h, http.MethodPost, "/r66_ms1/_search", q, http.StatusOK)
		hitsObj, _ := res["hits"].(map[string]any)
		if hitsObj == nil {
			t.Fatalf("missing hits in %v", res)
		}
	}

	// 2. handleMSearch: valid multi-item + PIT + typed_keys + filter_path + error items
	pitResp := mustR66CovHTTP(t, h, http.MethodPost, "/r66_ms1/_pit?keep_alive=1m", "", http.StatusOK)
	pitID, _ := pitResp["id"].(string)

	msearchBody := strings.Join([]string{
		`{"indices":["r66_ms1","r66_ms2"],"routing":1,"search_type":"count","rest_total_hits_as_int":true,"filter_path":"hits.total,status"}`,
		`{"query":{"match_all":{}}}`,
		`{"index":"r66_ms1","routing":[1,2],"typed_keys":true,"terminate_after":5,"ignore_unavailable":false}`,
		`{"query":{"match":{"title":"fox"}},"aggs":{"t":{"terms":{"field":"tag"}}},"suggest":{"s1":{"text":"quik","term":{"field":"title"}}}}`,
		fmt.Sprintf(`{"rest_total_hits_as_int":-1}`+"\n"+`{"pit":{"id":%q,"keep_alive":"1m"},"query":{"match_all":{}}}`, pitID),
		`{"index":"r66_ms1","search_type":"query_then_fetch"}`,
		`{"knn":{"field":"vec","query_vector":[1.0,0.0],"k":1,"num_candidates":2}}`,
		`{"index":"r66_missing"}`,
		`{"query":{"match_all":{}}}`,
		`{"index":"r66_ms_closed"}`,
		`{"query":{"match_all":{}}}`,
		`{"index":"r66_ms1","terminate_after":0}`,
		`{"query":{"match_all":{}}}`,
		`{"index":"r66_ms1"}`,
		`{"rank":{"rrf":{"rank_window_size":2}},"size":10}`,
		`{"index":"r66_ms1"}`,
		`{bad json`,
		"",
	}, "\n")
	msResp := mustR66CovHTTP(t, h, http.MethodPost, "/_msearch", msearchBody, http.StatusOK)
	resps, _ := msResp["responses"].([]any)
	if len(resps) != 9 {
		t.Fatalf("expected 9 msearch responses, got %d (%v)", len(resps), msResp)
	}
	// Odd-line msearch validation failure
	mustR66CovHTTP(t, h, http.MethodPost, "/_msearch", `{"index":"r66_ms1"}`+"\n", http.StatusBadRequest)

	// 3. handleScroll & executeStatefulScrollR61CRUD
	sInit := mustR66CovHTTP(t, h, http.MethodPost, "/r66_ms1/_search?scroll=1m&size=1", `{"query":{"match_all":{}},"sort":["_doc"]}`, http.StatusOK)
	scrollID, _ := sInit["_scroll_id"].(string)
	if scrollID == "" {
		t.Fatalf("expected _scroll_id in %v", sInit)
	}
	// Next page + EOF page + rest_total_hits_as_int
	p2 := mustR66CovHTTP(t, h, http.MethodPost, "/_search/scroll?rest_total_hits_as_int=true", fmt.Sprintf(`{"scroll":"1m","scroll_id":%q}`, scrollID), http.StatusOK)
	p2ID, _ := p2["_scroll_id"].(string)
	_ = mustR66CovHTTP(t, h, http.MethodPost, "/_search/scroll?rest_total_hits_as_int=true", fmt.Sprintf(`{"scroll":"1m","scroll_id":%q}`, p2ID), http.StatusOK)
	// Exceed max_keep_alive
	srv.mu.Lock()
	srv.clusterTransientSettings["search.max_keep_alive"] = "1m"
	srv.mu.Unlock()
	mustR66CovHTTP(t, h, http.MethodPost, "/_search/scroll", fmt.Sprintf(`{"scroll":"10m","scroll_id":%q}`, scrollID), http.StatusBadRequest)
	// Bad scroll bodies & DELETE scroll variants
	mustR66CovHTTP(t, h, http.MethodPost, "/_search/scroll", `["bad"]`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_search/scroll", `{"scroll_id":123}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_search/scroll", `{"scroll":"bad_ttl","scroll_id":"x"}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_search/scroll", `{}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_search/scroll", `{"scroll_id":[123]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_search/scroll", `{"scroll_id":123}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_search/scroll", `{"scroll_id":"nonexistent_scroll"}`, http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_search/scroll", fmt.Sprintf(`[%q]`, scrollID), http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_search/scroll/_all", "", http.StatusOK)
}

func TestRound66CovServer_IndicesMappingsTemplatesFieldCapsAndAdmin(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.5")

	// 1. handleCreateIndex error & mode branches
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_logsdb", `{"settings":{"index":{"mode":"logsdb"}},"mappings":{"properties":{"@timestamp":{"type":"date"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_bad_pipe", `{"settings":{"index.default_pipeline":"no_such_pipe"}}`, http.StatusOK) // only checks if s.pipelines non-empty
	mustR66CovHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r66_real_pipe", `{"processors":[{"set":{"field":"x","value":1}}]}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_bad_def_p", `{"settings":{"index.default_pipeline":"missing_pipe"}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_bad_fin_p", `{"settings":{"index.final_pipeline":"missing_pipe"}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_bad_ts_rt", `{
		"settings":{"index":{"mode":"time_series","routing_path":["host"]}},
		"mappings":{"_routing":{"required":true},"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true}}}
	}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_bad_ts_src", `{
		"settings":{"index":{"mode":"time_series","routing_path":["host"]}},
		"mappings":{"_source":{"enabled":false},"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true}}}
	}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_bad_ts_al", `{
		"settings":{"index":{"mode":"time_series","routing_path":["host"]}},
		"aliases":{"ts_al":{"routing":"1"}},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true}}}
	}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_al_coll", `{"aliases":{"r66_logsdb":{}}}`, http.StatusBadRequest)

	// 2. Component templates + mappings + field_caps + synonyms + MGet
	mustR66CovHTTP(t, h, http.MethodPut, "/_component_template/r66_comp1", `{"template":{"mappings":{"properties":{"msg":{"type":"text"}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_component_template/r66_comp1?create=true", `{}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodHead, "/_component_template/r66_comp1", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodHead, "/_component_template/r66_comp*", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodHead, "/_component_template/missing_comp", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodGet, "/_component_template/r66_comp*", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_component_template/missing_comp", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_component_template/r66_comp1", "", http.StatusOK)

	// Rich index for _field_caps, _mapping/field, _cluster/stats, _analyze, synonyms
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_rich", `{
		"settings":{
			"analysis":{
				"filter":{"syn_f":{"type":"synonym","synonyms":["ny, new york","big apple => ny"]}},
				"analyzer":{"syn_an":{"type":"custom","tokenizer":"standard","filter":["lowercase","syn_f"]}}
			}
		},
		"mappings":{
			"runtime":{
				"comp_rt":{"type":"composite","script":{"source":"emit('sub_k','k'); emit('sub_d',1.5);"},"fields":{"sub_k":{"type":"keyword"},"sub_d":{"type":"double"}}},
				"calc_rt":{"type":"long","script":{"source":"emit(1L);"}}
			},
			"properties":{
				"title":{"type":"text","analyzer":"syn_an","fields":{"kw":{"type":"keyword"}}},
				"sayt":{"type":"search_as_you_type"},
				"dv":{"type":"dense_vector","dims":2,"index":true,"similarity":"cosine"},
				"sv":{"type":"sparse_vector"},
				"obj":{"type":"object","properties":{"inner":{"type":"keyword"}}},
				"nobj":{"type":"nested","properties":{"nk":{"type":"keyword"}}},
				"al":{"type":"alias","path":"title"},
				"bin":{"type":"binary"},
				"no_idx":{"type":"keyword","index":false},
				"disabled_obj":{"type":"object","enabled":false},
				"createdAt":{"type":"date"}
			}
		}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_rich/_doc/1?refresh=true", `{"title":"new york city","sayt":"hello","dv":[1.0,0.0],"sv":{"a":1.0},"obj":{"inner":"v"},"nobj":[{"nk":"v"}],"createdAt":"2026-01-01T00:00:00Z"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_no_src", `{"mappings":{"_source":{"enabled":false},"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_no_src/_doc/1?refresh=true", `{"k":"v"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_mget_rt", `{"mappings":{"_routing":{"required":true},"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_mget_rt/_doc/1?routing=r1&refresh=true", `{"k":"v"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPut, "/r66_mget_closed", `{}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_mget_closed/_close", "", http.StatusOK)

	// Synonym expansion search
	synSearch := mustR66CovHTTP(t, h, http.MethodPost, "/r66_rich/_search", `{"query":{"bool":{"must":[{"match":{"title":"big apple"}},{"match_phrase":{"title":{"query":"ny"}}}]}}}`, http.StatusOK)
	if synSearch["hits"] == nil {
		t.Fatalf("expected hits in synonym search: %v", synSearch)
	}

	// _field_caps & _mapping/field & _mapping
	fcResp := mustR66CovHTTP(t, h, http.MethodPost, "/r66_rich/_field_caps?fields=*&include_unmapped=true", `{"runtime_mappings":{"req_comp":{"type":"composite","fields":{"c":{"type":"long"}}}}}`, http.StatusOK)
	if fcResp["fields"] == nil {
		t.Fatalf("expected fields in _field_caps: %v", fcResp)
	}
	mustR66CovHTTP(t, h, http.MethodGet, "/r66_rich/_mapping/field/_id,title,sayt*,al,createdAt?include_defaults=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodHead, "/r66_rich/_mapping/field/title", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_mapping?expand_wildcards=none", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/r66_nomatch_*/_mapping?expand_wildcards=none&allow_no_indices=false", "", http.StatusNotFound)
	// ES7 typed mappings + field mappings
	_, h7 := newR66CovServer(t, "7.10.2")
	mustR66CovHTTP(t, h7, http.MethodPut, "/r66_v7_m?include_type_name=true", `{"mappings":{"mytype":{"properties":{"k":{"type":"keyword"}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodGet, "/r66_v7_m/_mapping/mytype?include_type_name=true", "", http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodGet, "/r66_v7_m/_mapping/missing_type", "", http.StatusNotFound)
	mustR66CovHTTP(t, h7, http.MethodGet, "/r66_v7_m/_mapping/mytype/field/k?local=true", "", http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodGet, "/r66_v7_m/_mapping/missing_type/field/k", "", http.StatusNotFound)
	mustR66CovHTTP(t, h7, http.MethodPut, "/r66_v7_m/_mapping/other_type?include_type_name=true", `{"properties":{"k2":{"type":"keyword"}}}`, http.StatusBadRequest)

	// _mget error & edge item branches
	mgetResp := mustR66CovHTTP(t, h, http.MethodPost, "/_mget?refresh=true&force_synthetic_source=false", `{
		"docs":[
			{"_index":"r66_rich","_id":"1","routing":"x"},
			{"_index":"r66_missing","_id":"1"},
			{"_index":"r66_mget_closed","_id":"1"},
			{"_index":"r66_mget_rt","_id":"1"},
			{"_index":"r66_mget_rt","_id":"1","routing":"r1","version":999},
			{"_index":"r66_no_src","_id":"1","_source":true},
			{"_index":"r66_rich","_id":"missing_doc"}
		]
	}`, http.StatusOK)
	if docs, ok := mgetResp["docs"].([]any); !ok || len(docs) != 7 {
		t.Fatalf("expected 7 mget docs, got %v", mgetResp)
	}
	mustR66CovHTTP(t, h, http.MethodPost, "/_mget", `{"docs":[{"_id":"1"}]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_mget", `{"docs":[{"_index":"r66_rich"}]}`, http.StatusBadRequest)

	// _alias resolution & expand_wildcards
	mustR66CovHTTP(t, h, http.MethodHead, "/r66_nomatch_*/_alias?expand_wildcards=none&allow_no_indices=false", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodGet, "/r66_nomatch_*/_alias?expand_wildcards=none&allow_no_indices=false", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodGet, "/_alias?expand_wildcards=bad", "", http.StatusBadRequest)

	// _cluster/health, _cat/indices, _analyze, _cluster/reroute, _cluster/stats
	mustR66CovHTTP(t, h, http.MethodGet, "/_cluster/health?level=shards&wait_for_status=green&wait_for_events=immediate&wait_for_no_relocating_shards=true&timeout=5s&wait_for_active_shards=1&wait_for_nodes=>=1", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodHead, "/_cluster/health/r66_rich?level=indices", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_cluster/health?bad_param=1", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/_cluster/health?level=bad", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/_cluster/health?wait_for_status=blue", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/_cluster/health?wait_for_events=bad", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/_cluster/health?wait_for_active_shards=-1", "", http.StatusBadRequest)

	mustR66CovHTTP(t, h, http.MethodGet, "/_cat/indices?format=json&health=green&expand_wildcards=open,closed", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_cat/indices?health=bad", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/_cat/indices/r66_nomatch_*?expand_wildcards=none&allow_no_indices=false", "", http.StatusNotFound)

	mustR66CovHTTP(t, h, http.MethodPost, "/r66_rich/_analyze?attributes=term,type", `{"field":"title","text":["Hello World"],"explain":true}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_analyze?text=Hello&filter=lowercase&char_filter=html_strip&attributes=term", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_analyze", `{"field":"title","text":"hi"}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/r66_rich/_analyze", `{"field":"title","analyzer":"standard","text":"hi"}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_analyze", `{"unknown_key":1,"text":"hi"}`, http.StatusBadRequest)

	mustR66CovHTTP(t, h, http.MethodPost, "/_cluster/reroute?explain=true&metric=_all", `{"commands":[{"cancel":{"index":"r66_rich","shard":0,"node":"n1"}},{"move":{"index":"r66_rich","shard":0,"from_node":"n1","to_node":"n2"}}]}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_cluster/reroute", `{"commands":[{"cancel":{"index":"r66_rich","shard":0,"node":"n1"}}]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/_cluster/reroute?metric=bad_metric", `{}`, http.StatusBadRequest)

	csResp := mustR66CovHTTP(t, h, http.MethodGet, "/_cluster/stats?human=true", "", http.StatusOK)
	if csResp["indices"] == nil {
		t.Fatalf("expected indices stats in /_cluster/stats, got %v", csResp)
	}
	_ = srv
}

func TestRound66CovServer_FieldCapsSynonymsMappingsPITTemplatesAndCat(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.5")

	// 1. Setup rich index, TSDB index, dynamic index, closed index, alias, synonyms
	mustR66CovHTTP(t, h, http.MethodPut, "/fc_rich", `{
		"mappings": {
			"runtime": {
				"comp_rt": {"type": "composite", "script": "emit('x', 1)", "fields": {"k": {"type": "keyword"}, "v": {"type": "long"}}}
			},
			"properties": {
				"title": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
				"sayt": {"type": "search_as_you_type"},
				"mot": {"type": "match_only_text"},
				"price": {"type": "double"},
				"alias_title": {"type": "alias", "path": "title"},
				"obj_parent": {"type": "object", "properties": {"x": {"type": "integer"}}},
				"nested_arr": {"type": "nested", "properties": {"nk": {"type": "keyword"}}}
			}
		}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/fc_rich/_doc/1?refresh=true", `{"title":"fast database search","mot":"hello","price":12.5,"dyn_txt":"hello world","dyn_num":42,"dyn_flag":true}`, http.StatusCreated)

	mustR66CovHTTP(t, h, http.MethodPut, "/fc_tsdb", `{
		"settings": {"index": {"mode": "time_series", "routing_path": ["host"]}},
		"mappings": {"properties": {"@timestamp": {"type": "date"}, "host": {"type": "keyword", "time_series_dimension": true}, "cpu": {"type": "double", "time_series_metric": "gauge"}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/fc_closed", `{"mappings":{"properties":{"a":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/fc_closed/_close", "", http.StatusOK)

	// _field_caps valid + TSDB + runtime_mappings + closed index error
	mustR66CovHTTP(t, h, http.MethodHead, "/fc_rich/_field_caps", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/fc_rich,fc_tsdb/_field_caps?include_empty_fields=false", `{
		"fields": ["*"],
		"runtime_mappings": {"rt_double": {"type": "double", "script": {"source": "emit(1.0)"}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/fc_closed/_field_caps", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/fc_closed/_field_caps?ignore_unavailable=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/fc_rich/_field_caps", `{"runtime_mappings":{"bad_lang":{"type":"keyword","script":{"lang":"mustache","source":"x"}}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/fc_rich/_field_caps", `{"runtime_mappings":{"bad_syn":{"type":"keyword","script":{"source":"return ("}}}}`, http.StatusBadRequest)

	// 2. Synonyms CRUD + expandSearchBodySynonymsRound61 via match, match_phrase, bool
	mustR66CovHTTP(t, h, http.MethodPut, "/_synonyms/cov_syns", `{
		"synonyms_set": [
			{"id": "s1", "synonyms": "db, database, doris"},
			{"id": "s2", "synonyms": "fast => quick, rapid"}
		]
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/syn_idx", `{
		"settings": {"analysis": {"filter": {"my_syn": {"type": "synonym", "synonyms_set": "cov_syns"}}, "analyzer": {"syn_an": {"type": "custom", "tokenizer": "standard", "filter": ["lowercase", "my_syn"]}}}},
		"mappings": {"properties": {"body": {"type": "text", "analyzer": "syn_an"}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/syn_idx/_doc/1?refresh=true", `{"body":"quick doris engine"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/syn_idx/_search", `{
		"query": {"bool": {"should": [{"match": {"body": "fast database"}}, {"match_phrase": {"body": "fast database"}}]}}
	}`, http.StatusOK)

	// 3. Mappings (PUT validation on TSDB + GET _mappings/{type} 404/200/HEAD + _mapping/{type}/field/{fields})
	mustR66CovHTTP(t, h, http.MethodPut, "/fc_tsdb/_mapping", `{"_routing":{"required":true},"properties":{"cpu":{"type":"double"}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/fc_tsdb/_mapping", `{"runtime":{"host":{"type":"keyword"}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/fc_rich/_mapping/field/title,price", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_mapping/_doc/field/title", "", http.StatusBadRequest)
	_, h7 := newR66CovServer(t, "7.10.2")
	mustR66CovHTTP(t, h7, http.MethodPut, "/fc_v7?include_type_name=true", `{"mappings":{"_doc":{"properties":{"title":{"type":"text"}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodGet, "/_mapping/_doc/field/title", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/fc_rich/_mapping/missing_type", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h7, http.MethodGet, "/fc_v7/_mapping/missing_type?include_type_name=true", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodGet, "/fc_nomatch_*/_mapping?expand_wildcards=none&allow_no_indices=false", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodGet, "/_mapping?expand_wildcards=bad", "", http.StatusBadRequest)

	// 4. PIT lifecycle & DELETE /_pit error branches
	p1 := mustR66CovHTTP(t, h, http.MethodPost, "/fc_rich/_pit?keep_alive=1m", `{"index_filter":{"term":{"title":"fast"}}}`, http.StatusOK)
	p2 := mustR66CovHTTP(t, h, http.MethodPost, "/fc_rich/_pit?keep_alive=1m", "", http.StatusOK)
	pitID1, _ := p1["id"].(string)
	pitID2, _ := p2["id"].(string)
	mustR66CovHTTP(t, h, http.MethodPost, "/fc_rich/_pit?keep_alive=1m", `{"bad_key":1}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_pit", `{}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_pit", `{"id":123}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_pit", `{"id":[]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_pit", `{"id":["`+pitID1+`"]}`, http.StatusOK)
	if pitID2 != "" {
		mustR66CovHTTP(t, h, http.MethodDelete, "/_pit", `{"id":"_all"}`, http.StatusOK)
	}

	// 5. Templates (composable + legacy): create=true, component missing, wildcard GET/DELETE, include_type_name
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/tpl_cov_missing_comp", `{"index_patterns":["x-*"],"composed_of":["missing_comp"]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/tpl_cov_1", `{"index_patterns":["tpl1-*"],"template":{"mappings":{"properties":{"a":{"type":"keyword"}}},"lifecycle":{"data_retention":"7d"}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/tpl_cov_1?create=true", `{"index_patterns":["tpl1-*"]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/_index_template/tpl_cov_*?flat_settings=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_index_template/no_such_tpl", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_index_template/tpl_cov_*", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_index_template/no_such_tpl", "", http.StatusNotFound)

	mustR66CovHTTP(t, h7, http.MethodPut, "/_template/leg_cov_1?template=leg-*", `{"mappings":{"mytype":{"properties":{"a":{"type":"keyword"}}}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h7, http.MethodPut, "/_template/leg_cov_1?include_type_name=true", `{"index_patterns":["leg-*"],"mappings":{"mytype":{"properties":{"a":{"type":"keyword"}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodPut, "/_template/leg_cov_1?create=true", `{"index_patterns":["leg-*"]}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h7, http.MethodGet, "/_template/leg_cov_*?flat_settings=true", "", http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodDelete, "/_template/leg_cov_*", "", http.StatusOK)

	// 6. _cat endpoints + _mpercolate + _search expand_wildcards=none / scroll size=0 + _explain script_score min_score
	for _, catPath := range []string{"/_cat/master?format=json", "/_cat/nodeattrs?format=json", "/_cat/fielddata?format=json", "/_cat/recovery?format=json", "/_cat/tasks?format=json", "/_cat/plugins?format=json"} {
		mustR66CovHTTP(t, h, http.MethodGet, catPath, "", http.StatusOK)
	}
	mustR66CovHTTP(t, h, http.MethodGet, "/fc_nomatch_*/_search?expand_wildcards=none&allow_no_indices=false", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPost, "/fc_rich/_search?scroll=1m", `{"size":0,"query":{"match_all":{}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/fc_rich/_doc/1/_explain?_source=false", `{"query":{"script_score":{"query":{"match_all":{}},"script":{"source":"1.0"},"min_score":10.0}}}`, http.StatusOK)
	_, _, _, _ = doR66CovHTTP(t, h, http.MethodPost, "/fc_rich/_mpercolate", "{\"index\":\"fc_rich\"}\n{\"doc\":{\"title\":\"fast\"}}\n", map[string]string{"Content-Type": "application/x-ndjson"})
	mustR66CovHTTP(t, h, http.MethodPost, "/fc_rich/_clone", `{}`, http.StatusBadRequest)
}

func TestRound66CovServer_TSDBWritesAliasesTemplatesAutoCreateAndMappings(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.0")

	// 1. TSDB index creation & validation + doc PUT / GET / HEAD / BULK conflicts & routing errors
	mustR66CovHTTP(t, h, http.MethodPut, "/ts_metrics_cov", `{
		"settings": {"index.mode": "time_series", "index.routing_path": ["host", "env"]},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"host": {"type": "keyword", "time_series_dimension": true},
				"env": {"type": "keyword", "time_series_dimension": true},
				"cpu": {"type": "double", "time_series_metric": "gauge"},
				"ok": {"type": "boolean"},
				"sayt": {"type": "search_as_you_type"}
			}
		}
	}`, http.StatusOK)
	tsPost := mustR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_cov/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","env":"prod","cpu":0.5,"ok":true,"sayt":"cpu load"}`, http.StatusCreated)
	tsID1, _ := tsPost["_id"].(string)
	if tsID1 == "" {
		t.Fatalf("expected derived _id from TSDB post, got %v", tsPost)
	}
	// PUT invalid TSDB id -> 400; PUT create on existing derived TSDB id -> 409 conflict
	mustR66CovHTTP(t, h, http.MethodPut, "/ts_metrics_cov/_doc/ts1?refresh=true", `{"@timestamp":"2026-01-01T00:00:01Z","host":"h2","env":"prod","cpu":0.8}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/ts_metrics_cov/_create/"+tsID1, `{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","env":"prod","cpu":0.9}`, http.StatusConflict)
	// GET & HEAD invalid version / realtime params on TSDB
	mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_cov/_doc/"+tsID1+"?version=bad", "", http.StatusBadRequest)
	stHead, _, _, _ := doR66CovHTTP(t, h, http.MethodHead, "/ts_metrics_cov/_doc/"+tsID1+"?version=bad", "", nil)
	if stHead != http.StatusBadRequest {
		t.Fatalf("expected 400 HEAD with bad version, got %d", stHead)
	}
	mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_cov/_doc/"+tsID1+"?realtime=true", "", http.StatusOK)

	// TSDB bulk ops: create conflict, valid create, auto id success
	bulkBody := strings.Join([]string{
		`{"create":{"_index":"ts_metrics_cov","_id":"` + tsID1 + `"}}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","env":"prod","cpu":0.1}`,
		`{"index":{"_index":"ts_metrics_cov"}}`,
		`{"@timestamp":"2026-01-01T00:00:02Z","host":"h3","env":"stage","cpu":0.2}`,
		"",
	}, "\n")
	bulkResp := mustR66CovHTTP(t, h, http.MethodPost, "/_bulk?refresh=true", bulkBody, http.StatusOK)
	if errorsFlag, _ := bulkResp["errors"].(bool); !errorsFlag {
		t.Fatalf("expected bulk errors=true for duplicate TSDB create, got %v", bulkResp)
	}

	// _field_caps on TSDB + boolean + double + search_as_you_type + closed/runtime fields
	fcResp := mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_cov/_field_caps?fields=*", "", http.StatusOK)
	if _, ok := fcResp["fields"]; !ok {
		t.Fatalf("missing fields in _field_caps: %v", fcResp)
	}

	// 2. PUT /_mapping validation errors: runtime cycle (default mode), TSDB shadowing/routing_path
	_, hDefault := newR66CovServer(t, "")
	mustR66CovHTTP(t, hDefault, http.MethodPut, "/rt_cycle_idx", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, hDefault, http.MethodPut, "/rt_cycle_idx/_mapping", `{"runtime":{"rt_cycle_a":{"type":"keyword","script":{"source":"emit(doc['rt_cycle_b'].value)"}},"rt_cycle_b":{"type":"keyword","script":{"source":"emit(doc['rt_cycle_a'].value)"}}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/ts_metrics_cov/_mapping", `{"runtime":{"host":{"type":"keyword","script":{"source":"emit('x')"}}}}`, http.StatusBadRequest)

	// GET _mapping with expand_wildcards=none & invalid expand_wildcards
	mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_*/_mapping?expand_wildcards=invalid", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_*/_mapping?expand_wildcards=none&allow_no_indices=false", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_*/_mapping?expand_wildcards=none&ignore_unavailable=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_cov,ts_*/_mapping?expand_wildcards=none&ignore_unavailable=true", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_mapping?expand_wildcards=none", "", http.StatusOK)

	// 3. _component_template GET/HEAD/DELETE & _alias full metadata (filter, routing, is_write_index)
	mustR66CovHTTP(t, h, http.MethodPut, "/_component_template/comp_cov_1", `{"template":{"mappings":{"properties":{"k":{"type":"keyword"}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_component_template/comp_cov_*", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_component_template/missing_comp_cov", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_component_template/comp_cov_1", "", http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPut, "/alias_cov_src", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"alias_cov_src","alias":"alias_cov_full","filter":{"term":{"tag":"keep"}},"index_routing":"r1","search_routing":"r1","is_write_index":true}}]}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_alias/alias_cov_full", "", http.StatusOK)

	// 4. auto_create_index restrictions & reindex external version conflicts / data stream / write alias
	mustR66CovHTTP(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"action.auto_create_index":"-blocked*,+allowed*"}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/blocked_idx/_doc/1", `{"a":1}`, http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPut, "/unlisted_idx/_doc/1", `{"a":1}`, http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPut, "/_cluster/settings", `{"transient":{"action.auto_create_index":null}}`, http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodPut, "/re_src", `{"mappings":{"properties":{"v":{"type":"integer"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/re_dst", `{"mappings":{"properties":{"v":{"type":"integer"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/re_src/_doc/1?version=2&version_type=external&refresh=true", `{"v":10}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPut, "/re_dst/_doc/1?version=5&version_type=external&refresh=true", `{"v":99}`, http.StatusCreated)
	// External version conflict during reindex -> 409 conflict; also exercise slice id/max
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex", `{"conflicts":"proceed","source":{"index":"re_src","slice":{"id":0,"max":2}},"dest":{"index":"re_dst","version_type":"external"}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex", `{"conflicts":"abort","source":{"index":"re_src"},"dest":{"index":"re_dst","version_type":"external"}}`, http.StatusConflict)
	// External version proceed on conflict -> 200
	reOK := mustR66CovHTTP(t, h, http.MethodPost, "/_reindex", `{"conflicts":"proceed","source":{"index":"re_src"},"dest":{"index":"re_dst","version_type":"external"}}`, http.StatusOK)
	if fmt.Sprintf("%v", reOK["version_conflicts"]) != "1" {
		t.Fatalf("expected 1 version_conflict in reindex proceed, got %v", reOK)
	}
	// External conflict against tombstone in dest
	mustR66CovHTTP(t, h, http.MethodDelete, "/re_dst/_doc/2?version=5&version_type=external&refresh=true", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodPut, "/re_src/_doc/2?version=3&version_type=external&refresh=true", `{"v":20}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex", `{"conflicts":"abort","source":{"index":"re_src","query":{"term":{"_id":"2"}}},"dest":{"index":"re_dst","version_type":"external"}}`, http.StatusConflict)
	// Auto-create dest on reindex with data stream requires op_type=create
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/ds_re_tpl", `{"index_patterns":["ds-re-*"],"data_stream":{}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_data_stream/ds-re-1", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_reindex", `{"source":{"index":"re_src"},"dest":{"index":"ds-re-1"}}`, http.StatusBadRequest)

	// 5. ES7 vs ES8 ?size= vs ?max_docs= on update_by_query, runtime query script on zero hits, DELETE /_all?expand_wildcards=none
	_, h7 := newR66CovServer(t, "7.10.2")
	mustR66CovHTTP(t, h7, http.MethodPut, "/ubq_v7", `{"mappings":{"properties":{"v":{"type":"integer"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodPost, "/ubq_v7/_update_by_query?size=5&max_docs=bad", `{"query":{"match_all":{}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h7, http.MethodPost, "/ubq_v7/_update_by_query?size=5", `{"query":{"match_all":{}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/re_src/_update_by_query?size=5", `{"query":{"match_all":{}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/re_src/_update_by_query", `{"runtime_mappings":{"dyn":{"type":"keyword","script":{"source":"emit('x')"}}},"query":{"term":{"dyn":"nomatch"}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/re_src/_delete_by_query", `{"runtime_mappings":{"dyn":{"type":"keyword","script":{"source":"emit('x')"}}},"query":{"term":{"dyn":"nomatch"}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodDelete, "/_all?expand_wildcards=none&allow_no_indices=false", "", http.StatusNotFound)

	// 6. TSDB dynamic=runtime doc indexing in ES7 & ES8 mode (exercises inferTSDBRuntimeDynamicLeafType & validateTSDBDocDynamicRoutingPaths)
	mustR66CovHTTP(t, h, http.MethodPut, "/ts_dyn_rt8", `{
		"settings":{"index.mode":"time_series","index.routing_path":["host"]},
		"mappings":{
			"dynamic":"runtime",
			"properties":{
				"@timestamp":{"type":"date"},
				"host":{"type":"keyword","time_series_dimension":true},
				"m":{"type":"double","time_series_metric":"gauge"}
			}
		}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_dyn_rt8/_doc?refresh=true", `{
		"@timestamp":"2026-01-01T00:00:00Z","host":"h1","m":1.0,
		"d_bool":true,"d_int":42,"d_flt":3.14,"d_dt":"2026-01-02T00:00:00Z","d_kw":"abc",
		"nested_obj":[{"sub":"v"}]
	}`, http.StatusCreated)
	mustR66CovHTTP(t, h7, http.MethodPut, "/ts_dyn_rt7", `{
		"settings":{"index.mode":"time_series","index.routing_path":["host"]},
		"mappings":{
			"dynamic":"runtime",
			"properties":{
				"@timestamp":{"type":"date"},
				"host":{"type":"keyword","time_series_dimension":true},
				"m":{"type":"double","time_series_metric":"gauge"}
			}
		}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodPost, "/ts_dyn_rt7/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","m":1.0,"d_flt":3.14}`, http.StatusCreated)

	// 7. _source GET/HEAD + _shard_stores + _refresh/_flush/_forcemerge + _cluster/state + _rollover dry_run
	mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_cov/_source/"+tsID1, "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_cov/_source/"+tsID1+"?version=bad", "", http.StatusBadRequest)
	stSrcHead, _, _, _ := doR66CovHTTP(t, h, http.MethodHead, "/ts_metrics_cov/_source/"+tsID1+"?version=bad", "", nil)
	if stSrcHead != http.StatusBadRequest {
		t.Fatalf("expected 400 HEAD _source bad version, got %d", stSrcHead)
	}
	mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_cov/_source/missing_ts_id", "", http.StatusNotFound)

	mustR66CovHTTP(t, h, http.MethodGet, "/_shard_stores?status=green,yellow,red", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/ts_metrics_cov/_shard_stores", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_cov/_refresh", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_cov/_flush", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_cov/_forcemerge", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/missing_rf_idx/_refresh", "", http.StatusNotFound)
	mustR66CovHTTP(t, h, http.MethodGet, "/_refresh", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_cov/_forcemerge?only_expunge_deletes=true&max_num_segments=2", "", http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_metrics_cov/_forcemerge?wait_for_completion=false", "", http.StatusOK)

	mustR66CovHTTP(t, h, http.MethodGet, "/_cluster/state/metadata,routing_table/ts_metrics_*?expand_wildcards=open,closed", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodGet, "/_cluster/state/metadata/ts_metrics_*?expand_wildcards=none&allow_no_indices=false", "", http.StatusNotFound)

	mustR66CovHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"alias_cov_src","alias":"roll_cov_alias","is_write_index":true}}]}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/roll_cov_alias/_rollover/roll_cov_dst?dry_run=true", `{"conditions":{"max_age":"1d","max_docs":10,"max_size":"1gb"}}`, http.StatusOK)
	_ = srv
}

func TestRound66CovServer_TSDBWritesConflictsBulkMappingsAndByQueryScripts(t *testing.T) {
	_, h := newR66CovServer(t, "8.15.0")
	_, h7 := newR66CovServer(t, "7.10.2")

	// 1. TSDB dynamic=runtime routing_path dynamic leaf rejection across boolean/int/float/date/keyword in ES8 & ES7 (inferTSDBRuntimeDynamicLeafType)
	mustR66CovHTTP(t, h, http.MethodPut, "/ts_dyn_leaf8", `{
		"settings":{"index.mode":"time_series","index.routing_path":["dims.*"]},
		"mappings":{"dynamic":"runtime","properties":{"@timestamp":{"type":"date"},"dims":{"type":"object","properties":{"fixed":{"type":"keyword","time_series_dimension":true}}},"m":{"type":"double","time_series_metric":"gauge"}}}
	}`, http.StatusOK)
	mustR66CovHTTP(t, h7, http.MethodPut, "/ts_dyn_leaf7", `{
		"settings":{"index.mode":"time_series","index.routing_path":["dims.*"]},
		"mappings":{"dynamic":"runtime","properties":{"@timestamp":{"type":"date"},"dims":{"type":"object","properties":{"fixed":{"type":"keyword","time_series_dimension":true}}},"m":{"type":"double","time_series_metric":"gauge"}}}
	}`, http.StatusOK)
	for _, docBody := range []string{
		`{"@timestamp":"2026-01-01T00:00:00Z","dims":{"fixed":"a","b":true},"m":1}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","dims":{"fixed":"a","n":42},"m":1}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","dims":{"fixed":"a","f":3.14},"m":1}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","dims":{"fixed":"a","d":2.0},"m":1}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","dims":{"fixed":"a","dt":"2026-01-02T00:00:00Z"},"m":1}`,
		`{"@timestamp":"2026-01-01T00:00:00Z","dims":{"fixed":"a","kw":"abc"},"m":1}`,
	} {
		mustR66CovHTTP(t, h, http.MethodPost, "/ts_dyn_leaf8/_doc", docBody, http.StatusBadRequest)
		mustR66CovHTTP(t, h7, http.MethodPost, "/ts_dyn_leaf7/_doc", docBody, http.StatusBadRequest)
	}

	// 2. TSDB single doc writes, auto-ID create conflict (409), explicit-ID update existing, and bulk index/create/errors
	mustR66CovHTTP(t, h, http.MethodPut, "/ts_writes_b6", `{
		"settings":{"index.mode":"time_series","index.routing_path":["host"]},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true},"m":{"type":"double","time_series_metric":"gauge"}}}
	}`, http.StatusOK)
	cResp := mustR66CovHTTP(t, h, http.MethodPost, "/ts_writes_b6/_doc?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","m":1.0}`, http.StatusCreated)
	tsID, _ := cResp["_id"].(string)
	// Duplicate auto-ID TSDB create -> 409 version_conflict_engine_exception
	mustR66CovHTTP(t, h, http.MethodPost, "/ts_writes_b6/_doc", `{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","m":1.0}`, http.StatusConflict)
	// Update existing explicit TSDB ID -> 200
	if tsID != "" {
		mustR66CovHTTP(t, h, http.MethodPut, "/ts_writes_b6/_doc/"+tsID+"?refresh=true", `{"@timestamp":"2026-01-01T00:00:00Z","host":"h1","m":2.0}`, http.StatusOK)
	}

	// Bulk create/index/conflict/missing-tsdb-timestamp on TSDB index
	bulkBody := strings.Join([]string{
		`{"create":{"_index":"ts_writes_b6"}}`,
		`{"@timestamp":"2026-01-02T00:00:00Z","host":"h2","m":5.0}`,
		`{"create":{"_index":"ts_writes_b6"}}`,
		`{"@timestamp":"2026-01-02T00:00:00Z","host":"h2","m":5.0}`,
		`{"create":{"_index":"ts_writes_b6"}}`,
		`{"host":"h_notimestamp","m":5.0}`,
		`{"index":{"_index":"ts_writes_b6","_id":"bad_explicit"}}`,
		`{"@timestamp":"2026-01-03T00:00:00Z","host":"h3","m":6.0}`,
		``,
	}, "\n")
	mustR66CovHTTP(t, h, http.MethodPost, "/_bulk?refresh=true", bulkBody, http.StatusOK)

	// 3. handlePutMappingR61CRUD errors: TSDB runtime shadowing routing_path, TSDB _routing forbidden, self alias loop, synthetic flattened
	mustR66CovHTTP(t, h, http.MethodPut, "/ts_writes_b6/_mapping", `{"runtime":{"host":{"type":"keyword"}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPut, "/ts_writes_b6/_mapping", `{"_routing":{"required":true}}`, http.StatusBadRequest)

	mustR66CovHTTP(t, h, http.MethodPut, "/map_err_b6", `{"mappings":{"properties":{"f":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/map_err_b6/_mapping", `{"properties":{"bad_al":{"type":"alias","path":"bad_al"}}}`, http.StatusBadRequest)

	// 4. _update_by_query and _delete_by_query with runtime script filter & script error
	mustR66CovHTTP(t, h, http.MethodPut, "/byq_b6", `{"mappings":{"properties":{"v":{"type":"long"},"tag":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/byq_b6/_doc/1?refresh=true", `{"v":10,"tag":"keep"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/byq_b6/_doc/2?refresh=true", `{"v":2,"tag":"drop"}`, http.StatusCreated)
	mustR66CovHTTP(t, h, http.MethodPost, "/byq_b6/_update_by_query?refresh=true", `{"query":{"script":{"script":"doc['v'].value > 5"}},"script":{"source":"ctx._source.v += 1"}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/byq_b6/_update_by_query", `{"query":{"script":{"script":"doc['v'].value / 0 > 0"}}}`, http.StatusBadRequest)
	mustR66CovHTTP(t, h, http.MethodPost, "/byq_b6/_delete_by_query?refresh=true", `{"query":{"script":{"script":"doc['v'].value < 5"}}}`, http.StatusOK)
}
