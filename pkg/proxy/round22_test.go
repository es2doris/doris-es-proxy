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
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/painless"
)

func r22Req(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var bodyStr string
	if body != nil {
		if s, ok := body.(string); ok {
			bodyStr = s
		} else {
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal body failed: %v", err)
			}
			bodyStr = string(b)
		}
	}
	req := httptest.NewRequest(method, path, strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func r22JSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal response failed (status=%d, body=%s): %v", w.Code, w.Body.String(), err)
	}
	return m
}

func TestRound22QueryDSLKeywordMatchSimpleQueryStringAndMultiMatch(t *testing.T) {
	srv, _ := newTestServer()
	r22Req(t, srv, http.MethodPut, "/r22_dsl", `{
		"mappings": {
			"properties": {
				"status": {"type": "keyword"},
				"tags":   {"type": "keyword", "multi_valued": true},
				"title":  {"type": "text"},
				"body":   {"type": "text"},
				"age":    {"type": "integer"}
			}
		}
	}`)
	r22Req(t, srv, http.MethodPost, "/r22_dsl/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"status":"ERR","tags":["prod","urgent"],"title":"http://example.com:8080 alpha beta","body":"gamma","age":30}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"status":"err","tags":["prod_eu","urgent_care"],"title":"ERR:100 alpha","body":"beta","age":25}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"status":"OK","tags":["staging"],"title":"gamma delta","body":"alpha beta","age":40}`+"\n")

	// 1. match on exact keyword scalar ("ERR" matches doc 1 only, not lowercase "err" in doc 2)
	wKw := r22Req(t, srv, http.MethodPost, "/r22_dsl/_search", `{
		"query": {"match": {"status": "ERR"}}
	}`)
	hitsKw := r22JSON(t, wKw)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsKw) != 1 || hitsKw[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected only doc 1 for exact keyword match status=ERR, got %v", hitsKw)
	}

	// 2. match on exact keyword array ("prod" matches doc 1 only, not substring "prod_eu" in doc 2)
	wKwArr := r22Req(t, srv, http.MethodPost, "/r22_dsl/_search", `{
		"query": {"match": {"tags": "prod"}}
	}`)
	hitsKwArr := r22JSON(t, wKwArr)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsKwArr) != 1 || hitsKwArr[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected only doc 1 for exact keyword array match tags=prod, got %v", hitsKwArr)
	}

	// 3. Single-token match and match_bool_prefix with operator="and" and minimum_should_match=2 -> 0 hits
	for _, qBody := range []string{
		`{"query":{"match":{"title":{"query":"alpha","operator":"and","minimum_should_match":2}}}}`,
		`{"query":{"match_bool_prefix":{"title":{"query":"alp","operator":"and","minimum_should_match":2}}}}`,
	} {
		wMSM := r22Req(t, srv, http.MethodPost, "/r22_dsl/_search", qBody)
		hitsMSM := r22JSON(t, wMSM)["hits"].(map[string]any)["hits"].([]any)
		if len(hitsMSM) != 0 {
			t.Fatalf("expected 0 hits for single-token minimum_should_match=2 (%s), got %d", qBody, len(hitsMSM))
		}
	}

	// 4. simple_query_string treats colons literally ("ERR:100") and splits unspaced |, ||, &&
	wSQSColon := r22Req(t, srv, http.MethodPost, "/r22_dsl/_search", `{
		"query": {
			"simple_query_string": {
				"fields": ["title"],
				"query": "ERR:100"
			}
		}
	}`)
	hitsSQSColon := r22JSON(t, wSQSColon)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsSQSColon) != 1 || hitsSQSColon[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected doc 2 for simple_query_string 'ERR:100', got %v", hitsSQSColon)
	}

	wSQSOps := r22Req(t, srv, http.MethodPost, "/r22_dsl/_search", `{
		"query": {
			"simple_query_string": {
				"fields": ["title"],
				"query": "alpha&&beta"
			}
		}
	}`)
	hitsSQSOps := r22JSON(t, wSQSOps)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsSQSOps) != 1 || hitsSQSOps[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 for simple_query_string 'alpha&&beta', got %v", hitsSQSOps)
	}

	wSQSPipe := r22Req(t, srv, http.MethodPost, "/r22_dsl/_search", `{
		"query": {
			"simple_query_string": {
				"fields": ["status"],
				"query": "ERR|OK"
			}
		}
	}`)
	hitsSQSPipe := r22JSON(t, wSQSPipe)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsSQSPipe) != 2 {
		t.Fatalf("expected 2 hits (docs 1 and 3) for simple_query_string 'ERR|OK', got %v", hitsSQSPipe)
	}

	// 5. multi_match best_fields with minimum_should_match: 2 requires 2 tokens in the SAME field
	// Doc 1 has "alpha beta" in title; Doc 3 has "alpha beta" in body; Doc 2 has "alpha" in title and "beta" in body (split across fields).
	wMMBest := r22Req(t, srv, http.MethodPost, "/r22_dsl/_search", `{
		"query": {
			"multi_match": {
				"query": "alpha beta",
				"fields": ["title", "body"],
				"type": "best_fields",
				"minimum_should_match": 2
			}
		}
	}`)
	hitsMMBest := r22JSON(t, wMMBest)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsMMBest) != 2 {
		t.Fatalf("expected 2 hits (docs 1 and 3, not doc 2) for best_fields minimum_should_match=2, got %d: %v", len(hitsMMBest), hitsMMBest)
	}

	// 6. multi_match with incompatible numeric field ["age", "title"] and text query "delta"
	wMMIncompat := r22Req(t, srv, http.MethodPost, "/r22_dsl/_search", `{
		"query": {
			"multi_match": {
				"query": "delta",
				"fields": ["age", "title"]
			}
		}
	}`)
	hitsMMIncompat := r22JSON(t, wMMIncompat)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsMMIncompat) != 1 || hitsMMIncompat[0].(map[string]any)["_id"] != "3" {
		t.Fatalf("expected doc 3 for multi_match across [age, title], got %v", hitsMMIncompat)
	}
}

func TestRound22SchemaCopyToKeywordArrayAliasChainsIgnoreAboveAndNestedKeyword(t *testing.T) {
	srv, _ := newTestServer()
	r22Req(t, srv, http.MethodPut, "/r22_schema", `{
		"mappings": {
			"properties": {
				"first_name": {
					"type": "keyword",
					"copy_to": "full_search_alias"
				},
				"last_name": {
					"type": "keyword",
					"copy_to": "full_search"
				},
				"full_search": {
					"type": "text",
					"fields": {
						"keyword": {"type": "keyword"}
					}
				},
				"full_search_alias": {
					"type": "alias",
					"path": "full_search"
				},
				"chained_alias": {
					"type": "alias",
					"path": "full_search_alias"
				},
				"dyn_alias": {
					"type": "alias",
					"path": "unmapped_dyn_field"
				},
				"logs_msg": {
					"type": "match_only_text"
				},
				"long_code": {
					"type": "keyword",
					"ignore_above": 1024
				},
				"items": {
					"type": "nested",
					"properties": {
						"label": {
							"type": "text",
							"fields": {
								"keyword": {
									"type": "keyword",
									"ignore_above": 4,
									"normalizer": "lowercase"
								}
							}
						}
					}
				}
			}
		}
	}`)

	long1050 := strings.Repeat("X", 1050)
	r22Req(t, srv, http.MethodPost, "/r22_schema/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+fmt.Sprintf(`{"first_name":"Alice","last_name":"Smith","unmapped_dyn_field":"dyn_val","logs_msg":"hello world","long_code":%q,"items":[{"label":"MixedCaseLongLabel"}]}`, long1050)+"\n")

	// 1. Chained alias + copy_to via alias + term query on full_search (whose .keyword companion was promoted to ARRAY<STRING> by copy_to)
	for _, fieldName := range []string{"full_search", "full_search.keyword", "full_search_alias", "chained_alias"} {
		w := r22Req(t, srv, http.MethodPost, "/r22_schema/_search", fmt.Sprintf(`{
			"query": {"term": {%q: "Alice"}}
		}`, fieldName))
		if w.Code != http.StatusOK {
			t.Fatalf("term query on %s failed: %d %s", fieldName, w.Code, w.Body.String())
		}
		hits := r22JSON(t, w)["hits"].(map[string]any)["hits"].([]any)
		if len(hits) != 1 {
			t.Fatalf("expected 1 hit for term query on %s='Alice', got %d: %s", fieldName, len(hits), w.Body.String())
		}
	}

	// 2. Alias targeting unmapped dynamic field works without emitting empty column backticks
	wDyn := r22Req(t, srv, http.MethodPost, "/r22_schema/_search", `{
		"query": {"term": {"dyn_alias": "dyn_val"}}
	}`)
	if wDyn.Code != http.StatusOK || len(r22JSON(t, wDyn)["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("expected 1 hit for term query on dyn_alias, got %d: %s", wDyn.Code, wDyn.Body.String())
	}

	// 3. ignore_above: 1024 drops 1050-byte string before VARCHAR(1024) truncation
	wLong := r22Req(t, srv, http.MethodPost, "/r22_schema/_search", `{
		"query": {"exists": {"field": "long_code"}}
	}`)
	if len(r22JSON(t, wLong)["hits"].(map[string]any)["hits"].([]any)) != 0 {
		t.Fatalf("expected long_code (1050 bytes > ignore_above 1024) to be ignored (not truncated to 1024), got hits: %s", wLong.Body.String())
	}

	// 4. Nested text field with .keyword(ignore_above: 4, normalizer: lowercase):
	//    - nested term query on items.label.keyword for "MixedCaseLongLabel" -> 0 hits (ignored above 4)
	//    - nested match query on items.label for "MixedCaseLongLabel" -> 1 hit (parent text field preserved in n__items!)
	wNestedKw := r22Req(t, srv, http.MethodPost, "/r22_schema/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"term": {"items.label.keyword": "mixedcaselonglabel"}}
			}
		}
	}`)
	if len(r22JSON(t, wNestedKw)["hits"].(map[string]any)["hits"].([]any)) != 0 {
		t.Fatalf("expected 0 hits on items.label.keyword due to ignore_above=4, got: %s", wNestedKw.Body.String())
	}
	wNestedText := r22Req(t, srv, http.MethodPost, "/r22_schema/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"match": {"items.label": "MixedCaseLongLabel"}}
			}
		}
	}`)
	if len(r22JSON(t, wNestedText)["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("expected 1 hit on nested parent text field items.label, got: %s", wNestedText.Body.String())
	}

	// 5. _field_caps: match_only_text has aggregatable=false, and <alias>.keyword is not emitted
	wCaps := r22Req(t, srv, http.MethodGet, "/r22_schema/_field_caps?fields=*", nil)
	capsFields := r22JSON(t, wCaps)["fields"].(map[string]any)
	if _, hasAliasKw := capsFields["full_search_alias.keyword"]; hasAliasKw {
		t.Fatalf("expected full_search_alias.keyword to be suppressed in _field_caps, got %v", capsFields["full_search_alias.keyword"])
	}
	logsMsgCaps := capsFields["logs_msg"].(map[string]any)["match_only_text"].(map[string]any)
	if logsMsgCaps["aggregatable"] != false {
		t.Fatalf("expected match_only_text aggregatable=false, got %v", logsMsgCaps)
	}
}

func TestRound22MultiValuedChildBucketAggsAndMultiHopReverseNested(t *testing.T) {
	srv, _ := newTestServer()
	r22Req(t, srv, http.MethodPut, "/r22_aggs", `{
		"mappings": {
			"properties": {
				"dept":   {"type": "keyword"},
				"tags":   {"type": "keyword", "multi_valued": true},
				"scores": {"type": "integer", "multi_valued": true},
				"amount": {"type": "integer"},
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"}
					}
				}
			}
		}
	}`)
	// Doc 1 has duplicate values in tags ["a", "a"] and scores [10, 15] (both in histogram bucket 10..20)
	r22Req(t, srv, http.MethodPost, "/r22_aggs/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"dept":"eng","tags":["a","a"],"scores":[10,15],"amount":100,"items":[{"sku":"s1"},{"sku":"s1"}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"dept":"eng","tags":["a","b"],"scores":[12],"amount":50,"items":[{"sku":"s2"}]}`+"\n")

	w := r22Req(t, srv, http.MethodPost, "/r22_aggs/_search?size=0", `{
		"aggs": {
			"by_dept": {
				"terms": {"field": "dept"},
				"aggs": {
					"by_tag": {
						"terms": {"field": "tags"},
						"aggs": {
							"total_amount": {"sum": {"field": "amount"}},
							"to_items": {
								"nested": {"path": "items"},
								"aggs": {
									"back_to_root": {
										"reverse_nested": {},
										"aggs": {
											"root_sum": {"sum": {"field": "amount"}}
										}
									}
								}
							}
						}
					},
					"by_score_hist": {
						"histogram": {"field": "scores", "interval": 10},
						"aggs": {
							"hist_amount": {"sum": {"field": "amount"}}
						}
					}
				}
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	res := r22JSON(t, w)
	deptBucket := res["aggregations"].(map[string]any)["by_dept"].(map[string]any)["buckets"].([]any)[0].(map[string]any)
	tagBuckets := deptBucket["by_tag"].(map[string]any)["buckets"].([]any)
	var tagABucket map[string]any
	for _, b := range tagBuckets {
		bm := b.(map[string]any)
		if bm["key"] == "a" {
			tagABucket = bm
			break
		}
	}
	if tagABucket == nil {
		t.Fatalf("missing tag 'a' bucket: %v", tagBuckets)
	}
	if tagABucket["doc_count"] != float64(2) {
		t.Fatalf("expected deduplicated doc_count=2 for child terms bucket 'a', got %v", tagABucket["doc_count"])
	}
	if tagABucket["total_amount"].(map[string]any)["value"] != float64(150) {
		t.Fatalf("expected deduplicated grandchild sum total_amount=150, got %v", tagABucket["total_amount"])
	}
	rn := tagABucket["to_items"].(map[string]any)["back_to_root"].(map[string]any)
	if rn["doc_count"] != float64(2) || rn["root_sum"].(map[string]any)["value"] != float64(150) {
		t.Fatalf("expected reverse_nested under deduplicated parent bucket to have doc_count=2, root_sum=150, got %v", rn)
	}

	histBuckets := deptBucket["by_score_hist"].(map[string]any)["buckets"].([]any)
	if len(histBuckets) != 1 || histBuckets[0].(map[string]any)["doc_count"] != float64(2) {
		t.Fatalf("expected deduplicated doc_count=2 for child histogram bucket 10, got %v", histBuckets)
	}
	if histBuckets[0].(map[string]any)["hist_amount"].(map[string]any)["value"] != float64(150) {
		t.Fatalf("expected deduplicated grandchild hist_amount=150, got %v", histBuckets[0])
	}
}

func TestRound22BooleanIPSortSearchAfterAndSchemaAwareFieldExtraction(t *testing.T) {
	srv, _ := newTestServer()
	r22Req(t, srv, http.MethodPut, "/r22_sort", `{
		"mappings": {
			"properties": {
				"active": {
					"type": "boolean"
				},
				"status": {
					"type": "keyword",
					"null_value": "PENDING"
				},
				"src_tag": {
					"type": "keyword",
					"copy_to": "combined_tag"
				},
				"combined_tag": {
					"type": "keyword"
				}
			}
		}
	}`)
	r22Req(t, srv, http.MethodPost, "/r22_sort/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"active":true,"src_tag":"alpha"}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"active":false,"status":"DONE","src_tag":"beta"}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"status":null,"src_tag":"gamma"}`+"\n")

	// 1. Boolean sort asc with missing="_last": false (doc 2), true (doc 1), missing (doc 3)
	wBoolSort := r22Req(t, srv, http.MethodPost, "/r22_sort/_search", `{
		"sort": [
			{"active": {"order": "asc", "missing": "_last"}},
			{"_id": "asc"}
		],
		"fields": ["status", "combined_tag"],
		"docvalue_fields": ["status", "combined_tag"]
	}`)
	if wBoolSort.Code != http.StatusOK {
		t.Fatalf("boolean sort failed: %d %s", wBoolSort.Code, wBoolSort.Body.String())
	}
	hits := r22JSON(t, wBoolSort)["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 3 || hits[0].(map[string]any)["_id"] != "2" || hits[1].(map[string]any)["_id"] != "1" || hits[2].(map[string]any)["_id"] != "3" {
		t.Fatalf("expected boolean sort order [2, 1, 3], got %v", hits)
	}
	// Check copy_to extraction on doc 1 (combined_tag -> alpha) and null_value extraction on doc 3 (explicit status:null -> PENDING)
	doc1Fields := hits[1].(map[string]any)["fields"].(map[string]any)
	if doc1Fields["combined_tag"].([]any)[0] != "alpha" {
		t.Fatalf("expected doc 1 fields to include copy_to combined_tag=alpha, got %v", doc1Fields)
	}
	doc3Fields := hits[2].(map[string]any)["fields"].(map[string]any)
	if doc3Fields["status"].([]any)[0] != "PENDING" || doc3Fields["combined_tag"].([]any)[0] != "gamma" {
		t.Fatalf("expected doc 3 fields to include null_value status=PENDING and copy_to combined_tag=gamma, got %v", doc3Fields)
	}

	// 2. Boolean search_after: after [false, "2"] should return docs 1 and 3
	wAfter := r22Req(t, srv, http.MethodPost, "/r22_sort/_search", `{
		"sort": [
			{"active": {"order": "asc", "missing": "_last"}},
			{"_id": "asc"}
		],
		"search_after": [false, "2"]
	}`)
	hitsAfter := r22JSON(t, wAfter)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsAfter) != 2 || hitsAfter[0].(map[string]any)["_id"] != "1" || hitsAfter[1].(map[string]any)["_id"] != "3" {
		t.Fatalf("expected docs [1, 3] after search_after=[false, '2'], got %v", hitsAfter)
	}

	// 3. Unmapped IP sort with unmapped_type: "ip"
	wIPSort := r22Req(t, srv, http.MethodPost, "/r22_sort/_search", `{
		"sort": [
			{"unmapped_ip": {"order": "asc", "unmapped_type": "ip"}},
			{"_id": "asc"}
		]
	}`)
	if wIPSort.Code != http.StatusOK {
		t.Fatalf("expected unmapped_type=ip sort to succeed, got %d: %s", wIPSort.Code, wIPSort.Body.String())
	}
}

func TestRound22RescoreOrderWithCollapseSearchAfterAndInnerHitsHighlight(t *testing.T) {
	srv, _ := newTestServer()
	r22Req(t, srv, http.MethodPut, "/r22_rescore", `{
		"mappings": {
			"properties": {
				"group": {"type": "keyword"},
				"title": {"type": "text"},
				"items": {
					"type": "nested",
					"properties": {
						"name": {"type": "text"}
					}
				}
			}
		}
	}`)
	r22Req(t, srv, http.MethodPost, "/r22_rescore/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"group":"g1","title":"common","items":[{"name":"ordinary item"}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"group":"g1","title":"common rocket","items":[{"name":"special rocket item"}]}`+"\n")

	// 1. Without rescore, match_all + default sort [_score desc, _id asc] picks doc 1 first for group "g1".
	//    With rescore boosting "rocket", doc 2 gets a higher _score and MUST win collapse on "group"!
	wCollapse := r22Req(t, srv, http.MethodPost, "/r22_rescore/_search", `{
		"query": {"match_all": {}},
		"collapse": {
			"field": "group",
			"inner_hits": {
				"name": "group_docs",
				"size": 2,
				"highlight": {
					"fields": {
						"title": {}
					}
				}
			}
		},
		"rescore": {
			"window_size": 10,
			"query": {
				"rescore_query": {
					"function_score": {
						"query": {"match": {"title": "rocket"}},
						"weight": 5
					}
				},
				"query_weight": 1,
				"rescore_query_weight": 2
			}
		}
	}`)
	if wCollapse.Code != http.StatusOK {
		t.Fatalf("rescore+collapse failed: %d %s", wCollapse.Code, wCollapse.Body.String())
	}
	hits := r22JSON(t, wCollapse)["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected rescore to run before collapse so doc 2 wins group g1, got %v", hits)
	}
	// Verify function_score weight=5 was NOT double-multiplied:
	// primary score = 1.0, rescore query score = 5.0 * 1.0 = 5.0, total = 1*1.0 + 2*5.0 = 11.0 (not 1 + 2*25 = 51.0)
	gotScore := hits[0].(map[string]any)["_score"].(float64)
	if math.Abs(gotScore-11.0) > 1e-6 {
		t.Fatalf("expected rescored _score=11.0 (no double function_score multiplication), got %v", gotScore)
	}

	// 2. Nested inner_hits with highlight using relative field name "name" and require_field_match: true
	wNestedHL := r22Req(t, srv, http.MethodPost, "/r22_rescore/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"match": {"items.name": "rocket"}},
				"inner_hits": {
					"highlight": {
						"require_field_match": true,
						"fields": {
							"name": {}
						}
					}
				}
			}
		}
	}`)
	hitsNHL := r22JSON(t, wNestedHL)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsNHL) != 1 {
		t.Fatalf("expected 1 hit for nested rocket query, got %v", hitsNHL)
	}
	innerHits := hitsNHL[0].(map[string]any)["inner_hits"].(map[string]any)["items"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	hlMap, ok := innerHits[0].(map[string]any)["highlight"].(map[string]any)
	if !ok || len(hlMap["name"].([]any)) == 0 {
		t.Fatalf("expected nested inner_hits highlight on relative field 'name', got %v", innerHits[0])
	}
}

func TestRound22PipelineAggsOverKeyedBucketsAndFractionalHistogram(t *testing.T) {
	srv, _ := newTestServer()
	r22Req(t, srv, http.MethodPut, "/r22_pipe", `{
		"mappings": {
			"properties": {
				"category": {"type": "keyword"},
				"price":    {"type": "double"},
				"ratio":    {"type": "double"},
				"ts":       {"type": "date"}
			}
		}
	}`)
	r22Req(t, srv, http.MethodPost, "/r22_pipe/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"category":"A","price":100,"ratio":0.1,"ts":"2026-01-10T00:00:00Z"}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"category":"B","price":250,"ratio":0.2,"ts":"2026-01-15T00:00:00Z"}`+"\n")

	w := r22Req(t, srv, http.MethodPost, "/r22_pipe/_search?size=0", `{
		"aggs": {
			"by_filters": {
				"filters": {
					"filters": {
						"cat_a": {"term": {"category": "A"}},
						"cat_b": {"term": {"category": "B"}}
					}
				},
				"aggs": {
					"price_stats": {"stats": {"field": "price"}}
				}
			},
			"max_filter_price": {
				"max_bucket": {
					"buckets_path": "by_filters>price_stats.max"
				}
			},
			"ratio_hist": {
				"histogram": {
					"field": "ratio",
					"interval": 0.1,
					"min_doc_count": 0,
					"extended_bounds": {"min": 0.0, "max": 0.3}
				}
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for pipeline agg over keyed filters + fractional histogram, got %d: %s", w.Code, w.Body.String())
	}
	aggs := r22JSON(t, w)["aggregations"].(map[string]any)
	maxFilter := aggs["max_filter_price"].(map[string]any)
	if maxFilter["value"] != float64(250) {
		t.Fatalf("expected max_filter_price=250, got %v", maxFilter)
	}
	histBuckets := aggs["ratio_hist"].(map[string]any)["buckets"].([]any)
	if len(histBuckets) != 4 {
		t.Fatalf("expected 4 buckets [0, 0.1, 0.2, 0.3], got %v", histBuckets)
	}
	expectedKeys := []float64{0, 0.1, 0.2, 0.3}
	for i, exp := range expectedKeys {
		gotKey := histBuckets[i].(map[string]any)["key"].(float64)
		if gotKey != exp {
			t.Fatalf("bucket %d: expected exact float key %v, got %v", i, exp, gotKey)
		}
	}
}

func TestRound22OCCVersionConsistencyCreate405PainlessAndReindexDelete(t *testing.T) {
	srv, _ := newTestServer()

	// 1. PUT /{index}/_doc/{id} returns the exact _version stored in Doris, and ?version=<v1> OCC succeeds
	wPut := r22Req(t, srv, http.MethodPut, "/r22_occ/_doc/1?refresh=true", `{"count":5,"vals":[10,25,30,60]}`)
	if wPut.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", wPut.Code, wPut.Body.String())
	}
	putVer := int64(r22JSON(t, wPut)["_version"].(float64))

	wGet := r22Req(t, srv, http.MethodGet, "/r22_occ/_doc/1", nil)
	getVer := int64(r22JSON(t, wGet)["_version"].(float64))
	if putVer != getVer {
		t.Fatalf("expected PUT _version (%d) to equal GET _version (%d)", putVer, getVer)
	}

	// Internal OCC with matching ?version=putVer succeeds
	wOCCOk := r22Req(t, srv, http.MethodPut, fmt.Sprintf("/r22_occ/_doc/1?version=%d&refresh=true", putVer), `{"count":6,"vals":[10,25,30,60]}`)
	if wOCCOk.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for matching ?version=%d, got %d: %s", putVer, wOCCOk.Code, wOCCOk.Body.String())
	}
	// Stale ?version=putVer now fails with 409 Conflict
	wOCCConflict := r22Req(t, srv, http.MethodPut, fmt.Sprintf("/r22_occ/_doc/1?version=%d&refresh=true", putVer), `{"count":7}`)
	if wOCCConflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for stale ?version=%d, got %d: %s", putVer, wOCCConflict.Code, wOCCConflict.Body.String())
	}

	// 2. GET / HEAD / DELETE on /{index}/_create/{id} returns 405 Method Not Allowed
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodDelete} {
		w405 := r22Req(t, srv, m, "/r22_occ/_create/1", nil)
		if w405.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 Method Not Allowed for %s /r22_occ/_create/1, got %d", m, w405.Code)
		}
	}

	// 3. Painless: scalar local variable assignment does not alias/mutate ctx._source,
	//    removeIf supports compound boolean conditions, and Eval supports bitwise/shift & null ternary.
	wUpd := r22Req(t, srv, http.MethodPost, "/r22_occ/_update/1?refresh=true", `{
		"script": {
			"source": "def localCnt = ctx._source.count; localCnt = localCnt + 100; ctx._source.vals.removeIf(x -> x > 20 && x < 50); ctx._source.shifted = (1 << 4) | (15 & 6);"
		}
	}`)
	if wUpd.Code != http.StatusOK {
		t.Fatalf("update failed: %d %s", wUpd.Code, wUpd.Body.String())
	}
	wAfterUpd := r22Req(t, srv, http.MethodGet, "/r22_occ/_doc/1", nil)
	srcAfter := r22JSON(t, wAfterUpd)["_source"].(map[string]any)
	if srcAfter["count"] != float64(6) {
		t.Fatalf("expected ctx._source.count to remain 6 when scalar localCnt was modified, got %v", srcAfter["count"])
	}
	valsAfter := srcAfter["vals"].([]any)
	if len(valsAfter) != 2 || valsAfter[0] != float64(10) || valsAfter[1] != float64(60) {
		t.Fatalf("expected removeIf(x -> x > 20 && x < 50) to leave [10, 60], got %v", valsAfter)
	}
	if srcAfter["shifted"] != float64(22) {
		t.Fatalf("expected (1 << 4) | (15 & 6) == 22, got %v", srcAfter["shifted"])
	}

	// Direct Painless Eval check for null-returning ternary and unsigned right shift
	nullVal, err := painless.Eval(map[string]any{}, "doc['missing'].size() == 0 ? null : 'present'", nil)
	if err != nil || nullVal != nil {
		t.Fatalf("expected nil from null-returning ternary in painless.Eval, got %v (err=%v)", nullVal, err)
	}

	// 4. _reindex with ctx.op = "delete" writes a delete tombstone to destination index
	r22Req(t, srv, http.MethodPut, "/r22_reindex_dst/_doc/1?refresh=true", `{"count":999}`)
	wReindex := r22Req(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "r22_occ"},
		"dest":   {"index": "r22_reindex_dst"},
		"script": {
			"source": "if (ctx._id == '1') { ctx.op = 'delete'; }"
		}
	}`)
	if wReindex.Code != http.StatusOK {
		t.Fatalf("_reindex failed: %d %s", wReindex.Code, wReindex.Body.String())
	}
	wDstGet := r22Req(t, srv, http.MethodGet, "/r22_reindex_dst/_doc/1", nil)
	if wDstGet.Code != http.StatusNotFound {
		t.Fatalf("expected destination doc 1 to be deleted by _reindex ctx.op='delete', got %d: %s", wDstGet.Code, wDstGet.Body.String())
	}
}
