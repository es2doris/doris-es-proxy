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
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func r23Req(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
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

func r23JSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal response failed (status=%d, body=%s): %v", w.Code, w.Body.String(), err)
	}
	return m
}

// R23-P0-1: Lucene query_string unary +/-/! precedence, simple_query_string literal and/or/not & unbalanced quotes/parens/flags,
// and multi_match cross_fields operator: "or" / bool_prefix incompatible field pruning / zero_terms_query.
func TestRound23LuceneUnarySimpleQueryStringAndMultiMatch(t *testing.T) {
	srv, _ := newTestServer()
	r23Req(t, srv, http.MethodPut, "/r23_qs", `{
		"mappings": {
			"properties": {
				"title":      {"type": "text"},
				"first_name": {"type": "keyword"},
				"last_name":  {"type": "keyword"},
				"age":        {"type": "integer"}
			}
		}
	}`)
	r23Req(t, srv, http.MethodPost, "/r23_qs/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"title":"requiredalpha opt1","first_name":"alice","last_name":"smith","age":30}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"title":"requiredalpha other","first_name":"alice","last_name":"jones","age":25}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"title":"opt1 opt2","first_name":"bob","last_name":"smith","age":40}`+"\n"+
			`{"index":{"_id":"4"}}`+"\n"+`{"title":"forbiddenbeta opt1 opt2","first_name":"carol","last_name":"white","age":35}`+"\n"+
			`{"index":{"_id":"5"}}`+"\n"+`{"title":"not working today","first_name":"dave","last_name":"brown","age":50}`+"\n")

	// 1. query_string "+requiredalpha opt1" under default_operator OR: must require "requiredalpha" (docs 1 and 2, NOT doc 3)
	w := r23Req(t, srv, http.MethodPost, "/r23_qs/_search", `{
		"query": {
			"query_string": {
				"default_field": "title",
				"default_operator": "OR",
				"query": "+requiredalpha opt1"
			}
		}
	}`)
	res := r23JSON(t, w)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits for '+requiredalpha opt1' (docs 1 and 2), got %d: %+v", len(hits), hits)
	}
	if hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 to rank first due to optional 'opt1' match, got %+v", hits[0])
	}

	// 2. query_string "-forbiddenbeta opt1 AND opt2": must exclude doc 4 and match only doc 3
	w = r23Req(t, srv, http.MethodPost, "/r23_qs/_search", `{
		"query": {
			"query_string": {
				"default_field": "title",
				"query": "-forbiddenbeta opt1 AND opt2"
			}
		}
	}`)
	res = r23JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "3" {
		t.Fatalf("expected only doc 3 for '-bad_term opt1 AND opt2', got %+v", hits)
	}

	// 3. simple_query_string treats "not" as a literal word, not boolean NOT
	w = r23Req(t, srv, http.MethodPost, "/r23_qs/_search", `{
		"query": {
			"simple_query_string": {
				"fields": ["title"],
				"default_operator": "AND",
				"query": "not working"
			}
		}
	}`)
	res = r23JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "5" {
		t.Fatalf("expected doc 5 for simple_query_string 'not working', got %+v", hits)
	}

	// 4. simple_query_string with unclosed quote and unbalanced paren
	w = r23Req(t, srv, http.MethodPost, "/r23_qs/_search", `{
		"query": {
			"simple_query_string": {
				"fields": ["title"],
				"default_operator": "AND",
				"query": "\"working (today"
			}
		}
	}`)
	res = r23JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "5" {
		t.Fatalf("expected doc 5 for simple_query_string with unbalanced quote/paren, got %+v", hits)
	}

	// 5. multi_match cross_fields with default operator "or" across keyword fields
	w = r23Req(t, srv, http.MethodPost, "/r23_qs/_search", `{
		"query": {
			"multi_match": {
				"query": "alice smith",
				"type": "cross_fields",
				"fields": ["first_name", "last_name"]
			}
		}
	}`)
	res = r23JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 3 {
		t.Fatalf("expected 3 hits (docs 1, 2, 3) for cross_fields 'alice smith', got %d: %+v", len(hits), hits)
	}
	if hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 (matching both alice and smith) first, got %+v", hits[0])
	}

	// 6. multi_match bool_prefix across text + integer field (prunes incompatible integer field)
	w = r23Req(t, srv, http.MethodPost, "/r23_qs/_search", `{
		"query": {
			"multi_match": {
				"query": "working tod",
				"type": "bool_prefix",
				"operator": "and",
				"fields": ["title", "age"]
			}
		}
	}`)
	res = r23JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "5" {
		t.Fatalf("expected doc 5 for bool_prefix across title+age, got %+v", hits)
	}
}

// R23-P0-2: Schema & Shredder — ResolveEffectiveField coverage, transitive copy_to through aliases & nested subfields,
// multi-valued text scalar joining, and nested alias resolution.
func TestRound23SchemaEffectiveFieldTransitiveCopyToAndNestedAlias(t *testing.T) {
	srv, _ := newTestServer()
	r23Req(t, srv, http.MethodPut, "/r23_schema", `{
		"mappings": {
			"properties": {
				"raw_code":   {"type": "keyword", "copy_to": "code_alias"},
				"code_alias": {"type": "alias", "path": "mid_code"},
				"mid_code":   {"type": "keyword", "copy_to": "final_bucket"},
				"final_bucket": {
					"type": "text",
					"fields": {
						"keyword": {"type": "keyword"}
					}
				},
				"notes": {"type": "text"},
				"items": {
					"type": "nested",
					"properties": {
						"first": {"type": "keyword", "copy_to": "items.full"},
						"last":  {"type": "keyword", "copy_to": "items.full"},
						"full":  {"type": "keyword"}
					}
				},
				"item_full_alias": {"type": "alias", "path": "items.full"}
			}
		}
	}`)

	r23Req(t, srv, http.MethodPost, "/r23_schema/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"raw_code":"C100","notes":["first paragraph","second paragraph"],"items":[{"first":"Ada","last":"Lovelace"}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"raw_code":"C200","notes":["only one"],"items":[{"first":"Alan","last":"Turing"}]}`+"\n")

	// 1. Transitive copy_to through alias (raw_code -> code_alias -> mid_code -> final_bucket.keyword)
	// and collapse + composite on final_bucket.keyword (promoted to array via copy_to)
	w := r23Req(t, srv, http.MethodPost, "/r23_schema/_search", `{
		"query": {"term": {"final_bucket.keyword": "C100"}},
		"collapse": {"field": "final_bucket.keyword"},
		"aggs": {
			"comp": {
				"composite": {
					"sources": [
						{"b": {"terms": {"field": "final_bucket.keyword"}}}
					]
				}
			}
		}
	}`)
	res := r23JSON(t, w)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 via transitive copy_to through alias, got %+v", hits)
	}
	compBuckets := res["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	if len(compBuckets) != 1 || compBuckets[0].(map[string]any)["key"].(map[string]any)["b"] != "C100" {
		t.Fatalf("expected composite bucket C100, got %+v", compBuckets)
	}

	// 2. Multi-valued text scalar array joining ("second" in second element of notes array)
	w = r23Req(t, srv, http.MethodPost, "/r23_schema/_search", `{
		"query": {"match": {"notes": "second"}}
	}`)
	res = r23JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 to match 'second' from multi-valued text array, got %+v", hits)
	}

	// 3. Correlated nested copy_to (items.first + items.last -> items.full) queried via nested alias (item_full_alias)
	w = r23Req(t, srv, http.MethodPost, "/r23_schema/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {
					"bool": {
						"must": [
							{"term": {"item_full_alias": "Ada"}},
							{"term": {"item_full_alias": "Lovelace"}}
						]
					}
				}
			}
		}
	}`)
	res = r23JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 via nested copy_to and nested alias, got %+v", hits)
	}
}

// R23-P0-3: Aggregations — composite array source deduplication, string script array element_at / EXPLODE,
// and sub-aggregation null metrics on non-empty buckets & empty sibling pipeline aggs.
func TestRound23CompositeArrayDedupStringScriptsAndSubAggNulls(t *testing.T) {
	srv, _ := newTestServer()
	r23Req(t, srv, http.MethodPut, "/r23_aggs", `{
		"mappings": {
			"properties": {
				"dept":   {"type": "keyword"},
				"tags":   {"type": "keyword", "multi_valued": true},
				"amount": {"type": "double"},
				"bonus":  {"type": "double"}
			}
		}
	}`)
	r23Req(t, srv, http.MethodPost, "/r23_aggs/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"dept":"eng","tags":["go","go","rust"],"amount":100}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"dept":"eng","tags":["go"],"amount":200}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"dept":"sales","tags":["crm"],"bonus":50}`+"\n")

	// 1. Composite aggregation on multi-valued array ("tags") + sub-agg sum(amount):
	// doc 1 has duplicate "go" in tags, so (dept="eng", tag="go") must have doc_count=2 and sum_amount=300 (not 3 and 400).
	w := r23Req(t, srv, http.MethodPost, "/r23_aggs/_search", `{
		"size": 0,
		"aggs": {
			"comp": {
				"composite": {
					"sources": [
						{"d": {"terms": {"field": "dept"}}},
						{"t": {"terms": {"field": "tags"}}}
					]
				},
				"aggs": {
					"sum_amt": {"sum": {"field": "amount"}}
				}
			}
		}
	}`)
	res := r23JSON(t, w)
	compBuckets := res["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	foundEngGo := false
	for _, rawB := range compBuckets {
		b := rawB.(map[string]any)
		k := b["key"].(map[string]any)
		if k["d"] == "eng" && k["t"] == "go" {
			foundEngGo = true
			if b["doc_count"] != float64(2) {
				t.Fatalf("expected deduplicated doc_count=2 for (eng, go), got %v", b["doc_count"])
			}
			sumAmt := b["sum_amt"].(map[string]any)["value"]
			if sumAmt != float64(300) {
				t.Fatalf("expected deduplicated sum_amt=300 for (eng, go), got %v", sumAmt)
			}
		}
	}
	if !foundEngGo {
		t.Fatalf("expected (eng, go) bucket in composite agg, got %+v", compBuckets)
	}

	// 2. Non-empty bucket ("sales", doc_count=1) where "amount" is missing on all docs in that bucket:
	// avg_amt / min_amt / max_amt must have value=nil, and min_bucket across departments must be 150 (not 0).
	w = r23Req(t, srv, http.MethodPost, "/r23_aggs/_search", `{
		"size": 0,
		"aggs": {
			"by_dept": {
				"terms": {"field": "dept"},
				"aggs": {
					"avg_amt": {"avg": {"field": "amount"}},
					"min_amt": {"min": {"field": "amount"}},
					"max_amt": {"max": {"field": "amount"}}
				}
			},
			"min_dept_avg": {
				"min_bucket": {"buckets_path": "by_dept>avg_amt"}
			},
			"empty_ filter_terms": {
				"terms": {"field": "dept", "include": "nonexistent"},
				"aggs": {
					"s": {"sum": {"field": "amount"}}
				}
			},
			"empty_avg_bucket": {
				"avg_bucket": {"buckets_path": "empty_ filter_terms>s"}
			}
		}
	}`)
	res = r23JSON(t, w)
	aggs := res["aggregations"].(map[string]any)
	deptBuckets := aggs["by_dept"].(map[string]any)["buckets"].([]any)
	for _, rawB := range deptBuckets {
		b := rawB.(map[string]any)
		if b["key"] == "sales" {
			for _, mName := range []string{"avg_amt", "min_amt", "max_amt"} {
				if v := b[mName].(map[string]any)["value"]; v != nil {
					t.Fatalf("expected %s.value == nil on sales bucket without amount, got %v", mName, v)
				}
			}
		}
	}
	minDeptAvg := aggs["min_dept_avg"].(map[string]any)["value"]
	if minDeptAvg != float64(150) {
		t.Fatalf("expected min_dept_avg == 150 (ignoring nil sales bucket), got %v", minDeptAvg)
	}
	if emptyAvgVal := aggs["empty_avg_bucket"].(map[string]any)["value"]; emptyAvgVal != nil {
		t.Fatalf("expected empty_avg_bucket.value == nil when 0 buckets match, got %v", emptyAvgVal)
	}

	// 3. String script terms agg on StoragePromotedArray ("doc['tags'].value.toUpperCase()" and "field": "tags" + "_value.toUpperCase()")
	w = r23Req(t, srv, http.MethodPost, "/r23_aggs/_search", `{
		"size": 0,
		"aggs": {
			"upper_first_tag": {
				"terms": {
					"script": "doc['tags'].value.toUpperCase()"
				}
			},
			"upper_all_tags": {
				"terms": {
					"field": "tags",
					"script": "_value.toUpperCase()"
				}
			}
		}
	}`)
	res = r23JSON(t, w)
	ufBuckets := res["aggregations"].(map[string]any)["upper_first_tag"].(map[string]any)["buckets"].([]any)
	if len(ufBuckets) != 2 {
		t.Fatalf("expected 2 upper_first_tag buckets (GO, CRM), got %+v", ufBuckets)
	}
	utBuckets := res["aggregations"].(map[string]any)["upper_all_tags"].(map[string]any)["buckets"].([]any)
	if len(utBuckets) != 3 {
		t.Fatalf("expected 3 upper_all_tags buckets (GO, RUST, CRM), got %+v", utBuckets)
	}
}

// R23-P0-4: Pipeline Aggregations & Runtime Aggregations — Keyed/Unkeyed buckets_path selectors,
// Painless multi-statement bucket_script/bucket_selector fallback, and schema-aware runtime aggs.
func TestRound23PipelineAggSelectorsPainlessBucketScriptAndSchemaRuntimeAggs(t *testing.T) {
	srv, _ := newTestServer()
	r23Req(t, srv, http.MethodPut, "/r23_pipe", `{
		"mappings": {
			"properties": {
				"store":      {"type": "keyword"},
				"price":      {"type": "double"},
				"cost":       {"type": "double"},
				"status":     {"type": "keyword", "null_value": "UNKNOWN"},
				"price_alias": {"type": "alias", "path": "price"}
			}
		}
	}`)
	r23Req(t, srv, http.MethodPost, "/r23_pipe/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"store":"s1","price":100,"cost":36,"status":"OK"}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"store":"s1","price":20,"cost":10,"status":null}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"store":"s2","price":50,"cost":40,"status":"ERR"}`+"\n")

	// 1. Keyed & unkeyed buckets_path selectors + multi-statement Painless bucket_script & bucket_selector
	w := r23Req(t, srv, http.MethodPost, "/r23_pipe/_search", `{
		"size": 0,
		"aggs": {
			"by_store": {
				"terms": {"field": "store"},
				"aggs": {
					"rev":  {"sum": {"field": "price_alias"}},
					"cost": {"sum": {"field": "cost"}},
					"by_tier": {
						"range": {
							"field": "price",
							"keyed": false,
							"ranges": [
								{"key": "cheap", "to": 50},
								{"key": "premium", "from": 50}
							]
						},
						"aggs": {
							"tier_rev": {"sum": {"field": "price"}}
						}
					},
					"sqrt_profit": {
						"bucket_script": {
							"buckets_path": {"r": "rev", "c": "cost"},
							"script": "def profit = params.r - params.c; return Math.sqrt(profit);"
						}
					},
					"premium_share": {
						"bucket_script": {
							"buckets_path": {
								"prem": "by_tier['premium']>tier_rev",
								"tot":  "rev"
							},
							"script": "params.prem / params.tot"
						}
					},
					"keep_high_profit": {
						"bucket_selector": {
							"buckets_path": {"r": "rev", "c": "cost"},
							"script": "def margin = params.r - params.c; return margin >= 50;"
						}
					}
				}
			},
			"by_status_filters": {
				"filters": {
					"filters": {
						"unknowns": {"term": {"status": "UNKNOWN"}},
						"errors":   {"term": {"status": "ERR"}}
					}
				}
			},
			"unknown_count_sum": {
				"sum_bucket": {
					"buckets_path": "by_status_filters['unknowns']>_count"
				}
			}
		}
	}`)
	res := r23JSON(t, w)
	aggs := res["aggregations"].(map[string]any)
	storeBuckets := aggs["by_store"].(map[string]any)["buckets"].([]any)
	if len(storeBuckets) != 1 {
		t.Fatalf("expected bucket_selector to keep only store s1, got %+v", storeBuckets)
	}
	s1 := storeBuckets[0].(map[string]any)
	if s1["key"] != "s1" {
		t.Fatalf("expected store s1, got %v", s1["key"])
	}
	// s1 rev=120, cost=46 -> profit=74 -> sqrt(74) ~= 8.6023
	sqrtProfit := s1["sqrt_profit"].(map[string]any)["value"].(float64)
	if math.Abs(sqrtProfit-math.Sqrt(74)) > 1e-4 {
		t.Fatalf("expected sqrt_profit ~= %.4f, got %v", math.Sqrt(74), sqrtProfit)
	}
	// s1 premium tier_rev=100, tot=120 -> 100/120
	premShare := s1["premium_share"].(map[string]any)["value"].(float64)
	if math.Abs(premShare-(100.0/120.0)) > 1e-4 {
		t.Fatalf("expected premium_share ~= %.4f, got %v", 100.0/120.0, premShare)
	}
	unkCount := aggs["unknown_count_sum"].(map[string]any)["value"].(float64)
	if unkCount != 1 {
		t.Fatalf("expected unknown_count_sum == 1 (from null_value UNKNOWN), got %v", unkCount)
	}
}

// R23-P0-5: highlight UTF-8 rune-safe fragment slicing & default fragment_size: 100, alias/copy_to highlight,
// rescore + collapse + collapse.inner_hits, top_metrics schema awareness, wildcard fields: ["*"], and paginated max_score.
func TestRound23HighlightUTF8RescoreCollapseTopMetricsAndWildcardFields(t *testing.T) {
	srv, _ := newTestServer()
	r23Req(t, srv, http.MethodPut, "/r23_post", `{
		"mappings": {
			"properties": {
				"dept":       {"type": "keyword"},
				"title":      {"type": "text", "copy_to": "mid_text"},
				"mid_text":   {"type": "text", "copy_to": "full_text"},
				"full_text":  {"type": "text"},
				"title_alias": {"type": "alias", "path": "title"},
				"salary":     {"type": "integer"},
				"tier":       {"type": "keyword", "null_value": "STANDARD"}
			}
		}
	}`)

	longUTF8 := strings.Repeat("日本語テキスト🔍", 8) + " 検索エンジン " + strings.Repeat("データ解析🚀", 8)
	b1, _ := json.Marshal(map[string]any{"dept": "eng", "title": longUTF8, "salary": 100, "tier": nil})
	b2, _ := json.Marshal(map[string]any{"dept": "eng", "title": "検索エンジン boost_target", "salary": 200, "tier": "GOLD"})
	b3, _ := json.Marshal(map[string]any{"dept": "sales", "title": "検索エンジン sales", "salary": 150, "tier": "SILVER"})

	r23Req(t, srv, http.MethodPost, "/r23_post/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+string(b1)+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+string(b2)+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+string(b3)+"\n")

	// 1. Highlight UTF-8 rune-boundary safety with number_of_fragments: 1 (default fragment_size: 100),
	// query on title_alias highlighting "title", and 2-hop copy_to highlighting "full_text".
	w := r23Req(t, srv, http.MethodPost, "/r23_post/_search", `{
		"query": {"match": {"title_alias": "検索エンジン"}},
		"from": 1,
		"size": 1,
		"fields": ["*"],
		"highlight": {
			"number_of_fragments": 1,
			"fields": {
				"title": {},
				"full_text": {}
			}
		},
		"aggs": {
			"top_sal": {
				"top_metrics": {
					"metrics": [{"field": "tier"}, {"field": "title_alias"}],
					"sort": [{"salary": "asc"}],
					"size": 1
				}
			}
		}
	}`)
	res := r23JSON(t, w)
	hitsEnv := res["hits"].(map[string]any)
	if hitsEnv["max_score"] == nil || hitsEnv["max_score"].(float64) <= 0 {
		t.Fatalf("expected positive max_score on paginated page (from=1, size=1), got %v", hitsEnv["max_score"])
	}
	hits := hitsEnv["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit on page, got %d", len(hits))
	}
	hit0 := hits[0].(map[string]any)
	hl := hit0["highlight"].(map[string]any)
	for _, fName := range []string{"title", "full_text"} {
		frags, ok := hl[fName].([]any)
		if !ok || len(frags) == 0 {
			t.Fatalf("expected highlight fragments for %s, got %+v", fName, hl)
		}
		fragStr := frags[0].(string)
		if !utf8.ValidString(fragStr) {
			t.Fatalf("highlight fragment for %s is invalid UTF-8: %q", fName, fragStr)
		}
	}
	// Check top_metrics resolved null_value "STANDARD" on doc 1 (lowest salary=100)
	topArr := res["aggregations"].(map[string]any)["top_sal"].(map[string]any)["top"].([]any)
	topMetrics := topArr[0].(map[string]any)["metrics"].(map[string]any)
	if topMetrics["tier"] != "STANDARD" {
		t.Fatalf("expected top_metrics tier == 'STANDARD' via null_value, got %v", topMetrics["tier"])
	}

	// 2. Rescore + Collapse + Collapse InnerHits:
	// Doc 1 and Doc 2 are both in dept="eng"; rescore boosts "boost_target" (Doc 2), so Doc 2 must win the collapse group
	// and also rank first inside collapse.inner_hits.
	w = r23Req(t, srv, http.MethodPost, "/r23_post/_search", `{
		"query": {"match": {"title": "検索エンジン"}},
		"collapse": {
			"field": "dept",
			"inner_hits": {
				"name": "dept_members",
				"size": 5
			}
		},
		"rescore": {
			"window_size": 10,
			"query": {
				"rescore_query": {"match": {"title": "boost_target"}},
				"query_weight": 1.0,
				"rescore_query_weight": 10.0
			}
		}
	}`)
	res = r23JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 collapsed hits (eng and sales), got %+v", hits)
	}
	firstCollapsed := hits[0].(map[string]any)
	if firstCollapsed["_id"] != "2" {
		t.Fatalf("expected doc 2 to win 'eng' collapse group after rescore, got _id=%v", firstCollapsed["_id"])
	}
	innerHits := firstCollapsed["inner_hits"].(map[string]any)["dept_members"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(innerHits) != 2 || innerHits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected doc 2 first in inner_hits after rescore, got %+v", innerHits)
	}
}

// R23-P0-6: Painless Engine — Bitwise/shift left-associativity & precedence, bitwise compound assignments,
// ZonedDateTime methods, Java 11 String/List methods, and schema-aware doc['...'].
func TestRound23PainlessBitwiseAssociativityCompoundAssignZonedDateTimeAndJava11Methods(t *testing.T) {
	srv, _ := newTestServer()
	r23Req(t, srv, http.MethodPut, "/r23_painless", `{
		"mappings": {
			"properties": {
				"ts":         {"type": "date"},
				"tag":        {"type": "keyword", "null_value": "DEFAULT_TAG", "copy_to": "copied_tag"},
				"copied_tag": {"type": "keyword"},
				"tag_alias":  {"type": "alias", "path": "tag"}
			}
		}
	}`)
	r23Req(t, srv, http.MethodPost, "/r23_painless/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"ts":"2026-03-15T14:30:45.123Z","tag":null}`+"\n")

	w := r23Req(t, srv, http.MethodPost, "/r23_painless/_search", `{
		"script_fields": {
			"shift_left_assoc": {
				"script": "64 >> 2 >> 1"
			},
			"shift_mixed_prec": {
				"script": "1 << 4 >> 2"
			},
			"compound_bitwise": {
				"script": "int x = 5; x <<= 2; x |= 3; x &= 15; x ^= 1; x >>= 1; return x;"
			},
			"zdt_parts": {
				"script": "doc['ts'].value.getYear() * 10000 + doc['ts'].value.getMonthValue() * 100 + doc['ts'].value.getDayOfMonth()"
			},
			"zdt_time_dow": {
				"script": "doc['ts'].value.getHour() * 100 + doc['ts'].value.getMinute() + doc['ts'].value.getDayOfWeek().getValue()"
			},
			"java11_str": {
				"script": "'   '.isBlank() ? '  ab  '.strip().repeat(3) : 'no'"
			},
			"java11_list": {
				"script": "def a = [1, 2, 3, 4]; a.removeAll([2, 4]); a.retainAll([1, 3, 5]); return a.containsAll([1, 3]) ? a.size() : 0;"
			},
			"schema_doc": {
				"script": "doc['tag_alias'].value + '|' + doc['copied_tag'].value"
			}
		}
	}`)
	res := r23JSON(t, w)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %+v", hits)
	}
	fields := hits[0].(map[string]any)["fields"].(map[string]any)
	if got := fields["shift_left_assoc"].([]any)[0]; got != float64(8) {
		t.Fatalf("expected 64 >> 2 >> 1 == 8, got %v", got)
	}
	if got := fields["shift_mixed_prec"].([]any)[0]; got != float64(4) {
		t.Fatalf("expected 1 << 4 >> 2 == 4, got %v", got)
	}
	// x=5 -> <<=2 (20) -> |=3 (23) -> &=15 (7) -> ^=1 (6) -> >>=1 (3)
	if got := fields["compound_bitwise"].([]any)[0]; got != float64(3) {
		t.Fatalf("expected compound_bitwise == 3, got %v", got)
	}
	if got := fields["zdt_parts"].([]any)[0]; got != float64(20260315) {
		t.Fatalf("expected zdt_parts == 20260315, got %v", got)
	}
	// 2026-03-15 is Sunday (ISO day-of-week = 7), hour=14, minute=30 -> 1400 + 30 + 7 = 1437
	if got := fields["zdt_time_dow"].([]any)[0]; got != float64(1437) {
		t.Fatalf("expected zdt_time_dow == 1437, got %v", got)
	}
	if got := fields["java11_str"].([]any)[0]; got != "ababab" {
		t.Fatalf("expected java11_str == 'ababab', got %v", got)
	}
	if got := fields["java11_list"].([]any)[0]; got != float64(2) {
		t.Fatalf("expected java11_list == 2, got %v", got)
	}
	if got := fields["schema_doc"].([]any)[0]; got != "DEFAULT_TAG|DEFAULT_TAG" {
		t.Fatalf("expected schema_doc == 'DEFAULT_TAG|DEFAULT_TAG', got %v", got)
	}
}

// R23-P0-7: OCC & Write Path — External version after DELETE, validateOCC validation,
// _reindex dest.version_type, _update_by_query pipeline _id mutation, and ingest processors.
func TestRound23OCCExternalVersionDeleteReindexUpdateByQueryAndIngestProcessors(t *testing.T) {
	srv, _ := newTestServer()
	r23Req(t, srv, http.MethodPut, "/r23_occ", `{
		"mappings": {
			"properties": {
				"v": {"type": "keyword"}
			}
		}
	}`)

	// 1. External version PUT v=5 -> DELETE -> PUT v=10&version_type=external must succeed and be searchable!
	w := r23Req(t, srv, http.MethodPut, "/r23_occ/_doc/1?version=5&version_type=external&refresh=true", `{"v":"five"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on initial external PUT, got %d: %s", w.Code, w.Body.String())
	}
	w = r23Req(t, srv, http.MethodDelete, "/r23_occ/_doc/1?refresh=true", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on DELETE, got %d: %s", w.Code, w.Body.String())
	}
	w = r23Req(t, srv, http.MethodPut, "/r23_occ/_doc/1?version=10&version_type=external&refresh=true", `{"v":"ten"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created on re-creating deleted doc with external version=10, got %d: %s", w.Code, w.Body.String())
	}
	w = r23Req(t, srv, http.MethodGet, "/r23_occ/_doc/1", nil)
	docRes := r23JSON(t, w)
	if docRes["found"] != true || docRes["_version"] != float64(10) {
		t.Fatalf("expected found=true and _version=10 after external re-create, got %+v", docRes)
	}

	// 2. validateOCC error cases:
	// a) if_seq_no + version combined -> 400
	w = r23Req(t, srv, http.MethodPut, "/r23_occ/_doc/1?if_seq_no=1&if_primary_term=1&version=11", `{"v":"bad"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when combining if_seq_no and version, got %d", w.Code)
	}
	// b) version_type=external without version -> 400
	w = r23Req(t, srv, http.MethodPut, "/r23_occ/_doc/1?version_type=external", `{"v":"bad"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for version_type=external without version, got %d", w.Code)
	}
	// c) _update with version_type=external -> 400
	w = r23Req(t, srv, http.MethodPost, "/r23_occ/_update/1?version=20&version_type=external", `{"doc":{"v":"bad"}}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for _update with version_type=external, got %d", w.Code)
	}

	// 3. _reindex with dest.version_type: "external"
	r23Req(t, srv, http.MethodPut, "/r23_occ_dst", `{"mappings":{"properties":{"v":{"type":"keyword"}}}}`)
	r23Req(t, srv, http.MethodPut, "/r23_occ_dst/_doc/1?version=15&version_type=external&refresh=true", `{"v":"fifteen"}`)
	// Reindexing doc 1 (version 10) into r23_occ_dst (already at version 15) with version_type=external and conflicts=proceed
	w = r23Req(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"conflicts": "proceed",
		"source": {"index": "r23_occ"},
		"dest":   {"index": "r23_occ_dst", "version_type": "external"}
	}`)
	reidxRes := r23JSON(t, w)
	if reidxRes["version_conflicts"] != float64(1) {
		t.Fatalf("expected 1 version_conflict in _reindex with external version 10 <= 15, got %+v", reidxRes)
	}

	// 4. _update_by_query with pipeline mutating ctx._id
	r23Req(t, srv, http.MethodPut, "/_ingest/pipeline/r23_rename_id", `{
		"processors": [
			{"script": {"source": "ctx._id = 'renamed_' + ctx._id; ctx.v = 'updated';"}}
		]
	}`)
	w = r23Req(t, srv, http.MethodPost, "/r23_occ/_update_by_query?pipeline=r23_rename_id&refresh=true", `{
		"query": {"match_all": {}}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("_update_by_query failed: %d %s", w.Code, w.Body.String())
	}
	w = r23Req(t, srv, http.MethodGet, "/r23_occ/_doc/renamed_1", nil)
	if r23JSON(t, w)["found"] != true {
		t.Fatalf("expected renamed_1 to exist after _update_by_query pipeline _id mutation")
	}
	w = r23Req(t, srv, http.MethodGet, "/r23_occ/_doc/1", nil)
	if r23JSON(t, w)["found"] != false {
		t.Fatalf("expected old _id=1 to be deleted after _update_by_query pipeline _id mutation")
	}

	// 5. Ingest processors: kv duplicate keys, remove keep + Mustache template, json add_to_root_conflict_strategy: "merge",
	// and null field with ignore_missing: false triggering on_failure.
	w = r23Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"kv": {"field": "query", "field_split": "&", "value_split": "=", "target_field": "parsed_kv"}},
				{"json": {"field": "payload", "add_to_root": true, "add_to_root_conflict_strategy": "merge"}},
				{"remove": {"field": ["{{drop_me}}"], "keep": ["query", "parsed_kv", "meta", "null_field"]}},
				{
					"lowercase": {
						"field": "null_field",
						"ignore_missing": false,
						"on_failure": [
							{"set": {"field": "null_error_caught", "value": true}}
						]
					}
				}
			]
		},
		"docs": [
			{
				"_source": {
					"query": "tag=a&tag=b&tag=c",
					"payload": "{\"meta\":{\"b\":2}}",
					"meta": {"a": 1},
					"drop_me": "secret",
					"secret": "remove_this",
					"extra_unkept": "also_remove",
					"null_field": null
				}
			}
		]
	}`)
	simRes := r23JSON(t, w)
	simDoc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	kvTags := simDoc["parsed_kv"].(map[string]any)["tag"].([]any)
	if len(kvTags) != 3 || kvTags[0] != "a" || kvTags[1] != "b" || kvTags[2] != "c" {
		t.Fatalf("expected kv duplicate keys [a, b, c], got %+v", kvTags)
	}
	metaMap := simDoc["meta"].(map[string]any)
	if metaMap["a"] != float64(1) || metaMap["b"] != float64(2) {
		t.Fatalf("expected merged root meta {a:1, b:2}, got %+v", metaMap)
	}
	if _, hasSecret := simDoc["secret"]; hasSecret {
		t.Fatalf("expected 'secret' removed by Mustache template, got %+v", simDoc)
	}
	if _, hasUnkept := simDoc["extra_unkept"]; hasUnkept {
		t.Fatalf("expected 'extra_unkept' removed by keep list, got %+v", simDoc)
	}
	if simDoc["null_error_caught"] != true {
		t.Fatalf("expected lowercase on explicit null with ignore_missing:false to trigger on_failure, got %+v", simDoc)
	}
}
