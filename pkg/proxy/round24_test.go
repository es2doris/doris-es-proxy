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

	"github.com/es2doris/doris-es-proxy/pkg/painless"
)

func r24Req(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
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

func r24JSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal response failed (status=%d, body=%s): %v", w.Code, w.Body.String(), err)
	}
	return m
}

// R24-P0-1: Lucene boolean precedence (NOT A OR B, +A B OR C under AND, +A B AND C under OR) and DisMax FALSE disjuncts.
func TestRound24LuceneAndDisMaxBooleanCompilation(t *testing.T) {
	srv, _ := newTestServer()
	r24Req(t, srv, http.MethodPut, "/r24_lucene", `{
		"mappings": {
			"properties": {
				"env":   {"type": "keyword"},
				"level": {"type": "keyword"},
				"service": {"type": "keyword"}
			}
		}
	}`)
	r24Req(t, srv, http.MethodPost, "/r24_lucene/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"env":"prod","level":"error","service":"auth"}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"env":"prod","level":"info","service":"billing"}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"env":"dev","level":"error","service":"auth"}`+"\n"+
			`{"index":{"_id":"4"}}`+"\n"+`{"env":"dev","level":"info","service":"search"}`+"\n")

	// 1. NOT env:prod OR level:error -> (NOT env:prod) OR (level:error)
	// Should match doc 1 (level:error), doc 3 (NOT prod & level:error), doc 4 (NOT prod), excluding only doc 2 (prod & info).
	w := r24Req(t, srv, http.MethodPost, "/r24_lucene/_search", `{
		"query": {
			"query_string": {
				"query": "NOT env:prod OR level:error"
			}
		}
	}`)
	res := r24JSON(t, w)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 3 {
		t.Fatalf("expected 3 hits for 'NOT env:prod OR level:error', got %d: %+v", len(hits), hits)
	}

	// 2. +env:prod service:auth OR service:billing under default_operator: AND
	// Must require env:prod AND (service:auth OR service:billing) -> docs 1 and 2.
	w = r24Req(t, srv, http.MethodPost, "/r24_lucene/_search", `{
		"query": {
			"query_string": {
				"default_operator": "AND",
				"query": "+env:prod service:auth OR service:billing"
			}
		}
	}`)
	res = r24JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits for '+env:prod service:auth OR service:billing' under AND, got %d: %+v", len(hits), hits)
	}

	// 3. +env:prod level:error AND service:auth under default_operator: OR
	// Must require env:prod (matching docs 1 and 2) and optionally boost (level:error AND service:auth) (doc 1 first).
	w = r24Req(t, srv, http.MethodPost, "/r24_lucene/_search", `{
		"query": {
			"query_string": {
				"default_operator": "OR",
				"query": "+env:prod level:error AND service:auth"
			}
		}
	}`)
	res = r24JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits for '+env:prod level:error AND service:auth' under OR, got %d: %+v", len(hits), hits)
	}
	if hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 to rank first, got %+v", hits[0])
	}

	// 4. dis_max containing a zero-scoring bool filter clause and an unmapped/FALSE query
	w = r24Req(t, srv, http.MethodPost, "/r24_lucene/_search", `{
		"query": {
			"dis_max": {
				"queries": [
					{"bool": {"filter": [{"term": {"env": "prod"}}]}},
					{"term": {"unmapped_int": "not_a_number"}}
				]
			}
		}
	}`)
	res = r24JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits for dis_max with zero-score filter + FALSE disjunct, got %d: %+v", len(hits), hits)
	}
}

// R24-P0-2: Nested array-valued subfields & nested .keyword companions (ignore_above, null_value, copy_to).
func TestRound24NestedArraySubfieldsAndNestedKeywordCompanions(t *testing.T) {
	srv, _ := newTestServer()
	r24Req(t, srv, http.MethodPut, "/r24_nested", `{
		"mappings": {
			"properties": {
				"items": {
					"type": "nested",
					"properties": {
						"scores": {"type": "integer"},
						"label": {
							"type": "text",
							"fields": {
								"keyword": {
									"type": "keyword",
									"ignore_above": 10,
									"null_value": "MISSING",
									"copy_to": "items.all_keywords"
								}
							}
						},
						"all_keywords": {"type": "keyword"}
					}
				}
			}
		}
	}`)
	r24Req(t, srv, http.MethodPost, "/r24_nested/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"items":[{"scores":[10,20],"label":"short"},{"scores":[100],"label":null}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"items":[{"scores":[100,200],"label":"this_label_is_way_too_long"}]}`+"\n")

	// 1. Exact numeric term query on nested array subfield (scores: 10 must match doc 1, NOT doc 2 which has [100,200])
	w := r24Req(t, srv, http.MethodPost, "/r24_nested/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"term": {"items.scores": 10}}
			}
		}
	}`)
	res := r24JSON(t, w)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected only doc 1 to match items.scores=10, got %+v", hits)
	}

	// 2. Nested .keyword null_value ("MISSING") and copy_to ("items.all_keywords")
	w = r24Req(t, srv, http.MethodPost, "/r24_nested/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"term": {"items.label.keyword": "MISSING"}}
			}
		}
	}`)
	res = r24JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 to match items.label.keyword=MISSING, got %+v", hits)
	}

	w = r24Req(t, srv, http.MethodPost, "/r24_nested/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"term": {"items.all_keywords": "short"}}
			}
		}
	}`)
	res = r24JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 to match items.all_keywords=short via .keyword copy_to, got %+v", hits)
	}

	// 3. Nested .keyword ignore_above (doc 2's label is > 10 chars so must be ignored in .keyword and copy_to)
	w = r24Req(t, srv, http.MethodPost, "/r24_nested/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"exists": {"field": "items.label.keyword"}}
			}
		}
	}`)
	res = r24JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected only doc 1 to have items.label.keyword after ignore_above, got %+v", hits)
	}

	// 4. Nested metric agg over array-valued subfield (doc 1: [10,20] + [100] = 130, doc 2: [100,200] = 300 -> total sum = 430, count = 5, avg = 86)
	w = r24Req(t, srv, http.MethodPost, "/r24_nested/_search", `{
		"size": 0,
		"aggs": {
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"total_score": {"sum": {"field": "items.scores"}},
					"avg_score":   {"avg": {"field": "items.scores"}}
				}
			}
		}
	}`)
	res = r24JSON(t, w)
	nestedAgg := res["aggregations"].(map[string]any)["nested_items"].(map[string]any)
	totalScore := nestedAgg["total_score"].(map[string]any)["value"].(float64)
	avgScore := nestedAgg["avg_score"].(map[string]any)["value"].(float64)
	if totalScore != 430 || avgScore != 86 {
		t.Fatalf("expected nested array sum=430 and avg=86, got sum=%v avg=%v", totalScore, avgScore)
	}
}

// R24-P0-3: Top-level & container avg/min/max null values on 0 matching docs, and sibling-before-child pipeline agg ordering.
func TestRound24EmptyMetricNullsAndPipelineAggOrdering(t *testing.T) {
	srv, _ := newTestServer()
	r24Req(t, srv, http.MethodPut, "/r24_aggs", `{
		"mappings": {
			"properties": {
				"category": {"type": "keyword"},
				"amount":   {"type": "double"}
			}
		}
	}`)
	r24Req(t, srv, http.MethodPost, "/r24_aggs/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"category":"books","amount":50}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"category":"games","amount":150}`+"\n")

	// 1. 0 matching documents: top-level and filter-container avg/min/max must return nil ("value": null), while sum returns 0
	w := r24Req(t, srv, http.MethodPost, "/r24_aggs/_search", `{
		"size": 0,
		"query": {"term": {"category": "nonexistent"}},
		"aggs": {
			"avg_amt": {"avg": {"field": "amount"}},
			"min_amt": {"min": {"field": "amount"}},
			"max_amt": {"max": {"field": "amount"}},
			"sum_amt": {"sum": {"field": "amount"}},
			"filtered": {
				"filter": {"term": {"category": "nonexistent"}},
				"aggs": {
					"f_avg": {"avg": {"field": "amount"}},
					"f_min": {"min": {"field": "amount"}},
					"f_max": {"max": {"field": "amount"}}
				}
			}
		}
	}`)
	res := r24JSON(t, w)
	aggs := res["aggregations"].(map[string]any)
	for _, k := range []string{"avg_amt", "min_amt", "max_amt"} {
		if aggs[k].(map[string]any)["value"] != nil {
			t.Fatalf("expected %s.value to be nil on 0 hits, got %+v", k, aggs[k])
		}
	}
	if aggs["sum_amt"].(map[string]any)["value"].(float64) != 0 {
		t.Fatalf("expected sum_amt.value to be 0 on 0 hits, got %+v", aggs["sum_amt"])
	}
	fAgg := aggs["filtered"].(map[string]any)
	for _, k := range []string{"f_avg", "f_min", "f_max"} {
		if fAgg[k].(map[string]any)["value"] != nil {
			t.Fatalf("expected filtered.%s.value to be nil on 0 hits, got %+v", k, fAgg[k])
		}
	}

	// 2. Single-bucket container with sibling pipeline agg (sum_bucket) referenced by a child pipeline agg (bucket_script),
	// plus root-level bucket_script referencing root-level sum_bucket.
	w = r24Req(t, srv, http.MethodPost, "/r24_aggs/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {"field": "category"},
				"aggs": {
					"cat_sum": {"sum": {"field": "amount"}}
				}
			},
			"total_across_cats": {
				"sum_bucket": {"buckets_path": "by_cat>cat_sum"}
			},
			"root_doubled": {
				"bucket_script": {
					"buckets_path": {"t": "total_across_cats"},
					"script": "params.t * 2"
				}
			},
			"all_filter": {
				"filter": {"match_all": {}},
				"aggs": {
					"inner_cats": {
						"terms": {"field": "category"},
						"aggs": {
							"s": {"sum": {"field": "amount"}}
						}
					},
					"inner_sum_bucket": {
						"sum_bucket": {"buckets_path": "inner_cats>s"}
					},
					"inner_script": {
						"bucket_script": {
							"buckets_path": {"x": "inner_sum_bucket"},
							"script": "params.x + 10"
						}
					}
				}
			}
		}
	}`)
	res = r24JSON(t, w)
	aggs = res["aggregations"].(map[string]any)
	if aggs["root_doubled"].(map[string]any)["value"].(float64) != 400 {
		t.Fatalf("expected root_doubled=400, got %+v", aggs["root_doubled"])
	}
	allFilter := aggs["all_filter"].(map[string]any)
	if allFilter["inner_script"].(map[string]any)["value"].(float64) != 210 {
		t.Fatalf("expected all_filter.inner_script=210, got %+v", allFilter["inner_script"])
	}
}

// R24-P0-4: Runtime script scoring with boosted non-script clauses, moving_avg/moving_fn ewma alpha & custom scripts, and scripted_metric.
func TestRound24RuntimeScriptScoringMovingFnAndScriptedMetric(t *testing.T) {
	srv, _ := newTestServer()
	r24Req(t, srv, http.MethodPut, "/r24_scripts", `{
		"mappings": {
			"properties": {
				"tag":   {"type": "keyword"},
				"price": {"type": "double"},
				"step":  {"type": "integer"}
			}
		}
	}`)
	r24Req(t, srv, http.MethodPost, "/r24_scripts/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"tag":"vip","price":10,"step":1}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"tag":"regular","price":30,"step":2}`+"\n")

	// 1. Runtime bool.should mixing a script clause and a boosted term clause (tag:vip^10)
	// Doc 1 matches tag:vip^10 (score 10), Doc 2 matches only script (score 1). Doc 1 must rank first with score >= 10.
	w := r24Req(t, srv, http.MethodPost, "/r24_scripts/_search", `{
		"query": {
			"bool": {
				"should": [
					{"term": {"tag": {"value": "vip", "boost": 10.0}}},
					{"script": {"script": "doc['price'].value > 20"}}
				],
				"minimum_should_match": 1
			}
		}
	}`)
	res := r24JSON(t, w)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 (boosted vip) to rank first, got %+v", hits)
	}
	if hits[0].(map[string]any)["_score"].(float64) < 10.0 {
		t.Fatalf("expected doc 1 _score >= 10.0, got %v", hits[0].(map[string]any)["_score"])
	}

	// 2. moving_avg with ewma settings.alpha=0.5, moving_fn with custom script, and scripted_metric
	w = r24Req(t, srv, http.MethodPost, "/r24_scripts/_search", `{
		"size": 0,
		"aggs": {
			"by_step": {
				"histogram": {"field": "step", "interval": 1},
				"aggs": {
					"p": {"sum": {"field": "price"}},
					"ewma_half": {
						"moving_avg": {
							"buckets_path": "p",
							"window": 2,
							"model": "ewma",
							"settings": {"alpha": 0.5}
						}
					},
					"custom_fn": {
						"moving_fn": {
							"buckets_path": "p",
							"window": 2,
							"script": "values.length > 0 ? values[values.length - 1] * 3 : 0"
						}
					}
				}
			},
			"profit_metric": {
				"scripted_metric": {
					"params": {"factor": 2},
					"init_script": "state.total = 0",
					"map_script": "state.total += doc['price'].value * params.factor",
					"combine_script": "return state.total",
					"reduce_script": "double sum = 0; for (s in states) { sum += s; } return sum"
				}
			}
		}
	}`)
	res = r24JSON(t, w)
	aggs := res["aggregations"].(map[string]any)
	buckets := aggs["by_step"].(map[string]any)["buckets"].([]any)
	b0 := buckets[0].(map[string]any)
	if math.Abs(b0["ewma_half"].(map[string]any)["value"].(float64)-10.0) > 1e-6 {
		t.Fatalf("expected ewma_half at bucket 0 to be 10.0, got %+v", b0["ewma_half"])
	}
	b1 := buckets[1].(map[string]any)
	// With alpha=0.5 (instead of default 0.3), ewma at bucket 1 is 0.5*30 + 0.5*10 = 20.0
	if math.Abs(b1["ewma_half"].(map[string]any)["value"].(float64)-20.0) > 1e-6 {
		t.Fatalf("expected ewma_half at bucket 1 to be 20.0, got %+v", b1["ewma_half"])
	}
	if math.Abs(b1["custom_fn"].(map[string]any)["value"].(float64)-90.0) > 1e-6 {
		t.Fatalf("expected custom_fn at bucket 1 (30 * 3) to be 90.0, got %+v", b1["custom_fn"])
	}
	pmVal := aggs["profit_metric"].(map[string]any)["value"].(float64)
	if math.Abs(pmVal-80.0) > 1e-6 {
		t.Fatalf("expected scripted_metric value=(10+30)*2=80, got %v", pmVal)
	}
}

// R24-P0-5: Collapse inner_hits with runtime post_filter/min_score, merged nested inner_hits pagination, and highlight multi-fields/terms_set.
func TestRound24CollapseInnerHitsMergedNestedInnerHitsAndHighlight(t *testing.T) {
	srv, _ := newTestServer()
	r24Req(t, srv, http.MethodPut, "/r24_search_post", `{
		"mappings": {
			"properties": {
				"group": {"type": "keyword"},
				"val":   {"type": "integer"},
				"title": {
					"type": "text",
					"fields": {
						"raw": {"type": "keyword"}
					}
				},
				"comments": {
					"type": "nested",
					"properties": {
						"author": {"type": "keyword"},
						"votes":  {"type": "integer"}
					}
				}
			}
		}
	}`)
	r24Req(t, srv, http.MethodPost, "/r24_search_post/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"group":"g1","val":100,"title":"alpha beta","comments":[{"author":"alice","votes":5},{"author":"bob","votes":20},{"author":"alice","votes":30}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"group":"g1","val":50,"title":"alpha gamma","comments":[{"author":"bob","votes":10}]}`+"\n")

	// 1. Collapse with runtime script post_filter: post_filter excludes doc 2 (val=50 <= 60) from both top hits and collapse inner_hits
	w := r24Req(t, srv, http.MethodPost, "/r24_search_post/_search", `{
		"query": {"term": {"group": "g1"}},
		"post_filter": {"script": {"script": "doc['val'].value > 60"}},
		"collapse": {
			"field": "group",
			"inner_hits": {"name": "all_in_group", "size": 5}
		}
	}`)
	res := r24JSON(t, w)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected 1 top hit (doc 1) after scripted post_filter, got %+v", hits)
	}
	ihHits := hits[0].(map[string]any)["inner_hits"].(map[string]any)["all_in_group"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(ihHits) != 1 || ihHits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected collapse inner_hits to enforce scripted post_filter (excluding doc 2 with val=50), got %d: %+v", len(ihHits), ihHits)
	}

	// 2. Multiple nested clauses sharing inner_hits name="matched_comments" with sort on comments.votes desc, from=1, size=1
	// Doc 1 has 3 matching comments across the two nested clauses (votes 30, 20, 5).
	// Total must be 3, and [from=1, size=1] sorted by votes desc must return the comment with votes=20.
	w = r24Req(t, srv, http.MethodPost, "/r24_search_post/_search", `{
		"query": {
			"bool": {
				"must": [
					{
						"nested": {
							"path": "comments",
							"query": {"term": {"comments.author": "alice"}},
							"inner_hits": {
								"name": "matched_comments",
								"from": 1,
								"size": 1,
								"sort": [{"comments.votes": {"order": "desc"}}]
							}
						}
					},
					{
						"nested": {
							"path": "comments",
							"query": {"term": {"comments.author": "bob"}},
							"inner_hits": {
								"name": "matched_comments",
								"from": 1,
								"size": 1,
								"sort": [{"comments.votes": {"order": "desc"}}]
							}
						}
					}
				]
			}
		}
	}`)
	res = r24JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit (doc 1), got %d", len(hits))
	}
	mcEnv := hits[0].(map[string]any)["inner_hits"].(map[string]any)["matched_comments"].(map[string]any)["hits"].(map[string]any)
	if mcEnv["total"].(map[string]any)["value"].(float64) != 3 {
		t.Fatalf("expected merged nested inner_hits total=3, got %+v", mcEnv["total"])
	}
	mcHits := mcEnv["hits"].([]any)
	if len(mcHits) != 1 || mcHits[0].(map[string]any)["_source"].(map[string]any)["votes"].(float64) != 20 {
		t.Fatalf("expected merged nested inner_hits page [from=1,size=1] to have votes=20, got %+v", mcHits)
	}

	// 3. Highlight with require_field_match: true when query targets multi-field "title.raw" and highlight targets "title"
	w = r24Req(t, srv, http.MethodPost, "/r24_search_post/_search", `{
		"query": {"term": {"title.raw": "alpha beta"}},
		"highlight": {
			"require_field_match": true,
			"fields": {"title": {}}
		}
	}`)
	res = r24JSON(t, w)
	hits = res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for title.raw='alpha beta', got %d", len(hits))
	}
	hl, ok := hits[0].(map[string]any)["highlight"].(map[string]any)
	if !ok || len(hl["title"].([]any)) == 0 {
		t.Fatalf("expected highlight on 'title' when querying multi-field 'title.raw', got %+v", hits[0])
	}
}

// R24-P0-6: Painless params isolation, single execution of mutating final expressions, and ternary/list literal parsing.
func TestRound24PainlessParamsIsolationMutatingFinalStmtAndTernaryList(t *testing.T) {
	// 1. Caller params map must not be mutated when script writes to params
	callerParams := map[string]any{"multiplier": 3.0}
	doc := map[string]any{"v": 10.0}
	val, err := painless.Eval(doc, "params.leaked = 99; return doc['v'].value * params.multiplier;", callerParams)
	fv, ok := toFloat64(val)
	if err != nil || !ok || fv != 30.0 {
		t.Fatalf("expected 30.0, got val=%v err=%v", val, err)
	}
	if _, leaked := callerParams["leaked"]; leaked {
		t.Fatalf("expected callerParams to remain unmutated in Eval, got %+v", callerParams)
	}
	if err := painless.EvalPainless(doc, "params.leaked2 = 99; ctx._source.v = 20;", callerParams); err != nil {
		t.Fatalf("unexpected error in EvalPainless: %v", err)
	}
	if _, leaked := callerParams["leaked2"]; leaked {
		t.Fatalf("expected callerParams to remain unmutated in EvalPainless, got %+v", callerParams)
	}

	// 2. Mutating final statement (without explicit return) must execute only once in Eval
	srcDoc := map[string]any{"tags": []any{"a", "b", "c"}}
	removed, err := painless.Eval(srcDoc, "ctx._source.tags.remove(0)", nil)
	if err != nil || removed != "a" {
		t.Fatalf("expected removed='a', got val=%v err=%v", removed, err)
	}
	tags := srcDoc["tags"].([]any)
	if len(tags) != 2 || tags[0] != "b" || tags[1] != "c" {
		t.Fatalf("expected tags=['b','c'] after single remove(0), got %+v", tags)
	}

	// 3. List literal with ternary first element and ternary with Elvis operator
	listVal, err := painless.Eval(map[string]any{}, "return [true ? 'yes' : 'no', 'second'];", nil)
	if err != nil {
		t.Fatalf("unexpected error evaluating list literal with ternary: %v", err)
	}
	listSlice, ok := listVal.([]any)
	if !ok || len(listSlice) != 2 || listSlice[0] != "yes" || listSlice[1] != "second" {
		t.Fatalf("expected ['yes', 'second'], got %#v", listVal)
	}

	elvisVal, err := painless.Eval(map[string]any{}, "def x = null; return true ? (x ?: 'fallback') : 'other';", nil)
	if err != nil || elvisVal != "fallback" {
		t.Fatalf("expected 'fallback' from ternary+elvis, got val=%v err=%v", elvisVal, err)
	}
}

// R24-P0-7: Write-path _update_by_query & _reindex pipeline _index rerouting, alias filter enforcement, and ingest foreach/on_failure metadata.
func TestRound24UpdateByQueryAndReindexPipelineReroutingAndIngestOnFailure(t *testing.T) {
	srv, _ := newTestServer()

	// Create source and destination indices plus a filtered alias on dest
	r24Req(t, srv, http.MethodPut, "/r24_src", `{"mappings":{"properties":{"status":{"type":"keyword"},"val":{"type":"integer"}}}}`)
	r24Req(t, srv, http.MethodPut, "/r24_dst", `{
		"aliases": {
			"r24_dst_active_only": {
				"filter": {"term": {"status": "active"}}
			}
		},
		"mappings":{"properties":{"status":{"type":"keyword"},"val":{"type":"integer"}}}
	}`)

	// Create pipeline that reroutes _index to params or fixed target
	r24Req(t, srv, http.MethodPut, "/_ingest/pipeline/reroute_to_dst", `{
		"processors": [
			{"set": {"field": "_index", "value": "r24_dst_active_only"}}
		]
	}`)

	r24Req(t, srv, http.MethodPost, "/r24_src/_doc/1?refresh=true", `{"status":"active","val":42}`)

	// 1. _update_by_query with pipeline=reroute_to_dst moves doc 1 from r24_src to r24_dst (via alias r24_dst_active_only)
	w := r24Req(t, srv, http.MethodPost, "/r24_src/_update_by_query?pipeline=reroute_to_dst&refresh=true", `{
		"query": {"term": {"status": "active"}}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on _update_by_query with pipeline reroute, got %d: %s", w.Code, w.Body.String())
	}
	// Verify doc 1 is gone from r24_src and present in r24_dst
	wSrc := r24Req(t, srv, http.MethodGet, "/r24_src/_doc/1", nil)
	if wSrc.Code != http.StatusNotFound {
		t.Fatalf("expected doc 1 to be tombstoned in r24_src after pipeline _index reroute, got %d: %s", wSrc.Code, wSrc.Body.String())
	}
	wDst := r24Req(t, srv, http.MethodGet, "/r24_dst/_doc/1", nil)
	if wDst.Code != http.StatusOK {
		t.Fatalf("expected doc 1 to exist in r24_dst after pipeline _index reroute, got %d: %s", wDst.Code, wDst.Body.String())
	}

	// 2. _reindex with pipeline rerouting to filtered alias must reject doc that violates alias filter
	r24Req(t, srv, http.MethodPost, "/r24_src/_doc/2?refresh=true", `{"status":"inactive","val":99}`)
	wReindex := r24Req(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "r24_src"},
		"dest":   {"index": "r24_src", "pipeline": "reroute_to_dst"}
	}`)
	if wReindex.Code == http.StatusOK {
		resReindex := r24JSON(t, wReindex)
		failures, _ := resReindex["failures"].([]any)
		if len(failures) == 0 {
			t.Fatalf("expected _reindex into filtered alias via pipeline reroute to fail for status=inactive, got %+v", resReindex)
		}
	}

	// 3. Nested on_failure blocks preserving outer on_failure_message / on_failure_processor_type
	wSim := r24Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"convert": {
						"field": "bad_int",
						"type": "integer",
						"on_failure": [
							{
								"convert": {
									"field": "bad_float",
									"type": "float",
									"on_failure": [
										{
											"set": {
												"field": "inner_err_field",
												"value": "{{_ingest.on_failure_processor_tag}}"
											}
										}
									],
									"tag": "inner_tag"
								}
							},
							{
								"set": {
									"field": "outer_err_tag",
									"value": "{{_ingest.on_failure_processor_tag}}"
								}
							}
						],
						"tag": "outer_tag"
					}
				}
			]
		},
		"docs": [
			{"_source": {"bad_int": "not_int", "bad_float": "not_float"}}
		]
	}`)
	resSim := r24JSON(t, wSim)
	simDoc := resSim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if simDoc["inner_err_field"] != "inner_tag" || simDoc["outer_err_tag"] != "outer_tag" {
		t.Fatalf("expected inner_err_field='inner_tag' and outer_err_tag='outer_tag', got %+v", simDoc)
	}
}
