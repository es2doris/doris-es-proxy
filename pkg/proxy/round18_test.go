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
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound18_ScalarToArrayPromotionAndIntermediateArrayOfObjects(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Index a document with scalar fields and an object path
	doJSON(t, srv, http.MethodPut, "/r18_promo", `{
		"mappings": {
			"properties": {
				"tags": {"type": "keyword"},
				"role": {"type": "keyword"},
				"item": {
					"properties": {
						"name": {"type": "keyword"}
					}
				}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPut, "/r18_promo/_doc/1?refresh=true", `{
		"tags": "alpha",
		"role": "reader",
		"item": {"name": "widget-1"}
	}`)

	// 2. _update upgrades `tags` from scalar "alpha" to array ["alpha", "beta"]
	doJSON(t, srv, http.MethodPost, "/r18_promo/_update/1?refresh=true", `{
		"doc": {
			"tags": ["alpha", "beta"]
		}
	}`)
	res1 := doJSON(t, srv, http.MethodPost, "/r18_promo/_search", `{
		"query": {"term": {"tags": "beta"}}
	}`)
	hits1 := res1["hits"].(map[string]any)["hits"].([]any)
	if len(hits1) != 1 {
		t.Fatalf("expected _update to promote scalar 'tags' to array so 'beta' is searchable, got %d hits", len(hits1))
	}

	// 3. _update_by_query upgrades `role` from scalar "reader" to array ["reader", "admin"]
	doJSON(t, srv, http.MethodPost, "/r18_promo/_update_by_query?refresh=true", `{
		"query": {"match_all": {}},
		"script": {
			"source": "ctx._source.role = ['reader', 'admin']"
		}
	}`)
	res2 := doJSON(t, srv, http.MethodPost, "/r18_promo/_search", `{
		"query": {"term": {"role": "admin"}}
	}`)
	hits2 := res2["hits"].(map[string]any)["hits"].([]any)
	if len(hits2) != 1 {
		t.Fatalf("expected _update_by_query to promote scalar 'role' to array so 'admin' is searchable, got %d hits", len(hits2))
	}

	// 4. Intermediate array of objects (`{"item": [{"name": "w-a"}, {"name": "w-b"}]}`) via _bulk
	doJSON(t, srv, http.MethodPost, "/r18_promo/_bulk?refresh=true",
		`{"index":{"_id":"2"}}`+"\n"+`{"item":[{"name":"w-a"},{"name":"w-b"}]}`+"\n")
	res3 := doJSON(t, srv, http.MethodPost, "/r18_promo/_search", `{
		"query": {"term": {"item.name": "w-b"}}
	}`)
	hits3 := res3["hits"].(map[string]any)["hits"].([]any)
	if len(hits3) != 1 {
		t.Fatalf("expected intermediate array-of-objects on item.name to promote and match 'w-b', got %d hits", len(hits3))
	}
}

func TestRound18_DateNanosBoundsDateMathAndPlusZeroOffset(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)

	// 1. ParseESDateBoundToEpochMillis with integer nanosecond anchor before || date math
	msMath, ok := schema.ParseESDateBoundToEpochMillis("1700000000000000000||+1d", now, false)
	if !ok || msMath != 1700000000000+86400000 {
		t.Fatalf("expected nanosecond anchor before ||+1d to normalize to %d, got %d (ok=%v)", 1700000000000+86400000, msMath, ok)
	}

	// 2. ISO-8601 with fractional micro/nanoseconds and no-colon offset (+0000)
	msISO, ok := schema.ParseESDateToEpochMillis("2026-01-02T03:04:05.123456+0000", now)
	wantISO := time.Date(2026, 1, 2, 3, 4, 5, 123000000, time.UTC).UnixMilli()
	if !ok || msISO != wantISO {
		t.Fatalf("expected ISO +0000 microsecond date to parse to %d, got %d (ok=%v)", wantISO, msISO, ok)
	}

	// 3. Transpiler date_nanos range agg bounds, date_histogram missing, and sort missing
	var mSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"ts_ns":{"type":"date_nanos"}}}`), &mSpec)
	idxSchema := schema.CompileIndexSchema("es_compat", "r18_nanos", &mSpec)
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})

	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"sort": [
			{"ts_ns": {"order": "asc", "missing": "1700000000000000000"}}
		],
		"search_after": ["1700000000000000000"],
		"aggs": {
			"dh": {
				"date_histogram": {
					"field": "ts_ns",
					"fixed_interval": "1h",
					"missing": "1700000000000000000"
				}
			},
			"dr": {
				"date_range": {
					"field": "ts_ns",
					"ranges": [
						{"from": "1700000000000000000", "to": "1700003600000000000"}
					]
				}
			}
		}
	}`), &req); err != nil {
		t.Fatal(err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan.HitsSQL, "1700000000000000000") || !strings.Contains(plan.HitsSQL, "1700000000000") {
		t.Fatalf("expected HitsSQL to normalize nanosecond sort missing & search_after to epoch millis, got:\n%s", plan.HitsSQL)
	}
	if !strings.Contains(plan.AggsSQL, "COALESCE(`f__ts_ns`, 1700000000000)") ||
		!strings.Contains(plan.AggsSQL, "`f__ts_ns` >= 1700000000000 AND `f__ts_ns` < 1700003600000") {
		t.Fatalf("expected AggsSQL to normalize nanosecond date_histogram missing & date_range bounds to epoch millis, got:\n%s", plan.AggsSQL)
	}
}

func TestRound18_PolymorphicScriptsBucketScriptsArrayScriptsAndMissing(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r18_aggs", `{
		"mappings": {
			"properties": {
				"serviceType": {"type": "keyword"},
				"price": {"type": "double"},
				"scores": {"type": "double", "multi_valued": true}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r18_aggs/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"serviceType":"web","price":10,"scores":[10,20]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"serviceType":"db","price":20,"scores":[30]}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"serviceType":"web"}`+"\n")

	res := doJSON(t, srv, http.MethodPost, "/r18_aggs/_search", `{
		"size": 0,
		"aggs": {
			"card_svc": {
				"cardinality": {
					"script": "doc['serviceType'].value"
				}
			},
			"vc_svc": {
				"value_count": {
					"script": "doc['serviceType'].value"
				}
			},
			"sum_missing_script": {
				"sum": {
					"field": "price",
					"missing": 5,
					"script": "_value * 2"
				}
			},
			"sum_array_script": {
				"sum": {
					"field": "scores",
					"script": "_value * 2"
				}
			},
			"hist_script": {
				"histogram": {
					"script": "doc['price'].value * 2",
					"interval": 20
				}
			},
			"range_script": {
				"range": {
					"script": "doc['price'].value * 2",
					"ranges": [
						{"key": "low", "to": 30},
						{"key": "high", "from": 30}
					]
				}
			},
			"rt_hist_script": {
				"histogram": {
					"script": "def p = doc['price'].value; return p * 2;",
					"interval": 20
				},
				"aggs": {
					"sub_sum": {"sum": {"script": "def p = doc['price'].value; return p;"}}
				}
			},
			"rt_dh_script": {
				"date_histogram": {
					"script": "def p = doc['price'].value; return p * 3600000;",
					"fixed_interval": "10h"
				},
				"aggs": {
					"sub_cnt": {"value_count": {"script": "def s = doc['serviceType'].value; return s;"}}
				}
			},
			"rt_range_script": {
				"range": {
					"script": "def p = doc['price'].value; return p * 2;",
					"ranges": [
						{"key": "low", "to": 30},
						{"key": "high", "from": 30}
					]
				},
				"aggs": {
					"sub_max": {"max": {"script": "def p = doc['price'].value; return p;"}}
				}
			}
		}
	}`)
	aggs := res["aggregations"].(map[string]any)
	if aggs["card_svc"].(map[string]any)["value"] != float64(2) {
		t.Fatalf("expected card_svc=2 on string script doc['serviceType'].value, got %v", aggs["card_svc"])
	}
	if aggs["vc_svc"].(map[string]any)["value"] != float64(3) {
		t.Fatalf("expected vc_svc=3 on string script doc['serviceType'].value, got %v", aggs["vc_svc"])
	}
	// sum_missing_script: (10*2) + (20*2) + (5*2) = 70
	if aggs["sum_missing_script"].(map[string]any)["value"] != float64(70) {
		t.Fatalf("expected sum_missing_script=70 (missing substituted before _value*2), got %v", aggs["sum_missing_script"])
	}
	// sum_array_script: (10*2 + 20*2) + (30*2) = 120
	if aggs["sum_array_script"].(map[string]any)["value"] != float64(120) {
		t.Fatalf("expected sum_array_script=120 across all array elements, got %v", aggs["sum_array_script"])
	}
	hBuckets := aggs["hist_script"].(map[string]any)["buckets"].([]any)
	if len(hBuckets) != 2 {
		t.Fatalf("expected 2 histogram buckets from script, got %v", hBuckets)
	}
	rBuckets := aggs["range_script"].(map[string]any)["buckets"].([]any)
	if len(rBuckets) != 2 || rBuckets[0].(map[string]any)["doc_count"] != float64(1) || rBuckets[1].(map[string]any)["doc_count"] != float64(1) {
		t.Fatalf("expected 1 doc in each range_script bucket, got %v", rBuckets)
	}
	if len(aggs["rt_hist_script"].(map[string]any)["buckets"].([]any)) != 2 ||
		len(aggs["rt_dh_script"].(map[string]any)["buckets"].([]any)) != 2 ||
		len(aggs["rt_range_script"].(map[string]any)["buckets"].([]any)) != 2 {
		t.Fatalf("expected 2 buckets in each runtime script bucket agg, got hist=%v dh=%v range=%v",
			aggs["rt_hist_script"], aggs["rt_dh_script"], aggs["rt_range_script"])
	}
}

func TestRound18_Doris4SearchLuceneOperatorsWildcardFieldsAndSort(t *testing.T) {
	// 1. Doris 4 SEARCH() parenthesized groups & lowercase normalizer exclusion
	var mSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"title": {"type": "text"},
			"body": {"type": "text"},
			"status": {"type": "keyword"},
			"norm_kw": {"type": "keyword", "normalizer": "lowercase"},
			"code": {"type": "keyword"},
			"scores": {"type": "double", "multi_valued": true}
		}
	}`), &mSpec)
	idxSchema := schema.CompileIndexSchema("es_compat", "r18_d4", &mSpec)
	trD4 := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{UseDoris4SearchFunc: true})

	var req1 esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"query": "(title:orders OR body:urgent) AND status:open"
			}
		}
	}`), &req1)
	plan1, err := trD4.BuildSearchPlan(&req1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan1.HitsSQL, "SEARCH('(f__title:orders OR f__body:urgent)") {
		t.Fatalf("expected Doris 4 SEARCH() to rewrite fields inside parenthesized group, got:\n%s", plan1.HitsSQL)
	}

	var reqNorm esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"query": "norm_kw:Admin"
			}
		}
	}`), &reqNorm)
	planNorm, err := trD4.BuildSearchPlan(&reqNorm)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(planNorm.HitsSQL, "SEARCH(") {
		t.Fatalf("expected LowercaseNormalizer field to avoid Doris 4 SEARCH() and use lowercased equality, got:\n%s", planNorm.HitsSQL)
	}

	// 2. Numeric term on VARCHAR column is quoted, match on LowercaseNormalizer lowercases query,
	//    and _script sort + numeric array sort (array_min / array_max) push down to SQL
	var req2 esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"term": {"code": 12345}},
					{"match": {"norm_kw": "HeLLo"}},
					{"query_string": {"query": "title*:(alpha && !beta) || title*:[a TO z]"}}
				]
			}
		},
		"sort": [
			{"scores": {"order": "asc", "mode": "min"}},
			{"_script": {"type": "number", "order": "desc", "script": {"source": "doc['scores'].value * 2"}}}
		]
	}`), &req2)
	plan2, err := trD4.BuildSearchPlan(&req2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan2.HitsSQL, "`f__code` = '12345'") {
		t.Fatalf("expected numeric term on keyword column to be quoted as '12345', got:\n%s", plan2.HitsSQL)
	}
	if !strings.Contains(plan2.HitsSQL, "'hello'") {
		t.Fatalf("expected match on LowercaseNormalizer keyword to lowercase 'HeLLo' to 'hello', got:\n%s", plan2.HitsSQL)
	}
	if !strings.Contains(plan2.HitsSQL, "array_min(array_map(_x -> CAST(_x AS DOUBLE), `f__scores`)) ASC") {
		t.Fatalf("expected array_min on numeric array to map elements to DOUBLE, got:\n%s", plan2.HitsSQL)
	}
}

func TestRound18_RuntimeScriptAggsMultiIndexGlobalNestedAndPartitioning(t *testing.T) {
	srv, _ := newTestServer()

	mapping := `{
		"mappings": {
			"properties": {
				"dept": {"type": "keyword"},
				"val": {"type": "double"},
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"},
						"cost": {"type": "double"}
					}
				}
			}
		}
	}`
	doJSON(t, srv, http.MethodPut, "/r18_mi_1", mapping)
	doJSON(t, srv, http.MethodPut, "/r18_mi_2", mapping)

	doJSON(t, srv, http.MethodPost, "/r18_mi_1/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"dept":"eng","val":10,"items":[{"sku":"A","cost":5},{"sku":"B","cost":15}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"dept":"sales","val":20,"items":[{"sku":"C","cost":25}]}`+"\n")

	// r18_mi_2 is intentionally left empty for 'eng' to test empty-index exclusion and multi-index extended_stats
	doJSON(t, srv, http.MethodPost, "/r18_mi_2/_bulk?refresh=true",
		`{"index":{"_id":"3"}}`+"\n"+`{"dept":"sales","val":30,"items":[{"sku":"D","cost":35}]}`+"\n")

	res := doJSON(t, srv, http.MethodPost, "/r18_mi_1,r18_mi_2/_search", `{
		"size": 0,
		"query": {
			"bool": {
				"filter": [
					{"term": {"dept": "eng"}},
					{"script": {"script": "doc['val'].value > 0"}}
				]
			}
		},
		"aggs": {
			"ext_val": {
				"extended_stats": {
					"script": "doc['val'].value"
				}
			},
			"pct_val": {
				"percentiles": {
					"script": "doc['val'].value",
					"percents": [50]
				}
			},
			"all_docs": {
				"global": {},
				"aggs": {
					"total_val": {
						"sum": {
							"script": "def v = doc['val'].value; return v;"
						}
					}
				}
			},
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"high_cost": {
						"filter": {"range": {"items.cost": {"gte": 10}}},
						"aggs": {
							"back_to_root": {
								"reverse_nested": {},
								"aggs": {
									"root_val_sum": {
										"sum": {"script": "def v = doc['val'].value; return v;"}
									}
								}
							}
						}
					}
				}
			}
		}
	}`)

	aggs := res["aggregations"].(map[string]any)
	extVal := aggs["ext_val"].(map[string]any)
	// Single matching doc has val=10 -> sum_of_squares must be 100 (NOT doubled to 200)
	if extVal["sum_of_squares"] != float64(100) {
		t.Fatalf("expected multi-index runtime extended_stats sum_of_squares=100, got %v", extVal)
	}
	pctValues := aggs["pct_val"].(map[string]any)["values"].(map[string]any)
	// r18_mi_2 had 0 matching docs; p50 must be 10 (not diluted by 0 from empty index)
	if pctValues["50.0"] != float64(10) {
		t.Fatalf("expected multi-index runtime p50=10 without empty-index dilution, got %v", pctValues)
	}
	// global agg with runtime script sub-agg must sum across all 3 docs (10 + 20 + 30 = 60), not just 'eng'
	globalTotal := aggs["all_docs"].(map[string]any)["total_val"].(map[string]any)["value"]
	if globalTotal != float64(60) {
		t.Fatalf("expected global runtime script sum=60 across all docs, got %v", globalTotal)
	}
	// nested -> filter -> reverse_nested -> root_val_sum must restore root doc (val=10)
	rnObj := aggs["nested_items"].(map[string]any)["high_cost"].(map[string]any)["back_to_root"].(map[string]any)
	if rnObj["doc_count"] != float64(1) || rnObj["root_val_sum"].(map[string]any)["value"] != float64(10) {
		t.Fatalf("expected reverse_nested doc_count=1 and root_val_sum=10, got %v", rnObj)
	}
}

func TestRound18_RuntimeFunctionScoreBoolBoostAndCollapseInnerHits(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r18_score", `{
		"mappings": {
			"properties": {
				"group": {"type": "keyword"},
				"tag": {"type": "keyword"},
				"x": {"type": "double"}
			}
		},
		"aliases": {
			"r18_score_alias": {
				"filter": {
					"script": {
						"script": "def v = doc['x'].value; return v > -1.0;"
					}
				}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r18_score/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"group":"g1","tag":"match","x":-0.5}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"group":"g1","tag":"match","x":-2.0}`+"\n")

	// 1. field_value_factor with log1p on x = -0.5 -> log10(-0.5 + 1) = log10(0.5) != 0,
	//    top-level weight = 2.0 multiplying the function score, and bool.boost = 1.5
	res := doJSON(t, srv, http.MethodPost, "/r18_score_alias/_search", `{
		"query": {
			"bool": {
				"boost": 1.5,
				"must": [
					{
						"function_score": {
							"query": {"term": {"tag": "match"}},
							"field_value_factor": {
								"field": "x",
								"modifier": "log1p"
							},
							"weight": 2.0,
							"boost_mode": "replace"
						}
					}
				],
				"filter": [
					{
						"script": {
							"script": "def v = doc['x'].value; return v < 0;"
						}
					}
				]
			}
		},
		"collapse": {
			"field": "group",
			"inner_hits": {
				"name": "group_docs",
				"size": 10
			}
		}
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit through alias script filter, got %d", len(hits))
	}
	hit0 := hits[0].(map[string]any)
	wantScore := 1.5 * 2.0 * math.Log10(0.5)
	gotScore, _ := hit0["_score"].(float64)
	if math.Abs(gotScore-wantScore) > 1e-4 {
		t.Fatalf("expected score=%v (2.0 * log10(1 + -0.5)), got %v", wantScore, gotScore)
	}
	// Collapse inner_hits must also enforce the alias runtime script filter (excluding doc 2 where x=-2.0)
	innerHits := hit0["inner_hits"].(map[string]any)["group_docs"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(innerHits) != 1 || innerHits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected collapse inner_hits to enforce alias runtime script filter and return only doc 1, got %v", innerHits)
	}
}

func TestRound18_PainlessEdgeCasesAndUpdateDetectNoopSource(t *testing.T) {
	// 1. Painless:
	//    - bracket keys with operators ('a+b', 'x*y', 'k=v')
	//    - for loop with colon inside string literal
	//    - multiple .get(...) on the same line
	//    - '/a/b/c'.split('/') and .replaceAll('/v1/', '/v2/')
	//    - cast after binary operator: 10 + (int) -5
	//    - list literal indexing: ['x', 'y'][1]
	rawIn := json.RawMessage(`{"a+b":10,"path":"/v1/users","map1":{"k":3},"map2":{"m":4}}`)
	script := `
		ctx._source['a+b'] += 5;
		ctx._source['x*y'] = 10 + (int) -5;
		ctx._source.sum_gets = ctx._source.map1.get('k') + ctx._source.map2.get('m');
		ctx._source.picked = ['first', 'second'][1];
		ctx._source.replaced = ctx._source.path.replaceAll('/v1/', '/v2/');
		def parts = '/a/b'.split('/');
		ctx._source.split_len = parts.length;
		def acc = '';
		for (String s : ['http://a:80', 'http://b:90']) {
			acc = acc + s + ';';
		}
		ctx._source.urls = acc;
	`
	rawOut, err := painless.ApplyUpdate(rawIn, &painless.UpdateRequest{
		Script: &painless.ScriptSpec{Source: script},
	})
	if err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(rawOut, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["a+b"] != float64(15) || doc["x*y"] != float64(5) {
		t.Fatalf("expected a+b=15 and x*y=5, got a+b=%v x*y=%v", doc["a+b"], doc["x*y"])
	}
	if doc["sum_gets"] != float64(7) {
		t.Fatalf("expected sum_gets=7 from two .get() calls on same line, got %v", doc["sum_gets"])
	}
	if doc["picked"] != "second" {
		t.Fatalf("expected ['first','second'][1]=='second', got %v", doc["picked"])
	}
	if doc["replaced"] != "/v2/users" {
		t.Fatalf("expected replaceAll('/v1/','/v2/')=='/v2/users', got %v", doc["replaced"])
	}
	if doc["urls"] != "http://a:80;http://b:90;" {
		t.Fatalf("expected for loop with colons in string literals to succeed, got %v", doc["urls"])
	}

	// 2. _update and _bulk update with detect_noop: false, _source retrieval, and noop version preservation
	srv, _ := newTestServer()
	doJSON(t, srv, http.MethodPut, "/r18_upd/_doc/1?refresh=true", `{"status":"open","count":1}`)

	// First update mutates count -> 2 (version becomes > 1)
	upd1 := doJSON(t, srv, http.MethodPost, "/r18_upd/_update/1?refresh=true&_source=true", `{
		"doc": {"count": 2}
	}`)
	verAfterUpd1 := upd1["_version"]
	getObj1, _ := upd1["get"].(map[string]any)
	if getObj1 == nil || getObj1["_source"].(map[string]any)["count"] != float64(2) {
		t.Fatalf("expected _update?_source=true to return get._source, got %+v", upd1)
	}

	// Noop update with default detect_noop (true) preserves version and returns result: "noop"
	updNoop := doJSON(t, srv, http.MethodPost, "/r18_upd/_update/1?refresh=true", `{
		"doc": {"count": 2},
		"_source": ["status"]
	}`)
	if updNoop["result"] != "noop" || updNoop["_version"] != verAfterUpd1 {
		t.Fatalf("expected noop update to preserve _version=%v, got %+v", verAfterUpd1, updNoop)
	}
	if updNoop["get"].(map[string]any)["_source"].(map[string]any)["status"] != "open" {
		t.Fatalf("expected body _source filter on _update to return filtered get._source, got %+v", updNoop)
	}

	// Same update with detect_noop: false forces result: "updated" and increments version
	updForce := doJSON(t, srv, http.MethodPost, "/r18_upd/_update/1?refresh=true", `{
		"doc": {"count": 2},
		"detect_noop": false
	}`)
	if updForce["result"] != "updated" || updForce["_version"] == verAfterUpd1 {
		t.Fatalf("expected detect_noop:false to force result='updated' and increment _version, got %+v", updForce)
	}
}

func TestRound18_RuntimeSubAggsAndParentBucketPartitioning(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r18_part", `{
		"mappings": {
			"properties": {
				"cat": {"type": "keyword"},
				"price": {"type": "double"},
				"ts": {"type": "date"},
				"ip": {"type": "ip"},
				"opt": {"type": "double"},
				"scores": {"type": "double"},
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"},
						"cost": {"type": "double"}
					}
				}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r18_part/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"cat":"a","price":10,"ts":"2026-01-01T00:00:00Z","ip":"10.0.0.5","scores":[10,20],"items":[{"sku":"s1","cost":5}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"cat":"b","price":25,"ts":"2026-01-02T00:00:00Z","ip":"192.168.1.10","opt":5,"scores":[30],"items":[{"sku":"s2","cost":15}]}`+"\n")

	// 1. Runtime parent terms.script with all sub-aggregation types (emitRuntimeAllSubAggRows + filterDocsMatchingRangeEntry + cloneDocWithFieldPath)
	res1 := doJSON(t, srv, http.MethodPost, "/r18_part/_search", `{
		"size": 0,
		"aggs": {
			"rt_parent": {
				"terms": {"script": "String c = doc['cat'].value; return c;"},
				"aggs": {
					"sub_terms": {"terms": {"field": "cat"}},
					"sub_hist": {"histogram": {"field": "price", "interval": 10}},
					"sub_dh": {"date_histogram": {"field": "ts", "fixed_interval": "1d"}},
					"sub_rng": {"range": {"field": "price", "ranges": [{"to": 20}, {"from": 20}]}},
					"sub_drng": {"date_range": {"field": "ts", "ranges": [{"to": "2026-01-01T12:00:00Z"}, {"from": "2026-01-01T12:00:00Z"}]}},
					"sub_ip_cidr": {"ip_range": {"field": "ip", "ranges": [{"mask": "10.0.0.0/24"}, {"from": "192.168.1.1", "to": "192.168.1.255"}]}},
					"sub_flt": {"filter": {"term": {"cat": "a"}}, "aggs": {"c": {"value_count": {"field": "cat"}}}},
					"sub_flts": {
						"filters": {
							"other_bucket": true,
							"filters": {
								"is_a": {"term": {"cat": "a"}}
							}
						},
						"aggs": {"c": {"value_count": {"field": "cat"}}}
					},
					"sub_miss": {"missing": {"field": "opt"}, "aggs": {"c": {"value_count": {"field": "cat"}}}},
					"sub_samp": {"sampler": {"shard_size": 10}, "aggs": {"c": {"value_count": {"field": "cat"}}}},
					"sub_nest": {
						"nested": {"path": "items"},
						"aggs": {
							"rn": {
								"reverse_nested": {},
								"aggs": {"p": {"avg": {"field": "price"}}}
							}
						}
					},
					"sub_miss_script": {
						"avg": {
							"missing": 100,
							"script": "double v = doc['opt'].value; return v * 2;"
						}
					}
				}
			}
		}
	}`)
	rtBuckets := res1["aggregations"].(map[string]any)["rt_parent"].(map[string]any)["buckets"].([]any)
	if len(rtBuckets) != 2 {
		t.Fatalf("expected 2 buckets in rt_parent, got %d", len(rtBuckets))
	}
	b0 := rtBuckets[0].(map[string]any)
	if b0["sub_miss_script"].(map[string]any)["value"] != float64(200) {
		t.Fatalf("expected sub_miss_script on doc missing 'opt' (missing=100) * 2 = 200, got %v", b0["sub_miss_script"])
	}

	// 2. Non-script parent buckets with runtime script child metric (partitionDocsByParentBucket)
	res2 := doJSON(t, srv, http.MethodPost, "/r18_part/_search", `{
		"size": 0,
		"aggs": {
			"p_hist": {
				"histogram": {"field": "price", "interval": 10},
				"aggs": {"rt_avg": {"avg": {"script": "double x = doc['price'].value; return x * 2;"}}}
			},
			"p_dh": {
				"date_histogram": {"field": "ts", "fixed_interval": "1d"},
				"aggs": {"rt_avg": {"avg": {"script": "double x = doc['price'].value; return x * 2;"}}}
			},
			"p_rng": {
				"range": {"field": "price", "ranges": [{"key": "low", "to": 20}, {"key": "high", "from": 20}]},
				"aggs": {"rt_avg": {"avg": {"script": "double x = doc['price'].value; return x * 2;"}}}
			},
			"p_drng": {
				"date_range": {"field": "ts", "ranges": [{"key": "d1", "to": "2026-01-01T12:00:00Z"}, {"key": "d2", "from": "2026-01-01T12:00:00Z"}]},
				"aggs": {"rt_avg": {"avg": {"script": "double x = doc['price'].value; return x * 2;"}}}
			},
			"p_ip": {
				"ip_range": {"field": "ip", "ranges": [{"key": "cidr", "mask": "10.0.0.0/24"}, {"key": "lan", "from": "192.168.1.1", "to": "192.168.1.255"}]},
				"aggs": {"rt_avg": {"avg": {"script": "double x = doc['price'].value; return x * 2;"}}}
			},
			"p_comp": {
				"composite": {
					"sources": [
						{"c": {"terms": {"field": "cat"}}},
						{"h": {"histogram": {"field": "price", "interval": 10}}},
						{"d": {"date_histogram": {"field": "ts", "fixed_interval": "1d"}}}
					]
				},
				"aggs": {"rt_avg": {"avg": {"script": "double x = doc['price'].value; return x * 2;"}}}
			},
			"p_flts": {
				"filters": {
					"other_bucket": true,
					"filters": {"is_a": {"term": {"cat": "a"}}}
				},
				"aggs": {"rt_avg": {"avg": {"script": "double x = doc['price'].value; return x * 2;"}}}
			},
			"p_miss": {
				"missing": {"field": "opt"},
				"aggs": {"rt_avg": {"avg": {"script": "double x = doc['price'].value; return x * 2;"}}}
			},
			"p_samp": {
				"sampler": {"shard_size": 10},
				"aggs": {"rt_avg": {"avg": {"script": "double x = doc['price'].value; return x * 2;"}}}
			}
		}
	}`)
	aggs2 := res2["aggregations"].(map[string]any)
	compBuckets := aggs2["p_comp"].(map[string]any)["buckets"].([]any)
	if len(compBuckets) != 2 || compBuckets[0].(map[string]any)["rt_avg"].(map[string]any)["value"] != float64(20) {
		t.Fatalf("expected composite parent bucket with runtime script sub-agg rt_avg=20, got %v", compBuckets)
	}

	// 3. Transpiler sub-agg script + missing SQL generation across scalar & array fields
	var mSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"cat": {"type": "keyword"},
			"price": {"type": "double"},
			"ts": {"type": "date"},
			"scores": {"type": "double", "multi_valued": true}
		}
	}`), &mSpec)
	idxSchema := schema.CompileIndexSchema("es_compat", "r18_part", &mSpec)
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {"field": "cat"},
				"aggs": {
					"pct_arr": {"percentiles": {"field": "scores", "missing": 0, "script": "_value * 2"}},
					"pct_sc": {"percentiles": {"missing": 0, "script": "doc['price'].value * 2"}},
					"bp_arr": {"boxplot": {"field": "scores", "missing": 0, "script": "_value * 2"}},
					"bp_sc": {"boxplot": {"missing": 0, "script": "doc['price'].value * 2"}},
					"pr_arr": {"percentile_ranks": {"field": "scores", "values": [10, 50], "missing": 0, "script": "_value * 2"}},
					"pr_sc": {"percentile_ranks": {"values": [10, 50], "missing": 0, "script": "doc['price'].value * 2"}},
					"vc_arr": {"value_count": {"field": "scores", "missing": 0, "script": "_value + 1"}},
					"vc_sc": {"value_count": {"missing": 0, "script": "doc['price'].value + 1"}},
					"card_arr": {"cardinality": {"field": "scores", "missing": 0, "script": "_value + 1"}},
					"card_sc": {"cardinality": {"missing": 0, "script": "doc['price'].value + 1"}},
					"sub_t_arr": {"terms": {"field": "scores", "missing": 0, "script": "_value * 2"}},
					"sub_t_sc": {"terms": {"missing": "none", "script": "doc['cat'].value + '_x'"}},
					"sub_dh": {"date_histogram": {"missing": "1970-01-01T00:00:00Z", "fixed_interval": "1d", "script": "doc['ts'].value + 1000"}},
					"sub_h_arr": {"histogram": {"field": "scores", "interval": 10, "missing": 0, "script": "_value * 2"}},
					"sub_h_sc": {"histogram": {"interval": 10, "missing": 0, "script": "doc['price'].value * 2"}},
					"sub_r_arr": {"range": {"field": "scores", "script": "_value * 2", "ranges": [{"from": 10, "to": 50}]}},
					"sub_r_sc": {"range": {"missing": 0, "script": "doc['price'].value * 2", "ranges": [{"from": 10, "to": 50}]}}
				}
			}
		}
	}`), &req); err != nil {
		t.Fatal(err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil || plan.AggsSQL == "" {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
}
