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

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound17_MetricAndBucketScriptAggregations(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r17_aggs", `{
		"mappings": {
			"properties": {
				"category": {"type": "keyword"},
				"price": {"type": "double"},
				"qty": {"type": "long"},
				"tags": {"type": "keyword"},
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

	doJSON(t, srv, http.MethodPost, "/r17_aggs/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"category":"books","price":10,"qty":2,"tags":["a","b"],"items":[{"sku":"S1","cost":5},{"sku":"S2","cost":15}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"category":"books","price":20,"qty":3,"tags":["a"],"items":[{"sku":"S3","cost":10}]}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"category":"games","qty":5,"tags":["a","b","c"],"items":[{"sku":"S4","cost":20}]}`+"\n")

	// 1. Simple SQL-pushed script expressions across metric aggs & nested sub-aggs
	// Note doc 3 has no 'price'; SQL pushdown must keep NULL (not COALESCE(..., 1)) so avg/min/count skip doc 3 unless missing is set.
	resSQL := doJSON(t, srv, http.MethodPost, "/r17_aggs/_search", `{
		"size": 0,
		"aggs": {
			"avg_scaled": {
				"avg": {
					"script": {
						"source": "doc['price'].value * params.factor",
						"params": {"factor": 2}
					}
				}
			},
			"sum_value_var": {
				"sum": {
					"field": "price",
					"script": "_value + 5"
				}
			},
			"min_price_script": {
				"min": {
					"script": "doc['price'].value * 10"
				}
			},
			"val_cnt_script": {
				"value_count": {
					"script": "doc['price'].value"
				}
			},
			"by_cat": {
				"terms": {"field": "category"},
				"aggs": {
					"cat_sum_rev": {
						"sum": {
							"script": "doc['price'].value * doc['qty'].value"
						}
					}
				}
			}
		}
	}`)

	aggsSQL := resSQL["aggregations"].(map[string]any)
	// doc 1: 10*2=20, doc 2: 20*2=40, doc 3: NULL -> avg = 30
	if got := aggsSQL["avg_scaled"].(map[string]any)["value"].(float64); got != 30 {
		t.Fatalf("expected avg_scaled=30 (skipping missing doc 3), got %v", got)
	}
	// doc 1: 10+5=15, doc 2: 20+5=25, doc 3: NULL -> sum = 40
	if got := aggsSQL["sum_value_var"].(map[string]any)["value"].(float64); got != 40 {
		t.Fatalf("expected sum_value_var=40, got %v", got)
	}
	// doc 1: 100, doc 2: 200, doc 3: NULL -> min = 100
	if got := aggsSQL["min_price_script"].(map[string]any)["value"].(float64); got != 100 {
		t.Fatalf("expected min_price_script=100, got %v", got)
	}
	if got := aggsSQL["val_cnt_script"].(map[string]any)["value"].(float64); got != 2 {
		t.Fatalf("expected val_cnt_script=2, got %v", got)
	}

	// 2. Runtime Painless multi-statement scripts across metric aggs, filter/filters aggs, and bucket sub-aggs
	resRuntime := doJSON(t, srv, http.MethodPost, "/r17_aggs/_search", `{
		"size": 0,
		"aggs": {
			"complex_avg": {
				"avg": {
					"script": {
						"source": "if (doc['price'].size() == 0) { return null; } double p = doc['price'].value; return p * params.mult;",
						"params": {"mult": 3}
					}
				}
			},
			"complex_stats": {
				"extended_stats": {
					"script": {
						"source": "if (doc['price'].size() == 0) { return null; } double v = doc['price'].value * 2; return v;"
					}
				}
			},
			"complex_pct": {
				"percentiles": {
					"percents": [50],
					"script": {
						"source": "if (doc['price'].size() == 0) { return null; } double v = doc['price'].value * 2; return v;"
					}
				}
			},
			"complex_prank": {
				"percentile_ranks": {
					"values": [25],
					"script": {
						"source": "if (doc['price'].size() == 0) { return null; } double v = doc['price'].value * 2; return v;"
					}
				}
			},
			"complex_box": {
				"boxplot": {
					"script": {
						"source": "if (doc['price'].size() == 0) { return null; } double v = doc['price'].value * 2; return v;"
					}
				}
			},
			"high_qty_filter": {
				"filter": {
					"script": {
						"script": "doc['qty'].value >= 3"
					}
				},
				"aggs": {
					"sum_qty": {"sum": {"field": "qty"}}
				}
			},
			"bucket_filters": {
				"filters": {
					"other_bucket": true,
					"filters": {
						"multi_tag": {"script": {"script": "doc['tags'].size() >= 2"}},
						"expensive": {"script": {"script": "doc['price'].size() > 0 && doc['price'].value >= 20"}}
					}
				},
				"aggs": {
					"max_qty": {
						"max": {
							"script": {
								"source": "long q = doc['qty'].value; return q * 10;"
							}
						}
					}
				}
			},
			"by_cat_runtime": {
				"terms": {"field": "category"},
				"aggs": {
					"cat_card": {
						"cardinality": {
							"script": {
								"source": "String c = doc['category'].value; return c + '-' + doc['qty'].value;"
							}
						}
					}
				}
			}
		}
	}`)

	aggsRT := resRuntime["aggregations"].(map[string]any)
	// doc 1: 30, doc 2: 60 -> avg = 45
	if got := aggsRT["complex_avg"].(map[string]any)["value"].(float64); got != 45 {
		t.Fatalf("expected complex_avg=45, got %v", got)
	}
	statsRT := aggsRT["complex_stats"].(map[string]any)
	// doc 1: 20, doc 2: 40 -> count=2, sum=60, min=20, max=40, avg=30
	if statsRT["count"].(float64) != 2 || statsRT["sum"].(float64) != 60 || statsRT["min"].(float64) != 20 || statsRT["max"].(float64) != 40 {
		t.Fatalf("unexpected complex_stats: %+v", statsRT)
	}
	pctRT := aggsRT["complex_pct"].(map[string]any)["values"].(map[string]any)
	if pctRT["50.0"].(float64) != 30 {
		t.Fatalf("expected complex_pct 50.0=30, got %v", pctRT["50.0"])
	}
	prankRT := aggsRT["complex_prank"].(map[string]any)["values"].(map[string]any)
	if prankRT["25.0"].(float64) != 50 {
		t.Fatalf("expected complex_prank 25.0=50, got %v", prankRT["25.0"])
	}
	boxRT := aggsRT["complex_box"].(map[string]any)
	if boxRT["min"].(float64) != 20 || boxRT["max"].(float64) != 40 || boxRT["q2"].(float64) != 30 {
		t.Fatalf("unexpected complex_box: %+v", boxRT)
	}
	hqFilter := aggsRT["high_qty_filter"].(map[string]any)
	if hqFilter["doc_count"].(float64) != 2 || hqFilter["sum_qty"].(map[string]any)["value"].(float64) != 8 {
		t.Fatalf("unexpected high_qty_filter: %+v", hqFilter)
	}
	bfBuckets := aggsRT["bucket_filters"].(map[string]any)["buckets"].(map[string]any)
	multiTagBucket := bfBuckets["multi_tag"].(map[string]any)
	if multiTagBucket["doc_count"].(float64) != 2 || multiTagBucket["max_qty"].(map[string]any)["value"].(float64) != 50 {
		t.Fatalf("unexpected multi_tag bucket: %+v", multiTagBucket)
	}
	expensiveBucket := bfBuckets["expensive"].(map[string]any)
	if expensiveBucket["doc_count"].(float64) != 1 || expensiveBucket["max_qty"].(map[string]any)["value"].(float64) != 30 {
		t.Fatalf("unexpected expensive bucket: %+v", expensiveBucket)
	}
	catBuckets := aggsRT["by_cat_runtime"].(map[string]any)["buckets"].([]any)
	if len(catBuckets) != 2 {
		t.Fatalf("expected 2 category buckets, got %d", len(catBuckets))
	}
	booksBucket := catBuckets[0].(map[string]any)
	if booksBucket["key"] != "books" || booksBucket["cat_card"].(map[string]any)["value"].(float64) != 2 {
		t.Fatalf("unexpected books bucket: %+v", booksBucket)
	}
}

func TestRound17_TopLevelMinScoreAndExplainParity(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r17_minscore", `{
		"mappings": {
			"properties": {
				"tier": {"type": "keyword"},
				"points": {"type": "double"}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPost, "/r17_minscore/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"tier":"gold","points":100}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"tier":"silver","points":40}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"tier":"bronze","points":10}`+"\n")

	// 1. Top-level min_score on SQL-pushed query restricts hits, total, and aggregations
	resSQL := doJSON(t, srv, http.MethodPost, "/r17_minscore/_search", `{
		"min_score": 2.5,
		"query": {
			"bool": {
				"should": [
					{"term": {"tier": {"value": "gold", "boost": 5.0}}},
					{"term": {"tier": {"value": "silver", "boost": 2.0}}},
					{"term": {"tier": {"value": "bronze", "boost": 1.0}}}
				]
			}
		},
		"aggs": {
			"sum_pts": {"sum": {"field": "points"}}
		}
	}`)
	hitsSQL := resSQL["hits"].(map[string]any)
	if got := hitsSQL["total"].(map[string]any)["value"].(float64); got != 1 {
		t.Fatalf("expected 1 hit with min_score=2.5, got %v", got)
	}
	if got := resSQL["aggregations"].(map[string]any)["sum_pts"].(map[string]any)["value"].(float64); got != 100 {
		t.Fatalf("expected sum_pts=100 for min_score-filtered hits, got %v", got)
	}

	// 2. Top-level min_score on runtime script_score query
	resScript := doJSON(t, srv, http.MethodPost, "/r17_minscore/_search", `{
		"min_score": 50,
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"script": {"source": "doc['points'].value * 1.5"}
			}
		},
		"aggs": {
			"tiers": {"terms": {"field": "tier"}}
		}
	}`)
	// doc 1: 150, doc 2: 60, doc 3: 15 -> 2 hits
	hitsScript := resScript["hits"].(map[string]any)
	if got := hitsScript["total"].(map[string]any)["value"].(float64); got != 2 {
		t.Fatalf("expected 2 hits with runtime min_score=50, got %v", got)
	}
	buckets := resScript["aggregations"].(map[string]any)["tiers"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 agg buckets after runtime min_score=50, got %d", len(buckets))
	}

	// 3. /_explain honors SQL score, runtime script_score, and min_score
	expMatched := doJSON(t, srv, http.MethodPost, "/r17_minscore/_explain/1", `{
		"min_score": 50,
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"script": {"source": "doc['points'].value * 1.5"}
			}
		}
	}`)
	if expMatched["matched"] != true || expMatched["explanation"].(map[string]any)["value"].(float64) != 150 {
		t.Fatalf("expected doc 1 explain matched=true with value=150, got %+v", expMatched)
	}

	expUnmatched := doJSON(t, srv, http.MethodPost, "/r17_minscore/_explain/3", `{
		"min_score": 50,
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"script": {"source": "doc['points'].value * 1.5"}
			}
		}
	}`)
	if expUnmatched["matched"] != false {
		t.Fatalf("expected doc 3 explain matched=false when score < min_score, got %+v", expUnmatched)
	}
}

func TestRound17_RuntimeFunctionScoreFieldValueFactorAndAliasScriptFilter(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r17_fscore", `{
		"mappings": {
			"properties": {
				"tenant": {"type": "keyword"},
				"popularity": {"type": "double"},
				"bonus": {"type": "double"}
			}
		},
		"aliases": {
			"r17_tenant_script_alias": {
				"filter": {
					"script": {
						"script": "doc['popularity'].value >= 9"
					}
				}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPost, "/r17_fscore/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"tenant":"t1","popularity":9,"bonus":5}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"tenant":"t1","popularity":16,"bonus":10}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"tenant":"t2","popularity":4,"bonus":20}`+"\n")

	// 1. Alias with a runtime script filter on /_search and /_count
	cntRes := doJSON(t, srv, http.MethodPost, "/r17_tenant_script_alias/_count", `{}`)
	if cntRes["count"].(float64) != 2 {
		t.Fatalf("expected 2 docs in script-filtered alias count, got %v", cntRes["count"])
	}
	aliasSearch := doJSON(t, srv, http.MethodPost, "/r17_tenant_script_alias/_search", `{
		"aggs": {
			"sum_pop": {"sum": {"field": "popularity"}}
		}
	}`)
	if aliasSearch["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64) != 2 {
		t.Fatalf("expected 2 hits in script-filtered alias search, got %v", aliasSearch["hits"])
	}
	if aliasSearch["aggregations"].(map[string]any)["sum_pop"].(map[string]any)["value"].(float64) != 25 {
		t.Fatalf("expected sum_pop=25 in script-filtered alias search, got %v", aliasSearch["aggregations"])
	}

	// 2. function_score combining field_value_factor (sqrt) + script_score in functions array
	fsRes := doJSON(t, srv, http.MethodPost, "/r17_fscore/_search", `{
		"query": {
			"function_score": {
				"query": {"term": {"tenant": "t1"}},
				"score_mode": "sum",
				"boost_mode": "replace",
				"functions": [
					{
						"field_value_factor": {
							"field": "popularity",
							"factor": 1.0,
							"modifier": "sqrt",
							"missing": 1.0
						}
					},
					{
						"script_score": {
							"script": {"source": "doc['bonus'].value * 2"}
						}
					}
				]
			}
		}
	}`)
	// doc 1: sqrt(9) + 5*2 = 3 + 10 = 13
	// doc 2: sqrt(16) + 10*2 = 4 + 20 = 24
	fsHits := fsRes["hits"].(map[string]any)["hits"].([]any)
	if len(fsHits) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(fsHits))
	}
	if fsHits[0].(map[string]any)["_id"] != "2" || fsHits[0].(map[string]any)["_score"].(float64) != 24 {
		t.Fatalf("expected top hit id=2 score=24, got %+v", fsHits[0])
	}
	if fsHits[1].(map[string]any)["_id"] != "1" || fsHits[1].(map[string]any)["_score"].(float64) != 13 {
		t.Fatalf("expected second hit id=1 score=13, got %+v", fsHits[1])
	}

	// 3. bool.must wrapping script_score with min_score
	nestedMinScore := doJSON(t, srv, http.MethodPost, "/r17_fscore/_search", `{
		"query": {
			"bool": {
				"must": [
					{
						"script_score": {
							"query": {"match_all": {}},
							"script": {"source": "doc['popularity'].value"},
							"min_score": 10
						}
					}
				]
			}
		}
	}`)
	if nestedMinScore["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64) != 1 {
		t.Fatalf("expected 1 hit when nested script_score min_score=10 inside bool.must, got %+v", nestedMinScore["hits"])
	}
}

func TestRound17_SortUnmappedTypeAndScriptSortMissing(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r17_sort", `{
		"mappings": {
			"dynamic": false,
			"properties": {
				"name": {"type": "keyword"},
				"rank": {"type": "long"}
			}
		}
	}`)

	doJSON(t, srv, http.MethodPost, "/r17_sort/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"name":"alpha","rank":10,"dyn_num":100}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"name":"beta","rank":20,"dyn_num":25}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"name":"gamma"}`+"\n")

	// 1. unmapped_type: "long" sorts dynamic variant field numerically (25 before 100, not lexicographically "100" < "25")
	resUnmapped := doJSON(t, srv, http.MethodPost, "/r17_sort/_search", `{
		"sort": [
			{"dyn_num": {"order": "asc", "unmapped_type": "long", "missing": 500}},
			{"_id": {"order": "asc"}}
		]
	}`)
	hitsU := resUnmapped["hits"].(map[string]any)["hits"].([]any)
	if len(hitsU) != 3 || hitsU[0].(map[string]any)["_id"] != "2" || hitsU[1].(map[string]any)["_id"] != "1" || hitsU[2].(map[string]any)["_id"] != "3" {
		t.Fatalf("expected order [2, 1, 3] with unmapped_type=long and missing=500, got %+v", hitsU)
	}

	// Verify search_after with missing tie-breaker on rank
	page1 := doJSON(t, srv, http.MethodPost, "/r17_sort/_search", `{
		"size": 1,
		"sort": [
			{"rank": {"order": "asc", "missing": 5}},
			{"_id": {"order": "asc"}}
		]
	}`)
	p1Hits := page1["hits"].(map[string]any)["hits"].([]any)
	// doc 3 has missing rank -> coalesced to 5, so doc 3 comes first!
	if len(p1Hits) != 1 || p1Hits[0].(map[string]any)["_id"] != "3" {
		t.Fatalf("expected doc 3 first when rank missing=5, got %+v", p1Hits)
	}
	page2 := doJSON(t, srv, http.MethodPost, "/r17_sort/_search", `{
		"size": 2,
		"search_after": [5, "3"],
		"sort": [
			{"rank": {"order": "asc", "missing": 5}},
			{"_id": {"order": "asc"}}
		]
	}`)
	p2Hits := page2["hits"].(map[string]any)["hits"].([]any)
	if len(p2Hits) != 2 || p2Hits[0].(map[string]any)["_id"] != "1" || p2Hits[1].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected [1, 2] after search_after [5, '3'], got %+v", p2Hits)
	}

	// 2. _script sort with missing value fallback when doc['rank'] is missing on doc 3
	resScriptSort := doJSON(t, srv, http.MethodPost, "/r17_sort/_search", `{
		"sort": [
			{
				"_script": {
					"type": "number",
					"order": "asc",
					"missing": 15,
					"script": {
						"source": "doc['rank'].value"
					}
				}
			}
		]
	}`)
	hitsSS := resScriptSort["hits"].(map[string]any)["hits"].([]any)
	// doc 1: 10, doc 3 (missing -> 15), doc 2: 20
	if len(hitsSS) != 3 || hitsSS[0].(map[string]any)["_id"] != "1" || hitsSS[1].(map[string]any)["_id"] != "3" || hitsSS[2].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected _script sort order [1, 3, 2] with missing=15, got %+v", hitsSS)
	}
}

func TestRound17_TranspilerLuceneDateNanosVariantAndNestedKeyword(t *testing.T) {
	rawMapping := []byte(`{
		"dynamic": false,
		"properties": {
			"title": {"type": "text"},
			"count": {"type": "long"},
			"ts_nano": {"type": "date_nanos"},
			"tags": {"type": "keyword", " upgraded_array": true},
			"items": {
				"type": "nested",
				"properties": {
					"name": {
						"type": "text",
						"fields": {
							"keyword": {"type": "keyword"}
						}
					},
					"ns_time": {"type": "date_nanos"}
				}
			}
		}
	}`)
	var spec esast.MappingSpec
	_ = json.Unmarshal(rawMapping, &spec)
	p := spec.Properties["tags"]
	p.MultiValued = true
	p.UpgradedArray = true
	spec.Properties["tags"] = p

	idxSchema := schema.CompileIndexSchema("es_compat", "r17_transpile", &spec)

	// 1. Nested text+keyword companion preserves StorageNestedSubfield and PrefilterArrayCol
	nameB := idxSchema.ResolveField("items.name")
	kwB := idxSchema.ResolveField("items.name.keyword")
	if nameB.KeywordCompanion == "" || nameB.KeywordCompanion != kwB.PrefilterArrayCol {
		t.Fatalf("expected items.name KeywordCompanion=%q to equal items.name.keyword PrefilterArrayCol=%q", nameB.KeywordCompanion, kwB.PrefilterArrayCol)
	}
	if kwB.Kind != schema.StorageNestedSubfield || kwB.PrefilterArrayCol == "" {
		t.Fatalf("expected items.name.keyword to remain StorageNestedSubfield with PrefilterArrayCol, got %+v", kwB)
	}

	// 2. Doris 4 SEARCH() rewrites promoted string field to Doris column and falls back on numeric field
	trDoris4 := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{UseDoris4SearchFunc: true})
	planStr, err := trDoris4.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{QueryString: &esast.QueryStringQuery{Query: "title:laptop"}},
	})
	if err != nil || !strings.Contains(planStr.HitsSQL, "SEARCH('f__title:laptop'") {
		t.Fatalf("expected Doris 4 SEARCH() to rewrite title:laptop -> f__title:laptop, got: %s", planStr.HitsSQL)
	}
	planNum, err := trDoris4.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{QueryString: &esast.QueryStringQuery{Query: "count:42"}},
	})
	if err != nil || strings.Contains(planNum.HitsSQL, "SEARCH(") || !strings.Contains(planNum.HitsSQL, "`f__count` = 42") {
		t.Fatalf("expected Doris 4 SEARCH() to fall back to AST on numeric field count:42, got: %s", planNum.HitsSQL)
	}

	// 3. Lucene default_operator="OR" with mixed implicit OR and explicit AND, plus nested parentheses
	trStd := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	var reqLucene esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"default_field": "title",
				"default_operator": "OR",
				"query": "alpha beta AND (gamma delta)"
			}
		}
	}`), &reqLucene)
	planLucene, err := trStd.BuildSearchPlan(&reqLucene)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	// alpha OR (beta AND (gamma OR delta))
	if !strings.Contains(planLucene.HitsSQL, "OR") || !strings.Contains(planLucene.HitsSQL, "AND") {
		t.Fatalf("expected both OR and AND in mixed Lucene query, got: %s", planLucene.HitsSQL)
	}

	// 4. date_nanos normalization in term, terms, range, nested prefilter, and sort/search_after
	var reqNano esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"term": {"ts_nano": 1700000000123456789}},
					{"terms": {"ts_nano": [1700000000123456789, "1700000000999000000"]}},
					{"range": {"ts_nano": {"gte": 1700000000000000000}}},
					{
						"nested": {
							"path": "items",
							"query": {
								"term": {"items.ns_time": 1700000002500000000}
							}
						}
					}
				]
			}
		},
		"sort": [{"ts_nano": {"order": "asc", "missing": 1700000003000000000}}],
		"search_after": [1700000000123456789]
	}`), &reqNano)
	planNano, err := trStd.BuildSearchPlan(&reqNano)
	if err != nil {
		t.Fatalf("date_nanos BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(planNano.HitsSQL, "1700000000123") || !strings.Contains(planNano.HitsSQL, "1700000000999") || !strings.Contains(planNano.HitsSQL, "1700000002500") || !strings.Contains(planNano.HitsSQL, "1700000003000") {
		t.Fatalf("expected date_nanos values normalized to epoch ms in HitsSQL, got: %s", planNano.HitsSQL)
	}

	// 5. Dynamic variant regexp uses REGEXP (not MATCH_REGEXP) and match on promoted array uses ARRAY_CONTAINS/LIKE
	var reqVarArr esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"regexp": {"unmapped_str": "err.*"}},
					{"match": {"tags": "urgent"}}
				]
			}
		}
	}`), &reqVarArr)
	planVarArr, err := trStd.BuildSearchPlan(&reqVarArr)
	if err != nil {
		t.Fatalf("variant/array BuildSearchPlan failed: %v", err)
	}
	if strings.Contains(planVarArr.HitsSQL, "MATCH_REGEXP") || !strings.Contains(planVarArr.HitsSQL, "REGEXP") {
		t.Fatalf("expected REGEXP instead of MATCH_REGEXP on dynamic variant, got: %s", planVarArr.HitsSQL)
	}
	if strings.Contains(planVarArr.HitsSQL, "`f__tags` MATCH_") || !strings.Contains(planVarArr.HitsSQL, "array_exists") {
		t.Fatalf("expected array_exists instead of MATCH_ANY on promoted array column, got: %s", planVarArr.HitsSQL)
	}
}

func TestRound17_PainlessEngineHardening(t *testing.T) {
	doc := map[string]any{
		"path": "a/b/c",
		"csv":  "x,y;z",
		"pipe": "p1|p2|p3",
		"text": "abracadabra",
	}

	// 1. Regex literals in .replaceAll(/.../, ...) and .split(/.../, limit) + 2-arg .split("|", limit)
	scriptRegex := `
		ctx._source.clean_path = ctx._source.path.replaceAll(/\/+/, '-');
		ctx._source.parts = ctx._source.csv.split(/[,;]/, 2);
		ctx._source.pipes = ctx._source.pipe.split("|", 2);
	`
	if err := painless.EvalPainless(doc, scriptRegex, nil); err != nil {
		t.Fatalf("EvalPainless regex failed: %v", err)
	}
	if doc["clean_path"] != "a-b-c" {
		t.Fatalf("expected clean_path='a-b-c', got %v", doc["clean_path"])
	}
	parts, _ := doc["parts"].([]any)
	if len(parts) != 2 || parts[0] != "x" || parts[1] != "y;z" {
		t.Fatalf("expected parts=['x', 'y;z'], got %+v", doc["parts"])
	}
	pipes, _ := doc["pipes"].([]any)
	if len(pipes) != 2 || pipes[0] != "p1" || pipes[1] != "p2|p3" {
		t.Fatalf("expected literal pipe split ['p1', 'p2|p3'], got %+v", doc["pipes"])
	}

	// 2. Java primitive type casts, 2-arg indexOf/lastIndexOf, String.join varargs, for-loop with " in " string and comma post, braceless if/else, map alias ++, .put("a,b", 1), void return;
	scriptLang := `
		int trunc = (int) 3.9 + (int) 2.1;
		ctx._source.trunc = trunc;
		ctx._source.idx2 = ctx._source.text.indexOf("bra", 2);
		ctx._source.last2 = ctx._source.text.lastIndexOf("bra", 5);
		ctx._source.joined = String.join(":", "u", "v", "w");
		int sum = 0;
		for (int i = 0, j = 10; i < 3; i++, j += 10) {
			String label = "item in loop";
			if (label.length() > 0) sum += i + j;
		}
		ctx._source.loop_sum = sum;
		if (sum > 100) ctx._source.branch = "high"; else ctx._source.branch = "low";
		def m = ctx._source;
		m['trunc']++;
		m.put("a,b", 42);
		return;
		ctx._source.unreachable = true;
	`
	if err := painless.EvalPainless(doc, scriptLang, nil); err != nil {
		t.Fatalf("EvalPainless language constructs failed: %v", err)
	}
	// trunc = 3 + 2 = 5, then m['trunc']++ -> 6
	if doc["trunc"] != int64(6) {
		t.Fatalf("expected trunc=6 after cast and alias ++, got %v (%T)", doc["trunc"], doc["trunc"])
	}
	if doc["idx2"] != int64(8) || doc["last2"] != int64(1) {
		t.Fatalf("expected idx2=8, last2=1, got idx2=%v last2=%v", doc["idx2"], doc["last2"])
	}
	if doc["joined"] != "u:v:w" {
		t.Fatalf("expected joined='u:v:w', got %v", doc["joined"])
	}
	// (0+10) + (1+20) + (2+30) = 63
	if doc["loop_sum"] != int64(63) || doc["branch"] != "low" {
		t.Fatalf("expected loop_sum=63, branch='low', got sum=%v branch=%v", doc["loop_sum"], doc["branch"])
	}
	if doc["a,b"] != json.Number("42") && doc["a,b"] != int64(42) {
		t.Fatalf("expected map.put('a,b', 42) to set key 'a,b'=42, got %v (%T)", doc["a,b"], doc["a,b"])
	}
	if _, exists := doc["unreachable"]; exists {
		t.Fatalf("expected void return; to stop execution before unreachable statement")
	}
}

func TestRound17_IngestProcessorsHardening(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Simulate grok (optional capture group + ECS bracket field + integer/bool coercion),
	// dissect (%{msg} %{+msg}), date (Z0700 + epoch_millis), split & kv ("|" and "."),
	// foreach mutating top-level field, convert (ip, auto "t"), script (params.ctx + ctx['_source'] + _ingest.timestamp)
	simRes := doJSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"grok": {
						"field": "raw_log",
						"patterns": ["%{WORD:[client][name]} (?:%{NUMBER:opt_num:integer} )?%{WORD:active:boolean} %{INT:[client][port]:int}"]
					}
				},
				{
					"dissect": {
						"field": "dis_in",
						"pattern": "%{part} %{+part}",
						"append_separator": "-"
					}
				},
				{
					"date": {
						"field": "log_time",
						"formats": ["yyyy-MM-dd'T'HH:mm:ssZ"],
						"target_field": "epoch_ms",
						"output_format": "epoch_millis"
					}
				},
				{
					"split": {
						"field": "pipe_str",
						"separator": "|"
					}
				},
				{
					"kv": {
						"field": "kv_str",
						"field_split": "|",
						"value_split": ".",
						"target_field": "kv_out"
					}
				},
				{
					"foreach": {
						"field": "nums",
						"processor": {
							"script": {
								"source": "ctx.last_seen = ctx._ingest._value"
							}
						}
					}
				},
				{
					"convert": {
						"field": "client_ip",
						"type": "ip"
					}
				},
				{
					"convert": {
						"field": "short_str",
						"type": "auto"
					}
				},
				{
					"script": {
						"source": "ctx['_source']['from_param'] = params.ctx.val; ctx.has_ingest_ts = (ctx._ingest.timestamp != null);",
						"params": {
							"ctx": {"val": "ok"}
						}
					}
				}
			]
		},
		"docs": [
			{
				"_index": "test",
				"_id": "1",
				"_source": {
					"raw_log": "alice true 8080",
					"dis_in": "hello world",
					"log_time": "1970-01-01T00:00:02+0000",
					"pipe_str": "a|b|c",
					"kv_str": "k1.v1|k2.v2",
					"nums": [10, 20, 30],
					"client_ip": "192.168.1.1",
					"short_str": "t"
				}
			}
		]
	}`)

	simDocs := simRes["docs"].([]any)
	docOut := simDocs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)

	clientObj, _ := docOut["client"].(map[string]any)
	if clientObj["name"] != "alice" || clientObj["port"] != float64(8080) {
		t.Fatalf("unexpected ECS grok output: %+v", clientObj)
	}
	if _, hasOpt := docOut["opt_num"]; hasOpt {
		t.Fatalf("expected unmatched optional grok group opt_num to be omitted, got %v", docOut["opt_num"])
	}
	if docOut["active"] != true {
		t.Fatalf("expected grok boolean active=true, got %v", docOut["active"])
	}
	if docOut["part"] != "hello-world" {
		t.Fatalf("expected dissect part='hello-world', got %v", docOut["part"])
	}
	if docOut["epoch_ms"] != "2000" {
		t.Fatalf("expected date epoch_millis='2000', got %v (%T)", docOut["epoch_ms"], docOut["epoch_ms"])
	}
	pipeList, _ := docOut["pipe_str"].([]any)
	if len(pipeList) != 3 || pipeList[0] != "a" || pipeList[2] != "c" {
		t.Fatalf("expected pipe_str=['a','b','c'], got %+v", docOut["pipe_str"])
	}
	kvOut, _ := docOut["kv_out"].(map[string]any)
	if kvOut["k1"] != "v1" || kvOut["k2"] != "v2" {
		t.Fatalf("expected kv_out={k1:v1, k2:v2}, got %+v", kvOut)
	}
	if docOut["last_seen"] != float64(30) {
		t.Fatalf("expected foreach top-level mutation last_seen=30, got %v", docOut["last_seen"])
	}
	if docOut["client_ip"] != "192.168.1.1" || docOut["short_str"] != "t" {
		t.Fatalf("expected client_ip='192.168.1.1' and short_str='t' (not bool), got ip=%v short_str=%v", docOut["client_ip"], docOut["short_str"])
	}
	if docOut["from_param"] != "ok" || docOut["has_ingest_ts"] != true {
		t.Fatalf("expected from_param='ok' and has_ingest_ts=true, got from_param=%v has_ingest_ts=%v", docOut["from_param"], docOut["has_ingest_ts"])
	}

	// 2. Redirecting ctx._index to a write alias in default_pipeline still runs the concrete target's final_pipeline
	doJSON(t, srv, http.MethodPut, "/_ingest/pipeline/r17_redirect_pipe", `{
		"processors": [
			{"set": {"field": "_index", "value": "r17_dest_alias"}}
		]
	}`)
	doJSON(t, srv, http.MethodPut, "/_ingest/pipeline/r17_final_pipe", `{
		"processors": [
			{"set": {"field": "final_ran", "value": true}}
		]
	}`)
	doJSON(t, srv, http.MethodPut, "/r17_dest_concrete", `{
		"settings": {
			"index.final_pipeline": "r17_final_pipe"
		},
		"aliases": {
			"r17_dest_alias": {"is_write_index": true}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r17_src/_doc/1?pipeline=r17_redirect_pipe&refresh=true", `{"msg":"hi"}`)

	gotDest := doJSON(t, srv, http.MethodGet, "/r17_dest_concrete/_doc/1", "")
	if gotDest["found"] != true || gotDest["_source"].(map[string]any)["final_ran"] != true {
		t.Fatalf("expected final_pipeline on r17_dest_concrete to run when redirected via write alias r17_dest_alias, got %+v", gotDest)
	}

	// 3. convert type: "float" rejects NaN
	nanSim := doJSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"convert": {"field": "bad", "type": "float"}}
			]
		},
		"docs": [{"_source": {"bad": "NaN"}}]
	}`)
	nanDocs, _ := nanSim["docs"].([]any)
	if len(nanDocs) != 1 || nanDocs[0].(map[string]any)["error"] == nil {
		t.Fatalf("expected convert float NaN to record a doc error in simulate, got %+v", nanSim)
	}
	_ = math.NaN()
}
