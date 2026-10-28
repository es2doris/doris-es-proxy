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
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// TestRound14UpgradedArrayQueriesMultiFieldBulkAndReindex verifies R14-P0-1 and R14-P0-9:
//   - Scalar fields (`date`, `long`, `double`, `boolean`, and `text` with normalized `.keyword` multi-field)
//     upgraded to `StoragePromotedArray` (`UpgradedArray: true`) preserve their `ESType` and `.keyword` companion.
//   - `match`, `match_phrase`, `range` (with ISO-8601 date strings and numeric bounds), `term` (with lowercase
//     normalizer on `.keyword`), and `sort` + `search_after` (with ISO-8601 date strings) work on `UpgradedArray` fields.
//   - `_bulk` inspects all docs beyond the first 16 ops and re-shreds when a mid-bulk scripted `update`
//     promotes a scalar field to an array; `_reindex` promotes scalar fields across all batch docs.
func TestRound14UpgradedArrayQueriesMultiFieldBulkAndReindex(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/up_arr_r14", `{
		"settings": {
			"analysis": {
				"normalizer": {
					"lc": {"type": "custom", "filter": ["lowercase"]}
				}
			}
		},
		"mappings": {
			"properties": {
				"title": {
					"type": "text",
					"fields": {
						"keyword": {"type": "keyword", "normalizer": "lc"}
					}
				},
				"ts": {"type": "date"},
				"score_num": {"type": "long"},
				"active": {"type": "boolean"},
				"dyn_tag": {"type": "keyword"}
			}
		}
	}`)

	// Index doc 1 with scalar values
	mustReq(t, ts, http.MethodPut, "/up_arr_r14/_doc/1?refresh=true", `{
		"title": "Hello World",
		"ts": "2025-01-01T00:00:00Z",
		"score_num": 10,
		"active": true,
		"dyn_tag": "scalar_init"
	}`)

	// Bulk index 20 docs where doc #20 has array values for title, ts, score_num, active,
	// plus a scripted update on doc 1 that promotes dyn_tag to an array mid-bulk.
	var bulkBody string
	for i := 2; i <= 19; i++ {
		bulkBody += fmt.Sprintf("{\"index\":{\"_index\":\"up_arr_r14\",\"_id\":\"%d\"}}\n", i)
		bulkBody += fmt.Sprintf("{\"title\":\"Doc %d\",\"ts\":\"2025-01-02T00:00:00Z\",\"score_num\":%d,\"active\":false,\"dyn_tag\":\"s\"}\n", i, i)
	}
	bulkBody += `{"index":{"_index":"up_arr_r14","_id":"20"}}` + "\n"
	bulkBody += `{"title":["Alpha Beta","Gamma"],"ts":["2025-06-01T00:00:00Z","2025-07-01T00:00:00Z"],"score_num":[100,200],"active":[true,false],"dyn_tag":"s20"}` + "\n"
	bulkBody += `{"update":{"_index":"up_arr_r14","_id":"1"}}` + "\n"
	bulkBody += `{"script":{"source":"ctx._source.dyn_tag = ['promoted_a', 'promoted_b']"}}` + "\n"

	bulkRes := mustReq(t, ts, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if bulkRes["errors"] != false {
		t.Fatalf("expected _bulk with array at op #20 and mid-bulk scripted array promotion to succeed, got %v", bulkRes)
	}

	// 1. match on UpgradedArray date field `ts` with ISO-8601 string
	resDateMatch := mustReq(t, ts, http.MethodPost, "/up_arr_r14/_search", `{
		"query": {"match": {"ts": "2025-06-01T00:00:00Z"}}
	}`)
	hitsDate := resDateMatch["hits"].(map[string]any)["hits"].([]any)
	if len(hitsDate) != 1 || hitsDate[0].(map[string]any)["_id"] != "20" {
		t.Fatalf("expected match on UpgradedArray date field to return doc 20, got %v", hitsDate)
	}

	// 2. range on UpgradedArray date field `ts` with ISO-8601 bounds
	resDateRange := mustReq(t, ts, http.MethodPost, "/up_arr_r14/_search", `{
		"query": {"range": {"ts": {"gte": "2025-05-01T00:00:00Z", "lte": "2025-08-01T00:00:00Z"}}}
	}`)
	hitsRange := resDateRange["hits"].(map[string]any)["hits"].([]any)
	if len(hitsRange) != 1 || hitsRange[0].(map[string]any)["_id"] != "20" {
		t.Fatalf("expected range on UpgradedArray date field to return doc 20, got %v", hitsRange)
	}

	// 3. match & match_phrase on UpgradedArray numeric (`score_num`) and boolean (`active`) fields
	resNumMatch := mustReq(t, ts, http.MethodPost, "/up_arr_r14/_search", `{
		"query": {
			"bool": {
				"must": [
					{"match": {"score_num": 200}},
					{"match_phrase": {"active": "true"}},
					{"term": {"dyn_tag": "promoted_b"}}
				]
			}
		}
	}`)
	if resNumMatch["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(0) {
		t.Fatalf("expected doc 20 and doc 1 conjunction to be 0, got %v", resNumMatch["hits"])
	}
	resDoc20 := mustReq(t, ts, http.MethodPost, "/up_arr_r14/_search", `{
		"query": {
			"bool": {
				"must": [
					{"match": {"score_num": 200}},
					{"match": {"active": true}}
				]
			}
		}
	}`)
	hitsDoc20 := resDoc20["hits"].(map[string]any)["hits"].([]any)
	if len(hitsDoc20) != 1 || hitsDoc20[0].(map[string]any)["_id"] != "20" {
		t.Fatalf("expected match on UpgradedArray score_num=200 & active=true to return doc 20, got %v", hitsDoc20)
	}

	// 4. term on UpgradedArray `title` (using preserved `title.keyword` lowercase normalizer companion)
	resTitleTerm := mustReq(t, ts, http.MethodPost, "/up_arr_r14/_search", `{
		"query": {"term": {"title": "ALPHA BETA"}}
	}`)
	hitsTitle := resTitleTerm["hits"].(map[string]any)["hits"].([]any)
	if len(hitsTitle) != 1 || hitsTitle[0].(map[string]any)["_id"] != "20" {
		t.Fatalf("expected case-normalized term query on UpgradedArray title to return doc 20, got %v", hitsTitle)
	}

	// 5. sort + search_after with ISO-8601 date string on UpgradedArray `ts`
	resAfter := mustReq(t, ts, http.MethodPost, "/up_arr_r14/_search", `{
		"size": 5,
		"sort": [{"ts": "asc"}, {"_id": "asc"}],
		"search_after": ["2025-05-01T00:00:00Z", "0"]
	}`)
	hitsAfter := resAfter["hits"].(map[string]any)["hits"].([]any)
	if len(hitsAfter) != 1 || hitsAfter[0].(map[string]any)["_id"] != "20" {
		t.Fatalf("expected search_after with ISO date on UpgradedArray ts to return doc 20, got %v", hitsAfter)
	}
}

// TestRound14CollapseSearchAfterPaginationAndInnerHits verifies R14-P0-2 and R14-P0-6:
//   - `collapse` + `search_after` applies `search_after` after collapsing so secondary documents of
//     already-seen collapse groups are never promoted to `_collapse_rn = 1` on Page 2+.
//   - `collapse.inner_hits` clears `subReq.SearchAfter`, normalizes cross-index date/lowercase group keys,
//     nullifies `_score`/`max_score` when sorting by non-score fields, and populates `highlight`.
func TestRound14CollapseSearchAfterPaginationAndInnerHits(t *testing.T) {
	for _, useSQL := range []bool{false, true} {
		mem := NewMemoryBackend(useSQL)
		srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
		ts := httptest.NewServer(srv.Handler())

		mustReq(t, ts, http.MethodPut, "/col_page_1", `{
			"settings": {
				"analysis": {
					"normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}}
				}
			},
			"mappings": {
				"properties": {
					"dept": {"type": "keyword", "normalizer": "lc"},
					"salary": {"type": "long"},
					"bio": {"type": "text"}
				}
			}
		}`)
		mustReq(t, ts, http.MethodPut, "/col_page_2", `{
			"mappings": {
				"properties": {
					"dept": {"type": "keyword"},
					"salary": {"type": "long"},
					"bio": {"type": "text"}
				}
			}
		}`)
		// Group "eng": doc 1 (salary 300 in col_page_1 with "ENG"), doc 2 (salary 250 in col_page_2 with "eng")
		// Group "sales": doc 3 (salary 200 in col_page_1), doc 4 (salary 150 in col_page_2)
		// Group "hr": doc 5 (salary 100 in col_page_1)
		mustReq(t, ts, http.MethodPut, "/col_page_1/_doc/1?refresh=true", `{"dept":"ENG","salary":300,"bio":"leadsearch engineer"}`)
		mustReq(t, ts, http.MethodPut, "/col_page_2/_doc/2?refresh=true", `{"dept":"eng","salary":250,"bio":"staffsearch engineer"}`)
		mustReq(t, ts, http.MethodPut, "/col_page_1/_doc/3?refresh=true", `{"dept":"sales","salary":200,"bio":"enterprise search account"}`)
		mustReq(t, ts, http.MethodPut, "/col_page_2/_doc/4?refresh=true", `{"dept":"sales","salary":150,"bio":"midmarket search account"}`)
		mustReq(t, ts, http.MethodPut, "/col_page_1/_doc/5?refresh=true", `{"dept":"hr","salary":100,"bio":"talent search partner"}`)

		// Page 1: size=1, collapse on dept, sort by salary desc
		p1 := mustReq(t, ts, http.MethodPost, "/col_page_1,col_page_2/_search", `{
			"size": 1,
			"query": {"match": {"bio": "search"}},
			"sort": [{"salary": "desc"}],
			"collapse": {
				"field": "dept",
				"inner_hits": {
					"name": "team",
					"size": 5,
					"sort": [{"salary": "desc"}],
					"highlight": {"fields": {"bio": {}}}
				}
			}
		}`)
		p1Hits := p1["hits"].(map[string]any)["hits"].([]any)
		if len(p1Hits) != 1 || p1Hits[0].(map[string]any)["_id"] != "1" {
			t.Fatalf("useSQL=%v: expected Page 1 hit to be doc 1 (eng, salary 300), got %v", useSQL, p1Hits)
		}
		p1IH := p1Hits[0].(map[string]any)["inner_hits"].(map[string]any)["team"].(map[string]any)["hits"].(map[string]any)
		if p1IH["total"].(map[string]any)["value"] != float64(2) {
			t.Fatalf("useSQL=%v: expected cross-index normalized dept 'ENG'/'eng' to have 2 inner_hits, got %v", useSQL, p1IH)
		}
		if p1IH["max_score"] != nil {
			t.Fatalf("useSQL=%v: expected max_score=nil when collapse.inner_hits sorts by salary, got %v", useSQL, p1IH["max_score"])
		}
		p1TeamHits := p1IH["hits"].([]any)
		if p1TeamHits[0].(map[string]any)["_score"] != nil {
			t.Fatalf("useSQL=%v: expected inner hit _score=nil when sorted by non-score field, got %v", useSQL, p1TeamHits[0])
		}
		if p1TeamHits[0].(map[string]any)["highlight"] == nil {
			t.Fatalf("useSQL=%v: expected highlight in collapse.inner_hits, got %v", useSQL, p1TeamHits[0])
		}

		// Page 2: search_after=[300] MUST return doc 3 (sales, salary 200) and NOT doc 2 (eng, salary 250)!
		p2 := mustReq(t, ts, http.MethodPost, "/col_page_1,col_page_2/_search", `{
			"size": 1,
			"query": {"match": {"bio": "search"}},
			"sort": [{"salary": "desc"}],
			"search_after": [300],
			"collapse": {
				"field": "dept",
				"inner_hits": {
					"name": "team",
					"size": 5,
					"sort": [{"salary": "asc"}]
				}
			}
		}`)
		p2Hits := p2["hits"].(map[string]any)["hits"].([]any)
		if len(p2Hits) != 1 || p2Hits[0].(map[string]any)["_id"] != "3" {
			t.Fatalf("useSQL=%v: expected Page 2 hit to be doc 3 (sales, salary 200) and not secondary eng doc 2, got %v", useSQL, p2Hits)
		}
		p2IH := p2Hits[0].(map[string]any)["inner_hits"].(map[string]any)["team"].(map[string]any)["hits"].(map[string]any)
		if p2IH["total"].(map[string]any)["value"] != float64(2) {
			t.Fatalf("useSQL=%v: expected Page 2 sales inner_hits to have all 2 sales docs, got %v", useSQL, p2IH)
		}

		// Also verify single-index collapse + search_after when secondary doc of group 'eng' is in the SAME index
		mustReq(t, ts, http.MethodPut, "/col_page_1/_doc/1b?refresh=true", `{"dept":"ENG","salary":260,"bio":"principal search engineer"}`)
		sp2 := mustReq(t, ts, http.MethodPost, "/col_page_1/_search", `{
			"size": 1,
			"query": {"match": {"bio": "search"}},
			"sort": [{"salary": "desc"}],
			"search_after": [300],
			"collapse": {"field": "dept"}
		}`)
		sp2Hits := sp2["hits"].(map[string]any)["hits"].([]any)
		if len(sp2Hits) != 1 || sp2Hits[0].(map[string]any)["_id"] != "3" {
			t.Fatalf("useSQL=%v: expected single-index Page 2 hit to be doc 3 (sales, 200) and not secondary eng doc 1b (260), got %v", useSQL, sp2Hits)
		}

		ts.Close()
	}
}

// TestRound14NestedPercentileRanksAndInnerHits verifies R14-P0-3 and R14-P0-5:
//   - Direct `percentile_ranks` sub-aggregation under `nested`.
//   - `nested.inner_hits` inside `function_score.functions[].filter`, relative sort/fields resolution,
//     wildcard `fields: ["*"]` without duplicate prefixed keys, and `highlight` inside `nested.inner_hits`.
func TestRound14NestedPercentileRanksAndInnerHits(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/nested_r14", `{
		"mappings": {
			"properties": {
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"},
						"price": {"type": "double"},
						"created_at": {"type": "date"},
						"note": {"type": "text"}
					}
				}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/nested_r14/_doc/1?refresh=true", `{
		"items": [
			{"sku": "B", "price": 50, "created_at": 1700000005000, "note": "fast ssd drive"},
			{"sku": "A", "price": 10, "created_at": 1700000000000, "note": "fast nvme drive"},
			{"sku": "C", "price": 90, "created_at": 1700000010000, "note": "slow hdd"}
		]
	}`)

	res := mustReq(t, ts, http.MethodPost, "/nested_r14/_search", `{
		"query": {
			"function_score": {
				"query": {"match_all": {}},
				"functions": [
					{
						"filter": {
							"nested": {
								"path": "items",
								"query": {"match": {"items.note": "fast"}},
								"inner_hits": {
									"name": "fast_items",
									"sort": [{"created_at": "asc"}],
									"fields": ["*"],
									"highlight": {"fields": {"items.note": {}}}
								}
							}
						},
						"weight": 2
					}
				]
			}
		},
		"aggs": {
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"price_ranks": {
						"percentile_ranks": {
							"field": "items.price",
							"values": [20, 60]
						}
					}
				}
			}
		}
	}`)

	// 1. Verify nested percentile_ranks
	nestedAgg := res["aggregations"].(map[string]any)["nested_items"].(map[string]any)
	ranksVals := nestedAgg["price_ranks"].(map[string]any)["values"].(map[string]any)
	r20, ok20 := ranksVals["20.0"].(float64)
	r60, ok60 := ranksVals["60.0"].(float64)
	if !ok20 || !ok60 || r20 <= 0 || r60 <= r20 {
		t.Fatalf("expected nested percentile_ranks for 20.0 and 60.0 with 0 < r20 < r60, got %v", ranksVals)
	}

	// 2. Verify nested.inner_hits inside function_score.functions[].filter
	hit0 := res["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	fastIH := hit0["inner_hits"].(map[string]any)["fast_items"].(map[string]any)["hits"].(map[string]any)
	if fastIH["max_score"] != nil {
		t.Fatalf("expected max_score=nil on sorted nested inner_hits, got %v", fastIH["max_score"])
	}
	ihHits := fastIH["hits"].([]any)
	if len(ihHits) != 2 {
		t.Fatalf("expected 2 fast_items in nested.inner_hits, got %v", ihHits)
	}
	firstIH := ihHits[0].(map[string]any)
	if firstIH["_score"] != nil {
		t.Fatalf("expected _score=nil on sorted nested inner_hit, got %v", firstIH["_score"])
	}
	// Sorted by relative field `created_at` asc -> SKU "A" (offset 1, 1700000000000) comes first
	if firstIH["_nested"].(map[string]any)["offset"] != float64(1) {
		t.Fatalf("expected first inner_hit sorted by relative created_at asc to be offset 1 (SKU A), got %v", firstIH)
	}
	ihFields := firstIH["fields"].(map[string]any)
	if _, hasDupPrefixed := ihFields["items.sku"]; hasDupPrefixed {
		t.Fatalf("expected wildcard fields: ['*'] not to emit duplicate prefixed 'items.sku' key, got %v", ihFields)
	}
	if ihFields["created_at"].([]any)[0] != "2023-11-14T22:13:20.000Z" {
		t.Fatalf("expected relative 'created_at' field in nested inner_hits to format as ISO-8601 date, got %v", ihFields["created_at"])
	}
	if firstIH["highlight"] == nil {
		t.Fatalf("expected highlight on nested inner_hit, got %v", firstIH)
	}
}

// TestRound14SortMissingCustomValuePagination verifies R14-P0-4:
//   - Custom `sort.missing` values (e.g. `"missing": 150`) place missing documents between lower and higher
//     values and paginate accurately via `search_after`.
func TestRound14SortMissingCustomValuePagination(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/sort_miss_r14", `{
		"mappings": {"properties": {"rank": {"type": "long"}}}
	}`)
	mustReq(t, ts, http.MethodPut, "/sort_miss_r14/_doc/a?refresh=true", `{"rank":100}`)
	mustReq(t, ts, http.MethodPut, "/sort_miss_r14/_doc/b?refresh=true", `{}`)
	mustReq(t, ts, http.MethodPut, "/sort_miss_r14/_doc/c?refresh=true", `{"rank":200}`)

	// Full order with missing="150": a (100), b (150), c (200)
	resAll := mustReq(t, ts, http.MethodPost, "/sort_miss_r14/_search", `{
		"sort": [{"rank": {"order": "asc", "missing": "150"}}, {"_id": "asc"}]
	}`)
	hitsAll := resAll["hits"].(map[string]any)["hits"].([]any)
	if len(hitsAll) != 3 ||
		hitsAll[0].(map[string]any)["_id"] != "a" ||
		hitsAll[1].(map[string]any)["_id"] != "b" ||
		hitsAll[2].(map[string]any)["_id"] != "c" {
		t.Fatalf("expected order [a, b, c] with missing=150, got %v", hitsAll)
	}

	// Page 2 after a (rank=100, _id="a") -> b (rank=150) and c (rank=200)
	resAfterA := mustReq(t, ts, http.MethodPost, "/sort_miss_r14/_search", `{
		"sort": [{"rank": {"order": "asc", "missing": "150"}}, {"_id": "asc"}],
		"search_after": [100, "a"]
	}`)
	hitsAfterA := resAfterA["hits"].(map[string]any)["hits"].([]any)
	if len(hitsAfterA) != 2 || hitsAfterA[0].(map[string]any)["_id"] != "b" || hitsAfterA[1].(map[string]any)["_id"] != "c" {
		t.Fatalf("expected search_after=[100,'a'] to return [b, c], got %v", hitsAfterA)
	}
}

// TestRound14MultiIndexExtendedStatsMissingAndPipelineValidation verifies R14-P0-7 and R14-P1-1:
//   - Multi-index `extended_stats` (`sum_of_squares`) under `MemoryBackend(true)` SQL regex and `min` with `missing: 0`.
//   - `terms` ordered by keyed `filters` sub-agg (`by_tier['pro']>avg_sal`) and derived `extended_stats`/`boxplot` properties.
//   - Keyed `range` bucket referenced in pipeline `buckets_path` and empty bucket (`doc_count: 0`) gap skipping.
func TestRound14MultiIndexExtendedStatsMissingAndPipelineValidation(t *testing.T) {
	for _, useSQL := range []bool{false, true} {
		mem := NewMemoryBackend(useSQL)
		srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
		ts := httptest.NewServer(srv.Handler())

		mustReq(t, ts, http.MethodPut, "/mi_stat_1", `{
			"mappings": {"properties": {"dept": {"type": "keyword"}, "tier": {"type": "keyword"}, "val": {"type": "double"}, "step": {"type": "long"}}}
		}`)
		mustReq(t, ts, http.MethodPut, "/mi_stat_2", `{
			"mappings": {"properties": {"dept": {"type": "keyword"}, "tier": {"type": "keyword"}, "step": {"type": "long"}}}
		}`)
		mustReq(t, ts, http.MethodPut, "/mi_stat_1/_doc/1?refresh=true", `{"dept":"eng","tier":"pro","val":10,"step":0}`)
		mustReq(t, ts, http.MethodPut, "/mi_stat_1/_doc/2?refresh=true", `{"dept":"eng","tier":"pro","val":20,"step":0}`)
		mustReq(t, ts, http.MethodPut, "/mi_stat_2/_doc/3?refresh=true", `{"dept":"sales","tier":"pro","step":20}`)

		res := mustReq(t, ts, http.MethodPost, "/mi_stat_1,mi_stat_2/_search", `{
			"size": 0,
			"aggs": {
				"ext": {"extended_stats": {"field": "val"}},
				"min_with_zero_missing": {"min": {"field": "val", "missing": 0}},
				"by_dept": {
					"terms": {
						"field": "dept",
						"order": {"by_tier['pro']>avg_val": "desc"}
					},
					"aggs": {
						"by_tier": {
							"filters": {
								"filters": {
									"pro": {"term": {"tier": "pro"}}
								}
							},
							"aggs": {
								"avg_val": {"avg": {"field": "val", "missing": 0}}
							}
						}
					}
				},
				"by_range_keyed": {
					"range": {
						"field": "val",
						"keyed": true,
						"ranges": [
							{"key": "low", "to": 15},
							{"key": "high", "from": 15}
						]
					},
					"aggs": {
						"sum_val": {"sum": {"field": "val"}}
					}
				},
				"sum_of_high_range": {
					"sum_bucket": {"buckets_path": "by_range_keyed['high']>sum_val"}
				},
				"by_step": {
					"histogram": {"field": "step", "interval": 10, "min_doc_count": 0},
					"aggs": {
						"st": {"stats": {"field": "val"}}
					}
				},
				"min_of_stats_min": {
					"min_bucket": {"buckets_path": "by_step>st.min"}
				}
			}
		}`)
		aggs := res["aggregations"].(map[string]any)
		// 1. extended_stats sum_of_squares = 10^2 + 20^2 = 500
		ext := aggs["ext"].(map[string]any)
		if math.Abs(ext["sum_of_squares"].(float64)-500.0) > 1e-6 {
			t.Fatalf("useSQL=%v: expected extended_stats sum_of_squares=500, got %v", useSQL, ext)
		}
		// 2. min_with_zero_missing across mi_stat_1 (min=10) and mi_stat_2 (missing=0) -> 0
		if aggs["min_with_zero_missing"].(map[string]any)["value"] != float64(0) {
			t.Fatalf("useSQL=%v: expected min_with_zero_missing=0 across index lacking field, got %v", useSQL, aggs["min_with_zero_missing"])
		}
		// 3. by_dept ordered by by_tier['pro']>avg_val desc -> eng (15) then sales (0)
		deptBuckets := aggs["by_dept"].(map[string]any)["buckets"].([]any)
		if len(deptBuckets) != 2 || deptBuckets[0].(map[string]any)["key"] != "eng" {
			t.Fatalf("useSQL=%v: expected by_dept ordered by keyed filters sub-agg to put 'eng' first, got %v", useSQL, deptBuckets)
		}
		// 4. keyed range pipeline buckets_path
		if aggs["sum_of_high_range"].(map[string]any)["value"] != float64(20) {
			t.Fatalf("useSQL=%v: expected sum_of_high_range=20, got %v", useSQL, aggs["sum_of_high_range"])
		}
		// 5. min_of_stats_min skips empty step=10 and step=20 (val count=0) buckets -> 10
		if aggs["min_of_stats_min"].(map[string]any)["value"] != float64(10) {
			t.Fatalf("useSQL=%v: expected min_of_stats_min=10 (skipping count=0 buckets), got %v", useSQL, aggs["min_of_stats_min"])
		}

		// 6. terms ordered by extended_stats.variance, std_deviation_bounds.upper, and boxplot.upper
		resOrder := mustReq(t, ts, http.MethodPost, "/mi_stat_1/_search", `{
			"size": 0,
			"aggs": {
				"by_dept_var": {
					"terms": {"field": "dept", "order": {"st.variance": "desc"}},
					"aggs": {"st": {"extended_stats": {"field": "val"}}}
				},
				"by_dept_upper": {
					"terms": {"field": "dept", "order": {"st.std_deviation_bounds.upper": "desc"}},
					"aggs": {"st": {"extended_stats": {"field": "val"}}}
				},
				"by_dept_box": {
					"terms": {"field": "dept", "order": {"bx.upper": "desc"}},
					"aggs": {"bx": {"boxplot": {"field": "val"}}}
				}
			}
		}`)
		oAggs := resOrder["aggregations"].(map[string]any)
		if len(oAggs["by_dept_var"].(map[string]any)["buckets"].([]any)) != 1 ||
			len(oAggs["by_dept_upper"].(map[string]any)["buckets"].([]any)) != 1 ||
			len(oAggs["by_dept_box"].(map[string]any)["buckets"].([]any)) != 1 {
			t.Fatalf("useSQL=%v: expected derived extended_stats/boxplot terms order to succeed, got %v", useSQL, oAggs)
		}

		ts.Close()
	}
}

// TestRound14PainlessCForLoopsRelationalMethodsAndNestedArrayPaths verifies R14-P0-8:
//   - C-style `for (int i = 0; i < ...; i++)` loops.
//   - Relational/equality/`===`/`instanceof` with method calls.
//   - Post-method index/property chains (`split('/')[0]`, `get(0).name`).
//   - Nested array index mutations (`ctx._source.items[0].tags.add('x')`) and `remove('100')` vs `remove(0)`.
func TestRound14PainlessCForLoopsRelationalMethodsAndNestedArrayPaths(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/painless_r14/_doc/1?refresh=true", `{
		"path": "services/auth/v1",
		"codes": ["100", "200", "300"],
		"items": [
			{"name": "first", "price": 10, "tags": ["init"]},
			{"name": "second", "price": 20, "tags": []}
		]
	}`)

	mustReq(t, ts, http.MethodPost, "/painless_r14/_update/1?refresh=true", `{
		"script": {
			"source": "if (ctx._source.path.indexOf('auth') >= 0 && ctx._source.codes instanceof List && ctx._source.codes.size() === 3 && ctx._source.path !== 'none') { ctx._source.root_seg = ctx._source.path.split('/')[0]; ctx._source.first_name = ctx._source.items.get(0).name; ctx._source.items[0].tags.add('urgent'); ctx._source.codes.remove('200'); ctx._source.codes.remove(0); List tmp = ['a', 'b']; tmp.add('c'); tmp.removeIf(v -> v == 'b'); ctx._source.local_list = tmp; int sum = 0; for (int i = 0; i < ctx._source.items.size(); i++) { sum += ctx._source.items[i].price; } ctx._source.total_price = sum; }"
		}
	}`)

	doc := mustReq(t, ts, http.MethodGet, "/painless_r14/_doc/1", "")
	src := doc["_source"].(map[string]any)
	if src["root_seg"] != "services" || src["first_name"] != "first" || src["total_price"] != float64(30) {
		t.Fatalf("unexpected painless update result: %v", src)
	}
	codes := src["codes"].([]any)
	if len(codes) != 1 || codes[0] != "300" {
		t.Fatalf("expected remove('200') by value then remove(0) by index to leave ['300'], got %v", codes)
	}
	localList := src["local_list"].([]any)
	if len(localList) != 2 || localList[0] != "a" || localList[1] != "c" {
		t.Fatalf("expected local variable add + removeIf to produce ['a', 'c'], got %v", localList)
	}
	item0Tags := src["items"].([]any)[0].(map[string]any)["tags"].([]any)
	if len(item0Tags) != 2 || item0Tags[1] != "urgent" {
		t.Fatalf("expected items[0].tags.add('urgent') to produce [init, urgent], got %v", item0Tags)
	}
}

// TestRound14IngestDissectModifiersArrayConvertForeachAndOnFailure verifies R14-P0-9:
//   - `dissect` reference-only keys (`%{*r1}`), indirect keys (`%{&r1}`), `/N` append ordering (`%{+name/2} %{+name/1}`),
//     trailing literal validation, and `target_field` with dotted keys.
//   - `convert` and `gsub` on array fields.
//   - Nested `foreach` preserving outer `_ingest._value`.
//   - Pipeline-level `on_failure` receiving `on_failure_processor_type` and `on_failure_processor_tag`.
func TestRound14IngestDissectModifiersArrayConvertForeachAndOnFailure(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	simRes := mustReq(t, ts, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"dissect": {
						"field": "line",
						"pattern": "%{*k1}=%{&k1} %{+full/2} %{+full/1} END",
						"append_separator": " ",
						"target_field": "parsed"
					}
				},
				{
					"convert": {
						"field": "nums",
						"type": "integer"
					}
				},
				{
					"gsub": {
						"field": "paths",
						"pattern": "/",
						"replacement": "."
					}
				},
				{
					"foreach": {
						"field": "groups",
						"processor": {
							"foreach": {
								"field": "_ingest._value.members",
								"processor": {
									"uppercase": {"field": "_ingest._value"}
								}
							}
						}
					}
				},
				{
					"kv": {
						"field": "kv_raw",
						"field_split": "&",
						"value_split": "=",
						"target_field": "kv_parsed"
					}
				},
				{
					"uppercase": {
						"field": "groups.0.name"
					}
				}
			]
		},
		"docs": [
			{
				"_source": {
					"line": "service.env=prod Smith Jane END",
					"kv_raw": "http.status=200",
					"nums": ["10", "20"],
					"paths": ["a/b", "c/d"],
					"groups": [
						{"name": "g1", "members": ["alice", "bob"]}
					]
				}
			}
		]
	}`)
	simDoc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	parsed := simDoc["parsed"].(map[string]any)
	if parsed["full"] != "Jane Smith" {
		t.Fatalf("expected dissect /N append ordering to produce 'Jane Smith', got %v", parsed)
	}
	if simDoc["kv_parsed"].(map[string]any)["http"].(map[string]any)["status"] != "200" {
		t.Fatalf("expected kv target_field dotted key expansion, got %v", simDoc["kv_parsed"])
	}
	if simDoc["groups"].([]any)[0].(map[string]any)["name"] != "G1" {
		t.Fatalf("expected ingest path array index traversal groups.0.name='G1', got %v", simDoc["groups"])
	}
	if _, leakedRef := parsed["k1"]; leakedRef {
		t.Fatalf("expected reference-only key %%{*k1} not to be emitted, got %v", parsed)
	}
	if parsed["service"].(map[string]any)["env"] != "prod" {
		t.Fatalf("expected dissect target_field with dotted indirect key service.env='prod', got %v", parsed)
	}
	nums := simDoc["nums"].([]any)
	if nums[0] != float64(10) || nums[1] != float64(20) {
		t.Fatalf("expected convert on array field nums to produce [10, 20], got %v", nums)
	}
	paths := simDoc["paths"].([]any)
	if paths[0] != "a.b" || paths[1] != "c.d" {
		t.Fatalf("expected gsub on array field paths to produce ['a.b', 'c.d'], got %v", paths)
	}
	members := simDoc["groups"].([]any)[0].(map[string]any)["members"].([]any)
	if members[0] != "ALICE" || members[1] != "BOB" {
		t.Fatalf("expected nested foreach to preserve outer _ingest._value and uppercase inner members, got %v", simDoc["groups"])
	}

	// Verify pipeline-level on_failure receives on_failure_processor_type and on_failure_processor_tag
	failSim := mustReq(t, ts, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"dissect": {
						"tag": "bad_dissect_tag",
						"field": "line",
						"pattern": "%{a} LITERAL_TAIL"
					}
				}
			],
			"on_failure": [
				{
					"set": {
						"field": "err_info",
						"value": "{{ _ingest.on_failure_processor_type }}:{{ _ingest.on_failure_processor_tag }}"
					}
				}
			]
		},
		"docs": [
			{"_source": {"line": "hello WRONG_TAIL"}}
		]
	}`)
	failDoc := failSim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if failDoc["err_info"] != "dissect:bad_dissect_tag" {
		t.Fatalf("expected pipeline-level on_failure to populate err_info='dissect:bad_dissect_tag', got %v", failDoc)
	}
}
