package proxy

import (
	"math"
	"net/http"
	"strings"
	"testing"
)

func TestRound29_DateHistogramNestedTermsPipelineAggsNoDoubleEval(t *testing.T) {
	srv, _ := newTestServer()

	// Create index and index documents across two days and 3 categories (a, b, c)
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"sales_r29","_id":"1"}}`,
		`{"ts":"2026-10-01T10:00:00Z","cat":"a","amount":10}`,
		`{"index":{"_index":"sales_r29","_id":"2"}}`,
		`{"ts":"2026-10-01T11:00:00Z","cat":"a","amount":20}`,
		`{"index":{"_index":"sales_r29","_id":"3"}}`,
		`{"ts":"2026-10-01T12:00:00Z","cat":"b","amount":40}`,
		`{"index":{"_index":"sales_r29","_id":"4"}}`,
		`{"ts":"2026-10-01T13:00:00Z","cat":"b","amount":60}`,
		`{"index":{"_index":"sales_r29","_id":"5"}}`,
		`{"ts":"2026-10-01T14:00:00Z","cat":"b","amount":20}`,
		`{"index":{"_index":"sales_r29","_id":"6"}}`,
		`{"ts":"2026-10-01T15:00:00Z","cat":"c","amount":100}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index failed: %d", code)
	}

	// Query with date_histogram -> terms (both keyed:false and keyed:true) -> sum + cumulative_sum + bucket_sort(from:1, size:2)
	code, resp := doRound27Req(t, srv, http.MethodPost, "/sales_r29/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_day": map[string]any{
				"date_histogram": map[string]any{
					"field":             "ts",
					"calendar_interval": "1d",
				},
				"aggs": map[string]any{
					"by_cat": map[string]any{
						"terms": map[string]any{
							"field": "cat",
							"order": map[string]any{"_key": "asc"},
						},
						"aggs": map[string]any{
							"sum_amt": map[string]any{
								"sum": map[string]any{"field": "amount"},
							},
							"cum_amt": map[string]any{
								"cumulative_sum": map[string]any{"buckets_path": "sum_amt"},
							},
							"page": map[string]any{
								"bucket_sort": map[string]any{
									"from": 1,
									"size": 2,
								},
							},
						},
					},
					"by_amt_range_keyed": map[string]any{
						"range": map[string]any{
							"field": "amount",
							"keyed": true,
							"ranges": []any{
								map[string]any{"key": "low", "to": 50},
								map[string]any{"key": "high", "from": 50},
							},
						},
						"aggs": map[string]any{
							"sum_amt": map[string]any{
								"sum": map[string]any{"field": "amount"},
							},
							"cum_amt": map[string]any{
								"cumulative_sum": map[string]any{"buckets_path": "sum_amt"},
							},
						},
					},
				},
			},
			"by_day_keyed": map[string]any{
				"date_histogram": map[string]any{
					"field":             "ts",
					"calendar_interval": "1d",
					"keyed":             true,
				},
				"aggs": map[string]any{
					"by_cat": map[string]any{
						"terms": map[string]any{
							"field": "cat",
							"order": map[string]any{"_key": "asc"},
						},
						"aggs": map[string]any{
							"sum_amt": map[string]any{
								"sum": map[string]any{"field": "amount"},
							},
							"cum_amt": map[string]any{
								"cumulative_sum": map[string]any{"buckets_path": "sum_amt"},
							},
							"page": map[string]any{
								"bucket_sort": map[string]any{
									"from": 1,
									"size": 2,
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search failed: code=%d resp=%v", code, resp)
	}
	aggs := resp["aggregations"].(map[string]any)
	dayBuckets := aggs["by_day"].(map[string]any)["buckets"].([]any)
	if len(dayBuckets) != 1 {
		t.Fatalf("expected 1 day bucket, got %d", len(dayBuckets))
	}
	day0 := dayBuckets[0].(map[string]any)
	catBuckets := day0["by_cat"].(map[string]any)["buckets"].([]any)
	// Before fix: scaleBucketRates evaluated bucket_sort(from:1, size:2) a second time,
	// shrinking [a, b, c] -> [b, c] -> [c] (length 1) and recomputing cumulative_sum without 'a'.
	// After fix: [b, c] (length 2) with cum_amt(b) = 30+120 = 150 and cum_amt(c) = 150+100 = 250.
	if len(catBuckets) != 2 {
		t.Fatalf("expected 2 buckets after single bucket_sort(from:1, size:2), got %d: %+v", len(catBuckets), catBuckets)
	}
	b0 := catBuckets[0].(map[string]any)
	b1 := catBuckets[1].(map[string]any)
	if b0["key"] != "b" || b1["key"] != "c" {
		t.Fatalf("expected buckets [b, c], got [%v, %v]", b0["key"], b1["key"])
	}
	cumB := b0["cum_amt"].(map[string]any)["value"].(float64)
	cumC := b1["cum_amt"].(map[string]any)["value"].(float64)
	if cumB != 150.0 || cumC != 250.0 {
		t.Fatalf("expected cumulative_sum [150, 250], got [%v, %v]", cumB, cumC)
	}

	keyedRanges := day0["by_amt_range_keyed"].(map[string]any)["buckets"].(map[string]any)
	highBucket := keyedRanges["high"].(map[string]any)
	if highBucket["cum_amt"].(map[string]any)["value"].(float64) != 250.0 {
		t.Fatalf("expected keyed range 'high' cum_amt=250, got %v", highBucket["cum_amt"])
	}

	keyedDays := aggs["by_day_keyed"].(map[string]any)["buckets"].(map[string]any)
	for _, v := range keyedDays {
		kd := v.(map[string]any)
		kdCats := kd["by_cat"].(map[string]any)["buckets"].([]any)
		if len(kdCats) != 2 {
			t.Fatalf("expected 2 buckets under keyed date_histogram after bucket_sort, got %d", len(kdCats))
		}
	}
}

func TestRound29_TermsOrderByAvgSubAggWithMissingNullAndNegativeValues(t *testing.T) {
	srv, _ := newTestServer()

	// Create 3 categories:
	// - "neg": score = -10 (avg = -10)
	// - "pos": score = 5   (avg = 5)
	// - "missing": no score field (avg = null, Weight = -1)
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"metrics_r29","_id":"1"}}`,
		`{"cat":"neg","score":-10}`,
		`{"index":{"_index":"metrics_r29","_id":"2"}}`,
		`{"cat":"pos","score":5}`,
		`{"index":{"_index":"metrics_r29","_id":"3"}}`,
		`{"cat":"missing"}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index failed: %d", code)
	}

	// Ascending order by avg_score: ES sorts [-10 ("neg"), 5 ("pos"), null ("missing")] (nulls last)
	code, respAsc := doRound27Req(t, srv, http.MethodPost, "/metrics_r29/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_cat": map[string]any{
				"terms": map[string]any{
					"field": "cat",
					"order": map[string]any{"avg_score": "asc"},
				},
				"aggs": map[string]any{
					"avg_score": map[string]any{
						"avg": map[string]any{"field": "score"},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("asc search failed: %d %v", code, respAsc)
	}
	ascBuckets := respAsc["aggregations"].(map[string]any)["by_cat"].(map[string]any)["buckets"].([]any)
	if len(ascBuckets) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(ascBuckets))
	}
	if ascBuckets[0].(map[string]any)["key"] != "neg" ||
		ascBuckets[1].(map[string]any)["key"] != "pos" ||
		ascBuckets[2].(map[string]any)["key"] != "missing" {
		t.Fatalf("expected asc order [neg, pos, missing], got [%v, %v, %v]",
			ascBuckets[0].(map[string]any)["key"],
			ascBuckets[1].(map[string]any)["key"],
			ascBuckets[2].(map[string]any)["key"])
	}

	// Descending order by avg_score: ES sorts [5 ("pos"), -10 ("neg"), null ("missing")] (nulls last)
	code, respDesc := doRound27Req(t, srv, http.MethodPost, "/metrics_r29/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_cat": map[string]any{
				"terms": map[string]any{
					"field": "cat",
					"order": map[string]any{"avg_score": "desc"},
				},
				"aggs": map[string]any{
					"avg_score": map[string]any{
						"avg": map[string]any{"field": "score"},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("desc search failed: %d %v", code, respDesc)
	}
	descBuckets := respDesc["aggregations"].(map[string]any)["by_cat"].(map[string]any)["buckets"].([]any)
	if descBuckets[0].(map[string]any)["key"] != "pos" ||
		descBuckets[1].(map[string]any)["key"] != "neg" ||
		descBuckets[2].(map[string]any)["key"] != "missing" {
		t.Fatalf("expected desc order [pos, neg, missing], got [%v, %v, %v]",
			descBuckets[0].(map[string]any)["key"],
			descBuckets[1].(map[string]any)["key"],
			descBuckets[2].(map[string]any)["key"])
	}
}

func TestRound29_RuntimeIDsClauseMatchingInInnerHitsPostFilterAndFunctionScore(t *testing.T) {
	srv, _ := newTestServer()

	// Create index with nested mapping
	code, _ := doRound27Req(t, srv, http.MethodPut, "/orders_r29", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"customer": map[string]any{"type": "keyword"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"sku": map[string]any{"type": "keyword"},
						"qty": map[string]any{"type": "integer"},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index orders_r29 failed: %d", code)
	}

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"orders_r29","_id":"ord-100"}}`,
		`{"customer":"alice","items":[{"sku":"sku-1","qty":2},{"sku":"sku-2","qty":5}]}`,
		`{"index":{"_index":"orders_r29","_id":"ord-200"}}`,
		`{"customer":"bob","items":[{"sku":"sku-1","qty":10}]}`,
	}, "\n") + "\n"
	code, _ = doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index orders_r29 failed: %d", code)
	}

	// 1. bool.must with ids query + nested query with inner_hits + post_filter with ids + runtime script
	code, resp := doRound27Req(t, srv, http.MethodPost, "/orders_r29/_search", map[string]any{
		"query": map[string]any{
			"function_score": map[string]any{
				"query": map[string]any{
					"bool": map[string]any{
						"must": []any{
							map[string]any{
								"ids": map[string]any{
									"values": []any{"ord-100", "ord-200"},
								},
							},
							map[string]any{
								"nested": map[string]any{
									"path": "items",
									"query": map[string]any{
										"term": map[string]any{"items.sku": "sku-1"},
									},
									"inner_hits": map[string]any{},
								},
							},
						},
					},
				},
				"functions": []any{
					map[string]any{
						"filter": map[string]any{
							"ids": map[string]any{"values": []any{"ord-100"}},
						},
						"weight": 10.0,
					},
					map[string]any{
						"script_score": map[string]any{
							"script": map[string]any{
								"source": "_score * 2",
							},
						},
					},
				},
				"score_mode": "multiply",
			},
		},
		"post_filter": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"ids": map[string]any{"values": []any{"ord-100"}},
					},
					map[string]any{
						"script": map[string]any{
							"script": map[string]any{
								"source": "doc['customer'].value == 'alice'",
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search failed: code=%d resp=%v", code, resp)
	}
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit after post_filter with ids+script, got %d: %+v", len(hits), hits)
	}
	hit0 := hits[0].(map[string]any)
	if hit0["_id"] != "ord-100" {
		t.Fatalf("expected hit _id=ord-100, got %v", hit0["_id"])
	}
	innerHits := hit0["inner_hits"].(map[string]any)["items"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(innerHits) != 1 {
		t.Fatalf("expected 1 inner_hit for items.sku=sku-1 on ord-100, got %d: %+v", len(innerHits), innerHits)
	}
}

func TestRound29_MultiIndexPercentileRanksAndPercentilesEmptyShardNoDilution(t *testing.T) {
	srv, _ := newTestServer()

	// Create latency_a (with data: 10, 20, 30, 40) and latency_b (with 1 doc lacking "ms" field)
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"latency_a_r29","_id":"1"}}`,
		`{"ms":10}`,
		`{"index":{"_index":"latency_a_r29","_id":"2"}}`,
		`{"ms":20}`,
		`{"index":{"_index":"latency_a_r29","_id":"3"}}`,
		`{"ms":30}`,
		`{"index":{"_index":"latency_a_r29","_id":"4"}}`,
		`{"ms":40}`,
		`{"index":{"_index":"latency_b_r29","_id":"1"}}`,
		`{"other":"no_ms"}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index failed: %d", code)
	}

	code, resp := doRound27Req(t, srv, http.MethodPost, "/latency_a_r29,latency_b_r29/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"p_ranks": map[string]any{
				"percentile_ranks": map[string]any{
					"field":  "ms",
					"values": []any{20, 40},
				},
			},
			"pcts": map[string]any{
				"percentiles": map[string]any{
					"field":    "ms",
					"percents": []any{50},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("multi-index search failed: %d %v", code, resp)
	}
	aggs := resp["aggregations"].(map[string]any)
	ranks := aggs["p_ranks"].(map[string]any)["values"].(map[string]any)
	rank20, _ := ranks["20.0"].(float64)
	rank40, _ := ranks["40.0"].(float64)
	// With 4 values [10, 20, 30, 40] in latency_a and 0 values in latency_b,
	// rank(40) must be 100.0 (not diluted by latency_b's empty 0.0!).
	if math.Abs(rank40-100.0) > 1e-6 || rank20 <= 0 {
		t.Fatalf("expected percentile_ranks rank(40)=100.0 and rank(20)>0 without empty-shard dilution, got rank20=%v rank40=%v", rank20, rank40)
	}
	pcts := aggs["pcts"].(map[string]any)["values"].(map[string]any)
	p50, _ := pcts["50.0"].(float64)
	if p50 < 20.0 || p50 > 30.0 {
		t.Fatalf("expected p50 between 20 and 30 without empty-shard dilution, got %v", p50)
	}
}

func TestRound29_RuntimeReverseNestedPathSamplerAndPostFilterQueryTotal(t *testing.T) {
	srv, _ := newTestServer()

	// Create 2-level nested index: depts (nested) -> depts.emps (nested)
	code, _ := doRound27Req(t, srv, http.MethodPut, "/org_r29", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"company": map[string]any{"type": "keyword"},
				"tier":    map[string]any{"type": "integer"},
				"depts": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"dept_name": map[string]any{"type": "keyword"},
						"emps": map[string]any{
							"type": "nested",
							"properties": map[string]any{
								"emp_name": map[string]any{"type": "keyword"},
								"salary":   map[string]any{"type": "integer"},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create org_r29 failed: %d", code)
	}

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"org_r29","_id":"c1"}}`,
		`{"company":"acme","tier":1,"depts":[{"dept_name":"eng","emps":[{"emp_name":"alice","salary":200},{"emp_name":"bob","salary":180}]},{"dept_name":"sales","emps":[{"emp_name":"carol","salary":150}]}]}`,
		`{"index":{"_index":"org_r29","_id":"c2"}}`,
		`{"company":"globex","tier":2,"depts":[{"dept_name":"eng","emps":[{"emp_name":"dave","salary":210}]}]}`,
	}, "\n") + "\n"
	code, _ = doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index org_r29 failed: %d", code)
	}

	// Execute search with:
	// - runtime script agg (triggers runtime agg evaluation path)
	// - post_filter (restricts hits to tier == 1 while aggregations run on all query matches = 2)
	// - sampler agg (should see doc_count = 2 from pre-post_filter query matches, not 1 from post_filter hits)
	// - nested(depts) -> nested(depts.emps) -> reverse_nested(path: "depts") -> terms(depts.dept_name)
	//   AND reverse_nested(root) -> terms(company)
	code, resp := doRound27Req(t, srv, http.MethodPost, "/org_r29/_search", map[string]any{
		"size": 10,
		"post_filter": map[string]any{
			"term": map[string]any{"tier": 1},
		},
		"aggs": map[string]any{
			"runtime_bonus": map[string]any{
				"sum": map[string]any{
					"script": map[string]any{
						"source": "doc['tier'].value * 10",
					},
				},
			},
			"sampled": map[string]any{
				"sampler": map[string]any{
					"shard_size": 10,
				},
				"aggs": map[string]any{
					"by_company": map[string]any{
						"terms": map[string]any{"field": "company"},
					},
				},
			},
			"script_filtered": map[string]any{
				"filter": map[string]any{
					"script": map[string]any{
						"script": map[string]any{
							"source": "doc['tier'].value >= 1",
						},
					},
				},
				"aggs": map[string]any{
					"inner_sampled": map[string]any{
						"sampler": map[string]any{"shard_size": 10},
					},
					"inner_depts": map[string]any{
						"nested": map[string]any{"path": "depts"},
						"aggs": map[string]any{
							"inner_root": map[string]any{
								"reverse_nested": map[string]any{},
							},
						},
					},
				},
			},
			"by_depts": map[string]any{
				"nested": map[string]any{"path": "depts"},
				"aggs": map[string]any{
					"by_emps": map[string]any{
						"nested": map[string]any{"path": "depts.emps"},
						"aggs": map[string]any{
							"back_to_dept": map[string]any{
								"reverse_nested": map[string]any{"path": "depts"},
								"aggs": map[string]any{
									"dept_names": map[string]any{
										"terms": map[string]any{"field": "depts.dept_name"},
									},
								},
							},
							"back_to_root": map[string]any{
								"reverse_nested": map[string]any{},
								"aggs": map[string]any{
									"companies": map[string]any{
										"terms": map[string]any{"field": "company"},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search org_r29 failed: %d %v", code, resp)
	}
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit after post_filter(tier=1), got %d", len(hits))
	}
	aggs := resp["aggregations"].(map[string]any)
	sampled := aggs["sampled"].(map[string]any)
	if sampled["doc_count"].(float64) != 2 {
		t.Fatalf("expected sampler doc_count=2 (pre-post_filter query matches), got %v", sampled["doc_count"])
	}
	scriptFiltered := aggs["script_filtered"].(map[string]any)
	if scriptFiltered["inner_sampled"].(map[string]any)["doc_count"].(float64) != 2 {
		t.Fatalf("expected inner_sampled doc_count=2, got %v", scriptFiltered["inner_sampled"])
	}
	if scriptFiltered["inner_depts"].(map[string]any)["inner_root"].(map[string]any)["doc_count"].(float64) != 2 {
		t.Fatalf("expected inner_depts.inner_root doc_count=2, got %v", scriptFiltered["inner_depts"])
	}

	byEmps := aggs["by_depts"].(map[string]any)["by_emps"].(map[string]any)
	if byEmps["doc_count"].(float64) != 4 {
		t.Fatalf("expected 4 total nested emps across 2 docs, got %v", byEmps["doc_count"])
	}
	backToDept := byEmps["back_to_dept"].(map[string]any)
	if backToDept["doc_count"].(float64) != 3 {
		t.Fatalf("expected reverse_nested(path:depts) doc_count=3 (3 depts with emps), got %v", backToDept["doc_count"])
	}
	deptBuckets := backToDept["dept_names"].(map[string]any)["buckets"].([]any)
	if len(deptBuckets) != 2 {
		t.Fatalf("expected 2 dept_names buckets (eng, sales), got %+v", deptBuckets)
	}
	backToRoot := byEmps["back_to_root"].(map[string]any)
	if backToRoot["doc_count"].(float64) != 2 {
		t.Fatalf("expected reverse_nested(root) doc_count=2 (2 root companies), got %v", backToRoot["doc_count"])
	}
}

func TestRound29_IngestForeachScriptInPlaceMapMutation(t *testing.T) {
	srv, _ := newTestServer()

	code, simResp := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"foreach": map[string]any{
						"field": "items",
						"processor": map[string]any{
							"script": map[string]any{
								"source": "ctx._ingest._value.mutated = true; ctx._ingest._value.double_qty = ctx._ingest._value.qty * 2;",
							},
						},
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_index": "test_r29",
				"_id":    "1",
				"_source": map[string]any{
					"items": []any{
						map[string]any{"sku": "a", "qty": 3},
						map[string]any{"sku": "b", "qty": 7},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("simulate foreach+script failed: %d %v", code, simResp)
	}
	docSrc := simResp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	items := docSrc["items"].([]any)
	item0 := items[0].(map[string]any)
	item1 := items[1].(map[string]any)
	if item0["mutated"] != true || item0["double_qty"].(float64) != 6 ||
		item1["mutated"] != true || item1["double_qty"].(float64) != 14 {
		t.Fatalf("expected foreach script in-place mutations to persist on items, got %+v", items)
	}
}

func TestRound29_FilteredAliasWriteIsolationOnUpsertBulkUpdateAndReindexDelete(t *testing.T) {
	srv, _ := newTestServer()

	// Create backing index and two filtered tenant aliases (tenant_a and tenant_b)
	code, _ := doRound27Req(t, srv, http.MethodPut, "/shared_r29", map[string]any{
		"aliases": map[string]any{
			"alias_tenant_a": map[string]any{
				"filter": map[string]any{
					"term": map[string]any{"tenant": "a"},
				},
			},
			"alias_tenant_b": map[string]any{
				"filter": map[string]any{
					"term": map[string]any{"tenant": "b"},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create shared_r29 with filtered aliases failed: %d", code)
	}

	// Index doc-b1 belonging to tenant "b"
	code, _ = doRound27Req(t, srv, http.MethodPut, "/alias_tenant_b/_doc/doc-b1?refresh=true", map[string]any{
		"tenant": "b",
		"secret": "tenant-b-confidential",
	})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index doc-b1 via alias_tenant_b failed: %d", code)
	}

	// 1. Attempt POST /alias_tenant_a/_update/doc-b1 with doc_as_upsert: true
	// Must return 409 Conflict (cannot overwrite tenant B's document via tenant A's alias!)
	code, updResp := doRound27Req(t, srv, http.MethodPost, "/alias_tenant_a/_update/doc-b1", map[string]any{
		"doc":           map[string]any{"tenant": "a", "secret": "hijacked"},
		"doc_as_upsert": true,
	})
	if code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when updating tenant B doc via alias_tenant_a with doc_as_upsert:true, got %d (%v)", code, updResp)
	}

	// 2. Attempt POST /alias_tenant_a/_bulk update on doc-b1 with doc_as_upsert: true
	bulkUpd := strings.Join([]string{
		`{"update":{"_id":"doc-b1"}}`,
		`{"doc":{"tenant":"a","secret":"hijacked-bulk"},"doc_as_upsert":true}`,
	}, "\n") + "\n"
	code, bulkResp := doRound27Req(t, srv, http.MethodPost, "/alias_tenant_a/_bulk", bulkUpd)
	if code != http.StatusOK {
		t.Fatalf("bulk request failed: %d", code)
	}
	item0 := bulkResp["items"].([]any)[0].(map[string]any)["update"].(map[string]any)
	if int(item0["status"].(float64)) != http.StatusConflict {
		t.Fatalf("expected 409 status in bulk update response for cross-tenant doc_as_upsert, got %+v", item0)
	}

	// 3. Attempt _reindex into alias_tenant_a with script setting ctx.op = "delete" and ctx._id = "doc-b1"
	code, _ = doRound27Req(t, srv, http.MethodPut, "/src_r29/_doc/src-1?refresh=true", map[string]any{
		"tenant": "a",
	})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index src_r29 failed: %d", code)
	}
	code, reindexResp := doRound27Req(t, srv, http.MethodPost, "/_reindex", map[string]any{
		"source": map[string]any{"index": "src_r29"},
		"dest":   map[string]any{"index": "alias_tenant_a"},
		"script": map[string]any{
			"source": "ctx._id = 'doc-b1'; ctx.op = 'delete';",
		},
	})
	if code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when _reindex attempts cross-tenant delete via alias_tenant_a, got %d (%v)", code, reindexResp)
	}

	// Verify tenant B's document is completely intact
	code, getB := doRound27Req(t, srv, http.MethodGet, "/shared_r29/_doc/doc-b1", nil)
	if code != http.StatusOK || getB["_source"].(map[string]any)["secret"] != "tenant-b-confidential" {
		t.Fatalf("expected doc-b1 to remain intact after rejected cross-tenant attacks, got code=%d resp=%v", code, getB)
	}
}

func TestRound29_RolloverMultiTargetWriteIndexAndRequestAliasesPersistence(t *testing.T) {
	srv, _ := newTestServer()

	// Create logs-000001 (is_write_index: true) and logs-000002 (is_write_index: false, sorts after logs-000001)
	code, _ := doRound27Req(t, srv, http.MethodPut, "/logs-000001", map[string]any{
		"aliases": map[string]any{
			"logs_write": map[string]any{"is_write_index": true},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create logs-000001 failed: %d", code)
	}
	code, _ = doRound27Req(t, srv, http.MethodPut, "/logs-000002", map[string]any{
		"aliases": map[string]any{
			"logs_write": map[string]any{"is_write_index": false},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create logs-000002 failed: %d", code)
	}

	// Index 2 docs into logs_write (which routes to logs-000001)
	code, _ = doRound27Req(t, srv, http.MethodPut, "/logs_write/_doc/1?refresh=true", map[string]any{"msg": "one"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index doc 1 failed: %d", code)
	}
	code, _ = doRound27Req(t, srv, http.MethodPut, "/logs_write/_doc/2?refresh=true", map[string]any{"msg": "two"})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index doc 2 failed: %d", code)
	}

	// Rollover logs_write to logs-000003 with conditions.max_docs = 1 and an extra alias in request body
	code, rollResp := doRound27Req(t, srv, http.MethodPost, "/logs_write/_rollover/logs-000003", map[string]any{
		"conditions": map[string]any{
			"max_docs": 1,
		},
		"aliases": map[string]any{
			"logs_read_all": map[string]any{},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("rollover failed: %d %v", code, rollResp)
	}
	if rollResp["old_index"] != "logs-000001" || rollResp["new_index"] != "logs-000003" || rollResp["rolled_over"] != true {
		t.Fatalf("expected old_index=logs-000001, new_index=logs-000003, rolled_over=true, got %+v", rollResp)
	}

	// Verify logs_read_all alias was created on logs-000003 and logs_write is_write_index flipped to logs-000003
	code, aliasResp := doRound27Req(t, srv, http.MethodGet, "/logs-000003/_alias", nil)
	if code != http.StatusOK {
		t.Fatalf("GET /logs-000003/_alias failed: %d", code)
	}
	aliases03 := aliasResp["logs-000003"].(map[string]any)["aliases"].(map[string]any)
	if _, hasReadAll := aliases03["logs_read_all"]; !hasReadAll {
		t.Fatalf("expected logs_read_all alias on logs-000003, got %+v", aliases03)
	}
	writeMeta, hasWrite := aliases03["logs_write"].(map[string]any)
	if !hasWrite || writeMeta["is_write_index"] != true {
		t.Fatalf("expected logs_write with is_write_index:true on logs-000003, got %+v", aliases03)
	}
}
