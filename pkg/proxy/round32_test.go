package proxy

import (
	"net/http"
	"strings"
	"testing"
)

func TestRound32_ValidateTermsLookupSamplerDateRangeAndComposite(t *testing.T) {
	srv, _ := newTestServer()

	// Fix 10: _validate/query?explain=true resolves terms lookup and nested.filter sort terms lookup
	code, _ := doRound27Req(t, srv, http.MethodPut, "/r32_users/1", nil)
	_ = code
	doRound27Req(t, srv, http.MethodPut, "/r32_users/_doc/u1?refresh=true", map[string]any{
		"allowed_depts": []any{"eng", "sec"},
	})
	doRound27Req(t, srv, http.MethodPut, "/r32_docs", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"dept":  map[string]any{"type": "keyword"},
				"score": map[string]any{"type": "double"},
				"ts":    map[string]any{"type": "date"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"dept":  map[string]any{"type": "keyword"},
						"price": map[string]any{"type": "double"},
					},
				},
			},
		},
	})
	bulkDocs := strings.Join([]string{
		`{"index":{"_index":"r32_docs","_id":"1"}}`,
		`{"dept":"eng","score":10,"ts":"2026-01-15T00:00:00Z","items":[{"dept":"eng","price":100}]}`,
		`{"index":{"_index":"r32_docs","_id":"2"}}`,
		`{"dept":"eng","score":20,"ts":"2026-02-01T00:00:00Z","items":[{"dept":"eng","price":200}]}`,
		`{"index":{"_index":"r32_docs","_id":"3"}}`,
		`{"dept":"sales","score":30,"ts":"2026-02-10T00:00:00Z","items":[{"dept":"sales","price":300}]}`,
	}, "\n") + "\n"
	doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkDocs)

	code, valRes := doRound27Req(t, srv, http.MethodPost, "/r32_docs/_validate/query?explain=true", map[string]any{
		"query": map[string]any{
			"terms": map[string]any{
				"dept": map[string]any{
					"index": "r32_users",
					"id":    "u1",
					"path":  "allowed_depts",
				},
			},
		},
	})
	if code != http.StatusOK || valRes["valid"] != true {
		t.Fatalf("expected valid:true on _validate/query with terms lookup, got code=%d res=%+v", code, valRes)
	}
	explanations, _ := valRes["explanations"].([]any)
	if len(explanations) == 0 || !strings.Contains(explanations[0].(map[string]any)["explanation"].(string), "'eng'") {
		t.Fatalf("expected resolved 'eng' in _validate/query explanation, got %+v", explanations)
	}

	// Also verify terms lookup inside Sort[i].Entry.Nested.Filter on _search
	code, srchSortRes := doRound27Req(t, srv, http.MethodPost, "/r32_docs/_search", map[string]any{
		"sort": []any{
			map[string]any{
				"items.price": map[string]any{
					"order": "desc",
					"nested": map[string]any{
						"path": "items",
						"filter": map[string]any{
							"terms": map[string]any{
								"items.dept": map[string]any{
									"index": "r32_users",
									"id":    "u1",
									"path":  "allowed_depts",
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search with nested.filter terms lookup failed: %d (%v)", code, srchSortRes)
	}
	hitsSort := srchSortRes["hits"].(map[string]any)["hits"].([]any)
	if len(hitsSort) != 3 || hitsSort[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected doc 2 first when sorting by items.price filtered to eng/sec, got %+v", hitsSort)
	}

	// Fix 11: sampler (shard_size) and diversified_sampler (shard_size, field, max_docs_per_value)
	code, sampRes := doRound27Req(t, srv, http.MethodPost, "/r32_docs/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"samp": map[string]any{
				"sampler": map[string]any{"shard_size": 2},
				"aggs": map[string]any{
					"by_dept": map[string]any{"terms": map[string]any{"field": "dept"}},
				},
			},
			"div_samp": map[string]any{
				"diversified_sampler": map[string]any{
					"shard_size":         10,
					"field":              "dept",
					"max_docs_per_value": 1,
				},
				"aggs": map[string]any{
					"sum_score": map[string]any{"sum": map[string]any{"field": "score"}},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("sampler/diversified_sampler search failed: %d (%v)", code, sampRes)
	}
	aggs11 := sampRes["aggregations"].(map[string]any)
	if aggs11["samp"].(map[string]any)["doc_count"] != float64(2) {
		t.Fatalf("expected sampler shard_size=2 doc_count=2, got %+v", aggs11["samp"])
	}
	// diversified_sampler with max_docs_per_value=1 on dept ("eng", "sales") keeps at most 1 doc per dept -> doc_count=2
	if aggs11["div_samp"].(map[string]any)["doc_count"] != float64(2) {
		t.Fatalf("expected diversified_sampler doc_count=2, got %+v", aggs11["div_samp"])
	}

	// Fix 12 & Fix 13: date_range format/time_zone/default key, and composite date_histogram non-ISO format chronological sorting
	code, drCompRes := doRound27Req(t, srv, http.MethodPost, "/r32_docs/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"dr": map[string]any{
				"date_range": map[string]any{
					"field":  "ts",
					"format": "yyyy-MM-dd",
					"ranges": []any{
						map[string]any{"from": "2026-01-01", "to": "2026-02-01"},
						map[string]any{"from": "2026-02-01", "to": "2026-03-01"},
					},
				},
			},
			"comp": map[string]any{
				"composite": map[string]any{
					"sources": []any{
						map[string]any{
							"day": map[string]any{
								"date_histogram": map[string]any{
									"field":             "ts",
									"calendar_interval": "day",
									"format":            "dd/MM/yyyy",
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("date_range/composite search failed: %d (%v)", code, drCompRes)
	}
	aggs12 := drCompRes["aggregations"].(map[string]any)
	drBuckets := aggs12["dr"].(map[string]any)["buckets"].([]any)
	b0 := drBuckets[0].(map[string]any)
	if b0["from_as_string"] != "2026-01-01" || b0["to_as_string"] != "2026-02-01" || b0["key"] != "2026-01-01-2026-02-01" {
		t.Fatalf("unexpected date_range bucket[0]: %+v", b0)
	}
	compBuckets := aggs12["comp"].(map[string]any)["buckets"].([]any)
	// Chronological order: 15/01/2026, 01/02/2026, 10/02/2026 (NOT lexicographical 01/02/2026 first!)
	if len(compBuckets) != 3 || compBuckets[0].(map[string]any)["key"].(map[string]any)["day"] != "15/01/2026" || compBuckets[1].(map[string]any)["key"].(map[string]any)["day"] != "01/02/2026" {
		t.Fatalf("expected chronological composite date_histogram order [15/01/2026, 01/02/2026, 10/02/2026], got %+v", compBuckets)
	}
}

func TestRound32_SortCoercionHighlightPostFilterKeyedPipelineAndClone(t *testing.T) {
	srv, _ := newTestServer()

	// Fix 14, Fix 15, Fix 16: Stringified float sort, highlight on runtime script query, post_filter max_score, keyed sibling pipeline aggs, filters other_bucket last
	doRound27Req(t, srv, http.MethodPut, "/r32_search_post", map[string]any{
		"settings": map[string]any{
			"index.max_result_window": 2,
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"price":  map[string]any{"type": "double"},
				"title":  map[string]any{"type": "text"},
				"status": map[string]any{"type": "keyword"},
				"step":   map[string]any{"type": "integer"},
			},
		},
	})
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"r32_search_post","_id":"1"}}`,
		`{"price":"9.5","title":"quick brown fox","status":"ok","step":10}`,
		`{"index":{"_index":"r32_search_post","_id":"2"}}`,
		`{"price":"10.5","title":"lazy brown dog","status":"err","step":20}`,
		`{"index":{"_index":"r32_search_post","_id":"3"}}`,
		`{"price":"2.0","title":"brown cat","status":"other","step":30}`,
	}, "\n") + "\n"
	doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)

	// Fix 14: Runtime sort (triggered by script query) with stringified float in _source ("9.5" < "10.5" numerically, not lexicographically)
	// plus Fix 15: highlight on match query when sibling script filter forces runtime script evaluation
	code, res14 := doRound27Req(t, srv, http.MethodPost, "/r32_search_post/_search", map[string]any{
		"size": 2,
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{"match": map[string]any{"title": "brown"}},
					map[string]any{"script": map[string]any{"script": "doc['step'].value >= 10"}},
				},
			},
		},
		"sort": []any{
			map[string]any{"price": map[string]any{"order": "asc"}},
		},
		"highlight": map[string]any{
			"fields": map[string]any{"title": map[string]any{}},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search 14/15 failed: %d (%v)", code, res14)
	}
	hits14 := res14["hits"].(map[string]any)["hits"].([]any)
	// Numeric asc order of price: 2.0 (id=3), 9.5 (id=1), 10.5 (id=2)
	if len(hits14) != 2 || hits14[0].(map[string]any)["_id"] != "3" || hits14[1].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected numeric sort order [3, 1] on stringified double, got %+v", hits14)
	}
	hl0, _ := hits14[0].(map[string]any)["highlight"].(map[string]any)
	if hl0 == nil || len(hl0["title"].([]any)) == 0 {
		t.Fatalf("expected highlight on title when runtime script filter is active, got %+v", hits14[0])
	}

	// Fix 16: typed_keys prefixes for cumulative_cardinality & moving_avg, sibling pipeline agg on keyed histogram, and filters other_bucket last when keyed:false
	code, res16 := doRound27Req(t, srv, http.MethodPost, "/r32_search_post/_search?typed_keys=true", map[string]any{
		"size":        1,
		"post_filter": map[string]any{"term": map[string]any{"status": "ok"}},
		"aggs": map[string]any{
			"by_step": map[string]any{
				"histogram": map[string]any{
					"field":    "step",
					"interval": 10,
					"keyed":    true,
				},
				"aggs": map[string]any{
					"u_status": map[string]any{"cardinality": map[string]any{"field": "status"}},
					"cum_card": map[string]any{"cumulative_cardinality": map[string]any{"buckets_path": "u_status"}},
					"mov_avg":  map[string]any{"moving_avg": map[string]any{"buckets_path": "_count"}},
				},
			},
			"max_step_cnt": map[string]any{
				"max_bucket": map[string]any{"buckets_path": "by_step>_count"},
			},
			"by_flt": map[string]any{
				"filters": map[string]any{
					"keyed":        false,
					"other_bucket": true,
					"filters": []any{
						map[string]any{"term": map[string]any{"status": "ok"}},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search 16 failed: %d (%v)", code, res16)
	}
	if res16["hits"].(map[string]any)["max_score"] == nil {
		t.Fatalf("expected non-nil max_score when post_filter is present, got %+v", res16["hits"])
	}
	aggs16 := res16["aggregations"].(map[string]any)
	maxStep, ok := aggs16["max_bucket#max_step_cnt"].(map[string]any)
	if !ok {
		t.Fatalf("expected max_bucket#max_step_cnt in aggs: %+v", aggs16)
	}
	if maxStep["value"] != float64(1) {
		t.Fatalf("expected max_bucket over keyed histogram to be 1, got %+v", maxStep)
	}
	stepBuckets := aggs16["histogram#by_step"].(map[string]any)["buckets"].(map[string]any)
	b10 := stepBuckets["10"].(map[string]any)
	if b10["cumulative_cardinality#cum_card"] == nil || b10["moving_avg#mov_avg"] == nil {
		t.Fatalf("expected cumulative_cardinality#cum_card and moving_avg#mov_avg typed keys in bucket, got %+v", b10)
	}
	fltBuckets := aggs16["filters#by_flt"].(map[string]any)["buckets"].([]any)
	if len(fltBuckets) != 2 || fltBuckets[0].(map[string]any)["doc_count"] != float64(1) || fltBuckets[1].(map[string]any)["doc_count"] != float64(2) {
		t.Fatalf("expected filters other_bucket (doc_count=2) last after filter[0] (doc_count=1), got %+v", fltBuckets)
	}

	// Fix 17: _clone copies all 3 docs and settings even when index.max_result_window is 2 (< 1000)
	code, cloneRes := doRound27Req(t, srv, http.MethodPost, "/r32_search_post/_clone/r32_search_post_cloned", map[string]any{})
	if code != http.StatusOK || cloneRes["acknowledged"] != true {
		t.Fatalf("_clone failed: %d (%v)", code, cloneRes)
	}
	code, cntRes := doRound27Req(t, srv, http.MethodGet, "/r32_search_post_cloned/_count", nil)
	if code != http.StatusOK || cntRes["count"] != float64(3) {
		t.Fatalf("expected 3 cloned docs in r32_search_post_cloned, got code=%d res=%+v", code, cntRes)
	}
}

func TestRound32_UpdateValidationIngestProcessorsAndIntraBatchRerouting(t *testing.T) {
	srv, _ := newTestServer()

	doRound27Req(t, srv, http.MethodPut, "/r32_mut", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"v":       map[string]any{"type": "integer"},
				"next_id": map[string]any{"type": "keyword"},
			},
		},
	})
	doRound27Req(t, srv, http.MethodPut, "/r32_mut/_doc/1?refresh=true", map[string]any{"v": 10, "next_id": "2"})
	doRound27Req(t, srv, http.MethodPut, "/r32_mut/_doc/2?refresh=true", map[string]any{"v": 20, "next_id": "3"})

	// Fix 22: Empty {} update body rejected with 400 action_request_validation_exception; {"doc":{}} returns noop
	code, emptyUpd := doRound27Req(t, srv, http.MethodPost, "/r32_mut/_update/1", map[string]any{})
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty update request {}, got %d (%v)", code, emptyUpd)
	}
	code, noopUpd := doRound27Req(t, srv, http.MethodPost, "/r32_mut/_update/1", map[string]any{"doc": map[string]any{}})
	if code != http.StatusOK || noopUpd["result"] != "noop" {
		t.Fatalf("expected result=noop for {\"doc\":{}}, got %d (%v)", code, noopUpd)
	}

	// Fix 23: Ingest rename (ignore_missing:false with override:false), append allow_duplicates:false type-aware, and remove keep on flat dotted keys
	code, simRes := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"append": map[string]any{
						"field":            "items",
						"value":            []any{"1", 1},
						"allow_duplicates": false,
					},
				},
				map[string]any{
					"remove": map[string]any{
						"keep": []any{"items", "a"},
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_index": "r32_mut",
				"_id":    "sim1",
				"_source": map[string]any{
					"items": []any{1},
					"a.b":   "kept_flat",
					"drop":  "gone",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("_simulate failed: %d (%v)", code, simRes)
	}
	simSrc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	simItems, _ := simSrc["items"].([]any)
	// Numeric 1 was already present so 1 is skipped as duplicate, but string "1" is distinct and appended!
	if len(simItems) != 2 || simItems[1] != "1" {
		t.Fatalf("expected items=[1, \"1\"], got %+v", simItems)
	}
	aMap, _ := simSrc["a"].(map[string]any)
	if aMap["b"] != "kept_flat" || simSrc["drop"] != nil {
		t.Fatalf("expected flat dotted key a.b to be kept and drop removed, got %+v", simSrc)
	}

	// Fix 24a: _update_by_query with pipeline rerouting doc 1 -> _id=2 and doc 2 -> _id=3 in the same batch must not tombstone newly written doc 2
	doRound27Req(t, srv, http.MethodPut, "/_ingest/pipeline/r32_reroute_id", map[string]any{
		"processors": []any{
			map[string]any{
				"set": map[string]any{
					"field":     "_id",
					"copy_from": "next_id",
				},
			},
		},
	})
	code, ubqRes := doRound27Req(t, srv, http.MethodPost, "/r32_mut/_update_by_query?pipeline=r32_reroute_id&refresh=true", map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
	})
	if code != http.StatusOK || ubqRes["updated"] != float64(2) {
		t.Fatalf("_update_by_query reroute failed: %d (%v)", code, ubqRes)
	}
	code2, get2 := doRound27Req(t, srv, http.MethodGet, "/r32_mut/_doc/2", nil)
	code3, get3 := doRound27Req(t, srv, http.MethodGet, "/r32_mut/_doc/3", nil)
	if code2 != http.StatusOK || get2["found"] != true || get2["_source"].(map[string]any)["v"] != float64(10) {
		t.Fatalf("expected doc 2 to survive with v=10 (rerouted from doc 1), got code=%d res=%+v", code2, get2)
	}
	if code3 != http.StatusOK || get3["found"] != true || get3["_source"].(map[string]any)["v"] != float64(20) {
		t.Fatalf("expected doc 3 to exist with v=20 (rerouted from doc 2), got code=%d res=%+v", code3, get3)
	}

	// Fix 24b: _reindex with ctx.op = "delete" on non-existent dest doc counts as noop, and string literal "ctx._id" is not rewritten
	code, reidxRes := doRound27Req(t, srv, http.MethodPost, "/_reindex?refresh=true", map[string]any{
		"source": map[string]any{"index": "r32_mut"},
		"dest":   map[string]any{"index": "r32_mut_dest"},
		"script": map[string]any{
			"source": `if (ctx._id == '3') { ctx.op = 'delete'; } else { ctx._source.literal_check = 'ctx._id'; }`,
		},
	})
	if code != http.StatusOK {
		t.Fatalf("_reindex failed: %d (%v)", code, reidxRes)
	}
	if reidxRes["created"] != float64(1) || reidxRes["deleted"] != float64(0) || reidxRes["noops"] != float64(1) {
		t.Fatalf("expected created=1, deleted=0, noops=1 when ctx.op='delete' targets non-existent dest doc, got %+v", reidxRes)
	}
	code, destDoc2 := doRound27Req(t, srv, http.MethodGet, "/r32_mut_dest/_doc/2", nil)
	if code != http.StatusOK || destDoc2["_source"].(map[string]any)["literal_check"] != "ctx._id" {
		t.Fatalf("expected string literal 'ctx._id' to be preserved during _reindex, got %+v", destDoc2)
	}
}
