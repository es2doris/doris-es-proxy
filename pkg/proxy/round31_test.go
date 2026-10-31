package proxy

import (
	"net/http"
	"strings"
	"testing"
)

func TestRound31_MultiIndexZeroDocsAndHistogramPipelineOrder(t *testing.T) {
	srv, _ := newTestServer()

	// Fix 9: Multi-index weighted metrics (percentiles, boxplot, avg) when first index is empty
	code, _ := doRound27Req(t, srv, http.MethodPut, "/mi_r31_empty", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"val": map[string]any{"type": "double"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create mi_r31_empty failed: %d", code)
	}
	code, _ = doRound27Req(t, srv, http.MethodPut, "/mi_r31_populated", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"val": map[string]any{"type": "double"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create mi_r31_populated failed: %d", code)
	}
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"mi_r31_populated","_id":"1"}}`,
		`{"val":10}`,
		`{"index":{"_index":"mi_r31_populated","_id":"2"}}`,
		`{"val":30}`,
	}, "\n") + "\n"
	code, _ = doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index failed: %d", code)
	}

	code, resp := doRound27Req(t, srv, http.MethodPost, "/mi_r31_empty,mi_r31_populated/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"avg_val": map[string]any{"avg": map[string]any{"field": "val"}},
			"pct_val": map[string]any{"percentiles": map[string]any{"field": "val", "percents": []any{50}}},
			"box_val": map[string]any{"boxplot": map[string]any{"field": "val"}},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("multi-index search failed: %d (%v)", code, resp)
	}
	aggs := resp["aggregations"].(map[string]any)
	if got := aggs["avg_val"].(map[string]any)["value"]; got != 20.0 {
		t.Fatalf("expected avg_val=20.0 when first index is empty, got %v", got)
	}
	pctValues := aggs["pct_val"].(map[string]any)["values"].(map[string]any)
	if pctValues["50.0"] == nil || pctValues["50.0"] == 0.0 {
		t.Fatalf("expected non-zero p50 when first index is empty, got %v", pctValues)
	}

	// Fix 10: Histogram with extended_bounds (min_doc_count: 0) + cumulative_sum + bucket_sort (from: 1, size: 2)
	histBulk := strings.Join([]string{
		`{"index":{"_index":"hist_r31","_id":"1"}}`,
		`{"step":0,"val":10}`,
		`{"index":{"_index":"hist_r31","_id":"2"}}`,
		`{"step":20,"val":30}`,
	}, "\n") + "\n"
	code, _ = doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", histBulk)
	if code != http.StatusOK {
		t.Fatalf("hist_r31 bulk failed: %d", code)
	}
	code, hResp := doRound27Req(t, srv, http.MethodPost, "/hist_r31/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_step": map[string]any{
				"histogram": map[string]any{
					"field":         "step",
					"interval":      10,
					"min_doc_count": 0,
					"extended_bounds": map[string]any{
						"min": 0,
						"max": 20,
					},
				},
				"aggs": map[string]any{
					"sum_val":  map[string]any{"sum": map[string]any{"field": "val"}},
					"cum_val":  map[string]any{"cumulative_sum": map[string]any{"buckets_path": "sum_val"}},
					"page_two": map[string]any{"bucket_sort": map[string]any{"from": 1, "size": 2}},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("hist_r31 search failed: %d (%v)", code, hResp)
	}
	buckets := hResp["aggregations"].(map[string]any)["by_step"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets after bucket_sort(from:1, size:2) over [0, 10, 20], got %d: %+v", len(buckets), buckets)
	}
	b0 := buckets[0].(map[string]any)
	b1 := buckets[1].(map[string]any)
	// Bucket 0 is step=10 (zero-filled gap bucket): cumulative_sum should be 10 (from step=0)
	// Bucket 1 is step=20: cumulative_sum should be 10 + 30 = 40
	if b0["key"] != 10.0 || b0["cum_val"].(map[string]any)["value"] != 10.0 {
		t.Fatalf("expected bucket[0] key=10 cum_val=10.0, got %+v", b0)
	}
	if b1["key"] != 20.0 || b1["cum_val"].(map[string]any)["value"] != 40.0 {
		t.Fatalf("expected bucket[1] key=20 cum_val=40.0, got %+v", b1)
	}
}

func TestRound31_MemBackendCommasNumericScoreSortAndFieldCapsAlias(t *testing.T) {
	srv, _ := newTestServer()

	// Fix 11, 12, 13: Commas in term values (IN / arrays_overlap), numeric _score sort (10.0 > 2.0), and _field_caps alias
	code, _ := doRound27Req(t, srv, http.MethodPut, "/fc_r31", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"label":       map[string]any{"type": "keyword"},
				"tags":        map[string]any{"type": "keyword", "multi_valued": true},
				"label_alias": map[string]any{"type": "alias", "path": "label"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create fc_r31 failed: %d", code)
	}
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"fc_r31","_id":"1"}}`,
		`{"label":"a,b","tags":["x,y","z"]}`,
		`{"index":{"_index":"fc_r31","_id":"2"}}`,
		`{"label":"c,d","tags":["w"]}`,
	}, "\n") + "\n"
	code, _ = doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk fc_r31 failed: %d", code)
	}

	// Fix 11: terms query on scalar and array fields containing commas
	code, sResp := doRound27Req(t, srv, http.MethodPost, "/fc_r31/_search", map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{"terms": map[string]any{"label": []any{"a,b", "other"}}},
					map[string]any{"terms": map[string]any{"tags": []any{"x,y"}}},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search with commas in terms failed: %d (%v)", code, sResp)
	}
	hits := sResp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 matched by comma-containing terms, got %+v", hits)
	}

	// Fix 12: numeric _score sort (boost 10.0 vs boost 2.0)
	code, scoreResp := doRound27Req(t, srv, http.MethodPost, "/fc_r31/_search", map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"should": []any{
					map[string]any{"ids": map[string]any{"values": []any{"1"}, "boost": 2.0}},
					map[string]any{"ids": map[string]any{"values": []any{"2"}, "boost": 10.0}},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("numeric _score sort search failed: %d (%v)", code, scoreResp)
	}
	sHits := scoreResp["hits"].(map[string]any)["hits"].([]any)
	if len(sHits) != 2 || sHits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected doc 2 (_score=10.0) ranked before doc 1 (_score=2.0), got %+v", sHits)
	}

	// Fix 13: _field_caps resolves alias field to target type ("keyword")
	code, fcResp := doRound27Req(t, srv, http.MethodGet, "/fc_r31/_field_caps?fields=label_alias", nil)
	if code != http.StatusOK {
		t.Fatalf("_field_caps failed: %d (%v)", code, fcResp)
	}
	fieldsMap := fcResp["fields"].(map[string]any)
	aliasCaps, ok := fieldsMap["label_alias"].(map[string]any)
	if !ok || aliasCaps["keyword"] == nil {
		t.Fatalf("expected label_alias in _field_caps to resolve to 'keyword' capabilities, got %+v", fieldsMap)
	}
}

func TestRound31_TypedKeysMSearchParamsValidateAndExplain(t *testing.T) {
	srv, _ := newTestServer()

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"tk_r31","_id":"1"}}`,
		`{"cat":"books","price":25}`,
		`{"index":{"_index":"tk_r31","_id":"2"}}`,
		`{"cat":"games","price":60}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk tk_r31 failed: %d", code)
	}

	// Fix 14a: _search?typed_keys=true
	code, tkResp := doRound27Req(t, srv, http.MethodPost, "/tk_r31/_search?typed_keys=true", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_cat": map[string]any{
				"terms": map[string]any{"field": "cat"},
				"aggs": map[string]any{
					"avg_price": map[string]any{"avg": map[string]any{"field": "price"}},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("_search?typed_keys=true failed: %d (%v)", code, tkResp)
	}
	tkAggs := tkResp["aggregations"].(map[string]any)
	byCat, ok := tkAggs["sterms#by_cat"].(map[string]any)
	if !ok {
		t.Fatalf("expected sterms#by_cat in typed_keys aggregations, got %+v", tkAggs)
	}
	firstBucket := byCat["buckets"].([]any)[0].(map[string]any)
	if firstBucket["avg#avg_price"] == nil {
		t.Fatalf("expected avg#avg_price in nested typed_keys bucket, got %+v", firstBucket)
	}

	// Fix 14b: _msearch with search_type=count, rest_total_hits_as_int=true, and typed_keys=true
	msearchNDJSON := strings.Join([]string{
		`{"index":"tk_r31","search_type":"count"}`,
		`{"query":{"match_all":{}},"aggs":{"max_p":{"max":{"field":"price"}}}}`,
	}, "\n") + "\n"
	code, msResp := doRound27Req(t, srv, http.MethodPost, "/_msearch?rest_total_hits_as_int=true&typed_keys=true", msearchNDJSON)
	if code != http.StatusOK {
		t.Fatalf("_msearch failed: %d (%v)", code, msResp)
	}
	r0 := msResp["responses"].([]any)[0].(map[string]any)
	if len(r0["hits"].(map[string]any)["hits"].([]any)) != 0 {
		t.Fatalf("expected 0 hits when search_type=count in _msearch, got %+v", r0["hits"])
	}
	if _, isFloat := r0["hits"].(map[string]any)["total"].(float64); !isFloat {
		t.Fatalf("expected integer total hits when rest_total_hits_as_int=true in _msearch, got %T (%v)", r0["hits"].(map[string]any)["total"], r0["hits"].(map[string]any)["total"])
	}
	if r0["aggregations"].(map[string]any)["max#max_p"] == nil {
		t.Fatalf("expected max#max_p when typed_keys=true in _msearch, got %+v", r0["aggregations"])
	}

	// Fix 15: _validate/query?explain=true with invalid PIT and invalid pipeline buckets_path
	code, valPitResp := doRound27Req(t, srv, http.MethodPost, "/tk_r31/_validate/query?explain=true", map[string]any{
		"pit": map[string]any{"id": "!!!invalid_base64!!!"},
	})
	if code != http.StatusOK || valPitResp["valid"] != false {
		t.Fatalf("expected _validate/query with invalid pit.id to return valid:false, got code=%d resp=%+v", code, valPitResp)
	}
	code, valAggResp := doRound27Req(t, srv, http.MethodPost, "/tk_r31/_validate/query?explain=true", map[string]any{
		"aggs": map[string]any{
			"bad_deriv": map[string]any{
				"derivative": map[string]any{"buckets_path": ""},
			},
		},
	})
	if code != http.StatusOK || valAggResp["valid"] != false {
		t.Fatalf("expected _validate/query with empty pipeline buckets_path to return valid:false, got code=%d resp=%+v", code, valAggResp)
	}

	// Fix 16: _explain with boost:0, script_score, min_score, and post_filter
	code, expBoost0 := doRound27Req(t, srv, http.MethodPost, "/tk_r31/_explain/1", map[string]any{
		"query": map[string]any{
			"constant_score": map[string]any{
				"filter": map[string]any{"term": map[string]any{"cat": "books"}},
				"boost":  0.0,
			},
		},
	})
	if code != http.StatusOK || expBoost0["matched"] != true || expBoost0["explanation"].(map[string]any)["value"] != 0.0 {
		t.Fatalf("expected _explain with boost:0 to return matched:true value:0.0, got %+v", expBoost0)
	}

	code, expScript := doRound27Req(t, srv, http.MethodPost, "/tk_r31/_explain/1", map[string]any{
		"query": map[string]any{
			"script_score": map[string]any{
				"query":  map[string]any{"term": map[string]any{"cat": "books"}},
				"script": map[string]any{"source": "doc['price'].value * 2"},
			},
		},
	})
	if code != http.StatusOK || expScript["matched"] != true || expScript["explanation"].(map[string]any)["value"] != 50.0 {
		t.Fatalf("expected _explain with script_score (25*2) to return value:50.0, got %+v", expScript)
	}

	code, expPostFilter := doRound27Req(t, srv, http.MethodPost, "/tk_r31/_explain/1", map[string]any{
		"query":       map[string]any{"term": map[string]any{"cat": "books"}},
		"post_filter": map[string]any{"term": map[string]any{"cat": "games"}},
	})
	if code != http.StatusOK || expPostFilter["matched"] != false {
		t.Fatalf("expected _explain rejected by post_filter to return matched:false, got %+v", expPostFilter)
	}
}

func TestRound31_UpdateMetadataIngestCtxOpComposableTemplatesAndProcessors(t *testing.T) {
	srv, _ := newTestServer()

	// Fix 23: Composable _component_template + _index_template priority + aliases
	code, _ := doRound27Req(t, srv, http.MethodPut, "/_component_template/ct_r31_base", map[string]any{
		"template": map[string]any{
			"settings": map[string]any{"number_of_shards": 3},
			"mappings": map[string]any{
				"properties": map[string]any{
					"base_field": map[string]any{"type": "keyword"},
				},
			},
			"aliases": map[string]any{
				"r31_alias_base": map[string]any{},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("put _component_template failed: %d", code)
	}

	// Lower-priority template (priority 10)
	code, _ = doRound27Req(t, srv, http.MethodPut, "/_index_template/tpl_r31_low", map[string]any{
		"index_patterns": []any{"r31-logs-*"},
		"priority":       10,
		"template": map[string]any{
			"mappings": map[string]any{
				"properties": map[string]any{
					"conflict_field": map[string]any{"type": "long"},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("put tpl_r31_low failed: %d", code)
	}

	// Higher-priority template (priority 100) composed of ct_r31_base
	code, _ = doRound27Req(t, srv, http.MethodPut, "/_index_template/tpl_r31_high", map[string]any{
		"index_patterns": []any{"r31-logs-*"},
		"priority":       100,
		"composed_of":    []any{"ct_r31_base"},
		"template": map[string]any{
			"mappings": map[string]any{
				"properties": map[string]any{
					"conflict_field": map[string]any{"type": "keyword"},
				},
			},
			"aliases": map[string]any{
				"r31_alias_high": map[string]any{},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("put tpl_r31_high failed: %d", code)
	}

	code, _ = doRound27Req(t, srv, http.MethodPut, "/r31-logs-000001", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("create r31-logs-000001 failed: %d", code)
	}

	code, idxResp := doRound27Req(t, srv, http.MethodGet, "/r31-logs-000001", nil)
	if code != http.StatusOK {
		t.Fatalf("get r31-logs-000001 failed: %d", code)
	}
	idxEntry := idxResp["r31-logs-000001"].(map[string]any)
	props := idxEntry["mappings"].(map[string]any)["properties"].(map[string]any)
	if props["base_field"] == nil || props["conflict_field"].(map[string]any)["type"] != "keyword" {
		t.Fatalf("expected composed_of base_field and high-priority conflict_field=keyword, got %+v", props)
	}
	aliases := idxEntry["aliases"].(map[string]any)
	if aliases["r31_alias_base"] == nil || aliases["r31_alias_high"] == nil {
		t.Fatalf("expected template aliases r31_alias_base and r31_alias_high applied, got %+v", aliases)
	}

	// Fix 21: ctx._id, ctx._index, and ctx._version in _update and _update_by_query
	code, _ = doRound27Req(t, srv, http.MethodPut, "/r31-logs-000001/_doc/doc-1?refresh=true", map[string]any{
		"conflict_field": "init",
	})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("index doc-1 failed: %d", code)
	}
	code, _ = doRound27Req(t, srv, http.MethodPost, "/r31-logs-000001/_update/doc-1?refresh=true", map[string]any{
		"script": map[string]any{
			"source": "ctx._source.meta_tag = ctx._index + '/' + ctx._id + '/v' + ctx._version",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("_update doc-1 failed: %d", code)
	}
	code, getDoc := doRound27Req(t, srv, http.MethodGet, "/r31-logs-000001/_doc/doc-1", nil)
	if code != http.StatusOK {
		t.Fatalf("get doc-1 failed: %d", code)
	}
	src := getDoc["_source"].(map[string]any)
	metaTag, _ := src["meta_tag"].(string)
	if !strings.HasPrefix(metaTag, "r31-logs-000001/doc-1/v") || metaTag == "r31-logs-000001/doc-1/vnil" || metaTag == "r31-logs-000001/doc-1/v0" {
		t.Fatalf("expected meta_tag to start with 'r31-logs-000001/doc-1/v<positive>', got %v", src["meta_tag"])
	}

	// Fix 22 & Fix 24: Ingest script ctx.op document field, dissect target_field, and csv ignore_missing default false
	code, simResp := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"script": map[string]any{
						"source": "if (ctx.op == 'create') { ctx.op = 'insert'; }",
					},
				},
				map[string]any{
					"dissect": map[string]any{
						"field":        "line",
						"pattern":      "%{host} %{code}",
						"target_field": "parsed",
					},
				},
				map[string]any{
					"csv": map[string]any{
						"field":         "csv_line",
						"target_fields": []any{"col1", "col2"},
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_index": "r31-logs-000001",
				"_id":    "sim-1",
				"_source": map[string]any{
					"op":       "create",
					"line":     "web01 200",
					"csv_line": "alpha,beta",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("_simulate failed: %d (%v)", code, simResp)
	}
	simDoc := simResp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if simDoc["op"] != "insert" {
		t.Fatalf("expected ctx.op document field updated to 'insert', got %v", simDoc["op"])
	}
	parsedMap, ok := simDoc["parsed"].(map[string]any)
	if !ok || parsedMap["host"] != "web01" || parsedMap["code"] != "200" {
		t.Fatalf("expected dissect target_field 'parsed' map {host:web01, code:200}, got %+v", simDoc["parsed"])
	}
	if simDoc["col1"] != "alpha" || simDoc["col2"] != "beta" {
		t.Fatalf("expected csv col1=alpha col2=beta, got %+v", simDoc)
	}

	// csv with missing field and default ignore_missing:false should record error in _simulate
	code, csvErrResp := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"csv": map[string]any{
						"field":         "missing_csv",
						"target_fields": []any{"a", "b"},
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_index":  "r31-logs-000001",
				"_id":     "sim-err",
				"_source": map[string]any{"other": "val"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("_simulate csv missing field failed: %d", code)
	}
	simErrEntry := csvErrResp["docs"].([]any)[0].(map[string]any)
	if simErrEntry["error"] == nil {
		t.Fatalf("expected csv processor with default ignore_missing:false to fail on missing field, got %+v", simErrEntry)
	}
}
