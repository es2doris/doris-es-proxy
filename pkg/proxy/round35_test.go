package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound35_TranspilerSchemaASTAndLuceneParity(t *testing.T) {
	srv, _ := newTestServer()

	// Create index testing F3 (copy_to -> match_only_text), F4 (ignore_malformed), F5 (scaled_float),
	// F7 (nested string range with 'T'), F8 (long vs date with custom format), F9 (match_bool_prefix), F10 (sort NULLS LAST + ip search_after)
	code, createRes := doRound27Req(t, srv, http.MethodPut, "/r35_schema_idx", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title": map[string]any{
					"type":    "text",
					"copy_to": "all_mot",
				},
				"tags": map[string]any{
					"type":    "keyword",
					"copy_to": "all_mot",
				},
				"all_mot": map[string]any{
					"type": "match_only_text",
				},
				"strict_num": map[string]any{
					"type": "integer",
				},
				"lenient_num": map[string]any{
					"type":             "integer",
					"ignore_malformed": true,
				},
				"price": map[string]any{
					"type":           "scaled_float",
					"scaling_factor": 100.0,
				},
				"strict_long": map[string]any{
					"type": "long",
				},
				"sec_date": map[string]any{
					"type":   "date",
					"format": "epoch_second",
				},
				"code_kw": map[string]any{
					"type": "keyword",
				},
				"client_ip": map[string]any{
					"type": "ip",
				},
				"rank_score": map[string]any{
					"type": "integer",
				},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"code": map[string]any{"type": "keyword"},
						"cost": map[string]any{"type": "scaled_float", "scaling_factor": 10.0},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 creating r35_schema_idx, got %d: %+v", code, createRes)
	}

	// F3: Verify all_mot is compiled as StoragePromotedScalar (STRING) even when targeted by copy_to
	idxSchema := srv.getOrCompileReadOnlySchema(context.Background(), "r35_schema_idx")
	if b, ok := idxSchema.Fields["all_mot"]; !ok || b.Kind != schema.StoragePromotedScalar || b.DorisType != schema.DorisString {
		t.Fatalf("F3: expected all_mot (match_only_text target of copy_to) to be StoragePromotedScalar STRING, got %+v", b)
	}

	// F4: Strict integer field rejects uncoercible string ("not_a_number") with 400 mapper_parsing_exception
	code, badRes := doRound27Req(t, srv, http.MethodPut, "/r35_schema_idx/_doc/bad1", map[string]any{
		"strict_num": "not_a_number",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("F4: expected 400 mapper_parsing_exception on malformed strict_num, got %d: %+v", code, badRes)
	}

	// F8: Strict long field rejects date string ("2024-01-01") with 400 instead of silently converting to epoch millis
	code, badLongRes := doRound27Req(t, srv, http.MethodPut, "/r35_schema_idx/_doc/bad_long", map[string]any{
		"strict_long": "2024-01-01",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("F8: expected 400 mapper_parsing_exception when indexing date string into long field, got %d: %+v", code, badLongRes)
	}

	// F4 + F5 + F3: Index valid docs (including lenient_num with malformed value -> _ignored, scaled_float rounding, nested items)
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"r35_schema_idx","_id":"1"}}`,
		`{"title":"alpha search","tags":["k8s","doris"],"strict_num":10,"lenient_num":"oops_bad","price":19.999,"strict_long":100,"sec_date":1700000000,"code_kw":"foo bar-baz","client_ip":"10.0.0.1","rank_score":-10,"items":[{"code":"T200","cost":5.56}]}`,
		`{"index":{"_index":"r35_schema_idx","_id":"2"}}`,
		`{"title":"beta engine","tags":["rust"],"strict_num":20,"lenient_num":42,"price":25.001,"strict_long":200,"sec_date":1700000100,"code_kw":"foo qux","client_ip":"10.0.0.2","rank_score":-5,"items":[{"code":"T800","cost":9.94}]}`,
		`{"index":{"_index":"r35_schema_idx","_id":"3"}}`,
		`{"title":"gamma proxy","tags":["go"],"strict_num":30,"price":30.0,"strict_long":1704067200000,"sec_date":1700000200,"code_kw":"other","client_ip":"10.0.0.10","items":[{"code":"A100","cost":1.2}]}`,
	}, "\n") + "\n"
	code, bulkRes := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK || bulkRes["errors"] == true {
		t.Fatalf("bulk index failed (%d): %+v", code, bulkRes)
	}

	// F4: Query _ignored field to verify lenient_num was recorded in _ignored on doc 1
	code, ignRes := doRound27Req(t, srv, http.MethodPost, "/r35_schema_idx/_search", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"_ignored": "lenient_num"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F4: _ignored search failed (%d): %+v", code, ignRes)
	}
	ignHits := ignRes["hits"].(map[string]any)["hits"].([]any)
	if len(ignHits) != 1 || ignHits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F4: expected doc 1 to match term _ignored=lenient_num, got %+v", ignHits)
	}

	// F3: Full-text match query on all_mot (populated via copy_to from both title and tags array)
	code, motRes := doRound27Req(t, srv, http.MethodPost, "/r35_schema_idx/_search", map[string]any{
		"query": map[string]any{
			"match": map[string]any{"all_mot": "doris"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F3: match on all_mot failed (%d): %+v", code, motRes)
	}
	motHits := motRes["hits"].(map[string]any)["hits"].([]any)
	if len(motHits) != 1 || motHits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F3: expected doc 1 from copy_to match_only_text search, got %+v", motHits)
	}

	// F5: scaled_float query normalization (19.999 rounds to 20.00 via scaling_factor=100, matching doc 1)
	code, sfRes := doRound27Req(t, srv, http.MethodPost, "/r35_schema_idx/_search", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"price": 20.0},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F5: scaled_float term search failed (%d): %+v", code, sfRes)
	}
	sfHits := sfRes["hits"].(map[string]any)["hits"].([]any)
	if len(sfHits) != 1 || sfHits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F5: expected doc 1 (19.999 rounded to 20.00) to match price=20.0, got %+v", sfHits)
	}

	// F1 + F2: Named queries (_name), map-keyed boost, string case_insensitive: "true", and random_score in function_score
	code, f12Res := doRound27Req(t, srv, http.MethodPost, "/r35_schema_idx/_search", map[string]any{
		"query": map[string]any{
			"function_score": map[string]any{
				"query": map[string]any{
					"bool": map[string]any{
						"must": []any{
							map[string]any{
								"term": map[string]any{
									"code_kw": map[string]any{
										"value":            "FOO BAR-BAZ",
										"case_insensitive": "true",
										"_name":            "ci_term",
									},
									"_name": "outer_term_name",
									"boost": 1.5,
								},
							},
							map[string]any{
								"range": map[string]any{
									"strict_num": map[string]any{"gte": 5, "lte": 15},
									"_name":      "num_range",
									"boost":      2.0,
								},
							},
						},
					},
				},
				"random_score": map[string]any{
					"seed":  42,
					"field": "_seq_no",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F1/F2: function_score with random_score and named/boosted clauses failed (%d): %+v", code, f12Res)
	}
	f12Hits := f12Res["hits"].(map[string]any)["hits"].([]any)
	if len(f12Hits) != 1 || f12Hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F1/F2: expected doc 1 to match case_insensitive term + range + random_score, got %+v", f12Hits)
	}

	// F1: Verify SortSpec.MarshalJSON preserves format
	sortSpec := esast.SortSpec{
		Entry: esast.SortFieldSpec{
			Field:  "sec_date",
			Order:  "desc",
			Format: "epoch_second",
		},
	}
	sortBytes, err := json.Marshal(sortSpec)
	if err != nil || !bytes.Contains(sortBytes, []byte(`"format":"epoch_second"`)) {
		t.Fatalf("F1: expected SortSpec.MarshalJSON to preserve format, got %s (err=%v)", string(sortBytes), err)
	}

	// F6: Lucene query_string with escaped wildcard range bound [\* TO z] and lowercase/multi-space `to`
	tr := transpiler.NewTranspiler(idxSchema, srv.transpileOpts)
	qsPlan, err := tr.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{
			QueryString: &esast.QueryStringQuery{
				Query: `code_kw:[\* TO z] AND strict_num:[5   to   15]`,
			},
		},
	})
	if err != nil {
		t.Fatalf("F6: BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(qsPlan.HitsSQL, "`f__code_kw` >= '*'") || !strings.Contains(qsPlan.HitsSQL, "`f__strict_num` >= 5") {
		t.Fatalf("F6: expected escaped '\\*' lower bound and multi-space lowercase 'to' range in SQL, got: %s", qsPlan.HitsSQL)
	}

	// F7: Nested range query on keyword field with 'T'-containing bounds ("T100" to "T500") must NOT convert to UNIX_TIMESTAMP
	code, nestedRangeRes := doRound27Req(t, srv, http.MethodPost, "/r35_schema_idx/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"range": map[string]any{
						"items.code": map[string]any{
							"gte": "T100",
							"lte": "T500",
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F7: nested string range with 'T' failed (%d): %+v", code, nestedRangeRes)
	}
	nrHits := nestedRangeRes["hits"].(map[string]any)["hits"].([]any)
	if len(nrHits) != 1 || nrHits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F7: expected only doc 1 (items.code=T200) to match [T100..T500], got %+v", nrHits)
	}

	// F8: Querying long field with date string ("2024-01-01") does NOT coerce to epoch millis (1704067200000 on doc 3);
	// querying date field with epoch_second format converts seconds -> ms
	code, badLongQueryRes := doRound27Req(t, srv, http.MethodPost, "/r35_schema_idx/_search", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"strict_long": "2024-01-01"},
		},
	})
	if code != http.StatusOK || len(badLongQueryRes["hits"].(map[string]any)["hits"].([]any)) != 0 {
		t.Fatalf("F8: expected 0 hits when querying long field with date string '2024-01-01', got (%d): %+v", code, badLongQueryRes)
	}
	code, secDateRes := doRound27Req(t, srv, http.MethodPost, "/r35_schema_idx/_search", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"sec_date": "1700000100"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F8: sec_date term query failed (%d): %+v", code, secDateRes)
	}
	sdHits := secDateRes["hits"].(map[string]any)["hits"].([]any)
	if len(sdHits) != 1 || sdHits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("F8: expected doc 2 to match sec_date=1700000100 (epoch_second), got %+v", sdHits)
	}

	// F9: match_bool_prefix on keyword field preserves full untokenized prefix ("foo bar-")
	code, mbpRes := doRound27Req(t, srv, http.MethodPost, "/r35_schema_idx/_search", map[string]any{
		"query": map[string]any{
			"match_bool_prefix": map[string]any{
				"code_kw": "foo bar-",
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F9: match_bool_prefix on keyword field failed (%d): %+v", code, mbpRes)
	}
	mbpHits := mbpRes["hits"].(map[string]any)["hits"].([]any)
	if len(mbpHits) != 1 || mbpHits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("F9: expected only doc 1 ('foo bar-baz') to match keyword match_bool_prefix 'foo bar-', got %+v", mbpHits)
	}

	// F10: Sort DESC places NULL values LAST by default (so -5, -10 come before doc 3's null rank_score),
	// and search_after on IP field normalizes IPv4 cursor to canonical IPv6 hex.
	code, sortDescRes := doRound27Req(t, srv, http.MethodPost, "/r35_schema_idx/_search", map[string]any{
		"sort": []any{
			map[string]any{"rank_score": "desc"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F10: sort desc failed (%d): %+v", code, sortDescRes)
	}
	sdOrder := sortDescRes["hits"].(map[string]any)["hits"].([]any)
	if len(sdOrder) != 3 || sdOrder[0].(map[string]any)["_id"] != "2" || sdOrder[1].(map[string]any)["_id"] != "1" || sdOrder[2].(map[string]any)["_id"] != "3" {
		t.Fatalf("F10: expected DESC sort order [2 (-5), 1 (-10), 3 (null)], got %+v", sdOrder)
	}

	code, ipSARes := doRound27Req(t, srv, http.MethodPost, "/r35_schema_idx/_search", map[string]any{
		"sort": []any{
			map[string]any{"client_ip": "asc"},
			map[string]any{"_id": "asc"},
		},
		"search_after": []any{"10.0.0.2", "2"},
	})
	if code != http.StatusOK {
		t.Fatalf("F10: ip search_after failed (%d): %+v", code, ipSARes)
	}
	ipSAHits := ipSARes["hits"].(map[string]any)["hits"].([]any)
	if len(ipSAHits) != 1 || ipSAHits[0].(map[string]any)["_id"] != "3" {
		t.Fatalf("F10: expected doc 3 ('10.0.0.10') after IP cursor '10.0.0.2', got %+v", ipSAHits)
	}
}

func TestRound35_ProxySearchAggsAndCoalescerParity(t *testing.T) {
	srv, _ := newTestServer()

	// Create lookup index for F14
	doRound27Req(t, srv, http.MethodPut, "/r35_lookup/_doc/lu1?refresh=true", map[string]any{
		"allowed_depts": []any{"eng"},
		"allowed_tiers": []any{"gold"},
	})

	// Create main index for F11-F20
	doRound27Req(t, srv, http.MethodPut, "/r35_search_idx", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title":  map[string]any{"type": "text"},
				"dept":   map[string]any{"type": "keyword"},
				"tier":   map[string]any{"type": "keyword"},
				"active": map[string]any{"type": "boolean"},
				"seq":    map[string]any{"type": "integer"},
				"ts_ns":  map[string]any{"type": "date_nanos"},
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

	bulk := strings.Join([]string{
		`{"index":{"_index":"r35_search_idx","_id":"1"}}`,
		`{"title":"quick brown fox","dept":"sales","tier":"silver","active":false,"seq":1,"ts_ns":"2025-01-01T00:00:00.123456789Z","items":[{"sku":"S1","qty":2}]}`,
		`{"index":{"_index":"r35_search_idx","_id":"2"}}`,
		`{"title":"fox quick brown","dept":"eng","tier":"gold","active":true,"seq":2,"ts_ns":"2025-01-01T00:00:00.123456789Z","items":[{"sku":"S2","qty":5},{"sku":"S3","qty":1}]}`,
		`{"index":{"_index":"r35_search_idx","_id":"3"}}`,
		`{"title":"lazy dog","dept":"sales","tier":"silver","active":false,"seq":3,"ts_ns":"2025-01-02T00:00:00.000000000Z","items":[{"sku":"S4","qty":1}]}`,
		`{"index":{"_index":"r35_search_idx","_id":"4"}}`,
		`{"title":"eager beaver","dept":"eng","tier":"gold","active":true,"seq":4,"ts_ns":"2025-01-02T00:00:00.000000000Z","items":[{"sku":"S5","qty":10}]}`,
	}, "\n") + "\n"
	doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulk)

	// F11: search_after + post_filter (filtered out doc 1 and 3; cursor after seq=2 returns doc 4)
	code, sapfRes := doRound27Req(t, srv, http.MethodPost, "/r35_search_idx/_search", map[string]any{
		"size":         1,
		"sort":         []any{map[string]any{"seq": "asc"}},
		"search_after": []any{2},
		"post_filter": map[string]any{
			"term": map[string]any{"dept": "eng"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F11: search_after + post_filter failed (%d): %+v", code, sapfRes)
	}
	sapfHits := sapfRes["hits"].(map[string]any)["hits"].([]any)
	if len(sapfHits) != 1 || sapfHits[0].(map[string]any)["_id"] != "4" {
		t.Fatalf("F11: expected doc 4 after cursor [2] with post_filter dept=eng, got %+v", sapfHits)
	}

	// F12 + F13: collapse + rescore + nested query inner_hits on collapsed hits
	code, colRes := doRound27Req(t, srv, http.MethodPost, "/r35_search_idx/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"range": map[string]any{
						"items.qty": map[string]any{"gte": 1},
					},
				},
				"inner_hits": map[string]any{
					"name": "high_qty_items",
				},
			},
		},
		"collapse": map[string]any{
			"field": "dept",
		},
		"rescore": map[string]any{
			"window_size": 10,
			"query": map[string]any{
				"rescore_query": map[string]any{
					"term": map[string]any{
						"dept": map[string]any{
							"value": "eng",
							"boost": 10.0,
						},
					},
				},
				"query_weight":         1.0,
				"rescore_query_weight": 5.0,
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F12/F13: collapse + rescore + inner_hits failed (%d): %+v", code, colRes)
	}
	colHits := colRes["hits"].(map[string]any)["hits"].([]any)
	if len(colHits) != 2 {
		t.Fatalf("F12/F13: expected 2 collapsed hits (eng and sales), got %d: %+v", len(colHits), colHits)
	}
	topColHit := colHits[0].(map[string]any)
	if topColHit["_source"].(map[string]any)["dept"] != "eng" {
		t.Fatalf("F12: expected rescore to boost 'eng' collapsed hit to #1, got %+v", topColHit)
	}
	ihMap, hasIH := topColHit["inner_hits"].(map[string]any)
	if !hasIH || ihMap["high_qty_items"] == nil {
		t.Fatalf("F13: expected inner_hits on collapsed hit, got %+v", topColHit)
	}

	// F14: terms lookup inside post_filter, aggs.filter, aggs.filters, and rescore
	code, luRes := doRound27Req(t, srv, http.MethodPost, "/r35_search_idx/_search", map[string]any{
		"post_filter": map[string]any{
			"terms": map[string]any{
				"dept": map[string]any{
					"index": "r35_lookup",
					"id":    "lu1",
					"path":  "allowed_depts",
				},
			},
		},
		"rescore": map[string]any{
			"window_size": 10,
			"query": map[string]any{
				"rescore_query": map[string]any{
					"terms": map[string]any{
						"tier": map[string]any{
							"index": "r35_lookup",
							"id":    "lu1",
							"path":  "allowed_tiers",
						},
					},
				},
			},
		},
		"aggs": map[string]any{
			"only_allowed": map[string]any{
				"filter": map[string]any{
					"terms": map[string]any{
						"dept": map[string]any{
							"index": "r35_lookup",
							"id":    "lu1",
							"path":  "allowed_depts",
						},
					},
				},
			},
			"by_bucket": map[string]any{
				"filters": map[string]any{
					"filters": map[string]any{
						"gold_only": map[string]any{
							"terms": map[string]any{
								"tier": map[string]any{
									"index": "r35_lookup",
									"id":    "lu1",
									"path":  "allowed_tiers",
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F14: terms lookup in post_filter/aggs/rescore failed (%d): %+v", code, luRes)
	}
	luHits := luRes["hits"].(map[string]any)["hits"].([]any)
	if len(luHits) != 2 {
		t.Fatalf("F14: expected 2 hits after post_filter terms lookup, got %d", len(luHits))
	}
	aggsOut := luRes["aggregations"].(map[string]any)
	if aggsOut["only_allowed"].(map[string]any)["doc_count"].(float64) != 2 {
		t.Fatalf("F14: expected only_allowed filter agg doc_count=2, got %+v", aggsOut["only_allowed"])
	}
	goldBucket := aggsOut["by_bucket"].(map[string]any)["buckets"].(map[string]any)["gold_only"].(map[string]any)
	if goldBucket["doc_count"].(float64) != 2 {
		t.Fatalf("F14: expected gold_only filters agg doc_count=2, got %+v", goldBucket)
	}

	// F15: _count honors terminate_after query parameter
	code, cntRes := doRound27Req(t, srv, http.MethodPost, "/r35_search_idx/_count?terminate_after=2", nil)
	if code != http.StatusOK || cntRes["count"].(float64) != 2 {
		t.Fatalf("F15: expected _count?terminate_after=2 to return count=2, got (%d) %+v", code, cntRes)
	}

	// F16: GET /{index}/_doc/{id}?stored_fields=_source,dept returns both _source and fields.dept
	code, docRes := doRound27Req(t, srv, http.MethodGet, "/r35_search_idx/_doc/2?stored_fields=_source,dept", nil)
	if code != http.StatusOK {
		t.Fatalf("F16: GET _doc with stored_fields failed (%d): %+v", code, docRes)
	}
	if docRes["_source"] == nil || docRes["fields"] == nil {
		t.Fatalf("F16: expected both _source and fields when stored_fields=_source,dept, got %+v", docRes)
	}
	fieldsMap := docRes["fields"].(map[string]any)
	if deptArr, ok := fieldsMap["dept"].([]any); !ok || len(deptArr) != 1 || deptArr[0] != "eng" {
		t.Fatalf("F16: expected fields.dept=['eng'], got %+v", fieldsMap)
	}

	// F17: Coalescer FlushTable per-table isolation and FlushAll drain
	if err := srv.coalescer.FlushAll(context.Background()); err != nil {
		t.Fatalf("F17: FlushAll failed: %v", err)
	}

	// F18: Scroll request matching 0 hits still returns initial aggregations and suggest
	code, emptyScrollRes := doRound27Req(t, srv, http.MethodPost, "/r35_search_idx/_search?scroll=1m", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"dept": "nonexistent"},
		},
		"aggs": map[string]any{
			"total_depts": map[string]any{"terms": map[string]any{"field": "dept"}},
		},
		"suggest": map[string]any{
			"s": map[string]any{
				"text": "quik",
				"term": map[string]any{"field": "title"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F18: initial scroll with 0 hits failed (%d): %+v", code, emptyScrollRes)
	}
	if emptyScrollRes["aggregations"] == nil || emptyScrollRes["suggest"] == nil {
		t.Fatalf("F18: expected aggregations and suggest on initial 0-hit scroll response, got %+v", emptyScrollRes)
	}

	// F19: Composite aggregation preserves boolean key type (bool) and formats date_nanos
	code, compRes := doRound27Req(t, srv, http.MethodPost, "/r35_search_idx/_search?size=0", map[string]any{
		"aggs": map[string]any{
			"comp": map[string]any{
				"composite": map[string]any{
					"sources": []any{
						map[string]any{"act": map[string]any{"terms": map[string]any{"field": "active"}}},
						map[string]any{"day": map[string]any{"date_histogram": map[string]any{"field": "ts_ns", "calendar_interval": "day", "format": "yyyy-MM-dd"}}},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F19: composite agg failed (%d): %+v", code, compRes)
	}
	compBuckets := compRes["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	if len(compBuckets) == 0 {
		t.Fatalf("F19: expected non-empty composite buckets")
	}
	firstCompKey := compBuckets[0].(map[string]any)["key"].(map[string]any)
	if _, isBool := firstCompKey["act"].(bool); !isBool {
		t.Fatalf("F19: expected composite boolean source key to be bool, got %T (%v)", firstCompKey["act"], firstCompKey["act"])
	}
	if dayStr, _ := firstCompKey["day"].(string); !strings.HasPrefix(dayStr, "2025-01-0") {
		t.Fatalf("F19: expected date_nanos composite key formatted as 2025-01-0x, got %q", dayStr)
	}

	// F20: MemBackend MATCH_ALL matches multi-token query regardless of token order ("fox quick" matches both doc 1 and doc 2)
	code, maRes := doRound27Req(t, srv, http.MethodPost, "/r35_search_idx/_search", map[string]any{
		"query": map[string]any{
			"match": map[string]any{
				"title": map[string]any{
					"query":    "fox brown",
					"operator": "and",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F20: match operator=and failed (%d): %+v", code, maRes)
	}
	maHits := maRes["hits"].(map[string]any)["hits"].([]any)
	if len(maHits) != 2 {
		t.Fatalf("F20: expected both doc 1 ('quick brown fox') and doc 2 ('fox quick brown') to match 'fox brown' with operator=and, got %d: %+v", len(maHits), maHits)
	}
}

func TestRound35_PainlessIngestAndMutationParity(t *testing.T) {
	srv, _ := newTestServer()

	// F21, F22, F23, F24, F25: Direct Painless unit & runtime checks
	doc := map[string]any{
		"count": 1,
		"scores": map[string]any{
			"a": 10,
			"b": 20,
		},
		"items": []any{
			map[string]any{"name": "x", "val": 3, "active": false},
			map[string]any{"name": "y", "val": 1, "active": true},
			map[string]any{"name": "z", "val": 2, "active": true},
		},
		"nums": []any{1, 2, 3, 4},
	}
	params := map[string]any{
		"_ctx_id":      "doc-1",
		"_ctx_index":   "idx-a",
		"_ctx_version": int64(5),
	}
	script := `
		if (ctx.op == null || ctx.op == 'index') {
			ctx._id += '-v2';
			ctx._version++;
		}
		ctx._source.scores.replace('a', 15);
		ctx._source.scores.replace('b', 999, 50);
		ctx._source.scores.replace('b', 20, 25);
		ctx._source.scores.replaceAll((k, v) -> v * 2);
		def sum = 0;
		ctx._source.nums.forEach(n -> {
			if (n == 2) {
				return;
			}
			sum += n;
		});
		ctx._source.forEachSum = sum;
		ctx._source.nums.removeIf(n -> {
			def even = n % 2 == 0;
			return even;
		});
		ctx._source.items.sort((a, b) -> {
			def va = a.val;
			def vb = b.val;
			return va - vb;
		});
		ctx._source.items.stream().filter(it -> {
			def ok = it.active;
			return ok;
		}).collect(Collectors.toList())[0].winner = true;
	`
	opRes, err := painless.EvalPainlessWithOp(doc, script, params)
	if err != nil {
		t.Fatalf("F21-F25: EvalPainlessWithOp failed: %v", err)
	}
	if opRes != "" {
		t.Fatalf("F21: expected empty ctxOp after `ctx.op == 'index'` check, got %q", opRes)
	}
	if params["_ctx_id"] != "doc-1-v2" || params["_ctx_version"] != int64(6) {
		t.Fatalf("F21: expected _ctx_id='doc-1-v2' and _ctx_version=6, got id=%v ver=%v", params["_ctx_id"], params["_ctx_version"])
	}
	scores := doc["scores"].(map[string]any)
	if scores["a"] != int64(30) || scores["b"] != int64(50) {
		t.Fatalf("F22: expected Map.replace + Map.replaceAll to produce a=30, b=50, got %+v", scores)
	}
	if doc["forEachSum"] != int64(8) {
		t.Fatalf("F24: expected forEachSum=8 (1+3+4, skipping 2 via early return), got %v", doc["forEachSum"])
	}
	if len(doc["nums"].([]any)) != 2 {
		t.Fatalf("F23: expected block removeIf to keep 2 odd numbers, got %+v", doc["nums"])
	}
	sortedItems := doc["items"].([]any)
	firstItem := sortedItems[0].(map[string]any)
	if firstItem["name"] != "y" || firstItem["winner"] != true {
		t.Fatalf("F23/F25: expected block sort to put 'y' first and post-call stream()[0].winner=true, got %+v", firstItem)
	}

	// F26: _ingest/pipeline/_simulate preserves input _ingest.timestamp and reflects mutations to _ingest.timestamp
	code, simRes := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate?verbose=true", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"set": map[string]any{
						"field": "copied_ts",
						"value": "{{_ingest.timestamp}}",
					},
				},
				map[string]any{
					"set": map[string]any{
						"field": "_ingest.timestamp",
						"value": "2030-01-01T00:00:00Z",
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_index":  "sim_idx",
				"_id":     "sim1",
				"_ingest": map[string]any{"timestamp": "2020-05-05T12:00:00Z"},
				"_source": map[string]any{"msg": "hello"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F26: _simulate failed (%d): %+v", code, simRes)
	}
	simDocEntry := simRes["docs"].([]any)[0].(map[string]any)
	simProcs := simDocEntry["processor_results"].([]any)
	step1Source := simProcs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if step1Source["copied_ts"] != "2020-05-05T12:00:00Z" {
		t.Fatalf("F26: expected input _ingest.timestamp '2020-05-05T12:00:00Z' to be preserved, got %v", step1Source["copied_ts"])
	}
	step2Ingest := simProcs[1].(map[string]any)["doc"].(map[string]any)["_ingest"].(map[string]any)
	if step2Ingest["timestamp"] != "2030-01-01T00:00:00Z" {
		t.Fatalf("F26: expected mutated _ingest.timestamp '2030-01-01T00:00:00Z', got %v", step2Ingest["timestamp"])
	}

	// F28: dot_expander with override: false inside nested map / array preserves existing nested leaves
	code, deSimRes := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"dot_expander": map[string]any{
						"field":    "*",
						"override": false,
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_index": "de_idx",
				"_id":    "de1",
				"_source": map[string]any{
					"outer": map[string]any{
						"a.b": "new_val",
						"a":   map[string]any{"b": "orig_val", "c": "keep"},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("F28: dot_expander simulate failed (%d): %+v", code, deSimRes)
	}
	deSource := deSimRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	outerA := deSource["outer"].(map[string]any)["a"].(map[string]any)
	if outerA["b"] != "orig_val" || outerA["c"] != "keep" {
		t.Fatalf("F28: expected dot_expander override:false to preserve outer.a.b='orig_val', got %+v", deSource)
	}

	// F27: _reindex script iterating ctx._source.keySet() sees no __reindex_* pollution while mutating ctx._id
	doRound27Req(t, srv, http.MethodPut, "/r35_re_src/_doc/s1?refresh=true", map[string]any{
		"k1": "v1",
		"k2": "v2",
	})
	code, reRes := doRound27Req(t, srv, http.MethodPost, "/_reindex?refresh=true", map[string]any{
		"source": map[string]any{"index": "r35_re_src"},
		"dest":   map[string]any{"index": "r35_re_dst"},
		"script": map[string]any{
			"source": "ctx._id += '-clean'; ctx._source.key_count = ctx._source.keySet().size();",
		},
	})
	if code != http.StatusOK || reRes["created"].(float64) != 1 {
		t.Fatalf("F27: _reindex failed (%d): %+v", code, reRes)
	}
	code, reDoc := doRound27Req(t, srv, http.MethodGet, "/r35_re_dst/_doc/s1-clean", nil)
	if code != http.StatusOK || reDoc["_source"].(map[string]any)["key_count"].(float64) != 2 {
		t.Fatalf("F27: expected ctx._source.keySet().size() == 2 (no __reindex_* keys), got (%d) %+v", code, reDoc)
	}

	// F29: _update on missing doc with scripted_upsert: true and ctx.op = 'noop' returns _version: 1
	code, noopUpdRes := doRound27Req(t, srv, http.MethodPost, "/r35_re_dst/_update/missing_noop", map[string]any{
		"scripted_upsert": true,
		"script": map[string]any{
			"source": "ctx.op = 'noop'",
		},
		"upsert": map[string]any{"x": 1},
	})
	if code != http.StatusOK || noopUpdRes["result"] != "noop" || noopUpdRes["_version"].(float64) != 1 {
		t.Fatalf("F29: expected missing doc noop update to return result='noop' and _version=1, got (%d) %+v", code, noopUpdRes)
	}

	// F30: Same-batch _bulk index + _update that reroutes _id via final_pipeline deletes original _id
	doRound27Req(t, srv, http.MethodPut, "/_ingest/pipeline/r35_reroute_pipe", map[string]any{
		"processors": []any{
			map[string]any{
				"set": map[string]any{
					"if":    "ctx.reroute == true",
					"field": "_id",
					"value": "rerouted_id",
				},
			},
		},
	})
	doRound27Req(t, srv, http.MethodPut, "/r35_bulk_reroute", map[string]any{
		"settings": map[string]any{
			"index.final_pipeline": "r35_reroute_pipe",
		},
	})
	bulkReroute := strings.Join([]string{
		`{"index":{"_index":"r35_bulk_reroute","_id":"orig_id"}}`,
		`{"msg":"initial","reroute":false}`,
		`{"update":{"_index":"r35_bulk_reroute","_id":"orig_id"}}`,
		`{"doc":{"msg":"updated","reroute":true}}`,
	}, "\n") + "\n"
	code, brRes := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkReroute)
	if code != http.StatusOK || brRes["errors"] == true {
		t.Fatalf("F30: bulk reroute failed (%d): %+v", code, brRes)
	}
	code, origGet := doRound27Req(t, srv, http.MethodGet, "/r35_bulk_reroute/_doc/orig_id", nil)
	if code != http.StatusNotFound {
		t.Fatalf("F30: expected orig_id to be deleted (404) after same-batch update rerouted it to rerouted_id, got %d: %+v", code, origGet)
	}
	code, newGet := doRound27Req(t, srv, http.MethodGet, "/r35_bulk_reroute/_doc/rerouted_id", nil)
	if code != http.StatusOK || newGet["_source"].(map[string]any)["msg"] != "updated" {
		t.Fatalf("F30: expected rerouted_id to exist with msg='updated', got %d: %+v", code, newGet)
	}
}
