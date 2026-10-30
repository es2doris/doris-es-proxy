package proxy

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/painless"
)

func doRound27Req(t *testing.T, srv *Server, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var reqBody []byte
	if body != nil {
		switch b := body.(type) {
		case string:
			reqBody = []byte(b)
		case []byte:
			reqBody = b
		default:
			var err error
			reqBody, err = json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var resp map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	}
	return rec.Code, resp
}

func extractHitsSlice(t *testing.T, resp map[string]any) []any {
	t.Helper()
	hitsObj, ok := resp["hits"].(map[string]any)
	if !ok {
		return nil
	}
	hitsList, _ := hitsObj["hits"].([]any)
	return hitsList
}

func TestRound27_P0_1_SchemaWideningAndCopyToCompanionNestedParity(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Dynamic schema widening: mixed date + non-date string in same batch / array widens to text/keyword
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"r27_widen","_id":"1"}}`,
		`{"event_val":"2026-01-15T10:00:00Z","mixed_arr":["2026-01-01","not_a_date"],"flag_or_str":true,"num_or_str":42}`,
		`{"index":{"_index":"r27_widen","_id":"2"}}`,
		`{"event_val":"custom_label","mixed_arr":["another_str"],"flag_or_str":"yes_str","num_or_str":"forty_two"}`,
	}, "\n") + "\n"
	code, _ := doRound27Req(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	if code != http.StatusOK {
		t.Fatalf("bulk index status = %d", code)
	}

	code, sr := doRound27Req(t, srv, http.MethodPost, "/r27_widen/_search", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"event_val.keyword": "custom_label"},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit for widened event_val.keyword=custom_label, got code=%d resp=%v", code, sr)
	}

	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_widen/_search", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"mixed_arr": "not_a_date"},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit for mixed_arr=not_a_date, got code=%d resp=%v", code, sr)
	}

	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_widen/_search", map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{"term": map[string]any{"flag_or_str.keyword": "yes_str"}},
					map[string]any{"term": map[string]any{"num_or_str.keyword": "forty_two"}},
				},
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit for widened boolean/numeric->text fields, got code=%d resp=%v", code, sr)
	}

	// 2. Promoted array copy_to populates target.keyword companion + nested copy_to honors target ignore_above & normalizer
	code, _ = doRound27Req(t, srv, http.MethodPut, "/r27_copyto", map[string]any{
		"settings": map[string]any{
			"analysis": map[string]any{
				"normalizer": map[string]any{
					"lc": map[string]any{"type": "custom", "filter": []any{"lowercase"}},
				},
			},
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"src_tags": map[string]any{
					"type":    "keyword",
					"copy_to": "all_text",
				},
				"all_text": map[string]any{
					"type": "text",
					"fields": map[string]any{
						"keyword": map[string]any{"type": "keyword"},
					},
				},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"raw_code": map[string]any{
							"type":    "keyword",
							"copy_to": []any{"items.norm_code", "items.combined_title"},
						},
						"norm_code": map[string]any{
							"type":         "keyword",
							"normalizer":   "lc",
							"ignore_above": 10,
						},
						"combined_title": map[string]any{
							"type": "text",
							"fields": map[string]any{
								"keyword": map[string]any{
									"type":         "keyword",
									"ignore_above": 8,
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create r27_copyto failed: %d", code)
	}

	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_copyto/_doc/1?refresh=true", map[string]any{
		"src_tags": []any{"Alpha-Tag", "Beta-Tag"},
		"items": []any{
			map[string]any{"raw_code": "SHORT"},
			map[string]any{"raw_code": "VERY_LONG_CODE_EXCEEDING_LIMIT"},
		},
	})

	// Querying all_text.keyword for exact multi-valued copy_to value
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_copyto/_search", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"all_text.keyword": "Alpha-Tag"},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit on all_text.keyword copy_to companion, got %v", sr)
	}

	// Nested copy_to into norm_code should be lowercased ("short") and ignore_above=10 should drop "VERY_LONG_CODE_EXCEEDING_LIMIT"
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_copyto/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"term": map[string]any{"items.norm_code": "SHORT"},
				},
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit on nested copy_to lowercased norm_code, got %v", sr)
	}

	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_copyto/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"term": map[string]any{"items.norm_code": "VERY_LONG_CODE_EXCEEDING_LIMIT"},
				},
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 0 {
		t.Fatalf("expected 0 hits on nested copy_to value exceeding ignore_above, got %v", sr)
	}

	// Nested copy_to into combined_title.keyword should honor ignore_above=8 ("SHORT" kept, "VERY_LONG..." dropped on .keyword while kept on text)
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_copyto/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"exists": map[string]any{"field": "items.combined_title.keyword"},
				},
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit for exists on items.combined_title.keyword, got %v", sr)
	}
}

func TestRound27_P0_2_NestedKeywordCompanionRoutingAliasAndMultiLevelNestedCorrelation(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound27Req(t, srv, http.MethodPut, "/r27_nested_multi", map[string]any{
		"settings": map[string]any{
			"analysis": map[string]any{
				"normalizer": map[string]any{
					"lc": map[string]any{"type": "custom", "filter": []any{"lowercase"}},
				},
			},
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"title": map[string]any{
							"type": "text",
							"fields": map[string]any{
								"keyword": map[string]any{
									"type":         "keyword",
									"normalizer":   "lc",
									"ignore_above": 12,
								},
							},
						},
						"title_kw_alias": map[string]any{
							"type": "alias",
							"path": "items.title.keyword",
						},
						"cat": map[string]any{"type": "keyword"},
						"variants": map[string]any{
							"type": "nested",
							"properties": map[string]any{
								"color": map[string]any{"type": "keyword"},
								"stock": map[string]any{"type": "integer"},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index status = %d", code)
	}

	// Doc 1: item 0 (cat=shoes) has red(stock=0) and blue(stock=10); item 1 (cat=hat) has red(stock=10)
	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_nested_multi/_doc/1?refresh=true", map[string]any{
		"items": []any{
			map[string]any{
				"title": "ShortTitle",
				"cat":   "shoes",
				"variants": []any{
					map[string]any{"color": "red", "stock": 0},
					map[string]any{"color": "blue", "stock": 10},
				},
			},
			map[string]any{
				"title": "VeryLongTitleThatExceedsTwelveChars",
				"cat":   "hat",
				"variants": []any{
					map[string]any{"color": "red", "stock": 10},
				},
			},
		},
	})

	// Doc 2: only item with LongTitle (> 12 chars), so items.title exists but items.title.keyword does NOT exist
	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_nested_multi/_doc/2?refresh=true", map[string]any{
		"items": []any{
			map[string]any{
				"title": "AnotherVeryLongTitleExceedingTwelve",
				"cat":   "coat",
				"variants": []any{
					map[string]any{"color": "red", "stock": 5},
				},
			},
		},
	})

	// 1. Term query via base nested text field (preferKeyword=true) and via alias to .keyword
	for _, fieldName := range []string{"items.title", "items.title.keyword", "items.title_kw_alias"} {
		code, sr := doRound27Req(t, srv, http.MethodPost, "/r27_nested_multi/_search", map[string]any{
			"query": map[string]any{
				"nested": map[string]any{
					"path": "items",
					"query": map[string]any{
						"term": map[string]any{fieldName: "SHORTTITLE"},
					},
				},
			},
		})
		if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
			t.Fatalf("expected 1 hit for %s=SHORTTITLE, got code=%d resp=%v", fieldName, code, sr)
		}
	}

	// 2. Exists on items.title vs items.title.keyword on Doc 2
	code, sr := doRound27Req(t, srv, http.MethodPost, "/r27_nested_multi/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"exists": map[string]any{"field": "items.title"},
				},
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 2 {
		t.Fatalf("expected 2 hits for exists(items.title), got %v", sr)
	}

	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_nested_multi/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"exists": map[string]any{"field": "items.title.keyword"},
				},
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit for exists(items.title.keyword) due to ignore_above=12, got %v", sr)
	}

	// 3. Multi-level nested correlation:
	// Querying items.cat == "shoes" AND items.variants.(color == "red" AND stock > 5) must NOT match Doc 1
	// because in Doc 1 the "shoes" item only has red(stock=0), while red(stock=10) belongs to the "hat" item!
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_nested_multi/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"bool": map[string]any{
						"must": []any{
							map[string]any{"term": map[string]any{"items.cat": "shoes"}},
							map[string]any{
								"nested": map[string]any{
									"path": "items.variants",
									"query": map[string]any{
										"bool": map[string]any{
											"must": []any{
												map[string]any{"term": map[string]any{"items.variants.color": "red"}},
												map[string]any{"range": map[string]any{"items.variants.stock": map[string]any{"gt": 5}}},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 0 {
		t.Fatalf("expected 0 hits when correlating parent items.cat=shoes with child items.variants, got %v", sr)
	}

	// Querying items.cat == "shoes" AND items.variants.(color == "blue" AND stock > 5) MUST match Doc 1
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_nested_multi/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"bool": map[string]any{
						"must": []any{
							map[string]any{"term": map[string]any{"items.cat": "shoes"}},
							map[string]any{
								"nested": map[string]any{
									"path": "items.variants",
									"query": map[string]any{
										"bool": map[string]any{
											"must": []any{
												map[string]any{"term": map[string]any{"items.variants.color": "blue"}},
												map[string]any{"range": map[string]any{"items.variants.stock": map[string]any{"gt": 5}}},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit when correlating parent items.cat=shoes with blue variant stock>5, got %v", sr)
	}
}

func TestRound27_P0_3_LuceneQuoteFieldSuffixMultiThresholdMSMAndDateMissingMetrics(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound27Req(t, srv, http.MethodPut, "/r27_lucene", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title": map[string]any{
					"type": "text",
					"fields": map[string]any{
						"exact": map[string]any{"type": "keyword"},
					},
				},
				"tags":       map[string]any{"type": "keyword"},
				"created_at": map[string]any{"type": "date"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index status = %d", code)
	}

	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_lucene/_doc/1?refresh=true", map[string]any{
		"title":      "Quick Brown",
		"tags":       []any{"t1", "t2", "t3"},
		"created_at": "2026-01-01T00:00:00Z",
	})
	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_lucene/_doc/2?refresh=true", map[string]any{
		"title": "quick brown fox",
		"tags":  []any{"t1", "t2"},
		// created_at is missing on doc 2
	})

	// 1. quote_field_suffix=".exact": quoted "Quick Brown" routes to title.exact (case-sensitive keyword) -> matches only doc 1
	code, sr := doRound27Req(t, srv, http.MethodPost, "/r27_lucene/_search", map[string]any{
		"query": map[string]any{
			"query_string": map[string]any{
				"default_field":      "title",
				"quote_field_suffix": ".exact",
				"query":              `"Quick Brown"`,
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit with quote_field_suffix=.exact on query_string, got %v", sr)
	}

	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_lucene/_search", map[string]any{
		"query": map[string]any{
			"simple_query_string": map[string]any{
				"fields":             []any{"title"},
				"quote_field_suffix": ".exact",
				"query":              `"Quick Brown"`,
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit with quote_field_suffix=.exact on simple_query_string, got %v", sr)
	}

	// 2. Multi-threshold minimum_should_match: "2<-25% 4<-2" with 4 clauses (4 > 2 and not > 4, so 2<-25% applies -> 4 - 1 = 3 required)
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_lucene/_search", map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"should": []any{
					map[string]any{"term": map[string]any{"tags": "t1"}},
					map[string]any{"term": map[string]any{"tags": "t2"}},
					map[string]any{"term": map[string]any{"tags": "t3"}},
					map[string]any{"term": map[string]any{"tags": "t4"}},
				},
				"minimum_should_match": "2<-25% 4<-2",
			},
		},
	})
	if code != http.StatusOK || len(extractHitsSlice(t, sr)) != 1 {
		t.Fatalf("expected 1 hit (doc 1 has 3 tags) for minimum_should_match='2<-25%% 4<-2', got %v", sr)
	}

	// 3. ISO date string in metric missing parameter across avg, stats, extended_stats, percentiles
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_lucene/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"avg_date": map[string]any{
				"avg": map[string]any{
					"field":   "created_at",
					"missing": "2026-01-03T00:00:00Z",
				},
			},
			"stats_date": map[string]any{
				"stats": map[string]any{
					"field":   "created_at",
					"missing": "2026-01-03T00:00:00Z",
				},
			},
			"pct_date": map[string]any{
				"percentiles": map[string]any{
					"field":   "created_at",
					"missing": "2026-01-03T00:00:00Z",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("date metric missing search failed: %d %v", code, sr)
	}
	aggs, _ := sr["aggregations"].(map[string]any)
	avgDate, _ := aggs["avg_date"].(map[string]any)
	// 2026-01-01T00:00:00Z = 1767225600000, 2026-01-03T00:00:00Z = 1767398400000, avg = 1767312000000
	if gotAvg, _ := avgDate["value"].(float64); gotAvg != 1767312000000 {
		t.Fatalf("expected avg_date=1767312000000, got %v", avgDate)
	}
	statsDate, _ := aggs["stats_date"].(map[string]any)
	if gotMax, _ := statsDate["max"].(float64); gotMax != 1767398400000 {
		t.Fatalf("expected stats_date.max=1767398400000, got %v", statsDate)
	}
}

func TestRound27_P0_4_RuntimeScoringMinScoreBoostingBranchGuardsAndScoreBinding(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound27Req(t, srv, http.MethodPut, "/r27_score", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"cat":     map[string]any{"type": "keyword"},
				"weight":  map[string]any{"type": "double"},
				"penalty": map[string]any{"type": "boolean"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index status = %d", code)
	}

	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_score/_doc/1?refresh=true", map[string]any{
		"cat": "a", "weight": 10.0, "penalty": false,
	})
	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_score/_doc/2?refresh=true", map[string]any{
		"cat": "b", "weight": 2.0, "penalty": true,
	})

	// 1. Non-matching branch in bool.should containing script_score must NOT contribute to doc 1's score,
	// and _score must be bound inside script_fields and _script sort!
	code, sr := doRound27Req(t, srv, http.MethodPost, "/r27_score/_search", map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"should": []any{
					map[string]any{
						"script_score": map[string]any{
							"query":  map[string]any{"term": map[string]any{"cat": "a"}},
							"script": map[string]any{"source": "doc['weight'].value * 3"},
						},
					},
					map[string]any{
						"script_score": map[string]any{
							"query":  map[string]any{"term": map[string]any{"cat": "b"}},
							"script": map[string]any{"source": "999.0"},
						},
					},
				},
				"minimum_should_match": 1,
			},
		},
		"script_fields": map[string]any{
			"double_score": map[string]any{
				"script": map[string]any{"source": "_score * 2"},
			},
		},
		"sort": []any{
			map[string]any{
				"_script": map[string]any{
					"type":   "number",
					"order":  "asc",
					"script": map[string]any{"source": "_score"},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search status = %d %v", code, sr)
	}
	hits := extractHitsSlice(t, sr)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hits))
	}
	// Doc 1 has score 30.0 (not 30 + 999), Doc 2 has score 999.0; sorted asc by _score -> Doc 1 first
	firstHit := hits[0].(map[string]any)
	if firstHit["_id"] != "1" || firstHit["_score"].(float64) != 30.0 {
		t.Fatalf("expected doc 1 with _score=30.0 first, got %v", firstHit)
	}
	fields, _ := firstHit["fields"].(map[string]any)
	ds, _ := fields["double_score"].([]any)
	if len(ds) != 1 || ds[0].(float64) != 60.0 {
		t.Fatalf("expected script_fields double_score=[60.0], got %v", fields)
	}

	// 2. function_score.min_score inside bool.must filters out docs below min_score across _search and _count
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_score/_count", map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"function_score": map[string]any{
							"field_value_factor": map[string]any{"field": "weight"},
							"boost_mode":         "replace",
							"min_score":          5.0,
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK || sr["count"].(float64) != 1 {
		t.Fatalf("expected count=1 with nested function_score.min_score=5.0, got %v", sr)
	}

	// 3. boosting query with outer boost + runtime script
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_score/_search", map[string]any{
		"query": map[string]any{
			"boosting": map[string]any{
				"positive": map[string]any{
					"script_score": map[string]any{
						"query":  map[string]any{"match_all": map[string]any{}},
						"script": map[string]any{"source": "10.0"},
					},
				},
				"negative":       map[string]any{"term": map[string]any{"penalty": true}},
				"negative_boost": 0.5,
				"boost":          2.0,
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("boosting search failed: %d %v", code, sr)
	}
	hits = extractHitsSlice(t, sr)
	// Doc 1 (no penalty): 10.0 * 2.0 = 20.0; Doc 2 (penalty): 10.0 * 0.5 * 2.0 = 10.0
	if len(hits) != 2 || hits[0].(map[string]any)["_score"].(float64) != 20.0 || hits[1].(map[string]any)["_score"].(float64) != 10.0 {
		t.Fatalf("unexpected boosting scores: %v", hits)
	}
}

func TestRound27_P0_5_CompositeDateHistogramFormatPipelineFormatsAndMSearchPIT(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound27Req(t, srv, http.MethodPut, "/r27_comp", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"ts":  map[string]any{"type": "date"},
				"val": map[string]any{"type": "double"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index status = %d", code)
	}

	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_comp/_doc/1?refresh=true", map[string]any{
		"ts": "2026-03-01T10:00:00Z", "val": 10.0,
	})
	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_comp/_doc/2?refresh=true", map[string]any{
		"ts": "2026-03-02T10:00:00Z", "val": 30.0,
	})

	// 1. Composite date_histogram with format="yyyy-MM-dd" and after cursor pagination
	code, sr := doRound27Req(t, srv, http.MethodPost, "/r27_comp/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"comp_days": map[string]any{
				"composite": map[string]any{
					"size": 1,
					"sources": []any{
						map[string]any{
							"day": map[string]any{
								"date_histogram": map[string]any{
									"field":             "ts",
									"calendar_interval": "1d",
									"format":            "yyyy-MM-dd",
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("composite search failed: %d %v", code, sr)
	}
	compAgg := sr["aggregations"].(map[string]any)["comp_days"].(map[string]any)
	afterKey, _ := compAgg["after_key"].(map[string]any)
	if afterKey["day"] != "2026-03-01" {
		t.Fatalf("expected formatted after_key.day='2026-03-01', got %v", compAgg)
	}

	// Page 2 using formatted after_key
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_comp/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"comp_days": map[string]any{
				"composite": map[string]any{
					"size":  1,
					"after": afterKey,
					"sources": []any{
						map[string]any{
							"day": map[string]any{
								"date_histogram": map[string]any{
									"field":             "ts",
									"calendar_interval": "1d",
									"format":            "yyyy-MM-dd",
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("composite page 2 failed: %d %v", code, sr)
	}
	compAgg2 := sr["aggregations"].(map[string]any)["comp_days"].(map[string]any)
	afterKey2, _ := compAgg2["after_key"].(map[string]any)
	if afterKey2["day"] != "2026-03-02" {
		t.Fatalf("expected page 2 after_key.day='2026-03-02', got %v", compAgg2)
	}

	// 2. Sibling pipeline format on extended_stats_bucket and percentiles_bucket
	code, sr = doRound27Req(t, srv, http.MethodPost, "/r27_comp/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_day": map[string]any{
				"date_histogram": map[string]any{
					"field":             "ts",
					"calendar_interval": "1d",
				},
				"aggs": map[string]any{
					"sum_v": map[string]any{"sum": map[string]any{"field": "val"}},
				},
			},
			"ext_stats_b": map[string]any{
				"extended_stats_bucket": map[string]any{
					"buckets_path": "by_day>sum_v",
					"format":       "0.00",
				},
			},
			"pct_b": map[string]any{
				"percentiles_bucket": map[string]any{
					"buckets_path": "by_day>sum_v",
					"percents":     []any{50.0},
					"format":       "0.00",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("sibling pipeline format search failed: %d %v", code, sr)
	}
	extB := sr["aggregations"].(map[string]any)["ext_stats_b"].(map[string]any)
	if extB["avg_as_string"] != "20.00" || extB["max_as_string"] != "30.00" {
		t.Fatalf("expected avg_as_string='20.00' and max_as_string='30.00', got %v", extB)
	}
	pctB := sr["aggregations"].(map[string]any)["pct_b"].(map[string]any)
	valsAsStr, _ := pctB["values_as_string"].(map[string]any)
	if valsAsStr["50.0"] != "20.00" {
		t.Fatalf("expected percentiles_bucket values_as_string['50.0']='20.00', got %v", pctB)
	}

	// 3. _msearch with PIT ID (no index in header) resolves PIT index and returns pit_id
	code, pitResp := doRound27Req(t, srv, http.MethodPost, "/r27_comp/_pit?keep_alive=1m", nil)
	if code != http.StatusOK {
		t.Fatalf("open pit failed: %d", code)
	}
	pitID, _ := pitResp["id"].(string)
	msearchBody := `{}` + "\n" + `{"pit":{"id":"` + pitID + `"},"query":{"match_all":{}}}` + "\n"
	code, msResp := doRound27Req(t, srv, http.MethodPost, "/_msearch", msearchBody)
	if code != http.StatusOK {
		t.Fatalf("_msearch with pit failed: %d %v", code, msResp)
	}
	responses, _ := msResp["responses"].([]any)
	if len(responses) != 1 {
		t.Fatalf("expected 1 msearch response, got %v", msResp)
	}
	firstMS := responses[0].(map[string]any)
	if firstMS["pit_id"] != pitID || len(extractHitsSlice(t, firstMS)) != 2 {
		t.Fatalf("expected pit_id=%s and 2 hits in _msearch response, got %v", pitID, firstMS)
	}
}

func TestRound27_P0_6_PainlessRegexSplitCollectionsSortAndJavaTimeAPIs(t *testing.T) {
	doc := map[string]any{
		"s":    "user_42",
		"csv":  "a,b,c,,",
		"nums": []any{int64(3), int64(1), int64(2)},
	}

	// 1. String.replaceAll with $1 followed by _id and String.replaceFirst with a*
	res, err := painless.Eval(doc, `doc['s'].value.replaceAll('user_(\\d+)', '$1_id')`, nil)
	if err != nil || res != "42_id" {
		t.Fatalf("expected '42_id', got %v (err=%v)", res, err)
	}
	res, err = painless.Eval(doc, `'baaa'.replaceFirst('a*', 'X')`, nil)
	if err != nil || res != "Xbaaa" {
		t.Fatalf("expected 'Xbaaa', got %v (err=%v)", res, err)
	}

	// 2. String.split trailing empty token stripping vs negative limit
	res, err = painless.Eval(doc, `doc['csv'].value.split(',').length`, nil)
	if err != nil || res != int64(3) {
		t.Fatalf("expected split(',').length == 3, got %v (err=%v)", res, err)
	}
	res, err = painless.Eval(doc, `doc['csv'].value.split(',', -1).length`, nil)
	if err != nil || res != int64(5) {
		t.Fatalf("expected split(',', -1).length == 5, got %v (err=%v)", res, err)
	}
	res, err = painless.Eval(doc, `''.split(',').length`, nil)
	if err != nil || res != int64(1) {
		t.Fatalf("expected ''.split(',').length == 1, got %v (err=%v)", res, err)
	}

	// 3. Map.putIfAbsent, List.sort with comparator, Collections.sort / Collections.reverse in statement context
	rawDoc := json.RawMessage(`{"items":[3,1,2],"meta":{"a":1}}`)
	mutated, _, err := painless.ApplyUpdateWithResult(rawDoc, &painless.UpdateRequest{
		Script: &painless.ScriptSpec{
			Source: `
				ctx._source.meta.putIfAbsent('a', 99);
				ctx._source.meta.putIfAbsent('b', 2);
				Collections.sort(ctx._source.items);
				Collections.reverse(ctx._source.items);
			`,
		},
	}, true)
	if err != nil {
		t.Fatalf("ApplyUpdateWithResult error: %v", err)
	}
	var updated map[string]any
	_ = json.Unmarshal(mutated, &updated)
	metaMap := updated["meta"].(map[string]any)
	if metaMap["a"].(float64) != 1 || metaMap["b"].(float64) != 2 {
		t.Fatalf("unexpected meta after putIfAbsent: %v", metaMap)
	}
	itemsArr := updated["items"].([]any)
	if len(itemsArr) != 3 || itemsArr[0].(float64) != 3 || itemsArr[1].(float64) != 2 || itemsArr[2].(float64) != 1 {
		t.Fatalf("unexpected items after sort+reverse: %v", itemsArr)
	}

	// 4. Instant, ZonedDateTime, ChronoUnit.DAYS.between, plusDays, isAfter, and List.sort with lambda/reverseOrder
	res, err = painless.Eval(doc, `
		def arr = [1, 3, 2];
		arr.sort((a, b) -> b - a);
		ZonedDateTime t1 = ZonedDateTime.parse('2026-01-01T00:00:00Z');
		ZonedDateTime t2 = t1.plusDays(5).plusHours(12);
		Instant i1 = Instant.ofEpochMilli(1700000000000);
		Instant i2 = Instant.ofEpochSecond(1700000060);
		long mins = ChronoUnit.MINUTES.between(i1, i2);
		long days = ChronoUnit.DAYS.between(t1, t2);
		long secs = ChronoUnit.SECONDS.between(i1, i2);
		long ms = ChronoUnit.MILLIS.between(i1, i2);
		if (t2.isAfter(t1) && arr[0] == 3 && mins == 1 && days == 5 && secs == 60 && ms == 60000) {
			return ChronoUnit.HOURS.between(t1, t2);
		}
		return 0;
	`, nil)
	if err != nil || res != int64(132) {
		t.Fatalf("expected 132 hours between t1 and t2, got %v (err=%v)", res, err)
	}
}

func TestRound27_P0_7_IngestProcessorsWriteAliasGuardReindexConflictsAndStoredFields(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Simulate urlencode, network_direction, community_id, geoip, enrich, gsub Mustache, and html_strip entities
	code, simResp := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"urlencode": map[string]any{
						"field":        "raw_query",
						"target_field": "encoded_query",
					},
				},
				map[string]any{
					"network_direction": map[string]any{
						"source_ip":      "source.ip",
						"destination_ip": "destination.ip",
						"target_field":   "network.direction",
					},
				},
				map[string]any{
					"community_id": map[string]any{
						"target_field": "network.community_id",
					},
				},
				map[string]any{
					"geoip": map[string]any{
						"field":        "destination.ip",
						"target_field": "destination.geo",
						"properties":   []any{"country_iso_code", "location"},
					},
				},
				map[string]any{
					"enrich": map[string]any{
						"policy_name":  "env-policy",
						"field":        "env_key",
						"target_field": "enriched_env",
						"entries": map[string]any{
							"prod": map[string]any{"tier": "tier-1", "owner": "sre"},
						},
					},
				},
				map[string]any{
					"gsub": map[string]any{
						"field":       "msg",
						"pattern":     "USER",
						"replacement": "{{user_name}}",
					},
				},
				map[string]any{
					"html_strip": map[string]any{
						"field": "html_body",
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_source": map[string]any{
					"raw_query": "a b&c=d",
					"source": map[string]any{
						"ip":   "10.0.0.5",
						"port": 54321,
					},
					"destination": map[string]any{
						"ip":   "8.8.8.8",
						"port": 443,
					},
					"network": map[string]any{
						"transport": "tcp",
					},
					"env_key":   "prod",
					"user_name": "alice",
					"msg":       "hello USER!",
					"html_body": "<p>Tom &amp; Jerry &lt;3&gt;</p>",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("simulate ingest pipeline failed: %d %v", code, simResp)
	}
	simDocs, _ := simResp["docs"].([]any)
	simSrc := simDocs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if simSrc["encoded_query"] != "a+b%26c%3Dd" {
		t.Fatalf("expected encoded_query='a+b%%26c%%3Dd', got %v", simSrc["encoded_query"])
	}
	netMap, _ := simSrc["network"].(map[string]any)
	if netMap["direction"] != "outbound" {
		t.Fatalf("expected network.direction='outbound', got %v", netMap)
	}
	cid, _ := netMap["community_id"].(string)
	if !strings.HasPrefix(cid, "1:") || len(cid) < 10 {
		t.Fatalf("expected valid 1:<base64> community_id, got %q", cid)
	}
	dstMap, _ := simSrc["destination"].(map[string]any)
	geoMap, _ := dstMap["geo"].(map[string]any)
	if geoMap["country_iso_code"] != "US" {
		t.Fatalf("expected destination.geo.country_iso_code='US', got %v", geoMap)
	}
	enrichedEnv, _ := simSrc["enriched_env"].(map[string]any)
	if enrichedEnv["tier"] != "tier-1" {
		t.Fatalf("expected enriched_env.tier='tier-1', got %v", enrichedEnv)
	}
	if simSrc["msg"] != "hello alice!" {
		t.Fatalf("expected gsub Mustache replacement 'hello alice!', got %v", simSrc["msg"])
	}
	if simSrc["html_body"] != "Tom & Jerry <3>" {
		t.Fatalf("expected html_strip entity unescaping 'Tom & Jerry <3>', got %v", simSrc["html_body"])
	}

	// 2. Single-index alias with explicit is_write_index: false must reject writes with 400
	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_idx", map[string]any{
		"Aliases": map[string]any{
			"r27_ro_alias": map[string]any{
				"is_write_index": false,
			},
			"r27_filtered_alias": map[string]any{
				"is_write_index": true,
				"filter": map[string]any{
					"term": map[string]any{"tenant": "t1"},
				},
			},
		},
	})
	code, _ = doRound27Req(t, srv, http.MethodPut, "/r27_ro_alias/_doc/1", map[string]any{"tenant": "t1"})
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 when writing to alias with is_write_index=false, got %d", code)
	}

	// 3. _reindex with conflicts="proceed" when destination alias filter rejects a doc
	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_src/_doc/1?refresh=true", map[string]any{"tenant": "t1", "title": "keep"})
	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_src/_doc/2?refresh=true", map[string]any{"tenant": "t2", "title": "skip"})

	code, reResp := doRound27Req(t, srv, http.MethodPost, "/_reindex", map[string]any{
		"conflicts": "proceed",
		"source":    map[string]any{"index": "r27_src"},
		"dest":      map[string]any{"index": "r27_filtered_alias"},
	})
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _reindex with conflicts=proceed, got %d %v", code, reResp)
	}
	if math.Abs(reResp["created"].(float64)-1) > 1e-9 || math.Abs(reResp["version_conflicts"].(float64)-1) > 1e-9 {
		t.Fatalf("expected created=1 and version_conflicts=1, got %v", reResp)
	}

	// 4. GET /{index}/_doc/{id} and POST /_mget with stored_fields=_none_, stored_fields list, and per-doc _source_includes
	code, getResp := doRound27Req(t, srv, http.MethodGet, "/r27_src/_doc/1?stored_fields=_none_", nil)
	if code != http.StatusOK {
		t.Fatalf("GET doc with stored_fields=_none_ failed: %d", code)
	}
	if _, hasSrc := getResp["_source"]; hasSrc {
		t.Fatalf("expected _source to be omitted when stored_fields=_none_, got %v", getResp)
	}

	code, getResp = doRound27Req(t, srv, http.MethodGet, "/r27_src/_doc/1?stored_fields=title", nil)
	if code != http.StatusOK {
		t.Fatalf("GET doc with stored_fields=title failed: %d", code)
	}
	getFields, _ := getResp["fields"].(map[string]any)
	if len(getFields) == 0 {
		t.Fatalf("expected fields.title in GET doc response, got %v", getResp)
	}

	code, mgetResp := doRound27Req(t, srv, http.MethodPost, "/r27_src/_mget", map[string]any{
		"docs": []any{
			map[string]any{
				"_id":              "1",
				"_source_includes": []any{"title"},
			},
			map[string]any{
				"_id":           "2",
				"stored_fields": []any{"_none_"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("_mget failed: %d %v", code, mgetResp)
	}
	mDocs, _ := mgetResp["docs"].([]any)
	doc0Src, _ := mDocs[0].(map[string]any)["_source"].(map[string]any)
	if doc0Src["title"] != "keep" || doc0Src["tenant"] != nil {
		t.Fatalf("expected per-doc _source_includes=['title'] to keep only title, got %v", doc0Src)
	}
	if _, hasSrc := mDocs[1].(map[string]any)["_source"]; hasSrc {
		t.Fatalf("expected per-doc stored_fields=['_none_'] to omit _source, got %v", mDocs[1])
	}

	// 5. Enrich live index lookup
	_, _ = doRound27Req(t, srv, http.MethodPut, "/r27_users/_doc/u1?refresh=true", map[string]any{
		"user_id": "u-100",
		"dept":    "platform",
		"role":    "staff",
	})
	code, simEnrich := doRound27Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"enrich": map[string]any{
						"policy_name":  "r27_users-policy",
						"match_field":  "user_id",
						"field":        "actor_id",
						"target_field": "actor_info",
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_source": map[string]any{"actor_id": "u-100"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("simulate live enrich failed: %d %v", code, simEnrich)
	}
	enrDocs, _ := simEnrich["docs"].([]any)
	enrSrc := enrDocs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	actorInfo, _ := enrSrc["actor_info"].(map[string]any)
	if actorInfo["dept"] != "platform" || actorInfo["role"] != "staff" {
		t.Fatalf("expected actor_info enriched from r27_users index, got %v", actorInfo)
	}
}
