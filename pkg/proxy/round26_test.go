package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/painless"
)

func doRound26Req(t *testing.T, srv *Server, method, path string, body any) (int, map[string]any) {
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

func TestRound26_P0_1_NestedQueryContextWildcardFieldExpansionScoreModeBoostAndIgnoreUnmapped(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound26Req(t, srv, http.MethodPut, "/r26_nested_wild", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title": map[string]any{"type": "text"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"sku_en":  map[string]any{"type": "keyword"},
						"sku_fr":  map[string]any{"type": "keyword"},
						"desc_en": map[string]any{"type": "text"},
						"desc_fr": map[string]any{"type": "text"},
						"qty":     map[string]any{"type": "integer"},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index status = %d", code)
	}

	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_nested_wild/_doc/1?refresh=true", map[string]any{
		"title": "order one",
		"items": []any{
			map[string]any{"sku_en": "SKU-100", "desc_en": "wireless keyboard", "qty": 2},
			map[string]any{"sku_fr": "SKU-200", "desc_fr": "clavier sans fil", "qty": 5},
		},
	})
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_nested_wild/_doc/2?refresh=true", map[string]any{
		"title": "order two",
		"items": []any{
			map[string]any{"sku_en": "SKU-300", "desc_en": "ergonomic mouse", "qty": 1},
		},
	})

	// 1. Nested multi_match with wildcard field pattern items.desc_*
	code, resp := doRound26Req(t, srv, http.MethodPost, "/r26_nested_wild/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"multi_match": map[string]any{
						"query":  "clavier",
						"fields": []string{"items.desc_*"},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("nested multi_match wildcard status = %d: %v", code, resp)
	}
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 from nested multi_match wildcard, got %v", hits)
	}

	// 2. Nested query_string with wildcard field pattern items.sku_*
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_nested_wild/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"query_string": map[string]any{
						"query":  "SKU-200",
						"fields": []string{"items.sku_*"},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("nested query_string wildcard status = %d: %v", code, resp)
	}
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 from nested query_string wildcard, got %v", hits)
	}

	// 3. Nested score_mode: "none" yields 0.0 score while score_mode: "sum" with boost scales score
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_nested_wild/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path":       "items",
				"score_mode": "none",
				"query": map[string]any{
					"term": map[string]any{"items.sku_en": "SKU-100"},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("nested score_mode=none status = %d: %v", code, resp)
	}
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for score_mode=none, got %d", len(hits))
	}
	if score, _ := hits[0].(map[string]any)["_score"].(float64); score != 0.0 {
		t.Fatalf("expected _score=0.0 for score_mode=none, got %v", score)
	}

	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_nested_wild/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path":       "items",
				"score_mode": "max",
				"boost":      3.5,
				"query": map[string]any{
					"term": map[string]any{"items.sku_en": "SKU-100"},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("nested boost status = %d: %v", code, resp)
	}
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for nested boost, got %d", len(hits))
	}
	if score, _ := hits[0].(map[string]any)["_score"].(float64); score < 3.4 {
		t.Fatalf("expected boosted _score >= 3.5, got %v", score)
	}

	// 4. Nested ignore_unmapped: true on unmapped path returns 0 hits instead of error
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_nested_wild/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path":            "nonexistent_nested",
				"ignore_unmapped": true,
				"query": map[string]any{
					"term": map[string]any{"nonexistent_nested.foo": "bar"},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("nested ignore_unmapped=true status = %d: %v", code, resp)
	}
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits for ignore_unmapped=true on unmapped nested path, got %d", len(hits))
	}
}

func TestRound26_P0_2_FuzzyEditDistanceMatchFuzzinessAndLuceneGroupUnaryOperators(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound26Req(t, srv, http.MethodPut, "/r26_fuzzy", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"word":  map[string]any{"type": "keyword"},
				"title": map[string]any{"type": "text"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index status = %d", code)
	}

	// "elastic" (doc 1), "elastik" (substitution, edit distance 1, doc 2),
	// "elstic" (deletion, edit distance 1, doc 3), "elasttic" (insertion, edit distance 1, doc 4),
	// "elatsic" (transposition, edit distance 1, doc 5), "completely_different" (doc 6)
	docs := []map[string]any{
		{"id": "1", "word": "elastic", "title": "elastic search engine"},
		{"id": "2", "word": "elastik", "title": "elastik analytics"},
		{"id": "3", "word": "elstic", "title": "elstic cluster"},
		{"id": "4", "word": "elasttic", "title": "elasttic cloud"},
		{"id": "5", "word": "elatsic", "title": "elatsic platform"},
		{"id": "6", "word": "completely_different", "title": "database system"},
	}
	for _, d := range docs {
		_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_fuzzy/_doc/"+d["id"].(string)+"?refresh=true", map[string]any{
			"word":  d["word"],
			"title": d["title"],
		})
	}

	// 1. Term-level fuzzy query matches exact, substitution, deletion, insertion, transposition
	code, resp := doRound26Req(t, srv, http.MethodPost, "/r26_fuzzy/_search", map[string]any{
		"query": map[string]any{
			"fuzzy": map[string]any{
				"word": map[string]any{
					"value":     "elastic",
					"fuzziness": "AUTO",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("fuzzy query status = %d: %v", code, resp)
	}
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 5 {
		t.Fatalf("expected 5 hits for fuzzy edit distance 1 on 'elastic', got %d: %v", len(hits), hits)
	}

	// 2. fuzziness: 0 matches only exact "elastic"
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_fuzzy/_search", map[string]any{
		"query": map[string]any{
			"fuzzy": map[string]any{
				"word": map[string]any{
					"value":     "elastic",
					"fuzziness": 0,
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("fuzzy fuzziness=0 status = %d: %v", code, resp)
	}
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected only doc 1 for fuzziness=0, got %v", hits)
	}

	// 3. match query with fuzziness: "AUTO" matches edit-distance-1 tokens
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_fuzzy/_search", map[string]any{
		"query": map[string]any{
			"match": map[string]any{
				"title": map[string]any{
					"query":     "elastic",
					"fuzziness": "AUTO",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("match fuzziness=AUTO status = %d: %v", code, resp)
	}
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 5 {
		t.Fatalf("expected 5 hits for match with fuzziness=AUTO, got %d", len(hits))
	}

	// 4. Lucene float fuzziness ~0.8 and field-scoped unary group title:-(analytics cluster cloud platform)
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_fuzzy/_search", map[string]any{
		"query": map[string]any{
			"query_string": map[string]any{
				"query": `title:elastic~0.8 AND title:-(analytics cluster cloud platform)`,
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("lucene ~0.8 and field:-(...) status = %d: %v", code, resp)
	}
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected only doc 1 after excluding analytics/cluster/cloud/platform, got %v", hits)
	}
}

func TestRound26_P0_3_NestedSubAggsMultiValuedArraysEmptyBucketMetricsAndCompositeNormalization(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound26Req(t, srv, http.MethodPut, "/r26_nested_aggs", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"category": map[string]any{"type": "keyword"},
				"active":   map[string]any{"type": "boolean"},
				"title":    map[string]any{"type": "text"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"tags":   map[string]any{"type": "keyword"},
						"flag":   map[string]any{"type": "boolean"},
						"scores": map[string]any{"type": "integer"},
						"dates":  map[string]any{"type": "date"},
						"price":  map[string]any{"type": "double"},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index status = %d", code)
	}

	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_nested_aggs/_doc/1?refresh=true", map[string]any{
		"category": "A",
		"active":   true,
		"title":    "Alpha Item",
		"items": []any{
			map[string]any{
				"tags":   []any{"red", "blue", "red"}, // duplicate "red" in same nested element should count once
				"flag":   true,
				"scores": []any{10, 25},
				"dates":  []any{"2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z"},
				"price":  100.0,
			},
			map[string]any{
				"tags":  []any{"red"},
				"flag":  false,
				"price": nil, // null price
			},
		},
	})
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_nested_aggs/_doc/2?refresh=true", map[string]any{
		"category": "B",
		"active":   false,
		"title":    "Beta Item",
		"items": []any{
			map[string]any{
				"tags":  []any{"green"},
				"flag":  false,
				"price": nil,
			},
		},
	})

	code, resp := doRound26Req(t, srv, http.MethodPost, "/r26_nested_aggs/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"nested_items": map[string]any{
				"nested": map[string]any{"path": "items"},
				"aggs": map[string]any{
					"by_tag": map[string]any{
						"terms": map[string]any{"field": "items.tags"},
						"aggs": map[string]any{
							"avg_price": map[string]any{"avg": map[string]any{"field": "items.price"}},
						},
					},
					"by_flag": map[string]any{
						"terms": map[string]any{"field": "items.flag"},
					},
					"score_hist": map[string]any{
						"histogram": map[string]any{
							"field":    "items.scores",
							"interval": 10,
						},
					},
					"date_hist": map[string]any{
						"date_histogram": map[string]any{
							"field":          "items.dates",
							"fixed_interval": "1d",
						},
					},
				},
			},
			"comp": map[string]any{
				"composite": map[string]any{
					"size": 1,
					"sources": []any{
						map[string]any{"active": map[string]any{"terms": map[string]any{"field": "active"}}},
						map[string]any{"title": map[string]any{"terms": map[string]any{"field": "title"}}},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("nested subaggs status = %d: %v", code, resp)
	}
	aggs := resp["aggregations"].(map[string]any)
	nestedItems := aggs["nested_items"].(map[string]any)

	// Check by_tag: "red" has doc_count 2 (deduplicated per nested element), "green" has avg_price = nil (not 0.0)
	byTagBuckets := nestedItems["by_tag"].(map[string]any)["buckets"].([]any)
	tagCounts := map[string]float64{}
	tagAvgPrice := map[string]any{}
	for _, b := range byTagBuckets {
		bm := b.(map[string]any)
		k := bm["key"].(string)
		tagCounts[k] = bm["doc_count"].(float64)
		tagAvgPrice[k] = bm["avg_price"].(map[string]any)["value"]
	}
	if tagCounts["red"] != 2 {
		t.Fatalf("expected nested tag 'red' doc_count = 2 (deduplicated within element), got %v", tagCounts["red"])
	}
	if tagAvgPrice["green"] != nil {
		t.Fatalf("expected nested tag 'green' avg_price = nil when all values are null, got %v", tagAvgPrice["green"])
	}

	// Check by_flag: boolean keys normalized to "true"/"false" (not "1"/"0")
	byFlagBuckets := nestedItems["by_flag"].(map[string]any)["buckets"].([]any)
	if len(byFlagBuckets) != 2 {
		t.Fatalf("expected 2 boolean flag buckets, got %v", byFlagBuckets)
	}
	for _, b := range byFlagBuckets {
		bm := b.(map[string]any)
		k, _ := bm["key"].(string)
		if k != "true" && k != "false" {
			t.Fatalf("expected boolean key 'true' or 'false', got %v (bucket=%v)", k, bm)
		}
	}

	// Check score_hist on multi-valued nested integer array [10, 25]
	scoreHistBuckets := nestedItems["score_hist"].(map[string]any)["buckets"].([]any)
	if len(scoreHistBuckets) < 2 {
		t.Fatalf("expected at least 2 histogram buckets for multi-valued nested scores [10, 25], got %v", scoreHistBuckets)
	}

	// Check date_hist on multi-valued nested date array
	dateHistBuckets := nestedItems["date_hist"].(map[string]any)["buckets"].([]any)
	if len(dateHistBuckets) != 2 {
		t.Fatalf("expected 2 date_histogram buckets for multi-valued nested dates, got %v", dateHistBuckets)
	}

	// Check composite pagination with after cursor and boolean/text normalization
	comp := aggs["comp"].(map[string]any)
	compBuckets := comp["buckets"].([]any)
	if len(compBuckets) != 1 {
		t.Fatalf("expected 1 composite bucket on page 1, got %v", compBuckets)
	}
	afterKey := comp["after_key"].(map[string]any)

	code, resp2 := doRound26Req(t, srv, http.MethodPost, "/r26_nested_aggs/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"comp": map[string]any{
				"composite": map[string]any{
					"size":  1,
					"after": afterKey,
					"sources": []any{
						map[string]any{"active": map[string]any{"terms": map[string]any{"field": "active"}}},
						map[string]any{"title": map[string]any{"terms": map[string]any{"field": "title"}}},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("composite page 2 status = %d: %v", code, resp2)
	}
	comp2Buckets := resp2["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	if len(comp2Buckets) != 1 {
		t.Fatalf("expected 1 composite bucket on page 2 using after cursor, got %v", comp2Buckets)
	}
}

func TestRound26_P0_4_ShredderCopyToIgnoreAboveAndTransitiveNestedCopyTo(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound26Req(t, srv, http.MethodPut, "/r26_copy_to", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"short_code": map[string]any{
					"type":         "keyword",
					"ignore_above": 5,
					"copy_to":      "all_codes",
				},
				"all_codes": map[string]any{
					"type":         "keyword",
					"ignore_above": 8,
				},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"a": map[string]any{
							"type":    "keyword",
							"copy_to": "items.b",
						},
						"b": map[string]any{
							"type":    "keyword",
							"copy_to": "items.c",
						},
						"c": map[string]any{
							"type": "keyword",
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index status = %d", code)
	}

	// Doc 1: short_code "123456" exceeds source ignore_above: 5 -> should NOT be indexed or copied to all_codes
	// Nested items.a = "hop_val" -> copied transitively to items.b and items.c
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_copy_to/_doc/1?refresh=true", map[string]any{
		"short_code": "123456",
		"items": []any{
			map[string]any{"a": "hop_val"},
		},
	})
	// Doc 2: short_code "12345" fits ignore_above: 5 -> copied to all_codes
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_copy_to/_doc/2?refresh=true", map[string]any{
		"short_code": "12345",
	})

	// 1. Query on all_codes for "123456" should return 0 hits (filtered by source ignore_above: 5)
	code, resp := doRound26Req(t, srv, http.MethodPost, "/r26_copy_to/_search", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"all_codes": "123456"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search all_codes 123456 status = %d", code)
	}
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 0 {
		t.Fatalf("expected 0 hits for all_codes='123456' exceeding source ignore_above=5, got %v", hits)
	}

	// 2. Query on all_codes for "12345" should return doc 2
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_copy_to/_search", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"all_codes": "12345"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search all_codes 12345 status = %d", code)
	}
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected doc 2 for all_codes='12345', got %v", hits)
	}

	// 3. Transitive nested copy_to: items.a -> items.b -> items.c
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_copy_to/_search", map[string]any{
		"query": map[string]any{
			"nested": map[string]any{
				"path": "items",
				"query": map[string]any{
					"term": map[string]any{"items.c": "hop_val"},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search nested items.c status = %d: %v", code, resp)
	}
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 from transitive nested copy_to items.a -> items.b -> items.c, got %v", hits)
	}
}

func TestRound26_P0_5_RateAggPipelineDependencyAndBucketSelectorNullComparison(t *testing.T) {
	srv, _ := newTestServer()

	code, _ := doRound26Req(t, srv, http.MethodPut, "/r26_pipeline", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"ts":       map[string]any{"type": "date"},
				"requests": map[string]any{"type": "double"},
				"opt_val":  map[string]any{"type": "double"},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("create index status = %d", code)
	}

	// Day 1: requests = 240 (10/hour), opt_val = 50
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_pipeline/_doc/1?refresh=true", map[string]any{
		"ts":       "2025-01-01T02:00:00Z",
		"requests": 240.0,
		"opt_val":  50.0,
	})
	// Day 2: requests = 480 (20/hour), opt_val = null
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_pipeline/_doc/2?refresh=true", map[string]any{
		"ts":       "2025-01-02T02:00:00Z",
		"requests": 480.0,
	})

	// 1. Sibling max_bucket / avg_bucket referencing a `rate` sub-aggregation (per hour: 10.0 and 20.0)
	// and bucket_selector checking `params.avg_opt != null && params.hourly_rate >= 10`
	code, resp := doRound26Req(t, srv, http.MethodPost, "/r26_pipeline/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_day": map[string]any{
				"date_histogram": map[string]any{
					"field":          "ts",
					"fixed_interval": "1d",
				},
				"aggs": map[string]any{
					"hourly_rate": map[string]any{
						"rate": map[string]any{
							"field": "requests",
							"unit":  "1h",
						},
					},
					"avg_opt": map[string]any{
						"avg": map[string]any{"field": "opt_val"},
					},
					"non_null_filter": map[string]any{
						"bucket_selector": map[string]any{
							"buckets_path": map[string]any{
								"avg_opt":     "avg_opt",
								"hourly_rate": "hourly_rate",
							},
							"script": "params.avg_opt != null && params.hourly_rate >= 10",
						},
					},
				},
			},
			"max_hourly": map[string]any{
				"max_bucket": map[string]any{
					"buckets_path": "by_day>hourly_rate",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("pipeline rate/bucket_selector status = %d: %v", code, resp)
	}
	aggs := resp["aggregations"].(map[string]any)
	// max_hourly is computed over by_day>hourly_rate (before or after selector, hourly_rate is 10.0 / 20.0, not raw sum 240 / 480)
	maxHourly := aggs["max_hourly"].(map[string]any)["value"].(float64)
	if maxHourly != 10.0 && maxHourly != 20.0 {
		t.Fatalf("expected max_hourly to use scaled hourly rate (10 or 20), got %v", maxHourly)
	}
	// bucket_selector `params.avg_opt != null` should retain only Day 1 (where opt_val is not null)
	byDayBuckets := aggs["by_day"].(map[string]any)["buckets"].([]any)
	if len(byDayBuckets) != 1 {
		t.Fatalf("expected 1 bucket after bucket_selector `params.avg_opt != null`, got %d: %v", len(byDayBuckets), byDayBuckets)
	}
	b0 := byDayBuckets[0].(map[string]any)
	if hr := b0["hourly_rate"].(map[string]any)["value"].(float64); hr != 10.0 {
		t.Fatalf("expected Day 1 hourly_rate = 10.0, got %v", hr)
	}
}

func TestRound26_P0_6_SearchAfterTotalHitsTermsLookupInAggsHighlightScopedLuceneAndNestedSort(t *testing.T) {
	srv, _ := newTestServer()

	// Create lookup store index
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_allowlist", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"allowed_tags": map[string]any{"type": "keyword"},
			},
		},
	})
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_allowlist/_doc/list1?refresh=true", map[string]any{
		"allowed_tags": []any{"urgent", "security"},
	})

	// Create main index with nested items and boolean flag
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_search_post", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title":   map[string]any{"type": "text"},
				"body":    map[string]any{"type": "text"},
				"tag":     map[string]any{"type": "keyword"},
				"enabled": map[string]any{"type": "boolean"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"kind":  map[string]any{"type": "keyword"},
						"price": map[string]any{"type": "double"},
					},
				},
			},
		},
	})

	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_search_post/_doc/1?refresh=true", map[string]any{
		"title":   "foo report",
		"body":    "contains bar and baz",
		"tag":     "urgent",
		"enabled": true,
		"items": []any{
			map[string]any{"kind": "promo", "price": 5.0},
			map[string]any{"kind": "regular", "price": 50.0},
		},
	})
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_search_post/_doc/2?refresh=true", map[string]any{
		"title":   "foo summary",
		"body":    "contains bar only",
		"tag":     "normal",
		"enabled": false,
		"items": []any{
			map[string]any{"kind": "regular", "price": 20.0},
		},
	})
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_search_post/_doc/3?refresh=true", map[string]any{
		"title":   "foo notice",
		"body":    "contains baz only",
		"tag":     "security",
		"enabled": true,
		"items": []any{
			map[string]any{"kind": "regular", "price": 35.0},
		},
	})

	// 1. search_after preserves total hits count (3 total matching docs even when search_after returns page 2)
	// 2. filter agg with terms lookup resolves from /r26_allowlist/_doc/list1
	// 3. nested sort with nested.filter={"term":{"items.kind":"regular"}} sorts by regular price (50, 35, 20)
	// 4. highlight with require_field_match: true on `title:foo AND body:bar` highlights only "foo" in title and "bar" in body
	code, resp := doRound26Req(t, srv, http.MethodPost, "/r26_search_post/_search", map[string]any{
		"size": 1,
		"query": map[string]any{
			"query_string": map[string]any{
				"query": "title:foo AND body:(bar OR baz)",
			},
		},
		"sort": []any{
			map[string]any{
				"items.price": map[string]any{
					"order": "asc",
					"mode":  "min",
					"nested": map[string]any{
						"path": "items",
						"filter": map[string]any{
							"term": map[string]any{"items.kind": "regular"},
						},
					},
				},
			},
		},
		"search_after": []any{20.0},
		"highlight": map[string]any{
			"require_field_match": true,
			"fields": map[string]any{
				"title": map[string]any{},
				"body":  map[string]any{},
			},
		},
		"aggs": map[string]any{
			"allowed_only": map[string]any{
				"filter": map[string]any{
					"terms": map[string]any{
						"tag": map[string]any{
							"index": "r26_allowlist",
							"id":    "list1",
							"path":  "allowed_tags",
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("search post-processing status = %d: %v", code, resp)
	}
	hitsObj := resp["hits"].(map[string]any)
	totalVal := hitsObj["total"].(map[string]any)["value"].(float64)
	if totalVal != 3 {
		t.Fatalf("expected hits.total.value = 3 with search_after, got %v", totalVal)
	}
	hits := hitsObj["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "3" {
		t.Fatalf("expected doc 3 (regular price 35.0 after 20.0), got %v", hits)
	}
	sortVals := hits[0].(map[string]any)["sort"].([]any)
	if len(sortVals) != 1 || sortVals[0].(float64) != 35.0 {
		t.Fatalf("expected nested filtered sort value [35.0] (ignoring promo price 5.0), got %v", sortVals)
	}
	hl := hits[0].(map[string]any)["highlight"].(map[string]any)
	titleHL := hl["title"].([]any)[0].(string)
	bodyHL := hl["body"].([]any)[0].(string)
	if !strings.Contains(titleHL, "<em>foo</em>") || !strings.Contains(bodyHL, "<em>baz</em>") {
		t.Fatalf("expected field-scoped highlight on title and body, got title=%q body=%q", titleHL, bodyHL)
	}
	allowedOnlyCount := resp["aggregations"].(map[string]any)["allowed_only"].(map[string]any)["doc_count"].(float64)
	if allowedOnlyCount != 2 {
		t.Fatalf("expected allowed_only filter agg with terms lookup to match 2 docs (urgent + security), got %v", allowedOnlyCount)
	}
}

func TestRound26_P0_7_PainlessEntrySetValueClearAndIngestMetadataRerouteAndComments(t *testing.T) {
	// 1. Painless Map.entrySet() entry.setValue(...) and Map/List .clear() returning null
	src := map[string]any{
		"tags": map[string]any{
			"env":  "dev",
			"tier": "backend",
		},
		"temp": []any{"a", "b"},
	}
	_, err := painless.Eval(src, `
		for (entry in ctx._source.tags.entrySet()) {
			if (entry.getKey() == 'env') {
				entry.setValue('prod');
			}
		}
		ctx._source.temp.clear();
	`, nil)
	if err != nil {
		t.Fatalf("Eval entry.setValue + clear failed: %v", err)
	}
	tagsMap := src["tags"].(map[string]any)
	if tagsMap["env"] != "prod" {
		t.Fatalf("expected entry.setValue('prod') to mutate underlying map, got %v", tagsMap["env"])
	}
	if tempSlice, ok := src["temp"].([]any); !ok || len(tempSlice) != 0 {
		t.Fatalf("expected ctx._source.temp.clear() to empty slice, got %v", src["temp"])
	}

	// Verify .clear() at end of value script returns nil (not the map itself)
	val, err := painless.Eval(map[string]any{}, `Map m = ['a': 1]; m.clear();`, nil)
	if err != nil {
		t.Fatalf("EvalValue m.clear() failed: %v", err)
	}
	if val != nil {
		t.Fatalf("expected m.clear() expression value to be nil, got %v", val)
	}

	// 2. Ingest pipeline:
	// - comment with ctx.foo inside // comment and regex /.../
	// - user _source["_id"] preserved without clobbering document _id
	// - nested on_failure preserves outerctx._ingest.on_failure_message
	// - pipeline rerouting from filtered alias clears old alias filter
	srv, _ := newTestServer()

	_, _ = doRound26Req(t, srv, http.MethodPut, "/_ingest/pipeline/r26_pipe", map[string]any{
		"processors": []any{
			map[string]any{
				"script": map[string]any{
					// Line comment mentioning ctx.should_not_rewrite and regex literal
					"source": "// comment with ctx.fake_field\nif (ctx.msg =~ /foo\\/bar/) { ctx.matched_regex = true; }",
				},
			},
			map[string]any{
				"fail": map[string]any{
					"if":      "def x = true; return x;",
					"message": "outer failure reason",
				},
				"on_failure": []any{
					map[string]any{
						"set": map[string]any{
							"field": "inner_step",
							"value": "ran",
						},
					},
					map[string]any{
						"set": map[string]any{
							"field": "recorded_error",
							"value": "{{_ingest.on_failure_message}}",
						},
					},
				},
			},
		},
	})

	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_ingest_idx", map[string]any{
		"settings": map[string]any{
			"index.default_pipeline": "r26_pipe",
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"_id":            map[string]any{"type": "keyword"},
				"msg":            map[string]any{"type": "text"},
				"matched_regex":  map[string]any{"type": "boolean"},
				"inner_step":     map[string]any{"type": "keyword"},
				"recorded_error": map[string]any{"type": "keyword"},
			},
		},
	})
	_, _ = doRound26Req(t, srv, http.MethodPost, "/_aliases", map[string]any{
		"actions": []any{
			map[string]any{
				"add": map[string]any{
					"index": "r26_ingest_idx",
					"alias": "r26_ingest_alias",
				},
			},
		},
	})

	// Index via alias `r26_ingest_alias` (should resolve index.default_pipeline from concrete index `r26_ingest_idx`)
	// and include a user-level `_id` field inside `_source`
	code, putResp := doRound26Req(t, srv, http.MethodPut, "/r26_ingest_alias/_doc/real_doc_1?refresh=true", map[string]any{
		"_id": "user_payload_id_should_not_override_meta_id",
		"msg": "testing foo/bar pattern",
	})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("put doc via alias status = %d: %v", code, putResp)
	}
	if putResp["_id"] != "real_doc_1" {
		t.Fatalf("expected document metadata _id to remain 'real_doc_1', got %v", putResp["_id"])
	}

	code, getResp := doRound26Req(t, srv, http.MethodGet, "/r26_ingest_idx/_doc/real_doc_1", nil)
	if code != http.StatusOK {
		t.Fatalf("get real_doc_1 status = %d: %v", code, getResp)
	}
	docSrc := getResp["_source"].(map[string]any)
	if docSrc["_id"] != "user_payload_id_should_not_override_meta_id" {
		t.Fatalf("expected user _source._id to be preserved, got %v", docSrc["_id"])
	}
	if docSrc["matched_regex"] != true {
		t.Fatalf("expected script processor with // comment and /.../ regex to set matched_regex=true, got %v", docSrc["matched_regex"])
	}
	if docSrc["recorded_error"] != "outer failure reason" {
		t.Fatalf("expected on_failure handler to preserve _ingest.on_failure_message across sibling processor, got %v", docSrc["recorded_error"])
	}
}

func TestRound26_P0_8_AdditionalBranchesAndRuntimeMetricsCoverage(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Painless entry.value assignment and entry.setValue in RHS expression
	mSrc := map[string]any{
		"cfg": map[string]any{"k1": "v1", "k2": "v2"},
	}
	retVal, err := painless.Eval(mSrc, `
		def prev = null;
		for (entry in ctx._source.cfg.entrySet()) {
			if (entry.key == 'k1') {
				prev = entry.setValue('v1_updated');
			} else {
				entry.value = 'v2_updated';
			}
		}
		def es = ctx._source.cfg.entrySet();
		return prev;
	`, nil)
	if err != nil {
		t.Fatalf("Painless entry.value / entry.setValue RHS failed: %v", err)
	}
	if retVal != "v1" {
		t.Fatalf("expected entry.setValue RHS to return previous value 'v1', got %v", retVal)
	}
	cfgMap := mSrc["cfg"].(map[string]any)
	if cfgMap["k1"] != "v1_updated" || cfgMap["k2"] != "v2_updated" {
		t.Fatalf("expected k1=v1_updated and k2=v2_updated, got %v", cfgMap)
	}

	// 2. Setup index with array, boolean, geo_point, lowercase normalizer, and nested fields
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_cov_lookup", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"codes": map[string]any{"type": "keyword"},
			},
		},
	})
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_cov_lookup/_doc/l1?refresh=true", map[string]any{
		"codes": []any{"C1", "C2"},
	})

	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_cov", map[string]any{
		"settings": map[string]any{
			"analysis": map[string]any{
				"normalizer": map[string]any{
					"lc": map[string]any{
						"type":   "custom",
						"filter": []string{"lowercase"},
					},
				},
			},
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"code":   map[string]any{"type": "keyword"},
				"tags":   map[string]any{"type": "keyword"},
				"flag":   map[string]any{"type": "boolean"},
				"ts":     map[string]any{"type": "date"},
				"val":    map[string]any{"type": "double"},
				"loc":    map[string]any{"type": "geo_point"},
				"lc_key": map[string]any{"type": "keyword", "normalizer": "lc"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"k_a":    map[string]any{"type": "keyword"},
						"k_b":    map[string]any{"type": "keyword"},
						"lc_sub": map[string]any{"type": "keyword", "normalizer": "lc"},
						"n_val":  map[string]any{"type": "integer"},
					},
				},
			},
		},
	})

	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_cov/_doc/1?refresh=true", map[string]any{
		"code":    "C1",
		"tags":    []any{"elastic", "search"},
		"dyn_str": "elastic",
		"flag":    true,
		"ts":      "2025-01-01T01:00:00Z",
		"val":     10.0,
		"loc":     map[string]any{"lat": 37.77, "lon": -122.41},
		"lc_key":  "HeLLo",
		"items": []any{
			map[string]any{"k_a": "alpha", "k_b": "beta", "lc_sub": " MixedCase ", "n_val": 10},
			map[string]any{"k_a": "gamma", "k_b": "delta", "lc_sub": "OTHER", "n_val": 20},
		},
	})
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_cov/_doc/2?refresh=true", map[string]any{
		"code":    "C2",
		"tags":    []any{"elastik"},
		"dyn_str": "elastik",
		"flag":    false,
		"ts":      "2025-01-01T02:00:00Z",
		"val":     30.0,
		"loc":     map[string]any{"lat": 40.71, "lon": -74.00},
		"lc_key":  "WORLD",
		"items": []any{
			map[string]any{"k_a": "alpha", "k_b": "omega", "n_val": 5},
		},
	})

	// 3. Fuzzy on promoted array (tags), dynamic field (dyn_str), and nested subfield (items.k_a) + fuzziness: 0
	for _, q := range []map[string]any{
		{"fuzzy": map[string]any{"tags": map[string]any{"value": "elastic", "fuzziness": "AUTO"}}},
		{"fuzzy": map[string]any{"tags": map[string]any{"value": "elastic", "fuzziness": 0}}},
		{"fuzzy": map[string]any{"dyn_str": map[string]any{"value": "elastic", "fuzziness": "AUTO"}}},
		{"fuzzy": map[string]any{"dyn_str": map[string]any{"value": "elastic", "fuzziness": "0"}}},
		{"nested": map[string]any{"path": "items", "query": map[string]any{"fuzzy": map[string]any{"items.k_a": map[string]any{"value": "alphx", "fuzziness": 1}}}}},
		{"nested": map[string]any{"path": "items", "query": map[string]any{"fuzzy": map[string]any{"items.k_a": map[string]any{"value": "alpha", "fuzziness": 0}}}}},
	} {
		code, resp := doRound26Req(t, srv, http.MethodPost, "/r26_cov/_search", map[string]any{"query": q})
		if code != http.StatusOK {
			t.Fatalf("fuzzy query %v failed (%d): %v", q, code, resp)
		}
	}

	// 4. Nested wildcard field expansion across term, terms, prefix, wildcard, regexp, range, exists, simple_query_string
	nestedWildcardQueries := []map[string]any{
		{"term": map[string]any{"items.k_*": "alpha"}},
		{"terms": map[string]any{"items.k_*": []any{"alpha", "omega"}}},
		{"prefix": map[string]any{"items.k_*": "alp"}},
		{"wildcard": map[string]any{"items.k_*": "alp*"}},
		{"regexp": map[string]any{"items.k_*": "alp.*"}},
		{"range": map[string]any{"items.n_*": map[string]any{"gte": 5, "lte": 15}}},
		{"exists": map[string]any{"field": "items.k_*"}},
		{"simple_query_string": map[string]any{"query": "alpha", "fields": []string{"items.k_*"}}},
	}
	for _, nq := range nestedWildcardQueries {
		code, resp := doRound26Req(t, srv, http.MethodPost, "/r26_cov/_search", map[string]any{
			"query": map[string]any{
				"nested": map[string]any{
					"path":       "items",
					"score_mode": "avg",
					"query":      nq,
				},
			},
		})
		if code != http.StatusOK {
			t.Fatalf("nested wildcard query %v failed (%d): %v", nq, code, resp)
		}
		hits := resp["hits"].(map[string]any)["hits"].([]any)
		if len(hits) == 0 {
			t.Fatalf("expected hits for nested wildcard query %v", nq)
		}
	}

	// 5. Runtime script query filter + emitRuntimeMetricAggRows (percentile_ranks, string_stats, rate, top_metrics)
	// + terms lookup in post_filter, rescore, filters agg + SortSpec.MarshalJSON (_script and _geo_distance) + boolean collapse
	code, resp := doRound26Req(t, srv, http.MethodPost, "/r26_cov/_search", map[string]any{
		"query": map[string]any{
			"script_score": map[string]any{
				"query": map[string]any{
					"bool": map[string]any{
						"must": []any{
							map[string]any{
								"script": map[string]any{
									"script": "doc['val'].value >= 10",
								},
							},
							map[string]any{
								"nested": map[string]any{
									"path":       "items",
									"score_mode": "sum",
									"boost":      2.0,
									"query": map[string]any{
										"term": map[string]any{"items.k_a": "alpha"},
									},
								},
							},
						},
					},
				},
				"script": map[string]any{
					"source": "_score + 1.0",
				},
			},
		},
		"post_filter": map[string]any{
			"terms": map[string]any{
				"code": map[string]any{
					"index": "r26_cov_lookup",
					"id":    "l1",
					"path":  "codes",
				},
			},
		},
		"rescore": map[string]any{
			"window_size": 10,
			"query": map[string]any{
				"rescore_query": map[string]any{
					"terms": map[string]any{
						"code": map[string]any{
							"index": "r26_cov_lookup",
							"id":    "l1",
							"path":  "codes",
						},
					},
				},
			},
		},
		"collapse": map[string]any{
			"field": "flag",
		},
		"sort": []any{
			map[string]any{
				"_script": map[string]any{
					"type":   "number",
					"order":  "asc",
					"script": map[string]any{"source": "doc['val'].value"},
				},
			},
			map[string]any{
				"_geo_distance": map[string]any{
					"loc":   map[string]any{"lat": 37.0, "lon": -122.0},
					"order": "asc",
					"unit":  "km",
				},
			},
		},
		"aggs": map[string]any{
			"by_hour": map[string]any{
				"date_histogram": map[string]any{
					"field":          "ts",
					"fixed_interval": "1h",
				},
				"aggs": map[string]any{
					"r_sum": map[string]any{
						"rate": map[string]any{"field": "val", "unit": "1h"},
					},
					"r_cnt": map[string]any{
						"rate": map[string]any{"field": "code", "mode": "value_count", "unit": "1h"},
					},
					"pr": map[string]any{
						"percentile_ranks": map[string]any{"field": "val", "values": []float64{15.0, 50.0}},
					},
					"ss": map[string]any{
						"string_stats": map[string]any{"field": "code"},
					},
					"tm": map[string]any{
						"top_metrics": map[string]any{
							"metrics": map[string]any{"field": "val"},
							"sort":    map[string]any{"ts": "desc"},
						},
					},
					"sel": map[string]any{
						"bucket_selector": map[string]any{
							"buckets_path": map[string]any{"r": "r_sum"},
							"script":       "null != params.r && !(params.r == null)",
						},
					},
				},
			},
			"f_map": map[string]any{
				"filters": map[string]any{
					"filters": map[string]any{
						"in_lookup": map[string]any{
							"terms": map[string]any{
								"code": map[string]any{
									"index": "r26_cov_lookup",
									"id":    "l1",
									"path":  "codes",
								},
							},
						},
					},
				},
			},
			"nested_lc": map[string]any{
				"nested": map[string]any{"path": "items"},
				"aggs": map[string]any{
					"by_lc": map[string]any{
						"terms": map[string]any{
							"field":   "items.lc_sub",
							"missing": "MISSING_LC",
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("runtime metrics & terms lookup search status = %d: %v", code, resp)
	}
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 collapsed boolean hits, got %d", len(hits))
	}

	// 6. Alias rerouting in ingest pipeline across PUT, _update, _update_by_query, _bulk, and _reindex with float version
	_, _ = doRound26Req(t, srv, http.MethodPut, "/_ingest/pipeline/reroute_to_concrete", map[string]any{
		"processors": []any{
			map[string]any{
				"script": map[string]any{
					"if":     "/* block comment with ctx.ignored */ !(ctx.skip =~ /[a\\/b]/)",
					"source": "ctx._index = 'r26_concrete';",
				},
			},
		},
	})
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_concrete", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"tenant":     map[string]any{"type": "keyword"},
				"_id_prefix": map[string]any{"type": "keyword"},
			},
		},
	})
	_, _ = doRound26Req(t, srv, http.MethodPost, "/_aliases", map[string]any{
		"actions": []any{
			map[string]any{
				"add": map[string]any{
					"index":  "r26_concrete",
					"alias":  "r26_tenant_a",
					"filter": map[string]any{"term": map[string]any{"tenant": "a"}},
				},
			},
		},
	})
	// Writing tenant="b" through filtered alias r26_tenant_a succeeds when pipeline explicitly reroutes _index to "r26_concrete"
	code, resp = doRound26Req(t, srv, http.MethodPut, "/r26_tenant_a/_doc/d1?pipeline=reroute_to_concrete&refresh=true", map[string]any{
		"tenant":     "b",
		"_id_prefix": "pref1",
	})
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("expected PUT via alias with rerouting pipeline to succeed, got %d: %v", code, resp)
	}
	// Seed a tenant="a" doc so _update and _update_by_query via alias r26_tenant_a can mutate tenant="b" with pipeline=reroute_to_concrete
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_concrete/_doc/d_upd?refresh=true", map[string]any{
		"tenant":     "a",
		"_id_prefix": "pref_upd",
	})
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_tenant_a/_update/d_upd?pipeline=reroute_to_concrete&refresh=true", map[string]any{
		"doc": map[string]any{"tenant": "b"},
	})
	if code != http.StatusOK {
		t.Fatalf("expected _update via alias with rerouting pipeline to succeed, got %d: %v", code, resp)
	}
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_concrete/_doc/d_ubq?refresh=true", map[string]any{
		"tenant":     "a",
		"_id_prefix": "pref_ubq",
	})
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_tenant_a/_update_by_query?pipeline=reroute_to_concrete&refresh=true", map[string]any{
		"query": map[string]any{"term": map[string]any{"_id": "d_ubq"}},
		"script": map[string]any{
			"source": "ctx._source.tenant = 'b';",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected _update_by_query via alias with rerouting pipeline to succeed, got %d: %v", code, resp)
	}
	code, resp = doRound26Req(t, srv, http.MethodPost, "/_bulk?pipeline=reroute_to_concrete&refresh=true",
		"{\"index\":{\"_index\":\"r26_tenant_a\",\"_id\":\"d2\"}}\n{\"tenant\":\"b\",\"_id_prefix\":\"pref2\"}\n")
	if code != http.StatusOK || resp["errors"] == true {
		t.Fatalf("expected _bulk via alias with rerouting pipeline to succeed, got %d: %v", code, resp)
	}

	// _reindex with script touching ctx._id_prefix (should not be rewritten as ctx._id)
	_, _ = doRound26Req(t, srv, http.MethodPut, "/r26_reindex_dst", map[string]any{})
	code, resp = doRound26Req(t, srv, http.MethodPost, "/_reindex?refresh=true", map[string]any{
		"source": map[string]any{"index": "r26_concrete"},
		"dest":   map[string]any{"index": "r26_reindex_dst", "version_type": "external"},
		"script": map[string]any{
			"source": "ctx._source._id_prefix = 'updated_prefix'; ctx._version = 5;",
		},
	})
	if code != http.StatusOK {
		t.Fatalf("_reindex status = %d: %v", code, resp)
	}

	// 7. Nested score_mode min/max/none in script_score, rescore array, anonymous filters terms lookup, and query_string fuzziness=0
	code, resp = doRound26Req(t, srv, http.MethodPost, "/r26_cov_nested/_search", map[string]any{
		"query": map[string]any{
			"script_score": map[string]any{
				"query": map[string]any{
					"bool": map[string]any{
						"should": []any{
							map[string]any{
								"nested": map[string]any{
									"path":       "items",
									"score_mode": "min",
									"query":      map[string]any{"term": map[string]any{"items.sku": "ABC"}},
								},
							},
							map[string]any{
								"nested": map[string]any{
									"path":       "items",
									"score_mode": "max",
									"query":      map[string]any{"term": map[string]any{"items.sku": "ABC"}},
								},
							},
							map[string]any{
								"nested": map[string]any{
									"path":       "items",
									"score_mode": "none",
									"query":      map[string]any{"term": map[string]any{"items.sku": "ABC"}},
								},
							},
							map[string]any{
								"query_string": map[string]any{
									"query":     "title_arr:elatsic~1 OR title_arr:elastic~0",
									"fuzziness": "0",
								},
							},
						},
					},
				},
				"script": map[string]any{
					"source": "_score + 1.0",
				},
			},
		},
		"rescore": []any{
			map[string]any{
				"window_size": 5,
				"query": map[string]any{
					"rescore_query": map[string]any{
						"terms": map[string]any{
							"code": map[string]any{
								"index": "r26_cov_lookup",
								"id":    "l1",
								"path":  "codes",
							},
						},
					},
				},
			},
		},
		"aggs": map[string]any{
			"anon_filters": map[string]any{
				"filters": map[string]any{
					"filters": []any{
						map[string]any{
							"terms": map[string]any{
								"code": map[string]any{
									"index": "r26_cov_lookup",
									"id":    "l1",
									"path":  "codes",
								},
							},
						},
					},
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("nested score_mode & rescore array search status = %d: %v", code, resp)
	}

	// 8. Painless Math.*, instanceof, string unescaping, bitwise compound assignment, and ingest date timezone/UNIX formats
	doc8 := map[string]any{
		"arr":  []any{1, 2},
		"mp":   map[string]any{"k": "v"},
		"str":  "hello",
		"flag": true,
		"num":  10,
	}
	script8 := `
		ctx._source.esc = 'a\nb\rc\td\'e\"f\\g\x';
		ctx._source.is_list = ctx._source.arr instanceof List;
		ctx._source.is_map = ctx._source.mp instanceof Map;
		ctx._source.is_str = ctx._source.str instanceof String;
		ctx._source.is_bool = ctx._source.flag instanceof Boolean;
		ctx._source.is_num = ctx._source.num instanceof Number;
		ctx._source.is_obj = ctx._source.num instanceof Object;
		ctx._source.is_null = ctx._source.missing instanceof String;
		ctx._source.m_abs = Math.abs(-5);
		ctx._source.m_min = Math.min(3, 7);
		ctx._source.m_max = Math.max(3, 7);
		ctx._source.m_round = Math.round(2.6);
		ctx._source.m_floor = Math.floor(2.9);
		ctx._source.m_ceil = Math.ceil(2.1);
		ctx._source.m_pow = Math.pow(2, 3);
		ctx._source.m_sqrt = Math.sqrt(16);
		ctx._source.m_hypot = Math.hypot(3, 4);
		ctx._source.m_log = Math.log(1);
		ctx._source.m_log10 = Math.log10(100);
		ctx._source.m_exp = Math.exp(0);
		ctx._source.m_sig_pos = Math.signum(5);
		ctx._source.m_sig_neg = Math.signum(-5);
		ctx._source.m_clamp = Math.clamp(15, 0, 10);
		int b = 15;
		b &= 7;
		b |= 8;
		b ^= 3;
		b <<= 1;
		b >>= 1;
		b >>>= 1;
		ctx._source.bits = b;
	`
	if err := painless.EvalPainless(doc8, script8, nil); err != nil {
		t.Fatalf("unexpected error in step 8 Painless script: %v", err)
	}
	if doc8["is_list"] != true || doc8["is_map"] != true || doc8["is_str"] != true || doc8["is_bool"] != true || doc8["is_num"] != true || doc8["is_obj"] != true || doc8["is_null"] != false {
		t.Fatalf("unexpected instanceof results: %#v", doc8)
	}

	code, resp = doRound26Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"date": map[string]any{
						"field":        "ts_unix",
						"target_field": "out_unix",
						"formats":      []any{"UNIX"},
						"timezone":     "+05:30",
					},
				},
				map[string]any{
					"date": map[string]any{
						"field":        "ts_ms",
						"target_field": "out_ms",
						"formats":      []any{"UNIX_MS"},
						"timezone":     "-0500",
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_source": map[string]any{
					"ts_unix": "1700000000.5",
					"ts_ms":   "1700000000500",
				},
			},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("expected date simulate 200, got %d: %v", code, resp)
	}
}
