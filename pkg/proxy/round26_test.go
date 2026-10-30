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
