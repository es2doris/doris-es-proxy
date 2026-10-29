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
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func r20Req(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var bodyStr string
	if body != nil {
		if s, ok := body.(string); ok {
			bodyStr = s
		} else {
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal body failed: %v", err)
			}
			bodyStr = string(b)
		}
	}
	req := httptest.NewRequest(method, path, strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestRound20_SortScriptPushdownNestedFilterAndMedianMode(t *testing.T) {
	srv, _ := newTestServer()

	// Create index with numeric scalar, numeric array, and nested items
	rr := r20Req(t, srv, http.MethodPut, "/r20_sort", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title":  map[string]any{"type": "keyword"},
				"price":  map[string]any{"type": "double"},
				"scores": map[string]any{"type": "double"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"status": map[string]any{"type": "keyword"},
						"cost":   map[string]any{"type": "double"},
					},
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", rr.Code, rr.Body.String())
	}

	docs := []map[string]any{
		{
			"title":  "docA",
			"price":  10.0,
			"scores": []any{10.0, 20.0, 90.0}, // median = 20
			"items": []any{
				map[string]any{"status": "active", "cost": 50.0},
				map[string]any{"status": "inactive", "cost": 5.0},
			},
		},
		{
			"title":  "docB",
			"price":  30.0,
			"scores": []any{10.0, 30.0, 50.0, 70.0}, // median = (30+50)/2 = 40
			"items": []any{
				map[string]any{"status": "active", "cost": 15.0},
				map[string]any{"status": "inactive", "cost": 100.0},
			},
		},
		{
			"title":  "docC",
			"price":  20.0,
			"scores": []any{5.0, 15.0, 25.0}, // median = 15
			"items": []any{
				map[string]any{"status": "active", "cost": 30.0},
				map[string]any{"status": "inactive", "cost": 1.0},
			},
		},
	}
	for i, d := range docs {
		id := string(rune('1' + i))
		if r := r20Req(t, srv, http.MethodPut, "/r20_sort/_doc/"+id, d); r.Code != http.StatusCreated && r.Code != http.StatusOK {
			t.Fatalf("index doc %s failed: %d %s", id, r.Code, r.Body.String())
		}
	}

	// 1. _script sort with params pushdown & pagination (from: 1, size: 1)
	rr = r20Req(t, srv, http.MethodPost, "/r20_sort/_search", map[string]any{
		"from": 1,
		"size": 1,
		"sort": []any{
			map[string]any{
				"_script": map[string]any{
					"type":  "number",
					"order": "desc",
					"script": map[string]any{
						"source": "doc['price'].value * params.mult",
						"params": map[string]any{"mult": 2.5},
					},
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("_script sort search failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit with from=1,size=1, got %d", len(hits))
	}
	hit0 := hits[0].(map[string]any)
	if hit0["_id"] != "3" { // docB(75), docC(50), docA(25) -> offset 1 is docC ("3")
		t.Fatalf("expected _id=3 at offset 1, got %v", hit0["_id"])
	}
	sortVals := hit0["sort"].([]any)
	if len(sortVals) != 1 || sortVals[0].(float64) != 50.0 {
		t.Fatalf("expected sort=[50.0], got %v", sortVals)
	}

	// 2. nested.filter sort: sort by items.cost ASC but only where items.status == "active"
	// Without nested.filter, min(items.cost) would be docC(1.0), docA(5.0), docB(15.0).
	// With nested.filter status=="active", min(items.cost) is docB(15.0), docC(30.0), docA(50.0).
	rr = r20Req(t, srv, http.MethodPost, "/r20_sort/_search", map[string]any{
		"sort": []any{
			map[string]any{
				"items.cost": map[string]any{
					"order": "asc",
					"mode":  "min",
					"nested": map[string]any{
						"path": "items",
						"filter": map[string]any{
							"term": map[string]any{"items.status": "active"},
						},
					},
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("nested.filter sort failed: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 3 {
		t.Fatalf("expected 3 hits, got %d", len(hits))
	}
	gotIDs := []string{
		hits[0].(map[string]any)["_id"].(string),
		hits[1].(map[string]any)["_id"].(string),
		hits[2].(map[string]any)["_id"].(string),
	}
	if strings.Join(gotIDs, ",") != "2,3,1" {
		t.Fatalf("expected nested.filter sort order [2,3,1], got %v", gotIDs)
	}
	if s0 := hits[0].(map[string]any)["sort"].([]any)[0].(float64); s0 != 15.0 {
		t.Fatalf("expected first hit sort value 15.0, got %v", s0)
	}

	// 3. mode: "median" sort on multi-value array field `scores` DESC -> docB(40), docA(20), docC(15)
	rr = r20Req(t, srv, http.MethodPost, "/r20_sort/_search", map[string]any{
		"sort": []any{
			map[string]any{
				"scores": map[string]any{
					"order": "desc",
					"mode":  "median",
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("median sort failed: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	gotIDs = []string{
		hits[0].(map[string]any)["_id"].(string),
		hits[1].(map[string]any)["_id"].(string),
		hits[2].(map[string]any)["_id"].(string),
	}
	if strings.Join(gotIDs, ",") != "2,1,3" {
		t.Fatalf("expected median sort order [2,1,3], got %v", gotIDs)
	}
	if s0 := hits[0].(map[string]any)["sort"].([]any)[0].(float64); s0 != 40.0 {
		t.Fatalf("expected docB median sort value 40.0, got %v", s0)
	}
}

func TestRound20_QueryStringUnaryOperatorsBoostKeywordMatchAndTermsSetCaseInsensitive(t *testing.T) {
	srv, _ := newTestServer()

	rr := r20Req(t, srv, http.MethodPut, "/r20_dsl", map[string]any{
		"settings": map[string]any{
			"analysis": map[string]any{
				"normalizer": map[string]any{
					"lc_norm": map[string]any{
						"type":   "custom",
						"filter": []any{"lowercase"},
					},
				},
			},
		},
		"mappings": map[string]any{
			"properties": map[string]any{
				"status":   map[string]any{"type": "keyword"},
				"env":      map[string]any{"type": "keyword"},
				"tag":      map[string]any{"type": "keyword"},
				"category": map[string]any{"type": "keyword"},
				"roles":    map[string]any{"type": "keyword", "normalizer": "lc_norm"},
				"req_cnt":  map[string]any{"type": "integer"},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", rr.Code, rr.Body.String())
	}

	docs := []map[string]any{
		{"status": "open", "env": "stage", "tag": "modern", "category": "foo bar", "roles": []any{"Admin", "Editor"}, "req_cnt": 2},
		{"status": "open", "env": "prod", "tag": "modern", "category": "foo", "roles": []any{"Viewer"}, "req_cnt": 1},
		{"status": "open", "env": "stage", "tag": "legacy", "category": "bar", "roles": []any{"Admin"}, "req_cnt": 2},
	}
	for i, d := range docs {
		id := string(rune('1' + i))
		r20Req(t, srv, http.MethodPut, "/r20_dsl/_doc/"+id, d)
	}

	// 1. query_string with unary +, -, ! and boost: 3.5
	rr = r20Req(t, srv, http.MethodPost, "/r20_dsl/_search", map[string]any{
		"query": map[string]any{
			"query_string": map[string]any{
				"query": "+status:open -env:prod !tag:legacy",
				"boost": 3.5,
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("query_string failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected only doc 1 from unary +status:open -env:prod !tag:legacy, got %v", hits)
	}
	if score := hits[0].(map[string]any)["_score"].(float64); score < 3.0 {
		t.Fatalf("expected boosted score >= 3.0 from query_string boost=3.5, got %v", score)
	}

	// 2. match & match_phrase on keyword field with whitespace ("foo bar") must match only exact "foo bar" (doc 1), not "foo" (doc 2) or "bar" (doc 3)
	for _, qType := range []string{"match", "match_phrase"} {
		rr = r20Req(t, srv, http.MethodPost, "/r20_dsl/_search", map[string]any{
			"query": map[string]any{
				qType: map[string]any{
					"category": "foo bar",
				},
			},
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("%s on keyword failed: %d %s", qType, rr.Code, rr.Body.String())
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		hits = resp["hits"].(map[string]any)["hits"].([]any)
		if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
			t.Fatalf("expected only doc 1 for %s on keyword 'foo bar', got %d hits: %v", qType, len(hits), hits)
		}
	}

	// 3. terms_set on lowercase-normalized field with uppercase query terms ["ADMIN", "EDITOR"]
	rr = r20Req(t, srv, http.MethodPost, "/r20_dsl/_search", map[string]any{
		"query": map[string]any{
			"terms_set": map[string]any{
				"roles": map[string]any{
					"terms":                      []any{"ADMIN", "EDITOR"},
					"minimum_should_match_field": "req_cnt",
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("terms_set failed: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 from case-insensitive terms_set on normalizer field, got %v", hits)
	}
}

func TestRound20_AnonymousFiltersAggNestedScriptTermsAndNumericScriptCoalesce(t *testing.T) {
	srv, _ := newTestServer()

	rr := r20Req(t, srv, http.MethodPut, "/r20_aggs", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"env":   map[string]any{"type": "keyword"},
				"bonus": map[string]any{"type": "long"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"sku":  map[string]any{"type": "keyword"},
						"tier": map[string]any{"type": "keyword"},
					},
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", rr.Code, rr.Body.String())
	}

	docs := []map[string]any{
		{
			"env":   "prod",
			"bonus": 100,
			"items": []any{
				map[string]any{"sku": "A", "tier": "gold"},
				map[string]any{"sku": "B", "tier": "silver"},
			},
		},
		{
			"env":   "prod",
			"bonus": 200,
			"items": []any{
				map[string]any{"sku": "A", "tier": "gold"},
			},
		},
		{
			"env": "stage", // bonus is missing/NULL!
			"items": []any{
				map[string]any{"sku": "B", "tier": "silver"},
			},
		},
	}
	for i, d := range docs {
		id := string(rune('1' + i))
		r20Req(t, srv, http.MethodPut, "/r20_aggs/_doc/"+id, d)
	}

	rr = r20Req(t, srv, http.MethodPost, "/r20_aggs/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"anon_filters": map[string]any{
				"filters": map[string]any{
					"filters": []any{
						map[string]any{"term": map[string]any{"env": "prod"}},
						map[string]any{"term": map[string]any{"env": "stage"}},
					},
				},
			},
			"nested_items": map[string]any{
				"nested": map[string]any{"path": "items"},
				"aggs": map[string]any{
					"sku_tier": map[string]any{
						"terms": map[string]any{
							"script": map[string]any{
								"source": "doc['items.sku'].value + '-' + doc['items.tier'].value",
							},
						},
					},
				},
			},
			"bonus_plus_ten": map[string]any{
				"terms": map[string]any{
					"field": "bonus",
					"script": map[string]any{
						"source": "params._value + 10",
					},
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("aggs search failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	aggs := resp["aggregations"].(map[string]any)

	// 1. Top-level anonymous filters agg returns array of buckets
	anonBuckets, ok := aggs["anon_filters"].(map[string]any)["buckets"].([]any)
	if !ok || len(anonBuckets) != 2 {
		t.Fatalf("expected 2 anonymous filter buckets array, got %T %v", aggs["anon_filters"], aggs["anon_filters"])
	}
	if anonBuckets[0].(map[string]any)["doc_count"].(float64) != 2 || anonBuckets[1].(map[string]any)["doc_count"].(float64) != 1 {
		t.Fatalf("expected anonymous filter doc_counts [2, 1], got %v", anonBuckets)
	}

	// 2. Nested terms script agg
	nestedBuckets := aggs["nested_items"].(map[string]any)["sku_tier"].(map[string]any)["buckets"].([]any)
	if len(nestedBuckets) != 2 {
		t.Fatalf("expected 2 nested script terms buckets, got %v", nestedBuckets)
	}
	if nestedBuckets[0].(map[string]any)["key"] != "A-gold" || nestedBuckets[0].(map[string]any)["doc_count"].(float64) != 2 {
		t.Fatalf("expected A-gold(2), got %v", nestedBuckets[0])
	}

	// 3. Numeric terms agg with field+script does NOT coalesce NULL to 0+10=10
	bonusBuckets := aggs["bonus_plus_ten"].(map[string]any)["buckets"].([]any)
	if len(bonusBuckets) != 2 {
		t.Fatalf("expected 2 bonus_plus_ten buckets (excluding NULL doc 3), got %d: %v", len(bonusBuckets), bonusBuckets)
	}
	for _, b := range bonusBuckets {
		k := fmt.Sprintf("%v", b.(map[string]any)["key"])
		if k == "10" || k == "10.0" {
			t.Fatalf("NULL bonus was falsely coalesced to 0 + 10 = 10: %v", bonusBuckets)
		}
	}
}

func TestRound20_PostFilterScriptIsolationTerminateAfterTrackScoresAndInnerHitsFixes(t *testing.T) {
	srv, _ := newTestServer()

	rr := r20Req(t, srv, http.MethodPut, "/r20_search", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"group":  map[string]any{"type": "keyword"},
				"amount": map[string]any{"type": "long"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"name":     map[string]any{"type": "keyword"},
						"price":    map[string]any{"type": "double"},
						"featured": map[string]any{"type": "boolean"},
					},
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", rr.Code, rr.Body.String())
	}

	docs := []map[string]any{
		{
			"group":  "g1",
			"amount": 10,
			"items": []any{
				map[string]any{"name": "item1", "price": 100.0, "featured": false},
				map[string]any{"name": "item2", "price": 10.0, "featured": true},
			},
		},
		{
			"group":  "g1",
			"amount": 50,
			"items": []any{
				map[string]any{"name": "item3", "price": 200.0, "featured": true},
			},
		},
		{
			"group":  "g2",
			"amount": 90,
			"items": []any{
				map[string]any{"name": "item4", "price": 300.0, "featured": true},
			},
		},
	}
	for i, d := range docs {
		id := string(rune('1' + i))
		r20Req(t, srv, http.MethodPut, "/r20_search/_doc/"+id, d)
	}

	// 1. post_filter with script query must NOT filter aggregations, and track_scores: true must populate _score on sorted search
	rr = r20Req(t, srv, http.MethodPost, "/r20_search/_search", map[string]any{
		"track_scores": true,
		"query": map[string]any{
			"match_all": map[string]any{"boost": 2.0},
		},
		"post_filter": map[string]any{
			"script": map[string]any{
				"script": "doc['amount'].value >= 50",
			},
		},
		"sort": []any{
			map[string]any{"amount": "asc"},
		},
		"aggs": map[string]any{
			"by_group": map[string]any{
				"terms": map[string]any{"field": "group"},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("post_filter script search failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits after post_filter script (amount >= 50), got %d", len(hits))
	}
	if hits[0].(map[string]any)["_score"] == nil {
		t.Fatalf("expected non-null _score when track_scores=true, got nil")
	}
	// Aggregations must reflect all 3 query-matched docs (g1: 2, g2: 1), not just the 2 post_filter docs!
	groupBuckets := resp["aggregations"].(map[string]any)["by_group"].(map[string]any)["buckets"].([]any)
	if groupBuckets[0].(map[string]any)["key"] != "g1" || groupBuckets[0].(map[string]any)["doc_count"].(float64) != 2 {
		t.Fatalf("expected post_filter not to narrow aggregations (g1 doc_count=2), got %v", groupBuckets)
	}

	// 2. terminate_after with from > 0 on script query: terminate_after=2 caps the matched pool to 2 docs, so from=1, size=5 returns 1 hit and total=2
	rr = r20Req(t, srv, http.MethodPost, "/r20_search/_search", map[string]any{
		"from":            1,
		"size":            5,
		"terminate_after": 2,
		"query": map[string]any{
			"script": map[string]any{
				"script": "doc['amount'].value > 0",
			},
		},
		"sort": []any{
			map[string]any{"amount": "asc"},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("terminate_after search failed: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	totalVal := resp["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64)
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if totalVal != 2 || len(hits) != 1 {
		t.Fatalf("expected total=2 and len(hits)=1 with terminate_after=2, from=1, got total=%v len=%d", totalVal, len(hits))
	}

	// 3. Multiple nested queries on the same path ("items") with distinct inner_hits.name ("high_price" and "featured_items")
	rr = r20Req(t, srv, http.MethodPost, "/r20_search/_search", map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{
						"nested": map[string]any{
							"path": "items",
							"query": map[string]any{
								"range": map[string]any{"items.price": map[string]any{"gte": 50}},
							},
							"inner_hits": map[string]any{"name": "high_price"},
						},
					},
					map[string]any{
						"nested": map[string]any{
							"path": "items",
							"query": map[string]any{
								"term": map[string]any{"items.featured": true},
							},
							"inner_hits": map[string]any{"name": "featured_items"},
						},
					},
				},
			},
		},
		"sort": []any{map[string]any{"amount": "asc"}},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("multi nested inner_hits failed: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) == 0 {
		t.Fatalf("expected hits for multi nested inner_hits")
	}
	ihMap := hits[0].(map[string]any)["inner_hits"].(map[string]any)
	if _, ok := ihMap["high_price"]; !ok {
		t.Fatalf("missing high_price inner_hits in %v", ihMap)
	}
	if _, ok := ihMap["featured_items"]; !ok {
		t.Fatalf("missing featured_items inner_hits in %v", ihMap)
	}

	// 4. Collapse with multiple inner_hits where first has custom sort and second uses top-level sort
	rr = r20Req(t, srv, http.MethodPost, "/r20_search/_search", map[string]any{
		"sort": []any{map[string]any{"amount": "asc"}},
		"collapse": map[string]any{
			"field": "group",
			"inner_hits": []any{
				map[string]any{
					"name": "highest_amount",
					"size": 2,
					"sort": []any{map[string]any{"amount": "desc"}},
				},
				map[string]any{
					"name": "default_order",
					"size": 2,
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("collapse multi inner_hits failed: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	hits = resp["hits"].(map[string]any)["hits"].([]any)
	g1Hit := hits[0].(map[string]any)
	g1IH := g1Hit["inner_hits"].(map[string]any)
	hiHits := g1IH["highest_amount"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	defHits := g1IH["default_order"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if hiHits[0].(map[string]any)["_id"] != "2" || defHits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("collapse inner_hits slice aliasing corrupted ordering: highest_amount[0]=%v, default_order[0]=%v",
			hiHits[0].(map[string]any)["_id"], defHits[0].(map[string]any)["_id"])
	}
}

func TestRound20_PipelineBucketSelectorNormalizeFormattingAndNestedChildDetection(t *testing.T) {
	srv, _ := newTestServer()

	rr := r20Req(t, srv, http.MethodPut, "/r20_pipe", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"ts":     map[string]any{"type": "date"},
				"status": map[string]any{"type": "keyword"},
				"rev":    map[string]any{"type": "double"},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", rr.Code, rr.Body.String())
	}

	docs := []map[string]any{
		{"ts": "2025-01-01T00:00:00Z", "status": "active", "rev": 10.0},
		{"ts": "2025-01-02T00:00:00Z", "status": "active", "rev": 30.0},
		{"ts": "2025-01-03T00:00:00Z", "status": "active", "rev": 60.0},
	}
	for i, d := range docs {
		id := string(rune('1' + i))
		r20Req(t, srv, http.MethodPut, "/r20_pipe/_doc/"+id, d)
	}

	rr = r20Req(t, srv, http.MethodPost, "/r20_pipe/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_day": map[string]any{
				"date_histogram": map[string]any{
					"field":          "ts",
					"fixed_interval": "1d",
				},
				"aggs": map[string]any{
					"sum_rev": map[string]any{
						"sum": map[string]any{"field": "rev"},
					},
					"keep_gt_10": map[string]any{
						"bucket_selector": map[string]any{
							"buckets_path": map[string]any{"r": "sum_rev"},
							"script":       "params.r > 10",
						},
					},
					"pct_rev": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_rev",
							"method":       "percent_of_sum",
							"format":       "0.00",
						},
					},
					"norm_0_1": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_rev",
							"method":       "rescale_0_1",
							"format":       "0.00",
						},
					},
					"norm_0_100": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_rev",
							"method":       "rescale_0_100",
							"format":       "0.00",
						},
					},
					"norm_mean": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_rev",
							"method":       "mean",
							"format":       "0.00",
						},
					},
					"norm_zscore": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_rev",
							"method":       "z-score",
							"format":       "0.00",
						},
					},
					"norm_atan": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_rev",
							"method":       "atan",
							"format":       "0.00",
						},
					},
					"diff_rev": map[string]any{
						"serial_diff": map[string]any{
							"buckets_path": "sum_rev",
							"lag":          1,
							"format":       "0.00",
						},
					},
					"mavg_rev": map[string]any{
						"moving_avg": map[string]any{
							"buckets_path": "sum_rev",
							"window":       2,
							"format":       "0.00",
						},
					},
					"active_only": map[string]any{
						"filter": map[string]any{
							"term": map[string]any{"status": "active"},
						},
						"aggs": map[string]any{
							"act_rev": map[string]any{"sum": map[string]any{"field": "rev"}},
						},
					},
					"cum_active_rev": map[string]any{
						"cumulative_sum": map[string]any{
							"buckets_path": "active_only>act_rev",
						},
					},
				},
			},
			"sum_of_cum": map[string]any{
				"sum_bucket": map[string]any{
					"buckets_path": "by_day>cum_active_rev",
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("pipeline agg search failed: %d %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	aggs := resp["aggregations"].(map[string]any)
	buckets := aggs["by_day"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets after bucket_selector (30 and 60), got %d", len(buckets))
	}
	// Surviving buckets have sum_rev 30 and 60 (sum = 90).
	// percent_of_sum on surviving buckets must be 30/90*100 = 33.333... and 60/90*100 = 66.666...
	pct0 := buckets[0].(map[string]any)["pct_rev"].(map[string]any)
	if math.Abs(pct0["value"].(float64)-33.333333) > 0.01 || pct0["value_as_string"] != "33.33" {
		t.Fatalf("expected pct_rev after bucket_selector to be 33.33, got %v", pct0)
	}
	// serial_diff on bucket[1] (60 - 30 = 30) with format "0.00"
	diff1 := buckets[1].(map[string]any)["diff_rev"].(map[string]any)
	if diff1["value_as_string"] != "30.00" {
		t.Fatalf("expected serial_diff value_as_string='30.00', got %v", diff1)
	}
	// moving_avg on bucket[1] with format "0.00"
	mavg1 := buckets[1].(map[string]any)["mavg_rev"].(map[string]any)
	if mavg1["value_as_string"] == nil || mavg1["value_as_string"] == "" {
		t.Fatalf("expected moving_avg value_as_string to be populated, got %v", mavg1)
	}
	// sum_of_cum: cumulative_sum before pruning is [10, 40, 100], after pruning is [40, 100] -> sum = 140
	sumOfCum := aggs["sum_of_cum"].(map[string]any)["value"].(float64)
	if sumOfCum != 140.0 {
		t.Fatalf("expected sum_of_cum=140.0, got %v", sumOfCum)
	}
}

func TestRound20_MappingCopyToNullValueAndSingleDocDelete404Semantics(t *testing.T) {
	srv, _ := newTestServer()

	rr := r20Req(t, srv, http.MethodPut, "/r20_map", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"first_name": map[string]any{
					"type":    "keyword",
					"copy_to": "full_search",
				},
				"last_name": map[string]any{
					"type":    "keyword",
					"copy_to": []any{"full_search", "surname_alias"},
				},
				"full_search":   map[string]any{"type": "keyword"},
				"surname_alias": map[string]any{"type": "keyword"},
				"status": map[string]any{
					"type":       "keyword",
					"null_value": "PENDING",
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", rr.Code, rr.Body.String())
	}

	// Update mapping to ensure copy_to and null_value survive DeepMergeMappingProperties
	rr = r20Req(t, srv, http.MethodPut, "/r20_map/_mapping", map[string]any{
		"properties": map[string]any{
			"extra": map[string]any{"type": "keyword"},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("put mapping failed: %d %s", rr.Code, rr.Body.String())
	}

	// Index doc with explicit null status and first_name/last_name
	rr = r20Req(t, srv, http.MethodPut, "/r20_map/_doc/1", map[string]any{
		"first_name": "Ada",
		"last_name":  "Lovelace",
		"status":     nil,
	})
	if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
		t.Fatalf("index doc failed: %d %s", rr.Code, rr.Body.String())
	}

	// 1. Search by status: "PENDING" (populated via null_value)
	rr = r20Req(t, srv, http.MethodPost, "/r20_map/_search", map[string]any{
		"query": map[string]any{
			"term": map[string]any{"status": "PENDING"},
		},
	})
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for null_value 'PENDING', got %d (%s)", len(hits), rr.Body.String())
	}

	// 2. Search by copy_to target `full_search` ("Lovelace") and `surname_alias` ("Lovelace")
	for _, targetField := range []string{"full_search", "surname_alias"} {
		rr = r20Req(t, srv, http.MethodPost, "/r20_map/_search", map[string]any{
			"query": map[string]any{
				"term": map[string]any{targetField: "Lovelace"},
			},
		})
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		hits = resp["hits"].(map[string]any)["hits"].([]any)
		if len(hits) != 1 {
			t.Fatalf("expected 1 hit on copy_to target %s='Lovelace', got %d (%s)", targetField, len(hits), rr.Body.String())
		}
	}

	// 3. Single-doc DELETE on existing doc -> 200 deleted; second DELETE on missing doc -> 404 not_found
	rr = r20Req(t, srv, http.MethodDelete, "/r20_map/_doc/1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on existing doc delete, got %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["result"] != "deleted" {
		t.Fatalf("expected result='deleted', got %v", resp["result"])
	}

	rr = r20Req(t, srv, http.MethodDelete, "/r20_map/_doc/1", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on missing doc delete, got %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["result"] != "not_found" {
		t.Fatalf("expected result='not_found', got %v", resp["result"])
	}

	// 4. Bulk delete on non-existent doc -> status 404, result "not_found"
	bulkBody := `{"delete":{"_index":"r20_map","_id":"nonexistent_999"}}` + "\n"
	rr = r20Req(t, srv, http.MethodPost, "/_bulk", bulkBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("bulk delete failed: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	items := resp["items"].([]any)
	delItem := items[0].(map[string]any)["delete"].(map[string]any)
	if delItem["status"].(float64) != 404 || delItem["result"] != "not_found" {
		t.Fatalf("expected bulk delete status=404 result=not_found, got %v", delItem)
	}
}

func TestRound20_PainlessListMapOperatorsEntrySetAndIngestRenameSplitKvParity(t *testing.T) {
	srv, _ := newTestServer()

	// Register ingest pipeline testing Painless enhancements + rename, split, kv
	rr := r20Req(t, srv, http.MethodPut, "/_ingest/pipeline/r20_ingest", map[string]any{
		"processors": []any{
			// 1. split with preserve_trailing: false (default) vs true
			map[string]any{
				"split": map[string]any{
					"field":             "raw_csv",
					"separator":         ",",
					"target_field":      "parts_trimmed",
					"preserve_trailing": false,
				},
			},
			map[string]any{
				"split": map[string]any{
					"field":             "raw_csv",
					"separator":         ",",
					"target_field":      "parts_preserved",
					"preserve_trailing": true,
				},
			},
			// 2. kv with strip_brackets, trim_key, trim_value, include_keys, exclude_keys, prefix, target_field
			map[string]any{
				"kv": map[string]any{
					"field":          "kv_str",
					"field_split":    " ",
					"value_split":    "=",
					"strip_brackets": true,
					"trim_key":       " ",
					"trim_value":     "\"'",
					"include_keys":   []any{"host", "env", "secret"},
					"exclude_keys":   []any{"secret"},
					"prefix":         "meta_",
					"target_field":   "parsed",
				},
			},
			// 3. rename with override: false (should NOT overwrite existing keep_me)
			map[string]any{
				"rename": map[string]any{
					"field":        "candidate_val",
					"target_field": "keep_me",
					"override":     false,
				},
			},
			// 4. Painless script testing List + scalar, List + List, Map + Map, list.add(idx, val), entrySet(), Elvis ?:
			map[string]any{
				"script": map[string]any{
					"source": `
						def a = [1, 2];
						def b = a + 3;
						def c = b + [4, 5];
						c.add(1, 99);
						ctx.list_result = c;
						def m1 = ['x': 1];
						def m2 = m1 + ['y': 2];
						def sum = 0;
						for (entry in m2.entrySet()) {
							sum = sum + entry.getValue();
						}
						ctx.map_sum = sum;
						ctx.elvis_false = (false ?: true);
						ctx.elvis_zero = (0 ?: 42);
						ctx.elvis_null = (null ?: 'fallback');
					`,
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("put pipeline failed: %d %s", rr.Code, rr.Body.String())
	}

	rr = r20Req(t, srv, http.MethodPost, "/_ingest/pipeline/r20_ingest/_simulate", map[string]any{
		"docs": []any{
			map[string]any{
				"_source": map[string]any{
					"raw_csv":       "a,b,,",
					"kv_str":        `[host="web01" env='prod' secret="top" ignored="x"]`,
					"candidate_val": "new_val",
					"keep_me":       "orig_val",
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("simulate pipeline failed: %d %s", rr.Code, rr.Body.String())
	}
	var simResp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &simResp)
	doc := simResp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)

	// Verify split preserve_trailing
	if pt := doc["parts_trimmed"].([]any); len(pt) != 2 {
		t.Fatalf("expected parts_trimmed=['a','b'] (len 2), got %v", pt)
	}
	if pp := doc["parts_preserved"].([]any); len(pp) != 4 {
		t.Fatalf("expected parts_preserved=['a','b','',''] (len 4), got %v", pp)
	}

	// Verify kv options
	parsed := doc["parsed"].(map[string]any)
	if parsed["meta_host"] != "web01" || parsed["meta_env"] != "prod" {
		t.Fatalf("expected meta_host=web01 and meta_env=prod in parsed kv, got %v", parsed)
	}
	if _, hasSecret := parsed["meta_secret"]; hasSecret {
		t.Fatalf("expected excluded key 'secret' to be omitted, got %v", parsed)
	}

	// Verify rename override: false preserved keep_me="orig_val" and left candidate_val intact
	if doc["keep_me"] != "orig_val" || doc["candidate_val"] != "new_val" {
		t.Fatalf("expected rename override:false to preserve keep_me=orig_val and candidate_val=new_val, got keep_me=%v candidate_val=%v",
			doc["keep_me"], doc["candidate_val"])
	}

	// Verify Painless List +, List.add(idx, val), Map +, entrySet(), and Elvis ?:
	listRes := doc["list_result"].([]any)
	if len(listRes) != 6 || listRes[1].(float64) != 99 {
		t.Fatalf("expected list_result=[1, 99, 2, 3, 4, 5], got %v", listRes)
	}
	if doc["map_sum"].(float64) != 3 {
		t.Fatalf("expected map_sum=3 from entrySet() loop, got %v", doc["map_sum"])
	}
	if doc["elvis_false"] != false || doc["elvis_zero"].(float64) != 0 || doc["elvis_null"] != "fallback" {
		t.Fatalf("unexpected Elvis operator results: false=%v zero=%v null=%v",
			doc["elvis_false"], doc["elvis_zero"], doc["elvis_null"])
	}

	// Additional coverage: direct map iteration for(e in m), e.getKey(), parent-to-child rename, self-rename error, regex kv
	rr = r20Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", map[string]any{
		"pipeline": map[string]any{
			"processors": []any{
				map[string]any{
					"rename": map[string]any{
						"field":        "same_field",
						"target_field": "same_field",
						"on_failure": []any{
							map[string]any{
								"set": map[string]any{
									"field": "self_rename_failed",
									"value": true,
								},
							},
						},
					},
				},
				map[string]any{
					"rename": map[string]any{
						"field":        "nested_parent",
						"target_field": "nested_parent.child",
					},
				},
				map[string]any{
					"kv": map[string]any{
						"field":          "kv_regex",
						"field_split":    "[;&]",
						"value_split":    "[:=]",
						"strip_brackets": true,
						"target_field":   "existing_map",
					},
				},
				map[string]any{
					"script": map[string]any{
						"source": `
							def m = ['alpha': 10, 'beta': 20];
							def keys = '';
							for (e in m) {
								keys = keys + e.getKey() + ':' + e.getValue() + ';';
							}
							ctx.direct_map_iter = keys;
						`,
					},
				},
			},
		},
		"docs": []any{
			map[string]any{
				"_source": map[string]any{
					"same_field":    "val",
					"nested_parent": "moved_to_child",
					"kv_regex":      "(k1:v1;k2=v2)",
					"existing_map":  map[string]any{"pre": "yes"},
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("simulate extended pipeline failed: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &simResp)
	doc2 := simResp["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if doc2["self_rename_failed"] != true {
		t.Fatalf("expected self-rename to trigger on_failure, got %v", doc2)
	}
	if np, ok := doc2["nested_parent"].(map[string]any); !ok || np["child"] != "moved_to_child" {
		t.Fatalf("expected parent-to-child rename nested_parent.child='moved_to_child', got %v", doc2["nested_parent"])
	}
	if em, ok := doc2["existing_map"].(map[string]any); !ok || em["pre"] != "yes" || em["k1"] != "v1" || em["k2"] != "v2" {
		t.Fatalf("expected merged existing_map with pre/k1/k2, got %v", doc2["existing_map"])
	}
	if doc2["direct_map_iter"] == nil || doc2["direct_map_iter"] == "" {
		t.Fatalf("expected direct_map_iter to be populated, got %v", doc2["direct_map_iter"])
	}
}

func TestRound20_NestedSortModesAndTextCopyToWithArrayNullValue(t *testing.T) {
	srv, _ := newTestServer()

	rr := r20Req(t, srv, http.MethodPut, "/r20_modes", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"title": map[string]any{
					"type":    "text",
					"copy_to": "combined_text",
				},
				"combined_text": map[string]any{"type": "text"},
				"tags": map[string]any{
					"type":       "keyword",
					"null_value": "NULL_TAG",
				},
				"num": map[string]any{
					"type":       "integer",
					"null_value": -1,
				},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"active": map[string]any{"type": "boolean"},
						"score":  map[string]any{"type": "double"},
					},
				},
			},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", rr.Code, rr.Body.String())
	}

	r20Req(t, srv, http.MethodPut, "/r20_modes/_doc/1", map[string]any{
		"title": "hello world",
		"tags":  []any{"a", nil},
		"num":   nil,
		"items": []any{
			map[string]any{"active": true, "score": 10.0},
			map[string]any{"active": true, "score": 30.0},
			map[string]any{"active": false, "score": 1000.0},
		},
	})
	r20Req(t, srv, http.MethodPut, "/r20_modes/_doc/2", map[string]any{
		"title": "second doc",
		"tags":  []any{"b"},
		"num":   5,
		"items": []any{
			map[string]any{"active": true, "score": 25.0},
		},
	})

	// Test nested sort with modes: max, avg, sum, median and nested.filter + runtime script_fields to exercise extractHitSortValues
	for _, mode := range []string{"max", "avg", "sum", "median"} {
		rr = r20Req(t, srv, http.MethodPost, "/r20_modes/_search", map[string]any{
			"script_fields": map[string]any{
				"s": map[string]any{"script": "1"},
			},
			"sort": []any{
				map[string]any{
					"items.score": map[string]any{
						"order": "desc",
						"mode":  mode,
						"nested": map[string]any{
							"path": "items",
							"filter": map[string]any{
								"term": map[string]any{"items.active": true},
							},
						},
					},
				},
			},
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("nested sort mode=%s failed: %d %s", mode, rr.Code, rr.Body.String())
		}
	}

	// Test null_value inside array ("NULL_TAG") and numeric null_value (-1)
	rr = r20Req(t, srv, http.MethodPost, "/r20_modes/_search", map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": []any{
					map[string]any{"term": map[string]any{"tags": "NULL_TAG"}},
					map[string]any{"term": map[string]any{"num": -1}},
				},
			},
		},
	})
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	hits := resp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for array null_value 'NULL_TAG' and num=-1, got %d (%s)", len(hits), rr.Body.String())
	}
}
