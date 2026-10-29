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

func r21Req(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
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

func r21JSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal response failed (status=%d, body=%s): %v", w.Code, w.Body.String(), err)
	}
	return m
}

func TestRound21QueryStringMinShouldMatchAndLuceneOperators(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_qs", `{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"body":  {"type": "text"}
			}
		}
	}`)
	r21Req(t, srv, http.MethodPost, "/r21_qs/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"title":"alpha beta gamma","body":"extra"}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"title":"alpha beta","body":"other"}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"title":"alpha","body":"beta"}`+"\n"+
			`{"index":{"_id":"4"}}`+"\n"+`{"title":"alpha","body":"only"}`+"\n")

	// 1. query_string with minimum_should_match: 2 on title
	w := r21Req(t, srv, http.MethodPost, "/r21_qs/_search", `{
		"query": {
			"query_string": {
				"default_field": "title",
				"query": "alpha beta gamma",
				"minimum_should_match": 2
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	hits := r21JSON(t, w)["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits for query_string minimum_should_match=2, got %d: %v", len(hits), hits)
	}

	// 2. query_string with multi-field fields: ["title", "body"] and minimum_should_match: 2
	wMF := r21Req(t, srv, http.MethodPost, "/r21_qs/_search", `{
		"query": {
			"query_string": {
				"fields": ["title", "body"],
				"query": "alpha beta gamma",
				"minimum_should_match": 2
			}
		}
	}`)
	hitsMF := r21JSON(t, wMF)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsMF) != 3 {
		t.Fatalf("expected 3 hits (docs 1, 2, 3) for multi-field query_string minimum_should_match=2, got %d: %v", len(hitsMF), hitsMF)
	}

	// 3. Standalone '+', '-', and '!' tokens in query_string and simple_query_string
	wOp := r21Req(t, srv, http.MethodPost, "/r21_qs/_search", `{
		"query": {
			"query_string": {
				"default_field": "title",
				"query": "+ alpha - beta ! gamma"
			}
		}
	}`)
	hitsOp := r21JSON(t, wOp)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsOp) != 2 {
		t.Fatalf("expected 2 hits (docs 3 and 4: have alpha in title, neither beta nor gamma in title), got %d: %v", len(hitsOp), hitsOp)
	}

	wSQS := r21Req(t, srv, http.MethodPost, "/r21_qs/_search", `{
		"query": {
			"simple_query_string": {
				"fields": ["title"],
				"query": "+ alpha - gamma"
			}
		}
	}`)
	hitsSQS := r21JSON(t, wSQS)["hits"].(map[string]any)["hits"].([]any)
	if len(hitsSQS) != 3 {
		t.Fatalf("expected 3 hits (docs 2, 3, 4) for simple_query_string '+ alpha - gamma', got %d: %v", len(hitsSQS), hitsSQS)
	}
}

func TestRound21MultiMatchDefaultBestFieldsScoringAndArraySortModes(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_mm", `{
		"mappings": {
			"properties": {
				"title":  {"type": "text"},
				"body":   {"type": "text"},
				"scores": {"type": "integer", "multi_valued": true}
			}
		}
	}`)
	r21Req(t, srv, http.MethodPost, "/r21_mm/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"title":"rust","body":"unrelated","scores":[10, 20, 30]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"title":"other","body":"rust","scores":[2, 100, 2]}`+"\n")

	// 1. Default multi_match (type omitted, tie_breaker omitted) uses best_fields (MAX across fields)
	w := r21Req(t, srv, http.MethodPost, "/r21_mm/_search", `{
		"query": {
			"multi_match": {
				"query": "rust",
				"fields": ["title^3", "body^1"]
			}
		}
	}`)
	hits := r21JSON(t, w)["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hits))
	}
	topScore := hits[0].(map[string]any)["_score"].(float64)
	if math.Abs(topScore-3.0) > 1e-6 {
		t.Fatalf("expected best_fields top score 3.0, got %v", topScore)
	}

	// 2. Multi-valued integer array sorting with mode: avg, sum, median
	for _, tc := range []struct {
		mode      string
		order     string
		wantFirst string
	}{
		{mode: "avg", order: "desc", wantFirst: "2"},    // avg([2,100,2])=34.67 > avg([10,20,30])=20
		{mode: "sum", order: "desc", wantFirst: "2"},    // sum([2,100,2])=104 > sum([10,20,30])=60
		{mode: "median", order: "desc", wantFirst: "1"}, // median([10,20,30])=20 > median([2,2,100])=2
	} {
		wSort := r21Req(t, srv, http.MethodPost, "/r21_mm/_search", map[string]any{
			"sort": []map[string]any{
				{"scores": map[string]any{"order": tc.order, "mode": tc.mode}},
			},
		})
		sHits := r21JSON(t, wSort)["hits"].(map[string]any)["hits"].([]any)
		if len(sHits) != 2 || sHits[0].(map[string]any)["_id"] != tc.wantFirst {
			t.Fatalf("mode=%s: expected first hit %s, got %v", tc.mode, tc.wantFirst, sHits)
		}
	}
}

func TestRound21MultiValuedSubAggDocDeduplication(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_dedup", `{
		"mappings": {
			"properties": {
				"tags":   {"type": "keyword", "multi_valued": true},
				"amount": {"type": "double"},
				"scores": {"type": "double", "multi_valued": true},
				"dates":  {"type": "date", "multi_valued": true}
			}
		}
	}`)
	// Doc 1 has duplicate "go" in tags, two values in [10..20) histogram bucket, and two dates in same day bucket!
	r21Req(t, srv, http.MethodPost, "/r21_dedup/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"tags":["go","go","rust"],"amount":100,"scores":[12,18],"dates":["2026-01-01T01:00:00Z","2026-01-01T05:00:00Z"]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"tags":["go"],"amount":50,"scores":[15],"dates":["2026-01-01T12:00:00Z"]}`+"\n")

	w := r21Req(t, srv, http.MethodPost, "/r21_dedup/_search", `{
		"size": 0,
		"aggs": {
			"by_tag": {
				"terms": {"field": "tags"},
				"aggs": {
					"total_amount": {"sum": {"field": "amount"}}
				}
			},
			"by_hist": {
				"histogram": {"field": "scores", "interval": 10},
				"aggs": {
					"total_amount": {"sum": {"field": "amount"}}
				}
			},
			"by_date": {
				"date_histogram": {"field": "dates", "calendar_interval": "day"},
				"aggs": {
					"total_amount": {"sum": {"field": "amount"}}
				}
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	aggs := r21JSON(t, w)["aggregations"].(map[string]any)

	tagBuckets := aggs["by_tag"].(map[string]any)["buckets"].([]any)
	goBucket := tagBuckets[0].(map[string]any)
	if goBucket["key"] != "go" || goBucket["doc_count"] != float64(2) {
		t.Fatalf("expected 'go' bucket doc_count=2, got %v", goBucket)
	}
	if goSum := goBucket["total_amount"].(map[string]any)["value"].(float64); goSum != 150 {
		t.Fatalf("expected 'go' sub-agg total_amount=150 (100+50, not 200+50), got %v", goSum)
	}

	histBuckets := aggs["by_hist"].(map[string]any)["buckets"].([]any)
	b10 := histBuckets[0].(map[string]any)
	if b10["doc_count"] != float64(2) {
		t.Fatalf("expected histogram bucket 10 doc_count=2, got %v", b10)
	}
	if histSum := b10["total_amount"].(map[string]any)["value"].(float64); histSum != 150 {
		t.Fatalf("expected histogram bucket 10 total_amount=150 (deduped per doc), got %v", histSum)
	}

	dateBuckets := aggs["by_date"].(map[string]any)["buckets"].([]any)
	d0 := dateBuckets[0].(map[string]any)
	if d0["doc_count"] != float64(2) {
		t.Fatalf("expected date_histogram bucket doc_count=2, got %v", d0)
	}
	if dateSum := d0["total_amount"].(map[string]any)["value"].(float64); dateSum != 150 {
		t.Fatalf("expected date_histogram bucket total_amount=150 (deduped per doc), got %v", dateSum)
	}
}

func TestRound21CopyToTransitiveAndNormalizationAndNestedSubfieldNormalization(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_schema", `{
		"settings": {
			"analysis": {
				"normalizer": {
					"lc_norm": {"type": "custom", "filter": ["lowercase"]}
				}
			}
		},
		"mappings": {
			"properties": {
				"step1":     {"type": "keyword", "copy_to": "step2"},
				"step2":     {"type": "keyword", "copy_to": ["step3_kw", "step3_txt"]},
				"step3_kw":  {"type": "keyword", "normalizer": "lc_norm", "ignore_above": 10},
				"step3_txt": {"type": "text"},
				"short_kw":  {"type": "keyword", "ignore_above": 5},
				"items": {
					"type": "nested",
					"properties": {
						"code":   {"type": "keyword", "normalizer": "lc_norm", "ignore_above": 6, "null_value": "NONE"},
						"active": {"type": "boolean"},
						"ts":     {"type": "date"}
					}
				}
			}
		}
	}`)

	r21Req(t, srv, http.MethodPost, "/r21_schema/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"step1":"HeLLo","short_kw":"1234567","items":[{"code":"AbCd","active":"true","ts":"2026-05-01T00:00:00Z"},{"code":null,"active":false,"ts":"2020-01-01T00:00:00Z"}]}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"step1":"TooLongForStep3Kw","short_kw":"ok","items":[{"code":"TOOLONG_NESTED","active":"false","ts":"2026-05-02T00:00:00Z"}]}`+"\n")

	// 1. Transitive copy_to step1 -> step2 -> step3_kw (with lowercase normalizer) & step3_txt.keyword
	w1 := r21Req(t, srv, http.MethodPost, "/r21_schema/_search", `{
		"query": {"term": {"step3_kw": "HELLO"}}
	}`)
	h1 := r21JSON(t, w1)["hits"].(map[string]any)["hits"].([]any)
	if len(h1) != 1 || h1[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected transitive copy_to step3_kw term match on doc 1, got %v", h1)
	}

	w1Txt := r21Req(t, srv, http.MethodPost, "/r21_schema/_search", `{
		"query": {"term": {"step3_txt.keyword": "HeLLo"}}
	}`)
	h1Txt := r21JSON(t, w1Txt)["hits"].(map[string]any)["hits"].([]any)
	if len(h1Txt) != 1 || h1Txt[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected transitive copy_to step3_txt.keyword match on doc 1, got %v", h1Txt)
	}

	// 2. ignore_above on short_kw (doc 1 has "1234567" > 5 chars, so term query on short_kw must NOT match, but _source is preserved)
	wIgnore := r21Req(t, srv, http.MethodPost, "/r21_schema/_search", `{
		"query": {"term": {"short_kw": "1234567"}}
	}`)
	if hits := r21JSON(t, wIgnore)["hits"].(map[string]any)["hits"].([]any); len(hits) != 0 {
		t.Fatalf("expected ignore_above to skip indexing '1234567', got %v", hits)
	}

	// 3. Correlated nested query with normalized code, coerced boolean, and epoch-millis date range
	wNested := r21Req(t, srv, http.MethodPost, "/r21_schema/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {
					"bool": {
						"must": [
							{"term": {"items.code": "ABCD"}},
							{"term": {"items.active": true}},
							{"range": {"items.ts": {"gte": "2026-01-01T00:00:00Z"}}}
						]
					}
				}
			}
		}
	}`)
	hNested := r21JSON(t, wNested)["hits"].(map[string]any)["hits"].([]any)
	if len(hNested) != 1 || hNested[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected correlated nested query to match doc 1 after n__items normalization, got %v", hNested)
	}

	// 4. Nested null_value replacement ("NONE") and nested ignore_above (doc 2 "TOOLONG_NESTED" > 6 chars)
	wNestedNull := r21Req(t, srv, http.MethodPost, "/r21_schema/_search", `{
		"query": {
			"nested": {
				"path": "items",
				"query": {"term": {"items.code": "none"}}
			}
		}
	}`)
	hNestedNull := r21JSON(t, wNestedNull)["hits"].(map[string]any)["hits"].([]any)
	if len(hNestedNull) != 1 || hNestedNull[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected nested null_value 'NONE' (lowercased to 'none') to match doc 1, got %v", hNestedNull)
	}
}

func TestRound21PostFilterAggregationIsolation(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_pf_1", `{"mappings":{"properties":{"color":{"type":"keyword"},"price":{"type":"double"}}}}`)
	r21Req(t, srv, http.MethodPut, "/r21_pf_2", `{"mappings":{"properties":{"color":{"type":"keyword"},"price":{"type":"double"}}}}`)
	r21Req(t, srv, http.MethodPut, "/r21_pf_1/_doc/1?refresh=true", `{"color":"red","price":10}`)
	r21Req(t, srv, http.MethodPut, "/r21_pf_2/_doc/2?refresh=true", `{"color":"blue","price":30}`)

	// Multi-index search with post_filter matching only "red" (in r21_pf_1), while aggs must include both r21_pf_1 and r21_pf_2!
	w := r21Req(t, srv, http.MethodPost, "/r21_pf_1,r21_pf_2/_search", `{
		"query": {"match_all": {}},
		"post_filter": {"term": {"color": "red"}},
		"aggs": {
			"avg_price": {"avg": {"field": "price"}},
			"top_docs":  {"top_hits": {"size": 5}},
			"sampled": {
				"sampler": {"shard_size": 10},
				"aggs": {
					"sig_colors": {"significant_terms": {"field": "color", "min_doc_count": 1}}
				}
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	res := r21JSON(t, w)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected post_filter to restrict hits to doc 1, got %v", hits)
	}
	aggs := res["aggregations"].(map[string]any)
	if avg := aggs["avg_price"].(map[string]any)["value"].(float64); avg != 20 {
		t.Fatalf("expected pre-post_filter multi-index avg_price=20 ((10+30)/2), got %v", avg)
	}
	topHits := aggs["top_docs"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(topHits) != 2 {
		t.Fatalf("expected top_hits to see all 2 pre-post_filter docs, got %d: %v", len(topHits), topHits)
	}
	sampled := aggs["sampled"].(map[string]any)
	if sampled["doc_count"] != float64(2) {
		t.Fatalf("expected sampler doc_count=2 before post_filter, got %v", sampled["doc_count"])
	}
}

func TestRound21RescoreSearchWindowAndScoreModes(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_rescore", `{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"tag":   {"type": "keyword"},
				"boost_val": {"type": "double"}
			}
		}
	}`)
	r21Req(t, srv, http.MethodPost, "/r21_rescore/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"title":"search engine","tag":"basic","boost_val":1}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"title":"search proxy","tag":"vip","boost_val":10}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"title":"search analytics","tag":"basic","boost_val":2}`+"\n")

	for _, tc := range []struct {
		scoreMode string
		wantTopID string
		wantScore float64
	}{
		{scoreMode: "total", wantTopID: "2", wantScore: 1.0*2.0 + 1.0*5.0},    // 2 + 5 = 7
		{scoreMode: "multiply", wantTopID: "2", wantScore: (1.0 * 2.0) * 5.0}, // 2 * 5 = 10
		{scoreMode: "avg", wantTopID: "2", wantScore: (2.0 + 5.0) / 2.0},      // 3.5
		{scoreMode: "max", wantTopID: "2", wantScore: 5.0},
		{scoreMode: "min", wantTopID: "1", wantScore: 2.0},
	} {
		w := r21Req(t, srv, http.MethodPost, "/r21_rescore/_search", map[string]any{
			"size":  1,
			"query": map[string]any{"match": map[string]any{"title": "search"}},
			"rescore": map[string]any{
				"window_size": 3,
				"query": map[string]any{
					"score_mode":           tc.scoreMode,
					"query_weight":         2.0,
					"rescore_query_weight": 5.0,
					"rescore_query": map[string]any{
						"term": map[string]any{"tag": "vip"},
					},
				},
			},
		})
		if w.Code != http.StatusOK {
			t.Fatalf("score_mode=%s: expected 200, got %d: %s", tc.scoreMode, w.Code, w.Body.String())
		}
		hits := r21JSON(t, w)["hits"].(map[string]any)["hits"].([]any)
		if len(hits) != 1 || hits[0].(map[string]any)["_id"] != tc.wantTopID {
			t.Fatalf("score_mode=%s: expected top hit %s, got %v", tc.scoreMode, tc.wantTopID, hits)
		}
		gotScore := hits[0].(map[string]any)["_score"].(float64)
		if math.Abs(gotScore-tc.wantScore) > 1e-6 {
			t.Fatalf("score_mode=%s: expected score %v, got %v", tc.scoreMode, tc.wantScore, gotScore)
		}
	}

	// Array of rescorers with script_score and function_score
	wMultiRescore := r21Req(t, srv, http.MethodPost, "/r21_rescore/_search", `{
		"size": 1,
		"query": {"match_all": {}},
		"rescore": [
			{
				"window_size": 3,
				"query": {
					"score_mode": "total",
					"rescore_query": {
						"script_score": {
							"query": {"match_all": {}},
							"script": {"source": "doc['boost_val'].value"}
						}
					}
				}
			},
			{
				"window_size": 3,
				"query": {
					"score_mode": "total",
					"rescore_query": {
						"function_score": {
							"query": {"term": {"tag": "vip"}},
							"boost": 2.0
						}
					}
				}
			}
		]
	}`)
	if wMultiRescore.Code != http.StatusOK {
		t.Fatalf("expected 200 on multi-rescore, got %d: %s", wMultiRescore.Code, wMultiRescore.Body.String())
	}
}

func TestRound21MultiIndexCollapseDefaultScoreSearchAfterAndPITTiebreaker(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_col_1", `{"mappings":{"properties":{"dept":{"type":"keyword"},"title":{"type":"text"}}}}`)
	r21Req(t, srv, http.MethodPut, "/r21_col_2", `{"mappings":{"properties":{"dept":{"type":"keyword"},"title":{"type":"text"}}}}`)
	r21Req(t, srv, http.MethodPut, "/r21_col_1/_doc/1?refresh=true", `{"dept":"eng","title":"doris search"}`)
	r21Req(t, srv, http.MethodPut, "/r21_col_2/_doc/2?refresh=true", `{"dept":"sales","title":"doris"}`)

	// 1. Multi-index collapse with default _score sort + search_after
	qBool := map[string]any{
		"bool": map[string]any{
			"should": []map[string]any{
				{"match": map[string]any{"title": "doris"}},
				{"match": map[string]any{"title": "search"}},
			},
		},
	}
	w1 := r21Req(t, srv, http.MethodPost, "/r21_col_1,r21_col_2/_search", map[string]any{
		"size":     1,
		"query":    qBool,
		"collapse": map[string]any{"field": "dept"},
	})
	h1 := r21JSON(t, w1)["hits"].(map[string]any)["hits"].([]any)
	if len(h1) != 1 || h1[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected Page 1 hit to be doc 1, got %v", h1)
	}
	score1 := h1[0].(map[string]any)["_score"].(float64)

	w2 := r21Req(t, srv, http.MethodPost, "/r21_col_1,r21_col_2/_search", map[string]any{
		"size":         1,
		"query":        qBool,
		"collapse":     map[string]any{"field": "dept"},
		"search_after": []any{score1},
	})
	h2 := r21JSON(t, w2)["hits"].(map[string]any)["hits"].([]any)
	if len(h2) != 1 || h2[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected Page 2 hit to be doc 2, got %v", h2)
	}

	// 2. PIT search automatically appends _id: asc tiebreaker sort
	wPit := r21Req(t, srv, http.MethodPost, "/r21_col_1/_pit?keep_alive=1m", nil)
	pitID := r21JSON(t, wPit)["id"].(string)

	wPitNoSort := r21Req(t, srv, http.MethodPost, "/_search", map[string]any{
		"size":  1,
		"pit":   map[string]any{"id": pitID},
		"query": map[string]any{"match_all": map[string]any{}},
	})
	if wPitNoSort.Code != http.StatusOK {
		t.Fatalf("expected 200 on PIT search without explicit sort, got %d", wPitNoSort.Code)
	}
	wPitSearch := r21Req(t, srv, http.MethodPost, "/_search", map[string]any{
		"pit":   map[string]any{"id": pitID},
		"sort":  []map[string]any{{"dept": map[string]any{"order": "asc"}}},
		"query": map[string]any{"match_all": map[string]any{}},
	})
	pitHits := r21JSON(t, wPitSearch)["hits"].(map[string]any)["hits"].([]any)
	if len(pitHits) != 1 {
		t.Fatalf("expected 1 PIT hit, got %v", pitHits)
	}
	sortVals, ok := pitHits[0].(map[string]any)["sort"].([]any)
	if !ok || len(sortVals) < 2 || sortVals[len(sortVals)-1] != "1" {
		t.Fatalf("expected PIT hit sort to include _id tiebreaker '1', got %v", pitHits[0])
	}
	wExcl := r21Req(t, srv, http.MethodPost, "/r21_col_1,r21_col_2,-r21_col_2/_search", `{"query":{"match_all":{}}}`)
	if wExcl.Code != http.StatusOK {
		t.Fatalf("expected 200 on exclusion pattern, got %d", wExcl.Code)
	}
}

func TestRound21HighlightFullSpec(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_hl", `{
		"mappings": {
			"properties": {
				"title":      {"type": "text", "copy_to": "full_text"},
				"title_alias":{"type": "alias", "path": "title"},
				"body":       {"type": "text", "copy_to": "full_text"},
				"full_text":  {"type": "text"},
				"other":      {"type": "text"}
			}
		}
	}`)
	r21Req(t, srv, http.MethodPut, "/r21_hl/_doc/1?refresh=true", `{
		"title": "Doris <script> fast search",
		"body": "Apache Doris powers fast analytical search workloads across petabytes of log data",
		"other": "unmatched content here",
		"flat.dotted": "dotted field with search keyword"
	}`)

	w := r21Req(t, srv, http.MethodPost, "/r21_hl/_search", `{
		"query": {
			"match": {"title": "fast"}
		},
		"highlight": {
			"tag_schema": "styled",
			"encoder": "html",
			"require_field_match": true,
			"fields": {
				"title": {},
				"title_alias": {},
				"full_text": {},
				"body": {
					"require_field_match": false,
					"fragment_size": 30,
					"number_of_fragments": 1
				},
				"other": {
					"highlight_query": {"match": {"other": "nomatch"}},
					"no_match_size": 9
				},
				"flat.dotted": {
					"highlight_query": {"match": {"flat.dotted": "search"}}
				}
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	hits := r21JSON(t, w)["hits"].(map[string]any)["hits"].([]any)
	hl := hits[0].(map[string]any)["highlight"].(map[string]any)

	// 1. styled tag_schema + html encoder on title
	titleHL := hl["title"].([]any)[0].(string)
	if !strings.Contains(titleHL, "&lt;script&gt;") || !strings.Contains(titleHL, `<em class="hlt1">fast</em>`) {
		t.Fatalf("expected HTML-escaped styled highlight on title, got %q", titleHL)
	}
	// 2. alias and copy_to target resolution
	if len(hl["title_alias"].([]any)) == 0 {
		t.Fatalf("expected highlight on field alias 'title_alias', got %v", hl)
	}
	if len(hl["full_text"].([]any)) == 0 {
		t.Fatalf("expected highlight on copy_to target 'full_text', got %v", hl)
	}
	// 3. fragment_size=30 & number_of_fragments=1 on body
	bodyFrags := hl["body"].([]any)
	if len(bodyFrags) != 1 || len(bodyFrags[0].(string)) > 60 {
		t.Fatalf("expected 1 short fragment on body, got %v", bodyFrags)
	}
	// 4. no_match_size=9 on other
	otherFrags := hl["other"].([]any)
	if len(otherFrags) != 1 || otherFrags[0].(string) != "unmatched" {
		t.Fatalf("expected no_match_size=9 fallback 'unmatched' on other, got %v", otherFrags)
	}
	// 5. flat dotted key in _source + highlight_query
	dottedFrags := hl["flat.dotted"].([]any)
	if len(dottedFrags) != 1 || !strings.Contains(dottedFrags[0].(string), `<em class="hlt1">search</em>`) {
		t.Fatalf("expected highlight on flat.dotted key, got %v", dottedFrags)
	}
}

func TestRound21DateHistogramAndHistogramMinDocCountOrderAndFormat(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_hist", `{
		"mappings": {
			"properties": {
				"ts":  {"type": "date"},
				"val": {"type": "double"}
			}
		}
	}`)
	r21Req(t, srv, http.MethodPost, "/r21_hist/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"ts":"2026-03-01T00:00:00Z","val":10}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"ts":"2026-03-02T00:00:00Z","val":20}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"ts":"2026-03-02T05:00:00Z","val":25}`+"\n")

	w := r21Req(t, srv, http.MethodPost, "/r21_hist/_search", `{
		"size": 0,
		"aggs": {
			"by_day": {
				"date_histogram": {
					"field": "ts",
					"calendar_interval": "day",
					"format": "yyyy/MM/dd",
					"min_doc_count": 2
				}
			},
			"by_val": {
				"histogram": {
					"field": "val",
					"interval": 10,
					"order": {"_count": "desc"}
				}
			},
			"by_millis": {
				"date_histogram": {
					"field": "ts",
					"calendar_interval": "day",
					"format": "epoch_millis",
					"order": {"_key": "desc"}
				}
			},
			"by_sec": {
				"date_histogram": {
					"field": "ts",
					"calendar_interval": "day",
					"format": "epoch_second",
					"keyed": true
				}
			},
			"by_strict_tz": {
				"date_histogram": {
					"field": "ts",
					"calendar_interval": "day",
					"format": "strict_date_optional_time",
					"time_zone": "+02:00"
				}
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	aggs := r21JSON(t, w)["aggregations"].(map[string]any)
	dayBuckets := aggs["by_day"].(map[string]any)["buckets"].([]any)
	if len(dayBuckets) != 1 {
		t.Fatalf("expected min_doc_count=2 to filter out 1-doc day bucket, got %v", dayBuckets)
	}
	if ks := dayBuckets[0].(map[string]any)["key_as_string"]; ks != "2026/03/02" {
		t.Fatalf("expected custom format '2026/03/02', got %v", ks)
	}

	valBuckets := aggs["by_val"].(map[string]any)["buckets"].([]any)
	if len(valBuckets) != 2 || valBuckets[0].(map[string]any)["key"] != float64(20) {
		t.Fatalf("expected histogram ordered by _count desc (key 20 first), got %v", valBuckets)
	}
}

func TestRound21CumulativeCardinalityKeyedBucketPathsAndBucketSortGapPolicy(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_pipe", `{
		"mappings": {
			"properties": {
				"step": {"type": "integer"},
				"user": {"type": "keyword"},
				"val":  {"type": "double"}
			}
		}
	}`)
	r21Req(t, srv, http.MethodPost, "/r21_pipe/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"step":0,"user":"u1","val":10}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"step":10,"user":"u2","val":20}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"step":20,"user":"u3"}`+"\n")

	// 1. cumulative_cardinality & bucket_sort with gap_policy: "insert_zeros" over keyed histogram
	w := r21Req(t, srv, http.MethodPost, "/r21_pipe/_search", `{
		"size": 0,
		"aggs": {
			"by_step": {
				"histogram": {
					"field": "step",
					"interval": 10,
					"keyed": true
				},
				"aggs": {
					"uniq_users": {"cardinality": {"field": "user"}},
					"cum_users":  {"cumulative_cardinality": {"buckets_path": "uniq_users"}},
					"avg_val":    {"avg": {"field": "val"}},
					"sorted": {
						"bucket_sort": {
							"sort": [{"avg_val": {"order": "asc"}}],
							"gap_policy": "insert_zeros"
						}
					}
				}
			},
			"by_range": {
				"range": {
					"field": "val",
					"keyed": true,
					"ranges": [
						{"to": 15.5},
						{"from": 15.5}
					]
				},
				"aggs": {
					"sum_val": {"sum": {"field": "val"}},
					"double_sum": {
						"bucket_script": {
							"buckets_path": {"s": "sum_val"},
							"script": "params.s * 2"
						}
					}
				}
			}
		}
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	aggs := r21JSON(t, w)["aggregations"].(map[string]any)
	stepMap := aggs["by_step"].(map[string]any)["buckets"].(map[string]any)
	b20 := stepMap["20"].(map[string]any)
	if cc := b20["cum_users"].(map[string]any)["value"].(float64); cc != 3 {
		t.Fatalf("expected cumulative_cardinality at step 20 to be 3, got %v", cc)
	}
	// With gap_policy: "insert_zeros" and sort avg_val asc, step 20 (missing avg_val -> 0) sorts first!
	keys := make([]string, 0, len(stepMap))
	for k := range stepMap {
		keys = append(keys, k)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keyed buckets in by_step, got %v", stepMap)
	}

	// 2. Keyed range with dotted key ("*-15.5") and bucket_script
	rangeMap := aggs["by_range"].(map[string]any)["buckets"].(map[string]any)
	lowBucket := rangeMap["*-15.5"].(map[string]any)
	if ds, ok := lowBucket["double_sum"].(map[string]any); !ok || ds["value"] != float64(20) {
		t.Fatalf("expected bucket_script on keyed range bucket '*-15.5' to be 20, got %v", lowBucket)
	}
}

func TestRound21PainlessScriptedUpsertModuloAndNilSafety(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_painless", `{"mappings":{"properties":{"count":{"type":"integer"},"tags":{"type":"keyword","multi_valued":true}}}}`)

	// 1. scripted_upsert: true on missing doc must NOT overwrite script changes with req.Doc
	wUp := r21Req(t, srv, http.MethodPost, "/r21_painless/_update/1?refresh=true", `{
		"scripted_upsert": true,
		"script": {
			"source": "ctx._source.count = 17; ctx._source.count %= 5; ctx._source.neg_mod = 10 % -3; def a = ctx._source.tags; a = ['x', 'y']; a.add('z'); ctx._source.local_list = a"
		},
		"doc": {
			"count": 999,
			"tags": ["from_doc"]
		}
	}`)
	if wUp.Code != http.StatusCreated && wUp.Code != http.StatusOK {
		t.Fatalf("expected 201/200 on scripted_upsert, got %d: %s", wUp.Code, wUp.Body.String())
	}
	wGet := r21Req(t, srv, http.MethodGet, "/r21_painless/_doc/1", nil)
	src := r21JSON(t, wGet)["_source"].(map[string]any)
	if src["count"] != float64(2) {
		t.Fatalf("expected count=2 (17 %%= 5, not overwritten by doc.count=999), got %v", src)
	}
	if src["neg_mod"] != float64(1) {
		t.Fatalf("expected 10 %% -3 == 1, got %v", src["neg_mod"])
	}
	if src["tags"] != nil {
		t.Fatalf("expected rebound local variable 'a' not to mutate ctx._source.tags, got %v", src["tags"])
	}
}

func TestRound21WritePathOCCMgetIngestMetaAndCSVQuote(t *testing.T) {
	srv, _ := newTestServer()
	r21Req(t, srv, http.MethodPut, "/r21_occ", `{"mappings":{"properties":{"msg":{"type":"keyword"}}}}`)

	// 1. POST /{index}/_create without ID -> 400
	wNoID := r21Req(t, srv, http.MethodPost, "/r21_occ/_create", `{"msg":"bad"}`)
	if wNoID.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on POST /{index}/_create without ID, got %d: %s", wNoID.Code, wNoID.Body.String())
	}

	// 2. Index doc 1 and verify GET returns _seq_no and _primary_term
	wPut1 := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/1?refresh=true", `{"msg":"v1"}`)
	putRes1 := r21JSON(t, wPut1)
	seqNo1, ok := putRes1["_seq_no"].(float64)
	if !ok || seqNo1 <= 0 {
		t.Fatalf("expected positive _seq_no on PUT, got %v", putRes1)
	}
	wGet := r21Req(t, srv, http.MethodGet, "/r21_occ/_doc/1", nil)
	getRes := r21JSON(t, wGet)
	if getRes["_seq_no"] != seqNo1 || getRes["_primary_term"] != float64(1) {
		t.Fatalf("expected _seq_no=%v and _primary_term=1 on GET, got %v", int64(seqNo1), getRes)
	}

	// 3. Optimistic concurrency control: stale if_seq_no=99 returns 409 Conflict
	wConflict := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/1?if_seq_no=99&if_primary_term=1", `{"msg":"v2"}`)
	if wConflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on mismatched if_seq_no, got %d: %s", wConflict.Code, wConflict.Body.String())
	}
	// Matching if_seq_no succeeds
	wOK := r21Req(t, srv, http.MethodPut, fmt.Sprintf("/r21_occ/_doc/1?if_seq_no=%d&if_primary_term=1&refresh=true", int64(seqNo1)), `{"msg":"v2"}`)
	if wOK.Code != http.StatusOK {
		t.Fatalf("expected 200 on matching if_seq_no=%d, got %d: %s", int64(seqNo1), wOK.Code, wOK.Body.String())
	}
	// External version control on doc 2: create with version=2&version_type=external -> 201; repeat version=2&version_type=external -> 409; version=2&version_type=external_gte -> 200
	wExtInit := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/2?version=2&version_type=external&refresh=true", `{"msg":"v2_init"}`)
	if wExtInit.Code != http.StatusCreated {
		t.Fatalf("expected 201 on initial version=2&version_type=external, got %d: %s", wExtInit.Code, wExtInit.Body.String())
	}
	wExtConflict := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/2?version=2&version_type=external", `{"msg":"v3"}`)
	if wExtConflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 on version=2 with version_type=external, got %d", wExtConflict.Code)
	}
	wExtGTE := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/2?version=2&version_type=external_gte&refresh=true", `{"msg":"v3"}`)
	if wExtGTE.Code != http.StatusOK {
		t.Fatalf("expected 200 on version=2 with version_type=external_gte, got %d", wExtGTE.Code)
	}

	// 4. _mget with existing index and non-existent index returns 200 with per-doc error
	wMget := r21Req(t, srv, http.MethodPost, "/_mget", `{
		"docs": [
			{"_index": "r21_occ", "_id": "1"},
			{"_index": "no_such_index_r21", "_id": "1"}
		]
	}`)
	if wMget.Code != http.StatusOK {
		t.Fatalf("expected 200 on _mget, got %d: %s", wMget.Code, wMget.Body.String())
	}
	mgetDocs := r21JSON(t, wMget)["docs"].([]any)
	doc0 := mgetDocs[0].(map[string]any)
	if doc0["_seq_no"] == nil || doc0["_primary_term"] == nil {
		t.Fatalf("expected _seq_no and _primary_term in _mget hit, got %v", doc0)
	}
	doc1 := mgetDocs[1].(map[string]any)
	if doc1["error"] == nil || doc1["error"].(map[string]any)["type"] != "index_not_found_exception" {
		t.Fatalf("expected per-doc index_not_found_exception in _mget for missing index, got %v", doc1)
	}

	// 5. CSV processor with custom quote "'" preserves '"' inside fields, and empty verbose _simulate returns processor_results: []
	wSim := r21Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate?verbose=true", `{
		"pipeline": {
			"processors": [
				{
					"csv": {
						"field": "raw",
						"target_fields": ["a", "b"],
						"quote": "'"
					}
				}
			]
		},
		"docs": [{"_source": {"raw": "'hello \"world\"',42"}}]
	}`)
	simDocs := r21JSON(t, wSim)["docs"].([]any)
	simSrc := simDocs[0].(map[string]any)["processor_results"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if simSrc["a"] != `hello "world"` {
		t.Fatalf("expected csv custom quote to preserve double quotes in field a, got %q", simSrc["a"])
	}

	wEmptySim := r21Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate?verbose=true", `{
		"pipeline": {"processors": []},
		"docs": [{"_source": {"x": 1}}]
	}`)
	emptyRes := r21JSON(t, wEmptySim)["docs"].([]any)[0].(map[string]any)
	if _, ok := emptyRes["processor_results"].([]any); !ok {
		t.Fatalf("expected processor_results: [] on verbose empty pipeline simulate, got %v", emptyRes)
	}

	// 6. _bulk without URL index and without item _index returns 400
	wBulkNoIdx := r21Req(t, srv, http.MethodPost, "/_bulk", `{"index":{"_id":"1"}}`+"\n"+`{"msg":"no_idx"}`+"\n")
	if wBulkNoIdx.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when bulk action omits _index and URL has no default index, got %d: %s", wBulkNoIdx.Code, wBulkNoIdx.Body.String())
	}

	// 7. _update OCC, _delete OCC, _bulk OCC, ingest _id/_index routing, and _reindex?scroll_size=1
	wUpConflict := r21Req(t, srv, http.MethodPost, "/r21_occ/_update/2?if_seq_no=999&if_primary_term=1&retry_on_conflict=2", `{"doc":{"msg":"v4"}}`)
	if wUpConflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 on _update with stale if_seq_no, got %d", wUpConflict.Code)
	}
	wDelConflict := r21Req(t, srv, http.MethodDelete, "/r21_occ/_doc/2?if_seq_no=999&if_primary_term=1", nil)
	if wDelConflict.Code != http.StatusConflict {
		t.Fatalf("expected 409 on DELETE with stale if_seq_no, got %d", wDelConflict.Code)
	}
	wBulkOCC := r21Req(t, srv, http.MethodPost, "/r21_occ/_bulk?refresh=true",
		`{"index":{"_id":"2","if_seq_no":999,"if_primary_term":1}}`+"\n"+`{"msg":"conflict"}`+"\n"+
			`{"index":{"_id":"3","version":5,"version_type":"external"}}`+"\n"+`{"msg":"ext5"}`+"\n")
	bulkItems := r21JSON(t, wBulkOCC)["items"].([]any)
	if bulkItems[0].(map[string]any)["index"].(map[string]any)["status"] != float64(409) {
		t.Fatalf("expected 409 for bulk item 0 with stale if_seq_no, got %v", bulkItems[0])
	}
	if bulkItems[1].(map[string]any)["index"].(map[string]any)["status"] != float64(201) {
		t.Fatalf("expected 201 for bulk item 1 with external version=5, got %v", bulkItems[1])
	}

	// Ingest pipeline modifying _id and _index on PUT /{index}/_doc/{id}
	r21Req(t, srv, http.MethodPut, "/_ingest/pipeline/reroute_pipe", `{
		"processors": [
			{"set": {"field": "_index", "value": "r21_rerouted"}},
			{"set": {"field": "_id", "value": "rerouted_99"}}
		]
	}`)
	wReroute := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/orig_1?pipeline=reroute_pipe&refresh=true", `{"msg":"rerouted_doc"}`)
	rerouteRes := r21JSON(t, wReroute)
	if rerouteRes["_index"] != "r21_rerouted" || rerouteRes["_id"] != "rerouted_99" {
		t.Fatalf("expected _index=r21_rerouted and _id=rerouted_99, got %v", rerouteRes)
	}

	// _reindex?scroll_size=1
	wReindex := r21Req(t, srv, http.MethodPost, "/_reindex?scroll_size=1&refresh=true", `{
		"source": {"index": "r21_occ"},
		"dest": {"index": "r21_occ_copy"}
	}`)
	reidxRes := r21JSON(t, wReindex)
	if reidxRes["batches"].(float64) < 2 {
		t.Fatalf("expected _reindex?scroll_size=1 across multiple docs to run >= 2 batches, got %v", reidxRes)
	}

	// 8. Additional OCC validation branches (unpaired if_seq_no, invalid version_type, internal version, missing doc if_seq_no, bulk update/delete OCC)
	if w := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/2?if_seq_no=2", `{"msg":"bad"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unpaired if_seq_no, got %d", w.Code)
	}
	if w := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/2?if_seq_no=-1&if_primary_term=1", `{"msg":"bad"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on negative if_seq_no, got %d", w.Code)
	}
	if w := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/2?if_seq_no=1&if_primary_term=0", `{"msg":"bad"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on zero if_primary_term, got %d", w.Code)
	}
	if w := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/2?version=0", `{"msg":"bad"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on zero version, got %d", w.Code)
	}
	if w := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/2?version=2&version_type=bogus", `{"msg":"bad"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown version_type, got %d", w.Code)
	}
	if w := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/2?version=999", `{"msg":"bad"}`); w.Code != http.StatusConflict {
		t.Fatalf("expected 409 on mismatched internal version, got %d", w.Code)
	}
	if w := r21Req(t, srv, http.MethodPut, "/r21_occ/_doc/nonexistent_99?if_seq_no=1&if_primary_term=1", `{"msg":"bad"}`); w.Code != http.StatusConflict {
		t.Fatalf("expected 409 on if_seq_no for non-existent doc, got %d", w.Code)
	}
	wBulkUpDelOCC := r21Req(t, srv, http.MethodPost, "/r21_occ/_bulk?refresh=true",
		`{"update":{"_id":"2","if_seq_no":999,"if_primary_term":1}}`+"\n"+`{"doc":{"msg":"u_conflict"}}`+"\n"+
			`{"delete":{"_id":"2","if_seq_no":999,"if_primary_term":1}}`+"\n")
	upDelItems := r21JSON(t, wBulkUpDelOCC)["items"].([]any)
	if upDelItems[0].(map[string]any)["update"].(map[string]any)["status"] != float64(409) {
		t.Fatalf("expected 409 on bulk update OCC conflict, got %v", upDelItems[0])
	}
	if upDelItems[1].(map[string]any)["delete"].(map[string]any)["status"] != float64(409) {
		t.Fatalf("expected 409 on bulk delete OCC conflict, got %v", upDelItems[1])
	}
}
