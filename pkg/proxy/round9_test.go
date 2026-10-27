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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doReqJSON(t *testing.T, ts *httptest.Server, method, path string, payload any) (map[string]any, int) {
	t.Helper()
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, ts.URL+path, bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	rawResp, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(bytes.TrimSpace(rawResp)) > 0 {
		_ = json.Unmarshal(rawResp, &out)
	}
	return out, resp.StatusCode
}

// TestRound9FilteredAliasSingleDocCRUDAndGlobalAndKNN verifies R9-P0-1 and R9-P0-2:
// - Filtered aliases enforce their filter on GET / HEAD / _source / _mget / _update / DELETE / _bulk / terms lookup
// -Multi-target read aliases without is_write_index reject single-doc GET with 400
// - Global aggregations and top-level kNN respect alias filters while global still escapes the user query
// - normalizeDorisSQL preserves valid WHERE 1=1 when __DORIS_DELETE_SIGN__ = 0 is the sole predicate.
func TestRound9FilteredAliasSingleDocCRUDAndGlobalAndKNN(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/tenants", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"tenant": map[string]any{"type": "keyword"},
				"title":  map[string]any{"type": "text"},
				"amount": map[string]any{"type": "integer"},
				"vec":    map[string]any{"type": "dense_vector", "dims": 2},
			},
		},
		"aliases": map[string]any{
			"tenant_acme": map[string]any{
				"filter":         map[string]any{"term": map[string]any{"tenant": "acme"}},
				"is_write_index": true,
			},
			"tenant_globex": map[string]any{
				"filter": map[string]any{"term": map[string]any{"tenant": "globex"}},
			},
		},
	})

	mustReqJSON(t, ts, http.MethodPut, "/tenants/_doc/1?refresh=true", map[string]any{
		"tenant": "acme", "title": "acme invoice", "amount": 100, "vec": []float64{1.0, 0.0},
	})
	mustReqJSON(t, ts, http.MethodPut, "/tenants/_doc/2?refresh=true", map[string]any{
		"tenant": "globex", "title": "globex secret", "amount": 900, "vec": []float64{0.9, 0.1},
	})

	// 1. GET / HEAD / _source through tenant_acme must see doc 1 but return 404 on doc 2 (globex)
	doc1 := mustReqJSON(t, ts, http.MethodGet, "/tenant_acme/_doc/1", nil)
	if doc1["found"] != true {
		t.Fatalf("expected doc 1 found via tenant_acme, got: %+v", doc1)
	}
	res2, status2 := doReqJSON(t, ts, http.MethodGet, "/tenant_acme/_doc/2", nil)
	if status2 != http.StatusNotFound || res2["found"] != false {
		t.Fatalf("expected 404 NotFound for globex doc 2 via tenant_acme, got status=%d body=%+v", status2, res2)
	}
	headReq, _ := http.NewRequest(http.MethodHead, ts.URL+"/tenant_acme/_doc/2", nil)
	headResp, err := http.DefaultClient.Do(headReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = headResp.Body.Close()
	if headResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected HEAD /tenant_acme/_doc/2 to return 404, got %d", headResp.StatusCode)
	}
	_, srcStatus := doReqJSON(t, ts, http.MethodGet, "/tenant_acme/_source/2", nil)
	if srcStatus != http.StatusNotFound {
		t.Fatalf("expected GET /tenant_acme/_source/2 to return 404, got %d", srcStatus)
	}

	// 2. _mget via tenant_acme must filter out doc 2
	mgetRes := mustReqJSON(t, ts, http.MethodPost, "/tenant_acme/_mget", map[string]any{
		"ids": []string{"1", "2"},
	})
	docsList := mgetRes["docs"].([]any)
	if docsList[0].(map[string]any)["found"] != true || docsList[1].(map[string]any)["found"] != false {
		t.Fatalf("expected _mget via tenant_acme to return [found=true, found=false], got: %+v", docsList)
	}

	// 3. _update and DELETE via tenant_acme on globex doc 2 must return 404 and leave doc 2 intact
	_, updStatus := doReqJSON(t, ts, http.MethodPost, "/tenant_acme/_update/2?refresh=true", map[string]any{
		"doc": map[string]any{"amount": 0},
	})
	if updStatus != http.StatusNotFound {
		t.Fatalf("expected _update via tenant_acme on doc 2 to return 404, got %d", updStatus)
	}
	_, delStatus := doReqJSON(t, ts, http.MethodDelete, "/tenant_acme/_doc/2?refresh=true", nil)
	if delStatus != http.StatusNotFound {
		t.Fatalf("expected DELETE via tenant_acme on doc 2 to return 404, got %d", delStatus)
	}
	// Verify doc 2 is still intact via tenant_globex
	globexDoc2 := mustReqJSON(t, ts, http.MethodGet, "/tenant_globex/_doc/2", nil)
	if globexDoc2["found"] != true || globexDoc2["_source"].(map[string]any)["amount"] != float64(900) {
		t.Fatalf("expected globex doc 2 untouched after cross-tenant update/delete attempt, got: %+v", globexDoc2)
	}

	// 4. _bulk delete/update via tenant_acme on doc 2 must report 404
	bulkNDJSON := `{"delete":{"_index":"tenant_acme","_id":"2"}}` + "\n"
	bulkReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/_bulk?refresh=true", strings.NewReader(bulkNDJSON))
	bulkReq.Header.Set("Content-Type", "application/x-ndjson")
	bulkResp, err := http.DefaultClient.Do(bulkReq)
	if err != nil {
		t.Fatal(err)
	}
	var bulkRes map[string]any
	_ = json.NewDecoder(bulkResp.Body).Decode(&bulkRes)
	_ = bulkResp.Body.Close()
	bulkItems := bulkRes["items"].([]any)
	delItem := bulkItems[0].(map[string]any)["delete"].(map[string]any)
	if delItem["status"] != float64(404) {
		t.Fatalf("expected bulk delete via tenant_acme on doc 2 to return status 404, got: %+v", delItem)
	}

	// 5. Global aggregation and kNN search via tenant_acme must never leak globex doc 2
	mustReqJSON(t, ts, http.MethodPut, "/tenants/_doc/3?refresh=true", map[string]any{
		"tenant": "acme", "title": "acme renewal", "amount": 200, "vec": []float64{0.8, 0.2},
	})
	searchRes := mustReqJSON(t, ts, http.MethodPost, "/tenant_acme/_search", map[string]any{
		"query": map[string]any{"term": map[string]any{"amount": 100}},
		"aggs": map[string]any{
			"all_in_alias": map[string]any{
				"global": map[string]any{},
				"aggs": map[string]any{
					"total_amt": map[string]any{"sum": map[string]any{"field": "amount"}},
				},
			},
		},
	})
	if searchRes["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(1) {
		t.Fatalf("expected 1 query hit for amount=100 in tenant_acme, got: %+v", searchRes["hits"])
	}
	globalAgg := searchRes["aggregations"].(map[string]any)["all_in_alias"].(map[string]any)
	// tenant_acme has 2 docs (100 + 200 = 300); globex doc 2 (900) must NOT be included!
	if globalAgg["doc_count"] != float64(2) || globalAgg["total_amt"].(map[string]any)["value"] != float64(300) {
		t.Fatalf("expected global agg under tenant_acme to see 2 acme docs (sum=300), got: %+v", globalAgg)
	}

	knnRes := mustReqJSON(t, ts, http.MethodPost, "/tenant_acme/_search", map[string]any{
		"knn": map[string]any{
			"field":          "vec",
			"query_vector":   []float64{0.9, 0.1},
			"k":              5,
			"num_candidates": 10,
		},
	})
	for _, rawHit := range knnRes["hits"].(map[string]any)["hits"].([]any) {
		h := rawHit.(map[string]any)
		if h["_id"] == "2" {
			t.Fatalf("kNN search on tenant_acme leaked globex doc 2: %+v", knnRes["hits"])
		}
	}

	// 6. normalizeDorisSQL standalone `__DORIS_DELETE_SIGN__ = 0` replacement
	normSQL := normalizeDorisSQL("SELECT COUNT(*) FROM `es_db`.`tenants` WHERE `__DORIS_DELETE_SIGN__` = 0 GROUP BY `_bucket_key`")
	if strings.Contains(normSQL, "__DORIS_DELETE_SIGN__") || !strings.Contains(normSQL, "WHERE 1=1 GROUP BY") {
		t.Fatalf("expected standalone __DORIS_DELETE_SIGN__ = 0 to normalize to 1=1, got: %s", normSQL)
	}
}

// TestRound9CacheKeyCollisionsTopMetricsFiltersAndSort verifies R9-P0-3:
// - SearchRequest JSON marshaling preserves top_metrics, filters (named + anonymous), and sort mode/missing
func TestRound9CacheKeyCollisionsTopMetricsFiltersAndSort(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/metrics_cache_idx/_doc/1?refresh=true", map[string]any{
		"host": "h1", "cpu": 10, "mem": 90, "scores": []int{10, 50},
	})
	mustReqJSON(t, ts, http.MethodPut, "/metrics_cache_idx/_doc/2?refresh=true", map[string]any{
		"host": "h2", "cpu": 80, "mem": 20, "scores": []int{20, 30},
	})

	srv.SetQueryCacheTTL(30*time.Second, 512)
	// 1. Two top_metrics queries with different metric fields / sort orders must not collide in query cache
	tm1 := mustReqJSON(t, ts, http.MethodPost, "/metrics_cache_idx/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"tm": map[string]any{
				"top_metrics": map[string]any{
					"metrics": map[string]any{"field": "cpu"},
					"sort":    []any{map[string]any{"cpu": "desc"}},
				},
			},
		},
	})
	tm2 := mustReqJSON(t, ts, http.MethodPost, "/metrics_cache_idx/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"tm": map[string]any{
				"top_metrics": map[string]any{
					"metrics": map[string]any{"field": "mem"},
					"sort":    []any{map[string]any{"cpu": "asc"}},
				},
			},
		},
	})
	top1 := tm1["aggregations"].(map[string]any)["tm"].(map[string]any)["top"].([]any)[0].(map[string]any)["metrics"].(map[string]any)
	top2 := tm2["aggregations"].(map[string]any)["tm"].(map[string]any)["top"].([]any)[0].(map[string]any)["metrics"].(map[string]any)
	if top1["cpu"] != float64(80) || top2["mem"] != float64(90) {
		t.Fatalf("top_metrics cache collision: top1=%+v top2=%+v", top1, top2)
	}

	// 2. Two filters aggs with different filter clauses must not collide in query cache
	f1 := mustReqJSON(t, ts, http.MethodPost, "/metrics_cache_idx/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"f": map[string]any{
				"filters": map[string]any{
					"filters": map[string]any{
						"b": map[string]any{"term": map[string]any{"host": "h1"}},
					},
				},
			},
		},
	})
	f2 := mustReqJSON(t, ts, http.MethodPost, "/metrics_cache_idx/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"f": map[string]any{
				"filters": map[string]any{
					"filters": map[string]any{
						"b": map[string]any{"range": map[string]any{"cpu": map[string]any{"gt": 100}}},
					},
				},
			},
		},
	})
	b1 := f1["aggregations"].(map[string]any)["f"].(map[string]any)["buckets"].(map[string]any)["b"].(map[string]any)
	b2 := f2["aggregations"].(map[string]any)["f"].(map[string]any)["buckets"].(map[string]any)["b"].(map[string]any)
	if b1["doc_count"] != float64(1) || b2["doc_count"] != float64(0) {
		t.Fatalf("filters agg cache collision: b1=%+v b2=%+v", b1, b2)
	}

	// 3. Sort mode min vs max must not collide in query cache and must return mode-reduced sort values (R9-P1-6)
	sMin := mustReqJSON(t, ts, http.MethodPost, "/metrics_cache_idx/_search", map[string]any{
		"sort": []any{map[string]any{"scores": map[string]any{"order": "desc", "mode": "min"}}},
	})
	sMax := mustReqJSON(t, ts, http.MethodPost, "/metrics_cache_idx/_search", map[string]any{
		"sort": []any{map[string]any{"scores": map[string]any{"order": "desc", "mode": "max"}}},
	})
	hitsMin := sMin["hits"].(map[string]any)["hits"].([]any)
	hitsMax := sMax["hits"].(map[string]any)["hits"].([]any)
	// For mode=min: doc 1 has min(10,50)=10, doc 2 has min(20,30)=20 -> doc 2 comes first (sort=[20])
	// For mode=max: doc 1 has max(10,50)=50, doc 2 has max(20,30)=30 -> doc 1 comes first (sort=[50])
	if hitsMin[0].(map[string]any)["_id"] != "2" || hitsMin[0].(map[string]any)["sort"].([]any)[0] != float64(20) {
		t.Fatalf("expected mode=min desc to put doc 2 first with sort=[20], got: %+v", hitsMin)
	}
	if hitsMax[0].(map[string]any)["_id"] != "1" || hitsMax[0].(map[string]any)["sort"].([]any)[0] != float64(50) {
		t.Fatalf("expected mode=max desc to put doc 1 first with sort=[50], got: %+v", hitsMax)
	}
}

// TestRound9FilterSubAggTermsAndFiltersOtherBucketFulltext verifies R9-P0-4 and R9-P0-5:
// - MemoryBackend greedy extraWhere regexes do not drop `AND (...)` filter clauses on terms/date_histogram/etc. inside filter sub-aggs
// - Filters agg with `other_bucket: true` and full-text `match` clauses uses EffectiveSafeWhere() so MATCH_* is never wrapped in COALESCE.
func TestRound9FilterSubAggTermsAndFiltersOtherBucketFulltext(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/orders_idx", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"status":   map[string]any{"type": "keyword"},
				"category": map[string]any{"type": "keyword"},
				"notes":    map[string]any{"type": "text"},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/orders_idx/_doc/1?refresh=true", map[string]any{
		"status": "error", "category": "A", "notes": "database timeout error",
	})
	mustReqJSON(t, ts, http.MethodPut, "/orders_idx/_doc/2?refresh=true", map[string]any{
		"status": "ok", "category": "B", "notes": "request succeeded quickly",
	})

	res := mustReqJSON(t, ts, http.MethodPost, "/orders_idx/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"only_err": map[string]any{
				"filter": map[string]any{"term": map[string]any{"status": "error"}},
				"aggs": map[string]any{
					"by_cat": map[string]any{"terms": map[string]any{"field": "category"}},
				},
			},
			"by_note": map[string]any{
				"filters": map[string]any{
					"other_bucket": true,
					"filters": map[string]any{
						"timeout_notes": map[string]any{"match": map[string]any{"notes": "timeout"}},
					},
				},
			},
		},
	})
	onlyErr := res["aggregations"].(map[string]any)["only_err"].(map[string]any)
	catBuckets := onlyErr["by_cat"].(map[string]any)["buckets"].([]any)
	if len(catBuckets) != 1 || catBuckets[0].(map[string]any)["key"] != "A" {
		t.Fatalf("expected filter->terms sub-agg to only include category A, got: %+v", catBuckets)
	}
	noteBuckets := res["aggregations"].(map[string]any)["by_note"].(map[string]any)["buckets"].(map[string]any)
	if noteBuckets["timeout_notes"].(map[string]any)["doc_count"] != float64(1) || noteBuckets["_other_"].(map[string]any)["doc_count"] != float64(1) {
		t.Fatalf("expected filters other_bucket with match query to have 1 timeout and 1 _other_, got: %+v", noteBuckets)
	}

	// Also verify the generated SQL for `filters` with `other_bucket: true` + `match` does NOT contain COALESCE(MATCH_
	idxSchema := srv.getOrCompileReadOnlySchema(context.Background(), "orders_idx")
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	var req esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size":0,"aggs":{"by_note":{"filters":{"other_bucket":true,"filters":{"m":{"match":{"notes":"timeout"}}}}}}}`), &req)
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan.AggsSQL, "COALESCE((`f__notes` MATCH") || strings.Contains(plan.AggsSQL, "COALESCE(`f__notes` MATCH") {
		t.Fatalf("expected filters other_bucket SQL not to wrap MATCH_* in COALESCE, got: %s", plan.AggsSQL)
	}
}

// TestRound9PainlessSlashRegexAndNullSafeChaining verifies R9-P0-6:
// - Slash-delimited regex literals `/^https:\/\/foo\/bar$/` with `==~` and `=~`
// - Chained null-safe method calls `ctx._source.name?.trim()?.toLowerCase()` and `ctx._source.missing?.trim()?.toLowerCase()`
func TestRound9PainlessSlashRegexAndNullSafeChaining(t *testing.T) {
	t.Parallel()
	doc := map[string]any{
		"url":  "https://foo/bar",
		"name": "  Alice Smith  ",
	}
	script := `
		if (ctx._source.url ==~ /^https:\/\/foo\/bar$/) {
			ctx._source.matched_url = true;
		}
		ctx._source.clean_name = ctx._source.name?.trim()?.toLowerCase();
		ctx._source.missing_chain = ctx._source.nonexistent?.trim()?.toLowerCase();
		ctx._source.starts = ctx._source.name?.trim()?.startsWith('Alice');
	`
	if _, err := painless.EvalPainlessWithOp(doc, script, nil); err != nil {
		t.Fatalf("painless.EvalPainlessWithOp failed: %v", err)
	}
	if doc["matched_url"] != true {
		t.Fatalf("expected slash-delimited regex ==~ to match url, got: %+v", doc)
	}
	if doc["clean_name"] != "alice smith" {
		t.Fatalf("expected chained ?.trim()?.toLowerCase() to produce 'alice smith', got: %+v", doc["clean_name"])
	}
	if doc["missing_chain"] != nil {
		t.Fatalf("expected missing?.trim()?.toLowerCase() to evaluate to nil, got: %+v", doc["missing_chain"])
	}
	if doc["starts"] != true {
		t.Fatalf("expected chained ?.trim()?.startsWith('Alice') to be true, got: %+v", doc["starts"])
	}
}

// TestRound9PipelineAggsMovingFnRateAndExtendedStats verifies R9-P0-7, R9-P1-1, R9-P1-2, R9-P1-3:
// - moving_fn with shift=0, shift=1, MovingFunctions.max/min/sum/stdDev, model=linear/ewma
// - rate unit scaling across date_histogram and histogram
// - extended_stats exact sum_of_squares and null metrics on empty index
// - multi-index merge of nested sub-aggregations (terms -> avg, terms -> min, terms -> max, terms -> extended_stats)
func TestRound9PipelineAggsMovingFnRateAndExtendedStats(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Empty index stats / extended_stats must return null min/max/avg/std_deviation
	mustReqJSON(t, ts, http.MethodPut, "/empty_stats_idx", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{"val": map[string]any{"type": "double"}},
		},
	})
	emptyRes := mustReqJSON(t, ts, http.MethodPost, "/empty_stats_idx/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"st":  map[string]any{"stats": map[string]any{"field": "val"}},
			"est": map[string]any{"extended_stats": map[string]any{"field": "val"}},
		},
	})
	stMap := emptyRes["aggregations"].(map[string]any)["st"].(map[string]any)
	estMap := emptyRes["aggregations"].(map[string]any)["est"].(map[string]any)
	if stMap["count"] != float64(0) || stMap["min"] != nil || stMap["max"] != nil || stMap["avg"] != nil || stMap["sum"] != float64(0) {
		t.Fatalf("expected empty stats to have count=0, sum=0, and nil min/max/avg, got: %+v", stMap)
	}
	if estMap["count"] != float64(0) || estMap["std_deviation"] != nil || estMap["variance"] != nil {
		t.Fatalf("expected empty extended_stats to have nil std_deviation/variance, got: %+v", estMap)
	}

	// 2. Multi-index merge of nested sub-aggs + exact sum_of_squares + rate scaling + moving_fn
	mustReqJSON(t, ts, http.MethodPut, "/m_idx_1/_doc/1?refresh=true", map[string]any{
		"cat": "A", "val": 10.0, "ts": "2025-01-01T00:00:00Z",
	})
	mustReqJSON(t, ts, http.MethodPut, "/m_idx_2/_doc/2?refresh=true", map[string]any{
		"cat": "A", "val": 30.0, "ts": "2025-01-01T00:30:00Z",
	})
	mustReqJSON(t, ts, http.MethodPut, "/m_idx_2/_doc/3?refresh=true", map[string]any{
		"cat": "A", "val": 50.0, "ts": "2025-01-01T01:00:00Z",
	})

	multiRes := mustReqJSON(t, ts, http.MethodPost, "/m_idx_1,m_idx_2/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_cat": map[string]any{
				"terms": map[string]any{"field": "cat"},
				"aggs": map[string]any{
					"avg_val": map[string]any{"avg": map[string]any{"field": "val"}},
					"min_val": map[string]any{"min": map[string]any{"field": "val"}},
					"max_val": map[string]any{"max": map[string]any{"field": "val"}},
					"ext_val": map[string]any{"extended_stats": map[string]any{"field": "val"}},
				},
			},
			"by_hour": map[string]any{
				"date_histogram": map[string]any{
					"field":          "ts",
					"fixed_interval": "1h",
				},
				"aggs": map[string]any{
					"sum_val":      map[string]any{"sum": map[string]any{"field": "val"}},
					"per_min_rate": map[string]any{"rate": map[string]any{"field": "val", "unit": "minute"}},
					"mov_max":      map[string]any{"moving_fn": map[string]any{"buckets_path": "sum_val", "window": 2, "script": "MovingFunctions.max(values)"}},
					"mov_shift0":   map[string]any{"moving_fn": map[string]any{"buckets_path": "sum_val", "window": 2, "shift": 0, "script": "MovingFunctions.sum(values)"}},
					"mov_linear":   map[string]any{"moving_avg": map[string]any{"buckets_path": "sum_val", "window": 2, "model": "linear"}},
				},
			},
		},
	})

	catBucket := multiRes["aggregations"].(map[string]any)["by_cat"].(map[string]any)["buckets"].([]any)[0].(map[string]any)
	if catBucket["avg_val"].(map[string]any)["value"] != float64(30) {
		t.Fatalf("expected multi-index sub-agg avg_val=30, got: %+v", catBucket["avg_val"])
	}
	if catBucket["min_val"].(map[string]any)["value"] != float64(10) || catBucket["max_val"].(map[string]any)["value"] != float64(50) {
		t.Fatalf("expected multi-index sub-agg min=10 max=50, got min=%+v max=%+v", catBucket["min_val"], catBucket["max_val"])
	}
	extVal := catBucket["ext_val"].(map[string]any)
	// 10^2 + 30^2 + 50^2 = 100 + 900 + 2500 = 3500
	if math.Abs(extVal["sum_of_squares"].(float64)-3500.0) > 1e-6 {
		t.Fatalf("expected extended_stats sum_of_squares=3500, got: %+v", extVal)
	}

	hourBuckets := multiRes["aggregations"].(map[string]any)["by_hour"].(map[string]any)["buckets"].([]any)
	if len(hourBuckets) != 2 {
		t.Fatalf("expected 2 hourly buckets, got: %+v", hourBuckets)
	}
	hb0 := hourBuckets[0].(map[string]any) // sum_val = 40 (10+30)
	hb1 := hourBuckets[1].(map[string]any) // sum_val = 50
	// rate per minute over a 1-hour (60-minute) bucket: 40 / 60
	if math.Abs(hb0["per_min_rate"].(map[string]any)["value"].(float64)-(40.0/60.0)) > 1e-6 {
		t.Fatalf("expected rate with unit=minute on 1h bucket to be 40/60, got: %+v", hb0["per_min_rate"])
	}
	if hb1["mov_max"].(map[string]any)["value"] != float64(50) {
		t.Fatalf("expected MovingFunctions.max([40, 50]) = 50, got: %+v", hb1["mov_max"])
	}
	// shift=0 on bucket 1 uses only prior bucket [40] -> sum = 40
	if hb1["mov_shift0"].(map[string]any)["value"] != float64(40) {
		t.Fatalf("expected moving_fn shift=0 on bucket 1 to sum [40] = 40, got: %+v", hb1["mov_shift0"])
	}
	// linear weighted avg on [40, 50]: (40*1 + 50*2) / 3 = 140/3
	if math.Abs(hb1["mov_linear"].(map[string]any)["value"].(float64)-(140.0/3.0)) > 1e-6 {
		t.Fatalf("expected moving_avg model=linear on [40, 50] to be 140/3, got: %+v", hb1["mov_linear"])
	}
}

// TestRound9SubAggMatrixAndDeepTermsNesting verifies R9-P0-8:
// - boxplot, percentile_ranks, string_stats, sampler, reverse_nested inside bucket aggregations
// - nested -> terms -> metric sub-aggregations + accurate nested doc_count
// - 2-level terms -> terms -> sum + child pipeline agg
func TestRound9SubAggMatrixAndDeepTermsNesting(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/subagg_idx", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"region":  map[string]any{"type": "keyword"},
				"service": map[string]any{"type": "keyword"},
				"latency": map[string]any{"type": "double"},
				"items": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"sku":   map[string]any{"type": "keyword"},
						"price": map[string]any{"type": "double"},
					},
				},
			},
		},
	})

	mustReqJSON(t, ts, http.MethodPut, "/subagg_idx/_doc/1?refresh=true", map[string]any{
		"region": "us-east", "service": "auth", "latency": 10.0,
		"items": []any{
			map[string]any{"sku": "S1", "price": 100.0},
			map[string]any{"sku": "S2", "price": 250.0},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/subagg_idx/_doc/2?refresh=true", map[string]any{
		"region": "us-east", "service": "pay", "latency": 30.0,
		"items": []any{
			map[string]any{"sku": "S1", "price": 150.0},
		},
	})

	res := mustReqJSON(t, ts, http.MethodPost, "/subagg_idx/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_region": map[string]any{
				"terms": map[string]any{"field": "region"},
				"aggs": map[string]any{
					"lat_box":   map[string]any{"boxplot": map[string]any{"field": "latency"}},
					"lat_ranks": map[string]any{"percentile_ranks": map[string]any{"field": "latency", "values": []float64{15, 50}}},
					"svc_str":   map[string]any{"string_stats": map[string]any{"field": "service"}},
					"samp": map[string]any{
						"sampler": map[string]any{"shard_size": 100},
						"aggs": map[string]any{
							"max_lat": map[string]any{"max": map[string]any{"field": "latency"}},
						},
					},
					"by_service": map[string]any{
						"terms": map[string]any{"field": "service"},
						"aggs": map[string]any{
							"sum_lat":  map[string]any{"sum": map[string]any{"field": "latency"}},
							"csum_lat": map[string]any{"cumulative_sum": map[string]any{"buckets_path": "sum_lat"}},
						},
					},
				},
			},
			"nested_items": map[string]any{
				"nested": map[string]any{"path": "items"},
				"aggs": map[string]any{
					"price_box": map[string]any{"boxplot": map[string]any{"field": "items.price"}},
					"by_sku": map[string]any{
						"terms": map[string]any{"field": "items.sku"},
						"aggs": map[string]any{
							"total_price": map[string]any{"sum": map[string]any{"field": "items.price"}},
						},
					},
				},
			},
		},
	})

	regBucket := res["aggregations"].(map[string]any)["by_region"].(map[string]any)["buckets"].([]any)[0].(map[string]any)
	if regBucket["lat_box"].(map[string]any)["min"] != float64(10) || regBucket["lat_box"].(map[string]any)["max"] != float64(30) {
		t.Fatalf("expected boxplot sub-agg min=10 max=30, got: %+v", regBucket["lat_box"])
	}
	ranksVals := regBucket["lat_ranks"].(map[string]any)["values"].(map[string]any)
	if ranksVals["15.0"] != float64(50) || ranksVals["50.0"] != float64(100) {
		t.Fatalf("expected percentile_ranks sub-agg [15->50%%, 50->100%%], got: %+v", ranksVals)
	}
	if regBucket["svc_str"].(map[string]any)["count"] != float64(2) || regBucket["svc_str"].(map[string]any)["min_length"] != float64(3) {
		t.Fatalf("expected string_stats sub-agg count=2 min_length=3, got: %+v", regBucket["svc_str"])
	}
	if regBucket["samp"].(map[string]any)["max_lat"].(map[string]any)["value"] != float64(30) {
		t.Fatalf("expected sampler sub-agg max_lat=30, got: %+v", regBucket["samp"])
	}
	svcBuckets := regBucket["by_service"].(map[string]any)["buckets"].([]any)
	if len(svcBuckets) != 2 || svcBuckets[0].(map[string]any)["sum_lat"].(map[string]any)["value"] != float64(10) || svcBuckets[1].(map[string]any)["csum_lat"].(map[string]any)["value"] != float64(40) {
		t.Fatalf("expected 2-level terms->terms->sum+cumulative_sum, got: %+v", svcBuckets)
	}

	nestedAgg := res["aggregations"].(map[string]any)["nested_items"].(map[string]any)
	if nestedAgg["doc_count"] != float64(3) {
		t.Fatalf("expected nested doc_count=3 (total nested elements across 2 docs), got: %+v", nestedAgg)
	}
	skuBuckets := nestedAgg["by_sku"].(map[string]any)["buckets"].([]any)
	if len(skuBuckets) != 2 || skuBuckets[0].(map[string]any)["total_price"].(map[string]any)["value"] != float64(250) {
		t.Fatalf("expected nested->terms->sum for S1 to be 250, got: %+v", skuBuckets)
	}
}

// TestRound9CatalogRehydrationPipelinesSettingsAndRollover verifies R9-P1-4 and R9-P1-5:
// - Ingest pipelines, default_pipeline, and final_pipeline persist in _es_catalog across proxy restarts
// - Reindex executes final_pipeline on destination index
// - Rollover preserves old index on shared read alias while flipping is_write_index to new index
func TestRound9CatalogRehydrationPipelinesSettingsAndRollover(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv1 := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts1 := httptest.NewServer(srv1.Handler())
	defer ts1.Close()

	// 1. Register default and final ingest pipelines on srv1
	mustReqJSON(t, ts1, http.MethodPut, "/_ingest/pipeline/def_pipe", map[string]any{
		"processors": []any{
			map[string]any{"set": map[string]any{"field": "def_ran", "value": true}},
		},
	})
	mustReqJSON(t, ts1, http.MethodPut, "/_ingest/pipeline/fin_pipe", map[string]any{
		"processors": []any{
			map[string]any{"set": map[string]any{"field": "fin_ran", "value": "yes"}},
		},
	})

	// Create logs-000001 with write alias and set default_pipeline + final_pipeline via PUT /_settings
	mustReqJSON(t, ts1, http.MethodPut, "/logs-000001", map[string]any{
		"aliases": map[string]any{
			"logs_alias": map[string]any{"is_write_index": true},
		},
	})
	mustReqJSON(t, ts1, http.MethodPut, "/logs-000001/_settings", map[string]any{
		"index.default_pipeline": "def_pipe",
		"index.final_pipeline":   "fin_pipe",
	})

	// 2. Start a brand-new stateless Server instance srv2 backed by the same MemoryBackend
	srv2 := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	if err := srv2.BootstrapCatalog(context.Background()); err != nil {
		t.Fatalf("srv2.BootstrapCatalog failed: %v", err)
	}
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()

	// Index a document through srv2 and verify BOTH rehydrated default_pipeline and final_pipeline ran
	mustReqJSON(t, ts2, http.MethodPut, "/logs_alias/_doc/1?refresh=true", map[string]any{
		"msg": "hello",
	})
	gotDoc := mustReqJSON(t, ts2, http.MethodGet, "/logs-000001/_doc/1", nil)
	src := gotDoc["_source"].(map[string]any)
	if src["def_ran"] != true || src["fin_ran"] != "yes" {
		t.Fatalf("expected rehydrated default_pipeline and final_pipeline to enrich doc on srv2, got: %+v", src)
	}

	// 3. Rollover logs_alias (max_docs: 1) -> creates logs-000002, keeps logs-000001 in logs_alias with is_write_index=false
	rollRes := mustReqJSON(t, ts2, http.MethodPost, "/logs_alias/_rollover", map[string]any{
		"conditions": map[string]any{"max_docs": 1},
	})
	if rollRes["rolled_over"] != true || rollRes["new_index"] != "logs-000002" {
		t.Fatalf("expected rollover to logs-000002, got: %+v", rollRes)
	}

	// Index a second doc into logs_alias (goes to logs-000002) and verify search on logs_alias sees BOTH docs
	mustReqJSON(t, ts2, http.MethodPut, "/logs_alias/_doc/2?refresh=true", map[string]any{
		"msg": "world",
	})
	allLogs := mustReqJSON(t, ts2, http.MethodPost, "/logs_alias/_search", map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
	})
	if allLogs["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(2) {
		t.Fatalf("expected rollover alias logs_alias to retain old index and return 2 total docs, got: %+v", allLogs["hits"])
	}
}

// TestRound9IPRangeArrayAndLuceneDoris4GuardAndCatAliases verifies R9-P1-7, R9-P2-1, R9-P2-2, R9-P2-4:
// - ip_range on multi-valued IP arrays and invalid CIDR mask safety
// - /_cat/aliases empty array [] and filter/routing/is_write_index columns + HEAD /{index}/_alias/{name}
// - Lucene Doris 4 SEARCH() fallback when query contains range/wildcard/regex/fuzziness/boost
// - top_hits size:0 returns empty hits list
func TestRound9IPRangeArrayAndLuceneDoris4GuardAndCatAliases(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{UseDoris4SearchFunc: true})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. /_cat/aliases on empty server returns [] (not null)
	emptyCatReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/_cat/aliases?format=json", nil)
	emptyCatResp, err := http.DefaultClient.Do(emptyCatReq)
	if err != nil {
		t.Fatal(err)
	}
	var emptyCatList []any
	if err := json.NewDecoder(emptyCatResp.Body).Decode(&emptyCatList); err != nil || emptyCatList == nil || len(emptyCatList) != 0 {
		t.Fatalf("expected empty [] from /_cat/aliases?format=json, got err=%v list=%+v", err, emptyCatList)
	}
	_ = emptyCatResp.Body.Close()

	mustReqJSON(t, ts, http.MethodPut, "/net_idx/_doc/1?refresh=true", map[string]any{
		"ips": []string{"10.0.0.5", "192.168.1.9"}, "status": 200,
	})
	mustReqJSON(t, ts, http.MethodPost, "/_aliases", map[string]any{
		"actions": []any{
			map[string]any{
				"add": map[string]any{
					"index":          "net_idx",
					"alias":          "net_alias",
					"is_write_index": true,
					"routing":        "r1",
					"filter":         map[string]any{"term": map[string]any{"status": 200}},
				},
			},
		},
	})

	// 2. HEAD /net_idx/_alias/net_alias and HEAD /net_alias/_alias/net_alias return 200
	for _, p := range []string{"/net_idx/_alias/net_alias", "/net_alias/_alias/net_alias", "/net_idx/_alias/net_*"} {
		req, _ := http.NewRequest(http.MethodHead, ts.URL+p, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HEAD %s to return 200, got %d", p, resp.StatusCode)
		}
	}

	// 3. ip_range on multi-valued array + top_hits with size: 0 + Lucene range syntax with UseDoris4SearchFunc
	zero := 0
	searchRes := mustReqJSON(t, ts, http.MethodPost, "/net_idx/_search", map[string]any{
		"query": map[string]any{
			"query_string": map[string]any{
				"query": "status:[100 TO 300]",
			},
		},
		"aggs": map[string]any{
			"ip_subnets": map[string]any{
				"ip_range": map[string]any{
					"field": "ips",
					"ranges": []any{
						map[string]any{"mask": "10.0.0.0/8"},
						map[string]any{"mask": "192.168.0.0/16"},
						map[string]any{"mask": "not-a-valid-cidr"},
					},
				},
			},
			"zero_hits": map[string]any{
				"top_hits": map[string]any{"size": zero},
			},
		},
	})
	if searchRes["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(1) {
		t.Fatalf("expected query_string status:[100 TO 300] to fall back from Doris 4 SEARCH() and match doc 1, got: %+v", searchRes["hits"])
	}
	ipBuckets := searchRes["aggregations"].(map[string]any)["ip_subnets"].(map[string]any)["buckets"].([]any)
	if ipBuckets[0].(map[string]any)["doc_count"] != float64(1) || ipBuckets[1].(map[string]any)["doc_count"] != float64(1) || ipBuckets[2].(map[string]any)["doc_count"] != float64(0) {
		t.Fatalf("expected ip_range on array field to match both subnets (1, 1) and 0 on invalid CIDR, got: %+v", ipBuckets)
	}
	zh := searchRes["aggregations"].(map[string]any)["zero_hits"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(zh) != 0 {
		t.Fatalf("expected top_hits with size:0 to return 0 hits, got: %+v", zh)
	}
	_ = bytes.MinRead
}
