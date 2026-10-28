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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func mustRequestR7(t *testing.T, ts *httptest.Server, method, path, body string) map[string]any {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(path, "_bulk") {
		req.Header.Set("Content-Type", "application/x-ndjson")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s returned HTTP %d: %s", method, path, resp.StatusCode, string(raw))
	}
	var out map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func TestRound7_TermsSetScriptASTSecurityAndSelfCorruption(t *testing.T) {
	rawMapping := []byte(`{
		"properties": {
			"tags": {"type": "keyword"},
			"num_terms": {"type": "keyword"},
			"required_matches": {"type": "integer"},
			"vec": {"type": "dense_vector", "dims": 3}
		}
	}`)
	var spec esast.MappingSpec
	if err := json.Unmarshal(rawMapping, &spec); err != nil {
		t.Fatal(err)
	}
	idxSchema := schema.CompileIndexSchema("es_compat", "r7_idx", &spec)
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})

	// 1. Verify doc['num_terms'].size() does not get corrupted by params.num_terms replacement
	var qSelf esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"terms_set": {
				"tags": {
					"terms": ["a", "b", "c"],
					"minimum_should_match_script": {
						"source": "Math.min(params.num_terms, doc['num_terms'].size())"
					}
				}
			}
		}
	}`), &qSelf)
	planSelf, err := tr.BuildSearchPlan(&qSelf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(planSelf.HitsSQL, "f__'3'") || !strings.Contains(planSelf.HitsSQL, "LEAST(3, COALESCE(`f__num_terms`, 1))") {
		t.Fatalf("expected clean AST compilation for doc['num_terms'].size(), got:\n%s", planSelf.HitsSQL)
	}

	// 2. Verify malicious SQL injection attempts in minimum_should_match_script are rejected and fall back to num_terms (3)
	maliciousScripts := []string{
		"1) OR (SELECT 1)=1 --",
		"1 + 2)",
		"(1 + 2",
		"doc['tags']); DROP TABLE r7_idx; --'].size()",
		"System.exit(1)",
		"params.other_var",
	}
	for _, bad := range maliciousScripts {
		payload, _ := json.Marshal(map[string]any{
			"query": map[string]any{
				"terms_set": map[string]any{
					"tags": map[string]any{
						"terms":                       []string{"a", "b", "c"},
						"minimum_should_match_script": map[string]any{"source": bad},
					},
				},
			},
		})
		var req esast.SearchRequest
		_ = json.Unmarshal(payload, &req)
		plan, err := tr.BuildSearchPlan(&req)
		if err != nil {
			t.Fatalf("unexpected error for script %q: %v", bad, err)
		}
		if strings.Contains(plan.HitsSQL, "DROP TABLE") || strings.Contains(plan.HitsSQL, "SELECT 1") || !strings.Contains(plan.HitsSQL, ">= 1)") {
			t.Fatalf("expected malicious script %q to safely fall back to 1, got:\n%s", bad, plan.HitsSQL)
		}
	}

	// 3. Verify terms_set on _id system column and dense_vector field
	var reqSys esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"terms_set": {"_id": {"terms": ["doc-1", "doc-2"], "minimum_should_match_script": {"source": "1"}}}},
					{"terms_set": {"vec": {"terms": ["1.0"]}}}
				]
			}
		}
	}`), &reqSys)
	planSys, err := tr.BuildSearchPlan(&reqSys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(planSys.HitsSQL, "`_id` = 'doc-1'") || !strings.Contains(planSys.HitsSQL, "(FALSE)") {
		t.Fatalf("expected _id equality and FALSE for dense_vector terms_set, got:\n%s", planSys.HitsSQL)
	}
}

func TestRound7_CoalescerConcurrentStressAndCrossTableIsolation(t *testing.T) {
	slowTblStarted := make(chan struct{})
	unblockSlowTbl := make(chan struct{})
	var slowOnce sync.Once
	var totalFlushes int64

	coalescer := newStreamLoadCoalescer(func(_ context.Context, table string, _ []byte, _ bool) error {
		atomic.AddInt64(&totalFlushes, 1)
		if table == "slow_table" {
			slowOnce.Do(func() {
				close(slowTblStarted)
				<-unblockSlowTbl
			})
		}
		return nil
	})
	coalescer.Configure(50*time.Millisecond, 1024)

	// Start an in-flight byte-threshold flush on "slow_table"
	go func() {
		bigPayload := bytes.Repeat([]byte(`{"_id":"1"}`+"\n"), 120)
		_ = coalescer.Submit(context.Background(), "slow_table", bigPayload, false)
	}()
	<-slowTblStarted

	// FlushTable on "fast_table" must NOT block on "slow_table"'s in-flight flush
	fastDone := make(chan error, 1)
	go func() {
		_ = coalescer.Submit(context.Background(), "fast_table", []byte(`{"_id":"fast-1"}`+"\n"), true)
		fastDone <- coalescer.FlushTable(context.Background(), "fast_table")
	}()
	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatalf("expected fast_table flush to succeed, got: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("FlushTable(fast_table) was blocked by in-flight flush on slow_table")
	}
	close(unblockSlowTbl)

	// Concurrent stress test across 24 goroutines doing Submit + FlushTable + FlushAll
	var wg sync.WaitGroup
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tbl := fmt.Sprintf("stress_tbl_%d", id%3)
			for iter := 0; iter < 15; iter++ {
				_ = coalescer.Submit(context.Background(), tbl, []byte(fmt.Sprintf(`{"_id":"%d-%d"}`+"\n", id, iter)), iter%5 == 0)
				if iter%3 == 0 {
					_ = coalescer.FlushTable(context.Background(), tbl)
				}
				if iter%7 == 0 {
					_ = coalescer.FlushAll(context.Background())
				}
			}
		}(g)
	}
	wg.Wait()
	if err := coalescer.Close(context.Background()); err != nil {
		t.Fatalf("coalescer.Close failed: %v", err)
	}
}

func TestRound7_PipelineAggValidationOverflowAndScientificNotation(t *testing.T) {
	backend := NewMemoryBackend(false)
	srv := NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Seed index
	mustRequestR7(t, ts, http.MethodPut, "/r7_metrics", `{
		"mappings": {
			"properties": {
				"svc": {"type": "keyword"},
				"val": {"type": "double"}
			}
		}
	}`)
	mustRequestR7(t, ts, http.MethodPost, "/_bulk?refresh=true", strings.Join([]string{
		`{"index":{"_index":"r7_metrics","_id":"1"}}`,
		`{"svc":"api","val":100.0}`,
		`{"index":{"_index":"r7_metrics","_id":"2"}}`,
		`{"svc":"web","val":200.0}`,
		"",
	}, "\n"))

	// 1. Invalid multi-hop sibling buckets_path ("by_svc>nonexistent" -> HTTP 400)
	badHop := `{"size":0,"aggs":{"by_svc":{"terms":{"field":"svc"},"aggs":{"s":{"sum":{"field":"val"}}}},"bad_avg":{"avg_bucket":{"buckets_path":"by_svc>nonexistent"}}}}`
	resp1, _ := http.Post(ts.URL+"/r7_metrics/_search", "application/json", strings.NewReader(badHop))
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for invalid multi-hop buckets_path, got %d", resp1.StatusCode)
	}

	// 2. Invalid child cumulative_sum buckets_path (-> HTTP 400)
	badChild := `{"size":0,"aggs":{"by_svc":{"terms":{"field":"svc"},"aggs":{"cs":{"cumulative_sum":{"buckets_path":"missing_metric"}}}}}}`
	resp2, _ := http.Post(ts.URL+"/r7_metrics/_search", "application/json", strings.NewReader(badChild))
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for invalid child cumulative_sum buckets_path, got %d", resp2.StatusCode)
	}

	// 3. Cyclic child bucket_script dependency (a -> b -> a -> HTTP 400)
	cyclic := `{
		"size": 0,
		"aggs": {
			"by_svc": {
				"terms": {"field": "svc"},
				"aggs": {
					"a": {"bucket_script": {"buckets_path": {"x": "b"}, "script": "params.x + 1"}},
					"b": {"bucket_script": {"buckets_path": {"y": "a"}, "script": "params.y + 1"}}
				}
			}
		}
	}`
	resp3, _ := http.Post(ts.URL+"/r7_metrics/_search", "application/json", strings.NewReader(cyclic))
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 for cyclic child pipeline aggs, got %d", resp3.StatusCode)
	}

	// 4. Scientific notation ("params.s * 1e-2 + -0.5") + overflow protection ("params.s * 1e308 * 1e308")
	sciAndOverflow := `{
		"size": 0,
		"aggs": {
			"by_svc": {
				"terms": {"field": "svc"},
				"aggs": {
					"s": {"sum": {"field": "val"}},
					"sci": {"bucket_script": {"buckets_path": {"s": "s"}, "script": "params.s * 1e-2 + -0.5"}},
					"inf_script": {"bucket_script": {"buckets_path": {"s": "s"}, "script": "params.s * 1e308 * 1e308"}}
				}
			}
		}
	}`
	res4 := mustRequestR7(t, ts, http.MethodPost, "/r7_metrics/_search", sciAndOverflow)
	bySvcBuckets := res4["aggregations"].(map[string]any)["by_svc"].(map[string]any)["buckets"].([]any)
	if len(bySvcBuckets) != 2 {
		t.Fatalf("expected 2 buckets, got %+v", bySvcBuckets)
	}
	firstB := bySvcBuckets[0].(map[string]any)
	if firstB["sci"] == nil {
		t.Fatalf("expected sci bucket_script result, got %+v", firstB)
	}
	if _, hasInf := firstB["inf_script"]; hasInf {
		t.Fatalf("expected overflowing inf_script to be omitted, got %+v", firstB["inf_script"])
	}

	// 5. Painless scientific notation and overflow protection
	updatedJSON, err := painless.ApplyUpdate(json.RawMessage(`{"v":100.0}`), &painless.UpdateRequest{
		Script: &painless.ScriptSpec{
			Source: "ctx._source.scaled = 1e-2 * 50 + -0.1; ctx._source.overflow = 1e308 * 10;",
		},
	})
	if err != nil {
		t.Fatalf("painless.ApplyUpdate failed: %v", err)
	}
	var updatedDoc map[string]any
	_ = json.Unmarshal(updatedJSON, &updatedDoc)
	if updatedDoc["scaled"] != 0.4 {
		t.Fatalf("expected 0.4 from scientific notation, got %v", updatedDoc["scaled"])
	}
	if updatedDoc["overflow"] != float64(0) {
		t.Fatalf("expected overflow to clamp to 0, got %v", updatedDoc["overflow"])
	}
}

func TestRound7_TopHitsScoreSortDoris4SearchGuardAndLuceneEdgeCases(t *testing.T) {
	rawMapping := []byte(`{
		"properties": {
			"title": {"type": "text"},
			"service_a": {"type": "keyword"},
			"service_b": {"type": "keyword"}
		}
	}`)
	var spec esast.MappingSpec
	_ = json.Unmarshal(rawMapping, &spec)
	idxSchema := schema.CompileIndexSchema("es_compat", "r7_lucene", &spec)

	// 1. Doris 4.0 SEARCH() only used for promoted columns without _exists_ or range brackets
	trDoris4 := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{UseDoris4SearchFunc: true})
	// Promoted field -> uses SEARCH()
	planPromoted, err := trDoris4.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{QueryString: &esast.QueryStringQuery{Query: "title:orders"}},
	})
	if err != nil || !strings.Contains(planPromoted.HitsSQL, "SEARCH('f__title:orders'") {
		t.Fatalf("expected SEARCH() for promoted field, got: %v / %s", err, planPromoted.HitsSQL)
	}
	// Dynamic VARIANT field -> falls back to Lucene compiler
	planDynamic, err := trDoris4.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{QueryString: &esast.QueryStringQuery{Query: "unmapped_field:orders"}},
	})
	if err != nil || strings.Contains(planDynamic.HitsSQL, "SEARCH(") || !strings.Contains(planDynamic.HitsSQL, "`_doc`['unmapped_field']") {
		t.Fatalf("expected Lucene fallback for dynamic VARIANT field, got: %v / %s", err, planDynamic.HitsSQL)
	}

	// 2. top_hits with sort: ["_score"] must not reference _score on base_matched
	var topHitsReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"aggs":{"sample":{"top_hits":{"size":1,"sort":[{"_score":{"order":"desc"}}]}}}}`), &topHitsReq)
	planTopHits, err := trDoris4.BuildSearchPlan(&topHitsReq)
	if err != nil || strings.Contains(planTopHits.AggsSQL, "ORDER BY `_score`") {
		t.Fatalf("expected top_hits sort by _score to avoid referencing _score on base_matched, got:\n%s", planTopHits.AggsSQL)
	}

	// 3. Lucene (service_a:alpha)OR(service_b:beta), trailing colon, escaped caret, and wildcard field name
	trStd := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	planParens, err := trStd.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{QueryString: &esast.QueryStringQuery{Query: "(service_a:alpha)OR(service_b:beta)"}},
	})
	if err != nil || !strings.Contains(planParens.HitsSQL, "`f__service_a` MATCH_ANY 'alpha'") || !strings.Contains(planParens.HitsSQL, "`f__service_b` MATCH_ANY 'beta'") {
		t.Fatalf("expected (service_a:alpha)OR(service_b:beta) to parse both field clauses, got:\n%s", planParens.HitsSQL)
	}

	planWildField, err := trStd.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{QueryString: &esast.QueryStringQuery{Query: "service_*:alpha"}},
	})
	if err != nil || !strings.Contains(planWildField.HitsSQL, "`f__service_a`") || !strings.Contains(planWildField.HitsSQL, "`f__service_b`") {
		t.Fatalf("expected service_*:alpha to expand across service_a and service_b, got:\n%s", planWildField.HitsSQL)
	}
}

func TestRound7_RangeDateMathCompositeNumericTermsAndWildcardFieldExpand(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	if _, ok := schema.ParseESDateBoundToEpochMillis("nowhere", now, false); ok {
		t.Fatalf("expected 'nowhere' not to parse as ES date-math 'now'")
	}
	if _, ok := schema.ParseESDateBoundToEpochMillis("nowadays", now, true); ok {
		t.Fatalf("expected 'nowadays' not to parse as ES date-math 'now'")
	}

	backend := NewMemoryBackend(false)
	srv := NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	srv.SetQueryCacheTTL(10*time.Second, 64)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustRequestR7(t, ts, http.MethodPut, "/r7_events", `{
		"mappings": {
			"properties": {
				"code": {"type": "long"},
				"svc_a": {"type": "keyword"},
				"svc_b": {"type": "keyword"},
				"ts": {"type": "date"},
				"score_val": {"type": "double"}
			}
		}
	}`)
	mustRequestR7(t, ts, http.MethodPost, "/_bulk?refresh=true", strings.Join([]string{
		`{"index":{"_index":"r7_events","_id":"e1"}}`,
		`{"code":200,"svc_a":"alpha-prod","svc_b":"beta","ts":1700000000500,"score_val":10.0,"user":{"name":"alice"},"other":{"secret":"hide"},"big_uint":18446744073709551615}`,
		`{"index":{"_index":"r7_events","_id":"e2"}}`,
		`{"code":500,"svc_a":"gamma","svc_b":"alpha-stage","ts":1700000001000,"score_val":20.0,"user":{"name":"bob"},"other":{"secret":"hide"}}`,
		"",
	}, "\n"))

	// 1. Composite pagination with numeric `terms` source (`code` is `long`) + `after` cursor
	comp1 := mustRequestR7(t, ts, http.MethodPost, "/r7_events/_search", `{
		"size": 0,
		"aggs": {
			"comp_codes": {
				"composite": {
					"size": 1,
					"sources": [{"code_src": {"terms": {"field": "code"}}}]
				}
			}
		}
	}`)
	compAgg := comp1["aggregations"].(map[string]any)["comp_codes"].(map[string]any)
	afterKey := compAgg["after_key"].(map[string]any)
	if afterKey["code_src"] != float64(200) && afterKey["code_src"] != int64(200) && afterKey["code_src"] != "200" {
		t.Fatalf("expected first composite key 200, got %+v", afterKey)
	}
	comp2 := mustRequestR7(t, ts, http.MethodPost, "/r7_events/_search", `{
		"size": 0,
		"aggs": {
			"comp_codes": {
				"composite": {
					"size": 1,
					"after": {"code_src": 200},
					"sources": [{"code_src": {"terms": {"field": "code"}}}]
				}
			}
		}
	}`)
	compBuckets2 := comp2["aggregations"].(map[string]any)["comp_codes"].(map[string]any)["buckets"].([]any)
	if len(compBuckets2) != 1 || fmt.Sprintf("%v", compBuckets2[0].(map[string]any)["key"].(map[string]any)["code_src"]) != "500" {
		t.Fatalf("expected second page composite key 500, got %+v", compBuckets2)
	}

	// 2. Wildcard query with wildcard field pattern ("svc_*") + fractional epoch_second range bound
	wRes := mustRequestR7(t, ts, http.MethodPost, "/r7_events/_search", `{
		"query": {
			"bool": {
				"must": [
					{"wildcard": {"svc_*": {"value": "alpha*"}}},
					{"range": {"ts": {"gte": 1700000000.5, "lte": 1700000000.5, "format": "epoch_second"}}}
				]
			}
		},
		"_source": {"includes": ["user*", "big_uint"]}
	}`)
	wHits := wRes["hits"].(map[string]any)["hits"].([]any)
	if len(wHits) != 1 || wHits[0].(map[string]any)["_id"] != "e1" {
		t.Fatalf("expected 1 hit (e1) for wildcard field + fractional epoch_second, got %+v", wHits)
	}
	srcMap := wHits[0].(map[string]any)["_source"].(map[string]any)
	if _, hasOther := srcMap["other"]; hasOther || srcMap["user"] == nil {
		t.Fatalf("expected _source includes ['user*'] to include user and exclude other, got %+v", srcMap)
	}

	// 3. Significant_terms sub-aggregation + filters with child bucket_script + handleCount after cache hit
	sigAndFilters := mustRequestR7(t, ts, http.MethodPost, "/r7_events/_search", `{
		"size": 0,
		"aggs": {
			"by_code": {
				"terms": {"field": "code"},
				"aggs": {
					"sig_svc": {"significant_terms": {"field": "svc_a"}}
				}
			},
			"by_f": {
				"filters": {
					"filters": {
						"ok": {"term": {"code": 200}},
						"err": {"term": {"code": 500}}
					}
				},
				"aggs": {
					"s": {"sum": {"field": "score_val"}},
					"doubled": {"bucket_script": {"buckets_path": {"s": "s"}, "script": "params.s * 2"}}
				}
			}
		}
	}`)
	codeBuckets := sigAndFilters["aggregations"].(map[string]any)["by_code"].(map[string]any)["buckets"].([]any)
	sigSub := codeBuckets[0].(map[string]any)["sig_svc"].(map[string]any)
	if sigSub["bg_count"] == nil {
		t.Fatalf("expected significant_terms sub-agg envelope with bg_count, got %+v", sigSub)
	}
	fBuckets := sigAndFilters["aggregations"].(map[string]any)["by_f"].(map[string]any)["buckets"].(map[string]any)
	okBucket := fBuckets["ok"].(map[string]any)
	if okBucket["doubled"] == nil || okBucket["doubled"].(map[string]any)["value"] != float64(20) {
		t.Fatalf("expected filters child bucket_script doubled=20, got %+v", okBucket)
	}

	// Prime cache for count query and verify /_count returns 2 on both miss and hit
	cnt1 := mustRequestR7(t, ts, http.MethodPost, "/r7_events/_count", `{"query":{"match_all":{}}}`)
	cnt2 := mustRequestR7(t, ts, http.MethodPost, "/r7_events/_count", `{"query":{"match_all":{}}}`)
	if cnt1["count"] != float64(2) || cnt2["count"] != float64(2) {
		t.Fatalf("expected /_count=2 on both cache miss and cache hit, got %v and %v", cnt1["count"], cnt2["count"])
	}
}
