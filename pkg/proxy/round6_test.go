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

package proxy_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound6_CompositeHistogramAndAfterPagination(t *testing.T) {
	backend := proxy.NewMemoryBackend(false)
	srv := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	bulk := strings.Join([]string{
		`{"index":{"_index":"r6_comp","_id":"1"}}`,
		`{"service":"api","latency":12.5,"ts":1700000010000}`,
		`{"index":{"_index":"r6_comp","_id":"2"}}`,
		`{"service":"api","latency":35.0,"ts":1700000050000}`,
		`{"index":{"_index":"r6_comp","_id":"3"}}`,
		`{"service":"web","latency":15.0,"ts":1700000090000}`,
		"",
	}, "\n")
	resp, err := http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(bulk))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk failed: %v", err)
	}
	_ = resp.Body.Close()

	// Page 1 of composite agg with terms + histogram (with offset)
	page1Req := `{
		"size": 0,
		"aggs": {
			"my_comp": {
				"composite": {
					"size": 2,
					"sources": [
						{"svc": {"terms": {"field": "service.keyword"}}},
						{"lat": {"histogram": {"field": "latency", "interval": 20, "offset": 5}}}
					]
				}
			}
		}
	}`
	r1, err := http.Post(ts.URL+"/r6_comp/_search", "application/json", strings.NewReader(page1Req))
	if err != nil || r1.StatusCode != http.StatusOK {
		t.Fatalf("composite page 1 failed: %v", err)
	}
	var res1 map[string]any
	_ = json.NewDecoder(r1.Body).Decode(&res1)
	_ = r1.Body.Close()

	comp1 := res1["aggregations"].(map[string]any)["my_comp"].(map[string]any)
	buckets1 := comp1["buckets"].([]any)
	if len(buckets1) != 2 {
		t.Fatalf("expected 2 buckets in page 1, got %d: %+v", len(buckets1), comp1)
	}
	afterKey := comp1["after_key"].(map[string]any)
	afterJSON, _ := json.Marshal(afterKey)

	// Page 2 using after_key (including float64 histogram key)
	page2Req := `{
		"size": 0,
		"aggs": {
			"my_comp": {
				"composite": {
					"size": 2,
					"after": ` + string(afterJSON) + `,
					"sources": [
						{"svc": {"terms": {"field": "service.keyword"}}},
						{"lat": {"histogram": {"field": "latency", "interval": 20, "offset": 5}}}
					]
				}
			}
		}
	}`
	r2, err := http.Post(ts.URL+"/r6_comp/_search", "application/json", strings.NewReader(page2Req))
	if err != nil || r2.StatusCode != http.StatusOK {
		t.Fatalf("composite page 2 failed: %v", err)
	}
	var res2 map[string]any
	_ = json.NewDecoder(r2.Body).Decode(&res2)
	_ = r2.Body.Close()
	comp2 := res2["aggregations"].(map[string]any)["my_comp"].(map[string]any)
	buckets2 := comp2["buckets"].([]any)
	if len(buckets2) != 1 {
		t.Fatalf("expected 1 remaining bucket in page 2, got %d: %+v", len(buckets2), comp2)
	}
}

func TestRound6_TermsSetSingleTermScriptAndDynamicArray(t *testing.T) {
	backend := proxy.NewMemoryBackend(false)
	srv := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create index with dynamic mapping so `roles` is stored in `_doc['roles']` as dynamic array/scalar
	bulk := strings.Join([]string{
		`{"index":{"_index":"r6_tset","_id":"1"}}`,
		`{"roles":["admin","editor"],"min_req":1}`,
		`{"index":{"_index":"r6_tset","_id":"2"}}`,
		`{"roles":"viewer","min_req":1}`,
		"",
	}, "\n")
	resp, err := http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(bulk))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk failed: %v", err)
	}
	_ = resp.Body.Close()

	// Single-term terms_set + minimum_should_match_script using params.num_terms, Math.min, and doc['min_req'].value
	q := `{
		"query": {
			"terms_set": {
				"roles": {
					"terms": ["admin"],
					"minimum_should_match_script": {
						"source": "Math.min(params.num_terms, doc['min_req'].value)"
					}
				}
			}
		}
	}`
	sr, err := http.Post(ts.URL+"/r6_tset/_search", "application/json", strings.NewReader(q))
	if err != nil || sr.StatusCode != http.StatusOK {
		t.Fatalf("terms_set search failed: %v", err)
	}
	var res map[string]any
	_ = json.NewDecoder(sr.Body).Decode(&res)
	_ = sr.Body.Close()
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected doc 1 from single-term terms_set with script, got: %+v", hits)
	}
}

func TestRound6_MatchPhrasePrefixMultiTokenOrderAndSignificantTerms(t *testing.T) {
	backend := proxy.NewMemoryBackend(false)
	srv := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	bulk := strings.Join([]string{
		`{"index":{"_index":"r6_mpp","_id":"1"}}`,
		`{"title":"quick brown fox","category":"animals"}`,
		`{"index":{"_index":"r6_mpp","_id":"2"}}`,
		`{"title":"not quick bro","category":"other"}`,
		`{"index":{"_index":"r6_mpp","_id":"3"}}`,
		`{"title":"quick brown falcon","category":"animals"}`,
		"",
	}, "\n")
	resp, err := http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(bulk))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk failed: %v", err)
	}
	_ = resp.Body.Close()

	// "quick bro" should match doc 1 and doc 3, and should NOT match doc 2 if we query "brown f"
	q := `{
		"query": {
			"match_phrase_prefix": {
				"title": "brown f"
			}
		},
		"aggs": {
			"sig_cats": {
				"significant_terms": {
					"field": "category.keyword"
				}
			}
		}
	}`
	sr, err := http.Post(ts.URL+"/r6_mpp/_search", "application/json", strings.NewReader(q))
	if err != nil || sr.StatusCode != http.StatusOK {
		t.Fatalf("match_phrase_prefix search failed: %v", err)
	}
	var res map[string]any
	_ = json.NewDecoder(sr.Body).Decode(&res)
	_ = sr.Body.Close()
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits for match_phrase_prefix 'brown f', got %d: %+v", len(hits), hits)
	}
	sigCats := res["aggregations"].(map[string]any)["sig_cats"].(map[string]any)
	if sigCats["bg_count"] == nil {
		t.Fatalf("expected bg_count on significant_terms response, got: %+v", sigCats)
	}
	sigBuckets := sigCats["buckets"].([]any)
	if len(sigBuckets) == 0 || sigBuckets[0].(map[string]any)["score"] == nil {
		t.Fatalf("expected scored significant_terms buckets, got: %+v", sigBuckets)
	}
}

func TestRound6_PipelineAggsChainingBucketScriptAndValidation(t *testing.T) {
	backend := proxy.NewMemoryBackend(false)
	srv := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	bulk := strings.Join([]string{
		`{"index":{"_index":"r6_pipe","_id":"1"}}`,
		`{"bucket":10,"val":10}`,
		`{"index":{"_index":"r6_pipe","_id":"2"}}`,
		`{"bucket":20,"val":30}`,
		`{"index":{"_index":"r6_pipe","_id":"3"}}`,
		`{"bucket":30,"val":60}`,
		"",
	}, "\n")
	resp, err := http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(bulk))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk failed: %v", err)
	}
	_ = resp.Body.Close()

	// Chained pipeline aggs: cumulative_sum -> derivative (2nd order) + bucket_script
	q := `{
		"size": 0,
		"aggs": {
			"by_b": {
				"histogram": {"field": "bucket", "interval": 10},
				"aggs": {
					"sum_v": {"sum": {"field": "val"}},
					"cum_v": {"cumulative_sum": {"buckets_path": "sum_v"}},
					"deriv_cum": {"derivative": {"buckets_path": "cum_v"}},
					"pct": {
						"bucket_script": {
							"buckets_path": {"s": "sum_v", "c": "cum_v"},
							"script": "(params.s / params.c) * 100"
						}
					}
				}
			}
		}
	}`
	sr, err := http.Post(ts.URL+"/r6_pipe/_search", "application/json", strings.NewReader(q))
	if err != nil || sr.StatusCode != http.StatusOK {
		t.Fatalf("chained pipeline agg search failed: %v", err)
	}
	var res map[string]any
	_ = json.NewDecoder(sr.Body).Decode(&res)
	_ = sr.Body.Close()

	buckets := res["aggregations"].(map[string]any)["by_b"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(buckets))
	}
	b2 := buckets[2].(map[string]any)
	if b2["cum_v"].(map[string]any)["value"] != float64(100) {
		t.Fatalf("expected cum_v=100 on bucket 3, got %+v", b2["cum_v"])
	}
	if b2["deriv_cum"].(map[string]any)["value"] != float64(60) {
		t.Fatalf("expected deriv_cum=60 on bucket 3, got %+v", b2["deriv_cum"])
	}
	if b2["pct"].(map[string]any)["value"] != float64(60) {
		t.Fatalf("expected pct=60 on bucket 3, got %+v", b2["pct"])
	}

	// Invalid buckets_path should return 400 Bad Request
	badQ := `{
		"size": 0,
		"aggs": {
			"bad_sibling": {
				"avg_bucket": {"buckets_path": "nonexistent_agg>metric"}
			}
		}
	}`
	badResp, err := http.Post(ts.URL+"/r6_pipe/_search", "application/json", strings.NewReader(badQ))
	if err != nil {
		t.Fatalf("bad pipeline request failed: %v", err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for invalid buckets_path, got %d", badResp.StatusCode)
	}
}

func TestRound6_GzipNoContentFilterPathAndSourceWildcards(t *testing.T) {
	backend := proxy.NewMemoryBackend(false)
	srv := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. OPTIONS with Accept-Encoding: gzip must return 204 No Content with 0 body bytes and no Content-Encoding: gzip
	optReq, _ := http.NewRequest(http.MethodOptions, ts.URL+"/_search", nil)
	optReq.Header.Set("Accept-Encoding", "gzip")
	optResp, err := http.DefaultClient.Do(optReq)
	if err != nil {
		t.Fatalf("OPTIONS failed: %v", err)
	}
	optBody, _ := io.ReadAll(optResp.Body)
	_ = optResp.Body.Close()
	if optResp.StatusCode != http.StatusOK || len(optBody) != 0 || optResp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("expected 200 with empty body and no Content-Encoding on OPTIONS, got status=%d len=%d ce=%q",
			optResp.StatusCode, len(optBody), optResp.Header.Get("Content-Encoding"))
	}

	// 2. Index a document with deep nested structure + large integer for _source + filter_path tests
	doc := `{"a":{"x":{"b":42,"c":99}},"big_id":9007199254740993,"f1":"v1","f2":"v2"}`
	putReq, _ := http.NewRequest(http.MethodPut, ts.URL+"/r6_fp/_doc/1?refresh=true", strings.NewReader(doc))
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil || (putResp.StatusCode != http.StatusOK && putResp.StatusCode != http.StatusCreated) {
		t.Fatalf("PUT doc failed: %v", err)
	}
	_ = putResp.Body.Close()

	// Check GET /_source with large integer precision and multi-depth wildcard include `*.b`
	srcResp, err := http.Get(ts.URL + "/r6_fp/_source/1?_source_includes=*.b,big_id")
	if err != nil || srcResp.StatusCode != http.StatusOK {
		t.Fatalf("GET _source failed: %v", err)
	}
	srcBytes, _ := io.ReadAll(srcResp.Body)
	_ = srcResp.Body.Close()
	if !bytes.Contains(srcBytes, []byte("9007199254740993")) || !bytes.Contains(srcBytes, []byte(`"b":42`)) || bytes.Contains(srcBytes, []byte(`"c":99`)) {
		t.Fatalf("expected exact 64-bit integer and multi-depth wildcard *.b in _source, got: %s", string(srcBytes))
	}

	// 3. Check ? fields: ["f?"] single-char wildcard and filter_path=hits.hits._source.**
	searchQ := `{"fields":["f?"],"_source":["*.b"]}`
	sResp, err := http.Post(ts.URL+"/r6_fp/_search?filter_path=hits.hits._source.**,hits.hits.fields", "application/json", strings.NewReader(searchQ))
	if err != nil || sResp.StatusCode != http.StatusOK {
		t.Fatalf("search with filter_path failed: %v", err)
	}
	var sRes map[string]any
	_ = json.NewDecoder(sResp.Body).Decode(&sRes)
	_ = sResp.Body.Close()
	hit0 := sRes["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	fieldsMap := hit0["fields"].(map[string]any)
	if fieldsMap["f1"] == nil || fieldsMap["f2"] == nil {
		t.Fatalf("expected f? wildcard to match f1 and f2, got: %+v", fieldsMap)
	}
}

func TestRound6_QueryCacheContainsNowInAggsAndTermsLookupExplain(t *testing.T) {
	backend := proxy.NewMemoryBackend(false)
	srv := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	srv.SetQueryCacheTTL(10*time.Second, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Seed lookup document and target index
	_, _ = http.Post(ts.URL+"/_bulk?refresh=true", "application/x-ndjson", strings.NewReader(strings.Join([]string{
		`{"index":{"_index":"r6_users","_id":"u1"}}`,
		`{"allowed":["analytics","payments"]}`,
		`{"index":{"_index":"r6_events","_id":"e1"}}`,
		`{"dept":"analytics","ts":1700000000000}`,
		"",
	}, "\n")))

	// Verify /_doris/explain resolves cross-index Terms Lookup before transpiling
	explainQ := `{
		"query": {
			"terms": {
				"dept": {
					"index": "r6_users",
					"id": "u1",
					"path": "allowed"
				}
			}
		}
	}`
	expResp, err := http.Post(ts.URL+"/r6_events/_doris/explain", "application/json", strings.NewReader(explainQ))
	if err != nil || expResp.StatusCode != http.StatusOK {
		t.Fatalf("explain with terms lookup failed: %v", err)
	}
	var expRes map[string]any
	_ = json.NewDecoder(expResp.Body).Decode(&expRes)
	_ = expResp.Body.Close()
	hitsSQL, _ := expRes["hits_sql"].(string)
	if !strings.Contains(hitsSQL, "analytics") || !strings.Contains(hitsSQL, "payments") {
		t.Fatalf("expected /_doris/explain hits_sql to contain resolved lookup terms, got: %s", hitsSQL)
	}
}
