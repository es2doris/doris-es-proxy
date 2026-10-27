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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound4_P0_CoalescerDrain_TermsLookup_CacheAndAutoPromote_MultiIndexMetrics(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	srv.SetBulkCoalesce(50*time.Millisecond, DefaultBulkCoalesceMaxBytes)
	srv.SetQueryCacheTTL(10*time.Second, 100)
	srv.SetAutoPromoteThreshold(3)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, body string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	// P1-3: Read-your-own-writes & monotonic _version with coalescer enabled (no ?refresh=true)
	code, body := doReq(http.MethodPut, "/ryow_idx/_doc/1", `{"title":"v1","count":10}`)
	if code != http.StatusCreated {
		t.Fatalf("expected 201 on PutDoc, got %d %s", code, body)
	}
	// Immediate GET without refresh=true must flush pending coalescer batch and find doc 1
	code, body = doReq(http.MethodGet, "/ryow_idx/_doc/1", "")
	if code != http.StatusOK || !strings.Contains(body, `"title":"v1"`) {
		t.Fatalf("expected immediate GET after coalesced PutDoc to succeed, got %d %s", code, body)
	}
	// Immediate _update must see v1 and increment _version monotonically
	code, body = doReq(http.MethodPost, "/ryow_idx/_update/1", `{"doc":{"title":"v2"}}`)
	if code != http.StatusOK || !strings.Contains(body, `"result":"updated"`) {
		t.Fatalf("expected immediate _update after coalesced PutDoc to update, got %d %s", code, body)
	}
	code, body = doReq(http.MethodGet, "/ryow_idx/_source/1?_source_includes=title", "")
	if code != http.StatusOK || strings.TrimSpace(body) != `{"title":"v2"}` {
		t.Fatalf("expected GET _source with _source_includes=title to return updated v2, got %d %s", code, body)
	}

	// P0-4: Empty terms array returns 0 hits, scalar terms returns 400, terms lookup resolves from index
	if code, body = doReq(http.MethodPost, "/ryow_idx/_search", `{"query":{"terms":{"title":[]}}}`); code != http.StatusOK || !strings.Contains(body, `"value":0`) {
		t.Fatalf("expected empty terms array to match 0 docs, got %d %s", code, body)
	}
	if code, body = doReq(http.MethodPost, "/ryow_idx/_search", `{"query":{"terms":{"title":"v2"}}}`); code != http.StatusBadRequest {
		t.Fatalf("expected scalar terms query to return 400 parsing_exception, got %d %s", code, body)
	}
	_, _ = doReq(http.MethodPut, "/users_lookup/_doc/u1?refresh=true", `{"allowed_titles":["v2","v3"]}`)
	code, body = doReq(http.MethodPost, "/ryow_idx/_search", `{
		"query": {
			"terms": {
				"title": {
					"index": "users_lookup",
					"id": "u1",
					"path": "allowed_titles"
				}
			}
		}
	}`)
	if code != http.StatusOK || !strings.Contains(body, `"value":1`) {
		t.Fatalf("expected terms lookup query to match 1 doc, got %d %s", code, body)
	}

	// P0-5 & P0-6: Query cache hit still feeds SlowQueryTracker for --auto-promote & now date math bypasses cache
	_, _ = doReq(http.MethodPut, "/promo_cache_idx", `{"mappings":{"properties":{"fixed":{"type":"keyword"}}}}`)
	_, _ = doReq(http.MethodPut, "/promo_cache_idx/_doc/p1?refresh=true", `{"fixed":"a","hot_unmapped":"target"}`)
	for i := 0; i < 3; i++ {
		code, body = doReq(http.MethodPost, "/promo_cache_idx/_search", `{"query":{"term":{"hot_unmapped":"target"}}}`)
		if code != http.StatusOK || !strings.Contains(body, `"value":1`) {
			t.Fatalf("expected search %d on hot_unmapped to match 1 doc, got %d %s", i, code, body)
		}
	}
	// After 3 queries (even with 10s query cache enabled!), hot_unmapped must be auto-promoted to f__hot_unmapped
	code, body = doReq(http.MethodGet, "/promo_cache_idx/_mapping", "")
	if code != http.StatusOK || !strings.Contains(body, `"hot_unmapped"`) {
		t.Fatalf("expected hot_unmapped to be auto-promoted despite query cache hits, got %d %s", code, body)
	}

	// P0-9: Multi-index min/avg when one index lacks the metric field + weighted avg across shards
	_, _ = doReq(http.MethodPut, "/shard_a", `{"mappings":{"properties":{"latency":{"type":"double"}}}}`)
	_, _ = doReq(http.MethodPut, "/shard_b", `{"mappings":{"properties":{"host":{"type":"keyword"}}}}`)
	_, _ = doReq(http.MethodPut, "/shard_c", `{"mappings":{"properties":{"latency":{"type":"double"}}}}`)
	_, _ = doReq(http.MethodPut, "/shard_a/_doc/1?refresh=true", `{"latency":100}`)
	_, _ = doReq(http.MethodPut, "/shard_a/_doc/2?refresh=true", `{"latency":100}`)
	_, _ = doReq(http.MethodPut, "/shard_a/_doc/3?refresh=true", `{"latency":100}`)
	_, _ = doReq(http.MethodPut, "/shard_b/_doc/4?refresh=true", `{"host":"web-1"}`)
	_, _ = doReq(http.MethodPut, "/shard_c/_doc/5?refresh=true", `{"latency":300}`)

	code, body = doReq(http.MethodPost, "/shard_a,shard_b,shard_c/_search", `{
		"size": 0,
		"aggs": {
			"min_lat": {"min": {"field": "latency"}},
			"avg_lat": {"avg": {"field": "latency"}}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected multi-index metric search to succeed, got %d %s", code, body)
	}
	var shardResp map[string]any
	if err := json.Unmarshal([]byte(body), &shardResp); err != nil {
		t.Fatal(err)
	}
	aggsMap := shardResp["aggregations"].(map[string]any)
	minLat := aggsMap["min_lat"].(map[string]any)["value"].(float64)
	avgLat := aggsMap["avg_lat"].(map[string]any)["value"].(float64)
	if minLat != 100 {
		t.Fatalf("expected multi-index min_lat=100 (unpolluted by shard_b), got %v", minLat)
	}
	// Weighted avg across 3 docs @ 100 on shard_a and 1 doc @ 300 on shard_c = (300 + 300) / 4 = 150
	if avgLat != 150 {
		t.Fatalf("expected weighted multi-index avg_lat=150, got %v", avgLat)
	}

	// P0-1: Server.Close drains pending StreamLoadCoalescer batches immediately before returning
	srv.SetBulkCoalesce(10*time.Second, DefaultBulkCoalesceMaxBytes)
	coalesceDone := make(chan error, 1)
	go func() {
		coalesceDone <- srv.coalescer.Submit(context.Background(), "es_compat__ryow_idx", []byte(`{"_id":"2","_version":99,"_source":"{\"title\":\"flushed_on_close\"}","_doc":{}}`+"\n"), false)
	}()
	time.Sleep(15 * time.Millisecond)
	if err := srv.Close(context.Background()); err != nil {
		t.Fatalf("expected srv.Close to succeed, got %v", err)
	}
	if err := <-coalesceDone; err != nil {
		t.Fatalf("expected pending coalescer batch to flush cleanly on Close, got %v", err)
	}
}

func TestRound4_P0_HybridKNN_And_ShadowConcurrency(t *testing.T) {
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hits":{"total":{"value":1},"hits":[{"_id":"v1"}]}}`))
	}))
	defer shadowSrv.Close()

	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	srv.SetShadowESURL(shadowSrv.URL)

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, body string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	_, _ = doReq(http.MethodPut, "/vec_hybrid", `{
		"mappings": {
			"properties": {
				"category": {"type": "keyword"},
				"emb": {"type": "dense_vector", "dims": 2}
			}
		}
	}`)
	_, _ = doReq(http.MethodPut, "/vec_hybrid/_doc/v1?refresh=true", `{"category":"books","emb":[1.0,0.0]}`)
	_, _ = doReq(http.MethodPut, "/vec_hybrid/_doc/v2?refresh=true", `{"category":"movies","emb":[1.0,0.0]}`)

	// P0-7 & P0-2: Hybrid search (query + top-level knn) + rest_total_hits_as_int=true + _doris_explain with shadow enabled
	code, body := doReq(http.MethodPost, "/vec_hybrid/_search?rest_total_hits_as_int=true&_doris_explain=true", `{
		"query": {"term": {"category": "books"}},
		"knn": {
			"field": "emb",
			"query_vector": [1.0, 0.0],
			"k": 1
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected hybrid search to succeed, got %d %s", code, body)
	}
	if !strings.Contains(body, `"total":2`) || !strings.Contains(body, `"_id":"v1"`) || strings.Contains(body, `"_id":"v2"`) {
		t.Fatalf("expected hybrid search to rank v1 top-1 and return integer total:2, got %s", body)
	}
	if !strings.Contains(body, `"hits_sql_normalized"`) {
		t.Fatalf("expected _doris_explain to include hits_sql_normalized, got %s", body)
	}
}

func TestRound4_P1_TrackTotalHits_FilterPath_Pretty_ErrorTrace_PipelineAggs_TermsOptions(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, body string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	_, _ = doReq(http.MethodPut, "/sales_idx", `{
		"mappings": {
			"properties": {
				"region": {"type": "keyword"},
				"tags": {"type": "keyword", "multi_valued": true},
				"amount": {"type": "double"},
				"ts": {"type": "date"},
				"items": {
					"type": "nested",
					"properties": {
						"sku": {"type": "keyword"},
						"price": {"type": "double"}
					}
				}
			}
		}
	}`)
	_, _ = doReq(http.MethodPut, "/sales_idx/_doc/1?refresh=true", `{"region":"us-east","tags":["vip","0x1f00"],"amount":100,"ts":"2026-01-01T00:00:00Z","items":[{"sku":"A","price":40},{"sku":"B","price":60}]}`)
	_, _ = doReq(http.MethodPut, "/sales_idx/_doc/2?refresh=true", `{"region":"us-west","tags":["standard"],"amount":250,"ts":"2026-01-02T00:00:00Z","items":[{"sku":"A","price":250}]}`)
	_, _ = doReq(http.MethodPut, "/sales_idx/_doc/3?refresh=true", `{"region":"eu-central","amount":50,"ts":"2026-01-03T00:00:00Z","items":[]}`)

	// P1-7: track_total_hits: false omits hits.total; integer threshold returns relation: gte
	code, body := doReq(http.MethodPost, "/sales_idx/_search", `{"track_total_hits":false,"size":1}`)
	if code != http.StatusOK || strings.Contains(body, `"relation"`) {
		t.Fatalf("expected track_total_hits:false to omit hits.total, got %d %s", code, body)
	}
	code, body = doReq(http.MethodPost, "/sales_idx/_search?track_total_hits=2", `{"size":1}`)
	if code != http.StatusOK || !strings.Contains(body, `"relation":"gte"`) || !strings.Contains(body, `"value":2`) {
		t.Fatalf("expected track_total_hits=2 threshold to return relation:gte value:2, got %d %s", code, body)
	}

	// P1-8: filter_path (with exclusion), pretty=true, error_trace=true
	code, body = doReq(http.MethodPost, "/sales_idx/_search?filter_path=hits.hits._source,-hits.hits._source.items&pretty=true", `{"size":1,"sort":[{"amount":"asc"}]}`)
	if code != http.StatusOK || !strings.Contains(body, "\n  \"hits\"") || strings.Contains(body, `"_shards"`) || strings.Contains(body, `"items"`) {
		t.Fatalf("expected filter_path and pretty=true to format and filter response, got %d %s", code, body)
	}
	code, body = doReq(http.MethodPost, "/sales_idx/_search?error_trace=true", `{"invalid_json"`)
	if code != http.StatusBadRequest || !strings.Contains(body, `"stack_trace"`) {
		t.Fatalf("expected error_trace=true to include stack_trace, got %d %s", code, body)
	}

	// P1-5, P1-6, P1-9, P1-10: terms include/exclude/order/min_doc_count/missing on array, literal "0x1f00", nested metric sub-agg, and pipeline aggs
	code, body = doReq(http.MethodPost, "/sales_idx/_search", `{
		"size": 0,
		"aggs": {
			"by_region": {
				"terms": {
					"field": "region",
					"include": ["us-east", "us-west", "eu-central"],
					"exclude": ["eu-central"],
					"min_doc_count": 1,
					"order": {"total_amt": "desc"}
				},
				"aggs": {
					"total_amt": {"sum": {"field": "amount"}},
					"cum_amt": {"cumulative_sum": {"buckets_path": "total_amt"}},
					"deriv_amt": {"derivative": {"buckets_path": "total_amt"}},
					"high_only": {
						"bucket_selector": {
							"buckets_path": {"amt": "total_amt"},
							"script": "params.amt >= 100"
						}
					},
					"top_one": {
						"bucket_sort": {
							"size": 2
						}
					}
				}
			},
			"avg_regional_sales": {
				"avg_bucket": {"buckets_path": "by_region>total_amt"}
			},
			"sum_regional_sales": {
				"sum_bucket": {"buckets_path": "by_region>total_amt"}
			},
			"tags_with_missing": {
				"terms": {
					"field": "tags",
					"missing": "NO_TAG"
				}
			},
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"avg_item_price": {"avg": {"field": "items.price"}},
					"by_sku": {"terms": {"field": "items.sku"}}
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected complex aggs query to succeed, got %d %s", code, body)
	}
	if !strings.Contains(body, `"avg_regional_sales":{"value":175}`) || !strings.Contains(body, `"sum_regional_sales":{"value":350}`) {
		t.Fatalf("expected avg_bucket=175 and sum_bucket=350, got %s", body)
	}
	if !strings.Contains(body, `"0x1f00"`) || !strings.Contains(body, `"NO_TAG"`) {
		t.Fatalf("expected literal 0x1f00 and NO_TAG missing bucket on array field, got %s", body)
	}
	if !strings.Contains(body, `"avg_item_price":{"value":116.666`) {
		t.Fatalf("expected nested metric sub-agg avg_item_price=(40+60+250)/3, got %s", body)
	}
}

func TestRound4_P1_P2_Queries_Lucene_Painless_Auth_And_ClientRoutes(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	// P1-1: Setting only basicUser without basicPass must NOT enable empty-password Basic Auth
	srv.SetAuth("admin", "", "secret-token-123")

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doAuthReq := func(method, path, body, authHeader string) (int, string) {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	// Basic auth with admin:"" must be rejected when only API key is configured
	if code, _ := doAuthReq(http.MethodGet, "/", "", "Basic YWRtaW46"); code != http.StatusUnauthorized {
		t.Fatalf("expected partial basic auth config not to accept empty password, got %d", code)
	}
	authHdr := "Bearer secret-token-123"
	if code, body := doAuthReq(http.MethodGet, "/_security/_authenticate", "", authHdr); code != http.StatusOK || !strings.Contains(body, `"username":"elastic"`) || strings.Contains(body, `"admin"`) {
		t.Fatalf("expected /_security/_authenticate with Bearer token to succeed without leaking partial basicUser, got %d %s", code, body)
	}

	// P1-12: Client ecosystem routes (_nodes/http, _cluster/state, _cluster/stats, _ilm/policy, _component_template, _data_stream)
	for _, ep := range []string{"/_nodes", "/_nodes/http", "/_cluster/state", "/_cluster/stats", "/_ilm/policy", "/_ilm/status", "/_component_template", "/_data_stream"} {
		code, body := doAuthReq(http.MethodGet, ep, "", authHdr)
		if code != http.StatusOK {
			t.Fatalf("expected GET %s to return 200, got %d %s", ep, code, body)
		}
		if ep == "/_nodes" && !strings.Contains(body, `"publish_address"`) {
			t.Fatalf("expected /_nodes to include http.publish_address, got %s", body)
		}
	}

	// P1-4: VARCHAR(1024) UTF-8 safe truncation for long keyword values
	longKeyword := strings.Repeat("é", 600) // 1200 UTF-8 bytes
	_, _ = doAuthReq(http.MethodPut, "/q_idx", `{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"code": {"type": "keyword"},
				"req_count": {"type": "integer"},
				"skills": {"type": "keyword"},
				"score_num": {"type": "double"},
				"user": {
					"properties": {
						"name": {"type": "keyword"},
						"secret": {"type": "keyword"}
					}
				}
			}
		}
	}`, authHdr)
	_, _ = doAuthReq(http.MethodPut, "/q_idx/_doc/d1?refresh=true", `{
		"title": "apache doris search engine",
		"code": "`+longKeyword+`",
		"req_count": 2,
		"skills": ["go", "sql", "doris"],
		"score_num": 10,
		"user": {"name": "alice", "secret": "s1"}
	}`, authHdr)
	_, _ = doAuthReq(http.MethodPut, "/q_idx/_doc/d2?refresh=true", `{
		"title": "apache spark batch engine",
		"code": "spark-1",
		"req_count": 3,
		"skills": ["scala"],
		"score_num": 5,
		"user": {"name": "bob", "secret": "s2"}
	}`, authHdr)

	// P1-11: match_phrase with slop > 0 and multi-token match_phrase_prefix
	if code, body := doAuthReq(http.MethodPost, "/q_idx/_search", `{"query":{"match_phrase":{"title":{"query":"apache engine","slop":2}}}}`, authHdr); code != http.StatusOK || !strings.Contains(body, `"value":2`) {
		t.Fatalf("expected match_phrase with slop:2 to match both docs, got %d %s", code, body)
	}
	if code, body := doAuthReq(http.MethodPost, "/q_idx/_search", `{"query":{"match_phrase_prefix":{"title":"apache dor"}}}`, authHdr); code != http.StatusOK || !strings.Contains(body, `"value":1`) {
		t.Fatalf("expected multi-token match_phrase_prefix to match d1, got %d %s", code, body)
	}

	// P2-1: terms_set, fuzzy, combined_fields, script_score
	if code, body := doAuthReq(http.MethodPost, "/q_idx/_search", `{
		"query": {
			"terms_set": {
				"skills": {
					"terms": ["go", "doris", "rust"],
					"minimum_should_match_field": "req_count"
				}
			}
		}
	}`, authHdr); code != http.StatusOK || !strings.Contains(body, `"_id":"d1"`) || strings.Contains(body, `"_id":"d2"`) {
		t.Fatalf("expected terms_set to match d1 only, got %d %s", code, body)
	}
	if code, body := doAuthReq(http.MethodPost, "/q_idx/_search", `{"query":{"fuzzy":{"code":{"value":"spark-1","fuzziness":"AUTO"}}}}`, authHdr); code != http.StatusOK || !strings.Contains(body, `"_id":"d2"`) {
		t.Fatalf("expected fuzzy query to match d2, got %d %s", code, body)
	}
	if code, body := doAuthReq(http.MethodPost, "/q_idx/_search", `{"query":{"combined_fields":{"query":"doris","fields":["title","code"]}}}`, authHdr); code != http.StatusOK || !strings.Contains(body, `"_id":"d1"`) {
		t.Fatalf("expected combined_fields query to match d1, got %d %s", code, body)
	}
	if code, body := doAuthReq(http.MethodPost, "/q_idx/_search", `{"query":{"script_score":{"query":{"match_all":{}},"script":{"source":"_score * 2"}}}}`, authHdr); code != http.StatusOK || !strings.Contains(body, `"value":2`) {
		t.Fatalf("expected script_score query to succeed, got %d %s", code, body)
	}

	// P2-3: Wildcard parent _source_includes (*.name)
	if code, body := doAuthReq(http.MethodGet, "/q_idx/_doc/d1?_source_includes=*.name", "", authHdr); code != http.StatusOK || !strings.Contains(body, `"name":"alice"`) || strings.Contains(body, `"secret"`) {
		t.Fatalf("expected _source_includes=*.name to include user.name and exclude user.secret, got %d %s", code, body)
	}

	// P2-5: _update with empty upsert: {} creates empty doc with 201 Created
	if code, body := doAuthReq(http.MethodPost, "/q_idx/_update/empty_up", `{"doc":{"extra":1},"upsert":{}}`, authHdr); code != http.StatusCreated || !strings.Contains(body, `"result":"created"`) {
		t.Fatalf("expected _update with upsert:{} to return 201 created, got %d %s", code, body)
	}

	// P2-6: Lucene >=, <=, /regex/, default_operator: AND
	if code, body := doAuthReq(http.MethodPost, "/q_idx/_search", `{"query":{"query_string":{"query":"score_num:>=10 AND code:/spark-.*/ OR req_count:<=2","default_operator":"AND"}}}`, authHdr); code != http.StatusOK || !strings.Contains(body, `"_id":"d1"`) {
		t.Fatalf("expected Lucene >=, <=, and /regex/ to execute, got %d %s", code, body)
	}

	// P2-2: Painless *=, /=, and unary - on non-literal expression
	doc := map[string]any{"val": int64(10)}
	if _, err := painless.EvalPainlessWithOp(doc, "ctx._source.val *= 3; ctx._source.neg = -ctx._source.val; ctx._source.val /= 2", nil); err != nil {
		t.Fatalf("unexpected painless error: %v", err)
	}
	if doc["val"] != int64(15) || doc["neg"] != int64(-30) {
		t.Fatalf("expected val=15 and neg=-30 after *=, unary -, and /=, got %+v", doc)
	}

	// P1-2: NaN / Inf guard in ExpandFieldPattern
	idxSchema := schema.CompileIndexSchema("es_compat", "nan_idx", nil)
	expanded := idxSchema.ExpandFieldPattern("field^NaN")
	if len(expanded) == 0 || math.IsNaN(expanded[0].Boost) || math.IsInf(expanded[0].Boost, 0) || expanded[0].Boost != 1.0 {
		t.Fatalf("expected NaN boost to sanitize to 1.0, got %+v", expanded)
	}
}

func TestRound4_HelmAndK8sManifestHardening(t *testing.T) {
	helmDep, err := os.ReadFile("../../deploy/helm/doris-es-proxy/templates/deployment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(helmDep, []byte(")/{{ .Values.doris.database }}?")) {
		t.Fatalf("expected Helm deployment.yaml DSN not to hardcode database path before CREATE DATABASE IF NOT EXISTS")
	}
	if !bytes.Contains(helmDep, []byte("checksum/secret")) {
		t.Fatalf("expected Helm deployment.yaml to include checksum/secret annotation")
	}

	k8sManifest, err := os.ReadFile("../../deploy/kubernetes/doris-es-proxy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(k8sManifest, []byte("runAsNonRoot: true")) || !bytes.Contains(k8sManifest, []byte("readOnlyRootFilesystem: true")) {
		t.Fatalf("expected deploy/kubernetes/doris-es-proxy.yaml to enforce runAsNonRoot and readOnlyRootFilesystem")
	}

	// Verify concurrent SlowQueryTracker promotion only triggers once per field
	tracker := newSlowQueryTracker()
	var promotedCount int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := tracker.recordWithThreshold(SlowQueryEntry{
				Index:                  "idx",
				UnindexedVariantFields: []string{"hot_field"},
			}, 3)
			if len(res) > 0 {
				mu.Lock()
				promotedCount += len(res)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if promotedCount == 0 || promotedCount > 6 {
		// 20 goroutines / threshold 3 => at most 6 promotions, never a thundering herd of 18!
		t.Fatalf("expected atomic counter reset to bound promotions to <= 6 across 20 queries, got %d", promotedCount)
	}
}
