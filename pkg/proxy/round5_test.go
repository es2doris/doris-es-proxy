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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound5_P0_CompositeHistogram_MatchBoolPrefix_BackslashQuote_NestedMultiValued(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, body string) (int, string) {
		req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request %s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	// Create index with histogram field, text field, keyword with backslash, and nested multi-valued subfield
	code, body := doReq(http.MethodPut, "/r5_p0", `{
		"mappings": {
			"properties": {
				"latency": {"type": "integer"},
				"title": {"type": "text"},
				"path": {"type": "keyword"},
				"req_min": {"type": "integer"},
				"tags": {"type": "keyword"},
				"columns": {
					"type": "nested",
					"properties": {
						"name": {"type": "keyword"},
						"labels": {"type": "keyword", "multi_valued": true}
					}
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("create index failed: %d %s", code, body)
	}

	// Index documents with latencies 2, 7, 12, 22 so histogram(interval=5) produces buckets 0, 5, 10, 20
	docs := []string{
		`{"index":{"_index":"r5_p0","_id":"1"}}`,
		`{"latency":2,"title":"apache doris engine fast","path":"C:\\Users\\admin\\","req_min":2,"tags":["go","sql"],"columns":[{"name":"c1","labels":["pii","finance"]},{"name":"c2","labels":["public"]}]}`,
		`{"index":{"_index":"r5_p0","_id":"2"}}`,
		`{"latency":7,"title":"apache spark engine","path":"D:\\Data","req_min":2,"tags":["go","rust"],"columns":[{"name":"c1","labels":["public"]},{"name":"c2","labels":["pii","finance"]}]}`,
		`{"index":{"_index":"r5_p0","_id":"3"}}`,
		`{"latency":12,"title":"doris analytical database","path":"E:\\Logs","req_min":1,"tags":["python"],"columns":[{"name":"c1","labels":["internal"]}]}`,
		`{"index":{"_index":"r5_p0","_id":"4"}}`,
		`{"latency":22,"title":"apache doris enterprise","path":"F:\\Archive","req_min":3,"tags":["go","sql"],"columns":[]}`,
	}
	code, body = doReq(http.MethodPost, "/_bulk?refresh=true", strings.Join(docs, "\n")+"\n")
	if code != http.StatusOK || strings.Contains(body, `"errors":true`) {
		t.Fatalf("bulk index failed: %d %s", code, body)
	}

	// R5-P0-1: Composite aggregation with histogram source sorts numerically (0, 5, 10, 20) and paginates with after: {"lat_bucket": 5}
	code, body = doReq(http.MethodPost, "/r5_p0/_search", `{
		"size": 0,
		"aggs": {
			"comp": {
				"composite": {
					"size": 2,
					"sources": [
						{"lat_bucket": {"histogram": {"field": "latency", "interval": 5}}}
					]
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("composite histogram page 1 failed: %d %s", code, body)
	}
	var compResp1 struct {
		Aggregations struct {
			Comp struct {
				AfterKey map[string]int64 `json:"after_key"`
				Buckets  []struct {
					Key      map[string]int64 `json:"key"`
					DocCount int64            `json:"doc_count"`
				} `json:"buckets"`
			} `json:"comp"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal([]byte(body), &compResp1); err != nil {
		t.Fatalf("unmarshal compResp1: %v", err)
	}
	if len(compResp1.Aggregations.Comp.Buckets) != 2 ||
		compResp1.Aggregations.Comp.Buckets[0].Key["lat_bucket"] != 0 ||
		compResp1.Aggregations.Comp.Buckets[1].Key["lat_bucket"] != 5 ||
		compResp1.Aggregations.Comp.AfterKey["lat_bucket"] != 5 {
		t.Fatalf("expected composite histogram page 1 buckets [0, 5] and after_key=5, got %s", body)
	}

	code, body = doReq(http.MethodPost, "/r5_p0/_search", `{
		"size": 0,
		"aggs": {
			"comp": {
				"composite": {
					"size": 2,
					"after": {"lat_bucket": 5},
					"sources": [
						{"lat_bucket": {"histogram": {"field": "latency", "interval": 5}}}
					]
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("composite histogram page 2 failed: %d %s", code, body)
	}
	var compResp2 struct {
		Aggregations struct {
			Comp struct {
				Buckets []struct {
					Key map[string]int64 `json:"key"`
				} `json:"buckets"`
			} `json:"comp"`
		} `json:"aggregations"`
	}
	if err := json.Unmarshal([]byte(body), &compResp2); err != nil {
		t.Fatalf("unmarshal compResp2: %v", err)
	}
	if len(compResp2.Aggregations.Comp.Buckets) != 2 ||
		compResp2.Aggregations.Comp.Buckets[0].Key["lat_bucket"] != 10 ||
		compResp2.Aggregations.Comp.Buckets[1].Key["lat_bucket"] != 20 {
		t.Fatalf("expected composite histogram page 2 buckets [10, 20] after 5, got %s", body)
	}

	// R5-P0-2: Multi-token match_bool_prefix ("apache doris eng" -> matches doc 1 and doc 4)
	code, body = doReq(http.MethodPost, "/r5_p0/_search", `{
		"query": {
			"match_bool_prefix": {
				"title": {
					"query": "apache doris eng",
					"operator": "and"
				}
			}
		}
	}`)
	if code != http.StatusOK || !strings.Contains(body, `"_id":"1"`) || strings.Contains(body, `"_id":"2"`) {
		t.Fatalf("expected multi-token match_bool_prefix with operator:and to match doc 1 only, got %d %s", code, body)
	}

	// R5-P0-3: Trailing backslash in SQL string literal ('C:\\Users\\admin\\')
	code, body = doReq(http.MethodPost, "/r5_p0/_search", `{
		"query": {
			"bool": {
				"must": [
					{"term": {"path": "C:\\Users\\admin\\"}},
					{"term": {"latency": 2}}
				]
			}
		}
	}`)
	if code != http.StatusOK || !strings.Contains(body, `"_id":"1"`) {
		t.Fatalf("expected term query with trailing backslash to match doc 1, got %d %s", code, body)
	}

	// R5-P0-4: Correlated nested multi-valued subfield term query (columns.name="c1" AND columns.labels="pii")
	// Doc 1 has c1 with labels=["pii","finance"] (matches!), Doc 2 has c1 with ["public"] and c2 with ["pii","finance"] (must NOT match!)
	code, body = doReq(http.MethodPost, "/r5_p0/_search", `{
		"query": {
			"nested": {
				"path": "columns",
				"query": {
					"bool": {
						"must": [
							{"term": {"columns.name": "c1"}},
							{"term": {"columns.labels": "pii"}}
						]
					}
				}
			}
		}
	}`)
	if code != http.StatusOK || !strings.Contains(body, `"_id":"1"`) || strings.Contains(body, `"_id":"2"`) {
		t.Fatalf("expected correlated nested multi-valued term query to match doc 1 only (not doc 2), got %d %s", code, body)
	}

	// R5-P0-1 (Transpiler): terms_set with minimum_should_match_field evaluated per-row in SQL WHERE
	code, body = doReq(http.MethodPost, "/r5_p0/_search", `{
		"query": {
			"terms_set": {
				"tags": {
					"terms": ["go", "sql"],
					"minimum_should_match_field": "req_min"
				}
			}
		}
	}`)
	if code != http.StatusOK || !strings.Contains(body, `"_id":"1"`) || strings.Contains(body, `"_id":"2"`) || strings.Contains(body, `"_id":"4"`) {
		t.Fatalf("expected terms_set with minimum_should_match_field to match doc 1 only, got %d %s", code, body)
	}
}

func TestRound5_P1_SourceFilter_PipelineAggs_TermsLookup_Coalescer_And_ArrayAggs(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	srv.SetBulkCoalesce(200*time.Millisecond, 8*1024*1024)
	srv.SetQueryCacheTTL(10*time.Second, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	defer func() { _ = srv.Close(t.Context()) }()

	doReq := func(method, path, body string) (int, string) {
		req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request %s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	_, _ = doReq(http.MethodPut, "/r5_idx", `{
		"mappings": {
			"properties": {
				"region": {"type": "keyword"},
				"amount": {"type": "double"},
				"tags": {"type": "keyword"},
				"scores": {"type": "double"},
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

	// R5-P1-5: Write doc without refresh=true while coalescer window is 200ms, then immediately point-read GET /_doc, HEAD /_doc, GET /_source, POST /_mget
	_, _ = doReq(http.MethodPut, "/r5_idx/_doc/d1", `{
		"region": "us-east",
		"amount": 100,
		"tags": ["a", "b"],
		"scores": [10, 20],
		"ts": "2026-01-01T00:00:00Z",
		"user": {"name": "alice", "secret": "hidden"},
		"top_scalar": "should_not_leak",
		"top_arr": ["x", "y"],
		"items": [{"sku": "s1", "price": 15}, {" price": 25}]
	}`)
	if code, _ := doReq(http.MethodHead, "/r5_idx/_doc/d1", ""); code != http.StatusOK {
		t.Fatalf("expected HEAD /_doc/d1 to flush coalescer and return 200, got %d", code)
	}
	// R5-P1-1: _source_includes=*.name must NOT leak top-level scalars or scalar arrays
	code, body := doReq(http.MethodGet, "/r5_idx/_source/d1?_source_includes=*.name&pretty=true", "")
	if code != http.StatusOK || !strings.Contains(body, `"name": "alice"`) || strings.Contains(body, "should_not_leak") || strings.Contains(body, "top_arr") {
		t.Fatalf("expected _source_includes=*.name to only include user.name without leaking top_scalar/top_arr, got %d %s", code, body)
	}
	code, body = doReq(http.MethodPost, "/r5_idx/_mget", `{"ids":["d1"]}`)
	if code != http.StatusOK || !strings.Contains(body, `"found":true`) {
		t.Fatalf("expected _mget to return d1, got %d %s", code, body)
	}

	// Add d2 (empty tags & empty nested items) and d3
	_, _ = doReq(http.MethodPut, "/r5_idx/_doc/d2?refresh=true", `{
		"region": "us-west",
		"amount": 300,
		"tags": [],
		"scores": [30],
		"ts": "2026-01-02T00:00:00Z",
		"items": []
	}`)
	_, _ = doReq(http.MethodPut, "/r5_idx/_doc/d3?refresh=true", `{
		"region": "eu-west",
		"amount": 50,
		"ts": "2026-01-03T00:00:00Z"
	}`)

	// R5-P1-2: Sibling pipeline agg (sum_bucket) over `filters` aggregation (map-keyed buckets)
	// R5-P1-3: Child pipeline aggs: derivative referencing cumulative_sum, bucket_selector with `return` & `&&`, bucket_sort on string `_key`
	code, body = doReq(http.MethodPost, "/r5_idx/_search", `{
		"size": 0,
		"aggs": {
			"by_region_filters": {
				"filters": {
					"filters": {
						"us": {"prefix": {"region": "us-"}},
						"eu": {"prefix": {"region": "eu-"}}
					}
				},
				"aggs": {
					"sum_amt": {"sum": {"field": "amount"}}
				}
			},
			"total_filtered_amt": {
				"sum_bucket": {"buckets_path": "by_region_filters>sum_amt"}
			},
			"by_day": {
				"date_histogram": {"field": "ts", "fixed_interval": "1d"},
				"aggs": {
					"daily_sum": {"sum": {"field": "amount"}},
					"running_sum": {"cumulative_sum": {"buckets_path": "daily_sum"}},
					"running_delta": {"derivative": {"buckets_path": "running_sum"}},
					"sel": {
						"bucket_selector": {
							"buckets_path": {"s": "daily_sum", "r": "running_sum"},
							"script": "return (params.s >= 50 && params.r >= 100);"
						}
					}
				}
			},
			"by_reg": {
				"terms": {"field": "region", "size": 10},
				"aggs": {
					"sort_key_desc": {
						"bucket_sort": {
							"sort": [{"_key": {"order": "desc"}}]
						}
					}
				}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("pipeline aggs search failed: %d %s", code, body)
	}
	if !strings.Contains(body, `"total_filtered_amt":{"value":450}`) {
		t.Fatalf("expected sum_bucket over filters agg to equal 450, got %s", body)
	}
	if !strings.Contains(body, `"running_delta":{"value":300}`) {
		t.Fatalf("expected derivative of cumulative_sum on day 2 to equal 300, got %s", body)
	}

	// R5-P1-7 & R5-P1-8: nested terms with missing + nested stats
	code, body = doReq(http.MethodPost, "/r5_idx/_search", `{
		"size": 0,
		"aggs": {
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"by_sku": {"terms": {"field": "items.sku", "missing": "NO_SKU"}},
					"price_stats": {"stats": {"field": "items.price"}}
				}
			}
		}
	}`)
	if code != http.StatusOK || !strings.Contains(body, `"key":"NO_SKU"`) || !strings.Contains(body, `"price_stats"`) {
		t.Fatalf("expected nested terms missing bucket NO_SKU and nested price_stats, got %d %s", code, body)
	}

	// R5-P1-4: Terms lookup with flat dotted key in lookup document + _delete_by_query with terms lookup
	_, _ = doReq(http.MethodPut, "/lookup_idx/_doc/u1?refresh=true", `{"allow.regions": ["eu-west"]}`)
	code, body = doReq(http.MethodPost, "/r5_idx/_validate/query", `{
		"query": {
			"terms": {
				"region": {
					"index": "lookup_idx",
					"id": "u1",
					"path": "allow.regions"
				}
			}
		}
	}`)
	if code != http.StatusOK || !strings.Contains(body, `"valid":true`) {
		t.Fatalf("expected _validate/query with terms lookup to succeed, got %d %s", code, body)
	}
	code, body = doReq(http.MethodPost, "/r5_idx/_delete_by_query", `{
		"query": {
			"terms": {
				"region": {
					"index": "lookup_idx",
					"id": "u1",
					"path": "allow.regions"
				}
			}
		}
	}`)
	if code != http.StatusOK || !strings.Contains(body, `"deleted":1`) {
		t.Fatalf("expected _delete_by_query with terms lookup to delete 1 doc (d3), got %d %s", code, body)
	}
}

func TestRound5_P1_P2_Lucene_WireFormat_Templates_ILM_Scroll(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	srv.SetAuth("elastic", "secret", "")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, body string, withAuth bool) (int, string) {
		req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if withAuth {
			req.SetBasicAuth("elastic", "secret")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request %s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(raw)
	}

	// R5-P2-1: 401 Unauthorized with ?error_trace=true&pretty=true honors formatting
	code, body := doReq(http.MethodGet, "/_cluster/health?error_trace=true&pretty=true", "", false)
	if code != http.StatusUnauthorized || !strings.Contains(body, `"stack_trace"`) || !strings.Contains(body, "\n  ") {
		t.Fatalf("expected 401 with stack_trace and pretty formatting, got %d %s", code, body)
	}

	// R5-P2-2: Component templates, wildcard index templates, and /_ilm/explain
	code, body = doReq(http.MethodPut, "/_component_template/ct-logs", `{"template":{"settings":{"number_of_shards":1}}}`, true)
	if code != http.StatusOK {
		t.Fatalf("put component template failed: %d %s", code, body)
	}
	code, body = doReq(http.MethodGet, "/_component_template/ct-*", "", true)
	if code != http.StatusOK || !strings.Contains(body, `"ct-logs"`) {
		t.Fatalf("get wildcard component template failed: %d %s", code, body)
	}
	_, _ = doReq(http.MethodPut, "/_index_template/logs-tpl", `{"index_patterns":["logs-*"]}`, true)
	code, body = doReq(http.MethodGet, "/_index_template/logs-*", "", true)
	if code != http.StatusOK || !strings.Contains(body, `"logs-tpl"`) {
		t.Fatalf("get wildcard index template failed: %d %s", code, body)
	}
	_, _ = doReq(http.MethodPut, "/logs-001", `{"mappings":{"properties":{"host.name":{"type":"keyword"},"code":{"type":"integer"}}}}`, true)
	code, body = doReq(http.MethodGet, "/logs-001/_ilm/explain", "", true)
	if code != http.StatusOK || !strings.Contains(body, `"managed":false`) {
		t.Fatalf("expected /logs-001/_ilm/explain to return managed:false, got %d %s", code, body)
	}

	// R5-P2-1: filter_path on dotted map key in _field_caps
	code, body = doReq(http.MethodGet, "/logs-001/_field_caps?fields=*&filter_path=fields.host.name", "", true)
	if code != http.StatusOK || !strings.Contains(body, `"host.name"`) || strings.Contains(body, `"_id"`) {
		t.Fatalf("expected filter_path=fields.host.name to keep host.name only, got %d %s", code, body)
	}

	// R5-P1-11: Lucene default_field range [100 TO 200] & boosted field group
	_, _ = doReq(http.MethodPut, "/logs-001/_doc/1?refresh=true", `{"host.name":"web-1","code":150}`, true)
	_, _ = doReq(http.MethodPut, "/logs-001/_doc/2?refresh=true", `{"host.name":"db-1","code":500}`, true)
	code, body = doReq(http.MethodPost, "/logs-001/_search", `{
		"query": {
			"query_string": {
				"default_field": "code",
				"query": "[100 TO 200]"
			}
		}
	}`, true)
	if code != http.StatusOK || !strings.Contains(body, `"_id":"1"`) || strings.Contains(body, `"_id":"2"`) {
		t.Fatalf("expected default_field range [100 TO 200] to match doc 1 only, got %d %s", code, body)
	}

	// R5-P2-3: SourceFilter.MarshalJSON round-trip in scroll cursor
	var sf esast.SourceFilter
	if err := json.Unmarshal([]byte(`false`), &sf); err != nil {
		t.Fatalf("unmarshal SourceFilter false: %v", err)
	}
	marshaledSF, err := json.Marshal(sf)
	if err != nil || string(marshaledSF) != "false" {
		t.Fatalf("expected SourceFilter{Disabled:true} to marshal as false, got %s (%v)", string(marshaledSF), err)
	}
}
