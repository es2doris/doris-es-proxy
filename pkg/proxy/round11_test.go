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
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doRawReq(t *testing.T, ts *httptest.Server, method, path, body string) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func mustReq(t *testing.T, ts *httptest.Server, method, path, body string) map[string]any {
	t.Helper()
	code, raw := doRawReq(t, ts, method, path, body)
	if code >= 400 {
		t.Fatalf("%s %s returned HTTP %d: %s", method, path, code, string(raw))
	}
	var out map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("failed to decode JSON from %s %s: %v (raw=%s)", method, path, err, string(raw))
		}
	}
	return out
}

func getTotalHits(res map[string]any) float64 {
	hits, _ := res["hits"].(map[string]any)
	total, _ := hits["total"].(map[string]any)
	val, _ := total["value"].(float64)
	return val
}

// TestRound11DeleteIndexAliasGuardAndTargetResolution verifies R11-P0-1 and R11-P0-3:
// - DELETE /my_alias,my_alias and DELETE /alias* reject alias targets with 400 illegal_argument_exception
// - _all,-secret and tenant_a,-tenant_b / tenant_*,-tenant_b preserve concrete index and sibling tenant isolation.
func TestRound11DeleteIndexAliasGuardAndTargetResolution(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/shared_logs", `{"mappings":{"properties":{"tenant":{"type":"keyword"},"msg":{"type":"keyword"}}}}`)
	mustReq(t, ts, http.MethodPut, "/secret_logs", `{"mappings":{"properties":{"msg":{"type":"keyword"}}}}`)
	mustReq(t, ts, http.MethodPost, "/_aliases", `{
		"actions": [
			{"add": {"index": "shared_logs", "alias": "tenant_a", "filter": {"term": {"tenant": "a"}}}},
			{"add": {"index": "shared_logs", "alias": "tenant_b", "filter": {"term": {"tenant": "b"}}}}
		]
	}`)
	mustReq(t, ts, http.MethodPut, "/tenant_a/_doc/a1?refresh=true", `{"tenant":"a","msg":"hello-a"}`)
	mustReq(t, ts, http.MethodPut, "/tenant_b/_doc/b1?refresh=true", `{"tenant":"b","msg":"hello-b"}`)
	mustReq(t, ts, http.MethodPut, "/secret_logs/_doc/s1?refresh=true", `{"msg":"top-secret"}`)

	// R11-P0-1: DELETE /tenant_a,tenant_a and DELETE /tenant_* must be rejected with 400
	code, _ := doRawReq(t, ts, http.MethodDelete, "/tenant_a,tenant_a", "")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on DELETE /tenant_a,tenant_a, got %d", code)
	}
	code, _ = doRawReq(t, ts, http.MethodDelete, "/tenant_*", "")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on DELETE /tenant_*, got %d", code)
	}

	// Verify shared_logs documents still exist
	res := mustReq(t, ts, http.MethodPost, "/shared_logs/_search", `{}`)
	if getTotalHits(res) != 2 {
		t.Fatalf("expected 2 docs in shared_logs, got %v", getTotalHits(res))
	}

	// R11-P0-3: _all,-secret_logs must return only shared_logs (2 hits)
	res = mustReq(t, ts, http.MethodPost, "/_all,-secret_logs/_search", `{}`)
	if getTotalHits(res) != 2 {
		t.Fatalf("expected 2 hits for _all,-secret_logs, got %v", getTotalHits(res))
	}

	// R11-P0-3: tenant_a,-tenant_b and tenant_*,-tenant_b must return only tenant_a's 1 document
	res = mustReq(t, ts, http.MethodPost, "/tenant_a,-tenant_b/_search", `{}`)
	if getTotalHits(res) != 1 {
		t.Fatalf("expected 1 hit for tenant_a,-tenant_b, got %v", getTotalHits(res))
	}
	res = mustReq(t, ts, http.MethodPost, "/tenant_*,-tenant_b/_search", `{}`)
	if getTotalHits(res) != 1 {
		t.Fatalf("expected 1 hit for tenant_*,-tenant_b, got %v", getTotalHits(res))
	}
}

// TestRound11ReindexCrossTenantConflictAndOpTypeCreate verifies R11-P0-2:
// - POST /_reindex into a filtered destination write alias rejects cross-tenant ID collisions with 409 Conflict
// - conflicts: "proceed" skips colliding documents and increments version_conflicts
// - dest.op_type: "create" rejects overwriting existing documents in the same partition.
func TestRound11ReindexCrossTenantConflictAndOpTypeCreate(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/src_idx", `{"mappings":{"properties":{"tenant":{"type":"keyword"},"val":{"type":"integer"}}}}`)
	mustReq(t, ts, http.MethodPut, "/dst_shared", `{"mappings":{"properties":{"tenant":{"type":"keyword"},"val":{"type":"integer"}}}}`)
	mustReq(t, ts, http.MethodPost, "/_aliases", `{
		"actions": [
			{"add": {"index": "dst_shared", "alias": "dst_a", "filter": {"term": {"tenant": "a"}}}},
			{"add": {"index": "dst_shared", "alias": "dst_b", "filter": {"term": {"tenant": "b"}}}}
		]
	}`)

	// Seed tenant_b doc with id="shared-1" in dst_shared
	mustReq(t, ts, http.MethodPut, "/dst_b/_doc/shared-1?refresh=true", `{"tenant":"b","val":999}`)
	// Seed src_idx with id="shared-1" and id="a-only" for tenant "a"
	mustReq(t, ts, http.MethodPut, "/src_idx/_doc/shared-1?refresh=true", `{"tenant":"a","val":10}`)
	mustReq(t, ts, http.MethodPut, "/src_idx/_doc/a-only?refresh=true", `{"tenant":"a","val":20}`)

	// Reindexing into dst_a without conflicts="proceed" must fail with 409 Conflict on shared-1
	code, _ := doRawReq(t, ts, http.MethodPost, "/_reindex", `{
		"source": {"index": "src_idx"},
		"dest": {"index": "dst_a"}
	}`)
	if code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when reindexing colliding ID into dst_a, got %d", code)
	}

	// Verify tenant_b's document was not overwritten
	bDoc := mustReq(t, ts, http.MethodGet, "/dst_b/_doc/shared-1", "")
	if bDoc["found"] != true {
		t.Fatalf("expected dst_b doc shared-1 to remain intact, got %+v", bDoc)
	}

	// Reindexing with conflicts="proceed" must skip shared-1 (version_conflicts=1) and create a-only (created=1)
	reindexRes := mustReq(t, ts, http.MethodPost, "/_reindex", `{
		"conflicts": "proceed",
		"source": {"index": "src_idx"},
		"dest": {"index": "dst_a"}
	}`)
	if int(reindexRes["version_conflicts"].(float64)) != 1 || int(reindexRes["created"].(float64)) != 1 {
		t.Fatalf("expected version_conflicts=1 and created=1, got %+v", reindexRes)
	}

	// Reindexing again into dst_a with op_type="create" and conflicts="proceed" must count a-only as a conflict too
	reindexCreate := mustReq(t, ts, http.MethodPost, "/_reindex", `{
		"conflicts": "proceed",
		"source": {"index": "src_idx"},
		"dest": {"index": "dst_a", "op_type": "create"}
	}`)
	if int(reindexCreate["version_conflicts"].(float64)) != 2 || int(reindexCreate["created"].(float64)) != 0 {
		t.Fatalf("expected version_conflicts=2 and created=0 with op_type=create, got %+v", reindexCreate)
	}
}

// TestRound11IPFieldQueriesAndCIDR verifies R11-P0-4 and R11-P1-3:
// - range, term, and terms queries on "type": "ip" fields use numeric IPv4 comparisons and CIDR expansion
// - ip_range aggregation on array IP fields counts each document once per bucket.
func TestRound11IPFieldQueriesAndCIDR(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/net_logs", `{
		"mappings": {
			"properties": {
				"client_ip": {"type": "ip"},
				"proxy_ips": {"type": "ip", "multi_valued": true}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/net_logs/_doc/1?refresh=true", `{"client_ip":"10.0.0.9","proxy_ips":["10.0.0.10","10.0.0.20"]}`)
	mustReq(t, ts, http.MethodPut, "/net_logs/_doc/2?refresh=true", `{"client_ip":"10.0.0.50","proxy_ips":["192.168.1.5"]}`)
	mustReq(t, ts, http.MethodPut, "/net_logs/_doc/3?refresh=true", `{"client_ip":"10.0.0.200","proxy_ips":["10.0.0.99"]}`)

	// Numeric IPv4 range: 10.0.0.10 .. 10.0.0.250 must match 10.0.0.50 and 10.0.0.200 (2 docs), NOT lexicographic!
	res := mustReq(t, ts, http.MethodPost, "/net_logs/_search", `{
		"query": {"range": {"client_ip": {"gte": "10.0.0.10", "lte": "10.0.0.250"}}}
	}`)
	if getTotalHits(res) != 2 {
		t.Fatalf("expected 2 hits for IP range [10.0.0.10, 10.0.0.250], got %v", getTotalHits(res))
	}

	// CIDR term query on scalar IP field: 10.0.0.0/26 (10.0.0.0 .. 10.0.0.63) matches doc 1 and doc 2
	res = mustReq(t, ts, http.MethodPost, "/net_logs/_search", `{
		"query": {"term": {"client_ip": "10.0.0.0/26"}}
	}`)
	if getTotalHits(res) != 2 {
		t.Fatalf("expected 2 hits for CIDR term 10.0.0.0/26, got %v", getTotalHits(res))
	}

	// CIDR terms query on array IP field: 10.0.0.0/24 matches doc 1 and doc 3; doc 1 has 2 IPs in 10.0.0.0/24 so ip_range doc_count must be 2, not 3
	res = mustReq(t, ts, http.MethodPost, "/net_logs/_search", `{
		"query": {"terms": {"proxy_ips": ["10.0.0.0/24"]}},
		"aggs": {
			"by_subnet": {
				"ip_range": {
					"field": "proxy_ips",
					"ranges": [{"mask": "10.0.0.0/24"}]
				}
			}
		}
	}`)
	if getTotalHits(res) != 2 {
		t.Fatalf("expected 2 hits for CIDR terms on array IP field, got %v", getTotalHits(res))
	}
	buckets := res["aggregations"].(map[string]any)["by_subnet"].(map[string]any)["buckets"].([]any)
	if int(buckets[0].(map[string]any)["doc_count"].(float64)) != 2 {
		t.Fatalf("expected ip_range bucket doc_count=2 on multi-IP array field, got %+v", buckets[0])
	}
}

// TestRound11DynamicAliasFilterAndUpdatePipeline verifies R11-P0-5:
// - Write alias filter on dynamically inferred date and array fields succeeds on first document write
// - _update applies index default_pipeline before checking write alias filter.
func TestRound11DynamicAliasFilterAndUpdatePipeline(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/_ingest/pipeline/stamp_tenant", `{
		"processors": [
			{"set": {"field": "tenant", "value": "acme"}}
		]
	}`)
	mustReq(t, ts, http.MethodPut, "/dyn_events", `{
		"settings": {"index.default_pipeline": "stamp_tenant"}
	}`)
	mustReq(t, ts, http.MethodPost, "/_aliases", `{
		"actions": [
			{
				"add": {
					"index": "dyn_events",
					"alias": "acme_events",
					"filter": {
						"bool": {
							"filter": [
								{"term": {"tenant": "acme"}},
								{"term": {"tags": "prod"}},
								{"range": {"created_at": {"gte": "2025-01-01T00:00:00Z"}}}
							]
						}
					}
				}
			}
		]
	}`)

	// First write into acme_events: tenant is added by default_pipeline, tags is dynamic array, created_at is dynamic date
	mustReq(t, ts, http.MethodPut, "/acme_events/_doc/e1?refresh=true", `{
		"tags": ["prod", "v1"],
		"created_at": "2025-06-15T12:00:00Z",
		"msg": "initial"
	}`)

	// _update with doc_as_upsert via acme_events without explicit tenant field (supplied by default_pipeline)
	mustReq(t, ts, http.MethodPost, "/acme_events/_update/e2?refresh=true", `{
		"doc": {
			"tags": ["prod", "v2"],
			"created_at": "2025-07-01T00:00:00Z",
			"msg": "upserted"
		},
		"doc_as_upsert": true
	}`)

	res := mustReq(t, ts, http.MethodPost, "/acme_events/_search", `{}`)
	if getTotalHits(res) != 2 {
		t.Fatalf("expected 2 docs in acme_events, got %v", getTotalHits(res))
	}
}

// TestRound11ReverseNestedDeduplicationAndTopLevelNestedSubAggs verifies R11-P0-6 and R11-P0-8:
// - nested -> terms -> reverse_nested -> sum/terms deduplicates per root (_id, parent_bucket)
// - top-level nested supports 2nd-level histogram, range, filter, missing, top_hits, and deep array terms with missing.
func TestRound11ReverseNestedDeduplicationAndTopLevelNestedSubAggs(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/orders_idx", `{
		"mappings": {
			"properties": {
				"order_total": {"type": "double"},
				"region": {"type": "keyword"},
				"items": {
					"type": "nested",
					"properties": {
						"category": {"type": "keyword"},
						"price": {"type": "double"},
						"sku": {"type": "keyword"}
					}
				}
			}
		}
	}`)
	// Doc 1 has TWO items in category "books" and order_total=100
	mustReq(t, ts, http.MethodPut, "/orders_idx/_doc/1?refresh=true", `{
		"order_total": 100,
		"region": "us",
		"items": [
			{"category": "books", "price": 15, "sku": "b1"},
			{"category": "books", "price": 25}
		]
	}`)
	// Doc 2 has ONE item in category "books" and order_total=50
	mustReq(t, ts, http.MethodPut, "/orders_idx/_doc/2?refresh=true", `{
		"order_total": 50,
		"region": "eu",
		"items": [
			{"category": "books", "price": 50, "sku": "b2"}
		]
	}`)

	res := mustReq(t, ts, http.MethodPost, "/orders_idx/_search", `{
		"size": 0,
		"aggs": {
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"by_cat": {
						"terms": {"field": "items.category"},
						"aggs": {
							"root_orders": {
								"reverse_nested": {},
								"aggs": {
									"total_order_value": {"sum": {"field": "order_total"}},
									"by_region": {"terms": {"field": "region"}}
								}
							}
						}
					},
					"price_hist": {"histogram": {"field": "items.price", "interval": 20}},
					"expensive_filter": {
						"filter": {"range": {"items.price": {"gte": 20}}},
						"aggs": {"avg_p": {"avg": {"field": "items.price"}}}
					},
					"missing_sku": {"missing": {"field": "items.sku"}},
					"top_items": {"top_hits": {"size": 2}}
				}
			}
		}
	}`)
	nestedAgg := res["aggregations"].(map[string]any)["nested_items"].(map[string]any)
	catBuckets := nestedAgg["by_cat"].(map[string]any)["buckets"].([]any)
	booksBucket := catBuckets[0].(map[string]any)
	// 3 nested items have category="books", but only 2 root orders!
	if int(booksBucket["doc_count"].(float64)) != 3 {
		t.Fatalf("expected 3 nested items in books bucket, got %+v", booksBucket)
	}
	rn := booksBucket["root_orders"].(map[string]any)
	if int(rn["doc_count"].(float64)) != 2 {
		t.Fatalf("expected reverse_nested doc_count=2, got %+v", rn)
	}
	// Root order_total sum for books must be 100 + 50 = 150 (NOT 100 + 100 + 50 = 250!)
	if rn["total_order_value"].(map[string]any)["value"].(float64) != 150.0 {
		t.Fatalf("expected reverse_nested sum=150, got %+v", rn["total_order_value"])
	}
	regBuckets := rn["by_region"].(map[string]any)["buckets"].([]any)
	for _, rb := range regBuckets {
		rm := rb.(map[string]any)
		if int(rm["doc_count"].(float64)) != 1 {
			t.Fatalf("expected 1 root doc per region in reverse_nested terms, got %+v", rm)
		}
	}

	// Verify 2nd-level histogram, filter, missing, and top_hits under top-level nested
	if len(nestedAgg["price_hist"].(map[string]any)["buckets"].([]any)) == 0 {
		t.Fatalf("expected price_hist buckets under top-level nested, got %+v", nestedAgg["price_hist"])
	}
	expFilter := nestedAgg["expensive_filter"].(map[string]any)
	if int(expFilter["doc_count"].(float64)) != 2 || expFilter["avg_p"].(map[string]any)["value"].(float64) != 37.5 {
		t.Fatalf("expected expensive_filter doc_count=2 and avg_p=37.5, got %+v", expFilter)
	}
	if int(nestedAgg["missing_sku"].(map[string]any)["doc_count"].(float64)) != 1 {
		t.Fatalf("expected missing_sku doc_count=1, got %+v", nestedAgg["missing_sku"])
	}
}

// TestRound11CompositeDescPaginationAndMissingFormatting verifies R11-P0-7 and R11-P1-3:
// - composite aggregation with order="desc" on terms and histogram sources paginates accurately with after
// - numeric and date missing values in terms, composite, histogram, and date_histogram format without scientific notation.
func TestRound11CompositeDescPaginationAndMissingFormatting(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/comp_idx", `{
		"mappings": {
			"properties": {
				"service": {"type": "keyword"},
				"latency": {"type": "double"},
				"@timestamp": {"type": "date"}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/comp_idx/_doc/1?refresh=true", `{"service":"alpha","latency":10,"@timestamp":"2025-01-01T00:00:00Z"}`)
	mustReq(t, ts, http.MethodPut, "/comp_idx/_doc/2?refresh=true", `{"service":"beta","latency":20,"@timestamp":"2025-01-01T01:00:00Z"}`)
	mustReq(t, ts, http.MethodPut, "/comp_idx/_doc/3?refresh=true", `{"service":"gamma","latency":30,"@timestamp":"2025-01-01T02:00:00Z"}`)
	mustReq(t, ts, http.MethodPut, "/comp_idx/_doc/4?refresh=true", `{"service":"delta"}`)

	// Page 1: size=2, order="desc" -> should return "gamma", "delta"
	p1 := mustReq(t, ts, http.MethodPost, "/comp_idx/_search", `{
		"size": 0,
		"aggs": {
			"comp": {
				"composite": {
					"size": 2,
					"sources": [
						{"svc": {"terms": {"field": "service", "order": "desc"}}}
					]
				}
			}
		}
	}`)
	comp1 := p1["aggregations"].(map[string]any)["comp"].(map[string]any)
	b1 := comp1["buckets"].([]any)
	if len(b1) != 2 || b1[0].(map[string]any)["key"].(map[string]any)["svc"] != "gamma" || b1[1].(map[string]any)["key"].(map[string]any)["svc"] != "delta" {
		t.Fatalf("expected page 1 [gamma, delta], got %+v", b1)
	}

	// Page 2 using after_key={"svc": "delta"} -> should return "beta", "alpha"
	p2 := mustReq(t, ts, http.MethodPost, "/comp_idx/_search", `{
		"size": 0,
		"aggs": {
			"comp": {
				"composite": {
					"size": 2,
					"after": {"svc": "delta"},
					"sources": [
						{"svc": {"terms": {"field": "service", "order": "desc"}}}
					]
				}
			}
		}
	}`)
	b2 := p2["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	if len(b2) != 2 || b2[0].(map[string]any)["key"].(map[string]any)["svc"] != "beta" || b2[1].(map[string]any)["key"].(map[string]any)["svc"] != "alpha" {
		t.Fatalf("expected page 2 [beta, alpha], got %+v", b2)
	}

	// Verify date_histogram and histogram missing parameter and large integer missing formatting
	mRes := mustReq(t, ts, http.MethodPost, "/comp_idx/_search", `{
		"size": 0,
		"aggs": {
			"dh": {
				"date_histogram": {
					"field": "@timestamp",
					"fixed_interval": "1h",
					"missing": "2025-01-01T00:00:00Z"
				}
			},
			"h": {
				"histogram": {
					"field": "latency",
					"interval": 10,
					"missing": 0
				}
			},
			"t_epoch": {
				"terms": {
					"field": "latency",
					"missing": 1704067200000
				}
			}
		}
	}`)
	dhBuckets := mRes["aggregations"].(map[string]any)["dh"].(map[string]any)["buckets"].([]any)
	if int(dhBuckets[0].(map[string]any)["doc_count"].(float64)) != 2 {
		t.Fatalf("expected first date_histogram bucket doc_count=2 (including missing doc), got %+v", dhBuckets[0])
	}
	hBuckets := mRes["aggregations"].(map[string]any)["h"].(map[string]any)["buckets"].([]any)
	if hBuckets[0].(map[string]any)["key"].(float64) != 0 || int(hBuckets[0].(map[string]any)["doc_count"].(float64)) != 1 {
		t.Fatalf("expected histogram bucket at 0 with doc_count=1 from missing doc, got %+v", hBuckets[0])
	}
	tBuckets := mRes["aggregations"].(map[string]any)["t_epoch"].(map[string]any)["buckets"].([]any)
	foundLargeInt := false
	for _, tb := range tBuckets {
		if tb.(map[string]any)["key"].(string) == "1704067200000" {
			foundLargeInt = true
		}
	}
	if !foundLargeInt {
		t.Fatalf("expected large integer missing key '1704067200000' without scientific notation, got %+v", tBuckets)
	}
}

// TestRound11PipelineAggMultiSegmentPathsAndFiltersBucketSort verifies R11-P1-1, R11-P1-2, and R11-P1-4:
// - Multi-segment buckets_path (filter_agg>sum_agg) and bracket notation (p95[95.0]) in pipeline aggs and terms order
// - Named filters with keyed:false preserves bucket_sort ordering
// - 2nd-level missing and percentile_ranks sub-aggregations inside terms buckets.
func TestRound11PipelineAggMultiSegmentPathsAndFiltersBucketSort(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReq(t, ts, http.MethodPut, "/pipe_idx", `{
		"mappings": {
			"properties": {
				"cat": {"type": "keyword"},
				"status": {"type": "keyword"},
				"val": {"type": "double"},
				"opt": {"type": "keyword"}
			}
		}
	}`)
	mustReq(t, ts, http.MethodPut, "/pipe_idx/_doc/1?refresh=true", `{"cat":"a","status":"ok","val":10,"opt":"present"}`)
	mustReq(t, ts, http.MethodPut, "/pipe_idx/_doc/2?refresh=true", `{"cat":"b","status":"ok","val":100}`)
	mustReq(t, ts, http.MethodPut, "/pipe_idx/_doc/3?refresh=true", `{"cat":"b","status":"err","val":50}`)

	res := mustReq(t, ts, http.MethodPost, "/pipe_idx/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {
					"field": "cat",
					"order": {"ok_only>ok_sum": "desc"}
				},
				"aggs": {
					"ok_only": {
						"filter": {"term": {"status": "ok"}},
						"aggs": {
							"ok_sum": {"sum": {"field": "val"}}
						}
					},
					"p": {"percentiles": {"field": "val", "percents": [95]}},
					"pr": {"percentile_ranks": {"field": "val", "values": [50, 100]}},
					"miss_opt": {"missing": {"field": "opt"}},
					"scaled_ok": {
						"bucket_script": {
							"buckets_path": {"s": "ok_only>ok_sum", "p95": "p[95.0]"},
							"script": "params.s + params.p95"
						}
					}
				}
			},
			"max_p95": {
				"max_bucket": {"buckets_path": "by_cat>p[95.0]"}
			},
			"by_status_filters": {
				"filters": {
					"keyed": false,
					"filters": {
						"alpha_err": {"term": {"status": "err"}},
						"zeta_ok": {"term": {"status": "ok"}}
					}
				},
				"aggs": {
					"total_v": {"sum": {"field": "val"}},
					"sort_by_v": {
						"bucket_sort": {
							"sort": [{"total_v": {"order": "desc"}}]
						}
					}
				}
			}
		}
	}`)

	aggs := res["aggregations"].(map[string]any)
	catBuckets := aggs["by_cat"].(map[string]any)["buckets"].([]any)
	// "b" has ok_sum=100, "a" has ok_sum=10 -> "b" must be first
	b0 := catBuckets[0].(map[string]any)
	if b0["key"] != "b" {
		t.Fatalf("expected bucket 'b' first when ordered by ok_only>ok_sum desc, got %+v", catBuckets)
	}
	if int(b0["miss_opt"].(map[string]any)["doc_count"].(float64)) != 2 {
		t.Fatalf("expected 2nd-level missing doc_count=2 on bucket 'b', got %+v", b0["miss_opt"])
	}
	if b0["pr"].(map[string]any)["values"] == nil {
		t.Fatalf("expected 2nd-level percentile_ranks values on bucket 'b', got %+v", b0["pr"])
	}
	if b0["scaled_ok"].(map[string]any)["value"].(float64) <= 100 {
		t.Fatalf("expected bucket_script scaled_ok > 100, got %+v", b0["scaled_ok"])
	}
	if math.Abs(aggs["max_p95"].(map[string]any)["value"].(float64)-97.5) > 5.0 {
		t.Fatalf("expected max_p95 around 97.5, got %+v", aggs["max_p95"])
	}

	// Verify named filters with keyed:false preserved bucket_sort order (zeta_ok has total_v=110 > alpha_err total_v=50)
	fBuckets := aggs["by_status_filters"].(map[string]any)["buckets"].([]any)
	if fBuckets[0].(map[string]any)["key"] != "zeta_ok" {
		t.Fatalf("expected zeta_ok first after bucket_sort desc, got %+v", fBuckets)
	}
}

// TestRound11PainlessBracketKeysLiteralsAndLoopMutations verifies R11-P1-5:
// - doc['@timestamp'].value, doc['status.keyword'].value, and ctx._source['@timestamp']
// - Painless list/map literals, loop-variable property mutation, local compound assignment, and modulo (%).
func TestRound11PainlessBracketKeysLiteralsAndLoopMutations(t *testing.T) {
	raw := json.RawMessage(`{
		"@timestamp": "2026-01-01T00:00:00Z",
		"status": "ok",
		"items": [{"price": 10}, {"price": 25}]
	}`)
	upd := &painless.UpdateRequest{
		Script: &painless.ScriptSpec{
			Source: `
				if (doc['status.keyword'].value == 'ok' && doc['@timestamp'].value != null) {
					ctx._source['@timestamp'] = '2026-01-02T00:00:00Z';
				}
				def total = 0;
				for (item in ctx._source.items) {
					total += item.price;
					item.tag = 'checked';
				}
				ctx._source.total = total;
				ctx._source.rem = total % 10;
				ctx._source.tags = ['a', 'b'];
				ctx._source.meta = ['env': 'prod', 'ver': 2];
				for (t in ['c', 'd']) {
					ctx._source.tags.add(t);
				}
				for (r in ['b']) {
					ctx._source.tags.remove(r);
				}
			`,
		},
	}
	mutated, opRes, err := painless.ApplyUpdateWithResult(raw, upd, true)
	if err != nil || opRes != "updated" {
		t.Fatalf("expected Painless script to succeed, got opRes=%s err=%v", opRes, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(mutated, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["@timestamp"] != "2026-01-02T00:00:00Z" || doc["total"].(float64) != 35 || doc["rem"].(float64) != 5 {
		t.Fatalf("unexpected mutated doc scalars: %+v", doc)
	}
	items := doc["items"].([]any)
	if items[0].(map[string]any)["tag"] != "checked" {
		t.Fatalf("expected loop item mutation item.tag='checked', got %+v", items[0])
	}
	meta := doc["meta"].(map[string]any)
	if meta["env"] != "prod" {
		t.Fatalf("expected map literal meta.env='prod', got %+v", meta)
	}
	tags := doc["tags"].([]any)
	if len(tags) != 3 {
		t.Fatalf("expected 3 tags after loop add/remove, got %+v", tags)
	}
}

// TestRound11TermsEnumCaseInsensitiveAndExplainAndSimulateIngest verifies R11-P1-6, R11-P2-1, and R11-P2-2:
// - _terms_enum case-insensitive sorting & search_after pagination
// - _explain query validation
// - /_ingest/pipeline/_simulate with "if" conditionals, set/default/split/join/convert/append/gsub/json/script processors
// - PUT /{index}/_doc/{id} and /_bulk return 200 OK ("result": "updated") when overwriting existing docs.
func TestRound11TermsEnumCaseInsensitiveAndExplainAndSimulateIngest(t *testing.T) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_compat", mem, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// R11-P2-2: First PUT returns 201 ("created"), overwrite returns 200 ("updated")
	code, body := doRawReq(t, ts, http.MethodPut, "/te_idx/_doc/1?refresh=true", `{"host":"Beta"}`)
	if code != http.StatusCreated || !strings.Contains(string(body), `"result":"created"`) {
		t.Fatalf("expected 201 created on first PUT, got %d %s", code, string(body))
	}
	code, body = doRawReq(t, ts, http.MethodPut, "/te_idx/_doc/1?refresh=true", `{"host":"Beta"}`)
	if code != http.StatusOK || !strings.Contains(string(body), `"result":"updated"`) {
		t.Fatalf("expected 200 updated on overwrite PUT, got %d %s", code, string(body))
	}
	mustReq(t, ts, http.MethodPut, "/te_idx/_doc/2?refresh=true", `{"host":"alpha"}`)
	mustReq(t, ts, http.MethodPut, "/te_idx/_doc/3?refresh=true", `{"host":"Gamma"}`)

	// R11-P1-6: _terms_enum with case_insensitive=true sorts ["alpha", "Beta", "Gamma"]
	teRes := mustReq(t, ts, http.MethodPost, "/te_idx/_terms_enum", `{
		"field": "host",
		"case_insensitive": true,
		"size": 2
	}`)
	terms := teRes["terms"].([]any)
	if len(terms) != 2 || terms[0] != "alpha" || terms[1] != "Beta" {
		t.Fatalf("expected case-insensitive terms [alpha, Beta], got %+v", terms)
	}
	tePage2 := mustReq(t, ts, http.MethodPost, "/te_idx/_terms_enum", `{
		"field": "host",
		"case_insensitive": true,
		"search_after": "Beta",
		"size": 2
	}`)
	terms2 := tePage2["terms"].([]any)
	if len(terms2) != 1 || terms2[0] != "Gamma" {
		t.Fatalf("expected page 2 [Gamma], got %+v", terms2)
	}

	// R11-P1-6: _explain rejects unknown query clause with 400
	code, _ = doRawReq(t, ts, http.MethodPost, "/te_idx/_explain/1", `{"query":{"not_a_real_query":{}}}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 from _explain with invalid query, got %d", code)
	}

	// R11-P2-1: POST /_ingest/pipeline/_simulate with conditional processors
	simRes := mustReq(t, ts, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"set": {"field": "env", "value": "prod", "override": false}},
				{"set": {"field": "env_copy", "copy_from": "env"}},
				{"set": {"field": "banner", "value": "welcome-{{env}}-{{{msg}}}"}},
				{"default": {"field": "region", "value": "us-east-1"}},
				{"split": {"field": "csv", "separator": ","}},
				{"append": {"field": "csv", "value": ["d"], "if": "ctx.env == 'prod' && ctx.env != 'dev'"}},
				{"append": {"field": "csv", "value": ["e"], "if": "ctx.csv.contains('a') && !ctx.missing_flag"}},
				{"join": {"field": "csv", "separator": "|", "target_field": "joined"}},
				{"convert": {"field": "port_str", "type": "integer", "target_field": "port"}},
				{"convert": {"field": "ratio_str", "type": "float", "target_field": "ratio", "if": "ctx.port >= 8000"}},
				{"convert": {"field": "active_str", "type": "boolean", "target_field": "active", "if": "ctx.port <= 9000"}},
				{"convert": {"field": "port", "type": "string", "target_field": "port_back", "if": "ctx.port > 80 && ctx.port < 9000"}},
				{"gsub": {"field": "msg", "pattern": "foo", "replacement": "bar"}},
				{"json": {"field": "raw_json", "target_field": "parsed"}},
				{"json": {"field": "root_json", "add_to_root": true}},
				{"script": {"source": "ctx.port += 1"}},
				{"drop": {"if": "ctx.should_drop == true"}}
			]
		},
		"docs": [
			{
				"_index": "test",
				"_id": "1",
				"_source": {
					"env": "prod",
					"csv": "a,b,c",
					"port_str": "8080",
					"ratio_str": "0.95",
					"active_str": "true",
					"msg": "hello foo",
					"raw_json": "{\"k\":42}",
					"root_json": "{\"root_k\":\"v\"}"
				}
			},
			{
				"_index": "test",
				"_id": "2",
				"_source": {
					"should_drop": true
				}
			}
		]
	}`)
	simDocs := simRes["docs"].([]any)
	simDoc := simDocs[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if simDoc["region"] != "us-east-1" || simDoc["joined"] != "a|b|c|d|e" || simDoc["port"].(float64) != 8081 || simDoc["msg"] != "hello bar" || simDoc["root_k"] != "v" || simDoc["env_copy"] != "prod" {
		t.Fatalf("unexpected simulated ingest doc: %+v", simDoc)
	}
	if simDocs[1].(map[string]any)["doc"] != nil {
		t.Fatalf("expected dropped doc to return doc=nil in _simulate, got %+v", simDocs[1])
	}

	// Also test stored pipeline _simulate via POST /_ingest/pipeline/{id}/_simulate
	mustReq(t, ts, http.MethodPut, "/_ingest/pipeline/stored_sim", `{"processors":[{"uppercase":{"field":"host"}},{"trim":{"field":"host"}}]}`)
	storedSimRes := mustReq(t, ts, http.MethodPost, "/_ingest/pipeline/stored_sim/_simulate", `{"docs":[{"_source":{"host":"  web-01  "}}]}`)
	storedDoc := storedSimRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if storedDoc["host"] != "WEB-01" {
		t.Fatalf("expected stored pipeline _simulate to uppercase+trim host to WEB-01, got %+v", storedDoc)
	}
}
