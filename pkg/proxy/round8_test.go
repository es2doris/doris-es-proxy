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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func mustReqJSON(t *testing.T, ts *httptest.Server, method, path string, payload any) map[string]any {
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
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s returned HTTP %d: %s", method, path, resp.StatusCode, string(rawResp))
	}
	var out map[string]any
	if len(bytes.TrimSpace(rawResp)) > 0 {
		if err := json.Unmarshal(rawResp, &out); err != nil {
			t.Fatalf("%s %s invalid JSON (%v): %s", method, path, err, string(rawResp))
		}
	}
	return out
}

func TestRound8_RewriteDorisArrayExistsOuterQuotesAndEscapedQuotes(t *testing.T) {
	// R8-P0-1: Verify outer SQL string literal containing "array_exists(" is not corrupted,
	// and doubled single quotes ('') inside array_exists(...) lambda do not desynchronize quote tracking.
	q1 := "SELECT * FROM `es_compat`.`logs` WHERE `f__msg` = 'error in array_exists(a, b) call' AND array_exists(_x -> _x = 'it''s, ok', `f__tags`)"
	norm := NormalizeDorisSQL(q1)
	if !strings.Contains(norm, "`f__msg` = 'error in array_exists(a, b) call'") {
		t.Fatalf("outer string literal was corrupted: %s", norm)
	}
	if !strings.Contains(norm, "array_contains(array_exists(_x -> _x = 'it''s, ok', IFNULL(`f__tags`, CAST([] AS ARRAY<STRING>))), true)") {
		t.Fatalf("expected clean rewrite of array_exists with doubled single quotes, got: %s", norm)
	}
}

func TestRound8_CoalescerDetachedContextAndZeroWindowFlush(t *testing.T) {
	// R8-P0-2: Verify FlushTable and FlushAll detach from caller cancellation and do not return early when window == 0.
	var flushes int32
	c := newStreamLoadCoalescer(func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		atomic.AddInt32(&flushes, 1)
		return nil
	})
	c.Configure(100*time.Millisecond, 64*1024)

	// Disable window while item is pending in buffer, and call FlushTable with an already-canceled context.
	c.mu.Lock()
	c.batches["tbl_r8"] = &coalesceBatch{
		done: make(chan struct{}),
	}
	c.batches["tbl_r8"].buf.WriteString(`{"_id":"1"}` + "\n")
	c.window = 0
	c.mu.Unlock()

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := c.FlushTable(canceledCtx, "tbl_r8"); err != nil {
		t.Fatalf("expected FlushTable with canceled context and window=0 to succeed, got: %v", err)
	}
	if atomic.LoadInt32(&flushes) != 1 {
		t.Fatalf("expected 1 flush, got %d", atomic.LoadInt32(&flushes))
	}

	c.mu.Lock()
	c.batches["tbl_r8_all"] = &coalesceBatch{
		done: make(chan struct{}),
	}
	c.batches["tbl_r8_all"].buf.WriteString(`{"_id":"2"}` + "\n")
	c.mu.Unlock()

	if err := c.FlushAll(canceledCtx); err != nil {
		t.Fatalf("expected FlushAll with canceled context to succeed, got: %v", err)
	}
	if atomic.LoadInt32(&flushes) != 2 {
		t.Fatalf("expected 2 flushes, got %d", atomic.LoadInt32(&flushes))
	}
}

func TestRound8_ScrollPitOrderByTiebreakerAndDeleteScrollArray(t *testing.T) {
	// R8-P0-3: Verify handleScroll preserves sort/pit and guarantees _id tiebreaker,
	// and DELETE /_search/scroll accepts scroll_id as a JSON array.
	srv := NewServer("es_compat", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/r8_scroll", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"seq": map[string]any{"type": "integer"},
			},
		},
	})
	for i, id := range []string{"doc-a", "doc-b", "doc-c"} {
		mustReqJSON(t, ts, http.MethodPut, "/r8_scroll/_doc/"+id+"?refresh=true", map[string]any{
			"seq": 10, // identical sort values to exercise _id tiebreaker
			"idx": i,
		})
	}

	page1 := mustReqJSON(t, ts, http.MethodPost, "/r8_scroll/_search?scroll=1m", map[string]any{
		"size": 1,
		"sort": []any{map[string]any{"seq": "asc"}},
	})
	scrollID, _ := page1["_scroll_id"].(string)
	if scrollID == "" {
		t.Fatalf("expected _scroll_id in initial search response: %v", page1)
	}

	page2 := mustReqJSON(t, ts, http.MethodPost, "/_search/scroll", map[string]any{
		"scroll":    "1m",
		"scroll_id": scrollID,
	})
	hits2 := page2["hits"].(map[string]any)["hits"].([]any)
	if len(hits2) != 1 || hits2[0].(map[string]any)["_id"] != "doc-b" {
		t.Fatalf("expected second scroll page to return doc-b via _id tiebreaker, got: %v", hits2)
	}
	scrollID2 := page2["_scroll_id"].(string)

	page3 := mustReqJSON(t, ts, http.MethodPost, "/_search/scroll", map[string]any{
		"scroll":    "1m",
		"scroll_id": []string{scrollID2},
	})
	hits3 := page3["hits"].(map[string]any)["hits"].([]any)
	if len(hits3) != 1 || hits3[0].(map[string]any)["_id"] != "doc-c" {
		t.Fatalf("expected third scroll page to return doc-c, got: %v", hits3)
	}

	delResp := mustReqJSON(t, ts, http.MethodDelete, "/_search/scroll", map[string]any{
		"scroll_id": []string{scrollID, scrollID2},
	})
	if delResp["succeeded"] != true || int(delResp["num_freed"].(float64)) != 2 {
		t.Fatalf("expected num_freed=2 on DELETE /_search/scroll array, got: %v", delResp)
	}
}

func TestRound8_FilteredAliasesIsWriteIndexAndTemplateFormats(t *testing.T) {
	// R8-P0-4 & R8-P1-5:
	// - Filtered aliases in PUT /{index}, POST /_aliases, PUT /{index}/_alias/{name}
	// - Query cache isolation between filtered alias and underlying index
	// - is_write_index routing and multi-target alias write rejection
	// - Legacy /_template map format and 404 on missing DELETE /_index_template/{name}
	srv := NewServer("es_compat", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Legacy /_template GET returns top-level map, and missing DELETE returns 404
	mustReqJSON(t, ts, http.MethodPut, "/_template/r8_legacy_tpl", map[string]any{
		"index_patterns": []string{"r8_tenant_*"},
		"mappings": map[string]any{
			"properties": map[string]any{
				"tenant": map[string]any{"type": "keyword"},
				"amount": map[string]any{"type": "integer"},
			},
		},
	})
	legacyGet := mustReqJSON(t, ts, http.MethodGet, "/_template/r8_legacy_tpl", nil)
	if _, ok := legacyGet["r8_legacy_tpl"].(map[string]any); !ok {
		t.Fatalf("expected top-level template key in GET /_template/r8_legacy_tpl, got: %v", legacyGet)
	}
	req404, _ := http.NewRequest(http.MethodDelete, ts.URL+"/_index_template/non_existent_tpl", nil)
	resp404, err := http.DefaultClient.Do(req404)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 on deleting non-existent template, got %d", resp404.StatusCode)
	}

	// 2. Create two indices and configure aliases with filter + is_write_index
	mustReqJSON(t, ts, http.MethodPut, "/r8_tenant_1", map[string]any{
		"aliases": map[string]any{
			"tenant_acme": map[string]any{
				"filter": map[string]any{
					"term": map[string]any{"tenant": "acme"},
				},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/r8_tenant_2", nil)
	mustReqJSON(t, ts, http.MethodPost, "/_aliases", map[string]any{
		"actions": []any{
			map[string]any{
				"add": map[string]any{
					"index":          "r8_tenant_1",
					"alias":          "r8_rollover_alias",
					"is_write_index": false,
				},
			},
			map[string]any{
				"add": map[string]any{
					"index":          "r8_tenant_2",
					"alias":          "r8_rollover_alias",
					"is_write_index": true,
				},
			},
			map[string]any{
				"add": map[string]any{
					"indices": []string{"r8_tenant_1", "r8_tenant_2"},
					"alias":   "r8_ambiguous_alias",
				},
			},
		},
	})

	// Writing to r8_rollover_alias must route to r8_tenant_2 (is_write_index=true)
	writeResp := mustReqJSON(t, ts, http.MethodPost, "/r8_rollover_alias/_doc?refresh=true", map[string]any{
		"tenant": "beta",
		"amount": 50,
	})
	if writeResp["_index"] != "r8_tenant_2" {
		t.Fatalf("expected write to route to is_write_index r8_tenant_2, got: %v", writeResp["_index"])
	}

	// Writing to r8_ambiguous_alias (multiple indices without is_write_index=true) must return 400
	ambigReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/r8_ambiguous_alias/_doc", strings.NewReader(`{"tenant":"acme"}`))
	ambigReq.Header.Set("Content-Type", "application/json")
	ambigResp, err := http.DefaultClient.Do(ambigReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = ambigResp.Body.Close()
	if ambigResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 when writing to multi-index alias without is_write_index, got %d", ambigResp.StatusCode)
	}

	// Index docs into r8_tenant_1 for acme and globex
	mustReqJSON(t, ts, http.MethodPut, "/r8_tenant_1/_doc/1?refresh=true", map[string]any{"tenant": "acme", "amount": 100})
	mustReqJSON(t, ts, http.MethodPut, "/r8_tenant_1/_doc/2?refresh=true", map[string]any{"tenant": "globex", "amount": 200})

	// Querying r8_tenant_1 directly returns 2 docs; querying tenant_acme filtered alias returns 1 doc (and must not collide in queryCache!)
	srv.SetQueryCacheTTL(30*time.Second, 512)
	directSearch := mustReqJSON(t, ts, http.MethodPost, "/r8_tenant_1/_search", map[string]any{"query": map[string]any{"match_all": map[string]any{}}})
	aliasSearch := mustReqJSON(t, ts, http.MethodPost, "/tenant_acme/_search", map[string]any{"query": map[string]any{"match_all": map[string]any{}}})
	directTotal := int(directSearch["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64))
	aliasTotal := int(aliasSearch["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64))
	if directTotal != 2 || aliasTotal != 1 {
		t.Fatalf("expected directTotal=2 and filtered aliasTotal=1, got direct=%d alias=%d", directTotal, aliasTotal)
	}

	// Update-by-query and delete-by-query on filtered alias must only affect matching alias docs
	ubqResp := mustReqJSON(t, ts, http.MethodPost, "/tenant_acme/_update_by_query?refresh=true", map[string]any{
		"script": map[string]any{"source": "ctx._source.amount = ctx._source.amount + 10"},
	})
	if int(ubqResp["updated"].(float64)) != 1 {
		t.Fatalf("expected filtered alias _update_by_query to update 1 doc, got: %v", ubqResp)
	}
	dbqResp := mustReqJSON(t, ts, http.MethodPost, "/tenant_acme/_delete_by_query?refresh=true", map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
	})
	if int(dbqResp["deleted"].(float64)) != 1 {
		t.Fatalf("expected filtered alias _delete_by_query to delete 1 doc, got: %v", dbqResp)
	}
	remaining := mustReqJSON(t, ts, http.MethodPost, "/r8_tenant_1/_search", map[string]any{})
	remHits := remaining["hits"].(map[string]any)["hits"].([]any)
	if len(remHits) != 1 || remHits[0].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected globex doc 2 to remain untouched after filtered alias delete_by_query, got: %v", remHits)
	}
}

func TestRound8_ExtendedMetricBucketAndPipelineAggregations(t *testing.T) {
	// R8-P0-5, R8-P0-6, R8-P0-10, R8-P1-2, R8-P1-3, R8-P2-4:
	// Verify extended_stats, string_stats, boxplot, percentile_ranks, top_metrics, rate,
	// global, reverse_nested, sampler, ip_range, anonymous filters + other_bucket, keyed buckets,
	// moving_avg, moving_fn, serial_diff, extended_stats_bucket, percentiles_bucket,
	// top_hits from/sort/total, and bucket_selector ternary/negation/invalid script handling.
	srv := NewServer("es_compat", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/r8_aggs", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"@timestamp": map[string]any{"type": "date"},
				"service":    map[string]any{"type": "keyword"},
				"latency":    map[string]any{"type": "double"},
				"client_ip":  map[string]any{"type": "ip"},
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

	docs := []map[string]any{
		{
			"@timestamp": "2026-10-27T01:00:00Z",
			"service":    "api",
			"latency":    10.0,
			"client_ip":  "10.0.0.12",
			"items":      []any{map[string]any{"sku": "A1", "price": 5.0}},
		},
		{
			"@timestamp": "2026-10-27T02:00:00Z",
			"service":    "api",
			"latency":    20.0,
			"client_ip":  "10.0.0.45",
			"items":      []any{map[string]any{"sku": "A1", "price": 15.0}},
		},
		{
			"@timestamp": "2026-10-27T03:00:00Z",
			"service":    "web",
			"latency":    30.0,
			"client_ip":  "192.168.1.10",
			"items":      []any{map[string]any{"sku": "B2", "price": 25.0}},
		},
		{
			"@timestamp": "2026-10-27T04:00:00Z",
			"service":    "worker",
			"latency":    40.0,
			"client_ip":  "192.168.1.99",
			"items":      []any{map[string]any{"sku": "C3", "price": 35.0}},
		},
	}
	for i, d := range docs {
		mustReqJSON(t, ts, http.MethodPut, "/r8_aggs/_doc/"+string(rune('1'+i))+"?refresh=true", d)
	}

	res := mustReqJSON(t, ts, http.MethodPost, "/r8_aggs/_search", map[string]any{
		"size":  0,
		"query": map[string]any{"terms": map[string]any{"service": []string{"api", "web"}}},
		"aggs": map[string]any{
			"all_docs": map[string]any{
				"global": map[string]any{},
				"aggs": map[string]any{
					"max_lat": map[string]any{"max": map[string]any{"field": "latency"}},
				},
			},
			"sampled": map[string]any{
				"sampler": map[string]any{"shard_size": 100},
				"aggs": map[string]any{
					"ext_lat": map[string]any{"extended_stats": map[string]any{"field": "latency", "sigma": 2.0}},
				},
			},
			"str_stats": map[string]any{
				"string_stats": map[string]any{"field": "service"},
			},
			"lat_box": map[string]any{
				"boxplot": map[string]any{"field": "latency"},
			},
			"lat_ranks": map[string]any{
				"percentile_ranks": map[string]any{
					"field":  "latency",
					"values": []float64{15.0, 25.0},
					"keyed":  false,
				},
			},
			"latest_metric": map[string]any{
				"top_metrics": map[string]any{
					"metrics": map[string]any{"field": "latency"},
					"sort":    []any{map[string]any{"@timestamp": "desc"}},
					"size":    2,
				},
			},
			"paged_top_hits": map[string]any{
				"top_hits": map[string]any{
					"from": 1,
					"size": 1,
					"sort": []any{map[string]any{"latency": "asc"}},
				},
			},
			"anon_filters": map[string]any{
				"filters": map[string]any{
					"other_bucket":     true,
					"other_bucket_key": "rest",
					"filters": []any{
						map[string]any{"term": map[string]any{"service": "api"}},
					},
				},
			},
			"ip_subnets": map[string]any{
				"ip_range": map[string]any{
					"field": "client_ip",
					"keyed": true,
					"ranges": []any{
						map[string]any{"mask": "10.0.0.0/24"},
						map[string]any{"from": "192.168.1.0", "to": "192.168.1.255", "key": "lan"},
					},
				},
			},
			"nested_items": map[string]any{
				"nested": map[string]any{"path": "items"},
				"aggs": map[string]any{
					"back_to_root": map[string]any{
						"reverse_nested": map[string]any{},
						"aggs": map[string]any{
							"avg_root_lat": map[string]any{"avg": map[string]any{"field": "latency"}},
						},
					},
				},
			},
			"by_hour": map[string]any{
				"date_histogram": map[string]any{
					"field":          "@timestamp",
					"fixed_interval": "1h",
				},
				"aggs": map[string]any{
					"sum_lat":   map[string]any{"sum": map[string]any{"field": "latency"}},
					"stats_lat": map[string]any{"stats": map[string]any{"field": "latency"}},
					"pct_lat":   map[string]any{"percentiles": map[string]any{"field": "latency", "percents": []float64{50, 95}}},
					"req_rate":  map[string]any{"rate": map[string]any{"field": "latency", "mode": "sum"}},
					"mov_avg":   map[string]any{"moving_avg": map[string]any{"buckets_path": "sum_lat", "window": 2}},
					"mov_max":   map[string]any{"moving_fn": map[string]any{"buckets_path": "sum_lat", "window": 2, "script": "MovingFunctions.max(values)"}},
					"mov_min":   map[string]any{"moving_fn": map[string]any{"buckets_path": "sum_lat", "window": 2, "script": "MovingFunctions.min(values)"}},
					"mov_sum":   map[string]any{"moving_fn": map[string]any{"buckets_path": "sum_lat", "window": 2, "script": "MovingFunctions.sum(values)"}},
					"mov_std":   map[string]any{"moving_fn": map[string]any{"buckets_path": "sum_lat", "window": 2, "script": "MovingFunctions.stdDev(values, MovingFunctions.unweightedAvg(values))"}},
					"mov_lwma":  map[string]any{"moving_avg": map[string]any{"buckets_path": "sum_lat", "window": 2, "model": "linear"}},
					"mov_ewma":  map[string]any{"moving_avg": map[string]any{"buckets_path": "sum_lat", "window": 2, "model": "ewma"}},
					"diff_1":    map[string]any{"serial_diff": map[string]any{"buckets_path": "sum_lat", "lag": 1}},
					"from_stats": map[string]any{
						"bucket_script": map[string]any{
							"buckets_path": map[string]any{
								"a": "stats_lat.avg",
								"p": "pct_lat.95.0",
							},
							"script": "params.a > 15 ? (params.p > 25 ? 200 : 100) : 50",
						},
					},
					"keep_positive": map[string]any{
						"bucket_selector": map[string]any{
							"buckets_path": map[string]any{"s": "sum_lat"},
							"script":       "!(params.s < 5) && (params.s >= 10 ? true : false)",
						},
					},
				},
			},
			"div_sampled": map[string]any{
				"diversified_sampler": map[string]any{"field": "service", "shard_size": 50},
				"aggs": map[string]any{
					"c": map[string]any{"value_count": map[string]any{"field": "latency"}},
				},
			},
			"ext_stats_over_hours": map[string]any{
				"extended_stats_bucket": map[string]any{"buckets_path": "by_hour>sum_lat"},
			},
			"pct_over_hours": map[string]any{
				"percentiles_bucket": map[string]any{
					"buckets_path": "by_hour>sum_lat",
					"percents":     []float64{50.0, 95.0},
				},
			},
			"pct_over_hours_arr": map[string]any{
				"percentiles_bucket": map[string]any{
					"buckets_path": "by_hour>sum_lat",
					"percents":     []float64{0.0, 50.0, 100.0},
					"keyed":        false,
				},
			},
		},
	})

	aggs := res["aggregations"].(map[string]any)

	// 1. global agg escapes top-level query filter (sees all 4 docs and max_lat=40)
	allDocs := aggs["all_docs"].(map[string]any)
	if int(allDocs["doc_count"].(float64)) != 4 || allDocs["max_lat"].(map[string]any)["value"].(float64) != 40.0 {
		t.Fatalf("expected global agg doc_count=4 max_lat=40, got: %v", allDocs)
	}

	// 2. extended_stats inside sampler
	extLat := aggs["sampled"].(map[string]any)["ext_lat"].(map[string]any)
	if extLat["std_deviation"] == nil || extLat["variance_sampling"] == nil || extLat["std_deviation_bounds"] == nil {
		t.Fatalf("expected extended_stats fields, got: %v", extLat)
	}

	// 3. string_stats, boxplot, percentile_ranks, top_metrics
	strStats := aggs["str_stats"].(map[string]any)
	if int(strStats["count"].(float64)) != 3 || int(strStats["min_length"].(float64)) != 3 {
		t.Fatalf("unexpected string_stats: %v", strStats)
	}
	box := aggs["lat_box"].(map[string]any)
	if box["min"].(float64) != 10.0 || box["max"].(float64) != 30.0 || box["q2"].(float64) != 20.0 {
		t.Fatalf("unexpected boxplot: %v", box)
	}
	ranks := aggs["lat_ranks"].(map[string]any)["values"].([]any)
	if len(ranks) != 2 {
		t.Fatalf("expected 2 non-keyed percentile_ranks entries, got: %v", ranks)
	}
	topM := aggs["latest_metric"].(map[string]any)["top"].([]any)
	if len(topM) != 2 || topM[0].(map[string]any)["metrics"].(map[string]any)["latency"].(float64) != 30.0 {
		t.Fatalf("expected top_metrics latest latency=30.0, got: %v", topM)
	}

	// 4. top_hits with from=1, size=1, sort, and total=3
	thHitsObj := aggs["paged_top_hits"].(map[string]any)["hits"].(map[string]any)
	if int(thHitsObj["total"].(map[string]any)["value"].(float64)) != 3 {
		t.Fatalf("expected top_hits total.value=3 (matching bucket doc_count), got: %v", thHitsObj["total"])
	}
	thList := thHitsObj["hits"].([]any)
	if len(thList) != 1 || thList[0].(map[string]any)["_id"] != "2" || thList[0].(map[string]any)["sort"] == nil {
		t.Fatalf("expected paged top_hits from=1 to return doc 2 with sort values, got: %v", thList)
	}

	// 5. anonymous filters with other_bucket
	anonBuckets := aggs["anon_filters"].(map[string]any)["buckets"].([]any)
	if len(anonBuckets) != 2 || int(anonBuckets[0].(map[string]any)["doc_count"].(float64)) != 2 || int(anonBuckets[1].(map[string]any)["doc_count"].(float64)) != 1 {
		t.Fatalf("expected anonymous filters buckets [2, 1], got: %v", anonBuckets)
	}

	// 6. ip_range keyed buckets with CIDR mask
	ipBuckets := aggs["ip_subnets"].(map[string]any)["buckets"].(map[string]any)
	b10 := ipBuckets["10.0.0.0/24"].(map[string]any)
	if int(b10["doc_count"].(float64)) != 2 || b10["from"] != "10.0.0.0" || b10["to"] != "10.0.0.255" {
		t.Fatalf("unexpected ip_range 10.0.0.0/24 bucket: %v", b10)
	}

	// 7. by_hour moving_avg, serial_diff, nested ternary bucket_script over stats.avg & percentiles
	hourBuckets := aggs["by_hour"].(map[string]any)["buckets"].([]any)
	if len(hourBuckets) != 3 {
		t.Fatalf("expected 3 hour buckets, got: %v", hourBuckets)
	}
	hb2 := hourBuckets[1].(map[string]any)
	if hb2["mov_avg"].(map[string]any)["value"].(float64) != 15.0 || hb2["diff_1"].(map[string]any)["value"].(float64) != 10.0 {
		t.Fatalf("unexpected moving_avg or serial_diff in bucket 1: %v", hb2)
	}
	if hb2["from_stats"].(map[string]any)["value"].(float64) != 100.0 {
		t.Fatalf("expected nested ternary bucket_script value=100.0 in bucket 1, got: %v", hb2["from_stats"])
	}

	// 8. extended_stats_bucket & percentiles_bucket
	extOver := aggs["ext_stats_over_hours"].(map[string]any)
	if int(extOver["count"].(float64)) != 3 || extOver["sum"].(float64) != 60.0 {
		t.Fatalf("unexpected extended_stats_bucket: %v", extOver)
	}
	pctOver := aggs["pct_over_hours"].(map[string]any)["values"].(map[string]any)
	if pctOver["50.0"].(float64) != 20.0 {
		t.Fatalf("unexpected percentiles_bucket 50.0: %v", pctOver)
	}
}

func TestRound8_DateMathRoundingAndEmptyHistogramHardBounds(t *testing.T) {
	// R8-P0-7 & R8-P2-1:
	// 1. ParseESDateBoundToEpochMillis rounds date-only strings with day/month offsets to 23:59:59.999 when roundUp=true,
	//    and intermediate /d before +1h is floored rather than rounded to end-of-day.
	now := time.Date(2026, 10, 27, 14, 30, 0, 0, time.UTC)
	msEndDay, ok := schema.ParseESDateBoundToEpochMillis("2026-10-01||+1d", now, true)
	if !ok {
		t.Fatal("expected ParseESDateBoundToEpochMillis to parse 2026-10-01||+1d")
	}
	gotEnd := time.UnixMilli(msEndDay).UTC()
	if gotEnd.Day() != 2 || gotEnd.Hour() != 23 || gotEnd.Minute() != 59 || gotEnd.Second() != 59 || gotEnd.Nanosecond()/1e6 != 999 {
		t.Fatalf("expected 2026-10-02T23:59:59.999Z for roundUp on 2026-10-01||+1d, got: %s", gotEnd.Format(time.RFC3339Nano))
	}

	msMidFloor, ok := schema.ParseESDateBoundToEpochMillis("2026-10-01T12:30:00Z||/d+1h", now, true)
	if !ok {
		t.Fatal("expected ParseESDateBoundToEpochMillis to parse 2026-10-01T12:30:00Z||/d+1h")
	}
	gotMid := time.UnixMilli(msMidFloor).UTC()
	if gotMid.Day() != 1 || gotMid.Hour() != 1 || gotMid.Minute() != 0 || gotMid.Second() != 0 {
		t.Fatalf("expected intermediate /d before +1h to floor to 00:00:00 + 1h = 01:00:00, got: %s", gotMid.Format(time.RFC3339Nano))
	}

	// 2. Empty result set with min_doc_count: 0 and hard_bounds synthesizes zero-count buckets
	zero := 0
	dhRows := synthesizeDateHistogramBuckets(nil, &esast.DateHistogramAggSpec{
		Field:         "@timestamp",
		FixedInterval: "1d",
		MinDocCount:   &zero,
		HardBounds: &esast.HistogramBoundsSpec{
			Min: "2026-10-01T00:00:00Z",
			Max: "2026-10-03T00:00:00Z",
		},
	})
	if len(dhRows) != 3 {
		t.Fatalf("expected 3 synthesized date_histogram buckets from hard_bounds on empty result set, got %d", len(dhRows))
	}

	hRows := synthesizeHistogramBuckets(nil, &esast.HistogramAggSpec{
		Field:       "latency",
		Interval:    10,
		MinDocCount: &zero,
		HardBounds: &esast.HistogramBoundsSpec{
			Min: 0,
			Max: 20,
		},
	})
	if len(hRows) != 3 {
		t.Fatalf("expected 3 synthesized histogram buckets from hard_bounds on empty result set, got %d", len(hRows))
	}
}

func TestRound8_PainlessStringsRegexTernaryElvisAndNullSafe(t *testing.T) {
	// R8-P0-9: Verify Painless string methods (.contains, .startsWith, .endsWith, .toLowerCase, .toUpperCase, .trim, .length, .isEmpty),
	// regex operators (=~, ==~), Elvis (?:), ternary (? :), and null-safe navigation (?.).
	rawDoc := json.RawMessage(`{"msg":"  ERR-500: Database Timeout  ","tags":["prod","critical"],"meta":null}`)
	upd := &painless.UpdateRequest{
		Script: &painless.ScriptSpec{
			Source: `
				if (ctx._source.msg.trim().startsWith("ERR-") && ctx._source.msg.contains("Timeout") && ctx._source.msg.trim() =~ "ERR-[0-9]+") {
					ctx._source.norm = ctx._source.msg.trim().toLowerCase();
					ctx._source.code = ctx._source.tags.size() > 1 ? "multi" : "single";
					ctx._source.fallback = ctx._source.missing_field ?: "default_val";
					ctx._source.safe_null = ctx._source.meta?.nested?.field ?: "none";
					ctx._source.msg_len = ctx._source.norm.length();
				}
			`,
		},
	}
	mutated, opRes, err := painless.ApplyUpdateWithResult(rawDoc, upd, true)
	if err != nil || opRes != "updated" {
		t.Fatalf("expected Painless script to update doc, got opRes=%s err=%v", opRes, err)
	}
	var out map[string]any
	_ = json.Unmarshal(mutated, &out)
	if out["norm"] != "err-500: database timeout" || out["code"] != "multi" || out["fallback"] != "default_val" || out["safe_null"] != "none" {
		t.Fatalf("unexpected Painless evaluation result: %v", out)
	}
	if int(out["msg_len"].(float64)) != len("err-500: database timeout") {
		t.Fatalf("expected msg_len=%d, got %v", len("err-500: database timeout"), out["msg_len"])
	}
}

func TestRound8_DefaultPipelinePrecedenceAndBulkPipeline(t *testing.T) {
	// R8-P1-4: Verify index.default_pipeline, index.final_pipeline, and per-item Bulk action pipeline.
	srv := NewServer("es_compat", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/_ingest/pipeline/default_pipe", map[string]any{
		"processors": []any{
			map[string]any{"set": map[string]any{"field": "env", "value": "default_env"}},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/_ingest/pipeline/custom_pipe", map[string]any{
		"processors": []any{
			map[string]any{"set": map[string]any{"field": "env", "value": "custom_env"}},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/_ingest/pipeline/final_pipe", map[string]any{
		"processors": []any{
			map[string]any{"set": map[string]any{"field": "finalized", "value": true}},
		},
	})

	mustReqJSON(t, ts, http.MethodPut, "/r8_pipe_idx", map[string]any{
		"settings": map[string]any{
			"index.default_pipeline": "default_pipe",
			"index.final_pipeline":   "final_pipe",
		},
	})

	// Bulk with item 1 using index default_pipeline, item 2 overriding with custom_pipe, item 3 opting out with _none
	ndjson := strings.Join([]string{
		`{"index":{"_index":"r8_pipe_idx","_id":"1"}}`,
		`{"msg":"one"}`,
		`{"index":{"_index":"r8_pipe_idx","_id":"2","pipeline":"custom_pipe"}}`,
		`{"msg":"two"}`,
		`{"index":{"_index":"r8_pipe_idx","_id":"3","pipeline":"_none"}}`,
		`{"msg":"three"}`,
		"",
	}, "\n")
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/_bulk?refresh=true", strings.NewReader(ndjson))
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	d1 := mustReqJSON(t, ts, http.MethodGet, "/r8_pipe_idx/_doc/1", nil)["_source"].(map[string]any)
	d2 := mustReqJSON(t, ts, http.MethodGet, "/r8_pipe_idx/_doc/2", nil)["_source"].(map[string]any)
	d3 := mustReqJSON(t, ts, http.MethodGet, "/r8_pipe_idx/_doc/3", nil)["_source"].(map[string]any)

	if d1["env"] != "default_env" || d1["finalized"] != true {
		t.Fatalf("expected d1 to have default_pipe + final_pipe, got: %v", d1)
	}
	if d2["env"] != "custom_env" || d2["finalized"] != true {
		t.Fatalf("expected d2 to have custom_pipe + final_pipe, got: %v", d2)
	}
	if d3["env"] != nil || d3["finalized"] != true {
		t.Fatalf("expected d3 (_none) to skip default_pipe but still run final_pipe, got: %v", d3)
	}

	// Verify PUT /{index}/_settings and GET /{index}/_settings for default_pipeline & final_pipeline
	mustReqJSON(t, ts, http.MethodPut, "/r8_pipe_idx/_settings", map[string]any{
		"index": map[string]any{
			"default_pipeline": "custom_pipe",
			"final_pipeline":   "final_pipe",
		},
	})
	settingsResp := mustReqJSON(t, ts, http.MethodGet, "/r8_pipe_idx/_settings", nil)
	idxSettings := settingsResp["r8_pipe_idx"].(map[string]any)["settings"].(map[string]any)["index"].(map[string]any)
	if idxSettings["default_pipeline"] != "custom_pipe" || idxSettings["final_pipeline"] != "final_pipe" {
		t.Fatalf("unexpected GET /r8_pipe_idx/_settings: %v", settingsResp)
	}
	mustReqJSON(t, ts, http.MethodPut, "/r8_pipe_idx/_doc/4?refresh=true", map[string]any{"msg": "four"})
	d4 := mustReqJSON(t, ts, http.MethodGet, "/r8_pipe_idx/_doc/4", nil)["_source"].(map[string]any)
	if d4["env"] != "custom_env" || d4["finalized"] != true {
		t.Fatalf("expected d4 to have custom_pipe + final_pipe, got: %v", d4)
	}
}

func TestRound8_MultiValueSortModeAndDeterministicSortSpec(t *testing.T) {
	// R8-P0-8 & R8-P1-1: Verify sort on multi-valued array columns uses array_min/array_max/array_avg/array_sum,
	// and SortSpec.UnmarshalJSON handles reserved keys deterministically.
	rawMapping := []byte(`{"properties":{"tags":{"type":"keyword","multi_valued":true},"scores":{"type":"double","multi_valued":true}}}`)
	var mSpec esast.MappingSpec
	_ = json.Unmarshal(rawMapping, &mSpec)
	idxSchema := schema.CompileIndexSchema("es_compat", "r8_sort_idx", &mSpec)
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})

	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"prefix": {"tags": {"value": "Al", "case_insensitive": true, "boost": 1.5}}},
					{"wildcard": {"tags": {"value": "al*a", "case_insensitive": true, "boost": 2.0}}},
					{"regexp": {"tags": {"value": "al.*a", "case_insensitive": true, "boost": 2.5}}}
				]
			}
		},
		"sort": [
			{"scores": {"order": "desc", "mode": "avg"}},
			{"scores": {"order": "asc", "mode": "sum"}},
			{"scores": {"order": "desc", "mode": "max"}},
			{"tags": {"order": "asc", "unmapped_type": "keyword"}},
			{"_script": {"type": "number", "order": "desc", "script": {"source": "1"}}},
			{"_geo_distance": {"pin.location": [40, -70], "order": "asc", "unit": "km"}}
		],
		"search_after": [42.5, 100.0, 50.0, "alpha"]
	}`), &req); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("unexpected BuildSearchPlan error: %v", err)
	}
	if !strings.Contains(plan.HitsSQL, "array_avg(`f__scores`) DESC") || !strings.Contains(plan.HitsSQL, "array_sum(`f__scores`) ASC") || !strings.Contains(plan.HitsSQL, "array_min(`f__tags`) ASC") {
		t.Fatalf("expected array_avg, array_sum, and array_min in ORDER BY for multi-valued columns, got:\n%s", plan.HitsSQL)
	}
}

func TestRound8_LuceneParserBoostRegexDanglingOpsAndDoris4Pushdown(t *testing.T) {
	// R8-P1-6 & R8-P1-7:
	// - Dangling +, -, NOT in query_string do not eat the next token or emit bogus term("NOT")
	// - Regex boost field:/pat/^2.5 and escaped \/ are preserved
	// - Doris 4 SEARCH() pushdown is disabled when query_string touches nested/vector fields
	// - lenient / minimum_should_match on query_string & multi_match are respected
	rawMapping := []byte(`{
		"properties": {
			"title": {"type": "text"},
			"status": {"type": "keyword"},
			"items": {"type": "nested", "properties": {"sku": {"type": "keyword"}}},
			"emb":   {"type": "dense_vector", "dims": 3}
		}
	}`)
	var mSpec esast.MappingSpec
	_ = json.Unmarshal(rawMapping, &mSpec)
	idxSchema := schema.CompileIndexSchema("es_compat", "r8_lucene", &mSpec)
	trStd := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	var qsReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"status:/err\\/5[0-9]+/^2.5 AND + - NOT","default_field":"title"}}}`), &qsReq)
	planQS, err := trStd.BuildSearchPlan(&qsReq)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(planQS.HitsSQL, "'NOT'") {
		t.Fatalf("dangling NOT was parsed as a literal term: %s", planQS.HitsSQL)
	}
	if !strings.Contains(planQS.HitsSQL, "REGEXP 'err/5[0-9]+'") || !strings.Contains(planQS.HitsSQL, "2.5") {
		t.Fatalf("expected unescaped regex pattern and boost 2.5 in SQL, got: %s", planQS.HitsSQL)
	}

	trDoris4 := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{UseDoris4SearchFunc: true})

	// Nested field in query_string must fall back to AST transpiler (`array_exists`), not invalid Doris 4 `SEARCH('items.sku:A1')`
	var nestedQS esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"items.sku:A1"}}}`), &nestedQS)
	planNested, err := trDoris4.BuildSearchPlan(&nestedQS)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(planNested.HitsSQL, "SEARCH(") {
		t.Fatalf("expected nested field in query_string to use AST transpiler rather than Doris 4 SEARCH(), got: %s", planNested.HitsSQL)
	}
}

func TestRound8_ApplyDSNAuthAndHelmServiceMonitorTemplate(t *testing.T) {
	// R8-P1-9 & R8-P1-10:
	// 1. ApplyDSNAuth injects user and password when DSN lacks credentials or has $(DORIS_PASSWORD) placeholder
	dsn := ApplyDSNAuth("root:@tcp(doris-fe:9030)/es_compat", "admin", "s3cr3t!")
	if !strings.Contains(dsn, "admin:s3cr3t!@tcp(doris-fe:9030)/es_compat") {
		t.Fatalf("expected ApplyDSNAuth to inject user/password, got: %s", dsn)
	}
	dsn2 := ApplyDSNAuth("root:$(DORIS_PASSWORD)@tcp(doris-fe:9030)/es_compat", "root", "realpass")
	if !strings.Contains(dsn2, "root:realpass@tcp(doris-fe:9030)/es_compat") {
		t.Fatalf("expected ApplyDSNAuth to replace $(DORIS_PASSWORD), got: %s", dsn2)
	}

	// 2. Verify servicemonitor.yaml references basicAuthUser / basicAuthPass and doris-es-proxy.fullname
	smPath := filepath.Join("..", "..", "deploy", "helm", "doris-es-proxy", "templates", "servicemonitor.yaml")
	rawSM, err := os.ReadFile(smPath)
	if err != nil {
		t.Fatalf("failed to read servicemonitor.yaml: %v", err)
	}
	smStr := string(rawSM)
	if !strings.Contains(smStr, `.Values.auth.basicAuthUser`) || !strings.Contains(smStr, `.Values.auth.basicAuthPass`) || !strings.Contains(smStr, `default (include "doris-es-proxy.fullname" .) .Values.auth.existingSecret`) {
		t.Fatalf("expected servicemonitor.yaml to reference .Values.auth.basicAuthUser, .Values.auth.basicAuthPass, and default secret name:\n%s", smStr)
	}
	if strings.Contains(smStr, `.Values.auth.basicUsername`) {
		t.Fatalf("servicemonitor.yaml still contains stale key names:\n%s", smStr)
	}
}

func TestRound8_StreamLoadRedirectHostGuardAndMaxBodyEnforcement(t *testing.T) {
	// R8-P2-2 & R8-P2-3:
	// 1. StreamLoadClient strips Authorization header when redirected to an untrusted external host without _stream_load path
	var leakedAuth string
	extTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1}`))
	}))
	defer extTarget.Close()

	crossHostTargetURL := strings.Replace(extTarget.URL, "127.0.0.1", "localhost", 1) + "/untrusted/landing"
	feRedirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, crossHostTargetURL, http.StatusTemporaryRedirect)
	}))
	defer feRedirect.Close()

	slClient := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: feRedirect.URL,
		Database:       "es_compat",
		User:           "root",
		Password:       "supersecret",
	})
	if err := slClient.LoadNDJSON(context.Background(), "tbl", []byte(`{"_id":"1"}`), true); err != nil {
		t.Fatalf("unexpected LoadNDJSON error: %v", err)
	}
	if leakedAuth != "" {
		t.Fatalf("expected Authorization header not to be forwarded to non-_stream_load external path, got: %q", leakedAuth)
	}

	// 2. Verify oversized request body on JSON endpoints returns 413 Request Entity Too Large
	srv := NewServer("es_compat", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	srv.SetMaxRequestBodyBytes(64)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	bigBody := `{"mappings":{"properties":{"f":{"type":"keyword","ignore_above":256,"meta":{"description":"` + strings.Repeat("x", 128) + `"}}}}}`
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/big_idx", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Request Entity Too Large for oversized body, got %d", resp.StatusCode)
	}
}
