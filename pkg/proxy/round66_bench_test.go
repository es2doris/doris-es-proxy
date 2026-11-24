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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func BenchmarkSearch_MatchAndAggs(b *testing.B) {
	mem := NewMemoryBackend(false)
	srv := NewServer("es_bench", mem, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	b.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	h := srv.Handler()

	createReq := httptest.NewRequest(http.MethodPut, "/bench_search_idx", strings.NewReader(`{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"category": {"type": "keyword"},
				"price": {"type": "double"},
				"@timestamp": {"type": "date"}
			}
		}
	}`))
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		b.Fatalf("create index failed: %d %s", createRec.Code, createRec.Body.String())
	}

	var bulkBuf strings.Builder
	categories := []string{"electronics", "books", "apparel", "home"}
	for i := 0; i < 100; i++ {
		cat := categories[i%len(categories)]
		day := (i % 7) + 1
		fmt.Fprintf(&bulkBuf, "{\"index\":{\"_index\":\"bench_search_idx\",\"_id\":\"doc-%d\"}}\n", i)
		fmt.Fprintf(&bulkBuf, "{\"title\":\"apache doris search benchmark item %d %s\",\"category\":%q,\"price\":%.2f,\"@timestamp\":\"2026-01-0%dT12:00:00Z\"}\n",
			i, cat, cat, float64(10+i), day)
	}
	bulkReq := httptest.NewRequest(http.MethodPost, "/_bulk?refresh=true", strings.NewReader(bulkBuf.String()))
	bulkReq.Header.Set("Content-Type", "application/x-ndjson")
	bulkRec := httptest.NewRecorder()
	h.ServeHTTP(bulkRec, bulkReq)
	if bulkRec.Code != http.StatusOK {
		b.Fatalf("bulk index failed: %d %s", bulkRec.Code, bulkRec.Body.String())
	}

	searchBody := []byte(`{
		"size": 10,
		"query": {
			"bool": {
				"must": [{"match": {"title": "doris benchmark"}}],
				"filter": [{"range": {"price": {"gte": 20}}}]
			}
		},
		"aggs": {
			"by_cat": {
				"terms": {"field": "category", "size": 5},
				"aggs": {
					"price_stats": {"stats": {"field": "price"}}
				}
			},
			"by_day": {
				"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}
			}
		}
	}`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/bench_search_idx/_search", bytes.NewReader(searchBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("search failed: status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
}

func BenchmarkBulkIndex_Coalescer(b *testing.B) {
	var flushCount atomic.Int64
	var flushBytes atomic.Int64
	c := newStreamLoadCoalescer(func(_ context.Context, _ string, ndjson []byte, _ bool) error {
		flushCount.Add(1)
		flushBytes.Add(int64(len(ndjson)))
		return nil
	})
	c.Configure(50*time.Millisecond, 256)
	b.Cleanup(func() {
		_ = c.Close(context.Background())
	})

	payload := []byte(`{"_id":"bench-doc-1","_version":1,"__DORIS_DELETE_SIGN__":0,"_source":"{\"title\":\"coalescer benchmark payload\",\"count\":42,\"tags\":[\"alpha\",\"beta\"]}"}` + "\n")
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := c.Submit(ctx, "bench_tbl", payload, false); err != nil {
			b.Fatalf("coalescer Submit failed: %v", err)
		}
	}
	if err := c.FlushAll(ctx); err != nil {
		b.Fatalf("coalescer FlushAll failed: %v", err)
	}
	b.StopTimer()
	if flushCount.Load() == 0 || flushBytes.Load() == 0 {
		b.Fatalf("expected coalescer flushes > 0, got count=%d bytes=%d", flushCount.Load(), flushBytes.Load())
	}
}

func BenchmarkIngestPipeline_ExpandTemplate(b *testing.B) {
	tmpl := map[string]any{
		"message": "user={{user.name}} tags={{#join delimiter=|}}tags{{/join}} query={{#url}}{{raw_query}}{{/url}} meta={{#toJson}}meta{{/toJson}}",
		"nested": []any{
			"idx-{{env}}-{{region}}",
			map[string]any{"service": "{{service}}", "score": "{{score}}"},
		},
	}
	doc := map[string]any{
		"env":       "prod",
		"region":    "us-east-1",
		"service":   "search-proxy",
		"score":     99.5,
		"raw_query": "status:200 AND path:/api/v1/search?q=hello world",
		"tags":      []any{"fast", "durable", "es-compat"},
		"user":      map[string]any{"name": "alice"},
		"meta":      map[string]any{"shard": 1, "active": true},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := expandIngestTemplate(tmpl, doc)
		if err != nil {
			b.Fatalf("expandIngestTemplate failed: %v", err)
		}
		outMap, ok := out.(map[string]any)
		if !ok || outMap["message"] == "" {
			b.Fatalf("unexpected expanded output: %#v", out)
		}
	}
}
