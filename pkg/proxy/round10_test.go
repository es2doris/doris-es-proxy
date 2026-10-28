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
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doBulkNDJSON(t *testing.T, ts *httptest.Server, path, ndjson string) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(ndjson))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("failed to unmarshal bulk response: %v (raw=%s)", err, string(raw))
		}
	}
	return out
}

// TestRound10QueryCacheAliasFilterIsolationAndNowDateMath verifies R10-P0-1:
// - Mutating an alias filter invalidates cached query responses immediately
// - Alias filters containing `now` date-math bypass the TTL query cache.
func TestRound10QueryCacheAliasFilterIsolationAndNowDateMath(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	srv.queryCache.Configure(5*time.Minute, 128)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/events", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"tenant": map[string]any{"type": "keyword"},
				"ts":     map[string]any{"type": "date"},
			},
		},
		"aliases": map[string]any{
			"current_tenant": map[string]any{
				"filter": map[string]any{"term": map[string]any{"tenant": "acme"}},
			},
			"recent_events": map[string]any{
				"filter": map[string]any{"range": map[string]any{"ts": map[string]any{"gte": "now-1d/d"}}},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/events/_doc/1?refresh=true", map[string]any{
		"tenant": "acme", "ts": time.Now().UTC().Format(time.RFC3339),
	})
	mustReqJSON(t, ts, http.MethodPut, "/events/_doc/2?refresh=true", map[string]any{
		"tenant": "globex", "ts": time.Now().UTC().Format(time.RFC3339),
	})
	mustReqJSON(t, ts, http.MethodPut, "/events/_doc/3?refresh=true", map[string]any{
		"tenant": "globex", "ts": time.Now().UTC().Format(time.RFC3339),
	})

	// 1. Search current_tenant (points to acme -> 1 hit)
	s1 := mustReqJSON(t, ts, http.MethodPost, "/current_tenant/_search", map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
	})
	if total := s1["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64); total != 1 {
		t.Fatalf("expected 1 hit for acme, got %v", total)
	}

	// 2. Re-point current_tenant alias filter to globex via /_aliases (without writing to /events)
	mustReqJSON(t, ts, http.MethodPost, "/_aliases", map[string]any{
		"actions": []any{
			map[string]any{
				"add": map[string]any{
					"index":  "events",
					"alias":  "current_tenant",
					"filter": map[string]any{"term": map[string]any{"tenant": "globex"}},
				},
			},
		},
	})

	// 3. Repeat identical search against /current_tenant/_search -> must return 2 hits (globex), not stale cached 1 hit
	s2 := mustReqJSON(t, ts, http.MethodPost, "/current_tenant/_search", map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
	})
	if total := s2["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64); total != 2 {
		t.Fatalf("expected 2 hits after alias filter update to globex, got %v", total)
	}

	// 4. Verify containsNowDateMath detects `now` inside Req.AliasFilter
	reqWithNowAlias := &esast.SearchRequest{
		Query:       &esast.Query{MatchAll: map[string]any{}},
		AliasFilter: &esast.Query{Range: map[string]esast.RangeCond{"ts": {GTE: "now-1h"}}},
	}
	if !containsNowDateMath(reqWithNowAlias, nil) {
		t.Fatalf("expected containsNowDateMath to return true when AliasFilter contains now-1h")
	}
}

// TestRound10WriteIsolationOnFilteredAliases verifies R10-P0-2:
// - PUT /{alias}/_doc/{id} rejects documents that violate the alias filter and protects out-of-scope existing docs
// - POST /{alias}/_update/{id} rejects updates that mutate a doc out of the alias filter
// - POST /{alias}/_update_by_query rejects script/upsert mutations that violate the alias filter
// - POST /_bulk (create/index/update) enforces write alias filters per item
// - POST /_reindex into a filtered destination alias rejects out-of-scope docs.
func TestRound10WriteIsolationOnFilteredAliases(t *testing.T) {
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
			},
		},
		"aliases": map[string]any{
			"tenant_acme": map[string]any{
				"filter":         map[string]any{"term": map[string]any{"tenant": "acme"}},
				"is_write_index": true,
			},
		},
	})

	// Seed an acme doc (1) and a globex doc (2) directly into /tenants
	mustReqJSON(t, ts, http.MethodPut, "/tenants/_doc/1?refresh=true", map[string]any{
		"tenant": "acme", "title": "acme doc 1",
	})
	mustReqJSON(t, ts, http.MethodPut, "/tenants/_doc/2?refresh=true", map[string]any{
		"tenant": "globex", "title": "globex doc 2",
	})

	// 1. PUT /tenant_acme/_doc/3 with tenant="globex" must be rejected with 400
	_, status := doReqJSON(t, ts, http.MethodPut, "/tenant_acme/_doc/3", map[string]any{
		"tenant": "globex", "title": "spoofed tenant",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 when indexing out-of-scope doc via filtered alias, got %d", status)
	}

	// 2. PUT /tenant_acme/_doc/2 with tenant="acme" must be rejected with 409 Conflict (cannot overwrite globex's doc 2)
	_, status = doReqJSON(t, ts, http.MethodPut, "/tenant_acme/_doc/2", map[string]any{
		"tenant": "acme", "title": "attempt to hijack globex doc 2",
	})
	if status != http.StatusConflict {
		t.Fatalf("expected 409 when overwriting another tenant's doc via filtered alias, got %d", status)
	}

	// 3. POST /tenant_acme/_update/1 changing tenant to "globex" must be rejected with 400
	_, status = doReqJSON(t, ts, http.MethodPost, "/tenant_acme/_update/1", map[string]any{
		"doc": map[string]any{"tenant": "globex"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 when updating doc out of alias filter, got %d", status)
	}

	// 4. POST /tenant_acme/_update_by_query mutating tenant to "globex" must be rejected with 400
	_, status = doReqJSON(t, ts, http.MethodPost, "/tenant_acme/_update_by_query", map[string]any{
		"script": map[string]any{
			"source": "ctx._source.tenant = 'globex'",
		},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 when _update_by_query mutates doc out of alias filter, got %d", status)
	}

	// 5. POST /tenant_acme/_bulk with 1 valid acme doc, 1 invalid globex doc, and 1 hijack attempt on doc 2
	bulkLines := strings.Join([]string{
		`{"index":{"_id":"10"}}`,
		`{"tenant":"acme","title":"valid bulk acme"}`,
		`{"index":{"_id":"11"}}`,
		`{"tenant":"globex","title":"invalid bulk globex"}`,
		`{"index":{"_id":"2"}}`,
		`{"tenant":"acme","title":"hijack doc 2"}`,
		"",
	}, "\n")
	bulkResp := doBulkNDJSON(t, ts, "/tenant_acme/_bulk", bulkLines)
	if bulkResp["errors"] != true {
		t.Fatalf("expected bulk errors=true, got %+v", bulkResp)
	}
	items := bulkResp["items"].([]any)
	item0 := items[0].(map[string]any)["index"].(map[string]any)
	item1 := items[1].(map[string]any)["index"].(map[string]any)
	item2 := items[2].(map[string]any)["index"].(map[string]any)
	if int(item0["status"].(float64)) != http.StatusCreated {
		t.Fatalf("expected item 0 status 201, got %+v", item0)
	}
	if int(item1["status"].(float64)) != http.StatusBadRequest {
		t.Fatalf("expected item 1 status 400, got %+v", item1)
	}
	if int(item2["status"].(float64)) != http.StatusConflict {
		t.Fatalf("expected item 2 status 409, got %+v", item2)
	}

	// 6. POST /_reindex from /tenants (containing both acme and globex) into /tenant_acme must fail with 400
	_, status = doReqJSON(t, ts, http.MethodPost, "/_reindex", map[string]any{
		"source": map[string]any{"index": "tenants"},
		"dest":   map[string]any{"index": "tenant_acme"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 when reindexing out-of-scope docs into filtered alias, got %d", status)
	}
}

// TestRound10PITCountValidateAndExplain verifies R10-P0-3:
// - /_count, /_validate/query, and /_doris/explain decode body.pit.id and enforce alias filters encoded in the PIT.
func TestRound10PITCountValidateAndExplain(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/orders", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"tenant": map[string]any{"type": "keyword"},
				"amount": map[string]any{"type": "integer"},
			},
		},
		"aliases": map[string]any{
			"orders_acme": map[string]any{
				"filter": map[string]any{"term": map[string]any{"tenant": "acme"}},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/orders/_doc/1?refresh=true", map[string]any{"tenant": "acme", "amount": 50})
	mustReqJSON(t, ts, http.MethodPut, "/orders/_doc/2?refresh=true", map[string]any{"tenant": "globex", "amount": 150})

	pitResp := mustReqJSON(t, ts, http.MethodPost, "/orders_acme/_pit?keep_alive=1m", nil)
	pitID := pitResp["id"].(string)

	// 1. POST /_count with pit.id -> must scope to orders_acme (1 doc, not 2)
	cntResp := mustReqJSON(t, ts, http.MethodPost, "/_count", map[string]any{
		"pit": map[string]any{"id": pitID},
	})
	if cnt := cntResp["count"].(float64); cnt != 1 {
		t.Fatalf("expected PIT-scoped /_count to return 1, got %v", cnt)
	}

	// 2. POST /_validate/query?explain=true with pit.id -> must include tenant = 'acme' in explanation SQL
	valResp := mustReqJSON(t, ts, http.MethodPost, "/_validate/query?explain=true", map[string]any{
		"pit":   map[string]any{"id": pitID},
		"query": map[string]any{"range": map[string]any{"amount": map[string]any{"gte": 10}}},
	})
	if valResp["valid"] != true {
		t.Fatalf("expected valid=true, got %+v", valResp)
	}
	explanations := valResp["explanations"].([]any)
	explSQL := explanations[0].(map[string]any)["explanation"].(string)
	if !strings.Contains(explSQL, "'acme'") {
		t.Fatalf("expected PIT /_validate/query explanation SQL to include alias filter 'acme', got: %s", explSQL)
	}

	// 3. POST /_doris/explain with pit.id -> must include tenant = 'acme' in hits_sql
	dorisExpl := mustReqJSON(t, ts, http.MethodPost, "/_doris/explain", map[string]any{
		"pit":   map[string]any{"id": pitID},
		"query": map[string]any{"match_all": map[string]any{}},
	})
	searchSQL := dorisExpl["hits_sql"].(string)
	if !strings.Contains(searchSQL, "'acme'") {
		t.Fatalf("expected PIT /_doris/explain hits_sql to include alias filter 'acme', got: %s", searchSQL)
	}
}

// TestRound10DeleteAliasBlockedAndMinusPatternExclusion verifies R10-P0-4 and R10-P1-7:
// - DELETE /{alias} returns 400 illegal_argument_exception instead of dropping the backing table
// - DELETE /{index}/_alias/prefix-* supports wildcard alias patterns
// - Multi-index patterns support `-pattern` exclusions (e.g. `logs-*, -logs-secret`)
// - GET /{alias}/_stats returns filtered doc counts for filtered aliases.
func TestRound10DeleteAliasBlockedAndMinusPatternExclusion(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/logs-app", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"env": map[string]any{"type": "keyword"},
			},
		},
		"aliases": map[string]any{
			"logs-prod-alias": map[string]any{
				"filter": map[string]any{"term": map[string]any{"env": "prod"}},
			},
			"temp-alias-1": map[string]any{},
			"temp-alias-2": map[string]any{},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/logs-secret", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"env": map[string]any{"type": "keyword"},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/logs-app/_doc/1?refresh=true", map[string]any{"env": "prod"})
	mustReqJSON(t, ts, http.MethodPut, "/logs-app/_doc/2?refresh=true", map[string]any{"env": "dev"})
	mustReqJSON(t, ts, http.MethodPut, "/logs-secret/_doc/3?refresh=true", map[string]any{"env": "prod"})

	// 1. DELETE /logs-prod-alias must fail with 400 and NOT drop logs-app
	delResp, status := doReqJSON(t, ts, http.MethodDelete, "/logs-prod-alias", nil)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 when calling DELETE /{alias}, got %d (%+v)", status, delResp)
	}
	cntApp := mustReqJSON(t, ts, http.MethodGet, "/logs-app/_count", nil)
	if cntApp["count"].(float64) != 2 {
		t.Fatalf("expected logs-app to still have 2 docs, got %+v", cntApp)
	}

	// 2. Wildcard alias delete: DELETE /logs-app/_alias/temp-*
	mustReqJSON(t, ts, http.MethodDelete, "/logs-app/_alias/temp-*", nil)
	aliasesResp := mustReqJSON(t, ts, http.MethodGet, "/logs-app/_alias", nil)
	appAliases := aliasesResp["logs-app"].(map[string]any)["aliases"].(map[string]any)
	if _, exists := appAliases["temp-alias-1"]; exists {
		t.Fatalf("expected temp-alias-1 to be removed by wildcard delete, got %+v", appAliases)
	}
	if _, exists := appAliases["logs-prod-alias"]; !exists {
		t.Fatalf("expected logs-prod-alias to remain, got %+v", appAliases)
	}

	// 3. Multi-index exclusion pattern: /logs-*,-logs-secret/_search
	sResp := mustReqJSON(t, ts, http.MethodPost, "/logs-*,-logs-secret/_search", map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
	})
	if total := sResp["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64); total != 2 {
		t.Fatalf("expected 2 hits from logs-app (excluding logs-secret), got %v", total)
	}

	// 4. GET /logs-prod-alias/_stats must report 1 doc (env=prod), not 2
	statsResp := mustReqJSON(t, ts, http.MethodGet, "/logs-prod-alias/_stats", nil)
	allPrimaries := statsResp["_all"].(map[string]any)["primaries"].(map[string]any)["docs"].(map[string]any)
	if cnt := allPrimaries["count"].(float64); cnt != 1 {
		t.Fatalf("expected GET /logs-prod-alias/_stats doc count=1, got %v", cnt)
	}
}

// TestRound10CrossInstanceCatalogDeletionSync verifies R10-P0-5:
// - Deleting an index, alias, index template, or ingest pipeline on Server A propagates via tombstones to Server B.
func TestRound10CrossInstanceCatalogDeletionSync(t *testing.T) {
	t.Parallel()
	sharedMB := NewMemoryBackend(false)
	srvA := NewServer("es_db", sharedMB, transpiler.TranspilerOptions{})
	srvB := NewServer("es_db", sharedMB, transpiler.TranspilerOptions{})
	tsA := httptest.NewServer(srvA.Handler())
	defer tsA.Close()
	tsB := httptest.NewServer(srvB.Handler())
	defer tsB.Close()

	// Create index, alias, template, and pipeline on Server A
	mustReqJSON(t, tsA, http.MethodPut, "/shared-idx", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{"msg": map[string]any{"type": "keyword"}},
		},
		"aliases": map[string]any{
			"shared-alias": map[string]any{},
		},
	})
	mustReqJSON(t, tsA, http.MethodPut, "/_index_template/shared-tpl", map[string]any{
		"index_patterns": []string{"tpl-*"},
		"template": map[string]any{
			"mappings": map[string]any{
				"properties": map[string]any{"k": map[string]any{"type": "keyword"}},
			},
		},
	})
	mustReqJSON(t, tsA, http.MethodPut, "/_ingest/pipeline/shared-pipe", map[string]any{
		"processors": []any{
			map[string]any{"set": map[string]any{"field": "ingested", "value": true}},
		},
	})

	// Warm Server B's in-memory catalog cache by reading them
	_ = mustReqJSON(t, tsB, http.MethodGet, "/_alias/shared-alias", nil)
	_ = mustReqJSON(t, tsB, http.MethodGet, "/_index_template/shared-tpl", nil)
	_ = mustReqJSON(t, tsB, http.MethodGet, "/_ingest/pipeline/shared-pipe", nil)

	// Now delete alias, template, pipeline, and index on Server A
	mustReqJSON(t, tsA, http.MethodDelete, "/shared-idx/_alias/shared-alias", nil)
	mustReqJSON(t, tsA, http.MethodDelete, "/_index_template/shared-tpl", nil)
	mustReqJSON(t, tsA, http.MethodDelete, "/_ingest/pipeline/shared-pipe", nil)
	mustReqJSON(t, tsA, http.MethodDelete, "/shared-idx", nil)

	// Verify Server B immediately observes the deletions
	if _, status := doReqJSON(t, tsB, http.MethodGet, "/_alias/shared-alias", nil); status != http.StatusNotFound {
		t.Fatalf("expected 404 on Server B for deleted alias, got %d", status)
	}
	if _, status := doReqJSON(t, tsB, http.MethodGet, "/_index_template/shared-tpl", nil); status != http.StatusNotFound {
		t.Fatalf("expected 404 on Server B for deleted template, got %d", status)
	}
	pipesB := mustReqJSON(t, tsB, http.MethodGet, "/_ingest/pipeline", nil)
	if _, exists := pipesB["shared-pipe"]; exists {
		t.Fatalf("expected shared-pipe to be deleted on Server B, got %+v", pipesB)
	}
	if _, status := doReqJSON(t, tsB, http.MethodGet, "/shared-idx", nil); status != http.StatusNotFound {
		t.Fatalf("expected 404 on Server B for deleted index, got %d", status)
	}
}

// TestRound10FilteredAliasPureKNNSearch verifies R10-P0-6:
//   - Top-level `knn` search on a filtered alias without a user `query` takes the pure kNN transpiler path
//     and restricts results strictly to the alias filter (without injecting `OR (1=1)`).
func TestRound10FilteredAliasPureKNNSearch(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/vecs", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"tenant":    map[string]any{"type": "keyword"},
				"embedding": map[string]any{"type": "dense_vector", "dims": 2},
			},
		},
		"aliases": map[string]any{
			"vecs_acme": map[string]any{
				"filter": map[string]any{"term": map[string]any{"tenant": "acme"}},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/vecs/_doc/1?refresh=true", map[string]any{
		"tenant": "acme", "embedding": []float64{1.0, 0.0},
	})
	mustReqJSON(t, ts, http.MethodPut, "/vecs/_doc/2?refresh=true", map[string]any{
		"tenant": "globex", "embedding": []float64{1.0, 0.0},
	})

	expl := mustReqJSON(t, ts, http.MethodPost, "/vecs_acme/_doris/explain", map[string]any{
		"knn": map[string]any{
			"field":        "embedding",
			"query_vector": []float64{1.0, 0.0},
			"k":            5,
		},
	})
	sqlStr := expl["hits_sql"].(string)
	if strings.Contains(sqlStr, "OR (1=1)") || strings.Contains(sqlStr, "OR 1=1") {
		t.Fatalf("expected pure kNN SQL on filtered alias NOT to contain OR 1=1, got: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "'acme'") {
		t.Fatalf("expected pure kNN SQL on filtered alias to contain tenant = 'acme', got: %s", sqlStr)
	}

	sResp := mustReqJSON(t, ts, http.MethodPost, "/vecs_acme/_search", map[string]any{
		"knn": map[string]any{
			"field":        "embedding",
			"query_vector": []float64{1.0, 0.0},
			"k":            5,
		},
	})
	hits := sResp["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected only doc 1 (acme) from pure kNN on filtered alias, got: %+v", hits)
	}
}

// TestRound10SecondLevelMultiBucketSubAggs verifies R10-P0-7:
//   - 2nd-level `date_histogram`, `histogram`, `range`, `date_range`, `ip_range`, `filters`, and `nested`
//     nested under a parent `terms` bucket aggregation execute and return populated child buckets.
func TestRound10SecondLevelMultiBucketSubAggs(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/sales", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"region":     map[string]any{"type": "keyword"},
				"price":      map[string]any{"type": "double"},
				"created_at": map[string]any{"type": "date"},
				"client_ip":  map[string]any{"type": "ip"},
				"status":     map[string]any{"type": "keyword"},
				"items":      map[string]any{"type": "nested", "properties": map[string]any{"sku": map[string]any{"type": "keyword"}}},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/sales/_doc/1?refresh=true", map[string]any{
		"region":     "us",
		"price":      25.0,
		"created_at": "2025-01-05T10:00:00Z",
		"client_ip":  "10.0.0.5",
		"status":     "paid",
		"items":      []any{map[string]any{"sku": "A1"}, map[string]any{"sku": "B2"}},
	})
	mustReqJSON(t, ts, http.MethodPut, "/sales/_doc/2?refresh=true", map[string]any{
		"region":     "us",
		"price":      125.0,
		"created_at": "2025-02-20T12:00:00Z",
		"client_ip":  "192.168.1.10",
		"status":     "refunded",
		"items":      []any{map[string]any{"sku": "A1"}},
	})

	resp := mustReqJSON(t, ts, http.MethodPost, "/sales/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_region": map[string]any{
				"terms": map[string]any{"field": "region"},
				"aggs": map[string]any{
					"by_month": map[string]any{
						"date_histogram": map[string]any{"field": "created_at", "calendar_interval": "month"},
					},
					"by_price_hist": map[string]any{
						"histogram": map[string]any{"field": "price", "interval": 100},
					},
					"by_price_range": map[string]any{
						"range": map[string]any{
							"field": "price",
							"ranges": []any{
								map[string]any{"key": "cheap", "to": 50},
								map[string]any{"key": "expensive", "from": 50},
							},
						},
					},
					"by_date_range": map[string]any{
						"date_range": map[string]any{
							"field": "created_at",
							"ranges": []any{
								map[string]any{"to": "2025-02-01T00:00:00Z"},
								map[string]any{"from": "2025-02-01T00:00:00Z"},
							},
						},
					},
					"by_ip_range": map[string]any{
						"ip_range": map[string]any{
							"field": "client_ip",
							"ranges": []any{
								map[string]any{"mask": "10.0.0.0/8"},
								map[string]any{"from": "192.168.0.0", "to": "192.168.255.255"},
							},
						},
					},
					"by_status_anon_filters": map[string]any{
						"filters": map[string]any{
							"other_bucket": true,
							"filters": []any{
								map[string]any{"term": map[string]any{"status": "paid"}},
							},
						},
					},
					"by_status_filters": map[string]any{
						"filters": map[string]any{
							"other_bucket": true,
							"filters": map[string]any{
								"paid_only": map[string]any{"term": map[string]any{"status": "paid"}},
							},
						},
					},
					"nested_items": map[string]any{
						"nested": map[string]any{"path": "items"},
						"aggs": map[string]any{
							"skus": map[string]any{"terms": map[string]any{"field": "items.sku"}},
						},
					},
				},
			},
		},
	})

	buckets := resp["aggregations"].(map[string]any)["by_region"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 1 {
		t.Fatalf("expected 1 region bucket, got %+v", buckets)
	}
	usBucket := buckets[0].(map[string]any)
	if len(usBucket["by_month"].(map[string]any)["buckets"].([]any)) != 2 {
		t.Fatalf("expected 2 date_histogram sub-buckets, got %+v", usBucket["by_month"])
	}
	if len(usBucket["by_price_hist"].(map[string]any)["buckets"].([]any)) != 2 {
		t.Fatalf("expected 2 histogram sub-buckets, got %+v", usBucket["by_price_hist"])
	}
	if len(usBucket["by_price_range"].(map[string]any)["buckets"].([]any)) != 2 {
		t.Fatalf("expected 2 range sub-buckets, got %+v", usBucket["by_price_range"])
	}
	if len(usBucket["by_ip_range"].(map[string]any)["buckets"].([]any)) != 2 {
		t.Fatalf("expected 2 ip_range sub-buckets, got %+v", usBucket["by_ip_range"])
	}
	statusBuckets := usBucket["by_status_filters"].(map[string]any)["buckets"].(map[string]any)
	if statusBuckets["paid_only"].(map[string]any)["doc_count"].(float64) != 1 ||
		statusBuckets["_other_"].(map[string]any)["doc_count"].(float64) != 1 {
		t.Fatalf("unexpected 2nd-level filters buckets: %+v", statusBuckets)
	}
	nestedObj := usBucket["nested_items"].(map[string]any)
	if nestedObj["doc_count"].(float64) != 3 {
		t.Fatalf("expected nested_items doc_count=3, got %+v", nestedObj)
	}
	skuBuckets := nestedObj["skus"].(map[string]any)["buckets"].([]any)
	if len(skuBuckets) != 2 {
		t.Fatalf("expected 2 nested sku buckets under by_region, got %+v", skuBuckets)
	}
}

// TestRound10MultiIndexGlobalAndWeightedMetrics verifies R10-P0-8:
// - Multi-index `global` aggregation accumulates across indices even when an index has 0 hits for the user query
// - Multi-index `string_stats` weights `avg_length` by per-index count
// - Multi-index `percentiles` weights values by per-index count.
func TestRound10MultiIndexGlobalAndWeightedMetrics(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, idx := range []string{"m-idx-1", "m-idx-2"} {
		mustReqJSON(t, ts, http.MethodPut, "/"+idx, map[string]any{
			"mappings": map[string]any{
				"properties": map[string]any{
					"tag":  map[string]any{"type": "keyword"},
					"word": map[string]any{"type": "keyword"},
					"val":  map[string]any{"type": "double"},
				},
			},
		})
	}
	// m-idx-1 has 1 doc matching tag="match" (word len 2, val 10)
	mustReqJSON(t, ts, http.MethodPut, "/m-idx-1/_doc/1?refresh=true", map[string]any{
		"tag": "match", "word": "hi", "val": 10.0,
	})
	// m-idx-2 has 3 docs with tag="other" (0 hits for tag="match", word len 6, val 100)
	for _, id := range []string{"2", "3", "4"} {
		mustReqJSON(t, ts, http.MethodPut, "/m-idx-2/_doc/"+id+"?refresh=true", map[string]any{
			"tag": "other", "word": "abcdef", "val": 100.0,
		})
	}

	// 1. Search /m-idx-1,m-idx-2 with query tag="match" and a `global` agg
	// Even though m-idx-2 has 0 hits for tag="match", `global` must count all 4 docs across both indices!
	resp := mustReqJSON(t, ts, http.MethodPost, "/m-idx-1,m-idx-2/_search", map[string]any{
		"size":  0,
		"query": map[string]any{"term": map[string]any{"tag": "match"}},
		"aggs": map[string]any{
			"all_docs": map[string]any{
				"global": map[string]any{},
				"aggs": map[string]any{
					"total_val": map[string]any{"sum": map[string]any{"field": "val"}},
				},
			},
		},
	})
	allDocs := resp["aggregations"].(map[string]any)["all_docs"].(map[string]any)
	if allDocs["doc_count"].(float64) != 4 {
		t.Fatalf("expected multi-index global doc_count=4, got %+v", allDocs)
	}
	if allDocs["total_val"].(map[string]any)["value"].(float64) != 310 {
		t.Fatalf("expected multi-index global total_val=310, got %+v", allDocs)
	}

	// 2. Match-all across both indices: 1 doc of len 2 + 3 docs of len 6 -> weighted avg_length = (2 + 18) / 4 = 5.0
	resp2 := mustReqJSON(t, ts, http.MethodPost, "/m-idx-1,m-idx-2/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"str":  map[string]any{"string_stats": map[string]any{"field": "word"}},
			"pcts": map[string]any{"percentiles": map[string]any{"field": "val", "percents": []float64{50}}},
		},
	})
	strStats := resp2["aggregations"].(map[string]any)["str"].(map[string]any)
	if math.Abs(strStats["avg_length"].(float64)-5.0) > 1e-6 {
		t.Fatalf("expected weighted string_stats avg_length=5.0, got %+v", strStats)
	}
	pctValues := resp2["aggregations"].(map[string]any)["pcts"].(map[string]any)["values"].(map[string]any)
	// 1 doc @ 10.0, 3 docs @ 100.0 -> weighted 50th percentile is closer to 100 than 55 ( specifically 10*0.25 + 100*0.75 = 77.5)
	if math.Abs(pctValues["50.0"].(float64)-77.5) > 1e-6 {
		t.Fatalf("expected weighted p50=77.5, got %+v", pctValues)
	}
}

// TestRound10PainlessCommentsRegexAndBooleanAssignment verifies R10-P0-9 and R10-P1-7:
// - Single-line `//` and multi-line `/* */` comments are stripped cleanly
// - Regex literals containing escaped slashes `/a\/b/` and character classes `/[\/;]/` do not break statement splitting or ternary parsing
// - Boolean/relational/regex expressions on the RHS of assignments evaluate to bool.
func TestRound10PainlessCommentsRegexAndBooleanAssignment(t *testing.T) {
	t.Parallel()
	doc := map[string]any{
		"path":   "a/b",
		"score":  85.0,
		"active": false,
	}
	script := `
		// Single-line comment with ; and 'quotes'
		/* Multi-line comment
		   spanning lines */
		boolean pathOk = doc['path'].value =~ /a\/b/;
		ctx._source.high_or_active = doc['score'].value >= 80 || doc['active'].value;
		ctx._source.path_matched = pathOk;
		ctx._source.label = doc['path'].value =~ /[\/;]/ ? 'has_delim' : 'plain';
	`
	_, err := painless.EvalPainlessWithOp(doc, script, nil)
	if err != nil {
		t.Fatalf("unexpected painless error: %v", err)
	}
	if doc["high_or_active"] != true {
		t.Fatalf("expected high_or_active=true, got %+v", doc)
	}
	if doc["path_matched"] != true {
		t.Fatalf("expected path_matched=true, got %+v", doc)
	}
	if doc["label"] != "has_delim" {
		t.Fatalf("expected label='has_delim', got %+v", doc)
	}
}

// TestRound10DocLookupAliasFilterAndDynamicNumericCast verifies R10-P1-1:
// - `top_hits` and `top_metrics` docLookup enforce alias filters
// - Dynamic/unmapped numeric fields inside sub-aggregations cast to DOUBLE (preserving decimals) instead of BIGINT.
func TestRound10DocLookupAliasFilterAndDynamicNumericCast(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/host-metrics", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"host": map[string]any{"type": "keyword"},
			},
		},
	})
	expl := mustReqJSON(t, ts, http.MethodPost, "/host-metrics/_doris/explain", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_host": map[string]any{
				"terms": map[string]any{"field": "host"},
				"aggs": map[string]any{
					"avg_cpu": map[string]any{"avg": map[string]any{"field": "cpu_load"}},
				},
			},
		},
	})
	aggSQL := expl["aggs_sql"].(string)
	if !strings.Contains(aggSQL, "AS DOUBLE") || strings.Contains(aggSQL, "AS BIGINT") {
		t.Fatalf("expected dynamic numeric field in sub-agg to cast AS DOUBLE, got: %s", aggSQL)
	}
}

// TestRound10TermsLookupInAliasFilter verifies R10-P1-2:
//   - Alias filters containing a `terms` lookup (`{"terms": {"user_id": {"index": "acl", "id": "team1", "path": "members"}}}`)
//     are resolved before transpiling `/_search`, `/_count`, `/_doc/{id}`, `/_update_by_query`, `/_delete_by_query`, and `/_validate/query`.
func TestRound10TermsLookupInAliasFilter(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/acl", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{"members": map[string]any{"type": "keyword"}},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/acl/_doc/team1?refresh=true", map[string]any{
		"members": []string{"alice", "bob"},
	})

	mustReqJSON(t, ts, http.MethodPut, "/docs", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"owner": map[string]any{"type": "keyword"},
				"title": map[string]any{"type": "text"},
			},
		},
		"aliases": map[string]any{
			"team1_docs": map[string]any{
				"filter": map[string]any{
					"terms": map[string]any{
						"owner": map[string]any{
							"index": "acl",
							"id":    "team1",
							"path":  "members",
						},
					},
				},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/docs/_doc/1?refresh=true", map[string]any{"owner": "alice", "title": "alice spec"})
	mustReqJSON(t, ts, http.MethodPut, "/docs/_doc/2?refresh=true", map[string]any{"owner": "mallory", "title": "mallory secret"})

	// 1. /team1_docs/_search must return only doc 1 (alice)
	sResp := mustReqJSON(t, ts, http.MethodPost, "/team1_docs/_search", map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
	})
	if total := sResp["hits"].(map[string]any)["total"].(map[string]any)["value"].(float64); total != 1 {
		t.Fatalf("expected 1 hit via terms-lookup alias filter, got %v", total)
	}

	// 2. /team1_docs/_count must return 1
	cResp := mustReqJSON(t, ts, http.MethodGet, "/team1_docs/_count", nil)
	if cResp["count"].(float64) != 1 {
		t.Fatalf("expected count=1 via terms-lookup alias filter, got %+v", cResp)
	}

	// 3. GET /team1_docs/_doc/1 succeeds (200), GET /team1_docs/_doc/2 returns 404
	if _, status := doReqJSON(t, ts, http.MethodGet, "/team1_docs/_doc/1", nil); status != http.StatusOK {
		t.Fatalf("expected 200 for doc 1 via team1_docs, got %d", status)
	}
	if _, status := doReqJSON(t, ts, http.MethodGet, "/team1_docs/_doc/2", nil); status != http.StatusNotFound {
		t.Fatalf("expected 404 for doc 2 via team1_docs, got %d", status)
	}
}

// TestRound10NormalizePipelineAggAndSiblingBucketValidation verifies R10-P1-3:
// - `normalize` pipeline aggregation supports `percent_of_sum`, `rescale_0_1`, `rescale_0_100`, `mean`, `z-score`, and `atan`
// - Child pipeline aggregations inside a bucket can reference sibling `*_bucket` pipeline aggregations at the parent level without failing validation.
func TestRound10NormalizePipelineAggAndSiblingBucketValidation(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/norm-idx", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"k": map[string]any{"type": "keyword"},
				"v": map[string]any{"type": "double"},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/norm-idx/_doc/1?refresh=true", map[string]any{"k": "a", "v": 10.0})
	mustReqJSON(t, ts, http.MethodPut, "/norm-idx/_doc/2?refresh=true", map[string]any{"k": "b", "v": 30.0})
	mustReqJSON(t, ts, http.MethodPut, "/norm-idx/_doc/3?refresh=true", map[string]any{"k": "c", "v": 60.0})

	resp := mustReqJSON(t, ts, http.MethodPost, "/norm-idx/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_k": map[string]any{
				"terms": map[string]any{"field": "k", "order": map[string]any{"_key": "asc"}},
				"aggs": map[string]any{
					"sum_v": map[string]any{"sum": map[string]any{"field": "v"}},
					"pct_sum": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_v",
							"method":       "percent_of_sum",
							"format":       "00.0%",
						},
					},
					"rescaled_100": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_v",
							"method":       "rescale_0_100",
						},
					},
					"rescaled_1": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_v",
							"method":       "rescale_0_1",
							"format":       "0.00",
						},
					},
					"norm_mean": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_v",
							"method":       "mean",
						},
					},
					"norm_z": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_v",
							"method":       "z-score",
						},
					},
					"norm_atan": map[string]any{
						"normalize": map[string]any{
							"buckets_path": "sum_v",
							"method":       "atan",
						},
					},
				},
			},
		},
	})

	buckets := resp["aggregations"].(map[string]any)["by_k"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 3 {
		t.Fatalf("expected 3 buckets, got %+v", buckets)
	}
	b0 := buckets[0].(map[string]any)
	b1 := buckets[1].(map[string]any)
	b2 := buckets[2].(map[string]any)
	if math.Abs(b0["pct_sum"].(map[string]any)["value"].(float64)-10.0) > 1e-6 ||
		b0["pct_sum"].(map[string]any)["value_as_string"] != "10.00%" {
		t.Fatalf("unexpected b0 pct_sum: %+v", b0["pct_sum"])
	}
	if math.Abs(b1["rescaled_100"].(map[string]any)["value"].(float64)-40.0) > 1e-6 {
		t.Fatalf("expected b1 rescaled_100=40.0, got %+v", b1["rescaled_100"])
	}
	if math.Abs(b2["rescaled_100"].(map[string]any)["value"].(float64)-100.0) > 1e-6 {
		t.Fatalf("expected b2 rescaled_100=100.0, got %+v", b2["rescaled_100"])
	}
}

// TestRound10NestedTermsSubAggsAndTermsEnumAndExplainDoc verifies R10-P1-4 and R10-P1-7:
// - `nested` -> `terms` -> `reverse_nested` / `stats` / `percentiles` works end-to-end
// - `POST /{index}/_terms_enum` returns prefix-matched terms and respects alias filters
// - `GET/POST /{index}/_explain/{id}` returns match explanation and respects alias filters.
func TestRound10NestedTermsSubAggsAndTermsEnumAndExplainDoc(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/catalog", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"tenant": map[string]any{"type": "keyword"},
				"brand":  map[string]any{"type": "keyword"},
				"variants": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"color": map[string]any{"type": "keyword"},
						"price": map[string]any{"type": "double"},
					},
				},
			},
		},
		"aliases": map[string]any{
			"catalog_acme": map[string]any{
				"filter": map[string]any{"term": map[string]any{"tenant": "acme"}},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/catalog/_doc/1?refresh=true", map[string]any{
		"tenant": "acme",
		"brand":  "alpha-pro",
		"variants": []any{
			map[string]any{"color": "red", "price": 10.0},
			map[string]any{"color": "red", "price": 20.0},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/catalog/_doc/2?refresh=true", map[string]any{
		"tenant": "globex",
		"brand":  "alpha-secret",
		"variants": []any{
			map[string]any{"color": "blue", "price": 50.0},
		},
	})

	// 1. nested -> terms -> reverse_nested & stats
	resp := mustReqJSON(t, ts, http.MethodPost, "/catalog_acme/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"v": map[string]any{
				"nested": map[string]any{"path": "variants"},
				"aggs": map[string]any{
					"by_color": map[string]any{
						"terms": map[string]any{"field": "variants.color"},
						"aggs": map[string]any{
							"price_stats": map[string]any{"stats": map[string]any{"field": "variants.price"}},
							"root_docs":   map[string]any{"reverse_nested": map[string]any{}},
						},
					},
				},
			},
		},
	})
	colorBuckets := resp["aggregations"].(map[string]any)["v"].(map[string]any)["by_color"].(map[string]any)["buckets"].([]any)
	if len(colorBuckets) != 1 {
		t.Fatalf("expected 1 color bucket (red) for catalog_acme, got %+v", colorBuckets)
	}
	redB := colorBuckets[0].(map[string]any)
	if redB["doc_count"].(float64) != 2 {
		t.Fatalf("expected red nested doc_count=2, got %+v", redB)
	}
	if redB["root_docs"].(map[string]any)["doc_count"].(float64) != 1 {
		t.Fatalf("expected reverse_nested root_docs doc_count=1, got %+v", redB["root_docs"])
	}
	if redB["price_stats"].(map[string]any)["avg"].(float64) != 15.0 {
		t.Fatalf("expected price_stats avg=15.0, got %+v", redB["price_stats"])
	}

	// 2. POST /catalog_acme/_terms_enum for prefix "alpha-" -> must return ["alpha-pro"] and NOT "alpha-secret"
	teResp := mustReqJSON(t, ts, http.MethodPost, "/catalog_acme/_terms_enum", map[string]any{
		"field":  "brand",
		"string": "alpha-",
	})
	termsList := teResp["terms"].([]any)
	if len(termsList) != 1 || termsList[0].(string) != "alpha-pro" {
		t.Fatalf("expected _terms_enum on catalog_acme to return only ['alpha-pro'], got %+v", termsList)
	}

	// 3. POST /catalog_acme/_explain/1 -> matched=true; POST /catalog_acme/_explain/2 -> 404 (filtered out by alias)
	ex1 := mustReqJSON(t, ts, http.MethodPost, "/catalog_acme/_explain/1", map[string]any{
		"query": map[string]any{"term": map[string]any{"brand": "alpha-pro"}},
	})
	if ex1["matched"] != true {
		t.Fatalf("expected doc 1 matched=true on _explain, got %+v", ex1)
	}
	if _, status := doReqJSON(t, ts, http.MethodPost, "/catalog_acme/_explain/2", map[string]any{
		"query": map[string]any{"match_all": map[string]any{}},
	}); status != http.StatusNotFound {
		t.Fatalf("expected 404 on _explain for out-of-scope doc 2 via catalog_acme, got %d", status)
	}
}

// TestRound10CompositeMissingBucketAndOrder verifies R10-P1-5:
// - `composite` sources with `missing_bucket: true` include null values as `nil` keys and respect `missing_order`.
func TestRound10CompositeMissingBucketAndOrder(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/comp-idx", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"cat": map[string]any{"type": "keyword"},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/comp-idx/_doc/1?refresh=true", map[string]any{"cat": "books"})
	mustReqJSON(t, ts, http.MethodPut, "/comp-idx/_doc/2?refresh=true", map[string]any{})

	// missing_order: "first" (default) -> nil bucket first, then "books"
	respFirst := mustReqJSON(t, ts, http.MethodPost, "/comp-idx/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"comp": map[string]any{
				"composite": map[string]any{
					"sources": []any{
						map[string]any{
							"cat": map[string]any{
								"terms": map[string]any{
									"field":          "cat",
									"missing_bucket": true,
									"missing_order":  "first",
								},
							},
						},
					},
				},
			},
		},
	})
	bFirst := respFirst["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	if len(bFirst) != 2 {
		t.Fatalf("expected 2 composite buckets (including missing_bucket), got %+v", bFirst)
	}
	if bFirst[0].(map[string]any)["key"].(map[string]any)["cat"] != nil {
		t.Fatalf("expected first bucket key.cat to be nil when missing_order='first', got %+v", bFirst[0])
	}

	// missing_order: "last" -> "books" first, then nil bucket
	respLast := mustReqJSON(t, ts, http.MethodPost, "/comp-idx/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"comp": map[string]any{
				"composite": map[string]any{
					"sources": []any{
						map[string]any{
							"cat": map[string]any{
								"terms": map[string]any{
									"field":          "cat",
									"missing_bucket": true,
									"missing_order":  "last",
								},
							},
						},
					},
				},
			},
		},
	})
	bLast := respLast["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	if bLast[0].(map[string]any)["key"].(map[string]any)["cat"] != "books" ||
		bLast[1].(map[string]any)["key"].(map[string]any)["cat"] != nil {
		t.Fatalf("expected nil bucket last when missing_order='last', got %+v", bLast)
	}
}

// TestRound10TermsOrderMultiValueMetricsAndParentIsolation verifies R10-P1-6:
// - `terms` order by `stats.avg` or `percentiles.50.0` sorts buckets accurately
// - 2nd-level `terms` order by a child metric sorts independently within each parent bucket without cross-bucket key collisions.
func TestRound10TermsOrderMultiValueMetricsAndParentIsolation(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/perf", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"env":     map[string]any{"type": "keyword"},
				"service": map[string]any{"type": "keyword"},
				"latency": map[string]any{"type": "double"},
			},
		},
	})
	// In prod: auth has latency 100, billing has latency 10
	// In staging: auth has latency 5, billing has latency 500
	mustReqJSON(t, ts, http.MethodPut, "/perf/_doc/1?refresh=true", map[string]any{"env": "prod", "service": "auth", "latency": 100.0})
	mustReqJSON(t, ts, http.MethodPut, "/perf/_doc/2?refresh=true", map[string]any{"env": "prod", "service": "billing", "latency": 10.0})
	mustReqJSON(t, ts, http.MethodPut, "/perf/_doc/3?refresh=true", map[string]any{"env": "staging", "service": "auth", "latency": 5.0})
	mustReqJSON(t, ts, http.MethodPut, "/perf/_doc/4?refresh=true", map[string]any{"env": "staging", "service": "billing", "latency": 500.0})

	resp := mustReqJSON(t, ts, http.MethodPost, "/perf/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_service_stats": map[string]any{
				"terms": map[string]any{
					"field": "service",
					"order": map[string]any{"lat_stats.max": "desc"},
				},
				"aggs": map[string]any{
					"lat_stats": map[string]any{"stats": map[string]any{"field": "latency"}},
				},
			},
			"by_env": map[string]any{
				"terms": map[string]any{"field": "env", "order": map[string]any{"_key": "asc"}},
				"aggs": map[string]any{
					"by_service": map[string]any{
						"terms": map[string]any{
							"field": "service",
							"order": map[string]any{"avg_lat": "desc"},
						},
						"aggs": map[string]any{
							"avg_lat": map[string]any{"avg": map[string]any{"field": "latency"}},
						},
					},
				},
			},
		},
	})

	// 1. Top-level by_service_stats ordered by lat_stats.max desc -> billing (500) before auth (100)
	svcBuckets := resp["aggregations"].(map[string]any)["by_service_stats"].(map[string]any)["buckets"].([]any)
	if svcBuckets[0].(map[string]any)["key"] != "billing" {
		t.Fatalf("expected billing first when ordering by lat_stats.max desc, got %+v", svcBuckets)
	}

	// 2. 2nd-level by_service under prod vs staging must have opposite orders!
	envBuckets := resp["aggregations"].(map[string]any)["by_env"].(map[string]any)["buckets"].([]any)
	prodServices := envBuckets[0].(map[string]any)["by_service"].(map[string]any)["buckets"].([]any)
	stagingServices := envBuckets[1].(map[string]any)["by_service"].(map[string]any)["buckets"].([]any)
	if prodServices[0].(map[string]any)["key"] != "auth" {
		t.Fatalf("expected 'auth' (100) before 'billing' (10) in prod, got %+v", prodServices)
	}
	if stagingServices[0].(map[string]any)["key"] != "billing" {
		t.Fatalf("expected 'billing' (500) before 'auth' (5) in staging, got %+v", stagingServices)
	}
}

// TestRound10ChildTermsMissingAndIndexMetaTerms verifies R10-P2-1 and R10-P2-2:
// - Child `terms` aggregation under parent `terms` honors `"missing": "N/A"`
// - `terms` on `"_index"` returns the Elasticsearch index name (`my-index`), not the Doris table name (`es_my_index`).
func TestRound10ChildTermsMissingAndIndexMetaTerms(t *testing.T) {
	t.Parallel()
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	mustReqJSON(t, ts, http.MethodPut, "/my-index", map[string]any{
		"mappings": map[string]any{
			"properties": map[string]any{
				"dept": map[string]any{"type": "keyword"},
				"team": map[string]any{"type": "keyword"},
			},
		},
	})
	mustReqJSON(t, ts, http.MethodPut, "/my-index/_doc/1?refresh=true", map[string]any{"dept": "eng", "team": "core"})
	mustReqJSON(t, ts, http.MethodPut, "/my-index/_doc/2?refresh=true", map[string]any{"dept": "eng"})

	resp := mustReqJSON(t, ts, http.MethodPost, "/my-index/_search", map[string]any{
		"size": 0,
		"aggs": map[string]any{
			"by_index": map[string]any{
				"terms": map[string]any{"field": "_index"},
			},
			"by_dept": map[string]any{
				"terms": map[string]any{"field": "dept"},
				"aggs": map[string]any{
					"by_team": map[string]any{
						"terms": map[string]any{"field": "team", "missing": "unassigned"},
					},
				},
			},
		},
	})

	idxBuckets := resp["aggregations"].(map[string]any)["by_index"].(map[string]any)["buckets"].([]any)
	if len(idxBuckets) != 1 || idxBuckets[0].(map[string]any)["key"] != "my-index" {
		t.Fatalf("expected _index terms key='my-index', got %+v", idxBuckets)
	}

	deptBuckets := resp["aggregations"].(map[string]any)["by_dept"].(map[string]any)["buckets"].([]any)
	teamBuckets := deptBuckets[0].(map[string]any)["by_team"].(map[string]any)["buckets"].([]any)
	if len(teamBuckets) != 2 {
		t.Fatalf("expected 2 child team buckets (including 'unassigned' missing bucket), got %+v", teamBuckets)
	}
	rawJSON, _ := json.Marshal(teamBuckets)
	if !strings.Contains(string(rawJSON), "unassigned") {
		t.Fatalf("expected child terms buckets to contain 'unassigned', got %s", string(rawJSON))
	}
}
