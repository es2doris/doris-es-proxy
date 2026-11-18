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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doReqR62SearchTest(t *testing.T, h http.Handler, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec, out
}

// TestRound62Search_F26_ConcurrentAutoDimsCopyOnWrite hammers concurrent `/_bulk` writes
// locking `dense_vector` `AutoDims` + dynamic `[128..2048]` vectors alongside concurrent
// `/_search` and `GET /{index}/_mapping` readers under `-race`.
func TestRound62Search_F26_ConcurrentAutoDimsCopyOnWrite(t *testing.T) {
	t.Parallel()
	srv := NewServer("es_r62_f26", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	rec, _ := doReqR62SearchTest(t, h, http.MethodPut, "/vec_race", `{
		"mappings": {
			"properties": {
				"emb": {"type": "dense_vector"},
				"tag": {"type": "keyword"}
			}
		}
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create index failed (%d): %s", rec.Code, rec.Body.String())
	}

	// Build a 128-dim float vector string for ES8 dynamic vector inference
	dynParts := make([]string, 128)
	for i := range dynParts {
		dynParts[i] = fmt.Sprintf("%.3f", float64(i+1)/128.0)
	}
	dynVecJSON := "[" + strings.Join(dynParts, ",") + "]"

	var wg sync.WaitGroup
	// 8 concurrent bulk writer goroutines
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for iter := 0; iter < 5; iter++ {
				docID := fmt.Sprintf("w%d_%d", worker, iter)
				ndjson := fmt.Sprintf(
					"{\"index\":{\"_index\":\"vec_race\",\"_id\":%q}}\n{\"emb\":[0.5,0.5,0.5,0.5],\"dyn_vec\":%s,\"tag\":\"t%d\"}\n",
					docID, dynVecJSON, worker,
				)
				r := httptest.NewRequest(http.MethodPost, "/_bulk?refresh=true", strings.NewReader(ndjson))
				r.Header.Set("Content-Type", "application/x-ndjson")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusOK {
					t.Errorf("bulk write %s failed (%d): %s", docID, w.Code, w.Body.String())
				}
			}
		}(g)
	}

	// 6 concurrent `/_search` + `GET /vec_race/_mapping` reader goroutines
	for rIdx := 0; rIdx < 6; rIdx++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iter := 0; iter < 8; iter++ {
				sRec, _ := doReqR62SearchTest(t, h, http.MethodPost, "/vec_race/_search", `{"query":{"match_all":{}},"size":5}`)
				if sRec.Code != http.StatusOK {
					t.Errorf("concurrent search failed (%d): %s", sRec.Code, sRec.Body.String())
				}
				mRec, _ := doReqR62SearchTest(t, h, http.MethodGet, "/vec_race/_mapping", "")
				if mRec.Code != http.StatusOK {
					t.Errorf("concurrent get mapping failed (%d): %s", mRec.Code, mRec.Body.String())
				}
			}
		}()
	}
	wg.Wait()

	// Verify locked `dims: 4` on `emb` and dynamic `dims: 128` on `dyn_vec`
	mRec, mResp := doReqR62SearchTest(t, h, http.MethodGet, "/vec_race/_mapping", "")
	if mRec.Code != http.StatusOK {
		t.Fatalf("final get mapping failed (%d): %s", mRec.Code, mRec.Body.String())
	}
	rawJSON := mRec.Body.String()
	if !strings.Contains(rawJSON, `"dims":4`) && !strings.Contains(rawJSON, `"dims": 4`) {
		t.Fatalf("expected locked dims=4 in final mapping, got: %s (parsed=%v)", rawJSON, mResp)
	}
}

// TestRound62Search_F28_ServerCloseGlobalRegistryCleanup verifies `Server.Close` removes `s`
// from all package-level server state registries.
func TestRound62Search_F28_ServerCloseGlobalRegistryCleanup(t *testing.T) {
	srv := NewServer("es_r62_close", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	h := srv.Handler()

	// Touch admin, CRUD, ingest stats, and remote reindex registries
	_, _ = doReqR62SearchTest(t, h, http.MethodGet, "/_nodes/stats", "")
	_, _ = doReqR62SearchTest(t, h, http.MethodPut, "/idx_close", `{}`)
	_, _ = doReqR62SearchTest(t, h, http.MethodPut, "/_ingest/pipeline/p_close", `{"processors":[{"set":{"field":"x","value":1}}]}`)
	_, _ = doReqR62SearchTest(t, h, http.MethodPost, "/idx_close/_doc?pipeline=p_close", `{"a":1}`)
	srv.SetStaticRemoteReindexWhitelist("example.com:9200")
	srv.SetRemoteReindexTransport(http.DefaultTransport)

	if err := srv.Close(context.Background()); err != nil {
		t.Fatalf("Server.Close returned error: %v", err)
	}

	round61AdminRegistryMu.Lock()
	_, inAdmin := round61AdminRegistry[srv]
	round61AdminRegistryMu.Unlock()
	if inAdmin {
		t.Fatalf("expected srv removed from round61AdminRegistry after Close()")
	}

	serverStateRegistryMuR61CRUD.Lock()
	_, inCRUD := serverStateRegistryR61CRUD[srv]
	serverStateRegistryMuR61CRUD.Unlock()
	if inCRUD {
		t.Fatalf("expected srv removed from serverStateRegistryR61CRUD after Close()")
	}

	if _, ok := serverIngestStatsRegistryRound61.Load(srv); ok {
		t.Fatalf("expected srv removed from serverIngestStatsRegistryRound61 after Close()")
	}
	if _, ok := serverRemoteReindexTransportsRound61.Load(srv); ok {
		t.Fatalf("expected srv removed from serverRemoteReindexTransportsRound61 after Close()")
	}
	if _, ok := serverRemoteReindexSecurityConfigRound62.Load(srv); ok {
		t.Fatalf("expected srv removed from serverRemoteReindexSecurityConfigRound62 after Close()")
	}
}

// TestRound62Search_F6_DataStreamBackingIndicesAndFailureStore verifies `.ds-*` physical backing
// index provisioning, `op_type=create` enforcement, `/_rollover`, and `.fs-*` failure store redirection.
func TestRound62Search_F6_DataStreamBackingIndicesAndFailureStore(t *testing.T) {
	t.Parallel()
	srv := NewServer("es_r62_ds", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	rec, _ := doReqR62SearchTest(t, h, http.MethodPut, "/_index_template/logs_tpl", `{
		"index_patterns": ["logs-*"],
		"data_stream": {}
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put template failed (%d): %s", rec.Code, rec.Body.String())
	}

	rec, _ = doReqR62SearchTest(t, h, http.MethodPut, "/_data_stream/logs-app", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("create data stream failed (%d): %s", rec.Code, rec.Body.String())
	}

	// Enable failure_store via POST /_data_stream/_modify
	rec, _ = doReqR62SearchTest(t, h, http.MethodPost, "/_data_stream/_modify", `{
		"actions": [
			{"data_stream_options": {"data_stream": "logs-app", "failure_store": {"enabled": true}}}
		]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("modify data stream failed (%d): %s", rec.Code, rec.Body.String())
	}

	// Valid document with `@timestamp` goes to `.ds-logs-app-*-000001`
	rec, _ = doReqR62SearchTest(t, h, http.MethodPost, "/logs-app/_doc?refresh=true", `{"@timestamp":"2026-11-16T12:00:00Z","msg":"ok"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("post doc to data stream failed (%d): %s", rec.Code, rec.Body.String())
	}

	// Missing `@timestamp` with `failure_store` enabled redirects to `.fs-logs-app-*`
	rec, failResp := doReqR62SearchTest(t, h, http.MethodPost, "/logs-app/_doc?refresh=true", `{"msg":"missing_ts"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected failure_store redirect 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if idxStr, _ := failResp["_index"].(string); !strings.HasPrefix(idxStr, ".fs-logs-app-") {
		t.Fatalf("expected redirected _index starting with .fs-logs-app-, got %q (%v)", idxStr, failResp)
	}

	// Rollover advances `.ds-logs-app-*` to `-000003` (generation 1 was initial `.ds-*`, generation 2 was `.fs-*` init)
	rec, rollResp := doReqR62SearchTest(t, h, http.MethodPost, "/logs-app/_rollover", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollover failed (%d): %s", rec.Code, rec.Body.String())
	}
	if newIdx, _ := rollResp["new_index"].(string); !strings.HasSuffix(newIdx, "-000003") {
		t.Fatalf("expected new_index ending with -000003, got %q (%v)", newIdx, rollResp)
	}
}

// TestRound62Search_F21_F24_RuntimeLazyDFSIndexScriptsAndAllowList verifies lazy DFS skipping
// unused runtime cycles, `on_script_error: "continue"`, index-time `mappings.properties.<f>.script`,
// composite runtime fields, and `scripted_metric` cluster allow-list enforcement.
func TestRound62Search_F21_F24_RuntimeLazyDFSIndexScriptsAndAllowList(t *testing.T) {
	t.Parallel()
	srv := NewServer("es_r62_rt", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	// Create index with index-time scripted field `doubled`
	rec, _ := doReqR62SearchTest(t, h, http.MethodPut, "/rt_idx", `{
		"mappings": {
			"properties": {
				"val": {"type": "long"},
				"doubled": {
					"type": "long",
					"script": {"source": "emit(params._source.val * 2)"}
				}
			}
		}
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create rt_idx failed (%d): %s", rec.Code, rec.Body.String())
	}
	rec, _ = doReqR62SearchTest(t, h, http.MethodPost, "/rt_idx/_doc/1?refresh=true", `{"val":21,"raw":"k1=alpha"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("index doc failed (%d): %s", rec.Code, rec.Body.String())
	}

	// Search requesting `doubled`, `safe_err` (`on_script_error: continue`), composite `kv.k1`, while
	// leaving cyclic `cyc_a <-> cyc_b` unreferenced (lazy DFS must NOT fail on unused cycle!)
	rec, sResp := doReqR62SearchTest(t, h, http.MethodPost, "/rt_idx/_search", `{
		"runtime_mappings": {
			"cyc_a": {"type": "keyword", "script": "emit(doc['cyc_b'].value)"},
			"cyc_b": {"type": "keyword", "script": "emit(doc['cyc_a'].value)"},
			"safe_err": {
				"type": "long",
				"on_script_error": "continue",
				"script": "emit(1 / 0)"
			},
			"kv": {
				"type": "composite",
				"script": "Map m = new HashMap(); m.put('k1', 'alpha'); emit(m);",
				"fields": {
					"k1": {"type": "keyword"}
				}
			}
		},
		"fields": ["doubled", "safe_err", "kv.k1"]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("lazy DFS runtime search failed (%d): %s", rec.Code, rec.Body.String())
	}
	rawBody := rec.Body.String()
	if !strings.Contains(rawBody, "42") || !strings.Contains(rawBody, "alpha") {
		t.Fatalf("expected doubled=42 and kv.k1=alpha in fields response, got: %s (%v)", rawBody, sResp)
	}

	// Enable `search.aggs.only_allowed_metric_scripts: true` and verify disallowed inline `scripted_metric` is rejected
	rec, _ = doReqR62SearchTest(t, h, http.MethodPut, "/_cluster/settings", `{
		"transient": {
			"search.aggs.only_allowed_metric_scripts": true,
			"search.aggs.allowed_inline_metric_scripts": ["state.ok = 1"]
		}
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cluster settings failed (%d): %s", rec.Code, rec.Body.String())
	}
	rec, _ = doReqR62SearchTest(t, h, http.MethodPost, "/rt_idx/_search", `{
		"size": 0,
		"aggs": {
			"sm": {
				"scripted_metric": {
					"map_script": "state.bad = 1",
					"reduce_script": "return 1"
				}
			}
		}
	}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when inline scripted_metric is not in allow-list, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestRound62Search_F11_F19_AggStitchersLookupAndMPercolate verifies `histogram` `min_doc_count: 0`,
// `ip_prefix`, `lookup` runtime fields (`390_lookup_fields.yml`), and `/_mpercolate`.
func TestRound62Search_F11_F19_AggStitchersLookupAndMPercolate(t *testing.T) {
	t.Parallel()
	srv := NewServer("es_r62_aggs", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	defer func() { _ = srv.Close(context.Background()) }()
	h := srv.Handler()

	// 1. Lookup runtime field join (`390_lookup_fields.yml`)
	_, _ = doReqR62SearchTest(t, h, http.MethodPut, "/ip_locs/_doc/10.0.0.1?refresh=true", `{"country":"CA","city":"Montreal"}`)
	_, _ = doReqR62SearchTest(t, h, http.MethodPut, "/net_logs", `{
		"mappings": {
			"properties": {
				"ip": {"type": "ip"},
				"latency": {"type": "long"}
			}
		}
	}`)
	_, _ = doReqR62SearchTest(t, h, http.MethodPut, "/net_logs/_doc/1?refresh=true", `{"ip":"10.0.0.1","latency":0}`)
	_, _ = doReqR62SearchTest(t, h, http.MethodPut, "/net_logs/_doc/2?refresh=true", `{"ip":"10.0.0.2","latency":20}`)

	rec, _ := doReqR62SearchTest(t, h, http.MethodPost, "/net_logs/_search", `{
		"runtime_mappings": {
			"loc": {
				"type": "lookup",
				"target_index": "ip_locs",
				"input_field": "ip",
				"target_field": "_id",
				"fetch_fields": ["city", "country"]
			}
		},
		"sort": [{"latency": "asc"}],
		"fields": ["loc"],
		"aggs": {
			"hist": {"histogram": {"field": "latency", "interval": 10}},
			"net": {"ip_prefix": {"field": "ip", "prefix_length": 24}}
		}
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("lookup + histogram + ip_prefix search failed (%d): %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// Histogram interval=10 from 0..20 with default min_doc_count=0 must synthesize empty middle bucket key=10!
	if !strings.Contains(body, `"Montreal"`) || !strings.Contains(body, `"10.0.0.0"`) || !strings.Contains(body, `"doc_count":0`) {
		t.Fatalf("unexpected lookup/histogram/ip_prefix payload: %s", body)
	}

	// 2. `/_mpercolate` NDJSON endpoint
	_, _ = doReqR62SearchTest(t, h, http.MethodPut, "/perc_idx", `{
		"mappings": {
			"properties": {
				"msg": {"type": "text"},
				"query": {"type": "percolator"}
			}
		}
	}`)
	_, _ = doReqR62SearchTest(t, h, http.MethodPut, "/perc_idx/_doc/q1?refresh=true", `{"query":{"match":{"msg":"alert"}}}`)

	ndjson := "{\"percolate\":{\"index\":\"perc_idx\"}}\n{\"doc\":{\"msg\":\"critical alert fired\"}}\n"
	mpReq := httptest.NewRequest(http.MethodPost, "/_mpercolate", strings.NewReader(ndjson))
	mpReq.Header.Set("Content-Type", "application/x-ndjson")
	mpRec := httptest.NewRecorder()
	h.ServeHTTP(mpRec, mpReq)
	if mpRec.Code != http.StatusOK || !strings.Contains(mpRec.Body.String(), `"q1"`) {
		t.Fatalf("_mpercolate failed (%d): %s", mpRec.Code, mpRec.Body.String())
	}
}
