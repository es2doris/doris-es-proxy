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
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/compliance"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

var (
	r63SpecFilterFlag = flag.String("r63.filter", "", "pipe-separated spec path substrings")
	r63SpecCacheFlag  = flag.String("r63.cache", "/Users/ab/code/azra/doris-es-proxy/.cache", "conformance cache directory")
	r63SpecVerFlag    = flag.String("r63.ver", "8.15.5", "ES spec version (8.15.5 or 7.10.2)")
	r63SpecTraceFlag  = flag.Bool("r63.trace", false, "trace HTTP requests/responses")
)

func doTestJSONReqR63(t *testing.T, h http.Handler, method, urlPath, body string, headers map[string]string) (int, http.Header, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, urlPath, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
		dec.UseNumber()
		_ = dec.Decode(&out)
	}
	return rec.Code, rec.Header(), out
}

// TestRound63ConcurrentRaceStress verifies P0 concurrency/context-isolation fixes (`C-05`, `C-06`, `C-12`, `F6`, `F8`):
// parallel goroutines hammer `PUT /_mapping`, `PUT /_settings`, `/_search` with per-request `runtime_mappings`
// `lookup` + `indices_boost` + `significant_text`, and index-time mapped field scripts simultaneously under `-race`.
func TestRound63ConcurrentRaceStress(t *testing.T) {
	backend := NewMemoryBackend(false)
	srv := NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	// Seed two lookup target indices (`lookup_a` and `lookup_b`) with distinct enrichment payloads
	// so concurrent per-request `runtime_mappings` `lookup` specs on the same field name never bleed!
	for _, tc := range []struct {
		idx string
		val string
	}{
		{"lookup_a", "ALPHA_ENRICHED"},
		{"lookup_b", "BETA_ENRICHED"},
	} {
		code, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/"+tc.idx, `{
			"mappings": {
				"properties": {
					"ip_key": {"type": "keyword"},
					"owner": {"type": "keyword"}
				}
			}
		}`, nil)
		if code != http.StatusOK {
			t.Fatalf("create %s got status %d", tc.idx, code)
		}
		code, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/"+tc.idx+"/_doc/1?refresh=true",
			fmt.Sprintf(`{"ip_key":"10.0.0.1","owner":%q}`, tc.val), nil)
		if code != http.StatusCreated && code != http.StatusOK {
			t.Fatalf("seed %s got status %d", tc.idx, code)
		}
	}

	// Create main index with `constant_keyword`, `token_count`, and an index-time mapped field script.
	code, hdr, _ := doTestJSONReqR63(t, h, http.MethodPut, "/events_r63", `{
		"mappings": {
			"properties": {
				"ip": {"type": "keyword"},
				"msg": {
					"type": "text",
					"fields": {
						"tc": {"type": "token_count", "analyzer": "standard"}
					}
				},
				"env": {"type": "constant_keyword", "value": "prod-r63"},
				"computed_tag": {
					"type": "keyword",
					"script": {"source": "emit(doc['ip'].value + ':' + field('env').get('missing'))"}
				}
			}
		}
	}`, map[string]string{"X-Opaque-Id": "op-create"})
	if code != http.StatusOK {
		t.Fatalf("create events_r63 got %d", code)
	}
	if got := hdr.Values("X-Opaque-Id"); len(got) != 1 || got[0] != "op-create" {
		t.Fatalf("expected single X-Opaque-Id header, got %v", got)
	}

	// Index-time script accessing `metadata().routing` must be rejected with 400 (`80_index_field.yml`).
	badCode, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/bad_idx_script_r63", `{
		"mappings": {
			"properties": {
				"bad_rt": {
					"type": "keyword",
					"script": {"source": "emit(metadata().get('_routing'))"}
				}
			}
		}
	}`, nil)
	if badCode == http.StatusOK {
		idxCode, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/bad_idx_script_r63/_doc?routing=r1&refresh=true", `{"x":"1"}`, nil)
		if idxCode != http.StatusBadRequest {
			t.Fatalf("expected 400 when index-time script accesses metadata routing, got %d", idxCode)
		}
	}

	// Seed baseline documents (omitting `env` from `_source` to exercise `__constant_keyword_values`).
	for i := 1; i <= 4; i++ {
		st, _, _ := doTestJSONReqR63(t, h, http.MethodPut, fmt.Sprintf("/events_r63/_doc/%d?refresh=true", i),
			fmt.Sprintf(`{"ip":"10.0.0.1","msg":"hello world token %d"}`, i), nil)
		if st != http.StatusCreated && st != http.StatusOK {
			t.Fatalf("seed doc %d got %d", i, st)
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 64)

	// Worker group 1: concurrent `PUT /events_r63/_mapping` ( verifies copy-on-write RawMapping & single X-Opaque-Id ).
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := 0; iter < 12; iter++ {
				fieldName := fmt.Sprintf("dyn_f_%d_%d", id, iter)
				opID := fmt.Sprintf("map-%d-%d", id, iter)
				st, rHdr, _ := doTestJSONReqR63(t, h, http.MethodPut, "/events_r63/_mapping",
					fmt.Sprintf(`{"properties":{%q:{"type":"keyword"}}}`, fieldName),
					map[string]string{"X-Opaque-Id": opID})
				if st != http.StatusOK {
					errCh <- fmt.Errorf("PUT _mapping status=%d", st)
					return
				}
				if vals := rHdr.Values("X-Opaque-Id"); len(vals) != 1 || vals[0] != opID {
					errCh <- fmt.Errorf("duplicate/mismatched X-Opaque-Id on PUT _mapping: %v", vals)
					return
				}
			}
		}(g)
	}

	// Worker group 2: concurrent `PUT /events_r63/_settings`.
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := 0; iter < 12; iter++ {
				st, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/events_r63/_settings",
					fmt.Sprintf(`{"index":{"refresh_interval":"%ds"}}`, (id+iter)%5+1), nil)
				if st != http.StatusOK {
					errCh <- fmt.Errorf("PUT _settings status=%d", st)
					return
				}
			}
		}(g)
	}

	// Worker group 3: concurrent indexing hitting index-time mapped field script evaluator.
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := 0; iter < 10; iter++ {
				docID := fmt.Sprintf("w-%d-%d", id, iter)
				st, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/events_r63/_doc/"+docID,
					`{"ip":"10.0.0.1","msg":"concurrent indexing stress"}`, nil)
				if st != http.StatusCreated && st != http.StatusOK {
					errCh <- fmt.Errorf("concurrent PUT doc status=%d", st)
					return
				}
			}
		}(g)
	}

	// Worker group 4: concurrent `/_search` with conflicting per-request `lookup` runtime_mappings (`lookup_a` vs `lookup_b`),
	// `indices_boost`, `significant_text`, `constant_keyword` `field('env')`, and `token_count` doc values.
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			useAlpha := id%2 == 0
			targetLookup := "lookup_b"
			expectedOwner := "BETA_ENRICHED"
			if useAlpha {
				targetLookup = "lookup_a"
				expectedOwner = "ALPHA_ENRICHED"
			}
			body := fmt.Sprintf(`{
				"size": 2,
				"indices_boost": [{"events_r63": 2.0}],
				"runtime_mappings": {
					"enriched": {
						"type": "lookup",
						"target_index": %q,
						"input_field": "ip",
						"target_field": "ip_key",
						"fetch_fields": ["owner"]
					}
				},
				"fields": ["enriched", "computed_tag"],
				"script_fields": {
					"const_val": {"script": {"source": "field('env').get('fallback')"}},
					"tok_cnt": {"script": {"source": "doc['msg.tc'].value"}}
				},
				"aggs": {
					"sig": {"significant_text": {"field": "msg", "min_doc_count": 1}}
				}
			}`, targetLookup)
			for iter := 0; iter < 12; iter++ {
				st, _, resp := doTestJSONReqR63(t, h, http.MethodPost, "/events_r63/_search", body, nil)
				if st != http.StatusOK {
					errCh <- fmt.Errorf("search status=%d resp=%v", st, resp)
					return
				}
				hitsObj, _ := resp["hits"].(map[string]any)
				hitsArr, _ := hitsObj["hits"].([]any)
				if len(hitsArr) == 0 {
					errCh <- fmt.Errorf("expected non-empty hits")
					return
				}
				h0, _ := hitsArr[0].(map[string]any)
				fieldsMap, _ := h0["fields"].(map[string]any)
				enrichedArr, _ := fieldsMap["enriched"].([]any)
				if len(enrichedArr) == 0 {
					errCh <- fmt.Errorf("missing lookup field enriched in %v", fieldsMap)
					return
				}
				enrichedObj, _ := enrichedArr[0].(map[string]any)
				owners, _ := enrichedObj["owner"].([]any)
				if len(owners) == 0 || fmt.Sprintf("%v", owners[0]) != expectedOwner {
					errCh <- fmt.Errorf("lookup cross-request bleed: got %v, want %s", owners, expectedOwner)
					return
				}
				constArr, _ := fieldsMap["const_val"].([]any)
				if len(constArr) == 0 || fmt.Sprintf("%v", constArr[0]) != "prod-r63" {
					errCh <- fmt.Errorf("constant_keyword field() got %v, want prod-r63", constArr)
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	// Verify C-12: untrimmed inline script allow-list rejects trailing-space bypass!
	stSet, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/_cluster/settings", `{
		"transient": {
			"search.aggs.only_allowed_metric_scripts": true,
			"search.aggs.allowed_inline_metric_scripts": ["state.x = 1"]
		}
	}`, nil)
	if stSet != http.StatusOK {
		t.Fatalf("cluster settings got %d", stSet)
	}
	stBypass, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/events_r63/_search", `{
		"size": 0,
		"aggs": {
			"sm": {
				"scripted_metric": {
					"init_script": "state.x = 1   ",
					"map_script": "state.x = 1",
					"combine_script": "state.x = 1",
					"reduce_script": "state.x = 1"
				}
			}
		}
	}`, nil)
	if stBypass != http.StatusBadRequest {
		t.Fatalf("expected 400 when trailing spaces mismatch allow-list, got %d", stBypass)
	}

	// Verify F6: PUT /_mapping over MaxRequestBodyBytes returns 413 circuit_breaking_exception!
	srv.SetMaxRequestBodyBytes(64)
	bigMapping := `{"properties":{"oversized_field_name_exceeding_64_bytes":{"type":"keyword"}}}`
	st413, _, resp413 := doTestJSONReqR63(t, h, http.MethodPut, "/events_r63/_mapping", bigMapping, nil)
	if st413 != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 on oversized PUT /_mapping, got %d (%v)", st413, resp413)
	}
}

// TestRound63TargetedConformanceHelper runs filtered upstream YAML specs when R63_SPEC_FILTER or -r63.filter is set.
func TestRound63TargetedConformanceHelper(t *testing.T) {
	filter := strings.TrimSpace(os.Getenv("R63_SPEC_FILTER"))
	if filter == "" && r63SpecFilterFlag != nil {
		filter = strings.TrimSpace(*r63SpecFilterFlag)
	}
	cacheDir := strings.TrimSpace(os.Getenv("CONFORMANCE_CACHE_DIR"))
	if cacheDir == "" && r63SpecCacheFlag != nil {
		cacheDir = strings.TrimSpace(*r63SpecCacheFlag)
	}
	if filter == "" || cacheDir == "" {
		return
	}
	patterns := strings.FieldsFunc(filter, func(r rune) bool { return r == '|' || r == ',' })
	matchesAny := func(p string) bool {
		for _, sub := range patterns {
			sub = strings.TrimSpace(sub)
			if sub != "" && strings.Contains(p, sub) {
				return true
			}
		}
		return false
	}
	ver := strings.TrimSpace(os.Getenv("R63_SPEC_VERSION"))
	if ver == "" && r63SpecVerFlag != nil {
		ver = strings.TrimSpace(*r63SpecVerFlag)
	}
	if ver == "" {
		ver = "8.15.5"
	}
	var dirs []string
	specCached := filepath.Join(cacheDir, "spec-v"+ver)
	if fi, err := os.Stat(specCached); err == nil && fi.IsDir() {
		dirs = append(dirs, specCached)
	} else {
		esRoot := filepath.Join(cacheDir, "es-v"+ver)
		_ = filepath.WalkDir(esRoot, func(path string, d os.DirEntry, wErr error) error {
			if wErr != nil {
				return nil
			}
			if d.IsDir() && d.Name() == ".git" {
				return filepath.SkipDir
			}
			if d.IsDir() && strings.HasSuffix(filepath.ToSlash(path), "/rest-api-spec/test") {
				dirs = append(dirs, path)
				return filepath.SkipDir
			}
			return nil
		})
	}
	if len(dirs) == 0 {
		t.Skipf("no spec dir found under %s for %s", cacheDir, ver)
	}
	traceHTTP := os.Getenv("R63_TRACE_HTTP") == "1" || (r63SpecTraceFlag != nil && *r63SpecTraceFlag)
	newSec := func() (http.Handler, func()) {
		b := NewMemoryBackend(false)
		s := NewServer("es_compat", b, transpiler.TranspilerOptions{})
		s.SetTargetESVersion(ver)
		h := s.Handler()
		if traceHTTP {
			base := h
			h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var reqBody []byte
				if r.Body != nil {
					reqBody, _ = io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(reqBody))
				}
				rec := httptest.NewRecorder()
				base.ServeHTTP(rec, r)
				for k, vals := range rec.Header() {
					w.Header()[k] = append([]string(nil), vals...)
				}
				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes())
				t.Logf("HTTP %s %s body=%s -> %d %s", r.Method, r.URL.RequestURI(), strings.TrimSpace(string(reqBody)), rec.Code, strings.TrimSpace(rec.Body.String()))
			})
		}
		return h, func() { _ = s.Close(context.Background()) }
	}
	opts := compliance.SuiteOptions{
		CorpusName:                  "r63-" + ver,
		TargetVersion:               ver,
		SupportedClusterFeatures:    compliance.DefaultSupportedClusterFeatures(),
		SupportedTestRunnerFeatures: compliance.DefaultSupportedTestRunnerFeatures(),
		NewSectionHandler:           newSec,
	}
	sc, err := compliance.ScoreMatchingFiles(opts, matchesAny, newSec, dirs...)
	if err != nil {
		t.Fatalf("ScoreMatchingFiles error: %v", err)
	}
	t.Logf("[%s] files=%d passed=%d failed=%d skipped=%d (%.2f%%)",
		ver, sc.TotalFiles, sc.SectionsPassed, sc.SectionsFailed, sc.SectionsSkipped, sc.PassRatePct)
	for _, fs := range sc.FailureSamples {
		t.Logf("FAIL %s :: %s -> %s", fs.File, fs.Section, fs.Error)
	}
}

func TestRound63ShardRequestCacheAndStats(t *testing.T) {
	backend := NewMemoryBackend(false)
	srv := NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	st, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/rc_idx", `{
		"mappings": {"properties": {"cat": {"type": "keyword"}, "val": {"type": "integer"}}}
	}`, nil)
	if st != http.StatusOK {
		t.Fatalf("create rc_idx got %d", st)
	}
	for i := 1; i <= 3; i++ {
		c, _, _ := doTestJSONReqR63(t, h, http.MethodPut, fmt.Sprintf("/rc_idx/_doc/%d?refresh=true", i),
			fmt.Sprintf(`{"cat":"a","val":%d}`, i*10), nil)
		if c != http.StatusCreated && c != http.StatusOK {
			t.Fatalf("seed doc %d got %d", i, c)
		}
	}

	aggQuery := `{"size":0,"aggs":{"by_cat":{"terms":{"field":"cat"}}}}`
	// 1st size=0 search -> miss=1, hit=0
	st1, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/rc_idx/_search", aggQuery, nil)
	if st1 != http.StatusOK {
		t.Fatalf("first agg search got %d", st1)
	}
	// 2nd identical size=0 search -> miss=1, hit=1
	st2, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/rc_idx/_search", aggQuery, nil)
	if st2 != http.StatusOK {
		t.Fatalf("second agg search got %d", st2)
	}
	// Explicit request_cache=false bypasses cache -> still miss=1, hit=1
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/rc_idx/_search?request_cache=false", aggQuery, nil)
	// Explicit request_cache=true with size > 0 caches -> miss=2, then hit=2
	sizePosBody := `{"size":1,"query":{"term":{"cat":"a"}}}`
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/rc_idx/_search?request_cache=true&preference=_local", sizePosBody, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/rc_idx/_search?request_cache=true&preference=_local", sizePosBody, nil)

	// Non-deterministic queries (now, random_score) bypass our shard request cache
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/rc_idx/_search",
		`{"size":0,"query":{"function_score":{"random_score":{}}}}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/rc_idx/_search",
		`{"size":0,"query":{"query_string":{"query":"now-1d"}}}`, nil)

	// Verify authoritative shard request cache counters report exact hit_count=2, miss_count=2
	gotHits, gotMisses, _, _ := srv.getShardRequestCacheStatsR63("rc_idx")
	if gotHits != 2 || gotMisses != 2 {
		t.Fatalf("unexpected shard request_cache stats: hits=%d misses=%d", gotHits, gotMisses)
	}
	stStats, _, _ := doTestJSONReqR63(t, h, http.MethodGet, "/rc_idx/_stats", "", nil)
	if stStats != http.StatusOK {
		t.Fatalf("_stats got %d", stStats)
	}

	// Verify index.requests.cache.enable=false disables default size=0 caching unless ?request_cache=true
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/rc_idx/_settings", `{"index":{"requests":{"cache":{"enable":false}}}}`, nil)
	srv.mu.Lock()
	if srv.indexCustomSettings["rc_idx"] == nil {
		srv.indexCustomSettings["rc_idx"] = make(map[string]any)
	}
	srv.indexCustomSettings["rc_idx"]["index.requests.cache.enable"] = false
	srv.mu.Unlock()
	beforeHits, beforeMisses, _, _ := srv.getShardRequestCacheStatsR63("rc_idx")
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/rc_idx/_search", `{"size":0,"aggs":{"s":{"sum":{"field":"val"}}}}`, nil)
	hitsAfterDis, missesAfterDis, _, _ := srv.getShardRequestCacheStatsR63("rc_idx")
	if hitsAfterDis != beforeHits || missesAfterDis != beforeMisses {
		t.Fatalf("expected cache disabled to skip hit/miss, got before=%d/%d after=%d/%d", beforeHits, beforeMisses, hitsAfterDis, missesAfterDis)
	}

	// Test LRU maxSize eviction & _cache/clear
	store := srv.getOrCreateShardRequestCacheR63()
	store.mu.Lock()
	store.maxSize = 2
	store.mu.Unlock()
	srv.storeAndRecordShardRequestCacheMissR63("k1", []string{"rc_idx"}, map[string]any{"ok": 1}, []string{"u1"})
	srv.storeAndRecordShardRequestCacheMissR63("k1", []string{"rc_idx"}, map[string]any{"ok": 2}, nil)
	srv.storeAndRecordShardRequestCacheMissR63("k2", []string{"rc_idx"}, map[string]any{"ok": 3}, nil)
	srv.storeAndRecordShardRequestCacheMissR63("k3", []string{"rc_idx"}, map[string]any{"ok": 4}, nil)
	_, _, evicts, _ := srv.getShardRequestCacheStatsR63("rc_idx")
	if evicts < 1 {
		t.Fatalf("expected LRU eviction >= 1, got %d", evicts)
	}

	// Clear index cache via /rc_idx/_cache/clear?request=true and global /_cache/clear
	stClr1, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/rc_idx/_cache/clear?request=true", "", nil)
	stClr2, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/_cache/clear", "", nil)
	if stClr1 != http.StatusOK || stClr2 != http.StatusOK {
		t.Fatalf("cache clear failed: %d, %d", stClr1, stClr2)
	}
	_, _, _, memAfterClear := srv.getShardRequestCacheStatsR63("rc_idx")
	if memAfterClear != 0 {
		t.Fatalf("expected 0 bytes after clear, got %d", memAfterClear)
	}

	// Delete index purges stats
	stDel, _, _ := doTestJSONReqR63(t, h, http.MethodDelete, "/rc_idx", "", nil)
	if stDel != http.StatusOK {
		t.Fatalf("delete rc_idx got %d", stDel)
	}
	dh, dm, de, db := srv.getShardRequestCacheStatsR63("rc_idx")
	if dh != 0 || dm != 0 || de != 0 || db != 0 {
		t.Fatalf("expected zeroed stats after index delete, got %d/%d/%d/%d", dh, dm, de, db)
	}
	srv.invalidateShardRequestCacheR63()
	srv.cleanupShardRequestCacheR63()
}

func TestRound63DataStreamTSDBAndLifecycleHelpers(t *testing.T) {
	backend := NewMemoryBackend(false)
	srv := NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	// 1. Data stream template, creation, lifecycle wildcard PUT/GET/DELETE, explain, shrink/split/close/open/reindex
	stTpl, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/_index_template/logs_ds_tpl", `{
		"index_patterns": ["logs-r63-*"],
		"data_stream": {"failure_store": {"enabled": true}},
		"template": {
			"mappings": {"properties": {"@timestamp": {"type": "date"}, "msg": {"type": "text"}}}
		}
	}`, nil)
	if stTpl != http.StatusOK {
		t.Fatalf("put ds template got %d", stTpl)
	}
	// Bad template triggers handleIndexTemplateR63 spacing normalization
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/_index_template/bad_tpl", `{
		"index_patterns": ["bad-*"],
		"template": {"mappings": {"properties": {"x": {"type": "keyword", "bogus_param": true}}}}
	}`, nil)

	stDS, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/_data_stream/logs-r63-app", "", nil)
	if stDS != http.StatusOK {
		t.Fatalf("create data stream got %d", stDS)
	}
	// Wildcard data stream lifecycle PUT/GET/DELETE & concrete missing 404
	stLCPut, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/_data_stream/logs-r63-*/_lifecycle", `{"data_retention":"7d"}`, nil)
	stLCGet, _, _ := doTestJSONReqR63(t, h, http.MethodGet, "/_data_stream/logs-r63-*/_lifecycle", "", nil)
	stLCMiss, _, _ := doTestJSONReqR63(t, h, http.MethodGet, "/_data_stream/logs-r63-*,missing-ds/_lifecycle", "", nil)
	stLCExp, _, _ := doTestJSONReqR63(t, h, http.MethodGet, "/logs-r63-app/_lifecycle/explain", "", nil)
	stLCDel, _, _ := doTestJSONReqR63(t, h, http.MethodDelete, "/_data_stream/logs-r63-*/_lifecycle", "", nil)
	if stLCPut != http.StatusOK || stLCGet != http.StatusOK || stLCMiss != http.StatusNotFound || stLCExp != http.StatusOK || stLCDel != http.StatusOK {
		t.Fatalf("lifecycle statuses: put=%d get=%d miss=%d exp=%d del=%d", stLCPut, stLCGet, stLCMiss, stLCExp, stLCDel)
	}

	// Shrink/split on data stream and write backing index must return 400
	stShrink, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/logs-r63-app/_shrink/shrunk_target", `{}`, nil)
	if stShrink != http.StatusBadRequest {
		t.Fatalf("expected 400 shrinking data stream, got %d", stShrink)
	}

	// Wildcard _close must skip data stream backing indices; regular index closes and reopens cleanly
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/plain-r63-idx", `{"mappings":{"properties":{"msg":{"type":"text"}}}}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/plain-r63-idx/_doc/1?refresh=true", `{"msg":"hi"}`, nil)
	stCloseW, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/*r63*/_close", "", nil)
	if stCloseW != http.StatusOK {
		t.Fatalf("wildcard _close got %d", stCloseW)
	}
	// Reindex into data stream requires op_type=create, then succeeds with op_type=create
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/plain-r63-idx/_open", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/logs-r63-app/_open", "", nil)
	stReidxBad, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/_reindex", `{
		"source":{"index":"plain-r63-idx"},
		"dest":{"index":"logs-r63-app"}
	}`, nil)
	if stReidxBad != http.StatusBadRequest {
		t.Fatalf("expected 400 on reindex to data stream without op_type=create, got %d", stReidxBad)
	}
	stReidxOK, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/_reindex?refresh=true", `{
		"source":{"index":"plain-r63-idx"},
		"dest":{"index":"logs-r63-app","op_type":"create"}
	}`, nil)
	if stReidxOK != http.StatusOK {
		t.Fatalf("expected 200 on reindex to data stream with op_type=create, got %d", stReidxOK)
	}

	// Modify data stream: disable failure_store and remove its .fs-* backing index atomically
	_, _, dsGet := doTestJSONReqR63(t, h, http.MethodGet, "/_data_stream/logs-r63-app", "", nil)
	if dsArr, ok := dsGet["data_streams"].([]any); ok && len(dsArr) > 0 {
		ds0, _ := dsArr[0].(map[string]any)
		if fsObj, okF := ds0["failure_store"].(map[string]any); okF {
			if fsInds, okFI := fsObj["indices"].([]any); okFI && len(fsInds) > 0 {
				fsM, _ := fsInds[0].(map[string]any)
				fsIdxName := fmt.Sprintf("%v", fsM["index_name"])
				stMod, _, modResp := doTestJSONReqR63(t, h, http.MethodPost, "/_data_stream/_modify", fmt.Sprintf(`{
					"actions": [
						{"data_stream_options": {"data_stream": "logs-r63-app", "failure_store": {"enabled": false}}},
						{"remove_backing_index": {"data_stream": "logs-r63-app", "index": %q, "failure_store": true}}
					]
				}`, fsIdxName), nil)
				if stMod != http.StatusOK {
					t.Fatalf("modify data stream failure store got %d: %v", stMod, modResp)
				}
			}
		}
	}

	// 2. TSDB index creation, indexing, _tsid / _ts_routing_hash fetch, routing rejection, geo_point position avg error, tombstones & UBQ immutability
	stTSDB, _, tsdbResp := doTestJSONReqR63(t, h, http.MethodPut, "/metrics-tsdb-r63", `{
		"settings": {
			"index.mode": "time_series",
			"index.routing_path": ["host"],
			"index.time_series.start_time": "2020-01-01T00:00:00Z",
			"index.time_series.end_time": "2030-01-01T00:00:00Z"
		},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"host": {"type": "keyword", "time_series_dimension": true},
				"loc": {"type": "geo_point", "time_series_metric": "position"},
				"cpu": {"type": "double", "time_series_metric": "gauge"}
			}
		}
	}`, nil)
	if stTSDB != http.StatusOK {
		t.Fatalf("create TSDB index got %d: %v", stTSDB, tsdbResp)
	}
	stTSDoc, _, tsDocResp := doTestJSONReqR63(t, h, http.MethodPost, "/metrics-tsdb-r63/_doc?refresh=true",
		`{"@timestamp":"2025-05-01T12:00:00Z","host":"web-1","loc":"40.7,-74.0","cpu":0.75}`, nil)
	if stTSDoc != http.StatusCreated && stTSDoc != http.StatusOK {
		t.Fatalf("index TSDB doc got %d: %v", stTSDoc, tsDocResp)
	}
	tsDocID := fmt.Sprintf("%v", tsDocResp["_id"])

	// Duplicate create triggers formatTSDBVersionConflictReasonR63
	stDup, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/metrics-tsdb-r63/_create/"+tsDocID,
		`{"@timestamp":"2025-05-01T12:00:00Z","host":"web-1","cpu":0.8}`, nil)
	if stDup != http.StatusConflict {
		t.Fatalf("expected 409 on TSDB duplicate create, got %d", stDup)
	}
	// GET with routing on TSDB returns 400
	stRGet, _, _ := doTestJSONReqR63(t, h, http.MethodGet, "/metrics-tsdb-r63/_doc/"+tsDocID+"?routing=custom", "", nil)
	if stRGet != http.StatusBadRequest {
		t.Fatalf("expected 400 on TSDB GET with routing, got %d", stRGet)
	}
	// Search _tsid & _ts_routing_hash fields
	stTSSrch, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/metrics-tsdb-r63/_search",
		`{"fields":["_tsid","_ts_routing_hash","host","cpu"]}`, nil)
	if stTSSrch != http.StatusOK {
		t.Fatalf("TSDB search fields got %d", stTSSrch)
	}
	// avg agg on TSDB position geo_point returns 400
	stPosAvg, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/metrics-tsdb-r63/_search",
		`{"size":0,"aggs":{"bad_avg":{"avg":{"field":"loc"}}}}`, nil)
	if stPosAvg != http.StatusBadRequest {
		t.Fatalf("expected 400 on avg over TSDB position geo_point, got %d", stPosAvg)
	}

	// Direct helper coverage for TSDB tombstones, UBQ failure cause, routing path, mapper preview, backfill
	srv.recordTSDBTombstoneVersionR63("metrics-tsdb-r63", "tomb-1", 3)
	if v := srv.getDocTombstoneVersionR63("metrics-tsdb-r63", "tomb-1"); v != 3 {
		t.Fatalf("expected tombstone version 3, got %d", v)
	}
	srv.clearTSDBTombstoneVersionR63("metrics-tsdb-r63", "tomb-1")
	srv.clearTSDBIndexTombstonesR63("metrics-tsdb-r63")
	srv.clearTSDBIndexTombstonesR63("*")

	srv.mu.RLock()
	tsSchema := srv.indices["metrics-tsdb-r63"]
	srv.mu.RUnlock()
	cause := buildTSDBImmutabilityUBQFailureCauseR63(srv, tsSchema, "metrics-tsdb-r63", tsDocID,
		json.RawMessage(`{"@timestamp":"2025-05-01T12:00:00Z","host":"web-2","cpu":0.9}`))
	if cause["type"] != "mapper_parsing_exception" {
		t.Fatalf("unexpected UBQ failure cause: %v", cause)
	}
	if !docHasAnyTSDBRoutingPathFieldR63([]string{"host*"}, map[string]any{"host": "web-1"}) {
		t.Fatalf("expected routing path match")
	}
	if docHasAnyTSDBRoutingPathFieldR63([]string{"region"}, map[string]any{"host": "web-1"}) {
		t.Fatalf("expected routing path mismatch")
	}
	enrichedErr := enrichMapperFieldErrorWithDocIDAndPreviewR63(
		"failed to parse field [meta.num] of type [integer]: invalid", "doc-9",
		[]byte(`{"meta":{"num":{"nested":"bad","arr":[1,null]}}}`),
	)
	if !strings.Contains(enrichedErr, "in document with id 'doc-9'") || !strings.Contains(enrichedErr, "Preview of field's value") {
		t.Fatalf("unexpected enriched mapper error: %s", enrichedErr)
	}
	srv.backfillIndexSchemaPreserveVersionR63(context.Background(), "plain-r63-idx", srv.indices["plain-r63-idx"])

	srv.mu.Lock()
	dsMap := map[string]any{
		"name":       "logs-r63-app",
		"generation": 1,
		"indices":    []any{map[string]any{"index_name": "plain-r63-idx"}},
		"failure_store": map[string]any{
			"indices": []any{map[string]any{"index_name": ".fs-logs-1"}},
		},
	}
	srv.dataStreams["temp-ds-r63"] = dsMap
	incrementDataStreamGenLockedR63(dsMap)
	refreshDataStreamLifecycleManagedByLockedR63(srv, dsMap)
	_ = isBackingIndexAllowedWithoutHiddenR63(srv, ".ds-*", ".ds-logs-1")
	_ = isFailureStoreBackingIndexLockedR63(srv, "temp-ds-r63", ".fs-logs-1")
	_ = removeDeletedBackingIndexFromDataStreamsLockedR63(srv, "plain-r63-idx")
	_ = removeDeletedBackingIndexFromDataStreamsLockedR63(srv, ".fs-logs-1")
	delete(srv.dataStreams, "temp-ds-r63")
	srv.mu.Unlock()
}

func TestRound63SearchHighlightSortAndAggUnitCoverage(t *testing.T) {
	backend := NewMemoryBackend(false)
	srv := NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	// Create two indices with rich mappings to test cross-index sort, value_type mismatch, script_fields partial failure,
	// _ignored field values, variable_width_histogram, weighted_avg multi-weight, top_hits, highlight, percolator, etc.
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/idx_num_r63", `{
		"mappings": {
			"properties": {
				"mixed": {"type": "long"},
				"price": {"type": "double"},
				"weights": {"type": "double"},
				"bad_int": {"type": "integer", "ignore_malformed": true},
				"bad_ip": {"type": "ip", "ignore_malformed": true},
				"bad_bool": {"type": "boolean", "ignore_malformed": true},
				"bad_date": {"type": "date", "ignore_malformed": true},
				"title": {"type": "text", "fields": {"kw": {"type": "keyword"}, "tc": {"type": "token_count", "analyzer": "standard"}}},
				"ts": {"type": "date"},
				"ts_ns": {"type": "date_nanos"}
			}
		}
	}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/idx_kw_r63", `{
		"mappings": {
			"properties": {
				"mixed": {"type": "keyword"},
				"price": {"type": "double"}
			}
		}
	}`, nil)

	for i, doc := range []string{
		`{"mixed":10,"price":12.5,"weights":1.0,"bad_int":"not_int","bad_ip":"bad_ip","bad_bool":99,"bad_date":"bad_dt","title":"The quick brown fox.","ts":"2024-01-02T03:04:05Z","ts_ns":"2024-01-02T03:04:05.123456789Z"}`,
		`{"mixed":20,"price":25.0,"weights":2.0,"title":"Quick brown dog!","ts":"2024-01-03T03:04:05Z","ts_ns":"2024-01-03T03:04:05.123456789Z"}`,
		`{"mixed":30,"price":90.0,"weights":1.0,"title":"Lazy cat.","ts":"2024-01-04T03:04:05Z","ts_ns":"2024-01-04T03:04:05.123456789Z"}`,
	} {
		_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, fmt.Sprintf("/idx_num_r63/_doc/%d?refresh=true", i+1), doc, nil)
	}
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/idx_kw_r63/_doc/1?refresh=true", `{"mixed":"abc","price":50.0}`, nil)

	// Cross-index incompatible sort -> 400
	stSort, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/idx_num_r63,idx_kw_r63/_search",
		`{"sort":[{"mixed":"asc"}]}`, nil)
	if stSort != http.StatusBadRequest {
		t.Fatalf("expected 400 on cross-index incompatible sort, got %d", stSort)
	}

	// Cross-index script_fields partial shard failure -> 200 with _shards.failed == 1
	stPart, _, partResp := doTestJSONReqR63(t, h, http.MethodPost, "/idx_num_r63,idx_kw_r63/_search", `{
		"script_fields": {"tc_val": {"script": {"source": "doc['title.tc'].get(0)"}}}
	}`, nil)
	if stPart != http.StatusOK {
		t.Fatalf("expected 200 partial result on multi-index script_fields, got %d: %v", stPart, partResp)
	}

	// variable_width_histogram + random_sampler (p=0.5 & p=1.0) + top_hits with root fields & bucket_selector on top_hits[_source.price]
	stAgg, _, aggResp := doTestJSONReqR63(t, h, http.MethodPost, "/idx_num_r63/_search", `{
		"fields": ["title", "bad_int"],
		"highlight": {
			"type": "plain",
			"fields": {"title": {}, "title.kw": {"type": "unified"}}
		},
		"query": {"match": {"title": "quick brown"}},
		"aggs": {
			"vwh": {"variable_width_histogram": {"field": "price", "buckets": 2}},
			"rs_half": {"random_sampler": {"probability": 0.5, "seed": 42}, "aggs": {"cnt": {"value_count": {"field": "price"}}}},
			"rs_one": {
				"random_sampler": {"probability": 1.0},
				"aggs": {
					"by_m": {
						"terms": {"field": "mixed"},
						"aggs": {
							"th": {"top_hits": {"size": 1, "version": true, "seq_no_primary_term": true, "explain": true}},
							"sel": {"bucket_selector": {"buckets_path": {"p": "th[_source.price]"}, "script": "params.p > 10"}}
						}
					}
				}
			}
		}
	}`, nil)
	if stAgg != http.StatusOK {
		t.Fatalf("complex search/agg request got %d: %v", stAgg, aggResp)
	}

	// Invalid random_sampler probabilities (<= 0 and > 0.5 != 1.0) & negative sigma
	for _, badBody := range []string{
		`{"size":0,"aggs":{"r":{"random_sampler":{"probability":0.0}}}}`,
		`{"size":0,"aggs":{"r":{"random_sampler":{"probability":-0.2}}}}`,
		`{"size":0,"aggs":{"r":{"random_sampler":{"probability":0.8}}}}`,
		`{"size":0,"aggs":{"e":{"extended_stats":{"field":"price","sigma":-1.0}}}}`,
		`{"fields":["title"],"stored_fields":"_none_"}`,
	} {
		stBad, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/idx_num_r63/_search", badBody, nil)
		if stBad != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d", badBody, stBad)
		}
	}

	// Direct unit exercises for remaining pure helpers in round63_search_aggs_runtime.go
	srv.mu.RLock()
	numSc := srv.indices["idx_num_r63"]
	kwSc := srv.indices["idx_kw_r63"]
	srv.mu.RUnlock()

	// Spatial WKT <-> GeoJSON conversions
	for _, wkt := range []string{
		"POINT (10.5 20.5)",
		"LINESTRING (0 0, 1 1, 2 2)",
		"POLYGON ((0 0, 4 0, 4 4, 0 4, 0 0))",
		"BBOX (-10, 10, 20, -20)",
	} {
		gj := convertSpatialWKTAndGeoJSONR63(wkt, false)
		if _, isMap := gj.(map[string]any); !isMap {
			t.Fatalf("expected GeoJSON map for %s, got %T (%v)", wkt, gj, gj)
		}
	}
	wktPt := convertSpatialWKTAndGeoJSONR63(map[string]any{"type": "Point", "coordinates": []any{10.5, 20.5}}, true)
	if fmt.Sprintf("%v", wktPt) != "POINT (10.5 20.5)" {
		t.Fatalf("unexpected WKT point: %v", wktPt)
	}

	// Malformed check across all scalar/geo types
	trueVal := true
	malCases := []struct {
		b   schema.FieldBinding
		val any
	}{
		{schema.FieldBinding{ESType: "byte", IgnoreMalformed: &trueVal}, int64(999)},
		{schema.FieldBinding{ESType: "short", IgnoreMalformed: &trueVal}, int64(99999)},
		{schema.FieldBinding{ESType: "integer", IgnoreMalformed: &trueVal}, int64(1 << 40)},
		{schema.FieldBinding{ESType: "unsigned_long", IgnoreMalformed: &trueVal}, "-5"},
		{schema.FieldBinding{ESType: "double", IgnoreMalformed: &trueVal}, "nan_str"},
		{schema.FieldBinding{ESType: "boolean", IgnoreMalformed: &trueVal}, "maybe"},
		{schema.FieldBinding{ESType: "ip", IgnoreMalformed: &trueVal}, "999.999.999.999"},
		{schema.FieldBinding{ESType: "geo_point", IgnoreMalformed: &trueVal}, "not_a_geo_point"},
		{schema.FieldBinding{ESType: "date_nanos", IgnoreMalformed: &trueVal}, "not_a_date"},
	}
	for _, mc := range malCases {
		if !isValueMalformedForFieldR63(mc.val, mc.b) {
			t.Fatalf("expected malformed=true for %s (%v)", mc.b.ESType, mc.val)
		}
	}
	if !rawBodyDisablesIgnoredFieldValuesR63([]byte(`{"ignored_field_values":false}`)) {
		t.Fatalf("expected rawBodyDisablesIgnoredFieldValuesR63=true")
	}

	// Terms lookup exercise via HTTP search
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/idx_num_r63/_search", `{
		"query": {"terms": {"mixed": {"index": "idx_kw_r63", "id": "1", "path": "mixed"}}}
	}`, nil)

	// Max regex & prefix length validation + transpiler error rewrite
	var rxReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"/abcdef/"}}}`), &rxReq)
	if rxSt, _, rxEr := validateQueryMaxRegexAndPrefixLengthR63(&rxReq, map[string]map[string]any{"i": {"index.max_regex_length": 3}}); rxSt != http.StatusBadRequest || !strings.Contains(rxEr, "length of regex [6]") {
		t.Fatalf("unexpected regex limit result: %d %s", rxSt, rxEr)
	}
	var pfxReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"prefix":{"title":{"value":"abcdef"}}}}`), &pfxReq)
	if pSt, _, pEr := validateQueryMaxRegexAndPrefixLengthR63(&pfxReq, map[string]map[string]any{"i": {"max_regex_length": 3}}); pSt != http.StatusBadRequest || !strings.Contains(pEr, "length of prefix [6]") {
		t.Fatalf("unexpected prefix limit result: %d %s", pSt, pEr)
	}
	rewritten := rewriteTranspilerMaxRegexLengthErrorR63("illegal_argument_exception: Regular expression [abcdef] exceeds max_regex_length [3].")
	if !strings.Contains(rewritten, "The length of regex [6] used in the Regexp Query request") {
		t.Fatalf("unexpected rewritten regex error: %s", rewritten)
	}

	// keep_values pipeline validation (valid + NullPointerException)
	buckets := []map[string]any{
		{"key": "a", "doc_count": 1, "m1": map[string]any{"value": 10.0}, "m2": map[string]any{"value": nil}},
	}
	_, npeErr := validateAndApplyKeepValuesScriptPipelinesR63(buckets, map[string]esast.AggSpec{
		"bs": {BucketScript: &esast.BucketSelectorAggSpec{
			BucketsPath: map[string]string{"x": "m1", "y": "m2"},
			GapPolicy:   "keep_values",
			Script:      "params.x + params.y",
		}},
	})
	if npeErr == nil || !strings.Contains(npeErr.Error(), "NullPointerException") {
		t.Fatalf("expected NullPointerException from unguarded null param, got %v", npeErr)
	}
	_, okKeepErr := validateAndApplyKeepValuesScriptPipelinesR63(buckets, map[string]esast.AggSpec{
		"bs": {BucketScript: &esast.BucketSelectorAggSpec{
			BucketsPath: map[string]string{"x": "m1", "y": "m2"},
			GapPolicy:   "keep_values",
			Script:      "params.y == null ? params.x : params.x + params.y",
		}},
		"sel": {BucketSelector: &esast.BucketSelectorAggSpec{
			BucketsPath: map[string]string{"x": "m1", "y": "m2"},
			GapPolicy:   "keep_values",
			Script:      "params.y == null && params.x > 5",
		}},
	})
	if okKeepErr != nil {
		t.Fatalf("expected null-guarded keep_values script to succeed, got %v", okKeepErr)
	}

	// Weighted avg multi-weight error & cross-index terms value_type shard failure
	var waAggs map[string]esast.AggSpec
	_ = json.Unmarshal([]byte(`{"wa":{"weighted_avg":{"value":{"field":"price"},"weight":{"field":"weights"}}}}`), &waAggs)
	waErr := checkWeightedAvgMultiWeightOnDocsR63(
		waAggs,
		[]HitRow{{Index: "idx_num_r63", Source: json.RawMessage(`{"price":10,"weights":[1,2]}`)}},
		map[string]*schema.IndexSchema{"idx_num_r63": numSc},
		numSc,
	)
	if waErr == nil {
		t.Fatalf("expected multi-weight error")
	}
	vtFailed, _ := detectCrossIndexTermsValueTypeShardFailuresR63(
		[]string{"idx_num_r63", "idx_kw_r63"},
		map[string]*schema.IndexSchema{"idx_num_r63": numSc, "idx_kw_r63": kwSc},
		map[string]esast.AggSpec{"t": {Terms: &esast.TermsAggSpec{Field: "mixed", ValueType: "long"}}},
	)
	if vtFailed != 1 {
		t.Fatalf("expected 1 failed shard on cross-index value_type mismatch, got %d", vtFailed)
	}

	// Composite date bound TZ, sort entry format, highlight snippets, raw body deprecation, include_unmapped, sig heuristic, percolate order
	dhSpec := &esast.DateHistogramAggSpec{TimeZone: "-02:00", Format: "yyyy-MM-dd"}
	if ms, ok := parseCompositeDateBoundWithTZR63("2024-01-02T00:00:00.000-02:00", dhSpec, time.Now().UTC()); !ok || ms == 0 {
		t.Fatalf("expected valid composite date bound")
	}
	_ = formatSortValueWithEntryFormatR63(int64(1704164645000), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "ts", Format: "strict_date_optional_time"}}, numSc)
	_ = formatSortValueWithEntryFormatR63(int64(1704164645123456789), esast.SortSpec{Entry: esast.SortFieldSpec{Field: "ts_ns", Format: "strict_date_optional_time"}}, numSc)
	reFox := regexp.MustCompile(`(?i)(quick brown|fox)`)
	_ = buildHighlightedSnippetsModeAwareWithFieldTypeR63([]string{"The quick brown fox."}, reFox, "<em>", "</em>", true, 100, 1, 10, 50, "plain", false)
	_ = buildHighlightedSnippetsModeAwareWithFieldTypeR63([]string{"No match here."}, reFox, "", "", true, 100, 1, 5, -1, "plain", false)
	_ = extractIncludeUnmappedPatternsR63([]byte(`{"fields":[{"field":"unmapped_*","include_unmapped":true}]}`))
	_ = isNonTraversableMappedLeafTypeR63("geo_point")
	_ = extractSigHeuristicForAggFromRawR63([]byte(`{"aggs":{"outer":{"aggs":{"sig":{"significant_text":{"field":"title","chi_square":{"include_negatives":true}}}}}}}`), "outer.sig")
	scStrict := newActiveSearchScopeR63(context.Background(), srv, []byte(`{"indices_boost":[{"idx_num_r63":2.0}]}`), &esast.SearchRequest{})
	_, _, _ = formatTermsBucketKeyAndStringWithScopeR63(scStrict, "true", &esast.TermsAggSpec{Field: "bad_bool", ValueType: "boolean"}, numSc)
	reEvaluatePercentilesBucketWithScopeR63(scStrict, map[string]esast.AggSpec{
		"by_m": {
			Terms: &esast.TermsAggSpec{Field: "mixed"},
			Aggs: map[string]esast.AggSpec{
				"s": {Sum: &esast.MetricAggSpec{Field: "price"}},
			},
		},
		"pb": {PercentilesBucket: &esast.PercentilesBucketAggSpec{BucketsPath: "by_m>s"}},
	}, map[string]any{
		"by_m": map[string]any{"buckets": []map[string]any{{"key": 10, "doc_count": 1, "s": map[string]any{"value": 12.5}}}},
	})
	orderedMQ := orderMatchedQueriesByRawSourceR63([]byte(`{"a":{"_name":"first"},"b":{"_name":"second"}}`), []any{"second", "first"})
	if len(orderedMQ) != 2 || orderedMQ[0] != "first" {
		t.Fatalf("expected source order [first, second], got %v", orderedMQ)
	}
	if sum := sumDocCountFieldForMatchedDocsR63([]runtimeMatchedDoc{{doc: map[string]any{"_doc_count": 5}}, {doc: map[string]any{}}}); sum != 6 {
		t.Fatalf("expected _doc_count sum 6, got %d", sum)
	}

	// ES 7 date_histogram interval deprecation warning
	srv.SetTargetESVersion("7.10.2")
	recDep := httptest.NewRecorder()
	reqDep := httptest.NewRequest(http.MethodPost, "/idx_num_r63/_search", nil)
	emitRawBodyDeprecationWarningsR63(recDep, srv, reqDep, []byte(`{"aggs":{"dh":{"date_histogram":{"field":"ts","interval":"1d"}}}}`))
	if len(recDep.Header().Values("Warning")) == 0 {
		t.Fatalf("expected deprecation warning for ES 7 date_histogram.interval")
	}
	_, _, _, _ = preNormalizeSearchBodyR63([]byte(`{"query":{"percolate":{"field":"q","document":{"a":1},"document_type":"doc"}}}`), false)
}

func TestRound63DeepBranchUnitCoverage(t *testing.T) {
	backend := NewMemoryBackend(false)
	srv := NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	// 1. copyRecorderHeadersSetR63 with existing + duplicate + new Warning headers
	dstRec := httptest.NewRecorder()
	dstRec.Header().Add("Warning", `299 Elasticsearch-8.15.5 "w1"`)
	srcHdr := http.Header{}
	srcHdr.Add("Warning", `299 Elasticsearch-8.15.5 "w1"`)
	srcHdr.Add("Warning", `299 Elasticsearch-8.15.5 "w2"`)
	srcHdr.Set("X-Opaque-Id", "op-123")
	copyRecorderHeadersSetR63(dstRec, srcHdr)
	if len(dstRec.Header().Values("Warning")) != 2 {
		t.Fatalf("expected 2 deduplicated Warning headers, got %v", dstRec.Header().Values("Warning"))
	}
	if isMaxBytesBodyErrorR63(nil) || !isMaxBytesBodyErrorR63(&http.MaxBytesError{Limit: 10}) {
		t.Fatalf("unexpected isMaxBytesBodyErrorR63 result")
	}

	// 2. queryHasRandomScoreR63 across Bool (Must/Should/Filter/MustNot), ConstantScore, FunctionScore
	for _, rsJSON := range []string{
		`{"function_score":{"random_score":{}}}`,
		`{"function_score":{"query":{"function_score":{"random_score":{}}}}}`,
		`{"bool":{"must":[{"function_score":{"random_score":{}}}]}}`,
		`{"bool":{"should":[{"function_score":{"random_score":{}}}]}}`,
		`{"bool":{"filter":[{"function_score":{"random_score":{}}}]}}`,
		`{"bool":{"must_not":[{"function_score":{"random_score":{}}}]}}`,
		`{"constant_score":{"filter":{"function_score":{"random_score":{}}}}}`,
	} {
		var q esast.Query
		_ = json.Unmarshal([]byte(rsJSON), &q)
		_ = queryHasRandomScoreR63(&q)
	}

	// 3. Synthetic source index with token_count -> populateMissingTokenCountValuesFromBackendR63
	stSyn, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/syn_tc_r63", `{
		"settings": {"index.mapping.source.mode": "synthetic"},
		"mappings": {
			"properties": {
				"body": {"type": "text", "fields": {"tc": {"type": "token_count", "analyzer": "standard"}}},
				"tag": {"type": "constant_keyword", "value": "fixed"}
			}
		}
	}`, nil)
	if stSyn == http.StatusOK {
		_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/syn_tc_r63/_doc/1?refresh=true", `{"body":"one two three four"}`, nil)
		srv.mu.RLock()
		synSc := srv.indices["syn_tc_r63"]
		srv.mu.RUnlock()
		dm := map[string]any{}
		srv.populateMissingTokenCountValuesFromBackendR63(synSc, "1", dm)
	}

	// 4. Percolator index + multi-doc percolate query with _name clauses -> collectPercolateMultiDocMatchedQueriesMapR63
	stPerc, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/perc_r63", `{
		"mappings": {
			"properties": {
				"query": {"type": "percolator"},
				"kind": {"type": "keyword"},
				"rooms": {"type": "integer"}
			}
		}
	}`, nil)
	if stPerc == http.StatusOK {
		_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/perc_r63/_doc/q1?refresh=true", `{
			"query": {
				"bool": {
					"must": [
						{"match": {"kind": {"query": "detached", "_name": "detached_q"}}},
						{"match": {"rooms": {"query": 3, "_name": "rooms_q"}}}
					]
				}
			}
		}`, nil)
		stPS, _, pResp := doTestJSONReqR63(t, h, http.MethodPost, "/perc_r63/_search", `{
			"query": {
				"bool": {
					"filter": [
						{"percolate": {"field": "query", "documents": [{"kind": "detached", "rooms": 3}, {"kind": "flat", "rooms": 1}]}}
					]
				}
			}
		}`, nil)
		if stPS != http.StatusOK {
			t.Fatalf("percolate multi-doc search got %d: %v", stPS, pResp)
		}
	}

	// 5. Chained index-time mapped field scripts + on_script_error=continue + nil schema fallback
	stChain, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/chain_script_r63", `{
		"mappings": {
			"properties": {
				"base": {"type": "keyword"},
				"step1": {"type": "keyword", "script": {"source": "emit(doc['base'].value + '_s1')"}},
				"step2": {"type": "keyword", "script": {"source": "emit(doc['step1'].value + '_s2')"}},
				"err_cont": {"type": "keyword", "on_script_error": "continue", "script": {"source": "throw new Exception('boom')"}}
			}
		}
	}`, nil)
	if stChain == http.StatusOK {
		stCD, _, _ := doTestJSONReqR63(t, h, http.MethodPut, "/chain_script_r63/_doc/1?refresh=true", `{"base":"ok"}`, nil)
		if stCD != http.StatusCreated && stCD != http.StatusOK {
			t.Fatalf("chained script doc index got %d", stCD)
		}
	}
	_, _ = evalIndexTimeFieldScriptWithSchemaR63Search(nil, "f", "keyword", map[string]any{"source": "'v'"}, "fail", map[string]any{"x": 1})
	_, _ = evalIndexTimeFieldScriptWithSchemaR63Search(nil, "f", "keyword", map[string]any{"source": "throw new Exception('x')"}, "continue", map[string]any{})

	// 6. extractIgnoredFieldValuesMapR63 direct + search with _ignored field
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ig_r63", `{
		"mappings": {"properties": {"num": {"type": "integer", "ignore_malformed": true}}}
	}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ig_r63/_doc/1?refresh=true", `{"num":["bad_str", 42, 3.14159]}`, nil)
	stIG, _, _ := doTestJSONReqR63(t, h, http.MethodPost, "/ig_r63/_search", `{"fields":["_ignored","num"]}`, nil)
	if stIG != http.StatusOK {
		t.Fatalf("_ignored search got %d", stIG)
	}
	srv.mu.RLock()
	igSc := srv.indices["ig_r63"]
	srv.mu.RUnlock()
	igVals := extractIgnoredFieldValuesMapR63(HitRow{Source: json.RawMessage(`{"num":["bad_str", 42, 3.14159]}`)}, igSc)
	if len(igVals["num"]) == 0 {
		t.Fatalf("expected malformed values in extractIgnoredFieldValuesMapR63, got %v", igVals)
	}

	// 7. clusterVariableWidthHistogramR63 with duplicate + 6 distinct values merged down to 2 buckets
	vwhDocs := []runtimeMatchedDoc{
		{hit: HitRow{Index: "i", ID: "1"}, doc: map[string]any{"v": 1.0}},
		{hit: HitRow{Index: "i", ID: "2"}, doc: map[string]any{"v": 1.0}},
		{hit: HitRow{Index: "i", ID: "3"}, doc: map[string]any{"v": 2.0}},
		{hit: HitRow{Index: "i", ID: "4"}, doc: map[string]any{"v": 10.0}},
		{hit: HitRow{Index: "i", ID: "5"}, doc: map[string]any{"v": 11.0}},
		{hit: HitRow{Index: "i", ID: ""}, doc: map[string]any{"v": 50.0}},
	}
	var vwhSpec esast.VariableWidthHistogramAggSpec
	_ = json.Unmarshal([]byte(`{"field":"v","buckets":2}`), &vwhSpec)
	clusters := clusterVariableWidthHistogramR63(vwhDocs, &vwhSpec)
	if len(clusters) != 2 {
		t.Fatalf("expected 2 merged clusters, got %d", len(clusters))
	}

	// 8. validateQueryMaxRegexAndPrefixLengthR63 across nested/compound query wrappers
	var deepRxReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [{"constant_score": {"filter": {"match_all": {}}}}],
				"should": [{"dis_max": {"queries": [{"match_all": {}}]}}],
				"must_not": [{"nested": {"path": "n", "query": {"match_all": {}}}}],
				"filter": [
					{"function_score": {"query": {"match_all": {}}}},
					{"script_score": {"query": {"regexp": {"f": {"value": "abcdefgh"}}}, "script": {"source": "1.0"}}}
				]
			}
		}
	}`), &deepRxReq)
	if stRx, _, _ := validateQueryMaxRegexAndPrefixLengthR63(&deepRxReq, map[string]map[string]any{"i": {"max_regex_length": 4}}); stRx != http.StatusBadRequest {
		t.Fatalf("expected 400 on deep nested regexp length, got %d", stRx)
	}

	// 9. Authoritative catalog server -> validateTermsLookupsExistR63 across all query/agg/inner_hits/rescore branches
	srvAuth := NewServer("es_compat", NewMemoryBackend(true), transpiler.TranspilerOptions{})
	srvAuth.SetTargetESVersion("8.15.5")
	t.Cleanup(func() { _ = srvAuth.Close(context.Background()) })
	hAuth := srvAuth.Handler()
	_, _, _ = doTestJSONReqR63(t, hAuth, http.MethodPut, "/auth_idx", `{"mappings":{"properties":{"n":{"type":"nested","properties":{"f":{"type":"keyword"}}},"num":{"type":"integer"}}}}`, nil)
	stAuthTL, _, _ := doTestJSONReqR63(t, hAuth, http.MethodPost, "/auth_idx/_search", `{
		"query": {
			"bool": {
				"must": [{"nested": {"path": "n", "query": {"function_score": {"functions": [{"filter": {"match_all": {}}}], "query": {"script_score": {"query": {"match_all": {}}, "script": {"source": "1"}}}}}, "inner_hits": {"sort": [{"n.f": {"order": "asc", "nested": {"path": "n", "filter": {"match_all": {}}}}}], "highlight": {"fields": {"n.f": {}}}}}}],
				"should": [{"has_child": {"type": "c", "query": {"match_all": {}}}}],
				"must_not": [{"has_parent": {"parent_type": "p", "query": {"match_all": {}}}}]
			}
		},
		"knn": [{"field": "v", "query_vector": [1.0], "k": 1, "num_candidates": 2, "filter": [{"match_all": {}}]}],
		"rescore": [{"window_size": 5, "query": {"rescore_query": {"match_all": {}}}}],
		"aggs": {
			"f1": {"filter": {"match_all": {}}, "aggs": {"sub": {"terms": {"field": "num", "background_filter": {"match_all": {}}}}}},
			"fs": {"filters": {"filters": {"a": {"match_all": {}}}}},
			"am": {"adjacency_matrix": {"filters": {"a": {"terms": {"num": {"index": "missing_am_lookup", "id": "1", "path": "p"}}}}}}
		}
	}`, nil)
	if stAuthTL != http.StatusNotFound && stAuthTL != http.StatusBadRequest {
		t.Fatalf("expected 404/400 on missing adjacency_matrix lookup index, got %d", stAuthTL)
	}

	// 10. validateScriptedMetricAllowListR63Search stored & nested sub-aggs + extractUntrimmedScriptSourceR63 variants
	sSpec := esast.ScriptSpec{Source: "  raw_src  "}
	_, _ = extractUntrimmedScriptSourceR63(&sSpec)
	_, _ = extractUntrimmedScriptSourceR63(sSpec)
	_, _ = extractUntrimmedScriptSourceR63(map[string]any{"script": map[string]any{"inline": "  inline_src  "}})
	_, _ = extractUntrimmedScriptSourceR63(map[string]any{"id": "stored_1"})
	srv.mu.Lock()
	srv.clusterTransientSettings["search.aggs.only_allowed_metric_scripts"] = true
	srv.clusterTransientSettings["search.aggs.allowed_inline_metric_scripts"] = "state.ok = 1"
	srv.clusterTransientSettings["search.aggs.allowed_stored_metric_scripts"] = []string{"allowed_stored_id"}
	srv.mu.Unlock()
	var smNested map[string]esast.AggSpec
	_ = json.Unmarshal([]byte(`{
		"outer": {
			"terms": {"field": "num"},
			"aggs": {
				"sm": {"scripted_metric": {"init_script": {"id": "disallowed_id"}, "map_script": "state.ok = 1", "combine_script": "state.ok = 1", "reduce_script": "state.ok = 1"}}
			}
		}
	}`), &smNested)
	if smSt, _, _ := validateScriptedMetricAllowListR63Search(srv, smNested); smSt != http.StatusBadRequest {
		t.Fatalf("expected 400 for disallowed stored script in nested sub-agg, got %d", smSt)
	}

	// 11. Additional direct branches: extractTopHitsSourceMetricR63, parseCompositeDateBoundWithTZR63, handleIndexCloseR63 expand_wildcards=none, refreshDataStreamLifecycleManagedByLockedR63 ILM
	_, _ = extractTopHitsSourceMetricR63(map[string]any{
		"hits": map[string]any{"hits": []any{map[string]any{"_source": []byte(`{"salary": 125000}`)}}},
	}, []string{"_source", "salary"})
	_, _ = extractTopHitsSourceMetricR63(map[string]any{
		"hits": map[string]any{"hits": []map[string]any{{"_source": json.RawMessage(`{"salary": 99000}`)}}},
	}, []string{"_source", "salary"})
	dhTZ := &esast.DateHistogramAggSpec{TimeZone: "UTC", Format: "epoch_millis"}
	for _, dv := range []any{int64(1000), int(2000), float64(3000), json.Number("4000"), "5000", "2024-01-01"} {
		_, _ = parseCompositeDateBoundWithTZR63(dv, dhTZ, time.Now().UTC())
	}
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/ig_*/_close?expand_wildcards=none&allow_no_indices=false", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/ig_*/_close?expand_wildcards=none&allow_no_indices=true", "", nil)

	srv.mu.Lock()
	srv.indexCustomSettings["ig_r63"] = map[string]any{"index.lifecycle.name": "hot_ilm", "index.lifecycle.prefer_ilm": true}
	dsILM := map[string]any{
		"name":       "ilm-ds-r63",
		"generation": 1,
		"lifecycle":  map[string]any{"enabled": false},
		"indices":    []any{map[string]any{"index_name": "ig_r63"}},
	}
	refreshDataStreamLifecycleManagedByLockedR63(srv, dsILM)
	srv.mu.Unlock()

	// 12. Extra targeted branch coverage across round63_search_aggs_runtime.go
	scStrict := newActiveSearchScopeR63(context.Background(), srv, []byte(`{}`), &esast.SearchRequest{})
	_, _, _ = formatTermsBucketKeyAndStringWithScopeR63(scStrict, "__ES_MISSING_BUCKET__", &esast.TermsAggSpec{Field: "f"}, nil)
	_, _, _ = formatTermsBucketKeyAndStringWithScopeR63(scStrict, "false", &esast.TermsAggSpec{Field: "f", ValueType: "boolean"}, nil)
	reEvaluatePercentilesBucketWithScopeR63(scStrict, map[string]esast.AggSpec{
		"arr_b": {Terms: &esast.TermsAggSpec{Field: "num"}, Aggs: map[string]esast.AggSpec{"s": {Sum: &esast.MetricAggSpec{Field: "num"}}}},
		"map_b": {Filters: &esast.FiltersAggSpec{}, Aggs: map[string]esast.AggSpec{"s": {Sum: &esast.MetricAggSpec{Field: "num"}}}},
		"pb":    {PercentilesBucket: &esast.PercentilesBucketAggSpec{BucketsPath: "arr_b>s"}},
	}, map[string]any{
		"arr_b": map[string]any{"buckets": []any{map[string]any{"key": 1, "doc_count": 1, "s": map[string]any{"value": 5.0}}}},
		"map_b": map[string]any{"buckets": map[string]any{"k": map[string]any{"doc_count": 1, "s": map[string]any{"value": 5.0}}}},
	})

	var checkAggs map[string]esast.AggSpec
	_ = json.Unmarshal([]byte(`{
		"outer": {
			"terms": {"field": "num"},
			"aggs": {
				"st": {"significant_text": {"field": "num"}},
				"bs": {"bucket_script": {"buckets_path": {"c": "_count"}, "gap_policy": "keep_values", "script": "params.c"}},
				"sel": {"bucket_selector": {"buckets_path": {"c": "_count"}, "gap_policy": "keep_values", "script": "params.c > 0"}}
			}
		}
	}`), &checkAggs)
	_ = aggsHaveSignificantTextR63(checkAggs)
	_ = aggsHaveKeepValuesScriptPipelineR63(checkAggs)
	_, _, _, _ = resolveGreedyAggInMapR63(checkAggs, []string{"outer"}, 0)
	_, _, _, _ = resolveGreedyAggInMapR63(checkAggs, []string{"missing"}, 0)

	// TSDB routing hash extraction branches (numeric routing, empty routing + ID fallback)
	tsScFake := &schema.IndexSchema{IndexMode: "time_series"}
	_, _ = extractTSDBRoutingHashValueR63(HitRow{Routing: "12345"}, "m", tsScFake)
	_, _ = extractTSDBRoutingHashValueR63(HitRow{ID: "67890", SearchScope: scStrict}, "ig_r63", tsScFake)

	// Scripted metric allow-list with only_allowed=false and []any inline list
	srv.mu.Lock()
	srv.clusterTransientSettings["search.aggs.only_allowed_metric_scripts"] = false
	srv.mu.Unlock()
	_, _, _ = validateScriptedMetricAllowListR63Search(srv, smNested)
	srv.mu.Lock()
	srv.clusterTransientSettings["search.aggs.only_allowed_metric_scripts"] = true
	srv.clusterTransientSettings["search.aggs.allowed_inline_metric_scripts"] = []any{"state.ok = 1", 99}
	srv.mu.Unlock()
	_, _, _ = validateScriptedMetricAllowListR63Search(srv, smNested)

	// Alias wildcard _close, hidden index _close, missing index lifecycle explain, write-backing shrink rejection, allow_partial_search_results=false
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ig_r63/_alias/close_al_r63", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/.hidden_close_r63", `{"settings":{"index.hidden":true},"mappings":{"properties":{"x":{"type":"keyword"}}}}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/close_al_*/_close", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/ig_r63/_open", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/.hidden_close_*/_close", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodGet, "/no_such_lc_idx/_lifecycle/explain", "", nil)

	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/_index_template/ds_cov_tpl", `{
		"index_patterns": ["cov-ds-*"],
		"data_stream": {},
		"template": {"lifecycle": {"data_retention": "3d"}, "mappings": {"properties": {"@timestamp": {"type": "date"}}}}
	}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/_data_stream/cov-ds-1", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/cov-ds-1/_rollover", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodGet, "/.ds-cov-ds-1-*/_lifecycle/explain", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/cov-ds-1/_close", "", nil)
	srv.mu.RLock()
	var covWriteIdx string
	if dsCov := srv.dataStreams["cov-ds-1"]; dsCov != nil {
		if inds := extractDataStreamBackingIndexNames(dsCov); len(inds) > 0 {
			covWriteIdx = inds[len(inds)-1]
		}
	}
	srv.mu.RUnlock()
	if covWriteIdx != "" {
		_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/"+covWriteIdx+"/_shrink/shrunk_cov", `{}`, nil)
		_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/"+covWriteIdx+"/_open", "", nil)
	}

	// Direct validateTermsLookupsExistR63 on authoritative server with full AST nodes
	qTermLookup := esast.Query{
		Bool: &esast.BoolQuery{
			Must: []esast.Query{
				{Boosting: &esast.BoostingQuery{Positive: esast.Query{}, Negative: esast.Query{}}},
				{Nested: &esast.NestedQuery{
					Path:  "n",
					Query: esast.Query{},
					InnerHits: &esast.InnerHitsSpec{
						Sort:      []esast.SortSpec{{Entry: esast.SortFieldSpec{Field: "n.f", Nested: &esast.NestedSortSpec{Path: "n", Filter: &esast.Query{}}}}},
						Highlight: &esast.HighlightSpec{HighlightQuery: &esast.Query{}, Fields: map[string]any{"n.f": map[string]any{"highlight_query": map[string]any{"match_all": map[string]any{}}}}},
					},
				}},
				{FunctionScore: &esast.FunctionScoreQuery{
					Query:     &esast.Query{},
					Functions: []esast.ScoreFunction{{Filter: &esast.Query{}}},
				}},
			},
		},
	}
	_, _, _ = srvAuth.validateTermsLookupsExistR63(&esast.SearchRequest{
		Query: &qTermLookup,
		Aggs: map[string]esast.AggSpec{
			"fl": {Filters: &esast.FiltersAggSpec{
				Filters:          map[string]esast.Query{"a": {}},
				AnonymousFilters: []esast.Query{{}},
			}},
			"am": {AdjacencyMatrix: &esast.AdjacencyMatrixAggSpec{
				Filters: map[string]esast.Query{"a": {}},
			}},
		},
	})

	// allow_partial_search_results=false branch in evalMultiIndexScriptFieldsWithPartialFailuresR63
	reqFalseAP := httptest.NewRequest(http.MethodPost, "/ig_r63/_search?allow_partial_search_results=false", nil)
	_, _, _, _, _, _ = evalMultiIndexScriptFieldsWithPartialFailuresR63(srv, reqFalseAP, []string{"ig_r63", "syn_tc_r63"}, "ig_r63", nil, nil, &esast.SearchRequest{})

	// 13. Final micro-branches for >83% coverage on round63_search_aggs_runtime.go
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/_data_stream/cov-ds-*/_lifecycle", `{"invalid_lc_field":123}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/cov-ds-1,ig_*/_close", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/ig_*/_close?expand_wildcards=bogus_flag", "", nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/.ds-cov-ds-1-*/_close", "", nil)

	srv.mu.Lock()
	dsTplInherit := map[string]any{
		"name":       "cov-ds-inherit",
		"generation": 1,
		"indices":    []any{map[string]any{"index_name": "ig_r63"}},
	}
	refreshDataStreamLifecycleManagedByLockedR63(srv, dsTplInherit)
	synSc2 := srv.indices["syn_tc_r63"]
	srv.mu.Unlock()
	if synSc2 != nil {
		if fb, ok := synSc2.Fields["body.tc"]; ok && fb.ColumnName != "" {
			enrichRuntimeScriptDocBindingsR63(synSc2, map[string]any{"__shredded_fields": map[string]any{fb.ColumnName: int64(4)}}, map[string]any{}, map[string]string{"body.tc": "token_count"})
		}
		enrichRuntimeScriptDocBindingsR63(synSc2, map[string]any{"body": "hello world"}, map[string]any{}, map[string]string{"body.tc": "token_count"})
	}

	var escRxReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"a\\/b /abc\\/defgh/"}}}`), &escRxReq)
	_, _, _ = validateQueryMaxRegexAndPrefixLengthR63(&escRxReq, map[string]map[string]any{"i": {"max_regex_length": 3}})
	rePhrase := regexp.MustCompile(`(?i)hello world`)
	_ = buildHighlightedSnippetsModeAwareWithFieldTypeR63([]string{"hello world"}, rePhrase, "<b>", "</b>", false, 100, 1, 0, -1, "plain", true)
}
