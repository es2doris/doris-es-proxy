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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newR66TestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, srv.Handler()
}

func doR66Req(t *testing.T, h http.Handler, method, target, body string, headers map[string]string) (int, http.Header, map[string]any, string) {
	t.Helper()
	var rBody io.Reader
	if body != "" {
		rBody = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rBody)
	if body != "" {
		if _, ok := headers["Content-Type"]; !ok {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	}
	return rec.Code, rec.Header(), parsed, raw
}

type wrappedHandlerR66 struct {
	inner http.Handler
}

func (w wrappedHandlerR66) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	w.inner.ServeHTTP(rw, req)
}

func (w wrappedHandlerR66) Unwrap() http.Handler {
	return w.inner
}

func TestRound66_P0_1_StaticRepoSettingsRejectAndRestoreStrip(t *testing.T) {
	srv, h := newR66TestServer(t)

	// Handler exposes Server() any and static setters cleanly even if wrapped via Unwrap().
	sp, ok := h.(interface{ Server() any })
	if !ok || sp.Server() != srv {
		t.Fatalf("expected srv.Handler() to expose Server() == srv")
	}
	wrapped := http.Handler(wrappedHandlerR66{inner: h})
	if u, okU := wrapped.(interface{ Unwrap() http.Handler }); !okU || u.Unwrap() != h {
		t.Fatalf("expected Unwrap() delegation")
	}

	repoDir := t.TempDir()
	allowedURL := "http://127.0.0.1:*"
	if setter, okS := h.(interface{ SetStaticPathRepo([]string) }); !okS {
		t.Fatalf("expected Handler to implement SetStaticPathRepo")
	} else {
		setter.SetStaticPathRepo([]string{filepath.ToSlash(repoDir)})
	}
	if setter, okS := h.(interface{ SetStaticRepositoriesURLAllowedURLs([]string) }); !okS {
		t.Fatalf("expected Handler to implement SetStaticRepositoriesURLAllowedURLs")
	} else {
		setter.SetStaticRepositoriesURLAllowedURLs([]string{allowedURL})
	}

	// Dynamic PUT /_cluster/settings must reject static-only path.repo and repositories.url.allowed_urls.
	for _, key := range []string{
		"path.repo",
		"path.repo.custom",
		"repositories.url.allowed_urls",
		"repositories.url.allowed_urls.extra",
	} {
		for _, section := range []string{"persistent", "transient"} {
			body, err := json.Marshal(map[string]any{section: map[string]any{key: []string{"/tmp/bad"}}})
			if err != nil {
				t.Fatal(err)
			}
			st, _, res, raw := doR66Req(t, h, http.MethodPut, "/_cluster/settings", string(body), nil)
			if st != http.StatusBadRequest {
				t.Fatalf("expected 400 rejecting dynamic %s.%s, got %d: %s", section, key, st, raw)
			}
			if errObj, _ := res["error"].(map[string]any); errObj["type"] != "illegal_argument_exception" {
				t.Fatalf("expected illegal_argument_exception for %s.%s, got %+v", section, key, res)
			}
		}
	}
	// Nested object form in PUT /_cluster/settings must also fail.
	for _, nested := range []string{
		`{"persistent":{"path":{"repo":["/tmp/bad"]}}}`,
		`{"transient":{"repositories":{"url":{"allowed_urls":["http://*"]}}}}`,
	} {
		st, _, _, raw := doR66Req(t, h, http.MethodPut, "/_cluster/settings", nested, nil)
		if st != http.StatusBadRequest || !strings.Contains(raw, "illegal_argument_exception") {
			t.Fatalf("expected 400 illegal_argument_exception for nested %s, got %d: %s", nested, st, raw)
		}
	}

	// GET /_cluster/settings?include_defaults=true must surface static defaults.repo settings.
	st, _, settingsRes, raw := doR66Req(t, h, http.MethodGet, "/_cluster/settings?include_defaults=true", "", nil)
	if st != http.StatusOK {
		t.Fatalf("GET /_cluster/settings?include_defaults=true failed: %d %s", st, raw)
	}
	defaults, _ := settingsRes["defaults"].(map[string]any)
	pathDef, _ := defaults["path"].(map[string]any)
	reposDef, _ := defaults["repositories"].(map[string]any)
	if pathDef == nil {
		t.Fatalf("expected defaults.path.repo in cluster settings, got %+v", settingsRes)
	}
	if repoSlice, _ := pathDef["repo"].([]any); len(repoSlice) != 1 {
		t.Fatalf("expected 1 defaults.path.repo entry, got %+v", pathDef["repo"])
	}
	urlDef, _ := reposDef["url"].(map[string]any)
	if urlDef == nil {
		t.Fatalf("expected defaults.repositories.url.allowed_urls in cluster settings, got %+v", settingsRes)
	}
	if urlSlice, _ := urlDef["allowed_urls"].([]any); len(urlSlice) != 1 || urlSlice[0] != allowedURL {
		t.Fatalf("expected defaults.repositories.url.allowed_urls=[%q], got %+v", allowedURL, urlDef["allowed_urls"])
	}

	// Create snapshot with poisoned __cluster_persistent_settings including static keys + non-static key, then _restore.
	if st, _, _, raw = doR66Req(t, h, http.MethodPut, "/_snapshot/r_static", fmt.Sprintf(`{"type":"fs","settings":{"location":%q}}`, repoDir), nil); st != http.StatusOK {
		t.Fatalf("PUT _snapshot/r_static failed: %d %s", st, raw)
	}
	if st, _, _, raw = doR66Req(t, h, http.MethodPut, "/snap_src_idx", `{}`, nil); st != http.StatusOK {
		t.Fatalf("create idx failed: %d %s", st, raw)
	}
	if st, _, _, raw = doR66Req(t, h, http.MethodPut, "/_snapshot/r_static/snap1?wait_for_completion=true", `{"indices":"snap_src_idx","include_global_state":true}`, nil); st != http.StatusOK {
		t.Fatalf("PUT snap failed: %d %s", st, raw)
	}

	// Inject poisoned static-only settings + harmless cluster setting into snapshot global state.
	srv.mu.Lock()
	snapObj := srv.snapshots["r_static"]["snap1"]
	snapObj["__cluster_persistent_settings"] = map[string]any{
		"path.repo":                         []string{"/tmp/poisoned"},
		"path.repo.sub":                     "/tmp/poisoned2",
		"repositories.url.allowed_urls":     []string{"http://evil/*"},
		"reindex.remote.whitelist":          "evil:9200",
		"search.max_buckets":                12345,
		"path":                              map[string]any{"repo": []string{"/tmp/nested"}},
		"repositories":                      map[string]any{"url": map[string]any{"allowed_urls": []string{"http://nested/*"}}},
		"cluster.routing.allocation.enable": "all",
	}
	srv.mu.Unlock()

	if st, _, _, raw = doR66Req(t, h, http.MethodDelete, "/snap_src_idx", "", nil); st != http.StatusOK {
		t.Fatalf("delete idx failed: %d %s", st, raw)
	}
	if st, _, _, raw = doR66Req(t, h, http.MethodPost, "/_snapshot/r_static/snap1/_restore?wait_for_completion=true", `{"include_global_state":true}`, nil); st != http.StatusOK {
		t.Fatalf("restore failed: %d %s", st, raw)
	}

	srv.mu.RLock()
	persisted := srv.clusterPersistentSettings
	_, hasFlatPath := persisted["path.repo"]
	_, hasSubPath := persisted["path.repo.sub"]
	_, hasFlatURL := persisted["repositories.url.allowed_urls"]
	_, hasReindex := persisted["reindex.remote.whitelist"]
	_, hasNestedPath := persisted["path"]
	_, hasNestedRepos := persisted["repositories"]
	keptMaxBuckets := persisted["search.max_buckets"]
	srv.mu.RUnlock()
	if hasFlatPath || hasSubPath || hasFlatURL || hasReindex || hasNestedPath || hasNestedRepos {
		t.Fatalf("expected _restore to strip all static-only settings, got persistent=%+v", persisted)
	}
	if fmt.Sprintf("%v", keptMaxBuckets) != "12345" {
		t.Fatalf("expected non-static restored setting search.max_buckets preserved, got %v", keptMaxBuckets)
	}

	// Close clears static repo settings cleanly.
	_ = srv.Close(context.Background())
	if len(srv.getStaticPathReposResolvedR66()) != 0 || len(srv.getStaticAllowedRepoURLsR66()) != 0 {
		t.Fatalf("expected Close() to clear static repo slices")
	}
}

func TestRound66_P0_2_SnapshotConcurrentNoDeadlock(t *testing.T) {
	srv, h := newR66TestServer(t)
	repoDir := t.TempDir()
	srv.SetStaticPathRepo([]string{filepath.ToSlash(repoDir)})

	if st, _, _, raw := doR66Req(t, h, http.MethodPut, "/_snapshot/snap_repo", fmt.Sprintf(`{"type":"fs","settings":{"location":%q}}`, repoDir), nil); st != http.StatusOK {
		t.Fatalf("create repo failed: %d %s", st, raw)
	}
	if st, _, _, raw := doR66Req(t, h, http.MethodPut, "/snap_dl_idx", `{"settings":{"number_of_shards":2,"number_of_replicas":1}}`, nil); st != http.StatusOK {
		t.Fatalf("create idx failed: %d %s", st, raw)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 6; i++ {
			idx := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				st, _, _, raw := doR66Req(t, h, http.MethodPut, fmt.Sprintf("/_snapshot/snap_repo/s_%d?wait_for_completion=true", idx), `{"indices":"snap_dl_idx"}`, nil)
				if st != http.StatusOK {
					t.Errorf("snapshot s_%d failed: %d %s", idx, st, raw)
				}
				_, _, _, _ = doR66Req(t, h, http.MethodGet, fmt.Sprintf("/_snapshot/snap_repo/s_%d", idx), "", nil)
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("snapshot operations deadlocked")
	}
}

func TestRound66_P0_3_RollupCoWConcurrentRace(t *testing.T) {
	srv, h := newR66TestServer(t)
	if st, _, _, raw := doR66Req(t, h, http.MethodPut, "/rollup_src", `{"mappings":{"properties":{"ts":{"type":"date"},"host":{"type":"keyword"}}}}`, nil); st != http.StatusOK {
		t.Fatalf("create source idx failed: %d %s", st, raw)
	}
	// Seed rollup_dest via an initial rollup job so subsequent concurrent jobs share & CoW-clone rollup_dest.
	seedBody := `{
		"index_pattern":"rollup_src",
		"rollup_index":"rollup_dest",
		"cron":"0 * * * * ?",
		"page_size":100,
		"groups":{"date_histogram":{"field":"ts","calendar_interval":"hour"}}
	}`
	if st, _, _, raw := doR66Req(t, h, http.MethodPut, "/_rollup/job/job_seed", seedBody, nil); st != http.StatusOK {
		t.Fatalf("create seed rollup job failed: %d %s", st, raw)
	}
	_ = srv

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		id := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			jobBody := `{
				"index_pattern":"rollup_src",
				"rollup_index":"rollup_dest",
				"cron":"0 * * * * ?",
				"page_size":100,
				"groups":{"date_histogram":{"field":"ts","calendar_interval":"hour"}}
			}`
			st, _, _, raw := doR66Req(t, h, http.MethodPut, fmt.Sprintf("/_rollup/job/job_%d", id), jobBody, nil)
			if st != http.StatusOK {
				t.Errorf("create rollup job_%d failed: %d %s", id, st, raw)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _ = doR66Req(t, h, http.MethodGet, "/rollup_dest/_mapping", "", nil)
			_, _, _, _ = doR66Req(t, h, http.MethodPost, "/rollup_dest/_search", `{"query":{"match_all":{}}}`, nil)
		}()
	}
	wg.Wait()
}

func TestRound66_P0_4_HistogramSignedOverflowAndCrossDocCap(t *testing.T) {
	// 1. Overflow-safe subtraction in collectMetricRawValuesOrHistogramR65.
	histSchema := &schema.IndexSchema{
		IndexName: "hist_r66",
		Fields: map[string]schema.FieldBinding{
			"h": {ESFieldPath: "h", ColumnName: "f__h", ESType: "histogram"},
		},
	}
	doc := map[string]any{
		"h": map[string]any{
			"values": []any{float64(1.0), float64(2.0), float64(3.0)},
			"counts": []any{int64(math.MaxInt64), int64(math.MaxInt64), int64(500)},
		},
	}
	expanded := collectMetricRawValuesOrHistogramR65(histSchema, doc, "h", []string{"h"})
	if len(expanded) != 100000 {
		t.Fatalf("expected expanded length capped cleanly at 100000, got %d", len(expanded))
	}

	// 2. Cumulative cross-doc cap in emitRuntimeHistogramFieldHDRRawRowsR65.
	const numDocs = 15
	docs := make([]runtimeMatchedDoc, numDocs)
	for i := 0; i < numDocs; i++ {
		docs[i] = runtimeMatchedDoc{
			rootSchema: histSchema,
			doc: map[string]any{
				"h": map[string]any{
					"values": []any{float64(i + 1)},
					"counts": []any{int64(150000)},
				},
			},
		}
	}
	rows := emitRuntimeHistogramFieldHDRRawRowsR65("p", "", &esast.PercentilesAggSpec{Field: "h"}, docs, nil)
	if len(rows) != 1 {
		t.Fatalf("expected 1 emitted raw HDR row, got %d", len(rows))
	}
	if rows[0].DocCount != 1000000 {
		t.Fatalf("expected cumulative cross-doc cap of 1000000 samples, got %d", rows[0].DocCount)
	}
}

func TestRound66_P1_AuthDLSFilteredAliasesAndCache(t *testing.T) {
	srv, h := newR66TestServer(t)

	// Setup index + filtered aliases + denied index for _terms_enum tests.
	srv.SetAuth("secadmin", "setup-pw", "")
	setupHdr := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("secadmin:setup-pw"))}
	for _, setup := range []struct {
		method, path, body string
	}{
		{http.MethodPut, "/cat_shared", `{"mappings":{"properties":{"tenant":{"type":"keyword"},"tag":{"type":"keyword"}}}}`},
		{http.MethodPut, "/other_secret", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`},
		{http.MethodPost, "/cat_shared/_doc/1?refresh=true", `{"tenant":"acme","tag":"acme-only"}`},
		{http.MethodPost, "/cat_shared/_doc/2?refresh=true", `{"tenant":"globex","tag":"globex-secret"}`},
		{http.MethodPost, "/other_secret/_doc/1?refresh=true", `{"tag":"ultra-secret"}`},
		{http.MethodPost, "/_aliases", `{"actions":[
			{"add":{"index":"cat_shared","alias":"alias_acme","filter":{"term":{"tenant":"acme"}}}},
			{"add":{"index":"cat_shared","alias":"alias_globex","filter":{"term":{"tenant":"globex"}}}}
		]}`},
		{http.MethodPost, "/_security/role/acme_role", `{"indices":[{"names":["alias_acme"],"privileges":["read"]}]}`},
		{http.MethodPost, "/_security/role/dls_all_role", `{"indices":[{"names":["cat_shared"],"privileges":["read"],"query":{"match_all":{}}}]}`},
		{http.MethodPost, "/_security/user/acme_user", `{"password":"acme-pw","roles":["acme_role"]}`},
		{http.MethodPost, "/_security/user/cat_user", `{"password":"cat-pw","roles":["dls_all_role"]}`},
		{http.MethodPost, "/_security/user/disabled_u", `{"password":"dis-pw","enabled":false,"roles":["superuser"]}`},
	} {
		st, _, _, raw := doR66Req(t, h, setup.method, setup.path, setup.body, setupHdr)
		if st != http.StatusOK && st != http.StatusCreated {
			t.Fatalf("%s %s failed: %d %s", setup.method, setup.path, st, raw)
		}
	}
	srv.SetAuth("", "", "")

	basic := func(u, p string) map[string]string {
		return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))}
	}

	// 1. Filtered alias enforcement across mixed targets (denied other_secret) and sibling filtered aliases (alias_globex).
	for _, endpoint := range []string{
		"/alias_acme,other_secret/_terms_enum",
		"/alias_acme,alias_globex/_terms_enum",
	} {
		st, _, res, raw := doR66Req(t, h, http.MethodPost, endpoint, `{"field":"tag"}`, basic("acme_user", "acme-pw"))
		if st != http.StatusOK {
			t.Fatalf("POST %s failed: %d %s", endpoint, st, raw)
		}
		terms, _ := res["terms"].([]any)
		if len(terms) != 1 || terms[0] != "acme-only" {
			t.Fatalf("expected ONLY [acme-only] from %s, got %+v", endpoint, res)
		}
	}

	// 2. Password verification, unconfigured elastic rejection, API key secret + expiration rejection.
	for _, deniedHdr := range []map[string]string{
		basic("elastic", "wrong-any"),
		basic("cat_user", "wrong-pw"),
		basic("disabled_u", "dis-pw"),
	} {
		st, _, res, _ := doR66Req(t, h, http.MethodPost, "/cat_shared/_terms_enum", `{"field":"tag"}`, deniedHdr)
		if st != http.StatusUnauthorized {
			t.Fatalf("expected 401 unauthorized for denied credentials %v, got %d (%+v)", deniedHdr, st, res)
		}
		if terms, _ := res["terms"].([]any); len(terms) != 0 {
			t.Fatalf("expected denied credentials %v to yield 0 terms, got %+v", deniedHdr, res)
		}
	}

	// Valid cat_user password succeeds.
	st, _, res, _ := doR66Req(t, h, http.MethodPost, "/cat_shared/_terms_enum", `{"field":"tag"}`, basic("cat_user", "cat-pw"))
	if st != http.StatusOK {
		t.Fatalf("valid cat_user failed: %d", st)
	}
	if terms, _ := res["terms"].([]any); len(terms) != 2 {
		t.Fatalf("expected 2 terms for valid cat_user, got %+v", res)
	}

	// Expired API key fails, valid API key succeeds, wrong secret fails.
	st, _, akRes, raw := doR66Req(t, h, http.MethodPost, "/_security/api_key", `{"name":"short_live","expiration":"5s"}`, basic("cat_user", "cat-pw"))
	if st != http.StatusOK {
		t.Fatalf("create api_key failed: %d %s", st, raw)
	}
	keyID, _ := akRes["id"].(string)
	encodedAK, _ := akRes["encoded"].(string)

	st, _, res, _ = doR66Req(t, h, http.MethodPost, "/cat_shared/_terms_enum", `{"field":"tag"}`, map[string]string{"Authorization": "ApiKey " + encodedAK})
	if st != http.StatusOK {
		t.Fatalf("valid apiKey failed: %d", st)
	}
	if terms, _ := res["terms"].([]any); len(terms) != 2 {
		t.Fatalf("expected 2 terms for valid ApiKey, got %+v", res)
	}

	// Wrong secret for keyID fails.
	badAK := base64.StdEncoding.EncodeToString([]byte(keyID + ":wrong-secret"))
	_, _, res, _ = doR66Req(t, h, http.MethodPost, "/cat_shared/_terms_enum", `{"field":"tag"}`, map[string]string{"Authorization": "ApiKey " + badAK})
	if terms, _ := res["terms"].([]any); len(terms) != 0 {
		t.Fatalf("expected wrong ApiKey secret denied, got %+v", res)
	}

	// Force expiration into past -> must fail closed.
	srv.mu.Lock()
	srv.securityAPIKeys[keyID]["expiration"] = time.Now().Add(-time.Minute).UnixMilli()
	srv.mu.Unlock()
	_, _, res, _ = doR66Req(t, h, http.MethodPost, "/cat_shared/_terms_enum", `{"field":"tag"}`, map[string]string{"Authorization": "ApiKey " + encodedAK})
	if terms, _ := res["terms"].([]any); len(terms) != 0 {
		t.Fatalf("expected expired ApiKey denied, got %+v", res)
	}

	// 3. Fixture test_admin backdoor disabled when s.apiKey != "", and concurrent SetAuth + FilterTermsEnum safe under -race.
	var raceWG sync.WaitGroup
	raceWG.Add(2)
	go func() {
		defer raceWG.Done()
		for i := 0; i < 40; i++ {
			srv.SetAuth("", "", "proxy-secret-token")
			srv.SetAuth("", "", "")
		}
	}()
	go func() {
		defer raceWG.Done()
		for i := 0; i < 40; i++ {
			req := httptest.NewRequest(http.MethodPost, "/cat_shared/_terms_enum", nil)
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test_admin:x-pack-test-password")))
			_ = srv.FilterTermsEnumByDLSWithRawTargetsR65(req, "cat_shared", []string{"cat_shared"}, "tag")
		}
	}()
	raceWG.Wait()

	srv.SetAuth("", "", "proxy-secret-token")
	reqTA := httptest.NewRequest(http.MethodPost, "/cat_shared/_terms_enum", nil)
	reqTA.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("test_admin:x-pack-test-password")))
	if srv.FilterTermsEnumByDLSWithRawTargetsR65(reqTA, "cat_shared", []string{"cat_shared"}, "tag") {
		t.Fatalf("expected test_admin fixture backdoor rejected when apiKey is configured")
	}
	srv.SetAuth("", "", "")

	// 4. QueryResultCache auth/runas isolation on size > 0 queries.
	srv.SetQueryCacheTTL(30*time.Second, 64)
	searchBody := `{"size":5,"query":{"match_all":{}}}`
	st, _, _, raw = doR66Req(t, h, http.MethodPost, "/cat_shared/_search", searchBody, basic("acme_user", "acme-pw"))
	if st != http.StatusOK {
		t.Fatalf("search as acme_user failed: %d %s", st, raw)
	}
	st, _, _, raw = doR66Req(t, h, http.MethodPost, "/cat_shared/_search", searchBody, basic("acme_user", "acme-pw"))
	if st != http.StatusOK {
		t.Fatalf("cached search as acme_user failed: %d %s", st, raw)
	}
	hits1, misses1 := srv.queryCache.Stats()
	if hits1 != 1 || misses1 != 1 {
		t.Fatalf("expected 1 hit / 1 miss for same user, got hits=%d misses=%d", hits1, misses1)
	}

	// Different user / runas header MUST miss cache rather than reusing acme_user's cached result.
	st, _, _, _ = doR66Req(t, h, http.MethodPost, "/cat_shared/_search", searchBody, basic("cat_user", "cat-pw"))
	if st != http.StatusOK {
		t.Fatalf("search as cat_user failed: %d", st)
	}
	hits2, misses2 := srv.queryCache.Stats()
	if hits2 != 1 || misses2 != 2 {
		t.Fatalf("expected cross-user QueryResultCache miss (hits=1 misses=2), got hits=%d misses=%d", hits2, misses2)
	}

	runAsHdr := basic("cat_user", "cat-pw")
	runAsHdr["es-security-runas-user"] = "acme_user"
	st, _, _, _ = doR66Req(t, h, http.MethodPost, "/cat_shared/_search", searchBody, runAsHdr)
	if st != http.StatusOK {
		t.Fatalf("search with runas failed: %d", st)
	}
	hits3, misses3 := srv.queryCache.Stats()
	if hits3 != 1 || misses3 != 3 {
		t.Fatalf("expected runas user QueryResultCache miss (hits=1 misses=3), got hits=%d misses=%d", hits3, misses3)
	}
}

func TestRound66_P1_MonitoringBulkAuthAndValidation(t *testing.T) {
	srv, h := newR66TestServer(t)

	srv.mu.Lock()
	srv.securityRoles["mon_only"] = map[string]any{"cluster": []any{"monitor"}}
	srv.securityRoles["mon_bulk"] = map[string]any{"cluster": []any{"manage_monitoring"}}
	srv.securityUsers["mon_reader"] = map[string]any{"password": "pw1", "roles": []any{"mon_only"}, "enabled": true}
	srv.securityUsers["mon_writer"] = map[string]any{"password": "pw2", "roles": []any{"mon_bulk"}, "enabled": true}
	srv.securityUsers["mon_disabled"] = map[string]any{"password": "pw3", "roles": []any{"superuser"}, "enabled": false}
	srv.securityAPIKeys["mon_key"] = map[string]any{
		"id":              "mon_key",
		"username":        "mon_writer",
		"__secret_sha256": hashSecuritySecretR66("mon-secret"),
		"invalidated":     false,
	}
	srv.mu.Unlock()

	ndjson := "{\"index\":{}}\n{\"cpu\":1.0}\n"
	validURL := "/_monitoring/bulk?system_id=beats&system_api_version=8.15.5&interval=10s"

	// Unknown user (uObj == nil), wrong password, disabled user, invalid ApiKey must fail closed (401/403).
	for _, hdr := range []map[string]string{
		{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("ghost_user:any"))},
		{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("mon_writer:wrong-pw"))},
		{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("mon_disabled:pw3"))},
		{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("mon_reader:pw1"))},
		{"Authorization": "ApiKey " + base64.StdEncoding.EncodeToString([]byte("mon_key:wrong-secret"))},
		{"Authorization": "Bearer bogus-token"},
	} {
		st, _, res, raw := doR66Req(t, h, http.MethodPost, validURL, ndjson, hdr)
		if st != http.StatusUnauthorized && st != http.StatusForbidden {
			t.Fatalf("expected 401/403 for %v, got %d: %s", hdr, st, raw)
		}
		if errObj, _ := res["error"].(map[string]any); errObj["type"] != "security_exception" {
			t.Fatalf("expected security_exception, got %+v", res)
		}
	}

	// Valid user password & valid ApiKey succeed.
	for _, hdr := range []map[string]string{
		{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("mon_writer:pw2"))},
		{"Authorization": "ApiKey " + base64.StdEncoding.EncodeToString([]byte("mon_key:mon-secret"))},
	} {
		st, _, _, raw := doR66Req(t, h, http.MethodPost, validURL, ndjson, hdr)
		if st != http.StatusOK {
			t.Fatalf("expected 200 for valid auth %v, got %d: %s", hdr, st, raw)
		}
	}

	// Malformed/injection system_id or system_api_version must fail with 400 illegal_argument_exception.
	validAuth := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("mon_writer:pw2"))}
	for _, badURL := range []string{
		"/_monitoring/bulk?system_id=../evil&system_api_version=7&interval=10s",
		"/_monitoring/bulk?system_id=beats*&system_api_version=7&interval=10s",
		"/_monitoring/bulk?system_id=a+b&system_api_version=7&interval=10s",
		"/_monitoring/bulk?system_id=beats&system_api_version=7..1&interval=10s",
		"/_monitoring/bulk?system_id=beats&system_api_version=7/../../x&interval=10s",
		"/_monitoring/bulk?system_id=beats&system_api_version=1.2.3.4&interval=10s",
	} {
		st, _, _, raw := doR66Req(t, h, http.MethodPost, badURL, ndjson, validAuth)
		if st != http.StatusBadRequest || !strings.Contains(raw, "illegal_argument_exception") {
			t.Fatalf("expected 400 illegal_argument_exception for %s, got %d: %s", badURL, st, raw)
		}
	}
}

func TestRound66_P1_ExpandIngestTemplateCaps(t *testing.T) {
	// 1. Depth <= 32 allowed; depth 33 nested {{#url}} returns error.
	nested32 := strings.Repeat("{{#url}}", 32) + "{{q}}" + strings.Repeat("{{/url}}", 32)
	if out, err := expandIngestTemplate(nested32, map[string]any{"q": "abc"}); err != nil || out != "abc" {
		t.Fatalf("expected depth-32 template to succeed with 'abc', got out=%v err=%v", out, err)
	}
	nested33 := "{{#url}}" + nested32 + "{{/url}}"
	if _, err := expandIngestTemplate(nested33, map[string]any{"q": "abc"}); err == nil {
		t.Fatalf("expected depth-33 {{#url}} template to fail with recursion depth error")
	}

	// 2. Depth 33 nested map returns error.
	deepMap := map[string]any{"leaf": "ok"}
	for i := 0; i < 33; i++ {
		deepMap = map[string]any{"next": deepMap}
	}
	if _, err := expandIngestTemplate(deepMap, nil); err == nil {
		t.Fatalf("expected depth-33 map to fail with recursion depth error")
	}

	// 3. Exponential {{#url}} amplification (> 4 MiB) returns error immediately instead of OOM.
	bigDoc := map[string]any{"big": strings.Repeat("%", 1<<20)}
	expTemplate := strings.Repeat("{{#url}}", 5) + "{{big}}" + strings.Repeat("{{/url}}", 5)
	if _, err := expandIngestTemplate(expTemplate, bigDoc); err == nil {
		t.Fatalf("expected >4 MiB amplified output to fail with size limit error")
	}
}

func TestRound66_P1_LazyRolloverTOCTOUAndTemporalRanges(t *testing.T) {
	srv, h := newR66TestServer(t)

	// Configure a time_series data stream template and existing data stream with prior temporal_ranges + __lazy_rollover.
	if st, _, _, raw := doR66Req(t, h, http.MethodPut, "/_index_template/ts_tpl_r66", `{
		"index_patterns": ["ts_ds_r66*"],
		"data_stream": {},
		"template": {
			"settings": {"index.mode": "time_series", "index.routing_path": ["host"]},
			"mappings": {"properties": {"@timestamp": {"type": "date"}, "host": {"type": "keyword", "time_series_dimension": true}}}
		}
	}`, nil); st != http.StatusOK {
		t.Fatalf("create template failed: %d %s", st, raw)
	}
	if st, _, _, raw := doR66Req(t, h, http.MethodPut, "/_data_stream/ts_ds_r66", "", nil); st != http.StatusOK {
		t.Fatalf("create data stream failed: %d %s", st, raw)
	}

	srv.mu.Lock()
	ds := srv.dataStreams["ts_ds_r66"]
	priorRange := map[string]any{"start": "2020-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"}
	ds["time_series"] = map[string]any{
		"temporal_ranges": []any{priorRange},
	}
	dsSnap := deepCloneDocMap(ds)
	srv.mu.Unlock()
	srv.persistDataStream(context.Background(), "ts_ds_r66", dsSnap)

	if st, _, _, raw := doR66Req(t, h, http.MethodPost, "/ts_ds_r66/_rollover?lazy=true", "", nil); st != http.StatusOK {
		t.Fatalf("lazy rollover failed: %d %s", st, raw)
	}

	// Concurrent writes against __lazy_rollover must execute AT MOST ONE rollover and preserve priorRange.
	const workers = 6
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < workers; i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			tsNow := time.Now().UTC().Format(time.RFC3339)
			body := fmt.Sprintf(`{"@timestamp":%q,"host":"h-%d"}`, tsNow, idx)
			st, _, _, raw := doR66Req(t, h, http.MethodPost, "/ts_ds_r66/_doc", body, nil)
			if st != http.StatusCreated && st != http.StatusOK {
				t.Errorf("concurrent DS create failed: %d %s", st, raw)
			}
		}()
	}
	close(gate)
	wg.Wait()

	srv.mu.RLock()
	finalDS := srv.dataStreams["ts_ds_r66"]
	gen, _ := toInt64(finalDS["generation"])
	indices, _ := finalDS["indices"].([]any)
	_, stillLazy := finalDS["__lazy_rollover"]
	tsObj, _ := finalDS["time_series"].(map[string]any)
	ranges, _ := tsObj["temporal_ranges"].([]any)
	srv.mu.RUnlock()

	if stillLazy {
		t.Fatalf("expected __lazy_rollover flag cleared after rollover")
	}
	if gen != 2 || len(indices) != 2 {
		t.Fatalf("expected single rollover to generation 2 (2 backing indices), got gen=%d indices=%d", gen, len(indices))
	}
	if len(ranges) != 2 {
		t.Fatalf("expected priorRange preserved plus 1 new range (len=2), got %+v", ranges)
	}
	if r0, _ := ranges[0].(map[string]any); r0["start"] != "2020-01-01T00:00:00Z" {
		t.Fatalf("expected prior temporal_range preserved at index 0, got %+v", r0)
	}
}

func TestRound66_P1_PerServerTelemetryNoLeakedGlobalMaps(t *testing.T) {
	srv1, h1 := newR66TestServer(t)
	srv2, h2 := newR66TestServer(t)

	// Exercise all 5 telemetry trackers across 2 independent servers without cross-talk or global registries.
	_, _, _, _ = doR66Req(t, h1, http.MethodPost, "/_license/start_trial?acknowledge=true", "", nil)
	_, _, _, _ = doR66Req(t, h1, http.MethodGet, "/_health_report", "", nil)
	_, _, _, _ = doR66Req(t, h1, http.MethodPost, "/_query", `{"query":"SHOW TABLES"}`, nil)
	_, _, _, _ = doR66Req(t, h1, http.MethodGet, "/_enrich/_stats", "", nil)
	getEnrichExecSearchesCounterR64(srv1).Add(5)
	_ = getAnalyticsUsageTrackerR65(srv1)
	_ = getHealthAPIUsageTrackerR65(srv1)
	_ = getOrCreateESQLTelemetryR64(srv1)

	if isLicenseTrialActivatedR65(srv2) {
		t.Fatalf("srv1 trial activation leaked into srv2")
	}
	if getEnrichExecSearchesCounterR64(srv2).Load() != 0 {
		t.Fatalf("srv1 enrich exec counter leaked into srv2")
	}
	_, _, _, _ = doR66Req(t, h2, http.MethodGet, "/_enrich/_stats", "", nil)
}

func TestRound66_P2_NormalizerRefreshAutoscalingAcceptQAndGraphExplore(t *testing.T) {
	// 1. P2-1: syncCatalogFromBackend preserves normalizer flags via CopyIndexMappingSettingsFrom.
	mem := NewMemoryBackend(false)
	srv := NewServer("es_db", mem, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	h := srv.Handler()

	createBody := `{
		"settings":{"analysis":{"normalizer":{"lc":{"type":"custom","filter":["lowercase"]}}}},
		"mappings":{"properties":{"kw":{"type":"keyword","normalizer":"lc"}}}
	}`
	if st, _, _, raw := doR66Req(t, h, http.MethodPut, "/norm_sync_idx", createBody, nil); st != http.StatusOK {
		t.Fatalf("create norm_sync_idx failed: %d %s", st, raw)
	}
	// Force syncCatalogFromBackend reload over existing prevSchema by bumping UpdatedEpochMs in catalog backend.
	entries, err := mem.LoadCatalogEntries(context.Background(), "es_db")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.EntityType == "index" && e.EntityKey == "norm_sync_idx" {
			e.UpdatedEpochMs = time.Now().UnixMilli() + 1000
			if err := mem.UpsertCatalogEntry(context.Background(), "es_db", e); err != nil {
				t.Fatal(err)
			}
		}
	}
	srv.mu.Lock()
	kwBinding := srv.indices["norm_sync_idx"].Fields["kw"]
	kwBinding.LowercaseNormalizer = false
	srv.indices["norm_sync_idx"].Fields["kw"] = kwBinding
	srv.mu.Unlock()
	if err := srv.syncCatalogFromBackend(context.Background()); err != nil {
		t.Fatalf("syncCatalogFromBackend failed: %v", err)
	}
	srv.mu.RLock()
	reloadedField := srv.indices["norm_sync_idx"].Fields["kw"]
	srv.mu.RUnlock()
	if !reloadedField.LowercaseNormalizer {
		t.Fatalf("expected syncCatalogFromBackend to refresh LowercaseNormalizer=true")
	}

	// 2. P2-2: parseAutoscalingByteSizeR65 rejects NaN/Inf/overflow and saturatingMulInt64R66 clamps.
	for _, bad := range []any{"NaN", "Inf", "-Inf", "+Inf", "9223372036854775808b", "10000pb", math.NaN(), math.Inf(1), float64(9223372036854775808.0)} {
		if _, err := parseAutoscalingByteSizeR65(bad); err == nil {
			t.Fatalf("expected parseAutoscalingByteSizeR65(%v) to reject non-finite or overflowing input", bad)
		}
	}
	if got := saturatingMulInt64R66(math.MaxInt64/2, 4); got != math.MaxInt64 {
		t.Fatalf("expected saturatingMulInt64R66 overflow to saturate at MaxInt64, got %d", got)
	}

	// 3. P2-3: setESCompatHeadersWireR64 respects highest q weight when application/json beats vnd.opensearch+json.
	reqCompat := httptest.NewRequest(http.MethodGet, "/", nil)
	reqCompat.Header.Set("Content-Type", "application/vnd.opensearch+json; compatible-with=2")
	reqCompat.Header.Set("Accept", "application/vnd.opensearch+json;q=0.5, application/json;q=0.9")
	recCompat := httptest.NewRecorder()
	setESCompatHeadersWireR64(recCompat, reqCompat)
	if ct := recCompat.Header().Get("Content-Type"); ct != "application/json; charset=UTF-8" {
		t.Fatalf("expected application/json; charset=UTF-8 for higher-q Accept, got %q", ct)
	}

	// 4. P2-4: handleGraphExplore caps extreme size/sample_size/field specs safely.
	if st, _, _, raw := doR66Req(t, h, http.MethodPut, "/graph_idx", `{"mappings":{"properties":{"tags":{"type":"keyword"}}}}`, nil); st != http.StatusOK {
		t.Fatalf("create graph_idx failed: %d %s", st, raw)
	}
	manyTags := make([]string, 300)
	for i := range manyTags {
		manyTags[i] = fmt.Sprintf("t%d", i)
	}
	docBytes, err := json.Marshal(map[string]any{"tags": manyTags})
	if err != nil {
		t.Fatal(err)
	}
	if st, _, _, raw := doR66Req(t, h, http.MethodPost, "/graph_idx/_doc/1?refresh=true", string(docBytes), nil); st != http.StatusCreated && st != http.StatusOK {
		t.Fatalf("index graph doc failed: %d %s", st, raw)
	}
	st, _, gRes, raw := doR66Req(t, h, http.MethodPost, "/graph_idx/_graph/explore", `{"controls":{"sample_size":999999},"vertices":[{"field":"tags","size":999999}]}`, nil)
	if st != http.StatusOK {
		t.Fatalf("graph explore failed: %d %s", st, raw)
	}
	if verts, _ := gRes["vertices"].([]any); len(verts) > 100 {
		t.Fatalf("expected graph vertices capped at <= 100, got %d", len(verts))
	}
}
