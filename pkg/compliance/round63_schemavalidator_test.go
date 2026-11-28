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

package compliance_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/compliance"
	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func resolveSchemaJSONForRound63Test(t *testing.T) string {
	t.Helper()
	var cands []string
	if cacheDir := os.Getenv("CONFORMANCE_CACHE_DIR"); cacheDir != "" {
		cands = append(cands, filepath.Join(cacheDir, "es-specification", "output", "schema", "schema.json"))
	}
	cands = append(cands,
		filepath.Join("..", "..", ".cache", "es-specification", "output", "schema", "schema.json"),
		filepath.Join(".cache", "es-specification", "output", "schema", "schema.json"),
	)
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func resolveCacheRootForRound63Test() string {
	if cacheDir := os.Getenv("CONFORMANCE_CACHE_DIR"); cacheDir != "" {
		return cacheDir
	}
	for _, cand := range []string{filepath.Join("..", "..", ".cache"), ".cache"} {
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
	}
	return ""
}

func TestSpecSchemaValidatorMatchWildcardTargetSegmentsRound63(t *testing.T) {
	specPath := resolveSchemaJSONForRound63Test(t)
	if specPath == "" {
		// Synthetic fallback so unit test also passes without `.cache`
		raw := []byte(`{
			"endpoints": [
				{"name": "nodes.info", "urls": [{"methods": ["GET"], "path": "/_nodes"}, {"methods": ["GET"], "path": "/_nodes/{node_id}"}, {"methods": ["GET"], "path": "/_nodes/{metric}"}, {"methods": ["GET"], "path": "/_nodes/{node_id}/{metric}"}]},
				{"name": "nodes.stats", "urls": [{"methods": ["GET"], "path": "/_nodes/stats"}, {"methods": ["GET"], "path": "/_nodes/{node_id}/stats"}]},
				{"name": "nodes.usage", "urls": [{"methods": ["GET"], "path": "/_nodes/usage"}, {"methods": ["GET"], "path": "/_nodes/{node_id}/usage"}, {"methods": ["GET"], "path": "/_nodes/usage/{metric}"}, {"methods": ["GET"], "path": "/_nodes/{node_id}/usage/{metric}"}]},
				{"name": "indices.stats", "urls": [{"methods": ["GET"], "path": "/_stats"}, {"methods": ["GET"], "path": "/{index}/_stats"}]},
				{"name": "indices.get", "urls": [{"methods": ["GET"], "path": "/{index}"}]},
				{"name": "cluster.state", "urls": [{"methods": ["GET"], "path": "/_cluster/state"}, {"methods": ["GET"], "path": "/_cluster/state/{metric}/{index}"}]}
			],
			"types": []
		}`)
		v, err := compliance.ParseSpecSchemaValidator(raw)
		if err != nil {
			t.Fatalf("ParseSpecSchemaValidator failed: %v", err)
		}
		assertWildcardEndpointMatches(t, v)
		return
	}

	v, err := compliance.LoadSpecSchemaValidator(specPath)
	if err != nil {
		t.Fatalf("LoadSpecSchemaValidator(%q) failed: %v", specPath, err)
	}
	assertWildcardEndpointMatches(t, v)
}

func assertWildcardEndpointMatches(t *testing.T, v *compliance.SpecSchemaValidator) {
	t.Helper()
	candidates := []string{
		"nodes.info", "nodes.stats", "nodes.usage",
		"indices.stats", "indices.get", "cluster.state",
	}
	cases := []struct {
		method string
		path   string
		want   string
	}{
		{"GET", "/_nodes/_local/http", "nodes.info"},
		{"GET", "/_nodes/_master", "nodes.info"},
		{"GET", "/_nodes/_all", "nodes.info"},
		{"GET", "/_nodes/stats", "nodes.stats"},
		{"GET", "/_nodes/_local/stats", "nodes.stats"},
		{"GET", "/_nodes/usage", "nodes.usage"},
		{"GET", "/_nodes/_local/usage", "nodes.usage"},
		{"GET", "/_nodes/_local/usage/rest_actions", "nodes.usage"},
		{"GET", "/_all/_stats", "indices.stats"},
		{"GET", "/_stats", "indices.stats"},
		{"GET", "/_all", "indices.get"},
		{"GET", "/_cluster/state/_all/_all", "cluster.state"},
		{"GET", "/_search", ""},
	}
	for _, tc := range cases {
		got := v.MatchEndpoint(tc.method, tc.path, candidates...)
		if got != tc.want {
			t.Errorf("MatchEndpoint(%q, %q) = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestSpecSchemaValidatorHeadPlainTextBinaryAndNodesUsageRound63(t *testing.T) {
	specPath := resolveSchemaJSONForRound63Test(t)
	if specPath == "" {
		t.Skip("schema.json cache not present")
	}
	v, err := compliance.LoadSpecSchemaValidator(specPath)
	if err != nil {
		t.Fatalf("LoadSpecSchemaValidator failed: %v", err)
	}

	// 1. HEAD no_body endpoints (200 & 404)
	for _, ep := range []string{"ping", "exists", "indices.exists", "indices.exists_alias"} {
		if err := v.ValidateHTTPResponse(ep, http.StatusOK, nil); err != nil {
			t.Errorf("%s 200 empty body failed: %v", ep, err)
		}
		if ep != "ping" {
			if err := v.ValidateHTTPResponse(ep, http.StatusNotFound, nil); err != nil {
				t.Errorf("%s 404 empty body failed: %v", ep, err)
			}
		}
	}

	// 2. text/plain & binary endpoints
	if err := v.ValidateHTTPResponse("nodes.hot_threads", http.StatusOK, []byte("::: {doris-es-proxy}{node-1}\n   Hot threads at 2026-11-18\n")); err != nil {
		t.Errorf("nodes.hot_threads text/plain failed: %v", err)
	}
	if err := v.ValidateHTTPResponse("cat.nodes", http.StatusOK, []byte("127.0.0.1 50 50 1 0.10 0.10 0.10 cdfhilmrstw * doris-es-proxy\n")); err != nil {
		t.Errorf("cat.nodes text/plain failed: %v", err)
	}
	if err := v.ValidateHTTPResponse("search_mvt", http.StatusOK, []byte{0x1a, 0x05, 0x78, 0x02, 0x10, 0x01, 0x00}); err != nil {
		t.Errorf("search_mvt binary protobuf failed: %v", err)
	}

	// 3. Live proxy schema validation for nodes.usage, nodes.info, cluster.stats, cluster.reroute
	backend := proxy.NewMemoryBackend(false)
	srv := proxy.NewServer("es_db", backend, transpiler.TranspilerOptions{})
	srv.SetAllowTestFixtureAuth(true)
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	checkLive := func(method, path, ep string) {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do(%s %s): %v", method, path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s returned HTTP %d: %s", method, path, resp.StatusCode, string(body))
		}
		if err := v.ValidateHTTPResponse(ep, resp.StatusCode, body); err != nil {
			t.Errorf("%s %s (%s) failed schema.json validation: %v\nbody=%s", method, path, ep, err, string(body))
		}
	}

	checkLive("GET", "/_nodes/usage", "nodes.usage")
	checkLive("GET", "/_nodes/_local/usage", "nodes.usage")
	checkLive("GET", "/_nodes/usage/rest_actions", "nodes.usage")
	checkLive("GET", "/_nodes/_local/usage/_all", "nodes.usage")
	checkLive("GET", "/_nodes", "nodes.info")
	checkLive("GET", "/_nodes/_local/http,jvm,plugins", "nodes.info")
	checkLive("GET", "/_cluster/stats?human=true", "cluster.stats")
	checkLive("POST", "/_cluster/reroute?metric=none", "cluster.reroute")
}

func TestRound63TargetedAdminYAMLSpecs(t *testing.T) {
	cacheRoot := resolveCacheRootForRound63Test()
	if cacheRoot == "" {
		t.Skip("upstream YAML cache not present")
	}

	userFilter := strings.TrimSpace(os.Getenv("CONFORMANCE_FILTER"))

	defaultTargets := []string{
		"indices.flush/10_basic.yml",
		"indices.stats/20_translog.yml",
		"indices.stats/60_field_usage.yml",
		"search_shards/10_basic.yml",
		"cluster.reroute/10_basic.yml",
		"cluster.reroute/20_deprecated_response_filtering.yml",
		"cluster.stats/10_basic.yml",
		"search.vectors/70_dense_vector_telemetry.yml",
		"indices.get_index_template/10_basic.yml",
		"indices.get_index_template/20_get_missing.yml",
		"indices.put_index_template/15_composition.yml",
		"indices.simulate_index_template/10_basic.yml",
		"indices.get_mapping/50_wildcard_expansion.yml",
		"indices.put_settings/10_basic.yml",
		"indices.put_settings/20_update_non_dynamic_settings.yml",
		"indices.resolve_index/20_resolve_system_index.yml",
		"transport-netty4/src/yamlRestTest/resources/rest-api-spec/test/10_basic.yml",
	}

	matchFn := func(displayPath string) bool {
		slash := filepath.ToSlash(displayPath)
		if userFilter != "" {
			for _, tok := range strings.Split(userFilter, ",") {
				tok = strings.TrimSpace(tok)
				if tok != "" && strings.Contains(slash, tok) {
					return true
				}
			}
			return false
		}
		for _, dt := range defaultTargets {
			if strings.HasSuffix(slash, dt) {
				return true
			}
		}
		return false
	}

	corpora := []struct {
		name      string
		dir       string
		targetVer string
	}{
		{
			name:      "es-v7.10.2-round63-admin",
			dir:       filepath.Join(cacheRoot, "es-v7.10.2"),
			targetVer: "7.10.2",
		},
		{
			name:      "es-v8.15.5-round63-admin",
			dir:       filepath.Join(cacheRoot, "es-v8.15.5"),
			targetVer: "8.15.5",
		},
	}

	for _, corp := range corpora {
		if st, err := os.Stat(corp.dir); err != nil || !st.IsDir() {
			continue
		}
		corp := corp
		t.Run(corp.name, func(t *testing.T) {
			opts := compliance.SuiteOptions{
				CorpusName:                  corp.name,
				TargetVersion:               corp.targetVer,
				DefaultAuthUser:             compliance.DefaultFixtureAuthUser,
				DefaultAuthPass:             compliance.DefaultFixtureAuthPass,
				SupportedClusterFeatures:    compliance.DefaultSupportedClusterFeatures(),
				SupportedTestRunnerFeatures: compliance.DefaultSupportedTestRunnerFeatures(),
				FileFilter:                  matchFn,
				NewSectionHandler: func() (http.Handler, func()) {
					b := proxy.NewMemoryBackend(false)
					s := proxy.NewServer("es_db", b, transpiler.TranspilerOptions{})
					s.SetAllowTestFixtureAuth(true)
					s.SetTargetESVersion(corp.targetVer)
					s.SetRemoteReindexAllowPrivateIPs(true)
					return s.Handler(), func() { _ = s.Close(context.Background()) }
				},
			}
			sc, err := compliance.ScoreDirectories(opts, corp.dir)
			if err != nil {
				t.Fatalf("ScoreDirectories(%s): %v", corp.name, err)
			}
			for _, fail := range sc.FailureSamples {
				t.Errorf("[%s] %s :: %q failed: %+v", corp.name, fail.File, fail.Section, fail)
			}
			if sc.SectionsFailed > 0 {
				t.Errorf("[%s] expected 0 failed sections, got %d", corp.name, sc.SectionsFailed)
			}
			t.Logf("[%s] files=%d passed_sections=%d failed_sections=%d skipped_sections=%d",
				corp.name, sc.TotalFiles, sc.SectionsPassed, sc.SectionsFailed, sc.SectionsSkipped)
		})
	}
}
