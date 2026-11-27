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

package compliance

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound61_NoDefaultES8AcceptHeaderInjection(t *testing.T) {
	t.Parallel()

	handler := newConformanceProxyHandler("8.15.5")

	// 1. Without an explicit Accept header, _cat/health must return text/plain (not forced JSON).
	catReq := httptest.NewRequest(http.MethodGet, "http://conformance.local/_cat/health", nil)
	catRec := httptest.NewRecorder()
	handler.ServeHTTP(catRec, catReq)
	catResp := catRec.Result()
	defer func() { _ = catResp.Body.Close() }()

	if catResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_cat/health status = %d, want 200", catResp.StatusCode)
	}
	catCT := catResp.Header.Get("Content-Type")
	if !strings.HasPrefix(catCT, "text/plain") {
		t.Fatalf("GET /_cat/health without Accept returned Content-Type %q, want text/plain*", catCT)
	}

	// 2. Root info in ES 8.15.5 mode still reports version 8.15.5 and X-Elastic-Product without Accept injection.
	rootReq := httptest.NewRequest(http.MethodGet, "http://conformance.local/", nil)
	rootRec := httptest.NewRecorder()
	handler.ServeHTTP(rootRec, rootReq)
	rootResp := rootRec.Result()
	defer func() { _ = rootResp.Body.Close() }()

	if gotProd := rootResp.Header.Get("X-Elastic-Product"); gotProd != "Elasticsearch" {
		t.Fatalf("X-Elastic-Product = %q, want Elasticsearch", gotProd)
	}
	rawBody, err := io.ReadAll(rootResp.Body)
	if err != nil {
		t.Fatalf("reading root body: %v", err)
	}
	var info struct {
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
	}
	if err := json.Unmarshal(rawBody, &info); err != nil {
		t.Fatalf("unmarshaling root JSON: %v", err)
	}
	if info.Version.Number != "8.15.5" {
		t.Fatalf("version.number = %q, want 8.15.5", info.Version.Number)
	}

	// 3. Explicit compatible-with=8 negotiation still returns vnd.elasticsearch+json.
	compatReq := httptest.NewRequest(http.MethodGet, "http://conformance.local/", nil)
	compatReq.Header.Set("Accept", "application/vnd.elasticsearch+json; compatible-with=8")
	compatRec := httptest.NewRecorder()
	handler.ServeHTTP(compatRec, compatReq)
	compatResp := compatRec.Result()
	defer func() { _ = compatResp.Body.Close() }()

	if gotCT := compatResp.Header.Get("Content-Type"); !strings.Contains(gotCT, "application/vnd.elasticsearch+json") {
		t.Fatalf("explicit compatible-with=8 Content-Type = %q, want application/vnd.elasticsearch+json", gotCT)
	}
}

type mockRemoteReindexHandler struct {
	inner     http.Handler
	transport http.RoundTripper
	whitelist string
}

func (m *mockRemoteReindexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/_reindex" {
		// Probe remote loopback via the injected transport and verify :0 yields connect_exception.
		subReq, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:9200/_ping_remote", nil)
		resp, err := m.transport.RoundTrip(subReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = resp.Body.Close()

		zeroReq, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:0/_search", nil)
		_, zeroErr := m.transport.RoundTrip(zeroReq)
		if zeroErr == nil || !strings.Contains(zeroErr.Error(), "connect_exception") {
			http.Error(w, "expected connect_exception on port 0", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1,"whitelist":` + `"` + m.whitelist + `"}`))
		return
	}
	m.inner.ServeHTTP(w, r)
}

func (m *mockRemoteReindexHandler) SetRemoteReindexTransport(rt http.RoundTripper) {
	m.transport = rt
}

func (m *mockRemoteReindexHandler) SetRemoteReindexWhitelistForTest(wl string) {
	m.whitelist = wl
}

func TestRound61_RemoteReindexHarnessHooksAndPortZero(t *testing.T) {
	t.Parallel()

	var remotePingCount atomic.Int32
	newHandler := func() http.Handler {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/_ping_remote" {
				remotePingCount.Add(1)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"acknowledged":true}`))
		})
		return &mockRemoteReindexHandler{inner: inner}
	}

	fsys := fstest.MapFS{
		"reindex/90_remote.yml": &fstest.MapFile{
			Data: []byte(`---
"Remote reindex transport hook":
  - do:
      reindex:
        body:
          source:
            remote:
              host: http://127.0.0.1:9200
            index: src
          dest:
            index: dst
  - match: { created: 1 }
`),
		},
	}

	sc, err := ScoreSuiteFS(SuiteOptions{
		CorpusName:    "round61-remote",
		TargetVersion: "8.15.5",
		NewHandler:    newHandler,
	}, fsys)
	if err != nil {
		t.Fatalf("ScoreSuiteFS failed: %v", err)
	}
	if sc.SectionsPassed != 1 || sc.SectionsFailed != 0 {
		t.Fatalf("unexpected scorecard: %+v (failures: %+v)", sc, sc.FailureSamples)
	}
	if remotePingCount.Load() != 1 {
		t.Fatalf("remotePingCount = %d, want 1", remotePingCount.Load())
	}
}

func TestRound61_ActionBuilders_ClusterInfo_HealthReport_IncludeTypeName(t *testing.T) {
	t.Parallel()

	ctx := newRunnerContext(http.DefaultClient, "http://conformance.local")

	// 1. cluster.info -> /_info and /_info/{target}
	spec1, err := ctx.buildActionRequest("cluster.info", map[string]any{})
	if err != nil {
		t.Fatalf("cluster.info empty failed: %v", err)
	}
	if spec1.method != http.MethodGet || spec1.path != "/_info" {
		t.Fatalf("cluster.info empty = %s %s, want GET /_info", spec1.method, spec1.path)
	}

	spec2, err := ctx.buildActionRequest("cluster.info", map[string]any{
		"target": []any{"settings", "ingest"},
	})
	if err != nil {
		t.Fatalf("cluster.info slice target failed: %v", err)
	}
	if spec2.method != http.MethodGet || spec2.path != "/_info/settings,ingest" {
		t.Fatalf("cluster.info target = %s %s, want GET /_info/settings,ingest", spec2.method, spec2.path)
	}

	// 2. health_report -> /_health_report and /_health_report/{indicator} (with feature fallback)
	hr1, err := ctx.buildActionRequest("health_report", map[string]any{})
	if err != nil || hr1.path != "/_health_report" {
		t.Fatalf("health_report empty = %+v, err=%v", hr1, err)
	}
	hr2, err := ctx.buildActionRequest("health_report", map[string]any{"indicator": "shards_availability"})
	if err != nil || hr2.path != "/_health_report/shards_availability" {
		t.Fatalf("health_report indicator = %+v, err=%v", hr2, err)
	}
	hr3, err := ctx.buildActionRequest("health_report", map[string]any{"feature": "disk"})
	if err != nil || hr3.path != "/_health_report/disk" {
		t.Fatalf("health_report feature fallback = %+v, err=%v", hr3, err)
	}

	// 3. include_type_name query parameter preservation across mapping & template actions
	typeCases := []struct {
		action string
		params map[string]any
		wantP  string
		wantIT string
	}{
		{
			action: "indices.create",
			params: map[string]any{"index": "books", "include_type_name": true},
			wantP:  "/books",
			wantIT: "true",
		},
		{
			action: "indices.get_mapping",
			params: map[string]any{"index": "books", "include_type_name": false},
			wantP:  "/books/_mapping",
			wantIT: "false",
		},
		{
			action: "indices.put_mapping",
			params: map[string]any{"index": "books", "type": "_doc", "include_type_name": true, "body": map[string]any{}},
			wantP:  "/books/_mapping/_doc",
			wantIT: "true",
		},
		{
			action: "indices.get_field_mapping",
			params: map[string]any{"index": "books", "fields": "title", "include_type_name": true},
			wantP:  "/books/_mapping/field/title",
			wantIT: "true",
		},
		{
			action: "indices.put_template",
			params: map[string]any{"name": "tmpl1", "include_type_name": false, "body": map[string]any{}},
			wantP:  "/_template/tmpl1",
			wantIT: "false",
		},
	}

	for _, tc := range typeCases {
		reqSpec, reqErr := ctx.buildActionRequest(tc.action, tc.params)
		if reqErr != nil {
			t.Fatalf("%s buildActionRequest failed: %v", tc.action, reqErr)
		}
		if reqSpec.path != tc.wantP {
			t.Fatalf("%s path = %q, want %q", tc.action, reqSpec.path, tc.wantP)
		}
		if got := reqSpec.query.Get("include_type_name"); got != tc.wantIT {
			t.Fatalf("%s include_type_name query = %q, want %q", tc.action, got, tc.wantIT)
		}
	}
}

func TestRound61_CapabilitiesFeatureAndProbing(t *testing.T) {
	t.Parallel()

	feats := DefaultSupportedTestRunnerFeatures()
	if !feats["capabilities"] {
		t.Fatal("DefaultSupportedTestRunnerFeatures() must include \"capabilities\": true")
	}

	capHandler := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/_capabilities" {
				p := r.URL.Query().Get("path")
				params := r.URL.Query().Get("parameters")
				caps := r.URL.Query().Get("capabilities")
				supported := p == "/_capabilities" &&
					params == "method,path,parameters,capabilities" &&
					caps == ""
				if supported {
					_, _ = w.Write([]byte(`{"supported":true}`))
				} else {
					_, _ = w.Write([]byte(`{"supported":false}`))
				}
				return
			}
			_, _ = w.Write([]byte(`{"tagline":"You Know, for Search"}`))
		})
	}

	specYAML := `---
"Supported capability section runs":
  - requires:
      test_runner_features: [capabilities]
      capabilities:
        - method: GET
          path: /_capabilities
          parameters: [method, path, parameters, capabilities]
          capabilities: []
      reason: "capabilities api requires itself to be supported"
  - do:
      capabilities:
        method: GET
        path: /_capabilities
        parameters: method,path,parameters,capabilities
  - match: { supported: true }

---
"Unsupported capability section skips":
  - requires:
      test_runner_features: [capabilities]
      capabilities:
        - method: PUT
          path: /{index}
          capabilities: [lazy_rollover_failure_store]
      reason: "requires lazy rollover"
  - do:
      info: {}
  - match: { tagline: "should-not-run" }

---
"Skip when capability is supported":
  - skip:
      capabilities:
        - method: GET
          path: /_capabilities
          parameters: [method, path, parameters, capabilities]
      reason: "skip when supported"
  - do:
      info: {}
  - match: { tagline: "should-not-run" }
`

	fsys := fstest.MapFS{
		"capabilities/10_basic.yml": &fstest.MapFile{Data: []byte(specYAML)},
	}
	sc, err := ScoreSuiteFS(SuiteOptions{
		CorpusName:    "round61-capabilities",
		TargetVersion: "8.15.5",
		NewHandler:    capHandler,
	}, fsys)
	if err != nil {
		t.Fatalf("ScoreSuiteFS failed: %v", err)
	}
	if sc.SectionsPassed != 1 || sc.SectionsSkipped != 2 || sc.SectionsFailed != 0 {
		t.Fatalf("unexpected capabilities scorecard: passed=%d skipped=%d failed=%d samples=%+v",
			sc.SectionsPassed, sc.SectionsSkipped, sc.SectionsFailed, sc.FailureSamples)
	}
}

func TestRound61_TargetESVersionThreadingAndMaxFailureSamples(t *testing.T) {
	// Not parallel because t.Setenv mutates process environment.
	srv := proxy.NewServer("es_compat", proxy.NewMemoryBackend(false), transpiler.TranspilerOptions{})
	srv.SetAllowTestFixtureAuth(true)
	srv.SetTargetESVersion("8.15.5")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Section skips on <= 7.99.99; RunSuiteFSWithVersion and CONFORMANCE_TARGET_ES_VERSION must thread 8.15.5 cleanly.
	v8OnlySpec := `---
"Runs on ES 8 target":
  - skip:
      version: " - 7.99.99"
      reason: "ES 8+ only"
  - do:
      info: {}
  - match: { version.number: "8.15.5" }
`
	fsys := fstest.MapFS{
		"info/10_v8.yml": &fstest.MapFile{Data: []byte(v8OnlySpec)},
	}
	rep := RunSuiteFSWithVersion(t, fsys, ts.URL, "8.15.5")
	if rep.FilesRun != 1 || rep.SectionsRun != 1 || rep.StepsRun < 3 {
		t.Fatalf("expected ES 8 section to execute via RunSuiteFSWithVersion, got %+v", rep)
	}
	t.Setenv("CONFORMANCE_TARGET_ES_VERSION", "8.15.5")
	repEnv := RunSuiteFS(t, fsys, ts.URL)
	if repEnv.FilesRun != 1 || repEnv.SectionsRun != 1 || repEnv.StepsRun < 3 {
		t.Fatalf("expected ES 8 section to execute via CONFORMANCE_TARGET_ES_VERSION, got %+v", repEnv)
	}

	// Verify CONFORMANCE_MAX_FAILURE_SAMPLES caps failure samples cleanly.
	t.Setenv("CONFORMANCE_MAX_FAILURE_SAMPLES", "2")
	failYAML := `---
"f1":
  - do: { info: {} }
  - match: { tagline: "wrong" }
---
"f2":
  - do: { info: {} }
  - match: { tagline: "wrong" }
---
"f3":
  - do: { info: {} }
  - match: { tagline: "wrong" }
---
"f4":
  - do: { info: {} }
  - match: { tagline: "wrong" }
`
	sc, err := ScoreSuiteFS(SuiteOptions{
		CorpusName:    "round61-cap-samples",
		TargetVersion: "8.15.5",
		NewHandler:    func() http.Handler { return srv.Handler() },
	}, fstest.MapFS{"info/fails.yml": &fstest.MapFile{Data: []byte(failYAML)}})
	if err != nil {
		t.Fatalf("ScoreSuiteFS failed: %v", err)
	}
	if sc.SectionsFailed != 4 {
		t.Fatalf("SectionsFailed = %d, want 4", sc.SectionsFailed)
	}
	if len(sc.FailureSamples) != 2 {
		t.Fatalf("len(FailureSamples) = %d, want 2 (from CONFORMANCE_MAX_FAILURE_SAMPLES=2)", len(sc.FailureSamples))
	}
}

func TestRound61_SpecSchemaValidator_MatchEndpointAndHTTPResponse(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join(conformanceCacheBaseDir(), "es-specification", "output", "schema", "schema.json")
	if _, err := os.Stat(schemaPath); err != nil {
		if os.Getenv("CONFORMANCE_REQUIRE_UPSTREAM") == "1" {
			t.Fatalf("CONFORMANCE_REQUIRE_UPSTREAM=1 but %s missing: %v", schemaPath, err)
		}
		t.Skipf("skipping schema validator test (%s absent)", schemaPath)
	}

	v, err := LoadSpecSchemaValidator(schemaPath)
	if err != nil {
		t.Fatalf("LoadSpecSchemaValidator failed: %v", err)
	}

	candidates := []string{
		"info", "cluster.health", "indices.create", "index", "get",
		"search", "mget", "bulk", "count", "update", "delete",
	}
	if got := v.MatchEndpoint(http.MethodGet, "/_cluster/health", candidates...); got != "cluster.health" {
		t.Fatalf("MatchEndpoint GET /_cluster/health = %q, want cluster.health", got)
	}
	if got := v.MatchEndpoint(http.MethodPut, "/orders", candidates...); got != "indices.create" {
		t.Fatalf("MatchEndpoint PUT /orders = %q, want indices.create", got)
	}
	if got := v.MatchEndpoint(http.MethodGet, "/_nodes", candidates...); got != "" {
		t.Fatalf("MatchEndpoint GET /_nodes with restricted candidates = %q, want empty", got)
	}

	srv := proxy.NewServer("es_compat", proxy.NewMemoryBackend(false), transpiler.TranspilerOptions{})
	srv.SetAllowTestFixtureAuth(true)
	srv.SetTargetESVersion("8.15.5")
	h := srv.Handler()

	// Validate live cluster.health (200) via ValidateHTTPResponse with zero field skips.
	healthReq := httptest.NewRequest(http.MethodGet, "http://es.local/_cluster/health", nil)
	healthRec := httptest.NewRecorder()
	h.ServeHTTP(healthRec, healthReq)
	if err := v.ValidateHTTPResponse("cluster.health", healthRec.Code, healthRec.Body.Bytes()); err != nil {
		t.Fatalf("ValidateHTTPResponse(cluster.health, %d) failed: %v\nbody: %s", healthRec.Code, err, healthRec.Body.String())
	}

	// Create index, then validate get 404 exception payload via ValidateHTTPResponse.
	putIdxReq := httptest.NewRequest(http.MethodPut, "http://es.local/orders", strings.NewReader(`{}`))
	putIdxReq.Header.Set("Content-Type", "application/json")
	putIdxRec := httptest.NewRecorder()
	h.ServeHTTP(putIdxRec, putIdxReq)
	if err := v.ValidateHTTPResponse("indices.create", putIdxRec.Code, putIdxRec.Body.Bytes()); err != nil {
		t.Fatalf("ValidateHTTPResponse(indices.create) failed: %v", err)
	}

	get404Req := httptest.NewRequest(http.MethodGet, "http://es.local/orders/_doc/missing-99", nil)
	get404Rec := httptest.NewRecorder()
	h.ServeHTTP(get404Rec, get404Req)
	if get404Rec.Code != http.StatusNotFound {
		t.Fatalf("GET missing doc status = %d, want 404", get404Rec.Code)
	}
	if err := v.ValidateHTTPResponse("get", get404Rec.Code, get404Rec.Body.Bytes()); err != nil {
		t.Fatalf("ValidateHTTPResponse(get, 404) failed: %v\nbody: %s", err, get404Rec.Body.String())
	}
}
