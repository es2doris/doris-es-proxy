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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

func TestRound63BodyStashLookupAndLHSNoRegression(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/_search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"suggest": {
				"my-suggest": [
					{"options": [{"text": "xorn the god jewel", "score": 0.42}]},
					{"options": [{"text": "xorn the god jewel", "score": 0.42}]}
				]
			},
			"hits": {
				"total": {"value": 2},
				"hits": [
					{"_id": "doc-1", "_score": 2.5, "_source": {"dotted.key": "alpha", "null_field": null}},
					{"_id": "doc-2", "_score": 1.5, "_source": {"dotted.key": "alpha", "null_field": null}}
				]
			},
			"tags": ["doc-1", "doc-2"]
		}`))
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		_, _ = w.Write([]byte(".ds-k8s-2026.11.18-000001\n"))
	})
	mux.HandleFunc("/.ds-k8s-2026.11.18-000001", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			".ds-k8s-2026.11.18-000001": {
				"data_stream": "k8s"
			}
		}`))
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	yamlSpec := `---
"RHS $body.<path> and LHS $body assertions":
  - do:
      search: {}
  - match: { suggest.my-suggest.0.options.0.text: $body.suggest.my-suggest.1.options.0.text }
  - match: { suggest.my-suggest.0.options.0.score: $body.suggest.my-suggest.1.options.0.score }
  - match: { "hits.hits.0._source.dotted\\.key": "$body.hits.hits.1._source.dotted\\.key" }
  - match: { hits.hits.0._source.null_field: $body.hits.hits.1._source.null_field }
  - match: { hits.hits.0._id: "${body.tags.0}" }
  - contains: { tags: $body.hits.hits.0._id }
  - not_contains: { tags: "missing-$body.hits.hits.0._id" }
  - gt: { hits.hits.0._score: $body.hits.hits.1._score }
  - close_to:
      hits.hits.0._score:
        value: $body.hits.hits.0._score
        error: 0.001
  - length: { tags: $body.hits.total.value }
  - set: { hits.hits.0: first_hit }
  - match: { hits.hits.0._id: $first_hit._id }

  - do:
      cat.indices: {}
  - match:
      $body: |
        /^\.ds-k8s-\d{4}\.\d{2}\.\d{2}-000001\n$/

  - do:
      indices.get:
        index: ".ds-k8s-2026.11.18-000001"
  - set: { "\.ds-k8s-2026\.11\.18-000001.data_stream": ds_name }
  - match: { "$body.\.ds-k8s-2026\.11\.18-000001.data_stream": $ds_name }
`
	rep := RunSpecFile(t, "body_stash.yml", yamlSpec, ts.URL)
	if rep.SectionsRun != 1 {
		t.Fatalf("SectionsRun = %d, want 1", rep.SectionsRun)
	}

	// Direct unit edge cases on lookupStashPathValue & currentBodyRoot
	var nilCtx *runnerContext
	if _, ok := nilCtx.currentBodyRoot(); ok {
		t.Fatal("expected nil runnerContext.currentBodyRoot() to return false")
	}

	ctx := newRunnerContext(ts.Client(), ts.URL)
	ctx.lastBodyKind = bodyKindNone
	if _, ok := ctx.lookupStashPathValue("$body"); ok {
		t.Fatal("expected $body to return false when lastBodyKind == bodyKindNone")
	}
	if _, ok := ctx.lookupStashPathValue("$body.foo"); ok {
		t.Fatal("expected $body.foo to return false when lastBodyKind == bodyKindNone")
	}
	if _, ok := ctx.lookupStashPathValue("${body.foo}"); ok {
		t.Fatal("expected ${body.foo} to return false when lastBodyKind == bodyKindNone")
	}

	ctx.lastBodyKind = bodyKindEmptyText
	if v, ok := ctx.lookupStashPathValue("$body"); !ok || v != "" {
		t.Fatalf("expected empty text $body = \"\", true; got %v, %v", v, ok)
	}

	ctx.lastBodyKind = bodyKindJSONNull
	if v, ok := ctx.lookupStashPathValue("${body}"); !ok || v != nil {
		t.Fatalf("expected JSON null ${body} = nil, true; got %v, %v", v, ok)
	}

	ctx.lastBodyKind = bodyKindParsed
	ctx.lastResponse = map[string]any{
		"nested": map[string]any{
			"k": "from_response",
		},
	}
	if v, ok := ctx.lookupStashPathValue("${body.nested.k}"); !ok || v != "from_response" {
		t.Fatalf("expected ${body.nested.k} = from_response, got %v (%v)", v, ok)
	}
	if _, ok := ctx.lookupStashPathValue("$body.nested.missing"); ok {
		t.Fatal("expected missing $body.nested.missing to return false")
	}
	if _, ok := ctx.lookupStashPathValue("$headers.content-type"); ok {
		t.Fatal("expected $headers.* to return false in lookupStashPathValue")
	}
	if _, ok := ctx.lookupStashPathValue("plain_key"); ok {
		t.Fatal("expected non-$ key to return false in lookupStashPathValue")
	}

	// Explicit stash["body"] override & transform_and_set nested stash lookup
	ctx.stash["body"] = map[string]any{"nested": map[string]any{"k": "from_stash"}}
	if v, ok := ctx.lookupStashPathValue("$body.nested.k"); !ok || v != "from_stash" {
		t.Fatalf("expected stashed $body.nested.k = from_stash, got %v (%v)", v, ok)
	}
	if v, ok := ctx.lookupStashPathValue("$body"); !ok || v == nil {
		t.Fatalf("expected stashed $body map, got %v (%v)", v, ok)
	}
	if v, ok := ctx.lookupStashPathValue("${body}"); !ok || v == nil {
		t.Fatalf("expected stashed ${body} map, got %v (%v)", v, ok)
	}
	if v, ok := ctx.lookupStashPathValue("${body.nested.k}"); !ok || v != "from_stash" {
		t.Fatalf("expected stashed ${body.nested.k} = from_stash, got %v (%v)", v, ok)
	}
	delete(ctx.stash, "body")

	ctx.stash["saved_obj"] = map[string]any{"part.one": "hello"}
	if v, ok := ctx.lookupStashPathValue(`$saved_obj.part\.one`); !ok || v != "hello" {
		t.Fatalf("expected $saved_obj.part\\.one = hello, got %v (%v)", v, ok)
	}
	if err := ctx.execTransformAndSet(map[string]any{"upper_out": `upper($saved_obj.part\.one)`}); err != nil {
		t.Fatalf("execTransformAndSet nested stash failed: %v", err)
	}
	if ctx.stash["upper_out"] != "HELLO" {
		t.Fatalf("upper_out = %v, want HELLO", ctx.stash["upper_out"])
	}
	if err := ctx.execTransformAndSet(map[string]any{"concat_out": `concat($saved_obj.part\.one, "-world")`}); err != nil {
		t.Fatalf("execTransformAndSet concat nested stash failed: %v", err)
	}
	if ctx.stash["concat_out"] != "hello-world" {
		t.Fatalf("concat_out = %v, want hello-world", ctx.stash["concat_out"])
	}

	// Numeric scalar $body with close_to { field: $body, value: ..., error: ... }
	ctx.lastResponse = float64(3.14)
	ctx.lastBodyKind = bodyKindParsed
	if err := ctx.execCloseTo(map[string]any{"field": "$body", "value": 3.14, "error": 0.01}); err != nil {
		t.Fatalf("close_to on scalar $body failed: %v", err)
	}
}

func TestRound63NotExistsOperator(t *testing.T) {
	feats := DefaultSupportedTestRunnerFeatures()
	if !feats["not_exists"] {
		t.Fatal("expected DefaultSupportedTestRunnerFeatures() to include not_exists")
	}

	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")
	ctx.lastStatus = http.StatusOK
	ctx.lastMethod = http.MethodGet
	ctx.lastBodyKind = bodyKindParsed
	ctx.lastBodyRaw = `{"present":"yes","falsy_bool":false,"falsy_zero":0,"falsy_empty":"","explicit_null":null,"nodes":{"n1":{"dfs":{},"name":"node-1"}}}`
	ctx.lastResponse = map[string]any{
		"present":       "yes",
		"falsy_bool":    false,
		"falsy_zero":    int64(0),
		"falsy_empty":   "",
		"explicit_null": nil,
		"nodes": map[string]any{
			"n1": map[string]any{
				"dfs":  map[string]any{},
				"name": "node-1",
			},
		},
	}

	// Pass cases: absent paths
	passPaths := []any{
		"absent_top",
		"nodes.n1.absent_nested",
		"nodes._arbitrary_key_.absent_field",
		[]any{"absent_a", "nodes.n1.absent_b"},
	}
	for _, p := range passPaths {
		if err := ctx.execStep(SpecStep{Op: "not_exists", Value: p}, false); err != nil {
			t.Errorf("expected not_exists(%v) to pass, got error: %v", p, err)
		}
	}

	// Fail cases: existing truthy, falsy, null, and _arbitrary_key_ paths
	failPaths := []any{
		"present",
		"falsy_bool",
		"falsy_zero",
		"falsy_empty",
		"explicit_null",
		"nodes.n1.dfs",
		"nodes._arbitrary_key_.dfs",
		[]any{"absent_ok", "falsy_bool"},
		"$body",
		"",
	}
	for _, p := range failPaths {
		if err := ctx.execStep(SpecStep{Op: "not_exists", Value: p}, false); err == nil {
			t.Errorf("expected not_exists(%v) to fail when path exists", p)
		}
	}

	// HEAD & empty-body $body cases
	ctx.lastMethod = http.MethodHead
	ctx.lastBodyKind = bodyKindNone
	ctx.lastResponse = nil
	ctx.lastStatus = http.StatusNotFound
	if err := ctx.execNotExists("$body"); err != nil {
		t.Fatalf("expected HEAD 404 not_exists($body) to pass, got %v", err)
	}
	ctx.lastStatus = http.StatusOK
	if err := ctx.execNotExists("$body"); err == nil {
		t.Fatal("expected HEAD 200 not_exists($body) to fail")
	}

	ctx.lastMethod = http.MethodGet
	ctx.lastBodyKind = bodyKindNone
	if err := ctx.execNotExists("$body"); err != nil {
		t.Fatalf("expected bodyKindNone not_exists($body) to pass, got %v", err)
	}
}

type round63MockRemoteTarget struct {
	rt http.RoundTripper
	wl string
}

func (m *round63MockRemoteTarget) SetRemoteReindexTransport(rt http.RoundTripper) {
	m.rt = rt
}

func (m *round63MockRemoteTarget) SetRemoteReindexWhitelistForTest(wl string) {
	m.wl = wl
}

type round63ServerHolderHandler struct {
	http.Handler
	srv any
}

func (h round63ServerHolderHandler) Server() any {
	return h.srv
}

type round63UnwrapHandler struct {
	inner http.Handler
}

func (u round63UnwrapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.inner.ServeHTTP(w, r)
}

func (u round63UnwrapHandler) Unwrap() http.Handler {
	return u.inner
}

func TestRound63BasicLicenseSkipAndRemoteReindexConfig(t *testing.T) {
	// 1. Remote reindex handler unwrapping & hook tests
	configureHandlerRemoteReindex(nil, http.DefaultTransport)

	target := &round63MockRemoteTarget{}
	wrapped := round63UnwrapHandler{
		inner: round63ServerHolderHandler{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"acknowledged":true}`))
			}),
			srv: target,
		},
	}
	hookCalled := false
	configureHandlerRemoteReindexWithHook(wrapped, http.DefaultTransport, func(h http.Handler, rt http.RoundTripper) {
		hookCalled = true
	})
	if target.rt != http.DefaultTransport {
		t.Fatalf("expected SetRemoteReindexTransport via Unwrap()->Server(), got %v", target.rt)
	}
	if target.wl != defaultScorecardRemoteWhitelist {
		t.Fatalf("expected whitelist %q, got %q", defaultScorecardRemoteWhitelist, target.wl)
	}
	if !hookCalled {
		t.Fatal("expected ConfigureRemoteTransport hook to be invoked")
	}

	// Verify deriveSpecCategory handles /plugins/<name>/...
	if got := deriveSpecCategory("/cache/es-v8.15.5/plugins/mapper-size/src/yamlRestTest/resources/rest-api-spec/test", "10_basic.yml"); got != "mapper-size" {
		t.Fatalf("deriveSpecCategory(/plugins/mapper-size/...) = %q, want mapper-size", got)
	}

	// 2. Basic-license-restriction skip tests in ScoreSuiteFS
	fsys := fstest.MapFS{
		"license/100_license.yml": &fstest.MapFile{
			Data: []byte(`---
"rrf invalid license":
  - do:
      catch: forbidden
      search:
        index: test
        body: { query: { match_all: {} } }
  - match: { status: 403 }
  - match: { error.type: security_exception }
  - match: { error.reason: "current license is non-compliant for [Reciprocal Rank Fusion (RRF)]" }
---
"rrf retriever invalid license":
  - do:
      catch: forbidden
      search:
        index: test
        body: { query: { match_all: {} } }
  - match: { status: 403 }
  - match: { error.type: security_exception }
  - match: { error.reason: "current license is non-compliant for [Reciprocal Rank Fusion (RRF)]" }
`),
		},
		"rrf/100_mixed.yml": &fstest.MapFile{
			Data: []byte(`setup:
  - do:
      indices.create:
        index: test
---
"rrf valid search":
  - do:
      search:
        index: test
  - match: { acknowledged: true }
---
"rrf basic license downgrade section":
  - do:
      catch: forbidden
      search:
        index: test
  - match: { status: 403 }
  - match: { error.reason: "current license is non-compliant for [Reciprocal Rank Fusion (RRF)]" }
`),
		},
	}

	hookCount := 0
	for _, reuse := range []bool{false, true} {
		sc, err := ScoreSuiteFS(SuiteOptions{
			CorpusName:                 "round63-license-test",
			TargetVersion:              "8.15.5",
			ReuseSetupForReadOnlyFiles: reuse,
			NewHandler: func() http.Handler {
				return wrapped
			},
			ConfigureRemoteTransport: func(handler http.Handler, transport http.RoundTripper) {
				hookCount++
			},
		}, fsys)
		if err != nil {
			t.Fatalf("ScoreSuiteFS(reuse=%v) failed: %v", reuse, err)
		}
		if sc.FilesSkipped != 1 {
			t.Fatalf("reuse=%v: FilesSkipped = %d, want 1", reuse, sc.FilesSkipped)
		}
		if sc.SectionsPassed != 1 || sc.SectionsFailed != 0 || sc.SectionsSkipped != 3 {
			t.Fatalf("reuse=%v: unexpected section counts: passed=%d failed=%d skipped=%d",
				reuse, sc.SectionsPassed, sc.SectionsFailed, sc.SectionsSkipped)
		}
	}
	if hookCount == 0 {
		t.Fatal("expected SuiteOptions.ConfigureRemoteTransport to be called during ScoreSuiteFS")
	}
}

func TestRound63UpstreamStepOpsAndActions(t *testing.T) {
	cacheBase := conformanceCacheBaseDir()
	v7Dirs, v7Err := discoverRestAPISpecTestDirs(filepath.Join(cacheBase, "es-v7.10.2"))
	v8Dirs, v8Err := discoverRestAPISpecTestDirs(filepath.Join(cacheBase, "es-v8.15.5"))
	if (v7Err != nil || len(v7Dirs) == 0) && (v8Err != nil || len(v8Dirs) == 0) {
		t.Skipf("skipping upstream step/action audit (.cache corpora absent under %s)", cacheBase)
	}

	knownStepOps := map[string]bool{
		"skip":              true,
		"requires":          true,
		"do":                true,
		"set":               true,
		"transform_and_set": true,
		"match":             true,
		"contains":          true,
		"not_contains":      true,
		"is_true":           true,
		"is_false":          true,
		"is_unset":          true,
		"exists":            true,
		"not_exists":        true,
		"is_empty":          true,
		"length":            true,
		"close_to":          true,
		"gt":                true,
		"gte":               true,
		"lt":                true,
		"lte":               true,
		"wait_for_events":   true,
	}

	ctx := newRunnerContext(http.DefaultClient, "http://localhost:9200")
	unknownOps := make(map[string][]string)
	unknownActions := make(map[string][]string)

	auditFiles := func(label string, dirs []string) {
		files, err := collectYAMLFilesInDirs(dirs)
		if err != nil {
			t.Fatalf("[%s] collecting YAML files: %v", label, err)
		}
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("[%s] reading %s: %v", label, f, err)
			}
			doc, err := ParseSpecFile(string(raw))
			if err != nil {
				t.Fatalf("[%s] parsing %s: %v", label, f, err)
			}
			var allSteps []SpecStep
			allSteps = append(allSteps, doc.Setup...)
			allSteps = append(allSteps, doc.Teardown...)
			for _, sec := range doc.Sections {
				allSteps = append(allSteps, sec.Steps...)
			}
			for _, st := range allSteps {
				if !knownStepOps[st.Op] {
					unknownOps[st.Op] = append(unknownOps[st.Op], f)
				}
				if st.Op == "do" {
					act := extractDoStepActionName(st.Value)
					if act == "" || strings.HasPrefix(act, "_internal.") {
						continue
					}
					if om, ok := st.Value.(*OrderedMap); ok && om != nil {
						var rawParams any
						for _, field := range om.Fields {
							if field.Key == act {
								rawParams = field.Value
								break
							}
						}
						pm, _ := ToNative(rawParams).(map[string]any)
						if pm == nil {
							pm = map[string]any{}
						}
						// Clone pm before buildActionRequest mutates it
						cp := make(map[string]any, len(pm))
						for k, v := range pm {
							cp[k] = v
						}
						if _, bErr := ctx.buildActionRequest(act, cp); bErr != nil && strings.Contains(bErr.Error(), "unsupported API action") {
							unknownActions[act] = append(unknownActions[act], f)
						}
					}
				}
			}
		}
	}

	if len(v7Dirs) > 0 {
		auditFiles("v7.10.2", v7Dirs)
	}
	if len(v8Dirs) > 0 {
		auditFiles("v8.15.5", v8Dirs)
	}

	if len(unknownOps) > 0 {
		keys := make([]string, 0, len(unknownOps))
		for k := range unknownOps {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Errorf("unsupported SpecStep.Op %q (e.g. in %s)", k, unknownOps[k][0])
		}
	}
	if len(unknownActions) > 0 {
		keys := make([]string, 0, len(unknownActions))
		for k := range unknownActions {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Logf("observation: unsupported API action %q (%d occurrences, e.g. %s)", k, len(unknownActions[k]), unknownActions[k][0])
		}
	}
}
