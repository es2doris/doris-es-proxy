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
// KIND, either express or implied.  See the License for the specific
// language governing permissions and limitations
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
	"sync"
	"testing"
	"testing/fstest"
)

func TestRound64_KnownIssuesParsingAndVersionEval(t *testing.T) {
	t.Parallel()

	specYAML := `
---
setup:
  - do:
      cluster.health: {}
---
"fixed in 8.11 via cluster_feature":
  - skip:
      known_issues:
        - cluster_feature: gte_v8.10.0
          fixed_by: gte_v8.11.0
  - do:
      info: {}
---
"open issue via pr url":
  - skip:
      known_issues:
        - cluster_features: gte_v8.0.0
          fixed_by: https://github.com/elastic/elasticsearch/pull/1
      reason: "open upstream issue"
  - do:
      info: {}
---
"fixed in 8.16":
  - skip:
      known_issues:
        - cluster_feature: gte_v8.14.0
          fixed_by: gte_v8.16.0
  - do:
      info: {}
---
"empty known_issues":
  - skip:
      known_issues: []
  - do:
      info: {}
`
	doc, err := ParseSpecFile(specYAML)
	if err != nil {
		t.Fatalf("ParseSpecFile failed: %v", err)
	}
	if len(doc.Sections) != 4 {
		t.Fatalf("expected 4 sections, got %d", len(doc.Sections))
	}

	assertRuntimeSkip := func(ver string, stepVal any, wantSkip bool, wantReason string) {
		t.Helper()
		ctx := newRunnerContext(nil, "http://conformance.local")
		ctx.targetVersion = ver
		ctx.supportedClusterFeatures = DefaultSupportedClusterFeaturesForVersion(ver)
		err := ctx.execSkip(stepVal)
		if wantSkip {
			if err == nil {
				t.Fatalf("version %s: expected skip on %#v, got nil", ver, stepVal)
			}
			if wantReason != "" && !strings.Contains(err.Error(), wantReason) {
				t.Fatalf("version %s: expected skip reason %q, got %v", ver, wantReason, err)
			}
		} else if err != nil {
			t.Fatalf("version %s: unexpected skip on %#v: %v", ver, stepVal, err)
		}
	}

	// File-level skip parsing check (cluster_feature singular vs cluster_features plural)
	fileSkipDoc, err := ParseSpecFile(`
---
skip:
  known_issues:
    - cluster_feature: gte_v8.10.0
      fixed_by: gte_v8.11.0
---
"dummy":
  - do:
      info: {}
`)
	if err != nil {
		t.Fatalf("ParseSpecFile with file skip failed: %v", err)
	}
	if fileSkipDoc.Skip == nil || len(fileSkipDoc.Skip.KnownIssues) != 1 {
		t.Fatalf("expected 1 file-level known_issues entry, got %#v", fileSkipDoc.Skip)
	}
	for _, tc := range []struct {
		ver      string
		wantSkip bool
	}{
		{"7.10.2", false}, // pre-8.10.0: issue didn't affect cluster
		{"8.10.5", true},  // >=8.10.0 and <8.11.0: affected and not yet fixed
		{"8.11.0", false}, // fixed in >=8.11.0
		{"8.15.5", false}, // fixed well before 8.15.5
	} {
		ctx := newRunnerContext(nil, "http://conformance.local")
		ctx.targetVersion = tc.ver
		ctx.supportedClusterFeatures = DefaultSupportedClusterFeaturesForVersion(tc.ver)
		_, gotSkip := ctx.evalSkipSpec(fileSkipDoc.Skip, false)
		if gotSkip != tc.wantSkip {
			t.Fatalf("file-level known_issues version %s: got skip=%v, want %v", tc.ver, gotSkip, tc.wantSkip)
		}
	}

	// Runtime skip cases matching section steps in doc
	assertRuntimeSkip("7.10.2", doc.Sections[0].Steps[0].Value, false, "")
	assertRuntimeSkip("8.10.5", doc.Sections[0].Steps[0].Value, true, "known_issues")
	assertRuntimeSkip("8.15.5", doc.Sections[0].Steps[0].Value, false, "")
	assertRuntimeSkip("8.15.5", doc.Sections[1].Steps[0].Value, true, "open upstream issue")
	assertRuntimeSkip("8.15.5", doc.Sections[2].Steps[0].Value, true, "known_issues")
	assertRuntimeSkip("8.16.0", doc.Sections[2].Steps[0].Value, false, "")
	assertRuntimeSkip("8.15.5", doc.Sections[3].Steps[0].Value, false, "")

	// Single mapping known_issues (non-list) and requires guard
	singleMap := map[string]any{
		"known_issues": map[string]any{
			"cluster_feature": "gte_v8.12.0",
			"fixed_by":        "gte_v8.14.0",
		},
	}
	assertRuntimeSkip("8.13.0", singleMap, true, "known_issues")
	assertRuntimeSkip("8.15.5", singleMap, false, "")

	// Named cluster feature gating on known_issues
	namedFeatureSkip := map[string]any{
		"known_issues": []any{
			map[string]any{
				"cluster_feature": "rrf_retriever_supported",
				"fixed_by":        "gte_v8.16.0",
			},
		},
	}
	assertRuntimeSkip("7.10.2", namedFeatureSkip, false, "")
	assertRuntimeSkip("8.15.5", namedFeatureSkip, true, "known_issues")
	assertRuntimeSkip("8.16.0", namedFeatureSkip, false, "")
}

func TestRound64_KnownIssuesZeroFalseSkipsOnLiveV8Corpus(t *testing.T) {
	t.Parallel()

	v8Root := filepath.Join(conformanceCacheBaseDir(), "es-v8.15.5")
	dirs, err := discoverRestAPISpecTestDirs(v8Root)
	if err != nil || len(dirs) == 0 {
		t.Skipf("skipping live v8.15.5 known_issues audit (.cache absent under %s)", v8Root)
	}
	files, err := collectYAMLFilesInDirs(dirs)
	if err != nil {
		t.Fatalf("collectYAMLFilesInDirs: %v", err)
	}

	// Verify the expanded out-of-tree v8.15.5 test directories/files are discovered.
	joinedFiles := strings.Join(files, "\n")
	for _, wantSubpath := range []string{
		"yamlRestTestV7Compat",
		"smoke-test-ingest-with-all-dependencies",
		filepath.Join("autoscaling", "qa", "rest"),
		filepath.Join("test", "search-business-rules"),
		filepath.Join("test", "inference"),
		filepath.Join("test", "transform"),
	} {
		if !strings.Contains(joinedFiles, wantSubpath) {
			t.Errorf("expected discovered v8.15.5 files to contain %q", wantSubpath)
		}
	}

	ctx := newRunnerContext(nil, "http://conformance.local")
	ctx.targetVersion = "8.15.5"
	ctx.supportedClusterFeatures = DefaultSupportedClusterFeaturesForVersion("8.15.5")

	for _, f := range files {
		raw, rErr := os.ReadFile(f)
		if rErr != nil {
			t.Fatalf("reading %s: %v", f, rErr)
		}
		doc, pErr := ParseSpecFile(string(raw))
		if pErr != nil {
			t.Fatalf("parsing %s: %v", f, pErr)
		}
		if doc.Skip != nil {
			for _, ki := range doc.Skip.KnownIssues {
				if ctx.hasActiveKnownIssue(ki) {
					t.Errorf("%s: file-level known_issues unexpectedly triggers on 8.15.5: %+v", f, ki)
				}
			}
		}
		for _, sec := range doc.Sections {
			for _, st := range sec.Steps {
				if st.Op != "skip" {
					continue
				}
				spec, sErr := ctx.parseRuntimeSkipSpec("skip", st.Value)
				if sErr != nil {
					continue
				}
				for _, ki := range spec.KnownIssues {
					if ctx.hasActiveKnownIssue(ki) {
						t.Errorf("%s [%s]: section known_issues unexpectedly triggers on 8.15.5: %+v", f, sec.Name, ki)
					}
				}
			}
		}
	}
}

func TestRound64_ClusterFeaturesRegisteredAndVersionGated(t *testing.T) {
	t.Parallel()

	es8Features := []string{
		"mapper.vectors.bit_vectors",
		"mapper.vectors.int4_quantization",
		"rrf_retriever_supported",
		"mapper.annotated_text.synthetic_source",
		"search.vectors.k_param_supported",
		"unified_highlighter_matched_fields",
		"script.hamming",
		"geoip.downloader.database.configuration",
		"esql.agg_values",
		"esql.metrics_counter_fields",
		"mapper.pass_through_priority",
		"mapper.index_sorting_on_nested",
		"mapper.keyword_dimension_ignore_above",
		"mapper.source.synthetic_source_stored_fields_advance_fix",
		"stats.include_disk_thresholds",
		"mapper.range.null_values_off_by_one_fix",
		"esql.mv_ordering_sorted_ascending",
	}

	allDefaults := DefaultSupportedClusterFeatures()
	v8Feats := DefaultSupportedClusterFeaturesForVersion("8.15.5")
	v7Feats := DefaultSupportedClusterFeaturesForVersion("7.10.2")
	v717Feats := DefaultSupportedClusterFeaturesForVersion("7.17.0")

	for _, feat := range es8Features {
		if !allDefaults[feat] {
			t.Errorf("DefaultSupportedClusterFeatures missing %q", feat)
		}
		if !v8Feats[feat] {
			t.Errorf("DefaultSupportedClusterFeaturesForVersion(8.15.5) missing %q", feat)
		}
		if v7Feats[feat] {
			t.Errorf("DefaultSupportedClusterFeaturesForVersion(7.10.2) unexpectedly enabled ES8 feature %q", feat)
		}
		if v717Feats[feat] {
			t.Errorf("DefaultSupportedClusterFeaturesForVersion(7.17.0) unexpectedly enabled ES8 feature %q", feat)
		}
	}

	// Default runnerContext (7.10.2) gates ES8-only features off, even with nil supportedClusterFeatures.
	nilMapV7 := &runnerContext{targetVersion: "7.10.2"}
	nilMapV8 := &runnerContext{targetVersion: "8.15.5"}
	for _, feat := range es8Features {
		if nilMapV7.evalClusterFeature(feat) {
			t.Errorf("nilMapV7 should not support %q", feat)
		}
		if !nilMapV8.evalClusterFeature(feat) {
			t.Errorf("nilMapV8 should support %q", feat)
		}
	}

	// ScoreSuiteFS skips ES8 cluster_features on 7.10.2 and runs them on 8.15.5.
	fsys := fstest.MapFS{
		"search/10_features.yml": {
			Data: []byte(`
---
"requires all round64 es8 features":
  - requires:
      cluster_features:
        - mapper.vectors.bit_vectors
        - mapper.vectors.int4_quantization
        - rrf_retriever_supported
        - mapper.annotated_text.synthetic_source
        - search.vectors.k_param_supported
        - unified_highlighter_matched_fields
        - script.hamming
        - geoip.downloader.database.configuration
        - esql.agg_values
        - esql.metrics_counter_fields
        - mapper.pass_through_priority
        - mapper.index_sorting_on_nested
        - mapper.keyword_dimension_ignore_above
        - mapper.source.synthetic_source_stored_fields_advance_fix
        - stats.include_disk_thresholds
        - mapper.range.null_values_off_by_one_fix
        - esql.mv_ordering_sorted_ascending
  - do:
      info: {}
`),
		},
	}

	mockHandler := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":{"number":"8.15.5"}}`))
		})
	}

	scV8, err := ScoreSuiteFS(SuiteOptions{
		TargetVersion: "8.15.5",
		NewHandler:    mockHandler,
	}, fsys)
	if err != nil {
		t.Fatalf("ScoreSuiteFS(8.15.5): %v", err)
	}
	if scV8.SectionsPassed != 1 || scV8.SectionsSkipped != 0 || scV8.SectionsFailed != 0 {
		t.Fatalf("8.15.5 unexpected scorecard: passed=%d skipped=%d failed=%d samples=%+v",
			scV8.SectionsPassed, scV8.SectionsSkipped, scV8.SectionsFailed, scV8.FailureSamples)
	}

	scV7, err := ScoreSuiteFS(SuiteOptions{
		TargetVersion: "7.10.2",
		NewHandler:    mockHandler,
	}, fsys)
	if err != nil {
		t.Fatalf("ScoreSuiteFS(7.10.2): %v", err)
	}
	if scV7.SectionsSkipped != 1 || scV7.SectionsPassed != 0 || scV7.SectionsFailed != 0 {
		t.Fatalf("7.10.2 unexpected scorecard: passed=%d skipped=%d failed=%d samples=%+v",
			scV7.SectionsPassed, scV7.SectionsSkipped, scV7.SectionsFailed, scV7.FailureSamples)
	}
}

func TestRound64_LicenseGetFeatureUsageAction(t *testing.T) {
	t.Parallel()

	ctx := newRunnerContext(nil, "http://conformance.local")
	req, err := ctx.buildActionRequest("license.get_feature_usage", map[string]any{})
	if err != nil {
		t.Fatalf("buildActionRequest(license.get_feature_usage): %v", err)
	}
	if req.method != http.MethodGet || req.path != "/_license/feature_usage" {
		t.Fatalf("got %s %s, want GET /_license/feature_usage", req.method, req.path)
	}

	fsys := fstest.MapFS{
		"license/10_feature_usage.yml": {
			Data: []byte(`
---
"Get feature usage":
  - do:
      license.get_feature_usage: {}
  - length: { features: 0 }
`),
		},
	}
	sc, err := ScoreSuiteFS(SuiteOptions{
		TargetVersion: "8.15.5",
		NewHandler: func() http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/_license/feature_usage" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"features":{}}`))
			})
		},
	}, fsys)
	if err != nil {
		t.Fatalf("ScoreSuiteFS: %v", err)
	}
	if sc.SectionsPassed != 1 || sc.SectionsFailed != 0 {
		t.Fatalf("expected license.get_feature_usage to pass, got %+v", sc)
	}
}

func TestRound64_ScopedRepositoryURLFixtureIsolation(t *testing.T) {
	t.Parallel()

	type sharedRepoState struct {
		mu          sync.Mutex
		repos       map[string]map[string]any
		allowedURLs string
	}
	state := &sharedRepoState{
		repos: make(map[string]map[string]any),
	}

	sharedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/_cluster/settings":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if pers, ok := body["persistent"].(map[string]any); ok {
				state.mu.Lock()
				if val, exists := pers["repositories.url.allowed_urls"]; exists {
					if val == nil {
						state.allowedURLs = ""
					} else if s, ok := val.(string); ok {
						state.allowedURLs = s
					}
				}
				state.mu.Unlock()
			}
			_, _ = w.Write([]byte(`{"acknowledged":true}`))

		case r.URL.Path == "/_snapshot" || strings.HasPrefix(r.URL.Path, "/_snapshot/"):
			repo := strings.TrimPrefix(r.URL.Path, "/_snapshot")
			repo = strings.TrimPrefix(repo, "/")
			repo = strings.SplitN(repo, "/", 2)[0]
			if repo == "" {
				repo = "_all"
			}
			switch r.Method {
			case http.MethodPut:
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if body["type"] == "url" {
					settings, _ := body["settings"].(map[string]any)
					u, _ := settings["url"].(string)
					state.mu.Lock()
					allowed := state.allowedURLs
					state.mu.Unlock()
					if strings.Contains(u, "unknown") || (allowed == "" && !strings.HasPrefix(u, "http://snapshot.test")) {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = w.Write([]byte(`{"error":{"type":"repository_exception","reason":"disallowed url"},"status":400}`))
						return
					}
				}
				state.mu.Lock()
				state.repos[repo] = body
				state.mu.Unlock()
				_, _ = w.Write([]byte(`{"acknowledged":true}`))

			case http.MethodGet:
				state.mu.Lock()
				defer state.mu.Unlock()
				if repo == "_all" {
					_ = json.NewEncoder(w).Encode(state.repos)
					return
				}
				val, ok := state.repos[repo]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"error":{"type":"repository_missing_exception","reason":"missing"},"status":404}`))
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{repo: val})

			case http.MethodDelete:
				state.mu.Lock()
				delete(state.repos, repo)
				state.mu.Unlock()
				_, _ = w.Write([]byte(`{"acknowledged":true}`))
			}

		case r.Method == http.MethodGet && r.URL.Path == "/_cat/repositories":
			state.mu.Lock()
			list := make([]map[string]any, 0, len(state.repos))
			for name, def := range state.repos {
				list = append(list, map[string]any{"id": name, "type": def["type"]})
			}
			state.mu.Unlock()
			_ = json.NewEncoder(w).Encode(list)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	// Test both standard section execution and ReuseSetupForReadOnlyFiles.
	for _, reuse := range []bool{false, true} {
		fsys := fstest.MapFS{
			"repository_url/10_basic.yml": {
				Data: []byte(`
---
"repository_url fixture active inside repository_url category":
  - do:
      snapshot.get_repository: {}
  - match: { repository-fs.type: fs }
  - match: { repository-url.type: url }
  - match: { repository-file.type: url }
  - do:
      catch: bad_request
      snapshot.create_repository:
        repository: bad-url-repo
        body:
          type: url
          settings:
            url: http://snapshot.unknown/snapshots/
`),
			},
			"snapshot/20_other.yml": {
				Data: []byte(`
---
"non repository_url sections see zero fixture repos":
  - do:
      cat.repositories: {}
  - length: { $body: 0 }
  - do:
      snapshot.get_repository: {}
  - length: { $body: 0 }
`),
			},
		}

		sc, err := ScoreSuiteFS(SuiteOptions{
			TargetVersion:              "8.15.5",
			ReuseSetupForReadOnlyFiles: reuse,
			NewHandler: func() http.Handler {
				return sharedHandler
			},
		}, fsys)
		if err != nil {
			t.Fatalf("reuse=%v ScoreSuiteFS failed: %v", reuse, err)
		}
		if sc.SectionsPassed != 2 || sc.SectionsFailed != 0 {
			t.Fatalf("reuse=%v expected 2 passing sections, got passed=%d failed=%d samples=%+v",
				reuse, sc.SectionsPassed, sc.SectionsFailed, sc.FailureSamples)
		}
		state.mu.Lock()
		if len(state.repos) != 0 || state.allowedURLs != "" {
			state.mu.Unlock()
			t.Fatalf("reuse=%v expected clean state after repository_url teardown, got repos=%+v allowedURLs=%q",
				reuse, state.repos, state.allowedURLs)
		}
		state.mu.Unlock()
	}

	// Verify setupCategoryFixtureIfNeeded exposes an HTTP server serving files from repository-fs's temp dir.
	var capturedFSLocation string
	var capturedHTTPURL string
	var capturedFileURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(bodyBytes, &m)
		if r.Method == http.MethodPut {
			if settings, ok := m["settings"].(map[string]any); ok {
				switch r.URL.Path {
				case "/_snapshot/repository-fs":
					capturedFSLocation, _ = settings["location"].(string)
				case "/_snapshot/repository-url":
					capturedHTTPURL, _ = settings["url"].(string)
				case "/_snapshot/repository-file":
					capturedFileURL, _ = settings["url"].(string)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"acknowledged":true}`))
	}))
	defer srv.Close()

	// Rewrite transport host to srv so setupCategoryFixtureIfNeeded hits srv.
	client := &http.Client{
		Transport: inProcessHandlerTransport{
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				srv.Config.Handler.ServeHTTP(w, r)
			}),
		},
	}
	cleanup := setupCategoryFixtureIfNeeded("repository_url", client)
	if cleanup == nil {
		t.Fatal("expected non-nil cleanup for repository_url category")
	}
	if capturedFSLocation == "" || !strings.HasPrefix(capturedHTTPURL, "http://127.0.0.1:") || !strings.HasPrefix(capturedFileURL, "file://") {
		cleanup()
		t.Fatalf("unexpected fixture settings: fs=%q url=%q file=%q", capturedFSLocation, capturedHTTPURL, capturedFileURL)
	}
	if err := os.WriteFile(filepath.Join(capturedFSLocation, "index.latest"), []byte(`{"ok":true}`), 0o600); err != nil {
		cleanup()
		t.Fatalf("writing probe file in tmpDir: %v", err)
	}
	resp, err := http.Get(capturedHTTPURL + "index.latest")
	if err != nil {
		cleanup()
		t.Fatalf("GET fixture URL failed: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != `{"ok":true}` {
		cleanup()
		t.Fatalf("expected HTTP fixture to serve tmpDir file, got %q", string(got))
	}
	cleanup()
	if _, err := os.Stat(capturedFSLocation); !os.IsNotExist(err) {
		t.Fatalf("expected tmpDir %q to be removed after cleanup, err=%v", capturedFSLocation, err)
	}
}

func TestRound64_SchemaValidatorHardening(t *testing.T) {
	t.Parallel()

	// 1. Wildcard target segments
	for _, seg := range []string{"_all", "_local", "_master", "_nodes", "_primary", "_replica", "_only_nodes", "_data", "_ingest", "_data,_ingest"} {
		if !isSpecWildcardTargetSegment(seg) {
			t.Errorf("expected isSpecWildcardTargetSegment(%q) == true", seg)
		}
	}
	for _, seg := range []string{"_hidden", "_search", "orders", "_all,", "", "_search,_all"} {
		if isSpecWildcardTargetSegment(seg) {
			t.Errorf("expected isSpecWildcardTargetSegment(%q) == false", seg)
		}
	}

	schemaJSON := `{
  "endpoints": [
    {
      "name": "nodes.info",
      "urls": [
        {"methods": ["GET"], "path": "/_nodes"},
        {"methods": ["GET"], "path": "/_nodes/{node_id}"}
      ],
      "response": {"name": "ObjResponse", "namespace": "test"}
    },
    {
      "name": "cat.help",
      "urls": [{"methods": ["GET"], "path": "/_cat/help"}],
      "responseMediaType": ["text/plain"],
      "response": {"name": "CatArrayResponse", "namespace": "test"}
    },
    {
      "name": "nodes.hot_threads",
      "urls": [{"methods": ["GET"], "path": "/_nodes/hot_threads"}],
      "responseMediaType": ["text/plain"],
      "response": {"name": "HotThreadsResponse", "namespace": "test"}
    }
  ],
  "types": [
    {
      "kind": "interface",
      "name": {"name": "ErrorCause", "namespace": "_types"},
      "properties": [
        {"name": "type", "required": true, "type": {"kind": "instance_of", "type": {"name": "string", "namespace": "_builtins"}}}
      ]
    },
    {
      "kind": "interface",
      "name": {"name": "ErrorResponseBase", "namespace": "_types"},
      "properties": [
        {"name": "error", "required": true, "type": {"kind": "instance_of", "type": {"name": "ErrorCause", "namespace": "_types"}}},
        {"name": "status", "required": true, "type": {"kind": "instance_of", "type": {"name": "integer", "namespace": "_types"}}}
      ]
    },
    {
      "kind": "response",
      "name": {"name": "ObjResponse", "namespace": "test"},
      "body": {
        "kind": "properties",
        "properties": [
          {"name": "cluster_name", "required": false, "type": {"kind": "instance_of", "type": {"name": "string", "namespace": "_builtins"}}}
        ]
      }
    },
    {
      "kind": "response",
      "name": {"name": "CatArrayResponse", "namespace": "test"},
      "body": {
        "kind": "value",
        "value": {
          "kind": "array_of",
          "value": {
            "kind": "instance_of",
            "type": {"name": "CatRow", "namespace": "test"}
          }
        }
      }
    },
    {
      "kind": "interface",
      "name": {"name": "CatRow", "namespace": "test"},
      "properties": [
        {"name": "endpoint", "required": true, "type": {"kind": "instance_of", "type": {"name": "string", "namespace": "_builtins"}}}
      ]
    },
    {
      "kind": "response",
      "name": {"name": "HotThreadsResponse", "namespace": "test"},
      "body": {
        "kind": "value",
        "value": {"kind": "instance_of", "type": {"name": "string", "namespace": "_builtins"}}
      }
    }
  ]
}`
	v, err := ParseSpecSchemaValidator([]byte(schemaJSON))
	if err != nil {
		t.Fatalf("ParseSpecSchemaValidator failed: %v", err)
	}

	// MatchEndpoint accepts expanded wildcard segments on {node_id} and rejects _hidden.
	for _, p := range []string{"/_nodes/_nodes", "/_nodes/_primary", "/_nodes/_replica", "/_nodes/_only_nodes", "/_nodes/_data", "/_nodes/_ingest", "/_nodes/_data,_ingest"} {
		if got := v.MatchEndpoint(http.MethodGet, p); got != "nodes.info" {
			t.Errorf("MatchEndpoint(GET, %q) = %q, want nodes.info", p, got)
		}
	}
	if got := v.MatchEndpoint(http.MethodGet, "/_nodes/_hidden"); got != "" {
		t.Errorf("MatchEndpoint(GET, /_nodes/_hidden) = %q, want empty", got)
	}

	// 2. ValidateHTTPResponse validates status even when error is a legacy string.
	if err := v.ValidateHTTPResponse("nodes.info", http.StatusBadRequest, []byte(`{"error":"legacy error string","status":400}`)); err != nil {
		t.Errorf("expected valid legacy error with matching status 400 to pass: %v", err)
	}
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"legacy string missing status", http.StatusBadRequest, `{"error":"legacy error string"}`},
		{"legacy string mismatched status", http.StatusBadRequest, `{"error":"legacy error string","status":404}`},
		{"legacy string non-integer string status", http.StatusBadRequest, `{"error":"legacy error string","status":"400"}`},
		{"legacy string float status", http.StatusBadRequest, `{"error":"legacy error string","status":400.5}`},
	} {
		if err := v.ValidateHTTPResponse("nodes.info", tc.code, []byte(tc.body)); err == nil {
			t.Errorf("%s: expected ValidateHTTPResponse error for %s", tc.name, tc.body)
		}
	}

	// 3. ValidateEndpointResponse validates JSON shapes even when responseMediaType is text/plain only.
	if err := v.ValidateEndpointResponse("cat.help", []byte("/_cat/allocation\n/_cat/indices\n")); err != nil {
		t.Errorf("cat.help plain text should pass: %v", err)
	}
	if err := v.ValidateEndpointResponse("cat.help", []byte(`[{"endpoint":"/_cat/indices"}]`)); err != nil {
		t.Errorf("cat.help valid JSON array should pass: %v", err)
	}
	if err := v.ValidateEndpointResponse("cat.help", []byte(`{"wrong":"shape"}`)); err == nil {
		t.Errorf("cat.help JSON object root must fail array_of validation")
	}
	if err := v.ValidateEndpointResponse("cat.help", []byte(`[{malformed`)); err == nil {
		t.Errorf("cat.help malformed JSON starting with '[' must fail")
	}
	if err := v.ValidateEndpointResponse("nodes.hot_threads", []byte("::: [node-1] hot threads\n")); err != nil {
		t.Errorf("nodes.hot_threads plain text should pass: %v", err)
	}
	if err := v.ValidateEndpointResponse("nodes.hot_threads", []byte(`{"unexpected":true}`)); err == nil {
		t.Errorf("nodes.hot_threads JSON object root must fail string validation")
	}
}
