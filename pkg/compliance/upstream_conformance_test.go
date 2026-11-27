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
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

const (
	expectedUpstreamV7YAMLCount          = 593
	expectedUpstreamV8YAMLCount          = 971
	defaultRemoteReindexWhitelistForTest = "127.0.0.1:*,[::1]:*,localhost:*,conformance.local:*"
)

func conformanceCacheBaseDir() string {
	if envDir := strings.TrimSpace(os.Getenv("CONFORMANCE_CACHE_DIR")); envDir != "" {
		return envDir
	}
	return filepath.Join("..", "..", ".cache")
}

// discoverRestAPISpecTestDirs finds all `.../rest-api-spec/test` directories inside a sparse-cloned
// Elasticsearch repository root (including both core `rest-api-spec/` and `modules/*/src/yamlRestTest/`).
func discoverRestAPISpecTestDirs(corpusRoot string) ([]string, error) {
	info, err := os.Stat(corpusRoot)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, err
	}
	cleanRoot := filepath.Clean(corpusRoot)
	if strings.HasSuffix(filepath.ToSlash(cleanRoot), "/rest-api-spec/test") {
		return []string{cleanRoot}, nil
	}

	var dirs []string
	err = filepath.WalkDir(cleanRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() {
			return nil
		}
		if d.Name() == ".git" {
			return filepath.SkipDir
		}
		if strings.HasSuffix(filepath.ToSlash(p), "/rest-api-spec/test") {
			dirs = append(dirs, p)
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(dirs)
	return dirs, nil
}

func collectYAMLFilesInDirs(dirs []string) ([]string, error) {
	var files []string
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if isYAMLFileName(d.Name()) {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	return files, nil
}

type serverBackedHandler struct {
	http.Handler
	srv any
}

func (h serverBackedHandler) Server() any {
	return h.srv
}

func newConformanceProxyHandler(targetESVersion string) http.Handler {
	h, _ := newConformanceProxySectionHandler(targetESVersion)
	return h
}

func newConformanceProxySectionHandler(targetESVersion string) (http.Handler, func()) {
	srv := proxy.NewServer("es_compat", proxy.NewMemoryBackend(false), transpiler.TranspilerOptions{})
	srv.SetAllowTestFixtureAuth(true)
	if targetESVersion != "" {
		if cfg, ok := any(srv).(interface{ SetTargetESVersion(string) }); ok {
			cfg.SetTargetESVersion(targetESVersion)
		}
	}
	h := serverBackedHandler{Handler: srv.Handler(), srv: srv}
	transport := inProcessHandlerTransport{handler: h}
	if rtSetter, ok := any(srv).(interface{ SetRemoteReindexTransport(http.RoundTripper) }); ok {
		rtSetter.SetRemoteReindexTransport(transport)
	}
	if wlSetter, ok := any(srv).(interface{ SetRemoteReindexWhitelistForTest(string) }); ok {
		wlSetter.SetRemoteReindexWhitelistForTest(defaultRemoteReindexWhitelistForTest)
	}
	return h, func() {
		_ = srv.Close(context.Background())
	}
}

func TestUpstreamYAMLParse100Percent(t *testing.T) {
	requireUpstream := os.Getenv("CONFORMANCE_REQUIRE_UPSTREAM") == "1"
	cacheBase := conformanceCacheBaseDir()

	v7Root := filepath.Join(cacheBase, "es-v7.10.2")
	v8Root := filepath.Join(cacheBase, "es-v8.15.5")

	v7Dirs, v7Err := discoverRestAPISpecTestDirs(v7Root)
	v8Dirs, v8Err := discoverRestAPISpecTestDirs(v8Root)
	if (v7Err != nil || len(v7Dirs) == 0) && (v8Err != nil || len(v8Dirs) == 0) {
		if requireUpstream {
			t.Fatalf("CONFORMANCE_REQUIRE_UPSTREAM=1 but upstream YAML corpora missing under %s (v7Err=%v, v8Err=%v)", cacheBase, v7Err, v8Err)
		}
		t.Skipf("skipping upstream YAML parse test (.cache corpora absent under %s)", cacheBase)
	}

	totalParsed := 0
	totalErrors := 0

	if v7Err != nil || len(v7Dirs) == 0 {
		if requireUpstream {
			t.Fatalf("missing v7.10.2 corpus at %s: %v", v7Root, v7Err)
		}
	} else {
		v7Files, err := collectYAMLFilesInDirs(v7Dirs)
		if err != nil {
			t.Fatalf("walking v7.10.2 YAML files: %v", err)
		}
		if len(v7Files) != expectedUpstreamV7YAMLCount {
			t.Fatalf("v7.10.2 YAML file count = %d, want %d (dirs=%v)", len(v7Files), expectedUpstreamV7YAMLCount, v7Dirs)
		}
		v7ParseErrs := 0
		for _, f := range v7Files {
			raw, readErr := os.ReadFile(f)
			if readErr != nil {
				t.Fatalf("reading %s: %v", f, readErr)
			}
			if _, parseErr := ParseSpecFile(string(raw)); parseErr != nil {
				v7ParseErrs++
				totalErrors++
				if v7ParseErrs <= 20 {
					t.Errorf("[v7.10.2] YAML parse error in %s: %v", f, parseErr)
				}
			} else {
				totalParsed++
			}
		}
		t.Logf("v7.10.2 YAML parse result: %d / %d parsed cleanly (%d errors)", len(v7Files)-v7ParseErrs, len(v7Files), v7ParseErrs)
	}

	if v8Err != nil || len(v8Dirs) == 0 {
		if requireUpstream {
			t.Fatalf("missing v8.15.5 corpus at %s: %v", v8Root, v8Err)
		}
	} else {
		v8Files, err := collectYAMLFilesInDirs(v8Dirs)
		if err != nil {
			t.Fatalf("walking v8.15.5 YAML files: %v", err)
		}
		if len(v8Files) != expectedUpstreamV8YAMLCount {
			t.Fatalf("v8.15.5 YAML file count = %d, want %d (dirs=%v)", len(v8Files), expectedUpstreamV8YAMLCount, v8Dirs)
		}
		v8ParseErrs := 0
		for _, f := range v8Files {
			raw, readErr := os.ReadFile(f)
			if readErr != nil {
				t.Fatalf("reading %s: %v", f, readErr)
			}
			if _, parseErr := ParseSpecFile(string(raw)); parseErr != nil {
				v8ParseErrs++
				totalErrors++
				if v8ParseErrs <= 20 {
					t.Errorf("[v8.15.5] YAML parse error in %s: %v", f, parseErr)
				}
			} else {
				totalParsed++
			}
		}
		t.Logf("v8.15.5 YAML parse result: %d / %d parsed cleanly (%d errors)", len(v8Files)-v8ParseErrs, len(v8Files), v8ParseErrs)
	}

	if totalErrors != 0 {
		t.Fatalf("expected 0 YAML parse errors across upstream corpora, got %d errors (%d parsed)", totalErrors, totalParsed)
	}
	t.Logf("TOTAL upstream YAML parse result: %d / %d files parsed with 0 errors", totalParsed, totalParsed+totalErrors)
}

func TestUpstreamElasticConformanceScorecard(t *testing.T) {
	requireUpstream := os.Getenv("CONFORMANCE_REQUIRE_UPSTREAM") == "1"
	cacheBase := conformanceCacheBaseDir()

	v7Root := filepath.Join(cacheBase, "es-v7.10.2")
	v8Root := filepath.Join(cacheBase, "es-v8.15.5")

	v7Dirs, v7Err := discoverRestAPISpecTestDirs(v7Root)
	v8Dirs, v8Err := discoverRestAPISpecTestDirs(v8Root)
	hasV7 := v7Err == nil && len(v7Dirs) > 0
	hasV8 := v8Err == nil && len(v8Dirs) > 0

	if !hasV7 && !hasV8 {
		if requireUpstream {
			t.Fatalf("CONFORMANCE_REQUIRE_UPSTREAM=1 but neither v7.10.2 nor v8.15.5 corpus is present under %s", cacheBase)
		}
		t.Skipf("skipping upstream conformance scorecard (.cache corpora absent under %s)", cacheBase)
	}
	if requireUpstream && (!hasV7 || !hasV8) {
		t.Fatalf("CONFORMANCE_REQUIRE_UPSTREAM=1 requires both v7.10.2 (present=%v) and v8.15.5 (present=%v)", hasV7, hasV8)
	}

	var filterCategories []string
	if rawCats := strings.TrimSpace(os.Getenv("CONFORMANCE_CATEGORIES")); rawCats != "" {
		for _, c := range strings.Split(rawCats, ",") {
			if trimmed := strings.TrimSpace(c); trimmed != "" {
				filterCategories = append(filterCategories, trimmed)
			}
		}
	}

	combinedJSON := make(map[string]*SuiteScorecard, 2)
	var markdownBlocks []string

	if hasV7 {
		v7Card, err := ScoreDirectories(SuiteOptions{
			CorpusName:      "elasticsearch-v7.10.2",
			TargetVersion:   "7.10.2",
			DefaultAuthUser: DefaultFixtureAuthUser,
			DefaultAuthPass: DefaultFixtureAuthPass,
			Categories:      filterCategories,
			NewSectionHandler: func() (http.Handler, func()) {
				return newConformanceProxySectionHandler("7.10.2")
			},
		}, v7Dirs...)
		if err != nil {
			t.Fatalf("ScoreDirectories(v7.10.2) failed: %v", err)
		}
		if v7Card.ParseErrors != 0 {
			t.Errorf("v7.10.2 scorecard recorded %d YAML parse errors (want 0)", v7Card.ParseErrors)
		}
		t.Logf(
			"[Scorecard %s] files=%d (skipped=%d, parse_errors=%d) sections=%d passed=%d failed=%d skipped=%d pass_rate=%.2f%%",
			v7Card.Corpus,
			v7Card.TotalFiles,
			v7Card.FilesSkipped,
			v7Card.ParseErrors,
			v7Card.SectionsTotal,
			v7Card.SectionsPassed,
			v7Card.SectionsFailed,
			v7Card.SectionsSkipped,
			v7Card.PassRatePct,
		)
		if minV7Str := strings.TrimSpace(os.Getenv("CONFORMANCE_MIN_V7_PASSED")); minV7Str != "" {
			minV7, convErr := strconv.Atoi(minV7Str)
			if convErr != nil {
				t.Fatalf("invalid CONFORMANCE_MIN_V7_PASSED=%q: %v", minV7Str, convErr)
			}
			if v7Card.SectionsPassed < minV7 {
				t.Errorf("v7.10.2 SectionsPassed = %d, below CONFORMANCE_MIN_V7_PASSED threshold %d", v7Card.SectionsPassed, minV7)
			}
		}
		combinedJSON["v7.10.2"] = v7Card
		markdownBlocks = append(markdownBlocks, v7Card.FormatMarkdown())
	}

	if hasV8 {
		v8Card, err := ScoreDirectories(SuiteOptions{
			CorpusName:      "elasticsearch-v8.15.5",
			TargetVersion:   "8.15.5",
			DefaultAuthUser: DefaultFixtureAuthUser,
			DefaultAuthPass: DefaultFixtureAuthPass,
			Categories:      filterCategories,
			NewSectionHandler: func() (http.Handler, func()) {
				return newConformanceProxySectionHandler("8.15.5")
			},
		}, v8Dirs...)
		if err != nil {
			t.Fatalf("ScoreDirectories(v8.15.5) failed: %v", err)
		}
		if v8Card.ParseErrors != 0 {
			t.Errorf("v8.15.5 scorecard recorded %d YAML parse errors (want 0)", v8Card.ParseErrors)
		}
		t.Logf(
			"[Scorecard %s] files=%d (skipped=%d, parse_errors=%d) sections=%d passed=%d failed=%d skipped=%d pass_rate=%.2f%%",
			v8Card.Corpus,
			v8Card.TotalFiles,
			v8Card.FilesSkipped,
			v8Card.ParseErrors,
			v8Card.SectionsTotal,
			v8Card.SectionsPassed,
			v8Card.SectionsFailed,
			v8Card.SectionsSkipped,
			v8Card.PassRatePct,
		)
		if minV8Str := strings.TrimSpace(os.Getenv("CONFORMANCE_MIN_V8_PASSED")); minV8Str != "" {
			minV8, convErr := strconv.Atoi(minV8Str)
			if convErr != nil {
				t.Fatalf("invalid CONFORMANCE_MIN_V8_PASSED=%q: %v", minV8Str, convErr)
			}
			if v8Card.SectionsPassed < minV8 {
				t.Errorf("v8.15.5 SectionsPassed = %d, below CONFORMANCE_MIN_V8_PASSED threshold %d", v8Card.SectionsPassed, minV8)
			}
		}
		combinedJSON["v8.15.5"] = v8Card
		markdownBlocks = append(markdownBlocks, v8Card.FormatMarkdown())
	}

	if outJSONPath := strings.TrimSpace(os.Getenv("CONFORMANCE_OUT_JSON")); outJSONPath != "" {
		if dir := filepath.Dir(outJSONPath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("creating CONFORMANCE_OUT_JSON directory %s: %v", dir, err)
			}
		}
		payload, err := json.MarshalIndent(combinedJSON, "", "  ")
		if err != nil {
			t.Fatalf("marshaling CONFORMANCE_OUT_JSON: %v", err)
		}
		payload = append(payload, '\n')
		if err := os.WriteFile(outJSONPath, payload, 0o644); err != nil {
			t.Fatalf("writing CONFORMANCE_OUT_JSON to %s: %v", outJSONPath, err)
		}
	}

	if summaryMDPath := strings.TrimSpace(os.Getenv("CONFORMANCE_SUMMARY_MD")); summaryMDPath != "" && len(markdownBlocks) > 0 {
		if dir := filepath.Dir(summaryMDPath); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("creating CONFORMANCE_SUMMARY_MD directory %s: %v", dir, err)
			}
		}
		f, err := os.OpenFile(summaryMDPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatalf("opening CONFORMANCE_SUMMARY_MD %s: %v", summaryMDPath, err)
		}
		_, writeErr := f.WriteString(strings.Join(markdownBlocks, "\n"))
		closeErr := f.Close()
		if writeErr != nil {
			t.Fatalf("writing CONFORMANCE_SUMMARY_MD %s: %v", summaryMDPath, writeErr)
		}
		if closeErr != nil {
			t.Fatalf("closing CONFORMANCE_SUMMARY_MD %s: %v", summaryMDPath, closeErr)
		}
	}
}
