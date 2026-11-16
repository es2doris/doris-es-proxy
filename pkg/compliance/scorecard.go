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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultScorecardTargetVersion   = "7.17.0"
	defaultScorecardRemoteWhitelist = "127.0.0.1:*,[::1]:*,localhost:*,conformance.local:*"
	maxRecordedFailureSamples       = 250
	maxMarkdownFailureSamples       = 25
)

func effectiveMaxRecordedFailureSamples() int {
	if raw := strings.TrimSpace(os.Getenv("CONFORMANCE_MAX_FAILURE_SAMPLES")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v >= 0 {
			return v
		}
	}
	return maxRecordedFailureSamples
}

// SuiteOptions configures non-aborting conformance scorecard execution across a YAML spec corpus.
type SuiteOptions struct {
	CorpusName                  string
	TargetVersion               string
	SupportedClusterFeatures    map[string]bool
	SupportedTestRunnerFeatures map[string]bool
	Categories                  []string
	NewHandler                  func() http.Handler
}

// SectionFailure records a single failed section or parse error during scorecard execution.
type SectionFailure struct {
	File     string `json:"file"`
	Category string `json:"category"`
	Section  string `json:"section"`
	Error    string `json:"error"`
}

// CategoryScore aggregates conformance results for a single API category directory.
type CategoryScore struct {
	Category    string  `json:"category"`
	Files       int     `json:"files"`
	Passed      int     `json:"passed"`
	Failed      int     `json:"failed"`
	Skipped     int     `json:"skipped"`
	PassRatePct float64 `json:"pass_rate_pct"`
}

// SuiteScorecard summarizes non-aborting execution across an entire rest-api-spec corpus.
type SuiteScorecard struct {
	Corpus          string           `json:"corpus"`
	TargetVersion   string           `json:"target_version"`
	TotalFiles      int              `json:"total_files"`
	ParseErrors     int              `json:"parse_errors"`
	FilesSkipped    int              `json:"files_skipped"`
	SectionsTotal   int              `json:"sections_total"`
	SectionsPassed  int              `json:"sections_passed"`
	SectionsFailed  int              `json:"sections_failed"`
	SectionsSkipped int              `json:"sections_skipped"`
	PassRatePct     float64          `json:"pass_rate_pct"`
	Categories      []CategoryScore  `json:"categories"`
	FailureSamples  []SectionFailure `json:"failure_samples,omitempty"`
}

type scoredSpecEntry struct {
	displayPath string
	category    string
	readContent func() ([]byte, error)
}

type inProcessHandlerTransport struct {
	handler http.Handler
}

func (t inProcessHandlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req != nil && req.URL != nil && req.URL.Port() == "0" {
		return nil, fmt.Errorf("connect_exception: dial tcp %s: connect: connection refused", req.URL.Host)
	}
	if t.handler == nil {
		return nil, fmt.Errorf("connect_exception: nil in-process handler")
	}
	clone := req.Clone(req.Context())
	if clone.Body == nil {
		clone.Body = http.NoBody
	}
	if clone.RequestURI == "" && clone.URL != nil {
		clone.RequestURI = clone.URL.RequestURI()
	}
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, clone)
	resp := rec.Result()
	if resp.Body == nil {
		resp.Body = io.NopCloser(strings.NewReader(""))
	}
	return resp, nil
}

func configureHandlerRemoteReindex(handler http.Handler, transport http.RoundTripper) {
	if handler == nil {
		return
	}
	if rtSetter, ok := any(handler).(interface{ SetRemoteReindexTransport(http.RoundTripper) }); ok {
		rtSetter.SetRemoteReindexTransport(transport)
	}
	if wlSetter, ok := any(handler).(interface{ SetRemoteReindexWhitelistForTest(string) }); ok {
		wlSetter.SetRemoteReindexWhitelistForTest(defaultScorecardRemoteWhitelist)
	}
}

// ScoreDirectories executes all rest-api-spec YAML files across dirs without aborting on failures or panics.
func ScoreDirectories(opts SuiteOptions, dirs ...string) (*SuiteScorecard, error) {
	if opts.NewHandler == nil {
		return nil, fmt.Errorf("scorecard: SuiteOptions.NewHandler is required")
	}
	var entries []scoredSpecEntry
	for _, rootDir := range dirs {
		cleanRoot := filepath.Clean(rootDir)
		err := filepath.WalkDir(cleanRoot, func(fullPath string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !isYAMLFileName(d.Name()) {
				return nil
			}
			rel, relErr := filepath.Rel(cleanRoot, fullPath)
			if relErr != nil {
				rel = d.Name()
			}
			relSlash := filepath.ToSlash(rel)
			cat := deriveSpecCategory(cleanRoot, relSlash)
			disp := relSlash
			if !strings.Contains(relSlash, "/") && cat != "" && cat != "root" {
				disp = cat + "/" + relSlash
			}
			pathCopy := fullPath
			entries = append(entries, scoredSpecEntry{
				displayPath: disp,
				category:    cat,
				readContent: func() ([]byte, error) {
					return os.ReadFile(filepath.Clean(pathCopy)) // #nosec G304 -- trusted local conformance test corpus path
				},
			})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scorecard: walking %s: %w", cleanRoot, err)
		}
	}
	return scoreEntries(opts, entries), nil
}

// ScoreSuiteFS executes all rest-api-spec YAML files in fsys without aborting on failures or panics.
func ScoreSuiteFS(opts SuiteOptions, fsys fs.FS) (*SuiteScorecard, error) {
	if opts.NewHandler == nil {
		return nil, fmt.Errorf("scorecard: SuiteOptions.NewHandler is required")
	}
	var entries []scoredSpecEntry
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if !isYAMLFileName(d.Name()) {
			return nil
		}
		relSlash := filepath.ToSlash(p)
		cat := deriveSpecCategory("", relSlash)
		pathCopy := p
		entries = append(entries, scoredSpecEntry{
			displayPath: relSlash,
			category:    cat,
			readContent: func() ([]byte, error) {
				return fs.ReadFile(fsys, pathCopy)
			},
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scorecard: walking fs: %w", err)
	}
	return scoreEntries(opts, entries), nil
}

func isYAMLFileName(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

func deriveSpecCategory(rootDir, relSlash string) string {
	trimmed := strings.TrimPrefix(relSlash, "./")
	if slashIdx := strings.IndexByte(trimmed, '/'); slashIdx > 0 {
		first := trimmed[:slashIdx]
		rest := trimmed[slashIdx+1:]
		if first == "specs" {
			if subIdx := strings.IndexByte(rest, '/'); subIdx > 0 {
				return rest[:subIdx]
			}
		}
		return first
	}
	rootSlash := filepath.ToSlash(rootDir)
	if modIdx := strings.Index(rootSlash, "/modules/"); modIdx >= 0 {
		afterMod := rootSlash[modIdx+len("/modules/"):]
		if endIdx := strings.IndexByte(afterMod, '/'); endIdx > 0 {
			return afterMod[:endIdx]
		}
		if afterMod != "" {
			return afterMod
		}
	}
	base := filepath.Base(rootSlash)
	if base != "" && base != "." && base != "/" && base != "test" {
		return base
	}
	return "root"
}

func newConfiguredRunnerContext(
	client *http.Client,
	baseURL string,
	targetVersion string,
	clusterFeatures map[string]bool,
	runnerFeatures map[string]bool,
) *runnerContext {
	ctx := newRunnerContext(client, baseURL)
	if targetVersion != "" {
		ctx.targetVersion = targetVersion
	}
	if clusterFeatures != nil {
		ctx.supportedClusterFeatures = clusterFeatures
	}
	if runnerFeatures != nil {
		ctx.supportedTestRunnerFeatures = runnerFeatures
	}
	return ctx
}

func scoreEntries(opts SuiteOptions, entries []scoredSpecEntry) *SuiteScorecard {
	targetVer := strings.TrimSpace(opts.TargetVersion)
	if targetVer == "" {
		targetVer = defaultScorecardTargetVersion
	}
	corpusName := opts.CorpusName
	if corpusName == "" {
		corpusName = "rest-api-spec"
	}
	clusterFeats := opts.SupportedClusterFeatures
	if clusterFeats == nil {
		clusterFeats = DefaultSupportedClusterFeatures()
	}
	runnerFeats := opts.SupportedTestRunnerFeatures
	if runnerFeats == nil {
		runnerFeats = DefaultSupportedTestRunnerFeatures()
	}

	var categoryFilter map[string]bool
	if len(opts.Categories) > 0 {
		categoryFilter = make(map[string]bool, len(opts.Categories))
		for _, c := range opts.Categories {
			if trimmed := strings.TrimSpace(c); trimmed != "" {
				categoryFilter[trimmed] = true
			}
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].category != entries[j].category {
			return entries[i].category < entries[j].category
		}
		return entries[i].displayPath < entries[j].displayPath
	})

	sc := &SuiteScorecard{
		Corpus:        corpusName,
		TargetVersion: targetVer,
	}
	catMap := make(map[string]*CategoryScore)
	getCat := func(name string) *CategoryScore {
		cs, ok := catMap[name]
		if !ok {
			cs = &CategoryScore{Category: name}
			catMap[name] = cs
		}
		return cs
	}
	maxFailureSamples := effectiveMaxRecordedFailureSamples()
	recordFailure := func(file, cat, section, errMsg string) {
		if len(sc.FailureSamples) < maxFailureSamples {
			sc.FailureSamples = append(sc.FailureSamples, SectionFailure{
				File:     file,
				Category: cat,
				Section:  section,
				Error:    errMsg,
			})
		}
	}

	probeClient := http.DefaultClient
	if opts.NewHandler != nil {
		probeHandler := opts.NewHandler()
		probeTransport := inProcessHandlerTransport{handler: probeHandler}
		configureHandlerRemoteReindex(probeHandler, probeTransport)
		probeClient = &http.Client{Transport: probeTransport}
	}
	probeCtx := newConfiguredRunnerContext(probeClient, "http://conformance.local", targetVer, clusterFeats, runnerFeats)

	for _, entry := range entries {
		if categoryFilter != nil && !categoryFilter[entry.category] {
			continue
		}
		sc.TotalFiles++
		cs := getCat(entry.category)
		cs.Files++

		rawBytes, readErr := entry.readContent()
		if readErr != nil {
			sc.ParseErrors++
			recordFailure(entry.displayPath, entry.category, "<read>", readErr.Error())
			continue
		}

		specDoc, parseErr := parseSpecFileSafe(string(rawBytes))
		if parseErr != nil {
			sc.ParseErrors++
			recordFailure(entry.displayPath, entry.category, "<parse>", parseErr.Error())
			continue
		}

		if shouldSkipEntireFile(probeCtx, specDoc) {
			sc.FilesSkipped++
			n := len(specDoc.Sections)
			sc.SectionsTotal += n
			sc.SectionsSkipped += n
			cs.Skipped += n
			continue
		}

		for _, sec := range specDoc.Sections {
			sc.SectionsTotal++
			skipped, secErr := executeScoredSection(opts.NewHandler, targetVer, clusterFeats, runnerFeats, specDoc, sec)
			switch {
			case skipped:
				sc.SectionsSkipped++
				cs.Skipped++
			case secErr != nil:
				sc.SectionsFailed++
				cs.Failed++
				recordFailure(entry.displayPath, entry.category, sec.Name, secErr.Error())
			default:
				sc.SectionsPassed++
				cs.Passed++
			}
		}
	}

	sc.PassRatePct = computePassRatePct(sc.SectionsPassed, sc.SectionsFailed)
	sc.Categories = make([]CategoryScore, 0, len(catMap))
	for _, cs := range catMap {
		cs.PassRatePct = computePassRatePct(cs.Passed, cs.Failed)
		sc.Categories = append(sc.Categories, *cs)
	}
	sort.Slice(sc.Categories, func(i, j int) bool {
		return sc.Categories[i].Category < sc.Categories[j].Category
	})
	return sc
}

func parseSpecFileSafe(content string) (doc *SpecDocument, err error) {
	defer func() {
		if r := recover(); r != nil {
			doc = nil
			err = fmt.Errorf("panic during YAML parse: %v", r)
		}
	}()
	return ParseSpecFile(content)
}

func shouldSkipEntireFile(probeCtx *runnerContext, specDoc *SpecDocument) bool {
	if _, skip := probeCtx.evalSkipSpec(specDoc.Skip, false); skip {
		return true
	}
	if _, skip := probeCtx.evalSkipSpec(specDoc.Requires, true); skip {
		return true
	}
	for _, step := range specDoc.Setup {
		if step.Op == "skip" || step.Op == "requires" {
			if err := probeCtx.execStep(step, false); err != nil {
				var skipErr *errSkipSection
				if errors.As(err, &skipErr) {
					return true
				}
			}
		}
	}
	return false
}

func safeCleanupRunnerContext(ctx *runnerContext) {
	defer func() {
		_ = recover()
	}()
	ctx.cleanupAll()
}

func executeScoredSection(
	newHandler func() http.Handler,
	targetVer string,
	clusterFeats map[string]bool,
	runnerFeats map[string]bool,
	specDoc *SpecDocument,
	sec SpecSection,
) (skipped bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			skipped = false
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	handler := newHandler()
	transport := inProcessHandlerTransport{handler: handler}
	configureHandlerRemoteReindex(handler, transport)
	client := &http.Client{
		Transport: transport,
	}
	ctx := newConfiguredRunnerContext(client, "http://conformance.local", targetVer, clusterFeats, runnerFeats)
	defer safeCleanupRunnerContext(ctx)

	for i, step := range specDoc.Setup {
		if stepErr := ctx.execStep(step, false); stepErr != nil {
			var skipErr *errSkipSection
			if errors.As(stepErr, &skipErr) {
				return true, nil
			}
			return false, fmt.Errorf("[setup step %d (%s)] %w", i+1, step.Op, stepErr)
		}
	}

	var testErr error
	var skipErr *errSkipSection
	for i, step := range sec.Steps {
		if stepErr := ctx.execStep(step, false); stepErr != nil {
			if errors.As(stepErr, &skipErr) {
				break
			}
			testErr = fmt.Errorf("[step %d (%s)] %w", i+1, step.Op, stepErr)
			break
		}
	}

	for i, step := range specDoc.Teardown {
		if tdErr := ctx.execStep(step, true); tdErr != nil && testErr == nil && skipErr == nil {
			var tdSkip *errSkipSection
			if !errors.As(tdErr, &tdSkip) {
				testErr = fmt.Errorf("[teardown step %d (%s)] %w", i+1, step.Op, tdErr)
			}
		}
	}

	if skipErr != nil {
		return true, nil
	}
	return false, testErr
}

func computePassRatePct(passed, failed int) float64 {
	denom := passed + failed
	if denom <= 0 {
		return 0
	}
	return math.Round((float64(passed)*10000.0)/float64(denom)) / 100.0
}

// FormatMarkdown renders the SuiteScorecard as a GitHub-Flavored Markdown report.
func (s *SuiteScorecard) FormatMarkdown() string {
	if s == nil {
		return ""
	}
	var sb strings.Builder
	_, _ = fmt.Fprintf(&sb, "## Conformance Scorecard: `%s` (Target ES `%s`)\n\n", s.Corpus, s.TargetVersion)
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|---|---:|\n")
	_, _ = fmt.Fprintf(&sb, "| Total Files | %d |\n", s.TotalFiles)
	_, _ = fmt.Fprintf(&sb, "| Parse Errors | %d |\n", s.ParseErrors)
	_, _ = fmt.Fprintf(&sb, "| Files Skipped | %d |\n", s.FilesSkipped)
	_, _ = fmt.Fprintf(&sb, "| Sections Total | %d |\n", s.SectionsTotal)
	_, _ = fmt.Fprintf(&sb, "| Sections Passed | %d |\n", s.SectionsPassed)
	_, _ = fmt.Fprintf(&sb, "| Sections Failed | %d |\n", s.SectionsFailed)
	_, _ = fmt.Fprintf(&sb, "| Sections Skipped | %d |\n", s.SectionsSkipped)
	_, _ = fmt.Fprintf(&sb, "| Active Pass Rate | %.2f%% |\n\n", s.PassRatePct)

	if len(s.Categories) > 0 {
		sb.WriteString("### Category Breakdown\n\n")
		sb.WriteString("| Category | Files | Passed | Failed | Skipped | Pass Rate |\n")
		sb.WriteString("|---|---:|---:|---:|---:|---:|\n")
		for _, c := range s.Categories {
			_, _ = fmt.Fprintf(&sb, "| `%s` | %d | %d | %d | %d | %.2f%% |\n",
				c.Category, c.Files, c.Passed, c.Failed, c.Skipped, c.PassRatePct)
		}
		sb.WriteByte('\n')
	}

	if len(s.FailureSamples) > 0 {
		limit := len(s.FailureSamples)
		if limit > maxMarkdownFailureSamples {
			limit = maxMarkdownFailureSamples
		}
		_, _ = fmt.Fprintf(&sb, "### Failure Samples (showing %d of %d recorded)\n\n", limit, len(s.FailureSamples))
		sb.WriteString("| File | Section | Error |\n")
		sb.WriteString("|---|---|---|\n")
		for i := 0; i < limit; i++ {
			f := s.FailureSamples[i]
			errClean := strings.ReplaceAll(f.Error, "\n", " ")
			errClean = strings.ReplaceAll(errClean, "|", "\\|")
			if len(errClean) > 180 {
				errClean = errClean[:177] + "..."
			}
			secClean := strings.ReplaceAll(f.Section, "|", "\\|")
			_, _ = fmt.Fprintf(&sb, "| `%s` | `%s` | %s |\n", f.File, secClean, errClean)
		}
		sb.WriteByte('\n')
	}

	return sb.String()
}

// WriteJSON serializes the SuiteScorecard as indented JSON to path, creating parent directories if needed.
func (s *SuiteScorecard) WriteJSON(path string) error {
	if s == nil {
		return fmt.Errorf("scorecard: cannot write nil SuiteScorecard")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("scorecard: creating directory %s: %w", dir, err)
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("scorecard: marshaling JSON: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("scorecard: writing %s: %w", path, err)
	}
	return nil
}
