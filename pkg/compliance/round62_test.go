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
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
)

func TestRound62_SplitEscapedPathDoubleAndSingleBackslashes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want []string
	}{
		{
			raw:  `aggregations.ranks.values.50\.0`,
			want: []string{"aggregations", "ranks", "values", "50.0"},
		},
		{
			raw:  `aggregations.ranks.values.50\\.0`,
			want: []string{"aggregations", "ranks", "values", "50.0"},
		},
		{
			raw:  `hits.hits.1.fields.obj\\.products.1`,
			want: []string{"hits", "hits", "1", "fields", "obj.products", "1"},
		},
		{
			raw:  `fields.text\\.keyword`,
			want: []string{"fields", "text.keyword"},
		},
		{
			raw:  `fields.level1\\.level2\\.leaf1`,
			want: []string{"fields", "level1.level2.leaf1"},
		},
		{
			raw:  `nodes.${node.id}.fs`,
			want: []string{"nodes", "${node.id}", "fs"},
		},
		{
			raw:  `meta.keep\\slash.sub`,
			want: []string{"meta", `keep\\slash`, "sub"},
		},
	}

	for _, tc := range cases {
		got := splitEscapedPath(tc.raw)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitEscapedPath(%q) = %#v, want %#v", tc.raw, got, tc.want)
		}
	}
}

func TestRound62_JavaRegexEndAnchorRewriteInRE2(t *testing.T) {
	t.Parallel()

	// 1. Multiline free-spacing match regexes (cat.aliases & cat.indices trailing \n)
	emptyCatRe, isRe, err := compileMatchRegex("/^\n            $/")
	if err != nil || !isRe {
		t.Fatalf("compileMatchRegex emptyCatRe failed: isRe=%v err=%v", isRe, err)
	}
	for _, okInput := range []string{"", "\n", "\r\n"} {
		if !emptyCatRe.MatchString(okInput) {
			t.Errorf("expected /^\\n$/ to match %q", okInput)
		}
	}
	if emptyCatRe.MatchString("index1\n") {
		t.Errorf("expected /^\\n$/ NOT to match non-empty line")
	}

	fooCatRe, isRe, err := compileMatchRegex("/^(foo)$/")
	if err != nil || !isRe {
		t.Fatalf("compileMatchRegex /^(foo)$/ failed: isRe=%v err=%v", isRe, err)
	}
	for _, okInput := range []string{"foo", "foo\n", "foo\r\n"} {
		if !fooCatRe.MatchString(okInput) {
			t.Errorf("expected /^(foo)$/ to match %q", okInput)
		}
	}
	if fooCatRe.MatchString("foo\nbar\n") {
		t.Errorf("expected /^(foo)$/ NOT to match two-line string")
	}

	// 2. Escaped literal \$, [$] character class, and \Q...\E literal quotes
	priceRe, _, err := compileMatchRegex(`/^price:\s+\$100[$]\Qend$\E$/`)
	if err != nil {
		t.Fatalf("compileMatchRegex priceRe failed: %v", err)
	}
	if !priceRe.MatchString("price: $100$end$\n") {
		t.Fatalf("expected priceRe to match literal dollars + trailing newline")
	}
	if priceRe.MatchString("price: 100$end$\n") {
		t.Fatalf("expected priceRe NOT to match when literal \\$ is missing")
	}

	// 3. Explicit /m and inline (?m) preserve line-by-line '$' behavior
	mFlagRe, _, err := compileComplianceRegex("/^alpha$/m")
	if err != nil || !mFlagRe.MatchString("alpha\nbeta") {
		t.Fatalf("expected /^alpha$/m to match first line of multi-line text (err=%v)", err)
	}
	inlineMRe, _, err := compileComplianceRegex("/(?m)^alpha$/")
	if err != nil || !inlineMRe.MatchString("alpha\nbeta") {
		t.Fatalf("expected /(?m)^alpha$/ to match first line of multi-line text (err=%v)", err)
	}
}

func TestRound62_MatchNullOnAbsentJSONPath(t *testing.T) {
	t.Parallel()

	ctx := newRunnerContext(http.DefaultClient, "http://conformance.local")
	ctx.lastStatus = http.StatusOK
	ctx.lastBodyRaw = `{}`
	ctx.lastBodyKind = bodyKindParsed
	ctx.lastResponse = map[string]any{}

	// Simulate indices.simulate_index_template/10_basic.yml: `- match: {body: null}` on `{}`
	if err := ctx.execMatch(map[string]any{"body": nil}); err != nil {
		t.Fatalf("expected match: {body: null} to succeed on absent path in {}, got: %v", err)
	}

	// Non-null value on present key must still fail match: {body: null}
	ctx.lastResponse = map[string]any{"body": map[string]any{"template": map[string]any{}}}
	if err := ctx.execMatch(map[string]any{"body": nil}); err == nil {
		t.Fatalf("expected match: {body: null} to fail when body is non-null object")
	}

	// Non-null expected value on absent path must still fail
	ctx.lastResponse = map[string]any{}
	if err := ctx.execMatch(map[string]any{"body": "expected"}); err == nil {
		t.Fatalf("expected match: {body: \"expected\"} to fail when body is absent")
	}
}

func TestRound62_YAMLUnquotedFloatPreservationAndPainlessExecute(t *testing.T) {
	t.Parallel()

	src := `---
"Painless float params":
  - do:
      scripts_painless_execute:
        body:
          script:
            source: "params.count / params.total"
            params:
              count: 100.0
              total: 1000.0
              pos_float: +5.0
              lead_dot: .5
              trail_dot: 10.
              sci_val: 1e2
              plain_int: 42
  - match: { result: "0.1" }
---
"Score context float division":
  - do:
      indices.create:
        index: my-index
        body:
          mappings:
            properties:
              rank:
                type: long
  - do:
      scripts_painless_execute:
        body:
          script:
            source: "doc['rank'].value / params.max_rank"
            params:
              max_rank: 5.0
          context: "score"
          context_setup:
            document:
              rank: 4
            index: "my-index"
  - match: { result: 0.8 }
`
	doc, err := ParseSpecFile(src)
	if err != nil {
		t.Fatalf("ParseSpecFile failed: %v", err)
	}
	nativeStep := ToNative(doc.Sections[0].Steps[0].Value).(map[string]any)
	bodyBytes, err := json.Marshal(nativeStep["scripts_painless_execute"].(map[string]any)["body"])
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	serialized := string(bodyBytes)
	for _, wantToken := range []string{
		`"count":100.0`,
		`"total":1000.0`,
		`"pos_float":5.0`,
		`"lead_dot":0.5`,
		`"trail_dot":10.0`,
		`"sci_val":1e2`,
		`"plain_int":42`,
	} {
		if !strings.Contains(serialized, wantToken) {
			t.Errorf("expected serialized JSON %s to contain %s", serialized, wantToken)
		}
	}

	// Execute against in-process proxy handler to verify Painless float division ("0.1" and 0.8)
	fsys := fstest.MapFS{
		"painless/70_inline.yml": &fstest.MapFile{Data: []byte(src)},
	}
	sc, err := ScoreSuiteFS(SuiteOptions{
		CorpusName:    "round62-painless-floats",
		TargetVersion: "8.15.5",
		NewHandler:    func() http.Handler { return newConformanceProxyHandler("8.15.5") },
	}, fsys)
	if err != nil {
		t.Fatalf("ScoreSuiteFS failed: %v", err)
	}
	if sc.SectionsPassed != 2 || sc.SectionsFailed != 0 {
		t.Fatalf("expected 2/2 Painless float sections to pass, got passed=%d failed=%d samples=%+v",
			sc.SectionsPassed, sc.SectionsFailed, sc.FailureSamples)
	}

	// Also run the cached upstream v7.10.2 painless/70_execute_painless_scripts.yml if available
	v7Painless := filepath.Join(conformanceCacheBaseDir(), "es-v7.10.2",
		"modules", "lang-painless", "src", "yamlRestTest", "resources", "rest-api-spec", "test", "painless", "70_execute_painless_scripts.yml")
	if raw, readErr := os.ReadFile(v7Painless); readErr == nil {
		upSC, upErr := ScoreSuiteFS(SuiteOptions{
			CorpusName:    "v7-painless-70",
			TargetVersion: "7.10.2",
			NewHandler:    func() http.Handler { return newConformanceProxyHandler("7.10.2") },
		}, fstest.MapFS{"painless/70_execute_painless_scripts.yml": &fstest.MapFile{Data: raw}})
		if upErr != nil {
			t.Fatalf("ScoreSuiteFS(v7 70_execute_painless_scripts.yml) failed: %v", upErr)
		}
		if upSC.SectionsFailed != 0 || upSC.SectionsPassed < 4 {
			t.Fatalf("expected upstream v7 70_execute_painless_scripts.yml to pass 100%%, got passed=%d failed=%d samples=%+v",
				upSC.SectionsPassed, upSC.SectionsFailed, upSC.FailureSamples)
		}
	}
}

func TestRound62_ContainsStashLookupMapKeyMembershipAndExtractErrorText(t *testing.T) {
	t.Parallel()

	ctx := newRunnerContext(http.DefaultClient, "http://conformance.local")
	ctx.lastStatus = http.StatusOK
	ctx.lastBodyKind = bodyKindParsed
	ctx.lastBodyRaw = `{"profile":{"shards":[{"id":"[nodeA][test][0]","node_id":"nodeA","index":"test"}]},"fields":{"text":{"text":{}},"text.keyword":{"keyword":{}}}}`
	ctx.lastResponse = parseResponsePayload(ctx.lastBodyRaw)

	// 1. Stash extraction + $composite_id lookup in contains & not_contains (370_profile.yml)
	if err := ctx.execSet(map[string]any{
		"profile.shards.0.id":      "composite_id",
		"profile.shards.0.node_id": "first_node_id",
		"profile.shards.0.index":   "first_index",
	}); err != nil {
		t.Fatalf("execSet failed: %v", err)
	}
	if err := ctx.execContains(map[string]any{
		"$composite_id": "$first_node_id",
	}); err != nil {
		t.Fatalf("execContains($composite_id: $first_node_id) failed: %v", err)
	}
	if err := ctx.execContains(map[string]any{
		"$composite_id": "$first_index",
	}); err != nil {
		t.Fatalf("execContains($composite_id: $first_index) failed: %v", err)
	}
	if err := ctx.execNotContains(map[string]any{
		"$composite_id": "other_node",
	}); err != nil {
		t.Fatalf("execNotContains($composite_id: other_node) failed: %v", err)
	}

	// 2. Map-key membership in contains / not_contains (field_caps/50_fieldtype_filter.yml)
	ctx.stash["kw_field"] = "text.keyword"
	ctx.stash["absent_field"] = "missing.keyword"
	if err := ctx.execContains(map[string]any{"fields": "$kw_field"}); err != nil {
		t.Fatalf("expected contains on map key text.keyword to pass: %v", err)
	}
	if err := ctx.execNotContains(map[string]any{"fields": "$absent_field"}); err != nil {
		t.Fatalf("expected not_contains on absent map key to pass: %v", err)
	}
	if err := ctx.execContains(map[string]any{"fields": "$absent_field"}); err == nil {
		t.Fatalf("expected contains on absent map key to fail")
	}
	if err := ctx.execNotContains(map[string]any{"fields": "$kw_field"}); err == nil {
		t.Fatalf("expected not_contains on present map key to fail")
	}

	// 3. Java ResponseException-style type=<t>, reason=<r> in extractErrorText
	errPayload := map[string]any{
		"error": map[string]any{
			"type":   "search_phase_execution_exception",
			"reason": "all shards failed",
			"root_cause": []any{
				map[string]any{
					"type":   "script_exception",
					"reason": "runtime error",
				},
			},
			"caused_by": map[string]any{
				"type":   "illegal_argument_exception",
				"reason": "[init_script] contains not allowed script: [sum_of_values]",
			},
		},
		"status": int64(400),
	}
	errText := extractErrorText(errPayload, "{}")
	for _, wantSub := range []string{
		"type=search_phase_execution_exception, reason=all shards failed",
		"type=script_exception, reason=runtime error",
		"type=illegal_argument_exception, reason=[init_script] contains not allowed script: [sum_of_values]",
	} {
		if !strings.Contains(errText, wantSub) {
			t.Errorf("extractErrorText missing %q in %q", wantSub, errText)
		}
	}
	if err := ctx.verifyCatch("/type=script_exception, reason=runtime error/", "search", http.StatusBadRequest, "{}", errPayload); err != nil {
		t.Fatalf("verifyCatch Java ResponseException regex failed: %v", err)
	}
}

func TestRound62_BulkNDJSONSerializationAndScoreMatchingFiles(t *testing.T) {
	t.Parallel()

	// 1. Verify empty bulk string produces 0 bytes and 7-element map list produces 7 NDJSON lines
	emptyBytes, err := serializeNDJSON("")
	if err != nil || len(emptyBytes) != 0 {
		t.Fatalf("serializeNDJSON(\"\") = %q (len=%d), err=%v; want empty", string(emptyBytes), len(emptyBytes), err)
	}
	oddBulk := []any{
		map[string]any{"index": map[string]any{}},
		map[string]any{"date": "2015-01-01"},
		map[string]any{"index": map[string]any{}},
	}
	oddBytes, err := serializeNDJSON(oddBulk)
	if err != nil {
		t.Fatalf("serializeNDJSON(oddBulk) failed: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(oddBytes), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 NDJSON lines, got %d: %q", len(lines), string(oddBytes))
	}

	// 2. Verify Flow Mapping colon-brace ("script:{...}") parses cleanly
	flowColonYAML := `---
"Flow colon brace":
  - do:
      search:
        body:
          sort: [ { _script: { script:{ lang: "painless", source: "1" }, type: "number" } } ]
`
	if _, err := ParseSpecFile(flowColonYAML); err != nil {
		t.Fatalf("ParseSpecFile(flowColonYAML) failed: %v", err)
	}

	// 3. Verify ScoreMatchingFiles filters files and runs per-section cleanup callbacks
	tmpDir := t.TempDir()
	keepDir := filepath.Join(tmpDir, "bulk")
	skipDir := filepath.Join(tmpDir, "other")
	if err := os.MkdirAll(keepDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(skipDir, 0o750); err != nil {
		t.Fatal(err)
	}
	specContent := "---\n\"s1\":\n  - do: { info: {} }\n---\n\"s2\":\n  - do: { info: {} }\n"
	if err := os.WriteFile(filepath.Join(keepDir, "10_basic.yml"), []byte(specContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skipDir, "99_ignored.yml"), []byte(specContent), 0o600); err != nil {
		t.Fatal(err)
	}

	var cleanups atomic.Int32
	sc, err := ScoreMatchingFiles(
		SuiteOptions{
			CorpusName:    "round62-filtered",
			TargetVersion: "8.15.5",
		},
		func(displayPath string) bool {
			return displayPath == "bulk/10_basic.yml"
		},
		func() (http.Handler, func()) {
			h := newConformanceProxyHandler("8.15.5")
			return h, func() { cleanups.Add(1) }
		},
		tmpDir,
	)
	if err != nil {
		t.Fatalf("ScoreMatchingFiles failed: %v", err)
	}
	if sc.TotalFiles != 1 || sc.SectionsPassed != 2 || sc.SectionsFailed != 0 {
		t.Fatalf("unexpected ScoreMatchingFiles result: %+v", sc)
	}
	// 1 probe cleanup + 2 section cleanups = 3 total cleanup invocations
	if cleanups.Load() < 2 {
		t.Fatalf("expected >= 2 cleanup invocations, got %d", cleanups.Load())
	}
}

func TestRound62_SpecSchemaValidatorErrorResponseBaseValidation(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join(conformanceCacheBaseDir(), "es-specification", "output", "schema", "schema.json")
	if _, err := os.Stat(schemaPath); err != nil {
		t.Skipf("skipping live schema.json ErrorResponseBase test (%s absent)", schemaPath)
	}
	v, err := LoadSpecSchemaValidator(schemaPath)
	if err != nil {
		t.Fatalf("LoadSpecSchemaValidator failed: %v", err)
	}

	// Valid 400, 404, and 409 structured ErrorResponseBase payloads
	valid409 := []byte(`{"error":{"root_cause":[{"type":"version_conflict_engine_exception","reason":"[order-1]: version conflict"}],"type":"version_conflict_engine_exception","reason":"[order-1]: version conflict"},"status":409}`)
	if err := v.ValidateHTTPResponse("index", http.StatusConflict, valid409); err != nil {
		t.Fatalf("expected valid 409 conflict payload to pass schema validation: %v", err)
	}
	valid400 := []byte(`{"error":{"type":"parsing_exception","reason":"unknown query [bad]"},"status":400}`)
	if err := v.ValidateHTTPResponse("search", http.StatusBadRequest, valid400); err != nil {
		t.Fatalf("expected valid 400 error payload to pass schema validation: %v", err)
	}

	// Malformed ErrorResponseBase payloads must fail validation
	invalidCases := []struct {
		name string
		code int
		body string
	}{
		{"missing status field", 400, `{"error":{"type":"parsing_exception","reason":"bad"}}`},
		{"mismatched status code", 409, `{"error":{"type":"version_conflict_engine_exception","reason":"conflict"},"status":400}`},
		{"non-string error.type", 400, `{"error":{"type":123,"reason":"bad"},"status":400}`},
	}
	for _, tc := range invalidCases {
		if err := v.ValidateHTTPResponse("index", tc.code, []byte(tc.body)); err == nil {
			t.Errorf("case %q: expected schema validation error on %s", tc.name, tc.body)
		}
	}
}

func TestRound62_ReuseSetupForReadOnlyFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	searchDir := filepath.Join(tmpDir, "search")
	if err := os.MkdirAll(searchDir, 0o750); err != nil {
		t.Fatal(err)
	}
	roSpec := `---
setup:
  - do:
      index:
        index: ro_idx
        id: "1"
        body: { tag: "alpha", n: 10 }
        refresh: true
  - set: { _id: saved_id }

---
"sec_count":
  - do:
      count:
        index: ro_idx
  - match: { count: 1 }

---
"sec_get":
  - do:
      get:
        index: ro_idx
        id: $saved_id
  - match: { _source.tag: "alpha" }

---
"sec_search":
  - do:
      search:
        index: ro_idx
        body: { query: { term: { tag: "alpha" } } }
  - match: { hits.total.value: 1 }
`
	if err := os.WriteFile(filepath.Join(searchDir, "10_ro.yml"), []byte(roSpec), 0o600); err != nil {
		t.Fatal(err)
	}

	var handlerCreates atomic.Int32
	sc, err := ScoreMatchingFiles(
		SuiteOptions{
			CorpusName:                 "ro-shared-setup",
			TargetVersion:              "8.15.5",
			ReuseSetupForReadOnlyFiles: true,
		},
		nil,
		func() (http.Handler, func()) {
			handlerCreates.Add(1)
			return newConformanceProxyHandler("8.15.5"), func() {}
		},
		tmpDir,
	)
	if err != nil {
		t.Fatalf("ScoreMatchingFiles(ReuseSetupForReadOnlyFiles) failed: %v", err)
	}
	if sc.SectionsPassed != 3 || sc.SectionsFailed != 0 {
		t.Fatalf("expected 3 passed / 0 failed, got %+v", sc)
	}
	// 1 probe handler + 1 shared file handler = 2 (instead of 1 + 3 = 4)
	if handlerCreates.Load() != 2 {
		t.Fatalf("expected 2 handler creations with shared read-only setup, got %d", handlerCreates.Load())
	}
}
