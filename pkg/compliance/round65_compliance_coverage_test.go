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
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRound65_F10F12ActionsAndTracking(t *testing.T) {
	t.Parallel()

	// 1. indices.put_template_with_param: requires name, preserves template & order params, tracks cleanup.
	if _, err := (&runnerContext{}).buildActionRequest("indices.put_template_with_param", map[string]any{}); err == nil {
		t.Fatal("expected error when name parameter is missing for indices.put_template_with_param")
	}

	var recorded []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		recorded = append(recorded, r.Method+" "+r.URL.RequestURI()+" body="+strings.TrimSpace(string(body)))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"acknowledged":true}`))
	}))
	defer srv.Close()

	ctx := newRunnerContext(srv.Client(), srv.URL)
	spec, err := ctx.buildActionRequest("indices.put_template_with_param", map[string]any{
		"name":     "compat tmpl/v1",
		"template": "logs-*",
		"order":    3,
		"body":     map[string]any{"mappings": map[string]any{"properties": map[string]any{"msg": map[string]any{"type": "text"}}}},
	})
	if err != nil {
		t.Fatalf("buildActionRequest(indices.put_template_with_param) failed: %v", err)
	}
	if spec.method != http.MethodPut || spec.path != "/_template/compat%20tmpl%2Fv1" {
		t.Fatalf("unexpected request spec: method=%s path=%s", spec.method, spec.path)
	}
	if spec.query.Get("template") != "logs-*" || spec.query.Get("order") != "3" {
		t.Fatalf("expected template and order query params, got %v", spec.query)
	}

	ctx.trackCreatedResources("indices.put_template_with_param", map[string]any{"name": "compat_tmpl"}, nil)
	if !ctx.createdLegacyTmpls["compat_tmpl"] {
		t.Fatal("expected compat_tmpl in createdLegacyTmpls")
	}
	ctx.cleanupAll()
	if len(recorded) == 0 || !strings.Contains(recorded[0], "DELETE /_template/compat_tmpl") {
		t.Fatalf("expected cleanupAll to delete tracked legacy template, got %v", recorded)
	}

	// 2. cluster.post_voting_config_exclusions_with_node_name_part: requires node_name and URL-escapes path segment.
	if _, err := ctx.buildActionRequest("cluster.post_voting_config_exclusions_with_node_name_part", map[string]any{}); err == nil {
		t.Fatal("expected error when node_name parameter is missing")
	}
	exclSpec, err := ctx.buildActionRequest("cluster.post_voting_config_exclusions_with_node_name_part", map[string]any{
		"node_name":        "node with/slash",
		"wait_for_removal": false,
	})
	if err != nil {
		t.Fatalf("buildActionRequest(cluster.post_voting_config_exclusions_with_node_name_part) failed: %v", err)
	}
	if exclSpec.method != http.MethodPost || exclSpec.path != "/_cluster/voting_config_exclusions/node%20with%2Fslash" {
		t.Fatalf("unexpected voting exclusions spec: method=%s path=%s", exclSpec.method, exclSpec.path)
	}
	if exclSpec.query.Get("wait_for_removal") != "false" {
		t.Fatalf("expected wait_for_removal=false query param, got %v", exclSpec.query)
	}
}

func TestRound65_RunnerAssertionsLookupAndRegexHelpers(t *testing.T) {
	t.Parallel()

	ctx := newRunnerContext(&http.Client{}, "http://conformance.local")
	ctx.lastHeaders["content-type"] = "application/json"
	ctx.lastHeaders["x-custom"] = "ok"
	ctx.stash["target"] = map[string]any{"nested": []any{"a", "b"}}
	ctx.lastBodyKind = bodyKindParsed
	ctx.lastBodyRaw = `{"items":["x","y"],"buckets":{"b1":{"score":1.25,"tags":["t1","t2"]},"b2":{"score":10.5,"tags":[]}},"dotted\\.key":{"inner":"v"},"nested":{"a.b":[10,20]},"arr":[{"k":"v"}]}`
	ctx.lastResponse = map[string]any{
		"items": []any{"x", "y"},
		"buckets": map[string]any{
			"b1": map[string]any{"score": 1.25, "tags": []any{"t1", "t2"}},
			"b2": map[string]any{"score": 10.5, "tags": []any{}},
		},
		"dotted.key": map[string]any{"inner": "v"},
		"nested": map[string]any{
			"a": map[string]any{"b": []any{10, 20}},
		},
		"arr": []any{map[string]any{"k": "v"}},
	}

	// Headers + dotted fallback + negative slice index + stash root + _arbitrary_key_
	if v, ok := ctx.lookupResponsePath("$headers.Content-Type"); !ok || v != "application/json" {
		t.Fatalf("expected header lookup, got v=%v ok=%v", v, ok)
	}
	if v, ok := ctx.lookupResponsePath("headers.x-custom"); !ok || v != "ok" {
		t.Fatalf("expected headers.* lookup, got v=%v ok=%v", v, ok)
	}
	if v, ok := ctx.lookupResponsePath(".$target.nested.-1"); !ok || v != "b" {
		t.Fatalf("expected leading dot + stash + negative index lookup, got v=%v ok=%v", v, ok)
	}
	if v, ok := ctx.lookupResponsePath(`dotted\.key.inner`); !ok || v != "v" {
		t.Fatalf("expected escaped dot key lookup, got v=%v ok=%v", v, ok)
	}
	if v, ok := ctx.lookupResponsePath("nested.a\\.b.-1"); !ok || v != 20 {
		t.Fatalf("expected nested.a\\.b.-1 dotted fallback = 20, got v=%v ok=%v", v, ok)
	}
	if v, ok := ctx.lookupResponsePath("nested.a\\.missing"); ok {
		t.Fatalf("expected missing escaped segment lookup to return false, got %v", v)
	}
	// Trigger lookupDottedFallback via single dotted segment when node["a.b"] doesn't exist literally
	if v, ok := lookupSegments(map[string]any{"a": map[string]any{"b": []any{10, 20}}}, []string{"a.b.-1"}); !ok || v != 20 {
		t.Fatalf("expected lookupDottedFallback to resolve a.b.-1 = 20, got v=%v ok=%v", v, ok)
	}
	if cands := lookupAllSegments(map[string]any{"a": map[string]any{"b": 7}}, []string{"a.b"}); len(cands) != 1 || cands[0] != 7 {
		t.Fatalf("expected lookupAllSegments dotted fallback, got %v", cands)
	}

	// execExists / execNotExists ($body HEAD 200/404, bodyKindNone/Null, _arbitrary_key_, slice list)
	headCtx := newRunnerContext(&http.Client{}, "http://conformance.local")
	headCtx.lastMethod = http.MethodHead
	headCtx.lastStatus = http.StatusOK
	if err := headCtx.execExists("$body"); err != nil {
		t.Fatalf("HEAD 200 exists $body failed: %v", err)
	}
	headCtx.lastStatus = http.StatusNotFound
	if err := headCtx.execExists("$body"); err == nil {
		t.Fatal("expected HEAD 404 exists $body to fail")
	}
	if err := headCtx.execNotExists("$body"); err != nil {
		t.Fatalf("HEAD 404 not_exists $body failed: %v", err)
	}
	headCtx.lastStatus = http.StatusOK
	if err := headCtx.execNotExists("$body"); err == nil {
		t.Fatal("expected HEAD 200 not_exists $body to fail")
	}
	nullCtx := newRunnerContext(&http.Client{}, "http://conformance.local")
	nullCtx.lastBodyKind = bodyKindJSONNull
	if err := nullCtx.execExists("$body"); err == nil {
		t.Fatal("expected JSON null body exists to fail")
	}
	noneCtx := newRunnerContext(&http.Client{}, "http://conformance.local")
	noneCtx.lastBodyKind = bodyKindNone
	if err := noneCtx.execNotExists("$body"); err != nil {
		t.Fatalf("expected bodyKindNone not_exists $body to succeed: %v", err)
	}
	if err := ctx.execExists("buckets._arbitrary_key_.score"); err != nil {
		t.Fatalf("exists _arbitrary_key_ failed: %v", err)
	}
	if err := ctx.execExists("buckets._arbitrary_key_.nonexistent"); err == nil {
		t.Fatal("expected exists missing _arbitrary_key_ path to fail")
	}
	if err := ctx.execNotExists([]any{"missing1", "buckets._arbitrary_key_.missing2"}); err != nil {
		t.Fatalf("not_exists slice failed: %v", err)
	}
	if err := ctx.execNotExists("buckets._arbitrary_key_.score"); err == nil {
		t.Fatal("expected not_exists present _arbitrary_key_ path to fail")
	}

	// execCloseTo both forms + error paths
	if err := ctx.execCloseTo(map[string]any{"field": "buckets._arbitrary_key_.score", "value": 10.4, "error": 0.2}); err != nil {
		t.Fatalf("close_to field/value/error form failed: %v", err)
	}
	if err := ctx.execCloseTo(map[string]any{"buckets.b1.score": map[string]any{"value": 1.2, "error": 0.1}}); err != nil {
		t.Fatalf("close_to nested map form failed: %v", err)
	}
	for _, badCloseTo := range []any{
		map[string]any{"field": "buckets.b1.score", "value": "bad", "error": 0.1},
		map[string]any{"field": "buckets.b1.score", "value": 1.0, "error": -1},
		map[string]any{"field": "buckets._arbitrary_key_.score", "value": 99.0, "error": 0.1},
		map[string]any{"field": "buckets._arbitrary_key_.missing", "value": 1.0, "error": 0.1},
		map[string]any{"field": "arr.0.k", "value": 1.0, "error": 0.1},
		map[string]any{"missing_field": map[string]any{"value": 1.0, "error": 0.1}},
		map[string]any{"buckets.b1.score": map[string]any{"value": 1.0}},
	} {
		if err := ctx.execCloseTo(badCloseTo); err == nil {
			t.Fatalf("expected close_to failure for %#v", badCloseTo)
		}
	}

	// execIsEmpty + isEmptyValue + isTruthy + execLength
	emptyCtx := newRunnerContext(&http.Client{}, "http://conformance.local")
	emptyCtx.lastResponse = NewOrderedMap()
	if err := emptyCtx.execIsEmpty(""); err != nil {
		t.Fatalf("expected empty OrderedMap is_empty '' to pass: %v", err)
	}
	if !isEmptyValue(OrderedMap{}) || isEmptyValue(123) {
		t.Fatal("unexpected isEmptyValue behavior")
	}
	if err := ctx.execIsEmpty("buckets.b2.tags"); err != nil {
		t.Fatalf("expected empty slice path is_empty to pass: %v", err)
	}
	if err := ctx.execIsEmpty("buckets._arbitrary_key_.missing"); err != nil {
		t.Fatalf("expected missing _arbitrary_key_ is_empty to pass: %v", err)
	}
	if err := ctx.execIsEmpty(map[string]any{"buckets.b1.tags": ""}); err == nil {
		t.Fatal("expected non-empty slice map is_empty to fail")
	}
	if err := ctx.execIsEmpty("items"); err == nil {
		t.Fatal("expected non-empty path is_empty to fail")
	}
	for _, truthy := range []any{int8(1), int16(1), int32(1), int64(1), uint(1), uint8(1), uint16(1), uint32(1), uint64(1), float32(1.5), float64(2.5), json.Number("10"), json.Number("18446744073709551615"), json.Number("1.25"), json.Number("abc"), OrderedMap{}} {
		if !isTruthy(truthy) {
			t.Fatalf("expected isTruthy(%T %v) == true", truthy, truthy)
		}
	}
	for _, falsy := range []any{nil, false, int(0), int64(0), float32(0), float64(math.NaN()), json.Number("0"), ""} {
		if isTruthy(falsy) {
			t.Fatalf("expected isTruthy(%T %v) == false", falsy, falsy)
		}
	}
	if err := ctx.execLength(map[string]any{"arr.0.k": 1, "buckets.b1.tags": 2, "buckets": 2, "$target.nested": 2}); err != nil {
		t.Fatalf("execLength failed: %v", err)
	}
	if err := ctx.execLength(map[string]any{"buckets.b1.score": 1}); err == nil {
		t.Fatal("expected unsupported type error in execLength")
	}

	// execNotContains + checkSingleNotContains map/regex/string/unsupported branches
	if err := ctx.execNotContains(map[string]any{
		"buckets":                      "/^missing/",
		"buckets.b2.tags":              "anything",
		"arr.0.k":                      "zzz",
		"buckets._arbitrary_key_.tags": "absent",
	}); err != nil {
		t.Fatalf("execNotContains positive cases failed: %v", err)
	}
	for _, failingNC := range []map[string]any{
		{"buckets": "b1"},
		{"buckets": "/^b[0-9]$/"},
		{"buckets": map[string]any{"b1": map[string]any{"score": 1.25}}},
		{"arr.0.k": "v"},
		{"buckets.b1.tags": "t1"},
		{"buckets.b1.score": 1.25},
		{"buckets._arbitrary_key_.tags": "t2"},
	} {
		if err := ctx.execNotContains(failingNC); err == nil {
			t.Fatalf("expected execNotContains to fail for %#v", failingNC)
		}
	}

	// compareStringValues (timestamps, semver) & compareAsNumbers (big int, Inf, NaN)
	if compareStringValues("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z") >= 0 {
		t.Fatal("expected RFC3339 timestamp comparison < 0")
	}
	if compareStringValues("v8.15.5", "v8.15.4") <= 0 {
		t.Fatal("expected semver comparison > 0")
	}
	if cmp, ok := compareAsNumbers(json.Number("9007199254740993"), float64(math.Inf(1))); !ok || cmp >= 0 {
		t.Fatalf("expected exact int < +Inf, got cmp=%d ok=%v", cmp, ok)
	}
	if cmp, ok := compareAsNumbers(float64(math.Inf(-1)), json.Number("10")); !ok || cmp >= 0 {
		t.Fatalf("expected -Inf < exact int, got cmp=%d ok=%v", cmp, ok)
	}
	if _, ok := compareAsNumbers(json.Number("10"), math.NaN()); ok {
		t.Fatal("expected NaN number comparison to return false")
	}

	// validateResponseWarnings (RFC7234 escaping, Pass1/Pass2, regex, allowed, HEAD, unexpected)
	err := validateResponseWarnings(
		"search",
		http.MethodGet,
		true,
		[]string{
			`299 Elasticsearch-8.15.5-abc "Deprecated \"query\" param"`,
			`299 Elasticsearch-8.15.5-abc "Secondary minor note"`,
			`299 Elasticsearch-8.15.5-abc "Noise allowed header"`,
		},
		[]string{`Deprecated "query" param`, "minor"},
		[]string{`/Secondary\s+minor/`},
		[]string{"Noise allowed"},
		[]string{`^Noise`},
	)
	if err != nil {
		t.Fatalf("validateResponseWarnings expected pass, got %v", err)
	}
	if err := validateResponseWarnings("head", http.MethodHead, false, []string{`299 host "unasked"`}, nil, nil, nil, nil); err != nil {
		t.Fatalf("HEAD without warning directive should ignore unexpected headers, got %v", err)
	}
	if err := validateResponseWarnings("search", http.MethodGet, true, []string{`299 host "unexpected"`}, nil, nil, nil, nil); err == nil {
		t.Fatal("expected unexpected warning header error")
	}
	if err := validateResponseWarnings("search", http.MethodGet, true, nil, []string{"missing"}, nil, nil, nil); err == nil {
		t.Fatal("expected missing expected warning error")
	}
	if err := validateResponseWarnings("search", http.MethodGet, true, nil, nil, []string{"[unclosed"}, nil, nil); err == nil {
		t.Fatal("expected invalid warnings_regex error")
	}
	if err := validateResponseWarnings("search", http.MethodGet, true, nil, nil, nil, nil, []string{"[unclosed"}); err == nil {
		t.Fatal("expected invalid allowed_warnings_regex error")
	}

	// collectStructuredErrorStrings + extractErrorText
	structured := map[string]any{
		"error": map[string]any{
			"type":       "search_phase_execution_exception",
			"reason":     "all shards failed",
			"root_cause": []any{map[string]any{"type": "parsing_exception"}},
			"caused_by":  map[string]any{"reason": "bad token"},
			"failed_shards": []any{
				map[string]any{"reason": map[string]any{"type": "illegal_argument_exception", "reason": "bad field"}},
			},
		},
	}
	gotErrText := extractErrorText(structured, "raw")
	for _, want := range []string{"search_phase_execution_exception: all shards failed", "parsing_exception", "reason=bad token", "illegal_argument_exception: bad field"} {
		if !strings.Contains(gotErrText, want) {
			t.Fatalf("extractErrorText (%q) missing %q", gotErrText, want)
		}
	}
	if got := extractErrorText(map[string]any{"error": "string err"}, "raw"); got != "string err" {
		t.Fatalf("expected string error, got %q", got)
	}

	// stripESCommentsMode + extractInlineCommentsFlag + rewriteJavaEndAnchorForRE2 + compileRegexWithMode
	stripped := stripESCommentsMode(`foo [[:alpha:]\]a] \Q#keep space\E \#lit\  # trailing comment` + "\nbar$")
	if !strings.Contains(stripped, `#keep space`) || !strings.Contains(stripped, `#lit`) || strings.Contains(stripped, "trailing comment") {
		t.Fatalf("unexpected stripESCommentsMode output: %q", stripped)
	}
	noX, hasX := extractInlineCommentsFlag(`(?x)a b(?-x)c\ d[x(?x)]`)
	if !hasX || noX != `a bc\ d[x(?x)]` {
		t.Fatalf("unexpected extractInlineCommentsFlag: pat=%q hasX=%v", noX, hasX)
	}
	rewritten := rewriteJavaEndAnchorForRE2(`^a$(?m:^b$)$`, false)
	if !strings.Contains(rewritten, `\z`) || !strings.Contains(rewritten, `(?m:^b$)`) {
		t.Fatalf("unexpected rewriteJavaEndAnchorForRE2: %q", rewritten)
	}
	re, isRe, compErr := compileRegexWithMode("/hello\\s+world/ixms", false)
	if compErr != nil || !isRe || !re.MatchString("HELLO   WORLD") {
		t.Fatalf("expected /ixms regex to compile and match, got re=%v isRe=%v err=%v", re, isRe, compErr)
	}
	if _, isRe, _ := compileRegexWithMode("/abc/z", false); isRe {
		t.Fatal("expected unknown regex flag /z not to be treated as regex")
	}
}

func TestRound65_SchemaValidatorCoverage(t *testing.T) {
	t.Parallel()

	// validateEsqlColumnsJSON valid + every error case
	validEsql := map[string]any{
		"columns": []any{
			map[string]any{"name": "count", "type": "long"},
		},
		"values": []any{
			[]any{42},
		},
	}
	if err := validateEsqlColumnsJSON("$", validEsql); err != nil {
		t.Fatalf("valid EsqlColumns rejected: %v", err)
	}
	for _, bad := range []map[string]any{
		{},
		{"columns": "not-array", "values": []any{}},
		{"columns": []any{"not-object"}, "values": []any{}},
		{"columns": []any{map[string]any{"type": "long"}}, "values": []any{}},
		{"columns": []any{map[string]any{"name": "x"}}, "values": []any{}},
		{"columns": []any{map[string]any{"name": "x", "type": "long"}}},
		{"columns": []any{map[string]any{"name": "x", "type": "long"}}, "values": "not-array"},
		{"columns": []any{map[string]any{"name": "x", "type": "long"}}, "values": []any{"bad-row"}},
	} {
		if err := validateEsqlColumnsJSON("$", bad); err == nil {
			t.Fatalf("expected validateEsqlColumnsJSON failure for %#v", bad)
		}
	}

	// isConditionallyOmittedSpecProperty
	omittedCases := []struct {
		key  specTypeKey
		prop string
		want bool
	}{
		{specTypeKey{Namespace: "_types", Name: "SegmentsStats"}, "file_sizes", true},
		{specTypeKey{Namespace: "cluster.stats", Name: "ClusterNodes"}, "indexing_pressure", true},
		{specTypeKey{Namespace: "cluster.stats", Name: "ClusterNodeCount"}, "data_hot", true},
		{specTypeKey{Namespace: "cluster.stats", Name: "ClusterNodeCount"}, "voting_only", true},
		{specTypeKey{Namespace: "cluster.stats", Name: "ClusterOperatingSystem"}, "pretty_names", true},
		{specTypeKey{Namespace: "indices._types", Name: "DataStream"}, "template", true},
		{specTypeKey{Namespace: "indices._types", Name: "DataStreamIndex"}, "managed_by", true},
		{specTypeKey{Namespace: "_global.rank_eval", Name: "RankEvalHit"}, "_score", true},
		{specTypeKey{Namespace: "_types", Name: "Other"}, "file_sizes", false},
	}
	for _, tc := range omittedCases {
		if got := isConditionallyOmittedSpecProperty(tc.key, tc.prop); got != tc.want {
			t.Fatalf("isConditionallyOmittedSpecProperty(%v, %q) = %v, want %v", tc.key, tc.prop, got, tc.want)
		}
	}

	// validateBuiltinType + validateIntegralConstraint + validateEnumType
	for _, good := range []struct {
		val  any
		kind string
	}{
		{"ok", "string"},
		{true, "boolean"},
		{42, "number"},
		{nil, "null"},
		{"AQID", "binary"},
		{[]any{1, 2}, "binary"},
		{nil, "void"},
		{map[string]any{}, "void"},
	} {
		if err := validateBuiltinType("$", good.val, good.kind); err != nil {
			t.Fatalf("validateBuiltinType(%q) failed on valid value %#v: %v", good.kind, good.val, err)
		}
	}
	for _, bad := range []struct {
		val  any
		kind string
	}{
		{1, "string"},
		{"true", "boolean"},
		{"42", "number"},
		{"not-null", "null"},
		{123, "binary"},
		{"not-void", "void"},
		{"x", "no_such_builtin"},
	} {
		if err := validateBuiltinType("$", bad.val, bad.kind); err == nil {
			t.Fatalf("expected validateBuiltinType(%q) error on %#v", bad.kind, bad.val)
		}
	}

	if err := validateIntegralConstraint("$", 12, "unsigned_long"); err != nil {
		t.Fatalf("expected non-negative unsigned_long to pass: %v", err)
	}
	for _, badInt := range []struct {
		val  any
		kind string
	}{
		{"12", "integer"},
		{1.5, "long"},
		{-1, "unsigned_long"},
		{-2, "uint"},
	} {
		if err := validateIntegralConstraint("$", badInt.val, badInt.kind); err == nil {
			t.Fatalf("expected validateIntegralConstraint error for (%v, %s)", badInt.val, badInt.kind)
		}
	}

	closedEnum := specTypeDef{
		Name: specTypeName{Namespace: "_types", Name: "WaitMode"},
		Members: []specEnumMember{
			{Name: "true"},
			{Name: "all", Aliases: []string{"everything"}},
		},
	}
	if err := validateEnumType("$", true, closedEnum); err != nil {
		t.Fatalf("bool true enum failed: %v", err)
	}
	if err := validateEnumType("$", "everything", closedEnum); err != nil {
		t.Fatalf("enum alias match failed: %v", err)
	}
	if err := validateEnumType("$", 42, closedEnum); err == nil {
		t.Fatal("expected non-string/bool enum rejection")
	}
	if err := validateEnumType("$", "unknown", closedEnum); err == nil {
		t.Fatal("expected unknown closed enum value rejection")
	}
	openEnum := specTypeDef{Name: specTypeName{Namespace: "_types", Name: "OpenKind"}, IsOpen: true}
	if err := validateEnumType("$", "custom_value", openEnum); err != nil {
		t.Fatalf("expected open enum string pass: %v", err)
	}
	if err := validateEnumType("$", true, openEnum); err == nil {
		t.Fatal("expected open enum non-string rejection")
	}
}

func TestRound65_YAMLAndScorecardEdgeCases(t *testing.T) {
	t.Parallel()

	// parseCapabilityRequirements: slice + single + comma split + ignored item
	seqRaw := []any{
		&OrderedMap{Fields: []YAMLField{
			{Key: "method", Value: "post"},
			{Key: "path", Value: "/_search"},
			{Key: "parameters", Value: "q, size"},
			{Key: "capabilities", Value: []any{"cap1, cap2", "cap3"}},
		}},
		"not-a-map",
	}
	reqs := parseCapabilityRequirements(seqRaw)
	if len(reqs) != 1 || reqs[0].Method != "POST" || reqs[0].Path != "/_search" || len(reqs[0].Parameters) != 2 || len(reqs[0].Capabilities) != 3 {
		t.Fatalf("unexpected parseCapabilityRequirements output: %+v", reqs)
	}
	singleReqs := parseCapabilityRequirements(OrderedMap{Fields: []YAMLField{{Key: "method", Value: "get"}, {Key: "path", Value: "/"}}})
	if len(singleReqs) != 1 || singleReqs[0].Method != "GET" {
		t.Fatalf("unexpected single parseCapabilityRequirements output: %+v", singleReqs)
	}
	if nilReqs := parseCapabilityRequirements("invalid"); nilReqs != nil {
		t.Fatalf("expected nil capability requirements, got %+v", nilReqs)
	}

	// buildMergedOrderedMap + extractMergeSourceMaps
	src1 := NewOrderedMap()
	src1.Set("a", 1)
	src1.Set("b", 2)
	src2 := OrderedMap{Fields: []YAMLField{{Key: "b", Value: 99}, {Key: "c", Value: 3}}}
	merged, err := buildMergedOrderedMap([]parsedMapEntry{
		{key: "a", val: 100},
		{isMerge: true, val: []any{src1, src2}},
	})
	if err != nil {
		t.Fatalf("buildMergedOrderedMap failed: %v", err)
	}
	if va, _ := merged.Get("a"); va != 100 {
		t.Fatalf("expected explicit key precedence a=100, got %v", va)
	}
	if vb, _ := merged.Get("b"); vb != 2 {
		t.Fatalf("expected first merge map to win b=2, got %v", vb)
	}
	if vc, _ := merged.Get("c"); vc != 3 {
		t.Fatalf("expected second merge map c=3, got %v", vc)
	}
	for _, badMerge := range []any{(*OrderedMap)(nil), []any{(*OrderedMap)(nil)}, []any{"bad"}, 123} {
		if _, err := extractMergeSourceMaps(badMerge); err == nil {
			t.Fatalf("expected extractMergeSourceMaps error for %#v", badMerge)
		}
	}

	// isBasicLicenseRestrictionOnlySpec
	licDoc := &SpecDocument{
		Sections: []SpecSection{
			{
				Name: "license gated",
				Steps: []SpecStep{
					{Op: "do", Value: &OrderedMap{Fields: []YAMLField{{Key: "catch", Value: "forbidden"}}}},
					{Op: "match", Value: &OrderedMap{Fields: []YAMLField{{Key: "error.reason", Value: "current license is non-compliant for [rrf]"}}}},
				},
			},
		},
	}
	if !isBasicLicenseRestrictionOnlySpec(licDoc) {
		t.Fatal("expected basic license restriction spec detection = true")
	}
	if isBasicLicenseRestrictionOnlySpec(nil) {
		t.Fatal("expected nil SpecDocument = false")
	}

	// FormatMarkdown & WriteJSON edge cases
	var nilCard *SuiteScorecard
	if nilCard.FormatMarkdown() != "" {
		t.Fatal("expected empty markdown for nil scorecard")
	}
	if err := nilCard.WriteJSON(filepath.Join(t.TempDir(), "x.json")); err == nil {
		t.Fatal("expected error writing nil scorecard")
	}

	card := &SuiteScorecard{
		Corpus:         "test-corpus",
		TargetVersion:  "8.15.5",
		TotalFiles:     2,
		SectionsTotal:  3,
		SectionsPassed: 2,
		SectionsFailed: 1,
		PassRatePct:    computePassRatePct(2, 1),
		Categories:     []CategoryScore{{Category: "search", Files: 2, Passed: 2, Failed: 1, PassRatePct: 66.67}},
		FailureSamples: make([]SectionFailure, maxMarkdownFailureSamples+2),
	}
	for i := range card.FailureSamples {
		card.FailureSamples[i] = SectionFailure{
			File:    "search/10_basic.yml",
			Section: "sec|a",
			Error:   strings.Repeat("x", 200) + "\n|pipe",
		}
	}
	md := card.FormatMarkdown()
	if !strings.Contains(md, "showing 25 of 27 recorded") || !strings.Contains(md, `sec\|a`) || !strings.Contains(md, "...") {
		t.Fatalf("unexpected FormatMarkdown output:\n%s", md)
	}
	tmpDir := t.TempDir()
	outJSON := filepath.Join(tmpDir, "nested", "scorecard.json")
	if err := card.WriteJSON(outJSON); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	rawJSON, err := os.ReadFile(outJSON)
	if err != nil {
		t.Fatalf("reading written scorecard JSON: %v", err)
	}
	var decoded SuiteScorecard
	if err := json.Unmarshal(rawJSON, &decoded); err != nil || decoded.Corpus != "test-corpus" {
		t.Fatalf("unexpected scorecard JSON: err=%v decoded=%+v", err, decoded)
	}
	badParentFile := filepath.Join(tmpDir, "file.txt")
	if err := os.WriteFile(badParentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := card.WriteJSON(filepath.Join(badParentFile, "child.json")); err == nil {
		t.Fatal("expected WriteJSON error when parent path is a file")
	}

	// YAML anchor/alias error handling & deepCloneYAMLValue OrderedMap value path
	yp := &yamlParser{}
	if _, err := yp.resolveAlias(""); err == nil {
		t.Fatal("expected empty alias error")
	}
	if _, err := yp.resolveAlias("bad alias"); err == nil {
		t.Fatal("expected whitespace alias error")
	}
	if _, err := yp.resolveAlias("missing"); err == nil {
		t.Fatal("expected undefined alias error")
	}
	yp.setAnchor("m", OrderedMap{Fields: []YAMLField{{Key: "arr", Value: []any{map[string]any{"x": 1}}}}})
	if cloned, err := yp.parseScalarOrAlias("*m"); err != nil || cloned == nil {
		t.Fatalf("expected *m alias resolution, got cloned=%v err=%v", cloned, err)
	}
	if _, _, _, err := extractLeadingAnchor("&"); err == nil {
		t.Fatal("expected empty anchor name error")
	}

	// executeReadOnlyFileWithSharedSetup: setup skip, setup panic/fail, section skip & failure & panic
	okHandler := func() (http.Handler, func()) {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}), func() { panic("ignored cleanup panic") }
	}
	noopFail := func(file, cat, section, errMsg string) {}

	scSkip := &SuiteScorecard{}
	csSkip := CategoryScore{}
	executeReadOnlyFileWithSharedSetup(
		nil, okHandler, nil, "8.15.5", nil, nil, "f.yml", "search",
		&SpecDocument{
			Setup:    []SpecStep{{Op: "skip", Value: map[string]any{"features": "nonexistent_feature"}}},
			Sections: []SpecSection{{Name: "s1"}, {Name: "s2"}},
		},
		scSkip, &csSkip, noopFail,
	)
	if scSkip.SectionsSkipped != 2 || csSkip.Skipped != 2 {
		t.Fatalf("expected setup skip to skip 2 sections, got sc=%+v cs=%+v", scSkip, csSkip)
	}

	scFail := &SuiteScorecard{}
	csFail := CategoryScore{}
	var recordedFail string
	executeReadOnlyFileWithSharedSetup(
		nil, okHandler, nil, "8.15.5", nil, nil, "f2.yml", "search",
		&SpecDocument{
			Setup:    []SpecStep{{Op: "do", Value: map[string]any{"nonexistent.action": map[string]any{}}}},
			Sections: []SpecSection{{Name: "s1"}},
		},
		scFail, &csFail, func(file, cat, section, errMsg string) { recordedFail = errMsg },
	)
	if scFail.SectionsFailed != 1 || !strings.Contains(recordedFail, "[setup step 1 (do)]") {
		t.Fatalf("expected setup failure recorded, got failed=%d msg=%q", scFail.SectionsFailed, recordedFail)
	}

	scMixed := &SuiteScorecard{}
	csMixed := CategoryScore{}
	executeReadOnlyFileWithSharedSetup(
		nil, okHandler, nil, "8.15.5", nil, nil, "f3.yml", "search",
		&SpecDocument{
			Setup: []SpecStep{
				{Op: "do", Value: &OrderedMap{Fields: []YAMLField{{Key: "info", Value: NewOrderedMap()}}}},
				{Op: "set", Value: map[string]any{"ok": "ok_val"}},
			},
			Sections: []SpecSection{
				{Name: "skipped_sec", Steps: []SpecStep{{Op: "skip", Value: map[string]any{"features": "missing_feat"}}}},
				{Name: "failed_sec", Steps: []SpecStep{{Op: "match", Value: map[string]any{"missing_path": "val"}}}},
			},
		},
		scMixed, &csMixed, noopFail,
	)
	if scMixed.SectionsSkipped != 1 || scMixed.SectionsFailed != 1 {
		t.Fatalf("expected 1 skipped + 1 failed section, got %+v", scMixed)
	}

	// executeScoredSection panic recovery when handler panics
	skipped, execErr := executeScoredSection(
		func() http.Handler { panic("boom") },
		"8.15.5", nil, nil,
		&SpecDocument{},
		SpecSection{Name: "panic_sec"},
	)
	if skipped || execErr == nil || !strings.Contains(execErr.Error(), "panic: boom") {
		t.Fatalf("expected recovered panic error, got skipped=%v err=%v", skipped, execErr)
	}
}
