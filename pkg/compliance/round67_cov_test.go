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
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRound67_DefaultAuthHeaderInjectionOverrideAndCleanup(t *testing.T) {
	t.Parallel()

	var seenAuths []string
	var seenPaths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPaths = append(seenPaths, r.Method+" "+r.URL.Path)
		seenAuths = append(seenAuths, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/_capabilities" {
			_, _ = w.Write([]byte(`{"supported":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"acknowledged":true}`))
	}))
	defer ts.Close()

	wantDefault := "Basic " + base64.StdEncoding.EncodeToString([]byte(DefaultFixtureAuthUser+":"+DefaultFixtureAuthPass))
	if got := (RunOptions{DefaultAuthUser: DefaultFixtureAuthUser, DefaultAuthPass: DefaultFixtureAuthPass}).resolvedAuthHeader(); got != wantDefault {
		t.Fatalf("RunOptions.resolvedAuthHeader = %q, want %q", got, wantDefault)
	}
	if got := (RunOptions{DefaultAuthUser: "u", DefaultAuthPass: "p", DefaultAuthHeader: "Bearer custom-tok"}).resolvedAuthHeader(); got != "Bearer custom-tok" {
		t.Fatalf("explicit DefaultAuthHeader must win, got %q", got)
	}
	if got := (SuiteOptions{DefaultAuthUser: DefaultFixtureAuthUser, DefaultAuthPass: DefaultFixtureAuthPass}).resolvedAuthHeader(); got != wantDefault {
		t.Fatalf("SuiteOptions.resolvedAuthHeader = %q, want %q", got, wantDefault)
	}
	if got := (SuiteOptions{}).resolvedAuthHeader(); got != "" {
		t.Fatalf("empty SuiteOptions.resolvedAuthHeader = %q, want empty", got)
	}

	ctx := newRunnerContext(ts.Client(), ts.URL)
	ctx.setBasicAuth(DefaultFixtureAuthUser, DefaultFixtureAuthPass)

	// 1. Default auth injected when no explicit Authorization header is supplied.
	if status, _, err := ctx.rawHTTP(http.MethodGet, "/_cluster/health", nil, nil, nil); err != nil || status != http.StatusOK {
		t.Fatalf("rawHTTP default auth failed: status=%d err=%v", status, err)
	}
	if !ctx.probeServerCapability(CapabilityRequirement{Method: "GET", Path: "/_search"}) {
		t.Fatal("probeServerCapability expected true")
	}

	// 2. Explicit Authorization header preserves caller value case-insensitively.
	customHdr := "Basic dXNlcjpwYXNz"
	for _, hdrKey := range []string{"authorization", "AUTHORIZATION", "Authorization"} {
		if status, _, err := ctx.rawHTTP(http.MethodPost, "/_monitoring/bulk", nil, []byte("{}\n"), map[string]string{hdrKey: customHdr}); err != nil || status != http.StatusOK {
			t.Fatalf("rawHTTP explicit %s failed: status=%d err=%v", hdrKey, status, err)
		}
	}

	// 3. Teardown cleanupAll delegates to rawHTTP (PUT _settings + DELETE index + DELETE user) with default auth.
	ctx.createdSecurityUsers["temp_user"] = true
	ctx.createdIndices["temp_idx"] = true
	ctx.cleanupAll()

	wantSlice := []string{
		wantDefault,
		wantDefault,
		customHdr,
		customHdr,
		customHdr,
		wantDefault,
		wantDefault,
		wantDefault,
	}
	if len(seenAuths) != len(wantSlice) {
		t.Fatalf("recorded %d requests (%v), want %d", len(seenAuths), seenPaths, len(wantSlice))
	}
	for i, want := range wantSlice {
		if seenAuths[i] != want {
			t.Fatalf("req %d (%s) Authorization = %q, want %q", i, seenPaths[i], seenAuths[i], want)
		}
	}
}

func TestRound67_F16RunnerFeaturesAndF19InternalActions(t *testing.T) {
	t.Parallel()

	runnerFeats := DefaultSupportedTestRunnerFeatures()
	for _, feat := range []string{"spi_on_classpath_jdk9", "fips_140", "catch_unauthorized"} {
		if !runnerFeats[feat] {
			t.Fatalf("DefaultSupportedTestRunnerFeatures missing %q", feat)
		}
	}
	if runnerFeats["no_xpack"] {
		t.Fatalf("expected DefaultSupportedTestRunnerFeatures to leave no_xpack disabled when xpack is supported")
	}

	v7Cluster := DefaultSupportedClusterFeaturesForVersion("7.10.2")
	v8Cluster := DefaultSupportedClusterFeaturesForVersion("8.15.5")
	internalFeats := []string{
		"_internal.get_desired_balance",
		"_internal.delete_desired_balance",
		"_internal.update_desired_nodes",
		"_internal.get_desired_nodes",
		"_internal.delete_desired_nodes",
		"_internal.prevalidate_node_removal",
	}
	for _, feat := range internalFeats {
		if v7Cluster[feat] {
			t.Fatalf("expected v7.10.2 cluster features to omit ES8-only %q", feat)
		}
		if !v8Cluster[feat] {
			t.Fatalf("expected v8.15.5 cluster features to include %q", feat)
		}
	}

	// catch: unauthorized handles 401 and rejects non-401.
	ctx := newRunnerContext(http.DefaultClient, "http://127.0.0.1:0")
	ctx.targetVersion = "8.15.5"
	ctx.supportedClusterFeatures = DefaultSupportedClusterFeaturesForVersion("8.15.5")
	if err := ctx.verifyCatch("unauthorized", "monitoring.bulk", http.StatusUnauthorized, `{"error":{"type":"security_exception"}}`, nil); err != nil {
		t.Fatalf("verifyCatch(unauthorized, 401) failed: %v", err)
	}
	if err := ctx.verifyCatch("unauthorized", "monitoring.bulk", http.StatusForbidden, `{"error":{"type":"security_exception"}}`, nil); err == nil {
		t.Fatal("verifyCatch(unauthorized, 403) unexpectedly succeeded")
	}

	// _internal.* routing and unknown parameter rejection (catch: param for diy_run).
	internalCases := []struct {
		action     string
		params     map[string]any
		wantMethod string
		wantPath   string
		wantQuery  string
	}{
		{"_internal.get_desired_balance", map[string]any{}, http.MethodGet, "/_internal/desired_balance", ""},
		{"_internal.delete_desired_balance", map[string]any{}, http.MethodDelete, "/_internal/desired_balance", ""},
		{"_internal.get_desired_nodes", map[string]any{}, http.MethodGet, "/_internal/desired_nodes/_latest", ""},
		{"_internal.delete_desired_nodes", map[string]any{}, http.MethodDelete, "/_internal/desired_nodes", ""},
		{"_internal.update_desired_nodes", map[string]any{"history_id": "h/1", "version": "3", "dry_run": "true"}, http.MethodPut, "/_internal/desired_nodes/h%2F1/3", "true"},
		{"_internal.update_desired_nodes", map[string]any{}, http.MethodPut, "/_internal/desired_nodes", ""},
		{"_internal.prevalidate_node_removal", map[string]any{"ids": "n1"}, http.MethodPost, "/_internal/prevalidate_node_removal", "n1"},
	}
	for _, tc := range internalCases {
		req, err := ctx.buildActionRequest(tc.action, tc.params)
		if err != nil {
			t.Fatalf("buildActionRequest(%s) failed: %v", tc.action, err)
		}
		if req.method != tc.wantMethod || req.path != tc.wantPath {
			t.Fatalf("buildActionRequest(%s) = %s %s, want %s %s", tc.action, req.method, req.path, tc.wantMethod, tc.wantPath)
		}
		if tc.action == "_internal.update_desired_nodes" && tc.wantQuery != "" && req.query.Get("dry_run") != tc.wantQuery {
			t.Fatalf("update_desired_nodes dry_run=%q, want %q", req.query.Get("dry_run"), tc.wantQuery)
		}
		if tc.action == "_internal.prevalidate_node_removal" && req.query.Get("ids") != tc.wantQuery {
			t.Fatalf("prevalidate_node_removal ids=%q, want %q", req.query.Get("ids"), tc.wantQuery)
		}
	}

	if _, err := ctx.buildActionRequest("_internal.update_desired_nodes", map[string]any{"history_id": "h", "version": "1", "diy_run": "true"}); err == nil || !strings.Contains(err.Error(), "unknown parameter [diy_run]") {
		t.Fatalf("expected unknown parameter error for diy_run, got: %v", err)
	}
	doStep := NewOrderedMap()
	doStep.Set("catch", "param")
	badParams := NewOrderedMap()
	badParams.Set("history_id", "h")
	badParams.Set("version", 1)
	badParams.Set("diy_run", true)
	doStep.Set("_internal.update_desired_nodes", badParams)
	if err := ctx.execDo(doStep, false); err != nil {
		t.Fatalf("execDo catch: param on unknown parameter failed: %v", err)
	}
}

func TestRound67_F17ScoreDirectoriesCollisionDisambiguation(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	coreTestDir := filepath.Join(tmp, "rest-api-spec", "src", "yamlRestTest", "resources", "rest-api-spec", "test")
	modAnalysisDir := filepath.Join(tmp, "modules", "analysis-common", "src", "yamlRestTest", "resources", "rest-api-spec", "test")
	modIngestDir := filepath.Join(tmp, "modules", "ingest-common", "src", "yamlRestTest", "resources", "rest-api-spec", "test")
	extraDirA := filepath.Join(tmp, "custom_a")
	extraDirB := filepath.Join(tmp, "custom_b")

	simpleSpec := "---\n\"Section\":\n  - do:\n      info: {}\n  - match: { version.number: \"8.15.5\" }\n"
	writeSpec := func(dir, rel string) {
		t.Helper()
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(simpleSpec), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeSpec(coreTestDir, filepath.Join("indices.analyze", "10_analyze.yml"))
	writeSpec(coreTestDir, filepath.Join("ingest", "10_basic.yml"))
	writeSpec(coreTestDir, filepath.Join("info", "10_info.yml"))
	writeSpec(modAnalysisDir, filepath.Join("indices.analyze", "10_analyze.yml"))
	writeSpec(modIngestDir, filepath.Join("ingest", "10_basic.yml"))
	writeSpec(extraDirA, filepath.Join("ping", "10_ping.yml"))
	writeSpec(extraDirB, filepath.Join("ping", "10_ping.yml"))

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(DefaultFixtureAuthUser+":"+DefaultFixtureAuthPass))
	var seenHandlerAuths []string
	var matchedDisplayPaths []string

	sc, err := ScoreDirectories(SuiteOptions{
		CorpusName:                 "f17-disambig",
		TargetVersion:              "8.15.5",
		DefaultAuthUser:            DefaultFixtureAuthUser,
		DefaultAuthPass:            DefaultFixtureAuthPass,
		ReuseSetupForReadOnlyFiles: true,
		FileFilter: func(displayPath string) bool {
			matchedDisplayPaths = append(matchedDisplayPaths, displayPath)
			return true
		},
		NewSectionHandler: func() (http.Handler, func()) {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenHandlerAuths = append(seenHandlerAuths, r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"version":{"number":"8.15.5"}}`))
			}), func() {}
		},
	}, coreTestDir, modAnalysisDir, modIngestDir, extraDirA, extraDirB)
	if err != nil {
		t.Fatalf("ScoreDirectories failed: %v", err)
	}
	if sc.TotalFiles != 7 || sc.SectionsPassed != 7 || sc.SectionsFailed != 0 {
		t.Fatalf("unexpected F17 scorecard: total=%d passed=%d failed=%d samples=%+v", sc.TotalFiles, sc.SectionsPassed, sc.SectionsFailed, sc.FailureSamples)
	}

	seenMap := make(map[string]int, len(matchedDisplayPaths))
	for _, dp := range matchedDisplayPaths {
		seenMap[dp]++
	}
	for _, want := range []string{
		"indices.analyze/10_analyze.yml",
		"modules/analysis-common/indices.analyze/10_analyze.yml",
		"ingest/10_basic.yml",
		"modules/ingest-common/ingest/10_basic.yml",
		"info/10_info.yml",
		"custom_a/ping/10_ping.yml",
		"custom_b/ping/10_ping.yml",
	} {
		if seenMap[want] != 1 {
			t.Fatalf("expected unique displayPath %q count=1, got %d in %v", want, seenMap[want], matchedDisplayPaths)
		}
	}
	for i, auth := range seenHandlerAuths {
		if auth != wantAuth {
			t.Fatalf("handler call %d saw Authorization=%q, want %q", i, auth, wantAuth)
		}
	}
}

func TestRound67_W9_BuildActionRequestEdgeActionsAndEscaping(t *testing.T) {
	t.Parallel()

	ctx := newRunnerContext(http.DefaultClient, "http://127.0.0.1:0")

	// URL escaping & raw path sanitization helpers
	if got := sanitizeRawReqPath(""); got != "" {
		t.Fatalf("sanitizeRawReqPath empty = %q", got)
	}
	if got := sanitizeRawReqPath("/idx/%2Fok/%zz/a b#?\"<>\\^`{}|[]"); !strings.Contains(got, "%2Fok") || !strings.Contains(got, "%25zz") || !strings.Contains(got, "%20") || !strings.Contains(got, "%23%3F") {
		t.Fatalf("unexpected sanitizeRawReqPath output: %q", got)
	}
	if got := escapeIDSeg(""); got != "" {
		t.Fatalf("escapeIDSeg empty = %q", got)
	}
	if got := escapeIDSeg("*a#b?c/d"); got != "*a%23b%3Fc%2Fd" {
		t.Fatalf("escapeIDSeg = %q", got)
	}
	if got := escapeCommaIDSegs(""); got != "" {
		t.Fatalf("escapeCommaIDSegs empty = %q", got)
	}
	if got := escapeCommaIDSegs("a/1,b#2"); got != "a%2F1,b%232" {
		t.Fatalf("escapeCommaIDSegs = %q", got)
	}

	type reqCase struct {
		action   string
		params   map[string]any
		method   string
		path     string
		isNDJSON bool
	}
	cases := []reqCase{
		{"connector.put", map[string]any{"connector_id": "c/1", "body": map[string]any{"name": "n"}}, http.MethodPut, "/_connector/c%2F1", false},
		{"connector.post", map[string]any{"body": map[string]any{"name": "n"}}, http.MethodPost, "/_connector", false},
		{"connector.get", map[string]any{"id": "c1"}, http.MethodGet, "/_connector/c1", false},
		{"connector.list", map[string]any{}, http.MethodGet, "/_connector", false},
		{"connector.delete", map[string]any{"connector_id": "c1"}, http.MethodDelete, "/_connector/c1", false},
		{"connector.update_name", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_name", false},
		{"connector.update_native", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_native", false},
		{"connector.update_service_type", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_service_type", false},
		{"connector.update_status", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_status", false},
		{"connector.update_error", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_error", false},
		{"connector.update_filtering", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_filtering", false},
		{"connector.update_configuration", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_configuration", false},
		{"connector.update_pipeline", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_pipeline", false},
		{"connector.last_sync", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_last_sync", false},
		{"connector.update_index_name", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_index_name", false},
		{"connector.update_scheduling", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_scheduling", false},
		{"connector.update_custom_scheduling", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_custom_scheduling", false},
		{"connector.update_api_key_id", map[string]any{"connector_id": "c1"}, http.MethodPut, "/_connector/c1/_api_key_id", false},
		{"connector.update_active_filtering", map[string]any{"connector_id": "c1", "filtering_validation_state": "draft"}, http.MethodPost, "/_connector/c1/_filtering/draft", false},
		{"connector.sync_job_claim", map[string]any{}, http.MethodPost, "/_connector/_sync_job/_claim", false},
		{"connector.sync_job_post", map[string]any{}, http.MethodPost, "/_connector/_sync_job", false},
		{"connector.sync_job_get", map[string]any{"connector_sync_job_id": "j/1"}, http.MethodGet, "/_connector/_sync_job/j%2F1", false},
		{"connector.sync_job_list", map[string]any{}, http.MethodGet, "/_connector/_sync_job", false},
		{"connector.sync_job_delete", map[string]any{"id": "j1"}, http.MethodDelete, "/_connector/_sync_job/j1", false},
		{"connector.sync_job_cancel", map[string]any{"connector_sync_job_id": "j1"}, http.MethodPost, "/_connector/_sync_job/j1/_cancel", false},
		{"connector.sync_job_check_in", map[string]any{"connector_sync_job_id": "j1"}, http.MethodPost, "/_connector/_sync_job/j1/_check_in", false},
		{"connector.sync_job_error", map[string]any{"connector_sync_job_id": "j1"}, http.MethodPut, "/_connector/_sync_job/j1/_error", false},
		{"connector.sync_job_update_stats", map[string]any{"connector_sync_job_id": "j1"}, http.MethodPut, "/_connector/_sync_job/j1/_stats", false},
		{"monitoring.bulk", map[string]any{"system_id": "logstash", "body": []any{map[string]any{"index": map[string]any{}}, map[string]any{"a": 1}}}, http.MethodPost, "/_monitoring/bulk", true},
		{"monitoring.bulk", map[string]any{"type": "beats/v8", "body": []any{map[string]any{"index": map[string]any{}}}}, http.MethodPost, "/_monitoring/beats%2Fv8/bulk", true},
		{"ssl.certificates", map[string]any{}, http.MethodGet, "/_ssl/certificates", false},
		{"fleet.msearch", map[string]any{"index": "logs-*", "body": []any{map[string]any{}, map[string]any{"query": map[string]any{}}}}, http.MethodPost, "/logs-*/_fleet/msearch", true},
		{"fleet.msearch", map[string]any{}, http.MethodPost, "/_fleet/msearch", true},
		{"fleet.search", map[string]any{"index": "logs-*"}, http.MethodPost, "/logs-*/_fleet/search", false},
		{"fleet.search", map[string]any{}, http.MethodPost, "/_fleet/search", false},
		{"fleet.global_checkpoints", map[string]any{"index": "logs-1"}, http.MethodGet, "/logs-1/_fleet/global_checkpoints", false},
		{"fleet.post_secret", map[string]any{"body": `{"value":"s"}`}, http.MethodPost, "/_fleet/secrets", false},
		{"fleet.get_secret", map[string]any{"id": "sec/1"}, http.MethodGet, "/_fleet/secrets/sec%2F1", false},
		{"fleet.delete_secret", map[string]any{"id": "sec1"}, http.MethodDelete, "/_fleet/secrets/sec1", false},
		{"security.activate_profile", map[string]any{}, http.MethodPost, "/_security/profile/_activate", false},
		{"security.get_profile", map[string]any{"uid": "u1,u2"}, http.MethodGet, "/_security/profile/u1,u2", false},
		{"security.update_profile_data", map[string]any{"uid": "u1"}, http.MethodPost, "/_security/profile/u1/_data", false},
		{"security.enable_profile", map[string]any{"uid": "u1"}, http.MethodPut, "/_security/profile/u1/_enable", false},
		{"security.disable_profile", map[string]any{"uid": "u1"}, http.MethodPut, "/_security/profile/u1/_disable", false},
		{"security.suggest_profiles", map[string]any{}, http.MethodPost, "/_security/_suggest_profiles", false},
		{"security.has_privileges_profile", map[string]any{"uid": "u1"}, http.MethodGet, "/_security/profile/u1/_has_privileges", false},
		{"security.has_privileges_profile", map[string]any{"uid": "u1", "body": map[string]any{"labels": map[string]any{}}}, http.MethodPost, "/_security/profile/u1/_has_privileges", false},
		{"security.get_settings", map[string]any{}, http.MethodGet, "/_security/settings", false},
		{"security.update_settings", map[string]any{}, http.MethodPut, "/_security/settings", false},
		{"security.create_cross_cluster_api_key", map[string]any{}, http.MethodPost, "/_security/cross_cluster/api_key", false},
		{"security.update_cross_cluster_api_key", map[string]any{"id": "ak/1"}, http.MethodPut, "/_security/cross_cluster/api_key/ak%2F1", false},
		{"security.get_builtin_privileges", map[string]any{}, http.MethodGet, "/_security/privilege/_builtin", false},
		{"security.put_privileges", map[string]any{}, http.MethodPut, "/_security/privilege", false},
		{"security.get_privileges", map[string]any{"application": "app1", "name": "p1,p2"}, http.MethodGet, "/_security/privilege/app1/p1,p2", false},
		{"security.get_privileges", map[string]any{"application": "app1"}, http.MethodGet, "/_security/privilege/app1", false},
		{"security.get_privileges", map[string]any{}, http.MethodGet, "/_security/privilege", false},
		{"security.delete_privileges", map[string]any{"application": "app1", "name": "p1"}, http.MethodDelete, "/_security/privilege/app1/p1", false},
		{"security.create_service_token", map[string]any{"namespace": "ns", "service": "svc", "token_name": "tok"}, http.MethodPost, "/_security/service/ns/svc/credential/token/tok", false},
		{"security.create_service_token", map[string]any{"namespace": "ns", "service": "svc"}, http.MethodPost, "/_security/service/ns/svc/credential/token", false},
		{"security.delete_service_token", map[string]any{"namespace": "ns", "service": "svc", "name": "tok"}, http.MethodDelete, "/_security/service/ns/svc/credential/token/tok", false},
		{"security.list_service_tokens", map[string]any{"namespace": "ns", "service": "svc"}, http.MethodGet, "/_security/service/ns/svc/credential/token", false},
		{"security.get_service_accounts", map[string]any{"namespace": "ns", "service": "svc"}, http.MethodGet, "/_security/service/ns/svc", false},
		{"security.get_service_accounts", map[string]any{"namespace": "ns"}, http.MethodGet, "/_security/service/ns", false},
		{"security.get_service_accounts", map[string]any{}, http.MethodGet, "/_security/service", false},
		{"security.get_service_credentials", map[string]any{"namespace": "ns", "service": "svc"}, http.MethodGet, "/_security/service/ns/svc/credential", false},
		{"security.get_token", map[string]any{}, http.MethodPost, "/_security/oauth2/token", false},
		{"security.invalidate_token", map[string]any{}, http.MethodDelete, "/_security/oauth2/token", false},
	}

	for _, tc := range cases {
		req, err := ctx.buildActionRequest(tc.action, tc.params)
		if err != nil {
			t.Fatalf("buildActionRequest(%s, %v) unexpected error: %v", tc.action, tc.params, err)
		}
		if req.method != tc.method || req.path != tc.path || req.isNDJSON != tc.isNDJSON {
			t.Fatalf("buildActionRequest(%s) = (%s %s ndjson=%v), want (%s %s ndjson=%v)",
				tc.action, req.method, req.path, req.isNDJSON, tc.method, tc.path, tc.isNDJSON)
		}
	}

	missingParamActions := []struct {
		action string
		params map[string]any
	}{
		{"connector.put", nil},
		{"connector.get", nil},
		{"connector.delete", nil},
		{"connector.update_name", nil},
		{"connector.update_active_filtering", map[string]any{"connector_id": "c1"}},
		{"connector.sync_job_get", nil},
		{"connector.sync_job_delete", nil},
		{"connector.sync_job_cancel", nil},
		{"connector.sync_job_check_in", nil},
		{"connector.sync_job_error", nil},
		{"connector.sync_job_update_stats", nil},
		{"fleet.global_checkpoints", nil},
		{"fleet.get_secret", nil},
		{"fleet.delete_secret", nil},
		{"security.get_profile", nil},
		{"security.update_profile_data", nil},
		{"security.enable_profile", nil},
		{"security.disable_profile", nil},
		{"security.has_privileges_profile", nil},
		{"security.update_cross_cluster_api_key", nil},
		{"security.delete_privileges", map[string]any{"application": "app"}},
		{"security.create_service_token", map[string]any{"namespace": "ns"}},
		{"security.delete_service_token", map[string]any{"namespace": "ns", "service": "svc"}},
		{"security.list_service_tokens", map[string]any{"namespace": "ns"}},
		{"security.get_service_credentials", map[string]any{"namespace": "ns"}},
		{"completely.unknown_action", nil},
	}
	for _, tc := range missingParamActions {
		if _, err := ctx.buildActionRequest(tc.action, tc.params); err == nil {
			t.Fatalf("buildActionRequest(%s, %v) expected error", tc.action, tc.params)
		}
	}
	_ = url.Values{}
}

func TestRound67_W9_YAMLParserNodeAndFlowValueBranches(t *testing.T) {
	t.Parallel()

	yamlInput := `---
&docAnchor
base: &baseAnchor
  k1: v1
merged: &flowMapAnchor { <<: *baseAnchor, k2: "v2", empty: , }
seq_flow: [ a: 1, &pairAnchor b: "two", &seqAnchor [ 10, 20, ], emptyKey: ]
ref_pair: *pairAnchor
ref_seq: *seqAnchor
folded_plain: hello
  world continuation
  line three
seq_branches:
  -
    sub: item
  - &dashAnchor
    nested: true
  - |-
    block_in_seq
  - { inline: *flowMapAnchor }
empty_flow_map: {}
empty_flow_seq: []
`
	docs, err := ParseYAMLDocuments(yamlInput)
	if err != nil {
		t.Fatalf("ParseYAMLDocuments failed: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 doc, got %d", len(docs))
	}
	root := ToNative(docs[0]).(map[string]any)
	merged := root["merged"].(map[string]any)
	if merged["k1"] != "v1" || merged["k2"] != "v2" {
		t.Fatalf("unexpected merged flow map: %#v", merged)
	}
	if root["folded_plain"] != "hello world continuation line three" {
		t.Fatalf("unexpected folded_plain: %q", root["folded_plain"])
	}
	if em, ok := root["empty_flow_map"].(map[string]any); !ok || len(em) != 0 {
		t.Fatalf("expected empty_flow_map, got %#v", root["empty_flow_map"])
	}
	if es, ok := root["empty_flow_seq"].([]any); !ok || len(es) != 0 {
		t.Fatalf("expected empty_flow_seq, got %#v", root["empty_flow_seq"])
	}
	if refSeq, ok := root["ref_seq"].([]any); !ok || len(refSeq) != 2 {
		t.Fatalf("unexpected ref_seq alias: %#v", root["ref_seq"])
	}
	if refPair, ok := root["ref_pair"].(map[string]any); !ok || refPair["b"] != "two" {
		t.Fatalf("unexpected ref_pair alias: %#v", root["ref_pair"])
	}

	// Direct parseNode & parseFlowValue edge and error paths.
	p := &yamlParser{rawLines: []string{"  nested: 1"}}
	if nilNode, nErr := p.parseNode(4); nErr != nil || nilNode != nil {
		t.Fatalf("expected nil on indent < minIndent, got (%v, %v)", nilNode, nErr)
	}
	pEOF := &yamlParser{rawLines: []string{"   # only comment"}}
	if nilNode, nErr := pEOF.parseNode(0); nErr != nil || nilNode != nil {
		t.Fatalf("expected nil on EOF after comments, got (%v, %v)", nilNode, nErr)
	}

	for _, badFlow := range []string{
		"{unclosed: 1",
		"[1, 2",
		"{not_a_kv_entry}",
		"&dangling",
		"[&dangling]",
	} {
		pBad := &yamlParser{}
		if _, fErr := pBad.parseFlowValue(badFlow); fErr == nil {
			t.Fatalf("parseFlowValue(%q) expected error", badFlow)
		}
	}

	for _, badYAML := range []string{
		"a: *missing_alias\n",
		"a: *bad alias\n",
		"a: { x: [1, 2\n",
	} {
		if _, pErr := ParseYAMLDocuments(badYAML); pErr == nil {
			t.Fatalf("ParseYAMLDocuments(%q) expected error", badYAML)
		}
	}
}
