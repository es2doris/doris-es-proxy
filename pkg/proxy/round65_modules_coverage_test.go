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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func newRound65Server(targetVer string) *Server {
	mb := NewMemoryBackend(false)
	srv := NewServer("default", mb, transpiler.TranspilerOptions{})
	if targetVer != "" {
		srv.SetTargetESVersion(targetVer)
	}
	return srv
}

func doRound65Req(t *testing.T, h http.Handler, method, path, body string, hdrs map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mustDecodeJSONMapR65(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed JSON decode (status=%d body=%s): %v", rec.Code, rec.Body.String(), err)
	}
	return out
}

func TestRound65_DLS_TermsEnumFailClosedAndFeatures(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// Create `te_idx` with keyword, constant_keyword, flattened, version, wildcard, integer.
	rec := doRound65Req(t, h, http.MethodPut, "/te_idx", `{
		"mappings": {
			"properties": {
				"tag":     {"type": "keyword"},
				"ck":      {"type": "constant_keyword", "value": "fixed"},
				"flat":    {"type": "flattened"},
				"ver":     {"type": "version"},
				"wc":      {"type": "wildcard"},
				"num":     {"type": "integer"}
			}
		}
	}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("create te_idx failed: %d %s", rec.Code, rec.Body.String())
	}

	docs := []string{
		`{"tag":"alpha","ck":"fixed","flat":{"k":"v1"},"ver":"1.2.0","wc":"hello-1","num":1}`,
		`{"tag":"Beta","ck":"fixed","flat":{"k":"v2"},"ver":"1.10.0","wc":"hello-2","num":2}`,
		`{"tag":"gamma","ck":"fixed","flat":{"k":"v3"},"ver":"2.0.0-alpha.1","wc":"world","num":3}`,
	}
	for i, d := range docs {
		r := doRound65Req(t, h, http.MethodPut, fmt.Sprintf("/te_idx/_doc/%d?refresh=true", i+1), d, nil)
		if r.Code != http.StatusCreated && r.Code != http.StatusOK {
			t.Fatalf("index doc %d failed: %d %s", i+1, r.Code, r.Body.String())
		}
	}

	aliasRec := doRound65Req(t, h, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"te_idx","alias":"te_alias"}}]}`, nil)
	if aliasRec.Code != http.StatusOK {
		t.Fatalf("create alias failed: %d %s", aliasRec.Code, aliasRec.Body.String())
	}

	// Size bounds & field validation (ES parity: size <= 0 or size > 65536 -> 400).
	for _, badBody := range []string{
		`{"field":"tag","size":0}`,
		`{"field":"tag","size":-3}`,
		fmt.Sprintf(`{"field":"tag","size":%d}`, maxTermsEnumSize+1),
		`{"field":"num"}`,
		`{"size":5}`,
		`{not-json`,
	} {
		r := doRound65Req(t, h, http.MethodPost, "/te_idx/_terms_enum", badBody, nil)
		if r.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for body %s, got %d (%s)", badBody, r.Code, r.Body.String())
		}
	}

	// Flattened subfield support + version semver sorting + case-insensitive + search_after + wildcard + no-index target.
	flatRes := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/te_idx/_terms_enum", `{"field":"flat.k","size":10}`, nil))
	if terms, _ := flatRes["terms"].([]any); len(terms) != 3 {
		t.Fatalf("expected 3 flattened subfield terms, got %+v", flatRes)
	}
	verRes := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/te_idx/_terms_enum", `{"field":"ver","size":10}`, nil))
	if terms, _ := verRes["terms"].([]any); len(terms) != 3 || terms[0] != "1.2.0" || terms[1] != "1.10.0" {
		t.Fatalf("expected semver sorting (1.2.0 before 1.10.0), got %+v", verRes)
	}
	saRes := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/te_idx/_terms_enum", `{"field":"tag","string":"A","case_insensitive":true,"search_after":"alpha","size":5}`, nil))
	if terms, _ := saRes["terms"].([]any); len(terms) != 0 {
		t.Fatalf("expected empty terms for prefix A after alpha, got %+v", saRes)
	}
	wcRes := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/te_idx/_terms_enum", `{"field":"wc","size":10}`, nil))
	if terms, _ := wcRes["terms"].([]any); len(terms) != 3 {
		t.Fatalf("expected 3 wildcard field terms, got %+v", wcRes)
	}
	noIdxRes := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/_all/_terms_enum", `{"field":"tag","size":5}`, nil))
	if terms, _ := noIdxRes["terms"].([]any); len(terms) != 3 {
		t.Fatalf("expected 3 terms across all indices, got %+v", noIdxRes)
	}

	// Configure rich security fixtures for P0-3 / P0-5a verification.
	srv.mu.Lock()
	srv.securityRoles["dls_all_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names":      []any{"te_idx"},
			"privileges": []any{"read"},
			"query": map[string]any{
				"bool": map[string]any{
					"must":   []any{map[string]any{"match_all": map[string]any{}}},
					"filter": []any{map[string]any{"terms": map[string]any{"ck": []any{"fixed"}}}},
				},
			},
		}},
	}
	srv.securityRoles["dls_should_matchall"] = map[string]any{
		"indices": []any{map[string]any{
			"names":      []any{"te_idx"},
			"privileges": []any{"read"},
			"query": map[string]any{
				"bool": map[string]any{
					"should":               []any{map[string]any{"match_all": map[string]any{}}, map[string]any{"term": map[string]any{"tag": "alpha"}}},
					"minimum_should_match": "100%",
				},
			},
		}},
	}
	srv.securityRoles["dls_must_not_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names":      []any{"te_idx"},
			"privileges": []any{"read"},
			"query": map[string]any{
				"bool": map[string]any{
					"must":     []any{map[string]any{"match_all": map[string]any{}}},
					"must_not": []any{map[string]any{"term": map[string]any{"tag": "alpha"}}},
				},
			},
		}},
	}
	srv.securityRoles["dls_nonslice_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names":      []any{"te_idx"},
			"privileges": []any{"read"},
			"query": map[string]any{
				"bool": map[string]any{
					"must": "not_a_clause",
				},
			},
		}},
	}
	srv.securityRoles["cluster_only_role"] = map[string]any{
		"cluster": []any{"all"},
	}
	srv.securityRoles["write_only_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names":      []any{"te_idx"},
			"privileges": []any{"write"},
		}},
	}
	srv.securityRoles["fls_empty_grant"] = map[string]any{
		"indices": []any{map[string]any{
			"names":          []any{"te_idx"},
			"privileges":     []any{"read"},
			"field_security": map[string]any{"grant": []any{}},
		}},
	}
	srv.securityRoles["alias_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names":      []any{"te_alias"},
			"privileges": []any{"read"},
		}},
	}
	srv.securityUsers["dls_all_user"] = map[string]any{"password": "pw", "roles": []any{"dls_all_role"}, "enabled": true}
	srv.securityUsers["dls_should_denied"] = map[string]any{"password": "pw", "roles": []any{"dls_should_matchall"}, "enabled": true}
	srv.securityUsers["dls_must_not_user"] = map[string]any{"password": "pw", "roles": []any{"dls_must_not_role"}, "enabled": true}
	srv.securityUsers["dls_nonslice_user"] = map[string]any{"password": "pw", "roles": []any{"dls_nonslice_role"}, "enabled": true}
	srv.securityUsers["cluster_only_user"] = map[string]any{"password": "pw", "roles": []any{"cluster_only_role"}, "enabled": true}
	srv.securityUsers["write_only_user"] = map[string]any{"password": "pw", "roles": []any{"write_only_role"}, "enabled": true}
	srv.securityUsers["fls_empty_grant_user"] = map[string]any{"password": "pw", "roles": []any{"fls_empty_grant"}, "enabled": true}
	srv.securityUsers["dls_alias_user"] = map[string]any{"password": "pw", "roles": []any{"alias_role"}, "enabled": true}
	srv.securityUsers["disabled_user"] = map[string]any{"password": "pw", "roles": []any{"superuser"}, "enabled": false}
	srv.mu.Unlock()

	// Unauthenticated must fail closed when inbound proxy auth is enabled (even calling FilterTermsEnum directly).
	srv.authMu.Lock()
	srv.basicAuthUser = "sec_enabled"
	srv.authMu.Unlock()
	if srv.FilterTermsEnumByDLSWithRawTargetsR65(httptest.NewRequest(http.MethodPost, "/te_idx/_terms_enum", nil), "te_idx", []string{"te_idx"}, "tag") {
		t.Fatalf("expected unauthenticated FilterTermsEnumByDLSWithRawTargetsR65 to fail closed when basicAuthUser is configured")
	}
	srv.authMu.Lock()
	srv.basicAuthUser = ""
	srv.authMu.Unlock()

	// test_admin fixture is denied by default when AllowTestFixtureAuth is false, and passes once enabled.
	if recDeny := doRound65Req(t, h, http.MethodPost, "/te_idx/_terms_enum", `{"field":"tag"}`, map[string]string{
		"Authorization": basicHdrR65("test_admin", "x-pack-test-password"),
	}); recDeny.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for test_admin when AllowTestFixtureAuth=false, got %d %s", recDeny.Code, recDeny.Body.String())
	}
	srv.SetAllowTestFixtureAuth(true)
	t.Cleanup(func() { srv.SetAllowTestFixtureAuth(false) })
	taRes := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/te_idx/_terms_enum", `{"field":"tag"}`, map[string]string{
		"Authorization": basicHdrR65("test_admin", "x-pack-test-password"),
	}))
	if terms, _ := taRes["terms"].([]any); len(terms) != 3 {
		t.Fatalf("expected 3 terms for test_admin fixture when enabled, got %+v", taRes)
	}

	// Allowed user with bool(must match_all + filter terms ck=fixed).
	allRes := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/te_idx/_terms_enum", `{"field":"tag"}`, map[string]string{
		"Authorization": basicHdrR65("dls_all_user", "pw"),
	}))
	if terms, _ := allRes["terms"].([]any); len(terms) != 3 {
		t.Fatalf("expected 3 terms for dls_all_user, got %+v", allRes)
	}

	// Denied personas must see 0 terms.
	for _, deniedUser := range []string{
		"unknown_user", "dls_should_denied", "dls_must_not_user", "dls_nonslice_user",
		"cluster_only_user", "write_only_user", "fls_empty_grant_user", "disabled_user",
	} {
		dr := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/te_idx/_terms_enum", `{"field":"tag"}`, map[string]string{
			"Authorization": basicHdrR65(deniedUser, "pw"),
		}))
		if terms, _ := dr["terms"].([]any); len(terms) != 0 {
			t.Fatalf("user %q leaked terms: %+v", deniedUser, dr)
		}
	}

	// Alias security: dls_alias_user allowed on /te_alias/_terms_enum, denied on direct /te_idx/_terms_enum.
	aliasAllowed := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/te_alias/_terms_enum", `{"field":"tag"}`, map[string]string{
		"Authorization": basicHdrR65("dls_alias_user", "pw"),
	}))
	if terms, _ := aliasAllowed["terms"].([]any); len(terms) != 3 {
		t.Fatalf("expected 3 terms via alias te_alias, got %+v", aliasAllowed)
	}
	directDenied := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/te_idx/_terms_enum", `{"field":"tag"}`, map[string]string{
		"Authorization": basicHdrR65("dls_alias_user", "pw"),
	}))
	if terms, _ := directDenied["terms"].([]any); len(terms) != 0 {
		t.Fatalf("expected 0 terms when accessing concrete index te_idx directly, got %+v", directDenied)
	}

	// Direct FilterTermsEnumByDLSR64 & FilterTermsEnumByDLSWithRawTargetsR65 & parseTermsEnumDLSMinShouldMatchR65 edge cases.
	if srv.FilterTermsEnumByDLSR64(nil, []string{"te_idx"}, "tag") {
		t.Fatalf("nil request must fail closed")
	}
	if _, ok := parseTermsEnumDLSMinShouldMatchR65("invalid", 2); ok {
		t.Fatalf("expected invalid minimum_should_match string to fail")
	}
	if got, ok := parseTermsEnumDLSMinShouldMatchR65(float64(2), 3); !ok || got != 2 {
		t.Fatalf("expected float64 2 -> (2,true), got (%d,%v)", got, ok)
	}
	if got, ok := parseTermsEnumDLSMinShouldMatchR65("50%", 2); ok || got != 0 {
		t.Fatalf("expected non-100%% string to fail closed, got (%d,%v)", got, ok)
	}
	if got, ok := parseTermsEnumDLSMinShouldMatchR65("100%", 2); !ok || got != 2 {
		t.Fatalf("expected 100%% -> (2,true), got (%d,%v)", got, ok)
	}
}

func TestRound65_Wire_MiddlewareYAMLHeadAndAcceptQ0(t *testing.T) {
	srv := newRound65Server("8.15.5")
	srv.authMu.Lock()
	srv.basicAuthUser = "secuser"
	srv.basicAuthPass = "secpass"
	srv.apiKey = "secretapikey"
	srv.authMu.Unlock()
	h := srv.Handler()

	// 1. Accept ;q=0 rejection and compatible-with selection in setESCompatHeadersWireR64 & isCatStructuredOutputRound63.
	hdrRec := httptest.NewRecorder()
	reqQ0 := httptest.NewRequest(http.MethodGet, "/", nil)
	reqQ0.Header.Set("Accept", "application/vnd.elasticsearch+json; compatible-with=8; q=0, application/vnd.opensearch+json; compatible-with=2; q=0.8")
	setESCompatHeadersWireR64(hdrRec, reqQ0)
	if ct := hdrRec.Header().Get("Content-Type"); ct != "application/vnd.opensearch+json; compatible-with=2" {
		t.Fatalf("expected OpenSearch compat header with ES q=0 ignored, got %q", ct)
	}

	reqCatQ0 := httptest.NewRequest(http.MethodGet, "/_cat/indices", nil)
	reqCatQ0.Header.Set("Accept", "application/json; q=0, text/plain; q=1")
	if isCatStructuredOutputRound63(reqCatQ0) {
		t.Fatalf("expected application/json;q=0 + text/plain;q=1 NOT to force structured output")
	}
	reqCatStruct := httptest.NewRequest(http.MethodGet, "/_cat/indices", nil)
	reqCatStruct.Header.Set("Accept", "text/plain; q=0.2, application/yaml; q=0.9")
	if !isCatStructuredOutputRound63(reqCatStruct) {
		t.Fatalf("expected application/yaml;q=0.9 > text/plain;q=0.2 to select structured output")
	}

	// 2. Early errors in withWireMiddleware preserve HEAD empty body and YAML format on format=yaml.
	for _, tc := range []struct {
		method string
		target string
		hdrs   map[string]string
		body   string
		want   int
	}{
		{http.MethodHead, "/?format=yaml", nil, "", http.StatusUnauthorized},
		{http.MethodGet, "/?format=yaml", nil, "", http.StatusUnauthorized},
		{http.MethodHead, "/?http_compression=invalid", map[string]string{"Authorization": basicHdrR65("secuser", "secpass")}, "", http.StatusBadRequest},
		{http.MethodGet, "/?format=yaml&http_compression=invalid", map[string]string{"Authorization": basicHdrR65("secuser", "secpass")}, "", http.StatusBadRequest},
		{http.MethodHead, "/?pretty=notabool", map[string]string{"Authorization": basicHdrR65("secuser", "secpass")}, "", http.StatusBadRequest},
		{http.MethodGet, "/?format=yaml&error_trace=notabool", map[string]string{"Authorization": basicHdrR65("secuser", "secpass")}, "", http.StatusBadRequest},
		{http.MethodHead, "/?format=yaml", map[string]string{"Authorization": basicHdrR65("secuser", "secpass"), "Accept": "application/xml"}, "", http.StatusNotAcceptable},
		{http.MethodPost, "/_search?format=yaml", map[string]string{"Authorization": basicHdrR65("secuser", "secpass"), "Content-Type": "text/plain"}, "hello", http.StatusNotAcceptable},
		{http.MethodPost, "/_search?format=yaml", map[string]string{"Authorization": basicHdrR65("secuser", "secpass"), "Content-Type": "application/json", "Content-Encoding": "gzip"}, "not-gzip", http.StatusBadRequest},
	} {
		rec := doRound65Req(t, h, tc.method, tc.target, tc.body, tc.hdrs)
		if rec.Code != tc.want {
			t.Fatalf("%s %s: expected status %d, got %d body=%s", tc.method, tc.target, tc.want, rec.Code, rec.Body.String())
		}
		if tc.method == http.MethodHead && rec.Body.Len() != 0 {
			t.Fatalf("HEAD %s leaked body: %q", tc.target, rec.Body.String())
		}
		if tc.method != http.MethodHead && strings.Contains(tc.target, "format=yaml") && !strings.HasPrefix(rec.Body.String(), "---") {
			t.Fatalf("GET %s expected YAML output starting with ---, got %q", tc.target, rec.Body.String())
		}
	}

	// 3. Unwrap() and Flush() across gzipResponseWriter, vendorMediaTypeGuardWriterR64, and esFormatResponseWriter.
	baseRec := httptest.NewRecorder()
	gz := gzipWriterPool.Get().(*gzip.Writer)
	gzw := &gzipResponseWriter{ResponseWriter: baseRec, gz: gz}
	vw := &vendorMediaTypeGuardWriterR64{ResponseWriter: gzw, negotiatedCT: "application/vnd.elasticsearch+json; compatible-with=8"}
	fw := &esFormatResponseWriter{ResponseWriter: vw, opts: esResponseFormatOptions{pretty: true}}
	if gzw.Unwrap() != baseRec || vw.Unwrap() != gzw || fw.Unwrap() != vw {
		t.Fatalf("Unwrap() chain mismatch")
	}
	if gotOpts, okOpts := extractESResponseFormatOptions(&headResponseWriterR64{ResponseWriter: fw}); !okOpts || !gotOpts.pretty {
		t.Fatalf("extractESResponseFormatOptions failed through head/esFormat chain: (%+v, %v)", gotOpts, okOpts)
	}
	if _, okOpts := extractESResponseFormatOptions(&headResponseWriterR64{ResponseWriter: vw}); okOpts {
		t.Fatalf("expected extractESResponseFormatOptions without esFormatResponseWriter to return false")
	}
	vw.WriteHeader(http.StatusOK)
	_, _ = vw.Write([]byte(`{"ok":true}`))
	vw.Flush()
	gzw.Close()

	// 4. esFormatResponseWriter: multi-doc NDJSON, 204/304 pass-through, non-JSON pass-through, >maxYAMLFormatBufferBytes fallback.
	ndRec := httptest.NewRecorder()
	ndFW := &esFormatResponseWriter{ResponseWriter: ndRec, yamlFormat: true}
	ndFW.ResponseWriter.Header().Set("Content-Type", "application/json")
	ndFW.WriteHeader(http.StatusOK)
	_, _ = ndFW.Write([]byte("{\"k\":1}\n{\"k\":2}\n"))
	ndFW.Flush()
	if strings.Count(ndRec.Body.String(), "---") < 2 {
		t.Fatalf("expected multi-doc YAML separators for NDJSON, got:\n%s", ndRec.Body.String())
	}

	noContentRec := httptest.NewRecorder()
	ncFW := &esFormatResponseWriter{ResponseWriter: noContentRec, yamlFormat: true}
	ncFW.WriteHeader(http.StatusNoContent)
	ncFW.Finalize()
	if noContentRec.Code != http.StatusNoContent || noContentRec.Body.Len() != 0 {
		t.Fatalf("204 passthrough failed: status=%d body=%q", noContentRec.Code, noContentRec.Body.String())
	}

	nonJSONRec := httptest.NewRecorder()
	njFW := &esFormatResponseWriter{ResponseWriter: nonJSONRec, yamlFormat: true}
	njFW.ResponseWriter.Header().Set("Content-Type", "text/plain")
	_, _ = njFW.Write([]byte("plain"))
	njFW.Finalize()
	if nonJSONRec.Body.String() != "plain" {
		t.Fatalf("expected plain pass-through for text/plain, got %q", nonJSONRec.Body.String())
	}

	bigRec := httptest.NewRecorder()
	bigFW := &esFormatResponseWriter{ResponseWriter: bigRec, yamlFormat: true}
	bigFW.ResponseWriter.Header().Set("Content-Type", "application/json")
	bigFW.WriteHeader(http.StatusOK)
	chunk := bytes.Repeat([]byte("a"), 1024*1024)
	for i := 0; i < 65; i++ {
		if _, err := bigFW.Write(chunk); err != nil {
			t.Fatalf("write chunk %d failed: %v", i, err)
		}
	}
	bigFW.Finalize()
	if bigRec.Body.Len() != 65*1024*1024 {
		t.Fatalf("expected 65MB raw passthrough on YAML buffer cap, got %d bytes", bigRec.Body.Len())
	}

	// 5. writeYAMLValueWireR64 depth limit, []map[string]any, special keys, scalars.
	var deep any = "leaf"
	for i := 0; i < maxYAMLMarshalDepth+4; i++ {
		deep = map[string]any{"x": deep}
	}
	var yamlBuf strings.Builder
	writeYAMLValueWireR64(&yamlBuf, map[string]any{
		"nilVal":   nil,
		"boolVal":  true,
		"numVal":   json.Number("42"),
		"key:col":  "str",
		"emptyArr": []map[string]any{},
		"maps":     []map[string]any{{"a": 1}},
		"deep":     deep,
	}, 0, false)
	if !strings.Contains(yamlBuf.String(), `"key:col": "str"`) || !strings.Contains(yamlBuf.String(), `emptyArr: []`) {
		t.Fatalf("unexpected writeYAMLValueWireR64 output:\n%s", yamlBuf.String())
	}
}

func TestRound65_Modules_NodesClusterStatsDownsamplePercolateAndIngest(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// 1. /_nodes, /_nodes/stats, /_cluster/stats, /_cluster/state/_all (F6-L1 / F6-L2a / F10b).
	nodesInfo := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodGet, "/_nodes", "", nil))
	nodesMap, _ := nodesInfo["nodes"].(map[string]any)
	feNode, okNode := nodesMap["doris-fe-1"].(map[string]any)
	if !okNode {
		t.Fatalf("expected node ID doris-fe-1 in /_nodes, got %+v", nodesInfo)
	}
	if mods, _ := feNode["modules"].([]any); len(mods) == 0 {
		t.Fatalf("expected non-empty modules list in /_nodes, got %+v", feNode)
	}

	nodesStats := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodGet, "/_nodes/stats", "", nil))
	nsMap, _ := nodesStats["nodes"].(map[string]any)
	if _, okNS := nsMap["doris-fe-1"]; !okNS {
		t.Fatalf("expected matching node ID doris-fe-1 in /_nodes/stats, got %+v", nodesStats)
	}

	clusterStats := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodGet, "/_cluster/stats", "", nil))
	countMap, _ := clusterStats["nodes"].(map[string]any)["count"].(map[string]any)
	if vo, _ := countMap["voting_only"].(float64); vo != 0 {
		t.Fatalf("expected voting_only=0, got %v", countMap["voting_only"])
	}

	csState := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodGet, "/_cluster/state/_all", "", nil))
	if csState["cluster_name"] == nil {
		t.Fatalf("expected cluster_name in /_cluster/state/_all, got %+v", csState)
	}

	// 2. Ingest script compile error, mustache #join validation, redact missing field, grok ECS v1 QS unquoting.
	badJoin := doRound65Req(t, h, http.MethodPut, "/_ingest/pipeline/p_bad_join", `{
		"processors": [{"set": {"field": "out", "value": "{{#join}}a,b{{/join}}"}}]
	}`, nil)
	if badJoin.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid {{#join}}, got %d %s", badJoin.Code, badJoin.Body.String())
	}
	badJoinErr := mustDecodeJSONMapR65(t, badJoin)
	if errObj, _ := badJoinErr["error"].(map[string]any); errObj["type"] != "script_exception" {
		t.Fatalf("expected script_exception for invalid {{#join}}, got %+v", badJoinErr)
	}

	// Mustache template expansions (#join, #toJson, #url)
	expanded, err := expandIngestTemplate("{{#join delimiter=|}}tags{{/join}} {{#toJson}}obj{{/toJson}} {{#url}}{{q}}{{/url}}", map[string]any{
		"tags": []any{"x", "y"},
		"obj":  map[string]any{"k": 1},
		"q":    "hello world",
	})
	if err != nil {
		t.Fatalf("unexpected expandIngestTemplate error: %v", err)
	}
	if expanded != `x|y {"k":1} hello+world` {
		t.Fatalf("unexpected expandIngestTemplate output: %q", expanded)
	}

	simRec := doRound65Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"script": {"source": "invalid painless syntax (("}}]},
		"docs": [{"_source": {"a": 1}}]
	}`, nil)
	if simRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on bad painless script simulate, got %d %s", simRec.Code, simRec.Body.String())
	}
	simErr := mustDecodeJSONMapR65(t, simRec)
	if errObj, _ := simErr["error"].(map[string]any); errObj["type"] != "script_exception" || errObj["reason"] != "compile error" || errObj["processor_type"] != "script" {
		t.Fatalf("expected script_exception/compile error for bad painless script, got %+v", simErr)
	}

	redactMissing := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"redact": {"field": "msg", "patterns": ["%{IP}"]}}]},
		"docs": [{"_source": {"other": "ok"}}]
	}`, nil))
	if errObj, _ := redactMissing["docs"].([]any)[0].(map[string]any)["error"].(map[string]any); !strings.Contains(fmt.Sprintf("%v", errObj["reason"]), "field [msg] is null or missing") {
		t.Fatalf("expected redact null or missing error, got %+v", errObj)
	}

	grokMissing := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"grok": {"field": "msg", "patterns": ["%{WORD:w}"]}}]},
		"docs": [{"_source": {"other": "ok"}}]
	}`, nil))
	if errObj, _ := grokMissing["docs"].([]any)[0].(map[string]any)["error"].(map[string]any); !strings.Contains(fmt.Sprintf("%v", errObj["reason"]), "not present as part of path") {
		t.Fatalf("expected grok missing path error preserved, got %+v", errObj)
	}

	grokV1 := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {"processors": [{"grok": {"field": "msg", "ecs_compatibility": "v1", "patterns": ["%{IP:client.address} %{QS:req}"]}}]},
		"docs": [{"_source": {"msg": "198.51.100.7 \"GET /a HTTP/1.1\""}}]
	}`, nil))
	srcOut := grokV1["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if srcOut["req"] != "GET /a HTTP/1.1" || srcOut["client"].(map[string]any)["address"] != "198.51.100.7" {
		t.Fatalf("expected ECS v1 QS unquoting & client.address, got %+v", srcOut)
	}

	// 3. Percolator clause order (must -> should -> filter) and storedPercolatorQueryHasNamesRound63.
	rawQ := map[string]any{
		"bool": map[string]any{
			"_name":  "root",
			"filter": []any{map[string]any{"term": map[string]any{"_name": "z_filter", "env": "prod"}}},
			"should": []any{map[string]any{"term": map[string]any{"_name": "a_should", "env": "prod"}}},
			"must":   []any{map[string]any{"term": map[string]any{"_name": "m_must", "env": "prod"}}},
		},
	}
	if !storedPercolatorQueryHasNamesRound63(map[string]any{"query": rawQ}, "query") {
		t.Fatalf("expected storedPercolatorQueryHasNamesRound63 to detect _name")
	}
	sch := &schema.IndexSchema{Fields: map[string]schema.FieldBinding{
		"env": {ESFieldPath: "env", ESType: "keyword"},
	}}
	matchedMap := collectPercolateSlotMatchedQueriesRound63(sch, map[string]any{"query": rawQ}, &esast.PercolateQuery{
		Field:    "query",
		Document: map[string]any{"env": "prod"},
	})
	wantOrder := []string{"root", "m_must", "a_should", "z_filter"}
	if !reflect.DeepEqual(matchedMap[0], wantOrder) {
		t.Fatalf("expected clause order %v, got %v", wantOrder, matchedMap[0])
	}

	// 4. Downsample: buildDownsampleTargetMappingRound63 histogram clears TimeSeriesMetric + _downsample deterministic groupOrder + gauge merge.
	dsMap := buildDownsampleTargetMappingRound63(&esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"lat": {Type: "histogram", TimeSeriesMetric: "gauge"},
			"cpu": {Type: "double", TimeSeriesMetric: "gauge"},
		},
	}, "1h")
	if dsMap.Properties["lat"].TimeSeriesMetric != "" || dsMap.Properties["cpu"].Type != "aggregate_metric_double" {
		t.Fatalf("unexpected downsample target mapping: %+v", dsMap.Properties)
	}

	tsIdx := doRound65Req(t, h, http.MethodPut, "/ts_src", `{
		"settings": {"index.mode": "time_series", "index.routing_path": ["host"]},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"host":       {"type": "keyword", "time_series_dimension": true},
				"cpu":        {"type": "double", "time_series_metric": "gauge"},
				"pre_agg":    {"type": "aggregate_metric_double", "metrics": ["min","max","sum","value_count"], "default_metric": "max"}
			}
		}
	}`, nil)
	if tsIdx.Code != http.StatusOK {
		t.Fatalf("create ts_src failed: %d %s", tsIdx.Code, tsIdx.Body.String())
	}
	for i, doc := range []string{
		`{"@timestamp":"2026-01-01T00:05:00Z","host":"b-host","cpu":10}`,
		`{"@timestamp":"2026-01-01T00:05:00Z","host":"a-host","cpu":20,"pre_agg":{"min":1,"max":5,"sum":6,"value_count":2}}`,
		`{"@timestamp":"2026-01-01T00:10:00Z","host":"a-host","cpu":30,"pre_agg":{"min":2,"max":8,"sum":10,"value_count":2}}`,
	} {
		r := doRound65Req(t, h, http.MethodPost, "/ts_src/_doc?refresh=true", doc, nil)
		if r.Code != http.StatusCreated && r.Code != http.StatusOK {
			t.Fatalf("index ts doc %d failed: %d %s", i+1, r.Code, r.Body.String())
		}
	}
	dsResp := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/ts_src/_downsample/ts_dst", `{"fixed_interval":"1h"}`, nil))
	if ack, _ := dsResp["acknowledged"].(bool); !ack {
		t.Fatalf("downsample failed: %+v", dsResp)
	}
	dsHits := mustDecodeJSONMapR65(t, doRound65Req(t, h, http.MethodPost, "/ts_dst/_search", `{"sort":[{"host":"asc"}]}`, nil))
	hitArr, _ := dsHits["hits"].(map[string]any)["hits"].([]any)
	if len(hitArr) != 2 {
		t.Fatalf("expected 2 downsampled groups, got %d (%+v)", len(hitArr), dsHits)
	}
	firstSrc := hitArr[0].(map[string]any)["_source"].(map[string]any)
	cpuAgg, _ := firstSrc["cpu"].(map[string]any)
	if cpuAgg["min"] != 20.0 || cpuAgg["max"] != 30.0 || cpuAgg["sum"] != 50.0 || cpuAgg["value_count"] != 2.0 {
		t.Fatalf("unexpected merged cpu gauge agg: %+v", cpuAgg)
	}
	preAgg, _ := firstSrc["pre_agg"].(map[string]any)
	if preAgg["min"] != 1.0 || preAgg["max"] != 8.0 || preAgg["sum"] != 16.0 || preAgg["value_count"] != 4.0 {
		t.Fatalf("unexpected merged pre_agg aggregate_metric_double: %+v", preAgg)
	}
}

func TestRound65_Modules_UncoveredHelpers(t *testing.T) {
	srv := newRound65Server("8.15.5")
	h := srv.Handler()

	// Create base index & doc + alias for endpoint coverage.
	_ = doRound65Req(t, h, http.MethodPut, "/cov_idx-000001", `{"aliases":{"cov_alias":{"is_write_index":true}},"mappings":{"properties":{"msg":{"type":"text"}}}}`, nil)
	_ = doRound65Req(t, h, http.MethodPut, "/cov_idx-000001/_doc/d1?refresh=true", `{"msg":"hello world"}`, nil)

	// features.go HTTP handlers: handleReadyz, handleResolveIndex, handleResolveCluster, handleExplainDoc, handleRollover
	if r := doRound65Req(t, h, http.MethodGet, "/readyz", "", nil); r.Code != http.StatusOK {
		t.Fatalf("GET /readyz failed: %d %s", r.Code, r.Body.String())
	}
	if r := doRound65Req(t, h, http.MethodGet, "/_resolve/index/*", "", nil); r.Code != http.StatusOK {
		t.Fatalf("GET /_resolve/index/* failed: %d %s", r.Code, r.Body.String())
	}
	if r := doRound65Req(t, h, http.MethodGet, "/_resolve/cluster/*", "", nil); r.Code != http.StatusOK {
		t.Fatalf("GET /_resolve/cluster/* failed: %d %s", r.Code, r.Body.String())
	}
	if r := doRound65Req(t, h, http.MethodPost, "/cov_idx-000001/_explain/d1", `{"query":{"match":{"msg":"hello"}}}`, nil); r.Code != http.StatusOK {
		t.Fatalf("POST /_explain/d1 failed: %d %s", r.Code, r.Body.String())
	}
	if r := doRound65Req(t, h, http.MethodPost, "/cov_alias/_rollover?dry_run=true", `{"conditions":{"max_docs":0}}`, nil); r.Code != http.StatusOK {
		t.Fatalf("POST /_rollover?dry_run=true failed: %d %s", r.Code, r.Body.String())
	}

	// Direct features.go helper coverage.
	if !isEmptyIngestSetValue(nil) || !isEmptyIngestSetValue("") || !isEmptyIngestSetValue([]any{}) || !isEmptyIngestSetValue(map[string]any{}) || isEmptyIngestSetValue("ok") {
		t.Fatalf("isEmptyIngestSetValue mismatch")
	}
	if ce := wrapIngestProcErrRound60("set", "t1", "", fmt.Errorf("[field] bad")); ce.(*ingestConfigErrorRound60).propName != "field" {
		t.Fatalf("wrapIngestProcErrRound60 mismatch: %+v", ce)
	}
	if formatIngestDateInput(math.NaN()) != "NaN" || formatIngestDateInput(float64(123)) != "123" || formatIngestDateInput(int64(7)) != "7" || formatIngestDateInput(int(9)) != "9" {
		t.Fatalf("formatIngestDateInput mismatch")
	}
	if !isUSWeekLocaleRound60("en_US") || isUSWeekLocaleRound60("en-GB") {
		t.Fatalf("isUSWeekLocaleRound60 mismatch")
	}
	if _, ok := parseWeekYearDateRound60("2025-W01-1T01:02:03Z", "weekyear_week_day", time.UTC, "en_US"); !ok {
		t.Fatalf("expected US weekyear_week_day parse success")
	}
	if _, ok := parseWeekYearDateRound60("2025-01-1", "weekyear_week_day", time.UTC, "en_GB"); !ok {
		t.Fatalf("expected ISO weekyear_week_day parse success")
	}
	if _, ok := parseWeekYearDateRound60("2025-W01", "yyyy-MM-dd", time.UTC, "en_GB"); ok {
		t.Fatalf("expected parseWeekYearDateRound60 rejection for non-week format")
	}
	if v, ok := ingestNumericFloat64(json.Number("3.5")); !ok || v != 3.5 {
		t.Fatalf("ingestNumericFloat64 mismatch: (%v,%v)", v, ok)
	}
	if err := missingIngestPathErrorRound60(map[string]any{"a": map[string]any{"b": 1}}, "a.c.d"); !strings.Contains(err.Error(), "field [c]") {
		t.Fatalf("missingIngestPathErrorRound60 mismatch: %v", err)
	}
	for _, u := range []string{"1km", "1mi", "1yd", "1ft", "1cm", "1mm", "10m"} {
		if r, err := parseIngestCircleRadius(u, "geo_shape"); err != nil || r <= 0 {
			t.Fatalf("parseIngestCircleRadius(%q) failed: (%v, %v)", u, r, err)
		}
	}
	if _, err := parseIngestCircleRadius("-5", "shape"); err == nil {
		t.Fatalf("expected negative circle radius error")
	}
	docM := map[string]any{"a": map[string]any{"keep": 1}, "arr": []any{map[string]any{"k": "v"}}}
	setIngestPathMergeWithOverride(docM, "a", map[string]any{"keep": 2, "add": 3}, false)
	setIngestPathMergeWithOverride(docM, "arr.0.x", "y", true)
	if docM["a"].(map[string]any)["keep"] != 1 || docM["a"].(map[string]any)["add"] != 3 {
		t.Fatalf("setIngestPathMergeWithOverride mismatch: %+v", docM)
	}
	if c, ok := communityIDICMPEquiv(1, 8); !ok || c != 0 {
		t.Fatalf("communityIDICMPEquiv v4 failed: (%d,%v)", c, ok)
	}
	if c, ok := communityIDICMPEquiv(58, 128); !ok || c != 129 {
		t.Fatalf("communityIDICMPEquiv v6 failed: (%d,%v)", c, ok)
	}
	if cmp, ok := compareEnrichRangeValues("10.0.0.1", "10.0.0.2"); !ok || cmp >= 0 {
		t.Fatalf("compareEnrichRangeValues IP failed: (%d,%v)", cmp, ok)
	}
	if !enrichDocMatchesRangeValue(map[string]any{"cidr": "10.0.0.0/8", "rng": map[string]any{"gte": 5, "lt": 10}}, "cidr", []any{"10.1.2.3"}) {
		t.Fatalf("enrichDocMatchesRangeValue CIDR failed")
	}
	if !enrichDocMatchesRangeValue(map[string]any{"rng": map[string]any{"gt": 1, "lte": 10}}, "rng", 5) || !enrichScalarValuesEqual(5, float64(5)) {
		t.Fatalf("enrichDocMatchesRangeValue/enrichScalarValuesEqual failed")
	}

	// Direct round60_features.go helper coverage.
	if id := generateESAutoIDRound60(); len(id) != 20 {
		t.Fatalf("unexpected generateESAutoIDRound60 length: %q", id)
	}
	if _, err := srv.physicalDeleteDocs(context.Background(), srv.indices["cov_idx-000001"], []string{"d1"}); err != nil {
		t.Fatalf("physicalDeleteDocs failed: %v", err)
	}
	if !srv.hasExplicitTargetESVersion() {
		t.Fatalf("expected hasExplicitTargetESVersion=true")
	}
	reqWithType := withLegacyDocType(httptest.NewRequest(http.MethodGet, "/", nil), "_doc")
	if explicitLegacyDocTypeFromRequest(reqWithType) != "_doc" || legacyDocTypeFromRequest(reqWithType) != "_doc" {
		t.Fatalf("legacyDocType helpers mismatch")
	}
	if esMurmur3Shard("key", 3, 3) < 0 {
		t.Fatalf("unexpected negative shard")
	}
	if sVal, okS := stringifyScalarIDOrRouting(float64(42)); !okS || sVal != "42" {
		t.Fatalf("stringifyScalarIDOrRouting failed: (%q,%v)", sVal, okS)
	}
	if srv.wasDocDeletedRound60("cov_idx-000001", "nonexistent") {
		t.Fatalf("expected wasDocDeletedRound60=false")
	}
	if badCS := doRound65Req(t, h, http.MethodGet, "/_cluster/state/invalid_metric", "", nil); badCS.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid cluster state metric, got %d", badCS.Code)
	}

	// Direct round63_modules_ingest.go helper coverage.
	if v := normalizeDownsampleCounterValRound64([]any{float64(9), float64(2), float64(5)}); v != float64(2) {
		t.Fatalf("normalizeDownsampleCounterValRound64 mismatch: %v", v)
	}
	if sArr := sortDownsampleLabelSliceRound64([]any{"z", "a"}); !reflect.DeepEqual(sArr, []any{"a", "z"}) {
		t.Fatalf("sortDownsampleLabelSliceRound64 strings mismatch: %v", sArr)
	}
	if nArr := sortDownsampleLabelSliceRound64([]any{3, 1, 2}); !reflect.DeepEqual(nArr, []any{1, 2, 3}) {
		t.Fatalf("sortDownsampleLabelSliceRound64 nums mismatch: %v", nArr)
	}
	if !math.IsNaN(quantizeHalfFloatRound64(math.NaN())) || !math.IsInf(quantizeHalfFloatRound64(1e6), 1) || quantizeHalfFloatRound64(1.5) != 1.5 {
		t.Fatalf("quantizeHalfFloatRound64 mismatch")
	}
	if v := coerceESQLCellPreserveOrderRound64([]any{nil, "12"}, "integer"); v != int64(12) {
		t.Fatalf("coerceESQLCellPreserveOrderRound64 single-elem slice mismatch: %#v", v)
	}
	if v := coerceESQLCellPreserveOrderRound64([]any{"1", "2"}, "unsigned_long"); len(v.([]any)) != 2 {
		t.Fatalf("coerceESQLCellPreserveOrderRound64 multi-elem mismatch: %#v", v)
	}
	if b := encodeMVTInt64ValueRound63(-5); len(b) == 0 {
		t.Fatalf("encodeMVTInt64ValueRound63 negative mismatch")
	}
	// Construct valid Word CLX (Prc + Pcdt) with both ANSI and UTF-16LE pieces.
	var wd bytes.Buffer
	wd.WriteString("Hello ")
	u16Bytes := utf16.Encode([]rune("World"))
	for _, u := range u16Bytes {
		_ = binary.Write(&wd, binary.LittleEndian, u)
	}
	var clx bytes.Buffer
	clx.Write([]byte{0x01, 0x01, 0x00, 0x99}) // 1-byte Prc
	clx.WriteByte(0x02)                       // Pcdt
	_ = binary.Write(&clx, binary.LittleEndian, uint32(4*3+8*2))
	_ = binary.Write(&clx, binary.LittleEndian, uint32(0))
	_ = binary.Write(&clx, binary.LittleEndian, uint32(6))
	_ = binary.Write(&clx, binary.LittleEndian, uint32(11))
	// Piece 0: ANSI fc = 0 (encoded with 0x40000000, byteOff = fc/2 = 0)
	_ = binary.Write(&clx, binary.LittleEndian, uint16(0))
	_ = binary.Write(&clx, binary.LittleEndian, uint32(0x40000000))
	_ = binary.Write(&clx, binary.LittleEndian, uint16(0))
	// Piece 1: UTF-16 fc = 6
	_ = binary.Write(&clx, binary.LittleEndian, uint16(0))
	_ = binary.Write(&clx, binary.LittleEndian, uint32(6))
	_ = binary.Write(&clx, binary.LittleEndian, uint16(0))
	if txt, okTxt := parseWordClxPieceTableRound63(wd.Bytes(), clx.Bytes(), 11); !okTxt || txt != "Hello World" {
		t.Fatalf("parseWordClxPieceTableRound63 mismatch: (%q, %v)", txt, okTxt)
	}

	// finalizeReroutedDestinationRound63 + serveILMMoveToStepRound63
	srv.mu.Lock()
	srv.pipelines["dest_def"] = map[string]any{"processors": []any{map[string]any{"set": map[string]any{"field": "after", "value": true}}}}
	srv.indexDefaultPipelines["reroute_dst"] = "dest_def"
	srv.mu.Unlock()
	resReroute := &IngestWriteResultRound61{
		Doc:         json.RawMessage(`{"x":1}`),
		TargetIndex: "reroute_dst",
		DocID:       "r1",
	}
	if st, _, er := srv.finalizeReroutedDestinationRound63("orig_idx", resReroute); st != 0 || !strings.Contains(string(resReroute.Doc), `"after":true`) {
		t.Fatalf("finalizeReroutedDestinationRound63 mismatch: st=%d er=%s doc=%s", st, er, string(resReroute.Doc))
	}
	if pol := doRound65Req(t, h, http.MethodPut, "/_ilm/policy/cov_pol", `{"policy":{"phases":{"hot":{"actions":{}},"warm":{"actions":{}}}}}`, nil); pol.Code != http.StatusOK {
		t.Fatalf("create ILM policy failed: %d %s", pol.Code, pol.Body.String())
	}
	if stSet := doRound65Req(t, h, http.MethodPut, "/cov_idx-000001/_settings", `{"index.lifecycle.name":"cov_pol"}`, nil); stSet.Code != http.StatusOK {
		t.Fatalf("attach ILM policy failed: %d %s", stSet.Code, stSet.Body.String())
	}
	if r := doRound65Req(t, h, http.MethodPost, "/_ilm/move/cov_idx-000001", `{"current_step":{"phase":"hot","action":"complete","name":"complete"},"next_step":{"phase":"warm","action":"complete","name":"complete"}}`, nil); r.Code != http.StatusOK {
		t.Fatalf("ILM move step failed: %d %s", r.Code, r.Body.String())
	}
}
