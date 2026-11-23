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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func buildFuzzTermsEnumServerR65() *Server {
	mb := NewMemoryBackend(false)
	srv := NewServer("default", mb, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	h := srv.Handler()

	// Create `sec_idx` with keyword, flattened, and constant_keyword fields and seed one secret doc.
	reqIdx := httptest.NewRequest(http.MethodPut, "/sec_idx", bytes.NewBufferString(`{
		"mappings": {
			"properties": {
				"tag":  {"type": "keyword"},
				"flat": {"type": "flattened"},
				"ck":   {"type": "constant_keyword", "value": "const"}
			}
		}
	}`))
	reqIdx.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), reqIdx)

	reqDoc := httptest.NewRequest(http.MethodPut, "/sec_idx/_doc/1?refresh=true", bytes.NewBufferString(`{
		"tag":  "topsecret",
		"flat": {"sub": "flatsecret"},
		"ck":   "const"
	}`))
	reqDoc.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), reqDoc)

	// Create alias pointing to sec_idx.
	reqAlias := httptest.NewRequest(http.MethodPost, "/_aliases", bytes.NewBufferString(`{
		"actions": [{"add": {"index": "sec_idx", "alias": "alias_sec"}}]
	}`))
	reqAlias.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), reqAlias)

	// Install fixed security users, roles, and API keys representing fail-closed & allowed personas.
	srv.mu.Lock()
	srv.securityRoles["dls_all_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names": []any{"sec_idx"},
			"query": `{"term": {"ck": "const"}}`,
		}},
	}
	srv.securityRoles["dls_some_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names": []any{"sec_idx"},
			"query": `{"term": {"tag": "public"}}`,
		}},
	}
	srv.securityRoles["dls_must_not_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names": []any{"sec_idx"},
			"query": map[string]any{
				"bool": map[string]any{
					"must":     []any{map[string]any{"match_all": map[string]any{}}},
					"must_not": []any{map[string]any{"term": map[string]any{"tag": "hidden"}}},
				},
			},
		}},
	}
	srv.securityRoles["fls_except_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names": []any{"sec_idx"},
			"field_security": map[string]any{
				"except": []any{"tag", "flat.*"},
			},
		}},
	}
	srv.securityRoles["fls_empty_grant_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names": []any{"sec_idx"},
			"field_security": map[string]any{
				"grant": []any{},
			},
		}},
	}
	srv.securityRoles["cluster_only_role"] = map[string]any{
		"cluster": []any{"all"},
	}
	srv.securityRoles["alias_only_role"] = map[string]any{
		"indices": []any{map[string]any{
			"names":      []any{"alias_sec"},
			"privileges": []any{"read"},
		}},
	}
	srv.securityUsers["dls_all_user"] = map[string]any{"roles": []any{"dls_all_role"}, "enabled": true}
	srv.securityUsers["dls_some_user"] = map[string]any{"roles": []any{"dls_some_role"}, "enabled": true}
	srv.securityUsers["dls_must_not_user"] = map[string]any{"roles": []any{"dls_must_not_role"}, "enabled": true}
	srv.securityUsers["fls_user"] = map[string]any{"roles": []any{"fls_except_role"}, "enabled": true}
	srv.securityUsers["fls_empty_grant_user"] = map[string]any{"roles": []any{"fls_empty_grant_role"}, "enabled": true}
	srv.securityUsers["cluster_only_user"] = map[string]any{"roles": []any{"cluster_only_role"}, "enabled": true}
	srv.securityUsers["dls_alias_user"] = map[string]any{"roles": []any{"alias_only_role"}, "enabled": true}
	srv.securityUsers["disabled_user"] = map[string]any{"roles": []any{"superuser"}, "enabled": false}
	srv.securityAPIKeys["good_key"] = map[string]any{"id": "good_key", "username": "dls_all_user", "invalidated": false}
	srv.securityAPIKeys["revoked_key"] = map[string]any{"id": "revoked_key", "username": "elastic", "invalidated": true}
	srv.securityAPIKeys["cluster_key"] = map[string]any{
		"id":       "cluster_key",
		"username": "elastic",
		"role_descriptors": map[string]any{
			"only_cluster": map[string]any{"cluster": []any{"all"}},
		},
	}
	srv.mu.Unlock()
	return srv
}

func basicHdrR65(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// FuzzTermsEnumDLSFLS exercises fail-closed authorization and bypass resistance across both
// `EvaluateTermsEnumSecurityAccessR64` and end-to-end `/_terms_enum` HTTP handling.
func FuzzTermsEnumDLSFLS(f *testing.F) {
	f.Add("", "sec_idx", "tag", `{"match_all":{}}`, "tag", "", `{"field":"tag","size":10}`)
	f.Add("Basic invalid!!!", "sec_idx", "tag", `{"match_all":{}}`, "", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("", "pw"), "sec_idx", "tag", `{"match_all":{}}`, "", "", `{"field":"tag"}`)
	f.Add("Basic "+base64.StdEncoding.EncodeToString([]byte("nocolon")), "sec_idx", "tag", `{"match_all":{}}`, "", "", `{"field":"tag"}`)
	f.Add("Bearer secret-jwt-token", "sec_idx", "tag", `{"match_all":{}}`, "", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("unknown_attacker", "pw"), "sec_idx", "tag", `{"match_all":{}}`, "", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("dls_some_user", "pw"), "sec_idx", "tag", `{"term":{"tag":"public"}}`, "", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("dls_must_not_user", "pw"), "sec_idx", "tag", `{"bool":{"must":[{"match_all":{}}],"must_not":[{"term":{"tag":"x"}}]}}`, "", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("fls_user", "pw"), "sec_idx", "tag", `{"match_all":{}}`, "", "tag", `{"field":"tag"}`)
	f.Add(basicHdrR65("fls_user", "pw"), "sec_idx", "flat.sub", `{"match_all":{}}`, "", "flat.*", `{"field":"flat.sub"}`)
	f.Add(basicHdrR65("fls_empty_grant_user", "pw"), "sec_idx", "tag", `{"match_all":{}}`, "[]", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("cluster_only_user", "pw"), "sec_idx", "tag", `""`, "", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("disabled_user", "pw"), "sec_idx", "tag", `{"match_all":{}}`, "", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("dls_alias_user", "pw"), "alias_sec", "tag", `{"match_all":{}}`, "", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("dls_alias_user", "pw"), "sec_idx", "tag", `{"match_all":{}}`, "", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("dls_all_user", "pw"), "sec_idx", "tag", `{"bool":{"should":[{"match_all":{}},{"term":{"x":"1"}}],"minimum_should_match":2}}`, "", "", `{"field":"tag"}`)
	f.Add(basicHdrR65("dls_all_user", "pw"), "sec_idx", "tag", `{"bool":{"must":{"match_all":{}}}}`, "", "", `{"field":"tag","size":65537}`)
	f.Add("ApiKey "+base64.StdEncoding.EncodeToString([]byte("revoked_key:sec")), "sec_idx", "tag", `{}`, "", "", `{"field":"tag","size":0}`)
	f.Add("ApiKey "+base64.StdEncoding.EncodeToString([]byte("cluster_key:sec")), "sec_idx", "tag", `{}`, "", "", `{"field":"tag","size":-1}`)
	f.Add("ApiKey "+base64.StdEncoding.EncodeToString([]byte("good_key:sec")), "sec_idx", "tag", `{"term":{"ck":"const"}}`, "", "", `{"field":"flat.sub","size":5}`)
	f.Add(basicHdrR65("elastic", "pw"), "sec_idx", "tag", `{"term":{"ck":"const"}}`, "tag", "", `{"field":"tag","size":5}`)

	srv := buildFuzzTermsEnumServerR65()
	h := srv.Handler()

	schemas := map[string]*schema.IndexSchema{
		"sec_idx": {
			RawMapping: &esast.MappingSpec{
				Properties: map[string]esast.FieldProperty{
					"ck":   {Type: "constant_keyword", Value: "const"},
					"tag":  {Type: "keyword"},
					"flat": {Type: "flattened"},
				},
			},
		},
	}

	f.Fuzz(func(t *testing.T, authHeader, rawIndex, fieldName, dlsJSON, grantStr, exceptStr, reqBody string) {
		if len(authHeader) > 1024 || len(rawIndex) > 128 || len(fieldName) > 128 || len(dlsJSON) > 2048 || len(reqBody) > 4096 {
			return
		}
		// 1. Direct security evaluator fail-closed checks on fuzzed DLS/FLS descriptors.
		fuzzRole := map[string]any{
			"indices": []any{map[string]any{
				"names":      []any{"sec_idx"},
				"privileges": []any{"read"},
				"query":      dlsJSON,
			}},
		}
		if grantStr == "[]" {
			fuzzRole["indices"].([]any)[0].(map[string]any)["field_security"] = map[string]any{"grant": []any{}}
		} else if grantStr != "" || exceptStr != "" {
			fs := map[string]any{}
			if grantStr != "" {
				fs["grant"] = []any{grantStr}
			}
			if exceptStr != "" {
				fs["except"] = []any{exceptStr}
			}
			fuzzRole["indices"].([]any)[0].(map[string]any)["field_security"] = fs
		}
		users := map[string]map[string]any{
			"fuzz_user": {"roles": []any{"fuzz_role"}, "enabled": true},
			"disabled":  {"roles": []any{"superuser"}, "enabled": false},
		}
		roles := map[string]map[string]any{
			"fuzz_role":    fuzzRole,
			"cluster_only": {"cluster": []any{"all"}},
		}
		apiKeys := map[string]map[string]any{
			"revoked": {"username": "elastic", "invalidated": true},
			"orphan":  {"username": "nonexistent_owner"},
			"valid":   {"username": "fuzz_user", "invalidated": false},
		}

		// Empty, malformed, Bearer, empty-username, disabled, orphan/revoked keys must ALWAYS fail closed.
		if EvaluateTermsEnumSecurityAccessR64("", users, roles, apiKeys, schemas, []string{"sec_idx"}, fieldName) {
			t.Fatalf("empty authHeader unexpectedly granted access")
		}
		if EvaluateTermsEnumSecurityAccessR64("Bearer "+authHeader, users, roles, apiKeys, schemas, []string{"sec_idx"}, fieldName) {
			t.Fatalf("Bearer scheme unexpectedly granted access")
		}
		if EvaluateTermsEnumSecurityAccessR64(basicHdrR65("", "pass"), users, roles, apiKeys, schemas, []string{"sec_idx"}, fieldName) {
			t.Fatalf("empty Basic username unexpectedly granted access")
		}
		if EvaluateTermsEnumSecurityAccessR64(basicHdrR65("disabled", "pass"), users, roles, apiKeys, schemas, []string{"sec_idx"}, fieldName) {
			t.Fatalf("disabled user unexpectedly granted access")
		}
		if EvaluateTermsEnumSecurityAccessR64("ApiKey "+base64.StdEncoding.EncodeToString([]byte("revoked:sec")), users, roles, apiKeys, schemas, []string{"sec_idx"}, fieldName) {
			t.Fatalf("invalidated API key unexpectedly granted access")
		}
		if EvaluateTermsEnumSecurityAccessR64("ApiKey "+base64.StdEncoding.EncodeToString([]byte("orphan:sec")), users, roles, apiKeys, schemas, []string{"sec_idx"}, fieldName) {
			t.Fatalf("orphan API key unexpectedly granted access")
		}

		// Explicit denied DLS/FLS patterns with fuzzed target field must stay false.
		trimmedDLS := strings.TrimSpace(dlsJSON)
		if trimmedDLS == "" || trimmedDLS == "{}" {
			if EvaluateTermsEnumSecurityAccessR64(basicHdrR65("fuzz_user", "pw"), users, roles, apiKeys, schemas, []string{"sec_idx"}, fieldName) {
				t.Fatalf("empty/invalid DLS %q unexpectedly allowed access", dlsJSON)
			}
		}
		if grantStr == "[]" {
			if EvaluateTermsEnumSecurityAccessR64(basicHdrR65("fuzz_user", "pw"), users, roles, apiKeys, schemas, []string{"sec_idx"}, fieldName) {
				t.Fatalf("empty grant FLS unexpectedly allowed access")
			}
		}
		if !EvaluateTermsEnumSecurityAccessR64(basicHdrR65("elastic", "pw"), users, roles, apiKeys, schemas, []string{"sec_idx"}, fieldName) {
			t.Fatalf("superuser elastic must always have terms_enum access")
		}
		_ = EvaluateTermsEnumSecurityAccessR64(authHeader, users, roles, apiKeys, schemas, []string{"sec_idx"}, fieldName)

		// 2. End-to-end HTTP terms_enum request safety (zero panics + zero secret leak for denied identities).
		safeIdx := url.PathEscape(strings.ReplaceAll(strings.TrimSpace(rawIndex), "/", "_"))
		endpoint := "/_all/_terms_enum"
		if safeIdx != "" {
			endpoint = "/" + safeIdx + "/_terms_enum"
		}
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		if authHeader != "" && !strings.ContainsAny(authHeader, "\r\n") {
			req.Header.Set("Authorization", authHeader)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		bodyStr := rec.Body.String()
		for _, deniedAuth := range []string{
			basicHdrR65("unknown_attacker", "pw"),
			basicHdrR65("dls_some_user", "pw"),
			basicHdrR65("dls_must_not_user", "pw"),
			basicHdrR65("fls_user", "pw"),
			basicHdrR65("fls_empty_grant_user", "pw"),
			basicHdrR65("cluster_only_user", "pw"),
			basicHdrR65("disabled_user", "pw"),
			"Bearer " + authHeader,
		} {
			if authHeader == deniedAuth && (strings.Contains(bodyStr, "topsecret") || strings.Contains(bodyStr, "flatsecret")) {
				t.Fatalf("denied auth %q leaked secret terms on %s (status=%d body=%s)", deniedAuth, endpoint, rec.Code, bodyStr)
			}
		}
		if authHeader == basicHdrR65("dls_alias_user", "pw") && (safeIdx == "sec_idx" || safeIdx == "" || safeIdx == "_all" || safeIdx == "*") {
			if strings.Contains(bodyStr, "topsecret") || strings.Contains(bodyStr, "flatsecret") {
				t.Fatalf("dls_alias_user leaked secret terms on direct target %q (body=%s)", endpoint, bodyStr)
			}
		}

		// Verify size boundary enforcement matches ES (> 65536 or <= 0 => 400).
		var parsedBody map[string]any
		if json.Unmarshal([]byte(reqBody), &parsedBody) == nil {
			if rawSz, hasSz := parsedBody["size"]; hasSz && rawSz != nil {
				if szF, okF := toFloat(rawSz); okF && (szF <= 0 || szF > maxTermsEnumSize) {
					if rec.Code != http.StatusBadRequest {
						t.Fatalf("expected HTTP 400 for out-of-bounds size=%v on valid JSON body, got %d (%s)", rawSz, rec.Code, bodyStr)
					}
				}
			}
		}
	})
}

func buildFuzzWireServersR65() (openSrv, authSrv *Server) {
	openSrv = NewServer("default", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	openSrv.SetTargetESVersion("8.15.5")

	authSrv = NewServer("default", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	authSrv.SetTargetESVersion("8.15.5")
	authSrv.authMu.Lock()
	authSrv.basicAuthUser = "wireadmin"
	authSrv.basicAuthPass = "wiresecret"
	authSrv.apiKey = "wireapikey123"
	authSrv.authMu.Unlock()
	return openSrv, authSrv
}

// FuzzWireMiddlewareYAMLHead exercises `withWireMiddleware`, Accept `;q=0` negotiation,
// gzip decompression, HEAD empty-body invariants, and deep YAML marshaling without panics.
func FuzzWireMiddlewareYAMLHead(f *testing.F) {
	f.Add(uint8(0), "/", "application/json", "application/json", "format=yaml", []byte(`{}`), false)
	f.Add(uint8(1), "/_nodes", "application/vnd.elasticsearch+json; compatible-with=8; q=0", "application/json", "format=yaml", []byte(`{}`), false)
	f.Add(uint8(2), "/_cluster/stats", "application/vnd.opensearch+json; q=0.9, application/vnd.elasticsearch+json; compatible-with=8; q=0.1", "application/json", "pretty=true&error_trace=true", []byte(`{}`), false)
	f.Add(uint8(3), "/_cat/indices", "text/plain;q=0.5, application/json;q=0.9", "application/x-ndjson", "format=yaml", []byte("{\"a\":1}\n{\"b\":2}\n"), false)
	f.Add(uint8(4), "/_resolve/index/*", "application/xml", "text/plain", "http_compression=bad", []byte(`{{{`), true)
	f.Add(uint8(5), "/idx/_search", "*/*;q=0", "application/yaml", "format=yaml&bogus_param=1", []byte(`{"query":{"match_all":{}}}`), true)
	f.Add(uint8(0), "/", "invalid/media/type/with/extra", "application/json", "format=yaml&filter_path=cluster_name", []byte{}, false)
	f.Add(uint8(1), "/_nodes/stats", "application/json; charset=utf-8", "application/json", "format=yaml", []byte(strings.Repeat(`{"a":`, 140)+`1`+strings.Repeat(`}`, 140)), false)

	openSrv, authSrv := buildFuzzWireServersR65()
	openH := openSrv.Handler()
	authH := authSrv.Handler()
	methods := []string{http.MethodHead, http.MethodGet, http.MethodPost, http.MethodOptions}
	allowedPaths := []string{"/", "/_nodes", "/_nodes/stats", "/_cluster/stats", "/_cat/indices", "/_resolve/index/*", "/_resolve/cluster/*", "/idx/_search"}

	f.Fuzz(func(t *testing.T, methodIdx uint8, rawPath, acceptHdr, contentTypeHdr, rawQuery string, body []byte, useGzip bool) {
		if len(rawPath) > 256 || len(acceptHdr) > 256 || len(contentTypeHdr) > 256 || len(rawQuery) > 256 || len(body) > 16384 {
			return
		}
		method := methods[int(methodIdx)%len(methods)]
		targetPath := allowedPaths[int(methodIdx/4)%len(allowedPaths)]
		if strings.HasPrefix(rawPath, "/") && !strings.ContainsAny(rawPath, "\r\n?# ") && !strings.Contains(rawPath, "_doc") && !strings.Contains(rawPath, "_bulk") {
			if p := strings.TrimSpace(rawPath); p == "/" || p == "/_nodes" || p == "/_nodes/stats" || p == "/_cluster/stats" || p == "/_cat/indices" || p == "/_resolve/index/*" {
				targetPath = p
			}
		}

		payload := body
		if useGzip {
			var gzBuf bytes.Buffer
			gw := gzip.NewWriter(&gzBuf)
			_, _ = gw.Write(body)
			_ = gw.Close()
			if len(body)%2 == 0 {
				payload = gzBuf.Bytes()
			}
		}
		targetURL := targetPath
		if cleanQ := strings.Map(func(r rune) rune {
			if r <= ' ' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, rawQuery); cleanQ != "" {
			if vals, err := url.ParseQuery(cleanQ); err == nil {
				targetURL += "?" + vals.Encode()
			}
		}

		req := httptest.NewRequest(method, targetURL, bytes.NewReader(payload))
		if acceptHdr != "" && !strings.ContainsAny(acceptHdr, "\r\n") {
			req.Header.Set("Accept", acceptHdr)
		}
		if contentTypeHdr != "" && !strings.ContainsAny(contentTypeHdr, "\r\n") {
			req.Header.Set("Content-Type", contentTypeHdr)
		}
		if useGzip {
			req.Header.Set("Content-Encoding", "gzip")
		}

		rec := httptest.NewRecorder()
		openH.ServeHTTP(rec, req)
		if method == http.MethodHead && rec.Body.Len() != 0 {
			t.Fatalf("HEAD %s produced non-empty body (%d bytes): %s", targetURL, rec.Body.Len(), rec.Body.String())
		}

		// Also exercise early 401 auth failure + HEAD + format=yaml path via authH.
		authReq := req.Clone(req.Context())
		if len(body)%3 == 0 && acceptHdr != "" && !strings.ContainsAny(acceptHdr, "\r\n") {
			authReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("bad:"+acceptHdr)))
		}
		authRec := httptest.NewRecorder()
		authH.ServeHTTP(authRec, authReq)
		if method == http.MethodHead && authRec.Body.Len() != 0 {
			t.Fatalf("HEAD (auth) %s produced non-empty body (%d bytes): %s", targetURL, authRec.Body.Len(), authRec.Body.String())
		}

		// Direct writeYAMLValueWireR64 depth bound & esFormatResponseWriter Finalize safety.
		depth := (int(methodIdx) % 145) + 1
		var nested any = string(body)
		for i := 0; i < depth; i++ {
			nested = map[string]any{"k": nested}
		}
		var yamlOut strings.Builder
		writeYAMLValueWireR64(&yamlOut, nested, 0, false)
		if yamlOut.Len() == 0 {
			t.Fatalf("writeYAMLValueWireR64 produced empty output for depth=%d", depth)
		}

		// Exercise esFormatResponseWriter pass-through on 204/304 & multi-doc NDJSON.
		if len(body) > 0 && !bytes.ContainsRune(body, 0) {
			rec2 := httptest.NewRecorder()
			fw := &esFormatResponseWriter{
				ResponseWriter: rec2,
				yamlFormat:     true,
				isHead:         method == http.MethodHead,
			}
			status := http.StatusOK
			switch methodIdx % 5 {
			case 1:
				status = http.StatusNoContent
			case 2:
				status = http.StatusNotModified
			}
			fw.ResponseWriter.Header().Set("Content-Type", "application/json")
			fw.WriteHeader(status)
			_, _ = fw.Write(body)
			fw.Flush()
			fw.Finalize()
			if (status == http.StatusNoContent || status == http.StatusNotModified || method == http.MethodHead) && rec2.Body.Len() != 0 {
				t.Fatalf("status=%d method=%s leaked response body: %q", status, method, rec2.Body.String())
			}
		}
	})
}
