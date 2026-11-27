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
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func FuzzQueryAndShardCacheKeyIsolation(f *testing.F) {
	f.Add("key_id_alpha", "secret_a", "typed_keys", "true", "false", "filter_path_a", "hash_1")
	f.Add("k2", "s2", "rest_total_hits_as_int", "true", "false", "hits._id", "hash_2")
	f.Add("admin_key", "pw!", "search_type", "dfs_query_then_fetch", "query_then_fetch", "_all", "mh-xyz")
	f.Add("op", "tok", "preference", "_local", "_shards:0", "format=json", "m1")
	f.Add("a:b", "c=d", "source_content_type", "application/json", "application/x-ndjson", "pretty", "h9")

	f.Fuzz(func(t *testing.T, keyID, secret, paramName, valA, valB, extra, mapHashSeed string) {
		if strings.ContainsAny(keyID, ":\x00\r\n") || keyID == "" {
			keyID = "k1"
		}
		if strings.ContainsAny(secret, "\x00\r\n") || secret == "" {
			secret = "s1"
		}

		srv := NewServer("es_compat", NewMemoryBackend(false), transpiler.TranspilerOptions{})
		rawMapping := &esast.MappingSpec{
			Properties: map[string]esast.FieldProperty{
				"title": {Type: "text"},
			},
		}
		scA := schema.CompileIndexSchema("es_compat", "idx_fuzz", rawMapping)
		scA.RawMapping = rawMapping
		scA.MappingHash = "mh-a-" + mapHashSeed

		srv.mu.Lock()
		srv.indices["idx_fuzz"] = scA
		srv.securityUsers["alice"] = map[string]any{"roles": []string{"reader"}}
		srv.securityUsers["bob"] = map[string]any{"roles": []string{"writer"}}
		srv.securityRoles["reader"] = map[string]any{"indices": []any{map[string]any{"names": []string{"idx_fuzz"}, "privileges": []string{"read"}}}}
		srv.securityRoles["writer"] = map[string]any{"indices": []any{map[string]any{"names": []string{"idx_*"}, "privileges": []string{"all"}}}}
		srv.securityAPIKeys[keyID] = map[string]any{"id": keyID, "username": "alice"}
		srv.mu.Unlock()

		cred := keyID + ":" + secret
		stdTok := base64.StdEncoding.EncodeToString([]byte(cred))
		rawTok := base64.RawStdEncoding.EncodeToString([]byte(cred))

		makeHTTPReq := func(auth string, qv url.Values) *http.Request {
			u := &url.URL{Path: "/idx_fuzz/_search", RawQuery: qv.Encode()}
			req := &http.Request{Method: http.MethodPost, URL: u, Header: make(http.Header)}
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			return req
		}

		sReq := &esast.SearchRequest{Query: &esast.Query{MatchAll: map[string]any{}}}
		rawBody := []byte(`{"query":{"match_all":{}}}`)

		// Never panic on arbitrary tokens/params, and isolate StdEncoding vs RawStdEncoding cleanly when key resolves.
		scopeStd := srv.buildQueryCacheAuthScopeR66(makeHTTPReq("ApiKey "+stdTok, nil))
		scopeRaw := srv.buildQueryCacheAuthScopeR66(makeHTTPReq("ApiKey "+rawTok, nil))
		if scopeStd == "" || scopeRaw == "" {
			t.Fatalf("expected non-empty auth scopes")
		}

		// SecurityEpoch bump MUST isolate both ShardRequestCache and QueryResultCache keys.
		shardBefore := srv.buildShardRequestCacheKeyR63(makeHTTPReq("", nil), []string{"idx_fuzz"}, []string{"idx_fuzz"}, sReq, rawBody)
		scopeBefore := srv.buildQueryCacheAuthScopeR66(makeHTTPReq("", nil))
		srv.SetAllowTestFixtureAuth(true)
		shardAfter := srv.buildShardRequestCacheKeyR63(makeHTTPReq("", nil), []string{"idx_fuzz"}, []string{"idx_fuzz"}, sReq, rawBody)
		scopeAfter := srv.buildQueryCacheAuthScopeR66(makeHTTPReq("", nil))
		if shardBefore == shardAfter {
			t.Fatalf("expected SecurityEpoch change to isolate ShardRequestCache key")
		}
		if scopeBefore == scopeAfter {
			t.Fatalf("expected SecurityEpoch change to isolate QueryResultCache auth scope")
		}

		// Map parameter into allowed response-shaping URL params; different values must produce different keys.
		allowed := queryCacheResponseShapingURLParamsR67
		chosen := allowed[len(paramName)%len(allowed)]
		if valA == valB {
			valB = valA + "_diff"
		}
		qpA := url.Values{chosen: []string{valA}}
		qpB := url.Values{chosen: []string{valB}}

		sScopeA := srv.buildQueryCacheAuthScopeR66(makeHTTPReq("ApiKey "+rawTok, qpA))
		sScopeB := srv.buildQueryCacheAuthScopeR66(makeHTTPReq("ApiKey "+rawTok, qpB))
		if sScopeA == sScopeB {
			t.Fatalf("response-shaping param %s (%q vs %q) collided in QueryCacheAuthScope", chosen, valA, valB)
		}

		qcKeyA, okA := buildQueryCacheKeyWithAuthAndParams([]string{"idx_fuzz"}, sReq, "", 1, qpA)
		qcKeyB, okB := buildQueryCacheKeyWithAuthAndParams([]string{"idx_fuzz"}, sReq, "", 1, qpB)
		if !okA || !okB || qcKeyA == qcKeyB {
			t.Fatalf("response-shaping param %s (%q vs %q) failed isolation in QueryResultCache key", chosen, valA, valB)
		}
		qcEpoch1, _ := buildQueryCacheKeyWithAuthAndParams([]string{"idx_fuzz"}, sReq, "", 1, nil)
		qcEpoch2, _ := buildQueryCacheKeyWithAuthAndParams([]string{"idx_fuzz"}, sReq, "", 2, nil)
		if qcEpoch1 == qcEpoch2 {
			t.Fatalf("expected different securityEpoch values to produce distinct QueryResultCache keys")
		}

		shardA := srv.buildShardRequestCacheKeyR63(makeHTTPReq("", qpA), []string{"idx_fuzz"}, []string{"idx_fuzz"}, sReq, rawBody)
		shardB := srv.buildShardRequestCacheKeyR63(makeHTTPReq("", qpB), []string{"idx_fuzz"}, []string{"idx_fuzz"}, sReq, rawBody)
		if shardA == shardB {
			t.Fatalf("response-shaping param %s (%q vs %q) collided in ShardRequestCache key", chosen, valA, valB)
		}

		// Changing MappingHash must change ShardRequestCache key without re-marshaling RawMapping.
		_ = extra
		srv.mu.Lock()
		scA.MappingHash = "mh-b-" + mapHashSeed + "-changed"
		srv.mu.Unlock()
		shardMapChanged := srv.buildShardRequestCacheKeyR63(makeHTTPReq("", qpA), []string{"idx_fuzz"}, []string{"idx_fuzz"}, sReq, rawBody)
		if shardA == shardMapChanged {
			t.Fatalf("expected MappingHash change to isolate ShardRequestCache key")
		}
	})
}

func FuzzStreamLoadChunkingHeadersAndErrorURL(f *testing.F) {
	f.Add("http://10.0.0.10:8030,http://10.0.0.11:8030", "10.0.0.20", "http://10.0.0.20:8040/api/_load_error/1", "/api/es/orders/_stream_load", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nEvil: 1", "req-1\nX: y", 48, 3)
	f.Add("https://fe1.prod.example:8030,https://fe2.prod.example:8030", "be1.prod.example", "http://be1.prod.example:8040/api/_load_error/2", "/_stream_load", "00-abc-def-01", "rid-2", 64, 5)
	f.Add("http://127.0.0.1:8030", "", "http://169.254.169.254/api/_load_error/x", "/api/es/t/extra/_stream_load", "tp", "rid", 32, 4)

	f.Fuzz(func(t *testing.T, feEndpoints, discoveredHost, errURLStr, redirPath, traceparent, reqID string, maxBatchBytes int, lineCountRaw int) {
		if maxBatchBytes < 16 || maxBatchBytes > 512 {
			maxBatchBytes = 64
		}
		lineCount := (lineCountRaw & 7) + 1

		sl := NewStreamLoadClient(StreamLoadConfig{
			FEHTTPEndpoint: feEndpoints,
			User:           "root",
			Password:       "pw",
			Database:       "es_compat",
			Timeout:        time.Second,
			MaxBatchBytes:  maxBatchBytes,
			MaxRetries:     -1,
			BaseBackoff:    time.Millisecond,
		})
		if sl == nil {
			return
		}
		if discoveredHost != "" {
			sl.AllowBEHosts([]string{discoveredHost})
		}

		// 1. Validate error URL safety against metadata hosts and scheme downgrades.
		if parsedErrURL, err := url.Parse(errURLStr); err == nil {
			_, ok := sl.validateErrorDetailURL(parsedErrURL)
			if ok {
				host := parsedErrURL.Hostname()
				if isBlockedStreamLoadHost(host) || !strings.Contains(parsedErrURL.Path, "_load_error") || parsedErrURL.User != nil {
					t.Fatalf("validateErrorDetailURL unexpectedly accepted unsafe URL %q", errURLStr)
				}
				if feURLs, feErr := sl.parseConfiguredFEURLs(); feErr == nil && streamLoadAnyHTTPS(feURLs) && !strings.EqualFold(parsedErrURL.Scheme, "https") {
					t.Fatalf("validateErrorDetailURL accepted https->%s scheme downgrade %q", parsedErrURL.Scheme, errURLStr)
				}
			}
		}

		// 2. Enforce exact /api/<db>/<table>/_stream_load path validation on redirects.
		if parsedRedir, err := url.Parse("https://10.0.0.10:8040" + redirPath); err == nil {
			initReq, _ := http.NewRequest(http.MethodPut, "https://10.0.0.10:8030/api/es/orders/_stream_load", nil)
			redirReq, rErr := http.NewRequest(http.MethodPut, parsedRedir.String(), nil)
			if rErr == nil {
				cErr := sl.checkStreamLoadRedirect(redirReq, []*http.Request{initReq})
				if cErr == nil {
					if redirReq.URL.Path != initReq.URL.Path || !isValidStreamLoadPath(redirReq.URL.Path) {
						t.Fatalf("redirect accepted invalid or mismatched path %q (initial=%q)", redirReq.URL.Path, initReq.URL.Path)
					}
				}
			}
		}

		// 3. Test chunking and sanitized trace header propagation without spawning sockets.
		feURLs, feErr := sl.parseConfiguredFEURLs()
		if feErr != nil || len(feURLs) == 0 {
			return
		}
		for _, u := range feURLs {
			if isBlockedStreamLoadHost(u.Hostname()) {
				return
			}
		}

		var sentRequests atomic.Int64
		sl.httpClient = &http.Client{
			CheckRedirect: sl.checkStreamLoadRedirect,
			Transport: round67TestRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				sentRequests.Add(1)
				for _, h := range []string{"traceparent", "X-Request-ID", "X-Opaque-Id"} {
					if v := req.Header.Get(h); strings.ContainsAny(v, "\r\n") {
						t.Fatalf("header %s contains CR/LF characters: %q", h, v)
					}
				}
				_, _ = io.Copy(io.Discard, req.Body)
				return newRound67TestJSONResponse(req, http.StatusOK, nil, `{"Status":"Success"}`), nil
			}),
		}

		var payload strings.Builder
		for i := 0; i < lineCount; i++ {
			fmt.Fprintf(&payload, "{\"_id\":\"doc-%d\",\"v\":%d}\n", i, i)
		}
		ctx := WithTraceMeta(context.Background(), TraceMeta{
			Traceparent: traceparent,
			RequestID:   reqID,
			OpaqueID:    reqID + "-opq",
		})
		if err := sl.LoadNDJSON(ctx, "orders", []byte(payload.String()), false); err != nil {
			t.Fatalf("LoadNDJSON failed unexpectedly with valid transport: %v", err)
		}
		if sentRequests.Load() < 1 {
			t.Fatalf("expected at least 1 Stream Load chunk request, got %d", sentRequests.Load())
		}
	})
}
