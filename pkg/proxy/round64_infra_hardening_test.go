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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound64_Infra_StreamLoadProxyNilAndEnvIgnored(t *testing.T) {
	var proxyHits atomic.Int32
	proxyTrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "proxy must not be used", http.StatusBadGateway)
	}))
	defer proxyTrap.Close()

	t.Setenv("HTTP_PROXY", proxyTrap.URL)
	t.Setenv("HTTPS_PROXY", proxyTrap.URL)
	t.Setenv("http_proxy", proxyTrap.URL)
	t.Setenv("https_proxy", proxyTrap.URL)
	t.Setenv("NO_PROXY", "")

	var directHits atomic.Int32
	beSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1}`))
	}))
	defer beSrv.Close()

	sl := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: beSrv.URL,
		User:           "root",
		Password:       "pw",
		Database:       "es_compat",
		Timeout:        3 * time.Second,
	})

	tr, ok := sl.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport on httpClient, got %T", sl.httpClient.Transport)
	}
	if tr.Proxy != nil {
		t.Fatalf("expected StreamLoadClient http.Transport.Proxy to be nil")
	}
	errTr, ok := sl.errHTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport on errHTTPClient, got %T", sl.errHTTPClient.Transport)
	}
	if errTr.Proxy != nil {
		t.Fatalf("expected StreamLoadClient errHTTPClient transport Proxy to be nil")
	}

	if err := sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("LoadNDJSON failed with ambient HTTP_PROXY set: %v", err)
	}
	if directHits.Load() != 1 || proxyHits.Load() != 0 {
		t.Fatalf("expected directHits=1 proxyHits=0, got direct=%d proxy=%d", directHits.Load(), proxyHits.Load())
	}
}

func TestRound64_Infra_StreamLoadDNSLoopbackRebinding(t *testing.T) {
	t.Parallel()

	// Start a local listener to prove DialContext rejects before ever connecting.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	var dialed atomic.Int32
	doneAccept := make(chan struct{})
	go func() {
		defer close(doneAccept)
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			dialed.Add(1)
			_ = c.Close()
		}
	}()
	_, lnPort, _ := net.SplitHostPort(ln.Addr().String())

	// 1. Non-loopback FE must reject DNS resolution returning IPv4 loopback, IPv6 loopback,
	// IPv4-mapped IPv6 loopback (::ffff:127.0.0.1), or mixed private + loopback results.
	dnsCases := []struct {
		name string
		ips  []netip.Addr
	}{
		{"ipv4_loopback", []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		{"ipv4_loopback_alt", []netip.Addr{netip.MustParseAddr("127.0.1.1")}},
		{"ipv6_loopback", []netip.Addr{netip.MustParseAddr("::1")}},
		{"ipv4_mapped_ipv6_loopback", []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}},
		{"mixed_vpc_and_mapped_loopback", []netip.Addr{netip.MustParseAddr("10.0.1.25"), netip.MustParseAddr("::ffff:127.0.0.1")}},
		{"metadata_ipv4_mapped", []netip.Addr{netip.MustParseAddr("::ffff:169.254.169.254")}},
	}
	for _, tc := range dnsCases {
		sl := NewStreamLoadClient(StreamLoadConfig{
			FEHTTPEndpoint: "https://doris-fe.prod.example.com:8030",
			User:           "root",
			Database:       "es_compat",
			Timeout:        2 * time.Second,
		})
		sl.lookupNetIP = func(_ context.Context, _, _ string) ([]netip.Addr, error) {
			return tc.ips, nil
		}
		tr := sl.httpClient.Transport.(*http.Transport)
		conn, dErr := tr.DialContext(context.Background(), "tcp", net.JoinHostPort("rebind.attacker.example", lnPort))
		if conn != nil {
			_ = conn.Close()
		}
		if dErr == nil {
			t.Fatalf("%s: expected DialContext to block loopback/metadata DNS resolution", tc.name)
		}
	}

	// Literal loopback IP must also be rejected in DialContext when FE is non-loopback.
	slLiteral := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "http://10.0.1.10:8030",
		User:           "root",
		Database:       "es_compat",
	})
	trLiteral := slLiteral.httpClient.Transport.(*http.Transport)
	for _, litHost := range []string{"127.0.0.1", "[::ffff:127.0.0.1]"} {
		conn, dErr := trLiteral.DialContext(context.Background(), "tcp", litHost+":"+lnPort)
		if conn != nil {
			_ = conn.Close()
		}
		if dErr == nil {
			t.Fatalf("expected DialContext to block literal loopback %s for non-loopback FE", litHost)
		}
	}
	if dialed.Load() != 0 {
		t.Fatalf("expected 0 accepted TCP connections on blocked loopback dials, got %d", dialed.Load())
	}

	// 2. Loopback FE (http://127.0.0.1:8030 / http://localhost:8030) continues to allow loopback FE -> BE.
	beSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1}`))
	}))
	defer beSrv.Close()
	feSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, beSrv.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer feSrv.Close()

	slLoopback := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: feSrv.URL,
		User:           "root",
		Password:       "pw",
		Database:       "es_compat",
		Timeout:        2 * time.Second,
	})
	if err := slLoopback.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("expected loopback FE -> loopback BE Stream Load to succeed, got %v", err)
	}

	// Loopback FE with hostname "localhost" resolving to 127.0.0.1 must also succeed via DialContext.
	feLocalhostURL := strings.Replace(feSrv.URL, "127.0.0.1", "localhost", 1)
	slLocalhost := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: feLocalhostURL,
		User:           "root",
		Password:       "pw",
		Database:       "es_compat",
		Timeout:        2 * time.Second,
	})
	slLocalhost.lookupNetIP = func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if err := slLocalhost.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"2"}`+"\n"), true); err != nil {
		t.Fatalf("expected localhost loopback FE -> BE Stream Load to succeed, got %v", err)
	}

	_ = ln.Close()
	<-doneAccept
}

func TestRound64_Infra_StreamLoadNonStreamLoadPathAndLabelAlreadyExists(t *testing.T) {
	t.Parallel()

	// 1. Non-loopback allowlisted BE redirect to non-/_stream_load path must fail and strip Authorization.
	slPath := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "https://doris-fe.prod.example.com:8030",
		User:           "root",
		Password:       "secret",
		Database:       "es_compat",
		Timeout:        2 * time.Second,
	})
	slPath.AllowBEHosts([]string{"doris-be-01.prod.example.com"})
	var targetHits atomic.Int32
	slPath.httpClient.Transport = round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "doris-fe.prod.example.com:8030" {
			return newRound63JSONResponse(req, http.StatusTemporaryRedirect, map[string]string{
				"Location": "https://doris-be-01.prod.example.com:8040/api/admin/secret",
			}, ""), nil
		}
		targetHits.Add(1)
		return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success"}`), nil
	})
	if err := slPath.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true); err == nil || !strings.Contains(err.Error(), "non-stream-load") {
		t.Fatalf("expected non-stream-load redirect rejection, got %v", err)
	}
	if targetHits.Load() != 0 {
		t.Fatalf("expected 0 target hits on non-stream-load redirect, got %d", targetHits.Load())
	}

	// validateStreamLoadTargetURL and checkStreamLoadRedirect both reject non-/_stream_load paths on loopback.
	slLoop := NewStreamLoadClient(StreamLoadConfig{FEHTTPEndpoint: "http://127.0.0.1:8030", User: "root", Password: "secret", Database: "es_compat"})
	if badU, _ := url.Parse("http://127.0.0.1:8040/api/admin"); slLoop.validateStreamLoadTargetURL(badU) == nil {
		t.Fatalf("expected validateStreamLoadTargetURL to reject non-/_stream_load path")
	}
	var loopTargetHits atomic.Int32
	slLoop.httpClient.Transport = round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "127.0.0.1:8030" {
			return newRound63JSONResponse(req, http.StatusTemporaryRedirect, map[string]string{
				"Location": "http://127.0.0.1:8040/api/admin/secret",
			}, ""), nil
		}
		loopTargetHits.Add(1)
		return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success"}`), nil
	})
	if err := slLoop.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true); err == nil || !strings.Contains(err.Error(), "non-stream-load") {
		t.Fatalf("expected loopback non-stream-load redirect rejection, got %v", err)
	}
	if loopTargetHits.Load() != 0 {
		t.Fatalf("expected 0 target hits on loopback non-stream-load redirect, got %d", loopTargetHits.Load())
	}

	// 2. Label Already Exists handling with ExistingJobStatus.
	runLabelCase := func(name string, responses []struct {
		httpStatus int
		body       string
	}) (int, error) {
		sl := NewStreamLoadClient(StreamLoadConfig{
			FEHTTPEndpoint: "http://127.0.0.1:8030",
			User:           "root",
			Database:       "es_compat",
			Timeout:        2 * time.Second,
		})
		var calls atomic.Int32
		sl.httpClient.Transport = round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			idx := int(calls.Add(1)) - 1
			if idx >= len(responses) {
				idx = len(responses) - 1
			}
			r := responses[idx]
			return newRound63JSONResponse(req, r.httpStatus, nil, r.body), nil
		})
		err := sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true)
		return int(calls.Load()), err
	}

	// Attempt 1 returning Label Already Exists (even VISIBLE) must fail.
	if calls, err := runLabelCase("attempt1_visible", []struct {
		httpStatus int
		body       string
	}{
		{http.StatusOK, `{"Status":"Label Already Exists","ExistingJobStatus":"VISIBLE"}`},
	}); err == nil || calls != 1 {
		t.Fatalf("attempt1_visible: expected immediate failure on attempt 1, calls=%d err=%v", calls, err)
	}

	// Attempt 2 returning VISIBLE or COMMITTED succeeds.
	for _, st := range []string{"VISIBLE", "COMMITTED"} {
		calls, err := runLabelCase("attempt2_"+st, []struct {
			httpStatus int
			body       string
		}{
			{http.StatusServiceUnavailable, "busy"},
			{http.StatusOK, fmt.Sprintf(`{"Status":"Label Already Exists","ExistingJobStatus":%q}`, st)},
		})
		if err != nil || calls != 2 {
			t.Fatalf("attempt2_%s: expected nil err and 2 calls, got calls=%d err=%v", st, calls, err)
		}
	}

	// Attempt 2 PREPARE retries and succeeds when attempt 3 returns VISIBLE.
	if calls, err := runLabelCase("prepare_then_visible", []struct {
		httpStatus int
		body       string
	}{
		{http.StatusServiceUnavailable, "busy"},
		{http.StatusOK, `{"Status":"Label Already Exists","ExistingJobStatus":"PREPARE","Message":"still running"}`},
		{http.StatusOK, `{"Status":"Label Already Exists","ExistingJobStatus":"VISIBLE"}`},
	}); err != nil || calls != 3 {
		t.Fatalf("prepare_then_visible: expected retry success at attempt 3, got calls=%d err=%v", calls, err)
	}

	// Attempt 2 ABORTED fails immediately without silent success or extra retry.
	if calls, err := runLabelCase("aborted", []struct {
		httpStatus int
		body       string
	}{
		{http.StatusServiceUnavailable, "busy"},
		{http.StatusOK, `{"Status":"Label Already Exists","ExistingJobStatus":"ABORTED","Message":"txn aborted"}`},
	}); err == nil || calls != 2 || !strings.Contains(err.Error(), "ABORTED") {
		t.Fatalf("aborted: expected immediate failure mentioning ABORTED, calls=%d err=%v", calls, err)
	}

	// Attempt 2/3 stuck in RUNNING or empty ExistingJobStatus must fail rather than silent data loss.
	for _, st := range []string{"RUNNING", ""} {
		calls, err := runLabelCase("stuck_"+st, []struct {
			httpStatus int
			body       string
		}{
			{http.StatusServiceUnavailable, "busy"},
			{http.StatusOK, fmt.Sprintf(`{"Status":"Label Already Exists","ExistingJobStatus":%q,"Message":"pending"}`, st)},
			{http.StatusOK, fmt.Sprintf(`{"Status":"Label Already Exists","ExistingJobStatus":%q,"Message":"pending"}`, st)},
		})
		if err == nil || calls != 3 {
			t.Fatalf("stuck_%q: expected failure after maxAttempts=3, calls=%d err=%v", st, calls, err)
		}
	}
}

func TestRound64_Infra_NormalizeDorisSQLArrayLambdaFallbackTypes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "bare_col_cast_double",
			in:   "SELECT * FROM `es`.`t` WHERE array_exists(_x -> CAST(_x AS DOUBLE) > 10.5, `f__prices`)",
			want: "SELECT * FROM `es`.`t` WHERE array_contains(array_exists(_x -> CAST(_x AS DOUBLE) > 10.5, IFNULL(`f__prices`, CAST([] AS ARRAY<DOUBLE>))), true)",
		},
		{
			name: "bare_col_try_cast_bigint",
			in:   "SELECT * FROM `es`.`t` WHERE array_exists(_x -> TRY_CAST(_x AS BIGINT) >= 42, `f__counts`)",
			want: "SELECT * FROM `es`.`t` WHERE array_contains(array_exists(_x -> TRY_CAST(_x AS BIGINT) >= 42, IFNULL(`f__counts`, CAST([] AS ARRAY<BIGINT>))), true)",
		},
		{
			name: "bare_col_cast_boolean",
			in:   "SELECT * FROM `es`.`t` WHERE array_exists(_x -> CAST(_x AS BOOLEAN) = true, `f__flags`)",
			want: "SELECT * FROM `es`.`t` WHERE array_contains(array_exists(_x -> CAST(_x AS BOOLEAN) = true, IFNULL(`f__flags`, CAST([] AS ARRAY<BOOLEAN>))), true)",
		},
		{
			name: "bare_col_cast_datetimev2_3",
			in:   "SELECT * FROM `es`.`t` WHERE array_exists(_x -> CAST(_x AS DATETIMEV2(3)) >= '2026-01-01 00:00:00', `f__dates`)",
			want: "SELECT * FROM `es`.`t` WHERE array_contains(array_exists(_x -> CAST(_x AS DATETIMEV2(3)) >= '2026-01-01 00:00:00', IFNULL(`f__dates`, CAST([] AS ARRAY<DATETIMEV2(3)>))), true)",
		},
		{
			name: "bare_col_custom_lambda_param",
			in:   "SELECT * FROM `es`.`t` WHERE array_exists(el -> TRY_CAST(el AS FLOAT) < 1.5, `f__weights`)",
			want: "SELECT * FROM `es`.`t` WHERE array_contains(array_exists(el -> TRY_CAST(el AS FLOAT) < 1.5, IFNULL(`f__weights`, CAST([] AS ARRAY<FLOAT>))), true)",
		},
		{
			name: "nested_json_element_extract_stays_array_string",
			in:   "SELECT * FROM `es`.`t` WHERE array_exists(_el -> CAST(json_extract_string(_el, '$.price') AS DOUBLE) > 10.5, `n__items`)",
			want: "SELECT * FROM `es`.`t` WHERE array_contains(array_exists(_el -> CAST(json_extract_string(_el, '$.price') AS DOUBLE) > 10.5, IFNULL(`n__items`, CAST([] AS ARRAY<STRING>))), true)",
		},
		{
			name: "explicit_array_string_cast_not_overridden_by_lambda",
			in:   "SELECT * FROM `es`.`t` WHERE array_exists(_x -> CAST(_x AS DOUBLE) > 10.5, CAST(`_doc`['prices'] AS ARRAY<STRING>))",
			want: "SELECT * FROM `es`.`t` WHERE array_contains(array_exists(_x -> CAST(_x AS DOUBLE) > 10.5, IFNULL(CAST(`_doc`['prices'] AS ARRAY<STRING>), CAST([] AS ARRAY<STRING>))), true)",
		},
		{
			name: "case_when_runtime_array_string_stays_array_string",
			in:   "SELECT * FROM `es`.`t` WHERE array_exists(_x -> TRY_CAST(_x AS DOUBLE) > 10.5, CASE WHEN json_extract_string(`_source`, '$.\"p\"') IS NULL THEN NULL WHEN JSON_TYPE(`_source`, '$.\"p\"') = 'ARRAY' THEN TRY_CAST(json_extract_string(`_source`, '$.\"p\"') AS ARRAY<STRING>) ELSE [json_extract_string(`_source`, '$.\"p\"')] END)",
			want: "SELECT * FROM `es`.`t` WHERE array_contains(array_exists(_x -> TRY_CAST(_x AS DOUBLE) > 10.5, IFNULL(CASE WHEN json_extract_string(`_source`, '$.\"p\"') IS NULL THEN NULL WHEN JSON_TYPE(`_source`, '$.\"p\"') = 'ARRAY' THEN TRY_CAST(json_extract_string(`_source`, '$.\"p\"') AS ARRAY<STRING>) ELSE [json_extract_string(`_source`, '$.\"p\"')] END, CAST([] AS ARRAY<STRING>))), true)",
		},
		{
			name: "quoted_cast_in_string_literal_ignored",
			in:   "SELECT * FROM `es`.`t` WHERE array_exists(_x -> _x = 'CAST(_x AS DOUBLE)', `f__tags`)",
			want: "SELECT * FROM `es`.`t` WHERE array_contains(array_exists(_x -> _x = 'CAST(_x AS DOUBLE)', IFNULL(`f__tags`, CAST([] AS ARRAY<STRING>))), true)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeDorisSQL(tc.in)
			if got != tc.want {
				t.Fatalf("NormalizeDorisSQL mismatch:\n got: %s\nwant: %s", got, tc.want)
			}
			if again := NormalizeDorisSQL(got); again != tc.want {
				t.Fatalf("NormalizeDorisSQL not idempotent:\n got: %s\nwant: %s", again, tc.want)
			}
		})
	}
}

func TestRound64_Infra_LaunchAsyncTaskPanicRecovery(t *testing.T) {
	t.Parallel()

	srv := NewServer("es_r64_task_panic", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	// 1. Unexpected string panic inside async worker must mark task completed with internal_server_error.
	req := httptest.NewRequest(http.MethodPost, "/_reindex?wait_for_completion=false", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	srv.launchAsyncTaskRound60(rec, req, []byte(`{}`), "indices:data/write/reindex", "panic-test", -1, func(http.ResponseWriter, *http.Request) {
		panic("boom\nsecond-line")
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK task launch response, got %d: %s", rec.Code, rec.Body.String())
	}
	var launchResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &launchResp); err != nil {
		t.Fatalf("unmarshal launch response failed: %v", err)
	}
	taskID, _ := launchResp["task"].(string)
	if taskID == "" {
		t.Fatalf("missing task ID in launch response: %+v", launchResp)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/_tasks/"+taskID+"?wait_for_completion=true&timeout=5s", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /_tasks/%s failed: %d %s", taskID, getRec.Code, getRec.Body.String())
	}
	var taskResp map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &taskResp); err != nil {
		t.Fatalf("unmarshal task response failed: %v", err)
	}
	if taskResp["completed"] != true {
		t.Fatalf("expected recovered panic task completed=true, got %+v", taskResp)
	}
	errObj, ok := taskResp["error"].(map[string]any)
	if !ok || errObj["type"] != "internal_server_error" {
		t.Fatalf("expected internal_server_error in task error payload, got %+v", taskResp["error"])
	}
	reason, _ := errObj["reason"].(string)
	if !strings.Contains(reason, "boom") || strings.ContainsAny(reason, "\r\n") {
		t.Fatalf("expected sanitized single-line panic reason containing 'boom', got %q", reason)
	}

	// 2. panic(nil) (Go 1.21+ *runtime.PanicNilError) is also recovered cleanly.
	reqNil := httptest.NewRequest(http.MethodPost, "/_reindex?wait_for_completion=false", strings.NewReader(`{}`))
	recNil := httptest.NewRecorder()
	srv.launchAsyncTaskRound60(recNil, reqNil, []byte(`{}`), "indices:data/write/reindex", "panic-nil-test", -1, func(http.ResponseWriter, *http.Request) {
		panic(nil) //nolint:govet // intentional nil panic recovery test
	})
	var launchNil map[string]any
	_ = json.Unmarshal(recNil.Body.Bytes(), &launchNil)
	nilTaskID, _ := launchNil["task"].(string)

	getNilReq := httptest.NewRequest(http.MethodGet, "/_tasks/"+nilTaskID+"?wait_for_completion=true&timeout=5s", nil)
	getNilRec := httptest.NewRecorder()
	h.ServeHTTP(getNilRec, getNilReq)
	var nilTaskResp map[string]any
	_ = json.Unmarshal(getNilRec.Body.Bytes(), &nilTaskResp)
	if nilTaskResp["completed"] != true {
		t.Fatalf("expected panic(nil) recovered task completed=true, got %+v", nilTaskResp)
	}
	if errMap, _ := nilTaskResp["error"].(map[string]any); errMap["type"] != "internal_server_error" {
		t.Fatalf("expected internal_server_error for panic(nil), got %+v", nilTaskResp["error"])
	}
}

func TestRound64_Infra_ShardRequestCacheByteBudgetAndCap(t *testing.T) {
	t.Parallel()

	srv := NewServer("es_r64_cache", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	t.Cleanup(func() { _ = srv.Close(context.Background()) })

	store := srv.getOrCreateShardRequestCacheR63()
	store.mu.RLock()
	defMaxSize := store.maxSize
	defMaxBytes := store.maxBytes
	defMaxEntryBytes := store.maxEntryBytes
	store.mu.RUnlock()
	if defMaxSize != 512 || defMaxBytes != 64<<20 || defMaxEntryBytes != 1<<20 {
		t.Fatalf("unexpected cache defaults: maxSize=%d maxBytes=%d maxEntryBytes=%d", defMaxSize, defMaxBytes, defMaxEntryBytes)
	}

	// 1. Default >1 MiB per-entry payload must be rejected without evicting existing entries.
	srv.storeAndRecordShardRequestCacheMissR63("small_keep", []string{"idx_a"}, map[string]any{"ok": true}, nil)
	hugePayload := map[string]any{"blob": strings.Repeat("a", (1<<20)+128)}
	srv.storeAndRecordShardRequestCacheMissR63("too_big", []string{"idx_a"}, hugePayload, nil)
	if _, _, ok := srv.lookupShardRequestCacheR63("too_big"); ok {
		t.Fatalf("expected >1 MiB entry not to be cached")
	}
	if _, _, ok := srv.lookupShardRequestCacheR63("small_keep"); !ok {
		t.Fatalf("expected existing entry not to be evicted by rejected >1 MiB entry")
	}

	// Updating an existing key with an oversized payload removes the stale entry.
	srv.storeAndRecordShardRequestCacheMissR63("small_keep", []string{"idx_a"}, hugePayload, nil)
	if _, _, ok := srv.lookupShardRequestCacheR63("small_keep"); ok {
		t.Fatalf("expected stale small_keep entry to be removed when overwritten by >1 MiB payload")
	}
	store.mu.RLock()
	tbAfterReset := store.totalBytes
	store.mu.RUnlock()
	if tbAfterReset != 0 {
		t.Fatalf("expected totalBytes=0 after oversized overwrite removed small_keep, got %d", tbAfterReset)
	}

	// 2. Bounded total byte budget (default 64 MiB) evicts oldest entries cleanly.
	chunk960K := map[string]any{"v": strings.Repeat("z", 960<<10)}
	for i := 0; i < 70; i++ {
		srv.storeAndRecordShardRequestCacheMissR63(fmt.Sprintf("big64m_%d", i), []string{"idx_64m"}, chunk960K, nil)
	}
	_, _, ev64, mem64 := srv.getShardRequestCacheStatsR63("idx_64m")
	store.mu.RLock()
	tb64 := store.totalBytes
	store.mu.RUnlock()
	if ev64 < 1 || mem64 > 64<<20 || tb64 > 64<<20 {
		t.Fatalf("expected 64 MiB budget eviction, got evicts=%d mem64=%d totalBytes=%d", ev64, mem64, tb64)
	}
	srv.clearShardRequestCacheEntriesR63([]string{"idx_64m"})

	// 3. Deterministic LRU byte eviction with small budget (200 bytes, ~83-byte entries).
	store.mu.Lock()
	store.maxBytes = 200
	store.maxEntryBytes = 150
	store.mu.Unlock()

	p83 := map[string]any{"v": strings.Repeat("x", 75)} // {"v":"..."} = 83 bytes
	srv.storeAndRecordShardRequestCacheMissR63("k1", []string{"idx_b"}, p83, nil)
	srv.storeAndRecordShardRequestCacheMissR63("k2", []string{"idx_b"}, p83, nil)

	// Touch k1 so k2 becomes the LRU victim.
	if _, _, ok := srv.lookupShardRequestCacheR63("k1"); !ok {
		t.Fatalf("expected k1 cache hit")
	}
	// Inserting k3 pushes totalBytes (249) over 200, so LRU k2 is evicted while k1 & k3 remain.
	srv.storeAndRecordShardRequestCacheMissR63("k3", []string{"idx_b"}, p83, nil)

	if _, _, ok := srv.lookupShardRequestCacheR63("k2"); ok {
		t.Fatalf("expected LRU k2 to be evicted on byte budget pressure")
	}
	if _, _, ok := srv.lookupShardRequestCacheR63("k1"); !ok {
		t.Fatalf("expected recently accessed k1 to remain in cache")
	}
	if _, _, ok := srv.lookupShardRequestCacheR63("k3"); !ok {
		t.Fatalf("expected newly inserted k3 to be in cache")
	}
	_, _, evicts, memBytes := srv.getShardRequestCacheStatsR63("idx_b")
	if evicts < 1 || memBytes <= 0 || memBytes > 200 {
		t.Fatalf("unexpected cache stats after byte eviction: evicts=%d memBytes=%d", evicts, memBytes)
	}

	store.mu.RLock()
	tb := store.totalBytes
	store.mu.RUnlock()
	if tb > 200 || tb != memBytes {
		t.Fatalf("totalBytes=%d inconsistent with maxBytes=200 / memBytes=%d", tb, memBytes)
	}

	// Clearing specific target updates totalBytes cleanly.
	srv.clearShardRequestCacheEntriesR63([]string{"idx_b"})
	store.mu.RLock()
	tbCleared := store.totalBytes
	store.mu.RUnlock()
	if tbCleared != 0 {
		t.Fatalf("expected totalBytes=0 after clearShardRequestCacheEntriesR63, got %d", tbCleared)
	}
}

var (
	reFuzzOneArgJSONType  = regexp.MustCompile(`(?i)\bJSON_TYPE\s*\(`)
	reFuzzMatchPredicate  = regexp.MustCompile(`(?i)\bMATCH_(ALL|ANY|PHRASE|PHRASE_PREFIX)\b`)
	reFuzzFromBaseMatched = regexp.MustCompile("(?i)\\bFROM\\s+`?base_matched`?")
)

func hasOneArgJSONTypeR64(sqlStr string) bool {
	inSingle, inDouble, inBacktick := false, false, false
	for i := 0; i < len(sqlStr); {
		ch := sqlStr[i]
		if inSingle {
			if ch == '\\' && i+1 < len(sqlStr) {
				i += 2
				continue
			}
			if ch == '\'' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '\'' {
					i += 2
					continue
				}
				inSingle = false
			}
			i++
			continue
		}
		if inDouble {
			if ch == '\\' && i+1 < len(sqlStr) {
				i += 2
				continue
			}
			if ch == '"' {
				inDouble = false
			}
			i++
			continue
		}
		if inBacktick {
			if ch == '`' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '`' {
					i += 2
					continue
				}
				inBacktick = false
			}
			i++
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
			i++
			continue
		case '"':
			inDouble = true
			i++
			continue
		case '`':
			inBacktick = true
			i++
			continue
		}

		loc := reFuzzOneArgJSONType.FindStringIndex(sqlStr[i:])
		if loc == nil || loc[0] != 0 {
			i++
			continue
		}
		openIdx := i + loc[1] - 1
		depth := 1
		topCommas := 0
		qS, qD, qB := false, false, false
		j := openIdx + 1
		for j < len(sqlStr) && depth > 0 {
			c := sqlStr[j]
			if qS {
				if c == '\\' && j+1 < len(sqlStr) {
					j += 2
					continue
				}
				if c == '\'' {
					if j+1 < len(sqlStr) && sqlStr[j+1] == '\'' {
						j += 2
						continue
					}
					qS = false
				}
			} else if qD {
				if c == '\\' && j+1 < len(sqlStr) {
					j += 2
					continue
				}
				if c == '"' {
					qD = false
				}
			} else if qB {
				if c == '`' {
					if j+1 < len(sqlStr) && sqlStr[j+1] == '`' {
						j += 2
						continue
					}
					qB = false
				}
			} else {
				switch c {
				case '\'':
					qS = true
				case '"':
					qD = true
				case '`':
					qB = true
				case '(':
					depth++
				case ')':
					depth--
				case ',':
					if depth == 1 {
						topCommas++
					}
				}
			}
			j++
		}
		if depth == 0 && topCommas == 0 {
			return true
		}
		i = openIdx + 1
	}
	return false
}

func hasMatchInFromBaseMatchedR64(sqlStr string) bool {
	locs := reFuzzFromBaseMatched.FindAllStringIndex(sqlStr, -1)
	for _, loc := range locs {
		tail := sqlStr[loc[1]:]
		// Scan the enclosing SELECT segment up to UNION ALL or closing paren at depth 0.
		depth := 0
		inS, inD, inB := false, false, false
		end := len(tail)
		for i := 0; i < len(tail); i++ {
			c := tail[i]
			if inS {
				if c == '\\' && i+1 < len(tail) {
					i++
					continue
				}
				if c == '\'' {
					if i+1 < len(tail) && tail[i+1] == '\'' {
						i++
						continue
					}
					inS = false
				}
				continue
			}
			if inD {
				if c == '\\' && i+1 < len(tail) {
					i++
					continue
				}
				if c == '"' {
					inD = false
				}
				continue
			}
			if inB {
				if c == '`' {
					if i+1 < len(tail) && tail[i+1] == '`' {
						i++
						continue
					}
					inB = false
				}
				continue
			}
			switch c {
			case '\'':
				inS = true
			case '"':
				inD = true
			case '`':
				inB = true
			case '(':
				depth++
			case ')':
				if depth == 0 {
					end = i
					goto checkSeg
				}
				depth--
			}
		}
	checkSeg:
		seg := stripQuotedSQLSegmentsR64(tail[:end])
		if reFuzzMatchPredicate.MatchString(seg) {
			return true
		}
	}
	return false
}

func stripQuotedSQLSegmentsR64(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inS, inD, inB := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inS {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inS = false
			}
			continue
		}
		if inD {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '"' {
				inD = false
			}
			continue
		}
		if inB {
			if c == '`' {
				if i+1 < len(s) && s[i+1] == '`' {
					i++
					continue
				}
				inB = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
			b.WriteByte(' ')
		case '"':
			inD = true
			b.WriteByte(' ')
		case '`':
			inB = true
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isBalancedBackticksAndParensR64(sqlStr string) bool {
	inS, inD, inB := false, false, false
	parenDepth := 0
	for i := 0; i < len(sqlStr); i++ {
		c := sqlStr[i]
		if inS {
			if c == '\\' && i+1 < len(sqlStr) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '\'' {
					i++
					continue
				}
				inS = false
			}
			continue
		}
		if inD {
			if c == '\\' && i+1 < len(sqlStr) {
				i++
				continue
			}
			if c == '"' {
				inD = false
			}
			continue
		}
		if inB {
			if c == '`' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '`' {
					i++
					continue
				}
				inB = false
			}
			continue
		}
		switch c {
		case '\'':
			inS = true
		case '"':
			inD = true
		case '`':
			inB = true
		case '(':
			parenDepth++
		case ')':
			parenDepth--
			if parenDepth < 0 {
				return false
			}
		}
	}
	return !inS && !inD && !inB && parenDepth == 0
}

func sanitizeIdentForFuzzSQLR64(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 32; i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "f__col"
	}
	return b.String()
}

func sanitizeSingleQuotedForFuzzSQLR64(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	return s
}

func FuzzNormalizeDorisSQL(f *testing.F) {
	f.Add("SELECT * FROM `es`.`t` WHERE `__DORIS_DELETE_SIGN__` = 0 AND array_exists(_x -> CAST(_x AS DOUBLE) > 1.5, `f__prices`)", "f__prices", uint8(0), "ok")
	f.Add("SELECT * FROM `es`.`t` WHERE array_exists(_x -> TRY_CAST(_x AS BIGINT) >= 10, `f__ids`)", "f__counts", uint8(1), "a\x1fb")
	f.Add("WITH `base_matched` AS (SELECT * FROM `es`.`t` WHERE `__DORIS_DELETE_SIGN__` = 0 AND `f__msg` MATCH_ANY 'hello') SELECT COUNT(*) FROM `base_matched` WHERE JSON_TYPE(`_source`, '$.tags') = 'ARRAY' AND array_exists(_x -> CAST(_x AS BOOLEAN) = true, `f__flags`)", "f__flags", uint8(2), `test\x1f_vals:`)
	f.Add("SELECT `weird``array_exists(a,b)` FROM `es`.`t` WHERE array_exists(_el -> json_extract_string(_el, '$.name') = 'x', `n__items`)", "f__dates", uint8(3), "it's (ok)")

	castTypes := []string{"DOUBLE", "BIGINT", "BOOLEAN", "DATETIMEV2(3)", "FLOAT", "LARGEINT", "INT", "STRING"}

	f.Fuzz(func(t *testing.T, rawSQL, colName string, typeIdx uint8, litVal string) {
		// 1. Arbitrary input must never panic and must preserve invariants when valid on entry.
		normRaw := NormalizeDorisSQL(rawSQL)
		if isBalancedBackticksAndParensR64(rawSQL) && !hasOneArgJSONTypeR64(rawSQL) && !hasMatchInFromBaseMatchedR64(rawSQL) {
			if !isBalancedBackticksAndParensR64(normRaw) {
				t.Fatalf("NormalizeDorisSQL unbalanced backticks/parens:\n in:  %q\n out: %q", rawSQL, normRaw)
			}
			if hasOneArgJSONTypeR64(normRaw) {
				t.Fatalf("NormalizeDorisSQL introduced 1-arg JSON_TYPE:\n in:  %q\n out: %q", rawSQL, normRaw)
			}
			if hasMatchInFromBaseMatchedR64(normRaw) {
				t.Fatalf("NormalizeDorisSQL introduced MATCH_* inside FROM base_matched:\n in:  %q\n out: %q", rawSQL, normRaw)
			}
		}

		// 2. Structured Doris CTE + array_exists + unit-sep SQL generation.
		col := sanitizeIdentForFuzzSQLR64(colName)
		castTy := castTypes[int(typeIdx)%len(castTypes)]
		safeLit := sanitizeSingleQuotedForFuzzSQLR64(litVal)
		structured := fmt.Sprintf(
			"WITH `base_matched` AS (SELECT * FROM `es`.`tbl` WHERE `__DORIS_DELETE_SIGN__` = 0 AND `f__title` MATCH_ANY '%s') "+
				"SELECT CONCAT(`_id`, '\x1f_vals:', '%s') FROM `base_matched` "+
				"WHERE JSON_TYPE(`_source`, '$.%s') != 'NULL' AND array_exists(_x -> TRY_CAST(_x AS %s) IS NOT NULL, `%s`)",
			safeLit, safeLit, col, castTy, col,
		)
		normStruct := NormalizeDorisSQL(structured)
		if !isBalancedBackticksAndParensR64(normStruct) {
			t.Fatalf("structured NormalizeDorisSQL unbalanced backticks/parens:\n%s", normStruct)
		}
		if hasOneArgJSONTypeR64(normStruct) {
			t.Fatalf("structured NormalizeDorisSQL contains 1-arg JSON_TYPE:\n%s", normStruct)
		}
		if hasMatchInFromBaseMatchedR64(normStruct) {
			t.Fatalf("structured NormalizeDorisSQL contains MATCH_* inside FROM base_matched:\n%s", normStruct)
		}
		if again := NormalizeDorisSQL(normStruct); again != normStruct {
			t.Fatalf("structured NormalizeDorisSQL not idempotent:\nfirst:  %s\nsecond: %s", normStruct, again)
		}
	})
}

func FuzzStreamLoadRedirect(f *testing.F) {
	f.Add("https://doris-fe.prod.example.com:8030", "https://169.254.169.254/api/es/t/_stream_load", "doris-be.prod.example.com", "root", "secret")
	f.Add("https://doris-fe.prod.example.com:8030", "https://[::ffff:169.254.169.254]:8040/api/es/t/_stream_load", "", "root", "secret")
	f.Add("https://doris-fe.prod.example.com:8030", "https://[fe80::1]:8040/api/es/t/_stream_load", "", "root", "secret")
	f.Add("https://doris-fe.prod.example.com:8030", "https://[fd00:ec2::254]:8040/api/es/t/_stream_load", "", "root", "secret")
	f.Add("https://doris-fe.prod.example.com:8030", "http://doris-be.prod.example.com:8040/api/es/t/_stream_load", "doris-be.prod.example.com", "root", "secret")
	f.Add("https://doris-fe.prod.example.com:8030", "https://evil:pw@doris-be.prod.example.com:8040/api/es/t/_stream_load", "doris-be.prod.example.com", "root", "secret")
	f.Add("https://doris-fe.prod.example.com:8030", "https://127.0.0.1:8040/api/es/t/_stream_load", "127.0.0.1", "root", "secret")
	f.Add("https://doris-fe.prod.example.com:8030", "https://[::ffff:127.0.0.1]:8040/api/es/t/_stream_load", "", "root", "secret")
	f.Add("https://doris-fe.prod.example.com:8030", "https://metadata.google.internal/api/es/t/_stream_load", "metadata.google.internal", "root", "secret")
	f.Add("https://doris-fe.prod.example.com:8030", "https://doris-be.prod.example.com:8040/api/admin", "doris-be.prod.example.com", "root", "secret")
	f.Add("https://doris-fe.prod.example.com:8030", "https://doris-be.prod.example.com:8040/api/es/t/_stream_load", "doris-be.prod.example.com", "root", "secret")
	f.Add("http://127.0.0.1:8030", "http://127.0.0.1:8040/api/es/t/_stream_load", "", "root", "secret")

	f.Fuzz(func(t *testing.T, feEndpoint, redirectTarget, allowHost, user, pass string) {
		sl := NewStreamLoadClient(StreamLoadConfig{
			FEHTTPEndpoint: feEndpoint,
			User:           user,
			Password:       pass,
			Database:       "es_compat",
			Timeout:        time.Second,
		})
		if tr, ok := sl.httpClient.Transport.(*http.Transport); !ok || tr.Proxy != nil {
			t.Fatalf("expected non-nil *http.Transport with Proxy == nil")
		}
		if allowHost != "" {
			sl.AllowBEHosts([]string{allowHost})
		}

		feURL, feErr := sl.parseConfiguredFEURL()
		reqURL, urlErr := url.Parse(redirectTarget)
		if urlErr != nil || reqURL == nil || reqURL.Scheme == "" {
			return
		}
		// Never panic on validateStreamLoadTargetURL / validateCachedBEBaseURL / DialContext IP checks.
		_ = sl.validateStreamLoadTargetURL(reqURL)
		_ = sl.validateCachedBEBaseURL(redirectTarget)

		initReq, err := http.NewRequest(http.MethodPut, "https://doris-fe.prod.example.com:8030/api/es/t/_stream_load", nil)
		if err != nil {
			return
		}
		initReq.SetBasicAuth(user, pass)
		redirReq := &http.Request{
			Method: http.MethodPut,
			URL:    reqURL,
			Header: make(http.Header),
		}
		redirReq.Header.Set("Authorization", initReq.Header.Get("Authorization"))

		checkErr := sl.checkStreamLoadRedirect(redirReq, []*http.Request{initReq})
		if checkErr != nil {
			if redirReq.Header.Get("Authorization") != "" {
				t.Fatalf("rejected redirect %q still carried Authorization header", redirectTarget)
			}
			return
		}
		if feErr != nil {
			t.Fatalf("checkStreamLoadRedirect succeeded with invalid FE endpoint %q", feEndpoint)
		}
		if redirReq.URL.User != nil {
			t.Fatalf("accepted redirect %q retained embedded URL userinfo", redirectTarget)
		}
		if isBlockedStreamLoadHost(redirReq.URL.Hostname()) {
			t.Fatalf("accepted redirect to blocked host %q", redirectTarget)
		}
		if strings.EqualFold(feURL.Scheme, "https") && !strings.EqualFold(redirReq.URL.Scheme, "https") {
			t.Fatalf("accepted HTTPS->%s scheme downgrade to %q", redirReq.URL.Scheme, redirectTarget)
		}
		if !isLoopbackStreamLoadHost(feURL.Hostname()) && isLoopbackStreamLoadHost(redirReq.URL.Hostname()) {
			t.Fatalf("non-loopback FE %q accepted loopback redirect %q", feEndpoint, redirectTarget)
		}
		if !strings.HasSuffix(redirReq.URL.Path, "/_stream_load") {
			if redirReq.Header.Get("Authorization") != "" {
				t.Fatalf("non-stream-load redirect %q retained Authorization", redirectTarget)
			}
			if !isLoopbackStreamLoadHost(feURL.Hostname()) || !isLoopbackStreamLoadHost(redirReq.URL.Hostname()) {
				t.Fatalf("non-loopback FE %q accepted non-stream-load redirect %q", feEndpoint, redirectTarget)
			}
		}

		// Also assert DialContext blocks loopback resolution when FE is non-loopback.
		if !isLoopbackStreamLoadHost(feURL.Hostname()) {
			sl.lookupNetIP = func(_ context.Context, _, _ string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}, nil
			}
			tr := sl.httpClient.Transport.(*http.Transport)
			conn, dialErr := tr.DialContext(context.Background(), "tcp", "rebind.invalid:8040")
			if conn != nil {
				_ = conn.Close()
			}
			if dialErr == nil || !strings.Contains(dialErr.Error(), "loopback") {
				t.Fatalf("expected DialContext to reject mapped loopback IPv6 for non-loopback FE, got %v", dialErr)
			}
		}
	})
}
