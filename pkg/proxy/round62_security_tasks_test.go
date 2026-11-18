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
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound62RemoteReindexStaticWhitelistAndIPv6(t *testing.T) {
	t.Parallel()
	srv := NewServer("es_r62_sec", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	h := srv.Handler()

	// 1. IsStaticOnlyClusterSettingRound62 & ValidateDynamicClusterSettingsSectionRound62
	if !IsStaticOnlyClusterSettingRound62("reindex.remote.whitelist") ||
		!IsStaticOnlyClusterSettingRound62("reindex.remote.whitelist.extra") ||
		IsStaticOnlyClusterSettingRound62("action.auto_create_index") {
		t.Fatalf("unexpected IsStaticOnlyClusterSettingRound62 classification")
	}
	if st, et, _ := ValidateDynamicClusterSettingsSectionRound62("transient", map[string]any{
		"reindex.remote.whitelist": "evil.internal:9200",
	}); st != http.StatusBadRequest || et != "illegal_argument_exception" {
		t.Fatalf("expected 400 illegal_argument_exception on flat static setting, got %d %s", st, et)
	}
	if st, et, _ := ValidateDynamicClusterSettingsSectionRound62("persistent", map[string]any{
		"reindex": map[string]any{"remote": map[string]any{"whitelist": "evil.internal:9200"}},
	}); st != http.StatusBadRequest || et != "illegal_argument_exception" {
		t.Fatalf("expected 400 illegal_argument_exception on nested static setting, got %d %s", st, et)
	}

	// 2. Dynamic cluster settings MUST be ignored by validateReindexRemoteWhitelistRound60
	srv.mu.Lock()
	srv.clusterTransientSettings["reindex.remote.whitelist"] = "evil.internal:9200"
	srv.clusterPersistentSettings["reindex.remote.whitelist"] = "evil.internal:9200"
	srv.mu.Unlock()

	rec, _ := doRound61Req(t, h, http.MethodPost, "/_reindex",
		`{"source":{"remote":{"host":"http://evil.internal:9200"},"index":"src"},"dest":{"index":"dst"}}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "[evil.internal:9200] not whitelisted") {
		t.Fatalf("expected dynamic cluster setting whitelist to be ignored, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3. IPv6 host without explicit port must format as `[::1]:80` / `[::1]:443` (never `[[::1]]:80`)
	st, _, er := srv.validateReindexRemoteWhitelistRound60(map[string]any{"host": "http://[::1]"})
	if st != http.StatusBadRequest || strings.Contains(er, "[[::1]]") || !strings.Contains(er, "[[::1]:80]") {
		t.Fatalf("expected IPv6 default port message with [[::1]:80] and no double brackets, got st=%d er=%q", st, er)
	}

	srv.SetStaticRemoteReindexWhitelist("[::1]:80, [::1]:443, remote.allowed.example:9200")
	if st, _, er := srv.validateReindexRemoteWhitelistRound60(map[string]any{"host": "http://[::1]"}); st != 0 {
		t.Fatalf("expected http://[::1] to match static whitelist [::1]:80, got %d %q", st, er)
	}
	if st, _, er := srv.validateReindexRemoteWhitelistRound60(map[string]any{"host": "https://[::1]"}); st != 0 {
		t.Fatalf("expected https://[::1] to match static whitelist [::1]:443, got %d %q", st, er)
	}
}

func TestRound62RemoteReindexSSRFPostDNSDialerAndGuards(t *testing.T) {
	t.Parallel()
	srv := NewServer("es_r62_ssrf", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	h := srv.Handler()
	srv.SetStaticRemoteReindexWhitelist("*:*")

	// 1. Reject URL userinfo and non-root path segments in remote.host
	for _, badHost := range []string{
		"http://admin:secret@remote.example.com:9200",
		"https://token@remote.example.com:9200",
		"http://remote.example.com:9200/latest/meta-data/",
		"http://remote.example.com:9200/v1/../admin",
	} {
		rec, _ := doRound61Req(t, h, http.MethodPost, "/_reindex",
			fmt.Sprintf(`{"source":{"remote":{"host":%q},"index":"src"},"dest":{"index":"dst"}}`, badHost), nil)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "illegal_argument_exception") {
			t.Fatalf("expected 400 illegal_argument_exception for remote.host=%q, got %d: %s", badHost, rec.Code, rec.Body.String())
		}
	}

	// 2. Timeout cap (<= 60s), DisableKeepAlives: true, Proxy: nil
	client, cleanup := srv.buildRemoteReindexHTTPClientRound61(map[string]any{
		"connect_timeout": "300s",
		"socket_timeout":  "600s",
	})
	defer cleanup()
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport when custom RoundTripper is nil, got %T", client.Transport)
	}
	if !tr.DisableKeepAlives || tr.Proxy != nil {
		t.Fatalf("expected DisableKeepAlives=true and Proxy=nil, got DisableKeepAlives=%v Proxy=%v", tr.DisableKeepAlives, tr.Proxy != nil)
	}
	if tr.TLSHandshakeTimeout != maxRemoteReindexTimeout || tr.ResponseHeaderTimeout != maxRemoteReindexTimeout {
		t.Fatalf("expected connect/socket timeouts capped to %s, got tls=%s hdr=%s",
			maxRemoteReindexTimeout, tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout)
	}

	// 3. Post-DNS DialContext blocks loopback, RFC1918, IMDS, CGNAT, IPv4-mapped IPv6, and DNS rebinding!
	var resolvedCount atomic.Int32
	srv.setRemoteReindexLookupNetIPForTestRound62(func(_ context.Context, _, host string) ([]netip.Addr, error) {
		resolvedCount.Add(1)
		switch host {
		case "imds.rebind.example":
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		case "mapped-v6.rebind.example":
			return []netip.Addr{netip.MustParseAddr("::ffff:127.0.0.1")}, nil
		case "cgnat.rebind.example":
			return []netip.Addr{netip.MustParseAddr("100.64.42.9")}, nil
		case "dual-record.rebind.example":
			return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.5")}, nil
		default:
			return nil, fmt.Errorf("unexpected host %s", host)
		}
	})
	defer srv.setRemoteReindexLookupNetIPForTestRound62(nil)

	blockedTargets := []string{
		"http://127.0.0.1:9200",
		"http://[::1]:9200",
		"http://[::ffff:127.0.0.1]:9200",
		"http://169.254.169.254:80",
		"http://10.1.2.3:9200",
		"http://172.16.5.4:9200",
		"http://192.168.1.10:9200",
		"http://100.64.1.2:9200",
		"http://0.0.0.1:9200",
		"http://[fd00::1]:9200",
		"http://imds.rebind.example:80",
		"http://mapped-v6.rebind.example:9200",
		"http://cgnat.rebind.example:9200",
		"http://dual-record.rebind.example:9200",
	}
	for _, target := range blockedTargets {
		rec, _ := doRound61Req(t, h, http.MethodPost, "/_reindex",
			fmt.Sprintf(`{"source":{"remote":{"host":%q},"index":"src"},"dest":{"index":"dst"}}`, target), nil)
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "connect_exception") {
			t.Fatalf("expected 500 connect_exception for SSRF target %s, got %d: %s", target, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "connection refused") || strings.Contains(rec.Body.String(), "i/o timeout") {
			t.Fatalf("expected sanitized connect_exception without raw OS port-scan error for %s, got: %s", target, rec.Body.String())
		}
	}
	if resolvedCount.Load() < 4 {
		t.Fatalf("expected post-DNS resolver to be invoked for hostname targets, got %d", resolvedCount.Load())
	}

	// 4. Explicit SetRemoteReindexAllowPrivateIPs(true) permits loopback httptest.Server
	remoteCluster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete && r.URL.Path == "/_search/scroll" {
			_, _ = w.Write([]byte(`{"succeeded":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"_scroll_id":"s1","hits":{"hits":[{"_id":"1","_version":1,"_source":{"k":"v"}}]}}`))
	}))
	defer remoteCluster.Close()

	// Blocked while allowPrivateIPs == false
	rec, _ := doRound61Req(t, h, http.MethodPost, "/_reindex",
		fmt.Sprintf(`{"source":{"remote":{"host":%q},"index":"src"},"dest":{"index":"dst_priv"}}`, remoteCluster.URL), nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected loopback httptest server blocked when allowPrivateIPs=false, got %d: %s", rec.Code, rec.Body.String())
	}

	// Allowed once allowPrivateIPs == true
	srv.SetRemoteReindexAllowPrivateIPs(true)
	defer srv.SetRemoteReindexAllowPrivateIPs(false)
	uLocal, _ := url.Parse(remoteCluster.URL)
	srv.SetStaticRemoteReindexWhitelist(uLocal.Host)
	rec, resp := doRound61Req(t, h, http.MethodPost, "/_reindex",
		fmt.Sprintf(`{"source":{"remote":{"host":%q},"index":"src"},"dest":{"index":"dst_priv"}}`, remoteCluster.URL), nil)
	if rec.Code != http.StatusOK || fmt.Sprintf("%v", resp["created"]) != "1" {
		t.Fatalf("expected remote reindex to succeed with allowPrivateIPs=true, got %d: %s", rec.Code, rec.Body.String())
	}

	// 5. Block hop-by-hop & protected header overrides in source.remote.headers
	srv.SetStaticRemoteReindexWhitelist("headers.allowed.example:9200")
	var capturedHdr http.Header
	var capturedHost string
	srv.SetRemoteReindexTransport(roundTripperFuncRound61(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/src/_search" {
			capturedHdr = req.Header.Clone()
			capturedHost = req.Host
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"_scroll_id":"","hits":{"hits":[]}}`)),
		}, nil
	}))
	defer srv.SetRemoteReindexTransport(nil)

	rec, _ = doRound61Req(t, h, http.MethodPost, "/_reindex", `{
		"source": {
			"remote": {
				"host": "http://headers.allowed.example:9200",
				"username": "elastic",
				"password": "goodpassword",
				"headers": {
					"Host": "evil.internal",
					"Authorization": "Bearer attacker-token",
					"Content-Length": "999999",
					"Transfer-Encoding": "chunked",
					"Connection": "keep-alive, Upgrade",
					"Upgrade": "websocket",
					"Proxy-Authorization": "Basic ZXZpbA==",
					"Te": "trailers",
					"Trailer": "X-Injected",
					"X-Safe-Custom": "allowed-value"
				}
			},
			"index": "src"
		},
		"dest": {"index": "dst_hdr"}
	}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with disallowed headers stripped, got %d: %s", rec.Code, rec.Body.String())
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("elastic:goodpassword"))
	if capturedHdr.Get("Authorization") != wantAuth {
		t.Fatalf("expected Basic Auth preserved (%q), got %q", wantAuth, capturedHdr.Get("Authorization"))
	}
	if capturedHost != "headers.allowed.example:9200" || capturedHdr.Get("Host") != "" {
		t.Fatalf("expected Host header override blocked, got req.Host=%q Header[Host]=%q", capturedHost, capturedHdr.Get("Host"))
	}
	for _, forbidden := range []string{"Content-Length", "Transfer-Encoding", "Connection", "Upgrade", "Proxy-Authorization", "Te", "Trailer"} {
		if v := capturedHdr.Get(forbidden); v != "" {
			t.Fatalf("expected header %s blocked, got %q", forbidden, v)
		}
	}
	if capturedHdr.Get("X-Safe-Custom") != "allowed-value" {
		t.Fatalf("expected X-Safe-Custom header forwarded, got %q", capturedHdr.Get("X-Safe-Custom"))
	}
}

// ---------- Mock SQL driver for chunked GetDocsByIDs (>4,096 IDs) verification ----------

type round62BatchMockDriver struct {
	mu        sync.Mutex
	queries   []string
	argCounts []int
	docsByID  map[string]string
}

func (d *round62BatchMockDriver) Open(_ string) (driver.Conn, error) {
	return &round62BatchMockConn{drv: d}, nil
}

type round62BatchMockConn struct {
	drv *round62BatchMockDriver
}

func (c *round62BatchMockConn) Prepare(_ string) (driver.Stmt, error) {
	return nil, fmt.Errorf("unexpected Prepare")
}
func (c *round62BatchMockConn) Close() error              { return nil }
func (c *round62BatchMockConn) Begin() (driver.Tx, error) { return nil, fmt.Errorf("unexpected Begin") }

func (c *round62BatchMockConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if len(args) > getDocsBatchChunkSize {
		return nil, fmt.Errorf("MySQL Error 1390: prepared statement contains too many placeholders (%d > %d)", len(args), getDocsBatchChunkSize)
	}
	c.drv.mu.Lock()
	c.drv.queries = append(c.drv.queries, query)
	c.drv.argCounts = append(c.drv.argCounts, len(args))
	c.drv.mu.Unlock()

	var rows [][]driver.Value
	for _, nv := range args {
		id := fmt.Sprintf("%v", nv.Value)
		if src, ok := c.drv.docsByID[id]; ok {
			rows = append(rows, []driver.Value{id, int64(2), src, src, int64(0)})
		}
	}
	return &round62BatchMockRows{
		cols: []string{"_id", "_version", "_source", "_raw_doc", "__DORIS_DELETE_SIGN__"},
		rows: rows,
	}, nil
}

type round62BatchMockRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *round62BatchMockRows) Columns() []string { return r.cols }
func (r *round62BatchMockRows) Close() error      { return nil }
func (r *round62BatchMockRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.idx])
	r.idx++
	return nil
}

var (
	round62MockDriverOnce sync.Once
	round62SharedMockDrv  = &round62BatchMockDriver{docsByID: make(map[string]string)}
)

func TestRound62SQLBackendHardening(t *testing.T) {
	// 1. P0 Doris 4.1.3 CHAR(31) normalization for standalone '\x1f' AND '\x1f_vals:'
	cases := []struct {
		in   string
		want string
	}{
		{
			in:   `SELECT CONCAT(a, '\x1f', b) FROM t`,
			want: `SELECT CONCAT(a, CHAR(31), b) FROM t`,
		},
		{
			in:   "SELECT CONCAT(a, '\x1f', b) FROM t",
			want: "SELECT CONCAT(a, CHAR(31), b) FROM t",
		},
		{
			in:   `SELECT CONCAT(CAST(k AS STRING), '\x1f_vals:', COALESCE(v, '')) FROM t`,
			want: `SELECT CONCAT(CAST(k AS STRING), CONCAT(CHAR(31), '_vals:'), COALESCE(v, '')) FROM t`,
		},
		{
			in:   "SELECT CONCAT(CAST(k AS STRING), '\x1f_vals:', COALESCE(v, '')) FROM t",
			want: `SELECT CONCAT(CAST(k AS STRING), CONCAT(CHAR(31), '_vals:'), COALESCE(v, '')) FROM t`,
		},
		{
			in:   "SELECT * FROM t WHERE `_bucket_key` > 'checkout\x1fprod'",
			want: "SELECT * FROM t WHERE `_bucket_key` > CONCAT('checkout', CHAR(31), 'prod')",
		},
		{
			in:   "SELECT * FROM t WHERE tag = '0x1f00'",
			want: "SELECT * FROM t WHERE tag = '0x1f00'",
		},
	}
	for _, tc := range cases {
		if got := NormalizeDorisSQL(tc.in); got != tc.want {
			t.Fatalf("NormalizeDorisSQL(%q):\n got: %s\nwant: %s", tc.in, got, tc.want)
		}
	}

	// 2. ApplyDSNAuth strips multiStatements=true
	dsn := ApplyDSNAuth("root:@tcp(127.0.0.1:9030)/?interpolateParams=true&multiStatements=true&timeout=5s", "doris_u", "doris_p")
	if strings.Contains(strings.ToLower(dsn), "multistatements=true") {
		t.Fatalf("expected ApplyDSNAuth to strip multiStatements=true, got %q", dsn)
	}
	rawMalformedDSN := ApplyDSNAuth("://unparseable?multiStatements=true&timeout=5s", "", "")
	if strings.Contains(strings.ToLower(rawMalformedDSN), "multistatements") {
		t.Fatalf("expected fallback stripRawDSNMultiStatements to remove multiStatements, got %q", rawMalformedDSN)
	}

	// 3. Backtick escaping on dorisDB / table identifiers
	safeIdent := sanitizeAndEscapeDorisIdent("bad`db;DROP TABLE x")
	if strings.Contains(safeIdent, ";") || (strings.Contains(safeIdent, "`") && !strings.Contains(safeIdent, "``")) {
		t.Fatalf("unexpected sanitizeAndEscapeDorisIdent output: %q", safeIdent)
	}

	// 4. Chunked GetDocsByIDs (>4,096 IDs split into chunks of 4,096)
	round62MockDriverOnce.Do(func() {
		sql.Register("doris_r62_batch_mock", round62SharedMockDrv)
	})
	round62SharedMockDrv.mu.Lock()
	round62SharedMockDrv.queries = nil
	round62SharedMockDrv.argCounts = nil
	round62SharedMockDrv.docsByID = map[string]string{
		"doc-0":    `{"seq":0}`,
		"doc-4096": `{"seq":4096}`,
		"doc-8999": `{"seq":8999}`,
	}
	round62SharedMockDrv.mu.Unlock()

	db, err := sql.Open("doris_r62_batch_mock", "mock")
	if err != nil {
		t.Fatalf("sql.Open mock failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	sqlBackend := NewDorisSQLBackend(db, nil)
	ids := make([]string, 9000)
	for i := range ids {
		ids[i] = fmt.Sprintf("doc-%d", i)
	}
	gotDocs, err := sqlBackend.GetDocsByIDs(context.Background(), "es_db", "orders", ids)
	if err != nil {
		t.Fatalf("GetDocsByIDs(9000 IDs) failed: %v", err)
	}
	if len(gotDocs) != 3 || string(gotDocs["doc-8999"].Source) != `{"seq":8999}` {
		t.Fatalf("expected 3 matched docs across chunks, got %d: %+v", len(gotDocs), gotDocs)
	}
	round62SharedMockDrv.mu.Lock()
	counts := append([]int(nil), round62SharedMockDrv.argCounts...)
	round62SharedMockDrv.mu.Unlock()
	if len(counts) != 3 || counts[0] != 4096 || counts[1] != 4096 || counts[2] != 808 {
		t.Fatalf("expected chunk sizes [4096, 4096, 808], got %v", counts)
	}
}

func TestRound62TasksPainlessByQueryAndIngestTail(t *testing.T) {
	t.Parallel()
	srv := NewServer("es_r62_tail", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	h := srv.Handler()

	// 1. F24: painless/71_context_api.yml (`?context=score` query parameter)
	reqCtx := httptest.NewRequest(http.MethodGet, "/_scripts/painless/_context?context=score", nil)
	recCtx := httptest.NewRecorder()
	srv.handlePainlessContextDetailRound61(recCtx, reqCtx)
	if recCtx.Code != http.StatusOK || !strings.Contains(recCtx.Body.String(), `"name":"score"`) {
		t.Fatalf("expected 200 score context payload for ?context=score, got %d: %s", recCtx.Code, recCtx.Body.String())
	}

	// 2. F25.2: delete_by_query/20_validation.yml preflight order (stored_fields/from/_source=false BEFORE query is missing)
	for _, tc := range []struct {
		url      string
		body     string
		wantText string
	}{
		{"/test/_delete_by_query", `{"stored_fields":["_id"]}`, "stored_fields is not supported in this context"},
		{"/test/_delete_by_query", `{"from":5}`, "from is not supported in this context"},
		{"/test/_delete_by_query", `{"_source":false}`, "_source:false is not supported in this context"},
		{"/test/_delete_by_query?stored_fields=_id", ``, "stored_fields is not supported in this context"},
		{"/test/_delete_by_query", ``, "Required [body]"},
		{"/test/_delete_by_query", `{}`, "query is missing"},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.url, nil)
		rec := httptest.NewRecorder()
		_, _, _, _, st, _, er := srv.validateByQueryPreflightWithWarningsRound61(rec, req, []byte(tc.body), true)
		if st != http.StatusBadRequest || !strings.Contains(er, tc.wantText) {
			t.Fatalf("DBQ preflight (%s, %s): expected 400 containing %q, got st=%d er=%q", tc.url, tc.body, tc.wantText, st, er)
		}
	}

	// 3. F25.3: Remote reindex unknown field key order `[weird,badkey]` & malformed `source.query`
	rec, _ := doRound61Req(t, h, http.MethodPost, "/_reindex",
		`{"source":{"remote":{"host":"http://okremote:9200","weird":"stuff","badkey":"is bad"},"index":"test"},"dest":{"index":"dest"}}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Unsupported fields in [remote]: [weird,badkey]") {
		t.Fatalf("expected exact JSON key order [weird,badkey], got %d: %s", rec.Code, rec.Body.String())
	}
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_reindex",
		`{"source":{"remote":{"host":"http://okremote:9200","badkey":"is bad","weird":"stuff"},"index":"test"},"dest":{"index":"dest"}}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Unsupported fields in [remote]: [badkey,weird]") {
		t.Fatalf("expected exact JSON key order [badkey,weird], got %d: %s", rec.Code, rec.Body.String())
	}

	srv.SetStaticRemoteReindexWhitelist("okremote:9200")
	rec, _ = doRound61Req(t, h, http.MethodPost, "/_reindex",
		`{"source":{"remote":{"host":"http://okremote:9200"},"index":"source","query":{"garbage":"not a query"}},"dest":{"index":"dest"}}`, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "query malformed, no start_object after query name") {
		t.Fatalf("expected query malformed, no start_object after query name, got %d: %s", rec.Code, rec.Body.String())
	}

	// 4. F1: `.tasks` system index deprecation warning on `POST /_refresh` (`rawIndex == ""`) once async task completes
	recBefore, _ := doRound61Req(t, h, http.MethodPost, "/_refresh", "", nil)
	if strings.Contains(strings.Join(recBefore.Header().Values("Warning"), " "), ".tasks") {
		t.Fatalf("did not expect .tasks warning before any persisted task record exists")
	}
	doneTask := srv.getTaskRegistry().register("indices:data/write/delete/byquery", "dbq test", -1, nil, func() {})
	doneTask.markDone(map[string]any{"total": 1, "deleted": 1}, nil)

	recES7Refresh := httptest.NewRecorder()
	reqES7Refresh := httptest.NewRequest(http.MethodPost, "/_refresh", nil)
	srv.emitSystemIndexTasksWarningIfNeededRound61(recES7Refresh, reqES7Refresh, []string{"test", ""})
	if !strings.Contains(strings.Join(recES7Refresh.Header().Values("Warning"), " "), "this request accesses system indices: [.tasks]") {
		t.Fatalf("expected .tasks deprecation warning on all-indices refresh in ES7 mode, got %v", recES7Refresh.Header().Values("Warning"))
	}

	// 5. F25.5: Ingest residual tail (`?summary=true` omits `description`, cyclic ctx error reason, bulk upsert fail 500, empty `?pipeline=`, drop version -3)
	sumMap := summarizeIngestPipelineMapRound61(map[string]any{
		"description": "first",
		"version":     int64(3),
		"_meta":       map[string]any{"owner": "ingest"},
		"processors":  []any{},
	})
	if _, hasDesc := sumMap["description"]; hasDesc || sumMap["version"] != int64(3) {
		t.Fatalf("expected summarizeIngestPipelineMapRound61 to omit description and keep version/_meta, got %#v", sumMap)
	}

	_, _ = doRound61Req(t, h, http.MethodPut, "/_ingest/pipeline/my_cyclic_pipe", `{
		"processors": [{"script": {"ignore_failure": true, "source": "Map m = new HashMap(); m.self = m; ctx.foo = m;"}}]
	}`, nil)
	_, cycSt, cycET, cycER := srv.applyWritePipelinesFullRound61("test", "1", "my_cyclic_pipe", "", "", json.RawMessage(`{"foo":"bar"}`), false)
	wantCyc := "Failed to generate the source document for ingest pipeline [my_cyclic_pipe] for document [test/1]"
	if cycSt != http.StatusBadRequest || cycET != "illegal_argument_exception" || cycER != wantCyc {
		t.Fatalf("unexpected cyclic source ingest error: st=%d et=%s er=%q (want %q)", cycSt, cycET, cycER, wantCyc)
	}

	srvES8 := NewServer("es_r62_es8", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	srvES8.SetTargetESVersion("8.15.5")
	_, _ = doRound61Req(t, srvES8.Handler(), http.MethodPut, "/_ingest/pipeline/my_fail_pipe", `{
		"processors": [{"fail": {"message": "error-message"}}]
	}`, nil)
	_, failUpSt, failUpET, _ := srvES8.applyBulkUpsertIngestRound61("test", "3", "my_fail_pipe", "", json.RawMessage(`{"some":"fields"}`), false)
	if failUpSt != http.StatusInternalServerError || failUpET != "fail_processor_exception" {
		t.Fatalf("expected 500 fail_processor_exception on bulk upsert fail processor, got st=%d et=%s", failUpSt, failUpET)
	}

	reqEmptyPipe := httptest.NewRequest(http.MethodPut, "/test/_doc/10?pipeline=", nil)
	if pSt, pET, _ := ValidateExplicitPipelineParamRound62(reqEmptyPipe); pSt != http.StatusBadRequest || pET != "illegal_argument_exception" {
		t.Fatalf("expected 400 illegal_argument_exception for empty ?pipeline=, got %d %s", pSt, pET)
	}
	if BulkUpsertDropVersionRound62() != -3 {
		t.Fatalf("expected BulkUpsertDropVersionRound62() == -3")
	}

	// Ensure unused net import is exercised via IPv6 JoinHostPort sanity check
	if got := net.JoinHostPort("::1", "80"); got != "[::1]:80" {
		t.Fatalf("unexpected JoinHostPort: %s", got)
	}
}
