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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

type round63RoundTripFunc func(*http.Request) (*http.Response, error)

func (f round63RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newRound63JSONResponse(req *http.Request, status int, headers map[string]string, body string) *http.Response {
	hdr := make(http.Header, len(headers))
	for k, v := range headers {
		hdr.Set(k, v)
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     hdr,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

type round63SQLQuerySpec struct {
	cols []string
	rows [][]driver.Value
	err  error
}

type round63MockSQLDriver struct {
	mu       sync.RWMutex
	handlers map[string]func(query string, args []driver.NamedValue) round63SQLQueryResult
}

type round63SQLQueryResult = round63SQLQuerySpec

var (
	round63SQLDriverOnce sync.Once
	round63SQLDriverInst = &round63MockSQLDriver{
		handlers: make(map[string]func(query string, args []driver.NamedValue) round63SQLQueryResult),
	}
)

func openRound63MockDB(t *testing.T, fn func(query string, args []driver.NamedValue) round63SQLQueryResult) *sql.DB {
	t.Helper()
	round63SQLDriverOnce.Do(func() {
		sql.Register("round63_sqlbackend_mock", round63SQLDriverInst)
	})
	dsn := fmt.Sprintf("%s_%d", t.Name(), time.Now().UnixNano())
	round63SQLDriverInst.mu.Lock()
	round63SQLDriverInst.handlers[dsn] = fn
	round63SQLDriverInst.mu.Unlock()
	t.Cleanup(func() {
		round63SQLDriverInst.mu.Lock()
		delete(round63SQLDriverInst.handlers, dsn)
		round63SQLDriverInst.mu.Unlock()
	})
	db, err := sql.Open("round63_sqlbackend_mock", dsn)
	if err != nil {
		t.Fatalf("sql.Open mock failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (d *round63MockSQLDriver) Open(name string) (driver.Conn, error) {
	return &round63MockSQLConn{dsn: name, drv: d}, nil
}

type round63MockSQLConn struct {
	dsn string
	drv *round63MockSQLDriver
}

func (c *round63MockSQLConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *round63MockSQLConn) Close() error                        { return nil }
func (c *round63MockSQLConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (c *round63MockSQLConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.drv.mu.RLock()
	fn := c.drv.handlers[c.dsn]
	c.drv.mu.RUnlock()
	if fn == nil {
		return nil, fmt.Errorf("missing mock SQL handler for %q", c.dsn)
	}
	res := fn(query, args)
	if res.err != nil {
		return nil, res.err
	}
	return &round63MockSQLRows{cols: res.cols, rows: res.rows}, nil
}

type round63MockSQLRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *round63MockSQLRows) Columns() []string { return r.cols }
func (r *round63MockSQLRows) Close() error      { return nil }
func (r *round63MockSQLRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	row := r.rows[r.idx]
	r.idx++
	for i := range dest {
		if i < len(row) {
			dest[i] = row[i]
		} else {
			dest[i] = nil
		}
	}
	return nil
}

func TestRound63_StreamLoadClient_HTTPSDowngradeRejected(t *testing.T) {
	t.Parallel()

	var httpDowngradeHits atomic.Int32
	var errorDowngradeHits atomic.Int32

	sl := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "https://127.0.0.1:8030",
		User:           "root",
		Password:       "s3cr3t",
		Database:       "es_compat",
		Timeout:        2 * time.Second,
	})

	mode := "downgrade_redirect"
	rt := round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme == "http" {
			if strings.Contains(req.URL.Path, "_load_error") {
				errorDowngradeHits.Add(1)
			} else {
				httpDowngradeHits.Add(1)
			}
			return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success"}`), nil
		}
		switch mode {
		case "downgrade_redirect":
			return newRound63JSONResponse(req, http.StatusTemporaryRedirect, map[string]string{
				"Location": "http://127.0.0.1:8040" + req.URL.Path,
			}, ""), nil
		case "error_url_downgrade":
			return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Fail","Message":"bad row","ErrorURL":"http://127.0.0.1:8040/api/_load_error_log?file=err_1"}`), nil
		case "https_be_redirect":
			if req.URL.Host == "127.0.0.1:8030" {
				return newRound63JSONResponse(req, http.StatusTemporaryRedirect, map[string]string{
					"Location": "https://127.0.0.1:8040" + req.URL.Path,
				}, ""), nil
			}
			if !strings.HasPrefix(req.Header.Get("Authorization"), "Basic ") {
				t.Errorf("expected Basic Auth on https BE redirect, got %q", req.Header.Get("Authorization"))
			}
			return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1}`), nil
		default:
			return nil, fmt.Errorf("unexpected mode %s", mode)
		}
	})
	sl.httpClient.Transport = rt
	sl.errHTTPClient.Transport = rt

	// 1. HTTPS -> HTTP redirect must be rejected before issuing any cleartext HTTP request.
	err := sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true)
	if err == nil || !strings.Contains(err.Error(), "scheme downgrade") {
		t.Fatalf("expected scheme downgrade error, got %v", err)
	}
	if httpDowngradeHits.Load() != 0 {
		t.Fatalf("expected 0 cleartext HTTP requests on downgrade redirect, got %d", httpDowngradeHits.Load())
	}

	// 2. Poisoned cleartext cachedBEBase must be discarded when FEHTTPEndpoint is https://.
	sl.cachedBEBase.Store("http://127.0.0.1:8040")
	mode = "https_be_redirect"
	if err := sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("expected valid https->https redirect to succeed after discarding http cachedBEBase, got %v", err)
	}
	if httpDowngradeHits.Load() != 0 {
		t.Fatalf("expected poisoned http cachedBEBase not to be dialed, got %d hits", httpDowngradeHits.Load())
	}
	if cached, _ := sl.cachedBEBase.Load().(string); cached != "https://127.0.0.1:8040" {
		t.Fatalf("cachedBEBase = %q, want https://127.0.0.1:8040", cached)
	}

	// 3. ErrorURL with http:// when FE is https:// must never be fetched.
	sl.cachedBEBase.Store("")
	mode = "error_url_downgrade"
	err = sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true)
	if err == nil || errorDowngradeHits.Load() != 0 {
		t.Fatalf("expected error without fetching http ErrorURL, err=%v hits=%d", err, errorDowngradeHits.Load())
	}
}

func TestRound63_StreamLoadClient_SSRFMetadataAndUntrustedHostBlocking(t *testing.T) {
	t.Parallel()

	blockedRedirects := []string{
		"https://169.254.169.254/api/es_compat/orders/_stream_load",
		"https://[::ffff:169.254.169.254]:8040/api/es_compat/orders/_stream_load",
		"https://[fe80::1]:8040/api/es_compat/orders/_stream_load",
		"https://[fd00:ec2::254]:8040/api/es_compat/orders/_stream_load",
		"https://metadata.google.internal/api/es_compat/orders/_stream_load",
		"https://evil.attacker.example:8040/api/es_compat/orders/_stream_load",
		"https://127.0.0.1:8040/api/es_compat/orders/_stream_load",
		"https://10.0.1.11:8040/api/es_compat/orders/_stream_load",
		"https://doris-fe.prod.example.com:8030/api/admin/secret",
	}

	for _, redirectTarget := range blockedRedirects {
		var targetContacted atomic.Int32
		sl := NewStreamLoadClient(StreamLoadConfig{
			FEHTTPEndpoint: "https://doris-fe.prod.example.com:8030",
			User:           "root",
			Password:       "top_secret",
			Database:       "es_compat",
			Timeout:        2 * time.Second,
		})
		// Attempt to register IMDS/loopback into AllowBEHosts must be ignored.
		sl.AllowBEHosts([]string{"169.254.169.254", "::ffff:169.254.169.254", "fe80::1", "fd00:ec2::254", "127.0.0.1", "localhost"})

		rt := round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "doris-fe.prod.example.com:8030" && strings.HasSuffix(req.URL.Path, "/_stream_load") {
				return newRound63JSONResponse(req, http.StatusTemporaryRedirect, map[string]string{
					"Location": redirectTarget,
				}, ""), nil
			}
			targetContacted.Add(1)
			return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success"}`), nil
		})
		sl.httpClient.Transport = rt
		sl.errHTTPClient.Transport = rt

		err := sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true)
		if err == nil {
			t.Fatalf("expected redirect to %q to be blocked, but LoadNDJSON succeeded", redirectTarget)
		}
		if targetContacted.Load() != 0 {
			t.Fatalf("redirect target %q was contacted %d times (Authorization exfiltration risk)", redirectTarget, targetContacted.Load())
		}
	}

	// Once SHOW BACKENDS populates AllowBEHosts with real Doris BE host, redirect succeeds and preserves BasicAuth.
	slAllowed := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "https://doris-fe.prod.example.com:8030",
		User:           "doris_ingest",
		Password:       "ingest_pw",
		Database:       "es_compat",
		Timeout:        2 * time.Second,
	})
	slAllowed.AllowBEHosts([]string{"doris-be-01.prod.example.com", "10.24.8.15"})

	var gotBEAuth string
	rtAllowed := round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "doris-fe.prod.example.com:8030" {
			return newRound63JSONResponse(req, http.StatusTemporaryRedirect, map[string]string{
				"Location": "https://doris-be-01.prod.example.com:8040" + req.URL.Path,
			}, ""), nil
		}
		if req.URL.Host == "doris-be-01.prod.example.com:8040" {
			gotBEAuth = req.Header.Get("Authorization")
			return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1}`), nil
		}
		return nil, fmt.Errorf("unexpected host %s", req.URL.Host)
	})
	slAllowed.httpClient.Transport = rtAllowed
	if err := slAllowed.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("expected allowlisted BE redirect to succeed, got %v", err)
	}
	if !strings.HasPrefix(gotBEAuth, "Basic ") {
		t.Fatalf("expected Basic Auth forwarded to allowlisted BE, got %q", gotBEAuth)
	}

	// Private VPC FE (10.0.1.10) allows RFC1918 BE (10.0.1.11) before SHOW BACKENDS,
	// while still blocking IMDS (169.254.169.254), loopback (127.0.0.1), and public IPs (93.184.216.34).
	slVPC := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "http://10.0.1.10:8030",
		User:           "root",
		Password:       "vpc_pw",
		Database:       "es_compat",
		Timeout:        2 * time.Second,
	})
	vpcTarget := "http://10.0.1.11:8040"
	slVPC.httpClient.Transport = round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "10.0.1.10:8030" {
			return newRound63JSONResponse(req, http.StatusTemporaryRedirect, map[string]string{
				"Location": vpcTarget + req.URL.Path,
			}, ""), nil
		}
		return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1}`), nil
	})
	if err := slVPC.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("expected RFC1918 FE -> RFC1918 BE bootstrap redirect to succeed, got %v", err)
	}
	for _, badTarget := range []string{"http://169.254.169.254", "http://127.0.0.1:8040", "http://93.184.216.34:8040"} {
		slVPC.cachedBEBase.Store("")
		vpcTarget = badTarget
		if err := slVPC.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true); err == nil {
			t.Fatalf("expected RFC1918 FE -> %s redirect to fail", badTarget)
		}
	}
}

func TestRound63_StreamLoadClient_ErrorURLValidationAndSanitization(t *testing.T) {
	t.Parallel()

	var redirTargetHits atomic.Int32
	redirTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirTargetHits.Add(1)
		_, _ = w.Write([]byte("SECRET_IMDS_TOKEN"))
	}))
	defer redirTarget.Close()

	mode := "control_chars_and_long"
	var errSrv *httptest.Server
	errSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/_load_error_log":
			switch mode {
			case "control_chars_and_long":
				_, _ = w.Write([]byte("Reason: invalid ARRAY<STRING>\r\nrow 1:\x00\x07 bad\tvalue " + strings.Repeat("x", 700)))
			case "html_page":
				_, _ = w.Write([]byte("<!DOCTYPE html><html><body><h1>502 Bad Gateway</h1></body></html>"))
			case "redirect_302":
				http.Redirect(w, r, redirTarget.URL+"/api/_load_error_log", http.StatusFound)
			}
		case "/api/not_error_path":
			redirTargetHits.Add(1)
			_, _ = w.Write([]byte("SHOULD_NOT_BE_FETCHED"))
		default:
			w.Header().Set("Content-Type", "application/json")
			errURL := errSrv.URL + "/api/_load_error_log"
			switch mode {
			case "bad_path":
				errURL = errSrv.URL + "/api/not_error_path"
			case "imds_url":
				errURL = "http://169.254.169.254/api/_load_error_log"
			}
			_ = json.NewEncoder(w).Encode(streamLoadResponse{
				Status:   "Fail",
				Message:  "stream load failed",
				ErrorURL: errURL,
			})
		}
	}))
	defer errSrv.Close()

	sl := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: errSrv.URL,
		User:           "root",
		Password:       "pw",
		Database:       "es_compat",
		Timeout:        3 * time.Second,
	})

	// 1. Control chars stripped, ARRAY<STRING> preserved, capped <= 512 UTF-8 bytes.
	err := sl.LoadNDJSON(context.Background(), "tbl", []byte(`{"_id":"1"}`+"\n"), true)
	if err == nil {
		t.Fatal("expected stream load error")
	}
	if strings.ContainsAny(err.Error(), "\r\n\x00\x07") {
		t.Fatalf("expected control chars stripped from error detail: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "Reason: invalid ARRAY<STRING> row 1: bad value") {
		t.Fatalf("expected sanitized detail in error, got: %s", err.Error())
	}
	detailIdx := strings.Index(err.Error(), "detail=")
	if detailIdx < 0 {
		t.Fatalf("missing detail= in %s", err.Error())
	}
	detailPart := strings.TrimSuffix(err.Error()[detailIdx+len("detail="):], ")")
	if len(detailPart) > maxStreamLoadErrorDetailBytes || !utf8.ValidString(detailPart) {
		t.Fatalf("detail length = %d (validUTF8=%v), want <= %d", len(detailPart), utf8.ValidString(detailPart), maxStreamLoadErrorDetailBytes)
	}

	// 2. HTML error pages are stripped to empty string.
	mode = "html_page"
	err = sl.LoadNDJSON(context.Background(), "tbl", []byte(`{"_id":"1"}`+"\n"), true)
	if err == nil || strings.Contains(strings.ToLower(err.Error()), "<html") || !strings.HasSuffix(err.Error(), "detail=)") {
		t.Fatalf("expected HTML ErrorURL body to be stripped to empty detail, got: %v", err)
	}

	// 3. 302 redirect on ErrorURL is NOT followed (ErrUseLastResponse).
	mode = "redirect_302"
	err = sl.LoadNDJSON(context.Background(), "tbl", []byte(`{"_id":"1"}`+"\n"), true)
	if err == nil || redirTargetHits.Load() != 0 || strings.Contains(err.Error(), "SECRET_IMDS_TOKEN") {
		t.Fatalf("expected ErrorURL redirect not to be followed, hits=%d err=%v", redirTargetHits.Load(), err)
	}

	// 4. Non-_load_error path and IMDS host are never fetched.
	for _, m := range []string{"bad_path", "imds_url"} {
		mode = m
		err = sl.LoadNDJSON(context.Background(), "tbl", []byte(`{"_id":"1"}`+"\n"), true)
		if err == nil || redirTargetHits.Load() != 0 || !strings.HasSuffix(err.Error(), "detail=)") {
			t.Fatalf("mode %s: expected ErrorURL not fetched, hits=%d err=%v", m, redirTargetHits.Load(), err)
		}
	}
}

func TestRound63_NormalizeDorisSQL_EscapedBackticksAndArrayTypes(t *testing.T) {
	t.Parallel()

	// C-15: Escaped double-backticks in outer query and inside array_exists arguments.
	qEscaped := "SELECT `weird``array_exists(a, b)` FROM `db`.`t` WHERE array_exists(_x -> _x = 'ok', `f__col``with,comma)`) AND `other``col` = 1"
	gotEscaped := NormalizeDorisSQL(qEscaped)
	if !strings.Contains(gotEscaped, "SELECT `weird``array_exists(a, b)` FROM `db`.`t`") {
		t.Fatalf("outer escaped double-backtick corrupted: %s", gotEscaped)
	}
	if !strings.Contains(gotEscaped, "array_contains(array_exists(_x -> _x = 'ok', IFNULL(`f__col``with,comma)`, CAST([] AS ARRAY<STRING>))), true)") {
		t.Fatalf("inner escaped double-backtick inside array_exists corrupted: %s", gotEscaped)
	}

	// Array fallback type detection for ARRAY<FLOAT>, ARRAY<BOOLEAN>, ARRAY<DATETIMEV2(3)>, ARRAY<LARGEINT>.
	typeCases := []struct {
		inSQL    string
		wantCast string
	}{
		{
			inSQL:    "SELECT * FROM t WHERE array_exists(_x -> _x > 0.5, CAST(`_doc`['vec'] AS ARRAY<FLOAT>))",
			wantCast: "CAST([] AS ARRAY<FLOAT>)",
		},
		{
			inSQL:    "SELECT * FROM t WHERE array_exists(_x -> _x > 0.5, array_map(_x -> CAST(_x AS FLOAT), `f__vec`))",
			wantCast: "CAST([] AS ARRAY<FLOAT>)",
		},
		{
			inSQL:    "SELECT * FROM t WHERE array_exists(_x -> _x = true, CAST(`_doc`['flags'] AS ARRAY<BOOLEAN>))",
			wantCast: "CAST([] AS ARRAY<BOOLEAN>)",
		},
		{
			inSQL:    "SELECT * FROM t WHERE array_exists(_x -> _x = true, array_map(_x -> CAST(_x AS BOOLEAN), `f__flags`))",
			wantCast: "CAST([] AS ARRAY<BOOLEAN>)",
		},
		{
			inSQL:    "SELECT * FROM t WHERE array_exists(_x -> _x IS NOT NULL, CAST(`_doc`['dates'] AS ARRAY<DATETIMEV2(3)>))",
			wantCast: "CAST([] AS ARRAY<DATETIMEV2(3)>)",
		},
		{
			inSQL:    "SELECT * FROM t WHERE array_exists(_x -> _x > 1, array_map(_x -> CAST(_x AS DATETIMEV2(3)), `f__dates`))",
			wantCast: "CAST([] AS ARRAY<DATETIMEV2(3)>)",
		},
	}
	for _, tc := range typeCases {
		got := NormalizeDorisSQL(tc.inSQL)
		if !strings.Contains(got, tc.wantCast) {
			t.Errorf("NormalizeDorisSQL(%s) = %s, missing %s", tc.inSQL, got, tc.wantCast)
		}
	}
}

func TestRound63_DorisSQLBackend_RoutingProjectionFallbackAndBEAllowlist(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// 1. Full schema table (with `_doc` and `_routing`) for GetDocByID, GetDocsByIDs, and QueryHits
	// across standard, search_after, collapse, and multi-index UNION ALL queries.
	var recordedQueries []string
	var recMu sync.Mutex
	dbFull := openRound63MockDB(t, func(query string, _ []driver.NamedValue) round63SQLQueryResult {
		recMu.Lock()
		recordedQueries = append(recordedQueries, query)
		recMu.Unlock()
		switch {
		case strings.Contains(query, "SHOW BACKENDS"):
			return round63SQLQueryResult{
				cols: []string{"BackendId", "Host", "HttpPort", "Alive"},
				rows: [][]driver.Value{
					{"1001", "10.42.0.11", "8040", "true"},
					{"1002", "doris-be-2.internal", "8040", "true"},
				},
			}
		case strings.Contains(query, "WHERE `_id` = ?"):
			return round63SQLQueryResult{
				cols: []string{"_id", "_version", "_source", "_raw_doc", "_routing", "__DORIS_DELETE_SIGN__"},
				rows: [][]driver.Value{
					{"doc-1", int64(3), `{"k":"v"}`, `{"k":"v","extra":1}`, "tenant-a", int64(0)},
				},
			}
		case strings.Contains(query, "WHERE `_id` IN"):
			return round63SQLQueryResult{
				cols: []string{"_id", "_version", "_source", "_raw_doc", "_routing", "__DORIS_DELETE_SIGN__"},
				rows: [][]driver.Value{
					{"doc-1", int64(1), `{"k":"old"}`, `{"k":"old"}`, "old-route", int64(0)},
					{"doc-1", int64(4), `{"k":"new"}`, `{"k":"new"}`, "tenant-b", int64(0)},
					{"doc-del", int64(2), `{}`, `{}`, "tenant-del", int64(1)},
				},
			}
		default:
			return round63SQLQueryResult{
				cols: []string{"_id", "_version", "_source", "_raw_doc", "_routing", "_score", "_total_hits"},
				rows: [][]driver.Value{
					{"doc-1", int64(4), `{"k":"new"}`, `{"k":"new","dyn":true}`, "shard-route-7", float64(2.5), int64(1)},
				},
			}
		}
	})

	sl := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "https://doris-fe.internal:8030",
		User:           "root",
		Database:       "es_compat",
	})
	backend := NewDorisSQLBackend(dbFull, sl)

	// ShowBackendsTelemetry feeds BE hosts into StreamLoadClient allowlist.
	nodes, err := backend.ShowBackendsTelemetry(ctx)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("ShowBackendsTelemetry = (%d, %v), want 2 nodes", len(nodes), err)
	}
	allowed := strings.Join(sl.AllowedBEHosts(), ",")
	if !strings.Contains(allowed, "10.42.0.11") || !strings.Contains(allowed, "doris-be-2.internal") {
		t.Fatalf("expected StreamLoadClient allowlist populated from SHOW BACKENDS, got %q", allowed)
	}

	doc, found, err := backend.GetDocByID(ctx, "es_compat", "orders", "doc-1")
	if err != nil || !found || doc.Routing != "tenant-a" || !strings.Contains(string(doc.EffectiveSource()), `"extra":1`) {
		t.Fatalf("GetDocByID = (%+v, %v, %v), want Routing=tenant-a and merged RawSource", doc, found, err)
	}

	batchMap, err := backend.GetDocsByIDs(ctx, "es_compat", "orders", []string{"doc-1", "doc-del"})
	if err != nil || len(batchMap) != 1 || batchMap["doc-1"].Routing != "tenant-b" || batchMap["doc-1"].Version != 4 {
		t.Fatalf("GetDocsByIDs = (%+v, %v), want doc-1 v4 Routing=tenant-b and tombstone excluded", batchMap, err)
	}

	hitsShapes := []struct {
		name string
		sql  string
	}{
		{
			name: "standard",
			sql:  "SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`orders` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (TRUE) ORDER BY `_score` DESC LIMIT 10 OFFSET 0",
		},
		{
			name: "search_after",
			sql:  "SELECT `_id`, `_version`, `_source`, `_score`, `_total_hits` FROM (SELECT *, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`orders` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (TRUE)) `_scored` WHERE (`_id` > 'a') ORDER BY `_id` ASC LIMIT 10 OFFSET 0",
		},
		{
			name: "collapse",
			sql:  "SELECT `_id`, `_version`, `_source`, `_score`, `_total_hits` FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY `f__cat` ORDER BY `_score` DESC) AS `_collapse_rn` FROM (SELECT *, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`orders` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (TRUE)) `_scored`) `_collapsed` WHERE `_collapse_rn` = 1 ORDER BY `_score` DESC LIMIT 10 OFFSET 0",
		},
		{
			name: "union_all_branches",
			sql:  "(SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`orders_1` WHERE 1=1) UNION ALL (SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`orders_2` WHERE 1=1) ORDER BY `_score` DESC LIMIT 10",
		},
		{
			name: "wrapped_union_all",
			sql:  "SELECT `_id`, `_version`, `_source`, `_score`, `_total_hits` FROM ((SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`orders_1` WHERE 1=1) UNION ALL (SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`orders_2` WHERE 1=1)) `_u` ORDER BY `_score` DESC LIMIT 10",
		},
	}
	for _, hs := range hitsShapes {
		hits, qErr := backend.QueryHits(ctx, hs.sql)
		if qErr != nil || len(hits) != 1 || hits[0].Routing != "shard-route-7" || !strings.Contains(string(hits[0].EffectiveSource()), `"dyn":true`) {
			t.Fatalf("QueryHits(%s) = (%+v, %v), want Routing=shard-route-7 and EffectiveSource with dyn", hs.name, hits, qErr)
		}
	}

	// Verify wrapped_union_all rewrote outer SELECT with passthrough `_raw_doc`, `_routing` and inner branches with CAST(`_doc` AS STRING) AS `_raw_doc`, `_routing`.
	rewrittenWrapped, okWrap := injectRawDocAndRoutingSelectIntoHitsSQL(hitsShapes[4].sql)
	if !okWrap || !strings.HasPrefix(rewrittenWrapped, "SELECT `_id`, `_version`, `_source`, `_raw_doc`, `_routing`, `_score`") || strings.Count(rewrittenWrapped, "CAST(`_doc` AS STRING) AS `_raw_doc`, `_routing`") != 2 {
		t.Fatalf("unexpected wrapped UNION ALL rewrite: %s", rewrittenWrapped)
	}

	// 2. Legacy table lacking `_routing` (errors on `_routing`, succeeds on `_raw_doc` fallback)
	// and minimal external table lacking both `_routing` and `_doc` (falls back to bare normSQL / 3-col).
	for _, legacyMode := range []string{"no_routing", "no_routing_no_doc"} {
		dbLegacy := openRound63MockDB(t, func(query string, _ []driver.NamedValue) round63SQLQueryResult {
			if strings.Contains(query, "`_routing`") {
				return round63SQLQueryResult{err: errors.New("Unknown column '_routing' in 'field list'")}
			}
			if legacyMode == "no_routing_no_doc" && (strings.Contains(query, "`_doc`") || strings.Contains(query, "__DORIS_DELETE_SIGN__")) {
				return round63SQLQueryResult{err: errors.New("Unknown column '_doc' in 'field list'")}
			}
			switch {
			case strings.Contains(query, "WHERE `_id` = ?"):
				if legacyMode == "no_routing" {
					return round63SQLQueryResult{
						cols: []string{"_id", "_version", "_source", "_raw_doc", "__DORIS_DELETE_SIGN__"},
						rows: [][]driver.Value{{"leg-1", int64(2), `{"a":1}`, `{"a":1,"b":2}`, int64(0)}},
					}
				}
				return round63SQLQueryResult{
					cols: []string{"_id", "_version", "_source"},
					rows: [][]driver.Value{{"leg-1", int64(2), `{"a":1}`}},
				}
			case strings.Contains(query, "WHERE `_id` IN"):
				if legacyMode == "no_routing" {
					return round63SQLQueryResult{
						cols: []string{"_id", "_version", "_source", "_raw_doc", "__DORIS_DELETE_SIGN__"},
						rows: [][]driver.Value{{"leg-1", int64(2), `{"a":1}`, `{"a":1,"b":2}`, int64(0)}},
					}
				}
				return round63SQLQueryResult{
					cols: []string{"_id", "_version", "_source"},
					rows: [][]driver.Value{{"leg-1", int64(2), `{"a":1}`}},
				}
			default:
				if legacyMode == "no_routing" {
					return round63SQLQueryResult{
						cols: []string{"_id", "_version", "_source", "_raw_doc", "_score", "_total_hits"},
						rows: [][]driver.Value{{"leg-1", int64(2), `{"a":1}`, `{"a":1,"b":2}`, float64(1.0), int64(1)}},
					}
				}
				return round63SQLQueryResult{
					cols: []string{"_id", "_version", "_source", "_score", "_total_hits"},
					rows: [][]driver.Value{{"leg-1", int64(2), `{"a":1}`, float64(1.0), int64(1)}},
				}
			}
		})
		bLeg := NewDorisSQLBackend(dbLegacy, nil)
		gotDoc, okDoc, errDoc := bLeg.GetDocByID(ctx, "es_compat", "legacy_tbl", "leg-1")
		if errDoc != nil || !okDoc || gotDoc.ID != "leg-1" || gotDoc.Routing != "" {
			t.Fatalf("legacyMode=%s GetDocByID = (%+v, %v, %v)", legacyMode, gotDoc, okDoc, errDoc)
		}
		gotMap, errMap := bLeg.GetDocsByIDs(ctx, "es_compat", "legacy_tbl", []string{"leg-1"})
		if errMap != nil || gotMap["leg-1"].ID != "leg-1" {
			t.Fatalf("legacyMode=%s GetDocsByIDs = (%+v, %v)", legacyMode, gotMap, errMap)
		}
		gotHits, errHits := bLeg.QueryHits(ctx, hitsShapes[0].sql)
		if errHits != nil || len(gotHits) != 1 || gotHits[0].ID != "leg-1" {
			t.Fatalf("legacyMode=%s QueryHits = (%+v, %v)", legacyMode, gotHits, errHits)
		}
	}
}

func TestRound63_StreamLoadClient_DorisFE307EmbeddedUserinfo(t *testing.T) {
	t.Parallel()

	loopbackLocations := []string{
		"http://root:@127.0.0.1:8040/api/es_compat/orders/_stream_load",
		"http://root%40default_cluster:@127.0.0.1:8040/api/es_compat/orders/_stream_load",
		"http://default_cluster:root:@127.0.0.1:8040/api/es_compat/orders/_stream_load",
	}
	for _, loc := range loopbackLocations {
		sl := NewStreamLoadClient(StreamLoadConfig{
			FEHTTPEndpoint: "http://127.0.0.1:8030",
			User:           "root",
			Password:       "",
			Database:       "es_compat",
			Timeout:        2 * time.Second,
		})
		var beHits atomic.Int32
		var gotAuth string
		var sawUserinfo atomic.Bool
		sl.httpClient.Transport = round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "127.0.0.1:8030" {
				return newRound63JSONResponse(req, http.StatusTemporaryRedirect, map[string]string{
					"Location": loc,
				}, ""), nil
			}
			beHits.Add(1)
			if req.URL.User != nil {
				sawUserinfo.Store(true)
			}
			gotAuth = req.Header.Get("Authorization")
			return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1}`), nil
		})
		if err := sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
			t.Fatalf("loc=%q: LoadNDJSON failed: %v", loc, err)
		}
		if beHits.Load() != 1 {
			t.Fatalf("loc=%q: expected 1 BE hit, got %d", loc, beHits.Load())
		}
		if sawUserinfo.Load() {
			t.Fatalf("loc=%q: expected req.URL.User stripped before BE request", loc)
		}
		if !strings.HasPrefix(gotAuth, "Basic ") {
			t.Fatalf("loc=%q: expected Basic Authorization header forwarded, got %q", loc, gotAuth)
		}
		if cached, _ := sl.cachedBEBase.Load().(string); cached != "http://127.0.0.1:8040" {
			t.Fatalf("loc=%q: cachedBEBase = %q, want http://127.0.0.1:8040", loc, cached)
		}
	}

	matchingHTTPS := []string{
		"https://doris_ingest:ingest_pw@doris-be-01.prod.example.com:8040/api/es_compat/orders/_stream_load",
		"https://default_cluster:doris_ingest:ingest_pw@doris-be-01.prod.example.com:8040/api/es_compat/orders/_stream_load",
	}
	for _, loc := range matchingHTTPS {
		sl := NewStreamLoadClient(StreamLoadConfig{
			FEHTTPEndpoint: "https://doris-fe.prod.example.com:8030",
			User:           "doris_ingest",
			Password:       "ingest_pw",
			Database:       "es_compat",
			Timeout:        2 * time.Second,
		})
		sl.AllowBEHosts([]string{"doris-be-01.prod.example.com"})
		var sawUserinfo atomic.Bool
		sl.httpClient.Transport = round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "doris-fe.prod.example.com:8030" {
				return newRound63JSONResponse(req, http.StatusTemporaryRedirect, map[string]string{
					"Location": loc,
				}, ""), nil
			}
			if req.URL.User != nil {
				sawUserinfo.Store(true)
			}
			return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success","NumberTotalRows":1,"NumberLoadedRows":1}`), nil
		})
		if err := sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
			t.Fatalf("loc=%q: LoadNDJSON failed: %v", loc, err)
		}
		if sawUserinfo.Load() {
			t.Fatalf("loc=%q: expected req.URL.User stripped before BE request", loc)
		}
		if cached, _ := sl.cachedBEBase.Load().(string); cached != "https://doris-be-01.prod.example.com:8040" {
			t.Fatalf("loc=%q: cachedBEBase = %q, want https://doris-be-01.prod.example.com:8040", loc, cached)
		}
	}

	rejectedCases := []struct {
		name     string
		location string
		wantErr  string
	}{
		{
			name:     "foreign_credentials",
			location: "https://evil:secret@doris-be-01.prod.example.com:8040/api/es_compat/orders/_stream_load",
			wantErr:  "embedded userinfo",
		},
		{
			name:     "wrong_password",
			location: "https://doris_ingest:wrong_pw@doris-be-01.prod.example.com:8040/api/es_compat/orders/_stream_load",
			wantErr:  "embedded userinfo",
		},
		{
			name:     "untrusted_host_with_matching_creds",
			location: "https://doris_ingest:ingest_pw@evil.attacker.example:8040/api/es_compat/orders/_stream_load",
			wantErr:  "untrusted redirect host",
		},
		{
			name:     "scheme_downgrade_with_matching_creds",
			location: "http://doris_ingest:ingest_pw@doris-be-01.prod.example.com:8040/api/es_compat/orders/_stream_load",
			wantErr:  "scheme downgrade",
		},
	}
	for _, tc := range rejectedCases {
		sl := NewStreamLoadClient(StreamLoadConfig{
			FEHTTPEndpoint: "https://doris-fe.prod.example.com:8030",
			User:           "doris_ingest",
			Password:       "ingest_pw",
			Database:       "es_compat",
			Timeout:        2 * time.Second,
		})
		sl.AllowBEHosts([]string{"doris-be-01.prod.example.com"})
		var targetHits atomic.Int32
		sl.httpClient.Transport = round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "doris-fe.prod.example.com:8030" {
				return newRound63JSONResponse(req, http.StatusTemporaryRedirect, map[string]string{
					"Location": tc.location,
				}, ""), nil
			}
			targetHits.Add(1)
			return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success"}`), nil
		})
		err := sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), true)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: expected error containing %q, got %v", tc.name, tc.wantErr, err)
		}
		if targetHits.Load() != 0 {
			t.Fatalf("%s: expected 0 target hits, got %d", tc.name, targetHits.Load())
		}
	}
}
