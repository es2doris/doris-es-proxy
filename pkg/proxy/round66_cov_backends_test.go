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
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

type r66CovSQLResult struct {
	cols []string
	rows [][]driver.Value
	err  error
}

type r66CovMockDriver struct {
	mu       sync.RWMutex
	handlers map[string]func(query string) r66CovSQLResult
}

var (
	r66CovDriverOnce sync.Once
	r66CovDriverInst = &r66CovMockDriver{
		handlers: make(map[string]func(query string) r66CovSQLResult),
	}
)

func openR66CovMockDB(t *testing.T, fn func(query string) r66CovSQLResult) *sql.DB {
	t.Helper()
	r66CovDriverOnce.Do(func() {
		sql.Register("round66_cov_sql_mock", r66CovDriverInst)
	})
	dsn := fmt.Sprintf("%s_%d", t.Name(), time.Now().UnixNano())
	r66CovDriverInst.mu.Lock()
	r66CovDriverInst.handlers[dsn] = fn
	r66CovDriverInst.mu.Unlock()
	t.Cleanup(func() {
		r66CovDriverInst.mu.Lock()
		delete(r66CovDriverInst.handlers, dsn)
		r66CovDriverInst.mu.Unlock()
	})
	db, err := sql.Open("round66_cov_sql_mock", dsn)
	if err != nil {
		t.Fatalf("sql.Open mock failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (d *r66CovMockDriver) Open(name string) (driver.Conn, error) {
	return &r66CovMockConn{dsn: name, drv: d}, nil
}

type r66CovMockConn struct {
	dsn string
	drv *r66CovMockDriver
}

func (c *r66CovMockConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *r66CovMockConn) Close() error                        { return nil }
func (c *r66CovMockConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (c *r66CovMockConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.drv.mu.RLock()
	fn := c.drv.handlers[c.dsn]
	c.drv.mu.RUnlock()
	if fn == nil {
		return nil, fmt.Errorf("missing sql handler %s", c.dsn)
	}
	res := fn(query)
	if res.err != nil {
		return nil, res.err
	}
	return &r66CovMockRows{cols: res.cols, rows: res.rows}, nil
}

type r66CovMockRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *r66CovMockRows) Columns() []string { return r.cols }
func (r *r66CovMockRows) Close() error      { return nil }
func (r *r66CovMockRows) Next(dest []driver.Value) error {
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

func TestRound66CovBackends_SQLBackendRewritesAndQueryRows(t *testing.T) {
	// 1. rewriteDorisUnitSepLiterals edge cases (quotes, escapes, backticks, unclosed quote, \x1f/\x1F)
	qUnit := `SELECT "` + `\x1f` + `" AS "a\"b", ` + "`col\\x1f``1`" + `, 'abc\x1fdef\x1Fghi', 'unclosed\x1f`
	rewrittenUnit := rewriteDorisUnitSepLiterals(qUnit)
	if !strings.Contains(rewrittenUnit, "CONCAT('abc', CHAR(31), 'def', CHAR(31), 'ghi')") {
		t.Fatalf("unexpected unit sep rewrite: %s", rewrittenUnit)
	}
	if !strings.Contains(rewrittenUnit, "`col\\x1f``1`") {
		t.Fatalf("expected backtick identifier preserved, got %s", rewrittenUnit)
	}

	// 2. rewriteDorisArrayExists, detectDorisArrayFallbackType, detectDorisLambdaCastArrayType, stripOuterSQLParensR64
	if got := stripOuterSQLParensR64(`((('a''b\\c' AND "d\"e" AND ` + "`f``g`" + `)))`); got != `'a''b\\c' AND "d\"e" AND `+"`f``g`" {
		t.Fatalf("stripOuterSQLParensR64 unexpected: %s", got)
	}
	arrayTypeCases := []struct {
		expr string
		want string
	}{
		{`array_exists(x -> x > 1.5, CAST(col AS ARRAY<FLOAT>))`, `ARRAY<FLOAT>`},
		{`array_exists(x -> x = true, CAST(col AS ARRAY<BOOLEAN>))`, `ARRAY<BOOLEAN>`},
		{`array_exists(x -> x > '2026-01-01', CAST(col AS ARRAY<DATETIMEV2(3)>))`, `ARRAY<DATETIMEV2(3)>`},
		{`array_exists(x -> x > '2026-01-01', CAST(col AS ARRAY<DATETIMEV2(6)>))`, `ARRAY<DATETIMEV2(6)>`},
		{`array_exists(x -> x > '2026-01-01', CAST(col AS ARRAY<DATETIMEV2>))`, `ARRAY<DATETIMEV2>`},
		{`array_exists(x -> x > 1, CAST(col AS ARRAY<DOUBLE>))`, `ARRAY<DOUBLE>`},
		{`array_exists(x -> x > 1, CAST(col AS ARRAY<BIGINT>))`, `ARRAY<BIGINT>`},
		{`array_exists(x -> x > 1, CAST(col AS ARRAY<LARGEINT>))`, `ARRAY<LARGEINT>`},
		{`array_exists(x -> x > 1, CAST(col AS ARRAY<INT>))`, `ARRAY<INT>`},
		{`array_exists(x -> x = 'a', CAST(col AS ARRAY<VARCHAR>))`, `ARRAY<STRING>`},
		{`array_exists(x -> x > 1, ARRAY_MAP(e -> CAST(e AS FLOAT), arr))`, `ARRAY<FLOAT>`},
		{`array_exists(x -> x, ARRAY_MAP(e -> CAST(e AS BOOLEAN), arr))`, `ARRAY<BOOLEAN>`},
		{`array_exists(x -> x != '', ARRAY_MAP(e -> CAST(e AS DATETIMEV2(3)), arr))`, `ARRAY<DATETIMEV2(3)>`},
		{`array_exists(x -> x != '', ARRAY_MAP(e -> CAST(e AS DATETIMEV2(6)), arr))`, `ARRAY<DATETIMEV2(6)>`},
		{`array_exists(x -> x != '', ARRAY_MAP(e -> CAST(e AS DATETIMEV2), arr))`, `ARRAY<DATETIMEV2>`},
		{`array_exists(x -> x > 0, ARRAY_MAP(e -> CAST(e AS DOUBLE), arr))`, `ARRAY<DOUBLE>`},
		{`array_exists(x -> x > 0, ARRAY_MAP(e -> CAST(e AS BIGINT), arr))`, `ARRAY<BIGINT>`},
		{`array_exists(x -> x > 0, ARRAY_MAP(e -> CAST(e AS LARGEINT), arr))`, `ARRAY<LARGEINT>`},
		{`array_exists(x -> x > 0, ARRAY_MAP(e -> CAST(e AS INT), arr))`, `ARRAY<INT>`},
		{`array_exists(x -> x != '', ARRAY_MAP(e -> CAST(e AS VARCHAR), arr))`, `ARRAY<STRING>`},
		{`array_exists(x -> x > 0, CASE WHEN flag THEN CAST(a AS ARRAY<DOUBLE>) ELSE CAST(b AS ARRAY<DOUBLE>) END)`, `ARRAY<DOUBLE>`},
		{`array_exists((x) -> TRY_CAST(x AS BIGINT) > 10 AND 'ignored''\\' AND "dbl\"" AND ` + "`bt``k`" + `, raw_col)`, `ARRAY<BIGINT>`},
		{`array_exists(x -> CAST(x AS STRING) = 'foo', raw_col)`, `ARRAY<STRING>`},
		{`array_exists(x -> x = 'a', IFNULL(col, CAST([] AS ARRAY<STRING>)))`, `ARRAY<STRING>`},
	}
	for _, tc := range arrayTypeCases {
		got := rewriteDorisArrayExists(tc.expr)
		if !strings.Contains(got, tc.want) {
			t.Fatalf("rewriteDorisArrayExists(%s) = %s, want %s", tc.expr, got, tc.want)
		}
	}
	// Invalid lambda inputs
	if typ, ok := detectDorisLambdaCastArrayType("no_arrow"); ok || typ != "" {
		t.Fatalf("expected false for no arrow, got %q %v", typ, ok)
	}
	if typ, ok := detectDorisLambdaCastArrayType("bad$param -> CAST(x AS INT)"); ok || typ != "" {
		t.Fatalf("expected false for invalid param, got %q %v", typ, ok)
	}
	if typ, ok := detectDorisLambdaCastArrayType(" -> CAST(x AS INT)"); ok || typ != "" {
		t.Fatalf("expected false for empty param, got %q %v", typ, ok)
	}

	// 3. injectHitsSelectColumns & selectBlockWrapsNestedHitsSelect
	innerSQL := "/* cmt */ SELECT `_id`, `_version`, `_source`, 1.0 AS `_score` FROM `tbl` WHERE `msg` = 'SELECT `_id`, `_version`, `_source`, ' AND `x` = \"q\\\"1\" AND `y` = `z``w`"
	outerSQL := "SELECT `_id`, `_version`, `_source`, `_score` FROM (" + innerSQL + ") AS `sub` UNION ALL SELECT `_id`, `_version`, `_source`, 1.0 AS `_score` FROM `tbl2`"
	injected, changed := injectRawDocAndRoutingSelectIntoHitsSQL(outerSQL)
	if !changed {
		t.Fatal("expected injectRawDocAndRoutingSelectIntoHitsSQL to modify outerSQL")
	}
	if !strings.Contains(injected, "SELECT `_id`, `_version`, `_source`, `_raw_doc`, `_routing`, `_score` FROM") {
		t.Fatalf("expected passthrough columns on outer wrapper, got %s", injected)
	}
	if !strings.Contains(injected, "SELECT `_id`, `_version`, `_source`, CAST(`_doc` AS STRING) AS `_raw_doc`, `_routing`, 1.0 AS `_score` FROM `tbl`") {
		t.Fatalf("expected leaf columns on inner query, got %s", injected)
	}
	if _, ch2 := injectHitsSelectColumns("SELECT 1", false, false); ch2 {
		t.Fatal("expected unchanged when both flags false")
	}

	// 4. DorisSQLBackend.QueryRows + TraceMeta propagation
	nilBackend := NewDorisSQLBackend(nil, nil)
	if rows, err := nilBackend.QueryRows(context.Background(), "SELECT 1"); err != nil || rows != nil {
		t.Fatalf("expected nil, nil on nil db, got %v, %v", rows, err)
	}

	var capturedSQL string
	db := openR66CovMockDB(t, func(query string) r66CovSQLResult {
		capturedSQL = query
		if strings.Contains(query, "FAIL_ME") {
			return r66CovSQLResult{err: errors.New("mock query failure")}
		}
		return r66CovSQLResult{
			cols: []string{"_id", "cnt"},
			rows: [][]driver.Value{
				{[]byte("doc1"), int64(42)},
				{"doc2", float64(3.5)},
			},
		}
	})
	backend := NewDorisSQLBackend(db, nil)
	ctx := WithTraceMeta(context.Background(), TraceMeta{
		Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		OpaqueID:    "op-123;drop/*",
		RequestID:   "req-456",
	})
	gotRows, err := backend.QueryRows(ctx, "SELECT `_id`, COUNT(*) AS `cnt` FROM `t` WHERE `__DORIS_DELETE_SIGN__` = 0")
	if err != nil {
		t.Fatalf("QueryRows failed: %v", err)
	}
	if len(gotRows) != 2 || gotRows[0]["_id"] != "doc1" || gotRows[0]["cnt"] != int64(42) || gotRows[1]["cnt"] != float64(3.5) {
		t.Fatalf("unexpected QueryRows output: %#v", gotRows)
	}
	if !strings.HasPrefix(capturedSQL, "/* traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01, opaque_id=op-123drop, request_id=req-456 */") {
		t.Fatalf("expected sanitized trace comment in SQL, got %s", capturedSQL)
	}
	if _, err := backend.QueryRows(context.Background(), "SELECT FAIL_ME"); err == nil {
		t.Fatal("expected QueryRows error propagation")
	}
}

func TestRound66CovBackends_StreamLoadClientRetriesAndSanitize(t *testing.T) {
	// 1. sanitizeStreamLoadErrorDetail branches
	for _, htmlRaw := range []string{
		"",
		"<!DOCTYPE html><html><body>err</body></html>",
		"<?xml version=\"1.0\"?><root/>",
		"prefix <script>alert(1)</script> suffix",
	} {
		if got := sanitizeStreamLoadErrorDetail(htmlRaw); got != "" {
			t.Fatalf("expected empty sanitized output for %q, got %q", htmlRaw, got)
		}
	}
	cleanTag := sanitizeStreamLoadErrorDetail("<err>line 1\n\tline 2   > ok</err>\xff")
	if cleanTag != "line 1 line 2 > ok" {
		t.Fatalf("unexpected sanitizeStreamLoadErrorDetail: %q", cleanTag)
	}
	longStr := strings.Repeat("x", maxStreamLoadErrorDetailBytes+100)
	if trunc := sanitizeStreamLoadErrorDetail(longStr); len(trunc) != maxStreamLoadErrorDetailBytes {
		t.Fatalf("expected truncation to %d, got %d", maxStreamLoadErrorDetailBytes, len(trunc))
	}

	// 2. loadSingleNDJSONBatch empty & blocked IMDS host
	slBlocked := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "http://169.254.169.254:8030",
		Database:       "es_compat",
	})
	if err := slBlocked.LoadNDJSON(context.Background(), "tbl", []byte("   \n"), true); err != nil {
		t.Fatalf("expected nil on empty payload, got %v", err)
	}
	if err := slBlocked.LoadNDJSON(context.Background(), "tbl", []byte(`{"_id":"1"}`+"\n"), true); err == nil || !strings.Contains(err.Error(), "rejected blocked") {
		t.Fatalf("expected blocked IMDS host error, got %v", err)
	}

	// 3. Transient retry + cached BE URL + Label Already Exists VISIBLE
	var attempts atomic.Int32
	sl := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "http://127.0.0.1:8030",
		User:           "root",
		Password:       "pw",
		Database:       "es_compat",
		Timeout:        2 * time.Second,
	})
	sl.cachedBEBase.Store("http://127.0.0.1:8041")
	rt := round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		n := attempts.Add(1)
		if strings.Contains(req.URL.Path, "_load_error") {
			return newRound63JSONResponse(req, http.StatusOK, nil, "<detail>row 1 malformed\ncolumn mismatch</detail>"), nil
		}
		if n == 1 {
			return newRound63JSONResponse(req, http.StatusTooManyRequests, nil, "busy"), nil
		}
		if n == 2 {
			return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Fail","Message":"TOO_MANY_VERSIONS"}`), nil
		}
		return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Label Already Exists","ExistingJobStatus":"VISIBLE"}`), nil
	})
	sl.httpClient.Transport = rt
	sl.errHTTPClient.Transport = rt

	if err := sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), false); err != nil {
		t.Fatalf("expected retry to succeed via Label Already Exists VISIBLE, got %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts.Load())
	}

	// 4. Label Already Exists ABORTED & NumberFilteredRows > 0 error detail fetching
	attempts.Store(0)
	rtAbort := round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "_load_error") {
			return newRound63JSONResponse(req, http.StatusOK, nil, "<msg>bad json line</msg>"), nil
		}
		n := attempts.Add(1)
		if n == 1 {
			return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Fail","Message":"TRY AGAIN"}`), nil
		}
		return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Label Already Exists","ExistingJobStatus":"ABORTED","ErrorURL":"http://127.0.0.1:8030/api/_load_error_log?file=e1"}`), nil
	})
	sl.httpClient.Transport = rtAbort
	sl.errHTTPClient.Transport = rtAbort
	err := sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), false)
	if err == nil || !strings.Contains(err.Error(), "existing_job_status=ABORTED") || !strings.Contains(err.Error(), "bad json line") {
		t.Fatalf("expected ABORTED error with sanitized detail, got %v", err)
	}

	rtFiltered := round63RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.Path, "_load_error") {
			return newRound63JSONResponse(req, http.StatusOK, nil, "filtered row 1"), nil
		}
		return newRound63JSONResponse(req, http.StatusOK, nil, `{"Status":"Success","NumberTotalRows":2,"NumberFilteredRows":1,"ErrorURL":"http://127.0.0.1:8030/api/_load_error_log?file=e2"}`), nil
	})
	sl.httpClient.Transport = rtFiltered
	sl.errHTTPClient.Transport = rtFiltered
	err = sl.LoadNDJSON(context.Background(), "orders", []byte(`{"_id":"1"}`+"\n"), false)
	if err == nil || !strings.Contains(err.Error(), "filtered 1/2 rows") || !strings.Contains(err.Error(), "filtered row 1") {
		t.Fatalf("expected filtered rows error, got %v", err)
	}
}

func TestRound66CovBackends_MemBackendEvalAndSQLHelpers(t *testing.T) {
	row := map[string]any{
		"_id":        "doc-1",
		"_score":     2.5,
		"__tsid":     "ts-1",
		"ts":         "2026-03-08 02:30:00.123456", // DST spring-forward in America/New_York
		"ts_unix":    float64(1700000000.9999999),
		"sec_off":    float64(60),
		"num":        int64(16),
		"flt":        float64(2.75),
		"arr_any":    []any{"10", 20, "30.5"},
		"arr_nums":   []any{10, 20, 30.5},
		"arr_f64":    []float64{1.25, 2.5},
		"arr_str":    []string{"3", "4.5"},
		"json_str":   `{"nested":{"k":"val","arr":[1,2,3]}}`,
		"b64":        "aGVsbG8=",
		"text_val":   "abc-123-xyz",
		"vec_str":    "[0.1, 0.2, 0.3]",
		"bool_num":   json.Number("1"),
		"bool_bad":   math.NaN(),
		"nested_arr": []any{map[string]any{"tag": "x", "val": 10.0, "w": 2.0}, map[string]any{"tag": "y", "val": 20.0, "w": 3.0}},
	}

	// 1. Date/Time & numeric helpers
	if got := memEvalFromUnixtime(row, "`ts_unix`"); got != "2023-11-14 22:13:21.000000" {
		t.Fatalf("memEvalFromUnixtime unexpected: %v", got)
	}
	if got := memEvalFromUnixtime(row, "1 + 2"); got != "1970-01-01 00:00:03.000000" {
		t.Fatalf("memEvalFromUnixtime arith unexpected: %v", got)
	}
	if got := memEvalFromUnixtime(row, "`missing`"); got != nil {
		t.Fatalf("expected nil for missing col, got %v", got)
	}
	if got := memEvalConvertTZ(row, "`ts`", "'America/New_York'", "'UTC'"); got == nil {
		t.Fatal("expected non-nil memEvalConvertTZ on DST spring-forward gap")
	}
	for _, tc := range []struct {
		a0, a1, want string
	}{
		{"`ts`", "'second'", "2026-03-08 02:30:00.000000"},
		{"`ts`", "'minute'", "2026-03-08 02:30:00.000000"},
		{"`ts`", "'hour'", "2026-03-08 02:00:00.000000"},
		{"`ts`", "'day'", "2026-03-08 00:00:00.000000"},
		{"'week'", "`ts`", "2026-03-02 00:00:00.000000"},
		{"`ts`", "'month'", "2026-03-01 00:00:00.000000"},
		{"`ts`", "'quarter'", "2026-01-01 00:00:00.000000"},
		{"`ts`", "'year'", "2026-01-01 00:00:00.000000"},
	} {
		if got := memEvalDateTrunc(row, tc.a0, tc.a1); got != tc.want {
			t.Fatalf("memEvalDateTrunc(%s,%s) = %v, want %s", tc.a0, tc.a1, got, tc.want)
		}
	}
	if got := memEvalDateTrunc(row, "`ts`", "'invalid'"); got != nil {
		t.Fatalf("expected nil on invalid date_trunc unit, got %v", got)
	}
	if got := memEvalSecondsAdd(row, "`ts`", "`sec_off`"); got != "2026-03-08 02:31:00.123456" {
		t.Fatalf("memEvalSecondsAdd col unexpected: %v", got)
	}
	if got := memEvalSecondsAdd(row, "`ts`", "30 + 30"); got != "2026-03-08 02:31:00.123456" {
		t.Fatalf("memEvalSecondsAdd arith unexpected: %v", got)
	}
	if got := memEvalTimestampDiff(row, "'MINUTE'", "'2026-03-08 02:00:00'", "`ts`"); got != int64(30) {
		t.Fatalf("memEvalTimestampDiff minute unexpected: %v", got)
	}
	if got := memEvalTimestampDiff(row, "'HOUR'", "'2026-03-08 00:00:00'", "`ts`"); got != int64(2) {
		t.Fatalf("memEvalTimestampDiff hour unexpected: %v", got)
	}
	if got := memEvalTimestampDiff(row, "'DAY'", "'2026-03-07 00:00:00'", "`ts`"); got != int64(1) {
		t.Fatalf("memEvalTimestampDiff day unexpected: %v", got)
	}
	if got := memEvalTimestampDiff(row, "'BAD'", "'2026-03-07 00:00:00'", "`ts`"); got != nil {
		t.Fatalf("expected nil on invalid unit, got %v", got)
	}

	// 2. memCoerceArrayOfFloat & coerceSQLBool
	if got := memCoerceArrayOfFloat([]any{1, "2.5"}); len(got) != 2 || got[1] != 2.5 {
		t.Fatalf("memCoerceArrayOfFloat []any unexpected: %v", got)
	}
	if got := memCoerceArrayOfFloat([]string{"1.5", "2.5"}); len(got) != 2 {
		t.Fatalf("memCoerceArrayOfFloat []string unexpected: %v", got)
	}
	if got := memCoerceArrayOfFloat(row["vec_str"]); len(got) != 3 {
		t.Fatalf("memCoerceArrayOfFloat vec string unexpected: %v", got)
	}
	if b, ok := coerceSQLBool(json.Number("1")); !ok || !b {
		t.Fatalf("coerceSQLBool json.Number unexpected: %v %v", b, ok)
	}
	if b, ok := coerceSQLBool("false"); !ok || b {
		t.Fatalf("coerceSQLBool false unexpected: %v %v", b, ok)
	}
	if _, ok := coerceSQLBool(math.NaN()); ok {
		t.Fatal("expected NaN coerceSQLBool false")
	}

	// 3. evalNumericExpr math & conditional coverage
	for _, tc := range []struct {
		expr string
		want float64
	}{
		{"-`num`", -16},
		{"+`num`", 16},
		{"10 % 3", 1},
		{"10 / 0", 0},
		{"CASE WHEN `num` > 20 THEN 1 WHEN `num` = 16 THEN 42 ELSE 0 END", 42},
		{"PI()", math.Pi},
		{"IF(`num` = 16, 7, 9)", 7},
		{"GREATEST(1, `num`, 5)", 16},
		{"LEAST(10, `num`, 5)", 5},
		{"COALESCE(NULL, `arr_any`, 0)", 10},
		{"COALESCE(NULL, `arr_f64`, 0)", 1.25},
		{"COALESCE(NULL, `arr_str`, 0)", 3},
		{"COALESCE(NULL, 1 + 2)", 3},
		{"LOG10(100)", 2},
		{"LN(1)", 0},
		{"EXP(0)", 1},
		{"SQRT(`num`)", 4},
		{"SIN(0)", 0},
		{"COS(0)", 1},
		{"TAN(0)", 0},
		{"ASIN(0)", 0},
		{"ACOS(1)", 0},
		{"ATAN(0)", 0},
		{"ATAN2(0, 1)", 0},
		{"FLOOR(`flt`)", 2},
		{"CEIL(`flt`)", 3},
		{"ROUND(`flt`)", 3},
		{"TRUNCATE(`flt`)", 2},
		{"ABS(-5)", 5},
		{"MICROSECOND(`ts`)", 123456},
		{"TIMESTAMPDIFF('SECOND', '2026-03-08 02:29:00', `ts`)", 60},
		{"UNIX_TIMESTAMP(`ts`)", float64(time.Date(2026, 3, 8, 2, 30, 0, 123456000, time.UTC).Unix()) + 0.123456},
	} {
		got := evalNumericExpr(row, tc.expr)
		if math.Abs(got-tc.want) > 1e-6 {
			t.Fatalf("evalNumericExpr(%s) = %v, want %v", tc.expr, got, tc.want)
		}
	}
	if v := evalNumericExpr(row, "CONV(SUBSTRING(MD5(CONCAT(`_id`, '-', `num`)), 1, 8), 16, 10)"); v <= 0 {
		t.Fatalf("expected positive hash from CONV/MD5, got %v", v)
	}
	if r := evalNumericExpr(row, "RAND()"); r < 0 || r >= 1 {
		t.Fatalf("unexpected RAND() value: %v", r)
	}

	// 4. resolveColumnValue JSON path + CASTs
	if got := resolveColumnValue(row, "CAST(`json_str` AS JSON)['nested']['k']"); got != "val" {
		t.Fatalf("JSON path resolve failed: %v", got)
	}
	if got := resolveColumnValue(row, "CAST(`ts` AS DATETIMEV2(3))"); got != "2026-03-08 02:30:00.123456" {
		t.Fatalf("DATETIMEV2 cast failed: %v", got)
	}
	if got := resolveColumnValue(row, "CAST('12345678901234567890123' AS LARGEINT)"); got == nil {
		t.Fatal("LARGEINT cast failed")
	}
	if got := resolveColumnValue(row, "CAST(`arr_any` AS DOUBLE)"); len(asSliceOrSingle(got)) != 3 {
		t.Fatalf("CAST array AS DOUBLE failed: %#v", got)
	}
	if got := resolveColumnValue(row, "CAST(`arr_any` AS BIGINT)"); len(asSliceOrSingle(got)) != 3 {
		t.Fatalf("CAST array AS BIGINT failed: %#v", got)
	}
	if got := resolveColumnValue(row, "CAST(`arr_any` AS INT)"); len(asSliceOrSingle(got)) != 3 {
		t.Fatalf("CAST array AS INT failed: %#v", got)
	}
	if got := resolveColumnValue(row, "CAST('2026-03-08T02:30:00Z' AS BIGINT)"); got == nil {
		t.Fatal("expected epoch ms for CAST iso date AS BIGINT")
	}

	// 5. round63_membackend functions
	for _, tc := range []struct {
		expr string
		ok   bool
	}{
		{"TRY_CAST(`arr_any` AS BIGINT)", true},
		{"TRY_CAST('2026-05-01T12:00:00Z' AS BIGINT)", false},
		{"TRY_CAST(`arr_any` AS DOUBLE)", true},
		{"TRY_CAST(`bool_num` AS BOOLEAN)", true},
		{"TRY_CAST('[1, 2.5]' AS ARRAY<DOUBLE>)", true},
		{"TRY_CAST(`arr_f64` AS ARRAY<DOUBLE>)", true},
		{"TRY_CAST(`arr_nums` AS ARRAY<FLOAT>)", true},
		{"TRY_CAST('[\"a\",\"b\"]' AS ARRAY<STRING>)", true},
		{"JSON_TYPE(`json_str`, '$.nested')", true},
		{"JSON_LENGTH(`json_str`, '$.nested.arr')", true},
		{"JSON_LENGTH(`json_str`)", true},
		{"MICROSECOND(`ts`)", true},
		{"TRANSLATE(`text_val`, 'abc-', 'XYZ')", true},
		{"FROM_BASE64_BINARY(`b64`)", true},
		{"REGEXP_EXTRACT(`text_val`, '([0-9]+)', 1)", true},
		{"REGEXP_REPLACE(`text_val`, '[0-9]+', 'NUM')", true},
		{"ARRAY_JOIN(`arr_str`, ',')", true},
		{"OCTET_LENGTH(`text_val`)", true},
		{"TRUNCATE(`flt`, 1)", true},
	} {
		val, handled := evalColumnFuncR63Mem(row, tc.expr)
		if !handled {
			t.Fatalf("expected handled for %s", tc.expr)
		}
		if tc.ok && val == nil {
			t.Fatalf("expected non-nil for %s", tc.expr)
		}
		if !tc.ok && val != nil {
			t.Fatalf("expected nil for %s, got %v", tc.expr, val)
		}
	}

	// 6. BM25 helpers, sampler subqueries, sorting, evalAggBranch
	if sum, ok := sumPureBM25PlaceholdersFloat32R66Mem("(`__bm25_0` + `__bm25_1`)", map[string]float32{"__bm25_0": 1.25, "__bm25_1": 2.75}); !ok || math.Abs(sum-4.0) > 1e-5 {
		t.Fatalf("sumPureBM25PlaceholdersFloat32R66Mem unexpected: %v %v", sum, ok)
	}
	bm25SQL := "(CASE WHEN `title` IS NOT NULL THEN 2.0 * (GREATEST(CAST(CHAR_LENGTH(REGEXP_REPLACE(LOWER(COALESCE(CAST(`title` AS STRING), '')), '[^[:alnum:]_]+', '  ')) - CHAR_LENGTH(REPLACE(REGEXP_REPLACE(LOWER(COALESCE(CAST(`title` AS STRING), '')), '[^[:alnum:]_]+', '  '), 'alpha  beta', '')) AS DOUBLE), 0.0)) ELSE 0.0 END)"
	if spec, ok := extractBM25ClauseSpecR63Mem(bm25SQL); !ok || len(spec.terms) != 2 {
		t.Fatalf("extractBM25ClauseSpecR63Mem unexpected: %+v ok=%v", spec, ok)
	}

	rowsToSort := []map[string]any{
		{"_id": "2", "_score": 1.0, "__tsid": "b", "k": nil},
		{"_id": "1", "_score": 3.0, "__tsid": "a", "k": "z"},
		{"_id": "3", "_score": 2.0, "__tsid": nil, "k": "a"},
	}
	sortRowsByOrderClause(rowsToSort, "`__tsid` ASC NULLS FIRST, `k` DESC NULLS LAST, `_score` DESC, `_id` ASC")
	if rowsToSort[0]["_id"] != "3" {
		t.Fatalf("expected nil __tsid first, got %v", rowsToSort[0]["_id"])
	}

	// resolveRound62AggSubqueriesR62Mem with sampler & diversified_sampler
	baseRows := []map[string]any{
		{"_id": "1", "_score": 5.0, "cat": "a", "tags": []any{"t1", "t2"}, "nested_arr": row["nested_arr"]},
		{"_id": "2", "_score": 9.0, "cat": "a", "tags": []any{"t2"}, "nested_arr": row["nested_arr"]},
		{"_id": "3", "_score": 7.0, "cat": "b", "tags": []any{"t3"}, "nested_arr": []any{}},
	}
	smpSQL := "`_id` IN (SELECT `_id` FROM (SELECT `_id` FROM `base_matched` WHERE 1=1 ORDER BY CAST(`_score` AS DOUBLE) DESC, `_id` ASC LIMIT 2))"
	resolvedSmp := resolveRound62AggSubqueriesR62Mem(baseRows, smpSQL)
	if !strings.Contains(resolvedSmp, "'2'") || !strings.Contains(resolvedSmp, "'3'") || strings.Contains(resolvedSmp, "'1'") {
		t.Fatalf("unexpected sampler rewrite: %s", resolvedSmp)
	}
	divSQL := "`_id` IN (SELECT `_id` FROM (SELECT `_id`, ROW_NUMBER() OVER (PARTITION BY `_ds_key` ORDER BY `_ds_score` DESC, `_id` ASC) AS `_ds_rn` FROM (SELECT `_id`, `cat` AS `_ds_key`, CAST(`_score` AS DOUBLE) AS `_ds_score` FROM `base_matched` WHERE 1=1 ORDER BY `_ds_score` DESC, `_id` ASC LIMIT 3) `_ds_shard`) `_ds_part` WHERE `_ds_rn` <= 1)"
	resolvedDiv := resolveRound62AggSubqueriesR62Mem(baseRows, divSQL)
	if resolvedDiv == "" {
		t.Fatalf("unexpected empty diversified_sampler result")
	}

	// evalAggBranch: weighted percentile, percentile_rank, nested metric, scalar terms missing, tsid terms, filter, missing, card array/scalar, value_count array
	aggBranches := []string{
		"SELECT 'p' AS `_agg_name`, '50.0' AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX_WEIGHTED(`_helem`['val'], `_helem`['w'], 0.5), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`nested_arr`) `_ht` AS `_helem`",
		"SELECT 'nm_cnt' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT `_nel`['tag']) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`nested_arr`) `_nt` AS `_nel`",
		"SELECT 'nm_avg' AS `_agg_name`, '_stats_avg' AS `_bucket_key`, CAST(COALESCE(AVG(`_nel`['val']), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`nested_arr`) `_nt` AS `_nel`",
		"SELECT 'nm_min' AS `_agg_name`, '_stats_min' AS `_bucket_key`, CAST(COALESCE(MIN(`_nel`['val']), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`nested_arr`) `_nt` AS `_nel`",
		"SELECT 'nm_max' AS `_agg_name`, '_stats_max' AS `_bucket_key`, CAST(COALESCE(MAX(`_nel`['val']), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`nested_arr`) `_nt` AS `_nel`",
		"SELECT 'nm_std' AS `_agg_name`, '_stats_std_deviation' AS `_bucket_key`, CAST(COALESCE(STDDEV_POP(`_nel`['val']), 0) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`nested_arr`) `_nt` AS `_nel`",
		"SELECT 'miss_terms' AS `_agg_name`, COALESCE(CAST(`opt_cat` AS STRING), 'N/A') AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE 1=1 GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 5",
		"SELECT 'f' AS `_agg_name`, '_filter' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `cat` = 'a'",
		"SELECT 'm' AS `_agg_name`, '_missing' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE (1=1) AND NOT (`missing_f` IS NOT NULL)",
		"SELECT 'ca' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT `_t`.`_elem`) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`tags`) `_t` AS `_elem`",
		"SELECT 'cs' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT `cat`) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE 1=1",
		"SELECT 'vca' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(`_t`.`_elem`) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`tags`) `_t` AS `_elem`",
	}
	for _, br := range aggBranches {
		out := evalAggBranch(baseRows, br)
		if len(out) == 0 {
			t.Fatalf("evalAggBranch returned empty for %s", br)
		}
	}
}

func TestRound66CovBackends_CoalescerNowAndTasks(t *testing.T) {
	// 1. coalescer queryContainsNow & aggsContainNow & containsNowDateMath across DSL types
	reqJSON := `{
		"query": {
			"bool": {
				"must": [
					{"term": {"@timestamp": "now-1h"}},
					{"match": {"msg": "now"}},
					{"match_phrase": {"msg": "now/d"}},
					{"match_phrase_prefix": {"msg": "now-5m"}},
					{"match_bool_prefix": {"msg": "now+1h"}},
					{"multi_match": {"query": "now-1d", "fields": ["msg"]}},
					{"combined_fields": {"query": "now", "fields": ["msg"]}},
					{"terms": {"ts": ["now-2h"]}},
					{"range": {"ts": {"gte": "now-1d"}}},
					{"query_string": {"query": "ts:now"}},
					{"simple_query_string": {"query": "now"}},
					{"constant_score": {"filter": {"term": {"a": "now"}}}},
					{"dis_max": {"queries": [{"term": {"a": "now"}}]}},
					{"boosting": {"positive": {"term": {"a": "now"}}, "negative": {"term": {"b": "x"}}, "negative_boost": 0.2}},
					{"nested": {"path": "n", "query": {"term": {"n.ts": "now"}}}},
					{"function_score": {"random_score": {}}},
					{"script_score": {"query": {"match_all": {}}, "script": {"source": "1"}}},
					{"has_child": {"type": "c", "query": {"term": {"ts": "now"}}}},
					{"has_parent": {"parent_type": "p", "query": {"term": {"ts": "now"}}}}
				]
			}
		},
		"knn": {"field": "vec", "query_vector": [0.1], "k": 1, "num_candidates": 2, "filter": {"range": {"ts": {"gte": "now-1h"}}}},
		"rescore": {"window_size": 5, "query": {"rescore_query": {"term": {"ts": "now"}}}},
		"highlight": {"highlight_query": {"term": {"ts": "now"}}, "fields": {"msg": {"highlight_query": {"term": {"ts": "now"}}}}},
		"sort": [{"n.k": {"order": "asc", "nested": {"path": "n", "filter": {"term": {"n.ts": "now"}}}}}],
		"aggs": {
			"f": {"filter": {"term": {"ts": "now"}}},
			"fs": {"filters": {"filters": {"k": {"term": {"ts": "now"}}}}},
			"fs_anon": {"filters": {"filters": [{"term": {"ts": "now"}}]}},
			"dh": {"date_histogram": {"field": "ts", "calendar_interval": "day", "extended_bounds": {"min": "now-7d", "max": "now"}}},
			"dr": {"date_range": {"field": "ts", "ranges": [{"from": "now-1d", "to": "now"}]}},
			"r": {"range": {"field": "ts", "ranges": [{"from": "now-1d"}]}},
			"t": {"terms": {"field": "cat"}, "aggs": {"sub": {"filter": {"term": {"ts": "now"}}}}},
			"comp": {"composite": {"sources": [{"d": {"date_histogram": {"field": "ts", "calendar_interval": "day", "missing_bucket": true}}}]}}
		}
	}`
	var parsed esast.SearchRequest
	if err := json.Unmarshal([]byte(reqJSON), &parsed); err != nil {
		t.Fatalf("unmarshal SearchRequest failed: %v", err)
	}
	if !containsNowDateMath(&parsed, []byte(reqJSON)) {
		t.Fatal("expected containsNowDateMath true")
	}
	if !aggsContainNow(parsed.EffectiveAggs()) {
		t.Fatal("expected aggsContainNow true")
	}

	// 2. StreamLoadCoalescer timer flush, ctx cancellation, FlushTableIfDocPending, FlushAll
	var loaded []string
	var loadMu sync.Mutex
	releaseFlush := make(chan struct{})
	firstLoad := make(chan struct{}, 1)
	c := newStreamLoadCoalescer(func(_ context.Context, table string, ndjson []byte, _ bool) error {
		if table == "slow_tbl" {
			select {
			case firstLoad <- struct{}{}:
			default:
			}
			<-releaseFlush
		}
		loadMu.Lock()
		loaded = append(loaded, table+":"+string(ndjson))
		loadMu.Unlock()
		return nil
	})
	c.Configure(15*time.Millisecond, 1024*1024)

	// Canceled caller does not block or appear in batch
	cancelCtx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Submit(cancelCtx, "tbl_timer", []byte(`{"_id":"cancel1"}`+"\n"), false)
	}()
	time.Sleep(2 * time.Millisecond)
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Buffered doc flushed via FlushTableIfDocPending
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- c.Submit(context.Background(), "tbl_pending", []byte(`{"_id":"docA"}`+"\n"), false)
	}()
	time.Sleep(3 * time.Millisecond)
	if err := c.FlushTableIfDocPending(context.Background(), "tbl_pending", "otherDoc"); err != nil {
		t.Fatalf("FlushTableIfDocPending miss failed: %v", err)
	}
	if err := c.FlushTableIfDocPending(context.Background(), "tbl_pending", "docA"); err != nil {
		t.Fatalf("FlushTableIfDocPending hit failed: %v", err)
	}
	if err := <-doneCh; err != nil {
		t.Fatalf("Submit after FlushTableIfDocPending failed: %v", err)
	}

	// In-flight wait during FlushAll
	go func() {
		_ = c.Submit(context.Background(), "slow_tbl", []byte(`{"_id":"s1"}`+"\n"), true)
	}()
	<-firstLoad
	flushAllErr := make(chan error, 1)
	go func() {
		flushAllErr <- c.FlushAll(context.Background())
	}()
	time.Sleep(3 * time.Millisecond)
	close(releaseFlush)
	if err := <-flushAllErr; err != nil {
		t.Fatalf("FlushAll failed: %v", err)
	}
	reqs, flushes := c.Stats()
	if reqs == 0 || flushes == 0 {
		t.Fatalf("expected positive coalescer stats, got reqs=%d flushes=%d", reqs, flushes)
	}
	_ = c.Close(context.Background())

	// 3. tasks.go: getClusterSettingStringLocked & applyTaskThrottleAndProgressRound60 & launchAsyncTaskRound60
	srv := NewServer("es_tasks", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	srv.mu.Lock()
	srv.clusterTransientSettings = map[string]any{
		"flat_slice":   []any{"a", "b"},
		"flat_strs":    []string{"c", "d"},
		"nested":       map[string]any{"arr": []any{"x", "y"}, "leaf": "ok", "nullval": nil},
		"not_a_nested": "scalar",
	}
	srv.clusterPersistentSettings = map[string]any{"persisted": 123}
	if v, ok := srv.getClusterSettingStringLocked("flat_slice"); !ok || v != "a,b" {
		t.Fatalf("flat_slice lookup failed: %q %v", v, ok)
	}
	if v, ok := srv.getClusterSettingStringLocked("flat_strs"); !ok || v != "c,d" {
		t.Fatalf("flat_strs lookup failed: %q %v", v, ok)
	}
	if v, ok := srv.getClusterSettingStringLocked("nested.arr"); !ok || v != "x,y" {
		t.Fatalf("nested.arr lookup failed: %q %v", v, ok)
	}
	if v, ok := srv.getClusterSettingStringLocked("nested.leaf"); !ok || v != "ok" {
		t.Fatalf("nested.leaf lookup failed: %q %v", v, ok)
	}
	if _, ok := srv.getClusterSettingStringLocked("nested.nullval"); ok {
		t.Fatal("expected false for null nested leaf")
	}
	if _, ok := srv.getClusterSettingStringLocked("not_a_nested.sub"); ok {
		t.Fatal("expected false for non-map intermediate")
	}
	if v, ok := srv.getClusterSettingStringLocked("persisted"); !ok || v != "123" {
		t.Fatalf("persistent lookup failed: %q %v", v, ok)
	}
	srv.mu.Unlock()

	// Test applyTaskThrottleAndProgressRound60 rethrottle & cancel
	entry := srv.getTaskRegistry().register("test:action", "desc", 1.0, nil, func() {})
	tCtx, tCancel := context.WithCancel(context.WithValue(context.Background(), taskEntryContextKey{}, entry))
	go func() {
		time.Sleep(10 * time.Millisecond)
		entry.notifyRethrottle(-1) // unthrottle immediately
	}()
	if err := applyTaskThrottleAndProgressRound60(tCtx, 5, 1.0); err != nil {
		t.Fatalf("expected unthrottled return, got %v", err)
	}
	entry.notifyRethrottle(0.5)
	go func() {
		time.Sleep(10 * time.Millisecond)
		tCancel()
	}()
	if err := applyTaskThrottleAndProgressRound60(tCtx, 5, 0.5); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from throttle, got %v", err)
	}

	// Test launchAsyncTaskRound60 panic recovery & error status
	recPanic := httptest.NewRecorder()
	reqPanic := httptest.NewRequest(http.MethodPost, "/_reindex?wait_for_completion=false", strings.NewReader(`{}`))
	srv.launchAsyncTaskRound60(recPanic, reqPanic, []byte(`{}`), "test:panic", "panic task", -1, func(http.ResponseWriter, *http.Request) {
		panic("boom\nnewline")
	})
	var panicLaunchResp map[string]any
	if err := json.Unmarshal(recPanic.Body.Bytes(), &panicLaunchResp); err != nil || panicLaunchResp["task"] == "" {
		t.Fatalf("expected task id from async launch, got %d %s", recPanic.Code, recPanic.Body.String())
	}
	taskID, _ := panicLaunchResp["task"].(string)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		getReq := httptest.NewRequest(http.MethodGet, "/_tasks/"+taskID, nil)
		getRec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(getRec, getReq)
		if getRec.Code == http.StatusOK && strings.Contains(getRec.Body.String(), `"completed":true`) && strings.Contains(getRec.Body.String(), "internal_server_error") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	recErr := httptest.NewRecorder()
	reqErr := httptest.NewRequest(http.MethodPost, "/_reindex?wait_for_completion=false", strings.NewReader(`{}`))
	srv.launchAsyncTaskRound60(recErr, reqErr, []byte(`{}`), "test:err", "err task", -1, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	var errLaunchResp map[string]any
	_ = json.Unmarshal(recErr.Body.Bytes(), &errLaunchResp)
	errTaskID, _ := errLaunchResp["task"].(string)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		getReq := httptest.NewRequest(http.MethodGet, "/_tasks/"+errTaskID, nil)
		getRec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(getRec, getReq)
		if getRec.Code == http.StatusOK && strings.Contains(getRec.Body.String(), `"completed":true`) && strings.Contains(getRec.Body.String(), "task failed with status 400") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRound66CovBackends_DirectMemAndHelperBranches(t *testing.T) {
	// 1. resolveRound62AggSubqueriesR62Mem: sampler & diversified_sampler SQL subqueries
	baseRows := []map[string]any{
		{"_id": "d1", "f__cat": "a", "f__score": 10.0, "__tsid": "t2", "arr": []any{"x", "y"}},
		{"_id": "d2", "f__cat": "a", "f__score": 5.0, "__tsid": "t1", "arr": []any{"y", "z"}},
		{"_id": "d3", "f__cat": "b", "f__score": 8.0, "__tsid": "t3", "arr": []any{"z"}},
	}
	smpSQL := "`_id` IN (SELECT `_id` FROM (SELECT `_id` FROM `base_matched` WHERE 1=1 ORDER BY CAST(`f__score` AS DOUBLE) DESC, `_id` ASC LIMIT 2))"
	if resolved := resolveRound62AggSubqueriesR62Mem(baseRows, smpSQL); !strings.Contains(resolved, "d1") || !strings.Contains(resolved, "d3") {
		t.Fatalf("unexpected sampler SQL resolution: %s", resolved)
	}
	divSQL := "`_id` IN (SELECT `_id` FROM (SELECT `_id`, ROW_NUMBER() OVER (PARTITION BY `_ds_key` ORDER BY `_ds_score` DESC, `_id` ASC) AS `_ds_rn` FROM (SELECT `_id`, `f__cat` AS `_ds_key`, CAST(`f__score` AS DOUBLE) AS `_ds_score` FROM `base_matched` WHERE 1=1 ORDER BY `_ds_score` DESC, `_id` ASC LIMIT 10) `_ds_shard`) `_ds_part` WHERE `_ds_rn` <= 1)"
	_ = resolveRound62AggSubqueriesR62Mem(baseRows, divSQL)

	// 2. evalAggBranch: __tsid terms, array cardinality, array value_count
	scalarTsid := evalAggBranch(baseRows, "SELECT 'tsid_t' AS `_agg_name`, CAST(`__tsid` AS STRING) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE (1=1) AND `__tsid` IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 5")
	if len(scalarTsid) != 3 {
		t.Fatalf("expected 3 __tsid scalar buckets, got %d (%v)", len(scalarTsid), scalarTsid)
	}
	arrCard := evalAggBranch(baseRows, "SELECT 'c' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT `_elem`) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`arr`) `_t` AS `_elem` WHERE `_elem` IS NOT NULL")
	if len(arrCard) != 1 || arrCard[0].DocCount != 3 {
		t.Fatalf("expected array cardinality=3, got %v", arrCard)
	}
	arrVC := evalAggBranch(baseRows, "SELECT 'vc' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(`_elem`) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`arr`) `_t` AS `_elem` WHERE `_elem` IS NOT NULL")
	if len(arrVC) != 1 || arrVC[0].DocCount != 5 {
		t.Fatalf("expected array value_count=5, got %v", arrVC)
	}

	// 3. coalescer.go: queryContainsNow across remaining query types
	for _, qj := range []string{
		`{"query_string":{"query":"ts:[now-1d TO now]"}}`,
		`{"simple_query_string":{"query":"now"}}`,
		`{"match":{"ts":"now"}}`,
		`{"match_phrase":{"ts":"now"}}`,
		`{"match_phrase_prefix":{"ts":"now"}}`,
		`{"match_bool_prefix":{"ts":"now"}}`,
		`{"multi_match":{"query":"now","fields":["ts"]}}`,
		`{"combined_fields":{"query":"now","fields":["ts"]}}`,
		`{"terms":{"ts":["now"]}}`,
		`{"constant_score":{"filter":{"term":{"ts":"now"}}}}`,
		`{"pinned":{"ids":["1"],"organic":{"term":{"ts":"now"}}}}`,
		`{"script_score":{"query":{"term":{"ts":"now"}},"script":{"source":"1"}}}`,
		`{"knn":{"field":"v","query_vector":[1],"k":1,"num_candidates":2,"filter":{"term":{"ts":"now"}}}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(qj), &q); err != nil {
			t.Fatalf("unmarshal %s failed: %v", qj, err)
		}
		if !queryContainsNow(&q) {
			t.Fatalf("expected queryContainsNow true for %s", qj)
		}
	}

	// 4. sqlbackend.go: selectBlockWrapsNestedHitsSelect
	if !selectBlockWrapsNestedHitsSelect("('a''b', \"x\\\"y\", `col``s`) FROM (SELECT `_id` FROM t)", "SELECT ") {
		t.Fatal("expected selectBlockWrapsNestedHitsSelect true")
	}
	if selectBlockWrapsNestedHitsSelect(`) FROM (SELECT 1)`, "SELECT 1") {
		t.Fatal("expected selectBlockWrapsNestedHitsSelect false after closing paren")
	}
}

func TestRound66CovBackends_SchemaShredderValidationSpatialAndQueryWalks(t *testing.T) {
	nowUTC := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)

	// 1. schema.ShredDocumentWithNow: typed ignore_above, ignore_malformed, null_value, copy_to scalar/nested, completion, range, histogram, nested-in-nested
	ignTrue := true
	coTrue := true
	ms := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"kw": {
				Type: "keyword", IgnoreAbove: 5, Normalizer: "lowercase",
				NullValue: "DFLT", CopyTo: []string{"all_text", "num_cp", "items.copied_kw"},
			},
			"all_text": {Type: "text", Fields: map[string]esast.FieldProperty{"low": {Type: "keyword", Normalizer: "lowercase", IgnoreAbove: 4}}},
			"num_cp":   {Type: "integer", IgnoreMalformed: &ignTrue},
			"num":      {Type: "integer", Coerce: &coTrue, IgnoreAbove: 4, IgnoreMalformed: &ignTrue, NullValue: 7},
			"strict_i": {Type: "integer"},
			"dn":       {Type: "date_nanos"},
			"comp":     {Type: "completion", IgnoreMalformed: &ignTrue},
			"rng":      {Type: "integer_range"},
			"hist":     {Type: "histogram"},
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"copied_kw": {Type: "text"},
					"score":     {Type: "integer", IgnoreMalformed: &ignTrue},
					"irng":      {Type: "integer_range", IgnoreMalformed: &ignTrue},
					"sub": {
						Type: "nested",
						Properties: map[string]esast.FieldProperty{
							"k": {Type: "keyword"},
						},
					},
				},
			},
		},
	}
	sch := schema.CompileIndexSchema("es", "shred_cov", ms)
	if _, err := schema.ShredDocumentWithNow(sch, "d1", 1, false, json.RawMessage(`{
		"kw": "abc",
		"num": "bad_int",
		"comp": [{"input":"fast car","weight":5}],
		"rng": {"gte": 1, "lte": 10},
		"hist": {"values": [1.0, 2.0], "counts": [1, 2]},
		"items": [{"score": "bad_nested_int", "irng": {"gte": "bad"}, "sub": [{"k": "leaf1"}]}]
	}`), nowUTC); err != nil {
		t.Fatalf("ShredDocumentWithNow d1 failed: %v", err)
	}
	// Null value + empty string coercion + ignore_above exceeded
	if _, err := schema.ShredDocumentWithNow(sch, "d2", 1, false, json.RawMessage(`{
		"kw": null,
		"num": ""
	}`), nowUTC); err != nil {
		t.Fatalf("ShredDocumentWithNow d2 failed: %v", err)
	}
	// Malformed without ignore_malformed -> error
	if _, err := schema.ShredDocumentWithNow(sch, "d3", 1, false, json.RawMessage(`{"strict_i":"not_int"}`), nowUTC); err == nil {
		t.Fatal("expected mapper_parsing_exception for strict_i")
	}

	// 2. schema.ValidateMappingSpec: dynamic_templates match_mapping_type / unmatch_mapping_type & alias targets
	if err := schema.ValidateMappingSpec(&esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":  {Type: "text"},
			"al_kw":  {Type: "alias", Path: "title.keyword"},
			"al_id":  {Type: "alias", Path: "_id"},
			"al_ver": {Type: "alias", Path: "_version"},
			"al_idx": {Type: "alias", Path: "_index"},
			"al_rt":  {Type: "alias", Path: "_routing"},
			"al_ign": {Type: "alias", Path: "_ignored"},
		},
		DynamicTemplates: []map[string]any{
			{"str_tmpl": map[string]any{"match_mapping_type": "string", "mapping": map[string]any{"type": "keyword"}}},
			{"arr_tmpl": map[string]any{"match_mapping_type": []any{"long", "double"}, "unmatch_mapping_type": []string{"boolean"}, "mapping": map[string]any{"type": "double"}}},
		},
	}); err != nil {
		t.Fatalf("ValidateMappingSpec valid failed: %v", err)
	}
	for _, badSpec := range []*esast.MappingSpec{
		{DynamicTemplates: []map[string]any{{"bad1": map[string]any{"match_mapping_type": []any{}}}}},
		{DynamicTemplates: []map[string]any{{"bad2": map[string]any{"match_mapping_type": []any{123}}}}},
		{DynamicTemplates: []map[string]any{{"bad3": map[string]any{"match_mapping_type": 999}}}},
		{DynamicTemplates: []map[string]any{{"bad4": map[string]any{"unmatch_mapping_type": []any{}}}}},
		{DynamicTemplates: []map[string]any{{"bad5": map[string]any{"unmatch_mapping_type": []any{123}}}}},
		{DynamicTemplates: []map[string]any{{"bad6": map[string]any{"unmatch_mapping_type": "invalid_type"}}}},
	} {
		if err := schema.ValidateMappingSpec(badSpec); err == nil {
			t.Fatalf("expected ValidateMappingSpec error for %+v", badSpec)
		}
	}

	// 3. schema.ValidateTSDBMapping edge errors (nested, passthrough subobjects/routing_path)
	subTrue := true
	tsDim := true
	_ = schema.ValidateTSDBMapping(&esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"@timestamp": {Type: "date"},
			"nest":       {Type: "nested", TimeSeriesDimension: &tsDim, Properties: map[string]esast.FieldProperty{"x": {Type: "keyword"}}},
		},
	}, []string{"host"})
	_ = schema.ValidateTSDBMapping(&esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"@timestamp": {Type: "date"},
			"host":       {Type: "passthrough", Subobjects: &subTrue},
		},
	}, []string{"host"})
	_ = schema.ValidateTSDBMapping(&esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"@timestamp": {Type: "date"},
			"host":       {Type: "passthrough"},
		},
	}, []string{"host"})

	// 4. membackend: evalWhereExpr IS NULL on slices + SEARCH(..., 'AND'/'OR')
	memRows := []map[string]any{
		{"_id": "1", "empty_arr": []any{}, "non_arr": []string{"x"}, "flt_arr": []float64{1.2}, "body": "alpha beta"},
	}
	if !evalWhereExpr(memRows[0], "`empty_arr` IS NULL") || evalWhereExpr(memRows[0], "`non_arr` IS NULL") || evalWhereExpr(memRows[0], "`flt_arr` IS NULL") {
		t.Fatal("unexpected IS NULL slice result")
	}
	if !evalWhereExpr(memRows[0], "SEARCH('alpha beta', 'body', 'AND')") || !evalWhereExpr(memRows[0], "SEARCH('body:alpha', 'ignored', 'OR')") {
		t.Fatal("unexpected SEARCH(...) result")
	}

	// 5. round64_spatial_search_aggs: centroidAccumR64, minDistanceMetersFromGeomR64, validateGeoGridQueryFieldsR64
	var ca centroidAccumR64
	ca.addGeom(parsedGeomR64{kind: geomPointR64, pt: [2]float64{10, 20}})
	ca.addGeom(parsedGeomR64{kind: geomLineR64, line: [][2]float64{{0, 0}, {0, 2}}})
	ca.addGeom(parsedGeomR64{kind: geomLineR64, line: [][2]float64{{1, 1}, {1, 1}}})
	ca.addGeom(parsedGeomR64{kind: geomPolygonR64, outer: [][2]float64{{0, 0}, {0, 2}, {2, 2}, {2, 0}}})
	_ = minDistanceMetersFromGeomR64(parsedGeomR64{kind: geomPolygonR64, outer: [][2]float64{{0, 0}, {0, 1}, {1, 1}, {1, 0}}}, 0.5, 0.5)
	_ = pointInPolygonR64(0.5, 0.5, [][2]float64{{0, 0}, {0, 1}, {1, 1}, {1, 0}}, nil)

	geoBadSch := schema.CompileIndexSchema("es", "geobad", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"num":   {Type: "integer"},
			"noind": {Type: "keyword", Index: new(bool)},
		},
	})
	var qWrap esast.Query
	if err := json.Unmarshal([]byte(`{"bool":{"should":[{"dis_max":{"queries":[{"constant_score":{"filter":{"boosting":{"positive":{"pinned":{"ids":["1"],"organic":{"geo_grid":{"num":{"geotile":"1/0/0"}}}}},"negative":{"match_all":{}},"negative_boost":0.5}}}}]}}]}}`), &qWrap); err != nil {
		t.Fatalf("unmarshal geo_grid wrap failed: %v", err)
	}
	if st, _, _ := validateGeoGridQueryFieldsR64(geoBadSch, &qWrap); st == 0 {
		t.Fatal("expected validateGeoGridQueryFieldsR64 error on integer field")
	}

	// 6. Query AST walkers: collectIdsQueriesWithInnerHits, collectTermsFromQueryForFields, hasTermsLookupInQuery, queryContainsInnerHitsR62Search
	var walkQ esast.Query
	if err := json.Unmarshal([]byte(`{
		"bool":{
			"must":[
				{"constant_score":{"filter":{"pinned":{"ids":["1"],"organic":{"ids":{"values":["2"],"_name":"n2"}}}}}},
				{"boosting":{"positive":{"dis_max":{"queries":[{"function_score":{"query":{"script_score":{"query":{"terms":{"_id":["1"]}},"script":{"source":"1"}}}}}]}},"negative":{"match_all":{}},"negative_boost":0.5}}
			],
			"should":[{"span_containing":{"big":{"span_term":{"title":"hello"}},"little":{"span_near":{"clauses":[{"span_or":{"clauses":[{"span_term":{"title":"world"}}]}}],"slop":1,"in_order":true}}}}],
			"filter":[{"span_within":{"big":{"span_first":{"match":{"span_term":{"title":"top"}},"end":3}},"little":{"field_masking_span":{"field":"title","query":{"span_term":{"cat":"mask"}}}}}}],
			"must_not":[{"nested":{"path":"items","query":{"match_all":{}},"inner_hits":{"name":"ih"}}}]
		}
	}`), &walkQ); err != nil {
		t.Fatalf("unmarshal walkQ failed: %v", err)
	}
	var idsOut []*esast.IdsQuery
	collectIdsQueriesWithInnerHits(&walkQ, &idsOut)
	var termsOut []string
	collectTermsFromQueryForFields(&walkQ, map[string]bool{"title": true}, &termsOut)
	_ = hasTermsLookupInQuery(&walkQ)
	_ = queryContainsInnerHitsR62Search(&walkQ)
}

func TestRound66CovBackends_UnitAggsSpatialSettingsHalfFloatAndShredderEdges(t *testing.T) {
	// 1. aggTypePrefix across all AggSpec variants
	aggTypeJSONs := []string{
		`{"rate":{"field":"ts","unit":"day"}}`,
		`{"avg_bucket":{"buckets_path":"a"}}`,
		`{"sum_bucket":{"buckets_path":"a"}}`,
		`{"min_bucket":{"buckets_path":"a"}}`,
		`{"max_bucket":{"buckets_path":"a"}}`,
		`{"stats_bucket":{"buckets_path":"a"}}`,
		`{"extended_stats_bucket":{"buckets_path":"a"}}`,
		`{"percentiles_bucket":{"buckets_path":"a"}}`,
		`{"derivative":{"buckets_path":"a"}}`,
		`{"cumulative_cardinality":{"buckets_path":"a"}}`,
		`{"cumulative_sum":{"buckets_path":"a"}}`,
		`{"moving_percentiles":{"buckets_path":"a"}}`,
		`{"moving_avg":{"buckets_path":"a"}}`,
		`{"moving_fn":{"buckets_path":"a","window":2,"script":"MovingFunctions.sum(values)"}}`,
		`{"serial_diff":{"buckets_path":"a"}}`,
		`{"normalize":{"buckets_path":"a","method":"percent_of_sum"}}`,
		`{"bucket_script":{"buckets_path":{"a":"a"},"script":"params.a"}}`,
		`{"bucket_sort":{"size":1}}`,
		`{"bucket_selector":{"buckets_path":{"a":"a"},"script":"params.a > 0"}}`,
		`{"rare_terms":{"field":"cat"}}`,
		`{"multi_terms":{"terms":[{"field":"cat"}]}}`,
		`{"auto_date_histogram":{"field":"ts"}}`,
		`{"weighted_avg":{"value":{"field":"p"},"weight":{"field":"w"}}}`,
		`{"median_absolute_deviation":{"field":"p"}}`,
		`{"geo_bounds":{"field":"g"}}`,
		`{"geo_centroid":{"field":"g"}}`,
		`{"cartesian_bounds":{"field":"pt"}}`,
		`{"cartesian_centroid":{"field":"pt"}}`,
		`{"geo_line":{"point":{"field":"g"},"sort":{"field":"ts"}}}`,
		`{"geo_distance":{"field":"g","origin":{"lat":0,"lon":0},"ranges":[{"to":10}]}}`,
		`{"geohash_grid":{"field":"g","precision":3}}`,
		`{"geotile_grid":{"field":"g","precision":3}}`,
		`{"geohex_grid":{"field":"g","precision":3}}`,
		`{"adjacency_matrix":{"filters":{"a":{"term":{"cat":"x"}}}}}`,
		`{"matrix_stats":{"fields":["p"]}}`,
		`{"t_test":{"a":{"field":"p"},"b":{"field":"p"}}}`,
		`{"terms":{"field":"cat"}}`,
		`{"range":{"field":"p","ranges":[{"to":10}]}}`,
		`{"date_range":{"field":"ts","ranges":[{"to":"now"}]}}`,
		`{"filter":{"match_all":{}}}`,
		`{"filters":{"filters":{"a":{"match_all":{}}}}}`,
		`{"sum":{"field":"p"}}`,
		`{"avg":{"field":"p"}}`,
		`{"min":{"field":"p"}}`,
		`{"max":{"field":"p"}}`,
		`{"value_count":{"field":"p"}}`,
		`{"cardinality":{"field":"p"}}`,
		`{"stats":{"field":"p"}}`,
		`{"extended_stats":{"field":"p"}}`,
		`{"date_histogram":{"field":"ts","fixed_interval":"1d"}}`,
		`{"histogram":{"field":"p","interval":1}}`,
	}
	rollupOut := make(map[string]any)
	rollupSpecs := make(map[string]esast.AggSpec)
	for i, j := range aggTypeJSONs {
		var sp esast.AggSpec
		if err := json.Unmarshal([]byte(j), &sp); err != nil {
			t.Fatalf("AggSpec %s unmarshal failed: %v", j, err)
		}
		if pref := aggTypePrefix(sp); pref == "" {
			t.Fatalf("empty aggTypePrefix for %s", j)
		}
		_ = typedKeyPrefixForAggSpecR65(sp)
		k := fmt.Sprintf("a%d", i)
		rollupSpecs[k] = sp
		rollupOut[k] = map[string]any{"value": 1.0}
	}
	typedRoll := applyTypedKeysToRollupAggsR65(rollupOut, rollupSpecs)
	_ = normalizeTypedKeysValueR61Search(typedRoll)

	// 2. resolveAggregateMetricDefaultRound61 & extractAggregateMetricScalarRound61
	amdSch := schema.CompileIndexSchema("es", "amd", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"obj": {Properties: map[string]esast.FieldProperty{
				"m": {Type: "aggregate_metric_double", Metrics: []string{"min", "max", "sum", "value_count"}, DefaultMetric: "max"},
			}},
		},
	})
	if dm := resolveAggregateMetricDefaultRound61(amdSch, "obj.m"); dm != "max" {
		t.Fatalf("expected DefaultMetric max, got %q", dm)
	}
	if av, ok := extractAggregateMetricScalarRound61(map[string]any{"sum": 10.0, "value_count": 2}, "avg"); !ok || av != 5.0 {
		t.Fatalf("expected avg=5, got %v %v", av, ok)
	}

	// 3. evalMovingFnWindowR61Search: direct valid MovingFunctions, NaN, conditional if-return
	for _, src := range []string{
		`MovingFunctions.sum(values)`,
		`MovingFunctions.unweightedAvg(values)`,
		`Double.NaN`,
		`if (values.length > 0) { return values[0]; }`,
		`if (values.length > 99) { return 1.0; }`,
	} {
		var ma esast.MovingAvgAggSpec
		_ = json.Unmarshal([]byte(fmt.Sprintf(`{"buckets_path":"s","window":3,"script":%q}`, src)), &ma)
		if _, err := evalMovingFnWindowR61Search([]float64{2, 4, 6}, &ma); err != nil {
			t.Fatalf("evalMovingFnWindowR61Search(%q) failed: %v", src, err)
		}
	}

	// 4. resolveKNNQueryVectorR61Search (hex bit, hex byte, byte array -> bit), extractNestedChildMapsPreservingOffsetsR61Search
	_ = resolveKNNQueryVectorR61Search(&esast.KNNQuery{QueryVectorFromHex: true, QueryVectorHex: "0f"}, "bit", 8)
	_ = resolveKNNQueryVectorR61Search(&esast.KNNQuery{QueryVectorFromHex: true, QueryVectorHex: "01ff"}, "byte", 2)
	_ = resolveKNNQueryVectorR61Search(&esast.KNNQuery{QueryVector: []float64{-1, 127}}, "bit", 16)
	nestedDoc := map[string]any{"a": []any{map[string]any{"b": map[string]any{"c": 1}}, map[string]any{"b": []any{map[string]any{"c": 2}}}}}
	if res := extractNestedChildMapsPreservingOffsetsR61Search(nestedDoc, "a.b"); len(res) != 2 {
		t.Fatalf("expected 2 extracted child maps, got %v", res)
	}

	// 5. geomIntersectsQueryShapeR64 line-line, line-polygon, polygon-line, polygon-polygon
	lineA := parsedGeomR64{kind: geomLineR64, line: [][2]float64{{0, 0}, {2, 2}}}
	lineB := parsedGeomR64{kind: geomLineR64, line: [][2]float64{{0, 2}, {2, 0}}}
	polyA := parsedGeomR64{kind: geomPolygonR64, outer: [][2]float64{{0, 0}, {0, 3}, {3, 3}, {3, 0}}}
	polyB := parsedGeomR64{kind: geomPolygonR64, outer: [][2]float64{{1, 1}, {1, 4}, {4, 4}, {4, 1}}}
	if !geomIntersectsQueryShapeR64(lineA, lineB) || !geomIntersectsQueryShapeR64(lineA, polyA) || !geomIntersectsQueryShapeR64(polyA, lineA) || !geomIntersectsQueryShapeR64(polyA, polyB) {
		t.Fatal("expected spatial shape intersections true")
	}

	// 6. quantizeHalfFloatRound64, estimateJSONMarshalBytesBoundedR66, lookupRawIndexSettingPresenceR62Admin, countDocVectorFieldPresenceR63Admin, splitESQLStatsByClause, extractStringSliceAny
	for _, fv := range []float64{0, math.NaN(), math.Inf(1), 1e-6, 100000.0, 1.00048828125, -3.5} {
		_ = quantizeHalfFloatRound64(fv)
	}
	_, _ = estimateJSONMarshalBytesBoundedR66(map[string]any{"s": strings.Repeat("x", 100)}, 0, 50)
	_, _ = estimateJSONMarshalBytesBoundedR66([]any{nil, true, 123, "abc"}, 0, 1000)
	_, _ = estimateJSONMarshalBytesBoundedR66("a", maxIngestTemplateDepthR66+1, 100)
	_, _ = lookupRawIndexSettingPresenceR62Admin(map[string]any{"index": map[string]any{"routing": map[string]any{"allocation": map[string]any{"require": "warm"}}}}, "routing.allocation.require")
	_, _ = lookupRawIndexSettingPresenceR62Admin(map[string]any{"custom": map[string]any{"nested": "v"}}, "custom.nested")
	_ = countDocVectorFieldPresenceR63Admin(map[string]any{"arr": []any{map[string]any{"v": []any{[]any{1.0, 2.0}}}}}, "arr.v", false)
	_ = countDocVectorFieldPresenceR63Admin(map[string]any{"sv": map[string]any{"k": 1.0}}, "sv", true)
	k1, b1 := splitESQLStatsByClause(`c = COUNT("by") BY cat, ` + "`by`")
	if k1 == "" || b1 == "" {
		t.Fatalf("splitESQLStatsByClause failed: %q | %q", k1, b1)
	}
	_ = extractStringSliceAny("[a, b, c]")
	_ = extractStringSliceAny("[a b]")
	_ = extractStringSliceAny([]string{"x"})

	// 7. schema.ShredDocumentWithNow date_nanos out-of-range + copy_to non-string scalar + multi-field ignore_above
	dnSch := schema.CompileIndexSchema("es", "dnerr", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{"dn": {Type: "date_nanos"}},
	})
	if _, err := schema.ShredDocumentWithNow(dnSch, "1", 1, false, json.RawMessage(`{"dn":"2500-01-01T00:00:00Z"}`), time.Now().UTC()); err == nil {
		t.Fatal("expected date_nanos out of range error")
	}
}

func TestRound66CovBackends_DirectSQLSynthAndRound64Batch5(t *testing.T) {
	// 1. detectDorisLambdaCastArrayType across single/double/backtick/nested-paren quoting
	if gotArr, okLambda := detectDorisLambdaCastArrayType(`(_x) -> CAST('a''b' AS STRING) AND CAST("x\"y" AS BIGINT) AND CAST(` + "`c``1`" + ` AS DOUBLE) AND TRY_CAST((_x) AS INT)`); !okLambda || gotArr != "ARRAY<INT>" {
		t.Fatalf("expected (ARRAY<INT>, true) for nested INT cast on _x, got (%q, %v)", gotArr, okLambda)
	}

	// 2. schema.ReconstructSyntheticSource on histogram, geo_point (position), dense_vector (byte hex + float), flattened, rank_features, sparse_vector, integer_range
	synthSch := schema.CompileIndexSchema("es", "synth_cov", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"@timestamp": {Type: "date"},
			"hist":       {Type: "histogram"},
			"pos":        {Type: "geo_point", TimeSeriesMetric: "position"},
			"gp":         {Type: "geo_point"},
			"dv_b":       {Type: "dense_vector", Dims: 2, ElementType: "byte"},
			"dv_f":       {Type: "dense_vector", Dims: 2, ElementType: "float"},
			"rng":        {Type: "integer_range"},
			"flat":       {Type: "flattened"},
			"rf":         {Type: "rank_features"},
			"sv":         {Type: "sparse_vector"},
		},
	})
	_ = schema.ReconstructSyntheticSource(synthSch, map[string]any{
		"@timestamp": "2026-01-01T00:00:00Z",
		"hist":       map[string]any{"values": []any{1.0, 2.0}, "counts": []any{1, 2}},
		"pos":        map[string]any{"lat": 10.0, "lon": 20.0},
		"gp":         "10.0,20.0",
		"dv_b":       "0102",
		"dv_f":       []any{1.5, 2.5},
		"rng":        map[string]any{"gte": 1, "lte": 10},
		"flat":       map[string]any{"a": "b"},
		"rf":         map[string]any{"f1": 1.2},
		"sv":         map[string]any{"tok": 0.5},
	}, nil)

	// 3. aggsHaveMinDocCountZeroR64, resolveAPIKeyUsernameFromHeaderR64, resolveAggregateMetricDefaultRound61 (RawMapping only), checkDestAutoCreateIndexExactRound61
	for _, aj := range []string{
		`{"r":{"range":{"field":"p","min_doc_count":0,"ranges":[{"to":10}]}}}`,
		`{"dr":{"date_range":{"field":"ts","min_doc_count":0,"ranges":[{"to":"now"}]}}}`,
		`{"ir":{"ip_range":{"field":"ip","min_doc_count":0,"ranges":[{"mask":"10.0.0.0/8"}]}}}`,
		`{"h":{"histogram":{"field":"p","interval":1,"min_doc_count":0}}}`,
		`{"dh":{"date_histogram":{"field":"ts","fixed_interval":"1d","min_doc_count":0}}}`,
		`{"adh":{"auto_date_histogram":{"field":"ts","buckets":3,"minimum_interval":"day"}}}`,
	} {
		var m map[string]esast.AggSpec
		_ = json.Unmarshal([]byte(aj), &m)
		_ = aggsHaveMinDocCountZeroR64(m)
	}
	keysMap := map[string]map[string]any{"k1": {"username": "alice"}}
	if u := resolveAPIKeyUsernameFromHeaderR64("aGVsbG8=", keysMap); u != "" {
		t.Fatalf("expected empty without colon, got %q", u)
	}
	if u := resolveAPIKeyUsernameFromHeaderR64("k1:sec", keysMap); u != "" {
		t.Fatalf("expected empty username for non-base64 API key, got %q", u)
	}
	if u := resolveAPIKeyUsernameFromHeaderR64("azE6c2Vj", keysMap); u != "alice" {
		t.Fatalf("expected alice from valid base64 k1:sec, got %q", u)
	}

	rawOnlySch := &schema.IndexSchema{
		RawMapping: &esast.MappingSpec{
			Properties: map[string]esast.FieldProperty{
				"obj": {Properties: map[string]esast.FieldProperty{
					"m": {Type: "aggregate_metric_double", DefaultMetric: "min"},
				}},
			},
		},
	}
	if dm := resolveAggregateMetricDefaultRound61(rawOnlySch, "obj.m"); dm != "min" {
		t.Fatalf("expected min from RawMapping, got %q", dm)
	}

	srv, _ := newR66CovServer(t, "8.15.0")
	for _, setting := range []string{"false", "-blk*,+allow*", "+only_this*"} {
		srv.mu.Lock()
		srv.clusterTransientSettings["action.auto_create_index"] = setting
		srv.mu.Unlock()
		_, _, _ = srv.checkDestAutoCreateIndexExactRound61("blk_idx")
		_, _, _ = srv.checkDestAutoCreateIndexExactRound61("allow_idx")
		_, _, _ = srv.checkDestAutoCreateIndexExactRound61("other_idx")
	}
}

func TestRound66CovBackends_CopyToTypedMultiFieldTombstonesAndTermsLookup(t *testing.T) {
	// 1. schema.ShredDocumentWithNow copy_to targeting a typed non-string scalar + typed non-string multi-field
	mSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"src_num": {Type: "keyword", CopyTo: []string{"num_tgt", "txt_tgt"}},
			"num_tgt": {Type: "integer", IgnoreMalformed: boolPtrR66Cov(true)},
			"txt_tgt": {
				Type: "text",
				Fields: map[string]esast.FieldProperty{
					"int_sub": {Type: "integer", IgnoreMalformed: boolPtrR66Cov(true)},
					"str_sub": {Type: "keyword", IgnoreAbove: 5},
				},
			},
		},
	}
	idxSch := schema.CompileIndexSchema("es_r66", "copy_num_idx", mSpec)
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if _, err := schema.ShredDocumentWithNow(idxSch, "1", 1, false, json.RawMessage(`{"src_num":"42"}`), now); err != nil {
		t.Fatalf("ShredDocumentWithNow valid numeric copy_to failed: %v", err)
	}
	if _, err := schema.ShredDocumentWithNow(idxSch, "2", 1, false, json.RawMessage(`{"src_num":["", "not_int", "123456"]}`), now); err != nil {
		t.Fatalf("ShredDocumentWithNow ignore_malformed copy_to failed: %v", err)
	}

	strictSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"src":        {Type: "keyword", CopyTo: []string{"strict_num"}},
			"strict_num": {Type: "integer"},
		},
	}
	strictSch := schema.CompileIndexSchema("es_r66", "copy_strict_num", strictSpec)
	if _, err := schema.ShredDocumentWithNow(strictSch, "3", 1, false, json.RawMessage(`{"src":"bad_int"}`), now); err == nil {
		t.Fatal("expected mapper_parsing_exception on strict non-string copy_to target")
	}

	strictSubSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"src": {Type: "keyword", CopyTo: []string{"holder"}},
			"holder": {
				Type: "text",
				Fields: map[string]esast.FieldProperty{
					"strict_sub": {Type: "integer"},
				},
			},
		},
	}
	strictSubSch := schema.CompileIndexSchema("es_r66", "copy_strict_sub", strictSubSpec)
	if _, err := schema.ShredDocumentWithNow(strictSubSch, "4", 1, false, json.RawMessage(`{"src":"bad_int"}`), now); err == nil {
		t.Fatal("expected mapper_parsing_exception on strict non-string copy_to multi-field")
	}

	// 2. recordTSDBTombstoneVersionR63 stale TTL pruning + maxTSDBTombstonesPerServerR63 eviction
	srv, h := newR66CovServer(t, "8.15.0")
	mustR66CovHTTP(t, h, http.MethodPut, "/tsdb_tomb_cov", `{
		"settings":{"index.mode":"time_series","index.routing_path":["host"]},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true},"v":{"type":"double","time_series_metric":"gauge"}}}
	}`, http.StatusOK)
	t.Cleanup(func() {
		tsdbTombstoneMuR63.Lock()
		delete(tsdbTombstonesBySrvR63, srv)
		tsdbTombstoneMuR63.Unlock()
	})
	tsdbTombstoneMuR63.Lock()
	seedDocs := make(map[string]tsdbTombstoneEntryR63, maxTSDBTombstonesPerServerR63+5)
	seedDocs["stale_doc"] = tsdbTombstoneEntryR63{version: 1, updatedAt: 1}
	for i := 0; i < maxTSDBTombstonesPerServerR63+3; i++ {
		seedDocs[fmt.Sprintf("d_%06d", i)] = tsdbTombstoneEntryR63{version: 1, updatedAt: time.Now().UnixNano() - int64(i)}
	}
	tsdbTombstonesBySrvR63[srv] = map[string]map[string]tsdbTombstoneEntryR63{
		"tsdb_tomb_cov": seedDocs,
		"empty_stale_idx": {
			"old1": {version: 1, updatedAt: 1},
		},
	}
	tsdbTombstoneMuR63.Unlock()
	srv.recordTSDBTombstoneVersionR63("tsdb_tomb_cov", "fresh_doc", 2)

	// 3. hasTermsLookupInQuery & resolveTermsLookupsInQuery across every query AST branch
	mustR66CovHTTP(t, h, http.MethodPut, "/lk_vals", `{"mappings":{"properties":{"vals":{"type":"keyword"}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/lk_vals/_doc/1?refresh=true", `{"vals":["a","b"]}`, http.StatusCreated)

	newLookupLeaf := func() esast.Query {
		return esast.Query{Terms: &esast.TermsQuery{Lookups: map[string]esast.TermsLookupSpec{"f": {Index: "lk_vals", ID: "1", Path: "vals"}}}}
	}
	emptyLeaf := esast.Query{MatchAll: map[string]any{}}
	mkBranch := func(fn func(esast.Query) esast.Query) esast.Query {
		return fn(newLookupLeaf())
	}
	branches := []esast.Query{
		mkBranch(func(l esast.Query) esast.Query {
			return esast.Query{Bool: &esast.BoolQuery{Should: []esast.Query{emptyLeaf, l}}}
		}),
		mkBranch(func(l esast.Query) esast.Query {
			return esast.Query{Bool: &esast.BoolQuery{Filter: []esast.Query{emptyLeaf, l}}}
		}),
		mkBranch(func(l esast.Query) esast.Query {
			return esast.Query{Bool: &esast.BoolQuery{MustNot: []esast.Query{emptyLeaf, l}}}
		}),
		mkBranch(func(l esast.Query) esast.Query {
			return esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: l}}
		}),
		mkBranch(func(l esast.Query) esast.Query {
			return esast.Query{DisMax: &esast.DisMaxQuery{Queries: []esast.Query{emptyLeaf, l}}}
		}),
		mkBranch(func(l esast.Query) esast.Query {
			return esast.Query{Boosting: &esast.BoostingQuery{Positive: emptyLeaf, Negative: l}}
		}),
		mkBranch(func(l esast.Query) esast.Query { return esast.Query{Nested: &esast.NestedQuery{Path: "n", Query: l}} }),
		mkBranch(func(l esast.Query) esast.Query {
			return esast.Query{FunctionScore: &esast.FunctionScoreQuery{Query: &emptyLeaf, Functions: []esast.ScoreFunctionSpec{{Filter: &l}}}}
		}),
		mkBranch(func(l esast.Query) esast.Query { return esast.Query{ScriptScore: &esast.ScriptScoreQuery{Query: &l}} }),
		mkBranch(func(l esast.Query) esast.Query {
			return esast.Query{KNN: &esast.KNNQuery{Filter: []esast.Query{emptyLeaf, l}}}
		}),
		mkBranch(func(l esast.Query) esast.Query { return esast.Query{Wrapper: &esast.WrapperQuery{Decoded: &l}} }),
		mkBranch(func(l esast.Query) esast.Query { return esast.Query{Pinned: &esast.PinnedQuery{Organic: &l}} }),
		mkBranch(func(l esast.Query) esast.Query { return esast.Query{HasChild: &esast.HasChildQuery{Query: l}} }),
		mkBranch(func(l esast.Query) esast.Query { return esast.Query{HasParent: &esast.HasParentQuery{Query: l}} }),
	}
	for i := range branches {
		q := branches[i]
		if !hasTermsLookupInQuery(&q) {
			t.Fatalf("expected hasTermsLookupInQuery=true for branch %d", i)
		}
		srv.resolveTermsLookupsInQuery(context.Background(), &q)
	}
	if hasTermsLookupInQuery(&esast.Query{Bool: &esast.BoolQuery{Must: []esast.Query{emptyLeaf}, Should: []esast.Query{emptyLeaf}, Filter: []esast.Query{emptyLeaf}, MustNot: []esast.Query{emptyLeaf}}}) {
		t.Fatal("expected hasTermsLookupInQuery=false for match_all leaves")
	}
}

func boolPtrR66Cov(v bool) *bool { return &v }

func TestRound66CovBackends_PureHelpersDateYAMLIOSQLStatsAndSchemaWalks(t *testing.T) {
	// 1. convertESDateFormatToGoLayouts
	for _, fm := range []string{
		"ISO8601", "strict_date_optional_time", "UNIX", "epoch_second", "UNIX_MS", "epoch_millis",
		"TAI64N", "ordinal_date", "ordinal_date_no_millis", "ordinal_date_time",
		"ordinal_date_time_no_millis", "basic_ordinal_date", "basic_ordinal_date_time",
		"basic_ordinal_date_time_no_millis", "basic_date", "basic_date_time",
		"basic_date_time_no_millis", "date", "date_time", "date_time_no_millis",
		"date_hour_minute_second", "date_hour_minute_second_millis", "rfc_1123_date_time",
		"uuuu-MM-dd HH:mm:ss",
	} {
		if layouts := convertESDateFormatToGoLayouts(fm); len(layouts) == 0 {
			t.Fatalf("empty layouts for format %q", fm)
		}
	}

	// 2. writeYAMLValueWireR64 across scalars, maps, empty containers, special keys, slice of maps/values, and max recursion depth
	var ybuf strings.Builder
	deep := map[string]any{"leaf": "x"}
	for i := 0; i < 40; i++ {
		deep = map[string]any{"wrap": deep}
	}
	writeYAMLValueWireR64(&ybuf, map[string]any{
		"nil":        nil,
		"bool":       true,
		"num":        json.Number("42"),
		"flt":        3.25,
		"str":        "hello",
		"a: special": "v",
		"empty_map":  map[string]any{},
		"empty_arr":  []any{},
		"empty_ms":   []map[string]any{},
		"items":      []any{"x", 1, map[string]any{"k": "v"}},
		"maps":       []map[string]any{{}, {"m": 1, "n": []any{true}}},
		"deep":       deep,
	}, 0, false)
	if !strings.Contains(ybuf.String(), "empty_map: {}") {
		t.Fatalf("unexpected YAML output: %s", ybuf.String())
	}

	// 3. setIngestPathMergeWithOverride
	doc := map[string]any{
		"obj":  map[string]any{"a": 1},
		"keep": "orig",
		"scal": "scalar_v",
		"arr":  []any{nil, map[string]any{"x": 1}},
	}
	setIngestPathMergeWithOverride(doc, "obj", map[string]any{"b": 2}, false)
	setIngestPathMergeWithOverride(doc, "keep", "new", false)
	setIngestPathMergeWithOverride(doc, "scal.sub", "fail_no_override", false)
	setIngestPathMergeWithOverride(doc, "scal.sub", "ok_override", true)
	setIngestPathMergeWithOverride(doc, "arr.0.k", "zero", true)
	setIngestPathMergeWithOverride(doc, "arr.bad.k", "ignored", true)
	setIngestPathMergeWithOverride(doc, "new_nested.a.b", 9, true)

	// 4. formatESQLBoundLiteral & evalSQLScalarFunc
	for _, lit := range []any{
		nil,
		map[string]any{"n1": nil},
		map[string]any{"n2": "hi"},
		true,
		false,
		json.Number("99"),
		float64(1.25),
		float64(1e25),
		float32(2.5),
		float32(1e25),
		int64(7),
	} {
		if s := formatESQLBoundLiteral(lit); s == "" {
			t.Fatalf("empty literal for %#v", lit)
		}
	}
	sqlCases := []struct {
		fn   string
		args []any
	}{
		{"LOWER", []any{nil}}, {"LOWER", []any{"AB"}},
		{"UPPER", []any{nil}}, {"UPPER", []any{"ab"}},
		{"LENGTH", []any{nil}}, {"LENGTH", []any{"abc"}},
		{"CONCAT", []any{"a", nil}}, {"CONCAT", []any{"a", "b"}},
		{"SUBSTRING", []any{"abc"}}, {"SUBSTRING", []any{"abc", "bad"}},
		{"SUBSTRING", []any{"abc", 0}}, {"SUBSTRING", []any{"abc", 9}},
		{"SUBSTRING", []any{"abc", 1, 0}}, {"SUBSTRING", []any{"abc", 1, 20}},
		{"SUBSTRING", []any{"abc", 2}},
		{"TRIM", []any{nil}}, {"TRIM", []any{" x "}},
		{"LTRIM", []any{nil}}, {"LTRIM", []any{" x"}},
		{"RTRIM", []any{nil}}, {"RTRIM", []any{"x "}},
		{"COALESCE", []any{nil, "ok"}}, {"COALESCE", []any{nil}},
		{"IFNULL", []any{"a"}}, {"IFNULL", []any{nil, "b"}},
		{"ABS", []any{-3.5}}, {"ABS", []any{nil}},
		{"ROUND", []any{3.456, 2}}, {"ROUND", []any{3.6}},
		{"FLOOR", []any{3.9}}, {"CEIL", []any{3.1}},
		{"SQRT", []any{16.0}}, {"SQRT", []any{-1.0}},
		{"MOD", []any{10, 3}}, {"MOD", []any{10, 0}},
	}
	for _, sc := range sqlCases {
		_ = evalSQLScalarFunc(sc.fn, sc.args)
	}

	// 5. parseESSignedOffsetMillisR65, collectRollupQueryFieldsR65, compareTermsAnyOrderValR65, formatESDurationR61Admin, resolveFieldAcrossDocLookupAndSchemaR65
	if parseESSignedOffsetMillisR65("") != 0 || parseESSignedOffsetMillisR65("-2h") >= 0 || parseESSignedOffsetMillisR65("+15m") <= 0 || parseESSignedOffsetMillisR65("bogus") != 0 {
		t.Fatal("unexpected parseESSignedOffsetMillisR65 outputs")
	}
	qFields := make(map[string]bool)
	collectRollupQueryFieldsR65(nil, qFields)
	var rq esast.Query
	if err := json.Unmarshal([]byte(`{
		"bool": {
			"must": [{"term": {"bm": 1}}],
			"filter": [{"match": {"m": "v"}}],
			"should": [{"range": {"r": {"gte": 1}}}, {"terms": {"ts.keyword": ["a"]}}, {"term": {"t.keyword": "x"}}]
		}
	}`), &rq); err != nil {
		t.Fatalf("unmarshal rollup query failed: %v", err)
	}
	collectRollupQueryFieldsR65(&rq, qFields)
	if !qFields["t"] || !qFields["ts"] || !qFields["m"] || !qFields["r"] || !qFields["bm"] {
		t.Fatalf("missing collected rollup fields: %#v", qFields)
	}
	if compareTermsAnyOrderValR65(1, 2) >= 0 || compareTermsAnyOrderValR65(5, 2) <= 0 || compareTermsAnyOrderValR65(3, 3.0) != 0 || compareTermsAnyOrderValR65("a", "b") >= 0 {
		t.Fatal("unexpected compareTermsAnyOrderValR65")
	}
	for _, d := range []time.Duration{0, 48 * time.Hour, 3 * time.Hour, 5 * time.Minute, 7 * time.Second, 25 * time.Millisecond, 15 * time.Microsecond, 99 * time.Nanosecond} {
		if formatESDurationR61Admin(d) == "" {
			t.Fatalf("empty formatESDurationR61Admin for %v", d)
		}
	}

	altSch := schema.CompileIndexSchema("es_r66", "alt_lookup_idx", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{"alt_f": {Type: "integer"}},
	})
	scopeLookup := func(id string) *HitRow {
		if id == r63DocLookupScopeSentinel {
			return &HitRow{SearchScope: &activeSearchScope{
				schemasByIndex: map[string]*schema.IndexSchema{"alt_lookup_idx": altSch, "nil_idx": nil},
			}}
		}
		return nil
	}
	if fb := resolveFieldAcrossDocLookupAndSchemaR65("alt_f", nil, scopeLookup); fb.ESType != "integer" {
		t.Fatalf("expected integer from cross-index lookup schema, got %+v", fb)
	}
	_ = resolveFieldAcrossDocLookupAndSchemaR65("missing_f", altSch, scopeLookup)

	// 6. Server helpers: resolveIndexBoostFactor, validateDirectBackingIndexWriteR62Search, formatComponentTemplateForOutputR62Admin, wrapMappingsResponseForTypeR61CRUD, extractSearchStatsGroupsFromBodyRound61
	srv, h := newR66CovServer(t, "8.15.0")
	mustR66CovHTTP(t, h, http.MethodPut, "/boost_idx_1", `{}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"boost_idx_1","alias":"boost_al"}}]}`, http.StatusOK)
	if f, ok := srv.resolveIndexBoostFactor("boost_idx_1", map[string]float64{"boost_al": 2.5}); !ok || f != 2.5 {
		t.Fatalf("expected alias boost 2.5, got %v ok=%v", f, ok)
	}
	if f, ok := srv.resolveIndexBoostFactor("boost_idx_1", map[string]float64{"boost_*": 3.0}); !ok || f != 3.0 {
		t.Fatalf("expected wildcard boost 3.0, got %v ok=%v", f, ok)
	}
	if _, ok := srv.resolveIndexBoostFactor("boost_idx_1", map[string]float64{"other": 4.0}); ok {
		t.Fatal("expected unmatched boost ok=false")
	}

	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/b7_ds_tpl", `{"index_patterns":["b7_ds*"],"data_stream":{},"template":{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_data_stream/b7_ds", "", http.StatusOK)
	dsInfo := mustR66CovHTTP(t, h, http.MethodGet, "/_data_stream/b7_ds", "", http.StatusOK)
	dsList, _ := dsInfo["data_streams"].([]any)
	dsObj, _ := dsList[0].(map[string]any)
	dsIdxs, _ := dsObj["indices"].([]any)
	backingIdx, _ := dsIdxs[0].(map[string]any)["index_name"].(string)
	if st, _, _ := srv.validateDirectBackingIndexWriteR62Search(backingIdx, true, false); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on direct ds backing create, got %d", st)
	}
	if st, _, _ := srv.validateDirectBackingIndexWriteR62Search(backingIdx, false, false); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on direct ds backing index without seq_no, got %d", st)
	}
	if st, _, _ := srv.validateDirectBackingIndexWriteR62Search(backingIdx, false, true); st != 0 {
		t.Fatalf("expected 0 on direct ds backing index with seq_no, got %d", st)
	}

	_ = formatComponentTemplateForOutputR62Admin(nil, true, true, true)
	formattedComp := formatComponentTemplateForOutputR62Admin(map[string]any{
		"template": map[string]any{
			"settings":  map[string]any{"index.number_of_shards": "1"},
			"lifecycle": map[string]any{"data_retention": "7d"},
		},
	}, true, true, true)
	if tpl, _ := formattedComp["template"].(map[string]any); tpl == nil || tpl["lifecycle"] == nil {
		t.Fatalf("unexpected formatted component template: %#v", formattedComp)
	}

	_ = wrapMappingsResponseForTypeR61CRUD(&schema.IndexSchema{}, nil, true, "other_t")
	_ = wrapMappingsResponseForTypeR61CRUD(&schema.IndexSchema{}, map[string]any{}, true, "_doc")
	if gs := extractSearchStatsGroupsFromBodyRound61([]byte(`{"stats":["g1","g2"]}`)); len(gs) != 2 {
		t.Fatalf("expected 2 stats groups, got %#v", gs)
	}
	if gs := extractSearchStatsGroupsFromBodyRound61([]byte(`{"stats":"single_g"}`)); len(gs) != 1 {
		t.Fatalf("expected 1 stats group, got %#v", gs)
	}
}

func TestRound66CovBackends_Batch8RuntimeCoercionFormatSliceCompareAndPipelines(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	ipVal, err := painless.ParseIPAddressVal("10.0.0.1")
	if err != nil {
		t.Fatalf("ParseIPAddressVal failed: %v", err)
	}
	zdt := &painless.ZonedDateTimeVal{Time: now}

	// 1. coerceRuntimeValuesWithScriptFlagR62Search across geo_shape, geo_point, ip, unsigned_long, long, half_float, float, double, boolean, date_nanos, date
	gp := &painless.GeoPointVal{Lat: 37.77, Lon: -122.42}
	_ = coerceRuntimeValuesWithScriptFlagR62Search("geo_shape", "", []any{nil, map[string]any{"type": "point", "coordinates": []any{1.0, 2.0}}}, now, false)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("geo_point", "", []any{gp, []any{10.0, 20.0}}, now, true)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("geo_point", "", []any{gp, []any{10.0, 20.0}}, now, false)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("ip", "", []any{ipVal, "192.168.1.1", "not_ip", 42}, now, true)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("ip", "", []any{"not_ip"}, now, false)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("unsigned_long", "", []any{
		uint64(5), -1, 3, int64(-2), int64(7),
		json.Number("9"), json.Number("18446744073709551600"), json.Number("12.0"),
		"15", "18446744073709551600", "14.5",
		float64(9e19), float64(6),
	}, now, false)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("long", "", []any{int64(3), json.Number("4"), json.Number("5.0"), "6", "7.0", float64(8.0)}, now, false)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("half_float", "", []any{1.5, "2.5"}, now, false)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("float", "", []any{1.5, "2.5"}, now, false)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("double", "", []any{1.5, "2.5"}, now, false)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("boolean", "", []any{true, "true", "1", "false", "0"}, now, true)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("date_nanos", "", []any{int64(1700000000000000000), "unparsed"}, now, true)
	_ = coerceRuntimeValuesWithScriptFlagR62Search("date", "uuuu-MM-dd", []any{zdt, "2026-03-01"}, now, false)

	// 2. formatUnifiedFieldSliceR61Search across alias target, multi-field lookup, format validation, date_nanos, date, long, unsigned_long, integer/short/byte bounds, float/half_float
	imTrue := true
	idxSch := schema.CompileIndexSchema("es_r66", "fmt_slice_idx", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"ts_nanos": {Type: "date_nanos"},
			"ts_fmt":   {Type: "date", Format: "uuuu-MM-dd"},
			"num_l":    {Type: "long", IgnoreMalformed: &imTrue},
			"num_ul":   {Type: "unsigned_long", NullValue: "7", IgnoreMalformed: &imTrue},
			"num_b":    {Type: "byte", IgnoreMalformed: &imTrue},
			"num_s":    {Type: "short", IgnoreMalformed: &imTrue},
			"num_i":    {Type: "integer", IgnoreMalformed: &imTrue},
			"num_f":    {Type: "float", IgnoreMalformed: &imTrue},
			"num_hf":   {Type: "half_float", IgnoreMalformed: &imTrue},
			"al_l":     {Type: "alias", Path: "num_l"},
			"kw":       {Type: "keyword", IgnoreAbove: 4, Fields: map[string]esast.FieldProperty{"raw": {Type: "keyword"}}},
		},
	})
	_, _, _, _ = formatUnifiedFieldSliceR61Search("al_l", "al_l", []any{nil, "bad", int64(5)}, "0.00", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("kw.raw", "kw.raw", []any{"abcdefgh", "ok"}, "", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("@timestamp", "@timestamp", []any{"2026-01-01T00:00:00Z"}, "use_field_mapping", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("ts_nanos", "ts_nanos", []any{"bad", int64(1700000000000000000)}, "strict_date_optional_time_nanos", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("ts_fmt", "ts_fmt", []any{"bad", "2026-01-01"}, "use_field_mapping", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("num_ul", "num_ul", []any{"", "bad", "18446744073709551600", int64(5)}, "", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("num_ul", "num_ul", []any{int64(5)}, "0.0", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("num_b", "num_b", []any{"bad", 999, 5}, "0", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("num_s", "num_s", []any{99999, 5}, "", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("num_i", "num_i", []any{int64(999999999999), 5}, "", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("num_f", "num_f", []any{"bad", math.Inf(1), 1.5}, "0.0", false, idxSch)
	_, _, _, _ = formatUnifiedFieldSliceR61Search("num_hf", "num_hf", []any{"bad", 1.5}, "", false, idxSch)

	// 3. compareMultiTermsTupleElemR65, resolveMinimumShouldMatch, stripPainlessCommentsForDepsRound61, ExtractRuntimeScriptFieldDepsRound61
	_ = compareMultiTermsTupleElemR65("10.0.0.1", "10.0.0.2", "ip")
	_ = compareMultiTermsTupleElemR65(uint64(1), uint64(2), "")
	_ = compareMultiTermsTupleElemR65(uint64(5), uint64(2), "")
	_ = compareMultiTermsTupleElemR65(uint64(2), uint64(2), "")
	_ = compareMultiTermsTupleElemR65(int64(1), int64(2), "")
	_ = compareMultiTermsTupleElemR65(int64(5), int64(2), "")
	_ = compareMultiTermsTupleElemR65(int64(2), int64(2), "")
	_ = compareMultiTermsTupleElemR65(uint64(5), int64(-1), "")
	_ = compareMultiTermsTupleElemR65(uint64(2), int64(5), "")
	_ = compareMultiTermsTupleElemR65(uint64(2), int64(2), "")
	_ = compareMultiTermsTupleElemR65(int64(-1), uint64(2), "")
	_ = compareMultiTermsTupleElemR65(int64(5), uint64(2), "")
	_ = compareMultiTermsTupleElemR65(int64(2), uint64(2), "")
	_ = compareMultiTermsTupleElemR65(1.5, 2.5, "")
	_ = compareMultiTermsTupleElemR65(2.5, 1.5, "")
	_ = compareMultiTermsTupleElemR65(1.5, 1.5, "")
	_ = compareMultiTermsTupleElemR65("a", "b", "")

	for _, tc := range []struct {
		msm  any
		tot  int
		noMF bool
	}{
		{nil, 0, true},
		{nil, 3, true},
		{nil, 3, false},
		{-1, 3, false},
		{2, 3, false},
		{int64(-1), 3, false},
		{int64(2), 3, false},
		{float64(-1), 3, false},
		{float64(2), 3, false},
		{json.Number("-1"), 3, false},
		{json.Number("2"), 3, false},
		{"2<75% 4<2", 2, false},
		{"2<75% 4<2", 5, false},
		{"-25%", 4, false},
		{"10%", 2, false},
	} {
		_ = resolveMinimumShouldMatch(tc.msm, tc.tot, tc.noMF)
	}

	cands := map[string]bool{"a": true, "b": true, "c": true}
	deps := ExtractRuntimeScriptFieldDepsRound61(`
		// skip doc['ignored']
		/* block doc['also_ignored'] */
		String s = "escaped \" /* keep */";
		return doc['a.keyword'].value + doc['b.sub'].value + doc.c.size();
	`, cands)
	if len(deps) == 0 {
		t.Fatal("expected extracted field dependencies")
	}
	if len(ExtractRuntimeScriptFieldDepsRound61("", cands)) != 0 {
		t.Fatal("expected nil deps for empty script")
	}

	// 4. findMissingStaticSubPipelineForES7SimulateRound60, splitESQLAssignment, parseFieldCapsFilters, parseESPositiveDurationRound61, docMatchesScrollSliceR62Search
	srv, h := newR66CovServer(t, "8.15.0")
	missing := findMissingStaticSubPipelineForES7SimulateRound60(srv, map[string]any{
		"processors": []any{
			"bad_non_map",
			map[string]any{"if": "true", "tag": "t1"},
			map[string]any{"foreach": map[string]any{
				"processor":  map[string]any{"set": map[string]any{"field": "x", "value": 1, "on_failure": []any{map[string]any{"pipeline": map[string]any{"name": "ok_or_miss_on_fail"}}}}},
				"processors": []any{map[string]any{"set": map[string]any{"field": "y", "value": 2}}},
				"on_failure": []any{map[string]any{"pipeline": map[string]any{"name": "foreach_miss"}}},
			}},
		},
		"on_failure": []any{map[string]any{"pipeline": map[string]any{"name": "top_miss"}}},
	}, nil)
	if missing == "" {
		t.Fatal("expected missing sub-pipeline name")
	}
	for _, expr := range []string{`x = 1`, `a = 'q\'=r'`, `b = "s\"=t"`, "`c=d` = (1 + 2)", `x == 1`} {
		_, _, _ = splitESQLAssignment(expr)
	}
	_, _ = parseFieldCapsFilters([]string{"+metadata,-metadata,+multifield,-multifield,+nested,-nested,+parent,-parent,+runtime,-runtime"})
	for _, ds := range []string{"", "-1", "100", "-5", "bad", "2d", "3h", "4m", "5s", "10ms", "20micros", "30nanos"} {
		_, _ = parseESPositiveDurationRound61(ds)
	}

	mustR66CovHTTP(t, h, http.MethodPut, "/slice_b8", `{"settings":{"number_of_shards":2},"mappings":{"properties":{"k":{"type":"keyword"},"n":{"type":"long"}}}}`, http.StatusOK)
	_ = docMatchesScrollSliceR62Search(srv, "slice_b8", "d1", "r1", "_id", nil, 0, 1)
	_ = docMatchesScrollSliceR62Search(srv, "slice_b8", "d1", "", "_id", nil, 0, 2)
	_ = docMatchesScrollSliceR62Search(srv, "slice_b8", "d1", "", "n", json.RawMessage(`{"n":42}`), 0, 4)
	_ = docMatchesScrollSliceR62Search(srv, "slice_b8", "d1", "", "k", json.RawMessage(`{"k":"abc"}`), 0, 4)
	_ = docMatchesScrollSliceR62Search(srv, "slice_b8", "d1", "", "missing", json.RawMessage(`{"k":"abc"}`), 0, 4)
	_ = docMatchesScrollSliceR62Search(srv, "slice_b8", "d1", "", "_id", nil, 0, 4)
}

func TestRound66CovBackends_Batch9Cross853Helpers(t *testing.T) {
	srv, h := newR66CovServer(t, "8.15.0")

	// 1. persistLegacyTypeCopyOnWriteR62Search (ES8 skip, _doc skip, matching skip, ES7 copy-on-write)
	sch7 := schema.CompileIndexSchema("es_r66", "leg_cow_idx", &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"f": {Type: "keyword"}}})
	sch7.ES8Mode = false
	srv.mu.Lock()
	srv.indices["leg_cow_idx"] = sch7
	srv.mu.Unlock()
	_ = srv.persistLegacyTypeCopyOnWriteR62Search(context.Background(), "leg_cow_idx", sch7, "_doc")
	updated7 := srv.persistLegacyTypeCopyOnWriteR62Search(context.Background(), "leg_cow_idx", sch7, "my_type")
	if updated7 == nil || updated7.LegacyTypeName != "my_type" {
		t.Fatalf("expected LegacyTypeName=my_type, got %+v", updated7)
	}
	_ = srv.persistLegacyTypeCopyOnWriteR62Search(context.Background(), "leg_cow_idx", updated7, "my_type")
	_ = srv.persistLegacyTypeCopyOnWriteR62Search(context.Background(), "leg_cow_idx", sch7, "second_type")

	// 2. validateRequireDataStreamParamR62Search (empty, DS, pure DS alias, mixed alias, plain idx, missing tpl, auto-create DS)
	mustR66CovHTTP(t, h, http.MethodPut, "/_index_template/b9_ds_tpl", `{"index_patterns":["b9_ds*"],"data_stream":{},"template":{"mappings":{"properties":{"@timestamp":{"type":"date"}}}}}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/_data_stream/b9_ds_1", "", http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPut, "/b9_plain", `{}`, http.StatusOK)
	mustR66CovHTTP(t, h, http.MethodPost, "/_aliases", `{"actions":[{"add":{"index":"b9_ds_1","alias":"b9_ds_al"}},{"add":{"index":"b9_plain","alias":"b9_mix_al"}}]}`, http.StatusOK)

	_, _, _, _ = srv.validateRequireDataStreamParamR62Search(context.Background(), "", true)
	if ok, st, _, _ := srv.validateRequireDataStreamParamR62Search(context.Background(), "b9_ds_1", true); !ok || st != 0 {
		t.Fatalf("expected existing DS ok, got ok=%v st=%d", ok, st)
	}
	if ok, st, _, _ := srv.validateRequireDataStreamParamR62Search(context.Background(), "b9_ds_al", true); !ok || st != 0 {
		t.Fatalf("expected pure DS alias ok, got ok=%v st=%d", ok, st)
	}
	if ok, st, _, _ := srv.validateRequireDataStreamParamR62Search(context.Background(), "b9_mix_al", true); ok || st != http.StatusBadRequest {
		t.Fatalf("expected 400 non-DS alias, got ok=%v st=%d", ok, st)
	}
	if ok, st, _, _ := srv.validateRequireDataStreamParamR62Search(context.Background(), "b9_plain", true); ok || st != http.StatusBadRequest {
		t.Fatalf("expected 400 plain idx, got ok=%v st=%d", ok, st)
	}
	if ok, st, _, _ := srv.validateRequireDataStreamParamR62Search(context.Background(), "no_tpl_ds", true); ok || st != http.StatusNotFound {
		t.Fatalf("expected 404 missing DS tpl, got ok=%v st=%d", ok, st)
	}
	if ok, st, _, _ := srv.validateRequireDataStreamParamR62Search(context.Background(), "b9_ds_auto", true); !ok || st != 0 {
		t.Fatalf("expected auto-created DS ok, got ok=%v st=%d", ok, st)
	}

	// 3. ExtractRuntimeScriptFieldDepsRound61 (containsKey, doc.field, field(), $())
	cands := map[string]bool{"a": true, "b": true, "c": true, "d": true}
	deps := ExtractRuntimeScriptFieldDepsRound61(`
		if (doc.containsKey('a') && doc.containsKey("b")) {
			return doc.c.size() + field('d').get() + $('a');
		}
	`, cands)
	if len(deps) < 3 {
		t.Fatalf("expected >=3 extracted deps, got %#v", deps)
	}

	// 4. resolveMultiTermsFieldTypeR65 across explicit, Doris fallbacks, and heterogeneous merged schemas
	scUL := schema.CompileIndexSchema("es_r66", "mt_ul", &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"x": {Type: "unsigned_long"}}})
	scL := schema.CompileIndexSchema("es_r66", "mt_l", &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"x": {Type: "long"}}})
	scD := schema.CompileIndexSchema("es_r66", "mt_d", &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"x": {Type: "double"}}})
	scIP := schema.CompileIndexSchema("es_r66", "mt_ip", &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"x": {Type: "ip"}}})
	scDt := schema.CompileIndexSchema("es_r66", "mt_dt", &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"x": {Type: "date"}}})
	scKw := schema.CompileIndexSchema("es_r66", "mt_kw", &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"x": {Type: "keyword"}}})
	_ = resolveMultiTermsFieldTypeR65(esast.MultiTermTermSpec{Field: "x", ValueType: "keyword"}, scL, nil)
	_ = resolveMultiTermsFieldTypeR65(esast.MultiTermTermSpec{Field: "missing"}, scL, nil)
	_ = resolveMultiTermsFieldTypeR65(esast.MultiTermTermSpec{Field: "x"}, scUL, nil)
	_ = resolveMultiTermsFieldTypeR65(esast.MultiTermTermSpec{Field: "x"}, scL, map[string]*schema.IndexSchema{"d": scD})
	_ = resolveMultiTermsFieldTypeR65(esast.MultiTermTermSpec{Field: "x"}, scL, map[string]*schema.IndexSchema{"ul": scUL})
	_ = resolveMultiTermsFieldTypeR65(esast.MultiTermTermSpec{Field: "x"}, scIP, map[string]*schema.IndexSchema{"kw": scKw})
	_ = resolveMultiTermsFieldTypeR65(esast.MultiTermTermSpec{Field: "x"}, scDt, map[string]*schema.IndexSchema{"l": scL})

	// 5. compareHitRowsBySortWithSchemas (missing _first, _tsid, version, canonical IP, desc)
	var sorts []esast.SortSpec
	if err := json.Unmarshal([]byte(`[
		{"v":{"order":"desc","missing":"_first"}},
		{"_tsid":{"order":"asc"}},
		{"ver":{"order":"asc","numeric_type":"version"}},
		{"ip":{"order":"asc"}}
	]`), &sorts); err == nil {
		sorts[2].Entry.Type = "version"
		hr1 := HitRow{ID: "1", Source: json.RawMessage(`{"_tsid":"0001","ver":"1.2.3","ip":"10.0.0.1"}`)}
		hr2 := HitRow{ID: "2", Source: json.RawMessage(`{"v":5,"_tsid":"0002","ver":"1.2.10","ip":"::ffff:10.0.0.2"}`)}
		_ = compareHitRowsBySortWithSchemas(hr1, hr2, sorts, nil, nil)
		_ = compareHitRowsBySortWithSchemas(hr2, hr1, sorts, nil, nil)
		hrEmpty := HitRow{ID: "3", Source: json.RawMessage(`{}`)}
		_ = compareHitRowsBySortWithSchemas(hr1, hrEmpty, sorts[1:], nil, nil)
		_ = compareHitRowsBySortWithSchemas(hrEmpty, hr1, sorts[1:], nil, nil)
	}

	// 6. findMatchingTernaryColon, extractTopHitsSourceMetricR63, normalizeTypedKeysValueR61Search
	_ = findMatchingTernaryColon(`(a ? 'x:y' : 'z\'w') + b ? ''foo'' : c : d`)
	_ = findMatchingTernaryColon(`no_ternary`)
	_, _ = extractTopHitsSourceMetricR63(map[string]any{"hits": map[string]any{"hits": []map[string]any{{"sort": []float64{4.5}, "_score": 2.5}}}}, []string{"_sort"})
	_, _ = extractTopHitsSourceMetricR63(map[string]any{"hits": map[string]any{"hits": []any{map[string]any{"sort": []any{3.5}, "_score": 1.5, "_source": map[string]any{"m": 9.0}}}}}, []string{"_score"})
	_, _ = extractTopHitsSourceMetricR63(map[string]any{"hits": map[string]any{"hits": []any{map[string]any{"_source": map[string]any{"m": 9.0}}}}}, []string{"_source.m"})
	_, _ = extractTopHitsSourceMetricR63(map[string]any{}, []string{"_score"})

	_ = normalizeTypedKeysValueR61Search(map[string]any{
		"hits":    map[string]any{"total": 1},
		"buckets": []map[string]any{{"key": "a", "avg#x": map[string]any{"value": 1}}},
	})
	_ = normalizeTypedKeysValueR61Search(map[string]any{
		"buckets": []any{map[string]any{"key": "a", "sum#y": map[string]any{"value": 2}}, "raw"},
	})
	_ = normalizeTypedKeysValueR61Search(map[string]any{
		"buckets": map[string]any{"k#1": map[string]any{"avg#z": map[string]any{"value": 3}}, "k2": 1},
	})
	_ = normalizeTypedKeysValueR61Search(map[string]any{"buckets": 42})
}
