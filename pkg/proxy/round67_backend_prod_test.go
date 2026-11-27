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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
	"github.com/go-sql-driver/mysql"
)

type round67TestRoundTripFunc func(*http.Request) (*http.Response, error)

func (f round67TestRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newRound67TestJSONResponse(req *http.Request, status int, headers map[string]string, body string) *http.Response {
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

type round67SQLQuerySpec struct {
	cols []string
	rows [][]driver.Value
	err  error
}

type round67MockSQLDriver struct {
	mu       sync.RWMutex
	handlers map[string]func(query string, args []driver.NamedValue) round67SQLQuerySpec
}

var (
	round67SQLDriverOnce sync.Once
	round67SQLDriverInst = &round67MockSQLDriver{
		handlers: make(map[string]func(query string, args []driver.NamedValue) round67SQLQuerySpec),
	}
)

func (d *round67MockSQLDriver) Open(name string) (driver.Conn, error) {
	return &round67MockSQLConn{driver: d, dsn: name}, nil
}

type round67MockSQLConn struct {
	driver *round67MockSQLDriver
	dsn    string
}

func (c *round67MockSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *round67MockSQLConn) Close() error                        { return nil }
func (c *round67MockSQLConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }

func (c *round67MockSQLConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.driver.mu.RLock()
	fn := c.driver.handlers[c.dsn]
	c.driver.mu.RUnlock()
	if fn == nil {
		return driver.RowsAffected(1), nil
	}
	spec := fn(query, args)
	if spec.err != nil {
		return nil, spec.err
	}
	return driver.RowsAffected(1), nil
}

func (c *round67MockSQLConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.driver.mu.RLock()
	fn := c.driver.handlers[c.dsn]
	c.driver.mu.RUnlock()
	if fn == nil {
		return &round67MockSQLRows{}, nil
	}
	spec := fn(query, args)
	if spec.err != nil {
		return nil, spec.err
	}
	return &round67MockSQLRows{cols: spec.cols, rows: spec.rows}, nil
}

func (c *round67MockSQLConn) Ping(ctx context.Context) error {
	if _, err := c.QueryContext(ctx, "PING", nil); err != nil {
		return err
	}
	return nil
}

type round67MockSQLRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *round67MockSQLRows) Columns() []string { return r.cols }
func (r *round67MockSQLRows) Close() error      { return nil }
func (r *round67MockSQLRows) Next(dest []driver.Value) error {
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

func openRound67MockDB(tb testing.TB, fn func(query string, args []driver.NamedValue) round67SQLQuerySpec) *sql.DB {
	tb.Helper()
	round67SQLDriverOnce.Do(func() {
		sql.Register("round67_sqlbackend_mock", round67SQLDriverInst)
	})
	dsn := fmt.Sprintf("%s_%d", tb.Name(), time.Now().UnixNano())
	round67SQLDriverInst.mu.Lock()
	round67SQLDriverInst.handlers[dsn] = fn
	round67SQLDriverInst.mu.Unlock()
	tb.Cleanup(func() {
		round67SQLDriverInst.mu.Lock()
		delete(round67SQLDriverInst.handlers, dsn)
		round67SQLDriverInst.mu.Unlock()
	})
	db, err := sql.Open("round67_sqlbackend_mock", dsn)
	if err != nil {
		tb.Fatalf("sql.Open: %v", err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	return db
}

// -----------------------------------------------------------------------------
// Deliverable 1: MemoryBackend Parity & Bounded Regex Tests
// -----------------------------------------------------------------------------

func TestRound67_MemoryBackend_JSONPathCollectListTryCastAndBoundedRegex(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mb := NewMemoryBackend(false)
	ddl := "CREATE TABLE `es_compat`.`t67` (\n `_id` VARCHAR(256) NOT NULL,\n `_version` BIGINT NOT NULL,\n `_source` STRING NOT NULL,\n `f__title` STRING NULL,\n `n__items` ARRAY<STRING> NULL,\n `__DORIS_DELETE_SIGN__` TINYINT NOT NULL DEFAULT '0'\n) UNIQUE KEY(`_id`);"
	if err := mb.ExecDDL(ctx, ddl); err != nil {
		t.Fatalf("ExecDDL: %v", err)
	}
	ndjson := strings.Join([]string{
		`{"_id":"1","_version":1,"_source":"{\"title\":\"alpha widget\",\"price\":10,\"cat\":\"a\",\"a.b\":\"dotted-v1\",\"q\\\"k\":\"quoted-v1\",\"tags\":[\"x\",\"y\"]}","f__title":"alpha widget","n__items":["{\"name__keyword\":\"LONG_NAME\",\"score\":10.5}","{\"name__keyword\":\"SHORT\",\"score\":20.5}"]}`,
		`{"_id":"2","_version":1,"_source":"{\"title\":\"beta gadget\",\"price\":30,\"cat\":\"a\",\"a.b\":\"dotted-v2\",\"tags\":[\"z\"]}","f__title":"beta gadget","n__items":["{\"name__keyword\":\"LONG_NAME\",\"score\":30.5}"]}`,
		`{"_id":"3","_version":1,"_source":"{\"title\":\"gamma\",\"price\":50,\"cat\":\"b\"}","f__title":"gamma","n__items":["{\"score\":50.5}"]}`,
	}, "\n") + "\n"
	if err := mb.StreamLoad(ctx, "t67", []byte(ndjson), true); err != nil {
		t.Fatalf("StreamLoad: %v", err)
	}

	// 1. COLLECT_LIST(TRY_CAST(... AS DOUBLE)) in reAggRawValues & reAggSubRawValues.
	aggsSQL := "WITH `base_matched` AS (SELECT * FROM `es_compat`.`t67` WHERE `__DORIS_DELETE_SIGN__` = 0)\n" +
		"SELECT '__raw_vals__pct' AS `_agg_name`, CONCAT('_vals:', IF(COUNT(`_id`) <= 50000, COALESCE(ARRAY_JOIN(COLLECT_LIST(TRY_CAST(json_extract_string(`_source`, '$.\"price\"') AS DOUBLE)), ','), ''), ':OVERFLOW:')) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`\n" +
		"UNION ALL\n" +
		"SELECT '__raw_vals__sub_pct' AS `_agg_name`, CONCAT(CAST(json_extract_string(`_source`, '$.\"cat\"') AS STRING), '\\x1f_vals:', IF(COUNT(`_id`) <= 50000, COALESCE(ARRAY_JOIN(COLLECT_LIST(TRY_CAST(json_extract_string(`_source`, '$.\"price\"') AS DOUBLE)), ','), ''), ':OVERFLOW:')) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` GROUP BY json_extract_string(`_source`, '$.\"cat\"')"
	aggRows, err := mb.QueryAggs(ctx, aggsSQL)
	if err != nil {
		t.Fatalf("QueryAggs raw values: %v", err)
	}
	normSortedVals := func(bucketKey, prefix string) string {
		if !strings.HasPrefix(bucketKey, prefix) {
			return ""
		}
		parts := strings.Split(strings.TrimPrefix(bucketKey, prefix), ",")
		sort.Strings(parts)
		return strings.Join(parts, ",")
	}
	foundGlobal, foundSub := false, false
	for _, r := range aggRows {
		if r.AggName == "__raw_vals__pct" && normSortedVals(r.BucketKey, "_vals:") == "10,30,50" {
			foundGlobal = true
		}
		if r.AggName == "__raw_vals__sub_pct" && normSortedVals(r.BucketKey, "a\x1f_vals:") == "10,30" {
			foundSub = true
		}
	}
	if !foundGlobal || !foundSub {
		t.Fatalf("expected COLLECT_LIST(TRY_CAST) matches for global and sub aggs, got %+v", aggRows)
	}

	// 2. Quoted JSONPath evaluation across json_extract_string, json_extract, JSON_TYPE, JSON_LENGTH, array_map, and nested terms agg.
	nestedAggSQL := "WITH `base_matched` AS (SELECT * FROM `es_compat`.`t67` WHERE `__DORIS_DELETE_SIGN__` = 0)\n" +
		"(SELECT 'nested_kw' AS `_agg_name`, json_extract_string(`_nel`, '$.\"name__keyword\"') AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`n__items`) `_nt` AS `_nel` WHERE json_extract_string(`_nel`, '$.\"name__keyword\"') IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 10)\n" +
		"UNION ALL\n" +
		"(SELECT 'nested_kw_missing' AS `_agg_name`, COALESCE(json_extract_string(`_nel`, '$.\"name__keyword\"'), 'MISSING') AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`n__items`) `_nt` AS `_nel` GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 10)"
	nRows, err := mb.QueryAggs(ctx, nestedAggSQL)
	if err != nil {
		t.Fatalf("QueryAggs nested terms quoted JSONPath: %v", err)
	}
	gotLong, gotMissing := int64(0), int64(0)
	for _, r := range nRows {
		if r.AggName == "nested_kw" && r.BucketKey == "LONG_NAME" {
			gotLong = int64(r.DocCount)
		}
		if r.AggName == "nested_kw_missing" && r.BucketKey == "MISSING" {
			gotMissing = int64(r.DocCount)
		}
	}
	if gotLong != 2 || gotMissing != 1 {
		t.Fatalf("unexpected quoted nested JSONPath agg counts: LONG_NAME=%d MISSING=%d rows=%+v", gotLong, gotMissing, nRows)
	}

	hitsSQL := "SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` " +
		"FROM `es_compat`.`t67` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (" +
		"json_extract_string(`_source`, '$.\"a.b\"') = 'dotted-v1' AND " +
		"json_extract_string(`_source`, '$.\"q\\\"k\"') = 'quoted-v1' AND " +
		"LOWER(JSON_TYPE(TRY_CAST(`_source` AS JSON), '$.\"tags\"')) = 'array' AND " +
		"JSON_LENGTH(`_source`, '$.\"tags\"') = 2 AND " +
		"array_contains(array_map(_el -> json_extract_string(_el, '$.\"score\"'), `n__items`), '10.5') AND " +
		"json_extract(`_source`, '$') IS NOT NULL" +
		") ORDER BY `_id` ASC LIMIT 10 OFFSET 0"
	hits, err := mb.QueryHits(ctx, hitsSQL)
	if err != nil || len(hits) != 1 || hits[0].ID != "1" {
		t.Fatalf("expected quoted JSONPath QueryHits match for doc 1, got len=%d hits=%+v err=%v", len(hits), hits, err)
	}

	// 3. mergeSourceWithDocVariantJSON fast-path for {}, null, equal JSON, and fill-missing.
	src := json.RawMessage(`{"a":1,"b":"x"}`)
	if got := mergeSourceWithDocVariantJSON(src, json.RawMessage(`{}`)); string(got) != string(src) {
		t.Fatalf("empty _doc merge mismatch: %s", string(got))
	}
	if got := mergeSourceWithDocVariantJSON(src, json.RawMessage(`null`)); string(got) != string(src) {
		t.Fatalf("null _doc merge mismatch: %s", string(got))
	}
	if got := mergeSourceWithDocVariantJSON(src, json.RawMessage(`{"a":1,"b":"x"}`)); string(got) != string(src) {
		t.Fatalf("equal _doc merge mismatch: %s", string(got))
	}
	if got := mergeSourceWithDocVariantJSON(src, json.RawMessage(`{"a":9,"extra":true}`)); !strings.Contains(string(got), `"extra":true`) || !strings.Contains(string(got), `"a":1`) {
		t.Fatalf("expected fill-missing merge keeping _source priority, got: %s", string(got))
	}

	// 4. Runtime regex calls use painless.CompileBoundedRawRegex and fail gracefully on oversized patterns.
	hugePat := strings.Repeat("a", 5000)
	mb.mu.RLock()
	tbl := mb.tables["t67"]
	row1 := tbl["1"]
	mb.mu.RUnlock()
	if evalWhereExpr(row1, fmt.Sprintf("`f__title` REGEXP '%s'", hugePat)) {
		t.Fatalf("expected oversized REGEXP pattern to return false via CompileBoundedRawRegex")
	}
	if evalWhereExpr(row1, fmt.Sprintf("MATCH_REGEXP(`f__title`, '%s')", hugePat)) {
		t.Fatalf("expected oversized MATCH_REGEXP pattern to return false via CompileBoundedRawRegex")
	}
	if v, ok := evalColumnFuncR63Mem(row1, fmt.Sprintf("REGEXP_EXTRACT(`f__title`, '%s', 1)", hugePat)); !ok || v != "" {
		t.Fatalf("expected oversized REGEXP_EXTRACT to return empty string, got (%v, %v)", v, ok)
	}
	if v, ok := evalColumnFuncR63Mem(row1, fmt.Sprintf("REGEXP_REPLACE(`f__title`, '%s', 'z')", hugePat)); !ok || v != "alpha widget" {
		t.Fatalf("expected oversized REGEXP_REPLACE to return original value, got (%v, %v)", v, ok)
	}
	if v, ok := evalColumnFuncR63Mem(row1, `REGEXP_EXTRACT(`+"`f__title`"+`, '([a-z]+)', 1)`); !ok || v != "alpha" {
		t.Fatalf("expected normal REGEXP_EXTRACT match 'alpha', got (%v, %v)", v, ok)
	}
}

// -----------------------------------------------------------------------------
// Deliverable 2: Production StreamLoadClient (F8 & F13 & P2-1) Tests
// -----------------------------------------------------------------------------

func TestRound67_StreamLoad_MultiFEFailoverAndBERoundRobin(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// BE1 & BE2 serve directly; FE2 redirects cleanly; FE1 is down (closed listener).
	var be1Hits, be2Hits, fe2Hits atomic.Int64
	be1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		be1Hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":"Success"}`))
	}))
	defer be1.Close()

	be2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		be2Hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Status":"Success"}`))
	}))
	defer be2.Close()

	fe1Down := httptest.NewServer(http.NewServeMux())
	fe1URL := fe1Down.URL
	fe1Down.Close()

	fe2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fe2Hits.Add(1)
		http.Redirect(w, r, be1.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer fe2.Close()

	sl := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: fe1URL + ", " + fe2.URL,
		User:           "root",
		Database:       "es_compat",
		Timeout:        2 * time.Second,
		MaxRetries:     2,
		BaseBackoff:    2 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
	})

	// Multi-FE: at least one attempt hits dead fe1 and fails over cleanly to fe2 -> redirect to be1.
	for i := 0; i < 4; i++ {
		if err := sl.LoadNDJSON(ctx, "orders", []byte(`{"_id":"1"}`+"\n"), false); err != nil {
			t.Fatalf("multi-FE load #%d failed: %v", i, err)
		}
	}
	if fe2Hits.Load() == 0 {
		t.Fatalf("expected FE2 to serve requests when FE1 is down")
	}

	// Explicit discovered BE round-robin distributes across be1 and be2, falling back to FE on BE outage.
	be1Hits.Store(0)
	be2Hits.Store(0)
	fe2Hits.Store(0)
	sl.SetDiscoveredBEs([]string{be1.URL, be2.URL})
	for i := 0; i < 6; i++ {
		if err := sl.LoadNDJSON(ctx, "orders", []byte(`{"_id":"rr"}`+"\n"), false); err != nil {
			t.Fatalf("BE round-robin load #%d failed: %v", i, err)
		}
	}
	if be1Hits.Load() < 2 || be2Hits.Load() < 2 || fe2Hits.Load() != 0 {
		t.Fatalf("expected round-robin across be1 (%d) and be2 (%d) with 0 FE calls (%d)", be1Hits.Load(), be2Hits.Load(), fe2Hits.Load())
	}

	// Shut down be2 and verify StreamLoad falls back to FE redirect / live be1 seamlessly.
	be2.Close()
	if err := sl.LoadNDJSON(ctx, "orders", []byte(`{"_id":"after_be2_down"}`+"\n"), false); err != nil {
		t.Fatalf("expected failover after be2 close, got: %v", err)
	}
}

func TestRound67_StreamLoad_P2_1_StrictRedirectGate(t *testing.T) {
	t.Parallel()

	// 1. Before SHOW BACKENDS / SetDiscoveredBEs (!hasDiscoveredBEHosts), VPC FE trusts RFC1918 BE.
	sl := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "http://10.0.0.10:8030",
		User:           "root",
		Database:       "es_compat",
		MaxRetries:     -1,
	})
	initReq, _ := http.NewRequest(http.MethodPut, "http://10.0.0.10:8030/api/es_compat/orders/_stream_load", nil)
	vpcRedirectReq, _ := http.NewRequest(http.MethodPut, "http://10.0.0.20:8040/api/es_compat/orders/_stream_load", nil)
	if err := sl.checkStreamLoadRedirect(vpcRedirectReq, []*http.Request{initReq}); err != nil {
		t.Fatalf("expected initial VPC bootstrap redirect to succeed before discovered BEs, got: %v", err)
	}

	// Feeding blocked metadata hosts into AllowBEHosts must NOT satisfy hasDiscoveredBEHosts or permit metadata hosts.
	sl.AllowBEHosts([]string{"169.254.169.254", "metadata.google.internal"})
	if sl.hasDiscoveredBEHosts() {
		t.Fatalf("blocked hosts alone must not flip hasDiscoveredBEHosts to true")
	}

	// 2. Once AllowBEHosts or SetDiscoveredBEs populates >=1 real BE, un-allowlisted RFC1918 BE must be rejected!
	sl.AllowBEHosts([]string{"10.0.0.20"})
	if !sl.hasDiscoveredBEHosts() {
		t.Fatalf("expected hasDiscoveredBEHosts to become true after valid BE registration")
	}
	if err := sl.checkStreamLoadRedirect(vpcRedirectReq, []*http.Request{initReq}); err != nil {
		t.Fatalf("expected allowlisted BE 10.0.0.20 redirect to succeed, got: %v", err)
	}
	rogueRFC1918, _ := http.NewRequest(http.MethodPut, "http://10.99.99.99:8040/api/es_compat/orders/_stream_load", nil)
	if err := sl.checkStreamLoadRedirect(rogueRFC1918, []*http.Request{initReq}); err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatalf("P2-1 violated: un-allowlisted RFC1918 IP must be rejected after BE discovery, got err=%v", err)
	}

	// 3. Exact /api/<db>/<table>/_stream_load path enforcement & matching initial request path.
	for _, badPath := range []string{
		"/_stream_load",
		"/api/_stream_load",
		"/api/es_compat/_stream_load",
		"/api/es_compat/orders/extra/_stream_load",
		"/api/../orders/_stream_load",
		"/api/other_db/other_tbl/_stream_load",
	} {
		badReq, _ := http.NewRequest(http.MethodPut, "http://10.0.0.20:8040"+badPath, nil)
		if err := sl.checkStreamLoadRedirect(badReq, []*http.Request{initReq}); err == nil {
			t.Fatalf("expected strict redirect path check to reject %q", badPath)
		}
	}
}

func TestRound67_StreamLoad_BackoffPublishTimeoutSemaphoreTraceAndChunks(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// 1. 5-attempt exponential backoff succeeds on attempt 5 after -235 TOO_MANY_VERSIONS, 503, transport reset, Publish Timeout.
	var attempts atomic.Int64
	slRetry := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "https://fe.example.internal:8030",
		User:           "root",
		Database:       "es_compat",
		MaxRetries:     4,
		BaseBackoff:    2 * time.Millisecond,
		MaxBackoff:     8 * time.Millisecond,
	})
	slRetry.httpClient = &http.Client{
		CheckRedirect: slRetry.checkStreamLoadRedirect,
		Transport: round67TestRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			n := attempts.Add(1)
			switch n {
			case 1:
				return nil, errors.New("connection reset by peer")
			case 2:
				return newRound67TestJSONResponse(req, http.StatusServiceUnavailable, nil, "busy"), nil
			case 3:
				return newRound67TestJSONResponse(req, http.StatusOK, nil, `{"Status":"Fail","Message":"errCode = -235, TOO_MANY_VERSIONS"}`), nil
			case 4:
				return newRound67TestJSONResponse(req, http.StatusOK, nil, `{"Status":"Publish Timeout","Message":"publish timed out"}`), nil
			default:
				return newRound67TestJSONResponse(req, http.StatusOK, nil, `{"Status":"Success"}`), nil
			}
		}),
	}
	if err := slRetry.LoadNDJSON(ctx, "orders", []byte(`{"_id":"1"}`+"\n"), true); err != nil {
		t.Fatalf("expected 5-attempt retry recovery across transport/503/-235/PublishTimeout, got: %v", err)
	}
	if attempts.Load() != 5 {
		t.Fatalf("expected 5 attempts, got %d", attempts.Load())
	}

	// 2. Persistent Publish Timeout respects syncRefresh: false -> nil, true -> error.
	alwaysPubTimeout := round67TestRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newRound67TestJSONResponse(req, http.StatusOK, nil, `{"Status":"Publish Timeout","Message":"still publishing"}`), nil
	})
	slRetry.httpClient = &http.Client{CheckRedirect: slRetry.checkStreamLoadRedirect, Transport: alwaysPubTimeout}
	if err := slRetry.LoadNDJSON(ctx, "orders", []byte(`{"_id":"async"}`+"\n"), false); err != nil {
		t.Fatalf("expected Publish Timeout with syncRefresh=false to succeed, got: %v", err)
	}
	if err := slRetry.LoadNDJSON(ctx, "orders", []byte(`{"_id":"sync"}`+"\n"), true); err == nil || !strings.Contains(err.Error(), "Publish Timeout") {
		t.Fatalf("expected persistent Publish Timeout with syncRefresh=true to error, got: %v", err)
	}

	// 3. Concurrency semaphore caps concurrent uploads at MaxConcurrentUploads=2.
	var inFlight, maxInFlight atomic.Int64
	slSem := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint:       "https://fe.example.internal:8030",
		User:                 "root",
		Database:             "es_compat",
		MaxConcurrentUploads: 2,
		MaxRetries:           -1,
	})
	slSem.httpClient = &http.Client{
		CheckRedirect: slSem.checkStreamLoadRedirect,
		Transport: round67TestRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			cur := inFlight.Add(1)
			for {
				prev := maxInFlight.Load()
				if cur <= prev || maxInFlight.CompareAndSwap(prev, cur) {
					break
				}
			}
			time.Sleep(15 * time.Millisecond)
			inFlight.Add(-1)
			return newRound67TestJSONResponse(req, http.StatusOK, nil, `{"Status":"Success"}`), nil
		}),
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := slSem.LoadNDJSON(ctx, "orders", []byte(fmt.Sprintf("{\"_id\":\"%d\"}\n", idx)), false); err != nil {
				t.Errorf("concurrent load #%d failed: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()
	if maxInFlight.Load() > 2 || maxInFlight.Load() == 0 {
		t.Fatalf("expected max concurrent uploads in [1..2], got %d", maxInFlight.Load())
	}

	// 4. Trace header propagation across FE -> 307 -> BE + per-chunk error context + multi-FE ErrorURL validation.
	var seenBETrace, seenBEReqID, seenBEOpaque string
	var failChunkCount atomic.Int64
	var errDetailURL atomic.Value
	beSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBETrace = r.Header.Get("traceparent")
		seenBEReqID = r.Header.Get("X-Request-ID")
		seenBEOpaque = r.Header.Get("X-Opaque-Id")
		if r.URL.Path == "/api/es_compat/failchunks/_stream_load" && failChunkCount.Add(1) == 2 {
			detailBase, _ := errDetailURL.Load().(string)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"Status":"Fail","Message":"bad row","NumberFilteredRows":1,"NumberTotalRows":1,"ErrorURL":"%s/api/_load_error/bad"}`, detailBase)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Status":"Success"}`))
	}))
	defer beSrv.Close()

	feSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "_load_error") {
			_, _ = w.Write([]byte("column type mismatch detail"))
			return
		}
		http.Redirect(w, r, beSrv.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	defer feSrv.Close()
	errDetailURL.Store(feSrv.URL)

	slTrace := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: feSrv.URL,
		User:           "root",
		Database:       "es_compat",
		MaxBatchBytes:  30,
		MaxRetries:     -1,
	})
	traceCtx := WithTraceMeta(ctx, TraceMeta{
		Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nBad: hdr",
		RequestID:   "req-trace-67",
		OpaqueID:    "opq-67",
	})
	if err := slTrace.LoadNDJSON(traceCtx, "orders", []byte(`{"_id":"1"}`+"\n"), false); err != nil {
		t.Fatalf("trace LoadNDJSON failed: %v", err)
	}
	if seenBETrace != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01Bad: hdr" || seenBEReqID != "req-trace-67" || seenBEOpaque != "opq-67" {
		t.Fatalf("unexpected trace headers on BE redirect: trace=%q reqID=%q opaque=%q", seenBETrace, seenBEReqID, seenBEOpaque)
	}
	slTrace.cachedBEBase.Store("") // Force FE path for multi-chunk failure check.
	slTrace.beMu.Lock()
	slTrace.redirectBEs = nil
	slTrace.beMu.Unlock()
	err := slTrace.LoadNDJSON(ctx, "failchunks", []byte("{\"_id\":\"1\",\"v\":1}\n{\"_id\":\"2\",\"v\":2}\n"), false)
	if err == nil || !strings.Contains(err.Error(), "chunk 1") || !strings.Contains(err.Error(), "column type mismatch detail") {
		t.Fatalf("expected chunk 1 failure with fetched ErrorURL detail, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Deliverable 3: Sharded StreamLoadCoalescer Tests
// -----------------------------------------------------------------------------

func TestRound67_Coalescer_ShardedO1PendingAndBoundedFlushAll(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// 1. Per-table shard isolation: blocking flush on tbl_slow must NOT stall Submit/FlushTable on tbl_fast.
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	var fastFlushes atomic.Int64
	c := newStreamLoadCoalescer(func(fCtx context.Context, table string, ndjson []byte, syncRefresh bool) error {
		if table == "tbl_slow" {
			close(slowStarted)
			select {
			case <-releaseSlow:
				return nil
			case <-fCtx.Done():
				return fCtx.Err()
			}
		}
		if table == "tbl_fast" {
			fastFlushes.Add(1)
		}
		return nil
	})
	c.Configure(50*time.Millisecond, 64*1024)

	var slowErr error
	var slowWG sync.WaitGroup
	slowWG.Add(1)
	go func() {
		defer slowWG.Done()
		slowErr = c.Submit(ctx, "tbl_slow", []byte(`{"_id":"s1"}`+"\n"), true)
	}()
	<-slowStarted

	fastDone := make(chan error, 1)
	go func() {
		fastDone <- c.Submit(ctx, "tbl_fast", []byte(`{"_id":"f1"}`+"\n"), false)
	}()
	select {
	case err := <-fastDone:
		if err != nil || fastFlushes.Load() != 1 {
			t.Fatalf("expected tbl_fast submit+flush to finish while tbl_slow blocks, err=%v flushes=%d", err, fastFlushes.Load())
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("tbl_fast stalled behind tbl_slow global lock!")
	}
	close(releaseSlow)
	slowWG.Wait()
	if slowErr != nil {
		t.Fatalf("slow submit failed: %v", slowErr)
	}

	// 2. O(1) pendingDocIDs tracking + cancellation decrement.
	var pendingCalls atomic.Int64
	cPending := newStreamLoadCoalescer(func(_ context.Context, table string, ndjson []byte, _ bool) error {
		pendingCalls.Add(1)
		return nil
	})
	cPending.Configure(5*time.Second, 64*1024)

	cancelCtx, cancel := context.WithCancel(ctx)
	var cancelSubErr error
	var cwg sync.WaitGroup
	cwg.Add(1)
	go func() {
		defer cwg.Done()
		cancelSubErr = cPending.Submit(cancelCtx, "tbl_doc", []byte(`{"_id":"doc_cancel"}`+"\n"), false)
	}()
	var activeSubWG sync.WaitGroup
	activeSubWG.Add(1)
	go func() {
		defer activeSubWG.Done()
		_ = cPending.Submit(ctx, "tbl_doc", []byte(`{"_id":"doc_keep"}`+"\n"), false)
	}()

	// Wait until both are buffered in shard.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		sh := cPending.getShard("tbl_doc")
		if sh != nil {
			sh.mu.Lock()
			ok := sh.batch != nil && sh.batch.pendingDocIDs["doc_cancel"] == 1 && sh.batch.pendingDocIDs["doc_keep"] == 1
			sh.mu.Unlock()
			if ok {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	cwg.Wait()
	if !errors.Is(cancelSubErr, context.Canceled) {
		t.Fatalf("expected canceled submit to return context.Canceled, got %v", cancelSubErr)
	}
	// Canceled doc_cancel must NOT trigger flush; doc_keep MUST trigger flush.
	if err := cPending.FlushTableIfDocPending(ctx, "tbl_doc", "doc_cancel"); err != nil {
		t.Fatalf("FlushTableIfDocPending doc_cancel: %v", err)
	}
	if pendingCalls.Load() != 0 {
		t.Fatalf("expected canceled docID not to flush, got %d calls", pendingCalls.Load())
	}
	if err := cPending.FlushTableIfDocPending(ctx, "tbl_doc", "doc_keep"); err != nil {
		t.Fatalf("FlushTableIfDocPending doc_keep: %v", err)
	}
	activeSubWG.Wait()
	if pendingCalls.Load() != 1 {
		t.Fatalf("expected doc_keep flush to execute once, got %d calls", pendingCalls.Load())
	}

	// 3. FlushAll flushes tables concurrently and respects explicit ctx deadlines.
	var flushedTables atomic.Int64
	cConc := newStreamLoadCoalescer(func(fCtx context.Context, table string, _ []byte, _ bool) error {
		select {
		case <-time.After(70 * time.Millisecond):
			flushedTables.Add(1)
			return nil
		case <-fCtx.Done():
			return fCtx.Err()
		}
	})
	cConc.Configure(5*time.Second, 64*1024)
	var subWG sync.WaitGroup
	for i := 0; i < 6; i++ {
		subWG.Add(1)
		go func(idx int) {
			defer subWG.Done()
			_ = cConc.Submit(ctx, fmt.Sprintf("tbl_p_%d", idx), []byte(`{"_id":"1"}`+"\n"), false)
		}(i)
	}
	waitUntil := time.Now().Add(time.Second)
	for time.Now().Before(waitUntil) {
		if len(cConc.snapshotShards()) == 6 {
			ready := true
			for _, s := range cConc.snapshotShards() {
				s.shard.mu.Lock()
				if s.shard.batch == nil {
					ready = false
				}
				s.shard.mu.Unlock()
			}
			if ready {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	start := time.Now()
	if err := cConc.FlushAll(ctx); err != nil {
		t.Fatalf("concurrent FlushAll failed: %v", err)
	}
	elapsed := time.Since(start)
	subWG.Wait()
	if flushedTables.Load() != 6 || elapsed > 300*time.Millisecond {
		t.Fatalf("expected 6 tables flushed concurrently (<300ms vs 420ms serial), got count=%d elapsed=%v", flushedTables.Load(), elapsed)
	}

	// Tight ctx deadline on FlushAll returns DeadlineExceeded cleanly.
	cDL := newStreamLoadCoalescer(func(fCtx context.Context, _ string, _ []byte, _ bool) error {
		<-fCtx.Done()
		return fCtx.Err()
	})
	cDL.Configure(5*time.Second, 64*1024)
	go func() { _ = cDL.Submit(ctx, "tbl_dl", []byte(`{"_id":"1"}`+"\n"), false) }()
	for cDL.getShard("tbl_dl") == nil {
		time.Sleep(time.Millisecond)
	}
	dlCtx, dlCancel := context.WithTimeout(ctx, 25*time.Millisecond)
	defer dlCancel()
	if err := cDL.FlushAll(dlCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected FlushAll to respect deadline, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Deliverable 4: DorisSQLBackend Capabilities & Safety Tests
// -----------------------------------------------------------------------------

func TestRound67_DorisSQLBackend_CatalogHealthVersionDDLAndErrorGates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// 1. Catalog incremental load, ProbeDorisVersion, SetDDLOptions + InitCatalog, DBStats, CheckClusterHealth.
	var capturedDDL string
	var feHealthStatus atomic.Int32
	feHealthStatus.Store(http.StatusOK)

	feHealthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.WriteHeader(int(feHealthStatus.Load()))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer feHealthSrv.Close()

	db := openRound67MockDB(t, func(query string, args []driver.NamedValue) round67SQLQuerySpec {
		switch {
		case strings.Contains(query, "CREATE TABLE IF NOT EXISTS"):
			capturedDDL = query
			return round67SQLQuerySpec{}
		case strings.Contains(query, "WHERE `updated_epoch_ms` >="):
			if len(args) != 1 || args[0].Value != int64(500) {
				return round67SQLQuerySpec{err: fmt.Errorf("unexpected since arg: %+v", args)}
			}
			return round67SQLQuerySpec{
				cols: []string{"entity_type", "entity_key", "payload_json", "updated_epoch_ms"},
				rows: [][]driver.Value{
					{"index", "orders", `{}`, int64(500)},
					{"alias", "orders_ro", `["orders"]`, int64(501)},
				},
			}
		case strings.Contains(query, "SELECT `entity_type`"):
			return round67SQLQuerySpec{
				cols: []string{"entity_type", "entity_key", "payload_json", "updated_epoch_ms"},
				rows: [][]driver.Value{{"index", "all", `{}`, int64(100)}},
			}
		case query == "SELECT VERSION()":
			return round67SQLQuerySpec{
				cols: []string{"VERSION()"},
				rows: [][]driver.Value{{"8.0.29-Doris-4.1.3"}},
			}
		case strings.Contains(query, "SHOW BACKENDS"):
			return round67SQLQuerySpec{
				cols: []string{"BackendId", "Host", "HttpPort", "Alive"},
				rows: [][]driver.Value{
					{"1", "127.0.0.1", "8040", "true"},
					{"2", "127.0.0.2", "8040", "false"},
				},
			}
		default:
			return round67SQLQuerySpec{}
		}
	})

	sl := NewStreamLoadClient(StreamLoadConfig{FEHTTPEndpoint: feHealthSrv.URL, User: "root", Database: "es_compat"})
	b := NewDorisSQLBackend(db, sl)

	entries, err := b.LoadCatalogEntriesSince(ctx, "es_compat", 500)
	if err != nil || len(entries) != 2 || entries[0].EntityKey != "orders" {
		t.Fatalf("LoadCatalogEntriesSince(500) = (%+v, %v)", entries, err)
	}
	allEntries, err := b.LoadCatalogEntriesSince(ctx, "es_compat", 0)
	if err != nil || len(allEntries) != 1 || allEntries[0].EntityKey != "all" {
		t.Fatalf("LoadCatalogEntriesSince(0) = (%+v, %v)", allEntries, err)
	}
	ver, err := b.ProbeDorisVersion(ctx)
	if err != nil || ver != "8.0.29-Doris-4.1.3" {
		t.Fatalf("ProbeDorisVersion = (%q, %v)", ver, err)
	}
	st, ok := b.DBStats()
	if !ok || st.MaxOpenConnections != 64 {
		t.Fatalf("DBStats = (%+v, %v)", st, ok)
	}
	var nilB *DorisSQLBackend
	if _, ok := nilB.DBStats(); ok {
		t.Fatalf("expected nil backend DBStats to return false")
	}

	aliveBEs, feOK, err := b.CheckClusterHealth(ctx)
	if err != nil || aliveBEs != 1 || !feOK {
		t.Fatalf("CheckClusterHealth(healthy) = (%d, %v, %v), want (1, true, nil)", aliveBEs, feOK, err)
	}
	feHealthStatus.Store(http.StatusServiceUnavailable)
	aliveBEs, feOK, err = b.CheckClusterHealth(ctx)
	if err != nil || aliveBEs != 1 || feOK {
		t.Fatalf("CheckClusterHealth(fe down) = (%d, %v, %v), want (1, false, nil)", aliveBEs, feOK, err)
	}

	// Verify InitCatalog honors SetDDLOptions while defaulting to replication_num=1.
	if err := b.InitCatalog(ctx, "es_compat"); err != nil || !strings.Contains(capturedDDL, `"replication_num" = "1"`) {
		t.Fatalf("default InitCatalog DDL missing replication_num=1: err=%v ddl=%s", err, capturedDDL)
	}
	b.SetDDLOptions(schema.DorisDDLOptions{ReplicationNum: 3})
	if err := b.InitCatalog(ctx, "es_compat"); err != nil || !strings.Contains(capturedDDL, `"replication_num" = "3"`) {
		t.Fatalf("ReplicationNum=3 InitCatalog DDL mismatch: err=%v ddl=%s", err, capturedDDL)
	}
	b.SetDDLOptions(schema.DorisDDLOptions{CloudMode: true})
	if err := b.InitCatalog(ctx, "es_compat"); err != nil || strings.Contains(capturedDDL, "replication_") {
		t.Fatalf("CloudMode InitCatalog DDL must omit replication properties: err=%v ddl=%s", err, capturedDDL)
	}

	// 2. Fallback candidate gating: NEVER retry timeouts/non-missing-column errors; DO retry 1054/Unknown column.
	var errMode atomic.Int32 // 1 = timeout, 2 = mysql 1054
	var qCalls atomic.Int64
	dbGate := openRound67MockDB(t, func(query string, _ []driver.NamedValue) round67SQLQuerySpec {
		n := qCalls.Add(1)
		switch errMode.Load() {
		case 1:
			return round67SQLQuerySpec{err: context.DeadlineExceeded}
		case 2:
			if n == 1 || strings.Contains(query, "`_doc`") || strings.Contains(query, "`_routing`") {
				return round67SQLQuerySpec{err: &mysql.MySQLError{Number: 1054, Message: "Unknown column '_routing' in 'field list'"}}
			}
			return round67SQLQuerySpec{
				cols: []string{"_id", "_version", "_source", "_raw_doc", "_score", "_total_hits"},
				rows: [][]driver.Value{{"id1", int64(1), `{"k":1}`, `{}`, float64(1.0), int64(1)}},
			}
		}
		return round67SQLQuerySpec{}
	})
	bGate := NewDorisSQLBackend(dbGate, nil)

	errMode.Store(1)
	qCalls.Store(0)
	if _, _, err := bGate.GetDocByID(ctx, "es_compat", "t", "id1"); err == nil || qCalls.Load() != 1 {
		t.Fatalf("GetDocByID must NOT retry on DeadlineExceeded: calls=%d err=%v", qCalls.Load(), err)
	}
	qCalls.Store(0)
	if _, err := bGate.GetDocsByIDs(ctx, "es_compat", "t", []string{"id1"}); err == nil || qCalls.Load() != 1 {
		t.Fatalf("GetDocsByIDs must NOT retry on DeadlineExceeded: calls=%d err=%v", qCalls.Load(), err)
	}
	qCalls.Store(0)
	if _, err := bGate.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, CAST(1 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`t` LIMIT 10"); err == nil || qCalls.Load() != 1 {
		t.Fatalf("QueryHits must NOT retry on DeadlineExceeded: calls=%d err=%v", qCalls.Load(), err)
	}

	// MySQL 1054 DOES trigger candidate fallback cleanly + fast-path _raw_doc `{}` returns source directly.
	errMode.Store(2)
	qCalls.Store(0)
	hits, err := bGate.QueryHits(ctx, "SELECT `_id`, `_version`, `_source`, CAST(1 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`t` LIMIT 10")
	if err != nil || len(hits) != 1 || qCalls.Load() < 2 || string(hits[0].RawSource) != `{"k":1}` {
		t.Fatalf("expected 1054 missing-column fallback + raw_doc fast-path, got hits=%+v calls=%d err=%v", hits, qCalls.Load(), err)
	}
}

func TestRound67_NormalizeDorisSQL_ZeroAllocs(t *testing.T) {
	// NormalizeDorisSQL allocates 0 bytes/op when query has no internal rewrite markers.
	plainSQL := "SELECT `_id`, `_version`, `_source` FROM `es_compat`.`orders` WHERE `status` = 'paid' LIMIT 10"
	allocs := testing.AllocsPerRun(50, func() {
		if out := NormalizeDorisSQL(plainSQL); out != plainSQL {
			t.Fatalf("unexpected rewrite of plain SQL: %s", out)
		}
	})
	if allocs != 0 {
		t.Fatalf("expected NormalizeDorisSQL 0 allocs on normal SQL, got %.1f", allocs)
	}
}

// -----------------------------------------------------------------------------
// Deliverable 5: QueryResultCache & ShardRequestCache Isolation Tests
// -----------------------------------------------------------------------------

func TestRound67_Caches_SecurityEpochRawBase64APIKeyParamsAndMappingHash(t *testing.T) {
	t.Parallel()

	srv := NewServer("es_compat", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	rawMapping := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{"title": {Type: "text"}},
	}
	sc := schema.CompileIndexSchema("es_compat", "idx_c", rawMapping)
	sc.RawMapping = rawMapping

	srv.mu.Lock()
	srv.indices["idx_c"] = sc
	srv.securityUsers["alice"] = map[string]any{"roles": []string{"r_one"}}
	srv.securityRoles["r_one"] = map[string]any{"indices": []any{map[string]any{"names": []string{"idx_c"}, "privileges": []string{"read"}}}}
	srv.securityAPIKeys["ak1"] = map[string]any{"id": "ak1", "username": "alice", "role": "r_one"}
	srv.mu.Unlock()

	makeReq := func(auth string, rawQuery string) *http.Request {
		r := &http.Request{
			Method: http.MethodPost,
			URL:    &url.URL{Path: "/idx_c/_search", RawQuery: rawQuery},
			Header: make(http.Header),
		}
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		return r
	}
	sReq := &esast.SearchRequest{Query: &esast.Query{MatchAll: map[string]any{}}}
	rawBody := []byte(`{"query":{"match_all":{}}}`)

	// 1. RawStdEncoding APIKey token resolves ak1 + alice's role definition and reflects role mutation.
	rawAPIKey := "ApiKey " + base64.RawStdEncoding.EncodeToString([]byte("ak1:secret_no_pad"))
	kBefore := srv.buildShardRequestCacheKeyR63(makeReq(rawAPIKey, ""), []string{"idx_c"}, []string{"idx_c"}, sReq, rawBody)
	srv.mu.Lock()
	srv.securityRoles["r_one"] = map[string]any{"indices": []any{map[string]any{"names": []string{"idx_c"}, "privileges": []string{"none"}}}}
	srv.mu.Unlock()
	kAfter := srv.buildShardRequestCacheKeyR63(makeReq(rawAPIKey, ""), []string{"idx_c"}, []string{"idx_c"}, sReq, rawBody)
	if kBefore == kAfter {
		t.Fatalf("expected RawStdEncoding ApiKey token to resolve role definition in cache key")
	}

	// 2. SecurityEpoch isolates BOTH ShardRequestCache and QueryResultCache (including wired epoch func).
	anonBeforeShard := srv.buildShardRequestCacheKeyR63(makeReq("", ""), []string{"idx_c"}, []string{"idx_c"}, sReq, rawBody)
	anonBeforeQC := srv.buildQueryCacheAuthScopeR66(makeReq("", ""))
	srv.SetAllowTestFixtureAuth(true)
	anonAfterShard := srv.buildShardRequestCacheKeyR63(makeReq("", ""), []string{"idx_c"}, []string{"idx_c"}, sReq, rawBody)
	anonAfterQC := srv.buildQueryCacheAuthScopeR66(makeReq("", ""))
	if anonBeforeShard == anonAfterShard || anonBeforeQC == anonAfterQC {
		t.Fatalf("expected SecurityEpoch bump to change both ShardRequestCache and QueryResultCache scopes")
	}

	qc := newQueryResultCache()
	qc.Configure(time.Minute, 16)
	var epoch atomic.Uint64
	epoch.Store(1)
	qc.SetSecurityEpochFunc(epoch.Load)
	qc.Put([]string{"idx_c"}, sReq, map[string]any{"hits": map[string]any{"total": 1}})
	if _, ok := qc.Get([]string{"idx_c"}, sReq); !ok {
		t.Fatalf("expected QueryResultCache hit at same SecurityEpoch")
	}
	epoch.Store(2)
	if _, ok := qc.Get([]string{"idx_c"}, sReq); ok {
		t.Fatalf("expected QueryResultCache miss after SecurityEpoch increment")
	}

	// 3. All 10 response-shaping URL params isolate ShardRequestCache, QueryCacheAuthScope, and QueryResultCache.
	baseShard := srv.buildShardRequestCacheKeyR63(makeReq("", ""), []string{"idx_c"}, []string{"idx_c"}, sReq, rawBody)
	baseScope := srv.buildQueryCacheAuthScopeR66(makeReq("", ""))
	baseQC, ok := buildQueryCacheKeyWithAuthAndParams([]string{"idx_c"}, sReq, "", 1, nil)
	if !ok {
		t.Fatalf("buildQueryCacheKeyWithAuthAndParams failed")
	}
	seenScopes := make(map[string]string)
	for _, p := range []string{
		"typed_keys=true",
		"rest_total_hits_as_int=true",
		"search_type=dfs_query_then_fetch",
		"preference=_local",
		"filter_path=hits.hits._id",
		"pretty=true",
		"human=true",
		"format=yaml",
		"source=%7B%7D",
		"source_content_type=application/json",
	} {
		paramName := strings.SplitN(p, "=", 2)[0]
		shK := srv.buildShardRequestCacheKeyR63(makeReq("", p), []string{"idx_c"}, []string{"idx_c"}, sReq, rawBody)
		scK := srv.buildQueryCacheAuthScopeR66(makeReq("", p))
		qv, _ := url.ParseQuery(p)
		qcK, _ := buildQueryCacheKeyWithAuthAndParams([]string{"idx_c"}, sReq, "", 1, qv)
		if shK == baseShard || scK == baseScope || qcK == baseQC {
			t.Fatalf("param %s failed to isolate caches", p)
		}
		if prev, dup := seenScopes[scK]; dup {
			t.Fatalf("param %s collided with %s in QueryCacheAuthScope", paramName, prev)
		}
		seenScopes[scK] = paramName
	}

	// 4. buildShardRequestCacheKeyR63 reads precomputed sc.MappingHash instead of json.Marshal(sc.RawMapping).
	// Mutating RawMapping alone while MappingHash is non-empty leaves key unchanged; changing MappingHash updates key!
	srv.mu.Lock()
	sc.MappingHash = "precomputed-hash-v1"
	srv.mu.Unlock()
	kHash1 := srv.buildShardRequestCacheKeyR63(makeReq("", ""), []string{"idx_c"}, []string{"idx_c"}, sReq, rawBody)
	srv.mu.Lock()
	sc.RawMapping = &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"extra_unhashed": {Type: "keyword"}}}
	srv.mu.Unlock()
	kRawMutatedSameHash := srv.buildShardRequestCacheKeyR63(makeReq("", ""), []string{"idx_c"}, []string{"idx_c"}, sReq, rawBody)
	if kHash1 != kRawMutatedSameHash {
		t.Fatalf("expected buildShardRequestCacheKeyR63 to use MappingHash rather than re-marshaling RawMapping")
	}
	srv.mu.Lock()
	sc.MappingHash = "precomputed-hash-v2"
	srv.mu.Unlock()
	kHash2 := srv.buildShardRequestCacheKeyR63(makeReq("", ""), []string{"idx_c"}, []string{"idx_c"}, sReq, rawBody)
	if kHash1 == kHash2 {
		t.Fatalf("expected MappingHash update to isolate ShardRequestCache key")
	}
}

// -----------------------------------------------------------------------------
// Deliverable 6: Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkNormalizeDorisSQL(b *testing.B) {
	q := "SELECT `_id`, `_version`, `_source`, CAST(1.0 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`orders` WHERE `status` = 'paid' AND `total` >= 100 ORDER BY `_score` DESC, `_id` ASC LIMIT 20"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if NormalizeDorisSQL(q) == "" {
			b.Fatal("empty normalized sql")
		}
	}
}

func BenchmarkQueryHits_RawDocMerge(b *testing.B) {
	ctx := context.Background()
	b.Run("fastpath_empty_variant", func(b *testing.B) {
		db := openRound67MockDB(b, func(query string, _ []driver.NamedValue) round67SQLQuerySpec {
			rows := make([][]driver.Value, 50)
			for i := range rows {
				rows[i] = []driver.Value{fmt.Sprintf("id-%d", i), int64(1), `{"title":"widget","price":10.5}`, `{}`, float64(1.0), int64(50)}
			}
			return round67SQLQuerySpec{
				cols: []string{"_id", "_version", "_source", "_raw_doc", "_score", "_total_hits"},
				rows: rows,
			}
		})
		be := NewDorisSQLBackend(db, nil)
		q := "SELECT `_id`, `_version`, `_source`, CAST(1 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`orders` LIMIT 50"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hits, err := be.QueryHits(ctx, q)
			if err != nil || len(hits) != 50 {
				b.Fatalf("QueryHits failed: len=%d err=%v", len(hits), err)
			}
		}
	})
	b.Run("merge_dynamic_variant", func(b *testing.B) {
		db := openRound67MockDB(b, func(query string, _ []driver.NamedValue) round67SQLQuerySpec {
			rows := make([][]driver.Value, 50)
			for i := range rows {
				rows[i] = []driver.Value{fmt.Sprintf("id-%d", i), int64(1), `{"title":"widget"}`, `{"title":"widget","dyn":42}`, float64(1.0), int64(50)}
			}
			return round67SQLQuerySpec{
				cols: []string{"_id", "_version", "_source", "_raw_doc", "_score", "_total_hits"},
				rows: rows,
			}
		})
		be := NewDorisSQLBackend(db, nil)
		q := "SELECT `_id`, `_version`, `_source`, CAST(1 AS DOUBLE) AS `_score`, COUNT(*) OVER() AS `_total_hits` FROM `es_compat`.`orders` LIMIT 50"
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hits, err := be.QueryHits(ctx, q)
			if err != nil || len(hits) != 50 {
				b.Fatalf("QueryHits failed: len=%d err=%v", len(hits), err)
			}
		}
	})
}

func BenchmarkStreamLoad_NDJSON(b *testing.B) {
	ctx := context.Background()
	sl := NewStreamLoadClient(StreamLoadConfig{
		FEHTTPEndpoint: "https://doris-fe.internal:8030",
		User:           "root",
		Database:       "es_compat",
		MaxRetries:     -1,
	})
	sl.SetDiscoveredBEs([]string{"https://be1.internal:8040", "https://be2.internal:8040"})
	sl.httpClient = &http.Client{
		CheckRedirect: sl.checkStreamLoadRedirect,
		Transport: round67TestRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			_, _ = io.Copy(io.Discard, req.Body)
			return newRound67TestJSONResponse(req, http.StatusOK, nil, `{"Status":"Success"}`), nil
		}),
	}
	payload := []byte(strings.Repeat(`{"_id":"1","title":"hello world","price":99.5,"__DORIS_DELETE_SIGN__":0}`+"\n", 100))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sl.LoadNDJSON(ctx, "orders", payload, false); err != nil {
			b.Fatalf("LoadNDJSON failed: %v", err)
		}
	}
}

func BenchmarkMemBackend_EvalWhereExpr(b *testing.B) {
	row := map[string]any{
		"_id":       "doc-1",
		"f__title":  "apache doris search engine",
		"f__status": "published",
		"f__price":  149.99,
		"_source":   `{"title":"apache doris search engine","a.b":"val","score":42.5}`,
		"n__items":  []string{`{"name__keyword":"LONG_NAME","score":10.5}`},
	}
	whereExpr := "(`f__status` = 'published' AND TRY_CAST(json_extract_string(`_source`, '$.\"score\"') AS DOUBLE) >= 10.0 AND json_extract_string(`_source`, '$.\"a.b\"') = 'val')"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !evalWhereExpr(row, whereExpr) {
			b.Fatal("expected evalWhereExpr to evaluate true")
		}
	}
}
