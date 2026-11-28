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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

type r67TSCustomBackend struct {
	mem          *MemoryBackend
	mu           sync.Mutex
	getDocErr    error
	queryRowsOut []map[string]any
	queryRowsErr error
}

func newR67TSCustomBackend() *r67TSCustomBackend {
	return &r67TSCustomBackend{mem: NewMemoryBackend(false)}
}

func (b *r67TSCustomBackend) Ping(ctx context.Context) error { return b.mem.Ping(ctx) }
func (b *r67TSCustomBackend) ExecDDL(ctx context.Context, ddl string) error {
	return b.mem.ExecDDL(ctx, ddl)
}
func (b *r67TSCustomBackend) QueryHits(ctx context.Context, sqlStr string) ([]HitRow, error) {
	return b.mem.QueryHits(ctx, sqlStr)
}
func (b *r67TSCustomBackend) QueryAggs(ctx context.Context, sqlStr string) ([]AggRow, error) {
	return b.mem.QueryAggs(ctx, sqlStr)
}
func (b *r67TSCustomBackend) GetDocByID(ctx context.Context, db, table, id string) (*HitRow, bool, error) {
	b.mu.Lock()
	err := b.getDocErr
	b.mu.Unlock()
	if err != nil {
		return nil, false, err
	}
	return b.mem.GetDocByID(ctx, db, table, id)
}
func (b *r67TSCustomBackend) GetDocsByIDs(ctx context.Context, db, table string, ids []string) (map[string]HitRow, error) {
	return b.mem.GetDocsByIDs(ctx, db, table, ids)
}
func (b *r67TSCustomBackend) StreamLoad(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
	return b.mem.StreamLoad(ctx, table, ndjson, syncRefresh)
}
func (b *r67TSCustomBackend) QueryRows(_ context.Context, _ string) ([]map[string]any, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.queryRowsErr != nil {
		return nil, b.queryRowsErr
	}
	return b.queryRowsOut, nil
}

func newR67TSSrv(t *testing.T, ver string) (*Server, http.Handler) {
	t.Helper()
	mem := NewMemoryBackend(false)
	srv := NewServer("es_r67ts", mem, transpiler.TranspilerOptions{})
	if ver != "" {
		srv.SetTargetESVersion(ver)
	}
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, srv.Handler()
}

func newR67TSSrvWithBackend(t *testing.T, ver string, be DorisBackend) (*Server, http.Handler) {
	t.Helper()
	srv := NewServer("es_r67ts", be, transpiler.TranspilerOptions{})
	if ver != "" {
		srv.SetTargetESVersion(ver)
	}
	t.Cleanup(func() {
		_ = srv.Close(context.Background())
	})
	return srv, srv.Handler()
}

func doR67TSHTTP(t *testing.T, h http.Handler, method, path, body string, hdrs map[string]string) (int, http.Header, map[string]any, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	if trimmed := strings.TrimSpace(raw); strings.HasPrefix(trimmed, "{") {
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.UseNumber()
		_ = dec.Decode(&parsed)
	}
	return rec.Code, rec.Header(), parsed, raw
}

func mustR67TSHTTP(t *testing.T, h http.Handler, method, path, body string, want int) map[string]any {
	t.Helper()
	code, _, parsed, raw := doR67TSHTTP(t, h, method, path, body, nil)
	if code != want {
		t.Fatalf("%s %s: expected status %d, got %d body=%s", method, path, want, code, raw)
	}
	return parsed
}

func doR67TSDirectHandler(t *testing.T, fn func(http.ResponseWriter, *http.Request), method, path, body string, pathVals map[string]string) (int, map[string]any, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range pathVals {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	fn(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	if trimmed := strings.TrimSpace(raw); strings.HasPrefix(trimmed, "{") {
		dec := json.NewDecoder(strings.NewReader(trimmed))
		dec.UseNumber()
		_ = dec.Decode(&parsed)
	}
	return rec.Code, parsed, raw
}

func r67TSIntPtr(v int) *int           { return &v }
func r67TSFloatPtr(v float64) *float64 { return &v }
func r67TSBoolPtr(v bool) *bool        { return &v }

func TestRound67TopUpSrv_MemBackendR63EvalColumnFuncsAndTryCast(t *testing.T) {
	b64Payload := base64.StdEncoding.EncodeToString([]byte("hello-bin"))
	row := map[string]any{
		"_id":         "1",
		"dt":          "2026-05-01 12:34:56.789123",
		"s":           "abc-123-xyz",
		"b64":         b64Payload,
		"bad_b64":     "!!!not-base64!!!",
		"arr1":        []any{"a", "b", "c", "b"},
		"arr2":        []string{"b", "c", "d"},
		"arr3":        []any{"c", "e"},
		"utf8_s":      "αβγde",
		"num_s":       "42",
		"num_arr":     []any{"10", "bad", "20"},
		"flt_arr":     []any{1.5, json.Number("2.5")},
		"flt_str":     "[1.25, 2.75]",
		"str_json":    `["x","y"]`,
		"obj_json":    `{"k": 1}`,
		"num_val":     float64(123.4567),
		"bool_str":    "true",
		"null_col":    nil,
		"vec_str_arr": []string{"1", "2"},
		"_doc":        `{"a": {"b": [1, 2, 3]}}`,
	}

	// Lambda arrow helpers (`findTopLevelLambdaArrowR66Mem`, `hasNestedLambdaExprR66Mem`)
	if idx := findTopLevelLambdaArrowR66Mem(`x -> (x + '->' + "->" + ` + "`->`" + ` + (y -> y))`); idx != 2 {
		t.Fatalf("expected top-level lambda arrow at 2, got %d", idx)
	}
	if idx := findTopLevelLambdaArrowR66Mem(`'escaped''quote' -> z`); idx < 0 {
		t.Fatalf("expected arrow after escaped single quotes, got %d", idx)
	}
	if idx := findTopLevelLambdaArrowR66Mem(`"esc\"quote"`); idx != -1 {
		t.Fatalf("expected -1 when no arrow, got %d", idx)
	}
	if idx := findTopLevelLambdaArrowR66Mem("`esc``tick` -> x"); idx < 0 {
		t.Fatalf("expected arrow after escaped backtick, got %d", idx)
	}
	if !hasNestedLambdaExprR66Mem("SELECT array_exists(x -> array_exists(y -> y > 1, x), `arr`)") {
		t.Fatalf("expected nested lambda detection to return true")
	}
	if hasNestedLambdaExprR66Mem("SELECT array_exists(x -> x = '->', `arr`)") {
		t.Fatalf("expected arrow inside single quotes not to trigger nested lambda")
	}

	// TRY_CAST / CAST / JSON_TYPE / JSON_LENGTH / MICROSECOND / TRANSLATE / FROM_BASE64_BINARY
	cases := []struct {
		expr   string
		wantOK bool
		check  func(t *testing.T, v any)
	}{
		{"TRY_CAST(`num_s` AS BIGINT)", true, func(t *testing.T, v any) {
			if v != int64(42) {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRY_CAST(`num_arr` AS INT)", true, func(t *testing.T, v any) {
			arr, ok := v.([]any)
			if !ok || len(arr) != 2 {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRY_CAST(`flt_str` AS ARRAY<DOUBLE>)", true, func(t *testing.T, v any) {
			arr, ok := v.([]float64)
			if !ok || len(arr) != 2 {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRY_CAST(`flt_arr` AS ARRAY<FLOAT>)", true, func(t *testing.T, v any) {
			arr, ok := v.([]float64)
			if !ok || len(arr) != 2 {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRY_CAST(`str_json` AS ARRAY<STRING>)", true, func(t *testing.T, v any) {
			arr, ok := v.([]string)
			if !ok || len(arr) != 2 {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRY_CAST(`obj_json` AS JSON)", true, func(t *testing.T, v any) {
			if _, ok := v.(map[string]any); !ok {
				t.Fatalf("got %T %v", v, v)
			}
		}},
		{"TRY_CAST(`bool_str` AS BOOLEAN)", true, func(t *testing.T, v any) {
			if v != true {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRY_CAST(`num_s` AS STRING)", true, func(t *testing.T, v any) {
			if v != "42" {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRY_CAST(`num_arr` AS DOUBLE)", true, func(t *testing.T, v any) {
			arr, ok := v.([]any)
			if !ok || len(arr) != 2 {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRY_CAST(`dt` AS DATETIMEV2(3))", true, func(t *testing.T, v any) {
			if v == nil {
				t.Fatalf("expected non-nil DATETIMEV2")
			}
		}},
		{"CAST(`dt` AS DATETIMEV2(6))", true, func(t *testing.T, v any) {
			if v == nil {
				t.Fatalf("expected non-nil CAST DATETIMEV2")
			}
		}},
		{"JSON_TYPE(`_doc`, '$.a')", true, func(t *testing.T, v any) {
			if v == nil {
				t.Fatalf("expected JSON_TYPE non-nil")
			}
		}},
		{"JSON_TYPE(`_doc`)", true, func(t *testing.T, v any) {
			if v != nil {
				t.Fatalf("expected nil for 1-arg JSON_TYPE, got %v", v)
			}
		}},
		{"JSON_LENGTH(`_doc`, '$.a.b')", true, func(t *testing.T, v any) {
			if v == nil {
				t.Fatalf("expected JSON_LENGTH non-nil")
			}
		}},
		{"JSON_LENGTH(`_doc`)", true, func(t *testing.T, v any) {
			if v == nil {
				t.Fatalf("expected 1-arg JSON_LENGTH non-nil")
			}
		}},
		{"JSON_LENGTH(`_doc`, 'a', 'b')", true, func(t *testing.T, v any) {
			if v != nil {
				t.Fatalf("expected nil for 3-arg JSON_LENGTH, got %v", v)
			}
		}},
		{"MICROSECOND(`dt`)", true, func(t *testing.T, v any) {
			if v != int64(789123) {
				t.Fatalf("expected 789123, got %v", v)
			}
		}},
		{"MICROSECOND(`null_col`)", true, func(t *testing.T, v any) {
			if v != nil {
				t.Fatalf("expected nil, got %v", v)
			}
		}},
		{"TRANSLATE(`s`, 'ax-', 'AX')", true, func(t *testing.T, v any) {
			if v != "Abc123Xyz" {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRANSLATE(`s`, 'ax')", true, func(t *testing.T, v any) {
			if v != nil {
				t.Fatalf("expected nil for 2-arg TRANSLATE, got %v", v)
			}
		}},
		{"FROM_BASE64_BINARY(`b64`)", true, func(t *testing.T, v any) {
			if b, ok := v.([]byte); !ok || string(b) != "hello-bin" {
				t.Fatalf("got %v", v)
			}
		}},
		{"FROM_BASE64_BINARY(`bad_b64`)", true, func(t *testing.T, v any) {
			if v != nil {
				t.Fatalf("expected nil on invalid b64, got %v", v)
			}
		}},
		{"REGEXP_EXTRACT(`s`, '([0-9]+)', 1)", true, func(t *testing.T, v any) {
			if v != "123" {
				t.Fatalf("got %v", v)
			}
		}},
		{"REGEXP_EXTRACT(`s`, '([0-9]+)', 9)", true, func(t *testing.T, v any) {
			if v != "" {
				t.Fatalf("got %v", v)
			}
		}},
		{"REGEXP_EXTRACT(`s`, '[bad', 0)", true, func(t *testing.T, v any) {
			if v != "" {
				t.Fatalf("got %v", v)
			}
		}},
		{"REGEXP_REPLACE(`s`, '[0-9]+', 'NUM')", true, func(t *testing.T, v any) {
			if v != "abc-NUM-xyz" {
				t.Fatalf("got %v", v)
			}
		}},
		{"REGEXP_REPLACE(`s`, '[bad', 'NUM')", true, func(t *testing.T, v any) {
			if v != "abc-123-xyz" {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_JOIN(`arr1`, ',')", true, func(t *testing.T, v any) {
			if v != "a,b,c,b" {
				t.Fatalf("got %v", v)
			}
		}},
		{"SPLIT_BY_STRING(`s`, '-')", true, func(t *testing.T, v any) {
			if sl, ok := v.([]string); !ok || len(sl) != 3 {
				t.Fatalf("got %v", v)
			}
		}},
		{"OCTET_LENGTH(`utf8_s`)", true, func(t *testing.T, v any) {
			if v != int64(len("αβγde")) {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRUNCATE(`num_val`, 2)", true, func(t *testing.T, v any) {
			if v != 123.45 {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRUNCATE(`num_val`, 0)", true, func(t *testing.T, v any) {
			if v != 123.0 {
				t.Fatalf("got %v", v)
			}
		}},
		{"TRUNCATE(10 + 5.5, 0)", true, func(t *testing.T, v any) {
			if v != 15.0 {
				t.Fatalf("got %v", v)
			}
		}},
		{"IFNULL(`null_col`, 'fallback')", true, func(t *testing.T, v any) {
			if v != "fallback" {
				t.Fatalf("got %v", v)
			}
		}},
		{"IFNULL(`num_s`, 'fallback')", true, func(t *testing.T, v any) {
			if v != "42" {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_REMOVE(`arr1`, 'b')", true, func(t *testing.T, v any) {
			if arr, ok := v.([]any); !ok || len(arr) != 2 {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_REMOVE(`vec_str_arr`, '1')", true, func(t *testing.T, v any) {
			if arr, ok := v.([]any); !ok || len(arr) != 1 || arr[0] != "2" {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_REMOVE(`arr1`, NULL)", true, func(t *testing.T, v any) {
			if v != nil {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_INTERSECT(`arr1`, `arr2`, `arr3`)", true, func(t *testing.T, v any) {
			if arr, ok := v.([]any); !ok || len(arr) != 1 || arr[0] != "c" {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_INTERSECT(`arr1`)", true, func(t *testing.T, v any) {
			if v != nil {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_UNION(`arr1`, `arr2`)", true, func(t *testing.T, v any) {
			if arr, ok := v.([]any); !ok || len(arr) != 4 {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_UNION(`arr1`, `null_col`)", true, func(t *testing.T, v any) {
			if v != nil {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_EXCEPT(`arr1`, `arr2`)", true, func(t *testing.T, v any) {
			if arr, ok := v.([]any); !ok || len(arr) != 1 || arr[0] != "a" {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_REPEAT('z', 3)", true, func(t *testing.T, v any) {
			if arr, ok := v.([]any); !ok || len(arr) != 3 {
				t.Fatalf("got %v", v)
			}
		}},
		{"ARRAY_REPEAT('z', 0)", true, func(t *testing.T, v any) {
			if arr, ok := v.([]any); !ok || len(arr) != 0 {
				t.Fatalf("got %v", v)
			}
		}},
		{"INSTR(`utf8_s`, 'γ')", true, func(t *testing.T, v any) {
			if v != int64(3) {
				t.Fatalf("got %v", v)
			}
		}},
		{"INSTR(`utf8_s`, 'missing')", true, func(t *testing.T, v any) {
			if v != int64(0) {
				t.Fatalf("got %v", v)
			}
		}},
		{"INSTR(`null_col`, 'a')", true, func(t *testing.T, v any) {
			if v != nil {
				t.Fatalf("got %v", v)
			}
		}},
	}
	for _, tc := range cases {
		got, ok := evalColumnFuncR63Mem(row, tc.expr)
		if ok != tc.wantOK {
			t.Fatalf("%s: wantOK=%v got=%v", tc.expr, tc.wantOK, ok)
		}
		if tc.check != nil {
			tc.check(t, got)
		}
	}

	// `extractBM25ClauseSpecR63Mem`
	bm25SQL := "(CASE WHEN (`f__body` IS NOT NULL) THEN (2.5 * (GREATEST(CAST(CHAR_LENGTH(REGEXP_REPLACE(LOWER(COALESCE(CAST(`f__body` AS STRING), '')), '[^[:alnum:]_\\']+', ' ')) - CHAR_LENGTH(REPLACE(REGEXP_REPLACE(LOWER(COALESCE(CAST(`f__body` AS STRING), '')), '[^[:alnum:]_\\']+', ' '), 'hello  world', '')) AS DOUBLE) / 11.0, 0.0) / (1.0 + 1.2 * (1.0 - 0.75 + 0.75 * 1.0)))) ELSE 0.0 END)"
	spec, okBM := extractBM25ClauseSpecR63Mem(bm25SQL)
	if !okBM || spec.colExpr != "`f__body`" || len(spec.terms) != 2 {
		t.Fatalf("unexpected BM25 spec: ok=%v spec=%+v", okBM, spec)
	}
}

func TestRound67TopUpSrv_MemBackendEvalAggBranchResolveColAndSubqueries(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("raw"))
	rows := []map[string]any{
		{
			"_id":         "doc1",
			"f__tags":     []any{"go", "doris", "go"},
			"f__cat":      "tech",
			"f__parent":   "p1",
			"f__kind":     "parent",
			"f__score":    10.0,
			"f__ts":       int64(1700000000123),
			"f__dt":       "2026-05-01T12:34:56.123456Z",
			"f__str":      "  HelloWorld  ",
			"f__hex":      "6869",
			"f__b64":      b64,
			"f__num":      int64(3232235777), // 192.168.1.1
			"f__ip6":      make([]byte, 16),
			"f__vec":      []any{1.0, 0.0},
			"_doc":        `{"nested":{"k":"v'1"}}`,
			"_source":     `{"nested":{"k":"v'1"}}`,
			"f__str_list": []string{"ab", "cde"},
		},
		{
			"_id":       "doc2",
			"f__tags":   []any{},
			"f__cat":    "news",
			"f__parent": "p2",
			"f__kind":   "child",
			"f__score":  5.0,
			"f__ts":     int64(1700000005000),
		},
	}

	// evalAggBranch: HAVING + array explode + cardinality + value_count
	resCardArr := evalAggBranch(rows, "SELECT 'c_arr' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT `_elem`) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`f__tags`) `_t` AS `_elem` WHERE (`f__cat` = 'tech') AND `_elem` IS NOT NULL")
	if len(resCardArr) != 1 || resCardArr[0].DocCount != 2 {
		t.Fatalf("unexpected card array result: %+v", resCardArr)
	}
	resCardScalar := evalAggBranch(rows, "SELECT 'c_sc' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT `f__cat`) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `f__score` > 0")
	if len(resCardScalar) != 1 || resCardScalar[0].DocCount != 2 {
		t.Fatalf("unexpected card scalar result: %+v", resCardScalar)
	}
	resValCntArr := evalAggBranch(rows, "SELECT 'vc_arr' AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(`_elem`) AS DOUBLE) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE(`f__tags`) `_t` AS `_elem` WHERE (`f__cat` = 'tech') AND `_elem` IS NOT NULL")
	if len(resValCntArr) != 1 || resValCntArr[0].DocCount != 3 {
		t.Fatalf("unexpected value_count array result: %+v", resValCntArr)
	}
	resHaving := evalAggBranch(rows, "SELECT 't' AS `_agg_name`, COALESCE(CAST(`f__cat` AS STRING), '__ES_MISSING__') AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` GROUP BY `_bucket_key` HAVING `_doc_count` >= 1 ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 10")
	if len(resHaving) != 2 {
		t.Fatalf("expected 2 buckets from HAVING branch, got %+v", resHaving)
	}
	resHavingGt0 := evalAggBranch(rows, "SELECT 't2' AS `_agg_name`, COALESCE(CAST(`f__cat` AS STRING), '__ES_MISSING__') AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT 10 HAVING SUM(1) > 0")
	if len(resHavingGt0) == 0 {
		t.Fatalf("expected non-empty HAVING SUM(...) > 0 result")
	}

	// resolveColumnValue & evalColumnFuncR62Mem branches
	r0 := rows[0]
	colChecks := []struct {
		expr string
		want any
	}{
		{"DATE_FORMAT(`f__ts`, '%Y-%m-%d %H:%i:%s %T %F %f %% %z')", "2023-11-14 22:13:20 22:13:20 2023-11-14 123000 % %z"},
		{"CONCAT(`f__cat`, '-', `f__kind`)", "tech-parent"},
		{"LENGTH(`f__cat`)", int64(4)},
		{"CHAR_LENGTH(`f__str_list`)", []any{int64(2), int64(3)}},
		{"lower(`f__str`)", "  helloworld  "},
		{"UPPER(`f__str_list`)", []any{"AB", "CDE"}},
		{"TRIM(`f__str`)", "HelloWorld"},
		{"`base_matched`.`f__cat`", "tech"},
		{"`_doc`['nested']['k']", "v'1"},
		{"[NULL]", []any{nil}},
		{"[`f__cat`]", []string{"tech"}},
		{"RIGHT(`f__cat`, 2)", "ch"},
		{"RPAD(`f__cat`, 7, 'XY')", "techXYX"},
		{"REPLACE(`f__cat`, 'ec', 'EC')", "tECh"},
		{"CONV('ff', 16, 10)", "255"},
		{"IPV4_NUM_TO_STRING(`f__num`)", "192.168.1.1"},
		{"IPV6_NUM_TO_STRING(`f__ip6`)", "::"},
		{"COSINE_DISTANCE(`f__vec`, [1.0, 0.0])", 0.0},
		{"L2_DISTANCE(`f__vec`, [1.0, 0.0])", 0.0},
		{"INNER_PRODUCT(`f__vec`, [1.0, 0.0])", 1.0},
	}
	for _, cc := range colChecks {
		got := resolveColumnValue(r0, cc.expr)
		if !reflect.DeepEqual(got, cc.want) {
			t.Fatalf("resolveColumnValue(%s): got %#v (%T), want %#v (%T)", cc.expr, got, got, cc.want, cc.want)
		}
	}
	if b, ok := evalColumnFuncR62Mem(r0, "UNHEX(`f__hex`)"); !ok || string(b.([]byte)) != "hi" {
		t.Fatalf("UNHEX failed: ok=%v b=%v", ok, b)
	}
	if b, ok := evalColumnFuncR62Mem(r0, "FROM_BASE64(`f__b64`)"); !ok || string(b.([]byte)) != "raw" {
		t.Fatalf("FROM_BASE64 failed: ok=%v b=%v", ok, b)
	}
	_ = resolveColumnValue(r0, "FROM_UNIXTIME(1700000000)")
	_ = resolveColumnValue(r0, "CONVERT_TZ(`f__dt`, 'UTC', '+08:00')")
	_ = resolveColumnValue(r0, "DATE_TRUNC(`f__dt`, 'day')")
	_ = resolveColumnValue(r0, "SECONDS_ADD(`f__dt`, 10)")
	_ = resolveColumnValue(r0, "TIMESTAMPDIFF(SECOND, `f__dt`, `f__dt`)")
	_ = resolveColumnValue(r0, "UNIX_TIMESTAMP(`f__dt`)")
	_ = resolveColumnValue(r0, "MICROSECOND(`f__dt`)")

	// resolveRound62AggSubqueriesR62Mem: sampler, diversified_sampler, children
	smpExpr := "`_id` IN (SELECT `_id` FROM (SELECT `_id` FROM `base_matched` WHERE `f__score` > 0 ORDER BY CAST(`f__score` AS DOUBLE) DESC, `_id` ASC LIMIT 1))"
	if out := resolveRound62AggSubqueriesR62Mem(rows, smpExpr); !strings.Contains(out, "'doc1'") {
		t.Fatalf("expected sampler to select doc1, got %s", out)
	}
	divExpr := "`_id` IN (SELECT `_id` FROM (SELECT `_id`, ROW_NUMBER() OVER (PARTITION BY `_ds_key` ORDER BY `_ds_score` DESC, `_id` ASC) AS `_ds_rn` FROM (SELECT `_id`, `f__cat` AS `_ds_key`, CAST(`f__score` AS DOUBLE) AS `_ds_score` FROM `base_matched` WHERE `f__score` > 0 ORDER BY `_ds_score` DESC, `_id` ASC LIMIT 5)) WHERE `_ds_rn` <= 1)"
	if out := resolveRound62AggSubqueriesR62Mem(rows, divExpr); !strings.Contains(out, "'doc1'") || !strings.Contains(out, "'doc2'") {
		t.Fatalf("expected diversified_sampler to select both docs, got %s", out)
	}
	childExpr := "`f__parent` IN (SELECT `_id` FROM `base_matched` WHERE `f__kind` = 'parent')"
	if out := resolveRound62AggSubqueriesR62Mem(rows, childExpr); !strings.Contains(out, "'doc1'") {
		t.Fatalf("expected children subquery to resolve doc1, got %s", out)
	}

	// evalFulltextMatch branches (slice, regexp, phrase slop)
	ftRow := map[string]any{
		"a": []any{"Quick Brown", "Fox"},
		"b": []string{"alpha beta gamma"},
	}
	if !evalFulltextMatch(ftRow, "`a`", "MATCH_REGEXP", "bro.*") {
		t.Fatalf("expected MATCH_REGEXP on []any to match")
	}
	if !evalFulltextMatch(ftRow, "`b`", "MATCH_PHRASE", "alpha gamma~1") {
		t.Fatalf("expected MATCH_PHRASE with slop on []string to match")
	}
	if evalFulltextMatch(ftRow, "`a`", "MATCH_REGEXP", "[invalid") {
		t.Fatalf("expected invalid regex to return false")
	}
}

func TestRound67TopUpSrv_ServerPutDocBulkSearchFilterAndInnerHits(t *testing.T) {
	srv, h := newR67TSSrv(t, "8.15.5")

	// Data stream with failure store enabled
	mustR67TSHTTP(t, h, http.MethodPut, "/_index_template/r67ts_ds_tpl", `{
		"index_patterns":["r67ts-ds-*"],
		"data_stream":{"failure_store":{"enabled":true}},
		"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"cnt":{"type":"long"}}}}
	}`, http.StatusOK)
	mustR67TSHTTP(t, h, http.MethodPut, "/_data_stream/r67ts-ds-1", "", http.StatusOK)
	// Invalid date causes shred error and records into failure store
	code, _, _, raw := doR67TSHTTP(t, h, http.MethodPost, "/r67ts-ds-1/_doc", `{"@timestamp":"not-a-date","cnt":"not-a-long"}`, nil)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("expected failure store redirect on PUT/POST doc, got %d %s", code, raw)
	}

	// TSDB index (`handlePutDoc` & `handleBulk` TSDB paths)
	mustR67TSHTTP(t, h, http.MethodPut, "/r67ts_tsdb", `{
		"settings":{"index.mode":"time_series","index.routing_path":["host"]},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true},"cpu":{"type":"double","time_series_metric":"gauge"}}}
	}`, http.StatusOK)
	mustR67TSHTTP(t, h, http.MethodPost, "/r67ts_tsdb/_doc?refresh=true", `{"@timestamp":"2026-05-01T00:00:00Z","host":"h1","cpu":1.5}`, http.StatusCreated)
	// Explicit _id /_create rejected on TSDB index
	code, _, _, _ = doR67TSHTTP(t, h, http.MethodPost, "/r67ts_tsdb/_create/ignored?refresh=true", `{"@timestamp":"2026-05-01T00:00:00Z","host":"h1","cpu":2.0}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on TSDB _create with explicit id, got %d", code)
	}
	// Bulk TSDB create + conflict + missing routing on routing-required index
	mustR67TSHTTP(t, h, http.MethodPut, "/r67ts_rt_req", `{"mappings":{"_routing":{"required":true},"properties":{"tag":{"type":"keyword"}}}}`, http.StatusOK)
	bulkBody := strings.Join([]string{
		`{"create":{"_index":"r67ts_tsdb"}}`,
		`{"@timestamp":"2026-05-01T00:00:00Z","host":"h1","cpu":3.0}`,
		`{"index":{"_index":"r67ts_tsdb"}}`,
		`{"@timestamp":"2026-05-01T00:01:00Z","host":"h2","cpu":4.0}`,
		`{"index":{"_index":"r67ts_rt_req","_id":"1"}}`,
		`{"tag":"missing-routing"}`,
		"",
	}, "\n")
	bulkResp := mustR67TSHTTP(t, h, http.MethodPost, "/_bulk?refresh=true", bulkBody, http.StatusOK)
	if bulkResp["errors"] != true {
		t.Fatalf("expected bulk errors=true, got %v", bulkResp)
	}

	// `executeSearchRequest` expand_wildcards empty stateFiltered with allow_no_indices=false vs true + scroll + rest_total_hits_as_int
	mustR67TSHTTP(t, h, http.MethodPut, "/r67ts_closed_ew", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67TSHTTP(t, h, http.MethodPost, "/r67ts_closed_ew/_close", "", http.StatusOK)
	code, _, _, _ = doR67TSHTTP(t, h, http.MethodGet, "/r67ts_closed_ew/_search?expand_wildcards=open&allow_no_indices=false", `{"query":{"match_all":{}}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for literal closed index, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h, http.MethodGet, "/r67ts_closed_*/_search?expand_wildcards=open&allow_no_indices=false", `{"query":{"match_all":{}}}`, nil)
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 when expand_wildcards filters out wildcard closed index and allow_no_indices=false, got %d", code)
	}
	ewResp := mustR67TSHTTP(t, h, http.MethodGet, "/r67ts_closed_*/_search?expand_wildcards=open&allow_no_indices=true&scroll=1m&rest_total_hits_as_int=true", `{"query":{"match_all":{}}}`, http.StatusOK)
	if _, ok := ewResp["_scroll_id"]; !ok {
		t.Fatalf("expected _scroll_id in empty expand_wildcards response: %v", ewResp)
	}

	// `buildNestedInnerHitsForHitWithOpts` with dynamic unmapped nested path
	ihHit := HitRow{
		ID:     "h1",
		Index:  "r67ts_rt_req",
		Source: json.RawMessage(`{"items":[{"name":"apple","qty":3},{"name":"pear","qty":1}]}`),
	}
	nq := &esast.NestedQuery{
		Path:      "items",
		Query:     esast.Query{Term: map[string]esast.TermEntry{"items.name": {Value: "apple"}}},
		InnerHits: &esast.InnerHitsSpec{Size: r67TSIntPtr(5)},
	}
	ihEnv := buildNestedInnerHitsForHitWithOpts(ihHit, "r67ts_rt_req", nil, nq, false)
	hitsWrap, _ := ihEnv["hits"].(map[string]any)
	if hitsSlice, _ := hitsWrap["hits"].([]map[string]any); len(hitsSlice) != 1 {
		t.Fatalf("expected 1 nested inner hit, got %+v", ihEnv)
	}

	// `buildHighlightedFieldSnippetsWithMaxOffset`
	reHL := regexp.MustCompile(`(?i)needle`)
	snips := buildHighlightedFieldSnippetsWithMaxOffset(
		[]string{"prefix text needle middle text needle tail & <unanalyzed>"},
		reHL, "<em>", "</em>", true, 20, 2, 10, 38,
	)
	if len(snips) == 0 {
		t.Fatalf("expected highlighted snippets")
	}
	noMatchSnips := buildHighlightedFieldSnippetsWithMaxOffset(
		[]string{"no hit in this long string"},
		reHL, "<em>", "</em>", false, 15, 1, 8, 100,
	)
	if len(noMatchSnips) != 1 || len([]rune(noMatchSnips[0])) != 8 {
		t.Fatalf("expected 8-rune no_match snippet, got %v", noMatchSnips)
	}

	// `evalRuntimeMappingsOnHitRows` covering unsigned_long, long, double, boolean, date_nanos, date, geo_shape, dotted field, emit()
	rtSchema := schema.CompileIndexSchema("es_r67ts", "r67ts_rt_eval", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"base": {Type: "long"},
		},
	})
	rtMap := map[string]esast.FieldProperty{
		"ul_num":   {Type: "unsigned_long", Script: "emit(12345)"},
		"ul_str":   {Type: "unsigned_long", Script: "'999'"},
		"i_val":    {Type: "long", Script: "emit(42)"},
		"d_val":    {Type: "double", Script: "emit(3.25)"},
		"b_val":    {Type: "boolean", Script: "emit(true)"},
		"dn_val":   {Type: "date_nanos", Script: "emit('2026-05-01T00:00:00.123456789Z')"},
		"dt_val":   {Type: "date", Script: "emit('2026-05-01T00:00:00Z')"},
		"gs_val":   {Type: "geo_shape", Script: "emit('POINT (1 2)')"},
		"nest.sub": {Type: "keyword", Script: "emit('subv')"},
	}
	rtHits := []HitRow{{
		ID:     "rt1",
		Index:  "r67ts_rt_eval",
		Source: json.RawMessage(`{"base":7}`),
	}}
	srv.evalRuntimeMappingsOnHitRows(rtSchema, rtMap, rtHits)
	var rtOut map[string]any
	if err := json.Unmarshal(rtHits[0].RawSource, &rtOut); err != nil {
		t.Fatalf("failed to unmarshal runtime-enriched RawSource %q: %v", string(rtHits[0].RawSource), err)
	}
	nestMap, _ := rtOut["nest"].(map[string]any)
	if rtOut["ul_num"] == nil || rtOut["b_val"] != true || (rtOut["nest.sub"] != "subv" && nestMap["sub"] != "subv") {
		t.Fatalf("unexpected runtime fields evaluated in RawSource: %+v", rtOut)
	}

	// `scoreSearchQueryOnDoc` via both MemoryBackend and custom non-MemoryBackend + `evalRandomScoreOnDoc`
	custBE := newR67TSCustomBackend()
	srvCust, _ := newR67TSSrvWithBackend(t, "8.15.5", custBE)
	docScore := map[string]any{"__meta_id": "s1", "title": "hello world"}
	qTerm := &esast.Query{Match: map[string]esast.MatchEntry{"title": {Query: "hello"}}}
	sc1 := srv.scoreNonScriptDocWithCorpusR66(context.Background(), "r67ts_rt_eval", rtSchema, docScore, &esast.Query{MatchAll: map[string]any{}}, nil, nil)
	sc2 := srvCust.scoreNonScriptDocWithCorpusR66(context.Background(), "r67ts_rt_eval", rtSchema, docScore, qTerm, nil, nil)
	if sc1 != 1.0 || sc2 < 0 {
		t.Fatalf("unexpected scores: sc1=%v sc2=%v", sc1, sc2)
	}
	if rSc := evalRandomScoreOnDoc(docScore, nil); rSc != 0.5 {
		t.Fatalf("expected 0.5 for nil random_score, got %v", rSc)
	}
}

func TestRound67TopUpSrv_ServerTermsSortBucketSortAndValidation(t *testing.T) {
	_, h := newR67TSSrv(t, "8.15.5")

	// `handleCreateIndex` error paths: missing default/final pipeline, TSDB + routing, TSDB + non-synthetic source
	mustR67TSHTTP(t, h, http.MethodPut, "/_ingest/pipeline/r67ts_ok_pipe", `{"processors":[{"set":{"field":"p","value":"1"}}]}`, http.StatusOK)
	code, _, _, _ := doR67TSHTTP(t, h, http.MethodPut, "/r67ts_bad_dp", `{"settings":{"index.default_pipeline":"missing_pipe"}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing default_pipeline, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h, http.MethodPut, "/r67ts_bad_fp", `{"settings":{"index.final_pipeline":"missing_pipe"}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing final_pipeline, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h, http.MethodPut, "/r67ts_tsdb_rt", `{"settings":{"index.mode":"time_series"},"mappings":{"_routing":{"required":true}}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for TSDB with _routing, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h, http.MethodPut, "/r67ts_tsdb_src", `{"settings":{"index.mode":"time_series"},"mappings":{"_source":{"enabled":false}}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for TSDB with disabled _source, got %d", code)
	}

	// `filterAndSortTermsRowsWithSubAggs` with missing bucket, numeric keys, sub-agg metric, top_metrics
	numIdxSchema := schema.CompileIndexSchema("es_r67ts", "r67ts_num", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"code": {Type: "long"},
			"val":  {Type: "double"},
		},
	})
	rows := []AggRow{
		{AggName: "g", BucketKey: "10", DocCount: 2},
		{AggName: "g", BucketKey: "2", DocCount: 2},
		{AggName: "g", BucketKey: "__ES_MISSING_BUCKET__", DocCount: 1},
	}
	subRows := map[string][]AggRow{
		"g.s": {
			{AggName: "g.s", BucketKey: "10", Value: 50},
			{AggName: "g.s", BucketKey: "2", Value: 10},
			{AggName: "g.s", BucketKey: "__ES_MISSING_BUCKET__", Value: 5},
		},
	}
	subAggs := map[string]esast.AggSpec{
		"s": {Sum: &esast.MetricAggSpec{Field: "val"}},
	}
	specKey := &esast.TermsAggSpec{
		Field:        "code",
		MissingOrder: "first",
		Order:        map[string]any{"_key": "asc"},
	}
	sortedKey, _ := filterAndSortTermsRowsWithSubAggs(rows, specKey, "g", "", subRows, subAggs, "r67ts_num", nil, numIdxSchema)
	if len(sortedKey) != 3 || sortedKey[0].BucketKey != "__ES_MISSING_BUCKET__" || sortedKey[1].BucketKey != "2" {
		t.Fatalf("unexpected sorted terms rows: %+v", sortedKey)
	}
	specSub := &esast.TermsAggSpec{
		Field: "code",
		Order: []any{map[string]any{"s": "desc"}},
	}
	sortedSub, _ := filterAndSortTermsRowsWithSubAggs(rows, specSub, "g", "", subRows, subAggs, "r67ts_num", nil, numIdxSchema)
	if len(sortedSub) != 3 || sortedSub[0].BucketKey != "10" {
		t.Fatalf("unexpected sub-agg sorted terms rows: %+v", sortedSub)
	}

	// `evaluateBucketSortPipelineAggs`: composite `_key.sub`, `insert_zeros`, `missing: _first`, `from`/`size`
	buckets := []map[string]any{
		{"key": map[string]any{"sub": "b"}, "doc_count": int64(2), "m": map[string]any{"value": 5.0}},
		{"key": map[string]any{"sub": "a"}, "doc_count": int64(3)},
		{"key": map[string]any{"sub": "c"}, "doc_count": int64(1), "m": map[string]any{"value": 2.0}},
	}
	bsAggs := map[string]esast.AggSpec{
		"bs": {BucketSort: &esast.BucketSortAggSpec{
			GapPolicy: "insert_zeros",
			Sort: esast.SortSlice{
				{Entry: esast.SortFieldSpec{Field: "m", Order: "asc"}},
				{Entry: esast.SortFieldSpec{Field: "_key.sub", Order: "asc"}},
			},
			From: r67TSIntPtr(0),
			Size: r67TSIntPtr(2),
		}},
	}
	bsOut := evaluateBucketSortPipelineAggs(buckets, bsAggs)
	if len(bsOut) != 2 {
		t.Fatalf("expected 2 buckets after bucket_sort, got %d", len(bsOut))
	}
	// Composite map key sorting without `.sub` + missing: _first
	bsMapKey := map[string]esast.AggSpec{
		"bs": {BucketSort: &esast.BucketSortAggSpec{
			GapPolicy: "insert_zeros",
			Sort: esast.SortSlice{
				{Entry: esast.SortFieldSpec{Field: "m", Order: "desc", Missing: "_first"}},
				{Entry: esast.SortFieldSpec{Field: "_key", Order: "asc"}},
			},
		}},
	}
	_ = evaluateBucketSortPipelineAggs(buckets, bsMapKey)

	// `validateTopHitsAndPipelineScriptErrorsR65`
	thAggs := map[string]esast.AggSpec{
		"outer_slice": {
			Terms: &esast.TermsAggSpec{Field: "k"},
			Aggs: map[string]esast.AggSpec{
				"th": {TopHits: &esast.TopHitsAggSpec{Size: r67TSIntPtr(1)}},
				"bs": {BucketScript: &esast.BucketSelectorAggSpec{
					BucketsPath: map[string]string{"x": "th._source.missing_field"},
					Script:      "params.x",
				}},
			},
		},
		"outer_map": {
			Filters: &esast.FiltersAggSpec{Filters: map[string]esast.Query{"f1": {MatchAll: map[string]any{}}}},
			Aggs: map[string]esast.AggSpec{
				"th": {TopHits: &esast.TopHitsAggSpec{Size: r67TSIntPtr(1)}},
				"bs": {BucketScript: &esast.BucketSelectorAggSpec{
					BucketsPath: map[string]string{"x": "th._source.ok"},
					Script:      "params.x",
				}},
			},
		},
	}
	aggsOut := map[string]any{
		"outer_slice": map[string]any{
			"buckets": []any{
				map[string]any{
					"key":       "k1",
					"doc_count": int64(1),
					"th": map[string]any{
						"hits": map[string]any{
							"hits": []any{
								map[string]any{"_id": "1", "_source": map[string]any{"ok": 1}},
							},
						},
					},
				},
			},
		},
		"outer_map": map[string]any{
			"buckets": map[string]any{
				"f1": map[string]any{
					"doc_count": int64(1),
					"th": map[string]any{
						"hits": map[string]any{
							"hits": []any{
								map[string]any{"_id": "2", "_source": map[string]any{"ok": 1}},
							},
						},
					},
				},
			},
		},
	}
	if err := validateTopHitsAndPipelineScriptErrorsR65(thAggs, nil, aggsOut, nil); err == nil {
		t.Fatalf("expected error for missing _source path in bucket_script")
	}

	// `extractHitSortValues` across unsigned_long, boolean, date_nanos, date, double, lowercase, missing
	sortSchema := schema.CompileIndexSchema("es_r67ts", "r67ts_sort", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"ul": {Type: "unsigned_long"},
			"b":  {Type: "boolean"},
			"dn": {Type: "date_nanos"},
			"dt": {Type: "date"},
			"fl": {Type: "double"},
			"kw": {Type: "keyword", Normalizer: "lowercase"},
		},
	})
	sortHit := HitRow{
		ID:     "s1",
		Index:  "r67ts_sort",
		Schema: sortSchema,
		Source: json.RawMessage(`{"ul":18446744073709551610,"b":"true","dn":"2026-05-01T00:00:00.123456789Z","dt":"2026-05-01T00:00:00Z","fl":"12.5","kw":"HeLLo"}`),
	}
	sorts := []esast.SortSpec{
		{Entry: esast.SortFieldSpec{Field: "ul"}},
		{Entry: esast.SortFieldSpec{Field: "b"}},
		{Entry: esast.SortFieldSpec{Field: "dn"}},
		{Entry: esast.SortFieldSpec{Field: "dt"}},
		{Entry: esast.SortFieldSpec{Field: "fl"}},
		{Entry: esast.SortFieldSpec{Field: "kw"}},
		{Entry: esast.SortFieldSpec{Field: "missing_ul", Missing: "_last", Order: "asc"}},
		{Entry: esast.SortFieldSpec{Field: "missing_b", Missing: "false", Type: "boolean"}},
		{Entry: esast.SortFieldSpec{Field: "missing_dn", Missing: "2026-05-01T00:00:00Z"}},
	}
	sVals := extractHitSortValues(sortHit, sorts, sortSchema)
	if len(sVals) != len(sorts) {
		t.Fatalf("expected %d sort values, got %d", len(sorts), len(sVals))
	}
}

func TestRound67TopUpSrv_SearchRuntimeRRFIntervalsScriptScoreAndFields(t *testing.T) {
	srv, h := newR67TSSrv(t, "8.15.5")

	// Stored script for script_score & intervals tests
	mustR67TSHTTP(t, h, http.MethodPut, "/_scripts/r67ts_score_script", `{"script":{"lang":"painless","source":"return _score * 2.0;"}}`, http.StatusOK)
	mustR67TSHTTP(t, h, http.MethodPut, "/_scripts/r67ts_interval_script", `{"script":{"lang":"painless","source":"return interval.gaps <= 2;"}}`, http.StatusOK)

	// 1. `evalRuntimeMappingsOrderedOnDocWithOutR62Search`: nested runtime fields (scalar, geo_point, geo_shape, script emit & on_script_error=continue) + composite
	nestedSchema := schema.CompileIndexSchema("es_r67ts", "r67ts_nested_rt", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"name": {Type: "keyword"},
					"loc":  {Type: "geo_point"},
					"area": {Type: "geo_shape"},
					"qty":  {Type: "long"},
				},
			},
		},
	})
	rtNestedMap := map[string]esast.FieldProperty{
		"items.rt_qty":   {Type: "long", Script: "emit(doc['items.qty'].value + 1)"},
		"items.rt_bad":   {Type: "long", OnScriptError: "continue", Script: "throw new Exception('boom')"},
		"items.rt_plain": {Type: "keyword"},
		"items.loc":      {Type: "geo_point"},
		"items.area":     {Type: "geo_shape"},
		"comp_rt":        {Type: "composite", Fields: map[string]esast.FieldProperty{"sub": {Type: "keyword"}}},
	}
	rtOrder := []string{"items.rt_qty", "items.rt_bad", "items.rt_plain", "items.loc", "items.area", "comp_rt"}
	nestedDoc := map[string]any{
		"items": []any{
			map[string]any{
				"name":     "book",
				"qty":      int64(4),
				"rt_plain": "ok",
				"loc":      map[string]any{"lat": 10.0, "lon": 20.0},
				"area":     map[string]any{"type": "Point", "coordinates": []any{20.0, 10.0}},
			},
		},
	}
	_, rtOut, mod, _, err := evalRuntimeMappingsOrderedOnDocWithOutR62Search(nestedSchema, rtNestedMap, rtOrder, nestedDoc, true)
	if err != nil || !mod || rtOut["items.rt_qty"] == nil {
		t.Fatalf("unexpected nested runtime eval result: mod=%v err=%v out=%+v", mod, err, rtOut)
	}

	// 2. `emitRuntimeSignificantTextAggRowsR62Search` with unmergedOverwrittenSources + filter_duplicate_text + source_fields
	sigSchema := schema.CompileIndexSchema("es_r67ts", "r67ts_sig", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"body": {Type: "text"},
			"tag":  {Type: "keyword"},
		},
	})
	srv.recordUnmergedOverwrittenSourceR66("r67ts_sig", []byte(`{"body":"common filler text","tag":"bg"}`))
	scope := &activeSearchScope{srv: srv, ctx: context.Background()}
	fgDocs := []runtimeMatchedDoc{
		{hit: HitRow{ID: "1", Schema: sigSchema, SearchScope: scope}, doc: map[string]any{"body": "doris proxy analytics doris"}, rootDoc: map[string]any{"body": "doris proxy analytics doris"}, rootSchema: sigSchema},
		{hit: HitRow{ID: "2", Schema: sigSchema, SearchScope: scope}, doc: map[string]any{"body": "doris proxy vector search"}, rootDoc: map[string]any{"body": "doris proxy vector search"}, rootSchema: sigSchema},
	}
	bgDocs := append([]runtimeMatchedDoc{}, fgDocs...)
	bgDocs = append(bgDocs, runtimeMatchedDoc{hit: HitRow{ID: "3", Schema: sigSchema, SearchScope: scope}, doc: map[string]any{"body": "common filler text"}, rootDoc: map[string]any{"body": "common filler text"}, rootSchema: sigSchema})
	var sigOut []AggRow
	sigSpec := esast.AggSpec{
		SignificantText: &esast.TermsAggSpec{
			Field:               "body",
			Size:                5,
			FilterDuplicateText: r67TSBoolPtr(true),
			SourceFields:        []string{"body"},
		},
	}
	emitRuntimeSignificantTextAggRowsR62Search("sig", "", sigSpec, fgDocs, bgDocs, &sigOut, sigSchema)
	if len(sigOut) == 0 {
		t.Fatalf("expected significant_text agg rows")
	}

	// 3. `executeRRFSearchR62Search`: rank_window_size < size error, retriever.rrf with standard/knn/rule/nested rrf
	mustR67TSHTTP(t, h, http.MethodPut, "/r67ts_rrf", `{"mappings":{"properties":{"title":{"type":"text"},"vec":{"type":"dense_vector","dims":2}}}}`, http.StatusOK)
	mustR67TSHTTP(t, h, http.MethodPost, "/r67ts_rrf/_doc/1?refresh=true", `{"title":"doris search","vec":[1.0,0.0]}`, http.StatusCreated)
	rrfBad := &esast.SearchRequest{
		Size: r67TSIntPtr(20),
		Rank: &esast.RankSpec{RRF: &esast.RRFSpec{WindowSize: r67TSIntPtr(5)}},
	}
	_, stRRF, _, _ := srv.executeRRFSearchR62Search(context.Background(), nil, "r67ts_rrf", []string{"r67ts_rrf"}, rrfBad, time.Now())
	if stRRF != http.StatusBadRequest {
		t.Fatalf("expected 400 when rank_window_size < size, got %d", stRRF)
	}
	rrfRet := &esast.SearchRequest{
		Size: r67TSIntPtr(5),
		Rank: &esast.RankSpec{RRF: &esast.RRFSpec{WindowSize: r67TSIntPtr(10), RankConstant: r67TSIntPtr(60)}},
		Retriever: &esast.RetrieverSpec{
			RRF: &esast.RRFRetrieverSpec{
				Filter: esast.QuerySlice{{MatchAll: map[string]any{}}},
				Retrievers: []esast.RetrieverSpec{
					{Standard: &esast.StandardRetrieverSpec{Query: &esast.Query{MatchAll: map[string]any{}}}},
					{KNN: &esast.KNNRetrieverSpec{Field: "vec", QueryVector: []float64{1.0, 0.0}, K: 3, HasK: true}},
					{Rule: &esast.RuleRetrieverSpec{Retriever: &esast.RetrieverSpec{Standard: &esast.StandardRetrieverSpec{Query: &esast.Query{MatchAll: map[string]any{}}}}}},
				},
			},
		},
	}
	rrfResp, stRRF2, etRRF, erRRF := srv.executeRRFSearchR62Search(context.Background(), nil, "r67ts_rrf", []string{"r67ts_rrf"}, rrfRet, time.Now())
	if stRRF2 != http.StatusOK || rrfResp == nil {
		t.Fatalf("expected retriever RRF success, got %d %s %s", stRRF2, etRRF, erRRF)
	}

	// 4. `emitSingleMatchedFieldIntoOutR61Search`: flattened, constant_keyword, aggregate_metric_double, token_count, murmur3, date/date_nanos
	fieldSchema := schema.CompileIndexSchema("es_r67ts", "r67ts_fields", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"id_alias": {Type: "alias", Path: "_id"},
			"flat":     {Type: "flattened"},
			"ck":       {Type: "constant_keyword", Value: "const_v"},
			"agg_m":    {Type: "aggregate_metric_double", Metrics: []string{"min", "max", "sum", "value_count"}, DefaultMetric: "sum"},
			"title":    {Type: "text", Fields: map[string]esast.FieldProperty{"cnt": {Type: "token_count", Analyzer: "standard"}, "hash": {Type: "murmur3"}}},
			"dt":       {Type: "date"},
			"dt_ns":    {Type: "date_nanos"},
		},
	})
	fieldDoc := map[string]any{
		"flat":  map[string]any{"k1": "v1", "k2": 2},
		"agg_m": map[string]any{"min": json.Number("1"), "max": json.Number("9"), "sum": json.Number("10.5"), "ignored": 99},
		"title": "hello world",
		"dt":    "2026-05-01T00:00:00Z",
		"dt_ns": "2026-05-01T00:00:00.123456789Z",
	}
	fieldHit := HitRow{ID: "f1", Index: "r67ts_fields", Schema: fieldSchema, SearchScope: scope}
	outFields := make(map[string][]any)
	for _, fn := range []string{"id_alias", "flat", "flat.k1", "ck", "agg_m", "title.cnt", "title.hash"} {
		st, et, er := emitSingleMatchedFieldIntoOutR61Search(fieldHit, "r67ts_fields", fieldDoc, nil, nil, fn, fn, "", false, fieldSchema, outFields)
		if st != 0 {
			t.Fatalf("emitSingleMatchedFieldIntoOutR61Search(%s) failed: %d %s %s", fn, st, et, er)
		}
	}
	if len(outFields["id_alias"]) != 1 || len(outFields["ck"]) != 1 || len(outFields["title.cnt"]) != 1 {
		t.Fatalf("unexpected emitted fields: %+v", outFields)
	}
	// docvalue_fields on aggregate_metric_double -> 400 error; docvalue_fields on flattened -> sorted strings; date_nanos epoch_millis
	if st, _, _ := emitSingleMatchedFieldIntoOutR61Search(fieldHit, "r67ts_fields", fieldDoc, nil, nil, "agg_m", "agg_m", "", true, fieldSchema, outFields); st != http.StatusBadRequest {
		t.Fatalf("expected 400 for docvalue_fields on aggregate_metric_double, got %d", st)
	}
	_, _, _ = emitSingleMatchedFieldIntoOutR61Search(fieldHit, "r67ts_fields", fieldDoc, nil, nil, "flat", "flat", "", true, fieldSchema, outFields)
	_, _, _ = emitSingleMatchedFieldIntoOutR61Search(fieldHit, "r67ts_fields", fieldDoc, nil, nil, "dt", "dt", "epoch_millis", true, fieldSchema, outFields)
	_, _, _ = emitSingleMatchedFieldIntoOutR61Search(fieldHit, "r67ts_fields", fieldDoc, nil, nil, "dt_ns", "dt_ns", "epoch_millis", true, fieldSchema, outFields)

	// 5. `evalAndValidateSearchScriptScoreR61Search`: stored script, compile error, non-numeric error, negative score error, function_score with field_value_factor + random_score + weight
	activeStoredScriptsServerMu.Lock()
	prevSrv := activeStoredScriptsServer
	activeStoredScriptsServer = srv
	activeStoredScriptsServerMu.Unlock()
	t.Cleanup(func() {
		activeStoredScriptsServerMu.Lock()
		activeStoredScriptsServer = prevSrv
		activeStoredScriptsServerMu.Unlock()
	})

	ssDoc := map[string]any{"__meta_id": "d1", "price": 10.0, "body": "alpha beta gamma"}
	// Stored script_score with boost & min_score
	sc, okSS, stSS, _ := evalAndValidateSearchScriptScoreR61Search(sigSchema, ssDoc, &esast.Query{
		ScriptScore: &esast.ScriptScoreQuery{
			Query:    &esast.Query{MatchAll: map[string]any{}},
			Script:   map[string]any{"id": "r67ts_score_script"},
			Boost:    r67TSFloatPtr(2.0),
			MinScore: r67TSFloatPtr(1.0),
		},
	}, 1.5, true)
	if !okSS || stSS != 0 || sc <= 0 {
		t.Fatalf("expected stored script_score pass, got sc=%v ok=%v st=%d", sc, okSS, stSS)
	}
	// Non-numeric return -> 400
	_, _, stNonNum, _ := evalAndValidateSearchScriptScoreR61Search(sigSchema, ssDoc, &esast.Query{
		ScriptScore: &esast.ScriptScoreQuery{Script: "return 'abc';"},
	}, 1.0, true)
	if stNonNum != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-numeric script_score, got %d", stNonNum)
	}
	// Negative return -> 400
	_, _, stNeg, _ := evalAndValidateSearchScriptScoreR61Search(sigSchema, ssDoc, &esast.Query{
		ScriptScore: &esast.ScriptScoreQuery{Script: "return -1.0;"},
	}, 1.0, true)
	if stNeg != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative script_score, got %d", stNeg)
	}
	// FunctionScore with functions (script_score, field_value_factor, random_score, score_mode=first)
	scFS, okFS, stFS, _ := evalAndValidateSearchScriptScoreR61Search(sigSchema, ssDoc, &esast.Query{
		FunctionScore: &esast.FunctionScoreQuery{
			Query:     &esast.Query{MatchAll: map[string]any{}},
			ScoreMode: "first",
			Functions: []esast.ScoreFunctionSpec{
				{ScriptScore: &esast.ScriptScoreFunctionSpec{Script: map[string]any{"id": "r67ts_score_script"}}, Weight: r67TSFloatPtr(2.0)},
				{FieldValueFactor: &esast.FieldValueFactorSpec{Field: "price"}},
				{RandomScore: &esast.RandomScoreSpec{Field: "_id"}},
			},
		},
	}, 1.0, true)
	if !okFS || stFS != 0 || scFS <= 0 {
		t.Fatalf("expected function_score pass, got sc=%v ok=%v st=%d", scFS, okFS, stFS)
	}

	// 6. `evalIntervalsCompoundQueryR61Search`: all_of (max_gaps: 0), stored script filter, bool must_not/filter/must
	iq := &esast.Query{
		Bool: &esast.BoolQuery{
			Must: esast.QuerySlice{{
				Intervals: map[string]esast.IntervalsRule{
					"body": {
						AllOf: &esast.IntervalsAllOf{
							MaxGaps: r67TSIntPtr(0),
							Ordered: true,
							Intervals: []esast.IntervalsRule{
								{Match: &esast.IntervalsMatch{Query: "alpha"}},
								{Match: &esast.IntervalsMatch{Query: "beta"}},
							},
							Filter: &esast.IntervalsFilter{
								Script: &esast.ScriptSpec{ID: "r67ts_interval_script"},
							},
						},
					},
				},
			}},
			Filter: esast.QuerySlice{{
				Intervals: map[string]esast.IntervalsRule{
					"body": {Match: &esast.IntervalsMatch{Query: "gamma"}},
				},
			}},
		},
	}
	if m, isc, ierr := evalIntervalsCompoundQueryR61Search(sigSchema, ssDoc, iq, true, true); ierr != nil || !m || isc <= 0 {
		t.Fatalf("expected intervals compound match, got m=%v sc=%v err=%v", m, isc, ierr)
	}

	// 7. `applyExactQuantilesWalkR61Search` on []any, map[string]any, and empty doc_count=0 bucket
	qAggs := map[string]esast.AggSpec{
		"t_any": {
			Terms: &esast.TermsAggSpec{Field: "tag"},
			Aggs: map[string]esast.AggSpec{
				"pct": {Percentiles: &esast.PercentilesAggSpec{Field: "price", Percents: []float64{50, 95}}},
			},
		},
		"f_map": {
			Filters: &esast.FiltersAggSpec{Filters: map[string]esast.Query{"zero": {MatchAll: map[string]any{}}}},
			Aggs: map[string]esast.AggSpec{
				"pct": {Percentiles: &esast.PercentilesAggSpec{Field: "price", Percents: []float64{50}}},
			},
		},
		"wrap": {
			Filter: &esast.Query{MatchAll: map[string]any{}},
			Aggs: map[string]esast.AggSpec{
				"pct": {Percentiles: &esast.PercentilesAggSpec{Field: "price", Percents: []float64{50}}},
			},
		},
	}
	qContainer := map[string]any{
		"t_any": map[string]any{
			"buckets": []any{
				map[string]any{"key": "k1", "doc_count": int64(2), "pct": map[string]any{"values": map[string]any{}}},
			},
		},
		"f_map": map[string]any{
			"buckets": map[string]any{
				"zero": map[string]any{"doc_count": int64(0), "pct": map[string]any{"values": map[string]any{}}},
			},
		},
		"wrap": map[string]any{
			"doc_count": int64(1),
			"pct":       map[string]any{"values": map[string]any{}},
		},
	}
	rawVals := map[string]map[string][]float64{
		"t_any.pct": {"k1": {10, 20}},
		"wrap.pct":  {"": {10, 30}},
	}
	rawSeen := map[string]map[string]bool{
		"t_any.pct": {"k1": true},
		"f_map.pct": {"other": true},
		"wrap.pct":  {"": true},
	}
	if err := applyExactQuantilesWalkR61Search("", "", qAggs, qContainer, rawVals, rawSeen, true); err != nil {
		t.Fatalf("applyExactQuantilesWalkR61Search failed: %v", err)
	}
}

func TestRound67TopUpSrv_CRUDIndicesAdminFieldCapsAnalyzeAndModules(t *testing.T) {
	srv8, h8 := newR67TSSrv(t, "8.15.5")
	_, h7 := newR67TSSrv(t, "7.17.10")

	// 1. `handlePutMappingR61CRUD` error & compatibility branches
	mustR67TSHTTP(t, h7, http.MethodPut, "/r67ts_es7_map?include_type_name=true", `{"mappings":{"mytype":{"properties":{"a":{"type":"keyword"}}}}}`, http.StatusOK)
	code, _, _, _ := doR67TSHTTP(t, h7, http.MethodPut, "/r67ts_es7_map/_mapping?include_type_name=true", `{"other_type":{"properties":{"b":{"type":"keyword"}}}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on ES7 multiple mapping types, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h7, http.MethodPut, "/r67ts_es7_map/_mapping?include_type_name=true", `{"_bad":{"properties":{"b":{"type":"keyword"}}}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid _bad type name, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h7, http.MethodPut, "/r67ts_es7_map/_mapping", `{"_doc":{"properties":{"b":{"type":"keyword"}}}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on ES7 _doc without include_type_name, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodPut, "/r67ts_es7_map/_mapping/mytype", `{"properties":{"b":{"type":"keyword"}}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on ES8 path type in _mapping, got %d", code)
	}
	mustR67TSHTTP(t, h8, http.MethodPut, "/r67ts_tsdb_map", `{
		"settings":{"index.mode":"time_series","index.routing_path":["host"]},
		"mappings":{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword","time_series_dimension":true},"m":{"type":"long","time_series_metric":"gauge"}}}
	}`, http.StatusOK)
	// Shadowing TSDB routing path runtime field -> 400
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodPut, "/r67ts_tsdb_map/_mapping", `{"runtime":{"host":{"type":"keyword","script":"emit('x')"}}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 shadowing TSDB routing path runtime field, got %d", code)
	}
	// TSDB mapping update with _routing -> 400
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodPut, "/r67ts_tsdb_map/_mapping", `{"_routing":{"required":true}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for _routing on TSDB mapping update, got %d", code)
	}

	// 2. `resolveGetAliasTargetIndicesR61CRUD` via HTTP HEAD & GET /_alias
	mustR67TSHTTP(t, h8, http.MethodPut, "/.r67ts_hidden", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67TSHTTP(t, h8, http.MethodPut, "/r67ts_closed_al", `{"mappings":{"properties":{"k":{"type":"keyword"}}}}`, http.StatusOK)
	mustR67TSHTTP(t, h8, http.MethodPost, "/r67ts_closed_al/_alias/r67ts_alias_closed", "", http.StatusOK)
	mustR67TSHTTP(t, h8, http.MethodPost, "/r67ts_closed_al/_close", "", http.StatusOK)

	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodHead, "/_all/_alias?expand_wildcards=none&allow_no_indices=false", "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 on HEAD expand_wildcards=none allow_no_indices=false, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodGet, "/r67ts_missing_idx/_alias?ignore_unavailable=false", "", nil)
	if code != http.StatusNotFound {
		t.Fatalf("expected 404 on missing concrete index, got %d", code)
	}
	mustR67TSHTTP(t, h8, http.MethodGet, "/.r67ts_hidden/_alias?expand_wildcards=open,hidden", "", http.StatusOK)
	mustR67TSHTTP(t, h8, http.MethodGet, "/r67ts_alias_closed/_alias?expand_wildcards=open", "", http.StatusOK)

	// 3. `validateES8QueryCompatR61CRUD` across ES8 deprecated/removed query forms
	for _, q := range []*esast.Query{
		{GeoBoundingBox: &esast.GeoBoundingBoxQuery{Field: "loc", Type: "memory"}},
		{Type: &esast.TypeQuerySpec{Value: "_doc"}},
		{Common: map[string]esast.CommonTermsEntry{"body": {Query: "foo"}}},
		{Match: map[string]esast.MatchEntry{"body": {Query: "foo", CutoffFrequency: 0.1}}},
		{Bool: &esast.BoolQuery{Must: esast.QuerySlice{{Type: &esast.TypeQuerySpec{Value: "_doc"}}}}},
		{DisMax: &esast.DisMaxQuery{Queries: esast.QuerySlice{{Type: &esast.TypeQuerySpec{Value: "_doc"}}}}},
		{Boosting: &esast.BoostingQuery{Positive: esast.Query{Type: &esast.TypeQuerySpec{Value: "_doc"}}}},
		{ConstantScore: &esast.ConstantScoreQuery{Filter: esast.Query{Type: &esast.TypeQuerySpec{Value: "_doc"}}}},
		{HasChild: &esast.HasChildQuery{Type: "c", Query: esast.Query{Type: &esast.TypeQuerySpec{Value: "_doc"}}}},
		{HasParent: &esast.HasParentQuery{ParentType: "p", Query: esast.Query{Type: &esast.TypeQuerySpec{Value: "_doc"}}}},
		{Pinned: &esast.PinnedQuery{Organic: &esast.Query{Type: &esast.TypeQuerySpec{Value: "_doc"}}}},
		{Rule: &esast.RuleQuerySpec{Organic: &esast.Query{Type: &esast.TypeQuerySpec{Value: "_doc"}}}},
	} {
		req := &esast.SearchRequest{Query: q}
		st, _, _ := srv8.validateES8QueryCompatR61CRUD(httptest.NewRequest(http.MethodPost, "/_search", nil), req)
		if st != http.StatusBadRequest {
			t.Fatalf("expected 400 from validateES8QueryCompatR61CRUD, got %d", st)
		}
	}
	rescoreReq := &esast.SearchRequest{
		Rescore: esast.RescoreSlice{{Query: &esast.RescoreQuerySpec{RescoreQuery: &esast.Query{Type: &esast.TypeQuerySpec{Value: "_doc"}}}}},
	}
	if st, _, _ := srv8.validateES8QueryCompatR61CRUD(httptest.NewRequest(http.MethodPost, "/_search", nil), rescoreReq); st != http.StatusBadRequest {
		t.Fatalf("expected 400 for rescore ES8 compat, got %d", st)
	}

	// 4. `handleFieldCapsRound61`: negative index pattern, HEAD, runtime_mappings validation, index_filter, include_empty_fields=false, search_as_you_type, alias, unmapped
	mustR67TSHTTP(t, h8, http.MethodPut, "/r67ts_fc", `{
		"mappings":{
			"properties":{
				"msg":{"type":"text"},
				"sayt":{"type":"search_as_you_type"},
				"ts_at":{"type":"long"},
				"al_msg":{"type":"alias","path":"msg"},
				"obj":{"properties":{"sub":{"type":"boolean"}}}
			}
		}
	}`, http.StatusOK)
	mustR67TSHTTP(t, h8, http.MethodPost, "/r67ts_fc/_doc/1?refresh=true", `{"msg":"hi","dyn_txt":"hello","dyn_b":true,"dyn_i":5,"dyn_f":1.5,"obj":{"sub":true}}`, http.StatusCreated)
	code, _, _ = doR67TSDirectHandler(t, srv8.handleFieldCapsRound61, http.MethodHead, "/r67ts_fc/_field_caps", "", map[string]string{"index": "r67ts_fc"})
	if code != http.StatusOK {
		t.Fatalf("expected 200 for HEAD _field_caps, got %d", code)
	}
	code, _, _ = doR67TSDirectHandler(t, srv8.handleFieldCapsRound61, http.MethodGet, "/r67ts_fc/_field_caps?include_empty_fields=bogus", "", map[string]string{"index": "r67ts_fc"})
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bogus include_empty_fields, got %d", code)
	}
	code, _, _ = doR67TSDirectHandler(t, srv8.handleFieldCapsRound61, http.MethodPost, "/r67ts_fc/_field_caps", `{"runtime_mappings":{"bad":{"type":"keyword","script":{"lang":"mustache","source":"{{x}}"}}}}`, map[string]string{"index": "r67ts_fc"})
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported runtime script lang, got %d", code)
	}
	code, _, _ = doR67TSDirectHandler(t, srv8.handleFieldCapsRound61, http.MethodPost, "/r67ts_fc/_field_caps", `{"runtime_mappings":{"bad":{"type":"keyword","script":"if ("}}}`, map[string]string{"index": "r67ts_fc"})
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for runtime painless compile error, got %d", code)
	}
	code, fcResp, rawFC := doR67TSDirectHandler(t, srv8.handleFieldCapsRound61, http.MethodPost, "/-r67ts_missing/_field_caps?expand_wildcards=open", `{
		"fields":["*"],
		"types":["+runtime","text","keyword","long","date","boolean","double","unmapped"],
		"include_empty_fields":false,
		"include_unmapped":true,
		"index_filter":{"range":{"ts_at":{"gte":0}}}
	}`, map[string]string{"index": "-r67ts_missing"})
	if code != http.StatusOK || fcResp["fields"] == nil {
		t.Fatalf("expected 200 from negative _field_caps, got %d %s", code, rawFC)
	}

	// 5. `resolveAnalyzeFieldTargetCheckedR63Admin` & `serveAnalyzeR62Admin`
	mustR67TSHTTP(t, h8, http.MethodPut, "/r67ts_an", `{
		"settings":{"analysis":{"analyzer":{"default":{"type":"standard"},"custom_an":{"type":"keyword"}}}},
		"mappings":{"properties":{
			"al_kw":{"type":"alias","path":"kw"},
			"kw":{"type":"keyword"},
			"sayt":{"type":"search_as_you_type"},
			"sa":{"type":"text","search_analyzer":"custom_an"}
		}}
	}`, http.StatusOK)
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodPut, "/r67ts_an_cyc", `{"mappings":{"properties":{"a1":{"type":"alias","path":"a2"},"a2":{"type":"alias","path":"a1"}}}}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for cyclic alias mapping, got %d", code)
	}
	if _, _, err := srv8.resolveAnalyzeFieldTargetCheckedR63Admin(context.Background(), "r67ts_an", "al_kw", analysis.DefaultIndexAnalysisConfig(), map[string]bool{"kw": true}, 0); err == nil {
		t.Fatalf("expected alias cycle error in resolveAnalyzeFieldTargetCheckedR63Admin")
	}
	if an, _, err := srv8.resolveAnalyzeFieldTargetCheckedR63Admin(context.Background(), "r67ts_an", "sa", analysis.DefaultIndexAnalysisConfig(), nil, 0); err != nil || an != "custom_an" {
		t.Fatalf("expected custom_an, got an=%s err=%v", an, err)
	}
	if an, _, err := srv8.resolveAnalyzeFieldTargetCheckedR63Admin(context.Background(), "r67ts_an", "kw", analysis.DefaultIndexAnalysisConfig(), nil, 0); err != nil || an != "keyword" {
		t.Fatalf("expected keyword, got an=%s err=%v", an, err)
	}
	if an, _, err := srv8.resolveAnalyzeFieldTargetCheckedR63Admin(context.Background(), "r67ts_an", "sayt", analysis.DefaultIndexAnalysisConfig(), nil, 0); err != nil || an != "standard" {
		t.Fatalf("expected standard for sayt, got an=%s err=%v", an, err)
	}
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodGet, "/r67ts_an/_analyze?text=Hello%20World", `{"field":"sa"}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on _analyze with ?text=, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodPost, "/r67ts_an/_analyze", `{"bogus":1}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown _analyze param, got %d", code)
	}

	// 6. `serveDownsampleIndexRound63`: validation errors + full rollup execution
	mustR67TSHTTP(t, h8, http.MethodPost, "/r67ts_tsdb_map/_doc?refresh=true", `{"@timestamp":"2026-05-01T00:00:00Z","host":"h1","m":10}`, http.StatusCreated)
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodGet, "/r67ts_tsdb_map/_downsample/r67ts_tsdb_ds", `{"fixed_interval":"1h"}`, nil)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET _downsample, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodPost, "/r67ts_tsdb_map/_downsample/r67ts_tsdb_ds", `{"fixed_interval":"bad"}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid fixed_interval, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodPost, "/r67ts_fc/_downsample/r67ts_fc_ds", `{"fixed_interval":"1h"}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-TSDB _downsample in ES8, got %d", code)
	}
	mustR67TSHTTP(t, h8, http.MethodPost, "/r67ts_tsdb_map/_downsample/r67ts_tsdb_ds", `{"fixed_interval":"1h"}`, http.StatusOK)
	// Secondary downsample with smaller / non-multiple interval -> 400
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodPost, "/r67ts_tsdb_ds/_downsample/r67ts_tsdb_ds2", `{"fixed_interval":"30m"}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 when interval <= source interval, got %d", code)
	}
	code, _, _, _ = doR67TSHTTP(t, h8, http.MethodPost, "/r67ts_tsdb_ds/_downsample/r67ts_tsdb_ds2", `{"fixed_interval":"90m"}`, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 when interval not multiple of source interval, got %d", code)
	}

	// 7. `inspectESQLFromTargetSchemasRound63`: TSDB counter, dynamic:false, alias, nested, flattened, sayt, constant_keyword, doc_values:false, ambiguous types
	mustR67TSHTTP(t, h8, http.MethodPut, "/r67ts_esql_a", `{
		"settings":{"index.mode":"time_series","index.routing_path":["host"]},
		"mappings":{
			"dynamic":false,
			"properties":{
				"@timestamp":{"type":"date"},
				"host":{"type":"keyword","time_series_dimension":true,"ignore_above":128,"normalizer":"lowercase"},
				"cnt":{"type":"long","time_series_metric":"counter"},
				"al":{"type":"alias","path":"host"},
				"fl":{"type":"flattened"},
				"st":{"type":"search_as_you_type"},
				"ck":{"type":"constant_keyword","value":"v1"},
				"nodv":{"type":"keyword","doc_values":false,"index":false},
				"mix":{"type":"long"},
				"txt":{"type":"text","fields":{"kw":{"type":"keyword","ignore_above":64}}}
			}
		}
	}`, http.StatusOK)
	mustR67TSHTTP(t, h8, http.MethodPut, "/r67ts_esql_b", `{"mappings":{"properties":{"mix":{"type":"keyword"},"n":{"type":"nested","properties":{"x":{"type":"keyword"}}}}}}`, http.StatusOK)
	esqlSum := inspectESQLFromTargetSchemasRound63(srv8, context.Background(), "r67ts_esql_*")
	if !esqlSum.dynamicFalse || esqlSum.colTypes["cnt"] != "counter_long" || esqlSum.constVals["ck"] != "v1" || !esqlSum.nonIndexedNoDV["nodv"] || esqlSum.ambiguousError["mix"] == "" {
		t.Fatalf("unexpected ES|QL schema summary: %+v", esqlSum)
	}

	// 8. `isTermsEnumDLSStaticMatchAllR64` & `roleSliceAllowsTermsEnumR64`
	teSchema := schema.CompileIndexSchema("es_r67ts", "r67ts_te", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"env":   {Type: "constant_keyword", Value: "prod"},
			"title": {Type: "keyword"},
		},
	})
	if !isTermsEnumDLSStaticMatchAllR64(`{"bool":{"filter":[{"term":{"env":"prod"}}],"should":[{"terms":{"env":["prod"]}}],"minimum_should_match":1}}`, teSchema) {
		t.Fatalf("expected static constant_keyword bool query to be treated as static match_all")
	}
	if isTermsEnumDLSStaticMatchAllR64(`{"bool":{"must_not":[{"match_all":{}}]}}`, teSchema) {
		t.Fatalf("expected must_not to return false")
	}
	roles := []map[string]any{
		{
			"indices": []any{
				map[string]any{
					"names":          []any{"r67ts_*"},
					"privileges":     []any{"read"},
					"field_security": map[string]any{"grant": []any{"ti*"}, "except": []any{"secret*"}},
					"query":          `{"match_all":{}}`,
				},
			},
		},
	}
	if !roleSliceAllowsTermsEnumR64(roles, map[string]*schema.IndexSchema{"r67ts_te": teSchema}, []string{"r67ts_te"}, "title") {
		t.Fatalf("expected roleSliceAllowsTermsEnumR64 to allow title")
	}
	if roleSliceAllowsTermsEnumR64(roles, map[string]*schema.IndexSchema{"r67ts_te": teSchema}, []string{"r67ts_te"}, "secret_field") {
		t.Fatalf("expected roleSliceAllowsTermsEnumR64 to deny excluded secret_field")
	}
}
