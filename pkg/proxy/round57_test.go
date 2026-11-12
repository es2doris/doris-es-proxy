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
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doRound57Req(t *testing.T, srv *Server, method, path, body string) (int, string, map[string]any, http.Header) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		if strings.Contains(body, "\n") && !strings.HasPrefix(strings.TrimSpace(body), "{") {
			req.Header.Set("Content-Type", "application/x-ndjson")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	return rec.Code, raw, parsed, rec.Header()
}

func newRound57TestServer() *Server {
	mb := NewMemoryBackend(false)
	return NewServer("es_db", mb, transpiler.TranspilerOptions{})
}

func TestRound57F2_SQLEngineCompliance(t *testing.T) {
	srv := newRound57TestServer()

	// Create index with typed fields + alias
	code, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/r57_sql_emp", `{
		"mappings": {
			"properties": {
				"name": {"type": "keyword"},
				"dept": {"type": "keyword"},
				"age": {"type": "integer"},
				"salary": {"type": "double"},
				"active": {"type": "boolean"},
				"nickname": {"type": "keyword"}
			}
		},
		"aliases": {
			"r57_sql_emp_view": {}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 creating index, got %d", code)
	}

	bulkDocs := strings.Join([]string{
		`{"index":{"_id":"1"}}`,
		`{"name":"  Alice  ","dept":"eng","age":30,"salary":120.55,"active":true,"nickname":null}`,
		`{"index":{"_id":"2"}}`,
		`{"name":"Bob","dept":"eng","age":9,"salary":95.2,"active":true,"nickname":"Bobby"}`,
		`{"index":{"_id":"3"}}`,
		`{"name":"Charlie","dept":"sales","age":45,"salary":150.0,"active":false,"nickname":"Chuck"}`,
		`{"index":{"_id":"4"}}`,
		`{"name":"Diana","dept":"sales","age":28,"salary":80.0,"active":true}`,
		`{"index":{"_id":"5"}}`,
		`{"name":"Eve","dept":"hr","age":100,"salary":110.0,"active":true,"nickname":"Evie"}`,
	}, "\n") + "\n"
	code, _, _, _ = doRound57Req(t, srv, http.MethodPost, "/r57_sql_emp/_bulk?refresh=true", bulkDocs)
	if code != http.StatusOK {
		t.Fatalf("expected 200 indexing bulk docs, got %d", code)
	}

	// 1. DESCRIBE / DESC / SHOW COLUMNS IN|FROM + missing index error
	for _, q := range []string{
		"DESCRIBE r57_sql_emp",
		"DESC r57_sql_emp_view",
		"SHOW COLUMNS IN r57_sql_emp",
		"SHOW COLUMNS FROM r57_sql_emp_view",
	} {
		c, _, res, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", fmt.Sprintf(`{"query": %q}`, q))
		if c != http.StatusOK {
			t.Fatalf("query %q failed: %d %+v", q, c, res)
		}
		cols, _ := res["columns"].([]any)
		if len(cols) != 3 {
			t.Fatalf("expected 3 columns (column, type, mapping) for %q, got %+v", q, cols)
		}
		c0, _ := cols[0].(map[string]any)
		c1, _ := cols[1].(map[string]any)
		c2, _ := cols[2].(map[string]any)
		if c0["name"] != "column" || c1["name"] != "type" || c2["name"] != "mapping" {
			t.Fatalf("unexpected DESCRIBE column headers: %+v", cols)
		}
		rows, _ := res["rows"].([]any)
		if len(rows) < 6 {
			t.Fatalf("expected >= 6 field rows for %q, got %+v", q, rows)
		}
	}

	cMiss, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", `{"query":"DESCRIBE r57_missing_tbl"}`)
	if cMiss != http.StatusBadRequest && cMiss != http.StatusNotFound {
		t.Fatalf("expected 400/404 on DESCRIBE missing table, got %d", cMiss)
	}

	// 2. SHOW TABLES [LIKE] (including index & VIEW alias) and SHOW FUNCTIONS [LIKE]
	cST, _, resST, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", `{"query":"SHOW TABLES LIKE 'r57_sql_emp%'" }`)
	if cST != http.StatusOK {
		t.Fatalf("SHOW TABLES LIKE failed: %d %+v", cST, resST)
	}
	stRows, _ := resST["rows"].([]any)
	foundBase, foundView := false, false
	for _, r := range stRows {
		ra, _ := r.([]any)
		if len(ra) >= 2 {
			if ra[0] == "r57_sql_emp" && (ra[1] == "BASE TABLE" || ra[1] == "TABLE") {
				foundBase = true
			}
			if ra[0] == "r57_sql_emp_view" && ra[1] == "VIEW" {
				foundView = true
			}
		}
	}
	if !foundBase || !foundView {
		t.Fatalf("expected both BASE TABLE and VIEW in SHOW TABLES LIKE, got %+v", stRows)
	}

	cSF, _, resSF, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", `{"query":"SHOW FUNCTIONS LIKE 'CON%'" }`)
	if cSF != http.StatusOK {
		t.Fatalf("SHOW FUNCTIONS LIKE failed: %d %+v", cSF, resSF)
	}
	sfCols, _ := resSF["columns"].([]any)
	sfRows, _ := resSF["rows"].([]any)
	if len(sfCols) != 2 || len(sfRows) == 0 {
		t.Fatalf("expected 2 columns and matching CONCAT row in SHOW FUNCTIONS, got cols=%+v rows=%+v", sfCols, sfRows)
	}

	// 3. Scalar functions, aliases, arithmetic, and COALESCE
	scalarSQL := `SELECT
		LOWER(TRIM(name)) AS clean_name,
		UPPER(SUBSTRING(TRIM(name), 1, 3)) AS prefix3,
		LENGTH(TRIM(name)) AS name_len,
		CHAR_LENGTH(dept) AS dept_len,
		CONCAT(TRIM(name), ':', COALESCE(nickname, 'none')) AS display_tag,
		ROUND(salary, 1) AS sal_round,
		FLOOR(salary) AS sal_floor,
		CEIL(salary) AS sal_ceil,
		ABS(age - 50) AS age_diff,
		(age * 2 + 5) AS computed_score
	FROM r57_sql_emp WHERE dept = 'eng' AND age = 30`
	cSc, _, resSc, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", fmt.Sprintf(`{"query": %q}`, scalarSQL))
	if cSc != http.StatusOK {
		t.Fatalf("scalar SQL failed: %d %+v", cSc, resSc)
	}
	scCols, _ := resSc["columns"].([]any)
	if len(scCols) != 10 || scCols[0].(map[string]any)["name"] != "clean_name" || scCols[9].(map[string]any)["name"] != "computed_score" {
		t.Fatalf("expected preserved column aliases, got %+v", scCols)
	}
	scRows, _ := resSc["rows"].([]any)
	if len(scRows) != 1 {
		t.Fatalf("expected 1 row from scalar SQL, got %+v", scRows)
	}
	r0 := scRows[0].([]any)
	if r0[0] != "alice" || r0[1] != "ALI" || fmt.Sprintf("%v", r0[2]) != "5" || r0[4] != "Alice:none" || fmt.Sprintf("%v", r0[8]) != "20" || fmt.Sprintf("%v", r0[9]) != "65" {
		t.Fatalf("unexpected scalar SQL row values: %+v", r0)
	}

	// 4. GROUP BY + HAVING + COUNT(*), COUNT(col), COUNT(DISTINCT col), SUM, AVG, MIN, MAX
	grpSQL := `SELECT
		dept,
		COUNT(*) AS cnt_all,
		COUNT(nickname) AS cnt_nick,
		COUNT(DISTINCT active) AS distinct_active,
		SUM(age) AS sum_age,
		AVG(salary) AS avg_sal,
		MIN(age) AS min_age,
		MAX(age) AS max_age
	FROM r57_sql_emp
	GROUP BY dept
	HAVING COUNT(*) >= 2
	ORDER BY sum_age DESC`
	cGrp, _, resGrp, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", fmt.Sprintf(`{"query": %q}`, grpSQL))
	if cGrp != http.StatusOK {
		t.Fatalf("GROUP BY SQL failed: %d %+v", cGrp, resGrp)
	}
	grpRows, _ := resGrp["rows"].([]any)
	if len(grpRows) != 2 {
		t.Fatalf("expected 2 grouped departments (sales=73, eng=39), got %+v", grpRows)
	}
	g0 := grpRows[0].([]any)
	g1 := grpRows[1].([]any)
	if g0[0] != "sales" || fmt.Sprintf("%v", g0[1]) != "2" || fmt.Sprintf("%v", g0[3]) != "2" || fmt.Sprintf("%v", g0[4]) != "73" {
		t.Fatalf("unexpected first group row (sales): %+v", g0)
	}
	if g1[0] != "eng" || fmt.Sprintf("%v", g1[2]) != "1" || fmt.Sprintf("%v", g1[4]) != "39" || fmt.Sprintf("%v", g1[6]) != "9" || fmt.Sprintf("%v", g1[7]) != "30" {
		t.Fatalf("unexpected second group row (eng): %+v", g1)
	}

	// 5. Compound WHERE (AND, OR, NOT, IN, LIKE, BETWEEN, IS NULL, IS NOT NULL), positional ? params, Query DSL filter, numeric ORDER BY, and columnar: true
	paramBody := `{
		"query": "SELECT TRIM(name) AS nm, age FROM r57_sql_emp WHERE (dept IN (?, ?) OR age BETWEEN ? AND ?) AND NOT (name LIKE 'Char%') AND (nickname IS NOT NULL OR nickname IS NULL) ORDER BY age ASC",
		"params": ["eng", "hr", 25, 35],
		"filter": {"term": {"active": true}},
		"columnar": true,
		"fetch_size": 2
	}`
	cCol, _, resCol, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", paramBody)
	if cCol != http.StatusOK {
		t.Fatalf("columnar parameterized SQL failed: %d %+v", cCol, resCol)
	}
	if resCol["rows"] != nil {
		t.Fatalf("expected rows to be omitted when columnar=true, got %+v", resCol)
	}
	vals, okV := resCol["values"].([]any)
	if !okV || len(vals) != 2 {
		t.Fatalf("expected 2 column arrays in values, got %+v", resCol)
	}
	// Numeric ASC on ages [9, 28, 30, 100]: first page of fetch_size=2 MUST be [9, 28] (not lexicographical [100, 28]!)
	ageCol := vals[1].([]any)
	if len(ageCol) != 2 || fmt.Sprintf("%v", ageCol[0]) != "9" || fmt.Sprintf("%v", ageCol[1]) != "28" {
		t.Fatalf("expected numeric ASC sort [9, 28], got %+v", ageCol)
	}
	cursorStr, _ := resCol["cursor"].(string)
	if cursorStr == "" {
		t.Fatalf("expected pagination cursor for fetch_size=2, got %+v", resCol)
	}
	cPage2, _, resPage2, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", fmt.Sprintf(`{"cursor":%q,"columnar":true}`, cursorStr))
	if cPage2 != http.StatusOK {
		t.Fatalf("cursor page 2 failed: %d %+v", cPage2, resPage2)
	}
	vals2 := resPage2["values"].([]any)
	ageCol2 := vals2[1].([]any)
	if len(ageCol2) != 2 || fmt.Sprintf("%v", ageCol2[0]) != "30" || fmt.Sprintf("%v", ageCol2[1]) != "100" {
		t.Fatalf("expected cursor page 2 numeric ages [30, 100], got %+v", ageCol2)
	}
	cClose, _, resClose, _ := doRound57Req(t, srv, http.MethodPost, "/_sql/close", fmt.Sprintf(`{"cursor":%q}`, cursorStr))
	if cClose != http.StatusOK || resClose["succeeded"] != true {
		t.Fatalf("expected 200 closing SQL cursor, got %d %+v", cClose, resClose)
	}

	// CSV/TSV/TXT formatting + invalid SQL error
	cCSV, rawCSV, _, hdrCSV := doRound57Req(t, srv, http.MethodPost, "/_sql?format=csv", `{"query":"SELECT dept, age FROM r57_sql_emp WHERE age = 9"}`)
	if cCSV != http.StatusOK || !strings.Contains(hdrCSV.Get("Content-Type"), "text/csv") || !strings.Contains(rawCSV, "eng,9") {
		t.Fatalf("unexpected CSV SQL output: code=%d ct=%s body=%q", cCSV, hdrCSV.Get("Content-Type"), rawCSV)
	}
	cTXT, rawTXT, _, _ := doRound57Req(t, srv, http.MethodPost, "/_sql?format=txt", `{"query":"SELECT dept, age FROM r57_sql_emp WHERE age = 9"}`)
	if cTXT != http.StatusOK || !strings.Contains(rawTXT, "dept") || !strings.Contains(rawTXT, "---") {
		t.Fatalf("unexpected TXT SQL output: code=%d body=%q", cTXT, rawTXT)
	}
	cBadParam, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", `{"query":"SELECT * FROM r57_sql_emp WHERE age = ?", "params": []}`)
	if cBadParam != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing ? parameter, got %d", cBadParam)
	}

	// 6. POST /_sql/translate emits real Query/Sort/Aggs DSL
	cTr1, _, resTr1, _ := doRound57Req(t, srv, http.MethodPost, "/_sql/translate", `{
		"query": "SELECT name, age FROM r57_sql_emp WHERE dept = 'eng' AND age >= 10 ORDER BY age DESC LIMIT 5"
	}`)
	if cTr1 != http.StatusOK || resTr1["query"] == nil || resTr1["sort"] == nil || fmt.Sprintf("%v", resTr1["size"]) != "5" {
		t.Fatalf("expected translated query/sort/size DSL, got %d %+v", cTr1, resTr1)
	}
	cTr2, _, resTr2, _ := doRound57Req(t, srv, http.MethodPost, "/_sql/translate", `{
		"query": "SELECT dept, COUNT(*) AS c, AVG(salary) AS avg_s FROM r57_sql_emp GROUP BY dept"
	}`)
	if cTr2 != http.StatusOK || resTr2["aggs"] == nil || fmt.Sprintf("%v", resTr2["size"]) != "0" {
		t.Fatalf("expected translated GROUP BY aggs DSL with size=0, got %d %+v", cTr2, resTr2)
	}
}

func TestRound57F3_ESQLEngineExtensions(t *testing.T) {
	srv := newRound57TestServer()

	// Seed enrich source index + execute enrich policy
	doRound57Req(t, srv, http.MethodPut, "/r57_esql_geo", `{"mappings":{"properties":{"env_code":{"type":"keyword"},"region_name":{"type":"keyword"},"tier":{"type":"keyword"}}}}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_esql_geo/_doc/1?refresh=true", `{"env_code":"prod","region_name":"us-east-1","tier":"gold"}`)
	doRound57Req(t, srv, http.MethodPut, "/_enrich/policy/r57_env_pol", `{
		"match": {
			"indices": "r57_esql_geo",
			"match_field": "env_code",
			"enrich_fields": ["region_name", "tier"]
		}
	}`)
	doRound57Req(t, srv, http.MethodPost, "/_enrich/policy/r57_env_pol/_execute", "")

	// Seed events index
	doRound57Req(t, srv, http.MethodPut, "/r57_esql_logs", `{
		"mappings": {
			"properties": {
				"msg": {"type": "keyword"},
				"grok_line": {"type": "keyword"},
				"env_code": {"type": "keyword"},
				"latency": {"type": "double"},
				"tags": {"type": "keyword"},
				"scores": {"type": "integer"},
				"ts": {"type": "date"}
			}
		}
	}`)
	bulk := strings.Join([]string{
		`{"index":{"_id":"1"}}`,
		`{"msg":"prod|api|200","grok_line":"GET 200","env_code":"prod","latency":10.0,"tags":["b","a","b"],"scores":[10,30,20],"ts":"2026-05-15T14:35:20.000Z"}`,
		`{"index":{"_id":"2"}}`,
		`{"msg":"prod|web|500","grok_line":"POST 500","env_code":"prod","latency":30.0,"tags":["c"],"scores":[40,50],"ts":"2026-05-16T10:00:00.000Z"}`,
		`{"index":{"_id":"3"}}`,
		`{"msg":"prod|worker|204","grok_line":"DELETE 204","env_code":"prod","latency":90.0,"tags":["a","d"],"scores":[5],"ts":"2026-05-17T08:00:00.000Z"}`,
	}, "\n") + "\n"
	doRound57Req(t, srv, http.MethodPost, "/r57_esql_logs/_bulk?refresh=true", bulk)

	// 1. SHOW INFO + unknown stage 400 verification_exception
	cInfo, _, resInfo, _ := doRound57Req(t, srv, http.MethodPost, "/_query", `{"query": "SHOW INFO"}`)
	if cInfo != http.StatusOK {
		t.Fatalf("SHOW INFO failed: %d %+v", cInfo, resInfo)
	}
	infoRows, _ := resInfo["values"].([]any)
	if len(infoRows) != 1 {
		t.Fatalf("expected 1 row from SHOW INFO, got %+v", resInfo)
	}

	cUnk, _, resUnk, _ := doRound57Req(t, srv, http.MethodPost, "/_query", `{"query": "FROM r57_esql_logs | BOGUS_STAGE foo"}`)
	if cUnk != http.StatusBadRequest {
		t.Fatalf("expected 400 verification_exception for unknown ES|QL stage, got %d %+v", cUnk, resUnk)
	}

	// 2. DISSECT, GROK, ENRICH (missing policy 400 + valid policy join), and MV_EXPAND
	cMissPol, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_query", `{"query": "FROM r57_esql_logs | ENRICH r57_no_such_pol ON env_code"}`)
	if cMissPol != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing enrich policy in ES|QL ENRICH, got %d", cMissPol)
	}

	stageQuery := `FROM r57_esql_logs
		| WHERE latency == 10.0
		| DISSECT msg "%{d_env}|%{d_svc}|%{+d_env}" APPEND_SEPARATOR="-"
		| GROK grok_line "%{WORD:http_verb} %{NUMBER:http_code:int}"
		| ENRICH r57_env_pol ON env_code WITH reg = region_name, tier
		| MV_EXPAND scores
		| SORT scores ASC
		| KEEP d_env, d_svc, http_verb, http_code, reg, tier, scores`
	cStg, _, resStg, _ := doRound57Req(t, srv, http.MethodPost, "/_query", fmt.Sprintf(`{"query": %q}`, stageQuery))
	if cStg != http.StatusOK {
		t.Fatalf("DISSECT/GROK/ENRICH/MV_EXPAND query failed: %d %+v", cStg, resStg)
	}
	stgVals, _ := resStg["values"].([]any)
	if len(stgVals) != 3 {
		t.Fatalf("expected 3 expanded rows from MV_EXPAND on [10,30,20], got %+v", stgVals)
	}
	row0 := stgVals[0].([]any)
	if row0[0] != "prod-200" || row0[1] != "api" || row0[2] != "GET" || fmt.Sprintf("%v", row0[3]) != "200" || row0[4] != "us-east-1" || row0[5] != "gold" || fmt.Sprintf("%v", row0[6]) != "10" {
		t.Fatalf("unexpected DISSECT/GROK/ENRICH/MV_EXPAND row[0]: %+v", row0)
	}

	// 3. String, Math, CASE, Conversion, MV_*, and DATE_* functions
	fnQuery := `ROW s = "  Hello_World  ", arr = [30, 10, 20, 10], ts = "2026-05-15T14:35:20.000Z"
		| EVAL
			r_rep = REPLACE(TRIM(s), "World", "ESQL"),
			r_sub = SUBSTRING(TRIM(s), 1, 5),
			r_spl = MV_COUNT(SPLIT(TRIM(s), "_")),
			r_sw = STARTS_WITH(TRIM(s), "Hello"),
			r_ew = ENDS_WITH(TRIM(s), "World"),
			r_loc = LOCATE(TRIM(s), "World"),
			r_lt = LTRIM("  abc"),
			r_rt = RTRIM("abc  "),
			r_left = LEFT(TRIM(s), 2),
			r_right = RIGHT(TRIM(s), 2),
			m_fl = FLOOR(3.9),
			m_cl = CEIL(3.1),
			m_pw = POW(2, 3),
			m_sq = SQRT(16),
			m_md = MOD(17, 5),
			m_gr = GREATEST(3, 9, 5),
			m_ls = LEAST(3, 9, 5),
			c_cs = CASE(1 == 2, "no", 2 == 2, "yes", "other"),
			t_bl = TO_BOOLEAN("true"),
			t_dt = TO_DATETIME("2026-05-15T00:00:00Z"),
			mv_cnt = MV_COUNT(arr),
			mv_mn = MV_MIN(arr),
			mv_mx = MV_MAX(arr),
			mv_sm = MV_SUM(arr),
			mv_av = MV_AVG(arr),
			mv_cc = MV_CONCAT(MV_SORT(MV_DEDUPE(arr)), "-"),
			mv_sl = MV_SLICE(MV_SORT(arr), 0, 1),
			d_yr = DATE_EXTRACT("year", ts),
			d_hr = DATE_EXTRACT("hour", ts),
			d_tr = DATE_TRUNC("1d", ts),
			d_pr = DATE_PARSE("yyyy-MM-dd", "2026-05-20"),
			d_fm = DATE_FORMAT("yyyy/MM/dd", ts),
			d_df = DATE_DIFF("day", ts, "2026-05-20T14:35:20.000Z")
		| KEEP r_rep, r_sub, r_spl, r_sw, r_ew, r_loc, r_lt, r_rt, r_left, r_right, m_fl, m_cl, m_pw, m_sq, m_md, m_gr, m_ls, c_cs, t_bl, mv_cnt, mv_mn, mv_mx, mv_sm, mv_av, mv_cc, d_yr, d_hr, d_tr, d_fm, d_df`
	cFn, _, resFn, _ := doRound57Req(t, srv, http.MethodPost, "/_query", fmt.Sprintf(`{"query": %q}`, fnQuery))
	if cFn != http.StatusOK {
		t.Fatalf("ES|QL functions query failed: %d %+v", cFn, resFn)
	}
	fnRow := resFn["values"].([]any)[0].([]any)
	if fnRow[0] != "Hello_ESQL" || fnRow[1] != "Hello" || fmt.Sprintf("%v", fnRow[2]) != "2" || fnRow[3] != true || fnRow[4] != true {
		t.Fatalf("unexpected ES|QL string fn outputs: %+v", fnRow[:10])
	}
	if fnRow[6] != "abc" || fnRow[7] != "abc" || fnRow[8] != "He" || fnRow[9] != "ld" {
		t.Fatalf("unexpected ES|QL trim/left/right outputs: %+v", fnRow[6:10])
	}
	if fmt.Sprintf("%v", fnRow[10]) != "3" || fmt.Sprintf("%v", fnRow[11]) != "4" || fmt.Sprintf("%v", fnRow[12]) != "8" || fmt.Sprintf("%v", fnRow[13]) != "4" || fmt.Sprintf("%v", fnRow[14]) != "2" {
		t.Fatalf("unexpected ES|QL math outputs: %+v", fnRow[10:17])
	}
	if fnRow[17] != "yes" || fnRow[18] != true || fmt.Sprintf("%v", fnRow[19]) != "4" || fmt.Sprintf("%v", fnRow[20]) != "10" || fmt.Sprintf("%v", fnRow[21]) != "30" || fmt.Sprintf("%v", fnRow[22]) != "70" || fnRow[24] != "10-20-30" {
		t.Fatalf("unexpected ES|QL CASE/TO_BOOLEAN/MV_* outputs: %+v", fnRow[17:25])
	}
	if fmt.Sprintf("%v", fnRow[25]) != "2026" || fmt.Sprintf("%v", fnRow[26]) != "14" || fnRow[27] != "2026-05-15T00:00:00.000Z" || fnRow[28] != "2026/05/15" || fmt.Sprintf("%v", fnRow[29]) != "5" {
		t.Fatalf("unexpected ES|QL DATE_* outputs: %+v", fnRow[25:])
	}

	// 4. STATS with VALUES, COUNT_DISTINCT, MEDIAN, PERCENTILE
	statsQ := `FROM r57_esql_logs | STATS med = MEDIAN(latency), p50 = PERCENTILE(latency, 50), cd = COUNT_DISTINCT(env_code), vals = VALUES(env_code)`
	cSt, _, resSt, _ := doRound57Req(t, srv, http.MethodPost, "/_query", fmt.Sprintf(`{"query": %q}`, statsQ))
	if cSt != http.StatusOK {
		t.Fatalf("ES|QL STATS MEDIAN/PERCENTILE/COUNT_DISTINCT/VALUES failed: %d %+v", cSt, resSt)
	}
	stRow := resSt["values"].([]any)[0].([]any)
	if fmt.Sprintf("%v", stRow[0]) != "30" || fmt.Sprintf("%v", stRow[1]) != "30" || fmt.Sprintf("%v", stRow[2]) != "1" {
		t.Fatalf("unexpected STATS row: %+v", stRow)
	}

	// 5. /_query/async/{id}/_stop and keep_on_completion: false auto-delete on GET
	cAsync1, _, resAsync1, _ := doRound57Req(t, srv, http.MethodPost, "/_query/async", `{"query":"SHOW INFO","keep_on_completion":true}`)
	if cAsync1 != http.StatusOK {
		t.Fatalf("expected 200 creating async query, got %d %+v", cAsync1, resAsync1)
	}
	asyncID1, _ := resAsync1["id"].(string)
	cStop, _, resStop, _ := doRound57Req(t, srv, http.MethodPost, "/_query/async/"+asyncID1+"/_stop", "")
	if cStop != http.StatusOK || resStop["is_running"] != false {
		t.Fatalf("expected 200 with is_running=false on _stop, got %d %+v", cStop, resStop)
	}
	cStopMiss, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_query/async/no_such_id/_stop", "")
	if cStopMiss != http.StatusNotFound {
		t.Fatalf("expected 404 stopping missing async query, got %d", cStopMiss)
	}

	cAsync2, _, resAsync2, _ := doRound57Req(t, srv, http.MethodPost, "/_query/async", `{"query":"SHOW INFO","keep_on_completion":false,"wait_for_completion_timeout":"0s"}`)
	if cAsync2 != http.StatusOK {
		t.Fatalf("expected 200 creating auto-cleanup async query, got %d", cAsync2)
	}
	asyncID2, _ := resAsync2["id"].(string)
	cGet1, _, _, _ := doRound57Req(t, srv, http.MethodGet, "/_query/async/"+asyncID2, "")
	if cGet1 != http.StatusOK {
		t.Fatalf("expected first GET on keep_on_completion:false async query to succeed, got %d", cGet1)
	}
	cGet2, _, _, _ := doRound57Req(t, srv, http.MethodGet, "/_query/async/"+asyncID2, "")
	if cGet2 != http.StatusNotFound {
		t.Fatalf("expected second GET on keep_on_completion:false async query to return 404, got %d", cGet2)
	}
}

func TestRound57F4_EQLEventAndSequenceEngine(t *testing.T) {
	srv := newRound57TestServer()

	doRound57Req(t, srv, http.MethodPut, "/r57_eql_sec", `{
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"event": {"properties": {"category": {"type": "keyword"}, "action": {"type": "keyword"}}},
				"host": {"properties": {"name": {"type": "keyword"}}},
				"process": {"properties": {"name": {"type": "keyword"}, "pid": {"type": "integer"}}},
				"source": {"properties": {"ip": {"type": "ip"}}}
			}
		}
	}`)
	bulk := strings.Join([]string{
		// Host h1: valid sequence (cmd.exe -> outbound 10.1.2.3 within 5m, no until abort)
		`{"index":{"_id":"1"}}`,
		`{"@timestamp":"2026-06-01T10:00:00Z","event":{"category":"process","action":"start"},"host":{"name":"h1"},"process":{"name":"cmd.exe","pid":101},"source":{"ip":"10.1.2.3"}}`,
		`{"index":{"_id":"2"}}`,
		`{"@timestamp":"2026-06-01T10:02:00Z","event":{"category":"network","action":"connect"},"host":{"name":"h1"},"process":{"name":"cmd.exe","pid":101},"source":{"ip":"10.1.2.3"}}`,
		// Host h2: aborted by until event (logout) before network connect
		`{"index":{"_id":"3"}}`,
		`{"@timestamp":"2026-06-01T10:00:00Z","event":{"category":"process","action":"start"},"host":{"name":"h2"},"process":{"name":"powershell.exe","pid":202},"source":{"ip":"10.9.9.9"}}`,
		`{"index":{"_id":"4"}}`,
		`{"@timestamp":"2026-06-01T10:01:00Z","event":{"category":"authentication","action":"logout"},"host":{"name":"h2"},"process":{"name":"logoff.exe","pid":203},"source":{"ip":"10.9.9.9"}}`,
		`{"index":{"_id":"5"}}`,
		`{"@timestamp":"2026-06-01T10:02:00Z","event":{"category":"network","action":"connect"},"host":{"name":"h2"},"process":{"name":"powershell.exe","pid":202},"source":{"ip":"10.9.9.9"}}`,
		// Host h3: exceeds maxspan=5m (10:00 -> 10:10)
		`{"index":{"_id":"6"}}`,
		`{"@timestamp":"2026-06-01T10:00:00Z","event":{"category":"process","action":"start"},"host":{"name":"h3"},"process":{"name":"cmd.exe","pid":303},"source":{"ip":"192.168.1.5"}}`,
		`{"index":{"_id":"7"}}`,
		`{"@timestamp":"2026-06-01T10:10:00Z","event":{"category":"network","action":"connect"},"host":{"name":"h3"},"process":{"name":"cmd.exe","pid":303},"source":{"ip":"192.168.1.5"}}`,
	}, "\n") + "\n"
	doRound57Req(t, srv, http.MethodPost, "/r57_eql_sec/_bulk?refresh=true", bulk)

	// 1. Malformed EQL rejected with 400
	for _, badEQL := range []string{
		`process`,
		`process where (process.name == "cmd.exe"`,
		`process where process.name == "unterminated`,
		`sequence [process where true]`, // sequence requires >= 2 stages or valid syntax; test unbalanced bracket too
		`sequence by host.name [process where process.pid == 101`,
		`process where process.pid === 101`,
	} {
		cBad, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/r57_eql_sec/_eql/search", fmt.Sprintf(`{"query": %q}`, badEQL))
		if cBad != http.StatusBadRequest {
			t.Fatalf("expected 400 for malformed EQL %q, got %d", badEQL, cBad)
		}
	}

	// 2. Single-event EQL with boolean ops, wildcards ':', in (...), like/regex, length/startsWith/endsWith/stringContains, and cidrMatch
	singleEQL := `process where (process.name : "cmd*" or process.name in ("powershell.exe")) and process.pid >= 100 and length(process.name) >= 7 and startsWith(process.name, "cmd") and endsWith(process.name, ".exe") and stringContains(process.name, "md.") and cidrMatch(source.ip, "10.0.0.0/8")`
	cEv, _, resEv, _ := doRound57Req(t, srv, http.MethodPost, "/r57_eql_sec/_eql/search", fmt.Sprintf(`{"query": %q}`, singleEQL))
	if cEv != http.StatusOK {
		t.Fatalf("single-event EQL failed: %d %+v", cEv, resEv)
	}
	evHits := resEv["hits"].(map[string]any)
	evArr := evHits["events"].([]any)
	if len(evArr) != 1 || evArr[0].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected exactly doc _id=1 from single-event EQL (h3 is 192.168.x.x, h2 is powershell), got %+v", evHits)
	}

	// Also test 'any where ... like / regex'
	anyEQL := `any where host.name like "h%" and not (event.action == "logout")`
	cAny, _, resAny, _ := doRound57Req(t, srv, http.MethodPost, "/r57_eql_sec/_eql/search", fmt.Sprintf(`{"query": %q, "size": 2}`, anyEQL))
	if cAny != http.StatusOK {
		t.Fatalf("any EQL failed: %d %+v", cAny, resAny)
	}
	anyHits := resAny["hits"].(map[string]any)
	if fmt.Sprintf("%v", anyHits["total"].(map[string]any)["value"]) != "6" || len(anyHits["events"].([]any)) != 2 {
		t.Fatalf("expected total=6 and size=2 events, got %+v", anyHits)
	}

	// 3. Multi-stage sequence with `by host.name`, `with maxspan=5m`, and `until [...]`
	seqEQL := `sequence by host.name with maxspan=5m
		[process where event.action == "start" and process.name in ("cmd.exe", "powershell.exe")]
		[network where event.action == "connect"]
		until [authentication where event.action == "logout"]`
	cSeq, _, resSeq, _ := doRound57Req(t, srv, http.MethodPost, "/r57_eql_sec/_eql/search", fmt.Sprintf(`{"query": %q, "keep_on_completion": true}`, seqEQL))
	if cSeq != http.StatusOK {
		t.Fatalf("sequence EQL failed: %d %+v", cSeq, resSeq)
	}
	seqHits := resSeq["hits"].(map[string]any)
	seqs := seqHits["sequences"].([]any)
	if len(seqs) != 1 {
		t.Fatalf("expected exactly 1 matched sequence (h1 matches, h2 aborted by until, h3 exceeded maxspan), got %+v", seqHits)
	}
	s0 := seqs[0].(map[string]any)
	jks := s0["join_keys"].([]any)
	if len(jks) != 1 || jks[0] != "h1" || len(s0["events"].([]any)) != 2 {
		t.Fatalf("unexpected matched sequence payload: %+v", s0)
	}

	// 4. Async EQL GET / status / DELETE
	eqlID, _ := resSeq["id"].(string)
	cGet, _, resGet, _ := doRound57Req(t, srv, http.MethodGet, "/_eql/search/"+eqlID, "")
	if cGet != http.StatusOK || resGet["id"] != eqlID {
		t.Fatalf("expected 200 fetching stored EQL search %s, got %d %+v", eqlID, cGet, resGet)
	}
	cStat, _, resStat, _ := doRound57Req(t, srv, http.MethodGet, "/_eql/search/status/"+eqlID, "")
	if cStat != http.StatusOK || resStat["id"] != eqlID {
		t.Fatalf("expected 200 on EQL status %s, got %d %+v", eqlID, cStat, resStat)
	}
	cDel, _, resDel, _ := doRound57Req(t, srv, http.MethodDelete, "/_eql/search/"+eqlID, "")
	if cDel != http.StatusOK || resDel["acknowledged"] != true {
		t.Fatalf("expected 200 deleting EQL search %s, got %d %+v", eqlID, cDel, resDel)
	}
	cGone, _, _, _ := doRound57Req(t, srv, http.MethodGet, "/_eql/search/"+eqlID, "")
	if cGone != http.StatusNotFound {
		t.Fatalf("expected 404 after deleting EQL search, got %d", cGone)
	}
}

func TestRound57F5_SnapshotRestoreMountRepoAnalyzeAndSLM(t *testing.T) {
	srv := newRound57TestServer()

	// Create repo
	cRepo, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/_snapshot/r57_repo", `{"type":"fs","settings":{"location":"/tmp/r57_repo"}}`)
	if cRepo != http.StatusOK {
		t.Fatalf("expected 200 creating repo, got %d", cRepo)
	}

	// Repo _analyze (valid + missing 404 + invalid blob_count 400)
	cAn, _, resAn, _ := doRound57Req(t, srv, http.MethodPost, "/_snapshot/r57_repo/_analyze?blob_count=3", "")
	if cAn != http.StatusOK || fmt.Sprintf("%v", resAn["blob_count"]) != "3" || len(resAn["details"].([]any)) != 3 {
		t.Fatalf("expected 200 with 3 blob details on _snapshot/_analyze, got %d %+v", cAn, resAn)
	}
	cAnMiss, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_snapshot/no_such_repo/_analyze", "")
	if cAnMiss != http.StatusNotFound {
		t.Fatalf("expected 404 on _analyze for missing repo, got %d", cAnMiss)
	}
	cAnBad, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_snapshot/r57_repo/_analyze?blob_count=-1", "")
	if cAnBad != http.StatusBadRequest {
		t.Fatalf("expected 400 on negative blob_count, got %d", cAnBad)
	}

	// Seed index with custom settings, alias, and documents
	doRound57Req(t, srv, http.MethodPut, "/r57_orders", `{
		"settings": {
			"number_of_replicas": 2,
			"refresh_interval": "5s"
		},
		"mappings": {
			"properties": {
				"item": {"type": "keyword"},
				"qty": {"type": "integer"}
			}
		},
		"aliases": {
			"r57_orders_alias": {}
		}
	}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_orders/_doc/ord-1?refresh=true", `{"item":"keyboard","qty":4}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_orders/_doc/ord-2?refresh=true", `{"item":"monitor","qty":2}`)

	// Take snapshot snap_1, clone to snap_cloned, then delete original index
	cSnap, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/_snapshot/r57_repo/snap_1?wait_for_completion=true", `{"indices":"r57_orders"}`)
	if cSnap != http.StatusOK {
		t.Fatalf("expected 200 creating snapshot, got %d", cSnap)
	}
	cClone, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/_snapshot/r57_repo/snap_1/_clone/snap_cloned", `{"indices":"r57_orders"}`)
	if cClone != http.StatusOK {
		t.Fatalf("expected 200 cloning snapshot, got %d", cClone)
	}
	doRound57Req(t, srv, http.MethodDelete, "/r57_orders", "")

	// Restore with Java $1 rename_replacement, ignore_index_settings, index_settings override, and include_aliases
	cRest, _, resRest, _ := doRound57Req(t, srv, http.MethodPost, "/_snapshot/r57_repo/snap_1/_restore", `{
		"indices": "r57_orders",
		"rename_pattern": "r57_(.+)",
		"rename_replacement": "restored_$1",
		"ignore_index_settings": ["index.refresh_interval"],
		"index_settings": {"index.number_of_replicas": 0},
		"include_aliases": true
	}`)
	if cRest != http.StatusOK {
		t.Fatalf("expected 200 restoring snapshot, got %d %+v", cRest, resRest)
	}

	// Verify restored_orders has searchable documents & alias & overridden settings!
	cSearch, _, resSearch, _ := doRound57Req(t, srv, http.MethodPost, "/r57_orders_alias/_search", `{"query":{"term":{"item":"keyboard"}}}`)
	if cSearch != http.StatusOK {
		t.Fatalf("expected 200 searching restored alias, got %d %+v", cSearch, resSearch)
	}
	hits := resSearch["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 || hits[0].(map[string]any)["_index"] != "restored_orders" {
		t.Fatalf("expected 1 hit in restored_orders via alias, got %+v", hits)
	}

	// Mount cloned snapshot as searchable snapshot + clear searchable snapshots cache
	cMount, _, resMount, _ := doRound57Req(t, srv, http.MethodPost, "/_snapshot/r57_repo/snap_cloned/_mount?storage=shared_cache", `{
		"index": "r57_orders",
		"renamed_index": "mounted_orders"
	}`)
	if cMount != http.StatusOK {
		t.Fatalf("expected 200 mounting searchable snapshot, got %d %+v", cMount, resMount)
	}
	cMGet, _, resMGet, _ := doRound57Req(t, srv, http.MethodGet, "/mounted_orders/_doc/ord-2", "")
	if cMGet != http.StatusOK || resMGet["found"] != true {
		t.Fatalf("expected mounted searchable snapshot to contain doc ord-2, got %d %+v", cMGet, resMGet)
	}
	cClear, _, resClear, _ := doRound57Req(t, srv, http.MethodPost, "/mounted_orders/_searchable_snapshots/cache/clear", "")
	if cClear != http.StatusOK {
		t.Fatalf("expected 200 clearing searchable snapshot cache, got %d %+v", cClear, resClear)
	}
	_ = resClear
	cClearMiss, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/no_such_mounted_idx/_searchable_snapshots/cache/clear", "")
	if cClearMiss != http.StatusNotFound {
		t.Fatalf("expected 404 clearing cache on missing index, got %d", cClearMiss)
	}

	// SLM: missing policy 404 message, policy with missing repo fails & increments snapshots_failed, valid policy takes snapshots & _execute_retention prunes!
	cSLMMiss, _, resSLMMiss, _ := doRound57Req(t, srv, http.MethodGet, "/_slm/policy/no_such_pol", "")
	if cSLMMiss != http.StatusNotFound || !strings.Contains(fmt.Sprintf("%v", resSLMMiss), "snapshot lifecycle policy") {
		t.Fatalf("expected 404 with SLM message for missing policy, got %d %+v", cSLMMiss, resSLMMiss)
	}

	doRound57Req(t, srv, http.MethodPut, "/_snapshot/temp_missing_repo", `{"type":"fs","settings":{"location":"/tmp/r57_tmp_repo"}}`)
	cBadPolPut, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/_slm/policy/bad_repo_pol", `{
		"schedule": "0 30 1 * * ?",
		"name": "<bad-snap>",
		"repository": "temp_missing_repo",
		"config": {"indices": ["restored_*"]}
	}`)
	if cBadPolPut != http.StatusOK {
		t.Fatalf("expected 200 creating bad_repo_pol against existing temp_missing_repo, got %d", cBadPolPut)
	}
	doRound57Req(t, srv, http.MethodDelete, "/_snapshot/temp_missing_repo", "")
	cExecFail, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_slm/policy/bad_repo_pol/_execute", "")
	if cExecFail != http.StatusNotFound {
		t.Fatalf("expected 404 repository_missing_exception when SLM executes against missing repo, got %d", cExecFail)
	}

	doRound57Req(t, srv, http.MethodPut, "/_slm/policy/r57_daily", `{
		"schedule": "0 30 1 * * ?",
		"name": "<r57-daily>",
		"repository": "r57_repo",
		"config": {"indices": ["restored_*"]},
		"retention": {"max_count": 1, "min_count": 1, "expire_after": "30d"}
	}`)
	cEx1, _, resEx1, _ := doRound57Req(t, srv, http.MethodPost, "/_slm/policy/r57_daily/_execute", "")
	cEx2, _, resEx2, _ := doRound57Req(t, srv, http.MethodPost, "/_slm/policy/r57_daily/_execute", "")
	if cEx1 != http.StatusOK || cEx2 != http.StatusOK {
		t.Fatalf("expected 200 executing r57_daily policy twice, got %d/%d", cEx1, cEx2)
	}
	snap1Name, _ := resEx1["snapshot_name"].(string)
	snap2Name, _ := resEx2["snapshot_name"].(string)

	cRet, _, resRet, _ := doRound57Req(t, srv, http.MethodPost, "/_slm/_execute_retention", "")
	if cRet != http.StatusOK || resRet["acknowledged"] != true {
		t.Fatalf("expected 200 on _slm/_execute_retention, got %d %+v", cRet, resRet)
	}
	// Oldest SLM snapshot should be pruned (max_count: 1), newest kept!
	cOldSnap, _, _, _ := doRound57Req(t, srv, http.MethodGet, "/_snapshot/r57_repo/"+snap1Name, "")
	cNewSnap, _, _, _ := doRound57Req(t, srv, http.MethodGet, "/_snapshot/r57_repo/"+snap2Name, "")
	if cOldSnap != http.StatusNotFound || cNewSnap != http.StatusOK {
		t.Fatalf("expected retention to prune %s (got %d) and keep %s (got %d)", snap1Name, cOldSnap, snap2Name, cNewSnap)
	}

	cStats, _, resStats, _ := doRound57Req(t, srv, http.MethodGet, "/_slm/stats", "")
	if cStats != http.StatusOK || fmt.Sprintf("%v", resStats["total_snapshots_taken"]) != "2" || fmt.Sprintf("%v", resStats["total_snapshots_failed"]) != "1" || fmt.Sprintf("%v", resStats["total_snapshots_deleted"]) != "1" {
		t.Fatalf("unexpected _slm/stats counters: %d %+v", cStats, resStats)
	}
	if len(resStats["policy_stats"].([]any)) < 2 {
		t.Fatalf("expected per-policy policy_stats entries in _slm/stats, got %+v", resStats)
	}
}

func TestRound57F6_SynonymsAndInferenceStreaming(t *testing.T) {
	srv := newRound57TestServer()

	// 1. Synonym rule validation (400 on malformed rules)
	for _, badBody := range []string{
		`{"synonyms_set":[{"id":"r1","synonyms":""}]}`,
		`{"synonyms_set":[{"id":"r1","synonyms":"=> laptop"}]}`,
		`{"synonyms_set":[{"id":"r1","synonyms":"laptop =>"}]}`,
		`{"synonyms_set":[{"id":"r1","synonyms":"a => b => c"}]}`,
		`{"synonyms_set":[{"id":"r1","synonyms":"singleword"}]}`,
	} {
		cBad, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/_synonyms/r57_bad_syn", badBody)
		if cBad != http.StatusBadRequest {
			t.Fatalf("expected 400 for malformed synonym rule %s, got %d", badBody, cBad)
		}
	}

	// Create valid synonym set
	cSyn, _, resSyn, _ := doRound57Req(t, srv, http.MethodPut, "/_synonyms/r57_tech_syn", `{
		"synonyms_set": [
			{"id": "eq1", "synonyms": "laptop, notebook"},
			{"id": "ex1", "synonyms": "ny => newyork"}
		]
	}`)
	if cSyn != http.StatusOK || resSyn["result"] != "created" {
		t.Fatalf("expected 200 created for synonym set, got %d %+v", cSyn, resSyn)
	}

	// Create index referencing r57_tech_syn via custom search analyzer
	cIdx, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/r57_syn_docs", `{
		"settings": {
			"analysis": {
				"filter": {
					"my_syn_filter": {
						"type": "synonym_graph",
						"synonyms_set": "r57_tech_syn",
						"updateable": true
					}
				},
				"analyzer": {
					"my_syn_search": {
						"tokenizer": "standard",
						"filter": ["lowercase", "my_syn_filter"]
					}
				}
			}
		},
		"mappings": {
			"properties": {
				"title": {
					"type": "text",
					"search_analyzer": "my_syn_search"
				}
			}
		}
	}`)
	if cIdx != http.StatusOK {
		t.Fatalf("expected 200 creating index with synonym analyzer, got %d", cIdx)
	}
	doRound57Req(t, srv, http.MethodPut, "/r57_syn_docs/_doc/1?refresh=true", `{"title":"ultralight notebook pro"}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_syn_docs/_doc/2?refresh=true", `{"title":"newyork office guide"}`)

	// DELETE /_synonyms/r57_tech_syn MUST fail with 400 while referenced by r57_syn_docs!
	cDelInUse, _, _, _ := doRound57Req(t, srv, http.MethodDelete, "/_synonyms/r57_tech_syn", "")
	if cDelInUse != http.StatusBadRequest {
		t.Fatalf("expected 400 deleting synonym set referenced by open index, got %d", cDelInUse)
	}

	// Reload synonym set & reload search analyzers return populated reload_details
	cRel1, _, resRel1, _ := doRound57Req(t, srv, http.MethodPost, "/_synonyms/r57_tech_syn/_reload", "")
	if cRel1 != http.StatusOK || len(resRel1["reload_details"].([]any)) != 1 {
		t.Fatalf("expected 1 reload_details entry on _synonyms/_reload, got %d %+v", cRel1, resRel1)
	}
	cRel2, _, resRel2, _ := doRound57Req(t, srv, http.MethodPost, "/r57_syn_docs/_reload_search_analyzers", "")
	if cRel2 != http.StatusOK || len(resRel2["reload_details"].([]any)) != 1 {
		t.Fatalf("expected 1 reload_details entry on _reload_search_analyzers, got %d %+v", cRel2, resRel2)
	}

	// Custom index _analyze expands "laptop" -> ["laptop", "notebook"] and "NY" -> ["newyork"]
	cAn1, _, resAn1, _ := doRound57Req(t, srv, http.MethodPost, "/r57_syn_docs/_analyze", `{"analyzer":"my_syn_search","text":"Laptop NY"}`)
	if cAn1 != http.StatusOK {
		t.Fatalf("expected 200 on custom index _analyze, got %d %+v", cAn1, resAn1)
	}
	toks := resAn1["tokens"].([]any)
	if len(toks) != 3 {
		t.Fatalf("expected 3 tokens (laptop, notebook, newyork), got %+v", toks)
	}

	// Search-time synonym expansion: searching "laptop" matches doc 1 ("notebook") and searching "ny" matches doc 2 ("newyork")!
	cS1, _, resS1, _ := doRound57Req(t, srv, http.MethodPost, "/r57_syn_docs/_search", `{"query":{"match":{"title":"laptop"}}}`)
	if cS1 != http.StatusOK || len(resS1["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("expected match query for 'laptop' to match 'notebook' doc via synonym_set, got %d %+v", cS1, resS1)
	}
	cS2, _, resS2, _ := doRound57Req(t, srv, http.MethodPost, "/r57_syn_docs/_search", `{"query":{"multi_match":{"query":"ny","fields":["title"]}}}`)
	if cS2 != http.StatusOK || len(resS2["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("expected multi_match query for 'ny' to match 'newyork' doc via explicit synonym, got %d %+v", cS2, resS2)
	}

	// 2. Inference SSE _stream, chat_completion (messages), classification, ner, and search-time knn/sparse_vector resolution
	doRound57Req(t, srv, http.MethodPut, "/_inference/chat_completion/r57_chat_ep", `{"service":"openai","service_settings":{"api_key":"sk-test","model":"gpt-4o"}}`)
	doRound57Req(t, srv, http.MethodPut, "/_inference/completion/r57_comp_ep", `{"service":"openai","service_settings":{"api_key":"sk-test"}}`)
	doRound57Req(t, srv, http.MethodPut, "/_inference/classification/r57_cls_ep", `{"service":"elasticsearch","service_settings":{"model_id":"cls-1"}}`)
	doRound57Req(t, srv, http.MethodPut, "/_inference/ner/r57_ner_ep", `{"service":"elasticsearch","service_settings":{"model_id":"ner-1"}}`)
	doRound57Req(t, srv, http.MethodPut, "/_inference/text_embedding/r57_emb_ep", `{"service":"openai","service_settings":{"api_key":"sk-test"}}`)
	doRound57Req(t, srv, http.MethodPut, "/_inference/sparse_embedding/r57_sparse_ep", `{"service":"elser","service_settings":{}}`)

	// SSE streaming (4-seg & 3-seg, plus non-streaming task 400 and missing 404)
	cStr1, rawStr1, _, hdrStr1 := doRound57Req(t, srv, http.MethodPost, "/_inference/chat_completion/r57_chat_ep/_stream", `{
		"messages": [{"role": "user", "content": "hello world"}]
	}`)
	if cStr1 != http.StatusOK || !strings.Contains(hdrStr1.Get("Content-Type"), "text/event-stream") || !strings.Contains(rawStr1, "data: ") || !strings.Contains(rawStr1, "[DONE]") {
		t.Fatalf("unexpected chat_completion SSE stream: code=%d ct=%s body=%q", cStr1, hdrStr1.Get("Content-Type"), rawStr1)
	}
	cStr2, rawStr2, _, _ := doRound57Req(t, srv, http.MethodPost, "/_inference/r57_comp_ep/_stream", `{"input": "stream prompt"}`)
	if cStr2 != http.StatusOK || !strings.Contains(rawStr2, `"task_type":"completion"`) {
		t.Fatalf("unexpected 3-seg completion SSE stream: code=%d body=%q", cStr2, rawStr2)
	}
	cStrBadTask, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_inference/r57_emb_ep/_stream", `{"input": "abc"}`)
	if cStrBadTask != http.StatusBadRequest {
		t.Fatalf("expected 400 streaming non-completion endpoint, got %d", cStrBadTask)
	}
	cStrMiss, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_inference/no_such_ep/_stream", `{"input": "abc"}`)
	if cStrMiss != http.StatusNotFound {
		t.Fatalf("expected 404 streaming missing endpoint, got %d", cStrMiss)
	}

	// Non-stream chat_completion (messages), classification, and ner
	cChat, _, resChat, _ := doRound57Req(t, srv, http.MethodPost, "/_inference/chat_completion/r57_chat_ep", `{"messages":[{"role":"user","content":"ping"}]}`)
	if cChat != http.StatusOK || resChat["chat_completion"] == nil {
		t.Fatalf("expected 200 with chat_completion choices, got %d %+v", cChat, resChat)
	}
	cCls, _, resCls, _ := doRound57Req(t, srv, http.MethodPost, "/_inference/classification/r57_cls_ep", `{"input":["Great product, love it!","Bad error occurred"]}`)
	if cCls != http.StatusOK || len(resCls["classification"].([]any)) != 2 {
		t.Fatalf("expected 2 classification results, got %d %+v", cCls, resCls)
	}
	if resCls["classification"].([]any)[0].(map[string]any)["predicted_value"] != "POSITIVE" {
		t.Fatalf("expected POSITIVE classification for positive text, got %+v", resCls["classification"])
	}
	cNER, _, resNER, _ := doRound57Req(t, srv, http.MethodPost, "/_inference/ner/r57_ner_ep", `{"input":"Alice visited Paris with Elastic"}`)
	if cNER != http.StatusOK || len(resNER["ner"].([]any)) != 1 {
		t.Fatalf("expected 1 NER result, got %d %+v", cNER, resNER)
	}

	// Search-time knn.query_vector_builder and sparse_vector.inference_id validation
	doRound57Req(t, srv, http.MethodPut, "/r57_vec_idx", `{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"emb": {"type": "dense_vector", "dims": 4},
				"ml_tokens": {"type": "sparse_vector"}
			}
		}
	}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_vec_idx/_doc/1?refresh=true", `{"title":"doc1","emb":[0.1,0.2,0.3,0.4],"ml_tokens":{"hello":1.5,"world":0.8}}`)

	cKNN, _, resKNN, _ := doRound57Req(t, srv, http.MethodPost, "/r57_vec_idx/_search", `{
		"knn": {
			"field": "emb",
			"k": 1,
			"num_candidates": 5,
			"query_vector_builder": {
				"text_embedding": {
					"model_id": "r57_emb_ep",
					"model_text": "hello world"
				}
			}
		}
	}`)
	if cKNN != http.StatusOK {
		t.Fatalf("expected 200 searching with knn.query_vector_builder, got %d %+v", cKNN, resKNN)
	}
	cKNNMiss, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/r57_vec_idx/_search", `{
		"knn": {"field":"emb","k":1,"num_candidates":5,"query_vector_builder":{"text_embedding":{"model_id":"missing_model_xyz","model_text":"hi"}}}
	}`)
	if cKNNMiss != http.StatusBadRequest {
		t.Fatalf("expected 400 when knn.query_vector_builder references missing model_id, got %d", cKNNMiss)
	}

	cSV, _, resSV, _ := doRound57Req(t, srv, http.MethodPost, "/r57_vec_idx/_search", `{
		"query": {
			"sparse_vector": {
				"field": "ml_tokens",
				"inference_id": "r57_sparse_ep",
				"query": "hello world"
			}
		}
	}`)
	if cSV != http.StatusOK {
		t.Fatalf("expected 200 searching with sparse_vector.inference_id, got %d %+v", cSV, resSV)
	}
	cSVWrongTask, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/r57_vec_idx/_search", `{
		"query": {"sparse_vector": {"field":"ml_tokens","inference_id":"r57_chat_ep","query":"hello"}}
	}`)
	if cSVWrongTask != http.StatusBadRequest {
		t.Fatalf("expected 400 when sparse_vector references chat_completion endpoint, got %d", cSVWrongTask)
	}
}

func TestRound57F7_ConnectorsAndSearchApplications(t *testing.T) {
	srv := newRound57TestServer()

	// 1. Connector sub-routes, parent validation on _sync_job, _stats typo fix, and _claim
	cCreate, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/_connector/r57_conn_1", `{
		"name": "Postgres Prod",
		"service_type": "postgresql",
		"index_name": "search-pg-init"
	}`)
	if cCreate != http.StatusCreated && cCreate != http.StatusOK {
		t.Fatalf("expected 200/201 creating connector, got %d", cCreate)
	}

	for _, step := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPut, "/_connector/r57_conn_1/_index_name", `{"index_name": "search-pg-v2"}`},
		{http.MethodPut, "/_connector/r57_conn_1/_scheduling", `{"scheduling": {"full": {"enabled": true, "interval": "0 0 * * *"}}}`},
		{http.MethodPut, "/_connector/r57_conn_1/_custom_scheduling", `{"custom_scheduling": {"incremental": {"enabled": true}}}`},
		{http.MethodPut, "/_connector/r57_conn_1/_api_key_id", `{"api_key_id": "ak-123", "api_key_secret_id": "sec-456"}`},
		{http.MethodPost, "/_connector/r57_conn_1/_filtering/valid", `{}`},
	} {
		cSub, _, resSub, _ := doRound57Req(t, srv, step.method, step.path, step.body)
		if cSub != http.StatusOK {
			t.Fatalf("%s %s failed: %d %+v", step.method, step.path, cSub, resSub)
		}
	}

	// Orphan sync job must fail with 404
	cOrphan, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_connector/_sync_job", `{"connector_id": "missing_conn"}`)
	if cOrphan != http.StatusNotFound {
		t.Fatalf("expected 404 creating sync_job for missing connector, got %d", cOrphan)
	}

	// _claim when none pending -> 204 No Content
	cClaimEmpty, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_connector/_sync_job/_claim", `{}`)
	if cClaimEmpty != http.StatusNoContent {
		t.Fatalf("expected 204 claiming when no sync job pending, got %d", cClaimEmpty)
	}

	// Create valid sync job -> copies updated index_name ("search-pg-v2") & service_type ("postgresql")
	cJob, _, resJob, _ := doRound57Req(t, srv, http.MethodPost, "/_connector/_sync_job", `{"connector_id": "r57_conn_1", "job_type": "full"}`)
	if cJob != http.StatusCreated && cJob != http.StatusOK {
		t.Fatalf("expected 201 creating sync_job, got %d %+v", cJob, resJob)
	}
	jobID, _ := resJob["id"].(string)

	// Claim pending sync job -> 200 in_progress with worker_hostname
	cClaim, _, resClaim, _ := doRound57Req(t, srv, http.MethodPost, "/_connector/_sync_job/_claim", `{"connector_id":"r57_conn_1","worker_hostname":"worker-node-7"}`)
	if cClaim != http.StatusOK || resClaim["id"] != jobID || resClaim["status"] != "in_progress" || resClaim["index_name"] != "search-pg-v2" || resClaim["worker_hostname"] != "worker-node-7" {
		t.Fatalf("unexpected claimed sync job: %d %+v", cClaim, resClaim)
	}

	// Update _stats with indexed_document_volume (no leading space!)
	cSt, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/_connector/_sync_job/"+jobID+"/_stats", `{"indexed_document_count": 42, "indexed_document_volume": 8192}`)
	if cSt != http.StatusOK {
		t.Fatalf("expected 200 on sync_job _stats, got %d", cSt)
	}
	cGetJob, _, resGetJob, _ := doRound57Req(t, srv, http.MethodGet, "/_connector/_sync_job/"+jobID, "")
	if cGetJob != http.StatusOK || fmt.Sprintf("%v", resGetJob["indexed_document_volume"]) != "8192" {
		t.Fatalf("expected indexed_document_volume=8192 on sync job, got %d %+v", cGetJob, resGetJob)
	}

	// 2. Search Application pagination & template.dictionary validation
	doRound57Req(t, srv, http.MethodPut, "/r57_app_docs", `{"mappings":{"properties":{"title":{"type":"text"},"category":{"type":"keyword"}}}}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_app_docs/_doc/1?refresh=true", `{"title":"go concurrency guide","category":"books"}`)

	doRound57Req(t, srv, http.MethodPut, "/_application/search_application/r57_app_a", `{
		"indices": ["r57_app_docs"],
		"template": {
			"script": {
				"lang": "mustache",
				"source": "{\"query\":{\"bool\":{\"must\":[{\"match\":{\"title\":\"{{q}}\"}},{\"term\":{\"category\":\"{{cat}}\"}}]}},\"size\":{{sz}}}",
				"params": {"sz": 5}
			},
			"dictionary": {
				"required": ["q", "cat"],
				"additionalProperties": false,
				"properties": {
					"q": {"type": "string"},
					"cat": {"type": "string", "enum": ["books", "videos"]},
					"sz": {"type": "integer"}
				}
			}
		}
	}`)
	doRound57Req(t, srv, http.MethodPut, "/_application/search_application/r57_app_b", `{"indices": ["r57_app_docs"]}`)

	// Pagination on GET /_application/search_application?from=1&size=1
	cList, _, resList, _ := doRound57Req(t, srv, http.MethodGet, "/_application/search_application?from=1&size=1", "")
	if cList != http.StatusOK || fmt.Sprintf("%v", resList["count"]) != "2" || len(resList["results"].([]any)) != 1 {
		t.Fatalf("expected count=2 and 1 paginated result, got %d %+v", cList, resList)
	}

	// Dictionary violations rejected with 400
	for _, badParams := range []string{
		`{"params": {"q": "go"}}`,                                      // missing required "cat"
		`{"params": {"q": 123, "cat": "books"}}`,                       // wrong type for "q"
		`{"params": {"q": "go", "cat": "podcasts"}}`,                   // enum violation
		`{"params": {"q": "go", "cat": "books", "sz": "five"}}`,        // wrong type for "sz"
		`{"params": {"q": "go", "cat": "books", "extra_param": true}}`, // additionalProperties: false
	} {
		cBad, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_application/search_application/r57_app_a/_render_query", badParams)
		if cBad != http.StatusBadRequest {
			t.Fatalf("expected 400 dictionary validation error for %s, got %d", badParams, cBad)
		}
	}

	// Valid params succeed on both _render_query and _search
	cRen, _, resRen, _ := doRound57Req(t, srv, http.MethodPost, "/_application/search_application/r57_app_a/_render_query", `{"params":{"q":"concurrency","cat":"books"}}`)
	if cRen != http.StatusOK || resRen["query"] == nil {
		t.Fatalf("expected 200 on valid _render_query, got %d %+v", cRen, resRen)
	}
	cAppS, _, resAppS, _ := doRound57Req(t, srv, http.MethodPost, "/_application/search_application/r57_app_a/_search", `{"params":{"q":"concurrency","cat":"books"}}`)
	if cAppS != http.StatusOK || len(resAppS["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("expected 1 hit from valid search application _search, got %d %+v", cAppS, resAppS)
	}
}

func TestRound57F8_SecurityAPIKeyQueryDSLPrivilegesCacheAndAuth(t *testing.T) {
	srv := newRound57TestServer()

	// 1. API key create, PUT /_security/api_key/{id}, invalidate rejection, and POST /_security/api_key/_bulk_update
	_, _, k1, _ := doRound57Req(t, srv, http.MethodPost, "/_security/api_key", `{"name":"r57-key-alpha","metadata":{"env":"dev"}}`)
	_, _, k2, _ := doRound57Req(t, srv, http.MethodPost, "/_security/api_key", `{"name":"r57-key-beta","metadata":{"env":"prod"}}`)
	id1, _ := k1["id"].(string)
	id2, _ := k2["id"].(string)

	cUpd, _, resUpd, _ := doRound57Req(t, srv, http.MethodPut, "/_security/api_key/"+id1, `{
		"role_descriptors": {"writer": {"cluster": ["monitor"]}},
		"metadata": {"env": "staging", "owner": "team-a"}
	}`)
	if cUpd != http.StatusOK || resUpd["updated"] != true {
		t.Fatalf("expected 200 updated:true on PUT /_security/api_key/%s, got %d %+v", id1, cUpd, resUpd)
	}
	cUpdMiss, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/_security/api_key/no_such_key", `{"metadata":{}}`)
	if cUpdMiss != http.StatusNotFound {
		t.Fatalf("expected 404 updating missing api_key, got %d", cUpdMiss)
	}

	// Invalidate id2 -> single PUT returns 400; _bulk_update updates id1 and reports error on id2 + missing_id
	doRound57Req(t, srv, http.MethodDelete, "/_security/api_key", fmt.Sprintf(`{"ids":[%q]}`, id2))
	cUpdInv, _, _, _ := doRound57Req(t, srv, http.MethodPut, "/_security/api_key/"+id2, `{"metadata":{"env":"x"}}`)
	if cUpdInv != http.StatusBadRequest {
		t.Fatalf("expected 400 updating invalidated api_key, got %d", cUpdInv)
	}

	cBulk, _, resBulk, _ := doRound57Req(t, srv, http.MethodPost, "/_security/api_key/_bulk_update", fmt.Sprintf(`{
		"ids": [%q, %q, "missing_key_999"],
		"metadata": {"env": "prod-v2"}
	}`, id1, id2))
	if cBulk != http.StatusOK || len(resBulk["updated"].([]any)) != 1 || fmt.Sprintf("%v", resBulk["error_count"]) != "2" {
		t.Fatalf("unexpected _bulk_update response: %d %+v", cBulk, resBulk)
	}

	// 2. /_security/_query/{api_key,user,role} with Query DSL, sort, from, size
	doRound57Req(t, srv, http.MethodPut, "/_security/user/alice_eng", `{"password":"secretPassword123","roles":["admin","dev"],"full_name":"Alice Eng","email":"alice@example.com"}`)
	doRound57Req(t, srv, http.MethodPut, "/_security/user/bob_sales", `{"password":"secretPassword123","roles":["viewer"],"full_name":"Bob Sales","email":"bob@example.com"}`)
	doRound57Req(t, srv, http.MethodPut, "/_security/role/r57_analytics_role", `{"cluster":["monitor"],"metadata":{"tier":2}}`)

	cQUser, _, resQUser, _ := doRound57Req(t, srv, http.MethodPost, "/_security/_query/user?with_profile_uid=true", `{
		"query": {
			"bool": {
				"must": [{"prefix": {"username": "alice"}}],
				"filter": [{"term": {"roles": "dev"}}, {"exists": {"field": "email"}}],
				"must_not": [{"term": {"username": "bob_sales"}}]
			}
		},
		"sort": [{"username": "asc"}],
		"from": 0,
		"size": 10
	}`)
	if cQUser != http.StatusOK || fmt.Sprintf("%v", resQUser["total"]) != "1" {
		t.Fatalf("expected 1 matched user from /_security/_query/user, got %d %+v", cQUser, resQUser)
	}
	u0 := resQUser["users"].([]any)[0].(map[string]any)
	if u0["username"] != "alice_eng" || u0["profile_uid"] == nil {
		t.Fatalf("expected alice_eng with profile_uid, got %+v", u0)
	}

	cQRole, _, resQRole, _ := doRound57Req(t, srv, http.MethodPost, "/_security/_query/role", `{
		"query": {"wildcard": {"name": "r57_*"}},
		"size": 5
	}`)
	if cQRole != http.StatusOK || fmt.Sprintf("%v", resQRole["total"]) != "1" {
		t.Fatalf("expected 1 matched role from /_security/_query/role, got %d %+v", cQRole, resQRole)
	}

	cQKey, _, resQKey, _ := doRound57Req(t, srv, http.MethodPost, "/_security/_query/api_key", `{
		"query": {"bool": {"must": [{"term": {"invalidated": false}}, {"match": {"name": "alpha"}}]}}
	}`)
	if cQKey != http.StatusOK || fmt.Sprintf("%v", resQKey["total"]) != "1" {
		t.Fatalf("expected 1 active alpha api_key from /_security/_query/api_key, got %d %+v", cQKey, resQKey)
	}

	// 3. GET /_security/user/_privileges (must not look up user named "_privileges")
	cPriv, _, resPriv, _ := doRound57Req(t, srv, http.MethodGet, "/_security/user/_privileges", "")
	if cPriv != http.StatusOK || resPriv["cluster"] == nil || resPriv["indices"] == nil {
		t.Fatalf("expected 200 cluster/indices privileges on GET /_security/user/_privileges, got %d %+v", cPriv, resPriv)
	}

	// 4. Non-destructive cache-clear interceptors for privilege & service token
	doRound57Req(t, srv, http.MethodPut, "/_security/privilege", `{"my_app":{"read":{"actions":["data:read/*"]}}}`)
	cPCC, _, resPCC, _ := doRound57Req(t, srv, http.MethodPost, "/_security/privilege/my_app/_clear_cache", "")
	if cPCC != http.StatusOK || resPCC["_nodes"] == nil {
		t.Fatalf("expected _nodes cache-clear response for privilege, got %d %+v", cPCC, resPCC)
	}
	cGetPriv, _, resGetPriv, _ := doRound57Req(t, srv, http.MethodGet, "/_security/privilege/my_app", "")
	if cGetPriv != http.StatusOK || resGetPriv["my_app"].(map[string]any)["_clear_cache"] != nil {
		t.Fatalf("privilege _clear_cache must NOT mutate stored privileges: %+v", resGetPriv)
	}

	_, _, resTok, _ := doRound57Req(t, srv, http.MethodPost, "/_security/service/elastic/fleet-server/credential/token/tok1", "")
	origVal := resTok["token"].(map[string]any)["value"]
	cSCC, _, resSCC, _ := doRound57Req(t, srv, http.MethodPost, "/_security/service/elastic/fleet-server/credential/token/tok1/_clear_cache", "")
	if cSCC != http.StatusOK || resSCC["_nodes"] == nil {
		t.Fatalf("expected _nodes cache-clear response for service token, got %d %+v", cSCC, resSCC)
	}
	_ = origVal

	// 5. OIDC, SAML, Delegate PKI, and SSL Certificates
	cOIDCPrep, _, resOIDCPrep, _ := doRound57Req(t, srv, http.MethodPost, "/_security/oidc/prepare", `{"realm":"oidc1"}`)
	if cOIDCPrep != http.StatusOK || resOIDCPrep["redirect"] == nil || resOIDCPrep["state"] == nil {
		t.Fatalf("OIDC prepare failed: %d %+v", cOIDCPrep, resOIDCPrep)
	}
	cOIDCAuth, _, resOIDCAuth, _ := doRound57Req(t, srv, http.MethodPost, "/_security/oidc/authenticate", fmt.Sprintf(`{"redirect_uri":"https://app/cb?code=abc","state":%q}`, resOIDCPrep["state"]))
	if cOIDCAuth != http.StatusOK || resOIDCAuth["access_token"] == nil {
		t.Fatalf("OIDC authenticate failed: %d %+v", cOIDCAuth, resOIDCAuth)
	}
	cOIDCOut, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_security/oidc/logout", fmt.Sprintf(`{"token":%q}`, resOIDCAuth["access_token"]))
	if cOIDCOut != http.StatusOK {
		t.Fatalf("OIDC logout failed: %d", cOIDCOut)
	}

	cSAMLPrep, _, resSAMLPrep, _ := doRound57Req(t, srv, http.MethodPost, "/_security/saml/prepare", `{"realm":"saml1"}`)
	if cSAMLPrep != http.StatusOK || resSAMLPrep["id"] == nil {
		t.Fatalf("SAML prepare failed: %d %+v", cSAMLPrep, resSAMLPrep)
	}
	cSAMLAuth, _, resSAMLAuth, _ := doRound57Req(t, srv, http.MethodPost, "/_security/saml/authenticate", `{"content":"PHNhbWw+...","ids":["req1"]}`)
	if cSAMLAuth != http.StatusOK || resSAMLAuth["access_token"] == nil {
		t.Fatalf("SAML authenticate failed: %d %+v", cSAMLAuth, resSAMLAuth)
	}
	cSAMLInv, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_security/saml/invalidate", `{"query_string":"SAMLRequest=xyz"}`)
	cSAMLOut, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_security/saml/logout", fmt.Sprintf(`{"token":%q}`, resSAMLAuth["access_token"]))
	cSAMLDone, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_security/saml/complete_logout", `{}`)
	cSAMLMeta, rawMeta, _, hdrMeta := doRound57Req(t, srv, http.MethodPost, "/_security/saml/metadata", `{"realm_name":"saml1"}`)
	if cSAMLInv != http.StatusOK || cSAMLOut != http.StatusOK || cSAMLDone != http.StatusOK || cSAMLMeta != http.StatusOK || !strings.Contains(hdrMeta.Get("Content-Type"), "xml") || !strings.Contains(rawMeta, "EntityDescriptor") {
		t.Fatalf("SAML lifecycle failed: inv=%d out=%d done=%d meta=%d body=%q", cSAMLInv, cSAMLOut, cSAMLDone, cSAMLMeta, rawMeta)
	}

	cPKI, _, resPKI, _ := doRound57Req(t, srv, http.MethodPost, "/_security/delegate_pki", `{"subject_dn":"CN=svc_node,OU=Eng,O=Org"}`)
	if cPKI != http.StatusOK || resPKI["username"] != "svc_node" || resPKI["access_token"] == nil {
		t.Fatalf("delegate_pki failed: %d %+v", cPKI, resPKI)
	}
	cSSL, rawSSL, _, _ := doRound57Req(t, srv, http.MethodGet, "/_security/ssl/certificates", "")
	if cSSL != http.StatusOK || !strings.Contains(rawSSL, "http.p12") {
		t.Fatalf("expected 200 JSON array on GET /_security/ssl/certificates, got %d %s", cSSL, rawSSL)
	}
}

func TestRound57F9_FleetCapabilitiesIngestSimulateScriptsMLAndOps(t *testing.T) {
	srv := newRound57TestServer()

	// 1. Fleet global_checkpoints lowercase key + /_fleet/secrets CRUD with redaction
	doRound57Req(t, srv, http.MethodPut, "/r57_fleet_idx", `{"mappings":{"properties":{"msg":{"type":"keyword"}}}}`)
	cFleetCP, _, resFleetCP, _ := doRound57Req(t, srv, http.MethodGet, "/r57_fleet_idx/_fleet/global_checkpoints", "")
	if cFleetCP != http.StatusOK || resFleetCP["last_known_global_checkpoints"] == nil || resFleetCP["last_KNOWN_global_checkpoints"] != nil {
		t.Fatalf("expected lowercase last_known_global_checkpoints, got %d %+v", cFleetCP, resFleetCP)
	}

	cFSecPost, _, resFSecPost, _ := doRound57Req(t, srv, http.MethodPost, "/_fleet/secrets", `{"value":"super-secret-token"}`)
	if cFSecPost != http.StatusOK || resFSecPost["id"] == nil {
		t.Fatalf("POST /_fleet/secrets failed: %d %+v", cFSecPost, resFSecPost)
	}
	secID, _ := resFSecPost["id"].(string)
	cFSecGet, rawFSecGet, resFSecGet, _ := doRound57Req(t, srv, http.MethodGet, "/_fleet/secrets/"+secID, "")
	if cFSecGet != http.StatusOK || resFSecGet["id"] != secID || strings.Contains(rawFSecGet, "super-secret-token") {
		t.Fatalf("expected GET /_fleet/secrets/%s to redact secret value, got %d %s", secID, cFSecGet, rawFSecGet)
	}
	cFSecDel, _, _, _ := doRound57Req(t, srv, http.MethodDelete, "/_fleet/secrets/"+secID, "")
	cFSecGone, _, _, _ := doRound57Req(t, srv, http.MethodGet, "/_fleet/secrets/"+secID, "")
	if cFSecDel != http.StatusOK || cFSecGone != http.StatusNotFound {
		t.Fatalf("expected 200 DELETE then 404 GET on fleet secret, got %d / %d", cFSecDel, cFSecGone)
	}

	// 2. GET/POST /_capabilities
	cCap1, _, resCap1, _ := doRound57Req(t, srv, http.MethodGet, "/_capabilities", "")
	cCap2, _, resCap2, _ := doRound57Req(t, srv, http.MethodPost, "/_capabilities", `{"capabilities":["esql","eql"]}`)
	if cCap1 != http.StatusOK || resCap1["capabilities"] == nil || cCap2 != http.StatusOK || len(resCap2["capabilities"].(map[string]any)) != 2 {
		t.Fatalf("unexpected /_capabilities responses: %d %+v / %d %+v", cCap1, resCap1, cCap2, resCap2)
	}

	// 3. POST /_ingest/_simulate (template resolution, default_pipeline + final_pipeline + pipeline_substitutions + mapping_addition)
	doRound57Req(t, srv, http.MethodPut, "/_ingest/pipeline/r57_def_pipe", `{"processors":[{"set":{"field":"from_default","value":"orig"}}]}`)
	doRound57Req(t, srv, http.MethodPut, "/_ingest/pipeline/r57_fin_pipe", `{"processors":[{"set":{"field":"final_stamp","value":42}}]}`)
	doRound57Req(t, srv, http.MethodPut, "/_index_template/r57_sim_tpl", `{
		"index_patterns": ["r57-sim-*"],
		"template": {
			"settings": {
				"index.default_pipeline": "r57_def_pipe",
				"index.final_pipeline": "r57_fin_pipe"
			},
			"mappings": {
				"properties": {
					"declared_host": {"type": "keyword"}
				}
			}
		}
	}`)

	cSimBad, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_ingest/_simulate", `{"docs":[{"msg":"hi"}]}`)
	if cSimBad != http.StatusBadRequest {
		t.Fatalf("expected 400 when index is missing in /_ingest/_simulate, got %d", cSimBad)
	}

	cSim, _, resSim, _ := doRound57Req(t, srv, http.MethodPost, "/_ingest/_simulate?verbose=true", `{
		"index": "r57-sim-logs-01",
		"docs": [
			{"_source": {"declared_host": "web-1", "dyn_flag": true}}
		],
		"pipeline_substitutions": {
			"r57_def_pipe": {
				"processors": [
					{"set": {"field": "from_default", "value": "substituted"}}
				]
			}
		}
	}`)
	if cSim != http.StatusOK {
		t.Fatalf("POST /_ingest/_simulate failed: %d %+v", cSim, resSim)
	}
	simArr, _ := resSim["pipeline_simulation"].([]any)
	if len(simArr) != 1 {
		t.Fatalf("expected 1 pipeline_simulation entry, got %+v", resSim)
	}
	sim0 := simArr[0].(map[string]any)
	simSrc := sim0["doc"].(map[string]any)["_source"].(map[string]any)
	if simSrc["from_default"] != "substituted" || fmt.Sprintf("%v", simSrc["final_stamp"]) != "42" || sim0["processor_results"] == nil {
		t.Fatalf("unexpected pipeline_simulation doc/verbose trace: %+v", sim0)
	}
	mapAddProps := resSim["mapping_addition"].(map[string]any)["properties"].(map[string]any)
	if mapAddProps["declared_host"] != nil || mapAddProps["dyn_flag"] == nil || mapAddProps["final_stamp"] == nil {
		t.Fatalf("expected mapping_addition to omit declared_host and include dynamic fields, got %+v", mapAddProps)
	}

	// 4. GET /_scripts/_context & GET /_scripts/_languages
	cCtx, _, resCtx, _ := doRound57Req(t, srv, http.MethodGet, "/_scripts/_context", "")
	cLang, _, resLang, _ := doRound57Req(t, srv, http.MethodGet, "/_scripts/_languages", "")
	if cCtx != http.StatusOK || len(resCtx["contexts"].([]any)) < 5 || cLang != http.StatusOK || len(resLang["language_contexts"].([]any)) < 3 {
		t.Fatalf("unexpected _scripts/_context or _scripts/_languages: ctx=%d %+v lang=%d %+v", cCtx, resCtx, cLang, resLang)
	}

	// 5. ML routes, HEAD /_logstash/pipeline/{id}, _flush/synced, _freeze/_unfreeze, _rethrottle, /_migration/system_features
	cMLMiss, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_ml/trained_models/no_model/deployment/_cache/_clear", "")
	if cMLMiss != http.StatusNotFound {
		t.Fatalf("expected 404 clearing cache on missing ML model, got %d", cMLMiss)
	}
	doRound57Req(t, srv, http.MethodPut, "/_ml/trained_models/r57_mdl", `{"input":{"field_names":["text"]}}`)
	doRound57Req(t, srv, http.MethodPost, "/_ml/trained_models/r57_mdl/deployment/_start", `{}`)
	cMLClr, _, resMLClr, _ := doRound57Req(t, srv, http.MethodPost, "/_ml/trained_models/r57_mdl/deployment/_cache/_clear", "")
	if cMLClr != http.StatusOK || resMLClr["acknowledged"] != true {
		t.Fatalf("expected 200 clearing ML deployment cache, got %d %+v", cMLClr, resMLClr)
	}

	cFFS, _, resFFS, _ := doRound57Req(t, srv, http.MethodPost, "/_ml/find_file_structure", "a,b\n1,2\n3,4\n")
	if cFFS != http.StatusOK || resFFS["format"] == nil {
		t.Fatalf("POST /_ml/find_file_structure failed: %d %+v", cFFS, resFFS)
	}

	doRound57Req(t, srv, http.MethodPut, "/_ml/anomaly_detectors/r57_job", `{"analysis_config":{"bucket_span":"15m","detectors":[{"function":"count"}]},"data_description":{"time_field":"@timestamp"}}`)
	doRound57Req(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r57_job/_open", `{}`)
	doRound57Req(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r57_job/_data", `{"@timestamp": 1700000000000}`)
	doRound57Req(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r57_job/_close", `{}`)
	cUpgMiss, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r57_job/model_snapshots/snap_missing/_upgrade", `{}`)
	cUpg1, _, resUpg1, _ := doRound57Req(t, srv, http.MethodPost, "/_ml/anomaly_detectors/r57_job/model_snapshots/1/_upgrade", `{}`)
	cUpg2, _, resUpg2, _ := doRound57Req(t, srv, http.MethodGet, "/_ml/anomaly_detectors/r57_job/model_snapshots/1/_upgrade/_stats", "")
	if cUpgMiss != http.StatusNotFound || cUpg1 != http.StatusOK || resUpg1["acknowledged"] != true || cUpg2 != http.StatusOK {
		t.Fatalf("ML snapshot _upgrade/_stats failed: miss=%d upg=%d %+v stats=%d %+v", cUpgMiss, cUpg1, resUpg1, cUpg2, resUpg2)
	}

	cLSMiss, _, _, _ := doRound57Req(t, srv, http.MethodHead, "/_logstash/pipeline/r57_ls_pipe", "")
	doRound57Req(t, srv, http.MethodPut, "/_logstash/pipeline/r57_ls_pipe", `{"pipeline":"input { stdin {} }","description":"test"}`)
	cLSHit, _, _, _ := doRound57Req(t, srv, http.MethodHead, "/_logstash/pipeline/r57_ls_pipe", "")
	if cLSMiss != http.StatusNotFound || cLSHit != http.StatusOK {
		t.Fatalf("expected HEAD /_logstash/pipeline to return 404 before PUT and 200 after PUT, got %d / %d", cLSMiss, cLSHit)
	}

	cFS1, _, resFS1, _ := doRound57Req(t, srv, http.MethodPost, "/_flush/synced", "")
	cFS2, _, resFS2, _ := doRound57Req(t, srv, http.MethodPost, "/r57_fleet_idx/_flush/synced", "")
	if cFS1 != http.StatusOK || resFS1["_shards"] == nil || cFS2 != http.StatusOK || resFS2["r57_fleet_idx"] == nil {
		t.Fatalf("_flush/synced failed: %d %+v / %d %+v", cFS1, resFS1, cFS2, resFS2)
	}

	cFrz, _, resFrz, _ := doRound57Req(t, srv, http.MethodPost, "/r57_fleet_idx/_freeze", "")
	cUnfrz, _, resUnfrz, _ := doRound57Req(t, srv, http.MethodPost, "/r57_fleet_idx/_unfreeze", "")
	cFrzMiss, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/missing_idx_xyz/_freeze", "")
	if cFrz != http.StatusOK || resFrz["acknowledged"] != true || cUnfrz != http.StatusOK || resUnfrz["acknowledged"] != true || cFrzMiss != http.StatusNotFound {
		t.Fatalf("_freeze/_unfreeze failed: %d / %d / %d", cFrz, cUnfrz, cFrzMiss)
	}

	for _, rtPath := range []string{
		"/_reindex/nodeA:101/_rethrottle?requests_per_second=250",
		"/_update_by_query/nodeA:102/_rethrottle?requests_per_second=unlimited",
		"/r57_fleet_idx/_update_by_query/nodeA:103/_rethrottle?requests_per_second=50",
		"/_delete_by_query/nodeA:104/_rethrottle?requests_per_second=-1",
		"/r57_fleet_idx/_delete_by_query/nodeA:105/_rethrottle?requests_per_second=10",
	} {
		cRT, _, resRT, _ := doRound57Req(t, srv, http.MethodPost, rtPath, "")
		if cRT != http.StatusOK || resRT["nodes"] == nil {
			t.Fatalf("expected 200 on %s, got %d %+v", rtPath, cRT, resRT)
		}
	}
	cRTBadTask, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_reindex/not_a_task_id/_rethrottle", "")
	cRTBadRPS, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_reindex/nodeA:101/_rethrottle?requests_per_second=0", "")
	if cRTBadTask != http.StatusBadRequest || cRTBadRPS != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid _rethrottle task_id or rps, got %d / %d", cRTBadTask, cRTBadRPS)
	}

	cMigGet, _, resMigGet, _ := doRound57Req(t, srv, http.MethodGet, "/_migration/system_features", "")
	cMigPost, _, resMigPost, _ := doRound57Req(t, srv, http.MethodPost, "/_migration/system_features", `{"feature_name":"kibana"}`)
	if cMigGet != http.StatusOK || resMigGet["features"] == nil || cMigPost != http.StatusOK || resMigPost["acknowledged"] != true {
		t.Fatalf("/_migration/system_features failed: %d %+v / %d %+v", cMigGet, resMigGet, cMigPost, resMigPost)
	}
}

func TestRound57F27_F28_F29_IngestValidationJavaRegexAndStrictConvert(t *testing.T) {
	srv := newRound57TestServer()

	// 1. F27: Pipeline processor validation rejections (400)
	invalidPipelines := []string{
		`{"processors":[{"sort":{"field":"arr","order":"ascending"}}]}`,
		`{"processors":[{"sort":{"field":"arr","order":123}}]}`,
		`{"processors":[{"split":{"field":"s","separator":"[unclosed"}}]}`,
		`{"processors":[{"split":{"field":"s","separator":",","preserve_trailing":"yes"}}]}`,
		`{"processors":[{"kv":{"field":"s","field_split":"[unclosed","value_split":"="}}]}`,
		`{"processors":[{"kv":{"field":"s","field_split":" ","value_split":"[unclosed"}}]}`,
		`{"processors":[{"kv":{"field":"s","field_split":" ","value_split":"=","include_keys":"not_array"}}]}`,
		`{"processors":[{"kv":{"field":"s","field_split":" ","value_split":"=","exclude_keys":[123]}}]}`,
		`{"processors":[{"date":{"field":"ts","formats":[]}}]}`,
		`{"processors":[{"date":{"field":"ts","formats":[""]}}]}`,
		`{"processors":[{"date_index_name":{"field":"ts","date_rounding":"d","date_formats":[]}}]}`,
		`{"processors":[{"fingerprint":{"fields":[]}}]}`,
		`{"processors":[{"fingerprint":{"fields":[""]}}]}`,
		`{"processors":[{"fingerprint":{"exclude_fields":[42]}}]}`,
	}
	for i, badSpec := range invalidPipelines {
		cBad, _, _, _ := doRound57Req(t, srv, http.MethodPut, fmt.Sprintf("/_ingest/pipeline/r57_bad_%d", i), badSpec)
		if cBad != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid pipeline #%d (%s), got %d", i, badSpec, cBad)
		}
	}

	// F27: date TAI64N, DDD / u / y / ordinal_date, and UNIX / UNIX_MS NaN/Inf rejection
	cDateSim, _, resDateSim, _ := doRound57Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"date": {
						"field": "tai_ts",
						"formats": ["TAI64N"],
						"target_field": "parsed_tai"
					}
				},
				{
					"date": {
						"field": "ord_ts",
						"formats": ["uuuu-DDD'T'HH:mm:ssZ"],
						"target_field": "parsed_ord"
					}
				},
				{
					"date": {
						"field": "builtin_ord",
						"formats": ["ordinal_date_no_millis"],
						"target_field": "parsed_builtin_ord"
					}
				},
				{
					"date": {
						"field": "nan_epoch",
						"formats": ["UNIX"],
						"on_failure": [{"set": {"field": "nan_rejected", "value": true}}]
					}
				},
				{
					"date": {
						"field": "inf_epoch_ms",
						"formats": ["UNIX_MS"],
						"on_failure": [{"set": {"field": "inf_rejected", "value": true}}]
					}
				}
			]
		},
		"docs": [
			{
				"_source": {
					"tai_ts": "@400000006592008a00000000",
					"ord_ts": "2024-032T00:00:00+0000",
					"builtin_ord": "2024-060T12:30:00Z",
					"nan_epoch": "NaN",
					"inf_epoch_ms": "Infinity"
				}
			}
		]
	}`)
	if cDateSim != http.StatusOK {
		t.Fatalf("F27 date simulate failed: %d %+v", cDateSim, resDateSim)
	}
	docEntry, _ := resDateSim["docs"].([]any)[0].(map[string]any)
	docObj, okDoc := docEntry["doc"].(map[string]any)
	if !okDoc {
		t.Fatalf("F27 date simulate returned doc error: %+v", resDateSim)
	}
	dOut := docObj["_source"].(map[string]any)
	if dOut["parsed_tai"] != "2024-01-01T00:00:00.000Z" && dOut["parsed_tai"] != "2024-01-01T00:00:00Z" {
		t.Fatalf("expected TAI64N @400000006592008a00000000 -> 2024-01-01T00:00:00Z, got %v", dOut["parsed_tai"])
	}
	if !strings.HasPrefix(fmt.Sprintf("%v", dOut["parsed_ord"]), "2024-02-01") {
		t.Fatalf("expected ordinal day 032 of 2024 -> 2024-02-01, got %v", dOut["parsed_ord"])
	}
	if !strings.HasPrefix(fmt.Sprintf("%v", dOut["parsed_builtin_ord"]), "2024-02-29T12:30:00") {
		t.Fatalf("expected leap ordinal day 060 of 2024 -> 2024-02-29, got %v", dOut["parsed_builtin_ord"])
	}
	if dOut["nan_rejected"] != true || dOut["inf_rejected"] != true {
		t.Fatalf("expected NaN and Infinity epoch values to trigger on_failure, got %+v", dOut)
	}

	// 2. F28: Java named capture (?<name>...), ${name}, $0, \-, \$, \\, and invalid replacement errors
	cRegexSim, _, resRegexSim, _ := doRound57Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{
					"gsub": {
						"field": "named_src",
						"pattern": "(?<dept>[a-z]+)-(?<code>\\d+)",
						"replacement": "${code}\\-${dept}\\$\\\\[$0]"
					}
				},
				{
					"split": {
						"field": "pipe_str",
						"separator": "|"
					}
				},
				{
					"gsub": {
						"field": "bad_repl_group",
						"pattern": "(\\w+)",
						"replacement": "$9",
						"on_failure": [{"set": {"field": "bad_group_caught", "value": true}}]
					}
				},
				{
					"gsub": {
						"field": "bad_repl_slash",
						"pattern": "(\\w+)",
						"replacement": "trailing\\",
						"on_failure": [{"set": {"field": "bad_slash_caught", "value": true}}]
					}
				},
				{
					"gsub": {
						"field": "bad_repl_dollar",
						"pattern": "(\\w+)",
						"replacement": "$unknown",
						"on_failure": [{"set": {"field": "bad_dollar_caught", "value": true}}]
					}
				}
			]
		},
		"docs": [
			{
				"_source": {
					"named_src": "eng-404",
					"pipe_str": "x|y|z",
					"bad_repl_group": "abc",
					"bad_repl_slash": "abc",
					"bad_repl_dollar": "abc"
				}
			}
		]
	}`)
	if cRegexSim != http.StatusOK {
		t.Fatalf("F28 regex simulate failed: %d %+v", cRegexSim, resRegexSim)
	}
	rOut := resRegexSim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if rOut["named_src"] != `404-eng$\[eng-404]` {
		t.Fatalf("unexpected Java Matcher.replaceAll output: %q", rOut["named_src"])
	}
	if len(rOut["pipe_str"].([]any)) != 3 || rOut["bad_group_caught"] != true || rOut["bad_slash_caught"] != true || rOut["bad_dollar_caught"] != true {
		t.Fatalf("unexpected F28 split/on_failure results: %+v", rOut)
	}

	// 3. F29: Strict Go-type aware convert processor (integer/unsigned_long/float/boolean/ip/auto)
	cConvSim, _, resConvSim, _ := doRound57Req(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"convert": {"field": "sci_int", "type": "integer", "on_failure": [{"set": {"field": "sci_int_err", "value": true}}]}},
				{"convert": {"field": "pad_int", "type": "integer", "on_failure": [{"set": {"field": "pad_int_err", "value": true}}]}},
				{"convert": {"field": "ulong_ok", "type": "unsigned_long"}},
				{"convert": {"field": "ulong_neg", "type": "unsigned_long", "on_failure": [{"set": {"field": "ulong_neg_err", "value": true}}]}},
				{"convert": {"field": "pad_float", "type": "float", "on_failure": [{"set": {"field": "pad_float_err", "value": true}}]}},
				{"convert": {"field": "int_bool", "type": "boolean", "on_failure": [{"set": {"field": "int_bool_err", "value": true}}]}},
				{"convert": {"field": "pad_bool", "type": "boolean", "on_failure": [{"set": {"field": "pad_bool_err", "value": true}}]}},
				{"convert": {"field": "yes_bool", "type": "boolean"}},
				{"convert": {"field": "off_bool", "type": "boolean"}},
				{"convert": {"field": "ip_v6", "type": "ip"}},
				{"convert": {"field": "ip_bad", "type": "ip", "on_failure": [{"set": {"field": "ip_bad_err", "value": true}}]}},
				{"convert": {"field": "auto_float", "type": "auto"}},
				{"convert": {"field": "auto_bool", "type": "auto"}},
				{"convert": {"field": "auto_str_int", "type": "auto"}},
				{"convert": {"field": "auto_padded", "type": "auto"}}
			]
		},
		"docs": [
			{
				"_source": {
					"sci_int": "1e2",
					"pad_int": " 42 ",
					"ulong_ok": "18446744073709551615",
					"ulong_neg": "-1",
					"pad_float": " 3.14 ",
					"int_bool": 1,
					"pad_bool": " true ",
					"yes_bool": "yes",
					"off_bool": "off",
					"ip_v6": "2001:0db8:0000:0000:0000:0000:0000:0001",
					"ip_bad": "999.999.1.1",
					"auto_float": 2.5,
					"auto_bool": true,
					"auto_str_int": "77",
					"auto_padded": " 77 "
				}
			}
		]
	}`)
	if cConvSim != http.StatusOK {
		t.Fatalf("F29 convert simulate failed: %d %+v", cConvSim, resConvSim)
	}
	cOut := resConvSim["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	for _, errFlag := range []string{"sci_int_err", "pad_int_err", "ulong_neg_err", "pad_float_err", "int_bool_err", "pad_bool_err", "ip_bad_err"} {
		if cOut[errFlag] != true {
			t.Fatalf("expected %s=true in strict convert validation, got %+v", errFlag, cOut)
		}
	}
	if cOut["yes_bool"] != true || cOut["off_bool"] != false {
		t.Fatalf("expected yes_bool=true and off_bool=false, got %v / %v", cOut["yes_bool"], cOut["off_bool"])
	}
	if cOut["ip_v6"] != "2001:db8::1" {
		t.Fatalf("expected canonicalized IPv6 '2001:db8::1', got %v", cOut["ip_v6"])
	}
	if fv, ok := cOut["auto_float"].(float64); !ok || math.Abs(fv-2.5) > 1e-9 {
		t.Fatalf("expected auto_float=2.5, got %T %v", cOut["auto_float"], cOut["auto_float"])
	}
	if cOut["auto_bool"] != true || fmt.Sprintf("%v", cOut["auto_str_int"]) != "77" || cOut["auto_padded"] != " 77 " {
		t.Fatalf("unexpected auto convert outputs: %+v", cOut)
	}
}

func TestRound57F_ExtendedBranchCoverage(t *testing.T) {
	srv := newRound57TestServer()

	// --- 1. SQL Engine extended scalar functions, aggregates, predicates, comments, params, translate DSL, type mapping ---
	doRound57Req(t, srv, http.MethodPut, "/r57_sql_cov", `{
		"mappings": {
			"properties": {
				"name": {"type": "keyword"},
				"bio": {"type": "text"},
				"age": {"type": "integer"},
				"salary": {"type": "long"},
				"score": {"type": "double"},
				"ratio": {"type": "float"},
				"active": {"type": "boolean"},
				"created_at": {"type": "date"},
				"ip_addr": {"type": "ip"},
				"meta": {"type": "object"},
				"items": {"type": "nested"}
			}
		}
	}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_sql_cov/_alias/r57_sql_cov_alias", `{}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_sql_cov/_doc/1?refresh=true", `{"name":"Alice","bio":"  hello world  ","age":30,"salary":1000,"score":9.6,"ratio":1.5,"active":true,"created_at":"2025-01-15T10:20:30Z","ip_addr":"10.0.0.1"}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_sql_cov/_doc/2?refresh=true", `{"name":"Bob","bio":"  foo bar  ","age":20,"salary":500,"score":-4.2,"ratio":0.5,"active":false,"created_at":"2025-02-20T08:00:00Z","ip_addr":"10.0.0.2","extra":"present"}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_sql_cov/_doc/3?refresh=true", `{"name":"Alice","bio":"dup","age":30,"salary":1500,"score":2.4,"ratio":2.5,"active":true}`)

	// DESCRIBE covering all ES->SQL field types + SHOW COLUMNS FROM alias
	cDesc, _, resDesc, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", `{"query":"/* block comment */ SHOW COLUMNS FROM \"r57_sql_cov_alias\""}`)
	if cDesc != http.StatusOK || len(resDesc["rows"].([]any)) < 8 {
		t.Fatalf("SHOW COLUMNS FROM alias failed: %d %+v", cDesc, resDesc)
	}
	cShowFn, _, resShowFn, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", `{"query":"SHOW FUNCTIONS LIKE '%LEN%'"}`)
	if cShowFn != http.StatusOK || len(resShowFn["rows"].([]any)) == 0 {
		t.Fatalf("SHOW FUNCTIONS LIKE failed: %d %+v", cShowFn, resShowFn)
	}

	// Scalar SQL functions + arithmetic + comments + escaped quotes + typed params
	cScal, rawScal, _, hdrScal := doRound57Req(t, srv, http.MethodPost, "/_sql?format=tsv", `{
		"query": "-- line comment\nSELECT DISTINCT UPPER(`+"`name`"+`) AS u, LENGTH(TRIM(bio)) AS l, CHAR_LENGTH(name) AS cl, SUBSTRING(name, 1, 3) AS sub, ROUND(score, 0) AS rnd, ABS(score) AS ab, FLOOR(score) AS fl, CEIL(score) AS cl2, -age + 10 * 2 - 4 / 2 + 7 % 4 AS math_v FROM r57_sql_cov AS emp WHERE name <> ? AND active = ? AND score >= ? AND extra IS NULL AND age NOT IN (99, 100) AND name NOT LIKE 'Z%' AND age NOT BETWEEN 50 AND 60 ORDER BY u ASC NULLS LAST LIMIT 5",
		"params": ["O'Reilly", true, -10.5]
	}`)
	if cScal != http.StatusOK || !strings.Contains(hdrScal.Get("Content-Type"), "tab-separated-values") || !strings.Contains(rawScal, "ALICE") {
		t.Fatalf("SQL scalar/TSV query failed: %d ct=%s body=%q", cScal, hdrScal.Get("Content-Type"), rawScal)
	}

	// Aggregates (COUNT(col), MIN, MAX, SUM, AVG) + NULLS FIRST
	cAgg, _, resAgg, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", `{
		"query": "SELECT name, COUNT(extra) AS cnt_extra, MIN(salary) AS min_sal, MAX(salary) AS max_sal, SUM(salary) AS sum_sal, AVG(salary) AS avg_sal FROM r57_sql_cov WHERE (active = true OR extra IS NOT NULL) AND NOT (age < 10) GROUP BY name HAVING SUM(salary) >= 500 ORDER BY sum_sal DESC NULLS FIRST LIMIT 2"
	}`)
	if cAgg != http.StatusOK || len(resAgg["rows"].([]any)) != 2 {
		t.Fatalf("SQL aggregates + FETCH FIRST failed: %d %+v", cAgg, resAgg)
	}
	cStar, _, resStar, _ := doRound57Req(t, srv, http.MethodPost, "/_sql", `{"query":"SELECT * FROM r57_sql_cov WHERE extra IS NOT NULL"}`)
	if cStar != http.StatusOK || len(resStar["rows"].([]any)) != 1 {
		t.Fatalf("SELECT * failed: %d %+v", cStar, resStar)
	}

	// /_sql/translate covering compound OR, NOT, IS NULL, IS NOT NULL, IN, NOT IN, LIKE, BETWEEN, !=, <=, <, >
	cTransComplex, _, resTransComplex, _ := doRound57Req(t, srv, http.MethodPost, "/_sql/translate", `{
		"query": "SELECT name, COUNT(*) AS c, SUM(salary) AS s, AVG(age) AS a, MIN(score) AS mn, MAX(score) AS mx FROM r57_sql_cov WHERE (name = 'Alice' OR name IN ('Bob', 'Carol')) AND name NOT IN ('Mallory') AND NOT (age <= 5) AND score > -10 AND ratio < 10.0 AND bio LIKE '%hello%' AND extra IS NULL AND created_at IS NOT NULL AND salary BETWEEN 100 AND 2000 AND age != 999 GROUP BY name ORDER BY name ASC LIMIT 10"
	}`)
	if cTransComplex != http.StatusOK || resTransComplex["query"] == nil || resTransComplex["aggs"] == nil {
		t.Fatalf("complex /_sql/translate failed: %d %+v", cTransComplex, resTransComplex)
	}

	// --- 2. ES|QL Engine extended functions (SPLIT, LOCATE, LTRIM, RTRIM, LEFT, RIGHT, POW, SQRT, MOD, GREATEST, LEAST, TO_DATETIME, MV_*, DATE_*) & stages ---
	cESQL, _, resESQL, _ := doRound57Req(t, srv, http.MethodPost, "/_query", `{
		"query": "ROW raw = \"  alpha,beta,gamma  \", nums = [30, 10, 20, 10], d1 = \"2025-01-01T00:00:00Z\", d2 = \"2025-03-16T06:30:45Z\" | EVAL sp = SPLIT(TRIM(raw), \",\"), loc = LOCATE(raw, \"beta\", 1), lt = LTRIM(raw), rt = RTRIM(raw), lf = LEFT(TRIM(raw), 5), rg = RIGHT(TRIM(raw), 5), pw = POW(2, 4), sq = SQRT(81), md = MOD(17, 5), gr = GREATEST(3, 9, 5), ls = LEAST(3, 9, 5), dt = TO_DATETIME(d1), mn = MV_MIN(nums), av = MV_AVG(nums), cc = MV_CONCAT(MV_SORT(MV_DEDUPE(nums), \"DESC\"), \"-\"), sl = MV_SLICE(nums, 1, 2), dy = DATE_EXTRACT(\"month\", d2), dw = DATE_EXTRACT(\"dow\", d2), dh = DATE_EXTRACT(\"hour\", d2), dm = DATE_EXTRACT(\"minute\", d2), ds = DATE_EXTRACT(\"second\", d2), tr_m = DATE_TRUNC(\"1month\", d2), tr_d = DATE_TRUNC(\"1d\", d2), tr_h = DATE_TRUNC(\"1h\", d2), tr_min = DATE_TRUNC(\"5m\", d2), tr_s = DATE_TRUNC(\"1s\", d2), dp = DATE_PARSE(\"yyyy-MM-dd\", \"2025-04-05\"), df = DATE_FORMAT(\"yyyy-MM-dd\", d2), df_y = DATE_DIFF(\"years\", d1, d2), df_mo = DATE_DIFF(\"months\", d1, d2), df_w = DATE_DIFF(\"weeks\", d1, d2), df_d = DATE_DIFF(\"days\", d1, d2), df_h = DATE_DIFF(\"hours\", d1, d2), df_m = DATE_DIFF(\"minutes\", d1, d2), df_s = DATE_DIFF(\"seconds\", d1, d2), df_ms = DATE_DIFF(\"ms\", d1, d2) | RENAME lf AS left_part | DROP raw | LIMIT 5"
	}`)
	if cESQL != http.StatusOK || len(resESQL["values"].([]any)) != 1 {
		t.Fatalf("extended ES|QL functions failed: %d %+v", cESQL, resESQL)
	}
	// ES|QL DISSECT APPEND_SEPARATOR + error paths on GROK / ENRICH
	cDis, _, resDis, _ := doRound57Req(t, srv, http.MethodPost, "/_query", `{
		"query": "ROW msg = \"a b c\" | DISSECT msg \"%{part} %{+part} %{last}\" APPEND_SEPARATOR=\"_\" | KEEP part, last"
	}`)
	if cDis != http.StatusOK || resDis["values"].([]any)[0].([]any)[0] != "a_b" {
		t.Fatalf("ES|QL DISSECT APPEND_SEPARATOR failed: %d %+v", cDis, resDis)
	}
	cBadEnrich, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_query", `{"query": "ROW k = \"1\" | ENRICH missing_policy ON k"}`)
	if cBadEnrich != http.StatusBadRequest {
		t.Fatalf("expected 400 on missing ES|QL ENRICH policy, got %d", cBadEnrich)
	}

	// --- 3. EQL extended functions, operators, negation stage (![...]), async get/delete ---
	doRound57Req(t, srv, http.MethodPut, "/r57_eql_cov", `{"mappings":{"properties":{"@timestamp":{"type":"date"},"event.category":{"type":"keyword"},"host.name":{"type":"keyword"},"process.name":{"type":"keyword"},"source.ip":{"type":"ip"},"port":{"type":"integer"}}}}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_eql_cov/_doc/1?refresh=true", `{"@timestamp":"2025-05-01T00:00:01Z","event":{"category":"process"},"host":{"name":"h1"},"process":{"name":"powershell.exe"},"source":{"ip":"192.168.1.25"},"port":443}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_eql_cov/_doc/2?refresh=true", `{"@timestamp":"2025-05-01T00:00:05Z","event":{"category":"file"},"host":{"name":"h1"},"process":{"name":"cmd.exe"},"source":{"ip":"192.168.1.25"},"port":8080}`)

	cEQL1, _, resEQL1, _ := doRound57Req(t, srv, http.MethodPost, "/r57_eql_cov/_eql/search", `{
		"query": "// eql comment\n/* block */ process where length(process.name) >= 5 and startsWith(process.name, \"power\") and endsWith(process.name, \".exe\") and stringContains(process.name, \"shell\") and cidrMatch(source.ip, \"192.168.1.0/24\") and regex(process.name, \"^power.*\") and process.name ~ \".*exe$\" and port != 80 and port > 100 and port <= 443 and process.name not in (\"bash\", \"sh\")",
		"keep_on_completion": true
	}`)
	if cEQL1 != http.StatusOK || len(resEQL1["hits"].(map[string]any)["events"].([]any)) != 1 {
		t.Fatalf("extended single-event EQL failed: %d %+v", cEQL1, resEQL1)
	}
	if eqlID, okID := resEQL1["id"].(string); okID && eqlID != "" {
		cEG, _, _, _ := doRound57Req(t, srv, http.MethodGet, "/_eql/search/"+eqlID, "")
		cED, _, _, _ := doRound57Req(t, srv, http.MethodDelete, "/_eql/search/"+eqlID, "")
		if cEG != http.StatusOK || cED != http.StatusOK {
			t.Fatalf("expected 200 GET/DELETE /_eql/search/%s, got %d / %d", eqlID, cEG, cED)
		}
	}
	cEQLSeq, _, resEQLSeq, _ := doRound57Req(t, srv, http.MethodPost, "/r57_eql_cov/_eql/search", `{
		"query": "sequence by host.name with maxspan=1m [process where port >= 400] ![network where port == 22] [file where port > 1000]"
	}`)
	if cEQLSeq != http.StatusOK || len(resEQLSeq["hits"].(map[string]any)["sequences"].([]any)) != 1 {
		t.Fatalf("EQL sequence with ![...] stage failed: %d %+v", cEQLSeq, resEQLSeq)
	}

	// --- 4. Snapshot rename_pattern + global state restore, Custom Analyze inline & field modes ---
	doRound57Req(t, srv, http.MethodPut, "/_snapshot/r57_cov_repo", `{"type":"fs","settings":{"location":"/tmp/r57_cov"}}`)
	doRound57Req(t, srv, http.MethodPut, "/_ingest/pipeline/r57_snap_pipe", `{"processors":[{"set":{"field":"snap_restored","value":true}}]}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_orig_idx", `{"settings":{"index.number_of_replicas":"0"},"aliases":{"r57_orig_alias":{}},"mappings":{"properties":{"k":{"type":"keyword"}}}}`)
	doRound57Req(t, srv, http.MethodPut, "/r57_orig_idx/_doc/1?refresh=true", `{"k":"v1"}`)
	doRound57Req(t, srv, http.MethodPut, "/_snapshot/r57_cov_repo/snap_full?wait_for_completion=true", `{"indices":"r57_orig_idx","include_global_state":true}`)
	doRound57Req(t, srv, http.MethodDelete, "/_ingest/pipeline/r57_snap_pipe", "")
	cRestRen, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_snapshot/r57_cov_repo/snap_full/_restore", `{
		"indices": "r57_orig_idx",
		"include_global_state": true,
		"include_aliases": true,
		"rename_pattern": "r57_orig_(.+)",
		"rename_replacement": "r57_renamed_$1",
		"index_settings": {"index.refresh_interval": "5s"},
		"ignore_index_settings": ["index.number_of_replicas"]
	}`)
	if cRestRen != http.StatusOK {
		t.Fatalf("snapshot restore with rename_pattern + global_state failed: %d", cRestRen)
	}
	cPipeCheck, _, _, _ := doRound57Req(t, srv, http.MethodGet, "/_ingest/pipeline/r57_snap_pipe", "")
	cRenSearch, _, resRenSearch, _ := doRound57Req(t, srv, http.MethodGet, "/r57_renamed_idx/_search", "")
	if cPipeCheck != http.StatusOK || cRenSearch != http.StatusOK || len(resRenSearch["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("restored pipeline or renamed index verification failed: pipe=%d search=%d", cPipeCheck, cRenSearch)
	}

	// Inline synonym filter on /_analyze + field-based custom analyze
	cInlAn, _, resInlAn, _ := doRound57Req(t, srv, http.MethodPost, "/_analyze", `{
		"tokenizer": "whitespace",
		"filter": ["lowercase", {"type": "synonym", "synonyms": ["fast, quick", "nyc => newyork"]}],
		"text": ["Fast NYC"]
	}`)
	if cInlAn != http.StatusOK || len(resInlAn["tokens"].([]any)) != 3 {
		t.Fatalf("inline synonym /_analyze failed: %d %+v", cInlAn, resInlAn)
	}

	// --- 5. Security Query DSL full clause coverage (exists, terms, prefix, wildcard, match, range, bool should/must_not, sort, search_after) ---
	for i, kn := range []string{"alpha-key", "beta-key", "gamma-key"} {
		doRound57Req(t, srv, http.MethodPost, "/_security/api_key", fmt.Sprintf(`{"name":%q,"metadata":{"tier":%d,"env":"prod-us"}}`, kn, (i+1)*10))
	}
	cSecQ, _, resSecQ, _ := doRound57Req(t, srv, http.MethodPost, "/_security/_query/api_key", `{
		"query": {
			"bool": {
				"must": [
					{"exists": {"field": "name"}},
					{"prefix": {"name": {"value": "AL", "case_insensitive": true}}},
					{"wildcard": {"metadata.env": {"value": "prod-*", "case_insensitive": true}}},
					{"match": {"name": {"query": "alpha"}}},
					{"terms": {"invalidated": [false]}},
					{"range": {"metadata.tier": {"gte": 5, "lte": 25, "gt": 0, "lt": 30}}}
				],
				"should": [
					{"term": {"name": {"value": "ALPHA-KEY", "case_insensitive": true}}}
				],
				"minimum_should_match": 1,
				"must_not": [
					{"match_none": {}}
				]
			}
		},
		"sort": [{"name": {"order": "asc"}}],
		"size": 5
	}`)
	if cSecQ != http.StatusOK || len(resSecQ["api_keys"].([]any)) != 1 {
		t.Fatalf("extended security _query DSL failed: %d %+v", cSecQ, resSecQ)
	}

	// --- 6. Search Application JSON schema types (integer, number, boolean, array, object) + /_ingest/_simulate dynamic field inference ---
	doRound57Req(t, srv, http.MethodPut, "/r57_sapp_cov", `{"mappings":{"properties":{"title":{"type":"text"}}}}`)
	doRound57Req(t, srv, http.MethodPut, "/_application/search_application/r57_typed_app", `{
		"indices": ["r57_sapp_cov"],
		"template": {
			"script": {
				"source": "{\"query\":{\"match_all\":{}}}",
				"params": {"q": "x", "lim": 5, "boost": 1.5, "flag": true, "tags": ["a"], "flt": {"k": "v"}}
			},
			"dictionary": {
				"type": "object",
				"required": ["q"],
				"properties": {
					"q": {"type": "string"},
					"lim": {"type": "integer"},
					"boost": {"type": "number"},
					"flag": {"type": "boolean"},
					"tags": {"type": "array"},
					"flt": {"type": "object"}
				}
			}
		}
	}`)
	cAppOK, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_application/search_application/r57_typed_app/_search", `{
		"params": {"q": "ok", "lim": 10, "boost": 2.25, "flag": false, "tags": ["x", "y"], "flt": {"a": 1}}
	}`)
	cAppBadInt, _, _, _ := doRound57Req(t, srv, http.MethodPost, "/_application/search_application/r57_typed_app/_search", `{
		"params": {"q": "ok", "lim": "not_int"}
	}`)
	if cAppOK != http.StatusOK || cAppBadInt != http.StatusBadRequest {
		t.Fatalf("search application JSON schema validation failed: ok=%d bad=%d", cAppOK, cAppBadInt)
	}

	// /_ingest/_simulate with rich dynamic types (float, int, bool, string, nested object, array)
	cIngRich, _, resIngRich, _ := doRound57Req(t, srv, http.MethodPost, "/_ingest/_simulate", `{
		"index": "r57-rich-dyn-01",
		"docs": [{
			"_source": {
				"str_v": "hello",
				"int_v": 42,
				"flt_v": 3.14,
				"bool_v": true,
				"arr_v": ["x", "y"],
				"nested_obj": {"sub_k": "sub_v", "sub_n": 7}
			}
		}]
	}`)
	if cIngRich != http.StatusOK || resIngRich["mapping_addition"] == nil {
		t.Fatalf("rich /_ingest/_simulate failed: %d %+v", cIngRich, resIngRich)
	}
}
