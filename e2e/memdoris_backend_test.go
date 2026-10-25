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

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
)

// MemDorisBackend is a stateful in-process Apache Doris storage & SQL execution engine
// for fast, deterministic E2E testing of `doris-es-proxy`.
// It stores shredded Stream Load JSON rows (`f__*`, `n__*`, `_doc`, `_source`, `_all_text`,
// `_id`, `_version`, `__DORIS_DELETE_SIGN__`) in Unique Key Merge-on-Write tables and
// evaluates the transpiled Doris SQL AST (`WHERE`, `_score`, `ORDER BY`, `LIMIT/OFFSET`,
// `WITH base_matched AS (...)`, `LATERAL VIEW EXPLODE`, `array_exists`, `array_contains`,
// `MATCH_ANY`/`MATCH_ALL`/`MATCH_PHRASE`, and metric/bucket aggregations) against the physical
// shredded columns.
type MemDorisBackend struct {
	mu       sync.RWMutex
	ddls     []string
	hitsSQLs []string
	aggsSQLs []string
	tables   map[string]map[string]map[string]any // table -> _id -> shredded row map
}

func NewMemDorisBackend() *MemDorisBackend {
	return &MemDorisBackend{
		tables: make(map[string]map[string]map[string]any),
	}
}

func (m *MemDorisBackend) ExecDDL(_ context.Context, ddl string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ddls = append(m.ddls, ddl)

	upper := strings.ToUpper(ddl)
	if strings.HasPrefix(upper, "CREATE TABLE") {
		tbl := extractTableNameFromDDL(ddl)
		if tbl != "" && m.tables[tbl] == nil {
			m.tables[tbl] = make(map[string]map[string]any)
		}
	} else if strings.HasPrefix(upper, "DROP TABLE") {
		tbl := extractTableNameFromDDL(ddl)
		delete(m.tables, tbl)
	}
	return nil
}

func (m *MemDorisBackend) StreamLoad(_ context.Context, table string, ndjson []byte, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tables[table] == nil {
		m.tables[table] = make(map[string]map[string]any)
	}
	scanner := bufio.NewScanner(bytes.NewReader(ndjson))
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		var row map[string]any
		if err := dec.Decode(&row); err != nil {
			return err
		}
		id := fmt.Sprintf("%v", row["_id"])
		delSign, _ := toInt64(row["__DORIS_DELETE_SIGN__"])
		if delSign == 1 {
			delete(m.tables[table], id)
			continue
		}
		m.tables[table][id] = row
	}
	return scanner.Err()
}

func (m *MemDorisBackend) GetDocByID(_ context.Context, _, table, id string) (*proxy.HitRow, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tbl := m.tables[table]
	if tbl == nil {
		return nil, false, nil
	}
	row, ok := tbl[id]
	if !ok {
		return nil, false, nil
	}
	ver, _ := toInt64(row["_version"])
	srcStr, _ := row["_source"].(string)
	return &proxy.HitRow{
		ID:      id,
		Version: ver,
		Source:  json.RawMessage(srcStr),
		Score:   1.0,
	}, true, nil
}

var (
	reHitsSQL = regexp.MustCompile(`(?s)^SELECT ` + "`_id`, `_version`, `_source`, CAST\\((.+) AS DOUBLE\\) AS `_score`, COUNT\\(\\*\\) OVER\\(\\) AS `_total_hits` FROM `[^`]+`\\.`([^`]+)` WHERE `__DORIS_DELETE_SIGN__` = 0 AND \\((.+)\\) AND \\((.+)\\) ORDER BY (.+) LIMIT (\\d+) OFFSET (\\d+)$")
	reCTEBase = regexp.MustCompile(`(?s)^WITH ` + "`base_matched` AS \\(SELECT \\* FROM `[^`]+`\\.`([^`]+)` WHERE `__DORIS_DELETE_SIGN__` = 0 AND \\((.+?)\\)\\)\n(.+)$")
)

func (m *MemDorisBackend) QueryHits(_ context.Context, sqlStr string) ([]proxy.HitRow, error) {
	m.mu.Lock()
	m.hitsSQLs = append(m.hitsSQLs, sqlStr)
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	sub := reHitsSQL.FindStringSubmatch(sqlStr)
	if sub == nil {
		return nil, fmt.Errorf("unrecognized HitsSQL format: %s", sqlStr)
	}
	scoreExpr := sub[1]
	tableName := sub[2]
	mainWhere := sub[3]
	postWhere := sub[4]
	orderByClause := sub[5]
	limit, _ := strconv.Atoi(sub[6])
	offset, _ := strconv.Atoi(sub[7])

	tbl := m.tables[tableName]
	var matchedRows []map[string]any
	var hits []proxy.HitRow

	for _, row := range tbl {
		if evalWhereExpr(row, mainWhere) && evalWhereExpr(row, postWhere) {
			score := evalNumericExpr(row, scoreExpr)
			ver, _ := toInt64(row["_version"])
			srcStr, _ := row["_source"].(string)
			matchedRows = append(matchedRows, row)
			hits = append(hits, proxy.HitRow{
				ID:      fmt.Sprintf("%v", row["_id"]),
				Version: ver,
				Source:  json.RawMessage(srcStr),
				Score:   score,
			})
		}
	}

	totalHits := int64(len(hits))
	for i := range hits {
		hits[i].TotalHits = totalHits
	}

	// Sort hits according to ORDER BY clause
	sortIdx := make([]int, len(hits))
	for i := range sortIdx {
		sortIdx[i] = i
	}
	orderSpecs := strings.Split(orderByClause, ",")
	sort.SliceStable(sortIdx, func(a, b int) bool {
		ia, ib := sortIdx[a], sortIdx[b]
		for _, spec := range orderSpecs {
			fields := strings.Fields(strings.TrimSpace(spec))
			if len(fields) == 0 {
				continue
			}
			colExpr := fields[0]
			desc := len(fields) > 1 && strings.EqualFold(fields[1], "DESC")
			var cmp int
			switch colExpr {
			case "`_score`":
				cmp = compareFloats(hits[ia].Score, hits[ib].Score)
			case "`_id`":
				cmp = strings.Compare(hits[ia].ID, hits[ib].ID)
			default:
				va := resolveColumnValue(matchedRows[ia], colExpr)
				vb := resolveColumnValue(matchedRows[ib], colExpr)
				cmp = compareAny(va, vb)
			}
			if cmp != 0 {
				if desc {
					return cmp > 0
				}
				return cmp < 0
			}
		}
		return hits[ia].ID < hits[ib].ID
	})

	sortedHits := make([]proxy.HitRow, 0, len(hits))
	for _, idx := range sortIdx {
		sortedHits = append(sortedHits, hits[idx])
	}

	if offset >= len(sortedHits) {
		return nil, nil
	}
	end := offset + limit
	if end > len(sortedHits) {
		end = len(sortedHits)
	}
	return sortedHits[offset:end], nil
}

func (m *MemDorisBackend) QueryAggs(_ context.Context, sqlStr string) ([]proxy.AggRow, error) {
	m.mu.Lock()
	m.aggsSQLs = append(m.aggsSQLs, sqlStr)
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	sub := reCTEBase.FindStringSubmatch(sqlStr)
	if sub == nil {
		return nil, fmt.Errorf("unrecognized AggsSQL format: %s", sqlStr)
	}
	tableName := sub[1]
	baseWhere := sub[2]
	unionBranches := strings.Split(sub[3], "\nUNION ALL\n")

	tbl := m.tables[tableName]
	var baseRows []map[string]any
	for _, row := range tbl {
		if evalWhereExpr(row, baseWhere) {
			baseRows = append(baseRows, row)
		}
	}

	var out []proxy.AggRow
	for _, branch := range unionBranches {
		branch = strings.TrimSpace(branch)
		rows := evalAggBranch(baseRows, branch)
		out = append(out, rows...)
	}
	return out, nil
}

var (
	reAggArrayExplode = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CAST\\(`_elem` AS STRING\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_t` AS `_elem` WHERE (?:\\((.+?)\\) AND )?`_elem` IS NOT NULL GROUP BY `_elem` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggScalarTerms  = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CAST\\((.+?) AS STRING\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (?:\\((.+?)\\) AND )?.+? IS NOT NULL GROUP BY .+? ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggNestedTerms  = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, json_extract_string\\(`_nel`, '\\$\\.([^']+)'\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_nt` AS `_nel` WHERE (?:\\((.+?)\\) AND )?json_extract_string\\(`_nel`, '\\$\\.[^']+'\\) IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggFilter       = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_filter' AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (.+)$")
	reAggMissing      = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_missing' AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (?:\\((.+?)\\) AND )?NOT \\((.+)\\)$")
	reAggCardArray    = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COUNT\\(DISTINCT `_elem`\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_t` AS `_elem` WHERE (?:\\((.+?)\\) AND )?`_elem` IS NOT NULL$")
	reAggCardScalar   = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COUNT\\(DISTINCT (.+?)\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
	reAggMetric       = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COALESCE\\((AVG|SUM|MIN|MAX)\\((.+?)\\), 0\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
)

func evalAggBranch(baseRows []map[string]any, branch string) []proxy.AggRow {
	if strings.Contains(branch, "'__meta_total'") {
		cnt := int64(len(baseRows))
		return []proxy.AggRow{{AggName: "__meta_total", BucketKey: "_count", DocCount: cnt, Value: float64(cnt)}}
	}

	if m := reAggArrayExplode.FindStringSubmatch(branch); m != nil {
		aggName, arrCol, extraWhere := m[1], m[2], m[3]
		limit, _ := strconv.Atoi(m[4])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			for _, elem := range toStringSlice(row[arrCol]) {
				if elem != "" {
					counts[elem]++
				}
			}
		}
		return topBuckets(aggName, counts, limit)
	}

	if m := reAggNestedTerms.FindStringSubmatch(branch); m != nil {
		aggName, relPath, corrCol, extraWhere := m[1], m[2], m[3], m[4]
		limit, _ := strconv.Atoi(m[5])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			for _, elemJSON := range toStringSlice(row[corrCol]) {
				val := extractJSONPathFromStr(elemJSON, strings.Split(relPath, "."))
				if val != nil {
					switch v := val.(type) {
					case []any:
						for _, item := range v {
							counts[fmt.Sprintf("%v", item)]++
						}
					default:
						s := fmt.Sprintf("%v", v)
						if s != "" {
							counts[s]++
						}
					}
				}
			}
		}
		return topBuckets(aggName, counts, limit)
	}

	if m := reAggScalarTerms.FindStringSubmatch(branch); m != nil {
		aggName, colExpr, extraWhere := m[1], m[2], m[3]
		limit, _ := strconv.Atoi(m[4])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			val := resolveColumnValue(row, colExpr)
			if val != nil {
				s := fmt.Sprintf("%v", val)
				if s != "" {
					counts[s]++
				}
			}
		}
		return topBuckets(aggName, counts, limit)
	}

	if m := reAggFilter.FindStringSubmatch(branch); m != nil {
		aggName, filterWhere := m[1], m[2]
		var cnt int64
		for _, row := range baseRows {
			if evalWhereExpr(row, filterWhere) {
				cnt++
			}
		}
		return []proxy.AggRow{{AggName: aggName, BucketKey: "_filter", DocCount: cnt, Value: float64(cnt)}}
	}

	if m := reAggMissing.FindStringSubmatch(branch); m != nil {
		aggName, extraWhere, existsWhere := m[1], m[2], m[3]
		var cnt int64
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			if !evalWhereExpr(row, existsWhere) {
				cnt++
			}
		}
		return []proxy.AggRow{{AggName: aggName, BucketKey: "_missing", DocCount: cnt, Value: float64(cnt)}}
	}

	if m := reAggCardArray.FindStringSubmatch(branch); m != nil {
		aggName, arrCol, extraWhere := m[1], m[2], m[3]
		seen := make(map[string]bool)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			for _, elem := range toStringSlice(row[arrCol]) {
				if elem != "" {
					seen[elem] = true
				}
			}
		}
		cnt := int64(len(seen))
		return []proxy.AggRow{{AggName: aggName, BucketKey: "_metric", DocCount: cnt, Value: float64(cnt)}}
	}

	if m := reAggCardScalar.FindStringSubmatch(branch); m != nil {
		aggName, colExpr, extraWhere := m[1], m[2], m[3]
		seen := make(map[string]bool)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			if val := resolveColumnValue(row, colExpr); val != nil {
				seen[fmt.Sprintf("%v", val)] = true
			}
		}
		cnt := int64(len(seen))
		return []proxy.AggRow{{AggName: aggName, BucketKey: "_metric", DocCount: cnt, Value: float64(cnt)}}
	}

	if m := reAggMetric.FindStringSubmatch(branch); m != nil {
		aggName, fn, colExpr, extraWhere := m[1], m[2], m[3], m[4]
		var nums []float64
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			if val := resolveColumnValue(row, colExpr); val != nil {
				if f, ok := toFloat(val); ok {
					nums = append(nums, f)
				}
			}
		}
		var res float64
		if len(nums) > 0 {
			switch fn {
			case "SUM":
				for _, v := range nums {
					res += v
				}
			case "AVG":
				for _, v := range nums {
					res += v
				}
				res /= float64(len(nums))
			case "MIN":
				res = nums[0]
				for _, v := range nums[1:] {
					if v < res {
						res = v
					}
				}
			case "MAX":
				res = nums[0]
				for _, v := range nums[1:] {
					if v > res {
						res = v
					}
				}
			}
		}
		return []proxy.AggRow{{AggName: aggName, BucketKey: "_metric", DocCount: int64(res), Value: res}}
	}

	return nil
}

func topBuckets(aggName string, counts map[string]int64, limit int) []proxy.AggRow {
	rows := make([]proxy.AggRow, 0, len(counts))
	for k, c := range counts {
		rows = append(rows, proxy.AggRow{
			AggName:   aggName,
			BucketKey: k,
			DocCount:  c,
			Value:     float64(c),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DocCount != rows[j].DocCount {
			return rows[i].DocCount > rows[j].DocCount
		}
		return rows[i].BucketKey < rows[j].BucketKey
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

func evalWhereExpr(row map[string]any, expr string) bool {
	expr = trimOuterParens(strings.TrimSpace(expr))
	if expr == "" || strings.EqualFold(expr, "TRUE") {
		return true
	}
	if strings.EqualFold(expr, "FALSE") {
		return false
	}

	// Split top-level OR
	if parts := splitTopLevelLogicalOp(expr, " OR "); len(parts) > 1 {
		for _, p := range parts {
			if evalWhereExpr(row, p) {
				return true
			}
		}
		return false
	}

	// Split top-level AND
	if parts := splitTopLevelLogicalOp(expr, " AND "); len(parts) > 1 {
		for _, p := range parts {
			if !evalWhereExpr(row, p) {
				return false
			}
		}
		return true
	}

	if strings.HasPrefix(expr, "NOT COALESCE(") && strings.HasSuffix(expr, ", FALSE)") {
		inner := expr[len("NOT COALESCE(") : len(expr)-len(", FALSE)")]
		return !evalWhereExpr(row, inner)
	}
	if strings.HasPrefix(expr, "NOT ") {
		return !evalWhereExpr(row, expr[4:])
	}

	// Check array_exists(_el -> <bodyExpr>, `<col>`)
	if strings.HasPrefix(expr, "array_exists(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("array_exists(") : len(expr)-1]
		arrowIdx := strings.Index(inner, "->")
		lastComma := strings.LastIndexByte(inner, ',')
		if arrowIdx > 0 && lastComma > arrowIdx {
			varName := strings.TrimSpace(inner[:arrowIdx])
			bodyExpr := strings.TrimSpace(inner[arrowIdx+2 : lastComma])
			colName := strings.Trim(strings.TrimSpace(inner[lastComma+1:]), "`")
			for _, elemStr := range toStringSlice(row[colName]) {
				if evalLambdaBody(elemStr, varName, bodyExpr) {
					return true
				}
			}
			return false
		}
	}

	// Check array_contains(`<col>`, 'val')
	if strings.HasPrefix(expr, "array_contains(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("array_contains(") : len(expr)-1]
		commaIdx := strings.IndexByte(inner, ',')
		if commaIdx > 0 {
			colName := strings.Trim(strings.TrimSpace(inner[:commaIdx]), "`")
			target := unquoteSQLLiteral(strings.TrimSpace(inner[commaIdx+1:]))
			for _, item := range toStringSlice(row[colName]) {
				if item == target {
					return true
				}
			}
			return false
		}
	}

	// Check arrays_overlap(`<col>`, [...])
	if strings.HasPrefix(expr, "arrays_overlap(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("arrays_overlap(") : len(expr)-1]
		brackIdx := strings.IndexByte(inner, '[')
		if brackIdx > 0 {
			colName := strings.Trim(strings.TrimSpace(inner[: strings.IndexByte(inner, ',')]), "`")
			listStr := strings.TrimSuffix(inner[brackIdx+1:], "]")
			targets := make(map[string]bool)
			for _, part := range strings.Split(listStr, ",") {
				targets[unquoteSQLLiteral(strings.TrimSpace(part))] = true
			}
			for _, item := range toStringSlice(row[colName]) {
				if targets[item] {
					return true
				}
			}
			return false
		}
	}

	// Check array_size(`<col>`) > 0
	if strings.HasPrefix(expr, "array_size(") && strings.HasSuffix(expr, ") > 0") {
		colName := strings.Trim(strings.TrimSpace(expr[len("array_size("):len(expr)-len(") > 0")]), "`")
		return len(toStringSlice(row[colName])) > 0
	}

	// Check IS NOT NULL
	if strings.HasSuffix(expr, " IS NOT NULL") {
		colExpr := strings.TrimSpace(expr[:len(expr)-len(" IS NOT NULL")])
		val := resolveColumnValue(row, colExpr)
		return val != nil
	}

	// Check MATCH_ANY / MATCH_ALL / MATCH_PHRASE / MATCH_PHRASE_PREFIX / MATCH_REGEXP
	for _, matchOp := range []string{" MATCH_PHRASE_PREFIX ", " MATCH_PHRASE ", " MATCH_REGEXP ", " MATCH_ALL ", " MATCH_ANY "} {
		if idx := strings.Index(expr, matchOp); idx > 0 {
			colExpr := strings.TrimSpace(expr[:idx])
			lit := unquoteSQLLiteral(strings.TrimSpace(expr[idx+len(matchOp):]))
			return evalFulltextMatch(row, colExpr, strings.TrimSpace(matchOp), lit)
		}
	}

	// Check IN (...)
	if idx := strings.Index(expr, " IN ("); idx > 0 && strings.HasSuffix(expr, ")") {
		colExpr := strings.TrimSpace(expr[:idx])
		listStr := expr[idx+len(" IN (") : len(expr)-1]
		val := resolveColumnValue(row, colExpr)
		if val == nil {
			return false
		}
		valStr := fmt.Sprintf("%v", val)
		for _, item := range strings.Split(listStr, ",") {
			if valStr == unquoteSQLLiteral(strings.TrimSpace(item)) {
				return true
			}
		}
		return false
	}

	// Check LIKE
	if idx := strings.Index(expr, " LIKE "); idx > 0 {
		lhs := strings.TrimSpace(expr[:idx])
		rhs := strings.TrimSpace(expr[idx+len(" LIKE "):])
		ci := false
		if strings.HasPrefix(lhs, "lower(") && strings.HasSuffix(lhs, ")") {
			ci = true
			lhs = lhs[6 : len(lhs)-1]
		}
		if strings.HasPrefix(rhs, "lower(") && strings.HasSuffix(rhs, ")") {
			ci = true
			rhs = rhs[6 : len(rhs)-1]
		}
		val := resolveColumnValue(row, lhs)
		if val == nil {
			return false
		}
		pat := unquoteSQLLiteral(rhs)
		return evalLikePattern(fmt.Sprintf("%v", val), pat, ci)
	}

	// Check REGEXP
	if idx := strings.Index(expr, " REGEXP "); idx > 0 {
		lhs := strings.TrimSpace(expr[:idx])
		pat := unquoteSQLLiteral(strings.TrimSpace(expr[idx+len(" REGEXP "):]))
		val := resolveColumnValue(row, lhs)
		if val == nil {
			return false
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return false
		}
		return re.MatchString(fmt.Sprintf("%v", val))
	}

	// Check comparison operators (`>=`, `<=`, `!=`, `=`, `>`, `<`)
	for _, op := range []string{">=", "<=", "!=", "=", ">", "<"} {
		if idx := findTopLevelOp(expr, op); idx > 0 {
			lhs := strings.TrimSpace(expr[:idx])
			rhs := strings.TrimSpace(expr[idx+len(op):])
			ci := false
			if strings.HasPrefix(lhs, "lower(") && strings.HasSuffix(lhs, ")") {
				ci = true
				lhs = lhs[6 : len(lhs)-1]
			}
			if strings.HasPrefix(rhs, "lower(") && strings.HasSuffix(rhs, ")") {
				ci = true
				rhs = rhs[6 : len(rhs)-1]
			}
			// Check if lhs is arithmetic sum like `((CAST(...) + CAST(...)) >= 2)`
			if op == ">=" && strings.Contains(lhs, " + ") {
				lhsNum := evalNumericExpr(row, lhs)
				rhsNum, _ := strconv.ParseFloat(rhs, 64)
				return lhsNum >= rhsNum
			}
			val := resolveColumnValue(row, lhs)
			if val == nil {
				return false
			}
			rhsVal := parseSQLLiteralValue(rhs)
			if ci {
				val = strings.ToLower(fmt.Sprintf("%v", val))
				rhsVal = strings.ToLower(fmt.Sprintf("%v", rhsVal))
			}
			cmp := compareAny(val, rhsVal)
			switch op {
			case "=":
				return cmp == 0
			case "!=":
				return cmp != 0
			case ">":
				return cmp > 0
			case ">=":
				return cmp >= 0
			case "<":
				return cmp < 0
			case "<=":
				return cmp <= 0
			}
		}
	}

	return false
}

func evalLambdaBody(elemStr, varName, bodyExpr string) bool {
	bodyExpr = trimOuterParens(strings.TrimSpace(bodyExpr))
	if parts := splitTopLevelLogicalOp(bodyExpr, " OR "); len(parts) > 1 {
		for _, p := range parts {
			if evalLambdaBody(elemStr, varName, p) {
				return true
			}
		}
		return false
	}
	if parts := splitTopLevelLogicalOp(bodyExpr, " AND "); len(parts) > 1 {
		for _, p := range parts {
			if !evalLambdaBody(elemStr, varName, p) {
				return false
			}
		}
		return true
	}

	syntheticRow := map[string]any{varName: elemStr}
	return evalWhereExpr(syntheticRow, bodyExpr)
}

func evalFulltextMatch(row map[string]any, colExpr, matchOp, queryStr string) bool {
	colName := strings.Trim(colExpr, "`")
	rawVal, ok := row[colName]
	if !ok && strings.HasPrefix(colExpr, "CAST(`_doc`") {
		rawVal = resolveColumnValue(row, colExpr)
	}
	if rawVal == nil {
		return false
	}

	var haystacks []string
	switch v := rawVal.(type) {
	case string:
		haystacks = []string{strings.ToLower(v)}
	case []any:
		for _, item := range v {
			haystacks = append(haystacks, strings.ToLower(fmt.Sprintf("%v", item)))
		}
	case []string:
		for _, item := range v {
			haystacks = append(haystacks, strings.ToLower(item))
		}
	default:
		haystacks = []string{strings.ToLower(fmt.Sprintf("%v", v))}
	}
	combined := strings.Join(haystacks, " ")

	switch matchOp {
	case "MATCH_REGEXP":
		re, err := regexp.Compile("(?i)" + queryStr)
		if err != nil {
			return false
		}
		return re.MatchString(combined)
	case "MATCH_PHRASE", "MATCH_PHRASE_PREFIX":
		cleanPhrase := strings.ToLower(strings.TrimSpace(strings.Split(queryStr, "~")[0]))
		return strings.Contains(combined, cleanPhrase)
	case "MATCH_ALL":
		tokens := tokenizeWords(queryStr)
		for _, tok := range tokens {
			if !strings.Contains(combined, tok) {
				return false
			}
		}
		return len(tokens) > 0
	default: // MATCH_ANY
		tokens := tokenizeWords(queryStr)
		for _, tok := range tokens {
			if strings.Contains(combined, tok) {
				return true
			}
		}
		return false
	}
}

func tokenizeWords(s string) []string {
	var out []string
	var cur strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			cur.WriteRune(r)
		} else if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func evalNumericExpr(row map[string]any, expr string) float64 {
	expr = trimOuterParens(strings.TrimSpace(expr))
	if expr == "" {
		return 0
	}
	if f, err := strconv.ParseFloat(expr, 64); err == nil {
		return f
	}

	// Check CASE WHEN <cond> THEN <thenExpr> ELSE <elseExpr> END
	if strings.HasPrefix(expr, "CASE WHEN ") && strings.HasSuffix(expr, " END") {
		inner := expr[len("CASE WHEN ") : len(expr)-len(" END")]
		thenIdx := strings.LastIndex(inner, " THEN ")
		elseIdx := strings.LastIndex(inner, " ELSE ")
		if thenIdx > 0 && elseIdx > thenIdx {
			cond := inner[:thenIdx]
			thenExpr := inner[thenIdx+6 : elseIdx]
			elseExpr := inner[elseIdx+6:]
			if evalWhereExpr(row, cond) {
				return evalNumericExpr(row, thenExpr)
			}
			return evalNumericExpr(row, elseExpr)
		}
	}

	if strings.HasPrefix(expr, "CAST(COALESCE(") && strings.HasSuffix(expr, ", FALSE) AS INT)") {
		inner := expr[len("CAST(COALESCE(") : len(expr)-len(", FALSE) AS INT)")]
		if evalWhereExpr(row, inner) {
			return 1
		}
		return 0
	}

	// Check function calls: GREATEST(...), COALESCE(...), LOG10(...), LN(...), SQRT(...)
	for _, fn := range []string{"GREATEST", "COALESCE", "LOG10", "LN", "SQRT"} {
		if strings.HasPrefix(expr, fn+"(") && strings.HasSuffix(expr, ")") {
			inner := expr[len(fn)+1 : len(expr)-1]
			args := splitTopLevelArgs(inner)
			switch fn {
			case "GREATEST":
				maxVal := 0.0
				for i, a := range args {
					v := evalNumericExpr(row, a)
					if i == 0 || v > maxVal {
						maxVal = v
					}
				}
				return maxVal
			case "COALESCE":
				if len(args) == 2 {
					colVal := resolveColumnValue(row, strings.TrimSpace(args[0]))
					if colVal != nil {
						if f, ok := toFloat(colVal); ok {
							return f
						}
					}
					return evalNumericExpr(row, args[1])
				}
			case "LOG10":
				return math.Log10(evalNumericExpr(row, inner))
			case "LN":
				return math.Log(evalNumericExpr(row, inner))
			case "SQRT":
				return math.Sqrt(evalNumericExpr(row, inner))
			}
		}
	}

	// Check top-level `+`
	if parts := splitTopLevelBinaryMath(expr, '+'); len(parts) > 1 {
		sum := 0.0
		for _, p := range parts {
			sum += evalNumericExpr(row, p)
		}
		return sum
	}

	// Check top-level `*`
	if parts := splitTopLevelBinaryMath(expr, '*'); len(parts) > 1 {
		prod := 1.0
		for _, p := range parts {
			prod *= evalNumericExpr(row, p)
		}
		return prod
	}

	// Check top-level `/`
	if parts := splitTopLevelBinaryMath(expr, '/'); len(parts) == 2 {
		denom := evalNumericExpr(row, parts[1])
		if denom == 0 {
			return 0
		}
		return evalNumericExpr(row, parts[0]) / denom
	}

	val := resolveColumnValue(row, expr)
	if f, ok := toFloat(val); ok {
		return f
	}
	return 0
}

func resolveColumnValue(row map[string]any, colExpr string) any {
	colExpr = strings.TrimSpace(colExpr)
	if strings.HasPrefix(colExpr, "`") && strings.HasSuffix(colExpr, "`") {
		colName := strings.Trim(colExpr, "`")
		return row[colName]
	}
	if val, ok := row[colExpr]; ok {
		return val
	}
	// Check json_extract_string(_el, '$.path')
	if strings.HasPrefix(colExpr, "json_extract_string(") && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("json_extract_string(") : len(colExpr)-1]
		commaIdx := strings.IndexByte(inner, ',')
		if commaIdx > 0 {
			varName := strings.Trim(strings.TrimSpace(inner[:commaIdx]), "`")
			jsonPath := strings.TrimPrefix(unquoteSQLLiteral(strings.TrimSpace(inner[commaIdx+1:])), "$.")
			elemJSON, _ := row[varName].(string)
			return extractJSONPathFromStr(elemJSON, strings.Split(jsonPath, "."))
		}
	}
	// Check CAST(`_doc`['a']['b'] AS STRING|BIGINT|DOUBLE|BOOLEAN)
	if strings.HasPrefix(colExpr, "CAST(`_doc`") {
		asIdx := strings.LastIndex(colExpr, " AS ")
		if asIdx > 0 {
			pathPart := colExpr[len("CAST(`_doc`"):asIdx]
			var segs []string
			for _, p := range strings.Split(pathPart, "['") {
				p = strings.TrimSuffix(p, "']")
				if p != "" {
					segs = append(segs, strings.ReplaceAll(p, "''", "'"))
				}
			}
			srcStr, _ := row["_source"].(string)
			return extractJSONPathFromStr(srcStr, segs)
		}
	}
	return nil
}

func extractJSONPathFromStr(rawJSON string, path []string) any {
	if rawJSON == "" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(rawJSON))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil
	}
	var curr any = doc
	for _, seg := range path {
		switch node := curr.(type) {
		case map[string]any:
			curr = node[seg]
		case []any:
			var collected []any
			for _, elem := range node {
				if m, ok := elem.(map[string]any); ok {
					if v, exists := m[seg]; exists {
						collected = append(collected, v)
					}
				}
			}
			curr = collected
		default:
			return nil
		}
	}
	return curr
}

func extractTableNameFromDDL(ddl string) string {
	re := regexp.MustCompile("`[^`]+`\\.`([^`]+)`")
	if m := re.FindStringSubmatch(ddl); m != nil {
		return m[1]
	}
	return ""
}

func trimOuterParens(s string) string {
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		depth := 0
		inQuotes := false
		matchedAtEnd := false
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c == '\'' && (i == 0 || s[i-1] != '\\') {
				inQuotes = !inQuotes
				continue
			}
			if inQuotes {
				continue
			}
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					if i == len(s)-1 {
						matchedAtEnd = true
					}
					break
				}
			}
		}
		if matchedAtEnd {
			s = strings.TrimSpace(s[1 : len(s)-1])
		} else {
			break
		}
	}
	return s
}

func splitTopLevelLogicalOp(s, op string) []string {
	var parts []string
	depth := 0
	inQuotes := false
	lastStart := 0
	for i := 0; i <= len(s)-len(op); i++ {
		c := s[i]
		if c == '\'' && (i == 0 || s[i-1] != '\\') {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			continue
		}
		switch c {
		case '(', '[':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && s[i:i+len(op)] == op {
			parts = append(parts, s[lastStart:i])
			lastStart = i + len(op)
			i += len(op) - 1
		}
	}
	if len(parts) > 0 {
		parts = append(parts, s[lastStart:])
	}
	return parts
}

func splitTopLevelBinaryMath(s string, op byte) []string {
	var parts []string
	depth := 0
	inQuotes := false
	lastStart := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\'' && (i == 0 || s[i-1] != '\\') {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			continue
		}
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case op:
			if depth == 0 && i > 0 {
				parts = append(parts, s[lastStart:i])
				lastStart = i + 1
			}
		}
	}
	if len(parts) > 0 {
		parts = append(parts, s[lastStart:])
	}
	return parts
}

func splitTopLevelArgs(s string) []string {
	var parts []string
	depth := 0
	inQuotes := false
	lastStart := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\'' && (i == 0 || s[i-1] != '\\') {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			continue
		}
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, s[lastStart:i])
				lastStart = i + 1
			}
		}
	}
	parts = append(parts, s[lastStart:])
	return parts
}

func findTopLevelOp(s, op string) int {
	depth := 0
	inQuotes := false
	for i := 0; i <= len(s)-len(op); i++ {
		c := s[i]
		if c == '\'' && (i == 0 || s[i-1] != '\\') {
			inQuotes = !inQuotes
			continue
		}
		if inQuotes {
			continue
		}
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && s[i:i+len(op)] == op {
			if op == ">" && i > 0 && s[i-1] == '-' {
				continue // skip `->` lambda arrow
			}
			return i
		}
	}
	return -1
}

func unquoteSQLLiteral(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") && len(s) >= 2 {
		s = s[1 : len(s)-1]
		s = strings.ReplaceAll(s, "''", "'")
		s = strings.ReplaceAll(s, `\\`, `\`)
	}
	return s
}

func parseSQLLiteralValue(s string) any {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "TRUE") {
		return true
	}
	if strings.EqualFold(s, "FALSE") {
		return false
	}
	if strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") {
		return unquoteSQLLiteral(s)
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return unquoteSQLLiteral(s)
}

func evalLikePattern(val, pat string, caseInsensitive bool) bool {
	if caseInsensitive {
		val = strings.ToLower(val)
		pat = strings.ToLower(pat)
	}
	var sb strings.Builder
	sb.WriteString("^")
	escaped := false
	for _, r := range pat {
		if escaped {
			sb.WriteString(regexp.QuoteMeta(string(r)))
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '%':
			sb.WriteString(".*")
		case '_':
			sb.WriteString(".")
		default:
			sb.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	sb.WriteString("$")
	re, err := regexp.Compile("(?s)" + sb.String())
	if err != nil {
		return false
	}
	return re.MatchString(val)
}

func toStringSlice(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	default:
		return nil
	}
}

func toInt64(v any) (int64, bool) {
	switch val := v.(type) {
	case int:
		return int64(val), true
	case int64:
		return val, true
	case float64:
		return int64(val), true
	case json.Number:
		i, err := val.Int64()
		return i, err == nil
	case string:
		i, err := strconv.ParseInt(val, 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}

func toFloat(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case json.Number:
		f, err := val.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(val, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func compareFloats(a, b float64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func compareAny(a, b any) int {
	fa, aNum := toFloat(a)
	fb, bNum := toFloat(b)
	if aNum && bNum {
		return compareFloats(fa, fb)
	}
	return strings.Compare(fmt.Sprintf("%v", a), fmt.Sprintf("%v", b))
}
