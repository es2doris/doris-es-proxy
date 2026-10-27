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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// MemoryBackend is a stateful in-process Apache Doris storage & SQL execution emulator
// used for instant local quickstart demos (`--in-memory`) and deterministic E2E test suites.
// It stores shredded Stream Load JSON rows (`f__*`, `n__*`, `_doc`, `_source`, `_all_text`,
// `_id`, `_version`, `__DORIS_DELETE_SIGN__`) in Unique Key Merge-on-Write tables and evaluates
// transpiled Doris SQL (`WHERE`, `_score`, `ORDER BY`, `LIMIT/OFFSET`, `WITH base_matched AS (...)`,
// `LATERAL VIEW EXPLODE`, `array_exists`, `array_contains`, and `MATCH_*` predicates).
type MemoryBackend struct {
	mu       sync.RWMutex
	logSQL   bool
	ddls     []string
	hitsSQLs []string
	aggsSQLs []string
	tables   map[string]map[string]map[string]any // table -> _id -> shredded row map
	catalog  map[string]CatalogEntry              // entityType+":"+entityKey -> CatalogEntry
}

func NewMemoryBackend(logSQL bool) *MemoryBackend {
	return &MemoryBackend{
		logSQL:  logSQL,
		tables:  make(map[string]map[string]map[string]any),
		catalog: make(map[string]CatalogEntry),
	}
}

func (m *MemoryBackend) InitCatalog(_ context.Context, _ string) error {
	return nil
}

func (m *MemoryBackend) UpsertCatalogEntry(_ context.Context, _ string, entry CatalogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.catalog[entry.EntityType+":"+entry.EntityKey] = entry
	return nil
}

func (m *MemoryBackend) DeleteCatalogEntry(_ context.Context, _, entityType, entityKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.catalog, entityType+":"+entityKey)
	return nil
}

func (m *MemoryBackend) LoadCatalogEntries(_ context.Context, _ string) ([]CatalogEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]CatalogEntry, 0, len(m.catalog))
	for _, e := range m.catalog {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedEpochMs != out[j].UpdatedEpochMs {
			return out[i].UpdatedEpochMs < out[j].UpdatedEpochMs
		}
		return out[i].EntityKey < out[j].EntityKey
	})
	return out, nil
}

func (m *MemoryBackend) ExecDDL(_ context.Context, ddl string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ddls = append(m.ddls, ddl)
	if m.logSQL {
		log.Printf("[Doris DDL]\n%s", ddl)
	}

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

func (m *MemoryBackend) StreamLoad(_ context.Context, table string, ndjson []byte, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tables[table] == nil {
		m.tables[table] = make(map[string]map[string]any)
	}
	scanner := bufio.NewScanner(bytes.NewReader(ndjson))
	scanner.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	rowsLoaded := 0
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
		newVer, _ := toInt64(row["_version"])
		if existing, ok := m.tables[table][id]; ok {
			if curVer, ok := toInt64(existing["_version"]); ok && newVer > 0 && newVer < curVer {
				continue
			}
		}
		delSign, _ := toInt64(row["__DORIS_DELETE_SIGN__"])
		if delSign == 1 {
			delete(m.tables[table], id)
		} else {
			m.tables[table][id] = row
		}
		rowsLoaded++
	}
	if m.logSQL {
		// #nosec G706 -- table name is sanitized and only logged when --log-sql is enabled
		log.Printf("[Doris Stream Load] table=%s rows=%d merge_type=MERGE", table, rowsLoaded)
	}
	return scanner.Err()
}

func (m *MemoryBackend) Ping(_ context.Context) error {
	return nil
}

func (m *MemoryBackend) GetDocByID(_ context.Context, _, table, id string) (*HitRow, bool, error) {
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
	return &HitRow{
		ID:      id,
		Version: ver,
		Source:  json.RawMessage(srcStr),
		Score:   1.0,
	}, true, nil
}

func (m *MemoryBackend) GetDocsByIDs(_ context.Context, _, table string, ids []string) (map[string]HitRow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]HitRow, len(ids))
	tbl := m.tables[table]
	if tbl == nil {
		return out, nil
	}
	for _, id := range ids {
		if row, ok := tbl[id]; ok {
			ver, _ := toInt64(row["_version"])
			srcStr, _ := row["_source"].(string)
			out[id] = HitRow{
				ID:      id,
				Version: ver,
				Source:  json.RawMessage(srcStr),
				Score:   1.0,
			}
		}
	}
	return out, nil
}

var (
	reHitsSQL          = regexp.MustCompile(`(?s)^SELECT ` + "`_id`, `_version`, `_source`, CAST\\((.+) AS DOUBLE\\) AS `_score`, (COUNT\\(\\*\\) OVER\\(\\)|CAST\\(-1 AS BIGINT\\)) AS `_total_hits` FROM `[^`]+`\\.`([^`]+)` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (.+) ORDER BY (.+) LIMIT (\\d+) OFFSET (\\d+)$")
	reCollapsedHitsSQL = regexp.MustCompile(`(?s)^SELECT ` + "`_id`, `_version`, `_source`, `_score`, `_total_hits` FROM \\(SELECT \\*, ROW_NUMBER\\(\\) OVER \\(PARTITION BY (.+?) ORDER BY .+\\) AS `_collapse_rn` FROM \\(SELECT \\*, CAST\\((.+) AS DOUBLE\\) AS `_score`, (COUNT\\(\\*\\) OVER\\(\\)|CAST\\(-1 AS BIGINT\\)) AS `_total_hits` FROM `[^`]+`\\.`([^`]+)` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (.+)\\) `_scored`\\) `_collapsed` WHERE `_collapse_rn` = 1 ORDER BY (.+) LIMIT (\\d+) OFFSET (\\d+)$")
	reCTEBase          = regexp.MustCompile(`(?s)^WITH ` + "`base_matched` AS \\(SELECT \\* FROM `[^`]+`\\.`([^`]+)` WHERE `__DORIS_DELETE_SIGN__` = 0 AND \\((.+?)\\)\\)\n(.+)$")
)

func parseOrderSpec(spec string) (colExpr string, desc bool) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return "", false
	}
	upper := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(upper, " DESC"):
		return strings.TrimSpace(s[:len(s)-5]), true
	case strings.HasSuffix(upper, " ASC"):
		return strings.TrimSpace(s[:len(s)-4]), false
	default:
		return s, false
	}
}

func splitHitsWhereBody(whereBody string) (mainWhere, postWhere string) {
	parts := splitTopLevelLogicalOp(strings.TrimSpace(whereBody), " AND ")
	if len(parts) == 0 {
		return "TRUE", "TRUE"
	}
	if len(parts) == 1 {
		return parts[0], "TRUE"
	}
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return strings.Join(parts[:len(parts)-1], " AND "), parts[len(parts)-1]
}

func (m *MemoryBackend) QueryHits(_ context.Context, sqlStr string) ([]HitRow, error) {
	m.mu.Lock()
	m.hitsSQLs = append(m.hitsSQLs, sqlStr)
	logSQL := m.logSQL
	m.mu.Unlock()

	if logSQL {
		log.Printf("[Doris HitsSQL]\n%s", sqlStr)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var scoreExpr, totalExpr, collapseCol, tableName, mainWhere, postWhere, orderByClause string
	var limit, offset int
	if sub := reHitsSQL.FindStringSubmatch(sqlStr); sub != nil {
		scoreExpr = sub[1]
		totalExpr = sub[2]
		tableName = sub[3]
		mainWhere, postWhere = splitHitsWhereBody(sub[4])
		orderByClause = sub[5]
		limit, _ = strconv.Atoi(sub[6])
		offset, _ = strconv.Atoi(sub[7])
	} else if csub := reCollapsedHitsSQL.FindStringSubmatch(sqlStr); csub != nil {
		collapseCol = csub[1]
		scoreExpr = csub[2]
		totalExpr = csub[3]
		tableName = csub[4]
		mainWhere, postWhere = splitHitsWhereBody(csub[5])
		orderByClause = csub[6]
		limit, _ = strconv.Atoi(csub[7])
		offset, _ = strconv.Atoi(csub[8])
	} else {
		return nil, fmt.Errorf("unrecognized HitsSQL format: %s", sqlStr)
	}

	tbl := m.tables[tableName]
	var matchedRows []map[string]any
	var hits []HitRow

	for _, row := range tbl {
		if evalWhereExpr(row, mainWhere) && evalWhereExpr(row, postWhere) {
			score := evalNumericExpr(row, scoreExpr)
			ver, _ := toInt64(row["_version"])
			srcStr, _ := row["_source"].(string)
			matchedRows = append(matchedRows, row)
			hits = append(hits, HitRow{
				ID:      fmt.Sprintf("%v", row["_id"]),
				Version: ver,
				Source:  json.RawMessage(srcStr),
				Score:   score,
			})
		}
	}

	totalHits := int64(len(hits))
	if strings.Contains(totalExpr, "-1") {
		totalHits = -1
	}
	for i := range hits {
		hits[i].TotalHits = totalHits
	}

	sortIdx := make([]int, len(hits))
	for i := range sortIdx {
		sortIdx[i] = i
	}
	orderSpecs := splitTopLevelArgs(orderByClause)
	sort.SliceStable(sortIdx, func(a, b int) bool {
		ia, ib := sortIdx[a], sortIdx[b]
		for _, spec := range orderSpecs {
			colExpr, desc := parseOrderSpec(spec)
			if colExpr == "" {
				continue
			}
			var cmp int
			switch colExpr {
			case "`_score`":
				cmp = compareFloats(hits[ia].Score, hits[ib].Score)
			case "`_id`":
				cmp = strings.Compare(hits[ia].ID, hits[ib].ID)
			default:
				va := resolveColumnValue(matchedRows[ia], colExpr)
				vb := resolveColumnValue(matchedRows[ib], colExpr)
				if va == nil && vb == nil {
					continue
				}
				if va == nil {
					return false
				}
				if vb == nil {
					return true
				}
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

	sortedHits := make([]HitRow, 0, len(hits))
	seenCollapse := make(map[string]bool)
	for _, idx := range sortIdx {
		if collapseCol != "" {
			cVal := resolveColumnValue(matchedRows[idx], collapseCol)
			cKey := fmt.Sprintf("%v", cVal)
			if seenCollapse[cKey] {
				continue
			}
			seenCollapse[cKey] = true
		}
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

func (m *MemoryBackend) QueryAggs(_ context.Context, sqlStr string) ([]AggRow, error) {
	m.mu.Lock()
	m.aggsSQLs = append(m.aggsSQLs, sqlStr)
	logSQL := m.logSQL
	m.mu.Unlock()

	if logSQL {
		log.Printf("[Doris AggsSQL (Nereids Multi-Cast CTE)]\n%s", sqlStr)
	}

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

	var out []AggRow
	for _, branch := range unionBranches {
		branch = strings.TrimSpace(branch)
		rows := evalAggBranch(baseRows, branch)
		out = append(out, rows...)
	}
	return out, nil
}

var (
	reAggArrayExplode        = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CAST\\(`_elem` AS STRING\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_t` AS `_elem` WHERE (?:\\((.+?)\\) AND )?`_elem` IS NOT NULL GROUP BY `_elem` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggArrayExplodeMissing = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, COALESCE\\(CAST\\(`_elem` AS STRING\\), ('(?:''|[^'])*')\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(CASE WHEN `([^`]+)` IS NULL.+?\\) `_t` AS `_elem`(?: WHERE (.+?))? GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggScalarTerms         = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CAST\\((.+?) AS STRING\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (?:\\((.+?)\\) AND )?.+? IS NOT NULL GROUP BY .+? ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggScalarTermsMissing  = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, COALESCE\\(CAST\\((.+?) AS STRING\\), ('(?:''|[^'])*')\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+?))? GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggNestedTerms         = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, json_extract_string\\(`_nel`, '\\$\\.([^']+)'\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_nt` AS `_nel` WHERE (?:\\((.+?)\\) AND )?json_extract_string\\(`_nel`, '\\$\\.[^']+'\\) IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggNestedTermsMissing  = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, COALESCE\\(json_extract_string\\(`_nel`, '\\$\\.([^']+)'\\), ('(?:''|[^'])*')\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(CASE WHEN `([^`]+)` IS NULL.+?\\) `_nt` AS `_nel`(?: WHERE (.+?))? GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggNestedMetric        = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '(_metric|_stats_[a-z]+)' AS `_bucket_key`, CAST\\((?:COALESCE\\((AVG|SUM|MIN|MAX|COUNT)\\((.+?)\\), 0\\)|(COUNT)\\((DISTINCT )?(.+?)\\)) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_nt` AS `_nel`(?: WHERE (.+))?$")
	reAggFilter             = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_filter' AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (.+)$")
	reAggMissing            = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_missing' AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (?:\\((.+?)\\) AND )?NOT \\((.+)\\)$")
	reAggCardArray          = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COUNT\\(DISTINCT `_elem`\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_t` AS `_elem` WHERE (?:\\((.+?)\\) AND )?`_elem` IS NOT NULL$")
	reAggCardScalar         = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COUNT\\(DISTINCT (.+?)\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
	reAggValueCountArray    = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COUNT\\(`_elem`\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_t` AS `_elem` WHERE (?:\\((.+?)\\) AND )?`_elem` IS NOT NULL$")
	reAggValueCountScalar   = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COUNT\\((.+?)\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
	reAggMetric             = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '(_metric|_stats_[a-z]+)' AS `_bucket_key`, CAST\\(COALESCE\\((AVG|SUM|MIN|MAX|COUNT)\\((.+?)\\), 0\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
	reAggPercentile         = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '([^']+)' AS `_bucket_key`, CAST\\(COALESCE\\(PERCENTILE_APPROX\\((.+?), ([0-9.]+)\\), 0\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
	reAggDateHist           = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CAST\\(CAST\\(FLOOR\\((.+?) / (\\d+)\\) \\* \\d+ AS BIGINT\\) AS STRING\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (?:\\((.+?)\\) AND )?.+? IS NOT NULL GROUP BY `_bucket_key` ORDER BY CAST\\(`_bucket_key` AS BIGINT\\) ASC")
	reAggHist               = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CAST\\(FLOOR\\(\\((.+?) - ([^)]+)\\) / ([^)]+)\\) \\* [^)]+ \\+ [^)]+ AS STRING\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (?:\\((.+?)\\) AND )?.+? IS NOT NULL GROUP BY `_bucket_key` ORDER BY CAST\\(`_bucket_key` AS DOUBLE\\) ASC")
	reAggRange              = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '([^']+)' AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (.+)$")
	reAggSubMetric          = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, (.+?) AS `_bucket_key`, CAST\\((?:COALESCE\\((AVG|SUM|MIN|MAX)\\((.+?)\\), 0\\)|(COUNT)\\((DISTINCT )?(.+?)\\)) AS DOUBLE\\) AS `_doc_count` FROM (.+?) WHERE (.+) GROUP BY `_bucket_key`$")
	reAggSubTerms           = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CONCAT\\((.+?), '\\\\x1f', CAST\\((.+?) AS STRING\\)\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM (.+?) WHERE \\((.+)\\) AND .+? IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC")
	reAggTopHits            = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, `_id` AS `_bucket_key`, CAST\\(1 AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+?))? ORDER BY (.+?) LIMIT (\\d+)")
	reAggSubTopHits         = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CONCAT\\((.+?), '\\\\x1f', `_id`\\) AS `_bucket_key`, CAST\\(ROW_NUMBER\\(\\) OVER \\(PARTITION BY .+? ORDER BY (.+?)\\) AS DOUBLE\\) AS `_doc_count` FROM (.+?) WHERE (.+)\\) `_agg_sub_\\d+` WHERE `_doc_count` <= (\\d+)")
	reAggComposite          = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, (.+?) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (.+?) GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT (\\d+)")
)

func evalAggBranch(baseRows []map[string]any, branch string) []AggRow {
	if strings.Contains(branch, "'__meta_total'") {
		var cnt int64
		if idx := strings.Index(branch, " FROM `base_matched` WHERE "); idx >= 0 {
			extraWhere := strings.TrimSpace(branch[idx+len(" FROM `base_matched` WHERE "):])
			for _, row := range baseRows {
				if evalWhereExpr(row, extraWhere) {
					cnt++
				}
			}
		} else {
			cnt = int64(len(baseRows))
		}
		return []AggRow{{AggName: "__meta_total", BucketKey: "_count", DocCount: cnt, Value: float64(cnt)}}
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

	if m := reAggArrayExplodeMissing.FindStringSubmatch(branch); m != nil {
		aggName, missingLit, arrCol, extraWhere := m[1], m[2], m[3], m[4]
		missingVal := unquoteSQLLiteral(missingLit)
		limit, _ := strconv.Atoi(m[5])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			elems := toStringSlice(row[arrCol])
			added := false
			for _, elem := range elems {
				if elem != "" {
					counts[elem]++
					added = true
				}
			}
			if !added && missingVal != "" {
				counts[missingVal]++
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

	if m := reAggNestedTermsMissing.FindStringSubmatch(branch); m != nil {
		aggName, relPath, missingLit, corrCol, extraWhere := m[1], m[2], m[3], m[4], m[5]
		missingVal := unquoteSQLLiteral(missingLit)
		limit, _ := strconv.Atoi(m[6])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			elems := toStringSlice(row[corrCol])
			if len(elems) == 0 {
				if missingVal != "" {
					counts[missingVal]++
				}
				continue
			}
			for _, elemJSON := range elems {
				val := extractJSONPathFromStr(elemJSON, strings.Split(relPath, "."))
				if val == nil {
					if missingVal != "" {
						counts[missingVal]++
					}
					continue
				}
				s := fmt.Sprintf("%v", val)
				if s == "" {
					s = missingVal
				}
				if s != "" {
					counts[s]++
				}
			}
		}
		return topBuckets(aggName, counts, limit)
	}

	if m := reAggNestedMetric.FindStringSubmatch(branch); m != nil {
		aggName, bKey := m[1], m[2]
		fn := m[3]
		colExpr := m[4]
		isDistinct := m[6] != ""
		if fn == "" {
			fn = m[5]
			colExpr = m[7]
		}
		corrCol, extraWhere := m[8], m[9]
		expanded := expandFromClauseRows(baseRows, fmt.Sprintf("LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel`", corrCol), extraWhere)
		var nums []float64
		seen := make(map[string]bool)
		var cnt int64
		for _, row := range expanded {
			val := resolveColumnValue(row, colExpr)
			if val == nil {
				continue
			}
			cnt++
			seen[fmt.Sprintf("%v", val)] = true
			if f, ok := toFloat(val); ok {
				nums = append(nums, f)
			}
		}
		var res float64
		switch fn {
		case "COUNT":
			if isDistinct {
				res = float64(len(seen))
			} else {
				res = float64(cnt)
			}
		case "SUM":
			for _, v := range nums {
				res += v
			}
		case "AVG":
			if len(nums) > 0 {
				for _, v := range nums {
					res += v
				}
				res /= float64(len(nums))
			}
		case "MIN":
			if len(nums) > 0 {
				res = nums[0]
				for _, v := range nums[1:] {
					if v < res {
						res = v
					}
				}
			}
		case "MAX":
			if len(nums) > 0 {
				res = nums[0]
				for _, v := range nums[1:] {
					if v > res {
						res = v
					}
				}
			}
		}
		return []AggRow{{AggName: aggName, BucketKey: bKey, DocCount: int64(res), Value: res}}
	}

	if m := reAggScalarTermsMissing.FindStringSubmatch(branch); m != nil {
		aggName, colExpr, missingLit, extraWhere := m[1], m[2], m[3], m[4]
		missingVal := unquoteSQLLiteral(missingLit)
		limit, _ := strconv.Atoi(m[5])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			val := resolveColumnValue(row, colExpr)
			s := ""
			if val != nil {
				s = fmt.Sprintf("%v", val)
			}
			if s == "" {
				s = missingVal
			}
			if s != "" {
				counts[s]++
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
		return []AggRow{{AggName: aggName, BucketKey: "_filter", DocCount: cnt, Value: float64(cnt)}}
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
		return []AggRow{{AggName: aggName, BucketKey: "_missing", DocCount: cnt, Value: float64(cnt)}}
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
		return []AggRow{{AggName: aggName, BucketKey: "_metric", DocCount: cnt, Value: float64(cnt)}}
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
		return []AggRow{{AggName: aggName, BucketKey: "_metric", DocCount: cnt, Value: float64(cnt)}}
	}

	if m := reAggValueCountArray.FindStringSubmatch(branch); m != nil {
		aggName, arrCol, extraWhere := m[1], m[2], m[3]
		var cnt int64
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			for _, elem := range toStringSlice(row[arrCol]) {
				if elem != "" {
					cnt++
				}
			}
		}
		return []AggRow{{AggName: aggName, BucketKey: "_metric", DocCount: cnt, Value: float64(cnt)}}
	}

	if m := reAggValueCountScalar.FindStringSubmatch(branch); m != nil {
		aggName, colExpr, extraWhere := m[1], m[2], m[3]
		var cnt int64
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			if val := resolveColumnValue(row, colExpr); val != nil {
				cnt++
			}
		}
		return []AggRow{{AggName: aggName, BucketKey: "_metric", DocCount: cnt, Value: float64(cnt)}}
	}

	if m := reAggMetric.FindStringSubmatch(branch); m != nil {
		aggName, bKey, fn, colExpr, extraWhere := m[1], m[2], m[3], m[4], m[5]
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
			case "COUNT":
				res = float64(len(nums))
			}
		}
		return []AggRow{{AggName: aggName, BucketKey: bKey, DocCount: int64(res), Value: res}}
	}

	if m := reAggPercentile.FindStringSubmatch(branch); m != nil {
		aggName, pctKey, colExpr, qStr, extraWhere := m[1], m[2], m[3], m[4], m[5]
		q, _ := strconv.ParseFloat(qStr, 64)
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
		sort.Float64s(nums)
		var res float64
		if len(nums) > 0 {
			pos := q * float64(len(nums)-1)
			lower := int(math.Floor(pos))
			upper := int(math.Ceil(pos))
			if lower == upper || upper >= len(nums) {
				res = nums[lower]
			} else {
				weight := pos - float64(lower)
				res = nums[lower]*(1-weight) + nums[upper]*weight
			}
		}
		return []AggRow{{AggName: aggName, BucketKey: pctKey, DocCount: int64(res), Value: res}}
	}

	if m := reAggDateHist.FindStringSubmatch(branch); m != nil {
		aggName, colExpr, intervalStr, extraWhere := m[1], m[2], m[3], m[4]
		intervalMs, _ := strconv.ParseInt(intervalStr, 10, 64)
		if intervalMs <= 0 {
			intervalMs = 86400000
		}
		counts := make(map[int64]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			if val := resolveColumnValue(row, colExpr); val != nil {
				if ts, ok := toInt64(val); ok {
					b := (ts / intervalMs) * intervalMs
					counts[b]++
				}
			}
		}
		keys := make([]int64, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		rows := make([]AggRow, 0, len(keys))
		for _, k := range keys {
			rows = append(rows, AggRow{
				AggName:   aggName,
				BucketKey: strconv.FormatInt(k, 10),
				DocCount:  counts[k],
				Value:     float64(counts[k]),
			})
		}
		return rows
	}

	if m := reAggHist.FindStringSubmatch(branch); m != nil {
		aggName, colExpr, offsetStr, intervalStr, extraWhere := m[1], m[2], m[3], m[4], m[5]
		offset, _ := strconv.ParseFloat(offsetStr, 64)
		interval, _ := strconv.ParseFloat(intervalStr, 64)
		if interval <= 0 {
			interval = 1.0
		}
		counts := make(map[float64]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			if val := resolveColumnValue(row, colExpr); val != nil {
				if f, ok := toFloat(val); ok {
					b := math.Floor((f-offset)/interval)*interval + offset
					counts[b]++
				}
			}
		}
		keys := make([]float64, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Float64s(keys)
		rows := make([]AggRow, 0, len(keys))
		for _, k := range keys {
			rows = append(rows, AggRow{
				AggName:   aggName,
				BucketKey: strconv.FormatFloat(k, 'f', -1, 64),
				DocCount:  counts[k],
				Value:     float64(counts[k]),
			})
		}
		return rows
	}

	if m := reAggTopHits.FindStringSubmatch(branch); m != nil {
		aggName, extraWhere, orderByClause, limitStr := m[1], m[2], m[3], m[4]
		limit, _ := strconv.Atoi(limitStr)
		var rows []map[string]any
		for _, r := range baseRows {
			if extraWhere != "" && !evalWhereExpr(r, extraWhere) {
				continue
			}
			rows = append(rows, r)
		}
		sortRowsByOrderClause(rows, orderByClause)
		if limit > 0 && len(rows) > limit {
			rows = rows[:limit]
		}
		var out []AggRow
		for i, r := range rows {
			out = append(out, AggRow{
				AggName:   aggName,
				BucketKey: fmt.Sprintf("%v", r["_id"]),
				DocCount:  int64(i + 1),
				Value:     float64(i + 1),
			})
		}
		return out
	}

	if m := reAggSubTopHits.FindStringSubmatch(branch); m != nil {
		aggName, parentBucketExpr, orderByClause, fromClause, whereClause, limitStr := m[1], m[2], m[3], m[4], m[5], m[6]
		limit, _ := strconv.Atoi(limitStr)
		expanded := expandFromClauseRows(baseRows, fromClause, whereClause)
		byBucket := make(map[string][]map[string]any)
		var bucketOrder []string
		for _, row := range expanded {
			bKey := evalBucketKeyExpr(row, parentBucketExpr)
			if bKey == "" {
				continue
			}
			if _, exists := byBucket[bKey]; !exists {
				bucketOrder = append(bucketOrder, bKey)
			}
			byBucket[bKey] = append(byBucket[bKey], row)
		}
		sort.Strings(bucketOrder)
		var out []AggRow
		for _, bKey := range bucketOrder {
			rows := byBucket[bKey]
			sortRowsByOrderClause(rows, orderByClause)
			if limit > 0 && len(rows) > limit {
				rows = rows[:limit]
			}
			for i, r := range rows {
				out = append(out, AggRow{
					AggName:   aggName,
					BucketKey: bKey + "\x1f" + fmt.Sprintf("%v", r["_id"]),
					DocCount:  int64(i + 1),
					Value:     float64(i + 1),
				})
			}
		}
		return out
	}

	if m := reAggComposite.FindStringSubmatch(branch); m != nil {
		aggName, bucketKeyExpr, whereClause, limitStr := m[1], m[2], m[3], m[4]
		limit, _ := strconv.Atoi(limitStr)
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if whereClause != "" && !evalWhereExpr(row, whereClause) {
				continue
			}
			bKey := evalCompositeKeyExpr(row, bucketKeyExpr)
			if bKey != "" {
				counts[bKey]++
			}
		}
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if limit > 0 && len(keys) > limit {
			keys = keys[:limit]
		}
		var out []AggRow
		for _, k := range keys {
			out = append(out, AggRow{
				AggName:   aggName,
				BucketKey: k,
				DocCount:  counts[k],
				Value:     float64(counts[k]),
			})
		}
		return out
	}

	if m := reAggSubTerms.FindStringSubmatch(branch); m != nil {
		aggName, parentBucketExpr, childColExpr, fromClause, whereClause := m[1], m[2], m[3], m[4], m[5]
		expanded := expandFromClauseRows(baseRows, fromClause, whereClause)
		counts := make(map[string]int64)
		for _, row := range expanded {
			pKey := evalBucketKeyExpr(row, parentBucketExpr)
			if pKey == "" {
				continue
			}
			cVal := resolveColumnValue(row, childColExpr)
			if cVal == nil {
				continue
			}
			cStr := fmt.Sprintf("%v", cVal)
			if cStr != "" {
				counts[pKey+"\x1f"+cStr]++
			}
		}
		return topBuckets(aggName, counts, 0)
	}

	if m := reAggSubMetric.FindStringSubmatch(branch); m != nil {
		aggName, parentBucketExpr := m[1], m[2]
		fn := m[3]
		colExpr := m[4]
		isDistinct := m[6] != ""
		if fn == "" {
			fn = m[5]
			colExpr = m[7]
		}
		fromClause, whereClause := m[8], m[9]
		expanded := expandFromClauseRows(baseRows, fromClause, whereClause)

		type bucketAcc struct {
			nums []float64
			cnt  int64
			seen map[string]bool
		}
		byBucket := make(map[string]*bucketAcc)
		var bucketOrder []string

		for _, row := range expanded {
			bKey := evalBucketKeyExpr(row, parentBucketExpr)
			if bKey == "" {
				continue
			}
			acc, exists := byBucket[bKey]
			if !exists {
				acc = &bucketAcc{seen: make(map[string]bool)}
				byBucket[bKey] = acc
				bucketOrder = append(bucketOrder, bKey)
			}
			val := resolveColumnValue(row, colExpr)
			if val == nil {
				continue
			}
			acc.cnt++
			acc.seen[fmt.Sprintf("%v", val)] = true
			if f, ok := toFloat(val); ok {
				acc.nums = append(acc.nums, f)
			}
		}

		sort.Strings(bucketOrder)
		var out []AggRow
		for _, bKey := range bucketOrder {
			acc := byBucket[bKey]
			var res float64
			switch fn {
			case "COUNT":
				if isDistinct {
					res = float64(len(acc.seen))
				} else {
					res = float64(acc.cnt)
				}
			case "SUM":
				for _, v := range acc.nums {
					res += v
				}
			case "AVG":
				if len(acc.nums) > 0 {
					for _, v := range acc.nums {
						res += v
					}
					res /= float64(len(acc.nums))
				}
			case "MIN":
				if len(acc.nums) > 0 {
					res = acc.nums[0]
					for _, v := range acc.nums[1:] {
						if v < res {
							res = v
						}
					}
				}
			case "MAX":
				if len(acc.nums) > 0 {
					res = acc.nums[0]
					for _, v := range acc.nums[1:] {
						if v > res {
							res = v
						}
					}
				}
			}
			out = append(out, AggRow{
				AggName:   aggName,
				BucketKey: bKey,
				DocCount:  int64(res),
				Value:     res,
			})
		}
		return out
	}

	if m := reAggRange.FindStringSubmatch(branch); m != nil {
		aggName, bkey, rangeWhere := m[1], m[2], m[3]
		if bkey != "_filter" && bkey != "_missing" && bkey != "_metric" && bkey != "_count" {
			var cnt int64
			for _, row := range baseRows {
				if evalWhereExpr(row, rangeWhere) {
					cnt++
				}
			}
			return []AggRow{{AggName: aggName, BucketKey: bkey, DocCount: cnt, Value: float64(cnt)}}
		}
	}

	return nil
}

func sortRowsByOrderClause(rows []map[string]any, orderByClause string) {
	orderSpecs := splitTopLevelArgs(orderByClause)
	sort.SliceStable(rows, func(i, j int) bool {
		for _, spec := range orderSpecs {
			colExpr, desc := parseOrderSpec(spec)
			if colExpr == "" {
				continue
			}
			var cmp int
			if colExpr == "`_id`" || colExpr == "`_score`" {
				cmp = strings.Compare(fmt.Sprintf("%v", rows[i]["_id"]), fmt.Sprintf("%v", rows[j]["_id"]))
			} else {
				va := resolveColumnValue(rows[i], colExpr)
				vb := resolveColumnValue(rows[j], colExpr)
				if va == nil && vb == nil {
					continue
				}
				if va == nil {
					return false
				}
				if vb == nil {
					return true
				}
				cmp = compareAny(va, vb)
			}
			if cmp != 0 {
				if desc {
					return cmp > 0
				}
				return cmp < 0
			}
		}
		return false
	})
}

func evalCompositeKeyExpr(row map[string]any, expr string) string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "CONCAT_WS('\\x1f', ") && strings.HasSuffix(expr, ")") {
		inner := expr[len("CONCAT_WS('\\x1f', ") : len(expr)-1]
		args := splitTopLevelArgs(inner)
		parts := make([]string, 0, len(args))
		for _, a := range args {
			p := evalBucketKeyExpr(row, a)
			if p == "" {
				return ""
			}
			parts = append(parts, p)
		}
		return strings.Join(parts, "\x1f")
	}
	return evalBucketKeyExpr(row, expr)
}

var reLateralViewExplode = regexp.MustCompile("LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `[^`]+` AS `([^`]+)`")

func expandFromClauseRows(baseRows []map[string]any, fromClause, whereClause string) []map[string]any {
	explodes := reLateralViewExplode.FindAllStringSubmatch(fromClause, -1)
	currRows := baseRows
	for _, m := range explodes {
		explodeCol, aliasName := m[1], m[2]
		var nextRows []map[string]any
		for _, row := range currRows {
			for _, elem := range toStringSlice(row[explodeCol]) {
				cp := make(map[string]any, len(row)+1)
				for k, v := range row {
					cp[k] = v
				}
				cp[aliasName] = elem
				nextRows = append(nextRows, cp)
			}
		}
		currRows = nextRows
	}
	var out []map[string]any
	for _, row := range currRows {
		if evalWhereExpr(row, whereClause) {
			out = append(out, row)
		}
	}
	return out
}

var (
	reBucketDateHist = regexp.MustCompile(`^CAST\(CAST\(FLOOR\((.+?) / (\d+)\) \* \d+ AS BIGINT\) AS STRING\)$`)
	reBucketHist     = regexp.MustCompile(`^CAST\(FLOOR\(\((.+?) - ([^)]+)\) / ([^)]+)\) \* [^)]+ \+ [^)]+ AS STRING\)$`)
)

func evalBucketKeyExpr(row map[string]any, expr string) string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "'") && strings.HasSuffix(expr, "'") {
		return unquoteSQLLiteral(expr)
	}
	if m := reBucketDateHist.FindStringSubmatch(expr); m != nil {
		colExpr, intervalStr := m[1], m[2]
		intervalMs, _ := strconv.ParseInt(intervalStr, 10, 64)
		if intervalMs <= 0 {
			intervalMs = 86400000
		}
		if val := resolveColumnValue(row, colExpr); val != nil {
			if ts, ok := toInt64(val); ok {
				return strconv.FormatInt((ts/intervalMs)*intervalMs, 10)
			}
		}
		return ""
	}
	if m := reBucketHist.FindStringSubmatch(expr); m != nil {
		colExpr, offsetStr, intervalStr := m[1], m[2], m[3]
		offset, _ := strconv.ParseFloat(offsetStr, 64)
		interval, _ := strconv.ParseFloat(intervalStr, 64)
		if interval <= 0 {
			interval = 1.0
		}
		if val := resolveColumnValue(row, colExpr); val != nil {
			if f, ok := toFloat(val); ok {
				b := math.Floor((f-offset)/interval)*interval + offset
				return strconv.FormatFloat(b, 'f', -1, 64)
			}
		}
		return ""
	}
	if strings.HasPrefix(expr, "COALESCE(CAST(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("COALESCE(") : len(expr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 2 {
			v := evalBucketKeyExpr(row, args[0])
			if v != "" {
				return v
			}
			return unquoteSQLLiteral(strings.TrimSpace(args[1]))
		}
	}
	if strings.HasPrefix(expr, "CAST(") && strings.HasSuffix(expr, " AS STRING)") {
		inner := expr[len("CAST:") : len(expr)-len(" AS STRING)")]
		if strings.HasPrefix(expr, "CAST(") {
			inner = expr[len("CAST(") : len(expr)-len(" AS STRING)")]
		}
		val := resolveColumnValue(row, inner)
		if val == nil {
			return ""
		}
		return fmt.Sprintf("%v", val)
	}
	val := resolveColumnValue(row, expr)
	if val == nil {
		return ""
	}
	return fmt.Sprintf("%v", val)
}

func topBuckets(aggName string, counts map[string]int64, limit int) []AggRow {
	rows := make([]AggRow, 0, len(counts))
	for k, c := range counts {
		rows = append(rows, AggRow{
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

	if parts := splitTopLevelLogicalOp(expr, " OR "); len(parts) > 1 {
		for _, p := range parts {
			if evalWhereExpr(row, p) {
				return true
			}
		}
		return false
	}

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

	if strings.HasPrefix(expr, "arrays_overlap(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("arrays_overlap(") : len(expr)-1]
		brackIdx := strings.IndexByte(inner, '[')
		if brackIdx > 0 {
			colName := strings.Trim(strings.TrimSpace(inner[:strings.IndexByte(inner, ',')]), "`")
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

	if strings.HasPrefix(expr, "array_size(") && strings.HasSuffix(expr, ") > 0") {
		colName := strings.Trim(strings.TrimSpace(expr[len("array_size("):len(expr)-len(") > 0")]), "`")
		return len(toStringSlice(row[colName])) > 0
	}

	if strings.HasSuffix(expr, " IS NOT NULL") {
		colExpr := strings.TrimSpace(expr[:len(expr)-len(" IS NOT NULL")])
		val := resolveColumnValue(row, colExpr)
		return val != nil
	}
	if strings.HasSuffix(expr, " IS NULL") {
		colExpr := strings.TrimSpace(expr[:len(expr)-len(" IS NULL")])
		val := resolveColumnValue(row, colExpr)
		return val == nil
	}

	for _, matchOp := range []string{" MATCH_PHRASE_PREFIX ", " MATCH_PHRASE ", " MATCH_REGEXP ", " MATCH_ALL ", " MATCH_ANY "} {
		if idx := strings.Index(expr, matchOp); idx > 0 {
			colExpr := strings.TrimSpace(expr[:idx])
			lit := unquoteSQLLiteral(strings.TrimSpace(expr[idx+len(matchOp):]))
			return evalFulltextMatch(row, colExpr, strings.TrimSpace(matchOp), lit)
		}
	}

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
	if !ok {
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
	case "MATCH_PHRASE":
		parts := strings.SplitN(queryStr, "~", 2)
		cleanPhrase := strings.ToLower(strings.TrimSpace(parts[0]))
		slop := 0
		if len(parts) == 2 {
			slop, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		}
		if strings.Contains(combined, cleanPhrase) {
			return true
		}
		if slop > 0 {
			phraseTokens := tokenizeWords(cleanPhrase)
			docTokens := tokenizeWords(combined)
			return matchPhraseWithSlop(docTokens, phraseTokens, slop)
		}
		return false
	case "MATCH_PHRASE_PREFIX":
		cleanPhrase := strings.ToLower(strings.TrimSpace(strings.Split(queryStr, "~")[0]))
		if strings.Contains(combined, cleanPhrase) {
			return true
		}
		phraseTokens := tokenizeWords(cleanPhrase)
		docTokens := tokenizeWords(combined)
		if len(phraseTokens) == 0 || len(docTokens) < len(phraseTokens) {
			return false
		}
		for i := 0; i <= len(docTokens)-len(phraseTokens); i++ {
			matched := true
			for j := 0; j < len(phraseTokens)-1; j++ {
				if docTokens[i+j] != phraseTokens[j] {
					matched = false
					break
				}
			}
			if matched && strings.HasPrefix(docTokens[i+len(phraseTokens)-1], phraseTokens[len(phraseTokens)-1]) {
				return true
			}
		}
		return false
	case "MATCH_ALL":
		tokens := tokenizeWords(queryStr)
		for _, tok := range tokens {
			if !strings.Contains(combined, tok) {
				return false
			}
		}
		return len(tokens) > 0
	default:
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

func matchPhraseWithSlop(docTokens, phraseTokens []string, slop int) bool {
	if len(phraseTokens) == 0 {
		return false
	}
	if len(phraseTokens) == 1 {
		for _, dt := range docTokens {
			if dt == phraseTokens[0] {
				return true
			}
		}
		return false
	}
	for start := 0; start < len(docTokens); start++ {
		if docTokens[start] != phraseTokens[0] {
			continue
		}
		pos := start
		totalGap := 0
		matched := true
		for j := 1; j < len(phraseTokens); j++ {
			foundNext := -1
			for k := pos + 1; k < len(docTokens); k++ {
				if docTokens[k] == phraseTokens[j] {
					foundNext = k
					break
				}
			}
			if foundNext < 0 {
				matched = false
				break
			}
			totalGap += (foundNext - pos - 1)
			pos = foundNext
			if totalGap > slop {
				matched = false
				break
			}
		}
		if matched && totalGap <= slop {
			return true
		}
	}
	return false
}

func evalNumericExpr(row map[string]any, expr string) float64 {
	expr = trimOuterParens(strings.TrimSpace(expr))
	if expr == "" {
		return 0
	}
	if f, err := strconv.ParseFloat(expr, 64); err == nil {
		return f
	}

	if strings.HasPrefix(expr, "CASE WHEN ") && strings.HasSuffix(expr, " END") {
		inner := expr[len("CASE WHEN ") : len(expr)-len(" END")]
		elseIdx := findTopLevelOp(inner, " ELSE ")
		if elseIdx > 0 {
			elseExpr := inner[elseIdx+6:]
			whenChain := inner[:elseIdx]
			for {
				thenIdx := findTopLevelOp(whenChain, " THEN ")
				if thenIdx <= 0 {
					break
				}
				cond := whenChain[:thenIdx]
				rest := whenChain[thenIdx+6:]
				nextWhenIdx := findTopLevelOp(rest, " WHEN ")
				var thenExpr string
				if nextWhenIdx > 0 {
					thenExpr = rest[:nextWhenIdx]
				} else {
					thenExpr = rest
				}
				if evalWhereExpr(row, cond) {
					return evalNumericExpr(row, thenExpr)
				}
				if nextWhenIdx <= 0 {
					break
				}
				whenChain = rest[nextWhenIdx+6:]
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

	for _, fn := range []string{"GREATEST", "LEAST", "COALESCE", "LOG10", "LN", "SQRT"} {
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
			case "LEAST":
				minVal := 0.0
				for i, a := range args {
					v := evalNumericExpr(row, a)
					if i == 0 || v < minVal {
						minVal = v
					}
				}
				return minVal
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

	if parts := splitTopLevelBinaryMath(expr, '+'); len(parts) > 1 {
		sum := 0.0
		for _, p := range parts {
			sum += evalNumericExpr(row, p)
		}
		return sum
	}

	if parts := splitTopLevelBinaryMath(expr, '*'); len(parts) > 1 {
		prod := 1.0
		for _, p := range parts {
			prod *= evalNumericExpr(row, p)
		}
		return prod
	}

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
	if strings.HasPrefix(colExpr, "CONCAT_WS('\\x1f', ") && strings.HasSuffix(colExpr, ")") {
		return evalCompositeKeyExpr(row, colExpr)
	}
	if strings.HasPrefix(colExpr, "`") && strings.HasSuffix(colExpr, "`") {
		colName := strings.Trim(colExpr, "`")
		return row[colName]
	}
	if val, ok := row[colExpr]; ok {
		return val
	}
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
	if strings.HasPrefix(colExpr, "CAST(`_doc`") {
		asIdx := strings.LastIndex(colExpr, " AS ")
		if asIdx > 0 {
			pathPart := colExpr[len("CAST(`_doc`"):asIdx]
			var segs []string
			for _, p := range strings.Split(pathPart, "['") {
				p = strings.TrimSuffix(p, "']")
				if p != "" {
					p = strings.ReplaceAll(p, "''", "'")
					p = strings.ReplaceAll(p, `\\`, `\`)
					segs = append(segs, p)
				}
			}
			srcStr, _ := row["_source"].(string)
			return extractJSONPathFromStr(srcStr, segs)
		}
	}
	if strings.HasPrefix(colExpr, "array_size(") && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("array_size(") : len(colExpr)-1]
		val := resolveColumnValue(row, inner)
		if val == nil {
			return int64(0)
		}
		return int64(len(toStringSlice(val)))
	}
	if (strings.HasPrefix(colExpr, "COSINE_DISTANCE(") || strings.HasPrefix(colExpr, "L2_DISTANCE(") || strings.HasPrefix(colExpr, "INNER_PRODUCT(")) && strings.HasSuffix(colExpr, ")") {
		isL2 := strings.HasPrefix(colExpr, "L2_DISTANCE(")
		isIP := strings.HasPrefix(colExpr, "INNER_PRODUCT(")
		fnLen := len("COSINE_DISTANCE(")
		if isL2 {
			fnLen = len("L2_DISTANCE(")
		} else if isIP {
			fnLen = len("INNER_PRODUCT(")
		}
		inner := colExpr[fnLen : len(colExpr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 2 {
			docVec := resolveVectorValue(row, args[0])
			qVec := parseVectorLiteral(args[1])
			if len(docVec) > 0 && len(docVec) == len(qVec) {
				if isL2 {
					return computeL2Distance(docVec, qVec)
				}
				if isIP {
					return computeInnerProduct(docVec, qVec)
				}
				return computeCosineDistance(docVec, qVec)
			}
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "lower(") && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("lower(") : len(colExpr)-1]
		if v := resolveColumnValue(row, inner); v != nil {
			return strings.ToLower(fmt.Sprintf("%v", v))
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "LENGTH(") && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("LENGTH(") : len(colExpr)-1]
		if v := resolveColumnValue(row, inner); v != nil {
			return int64(len(fmt.Sprintf("%v", v)))
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "CAST(") && !strings.HasPrefix(colExpr, "CAST(`_doc`") {
		if strings.HasSuffix(colExpr, " AS DOUBLE)") {
			inner := colExpr[len("CAST(") : len(colExpr)-len(" AS DOUBLE)")]
			return evalNumericExpr(row, inner)
		}
		if strings.HasSuffix(colExpr, " AS BIGINT)") {
			inner := colExpr[len("CAST(") : len(colExpr)-len(" AS BIGINT)")]
			return int64(evalNumericExpr(row, inner))
		}
		if strings.HasSuffix(colExpr, " AS STRING)") {
			inner := colExpr[len("CAST(") : len(colExpr)-len(" AS STRING)")]
			if v := resolveColumnValue(row, inner); v != nil {
				return fmt.Sprintf("%v", v)
			}
			return nil
		}
		if strings.HasSuffix(colExpr, " AS BOOLEAN)") {
			inner := colExpr[len("CAST(") : len(colExpr)-len(" AS BOOLEAN)")]
			if v := resolveColumnValue(row, inner); v != nil {
				s := fmt.Sprintf("%v", v)
				return strings.EqualFold(s, "true") || s == "1"
			}
			return nil
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
				continue
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
	case []float64:
		out := make([]string, 0, len(s))
		for _, item := range s {
			out = append(out, strconv.FormatFloat(item, 'f', -1, 64))
		}
		return out
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

func resolveVectorValue(row map[string]any, expr string) []float64 {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "IF(") && strings.HasSuffix(expr, ")") {
		args := splitTopLevelArgs(expr[3 : len(expr)-1])
		if len(args) == 3 {
			expr = strings.TrimSpace(args[1])
		}
	}
	val := resolveColumnValue(row, expr)
	switch s := val.(type) {
	case []float64:
		return s
	case []any:
		out := make([]float64, 0, len(s))
		for _, item := range s {
			if f, ok := toFloat(item); ok {
				out = append(out, f)
			}
		}
		return out
	default:
		return nil
	}
}

func parseVectorLiteral(expr string) []float64 {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "CAST([") && strings.HasSuffix(expr, "] AS ARRAY<FLOAT>)") {
		expr = expr[len("CAST([") : len(expr)-len("] AS ARRAY<FLOAT>)")]
	} else if strings.HasPrefix(expr, "[") && strings.HasSuffix(expr, "]") {
		expr = expr[1 : len(expr)-1]
	}
	var out []float64
	for _, part := range strings.Split(expr, ",") {
		if f, err := strconv.ParseFloat(strings.TrimSpace(part), 64); err == nil {
			out = append(out, f)
		}
	}
	return out
}

func computeCosineDistance(a, b []float64) float64 {
	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 1.0
	}
	sim := dot / (math.Sqrt(normA) * math.Sqrt(normB))
	return 1.0 - sim
}

func computeL2Distance(a, b []float64) float64 {
	var sumSq float64
	for i := range a {
		d := a[i] - b[i]
		sumSq += d * d
	}
	return math.Sqrt(sumSq)
}

func computeInnerProduct(a, b []float64) float64 {
	var dot float64
	for i := range a {
		dot += a[i] * b[i]
	}
	return dot
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
