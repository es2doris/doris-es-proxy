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
	"crypto/md5" // #nosec G501 -- used only to emulate Doris MD5() SQL function in MemoryBackend
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/schema"
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

func appendBoundedSQL(slice []string, sqlStr string) []string {
	const maxSQLHistory = 256
	slice = append(slice, sqlStr)
	if len(slice) > maxSQLHistory {
		slice = append([]string(nil), slice[len(slice)-maxSQLHistory:]...)
	}
	return slice
}

func (m *MemoryBackend) ExecDDL(_ context.Context, ddl string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ddls = appendBoundedSQL(m.ddls, ddl)
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
		m.tables[table][id] = row
		rowsLoaded++
	}
	if m.logSQL {
		// #nosec G706 -- table name is sanitized and only logged when --log-sql is enabled
		log.Printf("[Doris Stream Load] table=%s rows=%d merge_type=MERGE", table, rowsLoaded)
	}
	return scanner.Err()
}

func isTombstoneRow(row map[string]any) bool {
	if row == nil {
		return true
	}
	delSign, _ := toInt64(row["__DORIS_DELETE_SIGN__"])
	return delSign != 0
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
	hit := &HitRow{
		ID:      id,
		Version: ver,
		Source:  json.RawMessage(srcStr),
		Score:   1.0,
	}
	if isTombstoneRow(row) {
		return hit, false, nil
	}
	return hit, true, nil
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
		if row, ok := tbl[id]; ok && !isTombstoneRow(row) {
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
	reHitsSQL            = regexp.MustCompile(`(?s)^SELECT ` + "`_id`, `_version`, `_source`, CAST\\((.+) AS DOUBLE\\) AS `_score`, (COUNT\\(\\*\\) OVER\\(\\)|CAST\\(-1 AS BIGINT\\)) AS `_total_hits` FROM `[^`]+`\\.`([^`]+)` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (.+) ORDER BY (.+) LIMIT (\\d+) OFFSET (\\d+)$")
	reSearchAfterHitsSQL = regexp.MustCompile(`(?s)^SELECT ` + "`_id`, `_version`, `_source`, `_score`, `_total_hits` FROM \\(SELECT \\*, CAST\\((.+) AS DOUBLE\\) AS `_score`, (COUNT\\(\\*\\) OVER\\(\\)|CAST\\(-1 AS BIGINT\\)) AS `_total_hits` FROM `[^`]+`\\.`([^`]+)` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (.+)\\) `_scored` WHERE (.+) ORDER BY (.+) LIMIT (\\d+) OFFSET (\\d+)$")
	reCollapsedHitsSQL   = regexp.MustCompile(`(?s)^SELECT ` + "`_id`, `_version`, `_source`, `_score`, `_total_hits` FROM \\(SELECT \\*, ROW_NUMBER\\(\\) OVER \\(PARTITION BY (.+?) ORDER BY .+\\) AS `_collapse_rn` FROM \\(SELECT \\*, CAST\\((.+) AS DOUBLE\\) AS `_score`, (COUNT\\(\\*\\) OVER\\(\\)|CAST\\(-1 AS BIGINT\\)) AS `_total_hits` FROM `[^`]+`\\.`([^`]+)` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (.+)\\) `_scored`\\) `_collapsed` WHERE (?:\\()?`_collapse_rn` = 1(?: OR .+? IS NULL)?(?:\\) AND \\((.+)\\))? ORDER BY (.+) LIMIT (\\d+) OFFSET (\\d+)$")
	reCTEBase            = regexp.MustCompile(`(?s)^WITH ` + "`base_matched` AS \\(SELECT \\* FROM `[^`]+`\\.`([^`]+)` WHERE `__DORIS_DELETE_SIGN__` = 0(?: AND \\((.+?)\\))?\\)\n(.+)$")
)

func parseOrderSpec(spec string) (colExpr string, desc bool, nullsFirst bool) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return "", false, false
	}
	upper := strings.ToUpper(s)
	if strings.HasSuffix(upper, " NULLS FIRST") {
		nullsFirst = true
		s = strings.TrimSpace(s[:len(s)-len(" NULLS FIRST")])
		upper = strings.ToUpper(s)
	} else if strings.HasSuffix(upper, " NULLS LAST") {
		s = strings.TrimSpace(s[:len(s)-len(" NULLS LAST")])
		upper = strings.ToUpper(s)
	}
	switch {
	case strings.HasSuffix(upper, " DESC"):
		return strings.TrimSpace(s[:len(s)-5]), true, nullsFirst
	case strings.HasSuffix(upper, " ASC"):
		return strings.TrimSpace(s[:len(s)-4]), false, nullsFirst
	default:
		return s, false, nullsFirst
	}
}

func splitHitsWhereBody(whereBody string) (mainWhere, postWhere string) {
	trimmed := strings.TrimSpace(whereBody)
	if trimmed == "" {
		return "TRUE", "TRUE"
	}
	if len(splitTopLevelLogicalOp(trimmed, " OR ")) > 1 {
		return trimmed, "TRUE"
	}
	parts := splitTopLevelLogicalOp(trimmed, " AND ")
	if len(parts) == 0 {
		return trimmed, "TRUE"
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
	m.hitsSQLs = appendBoundedSQL(m.hitsSQLs, sqlStr)
	logSQL := m.logSQL
	m.mu.Unlock()

	if logSQL {
		log.Printf("[Doris HitsSQL]\n%s", sqlStr)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var scoreExpr, totalExpr, collapseCol, collapseSearchAfterWhere, tableName, mainWhere, postWhere, orderByClause string
	var limit, offset int
	if sub := reHitsSQL.FindStringSubmatch(sqlStr); sub != nil {
		scoreExpr = sub[1]
		totalExpr = sub[2]
		tableName = sub[3]
		mainWhere, postWhere = splitHitsWhereBody(sub[4])
		orderByClause = sub[5]
		limit, _ = strconv.Atoi(sub[6])
		offset, _ = strconv.Atoi(sub[7])
	} else if ssub := reSearchAfterHitsSQL.FindStringSubmatch(sqlStr); ssub != nil {
		scoreExpr = ssub[1]
		totalExpr = ssub[2]
		tableName = ssub[3]
		mainWhere, postWhere = splitHitsWhereBody(ssub[4])
		collapseSearchAfterWhere = ssub[5]
		orderByClause = ssub[6]
		limit, _ = strconv.Atoi(ssub[7])
		offset, _ = strconv.Atoi(ssub[8])
	} else if csub := reCollapsedHitsSQL.FindStringSubmatch(sqlStr); csub != nil {
		collapseCol = csub[1]
		scoreExpr = csub[2]
		totalExpr = csub[3]
		tableName = csub[4]
		mainWhere, postWhere = splitHitsWhereBody(csub[5])
		collapseSearchAfterWhere = csub[6]
		orderByClause = csub[7]
		limit, _ = strconv.Atoi(csub[8])
		offset, _ = strconv.Atoi(csub[9])
	} else {
		return nil, fmt.Errorf("unrecognized HitsSQL format: %s", sqlStr)
	}

	tbl := m.tables[tableName]
	var matchedRows []map[string]any
	var hits []HitRow

	for _, row := range tbl {
		if isTombstoneRow(row) {
			continue
		}
		if evalWhereExpr(row, mainWhere) && evalWhereExpr(row, postWhere) {
			score := evalNumericExpr(row, scoreExpr)
			ver, _ := toInt64(row["_version"])
			srcStr, _ := row["_source"].(string)
			rowCopy := make(map[string]any, len(row)+1)
			for k, v := range row {
				rowCopy[k] = v
			}
			rowCopy["_score"] = score
			matchedRows = append(matchedRows, rowCopy)
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
			colExpr, desc, nullsFirst := parseOrderSpec(spec)
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
					return nullsFirst
				}
				if vb == nil {
					return !nullsFirst
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
			switch s := cVal.(type) {
			case []any:
				cVal = nil
				for _, el := range s {
					if el == nil {
						continue
					}
					if cVal == nil || compareAny(el, cVal) < 0 {
						cVal = el
					}
				}
			case []string:
				cVal = nil
				for _, el := range s {
					if cVal == nil || compareAny(el, cVal) < 0 {
						cVal = el
					}
				}
			}
			if cVal != nil {
				cKey := fmt.Sprintf("%v", cVal)
				if seenCollapse[cKey] {
					continue
				}
				seenCollapse[cKey] = true
			}
		}
		if collapseSearchAfterWhere != "" && !evalWhereExpr(matchedRows[idx], collapseSearchAfterWhere) {
			continue
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
	m.aggsSQLs = appendBoundedSQL(m.aggsSQLs, sqlStr)
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
		if isTombstoneRow(row) {
			continue
		}
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
	reAggArrayExplode          = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CAST\\((.+?) AS STRING\\) AS `_bucket_key`, CAST\\((?:COUNT\\(\\*\\)|COUNT\\(DISTINCT `_id`\\)) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_t` AS `_elem` WHERE (?:\\((.+)\\) AND )?`_elem` IS NOT NULL GROUP BY (?:`_elem`|`_bucket_key`) ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggArrayExplodeMissing   = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, COALESCE\\(CAST\\((.+?) AS STRING\\), ('(?:''|[^'])*')\\) AS `_bucket_key`, CAST\\((?:COUNT\\(\\*\\)|COUNT\\(DISTINCT `_id`\\)) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(CASE WHEN `([^`]+)` IS NULL.+?\\) `_t` AS `_elem`(?: WHERE (.+?))? GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggScalarTerms           = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CAST\\((.+?) AS STRING\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (.+?) IS NOT NULL GROUP BY .+? ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggScalarTermsMissing    = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, COALESCE\\(CAST\\((.+?) AS STRING\\), ('(?:''|[^'])*')\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+?))? GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggNestedTerms           = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, (?:json_extract_string\\(`_nel`, '\\$\\.([^']+)'\\)|CAST\\((.+?) AS STRING\\)) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_nt` AS `_nel` WHERE (?:\\((.+)\\) AND )?(?:json_extract_string\\(`_nel`, '\\$\\.[^']+'\\)|CAST\\(.+? AS STRING\\)) IS NOT NULL GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggNestedTermsMissing    = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, COALESCE\\((?:json_extract_string\\(`_nel`, '\\$\\.([^']+)'\\)|CAST\\((.+?) AS STRING\\)), ('(?:''|[^'])*')\\) AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\((?:CASE WHEN )?`([^`]+)`(?: IS NULL.+?)?\\) `_nt` AS `_nel`(?: WHERE (.+?))? GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT (\\d+)")
	reAggNestedMetric          = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '(_metric|_nested_doc_count|_stats_[a-z_]+)' AS `_bucket_key`, CAST\\((?:COALESCE\\((AVG|SUM|MIN|MAX|COUNT|STDDEV_POP)\\((.+?)\\), 0\\)|(COUNT)\\((DISTINCT )?(.+?)\\)) AS DOUBLE\\) AS `_doc_count` FROM (`base_matched` LATERAL VIEW EXPLODE\\(.+?\\) `_(?:nt|t)` AS `_(?:nel|elem)`)(?: WHERE (.+))?$")
	reAggFilter                = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '(_filter|_global|_reverse_nested|_sampler)' AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
	reAggMissing               = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_missing' AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` WHERE (?:\\((.+)\\) AND )?NOT \\((.+)\\)$")
	reAggCardArray             = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COUNT\\(DISTINCT `_elem`\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_t` AS `_elem` WHERE (?:\\((.+)\\) AND )?`_elem` IS NOT NULL$")
	reAggCardScalar            = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COUNT\\(DISTINCT (.+?)\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
	reAggValueCountArray       = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COUNT\\(`_elem`\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched` LATERAL VIEW EXPLODE\\(`([^`]+)`\\) `_t` AS `_elem` WHERE (?:\\((.+)\\) AND )?`_elem` IS NOT NULL$")
	reAggValueCountScalar      = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '_metric' AS `_bucket_key`, CAST\\(COUNT\\((.+?)\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
	reAggMetric                = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '(_metric|_stats_[a-z_]+)' AS `_bucket_key`, CAST\\(COALESCE\\((AVG|SUM|MIN|MAX|COUNT|STDDEV_POP)\\((.+?)\\), 0\\) AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+))?$")
	reAggPercentile            = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '([^']+)' AS `_bucket_key`, CAST\\(COALESCE\\(PERCENTILE_APPROX\\((.+?), ([0-9.]+)\\), 0\\) AS DOUBLE\\) AS `_doc_count` FROM (`base_matched`(?: LATERAL VIEW EXPLODE\\(.+?\\) `_(?:nt|t)` AS `_(?:nel|elem)`)?)(?: WHERE (.+))?$")
	reAggPercentileRank        = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '([^']+)' AS `_bucket_key`, CAST\\(COALESCE\\(AVG\\(CASE WHEN (.+?) <= ([0-9.eE+-]+) THEN 100\\.0 ELSE 0\\.0 END\\), 0\\) AS DOUBLE\\) AS `_doc_count` FROM (`base_matched`(?: LATERAL VIEW EXPLODE\\(.+?\\) `_(?:nt|t)` AS `_(?:nel|elem)`)?)(?: WHERE (.+))?$")
	reAggDateHist              = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CAST\\(CAST\\(FLOOR\\((?:\\((.+?) \\+ (-?\\d+)\\)|(.+?)) / (\\d+)\\) \\* \\d+(?: - -?\\d+)? AS BIGINT\\) AS STRING\\) AS `_bucket_key`, CAST\\((?:COUNT\\(\\*\\)|COUNT\\(DISTINCT `_id`\\)) AS DOUBLE\\) AS `_doc_count` FROM (`base_matched`(?: LATERAL VIEW EXPLODE\\((?:CASE WHEN .+ END|`[^`]+`)\\) `_t` AS `_elem`)?) WHERE (?:(?:\\((.+)\\) AND )?(?:`[^`]+`|CAST\\([^)]+\\)|`_doc`\\[[^\\]]+\\]) IS NOT NULL|(.+?)) GROUP BY `_bucket_key` ORDER BY CAST\\(`_bucket_key` AS BIGINT\\) ASC")
	reAggHist                  = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CAST\\(FLOOR\\(\\((.+?) - ([^)]+)\\) / ([^)]+)\\) \\* [^)]+ \\+ [^)]+ AS STRING\\) AS `_bucket_key`, CAST\\((?:COUNT\\(\\*\\)|COUNT\\(DISTINCT `_id`\\)) AS DOUBLE\\) AS `_doc_count` FROM (`base_matched`(?: LATERAL VIEW EXPLODE\\((?:CASE WHEN .+ END|`[^`]+`)\\) `_t` AS `_elem`)?) WHERE (?:(?:\\((.+)\\) AND )?(?:`[^`]+`|CAST\\([^)]+\\)|`_doc`\\[[^\\]]+\\]) IS NOT NULL|(.+?)) GROUP BY `_bucket_key` ORDER BY CAST\\(`_bucket_key` AS DOUBLE\\) ASC")
	reAggRange                 = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, '([^']+)' AS `_bucket_key`, CAST\\(COUNT\\(\\*\\) AS DOUBLE\\) AS `_doc_count` FROM (`base_matched`(?: LATERAL VIEW EXPLODE\\(`[^`]+`\\) `_t` AS `_elem`)?) WHERE (.+)$")
	reAggSubMetric             = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, (.+?) AS `_bucket_key`, CAST\\((?:COALESCE\\((AVG|SUM|MIN|MAX|COUNT|STDDEV_POP)\\((.+?)\\), 0\\)|(COUNT)\\((DISTINCT )?(.+?)\\)) AS DOUBLE\\) AS `_doc_count` FROM (.+) WHERE (.+?) GROUP BY `_bucket_key`$")
	reAggSubPercentile         = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, (.+?) AS `_bucket_key`, CAST\\(COALESCE\\(PERCENTILE_APPROX\\((.+?), ([0-9.]+)\\), 0\\) AS DOUBLE\\) AS `_doc_count` FROM (.+) WHERE (.+?) GROUP BY `_bucket_key`$")
	reAggSubPercentileRank     = regexp.MustCompile(`^SELECT '([^']+)' AS ` + "`_agg_name`, (.+?) AS `_bucket_key`, CAST\\(COALESCE\\(AVG\\(CASE WHEN (.+?) <= ([0-9.eE+-]+) THEN 100\\.0 ELSE 0\\.0 END\\), 0\\) AS DOUBLE\\) AS `_doc_count` FROM (.+) WHERE (.+?) GROUP BY `_bucket_key`$")
	reAggSubTerms              = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, (CONCAT\\(.+?\\)) AS `_bucket_key`, CAST\\((?:COUNT\\(\\*\\)|COUNT\\(DISTINCT `_id`\\)) AS DOUBLE\\) AS `_doc_count` FROM (.+) WHERE (.+?) GROUP BY `_bucket_key` ORDER BY `_doc_count` (DESC|ASC), `_bucket_key` ASC")
	reAggTopHits               = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, `_id` AS `_bucket_key`, CAST\\(1 AS DOUBLE\\) AS `_doc_count` FROM `base_matched`(?: WHERE (.+?))? ORDER BY (.+?) LIMIT (\\d+)")
	reAggSubTopHits            = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, CONCAT\\((.+?), '\\\\x1f', `_id`\\) AS `_bucket_key`, CAST\\(ROW_NUMBER\\(\\) OVER \\(PARTITION BY .+? ORDER BY (.+?)\\) AS DOUBLE\\) AS `_doc_count` FROM (.+) WHERE (.+?)\\) `_agg_sub_\\d+` WHERE `_doc_count` <= (\\d+)")
	reAggComposite             = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, (.+?) AS `_bucket_key`, CAST\\((?:COUNT\\(\\*\\)|COUNT\\(DISTINCT `_id`\\)) AS DOUBLE\\) AS `_doc_count` FROM (.+?)(?: WHERE (.+?))? GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT (\\d+)")
	reAggGenericGroupedBuckets = regexp.MustCompile(`SELECT '([^']+)' AS ` + "`_agg_name`, (.+?) AS `_bucket_key`, CAST\\((?:COUNT\\(\\*\\)|COUNT\\(DISTINCT `_id`\\)) AS DOUBLE\\) AS `_doc_count` FROM (.+?)(?: WHERE (.+?))? GROUP BY `_bucket_key` ORDER BY `_doc_count` (DESC|ASC), `_bucket_key` ASC LIMIT (\\d+)")
)

func computePopStdDev(nums []float64) float64 {
	if len(nums) == 0 {
		return 0
	}
	var sum float64
	for _, v := range nums {
		sum += v
	}
	mean := sum / float64(len(nums))
	var sqDiff float64
	for _, v := range nums {
		d := v - mean
		sqDiff += d * d
	}
	return math.Sqrt(sqDiff / float64(len(nums)))
}

func evalAggBranch(baseRows []map[string]any, branch string) []AggRow {
	hasHavingCountGtZero := false
	havingExpr := ""
	if hIdx := strings.LastIndex(branch, " HAVING COUNT("); hIdx > 0 && strings.HasSuffix(branch, ") > 0") {
		hasHavingCountGtZero = true
		branch = branch[:hIdx]
	} else if hIdx := strings.LastIndex(branch, " HAVING "); hIdx > 0 {
		tail := branch[hIdx+len(" HAVING "):]
		orderIdx := strings.Index(tail, " ORDER BY ")
		limitIdx := strings.Index(tail, " LIMIT ")
		endIdx := len(tail)
		if orderIdx >= 0 && orderIdx < endIdx {
			endIdx = orderIdx
		}
		if limitIdx >= 0 && limitIdx < endIdx {
			endIdx = limitIdx
		}
		havingExpr = strings.TrimSpace(tail[:endIdx])
		branch = branch[:hIdx] + tail[endIdx:]
	}
	filterHaving := func(rows []AggRow) []AggRow {
		if havingExpr == "" {
			return rows
		}
		filtered := make([]AggRow, 0, len(rows))
		for _, r := range rows {
			synth := map[string]any{
				"_agg_name":             r.AggName,
				"_bucket_key":           r.BucketKey,
				"_doc_count":            r.DocCount,
				"doc_count":             r.DocCount,
				"bucket_key":            r.BucketKey,
				"COUNT(*)":              r.DocCount,
				"COUNT(DISTINCT `_id`)": r.DocCount,
			}
			if evalWhereExpr(synth, havingExpr) {
				filtered = append(filtered, r)
			}
		}
		return filtered
	}
	topFilteredBuckets := func(aggName string, counts map[string]int64, limit int) []AggRow {
		rows := filterHaving(topBuckets(aggName, counts, 0))
		if limit > 0 && len(rows) > limit {
			rows = rows[:limit]
		}
		return rows
	}
	ascFilteredBuckets := func(aggName string, counts map[string]int64, limit int) []AggRow {
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
				return rows[i].DocCount < rows[j].DocCount
			}
			return rows[i].BucketKey < rows[j].BucketKey
		})
		rows = filterHaving(rows)
		if limit > 0 && len(rows) > limit {
			rows = rows[:limit]
		}
		return rows
	}
	if strings.Contains(branch, "'__meta_total'") || strings.Contains(branch, "'__meta_query_total'") {
		metaName := "__meta_total"
		if strings.Contains(branch, "'__meta_query_total'") {
			metaName = "__meta_query_total"
		}
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
		return []AggRow{{AggName: metaName, BucketKey: "_count", DocCount: cnt, Value: float64(cnt)}}
	}

	if m := reAggArrayExplode.FindStringSubmatch(branch); m != nil {
		aggName, elemExpr, arrCol, extraWhere := m[1], m[2], m[3], m[4]
		limit, _ := strconv.Atoi(m[5])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			seenInDoc := make(map[string]bool)
			for _, elem := range toStringSlice(row[arrCol]) {
				if elem == "" {
					continue
				}
				valStr := elem
				if elemExpr != "`_elem`" {
					cp := make(map[string]any, len(row)+1)
					for k, v := range row {
						cp[k] = v
					}
					cp["_elem"] = elem
					if v := resolveColumnValue(cp, elemExpr); v != nil {
						valStr = fmt.Sprintf("%v", v)
					} else {
						valStr = ""
					}
				}
				if valStr != "" && !seenInDoc[valStr] {
					seenInDoc[valStr] = true
					counts[valStr]++
				}
			}
		}
		return topFilteredBuckets(aggName, counts, limit)
	}

	if m := reAggArrayExplodeMissing.FindStringSubmatch(branch); m != nil {
		aggName, elemExpr, missingLit, arrCol, extraWhere := m[1], m[2], m[3], m[4], m[5]
		missingVal := unquoteSQLLiteral(missingLit)
		limit, _ := strconv.Atoi(m[6])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			elems := toStringSlice(row[arrCol])
			added := false
			seenInDoc := make(map[string]bool)
			for _, elem := range elems {
				if elem == "" {
					continue
				}
				valStr := elem
				if elemExpr != "`_elem`" {
					cp := make(map[string]any, len(row)+1)
					for k, v := range row {
						cp[k] = v
					}
					cp["_elem"] = elem
					if v := resolveColumnValue(cp, elemExpr); v != nil {
						valStr = fmt.Sprintf("%v", v)
					} else {
						valStr = ""
					}
				}
				if valStr != "" {
					if !seenInDoc[valStr] {
						seenInDoc[valStr] = true
						counts[valStr]++
					}
					added = true
				}
			}
			if !added && missingVal != "" {
				counts[missingVal]++
			}
		}
		return topFilteredBuckets(aggName, counts, limit)
	}

	if m := reAggNestedTerms.FindStringSubmatch(branch); m != nil {
		aggName, relPath, scriptExpr, corrCol, extraWhere := m[1], m[2], m[3], m[4], m[5]
		limit, _ := strconv.Atoi(m[6])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			for _, elemJSON := range toStringSlice(row[corrCol]) {
				var val any
				if scriptExpr != "" {
					cp := make(map[string]any, len(row)+1)
					for k, v := range row {
						cp[k] = v
					}
					cp["_nel"] = elemJSON
					val = resolveColumnValue(cp, scriptExpr)
				} else {
					val = extractJSONPathFromStr(elemJSON, strings.Split(relPath, "."))
				}
				if val != nil {
					seenInElem := make(map[string]bool)
					for _, item := range asSliceOrSingle(val) {
						if item == nil {
							continue
						}
						s := fmt.Sprintf("%v", item)
						if s != "" && !seenInElem[s] {
							seenInElem[s] = true
							counts[s]++
						}
					}
				}
			}
		}
		return topFilteredBuckets(aggName, counts, limit)
	}

	if m := reAggNestedTermsMissing.FindStringSubmatch(branch); m != nil {
		aggName, relPath, scriptExpr, missingLit, corrCol, extraWhere := m[1], m[2], m[3], m[4], m[5], m[6]
		missingVal := unquoteSQLLiteral(missingLit)
		limit, _ := strconv.Atoi(m[7])
		counts := make(map[string]int64)
		for _, row := range baseRows {
			if extraWhere != "" && !evalWhereExpr(row, extraWhere) {
				continue
			}
			elems := toStringSlice(row[corrCol])
			for _, elemJSON := range elems {
				var val any
				if scriptExpr != "" {
					cp := make(map[string]any, len(row)+1)
					for k, v := range row {
						cp[k] = v
					}
					cp["_nel"] = elemJSON
					val = resolveColumnValue(cp, scriptExpr)
				} else {
					val = extractJSONPathFromStr(elemJSON, strings.Split(relPath, "."))
				}
				if val == nil {
					if missingVal != "" {
						counts[missingVal]++
					}
					continue
				}
				items := asSliceOrSingle(val)
				if len(items) == 0 {
					if missingVal != "" {
						counts[missingVal]++
					}
				} else {
					seenInElem := make(map[string]bool)
					for _, item := range items {
						s := fmt.Sprintf("%v", item)
						if item == nil || s == "" {
							s = missingVal
						}
						if s != "" && !seenInElem[s] {
							seenInElem[s] = true
							counts[s]++
						}
					}
				}
			}
		}
		return topFilteredBuckets(aggName, counts, limit)
	}

	if !strings.HasSuffix(branch, " GROUP BY `_bucket_key`") {
		if m := reAggNestedMetric.FindStringSubmatch(branch); m != nil {
			aggName, bKey := m[1], m[2]
			fn := m[3]
			colExpr := m[4]
			isDistinct := m[6] != ""
			if fn == "" {
				fn = m[5]
				colExpr = m[7]
			}
			fromClause, extraWhere := m[8], m[9]
			expanded := expandFromClauseRows(baseRows, fromClause, extraWhere)
			var nums []float64
			seen := make(map[string]bool)
			var cnt int64
			for _, row := range expanded {
				var val any
				if colExpr == "*" {
					val = 1
				} else {
					val = resolveColumnValue(row, colExpr)
				}
				if val == nil {
					continue
				}
				for _, elem := range asSliceOrSingle(val) {
					if elem == nil {
						continue
					}
					cnt++
					seen[fmt.Sprintf("%v", elem)] = true
					if f, ok := toFloat(elem); ok {
						nums = append(nums, f)
					}
				}
			}
			w := int64(len(nums))
			if len(nums) == 0 && (fn == "AVG" || fn == "MIN" || fn == "MAX" || fn == "STDDEV_POP") {
				if bKey == "_metric" {
					return nil
				}
				w = -1
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
			case "STDDEV_POP":
				res = computePopStdDev(nums)
			}
			return []AggRow{{AggName: aggName, BucketKey: bKey, DocCount: int64(res), Value: res, Weight: w}}
		}
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
		return topFilteredBuckets(aggName, counts, limit)
	}

	if m := reAggScalarTerms.FindStringSubmatch(branch); m != nil {
		aggName, colExpr, wherePrefix := m[1], m[2], strings.TrimSpace(m[3])
		var extraWhere string
		if strings.HasSuffix(wherePrefix, " AND "+colExpr) {
			extraWhere = trimOuterParens(strings.TrimSpace(strings.TrimSuffix(wherePrefix, " AND "+colExpr)))
		} else if wherePrefix != colExpr {
			if parts := splitTopLevelLogicalOp(wherePrefix, " AND "); len(parts) > 1 {
				extraWhere = trimOuterParens(strings.TrimSpace(strings.Join(parts[:len(parts)-1], " AND ")))
			}
		}
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
		return topFilteredBuckets(aggName, counts, limit)
	}

	if m := reAggFilter.FindStringSubmatch(branch); m != nil {
		aggName, bKey, filterWhere := m[1], m[2], m[3]
		var cnt int64
		for _, row := range baseRows {
			if filterWhere == "" || evalWhereExpr(row, filterWhere) {
				cnt++
			}
		}
		return []AggRow{{AggName: aggName, BucketKey: bKey, DocCount: cnt, Value: float64(cnt)}}
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
				for _, elem := range asSliceOrSingle(val) {
					if f, ok := toFloat(elem); ok {
						nums = append(nums, f)
					}
				}
			}
		}
		w := int64(len(nums))
		if len(nums) == 0 && (fn == "AVG" || fn == "MIN" || fn == "MAX" || fn == "STDDEV_POP") {
			if bKey == "_metric" {
				return nil
			}
			w = -1
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
			case "STDDEV_POP":
				res = computePopStdDev(nums)
			}
		}
		return []AggRow{{AggName: aggName, BucketKey: bKey, DocCount: int64(res), Value: res, Weight: w}}
	}

	if m := reAggSubPercentile.FindStringSubmatch(branch); m != nil {
		aggName, parentBucketExpr, colExpr, qStr, fromClause, whereClause := m[1], m[2], m[3], m[4], m[5], m[6]
		q, _ := strconv.ParseFloat(qStr, 64)
		expanded := expandFromClauseRows(baseRows, fromClause, whereClause)
		byBucket := make(map[string][]float64)
		var bucketOrder []string
		for _, row := range expanded {
			for _, bKey := range evalBucketKeyExprs(row, parentBucketExpr) {
				if bKey == "" {
					continue
				}
				if _, exists := byBucket[bKey]; !exists {
					bucketOrder = append(bucketOrder, bKey)
				}
				if val := resolveColumnValue(row, colExpr); val != nil {
					for _, elem := range asSliceOrSingle(val) {
						if f, ok := toFloat(elem); ok {
							byBucket[bKey] = append(byBucket[bKey], f)
						}
					}
				}
			}
		}
		sort.Strings(bucketOrder)
		var out []AggRow
		for _, bKey := range bucketOrder {
			nums := byBucket[bKey]
			if len(nums) == 0 && hasHavingCountGtZero {
				continue
			}
			sort.Float64s(nums)
			var res float64
			var w int64 = -1
			if len(nums) > 0 {
				w = int64(len(nums))
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
			out = append(out, AggRow{
				AggName:   aggName,
				BucketKey: bKey,
				DocCount:  int64(res),
				Value:     res,
				Weight:    w,
			})
		}
		return out
	}

	if m := reAggSubPercentileRank.FindStringSubmatch(branch); m != nil {
		aggName, parentBucketExpr, colExpr, threshStr, fromClause, whereClause := m[1], m[2], m[3], m[4], m[5], m[6]
		thresh, _ := strconv.ParseFloat(threshStr, 64)
		expanded := expandFromClauseRows(baseRows, fromClause, whereClause)
		type rankAcc struct {
			total   int64
			leCount int64
		}
		byBucket := make(map[string]*rankAcc)
		var bucketOrder []string
		for _, row := range expanded {
			for _, bKey := range evalBucketKeyExprs(row, parentBucketExpr) {
				if bKey == "" {
					continue
				}
				acc, exists := byBucket[bKey]
				if !exists {
					acc = &rankAcc{}
					byBucket[bKey] = acc
					bucketOrder = append(bucketOrder, bKey)
				}
				if val := resolveColumnValue(row, colExpr); val != nil {
					for _, elem := range asSliceOrSingle(val) {
						if f, ok := toFloat(elem); ok {
							acc.total++
							if f <= thresh {
								acc.leCount++
							}
						}
					}
				}
			}
		}
		sort.Strings(bucketOrder)
		var out []AggRow
		for _, bKey := range bucketOrder {
			acc := byBucket[bKey]
			if acc.total == 0 && hasHavingCountGtZero {
				continue
			}
			var res float64
			var w int64 = -1
			if acc.total > 0 {
				w = acc.total
				res = float64(acc.leCount) * 100.0 / float64(acc.total)
			}
			out = append(out, AggRow{
				AggName:   aggName,
				BucketKey: bKey,
				DocCount:  int64(res),
				Value:     res,
				Weight:    w,
			})
		}
		return out
	}

	if m := reAggPercentile.FindStringSubmatch(branch); m != nil {
		aggName, pctKey, colExpr, qStr, fromClause, extraWhere := m[1], m[2], m[3], m[4], m[5], m[6]
		q, _ := strconv.ParseFloat(qStr, 64)
		expanded := expandFromClauseRows(baseRows, fromClause, extraWhere)
		var nums []float64
		for _, row := range expanded {
			if val := resolveColumnValue(row, colExpr); val != nil {
				for _, elem := range asSliceOrSingle(val) {
					if f, ok := toFloat(elem); ok {
						nums = append(nums, f)
					}
				}
			}
		}
		sort.Float64s(nums)
		var res float64
		var w int64 = -1
		if len(nums) > 0 {
			w = int64(len(nums))
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
		return []AggRow{{AggName: aggName, BucketKey: pctKey, DocCount: int64(res), Value: res, Weight: w}}
	}

	if m := reAggPercentileRank.FindStringSubmatch(branch); m != nil {
		aggName, valKey, colExpr, threshStr, fromClause, extraWhere := m[1], m[2], m[3], m[4], m[5], m[6]
		thresh, _ := strconv.ParseFloat(threshStr, 64)
		expanded := expandFromClauseRows(baseRows, fromClause, extraWhere)
		var total, leCount int64
		for _, row := range expanded {
			if val := resolveColumnValue(row, colExpr); val != nil {
				for _, elem := range asSliceOrSingle(val) {
					if f, ok := toFloat(elem); ok {
						total++
						if f <= thresh {
							leCount++
						}
					}
				}
			}
		}
		var res float64
		var w int64 = -1
		if total > 0 {
			w = total
			res = float64(leCount) * 100.0 / float64(total)
		}
		return []AggRow{{AggName: aggName, BucketKey: valKey, DocCount: int64(res), Value: res, Weight: w}}
	}

	if m := reAggDateHist.FindStringSubmatch(branch); m != nil {
		aggName := m[1]
		colExpr := m[4]
		var tzShiftMs int64
		if m[2] != "" {
			colExpr = m[2]
			tzShiftMs, _ = strconv.ParseInt(m[3], 10, 64)
		}
		intervalStr, fromClause, extraWhere := m[5], m[6], m[7]
		if extraWhere == "" {
			extraWhere = m[8]
		}
		intervalMs, _ := strconv.ParseInt(intervalStr, 10, 64)
		if intervalMs <= 0 {
			intervalMs = 86400000
		}
		expanded := expandFromClauseRows(baseRows, fromClause, extraWhere)
		counts := make(map[int64]int64)
		seenDocBucket := make(map[string]bool)
		isDistinctDoc := strings.Contains(branch, "COUNT(DISTINCT `_id`)")
		for _, row := range expanded {
			if val := resolveColumnValue(row, colExpr); val != nil {
				seenRowBucket := make(map[int64]bool)
				for _, elem := range asSliceOrSingle(val) {
					if ts, ok := toInt64(elem); ok {
						b := int64(math.Floor(float64(ts+tzShiftMs)/float64(intervalMs)))*intervalMs - tzShiftMs
						if seenRowBucket[b] {
							continue
						}
						seenRowBucket[b] = true
						if isDistinctDoc {
							dk := fmt.Sprintf("%v\x00%d", row["_id"], b)
							if seenDocBucket[dk] {
								continue
							}
							seenDocBucket[dk] = true
						}
						counts[b]++
					}
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
		return filterHaving(rows)
	}

	if m := reAggHist.FindStringSubmatch(branch); m != nil {
		aggName, colExpr, offsetStr, intervalStr, fromClause, extraWhere := m[1], m[2], m[3], m[4], m[5], m[6]
		if extraWhere == "" {
			extraWhere = m[7]
		}
		offset, _ := strconv.ParseFloat(offsetStr, 64)
		interval, _ := strconv.ParseFloat(intervalStr, 64)
		if interval <= 0 {
			interval = 1.0
		}
		expanded := expandFromClauseRows(baseRows, fromClause, extraWhere)
		counts := make(map[float64]int64)
		seenDocBucket := make(map[string]bool)
		isDistinctDoc := strings.Contains(branch, "COUNT(DISTINCT `_id`)")
		for _, row := range expanded {
			if val := resolveColumnValue(row, colExpr); val != nil {
				seenRowBucket := make(map[float64]bool)
				for _, elem := range asSliceOrSingle(val) {
					if f, ok := toFloat(elem); ok {
						b := math.Round((math.Floor((f-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
						if seenRowBucket[b] {
							continue
						}
						seenRowBucket[b] = true
						if isDistinctDoc {
							dk := fmt.Sprintf("%v\x00%g", row["_id"], b)
							if seenDocBucket[dk] {
								continue
							}
							seenDocBucket[dk] = true
						}
						counts[b]++
					}
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
		return filterHaving(rows)
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
		if limit <= 0 {
			rows = nil
		} else if len(rows) > limit {
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
		seenBucketDoc := make(map[string]bool)
		var bucketOrder []string
		for _, row := range expanded {
			rowID := fmt.Sprintf("%v", row["_id"])
			for _, bKey := range evalBucketKeyExprs(row, parentBucketExpr) {
				if bKey == "" {
					continue
				}
				dk := bKey + "\x00" + rowID
				if seenBucketDoc[dk] {
					continue
				}
				seenBucketDoc[dk] = true
				if _, exists := byBucket[bKey]; !exists {
					bucketOrder = append(bucketOrder, bKey)
				}
				byBucket[bKey] = append(byBucket[bKey], row)
			}
		}
		sort.Strings(bucketOrder)
		var out []AggRow
		for _, bKey := range bucketOrder {
			rows := byBucket[bKey]
			sortRowsByOrderClause(rows, orderByClause)
			if limit <= 0 {
				rows = nil
			} else if len(rows) > limit {
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
		aggName, bucketKeyExpr, fromClause, whereClause, limitStr := m[1], m[2], m[3], m[4], m[5]
		limit, _ := strconv.Atoi(limitStr)
		expanded := expandFromClauseRows(baseRows, fromClause, whereClause)
		counts := make(map[string]int64)
		seenDocBucket := make(map[string]bool)
		isDistinctDoc := strings.Contains(branch, "COUNT(DISTINCT `_id`)")
		for _, row := range expanded {
			for _, bKey := range evalBucketKeyExprs(row, bucketKeyExpr) {
				if bKey != "" {
					if isDistinctDoc {
						dk := fmt.Sprintf("%v\x00%s", row["_id"], bKey)
						if seenDocBucket[dk] {
							continue
						}
						seenDocBucket[dk] = true
					}
					counts[bKey]++
				}
			}
		}
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var out []AggRow
		for _, k := range keys {
			out = append(out, AggRow{
				AggName:   aggName,
				BucketKey: k,
				DocCount:  counts[k],
				Value:     float64(counts[k]),
			})
		}
		out = filterHaving(out)
		if limit > 0 && len(out) > limit {
			out = out[:limit]
		}
		return out
	}

	if m := reAggSubTerms.FindStringSubmatch(branch); m != nil {
		aggName, bucketKeyExpr, fromClause, whereClause, dir := m[1], m[2], m[3], m[4], m[5]
		expanded := expandFromClauseRows(baseRows, fromClause, whereClause)
		counts := make(map[string]int64)
		seenDocBucket := make(map[string]bool)
		isDistinctDoc := strings.Contains(branch, "COUNT(DISTINCT `_id`)")
		for _, row := range expanded {
			for _, bKey := range evalBucketKeyExprs(row, bucketKeyExpr) {
				if bKey != "" {
					if isDistinctDoc {
						dk := fmt.Sprintf("%v\x00%s", row["_id"], bKey)
						if seenDocBucket[dk] {
							continue
						}
						seenDocBucket[dk] = true
					}
					counts[bKey]++
				}
			}
		}
		if dir == "ASC" {
			return ascFilteredBuckets(aggName, counts, 0)
		}
		return topFilteredBuckets(aggName, counts, 0)
	}

	if m := reAggGenericGroupedBuckets.FindStringSubmatch(branch); m != nil {
		aggName, bucketKeyExpr, fromClause, whereClause, dir, limitStr := m[1], m[2], m[3], m[4], m[5], m[6]
		limit, _ := strconv.Atoi(limitStr)
		expanded := expandFromClauseRows(baseRows, fromClause, whereClause)
		counts := make(map[string]int64)
		seenDocBucket := make(map[string]bool)
		isDistinctDoc := strings.Contains(branch, "COUNT(DISTINCT `_id`)")
		for _, row := range expanded {
			for _, bKey := range evalBucketKeyExprs(row, bucketKeyExpr) {
				if bKey != "" {
					if isDistinctDoc {
						dk := fmt.Sprintf("%v\x00%s", row["_id"], bKey)
						if seenDocBucket[dk] {
							continue
						}
						seenDocBucket[dk] = true
					}
					counts[bKey]++
				}
			}
		}
		if dir == "ASC" {
			return ascFilteredBuckets(aggName, counts, limit)
		}
		return topFilteredBuckets(aggName, counts, limit)
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
			for _, bKey := range evalBucketKeyExprs(row, parentBucketExpr) {
				if bKey == "" {
					continue
				}
				acc, exists := byBucket[bKey]
				if !exists {
					acc = &bucketAcc{seen: make(map[string]bool)}
					byBucket[bKey] = acc
					bucketOrder = append(bucketOrder, bKey)
				}
				var val any
				if strings.TrimSpace(colExpr) == "*" {
					val = int64(1)
				} else {
					val = resolveColumnValue(row, colExpr)
				}
				if val == nil {
					continue
				}
				for _, elem := range asSliceOrSingle(val) {
					if elem == nil {
						continue
					}
					acc.cnt++
					acc.seen[fmt.Sprintf("%v", elem)] = true
					if f, ok := toFloat(elem); ok {
						acc.nums = append(acc.nums, f)
					}
				}
			}
		}

		sort.Strings(bucketOrder)
		var out []AggRow
		for _, bKey := range bucketOrder {
			acc := byBucket[bKey]
			hasCount := len(acc.nums) > 0 || (fn == "COUNT" && acc.cnt > 0)
			if (len(acc.nums) == 0 && (fn == "AVG" || fn == "MIN" || fn == "MAX" || fn == "STDDEV_POP")) || (!hasCount && hasHavingCountGtZero) {
				continue
			}
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
			case "STDDEV_POP":
				res = computePopStdDev(acc.nums)
			}
			weightVal := int64(len(acc.nums))
			if fn == "COUNT" && weightVal == 0 {
				weightVal = acc.cnt
			}
			out = append(out, AggRow{
				AggName:   aggName,
				BucketKey: bKey,
				DocCount:  int64(res),
				Value:     res,
				Weight:    weightVal,
			})
		}
		return out
	}

	if m := reAggRange.FindStringSubmatch(branch); m != nil {
		aggName, bkey, fromClause, rangeWhere := m[1], m[2], m[3], m[4]
		if bkey != "_filter" && bkey != "_missing" && bkey != "_metric" && bkey != "_count" &&
			bkey != "_global" && bkey != "_reverse_nested" && bkey != "_sampler" {
			expanded := expandFromClauseRows(baseRows, fromClause, rangeWhere)
			cnt := int64(len(expanded))
			return []AggRow{{AggName: aggName, BucketKey: bkey, DocCount: cnt, Value: float64(cnt)}}
		}
	}

	return nil
}

func sortRowsByOrderClause(rows []map[string]any, orderByClause string) {
	orderSpecs := splitTopLevelArgs(orderByClause)
	sort.SliceStable(rows, func(i, j int) bool {
		for _, spec := range orderSpecs {
			colExpr, desc, nullsFirst := parseOrderSpec(spec)
			if colExpr == "" {
				continue
			}
			var cmp int
			switch colExpr {
			case "`_id`":
				cmp = strings.Compare(fmt.Sprintf("%v", rows[i]["_id"]), fmt.Sprintf("%v", rows[j]["_id"]))
			case "`_score`":
				sa, _ := toFloat(rows[i]["_score"])
				sb, _ := toFloat(rows[j]["_score"])
				if sa < sb {
					cmp = -1
				} else if sa > sb {
					cmp = 1
				}
			default:
				va := resolveColumnValue(rows[i], colExpr)
				vb := resolveColumnValue(rows[j], colExpr)
				if va == nil && vb == nil {
					continue
				}
				if va == nil {
					return nullsFirst
				}
				if vb == nil {
					return !nullsFirst
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

var (
	reLateralViewExplode = regexp.MustCompile("LATERAL VIEW EXPLODE\\((?:(CASE WHEN )`([^`]+)` IS NULL.+?END|`([^`]+)`)\\) `[^`]+` AS `([^`]+)`")
	reDedupSelectInner   = regexp.MustCompile("^SELECT DISTINCT `_id` AS `_rn_id(?:_\\d+)?`, (.+?) AS `(_rn_bkey(?:_\\d+)?)` FROM (.+)$")
	reDedupJoinTail      = regexp.MustCompile("^\\s*`_rn_dedup(?:_\\d+)?` ON `base_matched`\\.`_id` = `_rn_dedup(?:_\\d+)?`\\.`_rn_id(?:_\\d+)?`(.*)$")
)

func parseLeadingDedupJoin(fromClause string) (innerBucketExpr, bkeyAlias, innerFrom, innerWhere, tailFrom string, ok bool) {
	const prefix = "`base_matched` INNER JOIN ("
	trimmed := strings.TrimSpace(fromClause)
	if !strings.HasPrefix(trimmed, prefix) {
		return "", "", "", "", "", false
	}
	openIdx := len(prefix) - 1
	depth := 0
	inSingleQuote := false
	closeIdx := -1
	for i := openIdx; i < len(trimmed); i++ {
		ch := trimmed[i]
		if ch == '\'' {
			inSingleQuote = !inSingleQuote
			continue
		}
		if inSingleQuote {
			continue
		}
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
			if depth == 0 {
				closeIdx = i
				break
			}
		}
	}
	if closeIdx <= openIdx {
		return "", "", "", "", "", false
	}
	subquery := trimmed[openIdx+1 : closeIdx]
	afterParen := trimmed[closeIdx+1:]
	tm := reDedupJoinTail.FindStringSubmatch(afterParen)
	if tm == nil {
		return "", "", "", "", "", false
	}
	tailFrom = tm[1]
	sm := reDedupSelectInner.FindStringSubmatch(subquery)
	if sm == nil {
		return "", "", "", "", "", false
	}
	innerBucketExpr = sm[1]
	bkeyAlias = sm[2]
	fromAndWhere := sm[3]
	// Find top-level " WHERE " in fromAndWhere
	wDepth := 0
	wQuote := false
	wherePos := -1
	for i := 0; i <= len(fromAndWhere)-7; i++ {
		ch := fromAndWhere[i]
		if ch == '\'' {
			wQuote = !wQuote
			continue
		}
		if wQuote {
			continue
		}
		switch ch {
		case '(':
			wDepth++
		case ')':
			if wDepth > 0 {
				wDepth--
			}
		default:
			if wDepth == 0 && fromAndWhere[i:i+7] == " WHERE " {
				wherePos = i
			}
		}
	}
	if wherePos < 0 {
		innerFrom = strings.TrimSpace(fromAndWhere)
		innerWhere = ""
	} else {
		innerFrom = strings.TrimSpace(fromAndWhere[:wherePos])
		innerWhere = strings.TrimSpace(fromAndWhere[wherePos+7:])
	}
	return innerBucketExpr, bkeyAlias, innerFrom, innerWhere, tailFrom, true
}

func expandFromClauseRows(baseRows []map[string]any, fromClause, whereClause string) []map[string]any {
	currRows := baseRows
	if innerBucketExpr, bkeyAlias, innerFrom, innerWhere, tailFrom, ok := parseLeadingDedupJoin(fromClause); ok {
		innerRows := expandFromClauseRows(baseRows, innerFrom, innerWhere)
		baseByID := make(map[string]map[string]any, len(baseRows))
		for _, r := range baseRows {
			baseByID[fmt.Sprintf("%v", r["_id"])] = r
		}
		seen := make(map[string]bool)
		var deduped []map[string]any
		for _, r := range innerRows {
			idStr := fmt.Sprintf("%v", r["_id"])
			bKey := evalBucketKeyExpr(r, innerBucketExpr)
			if bKey == "" {
				continue
			}
			pairKey := idStr + "\x00" + bKey
			if seen[pairKey] {
				continue
			}
			seen[pairKey] = true
			if orig, ok := baseByID[idStr]; ok {
				cp := make(map[string]any, len(orig)+2)
				for k, v := range orig {
					cp[k] = v
				}
				cp[bkeyAlias] = bKey
				cp["_rn_bkey"] = bKey
				deduped = append(deduped, cp)
			}
		}
		currRows = deduped
		fromClause = tailFrom
	}
	explodes := reLateralViewExplode.FindAllStringSubmatch(fromClause, -1)
	for _, m := range explodes {
		isCaseNull := m[1] != ""
		explodeCol := m[2]
		if explodeCol == "" {
			explodeCol = m[3]
		}
		aliasName := m[4]
		var nextRows []map[string]any
		for _, row := range currRows {
			elems := toStringSlice(row[explodeCol])
			if len(elems) == 0 && isCaseNull {
				cp := make(map[string]any, len(row)+1)
				for k, v := range row {
					cp[k] = v
				}
				cp[aliasName] = nil
				nextRows = append(nextRows, cp)
				continue
			}
			for _, elem := range elems {
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
	reBucketDateHist = regexp.MustCompile(`^CAST\(CAST\(FLOOR\((?:\((.+?) \+ (-?\d+)\)|(.+?)) / (\d+)\) \* \d+(?: - -?\d+)? AS BIGINT\) AS STRING\)$`)
	reBucketHist     = regexp.MustCompile(`^CAST\(FLOOR\(\((.+?) - ([^)]+)\) / ([^)]+)\) \* [^)]+ \+ [^)]+ AS STRING\)$`)
)

func unescapeCONCATWSSeparator(rawLit string) string {
	sep := unquoteSQLLiteral(strings.TrimSpace(rawLit))
	if sep == `\x1f` {
		return "\x1f"
	}
	return sep
}

func evalBucketKeyExprs(row map[string]any, expr string) []string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "CONCAT_WS(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("CONCAT_WS(") : len(expr)-1]
		allArgs := splitTopLevelArgs(inner)
		if len(allArgs) >= 2 {
			sep := unescapeCONCATWSSeparator(allArgs[0])
			args := allArgs[1:]
			partials := [][]string{{}}
			for _, a := range args {
				vals := evalBucketKeyExprs(row, a)
				if len(vals) == 0 {
					return nil
				}
				var next [][]string
				for _, prev := range partials {
					for _, v := range vals {
						if v == "" {
							continue
						}
						next = append(next, append(append([]string(nil), prev...), v))
					}
				}
				partials = next
			}
			var out []string
			for _, p := range partials {
				if len(p) == len(args) {
					out = append(out, strings.Join(p, sep))
				}
			}
			return out
		}
	}
	if strings.HasPrefix(expr, "CONCAT(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("CONCAT(") : len(expr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 3 && (strings.TrimSpace(args[1]) == `'\x1f'` || strings.TrimSpace(args[1]) == "'\x1f'") {
			ps := evalBucketKeyExprs(row, args[0])
			cs := evalBucketKeyExprs(row, args[2])
			var out []string
			for _, p := range ps {
				if p == "" {
					continue
				}
				for _, c := range cs {
					if c != "" {
						out = append(out, p+"\x1f"+c)
					}
				}
			}
			return out
		}
	}
	if strings.HasPrefix(expr, "COALESCE(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("COALESCE(") : len(expr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 2 {
			vs := evalBucketKeyExprs(row, args[0])
			if len(vs) > 0 {
				return vs
			}
			m := unquoteSQLLiteral(strings.TrimSpace(args[1]))
			if m != "" {
				return []string{m}
			}
			return nil
		}
	}
	if m := reBucketDateHist.FindStringSubmatch(expr); m != nil {
		colExpr := m[3]
		var tzShiftMs int64
		if m[1] != "" {
			colExpr = m[1]
			tzShiftMs, _ = strconv.ParseInt(m[2], 10, 64)
		}
		intervalMs, _ := strconv.ParseInt(m[4], 10, 64)
		if intervalMs <= 0 {
			intervalMs = 86400000
		}
		if val := resolveColumnValue(row, colExpr); val != nil {
			var out []string
			seen := make(map[string]bool)
			for _, elem := range asSliceOrSingle(val) {
				if ts, ok := toInt64(elem); ok {
					b := int64(math.Floor(float64(ts+tzShiftMs)/float64(intervalMs)))*intervalMs - tzShiftMs
					s := strconv.FormatInt(b, 10)
					if !seen[s] {
						seen[s] = true
						out = append(out, s)
					}
				}
			}
			return out
		}
		return nil
	}
	if m := reBucketHist.FindStringSubmatch(expr); m != nil {
		colExpr, offsetStr, intervalStr := m[1], m[2], m[3]
		offset, _ := strconv.ParseFloat(offsetStr, 64)
		interval, _ := strconv.ParseFloat(intervalStr, 64)
		if interval <= 0 {
			interval = 1.0
		}
		if val := resolveColumnValue(row, colExpr); val != nil {
			var out []string
			seen := make(map[string]bool)
			for _, elem := range asSliceOrSingle(val) {
				if f, ok := toFloat(elem); ok {
					b := math.Round((math.Floor((f-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
					s := strconv.FormatFloat(b, 'f', -1, 64)
					if !seen[s] {
						seen[s] = true
						out = append(out, s)
					}
				}
			}
			return out
		}
		return nil
	}
	unwrapped := expr
	if strings.HasPrefix(unwrapped, "CAST(") && strings.HasSuffix(unwrapped, " AS STRING)") {
		unwrapped = strings.TrimSpace(unwrapped[len("CAST(") : len(unwrapped)-len(" AS STRING)")])
	}
	if strings.HasPrefix(unwrapped, "json_extract_string(") && strings.HasSuffix(unwrapped, ")") {
		inner := unwrapped[len("json_extract_string(") : len(unwrapped)-1]
		if commaIdx := strings.IndexByte(inner, ','); commaIdx > 0 {
			varName := strings.Trim(strings.TrimSpace(inner[:commaIdx]), "`")
			jsonPath := strings.TrimPrefix(unquoteSQLLiteral(strings.TrimSpace(inner[commaIdx+1:])), "$.")
			elemJSON, _ := row[varName].(string)
			res := extractJSONPathFromStr(elemJSON, strings.Split(jsonPath, "."))
			if arr, ok := res.([]any); ok {
				var out []string
				for _, item := range arr {
					if item != nil {
						if s := fmt.Sprintf("%v", item); s != "" {
							out = append(out, s)
						}
					}
				}
				return out
			}
		}
	}
	if rawVal := resolveColumnValue(row, unwrapped); rawVal != nil {
		switch tv := rawVal.(type) {
		case []any:
			var out []string
			for _, item := range tv {
				if item != nil {
					if s := fmt.Sprintf("%v", item); s != "" {
						out = append(out, s)
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		case []string:
			var out []string
			for _, s := range tv {
				if s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	if single := evalBucketKeyExpr(row, expr); single != "" {
		return []string{single}
	}
	return nil
}

func evalBucketKeyExpr(row map[string]any, expr string) string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "'") && strings.HasSuffix(expr, "'") {
		return unquoteSQLLiteral(expr)
	}
	if strings.HasPrefix(expr, "CONCAT_WS(") && strings.HasSuffix(expr, ")") {
		if vals := evalBucketKeyExprs(row, expr); len(vals) > 0 {
			return vals[0]
		}
		return ""
	}
	if strings.HasPrefix(expr, "CONCAT(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("CONCAT(") : len(expr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 3 && (strings.TrimSpace(args[1]) == `'\x1f'` || strings.TrimSpace(args[1]) == "'\x1f'") {
			p := evalBucketKeyExpr(row, args[0])
			c := evalBucketKeyExpr(row, args[2])
			if p == "" || c == "" {
				return ""
			}
			return p + "\x1f" + c
		}
	}
	if m := reBucketDateHist.FindStringSubmatch(expr); m != nil {
		colExpr := m[3]
		var tzShiftMs int64
		if m[1] != "" {
			colExpr = m[1]
			tzShiftMs, _ = strconv.ParseInt(m[2], 10, 64)
		}
		intervalStr := m[4]
		intervalMs, _ := strconv.ParseInt(intervalStr, 10, 64)
		if intervalMs <= 0 {
			intervalMs = 86400000
		}
		if val := resolveColumnValue(row, colExpr); val != nil {
			if ts, ok := toInt64(val); ok {
				b := int64(math.Floor(float64(ts+tzShiftMs)/float64(intervalMs)))*intervalMs - tzShiftMs
				return strconv.FormatInt(b, 10)
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
				b := math.Round((math.Floor((f-offset)/interval+1e-9)*interval+offset)*1e12) / 1e12
				return strconv.FormatFloat(b, 'f', -1, 64)
			}
		}
		return ""
	}
	if strings.HasPrefix(expr, "COALESCE(") && strings.HasSuffix(expr, ")") {
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
	if expr == "" || expr == "1=1" || strings.EqualFold(expr, "TRUE") {
		return true
	}
	if expr == "1=0" || expr == "0=1" || strings.EqualFold(expr, "FALSE") {
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
		args := splitTopLevelArgs(inner)
		if len(args) == 2 {
			arrowIdx := strings.Index(args[0], "->")
			if arrowIdx > 0 {
				varName := strings.TrimSpace(args[0][:arrowIdx])
				bodyExpr := strings.TrimSpace(args[0][arrowIdx+2:])
				colArg := strings.TrimSpace(args[1])
				colName := strings.Trim(colArg, "`")
				arrVal := row[colName]
				if arrVal == nil {
					arrVal = resolveColumnValue(row, colArg)
				}
				var parentNestedID string
				if strings.HasPrefix(varName, "_el") && len(varName) > 3 {
					parentVar := varName[:len(varName)-1]
					if parentJSON, ok := row[parentVar].(string); ok && parentJSON != "" {
						if pid := extractJSONPathFromStr(parentJSON, []string{"_nested_id"}); pid != nil {
							parentNestedID = fmt.Sprintf("%v", pid)
						}
					}
				}
				for _, elemStr := range toStringSlice(arrVal) {
					if parentNestedID != "" {
						if elemParent := extractJSONPathFromStr(elemStr, []string{"_parent_id"}); elemParent != nil {
							epStr := fmt.Sprintf("%v", elemParent)
							if epStr != parentNestedID && !strings.HasPrefix(epStr, parentNestedID+".") {
								continue
							}
						}
					}
					if evalLambdaBody(row, elemStr, varName, bodyExpr) {
						return true
					}
				}
				return false
			}
		}
	}

	if strings.HasPrefix(expr, "array_contains(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("array_contains(") : len(expr)-1]
		if args := splitTopLevelArgs(inner); len(args) == 2 {
			colExpr := strings.TrimSpace(args[0])
			target := unquoteSQLLiteral(strings.TrimSpace(args[1]))
			val := resolveColumnValue(row, colExpr)
			for _, item := range toStringSlice(val) {
				if item == target {
					return true
				}
			}
			return false
		}
	}

	if strings.HasPrefix(expr, "arrays_overlap(") && strings.HasSuffix(expr, ")") {
		inner := expr[len("arrays_overlap(") : len(expr)-1]
		if args := splitTopLevelArgs(inner); len(args) == 2 {
			colExpr := strings.TrimSpace(args[0])
			listArg := strings.TrimSpace(args[1])
			listStr := strings.TrimSuffix(strings.TrimPrefix(listArg, "["), "]")
			targets := make(map[string]bool)
			for _, part := range splitTopLevelArgs(listStr) {
				targets[unquoteSQLLiteral(strings.TrimSpace(part))] = true
			}
			val := resolveColumnValue(row, colExpr)
			for _, item := range toStringSlice(val) {
				if targets[item] {
					return true
				}
			}
			return false
		}
	}

	if strings.HasPrefix(expr, "array_size(") && strings.HasSuffix(expr, ") > 0") {
		colExpr := strings.TrimSpace(expr[len("array_size(") : len(expr)-len(") > 0")])
		return len(toStringSlice(resolveColumnValue(row, colExpr))) > 0
	}

	if strings.HasSuffix(expr, " IS NOT NULL") {
		colExpr := strings.TrimSpace(expr[:len(expr)-len(" IS NOT NULL")])
		val := resolveColumnValue(row, colExpr)
		if arr, ok := val.([]any); ok {
			return len(arr) > 0
		}
		if arr, ok := val.([]string); ok {
			return len(arr) > 0
		}
		return val != nil
	}
	if strings.HasSuffix(expr, " IS NULL") {
		colExpr := strings.TrimSpace(expr[:len(expr)-len(" IS NULL")])
		val := resolveColumnValue(row, colExpr)
		if arr, ok := val.([]any); ok {
			return len(arr) == 0
		}
		if arr, ok := val.([]string); ok {
			return len(arr) == 0
		}
		return val == nil
	}

	if strings.HasPrefix(expr, "SEARCH(") && strings.HasSuffix(expr, ")") {
		args := splitTopLevelArgs(expr[len("SEARCH(") : len(expr)-1])
		if len(args) >= 3 {
			dsl := unquoteSQLLiteral(strings.TrimSpace(args[0]))
			col := unquoteSQLLiteral(strings.TrimSpace(args[1]))
			op := strings.ToUpper(unquoteSQLLiteral(strings.TrimSpace(args[2])))
			if idx := strings.IndexByte(dsl, ':'); idx > 0 && !strings.ContainsAny(dsl, " \t()") {
				col = dsl[:idx]
				dsl = dsl[idx+1:]
			}
			matchOp := "MATCH_ANY"
			if op == "AND" {
				matchOp = "MATCH_ALL"
			}
			return evalFulltextMatch(row, "`"+col+"`", matchOp, dsl)
		}
	}

	for _, matchOp := range []string{" MATCH_PHRASE_PREFIX ", " MATCH_PHRASE ", " MATCH_REGEXP ", " MATCH_ALL ", " MATCH_ANY "} {
		if idx := findTopLevelOp(expr, matchOp); idx > 0 {
			colExpr := strings.TrimSpace(expr[:idx])
			lit := unquoteSQLLiteral(strings.TrimSpace(expr[idx+len(matchOp):]))
			return evalFulltextMatch(row, colExpr, strings.TrimSpace(matchOp), lit)
		}
	}

	if idx := findTopLevelOp(expr, " IN ("); idx > 0 && strings.HasSuffix(expr, ")") {
		colExpr := strings.TrimSpace(expr[:idx])
		negate := false
		if len(colExpr) > 4 && strings.EqualFold(colExpr[len(colExpr)-4:], " NOT") {
			negate = true
			colExpr = strings.TrimSpace(colExpr[:len(colExpr)-4])
		}
		listStr := expr[idx+len(" IN (") : len(expr)-1]
		val := resolveColumnValue(row, colExpr)
		if val == nil {
			return false
		}
		targets := make(map[string]bool)
		var parsedTargets []any
		for _, item := range splitTopLevelArgs(listStr) {
			unq := unquoteSQLLiteral(strings.TrimSpace(item))
			targets[unq] = true
			parsedTargets = append(parsedTargets, parseSQLLiteralValue(item))
		}
		matched := false
		for _, elem := range asSliceOrSingle(val) {
			if elem == nil {
				continue
			}
			if targets[fmt.Sprintf("%v", elem)] {
				matched = true
				break
			}
			for _, pt := range parsedTargets {
				if compareAny(elem, pt) == 0 {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if negate {
			return !matched
		}
		return matched
	}

	if idx := findTopLevelOp(expr, " LIKE "); idx > 0 {
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
		for _, elem := range asSliceOrSingle(val) {
			if elem != nil && evalLikePattern(fmt.Sprintf("%v", elem), pat, ci) {
				return true
			}
		}
		return false
	}

	if idx := findTopLevelOp(expr, " REGEXP "); idx > 0 {
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
		for _, elem := range asSliceOrSingle(val) {
			if elem != nil && re.MatchString(fmt.Sprintf("%v", elem)) {
				return true
			}
		}
		return false
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
			if isArithmeticSQLExpr(lhs) || strings.HasPrefix(lhs, "CAST(COALESCE(") {
				if hasUnwrappedNullColumnRef(row, lhs) {
					return false
				}
				lhsNum := evalNumericExpr(row, lhs)
				rhsNum, err := strconv.ParseFloat(rhs, 64)
				if err != nil {
					rhsNum = evalNumericExpr(row, rhs)
				}
				switch op {
				case ">=":
					return lhsNum >= rhsNum
				case "<=":
					return lhsNum <= rhsNum
				case "!=":
					return lhsNum != rhsNum
				case "=":
					return lhsNum == rhsNum
				case ">":
					return lhsNum > rhsNum
				case "<":
					return lhsNum < rhsNum
				}
			}
			val := resolveColumnValue(row, lhs)
			if val == nil {
				return false
			}
			var rhsVal any
			if strings.HasPrefix(rhs, "json_extract_string(") || (strings.HasPrefix(rhs, "`") && strings.HasSuffix(rhs, "`")) || isArithmeticSQLExpr(rhs) || strings.HasPrefix(rhs, "CAST(") || strings.HasPrefix(rhs, "COALESCE(") {
				rhsVal = resolveColumnValue(row, rhs)
				if rhsVal == nil {
					return false
				}
			} else {
				rhsVal = parseSQLLiteralValue(rhs)
			}
			if ci {
				rhsVal = strings.ToLower(fmt.Sprintf("%v", rhsVal))
			}
			for _, elem := range asSliceOrSingle(val) {
				if elem == nil {
					continue
				}
				elemVal := elem
				if ci {
					elemVal = strings.ToLower(fmt.Sprintf("%v", elemVal))
				}
				cmp := compareAny(elemVal, rhsVal)
				matched := false
				switch op {
				case "=":
					matched = cmp == 0
				case "!=":
					matched = cmp != 0
				case ">":
					matched = cmp > 0
				case ">=":
					matched = cmp >= 0
				case "<":
					matched = cmp < 0
				case "<=":
					matched = cmp <= 0
				}
				if matched {
					return true
				}
			}
			return false
		}
	}

	return false
}

func asSliceOrSingle(val any) []any {
	switch v := val.(type) {
	case nil:
		return nil
	case []any:
		return v
	case []string:
		out := make([]any, len(v))
		for i, s := range v {
			out[i] = s
		}
		return out
	default:
		return []any{val}
	}
}

func evalLambdaBody(outerRow map[string]any, elemStr, varName, bodyExpr string) bool {
	bodyExpr = trimOuterParens(strings.TrimSpace(bodyExpr))
	if parts := splitTopLevelLogicalOp(bodyExpr, " OR "); len(parts) > 1 {
		for _, p := range parts {
			if evalLambdaBody(outerRow, elemStr, varName, p) {
				return true
			}
		}
		return false
	}
	if parts := splitTopLevelLogicalOp(bodyExpr, " AND "); len(parts) > 1 {
		for _, p := range parts {
			if !evalLambdaBody(outerRow, elemStr, varName, p) {
				return false
			}
		}
		return true
	}

	syntheticRow := make(map[string]any, len(outerRow)+1)
	for k, v := range outerRow {
		syntheticRow[k] = v
	}
	syntheticRow[varName] = elemStr
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
		phraseTokens := tokenizeWords(cleanPhrase)
		docTokens := tokenizeWords(combined)
		if len(phraseTokens) == 0 {
			return cleanPhrase != "" && strings.Contains(combined, cleanPhrase)
		}
		if len(docTokens) < len(phraseTokens) {
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
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
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

	if parts := splitTopLevelBinaryMath(expr, '+'); len(parts) > 1 {
		sum := 0.0
		for _, p := range parts {
			sum += evalNumericExpr(row, p)
		}
		return sum
	}

	if parts := splitTopLevelBinaryMath(expr, '-'); len(parts) > 1 {
		res := evalNumericExpr(row, parts[0])
		for _, p := range parts[1:] {
			res -= evalNumericExpr(row, p)
		}
		return res
	}

	if parts := splitTopLevelBinaryMath(expr, '*'); len(parts) > 1 {
		prod := 1.0
		for _, p := range parts {
			prod *= evalNumericExpr(row, p)
		}
		return prod
	}

	if parts := splitTopLevelBinaryMath(expr, '/'); len(parts) >= 2 {
		res := evalNumericExpr(row, parts[0])
		for _, p := range parts[1:] {
			denom := evalNumericExpr(row, p)
			if denom == 0 {
				return 0
			}
			res /= denom
		}
		return res
	}

	if parts := splitTopLevelBinaryMath(expr, '%'); len(parts) >= 2 {
		res := evalNumericExpr(row, parts[0])
		for _, p := range parts[1:] {
			denom := evalNumericExpr(row, p)
			if denom == 0 {
				return 0
			}
			res = math.Mod(res, denom)
		}
		return res
	}

	if strings.HasPrefix(expr, "-") {
		return -evalNumericExpr(row, strings.TrimSpace(expr[1:]))
	}
	if strings.HasPrefix(expr, "+") {
		return evalNumericExpr(row, strings.TrimSpace(expr[1:]))
	}

	if strings.HasPrefix(expr, "CASE WHEN ") && strings.HasSuffix(expr, " END") {
		inner := expr[len("CASE WHEN ") : len(expr)-len(" END")]
		elseIdx := findTopLevelOp(inner, " ELSE ")
		var elseExpr string
		whenChain := inner
		if elseIdx > 0 {
			elseExpr = inner[elseIdx+6:]
			whenChain = inner[:elseIdx]
		}
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
		if elseIdx > 0 {
			return evalNumericExpr(row, elseExpr)
		}
		return 0
	}

	if expr == "RAND()" {
		// #nosec G404 -- non-cryptographic SQL RAND() emulation for unseeded random_score
		return rand.Float64()
	}
	if strings.HasPrefix(expr, "CONV(SUBSTRING(MD5(CONCAT(") && strings.HasSuffix(expr, ")), 1, 8), 16, 10)") {
		inner := expr[len("CONV(SUBSTRING(MD5(CONCAT(") : len(expr)-len(")), 1, 8), 16, 10)")]
		var sb strings.Builder
		for _, arg := range splitTopLevelArgs(inner) {
			val := resolveColumnValue(row, strings.TrimSpace(arg))
			if val != nil {
				_, _ = fmt.Fprintf(&sb, "%v", val)
			}
		}
		// #nosec G401 -- used only to emulate Doris MD5() SQL function in MemoryBackend
		sum := md5.Sum([]byte(sb.String()))
		hexStr := hex.EncodeToString(sum[:])
		if len(hexStr) >= 8 {
			if u, err := strconv.ParseUint(hexStr[:8], 16, 64); err == nil {
				return float64(u)
			}
		}
		return 0
	}

	if strings.HasPrefix(expr, "CAST(COALESCE(") && strings.HasSuffix(expr, ", FALSE) AS INT)") {
		inner := expr[len("CAST(COALESCE(") : len(expr)-len(", FALSE) AS INT)")]
		if evalWhereExpr(row, inner) {
			return 1
		}
		return 0
	}

	if strings.HasPrefix(expr, "CAST(") && !strings.HasPrefix(expr, "CAST(`_doc`") {
		for _, suffix := range []string{" AS DOUBLE)", " AS BIGINT)", " AS INT)"} {
			if strings.HasSuffix(expr, suffix) {
				inner := strings.TrimSpace(expr[len("CAST:") : len(expr)-len(suffix)])
				if strings.HasPrefix(expr, "CAST(") {
					inner = strings.TrimSpace(expr[len("CAST(") : len(expr)-len(suffix)])
				}
				return evalNumericExpr(row, inner)
			}
		}
	}

	for _, fn := range []string{"GREATEST", "LEAST", "COALESCE", "POW", "LOG10", "LN", "SQRT", "FLOOR", "CEIL", "ROUND", "TRUNCATE", "ABS"} {
		if strings.HasPrefix(expr, fn+"(") && strings.HasSuffix(expr, ")") {
			inner := expr[len(fn)+1 : len(expr)-1]
			args := splitTopLevelArgs(inner)
			switch fn {
			case "POW":
				if len(args) == 2 {
					return math.Pow(evalNumericExpr(row, args[0]), evalNumericExpr(row, args[1]))
				}
			case "TRUNCATE":
				if len(args) >= 1 {
					return math.Trunc(evalNumericExpr(row, args[0]))
				}
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
				for i, rawArg := range args {
					arg := strings.TrimSpace(rawArg)
					if strings.EqualFold(arg, "NULL") {
						continue
					}
					if colVal := resolveColumnValue(row, arg); colVal != nil {
						if f, ok := toFloat(colVal); ok {
							return f
						}
						switch sv := colVal.(type) {
						case []any:
							for _, el := range sv {
								if f, ok := toFloat(el); ok {
									return f
								}
							}
						case []float64:
							if len(sv) > 0 {
								return sv[0]
							}
						case []string:
							for _, el := range sv {
								if f, ok := toFloat(el); ok {
									return f
								}
							}
						}
					}
					if i == len(args)-1 {
						return evalNumericExpr(row, arg)
					}
				}
			case "LOG10":
				return math.Log10(evalNumericExpr(row, inner))
			case "LN":
				return math.Log(evalNumericExpr(row, inner))
			case "SQRT":
				return math.Sqrt(evalNumericExpr(row, inner))
			case "FLOOR":
				return math.Floor(evalNumericExpr(row, inner))
			case "CEIL":
				return math.Ceil(evalNumericExpr(row, inner))
			case "ROUND":
				return math.Round(evalNumericExpr(row, inner))
			case "ABS":
				return math.Abs(evalNumericExpr(row, inner))
			}
		}
	}

	val := resolveColumnValue(row, expr)
	if f, ok := toFloat(val); ok {
		return f
	}
	return 0
}

func resolveColumnValue(row map[string]any, colExpr string) any {
	colExpr = trimOuterParens(strings.TrimSpace(colExpr))
	if strings.HasPrefix(colExpr, "CONCAT_WS(") && strings.HasSuffix(colExpr, ")") {
		vals := evalBucketKeyExprs(row, colExpr)
		if len(vals) == 1 {
			return vals[0]
		}
		if len(vals) > 1 {
			return vals
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "`") && strings.HasSuffix(colExpr, "`") {
		colName := strings.Trim(colExpr, "`")
		if val := row[colName]; val != nil {
			return val
		}
		if strings.HasPrefix(colName, "n__") {
			return extractDynamicNestedJSONElementsFromRow(row, strings.TrimPrefix(colName, "n__"))
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "'") && strings.HasSuffix(colExpr, "'") {
		return unquoteSQLLiteral(colExpr)
	}
	if val, ok := row[colExpr]; ok {
		return val
	}
	if f, err := strconv.ParseFloat(colExpr, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
		return f
	}
	if strings.HasPrefix(colExpr, "element_at(") && strings.HasSuffix(colExpr, ", 1)") {
		inner := strings.TrimSpace(colExpr[len("element_at(") : len(colExpr)-len(", 1)")])
		elems := toStringSlice(resolveColumnValue(row, inner))
		if len(elems) > 0 {
			return elems[0]
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "array_map(_x -> CAST(_x AS DOUBLE), ") && strings.HasSuffix(colExpr, ")") {
		inner := strings.TrimSpace(colExpr[len("array_map(_x -> CAST(_x AS DOUBLE), ") : len(colExpr)-1])
		return resolveColumnValue(row, inner)
	}
	if strings.HasPrefix(colExpr, "array_map(_x -> CAST(_x AS BIGINT), ") && strings.HasSuffix(colExpr, ")") {
		inner := strings.TrimSpace(colExpr[len("array_map(_x -> CAST(_x AS BIGINT), ") : len(colExpr)-1])
		return resolveColumnValue(row, inner)
	}
	if strings.HasPrefix(colExpr, "array_map(_el -> json_extract_string(_el, ") && strings.HasSuffix(colExpr, ")") {
		args := splitTopLevelArgs(colExpr[len("array_map(") : len(colExpr)-1])
		if len(args) == 2 {
			lambda := strings.TrimSpace(args[0])
			if strings.HasPrefix(lambda, "_el -> json_extract_string(_el,") && strings.HasSuffix(lambda, ")") {
				pathLit := strings.TrimSpace(lambda[len("_el -> json_extract_string(_el,") : len(lambda)-1])
				relPath := strings.TrimPrefix(unquoteSQLLiteral(pathLit), "$.")
				var out []any
				for _, elemJSON := range toStringSlice(resolveColumnValue(row, strings.TrimSpace(args[1]))) {
					if v := extractJSONPathFromStr(elemJSON, strings.Split(relPath, ".")); v != nil {
						for _, sub := range asSliceOrSingle(v) {
							if sub != nil {
								out = append(out, sub)
							}
						}
					}
				}
				if len(out) == 0 {
					return nil
				}
				return out
			}
		}
	}
	if strings.HasPrefix(colExpr, "array_filter(_el -> ") && strings.HasSuffix(colExpr, ")") {
		args := splitTopLevelArgs(colExpr[len("array_filter(") : len(colExpr)-1])
		if len(args) == 2 {
			condSQL := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(args[0]), "_el ->"))
			var out []string
			for _, elemJSON := range toStringSlice(resolveColumnValue(row, strings.TrimSpace(args[1]))) {
				cp := make(map[string]any, len(row)+1)
				for k, v := range row {
					cp[k] = v
				}
				cp["_el"] = elemJSON
				if evalWhereExpr(cp, condSQL) {
					out = append(out, elemJSON)
				}
			}
			return out
		}
	}
	if strings.HasPrefix(colExpr, "array_map(_x -> IPV4_STRING_TO_NUM_OR_NULL(_x), ") && strings.HasSuffix(colExpr, ")") {
		inner := strings.TrimSpace(colExpr[len("array_map(_x -> IPV4_STRING_TO_NUM_OR_NULL(_x), ") : len(colExpr)-1])
		var out []any
		for _, elem := range toStringSlice(resolveColumnValue(row, inner)) {
			if ipNum, ok := parseIPv4SortUint32(elem); ok {
				out = append(out, int64(ipNum))
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	if strings.HasPrefix(colExpr, "array_map(_x -> ") && strings.HasSuffix(colExpr, ")") {
		args := splitTopLevelArgs(colExpr[len("array_map(") : len(colExpr)-1])
		if len(args) == 2 {
			bodyExpr := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(args[0]), "_x ->"))
			var out []any
			for _, elem := range toStringSlice(resolveColumnValue(row, strings.TrimSpace(args[1]))) {
				cp := make(map[string]any, len(row)+1)
				for k, v := range row {
					cp[k] = v
				}
				cp["_x"] = elem
				if mv := resolveColumnValue(cp, bodyExpr); mv != nil {
					out = append(out, mv)
				}
			}
			if len(out) == 0 {
				return nil
			}
			return out
		}
	}
	if strings.HasPrefix(colExpr, "array_median(") && strings.HasSuffix(colExpr, ")") {
		inner := strings.TrimSpace(colExpr[len("array_median(") : len(colExpr)-1])
		elems := toStringSlice(resolveColumnValue(row, inner))
		var nums []float64
		for _, e := range elems {
			if f, ok := toFloat(e); ok {
				nums = append(nums, f)
			}
		}
		if len(nums) == 0 {
			return nil
		}
		sort.Float64s(nums)
		mid := len(nums) / 2
		if len(nums)%2 == 1 {
			return nums[mid]
		}
		return (nums[mid-1] + nums[mid]) / 2.0
	}
	if (strings.HasPrefix(colExpr, "array_min(") || strings.HasPrefix(colExpr, "array_max(") || strings.HasPrefix(colExpr, "array_avg(") || strings.HasPrefix(colExpr, "array_sum(")) && strings.HasSuffix(colExpr, ")") {
		fn := colExpr[:len("array_min")]
		inner := strings.TrimSpace(colExpr[len("array_min(") : len(colExpr)-1])
		elems := toStringSlice(resolveColumnValue(row, inner))
		if len(elems) == 0 {
			return nil
		}
		if fn == "array_avg" || fn == "array_sum" {
			var sum float64
			var cnt int
			for _, e := range elems {
				if f, ok := toFloat(e); ok {
					sum += f
					cnt++
				}
			}
			if cnt == 0 {
				return nil
			}
			if fn == "array_avg" {
				return sum / float64(cnt)
			}
			return sum
		}
		isMax := fn == "array_max"
		best := elems[0]
		for _, e := range elems[1:] {
			var cmp int
			if ipE, okE := parseIPv4SortUint32(e); okE {
				if ipBest, okBest := parseIPv4SortUint32(best); okBest {
					if ipE < ipBest {
						cmp = -1
					} else if ipE > ipBest {
						cmp = 1
					}
				} else {
					cmp = compareAny(e, best)
				}
			} else {
				cmp = compareAny(e, best)
			}
			if (!isMax && cmp < 0) || (isMax && cmp > 0) {
				best = e
			}
		}
		if strings.HasPrefix(inner, "array_map(_x -> CAST(_x AS LARGEINT), ") {
			if bi, ok := memParseExactBigInt(best); ok {
				return memNormalizeExactIntValue(bi)
			}
		}
		if strings.HasPrefix(inner, "array_map(_x -> CAST(_x AS BIGINT), ") {
			if iv, ok := toInt64(best); ok {
				return iv
			}
		}
		if strings.HasPrefix(inner, "array_map(_x -> CAST(_x AS DOUBLE), ") {
			if fv, ok := toFloat(best); ok {
				return fv
			}
		}
		return best
	}
	if strings.HasPrefix(colExpr, "COALESCE(") && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("COALESCE(") : len(colExpr)-1]
		args := splitTopLevelArgs(inner)
		for i, rawArg := range args {
			arg := strings.TrimSpace(rawArg)
			if strings.EqualFold(arg, "NULL") {
				continue
			}
			if v := resolveColumnValue(row, arg); v != nil && fmt.Sprintf("%v", v) != "" {
				return v
			}
			if strings.HasPrefix(arg, "'") && strings.HasSuffix(arg, "'") {
				if lit := unquoteSQLLiteral(arg); lit != "" {
					return lit
				}
			} else if f, err := strconv.ParseFloat(arg, 64); err == nil {
				return f
			} else if i == len(args)-1 && (strings.EqualFold(arg, "TRUE") || strings.EqualFold(arg, "FALSE")) {
				return strings.EqualFold(arg, "TRUE")
			}
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "HEX(IPV6_STRING_TO_NUM_OR_NULL(") && strings.HasSuffix(colExpr, "))") {
		inner := colExpr[len("HEX(IPV6_STRING_TO_NUM_OR_NULL(") : len(colExpr)-2]
		if v := resolveColumnValue(row, inner); v != nil {
			switch sliceVal := v.(type) {
			case []any, []string:
				var out []any
				for _, elem := range asSliceOrSingle(sliceVal) {
					if ip := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", elem))); ip != nil {
						if ip16 := ip.To16(); len(ip16) == 16 {
							out = append(out, strings.ToUpper(hex.EncodeToString(ip16)))
						}
					}
				}
				if len(out) == 0 {
					return nil
				}
				return out
			default:
				if ip := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", v))); ip != nil {
					if ip16 := ip.To16(); len(ip16) == 16 {
						return strings.ToUpper(hex.EncodeToString(ip16))
					}
				}
			}
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "IPV4_STRING_TO_NUM_OR_NULL(") && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("IPV4_STRING_TO_NUM_OR_NULL(") : len(colExpr)-1]
		if v := resolveColumnValue(row, inner); v != nil {
			switch sliceVal := v.(type) {
			case []any, []string:
				var out []any
				for _, elem := range asSliceOrSingle(sliceVal) {
					if ip := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", elem))); ip != nil {
						if ip4 := ip.To4(); ip4 != nil {
							out = append(out, int64(uint32(ip4[0])<<24|uint32(ip4[1])<<16|uint32(ip4[2])<<8|uint32(ip4[3])))
						}
					}
				}
				if len(out) == 0 {
					return nil
				}
				return out
			default:
				if ip := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", v))); ip != nil {
					if ip4 := ip.To4(); ip4 != nil {
						return int64(uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]))
					}
				}
			}
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "CHAR_LENGTH(") && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("CHAR_LENGTH(") : len(colExpr)-1]
		if v := resolveColumnValue(row, inner); v != nil {
			switch sliceVal := v.(type) {
			case []any, []string:
				var out []any
				for _, elem := range asSliceOrSingle(sliceVal) {
					if elem != nil {
						out = append(out, int64(len([]rune(fmt.Sprintf("%v", elem)))))
					}
				}
				return out
			default:
				return int64(len([]rune(fmt.Sprintf("%v", v))))
			}
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "json_extract_string(") && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("json_extract_string(") : len(colExpr)-1]
		commaIdx := strings.IndexByte(inner, ',')
		if commaIdx > 0 {
			varName := strings.Trim(strings.TrimSpace(inner[:commaIdx]), "`")
			jsonPath := strings.TrimPrefix(unquoteSQLLiteral(strings.TrimSpace(inner[commaIdx+1:])), "$.")
			elemJSON, _ := row[varName].(string)
			res := extractJSONPathFromStr(elemJSON, strings.Split(jsonPath, "."))
			if rv, ok := res.(map[string]any); ok {
				if b, err := json.Marshal(rv); err == nil {
					return string(b)
				}
			}
			return res
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
			if docVal, hasDoc := row["_doc"]; hasDoc && docVal != nil {
				if docStr, ok := docVal.(string); ok {
					srcStr = docStr
				} else if docBytes, err := json.Marshal(docVal); err == nil {
					srcStr = string(docBytes)
				}
			}
			res := extractJSONPathFromStr(srcStr, segs)
			if res == nil && len(segs) == 1 && segs[0] == "_ignored" {
				res = row["_ignored"]
			}
			if res != nil {
				if strings.HasSuffix(colExpr, " AS LARGEINT)") {
					return memCoerceSQLLargeInt(res)
				} else if strings.HasSuffix(colExpr, " AS BIGINT)") {
					if iv, ok := toInt64(res); ok {
						return iv
					}
					if s, ok := res.(string); ok {
						if ms, ok := schema.ParseESDateToEpochMillis(s, time.Now().UTC()); ok {
							return ms
						}
					}
				} else if strings.HasSuffix(colExpr, " AS DOUBLE)") {
					if fv, ok := toFloat(res); ok {
						return fv
					}
				} else if strings.HasSuffix(colExpr, " AS ARRAY<STRING>)") {
					return memCoerceVariantToArrayOfString(res)
				} else if strings.HasSuffix(colExpr, " AS BOOLEAN)") {
					switch res.(type) {
					case []any, []string:
						var out []any
						for _, elem := range asSliceOrSingle(res) {
							if bv, ok := coerceSQLBool(elem); ok {
								out = append(out, bv)
							}
						}
						if len(out) == 0 {
							return nil
						}
						return out
					default:
						if bv, ok := coerceSQLBool(res); ok {
							return bv
						}
						return nil
					}
				}
			}
			return res
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
	if (strings.HasPrefix(colExpr, "SPLIT_PART(") || strings.HasPrefix(colExpr, "split_part(")) && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("SPLIT_PART(") : len(colExpr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 3 {
			strVal := resolveColumnValue(row, strings.TrimSpace(args[0]))
			delim := unquoteSQLLiteral(strings.TrimSpace(args[1]))
			idx, err := strconv.Atoi(strings.TrimSpace(args[2]))
			if strVal != nil && err == nil && idx >= 1 {
				parts := strings.Split(fmt.Sprintf("%v", strVal), delim)
				if idx <= len(parts) {
					return strings.TrimSpace(parts[idx-1])
				}
				return ""
			}
		}
		return nil
	}
	if (strings.HasPrefix(colExpr, "LPAD(") || strings.HasPrefix(colExpr, "lpad(")) && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("LPAD(") : len(colExpr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 3 {
			strVal := resolveColumnValue(row, strings.TrimSpace(args[0]))
			targetLen, err := strconv.Atoi(strings.TrimSpace(args[1]))
			padStr := unquoteSQLLiteral(strings.TrimSpace(args[2]))
			if strVal != nil && err == nil && targetLen >= 0 {
				s := fmt.Sprintf("%v", strVal)
				if len(s) >= targetLen {
					return s[:targetLen]
				}
				if padStr == "" {
					return s
				}
				need := targetLen - len(s)
				var sb strings.Builder
				sb.Grow(targetLen)
				for sb.Len() < need {
					rem := need - sb.Len()
					if rem >= len(padStr) {
						sb.WriteString(padStr)
					} else {
						sb.WriteString(padStr[:rem])
					}
				}
				sb.WriteString(s)
				return sb.String()
			}
		}
		return nil
	}
	if (strings.HasPrefix(colExpr, "IF(") || strings.HasPrefix(colExpr, "if(")) && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("IF(") : len(colExpr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 3 {
			chosen := strings.TrimSpace(args[2])
			if evalWhereExpr(row, strings.TrimSpace(args[0])) {
				chosen = strings.TrimSpace(args[1])
			}
			if strings.EqualFold(chosen, "NULL") {
				return nil
			}
			return resolveColumnValue(row, chosen)
		}
		return nil
	}
	if (strings.HasPrefix(colExpr, "LOCATE(") || strings.HasPrefix(colExpr, "locate(")) && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("LOCATE(") : len(colExpr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 2 {
			sub := unquoteSQLLiteral(strings.TrimSpace(args[0]))
			strVal := resolveColumnValue(row, strings.TrimSpace(args[1]))
			if strVal != nil {
				idx := strings.Index(fmt.Sprintf("%v", strVal), sub)
				if idx < 0 {
					return int64(0)
				}
				return int64(idx + 1)
			}
		}
		return nil
	}
	if (strings.HasPrefix(colExpr, "SUBSTRING(") || strings.HasPrefix(colExpr, "substring(")) && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("SUBSTRING(") : len(colExpr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 2 || len(args) == 3 {
			strVal := resolveColumnValue(row, strings.TrimSpace(args[0]))
			if strVal != nil {
				s := fmt.Sprintf("%v", strVal)
				pos := int(evalNumericExpr(row, strings.TrimSpace(args[1])))
				if pos < 1 {
					pos = 1
				}
				if pos > len(s) {
					return ""
				}
				sub := s[pos-1:]
				if len(args) == 3 {
					length := int(evalNumericExpr(row, strings.TrimSpace(args[2])))
					if length <= 0 {
						return ""
					}
					if length < len(sub) {
						sub = sub[:length]
					}
				}
				return sub
			}
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "ST_Distance_Sphere(") && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("ST_Distance_Sphere(") : len(colExpr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 4 {
			tLon, errLon := strconv.ParseFloat(strings.TrimSpace(args[2]), 64)
			tLat, errLat := strconv.ParseFloat(strings.TrimSpace(args[3]), 64)
			if errLon == nil && errLat == nil {
				lonExpr := strings.TrimSpace(args[0])
				if docIdx := strings.Index(lonExpr, "CAST(`_doc`"); docIdx >= 0 {
					docSub := lonExpr[docIdx:]
					if asIdx := strings.Index(docSub, " AS "); asIdx > 0 {
						pathPart := docSub[len("CAST(`_doc`"):asIdx]
						var segs []string
						for _, p := range strings.Split(pathPart, "['") {
							p = strings.TrimSuffix(p, "']")
							if p != "" {
								p = strings.ReplaceAll(p, "''", "'")
								p = strings.ReplaceAll(p, `\\`, `\`)
								segs = append(segs, p)
							}
						}
						if len(segs) > 1 && segs[len(segs)-1] == "lon" {
							segs = segs[:len(segs)-1]
						}
						srcStr, _ := row["_source"].(string)
						if srcStr != "" {
							var doc map[string]any
							if json.Unmarshal([]byte(srcStr), &doc) == nil {
								pts := collectGeoPointsAtPath(doc, segs)
								if len(pts) > 0 {
									minDist := math.MaxFloat64
									for _, pt := range pts {
										d := haversineDistanceMeters(tLat, tLon, pt[0], pt[1])
										if d < minDist {
											minDist = d
										}
									}
									return minDist
								}
							}
						}
					}
				}
				lonVal := resolveColumnValue(row, lonExpr)
				latVal := resolveColumnValue(row, strings.TrimSpace(args[1]))
				if lonF, ok1 := toFloat(lonVal); ok1 {
					if latF, ok2 := toFloat(latVal); ok2 {
						return haversineDistanceMeters(tLat, tLon, latF, lonF)
					}
				}
			}
		}
		return nil
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
	if (strings.HasPrefix(colExpr, "lower(") || strings.HasPrefix(colExpr, "LOWER(")) && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("lower(") : len(colExpr)-1]
		if v := resolveColumnValue(row, inner); v != nil {
			switch sliceVal := v.(type) {
			case []any, []string:
				var out []any
				for _, elem := range asSliceOrSingle(sliceVal) {
					out = append(out, strings.ToLower(fmt.Sprintf("%v", elem)))
				}
				return out
			default:
				return strings.ToLower(fmt.Sprintf("%v", v))
			}
		}
		return nil
	}
	if (strings.HasPrefix(colExpr, "upper(") || strings.HasPrefix(colExpr, "UPPER(")) && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("upper(") : len(colExpr)-1]
		if v := resolveColumnValue(row, inner); v != nil {
			switch sliceVal := v.(type) {
			case []any, []string:
				var out []any
				for _, elem := range asSliceOrSingle(sliceVal) {
					out = append(out, strings.ToUpper(fmt.Sprintf("%v", elem)))
				}
				return out
			default:
				return strings.ToUpper(fmt.Sprintf("%v", v))
			}
		}
		return nil
	}
	if (strings.HasPrefix(colExpr, "trim(") || strings.HasPrefix(colExpr, "TRIM(")) && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("trim(") : len(colExpr)-1]
		if v := resolveColumnValue(row, inner); v != nil {
			switch sliceVal := v.(type) {
			case []any, []string:
				var out []any
				for _, elem := range asSliceOrSingle(sliceVal) {
					out = append(out, strings.TrimSpace(fmt.Sprintf("%v", elem)))
				}
				return out
			default:
				return strings.TrimSpace(fmt.Sprintf("%v", v))
			}
		}
		return nil
	}
	if (strings.HasPrefix(colExpr, "DATE_FORMAT(") || strings.HasPrefix(colExpr, "date_format(")) && strings.HasSuffix(colExpr, ")") {
		inner := colExpr[len("DATE_FORMAT(") : len(colExpr)-1]
		args := splitTopLevelArgs(inner)
		if len(args) == 2 {
			tsArg := strings.TrimSpace(args[0])
			fmtStr := unquoteSQLLiteral(strings.TrimSpace(args[1]))
			if (strings.HasPrefix(tsArg, "FROM_UNIXTIME(") || strings.HasPrefix(tsArg, "from_unixtime(")) && strings.HasSuffix(tsArg, ")") {
				tsArg = strings.TrimSpace(tsArg[len("FROM_UNIXTIME(") : len(tsArg)-1])
			}
			rawVal := resolveColumnValue(row, tsArg)
			if rawVal == nil && isArithmeticSQLExpr(tsArg) {
				rawVal = evalNumericExpr(row, tsArg)
			}
			if rawVal != nil {
				var t time.Time
				hasTime := false
				if fv, ok := toFloat(rawVal); ok {
					if fv > 1e11 || fv < -1e11 {
						t = time.UnixMilli(int64(fv)).UTC()
					} else {
						sec := int64(math.Floor(fv))
						nsec := int64(math.Round((fv - float64(sec)) * 1e9))
						t = time.Unix(sec, nsec).UTC()
					}
					hasTime = true
				} else if sv, ok := rawVal.(string); ok {
					if ms, ok := schema.ParseESDateToEpochMillis(sv, time.Now().UTC()); ok {
						t = time.UnixMilli(ms).UTC()
						hasTime = true
					}
				}
				if hasTime {
					var out strings.Builder
					for i := 0; i < len(fmtStr); i++ {
						if fmtStr[i] == '%' && i+1 < len(fmtStr) {
							i++
							switch fmtStr[i] {
							case 'Y':
								out.WriteString(t.Format("2006"))
							case 'm':
								out.WriteString(t.Format("01"))
							case 'd':
								out.WriteString(t.Format("02"))
							case 'H':
								out.WriteString(t.Format("15"))
							case 'i':
								out.WriteString(t.Format("04"))
							case 's':
								out.WriteString(t.Format("05"))
							case 'T':
								out.WriteString(t.Format("15:04:05"))
							case 'F':
								out.WriteString(t.Format("2006-01-02"))
							case 'f':
								_, _ = fmt.Fprintf(&out, "%06d", t.Nanosecond()/1000)
							case '%':
								out.WriteByte('%')
							default:
								out.WriteByte('%')
								out.WriteByte(fmtStr[i])
							}
						} else {
							out.WriteByte(fmtStr[i])
						}
					}
					return out.String()
				}
			}
		}
		return nil
	}
	if (strings.HasPrefix(colExpr, "CONCAT(") || strings.HasPrefix(colExpr, "concat(")) && strings.HasSuffix(colExpr, ")") && !strings.Contains(colExpr, "'\\x1f'") {
		inner := colExpr[len("CONCAT(") : len(colExpr)-1]
		args := splitTopLevelArgs(inner)
		var sb strings.Builder
		for _, a := range args {
			v := resolveColumnValue(row, strings.TrimSpace(a))
			if v == nil {
				return nil
			}
			_, _ = fmt.Fprintf(&sb, "%v", v)
		}
		return sb.String()
	}
	if (strings.HasPrefix(colExpr, "LENGTH(") || strings.HasPrefix(colExpr, "CHAR_LENGTH(")) && strings.HasSuffix(colExpr, ")") {
		isCharLen := strings.HasPrefix(colExpr, "CHAR_LENGTH(")
		prefixLen := len("LENGTH(")
		if isCharLen {
			prefixLen = len("CHAR_LENGTH(")
		}
		inner := colExpr[prefixLen : len(colExpr)-1]
		measureStr := func(s string) int64 {
			if isCharLen {
				return int64(utf8.RuneCountInString(s))
			}
			return int64(len(s))
		}
		if v := resolveColumnValue(row, inner); v != nil {
			switch sliceVal := v.(type) {
			case []any, []string:
				var out []any
				for _, elem := range asSliceOrSingle(sliceVal) {
					if elem != nil {
						out = append(out, measureStr(fmt.Sprintf("%v", elem)))
					}
				}
				return out
			default:
				return measureStr(fmt.Sprintf("%v", v))
			}
		}
		return nil
	}
	if strings.HasPrefix(colExpr, "CAST(") && !strings.HasPrefix(colExpr, "CAST(`_doc`") {
		if asJSONIdx := strings.Index(colExpr, " AS JSON)["); asJSONIdx > len("CAST(") && strings.HasSuffix(colExpr, "]") && findTopLevelOp(colExpr, " AS ") < 0 {
			innerVar := strings.TrimSpace(colExpr[len("CAST("):asJSONIdx])
			pathPart := colExpr[asJSONIdx+len(" AS JSON)"):]
			rawVal := resolveColumnValue(row, innerVar)
			if rawVal == nil {
				return nil
			}
			var rawStr string
			switch rv := rawVal.(type) {
			case string:
				rawStr = rv
			default:
				if jb, err := json.Marshal(rv); err == nil {
					rawStr = string(jb)
				}
			}
			var segs []string
			for _, p := range strings.Split(pathPart, "['") {
				p = strings.TrimSuffix(p, "']")
				if p != "" {
					p = strings.ReplaceAll(p, "''", "'")
					p = strings.ReplaceAll(p, `\\`, `\`)
					segs = append(segs, p)
				}
			}
			return extractJSONPathFromStr(rawStr, segs)
		}
		if strings.HasSuffix(colExpr, " AS LARGEINT)") {
			inner := strings.TrimSpace(colExpr[len("CAST(") : len(colExpr)-len(" AS LARGEINT)")])
			if bi, ok := memParseExactBigInt(inner); ok {
				return memNormalizeExactIntValue(bi)
			}
			if v := resolveColumnValue(row, inner); v != nil {
				return memCoerceSQLLargeInt(v)
			}
			return nil
		}
		if strings.HasSuffix(colExpr, " AS DOUBLE)") {
			inner := strings.TrimSpace(colExpr[len("CAST(") : len(colExpr)-len(" AS DOUBLE)")])
			if f, err := strconv.ParseFloat(inner, 64); err == nil {
				return f
			}
			if v := resolveColumnValue(row, inner); v != nil {
				switch v.(type) {
				case []any, []string:
					var out []any
					for _, elem := range asSliceOrSingle(v) {
						if f, ok := toFloat(elem); ok {
							out = append(out, f)
						}
					}
					if len(out) == 0 {
						return nil
					}
					return out
				default:
					if f, ok := toFloat(v); ok {
						return f
					}
				}
			}
			if isArithmeticSQLExpr(inner) || strings.Contains(inner, "CASE WHEN") {
				if hasUnwrappedNullColumnRef(row, inner) {
					return nil
				}
				return evalNumericExpr(row, inner)
			}
			return nil
		}
		if strings.HasSuffix(colExpr, " AS BIGINT)") {
			inner := strings.TrimSpace(colExpr[len("CAST(") : len(colExpr)-len(" AS BIGINT)")])
			if v := resolveColumnValue(row, inner); v != nil {
				switch v.(type) {
				case []any, []string:
					var out []any
					for _, elem := range asSliceOrSingle(v) {
						if f, ok := toFloat(elem); ok {
							out = append(out, int64(f))
						} else if s, ok := elem.(string); ok {
							if ms, ok := schema.ParseESDateToEpochMillis(s, time.Now().UTC()); ok {
								out = append(out, ms)
							}
						}
					}
					if len(out) == 0 {
						return nil
					}
					return out
				default:
					if f, ok := toFloat(v); ok {
						return int64(f)
					}
					if s, ok := v.(string); ok {
						if ms, ok := schema.ParseESDateToEpochMillis(s, time.Now().UTC()); ok {
							return ms
						}
					}
				}
			}
			if isArithmeticSQLExpr(inner) {
				if hasUnwrappedNullColumnRef(row, inner) {
					return nil
				}
				return int64(evalNumericExpr(row, inner))
			}
			return nil
		}
		if strings.HasSuffix(colExpr, " AS INT)") {
			if strings.HasPrefix(colExpr, "CAST(COALESCE(") && strings.HasSuffix(colExpr, ", FALSE) AS INT)") {
				innerCond := colExpr[len("CAST(COALESCE(") : len(colExpr)-len(", FALSE) AS INT)")]
				if evalWhereExpr(row, innerCond) {
					return int64(1)
				}
				return int64(0)
			}
			inner := strings.TrimSpace(colExpr[len("CAST(") : len(colExpr)-len(" AS INT)")])
			if v := resolveColumnValue(row, inner); v != nil {
				switch v.(type) {
				case []any, []string:
					var out []any
					for _, elem := range asSliceOrSingle(v) {
						if f, ok := toFloat(elem); ok {
							out = append(out, int64(f))
						}
					}
					if len(out) == 0 {
						return nil
					}
					return out
				default:
					if f, ok := toFloat(v); ok {
						return int64(f)
					}
				}
			}
			if isArithmeticSQLExpr(inner) || strings.Contains(inner, "CASE WHEN") {
				if hasUnwrappedNullColumnRef(row, inner) {
					return nil
				}
				return int64(evalNumericExpr(row, inner))
			}
			return nil
		}
		if strings.HasSuffix(colExpr, " AS STRING)") {
			inner := colExpr[len("CAST(") : len(colExpr)-len(" AS STRING)")]
			if v := resolveColumnValue(row, inner); v != nil {
				switch tv := v.(type) {
				case []any, []string:
					var out []any
					for _, elem := range asSliceOrSingle(v) {
						if elem != nil {
							out = append(out, fmt.Sprintf("%v", elem))
						}
					}
					if len(out) == 0 {
						return nil
					}
					return out
				case float64:
					if isArithmeticSQLExpr(inner) && !math.IsNaN(tv) && !math.IsInf(tv, 0) && tv == math.Trunc(tv) {
						return strconv.FormatInt(int64(tv), 10)
					}
					return fmt.Sprintf("%v", v)
				default:
					return fmt.Sprintf("%v", v)
				}
			}
			return nil
		}
		if strings.HasSuffix(colExpr, " AS ARRAY<STRING>)") {
			inner := strings.TrimSpace(colExpr[len("CAST(") : len(colExpr)-len(" AS ARRAY<STRING>)")])
			return toStringSlice(resolveColumnValue(row, inner))
		}
		if strings.HasSuffix(colExpr, " AS BOOLEAN)") {
			inner := colExpr[len("CAST(") : len(colExpr)-len(" AS BOOLEAN)")]
			if v := resolveColumnValue(row, inner); v != nil {
				switch v.(type) {
				case []any, []string:
					var out []any
					for _, elem := range asSliceOrSingle(v) {
						if bv, ok := coerceSQLBool(elem); ok {
							out = append(out, bv)
						}
					}
					if len(out) == 0 {
						return nil
					}
					return out
				default:
					if bv, ok := coerceSQLBool(v); ok {
						return bv
					}
					return nil
				}
			}
			return nil
		}
	}
	if trimmedCase := trimOuterParens(colExpr); strings.HasPrefix(trimmedCase, "CASE WHEN ") && strings.HasSuffix(trimmedCase, " END") {
		return evalCaseWhenValue(row, trimmedCase)
	}
	if isArithmeticSQLExpr(colExpr) {
		if hasUnwrappedNullColumnRef(row, colExpr) {
			return nil
		}
		return evalNumericExpr(row, colExpr)
	}
	return nil
}

func evalCaseWhenBranchVal(row map[string]any, branchExpr string) any {
	branchExpr = strings.TrimSpace(branchExpr)
	if strings.EqualFold(branchExpr, "NULL") {
		return nil
	}
	if strings.HasPrefix(branchExpr, "'") && strings.HasSuffix(branchExpr, "'") {
		return unquoteSQLLiteral(branchExpr)
	}
	if f, err := strconv.ParseFloat(branchExpr, 64); err == nil {
		return f
	}
	return resolveColumnValue(row, branchExpr)
}

func evalCaseWhenValue(row map[string]any, expr string) any {
	inner := expr[len("CASE WHEN ") : len(expr)-len(" END")]
	elseIdx := findTopLevelOp(inner, " ELSE ")
	var elseExpr string
	whenChain := inner
	if elseIdx > 0 {
		elseExpr = inner[elseIdx+6:]
		whenChain = inner[:elseIdx]
	}
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
			return evalCaseWhenBranchVal(row, thenExpr)
		}
		if nextWhenIdx <= 0 {
			break
		}
		whenChain = rest[nextWhenIdx+6:]
	}
	if elseIdx > 0 {
		return evalCaseWhenBranchVal(row, elseExpr)
	}
	return nil
}

var (
	reUnwrappedBacktickCol = regexp.MustCompile("`([a-zA-Z0-9_]+)`")
	reUnwrappedJSONExtract = regexp.MustCompile(`json_extract_string\([^)]+\)`)
	reUnwrappedDocExtract  = regexp.MustCompile("CAST\\(`_doc`(?:\\['[^']+'\\])+ AS [A-Z]+\\)")
)

func stripCoalesceSubexprs(expr string) string {
	for {
		idx := strings.Index(expr, "COALESCE(")
		if idx < 0 {
			return expr
		}
		depth := 0
		end := -1
		for i := idx + len("COALESCE"); i < len(expr); i++ {
			if expr[i] == '(' {
				depth++
			} else if expr[i] == ')' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			return expr
		}
		expr = expr[:idx] + "1" + expr[end+1:]
	}
}

func hasUnwrappedNullColumnRef(row map[string]any, expr string) bool {
	if strings.Contains(expr, "CASE ") {
		return false
	}
	if strings.Contains(expr, "_el ->") || strings.Contains(expr, "_x ->") {
		return resolveColumnValue(row, expr) == nil
	}
	stripped := stripCoalesceSubexprs(expr)
	for {
		idx := strings.Index(stripped, "ST_Distance_Sphere(")
		if idx < 0 {
			break
		}
		depth := 0
		end := -1
		for i := idx + len("ST_Distance_Sphere"); i < len(stripped); i++ {
			if stripped[i] == '(' {
				depth++
			} else if stripped[i] == ')' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			break
		}
		call := stripped[idx : end+1]
		if v := resolveColumnValue(row, call); v == nil {
			return true
		}
		stripped = stripped[:idx] + "1" + stripped[end+1:]
	}
	for _, m := range reUnwrappedDocExtract.FindAllString(stripped, -1) {
		if v := resolveColumnValue(row, m); v == nil || fmt.Sprintf("%v", v) == "" {
			return true
		}
	}
	stripped = reUnwrappedDocExtract.ReplaceAllString(stripped, "1")
	for _, m := range reUnwrappedJSONExtract.FindAllString(stripped, -1) {
		if v := resolveColumnValue(row, m); v == nil || fmt.Sprintf("%v", v) == "" {
			return true
		}
	}
	stripped = reUnwrappedJSONExtract.ReplaceAllString(stripped, "1")
	for _, m := range reUnwrappedBacktickCol.FindAllStringSubmatch(stripped, -1) {
		col := m[1]
		if col == "_doc" {
			continue
		}
		if v, ok := row[col]; !ok || v == nil || fmt.Sprintf("%v", v) == "" {
			return true
		}
	}
	return false
}

func isArithmeticSQLExpr(expr string) bool {
	trimmed := trimOuterParens(strings.TrimSpace(expr))
	for _, fn := range []string{"CASE ", "ST_Distance_Sphere(", "GREATEST(", "LEAST(", "POW(", "LOG10(", "LN(", "SQRT(", "FLOOR(", "CEIL(", "ROUND(", "TRUNCATE(", "ABS("} {
		if strings.HasPrefix(trimmed, fn) {
			return true
		}
	}
	for _, op := range []byte{'+', '-', '*', '/', '%'} {
		if len(splitTopLevelBinaryMath(trimmed, op)) > 1 {
			return true
		}
	}
	if strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "+") {
		return true
	}
	return false
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
			if inQuotes {
				if c == '\\' && i+1 < len(s) {
					i++
					continue
				}
				if c == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i++
						continue
					}
					inQuotes = false
				}
				continue
			}
			if c == '\'' {
				inQuotes = true
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
		if inQuotes {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inQuotes = false
			}
			continue
		}
		if c == '\'' {
			inQuotes = true
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

func isSQLKeywordBoundary(s string, pos, kwLen int) bool {
	if pos > 0 {
		prev := s[pos-1]
		if (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') || prev == '_' || prev == '`' {
			return false
		}
	}
	end := pos + kwLen
	if end < len(s) {
		next := s[end]
		if (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') || (next >= '0' && next <= '9') || next == '_' || next == '`' {
			return false
		}
	}
	return true
}

func endsWithSQLUnaryPrefixKeyword(prev string) bool {
	upper := strings.ToUpper(strings.TrimSpace(prev))
	for _, kw := range []string{"CASE", "WHEN", "THEN", "ELSE", "AND", "OR", "NOT"} {
		if strings.HasSuffix(upper, kw) && isSQLKeywordBoundary(upper, len(upper)-len(kw), len(kw)) {
			return true
		}
	}
	return false
}

func splitTopLevelBinaryMath(s string, op byte) []string {
	var parts []string
	depth := 0
	caseDepth := 0
	inQuotes := false
	inBackticks := false
	lastStart := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuotes {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inQuotes = false
			}
			continue
		}
		if inBackticks {
			if c == '`' {
				inBackticks = false
			}
			continue
		}
		if c == '\'' {
			inQuotes = true
			continue
		}
		if c == '`' {
			inBackticks = true
			continue
		}
		if depth == 0 {
			if i+4 <= len(s) && strings.EqualFold(s[i:i+4], "CASE") && isSQLKeywordBoundary(s, i, 4) {
				caseDepth++
				i += 3
				continue
			}
			if caseDepth > 0 && i+3 <= len(s) && strings.EqualFold(s[i:i+3], "END") && isSQLKeywordBoundary(s, i, 3) {
				caseDepth--
				i += 2
				continue
			}
		}
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case op:
			if depth == 0 && caseDepth == 0 && i > 0 {
				if (op == '+' || op == '-') && (s[i-1] == 'e' || s[i-1] == 'E') && i >= 2 && ((s[i-2] >= '0' && s[i-2] <= '9') || s[i-2] == '.') {
					continue
				}
				prev := strings.TrimSpace(s[lastStart:i])
				if prev == "" {
					continue
				}
				if op == '+' || op == '-' {
					lastChar := prev[len(prev)-1]
					if lastChar == '+' || lastChar == '-' || lastChar == '*' || lastChar == '/' || lastChar == '(' ||
						lastChar == ',' || lastChar == '?' || lastChar == ':' || lastChar == '=' || lastChar == '<' || lastChar == '>' || lastChar == '!' ||
						endsWithSQLUnaryPrefixKeyword(prev) {
						continue
					}
				}
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
	inBackticks := false
	lastStart := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuotes {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inQuotes = false
			}
			continue
		}
		if inBackticks {
			if c == '`' {
				inBackticks = false
			}
			continue
		}
		if c == '\'' {
			inQuotes = true
			continue
		}
		if c == '`' {
			inBackticks = true
			continue
		}
		switch c {
		case '(', '[':
			depth++
		case ')', ']':
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
	caseDepth := 0
	inQuotes := false
	inBackticks := false
	for i := 0; i <= len(s)-len(op); i++ {
		c := s[i]
		if inQuotes {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inQuotes = false
			}
			continue
		}
		if inBackticks {
			if c == '`' {
				inBackticks = false
			}
			continue
		}
		if c == '\'' {
			inQuotes = true
			continue
		}
		if c == '`' {
			inBackticks = true
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
		if depth == 0 {
			if i+4 <= len(s) && strings.EqualFold(s[i:i+4], "CASE") && isSQLKeywordBoundary(s, i, 4) {
				caseDepth++
			} else if caseDepth > 0 && i+3 <= len(s) && strings.EqualFold(s[i:i+3], "END") && isSQLKeywordBoundary(s, i, 3) {
				caseDepth--
			}
		}
		if depth == 0 && caseDepth == 0 && s[i:i+len(op)] == op {
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
	if u, err := strconv.ParseUint(s, 10, 64); err == nil {
		return u
	}
	if memIsSignedASCIIDigits(s) {
		if bi, ok := new(big.Int).SetString(s, 10); ok {
			return memNormalizeExactIntValue(bi)
		}
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
	case string:
		if s != "" {
			return []string{s}
		}
		return nil
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
			switch tv := item.(type) {
			case map[string]any, []any:
				if jb, err := json.Marshal(tv); err == nil {
					out = append(out, string(jb))
				}
			default:
				out = append(out, fmt.Sprintf("%v", item))
			}
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

func memIsSignedASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' || s[0] == '+' {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func memNormalizeExactIntValue(bi *big.Int) any {
	if bi == nil {
		return nil
	}
	if bi.IsInt64() {
		return bi.Int64()
	}
	if bi.IsUint64() {
		return bi.Uint64()
	}
	return bi
}

func memParseExactBigInt(v any) (*big.Int, bool) {
	switch val := v.(type) {
	case int:
		return big.NewInt(int64(val)), true
	case int64:
		return big.NewInt(val), true
	case uint64:
		return new(big.Int).SetUint64(val), true
	case *big.Int:
		if val == nil {
			return nil, false
		}
		return val, true
	case json.Number:
		s := strings.TrimSpace(val.String())
		if !memIsSignedASCIIDigits(s) {
			return nil, false
		}
		bi, ok := new(big.Int).SetString(s, 10)
		return bi, ok
	case string:
		s := strings.TrimSpace(val)
		if !memIsSignedASCIIDigits(s) {
			return nil, false
		}
		bi, ok := new(big.Int).SetString(s, 10)
		return bi, ok
	default:
		return nil, false
	}
}

func memCoerceSQLLargeInt(res any) any {
	switch res.(type) {
	case []any, []string:
		var out []any
		for _, elem := range asSliceOrSingle(res) {
			if bi, ok := memParseExactBigInt(elem); ok {
				out = append(out, memNormalizeExactIntValue(bi))
			} else if f, okF := toFloat(elem); okF && !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f) {
				biF, _ := new(big.Float).SetFloat64(f).Int(nil)
				out = append(out, memNormalizeExactIntValue(biF))
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		if bi, ok := memParseExactBigInt(res); ok {
			return memNormalizeExactIntValue(bi)
		}
		if f, okF := toFloat(res); okF && !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f) {
			biF, _ := new(big.Float).SetFloat64(f).Int(nil)
			return memNormalizeExactIntValue(biF)
		}
		return nil
	}
}

func memCoerceVariantToArrayOfString(res any) any {
	switch tv := res.(type) {
	case nil, map[string]any:
		return nil
	case []string:
		return tv
	case []any:
		var out []string
		var appendElem func(item any)
		appendElem = func(item any) {
			if item == nil {
				return
			}
			switch sub := item.(type) {
			case []any:
				for _, child := range sub {
					appendElem(child)
				}
			case map[string]any:
				if jb, err := json.Marshal(sub); err == nil {
					out = append(out, string(jb))
				}
			default:
				out = append(out, fmt.Sprintf("%v", sub))
			}
		}
		for _, item := range tv {
			appendElem(item)
		}
		return out
	default:
		return toStringSlice(fmt.Sprintf("%v", tv))
	}
}

func toInt64(v any) (int64, bool) {
	switch val := v.(type) {
	case int:
		return int64(val), true
	case int64:
		return val, true
	case uint64:
		if val <= math.MaxInt64 {
			return int64(val), true
		}
		return 0, false
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
	case uint64:
		return float64(val), true
	case *big.Int:
		if val == nil {
			return 0, false
		}
		f, _ := new(big.Float).SetInt(val).Float64()
		return f, true
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

func coerceSQLBool(v any) (bool, bool) {
	switch tv := v.(type) {
	case nil:
		return false, false
	case bool:
		return tv, true
	case int:
		return tv != 0, true
	case int64:
		return tv != 0, true
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return false, false
		}
		return tv != 0, true
	case json.Number:
		if f, err := tv.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f != 0, true
		}
		return false, false
	case string:
		s := strings.TrimSpace(tv)
		if strings.EqualFold(s, "true") || s == "1" {
			return true, true
		}
		if strings.EqualFold(s, "false") || s == "0" {
			return false, true
		}
		return false, false
	default:
		return false, false
	}
}

func compareBools(a, b bool) int {
	if a == b {
		return 0
	}
	if !a && b {
		return -1
	}
	return 1
}

func compareAny(a, b any) int {
	if ab, aOk := a.(bool); aOk {
		if bb, bOk := coerceSQLBool(b); bOk {
			return compareBools(ab, bb)
		}
	} else if bb, bOk := b.(bool); bOk {
		if ab2, aOk2 := coerceSQLBool(a); aOk2 {
			return compareBools(ab2, bb)
		}
	}
	if biA, okA := memParseExactBigInt(a); okA {
		if biB, okB := memParseExactBigInt(b); okB {
			return biA.Cmp(biB)
		}
	}
	fa, aNum := toFloat(a)
	fb, bNum := toFloat(b)
	if aNum && bNum {
		return compareFloats(fa, fb)
	}
	if aNum && !bNum {
		if sb, ok := b.(string); ok {
			if ms, ok := schema.ParseESDateToEpochMillis(sb, time.Now().UTC()); ok {
				return compareFloats(fa, float64(ms))
			}
		}
	} else if !aNum && bNum {
		if sa, ok := a.(string); ok {
			if ms, ok := schema.ParseESDateToEpochMillis(sa, time.Now().UTC()); ok {
				return compareFloats(float64(ms), fb)
			}
		}
	}
	return strings.Compare(fmt.Sprintf("%v", a), fmt.Sprintf("%v", b))
}

func extractDynamicNestedJSONElementsFromRow(row map[string]any, rawNestedPath string) []string {
	srcStr, ok := row["_source"].(string)
	if !ok || srcStr == "" {
		return nil
	}
	var docMap map[string]any
	dec := json.NewDecoder(strings.NewReader(srcStr))
	dec.UseNumber()
	if err := dec.Decode(&docMap); err != nil || docMap == nil {
		return nil
	}
	segs := strings.Split(rawNestedPath, "__")
	var out []string
	var walk func(curr any, idx int)
	walk = func(curr any, idx int) {
		if curr == nil {
			return
		}
		if idx >= len(segs) {
			switch tv := curr.(type) {
			case map[string]any:
				if b, err := json.Marshal(tv); err == nil {
					out = append(out, string(b))
				}
			case []any:
				for _, el := range tv {
					walk(el, idx)
				}
			}
			return
		}
		switch tv := curr.(type) {
		case map[string]any:
			if next, exists := tv[segs[idx]]; exists {
				walk(next, idx+1)
			}
		case []any:
			for _, el := range tv {
				walk(el, idx)
			}
		}
	}
	walk(docMap, 0)
	return out
}
