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
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

const (
	// BM25ModeAuto enables corpus stats on tables <= bm25MaxRows and skips expensive full scans above the cap.
	BM25ModeAuto = "auto"
	// BM25ModeDorisScore bypasses corpus scans and enables Doris native score()/SEARCH() scoring.
	BM25ModeDorisScore = "doris-score"
	// BM25ModeExactCorpusScan runs bounded deduplicated corpus stats scans regardless of row count.
	BM25ModeExactCorpusScan = "exact-corpus-scan"
	// BM25ModeApprox skips corpus scans and relies on single-pass BM25 scoring without pre-query DF.
	BM25ModeApprox = "approx"

	maxBM25TermsR67          = 256
	defaultBM25MaxRowsR67    = 50000
	defaultBM25StatsCacheTTL = 3 * time.Second
	defaultBM25OverRowCapTTL = 30 * time.Second
	maxBM25CacheEntriesR67   = 1024
)

type bm25OverRowCapEntryR67 struct {
	totalRows int64
	expiresAt time.Time
}

type bm25CacheEntryR67 struct {
	stats     map[string]*transpiler.BM25FieldTermStats
	expiresAt time.Time
}

type bm25CorpusCacheR67 struct {
	mu         sync.RWMutex
	ttl        time.Duration
	overCapTTL time.Duration
	entries    map[string]bm25CacheEntryR67
	overCap    map[string]bm25OverRowCapEntryR67
	sf         sfGroupR67
}

func newBM25CorpusCacheR67() *bm25CorpusCacheR67 {
	return &bm25CorpusCacheR67{
		ttl:        defaultBM25StatsCacheTTL,
		overCapTTL: defaultBM25OverRowCapTTL,
		entries:    make(map[string]bm25CacheEntryR67),
		overCap:    make(map[string]bm25OverRowCapEntryR67),
	}
}

func normalizeBM25ModeR67(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", BM25ModeAuto:
		return BM25ModeAuto
	case BM25ModeDorisScore:
		return BM25ModeDorisScore
	case BM25ModeExactCorpusScan:
		return BM25ModeExactCorpusScan
	case BM25ModeApprox:
		return BM25ModeApprox
	default:
		return BM25ModeAuto
	}
}

// SetBM25Mode configures how corpus BM25 statistics are computed (`auto`, `doris-score`, `exact-corpus-scan`, `approx`).
func (s *Server) SetBM25Mode(mode string) {
	if s == nil {
		return
	}
	norm := normalizeBM25ModeR67(mode)
	s.bm25Mu.Lock()
	s.bm25Mode = norm
	s.bm25Mu.Unlock()
}

// BM25Mode returns the active BM25 corpus statistics mode (defaults to `"auto"`).
func (s *Server) BM25Mode() string {
	if s == nil {
		return BM25ModeAuto
	}
	s.bm25Mu.RLock()
	m := s.bm25Mode
	s.bm25Mu.RUnlock()
	if m == "" {
		return BM25ModeAuto
	}
	return m
}

// SetBM25MaxRows configures the row-count threshold above which `"auto"` mode skips full-table BM25 scans.
func (s *Server) SetBM25MaxRows(maxRows int64) {
	if s == nil {
		return
	}
	if maxRows <= 0 {
		maxRows = defaultBM25MaxRowsR67
	}
	s.bm25Mu.Lock()
	s.bm25MaxRows = maxRows
	s.bm25Mu.Unlock()
}

// BM25MaxRows returns the row-count cap for `"auto"` corpus BM25 scans (defaults to 50000).
func (s *Server) BM25MaxRows() int64 {
	if s == nil {
		return defaultBM25MaxRowsR67
	}
	s.bm25Mu.RLock()
	v := s.bm25MaxRows
	s.bm25Mu.RUnlock()
	if v <= 0 {
		return defaultBM25MaxRowsR67
	}
	return v
}

func cloneBM25StatsMapR67(in map[string]*transpiler.BM25FieldTermStats) map[string]*transpiler.BM25FieldTermStats {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*transpiler.BM25FieldTermStats, len(in))
	for k, v := range in {
		if v == nil {
			continue
		}
		dfCopy := make(map[string]int64, len(v.TermDocFreq))
		for tk, df := range v.TermDocFreq {
			dfCopy[tk] = df
		}
		out[k] = &transpiler.BM25FieldTermStats{
			TotalDocs:   v.TotalDocs,
			AvgDL:       v.AvgDL,
			TermDocFreq: dfCopy,
		}
	}
	return out
}

func bm25TablePrefixR67(db, table string) string {
	return db + "\x00" + table + "\x00"
}

func (c *bm25CorpusCacheR67) invalidateAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if len(c.entries) > 0 {
		c.entries = make(map[string]bm25CacheEntryR67)
	}
	if len(c.overCap) > 0 {
		c.overCap = make(map[string]bm25OverRowCapEntryR67)
	}
	c.mu.Unlock()
}

func (c *bm25CorpusCacheR67) invalidateTable(db, table string) {
	if c == nil || table == "" {
		return
	}
	prefix := ""
	if db != "" {
		prefix = bm25TablePrefixR67(db, table)
	}
	mid := "\x00" + table + "\x00"
	c.mu.Lock()
	for k := range c.entries {
		if (prefix != "" && strings.HasPrefix(k, prefix)) || strings.Contains(k, mid) {
			delete(c.entries, k)
		}
	}
	for k := range c.overCap {
		if (prefix != "" && strings.HasPrefix(k, prefix)) || strings.Contains(k, mid) {
			delete(c.overCap, k)
		}
	}
	c.mu.Unlock()
}

func (s *Server) invalidateBM25ForTableR67(db, table string) {
	if s != nil && s.bm25Cache != nil {
		s.bm25Cache.invalidateTable(db, table)
	}
}

func (s *Server) invalidateBM25ForIndexR67(indexName string) {
	if s == nil || s.bm25Cache == nil || indexName == "" {
		return
	}
	s.mu.RLock()
	sc := s.indices[indexName]
	s.mu.RUnlock()
	if sc != nil && sc.DorisTable != "" {
		db := sc.DorisDB
		if db == "" {
			db = s.dorisDB
		}
		s.bm25Cache.invalidateTable(db, sc.DorisTable)
		return
	}
	s.bm25Cache.invalidateTable(s.dorisDB, indexName)
}

func (c *bm25CorpusCacheR67) getOverRowCap(tableFilterKey string, now time.Time) (int64, bool) {
	if c == nil {
		return 0, false
	}
	c.mu.RLock()
	ent, ok := c.overCap[tableFilterKey]
	c.mu.RUnlock()
	if !ok || !now.Before(ent.expiresAt) {
		return 0, false
	}
	return ent.totalRows, true
}

func (c *bm25CorpusCacheR67) markOverRowCap(tableFilterKey string, totalRows int64, now time.Time) {
	if c == nil {
		return
	}
	ttl := c.overCapTTL
	if ttl <= 0 {
		ttl = defaultBM25OverRowCapTTL
	}
	c.mu.Lock()
	if len(c.overCap) >= maxBM25CacheEntriesR67 {
		c.overCap = make(map[string]bm25OverRowCapEntryR67)
	}
	c.overCap[tableFilterKey] = bm25OverRowCapEntryR67{
		totalRows: totalRows,
		expiresAt: now.Add(ttl),
	}
	c.mu.Unlock()
}

func (c *bm25CorpusCacheR67) get(key string, now time.Time) (map[string]*transpiler.BM25FieldTermStats, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	ent, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || !now.Before(ent.expiresAt) {
		return nil, false
	}
	return cloneBM25StatsMapR67(ent.stats), true
}

func (c *bm25CorpusCacheR67) put(key string, stats map[string]*transpiler.BM25FieldTermStats, now time.Time) {
	if c == nil || len(stats) == 0 {
		return
	}
	ttl := c.ttl
	if ttl <= 0 {
		ttl = defaultBM25StatsCacheTTL
	}
	c.mu.Lock()
	if len(c.entries) >= maxBM25CacheEntriesR67 {
		for k, e := range c.entries {
			if !now.Before(e.expiresAt) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= maxBM25CacheEntriesR67 {
			c.entries = make(map[string]bm25CacheEntryR67)
		}
	}
	c.entries[key] = bm25CacheEntryR67{
		stats:     cloneBM25StatsMapR67(stats),
		expiresAt: now.Add(ttl),
	}
	c.mu.Unlock()
}

// dedupAndCapBM25ReqsR67 deduplicates requirements by (ColExpr, CaseSensitive), deduplicates
// terms within each requirement, and caps total field*term checks at capTerms (256).
func dedupAndCapBM25ReqsR67(reqs []transpiler.BM25QueryRequirement, capTerms int) []transpiler.BM25QueryRequirement {
	if len(reqs) == 0 || capTerms <= 0 {
		return nil
	}
	type reqGroupKey struct {
		colExpr       string
		caseSensitive bool
	}
	type mergedGroup struct {
		field         string
		altFields     []string
		colExpr       string
		caseSensitive bool
		terms         []string
		seenTerms     map[string]struct{}
	}
	var order []reqGroupKey
	groups := make(map[reqGroupKey]*mergedGroup, len(reqs))

	for _, r := range reqs {
		col := strings.TrimSpace(r.ColExpr)
		if col == "" || len(r.Terms) == 0 {
			continue
		}
		k := reqGroupKey{colExpr: col, caseSensitive: r.CaseSensitive}
		mg, exists := groups[k]
		if !exists {
			mg = &mergedGroup{
				field:         r.Field,
				colExpr:       col,
				caseSensitive: r.CaseSensitive,
				seenTerms:     make(map[string]struct{}, len(r.Terms)),
			}
			groups[k] = mg
			order = append(order, k)
		} else if r.Field != "" && r.Field != mg.field {
			mg.altFields = append(mg.altFields, r.Field)
		}
		for _, tk := range r.Terms {
			if tk == "" {
				continue
			}
			normTk := tk
			if !r.CaseSensitive {
				normTk = strings.ToLower(tk)
			}
			if _, dup := mg.seenTerms[normTk]; dup {
				continue
			}
			mg.seenTerms[normTk] = struct{}{}
			mg.terms = append(mg.terms, normTk)
		}
	}
	if len(order) == 0 {
		return nil
	}

	sort.Slice(order, func(i, j int) bool {
		if order[i].colExpr != order[j].colExpr {
			return order[i].colExpr < order[j].colExpr
		}
		return !order[i].caseSensitive && order[j].caseSensitive
	})

	if len(order) > capTerms {
		order = order[:capTerms]
	}

	maxTermsPerField := capTerms / len(order)
	if maxTermsPerField < 1 {
		maxTermsPerField = 1
	}

	out := make([]transpiler.BM25QueryRequirement, 0, len(order))
	totalSlots := 0
	for _, k := range order {
		mg := groups[k]
		if len(mg.terms) == 0 {
			continue
		}
		terms := append([]string(nil), mg.terms...)
		sort.Strings(terms)
		allowed := capTerms - totalSlots
		if allowed <= 0 {
			break
		}
		limit := maxTermsPerField
		if allowed < limit {
			limit = allowed
		}
		if len(terms) > limit {
			terms = terms[:limit]
		}
		totalSlots += len(terms)
		out = append(out, transpiler.BM25QueryRequirement{
			Field:         mg.field,
			ColExpr:       mg.colExpr,
			CaseSensitive: mg.caseSensitive,
			Terms:         terms,
		})
	}
	return out
}

func buildBM25CacheKeyR67(db, table, filterKey string, reqs []transpiler.BM25QueryRequirement) string {
	var b strings.Builder
	b.Grow(len(db) + len(table) + len(filterKey) + len(reqs)*32)
	b.WriteString(db)
	b.WriteByte('\x00')
	b.WriteString(table)
	b.WriteByte('\x00')
	b.WriteString(filterKey)
	for _, r := range reqs {
		b.WriteByte('\x01')
		b.WriteString(r.ColExpr)
		b.WriteByte('\x02')
		if r.CaseSensitive {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
		for _, tk := range r.Terms {
			b.WriteByte('\x03')
			b.WriteString(tk)
		}
	}
	return b.String()
}

func mergeBM25StatsIntoOptsR67(opts *transpiler.TranspilerOptions, reqs []transpiler.BM25QueryRequirement, stats map[string]*transpiler.BM25FieldTermStats) {
	if opts == nil || len(stats) == 0 {
		return
	}
	if opts.CorpusBM25Stats == nil {
		opts.CorpusBM25Stats = make(map[string]*transpiler.BM25FieldTermStats, len(stats))
	}
	mergeOne := func(key string, src *transpiler.BM25FieldTermStats) {
		if key == "" || src == nil {
			return
		}
		if existing, ok := opts.CorpusBM25Stats[key]; ok && existing != nil {
			if existing.TotalDocs == 0 && src.TotalDocs > 0 {
				existing.TotalDocs = src.TotalDocs
			}
			if existing.AvgDL == 0 && src.AvgDL > 0 {
				existing.AvgDL = src.AvgDL
			}
			if existing.TermDocFreq == nil {
				existing.TermDocFreq = make(map[string]int64, len(src.TermDocFreq))
			}
			for tk, df := range src.TermDocFreq {
				existing.TermDocFreq[tk] = df
			}
			return
		}
		dfCopy := make(map[string]int64, len(src.TermDocFreq))
		for tk, df := range src.TermDocFreq {
			dfCopy[tk] = df
		}
		opts.CorpusBM25Stats[key] = &transpiler.BM25FieldTermStats{
			TotalDocs:   src.TotalDocs,
			AvgDL:       src.AvgDL,
			TermDocFreq: dfCopy,
		}
	}
	for k, v := range stats {
		mergeOne(k, v)
	}
	for _, r := range reqs {
		if st, ok := stats[r.ColExpr]; ok {
			mergeOne(r.Field, st)
		}
	}
}

func extractAliasWherePredicateR67(idxSchema *schema.IndexSchema, req *esast.SearchRequest, opts transpiler.TranspilerOptions) string {
	if idxSchema == nil || req == nil || req.AliasFilter == nil {
		return ""
	}
	optsNoBM25 := opts
	optsNoBM25.CorpusBM25Stats = nil
	optsNoBM25.TermDocFreqFn = nil
	one := 1
	filterReq := &esast.SearchRequest{
		Query: (*esast.Query)(req.AliasFilter),
		Size:  &one,
	}
	plan, err := transpiler.NewTranspiler(idxSchema, optsNoBM25).BuildSearchPlan(filterReq)
	if err != nil {
		return ""
	}
	return extractOuterWherePredicateR67(plan.HitsSQL)
}

func isSQLWhitespaceR67(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func matchesSQLKeywordAtR67(upper string, idx int, kw string) bool {
	if idx < 0 || idx+len(kw) > len(upper) {
		return false
	}
	if idx > 0 && !isSQLWhitespaceR67(upper[idx-1]) {
		return false
	}
	end := idx + len(kw)
	if end < len(upper) && !isSQLWhitespaceR67(upper[end]) {
		return false
	}
	return upper[idx:end] == kw
}

func extractOuterWherePredicateR67(sqlStr string) string {
	if sqlStr == "" {
		return ""
	}
	upper := strings.ToUpper(sqlStr)
	inSingle := false
	inBacktick := false
	depth := 0
	whereStart := -1
	whereEnd := len(sqlStr)
	for i := 0; i < len(sqlStr); i++ {
		ch := sqlStr[i]
		if inSingle {
			if ch == '\\' && i+1 < len(sqlStr) {
				i++
				continue
			}
			if ch == '\'' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inBacktick {
			if ch == '`' {
				inBacktick = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '`':
			inBacktick = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				if whereStart < 0 && matchesSQLKeywordAtR67(upper, i, "WHERE") {
					whereStart = i + len("WHERE")
					i += len("WHERE") - 1
					continue
				}
				if whereStart >= 0 && (matchesSQLKeywordAtR67(upper, i, "ORDER BY") ||
					matchesSQLKeywordAtR67(upper, i, "GROUP BY") ||
					matchesSQLKeywordAtR67(upper, i, "LIMIT")) {
					whereEnd = i
					break
				}
			}
		}
		if whereEnd < len(sqlStr) {
			break
		}
	}
	if whereStart < 0 || whereEnd <= whereStart {
		return ""
	}
	pred := strings.TrimSpace(sqlStr[whereStart:whereEnd])
	// Strip the redundant delete sign prefix so we cleanly compose it once in statsSQL.
	const delPrefix = "(`__DORIS_DELETE_SIGN__` = 0)"
	if pred == delPrefix {
		return ""
	}
	return pred
}

func buildApproxBM25StatsR67(reqs []transpiler.BM25QueryRequirement, totalRows int64) map[string]*transpiler.BM25FieldTermStats {
	if totalRows <= 0 {
		return nil
	}
	out := make(map[string]*transpiler.BM25FieldTermStats, len(reqs)*2)
	for _, r := range reqs {
		dfMap := make(map[string]int64, len(r.Terms))
		estDF := totalRows / 10
		if estDF < 1 {
			estDF = 1
		}
		for _, tk := range r.Terms {
			dfMap[tk] = estDF
		}
		st := &transpiler.BM25FieldTermStats{
			TotalDocs:   totalRows,
			AvgDL:       1.0,
			TermDocFreq: dfMap,
		}
		if r.ColExpr != "" {
			out[r.ColExpr] = st
		}
		if r.Field != "" {
			out[r.Field] = st
		}
	}
	return out
}

func (s *Server) populateCorpusBM25StatsWithCacheR67(
	ctx context.Context,
	idxSchema *schema.IndexSchema,
	req *esast.SearchRequest,
	opts *transpiler.TranspilerOptions,
) {
	if s == nil || s.backend == nil || idxSchema == nil || req == nil || opts == nil || idxSchema.DorisTable == "" {
		return
	}
	if _, isMem := s.backend.(*MemoryBackend); isMem {
		return
	}
	rowsBackend, ok := s.backend.(SQLRowsBackend)
	if !ok {
		return
	}

	mode := s.BM25Mode()
	switch mode {
	case BM25ModeDorisScore:
		opts.UseDoris4SearchFunc = true
		s.RecordBM25ScanMetric("skipped_doris_score")
		return
	case BM25ModeApprox:
		s.RecordBM25ScanMetric("skipped_approx")
		return
	}

	rawReqs := transpiler.CollectBM25QueryRequirements(req, idxSchema, *opts)
	if len(rawReqs) == 0 {
		return
	}
	reqs := dedupAndCapBM25ReqsR67(rawReqs, maxBM25TermsR67)
	if len(reqs) == 0 {
		return
	}

	dbName := idxSchema.DorisDB
	if dbName == "" {
		dbName = s.dorisDB
	}
	aliasWhere := extractAliasWherePredicateR67(idxSchema, req, *opts)
	tableFilterKey := bm25TablePrefixR67(dbName, idxSchema.DorisTable) + aliasWhere
	cacheKey := buildBM25CacheKeyR67(dbName, idxSchema.DorisTable, aliasWhere, reqs)

	now := time.Now()
	if s.bm25Cache != nil {
		if mode == BM25ModeAuto {
			if totalRows, over := s.bm25Cache.getOverRowCap(tableFilterKey, now); over {
				s.RecordBM25ScanMetric("skipped_over_row_cap")
				mergeBM25StatsIntoOptsR67(opts, reqs, buildApproxBM25StatsR67(reqs, totalRows))
				return
			}
		}
		if cachedStats, hit := s.bm25Cache.get(cacheKey, now); hit {
			s.RecordBM25ScanMetric("cache_hit")
			mergeBM25StatsIntoOptsR67(opts, reqs, cachedStats)
			return
		}
	}

	fetchStats := func() (map[string]*transpiler.BM25FieldTermStats, error) {
		safeDB := escapeDorisDBIdent(dbName)
		safeTable := sanitizeAndEscapeDorisIdent(idxSchema.DorisTable)

		selectExprs := make([]string, 0, len(reqs)*4+1)
		selectExprs = append(selectExprs, "COUNT(*) AS `__bm25_total_rows`")
		edgeAposPat := transpiler.EscapeDorisSQLString(`(^|[^[:alnum:]_])'+|'+([^[:alnum:]_]|$)`)
		delimPat := transpiler.EscapeDorisSQLString(`[^[:alnum:]_']+`)

		for i, r := range reqs {
			strCol := fmt.Sprintf("COALESCE(CAST(%s AS STRING), '')", r.ColExpr)
			if !r.CaseSensitive {
				strCol = fmt.Sprintf("LOWER(%s)", strCol)
			}
			stripEdge := fmt.Sprintf("REGEXP_REPLACE(%s, '%s', ' ')", strCol, edgeAposPat)
			trimOne := fmt.Sprintf("TRIM(REGEXP_REPLACE(%s, '%s', ' '))", stripEdge, delimPat)
			normDbl := fmt.Sprintf("CONCAT(' ', REPLACE(%s, ' ', '  '), ' ')", trimOne)
			tokCnt := fmt.Sprintf(
				"CASE WHEN %s IS NULL OR %s = '' THEN NULL ELSE CAST(1 + CHAR_LENGTH(%s) - CHAR_LENGTH(REPLACE(%s, ' ', '')) AS DOUBLE) END",
				r.ColExpr, trimOne, trimOne, trimOne,
			)
			selectExprs = append(selectExprs,
				fmt.Sprintf("SUM(CASE WHEN %s IS NOT NULL AND %s != '' THEN 1 ELSE 0 END) AS `__bm25_n_%d`", r.ColExpr, trimOne, i),
				fmt.Sprintf("AVG(%s) AS `__bm25_avgdl_%d`", tokCnt, i),
			)
			for j, tk := range r.Terms {
				patTerm := tk
				if !r.CaseSensitive {
					patTerm = strings.ToLower(patTerm)
				}
				patLit := "'" + transpiler.EscapeDorisSQLString(" "+patTerm+" ") + "'"
				selectExprs = append(selectExprs,
					fmt.Sprintf("SUM(CASE WHEN LOCATE(%s, %s) > 0 THEN 1 ELSE 0 END) AS `__bm25_df_%d_%d`", patLit, normDbl, i, j),
				)
			}
		}

		whereExpr := "`__DORIS_DELETE_SIGN__` = 0"
		if aliasWhere != "" {
			whereExpr = "(" + whereExpr + ") AND (" + aliasWhere + ")"
		}
		// #nosec G201 -- identifiers are sanitized via escapeDorisDBIdent and sanitizeAndEscapeDorisIdent; patterns are SQL-escaped
		statsSQL := fmt.Sprintf(
			"SELECT %s FROM `%s`.`%s` WHERE %s",
			strings.Join(selectExprs, ", "),
			safeDB,
			safeTable,
			whereExpr,
		)
		sqlStart := time.Now()
		rows, err := rowsBackend.QueryRows(ctx, statsSQL)
		s.RecordSQLMetrics(time.Since(sqlStart), err)
		if err != nil {
			s.RecordBM25ScanMetric("error")
			return nil, err
		}
		if len(rows) == 0 {
			s.RecordBM25ScanMetric("empty")
			return nil, nil
		}
		row := rows[0]
		totalRows, _ := sqlRowValToInt64R66(row["__bm25_total_rows"])
		maxRows := s.BM25MaxRows()
		if mode == BM25ModeAuto && maxRows > 0 && totalRows > maxRows {
			if s.bm25Cache != nil {
				s.bm25Cache.markOverRowCap(tableFilterKey, totalRows, time.Now())
			}
			s.RecordBM25ScanMetric("over_row_cap")
			return buildApproxBM25StatsR67(reqs, totalRows), nil
		}

		scanned := make(map[string]*transpiler.BM25FieldTermStats, len(reqs)*2)
		for i, r := range reqs {
			nVal, _ := sqlRowValToInt64R66(row[fmt.Sprintf("__bm25_n_%d", i)])
			avgVal, _ := sqlRowValToFloat64R66(row[fmt.Sprintf("__bm25_avgdl_%d", i)])
			termDF := make(map[string]int64, len(r.Terms))
			for j, tk := range r.Terms {
				dfVal, _ := sqlRowValToInt64R66(row[fmt.Sprintf("__bm25_df_%d_%d", i, j)])
				termDF[tk] = dfVal
			}
			st := &transpiler.BM25FieldTermStats{
				TotalDocs:   nVal,
				AvgDL:       avgVal,
				TermDocFreq: termDF,
			}
			if r.ColExpr != "" {
				scanned[r.ColExpr] = st
			}
			if r.Field != "" {
				scanned[r.Field] = st
			}
		}
		for _, origReq := range rawReqs {
			if st, exists := scanned[origReq.ColExpr]; exists && origReq.Field != "" {
				scanned[origReq.Field] = st
			}
		}
		if s.bm25Cache != nil {
			s.bm25Cache.put(cacheKey, scanned, time.Now())
		}
		s.RecordBM25ScanMetric("scanned")
		return scanned, nil
	}

	var (
		resStats map[string]*transpiler.BM25FieldTermStats
		err      error
	)
	if s.bm25Cache != nil {
		rawVal, callErr, _ := s.bm25Cache.sf.Do(cacheKey, func() (any, error) {
			if cStats, hit := s.bm25Cache.get(cacheKey, time.Now()); hit {
				return cStats, nil
			}
			return fetchStats()
		})
		err = callErr
		if err == nil {
			resStats, _ = rawVal.(map[string]*transpiler.BM25FieldTermStats)
		}
	} else {
		resStats, err = fetchStats()
	}
	if err != nil || len(resStats) == 0 {
		return
	}
	mergeBM25StatsIntoOptsR67(opts, rawReqs, resStats)
}

func (s *Server) formatBM25MetricLabelsSummary() string {
	return strconv.FormatInt(s.BM25MaxRows(), 10)
}
