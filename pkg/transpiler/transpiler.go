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

package transpiler

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// CompiledQuery holds the compiled Doris SQL `WHERE` predicate and projection-safe `_score` expression.
type CompiledQuery struct {
	WhereSQL          string
	SafeWhereSQL      string
	ScoreSQL          string
	UsesFulltextMatch bool
}

// EffectiveSafeWhere returns a boolean SQL condition that is guaranteed not to contain `MATCH_*`
// predicates, making it safe inside `SELECT`, `CASE WHEN`, `COALESCE`, and `array_exists` lambdas.
func (c CompiledQuery) EffectiveSafeWhere() string {
	if c.SafeWhereSQL != "" {
		return c.SafeWhereSQL
	}
	if c.UsesFulltextMatch {
		return fmt.Sprintf("(%s) > 0", c.ScoreSQL)
	}
	if c.WhereSQL == "" {
		return "TRUE"
	}
	return c.WhereSQL
}

const (
	DefaultMaxResultWindow = 10_000
	DefaultMaxAggBuckets   = 10_000
)

// ExecutionPlan represents the Doris SQL queries generated for an Elasticsearch `/_search` request.
type ExecutionPlan struct {
	// Query 1: Paginated Top-K hits + window total count (empty when `size == 0`)
	HitsSQL string
	// Query 2: Consolidated Nereids Multi-Cast CTE query for all aggregations (or total count if `size == 0`)
	AggsSQL string
	// UnindexedVariantFields lists dynamic `_doc[...]` fields accessed by this query that are not yet
	// promoted to physical `f__*` columns with `USING INVERTED` indexes.
	UnindexedVariantFields []string
}

// TranspilerOptions configures dialect features for the Doris SQL compiler.
type TranspilerOptions struct {
	// UseDoris4SearchFunc enables pushing `query_string` / `simple_query_string` directly to
	// Apache Doris 4.0's native `SEARCH('<dsl>', '<default_field>', '<default_op>')` function
	// and `score()` projection.
	UseDoris4SearchFunc bool
	MaxResultWindow     int
	MaxAggBuckets       int
}

type Transpiler struct {
	Schema          *schema.IndexSchema
	Opts            TranspilerOptions
	unindexedFields map[string]bool
}

func NewTranspiler(s *schema.IndexSchema, opts TranspilerOptions) *Transpiler {
	return &Transpiler{
		Schema:          s,
		Opts:            opts,
		unindexedFields: make(map[string]bool),
	}
}

type nestedCtx struct {
	nestedPath string
	elemVar    string
}

// BuildSearchPlan compiles an Elasticsearch `SearchRequest` into a Doris `ExecutionPlan`.
func (t *Transpiler) BuildSearchPlan(req *esast.SearchRequest) (*ExecutionPlan, error) {
	t.unindexedFields = make(map[string]bool)

	mainQ := CompiledQuery{
		WhereSQL: "TRUE",
		ScoreSQL: "1.0",
	}
	if req.Query != nil {
		mainQ = t.CompileQuery(req.Query, true, nil)
		if len(req.KNN) > 0 && mainQ.UsesFulltextMatch && t.Opts.UseDoris4SearchFunc {
			mainQ.ScoreSQL = fmt.Sprintf("COALESCE(score(), 1.0) * (%s)", mainQ.ScoreSQL)
		}
	}
	if len(req.KNN) > 0 {
		var knnWheres, knnSafeWheres, knnScores []string
		knnUsesFT := false
		for i := range req.KNN {
			kc := t.compileKNN(&req.KNN[i], true, nil)
			knnWheres = append(knnWheres, fmt.Sprintf("(%s)", kc.WhereSQL))
			knnSafeWheres = append(knnSafeWheres, fmt.Sprintf("(%s)", kc.EffectiveSafeWhere()))
			knnScores = append(knnScores, kc.ScoreSQL)
			knnUsesFT = knnUsesFT || kc.UsesFulltextMatch
		}
		knnWhere := strings.Join(knnWheres, " OR ")
		knnSafeWhere := strings.Join(knnSafeWheres, " OR ")
		knnScore := strings.Join(knnScores, " + ")
		if req.Query == nil || mainQ.WhereSQL == "TRUE" {
			scoreSQL := knnScore
			if req.Query != nil && mainQ.ScoreSQL != "1.0" && mainQ.ScoreSQL != "0.0" {
				scoreSQL = fmt.Sprintf("((%s) + (%s))", mainQ.ScoreSQL, knnScore)
			}
			mainQ = CompiledQuery{
				WhereSQL:          knnWhere,
				SafeWhereSQL:      knnSafeWhere,
				ScoreSQL:          scoreSQL,
				UsesFulltextMatch: knnUsesFT,
			}
		} else {
			mainQ = CompiledQuery{
				WhereSQL:          fmt.Sprintf("((%s) OR (%s))", mainQ.WhereSQL, knnWhere),
				SafeWhereSQL:      fmt.Sprintf("((%s) OR (%s))", mainQ.EffectiveSafeWhere(), knnSafeWhere),
				ScoreSQL:          fmt.Sprintf("((%s) + (%s))", mainQ.ScoreSQL, knnScore),
				UsesFulltextMatch: mainQ.UsesFulltextMatch || knnUsesFT,
			}
		}
	}

	userWhere := mainQ.WhereSQL
	if req.MinScore != nil && !queryContainsScript(req.Query) {
		minScoreExpr := mainQ.ScoreSQL
		if len(req.KNN) == 0 && mainQ.UsesFulltextMatch && t.Opts.UseDoris4SearchFunc {
			minScoreExpr = fmt.Sprintf("COALESCE(score(), 1.0) * (%s)", mainQ.ScoreSQL)
		}
		minCond := fmt.Sprintf("(CAST(%s AS DOUBLE) >= %s)", minScoreExpr, strconv.FormatFloat(*req.MinScore, 'f', -1, 64))
		if mainQ.WhereSQL == "" || mainQ.WhereSQL == "TRUE" {
			mainQ.WhereSQL = minCond
			mainQ.SafeWhereSQL = minCond
		} else {
			mainQ.WhereSQL = fmt.Sprintf("((%s) AND %s)", mainQ.WhereSQL, minCond)
			mainQ.SafeWhereSQL = fmt.Sprintf("((%s) AND %s)", mainQ.EffectiveSafeWhere(), minCond)
		}
		userWhere = mainQ.WhereSQL
	}
	aliasWhere := ""
	if req.AliasFilter != nil {
		afQ := esast.Query(*req.AliasFilter)
		afCompiled := t.CompileQuery(&afQ, false, nil)
		if afCompiled.WhereSQL != "" && afCompiled.WhereSQL != "TRUE" {
			aliasWhere = afCompiled.WhereSQL
			if mainQ.WhereSQL == "" || mainQ.WhereSQL == "TRUE" {
				mainQ.WhereSQL = aliasWhere
				mainQ.SafeWhereSQL = afCompiled.EffectiveSafeWhere()
			} else {
				mainQ.WhereSQL = fmt.Sprintf("((%s) AND (%s))", mainQ.WhereSQL, aliasWhere)
				mainQ.SafeWhereSQL = fmt.Sprintf("((%s) AND (%s))", mainQ.EffectiveSafeWhere(), afCompiled.EffectiveSafeWhere())
			}
			mainQ.UsesFulltextMatch = mainQ.UsesFulltextMatch || afCompiled.UsesFulltextMatch
		}
	}

	postFilterSQL := "TRUE"
	if req.PostFilter != nil {
		postFilterSQL = t.CompileQuery(req.PostFilter, false, nil).WhereSQL
	}

	from := 0
	if req.From != nil && *req.From > 0 {
		from = *req.From
	}
	size := 10
	if req.Size != nil {
		size = *req.Size
	} else if len(req.KNN) > 0 && req.KNN[0].K > 0 {
		size = req.KNN[0].K
	}
	if size < 0 {
		size = 0
	}

	maxWin := t.Opts.MaxResultWindow
	if maxWin <= 0 {
		maxWin = DefaultMaxResultWindow
	}
	if len(req.SearchAfter) == 0 && from+size > maxWin {
		if from >= maxWin {
			from = maxWin
			size = 0
		} else {
			size = maxWin - from
		}
	}

	plan := &ExecutionPlan{}
	if size > 0 {
		scoreExpr := mainQ.ScoreSQL
		if len(req.KNN) == 0 && mainQ.UsesFulltextMatch && t.Opts.UseDoris4SearchFunc {
			scoreExpr = fmt.Sprintf("COALESCE(score(), 1.0) * (%s)", mainQ.ScoreSQL)
		}
		totalHitsExpr := "COUNT(*) OVER() AS `_total_hits`"
		if !req.ShouldTrackTotalHits() {
			totalHitsExpr = "CAST(-1 AS BIGINT) AS `_total_hits`"
		}
		effSorts := EffectiveSortsForRequest(req)
		orderBy := t.compileOrderByWithAfter(effSorts, req.SearchAfter)
		var saPred string
		if len(req.SearchAfter) > 0 {
			from = 0
			saScoreExpr := scoreExpr
			if req.Collapse != nil && req.Collapse.Field != "" {
				saScoreExpr = "`_score`"
			}
			saPred = t.compileSearchAfterPredicate(effSorts, req.SearchAfter, saScoreExpr)
		}
		if req.Collapse != nil && req.Collapse.Field != "" {
			bCollapse := t.Schema.ResolveField(req.Collapse.Field)
			collapseCol := t.sqlColumnRef(req.Collapse.Field, true, nil)
			if bCollapse.Kind == schema.StoragePromotedArray || bCollapse.Kind == schema.StorageNestedSubfield {
				collapseCol = fmt.Sprintf("element_at(`%s`, 1)", bCollapse.EffectiveArrayColumn(true))
			}
			preCollapseWhere := fmt.Sprintf("`__DORIS_DELETE_SIGN__` = 0 AND (%s) AND (%s)", mainQ.WhereSQL, postFilterSQL)
			outerCollapseWhere := fmt.Sprintf("`_collapse_rn` = 1 OR %s IS NULL", collapseCol)
			if saPred != "" && saPred != "TRUE" {
				outerCollapseWhere = fmt.Sprintf("(%s) AND (%s)", outerCollapseWhere, saPred)
			}
			plan.HitsSQL = fmt.Sprintf(
				"SELECT `_id`, `_version`, `_source`, `_score`, `_total_hits` "+
					"FROM ("+
					"SELECT *, "+
					"ROW_NUMBER() OVER (PARTITION BY %s ORDER BY %s) AS `_collapse_rn` "+
					"FROM ("+
					"SELECT *, CAST(%s AS DOUBLE) AS `_score`, %s "+
					"FROM `%s`.`%s` "+
					"WHERE %s"+
					") `_scored`"+
					") `_collapsed` "+
					"WHERE %s "+
					"ORDER BY %s "+
					"LIMIT %d OFFSET %d",
				collapseCol,
				orderBy,
				scoreExpr,
				totalHitsExpr,
				t.Schema.DorisDB,
				t.Schema.DorisTable,
				preCollapseWhere,
				outerCollapseWhere,
				orderBy,
				size,
				from,
			)
		} else {
			effectiveWhere := postFilterSQL
			if saPred != "" && saPred != "TRUE" {
				if effectiveWhere == "TRUE" {
					effectiveWhere = saPred
				} else {
					effectiveWhere = fmt.Sprintf("(%s) AND (%s)", effectiveWhere, saPred)
				}
			}
			whereClause := fmt.Sprintf("`__DORIS_DELETE_SIGN__` = 0 AND (%s) AND (%s)", mainQ.WhereSQL, effectiveWhere)
			plan.HitsSQL = fmt.Sprintf(
				"SELECT `_id`, `_version`, `_source`, CAST(%s AS DOUBLE) AS `_score`, "+
					"%s "+
					"FROM `%s`.`%s` "+
					"WHERE %s "+
					"ORDER BY %s "+
					"LIMIT %d OFFSET %d",
				scoreExpr,
				totalHitsExpr,
				t.Schema.DorisDB,
				t.Schema.DorisTable,
				whereClause,
				orderBy,
				size,
				from,
			)
		}
	}

	aggs := req.EffectiveAggs()
	if len(aggs) > 0 || size == 0 {
		plan.AggsSQL = t.buildAggsCTESQL(mainQ.WhereSQL, userWhere, aliasWhere, postFilterSQL, aggs)
	}

	if len(t.unindexedFields) > 0 {
		fields := make([]string, 0, len(t.unindexedFields))
		for f := range t.unindexedFields {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		plan.UnindexedVariantFields = fields
	}

	return plan, nil
}

// CompileQuery compiles a single `esast.Query` AST node into Doris SQL.
// Note: Apache Doris BE (`VMatchPredicate`) evaluates `MATCH_*` predicates strictly in `WHERE`
// scan pushdown, never inside `SELECT` projections, `COALESCE(...)`, or `array_exists(...)` lambdas.
func (t *Transpiler) CompileQuery(q *esast.Query, scoring bool, nctx *nestedCtx) CompiledQuery {
	if q == nil {
		return CompiledQuery{WhereSQL: "TRUE", ScoreSQL: "1.0"}
	}
	switch {
	case q.MatchAll != nil:
		return CompiledQuery{WhereSQL: "TRUE", ScoreSQL: "1.0"}
	case q.MatchNone != nil:
		return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
	case q.Ids != nil:
		if len(q.Ids.Values) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		quoted := make([]string, 0, len(q.Ids.Values))
		for _, id := range q.Ids.Values {
			quoted = append(quoted, quoteStr(id))
		}
		pred := fmt.Sprintf("`_id` IN (%s)", strings.Join(quoted, ", "))
		score := "1.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN 1.0000 ELSE 0.0 END)", pred)
		}
		return CompiledQuery{
			WhereSQL:     pred,
			SafeWhereSQL: pred,
			ScoreSQL:     score,
		}
	case q.Bool != nil:
		return t.compileBool(q.Bool, scoring, nctx)
	case q.DisMax != nil:
		return t.compileDisMax(q.DisMax, scoring, nctx)
	case q.Boosting != nil:
		return t.compileBoosting(q.Boosting, scoring, nctx)
	case len(q.Term) > 0:
		keys := sortedMapKeys(q.Term)
		var preds, scores []string
		for _, field := range keys {
			entry := q.Term[field]
			pred := t.compileTermPredicate(field, entry.Value, entry.CaseInsensitive, nctx)
			preds = append(preds, pred)
			if scoring {
				scores = append(scores, fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, entry.Boost))
			}
		}
		where := strings.Join(preds, " AND ")
		score := "0.0"
		if scoring && len(scores) > 0 {
			score = strings.Join(scores, " + ")
		}
		return CompiledQuery{WhereSQL: where, SafeWhereSQL: where, ScoreSQL: score}
	case q.Terms != nil:
		if len(q.Terms.Fields) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		fields := sortedMapKeys(q.Terms.Fields)
		var preds []string
		for _, field := range fields {
			preds = append(preds, t.compileTermsPredicate(field, q.Terms.Fields[field], nctx))
		}
		pred := strings.Join(preds, " AND ")
		score := "1.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, q.Terms.Boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case len(q.TermsSet) > 0:
		fields := sortedMapKeys(q.TermsSet)
		var preds []string
		boost := 1.0
		for _, field := range fields {
			ts := q.TermsSet[field]
			if ts.Boost != nil {
				boost = *ts.Boost
			}
			b := t.Schema.ResolveField(field)
			if len(ts.Terms) == 0 || b.Kind == schema.StoragePromotedVector {
				preds = append(preds, "FALSE")
			} else {
				var termSums []string
				for _, tv := range ts.Terms {
					tp := t.compileTermsSetTermPredicate(field, tv, nctx)
					termSums = append(termSums, fmt.Sprintf("CAST(COALESCE(%s, FALSE) AS INT)", tp))
				}
				threshExpr := "1"
				if ts.MinimumShouldMatchField != "" {
					threshExpr = fmt.Sprintf("COALESCE(%s, 1)", t.sqlNumericColumnRef(ts.MinimumShouldMatchField, nctx))
				} else if len(ts.MinimumShouldMatchScript) > 0 {
					threshExpr = t.compileTermsSetScriptThreshold(ts.MinimumShouldMatchScript, len(ts.Terms), nctx)
				}
				preds = append(preds, fmt.Sprintf("((%s) >= %s)", strings.Join(termSums, " + "), threshExpr))
			}
		}
		pred := strings.Join(preds, " AND ")
		score := "1.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case len(q.Fuzzy) > 0:
		keys := sortedMapKeys(q.Fuzzy)
		if len(keys) == 1 {
			fe := q.Fuzzy[keys[0]]
			return t.compileMatchField(keys[0], fe.Value, "or", fe.Boost, scoring, nctx)
		}
		var subs []esast.Query
		for _, k := range keys {
			fe := q.Fuzzy[k]
			subs = append(subs, esast.Query{Match: map[string]esast.MatchEntry{k: {Query: fe.Value, Operator: "or", Boost: fe.Boost}}})
		}
		return t.compileBool(&esast.BoolQuery{Must: subs}, scoring, nctx)
	case q.CombinedFields != nil:
		return t.compileMultiMatch(&esast.MultiMatchQuery{
			Query:              q.CombinedFields.Query,
			Fields:             q.CombinedFields.Fields,
			Type:               "cross_fields",
			Operator:           q.CombinedFields.Operator,
			MinimumShouldMatch: q.CombinedFields.MinimumShouldMatch,
			ZeroTermsQuery:     q.CombinedFields.ZeroTermsQuery,
			Boost:              q.CombinedFields.Boost,
		}, scoring, nctx)
	case len(q.Range) > 0:
		keys := sortedMapKeys(q.Range)
		var preds []string
		boost := 1.0
		for _, field := range keys {
			rc := q.Range[field]
			if rc.Boost != nil {
				boost = *rc.Boost
			}
			preds = append(preds, t.compileRangePredicate(field, rc, nctx))
		}
		pred := strings.Join(preds, " AND ")
		score := "1.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case q.Exists != nil:
		pred := t.compileExistsPredicate(q.Exists.Field, nctx)
		score := "1.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN 1.0000 ELSE 0.0 END)", pred)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case len(q.Prefix) > 0:
		keys := sortedMapKeys(q.Prefix)
		var preds []string
		boost := 1.0
		for _, field := range keys {
			pe := q.Prefix[field]
			if pe.Boost != 0 {
				boost = pe.Boost
			}
			preds = append(preds, t.compilePrefixPredicate(field, pe.Value, pe.CaseInsensitive, nctx))
		}
		pred := strings.Join(preds, " AND ")
		score := "1.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case len(q.Wildcard) > 0:
		keys := sortedMapKeys(q.Wildcard)
		var preds []string
		boost := 1.0
		for _, field := range keys {
			we := q.Wildcard[field]
			if we.Boost != 0 {
				boost = we.Boost
			}
			preds = append(preds, t.compileWildcardPredicate(field, we.Value, we.CaseInsensitive, nctx))
		}
		pred := strings.Join(preds, " AND ")
		score := "1.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case len(q.Regexp) > 0:
		keys := sortedMapKeys(q.Regexp)
		var preds []string
		var safePreds []string
		usesFT := false
		boost := 1.0
		compileSingleRegexp := func(field string, re esast.RegexpEntry) (string, string, bool) {
			b := t.Schema.ResolveField(field)
			if b.Kind == schema.StoragePromotedVector {
				return "FALSE", "FALSE", false
			}
			effCI := re.CaseInsensitive || (nctx != nil && b.EffectiveLowercase(false))
			pat := re.Value
			if (effCI || ((nctx == nil || nctx.nestedPath != b.NestedPath) && b.EffectiveLowercase(false))) && !strings.HasPrefix(pat, "(?i)") {
				pat = "(?i)" + pat
			}
			if (nctx == nil || nctx.nestedPath != b.NestedPath) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				arrPred := fmt.Sprintf("array_exists(_x -> _x REGEXP %s, `%s`)", quoteStr(pat), b.EffectiveArrayColumn(false))
				return arrPred, arrPred, false
			}
			col := t.sqlColumnRef(field, false, nctx)
			safePred := fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, quoteStr(pat))
			if nctx != nil || b.Kind == schema.StorageDynamicVariant || effCI || strings.HasPrefix(pat, "(?i)") {
				return fmt.Sprintf("%s REGEXP %s", col, quoteStr(pat)), safePred, false
			}
			return fmt.Sprintf("%s MATCH_REGEXP %s", col, quoteStr(pat)), safePred, true
		}
		for _, field := range keys {
			re := q.Regexp[field]
			if re.Boost != 0 {
				boost = re.Boost
			}
			if strings.ContainsAny(field, "*?") && t.Schema != nil {
				exp := t.Schema.ExpandFieldPattern(field)
				if len(exp) == 0 {
					w, sw, ft := compileSingleRegexp("_all_text", re)
					preds = append(preds, w)
					safePreds = append(safePreds, sw)
					usesFT = usesFT || ft
					continue
				}
				var wDisj, swDisj []string
				for _, bf := range exp {
					w, sw, ft := compileSingleRegexp(bf.Field, re)
					wDisj = append(wDisj, w)
					swDisj = append(swDisj, sw)
					usesFT = usesFT || ft
				}
				if len(wDisj) == 1 {
					preds = append(preds, wDisj[0])
					safePreds = append(safePreds, swDisj[0])
				} else {
					preds = append(preds, "("+strings.Join(wDisj, " OR ")+")")
					safePreds = append(safePreds, "("+strings.Join(swDisj, " OR ")+")")
				}
				continue
			}
			w, sw, ft := compileSingleRegexp(field, re)
			preds = append(preds, w)
			safePreds = append(safePreds, sw)
			usesFT = usesFT || ft
		}
		safeWhere := strings.Join(safePreds, " AND ")
		scoreSQL := "1.0"
		if scoring && len(safePreds) > 0 {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", safeWhere, boost)
		}
		return CompiledQuery{WhereSQL: strings.Join(preds, " AND "), SafeWhereSQL: safeWhere, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}
	case len(q.Match) > 0:
		keys := sortedMapKeys(q.Match)
		if len(keys) == 1 {
			me := q.Match[keys[0]]
			qStr := ""
			if me.Query != nil {
				qStr = strings.TrimSpace(fmt.Sprintf("%v", me.Query))
			}
			if qStr == "" && strings.EqualFold(me.ZeroTermsQuery, "all") {
				return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: fmt.Sprintf("%.4f", me.Boost)}
			}
			if me.MinimumShouldMatch != nil && !strings.EqualFold(me.Operator, "and") {
				b := t.Schema.ResolveField(keys[0])
				tokens := strings.Fields(qStr)
				if isExactKeywordField(keys[0], b) && qStr != "" {
					tokens = []string{qStr}
				}
				if len(tokens) == 1 && parseMinShouldMatch(me.MinimumShouldMatch, 1, true) > 1 {
					return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
				}
				if len(tokens) > 1 {
					var shoulds []esast.Query
					for _, tok := range tokens {
						shoulds = append(shoulds, esast.Query{
							Match: map[string]esast.MatchEntry{
								keys[0]: {Query: tok, Operator: "or", Boost: 1.0},
							},
						})
					}
					boost := me.Boost
					return t.compileBool(&esast.BoolQuery{
						Should:             shoulds,
						MinimumShouldMatch: me.MinimumShouldMatch,
						Boost:              &boost,
					}, scoring, nctx)
				}
			}
			return t.compileMatchField(keys[0], me.Query, me.Operator, me.Boost, scoring, nctx)
		}
		var subs []esast.Query
		for _, k := range keys {
			subs = append(subs, esast.Query{Match: map[string]esast.MatchEntry{k: q.Match[k]}})
		}
		return t.compileBool(&esast.BoolQuery{Must: subs}, scoring, nctx)
	case len(q.MatchPhrase) > 0:
		keys := sortedMapKeys(q.MatchPhrase)
		if len(keys) == 1 {
			pe := q.MatchPhrase[keys[0]]
			return t.compileMatchPhraseField(keys[0], pe.Query, pe.Slop, pe.Boost, false, scoring, nctx)
		}
		var subs []esast.Query
		for _, k := range keys {
			subs = append(subs, esast.Query{MatchPhrase: map[string]esast.PhraseEntry{k: q.MatchPhrase[k]}})
		}
		return t.compileBool(&esast.BoolQuery{Must: subs}, scoring, nctx)
	case len(q.MatchPhrasePrefix) > 0:
		keys := sortedMapKeys(q.MatchPhrasePrefix)
		if len(keys) == 1 {
			pe := q.MatchPhrasePrefix[keys[0]]
			return t.compileMatchPhraseField(keys[0], pe.Query, pe.Slop, pe.Boost, true, scoring, nctx)
		}
		var subs []esast.Query
		for _, k := range keys {
			subs = append(subs, esast.Query{MatchPhrasePrefix: map[string]esast.PhraseEntry{k: q.MatchPhrasePrefix[k]}})
		}
		return t.compileBool(&esast.BoolQuery{Must: subs}, scoring, nctx)
	case len(q.MatchBoolPrefix) > 0:
		keys := sortedMapKeys(q.MatchBoolPrefix)
		if len(keys) == 1 {
			pe := q.MatchBoolPrefix[keys[0]]
			tokens := strings.Fields(strings.TrimSpace(pe.Query))
			if len(tokens) == 1 && !strings.EqualFold(pe.Operator, "and") && pe.MinimumShouldMatch != nil && parseMinShouldMatch(pe.MinimumShouldMatch, 1, true) > 1 {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			if len(tokens) > 1 {
				var shoulds []esast.Query
				for i := 0; i < len(tokens)-1; i++ {
					shoulds = append(shoulds, esast.Query{
						Match: map[string]esast.MatchEntry{
							keys[0]: {Query: tokens[i], Operator: "or", Boost: 1.0},
						},
					})
				}
				shoulds = append(shoulds, esast.Query{
					MatchPhrasePrefix: map[string]esast.PhraseEntry{
						keys[0]: {Query: tokens[len(tokens)-1], Boost: 1.0},
					},
				})
				boost := pe.Boost
				if strings.EqualFold(pe.Operator, "and") {
					return t.compileBool(&esast.BoolQuery{
						Must:  shoulds,
						Boost: &boost,
					}, scoring, nctx)
				}
				msm := any(1)
				if pe.MinimumShouldMatch != nil {
					msm = pe.MinimumShouldMatch
				}
				return t.compileBool(&esast.BoolQuery{
					Should:             shoulds,
					MinimumShouldMatch: msm,
					Boost:              &boost,
				}, scoring, nctx)
			}
			return t.compileMatchPhraseField(keys[0], pe.Query, pe.Slop, pe.Boost, true, scoring, nctx)
		}
		var subs []esast.Query
		for _, k := range keys {
			subs = append(subs, esast.Query{MatchBoolPrefix: map[string]esast.PhraseEntry{k: q.MatchBoolPrefix[k]}})
		}
		return t.compileBool(&esast.BoolQuery{Must: subs}, scoring, nctx)
	case q.MultiMatch != nil:
		return t.compileMultiMatch(q.MultiMatch, scoring, nctx)
	case q.QueryString != nil:
		return t.compileQueryString(q.QueryString, scoring, nctx)
	case q.SimpleQueryString != nil:
		return t.compileQueryString(q.SimpleQueryString, scoring, nctx)
	case q.Nested != nil:
		return t.compileNestedWithParent(q.Nested, scoring, nctx)
	case q.ConstantScore != nil:
		inner := t.CompileQuery(&q.ConstantScore.Filter, scoring, nctx)
		boost := 1.0
		if q.ConstantScore.Boost != nil {
			boost = *q.ConstantScore.Boost
		}
		safeCond := inner.EffectiveSafeWhere()
		scoreSQL := fmt.Sprintf("%.4f", boost)
		if scoring {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", safeCond, boost)
		}
		return CompiledQuery{
			WhereSQL:          inner.WhereSQL,
			SafeWhereSQL:      safeCond,
			ScoreSQL:          scoreSQL,
			UsesFulltextMatch: inner.UsesFulltextMatch,
		}
	case q.FunctionScore != nil:
		return t.compileFunctionScore(q.FunctionScore, nctx)
	case q.ScriptScore != nil:
		return t.compileScriptScore(q.ScriptScore, scoring, nctx)
	case q.Script != nil:
		return t.compileScriptQuery(q.Script, scoring, nctx)
	case q.KNN != nil:
		return t.compileKNN(q.KNN, scoring, nctx)
	}
	return CompiledQuery{WhereSQL: "TRUE", ScoreSQL: "1.0"}
}

func (t *Transpiler) compileKNN(kq *esast.KNNQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if kq == nil || kq.Field == "" || len(kq.QueryVector) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	b := t.Schema.ResolveField(kq.Field)
	var colExpr string
	if b.ColumnName != "" {
		colExpr = fmt.Sprintf("`%s`", b.ColumnName)
	} else {
		if t.unindexedFields != nil && kq.Field != "" {
			t.unindexedFields[strings.TrimSuffix(kq.Field, ".keyword")] = true
		}
		var pathBuilder strings.Builder
		for _, seg := range b.SourceJSONPath {
			_, _ = fmt.Fprintf(&pathBuilder, "[%s]", quoteStr(seg))
		}
		colExpr = fmt.Sprintf("CAST(`_doc`%s AS ARRAY<FLOAT>)", pathBuilder.String())
	}

	vecParts := make([]string, len(kq.QueryVector))
	for i, v := range kq.QueryVector {
		vecParts[i] = strconv.FormatFloat(v, 'f', -1, 64)
	}
	vecLit := fmt.Sprintf("CAST([%s] AS ARRAY<FLOAT>)", strings.Join(vecParts, ", "))
	dim := len(kq.QueryVector)

	var conds []string
	var safeConds []string
	usesFT := false
	baseCond := fmt.Sprintf("(%s IS NOT NULL AND array_size(%s) = %d)", colExpr, colExpr, dim)
	conds = append(conds, baseCond)
	safeConds = append(safeConds, baseCond)
	for i := range kq.Filter {
		fc := t.CompileQuery(&kq.Filter[i], true, nctx)
		conds = append(conds, fmt.Sprintf("(%s)", fc.WhereSQL))
		safeConds = append(safeConds, fmt.Sprintf("(%s)", fc.EffectiveSafeWhere()))
		if fc.UsesFulltextMatch {
			usesFT = true
		}
	}

	distFn := "COSINE_DISTANCE"
	if strings.EqualFold(b.VectorMetric, "l2_norm") || strings.EqualFold(b.VectorMetric, "l2") {
		distFn = "L2_DISTANCE"
	} else if strings.EqualFold(b.VectorMetric, "dot_product") || strings.EqualFold(b.VectorMetric, "max_inner_product") {
		distFn = "INNER_PRODUCT"
	}
	safeColExpr := fmt.Sprintf("IF(array_size(%s) = %d, %s, %s)", colExpr, dim, colExpr, vecLit)
	distExpr := fmt.Sprintf("%s(%s, %s)", distFn, safeColExpr, vecLit)
	if kq.Similarity != nil {
		var simCond string
		switch distFn {
		case "L2_DISTANCE":
			simStr := strconv.FormatFloat(*kq.Similarity, 'f', -1, 64)
			simCond = fmt.Sprintf("(%s <= %s)", distExpr, simStr)
		case "INNER_PRODUCT":
			simStr := strconv.FormatFloat(*kq.Similarity, 'f', -1, 64)
			simCond = fmt.Sprintf("(%s >= %s)", distExpr, simStr)
		default:
			maxDist := 1.0 - *kq.Similarity
			maxDistStr := strconv.FormatFloat(maxDist, 'f', -1, 64)
			simCond = fmt.Sprintf("(%s <= %s)", distExpr, maxDistStr)
		}
		conds = append(conds, simCond)
		safeConds = append(safeConds, simCond)
	}

	whereSQL := strings.Join(conds, " AND ")
	safeWhereSQL := strings.Join(safeConds, " AND ")
	boost := 1.0
	if kq.Boost != nil {
		boost = *kq.Boost
	}
	scoreSQL := "1.0"
	if scoring {
		if distFn == "INNER_PRODUCT" {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%.4f * ((1.0 + COALESCE(%s, 0.0)) / 2.0)) ELSE 0.0 END)",
				safeWhereSQL, boost, distExpr)
		} else {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN (%.4f * (1.0 / (1.0 + COALESCE(%s, 2.0)))) ELSE 0.0 END)",
				safeWhereSQL, boost, distExpr)
		}
	}
	return CompiledQuery{
		WhereSQL:          whereSQL,
		SafeWhereSQL:      safeWhereSQL,
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: usesFT,
	}
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (t *Transpiler) compileDisMax(dm *esast.DisMaxQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if dm == nil || len(dm.Queries) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	var disjuncts, safeDisjuncts, scores []string
	usesFT := false
	for i := range dm.Queries {
		c := t.CompileQuery(&dm.Queries[i], scoring, nctx)
		disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
		safeDisjuncts = append(safeDisjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
		if scoring {
			scores = append(scores, c.ScoreSQL)
		}
		usesFT = usesFT || c.UsesFulltextMatch
	}
	boost := 1.0
	if dm.Boost != nil {
		boost = *dm.Boost
	}
	scoreSQL := fmt.Sprintf("%.4f", boost)
	if scoring && len(scores) > 0 {
		maxExpr := scores[0]
		if len(scores) > 1 {
			maxExpr = fmt.Sprintf("GREATEST(%s)", strings.Join(scores, ", "))
		}
		tb := dm.TieBreaker
		if tb < 0 {
			tb = 0
		} else if tb > 1 {
			tb = 1
		}
		if tb > 0 && len(scores) > 1 {
			sumExpr := strings.Join(scores, " + ")
			scoreSQL = fmt.Sprintf("(%.4f * ((%.4f * %s) + (%.4f * (%s))))",
				boost, 1.0-tb, maxExpr, tb, sumExpr)
		} else {
			scoreSQL = fmt.Sprintf("(%.4f * %s)", boost, maxExpr)
		}
	}
	return CompiledQuery{
		WhereSQL:          "(" + strings.Join(disjuncts, " OR ") + ")",
		SafeWhereSQL:      "(" + strings.Join(safeDisjuncts, " OR ") + ")",
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: usesFT,
	}
}

func (t *Transpiler) compileBoosting(bq *esast.BoostingQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if bq == nil {
		return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: "1.0"}
	}
	pos := t.CompileQuery(&bq.Positive, scoring, nctx)
	neg := t.CompileQuery(&bq.Negative, true, nctx)
	negBoost := bq.NegativeBoost
	if negBoost <= 0 {
		negBoost = 0.5
	}
	boost := 1.0
	if bq.Boost != nil {
		boost = *bq.Boost
	}
	scoreSQL := "1.0"
	if scoring {
		if queryContainsScript(&bq.Negative) || queryContainsScript(&bq.Positive) {
			scoreSQL = pos.ScoreSQL
		} else {
			negCond := neg.EffectiveSafeWhere()
			scoreSQL = fmt.Sprintf("(%.4f * (%s) * (CASE WHEN %s THEN %.4f ELSE 1.0 END))",
				boost, pos.ScoreSQL, negCond, negBoost)
		}
	}
	return CompiledQuery{
		WhereSQL:          pos.WhereSQL,
		SafeWhereSQL:      pos.EffectiveSafeWhere(),
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: pos.UsesFulltextMatch,
	}
}

func queryContainsScript(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.Script != nil || q.ScriptScore != nil {
		return true
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.ScriptScore != nil {
			return true
		}
		for _, fn := range q.FunctionScore.Functions {
			if fn.ScriptScore != nil || queryContainsScript(fn.Filter) {
				return true
			}
		}
		if queryContainsScript(q.FunctionScore.Query) {
			return true
		}
	}
	if q.ConstantScore != nil && queryContainsScript(&q.ConstantScore.Filter) {
		return true
	}
	if q.Nested != nil && queryContainsScript(&q.Nested.Query) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryContainsScript(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil {
		if queryContainsScript(&q.Boosting.Positive) || queryContainsScript(&q.Boosting.Negative) {
			return true
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryContainsScript(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryContainsScript(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryContainsScript(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryContainsScript(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	return false
}

func (t *Transpiler) compileBool(b *esast.BoolQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	var conjuncts []string
	var safeConjuncts []string
	var scoreTerms []string
	usesFT := false

	for i := range b.Must {
		c := t.CompileQuery(&b.Must[i], scoring, nctx)
		conjuncts = append(conjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
		safeConjuncts = append(safeConjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
		if scoring {
			scoreTerms = append(scoreTerms, c.ScoreSQL)
		}
		usesFT = usesFT || c.UsesFulltextMatch
	}
	for i := range b.Filter {
		c := t.CompileQuery(&b.Filter[i], false, nctx)
		conjuncts = append(conjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
		safeConjuncts = append(safeConjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
		usesFT = usesFT || c.UsesFulltextMatch
	}
	for i := range b.MustNot {
		if queryContainsScript(&b.MustNot[i]) {
			continue
		}
		c := t.CompileQuery(&b.MustNot[i], false, nctx)
		if c.UsesFulltextMatch {
			// Doris BE does not allow MATCH_* inside COALESCE(...)
			conjuncts = append(conjuncts, fmt.Sprintf("NOT (%s)", c.WhereSQL))
		} else {
			conjuncts = append(conjuncts, fmt.Sprintf("NOT COALESCE(%s, FALSE)", c.WhereSQL))
		}
		safeConjuncts = append(safeConjuncts, fmt.Sprintf("NOT COALESCE(%s, FALSE)", c.EffectiveSafeWhere()))
		usesFT = usesFT || c.UsesFulltextMatch
	}
	minShould := 0
	if len(b.Should) > 0 {
		var disjuncts []string
		var safeDisjuncts []string
		shouldUsesFT := false
		for i := range b.Should {
			c := t.CompileQuery(&b.Should[i], scoring, nctx)
			disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
			safeDisjuncts = append(safeDisjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
			if scoring {
				scoreTerms = append(scoreTerms, c.ScoreSQL)
			}
			shouldUsesFT = shouldUsesFT || c.UsesFulltextMatch
		}
		minShould = parseMinShouldMatch(b.MinimumShouldMatch, len(b.Should), len(b.Must) == 0 && len(b.Filter) == 0)
		if minShould > len(disjuncts) {
			conjuncts = append(conjuncts, "FALSE")
			safeConjuncts = append(safeConjuncts, "FALSE")
		} else if minShould == 1 {
			conjuncts = append(conjuncts, fmt.Sprintf("(%s)", strings.Join(disjuncts, " OR ")))
			safeConjuncts = append(safeConjuncts, fmt.Sprintf("(%s)", strings.Join(safeDisjuncts, " OR ")))
			usesFT = usesFT || shouldUsesFT
		} else if minShould > 1 {
			if minShould == len(disjuncts) {
				conjuncts = append(conjuncts, fmt.Sprintf("(%s)", strings.Join(disjuncts, " AND ")))
				safeConjuncts = append(safeConjuncts, fmt.Sprintf("(%s)", strings.Join(safeDisjuncts, " AND ")))
				usesFT = usesFT || shouldUsesFT
			} else {
				var intCasts []string
				for _, sd := range safeDisjuncts {
					intCasts = append(intCasts, fmt.Sprintf("CAST(COALESCE(%s, FALSE) AS INT)", sd))
				}
				msmCond := fmt.Sprintf("((%s) >= %d)", strings.Join(intCasts, " + "), minShould)
				conjuncts = append(conjuncts, fmt.Sprintf("(%s)", strings.Join(disjuncts, " OR ")), msmCond)
				safeConjuncts = append(safeConjuncts, msmCond)
				usesFT = usesFT || shouldUsesFT
			}
		}
	}

	whereSQL := "TRUE"
	if len(conjuncts) > 0 {
		whereSQL = strings.Join(conjuncts, " AND ")
	}
	safeWhereSQL := "TRUE"
	if len(safeConjuncts) > 0 {
		safeWhereSQL = strings.Join(safeConjuncts, " AND ")
	}
	boost := 1.0
	if b.Boost != nil {
		boost = *b.Boost
	}
	scoreSQL := fmt.Sprintf("%.4f", boost)
	if scoring {
		if len(scoreTerms) == 0 {
			if safeWhereSQL != "TRUE" {
				scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", safeWhereSQL, boost)
			}
		} else {
			rawScore := fmt.Sprintf("(%.4f * (%s))", boost, strings.Join(scoreTerms, " + "))
			if len(b.Must) > 1 || (len(b.Must) > 0 && len(b.Should) > 0) || len(b.Filter) > 0 || len(b.MustNot) > 0 || minShould > 1 {
				scoreSQL = fmt.Sprintf("((CASE WHEN %s THEN 1.0000 ELSE 0.0 END) * %s)", safeWhereSQL, rawScore)
			} else {
				scoreSQL = rawScore
			}
		}
	}
	return CompiledQuery{
		WhereSQL:          whereSQL,
		SafeWhereSQL:      safeWhereSQL,
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: usesFT,
	}
}

func effectiveDorisScalarType(b schema.FieldBinding) schema.DorisScalarType {
	if b.DorisType != schema.DorisString && b.DorisType != schema.DorisVarchar {
		return b.DorisType
	}
	switch b.ESType {
	case "date", "date_nanos", "long", "unsigned_long":
		return schema.DorisBigInt
	case "integer", "short", "byte":
		return schema.DorisInt
	case "double", "float", "half_float", "scaled_float":
		return schema.DorisDouble
	case "boolean":
		return schema.DorisBoolean
	default:
		return b.DorisType
	}
}

func isScalarQueryCompatible(dt schema.DorisScalarType, queryVal any) bool {
	s := strings.TrimSpace(fmt.Sprintf("%v", queryVal))
	switch dt {
	case schema.DorisBigInt:
		if _, err := strconv.ParseInt(s, 10, 64); err == nil {
			return true
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return true
		}
		_, ok := schema.ParseESDateToEpochMillis(s, time.Now().UTC())
		return ok
	case schema.DorisInt, schema.DorisDouble:
		f, err := strconv.ParseFloat(s, 64)
		return err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case schema.DorisBoolean:
		ls := strings.ToLower(s)
		return ls == "true" || ls == "false" || ls == "1" || ls == "0"
	default:
		return true
	}
}

func isExactKeywordField(field string, b schema.FieldBinding) bool {
	return strings.HasSuffix(field, ".keyword") || b.ESType == "keyword" || b.ESType == "constant_keyword"
}

func (t *Transpiler) compileMatchField(
	field string,
	queryVal any,
	operator string,
	boost float64,
	scoring bool,
	nctx *nestedCtx,
) CompiledQuery {
	b := t.Schema.ResolveField(field)
	if b.Kind == schema.StoragePromotedVector {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}

	// IP fields and non-string promoted scalar/array columns (BIGINT, INT, DOUBLE, BOOLEAN, date) use term/CIDR equality instead of MATCH_*
	if b.ESType == "ip" {
		qStr := strings.TrimSpace(fmt.Sprintf("%v", queryVal))
		if queryVal == nil || qStr == "" {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		_, _, isCIDR := parseCIDRBounds(qStr)
		if !isCIDR && net.ParseIP(qStr) == nil {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		pred := t.compileTermPredicate(field, qStr, false, nctx)
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	}
	if effDT := effectiveDorisScalarType(b); (b.Kind == schema.StoragePromotedScalar || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && effDT != schema.DorisString && effDT != schema.DorisVarchar {
		if !isScalarQueryCompatible(effDT, queryVal) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		pred := t.compileTermPredicate(field, queryVal, false, nctx)
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	}

	queryStr := fmt.Sprintf("%v", queryVal)
	if queryVal == nil || strings.TrimSpace(queryStr) == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if isExactKeywordField(field, b) && (strings.Contains(strings.TrimSpace(queryStr), " ") || strings.HasSuffix(field, ".keyword") || b.ESType == "constant_keyword") {
		pred := t.compileTermPredicate(field, queryVal, false, nctx)
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	}
	if b.EffectiveLowercase(false) {
		queryStr = strings.ToLower(queryStr)
	}
	scorePred := t.projectionSafeTextMatchSQL(field, queryStr, operator, nctx)
	score := "0.0"
	if scoring {
		score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", scorePred, boost)
	}

	// Inside nested `array_exists(_el -> ...)` lambdas or on untokenized array columns, use projection-safe LIKE matching.
	if nctx != nil || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		return CompiledQuery{WhereSQL: scorePred, SafeWhereSQL: scorePred, ScoreSQL: score, UsesFulltextMatch: false}
	}

	matchOp := "MATCH_ANY"
	if strings.EqualFold(operator, "and") {
		matchOp = "MATCH_ALL"
	}
	col := t.sqlColumnRef(field, false, nil)
	lit := quoteStr(queryStr)
	pred := fmt.Sprintf("%s %s %s", col, matchOp, lit)
	return CompiledQuery{WhereSQL: pred, SafeWhereSQL: scorePred, ScoreSQL: score, UsesFulltextMatch: true}
}

func (t *Transpiler) compileMatchPhraseField(
	field string,
	queryStr string,
	slop int,
	boost float64,
	isPrefix bool,
	scoring bool,
	nctx *nestedCtx,
) CompiledQuery {
	b := t.Schema.ResolveField(field)
	if b.Kind == schema.StoragePromotedVector || strings.TrimSpace(queryStr) == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.ESType == "ip" {
		qTrim := strings.TrimSpace(queryStr)
		_, _, isCIDR := parseCIDRBounds(qTrim)
		if !isCIDR && net.ParseIP(qTrim) == nil {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		pred := t.compileTermPredicate(field, qTrim, false, nctx)
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	}
	if effDT := effectiveDorisScalarType(b); (b.Kind == schema.StoragePromotedScalar || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && effDT != schema.DorisString && effDT != schema.DorisVarchar {
		if !isScalarQueryCompatible(effDT, queryStr) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		pred := t.compileTermPredicate(field, queryStr, false, nctx)
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	}
	if isExactKeywordField(field, b) {
		var pred string
		if isPrefix {
			pred = t.compilePrefixPredicate(field, queryStr, false, nctx)
		} else {
			pred = t.compileTermPredicate(field, queryStr, false, nctx)
		}
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	}
	if b.EffectiveLowercase(false) {
		queryStr = strings.ToLower(queryStr)
	}
	safeOp := "phrase"
	if slop > 0 {
		safeOp = "and"
	}
	scorePred := t.projectionSafeTextMatchSQL(field, queryStr, safeOp, nctx)
	score := "0.0"
	if scoring {
		score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", scorePred, boost)
	}
	if nctx != nil || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield || b.Kind == schema.StorageDynamicVariant {
		return CompiledQuery{WhereSQL: scorePred, SafeWhereSQL: scorePred, ScoreSQL: score, UsesFulltextMatch: false}
	}
	col := t.sqlColumnRef(field, false, nil)
	if isPrefix {
		pred := fmt.Sprintf("%s MATCH_PHRASE_PREFIX %s", col, quoteStr(queryStr))
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: scorePred, ScoreSQL: score, UsesFulltextMatch: true}
	}
	phrase := queryStr
	if slop > 0 {
		phrase = fmt.Sprintf("%s ~%d", phrase, slop)
	}
	pred := fmt.Sprintf("%s MATCH_PHRASE %s", col, quoteStr(phrase))
	return CompiledQuery{WhereSQL: pred, SafeWhereSQL: scorePred, ScoreSQL: score, UsesFulltextMatch: true}
}

// projectionSafeTextMatchSQL generates a SQL boolean expression that does NOT use `MATCH_*`,
// making it safe inside `SELECT (...) AS _score` projections and `array_exists(_el -> ...)` lambdas.
func (t *Transpiler) projectionSafeTextMatchSQL(field, queryStr, operator string, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	tokens := strings.Fields(strings.TrimSpace(queryStr))
	if len(tokens) == 0 || operator == "phrase" {
		tokens = []string{strings.TrimSpace(queryStr)}
	}
	joinOp := " OR "
	if strings.EqualFold(operator, "and") {
		joinOp = " AND "
	}

	if (nctx == nil || nctx.nestedPath != b.NestedPath) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		arrCol := b.EffectiveArrayColumn(false)
		var parts []string
		for _, tok := range tokens {
			likeLit := quoteStr("%" + escapeLikeLiteral(tok) + "%")
			parts = append(parts, fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `%s`)", likeLit, arrCol))
		}
		return "(" + strings.Join(parts, joinOp) + ")"
	}

	col := t.sqlColumnRef(field, false, nctx)
	var parts []string
	for _, tok := range tokens {
		likeLit := quoteStr("%" + escapeLikeLiteral(tok) + "%")
		parts = append(parts, fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likeLit))
	}
	return "(" + strings.Join(parts, joinOp) + ")"
}

func (t *Transpiler) compileMultiMatch(mm *esast.MultiMatchQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	fields := mm.Fields
	if len(fields) == 0 {
		fields = []string{"_all_text"}
	}
	op := mm.Operator
	if op == "" {
		op = "or"
	}
	qStr := ""
	if mm.Query != nil {
		qStr = strings.TrimSpace(fmt.Sprintf("%v", mm.Query))
	}
	if qStr == "" && strings.EqualFold(mm.ZeroTermsQuery, "all") {
		boost := 1.0
		if mm.Boost != nil {
			boost = *mm.Boost
		}
		return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: fmt.Sprintf("%.4f", boost)}
	}
	mmType := strings.ToLower(mm.Type)

	// Term-centric cross_fields (and combined_fields) or minimum_should_match token splitting
	if mmType == "cross_fields" || (mm.MinimumShouldMatch != nil && !strings.EqualFold(op, "and") && mmType != "phrase" && mmType != "phrase_prefix" && mmType != "bool_prefix") {
		tokens := strings.Fields(qStr)
		if len(tokens) == 1 && !strings.EqualFold(op, "and") && mm.MinimumShouldMatch != nil && parseMinShouldMatch(mm.MinimumShouldMatch, 1, true) > 1 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if len(tokens) > 1 && (strings.EqualFold(op, "and") || mm.MinimumShouldMatch != nil) {
			var tokenQueries []esast.Query
			for _, tok := range tokens {
				tokenQueries = append(tokenQueries, esast.Query{
					MultiMatch: &esast.MultiMatchQuery{
						Query:    tok,
						Fields:   fields,
						Type:     "best_fields",
						Operator: "or",
					},
				})
			}
			if strings.EqualFold(op, "and") {
				return t.compileBool(&esast.BoolQuery{
					Must:  tokenQueries,
					Boost: mm.Boost,
				}, scoring, nctx)
			}
			return t.compileBool(&esast.BoolQuery{
				Should:             tokenQueries,
				MinimumShouldMatch: mm.MinimumShouldMatch,
				Boost:              mm.Boost,
			}, scoring, nctx)
		}
	}

	var disjuncts []string
	var safeDisjuncts []string
	var scores []string
	usesFT := false

	for _, fpat := range fields {
		expanded := t.Schema.ExpandFieldPattern(fpat)
		for _, bf := range expanded {
			var c CompiledQuery
			switch mmType {
			case "phrase":
				c = t.compileMatchPhraseField(bf.Field, qStr, mm.Slop, bf.Boost, false, scoring, nctx)
			case "phrase_prefix":
				c = t.compileMatchPhraseField(bf.Field, qStr, mm.Slop, bf.Boost, true, scoring, nctx)
			case "bool_prefix":
				c = t.CompileQuery(&esast.Query{
					MatchBoolPrefix: map[string]esast.PhraseEntry{
						bf.Field: {
							Query:              qStr,
							Operator:           op,
							MinimumShouldMatch: mm.MinimumShouldMatch,
							Boost:              bf.Boost,
						},
					},
				}, scoring, nctx)
			default:
				c = t.compileMatchField(bf.Field, mm.Query, op, bf.Boost, scoring, nctx)
			}
			if c.WhereSQL == "FALSE" && len(expanded) > 1 {
				continue
			}
			disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
			safeDisjuncts = append(safeDisjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
			if scoring {
				scores = append(scores, c.ScoreSQL)
			}
			usesFT = usesFT || c.UsesFulltextMatch
		}
	}

	if len(disjuncts) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	scoreExpr := "1.0"
	if scoring && len(scores) > 0 {
		if (mmType == "" || mmType == "best_fields" || mmType == "bool_prefix" || mmType == "phrase" || mmType == "phrase_prefix") && len(scores) > 1 {
			maxExpr := fmt.Sprintf("GREATEST(%s)", strings.Join(scores, ", "))
			if mm.TieBreaker != nil && *mm.TieBreaker > 0 {
				sumExpr := fmt.Sprintf("(%s)", strings.Join(scores, " + "))
				scoreExpr = fmt.Sprintf("(%s + %.4f * (%s - %s))", maxExpr, *mm.TieBreaker, sumExpr, maxExpr)
			} else {
				scoreExpr = maxExpr
			}
		} else {
			scoreExpr = fmt.Sprintf("(%s)", strings.Join(scores, " + "))
		}
		if mm.Boost != nil && *mm.Boost != 1.0 {
			scoreExpr = fmt.Sprintf("(%.4f * %s)", *mm.Boost, scoreExpr)
		}
	}
	return CompiledQuery{
		WhereSQL:          fmt.Sprintf("(%s)", strings.Join(disjuncts, " OR ")),
		SafeWhereSQL:      fmt.Sprintf("(%s)", strings.Join(safeDisjuncts, " OR ")),
		ScoreSQL:          scoreExpr,
		UsesFulltextMatch: usesFT,
	}
}

func (t *Transpiler) compileNestedWithParent(nq *esast.NestedQuery, scoring bool, parentNctx *nestedCtx) CompiledQuery {
	corrCol, ok := t.Schema.NestedRoots[nq.Path]
	if !ok {
		corrCol = "n__" + schema.SanitizeDorisIdentifier(nq.Path)
	}
	elemVar := "_el"
	if parentNctx != nil && strings.HasPrefix(parentNctx.elemVar, "_el") {
		elemVar = parentNctx.elemVar + "2"
	}
	inner := t.CompileQuery(&nq.Query, false, &nestedCtx{
		nestedPath: nq.Path,
		elemVar:    elemVar,
	})
	prefilter := t.extractNestedPrefilter(nq.Path, &nq.Query)
	whereSQL := fmt.Sprintf("array_exists(%s -> %s, `%s`)", elemVar, inner.WhereSQL, corrCol)
	if prefilter != "" {
		whereSQL = fmt.Sprintf("(%s AND %s)", prefilter, whereSQL)
	}
	scoreSQL := "1.0"
	if scoring {
		scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN 1.0000 ELSE 0.0 END)", whereSQL)
	}
	return CompiledQuery{
		WhereSQL:          whereSQL,
		SafeWhereSQL:      whereSQL,
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: inner.UsesFulltextMatch,
	}
}

func (t *Transpiler) compileScriptScore(ss *esast.ScriptScoreQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	base := CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: "1.0"}
	if ss != nil && ss.Query != nil {
		base = t.CompileQuery(ss.Query, true, nctx)
	}
	scoreSQL := "1.0"
	if scoring {
		scoreSQL = base.ScoreSQL
	}
	return CompiledQuery{
		WhereSQL:          base.WhereSQL,
		SafeWhereSQL:      base.EffectiveSafeWhere(),
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: base.UsesFulltextMatch,
	}
}

func (t *Transpiler) compileScriptQuery(sq *esast.ScriptQuery, scoring bool, _ *nestedCtx) CompiledQuery {
	boost := 1.0
	if sq != nil && sq.Boost != nil {
		boost = *sq.Boost
	}
	scoreSQL := "1.0"
	if scoring {
		scoreSQL = fmt.Sprintf("%.4f", boost)
	}
	return CompiledQuery{
		WhereSQL:     "TRUE",
		SafeWhereSQL: "TRUE",
		ScoreSQL:     scoreSQL,
	}
}

func (t *Transpiler) extractNestedPrefilter(nestedPath string, q *esast.Query) string {
	if q == nil {
		return ""
	}
	if len(q.Term) > 0 {
		var parts []string
		for _, field := range sortedMapKeys(q.Term) {
			entry := q.Term[field]
			b := t.Schema.ResolveField(field)
			if b.Kind == schema.StorageNestedSubfield && b.NestedPath == nestedPath && b.PrefilterArrayCol != "" {
				effLower := b.EffectiveLowercase(true)
				arrCol := b.EffectiveArrayColumn(true)
				if entry.CaseInsensitive && !effLower {
					continue
				}
				if b.ESType == "ip" {
					if startNum, endNum, isCIDR := parseCIDRBounds(fmt.Sprintf("%v", entry.Value)); isCIDR {
						parts = append(parts, fmt.Sprintf("array_exists(_x -> IPV4_STRING_TO_NUM_OR_NULL(_x) >= %d AND IPV4_STRING_TO_NUM_OR_NULL(_x) <= %d, `%s`)", startNum, endNum, arrCol))
						continue
					}
				}
				val := entry.Value
				if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean {
					if bv, ok := normalizeBooleanQueryValue(val); ok {
						val = bv
					}
				} else if strVal, ok := val.(string); ok {
					if effLower {
						val = strings.ToLower(strVal)
					} else if b.ESType == "date" || b.ESType == "date_nanos" {
						if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
							val = ms
						}
					}
				}
				val = normalizeDateNanosValue(b.ESType, val)
				parts = append(parts, fmt.Sprintf("array_contains(`%s`, %s)", arrCol, quoteStr(fmt.Sprintf("%v", val))))
			}
		}
		return strings.Join(parts, " AND ")
	}
	if q.Terms != nil && len(q.Terms.Fields) > 0 {
		var parts []string
		for _, field := range sortedMapKeys(q.Terms.Fields) {
			vals := q.Terms.Fields[field]
			b := t.Schema.ResolveField(field)
			if b.Kind == schema.StorageNestedSubfield && b.NestedPath == nestedPath && b.PrefilterArrayCol != "" && len(vals) > 0 {
				effLower := b.EffectiveLowercase(true)
				arrCol := b.EffectiveArrayColumn(true)
				if b.ESType == "ip" {
					hasCIDR := false
					for _, v := range vals {
						if _, _, isCIDR := parseCIDRBounds(fmt.Sprintf("%v", v)); isCIDR {
							hasCIDR = true
							break
						}
					}
					if hasCIDR {
						continue
					}
				}
				now := time.Now().UTC()
				var quoted []string
				for _, v := range vals {
					if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean {
						if bv, ok := normalizeBooleanQueryValue(v); ok {
							v = bv
						}
					} else if strVal, ok := v.(string); ok {
						if effLower {
							v = strings.ToLower(strVal)
						} else if b.ESType == "date" || b.ESType == "date_nanos" {
							if ms, ok := schema.ParseESDateToEpochMillis(strVal, now); ok {
								v = ms
							}
						}
					}
					v = normalizeDateNanosValue(b.ESType, v)
					quoted = append(quoted, quoteStr(fmt.Sprintf("%v", v)))
				}
				parts = append(parts, fmt.Sprintf("arrays_overlap(`%s`, [%s])", arrCol, strings.Join(quoted, ", ")))
			}
		}
		return strings.Join(parts, " AND ")
	}
	if q.Bool != nil {
		var parts []string
		for i := range q.Bool.Must {
			if pf := t.extractNestedPrefilter(nestedPath, &q.Bool.Must[i]); pf != "" {
				parts = append(parts, pf)
			}
		}
		for i := range q.Bool.Filter {
			if pf := t.extractNestedPrefilter(nestedPath, &q.Bool.Filter[i]); pf != "" {
				parts = append(parts, pf)
			}
		}
		return strings.Join(parts, " AND ")
	}
	return ""
}

func (t *Transpiler) compileFunctionScore(fs *esast.FunctionScoreQuery, nctx *nestedCtx) CompiledQuery {
	base := CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: "1.0"}
	if fs.Query != nil {
		base = t.CompileQuery(fs.Query, true, nctx)
	}
	hasScriptFn := fs.ScriptScore != nil
	for i := range fs.Functions {
		if fs.Functions[i].ScriptScore != nil || queryContainsScript(fs.Functions[i].Filter) {
			hasScriptFn = true
			break
		}
	}
	if hasScriptFn {
		return base
	}
	funcs := fs.Functions
	if len(funcs) == 0 && (fs.FieldValueFactor != nil || fs.Weight != nil) {
		funcs = []esast.ScoreFunctionSpec{
			{
				Weight:           fs.Weight,
				FieldValueFactor: fs.FieldValueFactor,
			},
		}
	}
	if len(funcs) == 0 {
		if fs.Boost != nil && *fs.Boost != 1.0 {
			base.ScoreSQL = fmt.Sprintf("(%.4f * (%s))", *fs.Boost, base.ScoreSQL)
		}
		if fs.MinScore != nil && !queryContainsScript(&esast.Query{FunctionScore: fs}) {
			minCond := fmt.Sprintf("(%s >= %.4f)", base.ScoreSQL, *fs.MinScore)
			base.WhereSQL = fmt.Sprintf("(%s) AND %s", base.WhereSQL, minCond)
			base.SafeWhereSQL = fmt.Sprintf("(%s) AND %s", base.EffectiveSafeWhere(), minCond)
		}
		return base
	}
	scoreMode := strings.ToLower(fs.ScoreMode)
	isMultiplyMode := scoreMode == "" || scoreMode == "multiply"
	var funcExprs []string
	var rawValExprs []string
	var filterCondExprs []string
	var activeFilterConds []string
	hasUnfilteredFunc := false
	for _, fn := range funcs {
		weight := 1.0
		if fn.Weight != nil {
			weight = *fn.Weight
		}
		valExpr := fmt.Sprintf("%.4f", weight)
		if fn.FieldValueFactor != nil {
			fvf := fn.FieldValueFactor
			col := t.sqlNumericColumnRef(fvf.Field, nctx)
			factor := 1.0
			if fvf.Factor != nil {
				factor = *fvf.Factor
			}
			missing := 0.0
			if fvf.Missing != nil {
				missing = *fvf.Missing
			}
			scaled := fmt.Sprintf("(%.4f * COALESCE(%s, %.4f))", factor, col, missing)
			var modExpr string
			switch strings.ToLower(fvf.Modifier) {
			case "log":
				modExpr = fmt.Sprintf("LOG10(GREATEST(0.0001, %s))", scaled)
			case "log1p":
				modExpr = fmt.Sprintf("LOG10(1.0 + GREATEST(0.0, %s))", scaled)
			case "log2p":
				modExpr = fmt.Sprintf("LOG10(2.0 + GREATEST(0.0, %s))", scaled)
			case "ln":
				modExpr = fmt.Sprintf("LN(GREATEST(0.0001, %s))", scaled)
			case "ln1p":
				modExpr = fmt.Sprintf("LN(1.0 + GREATEST(0.0, %s))", scaled)
			case "ln2p":
				modExpr = fmt.Sprintf("LN(2.0 + GREATEST(0.0, %s))", scaled)
			case "square":
				modExpr = fmt.Sprintf("((%s) * (%s))", scaled, scaled)
			case "sqrt":
				modExpr = fmt.Sprintf("SQRT(GREATEST(0.0, %s))", scaled)
			case "reciprocal":
				modExpr = fmt.Sprintf("(1.0 / (1.0 + GREATEST(0.0, %s)))", scaled)
			default:
				modExpr = scaled
			}
			valExpr = fmt.Sprintf("(%.4f * %s)", weight, modExpr)
		}
		rawValExprs = append(rawValExprs, valExpr)
		if fn.Filter != nil {
			cond := t.CompileQuery(fn.Filter, true, nctx)
			condExpr := cond.EffectiveSafeWhere()
			filterCondExprs = append(filterCondExprs, condExpr)
			activeFilterConds = append(activeFilterConds, fmt.Sprintf("(%s)", condExpr))
			elseVal := "0.0"
			if isMultiplyMode {
				elseVal = "1.0"
			} else if scoreMode == "min" {
				elseVal = "999999999.0"
			}
			funcExprs = append(funcExprs, fmt.Sprintf("(CASE WHEN %s THEN %s ELSE %s END)", condExpr, valExpr, elseVal))
		} else {
			hasUnfilteredFunc = true
			filterCondExprs = append(filterCondExprs, "")
			funcExprs = append(funcExprs, valExpr)
		}
	}

	var combinedFuncs string
	switch scoreMode {
	case "sum":
		combinedFuncs = strings.Join(funcExprs, " + ")
	case "avg":
		if len(funcExprs) == 1 {
			combinedFuncs = funcExprs[0]
		} else if len(activeFilterConds) > 0 {
			var countTerms []string
			for _, fc := range filterCondExprs {
				if fc == "" {
					countTerms = append(countTerms, "1.0")
				} else {
					countTerms = append(countTerms, fmt.Sprintf("(CASE WHEN %s THEN 1.0 ELSE 0.0 END)", fc))
				}
			}
			combinedFuncs = fmt.Sprintf("((%s) / GREATEST(1.0, %s))", strings.Join(funcExprs, " + "), strings.Join(countTerms, " + "))
		} else {
			combinedFuncs = fmt.Sprintf("((%s) / %d.0)", strings.Join(funcExprs, " + "), len(funcExprs))
		}
	case "max":
		if len(funcExprs) == 1 {
			combinedFuncs = funcExprs[0]
		} else {
			combinedFuncs = fmt.Sprintf("GREATEST(%s)", strings.Join(funcExprs, ", "))
		}
	case "min":
		if len(funcExprs) == 1 {
			combinedFuncs = funcExprs[0]
		} else {
			combinedFuncs = fmt.Sprintf("LEAST(%s)", strings.Join(funcExprs, ", "))
		}
	case "first":
		if len(funcExprs) == 1 {
			combinedFuncs = funcExprs[0]
		} else {
			var caseParts []string
			elseFallback := "1.0"
			hasUnfiltered := false
			for i := range funcs {
				if filterCondExprs[i] == "" {
					elseFallback = rawValExprs[i]
					hasUnfiltered = true
					break
				}
				caseParts = append(caseParts, fmt.Sprintf("WHEN %s THEN %s", filterCondExprs[i], rawValExprs[i]))
			}
			if len(caseParts) == 0 {
				combinedFuncs = elseFallback
			} else {
				if !hasUnfiltered && strings.ToLower(fs.BoostMode) == "replace" {
					elseFallback = base.ScoreSQL
				}
				combinedFuncs = fmt.Sprintf("(CASE %s ELSE %s END)", strings.Join(caseParts, " "), elseFallback)
			}
		}
	default:
		combinedFuncs = strings.Join(funcExprs, " * ")
	}
	if fs.MaxBoost != nil {
		combinedFuncs = fmt.Sprintf("LEAST(%.4f, %s)", *fs.MaxBoost, combinedFuncs)
	}

	var finalScore string
	switch strings.ToLower(fs.BoostMode) {
	case "sum":
		finalScore = fmt.Sprintf("((%s) + (%s))", base.ScoreSQL, combinedFuncs)
	case "avg":
		finalScore = fmt.Sprintf("(((%s) + (%s)) / 2.0)", base.ScoreSQL, combinedFuncs)
	case "max":
		finalScore = fmt.Sprintf("GREATEST(%s, %s)", base.ScoreSQL, combinedFuncs)
	case "min":
		finalScore = fmt.Sprintf("LEAST(%s, %s)", base.ScoreSQL, combinedFuncs)
	case "replace":
		finalScore = combinedFuncs
	default:
		finalScore = fmt.Sprintf("((%s) * (%s))", base.ScoreSQL, combinedFuncs)
	}
	if !hasUnfilteredFunc && len(activeFilterConds) > 0 {
		finalScore = fmt.Sprintf("(CASE WHEN (%s) THEN %s ELSE %s END)", strings.Join(activeFilterConds, " OR "), finalScore, base.ScoreSQL)
	}
	if fs.Boost != nil && *fs.Boost != 1.0 {
		finalScore = fmt.Sprintf("(%.4f * %s)", *fs.Boost, finalScore)
	}
	whereSQL := base.WhereSQL
	safeWhereSQL := base.EffectiveSafeWhere()
	if fs.MinScore != nil && !queryContainsScript(&esast.Query{FunctionScore: fs}) {
		minScoreCond := fmt.Sprintf("(%s >= %.4f)", finalScore, *fs.MinScore)
		if whereSQL == "" || whereSQL == "TRUE" {
			whereSQL = minScoreCond
		} else {
			whereSQL = fmt.Sprintf("(%s AND %s)", whereSQL, minScoreCond)
		}
		if safeWhereSQL == "" || safeWhereSQL == "TRUE" {
			safeWhereSQL = minScoreCond
		} else {
			safeWhereSQL = fmt.Sprintf("(%s AND %s)", safeWhereSQL, minScoreCond)
		}
	}
	return CompiledQuery{
		WhereSQL:          whereSQL,
		SafeWhereSQL:      safeWhereSQL,
		ScoreSQL:          finalScore,
		UsesFulltextMatch: base.UsesFulltextMatch,
	}
}

func (t *Transpiler) compileTermsSetTermPredicate(field string, val any, nctx *nestedCtx) string {
	basePred := t.compileTermPredicate(field, val, false, nctx)
	b := t.Schema.ResolveField(field)
	if nctx != nil || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield ||
		b.Kind == schema.StoragePromotedVector || len(b.SourceJSONPath) == 0 ||
		field == "_id" || field == "_doc" || field == "_all_text" || field == "*" {
		return basePred
	}
	effLower := b.EffectiveLowercase(true)
	strVal := fmt.Sprintf("%v", val)
	if effLower {
		strVal = strings.ToLower(strVal)
	}
	var pathBuilder strings.Builder
	for _, seg := range b.SourceJSONPath {
		_, _ = fmt.Fprintf(&pathBuilder, "[%s]", quoteStr(seg))
	}
	var arrExpr string
	if effLower {
		arrExpr = fmt.Sprintf("array_exists(_x -> lower(_x) = %s, CAST(`_doc`%s AS ARRAY<STRING>))", quoteStr(strVal), pathBuilder.String())
	} else {
		arrExpr = fmt.Sprintf("array_contains(CAST(`_doc`%s AS ARRAY<STRING>), %s)", pathBuilder.String(), quoteStr(strVal))
	}
	return fmt.Sprintf("(%s OR %s)", basePred, arrExpr)
}

func (t *Transpiler) compileTermPredicate(field string, val any, caseInsensitive bool, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	if b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	if b.ESType == "ip" {
		if strVal, ok := val.(string); ok {
			if startNum, endNum, isCIDR := parseCIDRBounds(strVal); isCIDR {
				if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) {
					colName := b.EffectiveArrayColumn(true)
					return fmt.Sprintf("array_exists(_x -> IPV4_STRING_TO_NUM_OR_NULL(_x) >= %d AND IPV4_STRING_TO_NUM_OR_NULL(_x) <= %d, `%s`)", startNum, endNum, colName)
				}
				rawCol := t.sqlColumnRef(field, true, nctx)
				numCol := fmt.Sprintf("IPV4_STRING_TO_NUM_OR_NULL(%s)", rawCol)
				return fmt.Sprintf("(%s >= %d AND %s <= %d)", numCol, startNum, numCol, endNum)
			}
		}
	}
	if b.ESType == "text" && b.KeywordCompanion == "" && !strings.HasSuffix(field, ".keyword") {
		if _, isBool := val.(bool); isBool {
			return t.compileMatchField(field, fmt.Sprintf("%v", val), "or", 1.0, false, nctx).WhereSQL
		}
	}
	effLower := b.EffectiveLowercase(true)
	effDT := effectiveDorisScalarType(b)
	if effDT == schema.DorisBoolean {
		if bv, ok := normalizeBooleanQueryValue(val); ok {
			val = bv
		}
	} else if strVal, ok := val.(string); ok {
		if effLower {
			val = strings.ToLower(strVal)
		} else if effDT == schema.DorisBigInt || b.ESType == "date" || b.ESType == "date_nanos" {
			if b.Kind == schema.StorageNestedSubfield && nctx != nil && nctx.nestedPath == b.NestedPath {
				if strings.HasPrefix(strings.TrimSpace(strVal), "now") || strings.Contains(strVal, "||") {
					if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
						val = time.UnixMilli(ms).UTC().Format(time.RFC3339)
					}
				}
			} else if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
				val = ms
			}
		}
	} else if val != nil && (b.Kind == schema.StoragePromotedScalar || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && (effDT == schema.DorisVarchar || effDT == schema.DorisString) {
		sv := fmt.Sprintf("%v", val)
		if effLower {
			sv = strings.ToLower(sv)
		}
		val = sv
	}
	val = normalizeDateNanosValue(b.ESType, val)
	lit := quoteValue(val)

	switch b.Kind {
	case schema.StoragePromotedVector:
		return "FALSE"
	case schema.StoragePromotedArray:
		colName := b.EffectiveArrayColumn(true)
		if caseInsensitive && !effLower {
			return fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), `%s`)", quoteStr(fmt.Sprintf("%v", val)), colName)
		}
		return fmt.Sprintf("array_contains(`%s`, %s)", colName, quoteStr(fmt.Sprintf("%v", val)))
	case schema.StorageNestedSubfield:
		if nctx != nil && nctx.nestedPath == b.NestedPath {
			relPath := "$." + strings.Join(b.RelativeJSONPath, ".")
			if b.IsMultiValued {
				strVal := fmt.Sprintf("%v", val)
				if _, isStr := val.(string); isStr {
					strVal = `"` + strVal + `"`
				}
				likePat := quoteStr("%" + escapeLikeLiteral(strVal) + "%")
				extracted := fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath))
				rawLit := quoteStr(fmt.Sprintf("%v", val))
				if caseInsensitive || effLower {
					return fmt.Sprintf("(lower(%s) = lower(%s) OR lower(%s) LIKE lower(%s))", extracted, rawLit, extracted, likePat)
				}
				return fmt.Sprintf("(%s = %s OR %s LIKE %s)", extracted, rawLit, extracted, likePat)
			}
			if caseInsensitive || effLower {
				return fmt.Sprintf("lower(json_extract_string(%s, %s)) = lower(%s)", nctx.elemVar, quoteStr(relPath), quoteStr(fmt.Sprintf("%v", val)))
			}
			return fmt.Sprintf("json_extract_string(%s, %s) = %s", nctx.elemVar, quoteStr(relPath), quoteStr(fmt.Sprintf("%v", val)))
		}
		if b.PrefilterArrayCol != "" {
			arrCol := b.EffectiveArrayColumn(true)
			if caseInsensitive && !effLower {
				return fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), `%s`)", quoteStr(fmt.Sprintf("%v", val)), arrCol)
			}
			return fmt.Sprintf("array_contains(`%s`, %s)", arrCol, quoteStr(fmt.Sprintf("%v", val)))
		}
	}

	col := t.sqlTypedColumnRef(field, val, true, nctx)
	if caseInsensitive {
		return fmt.Sprintf("lower(%s) = lower(%s)", col, lit)
	}
	return fmt.Sprintf("%s = %s", col, lit)
}

func (t *Transpiler) compileTermsPredicate(field string, vals []any, nctx *nestedCtx) string {
	if len(vals) == 0 {
		return "FALSE"
	}
	b := t.Schema.ResolveField(field)
	if b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	if b.ESType == "ip" {
		hasCIDR := false
		for _, v := range vals {
			if s, ok := v.(string); ok {
				if _, _, isCIDR := parseCIDRBounds(s); isCIDR {
					hasCIDR = true
					break
				}
			}
		}
		if hasCIDR {
			var disjuncts []string
			for _, v := range vals {
				disjuncts = append(disjuncts, t.compileTermPredicate(field, v, false, nctx))
			}
			if len(disjuncts) == 1 {
				return disjuncts[0]
			}
			return "(" + strings.Join(disjuncts, " OR ") + ")"
		}
	}
	effLower := b.EffectiveLowercase(true)
	isArrayCol := b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath))
	if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
		var disjuncts []string
		for _, v := range vals {
			disjuncts = append(disjuncts, t.compileTermPredicate(field, v, false, nctx))
		}
		return "(" + strings.Join(disjuncts, " OR ") + ")"
	}
	now := time.Now().UTC()
	effDT := effectiveDorisScalarType(b)
	quoted := make([]string, 0, len(vals))
	normalizedVals := make([]any, 0, len(vals))
	for _, v := range vals {
		if effDT == schema.DorisBoolean {
			if bv, ok := normalizeBooleanQueryValue(v); ok {
				v = bv
			}
		} else if strVal, ok := v.(string); ok {
			if effLower {
				v = strings.ToLower(strVal)
			} else if effDT == schema.DorisBigInt || b.ESType == "date" || b.ESType == "date_nanos" {
				if b.Kind == schema.StorageNestedSubfield && nctx != nil && nctx.nestedPath == b.NestedPath {
					if strings.HasPrefix(strings.TrimSpace(strVal), "now") || strings.Contains(strVal, "||") {
						if ms, ok := schema.ParseESDateToEpochMillis(strVal, now); ok {
							v = time.UnixMilli(ms).UTC().Format(time.RFC3339)
						}
					}
				} else if ms, ok := schema.ParseESDateToEpochMillis(strVal, now); ok {
					v = ms
				}
			}
		} else if v != nil && (b.Kind == schema.StoragePromotedScalar || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && (effDT == schema.DorisVarchar || effDT == schema.DorisString) {
			sv := fmt.Sprintf("%v", v)
			if effLower {
				sv = strings.ToLower(sv)
			}
			v = sv
		}
		v = normalizeDateNanosValue(b.ESType, v)
		normalizedVals = append(normalizedVals, v)
		if isArrayCol {
			quoted = append(quoted, quoteStr(fmt.Sprintf("%v", v)))
		} else {
			quoted = append(quoted, quoteValue(v))
		}
	}
	if isArrayCol {
		colName := b.EffectiveArrayColumn(true)
		return fmt.Sprintf("arrays_overlap(`%s`, [%s])", colName, strings.Join(quoted, ", "))
	}
	col := t.sqlTypedColumnRef(field, normalizedVals[0], true, nctx)
	if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && effLower {
		col = fmt.Sprintf("lower(%s)", col)
	}
	return fmt.Sprintf("%s IN (%s)", col, strings.Join(quoted, ", "))
}

func (t *Transpiler) compilePrefixPredicate(field, val string, caseInsensitive bool, nctx *nestedCtx) string {
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.Schema.ExpandFieldPattern(field)
		if len(exp) == 0 {
			return t.compilePrefixSingleField("_all_text", val, caseInsensitive, nctx)
		}
		var disjuncts []string
		for _, bf := range exp {
			disjuncts = append(disjuncts, t.compilePrefixSingleField(bf.Field, val, caseInsensitive, nctx))
		}
		if len(disjuncts) == 1 {
			return disjuncts[0]
		}
		return "(" + strings.Join(disjuncts, " OR ") + ")"
	}
	return t.compilePrefixSingleField(field, val, caseInsensitive, nctx)
}

func (t *Transpiler) compilePrefixSingleField(field, val string, caseInsensitive bool, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	if b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	effLower := b.EffectiveLowercase(true)
	if effLower {
		val = strings.ToLower(val)
	}
	likePat := quoteStr(escapeLikeLiteral(val) + "%")
	if (nctx == nil || nctx.nestedPath != b.NestedPath) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		colName := b.EffectiveArrayColumn(true)
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `%s`)", likePat, colName)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, `%s`)", likePat, colName)
	}
	col := t.sqlColumnRef(field, true, nctx)
	if caseInsensitive || (nctx != nil && effLower) {
		return fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likePat)
	}
	return fmt.Sprintf("%s LIKE %s", col, likePat)
}

func (t *Transpiler) compileWildcardPredicate(field, val string, caseInsensitive bool, nctx *nestedCtx) string {
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.Schema.ExpandFieldPattern(field)
		if len(exp) == 0 {
			return t.compileWildcardSingleField("_all_text", val, caseInsensitive, nctx)
		}
		var disjuncts []string
		for _, bf := range exp {
			disjuncts = append(disjuncts, t.compileWildcardSingleField(bf.Field, val, caseInsensitive, nctx))
		}
		if len(disjuncts) == 1 {
			return disjuncts[0]
		}
		return "(" + strings.Join(disjuncts, " OR ") + ")"
	}
	return t.compileWildcardSingleField(field, val, caseInsensitive, nctx)
}

func (t *Transpiler) compileWildcardSingleField(field, val string, caseInsensitive bool, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	if b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	effLower := b.EffectiveLowercase(true)
	if effLower {
		val = strings.ToLower(val)
	}
	likePat := quoteStr(wildcardToLike(val))
	if (nctx == nil || nctx.nestedPath != b.NestedPath) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		colName := b.EffectiveArrayColumn(true)
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `%s`)", likePat, colName)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, `%s`)", likePat, colName)
	}
	col := t.sqlColumnRef(field, true, nctx)
	if caseInsensitive || (nctx != nil && effLower) {
		return fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likePat)
	}
	return fmt.Sprintf("%s LIKE %s", col, likePat)
}

func (t *Transpiler) compileRangePredicate(field string, rc esast.RangeCond, nctx *nestedCtx) string {
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.Schema.ExpandFieldPattern(field)
		if len(exp) > 0 {
			var disjuncts []string
			for _, bf := range exp {
				disjuncts = append(disjuncts, t.compileRangeSingleField(bf.Field, rc, nctx))
			}
			if len(disjuncts) == 1 {
				return disjuncts[0]
			}
			return "(" + strings.Join(disjuncts, " OR ") + ")"
		}
	}
	return t.compileRangeSingleField(field, rc, nctx)
}

func (t *Transpiler) compileRangeSingleField(field string, rc esast.RangeCond, nctx *nestedCtx) string {
	gt, gte, lt, lte := rc.NormalizedBounds()
	b := t.Schema.ResolveField(field)
	if b.ESType == "ip" {
		if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) {
			colName := b.EffectiveArrayColumn(true)
			numElem := "IPV4_STRING_TO_NUM_OR_NULL(_x)"
			var elemParts []string
			if gt != nil {
				if n, ok := parseIPv4ToUint32(gt); ok {
					elemParts = append(elemParts, fmt.Sprintf("%s > %d", numElem, n))
				} else {
					elemParts = append(elemParts, fmt.Sprintf("_x > %s", quoteValue(gt)))
				}
			}
			if gte != nil {
				if n, ok := parseIPv4ToUint32(gte); ok {
					elemParts = append(elemParts, fmt.Sprintf("%s >= %d", numElem, n))
				} else {
					elemParts = append(elemParts, fmt.Sprintf("_x >= %s", quoteValue(gte)))
				}
			}
			if lt != nil {
				if n, ok := parseIPv4ToUint32(lt); ok {
					elemParts = append(elemParts, fmt.Sprintf("%s < %d", numElem, n))
				} else {
					elemParts = append(elemParts, fmt.Sprintf("_x < %s", quoteValue(lt)))
				}
			}
			if lte != nil {
				if n, ok := parseIPv4ToUint32(lte); ok {
					elemParts = append(elemParts, fmt.Sprintf("%s <= %d", numElem, n))
				} else {
					elemParts = append(elemParts, fmt.Sprintf("_x <= %s", quoteValue(lte)))
				}
			}
			if len(elemParts) == 0 {
				return "TRUE"
			}
			return fmt.Sprintf("array_exists(_x -> %s, `%s`)", strings.Join(elemParts, " AND "), colName)
		}
		rawCol := t.sqlColumnRef(field, true, nctx)
		numCol := fmt.Sprintf("IPV4_STRING_TO_NUM_OR_NULL(%s)", rawCol)
		var parts []string
		if gt != nil {
			if n, ok := parseIPv4ToUint32(gt); ok {
				parts = append(parts, fmt.Sprintf("%s > %d", numCol, n))
			} else {
				parts = append(parts, fmt.Sprintf("%s > %s", rawCol, quoteValue(gt)))
			}
		}
		if gte != nil {
			if n, ok := parseIPv4ToUint32(gte); ok {
				parts = append(parts, fmt.Sprintf("%s >= %d", numCol, n))
			} else {
				parts = append(parts, fmt.Sprintf("%s >= %s", rawCol, quoteValue(gte)))
			}
		}
		if lt != nil {
			if n, ok := parseIPv4ToUint32(lt); ok {
				parts = append(parts, fmt.Sprintf("%s < %d", numCol, n))
			} else {
				parts = append(parts, fmt.Sprintf("%s < %s", rawCol, quoteValue(lt)))
			}
		}
		if lte != nil {
			if n, ok := parseIPv4ToUint32(lte); ok {
				parts = append(parts, fmt.Sprintf("%s <= %d", numCol, n))
			} else {
				parts = append(parts, fmt.Sprintf("%s <= %s", rawCol, quoteValue(lte)))
			}
		}
		if len(parts) == 0 {
			return "TRUE"
		}
		return strings.Join(parts, " AND ")
	}
	now := time.Now().UTC()
	isEpochSecond := strings.EqualFold(rc.Format, "epoch_second")
	tzOffsetMs := esast.ParseTimeZoneOffsetMs(strings.TrimSpace(rc.TimeZone))

	coerceBound := func(v any, roundUp bool) any {
		if v == nil {
			return nil
		}
		if b.Kind == schema.StorageNestedSubfield && nctx != nil && nctx.nestedPath == b.NestedPath {
			if b.ESType == "date" || b.ESType == "date_nanos" {
				if strVal, ok := v.(string); ok {
					trimmed := strings.TrimSpace(strVal)
					if strings.HasPrefix(trimmed, "now") || strings.Contains(trimmed, "||") {
						if ms, ok := schema.ParseESDateBoundToEpochMillis(strVal, now, roundUp); ok {
							return time.UnixMilli(ms).UTC().Format(time.RFC3339)
						}
					}
				}
			}
			return v
		}
		switch effectiveDorisScalarType(b) {
		case schema.DorisBigInt:
			if strVal, ok := v.(string); ok {
				trimmed := strings.TrimSpace(strVal)
				if rawSec, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(rawSec) && !math.IsInf(rawSec, 0) {
					if isEpochSecond {
						return int64(rawSec * 1000)
					}
					iv := int64(rawSec)
					if norm, ok := normalizeDateNanosValue(b.ESType, iv).(int64); ok {
						iv = norm
					}
					return iv
				}
				if ms, ok := schema.ParseESDateBoundToEpochMillis(strVal, now, roundUp); ok {
					datePart := trimmed
					if idx := strings.Index(datePart, "||"); idx >= 0 {
						datePart = strings.TrimSpace(datePart[:idx])
					}
					if _, intErr := strconv.ParseInt(datePart, 10, 64); intErr != nil &&
						tzOffsetMs != 0 && !strings.HasPrefix(datePart, "now") &&
						!strings.HasSuffix(datePart, "Z") && !strings.HasSuffix(datePart, "z") &&
						!strings.Contains(datePart[min(10, len(datePart)):], "+") &&
						!strings.Contains(datePart[min(10, len(datePart)):], "-") {
						ms -= tzOffsetMs
					}
					return normalizeDateNanosValue(b.ESType, ms)
				}
			}
			if b.ESType == "date_nanos" && !isEpochSecond {
				return normalizeDateNanosValue(b.ESType, v)
			}
			if isEpochSecond {
				switch nv := v.(type) {
				case int:
					return int64(nv) * 1000
				case int64:
					return nv * 1000
				case float64:
					return int64(nv * 1000)
				case json.Number:
					if i, err := nv.Int64(); err == nil {
						return i * 1000
					} else if f, err := nv.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
						return int64(f * 1000)
					}
				}
			}
		case schema.DorisInt:
			if strVal, ok := v.(string); ok {
				if i, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
					return i
				}
			}
		case schema.DorisDouble:
			if strVal, ok := v.(string); ok {
				if f, err := strconv.ParseFloat(strings.TrimSpace(strVal), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					return f
				}
			}
		}
		return v
	}

	gt = coerceBound(gt, true)
	gte = coerceBound(gte, false)
	lt = coerceBound(lt, false)
	lte = coerceBound(lte, true)

	var sampleBound any
	for _, cand := range []any{gt, gte, lt, lte} {
		if cand == nil {
			continue
		}
		if sampleBound == nil {
			sampleBound = cand
		}
		switch fv := cand.(type) {
		case float64:
			if fv != math.Trunc(fv) {
				sampleBound = cand
			}
		case json.Number:
			if _, err := fv.Int64(); err != nil {
				sampleBound = cand
			}
		}
	}

	if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) {
		elemExpr := "_x"
		switch sv := sampleBound.(type) {
		case int, int64:
			elemExpr = "CAST(_x AS BIGINT)"
		case float64:
			if sv == math.Trunc(sv) {
				elemExpr = "CAST(_x AS BIGINT)"
			} else {
				elemExpr = "CAST(_x AS DOUBLE)"
			}
		case json.Number:
			if _, err := sv.Int64(); err == nil {
				elemExpr = "CAST(_x AS BIGINT)"
			} else {
				elemExpr = "CAST(_x AS DOUBLE)"
			}
		}
		var elemParts []string
		if gt != nil {
			elemParts = append(elemParts, fmt.Sprintf("%s > %s", elemExpr, quoteValue(gt)))
		}
		if gte != nil {
			elemParts = append(elemParts, fmt.Sprintf("%s >= %s", elemExpr, quoteValue(gte)))
		}
		if lt != nil {
			elemParts = append(elemParts, fmt.Sprintf("%s < %s", elemExpr, quoteValue(lt)))
		}
		if lte != nil {
			elemParts = append(elemParts, fmt.Sprintf("%s <= %s", elemExpr, quoteValue(lte)))
		}
		if len(elemParts) == 0 {
			return "TRUE"
		}
		return fmt.Sprintf("array_exists(_x -> %s, `%s`)", strings.Join(elemParts, " AND "), b.EffectiveArrayColumn(true))
	}

	col := t.sqlTypedColumnRef(field, sampleBound, true, nctx)

	var parts []string
	if gt != nil {
		parts = append(parts, fmt.Sprintf("%s > %s", col, quoteValue(gt)))
	}
	if gte != nil {
		parts = append(parts, fmt.Sprintf("%s >= %s", col, quoteValue(gte)))
	}
	if lt != nil {
		parts = append(parts, fmt.Sprintf("%s < %s", col, quoteValue(lt)))
	}
	if lte != nil {
		parts = append(parts, fmt.Sprintf("%s <= %s", col, quoteValue(lte)))
	}
	if len(parts) == 0 {
		return "TRUE"
	}
	return strings.Join(parts, " AND ")
}

func (t *Transpiler) compileExistsPredicate(field string, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) {
		arrCol := b.EffectiveArrayColumn(true)
		return fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", arrCol, arrCol)
	}
	col := t.sqlColumnRef(field, true, nctx)
	return fmt.Sprintf("%s IS NOT NULL", col)
}

func hasGlobalAgg(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.Global != nil || hasGlobalAgg(spec.SubAggs()) {
			return true
		}
	}
	return false
}

func (t *Transpiler) buildAggsCTESQL(baseWhere, userWhere, aliasWhere, postFilterSQL string, aggs map[string]esast.AggSpec) string {
	if !hasGlobalAgg(aggs) {
		var branches []string
		metaWhere := ""
		if postFilterSQL != "" && postFilterSQL != "TRUE" {
			metaWhere = " WHERE " + postFilterSQL
			branches = append(branches,
				"SELECT '__meta_query_total' AS `_agg_name`, '_count' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`")
		}
		branches = append(branches,
			"SELECT '__meta_total' AS `_agg_name`, '_count' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`"+metaWhere)

		subIdx := 0
		t.appendAggBranches(&branches, &subIdx, "", "", aggs)

		return fmt.Sprintf(
			"WITH `base_matched` AS (SELECT * FROM `%s`.`%s` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (%s))\n%s",
			t.Schema.DorisDB,
			t.Schema.DorisTable,
			baseWhere,
			strings.Join(branches, "\nUNION ALL\n"),
		)
	}

	effectiveUserWhere := userWhere
	if aliasWhere == "" {
		effectiveUserWhere = baseWhere
	}

	var branches []string
	var metaConds []string
	var queryMetaConds []string
	if effectiveUserWhere != "" && effectiveUserWhere != "TRUE" {
		metaConds = append(metaConds, fmt.Sprintf("(%s)", effectiveUserWhere))
		queryMetaConds = append(queryMetaConds, fmt.Sprintf("(%s)", effectiveUserWhere))
	}
	if postFilterSQL != "" && postFilterSQL != "TRUE" {
		metaConds = append(metaConds, fmt.Sprintf("(%s)", postFilterSQL))
		queryMetaWhere := ""
		if len(queryMetaConds) > 0 {
			queryMetaWhere = " WHERE " + strings.Join(queryMetaConds, " AND ")
		}
		branches = append(branches,
			"SELECT '__meta_query_total' AS `_agg_name`, '_count' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`"+queryMetaWhere)
	}
	metaWhere := ""
	if len(metaConds) > 0 {
		metaWhere = " WHERE " + strings.Join(metaConds, " AND ")
	}
	branches = append(branches,
		"SELECT '__meta_total' AS `_agg_name`, '_count' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`"+metaWhere)

	topExtraWhere := ""
	if effectiveUserWhere != "" && effectiveUserWhere != "TRUE" {
		topExtraWhere = effectiveUserWhere
	}
	subIdx := 0
	t.appendAggBranches(&branches, &subIdx, "", topExtraWhere, aggs)

	cteWhere := "`__DORIS_DELETE_SIGN__` = 0"
	if aliasWhere != "" && aliasWhere != "TRUE" {
		cteWhere = fmt.Sprintf("`__DORIS_DELETE_SIGN__` = 0 AND (%s)", aliasWhere)
	}
	return fmt.Sprintf(
		"WITH `base_matched` AS (SELECT * FROM `%s`.`%s` WHERE %s)\n%s",
		t.Schema.DorisDB,
		t.Schema.DorisTable,
		cteWhere,
		strings.Join(branches, "\nUNION ALL\n"),
	)
}

func (t *Transpiler) appendAggBranches(
	branches *[]string,
	subIdx *int,
	prefix string,
	extraWhere string,
	aggs map[string]esast.AggSpec,
) {
	aggNames := make([]string, 0, len(aggs))
	for k := range aggs {
		aggNames = append(aggNames, k)
	}
	sort.Strings(aggNames)

	wherePrefix := ""
	if extraWhere != "" {
		wherePrefix = fmt.Sprintf("(%s) AND ", extraWhere)
	}

	for _, name := range aggNames {
		fullAggName := name
		if prefix != "" {
			fullAggName = prefix + "." + name
		}
		spec := aggs[name]
		switch {
		case spec.Global != nil:
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_global' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`",
				quoteStr(fullAggName),
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendAggBranches(branches, subIdx, fullAggName, "", subAggs)
			}

		case spec.ReverseNested != nil:
			wClause := ""
			if extraWhere != "" {
				wClause = " WHERE " + extraWhere
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_reverse_nested' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`%s",
				quoteStr(fullAggName), wClause,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendAggBranches(branches, subIdx, fullAggName, extraWhere, subAggs)
			}

		case spec.EffectiveSampler() != nil:
			wClause := ""
			if extraWhere != "" {
				wClause = " WHERE " + extraWhere
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_sampler' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`%s",
				quoteStr(fullAggName), wClause,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendAggBranches(branches, subIdx, fullAggName, extraWhere, subAggs)
			}

		case spec.EffectiveTerms() != nil:
			termsSpec := spec.EffectiveTerms()
			size := t.capBucketSize(termsSpec.Size)
			if termsSpec.Order != nil || termsSpec.Include != nil || termsSpec.Exclude != nil {
				size = t.maxAggBuckets()
			}
			effField := termsSpec.Field
			if effField == "" && termsSpec.Script != nil {
				if df, ok := extractSimpleDocFieldFromScript(termsSpec.Script); ok {
					effField = df
				}
			}
			b := t.Schema.ResolveField(effField)
			*subIdx++
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				arrCol := b.EffectiveArrayColumn(true)
				elemValExpr := "`_elem`"
				if termsSpec.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(termsSpec.Script, effField, "`_elem`", nil); ok {
						elemValExpr = scriptExpr
					}
				}
				if termsSpec.Missing != nil {
					missingLit := quoteStr(formatMissingScalar(termsSpec.Missing))
					coalescedElem := fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", elemValExpr, missingLit)
					explodeFrom := fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) `_t` AS `_elem`", arrCol, arrCol, arrCol)
					wCond := ""
					if extraWhere != "" {
						wCond = "WHERE " + extraWhere + " "
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT `_id`) AS DOUBLE) AS `_doc_count` "+
							"FROM %s %s"+
							"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
							") `_agg_sub_%d`",
						quoteStr(fullAggName), coalescedElem, explodeFrom, wCond, size, *subIdx,
					))
					if subAggs := spec.SubAggs(); len(subAggs) > 0 {
						subWhere := "TRUE"
						if extraWhere != "" {
							subWhere = extraWhere
						}
						dedupFrom := fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id`, %s AS `_rn_bkey` FROM %s WHERE %s) `_rn_dedup` ON `base_matched`.`_id` = `_rn_dedup`.`_rn_id`", coalescedElem, explodeFrom, subWhere)
						t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, "`_rn_bkey`", dedupFrom, "1=1", subAggs)
					}
				} else {
					bucketKeyExpr := fmt.Sprintf("CAST(%s AS STRING)", elemValExpr)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT `_id`) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem` "+
							"WHERE %s`_elem` IS NOT NULL "+
							"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
							") `_agg_sub_%d`",
						quoteStr(fullAggName), bucketKeyExpr, arrCol, wherePrefix, size, *subIdx,
					))
					if subAggs := spec.SubAggs(); len(subAggs) > 0 {
						explodeFrom := fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem`", arrCol)
						explodeWhere := fmt.Sprintf("%s`_elem` IS NOT NULL", wherePrefix)
						dedupFrom := fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id`, %s AS `_rn_bkey` FROM %s WHERE %s) `_rn_dedup` ON `base_matched`.`_id` = `_rn_dedup`.`_rn_id`", bucketKeyExpr, explodeFrom, explodeWhere)
						t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, "`_rn_bkey`",
							dedupFrom, "1=1", subAggs)
					}
				}
			} else {
				col := t.sqlColumnRef(effField, true, nil)
				if termsSpec.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(termsSpec.Script, effField, col, nil); ok {
						col = scriptExpr
					}
				}
				if termsSpec.Missing != nil {
					missingLit := quoteStr(formatMissingScalar(termsSpec.Missing))
					coalescedCol := fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, missingLit)
					wCond := ""
					if extraWhere != "" {
						wCond = "WHERE " + extraWhere + " "
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` "+
							"%s"+
							"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
							") `_agg_sub_%d`",
						quoteStr(fullAggName), coalescedCol, wCond, size, *subIdx,
					))
					if subAggs := spec.SubAggs(); len(subAggs) > 0 {
						subWhere := "TRUE"
						if extraWhere != "" {
							subWhere = extraWhere
						}
						t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, coalescedCol,
							"`base_matched`", subWhere, subAggs)
					}
				} else {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
							"SELECT %s AS `_agg_name`, CAST(%s AS STRING) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` "+
							"WHERE %s%s IS NOT NULL "+
							"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
							") `_agg_sub_%d`",
						quoteStr(fullAggName), col, wherePrefix, col, size, *subIdx,
					))
					if subAggs := spec.SubAggs(); len(subAggs) > 0 {
						t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, fmt.Sprintf("CAST(%s AS STRING)", col),
							"`base_matched`", fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, col), subAggs)
					}
				}
			}

		case spec.Nested != nil:
			corrCol, ok := t.Schema.NestedRoots[spec.Nested.Path]
			if !ok {
				corrCol = "n__" + schema.SanitizeDorisIdentifier(spec.Nested.Path)
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_nested_doc_count' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s`_nel` IS NOT NULL",
				quoteStr(fullAggName), corrCol, wherePrefix,
			))
			subAggs := spec.SubAggs()
			subNames := make([]string, 0, len(subAggs))
			for sk := range subAggs {
				subNames = append(subNames, sk)
			}
			sort.Strings(subNames)
			nestedRelJSON := func(f string) string {
				relKey := strings.TrimSuffix(strings.TrimPrefix(f, spec.Nested.Path+"."), ".keyword")
				if b := t.Schema.ResolveField(f); len(b.RelativeJSONPath) > 0 {
					relKey = strings.Join(b.RelativeJSONPath, ".")
				}
				return quoteStr("$." + relKey)
			}
			for _, subName := range subNames {
				subSpec := subAggs[subName]
				subFull := fullAggName + "." + subName
				switch {
				case subSpec.ReverseNested != nil:
					rnWhere := fmt.Sprintf("`%s` IS NOT NULL AND array_size(`%s`) > 0", corrCol, corrCol)
					if extraWhere != "" {
						rnWhere = fmt.Sprintf("(%s) AND (%s)", extraWhere, rnWhere)
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, '_reverse_nested' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` WHERE %s",
						quoteStr(subFull), rnWhere,
					))
					if rnSubAggs := subSpec.SubAggs(); len(rnSubAggs) > 0 {
						t.appendAggBranches(branches, subIdx, subFull, rnWhere, rnSubAggs)
					}
				case subSpec.EffectiveTerms() != nil:
					subTerms := subSpec.EffectiveTerms()
					size := t.capBucketSize(subTerms.Size)
					if subTerms.Order != nil || subTerms.Include != nil || subTerms.Exclude != nil {
						size = t.maxAggBuckets()
					}
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					effField := subTerms.Field
					if effField == "" && subTerms.Script != nil {
						if df, ok := extractSimpleDocFieldFromScript(subTerms.Script); ok {
							effField = df
						}
					}
					relJSONPath := nestedRelJSON(effField)
					rawElemExpr := fmt.Sprintf("json_extract_string(`_nel`, %s)", relJSONPath)
					if subTerms.Script != nil {
						overrideExpr := ""
						if effField != "" {
							overrideExpr = rawElemExpr
						}
						if scriptExpr, ok := t.compilePolymorphicScriptExpr(subTerms.Script, effField, overrideExpr, nestedElemCtx); ok {
							rawElemExpr = fmt.Sprintf("CAST(%s AS STRING)", scriptExpr)
						}
					}
					*subIdx++
					var bucketExpr, fromExpr, whereExpr string
					if subTerms.Missing != nil {
						missingLit := quoteStr(formatMissingScalar(subTerms.Missing))
						bucketExpr = fmt.Sprintf("COALESCE(%s, %s)", rawElemExpr, missingLit)
						fromExpr = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel`", corrCol)
						whereExpr = "1=1"
						wCond := ""
						if wherePrefix != "" {
							whereExpr = strings.TrimSuffix(wherePrefix, " AND ")
							wCond = "WHERE " + whereExpr + " "
						}
						*branches = append(*branches, fmt.Sprintf(
							"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
								"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
								"FROM %s "+
								"%s"+
								"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
								") `_agg_sub_%d`",
							quoteStr(subFull), bucketExpr, fromExpr, wCond, size, *subIdx,
						))
					} else {
						bucketExpr = rawElemExpr
						fromExpr = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel`", corrCol)
						whereExpr = fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, rawElemExpr)
						*branches = append(*branches, fmt.Sprintf(
							"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
								"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
								"FROM %s "+
								"WHERE %s "+
								"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
								") `_agg_sub_%d`",
							quoteStr(subFull), bucketExpr, fromExpr, whereExpr, size, *subIdx,
						))
					}
					if nestedChildSubs := subSpec.SubAggs(); len(nestedChildSubs) > 0 {
						t.appendGroupedBucketSubAggsWithNested(
							branches,
							subIdx,
							subFull,
							bucketExpr,
							fromExpr,
							whereExpr,
							nestedElemCtx,
							nestedChildSubs,
						)
					}
				case subSpec.Avg != nil, subSpec.Sum != nil, subSpec.Min != nil, subSpec.Max != nil:
					var fn, field string
					var miss, script any
					switch {
					case subSpec.Avg != nil:
						fn, field, miss, script = "AVG", subSpec.Avg.Field, subSpec.Avg.Missing, subSpec.Avg.Script
					case subSpec.Sum != nil:
						fn, field, miss, script = "SUM", subSpec.Sum.Field, subSpec.Sum.Missing, subSpec.Sum.Script
					case subSpec.Min != nil:
						fn, field, miss, script = "MIN", subSpec.Min.Field, subSpec.Min.Missing, subSpec.Min.Script
					case subSpec.Max != nil:
						fn, field, miss, script = "MAX", subSpec.Max.Field, subSpec.Max.Missing, subSpec.Max.Script
					}
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					relJSONPath := nestedRelJSON(field)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					nWhere := fmt.Sprintf("%sjson_extract_string(`_nel`, %s) IS NOT NULL", wherePrefix, relJSONPath)
					if miss != nil {
						if mf, ok := resolveHistogramMissingFloat(miss); ok {
							if field != "" {
								numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					if script != nil {
						overrideExpr := ""
						if field != "" {
							overrideExpr = numExpr
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(script, field, overrideExpr, nestedElemCtx); ok {
							numExpr = scriptExpr
							if miss != nil && field == "" {
								if mf, ok := resolveHistogramMissingFloat(miss); ok {
									numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
								}
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s",
						quoteStr(subFull), fn, numExpr, corrCol, nWhere,
					))
				case subSpec.EffectiveStats() != nil:
					statsSpec := subSpec.EffectiveStats()
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					relJSONPath := nestedRelJSON(statsSpec.Field)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					nWhere := fmt.Sprintf("%sjson_extract_string(`_nel`, %s) IS NOT NULL", wherePrefix, relJSONPath)
					if statsSpec.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(statsSpec.Missing); ok {
							if statsSpec.Field != "" {
								numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					if statsSpec.Script != nil {
						overrideExpr := ""
						if statsSpec.Field != "" {
							overrideExpr = numExpr
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(statsSpec.Script, statsSpec.Field, overrideExpr, nestedElemCtx); ok {
							numExpr = scriptExpr
							if statsSpec.Missing != nil && statsSpec.Field == "" {
								if mf, ok := resolveHistogramMissingFloat(statsSpec.Missing); ok {
									numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
								}
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					statOps := []struct{ key, fn string }{
						{"_stats_count", "COUNT"},
						{"_stats_min", "MIN"},
						{"_stats_max", "MAX"},
						{"_stats_avg", "AVG"},
						{"_stats_sum", "SUM"},
					}
					if subSpec.ExtendedStats != nil {
						statOps = append(statOps, struct{ key, fn string }{"_stats_std", "STDDEV_POP"})
					}
					for _, statOp := range statOps {
						*branches = append(*branches, fmt.Sprintf(
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
								"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s",
							quoteStr(subFull), quoteStr(statOp.key), statOp.fn, numExpr, corrCol, nWhere,
						))
					}
				case subSpec.Percentiles != nil:
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					relJSONPath := nestedRelJSON(subSpec.Percentiles.Field)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					nWhere := fmt.Sprintf("%sjson_extract_string(`_nel`, %s) IS NOT NULL", wherePrefix, relJSONPath)
					if subSpec.Percentiles.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Percentiles.Missing); ok {
							if subSpec.Percentiles.Field != "" {
								numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					if subSpec.Percentiles.Script != nil {
						overrideExpr := ""
						if subSpec.Percentiles.Field != "" {
							overrideExpr = numExpr
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.Percentiles.Script, subSpec.Percentiles.Field, overrideExpr, nestedElemCtx); ok {
							numExpr = scriptExpr
							if subSpec.Percentiles.Missing != nil && subSpec.Percentiles.Field == "" {
								if mf, ok := resolveHistogramMissingFloat(subSpec.Percentiles.Missing); ok {
									numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
								}
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					for _, pct := range subSpec.Percentiles.EffectivePercents() {
						q := pct / 100.0
						if q < 0 {
							q = 0
						} else if q > 1 {
							q = 1
						}
						pctKey := strconv.FormatFloat(pct, 'f', -1, 64)
						if !strings.Contains(pctKey, ".") {
							pctKey += ".0"
						}
						*branches = append(*branches, fmt.Sprintf(
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
								"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s",
							quoteStr(subFull), quoteStr(pctKey), numExpr, q, corrCol, nWhere,
						))
					}
				case subSpec.PercentileRanks != nil:
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					relJSONPath := nestedRelJSON(subSpec.PercentileRanks.Field)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					nWhere := fmt.Sprintf("%sjson_extract_string(`_nel`, %s) IS NOT NULL", wherePrefix, relJSONPath)
					if subSpec.PercentileRanks.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.PercentileRanks.Missing); ok {
							if subSpec.PercentileRanks.Field != "" {
								numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					if subSpec.PercentileRanks.Script != nil {
						overrideExpr := ""
						if subSpec.PercentileRanks.Field != "" {
							overrideExpr = numExpr
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.PercentileRanks.Script, subSpec.PercentileRanks.Field, overrideExpr, nestedElemCtx); ok {
							numExpr = scriptExpr
							if subSpec.PercentileRanks.Missing != nil && subSpec.PercentileRanks.Field == "" {
								if mf, ok := resolveHistogramMissingFloat(subSpec.PercentileRanks.Missing); ok {
									numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
								}
							}
							if subSpec.PercentileRanks.Missing != nil {
								nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
							} else {
								nWhere = fmt.Sprintf("%s(%s) IS NOT NULL", wherePrefix, numExpr)
							}
						}
					}
					for _, val := range subSpec.PercentileRanks.Values {
						valKey := strconv.FormatFloat(val, 'f', -1, 64)
						if !strings.Contains(valKey, ".") {
							valKey += ".0"
						}
						valLit := strconv.FormatFloat(val, 'f', -1, 64)
						*branches = append(*branches, fmt.Sprintf(
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(AVG(CASE WHEN %s <= %s THEN 100.0 ELSE 0.0 END), 0) AS DOUBLE) AS `_doc_count` "+
								"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s",
							quoteStr(subFull), quoteStr(valKey), numExpr, valLit, corrCol, nWhere,
						))
					}
				case subSpec.Boxplot != nil:
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					relJSONPath := nestedRelJSON(subSpec.Boxplot.Field)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					nWhere := fmt.Sprintf("%sjson_extract_string(`_nel`, %s) IS NOT NULL", wherePrefix, relJSONPath)
					if subSpec.Boxplot.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Boxplot.Missing); ok {
							if subSpec.Boxplot.Field != "" {
								numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					if subSpec.Boxplot.Script != nil {
						overrideExpr := ""
						if subSpec.Boxplot.Field != "" {
							overrideExpr = numExpr
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.Boxplot.Script, subSpec.Boxplot.Field, overrideExpr, nestedElemCtx); ok {
							numExpr = scriptExpr
							if subSpec.Boxplot.Missing != nil && subSpec.Boxplot.Field == "" {
								if mf, ok := resolveHistogramMissingFloat(subSpec.Boxplot.Missing); ok {
									numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
								}
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					for _, pct := range []float64{0.0, 25.0, 50.0, 75.0, 100.0} {
						q := pct / 100.0
						pctKey := fmt.Sprintf("%.1f", pct)
						*branches = append(*branches, fmt.Sprintf(
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
								"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s",
							quoteStr(subFull), quoteStr(pctKey), numExpr, q, corrCol, nWhere,
						))
					}
				case subSpec.StringStats != nil:
					relJSONPath := nestedRelJSON(subSpec.StringStats.Field)
					lenExpr := fmt.Sprintf("CAST(CHAR_LENGTH(json_extract_string(`_nel`, %s)) AS DOUBLE)", relJSONPath)
					for _, op := range []struct{ key, fn string }{
						{"_stats_count", "COUNT"},
						{"_stats_min", "MIN"},
						{"_stats_max", "MAX"},
						{"_stats_avg", "AVG"},
					} {
						*branches = append(*branches, fmt.Sprintf(
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
								"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %sjson_extract_string(`_nel`, %s) IS NOT NULL",
							quoteStr(subFull), quoteStr(op.key), op.fn, lenExpr, corrCol, wherePrefix, relJSONPath,
						))
					}
				case subSpec.Cardinality != nil:
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					relJSONPath := nestedRelJSON(subSpec.Cardinality.Field)
					valExpr := fmt.Sprintf("json_extract_string(`_nel`, %s)", relJSONPath)
					nWhere := fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, valExpr)
					if subSpec.Cardinality.Missing != nil {
						if subSpec.Cardinality.Field != "" {
							valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", valExpr, quoteStr(formatMissingScalar(subSpec.Cardinality.Missing)))
						}
						nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
					}
					if subSpec.Cardinality.Script != nil {
						overrideExpr := ""
						if subSpec.Cardinality.Field != "" {
							overrideExpr = valExpr
						}
						if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.Cardinality.Script, subSpec.Cardinality.Field, overrideExpr, nestedElemCtx); ok {
							valExpr = scriptExpr
							if subSpec.Cardinality.Missing != nil && subSpec.Cardinality.Field == "" {
								valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", valExpr, quoteStr(formatMissingScalar(subSpec.Cardinality.Missing)))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT %s) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s",
						quoteStr(subFull), valExpr, corrCol, nWhere,
					))
				case subSpec.ValueCount != nil:
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					relJSONPath := nestedRelJSON(subSpec.ValueCount.Field)
					valExpr := fmt.Sprintf("json_extract_string(`_nel`, %s)", relJSONPath)
					nWhere := fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, valExpr)
					if subSpec.ValueCount.Missing != nil {
						if subSpec.ValueCount.Field != "" {
							valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", valExpr, quoteStr(formatMissingScalar(subSpec.ValueCount.Missing)))
						}
						nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
					}
					if subSpec.ValueCount.Script != nil {
						overrideExpr := ""
						if subSpec.ValueCount.Field != "" {
							overrideExpr = valExpr
						}
						if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.ValueCount.Script, subSpec.ValueCount.Field, overrideExpr, nestedElemCtx); ok {
							valExpr = scriptExpr
							if subSpec.ValueCount.Missing != nil && subSpec.ValueCount.Field == "" {
								valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", valExpr, quoteStr(formatMissingScalar(subSpec.ValueCount.Missing)))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s",
						quoteStr(subFull), valExpr, corrCol, nWhere,
					))
				default:
					nFrom := fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel`", corrCol)
					nWhere := fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
					t.appendGroupedBucketSubAggsWithNested(
						branches,
						subIdx,
						fullAggName,
						"'_nested_doc_count'",
						nFrom,
						nWhere,
						&nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"},
						map[string]esast.AggSpec{subName: subSpec},
					)
				}
			}

		case spec.Filter != nil:
			cond := t.CompileQuery(spec.Filter, false, nil)
			combinedWhere := cond.WhereSQL
			if extraWhere != "" {
				combinedWhere = fmt.Sprintf("(%s) AND (%s)", extraWhere, cond.WhereSQL)
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_filter' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s",
				quoteStr(fullAggName), combinedWhere,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendAggBranches(branches, subIdx, fullAggName, combinedWhere, subAggs)
			}

		case spec.Filters != nil && (len(spec.Filters.Filters) > 0 || len(spec.Filters.AnonymousFilters) > 0 || spec.Filters.OtherBucket):
			var matchedConds []string
			if spec.Filters.IsAnonymous {
				for i, fq := range spec.Filters.AnonymousFilters {
					fk := strconv.Itoa(i)
					cond := t.CompileQuery(&fq, false, nil)
					matchedConds = append(matchedConds, fmt.Sprintf("(%s)", cond.EffectiveSafeWhere()))
					combinedWhere := cond.WhereSQL
					if extraWhere != "" {
						combinedWhere = fmt.Sprintf("(%s) AND (%s)", extraWhere, cond.WhereSQL)
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` WHERE %s",
						quoteStr(fullAggName), quoteStr(fk), combinedWhere,
					))
					if subAggs := spec.SubAggs(); len(subAggs) > 0 {
						t.appendBucketScopedSubAggs(branches, subIdx, fullAggName, fk, combinedWhere, subAggs)
					}
				}
			} else {
				fKeys := make([]string, 0, len(spec.Filters.Filters))
				for fk := range spec.Filters.Filters {
					fKeys = append(fKeys, fk)
				}
				sort.Strings(fKeys)
				for _, fk := range fKeys {
					fq := spec.Filters.Filters[fk]
					cond := t.CompileQuery(&fq, false, nil)
					matchedConds = append(matchedConds, fmt.Sprintf("(%s)", cond.EffectiveSafeWhere()))
					combinedWhere := cond.WhereSQL
					if extraWhere != "" {
						combinedWhere = fmt.Sprintf("(%s) AND (%s)", extraWhere, cond.WhereSQL)
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` WHERE %s",
						quoteStr(fullAggName), quoteStr(fk), combinedWhere,
					))
					if subAggs := spec.SubAggs(); len(subAggs) > 0 {
						t.appendBucketScopedSubAggs(branches, subIdx, fullAggName, fk, combinedWhere, subAggs)
					}
				}
			}
			if spec.Filters.OtherBucket {
				otherKey := spec.Filters.EffectiveOtherBucketKey()
				otherWhere := "TRUE"
				if len(matchedConds) > 0 {
					otherWhere = fmt.Sprintf("NOT COALESCE(%s, FALSE)", strings.Join(matchedConds, " OR "))
				}
				if extraWhere != "" {
					otherWhere = fmt.Sprintf("(%s) AND (%s)", extraWhere, otherWhere)
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched` WHERE %s",
					quoteStr(fullAggName), quoteStr(otherKey), otherWhere,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					t.appendBucketScopedSubAggs(branches, subIdx, fullAggName, otherKey, otherWhere, subAggs)
				}
			}

		case spec.Missing != nil:
			existsPred := t.compileExistsPredicate(spec.Missing.Field, nil)
			missingWhere := fmt.Sprintf("%sNOT (%s)", wherePrefix, existsPred)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_missing' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s",
				quoteStr(fullAggName), missingWhere,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendAggBranches(branches, subIdx, fullAggName, missingWhere, subAggs)
			}

		case spec.Cardinality != nil:
			effCardField := spec.Cardinality.Field
			if effCardField == "" && spec.Cardinality.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.Cardinality.Script); ok {
					effCardField = docF
				}
			}
			b := t.Schema.ResolveField(effCardField)
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				arrCol := b.EffectiveArrayColumn(true)
				valExpr := "`_elem`"
				explodeExpr := fmt.Sprintf("`%s`", arrCol)
				wClause := fmt.Sprintf(" WHERE %s`_elem` IS NOT NULL", wherePrefix)
				if spec.Cardinality.Missing != nil {
					missLit := quoteStr(formatMissingScalar(spec.Cardinality.Missing))
					valExpr = fmt.Sprintf("COALESCE(`_elem`, %s)", missLit)
					explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END", arrCol, arrCol, arrCol)
					wClause = ""
					if extraWhere != "" {
						wClause = " WHERE " + extraWhere
					}
				}
				if spec.Cardinality.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(spec.Cardinality.Script, effCardField, valExpr, nil); ok {
						valExpr = scriptExpr
					}
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT %s) AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_t` AS `_elem`%s",
					quoteStr(fullAggName), valExpr, explodeExpr, wClause,
				))
			} else {
				col := t.sqlColumnRef(effCardField, true, nil)
				if spec.Cardinality.Missing != nil && effCardField != "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(spec.Cardinality.Missing)))
				}
				if spec.Cardinality.Script != nil {
					overrideExpr := ""
					if effCardField != "" {
						overrideExpr = col
					}
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(spec.Cardinality.Script, effCardField, overrideExpr, nil); ok {
						col = scriptExpr
					}
				}
				if spec.Cardinality.Missing != nil && effCardField == "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(spec.Cardinality.Missing)))
				}
				wClause := ""
				if extraWhere != "" {
					wClause = " WHERE " + extraWhere
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT %s) AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched`%s",
					quoteStr(fullAggName), col, wClause,
				))
			}

		case spec.Avg != nil:
			t.appendMetricAggBranchWithMissingAndScript(branches, fullAggName, "AVG", spec.Avg.Field, extraWhere, spec.Avg.Missing, spec.Avg.Script)
		case spec.Sum != nil:
			t.appendMetricAggBranchWithMissingAndScript(branches, fullAggName, "SUM", spec.Sum.Field, extraWhere, spec.Sum.Missing, spec.Sum.Script)
		case spec.Min != nil:
			t.appendMetricAggBranchWithMissingAndScript(branches, fullAggName, "MIN", spec.Min.Field, extraWhere, spec.Min.Missing, spec.Min.Script)
		case spec.Max != nil:
			t.appendMetricAggBranchWithMissingAndScript(branches, fullAggName, "MAX", spec.Max.Field, extraWhere, spec.Max.Missing, spec.Max.Script)
		case spec.ValueCount != nil:
			t.appendValueCountAggBranchWithMissingAndScript(branches, fullAggName, spec.ValueCount.Field, extraWhere, spec.ValueCount.Missing, spec.ValueCount.Script)

		case spec.Rate != nil:
			if spec.Rate.Field == "" && spec.Rate.Script == nil {
				wClause := ""
				if extraWhere != "" {
					wClause = " WHERE " + extraWhere
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` FROM `base_matched`%s",
					quoteStr(fullAggName), wClause,
				))
			} else if strings.EqualFold(spec.Rate.Mode, "value_count") {
				t.appendValueCountAggBranchWithMissingAndScript(branches, fullAggName, spec.Rate.Field, extraWhere, nil, spec.Rate.Script)
			} else {
				t.appendMetricAggBranchWithMissingAndScript(branches, fullAggName, "SUM", spec.Rate.Field, extraWhere, nil, spec.Rate.Script)
			}

		case spec.EffectiveStats() != nil:
			statsSpec := spec.EffectiveStats()
			effStatsField := statsSpec.Field
			if effStatsField == "" && statsSpec.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(statsSpec.Script); ok {
					effStatsField = docF
				}
			}
			b := t.Schema.ResolveField(effStatsField)
			statOps := []struct{ key, fn string }{
				{"_stats_count", "COUNT"},
				{"_stats_min", "MIN"},
				{"_stats_max", "MAX"},
				{"_stats_avg", "AVG"},
				{"_stats_sum", "SUM"},
			}
			if spec.ExtendedStats != nil {
				statOps = append(statOps, struct{ key, fn string }{"_stats_std", "STDDEV_POP"})
			}
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				arrCol := b.EffectiveArrayColumn(true)
				valExpr := "CAST(`_nel` AS DOUBLE)"
				explodeExpr := fmt.Sprintf("`%s`", arrCol)
				wCond := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
				if statsSpec.Missing != nil {
					if mf, ok := resolveHistogramMissingFloat(statsSpec.Missing); ok {
						valExpr = fmt.Sprintf("COALESCE(CAST(`_nel` AS DOUBLE), %s)", strconv.FormatFloat(mf, 'f', -1, 64))
						explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END", arrCol, arrCol, arrCol)
						wCond = ""
						if extraWhere != "" {
							wCond = " WHERE " + extraWhere
						}
					}
				}
				if statsSpec.Script != nil {
					if scriptExpr, ok := t.compileMetricScriptExprWithOverride(statsSpec.Script, effStatsField, valExpr, nil); ok {
						valExpr = scriptExpr
					}
				}
				for _, statOp := range statOps {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_nt` AS `_nel`%s",
						quoteStr(fullAggName), quoteStr(statOp.key), statOp.fn, valExpr, explodeExpr, wCond,
					))
				}
			} else {
				col := t.sqlNumericColumnRef(effStatsField, nil)
				if statsSpec.Missing != nil && effStatsField != "" {
					if mf, ok := resolveHistogramMissingFloat(statsSpec.Missing); ok {
						col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
					}
				}
				if statsSpec.Script != nil {
					overrideExpr := ""
					if effStatsField != "" {
						overrideExpr = col
					}
					if scriptExpr, ok := t.compileMetricScriptExprWithOverride(statsSpec.Script, effStatsField, overrideExpr, nil); ok {
						col = scriptExpr
					}
				}
				if statsSpec.Missing != nil && effStatsField == "" {
					if mf, ok := resolveHistogramMissingFloat(statsSpec.Missing); ok {
						col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
					}
				}
				wClause := ""
				if extraWhere != "" {
					wClause = " WHERE " + extraWhere
				}
				for _, statOp := range statOps {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched`%s",
						quoteStr(fullAggName), quoteStr(statOp.key), statOp.fn, col, wClause,
					))
				}
			}

		case spec.StringStats != nil:
			b := t.Schema.ResolveField(spec.StringStats.Field)
			statOps := []struct{ key, fn string }{
				{"_stats_count", "COUNT"},
				{"_stats_min", "MIN"},
				{"_stats_max", "MAX"},
				{"_stats_avg", "AVG"},
			}
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				arrCol := b.EffectiveArrayColumn(true)
				lenExpr := "CAST(CHAR_LENGTH(CAST(`_nel` AS STRING)) AS DOUBLE)"
				for _, statOp := range statOps {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s`_nel` IS NOT NULL",
						quoteStr(fullAggName), quoteStr(statOp.key), statOp.fn, lenExpr, arrCol, wherePrefix,
					))
				}
			} else {
				col := t.sqlColumnRef(spec.StringStats.Field, true, nil)
				lenExpr := fmt.Sprintf("CAST(CHAR_LENGTH(CAST(%s AS STRING)) AS DOUBLE)", col)
				for _, statOp := range statOps {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` WHERE %s%s IS NOT NULL",
						quoteStr(fullAggName), quoteStr(statOp.key), statOp.fn, lenExpr, wherePrefix, col,
					))
				}
			}

		case spec.Boxplot != nil:
			effBpField := spec.Boxplot.Field
			if effBpField == "" && spec.Boxplot.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.Boxplot.Script); ok {
					effBpField = docF
				}
			}
			b := t.Schema.ResolveField(effBpField)
			arrCol := b.EffectiveArrayColumn(true)
			for _, bp := range []struct {
				key string
				q   float64
			}{
				{"0.0", 0.0},
				{"25.0", 0.25},
				{"50.0", 0.50},
				{"75.0", 0.75},
				{"100.0", 1.0},
			} {
				if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
					valExpr := "CAST(`_nel` AS DOUBLE)"
					explodeExpr := fmt.Sprintf("`%s`", arrCol)
					wCond := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
					if spec.Boxplot.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(spec.Boxplot.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(CAST(`_nel` AS DOUBLE), %s)", strconv.FormatFloat(mf, 'f', -1, 64))
							explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END", arrCol, arrCol, arrCol)
							wCond = ""
							if extraWhere != "" {
								wCond = " WHERE " + extraWhere
							}
						}
					}
					if spec.Boxplot.Script != nil {
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.Boxplot.Script, effBpField, valExpr, nil); ok {
							valExpr = scriptExpr
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_nt` AS `_nel`%s",
						quoteStr(fullAggName), quoteStr(bp.key), valExpr, bp.q, explodeExpr, wCond,
					))
				} else {
					col := t.sqlNumericColumnRef(effBpField, nil)
					if spec.Boxplot.Missing != nil && effBpField != "" {
						if mf, ok := resolveHistogramMissingFloat(spec.Boxplot.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
						}
					}
					if spec.Boxplot.Script != nil {
						overrideExpr := ""
						if effBpField != "" {
							overrideExpr = col
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.Boxplot.Script, effBpField, overrideExpr, nil); ok {
							col = scriptExpr
						}
					}
					if spec.Boxplot.Missing != nil && effBpField == "" {
						if mf, ok := resolveHistogramMissingFloat(spec.Boxplot.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
						}
					}
					wClause := ""
					if extraWhere != "" {
						wClause = " WHERE " + extraWhere
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched`%s",
						quoteStr(fullAggName), quoteStr(bp.key), col, bp.q, wClause,
					))
				}
			}

		case spec.Percentiles != nil:
			effPctField := spec.Percentiles.Field
			if effPctField == "" && spec.Percentiles.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.Percentiles.Script); ok {
					effPctField = docF
				}
			}
			b := t.Schema.ResolveField(effPctField)
			arrCol := b.EffectiveArrayColumn(true)
			for _, pct := range spec.Percentiles.EffectivePercents() {
				q := pct / 100.0
				if q < 0 {
					q = 0
				} else if q > 1 {
					q = 1
				}
				pctKey := strconv.FormatFloat(pct, 'f', -1, 64)
				if !strings.Contains(pctKey, ".") {
					pctKey += ".0"
				}
				if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
					valExpr := "CAST(`_nel` AS DOUBLE)"
					explodeExpr := fmt.Sprintf("`%s`", arrCol)
					wCond := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
					if spec.Percentiles.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(spec.Percentiles.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(CAST(`_nel` AS DOUBLE), %s)", strconv.FormatFloat(mf, 'f', -1, 64))
							explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END", arrCol, arrCol, arrCol)
							wCond = ""
							if extraWhere != "" {
								wCond = " WHERE " + extraWhere
							}
						}
					}
					if spec.Percentiles.Script != nil {
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.Percentiles.Script, effPctField, valExpr, nil); ok {
							valExpr = scriptExpr
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_nt` AS `_nel`%s",
						quoteStr(fullAggName), quoteStr(pctKey), valExpr, q, explodeExpr, wCond,
					))
				} else {
					col := t.sqlNumericColumnRef(effPctField, nil)
					if spec.Percentiles.Missing != nil && effPctField != "" {
						if mf, ok := resolveHistogramMissingFloat(spec.Percentiles.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
						}
					}
					if spec.Percentiles.Script != nil {
						overrideExpr := ""
						if effPctField != "" {
							overrideExpr = col
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.Percentiles.Script, effPctField, overrideExpr, nil); ok {
							col = scriptExpr
						}
					}
					if spec.Percentiles.Missing != nil && effPctField == "" {
						if mf, ok := resolveHistogramMissingFloat(spec.Percentiles.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
						}
					}
					wClause := ""
					if extraWhere != "" {
						wClause = " WHERE " + extraWhere
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched`%s",
						quoteStr(fullAggName), quoteStr(pctKey), col, q, wClause,
					))
				}
			}

		case spec.PercentileRanks != nil:
			effPrField := spec.PercentileRanks.Field
			if effPrField == "" && spec.PercentileRanks.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.PercentileRanks.Script); ok {
					effPrField = docF
				}
			}
			b := t.Schema.ResolveField(effPrField)
			arrCol := b.EffectiveArrayColumn(true)
			for _, val := range spec.PercentileRanks.Values {
				valKey := strconv.FormatFloat(val, 'f', -1, 64)
				if !strings.Contains(valKey, ".") {
					valKey += ".0"
				}
				valLit := strconv.FormatFloat(val, 'f', -1, 64)
				if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
					valExpr := "CAST(`_nel` AS DOUBLE)"
					explodeExpr := fmt.Sprintf("`%s`", arrCol)
					wCond := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
					if spec.PercentileRanks.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(spec.PercentileRanks.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(CAST(`_nel` AS DOUBLE), %s)", strconv.FormatFloat(mf, 'f', -1, 64))
							explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END", arrCol, arrCol, arrCol)
							wCond = ""
							if extraWhere != "" {
								wCond = " WHERE " + extraWhere
							}
						}
					}
					if spec.PercentileRanks.Script != nil {
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.PercentileRanks.Script, effPrField, valExpr, nil); ok {
							valExpr = scriptExpr
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(AVG(CASE WHEN %s <= %s THEN 100.0 ELSE 0.0 END), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_nt` AS `_nel`%s",
						quoteStr(fullAggName), quoteStr(valKey), valExpr, valLit, explodeExpr, wCond,
					))
				} else {
					col := t.sqlNumericColumnRef(effPrField, nil)
					wCond := fmt.Sprintf(" WHERE %s%s IS NOT NULL", wherePrefix, col)
					if spec.PercentileRanks.Missing != nil && effPrField != "" {
						if mf, ok := resolveHistogramMissingFloat(spec.PercentileRanks.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
							wCond = ""
							if extraWhere != "" {
								wCond = " WHERE " + extraWhere
							}
						}
					}
					if spec.PercentileRanks.Script != nil {
						overrideExpr := ""
						if effPrField != "" {
							overrideExpr = col
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.PercentileRanks.Script, effPrField, overrideExpr, nil); ok {
							col = scriptExpr
							if spec.PercentileRanks.Missing == nil {
								wCond = fmt.Sprintf(" WHERE %s%s IS NOT NULL", wherePrefix, col)
							}
						}
					}
					if spec.PercentileRanks.Missing != nil && effPrField == "" {
						if mf, ok := resolveHistogramMissingFloat(spec.PercentileRanks.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
							wCond = ""
							if extraWhere != "" {
								wCond = " WHERE " + extraWhere
							}
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(AVG(CASE WHEN %s <= %s THEN 100.0 ELSE 0.0 END), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched`%s",
						quoteStr(fullAggName), quoteStr(valKey), col, valLit, wCond,
					))
				}
			}

		case spec.DateHistogram != nil:
			intervalMs := spec.DateHistogram.EffectiveIntervalMs()
			tzShiftMs := spec.DateHistogram.EffectiveTimeZoneOffsetMs() - spec.DateHistogram.EffectiveOffsetMs()
			effDHField := spec.DateHistogram.Field
			if effDHField == "" && spec.DateHistogram.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.DateHistogram.Script); ok {
					effDHField = docF
				}
			}
			b := t.Schema.ResolveField(effDHField)
			arrCol := b.EffectiveArrayColumn(true)
			col := t.sqlNumericColumnRef(effDHField, nil)
			fromClause := "`base_matched`"
			notNullCond := fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, col)
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				col = "CAST(`_elem` AS DOUBLE)"
				fromClause = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem`", arrCol)
				notNullCond = fmt.Sprintf("%s`_elem` IS NOT NULL", wherePrefix)
				if spec.DateHistogram.Missing != nil {
					if missMs, ok := t.resolveDateHistogramMissingMs(b.ESType, spec.DateHistogram.Missing); ok {
						fromClause = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) `_t` AS `_elem`", arrCol, arrCol, arrCol)
						col = fmt.Sprintf("COALESCE(CAST(`_elem` AS DOUBLE), %d)", missMs)
						notNullCond = "1=1"
						if extraWhere != "" {
							notNullCond = extraWhere
						}
					}
				}
				if spec.DateHistogram.Script != nil {
					if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.DateHistogram.Script, effDHField, col, nil); ok {
						col = scriptExpr
					}
				}
			} else {
				if spec.DateHistogram.Missing != nil && effDHField != "" {
					if missMs, ok := t.resolveDateHistogramMissingMs(b.ESType, spec.DateHistogram.Missing); ok {
						col = fmt.Sprintf("COALESCE(%s, %d)", col, missMs)
						notNullCond = "1=1"
						if extraWhere != "" {
							notNullCond = extraWhere
						}
					}
				}
				if spec.DateHistogram.Script != nil {
					overrideExpr := ""
					if effDHField != "" {
						overrideExpr = col
					}
					if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.DateHistogram.Script, effDHField, overrideExpr, nil); ok {
						col = scriptExpr
						if spec.DateHistogram.Missing == nil {
							notNullCond = fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, col)
						}
					}
				}
				if spec.DateHistogram.Missing != nil && effDHField == "" {
					if missMs, ok := t.resolveDateHistogramMissingMs(b.ESType, spec.DateHistogram.Missing); ok {
						col = fmt.Sprintf("COALESCE(%s, %d)", col, missMs)
						notNullCond = "1=1"
						if extraWhere != "" {
							notNullCond = extraWhere
						}
					}
				}
			}
			bucketExpr := fmt.Sprintf("CAST(CAST(FLOOR(%s / %d) * %d AS BIGINT) AS STRING)", col, intervalMs, intervalMs)
			if tzShiftMs != 0 {
				bucketExpr = fmt.Sprintf("CAST(CAST(FLOOR((%s + %d) / %d) * %d - %d AS BIGINT) AS STRING)", col, tzShiftMs, intervalMs, intervalMs, tzShiftMs)
			}
			dhCountExpr := "COUNT(*)"
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				dhCountExpr = "COUNT(DISTINCT `_id`)"
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM %s "+
					"WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY CAST(`_bucket_key` AS BIGINT) ASC"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), bucketExpr, dhCountExpr, fromClause, notNullCond, *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				subBucketExpr := bucketExpr
				subFromClause := fromClause
				subWhereCond := notNullCond
				if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
					subFromClause = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id`, %s AS `_rn_bkey` FROM %s WHERE %s) `_rn_dedup` ON `base_matched`.`_id` = `_rn_dedup`.`_rn_id`", bucketExpr, fromClause, notNullCond)
					subBucketExpr = "`_rn_bkey`"
					subWhereCond = "1=1"
				}
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, subBucketExpr,
					subFromClause, subWhereCond, subAggs)
			}

		case spec.Histogram != nil:
			interval := spec.Histogram.Interval
			if interval <= 0 {
				interval = 1.0
			}
			offset := spec.Histogram.Offset
			effHField := spec.Histogram.Field
			if effHField == "" && spec.Histogram.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.Histogram.Script); ok {
					effHField = docF
				}
			}
			b := t.Schema.ResolveField(effHField)
			arrCol := b.EffectiveArrayColumn(true)
			col := t.sqlNumericColumnRef(effHField, nil)
			fromClause := "`base_matched`"
			notNullCond := fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, col)
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				col = "CAST(`_elem` AS DOUBLE)"
				fromClause = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem`", arrCol)
				notNullCond = fmt.Sprintf("%s`_elem` IS NOT NULL", wherePrefix)
				if spec.Histogram.Missing != nil {
					if missVal, ok := resolveHistogramMissingFloat(spec.Histogram.Missing); ok {
						fromClause = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) `_t` AS `_elem`", arrCol, arrCol, arrCol)
						col = fmt.Sprintf("COALESCE(CAST(`_elem` AS DOUBLE), %s)", strconv.FormatFloat(missVal, 'f', -1, 64))
						notNullCond = "1=1"
						if extraWhere != "" {
							notNullCond = extraWhere
						}
					}
				}
				if spec.Histogram.Script != nil {
					if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.Histogram.Script, effHField, col, nil); ok {
						col = scriptExpr
					}
				}
			} else {
				if spec.Histogram.Missing != nil && effHField != "" {
					if missVal, ok := resolveHistogramMissingFloat(spec.Histogram.Missing); ok {
						col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(missVal, 'f', -1, 64))
						notNullCond = "1=1"
						if extraWhere != "" {
							notNullCond = extraWhere
						}
					}
				}
				if spec.Histogram.Script != nil {
					overrideExpr := ""
					if effHField != "" {
						overrideExpr = col
					}
					if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.Histogram.Script, effHField, overrideExpr, nil); ok {
						col = scriptExpr
						if spec.Histogram.Missing == nil {
							notNullCond = fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, col)
						}
					}
				}
				if spec.Histogram.Missing != nil && effHField == "" {
					if missVal, ok := resolveHistogramMissingFloat(spec.Histogram.Missing); ok {
						col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(missVal, 'f', -1, 64))
						notNullCond = "1=1"
						if extraWhere != "" {
							notNullCond = extraWhere
						}
					}
				}
			}
			bucketExpr := fmt.Sprintf("CAST(FLOOR((%s - %v) / %v) * %v + %v AS STRING)", col, offset, interval, interval, offset)
			hCountExpr := "COUNT(*)"
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				hCountExpr = "COUNT(DISTINCT `_id`)"
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM %s "+
					"WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY CAST(`_bucket_key` AS DOUBLE) ASC"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), bucketExpr, hCountExpr, fromClause, notNullCond, *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				subBucketExpr := bucketExpr
				subFromClause := fromClause
				subWhereCond := notNullCond
				if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
					subFromClause = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id`, %s AS `_rn_bkey` FROM %s WHERE %s) `_rn_dedup` ON `base_matched`.`_id` = `_rn_dedup`.`_rn_id`", bucketExpr, fromClause, notNullCond)
					subBucketExpr = "`_rn_bkey`"
					subWhereCond = "1=1"
				}
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, subBucketExpr,
					subFromClause, subWhereCond, subAggs)
			}

		case spec.EffectiveRange() != nil:
			rngSpec := spec.EffectiveRange()
			now := time.Now().UTC()
			effRField := rngSpec.Field
			if effRField == "" && rngSpec.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(rngSpec.Script); ok {
					effRField = docF
				}
			}
			b := t.Schema.ResolveField(effRField)
			arrCol := b.EffectiveArrayColumn(true)
			isArray := b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield
			for _, rng := range rngSpec.Ranges {
				var rWhere string
				fromSource := "`base_matched`"
				if spec.IPRange != nil {
					ipCol := t.sqlColumnRef(effRField, true, nil)
					if isArray {
						ipCol = "_x"
					}
					numCol := fmt.Sprintf("IPV4_STRING_TO_NUM_OR_NULL(%s)", ipCol)
					var conds []string
					if !isArray {
						conds = append(conds, fmt.Sprintf("%s IS NOT NULL", ipCol))
					}
					if rng.Mask != "" {
						validMask := false
						if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(rng.Mask)); err == nil && ipNet != nil {
							if ip4 := ipNet.IP.To4(); ip4 != nil && len(ipNet.Mask) == 4 {
								validMask = true
								maskNum := uint32(ipNet.Mask[0])<<24 | uint32(ipNet.Mask[1])<<16 | uint32(ipNet.Mask[2])<<8 | uint32(ipNet.Mask[3])
								startNum := (uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])) & maskNum
								endNum := startNum | ^maskNum
								conds = append(conds,
									fmt.Sprintf("%s >= %d", numCol, int64(startNum)),
									fmt.Sprintf("%s <= %d", numCol, int64(endNum)),
								)
							}
						}
						if !validMask {
							conds = append(conds, "1=0")
						}
					} else {
						if rng.From != nil {
							if n, ok := parseIPv4ToUint32(rng.From); ok {
								conds = append(conds, fmt.Sprintf("%s >= %d", numCol, n))
							} else {
								conds = append(conds, fmt.Sprintf("%s >= %s", ipCol, quoteValue(rng.From)))
							}
						}
						if rng.To != nil {
							if n, ok := parseIPv4ToUint32(rng.To); ok {
								conds = append(conds, fmt.Sprintf("%s < %d", numCol, n))
							} else {
								conds = append(conds, fmt.Sprintf("%s < %s", ipCol, quoteValue(rng.To)))
							}
						}
					}
					if isArray {
						if len(conds) == 0 {
							rWhere = fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", arrCol, arrCol)
						} else {
							rWhere = fmt.Sprintf("array_exists(_x -> %s, `%s`)", strings.Join(conds, " AND "), arrCol)
						}
					} else {
						rWhere = strings.Join(conds, " AND ")
					}
				} else if isArray {
					elemExpr := "CAST(_x AS DOUBLE)"
					if rngSpec.Script != nil {
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(rngSpec.Script, effRField, elemExpr, nil); ok {
							elemExpr = scriptExpr
						}
					}
					var elemConds []string
					if rng.From != nil {
						elemConds = append(elemConds, fmt.Sprintf("%s >= %s", elemExpr, quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.From, now))))
					}
					if rng.To != nil {
						elemConds = append(elemConds, fmt.Sprintf("%s < %s", elemExpr, quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.To, now))))
					}
					arrExpr := fmt.Sprintf("`%s`", arrCol)
					if rngSpec.Missing != nil {
						if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
							arrExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [%s] ELSE `%s` END", arrCol, arrCol, strconv.FormatFloat(mf, 'f', -1, 64), arrCol)
						}
					}
					if len(elemConds) == 0 {
						rWhere = fmt.Sprintf("(%s IS NOT NULL AND array_size(%s) > 0)", arrExpr, arrExpr)
					} else {
						rWhere = fmt.Sprintf("array_exists(_x -> %s, %s)", strings.Join(elemConds, " AND "), arrExpr)
					}
				} else {
					col := t.sqlNumericColumnRef(effRField, nil)
					if rngSpec.Missing != nil && effRField != "" {
						if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
						}
					}
					if rngSpec.Script != nil {
						overrideExpr := ""
						if effRField != "" {
							overrideExpr = col
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(rngSpec.Script, effRField, overrideExpr, nil); ok {
							col = scriptExpr
						}
					}
					if rngSpec.Missing != nil && effRField == "" {
						if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
						}
					}
					var conds []string
					conds = append(conds, fmt.Sprintf("%s IS NOT NULL", col))
					if rng.From != nil {
						conds = append(conds, fmt.Sprintf("%s >= %s", col, quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.From, now))))
					}
					if rng.To != nil {
						conds = append(conds, fmt.Sprintf("%s < %s", col, quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.To, now))))
					}
					rWhere = strings.Join(conds, " AND ")
				}
				if extraWhere != "" {
					rWhere = fmt.Sprintf("(%s) AND (%s)", extraWhere, rWhere)
				}
				bKey := rng.EffectiveKey()
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s",
					quoteStr(fullAggName), quoteStr(bKey), fromSource, rWhere,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, quoteStr(bKey), fromSource, rWhere, subAggs)
				}
			}

		case spec.TopHits != nil:
			size := spec.TopHits.EffectiveFetchLimit()
			if topHitsNeedsRuntimeSort(spec.TopHits.Sort) && size < 100 {
				size = 100
			}
			orderBy := t.compileTopHitsOrderBy(spec.TopHits.Sort)
			wClause := ""
			if extraWhere != "" {
				wClause = " WHERE " + extraWhere
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, `_id` AS `_bucket_key`, CAST(1 AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched`%s "+
					"ORDER BY %s LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), wClause, orderBy, size, *subIdx,
			))

		case spec.TopMetrics != nil:
			size := spec.TopMetrics.EffectiveSize()
			if topHitsNeedsRuntimeSort(spec.TopMetrics.Sort) && size < 100 {
				size = 100
			}
			orderBy := t.compileTopHitsOrderBy(spec.TopMetrics.Sort)
			wClause := ""
			if extraWhere != "" {
				wClause = " WHERE " + extraWhere
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, `_id` AS `_bucket_key`, CAST(1 AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched`%s "+
					"ORDER BY %s LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), wClause, orderBy, size, *subIdx,
			))

		case spec.Composite != nil && len(spec.Composite.Sources) > 0:
			size := t.capBucketSize(spec.Composite.Size)
			var colExprs []string
			var notNullConds []string
			var srcNames []string
			hasHistogramSrc := false
			compFrom := "`base_matched`"
			compExplodeIdx := 0
			resolveCompSourceCol := func(field string, isNumeric bool, hasMissing bool) string {
				b := t.Schema.ResolveField(field)
				if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
					arrCol := b.EffectiveArrayColumn(true)
					compExplodeIdx++
					tblAlias := fmt.Sprintf("`_comp_t_%d`", compExplodeIdx)
					elemAlias := fmt.Sprintf("`_comp_el_%d`", compExplodeIdx)
					if hasMissing {
						compFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", compFrom, arrCol, arrCol, arrCol, tblAlias, elemAlias)
					} else {
						compFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", compFrom, arrCol, tblAlias, elemAlias)
					}
					if isNumeric {
						return fmt.Sprintf("CAST(%s AS DOUBLE)", elemAlias)
					}
					return elemAlias
				}
				if isNumeric {
					return t.sqlNumericColumnRef(field, nil)
				}
				return t.sqlColumnRef(field, true, nil)
			}
			for _, srcMap := range spec.Composite.Sources {
				srcKeys := sortedMapKeys(srcMap)
				for _, sk := range srcKeys {
					srcSpec := srcMap[sk]
					switch {
					case srcSpec.Terms != nil:
						effField := srcSpec.Terms.Field
						if effField == "" && srcSpec.Terms.Script != nil {
							if docF, ok := extractSimpleDocFieldFromScript(srcSpec.Terms.Script); ok {
								effField = docF
							}
						}
						b := t.Schema.ResolveField(effField)
						effDT := effectiveDorisScalarType(b)
						if effDT == schema.DorisBigInt || effDT == schema.DorisInt || effDT == schema.DorisDouble || b.ESType == "ip" || srcSpec.Terms.Order != nil || srcSpec.Terms.Script != nil {
							hasHistogramSrc = true
						}
						hasMiss := srcSpec.Terms.Missing != nil || srcSpec.Terms.MissingBucket
						col := resolveCompSourceCol(effField, false, hasMiss)
						if srcSpec.Terms.Script != nil {
							overrideExpr := ""
							if effField != "" {
								overrideExpr = col
							}
							if scriptExpr, ok := t.compilePolymorphicScriptExpr(srcSpec.Terms.Script, effField, overrideExpr, nil); ok {
								col = scriptExpr
							}
						}
						expr := fmt.Sprintf("CAST(%s AS STRING)", col)
						if effDT == schema.DorisBoolean && srcSpec.Terms.Script == nil {
							expr = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN CAST(%s AS STRING) IN ('true', '1') THEN 'true' ELSE 'false' END", col, col)
						}
						if srcSpec.Terms.Missing != nil {
							hasHistogramSrc = true
							expr = fmt.Sprintf("COALESCE(%s, %s)", expr, quoteStr(formatMissingScalar(srcSpec.Terms.Missing)))
						} else if srcSpec.Terms.MissingBucket {
							hasHistogramSrc = true
							expr = fmt.Sprintf("COALESCE(%s, '__ES_MISSING_BUCKET__')", expr)
						} else {
							notNullConds = append(notNullConds, fmt.Sprintf("%s IS NOT NULL", col))
						}
						colExprs = append(colExprs, expr)
						srcNames = append(srcNames, sk)
					case srcSpec.DateHistogram != nil:
						hasHistogramSrc = true
						intervalMs := srcSpec.DateHistogram.EffectiveIntervalMs()
						tzShiftMs := srcSpec.DateHistogram.EffectiveTimeZoneOffsetMs() - srcSpec.DateHistogram.EffectiveOffsetMs()
						hasMiss := srcSpec.DateHistogram.Missing != nil || srcSpec.DateHistogram.MissingBucket
						effDHField := srcSpec.DateHistogram.Field
						if effDHField == "" && srcSpec.DateHistogram.Script != nil {
							if docF, ok := extractSimpleDocFieldFromScript(srcSpec.DateHistogram.Script); ok {
								effDHField = docF
							}
						}
						dhB := t.Schema.ResolveField(effDHField)
						col := resolveCompSourceCol(effDHField, true, hasMiss)
						if srcSpec.DateHistogram.Script != nil {
							overrideExpr := ""
							if effDHField != "" {
								overrideExpr = col
							}
							if scriptExpr, ok := t.compileMetricScriptExprWithOverride(srcSpec.DateHistogram.Script, effDHField, overrideExpr, nil); ok {
								col = scriptExpr
							}
						}
						if srcSpec.DateHistogram.Missing != nil {
							if missMs, ok := t.resolveDateHistogramMissingMs(dhB.ESType, srcSpec.DateHistogram.Missing); ok {
								col = fmt.Sprintf("COALESCE(%s, %d)", col, missMs)
							}
						}
						var expr string
						if tzShiftMs != 0 {
							expr = fmt.Sprintf("CAST(CAST(FLOOR((%s + %d) / %d) * %d - %d AS BIGINT) AS STRING)", col, tzShiftMs, intervalMs, intervalMs, tzShiftMs)
						} else {
							expr = fmt.Sprintf("CAST(CAST(FLOOR(%s / %d) * %d AS BIGINT) AS STRING)", col, intervalMs, intervalMs)
						}
						if srcSpec.DateHistogram.Missing != nil {
							if _, ok := t.resolveDateHistogramMissingMs(dhB.ESType, srcSpec.DateHistogram.Missing); !ok {
								expr = fmt.Sprintf("COALESCE(%s, %s)", expr, quoteStr(formatMissingScalar(srcSpec.DateHistogram.Missing)))
							}
						} else if srcSpec.DateHistogram.MissingBucket {
							expr = fmt.Sprintf("COALESCE(%s, '__ES_MISSING_BUCKET__')", expr)
						} else {
							notNullConds = append(notNullConds, fmt.Sprintf("%s IS NOT NULL", col))
						}
						colExprs = append(colExprs, expr)
						srcNames = append(srcNames, sk)
					case srcSpec.Histogram != nil:
						hasHistogramSrc = true
						interval := srcSpec.Histogram.Interval
						if interval <= 0 {
							interval = 1.0
						}
						offset := srcSpec.Histogram.Offset
						hasMiss := srcSpec.Histogram.Missing != nil || srcSpec.Histogram.MissingBucket
						effHField := srcSpec.Histogram.Field
						if effHField == "" && srcSpec.Histogram.Script != nil {
							if docF, ok := extractSimpleDocFieldFromScript(srcSpec.Histogram.Script); ok {
								effHField = docF
							}
						}
						col := resolveCompSourceCol(effHField, true, hasMiss)
						if srcSpec.Histogram.Script != nil {
							overrideExpr := ""
							if effHField != "" {
								overrideExpr = col
							}
							if scriptExpr, ok := t.compileMetricScriptExprWithOverride(srcSpec.Histogram.Script, effHField, overrideExpr, nil); ok {
								col = scriptExpr
							}
						}
						if srcSpec.Histogram.Missing != nil {
							if missVal, ok := resolveHistogramMissingFloat(srcSpec.Histogram.Missing); ok {
								col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(missVal, 'f', -1, 64))
							}
						}
						expr := fmt.Sprintf("CAST(FLOOR((%s - %v) / %v) * %v + %v AS STRING)", col, offset, interval, interval, offset)
						if srcSpec.Histogram.Missing != nil {
							if _, ok := resolveHistogramMissingFloat(srcSpec.Histogram.Missing); !ok {
								expr = fmt.Sprintf("COALESCE(%s, %s)", expr, quoteStr(formatMissingScalar(srcSpec.Histogram.Missing)))
							}
						} else if srcSpec.Histogram.MissingBucket {
							expr = fmt.Sprintf("COALESCE(%s, '__ES_MISSING_BUCKET__')", expr)
						} else {
							notNullConds = append(notNullConds, fmt.Sprintf("%s IS NOT NULL", col))
						}
						colExprs = append(colExprs, expr)
						srcNames = append(srcNames, sk)
					}
				}
			}
			if len(colExprs) > 0 {
				bucketKeyExpr := colExprs[0]
				if len(colExprs) > 1 {
					bucketKeyExpr = fmt.Sprintf("CONCAT_WS('\\x1f', %s)", strings.Join(colExprs, ", "))
				}
				wCond := "1=1"
				if len(notNullConds) > 0 {
					wCond = strings.Join(notNullConds, " AND ")
				}
				if hasHistogramSrc {
					size = t.maxAggBuckets()
				} else if len(spec.Composite.After) > 0 {
					var afterParts []string
					for _, sn := range srcNames {
						if av, ok := spec.Composite.After[sn]; ok && av != nil {
							if fv, ok := av.(float64); ok && fv == math.Trunc(fv) {
								afterParts = append(afterParts, strconv.FormatInt(int64(fv), 10))
							} else {
								afterParts = append(afterParts, fmt.Sprintf("%v", av))
							}
						} else {
							afterParts = append(afterParts, "")
						}
					}
					afterCursor := strings.Join(afterParts, "\x1f")
					wCond = fmt.Sprintf("(%s) AND (%s > %s)", wCond, bucketKeyExpr, quoteStr(afterCursor))
				}
				if extraWhere != "" {
					wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
				}
				*subIdx++
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s "+
						"GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(fullAggName), bucketKeyExpr, compFrom, wCond, size, *subIdx,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, bucketKeyExpr,
						compFrom, wCond, subAggs)
				}
			}
		}
	}
}

func (t *Transpiler) maxAggBuckets() int {
	if t.Opts.MaxAggBuckets > 0 {
		return t.Opts.MaxAggBuckets
	}
	return DefaultMaxAggBuckets
}

func (t *Transpiler) capBucketSize(size int) int {
	if size <= 0 {
		return 10
	}
	maxBuckets := t.maxAggBuckets()
	if size > maxBuckets {
		return maxBuckets
	}
	return size
}

func (t *Transpiler) appendValueCountAggBranchWithMissingAndScript(branches *[]string, fullAggName, field, extraWhere string, missing any, script any) {
	effField := field
	if effField == "" && script != nil {
		if docF, ok := extractSimpleDocFieldFromScript(script); ok {
			effField = docF
		}
	}
	b := t.Schema.ResolveField(effField)
	arrCol := b.EffectiveArrayColumn(true)
	wherePrefix := ""
	if extraWhere != "" {
		wherePrefix = fmt.Sprintf("(%s) AND ", extraWhere)
	}
	if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		valExpr := "`_elem`"
		explodeExpr := fmt.Sprintf("`%s`", arrCol)
		wClause := fmt.Sprintf(" WHERE %s`_elem` IS NOT NULL", wherePrefix)
		if missing != nil {
			missLit := quoteStr(formatMissingScalar(missing))
			valExpr = fmt.Sprintf("COALESCE(`_elem`, %s)", missLit)
			explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END", arrCol, arrCol, arrCol)
			wClause = ""
			if extraWhere != "" {
				wClause = " WHERE " + extraWhere
			}
		}
		if script != nil {
			if scriptExpr, ok := t.compilePolymorphicScriptExpr(script, effField, valExpr, nil); ok {
				valExpr = scriptExpr
			}
		}
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
				"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_t` AS `_elem`%s",
			quoteStr(fullAggName), valExpr, explodeExpr, wClause,
		))
		return
	}
	col := t.sqlColumnRef(effField, true, nil)
	if missing != nil && effField != "" {
		col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(missing)))
	}
	if script != nil {
		overrideExpr := ""
		if effField != "" {
			overrideExpr = col
		}
		if scriptExpr, ok := t.compilePolymorphicScriptExpr(script, effField, overrideExpr, nil); ok {
			col = scriptExpr
		}
	}
	if missing != nil && effField == "" {
		col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(missing)))
	}
	wClause := ""
	if extraWhere != "" {
		wClause = " WHERE " + extraWhere
	}
	*branches = append(*branches, fmt.Sprintf(
		"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
			"FROM `base_matched`%s",
		quoteStr(fullAggName), col, wClause,
	))
}

func (t *Transpiler) appendGroupedBucketSubAggs(
	branches *[]string,
	subIdx *int,
	parentAggName string,
	parentBucketExpr string,
	fromClause string,
	whereClause string,
	subAggs map[string]esast.AggSpec,
) {
	t.appendGroupedBucketSubAggsWithNested(branches, subIdx, parentAggName, parentBucketExpr, fromClause, whereClause, nil, subAggs)
}

func (t *Transpiler) appendGroupedBucketSubAggsWithNested(
	branches *[]string,
	subIdx *int,
	parentAggName string,
	parentBucketExpr string,
	fromClause string,
	whereClause string,
	nctx *nestedCtx,
	subAggs map[string]esast.AggSpec,
) {
	subNames := make([]string, 0, len(subAggs))
	for k := range subAggs {
		subNames = append(subNames, k)
	}
	sort.Strings(subNames)

	isExplodedNested := func(b schema.FieldBinding, field string) bool {
		return nctx != nil && ((b.Kind == schema.StorageNestedSubfield && b.NestedPath == nctx.nestedPath) || strings.HasPrefix(field, nctx.nestedPath+"."))
	}

	explodeDepth := strings.Count(fromClause, "LATERAL VIEW EXPLODE")
	subTableAlias := "`_sub_t`"
	subElemAlias := "`_sub_elem`"
	if strings.Contains(fromClause, "`_sub_elem`") {
		subTableAlias = fmt.Sprintf("`_sub_t_%d`", explodeDepth)
		subElemAlias = fmt.Sprintf("`_sub_elem_%d`", explodeDepth)
	}

	appendSubNumericMetric := func(subFull, fn, field string, missing any, script any) {
		effField := field
		if effField == "" && script != nil {
			if docF, ok := extractSimpleDocFieldFromScript(script); ok {
				effField = docF
			}
		}
		b := t.Schema.ResolveField(effField)
		arrCol := b.EffectiveArrayColumn(true)
		if isExplodedNested(b, effField) {
			col := t.sqlNumericColumnRef(effField, nctx)
			rawCol := t.sqlColumnRef(effField, true, nctx)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, rawCol)
			if missing != nil {
				if mf, ok := resolveHistogramMissingFloat(missing); ok {
					col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
					subWhere = whereClause
				}
			}
			if script != nil {
				if scriptExpr, ok := t.compileMetricScriptExprWithOverride(script, effField, col, nctx); ok {
					col = scriptExpr
				}
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, fn, col, fromClause, subWhere,
			))
			return
		}
		if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
			valExpr := fmt.Sprintf("CAST(%s AS DOUBLE)", subElemAlias)
			subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
			if missing != nil {
				if mf, ok := resolveHistogramMissingFloat(missing); ok {
					valExpr = fmt.Sprintf("COALESCE(CAST(%s AS DOUBLE), %s)", subElemAlias, strconv.FormatFloat(mf, 'f', -1, 64))
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
					subWhere = whereClause
				}
			}
			if script != nil {
				if scriptExpr, ok := t.compileMetricScriptExprWithOverride(script, effField, valExpr, nil); ok {
					valExpr = scriptExpr
				}
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, fn, valExpr, subFrom, subWhere,
			))
			return
		}
		col := t.sqlNumericColumnRef(effField, nctx)
		if missing != nil && effField != "" {
			if mf, ok := resolveHistogramMissingFloat(missing); ok {
				col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
			}
		}
		if script != nil {
			overrideExpr := ""
			if effField != "" {
				overrideExpr = col
			}
			if scriptExpr, ok := t.compileMetricScriptExprWithOverride(script, effField, overrideExpr, nctx); ok {
				col = scriptExpr
			}
		}
		if missing != nil && effField == "" {
			if mf, ok := resolveHistogramMissingFloat(missing); ok {
				col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
			}
		}
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
				"FROM %s WHERE %s GROUP BY `_bucket_key`",
			quoteStr(subFull), parentBucketExpr, fn, col, fromClause, whereClause,
		))
	}

	for _, subName := range subNames {
		subSpec := subAggs[subName]
		subFull := parentAggName + "." + subName
		switch {
		case subSpec.Avg != nil:
			appendSubNumericMetric(subFull, "AVG", subSpec.Avg.Field, subSpec.Avg.Missing, subSpec.Avg.Script)
		case subSpec.Sum != nil:
			appendSubNumericMetric(subFull, "SUM", subSpec.Sum.Field, subSpec.Sum.Missing, subSpec.Sum.Script)
		case subSpec.Min != nil:
			appendSubNumericMetric(subFull, "MIN", subSpec.Min.Field, subSpec.Min.Missing, subSpec.Min.Script)
		case subSpec.Max != nil:
			appendSubNumericMetric(subFull, "MAX", subSpec.Max.Field, subSpec.Max.Missing, subSpec.Max.Script)
		case subSpec.Rate != nil:
			if subSpec.Rate.Field == "" && subSpec.Rate.Script == nil {
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), parentBucketExpr, fromClause, whereClause,
				))
			} else if strings.EqualFold(subSpec.Rate.Mode, "value_count") {
				b := t.Schema.ResolveField(subSpec.Rate.Field)
				arrCol := b.EffectiveArrayColumn(true)
				if !isExplodedNested(b, subSpec.Rate.Field) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
					subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
					subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull), parentBucketExpr, subElemAlias, subFrom, subWhere,
					))
				} else {
					col := t.sqlColumnRef(subSpec.Rate.Field, true, nctx)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
					))
				}
			} else {
				appendSubNumericMetric(subFull, "SUM", subSpec.Rate.Field, nil, subSpec.Rate.Script)
			}
		case subSpec.EffectiveStats() != nil:
			statsSpec := subSpec.EffectiveStats()
			statOps := []struct{ key, fn string }{
				{"_stats_count", "COUNT"},
				{"_stats_min", "MIN"},
				{"_stats_max", "MAX"},
				{"_stats_avg", "AVG"},
				{"_stats_sum", "SUM"},
			}
			if subSpec.ExtendedStats != nil {
				statOps = append(statOps, struct{ key, fn string }{"_stats_std", "STDDEV_POP"})
			}
			for _, statOp := range statOps {
				appendSubNumericMetric(subFull+"."+statOp.key, statOp.fn, statsSpec.Field, statsSpec.Missing, statsSpec.Script)
			}
		case subSpec.Percentiles != nil:
			effPctField := subSpec.Percentiles.Field
			if effPctField == "" && subSpec.Percentiles.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.Percentiles.Script); ok {
					effPctField = docF
				}
			}
			b := t.Schema.ResolveField(effPctField)
			arrCol := b.EffectiveArrayColumn(true)
			for _, pct := range subSpec.Percentiles.EffectivePercents() {
				q := pct / 100.0
				if q < 0 {
					q = 0
				} else if q > 1 {
					q = 1
				}
				pctKey := strconv.FormatFloat(pct, 'f', -1, 64)
				if !strings.Contains(pctKey, ".") {
					pctKey += ".0"
				}
				if !isExplodedNested(b, effPctField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
					valExpr := fmt.Sprintf("CAST(%s AS DOUBLE)", subElemAlias)
					subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
					subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
					if subSpec.Percentiles.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Percentiles.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(CAST(%s AS DOUBLE), %s)", subElemAlias, strconv.FormatFloat(mf, 'f', -1, 64))
							subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
							subWhere = whereClause
						}
					}
					if subSpec.Percentiles.Script != nil {
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.Percentiles.Script, effPctField, valExpr, nil); ok {
							valExpr = scriptExpr
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull+"."+pctKey), parentBucketExpr, valExpr, q, subFrom, subWhere,
					))
				} else {
					col := t.sqlNumericColumnRef(effPctField, nctx)
					subWhere := whereClause
					if isExplodedNested(b, effPctField) {
						subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, t.sqlColumnRef(effPctField, true, nctx))
					}
					if subSpec.Percentiles.Missing != nil && effPctField != "" {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Percentiles.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
							subWhere = whereClause
						}
					}
					if subSpec.Percentiles.Script != nil {
						overrideExpr := ""
						if effPctField != "" {
							overrideExpr = col
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.Percentiles.Script, effPctField, overrideExpr, nctx); ok {
							col = scriptExpr
							if subSpec.Percentiles.Missing == nil {
								subWhere = whereClause
							}
						}
					}
					if subSpec.Percentiles.Missing != nil && effPctField == "" {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Percentiles.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
							subWhere = whereClause
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull+"."+pctKey), parentBucketExpr, col, q, fromClause, subWhere,
					))
				}
			}
		case subSpec.Boxplot != nil:
			effBpField := subSpec.Boxplot.Field
			if effBpField == "" && subSpec.Boxplot.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.Boxplot.Script); ok {
					effBpField = docF
				}
			}
			b := t.Schema.ResolveField(effBpField)
			arrCol := b.EffectiveArrayColumn(true)
			for _, pct := range []float64{0.0, 25.0, 50.0, 75.0, 100.0} {
				q := pct / 100.0
				pctKey := fmt.Sprintf("%.1f", pct)
				if !isExplodedNested(b, effBpField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
					valExpr := fmt.Sprintf("CAST(%s AS DOUBLE)", subElemAlias)
					subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
					subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
					if subSpec.Boxplot.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Boxplot.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(CAST(%s AS DOUBLE), %s)", subElemAlias, strconv.FormatFloat(mf, 'f', -1, 64))
							subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
							subWhere = whereClause
						}
					}
					if subSpec.Boxplot.Script != nil {
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.Boxplot.Script, effBpField, valExpr, nil); ok {
							valExpr = scriptExpr
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull+"."+pctKey), parentBucketExpr, valExpr, q, subFrom, subWhere,
					))
				} else {
					col := t.sqlNumericColumnRef(effBpField, nctx)
					subWhere := whereClause
					if isExplodedNested(b, effBpField) {
						subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, t.sqlColumnRef(effBpField, true, nctx))
					}
					if subSpec.Boxplot.Missing != nil && effBpField != "" {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Boxplot.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
							subWhere = whereClause
						}
					}
					if subSpec.Boxplot.Script != nil {
						overrideExpr := ""
						if effBpField != "" {
							overrideExpr = col
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.Boxplot.Script, effBpField, overrideExpr, nctx); ok {
							col = scriptExpr
							if subSpec.Boxplot.Missing == nil {
								subWhere = whereClause
							}
						}
					}
					if subSpec.Boxplot.Missing != nil && effBpField == "" {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Boxplot.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
							subWhere = whereClause
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull+"."+pctKey), parentBucketExpr, col, q, fromClause, subWhere,
					))
				}
			}
		case subSpec.PercentileRanks != nil:
			effPrField := subSpec.PercentileRanks.Field
			if effPrField == "" && subSpec.PercentileRanks.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.PercentileRanks.Script); ok {
					effPrField = docF
				}
			}
			b := t.Schema.ResolveField(effPrField)
			arrCol := b.EffectiveArrayColumn(true)
			for _, v := range subSpec.PercentileRanks.Values {
				valKey := strconv.FormatFloat(v, 'f', -1, 64)
				if !strings.Contains(valKey, ".") {
					valKey += ".0"
				}
				valLit := strconv.FormatFloat(v, 'f', -1, 64)
				if !isExplodedNested(b, effPrField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
					valExpr := fmt.Sprintf("CAST(%s AS DOUBLE)", subElemAlias)
					subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
					subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
					if subSpec.PercentileRanks.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.PercentileRanks.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(CAST(%s AS DOUBLE), %s)", subElemAlias, strconv.FormatFloat(mf, 'f', -1, 64))
							subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
							subWhere = whereClause
						}
					}
					if subSpec.PercentileRanks.Script != nil {
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.PercentileRanks.Script, effPrField, valExpr, nil); ok {
							valExpr = scriptExpr
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(AVG(CASE WHEN %s <= %s THEN 100.0 ELSE 0.0 END), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull+"."+valKey), parentBucketExpr, valExpr, valLit, subFrom, subWhere,
					))
				} else {
					col := t.sqlNumericColumnRef(effPrField, nctx)
					notNullRef := col
					if isExplodedNested(b, effPrField) {
						notNullRef = t.sqlColumnRef(effPrField, true, nctx)
					}
					subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, notNullRef)
					if subSpec.PercentileRanks.Missing != nil && effPrField != "" {
						if mf, ok := resolveHistogramMissingFloat(subSpec.PercentileRanks.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
							subWhere = whereClause
						}
					}
					if subSpec.PercentileRanks.Script != nil {
						overrideExpr := ""
						if effPrField != "" {
							overrideExpr = col
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.PercentileRanks.Script, effPrField, overrideExpr, nctx); ok {
							col = scriptExpr
							if subSpec.PercentileRanks.Missing == nil {
								subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
							}
						}
					}
					if subSpec.PercentileRanks.Missing != nil && effPrField == "" {
						if mf, ok := resolveHistogramMissingFloat(subSpec.PercentileRanks.Missing); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
							subWhere = whereClause
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(AVG(CASE WHEN %s <= %s THEN 100.0 ELSE 0.0 END), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull+"."+valKey), parentBucketExpr, col, valLit, fromClause, subWhere,
					))
				}
			}
		case subSpec.StringStats != nil:
			b := t.Schema.ResolveField(subSpec.StringStats.Field)
			arrCol := b.EffectiveArrayColumn(true)
			var lenExpr, subFrom, subWhere string
			if !isExplodedNested(b, subSpec.StringStats.Field) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				lenExpr = fmt.Sprintf("CAST(CHAR_LENGTH(CAST(%s AS STRING)) AS DOUBLE)", subElemAlias)
				subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
			} else {
				col := t.sqlColumnRef(subSpec.StringStats.Field, true, nctx)
				lenExpr = fmt.Sprintf("CAST(CHAR_LENGTH(CAST(%s AS STRING)) AS DOUBLE)", col)
				subFrom = fromClause
				subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
			}
			for _, op := range []struct{ key, fn string }{
				{"_stats_count", "COUNT"},
				{"_stats_min", "MIN"},
				{"_stats_max", "MAX"},
				{"_stats_avg", "AVG"},
			} {
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull+"."+op.key), parentBucketExpr, op.fn, lenExpr, subFrom, subWhere,
				))
			}
		case subSpec.EffectiveSampler() != nil:
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, fromClause, whereClause,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, parentBucketExpr, fromClause, whereClause, nctx, nestedSubs)
			}
		case subSpec.ReverseNested != nil:
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT `_id`) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, fromClause, whereClause,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				rnFrom := fromClause
				rnBucketExpr := parentBucketExpr
				rnWhere := whereClause
				if fromClause != "`base_matched`" {
					rnFrom = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id`, %s AS `_rn_bkey` FROM %s WHERE %s) `_rn_dedup` ON `base_matched`.`_id` = `_rn_dedup`.`_rn_id`", parentBucketExpr, fromClause, whereClause)
					rnBucketExpr = "`_rn_bkey`"
					rnWhere = "1=1"
				}
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, rnBucketExpr, rnFrom, rnWhere, nil, nestedSubs)
			}
		case subSpec.Filter != nil:
			cond := t.CompileQuery(subSpec.Filter, false, nctx)
			subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, cond.WhereSQL)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, fromClause, subWhere,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, parentBucketExpr, fromClause, subWhere, nctx, nestedSubs)
			}
		case subSpec.Missing != nil:
			existsPred := t.compileExistsPredicate(subSpec.Missing.Field, nctx)
			subWhere := fmt.Sprintf("(%s) AND NOT (%s)", whereClause, existsPred)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, fromClause, subWhere,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, parentBucketExpr, fromClause, subWhere, nctx, nestedSubs)
			}
		case subSpec.ValueCount != nil:
			effVCField := subSpec.ValueCount.Field
			if effVCField == "" && subSpec.ValueCount.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.ValueCount.Script); ok {
					effVCField = docF
				}
			}
			b := t.Schema.ResolveField(effVCField)
			arrCol := b.EffectiveArrayColumn(true)
			if !isExplodedNested(b, effVCField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				valExpr := subElemAlias
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
				if subSpec.ValueCount.Missing != nil {
					valExpr = fmt.Sprintf("COALESCE(%s, %s)", subElemAlias, quoteStr(formatMissingScalar(subSpec.ValueCount.Missing)))
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
					subWhere = whereClause
				}
				if subSpec.ValueCount.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.ValueCount.Script, effVCField, valExpr, nil); ok {
						valExpr = scriptExpr
					}
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), parentBucketExpr, valExpr, subFrom, subWhere,
				))
			} else {
				col := t.sqlColumnRef(effVCField, true, nctx)
				subWhere := whereClause
				if isExplodedNested(b, effVCField) {
					subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
				}
				if subSpec.ValueCount.Missing != nil && effVCField != "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(subSpec.ValueCount.Missing)))
					subWhere = whereClause
				}
				if subSpec.ValueCount.Script != nil {
					overrideExpr := ""
					if effVCField != "" {
						overrideExpr = col
					}
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.ValueCount.Script, effVCField, overrideExpr, nctx); ok {
						col = scriptExpr
						if subSpec.ValueCount.Missing == nil {
							subWhere = whereClause
						}
					}
				}
				if subSpec.ValueCount.Missing != nil && effVCField == "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(subSpec.ValueCount.Missing)))
					subWhere = whereClause
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), parentBucketExpr, col, fromClause, subWhere,
				))
			}
		case subSpec.Cardinality != nil:
			effCardField := subSpec.Cardinality.Field
			if effCardField == "" && subSpec.Cardinality.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.Cardinality.Script); ok {
					effCardField = docF
				}
			}
			b := t.Schema.ResolveField(effCardField)
			if !isExplodedNested(b, effCardField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				arrCol := b.EffectiveArrayColumn(true)
				valExpr := subElemAlias
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
				if subSpec.Cardinality.Missing != nil {
					valExpr = fmt.Sprintf("COALESCE(%s, %s)", subElemAlias, quoteStr(formatMissingScalar(subSpec.Cardinality.Missing)))
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
					subWhere = whereClause
				}
				if subSpec.Cardinality.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.Cardinality.Script, effCardField, valExpr, nil); ok {
						valExpr = scriptExpr
					}
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT %s) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), parentBucketExpr, valExpr, subFrom, subWhere,
				))
			} else {
				col := t.sqlColumnRef(effCardField, true, nctx)
				subWhere := whereClause
				if isExplodedNested(b, effCardField) {
					subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
				}
				if subSpec.Cardinality.Missing != nil && effCardField != "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(subSpec.Cardinality.Missing)))
					subWhere = whereClause
				}
				if subSpec.Cardinality.Script != nil {
					overrideExpr := ""
					if effCardField != "" {
						overrideExpr = col
					}
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.Cardinality.Script, effCardField, overrideExpr, nctx); ok {
						col = scriptExpr
						if subSpec.Cardinality.Missing == nil {
							subWhere = whereClause
						}
					}
				}
				if subSpec.Cardinality.Missing != nil && effCardField == "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(subSpec.Cardinality.Missing)))
					subWhere = whereClause
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT %s) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), parentBucketExpr, col, fromClause, subWhere,
				))
			}
		case subSpec.EffectiveTerms() != nil:
			subTerms := subSpec.EffectiveTerms()
			effSubField := subTerms.Field
			if effSubField == "" && subTerms.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subTerms.Script); ok {
					effSubField = docF
				}
			}
			b := t.Schema.ResolveField(effSubField)
			effSubSize := t.capBucketSize(subTerms.Size)
			if subTerms.Order != nil || subTerms.Include != nil || subTerms.Exclude != nil {
				effSubSize = t.maxAggBuckets()
			}
			subLimit := t.capBucketSize(effSubSize * 100)
			*subIdx++
			if !isExplodedNested(b, effSubField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				arrCol := b.EffectiveArrayColumn(true)
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				valExpr := fmt.Sprintf("CAST(%s AS STRING)", subElemAlias)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
				if subTerms.Missing != nil {
					missingLit := quoteStr(formatMissingScalar(subTerms.Missing))
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
					valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", subElemAlias, missingLit)
					subWhere = whereClause
				}
				if subTerms.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(subTerms.Script, effSubField, valExpr, nil); ok {
						valExpr = fmt.Sprintf("CAST(%s AS STRING)", scriptExpr)
					}
				}
				childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, valExpr)
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s "+
						"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(subFull), childKeyExpr, subFrom, subWhere, subLimit, *subIdx,
				))
				if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, subFrom, subWhere, nctx, nestedSubs)
				}
			} else {
				col := t.sqlColumnRef(effSubField, true, nctx)
				if subTerms.Missing != nil && effSubField != "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(subTerms.Missing)))
				}
				if subTerms.Script != nil {
					overrideExpr := ""
					if effSubField != "" {
						overrideExpr = col
					}
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(subTerms.Script, effSubField, overrideExpr, nctx); ok {
						col = scriptExpr
					}
				}
				if subTerms.Missing != nil && effSubField == "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(subTerms.Missing)))
				}
				childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', CAST(%s AS STRING))", parentBucketExpr, col)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
				if subTerms.Missing != nil {
					subWhere = whereClause
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s "+
						"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(subFull), childKeyExpr, fromClause, subWhere, subLimit, *subIdx,
				))
				if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, fromClause, subWhere, nctx, nestedSubs)
				}
			}
		case subSpec.DateHistogram != nil:
			intervalMs := subSpec.DateHistogram.EffectiveIntervalMs()
			tzShiftMs := subSpec.DateHistogram.EffectiveTimeZoneOffsetMs() - subSpec.DateHistogram.EffectiveOffsetMs()
			effDHField := subSpec.DateHistogram.Field
			if effDHField == "" && subSpec.DateHistogram.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.DateHistogram.Script); ok {
					effDHField = docF
				}
			}
			b := t.Schema.ResolveField(effDHField)
			arrCol := b.EffectiveArrayColumn(true)
			subFrom := fromClause
			var col, notNullExpr string
			hasMissing := false
			if isExplodedNested(b, effDHField) {
				col = t.sqlNumericColumnRef(effDHField, nctx)
				notNullExpr = t.sqlColumnRef(effDHField, true, nctx)
			} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				col = fmt.Sprintf("CAST(%s AS DOUBLE)", subElemAlias)
				notNullExpr = subElemAlias
				subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				if subSpec.DateHistogram.Missing != nil {
					if missMs, ok := t.resolveDateHistogramMissingMs(b.ESType, subSpec.DateHistogram.Missing); ok {
						subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
						col = fmt.Sprintf("COALESCE(CAST(%s AS DOUBLE), %d)", subElemAlias, missMs)
						hasMissing = true
					}
				}
			} else {
				col = t.sqlNumericColumnRef(effDHField, nctx)
				notNullExpr = col
			}
			if !hasMissing && subSpec.DateHistogram.Missing != nil && effDHField != "" {
				if missMs, ok := t.resolveDateHistogramMissingMs(b.ESType, subSpec.DateHistogram.Missing); ok {
					col = fmt.Sprintf("COALESCE(%s, %d)", col, missMs)
					hasMissing = true
				}
			}
			if subSpec.DateHistogram.Script != nil {
				overrideExpr := ""
				if effDHField != "" {
					overrideExpr = col
				}
				var scriptNctx *nestedCtx
				if isExplodedNested(b, effDHField) || (b.Kind != schema.StoragePromotedArray && b.Kind != schema.StorageNestedSubfield) {
					scriptNctx = nctx
				}
				if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.DateHistogram.Script, effDHField, overrideExpr, scriptNctx); ok {
					col = scriptExpr
					if !hasMissing {
						notNullExpr = col
					}
				}
			}
			if !hasMissing && subSpec.DateHistogram.Missing != nil && effDHField == "" {
				if missMs, ok := t.resolveDateHistogramMissingMs(b.ESType, subSpec.DateHistogram.Missing); ok {
					col = fmt.Sprintf("COALESCE(%s, %d)", col, missMs)
					hasMissing = true
				}
			}
			childBucketExpr := fmt.Sprintf("CAST(CAST(FLOOR(%s / %d) * %d AS BIGINT) AS STRING)", col, intervalMs, intervalMs)
			if tzShiftMs != 0 {
				childBucketExpr = fmt.Sprintf("CAST(CAST(FLOOR((%s + %d) / %d) * %d - %d AS BIGINT) AS STRING)", col, tzShiftMs, intervalMs, intervalMs, tzShiftMs)
			}
			compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, childBucketExpr)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, notNullExpr)
			if hasMissing {
				subWhere = whereClause
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), compKeyExpr, subFrom, subWhere,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, compKeyExpr, subFrom, subWhere, nctx, nestedSubs)
			}
		case subSpec.Histogram != nil:
			interval := subSpec.Histogram.Interval
			if interval <= 0 {
				interval = 1.0
			}
			offset := subSpec.Histogram.Offset
			effHField := subSpec.Histogram.Field
			if effHField == "" && subSpec.Histogram.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.Histogram.Script); ok {
					effHField = docF
				}
			}
			b := t.Schema.ResolveField(effHField)
			arrCol := b.EffectiveArrayColumn(true)
			subFrom := fromClause
			var col, notNullExpr string
			hasMissing := false
			if isExplodedNested(b, effHField) {
				col = t.sqlNumericColumnRef(effHField, nctx)
				notNullExpr = t.sqlColumnRef(effHField, true, nctx)
			} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				col = fmt.Sprintf("CAST(%s AS DOUBLE)", subElemAlias)
				notNullExpr = subElemAlias
				subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				if subSpec.Histogram.Missing != nil {
					if missVal, ok := resolveHistogramMissingFloat(subSpec.Histogram.Missing); ok {
						subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
						col = fmt.Sprintf("COALESCE(CAST(%s AS DOUBLE), %s)", subElemAlias, strconv.FormatFloat(missVal, 'f', -1, 64))
						hasMissing = true
					}
				}
			} else {
				col = t.sqlNumericColumnRef(effHField, nctx)
				notNullExpr = col
			}
			if !hasMissing && subSpec.Histogram.Missing != nil && effHField != "" {
				if missVal, ok := resolveHistogramMissingFloat(subSpec.Histogram.Missing); ok {
					col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(missVal, 'f', -1, 64))
					hasMissing = true
				}
			}
			if subSpec.Histogram.Script != nil {
				overrideExpr := ""
				if effHField != "" {
					overrideExpr = col
				}
				var scriptNctx *nestedCtx
				if isExplodedNested(b, effHField) || (b.Kind != schema.StoragePromotedArray && b.Kind != schema.StorageNestedSubfield) {
					scriptNctx = nctx
				}
				if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.Histogram.Script, effHField, overrideExpr, scriptNctx); ok {
					col = scriptExpr
					if !hasMissing {
						notNullExpr = col
					}
				}
			}
			if !hasMissing && subSpec.Histogram.Missing != nil && effHField == "" {
				if missVal, ok := resolveHistogramMissingFloat(subSpec.Histogram.Missing); ok {
					col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(missVal, 'f', -1, 64))
					hasMissing = true
				}
			}
			childBucketExpr := fmt.Sprintf("CAST(FLOOR((%s - %v) / %v) * %v + %v AS STRING)", col, offset, interval, interval, offset)
			compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, childBucketExpr)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, notNullExpr)
			if hasMissing {
				subWhere = whereClause
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), compKeyExpr, subFrom, subWhere,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, compKeyExpr, subFrom, subWhere, nctx, nestedSubs)
			}
		case subSpec.EffectiveRange() != nil:
			rngSpec := subSpec.EffectiveRange()
			now := time.Now().UTC()
			effRField := rngSpec.Field
			if effRField == "" && rngSpec.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(rngSpec.Script); ok {
					effRField = docF
				}
			}
			b := t.Schema.ResolveField(effRField)
			arrCol := b.EffectiveArrayColumn(true)
			isArray := !isExplodedNested(b, effRField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield)
			for _, rng := range rngSpec.Ranges {
				var rWhere string
				subFrom := fromClause
				if subSpec.IPRange != nil {
					ipCol := t.sqlColumnRef(effRField, true, nctx)
					if isArray {
						ipCol = "_x"
					}
					numCol := fmt.Sprintf("IPV4_STRING_TO_NUM_OR_NULL(%s)", ipCol)
					var conds []string
					if !isArray {
						conds = append(conds, fmt.Sprintf("%s IS NOT NULL", ipCol))
					}
					if rng.Mask != "" {
						validMask := false
						if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(rng.Mask)); err == nil && ipNet != nil {
							if ip4 := ipNet.IP.To4(); ip4 != nil && len(ipNet.Mask) == 4 {
								validMask = true
								maskNum := uint32(ipNet.Mask[0])<<24 | uint32(ipNet.Mask[1])<<16 | uint32(ipNet.Mask[2])<<8 | uint32(ipNet.Mask[3])
								startNum := (uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])) & maskNum
								endNum := startNum | ^maskNum
								conds = append(conds,
									fmt.Sprintf("%s >= %d", numCol, int64(startNum)),
									fmt.Sprintf("%s <= %d", numCol, int64(endNum)),
								)
							}
						}
						if !validMask {
							conds = append(conds, "1=0")
						}
					} else {
						if rng.From != nil {
							if n, ok := parseIPv4ToUint32(rng.From); ok {
								conds = append(conds, fmt.Sprintf("%s >= %d", numCol, n))
							} else {
								conds = append(conds, fmt.Sprintf("%s >= %s", ipCol, quoteValue(rng.From)))
							}
						}
						if rng.To != nil {
							if n, ok := parseIPv4ToUint32(rng.To); ok {
								conds = append(conds, fmt.Sprintf("%s < %d", numCol, n))
							} else {
								conds = append(conds, fmt.Sprintf("%s < %s", ipCol, quoteValue(rng.To)))
							}
						}
					}
					if isArray {
						if len(conds) == 0 {
							rWhere = fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", arrCol, arrCol)
						} else {
							rWhere = fmt.Sprintf("array_exists(_x -> %s, `%s`)", strings.Join(conds, " AND "), arrCol)
						}
					} else {
						rWhere = strings.Join(conds, " AND ")
					}
				} else if isArray {
					elemExpr := "CAST(_x AS DOUBLE)"
					if rngSpec.Script != nil {
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(rngSpec.Script, effRField, elemExpr, nil); ok {
							elemExpr = scriptExpr
						}
					}
					var elemConds []string
					if rng.From != nil {
						elemConds = append(elemConds, fmt.Sprintf("%s >= %s", elemExpr, quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.From, now))))
					}
					if rng.To != nil {
						elemConds = append(elemConds, fmt.Sprintf("%s < %s", elemExpr, quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.To, now))))
					}
					arrExpr := fmt.Sprintf("`%s`", arrCol)
					if rngSpec.Missing != nil {
						if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
							arrExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [%s] ELSE `%s` END", arrCol, arrCol, strconv.FormatFloat(mf, 'f', -1, 64), arrCol)
						}
					}
					if len(elemConds) == 0 {
						rWhere = fmt.Sprintf("(%s IS NOT NULL AND array_size(%s) > 0)", arrExpr, arrExpr)
					} else {
						rWhere = fmt.Sprintf("array_exists(_x -> %s, %s)", strings.Join(elemConds, " AND "), arrExpr)
					}
				} else {
					col := t.sqlNumericColumnRef(effRField, nctx)
					if rngSpec.Missing != nil && effRField != "" {
						if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
						}
					}
					if rngSpec.Script != nil {
						overrideExpr := ""
						if effRField != "" {
							overrideExpr = col
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(rngSpec.Script, effRField, overrideExpr, nctx); ok {
							col = scriptExpr
						}
					}
					if rngSpec.Missing != nil && effRField == "" {
						if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
							col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
						}
					}
					var conds []string
					conds = append(conds, fmt.Sprintf("%s IS NOT NULL", col))
					if rng.From != nil {
						conds = append(conds, fmt.Sprintf("%s >= %s", col, quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.From, now))))
					}
					if rng.To != nil {
						conds = append(conds, fmt.Sprintf("%s < %s", col, quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.To, now))))
					}
					rWhere = strings.Join(conds, " AND ")
				}
				subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, rWhere)
				compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(rng.EffectiveKey()))
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), compKeyExpr, subFrom, subWhere,
				))
				if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, compKeyExpr, subFrom, subWhere, nctx, nestedSubs)
				}
			}
		case subSpec.Filters != nil:
			if subSpec.Filters.IsAnonymous {
				var allSafeConds []string
				for i, fq := range subSpec.Filters.AnonymousFilters {
					fCond := t.CompileQuery(&fq, false, nctx)
					allSafeConds = append(allSafeConds, fmt.Sprintf("(%s)", fCond.EffectiveSafeWhere()))
					bKey := strconv.Itoa(i)
					compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(bKey))
					subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, fCond.WhereSQL)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull), compKeyExpr, fromClause, subWhere,
					))
					if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
						t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, compKeyExpr, fromClause, subWhere, nctx, nestedSubs)
					}
				}
				if subSpec.Filters.OtherBucket && len(allSafeConds) > 0 {
					otherKey := subSpec.Filters.EffectiveOtherBucketKey()
					compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(otherKey))
					otherWhere := fmt.Sprintf("(%s) AND (NOT COALESCE(%s, FALSE))", whereClause, strings.Join(allSafeConds, " OR "))
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull), compKeyExpr, fromClause, otherWhere,
					))
					if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
						t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, compKeyExpr, fromClause, otherWhere, nctx, nestedSubs)
					}
				}
			} else {
				fKeys := make([]string, 0, len(subSpec.Filters.Filters))
				for fk := range subSpec.Filters.Filters {
					fKeys = append(fKeys, fk)
				}
				sort.Strings(fKeys)
				var allSafeConds []string
				for _, fk := range fKeys {
					fq := subSpec.Filters.Filters[fk]
					fCond := t.CompileQuery(&fq, false, nctx)
					allSafeConds = append(allSafeConds, fmt.Sprintf("(%s)", fCond.EffectiveSafeWhere()))
					compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(fk))
					subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, fCond.WhereSQL)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull), compKeyExpr, fromClause, subWhere,
					))
					if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
						t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, compKeyExpr, fromClause, subWhere, nctx, nestedSubs)
					}
				}
				if subSpec.Filters.OtherBucket && len(allSafeConds) > 0 {
					otherKey := subSpec.Filters.EffectiveOtherBucketKey()
					compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(otherKey))
					otherWhere := fmt.Sprintf("(%s) AND (NOT COALESCE(%s, FALSE))", whereClause, strings.Join(allSafeConds, " OR "))
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull), compKeyExpr, fromClause, otherWhere,
					))
					if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
						t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, compKeyExpr, fromClause, otherWhere, nctx, nestedSubs)
					}
				}
			}
		case subSpec.Nested != nil:
			corrCol, ok := t.Schema.NestedRoots[subSpec.Nested.Path]
			if !ok {
				corrCol = "n__" + schema.SanitizeDorisIdentifier(subSpec.Nested.Path)
			}
			ntAlias := "`_nt`"
			nelAlias := "`_nel`"
			if strings.Contains(fromClause, "`_nel`") {
				ntAlias = fmt.Sprintf("`_nt_%d`", explodeDepth)
				nelAlias = fmt.Sprintf("`_nel_%d`", explodeDepth)
			}
			subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, corrCol, ntAlias, nelAlias)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, nelAlias)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, nelAlias, subFrom, subWhere,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(
					branches,
					subIdx,
					subFull,
					parentBucketExpr,
					subFrom,
					subWhere,
					&nestedCtx{nestedPath: subSpec.Nested.Path, elemVar: nelAlias},
					nestedSubs,
				)
			}
		case subSpec.TopHits != nil:
			size := subSpec.TopHits.EffectiveFetchLimit()
			if topHitsNeedsRuntimeSort(subSpec.TopHits.Sort) && size < 100 {
				size = 100
			}
			orderBy := t.compileTopHitsOrderBy(subSpec.TopHits.Sort)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, CONCAT(%s, '\\x1f', `_id`) AS `_bucket_key`, "+
					"CAST(ROW_NUMBER() OVER (PARTITION BY %s ORDER BY %s) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s"+
					") `_agg_sub_%d` WHERE `_doc_count` <= %d",
				quoteStr(subFull), parentBucketExpr, parentBucketExpr, orderBy, fromClause, whereClause, *subIdx, size,
			))
		case subSpec.TopMetrics != nil:
			size := subSpec.TopMetrics.EffectiveSize()
			if topHitsNeedsRuntimeSort(subSpec.TopMetrics.Sort) && size < 100 {
				size = 100
			}
			orderBy := t.compileTopHitsOrderBy(subSpec.TopMetrics.Sort)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, CONCAT(%s, '\\x1f', `_id`) AS `_bucket_key`, "+
					"CAST(ROW_NUMBER() OVER (PARTITION BY %s ORDER BY %s) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s"+
					") `_agg_sub_%d` WHERE `_doc_count` <= %d",
				quoteStr(subFull), parentBucketExpr, parentBucketExpr, orderBy, fromClause, whereClause, *subIdx, size,
			))
		}
	}
}

func formatMissingScalar(v any) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return "0"
		}
		if val == math.Trunc(val) && val >= math.MinInt64 && val <= math.MaxInt64 {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case json.Number:
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}

func (t *Transpiler) resolveDateHistogramMissingMs(esType string, missing any) (int64, bool) {
	norm := func(ms int64) int64 {
		if nv, ok := normalizeDateNanosValue(esType, ms).(int64); ok {
			return nv
		}
		return ms
	}
	switch v := missing.(type) {
	case int:
		return norm(int64(v)), true
	case int64:
		return norm(v), true
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			return norm(int64(v)), true
		}
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return norm(i), true
		}
		if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return norm(int64(f)), true
		}
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return norm(i), true
		}
		if ms, ok := schema.ParseESDateToEpochMillis(v, time.Now().UTC()); ok {
			return norm(ms), true
		}
	}
	return 0, false
}

func resolveHistogramMissingFloat(missing any) (float64, bool) {
	switch v := missing.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			return v, true
		}
	case json.Number:
		if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
		if ms, ok := schema.ParseESDateToEpochMillis(v, time.Now().UTC()); ok {
			return float64(ms), true
		}
	}
	return 0, false
}

func parseCIDRBounds(s string) (int64, int64, bool) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		return 0, 0, false
	}
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil || ipNet == nil {
		return 0, 0, false
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil || len(ipNet.Mask) != 4 {
		return 0, 0, false
	}
	maskNum := uint32(ipNet.Mask[0])<<24 | uint32(ipNet.Mask[1])<<16 | uint32(ipNet.Mask[2])<<8 | uint32(ipNet.Mask[3])
	startNum := (uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])) & maskNum
	endNum := startNum | ^maskNum
	return int64(startNum), int64(endNum), true
}

func topHitsNeedsRuntimeSort(sorts []esast.SortSpec) bool {
	if len(sorts) == 0 {
		return true
	}
	for _, s := range sorts {
		if s.Entry.Field == "_score" || s.Entry.Field == "_script" || s.Entry.Field == "_geo_distance" {
			return true
		}
	}
	return false
}

func (t *Transpiler) compileTopHitsOrderBy(sorts []esast.SortSpec) string {
	var filtered []esast.SortSpec
	for _, s := range sorts {
		if s.Entry.Field == "" || s.Entry.Field == "_score" || s.Entry.Field == "_geo_distance" {
			continue
		}
		if s.Entry.Field == "_script" {
			if _, _, ok := t.compileScriptSortExpr(s); !ok {
				continue
			}
		}
		filtered = append(filtered, s)
	}
	if len(filtered) == 0 {
		return "`_id` ASC"
	}
	return t.compileOrderBy(filtered)
}

func (t *Transpiler) resolveRangeAggMissingFloat(field string, rngSpec *esast.RangeAggSpec, now time.Time) (float64, bool) {
	if rngSpec == nil || rngSpec.Missing == nil {
		return 0, false
	}
	coerced := t.coerceRangeAggBoundWithNow(field, rngSpec, rngSpec.Missing, now)
	return resolveHistogramMissingFloat(coerced)
}

func (t *Transpiler) coerceRangeAggBoundWithNow(field string, rngSpec *esast.RangeAggSpec, v any, now time.Time) any {
	b := t.Schema.ResolveField(field)
	isEpochSecond := rngSpec != nil && strings.EqualFold(rngSpec.Format, "epoch_second")
	var tzOffsetMs int64
	if rngSpec != nil {
		tzOffsetMs = esast.ParseTimeZoneOffsetMs(strings.TrimSpace(rngSpec.TimeZone))
	}
	if strVal, ok := v.(string); ok {
		trimmed := strings.TrimSpace(strVal)
		if isEpochSecond {
			if rawSec, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(rawSec) && !math.IsInf(rawSec, 0) {
				return int64(rawSec * 1000)
			}
		}
		if ms, ok := schema.ParseESDateToEpochMillis(strVal, now); ok {
			datePart := trimmed
			if idx := strings.Index(datePart, "||"); idx >= 0 {
				datePart = strings.TrimSpace(datePart[:idx])
			}
			if _, intErr := strconv.ParseInt(datePart, 10, 64); intErr != nil &&
				tzOffsetMs != 0 && !strings.HasPrefix(datePart, "now") &&
				!strings.HasSuffix(datePart, "Z") && !strings.HasSuffix(datePart, "z") &&
				!strings.Contains(datePart[min(10, len(datePart)):], "+") &&
				!strings.Contains(datePart[min(10, len(datePart)):], "-") {
				ms -= tzOffsetMs
			}
			return normalizeDateNanosValue(b.ESType, ms)
		}
		if b.ESType == "date_nanos" {
			if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				return normalizeDateNanosValue(b.ESType, iv)
			}
		}
	}
	if isEpochSecond {
		switch nv := v.(type) {
		case int:
			return int64(nv) * 1000
		case int64:
			return nv * 1000
		case float64:
			return int64(nv * 1000)
		case json.Number:
			if i, err := nv.Int64(); err == nil {
				return i * 1000
			} else if f, err := nv.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return int64(f * 1000)
			}
		}
	}
	return normalizeDateNanosValue(b.ESType, v)
}

func normalizeDateNanosValue(esType string, v any) any {
	if esType != "date_nanos" || v == nil {
		return v
	}
	switch nv := v.(type) {
	case int:
		if int64(nv) > 1_000_000_000_000_000 || int64(nv) < -1_000_000_000_000_000 {
			return int64(nv) / 1_000_000
		}
	case int64:
		if nv > 1_000_000_000_000_000 || nv < -1_000_000_000_000_000 {
			return nv / 1_000_000
		}
	case float64:
		if nv > 1e15 || nv < -1e15 {
			return int64(nv) / 1_000_000
		}
	case json.Number:
		if i, err := nv.Int64(); err == nil && (i > 1_000_000_000_000_000 || i < -1_000_000_000_000_000) {
			return i / 1_000_000
		}
		if f, err := nv.Float64(); err == nil && (f > 1e15 || f < -1e15) {
			return int64(f) / 1_000_000
		}
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(nv), 10, 64); err == nil && (i > 1_000_000_000_000_000 || i < -1_000_000_000_000_000) {
			return i / 1_000_000
		}
	}
	return v
}

func parseIPv4ToUint32(v any) (int64, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return 0, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, false
	}
	return int64(uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])), true
}

func (t *Transpiler) appendBucketScopedSubAggs(
	branches *[]string,
	subIdx *int,
	parentAggName string,
	parentBucketKey string,
	bucketWhere string,
	subAggs map[string]esast.AggSpec,
) {
	t.appendGroupedBucketSubAggs(branches, subIdx, parentAggName, quoteStr(parentBucketKey), "`base_matched`", bucketWhere, subAggs)
}

func normalizeScriptSourceAndParams(script any) (string, map[string]any, bool) {
	if script == nil {
		return "", nil, false
	}
	var scriptMap map[string]any
	switch sc := script.(type) {
	case string:
		scriptMap = map[string]any{"source": sc}
	case map[string]any:
		scriptMap = sc
	default:
		return "", nil, false
	}
	src, _ := scriptMap["source"].(string)
	if src == "" {
		src, _ = scriptMap["inline"].(string)
	}
	s := strings.TrimSpace(src)
	for strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	for strings.HasSuffix(s, ";") {
		s = strings.TrimSpace(strings.TrimSuffix(s, ";"))
	}
	if strings.HasPrefix(s, "return") && (len(s) == 6 || s[6] == ' ' || s[6] == '\t' || s[6] == '(') {
		s = strings.TrimSpace(s[6:])
	}
	for strings.HasSuffix(s, ";") {
		s = strings.TrimSpace(strings.TrimSuffix(s, ";"))
	}
	for hasMatchingThresholdParens(s) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	if s == "" {
		return "", nil, false
	}
	params, _ := scriptMap["params"].(map[string]any)
	return s, params, true
}

func extractSimpleDocFieldFromScript(script any) (string, bool) {
	s, _, ok := normalizeScriptSourceAndParams(script)
	if !ok {
		return "", false
	}
	s = stripLeadingScriptCast(s)
	for hasMatchingThresholdParens(s) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	field, tail, ok := parseDocFieldAccess(s)
	if !ok || (tail != "" && tail != ".value") {
		return "", false
	}
	return field, true
}

func (t *Transpiler) compilePolymorphicScriptExpr(script any, defaultField string, fieldOverrideExpr string, nctx *nestedCtx) (string, bool) {
	s, params, ok := normalizeScriptSourceAndParams(script)
	if !ok {
		return "", false
	}
	sClean := stripLeadingScriptCast(s)
	for hasMatchingThresholdParens(sClean) {
		sClean = strings.TrimSpace(sClean[1 : len(sClean)-1])
	}
	if (sClean == "_value" || sClean == "params._value") && defaultField != "" {
		if fieldOverrideExpr != "" {
			return fieldOverrideExpr, true
		}
		return t.sqlColumnRef(defaultField, true, nctx), true
	}
	if field, tail, ok := parseDocFieldAccess(sClean); ok && (tail == "" || tail == ".value") {
		if fieldOverrideExpr != "" && defaultField != "" && field == defaultField {
			return fieldOverrideExpr, true
		}
		return t.sqlColumnRef(field, true, nctx), true
	}
	if strExpr, isStr, ok := t.parseStringScriptExpr(sClean, params, defaultField, fieldOverrideExpr, nctx, 0); ok && isStr {
		return strExpr, true
	}
	return t.compileMetricScriptExprWithOverride(script, defaultField, fieldOverrideExpr, nctx)
}

func (t *Transpiler) parseStringScriptExpr(s string, params map[string]any, defaultField string, fieldOverrideExpr string, nctx *nestedCtx, depth int) (string, bool, bool) {
	if depth > 16 {
		return "", false, false
	}
	s = stripLeadingScriptCast(s)
	for hasMatchingThresholdParens(s) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	if s == "" {
		return "", false, false
	}
	// Check top-level '+' concatenation outside quotes/parens/brackets
	parenDepth := 0
	var inQuote byte
	var plusParts []string
	lastSplit := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inQuote != 0 {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			inQuote = ch
			continue
		}
		switch ch {
		case '(', '[':
			parenDepth++
		case ')', ']':
			parenDepth--
		case '+':
			if parenDepth == 0 && i > lastSplit && i < len(s)-1 {
				plusParts = append(plusParts, strings.TrimSpace(s[lastSplit:i]))
				lastSplit = i + 1
			}
		}
	}
	if len(plusParts) > 0 {
		plusParts = append(plusParts, strings.TrimSpace(s[lastSplit:]))
		compiledParts := make([]string, 0, len(plusParts))
		hasStringOperand := false
		allOK := true
		for _, part := range plusParts {
			cp, isStr, ok := t.parseStringScriptExpr(part, params, defaultField, fieldOverrideExpr, nctx, depth+1)
			if !ok {
				allOK = false
				break
			}
			if isStr {
				hasStringOperand = true
			}
			compiledParts = append(compiledParts, fmt.Sprintf("CAST(%s AS STRING)", cp))
		}
		if allOK && hasStringOperand {
			return fmt.Sprintf("CONCAT(%s)", strings.Join(compiledParts, ", ")), true, true
		}
	}
	for _, mSpec := range []struct{ suffix, sqlFn string }{
		{".toLowerCase()", "LOWER"},
		{".toUpperCase()", "UPPER"},
		{".trim()", "TRIM"},
	} {
		if strings.HasSuffix(s, mSpec.suffix) {
			recv := strings.TrimSpace(s[:len(s)-len(mSpec.suffix)])
			inner, _, ok := t.parseStringScriptExpr(recv, params, defaultField, fieldOverrideExpr, nctx, depth+1)
			if ok {
				return fmt.Sprintf("%s(CAST(%s AS STRING))", mSpec.sqlFn, inner), true, true
			}
		}
	}
	if len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"')) {
		qChar := s[0]
		innerLit := s[1 : len(s)-1]
		if !strings.ContainsRune(innerLit, rune(qChar)) {
			return quoteStr(innerLit), true, true
		}
	}
	if (s == "_value" || s == "params._value") && defaultField != "" {
		b := t.Schema.ResolveField(defaultField)
		effDT := effectiveDorisScalarType(b)
		isStr := effDT == schema.DorisString || effDT == schema.DorisVarchar
		if fieldOverrideExpr != "" {
			return fieldOverrideExpr, isStr, true
		}
		return t.sqlColumnRef(defaultField, true, nctx), isStr, true
	}
	if field, tail, ok := parseDocFieldAccess(s); ok && (tail == "" || tail == ".value") {
		b := t.Schema.ResolveField(field)
		effDT := effectiveDorisScalarType(b)
		isStr := effDT == schema.DorisString || effDT == schema.DorisVarchar || b.Kind == schema.StorageDynamicVariant || fieldOverrideExpr == "`_elem`"
		if fieldOverrideExpr != "" && defaultField != "" && field == defaultField {
			return fieldOverrideExpr, isStr, true
		}
		return t.sqlColumnRef(field, true, nctx), isStr, true
	}
	if paramKey, ok := parseScriptParamKey(s); ok {
		if params != nil {
			if rawVal, exists := params[paramKey]; exists {
				if strVal, ok := rawVal.(string); ok {
					return quoteStr(strVal), true, true
				}
				if fv, ok := resolveHistogramMissingFloat(rawVal); ok {
					return strconv.FormatFloat(fv, 'f', -1, 64), false, true
				}
			}
		}
	}
	return "", false, false
}

func (t *Transpiler) compileMetricScriptExpr(script any, defaultField string, nctx *nestedCtx) (string, bool) {
	return t.compileMetricScriptExprWithOverride(script, defaultField, "", nctx)
}

func (t *Transpiler) compileMetricScriptExprWithOverride(script any, defaultField string, fieldOverrideExpr string, nctx *nestedCtx) (string, bool) {
	s, params, ok := normalizeScriptSourceAndParams(script)
	if !ok {
		return "", false
	}
	compiled, ok := t.parseMetricScriptExpr(s, params, defaultField, fieldOverrideExpr, nctx, 0)
	if !ok || compiled == "" {
		return "", false
	}
	return fmt.Sprintf("CAST(%s AS DOUBLE)", compiled), true
}

func stripLeadingScriptCast(s string) string {
	s = strings.TrimSpace(s)
	for _, castPrefix := range []string{"(double)", "(float)", "(long)", "(int)", "(short)", "(byte)", "(String)", "(def)"} {
		if len(s) > len(castPrefix) && strings.EqualFold(s[:len(castPrefix)], castPrefix) {
			s = strings.TrimSpace(s[len(castPrefix):])
		}
	}
	return s
}

func parseDocFieldAccess(s string) (string, string, bool) {
	for _, quote := range []string{"'", `"`} {
		prefix := "doc[" + quote
		suffix := quote + "]"
		if strings.HasPrefix(s, prefix) {
			rest := s[len(prefix):]
			end := strings.Index(rest, suffix)
			if end > 0 {
				field := rest[:end]
				tail := strings.TrimSpace(rest[end+len(suffix):])
				return field, tail, true
			}
		}
	}
	return "", "", false
}

func parseScriptParamKey(s string) (string, bool) {
	if strings.HasPrefix(s, "params.") {
		return s[len("params."):], true
	}
	for _, quote := range []string{"'", `"`} {
		prefix := "params[" + quote
		suffix := quote + "]"
		if strings.HasPrefix(s, prefix) && strings.HasSuffix(s, suffix) {
			key := s[len(prefix) : len(s)-len(suffix)]
			if key != "" {
				return key, true
			}
		}
	}
	return "", false
}

func (t *Transpiler) parseMetricScriptExpr(s string, params map[string]any, defaultField string, fieldOverrideExpr string, nctx *nestedCtx, depth int) (string, bool) {
	if depth > 16 {
		return "", false
	}
	s = stripLeadingScriptCast(s)
	if s == "" {
		return "", false
	}
	if hasMatchingThresholdParens(s) {
		inner, ok := t.parseMetricScriptExpr(s[1:len(s)-1], params, defaultField, fieldOverrideExpr, nctx, depth+1)
		if !ok {
			return "", false
		}
		return "(" + inner + ")", true
	}
	for _, ops := range []string{"+-", "*/%"} {
		parenDepth := 0
		var inQuote byte
		for i := len(s) - 1; i > 0; i-- {
			ch := s[i]
			if inQuote != 0 {
				if ch == inQuote {
					inQuote = 0
				}
				continue
			}
			if ch == '\'' || ch == '"' {
				inQuote = ch
				continue
			}
			switch ch {
			case ')', ']':
				parenDepth++
			case '(', '[':
				parenDepth--
			default:
				if parenDepth == 0 && strings.IndexByte(ops, ch) >= 0 {
					lhs, ok1 := t.parseMetricScriptExpr(s[:i], params, defaultField, fieldOverrideExpr, nctx, depth+1)
					rhs, ok2 := t.parseMetricScriptExpr(s[i+1:], params, defaultField, fieldOverrideExpr, nctx, depth+1)
					if ok1 && ok2 {
						return fmt.Sprintf("(%s %c %s)", lhs, ch, rhs), true
					}
				}
			}
		}
	}
	if strings.HasPrefix(s, "+") {
		return t.parseMetricScriptExpr(s[1:], params, defaultField, fieldOverrideExpr, nctx, depth+1)
	}
	if strings.HasPrefix(s, "-") {
		inner, ok := t.parseMetricScriptExpr(s[1:], params, defaultField, fieldOverrideExpr, nctx, depth+1)
		if ok {
			return "(-" + inner + ")", true
		}
	}
	for _, fnSpec := range []struct{ prefix, sqlFn string }{
		{"Math.min(", "LEAST"},
		{"Math.max(", "GREATEST"},
		{"Math.pow(", "POW"},
		{"LEAST(", "LEAST"},
		{"GREATEST(", "GREATEST"},
		{"POW(", "POW"},
	} {
		if strings.HasPrefix(s, fnSpec.prefix) && strings.HasSuffix(s, ")") {
			inner := s[len(fnSpec.prefix) : len(s)-1]
			a1, a2, ok := splitTwoThresholdArgs(inner)
			if !ok {
				return "", false
			}
			c1, ok1 := t.parseMetricScriptExpr(a1, params, defaultField, fieldOverrideExpr, nctx, depth+1)
			c2, ok2 := t.parseMetricScriptExpr(a2, params, defaultField, fieldOverrideExpr, nctx, depth+1)
			if !ok1 || !ok2 {
				return "", false
			}
			return fmt.Sprintf("%s(%s, %s)", fnSpec.sqlFn, c1, c2), true
		}
	}
	for _, fnSpec := range []struct{ prefix, sqlFn string }{
		{"Math.floor(", "FLOOR"},
		{"Math.ceil(", "CEIL"},
		{"Math.abs(", "ABS"},
		{"Math.round(", "ROUND"},
		{"Math.sqrt(", "SQRT"},
		{"Math.log(", "LN"},
		{"Math.log10(", "LOG10"},
		{"Math.exp(", "EXP"},
	} {
		if strings.HasPrefix(s, fnSpec.prefix) && strings.HasSuffix(s, ")") {
			inner := s[len(fnSpec.prefix) : len(s)-1]
			c1, ok1 := t.parseMetricScriptExpr(inner, params, defaultField, fieldOverrideExpr, nctx, depth+1)
			if !ok1 {
				return "", false
			}
			return fmt.Sprintf("%s(%s)", fnSpec.sqlFn, c1), true
		}
	}
	if field, tail, ok := parseDocFieldAccess(s); ok {
		if tail != "" && tail != ".value" && tail != ".size()" && tail != ".length" {
			return "", false
		}
		b := t.Schema.ResolveField(field)
		if tail == ".size()" || tail == ".length" {
			if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) {
				colName := b.EffectiveArrayColumn(true)
				if colName != "" {
					return fmt.Sprintf("COALESCE(array_size(`%s`), 0)", colName), true
				}
			}
			colRef := t.sqlColumnRef(field, true, nctx)
			return fmt.Sprintf("(CASE WHEN %s IS NOT NULL THEN 1 ELSE 0 END)", colRef), true
		}
		if fieldOverrideExpr != "" && defaultField != "" && field == defaultField {
			return fieldOverrideExpr, true
		}
		return t.sqlNumericColumnRef(field, nctx), true
	}
	if (s == "_value" || s == "params._value") && defaultField != "" {
		if fieldOverrideExpr != "" {
			return fieldOverrideExpr, true
		}
		return t.sqlNumericColumnRef(defaultField, nctx), true
	}
	if key, ok := parseScriptParamKey(s); ok {
		if pv, ok := params[key]; ok {
			switch v := pv.(type) {
			case int:
				return strconv.Itoa(v), true
			case int64:
				return strconv.FormatInt(v, 10), true
			case float64:
				if !math.IsNaN(v) && !math.IsInf(v, 0) {
					if v == math.Trunc(v) {
						return strconv.FormatInt(int64(v), 10), true
					}
					return strconv.FormatFloat(v, 'f', -1, 64), true
				}
			case json.Number:
				if i, err := v.Int64(); err == nil {
					return strconv.FormatInt(i, 10), true
				}
				if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					return strconv.FormatFloat(f, 'f', -1, 64), true
				}
			}
		}
		return "", false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return strconv.Itoa(n), true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
		return strconv.FormatFloat(f, 'f', -1, 64), true
	}
	return "", false
}

func (t *Transpiler) appendMetricAggBranchWithMissingAndScript(branches *[]string, fullAggName, sqlFunc, field, extraWhere string, missing any, script any) {
	effField := field
	if effField == "" && script != nil {
		if docF, ok := extractSimpleDocFieldFromScript(script); ok {
			effField = docF
		}
	}
	b := t.Schema.ResolveField(effField)
	if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := b.EffectiveArrayColumn(true)
		wherePrefix := ""
		if extraWhere != "" {
			wherePrefix = fmt.Sprintf("(%s) AND ", extraWhere)
		}
		valExpr := "CAST(`_nel` AS DOUBLE)"
		explodeExpr := fmt.Sprintf("`%s`", arrCol)
		wClause := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
		if missing != nil {
			if mf, ok := resolveHistogramMissingFloat(missing); ok {
				valExpr = fmt.Sprintf("COALESCE(CAST(`_nel` AS DOUBLE), %s)", strconv.FormatFloat(mf, 'f', -1, 64))
				explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END", arrCol, arrCol, arrCol)
				wClause = ""
				if extraWhere != "" {
					wClause = " WHERE " + extraWhere
				}
			}
		}
		if script != nil {
			if scriptExpr, ok := t.compileMetricScriptExprWithOverride(script, effField, valExpr, nil); ok {
				valExpr = scriptExpr
			}
		}
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
				"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_nt` AS `_nel`%s",
			quoteStr(fullAggName), sqlFunc, valExpr, explodeExpr, wClause,
		))
		return
	}
	col := t.sqlNumericColumnRef(effField, nil)
	if missing != nil && effField != "" {
		if mf, ok := resolveHistogramMissingFloat(missing); ok {
			col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
		}
	}
	if script != nil {
		overrideExpr := ""
		if effField != "" {
			overrideExpr = col
		}
		if scriptExpr, ok := t.compileMetricScriptExprWithOverride(script, effField, overrideExpr, nil); ok {
			col = scriptExpr
		}
	}
	if missing != nil && effField == "" {
		if mf, ok := resolveHistogramMissingFloat(missing); ok {
			col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
		}
	}
	wClause := ""
	if extraWhere != "" {
		wClause = " WHERE " + extraWhere
	}
	*branches = append(*branches, fmt.Sprintf(
		"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
			"FROM `base_matched`%s",
		quoteStr(fullAggName), sqlFunc, col, wClause,
	))
}

func (t *Transpiler) compileTermsSetScriptThreshold(script map[string]any, numTerms int, nctx *nestedCtx) string {
	src, _ := script["source"].(string)
	if src == "" {
		src, _ = script["inline"].(string)
	}
	s := strings.TrimSpace(src)
	for strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	for strings.HasSuffix(s, ";") {
		s = strings.TrimSpace(strings.TrimSuffix(s, ";"))
	}
	if strings.HasPrefix(s, "return") && (len(s) == 6 || s[6] == ' ' || s[6] == '\t' || s[6] == '(') {
		s = strings.TrimSpace(s[6:])
	}
	for strings.HasSuffix(s, ";") {
		s = strings.TrimSpace(strings.TrimSuffix(s, ";"))
	}
	if s == "" {
		return "1"
	}
	params, _ := script["params"].(map[string]any)
	compiled, ok := t.parseSafeThresholdExpr(s, params, numTerms, nctx, 0)
	if !ok || compiled == "" {
		return "1"
	}
	return compiled
}

func hasMatchingThresholdParens(s string) bool {
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return false
	}
	depth := 0
	var inQuote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inQuote != 0 {
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			inQuote = ch
			continue
		}
		switch ch {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
			if depth == 0 && i < len(s)-1 {
				return false
			}
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && inQuote == 0
}

func (t *Transpiler) parseSafeThresholdExpr(s string, params map[string]any, numTerms int, nctx *nestedCtx, depth int) (string, bool) {
	if depth > 16 {
		return "", false
	}
	s = stripLeadingScriptCast(s)
	if s == "" {
		return "", false
	}
	if hasMatchingThresholdParens(s) {
		inner, ok := t.parseSafeThresholdExpr(s[1:len(s)-1], params, numTerms, nctx, depth+1)
		if !ok {
			return "", false
		}
		return "(" + inner + ")", true
	}
	for _, ops := range []string{"+-", "*/%"} {
		parenDepth := 0
		var inQuote byte
		for i := len(s) - 1; i > 0; i-- {
			ch := s[i]
			if inQuote != 0 {
				if ch == inQuote {
					inQuote = 0
				}
				continue
			}
			if ch == '\'' || ch == '"' {
				inQuote = ch
				continue
			}
			switch ch {
			case ')', ']':
				parenDepth++
			case '(', '[':
				parenDepth--
			default:
				if parenDepth == 0 && strings.IndexByte(ops, ch) >= 0 {
					lhs, ok1 := t.parseSafeThresholdExpr(s[:i], params, numTerms, nctx, depth+1)
					rhs, ok2 := t.parseSafeThresholdExpr(s[i+1:], params, numTerms, nctx, depth+1)
					if ok1 && ok2 {
						return fmt.Sprintf("(%s %c %s)", lhs, ch, rhs), true
					}
				}
			}
		}
	}
	if strings.HasPrefix(s, "+") {
		return t.parseSafeThresholdExpr(s[1:], params, numTerms, nctx, depth+1)
	}
	if strings.HasPrefix(s, "-") {
		inner, ok := t.parseSafeThresholdExpr(s[1:], params, numTerms, nctx, depth+1)
		if ok {
			return "(-" + inner + ")", true
		}
	}
	for _, fnSpec := range []struct{ prefix, sqlFn string }{
		{"Math.min(", "LEAST"},
		{"Math.max(", "GREATEST"},
		{"Math.pow(", "POW"},
		{"LEAST(", "LEAST"},
		{"GREATEST(", "GREATEST"},
		{"POW(", "POW"},
	} {
		if strings.HasPrefix(s, fnSpec.prefix) && strings.HasSuffix(s, ")") {
			inner := s[len(fnSpec.prefix) : len(s)-1]
			a1, a2, ok := splitTwoThresholdArgs(inner)
			if !ok {
				return "", false
			}
			c1, ok1 := t.parseSafeThresholdExpr(a1, params, numTerms, nctx, depth+1)
			c2, ok2 := t.parseSafeThresholdExpr(a2, params, numTerms, nctx, depth+1)
			if !ok1 || !ok2 {
				return "", false
			}
			return fmt.Sprintf("%s(%s, %s)", fnSpec.sqlFn, c1, c2), true
		}
	}
	for _, fnSpec := range []struct{ prefix, sqlFn string }{
		{"Math.floor(", "FLOOR"},
		{"Math.ceil(", "CEIL"},
		{"Math.abs(", "ABS"},
		{"Math.round(", "ROUND"},
		{"Math.sqrt(", "SQRT"},
		{"Math.log(", "LN"},
		{"Math.log10(", "LOG10"},
		{"Math.exp(", "EXP"},
	} {
		if strings.HasPrefix(s, fnSpec.prefix) && strings.HasSuffix(s, ")") {
			inner := s[len(fnSpec.prefix) : len(s)-1]
			c1, ok1 := t.parseSafeThresholdExpr(inner, params, numTerms, nctx, depth+1)
			if !ok1 {
				return "", false
			}
			return fmt.Sprintf("%s(%s)", fnSpec.sqlFn, c1), true
		}
	}
	if field, tail, ok := parseDocFieldAccess(s); ok {
		if tail != "" && tail != ".value" && tail != ".size()" && tail != ".length" {
			return "", false
		}
		b := t.Schema.ResolveField(field)
		if (tail == ".size()" || tail == ".length") && (b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && nctx == nil)) {
			colName := b.EffectiveArrayColumn(true)
			if colName != "" {
				return fmt.Sprintf("COALESCE(array_size(`%s`), 0)", colName), true
			}
		}
		return fmt.Sprintf("COALESCE(%s, 1)", t.sqlColumnRef(field, true, nctx)), true
	}
	if s == "params.num_terms" {
		if numTerms > 0 {
			return strconv.Itoa(numTerms), true
		}
		return "1", true
	}
	if key, ok := parseScriptParamKey(s); ok {
		if key == "num_terms" {
			if numTerms > 0 {
				return strconv.Itoa(numTerms), true
			}
			return "1", true
		}
		if pv, ok := params[key]; ok {
			switch v := pv.(type) {
			case int:
				return strconv.Itoa(v), true
			case int64:
				return strconv.FormatInt(v, 10), true
			case float64:
				if !math.IsNaN(v) && !math.IsInf(v, 0) {
					if v == math.Trunc(v) {
						return strconv.FormatInt(int64(v), 10), true
					}
					return strconv.FormatFloat(v, 'f', -1, 64), true
				}
			case json.Number:
				if i, err := v.Int64(); err == nil {
					return strconv.FormatInt(i, 10), true
				}
				if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					return strconv.FormatFloat(f, 'f', -1, 64), true
				}
			}
		}
		return "", false
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return strconv.Itoa(n), true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 {
		return strconv.FormatFloat(f, 'f', -1, 64), true
	}
	return "", false
}

func splitTwoThresholdArgs(s string) (string, string, bool) {
	parenDepth := 0
	var inQuote byte
	commaIdx := -1
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inQuote != 0 {
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			inQuote = ch
			continue
		}
		switch ch {
		case '(', '[':
			parenDepth++
		case ')', ']':
			parenDepth--
			if parenDepth < 0 {
				return "", "", false
			}
		case ',':
			if parenDepth == 0 {
				if commaIdx >= 0 {
					return "", "", false
				}
				commaIdx = i
			}
		}
	}
	if parenDepth != 0 || inQuote != 0 || commaIdx <= 0 || commaIdx >= len(s)-1 {
		return "", "", false
	}
	return s[:commaIdx], s[commaIdx+1:], true
}

func sampleValForSortType(sortType string) any {
	switch strings.ToLower(strings.TrimSpace(sortType)) {
	case "long", "integer", "short", "byte", "date", "date_nanos":
		return int64(1)
	case "double", "float", "half_float", "scaled_float", "number":
		return float64(0.5)
	case "boolean":
		return true
	case "keyword", "text", "string":
		return ""
	}
	return nil
}

func effectiveSortESType(b schema.FieldBinding, sortType string) string {
	st := strings.ToLower(strings.TrimSpace(sortType))
	if st == "date_nanos" || b.ESType == "date_nanos" {
		return "date_nanos"
	}
	if st == "date" || b.ESType == "date" {
		return "date"
	}
	if st == "ip" || b.ESType == "ip" {
		return "ip"
	}
	if b.ESType != "" {
		return b.ESType
	}
	return st
}

func (t *Transpiler) compileOrderBy(sorts []esast.SortSpec) string {
	return t.compileOrderByWithAfter(sorts, nil)
}

func (t *Transpiler) resolveSortMissing(s esast.SortSpec, b schema.FieldBinding) (any, string) {
	if s.Entry.Missing == "" || strings.EqualFold(s.Entry.Missing, "_last") || strings.EqualFold(s.Entry.Missing, "_first") {
		return nil, ""
	}
	mStr := strings.TrimSpace(s.Entry.Missing)
	effType := effectiveSortESType(b, s.Entry.Type)
	if effType == "ip" {
		if n, ok := parseIPv4ToUint32(mStr); ok {
			return n, strconv.FormatInt(n, 10)
		}
	}
	if b.DorisType == schema.DorisBigInt || effType == "date" || effType == "date_nanos" {
		if ms, ok := schema.ParseESDateToEpochMillis(mStr, time.Now().UTC()); ok {
			if niv, ok := normalizeDateNanosValue(effType, ms).(int64); ok {
				ms = niv
			}
			return ms, strconv.FormatInt(ms, 10)
		}
	}
	if iv, err := strconv.ParseInt(mStr, 10, 64); err == nil {
		norm := normalizeDateNanosValue(effType, iv)
		if niv, ok := norm.(int64); ok {
			return niv, strconv.FormatInt(niv, 10)
		}
		return iv, strconv.FormatInt(iv, 10)
	}
	if fv, err := strconv.ParseFloat(mStr, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
		return fv, strconv.FormatFloat(fv, 'f', -1, 64)
	}
	if b.EffectiveLowercase(true) {
		mStr = strings.ToLower(mStr)
	}
	return mStr, quoteStr(mStr)
}

func (t *Transpiler) compileScriptSortExpr(s esast.SortSpec) (string, schema.FieldBinding, bool) {
	if strings.EqualFold(s.Entry.Type, "string") {
		if scriptExpr, ok := t.compilePolymorphicScriptExpr(s.Entry.Script, "", "", nil); ok {
			return fmt.Sprintf("CAST(%s AS STRING)", scriptExpr), schema.FieldBinding{DorisType: schema.DorisString, ESType: "keyword"}, true
		}
		return "", schema.FieldBinding{}, false
	}
	if scriptExpr, ok := t.compileMetricScriptExpr(s.Entry.Script, "", nil); ok {
		return scriptExpr, schema.FieldBinding{DorisType: schema.DorisDouble}, true
	}
	return "", schema.FieldBinding{}, false
}

// EffectiveSortsForRequest returns the effective sort specifications for a search request,
// automatically appending an `_id` tiebreaker sort when `pit` (Point-In-Time) is active.
func EffectiveSortsForRequest(req *esast.SearchRequest) []esast.SortSpec {
	if req == nil {
		return nil
	}
	if req.PIT == nil {
		return req.Sort
	}
	if len(req.Sort) == 0 {
		return []esast.SortSpec{
			{Entry: esast.SortFieldSpec{Field: "_score", Order: "desc"}},
			{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}},
		}
	}
	for _, s := range req.Sort {
		if s.Entry.Field == "_id" || s.Entry.Field == "_doc" {
			return req.Sort
		}
	}
	out := make([]esast.SortSpec, len(req.Sort), len(req.Sort)+1)
	copy(out, req.Sort)
	out = append(out, esast.SortSpec{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}})
	return out
}

func (t *Transpiler) compileOrderByWithAfter(sorts []esast.SortSpec, after []any) string {
	if len(sorts) == 0 {
		return "`_score` DESC, `_id` ASC"
	}
	var parts []string
	afterIdx := 0
	for _, s := range sorts {
		if s.Entry.Field == "" {
			continue
		}
		if s.Entry.Field == "_geo_distance" {
			afterIdx++
			continue
		}
		dir := "ASC"
		if strings.EqualFold(s.Entry.Order, "desc") {
			dir = "DESC"
		}
		if s.Entry.Field == "_script" {
			if scriptExpr, sb, ok := t.compileScriptSortExpr(s); ok {
				_, missingSQL := t.resolveSortMissing(s, sb)
				if missingSQL != "" {
					scriptExpr = fmt.Sprintf("COALESCE(%s, %s)", scriptExpr, missingSQL)
				}
				orderPart := scriptExpr + " " + dir
				if strings.EqualFold(s.Entry.Missing, "_first") {
					orderPart += " NULLS FIRST"
				} else if missingSQL == "" && (strings.EqualFold(s.Entry.Missing, "_last") || dir == "ASC") {
					orderPart += " NULLS LAST"
				}
				parts = append(parts, orderPart)
			}
			afterIdx++
			continue
		}
		switch s.Entry.Field {
		case "_score":
			parts = append(parts, "`_score` "+dir)
		case "_id", "_doc":
			parts = append(parts, "`_id` "+dir)
		default:
			b := t.Schema.ResolveField(s.Entry.Field)
			effType := effectiveSortESType(b, s.Entry.Type)
			sampleVal, missingSQL := t.resolveSortMissing(s, b)
			if sampleVal == nil && s.Entry.Type != "" {
				sampleVal = sampleValForSortType(s.Entry.Type)
			}
			if afterIdx < len(after) && after[afterIdx] != nil {
				sampleVal = after[afterIdx]
				if strVal, ok := sampleVal.(string); ok {
					if b.DorisType == schema.DorisBigInt || effType == "date" || effType == "date_nanos" {
						if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
							sampleVal = ms
						}
					}
				}
				sampleVal = normalizeDateNanosValue(effType, sampleVal)
			}
			col := t.sqlSortColumnRef(s.Entry.Field, sampleVal, dir == "DESC", s.Entry.Mode, s.Entry.Nested)
			if missingSQL != "" {
				col = fmt.Sprintf("COALESCE(%s, %s)", col, missingSQL)
			}
			orderPart := col + " " + dir
			if strings.EqualFold(s.Entry.Missing, "_first") {
				orderPart += " NULLS FIRST"
			} else if missingSQL == "" && (strings.EqualFold(s.Entry.Missing, "_last") || dir == "ASC") {
				orderPart += " NULLS LAST"
			}
			parts = append(parts, orderPart)
		}
		afterIdx++
	}
	if len(parts) == 0 {
		return "`_score` DESC, `_id` ASC"
	}
	return strings.Join(parts, ", ")
}

func (t *Transpiler) compileSearchAfterPredicate(sorts []esast.SortSpec, after []any, scoreExpr string) string {
	var effectiveSorts []esast.SortSpec
	for _, s := range sorts {
		if s.Entry.Field == "_geo_distance" {
			break
		}
		if s.Entry.Field == "_script" {
			if _, _, ok := t.compileScriptSortExpr(s); !ok {
				break
			}
		}
		if s.Entry.Field != "" {
			effectiveSorts = append(effectiveSorts, s)
		}
	}
	if len(sorts) == 0 {
		effectiveSorts = []esast.SortSpec{
			{Entry: esast.SortFieldSpec{Field: "_score", Order: "desc"}},
			{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}},
		}
	}
	n := len(effectiveSorts)
	if len(after) < n {
		n = len(after)
	}
	if n == 0 {
		return "TRUE"
	}

	sortExpr := func(idx int) (string, any, bool, any) {
		field := effectiveSorts[idx].Entry.Field
		val := after[idx]
		desc := strings.EqualFold(effectiveSorts[idx].Entry.Order, "desc")
		switch field {
		case "_score":
			return fmt.Sprintf("CAST(%s AS DOUBLE)", scoreExpr), val, true, nil
		case "_id", "_doc":
			return "`_id`", val, true, nil
		case "_script":
			scriptExpr, sb, _ := t.compileScriptSortExpr(effectiveSorts[idx])
			missSample, missingSQL := t.resolveSortMissing(effectiveSorts[idx], sb)
			if missingSQL != "" {
				scriptExpr = fmt.Sprintf("COALESCE(%s, %s)", scriptExpr, missingSQL)
			}
			return scriptExpr, val, missingSQL != "", missSample
		default:
			b := t.Schema.ResolveField(field)
			effType := effectiveSortESType(b, effectiveSorts[idx].Entry.Type)
			missSample, missingSQL := t.resolveSortMissing(effectiveSorts[idx], b)
			if effType == "ip" {
				if n, ok := parseIPv4ToUint32(val); ok {
					val = n
				}
			} else if strVal, ok := val.(string); ok {
				if b.EffectiveLowercase(true) && effType != "date" && effType != "date_nanos" {
					val = strings.ToLower(strVal)
				} else if b.DorisType == schema.DorisBigInt || effType == "date" || effType == "date_nanos" {
					if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
						val = ms
					}
				}
			}
			val = normalizeDateNanosValue(effType, val)
			sampleForCol := val
			if sampleForCol == nil {
				sampleForCol = missSample
			}
			if sampleForCol == nil && effectiveSorts[idx].Entry.Type != "" {
				sampleForCol = sampleValForSortType(effectiveSorts[idx].Entry.Type)
			}
			col := t.sqlSortColumnRef(field, sampleForCol, desc, effectiveSorts[idx].Entry.Mode, effectiveSorts[idx].Entry.Nested)
			if missingSQL != "" {
				col = fmt.Sprintf("COALESCE(%s, %s)", col, missingSQL)
			}
			return col, val, missingSQL != "", missSample
		}
	}

	var disjuncts []string
	for i := 0; i < n; i++ {
		var conjuncts []string
		for j := 0; j < i; j++ {
			colJ, valJ, hasCoalesceJ, missSampleJ := sortExpr(j)
			if valJ == nil {
				if hasCoalesceJ && missSampleJ != nil {
					conjuncts = append(conjuncts, fmt.Sprintf("%s = %s", colJ, quoteValue(missSampleJ)))
				} else {
					conjuncts = append(conjuncts, fmt.Sprintf("%s IS NULL", colJ))
				}
			} else {
				conjuncts = append(conjuncts, fmt.Sprintf("%s = %s", colJ, quoteValue(valJ)))
			}
		}
		colI, valI, hasCoalesce, _ := sortExpr(i)
		missingFirst := strings.EqualFold(effectiveSorts[i].Entry.Missing, "_first")
		if valI == nil {
			if !missingFirst {
				conjuncts = append(conjuncts, "FALSE")
			} else {
				conjuncts = append(conjuncts, fmt.Sprintf("%s IS NOT NULL", colI))
			}
		} else {
			op := ">"
			if strings.EqualFold(effectiveSorts[i].Entry.Order, "desc") {
				op = "<"
			}
			if !missingFirst && !hasCoalesce && effectiveSorts[i].Entry.Field != "_score" && effectiveSorts[i].Entry.Field != "_id" && effectiveSorts[i].Entry.Field != "_doc" {
				conjuncts = append(conjuncts, fmt.Sprintf("(%s %s %s OR %s IS NULL)", colI, op, quoteValue(valI), colI))
			} else {
				conjuncts = append(conjuncts, fmt.Sprintf("%s %s %s", colI, op, quoteValue(valI)))
			}
		}
		if len(conjuncts) == 1 {
			disjuncts = append(disjuncts, conjuncts[0])
		} else {
			disjuncts = append(disjuncts, "("+strings.Join(conjuncts, " AND ")+")")
		}
	}
	return strings.Join(disjuncts, " OR ")
}

func (t *Transpiler) sqlSortColumnRef(field string, sampleVal any, desc bool, mode string, nested *esast.NestedSortSpec) string {
	b := t.Schema.ResolveField(field)
	resolveArraySortFn := func() string {
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "avg":
			return "array_avg"
		case "sum":
			return "array_sum"
		case "median":
			return "array_median"
		case "max":
			return "array_max"
		case "min":
			return "array_min"
		default:
			if desc {
				return "array_max"
			}
			return "array_min"
		}
	}
	formatArraySortExpr := func(arrRef string) string {
		fn := resolveArraySortFn()
		if b.ESType == "ip" {
			return fmt.Sprintf("%s(array_map(_x -> IPV4_STRING_TO_NUM_OR_NULL(_x), %s))", fn, arrRef)
		}
		effDT := effectiveDorisScalarType(b)
		switch fn {
		case "array_min", "array_max":
			if effDT == schema.DorisBigInt || effDT == schema.DorisInt {
				return fmt.Sprintf("%s(array_map(_x -> CAST(_x AS BIGINT), %s))", fn, arrRef)
			}
			if effDT == schema.DorisDouble {
				return fmt.Sprintf("%s(array_map(_x -> CAST(_x AS DOUBLE), %s))", fn, arrRef)
			}
		case "array_avg", "array_sum", "array_median":
			if effDT == schema.DorisBigInt || effDT == schema.DorisInt {
				return fmt.Sprintf("%s(array_map(_x -> CAST(_x AS BIGINT), %s))", fn, arrRef)
			}
			return fmt.Sprintf("%s(array_map(_x -> CAST(_x AS DOUBLE), %s))", fn, arrRef)
		}
		return fmt.Sprintf("%s(%s)", fn, arrRef)
	}
	switch b.Kind {
	case schema.StoragePromotedArray:
		return formatArraySortExpr(fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true)))
	case schema.StorageNestedSubfield:
		if nested != nil && nested.Filter != nil {
			nestedPath := nested.Path
			if nestedPath == "" {
				nestedPath = b.NestedPath
			}
			corrCol, ok := t.Schema.NestedRoots[nestedPath]
			if !ok {
				corrCol = "n__" + schema.SanitizeDorisIdentifier(nestedPath)
			}
			fCompiled := t.CompileQuery(nested.Filter, false, &nestedCtx{nestedPath: nestedPath, elemVar: "_el"})
			relPath := "$." + strings.TrimSuffix(strings.TrimPrefix(field, nestedPath+"."), ".keyword")
			if len(b.RelativeJSONPath) > 0 {
				relPath = "$." + strings.Join(b.RelativeJSONPath, ".")
			}
			filteredArr := fmt.Sprintf("array_map(_el -> json_extract_string(_el, %s), array_filter(_el -> %s, `%s`))", quoteStr(relPath), fCompiled.WhereSQL, corrCol)
			return formatArraySortExpr(filteredArr)
		}
		colName := b.EffectiveArrayColumn(true)
		if colName != "" {
			return formatArraySortExpr(fmt.Sprintf("`%s`", colName))
		}
	case schema.StoragePromotedVector:
		return fmt.Sprintf("element_at(`%s`, 1)", b.ColumnName)
	}
	if b.ESType == "ip" {
		return fmt.Sprintf("IPV4_STRING_TO_NUM_OR_NULL(%s)", t.sqlColumnRef(field, true, nil))
	}
	return t.sqlTypedColumnRef(field, sampleVal, true, nil)
}

func (t *Transpiler) sqlColumnRef(field string, preferKeyword bool, nctx *nestedCtx) string {
	return t.sqlTypedColumnRef(field, nil, preferKeyword, nctx)
}

func (t *Transpiler) sqlNumericColumnRef(field string, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	switch b.Kind {
	case schema.StoragePromotedScalar:
		if b.DorisType == schema.DorisBigInt || b.DorisType == schema.DorisInt || b.DorisType == schema.DorisDouble {
			return fmt.Sprintf("`%s`", b.ColumnName)
		}
		return fmt.Sprintf("CAST(`%s` AS DOUBLE)", b.ColumnName)
	case schema.StoragePromotedArray, schema.StoragePromotedVector:
		return fmt.Sprintf("CAST(element_at(`%s`, 1) AS DOUBLE)", b.EffectiveArrayColumn(true))
	case schema.StorageNestedSubfield:
		if (nctx == nil || nctx.nestedPath != b.NestedPath) && b.EffectiveArrayColumn(true) != "" {
			return fmt.Sprintf("CAST(element_at(`%s`, 1) AS DOUBLE)", b.EffectiveArrayColumn(true))
		}
	}
	return t.sqlTypedColumnRef(field, float64(0.5), false, nctx)
}

func (t *Transpiler) sqlTypedColumnRef(field string, sampleVal any, preferKeyword bool, nctx *nestedCtx) string {
	if field == "_all_text" || field == "*" {
		return "`_all_text`"
	}
	if field == "_id" || field == "_doc" {
		return "`_id`"
	}
	if field == "_version" {
		return "`_version`"
	}
	if field == "_source" {
		return "`_source`"
	}
	if field == "_index" {
		if t.Schema != nil && t.Schema.IndexName != "" {
			return quoteStr(t.Schema.IndexName)
		}
		if t.Schema != nil && t.Schema.DorisTable != "" {
			return quoteStr(t.Schema.DorisTable)
		}
		return "'_index'"
	}
	castType := "STRING"
	switch v := sampleVal.(type) {
	case int, int64:
		castType = "BIGINT"
	case float64:
		if v == math.Trunc(v) {
			castType = "BIGINT"
		} else {
			castType = "DOUBLE"
		}
	case json.Number:
		if _, err := v.Int64(); err == nil {
			castType = "BIGINT"
		} else {
			castType = "DOUBLE"
		}
	case bool:
		castType = "BOOLEAN"
	}

	b := t.Schema.ResolveField(field)
	if nctx != nil && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(field, nctx.nestedPath+".")) {
		relPath := "$." + strings.TrimSuffix(strings.TrimPrefix(field, nctx.nestedPath+"."), ".keyword")
		if len(b.RelativeJSONPath) > 0 {
			relPath = "$." + strings.Join(b.RelativeJSONPath, ".")
		}
		extractExpr := fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath))
		if castType != "STRING" {
			return fmt.Sprintf("CAST(%s AS %s)", extractExpr, castType)
		}
		return extractExpr
	}

	switch b.Kind {
	case schema.StoragePromotedScalar:
		if preferKeyword && b.KeywordCompanion != "" {
			return fmt.Sprintf("`%s`", b.KeywordCompanion)
		}
		return fmt.Sprintf("`%s`", b.ColumnName)
	case schema.StoragePromotedArray:
		return fmt.Sprintf("`%s`", b.EffectiveArrayColumn(preferKeyword))
	case schema.StoragePromotedVector:
		return fmt.Sprintf("`%s`", b.ColumnName)
	case schema.StorageNestedSubfield:
		if b.PrefilterArrayCol != "" {
			return fmt.Sprintf("`%s`", b.EffectiveArrayColumn(preferKeyword))
		}
	}
	if t.unindexedFields != nil && field != "" && !strings.HasPrefix(field, "_") && !strings.ContainsAny(field, "*?") {
		t.unindexedFields[strings.TrimSuffix(field, ".keyword")] = true
	}
	var pathBuilder strings.Builder
	for _, seg := range b.SourceJSONPath {
		_, _ = fmt.Fprintf(&pathBuilder, "[%s]", quoteStr(seg))
	}
	return fmt.Sprintf("CAST(`_doc`%s AS %s)", pathBuilder.String(), castType)
}

func parseMinShouldMatch(v any, numClauses int, defaultOne bool) int {
	normalizeCount := func(n int) int {
		if n < 0 {
			if numClauses <= 0 {
				return 0
			}
			res := numClauses + n
			if res < 1 {
				return 1
			}
			return res
		}
		return n
	}
	switch val := v.(type) {
	case float64:
		return normalizeCount(int(val))
	case int:
		return normalizeCount(val)
	case json.Number:
		if i, err := val.Int64(); err == nil {
			return normalizeCount(int(i))
		}
	case string:
		s := strings.TrimSpace(val)
		if idx := strings.IndexByte(s, '<'); idx > 0 {
			if thresh, err := strconv.Atoi(strings.TrimSpace(s[:idx])); err == nil {
				if numClauses <= thresh {
					return numClauses
				}
				s = strings.TrimSpace(s[idx+1:])
			}
		}
		if strings.HasSuffix(s, "%") {
			if pct, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64); err == nil && numClauses > 0 {
				if pct < 0 {
					drop := int(math.Floor(float64(numClauses) * (-pct) / 100.0))
					res := numClauses - drop
					if res < 1 {
						res = 1
					}
					return res
				}
				req := int(math.Floor(float64(numClauses) * pct / 100.0))
				if req < 1 && pct > 0 {
					req = 1
				}
				return req
			}
		}
		if n, err := strconv.Atoi(s); err == nil {
			return normalizeCount(n)
		}
	}
	if defaultOne {
		return 1
	}
	return 0
}

func quoteStr(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `''`)
	return "'" + escaped + "'"
}

func quoteValue(v any) string {
	switch val := v.(type) {
	case nil:
		return "NULL"
	case string:
		return quoteStr(val)
	case bool:
		if val {
			return "TRUE"
		}
		return "FALSE"
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return "NULL"
		}
		if val == math.Trunc(val) && val >= math.MinInt64 && val <= math.MaxInt64 {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case json.Number:
		return val.String()
	default:
		return quoteStr(fmt.Sprintf("%v", val))
	}
}

func escapeLikeLiteral(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func wildcardToLike(w string) string {
	var sb strings.Builder
	escaped := false
	for _, r := range w {
		if escaped {
			switch r {
			case '%':
				sb.WriteString(`\%`)
			case '_':
				sb.WriteString(`\_`)
			case '\\':
				sb.WriteString(`\\`)
			default:
				sb.WriteRune(r)
			}
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '*':
			sb.WriteByte('%')
		case '?':
			sb.WriteByte('_')
		case '%':
			sb.WriteString(`\%`)
		case '_':
			sb.WriteString(`\_`)
		default:
			sb.WriteRune(r)
		}
	}
	if escaped {
		sb.WriteString(`\\`)
	}
	return sb.String()
}

func normalizeBooleanQueryValue(val any) (bool, bool) {
	switch v := val.(type) {
	case bool:
		return v, true
	case int:
		return v != 0, true
	case int64:
		return v != 0, true
	case float64:
		return v != 0 && !math.IsNaN(v), true
	case json.Number:
		return v.String() != "0", true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1":
			return true, true
		case "false", "0":
			return false, true
		}
	}
	return false, false
}
