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
		orderBy := t.compileOrderByWithAfter(req.Sort, req.SearchAfter)
		effectiveWhere := postFilterSQL
		if len(req.SearchAfter) > 0 {
			from = 0
			if saPred := t.compileSearchAfterPredicate(req.Sort, req.SearchAfter, scoreExpr); saPred != "" && saPred != "TRUE" {
				if effectiveWhere == "TRUE" {
					effectiveWhere = saPred
				} else {
					effectiveWhere = fmt.Sprintf("(%s) AND (%s)", effectiveWhere, saPred)
				}
			}
		}
		whereClause := fmt.Sprintf("`__DORIS_DELETE_SIGN__` = 0 AND (%s) AND (%s)", mainQ.WhereSQL, effectiveWhere)
		if req.Collapse != nil && req.Collapse.Field != "" {
			collapseCol := t.sqlColumnRef(req.Collapse.Field, true, nil)
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
					"WHERE `_collapse_rn` = 1 "+
					"ORDER BY %s "+
					"LIMIT %d OFFSET %d",
				collapseCol,
				orderBy,
				scoreExpr,
				totalHitsExpr,
				t.Schema.DorisDB,
				t.Schema.DorisTable,
				whereClause,
				orderBy,
				size,
				from,
			)
		} else {
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
		plan.AggsSQL = t.buildAggsCTESQL(mainQ.WhereSQL, postFilterSQL, aggs)
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
			if ts.MinimumShouldMatchField != "" || len(ts.MinimumShouldMatchScript) > 0 {
				if len(ts.Terms) == 0 {
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
			} else {
				preds = append(preds, t.compileTermsPredicate(field, ts.Terms, nctx))
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
	case q.ScriptScore != nil:
		base := CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: "1.0"}
		if q.ScriptScore.Query != nil {
			base = t.CompileQuery(q.ScriptScore.Query, true, nctx)
		}
		if q.ScriptScore.Boost != nil && *q.ScriptScore.Boost != 1.0 {
			base.ScoreSQL = fmt.Sprintf("(%.4f * (%s))", *q.ScriptScore.Boost, base.ScoreSQL)
		}
		return base
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
		for _, field := range keys {
			re := q.Regexp[field]
			if re.Boost != 0 {
				boost = re.Boost
			}
			pat := re.Value
			if re.CaseInsensitive && !strings.HasPrefix(pat, "(?i)") {
				pat = "(?i)" + pat
			}
			b := t.Schema.ResolveField(field)
			if nctx == nil && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				arrPred := fmt.Sprintf("array_exists(_x -> _x REGEXP %s, `%s`)", quoteStr(pat), b.ColumnName)
				preds = append(preds, arrPred)
				safePreds = append(safePreds, arrPred)
				continue
			}
			col := t.sqlColumnRef(field, false, nctx)
			safePred := fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, quoteStr(pat))
			safePreds = append(safePreds, safePred)
			if nctx != nil || re.CaseInsensitive {
				preds = append(preds, fmt.Sprintf("%s REGEXP %s", col, quoteStr(pat)))
			} else {
				preds = append(preds, fmt.Sprintf("%s MATCH_REGEXP %s", col, quoteStr(pat)))
				usesFT = true
			}
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
			qStr := strings.TrimSpace(fmt.Sprintf("%v", me.Query))
			if qStr == "" && strings.EqualFold(me.ZeroTermsQuery, "all") {
				return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: fmt.Sprintf("%.4f", me.Boost)}
			}
			if me.MinimumShouldMatch != nil && !strings.EqualFold(me.Operator, "and") {
				tokens := strings.Fields(qStr)
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
		return t.compileNested(q.Nested, scoring)
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
		negCond := neg.EffectiveSafeWhere()
		scoreSQL = fmt.Sprintf("(%.4f * (%s) * (CASE WHEN %s THEN %.4f ELSE 1.0 END))",
			boost, pos.ScoreSQL, negCond, negBoost)
	}
	return CompiledQuery{
		WhereSQL:          pos.WhereSQL,
		SafeWhereSQL:      pos.EffectiveSafeWhere(),
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: pos.UsesFulltextMatch,
	}
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

	// Non-string promoted scalar columns (BIGINT, INT, DOUBLE, BOOLEAN) use equality instead of MATCH_*
	if b.Kind == schema.StoragePromotedScalar && b.DorisType != schema.DorisString && b.DorisType != schema.DorisVarchar {
		if !isScalarQueryCompatible(b.DorisType, queryVal) {
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
	scorePred := t.projectionSafeTextMatchSQL(field, queryStr, operator, nctx)
	score := "0.0"
	if scoring {
		score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", scorePred, boost)
	}

	// Inside nested `array_exists(_el -> ...)` lambdas, Doris BE does not allow `MATCH_*`.
	if nctx != nil {
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
	if b.Kind == schema.StoragePromotedScalar && b.DorisType != schema.DorisString && b.DorisType != schema.DorisVarchar {
		if !isScalarQueryCompatible(b.DorisType, queryStr) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		pred := t.compileTermPredicate(field, queryStr, false, nctx)
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
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
	if nctx != nil {
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

	if nctx == nil && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		var parts []string
		for _, tok := range tokens {
			likeLit := quoteStr("%" + escapeLikeLiteral(tok) + "%")
			parts = append(parts, fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `%s`)", likeLit, b.ColumnName))
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
	qStr := strings.TrimSpace(fmt.Sprintf("%v", mm.Query))
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
		if (mmType == "best_fields" || mmType == "bool_prefix" || mmType == "phrase" || mmType == "phrase_prefix") && len(scores) > 1 {
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

func (t *Transpiler) compileNested(nq *esast.NestedQuery, scoring bool) CompiledQuery {
	corrCol, ok := t.Schema.NestedRoots[nq.Path]
	if !ok {
		corrCol = "n__" + schema.SanitizeDorisIdentifier(nq.Path)
	}
	inner := t.CompileQuery(&nq.Query, false, &nestedCtx{
		nestedPath: nq.Path,
		elemVar:    "_el",
	})
	prefilter := t.extractNestedPrefilter(nq.Path, &nq.Query)
	whereSQL := fmt.Sprintf("array_exists(_el -> %s, `%s`)", inner.WhereSQL, corrCol)
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
				if entry.CaseInsensitive && !b.LowercaseNormalizer {
					continue
				}
				val := entry.Value
				if strVal, ok := val.(string); ok && b.LowercaseNormalizer {
					val = strings.ToLower(strVal)
				}
				parts = append(parts, fmt.Sprintf("array_contains(`%s`, %s)", b.PrefilterArrayCol, quoteStr(fmt.Sprintf("%v", val))))
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
				var quoted []string
				for _, v := range vals {
					if strVal, ok := v.(string); ok && b.LowercaseNormalizer {
						v = strings.ToLower(strVal)
					}
					quoted = append(quoted, quoteStr(fmt.Sprintf("%v", v)))
				}
				parts = append(parts, fmt.Sprintf("arrays_overlap(`%s`, [%s])", b.PrefilterArrayCol, strings.Join(quoted, ", ")))
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
	if fs.MinScore != nil {
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
	if nctx != nil || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
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
	arrExpr := fmt.Sprintf("array_contains(CAST(`_doc`%s AS ARRAY<STRING>), %s)", pathBuilder.String(), quoteStr(strVal))
	return fmt.Sprintf("(%s OR %s)", basePred, arrExpr)
}

func (t *Transpiler) compileTermPredicate(field string, val any, caseInsensitive bool, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	effLower := b.EffectiveLowercase(true)
	if strVal, ok := val.(string); ok {
		if effLower {
			val = strings.ToLower(strVal)
		} else if b.DorisType == schema.DorisBigInt && b.Kind != schema.StorageNestedSubfield {
			if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
				val = ms
			}
		}
	}
	lit := quoteValue(val)

	switch b.Kind {
	case schema.StoragePromotedArray:
		if caseInsensitive && !effLower {
			return fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), `%s`)", quoteStr(fmt.Sprintf("%v", val)), b.ColumnName)
		}
		return fmt.Sprintf("array_contains(`%s`, %s)", b.ColumnName, quoteStr(fmt.Sprintf("%v", val)))
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
			if caseInsensitive && !effLower {
				return fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), `%s`)", quoteStr(fmt.Sprintf("%v", val)), b.PrefilterArrayCol)
			}
			return fmt.Sprintf("array_contains(`%s`, %s)", b.PrefilterArrayCol, quoteStr(fmt.Sprintf("%v", val)))
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
	quoted := make([]string, 0, len(vals))
	for _, v := range vals {
		if strVal, ok := v.(string); ok {
			if effLower {
				v = strings.ToLower(strVal)
			} else if b.DorisType == schema.DorisBigInt && b.Kind != schema.StorageNestedSubfield {
				if ms, ok := schema.ParseESDateToEpochMillis(strVal, now); ok {
					v = ms
				}
			}
		}
		if isArrayCol {
			quoted = append(quoted, quoteStr(fmt.Sprintf("%v", v)))
		} else {
			quoted = append(quoted, quoteValue(v))
		}
	}
	if isArrayCol {
		return fmt.Sprintf("arrays_overlap(`%s`, [%s])", b.ColumnName, strings.Join(quoted, ", "))
	}
	col := t.sqlTypedColumnRef(field, vals[0], true, nctx)
	if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && effLower {
		col = fmt.Sprintf("lower(%s)", col)
	}
	return fmt.Sprintf("%s IN (%s)", col, strings.Join(quoted, ", "))
}

func (t *Transpiler) compilePrefixPredicate(field, val string, caseInsensitive bool, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	effLower := b.EffectiveLowercase(true)
	if effLower {
		val = strings.ToLower(val)
	}
	likePat := quoteStr(escapeLikeLiteral(val) + "%")
	if (nctx == nil || nctx.nestedPath != b.NestedPath) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `%s`)", likePat, b.ColumnName)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, `%s`)", likePat, b.ColumnName)
	}
	col := t.sqlColumnRef(field, true, nctx)
	if caseInsensitive || (nctx != nil && effLower) {
		return fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likePat)
	}
	return fmt.Sprintf("%s LIKE %s", col, likePat)
}

func (t *Transpiler) compileWildcardPredicate(field, val string, caseInsensitive bool, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	effLower := b.EffectiveLowercase(true)
	if effLower {
		val = strings.ToLower(val)
	}
	likePat := quoteStr(wildcardToLike(val))
	if (nctx == nil || nctx.nestedPath != b.NestedPath) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `%s`)", likePat, b.ColumnName)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, `%s`)", likePat, b.ColumnName)
	}
	col := t.sqlColumnRef(field, true, nctx)
	if caseInsensitive || (nctx != nil && effLower) {
		return fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likePat)
	}
	return fmt.Sprintf("%s LIKE %s", col, likePat)
}

func (t *Transpiler) compileRangePredicate(field string, rc esast.RangeCond, nctx *nestedCtx) string {
	gt, gte, lt, lte := rc.NormalizedBounds()
	b := t.Schema.ResolveField(field)
	now := time.Now().UTC()
	isEpochSecond := strings.EqualFold(rc.Format, "epoch_second")
	tzOffsetMs := esast.ParseTimeZoneOffsetMs(strings.TrimSpace(rc.TimeZone))

	coerceBound := func(v any, roundUp bool) any {
		if v == nil {
			return nil
		}
		if b.Kind != schema.StorageNestedSubfield {
			switch b.DorisType {
			case schema.DorisBigInt:
				if strVal, ok := v.(string); ok {
					trimmed := strings.TrimSpace(strVal)
					if rawSec, err := strconv.ParseFloat(trimmed, 64); err == nil {
						if isEpochSecond {
							return int64(rawSec * 1000)
						}
						return int64(rawSec)
					}
					if ms, ok := schema.ParseESDateBoundToEpochMillis(strVal, now, roundUp); ok {
						if tzOffsetMs != 0 && !strings.HasSuffix(trimmed, "Z") && !strings.HasSuffix(trimmed, "z") && !strings.Contains(trimmed[min(10, len(trimmed)):], "+") && !strings.Contains(trimmed[min(10, len(trimmed)):], "-") {
							ms -= tzOffsetMs
						}
						return ms
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
					if f, err := strconv.ParseFloat(strings.TrimSpace(strVal), 64); err == nil {
						return f
					}
				}
			}
		}
		return v
	}

	gt = coerceBound(gt, false)
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
		return fmt.Sprintf("array_exists(_x -> %s, `%s`)", strings.Join(elemParts, " AND "), b.ColumnName)
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
	if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && nctx == nil) {
		return fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", b.ColumnName, b.ColumnName)
	}
	col := t.sqlColumnRef(field, true, nctx)
	return fmt.Sprintf("%s IS NOT NULL", col)
}

func (t *Transpiler) buildAggsCTESQL(baseWhere, postFilterSQL string, aggs map[string]esast.AggSpec) string {
	var branches []string
	metaWhere := ""
	if postFilterSQL != "" && postFilterSQL != "TRUE" {
		metaWhere = " WHERE " + postFilterSQL
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
		case spec.EffectiveTerms() != nil:
			termsSpec := spec.EffectiveTerms()
			size := t.capBucketSize(termsSpec.Size)
			if termsSpec.Order != nil || termsSpec.Include != nil || termsSpec.Exclude != nil {
				size = t.maxAggBuckets()
			}
			b := t.Schema.ResolveField(termsSpec.Field)
			*subIdx++
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				if termsSpec.Missing != nil {
					missingLit := quoteStr(fmt.Sprintf("%v", termsSpec.Missing))
					coalescedElem := fmt.Sprintf("COALESCE(CAST(`_elem` AS STRING), %s)", missingLit)
					explodeFrom := fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) `_t` AS `_elem`", b.ColumnName, b.ColumnName, b.ColumnName)
					wCond := ""
					if extraWhere != "" {
						wCond = "WHERE " + extraWhere + " "
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
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
						t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, coalescedElem, explodeFrom, subWhere, subAggs)
					}
				} else {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
							"SELECT %s AS `_agg_name`, CAST(`_elem` AS STRING) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem` "+
							"WHERE %s`_elem` IS NOT NULL "+
							"GROUP BY `_elem` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
							") `_agg_sub_%d`",
						quoteStr(fullAggName), b.ColumnName, wherePrefix, size, *subIdx,
					))
					if subAggs := spec.SubAggs(); len(subAggs) > 0 {
						t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, "CAST(`_elem` AS STRING)",
							fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem`", b.ColumnName),
							fmt.Sprintf("%s`_elem` IS NOT NULL", wherePrefix), subAggs)
					}
				}
			} else {
				col := t.sqlColumnRef(termsSpec.Field, true, nil)
				if termsSpec.Missing != nil {
					missingLit := quoteStr(fmt.Sprintf("%v", termsSpec.Missing))
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
							"GROUP BY %s ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
							") `_agg_sub_%d`",
						quoteStr(fullAggName), col, wherePrefix, col, col, size, *subIdx,
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
				case subSpec.EffectiveTerms() != nil:
					subTerms := subSpec.EffectiveTerms()
					size := t.capBucketSize(subTerms.Size)
					if subTerms.Order != nil || subTerms.Include != nil || subTerms.Exclude != nil {
						size = t.maxAggBuckets()
					}
					relJSONPath := nestedRelJSON(subTerms.Field)
					*subIdx++
					if subTerms.Missing != nil {
						missingLit := quoteStr(fmt.Sprintf("%v", subTerms.Missing))
						wCond := ""
						if extraWhere != "" {
							wCond = "WHERE " + extraWhere + " "
						}
						*branches = append(*branches, fmt.Sprintf(
							"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
								"SELECT %s AS `_agg_name`, COALESCE(json_extract_string(`_nel`, %s), %s) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
								"FROM `base_matched` LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN ['{}'] ELSE `%s` END) `_nt` AS `_nel` "+
								"%s"+
								"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
								") `_agg_sub_%d`",
							quoteStr(subFull), relJSONPath, missingLit, corrCol, corrCol, corrCol, wCond, size, *subIdx,
						))
					} else {
						*branches = append(*branches, fmt.Sprintf(
							"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
								"SELECT %s AS `_agg_name`, json_extract_string(`_nel`, %s) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
								"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` "+
								"WHERE %sjson_extract_string(`_nel`, %s) IS NOT NULL "+
								"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
								") `_agg_sub_%d`",
							quoteStr(subFull), relJSONPath, corrCol, wherePrefix, relJSONPath, size, *subIdx,
						))
					}
				case subSpec.Avg != nil, subSpec.Sum != nil, subSpec.Min != nil, subSpec.Max != nil:
					var fn, field string
					switch {
					case subSpec.Avg != nil:
						fn, field = "AVG", subSpec.Avg.Field
					case subSpec.Sum != nil:
						fn, field = "SUM", subSpec.Sum.Field
					case subSpec.Min != nil:
						fn, field = "MIN", subSpec.Min.Field
					case subSpec.Max != nil:
						fn, field = "MAX", subSpec.Max.Field
					}
					relJSONPath := nestedRelJSON(field)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %sjson_extract_string(`_nel`, %s) IS NOT NULL",
						quoteStr(subFull), fn, numExpr, corrCol, wherePrefix, relJSONPath,
					))
				case subSpec.Stats != nil:
					relJSONPath := nestedRelJSON(subSpec.Stats.Field)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					for _, statOp := range []struct{ key, fn string }{
						{"_stats_count", "COUNT"},
						{"_stats_min", "MIN"},
						{"_stats_max", "MAX"},
						{"_stats_avg", "AVG"},
						{"_stats_sum", "SUM"},
					} {
						*branches = append(*branches, fmt.Sprintf(
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
								"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %sjson_extract_string(`_nel`, %s) IS NOT NULL",
							quoteStr(subFull), quoteStr(statOp.key), statOp.fn, numExpr, corrCol, wherePrefix, relJSONPath,
						))
					}
				case subSpec.Cardinality != nil:
					relJSONPath := nestedRelJSON(subSpec.Cardinality.Field)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT json_extract_string(`_nel`, %s)) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %sjson_extract_string(`_nel`, %s) IS NOT NULL",
						quoteStr(subFull), relJSONPath, corrCol, wherePrefix, relJSONPath,
					))
				case subSpec.ValueCount != nil:
					relJSONPath := nestedRelJSON(subSpec.ValueCount.Field)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(json_extract_string(`_nel`, %s)) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %sjson_extract_string(`_nel`, %s) IS NOT NULL",
						quoteStr(subFull), relJSONPath, corrCol, wherePrefix, relJSONPath,
					))
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

		case spec.Filters != nil && len(spec.Filters.Filters) > 0:
			fKeys := make([]string, 0, len(spec.Filters.Filters))
			for fk := range spec.Filters.Filters {
				fKeys = append(fKeys, fk)
			}
			sort.Strings(fKeys)
			for _, fk := range fKeys {
				fq := spec.Filters.Filters[fk]
				cond := t.CompileQuery(&fq, false, nil)
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
			b := t.Schema.ResolveField(spec.Cardinality.Field)
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT `_elem`) AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem` WHERE %s`_elem` IS NOT NULL",
					quoteStr(fullAggName), b.ColumnName, wherePrefix,
				))
			} else {
				col := t.sqlColumnRef(spec.Cardinality.Field, true, nil)
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
			t.appendMetricAggBranch(branches, fullAggName, "AVG", spec.Avg.Field, extraWhere)
		case spec.Sum != nil:
			t.appendMetricAggBranch(branches, fullAggName, "SUM", spec.Sum.Field, extraWhere)
		case spec.Min != nil:
			t.appendMetricAggBranch(branches, fullAggName, "MIN", spec.Min.Field, extraWhere)
		case spec.Max != nil:
			t.appendMetricAggBranch(branches, fullAggName, "MAX", spec.Max.Field, extraWhere)
		case spec.ValueCount != nil:
			t.appendValueCountAggBranch(branches, fullAggName, spec.ValueCount.Field, extraWhere)

		case spec.Stats != nil:
			b := t.Schema.ResolveField(spec.Stats.Field)
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				for _, statOp := range []struct{ key, fn string }{
					{"_stats_count", "COUNT"},
					{"_stats_min", "MIN"},
					{"_stats_max", "MAX"},
					{"_stats_avg", "AVG"},
					{"_stats_sum", "SUM"},
				} {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(CAST(`_nel` AS DOUBLE)), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s`_nel` IS NOT NULL",
						quoteStr(fullAggName), quoteStr(statOp.key), statOp.fn, b.ColumnName, wherePrefix,
					))
				}
			} else {
				col := t.sqlNumericColumnRef(spec.Stats.Field, nil)
				wClause := ""
				if extraWhere != "" {
					wClause = " WHERE " + extraWhere
				}
				for _, statOp := range []struct{ key, fn string }{
					{"_stats_count", "COUNT"},
					{"_stats_min", "MIN"},
					{"_stats_max", "MAX"},
					{"_stats_avg", "AVG"},
					{"_stats_sum", "SUM"},
				} {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched`%s",
						quoteStr(fullAggName), quoteStr(statOp.key), statOp.fn, col, wClause,
					))
				}
			}

		case spec.Percentiles != nil:
			col := t.sqlNumericColumnRef(spec.Percentiles.Field, nil)
			wClause := ""
			if extraWhere != "" {
				wClause = " WHERE " + extraWhere
			}
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
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, %.4f), 0) AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched`%s",
					quoteStr(fullAggName), quoteStr(pctKey), col, q, wClause,
				))
			}

		case spec.DateHistogram != nil:
			intervalMs := spec.DateHistogram.EffectiveIntervalMs()
			tzShiftMs := spec.DateHistogram.EffectiveTimeZoneOffsetMs() - spec.DateHistogram.EffectiveOffsetMs()
			col := t.sqlNumericColumnRef(spec.DateHistogram.Field, nil)
			bucketExpr := fmt.Sprintf("CAST(CAST(FLOOR(%s / %d) * %d AS BIGINT) AS STRING)", col, intervalMs, intervalMs)
			if tzShiftMs != 0 {
				bucketExpr = fmt.Sprintf("CAST(CAST(FLOOR((%s + %d) / %d) * %d - %d AS BIGINT) AS STRING)", col, tzShiftMs, intervalMs, intervalMs, tzShiftMs)
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` "+
					"WHERE %s%s IS NOT NULL "+
					"GROUP BY `_bucket_key` ORDER BY CAST(`_bucket_key` AS BIGINT) ASC"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), bucketExpr, wherePrefix, col, *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, bucketExpr,
					"`base_matched`", fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, col), subAggs)
			}

		case spec.Histogram != nil:
			interval := spec.Histogram.Interval
			if interval <= 0 {
				interval = 1.0
			}
			offset := spec.Histogram.Offset
			col := t.sqlNumericColumnRef(spec.Histogram.Field, nil)
			bucketExpr := fmt.Sprintf("CAST(FLOOR((%s - %v) / %v) * %v + %v AS STRING)", col, offset, interval, interval, offset)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` "+
					"WHERE %s%s IS NOT NULL "+
					"GROUP BY `_bucket_key` ORDER BY CAST(`_bucket_key` AS DOUBLE) ASC"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), bucketExpr, wherePrefix, col, *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, bucketExpr,
					"`base_matched`", fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, col), subAggs)
			}

		case spec.Range != nil || spec.DateRange != nil:
			rngSpec := spec.Range
			if rngSpec == nil {
				rngSpec = spec.DateRange
			}
			col := t.sqlNumericColumnRef(rngSpec.Field, nil)
			for _, rng := range rngSpec.Ranges {
				var conds []string
				conds = append(conds, fmt.Sprintf("%s IS NOT NULL", col))
				if rng.From != nil {
					conds = append(conds, fmt.Sprintf("%s >= %s", col, quoteValue(t.coerceRangeAggBound(rngSpec.Field, rng.From))))
				}
				if rng.To != nil {
					conds = append(conds, fmt.Sprintf("%s < %s", col, quoteValue(t.coerceRangeAggBound(rngSpec.Field, rng.To))))
				}
				rWhere := strings.Join(conds, " AND ")
				if extraWhere != "" {
					rWhere = fmt.Sprintf("(%s) AND (%s)", extraWhere, rWhere)
				}
				bKey := rng.EffectiveKey()
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched` WHERE %s",
					quoteStr(fullAggName), quoteStr(bKey), rWhere,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					t.appendBucketScopedSubAggs(branches, subIdx, fullAggName, bKey, rWhere, subAggs)
				}
			}

		case spec.TopHits != nil:
			size := spec.TopHits.EffectiveSize()
			orderBy := "`_id` ASC"
			if len(spec.TopHits.Sort) > 0 {
				orderBy = t.compileOrderBy(spec.TopHits.Sort)
			}
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
			for _, srcMap := range spec.Composite.Sources {
				srcKeys := sortedMapKeys(srcMap)
				for _, sk := range srcKeys {
					srcSpec := srcMap[sk]
					switch {
					case srcSpec.Terms != nil:
						col := t.sqlColumnRef(srcSpec.Terms.Field, true, nil)
						colExprs = append(colExprs, fmt.Sprintf("CAST(%s AS STRING)", col))
						notNullConds = append(notNullConds, fmt.Sprintf("%s IS NOT NULL", col))
						srcNames = append(srcNames, sk)
					case srcSpec.DateHistogram != nil:
						hasHistogramSrc = true
						intervalMs := srcSpec.DateHistogram.EffectiveIntervalMs()
						tzShiftMs := srcSpec.DateHistogram.EffectiveTimeZoneOffsetMs() - srcSpec.DateHistogram.EffectiveOffsetMs()
						col := t.sqlNumericColumnRef(srcSpec.DateHistogram.Field, nil)
						if tzShiftMs != 0 {
							colExprs = append(colExprs, fmt.Sprintf("CAST(CAST(FLOOR((%s + %d) / %d) * %d - %d AS BIGINT) AS STRING)", col, tzShiftMs, intervalMs, intervalMs, tzShiftMs))
						} else {
							colExprs = append(colExprs, fmt.Sprintf("CAST(CAST(FLOOR(%s / %d) * %d AS BIGINT) AS STRING)", col, intervalMs, intervalMs))
						}
						notNullConds = append(notNullConds, fmt.Sprintf("%s IS NOT NULL", col))
						srcNames = append(srcNames, sk)
					case srcSpec.Histogram != nil:
						hasHistogramSrc = true
						interval := srcSpec.Histogram.Interval
						if interval <= 0 {
							interval = 1.0
						}
						offset := srcSpec.Histogram.Offset
						col := t.sqlNumericColumnRef(srcSpec.Histogram.Field, nil)
						colExprs = append(colExprs, fmt.Sprintf("CAST(FLOOR((%s - %v) / %v) * %v + %v AS STRING)", col, offset, interval, interval, offset))
						notNullConds = append(notNullConds, fmt.Sprintf("%s IS NOT NULL", col))
						srcNames = append(srcNames, sk)
					}
				}
			}
			if len(colExprs) > 0 {
				bucketKeyExpr := colExprs[0]
				if len(colExprs) > 1 {
					bucketKeyExpr = fmt.Sprintf("CONCAT_WS('\\x1f', %s)", strings.Join(colExprs, ", "))
				}
				wCond := strings.Join(notNullConds, " AND ")
				if hasHistogramSrc {
					size = t.capBucketSize(size * 100)
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
						"FROM `base_matched` WHERE %s "+
						"GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(fullAggName), bucketKeyExpr, wCond, size, *subIdx,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, bucketKeyExpr,
						"`base_matched`", wCond, subAggs)
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

func (t *Transpiler) appendValueCountAggBranch(branches *[]string, fullAggName, field, extraWhere string) {
	b := t.Schema.ResolveField(field)
	wherePrefix := ""
	if extraWhere != "" {
		wherePrefix = fmt.Sprintf("(%s) AND ", extraWhere)
	}
	if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(`_elem`) AS DOUBLE) AS `_doc_count` "+
				"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem` WHERE %s`_elem` IS NOT NULL",
			quoteStr(fullAggName), b.ColumnName, wherePrefix,
		))
		return
	}
	col := t.sqlColumnRef(field, true, nil)
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
	subNames := make([]string, 0, len(subAggs))
	for k := range subAggs {
		subNames = append(subNames, k)
	}
	sort.Strings(subNames)

	appendSubNumericMetric := func(subFull, fn, field string) {
		b := t.Schema.ResolveField(field)
		if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
			subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) `_sub_t` AS `_sub_elem`", fromClause, b.ColumnName)
			subWhere := fmt.Sprintf("(%s) AND `_sub_elem` IS NOT NULL", whereClause)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(CAST(`_sub_elem` AS DOUBLE)), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, fn, subFrom, subWhere,
			))
			return
		}
		col := t.sqlNumericColumnRef(field, nil)
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
			appendSubNumericMetric(subFull, "AVG", subSpec.Avg.Field)
		case subSpec.Sum != nil:
			appendSubNumericMetric(subFull, "SUM", subSpec.Sum.Field)
		case subSpec.Min != nil:
			appendSubNumericMetric(subFull, "MIN", subSpec.Min.Field)
		case subSpec.Max != nil:
			appendSubNumericMetric(subFull, "MAX", subSpec.Max.Field)
		case subSpec.ValueCount != nil:
			b := t.Schema.ResolveField(subSpec.ValueCount.Field)
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) `_sub_t` AS `_sub_elem`", fromClause, b.ColumnName)
				subWhere := fmt.Sprintf("(%s) AND `_sub_elem` IS NOT NULL", whereClause)
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_sub_elem`) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), parentBucketExpr, subFrom, subWhere,
				))
			} else {
				col := t.sqlColumnRef(subSpec.ValueCount.Field, true, nil)
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
				))
			}
		case subSpec.Cardinality != nil:
			b := t.Schema.ResolveField(subSpec.Cardinality.Field)
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) `_sub_t` AS `_sub_elem`", fromClause, b.ColumnName)
				subWhere := fmt.Sprintf("(%s) AND `_sub_elem` IS NOT NULL", whereClause)
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT `_sub_elem`) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), parentBucketExpr, subFrom, subWhere,
				))
			} else {
				col := t.sqlColumnRef(subSpec.Cardinality.Field, true, nil)
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT %s) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
				))
			}
		case subSpec.EffectiveTerms() != nil:
			subTerms := subSpec.EffectiveTerms()
			b := t.Schema.ResolveField(subTerms.Field)
			effSubSize := t.capBucketSize(subTerms.Size)
			if subTerms.Order != nil || subTerms.Include != nil || subTerms.Exclude != nil {
				effSubSize = t.maxAggBuckets()
			}
			subLimit := t.capBucketSize(effSubSize * 100)
			*subIdx++
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) `_sub_t` AS `_sub_elem`", fromClause, b.ColumnName)
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, CONCAT(%s, '\\x1f', CAST(`_sub_elem` AS STRING)) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE (%s) AND `_sub_elem` IS NOT NULL "+
						"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(subFull), parentBucketExpr, subFrom, whereClause, subLimit, *subIdx,
				))
			} else {
				col := t.sqlColumnRef(subTerms.Field, true, nil)
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, CONCAT(%s, '\\x1f', CAST(%s AS STRING)) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE (%s) AND %s IS NOT NULL "+
						"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause, col, subLimit, *subIdx,
				))
			}
		case subSpec.TopHits != nil:
			size := subSpec.TopHits.EffectiveSize()
			orderBy := "`_id` ASC"
			if len(subSpec.TopHits.Sort) > 0 {
				orderBy = t.compileOrderBy(subSpec.TopHits.Sort)
			}
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

func (t *Transpiler) coerceRangeAggBound(_ string, v any) any {
	if strVal, ok := v.(string); ok {
		if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
			return ms
		}
	}
	return v
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

func (t *Transpiler) appendMetricAggBranch(branches *[]string, fullAggName, sqlFunc, field, extraWhere string) {
	b := t.Schema.ResolveField(field)
	if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		wherePrefix := ""
		if extraWhere != "" {
			wherePrefix = fmt.Sprintf("(%s) AND ", extraWhere)
		}
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(%s(CAST(`_nel` AS DOUBLE)), 0) AS DOUBLE) AS `_doc_count` "+
				"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s`_nel` IS NOT NULL",
			quoteStr(fullAggName), sqlFunc, b.ColumnName, wherePrefix,
		))
		return
	}
	col := t.sqlNumericColumnRef(field, nil)
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
	if params, ok := script["params"].(map[string]any); ok {
		for pk, pv := range params {
			src = strings.ReplaceAll(src, "params."+pk, fmt.Sprintf("%v", pv))
		}
	}
	if numTerms > 0 {
		src = strings.ReplaceAll(src, "params.num_terms", strconv.Itoa(numTerms))
	}
	for {
		idx := strings.Index(src, "doc['")
		if idx < 0 {
			break
		}
		rest := src[idx+len("doc['"):]
		end := strings.Index(rest, "']")
		if end <= 0 {
			break
		}
		f := rest[:end]
		colExpr := fmt.Sprintf("COALESCE(%s, 1)", t.sqlNumericColumnRef(f, nctx))
		afterDoc := strings.TrimPrefix(rest[end+len("']"):], ".value")
		src = src[:idx] + colExpr + afterDoc
	}
	cleaned := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(src), "return")), ";"))
	cleaned = strings.ReplaceAll(cleaned, "Math.min(", "LEAST(")
	cleaned = strings.ReplaceAll(cleaned, "Math.max(", "GREATEST(")
	if strings.HasPrefix(cleaned, "LEAST(") || strings.HasPrefix(cleaned, "GREATEST(") || strings.HasPrefix(cleaned, "COALESCE(") {
		return cleaned
	}
	if n, err := strconv.Atoi(cleaned); err == nil && n > 0 {
		return strconv.Itoa(n)
	}
	return "1"
}

func (t *Transpiler) compileOrderBy(sorts []esast.SortSpec) string {
	return t.compileOrderByWithAfter(sorts, nil)
}

func (t *Transpiler) compileOrderByWithAfter(sorts []esast.SortSpec, after []any) string {
	if len(sorts) == 0 {
		if len(after) >= 2 {
			return "`_score` DESC, `_id` ASC"
		}
		return "`_score` DESC, `_id` ASC"
	}
	var parts []string
	for idx, s := range sorts {
		dir := "ASC"
		if strings.EqualFold(s.Entry.Order, "desc") {
			dir = "DESC"
		}
		switch s.Entry.Field {
		case "_score":
			parts = append(parts, "`_score` "+dir)
		case "_id", "_doc":
			parts = append(parts, "`_id` "+dir)
		default:
			var sampleVal any
			if idx < len(after) {
				sampleVal = after[idx]
			}
			col := t.sqlTypedColumnRef(s.Entry.Field, sampleVal, true, nil)
			parts = append(parts, col+" "+dir)
		}
	}
	return strings.Join(parts, ", ")
}

func (t *Transpiler) compileSearchAfterPredicate(sorts []esast.SortSpec, after []any, scoreExpr string) string {
	effectiveSorts := sorts
	if len(effectiveSorts) == 0 {
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

	sortExpr := func(idx int) (string, any) {
		field := effectiveSorts[idx].Entry.Field
		val := after[idx]
		switch field {
		case "_score":
			return fmt.Sprintf("CAST(%s AS DOUBLE)", scoreExpr), val
		case "_id", "_doc":
			return "`_id`", val
		default:
			b := t.Schema.ResolveField(field)
			if strVal, ok := val.(string); ok {
				if b.EffectiveLowercase(true) {
					val = strings.ToLower(strVal)
				} else if b.DorisType == schema.DorisBigInt {
					if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
						val = ms
					}
				}
			}
			return t.sqlTypedColumnRef(field, val, true, nil), val
		}
	}

	var disjuncts []string
	for i := 0; i < n; i++ {
		var conjuncts []string
		for j := 0; j < i; j++ {
			colJ, valJ := sortExpr(j)
			if valJ == nil {
				conjuncts = append(conjuncts, fmt.Sprintf("%s IS NULL", colJ))
			} else {
				conjuncts = append(conjuncts, fmt.Sprintf("%s = %s", colJ, quoteValue(valJ)))
			}
		}
		colI, valI := sortExpr(i)
		if valI == nil {
			conjuncts = append(conjuncts, fmt.Sprintf("%s IS NOT NULL", colI))
		} else {
			op := ">"
			if strings.EqualFold(effectiveSorts[i].Entry.Order, "desc") {
				op = "<"
			}
			conjuncts = append(conjuncts, fmt.Sprintf("%s %s %s", colI, op, quoteValue(valI)))
		}
		if len(conjuncts) == 1 {
			disjuncts = append(disjuncts, conjuncts[0])
		} else {
			disjuncts = append(disjuncts, "("+strings.Join(conjuncts, " AND ")+")")
		}
	}
	return strings.Join(disjuncts, " OR ")
}

func (t *Transpiler) sqlColumnRef(field string, preferKeyword bool, nctx *nestedCtx) string {
	return t.sqlTypedColumnRef(field, nil, preferKeyword, nctx)
}

func (t *Transpiler) sqlNumericColumnRef(field string, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	if b.Kind == schema.StoragePromotedScalar {
		return fmt.Sprintf("`%s`", b.ColumnName)
	}
	return t.sqlTypedColumnRef(field, float64(0), false, nctx)
}

func (t *Transpiler) sqlTypedColumnRef(field string, sampleVal any, preferKeyword bool, nctx *nestedCtx) string {
	if field == "_all_text" || field == "*" {
		return "`_all_text`"
	}
	if field == "_id" || field == "_doc" {
		return "`_id`"
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
	case schema.StoragePromotedArray, schema.StoragePromotedVector:
		return fmt.Sprintf("`%s`", b.ColumnName)
	case schema.StorageNestedSubfield:
		if b.PrefilterArrayCol != "" {
			return fmt.Sprintf("`%s`", b.PrefilterArrayCol)
		}
	}
	if t.unindexedFields != nil && field != "" {
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
