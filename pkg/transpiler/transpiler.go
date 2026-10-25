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
	ScoreSQL          string
	UsesFulltextMatch bool
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
		if mainQ.UsesFulltextMatch && t.Opts.UseDoris4SearchFunc {
			scoreExpr = fmt.Sprintf("COALESCE(score(), 1.0) * (%s)", mainQ.ScoreSQL)
		}
		orderBy := t.compileOrderBy(req.Sort)
		if len(req.SearchAfter) > 0 {
			from = 0
			if saPred := t.compileSearchAfterPredicate(req.Sort, req.SearchAfter, scoreExpr); saPred != "" && saPred != "TRUE" {
				if postFilterSQL == "TRUE" {
					postFilterSQL = saPred
				} else {
					postFilterSQL = fmt.Sprintf("(%s) AND (%s)", postFilterSQL, saPred)
				}
			}
		}
		whereClause := fmt.Sprintf("`__DORIS_DELETE_SIGN__` = 0 AND (%s) AND (%s)", mainQ.WhereSQL, postFilterSQL)
		if req.Collapse != nil && req.Collapse.Field != "" {
			collapseCol := t.sqlColumnRef(req.Collapse.Field, true, nil)
			plan.HitsSQL = fmt.Sprintf(
				"SELECT `_id`, `_version`, `_source`, `_score`, COUNT(*) OVER() AS `_total_hits` "+
					"FROM ("+
					"SELECT *, CAST(%s AS DOUBLE) AS `_score`, "+
					"ROW_NUMBER() OVER (PARTITION BY %s ORDER BY %s) AS `_collapse_rn` "+
					"FROM `%s`.`%s` "+
					"WHERE %s"+
					") `_collapsed` "+
					"WHERE `_collapse_rn` = 1 "+
					"ORDER BY %s "+
					"LIMIT %d OFFSET %d",
				scoreExpr,
				collapseCol,
				orderBy,
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
					"COUNT(*) OVER() AS `_total_hits` "+
					"FROM `%s`.`%s` "+
					"WHERE %s "+
					"ORDER BY %s "+
					"LIMIT %d OFFSET %d",
				scoreExpr,
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
		plan.AggsSQL = t.buildAggsCTESQL(mainQ.WhereSQL, aggs)
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
			return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		quoted := make([]string, 0, len(q.Ids.Values))
		for _, id := range q.Ids.Values {
			quoted = append(quoted, quoteStr(id))
		}
		return CompiledQuery{
			WhereSQL: fmt.Sprintf("`_id` IN (%s)", strings.Join(quoted, ", ")),
			ScoreSQL: "1.0",
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
		return CompiledQuery{WhereSQL: where, ScoreSQL: score}
	case q.Terms != nil && len(q.Terms.Fields) > 0:
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
		return CompiledQuery{WhereSQL: pred, ScoreSQL: score}
	case len(q.Range) > 0:
		keys := sortedMapKeys(q.Range)
		var preds []string
		for _, field := range keys {
			preds = append(preds, t.compileRangePredicate(field, q.Range[field], nctx))
		}
		return CompiledQuery{WhereSQL: strings.Join(preds, " AND "), ScoreSQL: "1.0"}
	case q.Exists != nil:
		pred := t.compileExistsPredicate(q.Exists.Field, nctx)
		return CompiledQuery{WhereSQL: pred, ScoreSQL: "1.0"}
	case len(q.Prefix) > 0:
		keys := sortedMapKeys(q.Prefix)
		var preds []string
		for _, field := range keys {
			pe := q.Prefix[field]
			preds = append(preds, t.compilePrefixPredicate(field, pe.Value, pe.CaseInsensitive, nctx))
		}
		return CompiledQuery{WhereSQL: strings.Join(preds, " AND "), ScoreSQL: "1.0"}
	case len(q.Wildcard) > 0:
		keys := sortedMapKeys(q.Wildcard)
		var preds []string
		for _, field := range keys {
			we := q.Wildcard[field]
			preds = append(preds, t.compileWildcardPredicate(field, we.Value, we.CaseInsensitive, nctx))
		}
		return CompiledQuery{WhereSQL: strings.Join(preds, " AND "), ScoreSQL: "1.0"}
	case len(q.Regexp) > 0:
		keys := sortedMapKeys(q.Regexp)
		var preds []string
		usesFT := false
		for _, field := range keys {
			re := q.Regexp[field]
			b := t.Schema.ResolveField(field)
			if nctx == nil && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				preds = append(preds, fmt.Sprintf("array_exists(_x -> _x REGEXP %s, `%s`)", quoteStr(re.Value), b.ColumnName))
				continue
			}
			col := t.sqlColumnRef(field, false, nctx)
			if nctx != nil {
				preds = append(preds, fmt.Sprintf("%s REGEXP %s", col, quoteStr(re.Value)))
			} else {
				preds = append(preds, fmt.Sprintf("%s MATCH_REGEXP %s", col, quoteStr(re.Value)))
				usesFT = true
			}
		}
		return CompiledQuery{WhereSQL: strings.Join(preds, " AND "), ScoreSQL: "1.0", UsesFulltextMatch: usesFT}
	case len(q.Match) > 0:
		keys := sortedMapKeys(q.Match)
		if len(keys) == 1 {
			me := q.Match[keys[0]]
			return t.compileMatchField(keys[0], me.Query, me.Operator, me.Boost, scoring, nctx)
		}
		var subs []esast.Query
		for _, k := range keys {
			subs = append(subs, esast.Query{Match: map[string]esast.MatchEntry{k: q.Match[k]}})
		}
		return t.compileBool(&esast.BoolQuery{Must: subs}, scoring, nctx)
	case len(q.MatchPhrase) > 0:
		keys := sortedMapKeys(q.MatchPhrase)
		pe := q.MatchPhrase[keys[0]]
		return t.compileMatchPhraseField(keys[0], pe.Query, pe.Slop, pe.Boost, false, scoring, nctx)
	case len(q.MatchPhrasePrefix) > 0:
		keys := sortedMapKeys(q.MatchPhrasePrefix)
		pe := q.MatchPhrasePrefix[keys[0]]
		return t.compileMatchPhraseField(keys[0], pe.Query, pe.Slop, pe.Boost, true, scoring, nctx)
	case len(q.MatchBoolPrefix) > 0:
		keys := sortedMapKeys(q.MatchBoolPrefix)
		pe := q.MatchBoolPrefix[keys[0]]
		return t.compileMatchPhraseField(keys[0], pe.Query, pe.Slop, pe.Boost, true, scoring, nctx)
	case q.MultiMatch != nil:
		return t.compileMultiMatch(q.MultiMatch, scoring, nctx)
	case q.QueryString != nil:
		return t.compileQueryString(q.QueryString, scoring, nctx)
	case q.SimpleQueryString != nil:
		return t.compileQueryString(q.SimpleQueryString, scoring, nctx)
	case q.Nested != nil:
		return t.compileNested(q.Nested)
	case q.ConstantScore != nil:
		inner := t.CompileQuery(&q.ConstantScore.Filter, false, nctx)
		boost := 1.0
		if q.ConstantScore.Boost != nil {
			boost = *q.ConstantScore.Boost
		}
		return CompiledQuery{
			WhereSQL:          inner.WhereSQL,
			ScoreSQL:          fmt.Sprintf("%.4f", boost),
			UsesFulltextMatch: inner.UsesFulltextMatch,
		}
	case q.FunctionScore != nil:
		return t.compileFunctionScore(q.FunctionScore, nctx)
	}
	return CompiledQuery{WhereSQL: "TRUE", ScoreSQL: "1.0"}
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
		return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	var disjuncts, scores []string
	usesFT := false
	for i := range dm.Queries {
		c := t.CompileQuery(&dm.Queries[i], scoring, nctx)
		disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
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
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: usesFT,
	}
}

func (t *Transpiler) compileBoosting(bq *esast.BoostingQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if bq == nil {
		return CompiledQuery{WhereSQL: "TRUE", ScoreSQL: "1.0"}
	}
	pos := t.CompileQuery(&bq.Positive, scoring, nctx)
	neg := t.CompileQuery(&bq.Negative, false, nctx)
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
		scoreSQL = fmt.Sprintf("(%.4f * (%s) * (CASE WHEN %s THEN %.4f ELSE 1.0 END))",
			boost, pos.ScoreSQL, neg.WhereSQL, negBoost)
	}
	return CompiledQuery{
		WhereSQL:          pos.WhereSQL,
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: pos.UsesFulltextMatch || neg.UsesFulltextMatch,
	}
}

func (t *Transpiler) compileBool(b *esast.BoolQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	var conjuncts []string
	var scoreTerms []string
	usesFT := false

	for i := range b.Must {
		c := t.CompileQuery(&b.Must[i], scoring, nctx)
		conjuncts = append(conjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
		if scoring {
			scoreTerms = append(scoreTerms, c.ScoreSQL)
		}
		usesFT = usesFT || c.UsesFulltextMatch
	}
	for i := range b.Filter {
		c := t.CompileQuery(&b.Filter[i], false, nctx)
		conjuncts = append(conjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
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
		usesFT = usesFT || c.UsesFulltextMatch
	}
	if len(b.Should) > 0 {
		var disjuncts []string
		for i := range b.Should {
			c := t.CompileQuery(&b.Should[i], scoring, nctx)
			disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
			if scoring {
				scoreTerms = append(scoreTerms, c.ScoreSQL)
			}
			usesFT = usesFT || c.UsesFulltextMatch
		}
		minShould := parseMinShouldMatch(b.MinimumShouldMatch, len(b.Must) == 0 && len(b.Filter) == 0)
		if minShould == 1 {
			conjuncts = append(conjuncts, fmt.Sprintf("(%s)", strings.Join(disjuncts, " OR ")))
		} else if minShould > 1 {
			if minShould >= len(disjuncts) {
				conjuncts = append(conjuncts, fmt.Sprintf("(%s)", strings.Join(disjuncts, " AND ")))
			} else {
				var intCasts []string
				for i := range b.Should {
					c := t.CompileQuery(&b.Should[i], true, nctx)
					if c.UsesFulltextMatch {
						intCasts = append(intCasts, fmt.Sprintf("(CASE WHEN (%s) > 0 THEN 1 ELSE 0 END)", c.ScoreSQL))
					} else {
						intCasts = append(intCasts, fmt.Sprintf("CAST(COALESCE(%s, FALSE) AS INT)", c.WhereSQL))
					}
				}
				conjuncts = append(conjuncts, fmt.Sprintf("((%s) >= %d)", strings.Join(intCasts, " + "), minShould))
			}
		}
	}

	whereSQL := "TRUE"
	if len(conjuncts) > 0 {
		whereSQL = strings.Join(conjuncts, " AND ")
	}
	boost := 1.0
	if b.Boost != nil {
		boost = *b.Boost
	}
	scoreSQL := fmt.Sprintf("%.4f", boost)
	if scoring && len(scoreTerms) > 0 {
		scoreSQL = fmt.Sprintf("(%.4f * (%s))", boost, strings.Join(scoreTerms, " + "))
	}
	return CompiledQuery{
		WhereSQL:          whereSQL,
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: usesFT,
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

	// Non-string promoted scalar columns (BIGINT, INT, DOUBLE, BOOLEAN) use equality instead of MATCH_*
	if b.Kind == schema.StoragePromotedScalar && b.DorisType != schema.DorisString && b.DorisType != schema.DorisVarchar {
		pred := t.compileTermPredicate(field, queryVal, false, nctx)
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, ScoreSQL: score}
	}

	queryStr := fmt.Sprintf("%v", queryVal)
	scorePred := t.projectionSafeTextMatchSQL(field, queryStr, operator, nctx)
	score := "0.0"
	if scoring {
		score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", scorePred, boost)
	}

	// Inside nested `array_exists(_el -> ...)` lambdas, Doris BE does not allow `MATCH_*`.
	if nctx != nil {
		return CompiledQuery{WhereSQL: scorePred, ScoreSQL: score, UsesFulltextMatch: false}
	}

	matchOp := "MATCH_ANY"
	if strings.EqualFold(operator, "and") {
		matchOp = "MATCH_ALL"
	}
	col := t.sqlColumnRef(field, false, nil)
	lit := quoteValue(queryVal)
	pred := fmt.Sprintf("%s %s %s", col, matchOp, lit)
	return CompiledQuery{WhereSQL: pred, ScoreSQL: score, UsesFulltextMatch: true}
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
	scorePred := t.projectionSafeTextMatchSQL(field, queryStr, "phrase", nctx)
	score := "0.0"
	if scoring {
		score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", scorePred, boost)
	}
	if nctx != nil {
		return CompiledQuery{WhereSQL: scorePred, ScoreSQL: score, UsesFulltextMatch: false}
	}
	col := t.sqlColumnRef(field, false, nil)
	if isPrefix {
		pred := fmt.Sprintf("%s MATCH_PHRASE_PREFIX %s", col, quoteStr(queryStr))
		return CompiledQuery{WhereSQL: pred, ScoreSQL: score, UsesFulltextMatch: true}
	}
	phrase := queryStr
	if slop > 0 {
		phrase = fmt.Sprintf("%s ~%d", phrase, slop)
	}
	pred := fmt.Sprintf("%s MATCH_PHRASE %s", col, quoteStr(phrase))
	return CompiledQuery{WhereSQL: pred, ScoreSQL: score, UsesFulltextMatch: true}
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

	var disjuncts []string
	var scores []string
	usesFT := false

	for _, fpat := range fields {
		expanded := t.Schema.ExpandFieldPattern(fpat)
		for _, bf := range expanded {
			var c CompiledQuery
			qStr := fmt.Sprintf("%v", mm.Query)
			switch strings.ToLower(mm.Type) {
			case "phrase":
				c = t.compileMatchPhraseField(bf.Field, qStr, mm.Slop, bf.Boost, false, scoring, nctx)
			case "phrase_prefix", "bool_prefix":
				c = t.compileMatchPhraseField(bf.Field, qStr, mm.Slop, bf.Boost, true, scoring, nctx)
			default:
				c = t.compileMatchField(bf.Field, mm.Query, op, bf.Boost, scoring, nctx)
			}
			disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
			if scoring {
				scores = append(scores, c.ScoreSQL)
			}
			usesFT = usesFT || c.UsesFulltextMatch
		}
	}

	if len(disjuncts) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	scoreExpr := "1.0"
	if scoring && len(scores) > 0 {
		if strings.EqualFold(mm.Type, "best_fields") && len(scores) > 1 {
			scoreExpr = fmt.Sprintf("GREATEST(%s)", strings.Join(scores, ", "))
		} else {
			scoreExpr = fmt.Sprintf("(%s)", strings.Join(scores, " + "))
		}
	}
	return CompiledQuery{
		WhereSQL:          fmt.Sprintf("(%s)", strings.Join(disjuncts, " OR ")),
		ScoreSQL:          scoreExpr,
		UsesFulltextMatch: usesFT,
	}
}

func (t *Transpiler) compileNested(nq *esast.NestedQuery) CompiledQuery {
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
	return CompiledQuery{
		WhereSQL:          whereSQL,
		ScoreSQL:          "1.0",
		UsesFulltextMatch: inner.UsesFulltextMatch,
	}
}

func (t *Transpiler) extractNestedPrefilter(nestedPath string, q *esast.Query) string {
	if q == nil {
		return ""
	}
	if len(q.Term) > 0 {
		for field, entry := range q.Term {
			b := t.Schema.ResolveField(field)
			if b.Kind == schema.StorageNestedSubfield && b.NestedPath == nestedPath && b.PrefilterArrayCol != "" {
				val := entry.Value
				if strVal, ok := val.(string); ok && b.LowercaseNormalizer {
					val = strings.ToLower(strVal)
				}
				return fmt.Sprintf("array_contains(`%s`, %s)", b.PrefilterArrayCol, quoteValue(val))
			}
		}
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
	base := CompiledQuery{WhereSQL: "TRUE", ScoreSQL: "1.0"}
	if fs.Query != nil {
		base = t.CompileQuery(fs.Query, true, nctx)
	}
	if len(fs.Functions) == 0 {
		return base
	}
	var funcExprs []string
	for _, fn := range fs.Functions {
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
			case "log1p":
				modExpr = fmt.Sprintf("LOG10(1.0 + GREATEST(0.0, %s))", scaled)
			case "ln1p":
				modExpr = fmt.Sprintf("LN(1.0 + GREATEST(0.0, %s))", scaled)
			case "sqrt":
				modExpr = fmt.Sprintf("SQRT(GREATEST(0.0, %s))", scaled)
			case "reciprocal":
				modExpr = fmt.Sprintf("(1.0 / (1.0 + GREATEST(0.0, %s)))", scaled)
			default:
				modExpr = scaled
			}
			valExpr = fmt.Sprintf("(%.4f * %s)", weight, modExpr)
		}
		if fn.Filter != nil {
			cond := t.CompileQuery(fn.Filter, true, nctx)
			condExpr := cond.WhereSQL
			if cond.UsesFulltextMatch {
				condExpr = fmt.Sprintf("(%s) > 0", cond.ScoreSQL)
			}
			funcExprs = append(funcExprs, fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", condExpr, valExpr))
		} else {
			funcExprs = append(funcExprs, valExpr)
		}
	}

	var combinedFuncs string
	switch strings.ToLower(fs.ScoreMode) {
	case "sum":
		combinedFuncs = strings.Join(funcExprs, " + ")
	case "max":
		if len(funcExprs) == 1 {
			combinedFuncs = funcExprs[0]
		} else {
			combinedFuncs = fmt.Sprintf("GREATEST(%s)", strings.Join(funcExprs, ", "))
		}
	default:
		combinedFuncs = strings.Join(funcExprs, " * ")
	}

	var finalScore string
	switch strings.ToLower(fs.BoostMode) {
	case "sum":
		finalScore = fmt.Sprintf("((%s) + (%s))", base.ScoreSQL, combinedFuncs)
	case "replace":
		finalScore = combinedFuncs
	default:
		finalScore = fmt.Sprintf("((%s) * GREATEST(1.0, %s))", base.ScoreSQL, combinedFuncs)
	}
	return CompiledQuery{
		WhereSQL:          base.WhereSQL,
		ScoreSQL:          finalScore,
		UsesFulltextMatch: base.UsesFulltextMatch,
	}
}

func (t *Transpiler) compileTermPredicate(field string, val any, caseInsensitive bool, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	if strVal, ok := val.(string); ok {
		if b.LowercaseNormalizer {
			val = strings.ToLower(strVal)
		} else if b.DorisType == schema.DorisBigInt {
			if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
				val = ms
			}
		}
	}
	lit := quoteValue(val)

	switch b.Kind {
	case schema.StoragePromotedArray:
		return fmt.Sprintf("array_contains(`%s`, %s)", b.ColumnName, quoteStr(fmt.Sprintf("%v", val)))
	case schema.StorageNestedSubfield:
		if nctx != nil && nctx.nestedPath == b.NestedPath {
			relPath := "$." + strings.Join(b.RelativeJSONPath, ".")
			if b.IsMultiValued {
				return fmt.Sprintf("(%s LIKE %s)", nctx.elemVar, quoteStr("%"+fmt.Sprintf("%v", val)+"%"))
			}
			return fmt.Sprintf("json_extract_string(%s, %s) = %s", nctx.elemVar, quoteStr(relPath), quoteStr(fmt.Sprintf("%v", val)))
		}
		if b.PrefilterArrayCol != "" {
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
	isArrayCol := b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && nctx == nil)
	quoted := make([]string, 0, len(vals))
	for _, v := range vals {
		if strVal, ok := v.(string); ok && b.LowercaseNormalizer {
			v = strings.ToLower(strVal)
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
	return fmt.Sprintf("%s IN (%s)", col, strings.Join(quoted, ", "))
}

func (t *Transpiler) compilePrefixPredicate(field, val string, caseInsensitive bool, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	if b.LowercaseNormalizer {
		val = strings.ToLower(val)
	}
	likePat := quoteStr(escapeLikeLiteral(val) + "%")
	if nctx == nil && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `%s`)", likePat, b.ColumnName)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, `%s`)", likePat, b.ColumnName)
	}
	col := t.sqlColumnRef(field, true, nctx)
	if caseInsensitive {
		return fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likePat)
	}
	return fmt.Sprintf("%s LIKE %s", col, likePat)
}

func (t *Transpiler) compileWildcardPredicate(field, val string, caseInsensitive bool, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	if b.LowercaseNormalizer {
		val = strings.ToLower(val)
	}
	likePat := quoteStr(wildcardToLike(val))
	if nctx == nil && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `%s`)", likePat, b.ColumnName)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, `%s`)", likePat, b.ColumnName)
	}
	col := t.sqlColumnRef(field, true, nctx)
	if caseInsensitive {
		return fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likePat)
	}
	return fmt.Sprintf("%s LIKE %s", col, likePat)
}

func (t *Transpiler) compileRangePredicate(field string, rc esast.RangeCond, nctx *nestedCtx) string {
	gt, gte, lt, lte := rc.NormalizedBounds()
	b := t.Schema.ResolveField(field)
	now := time.Now().UTC()

	coerceBound := func(v any) any {
		if v == nil {
			return nil
		}
		if strVal, ok := v.(string); ok && b.DorisType == schema.DorisBigInt {
			if ms, ok := schema.ParseESDateToEpochMillis(strVal, now); ok {
				return ms
			}
		}
		return v
	}

	gt = coerceBound(gt)
	gte = coerceBound(gte)
	lt = coerceBound(lt)
	lte = coerceBound(lte)

	var sampleBound any
	for _, cand := range []any{gt, gte, lt, lte} {
		if cand != nil {
			sampleBound = cand
			break
		}
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

func (t *Transpiler) buildAggsCTESQL(baseWhere string, aggs map[string]esast.AggSpec) string {
	var branches []string
	branches = append(branches,
		"SELECT '__meta_total' AS `_agg_name`, '_count' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched`")

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
		case spec.Terms != nil:
			size := t.capBucketSize(spec.Terms.Size)
			b := t.Schema.ResolveField(spec.Terms.Field)
			*subIdx++
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
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
			} else {
				col := t.sqlColumnRef(spec.Terms.Field, true, nil)
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
			for _, subName := range subNames {
				subSpec := subAggs[subName]
				if subSpec.Terms != nil {
					size := t.capBucketSize(subSpec.Terms.Size)
					relKey := strings.TrimPrefix(subSpec.Terms.Field, spec.Nested.Path+".")
					relJSONPath := quoteStr("$." + relKey)
					*subIdx++
					*branches = append(*branches, fmt.Sprintf(
						"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
							"SELECT %s AS `_agg_name`, json_extract_string(`_nel`, %s) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` "+
							"WHERE %sjson_extract_string(`_nel`, %s) IS NOT NULL "+
							"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
							") `_agg_sub_%d`",
						quoteStr(fullAggName+"."+subName), relJSONPath, corrCol, wherePrefix, relJSONPath, size, *subIdx,
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
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_missing' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %sNOT (%s)",
				quoteStr(fullAggName), wherePrefix, existsPred,
			))

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
			col := t.sqlNumericColumnRef(spec.DateHistogram.Field, nil)
			bucketExpr := fmt.Sprintf("CAST(CAST(FLOOR(%s / %d) * %d AS BIGINT) AS STRING)", col, intervalMs, intervalMs)
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
			for _, srcMap := range spec.Composite.Sources {
				srcKeys := sortedMapKeys(srcMap)
				for _, sk := range srcKeys {
					srcSpec := srcMap[sk]
					if srcSpec.Terms != nil {
						col := t.sqlColumnRef(srcSpec.Terms.Field, true, nil)
						colExprs = append(colExprs, fmt.Sprintf("CAST(%s AS STRING)", col))
						notNullConds = append(notNullConds, fmt.Sprintf("%s IS NOT NULL", col))
					}
				}
			}
			if len(colExprs) > 0 {
				bucketKeyExpr := colExprs[0]
				if len(colExprs) > 1 {
					bucketKeyExpr = fmt.Sprintf("CONCAT_WS('\\x1f', %s)", strings.Join(colExprs, ", "))
				}
				wCond := strings.Join(notNullConds, " AND ")
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
			}
		}
	}
}

func (t *Transpiler) capBucketSize(size int) int {
	if size <= 0 {
		return 10
	}
	maxBuckets := t.Opts.MaxAggBuckets
	if maxBuckets <= 0 {
		maxBuckets = DefaultMaxAggBuckets
	}
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

	for _, subName := range subNames {
		subSpec := subAggs[subName]
		subFull := parentAggName + "." + subName
		switch {
		case subSpec.Avg != nil:
			col := t.sqlNumericColumnRef(subSpec.Avg.Field, nil)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(AVG(%s), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
			))
		case subSpec.Sum != nil:
			col := t.sqlNumericColumnRef(subSpec.Sum.Field, nil)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(SUM(%s), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
			))
		case subSpec.Min != nil:
			col := t.sqlNumericColumnRef(subSpec.Min.Field, nil)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(MIN(%s), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
			))
		case subSpec.Max != nil:
			col := t.sqlNumericColumnRef(subSpec.Max.Field, nil)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(MAX(%s), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
			))
		case subSpec.ValueCount != nil:
			col := t.sqlColumnRef(subSpec.ValueCount.Field, true, nil)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
			))
		case subSpec.Cardinality != nil:
			col := t.sqlColumnRef(subSpec.Cardinality.Field, true, nil)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT %s) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause,
			))
		case subSpec.Terms != nil:
			col := t.sqlColumnRef(subSpec.Terms.Field, true, nil)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, CONCAT(%s, '\\x1f', CAST(%s AS STRING)) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE (%s) AND %s IS NOT NULL "+
					"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC"+
					") `_agg_sub_%d`",
				quoteStr(subFull), parentBucketExpr, col, fromClause, whereClause, col, *subIdx,
			))
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

func (t *Transpiler) compileOrderBy(sorts []esast.SortSpec) string {
	if len(sorts) == 0 {
		return "`_score` DESC"
	}
	var parts []string
	for _, s := range sorts {
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
			col := t.sqlColumnRef(s.Entry.Field, true, nil)
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
			if b.DorisType == schema.DorisBigInt {
				if strVal, ok := val.(string); ok {
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
	if field == "_id" {
		return "`_id`"
	}
	b := t.Schema.ResolveField(field)
	switch b.Kind {
	case schema.StoragePromotedScalar:
		if preferKeyword && b.KeywordCompanion != "" {
			return fmt.Sprintf("`%s`", b.KeywordCompanion)
		}
		return fmt.Sprintf("`%s`", b.ColumnName)
	case schema.StoragePromotedArray:
		return fmt.Sprintf("`%s`", b.ColumnName)
	case schema.StorageNestedSubfield:
		if nctx != nil && nctx.nestedPath == b.NestedPath {
			relPath := "$." + strings.Join(b.RelativeJSONPath, ".")
			return fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath))
		}
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
	return fmt.Sprintf("CAST(`_doc`%s AS %s)", pathBuilder.String(), castType)
}

func parseMinShouldMatch(v any, defaultOne bool) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case json.Number:
		if i, err := val.Int64(); err == nil {
			return int(i)
		}
	case string:
		s := strings.TrimSpace(val)
		if n, err := strconv.Atoi(s); err == nil {
			return n
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
		if !math.IsNaN(val) && !math.IsInf(val, 0) && val == math.Trunc(val) && val >= math.MinInt64 && val <= math.MaxInt64 {
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
			sb.WriteRune(r)
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
	return sb.String()
}
