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
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// CompiledQuery holds the compiled Doris SQL `WHERE` predicate and `_score` expression.
type CompiledQuery struct {
	WhereSQL          string
	ScoreSQL          string
	UsesFulltextMatch bool
}

// ExecutionPlan represents the Doris SQL queries generated for an Elasticsearch `/_search` request.
type ExecutionPlan struct {
	// Query 1: Paginated Top-K hits + window total count (empty when `size == 0`)
	HitsSQL string
	// Query 2: Consolidated Nereids Multi-Cast CTE query for all aggregations (or total count if `size == 0`)
	AggsSQL string
}

// TranspilerOptions configures dialect features for the Doris SQL compiler.
type TranspilerOptions struct {
	// UseDoris4SearchFunc enables pushing `query_string` / `simple_query_string` directly to
	// Apache Doris 4.0's native `SEARCH('<dsl>', '<default_field>', '<default_op>')` function.
	UseDoris4SearchFunc bool
}

type Transpiler struct {
	Schema *schema.IndexSchema
	Opts   TranspilerOptions
}

func NewTranspiler(s *schema.IndexSchema, opts TranspilerOptions) *Transpiler {
	return &Transpiler{Schema: s, Opts: opts}
}

type nestedCtx struct {
	nestedPath string
	elemVar    string
}

// BuildSearchPlan compiles an Elasticsearch `SearchRequest` into a Doris `ExecutionPlan`.
func (t *Transpiler) BuildSearchPlan(req *esast.SearchRequest) (*ExecutionPlan, error) {
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

	plan := &ExecutionPlan{}
	if size > 0 {
		scoreExpr := mainQ.ScoreSQL
		if mainQ.UsesFulltextMatch {
			scoreExpr = fmt.Sprintf("COALESCE(score(), 1.0) * (%s)", mainQ.ScoreSQL)
		}
		orderBy := t.compileOrderBy(req.Sort)
		plan.HitsSQL = fmt.Sprintf(
			"SELECT `_id`, `_version`, `_source`, CAST(%s AS DOUBLE) AS `_score`, "+
				"COUNT(*) OVER() AS `_total_hits` "+
				"FROM `%s`.`%s` "+
				"WHERE `__DORIS_DELETE_SIGN__` = 0 AND (%s) AND (%s) "+
				"ORDER BY %s "+
				"LIMIT %d OFFSET %d",
			scoreExpr,
			t.Schema.DorisDB,
			t.Schema.DorisTable,
			mainQ.WhereSQL,
			postFilterSQL,
			orderBy,
			size,
			from,
		)
	}

	aggs := req.EffectiveAggs()
	if len(aggs) > 0 || size == 0 {
		plan.AggsSQL = t.buildAggsCTESQL(mainQ.WhereSQL, aggs)
	}

	return plan, nil
}

// CompileQuery compiles a single `esast.Query` AST node into Doris SQL.
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
	case len(q.Term) > 0:
		for field, entry := range q.Term {
			pred := t.compileTermPredicate(field, entry.Value, entry.CaseInsensitive, nctx)
			score := "0.0"
			if scoring {
				score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, entry.Boost)
			}
			return CompiledQuery{WhereSQL: pred, ScoreSQL: score}
		}
	case len(q.Terms) > 0:
		for field, vals := range q.Terms {
			pred := t.compileTermsPredicate(field, vals, nctx)
			return CompiledQuery{WhereSQL: pred, ScoreSQL: "1.0"}
		}
	case len(q.Range) > 0:
		for field, rc := range q.Range {
			pred := t.compileRangePredicate(field, rc, nctx)
			return CompiledQuery{WhereSQL: pred, ScoreSQL: "1.0"}
		}
	case q.Exists != nil:
		pred := t.compileExistsPredicate(q.Exists.Field, nctx)
		return CompiledQuery{WhereSQL: pred, ScoreSQL: "1.0"}
	case len(q.Prefix) > 0:
		for field, pe := range q.Prefix {
			col := t.sqlColumnRef(field, true, nctx)
			likePat := quoteStr(escapeLikeLiteral(pe.Value) + "%")
			pred := fmt.Sprintf("%s LIKE %s", col, likePat)
			if pe.CaseInsensitive {
				pred = fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likePat)
			}
			return CompiledQuery{WhereSQL: pred, ScoreSQL: "1.0"}
		}
	case len(q.Wildcard) > 0:
		for field, we := range q.Wildcard {
			col := t.sqlColumnRef(field, true, nctx)
			likePat := quoteStr(wildcardToLike(we.Value))
			pred := fmt.Sprintf("%s LIKE %s", col, likePat)
			if we.CaseInsensitive {
				pred = fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likePat)
			}
			return CompiledQuery{WhereSQL: pred, ScoreSQL: "1.0"}
		}
	case len(q.Regexp) > 0:
		for field, re := range q.Regexp {
			col := t.sqlColumnRef(field, false, nctx)
			pred := fmt.Sprintf("%s MATCH_REGEXP %s", col, quoteStr(re.Value))
			return CompiledQuery{WhereSQL: pred, ScoreSQL: "1.0", UsesFulltextMatch: true}
		}
	case len(q.Match) > 0:
		for field, me := range q.Match {
			return t.compileMatchField(field, me.Query, me.Operator, me.Boost, scoring, nctx)
		}
	case len(q.MatchPhrase) > 0:
		for field, pe := range q.MatchPhrase {
			col := t.sqlColumnRef(field, false, nctx)
			phrase := pe.Query
			if pe.Slop > 0 {
				phrase = fmt.Sprintf("%s ~%d", phrase, pe.Slop)
			}
			pred := fmt.Sprintf("%s MATCH_PHRASE %s", col, quoteStr(phrase))
			score := "0.0"
			if scoring {
				score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, pe.Boost)
			}
			return CompiledQuery{WhereSQL: pred, ScoreSQL: score, UsesFulltextMatch: true}
		}
	case len(q.MatchPhrasePrefix) > 0:
		for field, pe := range q.MatchPhrasePrefix {
			col := t.sqlColumnRef(field, false, nctx)
			pred := fmt.Sprintf("%s MATCH_PHRASE_PREFIX %s", col, quoteStr(pe.Query))
			score := "0.0"
			if scoring {
				score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, pe.Boost)
			}
			return CompiledQuery{WhereSQL: pred, ScoreSQL: score, UsesFulltextMatch: true}
		}
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
		conjuncts = append(conjuncts, fmt.Sprintf("NOT COALESCE(%s, FALSE)", c.WhereSQL))
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
			var intCasts []string
			for _, d := range disjuncts {
				intCasts = append(intCasts, fmt.Sprintf("CAST(COALESCE(%s, FALSE) AS INT)", d))
			}
			conjuncts = append(conjuncts, fmt.Sprintf("((%s) >= %d)", strings.Join(intCasts, " + "), minShould))
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
	matchOp := "MATCH_ANY"
	if strings.EqualFold(operator, "and") {
		matchOp = "MATCH_ALL"
	}
	col := t.sqlColumnRef(field, false, nctx)
	lit := quoteValue(queryVal)
	pred := fmt.Sprintf("%s %s %s", col, matchOp, lit)
	score := "0.0"
	if scoring {
		score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
	}
	return CompiledQuery{WhereSQL: pred, ScoreSQL: score, UsesFulltextMatch: true}
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
			c := t.compileMatchField(bf.Field, mm.Query, op, bf.Boost, scoring, nctx)
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
			col := t.sqlColumnRef(fvf.Field, true, nctx)
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
			cond := t.CompileQuery(fn.Filter, false, nctx)
			funcExprs = append(funcExprs, fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", cond.WhereSQL, valExpr))
		} else {
			funcExprs = append(funcExprs, valExpr)
		}
	}

	var combinedFuncs string
	switch strings.ToLower(fs.ScoreMode) {
	case "sum":
		combinedFuncs = strings.Join(funcExprs, " + ")
	case "max":
		combinedFuncs = fmt.Sprintf("GREATEST(%s)", strings.Join(funcExprs, ", "))
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
	if strVal, ok := val.(string); ok && b.LowercaseNormalizer {
		val = strings.ToLower(strVal)
	}
	lit := quoteValue(val)

	switch b.Kind {
	case schema.StoragePromotedArray:
		return fmt.Sprintf("array_contains(`%s`, %s)", b.ColumnName, lit)
	case schema.StorageNestedSubfield:
		if nctx != nil && nctx.nestedPath == b.NestedPath {
			relPath := "$." + strings.Join(b.RelativeJSONPath, ".")
			if b.IsMultiValued {
				// Support nested arrays of objects like `columns.tags.tagFQN`
				return fmt.Sprintf("(%s LIKE %s)", nctx.elemVar, quoteStr("%"+fmt.Sprintf("%v", val)+"%"))
			}
			return fmt.Sprintf("json_extract_string(%s, '%s') = %s", nctx.elemVar, relPath, lit)
		}
		if b.PrefilterArrayCol != "" {
			return fmt.Sprintf("array_contains(`%s`, %s)", b.PrefilterArrayCol, lit)
		}
	}

	col := t.sqlColumnRef(field, true, nctx)
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
	quoted := make([]string, 0, len(vals))
	for _, v := range vals {
		if strVal, ok := v.(string); ok && b.LowercaseNormalizer {
			v = strings.ToLower(strVal)
		}
		quoted = append(quoted, quoteValue(v))
	}
	if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && nctx == nil) {
		return fmt.Sprintf("arrays_overlap(`%s`, [%s])", b.ColumnName, strings.Join(quoted, ", "))
	}
	col := t.sqlColumnRef(field, true, nctx)
	return fmt.Sprintf("%s IN (%s)", col, strings.Join(quoted, ", "))
}

func (t *Transpiler) compileRangePredicate(field string, rc esast.RangeCond, nctx *nestedCtx) string {
	col := t.sqlColumnRef(field, true, nctx)
	var parts []string
	if rc.GT != nil {
		parts = append(parts, fmt.Sprintf("%s > %s", col, quoteValue(rc.GT)))
	}
	if rc.GTE != nil {
		parts = append(parts, fmt.Sprintf("%s >= %s", col, quoteValue(rc.GTE)))
	}
	if rc.LT != nil {
		parts = append(parts, fmt.Sprintf("%s < %s", col, quoteValue(rc.LT)))
	}
	if rc.LTE != nil {
		parts = append(parts, fmt.Sprintf("%s <= %s", col, quoteValue(rc.LTE)))
	}
	if len(parts) == 0 {
		return "TRUE"
	}
	return strings.Join(parts, " AND ")
}

func (t *Transpiler) compileExistsPredicate(field string, nctx *nestedCtx) string {
	b := t.Schema.ResolveField(field)
	if b.Kind == schema.StoragePromotedArray {
		return fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", b.ColumnName, b.ColumnName)
	}
	col := t.sqlColumnRef(field, true, nctx)
	return fmt.Sprintf("%s IS NOT NULL", col)
}

func (t *Transpiler) buildAggsCTESQL(baseWhere string, aggs map[string]esast.AggSpec) string {
	var branches []string
	branches = append(branches,
		"(SELECT '__meta_total' AS `_agg_name`, '_count' AS `_bucket_key`, COUNT(*) AS `_doc_count` FROM `base_matched`)")

	aggNames := make([]string, 0, len(aggs))
	for k := range aggs {
		aggNames = append(aggNames, k)
	}
	sort.Strings(aggNames)

	for _, aggName := range aggNames {
		spec := aggs[aggName]
		switch {
		case spec.Terms != nil:
			size := spec.Terms.Size
			if size <= 0 {
				size = 10
			}
			b := t.Schema.ResolveField(spec.Terms.Field)
			if b.Kind == schema.StoragePromotedArray {
				branches = append(branches, fmt.Sprintf(
					"(SELECT %s AS `_agg_name`, CAST(`_elem` AS STRING) AS `_bucket_key`, COUNT(*) AS `_doc_count` "+
						"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem` "+
						"WHERE `_elem` IS NOT NULL "+
						"GROUP BY `_elem` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d)",
					quoteStr(aggName), b.ColumnName, size,
				))
			} else {
				col := t.sqlColumnRef(spec.Terms.Field, true, nil)
				branches = append(branches, fmt.Sprintf(
					"(SELECT %s AS `_agg_name`, CAST(%s AS STRING) AS `_bucket_key`, COUNT(*) AS `_doc_count` "+
						"FROM `base_matched` "+
						"WHERE %s IS NOT NULL "+
						"GROUP BY %s ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d)",
					quoteStr(aggName), col, col, col, size,
				))
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
					size := subSpec.Terms.Size
					if size <= 0 {
						size = 10
					}
					relKey := strings.TrimPrefix(subSpec.Terms.Field, spec.Nested.Path+".")
					branches = append(branches, fmt.Sprintf(
						"(SELECT %s AS `_agg_name`, json_extract_string(`_nel`, '$.%s') AS `_bucket_key`, COUNT(*) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` "+
							"WHERE json_extract_string(`_nel`, '$.%s') IS NOT NULL "+
							"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d)",
						quoteStr(aggName+"."+subName), relKey, corrCol, relKey, size,
					))
				}
			}
		case spec.Filter != nil:
			cond := t.CompileQuery(spec.Filter, false, nil)
			branches = append(branches, fmt.Sprintf(
				"(SELECT %s AS `_agg_name`, '_filter' AS `_bucket_key`, COUNT(*) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s)",
				quoteStr(aggName), cond.WhereSQL,
			))
		case spec.Missing != nil:
			existsPred := t.compileExistsPredicate(spec.Missing.Field, nil)
			branches = append(branches, fmt.Sprintf(
				"(SELECT %s AS `_agg_name`, '_missing' AS `_bucket_key`, COUNT(*) AS `_doc_count` "+
					"FROM `base_matched` WHERE NOT (%s))",
				quoteStr(aggName), existsPred,
			))
		}
	}

	return fmt.Sprintf(
		"WITH `base_matched` AS (SELECT * FROM `%s`.`%s` WHERE `__DORIS_DELETE_SIGN__` = 0 AND (%s))\n%s",
		t.Schema.DorisDB,
		t.Schema.DorisTable,
		baseWhere,
		strings.Join(branches, "\nUNION ALL\n"),
	)
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
		case "_id":
			parts = append(parts, "`_id` "+dir)
		default:
			col := t.sqlColumnRef(s.Entry.Field, true, nil)
			parts = append(parts, col+" "+dir)
		}
	}
	return strings.Join(parts, ", ")
}

func (t *Transpiler) sqlColumnRef(field string, preferKeyword bool, nctx *nestedCtx) string {
	if field == "_all_text" || field == "*" {
		return "`_all_text`"
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
			return fmt.Sprintf("json_extract_string(%s, '%s')", nctx.elemVar, relPath)
		}
		if b.PrefilterArrayCol != "" {
			return fmt.Sprintf("`%s`", b.PrefilterArrayCol)
		}
	}
	var pathBuilder strings.Builder
	for _, seg := range b.SourceJSONPath {
		pathBuilder.WriteString(fmt.Sprintf("['%s']", strings.ReplaceAll(seg, "'", "''")))
	}
	return fmt.Sprintf("CAST(`_doc`%s AS STRING)", pathBuilder.String())
}

func parseMinShouldMatch(v any, defaultOne bool) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case string:
		if n, err := strconv.Atoi(val); err == nil {
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
	case string:
		return quoteStr(val)
	case bool:
		if val {
			return "TRUE"
		}
		return "FALSE"
	case float64, int, int64:
		return fmt.Sprintf("%v", val)
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
