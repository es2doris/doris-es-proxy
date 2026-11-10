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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"regexp"
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
	Schema           *schema.IndexSchema
	Opts             TranspilerOptions
	unindexedFields  map[string]bool
	searchErr        error
	inFilterAggQuery bool
}

func NewTranspiler(s *schema.IndexSchema, opts TranspilerOptions) *Transpiler {
	return &Transpiler{
		Schema:          s,
		Opts:            opts,
		unindexedFields: make(map[string]bool),
	}
}

func (t *Transpiler) checkFieldSearchable(field string, b schema.FieldBinding) bool {
	if b.EnabledFalse {
		return false
	}
	if b.NotIndexed {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("cannot search on field [%s] since it is not indexed", field)
		}
		return false
	}
	return true
}

func (t *Transpiler) checkFieldDocValues(field string, b schema.FieldBinding) bool {
	if b.EnabledFalse {
		return false
	}
	if b.DocValuesFalse {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("illegal_argument_exception: cannot use field [%s] for doc_values operations because doc_values is disabled", field)
		}
		return false
	}
	return true
}

func (t *Transpiler) checkScriptDocValues(script any, nctx *nestedCtx) {
	s, _, ok := normalizeScriptSourceAndParams(script)
	if !ok || s == "" {
		return
	}
	rest := s
	for {
		idx := strings.Index(rest, "doc[")
		if idx < 0 {
			break
		}
		sub := rest[idx:]
		if field, _, okF := parseDocFieldAccess(sub); okF && field != "" && !strings.HasPrefix(field, "_") {
			resolved, b := t.resolveFieldInNestedCtx(field, true, nctx)
			t.checkFieldDocValues(resolved, b)
		}
		rest = sub[4:]
	}
}

func (t *Transpiler) validateAggsDocValues(aggs map[string]esast.AggSpec, nctx *nestedCtx) {
	if len(aggs) == 0 {
		return
	}
	checkField := func(field string, curNCtx *nestedCtx) {
		if field == "" || strings.HasPrefix(field, "_") {
			return
		}
		resolved, b := t.resolveFieldInNestedCtx(field, true, curNCtx)
		t.checkFieldDocValues(resolved, b)
	}
	for _, spec := range aggs {
		if termsSpec := spec.EffectiveTerms(); termsSpec != nil && spec.SignificantText == nil {
			effField := termsSpec.Field
			if effField == "" && termsSpec.Script != nil {
				if df, ok := extractSimpleDocFieldFromScript(termsSpec.Script); ok {
					effField = df
				}
			}
			checkField(effField, nctx)
			t.checkScriptDocValues(termsSpec.Script, nctx)
		}
		if spec.Histogram != nil {
			checkField(spec.Histogram.Field, nctx)
			t.checkScriptDocValues(spec.Histogram.Script, nctx)
		}
		if spec.DateHistogram != nil {
			checkField(spec.DateHistogram.Field, nctx)
			t.checkScriptDocValues(spec.DateHistogram.Script, nctx)
		}
		if rSpec := spec.EffectiveRange(); rSpec != nil {
			checkField(rSpec.Field, nctx)
			t.checkScriptDocValues(rSpec.Script, nctx)
		}
		if spec.Composite != nil {
			for _, srcMap := range spec.Composite.Sources {
				t.validateAggsDocValues(srcMap, nctx)
			}
		}
		if spec.Cardinality != nil {
			checkField(spec.Cardinality.Field, nctx)
			t.checkScriptDocValues(spec.Cardinality.Script, nctx)
		}
		if spec.ValueCount != nil {
			checkField(spec.ValueCount.Field, nctx)
			t.checkScriptDocValues(spec.ValueCount.Script, nctx)
		}
		if spec.Avg != nil {
			checkField(spec.Avg.Field, nctx)
			t.checkScriptDocValues(spec.Avg.Script, nctx)
		}
		if spec.Sum != nil {
			checkField(spec.Sum.Field, nctx)
			t.checkScriptDocValues(spec.Sum.Script, nctx)
		}
		if spec.Min != nil {
			checkField(spec.Min.Field, nctx)
			t.checkScriptDocValues(spec.Min.Script, nctx)
		}
		if spec.Max != nil {
			checkField(spec.Max.Field, nctx)
			t.checkScriptDocValues(spec.Max.Script, nctx)
		}
		if stSpec := spec.EffectiveStats(); stSpec != nil {
			checkField(stSpec.Field, nctx)
			t.checkScriptDocValues(stSpec.Script, nctx)
		}
		if spec.StringStats != nil {
			checkField(spec.StringStats.Field, nctx)
			t.checkScriptDocValues(spec.StringStats.Script, nctx)
		}
		if spec.Boxplot != nil {
			checkField(spec.Boxplot.Field, nctx)
			t.checkScriptDocValues(spec.Boxplot.Script, nctx)
		}
		if spec.Percentiles != nil {
			checkField(spec.Percentiles.Field, nctx)
			t.checkScriptDocValues(spec.Percentiles.Script, nctx)
		}
		if spec.PercentileRanks != nil {
			checkField(spec.PercentileRanks.Field, nctx)
			t.checkScriptDocValues(spec.PercentileRanks.Script, nctx)
		}
		if spec.Rate != nil {
			checkField(spec.Rate.Field, nctx)
			t.checkScriptDocValues(spec.Rate.Script, nctx)
		}
		if spec.ScriptedMetric != nil {
			t.checkScriptDocValues(spec.ScriptedMetric.InitScript, nctx)
			t.checkScriptDocValues(spec.ScriptedMetric.MapScript, nctx)
			t.checkScriptDocValues(spec.ScriptedMetric.CombineScript, nctx)
			t.checkScriptDocValues(spec.ScriptedMetric.ReduceScript, nctx)
		}
		if spec.TopMetrics != nil {
			for _, mf := range spec.TopMetrics.EffectiveMetricFields() {
				checkField(mf, nctx)
			}
			for _, s := range spec.TopMetrics.Sort {
				var sortNCtx *nestedCtx
				if deepest := deepestNestedSortPath(s.Entry.Nested); deepest != "" {
					sortNCtx = &nestedCtx{nestedPath: deepest}
				} else {
					sortNCtx = nctx
				}
				checkField(s.Entry.Field, sortNCtx)
				if s.Entry.Field == "_script" {
					t.checkScriptDocValues(s.Entry.Script, sortNCtx)
				}
			}
		}
		if spec.TopHits != nil {
			for _, dvf := range spec.TopHits.DocvalueFields {
				checkField(dvf.Field, nctx)
			}
			for _, sf := range spec.TopHits.ScriptFields {
				t.checkScriptDocValues(sf, nctx)
			}
			for _, s := range spec.TopHits.Sort {
				var sortNCtx *nestedCtx
				if deepest := deepestNestedSortPath(s.Entry.Nested); deepest != "" {
					sortNCtx = &nestedCtx{nestedPath: deepest}
				} else {
					sortNCtx = nctx
				}
				checkField(s.Entry.Field, sortNCtx)
				if s.Entry.Field == "_script" {
					t.checkScriptDocValues(s.Entry.Script, sortNCtx)
				}
			}
		}
		if sampSpec := spec.EffectiveSampler(); sampSpec != nil {
			checkField(sampSpec.Field, nctx)
			t.checkScriptDocValues(sampSpec.Script, nctx)
		}
		if spec.MultiTerms != nil {
			for _, mt := range spec.MultiTerms.Terms {
				checkField(mt.Field, nctx)
				t.checkScriptDocValues(mt.Script, nctx)
			}
		}
		if spec.RareTerms != nil {
			checkField(spec.RareTerms.Field, nctx)
		}
		if spec.AutoDateHistogram != nil {
			checkField(spec.AutoDateHistogram.Field, nctx)
			t.checkScriptDocValues(spec.AutoDateHistogram.Script, nctx)
		}
		if spec.VariableWidthHistogram != nil {
			checkField(spec.VariableWidthHistogram.Field, nctx)
			t.checkScriptDocValues(spec.VariableWidthHistogram.Script, nctx)
		}
		if spec.MedianAbsoluteDeviation != nil {
			checkField(spec.MedianAbsoluteDeviation.Field, nctx)
			t.checkScriptDocValues(spec.MedianAbsoluteDeviation.Script, nctx)
		}
		if spec.WeightedAvg != nil {
			checkField(spec.WeightedAvg.Value.Field, nctx)
			t.checkScriptDocValues(spec.WeightedAvg.Value.Script, nctx)
			checkField(spec.WeightedAvg.Weight.Field, nctx)
			t.checkScriptDocValues(spec.WeightedAvg.Weight.Script, nctx)
		}
		if spec.MatrixStats != nil {
			for _, f := range spec.MatrixStats.Fields {
				checkField(f, nctx)
			}
		}
		if spec.TTest != nil {
			checkField(spec.TTest.A.Field, nctx)
			t.checkScriptDocValues(spec.TTest.A.Script, nctx)
			if spec.TTest.A.Filter != nil {
				_ = t.CompileQuery(spec.TTest.A.Filter, false, nctx)
			}
			checkField(spec.TTest.B.Field, nctx)
			t.checkScriptDocValues(spec.TTest.B.Script, nctx)
			if spec.TTest.B.Filter != nil {
				_ = t.CompileQuery(spec.TTest.B.Filter, false, nctx)
			}
		}
		if spec.GeoBounds != nil {
			checkField(spec.GeoBounds.Field, nctx)
		}
		if spec.GeoCentroid != nil {
			checkField(spec.GeoCentroid.Field, nctx)
			t.checkScriptDocValues(spec.GeoCentroid.Script, nctx)
		}
		if spec.GeoDistance != nil {
			checkField(spec.GeoDistance.Field, nctx)
		}
		if spec.GeohashGrid != nil {
			checkField(spec.GeohashGrid.Field, nctx)
		}
		if spec.GeotileGrid != nil {
			checkField(spec.GeotileGrid.Field, nctx)
		}
		if spec.Missing != nil {
			checkField(spec.Missing.Field, nctx)
		}
		if spec.Nested != nil && spec.Nested.Path != "" {
			t.validateAggsDocValues(spec.SubAggs(), &nestedCtx{nestedPath: spec.Nested.Path})
		} else if spec.ReverseNested != nil {
			var rnNCtx *nestedCtx
			if rnPath, _ := spec.ReverseNested["path"].(string); strings.TrimSpace(rnPath) != "" {
				rnNCtx = &nestedCtx{nestedPath: strings.TrimSpace(rnPath)}
			}
			t.validateAggsDocValues(spec.SubAggs(), rnNCtx)
		} else {
			t.validateAggsDocValues(spec.SubAggs(), nctx)
		}
	}
}

type nestedCtx struct {
	nestedPath string
	elemVar    string
}

// LowerRetrieverToSearchRequest lowers an ES 8.x top-level `retriever` tree into `query`, `knn`, `sub_searches`, and `rank`.
func LowerRetrieverToSearchRequest(req *esast.SearchRequest) {
	esast.LowerRetrieverToSearchRequest(req)
}

// BuildSearchPlan compiles an Elasticsearch `SearchRequest` into a Doris `ExecutionPlan`.
func (t *Transpiler) BuildSearchPlan(req *esast.SearchRequest) (*ExecutionPlan, error) {
	t.unindexedFields = make(map[string]bool)
	t.searchErr = nil
	if req != nil && req.Retriever != nil {
		esast.LowerRetrieverToSearchRequest(req)
	}
	if req != nil && req.Query == nil && len(req.SubSearches) > 0 {
		var shoulds []esast.Query
		for i := range req.SubSearches {
			if req.SubSearches[i].Query != nil {
				shoulds = append(shoulds, *req.SubSearches[i].Query)
			}
		}
		if len(shoulds) == 1 {
			qCopy := shoulds[0]
			req.Query = &qCopy
		} else if len(shoulds) > 1 {
			req.Query = &esast.Query{
				Bool: &esast.BoolQuery{
					Should:             shoulds,
					MinimumShouldMatch: 1,
				},
			}
		}
	}

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
	if req.MinScore != nil && !queryContainsScript(req.Query) && !queryContainsNestedScoring(req.Query) {
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

	for _, dvf := range req.DocvalueFields {
		if dvf.Field != "" && !strings.HasPrefix(dvf.Field, "_") && !strings.ContainsAny(dvf.Field, "*?") {
			b := t.Schema.ResolveEffectiveField(dvf.Field, true)
			t.checkFieldDocValues(dvf.Field, b)
		}
	}
	for _, sf := range req.ScriptFields {
		t.checkScriptDocValues(sf, nil)
	}
	if req.Collapse != nil {
		for _, ih := range req.Collapse.InnerHits {
			for _, dvf := range ih.DocvalueFields {
				if dvf.Field != "" && !strings.HasPrefix(dvf.Field, "_") && !strings.ContainsAny(dvf.Field, "*?") {
					b := t.Schema.ResolveEffectiveField(dvf.Field, true)
					t.checkFieldDocValues(dvf.Field, b)
				}
			}
			for _, sf := range ih.ScriptFields {
				t.checkScriptDocValues(sf, nil)
			}
		}
	}
	effSorts := EffectiveSortsForRequest(req)
	orderBy := t.compileOrderByWithAfter(effSorts, req.SearchAfter)
	if req.Collapse != nil && req.Collapse.Field != "" {
		bCollapse := t.Schema.ResolveEffectiveField(req.Collapse.Field, true)
		t.checkFieldDocValues(req.Collapse.Field, bCollapse)
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
		var saPred string
		if len(req.SearchAfter) > 0 {
			from = 0
			saScoreExpr := "`_score`"
			saPred = t.compileSearchAfterPredicate(effSorts, req.SearchAfter, saScoreExpr)
		}
		if req.Collapse != nil && req.Collapse.Field != "" {
			bCollapse := t.Schema.ResolveEffectiveField(req.Collapse.Field, true)
			collapseCol := t.sqlColumnRef(req.Collapse.Field, true, nil)
			if bCollapse.Kind == schema.StoragePromotedArray || bCollapse.Kind == schema.StorageNestedSubfield {
				if arrCol := bCollapse.EffectiveArrayColumn(true); arrCol != "" {
					collapseCol = fmt.Sprintf("element_at(`%s`, 1)", arrCol)
				}
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
		} else if saPred != "" && saPred != "TRUE" {
			preAfterWhere := fmt.Sprintf("`__DORIS_DELETE_SIGN__` = 0 AND (%s) AND (%s)", mainQ.WhereSQL, postFilterSQL)
			plan.HitsSQL = fmt.Sprintf(
				"SELECT `_id`, `_version`, `_source`, `_score`, `_total_hits` "+
					"FROM ("+
					"SELECT *, CAST(%s AS DOUBLE) AS `_score`, %s "+
					"FROM `%s`.`%s` "+
					"WHERE %s"+
					") `_scored` "+
					"WHERE %s "+
					"ORDER BY %s "+
					"LIMIT %d OFFSET %d",
				scoreExpr,
				totalHitsExpr,
				t.Schema.DorisDB,
				t.Schema.DorisTable,
				preAfterWhere,
				saPred,
				orderBy,
				size,
				from,
			)
		} else {
			whereClause := fmt.Sprintf("`__DORIS_DELETE_SIGN__` = 0 AND (%s) AND (%s)", mainQ.WhereSQL, postFilterSQL)
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
	t.validateAggsDocValues(aggs, nil)
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
	if t.searchErr != nil {
		return nil, t.searchErr
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
		boost := 1.0
		if rawBoost, hasBoost := q.MatchAll["boost"]; hasBoost && rawBoost != nil {
			switch bv := rawBoost.(type) {
			case float64:
				boost = bv
			case json.Number:
				if f, err := bv.Float64(); err == nil {
					boost = f
				}
			case int:
				boost = float64(bv)
			case int64:
				boost = float64(bv)
			}
		}
		score := "1.0"
		if boost != 1.0 {
			score = fmt.Sprintf("%.4f", boost)
		}
		return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: score}
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
		boost := 1.0
		if q.Ids.Boost != nil {
			boost = *q.Ids.Boost
		}
		score := fmt.Sprintf("%.4f", boost)
		if scoring {
			if len(q.Ids.ResolvedScores) > 0 {
				var cases []string
				for _, id := range q.Ids.Values {
					sc := q.Ids.ResolvedScores[id] * boost
					cases = append(cases, fmt.Sprintf("WHEN `_id` = %s THEN %.4f", quoteStr(id), sc))
				}
				score = fmt.Sprintf("(CASE %s ELSE 0.0 END)", strings.Join(cases, " "))
			} else {
				score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
			}
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
			cleanField, fBoost := parseFieldBoost(field, 1.0)
			pred := t.compileTermPredicate(cleanField, entry.Value, entry.CaseInsensitive, nctx)
			preds = append(preds, pred)
			if scoring {
				scores = append(scores, fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, entry.Boost*fBoost))
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
		effBoost := q.Terms.Boost
		for _, field := range fields {
			cleanField, fBoost := parseFieldBoost(field, 1.0)
			effBoost *= fBoost
			preds = append(preds, t.compileTermsPredicateWithCI(cleanField, q.Terms.Fields[field], q.Terms.CaseInsensitive, nctx))
		}
		pred := strings.Join(preds, " AND ")
		score := "1.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, effBoost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case len(q.TermsSet) > 0:
		fields := sortedMapKeys(q.TermsSet)
		var preds []string
		var scores []string
		for _, field := range fields {
			ts := q.TermsSet[field]
			cleanField, fBoost := parseFieldBoost(field, 1.0)
			fieldBoost := fBoost
			if ts.Boost != nil {
				fieldBoost = *ts.Boost * fBoost
			}
			resolvedField, b := t.resolveFieldInNestedCtx(cleanField, true, nctx)
			var fp string
			if !t.checkFieldSearchable(resolvedField, b) || len(ts.Terms) == 0 || b.Kind == schema.StoragePromotedVector {
				fp = "FALSE"
			} else {
				var uniqueTerms []any
				seenTerms := make(map[string]bool, len(ts.Terms))
				for _, tv := range ts.Terms {
					key := fmt.Sprintf("%T:%v", tv, tv)
					if !seenTerms[key] {
						seenTerms[key] = true
						uniqueTerms = append(uniqueTerms, tv)
					}
				}
				var termSums []string
				for _, tv := range uniqueTerms {
					tp := t.compileTermsSetTermPredicate(resolvedField, tv, nctx)
					termSums = append(termSums, fmt.Sprintf("CAST(COALESCE(%s, FALSE) AS INT)", tp))
				}
				if ts.MinimumShouldMatchField != "" {
					resolvedMSM, bMSM := t.resolveFieldInNestedCtx(ts.MinimumShouldMatchField, true, nctx)
					t.checkFieldDocValues(resolvedMSM, bMSM)
					if bMSM.ESType != "" {
						switch bMSM.ESType {
						case "byte", "short", "integer", "long", "unsigned_long", "float", "half_float", "scaled_float", "double", "boolean":
						default:
							if t.searchErr == nil {
								t.searchErr = fmt.Errorf("illegal_argument_exception: [terms_set] minimum_should_match_field [%s] must be a numeric field, got [%s]", ts.MinimumShouldMatchField, bMSM.ESType)
							}
							fp = "FALSE"
						}
					}
					if fp != "FALSE" {
						colRef := t.sqlNumericColumnRef(ts.MinimumShouldMatchField, nctx)
						fp = fmt.Sprintf("(%s IS NOT NULL AND ((%s) >= GREATEST(0, %s)))", colRef, strings.Join(termSums, " + "), colRef)
					}
				} else if ts.MinimumShouldMatchScript != nil {
					t.checkScriptDocValues(ts.MinimumShouldMatchScript, nctx)
					scriptExpr := t.compileTermsSetScriptThreshold(ts.MinimumShouldMatchScript, len(ts.Terms), nctx)
					threshExpr := "1"
					if scriptExpr != "1" {
						threshExpr = fmt.Sprintf("GREATEST(1, %s)", scriptExpr)
					}
					fp = fmt.Sprintf("((%s) >= %s)", strings.Join(termSums, " + "), threshExpr)
				} else {
					fp = fmt.Sprintf("((%s) >= 1)", strings.Join(termSums, " + "))
				}
			}
			preds = append(preds, fp)
			if scoring {
				scores = append(scores, fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", fp, fieldBoost))
			}
		}
		pred := strings.Join(preds, " AND ")
		score := "1.0"
		if scoring {
			if len(scores) == 1 {
				score = scores[0]
			} else {
				score = "(" + strings.Join(scores, " + ") + ")"
			}
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case len(q.Fuzzy) > 0:
		keys := sortedMapKeys(q.Fuzzy)
		if len(keys) == 1 {
			fe := q.Fuzzy[keys[0]]
			return t.compileFuzzyFieldWithOpts(keys[0], fe.Value, "or", fe.Fuzziness, fe.CaseInsensitive, fe.PrefixLength, fe.Transpositions, fe.Boost, scoring, nctx)
		}
		var subs []esast.Query
		for _, k := range keys {
			fe := q.Fuzzy[k]
			subs = append(subs, esast.Query{Fuzzy: map[string]esast.FuzzyEntry{k: fe}})
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
		var preds, scores []string
		for _, field := range keys {
			rc := q.Range[field]
			cleanField, fBoost := parseFieldBoost(field, 1.0)
			boost := fBoost
			if rc.Boost != nil {
				boost = *rc.Boost * fBoost
			}
			p := t.compileRangePredicate(cleanField, rc, nctx)
			preds = append(preds, p)
			if scoring {
				scores = append(scores, fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", p, boost))
			}
		}
		pred := strings.Join(preds, " AND ")
		score := "1.0"
		if scoring && len(scores) > 0 {
			score = strings.Join(scores, " + ")
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case q.Exists != nil:
		cleanField, fBoost := parseFieldBoost(q.Exists.Field, 1.0)
		pred := t.compileExistsPredicate(cleanField, nctx)
		boost := fBoost
		if q.Exists.Boost != nil {
			boost = *q.Exists.Boost * fBoost
		}
		score := "1.0"
		if boost != 1.0 {
			score = fmt.Sprintf("%.4f", boost)
		}
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case len(q.Prefix) > 0:
		keys := sortedMapKeys(q.Prefix)
		var preds, scores []string
		for _, field := range keys {
			pe := q.Prefix[field]
			cleanField, fBoost := parseFieldBoost(field, 1.0)
			boost := fBoost
			if pe.HasBoost || pe.Boost != 0 {
				boost = pe.Boost * fBoost
			}
			p := t.compilePrefixPredicate(cleanField, pe.Value, pe.CaseInsensitive, nctx)
			preds = append(preds, p)
			if scoring {
				scores = append(scores, fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", p, boost))
			}
		}
		pred := strings.Join(preds, " AND ")
		score := "1.0"
		if scoring && len(scores) > 0 {
			score = strings.Join(scores, " + ")
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case len(q.Wildcard) > 0:
		keys := sortedMapKeys(q.Wildcard)
		var preds, scores []string
		for _, field := range keys {
			we := q.Wildcard[field]
			cleanField, fBoost := parseFieldBoost(field, 1.0)
			boost := fBoost
			if we.HasBoost || we.Boost != 0 {
				boost = we.Boost * fBoost
			}
			p := t.compileWildcardPredicate(cleanField, we.Value, we.CaseInsensitive, nctx)
			preds = append(preds, p)
			if scoring {
				scores = append(scores, fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", p, boost))
			}
		}
		pred := strings.Join(preds, " AND ")
		score := "1.0"
		if scoring && len(scores) > 0 {
			score = strings.Join(scores, " + ")
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	case len(q.Regexp) > 0:
		keys := sortedMapKeys(q.Regexp)
		var preds []string
		var safePreds []string
		var scores []string
		usesFT := false
		compileSingleRegexp := func(field string, re esast.RegexpEntry) (string, string, bool) {
			field, b := t.resolveFieldInNestedCtx(field, true, nctx)
			if !t.checkFieldSearchable(field, b) || b.Kind == schema.StoragePromotedVector {
				return "FALSE", "FALSE", false
			}
			effCI := re.CaseInsensitive || (nctx != nil && b.EffectiveLowercase(true))
			pat := re.Value
			if (effCI || ((nctx == nil || nctx.nestedPath != b.NestedPath) && b.EffectiveLowercase(true))) && !strings.HasPrefix(pat, "(?i)") {
				pat = "(?i)" + pat
			}
			if (nctx == nil || nctx.nestedPath != b.NestedPath) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				arrPred := fmt.Sprintf("array_exists(_x -> _x REGEXP %s, `%s`)", quoteStr(pat), b.EffectiveArrayColumn(true))
				return arrPred, arrPred, false
			}
			col := t.sqlColumnRef(field, true, nctx)
			if b.ESType == "flattened" {
				if isRoot, isSubKey := t.flattenedFieldMode(field, b); isSubKey {
					rawVar := t.flattenedRawVariantRef(field, b, nctx)
					arrPred := fmt.Sprintf("(%s REGEXP %s OR array_exists(_x -> _x REGEXP %s, CAST(%s AS ARRAY<STRING>)))", col, quoteStr(pat), quoteStr(pat), rawVar)
					return arrPred, arrPred, false
				} else if isRoot {
					safePred := fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, quoteStr(pat))
					return fmt.Sprintf("%s REGEXP %s", col, quoteStr(pat)), safePred, false
				}
			}
			if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
				arrPred := fmt.Sprintf("array_exists(_x -> _x REGEXP %s, CAST(%s AS ARRAY<STRING>))", quoteStr(pat), col)
				return arrPred, arrPred, false
			}
			safePred := fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, quoteStr(pat))
			if nctx != nil || b.Kind == schema.StorageDynamicVariant || b.DorisType == schema.DorisVarchar || effCI || strings.HasPrefix(pat, "(?i)") {
				return fmt.Sprintf("%s REGEXP %s", col, quoteStr(pat)), safePred, false
			}
			return fmt.Sprintf("%s MATCH_REGEXP %s", col, quoteStr(pat)), safePred, true
		}
		for _, field := range keys {
			re := q.Regexp[field]
			cleanField, fBoost := parseFieldBoost(field, 1.0)
			fieldBoost := fBoost
			if re.HasBoost || re.Boost != 0 {
				fieldBoost = re.Boost * fBoost
			}
			if strings.ContainsAny(cleanField, "*?") && t.Schema != nil {
				exp := t.expandFieldPatternForContext(cleanField, nctx)
				if len(exp) == 0 {
					if nctx != nil || (cleanField != "*" && len(t.Schema.Fields) > 0) {
						preds = append(preds, "FALSE")
						safePreds = append(safePreds, "FALSE")
						if scoring {
							scores = append(scores, "(CASE WHEN FALSE THEN 0.0000 ELSE 0.0 END)")
						}
						continue
					}
					w, sw, ft := compileSingleRegexp("_all_text", re)
					preds = append(preds, w)
					safePreds = append(safePreds, sw)
					if scoring {
						scores = append(scores, fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", sw, fieldBoost))
					}
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
				var wCombined, swCombined string
				if len(wDisj) == 1 {
					wCombined = wDisj[0]
					swCombined = swDisj[0]
				} else {
					wCombined = "(" + strings.Join(wDisj, " OR ") + ")"
					swCombined = "(" + strings.Join(swDisj, " OR ") + ")"
				}
				preds = append(preds, wCombined)
				safePreds = append(safePreds, swCombined)
				if scoring {
					scores = append(scores, fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", swCombined, fieldBoost))
				}
				continue
			}
			w, sw, ft := compileSingleRegexp(cleanField, re)
			preds = append(preds, w)
			safePreds = append(safePreds, sw)
			if scoring {
				scores = append(scores, fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", sw, fieldBoost))
			}
			usesFT = usesFT || ft
		}
		safeWhere := strings.Join(safePreds, " AND ")
		scoreSQL := "1.0"
		if scoring && len(scores) > 0 {
			scoreSQL = strings.Join(scores, " + ")
		}
		return CompiledQuery{WhereSQL: strings.Join(preds, " AND "), SafeWhereSQL: safeWhere, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}
	case len(q.Match) > 0:
		keys := sortedMapKeys(q.Match)
		if len(keys) == 1 {
			me := q.Match[keys[0]]
			cleanKey0, fBoost := parseFieldBoost(keys[0], 1.0)
			effBoost := me.Boost * fBoost
			qStr := ""
			if me.Query != nil {
				qStr = strings.TrimSpace(fmt.Sprintf("%v", me.Query))
			}
			effKey0, b := t.resolveFieldInNestedCtx(cleanKey0, false, nctx)
			effAnalyzer := me.Analyzer
			if effAnalyzer == "" {
				effAnalyzer = b.Analyzer
			}
			filteredTokens, allStopwords := filterStopwordTokens(qStr, effAnalyzer, me.ZeroTermsQuery)
			if (qStr == "" || allStopwords) && strings.EqualFold(me.ZeroTermsQuery, "all") {
				return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: fmt.Sprintf("%.4f", effBoost)}
			}
			if allStopwords {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			queryForMatch := me.Query
			if len(filteredTokens) > 0 && len(filteredTokens) < len(strings.Fields(qStr)) {
				qStr = strings.Join(filteredTokens, " ")
				queryForMatch = qStr
			}
			if me.MinimumShouldMatch != nil {
				tokens := strings.Fields(qStr)
				if !strings.ContainsAny(cleanKey0, "*?") && isExactKeywordField(effKey0, b) && qStr != "" {
					tokens = []string{qStr}
				}
				if len(tokens) == 1 && parseMinShouldMatch(me.MinimumShouldMatch, 1, true) > 1 {
					return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
				}
				if len(tokens) > 1 && !strings.EqualFold(me.Operator, "and") {
					var shoulds []esast.Query
					for _, tok := range tokens {
						shoulds = append(shoulds, esast.Query{
							Match: map[string]esast.MatchEntry{
								keys[0]: {
									Query:               tok,
									Operator:            "or",
									Fuzziness:           me.Fuzziness,
									PrefixLength:        me.PrefixLength,
									FuzzyTranspositions: me.FuzzyTranspositions,
									Lenient:             me.Lenient,
									Boost:               1.0,
								},
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
			if me.Fuzziness != nil {
				return t.compileFuzzyFieldWithOpts(keys[0], queryForMatch, me.Operator, me.Fuzziness, false, me.PrefixLength, me.FuzzyTranspositions, me.Boost, scoring, nctx)
			}
			return t.compileMatchField(keys[0], queryForMatch, me.Operator, me.Boost, scoring, nctx)
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
			cleanKey0, fBoost := parseFieldBoost(keys[0], 1.0)
			_, b := t.resolveFieldInNestedCtx(cleanKey0, false, nctx)
			effAnalyzer := pe.Analyzer
			if effAnalyzer == "" {
				effAnalyzer = b.Analyzer
			}
			filteredTokens, allStopwords := filterStopwordTokens(pe.Query, effAnalyzer, pe.ZeroTermsQuery)
			if (strings.TrimSpace(pe.Query) == "" || allStopwords) && strings.EqualFold(pe.ZeroTermsQuery, "all") {
				return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: fmt.Sprintf("%.4f", pe.Boost*fBoost)}
			}
			if allStopwords {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			if len(filteredTokens) > 0 && len(filteredTokens) < len(strings.Fields(strings.TrimSpace(pe.Query))) {
				pe.Query = strings.Join(filteredTokens, " ")
			}
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
			cleanKey0, fBoost := parseFieldBoost(keys[0], 1.0)
			_, b := t.resolveFieldInNestedCtx(cleanKey0, false, nctx)
			effAnalyzer := pe.Analyzer
			if effAnalyzer == "" {
				effAnalyzer = b.Analyzer
			}
			filteredTokens, allStopwords := filterStopwordTokens(pe.Query, effAnalyzer, pe.ZeroTermsQuery)
			if (strings.TrimSpace(pe.Query) == "" || allStopwords) && strings.EqualFold(pe.ZeroTermsQuery, "all") {
				return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: fmt.Sprintf("%.4f", pe.Boost*fBoost)}
			}
			if allStopwords {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			if len(filteredTokens) > 0 && len(filteredTokens) < len(strings.Fields(strings.TrimSpace(pe.Query))) {
				pe.Query = strings.Join(filteredTokens, " ")
			}
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
			cleanKey0, fBoost := parseFieldBoost(keys[0], 1.0)
			effBoost := pe.Boost * fBoost
			effKey0, b := t.resolveFieldInNestedCtx(cleanKey0, false, nctx)
			effAnalyzer := pe.Analyzer
			if effAnalyzer == "" {
				effAnalyzer = b.Analyzer
			}
			filteredTokens, allStopwords := filterStopwordTokens(pe.Query, effAnalyzer, pe.ZeroTermsQuery)
			if (strings.TrimSpace(pe.Query) == "" || allStopwords) && strings.EqualFold(pe.ZeroTermsQuery, "all") {
				return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: fmt.Sprintf("%.4f", effBoost)}
			}
			if allStopwords {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			if len(filteredTokens) > 0 && len(filteredTokens) < len(strings.Fields(strings.TrimSpace(pe.Query))) {
				pe.Query = strings.Join(filteredTokens, " ")
			}
			qStr := strings.TrimSpace(pe.Query)
			tokens := strings.Fields(qStr)
			if isExactKeywordField(effKey0, b) && qStr != "" && pe.Fuzziness == nil {
				tokens = []string{qStr}
			}
			if len(tokens) == 1 && pe.MinimumShouldMatch != nil && parseMinShouldMatch(pe.MinimumShouldMatch, 1, true) > 1 {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			if len(tokens) > 1 {
				var shoulds []esast.Query
				for i := 0; i < len(tokens)-1; i++ {
					shoulds = append(shoulds, esast.Query{
						Match: map[string]esast.MatchEntry{
							cleanKey0: {
								Query:               tokens[i],
								Operator:            "or",
								Analyzer:            pe.Analyzer,
								Fuzziness:           pe.Fuzziness,
								PrefixLength:        pe.PrefixLength,
								FuzzyTranspositions: pe.FuzzyTranspositions,
								Lenient:             pe.Lenient,
								Boost:               1.0,
							},
						},
					})
				}
				shoulds = append(shoulds, esast.Query{
					MatchPhrasePrefix: map[string]esast.PhraseEntry{
						cleanKey0: {
							Query:    tokens[len(tokens)-1],
							Analyzer: pe.Analyzer,
							Lenient:  pe.Lenient,
							Boost:    1.0,
						},
					},
				})
				boost := effBoost
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
	case len(q.Common) > 0:
		keys := sortedMapKeys(q.Common)
		if len(keys) == 1 {
			ce := q.Common[keys[0]]
			qStr := ""
			if ce.Query != nil {
				qStr = strings.TrimSpace(fmt.Sprintf("%v", ce.Query))
			}
			if qStr == "" {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			tokens := strings.Fields(qStr)
			lowOp := ce.LowFreqOperator
			if lowOp == "" {
				lowOp = "or"
			}
			highOp := ce.HighFreqOperator
			if highOp == "" {
				highOp = "or"
			}
			var lowFreq, highFreq []string
			for _, tok := range tokens {
				cleanTok := strings.ToLower(strings.Trim(tok, ".,!?;:\"'()[]{}"))
				if ce.CutoffFrequency > 0 && defaultEnglishStopwords[cleanTok] {
					highFreq = append(highFreq, tok)
				} else {
					lowFreq = append(lowFreq, tok)
				}
			}
			activeTokens := lowFreq
			activeOp := lowOp
			if len(activeTokens) == 0 {
				activeTokens = highFreq
				activeOp = highOp
			}
			return t.CompileQuery(&esast.Query{
				Match: map[string]esast.MatchEntry{
					keys[0]: {
						Query:              strings.Join(activeTokens, " "),
						Operator:           activeOp,
						MinimumShouldMatch: ce.MinimumShouldMatch,
						Analyzer:           ce.Analyzer,
						Boost:              ce.Boost,
						HasBoost:           ce.HasBoost,
					},
				},
			}, scoring, nctx)
		}
		var subs []esast.Query
		for _, k := range keys {
			subs = append(subs, esast.Query{Common: map[string]esast.CommonTermsEntry{k: q.Common[k]}})
		}
		return t.compileBool(&esast.BoolQuery{Must: subs}, scoring, nctx)
	case q.MultiMatch != nil:
		return t.compileMultiMatch(q.MultiMatch, scoring, nctx)
	case q.QueryString != nil:
		return t.compileQueryStringEntry(q.QueryString, scoring, nctx, false)
	case q.SimpleQueryString != nil:
		return t.compileQueryStringEntry(q.SimpleQueryString, scoring, nctx, true)
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
			UsesFulltextMatch: false,
		}
	case q.FunctionScore != nil:
		return t.compileFunctionScore(q.FunctionScore, nctx)
	case q.ScriptScore != nil:
		return t.compileScriptScore(q.ScriptScore, scoring, nctx)
	case q.Script != nil:
		return t.compileScriptQuery(q.Script, scoring, nctx)
	case q.KNN != nil:
		return t.compileKNN(q.KNN, scoring, nctx)
	case q.GeoDistance != nil:
		return t.compileGeoDistance(q.GeoDistance, scoring, nctx)
	case q.GeoBoundingBox != nil:
		return t.compileGeoBoundingBox(q.GeoBoundingBox, scoring, nctx)
	case q.GeoPolygon != nil:
		return t.compileGeoPolygon(q.GeoPolygon, scoring, nctx)
	case q.GeoShape != nil:
		return t.compileGeoShape(q.GeoShape, scoring, nctx)
	case q.Wrapper != nil:
		return t.compileWrapperQuery(q.Wrapper, scoring, nctx)
	case q.Pinned != nil:
		return t.compilePinnedQuery(q.Pinned, scoring, nctx)
	case q.MoreLikeThis != nil:
		return t.compileMoreLikeThis(q.MoreLikeThis, scoring, nctx)
	case len(q.Intervals) > 0:
		return t.compileIntervalsQuery(q.Intervals, scoring, nctx)
	case len(q.SpanTerm) > 0 || q.SpanNear != nil || q.SpanOr != nil || q.SpanNot != nil || q.SpanFirst != nil || q.SpanMulti != nil || q.SpanContaining != nil || q.SpanWithin != nil || q.FieldMaskingSpan != nil:
		return t.compileSpanQuery(q, scoring, nctx)
	case q.RankFeature != nil:
		return t.compileRankFeature(q.RankFeature, scoring, nctx)
	case q.DistanceFeature != nil:
		return t.compileDistanceFeature(q.DistanceFeature, scoring, nctx)
	case q.HasChild != nil:
		return t.compileHasChild(q.HasChild, scoring, nctx)
	case q.HasParent != nil:
		return t.compileHasParent(q.HasParent, scoring, nctx)
	case q.ParentID != nil:
		return t.compileParentID(q.ParentID, scoring, nctx)
	case q.Percolate != nil:
		return t.compilePercolate(q.Percolate, scoring, nctx)
	case q.Rule != nil:
		return t.compileRuleQuery(q.Rule, scoring, nctx)
	case q.SparseVector != nil:
		return t.compileSparseVectorQuery(q.SparseVector, scoring, nctx)
	}
	return CompiledQuery{WhereSQL: "TRUE", ScoreSQL: "1.0"}
}

func (t *Transpiler) compileGeoDistance(gd *esast.GeoDistanceQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if gd == nil || gd.Field == "" {
		return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	resolvedField, b := t.resolveFieldInNestedCtx(gd.Field, false, nctx)
	if !t.checkFieldSearchable(resolvedField, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.ESType == "" && gd.IgnoreUnmapped {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.ESType != "" && b.ESType != "geo_point" && b.ESType != "geo_shape" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: failed to find geo_point field [%s]", resolvedField)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	tLonStr := strconv.FormatFloat(gd.Lon, 'f', -1, 64)
	tLatStr := strconv.FormatFloat(gd.Lat, 'f', -1, 64)
	distStr := strconv.FormatFloat(gd.DistanceMeters, 'f', -1, 64)

	var whereSQL string
	if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(resolvedField, nctx.nestedPath+".")) {
		elemExpr := t.sqlColumnRef(resolvedField, true, nctx)
		latExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
		lonExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
		whereSQL = fmt.Sprintf("(%s IS NOT NULL AND ST_Distance_Sphere(%s, %s, %s, %s) <= %s)",
			elemExpr, lonExpr, latExpr, tLonStr, tLatStr, distStr)
	} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
		latExpr := "CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE)"
		lonExpr := "CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE)"
		whereSQL = fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND ST_Distance_Sphere(%s, %s, %s, %s) <= %s, %s)",
			lonExpr, latExpr, tLonStr, tLatStr, distStr, arrCol)
	} else {
		latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(resolvedField, b)
		whereSQL = fmt.Sprintf("(%s AND ST_Distance_Sphere(%s, %s, %s, %s) <= %s)",
			notNullCond, lonExpr, latExpr, tLonStr, tLatStr, distStr)
	}

	scoreSQL := "1.0"
	if scoring && gd.Boost != nil {
		scoreSQL = fmt.Sprintf("%.4f", *gd.Boost)
	}
	return CompiledQuery{
		WhereSQL:     whereSQL,
		SafeWhereSQL: whereSQL,
		ScoreSQL:     scoreSQL,
	}
}

func (t *Transpiler) compileGeoBoundingBox(gb *esast.GeoBoundingBoxQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if gb == nil || gb.Field == "" {
		return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	resolvedField, b := t.resolveFieldInNestedCtx(gb.Field, false, nctx)
	if !t.checkFieldSearchable(resolvedField, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.ESType == "" && gb.IgnoreUnmapped {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.ESType != "" && b.ESType != "geo_point" && b.ESType != "geo_shape" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: failed to find geo_point field [%s]", resolvedField)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	topStr := strconv.FormatFloat(gb.Top, 'f', -1, 64)
	bottomStr := strconv.FormatFloat(gb.Bottom, 'f', -1, 64)
	leftStr := strconv.FormatFloat(gb.Left, 'f', -1, 64)
	rightStr := strconv.FormatFloat(gb.Right, 'f', -1, 64)

	buildBBoxCond := func(latExpr, lonExpr string) string {
		latCond := fmt.Sprintf("%s >= %s AND %s <= %s", latExpr, bottomStr, latExpr, topStr)
		var lonCond string
		if gb.Left <= gb.Right {
			lonCond = fmt.Sprintf("%s >= %s AND %s <= %s", lonExpr, leftStr, lonExpr, rightStr)
		} else {
			lonCond = fmt.Sprintf("(%s >= %s OR %s <= %s)", lonExpr, leftStr, lonExpr, rightStr)
		}
		return fmt.Sprintf("%s AND %s", latCond, lonCond)
	}

	var whereSQL string
	if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(resolvedField, nctx.nestedPath+".")) {
		elemExpr := t.sqlColumnRef(resolvedField, true, nctx)
		latExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
		lonExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
		whereSQL = fmt.Sprintf("(%s IS NOT NULL AND %s)", elemExpr, buildBBoxCond(latExpr, lonExpr))
	} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
		latExpr := "CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE)"
		lonExpr := "CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE)"
		whereSQL = fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND %s, %s)", buildBBoxCond(latExpr, lonExpr), arrCol)
	} else {
		latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(resolvedField, b)
		whereSQL = fmt.Sprintf("(%s AND %s)", notNullCond, buildBBoxCond(latExpr, lonExpr))
	}

	scoreSQL := "1.0"
	if scoring && gb.Boost != nil {
		scoreSQL = fmt.Sprintf("%.4f", *gb.Boost)
	}
	return CompiledQuery{
		WhereSQL:     whereSQL,
		SafeWhereSQL: whereSQL,
		ScoreSQL:     scoreSQL,
	}
}

func (t *Transpiler) extractGeoPointExprs(resolvedField string, b schema.FieldBinding) (latExpr, lonExpr, notNullCond string) {
	if b.Kind == schema.StoragePromotedScalar && b.ColumnName != "" {
		col := fmt.Sprintf("`%s`", b.ColumnName)
		latExpr = fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", col)
		lonExpr = fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", col)
		notNullCond = fmt.Sprintf("%s IS NOT NULL", col)
		return latExpr, lonExpr, notNullCond
	}
	if t.unindexedFields != nil && resolvedField != "" {
		t.unindexedFields[strings.TrimSuffix(resolvedField, ".keyword")] = true
	}
	segs := b.SourceJSONPath
	if len(segs) == 0 {
		segs = strings.Split(resolvedField, ".")
	}
	var pathBuilder strings.Builder
	for _, seg := range segs {
		_, _ = fmt.Fprintf(&pathBuilder, "[%s]", quoteStr(seg))
	}
	docRef := fmt.Sprintf("`_doc`%s", pathBuilder.String())
	latExpr = fmt.Sprintf("COALESCE(CAST(%s['lat'] AS DOUBLE), CAST(SPLIT_PART(CAST(%s AS STRING), ',', 1) AS DOUBLE), CAST(element_at(CAST(%s AS ARRAY<DOUBLE>), 2) AS DOUBLE), CAST(element_at(CAST(%s['coordinates'] AS ARRAY<DOUBLE>), 2) AS DOUBLE))", docRef, docRef, docRef, docRef)
	lonExpr = fmt.Sprintf("COALESCE(CAST(%s['lon'] AS DOUBLE), CAST(SPLIT_PART(CAST(%s AS STRING), ',', 2) AS DOUBLE), CAST(element_at(CAST(%s AS ARRAY<DOUBLE>), 1) AS DOUBLE), CAST(element_at(CAST(%s['coordinates'] AS ARRAY<DOUBLE>), 1) AS DOUBLE))", docRef, docRef, docRef, docRef)
	notNullCond = fmt.Sprintf("%s IS NOT NULL AND %s IS NOT NULL", latExpr, lonExpr)
	return latExpr, lonExpr, notNullCond
}

func (t *Transpiler) compileKNN(kq *esast.KNNQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if kq == nil || kq.Field == "" || len(kq.QueryVector) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	resolvedField, b := t.resolveFieldInNestedCtx(kq.Field, false, nctx)
	if !t.checkFieldSearchable(resolvedField, b) {
		return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.Kind != schema.StoragePromotedVector && b.Kind != schema.StorageDynamicVariant && b.ESType != "dense_vector" && b.ESType != "knn_vector" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("cannot execute knn search on field [%s] of type [%s]", resolvedField, b.ESType)
		}
		return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.VectorDims > 0 && len(kq.QueryVector) != b.VectorDims {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query vector has invalid dimension: [%d], expected [%d] for field [%s]", len(kq.QueryVector), b.VectorDims, resolvedField)
		}
		return CompiledQuery{WhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	var colExpr string
	if b.ColumnName != "" {
		colExpr = fmt.Sprintf("`%s`", b.ColumnName)
	} else {
		if t.unindexedFields != nil && resolvedField != "" {
			t.unindexedFields[strings.TrimSuffix(resolvedField, ".keyword")] = true
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
		fc := t.CompileQuery(&kq.Filter[i], false, nctx)
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
		if k == "_name" && len(m) > 1 {
			continue
		}
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
		if c.WhereSQL == "FALSE" && len(dm.Queries) > 1 {
			continue
		}
		disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
		safeDisjuncts = append(safeDisjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
		if scoring {
			scores = append(scores, c.ScoreSQL)
		}
		usesFT = usesFT || c.UsesFulltextMatch
	}
	if len(disjuncts) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
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
	negBoost := bq.EffectiveNegativeBoost()
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
	if q.Wrapper != nil && q.Wrapper.Decoded != nil && queryContainsScript(q.Wrapper.Decoded) {
		return true
	}
	if q.Pinned != nil && queryContainsScript(q.Pinned.Organic) {
		return true
	}
	if q.Rule != nil && queryContainsScript(q.Rule.Organic) {
		return true
	}
	if q.HasChild != nil && queryContainsScript(&q.HasChild.Query) {
		return true
	}
	if q.HasParent != nil && queryContainsScript(&q.HasParent.Query) {
		return true
	}
	if q.SpanNear != nil {
		for i := range q.SpanNear.Clauses {
			if queryContainsScript(&q.SpanNear.Clauses[i]) {
				return true
			}
		}
	}
	if q.SpanOr != nil {
		for i := range q.SpanOr.Clauses {
			if queryContainsScript(&q.SpanOr.Clauses[i]) {
				return true
			}
		}
	}
	if q.SpanNot != nil && (queryContainsScript(q.SpanNot.Include) || queryContainsScript(q.SpanNot.Exclude)) {
		return true
	}
	if q.SpanFirst != nil && queryContainsScript(q.SpanFirst.Match) {
		return true
	}
	if q.SpanMulti != nil && queryContainsScript(q.SpanMulti.Match) {
		return true
	}
	if q.SpanContaining != nil && (queryContainsScript(q.SpanContaining.Big) || queryContainsScript(q.SpanContaining.Little)) {
		return true
	}
	if q.SpanWithin != nil && (queryContainsScript(q.SpanWithin.Big) || queryContainsScript(q.SpanWithin.Little)) {
		return true
	}
	if q.FieldMaskingSpan != nil && queryContainsScript(q.FieldMaskingSpan.Query) {
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

func queryContainsNestedScoring(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.Nested != nil && !strings.EqualFold(q.Nested.ScoreMode, "none") {
		return true
	}
	if q.ConstantScore != nil && queryContainsNestedScoring(&q.ConstantScore.Filter) {
		return true
	}
	if q.FunctionScore != nil && queryContainsNestedScoring(q.FunctionScore.Query) {
		return true
	}
	if q.ScriptScore != nil && queryContainsNestedScoring(q.ScriptScore.Query) {
		return true
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil && queryContainsNestedScoring(q.Wrapper.Decoded) {
		return true
	}
	if q.Pinned != nil && queryContainsNestedScoring(q.Pinned.Organic) {
		return true
	}
	if q.Rule != nil && queryContainsNestedScoring(q.Rule.Organic) {
		return true
	}
	if q.HasChild != nil && queryContainsNestedScoring(&q.HasChild.Query) {
		return true
	}
	if q.HasParent != nil && queryContainsNestedScoring(&q.HasParent.Query) {
		return true
	}
	if q.SpanNear != nil {
		for i := range q.SpanNear.Clauses {
			if queryContainsNestedScoring(&q.SpanNear.Clauses[i]) {
				return true
			}
		}
	}
	if q.SpanOr != nil {
		for i := range q.SpanOr.Clauses {
			if queryContainsNestedScoring(&q.SpanOr.Clauses[i]) {
				return true
			}
		}
	}
	if q.SpanNot != nil && (queryContainsNestedScoring(q.SpanNot.Include) || queryContainsNestedScoring(q.SpanNot.Exclude)) {
		return true
	}
	if q.SpanFirst != nil && queryContainsNestedScoring(q.SpanFirst.Match) {
		return true
	}
	if q.SpanMulti != nil && queryContainsNestedScoring(q.SpanMulti.Match) {
		return true
	}
	if q.SpanContaining != nil && (queryContainsNestedScoring(q.SpanContaining.Big) || queryContainsNestedScoring(q.SpanContaining.Little)) {
		return true
	}
	if q.SpanWithin != nil && (queryContainsNestedScoring(q.SpanWithin.Big) || queryContainsNestedScoring(q.SpanWithin.Little)) {
		return true
	}
	if q.FieldMaskingSpan != nil && queryContainsNestedScoring(q.FieldMaskingSpan.Query) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryContainsNestedScoring(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil {
		if queryContainsNestedScoring(&q.Boosting.Positive) || queryContainsNestedScoring(&q.Boosting.Negative) {
			return true
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryContainsNestedScoring(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryContainsNestedScoring(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryContainsNestedScoring(&q.Bool.Should[i]) {
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
			usesFT = usesFT || c.UsesFulltextMatch
		}
	}
	for i := range b.Filter {
		c := t.CompileQuery(&b.Filter[i], false, nctx)
		conjuncts = append(conjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
		safeConjuncts = append(safeConjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
	}
	for i := range b.MustNot {
		c := t.CompileQuery(&b.MustNot[i], false, nctx)
		if queryContainsScript(&b.MustNot[i]) && (c.WhereSQL == "" || c.WhereSQL == "TRUE" || strings.Contains(c.WhereSQL, "(TRUE)")) {
			continue
		}
		if c.UsesFulltextMatch || strings.Contains(c.WhereSQL, "MATCH_") || strings.Contains(c.WhereSQL, "SEARCH(") {
			// Doris BE does not allow MATCH_* inside COALESCE(...)
			conjuncts = append(conjuncts, negateFulltextWhereSQL(c.WhereSQL))
		} else {
			conjuncts = append(conjuncts, fmt.Sprintf("NOT COALESCE(%s, FALSE)", c.WhereSQL))
		}
		safeConjuncts = append(safeConjuncts, fmt.Sprintf("NOT COALESCE(%s, FALSE)", c.EffectiveSafeWhere()))
	}
	minShould := 0
	if len(b.Should) > 0 {
		var disjuncts []string
		var safeDisjuncts []string
		shouldUsesFT := false
		for i := range b.Should {
			c := t.CompileQuery(&b.Should[i], scoring, nctx)
			if c.WhereSQL == "FALSE" && len(b.Should) > 1 {
				continue
			}
			disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
			safeDisjuncts = append(safeDisjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
			if scoring {
				scoreTerms = append(scoreTerms, c.ScoreSQL)
				shouldUsesFT = shouldUsesFT || c.UsesFulltextMatch
			}
		}
		minShould = parseMinShouldMatch(b.MinimumShouldMatch, len(b.Should), len(b.Must) == 0 && len(b.Filter) == 0)
		if len(disjuncts) == 0 || minShould > len(disjuncts) {
			if minShould > 0 {
				conjuncts = append(conjuncts, "FALSE")
				safeConjuncts = append(safeConjuncts, "FALSE")
			}
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

	if len(conjuncts) > 0 {
		hasPositive := false
		allPosFalse := true
		for _, cj := range conjuncts {
			if strings.HasPrefix(cj, "NOT ") {
				continue
			}
			hasPositive = true
			if cj != "FALSE" && cj != "(FALSE)" && cj != "((FALSE))" {
				allPosFalse = false
				break
			}
		}
		if hasPositive && allPosFalse {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
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
	if b.DorisType != schema.DorisString && b.DorisType != schema.DorisVarchar && b.DorisType != schema.DorisVariant {
		return b.DorisType
	}
	switch b.ESType {
	case "date", "date_nanos", "long", "unsigned_long":
		return schema.DorisBigInt
	case "integer", "short", "byte", "token_count":
		return schema.DorisInt
	case "double", "float", "half_float", "scaled_float":
		return schema.DorisDouble
	case "boolean":
		return schema.DorisBoolean
	default:
		return b.DorisType
	}
}

func isScalarQueryCompatible(b schema.FieldBinding, queryVal any) bool {
	dt := effectiveDorisScalarType(b)
	s := strings.TrimSpace(fmt.Sprintf("%v", queryVal))
	switch dt {
	case schema.DorisBigInt:
		if b.ESType == "date" || b.ESType == "date_nanos" || b.ESType == "" {
			if _, err := strconv.ParseInt(s, 10, 64); err == nil {
				return true
			}
			if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return true
			}
			_, ok := schema.ParseESDateWithFormatToEpochMillis(s, b.Format, time.Now().UTC())
			return ok
		}
		if _, err := strconv.ParseInt(s, 10, 64); err == nil {
			return true
		}
		if _, err := strconv.ParseUint(s, 10, 64); err == nil {
			return true
		}
		f, err := strconv.ParseFloat(s, 64)
		return err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
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
	if field == "_id" || field == "_index" || field == "_version" || field == "_routing" {
		return true
	}
	return strings.HasSuffix(field, ".keyword") || b.ESType == "keyword" || b.ESType == "constant_keyword"
}

func isZeroFuzziness(fuzz any) bool {
	if fuzz == nil {
		return false
	}
	switch v := fuzz.(type) {
	case int:
		return v <= 0
	case int64:
		return v <= 0
	case float64:
		return v <= 0
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return f <= 0
		}
	case string:
		s := strings.TrimSpace(v)
		if s == "0" || s == "0.0" {
			return true
		}
	}
	return false
}

func resolveFuzzyMaxEdits(fuzz any, wordRuneLen int) int {
	switch v := fuzz.(type) {
	case nil:
		if wordRuneLen >= 6 {
			return 2
		}
		return 1
	case int:
		if v <= 0 {
			return 0
		}
		if v >= 2 {
			return 2
		}
		return 1
	case int64:
		if v <= 0 {
			return 0
		}
		if v >= 2 {
			return 2
		}
		return 1
	case float64:
		if v <= 0 {
			return 0
		}
		if v >= 2 {
			return 2
		}
		return 1
	case json.Number:
		if n, err := v.Int64(); err == nil {
			if n <= 0 {
				return 0
			}
			if n >= 2 {
				return 2
			}
			return 1
		}
		if f, err := v.Float64(); err == nil {
			if f <= 0 {
				return 0
			}
			if f >= 2 {
				return 2
			}
			return 1
		}
	case string:
		s := strings.ToUpper(strings.TrimSpace(v))
		switch s {
		case "0", "0.0":
			return 0
		case "1", "1.0":
			return 1
		case "2", "2.0":
			return 2
		}
		if s == "" || strings.HasPrefix(s, "AUTO") {
			low, high := 3, 6
			if strings.HasPrefix(s, "AUTO:") {
				parts := strings.Split(s[5:], ",")
				if len(parts) == 2 {
					if l, err1 := strconv.Atoi(strings.TrimSpace(parts[0])); err1 == nil {
						low = l
					}
					if h, err2 := strconv.Atoi(strings.TrimSpace(parts[1])); err2 == nil {
						high = h
					}
				}
				if wordRuneLen < low {
					return 0
				}
			}
			if wordRuneLen >= high {
				return 2
			}
			return 1
		}
	}
	return 1
}

func buildFuzzyEditDistanceRegex(word string, maxEdits int, prefixLen int, transpositions bool) string {
	runes := []rune(word)
	n := len(runes)
	if n == 0 {
		return ""
	}
	if n > 32 || maxEdits <= 0 {
		return regexp.QuoteMeta(word)
	}
	if prefixLen < 0 {
		prefixLen = 0
	}
	if prefixLen > n {
		prefixLen = n
	}
	fixedPrefix := ""
	if prefixLen > 0 {
		fixedPrefix = regexp.QuoteMeta(string(runes[:prefixLen]))
	}
	tail := runes[prefixLen:]
	m := len(tail)
	if m == 0 {
		if maxEdits >= 2 {
			return fixedPrefix + ".{0,2}"
		}
		return fixedPrefix + ".?"
	}
	esc := make([]string, m)
	for i, r := range tail {
		esc[i] = regexp.QuoteMeta(string(r))
	}
	seen := make(map[string]bool)
	var alts []string
	addAlt := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			alts = append(alts, p)
		}
	}
	addAlt(fixedPrefix + strings.Join(esc, ""))
	for i := 0; i < m; i++ {
		prefix := strings.Join(esc[:i], "")
		suffix := strings.Join(esc[i+1:], "")
		addAlt(fixedPrefix + prefix + ".?" + suffix)
	}
	for i := 0; i <= m; i++ {
		prefix := strings.Join(esc[:i], "")
		suffix := strings.Join(esc[i:], "")
		addAlt(fixedPrefix + prefix + "." + suffix)
	}
	if transpositions {
		for i := 0; i < m-1; i++ {
			prefix := strings.Join(esc[:i], "")
			suffix := strings.Join(esc[i+2:], "")
			addAlt(fixedPrefix + prefix + esc[i+1] + esc[i] + suffix)
		}
	}
	if maxEdits >= 2 && m <= 12 {
		for i := 0; i < m; i++ {
			for j := i + 1; j < m; j++ {
				p1 := strings.Join(esc[:i], "")
				p2 := strings.Join(esc[i+1:j], "")
				p3 := strings.Join(esc[j+1:], "")
				addAlt(fixedPrefix + p1 + ".?" + p2 + ".?" + p3)
			}
		}
		for i := 0; i <= m; i++ {
			prefix := strings.Join(esc[:i], "")
			suffix := strings.Join(esc[i:], "")
			addAlt(fixedPrefix + prefix + ".{0,2}" + suffix)
		}
		for i := 0; i < m; i++ {
			rem := make([]string, 0, m-1)
			rem = append(rem, esc[:i]...)
			rem = append(rem, esc[i+1:]...)
			for j := 0; j <= len(rem); j++ {
				addAlt(fixedPrefix + strings.Join(rem[:j], "") + ".?" + strings.Join(rem[j:], ""))
			}
		}
		if transpositions {
			for i := 0; i < m-1; i++ {
				swapped := make([]string, m)
				copy(swapped, esc)
				swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
				for j := 0; j < m; j++ {
					addAlt(fixedPrefix + strings.Join(swapped[:j], "") + ".?" + strings.Join(swapped[j+1:], ""))
				}
			}
		}
	}
	return strings.Join(alts, "|")
}

func (t *Transpiler) compileQueryStringEntry(qsq *esast.QueryStringQuery, scoring bool, nctx *nestedCtx, isSimple bool) CompiledQuery {
	if qsq == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	eff := *qsq
	if strings.Contains(eff.DefaultField, "^") && len(eff.Fields) == 0 {
		eff.Fields = []string{eff.DefaultField}
		eff.DefaultField = ""
	}
	if eff.MinimumShouldMatch != nil {
		raw := strings.TrimSpace(eff.Query)
		simpleFlags := parseSimpleQueryFlags(eff.Flags, isSimple)
		tokens := tokenizeLuceneWithFlags(raw, isSimple, simpleFlags)
		if len(tokens) == 1 {
			core := strings.TrimSpace(strings.TrimLeft(tokens[0], "+-!"))
			isGroup := hasMatchingOuterParens(core)
			if !isGroup && !isSimple {
				if colonIdx := strings.IndexByte(core, ':'); colonIdx > 0 && core[colonIdx-1] != '\\' {
					if hasMatchingOuterParens(strings.TrimSpace(core[colonIdx+1:])) {
						isGroup = true
					}
				}
			}
			if !isGroup {
				if parseMinShouldMatch(eff.MinimumShouldMatch, 1, true) > 1 {
					return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
				}
				eff.MinimumShouldMatch = nil
			}
		}
	}
	return t.compileQueryStringWithMode(&eff, scoring, nctx, isSimple)
}

func (t *Transpiler) expandFieldPatternForContext(pattern string, nctx *nestedCtx) []schema.BoostedField {
	if nctx == nil || nctx.nestedPath == "" {
		return t.Schema.ExpandFieldPattern(pattern)
	}
	if t.Schema == nil {
		return nil
	}
	prefix := nctx.nestedPath + "."
	filterNested := func(in []schema.BoostedField) []schema.BoostedField {
		var out []schema.BoostedField
		for _, bf := range in {
			b := t.Schema.ResolveField(bf.Field)
			if b.NestedPath == nctx.nestedPath || strings.HasPrefix(bf.Field, prefix) {
				out = append(out, bf)
			}
		}
		return out
	}
	exp := filterNested(t.Schema.ExpandFieldPattern(pattern))
	if len(exp) == 0 && !strings.HasPrefix(pattern, prefix) {
		exp = filterNested(t.Schema.ExpandFieldPattern(prefix + pattern))
	}
	return exp
}

func parseFieldBoost(fieldWithBoost string, baseBoost float64) (string, float64) {
	if idx := strings.IndexByte(fieldWithBoost, '^'); idx >= 0 {
		cleanField := fieldWithBoost[:idx]
		if parsed, err := strconv.ParseFloat(fieldWithBoost[idx+1:], 64); err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0) {
			return cleanField, baseBoost * parsed
		}
		return cleanField, baseBoost
	}
	return fieldWithBoost, baseBoost
}

func (t *Transpiler) compileFuzzyFieldWithOpts(
	field string,
	queryVal any,
	operator string,
	fuzziness any,
	caseInsensitive bool,
	prefixLength int,
	transpositions *bool,
	boost float64,
	scoring bool,
	nctx *nestedCtx,
) CompiledQuery {
	field, boost = parseFieldBoost(field, boost)
	if isZeroFuzziness(fuzziness) {
		if caseInsensitive {
			resolvedField, b := t.resolveFieldInNestedCtx(field, false, nctx)
			if isExactKeywordField(resolvedField, b) {
				return t.CompileQuery(&esast.Query{
					Term: map[string]esast.TermEntry{
						resolvedField: {Value: queryVal, CaseInsensitive: true, Boost: boost},
					},
				}, scoring, nctx)
			}
		}
		return t.compileMatchField(field, queryVal, operator, boost, scoring, nctx)
	}
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(field, nctx)
		if len(exp) == 0 {
			if nctx != nil || (field != "*" && len(t.Schema.Fields) > 0) {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			return t.compileFuzzyFieldWithOpts("_all_text", queryVal, operator, fuzziness, caseInsensitive, prefixLength, transpositions, boost, scoring, nctx)
		}
		var shoulds []esast.Query
		for _, bf := range exp {
			if caseInsensitive {
				shoulds = append(shoulds, esast.Query{
					Fuzzy: map[string]esast.FuzzyEntry{
						bf.Field: {
							Value:           queryVal,
							Fuzziness:       fuzziness,
							CaseInsensitive: true,
							PrefixLength:    prefixLength,
							Transpositions:  transpositions,
							Boost:           bf.Boost,
						},
					},
				})
			} else {
				shoulds = append(shoulds, esast.Query{
					Match: map[string]esast.MatchEntry{
						bf.Field: {
							Query:               queryVal,
							Operator:            operator,
							Fuzziness:           fuzziness,
							PrefixLength:        prefixLength,
							FuzzyTranspositions: transpositions,
							Boost:               bf.Boost,
						},
					},
				})
			}
		}
		b := boost
		return t.compileBool(&esast.BoolQuery{Should: shoulds, MinimumShouldMatch: 1, Boost: &b}, scoring, nctx)
	}
	resolvedField, b := t.resolveFieldInNestedCtx(field, false, nctx)
	if !t.checkFieldSearchable(resolvedField, b) || b.Kind == schema.StoragePromotedVector {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if effDT := effectiveDorisScalarType(b); (b.Kind == schema.StoragePromotedScalar || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && effDT != schema.DorisString && effDT != schema.DorisVarchar {
		return t.compileMatchField(field, queryVal, operator, boost, scoring, nctx)
	}
	if b.ESType == "ip" || schema.IsRangeFieldType(b.ESType) {
		return t.compileMatchField(field, queryVal, operator, boost, scoring, nctx)
	}
	queryStr := ""
	if queryVal != nil {
		queryStr = strings.TrimSpace(fmt.Sprintf("%v", queryVal))
	}
	if queryVal == nil || queryStr == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	allowTransp := true
	if transpositions != nil {
		allowTransp = *transpositions
	}
	if isExactKeywordField(resolvedField, b) {
		maxEdits := resolveFuzzyMaxEdits(fuzziness, len([]rune(queryStr)))
		if maxEdits <= 0 {
			return t.CompileQuery(&esast.Query{
				Term: map[string]esast.TermEntry{
					resolvedField: {Value: queryVal, CaseInsensitive: caseInsensitive, Boost: boost, HasBoost: true},
				},
			}, scoring, nctx)
		}
		pat := "^(" + buildFuzzyEditDistanceRegex(queryStr, maxEdits, prefixLength, allowTransp) + ")$"
		return t.CompileQuery(&esast.Query{
			Regexp: map[string]esast.RegexpEntry{
				resolvedField: {Value: pat, CaseInsensitive: caseInsensitive || b.EffectiveLowercase(true), Boost: boost, HasBoost: true},
			},
		}, scoring, nctx)
	}
	tokens := strings.Fields(queryStr)
	if len(tokens) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if len(tokens) == 1 {
		maxEdits := resolveFuzzyMaxEdits(fuzziness, len([]rune(tokens[0])))
		if maxEdits <= 0 {
			return t.compileMatchField(field, tokens[0], operator, boost, scoring, nctx)
		}
		pat := "(?i)(^|[^a-zA-Z0-9_])(" + buildFuzzyEditDistanceRegex(tokens[0], maxEdits, prefixLength, allowTransp) + ")($|[^a-zA-Z0-9_])"
		return t.CompileQuery(&esast.Query{
			Regexp: map[string]esast.RegexpEntry{
				resolvedField: {Value: pat, CaseInsensitive: true, Boost: boost},
			},
		}, scoring, nctx)
	}
	var subQueries []esast.Query
	for _, tok := range tokens {
		maxEdits := resolveFuzzyMaxEdits(fuzziness, len([]rune(tok)))
		if maxEdits <= 0 {
			subQueries = append(subQueries, esast.Query{
				Match: map[string]esast.MatchEntry{
					resolvedField: {Query: tok, Operator: "or", Boost: 1.0},
				},
			})
			continue
		}
		pat := "(?i)(^|[^a-zA-Z0-9_])(" + buildFuzzyEditDistanceRegex(tok, maxEdits, prefixLength, allowTransp) + ")($|[^a-zA-Z0-9_])"
		subQueries = append(subQueries, esast.Query{
			Regexp: map[string]esast.RegexpEntry{
				resolvedField: {Value: pat, CaseInsensitive: true, Boost: 1.0},
			},
		})
	}
	bBoost := boost
	if strings.EqualFold(operator, "and") {
		return t.compileBool(&esast.BoolQuery{Must: subQueries, Boost: &bBoost}, scoring, nctx)
	}
	return t.compileBool(&esast.BoolQuery{Should: subQueries, MinimumShouldMatch: 1, Boost: &bBoost}, scoring, nctx)
}

var defaultEnglishStopwords = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
	"be": true, "but": true, "by": true, "for": true, "if": true, "in": true,
	"into": true, "is": true, "it": true, "no": true, "not": true, "of": true,
	"on": true, "or": true, "such": true, "that": true, "the": true, "their": true,
	"then": true, "there": true, "these": true, "they": true, "this": true,
	"to": true, "was": true, "will": true, "with": true,
}

func filterStopwordTokens(qStr string, analyzer string, zeroTermsQuery string) (remaining []string, allFilteredOut bool) {
	trimmed := strings.TrimSpace(qStr)
	if trimmed == "" {
		return nil, false
	}
	rawTokens := strings.Fields(trimmed)
	if len(rawTokens) == 0 {
		return nil, false
	}
	lowerAnalyzer := strings.ToLower(strings.TrimSpace(analyzer))
	shouldFilter := lowerAnalyzer == "stop" || lowerAnalyzer == "english" || strings.EqualFold(zeroTermsQuery, "all")
	if !shouldFilter {
		return rawTokens, false
	}
	var kept []string
	for _, tok := range rawTokens {
		cleanTok := strings.ToLower(strings.Trim(tok, ".,!?;:\"'()[]{}"))
		if cleanTok == "" || defaultEnglishStopwords[cleanTok] {
			continue
		}
		kept = append(kept, tok)
	}
	if len(kept) == 0 {
		return nil, true
	}
	if lowerAnalyzer == "stop" || lowerAnalyzer == "english" {
		return kept, false
	}
	return rawTokens, false
}

func (t *Transpiler) compileMatchField(
	field string,
	queryVal any,
	operator string,
	boost float64,
	scoring bool,
	nctx *nestedCtx,
) CompiledQuery {
	field, boost = parseFieldBoost(field, boost)
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(field, nctx)
		if len(exp) == 0 {
			if nctx != nil || (field != "*" && len(t.Schema.Fields) > 0) {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			return t.compileMatchField("_all_text", queryVal, operator, boost, scoring, nctx)
		}
		var disjuncts, safeDisjuncts, scores []string
		usesFT := false
		for _, bf := range exp {
			c := t.compileMatchField(bf.Field, queryVal, operator, boost*bf.Boost, scoring, nctx)
			if c.WhereSQL == "FALSE" && len(exp) > 1 {
				continue
			}
			disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
			safeDisjuncts = append(safeDisjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
			if scoring {
				scores = append(scores, c.ScoreSQL)
			}
			usesFT = usesFT || c.UsesFulltextMatch
		}
		if len(disjuncts) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		whereSQL := disjuncts[0]
		safeWhereSQL := safeDisjuncts[0]
		if len(disjuncts) > 1 {
			whereSQL = "(" + strings.Join(disjuncts, " OR ") + ")"
			safeWhereSQL = "(" + strings.Join(safeDisjuncts, " OR ") + ")"
		}
		scoreExpr := "0.0"
		if scoring && len(scores) > 0 {
			if len(scores) == 1 {
				scoreExpr = scores[0]
			} else {
				scoreExpr = fmt.Sprintf("GREATEST(%s)", strings.Join(scores, ", "))
			}
		}
		return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreExpr, UsesFulltextMatch: usesFT}
	}
	origField := field
	field, b := t.resolveFieldInNestedCtx(field, false, nctx)
	if !t.checkFieldSearchable(field, b) || b.Kind == schema.StoragePromotedVector {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.ESType == "search_as_you_type" && strings.HasSuffix(origField, "._index_prefix") {
		return t.compileMatchPhraseField(field, fmt.Sprintf("%v", queryVal), 0, boost, true, scoring, nctx)
	}

	// IP fields and non-string promoted scalar/array columns (BIGINT, INT, DOUBLE, BOOLEAN, date) use term/CIDR equality instead of MATCH_*
	if b.ESType == "ip" {
		qStr := strings.TrimSpace(fmt.Sprintf("%v", queryVal))
		if queryVal == nil || qStr == "" {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		_, _, isCIDR := parseCIDRBounds(qStr)
		if !isCIDR && net.ParseIP(qStr) == nil {
			if tokens := strings.Fields(qStr); len(tokens) > 1 {
				var preds []string
				isAnd := strings.EqualFold(operator, "and")
				for _, tok := range tokens {
					tp := t.compileMatchField(field, tok, operator, boost, false, nctx).WhereSQL
					if tp == "FALSE" {
						if isAnd {
							return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
						}
						continue
					}
					preds = append(preds, tp)
				}
				if len(preds) == 0 {
					return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
				}
				joinOp := " OR "
				if isAnd {
					joinOp = " AND "
				}
				pred := preds[0]
				if len(preds) > 1 {
					pred = "(" + strings.Join(preds, joinOp) + ")"
				}
				score := "0.0"
				if scoring {
					score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
				}
				return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		pred := t.compileTermPredicate(field, qStr, false, nctx)
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	}
	if effDT := effectiveDorisScalarType(b); (b.Kind == schema.StoragePromotedScalar || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield || b.ESType != "") && effDT != schema.DorisString && effDT != schema.DorisVarchar && effDT != schema.DorisVariant {
		if !isScalarQueryCompatible(b, queryVal) {
			if tokens := strings.Fields(strings.TrimSpace(fmt.Sprintf("%v", queryVal))); len(tokens) > 1 {
				var preds []string
				isAnd := strings.EqualFold(operator, "and")
				for _, tok := range tokens {
					tp := t.compileMatchField(field, tok, operator, boost, false, nctx).WhereSQL
					if tp == "FALSE" {
						if isAnd {
							return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
						}
						continue
					}
					preds = append(preds, tp)
				}
				if len(preds) == 0 {
					return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
				}
				joinOp := " OR "
				if isAnd {
					joinOp = " AND "
				}
				pred := preds[0]
				if len(preds) > 1 {
					pred = "(" + strings.Join(preds, joinOp) + ")"
				}
				score := "0.0"
				if scoring {
					score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
				}
				return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		pred := t.compileTermPredicate(field, queryVal, false, nctx)
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	}

	if schema.IsRangeFieldType(b.ESType) {
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
	if !isExactKeywordField(field, b) {
		filteredTokens, allStopwords := filterStopwordTokens(queryStr, b.Analyzer, "")
		if allStopwords {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if len(filteredTokens) > 0 && len(filteredTokens) < len(strings.Fields(queryStr)) {
			queryStr = strings.Join(filteredTokens, " ")
		}
	}
	if isExactKeywordField(field, b) && (field == "_id" || field == "_index" || field == "_version" || field == "_routing" || b.ESType == "constant_keyword" || b.NullValue != nil || b.IgnoreAbove > 0 || b.EffectiveLowercase(true) || strings.ContainsAny(strings.TrimSpace(queryStr), " \t\n\r") || strings.ToLower(queryStr) != queryStr || strings.HasSuffix(field, ".keyword")) {
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

	// Inside nested `array_exists(_el -> ...)` lambdas or on untokenized array / dynamic variant columns, use projection-safe matching.
	if nctx != nil || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield || (b.Kind == schema.StorageDynamicVariant && field != "_all_text" && field != "*") {
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
	field, boost = parseFieldBoost(field, boost)
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(field, nctx)
		if len(exp) == 0 {
			if nctx != nil || (field != "*" && len(t.Schema.Fields) > 0) {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			return t.compileMatchPhraseField("_all_text", queryStr, slop, boost, isPrefix, scoring, nctx)
		}
		var disjuncts, safeDisjuncts, scores []string
		usesFT := false
		for _, bf := range exp {
			c := t.compileMatchPhraseField(bf.Field, queryStr, slop, boost*bf.Boost, isPrefix, scoring, nctx)
			if c.WhereSQL == "FALSE" && len(exp) > 1 {
				continue
			}
			disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
			safeDisjuncts = append(safeDisjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
			if scoring {
				scores = append(scores, c.ScoreSQL)
			}
			usesFT = usesFT || c.UsesFulltextMatch
		}
		if len(disjuncts) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		whereSQL := disjuncts[0]
		safeWhereSQL := safeDisjuncts[0]
		if len(disjuncts) > 1 {
			whereSQL = "(" + strings.Join(disjuncts, " OR ") + ")"
			safeWhereSQL = "(" + strings.Join(safeDisjuncts, " OR ") + ")"
		}
		scoreExpr := "0.0"
		if scoring && len(scores) > 0 {
			if len(scores) == 1 {
				scoreExpr = scores[0]
			} else {
				scoreExpr = fmt.Sprintf("GREATEST(%s)", strings.Join(scores, ", "))
			}
		}
		return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreExpr, UsesFulltextMatch: usesFT}
	}
	field, b := t.resolveFieldInNestedCtx(field, false, nctx)
	if !t.checkFieldSearchable(field, b) || b.Kind == schema.StoragePromotedVector || strings.TrimSpace(queryStr) == "" {
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
		if !isScalarQueryCompatible(b, queryStr) {
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
	if !isExactKeywordField(field, b) {
		filteredTokens, allStopwords := filterStopwordTokens(queryStr, b.Analyzer, "")
		if allStopwords {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if len(filteredTokens) > 0 && len(filteredTokens) < len(strings.Fields(strings.TrimSpace(queryStr))) {
			queryStr = strings.Join(filteredTokens, " ")
		}
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
	field, b := t.resolveFieldInNestedCtx(field, false, nctx)
	if isExactKeywordField(field, b) {
		qTrim := strings.TrimSpace(queryStr)
		if b.IgnoreAbove > 0 && len([]rune(qTrim)) > b.IgnoreAbove {
			return "FALSE"
		}
		if (nctx == nil || nctx.nestedPath != b.NestedPath) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
			arrCol := b.EffectiveArrayColumn(true)
			lit := quoteStr(qTrim)
			if b.EffectiveLowercase(true) {
				return fmt.Sprintf("(array_exists(_x -> lower(_x) = lower(%s), `%s`))", lit, arrCol)
			}
			return fmt.Sprintf("(array_exists(_x -> _x = %s, `%s`))", lit, arrCol)
		}
		return "(" + t.compileTermPredicate(field, qTrim, false, nctx) + ")"
	}
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
	var allExpanded []schema.BoostedField
	for _, fpat := range fields {
		if fpat == "_all_text" && nctx != nil {
			if exp := t.expandFieldPatternForContext("*", nctx); len(exp) > 0 {
				allExpanded = append(allExpanded, exp...)
				continue
			}
		}
		allExpanded = append(allExpanded, t.expandFieldPatternForContext(fpat, nctx)...)
	}

	effAnalyzer := mm.Analyzer
	if effAnalyzer == "" && t.Schema != nil && len(allExpanded) > 0 {
		sharedStopAnalyzer := ""
		allShareStop := true
		for _, bf := range allExpanded {
			_, fb := t.resolveFieldInNestedCtx(bf.Field, false, nctx)
			a := strings.ToLower(strings.TrimSpace(fb.Analyzer))
			if a != "stop" && a != "english" {
				allShareStop = false
				break
			}
			if sharedStopAnalyzer == "" {
				sharedStopAnalyzer = a
			}
		}
		if allShareStop && sharedStopAnalyzer != "" {
			effAnalyzer = sharedStopAnalyzer
		}
	}

	qStr := ""
	if mm.Query != nil {
		qStr = strings.TrimSpace(fmt.Sprintf("%v", mm.Query))
	}
	filteredTokens, allStopwords := filterStopwordTokens(qStr, effAnalyzer, mm.ZeroTermsQuery)
	if (qStr == "" || allStopwords) && strings.EqualFold(mm.ZeroTermsQuery, "all") {
		boost := 1.0
		if mm.Boost != nil {
			boost = *mm.Boost
		}
		return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: fmt.Sprintf("%.4f", boost)}
	}
	if qStr == "" || allStopwords {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	effQuery := mm.Query
	if len(filteredTokens) > 0 && len(filteredTokens) < len(strings.Fields(qStr)) {
		qStr = strings.Join(filteredTokens, " ")
		effQuery = qStr
	}
	mmType := strings.ToLower(mm.Type)

	// Term-centric cross_fields (and combined_fields) token splitting
	if mmType == "cross_fields" || mmType == "combined_fields" {
		tokens := strings.Fields(qStr)
		if len(tokens) == 1 && mm.MinimumShouldMatch != nil && parseMinShouldMatch(mm.MinimumShouldMatch, 1, true) > 1 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if len(tokens) > 1 {
			var tokenQueries []esast.Query
			for _, tok := range tokens {
				tokenQueries = append(tokenQueries, esast.Query{
					MultiMatch: &esast.MultiMatchQuery{
						Query:               tok,
						Fields:              fields,
						Type:                "best_fields",
						Operator:            "or",
						Analyzer:            effAnalyzer,
						ZeroTermsQuery:      mm.ZeroTermsQuery,
						Fuzziness:           mm.Fuzziness,
						PrefixLength:        mm.PrefixLength,
						MaxExpansions:       mm.MaxExpansions,
						FuzzyTranspositions: mm.FuzzyTranspositions,
						Lenient:             mm.Lenient,
						TieBreaker:          mm.TieBreaker,
					},
				})
			}
			if strings.EqualFold(op, "and") {
				return t.compileBool(&esast.BoolQuery{
					Must:  tokenQueries,
					Boost: mm.Boost,
				}, scoring, nctx)
			}
			msm := mm.MinimumShouldMatch
			if msm == nil {
				msm = 1
			}
			return t.compileBool(&esast.BoolQuery{
				Should:             tokenQueries,
				MinimumShouldMatch: msm,
				Boost:              mm.Boost,
			}, scoring, nctx)
		}
	}

	var disjuncts []string
	var safeDisjuncts []string
	var scores []string
	usesFT := false

	for _, bf := range allExpanded {
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
						Query:               qStr,
						Operator:            op,
						Analyzer:            mm.Analyzer,
						ZeroTermsQuery:      mm.ZeroTermsQuery,
						MinimumShouldMatch:  mm.MinimumShouldMatch,
						Fuzziness:           mm.Fuzziness,
						PrefixLength:        mm.PrefixLength,
						FuzzyTranspositions: mm.FuzzyTranspositions,
						Lenient:             mm.Lenient,
						Boost:               bf.Boost,
					},
				},
			}, scoring, nctx)
		default:
			if mm.MinimumShouldMatch != nil && mmType != "cross_fields" {
				c = t.CompileQuery(&esast.Query{
					Match: map[string]esast.MatchEntry{
						bf.Field: {
							Query:               effQuery,
							Operator:            op,
							Analyzer:            mm.Analyzer,
							ZeroTermsQuery:      mm.ZeroTermsQuery,
							MinimumShouldMatch:  mm.MinimumShouldMatch,
							Fuzziness:           mm.Fuzziness,
							PrefixLength:        mm.PrefixLength,
							FuzzyTranspositions: mm.FuzzyTranspositions,
							Lenient:             mm.Lenient,
							Boost:               bf.Boost,
						},
					},
				}, scoring, nctx)
			} else if mm.Fuzziness != nil {
				c = t.compileFuzzyFieldWithOpts(bf.Field, effQuery, op, mm.Fuzziness, false, mm.PrefixLength, mm.FuzzyTranspositions, bf.Boost, scoring, nctx)
			} else {
				c = t.compileMatchField(bf.Field, effQuery, op, bf.Boost, scoring, nctx)
			}
		}
		if c.WhereSQL == "FALSE" && len(allExpanded) > 1 {
			continue
		}
		disjuncts = append(disjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
		safeDisjuncts = append(safeDisjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
		if scoring {
			scores = append(scores, c.ScoreSQL)
		}
		usesFT = usesFT || c.UsesFulltextMatch
	}

	if len(disjuncts) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	scoreExpr := "1.0"
	if scoring && len(scores) > 0 {
		if (mmType == "" || mmType == "best_fields" || mmType == "bool_prefix" || mmType == "phrase" || mmType == "phrase_prefix" || mmType == "cross_fields") && len(scores) > 1 {
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

func negateFulltextWhereSQL(whereSQL string) string {
	trimmed := strings.TrimSpace(whereSQL)
	if strings.HasPrefix(trimmed, "`") {
		if endTick := strings.IndexByte(trimmed[1:], '`'); endTick > 0 {
			colIdent := trimmed[:endTick+2]
			rest := strings.TrimSpace(trimmed[endTick+2:])
			if strings.HasPrefix(rest, "MATCH_") && !strings.Contains(rest, " AND ") && !strings.Contains(rest, " OR ") {
				return fmt.Sprintf("(%s IS NULL OR NOT (%s))", colIdent, whereSQL)
			}
		}
	}
	return fmt.Sprintf("NOT (%s)", whereSQL)
}

func (t *Transpiler) compileNestedWithParent(nq *esast.NestedQuery, scoring bool, parentNctx *nestedCtx) CompiledQuery {
	if nq.Path == "" {
		if nq.IgnoreUnmapped {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
	}
	var corrCol string
	var ok bool
	if t.Schema != nil {
		corrCol, ok = t.Schema.NestedRoots[nq.Path]
	}
	if !ok {
		if nq.IgnoreUnmapped {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if t.Schema != nil && (len(t.Schema.Fields) > 0 || len(t.Schema.NestedRoots) > 0) {
			_, isNonNestedField := t.Schema.Fields[nq.Path]
			if isNonNestedField || len(t.Schema.NestedRoots) > 0 || !t.inFilterAggQuery {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("[nested] failed to find nested object under path [%s]", nq.Path)
				}
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
		}
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
	innerWhere := inner.WhereSQL
	if innerWhere == "FALSE" {
		return CompiledQuery{
			WhereSQL:          "FALSE",
			SafeWhereSQL:      "FALSE",
			ScoreSQL:          "0.0",
			UsesFulltextMatch: inner.UsesFulltextMatch,
		}
	}
	if parentNctx != nil && parentNctx.nestedPath != "" && strings.HasPrefix(nq.Path, parentNctx.nestedPath+".") {
		parentCorr := fmt.Sprintf("json_extract_string(%s, '$._parent_id') = json_extract_string(%s, '$._nested_id')", elemVar, parentNctx.elemVar)
		innerWhere = fmt.Sprintf("(%s AND %s)", parentCorr, innerWhere)
	}
	prefilter := t.extractNestedPrefilter(nq.Path, &nq.Query)
	whereSQL := fmt.Sprintf("array_exists(%s -> %s, `%s`)", elemVar, innerWhere, corrCol)
	if prefilter != "" {
		whereSQL = fmt.Sprintf("(%s AND %s)", prefilter, whereSQL)
	}
	scoreSQL := "1.0"
	if strings.EqualFold(nq.ScoreMode, "none") {
		scoreSQL = "0.0"
	} else if scoring {
		outerBoost := 1.0
		if nq.Boost != nil {
			outerBoost = *nq.Boost
		}
		scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", whereSQL, outerBoost)
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
	if ss == nil {
		return base
	}
	scoreSQL := base.ScoreSQL
	scriptCompiled := false
	if ss.Script != nil {
		t.checkScriptDocValues(ss.Script, nctx)
		if expr, ok := t.compileMetricScriptExprWithOverride(ss.Script, "_score", base.ScoreSQL, nctx); ok {
			scoreSQL = expr
			scriptCompiled = true
		}
	}
	if ss.Boost != nil && *ss.Boost != 1.0 {
		scoreSQL = fmt.Sprintf("(%.4f * (%s))", *ss.Boost, scoreSQL)
	}
	whereSQL := base.WhereSQL
	safeWhereSQL := base.EffectiveSafeWhere()
	if ss.MinScore != nil && (ss.Script == nil || scriptCompiled) && !queryContainsScript(ss.Query) && !queryContainsNestedScoring(ss.Query) {
		minScoreCond := fmt.Sprintf("(%s >= %.4f)", scoreSQL, *ss.MinScore)
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
	if !scoring {
		scoreSQL = "1.0"
	}
	return CompiledQuery{
		WhereSQL:          whereSQL,
		SafeWhereSQL:      safeWhereSQL,
		ScoreSQL:          scoreSQL,
		UsesFulltextMatch: base.UsesFulltextMatch,
	}
}

func (t *Transpiler) compileScriptQuery(sq *esast.ScriptQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	boost := 1.0
	if sq != nil && sq.Boost != nil {
		boost = *sq.Boost
	}
	whereSQL := "TRUE"
	if sq != nil && sq.Script != nil {
		t.checkScriptDocValues(sq.Script, nctx)
		if condSQL, ok := t.compileBooleanScriptComparison(sq.Script, nctx); ok && condSQL != "" {
			whereSQL = condSQL
		}
	}
	scoreSQL := "1.0"
	if scoring {
		if whereSQL != "TRUE" {
			scoreSQL = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", whereSQL, boost)
		} else {
			scoreSQL = fmt.Sprintf("%.4f", boost)
		}
	}
	return CompiledQuery{
		WhereSQL:     whereSQL,
		SafeWhereSQL: whereSQL,
		ScoreSQL:     scoreSQL,
	}
}

func (t *Transpiler) compileBooleanScriptComparison(script any, nctx *nestedCtx) (string, bool) {
	s, params, ok := normalizeScriptSourceAndParams(script)
	if !ok || s == "" {
		return "", false
	}
	if strings.ContainsAny(s, ";?") || strings.Contains(s, "def ") || strings.Contains(s, "for ") ||
		strings.Contains(s, "while ") || strings.Contains(s, "if ") || strings.Contains(s, "ctx.") ||
		strings.Contains(s, "_source") || strings.Contains(s, ".contains(") || strings.Contains(s, "=~") ||
		strings.Contains(s, "_score") {
		return "", false
	}
	return t.parseBooleanScriptCond(s, params, nctx, 0)
}

func (t *Transpiler) parseBooleanScriptCond(s string, params map[string]any, nctx *nestedCtx, depth int) (string, bool) {
	if depth > 12 {
		return "", false
	}
	s = strings.TrimSpace(s)
	for hasMatchingThresholdParens(s) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	if s == "" {
		return "", false
	}
	if s == "true" {
		return "TRUE", true
	}
	if s == "false" {
		return "FALSE", true
	}
	for _, logOp := range []struct{ op, sqlOp string }{{"||", " OR "}, {"&&", " AND "}} {
		if parts := splitTopLevelScriptToken(s, logOp.op); len(parts) > 1 {
			var compiledParts []string
			for _, p := range parts {
				cp, ok := t.parseBooleanScriptCond(p, params, nctx, depth+1)
				if !ok {
					return "", false
				}
				compiledParts = append(compiledParts, fmt.Sprintf("(%s)", cp))
			}
			return "(" + strings.Join(compiledParts, logOp.sqlOp) + ")", true
		}
	}
	if strings.HasPrefix(s, "!") {
		inner := strings.TrimSpace(s[1:])
		if field, tail, ok := parseDocFieldAccess(inner); ok && tail == ".empty" {
			resolved, b := t.resolveFieldInNestedCtx(field, true, nctx)
			t.checkFieldDocValues(resolved, b)
			return t.compileExistsPredicate(field, nctx), true
		}
		if cp, ok := t.parseBooleanScriptCond(inner, params, nctx, depth+1); ok {
			if cp == "TRUE" {
				return "FALSE", true
			}
			if cp == "FALSE" {
				return "TRUE", true
			}
			return fmt.Sprintf("NOT COALESCE(%s, FALSE)", cp), true
		}
		return "", false
	}
	if field, tail, ok := parseDocFieldAccess(s); ok && tail == ".empty" {
		resolved, b := t.resolveFieldInNestedCtx(field, true, nctx)
		t.checkFieldDocValues(resolved, b)
		return fmt.Sprintf("NOT COALESCE(%s, FALSE)", t.compileExistsPredicate(field, nctx)), true
	}
	resolveBoolLit := func(raw string) (bool, bool) {
		if raw == "true" {
			return true, true
		}
		if raw == "false" {
			return false, true
		}
		if strings.HasPrefix(raw, "params.") && params != nil {
			if bv, ok := params[strings.TrimPrefix(raw, "params.")].(bool); ok {
				return bv, true
			}
		}
		return false, false
	}
	for _, cmpOp := range []struct{ op, sqlOp string }{
		{">=", ">="},
		{"<=", "<="},
		{"!=", "!="},
		{"==", "="},
		{">", ">"},
		{"<", "<"},
	} {
		if parts := splitTopLevelScriptToken(s, cmpOp.op); len(parts) == 2 {
			lhsRaw := strings.TrimSpace(parts[0])
			rhsRaw := strings.TrimSpace(parts[1])
			if !t.scriptSideUsesOnlyScalarOrSize(lhsRaw, nctx) || !t.scriptSideUsesOnlyScalarOrSize(rhsRaw, nctx) {
				return "", false
			}
			if cmpOp.op == "==" || cmpOp.op == "!=" {
				checkBoolFieldVsLit := func(fieldRaw, litRaw string) (string, bool) {
					field, tail, okF := parseDocFieldAccess(fieldRaw)
					bv, okB := resolveBoolLit(litRaw)
					if !okF || (tail != "" && tail != ".value") || !okB || t.Schema == nil {
						return "", false
					}
					resolved, b := t.resolveFieldInNestedCtx(field, true, nctx)
					if effectiveDorisScalarType(b) != schema.DorisBoolean {
						return "", false
					}
					t.checkFieldDocValues(resolved, b)
					target := bv
					if cmpOp.op == "!=" {
						target = !bv
					}
					return t.compileTermPredicate(field, target, false, nctx), true
				}
				if cond, ok := checkBoolFieldVsLit(lhsRaw, rhsRaw); ok {
					return cond, true
				}
				if cond, ok := checkBoolFieldVsLit(rhsRaw, lhsRaw); ok {
					return cond, true
				}
			}
			if strL, isStrL, okL := t.parseStringScriptExpr(lhsRaw, params, "", "", nctx, 0); okL {
				if strR, isStrR, okR := t.parseStringScriptExpr(rhsRaw, params, "", "", nctx, 0); okR && (isStrL || isStrR) {
					return fmt.Sprintf("(%s %s %s)", strL, cmpOp.sqlOp, strR), true
				}
			}
			numL, okL := t.parseMetricScriptExpr(lhsRaw, params, "", "", nctx, 0)
			numR, okR := t.parseMetricScriptExpr(rhsRaw, params, "", "", nctx, 0)
			if okL && okR {
				return fmt.Sprintf("(%s %s %s)", numL, cmpOp.sqlOp, numR), true
			}
			return "", false
		}
	}
	if bv, ok := resolveBoolLit(s); ok {
		if bv {
			return "TRUE", true
		}
		return "FALSE", true
	}
	if field, tail, ok := parseDocFieldAccess(s); ok && (tail == "" || tail == ".value") {
		if t.Schema != nil && t.scriptSideUsesOnlyScalarOrSize(s, nctx) {
			resolved, b := t.resolveFieldInNestedCtx(field, true, nctx)
			if effectiveDorisScalarType(b) == schema.DorisBoolean {
				t.checkFieldDocValues(resolved, b)
				return t.compileTermPredicate(field, true, false, nctx), true
			}
		}
	}
	return "", false
}

func (t *Transpiler) scriptSideUsesOnlyScalarOrSize(expr string, nctx *nestedCtx) bool {
	rest := expr
	for {
		idx := strings.Index(rest, "doc[")
		if idx < 0 {
			break
		}
		sub := rest[idx:]
		field, tail, ok := parseDocFieldAccess(sub)
		if !ok {
			return false
		}
		if !strings.HasPrefix(tail, ".size()") && !strings.HasPrefix(tail, ".length") && !strings.HasPrefix(tail, ".empty") {
			if t.Schema != nil {
				_, b := t.resolveFieldInNestedCtx(field, true, nctx)
				if b.IsMultiValued || b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) || b.Kind == schema.StoragePromotedVector {
					return false
				}
			}
		}
		rest = sub[4:]
	}
	return true
}

func splitTopLevelScriptToken(s string, op string) []string {
	var parts []string
	depth := 0
	var inQuote byte
	lastStart := 0
	for i := 0; i <= len(s)-len(op); i++ {
		ch := s[i]
		if inQuote != 0 {
			if ch == '\\' {
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
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && s[i:i+len(op)] == op {
				if len(op) == 1 && (op == ">" || op == "<") && i+1 < len(s) && s[i+1] == '=' {
					continue
				}
				parts = append(parts, s[lastStart:i])
				lastStart = i + len(op)
				i += len(op) - 1
			}
		}
	}
	if len(parts) > 0 {
		parts = append(parts, s[lastStart:])
	}
	return parts
}

func (t *Transpiler) extractNestedPrefilter(nestedPath string, q *esast.Query) string {
	if q == nil {
		return ""
	}
	nctx := &nestedCtx{nestedPath: nestedPath}
	if len(q.Term) > 0 {
		var parts []string
		for _, field := range sortedMapKeys(q.Term) {
			entry := q.Term[field]
			cleanField, _ := parseFieldBoost(field, 1.0)
			_, b := t.resolveFieldInNestedCtx(cleanField, true, nctx)
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
				if normStr, ok := normalizeNestedPrefilterValue(b, entry.Value, effLower, time.Now().UTC()); ok {
					parts = append(parts, fmt.Sprintf("array_contains(`%s`, %s)", arrCol, quoteStr(normStr)))
				}
			}
		}
		return strings.Join(parts, " AND ")
	}
	if q.Terms != nil && len(q.Terms.Fields) > 0 {
		var parts []string
		for _, field := range sortedMapKeys(q.Terms.Fields) {
			vals := q.Terms.Fields[field]
			cleanField, _ := parseFieldBoost(field, 1.0)
			_, b := t.resolveFieldInNestedCtx(cleanField, true, nctx)
			if b.Kind == schema.StorageNestedSubfield && b.NestedPath == nestedPath && b.PrefilterArrayCol != "" && len(vals) > 0 {
				effLower := b.EffectiveLowercase(true)
				if q.Terms.CaseInsensitive && !effLower {
					continue
				}
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
				allValid := true
				for _, v := range vals {
					if normStr, ok := normalizeNestedPrefilterValue(b, v, effLower, now); ok {
						quoted = append(quoted, quoteStr(normStr))
					} else {
						allValid = false
						break
					}
				}
				if allValid && len(quoted) > 0 {
					parts = append(parts, fmt.Sprintf("arrays_overlap(`%s`, [%s])", arrCol, strings.Join(quoted, ", ")))
				}
			}
		}
		return strings.Join(parts, " AND ")
	}
	if q.Exists != nil && q.Exists.Field != "" {
		preferKw := strings.HasSuffix(q.Exists.Field, ".keyword")
		_, b := t.resolveFieldInNestedCtx(q.Exists.Field, preferKw, nctx)
		if strings.HasSuffix(b.AliasTarget, ".keyword") {
			preferKw = true
		}
		if b.Kind == schema.StorageNestedSubfield && b.NestedPath == nestedPath && b.PrefilterArrayCol != "" {
			arrCol := b.EffectiveArrayColumn(preferKw)
			return fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", arrCol, arrCol)
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

func normalizeNestedPrefilterValue(b schema.FieldBinding, val any, effLower bool, now time.Time) (string, bool) {
	if val == nil {
		return "", false
	}
	effDT := effectiveDorisScalarType(b)
	if b.ESType == "boolean" || effDT == schema.DorisBoolean {
		bv, ok := normalizeBooleanQueryValue(val)
		if !ok {
			return "", false
		}
		if bv {
			return "true", true
		}
		return "false", true
	}
	if strVal, ok := val.(string); ok {
		if effLower && effDT != schema.DorisBigInt && effDT != schema.DorisInt && effDT != schema.DorisDouble && b.ESType != "date" && b.ESType != "date_nanos" {
			val = strings.ToLower(strVal)
		} else if b.ESType == "date" || b.ESType == "date_nanos" || (b.ESType == "" && effDT == schema.DorisBigInt) {
			ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, b.Format, now)
			if !ok {
				return "", false
			}
			val = ms
		} else if effDT == schema.DorisBigInt || effDT == schema.DorisInt {
			trimmed := strings.TrimSpace(strVal)
			if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				val = iv
			} else if b.ESType == "unsigned_long" {
				if u, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
					val = u
				} else if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= 0 && fv < 18446744073709551616.0 && fv == math.Trunc(fv) {
					val = uint64(fv)
				} else {
					return "", false
				}
			} else if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) && fv >= float64(math.MinInt64) && fv < 9223372036854775808.0 {
				val = int64(fv)
			} else {
				return "", false
			}
		} else if effDT == schema.DorisDouble {
			trimmed := strings.TrimSpace(strVal)
			fv, err := strconv.ParseFloat(trimmed, 64)
			if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
				return "", false
			}
			val = fv
		}
	}
	val = normalizeScaledFloatValue(b, val)
	val = normalizeDateNanosValue(b.ESType, val)
	switch tv := val.(type) {
	case int64:
		return strconv.FormatInt(tv, 10), true
	case uint64:
		return strconv.FormatUint(tv, 10), true
	case int:
		return strconv.Itoa(tv), true
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return "", false
		}
		return strconv.FormatFloat(tv, 'f', -1, 64), true
	case json.Number:
		if effDT == schema.DorisBigInt || effDT == schema.DorisInt {
			if iv, err := tv.Int64(); err == nil {
				return strconv.FormatInt(iv, 10), true
			}
			if b.ESType == "unsigned_long" {
				if u, err := strconv.ParseUint(tv.String(), 10, 64); err == nil {
					return strconv.FormatUint(u, 10), true
				}
			}
			if fv, err := tv.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) && fv >= float64(math.MinInt64) && fv < 9223372036854775808.0 {
				return strconv.FormatInt(int64(fv), 10), true
			}
			return "", false
		}
		if effDT == schema.DorisDouble {
			if fv, err := tv.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				return strconv.FormatFloat(fv, 'f', -1, 64), true
			}
			return "", false
		}
		return tv.String(), true
	default:
		return fmt.Sprintf("%v", val), true
	}
}

func (t *Transpiler) compileFunctionScore(fs *esast.FunctionScoreQuery, nctx *nestedCtx) CompiledQuery {
	base := CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: "1.0"}
	if fs.Query != nil {
		base = t.CompileQuery(fs.Query, true, nctx)
	}
	hasUncompilableScriptFn := false
	if fs.ScriptScore != nil {
		t.checkScriptDocValues(fs.ScriptScore.Script, nctx)
		if _, ok := t.compileMetricScriptExprWithOverride(fs.ScriptScore.Script, "_score", base.ScoreSQL, nctx); !ok {
			hasUncompilableScriptFn = true
		}
	}
	if fs.FieldValueFactor != nil && fs.FieldValueFactor.Field != "" {
		resolvedFVF, bFVF := t.resolveFieldInNestedCtx(fs.FieldValueFactor.Field, true, nctx)
		t.checkFieldDocValues(resolvedFVF, bFVF)
	}
	for _, df := range []*esast.DecayFunctionSpec{fs.Gauss, fs.Exp, fs.Linear} {
		if df != nil && df.Field != "" {
			resolvedDF, bDF := t.resolveFieldInNestedCtx(df.Field, true, nctx)
			t.checkFieldDocValues(resolvedDF, bDF)
		}
	}
	for i := range fs.Functions {
		if fs.Functions[i].FieldValueFactor != nil && fs.Functions[i].FieldValueFactor.Field != "" {
			resolvedFVF, bFVF := t.resolveFieldInNestedCtx(fs.Functions[i].FieldValueFactor.Field, true, nctx)
			t.checkFieldDocValues(resolvedFVF, bFVF)
		}
		for _, df := range []*esast.DecayFunctionSpec{fs.Functions[i].Gauss, fs.Functions[i].Exp, fs.Functions[i].Linear} {
			if df != nil && df.Field != "" {
				resolvedDF, bDF := t.resolveFieldInNestedCtx(df.Field, true, nctx)
				t.checkFieldDocValues(resolvedDF, bDF)
			}
		}
		if fs.Functions[i].ScriptScore != nil {
			t.checkScriptDocValues(fs.Functions[i].ScriptScore.Script, nctx)
		}
		if queryContainsScript(fs.Functions[i].Filter) {
			hasUncompilableScriptFn = true
			break
		}
		if fs.Functions[i].ScriptScore != nil {
			if _, ok := t.compileMetricScriptExprWithOverride(fs.Functions[i].ScriptScore.Script, "_score", base.ScoreSQL, nctx); !ok {
				hasUncompilableScriptFn = true
				break
			}
		}
	}
	if hasUncompilableScriptFn {
		if fs.Boost != nil && *fs.Boost != 1.0 {
			base.ScoreSQL = fmt.Sprintf("(%.4f * (%s))", *fs.Boost, base.ScoreSQL)
		}
		return base
	}
	funcs := fs.Functions
	if len(funcs) == 0 && (fs.FieldValueFactor != nil || fs.ScriptScore != nil || fs.RandomScore != nil || fs.Gauss != nil || fs.Exp != nil || fs.Linear != nil || fs.Weight != nil) {
		funcs = []esast.ScoreFunctionSpec{
			{
				Weight:           fs.Weight,
				FieldValueFactor: fs.FieldValueFactor,
				ScriptScore:      fs.ScriptScore,
				RandomScore:      fs.RandomScore,
				Gauss:            fs.Gauss,
				Exp:              fs.Exp,
				Linear:           fs.Linear,
			},
		}
	}
	if len(funcs) == 0 {
		if fs.BoostMode != "" || fs.MaxBoost != nil {
			combinedFuncs := "1.0"
			if fs.MaxBoost != nil {
				combinedFuncs = fmt.Sprintf("LEAST(%.4f, 1.0)", *fs.MaxBoost)
			}
			switch strings.ToLower(fs.BoostMode) {
			case "sum":
				base.ScoreSQL = fmt.Sprintf("((%s) + (%s))", base.ScoreSQL, combinedFuncs)
			case "avg":
				base.ScoreSQL = fmt.Sprintf("(((%s) + (%s)) / 2.0)", base.ScoreSQL, combinedFuncs)
			case "max":
				base.ScoreSQL = fmt.Sprintf("GREATEST(%s, %s)", base.ScoreSQL, combinedFuncs)
			case "min":
				base.ScoreSQL = fmt.Sprintf("LEAST(%s, %s)", base.ScoreSQL, combinedFuncs)
			case "replace":
				base.ScoreSQL = combinedFuncs
			default:
				base.ScoreSQL = fmt.Sprintf("((%s) * (%s))", base.ScoreSQL, combinedFuncs)
			}
		}
		if fs.Boost != nil && *fs.Boost != 1.0 {
			base.ScoreSQL = fmt.Sprintf("(%.4f * (%s))", *fs.Boost, base.ScoreSQL)
		}
		if fs.MinScore != nil && !queryContainsScript(fs.Query) && !queryContainsNestedScoring(fs.Query) {
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
		if fn.ScriptScore != nil && fn.ScriptScore.Script != nil {
			if scriptExpr, ok := t.compileMetricScriptExprWithOverride(fn.ScriptScore.Script, "_score", base.ScoreSQL, nctx); ok {
				if fn.Weight != nil {
					valExpr = fmt.Sprintf("(%.4f * (%s))", weight, scriptExpr)
				} else {
					valExpr = scriptExpr
				}
			}
		} else if fn.FieldValueFactor != nil {
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
		} else if fn.RandomScore != nil {
			seedRaw := fn.RandomScore.Seed
			fieldRaw := fn.RandomScore.Field
			fieldCol := "`_id`"
			if fieldRaw != "" && fieldRaw != "_id" && fieldRaw != "_seq_no" && fieldRaw != "_uid" {
				fieldCol = t.sqlColumnRef(fieldRaw, true, nctx)
			}
			var randExpr string
			if seedRaw != nil {
				seedStr := quoteStr(fmt.Sprintf("%v", seedRaw))
				randExpr = fmt.Sprintf("(ABS(CAST(CONV(SUBSTRING(MD5(CONCAT(%s, ':', COALESCE(CAST(%s AS STRING), ''))), 1, 8), 16, 10) AS DOUBLE)) / 4294967296.0)", seedStr, fieldCol)
			} else {
				randExpr = "RAND()"
			}
			if fn.Weight != nil {
				valExpr = fmt.Sprintf("(%.4f * %s)", weight, randExpr)
			} else {
				valExpr = randExpr
			}
		} else if fn.Gauss != nil || fn.Exp != nil || fn.Linear != nil {
			var decayType string
			var df *esast.DecayFunctionSpec
			switch {
			case fn.Gauss != nil:
				decayType = "gauss"
				df = fn.Gauss
			case fn.Exp != nil:
				decayType = "exp"
				df = fn.Exp
			case fn.Linear != nil:
				decayType = "linear"
				df = fn.Linear
			}
			decayExpr := t.compileDecayFunction(decayType, df, nctx)
			if fn.Weight != nil {
				valExpr = fmt.Sprintf("(%.4f * (%s))", weight, decayExpr)
			} else {
				valExpr = decayExpr
			}
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
			} else if scoreMode == "max" {
				elseVal = "-1e308"
			} else if scoreMode == "min" {
				elseVal = "1e308"
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
		if len(funcExprs) == 1 && !hasUnfilteredFunc {
			combinedFuncs = rawValExprs[0]
		} else if len(funcExprs) == 1 {
			combinedFuncs = funcExprs[0]
		} else {
			combinedFuncs = fmt.Sprintf("GREATEST(%s)", strings.Join(funcExprs, ", "))
		}
	case "min":
		if len(funcExprs) == 1 && !hasUnfilteredFunc {
			combinedFuncs = rawValExprs[0]
		} else if len(funcExprs) == 1 {
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
	if fs.MinScore != nil && !hasUncompilableScriptFn && !queryContainsScript(fs.Query) && !queryContainsNestedScoring(fs.Query) {
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

func resolveDecayArrayFn(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "max":
		return "array_max"
	case "avg":
		return "array_avg"
	case "sum":
		return "array_sum"
	default:
		return "array_min"
	}
}

func (t *Transpiler) compileDecayFunction(decayType string, df *esast.DecayFunctionSpec, nctx *nestedCtx) string {
	if df == nil || df.Field == "" {
		return "1.0"
	}
	decay := 0.5
	if df.Decay != nil && *df.Decay > 0 && *df.Decay < 1.0 {
		decay = *df.Decay
	}
	resolvedField, b := t.resolveFieldInNestedCtx(df.Field, true, nctx)

	isGeo := b.ESType == "geo_point"
	if !isGeo && b.Kind == schema.StorageDynamicVariant {
		if _, _, err := esast.ParseGeoPoint(df.Origin); err == nil {
			if _, _, errScale := esast.ParseGeoDistanceMeters(df.Scale); errScale == nil {
				if _, isNum := parseDecayNumericValue(df.Origin); !isNum {
					isGeo = true
				}
			}
		}
	}

	var distExpr string
	var notNullCond string
	var scaleVal float64
	var offsetVal float64
	isArrayField := (b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.elemVar == "" || nctx.nestedPath != b.NestedPath))) && b.EffectiveArrayColumn(true) != ""

	if isGeo {
		lat, lon, err := esast.ParseGeoPoint(df.Origin)
		if err != nil {
			return "1.0"
		}
		_, sMeters, err := esast.ParseGeoDistanceMeters(df.Scale)
		if err != nil || sMeters <= 0 {
			return "1.0"
		}
		scaleVal = sMeters
		if df.Offset != nil {
			if _, oMeters, err := esast.ParseGeoDistanceMeters(df.Offset); err == nil && oMeters >= 0 {
				offsetVal = oMeters
			}
		}
		tLonStr := strconv.FormatFloat(lon, 'f', -1, 64)
		tLatStr := strconv.FormatFloat(lat, 'f', -1, 64)
		if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(resolvedField, nctx.nestedPath+".")) {
			elemExpr := t.sqlColumnRef(resolvedField, true, nctx)
			latExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
			lonExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
			notNullCond = fmt.Sprintf("%s IS NOT NULL", elemExpr)
			distExpr = fmt.Sprintf("COALESCE(ST_Distance_Sphere(%s, %s, %s, %s), 0.0)", lonExpr, latExpr, tLonStr, tLatStr)
		} else if isArrayField {
			arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
			notNullCond = fmt.Sprintf("(%s IS NOT NULL AND array_size(%s) > 0)", arrCol, arrCol)
			arrFn := resolveDecayArrayFn(df.MultiValueMode)
			distExpr = fmt.Sprintf("COALESCE(%s(array_map(_x -> ST_Distance_Sphere(CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE), CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE), %s, %s), %s)), 0.0)", arrFn, tLonStr, tLatStr, arrCol)
		} else {
			var latExpr, lonExpr string
			latExpr, lonExpr, notNullCond = t.extractGeoPointExprs(resolvedField, b)
			distExpr = fmt.Sprintf("COALESCE(ST_Distance_Sphere(%s, %s, %s, %s), 0.0)", lonExpr, latExpr, tLonStr, tLatStr)
		}
	} else if b.ESType == "date" || b.ESType == "date_nanos" || isDateDecayOriginAndScale(df.Origin, df.Scale) {
		originMs, ok := parseDecayDateOriginMillis(df.Origin, b.Format, time.Now().UTC())
		if !ok {
			return "1.0"
		}
		if b.ESType == "date_nanos" {
			if niv, okN := normalizeDateNanosValue(b.ESType, originMs).(int64); okN {
				originMs = niv
			}
		}
		scaleMs, ok := parseDecayDurationMillis(df.Scale)
		if !ok || scaleMs <= 0 {
			return "1.0"
		}
		scaleVal = scaleMs
		if df.Offset != nil {
			if offMs, ok := parseDecayDurationMillis(df.Offset); ok && offMs >= 0 {
				offsetVal = offMs
			}
		}
		if isArrayField {
			arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
			notNullCond = fmt.Sprintf("(%s IS NOT NULL AND array_size(%s) > 0)", arrCol, arrCol)
			arrFn := resolveDecayArrayFn(df.MultiValueMode)
			distExpr = fmt.Sprintf("COALESCE(%s(array_map(_x -> ABS(CAST(_x AS DOUBLE) - %.4f), %s)), 0.0)", arrFn, float64(originMs), arrCol)
		} else {
			col := t.sqlNumericColumnRef(df.Field, nctx)
			notNullCond = fmt.Sprintf("%s IS NOT NULL", col)
			distExpr = fmt.Sprintf("ABS(COALESCE(%s, %.4f) - %.4f)", col, float64(originMs), float64(originMs))
		}
	} else {
		originNum, ok := parseDecayNumericValue(df.Origin)
		if !ok {
			return "1.0"
		}
		scaleNum, ok := parseDecayNumericValue(df.Scale)
		if !ok || scaleNum <= 0 {
			return "1.0"
		}
		scaleVal = scaleNum
		if df.Offset != nil {
			if offNum, ok := parseDecayNumericValue(df.Offset); ok && offNum >= 0 {
				offsetVal = offNum
			}
		}
		if isArrayField {
			arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
			notNullCond = fmt.Sprintf("(%s IS NOT NULL AND array_size(%s) > 0)", arrCol, arrCol)
			arrFn := resolveDecayArrayFn(df.MultiValueMode)
			distExpr = fmt.Sprintf("COALESCE(%s(array_map(_x -> ABS(CAST(_x AS DOUBLE) - %.4f), %s)), 0.0)", arrFn, originNum, arrCol)
		} else {
			col := t.sqlNumericColumnRef(df.Field, nctx)
			notNullCond = fmt.Sprintf("%s IS NOT NULL", col)
			distExpr = fmt.Sprintf("ABS(COALESCE(%s, %.4f) - %.4f)", col, originNum, originNum)
		}
	}

	effDist := fmt.Sprintf("GREATEST(0.0, (%s) - %.4f)", distExpr, offsetVal)
	var rawDecayExpr string
	switch decayType {
	case "gauss":
		coeff := math.Log(decay) / (scaleVal * scaleVal)
		rawDecayExpr = fmt.Sprintf("EXP(%s * POW(%s, 2))", strconv.FormatFloat(coeff, 'g', 10, 64), effDist)
	case "exp":
		coeff := math.Log(decay) / scaleVal
		rawDecayExpr = fmt.Sprintf("EXP(%s * (%s))", strconv.FormatFloat(coeff, 'g', 10, 64), effDist)
	case "linear":
		slope := (1.0 - decay) / scaleVal
		rawDecayExpr = fmt.Sprintf("GREATEST(0.0, 1.0 - (%s * (%s)))", strconv.FormatFloat(slope, 'g', 10, 64), effDist)
	default:
		return "1.0"
	}
	if notNullCond != "" {
		return fmt.Sprintf("(CASE WHEN %s THEN %s ELSE 0.0 END)", notNullCond, rawDecayExpr)
	}
	return rawDecayExpr
}

func parseDecayNumericValue(raw any) (float64, bool) {
	switch v := raw.(type) {
	case float64:
		return v, !math.IsNaN(v) && !math.IsInf(v, 0)
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return 0, false
	}
}

func isDateDecayOriginAndScale(origin, scale any) bool {
	if _, isNum := parseDecayNumericValue(scale); isNum {
		return false
	}
	_, ok := parseDecayDurationMillis(scale)
	return ok
}

func parseDecayDateOriginMillis(raw any, format string, now time.Time) (int64, bool) {
	if f, ok := parseDecayNumericValue(raw); ok {
		return int64(f), true
	}
	if s, ok := raw.(string); ok {
		return schema.ParseESDateWithFormatToEpochMillis(s, format, now)
	}
	return 0, false
}

func parseDecayDurationMillis(raw any) (float64, bool) {
	if f, ok := parseDecayNumericValue(raw); ok {
		return f, true
	}
	s, ok := raw.(string)
	if !ok {
		return 0, false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	idx := len(s)
	for idx > 0 {
		ch := s[idx-1]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			idx--
		} else {
			break
		}
	}
	numStr := strings.TrimSpace(s[:idx])
	unitStr := strings.TrimSpace(s[idx:])
	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil || math.IsNaN(val) || math.IsInf(val, 0) {
		return 0, false
	}
	switch unitStr {
	case "", "ms", "MS":
		return val, true
	case "s", "S":
		return val * 1000.0, true
	case "m":
		return val * 60.0 * 1000.0, true
	case "h", "H":
		return val * 3600.0 * 1000.0, true
	case "d", "D":
		return val * 86400.0 * 1000.0, true
	case "w", "W":
		return val * 7.0 * 86400.0 * 1000.0, true
	case "M":
		return val * 30.0 * 86400.0 * 1000.0, true
	case "y", "Y":
		return val * 365.0 * 86400.0 * 1000.0, true
	default:
		return 0, false
	}
}

func (t *Transpiler) compileTermsSetTermPredicate(field string, val any, nctx *nestedCtx) string {
	basePred := t.compileTermPredicate(field, val, false, nctx)
	if basePred == "FALSE" {
		return "FALSE"
	}
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if nctx != nil || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield ||
		b.Kind == schema.StoragePromotedVector || len(b.SourceJSONPath) == 0 ||
		field == "_id" || field == "_doc" || field == "_routing" || field == "_version" || field == "_index" || field == "_all_text" || field == "*" {
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
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(field, nctx)
		if len(exp) > 0 {
			var disjuncts []string
			for _, bf := range exp {
				disjuncts = append(disjuncts, t.compileTermPredicate(bf.Field, val, caseInsensitive, nctx))
			}
			if len(disjuncts) == 1 {
				return disjuncts[0]
			}
			return "(" + strings.Join(disjuncts, " OR ") + ")"
		}
	}
	origField := field
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if !t.checkFieldSearchable(field, b) || b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	if b.ESType == "search_as_you_type" && strings.HasSuffix(origField, "._index_prefix") {
		return t.compilePrefixPredicate(field, fmt.Sprintf("%v", val), true, nctx)
	}
	if schema.IsRangeFieldType(b.ESType) {
		qf, ok := coerceRangeFieldQueryScalar(val, b, b.Format, 0, false, false)
		if !ok {
			return "FALSE"
		}
		lowerSQL, upperSQL, rawLower, rawUpper := t.rangeFieldBoundsAndRawSQL(field, b, nctx)
		qLit := strconv.FormatFloat(qf, 'f', -1, 64)
		return fmt.Sprintf("((%s IS NOT NULL OR %s IS NOT NULL) AND %s <= %s AND %s >= %s)", rawLower, rawUpper, lowerSQL, qLit, upperSQL, qLit)
	}
	if b.ESType == "ip" {
		if strVal, ok := val.(string); ok {
			if startNum, endNum, isCIDR := parseCIDRBounds(strVal); isCIDR {
				if b.Kind == schema.StorageNestedSubfield && nctx != nil && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
					rawCol := t.sqlColumnRef(field, true, nctx)
					return fmt.Sprintf("array_exists(_x -> IPV4_STRING_TO_NUM_OR_NULL(_x) >= %d AND IPV4_STRING_TO_NUM_OR_NULL(_x) <= %d, CAST(%s AS ARRAY<STRING>))", startNum, endNum, rawCol)
				}
				if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) {
					colName := b.EffectiveArrayColumn(true)
					return fmt.Sprintf("array_exists(_x -> IPV4_STRING_TO_NUM_OR_NULL(_x) >= %d AND IPV4_STRING_TO_NUM_OR_NULL(_x) <= %d, `%s`)", startNum, endNum, colName)
				}
				rawCol := t.sqlColumnRef(field, true, nctx)
				numCol := fmt.Sprintf("IPV4_STRING_TO_NUM_OR_NULL(%s)", rawCol)
				return fmt.Sprintf("(%s >= %d AND %s <= %d)", numCol, startNum, numCol, endNum)
			}
		}
		ip := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", val)))
		if ip == nil {
			return "FALSE"
		}
		val = ip.String()
	}
	if b.ESType == "text" && b.KeywordCompanion == "" && !strings.HasSuffix(field, ".keyword") {
		if _, isBool := val.(bool); isBool {
			return t.compileMatchField(field, fmt.Sprintf("%v", val), "or", 1.0, false, nctx).WhereSQL
		}
	}
	effLower := b.EffectiveLowercase(true)
	effDT := effectiveDorisScalarType(b)
	if _, isBool := val.(bool); isBool && b.ESType != "" && effDT != schema.DorisBoolean && effDT != schema.DorisString && effDT != schema.DorisVarchar {
		return "FALSE"
	}
	if effDT == schema.DorisBoolean {
		if bv, ok := normalizeBooleanQueryValue(val); ok {
			val = bv
		} else if b.ESType != "" {
			return "FALSE"
		}
	} else if strVal, ok := val.(string); ok {
		if effLower && effDT != schema.DorisBigInt && effDT != schema.DorisInt && effDT != schema.DorisDouble && b.ESType != "date" && b.ESType != "date_nanos" {
			val = strings.ToLower(strVal)
		} else if b.ESType == "date" || b.ESType == "date_nanos" || (b.ESType == "" && effDT == schema.DorisBigInt) {
			if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, b.Format, time.Now().UTC()); ok {
				val = ms
			} else if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
				val = iv
			} else if b.ESType == "date" || b.ESType == "date_nanos" {
				return "FALSE"
			}
		} else if effDT == schema.DorisBigInt || effDT == schema.DorisInt {
			trimmed := strings.TrimSpace(strVal)
			if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				if b.ESType == "unsigned_long" && iv < 0 {
					return "FALSE"
				}
				val = iv
			} else if b.ESType == "unsigned_long" {
				if u, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
					val = u
				} else if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= 0 && fv < 18446744073709551616.0 && fv == math.Trunc(fv) {
					if fv >= 9223372036854775808.0 {
						val = uint64(fv)
					} else {
						val = int64(fv)
					}
				} else {
					return "FALSE"
				}
			} else if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) && fv >= float64(math.MinInt64) && fv < 9223372036854775808.0 {
				val = int64(fv)
			} else if b.ESType != "" {
				return "FALSE"
			}
		} else if effDT == schema.DorisDouble {
			if fv, err := strconv.ParseFloat(strings.TrimSpace(strVal), 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				val = fv
			} else if b.ESType != "" {
				return "FALSE"
			}
		}
	} else if val != nil && ((b.Kind == schema.StoragePromotedScalar || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && (effDT == schema.DorisVarchar || effDT == schema.DorisString) || b.ESType == "flattened") {
		sv := fmt.Sprintf("%v", val)
		if effLower {
			sv = strings.ToLower(sv)
		}
		val = sv
	} else if nv, ok := val.(json.Number); ok && b.ESType == "unsigned_long" {
		if iv, err := nv.Int64(); err == nil {
			if iv < 0 {
				return "FALSE"
			}
			val = iv
		} else if u, err := strconv.ParseUint(nv.String(), 10, 64); err == nil {
			val = u
		}
	}
	val = normalizeScaledFloatValue(b, val)
	val = normalizeDateNanosValue(b.ESType, val)
	if b.IgnoreAbove > 0 && val != nil {
		if len([]rune(fmt.Sprintf("%v", val))) > b.IgnoreAbove {
			return "FALSE"
		}
	}
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
			relPath := t.nestedRelativeJSONPath(field, true, b.NestedPath)
			if b.IsMultiValued {
				extracted := fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath))
				rawLit := quoteStr(fmt.Sprintf("%v", val))
				_, isStr := val.(string)
				if isStr || b.DorisType == schema.DorisString {
					valStr := fmt.Sprintf("%v", val)
					strVal := `"` + valStr + `"`
					likePat := quoteStr("%" + escapeLikeLiteral(strVal) + "%")
					if _, numErr := strconv.ParseFloat(strings.TrimSpace(valStr), 64); numErr == nil {
						escVal := escapeLikeLiteral(valStr)
						p1 := quoteStr("[" + escVal + "]")
						p2 := quoteStr("[" + escVal + ",%")
						p3 := quoteStr("%," + escVal + ",%")
						p4 := quoteStr("%," + escVal + "]")
						if caseInsensitive || effLower {
							return fmt.Sprintf("(lower(%s) = lower(%s) OR lower(%s) LIKE lower(%s) OR %s LIKE %s OR %s LIKE %s OR %s LIKE %s OR %s LIKE %s)",
								extracted, rawLit, extracted, likePat, extracted, p1, extracted, p2, extracted, p3, extracted, p4)
						}
						return fmt.Sprintf("(%s = %s OR %s LIKE %s OR %s LIKE %s OR %s LIKE %s OR %s LIKE %s OR %s LIKE %s)",
							extracted, rawLit, extracted, likePat, extracted, p1, extracted, p2, extracted, p3, extracted, p4)
					}
					if caseInsensitive || effLower {
						return fmt.Sprintf("(lower(%s) = lower(%s) OR lower(%s) LIKE lower(%s))", extracted, rawLit, extracted, likePat)
					}
					return fmt.Sprintf("(%s = %s OR %s LIKE %s)", extracted, rawLit, extracted, likePat)
				}
				escVal := escapeLikeLiteral(fmt.Sprintf("%v", val))
				p1 := quoteStr("[" + escVal + "]")
				p2 := quoteStr("[" + escVal + ",%")
				p3 := quoteStr("%," + escVal + ",%")
				p4 := quoteStr("%," + escVal + "]")
				return fmt.Sprintf("(%s = %s OR %s LIKE %s OR %s LIKE %s OR %s LIKE %s OR %s LIKE %s)",
					extracted, rawLit, extracted, p1, extracted, p2, extracted, p3, extracted, p4)
			}
			if effDT == schema.DorisDouble && !caseInsensitive && !effLower {
				col := t.sqlTypedColumnRef(field, val, true, nctx)
				return fmt.Sprintf("%s = %s", col, lit)
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
	if b.ESType == "flattened" {
		valStr := fmt.Sprintf("%v", val)
		if isRoot, isSubKey := t.flattenedFieldMode(field, b); isRoot {
			jsonLeafPat := quoteStr("%" + escapeLikeLiteral(`"`+valStr+`"`) + "%")
			if caseInsensitive {
				return fmt.Sprintf("(lower(%s) = lower(%s) OR lower(%s) LIKE lower(%s))", col, lit, col, jsonLeafPat)
			}
			return fmt.Sprintf("(%s = %s OR %s LIKE %s)", col, lit, col, jsonLeafPat)
		} else if isSubKey {
			rawVar := t.flattenedRawVariantRef(field, b, nctx)
			strLit := quoteStr(valStr)
			if caseInsensitive {
				return fmt.Sprintf("(lower(%s) = lower(%s) OR array_exists(_x -> lower(_x) = lower(%s), CAST(%s AS ARRAY<STRING>)))", col, lit, strLit, rawVar)
			}
			return fmt.Sprintf("(%s = %s OR array_contains(CAST(%s AS ARRAY<STRING>), %s))", col, lit, rawVar, strLit)
		}
	}
	if caseInsensitive {
		return fmt.Sprintf("lower(%s) = lower(%s)", col, lit)
	}
	return fmt.Sprintf("%s = %s", col, lit)
}

func (t *Transpiler) flattenedFieldMode(field string, b schema.FieldBinding) (isRootFlattened bool, isSubKeyFlattened bool) {
	if b.ESType != "flattened" {
		return false, false
	}
	clean := strings.TrimSuffix(field, ".keyword")
	if t.Schema != nil {
		if fb, ok := t.Schema.Fields[clean]; ok && fb.ESType == "flattened" {
			return true, false
		}
	}
	return false, true
}

func (t *Transpiler) flattenedRawVariantRef(field string, b schema.FieldBinding, nctx *nestedCtx) string {
	effField := field
	if b.AliasTarget != "" {
		effField = b.AliasTarget
	}
	if nctx != nil && nctx.elemVar != "" && (b.NestedPath == nctx.nestedPath || strings.HasPrefix(effField, nctx.nestedPath+".")) {
		relPath := t.nestedRelativeJSONPath(field, true, nctx.nestedPath)
		return fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath))
	}
	segs := b.SourceJSONPath
	if len(segs) == 0 {
		segs = strings.Split(strings.TrimSuffix(effField, ".keyword"), ".")
	}
	var pathBuilder strings.Builder
	for _, seg := range segs {
		_, _ = fmt.Fprintf(&pathBuilder, "[%s]", quoteStr(seg))
	}
	return fmt.Sprintf("`_doc`%s", pathBuilder.String())
}

func (t *Transpiler) compileTermsPredicateWithCI(field string, vals []any, caseInsensitive bool, nctx *nestedCtx) string {
	if len(vals) == 0 {
		return "FALSE"
	}
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(field, nctx)
		if len(exp) > 0 {
			var disjuncts []string
			for _, bf := range exp {
				disjuncts = append(disjuncts, t.compileTermsPredicateWithCI(bf.Field, vals, caseInsensitive, nctx))
			}
			if len(disjuncts) == 1 {
				return disjuncts[0]
			}
			return "(" + strings.Join(disjuncts, " OR ") + ")"
		}
	}
	origField := field
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if !t.checkFieldSearchable(field, b) || b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	if b.ESType == "search_as_you_type" && strings.HasSuffix(origField, "._index_prefix") {
		var disjuncts []string
		for _, v := range vals {
			disjuncts = append(disjuncts, t.compilePrefixPredicate(field, fmt.Sprintf("%v", v), true, nctx))
		}
		if len(disjuncts) == 0 {
			return "FALSE"
		}
		if len(disjuncts) == 1 {
			return disjuncts[0]
		}
		return "(" + strings.Join(disjuncts, " OR ") + ")"
	}
	if schema.IsRangeFieldType(b.ESType) || b.ESType == "flattened" {
		var disjuncts []string
		for _, v := range vals {
			disjuncts = append(disjuncts, t.compileTermPredicate(field, v, caseInsensitive, nctx))
		}
		if len(disjuncts) == 1 {
			return disjuncts[0]
		}
		return "(" + strings.Join(disjuncts, " OR ") + ")"
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
	effLower := b.EffectiveLowercase(true) || caseInsensitive
	isArrayCol := b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath))
	if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
		var disjuncts []string
		for _, v := range vals {
			disjuncts = append(disjuncts, t.compileTermPredicate(field, v, caseInsensitive, nctx))
		}
		return "(" + strings.Join(disjuncts, " OR ") + ")"
	}
	now := time.Now().UTC()
	effDT := effectiveDorisScalarType(b)
	quoted := make([]string, 0, len(vals))
	normalizedVals := make([]any, 0, len(vals))
	for _, v := range vals {
		if b.IgnoreAbove > 0 && v != nil && len([]rune(fmt.Sprintf("%v", v))) > b.IgnoreAbove {
			continue
		}
		if effDT == schema.DorisBoolean {
			if bv, ok := normalizeBooleanQueryValue(v); ok {
				v = bv
			} else if b.ESType != "" {
				continue
			}
		} else if strVal, ok := v.(string); ok {
			if effLower && effDT != schema.DorisBigInt && effDT != schema.DorisInt && effDT != schema.DorisDouble && b.ESType != "date" && b.ESType != "date_nanos" {
				v = strings.ToLower(strVal)
			} else if b.ESType == "date" || b.ESType == "date_nanos" || (b.ESType == "" && effDT == schema.DorisBigInt) {
				if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, b.Format, now); ok {
					v = ms
				} else if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
					v = iv
				} else if b.ESType == "date" || b.ESType == "date_nanos" {
					continue
				}
			} else if effDT == schema.DorisBigInt || effDT == schema.DorisInt {
				trimmed := strings.TrimSpace(strVal)
				if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
					if b.ESType == "unsigned_long" && iv < 0 {
						continue
					}
					v = iv
				} else if b.ESType == "unsigned_long" {
					if u, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
						v = u
					} else if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= 0 && fv < 18446744073709551616.0 && fv == math.Trunc(fv) {
						if fv >= 9223372036854775808.0 {
							v = uint64(fv)
						} else {
							v = int64(fv)
						}
					} else {
						continue
					}
				} else if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) && fv >= float64(math.MinInt64) && fv < 9223372036854775808.0 {
					v = int64(fv)
				} else if b.ESType != "" {
					continue
				}
			} else if effDT == schema.DorisDouble {
				if fv, err := strconv.ParseFloat(strings.TrimSpace(strVal), 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
					v = fv
				} else if b.ESType != "" {
					continue
				}
			}
		} else if v != nil && (b.Kind == schema.StoragePromotedScalar || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && (effDT == schema.DorisVarchar || effDT == schema.DorisString) {
			sv := fmt.Sprintf("%v", v)
			if effLower {
				sv = strings.ToLower(sv)
			}
			v = sv
		} else if nv, ok := v.(json.Number); ok && b.ESType == "unsigned_long" {
			if iv, err := nv.Int64(); err == nil {
				if iv < 0 {
					continue
				}
				v = iv
			} else if u, err := strconv.ParseUint(nv.String(), 10, 64); err == nil {
				v = u
			}
		}
		v = normalizeScaledFloatValue(b, v)
		v = normalizeDateNanosValue(b.ESType, v)
		normalizedVals = append(normalizedVals, v)
		if isArrayCol {
			quoted = append(quoted, quoteStr(fmt.Sprintf("%v", v)))
		} else {
			quoted = append(quoted, quoteValue(v))
		}
	}
	if len(quoted) == 0 {
		return "FALSE"
	}
	if isArrayCol {
		colName := b.EffectiveArrayColumn(true)
		if caseInsensitive && !b.EffectiveLowercase(true) {
			return fmt.Sprintf("array_exists(_x -> lower(_x) IN (%s), `%s`)", strings.Join(quoted, ", "), colName)
		}
		return fmt.Sprintf("arrays_overlap(`%s`, [%s])", colName, strings.Join(quoted, ", "))
	}
	sampleVal := normalizedVals[0]
	for _, nv := range normalizedVals {
		if _, isU := nv.(uint64); isU {
			sampleVal = nv
			break
		}
		if fv, ok := nv.(float64); ok && fv != math.Trunc(fv) {
			sampleVal = nv
			break
		}
	}
	col := t.sqlTypedColumnRef(field, sampleVal, true, nctx)
	if (caseInsensitive && !b.EffectiveLowercase(true) && (effDT == schema.DorisVarchar || effDT == schema.DorisString)) ||
		(nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && effLower) {
		col = fmt.Sprintf("lower(%s)", col)
	}
	return fmt.Sprintf("%s IN (%s)", col, strings.Join(quoted, ", "))
}

func (t *Transpiler) compilePrefixPredicate(field, val string, caseInsensitive bool, nctx *nestedCtx) string {
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(field, nctx)
		if len(exp) == 0 {
			if nctx != nil || (field != "*" && len(t.Schema.Fields) > 0) {
				return "FALSE"
			}
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
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if !t.checkFieldSearchable(field, b) || b.Kind == schema.StoragePromotedVector {
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
	if b.ESType == "flattened" {
		if isRoot, isSubKey := t.flattenedFieldMode(field, b); isRoot {
			jsonLeafPat := quoteStr("%" + escapeLikeLiteral(`"`+val) + "%")
			if caseInsensitive || (nctx != nil && effLower) {
				return fmt.Sprintf("(lower(%s) LIKE lower(%s) OR lower(%s) LIKE lower(%s))", col, likePat, col, jsonLeafPat)
			}
			return fmt.Sprintf("(%s LIKE %s OR %s LIKE %s)", col, likePat, col, jsonLeafPat)
		} else if isSubKey {
			rawVar := t.flattenedRawVariantRef(field, b, nctx)
			if caseInsensitive || (nctx != nil && effLower) {
				return fmt.Sprintf("(lower(%s) LIKE lower(%s) OR array_exists(_x -> lower(_x) LIKE lower(%s), CAST(%s AS ARRAY<STRING>)))", col, likePat, likePat, rawVar)
			}
			return fmt.Sprintf("(%s LIKE %s OR array_exists(_x -> _x LIKE %s, CAST(%s AS ARRAY<STRING>)))", col, likePat, likePat, rawVar)
		}
	}
	if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
		if caseInsensitive || effLower {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), CAST(%s AS ARRAY<STRING>))", likePat, col)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, CAST(%s AS ARRAY<STRING>))", likePat, col)
	}
	if caseInsensitive || (nctx != nil && effLower) {
		return fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likePat)
	}
	return fmt.Sprintf("%s LIKE %s", col, likePat)
}

func (t *Transpiler) compileWildcardPredicate(field, val string, caseInsensitive bool, nctx *nestedCtx) string {
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(field, nctx)
		if len(exp) == 0 {
			if nctx != nil || (field != "*" && len(t.Schema.Fields) > 0) {
				return "FALSE"
			}
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
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if !t.checkFieldSearchable(field, b) || b.Kind == schema.StoragePromotedVector {
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
	if b.ESType == "flattened" {
		if isRoot, isSubKey := t.flattenedFieldMode(field, b); isRoot {
			jsonLeafPat := quoteStr(`%"` + wildcardToLike(val) + `"%`)
			if caseInsensitive || (nctx != nil && effLower) {
				return fmt.Sprintf("(lower(%s) LIKE lower(%s) OR lower(%s) LIKE lower(%s))", col, likePat, col, jsonLeafPat)
			}
			return fmt.Sprintf("(%s LIKE %s OR %s LIKE %s)", col, likePat, col, jsonLeafPat)
		} else if isSubKey {
			rawVar := t.flattenedRawVariantRef(field, b, nctx)
			if caseInsensitive || (nctx != nil && effLower) {
				return fmt.Sprintf("(lower(%s) LIKE lower(%s) OR array_exists(_x -> lower(_x) LIKE lower(%s), CAST(%s AS ARRAY<STRING>)))", col, likePat, likePat, rawVar)
			}
			return fmt.Sprintf("(%s LIKE %s OR array_exists(_x -> _x LIKE %s, CAST(%s AS ARRAY<STRING>)))", col, likePat, likePat, rawVar)
		}
	}
	if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
		if caseInsensitive || effLower {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), CAST(%s AS ARRAY<STRING>))", likePat, col)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, CAST(%s AS ARRAY<STRING>))", likePat, col)
	}
	if caseInsensitive || (nctx != nil && effLower) {
		return fmt.Sprintf("lower(%s) LIKE lower(%s)", col, likePat)
	}
	return fmt.Sprintf("%s LIKE %s", col, likePat)
}

func (t *Transpiler) compileRangePredicate(field string, rc esast.RangeCond, nctx *nestedCtx) string {
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(field, nctx)
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

func formatSemverBoundKey(v string) string {
	s := strings.TrimSpace(v)
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}
	core := s
	prerelease := ""
	hasPre := false
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		core = s[:idx]
		prerelease = s[idx+1:]
		hasPre = true
	}
	parts := strings.Split(core, ".")
	parsePart := func(i int) int64 {
		if i >= len(parts) || parts[i] == "" {
			return 0
		}
		if n, err := strconv.ParseInt(parts[i], 10, 64); err == nil && n >= 0 {
			return n
		}
		return 0
	}
	maj, minV, pat := parsePart(0), parsePart(1), parsePart(2)
	if hasPre {
		return fmt.Sprintf("%010d.%010d.%010d-%s", maj, minV, pat, prerelease)
	}
	return fmt.Sprintf("%010d.%010d.%010d~", maj, minV, pat)
}

func sqlSemverSortKeyExpr(colExpr string) string {
	noBuild := fmt.Sprintf("SPLIT_PART(%s, '+', 1)", colExpr)
	core := fmt.Sprintf("SPLIT_PART(%s, '-', 1)", noBuild)
	maj := fmt.Sprintf("LPAD(IF(SPLIT_PART(%s, '.', 1) = '', '0', SPLIT_PART(%s, '.', 1)), 10, '0')", core, core)
	minV := fmt.Sprintf("LPAD(IF(SPLIT_PART(%s, '.', 2) = '', '0', SPLIT_PART(%s, '.', 2)), 10, '0')", core, core)
	pat := fmt.Sprintf("LPAD(IF(SPLIT_PART(%s, '.', 3) = '', '0', SPLIT_PART(%s, '.', 3)), 10, '0')", core, core)
	pre := fmt.Sprintf("IF(LOCATE('-', %s) > 0, CONCAT('-', SUBSTRING(%s, LOCATE('-', %s) + 1)), '~')", noBuild, noBuild, noBuild)
	return fmt.Sprintf("CONCAT(%s, '.', %s, '.', %s, %s)", maj, minV, pat, pre)
}

func (t *Transpiler) compileRangeSingleField(field string, rc esast.RangeCond, nctx *nestedCtx) string {
	gt, gte, lt, lte := rc.NormalizedBounds()
	if gt == nil && gte == nil && lt == nil && lte == nil {
		return t.compileExistsPredicate(field, nctx)
	}
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if !t.checkFieldSearchable(field, b) || b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	if schema.IsRangeFieldType(b.ESType) {
		return t.compileRangeOnRangeField(field, b, rc, nctx)
	}
	if b.ESType == "version" {
		isNestedMultiVal := nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued
		if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) || isNestedMultiVal {
			colName := b.EffectiveArrayColumn(true)
			verElem := sqlSemverSortKeyExpr("_x")
			var elemParts []string
			if gt != nil {
				elemParts = append(elemParts, fmt.Sprintf("%s > %s", verElem, quoteStr(formatSemverBoundKey(fmt.Sprintf("%v", gt)))))
			}
			if gte != nil {
				elemParts = append(elemParts, fmt.Sprintf("%s >= %s", verElem, quoteStr(formatSemverBoundKey(fmt.Sprintf("%v", gte)))))
			}
			if lt != nil {
				elemParts = append(elemParts, fmt.Sprintf("%s < %s", verElem, quoteStr(formatSemverBoundKey(fmt.Sprintf("%v", lt)))))
			}
			if lte != nil {
				elemParts = append(elemParts, fmt.Sprintf("%s <= %s", verElem, quoteStr(formatSemverBoundKey(fmt.Sprintf("%v", lte)))))
			}
			if len(elemParts) == 0 {
				return "TRUE"
			}
			if isNestedMultiVal {
				rawCol := t.sqlColumnRef(field, true, nctx)
				return fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND %s, CAST(%s AS ARRAY<STRING>))", strings.Join(elemParts, " AND "), rawCol)
			}
			return fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND %s, `%s`)", strings.Join(elemParts, " AND "), colName)
		}
		rawCol := t.sqlColumnRef(field, true, nctx)
		verCol := sqlSemverSortKeyExpr(rawCol)
		var parts []string
		if gt != nil {
			parts = append(parts, fmt.Sprintf("%s > %s", verCol, quoteStr(formatSemverBoundKey(fmt.Sprintf("%v", gt)))))
		}
		if gte != nil {
			parts = append(parts, fmt.Sprintf("%s >= %s", verCol, quoteStr(formatSemverBoundKey(fmt.Sprintf("%v", gte)))))
		}
		if lt != nil {
			parts = append(parts, fmt.Sprintf("%s < %s", verCol, quoteStr(formatSemverBoundKey(fmt.Sprintf("%v", lt)))))
		}
		if lte != nil {
			parts = append(parts, fmt.Sprintf("%s <= %s", verCol, quoteStr(formatSemverBoundKey(fmt.Sprintf("%v", lte)))))
		}
		if len(parts) == 0 {
			return "TRUE"
		}
		return strings.Join(parts, " AND ")
	}
	if b.ESType == "ip" {
		for _, cand := range []any{gt, gte, lt, lte} {
			if cand != nil && net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", cand))) == nil {
				return "FALSE"
			}
		}
		isNestedMultiVal := nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued
		if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) || isNestedMultiVal {
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
			if isNestedMultiVal {
				rawCol := t.sqlColumnRef(field, true, nctx)
				return fmt.Sprintf("array_exists(_x -> %s, CAST(%s AS ARRAY<STRING>))", strings.Join(elemParts, " AND "), rawCol)
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
	effFormat := rc.Format
	if effFormat == "" {
		effFormat = b.Format
	}
	isEpochSecond := strings.EqualFold(effFormat, "epoch_second")
	tzOffsetMs := esast.ParseTimeZoneOffsetMs(strings.TrimSpace(rc.TimeZone))

	coerceBound := func(v any, roundUp bool) any {
		if v == nil {
			return nil
		}
		if b.ESType == "flattened" {
			s := fmt.Sprintf("%v", v)
			if b.EffectiveLowercase(true) {
				s = strings.ToLower(s)
			}
			return s
		}
		switch effectiveDorisScalarType(b) {
		case schema.DorisBigInt:
			if effFormat != "" && (b.ESType == "date" || b.ESType == "date_nanos" || rc.Format != "") && (!strings.Contains(strings.ToLower(effFormat), "epoch") || strings.Contains(strings.ToLower(effFormat), "basic_date")) {
				switch iv := v.(type) {
				case int, int64:
					if ms, ok := schema.ParseESDateBoundWithFormatToEpochMillis(fmt.Sprintf("%v", iv), effFormat, now, roundUp); ok {
						if tzOffsetMs != 0 && !strings.Contains(strings.ToLower(effFormat), "epoch") {
							ms -= tzOffsetMs
						}
						return normalizeDateNanosValue(b.ESType, ms)
					}
				}
			}
			if strVal, ok := v.(string); ok {
				trimmed := strings.TrimSpace(strVal)
				if effFormat != "" && (b.ESType == "date" || b.ESType == "date_nanos" || rc.Format != "") {
					if ms, ok := schema.ParseESDateBoundWithFormatToEpochMillis(strVal, effFormat, now, roundUp); ok {
						datePart := trimmed
						if idx := strings.Index(datePart, "||"); idx >= 0 {
							datePart = strings.TrimSpace(datePart[:idx])
						}
						if _, numErr := strconv.ParseFloat(datePart, 64); numErr != nil && !isEpochSecond &&
							tzOffsetMs != 0 && !strings.HasPrefix(datePart, "now") &&
							!strings.HasSuffix(datePart, "Z") && !strings.HasSuffix(datePart, "z") &&
							!strings.Contains(datePart[min(10, len(datePart)):], "+") &&
							!strings.Contains(datePart[min(10, len(datePart)):], "-") {
							ms -= tzOffsetMs
						}
						return normalizeDateNanosValue(b.ESType, ms)
					}
				}
				if b.ESType == "date" || b.ESType == "date_nanos" || rc.Format != "" {
					if ms, ok := schema.ParseESDateBoundWithFormatToEpochMillis(strVal, effFormat, now, roundUp); ok {
						datePart := trimmed
						if idx := strings.Index(datePart, "||"); idx >= 0 {
							datePart = strings.TrimSpace(datePart[:idx])
						}
						if _, numErr := strconv.ParseFloat(datePart, 64); numErr != nil &&
							tzOffsetMs != 0 && !strings.HasPrefix(datePart, "now") &&
							!strings.HasSuffix(datePart, "Z") && !strings.HasSuffix(datePart, "z") &&
							!strings.Contains(datePart[min(10, len(datePart)):], "+") &&
							!strings.Contains(datePart[min(10, len(datePart)):], "-") {
							ms -= tzOffsetMs
						}
						return normalizeDateNanosValue(b.ESType, ms)
					}
				}
				if !isEpochSecond {
					if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
						if norm, ok := normalizeDateNanosValue(b.ESType, iv).(int64); ok {
							iv = norm
						}
						return iv
					}
					if b.ESType == "unsigned_long" {
						if u, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
							return u
						}
					}
				}
				if rawSec, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(rawSec) && !math.IsInf(rawSec, 0) {
					if isEpochSecond {
						return int64(rawSec * 1000)
					}
					if b.ESType == "unsigned_long" && rawSec >= 9223372036854775808.0 {
						if rawSec < 18446744073709551616.0 {
							return uint64(rawSec)
						}
						return uint64(math.MaxUint64)
					}
					if rawSec >= 9223372036854775808.0 {
						return int64(math.MaxInt64)
					}
					if rawSec < float64(math.MinInt64) {
						return int64(math.MinInt64)
					}
					iv := int64(rawSec)
					if norm, ok := normalizeDateNanosValue(b.ESType, iv).(int64); ok {
						iv = norm
					}
					return iv
				}
				if b.ESType == "" {
					if ms, ok := schema.ParseESDateBoundWithFormatToEpochMillis(strVal, effFormat, now, roundUp); ok {
						datePart := trimmed
						if idx := strings.Index(datePart, "||"); idx >= 0 {
							datePart = strings.TrimSpace(datePart[:idx])
						}
						if _, numErr := strconv.ParseFloat(datePart, 64); numErr != nil &&
							tzOffsetMs != 0 && !strings.HasPrefix(datePart, "now") &&
							!strings.HasSuffix(datePart, "Z") && !strings.HasSuffix(datePart, "z") &&
							!strings.Contains(datePart[min(10, len(datePart)):], "+") &&
							!strings.Contains(datePart[min(10, len(datePart)):], "-") {
							ms -= tzOffsetMs
						}
						return normalizeDateNanosValue(b.ESType, ms)
					}
				}
			}
			if nv, ok := v.(json.Number); ok && b.ESType == "unsigned_long" && !isEpochSecond {
				if iv, err := nv.Int64(); err == nil {
					return iv
				}
				if u, err := strconv.ParseUint(nv.String(), 10, 64); err == nil {
					return u
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
					return normalizeScaledFloatValue(b, f)
				}
			}
			return normalizeScaledFloatValue(b, v)
		case schema.DorisVarchar, schema.DorisString:
			if b.ESType != "" {
				s := fmt.Sprintf("%v", v)
				if b.EffectiveLowercase(true) {
					s = strings.ToLower(s)
				}
				return s
			}
			if strVal, ok := v.(string); ok && b.EffectiveLowercase(true) {
				return strings.ToLower(strVal)
			}
		}
		return v
	}

	gt = coerceBound(gt, true)
	gte = coerceBound(gte, false)
	lt = coerceBound(lt, false)
	lte = coerceBound(lte, true)

	effDT := effectiveDorisScalarType(b)
	if b.ESType != "" &&
		(effDT == schema.DorisBigInt || effDT == schema.DorisInt || effDT == schema.DorisDouble) {
		for _, cand := range []any{gt, gte, lt, lte} {
			if _, isStr := cand.(string); isStr {
				return "FALSE"
			}
		}
	}

	var sampleBound any
	for _, cand := range []any{gt, gte, lt, lte} {
		if cand == nil {
			continue
		}
		if sampleBound == nil {
			sampleBound = cand
		}
		switch fv := cand.(type) {
		case uint64:
			sampleBound = cand
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

	isNestedMultiVal := nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued
	if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) || isNestedMultiVal {
		elemExpr := "_x"
		switch sv := sampleBound.(type) {
		case uint64:
			elemExpr = "CAST(_x AS LARGEINT)"
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
			} else if _, errU := strconv.ParseUint(sv.String(), 10, 64); errU == nil {
				elemExpr = "CAST(_x AS LARGEINT)"
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
		if isNestedMultiVal {
			col := t.sqlColumnRef(field, true, nctx)
			return fmt.Sprintf("array_exists(_x -> %s, CAST(%s AS ARRAY<STRING>))", strings.Join(elemParts, " AND "), col)
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
	if b.ESType == "flattened" {
		if _, isSubKey := t.flattenedFieldMode(field, b); isSubKey {
			rawVar := t.flattenedRawVariantRef(field, b, nctx)
			var elemParts []string
			if gt != nil {
				elemParts = append(elemParts, fmt.Sprintf("_x > %s", quoteValue(gt)))
			}
			if gte != nil {
				elemParts = append(elemParts, fmt.Sprintf("_x >= %s", quoteValue(gte)))
			}
			if lt != nil {
				elemParts = append(elemParts, fmt.Sprintf("_x < %s", quoteValue(lt)))
			}
			if lte != nil {
				elemParts = append(elemParts, fmt.Sprintf("_x <= %s", quoteValue(lte)))
			}
			scalarCond := strings.Join(parts, " AND ")
			if len(parts) > 1 {
				scalarCond = "(" + scalarCond + ")"
			}
			return fmt.Sprintf("(%s OR array_exists(_x -> _x IS NOT NULL AND %s, CAST(%s AS ARRAY<STRING>)))", scalarCond, strings.Join(elemParts, " AND "), rawVar)
		}
	}
	return strings.Join(parts, " AND ")
}

func (t *Transpiler) compileExistsPredicate(field string, nctx *nestedCtx) string {
	field, _ = parseFieldBoost(field, 1.0)
	if strings.ContainsAny(field, "*?") && t.Schema != nil {
		exp := t.expandFieldPatternForContext(field, nctx)
		if len(exp) == 0 {
			return "FALSE"
		}
		var disjuncts []string
		for _, bf := range exp {
			disjuncts = append(disjuncts, t.compileExistsPredicate(bf.Field, nctx))
		}
		if len(disjuncts) == 1 {
			return disjuncts[0]
		}
		return "(" + strings.Join(disjuncts, " OR ") + ")"
	}
	if t.Schema != nil && nctx == nil {
		if corrCol, ok := t.Schema.NestedRoots[field]; ok && corrCol != "" {
			return fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", corrCol, corrCol)
		}
	}
	preferKw := strings.HasSuffix(field, ".keyword")
	field, b := t.resolveFieldInNestedCtx(field, preferKw, nctx)
	if b.EnabledFalse {
		return "FALSE"
	}
	if strings.HasSuffix(b.AliasTarget, ".keyword") {
		preferKw = true
	}
	if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) {
		arrCol := b.EffectiveArrayColumn(preferKw)
		return fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", arrCol, arrCol)
	}
	col := t.sqlColumnRef(field, preferKw, nctx)
	basePred := fmt.Sprintf("%s IS NOT NULL", col)
	if b.ESType == "flattened" {
		basePred = fmt.Sprintf("(%s IS NOT NULL AND %s != '{}' AND %s != 'null')", col, col, col)
	}
	if b.Kind == schema.StorageDynamicVariant && t.Schema != nil && nctx == nil && !strings.ContainsAny(field, "*?") {
		prefix := field + "."
		var disjuncts []string
		disjuncts = append(disjuncts, basePred)
		for _, fb := range t.Schema.OrderedFields {
			if strings.HasPrefix(fb.ESFieldPath, prefix) && !strings.HasSuffix(fb.ESFieldPath, ".keyword") && !strings.HasSuffix(fb.ESFieldPath, ".ngram") {
				disjuncts = append(disjuncts, t.compileExistsPredicate(fb.ESFieldPath, nctx))
			}
		}
		if len(disjuncts) > 1 {
			return "(" + strings.Join(disjuncts, " OR ") + ")"
		}
	}
	return basePred
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
			termsExtraWhere := extraWhere
			termsWherePrefix := wherePrefix
			if termsSpec.BackgroundFilter != nil {
				bgCond := t.CompileQuery(termsSpec.BackgroundFilter, false, nil)
				if bgCond.WhereSQL != "" && bgCond.WhereSQL != "1=1" {
					if termsExtraWhere != "" {
						termsExtraWhere = fmt.Sprintf("(%s) AND (%s)", termsExtraWhere, bgCond.WhereSQL)
					} else {
						termsExtraWhere = bgCond.WhereSQL
					}
					termsWherePrefix = fmt.Sprintf("(%s) AND ", termsExtraWhere)
				}
			}
			size := t.maxAggBuckets()
			if capSz := t.capBucketSize(termsSpec.Size); capSz > size {
				size = capSz
			}
			effField := termsSpec.Field
			if effField == "" && termsSpec.Script != nil {
				if df, ok := extractSimpleDocFieldFromScript(termsSpec.Script); ok {
					effField = df
				}
			}
			b := t.Schema.ResolveEffectiveField(effField, true)
			*subIdx++
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				arrCol := b.EffectiveArrayColumn(true)
				elemValExpr := "`_elem`"
				if termsSpec.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(termsSpec.Script, effField, "`_elem`", nil); ok {
						elemValExpr = scriptExpr
					}
				} else if effField != "" {
					if effectiveDorisScalarType(b) == schema.DorisBoolean {
						elemValExpr = "CASE WHEN `_elem` IS NULL THEN NULL WHEN LOWER(CAST(`_elem` AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END"
					} else if b.EffectiveLowercase(!strings.HasSuffix(effField, ".keyword")) {
						elemValExpr = "LOWER(CAST(`_elem` AS STRING))"
					}
				}
				if termsSpec.Missing != nil || termsSpec.MissingBucket {
					missingLit := "'__ES_MISSING_BUCKET__'"
					if termsSpec.Missing != nil {
						missingLit = quoteStr(formatMissingScalar(termsSpec.Missing))
					}
					coalescedElem := fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", elemValExpr, missingLit)
					explodeFrom := fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) `_t` AS `_elem`", arrCol, arrCol, arrCol)
					wCond := ""
					if termsExtraWhere != "" {
						wCond = "WHERE " + termsExtraWhere + " "
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
						if termsExtraWhere != "" {
							subWhere = termsExtraWhere
						}
						dedupIdx := *subIdx
						dedupFrom := fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, coalescedElem, dedupIdx, explodeFrom, subWhere, dedupIdx, dedupIdx, dedupIdx)
						t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, fmt.Sprintf("`_rn_bkey_%d`", dedupIdx), dedupFrom, "1=1", subAggs)
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
						quoteStr(fullAggName), bucketKeyExpr, arrCol, termsWherePrefix, size, *subIdx,
					))
					if subAggs := spec.SubAggs(); len(subAggs) > 0 {
						explodeFrom := fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem`", arrCol)
						explodeWhere := fmt.Sprintf("%s`_elem` IS NOT NULL", termsWherePrefix)
						dedupIdx := *subIdx
						dedupFrom := fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, bucketKeyExpr, dedupIdx, explodeFrom, explodeWhere, dedupIdx, dedupIdx, dedupIdx)
						t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, fmt.Sprintf("`_rn_bkey_%d`", dedupIdx),
							dedupFrom, "1=1", subAggs)
					}
				}
			} else {
				col := t.sqlColumnRef(effField, true, nil)
				rawCol := col
				if termsSpec.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(termsSpec.Script, effField, col, nil); ok {
						col = scriptExpr
						rawCol = scriptExpr
					}
				} else if effField != "" {
					if effectiveDorisScalarType(b) == schema.DorisBoolean {
						col = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN LOWER(CAST(%s AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END", rawCol, rawCol)
					} else if b.EffectiveLowercase(!strings.HasSuffix(effField, ".keyword")) {
						col = fmt.Sprintf("LOWER(CAST(%s AS STRING))", rawCol)
					}
				}
				if termsSpec.Missing != nil || termsSpec.MissingBucket {
					missingLit := "'__ES_MISSING_BUCKET__'"
					if termsSpec.Missing != nil {
						missingLit = quoteStr(formatMissingScalar(termsSpec.Missing))
					}
					coalescedCol := fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, missingLit)
					wCond := ""
					if termsExtraWhere != "" {
						wCond = "WHERE " + termsExtraWhere + " "
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
						if termsExtraWhere != "" {
							subWhere = termsExtraWhere
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
						quoteStr(fullAggName), col, termsWherePrefix, rawCol, size, *subIdx,
					))
					if subAggs := spec.SubAggs(); len(subAggs) > 0 {
						t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, fmt.Sprintf("CAST(%s AS STRING)", col),
							"`base_matched`", fmt.Sprintf("%s%s IS NOT NULL", termsWherePrefix, rawCol), subAggs)
					}
				}
			}

		case spec.Nested != nil:
			var corrCol string
			var ok bool
			if t.Schema != nil {
				corrCol, ok = t.Schema.NestedRoots[spec.Nested.Path]
			}
			if !ok {
				if t.Schema != nil && (len(t.Schema.Fields) > 0 || len(t.Schema.NestedRoots) > 0) {
					if t.searchErr == nil {
						t.searchErr = fmt.Errorf("[nested] failed to find nested object under path [%s]", spec.Nested.Path)
					}
				}
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
				return quoteStr(t.nestedRelativeJSONPath(f, true, spec.Nested.Path))
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
					rnPathRaw, _ := subSpec.ReverseNested["path"].(string)
					rnPath := strings.TrimSpace(rnPathRaw)
					if rnPath != "" && t.Schema != nil {
						t.appendAggBranches(branches, subIdx, fullAggName, rnWhere, map[string]esast.AggSpec{
							subName: {
								Nested: &esast.NestedAggSpec{Path: rnPath},
								Aggs:   subSpec.SubAggs(),
							},
						})
					} else {
						*branches = append(*branches, fmt.Sprintf(
							"SELECT %s AS `_agg_name`, '_reverse_nested' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
								"FROM `base_matched` WHERE %s",
							quoteStr(subFull), rnWhere,
						))
						if rnSubAggs := subSpec.SubAggs(); len(rnSubAggs) > 0 {
							t.appendAggBranches(branches, subIdx, subFull, rnWhere, rnSubAggs)
						}
					}
				case subSpec.EffectiveTerms() != nil:
					subTerms := subSpec.EffectiveTerms()
					size := t.maxAggBuckets()
					if capSz := t.capBucketSize(subTerms.Size); capSz > size {
						size = capSz
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
					} else if effField != "" && t.Schema != nil {
						_, nb := t.resolveFieldInNestedCtx(effField, true, nestedElemCtx)
						if effectiveDorisScalarType(nb) == schema.DorisBoolean {
							rawElemExpr = fmt.Sprintf("CAST(CASE WHEN %s IS NULL THEN NULL WHEN LOWER(%s) IN ('true', '1') THEN 'true' ELSE 'false' END AS STRING)", rawElemExpr, rawElemExpr)
						} else if nb.EffectiveLowercase(!strings.HasSuffix(effField, ".keyword")) {
							rawElemExpr = fmt.Sprintf("CAST(LOWER(%s) AS STRING)", rawElemExpr)
						}
					}
					*subIdx++
					var bucketExpr, fromExpr, whereExpr string
					if subTerms.Missing != nil || subTerms.MissingBucket {
						missingLit := "'__ES_MISSING_BUCKET__'"
						if subTerms.Missing != nil {
							missingLit = quoteStr(formatMissingScalar(subTerms.Missing))
						}
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
					if field == "" && script != nil {
						if docF, ok := extractSimpleDocFieldFromScript(script); ok {
							field = docF
						}
					}
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
					havingClause := ""
					if fn == "AVG" || fn == "MIN" || fn == "MAX" {
						havingClause = fmt.Sprintf(" HAVING COUNT(%s) > 0", numExpr)
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s%s",
						quoteStr(subFull), fn, numExpr, corrCol, nWhere, havingClause,
					))
				case subSpec.EffectiveStats() != nil:
					statsSpec := subSpec.EffectiveStats()
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					effStatsField := statsSpec.Field
					if effStatsField == "" && statsSpec.Script != nil {
						if docF, ok := extractSimpleDocFieldFromScript(statsSpec.Script); ok {
							effStatsField = docF
						}
					}
					relJSONPath := nestedRelJSON(effStatsField)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					nWhere := fmt.Sprintf("%sjson_extract_string(`_nel`, %s) IS NOT NULL", wherePrefix, relJSONPath)
					if statsSpec.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(statsSpec.Missing); ok {
							if effStatsField != "" {
								numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					if statsSpec.Script != nil {
						overrideExpr := ""
						if effStatsField != "" {
							overrideExpr = numExpr
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(statsSpec.Script, effStatsField, overrideExpr, nestedElemCtx); ok {
							numExpr = scriptExpr
							if statsSpec.Missing != nil && effStatsField == "" {
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
					effPctField := subSpec.Percentiles.Field
					if effPctField == "" && subSpec.Percentiles.Script != nil {
						if docF, ok := extractSimpleDocFieldFromScript(subSpec.Percentiles.Script); ok {
							effPctField = docF
						}
					}
					relJSONPath := nestedRelJSON(effPctField)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					nWhere := fmt.Sprintf("%sjson_extract_string(`_nel`, %s) IS NOT NULL", wherePrefix, relJSONPath)
					if subSpec.Percentiles.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Percentiles.Missing); ok {
							if effPctField != "" {
								numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					if subSpec.Percentiles.Script != nil {
						overrideExpr := ""
						if effPctField != "" {
							overrideExpr = numExpr
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.Percentiles.Script, effPctField, overrideExpr, nestedElemCtx); ok {
							numExpr = scriptExpr
							if subSpec.Percentiles.Missing != nil && effPctField == "" {
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
					effPRField := subSpec.PercentileRanks.Field
					if effPRField == "" && subSpec.PercentileRanks.Script != nil {
						if docF, ok := extractSimpleDocFieldFromScript(subSpec.PercentileRanks.Script); ok {
							effPRField = docF
						}
					}
					relJSONPath := nestedRelJSON(effPRField)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					nWhere := fmt.Sprintf("%sjson_extract_string(`_nel`, %s) IS NOT NULL", wherePrefix, relJSONPath)
					if subSpec.PercentileRanks.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.PercentileRanks.Missing); ok {
							if effPRField != "" {
								numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					if subSpec.PercentileRanks.Script != nil {
						overrideExpr := ""
						if effPRField != "" {
							overrideExpr = numExpr
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.PercentileRanks.Script, effPRField, overrideExpr, nestedElemCtx); ok {
							numExpr = scriptExpr
							if subSpec.PercentileRanks.Missing != nil && effPRField == "" {
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
					effBoxField := subSpec.Boxplot.Field
					if effBoxField == "" && subSpec.Boxplot.Script != nil {
						if docF, ok := extractSimpleDocFieldFromScript(subSpec.Boxplot.Script); ok {
							effBoxField = docF
						}
					}
					relJSONPath := nestedRelJSON(effBoxField)
					numExpr := fmt.Sprintf("CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
					nWhere := fmt.Sprintf("%sjson_extract_string(`_nel`, %s) IS NOT NULL", wherePrefix, relJSONPath)
					if subSpec.Boxplot.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Boxplot.Missing); ok {
							if effBoxField != "" {
								numExpr = fmt.Sprintf("COALESCE(%s, %s)", numExpr, strconv.FormatFloat(mf, 'f', -1, 64))
							}
							nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
						}
					}
					if subSpec.Boxplot.Script != nil {
						overrideExpr := ""
						if effBoxField != "" {
							overrideExpr = numExpr
						}
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(subSpec.Boxplot.Script, effBoxField, overrideExpr, nestedElemCtx); ok {
							numExpr = scriptExpr
							if subSpec.Boxplot.Missing != nil && effBoxField == "" {
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
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					effSSField := subSpec.StringStats.Field
					if effSSField == "" && subSpec.StringStats.Script != nil {
						if docF, ok := extractSimpleDocFieldFromScript(subSpec.StringStats.Script); ok {
							effSSField = docF
						}
					}
					relJSONPath := nestedRelJSON(effSSField)
					valExpr := fmt.Sprintf("json_extract_string(`_nel`, %s)", relJSONPath)
					nWhere := fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, valExpr)
					if subSpec.StringStats.Missing != nil {
						if effSSField != "" {
							valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", valExpr, quoteStr(formatMissingScalar(subSpec.StringStats.Missing)))
						} else {
							valExpr = quoteStr(formatMissingScalar(subSpec.StringStats.Missing))
						}
						nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
					}
					if subSpec.StringStats.Script != nil {
						overrideExpr := ""
						if effSSField != "" {
							overrideExpr = valExpr
						}
						if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.StringStats.Script, effSSField, overrideExpr, nestedElemCtx); ok {
							valExpr = scriptExpr
							if subSpec.StringStats.Missing != nil && effSSField == "" {
								valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", valExpr, quoteStr(formatMissingScalar(subSpec.StringStats.Missing)))
							}
							if subSpec.StringStats.Missing != nil {
								nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
							} else {
								nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL AND (%s) IS NOT NULL", wherePrefix, valExpr)
							}
						}
					}
					lenExpr := fmt.Sprintf("CAST(CHAR_LENGTH(CAST(%s AS STRING)) AS DOUBLE)", valExpr)
					for _, op := range []struct{ key, fn string }{
						{"_stats_count", "COUNT"},
						{"_stats_min", "MIN"},
						{"_stats_max", "MAX"},
						{"_stats_avg", "AVG"},
					} {
						*branches = append(*branches, fmt.Sprintf(
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
								"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s",
							quoteStr(subFull), quoteStr(op.key), op.fn, lenExpr, corrCol, nWhere,
						))
					}
				case subSpec.Cardinality != nil:
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					effCardField := subSpec.Cardinality.Field
					if effCardField == "" && subSpec.Cardinality.Script != nil {
						if docF, ok := extractSimpleDocFieldFromScript(subSpec.Cardinality.Script); ok {
							effCardField = docF
						}
					}
					relJSONPath := nestedRelJSON(effCardField)
					valExpr := fmt.Sprintf("json_extract_string(`_nel`, %s)", relJSONPath)
					nWhere := fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, valExpr)
					if subSpec.Cardinality.Missing != nil {
						if effCardField != "" {
							valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", valExpr, quoteStr(formatMissingScalar(subSpec.Cardinality.Missing)))
						}
						nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
					}
					if subSpec.Cardinality.Script != nil {
						overrideExpr := ""
						if effCardField != "" {
							overrideExpr = valExpr
						}
						if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.Cardinality.Script, effCardField, overrideExpr, nestedElemCtx); ok {
							valExpr = scriptExpr
							if subSpec.Cardinality.Missing != nil && effCardField == "" {
								valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", valExpr, quoteStr(formatMissingScalar(subSpec.Cardinality.Missing)))
							}
							if subSpec.Cardinality.Missing != nil {
								nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
							} else {
								nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL AND (%s) IS NOT NULL", wherePrefix, valExpr)
							}
						}
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COUNT(DISTINCT %s) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel` WHERE %s",
						quoteStr(subFull), valExpr, corrCol, nWhere,
					))
				case subSpec.ValueCount != nil:
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					effVCField := subSpec.ValueCount.Field
					if effVCField == "" && subSpec.ValueCount.Script != nil {
						if docF, ok := extractSimpleDocFieldFromScript(subSpec.ValueCount.Script); ok {
							effVCField = docF
						}
					}
					relJSONPath := nestedRelJSON(effVCField)
					valExpr := fmt.Sprintf("json_extract_string(`_nel`, %s)", relJSONPath)
					nWhere := fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, valExpr)
					if subSpec.ValueCount.Missing != nil {
						if effVCField != "" {
							valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", valExpr, quoteStr(formatMissingScalar(subSpec.ValueCount.Missing)))
						}
						nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
					}
					if subSpec.ValueCount.Script != nil {
						overrideExpr := ""
						if effVCField != "" {
							overrideExpr = valExpr
						}
						if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.ValueCount.Script, effVCField, overrideExpr, nestedElemCtx); ok {
							valExpr = scriptExpr
							if subSpec.ValueCount.Missing != nil && effVCField == "" {
								valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", valExpr, quoteStr(formatMissingScalar(subSpec.ValueCount.Missing)))
							}
							if subSpec.ValueCount.Missing != nil {
								nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
							} else {
								nWhere = fmt.Sprintf("%s`_nel` IS NOT NULL AND (%s) IS NOT NULL", wherePrefix, valExpr)
							}
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
			prevInFilter := t.inFilterAggQuery
			t.inFilterAggQuery = true
			cond := t.CompileQuery(spec.Filter, false, nil)
			t.inFilterAggQuery = prevInFilter
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
					prevInFilter := t.inFilterAggQuery
					t.inFilterAggQuery = true
					cond := t.CompileQuery(&fq, false, nil)
					t.inFilterAggQuery = prevInFilter
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
					prevInFilter := t.inFilterAggQuery
					t.inFilterAggQuery = true
					cond := t.CompileQuery(&fq, false, nil)
					t.inFilterAggQuery = prevInFilter
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
			b := t.Schema.ResolveEffectiveField(effCardField, true)
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
			effSSField := spec.StringStats.Field
			if effSSField == "" && spec.StringStats.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.StringStats.Script); ok {
					effSSField = docF
				}
			}
			b := t.Schema.ResolveEffectiveField(effSSField, true)
			statOps := []struct{ key, fn string }{
				{"_stats_count", "COUNT"},
				{"_stats_min", "MIN"},
				{"_stats_max", "MAX"},
				{"_stats_avg", "AVG"},
			}
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				arrCol := b.EffectiveArrayColumn(true)
				valExpr := "CAST(`_nel` AS STRING)"
				explodeExpr := fmt.Sprintf("`%s`", arrCol)
				wCond := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
				if spec.StringStats.Missing != nil {
					missLit := quoteStr(formatMissingScalar(spec.StringStats.Missing))
					valExpr = fmt.Sprintf("COALESCE(CAST(`_nel` AS STRING), %s)", missLit)
					explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END", arrCol, arrCol, arrCol)
					wCond = ""
					if extraWhere != "" {
						wCond = " WHERE " + extraWhere
					}
				}
				if spec.StringStats.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(spec.StringStats.Script, effSSField, valExpr, nil); ok {
						valExpr = fmt.Sprintf("CAST(%s AS STRING)", scriptExpr)
					}
				}
				lenExpr := fmt.Sprintf("CAST(CHAR_LENGTH(%s) AS DOUBLE)", valExpr)
				for _, statOp := range statOps {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_nt` AS `_nel`%s",
						quoteStr(fullAggName), quoteStr(statOp.key), statOp.fn, lenExpr, explodeExpr, wCond,
					))
				}
			} else {
				col := t.sqlColumnRef(effSSField, true, nil)
				notNullCond := fmt.Sprintf("%s IS NOT NULL", col)
				if spec.StringStats.Missing != nil && effSSField != "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(spec.StringStats.Missing)))
					notNullCond = ""
				}
				if spec.StringStats.Script != nil {
					overrideExpr := ""
					if effSSField != "" {
						overrideExpr = col
					}
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(spec.StringStats.Script, effSSField, overrideExpr, nil); ok {
						col = scriptExpr
						notNullCond = fmt.Sprintf("%s IS NOT NULL", col)
					}
				}
				if spec.StringStats.Missing != nil && effSSField == "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(spec.StringStats.Missing)))
					notNullCond = ""
				}
				wClause := ""
				if notNullCond != "" {
					wClause = fmt.Sprintf(" WHERE %s%s", wherePrefix, notNullCond)
				} else if extraWhere != "" {
					wClause = " WHERE " + extraWhere
				}
				lenExpr := fmt.Sprintf("CAST(CHAR_LENGTH(CAST(%s AS STRING)) AS DOUBLE)", col)
				for _, statOp := range statOps {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched`%s",
						quoteStr(fullAggName), quoteStr(statOp.key), statOp.fn, lenExpr, wClause,
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
			if spec.DateHistogram.HardBounds != nil {
				if minMs, okMin := t.resolveDateHistogramMissingMs(b.ESType, spec.DateHistogram.HardBounds.Min); okMin {
					notNullCond = fmt.Sprintf("(%s) AND (%s >= %d)", notNullCond, col, minMs)
				}
				if maxMs, okMax := t.resolveDateHistogramMissingMs(b.ESType, spec.DateHistogram.HardBounds.Max); okMax {
					notNullCond = fmt.Sprintf("(%s) AND (%s <= %d)", notNullCond, col, maxMs)
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
					dedupIdx := *subIdx
					subFromClause = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, bucketExpr, dedupIdx, fromClause, notNullCond, dedupIdx, dedupIdx, dedupIdx)
					subBucketExpr = fmt.Sprintf("`_rn_bkey_%d`", dedupIdx)
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
			if spec.Histogram.HardBounds != nil {
				if minF, okMin := resolveHistogramMissingFloat(spec.Histogram.HardBounds.Min); okMin {
					notNullCond = fmt.Sprintf("(%s) AND (%s >= %s)", notNullCond, col, strconv.FormatFloat(minF, 'f', -1, 64))
				}
				if maxF, okMax := resolveHistogramMissingFloat(spec.Histogram.HardBounds.Max); okMax {
					notNullCond = fmt.Sprintf("(%s) AND (%s <= %s)", notNullCond, col, strconv.FormatFloat(maxF, 'f', -1, 64))
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
					dedupIdx := *subIdx
					subFromClause = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, bucketExpr, dedupIdx, fromClause, notNullCond, dedupIdx, dedupIdx, dedupIdx)
					subBucketExpr = fmt.Sprintf("`_rn_bkey_%d`", dedupIdx)
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
			b := t.Schema.ResolveEffectiveField(effRField, true)
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
				b := t.Schema.ResolveEffectiveField(field, true)
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
						b := t.Schema.ResolveEffectiveField(effField, true)
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
							hasHistogramSrc = true
							expr = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN LOWER(CAST(%s AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END", col, col)
						} else if b.EffectiveLowercase(!strings.HasSuffix(effField, ".keyword")) && srcSpec.Terms.Script == nil && !strings.HasPrefix(expr, "LOWER(") {
							hasHistogramSrc = true
							expr = fmt.Sprintf("LOWER(%s)", expr)
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
						dhB := t.Schema.ResolveEffectiveField(effDHField, true)
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
				if len(spec.Composite.After) > 0 {
					for _, sn := range srcNames {
						if av, ok := spec.Composite.After[sn]; !ok || av == nil {
							hasHistogramSrc = true
							break
						}
					}
				}
				if hasHistogramSrc {
					size = t.maxAggBuckets()
				} else if len(spec.Composite.After) > 0 {
					size = t.maxAggBuckets()
					var afterParts []string
					for _, sn := range srcNames {
						if av, ok := spec.Composite.After[sn]; ok && av != nil {
							if fv, ok := av.(float64); ok && fv == math.Trunc(fv) {
								afterParts = append(afterParts, strconv.FormatInt(int64(fv), 10))
							} else {
								afterParts = append(afterParts, fmt.Sprintf("%v", av))
							}
						} else {
							afterParts = append(afterParts, "__ES_MISSING_BUCKET__")
						}
					}
					afterCursor := strings.Join(afterParts, "\x1f")
					wCond = fmt.Sprintf("(%s) AND (%s > %s)", wCond, bucketKeyExpr, quoteStr(afterCursor))
				}
				if extraWhere != "" {
					wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
				}
				compCountExpr := "COUNT(*)"
				if compExplodeIdx > 0 {
					compCountExpr = "COUNT(DISTINCT `_id`)"
				}
				*subIdx++
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s "+
						"GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(fullAggName), bucketKeyExpr, compCountExpr, compFrom, wCond, size, *subIdx,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					subBucketExpr := bucketKeyExpr
					subFromClause := compFrom
					subWhereCond := wCond
					if compExplodeIdx > 0 {
						dedupIdx := *subIdx
						subFromClause = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, bucketKeyExpr, dedupIdx, compFrom, wCond, dedupIdx, dedupIdx, dedupIdx)
						subBucketExpr = fmt.Sprintf("`_rn_bkey_%d`", dedupIdx)
						subWhereCond = "1=1"
					}
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, subBucketExpr,
						subFromClause, subWhereCond, subAggs)
				}
			}

		case spec.WeightedAvg != nil:
			vCol := t.sqlNumericColumnRef(spec.WeightedAvg.Value.Field, nil)
			if spec.WeightedAvg.Value.Missing != nil && spec.WeightedAvg.Value.Field != "" {
				if mf, ok := resolveHistogramMissingFloat(spec.WeightedAvg.Value.Missing); ok {
					vCol = fmt.Sprintf("COALESCE(%s, %s)", vCol, strconv.FormatFloat(mf, 'f', -1, 64))
				}
			}
			if spec.WeightedAvg.Value.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(spec.WeightedAvg.Value.Script, spec.WeightedAvg.Value.Field, vCol, nil); ok {
					vCol = se
				}
			}
			wCol := t.sqlNumericColumnRef(spec.WeightedAvg.Weight.Field, nil)
			if spec.WeightedAvg.Weight.Missing != nil && spec.WeightedAvg.Weight.Field != "" {
				if mf, ok := resolveHistogramMissingFloat(spec.WeightedAvg.Weight.Missing); ok {
					wCol = fmt.Sprintf("COALESCE(%s, %s)", wCol, strconv.FormatFloat(mf, 'f', -1, 64))
				}
			}
			if spec.WeightedAvg.Weight.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(spec.WeightedAvg.Weight.Script, spec.WeightedAvg.Weight.Field, wCol, nil); ok {
					wCol = se
				}
			}
			wCond := fmt.Sprintf("%s IS NOT NULL AND %s IS NOT NULL", vCol, wCol)
			if extraWhere != "" {
				wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(SUM((%s) * (%s)) / NULLIF(SUM(%s), 0), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s HAVING COUNT(%s) > 0",
				quoteStr(fullAggName), vCol, wCol, wCol, wCond, vCol,
			))

		case spec.MedianAbsoluteDeviation != nil:
			effField := spec.MedianAbsoluteDeviation.Field
			if effField == "" && spec.MedianAbsoluteDeviation.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.MedianAbsoluteDeviation.Script); ok {
					effField = docF
				}
			}
			col := t.sqlNumericColumnRef(effField, nil)
			if spec.MedianAbsoluteDeviation.Missing != nil && effField != "" {
				if mf, ok := resolveHistogramMissingFloat(spec.MedianAbsoluteDeviation.Missing); ok {
					col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
				}
			}
			if spec.MedianAbsoluteDeviation.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(spec.MedianAbsoluteDeviation.Script, effField, col, nil); ok {
					col = se
				}
			}
			wCond := fmt.Sprintf("%s IS NOT NULL", col)
			if extraWhere != "" {
				wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, 0.5000), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s HAVING COUNT(%s) > 0",
				quoteStr(fullAggName), col, wCond, col,
			))

		case spec.RareTerms != nil:
			maxDocCount := 1
			if spec.RareTerms.MaxDocCount != nil && *spec.RareTerms.MaxDocCount >= 1 {
				maxDocCount = *spec.RareTerms.MaxDocCount
			}
			col := t.sqlColumnRef(spec.RareTerms.Field, true, nil)
			wCond := fmt.Sprintf("%s IS NOT NULL", col)
			if spec.RareTerms.Missing != nil {
				col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(spec.RareTerms.Missing)))
				wCond = "1=1"
			}
			if extraWhere != "" {
				wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, CAST(%s AS STRING) AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s "+
					"GROUP BY `_bucket_key` HAVING COUNT(*) <= %d ORDER BY `_doc_count` ASC, `_bucket_key` ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), col, wCond, maxDocCount, t.maxAggBuckets(), *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, fmt.Sprintf("CAST(%s AS STRING)", col), "`base_matched`", wCond, subAggs)
			}

		case spec.MultiTerms != nil && len(spec.MultiTerms.Terms) > 0:
			size := t.capBucketSize(spec.MultiTerms.Size)
			var termExprs, notNulls []string
			for _, mt := range spec.MultiTerms.Terms {
				col := t.sqlColumnRef(mt.Field, true, nil)
				if mt.Script != nil {
					if se, ok := t.compilePolymorphicScriptExpr(mt.Script, mt.Field, col, nil); ok {
						col = se
					}
				}
				if mt.Missing != nil {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(mt.Missing)))
				} else {
					notNulls = append(notNulls, fmt.Sprintf("%s IS NOT NULL", col))
				}
				termExprs = append(termExprs, fmt.Sprintf("CAST(%s AS STRING)", col))
			}
			keyExpr := termExprs[0]
			if len(termExprs) > 1 {
				keyExpr = fmt.Sprintf("CONCAT_WS('|', %s)", strings.Join(termExprs, ", "))
			}
			wCond := "1=1"
			if len(notNulls) > 0 {
				wCond = strings.Join(notNulls, " AND ")
			}
			if extraWhere != "" {
				wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), keyExpr, wCond, size, *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, keyExpr, "`base_matched`", wCond, subAggs)
			}

		case spec.AutoDateHistogram != nil:
			effField := spec.AutoDateHistogram.Field
			if effField == "" && spec.AutoDateHistogram.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.AutoDateHistogram.Script); ok {
					effField = docF
				}
			}
			col := t.sqlNumericColumnRef(effField, nil)
			if spec.AutoDateHistogram.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(spec.AutoDateHistogram.Script, effField, col, nil); ok {
					col = se
				}
			}
			wCond := fmt.Sprintf("%s IS NOT NULL", col)
			if extraWhere != "" {
				wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
			}
			keyExpr := fmt.Sprintf("CAST(CAST(FLOOR(%s / 3600000) * 3600000 AS BIGINT) AS STRING)", col)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), keyExpr, wCond, t.maxAggBuckets(), *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, keyExpr, "`base_matched`", wCond, subAggs)
			}

		case spec.VariableWidthHistogram != nil:
			effField := spec.VariableWidthHistogram.Field
			if effField == "" && spec.VariableWidthHistogram.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.VariableWidthHistogram.Script); ok {
					effField = docF
				}
			}
			col := t.sqlNumericColumnRef(effField, nil)
			if spec.VariableWidthHistogram.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(spec.VariableWidthHistogram.Script, effField, col, nil); ok {
					col = se
				}
			}
			wCond := fmt.Sprintf("%s IS NOT NULL", col)
			if extraWhere != "" {
				wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
			}
			keyExpr := fmt.Sprintf("CAST(FLOOR(%s) AS STRING)", col)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), keyExpr, wCond, t.maxAggBuckets(), *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, keyExpr, "`base_matched`", wCond, subAggs)
			}

		case spec.AdjacencyMatrix != nil && len(spec.AdjacencyMatrix.Filters) > 0:
			sep := spec.AdjacencyMatrix.Separator
			if sep == "" {
				sep = "&"
			}
			fKeys := sortedMapKeys(spec.AdjacencyMatrix.Filters)
			condMap := make(map[string]string, len(fKeys))
			for _, fk := range fKeys {
				fq := spec.AdjacencyMatrix.Filters[fk]
				c := t.CompileQuery(&fq, false, nil)
				wCond := c.WhereSQL
				if extraWhere != "" {
					wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
				}
				condMap[fk] = wCond
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched` WHERE %s",
					quoteStr(fullAggName), quoteStr(fk), wCond,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, quoteStr(fk), "`base_matched`", wCond, subAggs)
				}
			}
			for i := 0; i < len(fKeys); i++ {
				for j := i + 1; j < len(fKeys); j++ {
					pairKey := fKeys[i] + sep + fKeys[j]
					pairCond := fmt.Sprintf("(%s) AND (%s)", condMap[fKeys[i]], condMap[fKeys[j]])
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` WHERE %s",
						quoteStr(fullAggName), quoteStr(pairKey), pairCond,
					))
					if subAggs := spec.SubAggs(); len(subAggs) > 0 {
						t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, quoteStr(pairKey), "`base_matched`", pairCond, subAggs)
					}
				}
			}

		case spec.GeoBounds != nil:
			gbField, b := t.resolveFieldInNestedCtx(spec.GeoBounds.Field, false, nil)
			latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(gbField, b)
			wCond := notNullCond
			if extraWhere != "" {
				wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
			}
			for _, op := range []struct{ key, expr string }{
				{"_gb_top", fmt.Sprintf("MAX(%s)", latExpr)},
				{"_gb_bottom", fmt.Sprintf("MIN(%s)", latExpr)},
				{"_gb_left", fmt.Sprintf("MIN(%s)", lonExpr)},
				{"_gb_right", fmt.Sprintf("MAX(%s)", lonExpr)},
			} {
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(%s, 0) AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched` WHERE %s HAVING COUNT(%s) > 0",
					quoteStr(fullAggName+"."+op.key), op.expr, wCond, latExpr,
				))
			}

		case spec.GeoCentroid != nil:
			gcField, b := t.resolveFieldInNestedCtx(spec.GeoCentroid.Field, false, nil)
			latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(gcField, b)
			wCond := notNullCond
			if extraWhere != "" {
				wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
			}
			for _, op := range []struct{ key, expr string }{
				{"_gc_count", fmt.Sprintf("COUNT(%s)", latExpr)},
				{"_gc_lat", fmt.Sprintf("AVG(%s)", latExpr)},
				{"_gc_lon", fmt.Sprintf("AVG(%s)", lonExpr)},
			} {
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(%s, 0) AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched` WHERE %s",
					quoteStr(fullAggName+"."+op.key), op.expr, wCond,
				))
			}

		case spec.GeoDistance != nil && len(spec.GeoDistance.Ranges) > 0:
			gdField, b := t.resolveFieldInNestedCtx(spec.GeoDistance.Field, false, nil)
			origLat, origLon, _ := esast.ParseGeoPoint(spec.GeoDistance.Origin)
			latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(gdField, b)
			distExpr := fmt.Sprintf("ST_Distance_Sphere(%s, %s, %s, %s)",
				lonExpr, latExpr, strconv.FormatFloat(origLon, 'f', -1, 64), strconv.FormatFloat(origLat, 'f', -1, 64))
			unitMult := 1.0
			if mult, ok := esast.GeoDistanceUnitMultiplier(strings.TrimSpace(spec.GeoDistance.Unit)); ok && mult > 0 {
				unitMult = mult
			}
			for _, rng := range spec.GeoDistance.Ranges {
				conds := []string{notNullCond}
				if rng.From != nil {
					if fv, ok := parseFiniteFloatValue(rng.From); ok {
						conds = append(conds, fmt.Sprintf("%s >= %s", distExpr, strconv.FormatFloat(fv*unitMult, 'f', -1, 64)))
					}
				}
				if rng.To != nil {
					if fv, ok := parseFiniteFloatValue(rng.To); ok {
						conds = append(conds, fmt.Sprintf("%s < %s", distExpr, strconv.FormatFloat(fv*unitMult, 'f', -1, 64)))
					}
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
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, quoteStr(bKey), "`base_matched`", rWhere, subAggs)
				}
			}

		case spec.GeohashGrid != nil || spec.GeotileGrid != nil:
			ggSpec := spec.GeohashGrid
			if ggSpec == nil {
				ggSpec = spec.GeotileGrid
			}
			ggField, b := t.resolveFieldInNestedCtx(ggSpec.Field, false, nil)
			latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(ggField, b)
			wCond := notNullCond
			if extraWhere != "" {
				wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
			}
			keyExpr := fmt.Sprintf("CONCAT(CAST(FLOOR(%s) AS STRING), '/', CAST(FLOOR(%s) AS STRING))", latExpr, lonExpr)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), keyExpr, wCond, t.maxAggBuckets(), *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, keyExpr, "`base_matched`", wCond, subAggs)
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
	b := t.Schema.ResolveEffectiveField(effField, true)
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
		effField := field
		if b.AliasTarget != "" {
			effField = b.AliasTarget
		}
		return nctx != nil && ((b.Kind == schema.StorageNestedSubfield && b.NestedPath == nctx.nestedPath) || strings.HasPrefix(effField, nctx.nestedPath+"."))
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
		effField, b := t.resolveFieldInNestedCtx(effField, false, nctx)
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
			havingClause := ""
			if fn == "AVG" || fn == "MIN" || fn == "MAX" {
				havingClause = fmt.Sprintf(" HAVING COUNT(%s) > 0", col)
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`%s",
				quoteStr(subFull), parentBucketExpr, fn, col, fromClause, subWhere, havingClause,
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
			havingClause := ""
			if fn == "AVG" || fn == "MIN" || fn == "MAX" {
				havingClause = fmt.Sprintf(" HAVING COUNT(%s) > 0", valExpr)
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`%s",
				quoteStr(subFull), parentBucketExpr, fn, valExpr, subFrom, subWhere, havingClause,
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
		havingClause := ""
		if fn == "AVG" || fn == "MIN" || fn == "MAX" {
			havingClause = fmt.Sprintf(" HAVING COUNT(%s) > 0", col)
		}
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
				"FROM %s WHERE %s GROUP BY `_bucket_key`%s",
			quoteStr(subFull), parentBucketExpr, fn, col, fromClause, whereClause, havingClause,
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
				effRateField := subSpec.Rate.Field
				if effRateField == "" && subSpec.Rate.Script != nil {
					if docF, ok := extractSimpleDocFieldFromScript(subSpec.Rate.Script); ok {
						effRateField = docF
					}
				}
				rateField, b := t.resolveFieldInNestedCtx(effRateField, true, nctx)
				arrCol := b.EffectiveArrayColumn(true)
				if !isExplodedNested(b, rateField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
					valExpr := subElemAlias
					if subSpec.Rate.Script != nil {
						if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.Rate.Script, rateField, subElemAlias, nil); ok {
							valExpr = scriptExpr
						}
					}
					subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
					subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(%s) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull), parentBucketExpr, valExpr, subFrom, subWhere,
					))
				} else {
					var col string
					if rateField != "" {
						col = t.sqlColumnRef(rateField, true, nctx)
					}
					if subSpec.Rate.Script != nil {
						if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.Rate.Script, rateField, col, nctx); ok {
							col = scriptExpr
						}
					}
					if col == "" {
						col = t.sqlColumnRef(rateField, true, nctx)
					}
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
			effPctField, b := t.resolveFieldInNestedCtx(effPctField, false, nctx)
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
			effBpField, b := t.resolveFieldInNestedCtx(effBpField, false, nctx)
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
			effPrField, b := t.resolveFieldInNestedCtx(effPrField, false, nctx)
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
			effSSField := subSpec.StringStats.Field
			if effSSField == "" && subSpec.StringStats.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.StringStats.Script); ok {
					effSSField = docF
				}
			}
			ssField, b := t.resolveFieldInNestedCtx(effSSField, true, nctx)
			arrCol := b.EffectiveArrayColumn(true)
			var lenExpr, subFrom, subWhere string
			if !isExplodedNested(b, ssField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				valExpr := fmt.Sprintf("CAST(%s AS STRING)", subElemAlias)
				subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
				if subSpec.StringStats.Missing != nil {
					valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", subElemAlias, quoteStr(formatMissingScalar(subSpec.StringStats.Missing)))
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
					subWhere = whereClause
				}
				if subSpec.StringStats.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.StringStats.Script, ssField, valExpr, nil); ok {
						valExpr = fmt.Sprintf("CAST(%s AS STRING)", scriptExpr)
					}
				}
				lenExpr = fmt.Sprintf("CAST(CHAR_LENGTH(%s) AS DOUBLE)", valExpr)
			} else {
				col := t.sqlColumnRef(ssField, true, nctx)
				subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
				if subSpec.StringStats.Missing != nil && ssField != "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(subSpec.StringStats.Missing)))
					subWhere = whereClause
				}
				if subSpec.StringStats.Script != nil {
					overrideExpr := ""
					if ssField != "" {
						overrideExpr = col
					}
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(subSpec.StringStats.Script, ssField, overrideExpr, nctx); ok {
						col = scriptExpr
						if subSpec.StringStats.Missing == nil {
							subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
						}
					}
				}
				if subSpec.StringStats.Missing != nil && ssField == "" {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(subSpec.StringStats.Missing)))
					subWhere = whereClause
				}
				lenExpr = fmt.Sprintf("CAST(CHAR_LENGTH(CAST(%s AS STRING)) AS DOUBLE)", col)
				subFrom = fromClause
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
			rnPathRaw, _ := subSpec.ReverseNested["path"].(string)
			rnPath := strings.TrimSpace(rnPathRaw)
			if rnPath != "" && t.Schema != nil {
				rnCorrCol, ok := t.Schema.NestedRoots[rnPath]
				if !ok {
					rnCorrCol = "n__" + schema.SanitizeDorisIdentifier(rnPath)
				}
				rnFrom := fromClause
				rnBucketExpr := parentBucketExpr
				rnWhere := whereClause
				if fromClause != "`base_matched`" {
					*subIdx++
					rnIdx := *subIdx
					rnFrom = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", rnIdx, parentBucketExpr, rnIdx, fromClause, whereClause, rnIdx, rnIdx, rnIdx)
					rnBucketExpr = fmt.Sprintf("`_rn_bkey_%d`", rnIdx)
					rnWhere = "1=1"
				}
				rnFromExploded := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) `_nt_rn` AS `_nel`", rnFrom, rnCorrCol)
				rnWhereExploded := "`_nel` IS NOT NULL"
				if rnWhere != "" && rnWhere != "1=1" {
					rnWhereExploded = fmt.Sprintf("(%s) AND `_nel` IS NOT NULL", rnWhere)
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), rnBucketExpr, rnFromExploded, rnWhereExploded,
				))
				if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, rnBucketExpr, rnFromExploded, rnWhereExploded, &nestedCtx{nestedPath: rnPath, elemVar: "`_nel`"}, nestedSubs)
				}
			} else {
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
						*subIdx++
						rnIdx := *subIdx
						rnFrom = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", rnIdx, parentBucketExpr, rnIdx, fromClause, whereClause, rnIdx, rnIdx, rnIdx)
						rnBucketExpr = fmt.Sprintf("`_rn_bkey_%d`", rnIdx)
						rnWhere = "1=1"
					}
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, rnBucketExpr, rnFrom, rnWhere, nil, nestedSubs)
				}
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
			effVCField, b := t.resolveFieldInNestedCtx(effVCField, true, nctx)
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
			effCardField, b := t.resolveFieldInNestedCtx(effCardField, true, nctx)
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
			effSubField, b := t.resolveFieldInNestedCtx(effSubField, true, nctx)
			effSubSize := t.capBucketSize(subTerms.Size)
			if subTerms.Order != nil || subTerms.Include != nil || subTerms.Exclude != nil {
				effSubSize = t.maxAggBuckets()
			}
			subLimit := t.capBucketSize(effSubSize * 100)
			*subIdx++
			if !isExplodedNested(b, effSubField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				arrCol := b.EffectiveArrayColumn(true)
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				elemValExpr := subElemAlias
				if subTerms.Script == nil && effSubField != "" {
					if effectiveDorisScalarType(b) == schema.DorisBoolean {
						elemValExpr = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN LOWER(CAST(%s AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END", subElemAlias, subElemAlias)
					} else if b.EffectiveLowercase(!strings.HasSuffix(effSubField, ".keyword")) {
						elemValExpr = fmt.Sprintf("LOWER(CAST(%s AS STRING))", subElemAlias)
					}
				}
				valExpr := fmt.Sprintf("CAST(%s AS STRING)", elemValExpr)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
				if subTerms.Missing != nil || subTerms.MissingBucket {
					missingLit := "'__ES_MISSING_BUCKET__'"
					if subTerms.Missing != nil {
						missingLit = quoteStr(formatMissingScalar(subTerms.Missing))
					}
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, arrCol, subTableAlias, subElemAlias)
					valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", elemValExpr, missingLit)
					subWhere = whereClause
				}
				if subTerms.Script != nil {
					if scriptExpr, ok := t.compilePolymorphicScriptExpr(subTerms.Script, effSubField, valExpr, nil); ok {
						valExpr = fmt.Sprintf("CAST(%s AS STRING)", scriptExpr)
					}
				}
				childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, valExpr)
				childCountExpr := "COUNT(DISTINCT `_id`)"
				if nctx != nil {
					childCountExpr = "COUNT(*)"
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s "+
						"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(subFull), childKeyExpr, childCountExpr, subFrom, subWhere, subLimit, *subIdx,
				))
				if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
					nextKeyExpr := childKeyExpr
					nextFrom := subFrom
					nextWhere := subWhere
					if nctx == nil {
						dedupIdx := *subIdx
						nextFrom = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, childKeyExpr, dedupIdx, subFrom, subWhere, dedupIdx, dedupIdx, dedupIdx)
						nextKeyExpr = fmt.Sprintf("`_rn_bkey_%d`", dedupIdx)
						nextWhere = "1=1"
					}
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, nextKeyExpr, nextFrom, nextWhere, nctx, nestedSubs)
				}
			} else {
				col := t.sqlColumnRef(effSubField, true, nctx)
				if subTerms.Script == nil && effSubField != "" {
					if effectiveDorisScalarType(b) == schema.DorisBoolean {
						col = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN LOWER(CAST(%s AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END", col, col)
					} else if b.EffectiveLowercase(!strings.HasSuffix(effSubField, ".keyword")) {
						col = fmt.Sprintf("LOWER(CAST(%s AS STRING))", col)
					}
				}
				if (subTerms.Missing != nil || subTerms.MissingBucket) && effSubField != "" {
					missingLit := "'__ES_MISSING_BUCKET__'"
					if subTerms.Missing != nil {
						missingLit = quoteStr(formatMissingScalar(subTerms.Missing))
					}
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, missingLit)
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
				if (subTerms.Missing != nil || subTerms.MissingBucket) && effSubField == "" {
					missingLit := "'__ES_MISSING_BUCKET__'"
					if subTerms.Missing != nil {
						missingLit = quoteStr(formatMissingScalar(subTerms.Missing))
					}
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, missingLit)
				}
				childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', CAST(%s AS STRING))", parentBucketExpr, col)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
				if subTerms.Missing != nil || subTerms.MissingBucket {
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
			effDHField, b := t.resolveFieldInNestedCtx(effDHField, false, nctx)
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
			if subSpec.DateHistogram.HardBounds != nil {
				if minMs, okMin := t.resolveDateHistogramMissingMs(b.ESType, subSpec.DateHistogram.HardBounds.Min); okMin {
					subWhere = fmt.Sprintf("(%s) AND (%s >= %d)", subWhere, col, minMs)
				}
				if maxMs, okMax := t.resolveDateHistogramMissingMs(b.ESType, subSpec.DateHistogram.HardBounds.Max); okMax {
					subWhere = fmt.Sprintf("(%s) AND (%s <= %d)", subWhere, col, maxMs)
				}
			}
			dhChildCountExpr := "COUNT(`_id`)"
			isDHArray := !isExplodedNested(b, effDHField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield)
			if isDHArray && nctx == nil {
				dhChildCountExpr = "COUNT(DISTINCT `_id`)"
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), compKeyExpr, dhChildCountExpr, subFrom, subWhere,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				nextKeyExpr := compKeyExpr
				nextFrom := subFrom
				nextWhere := subWhere
				if isDHArray && nctx == nil {
					*subIdx++
					dedupIdx := *subIdx
					nextFrom = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, compKeyExpr, dedupIdx, subFrom, subWhere, dedupIdx, dedupIdx, dedupIdx)
					nextKeyExpr = fmt.Sprintf("`_rn_bkey_%d`", dedupIdx)
					nextWhere = "1=1"
				}
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, nextKeyExpr, nextFrom, nextWhere, nctx, nestedSubs)
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
			effHField, b := t.resolveFieldInNestedCtx(effHField, false, nctx)
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
			if subSpec.Histogram.HardBounds != nil {
				if minF, okMin := resolveHistogramMissingFloat(subSpec.Histogram.HardBounds.Min); okMin {
					subWhere = fmt.Sprintf("(%s) AND (%s >= %s)", subWhere, col, strconv.FormatFloat(minF, 'f', -1, 64))
				}
				if maxF, okMax := resolveHistogramMissingFloat(subSpec.Histogram.HardBounds.Max); okMax {
					subWhere = fmt.Sprintf("(%s) AND (%s <= %s)", subWhere, col, strconv.FormatFloat(maxF, 'f', -1, 64))
				}
			}
			hChildCountExpr := "COUNT(`_id`)"
			isHArray := !isExplodedNested(b, effHField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield)
			if isHArray && nctx == nil {
				hChildCountExpr = "COUNT(DISTINCT `_id`)"
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), compKeyExpr, hChildCountExpr, subFrom, subWhere,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				nextKeyExpr := compKeyExpr
				nextFrom := subFrom
				nextWhere := subWhere
				if isHArray && nctx == nil {
					*subIdx++
					dedupIdx := *subIdx
					nextFrom = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, compKeyExpr, dedupIdx, subFrom, subWhere, dedupIdx, dedupIdx, dedupIdx)
					nextKeyExpr = fmt.Sprintf("`_rn_bkey_%d`", dedupIdx)
					nextWhere = "1=1"
				}
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, nextKeyExpr, nextFrom, nextWhere, nctx, nestedSubs)
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
			effRField, b := t.resolveFieldInNestedCtx(effRField, true, nctx)
			arrCol := b.EffectiveArrayColumn(true)
			isArray := !isExplodedNested(b, effRField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield)
			isNestedMultiVal := isExplodedNested(b, effRField) && b.IsMultiValued
			for _, rng := range rngSpec.Ranges {
				var rWhere string
				subFrom := fromClause
				if subSpec.IPRange != nil {
					ipCol := t.sqlColumnRef(effRField, true, nctx)
					if isArray || isNestedMultiVal {
						ipCol = "_x"
					}
					numCol := fmt.Sprintf("IPV4_STRING_TO_NUM_OR_NULL(%s)", ipCol)
					var conds []string
					if !isArray && !isNestedMultiVal {
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
					if isNestedMultiVal {
						rawCol := t.sqlColumnRef(effRField, true, nctx)
						if len(conds) == 0 {
							rWhere = fmt.Sprintf("%s IS NOT NULL", rawCol)
						} else {
							rWhere = fmt.Sprintf("array_exists(_x -> %s, CAST(%s AS ARRAY<STRING>))", strings.Join(conds, " AND "), rawCol)
						}
					} else if isArray {
						if len(conds) == 0 {
							rWhere = fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", arrCol, arrCol)
						} else {
							rWhere = fmt.Sprintf("array_exists(_x -> %s, `%s`)", strings.Join(conds, " AND "), arrCol)
						}
					} else {
						rWhere = strings.Join(conds, " AND ")
					}
				} else if isArray || isNestedMultiVal {
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
					if isNestedMultiVal {
						rawCol := t.sqlColumnRef(effRField, true, nctx)
						arrExpr = fmt.Sprintf("CAST(%s AS ARRAY<STRING>)", rawCol)
						if rngSpec.Missing != nil {
							if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
								arrExpr = fmt.Sprintf("CASE WHEN %s IS NULL OR array_size(CAST(%s AS ARRAY<STRING>)) = 0 THEN [%s] ELSE CAST(%s AS ARRAY<STRING>) END", rawCol, rawCol, strconv.FormatFloat(mf, 'f', -1, 64), rawCol)
							}
						}
					} else if rngSpec.Missing != nil {
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
				if subSpec.Filters.OtherBucket {
					otherKey := subSpec.Filters.EffectiveOtherBucketKey()
					compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(otherKey))
					otherWhere := whereClause
					if len(allSafeConds) > 0 {
						otherWhere = fmt.Sprintf("(%s) AND (NOT COALESCE(%s, FALSE))", whereClause, strings.Join(allSafeConds, " OR "))
					}
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
				if subSpec.Filters.OtherBucket {
					otherKey := subSpec.Filters.EffectiveOtherBucketKey()
					compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(otherKey))
					otherWhere := whereClause
					if len(allSafeConds) > 0 {
						otherWhere = fmt.Sprintf("(%s) AND (NOT COALESCE(%s, FALSE))", whereClause, strings.Join(allSafeConds, " OR "))
					}
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
			if nctx != nil && strings.HasPrefix(subSpec.Nested.Path, nctx.nestedPath+".") {
				subWhere = fmt.Sprintf("(%s) AND json_extract_string(%s, '$._parent_id') = json_extract_string(%s, '$._nested_id')", subWhere, nelAlias, nctx.elemVar)
			}
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
			orderBy := t.compileTopHitsOrderByWithNested(subSpec.TopHits.Sort, nctx)
			idKeyExpr := "`_id`"
			if nctx != nil && nctx.elemVar != "" {
				idKeyExpr = fmt.Sprintf("COALESCE(json_extract_string(%s, '$._nested_id'), CAST(`_id` AS STRING))", nctx.elemVar)
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, CONCAT(%s, '\\x1f', %s) AS `_bucket_key`, "+
					"CAST(ROW_NUMBER() OVER (PARTITION BY %s ORDER BY %s) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s"+
					") `_agg_sub_%d` WHERE `_doc_count` <= %d",
				quoteStr(subFull), parentBucketExpr, idKeyExpr, parentBucketExpr, orderBy, fromClause, whereClause, *subIdx, size,
			))
		case subSpec.TopMetrics != nil:
			size := subSpec.TopMetrics.EffectiveSize()
			if topHitsNeedsRuntimeSort(subSpec.TopMetrics.Sort) && size < 100 {
				size = 100
			}
			orderBy := t.compileTopHitsOrderByWithNested(subSpec.TopMetrics.Sort, nctx)
			idKeyExpr := "`_id`"
			if nctx != nil && nctx.elemVar != "" {
				idKeyExpr = fmt.Sprintf("COALESCE(json_extract_string(%s, '$._nested_id'), CAST(`_id` AS STRING))", nctx.elemVar)
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, CONCAT(%s, '\\x1f', %s) AS `_bucket_key`, "+
					"CAST(ROW_NUMBER() OVER (PARTITION BY %s ORDER BY %s) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s"+
					") `_agg_sub_%d` WHERE `_doc_count` <= %d",
				quoteStr(subFull), parentBucketExpr, idKeyExpr, parentBucketExpr, orderBy, fromClause, whereClause, *subIdx, size,
			))
		case subSpec.Composite != nil && len(subSpec.Composite.Sources) > 0:
			size := t.maxAggBuckets()
			var colExprs []string
			var notNullConds []string
			compFrom := fromClause
			compExplodeIdx := explodeDepth
			resolveSubCompSourceCol := func(field string, isNumeric bool, hasMissing bool) string {
				field, b := t.resolveFieldInNestedCtx(field, true, nctx)
				if !isExplodedNested(b, field) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
					arrCol := b.EffectiveArrayColumn(true)
					compExplodeIdx++
					tblAlias := fmt.Sprintf("`_scomp_t_%d`", compExplodeIdx)
					elemAlias := fmt.Sprintf("`_scomp_el_%d`", compExplodeIdx)
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
					return t.sqlNumericColumnRef(field, nctx)
				}
				return t.sqlColumnRef(field, true, nctx)
			}
			for _, srcMap := range subSpec.Composite.Sources {
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
						_, b := t.resolveFieldInNestedCtx(effField, true, nctx)
						effDT := effectiveDorisScalarType(b)
						hasMiss := srcSpec.Terms.Missing != nil || srcSpec.Terms.MissingBucket
						col := resolveSubCompSourceCol(effField, false, hasMiss)
						if srcSpec.Terms.Script != nil {
							overrideExpr := ""
							if effField != "" {
								overrideExpr = col
							}
							if scriptExpr, ok := t.compilePolymorphicScriptExpr(srcSpec.Terms.Script, effField, overrideExpr, nctx); ok {
								col = scriptExpr
							}
						}
						expr := fmt.Sprintf("CAST(%s AS STRING)", col)
						if effDT == schema.DorisBoolean && srcSpec.Terms.Script == nil {
							expr = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN LOWER(CAST(%s AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END", col, col)
						} else if b.EffectiveLowercase(!strings.HasSuffix(effField, ".keyword")) && srcSpec.Terms.Script == nil && !strings.HasPrefix(expr, "LOWER(") {
							expr = fmt.Sprintf("LOWER(%s)", expr)
						}
						if srcSpec.Terms.Missing != nil {
							expr = fmt.Sprintf("COALESCE(%s, %s)", expr, quoteStr(formatMissingScalar(srcSpec.Terms.Missing)))
						} else if srcSpec.Terms.MissingBucket {
							expr = fmt.Sprintf("COALESCE(%s, '__ES_MISSING_BUCKET__')", expr)
						} else {
							notNullConds = append(notNullConds, fmt.Sprintf("%s IS NOT NULL", col))
						}
						colExprs = append(colExprs, expr)
					case srcSpec.DateHistogram != nil:
						intervalMs := srcSpec.DateHistogram.EffectiveIntervalMs()
						tzShiftMs := srcSpec.DateHistogram.EffectiveTimeZoneOffsetMs() - srcSpec.DateHistogram.EffectiveOffsetMs()
						hasMiss := srcSpec.DateHistogram.Missing != nil || srcSpec.DateHistogram.MissingBucket
						effDHField := srcSpec.DateHistogram.Field
						if effDHField == "" && srcSpec.DateHistogram.Script != nil {
							if docF, ok := extractSimpleDocFieldFromScript(srcSpec.DateHistogram.Script); ok {
								effDHField = docF
							}
						}
						_, dhB := t.resolveFieldInNestedCtx(effDHField, true, nctx)
						col := resolveSubCompSourceCol(effDHField, true, hasMiss)
						if srcSpec.DateHistogram.Script != nil {
							overrideExpr := ""
							if effDHField != "" {
								overrideExpr = col
							}
							if scriptExpr, ok := t.compileMetricScriptExprWithOverride(srcSpec.DateHistogram.Script, effDHField, overrideExpr, nctx); ok {
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
					case srcSpec.Histogram != nil:
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
						col := resolveSubCompSourceCol(effHField, true, hasMiss)
						if srcSpec.Histogram.Script != nil {
							overrideExpr := ""
							if effHField != "" {
								overrideExpr = col
							}
							if scriptExpr, ok := t.compileMetricScriptExprWithOverride(srcSpec.Histogram.Script, effHField, overrideExpr, nctx); ok {
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
					}
				}
			}
			if len(colExprs) > 0 {
				bucketKeyExpr := colExprs[0]
				if len(colExprs) > 1 {
					bucketKeyExpr = fmt.Sprintf("CONCAT_WS('\\x1f', %s)", strings.Join(colExprs, ", "))
				}
				compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, bucketKeyExpr)
				subWhere := whereClause
				if len(notNullConds) > 0 {
					subWhere = fmt.Sprintf("(%s) AND (%s)", whereClause, strings.Join(notNullConds, " AND "))
				}
				compCountExpr := "COUNT(*)"
				if compExplodeIdx > explodeDepth && nctx == nil {
					compCountExpr = "COUNT(DISTINCT `_id`)"
				}
				*subIdx++
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s "+
						"GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(subFull), compKeyExpr, compCountExpr, compFrom, subWhere, size, *subIdx,
				))
				if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
					nextKeyExpr := compKeyExpr
					nextFrom := compFrom
					nextWhere := subWhere
					if compExplodeIdx > explodeDepth && nctx == nil {
						dedupIdx := *subIdx
						nextFrom = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, compKeyExpr, dedupIdx, compFrom, subWhere, dedupIdx, dedupIdx, dedupIdx)
						nextKeyExpr = fmt.Sprintf("`_rn_bkey_%d`", dedupIdx)
						nextWhere = "1=1"
					}
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, nextKeyExpr, nextFrom, nextWhere, nctx, nestedSubs)
				}
			}

		case subSpec.WeightedAvg != nil:
			vField, _ := t.resolveFieldInNestedCtx(subSpec.WeightedAvg.Value.Field, false, nctx)
			vCol := t.sqlNumericColumnRef(vField, nctx)
			if subSpec.WeightedAvg.Value.Missing != nil && vField != "" {
				if mf, ok := resolveHistogramMissingFloat(subSpec.WeightedAvg.Value.Missing); ok {
					vCol = fmt.Sprintf("COALESCE(%s, %s)", vCol, strconv.FormatFloat(mf, 'f', -1, 64))
				}
			}
			if subSpec.WeightedAvg.Value.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(subSpec.WeightedAvg.Value.Script, vField, vCol, nctx); ok {
					vCol = se
				}
			}
			wField, _ := t.resolveFieldInNestedCtx(subSpec.WeightedAvg.Weight.Field, false, nctx)
			wCol := t.sqlNumericColumnRef(wField, nctx)
			if subSpec.WeightedAvg.Weight.Missing != nil && wField != "" {
				if mf, ok := resolveHistogramMissingFloat(subSpec.WeightedAvg.Weight.Missing); ok {
					wCol = fmt.Sprintf("COALESCE(%s, %s)", wCol, strconv.FormatFloat(mf, 'f', -1, 64))
				}
			}
			if subSpec.WeightedAvg.Weight.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(subSpec.WeightedAvg.Weight.Script, wField, wCol, nctx); ok {
					wCol = se
				}
			}
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL AND %s IS NOT NULL", whereClause, vCol, wCol)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(SUM((%s) * (%s)) / NULLIF(SUM(%s), 0), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key` HAVING COUNT(%s) > 0",
				quoteStr(subFull), parentBucketExpr, vCol, wCol, wCol, fromClause, subWhere, vCol,
			))

		case subSpec.MedianAbsoluteDeviation != nil:
			effField := subSpec.MedianAbsoluteDeviation.Field
			if effField == "" && subSpec.MedianAbsoluteDeviation.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.MedianAbsoluteDeviation.Script); ok {
					effField = docF
				}
			}
			effField, _ = t.resolveFieldInNestedCtx(effField, false, nctx)
			col := t.sqlNumericColumnRef(effField, nctx)
			if subSpec.MedianAbsoluteDeviation.Missing != nil && effField != "" {
				if mf, ok := resolveHistogramMissingFloat(subSpec.MedianAbsoluteDeviation.Missing); ok {
					col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
				}
			}
			if subSpec.MedianAbsoluteDeviation.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(subSpec.MedianAbsoluteDeviation.Script, effField, col, nctx); ok {
					col = se
				}
			}
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, 0.5000), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key` HAVING COUNT(%s) > 0",
				quoteStr(subFull), parentBucketExpr, col, fromClause, subWhere, col,
			))

		case subSpec.RareTerms != nil:
			maxDocCount := 1
			if subSpec.RareTerms.MaxDocCount != nil && *subSpec.RareTerms.MaxDocCount >= 1 {
				maxDocCount = *subSpec.RareTerms.MaxDocCount
			}
			rtField, _ := t.resolveFieldInNestedCtx(subSpec.RareTerms.Field, true, nctx)
			col := t.sqlColumnRef(rtField, true, nctx)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
			if subSpec.RareTerms.Missing != nil {
				col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(subSpec.RareTerms.Missing)))
				subWhere = whereClause
			}
			childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', CAST(%s AS STRING))", parentBucketExpr, col)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s "+
					"GROUP BY `_bucket_key` HAVING COUNT(*) <= %d ORDER BY `_doc_count` ASC, `_bucket_key` ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(subFull), childKeyExpr, fromClause, subWhere, maxDocCount, t.maxAggBuckets(), *subIdx,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, fromClause, subWhere, nctx, nestedSubs)
			}

		case subSpec.MultiTerms != nil && len(subSpec.MultiTerms.Terms) > 0:
			size := t.capBucketSize(subSpec.MultiTerms.Size)
			var termExprs, notNulls []string
			for _, mt := range subSpec.MultiTerms.Terms {
				mtField, _ := t.resolveFieldInNestedCtx(mt.Field, true, nctx)
				col := t.sqlColumnRef(mtField, true, nctx)
				if mt.Script != nil {
					if se, ok := t.compilePolymorphicScriptExpr(mt.Script, mtField, col, nctx); ok {
						col = se
					}
				}
				if mt.Missing != nil {
					col = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(mt.Missing)))
				} else {
					notNulls = append(notNulls, fmt.Sprintf("%s IS NOT NULL", col))
				}
				termExprs = append(termExprs, fmt.Sprintf("CAST(%s AS STRING)", col))
			}
			keyExpr := termExprs[0]
			if len(termExprs) > 1 {
				keyExpr = fmt.Sprintf("CONCAT_WS('|', %s)", strings.Join(termExprs, ", "))
			}
			childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, keyExpr)
			subWhere := whereClause
			if len(notNulls) > 0 {
				subWhere = fmt.Sprintf("(%s) AND (%s)", whereClause, strings.Join(notNulls, " AND "))
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(subFull), childKeyExpr, fromClause, subWhere, size, *subIdx,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, fromClause, subWhere, nctx, nestedSubs)
			}

		case subSpec.AutoDateHistogram != nil:
			effField := subSpec.AutoDateHistogram.Field
			if effField == "" && subSpec.AutoDateHistogram.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.AutoDateHistogram.Script); ok {
					effField = docF
				}
			}
			effField, _ = t.resolveFieldInNestedCtx(effField, false, nctx)
			col := t.sqlNumericColumnRef(effField, nctx)
			if subSpec.AutoDateHistogram.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(subSpec.AutoDateHistogram.Script, effField, col, nctx); ok {
					col = se
				}
			}
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
			childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', CAST(CAST(FLOOR(%s / 3600000) * 3600000 AS BIGINT) AS STRING))", parentBucketExpr, col)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(subFull), childKeyExpr, fromClause, subWhere, t.maxAggBuckets(), *subIdx,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, fromClause, subWhere, nctx, nestedSubs)
			}

		case subSpec.VariableWidthHistogram != nil:
			effField := subSpec.VariableWidthHistogram.Field
			if effField == "" && subSpec.VariableWidthHistogram.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.VariableWidthHistogram.Script); ok {
					effField = docF
				}
			}
			effField, _ = t.resolveFieldInNestedCtx(effField, false, nctx)
			col := t.sqlNumericColumnRef(effField, nctx)
			if subSpec.VariableWidthHistogram.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(subSpec.VariableWidthHistogram.Script, effField, col, nctx); ok {
					col = se
				}
			}
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
			childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', CAST(FLOOR(%s) AS STRING))", parentBucketExpr, col)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY `_bucket_key` ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(subFull), childKeyExpr, fromClause, subWhere, t.maxAggBuckets(), *subIdx,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, fromClause, subWhere, nctx, nestedSubs)
			}

		case subSpec.AdjacencyMatrix != nil && len(subSpec.AdjacencyMatrix.Filters) > 0:
			sep := subSpec.AdjacencyMatrix.Separator
			if sep == "" {
				sep = "&"
			}
			fKeys := sortedMapKeys(subSpec.AdjacencyMatrix.Filters)
			condMap := make(map[string]string, len(fKeys))
			for _, fk := range fKeys {
				fq := subSpec.AdjacencyMatrix.Filters[fk]
				c := t.CompileQuery(&fq, false, nctx)
				subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, c.WhereSQL)
				condMap[fk] = subWhere
				childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(fk))
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), childKeyExpr, fromClause, subWhere,
				))
				if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, fromClause, subWhere, nctx, nestedSubs)
				}
			}
			for i := 0; i < len(fKeys); i++ {
				for j := i + 1; j < len(fKeys); j++ {
					pairKey := fKeys[i] + sep + fKeys[j]
					pairCond := fmt.Sprintf("(%s) AND (%s)", condMap[fKeys[i]], condMap[fKeys[j]])
					childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(pairKey))
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull), childKeyExpr, fromClause, pairCond,
					))
					if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
						t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, fromClause, pairCond, nctx, nestedSubs)
					}
				}
			}

		case subSpec.GeoBounds != nil:
			gbField, b := t.resolveFieldInNestedCtx(subSpec.GeoBounds.Field, false, nctx)
			latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(gbField, b)
			subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, notNullCond)
			for _, op := range []struct{ key, expr string }{
				{"_gb_top", fmt.Sprintf("MAX(%s)", latExpr)},
				{"_gb_bottom", fmt.Sprintf("MIN(%s)", latExpr)},
				{"_gb_left", fmt.Sprintf("MIN(%s)", lonExpr)},
				{"_gb_right", fmt.Sprintf("MAX(%s)", lonExpr)},
			} {
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s, 0) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key` HAVING COUNT(%s) > 0",
					quoteStr(subFull+"."+op.key), parentBucketExpr, op.expr, fromClause, subWhere, latExpr,
				))
			}

		case subSpec.GeoCentroid != nil:
			gcField, b := t.resolveFieldInNestedCtx(subSpec.GeoCentroid.Field, false, nctx)
			latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(gcField, b)
			subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, notNullCond)
			for _, op := range []struct{ key, expr string }{
				{"_gc_count", fmt.Sprintf("COUNT(%s)", latExpr)},
				{"_gc_lat", fmt.Sprintf("AVG(%s)", latExpr)},
				{"_gc_lon", fmt.Sprintf("AVG(%s)", lonExpr)},
			} {
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(%s, 0) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull+"."+op.key), parentBucketExpr, op.expr, fromClause, subWhere,
				))
			}

		case subSpec.GeoDistance != nil && len(subSpec.GeoDistance.Ranges) > 0:
			gdField, b := t.resolveFieldInNestedCtx(subSpec.GeoDistance.Field, false, nctx)
			origLat, origLon, _ := esast.ParseGeoPoint(subSpec.GeoDistance.Origin)
			latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(gdField, b)
			distExpr := fmt.Sprintf("ST_Distance_Sphere(%s, %s, %s, %s)",
				lonExpr, latExpr, strconv.FormatFloat(origLon, 'f', -1, 64), strconv.FormatFloat(origLat, 'f', -1, 64))
			unitMult := 1.0
			if mult, ok := esast.GeoDistanceUnitMultiplier(strings.TrimSpace(subSpec.GeoDistance.Unit)); ok && mult > 0 {
				unitMult = mult
			}
			for _, rng := range subSpec.GeoDistance.Ranges {
				conds := []string{whereClause, notNullCond}
				if rng.From != nil {
					if fv, ok := parseFiniteFloatValue(rng.From); ok {
						conds = append(conds, fmt.Sprintf("%s >= %s", distExpr, strconv.FormatFloat(fv*unitMult, 'f', -1, 64)))
					}
				}
				if rng.To != nil {
					if fv, ok := parseFiniteFloatValue(rng.To); ok {
						conds = append(conds, fmt.Sprintf("%s < %s", distExpr, strconv.FormatFloat(fv*unitMult, 'f', -1, 64)))
					}
				}
				subWhere := "(" + strings.Join(conds, ") AND (") + ")"
				bKey := rng.EffectiveKey()
				childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(bKey))
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), childKeyExpr, fromClause, subWhere,
				))
				if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, fromClause, subWhere, nctx, nestedSubs)
				}
			}

		case subSpec.GeohashGrid != nil || subSpec.GeotileGrid != nil:
			ggSpec := subSpec.GeohashGrid
			if ggSpec == nil {
				ggSpec = subSpec.GeotileGrid
			}
			ggField, b := t.resolveFieldInNestedCtx(ggSpec.Field, false, nctx)
			latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(ggField, b)
			subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, notNullCond)
			childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', CAST(FLOOR(%s) AS STRING), '/', CAST(FLOOR(%s) AS STRING))", parentBucketExpr, latExpr, lonExpr)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(subFull), childKeyExpr, fromClause, subWhere, t.maxAggBuckets(), *subIdx,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, fromClause, subWhere, nctx, nestedSubs)
			}
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
	case uint64:
		return strconv.FormatUint(val, 10)
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
		if ms, ok := schema.ParseESDateBoundToEpochMillis(v, time.Now().UTC(), false); ok {
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
		if ms, ok := schema.ParseESDateBoundToEpochMillis(v, time.Now().UTC(), false); ok {
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
	return t.compileTopHitsOrderByWithNested(sorts, nil)
}

func (t *Transpiler) compileTopHitsOrderByWithNested(sorts []esast.SortSpec, nctx *nestedCtx) string {
	var filtered []esast.SortSpec
	for _, s := range sorts {
		if s.Entry.Field == "" || s.Entry.Field == "_score" {
			continue
		}
		if s.Entry.Field == "_geo_distance" {
			if _, ok := t.compileGeoDistanceSortExpr(s); !ok {
				continue
			}
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
	if nctx == nil || nctx.elemVar == "" {
		return t.compileOrderBy(filtered)
	}
	var parts []string
	for _, s := range filtered {
		dir := "ASC"
		if strings.EqualFold(s.Entry.Order, "desc") {
			dir = "DESC"
		}
		if s.Entry.Field == "_id" || s.Entry.Field == "_doc" {
			parts = append(parts, "`_id` "+dir)
			continue
		}
		resolvedField, b := t.resolveFieldInNestedCtx(s.Entry.Field, true, nctx)
		if (b.Kind == schema.StorageNestedSubfield && b.NestedPath == nctx.nestedPath) || strings.HasPrefix(resolvedField, nctx.nestedPath+".") {
			t.checkFieldDocValues(resolvedField, b)
			relPath := t.nestedRelativeJSONPath(resolvedField, true, nctx.nestedPath)
			rawExtract := fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath))
			effDT := effectiveDorisScalarType(b)
			col := rawExtract
			switch effDT {
			case schema.DorisBigInt, schema.DorisInt:
				col = fmt.Sprintf("CAST(%s AS BIGINT)", rawExtract)
			case schema.DorisDouble:
				col = fmt.Sprintf("CAST(%s AS DOUBLE)", rawExtract)
			case schema.DorisBoolean:
				col = fmt.Sprintf("CAST(%s AS BOOLEAN)", rawExtract)
			default:
				if strings.EqualFold(s.Entry.Type, "number") || strings.EqualFold(s.Entry.Type, "double") || strings.EqualFold(s.Entry.Type, "float") {
					col = fmt.Sprintf("CAST(%s AS DOUBLE)", rawExtract)
				} else if strings.EqualFold(s.Entry.Type, "long") || strings.EqualFold(s.Entry.Type, "integer") {
					col = fmt.Sprintf("CAST(%s AS BIGINT)", rawExtract)
				} else if b.EffectiveLowercase(true) {
					col = fmt.Sprintf("lower(%s)", rawExtract)
				}
			}
			_, missingSQL := t.resolveSortMissing(s, b)
			if missingSQL != "" {
				col = fmt.Sprintf("COALESCE(%s, %s)", col, missingSQL)
			}
			orderPart := col + " " + dir
			if strings.EqualFold(s.Entry.Missing, "_first") {
				orderPart += " NULLS FIRST"
			} else if missingSQL == "" {
				orderPart += " NULLS LAST"
			}
			parts = append(parts, orderPart)
			continue
		}
		parts = append(parts, t.compileOrderBy([]esast.SortSpec{s}))
	}
	if len(parts) == 0 {
		return "`_id` ASC"
	}
	return strings.Join(parts, ", ")
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
	var fmtSpec string
	if rngSpec != nil {
		fmtSpec = rngSpec.Format
	}
	if fmtSpec == "" {
		fmtSpec = b.Format
	}
	isEpochSecond := strings.EqualFold(fmtSpec, "epoch_second")
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
		if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, fmtSpec, now); ok {
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
	if field, tail, ok := parseDocFieldAccess(s); ok && (tail == "" || tail == ".value") {
		return field, true
	}
	if strings.Contains(s, ".size()") || strings.Contains(s, ".length") {
		return "", false
	}
	var uniqueField string
	for i := 0; i < len(s); i++ {
		if strings.HasPrefix(s[i:], "doc[") {
			rest := s[i:]
			for _, quote := range []string{"'", `"`} {
				prefix := "doc[" + quote
				suffix := quote + "]"
				if strings.HasPrefix(rest, prefix) {
					afterPrefix := rest[len(prefix):]
					if end := strings.Index(afterPrefix, suffix); end > 0 {
						f := afterPrefix[:end]
						if uniqueField == "" {
							uniqueField = f
						} else if uniqueField != f {
							return "", false
						}
						i += len(prefix) + end + len(suffix) - 1
						break
					}
				}
			}
		}
	}
	if uniqueField != "" {
		return uniqueField, true
	}
	return "", false
}

func (t *Transpiler) sqlStringScalarColumnRef(field string, preferKeyword bool, nctx *nestedCtx) string {
	field, b := t.resolveFieldInNestedCtx(field, preferKeyword, nctx)
	effField := field
	if b.AliasTarget != "" {
		effField = b.AliasTarget
	}
	if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(effField, nctx.nestedPath+".")) {
		return t.sqlColumnRef(field, preferKeyword, nctx)
	}
	if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := b.EffectiveArrayColumn(preferKeyword)
		if arrCol != "" {
			return fmt.Sprintf("element_at(`%s`, 1)", arrCol)
		}
	}
	return t.sqlColumnRef(field, preferKeyword, nctx)
}

func (t *Transpiler) sameScriptFieldInCtx(field, defaultField string, nctx *nestedCtx) bool {
	if field == "" || defaultField == "" {
		return false
	}
	if field == defaultField {
		return true
	}
	if nctx != nil {
		f1, _ := t.resolveFieldInNestedCtx(field, true, nctx)
		f2, _ := t.resolveFieldInNestedCtx(defaultField, true, nctx)
		return f1 != "" && f1 == f2
	}
	return false
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
		return t.sqlStringScalarColumnRef(defaultField, true, nctx), true
	}
	if field, tail, ok := parseDocFieldAccess(sClean); ok && (tail == "" || tail == ".value") {
		resolved, b := t.resolveFieldInNestedCtx(field, true, nctx)
		t.checkFieldDocValues(resolved, b)
		if fieldOverrideExpr != "" && t.sameScriptFieldInCtx(field, defaultField, nctx) {
			return fieldOverrideExpr, true
		}
		return t.sqlStringScalarColumnRef(field, true, nctx), true
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
		innerRaw := s[1 : len(s)-1]
		var unescaped strings.Builder
		valid := true
		for i := 0; i < len(innerRaw); i++ {
			if innerRaw[i] == '\\' {
				if i+1 >= len(innerRaw) {
					valid = false
					break
				}
				i++
				switch innerRaw[i] {
				case '\\', '\'', '"':
					unescaped.WriteByte(innerRaw[i])
				case 'n':
					unescaped.WriteByte('\n')
				case 'r':
					unescaped.WriteByte('\r')
				case 't':
					unescaped.WriteByte('\t')
				default:
					unescaped.WriteByte(innerRaw[i])
				}
				continue
			}
			if innerRaw[i] == qChar {
				valid = false
				break
			}
			unescaped.WriteByte(innerRaw[i])
		}
		if valid {
			return quoteStr(unescaped.String()), true, true
		}
	}
	if (s == "_value" || s == "params._value") && defaultField != "" {
		_, b := t.resolveFieldInNestedCtx(defaultField, true, nctx)
		effDT := effectiveDorisScalarType(b)
		isStr := effDT == schema.DorisString || effDT == schema.DorisVarchar || b.Kind == schema.StorageDynamicVariant
		if fieldOverrideExpr != "" {
			return fieldOverrideExpr, isStr, true
		}
		return t.sqlStringScalarColumnRef(defaultField, true, nctx), isStr, true
	}
	if field, tail, ok := parseDocFieldAccess(s); ok && (tail == "" || tail == ".value") {
		resolved, b := t.resolveFieldInNestedCtx(field, true, nctx)
		t.checkFieldDocValues(resolved, b)
		effDT := effectiveDorisScalarType(b)
		isStr := effDT == schema.DorisString || effDT == schema.DorisVarchar || b.Kind == schema.StorageDynamicVariant
		if fieldOverrideExpr != "" && t.sameScriptFieldInCtx(field, defaultField, nctx) {
			return fieldOverrideExpr, isStr, true
		}
		return t.sqlStringScalarColumnRef(field, true, nctx), isStr, true
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
			key = strings.ReplaceAll(key, `\`+quote, quote)
			key = strings.ReplaceAll(key, `\\`, `\`)
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
		var opIndices []int
		for i := 0; i < len(s); i++ {
			ch := s[i]
			if inQuote != 0 {
				if ch == '\\' {
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
			default:
				if i > 0 && parenDepth == 0 && strings.IndexByte(ops, ch) >= 0 {
					opIndices = append(opIndices, i)
				}
			}
		}
		for k := len(opIndices) - 1; k >= 0; k-- {
			i := opIndices[k]
			ch := s[i]
			lhs, ok1 := t.parseMetricScriptExpr(s[:i], params, defaultField, fieldOverrideExpr, nctx, depth+1)
			rhs, ok2 := t.parseMetricScriptExpr(s[i+1:], params, defaultField, fieldOverrideExpr, nctx, depth+1)
			if ok1 && ok2 {
				return fmt.Sprintf("(%s %c %s)", lhs, ch, rhs), true
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
		effField, b := t.resolveFieldInNestedCtx(field, true, nctx)
		t.checkFieldDocValues(effField, b)
		if tail == ".size()" || tail == ".length" {
			if nctx != nil && nctx.elemVar != "" && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
				relPath := t.nestedRelativeJSONPath(effField, true, b.NestedPath)
				return fmt.Sprintf("COALESCE(array_size(CAST(json_extract_string(%s, %s) AS ARRAY<STRING>)), 0)", nctx.elemVar, quoteStr(relPath)), true
			}
			if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.elemVar == "" || nctx.nestedPath != b.NestedPath)) {
				colName := b.EffectiveArrayColumn(true)
				if colName != "" {
					return fmt.Sprintf("COALESCE(array_size(`%s`), 0)", colName), true
				}
			}
			colRef := t.sqlColumnRef(field, true, nctx)
			return fmt.Sprintf("(CASE WHEN %s IS NOT NULL THEN 1 ELSE 0 END)", colRef), true
		}
		if fieldOverrideExpr != "" && t.sameScriptFieldInCtx(field, defaultField, nctx) {
			return fieldOverrideExpr, true
		}
		return t.sqlNumericColumnRef(field, nctx), true
	}
	if s == "_score" {
		if defaultField == "_score" && fieldOverrideExpr != "" {
			return "(" + fieldOverrideExpr + ")", true
		}
		return "1.0", true
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
		havingClause := ""
		if sqlFunc == "AVG" || sqlFunc == "MIN" || sqlFunc == "MAX" {
			havingClause = fmt.Sprintf(" HAVING COUNT(%s) > 0", valExpr)
		}
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
				"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_nt` AS `_nel`%s%s",
			quoteStr(fullAggName), sqlFunc, valExpr, explodeExpr, wClause, havingClause,
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
	havingClause := ""
	if sqlFunc == "AVG" || sqlFunc == "MIN" || sqlFunc == "MAX" {
		havingClause = fmt.Sprintf(" HAVING COUNT(%s) > 0", col)
	}
	*branches = append(*branches, fmt.Sprintf(
		"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(%s(%s), 0) AS DOUBLE) AS `_doc_count` "+
			"FROM `base_matched`%s%s",
		quoteStr(fullAggName), sqlFunc, col, wClause, havingClause,
	))
}

func (t *Transpiler) compileTermsSetScriptThreshold(script any, numTerms int, nctx *nestedCtx) string {
	s, params, ok := normalizeScriptSourceAndParams(script)
	if !ok || s == "" {
		return "1"
	}
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
			if ch == '\\' {
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
		var opIndices []int
		for i := 0; i < len(s); i++ {
			ch := s[i]
			if inQuote != 0 {
				if ch == '\\' {
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
			default:
				if i > 0 && parenDepth == 0 && strings.IndexByte(ops, ch) >= 0 {
					opIndices = append(opIndices, i)
				}
			}
		}
		for k := len(opIndices) - 1; k >= 0; k-- {
			i := opIndices[k]
			ch := s[i]
			lhs, ok1 := t.parseSafeThresholdExpr(s[:i], params, numTerms, nctx, depth+1)
			rhs, ok2 := t.parseSafeThresholdExpr(s[i+1:], params, numTerms, nctx, depth+1)
			if ok1 && ok2 {
				return fmt.Sprintf("(%s %c %s)", lhs, ch, rhs), true
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
		field, b := t.resolveFieldInNestedCtx(field, true, nctx)
		t.checkFieldDocValues(field, b)
		if tail == ".size()" || tail == ".length" {
			if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath || b.IsMultiValued)) {
				if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
					col := t.sqlColumnRef(field, true, nctx)
					return fmt.Sprintf("COALESCE(array_size(CAST(%s AS ARRAY<STRING>)), 0)", col), true
				}
				colName := b.EffectiveArrayColumn(true)
				if colName != "" {
					return fmt.Sprintf("COALESCE(array_size(`%s`), 0)", colName), true
				}
			}
			col := t.sqlColumnRef(field, true, nctx)
			return fmt.Sprintf("(CASE WHEN %s IS NOT NULL THEN 1 ELSE 0 END)", col), true
		}
		return fmt.Sprintf("COALESCE(%s, 1)", t.sqlNumericColumnRef(field, nctx)), true
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
			if ch == '\\' {
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

func effectiveSortESType(b schema.FieldBinding, sortType string, numericType ...string) string {
	st := strings.ToLower(strings.TrimSpace(sortType))
	nt := ""
	if len(numericType) > 0 {
		nt = strings.ToLower(strings.TrimSpace(numericType[0]))
	}
	if nt != "" && (b.ESType != "" || st != "") {
		return nt
	}
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

func parseGeoSortMissingMeters(missing, unit string) (float64, bool) {
	m := strings.TrimSpace(missing)
	if m == "" || strings.EqualFold(m, "_first") || strings.EqualFold(m, "_last") {
		return 0, false
	}
	if fv, err := strconv.ParseFloat(m, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
		if mult, ok := esast.GeoDistanceUnitMultiplier(strings.TrimSpace(unit)); ok && mult > 0 {
			return fv * mult, true
		}
		return fv, true
	}
	if _, distM, err := esast.ParseGeoDistanceMeters(m); err == nil && !math.IsNaN(distM) && !math.IsInf(distM, 0) {
		return distM, true
	}
	return 0, false
}

func extractGeoSortUnit(s esast.SortSpec) string {
	if geoMap, ok := s.Entry.Script.(map[string]any); ok {
		if uStr, okU := geoMap["unit"].(string); okU {
			return strings.TrimSpace(uStr)
		}
	}
	return ""
}

func normalizeEpochSecondSortValue(effType, effFormat string, b schema.FieldBinding, val any) any {
	if val == nil {
		return nil
	}
	if _, isStr := val.(string); isStr {
		return val
	}
	if effType != "date" && effType != "date_nanos" && (effType != "" || b.DorisType != schema.DorisBigInt) {
		return val
	}
	if effFormat == "" {
		effFormat = b.Format
	}
	lowerFmt := strings.ToLower(effFormat)
	if !strings.Contains(lowerFmt, "epoch_second") || strings.Contains(lowerFmt, "epoch_millis") {
		return val
	}
	switch v := val.(type) {
	case int:
		return int64(v) * 1000
	case int64:
		return v * 1000
	case float64:
		return int64(math.Round(v * 1000.0))
	case json.Number:
		if iv, err := v.Int64(); err == nil {
			return iv * 1000
		}
		if fv, err := v.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			return int64(math.Round(fv * 1000.0))
		}
	}
	return val
}

func (t *Transpiler) compileOrderBy(sorts []esast.SortSpec) string {
	return t.compileOrderByWithAfter(sorts, nil)
}

func (t *Transpiler) resolveSortMissing(s esast.SortSpec, b schema.FieldBinding) (any, string) {
	if s.Entry.Missing == "" || strings.EqualFold(s.Entry.Missing, "_last") || strings.EqualFold(s.Entry.Missing, "_first") {
		return nil, ""
	}
	mStr := strings.TrimSpace(s.Entry.Missing)
	effType := effectiveSortESType(b, s.Entry.Type, s.Entry.NumericType)
	if effType == "boolean" || b.DorisType == schema.DorisBoolean {
		if bv, ok := normalizeBooleanQueryValue(mStr); ok {
			if bv {
				return true, "TRUE"
			}
			return false, "FALSE"
		}
	}
	if effType == "ip" {
		if n, ok := parseIPv4ToUint32(mStr); ok {
			return n, strconv.FormatInt(n, 10)
		}
	}
	if effType == "date" || effType == "date_nanos" || (effType == "" && b.DorisType == schema.DorisBigInt) {
		effFormat := s.Entry.Format
		if effFormat == "" {
			effFormat = b.Format
		}
		if ms, ok := schema.ParseESDateWithFormatToEpochMillis(mStr, effFormat, time.Now().UTC()); ok {
			if niv, ok := normalizeDateNanosValue(effType, ms).(int64); ok {
				ms = niv
			}
			return ms, strconv.FormatInt(ms, 10)
		}
	}
	if effType != "scaled_float" {
		if iv, err := strconv.ParseInt(mStr, 10, 64); err == nil {
			norm := normalizeDateNanosValue(effType, iv)
			if niv, ok := norm.(int64); ok {
				return niv, strconv.FormatInt(niv, 10)
			}
			return iv, strconv.FormatInt(iv, 10)
		}
	}
	if fv, err := strconv.ParseFloat(mStr, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
		if nfv, ok := normalizeScaledFloatValue(b, fv).(float64); ok {
			fv = nfv
		}
		return fv, strconv.FormatFloat(fv, 'f', -1, 64)
	}
	if b.EffectiveLowercase(true) {
		mStr = strings.ToLower(mStr)
	}
	return mStr, quoteStr(mStr)
}

func (t *Transpiler) compileScriptSortExpr(s esast.SortSpec) (string, schema.FieldBinding, bool) {
	var sortNCtx *nestedCtx
	if deepest := deepestNestedSortPath(s.Entry.Nested); deepest != "" {
		sortNCtx = &nestedCtx{nestedPath: deepest}
	}
	if strings.EqualFold(s.Entry.Type, "string") {
		if scriptExpr, ok := t.compilePolymorphicScriptExpr(s.Entry.Script, "", "", sortNCtx); ok {
			return fmt.Sprintf("CAST(%s AS STRING)", scriptExpr), schema.FieldBinding{DorisType: schema.DorisString, ESType: "keyword"}, true
		}
		return "", schema.FieldBinding{}, false
	}
	if scriptExpr, ok := t.compileMetricScriptExpr(s.Entry.Script, "", sortNCtx); ok {
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

func (t *Transpiler) compileGeoDistanceSortExpr(s esast.SortSpec) (string, bool) {
	geoMap, ok := s.Entry.Script.(map[string]any)
	if !ok || len(geoMap) == 0 {
		return "", false
	}
	reserved := map[string]bool{
		"order": true, "mode": true, "missing": true, "unit": true,
		"distance_type": true, "validation_method": true, "ignore_unmapped": true, "nested": true,
	}
	var geoField string
	var originRaw any
	for k, v := range geoMap {
		if !reserved[k] {
			geoField = k
			originRaw = v
			break
		}
	}
	if geoField == "" {
		return "", false
	}
	tLat, tLon, ok := parseSortGeoPointLatLon(originRaw)
	if !ok {
		return "", false
	}
	resolvedField, b := t.resolveSortFieldAndBinding(geoField, s.Entry.Nested)
	tLonStr := strconv.FormatFloat(tLon, 'f', -1, 64)
	tLatStr := strconv.FormatFloat(tLat, 'f', -1, 64)

	if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrExpr := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
		if b.Kind == schema.StorageNestedSubfield && s.Entry.Nested != nil && s.Entry.Nested.Filter != nil {
			nestedPath := deepestNestedSortPath(s.Entry.Nested)
			if nestedPath == "" {
				nestedPath = b.NestedPath
			}
			fCompiled := t.CompileQuery(s.Entry.Nested.Filter, false, &nestedCtx{nestedPath: nestedPath, elemVar: "_el"})
			if fCompiled.WhereSQL != "" && fCompiled.WhereSQL != "TRUE" && t.Schema != nil {
				corrCol, ok := t.Schema.NestedRoots[nestedPath]
				if !ok {
					corrCol = "n__" + schema.SanitizeDorisIdentifier(nestedPath)
				}
				relPath := t.nestedRelativeJSONPath(resolvedField, true, nestedPath)
				arrExpr = fmt.Sprintf("array_map(_el -> json_extract_string(_el, %s), array_filter(_el -> %s, `%s`))", quoteStr(relPath), fCompiled.WhereSQL, corrCol)
			}
		}
		distMapExpr := fmt.Sprintf("array_map(_x -> ST_Distance_Sphere(CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE), CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE), %s, %s), %s)",
			tLonStr, tLatStr, arrExpr)
		mode := strings.ToLower(strings.TrimSpace(s.Entry.Mode))
		if mode == "" {
			if strings.EqualFold(s.Entry.Order, "desc") {
				mode = "max"
			} else {
				mode = "min"
			}
		}
		switch mode {
		case "max":
			return fmt.Sprintf("array_max(%s)", distMapExpr), true
		case "avg":
			return fmt.Sprintf("array_avg(%s)", distMapExpr), true
		case "median":
			return fmt.Sprintf("array_median(%s)", distMapExpr), true
		default:
			return fmt.Sprintf("array_min(%s)", distMapExpr), true
		}
	}

	segs := strings.Split(resolvedField, ".")
	if len(b.SourceJSONPath) > 0 {
		segs = b.SourceJSONPath
	}
	var pathBuilder strings.Builder
	for _, seg := range segs {
		_, _ = fmt.Fprintf(&pathBuilder, "[%s]", quoteStr(seg))
	}
	docRef := fmt.Sprintf("`_doc`%s", pathBuilder.String())
	lonExpr := fmt.Sprintf("COALESCE(CAST(%s['lon'] AS DOUBLE), CAST(SPLIT_PART(CAST(%s AS STRING), ',', 2) AS DOUBLE), CAST(element_at(CAST(%s AS ARRAY<DOUBLE>), 1) AS DOUBLE))", docRef, docRef, docRef)
	latExpr := fmt.Sprintf("COALESCE(CAST(%s['lat'] AS DOUBLE), CAST(SPLIT_PART(CAST(%s AS STRING), ',', 1) AS DOUBLE), CAST(element_at(CAST(%s AS ARRAY<DOUBLE>), 2) AS DOUBLE))", docRef, docRef, docRef)
	if b.Kind == schema.StoragePromotedScalar && b.ColumnName != "" {
		lonExpr = fmt.Sprintf("COALESCE(CAST(SPLIT_PART(`%s`, ',', 2) AS DOUBLE), %s)", b.ColumnName, lonExpr)
		latExpr = fmt.Sprintf("COALESCE(CAST(SPLIT_PART(`%s`, ',', 1) AS DOUBLE), %s)", b.ColumnName, latExpr)
	}
	return fmt.Sprintf("ST_Distance_Sphere(%s, %s, %s, %s)",
		lonExpr, latExpr,
		tLonStr,
		tLatStr,
	), true
}

func parseSortGeoPointLatLon(v any) (lat, lon float64, ok bool) {
	toF := func(x any) (float64, bool) {
		switch nv := x.(type) {
		case float64:
			return nv, !math.IsNaN(nv) && !math.IsInf(nv, 0)
		case int:
			return float64(nv), true
		case int64:
			return float64(nv), true
		case json.Number:
			f, err := nv.Float64()
			return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
		case string:
			f, err := strconv.ParseFloat(strings.TrimSpace(nv), 64)
			return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
		}
		return 0, false
	}
	switch tv := v.(type) {
	case map[string]any:
		latVal, okLat := toF(tv["lat"])
		lonVal, okLon := toF(tv["lon"])
		if okLat && okLon {
			return latVal, lonVal, true
		}
	case []any:
		if len(tv) >= 2 {
			lonVal, okLon := toF(tv[0])
			latVal, okLat := toF(tv[1])
			if okLat && okLon {
				return latVal, lonVal, true
			}
		}
	case string:
		str := strings.TrimSpace(tv)
		if strings.HasPrefix(strings.ToUpper(str), "POINT") {
			openIdx := strings.IndexByte(str, '(')
			closeIdx := strings.LastIndexByte(str, ')')
			if openIdx > 0 && closeIdx > openIdx {
				fields := strings.Fields(str[openIdx+1 : closeIdx])
				if len(fields) == 2 {
					lonVal, err1 := strconv.ParseFloat(fields[0], 64)
					latVal, err2 := strconv.ParseFloat(fields[1], 64)
					if err1 == nil && err2 == nil {
						return latVal, lonVal, true
					}
				}
			}
		}
		if parts := strings.Split(str, ","); len(parts) == 2 {
			latVal, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			lonVal, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			if err1 == nil && err2 == nil {
				return latVal, lonVal, true
			}
		}
		if latVal, lonVal, okHash := schema.DecodeGeohashLatLon(str); okHash {
			return latVal, lonVal, true
		}
	}
	return 0, 0, false
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
		dir := "ASC"
		if strings.EqualFold(s.Entry.Order, "desc") {
			dir = "DESC"
		}
		if s.Entry.Field == "_geo_distance" {
			if geoMap, ok := s.Entry.Script.(map[string]any); ok {
				reserved := map[string]bool{
					"order": true, "mode": true, "missing": true, "unit": true,
					"distance_type": true, "validation_method": true, "ignore_unmapped": true, "unmapped_type": true, "nested": true,
				}
				for k := range geoMap {
					if !reserved[k] {
						resolvedGeo, geoB := t.resolveSortFieldAndBinding(k, s.Entry.Nested)
						if t.Schema != nil && len(t.Schema.Fields) > 0 {
							if geoB.ESType != "" && geoB.ESType != "geo_point" {
								if t.searchErr == nil {
									t.searchErr = fmt.Errorf("failed to find mapper for [%s] for geo distance based sort", k)
								}
							} else if geoB.ESType == "" && !s.Entry.IgnoreUnmapped && s.Entry.Type == "" && len(after) == 0 && s.Entry.Missing == "" {
								if t.searchErr == nil {
									t.searchErr = fmt.Errorf("no mapping found for [%s] in order to sort on", k)
								}
							}
						}
						t.checkFieldDocValues(resolvedGeo, geoB)
						break
					}
				}
			}
			if geoExpr, ok := t.compileGeoDistanceSortExpr(s); ok {
				if missDist, okM := parseGeoSortMissingMeters(s.Entry.Missing, extractGeoSortUnit(s)); okM {
					geoExpr = fmt.Sprintf("COALESCE(%s, %g)", geoExpr, missDist)
				}
				orderPart := geoExpr + " " + dir
				if strings.EqualFold(s.Entry.Missing, "_first") {
					orderPart += " NULLS FIRST"
				} else {
					orderPart += " NULLS LAST"
				}
				parts = append(parts, orderPart)
			}
			afterIdx++
			continue
		}
		if s.Entry.Field == "_script" {
			var sortNCtx *nestedCtx
			if deepest := deepestNestedSortPath(s.Entry.Nested); deepest != "" {
				sortNCtx = &nestedCtx{nestedPath: deepest}
			}
			t.checkScriptDocValues(s.Entry.Script, sortNCtx)
			if scriptExpr, sb, ok := t.compileScriptSortExpr(s); ok {
				_, missingSQL := t.resolveSortMissing(s, sb)
				if missingSQL != "" {
					scriptExpr = fmt.Sprintf("COALESCE(%s, %s)", scriptExpr, missingSQL)
				}
				orderPart := scriptExpr + " " + dir
				if strings.EqualFold(s.Entry.Missing, "_first") {
					orderPart += " NULLS FIRST"
				} else if missingSQL == "" {
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
			resolvedField, b := t.resolveSortFieldAndBinding(s.Entry.Field, s.Entry.Nested)
			if s.Entry.IgnoreUnmapped && b.Kind == schema.StorageDynamicVariant && s.Entry.Type == "" {
				if len(after) >= len(sorts) {
					afterIdx++
				}
				continue
			}
			hasSortSample := (afterIdx < len(after) && after[afterIdx] != nil) ||
				(s.Entry.Missing != "" && !strings.EqualFold(s.Entry.Missing, "_first") && !strings.EqualFold(s.Entry.Missing, "_last"))
			if t.Schema != nil && len(t.Schema.Fields) > 0 && !strings.HasPrefix(s.Entry.Field, "_") && b.Kind == schema.StorageDynamicVariant && s.Entry.Type == "" && !s.Entry.IgnoreUnmapped && !hasSortSample {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("no mapping found for [%s] in order to sort on", s.Entry.Field)
				}
			}
			t.checkFieldDocValues(resolvedField, b)
			rawSortType := s.Entry.Type
			effType := effectiveSortESType(b, rawSortType, s.Entry.NumericType)
			sampleVal, missingSQL := t.resolveSortMissing(s, b)
			if sampleVal == nil && effType != "" {
				sampleVal = sampleValForSortType(effType)
			}
			if afterIdx < len(after) && after[afterIdx] != nil {
				sampleVal = after[afterIdx]
				if effType == "boolean" || b.DorisType == schema.DorisBoolean {
					if bv, ok := normalizeBooleanQueryValue(sampleVal); ok {
						sampleVal = bv
					}
				} else if effType == "ip" {
					if n, ok := parseIPv4ToUint32(sampleVal); ok {
						sampleVal = n
					}
				} else if strVal, ok := sampleVal.(string); ok {
					if effType == "date" || effType == "date_nanos" || (effType == "" && b.DorisType == schema.DorisBigInt) {
						effFormat := s.Entry.Format
						if effFormat == "" {
							effFormat = b.Format
						}
						if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, effFormat, time.Now().UTC()); ok {
							sampleVal = ms
						}
					} else if b.DorisType == schema.DorisBigInt || b.DorisType == schema.DorisInt {
						if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
							sampleVal = iv
						}
					}
				}
				sampleVal = normalizeEpochSecondSortValue(effType, s.Entry.Format, b, sampleVal)
				sampleVal = normalizeDateNanosValue(effType, sampleVal)
				sampleVal = normalizeScaledFloatValue(b, sampleVal)
			}
			col := t.sqlSortColumnRefWithType(s.Entry.Field, sampleVal, dir == "DESC", s.Entry.Mode, s.Entry.Nested, effType)
			if b.ESType != "" && s.Entry.NumericType != "" && b.Kind == schema.StoragePromotedScalar {
				switch strings.ToLower(s.Entry.NumericType) {
				case "long", "date", "date_nanos":
					col = fmt.Sprintf("CAST(%s AS BIGINT)", col)
				case "double":
					col = fmt.Sprintf("CAST(%s AS DOUBLE)", col)
				}
			}
			if missingSQL != "" {
				col = fmt.Sprintf("COALESCE(%s, %s)", col, missingSQL)
			}
			orderPart := col + " " + dir
			if strings.EqualFold(s.Entry.Missing, "_first") {
				orderPart += " NULLS FIRST"
			} else if missingSQL == "" {
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

func deepestNestedSortPath(nested *esast.NestedSortSpec) string {
	deepest := ""
	for cur := nested; cur != nil; cur = cur.Nested {
		if cur.Path != "" {
			deepest = cur.Path
		}
	}
	return deepest
}

func parseFiniteFloatValue(v any) (float64, bool) {
	switch nv := v.(type) {
	case float64:
		return nv, !math.IsNaN(nv) && !math.IsInf(nv, 0)
	case int:
		return float64(nv), true
	case int64:
		return float64(nv), true
	case json.Number:
		f, err := nv.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(nv), 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	default:
		return 0, false
	}
}

func (t *Transpiler) resolveSortFieldAndBinding(field string, nested *esast.NestedSortSpec) (string, schema.FieldBinding) {
	var sortNCtx *nestedCtx
	if deepestNestedPath := deepestNestedSortPath(nested); deepestNestedPath != "" {
		sortNCtx = &nestedCtx{nestedPath: deepestNestedPath}
	}
	return t.resolveFieldInNestedCtx(field, true, sortNCtx)
}

func (t *Transpiler) compileSearchAfterPredicate(sorts []esast.SortSpec, after []any, scoreExpr string) string {
	var effectiveSorts []esast.SortSpec
	var effectiveAfter []any
	useOrigIdx := len(after) >= len(sorts)
	seqIdx := 0
	for origIdx, s := range sorts {
		if s.Entry.Field == "_geo_distance" {
			if _, ok := t.compileGeoDistanceSortExpr(s); !ok {
				break
			}
		}
		if s.Entry.Field == "_script" {
			if _, _, ok := t.compileScriptSortExpr(s); !ok {
				break
			}
		}
		if s.Entry.Field != "" && s.Entry.Field != "_score" && s.Entry.Field != "_id" && s.Entry.Field != "_doc" && s.Entry.Field != "_geo_distance" && s.Entry.Field != "_script" {
			_, b := t.resolveSortFieldAndBinding(s.Entry.Field, s.Entry.Nested)
			if s.Entry.IgnoreUnmapped && b.Kind == schema.StorageDynamicVariant && s.Entry.Type == "" {
				continue
			}
		}
		if s.Entry.Field != "" {
			effectiveSorts = append(effectiveSorts, s)
			if useOrigIdx {
				if origIdx < len(after) {
					effectiveAfter = append(effectiveAfter, after[origIdx])
				}
			} else if seqIdx < len(after) {
				effectiveAfter = append(effectiveAfter, after[seqIdx])
				seqIdx++
			}
		}
	}
	if len(sorts) == 0 {
		effectiveSorts = []esast.SortSpec{
			{Entry: esast.SortFieldSpec{Field: "_score", Order: "desc"}},
			{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}},
		}
		effectiveAfter = after
	}
	n := len(effectiveSorts)
	if len(effectiveAfter) < n {
		n = len(effectiveAfter)
	}
	if n == 0 {
		return "TRUE"
	}

	sortExpr := func(idx int) (string, any, bool, any) {
		field := effectiveSorts[idx].Entry.Field
		val := effectiveAfter[idx]
		desc := strings.EqualFold(effectiveSorts[idx].Entry.Order, "desc")
		switch field {
		case "_score":
			return fmt.Sprintf("CAST(%s AS DOUBLE)", scoreExpr), val, true, nil
		case "_id", "_doc":
			if val != nil {
				val = fmt.Sprintf("%v", val)
			}
			return "`_id`", val, true, nil
		case "_geo_distance":
			geoExpr, _ := t.compileGeoDistanceSortExpr(effectiveSorts[idx])
			hasGeoMiss := false
			var geoMissSample any
			if missDist, okM := parseGeoSortMissingMeters(effectiveSorts[idx].Entry.Missing, extractGeoSortUnit(effectiveSorts[idx])); okM {
				geoExpr = fmt.Sprintf("COALESCE(%s, %g)", geoExpr, missDist)
				hasGeoMiss = true
				geoMissSample = missDist
			}
			if geoMap, ok := effectiveSorts[idx].Entry.Script.(map[string]any); ok {
				unit := "m"
				if uStr, okU := geoMap["unit"].(string); okU && uStr != "" {
					unit = strings.ToLower(strings.TrimSpace(uStr))
				}
				if fv, okF := parseFiniteFloatValue(val); okF {
					switch unit {
					case "km", "kilometers", "kilometer":
						val = fv * 1000.0
					case "mi", "miles", "mile":
						val = fv * 1609.344
					case "yd", "yards", "yard":
						val = fv * 0.9144
					case "ft", "feet", "foot":
						val = fv * 0.3048
					case "in", "inch", "inches":
						val = fv * 0.0254
					case "nmi", "nm":
						val = fv * 1852.0
					case "cm", "centimeters", "centimeter":
						val = fv * 0.01
					case "mm", "millimeters", "millimeter":
						val = fv * 0.001
					}
				}
			}
			return geoExpr, val, hasGeoMiss, geoMissSample
		case "_script":
			scriptExpr, sb, _ := t.compileScriptSortExpr(effectiveSorts[idx])
			missSample, missingSQL := t.resolveSortMissing(effectiveSorts[idx], sb)
			if missingSQL != "" {
				scriptExpr = fmt.Sprintf("COALESCE(%s, %s)", scriptExpr, missingSQL)
			}
			return scriptExpr, val, missingSQL != "", missSample
		default:
			_, b := t.resolveSortFieldAndBinding(field, effectiveSorts[idx].Entry.Nested)
			rawSortType := effectiveSorts[idx].Entry.Type
			effType := effectiveSortESType(b, rawSortType, effectiveSorts[idx].Entry.NumericType)
			missSample, missingSQL := t.resolveSortMissing(effectiveSorts[idx], b)
			if effType == "boolean" || b.DorisType == schema.DorisBoolean {
				if bv, ok := normalizeBooleanQueryValue(val); ok {
					val = bv
				}
			} else if effType == "ip" {
				if n, ok := parseIPv4ToUint32(val); ok {
					val = n
				}
			} else if effType == "version" || b.ESType == "version" {
				if val != nil {
					val = formatSemverBoundKey(fmt.Sprintf("%v", val))
				}
			} else if strVal, ok := val.(string); ok {
				if b.EffectiveLowercase(true) && effType != "date" && effType != "date_nanos" && b.DorisType != schema.DorisBigInt && b.DorisType != schema.DorisInt && b.DorisType != schema.DorisDouble {
					val = strings.ToLower(strVal)
				} else if effType == "date" || effType == "date_nanos" || (effType == "" && b.DorisType == schema.DorisBigInt) {
					effFormat := effectiveSorts[idx].Entry.Format
					if effFormat == "" {
						effFormat = b.Format
					}
					if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, effFormat, time.Now().UTC()); ok {
						val = ms
					}
				} else if b.DorisType == schema.DorisBigInt || b.DorisType == schema.DorisInt {
					if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
						val = iv
					}
				} else if b.DorisType == schema.DorisDouble {
					if fv, err := strconv.ParseFloat(strings.TrimSpace(strVal), 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
						val = fv
					}
				}
			}
			val = normalizeEpochSecondSortValue(effType, effectiveSorts[idx].Entry.Format, b, val)
			val = normalizeDateNanosValue(effType, val)
			val = normalizeScaledFloatValue(b, val)
			sampleForCol := val
			if sampleForCol == nil {
				sampleForCol = missSample
			}
			if sampleForCol == nil && effType != "" {
				sampleForCol = sampleValForSortType(effType)
			}
			col := t.sqlSortColumnRefWithType(field, sampleForCol, desc, effectiveSorts[idx].Entry.Mode, effectiveSorts[idx].Entry.Nested, effType)
			if b.ESType != "" && effectiveSorts[idx].Entry.NumericType != "" && b.Kind == schema.StoragePromotedScalar {
				switch strings.ToLower(effectiveSorts[idx].Entry.NumericType) {
				case "long", "date", "date_nanos":
					col = fmt.Sprintf("CAST(%s AS BIGINT)", col)
				case "double":
					col = fmt.Sprintf("CAST(%s AS DOUBLE)", col)
				}
			}
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

func (t *Transpiler) sqlSortColumnRefWithType(field string, sampleVal any, desc bool, mode string, nested *esast.NestedSortSpec, effType string) string {
	var sortNCtx *nestedCtx
	deepestNestedPath := ""
	for cur := nested; cur != nil; cur = cur.Nested {
		if cur.Path != "" {
			deepestNestedPath = cur.Path
		}
	}
	if deepestNestedPath != "" {
		sortNCtx = &nestedCtx{nestedPath: deepestNestedPath}
	}
	field, b := t.resolveFieldInNestedCtx(field, true, sortNCtx)
	if effType == "" {
		effType = b.ESType
	}
	buildNestedSortFilterCond := func(leafPath string) string {
		var conds []string
		levelIdx := 0
		for cur := nested; cur != nil; cur = cur.Nested {
			levelIdx++
			if cur.Filter == nil {
				continue
			}
			curPath := cur.Path
			if curPath == "" {
				curPath = leafPath
			}
			if curPath == leafPath {
				fCompiled := t.CompileQuery(cur.Filter, false, &nestedCtx{nestedPath: leafPath, elemVar: "_el"})
				if fCompiled.WhereSQL != "" && fCompiled.WhereSQL != "TRUE" {
					conds = append(conds, fCompiled.WhereSQL)
				}
			} else if strings.HasPrefix(leafPath, curPath+".") {
				ancCorrCol, ok := t.Schema.NestedRoots[curPath]
				if !ok {
					ancCorrCol = "n__" + schema.SanitizeDorisIdentifier(curPath)
				}
				ancVar := fmt.Sprintf("_el_p%d", levelIdx)
				fCompiled := t.CompileQuery(cur.Filter, false, &nestedCtx{nestedPath: curPath, elemVar: ancVar})
				parentCorr := fmt.Sprintf("json_extract_string(_el, '$._parent_id') = json_extract_string(%s, '$._nested_id')", ancVar)
				ancWhere := parentCorr
				if fCompiled.WhereSQL != "" && fCompiled.WhereSQL != "TRUE" {
					ancWhere = fmt.Sprintf("(%s AND %s)", parentCorr, fCompiled.WhereSQL)
				}
				conds = append(conds, fmt.Sprintf("array_exists(%s -> %s, `%s`)", ancVar, ancWhere, ancCorrCol))
			}
		}
		return strings.Join(conds, " AND ")
	}
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
		if effType == "ip" || b.ESType == "ip" {
			return fmt.Sprintf("%s(array_map(_x -> IPV4_STRING_TO_NUM_OR_NULL(_x), %s))", fn, arrRef)
		}
		if effType == "version" || b.ESType == "version" {
			return fmt.Sprintf("%s(array_map(_x -> %s, %s))", fn, sqlSemverSortKeyExpr("_x"), arrRef)
		}
		effDT := effectiveDorisScalarType(b)
		switch strings.ToLower(strings.TrimSpace(effType)) {
		case "long", "integer", "short", "byte", "date", "date_nanos":
			effDT = schema.DorisBigInt
		case "double", "float", "half_float", "scaled_float", "number":
			effDT = schema.DorisDouble
		case "boolean":
			effDT = schema.DorisBoolean
		}
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
		nestedPath := deepestNestedPath
		if nestedPath == "" {
			nestedPath = b.NestedPath
		}
		if filterCond := buildNestedSortFilterCond(nestedPath); filterCond != "" {
			corrCol, ok := t.Schema.NestedRoots[nestedPath]
			if !ok {
				corrCol = "n__" + schema.SanitizeDorisIdentifier(nestedPath)
			}
			relPath := t.nestedRelativeJSONPath(field, true, nestedPath)
			filteredArr := fmt.Sprintf("array_map(_el -> json_extract_string(_el, %s), array_filter(_el -> %s, `%s`))", quoteStr(relPath), filterCond, corrCol)
			return formatArraySortExpr(filteredArr)
		}
		colName := b.EffectiveArrayColumn(true)
		if colName != "" {
			return formatArraySortExpr(fmt.Sprintf("`%s`", colName))
		}
		if nestedPath != "" {
			corrCol, ok := t.Schema.NestedRoots[nestedPath]
			if !ok {
				corrCol = "n__" + schema.SanitizeDorisIdentifier(nestedPath)
			}
			relPath := t.nestedRelativeJSONPath(field, true, nestedPath)
			return formatArraySortExpr(fmt.Sprintf("array_map(_el -> json_extract_string(_el, %s), `%s`)", quoteStr(relPath), corrCol))
		}
	case schema.StoragePromotedVector:
		return fmt.Sprintf("element_at(`%s`, 1)", b.ColumnName)
	}
	if b.Kind == schema.StorageDynamicVariant && deepestNestedPath != "" {
		nestedPath := deepestNestedPath
		corrCol, ok := t.Schema.NestedRoots[nestedPath]
		if !ok {
			corrCol = "n__" + schema.SanitizeDorisIdentifier(nestedPath)
		}
		relPath := t.nestedRelativeJSONPath(field, true, nestedPath)
		if filterCond := buildNestedSortFilterCond(nestedPath); filterCond != "" {
			filteredArr := fmt.Sprintf("array_map(_el -> json_extract_string(_el, %s), array_filter(_el -> %s, `%s`))", quoteStr(relPath), filterCond, corrCol)
			return formatArraySortExpr(filteredArr)
		}
		return formatArraySortExpr(fmt.Sprintf("array_map(_el -> json_extract_string(_el, %s), `%s`)", quoteStr(relPath), corrCol))
	}
	if effType == "ip" || b.ESType == "ip" {
		return fmt.Sprintf("IPV4_STRING_TO_NUM_OR_NULL(%s)", t.sqlColumnRef(field, true, nil))
	}
	if effType == "version" || b.ESType == "version" {
		return sqlSemverSortKeyExpr(t.sqlColumnRef(field, true, nil))
	}
	return t.sqlTypedColumnRef(field, sampleVal, true, nil)
}

func (t *Transpiler) sqlColumnRef(field string, preferKeyword bool, nctx *nestedCtx) string {
	return t.sqlTypedColumnRef(field, nil, preferKeyword, nctx)
}

func (t *Transpiler) sqlNumericColumnRef(field string, nctx *nestedCtx) string {
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	switch b.Kind {
	case schema.StoragePromotedScalar:
		if b.DorisType == schema.DorisBigInt || b.DorisType == schema.DorisInt || b.DorisType == schema.DorisDouble {
			return fmt.Sprintf("`%s`", b.ColumnName)
		}
		return fmt.Sprintf("CAST(`%s` AS DOUBLE)", b.ColumnName)
	case schema.StoragePromotedArray, schema.StoragePromotedVector:
		return fmt.Sprintf("CAST(element_at(`%s`, 1) AS DOUBLE)", b.EffectiveArrayColumn(true))
	case schema.StorageNestedSubfield:
		if (nctx == nil || nctx.elemVar == "" || nctx.nestedPath != b.NestedPath) && b.EffectiveArrayColumn(true) != "" {
			return fmt.Sprintf("CAST(element_at(`%s`, 1) AS DOUBLE)", b.EffectiveArrayColumn(true))
		}
	}
	return t.sqlTypedColumnRef(field, float64(0.5), false, nctx)
}

func (t *Transpiler) nestedRelativeJSONPath(field string, preferKeyword bool, nestedPath string) string {
	resolvedField, b := t.resolveFieldInNestedCtx(field, preferKeyword, &nestedCtx{nestedPath: nestedPath})
	effField := resolvedField
	if b.AliasTarget != "" {
		effField = b.AliasTarget
		if strings.HasSuffix(resolvedField, ".keyword") && !strings.HasSuffix(effField, ".keyword") {
			effField += ".keyword"
		}
		if t.Schema != nil {
			b = t.Schema.ResolveEffectiveField(effField, preferKeyword)
		}
	}
	relKey := strings.TrimSuffix(strings.TrimPrefix(effField, nestedPath+"."), ".keyword")
	if len(b.RelativeJSONPath) > 0 {
		relKey = strings.Join(b.RelativeJSONPath, ".")
	} else if len(b.SourceJSONPath) > 0 {
		srcPath := strings.Join(b.SourceJSONPath, ".")
		if strings.HasPrefix(srcPath, nestedPath+".") {
			relKey = strings.TrimPrefix(srcPath, nestedPath+".")
		}
	}
	if t.Schema != nil {
		srcDotPath := strings.Join(b.SourceJSONPath, ".")
		if srcDotPath == "" {
			srcDotPath = strings.TrimSuffix(effField, ".keyword")
		}
		subKey := ""
		if strings.HasPrefix(effField, srcDotPath+".") {
			subKey = strings.TrimPrefix(effField, srcDotPath+".")
		} else if preferKeyword && b.ESType == "keyword" && effField == srcDotPath {
			subKey = "keyword"
		}
		if subKey != "" && !strings.Contains(subKey, ".") {
			if baseB, hasBase := t.Schema.Fields[srcDotPath]; hasBase {
				if subKey != "keyword" || baseB.ESType == "text" || strings.HasSuffix(effField, ".keyword") {
					if b.IgnoreAbove > 0 || b.LowercaseNormalizer || b.IsMultiValued || b.NullValue != nil ||
						baseB.IgnoreAbove > 0 || baseB.LowercaseNormalizer || baseB.NullValue != nil ||
						b.ESType != baseB.ESType || b.Format != baseB.Format || b.ScalingFactor != baseB.ScalingFactor {
						relKey += "__" + subKey
					}
				}
			}
		}
	}
	return "$." + relKey
}

func (t *Transpiler) resolveFieldInNestedCtx(field string, preferKeyword bool, nctx *nestedCtx) (string, schema.FieldBinding) {
	if t.Schema == nil {
		return field, schema.FieldBinding{ESFieldPath: field, Kind: schema.StorageDynamicVariant}
	}
	b := t.Schema.ResolveEffectiveField(field, preferKeyword)
	if nctx != nil && nctx.nestedPath != "" && b.Kind == schema.StorageDynamicVariant && b.NestedPath != nctx.nestedPath && !strings.HasPrefix(field, nctx.nestedPath+".") {
		prefixed := nctx.nestedPath + "." + field
		if nb := t.Schema.ResolveEffectiveField(prefixed, preferKeyword); nb.Kind == schema.StorageNestedSubfield || nb.NestedPath == nctx.nestedPath {
			return prefixed, nb
		}
		if nb := t.Schema.ResolveField(prefixed); nb.Kind == schema.StorageNestedSubfield || nb.NestedPath == nctx.nestedPath {
			return prefixed, nb
		}
	}
	return field, b
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
	if field == "_routing" {
		return "`_routing`"
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
	case uint64:
		if v > math.MaxInt64 {
			castType = "LARGEINT"
		} else {
			castType = "BIGINT"
		}
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
		} else if _, errU := strconv.ParseUint(v.String(), 10, 64); errU == nil {
			castType = "LARGEINT"
		} else {
			castType = "DOUBLE"
		}
	case bool:
		castType = "BOOLEAN"
	}

	field, b := t.resolveFieldInNestedCtx(field, preferKeyword, nctx)
	if effectiveDorisScalarType(b) == schema.DorisDouble && castType == "BIGINT" {
		castType = "DOUBLE"
	}
	effField := field
	if b.AliasTarget != "" {
		effField = b.AliasTarget
	}
	if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(effField, nctx.nestedPath+".") || b.Kind == schema.StorageDynamicVariant) {
		relPath := t.nestedRelativeJSONPath(field, preferKeyword, nctx.nestedPath)
		extractExpr := fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath))
		if castType != "STRING" {
			extractExpr = fmt.Sprintf("CAST(%s AS %s)", extractExpr, castType)
		}
		if b.ESType == "constant_keyword" && b.ConstantValue != nil {
			constVal := fmt.Sprintf("%v", b.ConstantValue)
			if b.LowercaseNormalizer {
				constVal = strings.ToLower(constVal)
			}
			return fmt.Sprintf("COALESCE(%s, %s)", extractExpr, quoteStr(constVal))
		}
		return extractExpr
	}

	switch b.Kind {
	case schema.StoragePromotedScalar:
		if b.ESType == "unsigned_long" && castType == "LARGEINT" && effField != "" {
			break
		}
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
	if b.Kind != schema.StoragePromotedScalar && t.unindexedFields != nil && field != "" && !strings.HasPrefix(field, "_") && !strings.ContainsAny(field, "*?") {
		t.unindexedFields[strings.TrimSuffix(field, ".keyword")] = true
	}
	srcPath := b.SourceJSONPath
	if len(srcPath) == 0 && effField != "" {
		srcPath = strings.Split(strings.TrimSuffix(effField, ".keyword"), ".")
	}
	var pathBuilder strings.Builder
	for _, seg := range srcPath {
		_, _ = fmt.Fprintf(&pathBuilder, "[%s]", quoteStr(seg))
	}
	docExpr := fmt.Sprintf("CAST(`_doc`%s AS %s)", pathBuilder.String(), castType)
	if b.ESType == "constant_keyword" && b.ConstantValue != nil && b.Kind == schema.StorageDynamicVariant {
		constVal := fmt.Sprintf("%v", b.ConstantValue)
		if b.LowercaseNormalizer {
			constVal = strings.ToLower(constVal)
		}
		return fmt.Sprintf("COALESCE(%s, %s)", docExpr, quoteStr(constVal))
	}
	return docExpr
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
		if strings.Contains(s, "<") {
			parts := strings.Fields(s)
			activeSpec := ""
			bestThresh := math.MinInt
			minThresh := math.MaxInt
			hasValidThresh := false
			for _, part := range parts {
				if idx := strings.IndexByte(part, '<'); idx > 0 {
					if thresh, err := strconv.Atoi(strings.TrimSpace(part[:idx])); err == nil {
						hasValidThresh = true
						if thresh < minThresh {
							minThresh = thresh
						}
						if numClauses > thresh && thresh >= bestThresh {
							bestThresh = thresh
							activeSpec = strings.TrimSpace(part[idx+1:])
						}
					}
				}
			}
			if hasValidThresh && numClauses <= minThresh {
				return numClauses
			}
			if activeSpec != "" {
				s = activeSpec
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
	case uint64:
		return strconv.FormatUint(val, 10)
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

func normalizeScaledFloatValue(b schema.FieldBinding, val any) any {
	if b.ESType != "scaled_float" || b.ScalingFactor <= 0 || val == nil {
		return val
	}
	var fv float64
	var ok bool
	switch v := val.(type) {
	case float64:
		fv, ok = v, true
	case int:
		fv, ok = float64(v), true
	case int64:
		fv, ok = float64(v), true
	case json.Number:
		if f, err := v.Float64(); err == nil {
			fv, ok = f, true
		}
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			fv, ok = f, true
		}
	}
	if ok && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
		return math.Round(fv*b.ScalingFactor) / b.ScalingFactor
	}
	return val
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
		if f, err := v.Float64(); err == nil {
			return f != 0 && !math.IsNaN(f), true
		}
		return v.String() != "0" && v.String() != "", true
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

func coerceRangeFieldQueryScalar(v any, b schema.FieldBinding, format string, tzOffsetMs int64, isExclusive bool, isUpper bool) (float64, bool) {
	if v == nil {
		return 0, false
	}
	switch b.ESType {
	case "integer_range", "long_range":
		fv, ok := parseFiniteFloatValue(v)
		if !ok {
			return 0, false
		}
		var iv int64
		if isUpper {
			iv = int64(math.Floor(fv))
		} else {
			iv = int64(math.Ceil(fv))
		}
		if isExclusive {
			if isUpper {
				iv--
			} else {
				iv++
			}
		}
		return float64(iv), true
	case "float_range", "double_range":
		return parseFiniteFloatValue(v)
	case "date_range":
		now := time.Now().UTC()
		roundUp := isUpper && !isExclusive
		var ms int64
		if s, isStr := v.(string); isStr {
			parsedMs, ok := schema.ParseESDateBoundWithFormatToEpochMillis(s, format, now, roundUp)
			if !ok {
				return 0, false
			}
			ms = parsedMs
			datePart := strings.TrimSpace(s)
			if idx := strings.Index(datePart, "||"); idx >= 0 {
				datePart = strings.TrimSpace(datePart[:idx])
			}
			if _, numErr := strconv.ParseFloat(datePart, 64); numErr != nil &&
				tzOffsetMs != 0 && !strings.HasPrefix(datePart, "now") &&
				!strings.HasSuffix(datePart, "Z") && !strings.HasSuffix(datePart, "z") &&
				!strings.Contains(datePart[min(10, len(datePart)):], "+") &&
				!strings.Contains(datePart[min(10, len(datePart)):], "-") {
				ms -= tzOffsetMs
			}
		} else if fv, ok := parseFiniteFloatValue(v); ok {
			ms = int64(fv)
		} else {
			return 0, false
		}
		if isExclusive {
			if isUpper {
				ms--
			} else {
				ms++
			}
		}
		return float64(ms), true
	case "ip_range":
		s := strings.TrimSpace(fmt.Sprintf("%v", v))
		if lo, hi, isCIDR := parseCIDRBounds(s); isCIDR {
			if isUpper {
				return float64(hi), true
			}
			return float64(lo), true
		}
		fv, ok := schema.IPToSortableFloat(s)
		if !ok {
			return 0, false
		}
		if isExclusive && net.ParseIP(s) != nil && net.ParseIP(s).To4() != nil {
			if isUpper {
				fv--
			} else {
				fv++
			}
		}
		return fv, true
	}
	return 0, false
}

func (t *Transpiler) rangeFieldBoundsAndRawSQL(field string, b schema.FieldBinding, nctx *nestedCtx) (string, string, string, string) {
	if nctx != nil && nctx.elemVar != "" && (b.Kind == schema.StorageNestedSubfield || b.NestedPath == nctx.nestedPath) && nctx.nestedPath == b.NestedPath {
		relPath := t.nestedRelativeJSONPath(field, false, b.NestedPath)
		gtePath := strings.TrimSuffix(relPath, "") + "._gte"
		ltePath := strings.TrimSuffix(relPath, "") + "._lte"
		rawGtePath := strings.TrimSuffix(relPath, "") + ".gte"
		rawLtePath := strings.TrimSuffix(relPath, "") + ".lte"
		gtPath := strings.TrimSuffix(relPath, "") + "._gt"
		ltPath := strings.TrimSuffix(relPath, "") + "._lt"
		rawGtPath := strings.TrimSuffix(relPath, "") + ".gt"
		rawLtPath := strings.TrimSuffix(relPath, "") + ".lt"
		rawLower := fmt.Sprintf("COALESCE(CAST(json_extract_string(%s, %s) AS DOUBLE), CAST(json_extract_string(%s, %s) AS DOUBLE), CAST(json_extract_string(%s, %s) AS DOUBLE), CAST(json_extract_string(%s, %s) AS DOUBLE))",
			nctx.elemVar, quoteStr(gtePath), nctx.elemVar, quoteStr(rawGtePath), nctx.elemVar, quoteStr(gtPath), nctx.elemVar, quoteStr(rawGtPath))
		rawUpper := fmt.Sprintf("COALESCE(CAST(json_extract_string(%s, %s) AS DOUBLE), CAST(json_extract_string(%s, %s) AS DOUBLE), CAST(json_extract_string(%s, %s) AS DOUBLE), CAST(json_extract_string(%s, %s) AS DOUBLE))",
			nctx.elemVar, quoteStr(ltePath), nctx.elemVar, quoteStr(rawLtePath), nctx.elemVar, quoteStr(ltPath), nctx.elemVar, quoteStr(rawLtPath))
		lower := fmt.Sprintf("COALESCE(%s, -1e100)", rawLower)
		upper := fmt.Sprintf("COALESCE(%s, 1e100)", rawUpper)
		return lower, upper, rawLower, rawUpper
	}
	parts := b.SourceJSONPath
	if len(parts) == 0 {
		parts = strings.Split(field, ".")
	}
	var base strings.Builder
	base.WriteString("`_doc`")
	for _, p := range parts {
		escaped := strings.ReplaceAll(p, `'`, `''`)
		base.WriteString("['" + escaped + "']")
	}
	baseExpr := base.String()
	rawLower := fmt.Sprintf("COALESCE(CAST(%s['_gte'] AS DOUBLE), CAST(%s['gte'] AS DOUBLE), CAST(%s['_gt'] AS DOUBLE), CAST(%s['gt'] AS DOUBLE))", baseExpr, baseExpr, baseExpr, baseExpr)
	rawUpper := fmt.Sprintf("COALESCE(CAST(%s['_lte'] AS DOUBLE), CAST(%s['lte'] AS DOUBLE), CAST(%s['_lt'] AS DOUBLE), CAST(%s['lt'] AS DOUBLE))", baseExpr, baseExpr, baseExpr, baseExpr)
	lower := fmt.Sprintf("COALESCE(%s, -1e100)", rawLower)
	upper := fmt.Sprintf("COALESCE(%s, 1e100)", rawUpper)
	return lower, upper, rawLower, rawUpper
}

func (t *Transpiler) compileRangeOnRangeField(field string, b schema.FieldBinding, rc esast.RangeCond, nctx *nestedCtx) string {
	gt, gte, lt, lte := rc.NormalizedBounds()
	effFormat := rc.Format
	if effFormat == "" {
		effFormat = b.Format
	}
	tzOffsetMs := esast.ParseTimeZoneOffsetMs(strings.TrimSpace(rc.TimeZone))

	var hasLower, hasUpper bool
	var qLower, qUpper float64
	var qLowerExclusive, qUpperExclusive bool

	if gte != nil {
		v, ok := coerceRangeFieldQueryScalar(gte, b, effFormat, tzOffsetMs, false, false)
		if !ok {
			return "FALSE"
		}
		qLower = v
		hasLower = true
	} else if gt != nil {
		isIntLike := b.ESType == "integer_range" || b.ESType == "long_range" || b.ESType == "date_range" || b.ESType == "ip_range"
		v, ok := coerceRangeFieldQueryScalar(gt, b, effFormat, tzOffsetMs, isIntLike, false)
		if !ok {
			return "FALSE"
		}
		qLower = v
		hasLower = true
		qLowerExclusive = !isIntLike
	}

	if lte != nil {
		v, ok := coerceRangeFieldQueryScalar(lte, b, effFormat, tzOffsetMs, false, true)
		if !ok {
			return "FALSE"
		}
		qUpper = v
		hasUpper = true
	} else if lt != nil {
		isIntLike := b.ESType == "integer_range" || b.ESType == "long_range" || b.ESType == "date_range" || b.ESType == "ip_range"
		v, ok := coerceRangeFieldQueryScalar(lt, b, effFormat, tzOffsetMs, isIntLike, true)
		if !ok {
			return "FALSE"
		}
		qUpper = v
		hasUpper = true
		qUpperExclusive = !isIntLike
	}

	if hasLower && hasUpper {
		if qLower > qUpper || (qLower == qUpper && (qLowerExclusive || qUpperExclusive)) {
			return "FALSE"
		}
	}

	lowerSQL, upperSQL, rawLower, rawUpper := t.rangeFieldBoundsAndRawSQL(field, b, nctx)
	existsCond := fmt.Sprintf("(%s IS NOT NULL OR %s IS NOT NULL)", rawLower, rawUpper)
	rel := strings.ToUpper(strings.TrimSpace(rc.Relation))
	if rel == "" {
		rel = "INTERSECTS"
	}

	qLowLit := strconv.FormatFloat(qLower, 'f', -1, 64)
	qUpLit := strconv.FormatFloat(qUpper, 'f', -1, 64)

	var conds []string
	switch rel {
	case "CONTAINS":
		if hasLower || hasUpper {
			if hasLower {
				conds = append(conds, fmt.Sprintf("%s <= %s", lowerSQL, qLowLit))
			} else {
				conds = append(conds, fmt.Sprintf("%s <= -1e99", lowerSQL))
			}
			if hasUpper {
				conds = append(conds, fmt.Sprintf("%s >= %s", upperSQL, qUpLit))
			} else {
				conds = append(conds, fmt.Sprintf("%s >= 1e99", upperSQL))
			}
		}
	case "WITHIN":
		if hasLower {
			if qLowerExclusive {
				conds = append(conds, fmt.Sprintf("%s > %s", lowerSQL, qLowLit))
			} else {
				conds = append(conds, fmt.Sprintf("%s >= %s", lowerSQL, qLowLit))
			}
		}
		if hasUpper {
			if qUpperExclusive {
				conds = append(conds, fmt.Sprintf("%s < %s", upperSQL, qUpLit))
			} else {
				conds = append(conds, fmt.Sprintf("%s <= %s", upperSQL, qUpLit))
			}
		}
	default: // INTERSECTS
		if hasUpper {
			if qUpperExclusive {
				conds = append(conds, fmt.Sprintf("%s < %s", lowerSQL, qUpLit))
			} else {
				conds = append(conds, fmt.Sprintf("%s <= %s", lowerSQL, qUpLit))
			}
		}
		if hasLower {
			if qLowerExclusive {
				conds = append(conds, fmt.Sprintf("%s > %s", upperSQL, qLowLit))
			} else {
				conds = append(conds, fmt.Sprintf("%s >= %s", upperSQL, qLowLit))
			}
		}
	}
	if len(conds) == 0 {
		return existsCond
	}
	conds = append([]string{existsCond}, conds...)
	return "(" + strings.Join(conds, " AND ") + ")"
}

func (t *Transpiler) compileGeoPolygon(gp *esast.GeoPolygonQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if gp == nil || gp.Field == "" || len(gp.Points) < 3 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	minLat, maxLat := 90.0, -90.0
	minLon, maxLon := 180.0, -180.0
	for _, pt := range gp.Points {
		if pt[0] < minLat {
			minLat = pt[0]
		}
		if pt[0] > maxLat {
			maxLat = pt[0]
		}
		if pt[1] < minLon {
			minLon = pt[1]
		}
		if pt[1] > maxLon {
			maxLon = pt[1]
		}
	}
	bboxQ := t.compileGeoBoundingBox(&esast.GeoBoundingBoxQuery{
		Field:            gp.Field,
		Top:              maxLat,
		Bottom:           minLat,
		Left:             minLon,
		Right:            maxLon,
		ValidationMethod: gp.ValidationMethod,
		IgnoreUnmapped:   gp.IgnoreUnmapped,
		Boost:            gp.Boost,
		Name:             gp.Name,
	}, scoring, nctx)
	if bboxQ.WhereSQL == "FALSE" || t.searchErr != nil {
		return bboxQ
	}
	resolvedField, b := t.resolveFieldInNestedCtx(gp.Field, false, nctx)
	var whereSQL string
	if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(resolvedField, nctx.nestedPath+".")) {
		elemExpr := t.sqlColumnRef(resolvedField, true, nctx)
		latExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
		lonExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
		whereSQL = fmt.Sprintf("(%s AND %s)", bboxQ.WhereSQL, buildPointInPolygonSQL(latExpr, lonExpr, gp.Points))
	} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
		latExpr := "CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE)"
		lonExpr := "CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE)"
		whereSQL = fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND %s, %s)", buildPointInPolygonSQL(latExpr, lonExpr, gp.Points), arrCol)
	} else {
		latExpr, lonExpr, _ := t.extractGeoPointExprs(resolvedField, b)
		whereSQL = fmt.Sprintf("(%s AND %s)", bboxQ.WhereSQL, buildPointInPolygonSQL(latExpr, lonExpr, gp.Points))
	}
	return CompiledQuery{
		WhereSQL:     whereSQL,
		SafeWhereSQL: whereSQL,
		ScoreSQL:     bboxQ.ScoreSQL,
	}
}

func buildPointInPolygonSQL(latExpr, lonExpr string, pts [][2]float64) string {
	if len(pts) < 3 {
		return "FALSE"
	}
	minLat, maxLat := 90.0, -90.0
	minLon, maxLon := 180.0, -180.0
	for _, pt := range pts {
		if pt[0] < minLat {
			minLat = pt[0]
		}
		if pt[0] > maxLat {
			maxLat = pt[0]
		}
		if pt[1] < minLon {
			minLon = pt[1]
		}
		if pt[1] > maxLon {
			maxLon = pt[1]
		}
	}
	bboxCond := fmt.Sprintf("(%s >= %s AND %s <= %s AND %s >= %s AND %s <= %s)",
		latExpr, strconv.FormatFloat(minLat, 'f', -1, 64),
		latExpr, strconv.FormatFloat(maxLat, 'f', -1, 64),
		lonExpr, strconv.FormatFloat(minLon, 'f', -1, 64),
		lonExpr, strconv.FormatFloat(maxLon, 'f', -1, 64))
	var edgeCases []string
	n := len(pts)
	for i := 0; i < n; i++ {
		j := (i + n - 1) % n
		latI, lonI := pts[i][0], pts[i][1]
		latJ, lonJ := pts[j][0], pts[j][1]
		if latI == latJ {
			continue
		}
		latIStr := strconv.FormatFloat(latI, 'f', -1, 64)
		lonIStr := strconv.FormatFloat(lonI, 'f', -1, 64)
		latJStr := strconv.FormatFloat(latJ, 'f', -1, 64)
		dLonStr := strconv.FormatFloat(lonJ-lonI, 'f', -1, 64)
		dLatStr := strconv.FormatFloat(latJ-latI, 'f', -1, 64)
		edgeCases = append(edgeCases, fmt.Sprintf(
			"CASE WHEN ((%s > %s) != (%s > %s)) AND (%s <= (%s * (%s - %s) / %s + %s)) THEN 1 ELSE 0 END",
			latIStr, latExpr, latJStr, latExpr, lonExpr, dLonStr, latExpr, latIStr, dLatStr, lonIStr))
	}
	if len(edgeCases) == 0 {
		return bboxCond
	}
	return fmt.Sprintf("(%s AND ((%s) %% 2 = 1))", bboxCond, strings.Join(edgeCases, " + "))
}

func extractGeoShapePolygons(coords any, shapeType string) [][][][2]float64 {
	parseRing := func(rawRing any) [][2]float64 {
		arr, ok := rawRing.([]any)
		if !ok {
			return nil
		}
		var pts [][2]float64
		for _, item := range arr {
			ptArr, ok := item.([]any)
			if !ok || len(ptArr) < 2 {
				continue
			}
			lon, ok1 := toFloat64ForGeo(ptArr[0])
			lat, ok2 := toFloat64ForGeo(ptArr[1])
			if ok1 && ok2 {
				pts = append(pts, [2]float64{lat, lon})
			}
		}
		if len(pts) >= 2 && pts[0][0] == pts[len(pts)-1][0] && pts[0][1] == pts[len(pts)-1][1] {
			pts = pts[:len(pts)-1]
		}
		return pts
	}
	parsePoly := func(polyArr []any) [][][2]float64 {
		if len(polyArr) == 0 {
			return nil
		}
		ext := parseRing(polyArr[0])
		if len(ext) < 3 {
			return nil
		}
		rings := [][][2]float64{ext}
		for _, rawHole := range polyArr[1:] {
			if hole := parseRing(rawHole); len(hole) >= 3 {
				rings = append(rings, hole)
			}
		}
		return rings
	}
	arr, ok := coords.([]any)
	if !ok || len(arr) == 0 {
		return nil
	}
	var polys [][][][2]float64
	switch shapeType {
	case "polygon":
		if p := parsePoly(arr); len(p) > 0 {
			polys = append(polys, p)
		}
	case "multipolygon":
		for _, polyRaw := range arr {
			if polyArr, ok := polyRaw.([]any); ok {
				if p := parsePoly(polyArr); len(p) > 0 {
					polys = append(polys, p)
				}
			}
		}
	}
	return polys
}

func (t *Transpiler) evalGeoPointPredForField(field string, nctx *nestedCtx, buildCond func(latExpr, lonExpr string) string) string {
	resolvedField, b := t.resolveFieldInNestedCtx(field, false, nctx)
	if !t.checkFieldSearchable(resolvedField, b) {
		return "FALSE"
	}
	if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(resolvedField, nctx.nestedPath+".")) {
		elemExpr := t.sqlColumnRef(resolvedField, true, nctx)
		latExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
		lonExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
		return fmt.Sprintf("(%s IS NOT NULL AND %s)", elemExpr, buildCond(latExpr, lonExpr))
	}
	if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
		latExpr := "CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE)"
		lonExpr := "CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE)"
		return fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND %s, %s)", buildCond(latExpr, lonExpr), arrCol)
	}
	latExpr, lonExpr, notNullCond := t.extractGeoPointExprs(resolvedField, b)
	return fmt.Sprintf("(%s AND %s)", notNullCond, buildCond(latExpr, lonExpr))
}

func (t *Transpiler) compileGeoShape(gs *esast.GeoShapeQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if gs == nil || gs.Field == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	resolvedField, b := t.resolveFieldInNestedCtx(gs.Field, false, nctx)
	if !t.checkFieldSearchable(resolvedField, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.ESType == "" && gs.IgnoreUnmapped {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.ESType != "" && b.ESType != "geo_shape" && b.ESType != "geo_point" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: failed to find geo_shape field [%s]", resolvedField)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	boost := 1.0
	if gs.Boost != nil {
		boost = *gs.Boost
	}
	scoreSQL := "1.0"
	if scoring && gs.Boost != nil {
		scoreSQL = fmt.Sprintf("%.4f", boost)
	}
	if len(gs.IndexedShape) > 0 {
		w := t.compileExistsPredicate(gs.Field, nctx)
		return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: scoreSQL}
	}
	if gs.Shape == nil {
		w := t.compileExistsPredicate(gs.Field, nctx)
		return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: scoreSQL}
	}
	rel := strings.ToUpper(strings.TrimSpace(gs.Relation))
	if rel == "" {
		rel = "INTERSECTS"
	}
	shapeType, _ := gs.Shape["type"].(string)
	shapeType = strings.ToLower(strings.TrimSpace(shapeType))

	if shapeType == "geometrycollection" {
		var childShapes []map[string]any
		switch geoms := gs.Shape["geometries"].(type) {
		case []any:
			for _, g := range geoms {
				if gm, ok := g.(map[string]any); ok {
					childShapes = append(childShapes, gm)
				}
			}
		case []map[string]any:
			childShapes = geoms
		}
		if len(childShapes) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		childRel := "INTERSECTS"
		if rel == "CONTAINS" {
			childRel = "CONTAINS"
		}
		var childPreds []string
		for _, cs := range childShapes {
			cp := t.compileGeoShape(&esast.GeoShapeQuery{
				Field:    gs.Field,
				Shape:    cs,
				Relation: childRel,
			}, false, nctx)
			if cp.WhereSQL != "FALSE" {
				childPreds = append(childPreds, cp.WhereSQL)
			} else if rel == "CONTAINS" {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
		}
		if len(childPreds) == 0 {
			if rel == "DISJOINT" {
				w := t.compileExistsPredicate(gs.Field, nctx)
				return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: scoreSQL}
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		joinOp := " OR "
		if rel == "CONTAINS" {
			joinOp = " AND "
		}
		combined := childPreds[0]
		if len(childPreds) > 1 {
			combined = "(" + strings.Join(childPreds, joinOp) + ")"
		}
		if rel == "DISJOINT" {
			w := fmt.Sprintf("(%s AND NOT (%s))", t.compileExistsPredicate(gs.Field, nctx), combined)
			return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: scoreSQL}
		}
		return CompiledQuery{WhereSQL: combined, SafeWhereSQL: combined, ScoreSQL: scoreSQL}
	}

	if shapeType == "circle" {
		coords, ok := gs.Shape["coordinates"].([]any)
		if !ok || len(coords) < 2 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		cLon, ok1 := toFloat64ForGeo(coords[0])
		cLat, ok2 := toFloat64ForGeo(coords[1])
		if !ok1 || !ok2 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		radiusMeters := 0.0
		if rawRad, hasRad := gs.Shape["radius"]; hasRad && rawRad != nil {
			if _, rm, err := esast.ParseGeoDistanceMeters(rawRad); err == nil {
				radiusMeters = rm
			}
		}
		if rel == "CONTAINS" && radiusMeters > 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		cLonStr := strconv.FormatFloat(cLon, 'f', -1, 64)
		cLatStr := strconv.FormatFloat(cLat, 'f', -1, 64)
		radStr := strconv.FormatFloat(radiusMeters, 'f', -1, 64)
		posWhere := t.evalGeoPointPredForField(gs.Field, nctx, func(latExpr, lonExpr string) string {
			return fmt.Sprintf("ST_Distance_Sphere(%s, %s, %s, %s) <= %s", lonExpr, latExpr, cLonStr, cLatStr, radStr)
		})
		if rel == "DISJOINT" {
			w := fmt.Sprintf("(%s AND NOT (%s))", t.compileExistsPredicate(gs.Field, nctx), posWhere)
			return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: scoreSQL}
		}
		return CompiledQuery{WhereSQL: posWhere, SafeWhereSQL: posWhere, ScoreSQL: scoreSQL}
	}

	if shapeType == "polygon" || shapeType == "multipolygon" {
		polys := extractGeoShapePolygons(gs.Shape["coordinates"], shapeType)
		if len(polys) > 0 {
			if rel == "CONTAINS" {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			posWhere := t.evalGeoPointPredForField(gs.Field, nctx, func(latExpr, lonExpr string) string {
				var polyPreds []string
				for _, poly := range polys {
					extCond := buildPointInPolygonSQL(latExpr, lonExpr, poly[0])
					if len(poly) == 1 {
						polyPreds = append(polyPreds, extCond)
					} else {
						var holeConds []string
						holeConds = append(holeConds, extCond)
						for _, hole := range poly[1:] {
							holeConds = append(holeConds, "NOT "+buildPointInPolygonSQL(latExpr, lonExpr, hole))
						}
						polyPreds = append(polyPreds, "("+strings.Join(holeConds, " AND ")+")")
					}
				}
				if len(polyPreds) == 1 {
					return polyPreds[0]
				}
				return "(" + strings.Join(polyPreds, " OR ") + ")"
			})
			if rel == "DISJOINT" {
				w := fmt.Sprintf("(%s AND NOT (%s))", t.compileExistsPredicate(gs.Field, nctx), posWhere)
				return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: scoreSQL}
			}
			return CompiledQuery{WhereSQL: posWhere, SafeWhereSQL: posWhere, ScoreSQL: scoreSQL}
		}
	}

	if shapeType == "envelope" {
		if arr, ok := gs.Shape["coordinates"].([]any); ok && len(arr) >= 2 {
			pt0, ok0 := arr[0].([]any)
			pt1, ok1 := arr[1].([]any)
			if ok0 && ok1 && len(pt0) >= 2 && len(pt1) >= 2 {
				lon0, okLon0 := toFloat64ForGeo(pt0[0])
				lat0, okLat0 := toFloat64ForGeo(pt0[1])
				lon1, okLon1 := toFloat64ForGeo(pt1[0])
				lat1, okLat1 := toFloat64ForGeo(pt1[1])
				if okLon0 && okLat0 && okLon1 && okLat1 {
					top, bottom := lat0, lat1
					if top < bottom {
						top, bottom = bottom, top
					}
					if rel == "CONTAINS" && (top != bottom || lon0 != lon1) {
						return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
					}
					bp := t.compileGeoBoundingBox(&esast.GeoBoundingBoxQuery{
						Field:  gs.Field,
						Top:    top,
						Bottom: bottom,
						Left:   lon0,
						Right:  lon1,
						Boost:  gs.Boost,
					}, scoring, nctx)
					if rel == "DISJOINT" {
						w := fmt.Sprintf("(%s AND NOT (%s))", t.compileExistsPredicate(gs.Field, nctx), bp.WhereSQL)
						return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: scoreSQL}
					}
					return bp
				}
			}
		}
	}

	if shapeType == "multipoint" {
		if arr, ok := gs.Shape["coordinates"].([]any); ok && len(arr) > 0 {
			var ptPreds []string
			for _, item := range arr {
				ptArr, okPt := item.([]any)
				if !okPt || len(ptArr) < 2 {
					continue
				}
				lon, ok1 := toFloat64ForGeo(ptArr[0])
				lat, ok2 := toFloat64ForGeo(ptArr[1])
				if !ok1 || !ok2 {
					continue
				}
				bp := t.compileGeoBoundingBox(&esast.GeoBoundingBoxQuery{
					Field:  gs.Field,
					Top:    lat,
					Bottom: lat,
					Left:   lon,
					Right:  lon,
				}, false, nctx)
				if bp.WhereSQL != "FALSE" {
					ptPreds = append(ptPreds, bp.WhereSQL)
				} else if rel == "CONTAINS" {
					return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
				}
			}
			if len(ptPreds) == 0 {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			joinOp := " OR "
			if rel == "CONTAINS" {
				joinOp = " AND "
			}
			combined := ptPreds[0]
			if len(ptPreds) > 1 {
				combined = "(" + strings.Join(ptPreds, joinOp) + ")"
			}
			if rel == "DISJOINT" {
				w := fmt.Sprintf("(%s AND NOT (%s))", t.compileExistsPredicate(gs.Field, nctx), combined)
				return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: scoreSQL}
			}
			return CompiledQuery{WhereSQL: combined, SafeWhereSQL: combined, ScoreSQL: scoreSQL}
		}
	}

	minLat, maxLat := 90.0, -90.0
	minLon, maxLon := 180.0, -180.0
	hasCoords := false
	var visitCoords func(v any)
	visitCoords = func(v any) {
		switch arr := v.(type) {
		case []any:
			if len(arr) >= 2 {
				if lon, ok1 := toFloat64ForGeo(arr[0]); ok1 {
					if lat, ok2 := toFloat64ForGeo(arr[1]); ok2 {
						hasCoords = true
						if lat < minLat {
							minLat = lat
						}
						if lat > maxLat {
							maxLat = lat
						}
						if lon < minLon {
							minLon = lon
						}
						if lon > maxLon {
							maxLon = lon
						}
						return
					}
				}
			}
			for _, child := range arr {
				visitCoords(child)
			}
		}
	}
	visitCoords(gs.Shape["coordinates"])
	if hasCoords {
		if rel == "CONTAINS" && (minLat != maxLat || minLon != maxLon) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		bp := t.compileGeoBoundingBox(&esast.GeoBoundingBoxQuery{
			Field:  gs.Field,
			Top:    maxLat,
			Bottom: minLat,
			Left:   minLon,
			Right:  maxLon,
			Boost:  gs.Boost,
		}, scoring, nctx)
		if rel == "DISJOINT" {
			w := fmt.Sprintf("(%s AND NOT (%s))", t.compileExistsPredicate(gs.Field, nctx), bp.WhereSQL)
			return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: scoreSQL}
		}
		return bp
	}
	w := t.compileExistsPredicate(gs.Field, nctx)
	return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: scoreSQL}
}

func toFloat64ForGeo(v any) (float64, bool) {
	switch nv := v.(type) {
	case float64:
		return nv, !math.IsNaN(nv) && !math.IsInf(nv, 0)
	case int:
		return float64(nv), true
	case int64:
		return float64(nv), true
	case json.Number:
		if f, err := nv.Float64(); err == nil {
			return f, !math.IsNaN(f) && !math.IsInf(f, 0)
		}
	}
	return 0, false
}

func (t *Transpiler) compileWrapperQuery(w *esast.WrapperQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if w == nil || (w.Decoded == nil && strings.TrimSpace(w.Query) == "") {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	var inner *esast.Query
	if w.Decoded != nil {
		inner = w.Decoded
	} else {
		qTrim := strings.TrimSpace(w.Query)
		decoded, err := base64.StdEncoding.DecodeString(qTrim)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(qTrim)
			if err != nil {
				if strings.HasPrefix(qTrim, "{") {
					decoded = []byte(qTrim)
				} else {
					if t.searchErr == nil {
						t.searchErr = fmt.Errorf("parsing_exception: [wrapper] failed to decode base64 query: %w", err)
					}
					return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
				}
			}
		}
		var parsed esast.Query
		if err := json.Unmarshal(decoded, &parsed); err != nil {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("wrapper query decoded payload is invalid query JSON: %w", err)
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		inner = &parsed
	}
	cp := t.CompileQuery(inner, inScoring, nctx)
	if w.Boost != nil && inScoring {
		if *w.Boost == 0 {
			cp.ScoreSQL = "0.0"
		} else if *w.Boost != 1.0 && cp.ScoreSQL != "0.0" {
			cp.ScoreSQL = fmt.Sprintf("(%s * %g)", cp.ScoreSQL, *w.Boost)
		}
	}
	return cp
}

func (t *Transpiler) compilePinnedQuery(p *esast.PinnedQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if p == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	var pinnedIDs []any
	for _, id := range p.EffectiveIDs() {
		if id != "" {
			pinnedIDs = append(pinnedIDs, id)
		}
	}
	pinnedPred := "FALSE"
	if len(pinnedIDs) > 0 {
		pinnedPred = t.compileTermsPredicateWithCI("_id", pinnedIDs, false, nctx)
	}
	orgCP := CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	if p.Organic != nil {
		orgCP = t.CompileQuery(p.Organic, inScoring, nctx)
	}
	var whereSQL, safeWhereSQL string
	switch {
	case pinnedPred == "FALSE":
		whereSQL = orgCP.WhereSQL
		safeWhereSQL = orgCP.EffectiveSafeWhere()
	case orgCP.WhereSQL == "FALSE":
		whereSQL = pinnedPred
		safeWhereSQL = pinnedPred
	case orgCP.WhereSQL == "1=1" || orgCP.WhereSQL == "TRUE":
		whereSQL = "TRUE"
		safeWhereSQL = "TRUE"
	default:
		whereSQL = fmt.Sprintf("(%s OR %s)", pinnedPred, orgCP.WhereSQL)
		safeWhereSQL = fmt.Sprintf("(%s OR %s)", pinnedPred, orgCP.EffectiveSafeWhere())
	}
	scoreSQL := "0.0"
	if inScoring {
		boost := 1.0
		if p.Boost != nil {
			boost = *p.Boost
		}
		if boost == 0 {
			scoreSQL = "0.0"
		} else if pinnedPred != "FALSE" {
			var rankCases []string
			for i, id := range pinnedIDs {
				rankWeight := 1000000.0 - float64(i)*1000.0
				if rankWeight < 1000.0 {
					rankWeight = 1000.0
				}
				rankCases = append(rankCases, fmt.Sprintf("WHEN `_id` = %s THEN %g", quoteValue(id), rankWeight*boost))
			}
			fallbackScore := orgCP.ScoreSQL
			if fallbackScore == "" {
				fallbackScore = "0.0"
			}
			scoreSQL = fmt.Sprintf("(CASE %s ELSE %s END)", strings.Join(rankCases, " "), fallbackScore)
		} else {
			scoreSQL = orgCP.ScoreSQL
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreSQL, UsesFulltextMatch: orgCP.UsesFulltextMatch}
}

func resolvePathInMLTMap(m map[string]any, path string) (any, bool) {
	if v, ok := m[path]; ok {
		return v, true
	}
	parts := strings.Split(path, ".")
	if len(parts) <= 1 {
		return nil, false
	}
	var cur any = m
	for _, p := range parts {
		cm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, exists := cm[p]
		if !exists {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func extractMLTLikeTexts(v any, fields []string) ([]string, []string) {
	var texts []string
	var excludedIDs []string
	seenIDs := make(map[string]bool)

	var appendValueTexts func(val any)
	appendValueTexts = func(val any) {
		switch tv := val.(type) {
		case string:
			if strings.TrimSpace(tv) != "" {
				texts = append(texts, tv)
			}
		case []string:
			for _, s := range tv {
				if strings.TrimSpace(s) != "" {
					texts = append(texts, s)
				}
			}
		case []any:
			for _, item := range tv {
				appendValueTexts(item)
			}
		case map[string]any:
			keys := sortedMapKeys(tv)
			for _, k := range keys {
				appendValueTexts(tv[k])
			}
		}
	}

	hasExplicitFields := len(fields) > 0 && (len(fields) != 1 || (fields[0] != "_all_text" && fields[0] != "*"))

	var collect func(item any)
	collect = func(item any) {
		switch lv := item.(type) {
		case string:
			if strings.TrimSpace(lv) != "" {
				texts = append(texts, lv)
			}
		case []string:
			for _, s := range lv {
				collect(s)
			}
		case []any:
			for _, sub := range lv {
				collect(sub)
			}
		case map[string]any:
			if rawID, hasID := lv["_id"]; hasID && rawID != nil {
				idStr := strings.TrimSpace(fmt.Sprintf("%v", rawID))
				if idStr != "" && !seenIDs[idStr] {
					seenIDs[idStr] = true
					excludedIDs = append(excludedIDs, idStr)
				}
			}
			var docMap map[string]any
			if dm, ok := lv["doc"].(map[string]any); ok {
				docMap = dm
			} else if sm, ok := lv["_source"].(map[string]any); ok {
				docMap = sm
			}
			if docMap != nil {
				itemFields := fields
				itemHasExplicit := hasExplicitFields
				if rawF, hasF := lv["fields"]; hasF && rawF != nil {
					var overrideFields []string
					switch fv := rawF.(type) {
					case []string:
						for _, s := range fv {
							if strings.TrimSpace(s) != "" {
								overrideFields = append(overrideFields, strings.TrimSpace(s))
							}
						}
					case []any:
						for _, elem := range fv {
							if s, ok := elem.(string); ok && strings.TrimSpace(s) != "" {
								overrideFields = append(overrideFields, strings.TrimSpace(s))
							}
						}
					case string:
						if strings.TrimSpace(fv) != "" {
							overrideFields = append(overrideFields, strings.TrimSpace(fv))
						}
					}
					if len(overrideFields) > 0 {
						itemFields = overrideFields
						itemHasExplicit = len(itemFields) > 0 && (len(itemFields) != 1 || (itemFields[0] != "_all_text" && itemFields[0] != "*"))
					}
				}
				if itemHasExplicit {
					for _, f := range itemFields {
						cleanF, _ := parseFieldBoost(f, 1.0)
						if fv, ok := resolvePathInMLTMap(docMap, cleanF); ok {
							appendValueTexts(fv)
						}
					}
				} else {
					appendValueTexts(docMap)
				}
			}
		}
	}
	collect(v)
	return texts, excludedIDs
}

func tokenizeMLTTextsWithFreq(texts []string, stopSet map[string]bool, minWordLen, maxWordLen, minTermFreq, maxQueryTerms int) []string {
	var ordered []string
	seen := make(map[string]bool)
	counts := make(map[string]int)
	for _, txt := range texts {
		for _, tok := range strings.Fields(txt) {
			lowerTok := strings.ToLower(tok)
			if stopSet[lowerTok] {
				continue
			}
			if minWordLen > 0 && len([]rune(lowerTok)) < minWordLen {
				continue
			}
			if maxWordLen > 0 && len([]rune(lowerTok)) > maxWordLen {
				continue
			}
			counts[lowerTok]++
			if !seen[lowerTok] {
				seen[lowerTok] = true
				ordered = append(ordered, tok)
			}
		}
	}
	var tokens []string
	for _, tok := range ordered {
		if minTermFreq > 1 && counts[strings.ToLower(tok)] < minTermFreq {
			continue
		}
		tokens = append(tokens, tok)
	}
	if maxQueryTerms > 0 && len(tokens) > maxQueryTerms {
		tokens = tokens[:maxQueryTerms]
	}
	return tokens
}

func tokenizeMLTTexts(texts []string, stopSet map[string]bool, minWordLen, maxWordLen int) []string {
	return tokenizeMLTTextsWithFreq(texts, stopSet, minWordLen, maxWordLen, 0, 0)
}

func (t *Transpiler) compileMoreLikeThis(mlt *esast.MoreLikeThisQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if mlt == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	fields := mlt.Fields
	if len(fields) == 0 {
		fields = []string{"_all_text"}
	}
	var combinedLike []any
	if mlt.Like != nil {
		combinedLike = append(combinedLike, mlt.Like)
	}
	if strings.TrimSpace(mlt.LikeText) != "" {
		combinedLike = append(combinedLike, mlt.LikeText)
	}
	for _, d := range mlt.Docs {
		combinedLike = append(combinedLike, d)
	}
	for _, id := range mlt.Ids {
		if strings.TrimSpace(id) != "" {
			combinedLike = append(combinedLike, map[string]any{"_id": id})
		}
	}
	texts, excludedIDs := extractMLTLikeTexts(combinedLike, mlt.Fields)
	stopSet := make(map[string]bool, len(mlt.StopWords))
	for _, sw := range mlt.StopWords {
		stopSet[strings.ToLower(sw)] = true
	}
	tokens := tokenizeMLTTextsWithFreq(texts, stopSet, mlt.MinWordLength, mlt.MaxWordLength, mlt.MinTermFreq, mlt.MaxQueryTerms)
	if len(tokens) == 0 && len(excludedIDs) > 0 && mlt.MinimumShouldMatch == nil {
		// Document reference only (e.g., {"_id": "1"} without inline "doc"):
		// if include is false, exclude the referenced _id; otherwise match all.
		if !mlt.Include {
			var quotedIDs []string
			for _, id := range excludedIDs {
				quotedIDs = append(quotedIDs, quoteStr(id))
			}
			w := fmt.Sprintf("`_id` NOT IN (%s)", strings.Join(quotedIDs, ", "))
			return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: "1.0"}
		}
		return CompiledQuery{WhereSQL: "TRUE", SafeWhereSQL: "TRUE", ScoreSQL: "1.0"}
	}
	if len(tokens) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	boost := 1.0
	if mlt.Boost != nil {
		boost = *mlt.Boost
	}
	if mlt.BoostTerms > 0 {
		boost *= mlt.BoostTerms
	}

	var whereSQL, safeWhereSQL string
	var scoreTerms []string
	usesFT := false

	if mlt.MinimumShouldMatch != nil && len(tokens) > 1 {
		var tokenConds, safeTokenConds []string
		for _, tok := range tokens {
			var fPreds, fSafePreds []string
			for _, f := range fields {
				cp := t.compileMatchField(f, tok, "or", boost, inScoring, nctx)
				if cp.WhereSQL != "FALSE" {
					fPreds = append(fPreds, cp.WhereSQL)
					fSafePreds = append(fSafePreds, cp.EffectiveSafeWhere())
					usesFT = usesFT || cp.UsesFulltextMatch
					if inScoring && cp.ScoreSQL != "0.0" {
						scoreTerms = append(scoreTerms, cp.ScoreSQL)
					}
				}
			}
			if len(fPreds) == 1 {
				tokenConds = append(tokenConds, fPreds[0])
				safeTokenConds = append(safeTokenConds, fSafePreds[0])
			} else if len(fPreds) > 1 {
				tokenConds = append(tokenConds, "("+strings.Join(fPreds, " OR ")+")")
				safeTokenConds = append(safeTokenConds, "("+strings.Join(fSafePreds, " OR ")+")")
			}
		}
		if len(tokenConds) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		minShould := parseMinShouldMatch(mlt.MinimumShouldMatch, len(tokenConds), true)
		if minShould > len(tokenConds) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if minShould <= 1 {
			if len(tokenConds) == 1 {
				whereSQL = tokenConds[0]
				safeWhereSQL = safeTokenConds[0]
			} else {
				whereSQL = "(" + strings.Join(tokenConds, " OR ") + ")"
				safeWhereSQL = "(" + strings.Join(safeTokenConds, " OR ") + ")"
			}
		} else if minShould == len(tokenConds) {
			whereSQL = "(" + strings.Join(tokenConds, " AND ") + ")"
			safeWhereSQL = "(" + strings.Join(safeTokenConds, " AND ") + ")"
		} else {
			var intCasts []string
			for _, sc := range safeTokenConds {
				intCasts = append(intCasts, fmt.Sprintf("CAST(COALESCE(%s, FALSE) AS INT)", sc))
			}
			msmCond := fmt.Sprintf("((%s) >= %d)", strings.Join(intCasts, " + "), minShould)
			whereSQL = fmt.Sprintf("((%s) AND %s)", strings.Join(tokenConds, " OR "), msmCond)
			safeWhereSQL = msmCond
		}
	} else {
		joined := strings.Join(tokens, " ")
		var fieldPreds, safePreds []string
		for _, f := range fields {
			cp := t.compileMatchField(f, joined, "or", boost, inScoring, nctx)
			if cp.WhereSQL != "FALSE" {
				fieldPreds = append(fieldPreds, cp.WhereSQL)
				safePreds = append(safePreds, cp.EffectiveSafeWhere())
				usesFT = usesFT || cp.UsesFulltextMatch
				if inScoring && cp.ScoreSQL != "0.0" {
					scoreTerms = append(scoreTerms, cp.ScoreSQL)
				}
			}
		}
		if len(fieldPreds) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if mlt.MinimumShouldMatch != nil && len(tokens) == 1 && parseMinShouldMatch(mlt.MinimumShouldMatch, 1, true) > 1 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		whereSQL = fieldPreds[0]
		safeWhereSQL = safePreds[0]
		if len(fieldPreds) > 1 {
			whereSQL = "(" + strings.Join(fieldPreds, " OR ") + ")"
			safeWhereSQL = "(" + strings.Join(safePreds, " OR ") + ")"
		}
	}

	if mlt.Unlike != nil {
		unlikeTexts, _ := extractMLTLikeTexts(mlt.Unlike, mlt.Fields)
		unlikeTokens := tokenizeMLTTexts(unlikeTexts, stopSet, mlt.MinWordLength, mlt.MaxWordLength)
		if len(unlikeTokens) > 0 {
			unlikeJoined := strings.Join(unlikeTokens, " ")
			var uPreds, uSafePreds []string
			for _, f := range fields {
				ucp := t.compileMatchField(f, unlikeJoined, "or", 1.0, false, nctx)
				if ucp.WhereSQL != "FALSE" {
					if ucp.UsesFulltextMatch || strings.Contains(ucp.WhereSQL, "MATCH_") {
						uPreds = append(uPreds, ucp.EffectiveSafeWhere())
					} else {
						uPreds = append(uPreds, ucp.WhereSQL)
					}
					uSafePreds = append(uSafePreds, ucp.EffectiveSafeWhere())
				}
			}
			if len(uPreds) > 0 {
				uCombined := uPreds[0]
				uSafeCombined := uSafePreds[0]
				if len(uPreds) > 1 {
					uCombined = "(" + strings.Join(uPreds, " OR ") + ")"
					uSafeCombined = "(" + strings.Join(uSafePreds, " OR ") + ")"
				}
				whereSQL = fmt.Sprintf("(%s AND NOT COALESCE(%s, FALSE))", whereSQL, uCombined)
				safeWhereSQL = fmt.Sprintf("(%s AND NOT COALESCE(%s, FALSE))", safeWhereSQL, uSafeCombined)
			}
		}
	}

	if !mlt.Include && len(excludedIDs) > 0 {
		var quotedIDs []string
		for _, id := range excludedIDs {
			quotedIDs = append(quotedIDs, quoteStr(id))
		}
		exclCond := fmt.Sprintf("`_id` NOT IN (%s)", strings.Join(quotedIDs, ", "))
		whereSQL = fmt.Sprintf("(%s AND %s)", whereSQL, exclCond)
		safeWhereSQL = fmt.Sprintf("(%s AND %s)", safeWhereSQL, exclCond)
	}

	scoreSQL := "0.0"
	if inScoring && boost != 0 {
		if len(scoreTerms) == 1 {
			scoreSQL = scoreTerms[0]
		} else if len(scoreTerms) > 1 {
			scoreSQL = "(" + strings.Join(scoreTerms, " + ") + ")"
		} else {
			scoreSQL = fmt.Sprintf("%g", boost)
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}
}

func (t *Transpiler) compileIntervalsQuery(iq map[string]esast.IntervalsRule, inScoring bool, nctx *nestedCtx) CompiledQuery {
	keys := sortedMapKeys(iq)
	var preds, safePreds, scores []string
	usesFT := false
	for _, field := range keys {
		rule := iq[field]
		cp := t.compileIntervalsRule(field, rule, inScoring, nctx)
		preds = append(preds, cp.WhereSQL)
		safePreds = append(safePreds, cp.EffectiveSafeWhere())
		usesFT = usesFT || cp.UsesFulltextMatch
		if inScoring && cp.ScoreSQL != "0.0" {
			scores = append(scores, cp.ScoreSQL)
		}
	}
	if len(preds) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	whereSQL := preds[0]
	safeWhereSQL := safePreds[0]
	if len(preds) > 1 {
		whereSQL = "(" + strings.Join(preds, " AND ") + ")"
		safeWhereSQL = "(" + strings.Join(safePreds, " AND ") + ")"
	}
	scoreSQL := "0.0"
	if inScoring {
		if len(scores) == 1 {
			scoreSQL = scores[0]
		} else if len(scores) > 1 {
			scoreSQL = "(" + strings.Join(scores, " + ") + ")"
		} else if whereSQL != "FALSE" {
			scoreSQL = "1.0"
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}
}

func (t *Transpiler) compileIntervalsRule(field string, rule esast.IntervalsRule, inScoring bool, nctx *nestedCtx) CompiledQuery {
	boost := 1.0
	if rule.Boost != nil {
		boost = *rule.Boost
	}
	var cp CompiledQuery
	switch {
	case rule.Match != nil:
		targetField := field
		if strings.TrimSpace(rule.Match.UseField) != "" {
			targetField = strings.TrimSpace(rule.Match.UseField)
		}
		op := "and"
		if !rule.Match.Ordered && rule.Match.MaxGaps != nil && *rule.Match.MaxGaps != 0 {
			op = "or"
		}
		if rule.Match.Ordered && (rule.Match.MaxGaps == nil || *rule.Match.MaxGaps >= 0) {
			slop := 0
			if rule.Match.MaxGaps != nil && *rule.Match.MaxGaps > 0 {
				slop = *rule.Match.MaxGaps
			}
			cp = t.compileMatchPhraseField(targetField, rule.Match.Query, slop, boost, false, inScoring, nctx)
		} else {
			cp = t.compileMatchField(targetField, rule.Match.Query, op, boost, inScoring, nctx)
		}
		if rule.Match.Filter != nil {
			cp = t.applyIntervalsFilter(field, cp, rule.Match.Filter, inScoring, nctx)
		}
	case rule.Prefix != nil:
		targetField := field
		if strings.TrimSpace(rule.Prefix.UseField) != "" {
			targetField = strings.TrimSpace(rule.Prefix.UseField)
		}
		cp = t.compileMatchPhraseField(targetField, rule.Prefix.Prefix, 0, boost, true, inScoring, nctx)
	case rule.Wildcard != nil:
		targetField := field
		if strings.TrimSpace(rule.Wildcard.UseField) != "" {
			targetField = strings.TrimSpace(rule.Wildcard.UseField)
		}
		w := t.compileWildcardPredicate(targetField, rule.Wildcard.Pattern, true, nctx)
		sc := "0.0"
		if inScoring && boost != 0 && w != "FALSE" {
			sc = fmt.Sprintf("%g", boost)
		}
		cp = CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: sc}
	case rule.Fuzzy != nil:
		targetField := field
		if strings.TrimSpace(rule.Fuzzy.UseField) != "" {
			targetField = strings.TrimSpace(rule.Fuzzy.UseField)
		}
		fuzz := any("AUTO")
		if rule.Fuzzy.Fuzziness != nil {
			fuzz = rule.Fuzzy.Fuzziness
		}
		cp = t.compileFuzzyFieldWithOpts(targetField, rule.Fuzzy.Term, "or", fuzz, false, rule.Fuzzy.PrefixLength, rule.Fuzzy.Transpositions, boost, inScoring, nctx)
	case rule.AllOf != nil:
		var subPreds, safePreds []string
		usesFT := false
		for _, sub := range rule.AllOf.Intervals {
			scp := t.compileIntervalsRule(field, sub, false, nctx)
			subPreds = append(subPreds, scp.WhereSQL)
			safePreds = append(safePreds, scp.EffectiveSafeWhere())
			usesFT = usesFT || scp.UsesFulltextMatch
		}
		w, sw := "FALSE", "FALSE"
		if len(subPreds) == 1 {
			w, sw = subPreds[0], safePreds[0]
		} else if len(subPreds) > 1 {
			w = "(" + strings.Join(subPreds, " AND ") + ")"
			sw = "(" + strings.Join(safePreds, " AND ") + ")"
		}
		sc := "0.0"
		if inScoring && boost != 0 && w != "FALSE" {
			sc = fmt.Sprintf("%g", boost)
		}
		cp = CompiledQuery{WhereSQL: w, SafeWhereSQL: sw, ScoreSQL: sc, UsesFulltextMatch: usesFT}
		if rule.AllOf.Filter != nil {
			cp = t.applyIntervalsFilter(field, cp, rule.AllOf.Filter, inScoring, nctx)
		}
	case rule.AnyOf != nil:
		var subPreds, safePreds []string
		usesFT := false
		for _, sub := range rule.AnyOf.Intervals {
			scp := t.compileIntervalsRule(field, sub, false, nctx)
			if scp.WhereSQL != "FALSE" {
				subPreds = append(subPreds, scp.WhereSQL)
				safePreds = append(safePreds, scp.EffectiveSafeWhere())
				usesFT = usesFT || scp.UsesFulltextMatch
			}
		}
		w, sw := "FALSE", "FALSE"
		if len(subPreds) == 1 {
			w, sw = subPreds[0], safePreds[0]
		} else if len(subPreds) > 1 {
			w = "(" + strings.Join(subPreds, " OR ") + ")"
			sw = "(" + strings.Join(safePreds, " OR ") + ")"
		}
		sc := "0.0"
		if inScoring && boost != 0 && w != "FALSE" {
			sc = fmt.Sprintf("%g", boost)
		}
		cp = CompiledQuery{WhereSQL: w, SafeWhereSQL: sw, ScoreSQL: sc, UsesFulltextMatch: usesFT}
		if rule.AnyOf.Filter != nil {
			cp = t.applyIntervalsFilter(field, cp, rule.AnyOf.Filter, inScoring, nctx)
		}
	default:
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	return cp
}

func (t *Transpiler) applyIntervalsFilter(field string, base CompiledQuery, f *esast.IntervalsFilter, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if f == nil || base.WhereSQL == "FALSE" {
		return base
	}
	conds := []string{base.WhereSQL}
	safeConds := []string{base.EffectiveSafeWhere()}
	for _, posRule := range []*esast.IntervalsRule{f.Containing, f.ContainedBy, f.Overlapping, f.After, f.Before} {
		if posRule != nil {
			p := t.compileIntervalsRule(field, *posRule, false, nctx)
			conds = append(conds, p.WhereSQL)
			safeConds = append(safeConds, p.EffectiveSafeWhere())
			base.UsesFulltextMatch = base.UsesFulltextMatch || p.UsesFulltextMatch
		}
	}
	for _, negRule := range []*esast.IntervalsRule{f.NotContaining, f.NotContainedBy, f.NotOverlapping} {
		if negRule != nil {
			p := t.compileIntervalsRule(field, *negRule, false, nctx)
			if p.WhereSQL != "FALSE" {
				conds = append(conds, fmt.Sprintf("NOT (%s)", p.WhereSQL))
				safeConds = append(safeConds, fmt.Sprintf("NOT (%s)", p.EffectiveSafeWhere()))
				base.UsesFulltextMatch = base.UsesFulltextMatch || p.UsesFulltextMatch
			}
		}
	}
	if len(conds) > 1 {
		base.WhereSQL = "(" + strings.Join(conds, " AND ") + ")"
		base.SafeWhereSQL = "(" + strings.Join(safeConds, " AND ") + ")"
	}
	return base
}

func (t *Transpiler) compileSpanQuery(q *esast.Query, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if q == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	switch {
	case len(q.SpanTerm) > 0:
		keys := sortedMapKeys(q.SpanTerm)
		var preds, safePreds, scores []string
		usesFT := false
		for _, field := range keys {
			st := q.SpanTerm[field]
			boost := st.Boost
			_, b := t.resolveFieldInNestedCtx(field, false, nctx)
			var w, sw string
			if b.ESType == "text" || b.ESType == "match_only_text" || b.ESType == "search_as_you_type" || b.ESType == "annotated-text" {
				mc := t.compileMatchField(field, fmt.Sprintf("%v", st.Value), "and", boost, false, nctx)
				w = mc.WhereSQL
				sw = mc.EffectiveSafeWhere()
				usesFT = usesFT || mc.UsesFulltextMatch
			} else {
				w = t.compileTermPredicate(field, st.Value, st.CaseInsensitive, nctx)
				sw = w
			}
			preds = append(preds, w)
			safePreds = append(safePreds, sw)
			if inScoring && boost != 0 && w != "FALSE" {
				scores = append(scores, fmt.Sprintf("%g", boost))
			}
		}
		whereSQL := strings.Join(preds, " AND ")
		safeWhereSQL := strings.Join(safePreds, " AND ")
		scoreSQL := "0.0"
		if inScoring && len(scores) > 0 {
			scoreSQL = strings.Join(scores, " + ")
		}
		return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: safeWhereSQL, ScoreSQL: scoreSQL, UsesFulltextMatch: usesFT}

	case q.SpanNear != nil:
		if len(q.SpanNear.Clauses) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		boost := 1.0
		if q.SpanNear.Boost != nil {
			boost = *q.SpanNear.Boost
		}
		commonField := ""
		allSameFieldTerms := true
		var termStrs []string
		for _, cl := range q.SpanNear.Clauses {
			if len(cl.SpanTerm) != 1 {
				allSameFieldTerms = false
				break
			}
			for f, st := range cl.SpanTerm {
				if f == "" || (commonField != "" && f != commonField) {
					allSameFieldTerms = false
					break
				}
				commonField = f
				termStrs = append(termStrs, fmt.Sprintf("%v", st.Value))
			}
			if !allSameFieldTerms {
				break
			}
		}
		if allSameFieldTerms && commonField != "" && len(termStrs) > 0 {
			slop := q.SpanNear.Slop
			if q.SpanNear.InOrder != nil && !*q.SpanNear.InOrder && slop == 0 {
				slop = 1
			}
			cp := t.compileMatchPhraseField(commonField, strings.Join(termStrs, " "), slop, boost, false, inScoring, nctx)
			if q.SpanNear.Boost != nil && *q.SpanNear.Boost == 0 {
				cp.ScoreSQL = "0.0"
			}
			return cp
		}
		var preds, safePreds []string
		usesFT := false
		for _, cl := range q.SpanNear.Clauses {
			clCopy := cl
			cp := t.compileSpanQuery(&clCopy, false, nctx)
			preds = append(preds, cp.WhereSQL)
			safePreds = append(safePreds, cp.EffectiveSafeWhere())
			usesFT = usesFT || cp.UsesFulltextMatch
		}
		w := "(" + strings.Join(preds, " AND ") + ")"
		sw := "(" + strings.Join(safePreds, " AND ") + ")"
		if len(preds) == 1 {
			w, sw = preds[0], safePreds[0]
		}
		sc := "0.0"
		if inScoring && boost != 0 && w != "FALSE" {
			sc = fmt.Sprintf("%g", boost)
		}
		return CompiledQuery{WhereSQL: w, SafeWhereSQL: sw, ScoreSQL: sc, UsesFulltextMatch: usesFT}

	case q.SpanOr != nil:
		var preds, safePreds []string
		usesFT := false
		for _, cl := range q.SpanOr.Clauses {
			clCopy := cl
			cp := t.compileSpanQuery(&clCopy, false, nctx)
			if cp.WhereSQL != "FALSE" {
				preds = append(preds, cp.WhereSQL)
				safePreds = append(safePreds, cp.EffectiveSafeWhere())
				usesFT = usesFT || cp.UsesFulltextMatch
			}
		}
		if len(preds) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		w := "(" + strings.Join(preds, " OR ") + ")"
		sw := "(" + strings.Join(safePreds, " OR ") + ")"
		if len(preds) == 1 {
			w, sw = preds[0], safePreds[0]
		}
		boost := 1.0
		if q.SpanOr.Boost != nil {
			boost = *q.SpanOr.Boost
		}
		sc := "0.0"
		if inScoring && boost != 0 && w != "FALSE" {
			sc = fmt.Sprintf("%g", boost)
		}
		return CompiledQuery{WhereSQL: w, SafeWhereSQL: sw, ScoreSQL: sc, UsesFulltextMatch: usesFT}

	case q.SpanNot != nil:
		if q.SpanNot.Include == nil || q.SpanNot.Exclude == nil {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		inc := t.compileSpanQuery(q.SpanNot.Include, false, nctx)
		exc := t.compileSpanQuery(q.SpanNot.Exclude, false, nctx)
		if inc.WhereSQL == "FALSE" {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		w, sw := inc.WhereSQL, inc.EffectiveSafeWhere()
		if exc.WhereSQL != "FALSE" {
			w = fmt.Sprintf("(%s AND NOT COALESCE(%s, FALSE))", inc.WhereSQL, exc.WhereSQL)
			sw = fmt.Sprintf("(%s AND NOT COALESCE(%s, FALSE))", inc.EffectiveSafeWhere(), exc.EffectiveSafeWhere())
		}
		boost := 1.0
		if q.SpanNot.Boost != nil {
			boost = *q.SpanNot.Boost
		}
		sc := "0.0"
		if inScoring && boost != 0 {
			sc = fmt.Sprintf("%g", boost)
		}
		return CompiledQuery{WhereSQL: w, SafeWhereSQL: sw, ScoreSQL: sc, UsesFulltextMatch: inc.UsesFulltextMatch || exc.UsesFulltextMatch}

	case q.SpanFirst != nil:
		if q.SpanFirst.Match == nil {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		cp := t.compileSpanQuery(q.SpanFirst.Match, inScoring, nctx)
		if q.SpanFirst.Boost != nil && inScoring {
			if *q.SpanFirst.Boost == 0 {
				cp.ScoreSQL = "0.0"
			} else {
				cp.ScoreSQL = fmt.Sprintf("%g", *q.SpanFirst.Boost)
			}
		}
		return cp

	case q.SpanMulti != nil:
		if q.SpanMulti.Match == nil {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		cp := t.CompileQuery(q.SpanMulti.Match, inScoring, nctx)
		if q.SpanMulti.Boost != nil && inScoring {
			if *q.SpanMulti.Boost == 0 {
				cp.ScoreSQL = "0.0"
			} else {
				cp.ScoreSQL = fmt.Sprintf("%g", *q.SpanMulti.Boost)
			}
		}
		return cp

	case q.SpanContaining != nil:
		if q.SpanContaining.Big == nil || q.SpanContaining.Little == nil {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		big := t.compileSpanQuery(q.SpanContaining.Big, false, nctx)
		lit := t.compileSpanQuery(q.SpanContaining.Little, false, nctx)
		if big.WhereSQL == "FALSE" || lit.WhereSQL == "FALSE" {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		w := fmt.Sprintf("(%s AND %s)", big.WhereSQL, lit.WhereSQL)
		sw := fmt.Sprintf("(%s AND %s)", big.EffectiveSafeWhere(), lit.EffectiveSafeWhere())
		boost := 1.0
		if q.SpanContaining.Boost != nil {
			boost = *q.SpanContaining.Boost
		}
		sc := "0.0"
		if inScoring && boost != 0 {
			sc = fmt.Sprintf("%g", boost)
		}
		return CompiledQuery{WhereSQL: w, SafeWhereSQL: sw, ScoreSQL: sc, UsesFulltextMatch: big.UsesFulltextMatch || lit.UsesFulltextMatch}

	case q.SpanWithin != nil:
		if q.SpanWithin.Big == nil || q.SpanWithin.Little == nil {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		big := t.compileSpanQuery(q.SpanWithin.Big, false, nctx)
		lit := t.compileSpanQuery(q.SpanWithin.Little, false, nctx)
		if big.WhereSQL == "FALSE" || lit.WhereSQL == "FALSE" {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		w := fmt.Sprintf("(%s AND %s)", big.WhereSQL, lit.WhereSQL)
		sw := fmt.Sprintf("(%s AND %s)", big.EffectiveSafeWhere(), lit.EffectiveSafeWhere())
		boost := 1.0
		if q.SpanWithin.Boost != nil {
			boost = *q.SpanWithin.Boost
		}
		sc := "0.0"
		if inScoring && boost != 0 {
			sc = fmt.Sprintf("%g", boost)
		}
		return CompiledQuery{WhereSQL: w, SafeWhereSQL: sw, ScoreSQL: sc, UsesFulltextMatch: big.UsesFulltextMatch || lit.UsesFulltextMatch}

	case q.FieldMaskingSpan != nil:
		if q.FieldMaskingSpan.Query == nil {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		return t.compileSpanQuery(q.FieldMaskingSpan.Query, inScoring, nctx)
	}
	return t.CompileQuery(q, inScoring, nctx)
}

func (t *Transpiler) compileRankFeature(rf *esast.RankFeatureQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if rf == nil || strings.TrimSpace(rf.Field) == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	field, b := t.resolveFieldInNestedCtx(rf.Field, false, nctx)
	if !t.checkFieldSearchable(field, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if t.Schema != nil && len(t.Schema.Fields) > 0 && b.ESType != "" && b.ESType != "rank_feature" && b.ESType != "rank_features" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: [rank_feature] query only works on [rank_feature] or [rank_features] fields, not [%s]", b.ESType)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	col := t.sqlTypedColumnRef(field, 1.0, false, nctx)
	whereSQL := fmt.Sprintf("(%s IS NOT NULL AND %s > 0)", col, col)
	scoreSQL := "0.0"
	if inScoring {
		boost := 1.0
		if rf.Boost != nil {
			boost = *rf.Boost
		}
		if boost != 0 {
			numExpr := fmt.Sprintf("GREATEST(COALESCE(CAST(%s AS DOUBLE), 0.0), 0.0)", col)
			switch {
			case rf.Saturation != nil:
				pivot := 1.0
				if p, ok := toFloat64ForGeo(rf.Saturation["pivot"]); ok && p > 0 {
					pivot = p
				}
				scoreSQL = fmt.Sprintf("(%g * (%s / (%s + %g)))", boost, numExpr, numExpr, pivot)
			case rf.Log != nil:
				sf := 1.0
				if s, ok := toFloat64ForGeo(rf.Log["scaling_factor"]); ok && s > 0 {
					sf = s
				}
				scoreSQL = fmt.Sprintf("(%g * LN(%g + %s))", boost, sf, numExpr)
			case rf.Sigmoid != nil:
				pivot := 1.0
				if p, ok := toFloat64ForGeo(rf.Sigmoid["pivot"]); ok && p > 0 {
					pivot = p
				}
				exp := 1.0
				if e, ok := toFloat64ForGeo(rf.Sigmoid["exponent"]); ok && e > 0 {
					exp = e
				}
				scoreSQL = fmt.Sprintf("(%g * (POW(%s, %g) / (POW(%s, %g) + POW(%g, %g))))", boost, numExpr, exp, numExpr, exp, pivot, exp)
			case rf.Linear != nil:
				scoreSQL = fmt.Sprintf("(%g * %s)", boost, numExpr)
			default:
				scoreSQL = fmt.Sprintf("(%g * (%s / (%s + 1.0)))", boost, numExpr, numExpr)
			}
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: whereSQL, ScoreSQL: scoreSQL}
}

func (t *Transpiler) compileDistanceFeature(df *esast.DistanceFeatureQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if df == nil || strings.TrimSpace(df.Field) == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	field, b := t.resolveFieldInNestedCtx(df.Field, false, nctx)
	if !t.checkFieldSearchable(field, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if t.Schema != nil && len(t.Schema.Fields) > 0 && b.ESType != "" && b.ESType != "date" && b.ESType != "date_nanos" && b.ESType != "geo_point" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: [distance_feature] query only works on [date], [date_nanos], or [geo_point] fields, not [%s]", b.ESType)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	whereSQL := t.compileExistsPredicate(df.Field, nctx)
	scoreSQL := "0.0"
	if inScoring {
		boost := 1.0
		if df.Boost != nil {
			boost = *df.Boost
		}
		if boost != 0 {
			isGeo := b.ESType == "geo_point"
			if !isGeo && b.ESType == "" {
				if _, _, errG := esast.ParseGeoPoint(df.Origin); errG == nil {
					if _, _, errP := esast.ParseGeoDistanceMeters(df.Pivot); errP == nil {
						isGeo = true
					}
				}
			}
			if isGeo {
				if origLat, origLon, err := esast.ParseGeoPoint(df.Origin); err == nil {
					_, pivotM, err2 := esast.ParseGeoDistanceMeters(df.Pivot)
					if err2 != nil || pivotM <= 0 {
						pivotM = 1000.0
					}
					tLonStr := strconv.FormatFloat(origLon, 'f', -1, 64)
					tLatStr := strconv.FormatFloat(origLat, 'f', -1, 64)
					var distExpr string
					if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(field, nctx.nestedPath+".")) {
						elemExpr := t.sqlColumnRef(field, true, nctx)
						latExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
						lonExpr := fmt.Sprintf("CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
						distExpr = fmt.Sprintf("ST_Distance_Sphere(%s, %s, %s, %s)", lonExpr, latExpr, tLonStr, tLatStr)
					} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
						arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
						distExpr = fmt.Sprintf("array_min(array_map(_x -> ST_Distance_Sphere(CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE), CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE), %s, %s), %s))", tLonStr, tLatStr, arrCol)
					} else {
						latExpr, lonExpr, _ := t.extractGeoPointExprs(field, b)
						distExpr = fmt.Sprintf("ST_Distance_Sphere(%s, %s, %s, %s)", lonExpr, latExpr, tLonStr, tLatStr)
					}
					scoreSQL = fmt.Sprintf("(%g * (%g / (%g + GREATEST(%s, 0.0))))", boost, pivotM, pivotM, distExpr)
					return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: whereSQL, ScoreSQL: scoreSQL}
				}
			}
			now := time.Now().UTC()
			originMs := float64(now.UnixMilli())
			switch ov := df.Origin.(type) {
			case string:
				if ms, ok := schema.ParseESDateWithFormatToEpochMillis(ov, b.Format, now); ok {
					originMs = float64(ms)
				} else if f, err := strconv.ParseFloat(strings.TrimSpace(ov), 64); err == nil {
					if b.ESType == "date_nanos" {
						if niv, okN := normalizeDateNanosValue(b.ESType, int64(f)).(int64); okN {
							f = float64(niv)
						}
					}
					originMs = f
				}
			case float64:
				if b.ESType == "date_nanos" {
					if niv, okN := normalizeDateNanosValue(b.ESType, int64(ov)).(int64); okN {
						ov = float64(niv)
					}
				}
				originMs = ov
			case int64:
				if b.ESType == "date_nanos" {
					if niv, okN := normalizeDateNanosValue(b.ESType, ov).(int64); okN {
						ov = niv
					}
				}
				originMs = float64(ov)
			case int:
				iv := int64(ov)
				if b.ESType == "date_nanos" {
					if niv, okN := normalizeDateNanosValue(b.ESType, iv).(int64); okN {
						iv = niv
					}
				}
				originMs = float64(iv)
			case json.Number:
				if f, err := ov.Float64(); err == nil {
					if b.ESType == "date_nanos" {
						if niv, okN := normalizeDateNanosValue(b.ESType, int64(f)).(int64); okN {
							f = float64(niv)
						}
					}
					originMs = f
				}
			}
			pivotVal := parseDurationOrDistancePivotMs(df.Pivot)
			if pivotVal <= 0 {
				pivotVal = 1.0
			}
			col := t.sqlNumericColumnRef(field, nctx)
			distExpr := fmt.Sprintf("ABS(COALESCE(%s, %g) - %g)", col, originMs, originMs)
			scoreSQL = fmt.Sprintf("(%g * (%g / (%g + %s)))", boost, pivotVal, pivotVal, distExpr)
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: whereSQL, ScoreSQL: scoreSQL}
}

func parseDurationOrDistancePivotMs(v any) float64 {
	switch pv := v.(type) {
	case float64:
		return pv
	case int:
		return float64(pv)
	case int64:
		return float64(pv)
	case json.Number:
		if f, err := pv.Float64(); err == nil {
			return f
		}
	case string:
		s := strings.TrimSpace(strings.ToLower(pv))
		for _, unit := range []struct {
			suffix string
			mult   float64
		}{
			{"ms", 1},
			{"nanos", 1e-6},
			{"micros", 1e-3},
			{"s", 1000},
			{"m", 60 * 1000},
			{"h", 3600 * 1000},
			{"d", 86400 * 1000},
			{"w", 7 * 86400 * 1000},
		} {
			if strings.HasSuffix(s, unit.suffix) {
				numStr := strings.TrimSpace(strings.TrimSuffix(s, unit.suffix))
				if f, err := strconv.ParseFloat(numStr, 64); err == nil {
					return f * unit.mult
				}
			}
		}
		if _, m, err := esast.ParseGeoDistanceMeters(s); err == nil {
			return m
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return 1.0
}

func joinFieldHasChild(fb schema.FieldBinding, childType string) bool {
	if len(fb.Relations) == 0 {
		return true
	}
	for _, v := range fb.Relations {
		switch cv := v.(type) {
		case string:
			if cv == childType {
				return true
			}
		case []string:
			for _, s := range cv {
				if s == childType {
					return true
				}
			}
		case []any:
			for _, elem := range cv {
				if s, ok := elem.(string); ok && s == childType {
					return true
				}
			}
		}
	}
	return false
}

func joinFieldHasParent(fb schema.FieldBinding, parentType string) bool {
	if len(fb.Relations) == 0 {
		return true
	}
	_, ok := fb.Relations[parentType]
	return ok
}

func joinFieldDocExpr(jf string) string {
	parts := strings.Split(jf, ".")
	var base strings.Builder
	base.WriteString("`_doc`")
	for _, p := range parts {
		base.WriteString("['" + strings.ReplaceAll(p, `'`, `''`) + "']")
	}
	return base.String()
}

func joinFieldParentRoleConds(jf string, fb schema.FieldBinding, childType string) []string {
	if len(fb.Relations) == 0 {
		return nil
	}
	baseExpr := joinFieldDocExpr(jf)
	var parentNames []string
	for pName, v := range fb.Relations {
		matched := false
		switch cv := v.(type) {
		case string:
			matched = cv == childType
		case []string:
			for _, s := range cv {
				if s == childType {
					matched = true
					break
				}
			}
		case []any:
			for _, elem := range cv {
				if s, ok := elem.(string); ok && s == childType {
					matched = true
					break
				}
			}
		}
		if matched {
			parentNames = append(parentNames, pName)
		}
	}
	sort.Strings(parentNames)
	var conds []string
	for _, pName := range parentNames {
		qName := quoteStr(pName)
		conds = append(conds, fmt.Sprintf("(CAST(%s AS STRING) = %s OR CAST(%s['name'] AS STRING) = %s)", baseExpr, qName, baseExpr, qName))
	}
	return conds
}

func joinFieldChildRoleConds(jf string, fb schema.FieldBinding, parentType string) []string {
	if len(fb.Relations) == 0 {
		return nil
	}
	v, ok := fb.Relations[parentType]
	if !ok {
		return nil
	}
	baseExpr := joinFieldDocExpr(jf)
	var childNames []string
	switch cv := v.(type) {
	case string:
		if cv != "" {
			childNames = append(childNames, cv)
		}
	case []string:
		childNames = append(childNames, cv...)
	case []any:
		for _, elem := range cv {
			if s, ok := elem.(string); ok && s != "" {
				childNames = append(childNames, s)
			}
		}
	}
	sort.Strings(childNames)
	var conds []string
	for _, cName := range childNames {
		qName := quoteStr(cName)
		conds = append(conds, fmt.Sprintf("(CAST(%s['name'] AS STRING) = %s AND %s['parent'] IS NOT NULL)", baseExpr, qName, baseExpr))
	}
	return conds
}

func (t *Transpiler) compileHasChild(hc *esast.HasChildQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if hc == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if (hc.MinChildren != nil && hc.MaxChildren != nil && *hc.MinChildren > *hc.MaxChildren) || (hc.MaxChildren != nil && *hc.MaxChildren <= 0) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	var roleConds []string
	if t.Schema != nil && len(t.Schema.Fields) > 0 {
		hasMatchingJoin := false
		var joinFieldNames []string
		for fname, fb := range t.Schema.Fields {
			if fb.ESType == "join" && joinFieldHasChild(fb, hc.Type) {
				hasMatchingJoin = true
				joinFieldNames = append(joinFieldNames, fname)
			}
		}
		if !hasMatchingJoin {
			if !hc.IgnoreUnmapped && t.searchErr == nil {
				t.searchErr = fmt.Errorf("[has_child] no join field has been configured for type [%s]", hc.Type)
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if hc.Query.Ids == nil {
			sort.Strings(joinFieldNames)
			for _, jf := range joinFieldNames {
				roleConds = append(roleConds, joinFieldParentRoleConds(jf, t.Schema.Fields[jf], hc.Type)...)
			}
		}
	}
	cp := t.CompileQuery(&hc.Query, inScoring, nctx)
	if len(roleConds) > 0 && cp.WhereSQL != "FALSE" {
		roleSQL := strings.Join(roleConds, " OR ")
		cp.WhereSQL = fmt.Sprintf("(%s AND (%s))", cp.WhereSQL, roleSQL)
		cp.SafeWhereSQL = fmt.Sprintf("(%s AND (%s))", cp.EffectiveSafeWhere(), roleSQL)
	}
	if hc.Boost != nil && inScoring {
		if *hc.Boost == 0 || strings.EqualFold(hc.ScoreMode, "none") {
			cp.ScoreSQL = "0.0"
		} else if *hc.Boost != 1.0 && cp.ScoreSQL != "0.0" {
			cp.ScoreSQL = fmt.Sprintf("(%s * %g)", cp.ScoreSQL, *hc.Boost)
		}
	} else if inScoring && strings.EqualFold(hc.ScoreMode, "none") {
		cp.ScoreSQL = "0.0"
	}
	return cp
}

func (t *Transpiler) compileHasParent(hp *esast.HasParentQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if hp == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	var roleConds []string
	if t.Schema != nil && len(t.Schema.Fields) > 0 {
		hasMatchingJoin := false
		var joinFieldNames []string
		for fname, fb := range t.Schema.Fields {
			if fb.ESType == "join" && joinFieldHasParent(fb, hp.ParentType) {
				hasMatchingJoin = true
				joinFieldNames = append(joinFieldNames, fname)
			}
		}
		if !hasMatchingJoin {
			if !hp.IgnoreUnmapped && t.searchErr == nil {
				t.searchErr = fmt.Errorf("[has_parent] no join field has been configured for parent_type [%s]", hp.ParentType)
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if hp.Query.Ids == nil {
			sort.Strings(joinFieldNames)
			for _, jf := range joinFieldNames {
				roleConds = append(roleConds, joinFieldChildRoleConds(jf, t.Schema.Fields[jf], hp.ParentType)...)
			}
		}
	}
	scoreOn := hp.Score != nil && *hp.Score && inScoring
	cp := t.CompileQuery(&hp.Query, scoreOn, nctx)
	if len(roleConds) > 0 && cp.WhereSQL != "FALSE" {
		roleSQL := strings.Join(roleConds, " OR ")
		cp.WhereSQL = fmt.Sprintf("(%s AND (%s))", cp.WhereSQL, roleSQL)
		cp.SafeWhereSQL = fmt.Sprintf("(%s AND (%s))", cp.EffectiveSafeWhere(), roleSQL)
	}
	if !scoreOn {
		cp.ScoreSQL = "0.0"
	} else if hp.Boost != nil {
		if *hp.Boost == 0 {
			cp.ScoreSQL = "0.0"
		} else if *hp.Boost != 1.0 && cp.ScoreSQL != "0.0" {
			cp.ScoreSQL = fmt.Sprintf("(%s * %g)", cp.ScoreSQL, *hp.Boost)
		}
	}
	return cp
}

func (t *Transpiler) compileParentID(pid *esast.ParentIDQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if pid == nil || strings.TrimSpace(pid.Type) == "" || pid.ID == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	parentIDStr := fmt.Sprintf("%v", pid.ID)
	var joinFields []string
	if t.Schema != nil {
		for fname, fb := range t.Schema.Fields {
			if fb.ESType == "join" && joinFieldHasChild(fb, pid.Type) {
				joinFields = append(joinFields, fname)
			}
		}
		sort.Strings(joinFields)
		if len(t.Schema.Fields) > 0 && len(joinFields) == 0 {
			if !pid.IgnoreUnmapped && t.searchErr == nil {
				t.searchErr = fmt.Errorf("[parent_id] no join field has been configured for type [%s]", pid.Type)
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
	}
	var disjuncts []string
	for _, jf := range joinFields {
		parts := strings.Split(jf, ".")
		var base strings.Builder
		base.WriteString("`_doc`")
		for _, p := range parts {
			base.WriteString("['" + strings.ReplaceAll(p, `'`, `''`) + "']")
		}
		baseExpr := base.String()
		disjuncts = append(disjuncts, fmt.Sprintf("(CAST(%s['name'] AS STRING) = %s AND CAST(%s['parent'] AS STRING) = %s)",
			baseExpr, quoteStr(pid.Type), baseExpr, quoteStr(parentIDStr)))
	}
	if len(joinFields) == 0 {
		disjuncts = append(disjuncts, fmt.Sprintf("(`_routing` = %s)", quoteStr(parentIDStr)))
	}
	whereSQL := "(" + strings.Join(disjuncts, " OR ") + ")"
	scoreSQL := "0.0"
	if inScoring {
		boost := 1.0
		if pid.Boost != nil {
			boost = *pid.Boost
		}
		if boost != 0 {
			scoreSQL = fmt.Sprintf("%g", boost)
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: whereSQL, ScoreSQL: scoreSQL}
}

func (t *Transpiler) compilePercolate(pq *esast.PercolateQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if pq == nil || strings.TrimSpace(pq.Field) == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if t.Schema != nil && len(t.Schema.Fields) > 0 {
		_, b := t.resolveFieldInNestedCtx(pq.Field, false, nctx)
		if b.ESType == "" {
			if !pq.IgnoreUnmapped && t.searchErr == nil {
				t.searchErr = fmt.Errorf("query_shard_exception: no mapping found for field [%s]", pq.Field)
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if b.ESType != "percolator" {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("field [%s] is not of type [percolator]", pq.Field)
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
	}
	whereSQL := t.compileExistsPredicate(pq.Field, nctx)
	scoreSQL := "0.0"
	if inScoring {
		boost := 1.0
		if pq.Boost != nil {
			boost = *pq.Boost
		}
		if boost != 0 && whereSQL != "FALSE" {
			scoreSQL = fmt.Sprintf("%g", boost)
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: whereSQL, ScoreSQL: scoreSQL}
}

func (t *Transpiler) compileRuleQuery(rq *esast.RuleQuerySpec, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if rq == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if rq.Organic == nil {
		scoreSQL := "1.0"
		if rq.Boost != nil && inScoring {
			scoreSQL = fmt.Sprintf("%.4f", *rq.Boost)
		}
		return CompiledQuery{WhereSQL: "1=1", SafeWhereSQL: "1=1", ScoreSQL: scoreSQL}
	}
	cp := t.CompileQuery(rq.Organic, inScoring, nctx)
	if rq.Boost != nil && inScoring {
		if *rq.Boost == 0 {
			cp.ScoreSQL = "0.0"
		} else if *rq.Boost != 1.0 && cp.ScoreSQL != "" && cp.ScoreSQL != "0.0" {
			cp.ScoreSQL = fmt.Sprintf("((%s) * %.4f)", cp.ScoreSQL, *rq.Boost)
		}
	}
	return cp
}

func (t *Transpiler) compileSparseVectorQuery(sv *esast.SparseVectorQuerySpec, inScoring bool, nctx *nestedCtx) CompiledQuery {
	if sv == nil || strings.TrimSpace(sv.Field) == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	resolvedField, b := t.resolveFieldInNestedCtx(sv.Field, false, nctx)
	if !t.checkFieldSearchable(resolvedField, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if t.Schema != nil && len(t.Schema.Fields) > 0 && b.ESType != "" && b.ESType != "sparse_vector" && b.ESType != "rank_features" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: cannot execute [sparse_vector] query on [%s] of type [%s]; must be [sparse_vector] or [rank_features]", resolvedField, b.ESType)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	weights := make(map[string]float64)
	if effToks := sv.EffectiveTokens(); len(effToks) > 0 {
		for k, w := range effToks {
			if tk := strings.TrimSpace(k); tk != "" && w > 0 && !math.IsNaN(w) && !math.IsInf(w, 0) {
				weights[tk] = w
			}
		}
	} else if qt := strings.TrimSpace(sv.EffectiveQueryText()); qt != "" {
		for _, tok := range strings.Fields(strings.ToLower(qt)) {
			weights[tok] += 1.0
		}
	}
	if len(weights) == 0 {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	toks := sortedMapKeys(weights)
	var retrieveConds []string
	var allConds []string
	var scoreTerms []string
	var prunedScoreTerms []string
	var weightThreshold float64
	hasThreshold := false
	onlyScorePruned := false
	if sv.Prune != nil && *sv.Prune && sv.PruningConfig != nil {
		if twt, ok := parseFiniteFloatValue(sv.PruningConfig["tokens_weight_threshold"]); ok {
			weightThreshold = twt
			hasThreshold = true
		}
		if osp, ok := normalizeBooleanQueryValue(sv.PruningConfig["only_score_pruned_tokens"]); ok {
			onlyScorePruned = osp
		}
	}
	for _, tok := range toks {
		w := weights[tok]
		col := t.sqlTypedColumnRef(resolvedField+"."+tok, 1.0, false, nctx)
		cond := fmt.Sprintf("(%s IS NOT NULL AND %s > 0)", col, col)
		allConds = append(allConds, cond)
		sTerm := fmt.Sprintf("(GREATEST(COALESCE(CAST(%s AS DOUBLE), 0.0), 0.0) * %g)", col, w)
		scoreTerms = append(scoreTerms, sTerm)
		if !hasThreshold || w >= weightThreshold {
			if !hasThreshold || !onlyScorePruned {
				retrieveConds = append(retrieveConds, cond)
			}
			prunedScoreTerms = append(prunedScoreTerms, sTerm)
		}
	}
	if len(retrieveConds) == 0 {
		retrieveConds = allConds
	}
	if len(prunedScoreTerms) == 0 {
		prunedScoreTerms = scoreTerms
	}
	whereSQL := retrieveConds[0]
	if len(retrieveConds) > 1 {
		whereSQL = "(" + strings.Join(retrieveConds, " OR ") + ")"
	}
	if sv.Filter != nil {
		fc := t.CompileQuery(sv.Filter, false, nctx)
		whereSQL = fmt.Sprintf("(%s AND (%s))", whereSQL, fc.WhereSQL)
	}
	scoreSQL := "0.0"
	if inScoring {
		boost := 1.0
		if sv.Boost != nil {
			boost = *sv.Boost
		}
		if boost != 0 {
			effTerms := scoreTerms
			if hasThreshold && onlyScorePruned {
				effTerms = prunedScoreTerms
			}
			sumExpr := effTerms[0]
			if len(effTerms) > 1 {
				sumExpr = "(" + strings.Join(effTerms, " + ") + ")"
			}
			if boost != 1.0 {
				scoreSQL = fmt.Sprintf("(%g * %s)", boost, sumExpr)
			} else {
				scoreSQL = sumExpr
			}
		}
	}
	return CompiledQuery{WhereSQL: whereSQL, SafeWhereSQL: whereSQL, ScoreSQL: scoreSQL}
}
