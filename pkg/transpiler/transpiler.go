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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/spatial"
)

const internalRawRE2Flag = "\x00raw_re2"

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
	// CollapseMaxScoreSQL computes the pre-collapse `MAX(_score) AS _overall_max_score` without altering
	// `HitsSQL`'s 5-column projection expected by backend row scanners.
	CollapseMaxScoreSQL string
}

// BM25FieldTermStats provides corpus-wide field statistics (`TotalDocs`, `AvgDL`, and per-term `TermDocFreq`)
// so live Doris BM25 scoring can compute exact Lucene IDF and average document length normalization.
type BM25FieldTermStats struct {
	TotalDocs   int64
	AvgDL       float64
	TermDocFreq map[string]int64
}

// BM25QueryRequirement identifies a field/column and analyzed query terms requiring corpus BM25 stats.
type BM25QueryRequirement struct {
	Field         string
	ColExpr       string
	CaseSensitive bool
	Terms         []string
}

// RawHistParamStrings preserves unrounded JSON integer strings for `histogram`
// `interval`/`offset` so `unsigned_long` values above 2^53 do not lose precision in `float64`.
type RawHistParamStrings struct {
	Interval string
	Offset   string
}

// TranspilerOptions configures dialect features for the Doris SQL compiler.
type TranspilerOptions struct {
	// UseDoris4SearchFunc enables pushing `query_string` / `simple_query_string` directly to
	// Apache Doris 4.0's native `SEARCH('<dsl>', '<default_field>', '<default_op>')` function
	// and `score()` projection.
	UseDoris4SearchFunc        bool
	ES8Compat                  bool
	StrictTextTermRouting      bool
	LegacyFlatMatchScore       bool
	DynamicTextFields          map[string]bool
	CallerSize                 int
	MaxResultWindow            int
	MaxAggBuckets              int
	TopMetricsMaxSize          int
	MaxDocvalueFieldsSearch    int
	MaxScriptFields            int
	MaxRegexLength             int
	EnforceResultWindowError   bool
	DisallowExpensiveQueries   bool
	DisableSynonymsPhraseQuery bool
	ImplicitTimestampSort      bool
	NumberOfShards             int
	RuntimeMappings            map[string]esast.FieldProperty
	AnalysisConfig             *analysis.IndexAnalysisConfig
	AnalysisOpts               analysis.Options
	Similarities               map[string]SimilarityConfig
	TermDocFreqFn              func(colExpr string, terms []string, caseSensitive bool) (int, map[string]int)
	CorpusBM25Stats            map[string]*BM25FieldTermStats
	RawHistBounds              map[string]RawHistParamStrings
}

type Transpiler struct {
	Schema                *schema.IndexSchema
	Opts                  TranspilerOptions
	unindexedFields       map[string]bool
	collectedBM25Reqs     []BM25QueryRequirement
	searchErr             error
	inFilterAggQuery      bool
	inLenientQuery        bool
	inTopLevelKNN         bool
	inSpanQuery           bool
	activeRequestSize     int
	activeAliasWhere      string
	activeMainScoreSQL    string
	activeHasKNN          bool
	luceneDepth           int
	inQueryString         bool
	inGeoGridQuery        bool
	autoGenSynPhraseQuery *bool
}

func NewTranspiler(s *schema.IndexSchema, opts TranspilerOptions) *Transpiler {
	return &Transpiler{
		Schema:          s,
		Opts:            opts,
		unindexedFields: make(map[string]bool),
	}
}

// CollectBM25QueryRequirements dry-compiles a request's scoring queries and returns the deduplicated
// set of fields, Doris SQL column expressions, and analyzed tokens needing corpus BM25 statistics.
func CollectBM25QueryRequirements(req *esast.SearchRequest, sc *schema.IndexSchema, opts TranspilerOptions) []BM25QueryRequirement {
	if req == nil {
		return nil
	}
	collectOpts := opts
	collectOpts.CorpusBM25Stats = nil
	tr := NewTranspiler(sc, collectOpts)
	if req.Query != nil {
		_ = tr.CompileQuery(req.Query, true, nil)
	}
	for i := range req.Rescore {
		if req.Rescore[i].Query.RescoreQuery != nil {
			_ = tr.CompileQuery(req.Rescore[i].Query.RescoreQuery, true, nil)
		}
	}
	if len(tr.collectedBM25Reqs) == 0 {
		return nil
	}
	type reqKey struct {
		field         string
		colExpr       string
		caseSensitive bool
	}
	idxByKey := make(map[reqKey]int, len(tr.collectedBM25Reqs))
	seenTermsByIdx := make([]map[string]struct{}, 0, len(tr.collectedBM25Reqs))
	out := make([]BM25QueryRequirement, 0, len(tr.collectedBM25Reqs))
	for _, r := range tr.collectedBM25Reqs {
		k := reqKey{field: r.Field, colExpr: r.ColExpr, caseSensitive: r.CaseSensitive}
		idx, exists := idxByKey[k]
		if !exists {
			idx = len(out)
			idxByKey[k] = idx
			seenTermsByIdx = append(seenTermsByIdx, make(map[string]struct{}, len(r.Terms)))
			out = append(out, BM25QueryRequirement{
				Field:         r.Field,
				ColExpr:       r.ColExpr,
				CaseSensitive: r.CaseSensitive,
			})
		}
		termSet := seenTermsByIdx[idx]
		for _, tk := range r.Terms {
			if _, ok := termSet[tk]; !ok {
				termSet[tk] = struct{}{}
				out[idx].Terms = append(out[idx].Terms, tk)
			}
		}
	}
	return out
}

func (t *Transpiler) isES8DocValuesSearchEnabled() bool {
	return t.Opts.ES8Compat || (t.Schema != nil && t.Schema.ES8Mode)
}

func (t *Transpiler) maxTopMetricsSize() int {
	if t.Opts.TopMetricsMaxSize > 0 {
		return t.Opts.TopMetricsMaxSize
	}
	return 10
}

func (t *Transpiler) runtimeFieldDefR65(field string) (esast.FieldProperty, bool) {
	clean := strings.TrimSpace(field)
	if clean == "" {
		return esast.FieldProperty{}, false
	}
	if len(t.Opts.RuntimeMappings) > 0 {
		if fp, ok := t.Opts.RuntimeMappings[clean]; ok {
			return fp, true
		}
	}
	if t.Schema != nil && t.Schema.RawMapping != nil && len(t.Schema.RawMapping.Runtime) > 0 {
		if fp, ok := t.Schema.RawMapping.Runtime[clean]; ok {
			return fp, true
		}
	}
	return esast.FieldProperty{}, false
}

func isNumericTopMetricsSortTypeR65(esType string) bool {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "long", "integer", "short", "byte", "unsigned_long",
		"double", "float", "half_float", "scaled_float",
		"date", "date_nanos", "token_count", "aggregate_metric_double":
		return true
	}
	return false
}

func (t *Transpiler) checkFieldSearchable(field string, b schema.FieldBinding) bool {
	if field == "_tsid" {
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = esTranspilerError("query_shard_exception: failed to create query: Field [_tsid] is not searchable")
		}
		return false
	}
	if b.EnabledFalse {
		return false
	}
	if b.NotIndexed {
		if b.ESType == "constant_keyword" {
			return true
		}
		if b.ESType == "geo_shape" && !b.DocValuesFalse {
			return true
		}
		if t.inGeoGridQuery && !b.DocValuesFalse && (b.ESType == "geo_point" || b.ESType == "geo_shape" || b.ESType == "point" || b.ESType == "shape") {
			return true
		}
		if t.isES8DocValuesSearchEnabled() && schema.SupportsDocValuesQueriesInES8(b) {
			return true
		}
		if t.searchErr == nil {
			if (b.ESType == "geo_shape" || b.ESType == "geo_point") && b.DocValuesFalse {
				t.searchErr = esTranspilerError(fmt.Sprintf("all_shards_failed|query_shard_exception|failed to create query: Cannot search on field [%s] since it is not indexed nor has doc values.", field))
			} else {
				t.searchErr = fmt.Errorf("cannot search on field [%s] since it is not indexed", field)
			}
		}
		return false
	}
	return true
}

func (t *Transpiler) checkFieldPositionalSearchable(field string, b schema.FieldBinding) bool {
	if field == "_tsid" {
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = esTranspilerError("query_shard_exception: failed to create query: Field [_tsid] is not searchable")
		}
		return false
	}
	if t.inSpanQuery && !t.checkSpanFieldNotMatchOnlyText(field, b) {
		return false
	}
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

func (t *Transpiler) isNonStandardQueryRestrictedField(field string, b schema.FieldBinding, queryKind string) bool {
	switch b.ESType {
	case "rank_feature", "rank_features":
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: [%s] query is not supported on [%s] field [%s]; use [rank_feature] query instead", queryKind, b.ESType, field)
		}
		return true
	case "histogram":
		if queryKind != "range" && queryKind != "exists" {
			if !t.inLenientQuery && t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: [%s] query is not supported on [histogram] field [%s]", queryKind, field)
			}
			return true
		}
	}
	return false
}

func (t *Transpiler) validateAggsDocValues(aggs map[string]esast.AggSpec, nctx *nestedCtx) {
	t.validateAggsDocValuesDepthWithParent(aggs, nctx, 0, false)
}

func (t *Transpiler) validateAggsDocValuesDepthWithParent(aggs map[string]esast.AggSpec, nctx *nestedCtx, depth int, onlyNestedAncestors bool) {
	if len(aggs) == 0 {
		return
	}
	checkFieldForAgg := func(field string, aggKind string, hasScript bool, curNCtx *nestedCtx) {
		if field == "" || strings.HasPrefix(field, "_") {
			return
		}
		resolved, b := t.resolveFieldInNestedCtx(field, true, curNCtx)
		if b.ESType == "rank_feature" || b.ESType == "rank_features" {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: Aggregations are not supported on [%s] field [%s]", b.ESType, field)
			}
			return
		}
		if b.ESType == "histogram" {
			switch aggKind {
			case "min", "max", "sum", "avg", "value_count", "stats", "percentiles", "percentile_ranks", "boxplot", "histogram", "missing", "top_hits", "rate", "range":
			default:
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: Field [%s] of type [histogram] is not supported for aggregation [%s]", field, aggKind)
				}
				return
			}
		}
		if !hasScript && b.ESType == "geo_point" && strings.EqualFold(b.TimeSeriesMetric, "position") && isNumericMetricAggKind(aggKind) {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: Field [%s] of type [geo_point] is not supported for aggregation [%s]", field, aggKind)
			}
			return
		}
		if !hasScript && b.ESType == "aggregate_metric_double" {
			switch aggKind {
			case "min", "max", "sum", "avg", "value_count", "stats", "missing", "top_hits", "top_hits_sort", "aggregation":
			default:
				if t.searchErr == nil {
					t.searchErr = esTranspilerError(fmt.Sprintf("all_shards_failed|unsupported_aggregation_on_downsampled_index|Field [%s] of type [aggregate_metric_double] is not supported for aggregation [%s]", field, aggKind))
				}
				return
			}
		}
		if !hasScript && b.ESType != "" && isNumericMetricAggKind(aggKind) && isUnsupportedNumericMetricESType(b.ESType) {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: Field [%s] of type [%s] is not supported for aggregation [%s]", field, b.ESType, aggKind)
			}
			return
		}
		t.checkFieldDocValues(resolved, b)
	}
	checkField := func(field string, curNCtx *nestedCtx) {
		checkFieldForAgg(field, "aggregation", false, curNCtx)
	}
	for name, spec := range aggs {
		if termsSpec := spec.EffectiveTerms(); termsSpec != nil && spec.SignificantText == nil {
			effField := termsSpec.Field
			if effField == "" && termsSpec.Script != nil {
				if df, ok := extractSimpleDocFieldFromScript(termsSpec.Script); ok {
					effField = df
				}
			}
			checkFieldForAgg(effField, "terms", termsSpec.Script != nil, nctx)
			if _, _, isPart, errPart := ParseTermsIncludePartition(termsSpec.Include); isPart && errPart != nil && t.searchErr == nil {
				t.searchErr = errPart
			}
			if effField != "" {
				_, bTerms := t.resolveFieldInNestedCtx(effField, true, nctx)
				if errIE := validateTermsIncludeExcludeForBindingNamed(name, effField, bTerms, termsSpec); errIE != nil && t.searchErr == nil {
					t.searchErr = errIE
				}
			}
			t.checkScriptDocValues(termsSpec.Script, nctx)
		}
		if spec.RareTerms != nil && spec.RareTerms.Field != "" {
			checkFieldForAgg(spec.RareTerms.Field, "rare_terms", false, nctx)
			_, bRT := t.resolveFieldInNestedCtx(spec.RareTerms.Field, true, nctx)
			if errIE := validateTermsIncludeExcludeForBindingNamed(name, spec.RareTerms.Field, bRT, &esast.TermsAggSpec{
				Field:   spec.RareTerms.Field,
				Include: spec.RareTerms.Include,
				Exclude: spec.RareTerms.Exclude,
			}); errIE != nil && t.searchErr == nil {
				t.searchErr = errIE
			}
		}
		if spec.SignificantText != nil {
			checkFieldForAgg(spec.SignificantText.Field, "significant_text", false, nctx)
		}
		if spec.Histogram != nil {
			checkFieldForAgg(spec.Histogram.Field, "histogram", spec.Histogram.Script != nil, nctx)
			t.checkScriptDocValues(spec.Histogram.Script, nctx)
			t.validateHistogramBoundsSpec(spec.Histogram.ExtendedBounds, "extended_bounds", name)
			t.validateHistogramBoundsSpec(spec.Histogram.HardBounds, "hard_bounds", name)
		}
		if spec.DateHistogram != nil {
			checkFieldForAgg(spec.DateHistogram.Field, "date_histogram", spec.DateHistogram.Script != nil, nctx)
			t.checkScriptDocValues(spec.DateHistogram.Script, nctx)
			t.validateDateHistogramSpec(spec.DateHistogram, name, nctx)
		}
		if rSpec := spec.EffectiveRange(); rSpec != nil {
			checkFieldForAgg(rSpec.Field, "range", rSpec.Script != nil, nctx)
			t.checkScriptDocValues(rSpec.Script, nctx)
		}
		if spec.Composite != nil {
			if depth > 0 && !onlyNestedAncestors {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: [composite] aggregation cannot be used with a parent aggregation")
				}
			}
			if spec.Composite.Size > t.maxAggBuckets() {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: [composite] Trying to create too many buckets. Must be less than or equal to: [%d] but was [%d]", t.maxAggBuckets(), spec.Composite.Size)
				}
			}
			for _, srcMap := range spec.Composite.Sources {
				t.validateAggsDocValuesDepthWithParent(srcMap, nctx, 0, false)
			}
		}
		if spec.Cardinality != nil {
			checkFieldForAgg(spec.Cardinality.Field, "cardinality", spec.Cardinality.Script != nil, nctx)
			t.checkScriptDocValues(spec.Cardinality.Script, nctx)
		}
		if spec.ValueCount != nil {
			checkFieldForAgg(spec.ValueCount.Field, "value_count", spec.ValueCount.Script != nil, nctx)
			t.checkScriptDocValues(spec.ValueCount.Script, nctx)
		}
		if spec.Avg != nil {
			checkFieldForAgg(spec.Avg.Field, "avg", spec.Avg.Script != nil, nctx)
			t.checkScriptDocValues(spec.Avg.Script, nctx)
		}
		if spec.Sum != nil {
			checkFieldForAgg(spec.Sum.Field, "sum", spec.Sum.Script != nil, nctx)
			t.checkScriptDocValues(spec.Sum.Script, nctx)
		}
		if spec.Min != nil {
			checkFieldForAgg(spec.Min.Field, "min", spec.Min.Script != nil, nctx)
			t.checkScriptDocValues(spec.Min.Script, nctx)
		}
		if spec.Max != nil {
			checkFieldForAgg(spec.Max.Field, "max", spec.Max.Script != nil, nctx)
			t.checkScriptDocValues(spec.Max.Script, nctx)
		}
		if stSpec := spec.EffectiveStats(); stSpec != nil {
			aggKind := "stats"
			if spec.ExtendedStats != nil {
				aggKind = "extended_stats"
			}
			checkFieldForAgg(stSpec.Field, aggKind, stSpec.Script != nil, nctx)
			t.checkScriptDocValues(stSpec.Script, nctx)
		}
		if spec.StringStats != nil {
			checkFieldForAgg(spec.StringStats.Field, "string_stats", spec.StringStats.Script != nil, nctx)
			t.checkScriptDocValues(spec.StringStats.Script, nctx)
		}
		if spec.Boxplot != nil {
			checkFieldForAgg(spec.Boxplot.Field, "boxplot", spec.Boxplot.Script != nil, nctx)
			t.checkScriptDocValues(spec.Boxplot.Script, nctx)
		}
		if spec.Percentiles != nil {
			checkFieldForAgg(spec.Percentiles.Field, "percentiles", spec.Percentiles.Script != nil, nctx)
			t.checkScriptDocValues(spec.Percentiles.Script, nctx)
		}
		if spec.PercentileRanks != nil {
			checkFieldForAgg(spec.PercentileRanks.Field, "percentile_ranks", spec.PercentileRanks.Script != nil, nctx)
			t.checkScriptDocValues(spec.PercentileRanks.Script, nctx)
		}
		if spec.Rate != nil {
			checkFieldForAgg(spec.Rate.Field, "rate", spec.Rate.Script != nil, nctx)
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
				checkFieldForAgg(mf, "top_metrics", false, nctx)
			}
			for _, s := range spec.TopMetrics.Sort {
				var sortNCtx *nestedCtx
				if deepest := deepestNestedSortPath(s.Entry.Nested); deepest != "" {
					sortNCtx = &nestedCtx{nestedPath: deepest}
				} else {
					sortNCtx = nctx
				}
				checkFieldForAgg(s.Entry.Field, "top_metrics", false, sortNCtx)
				if s.Entry.Field == "_script" {
					t.checkScriptDocValues(s.Entry.Script, sortNCtx)
				}
			}
			if t.searchErr == nil {
				maxTM := t.maxTopMetricsSize()
				if spec.TopMetrics.Size != nil && *spec.TopMetrics.Size > maxTM {
					t.searchErr = fmt.Errorf("illegal_argument_exception: [top_metrics.size] must not be more than [%d] but was [%d]. This limit can be set by changing the [index.top_metrics_max_size] index level setting.", maxTM, *spec.TopMetrics.Size) //nolint:staticcheck // Exact Elasticsearch error message
					return
				}
				for _, mf := range spec.TopMetrics.EffectiveMetricFields() {
					if fp, isRT := t.runtimeFieldDefR65(mf); isRT && strings.EqualFold(strings.TrimSpace(fp.Type), "keyword") {
						t.searchErr = fmt.Errorf("illegal_argument_exception: top_metrics can only collect bytes that have segment ordinals but Field [%s] of type [keyword] does not", mf)
						return
					}
				}
				idxName := ""
				if t.Schema != nil {
					idxName = t.Schema.IndexName
				}
				for _, s := range spec.TopMetrics.Sort {
					sf := s.Entry.Field
					if sf == "_script" {
						if st := strings.ToLower(strings.TrimSpace(s.Entry.Type)); st != "" && st != "number" {
							t.searchErr = fmt.Errorf("illegal_argument_exception: error building sort for [_script]: script sorting only supported on [numeric] scripts but was [%s]", st)
							return
						}
						continue
					}
					if sf == "" || sf == "_score" || sf == "_doc" || sf == "_shard_doc" || sf == "_geo_distance" {
						continue
					}
					var sortNCtx *nestedCtx
					if deepest := deepestNestedSortPath(s.Entry.Nested); deepest != "" {
						sortNCtx = &nestedCtx{nestedPath: deepest}
					} else {
						sortNCtx = nctx
					}
					_, sortB := t.resolveFieldInNestedCtx(sf, true, sortNCtx)
					sortType := strings.ToLower(strings.TrimSpace(sortB.ESType))
					if sortType == "" {
						if fp, isRT := t.runtimeFieldDefR65(sf); isRT {
							sortType = normalizeRuntimeESType(fp.Type)
						}
					}
					if sortType != "" && !isNumericTopMetricsSortTypeR65(sortType) {
						t.searchErr = fmt.Errorf("illegal_argument_exception: error building sort for field [%s] of type [%s] in index [%s]: only supported on numeric fields", sf, sortType, idxName)
						return
					}
				}
			}
		}
		if spec.TopHits != nil {
			if errLim := t.validateDocvalueAndScriptFieldLimits(spec.TopHits.DocvalueFields, spec.TopHits.ScriptFields); errLim != nil && t.searchErr == nil {
				t.searchErr = errLim
			}
			for _, dvf := range spec.TopHits.DocvalueFields {
				checkFieldForAgg(dvf.Field, "top_hits", false, nctx)
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
				checkFieldForAgg(s.Entry.Field, "top_hits_sort", false, sortNCtx)
				if s.Entry.Field == "_script" {
					t.checkScriptDocValues(s.Entry.Script, sortNCtx)
				}
			}
		}
		if sampSpec := spec.EffectiveSampler(); sampSpec != nil {
			checkFieldForAgg(sampSpec.Field, "diversified_sampler", sampSpec.Script != nil, nctx)
			t.checkScriptDocValues(sampSpec.Script, nctx)
		}
		if spec.MultiTerms != nil {
			for _, mt := range spec.MultiTerms.Terms {
				checkFieldForAgg(mt.Field, "multi_terms", mt.Script != nil, nctx)
				t.checkScriptDocValues(mt.Script, nctx)
			}
		}
		if spec.RareTerms != nil {
			checkFieldForAgg(spec.RareTerms.Field, "rare_terms", false, nctx)
		}
		if spec.AutoDateHistogram != nil {
			checkFieldForAgg(spec.AutoDateHistogram.Field, "auto_date_histogram", spec.AutoDateHistogram.Script != nil, nctx)
			t.checkScriptDocValues(spec.AutoDateHistogram.Script, nctx)
		}
		if spec.VariableWidthHistogram != nil {
			checkFieldForAgg(spec.VariableWidthHistogram.Field, "variable_width_histogram", spec.VariableWidthHistogram.Script != nil, nctx)
			t.checkScriptDocValues(spec.VariableWidthHistogram.Script, nctx)
		}
		if spec.MedianAbsoluteDeviation != nil {
			if spec.MedianAbsoluteDeviation.Compression != nil && *spec.MedianAbsoluteDeviation.Compression <= 0 {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: [compression] must be greater than 0. Found [%v] in [%s]", *spec.MedianAbsoluteDeviation.Compression, name)
				}
			}
			checkFieldForAgg(spec.MedianAbsoluteDeviation.Field, "median_absolute_deviation", spec.MedianAbsoluteDeviation.Script != nil, nctx)
			t.checkScriptDocValues(spec.MedianAbsoluteDeviation.Script, nctx)
		}
		if spec.WeightedAvg != nil {
			checkFieldForAgg(spec.WeightedAvg.Value.Field, "weighted_avg", spec.WeightedAvg.Value.Script != nil, nctx)
			t.checkScriptDocValues(spec.WeightedAvg.Value.Script, nctx)
			checkFieldForAgg(spec.WeightedAvg.Weight.Field, "weighted_avg", spec.WeightedAvg.Weight.Script != nil, nctx)
			t.checkScriptDocValues(spec.WeightedAvg.Weight.Script, nctx)
		}
		if spec.MatrixStats != nil {
			for _, f := range spec.MatrixStats.Fields {
				checkField(f, nctx)
			}
		}
		if spec.TTest != nil {
			checkFieldForAgg(spec.TTest.A.Field, "t_test", spec.TTest.A.Script != nil, nctx)
			t.checkScriptDocValues(spec.TTest.A.Script, nctx)
			if spec.TTest.A.Filter != nil {
				_ = t.CompileQuery(spec.TTest.A.Filter, false, nctx)
			}
			checkFieldForAgg(spec.TTest.B.Field, "t_test", spec.TTest.B.Script != nil, nctx)
			t.checkScriptDocValues(spec.TTest.B.Script, nctx)
			if spec.TTest.B.Filter != nil {
				_ = t.CompileQuery(spec.TTest.B.Filter, false, nctx)
			}
		}
		if spec.GeoBounds != nil {
			checkFieldForAgg(spec.GeoBounds.Field, "geo_bounds", false, nctx)
		}
		if spec.GeoCentroid != nil {
			checkFieldForAgg(spec.GeoCentroid.Field, "geo_centroid", spec.GeoCentroid.Script != nil, nctx)
			t.checkScriptDocValues(spec.GeoCentroid.Script, nctx)
		}
		if spec.GeoDistance != nil {
			checkFieldForAgg(spec.GeoDistance.Field, "geo_distance", false, nctx)
		}
		if spec.GeohashGrid != nil {
			checkFieldForAgg(spec.GeohashGrid.Field, "geohash_grid", false, nctx)
		}
		if spec.GeotileGrid != nil {
			checkFieldForAgg(spec.GeotileGrid.Field, "geohash_grid", false, nctx)
		}
		if spec.Missing != nil {
			checkFieldForAgg(spec.Missing.Field, "missing", false, nctx)
		}
		if spec.Nested != nil && spec.Nested.Path != "" {
			t.validateAggsDocValuesDepthWithParent(spec.SubAggs(), &nestedCtx{nestedPath: spec.Nested.Path}, depth+1, depth == 0 || onlyNestedAncestors)
		} else if spec.Filter != nil || spec.Global != nil || spec.EffectiveSampler() != nil {
			t.validateAggsDocValuesDepthWithParent(spec.SubAggs(), nctx, depth+1, depth == 0 || onlyNestedAncestors)
		} else if spec.ReverseNested != nil {
			var rnNCtx *nestedCtx
			if rnPath, _ := spec.ReverseNested["path"].(string); strings.TrimSpace(rnPath) != "" {
				rnNCtx = &nestedCtx{nestedPath: strings.TrimSpace(rnPath)}
			}
			t.validateAggsDocValuesDepthWithParent(spec.SubAggs(), rnNCtx, depth+1, false)
		} else {
			t.validateAggsDocValuesDepthWithParent(spec.SubAggs(), nctx, depth+1, false)
		}
	}
}

type nestedCtx struct {
	nestedPath string
	elemVar    string
}

func (t *Transpiler) isBoundToNestedCtx(field string, b schema.FieldBinding, nctx *nestedCtx) bool {
	if nctx == nil || nctx.elemVar == "" || nctx.nestedPath == "" {
		return false
	}
	effField := field
	if b.AliasTarget != "" {
		effField = b.AliasTarget
	}
	return (b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) ||
		strings.HasPrefix(effField, nctx.nestedPath+".")
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

	if req != nil && len(req.RuntimeMappings) > 0 {
		merged := make(map[string]esast.FieldProperty, len(t.Opts.RuntimeMappings)+len(req.RuntimeMappings))
		for k, v := range t.Opts.RuntimeMappings {
			merged[k] = v
		}
		for k, v := range req.RuntimeMappings {
			merged[k] = v
		}
		t.Opts.RuntimeMappings = merged
	}
	if err := t.validateDisallowExpensiveQueries(req); err != nil {
		return nil, err
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
	t.activeRequestSize = size

	aliasWhere := ""
	var afCompiled CompiledQuery
	if req.AliasFilter != nil {
		afQ := esast.Query(*req.AliasFilter)
		afCompiled = t.CompileQuery(&afQ, false, nil)
		if afCompiled.WhereSQL != "" && afCompiled.WhereSQL != "TRUE" {
			aliasWhere = afCompiled.WhereSQL
		}
	}
	t.activeAliasWhere = aliasWhere
	t.activeHasKNN = req != nil && (len(req.KNN) > 0 || queryContainsKNNTreeR63(req.Query))

	mainQ := CompiledQuery{
		WhereSQL: "TRUE",
		ScoreSQL: "1.0",
	}
	safeScoreSQL := "1.0"
	if req.Query != nil {
		mainQ = t.CompileQuery(req.Query, true, nil)
		safeScoreSQL = mainQ.ScoreSQL
		if len(req.KNN) > 0 && mainQ.UsesFulltextMatch && t.Opts.UseDoris4SearchFunc {
			mainQ.ScoreSQL = fmt.Sprintf("COALESCE(score(), 1.0) * (%s)", mainQ.ScoreSQL)
		}
	}
	if len(req.KNN) > 0 {
		var knnWheres, knnSafeWheres, knnScores []string
		knnUsesFT := false
		prevTopKNN := t.inTopLevelKNN
		t.inTopLevelKNN = true
		for i := range req.KNN {
			kc := t.compileKNN(&req.KNN[i], true, nil)
			knnWheres = append(knnWheres, fmt.Sprintf("(%s)", kc.WhereSQL))
			knnSafeWheres = append(knnSafeWheres, fmt.Sprintf("(%s)", kc.EffectiveSafeWhere()))
			knnScores = append(knnScores, kc.ScoreSQL)
			knnUsesFT = knnUsesFT || kc.UsesFulltextMatch
		}
		t.inTopLevelKNN = prevTopKNN
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

	userWhere := mainQ.EffectiveSafeWhere()
	if req.MinScore != nil && !queryContainsScript(req.Query) && !queryContainsNestedScoring(req.Query) {
		minScoreExpr := mainQ.ScoreSQL
		if len(req.KNN) == 0 && mainQ.UsesFulltextMatch && t.Opts.UseDoris4SearchFunc {
			minScoreExpr = fmt.Sprintf("COALESCE(score(), 1.0) * (%s)", mainQ.ScoreSQL)
		}
		minCond := fmt.Sprintf("(CAST(%s AS DOUBLE) >= %s)", minScoreExpr, strconv.FormatFloat(*req.MinScore, 'f', -1, 64))
		// Never place Doris `score()` inside `mainQ.SafeWhereSQL` / `userWhere`: CTE consumers
		// (`global`, `join`, `sampler`, etc.) select `FROM base_matched WHERE (<userWhere>)`, where
		// Doris rejects `score()`. `base_matched` itself already applies `mainQ.WhereSQL`.
		usesScoreFunc := strings.Contains(minScoreExpr, "score()") || (mainQ.UsesFulltextMatch && t.Opts.UseDoris4SearchFunc)
		prevSafeWhere := mainQ.EffectiveSafeWhere()
		if mainQ.WhereSQL == "" || mainQ.WhereSQL == "TRUE" {
			mainQ.WhereSQL = minCond
			if usesScoreFunc {
				mainQ.SafeWhereSQL = "TRUE"
			} else {
				mainQ.SafeWhereSQL = minCond
			}
		} else {
			mainQ.WhereSQL = fmt.Sprintf("((%s) AND %s)", mainQ.WhereSQL, minCond)
			if usesScoreFunc {
				mainQ.SafeWhereSQL = prevSafeWhere
			} else {
				mainQ.SafeWhereSQL = fmt.Sprintf("((%s) AND %s)", prevSafeWhere, minCond)
			}
		}
		userWhere = mainQ.EffectiveSafeWhere()
	}
	if aliasWhere != "" {
		if mainQ.WhereSQL == "" || mainQ.WhereSQL == "TRUE" {
			mainQ.WhereSQL = aliasWhere
			mainQ.SafeWhereSQL = afCompiled.EffectiveSafeWhere()
		} else {
			mainQ.WhereSQL = fmt.Sprintf("((%s) AND (%s))", mainQ.WhereSQL, aliasWhere)
			mainQ.SafeWhereSQL = fmt.Sprintf("((%s) AND (%s))", mainQ.EffectiveSafeWhere(), afCompiled.EffectiveSafeWhere())
		}
	}

	postFilterSQL := "TRUE"
	postFilterSafeSQL := "TRUE"
	if req.PostFilter != nil {
		pfCompiled := t.CompileQuery(req.PostFilter, false, nil)
		postFilterSQL = pfCompiled.WhereSQL
		postFilterSafeSQL = pfCompiled.EffectiveSafeWhere()
	}

	maxWin := t.effectiveMaxResultWindow()
	if len(req.SearchAfter) == 0 && from+size > maxWin {
		return nil, fmt.Errorf("illegal_argument_exception: Result window is too large, from + size must be less than or equal to: [%d] but was [%d]. See the scroll api for a more efficient way to request large data sets. This limit can be set by changing the [index.max_result_window] index level setting.", maxWin, from+size) //nolint:staticcheck // ES exact error message
	}
	if err := t.validateDocvalueAndScriptFieldLimits(req.DocvalueFields, req.ScriptFields); err != nil {
		return nil, err
	}
	if err := t.validateCollapseRequest(req); err != nil {
		return nil, err
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
	effSorts := t.effectiveSortsForRequest(req)
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
			plan.CollapseMaxScoreSQL = fmt.Sprintf(
				"SELECT CAST(MAX(`_score`) AS DOUBLE) AS `_overall_max_score` FROM (SELECT CAST(%s AS DOUBLE) AS `_score` FROM `%s`.`%s` WHERE %s) `_scored`",
				scoreExpr,
				t.Schema.DorisDB,
				t.Schema.DorisTable,
				preCollapseWhere,
			)
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

	t.activeMainScoreSQL = safeScoreSQL
	aggs := req.EffectiveAggs()
	t.validateAggsDocValues(aggs, nil)
	t.validateRound62AggTree(aggs, nil, nil)
	if len(aggs) > 0 || size == 0 {
		plan.AggsSQL = t.buildAggsCTESQL(mainQ.WhereSQL, userWhere, aliasWhere, postFilterSafeSQL, aggs)
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
			if svCP, handled := t.compileSparseVectorTermQueryR63(cleanField, entry.Value, entry.Boost*fBoost, scoring, nctx); handled {
				preds = append(preds, svCP.WhereSQL)
				if scoring {
					scores = append(scores, svCP.ScoreSQL)
				}
				continue
			}
			pred := t.compileTermPredicate(cleanField, entry.Value, entry.CaseInsensitive, nctx)
			preds = append(preds, pred)
			if scoring {
				effB := entry.Boost * fBoost
				kwBoost := effB
				if t.activeHasKNN {
					kwBoost = effB * 0.4458
				}
				scExpr := fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, kwBoost)
				if pred != "FALSE" && entry.Value != nil {
					resolvedF, bText := t.resolveFieldInNestedCtx(cleanField, false, nctx)
					if _, tok, cs, handled := t.compileAnalyzedTextTermPredicateR63(cleanField, resolvedF, bText, entry.Value, entry.CaseInsensitive, nctx); handled && tok != "" {
						if bm25Sc, ok := t.compileBM25SingleTermScoreR63(cleanField, resolvedF, bText, tok, cs, effB, pred, nctx); ok {
							scExpr = bm25Sc
						}
					} else if bText.ESType == "text" && !strings.HasSuffix(cleanField, ".keyword") {
						rawTok := strings.TrimSpace(fmt.Sprintf("%v", entry.Value))
						if rawTok != "" {
							cs := !entry.CaseInsensitive && !bText.EffectiveLowercase(false)
							if bm25Sc, ok := t.compileBM25SingleTermScoreR63(cleanField, resolvedF, bText, rawTok, cs, effB, pred, nctx); ok {
								scExpr = bm25Sc
							}
						}
					}
				}
				scores = append(scores, scExpr)
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
			if !t.checkFieldSearchable(resolvedField, b) || t.isNonStandardQueryRestrictedField(cleanField, b, "terms_set") || len(ts.Terms) == 0 || b.Kind == schema.StoragePromotedVector {
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
		return t.compileCombinedFields(q.CombinedFields, scoring, nctx)
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
			origField := field
			if origField == "_ignored" && nctx == nil {
				if re.Flags != internalRawRE2Flag && !t.checkRegexLengthLimit(re.Value) {
					return "FALSE", "FALSE", false
				}
				if re.Flags == internalRawRE2Flag {
					pat := re.Value
					if re.CaseInsensitive && !strings.HasPrefix(pat, "(?i)") {
						pat = "(?i)" + pat
					}
					arrPred := fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `_ignored`)", quoteStr(pat))
					return arrPred, arrPred, false
				}
				compiledRE, errRE := CompileLuceneRegexpToSQLPredicates(re.Value, re.Flags, re.CaseInsensitive)
				if errRE != nil {
					if !t.inLenientQuery && t.searchErr == nil {
						t.searchErr = errRE
					}
					return "FALSE", "FALSE", false
				}
				if compiledRE.IsEmpty {
					return "FALSE", "FALSE", false
				}
				arrPred := fmt.Sprintf("array_exists(_x -> %s, `_ignored`)", compiledRE.ArrayElemSQL("_x"))
				return arrPred, arrPred, false
			}
			field, b := t.resolveFieldInNestedCtx(field, true, nctx)
			if !t.checkFieldSearchable(field, b) || t.isNonStandardQueryRestrictedField(origField, b, "regexp") || b.Kind == schema.StoragePromotedVector {
				return "FALSE", "FALSE", false
			}
			if re.Flags != internalRawRE2Flag && !t.checkRegexLengthLimit(re.Value) {
				return "FALSE", "FALSE", false
			}
			effCI := re.CaseInsensitive || (nctx != nil && b.EffectiveLowercase(true))
			wantCI := effCI || (!t.isBoundToNestedCtx(field, b, nctx) && b.EffectiveLowercase(true))
			if re.Flags == internalRawRE2Flag {
				pat := re.Value
				if wantCI && !strings.HasPrefix(pat, "(?i)") {
					pat = "(?i)" + pat
				}
				if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
					arrColExpr := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
					if b.Kind == schema.StoragePromotedArray && (b.DorisType == schema.DorisLargeInt || b.DorisType == schema.DorisLargeIntArray) {
						arrColExpr = fmt.Sprintf("array_map(_x -> CAST(_x AS STRING), `%s`)", b.EffectiveArrayColumn(true))
					}
					arrPred := fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, %s)", quoteStr(pat), arrColExpr)
					return arrPred, arrPred, false
				}
				col := t.sqlColumnRef(field, true, nctx)
				if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
					arrPred := fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, TRY_CAST(%s AS ARRAY<STRING>))", quoteStr(pat), col)
					return arrPred, arrPred, false
				}
				qPat := quoteStr(pat)
				safePred := fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, qPat)
				return fmt.Sprintf("%s REGEXP %s", col, qPat), safePred, false
			}
			compiledRE, errRE := CompileLuceneRegexpToSQLPredicates(re.Value, re.Flags, wantCI)
			if errRE != nil {
				if !t.inLenientQuery && t.searchErr == nil {
					t.searchErr = errRE
				}
				return "FALSE", "FALSE", false
			}
			if compiledRE.IsEmpty {
				return "FALSE", "FALSE", false
			}
			if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				arrColExpr := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
				if b.Kind == schema.StoragePromotedArray && (b.DorisType == schema.DorisLargeInt || b.DorisType == schema.DorisLargeIntArray) {
					arrColExpr = fmt.Sprintf("array_map(_x -> CAST(_x AS STRING), `%s`)", b.EffectiveArrayColumn(true))
				}
				arrPred := fmt.Sprintf("array_exists(_x -> %s, %s)", compiledRE.ArrayElemSQL("_x"), arrColExpr)
				return arrPred, arrPred, false
			}
			col := t.sqlColumnRef(field, true, nctx)
			if b.ESType == "flattened" {
				if isRoot, isSubKey := t.flattenedFieldMode(field, b); isSubKey {
					rawVar := t.flattenedRawVariantRef(field, b, nctx)
					_, scalarSafe, _ := compiledRE.ScalarSQL(col, false, false)
					arrPred := fmt.Sprintf("(%s OR array_exists(_x -> %s, TRY_CAST(%s AS ARRAY<STRING>)))", scalarSafe, compiledRE.ArrayElemSQL("_x"), rawVar)
					return arrPred, arrPred, false
				} else if isRoot {
					return compiledRE.ScalarSQL(col, false, false)
				}
			}
			if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
				arrPred := fmt.Sprintf("array_exists(_x -> %s, TRY_CAST(%s AS ARRAY<STRING>))", compiledRE.ArrayElemSQL("_x"), col)
				return arrPred, arrPred, false
			}
			isTokenizedText := b.DorisType == schema.DorisString && (schema.IsTextLikeESType(b.ESType) || field == "_all_text")
			allowMatchRegexp := nctx == nil && !b.NotIndexed && b.Kind != schema.StorageDynamicVariant && b.DorisType != schema.DorisVarchar && !effCI && !wantCI
			return compiledRE.ScalarSQL(col, allowMatchRegexp, isTokenizedText)
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
			if me.CutoffFrequency > 0 {
				if cp, ok := t.compileCommonTermsQueryR64(keys[0], qStr, me.Operator, "or", me.CutoffFrequency, me.MinimumShouldMatch, me.Analyzer, me.ZeroTermsQuery, me.Boost, scoring, nctx, false); ok {
					return cp
				}
			}
			if cp, ok := t.compileMatchWithAnalysisGraphOpts(keys[0], qStr, me.Operator, me.Analyzer, me.ZeroTermsQuery, me.MinimumShouldMatch, me.Fuzziness, me.PrefixLength, me.FuzzyTranspositions, me.AutoGenerateSynonymsPhraseQuery, me.Boost, scoring, nctx); ok {
				return cp
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
									Analyzer:            me.Analyzer,
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
			return t.compileMatchFieldWithAnalyzer(keys[0], queryForMatch, me.Operator, me.Analyzer, me.Boost, scoring, nctx)
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
			if cp, ok := t.compileMatchPhraseWithAnalysisGraph(keys[0], pe.Query, pe.Slop, pe.Analyzer, pe.ZeroTermsQuery, false, pe.Boost, scoring, nctx); ok {
				return cp
			}
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
			if cp, ok := t.compileMatchPhraseWithAnalysisGraph(keys[0], pe.Query, pe.Slop, pe.Analyzer, pe.ZeroTermsQuery, true, pe.Boost, scoring, nctx); ok {
				return cp
			}
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
			return t.compileMatchBoolPrefixRound62(keys[0], q.MatchBoolPrefix[keys[0]], scoring, nctx)
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
			if cp, ok := t.compileCommonTermsQueryR64(keys[0], qStr, ce.LowFreqOperator, ce.HighFreqOperator, ce.CutoffFrequency, ce.MinimumShouldMatch, ce.Analyzer, "", ce.Boost, scoring, nctx, true); ok {
				return cp
			}
			lowOp := ce.LowFreqOperator
			if lowOp == "" {
				lowOp = "or"
			}
			highOp := ce.HighFreqOperator
			if highOp == "" {
				highOp = "or"
			}
			tokens := strings.Fields(qStr)
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
		prevQS := t.inQueryString
		t.inQueryString = true
		res := t.compileQueryStringEntry(q.QueryString, scoring, nctx, false)
		t.inQueryString = prevQS
		return res
	case q.SimpleQueryString != nil:
		prevQS := t.inQueryString
		t.inQueryString = true
		res := t.compileQueryStringEntry(q.SimpleQueryString, scoring, nctx, true)
		t.inQueryString = prevQS
		return res
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
	case q.GeoGrid != nil:
		return t.compileGeoGrid(q.GeoGrid, scoring, nctx)
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
	if b.ESType != "" && b.ESType != "geo_point" && b.ESType != "geo_shape" && (!t.inGeoGridQuery || (b.ESType != "point" && b.ESType != "shape")) {
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
		latExpr := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
		lonExpr := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
		whereSQL = fmt.Sprintf("(%s IS NOT NULL AND ST_Distance_Sphere(%s, %s, %s, %s) <= %s)",
			elemExpr, lonExpr, latExpr, tLonStr, tLatStr, distStr)
	} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
		latExpr := "TRY_CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE)"
		lonExpr := "TRY_CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE)"
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
	if b.ESType != "" && b.ESType != "geo_point" && b.ESType != "geo_shape" && (!t.inGeoGridQuery || (b.ESType != "point" && b.ESType != "shape")) {
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
		latExpr := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
		lonExpr := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
		whereSQL = fmt.Sprintf("(%s IS NOT NULL AND %s)", elemExpr, buildBBoxCond(latExpr, lonExpr))
	} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
		latExpr := "TRY_CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE)"
		lonExpr := "TRY_CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE)"
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
	if latR63, lonR63, nnR63 := t.BuildGeoPointOrShapeLatLonExprsR63(resolvedField, b); latR63 != "" {
		return latR63, lonR63, nnR63
	}
	if b.Kind == schema.StoragePromotedScalar && b.ColumnName != "" {
		col := fmt.Sprintf("`%s`", b.ColumnName)
		latExpr = fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", col)
		lonExpr = fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", col)
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
	srcLat, srcLon := buildSingleGeoScalarLatLonSQLR63(sqlRuntimeSourceStringExpr(resolvedField))
	docCSVLat := fmt.Sprintf("CASE WHEN TRY_CAST(%s AS STRING) NOT LIKE '[%%' AND TRY_CAST(%s AS STRING) NOT REGEXP '^[[:space:]]*[A-Za-z{]' AND LOCATE(',', TRY_CAST(%s AS STRING)) > 0 THEN TRY_CAST(SPLIT_PART(TRY_CAST(%s AS STRING), ',', 1) AS DOUBLE) ELSE NULL END", docRef, docRef, docRef, docRef)
	docCSVLon := fmt.Sprintf("CASE WHEN TRY_CAST(%s AS STRING) NOT LIKE '[%%' AND TRY_CAST(%s AS STRING) NOT REGEXP '^[[:space:]]*[A-Za-z{]' AND LOCATE(',', TRY_CAST(%s AS STRING)) > 0 THEN TRY_CAST(SPLIT_PART(TRY_CAST(%s AS STRING), ',', 2) AS DOUBLE) ELSE NULL END", docRef, docRef, docRef, docRef)
	latExpr = fmt.Sprintf("COALESCE(TRY_CAST(%s['lat'] AS DOUBLE), %s, TRY_CAST(element_at(TRY_CAST(%s AS ARRAY<DOUBLE>), 2) AS DOUBLE), TRY_CAST(element_at(TRY_CAST(%s['coordinates'] AS ARRAY<DOUBLE>), 2) AS DOUBLE), %s)", docRef, docCSVLat, docRef, docRef, srcLat)
	lonExpr = fmt.Sprintf("COALESCE(TRY_CAST(%s['lon'] AS DOUBLE), %s, TRY_CAST(element_at(TRY_CAST(%s AS ARRAY<DOUBLE>), 1) AS DOUBLE), TRY_CAST(element_at(TRY_CAST(%s['coordinates'] AS ARRAY<DOUBLE>), 1) AS DOUBLE), %s)", docRef, docCSVLon, docRef, docRef, srcLon)
	notNullCond = fmt.Sprintf("%s IS NOT NULL AND %s IS NOT NULL", latExpr, lonExpr)
	return latExpr, lonExpr, notNullCond
}

func (t *Transpiler) compileKNN(kq *esast.KNNQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	return t.compileKNNRound61(kq, scoring, nctx)
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
	if q.Script != nil || q.ScriptScore != nil || QueryHasIntervalsScript(q) {
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
	hasPositive := false
	allPosFalse := true
	hasNegFalse := false

	recordPosClause := func(w string) {
		hasPositive = true
		if w != "FALSE" && w != "(FALSE)" && w != "((FALSE))" {
			allPosFalse = false
		}
	}

	for i := range b.Must {
		c := t.CompileQuery(&b.Must[i], scoring, nctx)
		recordPosClause(c.WhereSQL)
		conjuncts = append(conjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
		safeConjuncts = append(safeConjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
		if scoring {
			scoreTerms = append(scoreTerms, c.ScoreSQL)
			usesFT = usesFT || c.UsesFulltextMatch
		}
	}
	for i := range b.Filter {
		c := t.CompileQuery(&b.Filter[i], false, nctx)
		recordPosClause(c.WhereSQL)
		conjuncts = append(conjuncts, fmt.Sprintf("(%s)", c.WhereSQL))
		safeConjuncts = append(safeConjuncts, fmt.Sprintf("(%s)", c.EffectiveSafeWhere()))
	}
	for i := range b.MustNot {
		c := t.CompileQuery(&b.MustNot[i], false, nctx)
		if queryContainsScript(&b.MustNot[i]) && (c.WhereSQL == "" || c.WhereSQL == "TRUE" || strings.Contains(c.WhereSQL, "(TRUE)")) {
			continue
		}
		var negW string
		if c.UsesFulltextMatch || strings.Contains(c.WhereSQL, "MATCH_") || strings.Contains(c.WhereSQL, "SEARCH(") {
			// Doris BE does not allow MATCH_* inside COALESCE(...)
			negW = negateFulltextWhereSQL(c.WhereSQL)
		} else if c.WhereSQL == "TRUE" || c.WhereSQL == "(TRUE)" {
			negW = "FALSE"
		} else if c.WhereSQL == "FALSE" || c.WhereSQL == "(FALSE)" {
			negW = "TRUE"
		} else {
			negW = fmt.Sprintf("NOT COALESCE(%s, FALSE)", c.WhereSQL)
		}
		if negW == "FALSE" || negW == "(FALSE)" {
			hasNegFalse = true
		}
		conjuncts = append(conjuncts, negW)
		sw := c.EffectiveSafeWhere()
		if strings.Contains(sw, "MATCH_") || strings.Contains(sw, "SEARCH(") {
			safeConjuncts = append(safeConjuncts, negateFulltextWhereSQL(sw))
		} else if sw == "TRUE" || sw == "(TRUE)" {
			safeConjuncts = append(safeConjuncts, "FALSE")
		} else if sw == "FALSE" || sw == "(FALSE)" {
			safeConjuncts = append(safeConjuncts, "TRUE")
		} else {
			safeConjuncts = append(safeConjuncts, fmt.Sprintf("NOT COALESCE(%s, FALSE)", sw))
		}
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
				recordPosClause("FALSE")
				conjuncts = append(conjuncts, "FALSE")
				safeConjuncts = append(safeConjuncts, "FALSE")
			}
		} else if minShould == 1 {
			joined := fmt.Sprintf("(%s)", strings.Join(disjuncts, " OR "))
			recordPosClause(joined)
			conjuncts = append(conjuncts, joined)
			safeConjuncts = append(safeConjuncts, fmt.Sprintf("(%s)", strings.Join(safeDisjuncts, " OR ")))
			usesFT = usesFT || shouldUsesFT
		} else if minShould > 1 {
			if minShould == len(disjuncts) {
				joined := fmt.Sprintf("(%s)", strings.Join(disjuncts, " AND "))
				recordPosClause(joined)
				conjuncts = append(conjuncts, joined)
				safeConjuncts = append(safeConjuncts, fmt.Sprintf("(%s)", strings.Join(safeDisjuncts, " AND ")))
				usesFT = usesFT || shouldUsesFT
			} else {
				var intCasts []string
				for _, sd := range safeDisjuncts {
					intCasts = append(intCasts, fmt.Sprintf("CAST(COALESCE(%s, FALSE) AS INT)", sd))
				}
				msmCond := fmt.Sprintf("((%s) >= %d)", strings.Join(intCasts, " + "), minShould)
				joined := fmt.Sprintf("(%s)", strings.Join(disjuncts, " OR "))
				recordPosClause(joined)
				conjuncts = append(conjuncts, joined, msmCond)
				safeConjuncts = append(safeConjuncts, msmCond)
				usesFT = usesFT || shouldUsesFT
			}
		}
	}

	if hasNegFalse || (hasPositive && allPosFalse) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
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
	case "unsigned_long":
		return schema.DorisLargeInt
	case "date", "date_nanos", "long":
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
	case schema.DorisLargeInt, schema.DorisLargeIntArray:
		if _, err := strconv.ParseUint(s, 10, 64); err == nil {
			return true
		}
		if _, err := strconv.ParseInt(s, 10, 64); err == nil {
			return true
		}
		f, err := strconv.ParseFloat(s, 64)
		return err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
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
		if wordRuneLen < 3 {
			return 0
		}
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
			}
			if wordRuneLen < low {
				return 0
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
	origFuzzyField := field
	resolvedField, b := t.resolveFieldInNestedCtx(field, false, nctx)
	if !t.checkFieldSearchable(resolvedField, b) || t.isNonStandardQueryRestrictedField(origFuzzyField, b, "fuzzy") || b.Kind == schema.StoragePromotedVector {
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
				resolvedField: {Value: pat, Flags: internalRawRE2Flag, CaseInsensitive: caseInsensitive || b.EffectiveLowercase(true), Boost: boost, HasBoost: true},
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
				resolvedField: {Value: pat, Flags: internalRawRE2Flag, CaseInsensitive: true, Boost: boost},
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
				resolvedField: {Value: pat, Flags: internalRawRE2Flag, CaseInsensitive: true, Boost: 1.0},
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
	return t.compileMatchFieldWithAnalyzer(field, queryVal, operator, "", boost, scoring, nctx)
}

func (t *Transpiler) compileMatchFieldWithAnalyzer(
	field string,
	queryVal any,
	operator string,
	explicitAnalyzer string,
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
			return t.compileMatchFieldWithAnalyzer("_all_text", queryVal, operator, explicitAnalyzer, boost, scoring, nctx)
		}
		var disjuncts, safeDisjuncts, scores []string
		usesFT := false
		for _, bf := range exp {
			c := t.compileMatchFieldWithAnalyzer(bf.Field, queryVal, operator, explicitAnalyzer, boost*bf.Boost, scoring, nctx)
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
	if !t.checkFieldSearchable(field, b) || t.isNonStandardQueryRestrictedField(origField, b, "match") || b.Kind == schema.StoragePromotedVector {
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
	if cp, ok := t.compileMatchWithAnalysisGraph(field, queryStr, operator, explicitAnalyzer, "", nil, nil, 0, nil, boost, scoring, nctx); ok {
		return cp
	}
	effAnalyzer := strings.TrimSpace(explicitAnalyzer)
	if effAnalyzer == "" {
		effAnalyzer = effectiveFieldSearchAnalyzer(b)
	}
	if !isExactKeywordField(field, b) {
		filteredTokens, allStopwords := filterStopwordTokens(queryStr, effAnalyzer, "")
		if allStopwords {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if len(filteredTokens) > 0 && len(filteredTokens) < len(strings.Fields(queryStr)) {
			queryStr = strings.Join(filteredTokens, " ")
		}
	}
	if isExactKeywordField(field, b) || b.ESType == "wildcard" {
		if expAn := strings.TrimSpace(explicitAnalyzer); expAn != "" && !strings.EqualFold(expAn, "keyword") && !strings.EqualFold(expAn, "noop") {
			toks := TokenizeByAnalyzer(queryStr, expAn)
			if len(toks) == 0 {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			joinOp := " OR "
			if strings.EqualFold(operator, "and") {
				joinOp = " AND "
			}
			var parts []string
			for _, tok := range toks {
				parts = append(parts, t.compileTermPredicate(field, tok, false, nctx))
			}
			pred := parts[0]
			if len(parts) > 1 {
				pred = "(" + strings.Join(parts, joinOp) + ")"
			}
			score := "0.0"
			if scoring {
				score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
			}
			return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
		}
		if fp, okFP := t.lookupMappedFieldProperty(field, b); okFP && fp.SplitQueriesOnWhitespace != nil && *fp.SplitQueriesOnWhitespace {
			wsToks := strings.Fields(queryStr)
			if len(wsToks) == 0 {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			joinOp := " OR "
			if strings.EqualFold(operator, "and") {
				joinOp = " AND "
			}
			var parts []string
			for _, tok := range wsToks {
				parts = append(parts, t.compileTermPredicate(field, tok, false, nctx))
			}
			pred := parts[0]
			if len(parts) > 1 {
				pred = "(" + strings.Join(parts, joinOp) + ")"
			}
			score := "0.0"
			if scoring {
				kwB := boost
				if t.activeHasKNN {
					kwB = boost * 0.68
				}
				score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, kwB)
			}
			return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
		}
		pred := t.compileTermPredicate(field, queryVal, false, nctx)
		score := "0.0"
		if scoring {
			kwB := boost
			if t.activeHasKNN {
				kwB = boost * 0.68
			}
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, kwB)
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score}
	}

	if !isExactKeywordField(field, b) && strings.EqualFold(effAnalyzer, "whitespace") {
		wsTokens := TokenizeByAnalyzer(queryStr, "whitespace")
		if len(wsTokens) == 0 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		joinOp := " OR "
		if strings.EqualFold(operator, "and") {
			joinOp = " AND "
		}
		var parts []string
		if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
			arrCol := b.EffectiveArrayColumn(false)
			for _, tok := range wsTokens {
				rePat := quoteStr(buildAnalyzedTokenRegex(tok, true))
				parts = append(parts, fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `%s`)", rePat, arrCol))
			}
		} else {
			col := t.sqlColumnRef(field, false, nctx)
			for _, tok := range wsTokens {
				rePat := quoteStr(buildAnalyzedTokenRegex(tok, true))
				parts = append(parts, fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, rePat))
			}
		}
		pred := parts[0]
		if len(parts) > 1 {
			pred = "(" + strings.Join(parts, joinOp) + ")"
		}
		score := "0.0"
		if scoring {
			score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
			if bm25Sc, ok := t.compileBM25MultiTokenMatchScoreR63(field, field, b, wsTokens, true, boost, pred, nctx); ok {
				score = bm25Sc
			}
		}
		return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score, UsesFulltextMatch: false}
	}

	if !isExactKeywordField(field, b) && (effAnalyzer == "" || strings.EqualFold(effAnalyzer, "standard")) {
		uaxTokens := TokenizeByAnalyzer(queryStr, effAnalyzer)
		if hasInternalUnderscoreToken(uaxTokens) {
			joinOp := " OR "
			if strings.EqualFold(operator, "and") {
				joinOp = " AND "
			}
			var parts []string
			if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				arrCol := b.EffectiveArrayColumn(false)
				for _, tok := range uaxTokens {
					rePat := quoteStr(buildAnalyzedTokenRegex(tok, false))
					parts = append(parts, fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `%s`)", rePat, arrCol))
				}
			} else {
				col := t.sqlColumnRef(field, false, nctx)
				for _, tok := range uaxTokens {
					rePat := quoteStr(buildAnalyzedTokenRegex(tok, false))
					parts = append(parts, fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, rePat))
				}
			}
			pred := parts[0]
			if len(parts) > 1 {
				pred = "(" + strings.Join(parts, joinOp) + ")"
			}
			score := "0.0"
			if scoring {
				score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", pred, boost)
				if bm25Sc, ok := t.compileBM25MultiTokenMatchScoreR63(field, field, b, uaxTokens, false, boost, pred, nctx); ok {
					score = bm25Sc
				}
			}
			return CompiledQuery{WhereSQL: pred, SafeWhereSQL: pred, ScoreSQL: score, UsesFulltextMatch: false}
		}
	}

	if b.EffectiveLowercase(false) {
		queryStr = strings.ToLower(queryStr)
	}
	scorePred := t.projectionSafeTextMatchSQL(field, queryStr, operator, nctx)
	score := "0.0"
	if scoring {
		kwB := boost
		if t.activeHasKNN && isExactKeywordField(field, b) {
			kwB = boost * 0.4458
		}
		score = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", scorePred, kwB)
		matchToks := TokenizeByAnalyzer(queryStr, effAnalyzer)
		if len(matchToks) == 0 {
			matchToks = strings.Fields(queryStr)
		}
		if bm25Sc, ok := t.compileBM25MultiTokenMatchScoreR63(field, field, b, matchToks, strings.EqualFold(effAnalyzer, "whitespace"), boost, scorePred, nctx); ok {
			score = bm25Sc
		}
	}

	// Inside nested `array_exists(_el -> ...)` lambdas or on untokenized array / dynamic variant / unindexed doc-values columns, use projection-safe matching.
	if nctx != nil || b.NotIndexed || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield || (b.Kind == schema.StorageDynamicVariant && field != "_all_text" && field != "*") {
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
	origPhraseField := field
	field, b := t.resolveFieldInNestedCtx(field, false, nctx)
	if !t.checkFieldSearchable(field, b) || t.isNonStandardQueryRestrictedField(origPhraseField, b, "match_phrase") || b.Kind == schema.StoragePromotedVector || strings.TrimSpace(queryStr) == "" {
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
		if cp, ok := t.compileMatchPhraseWithAnalysisGraph(field, queryStr, slop, "", "", isPrefix, boost, scoring, nctx); ok {
			return cp
		}
		filteredTokens, allStopwords := filterStopwordTokens(queryStr, b.Analyzer, "")
		if allStopwords {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		if len(filteredTokens) > 0 && len(filteredTokens) < len(strings.Fields(strings.TrimSpace(queryStr))) {
			queryStr = strings.Join(filteredTokens, " ")
		}
		if strings.EqualFold(effectiveFieldSearchAnalyzer(b), "english") {
			if engToks, okEng := analyzeTokensWithBuiltinGraphR63(queryStr, "english"); okEng && len(engToks) > 0 {
				var terms []string
				var posGaps []int
				for i, tk := range engToks {
					terms = append(terms, tk.Term)
					if i > 0 {
						gap := tk.Position - engToks[i-1].Position - 1
						if gap < 0 {
							gap = 0
						}
						posGaps = append(posGaps, gap)
					}
				}
				return t.multiTokenExactPhraseWithStemSQLR66(field, b, terms, posGaps, slop, isPrefix, false, true, boost, scoring, nctx)
			}
		}
	}
	if isPrefix && !isExactKeywordField(field, b) {
		effAn := t.effectiveQueryAnalyzerName(b, "")
		isWS := strings.EqualFold(effAn, "whitespace")
		toks := TokenizeByAnalyzer(queryStr, effAn)
		if len(toks) > 0 {
			cp := t.multiTokenExactPhraseSQL(field, b, toks, slop, true, isWS, boost, scoring, nctx)
			if slop > 0 && len(toks) > 1 {
				var parts []string
				for i := 0; i < len(toks)-1; i++ {
					parts = append(parts, t.singleAnalyzedTokenSQL(field, b, toks[i], isWS, 1.0, false, nctx).WhereSQL)
				}
				parts = append(parts, t.compileAnalyzedTokenOrPhrasePrefixRegex(field, b, toks[len(toks)-1], !isWS, nctx))
				w := "(" + strings.Join(parts, " AND ") + ")"
				sc := "0.0"
				if scoring {
					sc = fmt.Sprintf("(CASE WHEN %s THEN %.4f ELSE 0.0 END)", w, boost)
				}
				return CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: sc}
			}
			if nctx != nil || b.ESType == "search_as_you_type" || b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield || b.Kind == schema.StorageDynamicVariant {
				return cp
			}
			col := t.sqlColumnRef(field, false, nil)
			qStr := queryStr
			if b.EffectiveLowercase(false) {
				qStr = strings.ToLower(qStr)
			}
			pred := fmt.Sprintf("%s MATCH_PHRASE_PREFIX %s", col, quoteStr(qStr))
			return CompiledQuery{WhereSQL: pred, SafeWhereSQL: cp.WhereSQL, ScoreSQL: cp.ScoreSQL, UsesFulltextMatch: true}
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
		if !isPrefix {
			effAn := effectiveFieldSearchAnalyzer(b)
			pToks := TokenizeByAnalyzer(queryStr, effAn)
			if len(pToks) == 0 {
				pToks = strings.Fields(queryStr)
			}
			if bm25Sc, ok := t.compileBM25PhraseScoreR63(origPhraseField, field, b, pToks, strings.EqualFold(effAn, "whitespace"), boost, scorePred, nctx); ok {
				score = bm25Sc
			}
		}
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
		if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
			arrCol := b.EffectiveArrayColumn(true)
			lit := quoteStr(qTrim)
			if b.EffectiveLowercase(true) {
				return fmt.Sprintf("(array_exists(_x -> lower(_x) = lower(%s), `%s`))", lit, arrCol)
			}
			return fmt.Sprintf("(array_exists(_x -> _x = %s, `%s`))", lit, arrCol)
		}
		return "(" + t.compileTermPredicate(field, qTrim, false, nctx) + ")"
	}
	effAnalyzer := effectiveFieldSearchAnalyzer(b)
	isWS := strings.EqualFold(effAnalyzer, "whitespace")
	tokens := strings.Fields(strings.TrimSpace(queryStr))
	if len(tokens) == 0 || operator == "phrase" {
		tokens = []string{strings.TrimSpace(queryStr)}
	}
	joinOp := " OR "
	if strings.EqualFold(operator, "and") {
		joinOp = " AND "
	}

	if operator != "phrase" && (isWS || ((effAnalyzer == "" || strings.EqualFold(effAnalyzer, "standard")) && hasInternalUnderscoreToken(TokenizeByAnalyzer(queryStr, effAnalyzer)))) {
		toks := TokenizeByAnalyzer(queryStr, effAnalyzer)
		if len(toks) > 0 {
			if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				arrCol := b.EffectiveArrayColumn(false)
				var parts []string
				for _, tok := range toks {
					rePat := quoteStr(buildAnalyzedTokenRegex(tok, isWS))
					parts = append(parts, fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `%s`)", rePat, arrCol))
				}
				return "(" + strings.Join(parts, joinOp) + ")"
			}
			col := t.sqlColumnRef(field, false, nctx)
			var parts []string
			for _, tok := range toks {
				rePat := quoteStr(buildAnalyzedTokenRegex(tok, isWS))
				parts = append(parts, fmt.Sprintf("(%s IS NOT NULL AND %s REGEXP %s)", col, col, rePat))
			}
			return "(" + strings.Join(parts, joinOp) + ")"
		}
	}

	if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
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
	if mmType == "bool_prefix" {
		if mm.Slop != 0 {
			if t.searchErr == nil {
				t.searchErr = esTranspilerError("illegal_argument_exception: [slop] not allowed for type [bool_prefix]")
			}
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		allExpanded = t.expandMultiMatchBoolPrefixSAYTFields(allExpanded)
	}

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

	hasCompatibleBoolPrefixField := false
	if mmType == "bool_prefix" && len(allExpanded) > 1 {
		for _, cand := range allExpanded {
			_, cfb := t.resolveFieldInNestedCtx(cand.Field, false, nctx)
			switch cfb.ESType {
			case "byte", "short", "integer", "long", "unsigned_long", "float", "half_float", "scaled_float", "double", "boolean", "date", "date_nanos", "ip":
			default:
				hasCompatibleBoolPrefixField = true
			}
		}
	}

	for _, bf := range allExpanded {
		var c CompiledQuery
		switch mmType {
		case "phrase":
			c = t.compileMatchPhraseField(bf.Field, qStr, mm.Slop, bf.Boost, false, scoring, nctx)
		case "phrase_prefix":
			c = t.compileMatchPhraseField(bf.Field, qStr, mm.Slop, bf.Boost, true, scoring, nctx)
		case "bool_prefix":
			effLenient := mm.Lenient
			if effLenient == nil && hasCompatibleBoolPrefixField {
				tVal := true
				effLenient = &tVal
			}
			autoSyn := mm.AutoGenerateSynonymsPhraseQuery
			if autoSyn == nil {
				autoSyn = t.autoGenSynPhraseQuery
			}
			c = t.compileMatchBoolPrefixRound62Opts(bf.Field, esast.PhraseEntry{
				Query:               qStr,
				Operator:            op,
				Analyzer:            mm.Analyzer,
				ZeroTermsQuery:      mm.ZeroTermsQuery,
				MinimumShouldMatch:  mm.MinimumShouldMatch,
				Fuzziness:           mm.Fuzziness,
				PrefixLength:        mm.PrefixLength,
				FuzzyTranspositions: mm.FuzzyTranspositions,
				Lenient:             effLenient,
				Boost:               bf.Boost,
			}, autoSyn, scoring, nctx)
		default:
			autoSyn := mm.AutoGenerateSynonymsPhraseQuery
			if autoSyn == nil {
				autoSyn = t.autoGenSynPhraseQuery
			}
			if mm.CutoffFrequency > 0 {
				if cp, ok := t.compileCommonTermsQueryR64(bf.Field, qStr, op, "or", mm.CutoffFrequency, mm.MinimumShouldMatch, mm.Analyzer, mm.ZeroTermsQuery, bf.Boost, scoring, nctx, false); ok {
					c = cp
					break
				}
			}
			if cp, ok := t.compileMatchWithAnalysisGraphOpts(bf.Field, qStr, op, mm.Analyzer, mm.ZeroTermsQuery, mm.MinimumShouldMatch, mm.Fuzziness, mm.PrefixLength, mm.FuzzyTranspositions, autoSyn, bf.Boost, scoring, nctx); ok {
				c = cp
			} else if mm.MinimumShouldMatch != nil && mmType != "cross_fields" {
				c = t.CompileQuery(&esast.Query{
					Match: map[string]esast.MatchEntry{
						bf.Field: {
							Query:                           effQuery,
							Operator:                        op,
							Analyzer:                        mm.Analyzer,
							ZeroTermsQuery:                  mm.ZeroTermsQuery,
							MinimumShouldMatch:              mm.MinimumShouldMatch,
							Fuzziness:                       mm.Fuzziness,
							PrefixLength:                    mm.PrefixLength,
							FuzzyTranspositions:             mm.FuzzyTranspositions,
							Lenient:                         mm.Lenient,
							AutoGenerateSynonymsPhraseQuery: autoSyn,
							Boost:                           bf.Boost,
						},
					},
				}, scoring, nctx)
			} else if mm.Fuzziness != nil {
				c = t.compileFuzzyFieldWithOpts(bf.Field, effQuery, op, mm.Fuzziness, false, mm.PrefixLength, mm.FuzzyTranspositions, bf.Boost, scoring, nctx)
			} else {
				c = t.compileMatchFieldWithAnalyzer(bf.Field, effQuery, op, mm.Analyzer, bf.Boost, scoring, nctx)
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

func (t *Transpiler) compileCombinedFields(cf *esast.CombinedFieldsQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if cf == nil {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	effSearchAnalyzer := func(fb schema.FieldBinding) string {
		sa := strings.ToLower(strings.TrimSpace(fb.SearchAnalyzer))
		if sa == "" {
			sa = strings.ToLower(strings.TrimSpace(fb.Analyzer))
		}
		if sa == "" {
			sa = "standard"
		}
		return sa
	}

	var validatedFields []string
	firstAnalyzer := ""
	firstField := ""
	checkResolvedBinding := func(displayName string, fb schema.FieldBinding) bool {
		if !t.checkFieldSearchable(displayName, fb) {
			return false
		}
		if fb.ESType != "" && fb.ESType != "text" && fb.ESType != "match_only_text" {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: combined_fields query only supports [text] fields, saw [%s] of type [%s]", displayName, fb.ESType)
			}
			return false
		}
		if fb.ESType == "text" || fb.ESType == "match_only_text" {
			sa := effSearchAnalyzer(fb)
			if firstAnalyzer == "" {
				firstAnalyzer = sa
				firstField = displayName
			} else if sa != firstAnalyzer {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: Cannot search with [combined_fields] query since fields [%s] and [%s] have different search analyzers [%s] vs [%s]", firstField, displayName, firstAnalyzer, sa)
				}
				return false
			}
		}
		return true
	}

	if len(cf.Fields) == 0 {
		if t.Schema != nil && len(t.Schema.Fields) > 0 {
			for _, bf := range t.expandFieldPatternForContext("*", nctx) {
				_, fb := t.resolveFieldInNestedCtx(bf.Field, false, nctx)
				if fb.ESType == "text" || fb.ESType == "match_only_text" {
					if !checkResolvedBinding(bf.Field, fb) {
						return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
					}
					validatedFields = append(validatedFields, bf.Field)
				}
			}
			if len(validatedFields) == 0 {
				validatedFields = []string{"_all_text"}
			}
		} else {
			validatedFields = []string{"_all_text"}
		}
	} else {
		for _, fpat := range cf.Fields {
			cleanPat, boost := parseFieldBoost(fpat, 1.0)
			if strings.ContainsAny(cleanPat, "*?") && t.Schema != nil {
				exp := t.expandFieldPatternForContext(fpat, nctx)
				if cleanPat == "*" {
					for _, bf := range exp {
						_, fb := t.resolveFieldInNestedCtx(bf.Field, false, nctx)
						if fb.ESType == "text" || fb.ESType == "match_only_text" || fb.ESType == "" {
							if !checkResolvedBinding(bf.Field, fb) {
								return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
							}
							if bf.Boost != 1.0 {
								validatedFields = append(validatedFields, fmt.Sprintf("%s^%g", bf.Field, bf.Boost))
							} else {
								validatedFields = append(validatedFields, bf.Field)
							}
						}
					}
					continue
				}
				for _, bf := range exp {
					_, fb := t.resolveFieldInNestedCtx(bf.Field, false, nctx)
					if !checkResolvedBinding(bf.Field, fb) {
						return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
					}
					if bf.Boost != 1.0 {
						validatedFields = append(validatedFields, fmt.Sprintf("%s^%g", bf.Field, bf.Boost))
					} else {
						validatedFields = append(validatedFields, bf.Field)
					}
				}
				continue
			}
			resolved, fb := t.resolveFieldInNestedCtx(cleanPat, false, nctx)
			if !checkResolvedBinding(resolved, fb) {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
			if boost != 1.0 {
				validatedFields = append(validatedFields, fmt.Sprintf("%s^%g", cleanPat, boost))
			} else {
				validatedFields = append(validatedFields, cleanPat)
			}
		}
	}

	return t.compileMultiMatch(&esast.MultiMatchQuery{
		Query:              cf.Query,
		Fields:             validatedFields,
		Type:               "cross_fields",
		Operator:           cf.Operator,
		Analyzer:           firstAnalyzer,
		MinimumShouldMatch: cf.MinimumShouldMatch,
		ZeroTermsQuery:     cf.ZeroTermsQuery,
		Boost:              cf.Boost,
	}, scoring, nctx)
}

func unwrapOuterBalancedSQLParens(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		inSingle := false
		inDouble := false
		inBacktick := false
		balancedOuter := true
		for i := 0; i < len(s); i++ {
			ch := s[i]
			if inSingle {
				if ch == '\\' && i+1 < len(s) {
					i++
					continue
				}
				if ch == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i++
						continue
					}
					inSingle = false
				}
				continue
			}
			if inDouble {
				if ch == '\\' && i+1 < len(s) {
					i++
					continue
				}
				if ch == '"' {
					inDouble = false
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
			case '"':
				inDouble = true
			case '`':
				inBacktick = true
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i < len(s)-1 {
					balancedOuter = false
				}
			}
			if !balancedOuter {
				break
			}
		}
		if !balancedOuter || depth != 0 {
			break
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

func isSQLIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func splitTopLevelSQLBoolOp(s, op string) []string {
	opLen := len(op)
	var parts []string
	depth := 0
	bracketDepth := 0
	inSingle := false
	inDouble := false
	inBacktick := false
	lastSplit := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inSingle {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inDouble {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == '"' {
				inDouble = false
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
		case '"':
			inDouble = true
		case '`':
			inBacktick = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		default:
			if depth == 0 && bracketDepth == 0 && i+opLen <= len(s) && strings.EqualFold(s[i:i+opLen], op) {
				prevOK := i > 0 && !isSQLIdentByte(s[i-1]) && s[i-1] != '`'
				nextOK := i+opLen < len(s) && !isSQLIdentByte(s[i+opLen]) && s[i+opLen] != '`'
				if prevOK && nextOK {
					// Watch out for `BETWEEN x AND y`: check if preceding segment has top-level `BETWEEN`
					if strings.EqualFold(op, "AND") && hasUnclosedTopLevelBetween(s[lastSplit:i]) {
						continue
					}
					parts = append(parts, strings.TrimSpace(s[lastSplit:i]))
					i += opLen - 1
					lastSplit = i + 1
				}
			}
		}
	}
	if len(parts) == 0 {
		return nil
	}
	parts = append(parts, strings.TrimSpace(s[lastSplit:]))
	return parts
}

func hasUnclosedTopLevelBetween(seg string) bool {
	depth := 0
	inSingle := false
	inBacktick := false
	for i := 0; i < len(seg); i++ {
		ch := seg[i]
		if inSingle {
			if ch == '\\' && i+1 < len(seg) {
				i++
				continue
			}
			if ch == '\'' {
				if i+1 < len(seg) && seg[i+1] == '\'' {
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
			if depth == 0 && i+7 <= len(seg) && strings.EqualFold(seg[i:i+7], "BETWEEN") {
				prevOK := i == 0 || !isSQLIdentByte(seg[i-1])
				nextOK := i+7 == len(seg) || !isSQLIdentByte(seg[i+7])
				if prevOK && nextOK {
					return true
				}
			}
		}
	}
	return false
}

func findTopLevelMatchOperatorIndex(s string) int {
	depth := 0
	bracketDepth := 0
	inSingle := false
	inDouble := false
	inBacktick := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inSingle {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inDouble {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == '"' {
				inDouble = false
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
		case '"':
			inDouble = true
		case '`':
			inBacktick = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		default:
			if depth == 0 && bracketDepth == 0 && i+6 < len(s) && strings.EqualFold(s[i:i+6], "MATCH_") {
				prevOK := i > 0 && !isSQLIdentByte(s[i-1]) && s[i-1] != '`'
				if prevOK {
					return i
				}
			}
		}
	}
	return -1
}

func negateFulltextWhereSQL(whereSQL string) string {
	trimmed := unwrapOuterBalancedSQLParens(whereSQL)
	if trimmed == "" || strings.EqualFold(trimmed, "TRUE") {
		return "FALSE"
	}
	if strings.EqualFold(trimmed, "FALSE") {
		return "TRUE"
	}
	if orParts := splitTopLevelSQLBoolOp(trimmed, "OR"); len(orParts) > 1 {
		negParts := make([]string, 0, len(orParts))
		for _, p := range orParts {
			negParts = append(negParts, negateFulltextWhereSQL(p))
		}
		return "(" + strings.Join(negParts, " AND ") + ")"
	}
	if andParts := splitTopLevelSQLBoolOp(trimmed, "AND"); len(andParts) > 1 {
		negParts := make([]string, 0, len(andParts))
		for _, p := range andParts {
			negParts = append(negParts, negateFulltextWhereSQL(p))
		}
		return "(" + strings.Join(negParts, " OR ") + ")"
	}
	if len(trimmed) > 3 && strings.EqualFold(trimmed[:3], "NOT") && !isSQLIdentByte(trimmed[3]) {
		rest := strings.TrimSpace(trimmed[3:])
		if strings.HasPrefix(strings.ToUpper(rest), "COALESCE(") {
			return rest
		}
		if strings.Contains(rest, "MATCH_") || strings.Contains(rest, "SEARCH(") {
			return "(" + unwrapOuterBalancedSQLParens(rest) + ")"
		}
	}
	if idx := findTopLevelMatchOperatorIndex(trimmed); idx > 0 {
		lhs := strings.TrimSpace(trimmed[:idx])
		if lhs != "" {
			return fmt.Sprintf("(%s IS NULL OR NOT (%s))", lhs, trimmed)
		}
	}
	if strings.HasPrefix(strings.ToUpper(trimmed), "SEARCH(") || strings.Contains(trimmed, "MATCH_") || strings.Contains(trimmed, "SEARCH(") {
		return fmt.Sprintf("NOT (%s)", trimmed)
	}
	return fmt.Sprintf("NOT COALESCE((%s), FALSE)", trimmed)
}

func (t *Transpiler) compileNestedWithParent(nq *esast.NestedQuery, scoring bool, parentNctx *nestedCtx) CompiledQuery {
	if parentNctx == nil && nq != nil {
		if cp, ok := t.compileNestedKNNQueryR63(nq, scoring); ok {
			return cp
		}
	}
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
			scoreSQL = fmt.Sprintf("(CASE WHEN (%s) < 0.0 THEN -1e308 ELSE (%s) END)", expr, expr)
			scriptCompiled = true
		}
	}
	if ss.Boost != nil && *ss.Boost != 1.0 {
		scoreSQL = fmt.Sprintf("(CASE WHEN (%s) <= -1e307 THEN -1e308 ELSE (%.4f * (%s)) END)", scoreSQL, *ss.Boost, scoreSQL)
	}
	whereSQL := base.WhereSQL
	safeWhereSQL := base.EffectiveSafeWhere()
	if ss.MinScore != nil && (ss.Script == nil || scriptCompiled) && !queryContainsScript(ss.Query) && !queryContainsNestedScoring(ss.Query) {
		minScoreCond := fmt.Sprintf("((%s >= %.4f) OR (%s <= -1e307))", scoreSQL, *ss.MinScore, scoreSQL)
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
					rawStr := fmt.Sprintf("%v", entry.Value)
					if startNum, endNum, isCIDR := parseCIDRBounds(rawStr); isCIDR {
						parts = append(parts, fmt.Sprintf("array_exists(_x -> IPV4_STRING_TO_NUM_OR_NULL(_x) >= %d AND IPV4_STRING_TO_NUM_OR_NULL(_x) <= %d, `%s`)", startNum, endNum, arrCol))
						continue
					}
					if startHex, endHex, isV6CIDR := parseIPv6CIDRHexBounds(rawStr); isV6CIDR {
						parts = append(parts, fmt.Sprintf("array_exists(_x -> HEX(IPV6_STRING_TO_NUM_OR_NULL(_x)) >= %s AND HEX(IPV6_STRING_TO_NUM_OR_NULL(_x)) <= %s, `%s`)", quoteStr(startHex), quoteStr(endHex), arrCol))
						continue
					}
				}
				if b.ESType == "version" {
					if strVal, ok := entry.Value.(string); ok && schema.ValidateSemver(strVal) {
						cleanVer := strings.SplitN(strings.TrimSpace(strVal), "+", 2)[0]
						parts = append(parts, fmt.Sprintf("array_exists(_x -> %s = %s, `%s`)", sqlStripSemverBuildExpr("_x"), quoteStr(cleanVer), arrCol))
					}
					continue
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
				if b.ESType == "version" {
					var verQuoted []string
					for _, v := range vals {
						if s, ok := v.(string); ok && schema.ValidateSemver(s) {
							verQuoted = append(verQuoted, quoteStr(strings.SplitN(strings.TrimSpace(s), "+", 2)[0]))
						}
					}
					if len(verQuoted) > 0 {
						parts = append(parts, fmt.Sprintf("array_exists(_x -> %s IN (%s), `%s`)", sqlStripSemverBuildExpr("_x"), strings.Join(verQuoted, ", "), arrCol))
					}
					continue
				}
				if b.ESType == "ip" {
					hasCIDR := false
					var ipQuoted []string
					for _, v := range vals {
						rawStr := fmt.Sprintf("%v", v)
						if _, _, isCIDR := parseCIDRBounds(rawStr); isCIDR {
							hasCIDR = true
							break
						}
						if _, _, isV6CIDR := parseIPv6CIDRHexBounds(rawStr); isV6CIDR {
							hasCIDR = true
							break
						}
						if ip := net.ParseIP(strings.TrimSpace(rawStr)); ip != nil {
							ipQuoted = append(ipQuoted, quoteStr(ip.String()))
						}
					}
					if hasCIDR {
						continue
					}
					if len(ipQuoted) > 0 {
						parts = append(parts, fmt.Sprintf("arrays_overlap(`%s`, [%s])", arrCol, strings.Join(ipQuoted, ", ")))
					}
					continue
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
	if b.ESType == "ip" {
		ip := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", val)))
		if ip == nil {
			return "", false
		}
		return ip.String(), true
	}
	if strVal, ok := val.(string); ok {
		if effLower && effDT != schema.DorisBigInt && effDT != schema.DorisLargeInt && effDT != schema.DorisInt && effDT != schema.DorisDouble && b.ESType != "date" && b.ESType != "date_nanos" {
			val = strings.ToLower(strVal)
		} else if b.ESType == "date" || b.ESType == "date_nanos" || (b.ESType == "" && effDT == schema.DorisBigInt) {
			ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, b.Format, now)
			if !ok {
				return "", false
			}
			val = ms
		} else if effDT == schema.DorisBigInt || effDT == schema.DorisLargeInt || effDT == schema.DorisInt {
			trimmed := strings.TrimSpace(strVal)
			if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				if b.ESType == "unsigned_long" && iv < 0 {
					return "", false
				}
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
		if effDT == schema.DorisBigInt || effDT == schema.DorisLargeInt || effDT == schema.DorisInt {
			if iv, err := tv.Int64(); err == nil {
				if b.ESType == "unsigned_long" && iv < 0 {
					return "", false
				}
				return strconv.FormatInt(iv, 10), true
			}
			if b.ESType == "unsigned_long" {
				if u, err := strconv.ParseUint(tv.String(), 10, 64); err == nil {
					return strconv.FormatUint(u, 10), true
				}
				return "", false
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
	var domainSentinelConds []string
	hasUnfilteredFunc := false
	for _, fn := range funcs {
		weight := 1.0
		if fn.Weight != nil {
			weight = *fn.Weight
		}
		if weight < 0 && t.searchErr == nil {
			t.searchErr = fmt.Errorf("illegal_argument_exception: weight in function_score must be non-negative, got [%v]", weight)
		}
		valExpr := fmt.Sprintf("%.4f", weight)
		canProduceSentinel := false
		if fn.ScriptScore != nil && fn.ScriptScore.Script != nil {
			if scriptExpr, ok := t.compileMetricScriptExprWithOverride(fn.ScriptScore.Script, "_score", base.ScoreSQL, nctx); ok {
				if fn.Weight != nil {
					valExpr = fmt.Sprintf("(CASE WHEN (%s) < 0.0 THEN -1e308 ELSE (%.4f * (%s)) END)", scriptExpr, weight, scriptExpr)
				} else {
					valExpr = fmt.Sprintf("(CASE WHEN (%s) < 0.0 THEN -1e308 ELSE (%s) END)", scriptExpr, scriptExpr)
				}
				canProduceSentinel = true
			}
		} else if fn.FieldValueFactor != nil {
			fvf := fn.FieldValueFactor
			col := t.sqlNumericColumnRef(fvf.Field, nctx)
			factor := 1.0
			if fvf.Factor != nil {
				factor = *fvf.Factor
			}
			colOrMissing := col
			if fvf.Missing != nil {
				colOrMissing = fmt.Sprintf("COALESCE(%s, %.4f)", col, *fvf.Missing)
			}
			scaled := fmt.Sprintf("(%.4f * %s)", factor, colOrMissing)
			var modExpr string
			switch strings.ToLower(fvf.Modifier) {
			case "log":
				modExpr = fmt.Sprintf("(CASE WHEN %s <= 0.0 THEN -1e308 ELSE LOG10(GREATEST(1e-300, %s)) END)", scaled, scaled)
			case "log1p":
				modExpr = fmt.Sprintf("(CASE WHEN %s <= -1.0 THEN -1e308 ELSE LOG10(GREATEST(1e-300, 1.0 + %s)) END)", scaled, scaled)
			case "log2p":
				modExpr = fmt.Sprintf("(CASE WHEN %s <= -2.0 THEN -1e308 ELSE LOG10(GREATEST(1e-300, 2.0 + %s)) END)", scaled, scaled)
			case "ln":
				modExpr = fmt.Sprintf("(CASE WHEN %s <= 0.0 THEN -1e308 ELSE LN(GREATEST(1e-300, %s)) END)", scaled, scaled)
			case "ln1p":
				modExpr = fmt.Sprintf("(CASE WHEN %s <= -1.0 THEN -1e308 ELSE LN(GREATEST(1e-300, 1.0 + %s)) END)", scaled, scaled)
			case "ln2p":
				modExpr = fmt.Sprintf("(CASE WHEN %s <= -2.0 THEN -1e308 ELSE LN(GREATEST(1e-300, 2.0 + %s)) END)", scaled, scaled)
			case "square":
				modExpr = fmt.Sprintf("((%s) * (%s))", scaled, scaled)
			case "sqrt":
				modExpr = fmt.Sprintf("(CASE WHEN %s < 0.0 THEN -1e308 ELSE SQRT(GREATEST(0.0, %s)) END)", scaled, scaled)
			case "reciprocal":
				modExpr = fmt.Sprintf("(CASE WHEN %s <= 0.0 THEN -1e308 ELSE (1.0 / GREATEST(1e-300, %s)) END)", scaled, scaled)
			case "", "none":
				modExpr = scaled
			default:
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: Unknown modifier [%s] for field_value_factor", fvf.Modifier)
				}
				modExpr = scaled
			}
			weightedFVF := fmt.Sprintf("(CASE WHEN (%s) < 0.0 THEN -1e308 ELSE (%.4f * %s) END)", modExpr, weight, modExpr)
			if fvf.Missing == nil {
				valExpr = fmt.Sprintf("(CASE WHEN %s IS NULL THEN 0.0 ELSE %s END)", col, weightedFVF)
			} else {
				valExpr = weightedFVF
			}
			canProduceSentinel = true
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
				elseVal = "-1e300"
			} else if scoreMode == "min" {
				elseVal = "1e308"
			}
			fExpr := fmt.Sprintf("(CASE WHEN %s THEN %s ELSE %s END)", condExpr, valExpr, elseVal)
			funcExprs = append(funcExprs, fExpr)
			if canProduceSentinel {
				domainSentinelConds = append(domainSentinelConds, fmt.Sprintf("(%s <= -1e307)", fExpr))
			}
		} else {
			hasUnfilteredFunc = true
			filterCondExprs = append(filterCondExprs, "")
			funcExprs = append(funcExprs, valExpr)
			if canProduceSentinel {
				domainSentinelConds = append(domainSentinelConds, fmt.Sprintf("(%s <= -1e307)", valExpr))
			}
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
	if len(domainSentinelConds) > 0 {
		finalScore = fmt.Sprintf("(CASE WHEN (%s) THEN -1e308 ELSE %s END)", strings.Join(domainSentinelConds, " OR "), finalScore)
	}
	whereSQL := base.WhereSQL
	safeWhereSQL := base.EffectiveSafeWhere()
	if fs.MinScore != nil && !hasUncompilableScriptFn && !queryContainsScript(fs.Query) && !queryContainsNestedScoring(fs.Query) {
		minScoreCond := fmt.Sprintf("(%s >= %.4f)", finalScore, *fs.MinScore)
		if len(domainSentinelConds) > 0 {
			minScoreCond = fmt.Sprintf("((%s >= %.4f) OR (%s <= -1e307))", finalScore, *fs.MinScore, finalScore)
		}
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
			latExpr := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
			lonExpr := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
			notNullCond = fmt.Sprintf("%s IS NOT NULL", elemExpr)
			distExpr = fmt.Sprintf("COALESCE(ST_Distance_Sphere(%s, %s, %s, %s), 0.0)", lonExpr, latExpr, tLonStr, tLatStr)
		} else if isArrayField {
			arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
			notNullCond = fmt.Sprintf("(%s IS NOT NULL AND array_size(%s) > 0)", arrCol, arrCol)
			arrFn := resolveDecayArrayFn(df.MultiValueMode)
			distExpr = fmt.Sprintf("COALESCE(%s(array_map(_x -> ST_Distance_Sphere(TRY_CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE), TRY_CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE), %s, %s), %s)), 0.0)", arrFn, tLonStr, tLatStr, arrCol)
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
			distExpr = fmt.Sprintf("COALESCE(%s(array_map(_x -> ABS(TRY_CAST(_x AS DOUBLE) - %.4f), %s)), 0.0)", arrFn, float64(originMs), arrCol)
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
			distExpr = fmt.Sprintf("COALESCE(%s(array_map(_x -> ABS(TRY_CAST(_x AS DOUBLE) - %.4f), %s)), 0.0)", arrFn, originNum, arrCol)
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
		arrExpr = fmt.Sprintf("array_exists(_x -> lower(_x) = %s, TRY_CAST(`_doc`%s AS ARRAY<STRING>))", quoteStr(strVal), pathBuilder.String())
	} else {
		arrExpr = fmt.Sprintf("array_contains(TRY_CAST(`_doc`%s AS ARRAY<STRING>), %s)", pathBuilder.String(), quoteStr(strVal))
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
	if IsSubpathUnderAggregateMetricDoubleR63(t.Schema, origField) {
		return "FALSE"
	}
	if origField == "_ignored" && nctx == nil {
		if val == nil {
			return "FALSE"
		}
		qVal := quoteStr(fmt.Sprintf("%v", val))
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), `_ignored`)", qVal)
		}
		return fmt.Sprintf("array_contains(`_ignored`, %s)", qVal)
	}
	isSAYTSub := strings.HasSuffix(origField, "._2gram") || strings.HasSuffix(origField, "._3gram") || strings.HasSuffix(origField, "._4gram") || strings.HasSuffix(origField, "._index_prefix")
	preferKW := !t.Opts.StrictTextTermRouting || strings.HasSuffix(origField, ".keyword") || isSAYTSub
	field, b := t.resolveFieldInNestedCtx(field, preferKW, nctx)
	if !t.checkFieldSearchable(field, b) || t.isNonStandardQueryRestrictedField(origField, b, "term") || b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	if b.ESType == "murmur3" {
		hv, okH := CoerceMurmur3TermValueR63(val)
		if !okH {
			return "FALSE"
		}
		val = hv
	}
	if b.IsVirtualSAYTSubfield && strings.HasSuffix(origField, "._index_prefix") {
		return t.compileSAYTIndexPrefixTerm(origField, b, val, caseInsensitive, nctx)
	}
	if b.IsVirtualSAYTSubfield && (strings.HasSuffix(origField, "._2gram") || strings.HasSuffix(origField, "._3gram") || strings.HasSuffix(origField, "._4gram")) {
		if val == nil {
			return "FALSE"
		}
		rawTerm := fmt.Sprintf("%v", val)
		if strings.TrimSpace(rawTerm) == "" {
			return "FALSE"
		}
		effAn := t.effectiveQueryAnalyzerName(b, "")
		caseSens := !caseInsensitive && !b.EffectiveLowercase(false)
		if effCfg := t.effectiveAnalysisConfig(); effCfg != nil {
			anCaseSens, _ := analyzerCaseAndWhitespaceFlagsR63(effAn, effCfg, t.Opts.AnalysisOpts)
			if caseInsensitive {
				caseSens = false
			} else {
				caseSens = anCaseSens
			}
		} else if strings.EqualFold(effAn, "whitespace") || strings.EqualFold(effAn, "keyword") || strings.EqualFold(effAn, "noop") {
			caseSens = !caseInsensitive
		}
		if arrCol := b.EffectiveArrayColumn(false); arrCol != "" && nctx == nil {
			if caseSens {
				return fmt.Sprintf("array_contains(`%s`, %s)", arrCol, quoteStr(rawTerm))
			}
			return fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), `%s`)", quoteStr(rawTerm), arrCol)
		}
		return t.compileMatchPhraseField(field, rawTerm, 0, 1.0, false, false, nctx).WhereSQL
	}
	if b.ESType == "sparse_vector" {
		if svCP, handled := t.compileSparseVectorTermQueryR63(origField, val, 1.0, false, nctx); handled {
			return svCP.WhereSQL
		}
	}
	if b.ESType == "search_as_you_type" && strings.HasSuffix(origField, "._index_prefix") {
		return t.compilePrefixPredicate(field, fmt.Sprintf("%v", val), true, nctx)
	}
	if b.ESType == "search_as_you_type" && !b.IsVirtualSAYTSubfield && !strings.HasSuffix(origField, "._index_prefix") {
		if val == nil {
			return "FALSE"
		}
		rawTerm := fmt.Sprintf("%v", val)
		if strings.TrimSpace(rawTerm) == "" {
			return "FALSE"
		}
		if !strings.EqualFold(b.Analyzer, "keyword") && !strings.EqualFold(b.Analyzer, "noop") && strings.ContainsAny(rawTerm, " \t\r\n") {
			return "FALSE"
		}
		return t.compileMatchField(field, rawTerm, "and", 1.0, false, nctx).WhereSQL
	}
	if strVal, isStr := val.(string); isStr && t.fieldNormalizerName(field, b) != "" && t.effectiveAnalysisConfig() != nil {
		val = t.normalizeKeywordOrAnalyzerTerm(strVal, b, caseInsensitive)
	}
	if _, rtType, isRT := t.resolveScriptlessRuntimeField(origField); isRT && nctx == nil && rtType == "keyword" && val != nil {
		arrExpr := sqlRuntimeSourceArrayExpr(origField)
		qVal := quoteStr(fmt.Sprintf("%v", val))
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), %s)", qVal, arrExpr)
		}
		return fmt.Sprintf("array_contains(%s, %s)", arrExpr, qVal)
	}
	if b.ESType == "long_range" && nctx == nil {
		return t.compileLongRangeOnRangeFieldR65(field, b, esast.RangeCond{
			GTE:      val,
			LTE:      val,
			Relation: "INTERSECTS",
		})
	}
	if schema.IsRangeFieldType(b.ESType) {
		qf, ok := coerceRangeFieldQueryScalar(val, b, b.Format, 0, false, false)
		if !ok {
			return "FALSE"
		}
		qLit := strconv.FormatFloat(qf, 'f', -1, 64)
		return t.compileRangePredOnRangeField(field, b, nctx, func(lowerSQL, upperSQL string) []string {
			return []string{
				fmt.Sprintf("%s <= %s", lowerSQL, qLit),
				fmt.Sprintf("%s >= %s", upperSQL, qLit),
			}
		})
	}
	if b.ESType == "ip" {
		if strVal, ok := val.(string); ok {
			if startHex, endHex, isCIDR := parseCanonicalIPCIDRHexBounds(strVal); isCIDR {
				sLit, eLit := quoteStr(startHex), quoteStr(endHex)
				if b.Kind == schema.StorageNestedSubfield && nctx != nil && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
					rawCol := t.sqlColumnRef(field, true, nctx)
					hexElem := sqlCanonicalIPHexExpr("_x")
					return fmt.Sprintf("array_exists(_x -> %s >= %s AND %s <= %s, TRY_CAST(%s AS ARRAY<STRING>))", hexElem, sLit, hexElem, eLit, rawCol)
				}
				if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) {
					colName := b.EffectiveArrayColumn(true)
					hexElem := sqlCanonicalIPHexExpr("_x")
					return fmt.Sprintf("array_exists(_x -> %s >= %s AND %s <= %s, `%s`)", hexElem, sLit, hexElem, eLit, colName)
				}
				rawCol := t.sqlColumnRef(field, true, nctx)
				hexCol := sqlCanonicalIPHexExpr(rawCol)
				return fmt.Sprintf("(%s >= %s AND %s <= %s)", hexCol, sLit, hexCol, eLit)
			}
		}
		ip := net.ParseIP(strings.TrimSpace(fmt.Sprintf("%v", val)))
		if ip == nil {
			return "FALSE"
		}
		val = ip.String()
	}
	if b.ESType == "version" {
		strVal, ok := val.(string)
		if !ok || !schema.ValidateSemver(strVal) {
			return "FALSE"
		}
		cleanVer := strings.SplitN(strings.TrimSpace(strVal), "+", 2)[0]
		if b.IgnoreAbove > 0 && len([]rune(strings.TrimSpace(strVal))) > b.IgnoreAbove {
			return "FALSE"
		}
		qVer := quoteStr(cleanVer)
		switch b.Kind {
		case schema.StoragePromotedVector:
			return "FALSE"
		case schema.StoragePromotedArray:
			return fmt.Sprintf("array_exists(_x -> %s = %s, `%s`)", sqlStripSemverBuildExpr("_x"), qVer, b.EffectiveArrayColumn(true))
		case schema.StorageNestedSubfield:
			if nctx != nil && nctx.nestedPath == b.NestedPath {
				rawCol := t.sqlColumnRef(field, true, nctx)
				if b.IsMultiValued {
					return fmt.Sprintf("array_exists(_x -> %s = %s, TRY_CAST(%s AS ARRAY<STRING>))", sqlStripSemverBuildExpr("_x"), qVer, rawCol)
				}
				return fmt.Sprintf("%s = %s", sqlStripSemverBuildExpr(rawCol), qVer)
			}
			if b.PrefilterArrayCol != "" {
				return fmt.Sprintf("array_exists(_x -> %s = %s, `%s`)", sqlStripSemverBuildExpr("_x"), qVer, b.EffectiveArrayColumn(true))
			}
		}
		rawCol := t.sqlColumnRef(field, true, nctx)
		return fmt.Sprintf("%s = %s", sqlStripSemverBuildExpr(rawCol), qVer)
	}
	if b.ESType == "text" && b.KeywordCompanion == "" && !strings.HasSuffix(field, ".keyword") {
		if _, isBool := val.(bool); isBool {
			return t.compileMatchField(field, fmt.Sprintf("%v", val), "or", 1.0, false, nctx).WhereSQL
		}
	}
	if textPred, _, _, handled := t.compileAnalyzedTextTermPredicateR63(origField, field, b, val, caseInsensitive, nctx); handled {
		return textPred
	}
	effLower := b.EffectiveLowercase(true)
	effDT := effectiveDorisScalarType(b)
	if _, isBool := val.(bool); isBool && b.ESType != "" && effDT != schema.DorisBoolean && effDT != schema.DorisString && effDT != schema.DorisVarchar {
		return "FALSE"
	}
	if b.ESType == "date_nanos" {
		ns, ok := parseDateNanosQueryScalar(val, b.Format, 0, time.Now().UTC(), false)
		if !ok {
			return "FALSE"
		}
		val = ns
	} else if effDT == schema.DorisBoolean {
		if bv, ok := normalizeBooleanQueryValue(val); ok {
			val = bv
		} else if b.ESType != "" {
			return "FALSE"
		}
	} else if b.ESType == "date" && b.Format != "" && !strings.Contains(strings.ToLower(b.Format), "epoch_millis") && val != nil {
		if strVal, isStr := val.(string); isStr {
			if ms, ok := schema.ParseESDateWithFormatAndLocaleToEpochMillis(strVal, b.Format, b.Locale, time.Now().UTC()); ok {
				val = ms
			} else if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
				val = iv
			} else {
				return "FALSE"
			}
		} else {
			numStr := ""
			switch nv := val.(type) {
			case int:
				numStr = strconv.Itoa(nv)
			case int64:
				numStr = strconv.FormatInt(nv, 10)
			case float64:
				if !math.IsNaN(nv) && !math.IsInf(nv, 0) && nv == math.Trunc(nv) {
					numStr = strconv.FormatInt(int64(nv), 10)
				}
			case json.Number:
				numStr = nv.String()
			}
			if numStr != "" {
				if ms, ok := schema.ParseESDateWithFormatAndLocaleToEpochMillis(numStr, b.Format, b.Locale, time.Now().UTC()); ok {
					val = ms
				}
			}
		}
	} else if strVal, ok := val.(string); ok {
		if effLower && effDT != schema.DorisBigInt && effDT != schema.DorisLargeInt && effDT != schema.DorisInt && effDT != schema.DorisDouble && b.ESType != "date" && b.ESType != "date_nanos" {
			val = strings.ToLower(strVal)
		} else if b.ESType == "date" || (b.ESType == "" && effDT == schema.DorisBigInt) {
			if ms, ok := schema.ParseESDateWithFormatAndLocaleToEpochMillis(strVal, b.Format, b.Locale, time.Now().UTC()); ok {
				val = ms
			} else if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
				val = iv
			} else if b.ESType == "date" {
				return "FALSE"
			}
		} else if effDT == schema.DorisBigInt || effDT == schema.DorisLargeInt || effDT == schema.DorisInt {
			trimmed := strings.TrimSpace(strVal)
			if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				if b.ESType == "unsigned_long" {
					if iv < 0 {
						return "FALSE"
					}
					val = uint64(iv)
				} else {
					val = iv
				}
			} else if b.ESType == "unsigned_long" {
				if u, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
					val = u
				} else if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= 0 && fv < 18446744073709551616.0 && fv == math.Trunc(fv) {
					val = uint64(fv)
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
	} else if b.ESType == "unsigned_long" {
		switch nv := val.(type) {
		case int:
			if nv < 0 {
				return "FALSE"
			}
			val = uint64(nv)
		case int64:
			if nv < 0 {
				return "FALSE"
			}
			val = uint64(nv)
		case uint64:
			val = nv
		case float64:
			if math.IsNaN(nv) || math.IsInf(nv, 0) || nv < 0 || nv != math.Trunc(nv) || nv >= 18446744073709551616.0 {
				return "FALSE"
			}
			val = uint64(nv)
		case json.Number:
			if u, err := strconv.ParseUint(nv.String(), 10, 64); err == nil {
				val = u
			} else if iv, err := nv.Int64(); err == nil {
				if iv < 0 {
					return "FALSE"
				}
				val = uint64(iv)
			} else if fv, err := nv.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= 0 && fv == math.Trunc(fv) && fv < 18446744073709551616.0 {
				val = uint64(fv)
			} else {
				return "FALSE"
			}
		}
	} else if nv, ok := val.(json.Number); ok && (effDT == schema.DorisBigInt || effDT == schema.DorisLargeInt || effDT == schema.DorisInt) {
		if iv, err := nv.Int64(); err == nil {
			val = iv
		} else if b.ESType != "" {
			return "FALSE"
		}
	}
	val = normalizeScaledFloatValue(b, val)
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
		if !t.isBoundToNestedCtx(field, b, nctx) {
			colName := b.EffectiveArrayColumn(true)
			if b.DorisType == schema.DorisLargeInt || b.DorisType == schema.DorisLargeIntArray {
				return fmt.Sprintf("array_contains(`%s`, TRY_CAST(%s AS LARGEINT))", colName, quoteValue(val))
			}
			if caseInsensitive && !effLower {
				return fmt.Sprintf("array_exists(_x -> lower(_x) = lower(%s), `%s`)", quoteStr(fmt.Sprintf("%v", val)), colName)
			}
			return fmt.Sprintf("array_contains(`%s`, %s)", colName, quoteStr(fmt.Sprintf("%v", val)))
		}
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
				return fmt.Sprintf("(lower(%s) = lower(%s) OR array_exists(_x -> lower(_x) = lower(%s), TRY_CAST(%s AS ARRAY<STRING>)))", col, lit, strLit, rawVar)
			}
			return fmt.Sprintf("(%s = %s OR array_contains(TRY_CAST(%s AS ARRAY<STRING>), %s))", col, lit, rawVar, strLit)
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
	maxTerms := 65536
	if t.Schema != nil && t.Schema.MaxTermsCount > 0 {
		maxTerms = t.Schema.MaxTermsCount
	}
	if len(vals) > maxTerms {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("illegal_argument_exception: The number of terms [%d] used in the TermsQuery request has exceeded the allowed maximum of [%d]. This maximum can be set by changing the [index.max_terms_count] index level setting", len(vals), maxTerms)
		}
		return "FALSE"
	}
	for _, elem := range vals {
		if elem == nil {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: Terms cannot contain null")
			}
			return "FALSE"
		}
	}
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
	if IsSubpathUnderAggregateMetricDoubleR63(t.Schema, origField) {
		return "FALSE"
	}
	if origField == "_ignored" && nctx == nil {
		var qVals []string
		for _, v := range vals {
			if v == nil {
				continue
			}
			s := fmt.Sprintf("%v", v)
			if caseInsensitive {
				s = strings.ToLower(s)
			}
			qVals = append(qVals, quoteStr(s))
		}
		if len(qVals) == 0 {
			return "FALSE"
		}
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) IN (%s), `_ignored`)", strings.Join(qVals, ", "))
		}
		return fmt.Sprintf("arrays_overlap(`_ignored`, [%s])", strings.Join(qVals, ", "))
	}
	if nctx == nil {
		if _, rtType, isRT := t.resolveScriptlessRuntimeField(origField); isRT && rtType == "keyword" {
			var qVals []string
			for _, v := range vals {
				if v == nil {
					continue
				}
				s := fmt.Sprintf("%v", v)
				if caseInsensitive {
					s = strings.ToLower(s)
				}
				qVals = append(qVals, quoteStr(s))
			}
			if len(qVals) == 0 {
				return "FALSE"
			}
			arrExpr := sqlRuntimeSourceArrayExpr(origField)
			if caseInsensitive {
				return fmt.Sprintf("array_exists(_x -> lower(_x) IN (%s), %s)", strings.Join(qVals, ", "), arrExpr)
			}
			return fmt.Sprintf("arrays_overlap(%s, [%s])", arrExpr, strings.Join(qVals, ", "))
		}
	}
	isSAYTSub := strings.HasSuffix(origField, "._2gram") || strings.HasSuffix(origField, "._3gram") || strings.HasSuffix(origField, "._4gram") || strings.HasSuffix(origField, "._index_prefix")
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if !t.checkFieldSearchable(field, b) || t.isNonStandardQueryRestrictedField(origField, b, "terms") || b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	if (b.IsVirtualSAYTSubfield || b.ESType == "search_as_you_type") && strings.HasSuffix(origField, "._index_prefix") {
		var disjuncts []string
		for _, v := range vals {
			disjuncts = append(disjuncts, t.compileSAYTIndexPrefixTerm(origField, b, v, caseInsensitive, nctx))
		}
		if len(disjuncts) == 0 {
			return "FALSE"
		}
		if len(disjuncts) == 1 {
			return disjuncts[0]
		}
		return "(" + strings.Join(disjuncts, " OR ") + ")"
	}
	if (isSAYTSub && b.IsVirtualSAYTSubfield && !strings.HasSuffix(origField, "._index_prefix")) || schema.IsRangeFieldType(b.ESType) || b.ESType == "flattened" || b.ESType == "murmur3" || b.ESType == "aggregate_metric_double" || ((b.ESType == "text" || b.ESType == "match_only_text") && b.KeywordCompanion == "" && !strings.HasSuffix(origField, ".keyword") && !strings.EqualFold(b.Analyzer, "keyword") && !strings.EqualFold(b.Analyzer, "noop")) {
		var disjuncts []string
		for _, v := range vals {
			disjuncts = append(disjuncts, t.compileTermPredicate(origField, v, caseInsensitive, nctx))
		}
		if len(disjuncts) == 1 {
			return disjuncts[0]
		}
		return "(" + strings.Join(disjuncts, " OR ") + ")"
	}
	if b.ESType == "version" {
		var quotedVers []string
		for _, v := range vals {
			strVal, ok := v.(string)
			if !ok || !schema.ValidateSemver(strVal) {
				continue
			}
			if b.IgnoreAbove > 0 && len([]rune(strings.TrimSpace(strVal))) > b.IgnoreAbove {
				continue
			}
			cleanVer := strings.SplitN(strings.TrimSpace(strVal), "+", 2)[0]
			quotedVers = append(quotedVers, quoteStr(cleanVer))
		}
		if len(quotedVers) == 0 {
			return "FALSE"
		}
		inList := strings.Join(quotedVers, ", ")
		switch b.Kind {
		case schema.StoragePromotedVector:
			return "FALSE"
		case schema.StoragePromotedArray:
			return fmt.Sprintf("array_exists(_x -> %s IN (%s), `%s`)", sqlStripSemverBuildExpr("_x"), inList, b.EffectiveArrayColumn(true))
		case schema.StorageNestedSubfield:
			if nctx != nil && nctx.nestedPath == b.NestedPath {
				rawCol := t.sqlColumnRef(field, true, nctx)
				if b.IsMultiValued {
					return fmt.Sprintf("array_exists(_x -> %s IN (%s), TRY_CAST(%s AS ARRAY<STRING>))", sqlStripSemverBuildExpr("_x"), inList, rawCol)
				}
				return fmt.Sprintf("%s IN (%s)", sqlStripSemverBuildExpr(rawCol), inList)
			}
			if b.PrefilterArrayCol != "" {
				return fmt.Sprintf("array_exists(_x -> %s IN (%s), `%s`)", sqlStripSemverBuildExpr("_x"), inList, b.EffectiveArrayColumn(true))
			}
		}
		rawCol := t.sqlColumnRef(field, true, nctx)
		return fmt.Sprintf("%s IN (%s)", sqlStripSemverBuildExpr(rawCol), inList)
	}
	if b.ESType == "ip" {
		var canonIPs []any
		var cidrVals []string
		for _, v := range vals {
			rawStr := strings.TrimSpace(fmt.Sprintf("%v", v))
			if v == nil || rawStr == "" {
				continue
			}
			if _, _, isCIDR := parseCanonicalIPCIDRHexBounds(rawStr); isCIDR {
				cidrVals = append(cidrVals, rawStr)
				continue
			}
			if ip := net.ParseIP(rawStr); ip != nil {
				canonIPs = append(canonIPs, ip.String())
			}
		}
		if len(canonIPs) == 0 && len(cidrVals) == 0 {
			return "FALSE"
		}
		if len(cidrVals) > 0 {
			var disjuncts []string
			if len(canonIPs) > 0 {
				if ipPred := t.compileTermsPredicateWithCI(field, canonIPs, false, nctx); ipPred != "" && ipPred != "FALSE" {
					disjuncts = append(disjuncts, ipPred)
				}
			}
			for _, cidr := range cidrVals {
				if cPred := t.compileTermPredicate(field, cidr, false, nctx); cPred != "" && cPred != "FALSE" {
					disjuncts = append(disjuncts, cPred)
				}
			}
			if len(disjuncts) == 0 {
				return "FALSE"
			}
			if len(disjuncts) == 1 {
				return disjuncts[0]
			}
			return "(" + strings.Join(disjuncts, " OR ") + ")"
		}
		vals = canonIPs
	}
	effLower := b.EffectiveLowercase(true) || caseInsensitive
	isArrayCol := !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield)
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
		if b.ESType == "date_nanos" {
			ns, ok := parseDateNanosQueryScalar(v, b.Format, 0, now, false)
			if !ok {
				continue
			}
			v = ns
		} else if effDT == schema.DorisBoolean {
			if bv, ok := normalizeBooleanQueryValue(v); ok {
				v = bv
			} else if b.ESType != "" {
				continue
			}
		} else if strVal, ok := v.(string); ok {
			if (effLower || (t.fieldNormalizerName(field, b) != "" && t.effectiveAnalysisConfig() != nil)) && effDT != schema.DorisBigInt && effDT != schema.DorisLargeInt && effDT != schema.DorisInt && effDT != schema.DorisDouble && b.ESType != "date" && b.ESType != "date_nanos" {
				v = t.normalizeKeywordOrAnalyzerTerm(strVal, b, effLower)
			} else if b.ESType == "date" || (b.ESType == "" && effDT == schema.DorisBigInt) {
				if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, b.Format, now); ok {
					v = ms
				} else if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
					v = iv
				} else if b.ESType == "date" {
					continue
				}
			} else if effDT == schema.DorisBigInt || effDT == schema.DorisLargeInt || effDT == schema.DorisInt {
				trimmed := strings.TrimSpace(strVal)
				if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
					if b.ESType == "unsigned_long" {
						if iv < 0 {
							continue
						}
						v = uint64(iv)
					} else {
						v = iv
					}
				} else if b.ESType == "unsigned_long" {
					if u, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
						v = u
					} else if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= 0 && fv < 18446744073709551616.0 && fv == math.Trunc(fv) {
						v = uint64(fv)
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
		} else if b.ESType == "unsigned_long" {
			switch nv := v.(type) {
			case int:
				if nv < 0 {
					continue
				}
				v = uint64(nv)
			case int64:
				if nv < 0 {
					continue
				}
				v = uint64(nv)
			case uint64:
				v = nv
			case float64:
				if math.IsNaN(nv) || math.IsInf(nv, 0) || nv < 0 || nv != math.Trunc(nv) || nv >= 18446744073709551616.0 {
					continue
				}
				v = uint64(nv)
			case json.Number:
				if u, err := strconv.ParseUint(nv.String(), 10, 64); err == nil {
					v = u
				} else if iv, err := nv.Int64(); err == nil {
					if iv < 0 {
						continue
					}
					v = uint64(iv)
				} else if fv, err := nv.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= 0 && fv == math.Trunc(fv) && fv < 18446744073709551616.0 {
					v = uint64(fv)
				} else {
					continue
				}
			}
		} else if nv, ok := v.(json.Number); ok && (effDT == schema.DorisBigInt || effDT == schema.DorisLargeInt || effDT == schema.DorisInt) {
			if iv, err := nv.Int64(); err == nil {
				v = iv
			} else if b.ESType != "" {
				continue
			}
		}
		v = normalizeScaledFloatValue(b, v)
		normalizedVals = append(normalizedVals, v)
		if isArrayCol {
			if b.Kind == schema.StoragePromotedArray && (b.DorisType == schema.DorisLargeInt || b.DorisType == schema.DorisLargeIntArray) {
				quoted = append(quoted, fmt.Sprintf("TRY_CAST(%s AS LARGEINT)", quoteValue(v)))
			} else {
				quoted = append(quoted, quoteStr(fmt.Sprintf("%v", v)))
			}
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
	origField := field
	if IsSubpathUnderAggregateMetricDoubleR63(t.Schema, origField) {
		return "FALSE"
	}
	if origField == "_ignored" && nctx == nil {
		likePat := quoteStr(escapeLikeLiteral(val) + "%")
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `_ignored`)", likePat)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, `_ignored`)", likePat)
	}
	if pfxSQL, handled := t.compileAnalyzedFieldPrefix(origField, val, caseInsensitive, nctx); handled {
		return pfxSQL
	}
	if nctx == nil {
		if _, rtType, isRT := t.resolveScriptlessRuntimeField(origField); isRT && rtType == "keyword" {
			likePat := quoteStr(escapeLikeLiteral(val) + "%")
			arrExpr := sqlRuntimeSourceArrayExpr(origField)
			if caseInsensitive {
				return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), %s)", likePat, arrExpr)
			}
			return fmt.Sprintf("array_exists(_x -> _x LIKE %s, %s)", likePat, arrExpr)
		}
	}
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if !t.checkFieldSearchable(field, b) || t.isNonStandardQueryRestrictedField(origField, b, "prefix") || b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	effLower := b.EffectiveLowercase(true)
	val = t.normalizeKeywordOrAnalyzerTerm(val, b, effLower)
	likePat := quoteStr(escapeLikeLiteral(val) + "%")
	if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
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
				return fmt.Sprintf("(lower(%s) LIKE lower(%s) OR array_exists(_x -> lower(_x) LIKE lower(%s), TRY_CAST(%s AS ARRAY<STRING>)))", col, likePat, likePat, rawVar)
			}
			return fmt.Sprintf("(%s LIKE %s OR array_exists(_x -> _x LIKE %s, TRY_CAST(%s AS ARRAY<STRING>)))", col, likePat, likePat, rawVar)
		}
	}
	if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
		if caseInsensitive || effLower {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), TRY_CAST(%s AS ARRAY<STRING>))", likePat, col)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, TRY_CAST(%s AS ARRAY<STRING>))", likePat, col)
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
	origField := field
	if IsSubpathUnderAggregateMetricDoubleR63(t.Schema, origField) {
		return "FALSE"
	}
	if origField == "_ignored" && nctx == nil {
		likePat := quoteStr(wildcardToLike(val))
		if caseInsensitive {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), `_ignored`)", likePat)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, `_ignored`)", likePat)
	}
	if nctx == nil {
		if _, rtType, isRT := t.resolveScriptlessRuntimeField(origField); isRT && rtType == "keyword" {
			likePat := quoteStr(wildcardToLike(val))
			arrExpr := sqlRuntimeSourceArrayExpr(origField)
			if caseInsensitive {
				return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), %s)", likePat, arrExpr)
			}
			return fmt.Sprintf("array_exists(_x -> _x LIKE %s, %s)", likePat, arrExpr)
		}
	}
	if !strings.HasSuffix(origField, ".keyword") {
		rawField, rawB := t.resolveFieldInNestedCtx(origField, false, nctx)
		if !strings.HasSuffix(rawB.AliasTarget, ".keyword") && schema.IsTextLikeESType(rawB.ESType) && rawB.ESType != "completion" {
			effAn := effectiveFieldSearchAnalyzer(rawB)
			if !strings.EqualFold(effAn, "keyword") {
				if !t.checkFieldSearchable(rawField, rawB) || t.isNonStandardQueryRestrictedField(origField, rawB, "wildcard") || rawB.Kind == schema.StoragePromotedVector {
					return "FALSE"
				}
				rePat := buildAnalyzedTextWildcardRegex(val, effAn, caseInsensitive)
				if rePat == "$^" {
					return "FALSE"
				}
				qPat := quoteStr(rePat)
				if !t.isBoundToNestedCtx(rawField, rawB, nctx) && (rawB.Kind == schema.StoragePromotedArray || rawB.Kind == schema.StorageNestedSubfield) {
					arrCol := rawB.EffectiveArrayColumn(false)
					return fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, `%s`)", qPat, arrCol)
				}
				col := t.sqlColumnRef(rawField, false, nctx)
				if nctx != nil && rawB.Kind == schema.StorageNestedSubfield && nctx.nestedPath == rawB.NestedPath && rawB.IsMultiValued {
					return fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND _x REGEXP %s, TRY_CAST(%s AS ARRAY<STRING>))", qPat, col)
				}
				return fmt.Sprintf("%s REGEXP %s", col, qPat)
			}
		}
	}
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if !t.checkFieldSearchable(field, b) || t.isNonStandardQueryRestrictedField(origField, b, "wildcard") || b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	effLower := b.EffectiveLowercase(true)
	if effLower {
		val = strings.ToLower(val)
	}
	likePat := quoteStr(wildcardToLike(val))
	if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
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
				return fmt.Sprintf("(lower(%s) LIKE lower(%s) OR array_exists(_x -> lower(_x) LIKE lower(%s), TRY_CAST(%s AS ARRAY<STRING>)))", col, likePat, likePat, rawVar)
			}
			return fmt.Sprintf("(%s LIKE %s OR array_exists(_x -> _x LIKE %s, TRY_CAST(%s AS ARRAY<STRING>)))", col, likePat, likePat, rawVar)
		}
	}
	if nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued {
		if caseInsensitive || effLower {
			return fmt.Sprintf("array_exists(_x -> lower(_x) LIKE lower(%s), TRY_CAST(%s AS ARRAY<STRING>))", likePat, col)
		}
		return fmt.Sprintf("array_exists(_x -> _x LIKE %s, TRY_CAST(%s AS ARRAY<STRING>))", likePat, col)
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

func isPureDigitsASCII(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func leftPadDigits20(seg string) string {
	trimmed := strings.TrimLeft(seg, "0")
	if trimmed == "" {
		trimmed = "0"
	}
	if len(trimmed) < 20 {
		return strings.Repeat("0", 20-len(trimmed)) + trimmed
	}
	return trimmed
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
	if len(parts) == 0 {
		return "~" + strings.TrimSpace(v)
	}
	for _, p := range parts {
		if !isPureDigitsASCII(p) {
			return "~" + strings.TrimSpace(v)
		}
	}
	padCore := func(i int) string {
		if i >= len(parts) || parts[i] == "" {
			return strings.Repeat("0", 20)
		}
		if isPureDigitsASCII(parts[i]) {
			return leftPadDigits20(parts[i])
		}
		return "z:" + parts[i]
	}
	nSegs := len(parts)
	if nSegs < 3 {
		nSegs = 3
	}
	// Join major.minor.patch with '.', and prefix any 4th+ numeric release segments with '~'
	// (0x7E > '-' 0x2D) so `1.2.3-rc.1` < `1.2.3` (`...0003~`) < `1.2.3.4-rc.1` < `1.2.3.4` (`...0003~...0004~`).
	coreJoined := padCore(0) + "." + padCore(1) + "." + padCore(2)
	for i := 3; i < nSegs; i++ {
		coreJoined += "~" + padCore(i)
	}
	if hasPre {
		preSegs := strings.Split(prerelease, ".")
		for i, seg := range preSegs {
			if isPureDigitsASCII(seg) {
				preSegs[i] = "0:" + leftPadDigits20(seg)
			} else {
				preSegs[i] = "1:" + seg
			}
		}
		// Space (' ', ASCII 0x20 < '0') separates pre-release identifiers so shorter prefix sets
		// (e.g., `1.0.0-alpha`) strictly precede longer sets (`1.0.0-alpha.1`) per SemVer 2.0.0 §11.4.4.
		return fmt.Sprintf("%s-%s", coreJoined, strings.Join(preSegs, " "))
	}
	return coreJoined + "~"
}

// FormatSemverSortKey returns a lexicographically ordered SemVer 2.0.0 sort key string.
func FormatSemverSortKey(v string) string {
	return formatSemverBoundKey(v)
}

// CompareSemverStrings compares two Semantic Versioning 2.0.0 strings according to SemVer §11
// (ignoring `+build` metadata, numeric < non-numeric pre-release precedence, shorter < longer
// pre-release prefix sets, and pre-release < normal release).
func CompareSemverStrings(a, b string) int {
	ka := formatSemverBoundKey(a)
	kb := formatSemverBoundKey(b)
	return strings.Compare(ka, kb)
}

func sqlStripSemverBuildExpr(expr string) string {
	return fmt.Sprintf("COALESCE(SPLIT_PART(%s, '+', 1), %s)", expr, expr)
}

func sqlSemverSortKeyExpr(colExpr string) string {
	noBuild := fmt.Sprintf("COALESCE(SPLIT_PART(%s, '+', 1), %s, '')", colExpr, colExpr)
	core := fmt.Sprintf("COALESCE(SPLIT_PART(%s, '-', 1), %s, '')", noBuild, noBuild)
	c1 := fmt.Sprintf("COALESCE(SPLIT_PART(%s, '.', 1), %s, '')", core, core)
	c2 := fmt.Sprintf("COALESCE(SPLIT_PART(%s, '.', 2), '')", core)
	c3 := fmt.Sprintf("COALESCE(SPLIT_PART(%s, '.', 3), '')", core)
	c4 := fmt.Sprintf("COALESCE(SPLIT_PART(%s, '.', 4), '')", core)
	c5 := fmt.Sprintf("COALESCE(SPLIT_PART(%s, '.', 5), '')", core)
	maj := fmt.Sprintf("LPAD(IF(%s = '', '0', %s), 20, '0')", c1, c1)
	minV := fmt.Sprintf("LPAD(IF(%s = '', '0', %s), 20, '0')", c2, c2)
	pat := fmt.Sprintf("LPAD(IF(%s = '', '0', %s), 20, '0')", c3, c3)
	ext4 := fmt.Sprintf("IF(%s = '', '', CONCAT('~', LPAD(%s, 20, '0')))", c4, c4)
	ext5 := fmt.Sprintf("IF(%s = '', '', CONCAT('~', LPAD(%s, 20, '0')))", c5, c5)
	preRaw := fmt.Sprintf("COALESCE(SUBSTRING(%s, LOCATE('-', %s) + 1), '')", noBuild, noBuild)
	var preParts []string
	for k := 1; k <= 8; k++ {
		var seg string
		if k == 1 {
			seg = fmt.Sprintf("COALESCE(SPLIT_PART(%s, '.', 1), %s, '')", preRaw, preRaw)
		} else {
			seg = fmt.Sprintf("COALESCE(SPLIT_PART(%s, '.', %d), '')", preRaw, k)
		}
		padded := fmt.Sprintf("IF(%s REGEXP '^[0-9]+$', CONCAT('0:', LPAD(%s, 20, '0')), CONCAT('1:', %s))", seg, seg, seg)
		if k == 1 {
			preParts = append(preParts, padded)
		} else {
			preParts = append(preParts, fmt.Sprintf("IF(%s = '', '', CONCAT(' ', %s))", seg, padded))
		}
	}
	preJoined := fmt.Sprintf("CONCAT(%s)", strings.Join(preParts, ", "))
	pre := fmt.Sprintf("IF(LOCATE('-', %s) > 0, CONCAT('-', %s), '~')", noBuild, preJoined)
	validKey := fmt.Sprintf("CONCAT(%s, '.', %s, '.', %s, %s, %s, %s)", maj, minV, pat, ext4, ext5, pre)
	return fmt.Sprintf("IF(%s IS NULL, NULL, IF(%s REGEXP '^[0-9]+(\\\\.[0-9]+)*$', %s, CONCAT('~', %s)))", colExpr, core, validKey, colExpr)
}

func sqlExactHistogramPercentileBranch(fullAggName, pctKey, hVal, hCnt, hArrExpr, wCond string, q float64) string {
	return fmt.Sprintf(
		"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, "+
			"CAST(COALESCE(MIN(CASE WHEN `_cum_w` + 0.000000001 >= %.6f * `_tot_w` THEN "+
			"CASE WHEN ABS(`_cum_w` - %.6f * `_tot_w`) <= 0.000000001 THEN (`_hv` + COALESCE(`_next_hv`, `_hv`)) / 2.0 ELSE `_hv` END "+
			"ELSE NULL END), MAX(`_hv`), 0) AS DOUBLE) AS `_doc_count` "+
			"FROM (SELECT `_hv`, "+
			"SUM(`_hw`) OVER (ORDER BY `_hv` ASC ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS `_cum_w`, "+
			"SUM(`_hw`) OVER () AS `_tot_w`, "+
			"LEAD(`_hv`) OVER (ORDER BY `_hv` ASC) AS `_next_hv` "+
			"FROM (SELECT %s AS `_hv`, SUM(%s) AS `_hw` FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_ht` AS `_helem`%s GROUP BY `_hv`) `_hbins`) `_hwcum` HAVING COUNT(`_hv`) > 0",
		quoteStr(fullAggName), quoteStr(pctKey), q, q, hVal, hCnt, hArrExpr, wCond,
	)
}

func sqlExactHistogramSubPercentileBranch(subFullPctKey, parentBucketExpr, hVal, hCnt, subFrom, subWhere string, q float64) string {
	return fmt.Sprintf(
		"SELECT %s AS `_agg_name`, `_bucket_key`, "+
			"CAST(COALESCE(MIN(CASE WHEN `_cum_w` + 0.000000001 >= %.6f * `_tot_w` THEN "+
			"CASE WHEN ABS(`_cum_w` - %.6f * `_tot_w`) <= 0.000000001 THEN (`_hv` + COALESCE(`_next_hv`, `_hv`)) / 2.0 ELSE `_hv` END "+
			"ELSE NULL END), MAX(`_hv`), 0) AS DOUBLE) AS `_doc_count` "+
			"FROM (SELECT `_bucket_key`, `_hv`, "+
			"SUM(`_hw`) OVER (PARTITION BY `_bucket_key` ORDER BY `_hv` ASC ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS `_cum_w`, "+
			"SUM(`_hw`) OVER (PARTITION BY `_bucket_key`) AS `_tot_w`, "+
			"LEAD(`_hv`) OVER (PARTITION BY `_bucket_key` ORDER BY `_hv` ASC) AS `_next_hv` "+
			"FROM (SELECT %s AS `_bucket_key`, %s AS `_hv`, SUM(%s) AS `_hw` FROM %s WHERE %s GROUP BY `_bucket_key`, `_hv`) `_hbins`) `_hwcum` GROUP BY `_bucket_key` HAVING COUNT(`_hv`) > 0",
		quoteStr(subFullPctKey), q, q, parentBucketExpr, hVal, hCnt, subFrom, subWhere,
	)
}

func (t *Transpiler) compileRangeSingleField(field string, rc esast.RangeCond, nctx *nestedCtx) string {
	gt, gte, lt, lte := rc.NormalizedBounds()
	if gt == nil && gte == nil && lt == nil && lte == nil {
		return t.compileExistsPredicate(field, nctx)
	}
	origField := field
	if IsSubpathUnderAggregateMetricDoubleR63(t.Schema, origField) {
		return "FALSE"
	}
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if !t.checkFieldSearchable(field, b) || t.isNonStandardQueryRestrictedField(origField, b, "range") || b.Kind == schema.StoragePromotedVector {
		return "FALSE"
	}
	if schema.IsRangeFieldType(b.ESType) {
		return t.compileRangeOnRangeField(field, b, rc, nctx)
	}
	if b.ESType == "histogram" {
		conds := []string{
			"_x IS NOT NULL",
			"_x != ''",
			"TRY_CAST(SPLIT_PART(_x, ',', 2) AS BIGINT) > 0",
		}
		addHistBound := func(op string, cand any) bool {
			if cand == nil {
				return true
			}
			fv, ok := parseFiniteFloatValue(cand)
			if !ok {
				if !t.inLenientQuery && t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: invalid numeric range bound [%v] for histogram field [%s]", cand, field)
				}
				return false
			}
			conds = append(conds, fmt.Sprintf("TRY_CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE) %s %s", op, strconv.FormatFloat(fv, 'f', -1, 64)))
			return true
		}
		if !addHistBound(">", gt) || !addHistBound(">=", gte) || !addHistBound("<", lt) || !addHistBound("<=", lte) {
			return "FALSE"
		}
		return fmt.Sprintf("array_exists(_x -> (%s), %s)", strings.Join(conds, " AND "), t.histogramArrayExpr(field, b, nctx))
	}
	if b.ESType == "version" {
		normVerBound := func(cand any) (string, bool) {
			if cand == nil {
				return "", true
			}
			return NormalizeESVersionRangeBoundR63(cand)
		}
		var gtVer, gteVer, ltVer, lteVer string
		var okV bool
		if gtVer, okV = normVerBound(gt); !okV {
			if !t.inLenientQuery && t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: invalid version range bound [%v] for field [%s]", gt, field)
			}
			return "FALSE"
		}
		if gteVer, okV = normVerBound(gte); !okV {
			if !t.inLenientQuery && t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: invalid version range bound [%v] for field [%s]", gte, field)
			}
			return "FALSE"
		}
		if ltVer, okV = normVerBound(lt); !okV {
			if !t.inLenientQuery && t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: invalid version range bound [%v] for field [%s]", lt, field)
			}
			return "FALSE"
		}
		if lteVer, okV = normVerBound(lte); !okV {
			if !t.inLenientQuery && t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: invalid version range bound [%v] for field [%s]", lte, field)
			}
			return "FALSE"
		}
		if gt != nil {
			gt = gtVer
		}
		if gte != nil {
			gte = gteVer
		}
		if lt != nil {
			lt = ltVer
		}
		if lte != nil {
			lte = lteVer
		}
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
				return fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND %s, TRY_CAST(%s AS ARRAY<STRING>))", strings.Join(elemParts, " AND "), rawCol)
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
			if cand == nil {
				continue
			}
			if _, ok := parseIPToUpperHex16(cand); !ok {
				if !t.inLenientQuery && t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: '%v' is not an IP string literal", cand)
				}
				return "FALSE"
			}
		}
		isNestedMultiVal := nctx != nil && b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath && b.IsMultiValued
		if b.Kind == schema.StoragePromotedArray || (b.Kind == schema.StorageNestedSubfield && (nctx == nil || nctx.nestedPath != b.NestedPath)) || isNestedMultiVal {
			colName := b.EffectiveArrayColumn(true)
			hexElem := sqlCanonicalIPHexExpr("_x")
			var elemParts []string
			if gt != nil {
				if h, ok := parseIPToUpperHex16(gt); ok {
					elemParts = append(elemParts, fmt.Sprintf("%s > %s", hexElem, quoteStr(h)))
				}
			}
			if gte != nil {
				if h, ok := parseIPToUpperHex16(gte); ok {
					elemParts = append(elemParts, fmt.Sprintf("%s >= %s", hexElem, quoteStr(h)))
				}
			}
			if lt != nil {
				if h, ok := parseIPToUpperHex16(lt); ok {
					elemParts = append(elemParts, fmt.Sprintf("%s < %s", hexElem, quoteStr(h)))
				}
			}
			if lte != nil {
				if h, ok := parseIPToUpperHex16(lte); ok {
					elemParts = append(elemParts, fmt.Sprintf("%s <= %s", hexElem, quoteStr(h)))
				}
			}
			if len(elemParts) == 0 {
				return "TRUE"
			}
			if isNestedMultiVal {
				rawCol := t.sqlColumnRef(field, true, nctx)
				return fmt.Sprintf("array_exists(_x -> %s, TRY_CAST(%s AS ARRAY<STRING>))", strings.Join(elemParts, " AND "), rawCol)
			}
			return fmt.Sprintf("array_exists(_x -> %s, `%s`)", strings.Join(elemParts, " AND "), colName)
		}
		rawCol := t.sqlColumnRef(field, true, nctx)
		hexCol := sqlCanonicalIPHexExpr(rawCol)
		var parts []string
		if gt != nil {
			if h, ok := parseIPToUpperHex16(gt); ok {
				parts = append(parts, fmt.Sprintf("%s > %s", hexCol, quoteStr(h)))
			}
		}
		if gte != nil {
			if h, ok := parseIPToUpperHex16(gte); ok {
				parts = append(parts, fmt.Sprintf("%s >= %s", hexCol, quoteStr(h)))
			}
		}
		if lt != nil {
			if h, ok := parseIPToUpperHex16(lt); ok {
				parts = append(parts, fmt.Sprintf("%s < %s", hexCol, quoteStr(h)))
			}
		}
		if lte != nil {
			if h, ok := parseIPToUpperHex16(lte); ok {
				parts = append(parts, fmt.Sprintf("%s <= %s", hexCol, quoteStr(h)))
			}
		}
		if len(parts) == 0 {
			return "TRUE"
		}
		return strings.Join(parts, " AND ")
	}
	now := time.Now().UTC()
	if !t.inQueryString && b.ESType != "" && b.ESType != "date" && b.ESType != "date_nanos" && b.ESType != "date_range" && strings.TrimSpace(rc.TimeZone) != "" {
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: range query does not support [time_zone] on non-date fields")
		}
		return "FALSE"
	}
	effFormat := rc.Format
	if effFormat == "" {
		effFormat = b.Format
	}
	isEpochSecond := strings.EqualFold(effFormat, "epoch_second")
	tzOffsetMs := esast.ParseTimeZoneOffsetMs(strings.TrimSpace(rc.TimeZone))

	switch b.ESType {
	case "date_nanos":
		parseNanosBound := func(cand any, roundUp bool) (any, bool) {
			if cand == nil {
				return nil, true
			}
			ns, ok := parseDateNanosQueryScalar(cand, effFormat, tzOffsetMs, now, roundUp)
			if !ok {
				if !t.inLenientQuery && t.searchErr == nil {
					t.searchErr = fmt.Errorf("parse_exception: failed to parse date field [%v] with format [%s]", cand, effFormat)
				}
				return nil, false
			}
			return ns, true
		}
		var ok bool
		if gt, ok = parseNanosBound(gt, true); !ok {
			return "FALSE"
		}
		if gte, ok = parseNanosBound(gte, false); !ok {
			return "FALSE"
		}
		if lt, ok = parseNanosBound(lt, false); !ok {
			return "FALSE"
		}
		if lte, ok = parseNanosBound(lte, true); !ok {
			return "FALSE"
		}
	case "unsigned_long":
		var okU bool
		gt, gte, lt, lte, okU = normalizeUnsignedLongRangeBounds(gt, gte, lt, lte)
		if !okU {
			return "FALSE"
		}
	default:
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
			case schema.DorisBigInt, schema.DorisLargeInt:
				if effFormat != "" && (b.ESType == "date" || rc.Format != "") && (!strings.Contains(strings.ToLower(effFormat), "epoch") || strings.Contains(strings.ToLower(effFormat), "basic_date")) {
					switch iv := v.(type) {
					case int, int64, json.Number:
						if ms, ok := schema.ParseESDateBoundWithFormatAndLocaleToEpochMillis(fmt.Sprintf("%v", iv), effFormat, b.Locale, now, roundUp); ok {
							if tzOffsetMs != 0 && !strings.Contains(strings.ToLower(effFormat), "epoch") {
								ms -= tzOffsetMs
							}
							return ms
						}
					case float64:
						if !math.IsNaN(iv) && !math.IsInf(iv, 0) && iv == math.Trunc(iv) && iv >= float64(math.MinInt64) && iv < 9223372036854775808.0 {
							if ms, ok := schema.ParseESDateBoundWithFormatAndLocaleToEpochMillis(strconv.FormatInt(int64(iv), 10), effFormat, b.Locale, now, roundUp); ok {
								if tzOffsetMs != 0 && !strings.Contains(strings.ToLower(effFormat), "epoch") {
									ms -= tzOffsetMs
								}
								return ms
							}
						}
					}
				}
				if strVal, ok := v.(string); ok {
					trimmed := strings.TrimSpace(strVal)
					if effFormat != "" && (b.ESType == "date" || rc.Format != "") {
						if ms, ok := schema.ParseESDateBoundWithFormatAndLocaleToEpochMillis(strVal, effFormat, b.Locale, now, roundUp); ok {
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
							return ms
						}
					}
					if b.ESType == "date" || rc.Format != "" {
						if ms, ok := schema.ParseESDateBoundWithFormatAndLocaleToEpochMillis(strVal, effFormat, b.Locale, now, roundUp); ok {
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
							return ms
						}
					}
					if !isEpochSecond {
						if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
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
						return int64(rawSec)
					}
					if b.ESType == "" {
						if ms, ok := schema.ParseESDateBoundWithFormatAndLocaleToEpochMillis(strVal, effFormat, b.Locale, now, roundUp); ok {
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
							return ms
						}
					}
				}
				if nv, ok := v.(json.Number); ok && !isEpochSecond {
					if iv, err := nv.Int64(); err == nil {
						return iv
					}
					if b.ESType == "unsigned_long" {
						if u, err := strconv.ParseUint(nv.String(), 10, 64); err == nil {
							return u
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
	}

	if foldedGT, foldedGTE, foldedLT, foldedLTE, alwaysFalse := foldNumericRangeBoundsOutOfBounds(b, gt, gte, lt, lte); alwaysFalse {
		return "FALSE"
	} else {
		gt, gte, lt, lte = foldedGT, foldedGTE, foldedLT, foldedLTE
	}

	effDT := effectiveDorisScalarType(b)
	if effDT == schema.DorisBoolean {
		parseBoolBound := func(cand any) (any, bool) {
			if cand == nil {
				return nil, true
			}
			bv, ok := normalizeBooleanQueryValue(cand)
			if !ok {
				if b.ESType == "boolean" && !t.inLenientQuery && t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: failed to parse boolean range bound [%v] for field [%s]", cand, field)
				}
				return nil, false
			}
			return bv, true
		}
		var ok bool
		if gt, ok = parseBoolBound(gt); !ok {
			return "FALSE"
		}
		if gte, ok = parseBoolBound(gte); !ok {
			return "FALSE"
		}
		if lt, ok = parseBoolBound(lt); !ok {
			return "FALSE"
		}
		if lte, ok = parseBoolBound(lte); !ok {
			return "FALSE"
		}
	}
	if b.ESType != "" &&
		(effDT == schema.DorisBigInt || effDT == schema.DorisLargeInt || effDT == schema.DorisInt || effDT == schema.DorisDouble) {
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
	if (!t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield)) || isNestedMultiVal {
		elemExpr := "_x"
		switch b.ESType {
		case "boolean":
			elemExpr = "TRY_CAST(_x AS BOOLEAN)"
		case "unsigned_long":
			elemExpr = "TRY_CAST(_x AS LARGEINT)"
		case "float", "half_float", "scaled_float", "double":
			elemExpr = "TRY_CAST(_x AS DOUBLE)"
		case "byte", "short", "integer", "long", "date", "date_nanos":
			elemExpr = "TRY_CAST(_x AS BIGINT)"
		default:
			switch sv := sampleBound.(type) {
			case bool:
				elemExpr = "TRY_CAST(_x AS BOOLEAN)"
			case uint64:
				elemExpr = "TRY_CAST(_x AS LARGEINT)"
			case int, int64:
				elemExpr = "TRY_CAST(_x AS BIGINT)"
			case float64:
				if sv == math.Trunc(sv) {
					elemExpr = "TRY_CAST(_x AS BIGINT)"
				} else {
					elemExpr = "TRY_CAST(_x AS DOUBLE)"
				}
			case json.Number:
				if _, err := sv.Int64(); err == nil {
					elemExpr = "TRY_CAST(_x AS BIGINT)"
				} else if _, errU := strconv.ParseUint(sv.String(), 10, 64); errU == nil {
					elemExpr = "TRY_CAST(_x AS LARGEINT)"
				} else {
					elemExpr = "TRY_CAST(_x AS DOUBLE)"
				}
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
			return fmt.Sprintf("array_exists(_x -> %s, TRY_CAST(%s AS ARRAY<STRING>))", strings.Join(elemParts, " AND "), col)
		}
		if b.Kind == schema.StoragePromotedArray && (b.DorisType == schema.DorisLargeInt || b.DorisType == schema.DorisLargeIntArray) {
			return fmt.Sprintf("array_exists(_x -> %s, TRY_CAST(`%s` AS ARRAY<LARGEINT>))", strings.Join(elemParts, " AND "), b.EffectiveArrayColumn(true))
		}
		return fmt.Sprintf("array_exists(_x -> %s, `%s`)", strings.Join(elemParts, " AND "), b.EffectiveArrayColumn(true))
	}

	if nctx == nil {
		if _, rtType, isRT := t.resolveScriptlessRuntimeField(origField); isRT && (rtType == "double" || rtType == "long" || rtType == "boolean") {
			arrExpr := sqlRuntimeSourceArrayExpr(origField)
			elemExpr := "TRY_CAST(_x AS DOUBLE)"
			switch rtType {
			case "long":
				elemExpr = "TRY_CAST(_x AS BIGINT)"
			case "boolean":
				elemExpr = "CASE WHEN LOWER(_x) IN ('true', '1') THEN TRUE WHEN LOWER(_x) IN ('false', '0') THEN FALSE ELSE NULL END"
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
			return fmt.Sprintf("array_exists(_x -> (%s) IS NOT NULL AND %s, %s)", elemExpr, strings.Join(elemParts, " AND "), arrExpr)
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
			return fmt.Sprintf("(%s OR array_exists(_x -> _x IS NOT NULL AND %s, TRY_CAST(%s AS ARRAY<STRING>)))", scalarCond, strings.Join(elemParts, " AND "), rawVar)
		}
	}
	return strings.Join(parts, " AND ")
}

func (t *Transpiler) compileExistsPredicate(field string, nctx *nestedCtx) string {
	field, _ = parseFieldBoost(field, 1.0)
	if IsSubpathUnderAggregateMetricDoubleR63(t.Schema, field) {
		return "FALSE"
	}
	if field == "_routing" {
		return "(`_routing` IS NOT NULL AND `_routing` != '')"
	}
	if metaPred, isMeta := t.compileMetadataExistsPredicate(field); isMeta {
		return metaPred
	}
	if nctx == nil {
		if _, _, isRT := t.resolveScriptlessRuntimeField(field); isRT {
			expr := sqlRuntimeSourceStringExpr(field)
			return fmt.Sprintf("(%s IS NOT NULL AND %s != '[]')", expr, expr)
		}
	}
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
	if b.ESType == "aggregate_metric_double" {
		return CompileAggregateMetricExistsExprR63(b)
	}
	if strings.HasSuffix(b.AliasTarget, ".keyword") {
		preferKw = true
	}
	if !t.isBoundToNestedCtx(field, b, nctx) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
		arrCol := b.EffectiveArrayColumn(preferKw)
		return fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", arrCol, arrCol)
	}
	col := t.sqlColumnRef(field, preferKw, nctx)
	basePred := fmt.Sprintf("%s IS NOT NULL", col)
	if b.ESType == "flattened" || b.ESType == "histogram" || schema.IsRangeFieldType(b.ESType) {
		basePred = fmt.Sprintf("(%s IS NOT NULL AND %s != '{}' AND %s != 'null')", col, col, col)
	} else if nctx == nil && b.Kind == schema.StorageDynamicVariant && !b.NotIndexed && b.ESType != "object" && b.ESType != "nested" && (t.Schema == nil || !t.Schema.SourceDisabled()) && field != "_all_text" && field != "*" {
		pathField := field
		if len(b.SourceJSONPath) > 0 {
			pathField = strings.Join(b.SourceJSONPath, ".")
		}
		nestedPath, dottedPath, hasDot := BuildQuotedDorisJSONPaths(pathField)
		jsonTypeExists := func(jp string) string {
			ql := quoteStr(jp)
			return fmt.Sprintf("(JSON_TYPE(TRY_CAST(`_source` AS JSON), %s) IS NOT NULL AND JSON_TYPE(TRY_CAST(`_source` AS JSON), %s) != 'NULL' AND (JSON_TYPE(TRY_CAST(`_source` AS JSON), %s) != 'ARRAY' OR JSON_LENGTH(TRY_CAST(`_source` AS JSON), %s) > 0))", ql, ql, ql, ql)
		}
		if !hasDot {
			basePred = jsonTypeExists(nestedPath)
		} else {
			basePred = fmt.Sprintf("(%s OR %s)", jsonTypeExists(nestedPath), jsonTypeExists(dottedPath))
		}
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

func (t *Transpiler) buildAggsCTESQL(baseWhere, userWhere, aliasWhere, postFilterSQL string, aggs map[string]esast.AggSpec) string {
	if !hasGlobalOrJoinAgg(aggs) {
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
			wrapUnionBranchesWithOuterOrderByR63(branches),
		)
	}

	effectiveUserWhere := userWhere

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
		wrapUnionBranchesWithOuterOrderByR63(branches),
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
		case t.appendRound62TopLevelAggBranch(branches, subIdx, fullAggName, extraWhere, wherePrefix, spec):

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

		case spec.EffectiveTerms() != nil:
			termsSpec := spec.EffectiveTerms()
			termsExtraWhere := extraWhere
			termsWherePrefix := wherePrefix
			if termsSpec.BackgroundFilter != nil {
				bgCond := t.CompileQuery(termsSpec.BackgroundFilter, false, nil)
				bgSafe := bgCond.EffectiveSafeWhere()
				if bgSafe != "" && bgSafe != "1=1" {
					if termsExtraWhere != "" {
						termsExtraWhere = fmt.Sprintf("(%s) AND (%s)", termsExtraWhere, bgSafe)
					} else {
						termsExtraWhere = bgSafe
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
			_, b := t.resolveFieldInNestedCtx(effField, true, nil)
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
					explodeFrom := fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) `_t` AS `_elem`", arrCol, arrCol, nullSingletonArraySQL(b), arrCol)
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
				if b.Kind == schema.StoragePromotedScalar && b.ESType == "unsigned_long" && effField != "" {
					col = t.sqlTypedColumnRef(effField, uint64(math.MaxUint64), true, nil)
				}
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
							"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` "+
							"%s"+
							"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
							") `_agg_sub_%d`",
						quoteStr(fullAggName), coalescedCol, t.sqlDocCountSumExpr(), wCond, size, *subIdx,
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
							"SELECT %s AS `_agg_name`, CAST(%s AS STRING) AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` "+
							"WHERE %s%s IS NOT NULL "+
							"GROUP BY `_bucket_key` ORDER BY `_doc_count` DESC, `_bucket_key` ASC LIMIT %d"+
							") `_agg_sub_%d`",
						quoteStr(fullAggName), col, t.sqlDocCountSumExpr(), termsWherePrefix, rawCol, size, *subIdx,
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
			if !ok && schemaHasNestedObjectPathR65(t.Schema, spec.Nested.Path) {
				corrCol = "n__" + schema.SanitizeDorisIdentifier(spec.Nested.Path)
				ok = true
			}
			if !ok {
				if t.Schema != nil && (len(t.Schema.Fields) > 0 || len(t.Schema.NestedRoots) > 0) {
					if schemaHasMappedNonNestedPathR66(t.Schema, spec.Nested.Path) {
						if t.searchErr == nil {
							t.searchErr = fmt.Errorf("[nested] failed to find nested object under path [%s]", spec.Nested.Path)
						}
						continue
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, '_nested_doc_count' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(CAST([] AS ARRAY<STRING>)) `_nt` AS `_nel` WHERE %s`_nel` IS NOT NULL",
						quoteStr(fullAggName), wherePrefix,
					))
					continue
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
					numExpr := fmt.Sprintf("TRY_CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
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
					numExpr := fmt.Sprintf("TRY_CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
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
					numExpr := fmt.Sprintf("TRY_CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
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
					*branches = append(*branches, sqlCollectRawValuesBranch(
						subFull, numExpr,
						fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel`", corrCol),
						nWhere,
					))
				case subSpec.PercentileRanks != nil:
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					effPRField := subSpec.PercentileRanks.Field
					if effPRField == "" && subSpec.PercentileRanks.Script != nil {
						if docF, ok := extractSimpleDocFieldFromScript(subSpec.PercentileRanks.Script); ok {
							effPRField = docF
						}
					}
					relJSONPath := nestedRelJSON(effPRField)
					numExpr := fmt.Sprintf("TRY_CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
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
					*branches = append(*branches, sqlCollectRawValuesBranch(
						subFull, numExpr,
						fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel`", corrCol),
						nWhere,
					))
				case subSpec.Boxplot != nil:
					nestedElemCtx := &nestedCtx{nestedPath: spec.Nested.Path, elemVar: "`_nel`"}
					effBoxField := subSpec.Boxplot.Field
					if effBoxField == "" && subSpec.Boxplot.Script != nil {
						if docF, ok := extractSimpleDocFieldFromScript(subSpec.Boxplot.Script); ok {
							effBoxField = docF
						}
					}
					relJSONPath := nestedRelJSON(effBoxField)
					numExpr := fmt.Sprintf("TRY_CAST(json_extract_string(`_nel`, %s) AS DOUBLE)", relJSONPath)
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
					*branches = append(*branches, sqlCollectRawValuesBranch(
						subFull, numExpr,
						fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_nt` AS `_nel`", corrCol),
						nWhere,
					))
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
			condSafe := cond.EffectiveSafeWhere()
			combinedWhere := condSafe
			if extraWhere != "" {
				combinedWhere = fmt.Sprintf("(%s) AND (%s)", extraWhere, condSafe)
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, '_filter' AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s",
				quoteStr(fullAggName), t.sqlDocCountSumExpr(), combinedWhere,
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
					condSafe := cond.EffectiveSafeWhere()
					matchedConds = append(matchedConds, fmt.Sprintf("(%s)", condSafe))
					combinedWhere := condSafe
					if extraWhere != "" {
						combinedWhere = fmt.Sprintf("(%s) AND (%s)", extraWhere, condSafe)
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` WHERE %s",
						quoteStr(fullAggName), quoteStr(fk), t.sqlDocCountSumExpr(), combinedWhere,
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
					condSafe := cond.EffectiveSafeWhere()
					matchedConds = append(matchedConds, fmt.Sprintf("(%s)", condSafe))
					combinedWhere := condSafe
					if extraWhere != "" {
						combinedWhere = fmt.Sprintf("(%s) AND (%s)", extraWhere, condSafe)
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` WHERE %s",
						quoteStr(fullAggName), quoteStr(fk), t.sqlDocCountSumExpr(), combinedWhere,
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
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched` WHERE %s",
					quoteStr(fullAggName), quoteStr(otherKey), t.sqlDocCountSumExpr(), otherWhere,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					t.appendBucketScopedSubAggs(branches, subIdx, fullAggName, otherKey, otherWhere, subAggs)
				}
			}

		case spec.Missing != nil:
			missingWhere := "FALSE"
			if spec.Missing.Missing == nil {
				existsPred := t.compileExistsPredicate(spec.Missing.Field, nil)
				missingWhere = fmt.Sprintf("%sNOT (%s)", wherePrefix, existsPred)
			}
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
			_, b := t.resolveFieldInNestedCtx(effCardField, true, nil)
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
				countExpr := "COUNT(`_id`)"
				if t.useDocCountFieldSQL() {
					countExpr = t.sqlDocCountSumExpr()
				}
				wClause := ""
				if extraWhere != "" {
					wClause = " WHERE " + extraWhere
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` FROM `base_matched`%s",
					quoteStr(fullAggName), countExpr, wClause,
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
			if b.ESType == "histogram" {
				hArrExpr := t.histogramArrayExpr(effStatsField, b, nil)
				wCond := fmt.Sprintf(" WHERE %s`_helem` IS NOT NULL AND `_helem` != '' AND TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS BIGINT) > 0", wherePrefix)
				hVal := "TRY_CAST(SPLIT_PART(`_helem`, ',', 1) AS DOUBLE)"
				hCnt := "TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS DOUBLE)"
				histStatExprs := []struct{ key, expr string }{
					{"_stats_count", fmt.Sprintf("COALESCE(SUM(%s), 0)", hCnt)},
					{"_stats_min", fmt.Sprintf("COALESCE(MIN(%s), 0)", hVal)},
					{"_stats_max", fmt.Sprintf("COALESCE(MAX(%s), 0)", hVal)},
					{"_stats_avg", fmt.Sprintf("COALESCE(SUM((%s) * (%s)) / NULLIF(SUM(%s), 0), 0)", hVal, hCnt, hCnt)},
					{"_stats_sum", fmt.Sprintf("COALESCE(SUM((%s) * (%s)), 0)", hVal, hCnt)},
				}
				for _, hs := range histStatExprs {
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_ht` AS `_helem`%s",
						quoteStr(fullAggName), quoteStr(hs.key), hs.expr, hArrExpr, wCond,
					))
				}
			} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				arrCol := b.EffectiveArrayColumn(true)
				valExpr := "TRY_CAST(`_nel` AS DOUBLE)"
				if b.ESType == "date_nanos" {
					valExpr = "(TRY_CAST(`_nel` AS DOUBLE) / 1000000.0)"
				}
				explodeExpr := fmt.Sprintf("`%s`", arrCol)
				wCond := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
				if statsSpec.Missing != nil {
					if mf, ok := resolveHistogramMissingFloat(statsSpec.Missing); ok {
						valExpr = fmt.Sprintf("COALESCE(%s, %s)", valExpr, strconv.FormatFloat(mf, 'f', -1, 64))
						explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END", arrCol, arrCol, nullSingletonArraySQL(b), arrCol)
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
			if b.ESType == "histogram" {
				hArrExpr := t.histogramArrayExpr(effBpField, b, nil)
				wCond := fmt.Sprintf(" WHERE %s`_helem` IS NOT NULL AND `_helem` != '' AND TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS BIGINT) > 0", wherePrefix)
				hVal := "TRY_CAST(SPLIT_PART(`_helem`, ',', 1) AS DOUBLE)"
				hCnt := "TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS DOUBLE)"
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
					*branches = append(*branches, sqlExactHistogramPercentileBranch(fullAggName, bp.key, hVal, hCnt, hArrExpr, wCond, bp.q))
				}
				continue
			}
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
					valExpr := "TRY_CAST(`_nel` AS DOUBLE)"
					explodeExpr := fmt.Sprintf("`%s`", arrCol)
					wCond := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
					if spec.Boxplot.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(spec.Boxplot.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(TRY_CAST(`_nel` AS DOUBLE), %s)", strconv.FormatFloat(mf, 'f', -1, 64))
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
					if bp.key == "0.0" {
						*branches = append(*branches, sqlCollectRawValuesBranch(fullAggName, col, "`base_matched`", fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, col)))
					}
				}
			}
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				valExpr := "TRY_CAST(`_nel` AS DOUBLE)"
				explodeExpr := fmt.Sprintf("`%s`", arrCol)
				wCond := fmt.Sprintf("%s`_nel` IS NOT NULL", wherePrefix)
				if spec.Boxplot.Missing != nil {
					if mf, ok := resolveHistogramMissingFloat(spec.Boxplot.Missing); ok {
						valExpr = fmt.Sprintf("COALESCE(TRY_CAST(`_nel` AS DOUBLE), %s)", strconv.FormatFloat(mf, 'f', -1, 64))
						explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END", arrCol, arrCol, nullSingletonArraySQL(b), arrCol)
						wCond = extraWhere
					}
				}
				if spec.Boxplot.Script != nil {
					if scriptExpr, ok := t.compileMetricScriptExprWithOverride(spec.Boxplot.Script, effBpField, valExpr, nil); ok {
						valExpr = scriptExpr
					}
				}
				*branches = append(*branches, sqlCollectRawValuesBranch(fullAggName, valExpr, fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(%s) `_nt` AS `_nel`", explodeExpr), wCond))
			}

		case spec.Percentiles != nil:
			effPctField := spec.Percentiles.Field
			if effPctField == "" && spec.Percentiles.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(spec.Percentiles.Script); ok {
					effPctField = docF
				}
			}
			b := t.Schema.ResolveField(effPctField)
			if b.ESType == "histogram" {
				hArrExpr := t.histogramArrayExpr(effPctField, b, nil)
				wCond := fmt.Sprintf(" WHERE %s`_helem` IS NOT NULL AND `_helem` != '' AND TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS BIGINT) > 0", wherePrefix)
				hVal := "TRY_CAST(SPLIT_PART(`_helem`, ',', 1) AS DOUBLE)"
				hCnt := "TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS DOUBLE)"
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
					*branches = append(*branches, sqlExactHistogramPercentileBranch(fullAggName, pctKey, hVal, hCnt, hArrExpr, wCond, q))
				}
				continue
			}
			arrCol := b.EffectiveArrayColumn(true)
			emittedRawPct := false
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
					valExpr := "TRY_CAST(`_nel` AS DOUBLE)"
					explodeExpr := fmt.Sprintf("`%s`", arrCol)
					wCond := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
					if spec.Percentiles.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(spec.Percentiles.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(TRY_CAST(`_nel` AS DOUBLE), %s)", strconv.FormatFloat(mf, 'f', -1, 64))
							explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END", arrCol, arrCol, nullSingletonArraySQL(b), arrCol)
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
					if !emittedRawPct {
						emittedRawPct = true
						*branches = append(*branches, sqlCollectRawValuesBranch(fullAggName, valExpr, fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(%s) `_nt` AS `_nel`", explodeExpr), wCond))
					}
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
					if !emittedRawPct {
						emittedRawPct = true
						*branches = append(*branches, sqlCollectRawValuesBranch(fullAggName, col, "`base_matched`", fmt.Sprintf("%s%s IS NOT NULL", wherePrefix, col)))
					}
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
			if b.ESType == "histogram" {
				hArrExpr := t.histogramArrayExpr(effPrField, b, nil)
				wCond := fmt.Sprintf(" WHERE %s`_helem` IS NOT NULL AND `_helem` != '' AND TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS BIGINT) > 0", wherePrefix)
				hVal := "TRY_CAST(SPLIT_PART(`_helem`, ',', 1) AS DOUBLE)"
				hCnt := "TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS DOUBLE)"
				for _, val := range spec.PercentileRanks.Values {
					valKey := strconv.FormatFloat(val, 'f', -1, 64)
					if !strings.Contains(valKey, ".") {
						valKey += ".0"
					}
					valLit := strconv.FormatFloat(val, 'f', -1, 64)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(100.0 * SUM(CASE WHEN %s <= %s THEN %s ELSE 0.0 END) / NULLIF(SUM(%s), 0), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_ht` AS `_helem`%s HAVING SUM(%s) > 0",
						quoteStr(fullAggName), quoteStr(valKey), hVal, valLit, hCnt, hCnt, hArrExpr, wCond, hCnt,
					))
				}
				continue
			}
			arrCol := b.EffectiveArrayColumn(true)
			emittedRawPR := false
			for _, val := range spec.PercentileRanks.Values {
				valKey := strconv.FormatFloat(val, 'f', -1, 64)
				if !strings.Contains(valKey, ".") {
					valKey += ".0"
				}
				valLit := strconv.FormatFloat(val, 'f', -1, 64)
				if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
					valExpr := "TRY_CAST(`_nel` AS DOUBLE)"
					explodeExpr := fmt.Sprintf("`%s`", arrCol)
					wCond := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
					if spec.PercentileRanks.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(spec.PercentileRanks.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(TRY_CAST(`_nel` AS DOUBLE), %s)", strconv.FormatFloat(mf, 'f', -1, 64))
							explodeExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END", arrCol, arrCol, nullSingletonArraySQL(b), arrCol)
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
					if !emittedRawPR {
						emittedRawPR = true
						*branches = append(*branches, sqlCollectRawValuesBranch(fullAggName, valExpr, fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(%s) `_nt` AS `_nel`", explodeExpr), wCond))
					}
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
					if !emittedRawPR {
						emittedRawPR = true
						*branches = append(*branches, sqlCollectRawValuesBranch(fullAggName, col, "`base_matched`", wCond))
					}
				}
			}

		case spec.DateHistogram != nil:
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
				col = "TRY_CAST(`_elem` AS DOUBLE)"
				if b.ESType == "date_nanos" {
					col = "(TRY_CAST(`_elem` AS DOUBLE) / 1000000.0)"
				}
				fromClause = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem`", arrCol)
				notNullCond = fmt.Sprintf("%s`_elem` IS NOT NULL", wherePrefix)
				if spec.DateHistogram.Missing != nil {
					if missMs, ok := t.resolveDateHistogramMissingMs(b.ESType, spec.DateHistogram.Missing); ok {
						fromClause = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) `_t` AS `_elem`", arrCol, arrCol, nullSingletonArraySQL(b), arrCol)
						col = fmt.Sprintf("COALESCE(%s, %d)", col, missMs)
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
			maxOp := "<="
			if t.Opts.ES8Compat {
				maxOp = "<"
			}
			if spec.DateHistogram.HardBounds != nil {
				if minMs, okMin := t.resolveDateHistogramBoundMs(b, spec.DateHistogram.Format, spec.DateHistogram.HardBounds.Min); okMin {
					notNullCond = fmt.Sprintf("(%s) AND (%s >= %d)", notNullCond, col, minMs)
				}
				if maxMs, okMax := t.resolveDateHistogramBoundMs(b, spec.DateHistogram.Format, spec.DateHistogram.HardBounds.Max); okMax {
					notNullCond = fmt.Sprintf("(%s) AND (%s %s %d)", notNullCond, col, maxOp, maxMs)
				}
			}
			isRangeDH := schema.IsRangeFieldType(b.ESType) && spec.DateHistogram.Script == nil
			if isRangeDH {
				_, _, rawLoSQL, rawHiSQL := t.rangeFieldBoundsAndRawSQL(effDHField, b, nil)
				var hardMin, hardMax, extMin, extMax *float64
				if spec.DateHistogram.HardBounds != nil {
					hardMin = t.resolveDateHistogramBoundFloatPtr(b, spec.DateHistogram.Format, spec.DateHistogram.HardBounds.Min)
					hardMax = t.resolveDateHistogramBoundFloatPtr(b, spec.DateHistogram.Format, spec.DateHistogram.HardBounds.Max)
				}
				if spec.DateHistogram.ExtendedBounds != nil {
					extMin = t.resolveDateHistogramBoundFloatPtr(b, spec.DateHistogram.Format, spec.DateHistogram.ExtendedBounds.Min)
					extMax = t.resolveDateHistogramBoundFloatPtr(b, spec.DateHistogram.Format, spec.DateHistogram.ExtendedBounds.Max)
				}
				effLoSQL, effHiSQL := rangeHistogramClampedBoundsSQL(rawLoSQL, rawHiSQL, hardMin, hardMax, extMin, extMax)
				ivMs := spec.DateHistogram.EffectiveIntervalMs()
				if ivMs <= 0 {
					ivMs = 86400000
				}
				fromClause, col = buildDateRangeBucketExplodeSQLR63("`base_matched`", effLoSQL, effHiSQL, ivMs)
				notNullCond = fmt.Sprintf("%s((%s) IS NOT NULL OR (%s) IS NOT NULL) AND (%s) <= (%s)", wherePrefix, rawLoSQL, rawHiSQL, effLoSQL, effHiSQL)
				if spec.DateHistogram.HardBounds != nil {
					if minMs, okMin := t.resolveDateHistogramBoundMs(b, spec.DateHistogram.Format, spec.DateHistogram.HardBounds.Min); okMin {
						notNullCond = fmt.Sprintf("(%s) AND (%s >= %d)", notNullCond, col, minMs)
					}
					if maxMs, okMax := t.resolveDateHistogramBoundMs(b, spec.DateHistogram.Format, spec.DateHistogram.HardBounds.Max); okMax {
						notNullCond = fmt.Sprintf("(%s) AND (%s <= %d)", notNullCond, col, maxMs)
					}
				}
			}
			bucketExpr := t.buildDateHistogramBucketKeySQL(spec.DateHistogram, col)
			dhCountExpr := "COUNT(*)"
			if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield || isRangeDH {
				dhCountExpr = "COUNT(DISTINCT `_id`)"
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM %s "+
					"WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY TRY_CAST(`_bucket_key` AS BIGINT) ASC"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), bucketExpr, dhCountExpr, fromClause, notNullCond, *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				subBucketExpr := bucketExpr
				subFromClause := fromClause
				subWhereCond := notNullCond
				if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield || isRangeDH {
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
			hCountExpr := "COUNT(*)"
			if b.ESType == "histogram" {
				hArrExpr := t.histogramArrayExpr(effHField, b, nil)
				fromClause = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(%s) `_ht` AS `_helem`", hArrExpr)
				col = "TRY_CAST(SPLIT_PART(`_helem`, ',', 1) AS DOUBLE)"
				hCountExpr = "COALESCE(SUM(TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS DOUBLE)), 0)"
				notNullCond = fmt.Sprintf("%s`_helem` IS NOT NULL AND `_helem` != '' AND TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS BIGINT) > 0", wherePrefix)
			} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				col = "TRY_CAST(`_elem` AS DOUBLE)"
				fromClause = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem`", arrCol)
				notNullCond = fmt.Sprintf("%s`_elem` IS NOT NULL", wherePrefix)
				if spec.Histogram.Missing != nil {
					if missVal, ok := resolveHistogramMissingFloat(spec.Histogram.Missing); ok {
						fromClause = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) `_t` AS `_elem`", arrCol, arrCol, nullSingletonArraySQL(b), arrCol)
						col = fmt.Sprintf("COALESCE(TRY_CAST(`_elem` AS DOUBLE), %s)", strconv.FormatFloat(missVal, 'f', -1, 64))
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
				hCountExpr = "COUNT(DISTINCT `_id`)"
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
			hMaxOp := "<="
			if t.Opts.ES8Compat {
				hMaxOp = "<"
			}
			if spec.Histogram.HardBounds != nil {
				if minF, okMin := resolveHistogramMissingFloat(spec.Histogram.HardBounds.Min); okMin {
					notNullCond = fmt.Sprintf("(%s) AND (%s >= %s)", notNullCond, col, strconv.FormatFloat(minF, 'f', -1, 64))
				}
				if maxF, okMax := resolveHistogramMissingFloat(spec.Histogram.HardBounds.Max); okMax {
					notNullCond = fmt.Sprintf("(%s) AND (%s %s %s)", notNullCond, col, hMaxOp, strconv.FormatFloat(maxF, 'f', -1, 64))
				}
			}
			isRangeHist := schema.IsRangeFieldType(b.ESType) && spec.Histogram.Script == nil
			if isRangeHist {
				_, _, rawLoSQL, rawHiSQL := t.rangeFieldBoundsAndRawSQL(effHField, b, nil)
				var hardMin, hardMax, extMin, extMax *float64
				if spec.Histogram.HardBounds != nil {
					hardMin = resolveHistogramBoundFloatPtr(spec.Histogram.HardBounds.Min)
					hardMax = resolveHistogramBoundFloatPtr(spec.Histogram.HardBounds.Max)
				}
				if spec.Histogram.ExtendedBounds != nil {
					extMin = resolveHistogramBoundFloatPtr(spec.Histogram.ExtendedBounds.Min)
					extMax = resolveHistogramBoundFloatPtr(spec.Histogram.ExtendedBounds.Max)
				}
				effLoSQL, effHiSQL := rangeHistogramClampedBoundsSQL(rawLoSQL, rawHiSQL, hardMin, hardMax, extMin, extMax)
				fromClause, col = buildRangeBucketExplodeSQL("`base_matched`", effLoSQL, effHiSQL, offset, interval)
				hCountExpr = "COUNT(DISTINCT `_id`)"
				notNullCond = fmt.Sprintf("%s((%s) IS NOT NULL OR (%s) IS NOT NULL) AND (%s) <= (%s)", wherePrefix, rawLoSQL, rawHiSQL, effLoSQL, effHiSQL)
				if spec.Histogram.HardBounds != nil {
					if minF, okMin := resolveHistogramMissingFloat(spec.Histogram.HardBounds.Min); okMin {
						notNullCond = fmt.Sprintf("(%s) AND (%s >= %s)", notNullCond, col, strconv.FormatFloat(minF, 'f', -1, 64))
					}
					if maxF, okMax := resolveHistogramMissingFloat(spec.Histogram.HardBounds.Max); okMax {
						notNullCond = fmt.Sprintf("(%s) AND (%s <= %s)", notNullCond, col, strconv.FormatFloat(maxF, 'f', -1, 64))
					}
				}
			}
			histKeyB := b
			if spec.Histogram.Script != nil {
				histKeyB = schema.FieldBinding{ESType: "double", DorisType: schema.DorisDouble}
			}
			colDiv := ensureDoubleHistogramExprR64(col, histKeyB)
			bucketExpr := t.formatHistogramBucketKeySQLWithRawR65(colDiv, fullAggName, offset, interval, histKeyB)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM %s "+
					"WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY TRY_CAST(`_bucket_key` AS DOUBLE) ASC"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), bucketExpr, hCountExpr, fromClause, notNullCond, *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				subBucketExpr := bucketExpr
				subFromClause := fromClause
				subWhereCond := notNullCond
				if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield || b.ESType == "histogram" || isRangeHist {
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
			rangeOrder := make([]int, len(rngSpec.Ranges))
			for i := range rngSpec.Ranges {
				rangeOrder[i] = i
			}
			if spec.IPRange == nil && !rngSpec.Keyed {
				rangeOrder = t.sortedRangeAggIndicesAscR63(effRField, rngSpec, now)
			}
			for _, rIdx := range rangeOrder {
				rng := rngSpec.Ranges[rIdx]
				var rWhere string
				fromSource := "`base_matched`"
				countExpr := "COUNT(*)"
				isHistRange := false
				if spec.IPRange != nil {
					ipCol := t.sqlColumnRef(effRField, true, nil)
					if isArray {
						ipCol = "_x"
					}
					hexCol := sqlCanonicalIPHexExpr(ipCol)
					var conds []string
					if !isArray {
						conds = append(conds, fmt.Sprintf("%s IS NOT NULL", ipCol))
					}
					if rng.Mask != "" {
						if startHex, endHex, okCIDR := parseCanonicalIPCIDRHexBounds(rng.Mask); okCIDR {
							conds = append(conds,
								fmt.Sprintf("%s >= %s", hexCol, quoteStr(startHex)),
								fmt.Sprintf("%s <= %s", hexCol, quoteStr(endHex)),
							)
						} else {
							conds = append(conds, "1=0")
						}
					} else {
						boundsValid := true
						for _, cand := range []any{rng.From, rng.To} {
							if cand == nil {
								continue
							}
							if _, ok := parseIPToUpperHex16(cand); !ok {
								boundsValid = false
								break
							}
						}
						if !boundsValid {
							conds = append(conds, "1=0")
						} else {
							if rng.From != nil {
								if h, ok := parseIPToUpperHex16(rng.From); ok {
									conds = append(conds, fmt.Sprintf("%s >= %s", hexCol, quoteStr(h)))
								}
							}
							if rng.To != nil {
								if h, ok := parseIPToUpperHex16(rng.To); ok {
									conds = append(conds, fmt.Sprintf("%s < %s", hexCol, quoteStr(h)))
								}
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
				} else if b.ESType == "histogram" {
					isHistRange = true
					hArrExpr := t.histogramArrayExpr(effRField, b, nil)
					hVal := "TRY_CAST(SPLIT_PART(`_helem`, ',', 1) AS DOUBLE)"
					if rngSpec.Script != nil {
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(rngSpec.Script, effRField, hVal, nil); ok {
							hVal = scriptExpr
						}
					}
					var fromLit, toLit string
					if rng.From != nil {
						fromLit = quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.From, now))
					}
					if rng.To != nil {
						toLit = quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.To, now))
					}
					fromSource, rWhere, countExpr = compileHistogramRangeBucketSQLR65("`base_matched`", hArrExpr, "`_ht`", "`_helem`", hVal, fromLit, toLit)
				} else if isArray {
					elemExpr := "TRY_CAST(_x AS DOUBLE)"
					if b.ESType == "date_nanos" {
						elemExpr = "(TRY_CAST(_x AS DOUBLE) / 1000000.0)"
					}
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
						if mu, okU := t.resolveUnsignedLongRangeAggMissingExact(effRField, rngSpec); okU {
							missArrLit := fmt.Sprintf("CAST([CAST(%s AS LARGEINT)] AS ARRAY<LARGEINT>)", strconv.FormatUint(mu, 10))
							arrExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END", arrCol, arrCol, missArrLit, arrCol)
						} else if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
							missArrLit := fmt.Sprintf("[%s]", strconv.FormatFloat(mf, 'f', -1, 64))
							arrExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END", arrCol, arrCol, missArrLit, arrCol)
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
						if mu, okU := t.resolveUnsignedLongRangeAggMissingExact(effRField, rngSpec); okU {
							col = fmt.Sprintf("COALESCE(%s, CAST(%s AS LARGEINT))", t.sqlColumnRef(effRField, true, nil), strconv.FormatUint(mu, 10))
						} else if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
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
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s",
					quoteStr(fullAggName), quoteStr(bKey), countExpr, fromSource, rWhere,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					subFrom := fromSource
					subWhere := rWhere
					if isHistRange {
						*subIdx++
						dedupIdx := *subIdx
						subFrom = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, fromSource, rWhere, dedupIdx, dedupIdx, dedupIdx)
						subWhere = "1=1"
					}
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, quoteStr(bKey), subFrom, subWhere, subAggs)
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
						compFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", compFrom, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, tblAlias, elemAlias)
					} else {
						compFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", compFrom, arrCol, tblAlias, elemAlias)
					}
					if isNumeric {
						return fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", elemAlias)
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
						if effDT == schema.DorisBigInt || effDT == schema.DorisLargeInt || effDT == schema.DorisInt || effDT == schema.DorisDouble || b.ESType == "ip" || b.ESType == "version" || srcSpec.Terms.Order != nil || srcSpec.Terms.Script != nil {
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
						hasMiss := srcSpec.DateHistogram.Missing != nil || srcSpec.DateHistogram.MissingBucket
						effDHField := srcSpec.DateHistogram.Field
						if effDHField == "" && srcSpec.DateHistogram.Script != nil {
							if docF, ok := extractSimpleDocFieldFromScript(srcSpec.DateHistogram.Script); ok {
								effDHField = docF
							}
						}
						dhB := t.Schema.ResolveEffectiveField(effDHField, true)
						col := resolveCompSourceCol(effDHField, true, hasMiss)
						if dhB.ESType == "date_nanos" && (dhB.Kind == schema.StoragePromotedArray || dhB.Kind == schema.StorageNestedSubfield) {
							col = fmt.Sprintf("(%s / 1000000.0)", col)
						}
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
						expr := t.buildDateHistogramBucketKeySQL(srcSpec.DateHistogram, col)
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
						hB := t.Schema.ResolveEffectiveField(effHField, true)
						if srcSpec.Histogram.Script != nil {
							hB = schema.FieldBinding{ESType: "double", DorisType: schema.DorisDouble}
						}
						if srcSpec.Histogram.Missing != nil {
							if missVal, ok := resolveHistogramMissingFloat(srcSpec.Histogram.Missing); ok {
								col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(missVal, 'f', -1, 64))
							}
						}
						colDiv := ensureDoubleHistogramExprR64(col, hB)
						expr := t.formatHistogramBucketKeySQLWithRawR65(colDiv, fullAggName+"."+sk, offset, interval, hB)
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
					case srcSpec.GeotileGrid != nil:
						hasHistogramSrc = true
						prec := 7
						if srcSpec.GeotileGrid.Precision != nil {
							prec = *srcSpec.GeotileGrid.Precision
						}
						latExpr, lonExpr, geoNotNull := t.resolveGeoPointLatLonSQL(srcSpec.GeotileGrid.Field, nil)
						expr := EncodeGeotileSQL(latExpr, lonExpr, prec)
						if srcSpec.GeotileGrid.MissingBucket {
							expr = fmt.Sprintf("COALESCE(%s, '__ES_MISSING_BUCKET__')", expr)
						} else {
							notNullConds = append(notNullConds, geoNotNull)
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
							if nv, ok := av.(json.Number); ok {
								afterParts = append(afterParts, nv.String())
							} else if fv, ok := av.(float64); ok && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) {
								if fv >= -9223372036854775808.0 && fv < 9223372036854775808.0 {
									afterParts = append(afterParts, strconv.FormatInt(int64(fv), 10))
								} else if fv >= 9223372036854775808.0 && fv < 18446744073709551616.0 {
									afterParts = append(afterParts, strconv.FormatUint(uint64(fv), 10))
								} else {
									afterParts = append(afterParts, strconv.FormatFloat(fv, 'f', -1, 64))
								}
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
				compCountExpr := t.sqlDocCountSumExpr()
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
			*branches = append(*branches, sqlCollectRawValuesBranch(fullAggName, col, "`base_matched`", wCond))

		case spec.RareTerms != nil:
			maxDocCount := 1
			if spec.RareTerms.MaxDocCount != nil && *spec.RareTerms.MaxDocCount >= 1 {
				maxDocCount = *spec.RareTerms.MaxDocCount
			}
			rtField, b := t.resolveFieldInNestedCtx(spec.RareTerms.Field, true, nil)
			*subIdx++
			if (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && b.EffectiveArrayColumn(true) != "" {
				arrCol := b.EffectiveArrayColumn(true)
				elemValExpr := "`_elem`"
				if rtField != "" {
					if effectiveDorisScalarType(b) == schema.DorisBoolean {
						elemValExpr = "CASE WHEN `_elem` IS NULL THEN NULL WHEN LOWER(CAST(`_elem` AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END"
					} else if b.EffectiveLowercase(!strings.HasSuffix(rtField, ".keyword")) {
						elemValExpr = "LOWER(CAST(`_elem` AS STRING))"
					}
				}
				rtFrom := fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(`%s`) `_t` AS `_elem`", arrCol)
				bucketKeyExpr := fmt.Sprintf("CAST(%s AS STRING)", elemValExpr)
				wCond := "`_elem` IS NOT NULL"
				if spec.RareTerms.Missing != nil {
					missingLit := quoteStr(formatMissingScalar(spec.RareTerms.Missing))
					rtFrom = fmt.Sprintf("`base_matched` LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN [NULL] ELSE `%s` END) `_t` AS `_elem`", arrCol, arrCol, arrCol)
					bucketKeyExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", elemValExpr, missingLit)
					wCond = "1=1"
				}
				if extraWhere != "" {
					wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT `_id`) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s "+
						"GROUP BY `_bucket_key` HAVING COUNT(DISTINCT `_id`) <= %d ORDER BY `_doc_count` ASC, `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(fullAggName), bucketKeyExpr, rtFrom, wCond, maxDocCount, t.maxAggBuckets(), *subIdx,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					dedupIdx := *subIdx
					dedupFrom := fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, bucketKeyExpr, dedupIdx, rtFrom, wCond, dedupIdx, dedupIdx, dedupIdx)
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, fmt.Sprintf("`_rn_bkey_%d`", dedupIdx), dedupFrom, "1=1", subAggs)
				}
			} else {
				rawCol := t.sqlColumnRef(rtField, true, nil)
				col := rawCol
				if rtField != "" {
					if effectiveDorisScalarType(b) == schema.DorisBoolean {
						col = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN LOWER(CAST(%s AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END", rawCol, rawCol)
					} else if b.EffectiveLowercase(!strings.HasSuffix(rtField, ".keyword")) {
						col = fmt.Sprintf("LOWER(CAST(%s AS STRING))", rawCol)
					}
				}
				bucketKeyExpr := fmt.Sprintf("CAST(%s AS STRING)", col)
				wCond := fmt.Sprintf("%s IS NOT NULL", rawCol)
				if spec.RareTerms.Missing != nil {
					bucketKeyExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(spec.RareTerms.Missing)))
					wCond = "1=1"
				}
				if extraWhere != "" {
					wCond = fmt.Sprintf("(%s) AND (%s)", extraWhere, wCond)
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
						"FROM `base_matched` WHERE %s "+
						"GROUP BY `_bucket_key` HAVING COUNT(*) <= %d ORDER BY `_doc_count` ASC, `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(fullAggName), bucketKeyExpr, wCond, maxDocCount, t.maxAggBuckets(), *subIdx,
				))
				if subAggs := spec.SubAggs(); len(subAggs) > 0 {
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, bucketKeyExpr, "`base_matched`", wCond, subAggs)
				}
			}

		case spec.MultiTerms != nil && len(spec.MultiTerms.Terms) > 0:
			size := t.capBucketSize(spec.MultiTerms.Size)
			termExprs, notNulls, mtFrom, explodedAny := t.compileMultiTermsTermExprsR65(spec.MultiTerms.Terms, "`base_matched`", nil, 0)
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
			mtCountExpr := t.sqlDocCountSumExpr()
			if explodedAny {
				mtCountExpr = "COUNT(DISTINCT `_id`)"
			}
			havingClause := ""
			if spec.MultiTerms.MinDocCount != nil && *spec.MultiTerms.MinDocCount > 1 {
				havingClause = fmt.Sprintf(" HAVING %s >= %d", mtCountExpr, *spec.MultiTerms.MinDocCount)
			}
			orderBySQL, needsPostSort := compileMultiTermsOrderByR65(spec.MultiTerms.Order)
			effSize := size
			if needsPostSort && t.maxAggBuckets() > effSize {
				effSize = t.maxAggBuckets()
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s "+
					"GROUP BY `_bucket_key`%s ORDER BY %s LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(fullAggName), keyExpr, mtCountExpr, mtFrom, wCond, havingClause, orderBySQL, effSize, *subIdx,
			))
			if subAggs := spec.SubAggs(); len(subAggs) > 0 {
				if explodedAny {
					dedupIdx := *subIdx
					dedupFrom := fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, keyExpr, dedupIdx, mtFrom, wCond, dedupIdx, dedupIdx, dedupIdx)
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, fmt.Sprintf("`_rn_bkey_%d`", dedupIdx), dedupFrom, "1=1", subAggs)
				} else {
					t.appendGroupedBucketSubAggs(branches, subIdx, fullAggName, keyExpr, "`base_matched`", wCond, subAggs)
				}
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
			keyExpr := fmt.Sprintf("CAST(TRY_CAST(FLOOR(%s) AS BIGINT) AS STRING)", col)
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
			keyExpr := fmt.Sprintf("CAST(%s AS STRING)", col)
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` "+
					"FROM `base_matched` WHERE %s "+
					"GROUP BY `_bucket_key` ORDER BY TRY_CAST(`_bucket_key` AS DOUBLE) ASC, `_bucket_key` ASC LIMIT %d"+
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
				wCond := c.EffectiveSafeWhere()
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
	_, b := t.resolveFieldInNestedCtx(effField, true, nil)
	arrCol := b.EffectiveArrayColumn(true)
	wherePrefix := ""
	if extraWhere != "" {
		wherePrefix = fmt.Sprintf("(%s) AND ", extraWhere)
	}
	if b.ESType == "histogram" {
		hArrExpr := t.histogramArrayExpr(effField, b, nil)
		wClause := fmt.Sprintf(" WHERE %s`_helem` IS NOT NULL AND `_helem` != '' AND TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS BIGINT) > 0", wherePrefix)
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(COALESCE(SUM(TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS BIGINT)), 0) AS DOUBLE) AS `_doc_count` "+
				"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_ht` AS `_helem`%s",
			quoteStr(fullAggName), hArrExpr, wClause,
		))
		return
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
		if b.ESType == "aggregate_metric_double" {
			t.appendSubAggregateMetricDoubleR63(branches, subFull, fn, effField, b, parentBucketExpr, fromClause, whereClause)
			return
		}
		if b.ESType == "histogram" {
			hArrExpr := t.histogramArrayExpr(effField, b, nctx)
			subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(%s) %s AS %s", fromClause, hArrExpr, subTableAlias, subElemAlias)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL AND %s != '' AND TRY_CAST(SPLIT_PART(%s, ',', 2) AS BIGINT) > 0", whereClause, subElemAlias, subElemAlias, subElemAlias)
			hVal := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", subElemAlias)
			hCnt := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", subElemAlias)
			var metricExpr, havingClause string
			switch fn {
			case "COUNT":
				metricExpr = fmt.Sprintf("COALESCE(SUM(%s), 0)", hCnt)
			case "MIN":
				metricExpr = fmt.Sprintf("COALESCE(MIN(%s), 0)", hVal)
				havingClause = fmt.Sprintf(" HAVING COUNT(%s) > 0", hVal)
			case "MAX":
				metricExpr = fmt.Sprintf("COALESCE(MAX(%s), 0)", hVal)
				havingClause = fmt.Sprintf(" HAVING COUNT(%s) > 0", hVal)
			case "SUM":
				metricExpr = fmt.Sprintf("COALESCE(SUM((%s) * (%s)), 0)", hVal, hCnt)
			case "AVG":
				metricExpr = fmt.Sprintf("COALESCE(SUM((%s) * (%s)) / NULLIF(SUM(%s), 0), 0)", hVal, hCnt, hCnt)
				havingClause = fmt.Sprintf(" HAVING SUM(%s) > 0", hCnt)
			default:
				metricExpr = fmt.Sprintf("COALESCE(%s(%s), 0)", fn, hVal)
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`%s",
				quoteStr(subFull), parentBucketExpr, metricExpr, subFrom, subWhere, havingClause,
			))
			return
		}
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
			valExpr := fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", subElemAlias)
			subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
			if missing != nil {
				if mf, ok := resolveHistogramMissingFloat(missing); ok {
					valExpr = fmt.Sprintf("COALESCE(TRY_CAST(%s AS DOUBLE), %s)", subElemAlias, strconv.FormatFloat(mf, 'f', -1, 64))
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
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
		case t.appendRound62GroupedSubAggBranch(branches, subIdx, subFull, parentBucketExpr, fromClause, whereClause, subTableAlias, subElemAlias, nctx, subSpec):
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
				countExpr := "COUNT(`_id`)"
				if t.useDocCountFieldSQL() {
					countExpr = t.sqlDocCountSumExpr()
				}
				*branches = append(*branches, fmt.Sprintf(
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), parentBucketExpr, countExpr, fromClause, whereClause,
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
				if b.ESType == "histogram" {
					appendSubNumericMetric(subFull, "COUNT", effRateField, nil, subSpec.Rate.Script)
				} else if !isExplodedNested(b, rateField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
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
			if b.ESType == "histogram" {
				hArrExpr := t.histogramArrayExpr(effPctField, b, nctx)
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(%s) %s AS %s", fromClause, hArrExpr, subTableAlias, subElemAlias)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL AND %s != '' AND TRY_CAST(SPLIT_PART(%s, ',', 2) AS BIGINT) > 0", whereClause, subElemAlias, subElemAlias, subElemAlias)
				hVal := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", subElemAlias)
				hCnt := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", subElemAlias)
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
					*branches = append(*branches, sqlExactHistogramSubPercentileBranch(subFull+"."+pctKey, parentBucketExpr, hVal, hCnt, subFrom, subWhere, q))
				}
				continue
			}
			arrCol := b.EffectiveArrayColumn(true)
			emittedSubPctRaw := false
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
					valExpr := fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", subElemAlias)
					subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
					subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
					if subSpec.Percentiles.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Percentiles.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(TRY_CAST(%s AS DOUBLE), %s)", subElemAlias, strconv.FormatFloat(mf, 'f', -1, 64))
							subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
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
					if !emittedSubPctRaw {
						emittedSubPctRaw = true
						*branches = append(*branches, sqlCollectGroupedRawValuesBranch(subFull, parentBucketExpr, valExpr, subFrom, subWhere))
					}
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
					if !emittedSubPctRaw {
						emittedSubPctRaw = true
						rawWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", subWhere, col)
						*branches = append(*branches, sqlCollectGroupedRawValuesBranch(subFull, parentBucketExpr, col, fromClause, rawWhere))
					}
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
			if b.ESType == "histogram" {
				hArrExpr := t.histogramArrayExpr(effBpField, b, nctx)
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(%s) %s AS %s", fromClause, hArrExpr, subTableAlias, subElemAlias)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL AND %s != '' AND TRY_CAST(SPLIT_PART(%s, ',', 2) AS BIGINT) > 0", whereClause, subElemAlias, subElemAlias, subElemAlias)
				hVal := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", subElemAlias)
				hCnt := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", subElemAlias)
				for _, pct := range []float64{0.0, 25.0, 50.0, 75.0, 100.0} {
					q := pct / 100.0
					pctKey := fmt.Sprintf("%.1f", pct)
					*branches = append(*branches, sqlExactHistogramSubPercentileBranch(subFull+"."+pctKey, parentBucketExpr, hVal, hCnt, subFrom, subWhere, q))
				}
				continue
			}
			arrCol := b.EffectiveArrayColumn(true)
			emittedSubBpRaw := false
			for _, pct := range []float64{0.0, 25.0, 50.0, 75.0, 100.0} {
				q := pct / 100.0
				pctKey := fmt.Sprintf("%.1f", pct)
				if !isExplodedNested(b, effBpField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
					valExpr := fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", subElemAlias)
					subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
					subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
					if subSpec.Boxplot.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.Boxplot.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(TRY_CAST(%s AS DOUBLE), %s)", subElemAlias, strconv.FormatFloat(mf, 'f', -1, 64))
							subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
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
					if !emittedSubBpRaw {
						emittedSubBpRaw = true
						*branches = append(*branches, sqlCollectGroupedRawValuesBranch(subFull, parentBucketExpr, valExpr, subFrom, subWhere))
					}
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
					if !emittedSubBpRaw {
						emittedSubBpRaw = true
						rawWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", subWhere, col)
						*branches = append(*branches, sqlCollectGroupedRawValuesBranch(subFull, parentBucketExpr, col, fromClause, rawWhere))
					}
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
			if b.ESType == "histogram" {
				hArrExpr := t.histogramArrayExpr(effPrField, b, nctx)
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(%s) %s AS %s", fromClause, hArrExpr, subTableAlias, subElemAlias)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL AND %s != '' AND TRY_CAST(SPLIT_PART(%s, ',', 2) AS BIGINT) > 0", whereClause, subElemAlias, subElemAlias, subElemAlias)
				hVal := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", subElemAlias)
				hCnt := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", subElemAlias)
				for _, v := range subSpec.PercentileRanks.Values {
					valKey := strconv.FormatFloat(v, 'f', -1, 64)
					if !strings.Contains(valKey, ".") {
						valKey += ".0"
					}
					valLit := strconv.FormatFloat(v, 'f', -1, 64)
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(100.0 * SUM(CASE WHEN %s <= %s THEN %s ELSE 0.0 END) / NULLIF(SUM(%s), 0), 0) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key` HAVING SUM(%s) > 0",
						quoteStr(subFull+"."+valKey), parentBucketExpr, hVal, valLit, hCnt, hCnt, subFrom, subWhere, hCnt,
					))
				}
				continue
			}
			arrCol := b.EffectiveArrayColumn(true)
			emittedSubPRRaw := false
			for _, v := range subSpec.PercentileRanks.Values {
				valKey := strconv.FormatFloat(v, 'f', -1, 64)
				if !strings.Contains(valKey, ".") {
					valKey += ".0"
				}
				valLit := strconv.FormatFloat(v, 'f', -1, 64)
				if !isExplodedNested(b, effPrField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
					valExpr := fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", subElemAlias)
					subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
					subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
					if subSpec.PercentileRanks.Missing != nil {
						if mf, ok := resolveHistogramMissingFloat(subSpec.PercentileRanks.Missing); ok {
							valExpr = fmt.Sprintf("COALESCE(TRY_CAST(%s AS DOUBLE), %s)", subElemAlias, strconv.FormatFloat(mf, 'f', -1, 64))
							subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
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
					if !emittedSubPRRaw {
						emittedSubPRRaw = true
						*branches = append(*branches, sqlCollectGroupedRawValuesBranch(subFull, parentBucketExpr, valExpr, subFrom, subWhere))
					}
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
					if !emittedSubPRRaw {
						emittedSubPRRaw = true
						*branches = append(*branches, sqlCollectGroupedRawValuesBranch(subFull, parentBucketExpr, col, fromClause, subWhere))
					}
				}
			}
		case subSpec.MedianAbsoluteDeviation != nil:
			effMADField := subSpec.MedianAbsoluteDeviation.Field
			if effMADField == "" && subSpec.MedianAbsoluteDeviation.Script != nil {
				if docF, ok := extractSimpleDocFieldFromScript(subSpec.MedianAbsoluteDeviation.Script); ok {
					effMADField = docF
				}
			}
			col := t.sqlNumericColumnRef(effMADField, nctx)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
			if subSpec.MedianAbsoluteDeviation.Missing != nil && effMADField != "" {
				if mf, ok := resolveHistogramMissingFloat(subSpec.MedianAbsoluteDeviation.Missing); ok {
					col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(mf, 'f', -1, 64))
					subWhere = whereClause
				}
			}
			if subSpec.MedianAbsoluteDeviation.Script != nil {
				if se, ok := t.compileMetricScriptExprWithOverride(subSpec.MedianAbsoluteDeviation.Script, effMADField, col, nctx); ok {
					col = se
					if subSpec.MedianAbsoluteDeviation.Missing == nil {
						subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, col)
					}
				}
			}
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COALESCE(PERCENTILE_APPROX(%s, 0.5000), 0) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, col, fromClause, subWhere,
			))
			*branches = append(*branches, sqlCollectGroupedRawValuesBranch(subFull, parentBucketExpr, col, fromClause, subWhere))
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
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
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
			subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, cond.EffectiveSafeWhere())
			*branches = append(*branches, fmt.Sprintf(
				"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(`_id`) AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s GROUP BY `_bucket_key`",
				quoteStr(subFull), parentBucketExpr, fromClause, subWhere,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, parentBucketExpr, fromClause, subWhere, nctx, nestedSubs)
			}
		case subSpec.Missing != nil:
			subWhere := "FALSE"
			if subSpec.Missing.Missing == nil {
				existsPred := t.compileExistsPredicate(subSpec.Missing.Field, nctx)
				subWhere = fmt.Sprintf("(%s) AND NOT (%s)", whereClause, existsPred)
			}
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
			if b.ESType == "histogram" {
				appendSubNumericMetric(subFull, "COUNT", effVCField, subSpec.ValueCount.Missing, subSpec.ValueCount.Script)
				continue
			}
			arrCol := b.EffectiveArrayColumn(true)
			if !isExplodedNested(b, effVCField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) {
				valExpr := subElemAlias
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
				if subSpec.ValueCount.Missing != nil {
					valExpr = fmt.Sprintf("COALESCE(%s, %s)", subElemAlias, quoteStr(formatMissingScalar(subSpec.ValueCount.Missing)))
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
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
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
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
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
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
				if (nctx == nil || nctx.elemVar == "") && b.Kind == schema.StoragePromotedScalar && b.ESType == "unsigned_long" && effSubField != "" {
					col = t.sqlTypedColumnRef(effSubField, uint64(math.MaxUint64), true, nctx)
				}
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
				col = fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", subElemAlias)
				if b.ESType == "date_nanos" {
					col = fmt.Sprintf("(TRY_CAST(%s AS DOUBLE) / 1000000.0)", subElemAlias)
				}
				notNullExpr = subElemAlias
				subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				if subSpec.DateHistogram.Missing != nil {
					if missMs, ok := t.resolveDateHistogramMissingMs(b.ESType, subSpec.DateHistogram.Missing); ok {
						subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
						col = fmt.Sprintf("COALESCE(%s, %d)", col, missMs)
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
			childBucketExpr := t.buildDateHistogramBucketKeySQL(subSpec.DateHistogram, col)
			compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, childBucketExpr)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, notNullExpr)
			if hasMissing {
				subWhere = whereClause
			}
			if subSpec.DateHistogram.HardBounds != nil {
				subDHMaxOp := "<="
				if t.Opts.ES8Compat {
					subDHMaxOp = "<"
				}
				if minMs, okMin := t.resolveDateHistogramBoundMs(b, subSpec.DateHistogram.Format, subSpec.DateHistogram.HardBounds.Min); okMin {
					subWhere = fmt.Sprintf("(%s) AND (%s >= %d)", subWhere, col, minMs)
				}
				if maxMs, okMax := t.resolveDateHistogramBoundMs(b, subSpec.DateHistogram.Format, subSpec.DateHistogram.HardBounds.Max); okMax {
					subWhere = fmt.Sprintf("(%s) AND (%s %s %d)", subWhere, col, subDHMaxOp, maxMs)
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
			isHistType := b.ESType == "histogram"
			if isHistType {
				hArrExpr := t.histogramArrayExpr(effHField, b, nctx)
				subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(%s) %s AS %s", fromClause, hArrExpr, subTableAlias, subElemAlias)
				col = fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", subElemAlias)
				notNullExpr = subElemAlias
			} else if isExplodedNested(b, effHField) {
				col = t.sqlNumericColumnRef(effHField, nctx)
				notNullExpr = t.sqlColumnRef(effHField, true, nctx)
			} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
				col = fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", subElemAlias)
				notNullExpr = subElemAlias
				subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				if subSpec.Histogram.Missing != nil {
					if missVal, ok := resolveHistogramMissingFloat(subSpec.Histogram.Missing); ok {
						subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
						col = fmt.Sprintf("COALESCE(TRY_CAST(%s AS DOUBLE), %s)", subElemAlias, strconv.FormatFloat(missVal, 'f', -1, 64))
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
			histKeyB := b
			if subSpec.Histogram.Script != nil {
				histKeyB = schema.FieldBinding{ESType: "double", DorisType: schema.DorisDouble}
			}
			colDiv := ensureDoubleHistogramExprR64(col, histKeyB)
			childBucketExpr := t.formatHistogramBucketKeySQLWithRawR65(colDiv, subFull, offset, interval, histKeyB)
			compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, childBucketExpr)
			subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, notNullExpr)
			if isHistType {
				subWhere = fmt.Sprintf("(%s) AND %s IS NOT NULL AND %s != '' AND TRY_CAST(SPLIT_PART(%s, ',', 2) AS BIGINT) > 0", whereClause, subElemAlias, subElemAlias, subElemAlias)
			} else if hasMissing {
				subWhere = whereClause
			}
			if subSpec.Histogram.HardBounds != nil {
				subHMaxOp := "<="
				if t.Opts.ES8Compat {
					subHMaxOp = "<"
				}
				if minF, okMin := resolveHistogramMissingFloat(subSpec.Histogram.HardBounds.Min); okMin {
					subWhere = fmt.Sprintf("(%s) AND (%s >= %s)", subWhere, col, strconv.FormatFloat(minF, 'f', -1, 64))
				}
				if maxF, okMax := resolveHistogramMissingFloat(subSpec.Histogram.HardBounds.Max); okMax {
					subWhere = fmt.Sprintf("(%s) AND (%s %s %s)", subWhere, col, subHMaxOp, strconv.FormatFloat(maxF, 'f', -1, 64))
				}
			}
			hChildCountExpr := "COUNT(`_id`)"
			isHArray := !isExplodedNested(b, effHField) && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield)
			if isHistType {
				hChildCountExpr = fmt.Sprintf("COALESCE(SUM(TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)), 0)", subElemAlias)
			} else if isHArray && nctx == nil {
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
				subCountExpr := "COUNT(`_id`)"
				isHistRange := false
				if subSpec.IPRange != nil {
					ipCol := t.sqlColumnRef(effRField, true, nctx)
					if isArray || isNestedMultiVal {
						ipCol = "_x"
					}
					hexCol := sqlCanonicalIPHexExpr(ipCol)
					var conds []string
					if !isArray && !isNestedMultiVal {
						conds = append(conds, fmt.Sprintf("%s IS NOT NULL", ipCol))
					}
					if rng.Mask != "" {
						if startHex, endHex, okCIDR := parseCanonicalIPCIDRHexBounds(rng.Mask); okCIDR {
							conds = append(conds,
								fmt.Sprintf("%s >= %s", hexCol, quoteStr(startHex)),
								fmt.Sprintf("%s <= %s", hexCol, quoteStr(endHex)),
							)
						} else {
							conds = append(conds, "1=0")
						}
					} else {
						boundsValid := true
						for _, cand := range []any{rng.From, rng.To} {
							if cand == nil {
								continue
							}
							if _, ok := parseIPToUpperHex16(cand); !ok {
								boundsValid = false
								break
							}
						}
						if !boundsValid {
							conds = append(conds, "1=0")
						} else {
							if rng.From != nil {
								if h, ok := parseIPToUpperHex16(rng.From); ok {
									conds = append(conds, fmt.Sprintf("%s >= %s", hexCol, quoteStr(h)))
								}
							}
							if rng.To != nil {
								if h, ok := parseIPToUpperHex16(rng.To); ok {
									conds = append(conds, fmt.Sprintf("%s < %s", hexCol, quoteStr(h)))
								}
							}
						}
					}
					if isNestedMultiVal {
						rawCol := t.sqlColumnRef(effRField, true, nctx)
						if len(conds) == 0 {
							rWhere = fmt.Sprintf("%s IS NOT NULL", rawCol)
						} else {
							rWhere = fmt.Sprintf("array_exists(_x -> %s, TRY_CAST(%s AS ARRAY<STRING>))", strings.Join(conds, " AND "), rawCol)
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
				} else if b.ESType == "histogram" {
					isHistRange = true
					hArrExpr := t.histogramArrayExpr(effRField, b, nctx)
					hVal := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", subElemAlias)
					if rngSpec.Script != nil {
						if scriptExpr, ok := t.compileMetricScriptExprWithOverride(rngSpec.Script, effRField, hVal, nil); ok {
							hVal = scriptExpr
						}
					}
					var fromLit, toLit string
					if rng.From != nil {
						fromLit = quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.From, now))
					}
					if rng.To != nil {
						toLit = quoteValue(t.coerceRangeAggBoundWithNow(effRField, rngSpec, rng.To, now))
					}
					subFrom, rWhere, subCountExpr = compileHistogramRangeBucketSQLR65(fromClause, hArrExpr, subTableAlias, subElemAlias, hVal, fromLit, toLit)
				} else if isArray || isNestedMultiVal {
					elemExpr := "TRY_CAST(_x AS DOUBLE)"
					if b.ESType == "date_nanos" {
						elemExpr = "(TRY_CAST(_x AS DOUBLE) / 1000000.0)"
					}
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
						arrExpr = fmt.Sprintf("TRY_CAST(%s AS ARRAY<STRING>)", rawCol)
						if rngSpec.Missing != nil {
							if mu, okU := t.resolveUnsignedLongRangeAggMissingExact(effRField, rngSpec); okU {
								arrExpr = fmt.Sprintf("CASE WHEN %s IS NULL OR array_size(TRY_CAST(%s AS ARRAY<STRING>)) = 0 THEN [%s] ELSE TRY_CAST(%s AS ARRAY<STRING>) END", rawCol, rawCol, quoteStr(strconv.FormatUint(mu, 10)), rawCol)
							} else if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
								arrExpr = fmt.Sprintf("CASE WHEN %s IS NULL OR array_size(TRY_CAST(%s AS ARRAY<STRING>)) = 0 THEN [%s] ELSE TRY_CAST(%s AS ARRAY<STRING>) END", rawCol, rawCol, strconv.FormatFloat(mf, 'f', -1, 64), rawCol)
							}
						}
					} else if rngSpec.Missing != nil {
						if mu, okU := t.resolveUnsignedLongRangeAggMissingExact(effRField, rngSpec); okU {
							missArrLit := fmt.Sprintf("CAST([CAST(%s AS LARGEINT)] AS ARRAY<LARGEINT>)", strconv.FormatUint(mu, 10))
							arrExpr = fmt.Sprintf("CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END", arrCol, arrCol, missArrLit, arrCol)
						} else if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
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
						if mu, okU := t.resolveUnsignedLongRangeAggMissingExact(effRField, rngSpec); okU {
							col = fmt.Sprintf("COALESCE(%s, CAST(%s AS LARGEINT))", t.sqlColumnRef(effRField, true, nctx), strconv.FormatUint(mu, 10))
						} else if mf, ok := t.resolveRangeAggMissingFloat(effRField, rngSpec, now); ok {
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
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s GROUP BY `_bucket_key`",
					quoteStr(subFull), compKeyExpr, subCountExpr, subFrom, subWhere,
				))
				if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
					nextKeyExpr := compKeyExpr
					nextFrom := subFrom
					nextWhere := subWhere
					if isHistRange {
						*subIdx++
						dedupIdx := *subIdx
						nextFrom = fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, compKeyExpr, dedupIdx, subFrom, subWhere, dedupIdx, dedupIdx, dedupIdx)
						nextKeyExpr = fmt.Sprintf("`_rn_bkey_%d`", dedupIdx)
						nextWhere = "1=1"
					}
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, nextKeyExpr, nextFrom, nextWhere, nctx, nestedSubs)
				}
			}
		case subSpec.Filters != nil:
			if subSpec.Filters.IsAnonymous {
				var allSafeConds []string
				for i, fq := range subSpec.Filters.AnonymousFilters {
					fCond := t.CompileQuery(&fq, false, nctx)
					fSafe := fCond.EffectiveSafeWhere()
					allSafeConds = append(allSafeConds, fmt.Sprintf("(%s)", fSafe))
					bKey := strconv.Itoa(i)
					compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(bKey))
					subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, fSafe)
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
					fSafe := fCond.EffectiveSafeWhere()
					allSafeConds = append(allSafeConds, fmt.Sprintf("(%s)", fSafe))
					compKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, quoteStr(fk))
					subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, fSafe)
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
			var corrCol string
			var ok bool
			if t.Schema != nil {
				corrCol, ok = t.Schema.NestedRoots[subSpec.Nested.Path]
			}
			if !ok && schemaHasNestedObjectPathR65(t.Schema, subSpec.Nested.Path) {
				corrCol = "n__" + schema.SanitizeDorisIdentifier(subSpec.Nested.Path)
				ok = true
			}
			if !ok {
				if t.Schema != nil && (len(t.Schema.Fields) > 0 || len(t.Schema.NestedRoots) > 0) {
					if schemaHasMappedNonNestedPathR66(t.Schema, subSpec.Nested.Path) {
						if t.searchErr == nil {
							t.searchErr = fmt.Errorf("[nested] failed to find nested object under path [%s]", subSpec.Nested.Path)
						}
						continue
					}
					*branches = append(*branches, fmt.Sprintf(
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(CAST(NULL AS STRING)) AS DOUBLE) AS `_doc_count` "+
							"FROM %s WHERE %s GROUP BY `_bucket_key`",
						quoteStr(subFull), parentBucketExpr, fromClause, whereClause,
					))
					continue
				}
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
						compFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", compFrom, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, tblAlias, elemAlias)
					} else {
						compFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", compFrom, arrCol, tblAlias, elemAlias)
					}
					if isNumeric {
						return fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", elemAlias)
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
						hasMiss := srcSpec.DateHistogram.Missing != nil || srcSpec.DateHistogram.MissingBucket
						effDHField := srcSpec.DateHistogram.Field
						if effDHField == "" && srcSpec.DateHistogram.Script != nil {
							if docF, ok := extractSimpleDocFieldFromScript(srcSpec.DateHistogram.Script); ok {
								effDHField = docF
							}
						}
						_, dhB := t.resolveFieldInNestedCtx(effDHField, true, nctx)
						col := resolveSubCompSourceCol(effDHField, true, hasMiss)
						if dhB.ESType == "date_nanos" && !isExplodedNested(dhB, effDHField) && (dhB.Kind == schema.StoragePromotedArray || dhB.Kind == schema.StorageNestedSubfield) {
							col = fmt.Sprintf("(%s / 1000000.0)", col)
						}
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
						expr := t.buildDateHistogramBucketKeySQL(srcSpec.DateHistogram, col)
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
						hB := t.Schema.ResolveEffectiveField(effHField, true)
						if srcSpec.Histogram.Script != nil {
							hB = schema.FieldBinding{ESType: "double", DorisType: schema.DorisDouble}
						}
						if srcSpec.Histogram.Missing != nil {
							if missVal, ok := resolveHistogramMissingFloat(srcSpec.Histogram.Missing); ok {
								col = fmt.Sprintf("COALESCE(%s, %s)", col, strconv.FormatFloat(missVal, 'f', -1, 64))
							}
						}
						colDiv := ensureDoubleHistogramExprR64(col, hB)
						expr := t.formatHistogramBucketKeySQLWithRawR65(colDiv, subFull+"."+sk, offset, interval, hB)
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
					case srcSpec.GeotileGrid != nil:
						prec := 7
						if srcSpec.GeotileGrid.Precision != nil {
							prec = *srcSpec.GeotileGrid.Precision
						}
						latExpr, lonExpr, geoNotNull := t.resolveGeoPointLatLonSQL(srcSpec.GeotileGrid.Field, nctx)
						expr := EncodeGeotileSQL(latExpr, lonExpr, prec)
						if srcSpec.GeotileGrid.MissingBucket {
							expr = fmt.Sprintf("COALESCE(%s, '__ES_MISSING_BUCKET__')", expr)
						} else {
							notNullConds = append(notNullConds, geoNotNull)
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
			rtField, b := t.resolveFieldInNestedCtx(subSpec.RareTerms.Field, true, nctx)
			*subIdx++
			if nctx == nil && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && b.EffectiveArrayColumn(true) != "" {
				arrCol := b.EffectiveArrayColumn(true)
				subFrom := fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", fromClause, arrCol, subTableAlias, subElemAlias)
				elemValExpr := subElemAlias
				if rtField != "" {
					if effectiveDorisScalarType(b) == schema.DorisBoolean {
						elemValExpr = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN LOWER(CAST(%s AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END", subElemAlias, subElemAlias)
					} else if b.EffectiveLowercase(!strings.HasSuffix(rtField, ".keyword")) {
						elemValExpr = fmt.Sprintf("LOWER(CAST(%s AS STRING))", subElemAlias)
					}
				}
				valExpr := fmt.Sprintf("CAST(%s AS STRING)", elemValExpr)
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, subElemAlias)
				if subSpec.RareTerms.Missing != nil {
					missingLit := quoteStr(formatMissingScalar(subSpec.RareTerms.Missing))
					subFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", fromClause, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, subTableAlias, subElemAlias)
					valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", elemValExpr, missingLit)
					subWhere = whereClause
				}
				childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, valExpr)
				*branches = append(*branches, fmt.Sprintf(
					"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
						"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(COUNT(DISTINCT `_id`) AS DOUBLE) AS `_doc_count` "+
						"FROM %s WHERE %s "+
						"GROUP BY `_bucket_key` HAVING COUNT(DISTINCT `_id`) <= %d ORDER BY `_doc_count` ASC, `_bucket_key` ASC LIMIT %d"+
						") `_agg_sub_%d`",
					quoteStr(subFull), childKeyExpr, subFrom, subWhere, maxDocCount, t.maxAggBuckets(), *subIdx,
				))
				if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
					dedupIdx := *subIdx
					nextFrom := fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, childKeyExpr, dedupIdx, subFrom, subWhere, dedupIdx, dedupIdx, dedupIdx)
					nextKeyExpr := fmt.Sprintf("`_rn_bkey_%d`", dedupIdx)
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, nextKeyExpr, nextFrom, "1=1", nctx, nestedSubs)
				}
			} else {
				rawCol := t.sqlColumnRef(rtField, true, nctx)
				col := rawCol
				if rtField != "" {
					if effectiveDorisScalarType(b) == schema.DorisBoolean {
						col = fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN LOWER(CAST(%s AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END", rawCol, rawCol)
					} else if b.EffectiveLowercase(!strings.HasSuffix(rtField, ".keyword")) {
						col = fmt.Sprintf("LOWER(CAST(%s AS STRING))", rawCol)
					}
				}
				subWhere := fmt.Sprintf("(%s) AND %s IS NOT NULL", whereClause, rawCol)
				valExpr := fmt.Sprintf("CAST(%s AS STRING)", col)
				if subSpec.RareTerms.Missing != nil {
					valExpr = fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(subSpec.RareTerms.Missing)))
					subWhere = whereClause
				}
				childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, valExpr)
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
			}

		case subSpec.MultiTerms != nil && len(subSpec.MultiTerms.Terms) > 0:
			size := t.capBucketSize(subSpec.MultiTerms.Size)
			termExprs, notNulls, subFrom, explodedAny := t.compileMultiTermsTermExprsR65(subSpec.MultiTerms.Terms, fromClause, nctx, explodeDepth)
			keyExpr := termExprs[0]
			if len(termExprs) > 1 {
				keyExpr = fmt.Sprintf("CONCAT_WS('|', %s)", strings.Join(termExprs, ", "))
			}
			childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', %s)", parentBucketExpr, keyExpr)
			subWhere := whereClause
			if len(notNulls) > 0 {
				subWhere = fmt.Sprintf("(%s) AND (%s)", whereClause, strings.Join(notNulls, " AND "))
			}
			mtCountExpr := t.sqlDocCountSumExpr()
			if explodedAny {
				mtCountExpr = "COUNT(DISTINCT `_id`)"
			}
			havingClause := ""
			if subSpec.MultiTerms.MinDocCount != nil && *subSpec.MultiTerms.MinDocCount > 1 {
				havingClause = fmt.Sprintf(" HAVING %s >= %d", mtCountExpr, *subSpec.MultiTerms.MinDocCount)
			}
			orderBySQL, needsPostSort := compileMultiTermsOrderByR65(subSpec.MultiTerms.Order)
			effSize := size
			if needsPostSort && t.maxAggBuckets() > effSize {
				effSize = t.maxAggBuckets()
			}
			*subIdx++
			*branches = append(*branches, fmt.Sprintf(
				"SELECT `_agg_name`, `_bucket_key`, `_doc_count` FROM ("+
					"SELECT %s AS `_agg_name`, %s AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
					"FROM %s WHERE %s "+
					"GROUP BY `_bucket_key`%s ORDER BY %s LIMIT %d"+
					") `_agg_sub_%d`",
				quoteStr(subFull), childKeyExpr, mtCountExpr, subFrom, subWhere, havingClause, orderBySQL, effSize, *subIdx,
			))
			if nestedSubs := subSpec.SubAggs(); len(nestedSubs) > 0 {
				if explodedAny {
					dedupIdx := *subIdx
					nextFrom := fmt.Sprintf("`base_matched` INNER JOIN (SELECT DISTINCT `_id` AS `_rn_id_%d`, %s AS `_rn_bkey_%d` FROM %s WHERE %s) `_rn_dedup_%d` ON `base_matched`.`_id` = `_rn_dedup_%d`.`_rn_id_%d`", dedupIdx, childKeyExpr, dedupIdx, subFrom, subWhere, dedupIdx, dedupIdx, dedupIdx)
					nextKeyExpr := fmt.Sprintf("`_rn_bkey_%d`", dedupIdx)
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, nextKeyExpr, nextFrom, "1=1", nctx, nestedSubs)
				} else {
					t.appendGroupedBucketSubAggsWithNested(branches, subIdx, subFull, childKeyExpr, subFrom, subWhere, nctx, nestedSubs)
				}
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
			childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', CAST(TRY_CAST(FLOOR(%s / 3600000) * 3600000 AS BIGINT) AS STRING))", parentBucketExpr, col)
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
			childKeyExpr := fmt.Sprintf("CONCAT(%s, '\\x1f', CAST(%s AS STRING))", parentBucketExpr, col)
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
				subWhere := fmt.Sprintf("(%s) AND (%s)", whereClause, c.EffectiveSafeWhere())
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
		if val == math.Trunc(val) {
			if val >= -9223372036854775808.0 && val < 9223372036854775808.0 {
				return strconv.FormatInt(int64(val), 10)
			}
			if val >= 9223372036854775808.0 && val < 18446744073709551616.0 {
				return strconv.FormatUint(uint64(val), 10)
			}
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
	if !strings.Contains(s, "/") || strings.Contains(s, ":") {
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

func parseIPv6CIDRHexBounds(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") || !strings.Contains(s, ":") {
		return "", "", false
	}
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil || ipNet == nil {
		return "", "", false
	}
	ip16 := ipNet.IP.To16()
	if len(ip16) != 16 {
		return "", "", false
	}
	var mask16 [16]byte
	switch len(ipNet.Mask) {
	case 16:
		copy(mask16[:], ipNet.Mask)
	case 4:
		for i := 0; i < 12; i++ {
			mask16[i] = 0xff
		}
		copy(mask16[12:], ipNet.Mask)
	default:
		return "", "", false
	}
	var start16, end16 [16]byte
	for i := 0; i < 16; i++ {
		start16[i] = ip16[i] & mask16[i]
		end16[i] = start16[i] | ^mask16[i]
	}
	return strings.ToUpper(hex.EncodeToString(start16[:])), strings.ToUpper(hex.EncodeToString(end16[:])), true
}

func sqlCanonicalIPHexExpr(colExpr string) string {
	v4Expr := fmt.Sprintf("IPV4_STRING_TO_NUM_OR_NULL(%s)", colExpr)
	return fmt.Sprintf("IF(%s IS NOT NULL, CONCAT('00000000000000000000FFFF', LPAD(HEX(%s), 8, '0')), HEX(IPV6_STRING_TO_NUM_OR_NULL(%s)))", v4Expr, v4Expr, colExpr)
}

func parseCanonicalIPCIDRHexBounds(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		return "", "", false
	}
	if startNum, endNum, ok := parseCIDRBounds(s); ok {
		return fmt.Sprintf("00000000000000000000FFFF%08X", startNum&0xFFFFFFFF),
			fmt.Sprintf("00000000000000000000FFFF%08X", endNum&0xFFFFFFFF),
			true
	}
	return parseIPv6CIDRHexBounds(s)
}

func parseIPToUpperHex16(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return schema.CanonicalIPToUpperHex16(s)
}

func parseDateNanosQueryScalar(v any, format string, tzOffsetMs int64, now time.Time, roundUp bool) (int64, bool) {
	if v == nil {
		return 0, false
	}
	adjustTZ := func(rawStr string, ns int64) int64 {
		if tzOffsetMs == 0 {
			return ns
		}
		lowerFmt := strings.ToLower(format)
		if strings.Contains(lowerFmt, "epoch") {
			return ns
		}
		datePart := strings.TrimSpace(rawStr)
		if idx := strings.Index(datePart, "||"); idx >= 0 {
			datePart = strings.TrimSpace(datePart[:idx])
		}
		if _, numErr := strconv.ParseFloat(datePart, 64); numErr != nil &&
			!strings.HasPrefix(datePart, "now") &&
			!strings.HasSuffix(datePart, "Z") && !strings.HasSuffix(datePart, "z") &&
			!strings.Contains(datePart[min(10, len(datePart)):], "+") &&
			!strings.Contains(datePart[min(10, len(datePart)):], "-") {
			return ns - tzOffsetMs*1_000_000
		}
		return ns
	}
	switch tv := v.(type) {
	case string:
		ns, ok := schema.ParseESDateBoundWithFormatToEpochNanos(tv, format, now, roundUp)
		if !ok {
			return 0, false
		}
		return adjustTZ(tv, ns), true
	case int:
		return parseDateNanosNumericScalar(strconv.Itoa(tv), int64(tv), true, format, now, roundUp)
	case int64:
		return parseDateNanosNumericScalar(strconv.FormatInt(tv, 10), tv, true, format, now, roundUp)
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return 0, false
		}
		if tv == math.Trunc(tv) && tv >= float64(math.MinInt64) && tv < 9223372036854775808.0 {
			iv := int64(tv)
			return parseDateNanosNumericScalar(strconv.FormatInt(iv, 10), iv, true, format, now, roundUp)
		}
		return parseDateNanosNumericScalar(strconv.FormatFloat(tv, 'f', -1, 64), 0, false, format, now, roundUp)
	case json.Number:
		if iv, err := tv.Int64(); err == nil {
			return parseDateNanosNumericScalar(tv.String(), iv, true, format, now, roundUp)
		}
		return parseDateNanosNumericScalar(tv.String(), 0, false, format, now, roundUp)
	default:
		return 0, false
	}
}

func parseDateNanosNumericScalar(raw string, iv int64, isInt bool, format string, now time.Time, roundUp bool) (int64, bool) {
	if isInt && (iv > math.MaxInt64/1_000_000 || iv < math.MinInt64/1_000_000) {
		return iv, true
	}
	if ns, ok := schema.ParseESDateBoundWithFormatToEpochNanos(raw, format, now, roundUp); ok {
		return ns, true
	}
	if isInt {
		if strings.EqualFold(format, "epoch_second") {
			return iv * 1_000_000_000, true
		}
		if strings.EqualFold(format, "epoch_nanos") {
			return iv, true
		}
		if iv <= math.MaxInt64/1_000_000 && iv >= math.MinInt64/1_000_000 {
			return iv * 1_000_000, true
		}
		return iv, true
	}
	return 0, false
}

func (t *Transpiler) histogramArrayExpr(field string, b schema.FieldBinding, nctx *nestedCtx) string {
	effField := field
	if b.AliasTarget != "" {
		effField = b.AliasTarget
	}
	if nctx != nil && nctx.elemVar != "" && ((b.Kind == schema.StorageNestedSubfield && nctx.nestedPath == b.NestedPath) || strings.HasPrefix(effField, nctx.nestedPath+".")) {
		relPath := t.nestedRelativeJSONPath(field, false, nctx.nestedPath)
		return fmt.Sprintf("TRY_CAST(json_extract_string(%s, %s) AS ARRAY<STRING>)", nctx.elemVar, quoteStr(relPath+"._h"))
	}
	srcPath := b.SourceJSONPath
	if len(srcPath) == 0 && effField != "" {
		srcPath = strings.Split(effField, ".")
	}
	var pathBuilder strings.Builder
	for _, seg := range srcPath {
		_, _ = fmt.Fprintf(&pathBuilder, "[%s]", quoteStr(seg))
	}
	return fmt.Sprintf("TRY_CAST(`_doc`%s['_h'] AS ARRAY<STRING>)", pathBuilder.String())
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
			if b.ESType == "histogram" || b.ESType == "rank_feature" || b.ESType == "rank_features" {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: Fielddata is not supported on field [%s] of type [%s]", s.Entry.Field, b.ESType)
				}
			}
			t.checkFieldDocValues(resolvedField, b)
			relPath := t.nestedRelativeJSONPath(resolvedField, true, nctx.nestedPath)
			rawExtract := fmt.Sprintf("json_extract_string(%s, %s)", nctx.elemVar, quoteStr(relPath))
			effDT := effectiveDorisScalarType(b)
			col := rawExtract
			if b.ESType == "ip" || strings.EqualFold(s.Entry.Type, "ip") {
				col = sqlCanonicalIPHexExpr(rawExtract)
			} else {
				switch effDT {
				case schema.DorisLargeInt, schema.DorisLargeIntArray:
					col = fmt.Sprintf("TRY_CAST(%s AS LARGEINT)", rawExtract)
				case schema.DorisBigInt, schema.DorisInt:
					col = fmt.Sprintf("TRY_CAST(%s AS BIGINT)", rawExtract)
				case schema.DorisDouble:
					col = fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", rawExtract)
				case schema.DorisBoolean:
					col = fmt.Sprintf("TRY_CAST(%s AS BOOLEAN)", rawExtract)
				default:
					if strings.EqualFold(s.Entry.Type, "number") || strings.EqualFold(s.Entry.Type, "double") || strings.EqualFold(s.Entry.Type, "float") {
						col = fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", rawExtract)
					} else if strings.EqualFold(s.Entry.Type, "unsigned_long") {
						col = fmt.Sprintf("TRY_CAST(%s AS LARGEINT)", rawExtract)
					} else if strings.EqualFold(s.Entry.Type, "long") || strings.EqualFold(s.Entry.Type, "integer") {
						col = fmt.Sprintf("TRY_CAST(%s AS BIGINT)", rawExtract)
					} else if b.EffectiveLowercase(true) {
						col = fmt.Sprintf("lower(%s)", rawExtract)
					}
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
				return fmt.Sprintf("COALESCE(array_size(TRY_CAST(json_extract_string(%s, %s) AS ARRAY<STRING>)), 0)", nctx.elemVar, quoteStr(relPath)), true
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
			case uint64:
				return strconv.FormatUint(v, 10), true
			case float64:
				if !math.IsNaN(v) && !math.IsInf(v, 0) {
					if v == math.Trunc(v) {
						if v >= -9223372036854775808.0 && v < 9223372036854775808.0 {
							return strconv.FormatInt(int64(v), 10), true
						}
						if v >= 9223372036854775808.0 && v < 18446744073709551616.0 {
							return strconv.FormatUint(uint64(v), 10), true
						}
					}
					return strconv.FormatFloat(v, 'f', -1, 64), true
				}
			case json.Number:
				if i, err := v.Int64(); err == nil {
					return strconv.FormatInt(i, 10), true
				}
				if u, err := strconv.ParseUint(v.String(), 10, 64); err == nil {
					return strconv.FormatUint(u, 10), true
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
	if b.ESType == "histogram" {
		hArrExpr := t.histogramArrayExpr(effField, b, nil)
		wherePrefix := ""
		if extraWhere != "" {
			wherePrefix = fmt.Sprintf("(%s) AND ", extraWhere)
		}
		wClause := fmt.Sprintf(" WHERE %s`_helem` IS NOT NULL AND `_helem` != '' AND TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS BIGINT) > 0", wherePrefix)
		hVal := "TRY_CAST(SPLIT_PART(`_helem`, ',', 1) AS DOUBLE)"
		hCnt := "TRY_CAST(SPLIT_PART(`_helem`, ',', 2) AS DOUBLE)"
		var metricExpr string
		var havingClause string
		switch sqlFunc {
		case "MIN":
			metricExpr = fmt.Sprintf("COALESCE(MIN(%s), 0)", hVal)
			havingClause = fmt.Sprintf(" HAVING COUNT(%s) > 0", hVal)
		case "MAX":
			metricExpr = fmt.Sprintf("COALESCE(MAX(%s), 0)", hVal)
			havingClause = fmt.Sprintf(" HAVING COUNT(%s) > 0", hVal)
		case "SUM":
			metricExpr = fmt.Sprintf("COALESCE(SUM((%s) * (%s)), 0)", hVal, hCnt)
		case "AVG":
			metricExpr = fmt.Sprintf("COALESCE(SUM((%s) * (%s)) / NULLIF(SUM(%s), 0), 0)", hVal, hCnt, hCnt)
			havingClause = fmt.Sprintf(" HAVING SUM(%s) > 0", hCnt)
		default:
			metricExpr = fmt.Sprintf("COALESCE(%s(%s), 0)", sqlFunc, hVal)
		}
		*branches = append(*branches, fmt.Sprintf(
			"SELECT %s AS `_agg_name`, '_metric' AS `_bucket_key`, CAST(%s AS DOUBLE) AS `_doc_count` "+
				"FROM `base_matched` LATERAL VIEW EXPLODE(%s) `_ht` AS `_helem`%s%s",
			quoteStr(fullAggName), metricExpr, hArrExpr, wClause, havingClause,
		))
		return
	}
	if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := b.EffectiveArrayColumn(true)
		wherePrefix := ""
		if extraWhere != "" {
			wherePrefix = fmt.Sprintf("(%s) AND ", extraWhere)
		}
		valExpr := "TRY_CAST(`_nel` AS DOUBLE)"
		if b.ESType == "date_nanos" {
			valExpr = "(TRY_CAST(`_nel` AS DOUBLE) / 1000000.0)"
		}
		explodeExpr := fmt.Sprintf("`%s`", arrCol)
		wClause := fmt.Sprintf(" WHERE %s`_nel` IS NOT NULL", wherePrefix)
		if missing != nil {
			if mf, ok := resolveHistogramMissingFloat(missing); ok {
				valExpr = fmt.Sprintf("COALESCE(%s, %s)", valExpr, strconv.FormatFloat(mf, 'f', -1, 64))
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
					return fmt.Sprintf("COALESCE(array_size(TRY_CAST(%s AS ARRAY<STRING>)), 0)", col), true
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
			case uint64:
				return strconv.FormatUint(v, 10), true
			case float64:
				if !math.IsNaN(v) && !math.IsInf(v, 0) {
					if v == math.Trunc(v) {
						if v >= -9223372036854775808.0 && v < 9223372036854775808.0 {
							return strconv.FormatInt(int64(v), 10), true
						}
						if v >= 9223372036854775808.0 && v < 18446744073709551616.0 {
							return strconv.FormatUint(uint64(v), 10), true
						}
					}
					return strconv.FormatFloat(v, 'f', -1, 64), true
				}
			case json.Number:
				if i, err := v.Int64(); err == nil {
					return strconv.FormatInt(i, 10), true
				}
				if u, err := strconv.ParseUint(v.String(), 10, 64); err == nil {
					return strconv.FormatUint(u, 10), true
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
	explicitSortFmt := strings.ToLower(strings.TrimSpace(effFormat))
	if effFormat == "" {
		effFormat = b.Format
	}
	lowerFmt := strings.ToLower(effFormat)
	isNanos := effType == "date_nanos" || b.ESType == "date_nanos"
	if isNanos && explicitSortFmt == "epoch_millis" {
		switch v := val.(type) {
		case int:
			if int64(v) <= math.MaxInt64/1_000_000 && int64(v) >= math.MinInt64/1_000_000 {
				return int64(v) * 1_000_000
			}
		case int64:
			if v <= math.MaxInt64/1_000_000 && v >= math.MinInt64/1_000_000 {
				return v * 1_000_000
			}
		case json.Number:
			if iv, err := v.Int64(); err == nil && iv <= math.MaxInt64/1_000_000 && iv >= math.MinInt64/1_000_000 {
				return iv * 1_000_000
			}
		}
		return val
	}
	if !strings.Contains(lowerFmt, "epoch_second") || strings.Contains(lowerFmt, "epoch_millis") || strings.Contains(lowerFmt, "epoch_nanos") {
		return val
	}
	scale := int64(1000)
	scaleF := 1000.0
	if isNanos {
		scale = 1_000_000_000
		scaleF = 1_000_000_000.0
	}
	switch v := val.(type) {
	case int:
		if isNanos && (int64(v) > math.MaxInt64/scale || int64(v) < math.MinInt64/scale) {
			return int64(v)
		}
		return int64(v) * scale
	case int64:
		if isNanos && (v > math.MaxInt64/scale || v < math.MinInt64/scale) {
			return v
		}
		return v * scale
	case float64:
		return int64(math.Round(v * scaleF))
	case json.Number:
		if iv, err := v.Int64(); err == nil {
			if isNanos && (iv > math.MaxInt64/scale || iv < math.MinInt64/scale) {
				return iv
			}
			return iv * scale
		}
		if fv, err := v.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			return int64(math.Round(fv * scaleF))
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
	if effType == "ip" || b.ESType == "ip" {
		if h, ok := schema.CanonicalIPToUpperHex16(mStr); ok {
			return h, quoteStr(h)
		}
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("illegal_argument_exception: '%s' is not an IP string literal", mStr)
		}
		return "", quoteStr("")
	}
	if effType == "date_nanos" || b.ESType == "date_nanos" {
		effFormat := s.Entry.Format
		if effFormat == "" {
			effFormat = b.Format
		}
		if ns, ok := schema.ParseESDateWithFormatToEpochNanos(mStr, effFormat, time.Now().UTC()); ok {
			return ns, strconv.FormatInt(ns, 10)
		}
		if iv, err := strconv.ParseInt(mStr, 10, 64); err == nil {
			return iv, strconv.FormatInt(iv, 10)
		}
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("parse_exception: failed to parse date field [%s] with format [%s]", mStr, effFormat)
		}
		return int64(0), "0"
	}
	if effType == "date" || (effType == "" && b.DorisType == schema.DorisBigInt) {
		effFormat := s.Entry.Format
		if effFormat == "" {
			effFormat = b.Format
		}
		if ms, ok := schema.ParseESDateWithFormatToEpochMillis(mStr, effFormat, time.Now().UTC()); ok {
			return ms, strconv.FormatInt(ms, 10)
		}
	}
	if effType != "scaled_float" {
		if iv, err := strconv.ParseInt(mStr, 10, 64); err == nil {
			return iv, strconv.FormatInt(iv, 10)
		}
		if effType == "unsigned_long" || b.ESType == "unsigned_long" {
			if uv, errU := strconv.ParseUint(mStr, 10, 64); errU == nil {
				return uv, strconv.FormatUint(uv, 10)
			}
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
		if s.Entry.Field == "_id" || s.Entry.Field == "_doc" || s.Entry.Field == "_shard_doc" {
			return req.Sort
		}
	}
	out := make([]esast.SortSpec, len(req.Sort), len(req.Sort)+1)
	copy(out, req.Sort)
	out = append(out, esast.SortSpec{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}})
	return out
}

func isConstantScoreQueryTreeR66(q *esast.Query) bool {
	if q == nil || q.MatchAll != nil || q.MatchNone != nil || q.Exists != nil ||
		len(q.Term) > 0 || q.Terms != nil || len(q.TermsSet) > 0 || len(q.Range) > 0 ||
		len(q.Prefix) > 0 || len(q.Wildcard) > 0 || len(q.Regexp) > 0 || q.Ids != nil ||
		q.GeoDistance != nil || q.GeoBoundingBox != nil || q.GeoPolygon != nil || q.GeoShape != nil || q.GeoGrid != nil ||
		q.ConstantScore != nil {
		return true
	}
	if q.Bool != nil {
		return len(q.Bool.Must) == 0 && len(q.Bool.Should) == 0
	}
	return false
}

func (t *Transpiler) effectiveSortsForRequest(req *esast.SearchRequest) []esast.SortSpec {
	base := EffectiveSortsForRequest(req)
	if t == nil || !t.Opts.ImplicitTimestampSort || req == nil || len(req.Sort) > 0 || len(req.SearchAfter) > 0 || t.Schema == nil {
		return base
	}
	tsB, ok := t.Schema.Fields["@timestamp"]
	if !ok || tsB.Kind == schema.StorageDynamicVariant || tsB.EnabledFalse || tsB.DocValuesFalse {
		return base
	}
	if tsB.ESType != "date" && tsB.ESType != "date_nanos" {
		return base
	}
	trackScores := req.TrackScores != nil && *req.TrackScores
	includeScore := trackScores || (req.Query != nil && !isConstantScoreQueryTreeR66(req.Query))
	if req.PIT != nil {
		if includeScore {
			return []esast.SortSpec{
				{Entry: esast.SortFieldSpec{Field: "_score", Order: "desc"}},
				{Entry: esast.SortFieldSpec{Field: "@timestamp", Order: "desc"}},
				{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}},
			}
		}
		return []esast.SortSpec{
			{Entry: esast.SortFieldSpec{Field: "@timestamp", Order: "desc"}},
			{Entry: esast.SortFieldSpec{Field: "_id", Order: "asc"}},
		}
	}
	if includeScore {
		return []esast.SortSpec{
			{Entry: esast.SortFieldSpec{Field: "_score", Order: "desc"}},
			{Entry: esast.SortFieldSpec{Field: "@timestamp", Order: "desc"}},
		}
	}
	return []esast.SortSpec{
		{Entry: esast.SortFieldSpec{Field: "@timestamp", Order: "desc"}},
	}
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
		distMapExpr := fmt.Sprintf("array_map(_x -> ST_Distance_Sphere(TRY_CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE), TRY_CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE), %s, %s), %s)",
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
	lonExpr := fmt.Sprintf("COALESCE(TRY_CAST(%s['lon'] AS DOUBLE), TRY_CAST(SPLIT_PART(TRY_CAST(%s AS STRING), ',', 2) AS DOUBLE), TRY_CAST(element_at(TRY_CAST(%s AS ARRAY<DOUBLE>), 1) AS DOUBLE))", docRef, docRef, docRef)
	latExpr := fmt.Sprintf("COALESCE(TRY_CAST(%s['lat'] AS DOUBLE), TRY_CAST(SPLIT_PART(TRY_CAST(%s AS STRING), ',', 1) AS DOUBLE), TRY_CAST(element_at(TRY_CAST(%s AS ARRAY<DOUBLE>), 2) AS DOUBLE))", docRef, docRef, docRef)
	if b.Kind == schema.StoragePromotedScalar && b.ColumnName != "" {
		lonExpr = fmt.Sprintf("COALESCE(TRY_CAST(SPLIT_PART(`%s`, ',', 2) AS DOUBLE), %s)", b.ColumnName, lonExpr)
		latExpr = fmt.Sprintf("COALESCE(TRY_CAST(SPLIT_PART(`%s`, ',', 1) AS DOUBLE), %s)", b.ColumnName, latExpr)
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
		case "_id", "_doc", "_shard_doc":
			parts = append(parts, "`_id` "+dir)
		default:
			resolvedField, b := t.resolveSortFieldAndBinding(s.Entry.Field, s.Entry.Nested)
			if b.ESType == "histogram" || b.ESType == "rank_feature" || b.ESType == "rank_features" {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("illegal_argument_exception: Fielddata is not supported on field [%s] of type [%s]", s.Entry.Field, b.ESType)
				}
			}
			if s.Entry.IgnoreUnmapped && b.Kind == schema.StorageDynamicVariant && b.ESType == "" && s.Entry.Type == "" {
				if len(after) >= len(sorts) {
					afterIdx++
				}
				continue
			}
			hasSortSample := (afterIdx < len(after) && after[afterIdx] != nil) ||
				(s.Entry.Missing != "" && !strings.EqualFold(s.Entry.Missing, "_first") && !strings.EqualFold(s.Entry.Missing, "_last"))
			if t.Schema != nil && len(t.Schema.Fields) > 0 && !strings.HasPrefix(s.Entry.Field, "_") && b.Kind == schema.StorageDynamicVariant && b.ESType == "" && s.Entry.Type == "" && !s.Entry.IgnoreUnmapped && !hasSortSample {
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
				} else if effType == "ip" || b.ESType == "ip" {
					if h, ok := parseIPToUpperHex16(sampleVal); ok {
						sampleVal = h
					}
				} else if effType == "date_nanos" || b.ESType == "date_nanos" {
					if strVal, ok := sampleVal.(string); ok {
						effFormat := s.Entry.Format
						if effFormat == "" {
							effFormat = b.Format
						}
						if ns, okN := schema.ParseESDateWithFormatToEpochNanos(strVal, effFormat, time.Now().UTC()); okN {
							sampleVal = ns
						} else if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
							sampleVal = iv
						}
					} else if nv, ok := sampleVal.(json.Number); ok {
						if iv, err := nv.Int64(); err == nil {
							sampleVal = iv
						}
					}
				} else if strVal, ok := sampleVal.(string); ok {
					if effType == "date" || (effType == "" && b.DorisType == schema.DorisBigInt) {
						effFormat := s.Entry.Format
						if effFormat == "" {
							effFormat = b.Format
						}
						if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, effFormat, time.Now().UTC()); ok {
							sampleVal = ms
						}
					} else if b.DorisType == schema.DorisBigInt || b.DorisType == schema.DorisLargeInt || b.DorisType == schema.DorisInt {
						if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
							sampleVal = iv
						} else if b.ESType == "unsigned_long" {
							if uv, errU := strconv.ParseUint(strings.TrimSpace(strVal), 10, 64); errU == nil {
								sampleVal = uv
							}
						}
					}
				} else if nv, ok := sampleVal.(json.Number); ok {
					if iv, err := nv.Int64(); err == nil {
						sampleVal = iv
					} else if b.ESType == "unsigned_long" || effType == "unsigned_long" {
						if uv, errU := strconv.ParseUint(nv.String(), 10, 64); errU == nil {
							sampleVal = uv
						}
					}
				}
				sampleVal = normalizeEpochSecondSortValue(effType, s.Entry.Format, b, sampleVal)
				sampleVal = normalizeScaledFloatValue(b, sampleVal)
			}
			col := t.sqlSortColumnRefWithType(s.Entry.Field, sampleVal, dir == "DESC", s.Entry.Mode, s.Entry.Nested, effType)
			if b.ESType != "" && s.Entry.NumericType != "" && b.Kind == schema.StoragePromotedScalar {
				switch strings.ToLower(s.Entry.NumericType) {
				case "long", "date", "date_nanos":
					if b.ESType != "unsigned_long" {
						if strings.EqualFold(s.Entry.NumericType, "long") && b.ESType == "scaled_float" {
							col = fmt.Sprintf("TRY_CAST(TRUNCATE(%s, 0) AS BIGINT)", col)
						} else {
							col = fmt.Sprintf("TRY_CAST(%s AS BIGINT)", col)
						}
					}
				case "double":
					col = fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", col)
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
	hasUniqueTieBreaker := false
	for _, s := range sorts {
		if s.Entry.Field == "_id" || s.Entry.Field == "_doc" || s.Entry.Field == "_shard_doc" {
			hasUniqueTieBreaker = true
			break
		}
	}
	if !hasUniqueTieBreaker {
		parts = append(parts, "`_id` ASC")
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
		if s.Entry.Field != "" && s.Entry.Field != "_score" && s.Entry.Field != "_id" && s.Entry.Field != "_doc" && s.Entry.Field != "_shard_doc" && s.Entry.Field != "_geo_distance" && s.Entry.Field != "_script" {
			_, b := t.resolveSortFieldAndBinding(s.Entry.Field, s.Entry.Nested)
			if s.Entry.IgnoreUnmapped && b.Kind == schema.StorageDynamicVariant && b.ESType == "" && s.Entry.Type == "" {
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
		case "_id", "_doc", "_shard_doc":
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
			} else if effType == "ip" || b.ESType == "ip" {
				if val != nil {
					if h, ok := parseIPToUpperHex16(val); ok {
						val = h
					} else {
						if t.searchErr == nil {
							t.searchErr = fmt.Errorf("illegal_argument_exception: '%v' is not an IP string literal", val)
						}
						val = ""
					}
				}
			} else if effType == "version" || b.ESType == "version" {
				if val != nil {
					val = formatSemverBoundKey(fmt.Sprintf("%v", val))
				}
			} else if effType == "date_nanos" || b.ESType == "date_nanos" {
				if strVal, ok := val.(string); ok {
					effFormat := effectiveSorts[idx].Entry.Format
					if effFormat == "" {
						effFormat = b.Format
					}
					if ns, okN := schema.ParseESDateWithFormatToEpochNanos(strVal, effFormat, time.Now().UTC()); okN {
						val = ns
					} else if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
						val = iv
					} else if t.searchErr == nil {
						t.searchErr = fmt.Errorf("parse_exception: failed to parse date field [%s] with format [%s]", strVal, effFormat)
					}
				} else if nv, ok := val.(json.Number); ok {
					if iv, err := nv.Int64(); err == nil {
						val = iv
					}
				}
			} else if strVal, ok := val.(string); ok {
				if b.EffectiveLowercase(true) && effType != "date" && effType != "date_nanos" && b.DorisType != schema.DorisBigInt && b.DorisType != schema.DorisLargeInt && b.DorisType != schema.DorisInt && b.DorisType != schema.DorisDouble {
					val = strings.ToLower(strVal)
				} else if effType == "date" || (effType == "" && b.DorisType == schema.DorisBigInt) {
					effFormat := effectiveSorts[idx].Entry.Format
					if effFormat == "" {
						effFormat = b.Format
					}
					if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, effFormat, time.Now().UTC()); ok {
						val = ms
					}
				} else if b.DorisType == schema.DorisBigInt || b.DorisType == schema.DorisLargeInt || b.DorisType == schema.DorisInt {
					if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
						val = iv
					} else if b.ESType == "unsigned_long" {
						if uv, errU := strconv.ParseUint(strings.TrimSpace(strVal), 10, 64); errU == nil {
							val = uv
						}
					}
				} else if b.DorisType == schema.DorisDouble {
					if fv, err := strconv.ParseFloat(strings.TrimSpace(strVal), 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
						val = fv
					}
				}
			} else if nv, ok := val.(json.Number); ok {
				if iv, err := nv.Int64(); err == nil {
					val = iv
				} else if b.ESType == "unsigned_long" || effType == "unsigned_long" {
					if uv, errU := strconv.ParseUint(nv.String(), 10, 64); errU == nil {
						val = uv
					}
				}
			}
			val = normalizeEpochSecondSortValue(effType, effectiveSorts[idx].Entry.Format, b, val)
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
					if b.ESType != "unsigned_long" {
						if strings.EqualFold(effectiveSorts[idx].Entry.NumericType, "long") && b.ESType == "scaled_float" {
							col = fmt.Sprintf("TRY_CAST(TRUNCATE(%s, 0) AS BIGINT)", col)
						} else {
							col = fmt.Sprintf("TRY_CAST(%s AS BIGINT)", col)
						}
					}
				case "double":
					col = fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", col)
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
			return fmt.Sprintf("%s(array_map(_x -> %s, %s))", fn, sqlCanonicalIPHexExpr("_x"), arrRef)
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
			if effType == "unsigned_long" || b.ESType == "unsigned_long" {
				return fmt.Sprintf("%s(array_map(_x -> TRY_CAST(_x AS LARGEINT), %s))", fn, arrRef)
			}
			if effDT == schema.DorisBigInt || effDT == schema.DorisInt {
				return fmt.Sprintf("%s(array_map(_x -> TRY_CAST(_x AS BIGINT), %s))", fn, arrRef)
			}
			if effDT == schema.DorisDouble {
				return fmt.Sprintf("%s(array_map(_x -> TRY_CAST(_x AS DOUBLE), %s))", fn, arrRef)
			}
		case "array_avg", "array_sum", "array_median":
			if effDT == schema.DorisBigInt || effDT == schema.DorisInt {
				return fmt.Sprintf("%s(array_map(_x -> TRY_CAST(_x AS BIGINT), %s))", fn, arrRef)
			}
			return fmt.Sprintf("%s(array_map(_x -> TRY_CAST(_x AS DOUBLE), %s))", fn, arrRef)
		}
		return fmt.Sprintf("%s(%s)", fn, arrRef)
	}
	switch b.Kind {
	case schema.StoragePromotedArray:
		return formatArraySortExpr(fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true)))
	case schema.StorageNestedSubfield:
		if deepestNestedPath == "" {
			switch b.DorisType {
			case schema.DorisBigInt, schema.DorisLargeInt, schema.DorisInt:
				return "TRY_CAST(NULL AS BIGINT)"
			case schema.DorisDouble:
				return "TRY_CAST(NULL AS DOUBLE)"
			default:
				return "CAST(NULL AS STRING)"
			}
		}
		nestedPath := deepestNestedPath
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
		return sqlCanonicalIPHexExpr(t.sqlColumnRef(field, true, nil))
	}
	if effType == "version" || b.ESType == "version" {
		return sqlSemverSortKeyExpr(t.sqlColumnRef(field, true, nil))
	}
	if (effType == "unsigned_long" || b.ESType == "unsigned_long") && sampleVal == nil {
		sampleVal = uint64(math.MaxUint64)
	}
	colRef := t.sqlTypedColumnRef(field, sampleVal, true, nil)
	if effType == "unsigned_long" || b.ESType == "unsigned_long" {
		return fmt.Sprintf("TRY_CAST(%s AS LARGEINT)", colRef)
	}
	return colRef
}

func (t *Transpiler) sqlColumnRef(field string, preferKeyword bool, nctx *nestedCtx) string {
	return t.sqlTypedColumnRef(field, nil, preferKeyword, nctx)
}

func (t *Transpiler) sqlNumericColumnRef(field string, nctx *nestedCtx) string {
	if nctx == nil {
		if _, effType, isRT := t.resolveScriptlessRuntimeField(field); isRT {
			expr := fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", sqlRuntimeSourceTypedExpr(field, effType))
			if effType == "date_nanos" {
				return fmt.Sprintf("(%s / 1000000.0)", expr)
			}
			return expr
		}
	}
	field, b := t.resolveFieldInNestedCtx(field, true, nctx)
	if b.ESType == "aggregate_metric_double" {
		if sb, ok := ResolveAggregateMetricDefaultBindingR63(b); ok {
			b = sb
		}
	}
	var expr string
	switch b.Kind {
	case schema.StoragePromotedScalar:
		if b.DorisType == schema.DorisBigInt || b.DorisType == schema.DorisInt || b.DorisType == schema.DorisDouble {
			expr = fmt.Sprintf("`%s`", b.ColumnName)
		} else {
			expr = fmt.Sprintf("TRY_CAST(`%s` AS DOUBLE)", b.ColumnName)
		}
	case schema.StoragePromotedArray, schema.StoragePromotedVector:
		if !t.isBoundToNestedCtx(field, b, nctx) {
			expr = fmt.Sprintf("TRY_CAST(element_at(`%s`, 1) AS DOUBLE)", b.EffectiveArrayColumn(true))
		}
	case schema.StorageNestedSubfield:
		if (nctx == nil || nctx.elemVar == "" || nctx.nestedPath != b.NestedPath) && b.EffectiveArrayColumn(true) != "" {
			expr = fmt.Sprintf("TRY_CAST(element_at(`%s`, 1) AS DOUBLE)", b.EffectiveArrayColumn(true))
		}
	}
	if expr == "" {
		expr = t.sqlTypedColumnRef(field, float64(0.5), false, nctx)
	}
	if b.ESType == "date_nanos" {
		return fmt.Sprintf("(TRY_CAST(%s AS DOUBLE) / 1000000.0)", expr)
	}
	return expr
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
		if _, isShreddedNested := t.Schema.NestedRoots[nestedPath]; isShreddedNested {
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
	}
	return "$." + relKey
}

func (t *Transpiler) resolveFieldInNestedCtx(field string, preferKeyword bool, nctx *nestedCtx) (string, schema.FieldBinding) {
	if field == "_ignored" && nctx == nil {
		return field, ignoredMetadataBinding()
	}
	if field == "_size" && nctx == nil {
		if t.Schema != nil && schema.IsSizeMetadataEnabled(t.Schema.RawMapping) {
			if fb, ok := t.Schema.Fields["_size"]; ok && fb.ColumnName != "" {
				return field, fb
			}
			return field, schema.FieldBinding{
				ESFieldPath: "_size",
				ColumnName:  "f___size",
				Kind:        schema.StoragePromotedScalar,
				DorisType:   schema.DorisBigInt,
				ESType:      "long",
			}
		}
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = esTranspilerError("all_shards_failed|query_shard_exception|failed to find [_size] field, Mapping Metadata [_size] is not enabled")
		}
		return field, schema.FieldBinding{ESFieldPath: "_size", EnabledFalse: true}
	}
	if nctx == nil {
		if fp, effType, isRT := t.resolveScriptlessRuntimeField(field); isRT {
			return field, runtimeFieldBinding(field, effType, fp)
		}
	}
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
	if field == "_ignored" {
		return "`_ignored`"
	}
	if field == "_size" && nctx == nil {
		if t.Schema != nil && schema.IsSizeMetadataEnabled(t.Schema.RawMapping) {
			return "COALESCE(`f___size`, OCTET_LENGTH(`_source`))"
		}
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = esTranspilerError("all_shards_failed|query_shard_exception|failed to find [_size] field, Mapping Metadata [_size] is not enabled")
		}
		return "NULL"
	}
	if field == "_tsid" && nctx == nil {
		return "`__tsid`"
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
	if nctx == nil {
		if _, effType, isRT := t.resolveScriptlessRuntimeField(field); isRT {
			return sqlRuntimeSourceTypedExpr(field, effType)
		}
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
	if b.ESType == "aggregate_metric_double" {
		if sb, ok := ResolveAggregateMetricDefaultBindingR63(b); ok {
			b = sb
		}
	}
	if b.ESType == "unsigned_long" && (castType == "BIGINT" || castType == "LARGEINT") {
		castType = "LARGEINT"
	} else if effectiveDorisScalarType(b) == schema.DorisDouble && castType == "BIGINT" {
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
			extractExpr = fmt.Sprintf("TRY_CAST(%s AS %s)", extractExpr, castType)
		}
		return extractExpr
	}

	switch b.Kind {
	case schema.StoragePromotedScalar:
		if b.ESType == "unsigned_long" && b.DorisType != schema.DorisLargeInt && (castType == "LARGEINT" || castType == "DOUBLE") && effField != "" {
			break
		}
		if b.DorisType == schema.DorisLargeInt && castType == "DOUBLE" {
			return fmt.Sprintf("TRY_CAST(`%s` AS DOUBLE)", b.ColumnName)
		}
		if preferKeyword && b.KeywordCompanion != "" && (b.ESType == "text" || b.ESType == "match_only_text" || b.ESType == "") {
			return fmt.Sprintf("`%s`", b.KeywordCompanion)
		}
		rawCol := fmt.Sprintf("`%s`", b.ColumnName)
		if b.ESType == "constant_keyword" && b.HasConstantValue && b.ConstantValue != nil {
			return ConstantKeywordScalarExprR63(rawCol, field, b)
		}
		return rawCol
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
	return fmt.Sprintf("TRY_CAST(`_doc`%s AS %s)", pathBuilder.String(), castType)
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
	return "'" + EscapeDorisSQLString(s) + "'"
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
		if val == math.Trunc(val) {
			if val >= -9223372036854775808.0 && val < 9223372036854775808.0 {
				return strconv.FormatInt(int64(val), 10)
			}
			if val >= 9223372036854775808.0 && val < 18446744073709551616.0 {
				return strconv.FormatUint(uint64(val), 10)
			}
		}
		if math.Abs(val) >= 1e18 {
			return strconv.FormatFloat(val, 'g', -1, 64)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case json.Number:
		s := strings.TrimSpace(val.String())
		if IsSafeJSONNumberLiteral(s) {
			return s
		}
		return quoteStr(s)
	default:
		return quoteStr(fmt.Sprintf("%v", val))
	}
}

func nullSingletonArraySQL(b schema.FieldBinding) string {
	if b.Kind == schema.StoragePromotedArray && (b.DorisType == schema.DorisLargeInt || b.DorisType == schema.DorisLargeIntArray) {
		return "CAST([NULL] AS ARRAY<LARGEINT>)"
	}
	return "[NULL]"
}

func parseUnsignedLongRawBound(v any) (uVal uint64, fVal float64, isExactUint, isNeg, isAboveMax, ok bool) {
	switch nv := v.(type) {
	case uint64:
		return nv, float64(nv), true, false, false, true
	case int:
		if nv < 0 {
			return 0, float64(nv), false, true, false, true
		}
		return uint64(nv), float64(nv), true, false, false, true
	case int64:
		if nv < 0 {
			return 0, float64(nv), false, true, false, true
		}
		return uint64(nv), float64(nv), true, false, false, true
	case float64:
		if math.IsNaN(nv) {
			return 0, 0, false, false, false, false
		}
		if nv < 0 {
			return 0, nv, false, true, false, true
		}
		if nv >= 18446744073709551616.0 || math.IsInf(nv, 1) {
			return 0, nv, false, false, true, true
		}
		if nv == math.Trunc(nv) {
			return uint64(nv), nv, true, false, false, true
		}
		return 0, nv, false, false, false, true
	case json.Number:
		s := strings.TrimSpace(nv.String())
		if u, err := strconv.ParseUint(s, 10, 64); err == nil {
			return u, float64(u), true, false, false, true
		}
		if iv, err := nv.Int64(); err == nil {
			if iv < 0 {
				return 0, float64(iv), false, true, false, true
			}
			return uint64(iv), float64(iv), true, false, false, true
		}
		if f, err := nv.Float64(); err == nil && !math.IsNaN(f) {
			if f < 0 {
				return 0, f, false, true, false, true
			}
			if f >= 18446744073709551616.0 || math.IsInf(f, 1) {
				return 0, f, false, false, true, true
			}
			if f == math.Trunc(f) {
				return uint64(f), f, true, false, false, true
			}
			return 0, f, false, false, false, true
		}
		return 0, 0, false, false, false, false
	case string:
		trimmed := strings.TrimSpace(nv)
		if trimmed == "" {
			return 0, 0, false, false, false, false
		}
		if u, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
			return u, float64(u), true, false, false, true
		}
		if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			if iv < 0 {
				return 0, float64(iv), false, true, false, true
			}
			return uint64(iv), float64(iv), true, false, false, true
		}
		if f, err := strconv.ParseFloat(trimmed, 64); err == nil && !math.IsNaN(f) {
			if f < 0 {
				return 0, f, false, true, false, true
			}
			if f >= 18446744073709551616.0 || math.IsInf(f, 1) {
				return 0, f, false, false, true, true
			}
			if f == math.Trunc(f) {
				return uint64(f), f, true, false, false, true
			}
			return 0, f, false, false, false, true
		}
		return 0, 0, false, false, false, false
	default:
		return 0, 0, false, false, false, false
	}
}

func normalizeUnsignedLongRangeBounds(gt, gte, lt, lte any) (outGT, outGTE, outLT, outLTE any, ok bool) {
	return NormalizeUnsignedLongRangeBoundsExactR63(gt, gte, lt, lte)
}

func (t *Transpiler) validateHistogramBoundsSpec(hb *esast.HistogramBoundsSpec, paramName, aggName string) {
	if hb == nil {
		return
	}
	var minF, maxF float64
	hasMin, hasMax := false, false
	if hb.Min != nil {
		v, ok := resolveHistogramMissingFloat(hb.Min)
		if !ok {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: failed to parse numeric [%s.min] in histogram aggregation [%s]", paramName, aggName)
			}
			return
		}
		minF, hasMin = v, true
	}
	if hb.Max != nil {
		v, ok := resolveHistogramMissingFloat(hb.Max)
		if !ok {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: failed to parse numeric [%s.max] in histogram aggregation [%s]", paramName, aggName)
			}
			return
		}
		maxF, hasMax = v, true
	}
	if hasMin && hasMax && minF > maxF {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("illegal_argument_exception: [%s.min] [%v] cannot be greater than [%s.max] [%v] in histogram aggregation [%s]", paramName, minF, paramName, maxF, aggName)
		}
	}
}

func (t *Transpiler) validateDateHistogramSpec(dh *esast.DateHistogramAggSpec, aggName string, nctx *nestedCtx) {
	if dh == nil {
		return
	}
	if strings.TrimSpace(dh.TimeZone) != "" {
		if _, _, _, err := esast.ParseESTimeZone(dh.TimeZone); err != nil {
			if t.searchErr == nil {
				t.searchErr = err
			}
			return
		}
	}
	effField := dh.Field
	if effField == "" && dh.Script != nil {
		if docF, ok := extractSimpleDocFieldFromScript(dh.Script); ok {
			effField = docF
		}
	}
	_, b := t.resolveFieldInNestedCtx(effField, false, nctx)
	checkBounds := func(hb *esast.HistogramBoundsSpec, paramName string) {
		if hb == nil {
			return
		}
		var minMs, maxMs int64
		hasMin, hasMax := false, false
		if hb.Min != nil {
			ms, ok := t.resolveDateHistogramBoundMs(b, dh.Format, hb.Min)
			if !ok {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("parse_exception: failed to parse date [%v] for [%s.min] in date_histogram aggregation [%s]", hb.Min, paramName, aggName)
				}
				return
			}
			minMs, hasMin = ms, true
		}
		if hb.Max != nil {
			ms, ok := t.resolveDateHistogramBoundMs(b, dh.Format, hb.Max)
			if !ok {
				if t.searchErr == nil {
					t.searchErr = fmt.Errorf("parse_exception: failed to parse date [%v] for [%s.max] in date_histogram aggregation [%s]", hb.Max, paramName, aggName)
				}
				return
			}
			maxMs, hasMax = ms, true
		}
		if hasMin && hasMax && minMs > maxMs {
			if t.searchErr == nil {
				t.searchErr = fmt.Errorf("illegal_argument_exception: [%s.min] [%d] cannot be greater than [%s.max] [%d] in date_histogram aggregation [%s]", paramName, minMs, paramName, maxMs, aggName)
			}
		}
	}
	checkBounds(dh.ExtendedBounds, "extended_bounds")
	checkBounds(dh.HardBounds, "hard_bounds")
}

func (t *Transpiler) resolveDateHistogramBoundMs(b schema.FieldBinding, aggFormat string, raw any) (int64, bool) {
	if raw == nil {
		return 0, false
	}
	effFmt := aggFormat
	if effFmt == "" {
		effFmt = b.Format
	}
	if strVal, isStr := raw.(string); isStr {
		if effFmt != "" {
			if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strVal, effFmt, time.Now().UTC()); ok {
				return ms, true
			}
		}
		if ms, ok := schema.ParseESDateToEpochMillis(strVal, time.Now().UTC()); ok {
			return ms, true
		}
		if iv, err := strconv.ParseInt(strings.TrimSpace(strVal), 10, 64); err == nil {
			return iv, true
		}
		return 0, false
	}
	return t.resolveDateHistogramMissingMs(b.ESType, raw)
}

func formatFixedOffsetDorisTZ(offsetMs int64) string {
	sign := "+"
	absMs := offsetMs
	if absMs < 0 {
		sign = "-"
		absMs = -absMs
	}
	totalMins := absMs / 60_000
	hours := totalMins / 60
	mins := totalMins % 60
	return fmt.Sprintf("%s%02d:%02d", sign, hours, mins)
}

func (t *Transpiler) buildDateHistogramBucketKeySQL(dh *esast.DateHistogramAggSpec, colMillisExpr string) string {
	if dh == nil {
		return fmt.Sprintf("CAST(CAST(%s AS BIGINT) AS STRING)", colMillisExpr)
	}
	intervalMs := dh.EffectiveIntervalMs()
	offsetMs := dh.EffectiveOffsetMs()
	tzRaw := strings.TrimSpace(dh.TimeZone)
	_, fixedOffMs, isFixed, tzErr := esast.ParseESTimeZone(tzRaw)
	if tzErr != nil {
		isFixed = true
		fixedOffMs = 0
	}

	if dh.IsCalendarInterval() {
		unit := dh.EffectiveCalendarUnit()
		isVarCalendar := unit == "week" || unit == "month" || unit == "quarter" || unit == "year"
		isDayOrLarger := unit == "day" || isVarCalendar
		if isVarCalendar || (isDayOrLarger && !isFixed) {
			shiftedMs := colMillisExpr
			if offsetMs != 0 {
				shiftedMs = fmt.Sprintf("((%s) - %d)", colMillisExpr, offsetMs)
			}
			const epoch0 = "CAST('1970-01-01 00:00:00' AS DATETIME)"
			secExpr := fmt.Sprintf("CAST(FLOOR((%s) / 1000) AS BIGINT)", shiftedMs)
			utcDt := fmt.Sprintf("SECONDS_ADD(%s, %s)", epoch0, secExpr)
			var epochMsExpr string
			if isFixed && fixedOffMs == 0 {
				truncDt := fmt.Sprintf("DATE_TRUNC(%s, %s)", utcDt, quoteStr(unit))
				epochMsExpr = fmt.Sprintf("(TIMESTAMPDIFF(SECOND, %s, %s) * 1000)", epoch0, truncDt)
			} else {
				dorisTZ := tzRaw
				if isFixed {
					dorisTZ = formatFixedOffsetDorisTZ(fixedOffMs)
				}
				localDt := fmt.Sprintf("CONVERT_TZ(%s, '+00:00', %s)", utcDt, quoteStr(dorisTZ))
				truncLocal := fmt.Sprintf("DATE_TRUNC(%s, %s)", localDt, quoteStr(unit))
				backToUTC := fmt.Sprintf("CONVERT_TZ(%s, %s, '+00:00')", truncLocal, quoteStr(dorisTZ))
				epochMsExpr = fmt.Sprintf("(TIMESTAMPDIFF(SECOND, %s, %s) * 1000)", epoch0, backToUTC)
			}
			if offsetMs != 0 {
				epochMsExpr = fmt.Sprintf("(%s + %d)", epochMsExpr, offsetMs)
			}
			return fmt.Sprintf("CAST(CAST(%s AS BIGINT) AS STRING)", epochMsExpr)
		}
	}

	if !isFixed {
		const epoch0 = "CAST('1970-01-01 00:00:00' AS DATETIME)"
		secExpr := fmt.Sprintf("TRY_CAST(FLOOR((%s) / 1000) AS BIGINT)", colMillisExpr)
		utcDt := fmt.Sprintf("SECONDS_ADD(%s, %s)", epoch0, secExpr)
		dynOffMs := fmt.Sprintf("(TIMESTAMPDIFF(SECOND, %s, CONVERT_TZ(%s, '+00:00', %s)) * 1000)", utcDt, utcDt, quoteStr(tzRaw))
		shiftExpr := dynOffMs
		if offsetMs != 0 {
			shiftExpr = fmt.Sprintf("(%s - %d)", dynOffMs, offsetMs)
		}
		flooredLocalMs := fmt.Sprintf("(FLOOR(((%s) + %s) / %d) * %d)", colMillisExpr, shiftExpr, intervalMs, intervalMs)
		if offsetMs != 0 {
			flooredLocalMs = fmt.Sprintf("(FLOOR(((%s) + %s) / %d) * %d + %d)", colMillisExpr, shiftExpr, intervalMs, intervalMs, offsetMs)
		}
		flooredLocalSec := fmt.Sprintf("TRY_CAST(FLOOR(%s / 1000) AS BIGINT)", flooredLocalMs)
		flooredLocalDt := fmt.Sprintf("SECONDS_ADD(%s, %s)", epoch0, flooredLocalSec)
		backToUTC := fmt.Sprintf("CONVERT_TZ(%s, %s, '+00:00')", flooredLocalDt, quoteStr(tzRaw))
		utcMsExpr := fmt.Sprintf("(TIMESTAMPDIFF(SECOND, %s, %s) * 1000)", epoch0, backToUTC)
		if intervalMs%1000 != 0 || offsetMs%1000 != 0 {
			subMsExpr := fmt.Sprintf("(TRY_CAST(%s AS BIGINT) - (%s * 1000))", flooredLocalMs, flooredLocalSec)
			utcMsExpr = fmt.Sprintf("(%s + %s)", utcMsExpr, subMsExpr)
		}
		return fmt.Sprintf("CAST(TRY_CAST(%s AS BIGINT) AS STRING)", utcMsExpr)
	}

	tzShiftMs := fixedOffMs - offsetMs
	if tzShiftMs != 0 {
		return fmt.Sprintf("CAST(CAST(FLOOR((%s + %d) / %d) * %d - %d AS BIGINT) AS STRING)", colMillisExpr, tzShiftMs, intervalMs, intervalMs, tzShiftMs)
	}
	return fmt.Sprintf("CAST(CAST(FLOOR(%s / %d) * %d AS BIGINT) AS STRING)", colMillisExpr, intervalMs, intervalMs)
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
		roundUp := isUpper != isExclusive
		var ms int64
		if s, isStr := v.(string); isStr {
			parsedMs, ok := schema.ParseESDateBoundWithFormatAndLocaleToEpochMillis(s, format, b.Locale, now, roundUp)
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

func rangeObjectBoundsSQLFromBase(baseExpr string) (string, string, string, string) {
	rawLower := fmt.Sprintf("COALESCE(TRY_CAST(%s['_gte'] AS DOUBLE), TRY_CAST(%s['gte'] AS DOUBLE), TRY_CAST(%s['_gt'] AS DOUBLE), TRY_CAST(%s['gt'] AS DOUBLE))", baseExpr, baseExpr, baseExpr, baseExpr)
	rawUpper := fmt.Sprintf("COALESCE(TRY_CAST(%s['_lte'] AS DOUBLE), TRY_CAST(%s['lte'] AS DOUBLE), TRY_CAST(%s['_lt'] AS DOUBLE), TRY_CAST(%s['lt'] AS DOUBLE))", baseExpr, baseExpr, baseExpr, baseExpr)
	lower := fmt.Sprintf("COALESCE(%s, -1e100)", rawLower)
	upper := fmt.Sprintf("COALESCE(%s, 1e100)", rawUpper)
	return lower, upper, rawLower, rawUpper
}

func rangeDocBaseExpr(field string, b schema.FieldBinding) string {
	parts := b.SourceJSONPath
	if len(parts) == 0 {
		parts = strings.Split(field, ".")
	}
	var base strings.Builder
	base.WriteString("`_doc`")
	for _, p := range parts {
		base.WriteString("[" + quoteStr(p) + "]")
	}
	return base.String()
}

func (t *Transpiler) rangeFieldBoundsAndRawSQL(field string, b schema.FieldBinding, nctx *nestedCtx) (string, string, string, string) {
	if b.ESType == "date_range" {
		return dateRangeObjectBoundsSQLR63(field, b, nctx)
	}
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
		rawLower := fmt.Sprintf("COALESCE(TRY_CAST(json_extract_string(%s, %s) AS DOUBLE), TRY_CAST(json_extract_string(%s, %s) AS DOUBLE), TRY_CAST(json_extract_string(%s, %s) AS DOUBLE), TRY_CAST(json_extract_string(%s, %s) AS DOUBLE))",
			nctx.elemVar, quoteStr(gtePath), nctx.elemVar, quoteStr(rawGtePath), nctx.elemVar, quoteStr(gtPath), nctx.elemVar, quoteStr(rawGtPath))
		rawUpper := fmt.Sprintf("COALESCE(TRY_CAST(json_extract_string(%s, %s) AS DOUBLE), TRY_CAST(json_extract_string(%s, %s) AS DOUBLE), TRY_CAST(json_extract_string(%s, %s) AS DOUBLE), TRY_CAST(json_extract_string(%s, %s) AS DOUBLE))",
			nctx.elemVar, quoteStr(ltePath), nctx.elemVar, quoteStr(rawLtePath), nctx.elemVar, quoteStr(ltPath), nctx.elemVar, quoteStr(rawLtPath))
		lower := fmt.Sprintf("COALESCE(%s, -1e100)", rawLower)
		upper := fmt.Sprintf("COALESCE(%s, 1e100)", rawUpper)
		return lower, upper, rawLower, rawUpper
	}
	return rangeObjectBoundsSQLFromBase(rangeDocBaseExpr(field, b))
}

func (t *Transpiler) compileRangeOnRangeField(field string, b schema.FieldBinding, rc esast.RangeCond, nctx *nestedCtx) string {
	if b.ESType == "long_range" && nctx == nil {
		return t.compileLongRangeOnRangeFieldR65(field, b, rc)
	}
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

	rel := strings.ToUpper(strings.TrimSpace(rc.Relation))
	if rel == "" {
		rel = "INTERSECTS"
	}

	qLowLit := strconv.FormatFloat(qLower, 'f', -1, 64)
	qUpLit := strconv.FormatFloat(qUpper, 'f', -1, 64)
	containsLow := qLower
	if qLowerExclusive && (b.ESType == "float_range" || b.ESType == "double_range") {
		containsLow = math.Nextafter(qLower, math.Inf(1))
	}
	containsUp := qUpper
	if qUpperExclusive && (b.ESType == "float_range" || b.ESType == "double_range") {
		containsUp = math.Nextafter(qUpper, math.Inf(-1))
	}
	containsLowLit := strconv.FormatFloat(containsLow, 'f', -1, 64)
	containsUpLit := strconv.FormatFloat(containsUp, 'f', -1, 64)

	buildConds := func(lowerSQL, upperSQL string) []string {
		var conds []string
		switch rel {
		case "CONTAINS":
			if hasLower || hasUpper {
				if hasLower {
					conds = append(conds, fmt.Sprintf("%s <= %s", lowerSQL, containsLowLit))
				} else {
					conds = append(conds, fmt.Sprintf("%s <= -1e99", lowerSQL))
				}
				if hasUpper {
					conds = append(conds, fmt.Sprintf("%s >= %s", upperSQL, containsUpLit))
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
		return conds
	}

	return t.compileRangePredOnRangeField(field, b, nctx, buildConds)
}

func clampFloat64ToInt64RangeBoundR65(fv float64, isUpper bool) (int64, bool) {
	if math.IsNaN(fv) || math.IsInf(fv, 0) {
		return 0, false
	}
	if fv >= float64(math.MaxInt64) {
		return math.MaxInt64, true
	}
	if fv <= float64(math.MinInt64) {
		return math.MinInt64, true
	}
	if isUpper {
		res := math.Floor(fv)
		if res >= float64(math.MaxInt64) {
			return math.MaxInt64, true
		}
		return int64(res), true
	}
	res := math.Ceil(fv)
	if res <= float64(math.MinInt64) {
		return math.MinInt64, true
	}
	return int64(res), true
}

func parseExactInt64RangeBoundR65(v any, isUpper bool) (int64, bool) {
	switch nv := v.(type) {
	case int:
		return int64(nv), true
	case int64:
		return nv, true
	case uint64:
		if nv <= math.MaxInt64 {
			return int64(nv), true
		}
		return 0, false
	case json.Number:
		s := strings.TrimSpace(nv.String())
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return iv, true
		}
		if fv, err := strconv.ParseFloat(s, 64); err == nil {
			return clampFloat64ToInt64RangeBoundR65(fv, isUpper)
		}
		return 0, false
	case string:
		s := strings.TrimSpace(nv)
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return iv, true
		}
		if fv, err := strconv.ParseFloat(s, 64); err == nil {
			return clampFloat64ToInt64RangeBoundR65(fv, isUpper)
		}
		return 0, false
	case float64:
		return clampFloat64ToInt64RangeBoundR65(nv, isUpper)
	default:
		return 0, false
	}
}

func evalInt64CmpR65(lhs int64, op string, rhs int64) bool {
	switch op {
	case "<=":
		return lhs <= rhs
	case ">=":
		return lhs >= rhs
	case "<":
		return lhs < rhs
	case ">":
		return lhs > rhs
	case "=":
		return lhs == rhs
	}
	return false
}

func (t *Transpiler) compileLongRangeOnRangeFieldR65(field string, b schema.FieldBinding, rc esast.RangeCond) string {
	gt, gte, lt, lte := rc.NormalizedBounds()
	var hasLower, hasUpper bool
	var qLower, qUpper int64

	if gte != nil {
		iv, ok := parseExactInt64RangeBoundR65(gte, false)
		if !ok {
			return "FALSE"
		}
		qLower = iv
		hasLower = true
	} else if gt != nil {
		iv, ok := parseExactInt64RangeBoundR65(gt, true)
		if !ok {
			return "FALSE"
		}
		if iv == math.MaxInt64 {
			return "FALSE"
		}
		qLower = iv + 1
		hasLower = true
	}

	if lte != nil {
		iv, ok := parseExactInt64RangeBoundR65(lte, true)
		if !ok {
			return "FALSE"
		}
		qUpper = iv
		hasUpper = true
	} else if lt != nil {
		iv, ok := parseExactInt64RangeBoundR65(lt, false)
		if !ok {
			return "FALSE"
		}
		if iv == math.MinInt64 {
			return "FALSE"
		}
		qUpper = iv - 1
		hasUpper = true
	}

	if hasLower && hasUpper && qLower > qUpper {
		return "FALSE"
	}

	rel := strings.ToUpper(strings.TrimSpace(rc.Relation))
	if rel == "" {
		rel = "INTERSECTS"
	}

	baseExpr := rangeDocBaseExpr(field, b)
	srcPath := b.SourceJSONPath
	if len(srcPath) == 0 {
		srcPath = strings.Split(field, ".")
	}
	var srcPathBuf strings.Builder
	srcPathBuf.WriteByte('$')
	for _, seg := range srcPath {
		srcPathBuf.WriteByte('.')
		srcPathBuf.WriteString(QuoteDorisJSONPathSegment(seg))
	}
	srcObjExpr := fmt.Sprintf("json_extract_string(`_source`, %s)", quoteStr(srcPathBuf.String()))

	cmpNullAware := func(colExpr string, nullGTVal, nullGTEVal int64, nullKeyPat, op string, qVal int64) string {
		resSpec := evalInt64CmpR65(nullGTVal, op, qVal)
		resOpen := evalInt64CmpR65(nullGTEVal, op, qVal)
		qStr := strconv.FormatInt(qVal, 10)
		if resSpec && resOpen {
			return fmt.Sprintf("(%s IS NULL OR %s %s %s)", colExpr, colExpr, op, qStr)
		}
		if !resSpec && !resOpen {
			return fmt.Sprintf("(%s IS NOT NULL AND %s %s %s)", colExpr, colExpr, op, qStr)
		}
		if resSpec {
			return fmt.Sprintf("((%s IS NOT NULL AND %s %s %s) OR (%s IS NULL AND (%s LIKE %s OR %s LIKE %s)))",
				colExpr, colExpr, op, qStr, colExpr,
				srcObjExpr, quoteStr(`%"`+nullKeyPat+`":null%`),
				srcObjExpr, quoteStr(`%"`+nullKeyPat+`": null%`))
		}
		return fmt.Sprintf("((%s IS NOT NULL AND %s %s %s) OR (%s IS NULL AND NOT (%s LIKE %s OR %s LIKE %s)))",
			colExpr, colExpr, op, qStr, colExpr,
			srcObjExpr, quoteStr(`%"`+nullKeyPat+`":null%`),
			srcObjExpr, quoteStr(`%"`+nullKeyPat+`": null%`))
	}

	buildConds := func(loExpr, hiExpr string) []string {
		var conds []string
		switch rel {
		case "CONTAINS":
			if hasLower || hasUpper {
				if hasLower {
					conds = append(conds, cmpNullAware(loExpr, math.MinInt64+1, math.MinInt64, "gt", "<=", qLower))
				} else {
					conds = append(conds, cmpNullAware(loExpr, math.MinInt64+1, math.MinInt64, "gt", "<=", math.MinInt64))
				}
				if hasUpper {
					conds = append(conds, cmpNullAware(hiExpr, math.MaxInt64-1, math.MaxInt64, "lt", ">=", qUpper))
				} else {
					conds = append(conds, cmpNullAware(hiExpr, math.MaxInt64-1, math.MaxInt64, "lt", ">=", math.MaxInt64))
				}
			}
		case "WITHIN":
			if hasLower {
				conds = append(conds, cmpNullAware(loExpr, math.MinInt64+1, math.MinInt64, "gt", ">=", qLower))
			}
			if hasUpper {
				conds = append(conds, cmpNullAware(hiExpr, math.MaxInt64-1, math.MaxInt64, "lt", "<=", qUpper))
			}
		default: // INTERSECTS
			if hasUpper {
				conds = append(conds, cmpNullAware(loExpr, math.MinInt64+1, math.MinInt64, "gt", "<=", qUpper))
			}
			if hasLower {
				conds = append(conds, cmpNullAware(hiExpr, math.MaxInt64-1, math.MaxInt64, "lt", ">=", qLower))
			}
		}
		return conds
	}

	rawLo := fmt.Sprintf("COALESCE(TRY_CAST(%s['_gte'] AS BIGINT), TRY_CAST(%s['gte'] AS BIGINT))", baseExpr, baseExpr)
	rawHi := fmt.Sprintf("COALESCE(TRY_CAST(%s['_lte'] AS BIGINT), TRY_CAST(%s['lte'] AS BIGINT))", baseExpr, baseExpr)
	existsCond := fmt.Sprintf("(%s IS NOT NULL OR %s IS NOT NULL OR TRY_CAST(%s['_gte'] AS DOUBLE) IS NOT NULL OR TRY_CAST(%s['_lte'] AS DOUBLE) IS NOT NULL)",
		rawLo, rawHi, baseExpr, baseExpr)
	singleConds := buildConds(rawLo, rawHi)
	singlePred := existsCond
	if len(singleConds) > 0 {
		singlePred = "(" + strings.Join(append([]string{existsCond}, singleConds...), " AND ") + ")"
	}
	rArrExpr := fmt.Sprintf("TRY_CAST(%s['_r'] AS ARRAY<STRING>)", baseExpr)
	elemLo := "TRY_CAST(SPLIT_PART(_x, ',', 1) AS BIGINT)"
	elemHi := "TRY_CAST(SPLIT_PART(_x, ',', 2) AS BIGINT)"
	elemConds := append([]string{"_x IS NOT NULL", "_x != ''"}, buildConds(elemLo, elemHi)...)
	elemPred := "(" + strings.Join(elemConds, " AND ") + ")"
	return fmt.Sprintf("(array_exists(_x -> %s, %s) OR %s)", elemPred, rArrExpr, singlePred)
}

func (t *Transpiler) compileRangePredOnRangeField(field string, b schema.FieldBinding, nctx *nestedCtx, buildConds func(lowerSQL, upperSQL string) []string) string {
	lowerSQL, upperSQL, rawLower, rawUpper := t.rangeFieldBoundsAndRawSQL(field, b, nctx)
	existsCond := fmt.Sprintf("(%s IS NOT NULL OR %s IS NOT NULL)", rawLower, rawUpper)
	singleConds := buildConds(lowerSQL, upperSQL)
	singlePred := existsCond
	if len(singleConds) > 0 {
		singlePred = "(" + strings.Join(append([]string{existsCond}, singleConds...), " AND ") + ")"
	}
	var rArrExpr string
	if nctx != nil && nctx.elemVar != "" && (b.Kind == schema.StorageNestedSubfield || b.NestedPath == nctx.nestedPath) && nctx.nestedPath == b.NestedPath {
		relPath := t.nestedRelativeJSONPath(field, false, b.NestedPath)
		rArrExpr = fmt.Sprintf("TRY_CAST(json_extract_string(%s, %s) AS ARRAY<STRING>)", nctx.elemVar, quoteStr(relPath+"._r"))
	} else {
		baseExpr := rangeDocBaseExpr(field, b)
		rArrExpr = fmt.Sprintf("TRY_CAST(%s['_r'] AS ARRAY<STRING>)", baseExpr)
	}
	elemLower := "TRY_CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE)"
	elemUpper := "TRY_CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE)"
	elemConds := append([]string{"_x IS NOT NULL", "_x != ''"}, buildConds(elemLower, elemUpper)...)
	elemPred := "(" + strings.Join(elemConds, " AND ") + ")"
	return fmt.Sprintf("(array_exists(_x -> %s, %s) OR %s)", elemPred, rArrExpr, singlePred)
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
		latExpr := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
		lonExpr := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
		whereSQL = fmt.Sprintf("(%s AND %s)", bboxQ.WhereSQL, buildPointInPolygonSQL(latExpr, lonExpr, gp.Points))
	} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
		arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
		latExpr := "TRY_CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE)"
		lonExpr := "TRY_CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE)"
		whereSQL = fmt.Sprintf("array_exists(_x -> _x IS NOT NULL AND %s, %s)", buildPointInPolygonSQL(latExpr, lonExpr, gp.Points), arrCol)
	} else {
		latExpr, lonExpr, _ := t.extractGeoPointExprs(resolvedField, b)
		whereSQL = fmt.Sprintf("(%s AND %s)", bboxQ.WhereSQL, buildPointInPolygonSQL(latExpr, lonExpr, gp.Points))
	}
	return CompiledQuery{
		WhereSQL:          whereSQL,
		SafeWhereSQL:      whereSQL,
		ScoreSQL:          bboxQ.ScoreSQL,
		UsesFulltextMatch: bboxQ.UsesFulltextMatch,
	}
}

func (t *Transpiler) compileGeoGrid(gg *esast.GeoGridQuery, scoring bool, nctx *nestedCtx) CompiledQuery {
	if gg == nil || strings.TrimSpace(gg.Field) == "" {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	resolvedField, b := t.resolveFieldInNestedCtx(gg.Field, false, nctx)
	if b.EnabledFalse {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.NotIndexed && b.DocValuesFalse {
		if t.searchErr == nil {
			t.searchErr = esTranspilerError(fmt.Sprintf("all_shards_failed|query_shard_exception|failed to create query: Cannot search on field [%s] since it is not indexed nor has doc values.", gg.Field))
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	prevInGG := t.inGeoGridQuery
	t.inGeoGridQuery = true
	defer func() { t.inGeoGridQuery = prevInGG }()
	if !t.checkFieldSearchable(resolvedField, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.ESType == "" && gg.IgnoreUnmapped {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if b.ESType != "" && b.ESType != "geo_point" && b.ESType != "geo_shape" && b.ESType != "point" && b.ESType != "shape" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: failed to find geo_point or geo_shape field [%s]", resolvedField)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	switch gg.GridType() {
	case "geohash":
		bot, top, left, right, ok := decodeGeohashBBoxR64(gg.Geohash)
		if !ok {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		return t.compileGeoBoundingBox(&esast.GeoBoundingBoxQuery{
			Field:          gg.Field,
			Top:            top,
			Bottom:         bot,
			Left:           left,
			Right:          right,
			IgnoreUnmapped: gg.IgnoreUnmapped,
			Boost:          gg.Boost,
			Name:           gg.Name,
		}, scoring, nctx)
	case "geotile":
		top, left, bot, right, ok := decodeGeotileBoundsR64(gg.Geotile)
		if !ok {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		return t.compileGeoBoundingBox(&esast.GeoBoundingBoxQuery{
			Field:          gg.Field,
			Top:            top,
			Bottom:         bot,
			Left:           left,
			Right:          right,
			IgnoreUnmapped: gg.IgnoreUnmapped,
			Boost:          gg.Boost,
			Name:           gg.Name,
		}, scoring, nctx)
	case "geohex":
		cell, err := spatial.StringToCell(strings.TrimSpace(gg.Geohex))
		if err != nil || !spatial.IsValidCell(cell) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		boundary := spatial.CellToBoundary(cell)
		if len(boundary) < 3 {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		return t.compileGeoPolygon(&esast.GeoPolygonQuery{
			Field:          gg.Field,
			Points:         boundary,
			IgnoreUnmapped: gg.IgnoreUnmapped,
			Boost:          gg.Boost,
			Name:           gg.Name,
		}, scoring, nctx)
	default:
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
}

func decodeGeohashBBoxR64(hash string) (bot, top, left, right float64, ok bool) {
	s := strings.ToLower(strings.TrimSpace(hash))
	if s == "" || len(s) > 12 {
		return 0, 0, 0, 0, false
	}
	const base32 = "0123456789bcdefghjkmnpqrstuvwxyz"
	minLat, maxLat := -90.0, 90.0
	minLon, maxLon := -180.0, 180.0
	evenBit := true
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(base32, s[i])
		if idx < 0 {
			return 0, 0, 0, 0, false
		}
		for bit := 4; bit >= 0; bit-- {
			if evenBit {
				mid := (minLon + maxLon) / 2.0
				if (idx>>bit)&1 == 1 {
					minLon = mid
				} else {
					maxLon = mid
				}
			} else {
				mid := (minLat + maxLat) / 2.0
				if (idx>>bit)&1 == 1 {
					minLat = mid
				} else {
					maxLat = mid
				}
			}
			evenBit = !evenBit
		}
	}
	return minLat, maxLat, minLon, maxLon, true
}

func decodeGeotileBoundsR64(tile string) (top, left, bot, right float64, ok bool) {
	parts := strings.Split(strings.TrimSpace(tile), "/")
	if len(parts) != 3 {
		return 0, 0, 0, 0, false
	}
	zoom, errZ := strconv.Atoi(parts[0])
	xtile, errX := strconv.Atoi(parts[1])
	ytile, errY := strconv.Atoi(parts[2])
	if errZ != nil || errX != nil || errY != nil || zoom < 0 || zoom > 29 {
		return 0, 0, 0, 0, false
	}
	maxCoord := 1 << zoom
	if xtile < 0 || xtile >= maxCoord || ytile < 0 || ytile >= maxCoord {
		return 0, 0, 0, 0, false
	}
	n := float64(maxCoord)
	left = float64(xtile)/n*360.0 - 180.0
	right = float64(xtile+1)/n*360.0 - 180.0
	top = math.Atan(math.Sinh(math.Pi*(1.0-2.0*float64(ytile)/n))) * 180.0 / math.Pi
	bot = math.Atan(math.Sinh(math.Pi*(1.0-2.0*float64(ytile+1)/n))) * 180.0 / math.Pi
	return top, left, bot, right, true
}

func ensureDoubleHistogramExprR64(expr string, b schema.FieldBinding) string {
	if b.ESType == "unsigned_long" || b.DorisType == schema.DorisLargeInt || b.DorisType == schema.DorisLargeIntArray {
		if (strings.HasPrefix(expr, "CAST(") || strings.HasPrefix(expr, "TRY_CAST(")) && strings.HasSuffix(expr, " AS DOUBLE)") {
			return expr
		}
		return fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", expr)
	}
	return expr
}

// formatHistogramBucketKeySQLR65 emits the SQL bucket-key string expression for `histogram`
// aggregations. For `unsigned_long` / `LARGEINT` columns with integral offset & interval,
// multiplying the integer bucket index in `LARGEINT` avoids Doris `CAST(DOUBLE AS STRING)`
// 15-digit precision drift (`mapper-unsigned-long/10_basic.yml` with `interval: 2^63-1`).
func formatHistogramBucketKeySQLR65(colDiv string, offset, interval float64, b schema.FieldBinding) string {
	return formatHistogramBucketKeySQLWithRawParamsR65(colDiv, offset, interval, RawHistParamStrings{}, b)
}

var (
	dorisLargeIntMinR66 = func() *big.Int {
		v, _ := new(big.Int).SetString("-170141183460469231731687303715884105728", 10)
		return v
	}()
	dorisLargeIntMaxR66 = func() *big.Int {
		v, _ := new(big.Int).SetString("170141183460469231731687303715884105727", 10)
		return v
	}()
)

func isExactSignedIntLiteralR65(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' || s[0] == '+' {
		if len(s) == 1 {
			return false
		}
		i = 1
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return false
	}
	return bi.Cmp(dorisLargeIntMinR66) >= 0 && bi.Cmp(dorisLargeIntMaxR66) <= 0
}

func isPositiveExactSignedIntLiteralR66(s string) bool {
	if !isExactSignedIntLiteralR65(s) {
		return false
	}
	bi, ok := new(big.Int).SetString(s, 10)
	return ok && bi.Sign() > 0
}

func (t *Transpiler) formatHistogramBucketKeySQLWithRawR65(colDiv, aggPath string, offset, interval float64, b schema.FieldBinding) string {
	var raw RawHistParamStrings
	if t != nil && t.Opts.RawHistBounds != nil {
		raw = t.Opts.RawHistBounds[aggPath]
	}
	return formatHistogramBucketKeySQLWithRawParamsR65(colDiv, offset, interval, raw, b)
}

func isIntegralHistogramTypeR66(b schema.FieldBinding) bool {
	switch b.ESType {
	case "unsigned_long", "long", "integer", "short", "byte":
		return true
	}
	switch b.DorisType {
	case schema.DorisLargeInt, schema.DorisLargeIntArray,
		schema.DorisBigInt, schema.DorisInt:
		return true
	}
	return false
}

func formatHistogramBucketKeySQLWithRawParamsR65(colDiv string, offset, interval float64, raw RawHistParamStrings, b schema.FieldBinding) string {
	if math.IsNaN(offset) || math.IsInf(offset, 0) {
		offset = 0
	}
	if math.IsNaN(interval) || math.IsInf(interval, 0) || interval <= 0 {
		interval = 1.0
	}
	offStr := FormatSQLFloatR63(offset)
	intStr := FormatSQLFloatR63(interval)
	isIntHist := isIntegralHistogramTypeR66(b)
	rawInt := strings.TrimSpace(raw.Interval)
	if isIntHist && isPositiveExactSignedIntLiteralR66(rawInt) {
		intStr = rawInt
		rawOff := strings.TrimSpace(raw.Offset)
		if isExactSignedIntLiteralR65(rawOff) {
			offStr = rawOff
		} else if offset == 0 {
			offStr = "0"
		}
		return fmt.Sprintf("CAST((TRY_CAST(FLOOR((%s - %s) / %s) AS LARGEINT) * %s + %s) AS STRING)", colDiv, offStr, intStr, intStr, offStr)
	}
	if isIntHist && interval > 0 && !math.IsNaN(offset) && !math.IsInf(offset, 0) && !math.IsNaN(interval) && !math.IsInf(interval, 0) &&
		interval == math.Trunc(interval) && offset == math.Trunc(offset) &&
		math.Abs(interval) <= 1e20 && math.Abs(offset) <= 1e20 {
		return fmt.Sprintf("CAST((TRY_CAST(FLOOR((%s - %s) / %s) AS LARGEINT) * %s + %s) AS STRING)", colDiv, offStr, intStr, intStr, offStr)
	}
	return fmt.Sprintf("CAST(FLOOR((%s - %s) / %s) * %s + %s AS STRING)", colDiv, offStr, intStr, intStr, offStr)
}

func schemaHasMappedNonNestedPathR66(sc *schema.IndexSchema, targetPath string) bool {
	if sc == nil || targetPath == "" {
		return false
	}
	if _, ok := sc.Fields[targetPath]; ok {
		return true
	}
	prefix := targetPath + "."
	for fp, fb := range sc.Fields {
		if strings.HasPrefix(fp, prefix) && fb.NestedPath != targetPath {
			return true
		}
	}
	if sc.RawMapping != nil && len(sc.RawMapping.Properties) > 0 {
		segs := strings.Split(targetPath, ".")
		props := sc.RawMapping.Properties
		for i, seg := range segs {
			prop, exists := props[seg]
			if !exists {
				return false
			}
			if i == len(segs)-1 {
				return !strings.EqualFold(strings.TrimSpace(prop.Type), "nested")
			}
			props = prop.Properties
			if len(props) == 0 {
				return true
			}
		}
	}
	return false
}

func schemaHasNestedObjectPathR65(sc *schema.IndexSchema, nestedPath string) bool {
	if sc == nil || nestedPath == "" {
		return false
	}
	if sc.RawMapping != nil && len(sc.RawMapping.Properties) > 0 {
		segs := strings.Split(nestedPath, ".")
		props := sc.RawMapping.Properties
		for i, seg := range segs {
			fp, ok := props[seg]
			if !ok {
				break
			}
			if i == len(segs)-1 {
				if fp.Type == "nested" {
					return true
				}
			} else {
				props = fp.Properties
			}
		}
	}
	prefix := nestedPath + "."
	for _, b := range sc.Fields {
		if b.NestedPath == nestedPath || strings.HasPrefix(b.NestedPath, prefix) {
			return true
		}
	}
	return false
}

func (t *Transpiler) resolveUnsignedLongRangeAggMissingExact(effField string, spec *esast.RangeAggSpec) (uint64, bool) {
	if spec == nil || spec.Missing == nil || effField == "" || t.Schema == nil {
		return 0, false
	}
	b := t.Schema.ResolveEffectiveField(effField, true)
	if b.ESType != "unsigned_long" && b.DorisType != schema.DorisLargeInt && b.DorisType != schema.DorisLargeIntArray {
		return 0, false
	}
	switch v := spec.Missing.(type) {
	case uint64:
		return v, true
	case int:
		if v >= 0 {
			return uint64(v), true
		}
	case int64:
		if v >= 0 {
			return uint64(v), true
		}
	case json.Number:
		if u, err := strconv.ParseUint(strings.TrimSpace(v.String()), 10, 64); err == nil {
			return u, true
		}
	case string:
		if u, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
			return u, true
		}
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v < 18446744073709551616.0 {
			return uint64(v), true
		}
	}
	return 0, false
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
	if b.ESType != "" && b.ESType != "geo_shape" && b.ESType != "geo_point" && b.ESType != "shape" && b.ESType != "point" {
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
		posWhere := t.evalGeoPointPredForFieldWithRelationR63(gs.Field, rel, nctx, func(latExpr, lonExpr string) string {
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
			posWhere := t.evalGeoPointPredForFieldWithRelationR63(gs.Field, rel, nctx, func(latExpr, lonExpr string) string {
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
					if rel == "CONTAINS" && b.ESType != "geo_shape" && (top != bottom || lon0 != lon1) {
						return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
					}
					if rel == "WITHIN" {
						topStr := strconv.FormatFloat(top, 'f', -1, 64)
						bottomStr := strconv.FormatFloat(bottom, 'f', -1, 64)
						leftStr := strconv.FormatFloat(lon0, 'f', -1, 64)
						rightStr := strconv.FormatFloat(lon1, 'f', -1, 64)
						withinWhere := t.evalGeoPointPredForFieldWithRelationR63(gs.Field, "WITHIN", nctx, func(latExpr, lonExpr string) string {
							latCond := fmt.Sprintf("%s >= %s AND %s <= %s", latExpr, bottomStr, latExpr, topStr)
							var lonCond string
							if lon0 <= lon1 {
								lonCond = fmt.Sprintf("%s >= %s AND %s <= %s", lonExpr, leftStr, lonExpr, rightStr)
							} else {
								lonCond = fmt.Sprintf("(%s >= %s OR %s <= %s)", lonExpr, leftStr, lonExpr, rightStr)
							}
							return fmt.Sprintf("%s AND %s", latCond, lonCond)
						})
						return CompiledQuery{WhereSQL: withinWhere, SafeWhereSQL: withinWhere, ScoreSQL: scoreSQL}
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
	var pinnedRanks []int
	if len(p.Docs) > 0 && t.Schema != nil && t.Schema.IndexName != "" {
		rankIdx := 0
		for _, id := range p.IDs {
			if id != "" {
				pinnedIDs = append(pinnedIDs, id)
				pinnedRanks = append(pinnedRanks, rankIdx)
			}
			rankIdx++
		}
		for _, d := range p.Docs {
			idxVal, okIdx := d["_index"]
			if (!okIdx || idxVal == nil) || strings.TrimSpace(fmt.Sprintf("%v", idxVal)) == t.Schema.IndexName {
				if idVal, okID := d["_id"]; okID && idVal != nil {
					if s := strings.TrimSpace(fmt.Sprintf("%v", idVal)); s != "" {
						pinnedIDs = append(pinnedIDs, s)
						pinnedRanks = append(pinnedRanks, rankIdx)
					}
				}
			}
			rankIdx++
		}
	} else {
		for idx, id := range p.EffectiveIDs() {
			if id != "" {
				pinnedIDs = append(pinnedIDs, id)
				pinnedRanks = append(pinnedRanks, idx)
			}
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
				rankWeight := 1000000.0 - float64(pinnedRanks[i])*1000.0
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

func (t *Transpiler) compileMoreLikeThis(mlt *esast.MoreLikeThisQuery, inScoring bool, nctx *nestedCtx) CompiledQuery {
	return t.compileMoreLikeThisRound61(mlt, inScoring, nctx)
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
		hasUseField := strings.TrimSpace(rule.Match.UseField) != ""
		if hasUseField {
			targetField = strings.TrimSpace(rule.Match.UseField)
		}
		rf, rb := t.resolveFieldInNestedCtx(targetField, false, nctx)
		if !t.checkFieldPositionalSearchable(rf, rb) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		effAn := t.effectiveQueryAnalyzerName(rb, rule.Match.Analyzer)
		if t.hasCustomQueryAnalysis(effAn) {
			// `EvaluateIntervalsRuleWithFieldLookup` evaluates exact stemmed/custom token streams in Go;
			// avoid rejecting un-stemmed column text (e.g. `"dogs"` vs stemmed `"dog"` in `70_intervals.yml :: Test use_field`).
			w := t.compileExistsPredicate(targetField, nctx)
			sc := "0.0"
			if inScoring && boost != 0 && w != "FALSE" {
				sc = fmt.Sprintf("%g", boost)
			}
			cp = CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: sc}
		} else {
			op := "and"
			if !rule.Match.Ordered && rule.Match.MaxGaps != nil && *rule.Match.MaxGaps != 0 {
				op = "or"
			}
			if rule.Match.Ordered && rule.Match.MaxGaps != nil && *rule.Match.MaxGaps >= 0 {
				slop := 0
				if *rule.Match.MaxGaps > 0 {
					slop = *rule.Match.MaxGaps
				}
				cp = t.compileMatchPhraseField(targetField, rule.Match.Query, slop, boost, false, inScoring, nctx)
			} else {
				cp = t.compileMatchField(targetField, rule.Match.Query, op, boost, inScoring, nctx)
			}
		}
		if rule.Match.Filter != nil {
			cp = t.applyIntervalsFilter(field, cp, rule.Match.Filter, inScoring, nctx)
		}
	case rule.Prefix != nil:
		targetField := field
		if strings.TrimSpace(rule.Prefix.UseField) != "" {
			targetField = strings.TrimSpace(rule.Prefix.UseField)
		}
		rf, rb := t.resolveFieldInNestedCtx(targetField, false, nctx)
		if !t.checkFieldPositionalSearchable(rf, rb) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		cp = t.compileMatchPhraseField(targetField, rule.Prefix.Prefix, 0, boost, true, inScoring, nctx)
		if rule.Prefix.Filter != nil {
			cp = t.applyIntervalsFilter(field, cp, rule.Prefix.Filter, inScoring, nctx)
		}
	case rule.Wildcard != nil:
		targetField := field
		if strings.TrimSpace(rule.Wildcard.UseField) != "" {
			targetField = strings.TrimSpace(rule.Wildcard.UseField)
		}
		rf, rb := t.resolveFieldInNestedCtx(targetField, false, nctx)
		if !t.checkFieldPositionalSearchable(rf, rb) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		w := t.compileWildcardPredicate(targetField, rule.Wildcard.Pattern, true, nctx)
		sc := "0.0"
		if inScoring && boost != 0 && w != "FALSE" {
			sc = fmt.Sprintf("%g", boost)
		}
		cp = CompiledQuery{WhereSQL: w, SafeWhereSQL: w, ScoreSQL: sc}
		if rule.Wildcard.Filter != nil {
			cp = t.applyIntervalsFilter(field, cp, rule.Wildcard.Filter, inScoring, nctx)
		}
	case rule.Fuzzy != nil:
		targetField := field
		if strings.TrimSpace(rule.Fuzzy.UseField) != "" {
			targetField = strings.TrimSpace(rule.Fuzzy.UseField)
		}
		rf, rb := t.resolveFieldInNestedCtx(targetField, false, nctx)
		if !t.checkFieldPositionalSearchable(rf, rb) {
			return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
		}
		fuzz := any("AUTO")
		if rule.Fuzzy.Fuzziness != nil {
			fuzz = rule.Fuzzy.Fuzziness
		}
		cp = t.compileFuzzyFieldWithOpts(targetField, rule.Fuzzy.Term, "or", fuzz, false, rule.Fuzzy.PrefixLength, rule.Fuzzy.Transpositions, boost, inScoring, nctx)
		if rule.Fuzzy.Filter != nil {
			cp = t.applyIntervalsFilter(field, cp, rule.Fuzzy.Filter, inScoring, nctx)
		}
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

func (t *Transpiler) applyIntervalsFilter(field string, base CompiledQuery, f *esast.IntervalsFilter, _ bool, nctx *nestedCtx) CompiledQuery {
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
	// Validate any nested field references inside negative rules (`not_containing`, `not_contained_by`, `not_overlapping`),
	// without emitting document-level `NOT (...)` in the SQL prefilter (since another span in the same document may satisfy the rule!).
	for _, negRule := range []*esast.IntervalsRule{f.NotContaining, f.NotContainedBy, f.NotOverlapping} {
		if negRule != nil {
			_ = t.compileIntervalsRule(field, *negRule, false, nctx)
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
	prevSpan := t.inSpanQuery
	t.inSpanQuery = true
	defer func() { t.inSpanQuery = prevSpan }()
	switch {
	case len(q.SpanTerm) > 0:
		keys := sortedMapKeys(q.SpanTerm)
		var preds, safePreds, scores []string
		usesFT := false
		for _, field := range keys {
			st := q.SpanTerm[field]
			boost := st.Boost
			_, b := t.resolveFieldInNestedCtx(field, false, nctx)
			if !t.checkSpanFieldNotMatchOnlyText(field, b) {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
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
			_, b := t.resolveFieldInNestedCtx(commonField, false, nctx)
			if !t.checkSpanFieldNotMatchOnlyText(commonField, b) {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
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
			var negExc string
			if exc.UsesFulltextMatch || strings.Contains(exc.WhereSQL, "MATCH_") || strings.Contains(exc.WhereSQL, "SEARCH(") {
				negExc = negateFulltextWhereSQL(exc.WhereSQL)
			} else {
				negExc = fmt.Sprintf("NOT COALESCE(%s, FALSE)", exc.WhereSQL)
			}
			var negSafeExc string
			excSafe := exc.EffectiveSafeWhere()
			if strings.Contains(excSafe, "MATCH_") || strings.Contains(excSafe, "SEARCH(") {
				negSafeExc = negateFulltextWhereSQL(excSafe)
			} else {
				negSafeExc = fmt.Sprintf("NOT COALESCE(%s, FALSE)", excSafe)
			}
			w = fmt.Sprintf("(%s AND %s)", inc.WhereSQL, negExc)
			sw = fmt.Sprintf("(%s AND %s)", inc.EffectiveSafeWhere(), negSafeExc)
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
		for _, fld := range spanMultiTargetFields(q.SpanMulti.Match) {
			_, b := t.resolveFieldInNestedCtx(fld, false, nctx)
			if !t.checkSpanFieldNotMatchOnlyText(fld, b) {
				return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
			}
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
	field, b, nullVal := t.resolveRankFeatureBindingAndNullValue(rf.Field, nctx)
	if !t.checkFieldSearchable(field, b) {
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	if t.Schema != nil && len(t.Schema.Fields) > 0 && b.ESType != "" && b.ESType != "rank_feature" && b.ESType != "rank_features" {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("query_shard_exception: [rank_feature] query only works on [rank_feature] or [rank_features] fields, not [%s]", b.ESType)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	positiveImpact := b.EffectivePositiveScoreImpact()
	if !positiveImpact && rf.Log != nil {
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("illegal_argument_exception: [rank_feature] Function [log] cannot be used when [positive_score_impact] is false on field [%s]", rf.Field)
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
	}
	col := t.sqlTypedColumnRef(field, 0.5, false, nctx)
	whereSQL := fmt.Sprintf("(%s IS NOT NULL AND %s > 0)", col, col)
	effDoubleExpr := fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", col)
	if nullVal != nil && *nullVal > 0 {
		nvLit := strconv.FormatFloat(*nullVal, 'g', -1, 64)
		whereSQL = fmt.Sprintf("(%s IS NULL OR %s > 0)", col, col)
		effDoubleExpr = fmt.Sprintf("COALESCE(TRY_CAST(%s AS DOUBLE), %s)", col, nvLit)
	}
	scoreSQL := "0.0"
	if inScoring {
		boost := 1.0
		if rf.Boost != nil {
			boost = *rf.Boost
		}
		if boost != 0 {
			if positiveImpact {
				numExpr := fmt.Sprintf("GREATEST(COALESCE(%s, 0.0), 0.0)", effDoubleExpr)
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
			} else {
				valExpr := effDoubleExpr
				var invFormula string
				switch {
				case rf.Saturation != nil:
					pivot := 1.0
					if p, ok := toFloat64ForGeo(rf.Saturation["pivot"]); ok && p > 0 {
						pivot = p
					}
					invFormula = fmt.Sprintf("(%g * (%g / (%s + %g)))", boost, pivot, valExpr, pivot)
				case rf.Sigmoid != nil:
					pivot := 1.0
					if p, ok := toFloat64ForGeo(rf.Sigmoid["pivot"]); ok && p > 0 {
						pivot = p
					}
					exp := 1.0
					if e, ok := toFloat64ForGeo(rf.Sigmoid["exponent"]); ok && e > 0 {
						exp = e
					}
					invFormula = fmt.Sprintf("(%g * (POW(%g, %g) / (POW(%s, %g) + POW(%g, %g))))", boost, pivot, exp, valExpr, exp, pivot, exp)
				case rf.Linear != nil:
					invFormula = fmt.Sprintf("(%g * (1.0 / %s))", boost, valExpr)
				default:
					invFormula = fmt.Sprintf("(%g * (1.0 / (%s + 1.0)))", boost, valExpr)
				}
				if nullVal != nil && *nullVal > 0 {
					scoreSQL = fmt.Sprintf("(CASE WHEN %s > 0 THEN %s ELSE 0.0 END)", valExpr, invFormula)
				} else {
					scoreSQL = fmt.Sprintf("(CASE WHEN %s IS NOT NULL AND %s > 0 THEN %s ELSE 0.0 END)", col, valExpr, invFormula)
				}
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
						latExpr := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 1) AS DOUBLE)", elemExpr)
						lonExpr := fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)", elemExpr)
						distExpr = fmt.Sprintf("ST_Distance_Sphere(%s, %s, %s, %s)", lonExpr, latExpr, tLonStr, tLatStr)
					} else if b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield {
						arrCol := fmt.Sprintf("`%s`", b.EffectiveArrayColumn(true))
						distExpr = fmt.Sprintf("array_min(array_map(_x -> ST_Distance_Sphere(TRY_CAST(SPLIT_PART(_x, ',', 2) AS DOUBLE), TRY_CAST(SPLIT_PART(_x, ',', 1) AS DOUBLE), %s, %s), %s))", tLonStr, tLatStr, arrCol)
					} else {
						latExpr, lonExpr, _ := t.extractGeoPointExprs(field, b)
						distExpr = fmt.Sprintf("ST_Distance_Sphere(%s, %s, %s, %s)", lonExpr, latExpr, tLonStr, tLatStr)
					}
					boostStr := FormatSQLFloatR63(boost)
					pivotStr := FormatSQLFloatR63(pivotM)
					scoreSQL = fmt.Sprintf("(%s * (%s / (%s + GREATEST(%s, 0.0))))", boostStr, pivotStr, pivotStr, distExpr)
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
			colDouble := col
			if !strings.HasSuffix(strings.TrimSpace(colDouble), " AS DOUBLE)") {
				colDouble = fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", colDouble)
			}
			originStr := FormatSQLFloatR63(originMs)
			pivotStr := FormatSQLFloatR63(pivotVal)
			boostStr := FormatSQLFloatR63(boost)
			distExpr := fmt.Sprintf("ABS(COALESCE(%s, %s) - %s)", colDouble, originStr, originStr)
			scoreSQL = fmt.Sprintf("(%s * (%s / (%s + %s)))", boostStr, pivotStr, pivotStr, distExpr)
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
		base.WriteString("[" + quoteStr(p) + "]")
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
		baseExpr := joinFieldDocExpr(jf)
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
		if t.searchErr == nil {
			t.searchErr = fmt.Errorf("parsing_exception: [rule] requires [organic] query")
		}
		return CompiledQuery{WhereSQL: "FALSE", SafeWhereSQL: "FALSE", ScoreSQL: "0.0"}
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
		col := t.buildSparseVectorTokenMaxWeightExprR63(resolvedField, tok, nctx)
		cond := fmt.Sprintf("(%s IS NOT NULL AND %s > 0)", col, col)
		allConds = append(allConds, cond)
		sTerm := fmt.Sprintf("(GREATEST(COALESCE(TRY_CAST(%s AS DOUBLE), 0.0), 0.0) * %g)", col, w)
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

// compileHistogramRangeBucketSQLR65 builds the LATERAL VIEW EXPLODE clause, matching entry
// predicate, and weighted `SUM(count)` expression for `range` aggregations on ES `histogram` fields.
func compileHistogramRangeBucketSQLR65(baseFrom, hArrExpr, tblAlias, elemAlias, valExpr, fromLit, toLit string) (fromClause, predSQL, countExpr string) {
	fromClause = fmt.Sprintf("%s LATERAL VIEW EXPLODE(%s) %s AS %s", baseFrom, hArrExpr, tblAlias, elemAlias)
	conds := []string{
		fmt.Sprintf("%s IS NOT NULL", elemAlias),
		fmt.Sprintf("%s != ''", elemAlias),
		fmt.Sprintf("TRY_CAST(SPLIT_PART(%s, ',', 2) AS BIGINT) > 0", elemAlias),
	}
	if fromLit != "" {
		conds = append(conds, fmt.Sprintf("%s >= %s", valExpr, fromLit))
	}
	if toLit != "" {
		conds = append(conds, fmt.Sprintf("%s < %s", valExpr, toLit))
	}
	predSQL = strings.Join(conds, " AND ")
	countExpr = fmt.Sprintf("COALESCE(SUM(TRY_CAST(SPLIT_PART(%s, ',', 2) AS DOUBLE)), 0)", elemAlias)
	return fromClause, predSQL, countExpr
}

// compileMultiTermsOrderByR65 converts a `multi_terms.order` spec into SQL `ORDER BY` clauses
// for `_count` / `_key` ordering and reports whether custom sub-agg post-sorting is needed.
func compileMultiTermsOrderByR65(order any) (orderBySQL string, needsPostSort bool) {
	const defaultOrder = "`_doc_count` DESC, `_bucket_key` ASC"
	if order == nil {
		return defaultOrder, false
	}
	var orderMaps []map[string]any
	switch o := order.(type) {
	case map[string]any:
		orderMaps = append(orderMaps, o)
	case []map[string]any:
		orderMaps = append(orderMaps, o...)
	case []any:
		for _, item := range o {
			if m, ok := item.(map[string]any); ok {
				orderMaps = append(orderMaps, m)
			}
		}
	}
	var parts []string
	hasBucketKey := false
	for _, m := range orderMaps {
		for _, k := range sortedMapKeys(m) {
			dir := "ASC"
			if strings.EqualFold(strings.TrimSpace(fmt.Sprint(m[k])), "desc") {
				dir = "DESC"
			}
			switch k {
			case "_count":
				parts = append(parts, "`_doc_count` "+dir)
			case "_key":
				parts = append(parts, "`_bucket_key` "+dir)
				hasBucketKey = true
			default:
				needsPostSort = true
			}
		}
	}
	if needsPostSort || len(parts) == 0 {
		return defaultOrder, needsPostSort
	}
	if !hasBucketKey {
		parts = append(parts, "`_bucket_key` ASC")
	}
	return strings.Join(parts, ", "), false
}

func formatMultiTermValueExprR65(expr string, mt esast.MultiTermTermSpec, mtField string, b schema.FieldBinding, alreadyTypedUL bool) (valExpr string, isExplicitCast bool) {
	vt := strings.ToLower(strings.TrimSpace(mt.ValueType))
	isUL := vt == "unsigned_long" || (vt == "" && (b.ESType == "unsigned_long" || b.DorisType == schema.DorisLargeInt || b.DorisType == schema.DorisLargeIntArray))
	isBool := vt == "boolean" || (vt == "" && effectiveDorisScalarType(b) == schema.DorisBoolean)
	switch {
	case isBool:
		return fmt.Sprintf("CASE WHEN %s IS NULL THEN NULL WHEN LOWER(CAST(%s AS STRING)) IN ('true', '1') THEN 'true' ELSE 'false' END", expr, expr), false
	case isUL:
		if alreadyTypedUL {
			return expr, false
		}
		return fmt.Sprintf("TRY_CAST(%s AS LARGEINT)", expr), vt != ""
	case vt == "long" || vt == "integer" || vt == "short" || vt == "byte":
		return fmt.Sprintf("TRY_CAST(%s AS BIGINT)", expr), true
	case vt == "double" || vt == "float" || vt == "half_float" || vt == "scaled_float":
		return fmt.Sprintf("TRY_CAST(%s AS DOUBLE)", expr), true
	case vt == "" && mtField != "" && b.EffectiveLowercase(!strings.HasSuffix(mtField, ".keyword")):
		return fmt.Sprintf("LOWER(CAST(%s AS STRING))", expr), false
	default:
		return expr, false
	}
}

func (t *Transpiler) compileMultiTermsTermExprsR65(mtTerms []esast.MultiTermTermSpec, baseFrom string, nctx *nestedCtx, explodeDepth int) (termExprs, notNulls []string, outFrom string, explodedAny bool) {
	outFrom = baseFrom
	for i, mt := range mtTerms {
		mtField, b := t.resolveFieldInNestedCtx(mt.Field, true, nctx)
		if nctx == nil && mt.Script == nil && (b.Kind == schema.StoragePromotedArray || b.Kind == schema.StorageNestedSubfield) && b.EffectiveArrayColumn(true) != "" {
			explodedAny = true
			arrCol := b.EffectiveArrayColumn(true)
			tblAlias := fmt.Sprintf("`_mt_t_%d`", i)
			elemAlias := fmt.Sprintf("`_mt_elem_%d`", i)
			if strings.Contains(outFrom, "`_mt_elem_") {
				tblAlias = fmt.Sprintf("`_mt_t_%d_%d`", explodeDepth, i)
				elemAlias = fmt.Sprintf("`_mt_elem_%d_%d`", explodeDepth, i)
			}
			elemValExpr, explicitCast := formatMultiTermValueExprR65(elemAlias, mt, mtField, b, false)
			if mt.Missing != nil {
				outFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(CASE WHEN `%s` IS NULL OR array_size(`%s`) = 0 THEN %s ELSE `%s` END) %s AS %s", outFrom, arrCol, arrCol, nullSingletonArraySQL(b), arrCol, tblAlias, elemAlias)
				termExprs = append(termExprs, fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", elemValExpr, quoteStr(formatMissingScalar(mt.Missing))))
			} else {
				outFrom = fmt.Sprintf("%s LATERAL VIEW EXPLODE(`%s`) %s AS %s", outFrom, arrCol, tblAlias, elemAlias)
				nullTarget := elemAlias
				if explicitCast {
					nullTarget = elemValExpr
				}
				notNulls = append(notNulls, fmt.Sprintf("%s IS NOT NULL", nullTarget))
				termExprs = append(termExprs, fmt.Sprintf("CAST(%s AS STRING)", elemValExpr))
			}
			continue
		}

		rawCol := t.sqlColumnRef(mtField, true, nctx)
		alreadyTypedUL := false
		isUL := strings.EqualFold(mt.ValueType, "unsigned_long") || (mt.ValueType == "" && b.ESType == "unsigned_long")
		if mt.Script == nil && isUL && mtField != "" {
			rawCol = t.sqlTypedColumnRef(mtField, uint64(math.MaxUint64), true, nctx)
			alreadyTypedUL = true
		}
		col := rawCol
		explicitCast := false
		if mt.Script != nil {
			if se, ok := t.compilePolymorphicScriptExpr(mt.Script, mtField, col, nctx); ok {
				col = se
				rawCol = se
				if mt.ValueType != "" {
					col, explicitCast = formatMultiTermValueExprR65(col, mt, mtField, b, false)
				}
			}
		} else if mtField != "" {
			col, explicitCast = formatMultiTermValueExprR65(rawCol, mt, mtField, b, alreadyTypedUL)
		}
		if mt.Missing != nil {
			termExprs = append(termExprs, fmt.Sprintf("COALESCE(CAST(%s AS STRING), %s)", col, quoteStr(formatMissingScalar(mt.Missing))))
		} else {
			nullTarget := rawCol
			if explicitCast {
				nullTarget = col
			}
			notNulls = append(notNulls, fmt.Sprintf("%s IS NOT NULL", nullTarget))
			termExprs = append(termExprs, fmt.Sprintf("CAST(%s AS STRING)", col))
		}
	}
	return termExprs, notNulls, outFrom, explodedAny
}
