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
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func buildRound60CovSchema(t *testing.T, disableSource bool) *schema.IndexSchema {
	t.Helper()
	srcBlock := `{"enabled": true}`
	if disableSource {
		srcBlock = `{"enabled": false}`
	}
	rawMapping := `{
		"_source": ` + srcBlock + `,
		"properties": {
			"title": {
				"type": "text",
				"analyzer": "standard",
				"fields": {
					"keyword": {"type": "keyword"}
				}
			},
			"ws_text": {
				"type": "text",
				"analyzer": "whitespace"
			},
			"category": {"type": "keyword"},
			"category_alias": {"type": "alias", "path": "category"},
			"no_dv": {"type": "keyword", "doc_values": false},
			"disabled_obj": {"type": "object", "enabled": false},
			"count_long": {"type": "long"},
			"count_ulong": {"type": "unsigned_long"},
			"score_double": {"type": "double"},
			"score_float": {"type": "float"},
			"active": {"type": "boolean"},
			"created_at": {"type": "date"},
			"created_nanos": {"type": "date_nanos"},
			"client_ip": {"type": "ip"},
			"location": {"type": "geo_point"},
			"tags": {"properties": {"name": {"type": "keyword"}}},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"qty": {"type": "integer"}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	idx := schema.CompileIndexSchema("es_db", "round60_idx", &spec)
	// Ensure multi-valued promoted array coverage for metadata/threshold helpers.
	if fb, ok := idx.Fields["tags.name"]; ok {
		fb.Kind = schema.StoragePromotedArray
		fb.IsMultiValued = true
		idx.Fields["tags.name"] = fb
		for i := range idx.OrderedFields {
			if idx.OrderedFields[i].ESFieldPath == "tags.name" {
				idx.OrderedFields[i] = fb
			}
		}
	}
	return idx
}

func TestRound60Coverage_LimitsAndCollapseValidation(t *testing.T) {
	idx := buildRound60CovSchema(t, false)

	// 1. Default limits, Schema limits, and Opts limits
	trDefault := NewTranspiler(nil, TranspilerOptions{})
	if got := trDefault.effectiveMaxResultWindow(); got != DefaultMaxResultWindow {
		t.Fatalf("expected DefaultMaxResultWindow, got %d", got)
	}
	if got := trDefault.effectiveMaxDocvalueFieldsSearch(); got != DefaultMaxDocvalueFieldsSearch {
		t.Fatalf("expected DefaultMaxDocvalueFieldsSearch, got %d", got)
	}
	if got := trDefault.effectiveMaxScriptFields(); got != DefaultMaxScriptFields {
		t.Fatalf("expected DefaultMaxScriptFields, got %d", got)
	}
	if got := trDefault.effectiveMaxRegexLength(); got != DefaultMaxRegexLength {
		t.Fatalf("expected DefaultMaxRegexLength, got %d", got)
	}

	idxCopy := *idx
	idxCopy.MaxResultWindow = 5000
	idxCopy.MaxDocvalueFieldsSearch = 4
	idxCopy.MaxScriptFields = 2
	idxCopy.MaxRegexLength = 10
	trSchemaLim := NewTranspiler(&idxCopy, TranspilerOptions{})
	if trSchemaLim.effectiveMaxResultWindow() != 5000 ||
		trSchemaLim.effectiveMaxDocvalueFieldsSearch() != 4 ||
		trSchemaLim.effectiveMaxScriptFields() != 2 ||
		trSchemaLim.effectiveMaxRegexLength() != 10 {
		t.Fatalf("unexpected schema-derived limits")
	}

	trOptsLim := NewTranspiler(&idxCopy, TranspilerOptions{
		MaxResultWindow:         123,
		MaxDocvalueFieldsSearch: 2,
		MaxScriptFields:         1,
		MaxRegexLength:          5,
	})
	if trOptsLim.effectiveMaxResultWindow() != 123 ||
		trOptsLim.effectiveMaxDocvalueFieldsSearch() != 2 ||
		trOptsLim.effectiveMaxScriptFields() != 1 ||
		trOptsLim.effectiveMaxRegexLength() != 5 {
		t.Fatalf("unexpected opts-derived limits")
	}

	// 2. countExpandedDocvalueFields & validateDocvalueAndScriptFieldLimits
	if got := trSchemaLim.countExpandedDocvalueFields(nil); got != 0 {
		t.Fatalf("expected 0 expanded docvalue fields, got %d", got)
	}
	expanded := trSchemaLim.countExpandedDocvalueFields([]esast.FieldRequestSpec{
		{Field: "*"},
		{Field: "explicit_field"},
	})
	if expanded < 5 {
		t.Fatalf("expected wildcard docvalue expansion >= 5, got %d", expanded)
	}
	if err := trOptsLim.validateDocvalueAndScriptFieldLimits([]esast.FieldRequestSpec{{Field: "a"}, {Field: "b"}}, map[string]any{"s1": 1}); err != nil {
		t.Fatalf("expected valid limits, got %v", err)
	}
	if err := trOptsLim.validateDocvalueAndScriptFieldLimits([]esast.FieldRequestSpec{{Field: "*"}}, nil); err == nil {
		t.Fatalf("expected docvalue_fields limit error")
	}
	if err := trOptsLim.validateDocvalueAndScriptFieldLimits(nil, map[string]any{"s1": 1, "s2": 2}); err == nil {
		t.Fatalf("expected script_fields limit error")
	}

	// 3. checkRegexLengthLimit
	if !trOptsLim.checkRegexLengthLimit("abc") {
		t.Fatalf("expected short regex to pass")
	}
	trOptsLim.inLenientQuery = true
	if trOptsLim.checkRegexLengthLimit("abcdefg") || trOptsLim.searchErr != nil {
		t.Fatalf("expected lenient regex limit failure without searchErr")
	}
	trOptsLim.inLenientQuery = false
	if trOptsLim.checkRegexLengthLimit("abcdefg") || trOptsLim.searchErr == nil {
		t.Fatalf("expected strict regex limit failure setting searchErr")
	}

	// 4. collapseFieldMatchesSortField
	tr := NewTranspiler(idx, TranspilerOptions{})
	if tr.collapseFieldMatchesSortField("", "category") || tr.collapseFieldMatchesSortField("category", "_score") {
		t.Fatalf("expected empty/_score sort mismatch")
	}
	if !tr.collapseFieldMatchesSortField("category", "category") {
		t.Fatalf("expected identical field match")
	}
	if trDefault.collapseFieldMatchesSortField("a", "b") {
		t.Fatalf("expected nil schema mismatch")
	}
	if !tr.collapseFieldMatchesSortField("category_alias", "category") || !tr.collapseFieldMatchesSortField("category", "category_alias") {
		t.Fatalf("expected alias field match")
	}
	if !tr.collapseFieldMatchesSortField("title", "title.keyword") {
		t.Fatalf("expected text/keyword companion match via ResolveEffectiveField")
	}
	if tr.collapseFieldMatchesSortField("category", "count_long") {
		t.Fatalf("expected distinct columns not to match")
	}

	// 5. validateCollapseRequest
	if err := tr.validateCollapseRequest(nil); err != nil {
		t.Fatalf("unexpected error for nil request: %v", err)
	}
	if err := tr.validateCollapseRequest(&esast.SearchRequest{
		Collapse: &esast.CollapseSpec{Field: "category"},
		Rescore:  esast.RescoreSlice{{}},
	}); err == nil {
		t.Fatalf("expected collapse + rescore error")
	}
	if err := tr.validateCollapseRequest(&esast.SearchRequest{
		Collapse: &esast.CollapseSpec{Field: "category"},
		Slice:    &esast.SliceSpec{Max: 2},
	}); err == nil {
		t.Fatalf("expected collapse + slice error")
	}
	if err := tr.validateCollapseRequest(&esast.SearchRequest{
		Collapse:    &esast.CollapseSpec{Field: "category"},
		SearchAfter: []any{"x"},
	}); err == nil {
		t.Fatalf("expected collapse + search_after without matching sort error")
	}
	var matchingSortReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"collapse": {"field": "category_alias"},
		"sort": [{"category": "asc"}],
		"search_after": ["books"]
	}`), &matchingSortReq); err != nil {
		t.Fatalf("unmarshal sort req: %v", err)
	}
	if err := tr.validateCollapseRequest(&matchingSortReq); err != nil {
		t.Fatalf("expected matching alias collapse + search_after to pass, got %v", err)
	}
	if err := trOptsLim.validateCollapseRequest(&esast.SearchRequest{
		Collapse: &esast.CollapseSpec{
			Field: "category",
			InnerHits: esast.CollapseInnerHits{
				{ScriptFields: map[string]any{"a": 1, "b": 2}},
			},
		},
	}); err == nil {
		t.Fatalf("expected inner_hits script_fields limit error")
	}
	if err := tr.validateCollapseRequest(&esast.SearchRequest{
		Collapse: &esast.CollapseSpec{
			Field: "category",
			InnerHits: esast.CollapseInnerHits{
				{Collapse: &esast.CollapseSpec{Field: "count_long", InnerHits: esast.CollapseInnerHits{{Name: "lvl3"}}}},
			},
		},
	}); err == nil {
		t.Fatalf("expected nested inner_hits > level 2 error")
	}
	trNoDV := NewTranspiler(idx, TranspilerOptions{})
	if err := trNoDV.validateCollapseRequest(&esast.SearchRequest{
		Collapse: &esast.CollapseSpec{
			Field: "category",
			InnerHits: esast.CollapseInnerHits{
				{Collapse: &esast.CollapseSpec{Field: "no_dv"}},
			},
		},
	}); err != nil {
		t.Fatalf("unexpected direct return error: %v", err)
	}
	if trNoDV.searchErr == nil {
		t.Fatalf("expected searchErr on inner_hits collapse field with doc_values: false")
	}

	// 6. Numeric metric & terms include/exclude helpers
	for _, supported := range []string{"", "long", "unsigned_long", "double", "date", "date_nanos", "boolean", "histogram", "long_range"} {
		if isUnsupportedNumericMetricESType(supported) {
			t.Fatalf("expected %q to be supported for numeric metric", supported)
		}
	}
	for _, unsupported := range []string{"keyword", "text", "ip", "geo_point"} {
		if !isUnsupportedNumericMetricESType(unsupported) {
			t.Fatalf("expected %q to be unsupported for numeric metric", unsupported)
		}
	}
	if !isNumericMetricAggKind("percentiles") || !isNumericMetricAggKind("boxplot") || isNumericMetricAggKind("terms") {
		t.Fatalf("unexpected isNumericMetricAggKind classification")
	}

	if err := validateTermsIncludeExcludeForBinding("count_long", schema.FieldBinding{ESType: "long"}, nil); err != nil {
		t.Fatalf("unexpected nil termsSpec error: %v", err)
	}
	if err := validateTermsIncludeExcludeForBinding("count_long", schema.FieldBinding{}, &esast.TermsAggSpec{Include: "1.*"}); err != nil {
		t.Fatalf("unexpected empty ESType error: %v", err)
	}
	if err := validateTermsIncludeExcludeForBinding("category", schema.FieldBinding{ESType: "keyword"}, &esast.TermsAggSpec{Include: "a.*", Exclude: "b.*"}); err != nil {
		t.Fatalf("expected keyword regex include/exclude to succeed, got %v", err)
	}
	if err := validateTermsIncludeExcludeForBinding("count_long", schema.FieldBinding{ESType: "long"}, &esast.TermsAggSpec{Include: "1.*"}); err == nil {
		t.Fatalf("expected string include pattern on long field to fail")
	}
	if err := validateTermsIncludeExcludeForBinding("client_ip", schema.FieldBinding{ESType: "ip"}, &esast.TermsAggSpec{Exclude: "10\\..*"}); err == nil {
		t.Fatalf("expected string exclude pattern on ip field to fail")
	}
	if err := validateTermsIncludeExcludeForBinding("count_long", schema.FieldBinding{ESType: "long"}, &esast.TermsAggSpec{Include: []any{1, 2}}); err != nil {
		t.Fatalf("expected array include on long field to succeed, got %v", err)
	}
}

func TestRound60Coverage_TypedAggKeyPrefix(t *testing.T) {
	idx := buildRound60CovSchema(t, false)

	if got := TypedAggKeyPrefix(nil, idx); got != "unknown" {
		t.Fatalf("expected unknown for nil agg, got %q", got)
	}
	if got := TypedAggKeyPrefix(&esast.AggSpec{}, idx); got != "unknown" {
		t.Fatalf("expected unknown for empty agg, got %q", got)
	}

	cases := []struct {
		agg  *esast.AggSpec
		want string
	}{
		{&esast.AggSpec{SignificantTerms: &esast.TermsAggSpec{Field: "count_long", Script: "doc['x']"}}, "sigsterms"},
		{&esast.AggSpec{SignificantTerms: &esast.TermsAggSpec{Field: "count_long"}}, "siglterms"},
		{&esast.AggSpec{SignificantTerms: &esast.TermsAggSpec{Field: "category"}}, "sigsterms"},
		{&esast.AggSpec{SignificantText: &esast.TermsAggSpec{Field: "title"}}, "significant_text"},
		{&esast.AggSpec{Terms: &esast.TermsAggSpec{Script: "'v'"}}, "sterms"},
		{&esast.AggSpec{Terms: &esast.TermsAggSpec{Field: "count_long"}}, "lterms"},
		{&esast.AggSpec{Terms: &esast.TermsAggSpec{Field: "count_ulong"}}, "uterms"},
		{&esast.AggSpec{Terms: &esast.TermsAggSpec{Field: "score_double"}}, "dterms"},
		{&esast.AggSpec{Terms: &esast.TermsAggSpec{Field: "category"}}, "sterms"},
		{&esast.AggSpec{MultiTerms: &esast.MultiTermsAggSpec{}}, "multi_terms"},
		{&esast.AggSpec{RareTerms: &esast.RareTermsAggSpec{}}, "rare_terms"},
		{&esast.AggSpec{Histogram: &esast.HistogramAggSpec{}}, "histogram"},
		{&esast.AggSpec{DateHistogram: &esast.DateHistogramAggSpec{}}, "date_histogram"},
		{&esast.AggSpec{AutoDateHistogram: &esast.AutoDateHistogramAggSpec{}}, "auto_date_histogram"},
		{&esast.AggSpec{VariableWidthHistogram: &esast.VariableWidthHistogramAggSpec{}}, "variable_width_histogram"},
		{&esast.AggSpec{DateRange: &esast.RangeAggSpec{}}, "date_range"},
		{&esast.AggSpec{IPRange: &esast.RangeAggSpec{}}, "ip_range"},
		{&esast.AggSpec{Range: &esast.RangeAggSpec{}}, "range"},
		{&esast.AggSpec{GeoDistance: &esast.GeoDistanceAggSpec{}}, "geo_distance"},
		{&esast.AggSpec{GeohashGrid: &esast.GeoGridAggSpec{}}, "geohash_grid"},
		{&esast.AggSpec{GeotileGrid: &esast.GeoGridAggSpec{}}, "geotile_grid"},
		{&esast.AggSpec{Filter: &esast.Query{}}, "filter"},
		{&esast.AggSpec{Filters: &esast.FiltersAggSpec{}}, "filters"},
		{&esast.AggSpec{Global: map[string]any{}}, "global"},
		{&esast.AggSpec{Missing: &esast.ExistsQuery{Field: "category"}}, "missing"},
		{&esast.AggSpec{Nested: &esast.NestedAggSpec{Path: "items"}}, "nested"},
		{&esast.AggSpec{ReverseNested: map[string]any{}}, "reverse_nested"},
		{&esast.AggSpec{Sampler: &esast.SamplerAggSpec{}}, "sampler"},
		{&esast.AggSpec{DiversifiedSampler: &esast.SamplerAggSpec{}}, "diversified_sampler"},
		{&esast.AggSpec{RandomSampler: &esast.RandomSamplerAggSpec{}}, "random_sampler"},
		{&esast.AggSpec{CategorizeText: &esast.CategorizeTextAggSpec{}}, "categorize_text"},
		{&esast.AggSpec{FrequentItemSets: &esast.FrequentItemSetsAggSpec{}}, "frequent_item_sets"},
		{&esast.AggSpec{AdjacencyMatrix: &esast.AdjacencyMatrixAggSpec{}}, "adjacency_matrix"},
		{&esast.AggSpec{Composite: &esast.CompositeAggSpec{}}, "composite"},
		{&esast.AggSpec{Avg: &esast.MetricAggSpec{}}, "avg"},
		{&esast.AggSpec{WeightedAvg: &esast.WeightedAvgAggSpec{}}, "weighted_avg"},
		{&esast.AggSpec{Sum: &esast.MetricAggSpec{}}, "sum"},
		{&esast.AggSpec{Min: &esast.MetricAggSpec{}}, "min"},
		{&esast.AggSpec{Max: &esast.MetricAggSpec{}}, "max"},
		{&esast.AggSpec{Cardinality: &esast.MetricAggSpec{}}, "cardinality"},
		{&esast.AggSpec{ValueCount: &esast.MetricAggSpec{}}, "value_count"},
		{&esast.AggSpec{Stats: &esast.MetricAggSpec{}}, "stats"},
		{&esast.AggSpec{ExtendedStats: &esast.MetricAggSpec{}}, "extended_stats"},
		{&esast.AggSpec{MatrixStats: &esast.MatrixStatsAggSpec{}}, "matrix_stats"},
		{&esast.AggSpec{StringStats: &esast.MetricAggSpec{}}, "string_stats"},
		{&esast.AggSpec{Boxplot: &esast.MetricAggSpec{}}, "boxplot"},
		{&esast.AggSpec{MedianAbsoluteDeviation: &esast.MetricAggSpec{}}, "median_absolute_deviation"},
		{&esast.AggSpec{Percentiles: &esast.PercentilesAggSpec{}}, "tdigest_percentiles"},
		{&esast.AggSpec{Percentiles: &esast.PercentilesAggSpec{HDR: &esast.HDRConfig{}}}, "hdr_percentiles"},
		{&esast.AggSpec{PercentileRanks: &esast.PercentileRanksAggSpec{}}, "tdigest_percentile_ranks"},
		{&esast.AggSpec{PercentileRanks: &esast.PercentileRanksAggSpec{HDR: &esast.HDRConfig{}}}, "hdr_percentile_ranks"},
		{&esast.AggSpec{TopHits: &esast.TopHitsAggSpec{}}, "top_hits"},
		{&esast.AggSpec{TopMetrics: &esast.TopMetricsAggSpec{}}, "top_metrics"},
		{&esast.AggSpec{ScriptedMetric: &esast.ScriptedMetricAggSpec{}}, "scripted_metric"},
		{&esast.AggSpec{Rate: &esast.RateAggSpec{}}, "rate"},
		{&esast.AggSpec{TTest: &esast.TTestAggSpec{}}, "t_test"},
		{&esast.AggSpec{GeoBounds: &esast.GeoBoundsAggSpec{}}, "geo_bounds"},
		{&esast.AggSpec{GeoCentroid: &esast.MetricAggSpec{}}, "geo_centroid"},
		{&esast.AggSpec{CartesianBounds: &esast.GeoBoundsAggSpec{}}, "cartesian_bounds"},
		{&esast.AggSpec{CartesianCentroid: &esast.MetricAggSpec{}}, "cartesian_centroid"},
		{&esast.AggSpec{GeoLine: &esast.GeoLineAggSpec{}}, "geo_line"},
		{&esast.AggSpec{MinBucket: &esast.PipelineAggSpec{}}, "bucket_metric_value"},
		{&esast.AggSpec{MaxBucket: &esast.PipelineAggSpec{}}, "bucket_metric_value"},
		{&esast.AggSpec{AvgBucket: &esast.PipelineAggSpec{}}, "simple_value"},
		{&esast.AggSpec{SumBucket: &esast.PipelineAggSpec{}}, "simple_value"},
		{&esast.AggSpec{Derivative: &esast.PipelineAggSpec{}}, "simple_value"},
		{&esast.AggSpec{CumulativeSum: &esast.PipelineAggSpec{}}, "simple_value"},
		{&esast.AggSpec{MovingAvg: &esast.MovingAvgAggSpec{}}, "simple_value"},
		{&esast.AggSpec{MovingFn: &esast.MovingAvgAggSpec{}}, "simple_value"},
		{&esast.AggSpec{BucketScript: &esast.BucketSelectorAggSpec{}}, "simple_value"},
		{&esast.AggSpec{SerialDiff: &esast.SerialDiffAggSpec{}}, "simple_value"},
		{&esast.AggSpec{Normalize: &esast.NormalizeAggSpec{}}, "simple_value"},
		{&esast.AggSpec{CumulativeCardinality: &esast.PipelineAggSpec{}}, "simple_value"},
		{&esast.AggSpec{StatsBucket: &esast.PipelineAggSpec{}}, "stats"},
		{&esast.AggSpec{ExtendedStatsBucket: &esast.PipelineAggSpec{}}, "extended_stats"},
		{&esast.AggSpec{PercentilesBucket: &esast.PercentilesBucketAggSpec{}}, "tdigest_percentiles"},
		{&esast.AggSpec{MovingPercentiles: &esast.MovingPercentilesAggSpec{}}, "tdigest_percentiles"},
		{&esast.AggSpec{BucketSort: &esast.BucketSortAggSpec{}}, "bucket_sort"},
		{&esast.AggSpec{BucketSelector: &esast.BucketSelectorAggSpec{}}, "bucket_selector"},
	}

	for i, tc := range cases {
		if got := TypedAggKeyPrefix(tc.agg, idx); got != tc.want {
			t.Fatalf("case %d: got %q, want %q", i, got, tc.want)
		}
	}
	// Also check nil idxSchema branch in resolveFieldESType
	if got := TypedAggKeyPrefix(&esast.AggSpec{Terms: &esast.TermsAggSpec{Field: "count_long"}}, nil); got != "sterms" {
		t.Fatalf("expected sterms with nil schema, got %q", got)
	}
}

func TestRound60Coverage_PartitionHashingAndCoercion(t *testing.T) {
	// MurmurHash3X86_32 tail lengths 0, 1, 2, 3, 4, 5, 6, 7
	for _, s := range []string{"", "a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg", "abcdefgh"} {
		_ = MurmurHash3X86_32([]byte(s), 0)
	}
	if javaFloorMod32(-7, 0) != 0 || javaFloorMod32(-7, 5) != 3 || javaFloorMod32(7, 5) != 2 {
		t.Fatalf("unexpected javaFloorMod32 results")
	}

	longInputs := []any{
		int64(42),
		int(-10),
		int32(7),
		uint64(math.MaxUint64),
		float64(19.0),
		true,
		false,
		json.Number("123"),
		json.Number("18446744073709551615"),
		json.Number("45.5"),
		"true",
		"FALSE",
		"-999",
		"18446744073709551614",
		"2025-01-02T03:04:05Z",
	}
	for _, in := range longInputs {
		if _, ok := coercePartitionLong(in); !ok {
			t.Fatalf("expected coercePartitionLong(%T=%v) to succeed", in, in)
		}
	}
	for _, bad := range []any{math.NaN(), math.Inf(1), json.Number("bad"), "not_a_date_or_num", struct{}{}} {
		if _, ok := coercePartitionLong(bad); ok {
			t.Fatalf("expected coercePartitionLong(%v) to fail", bad)
		}
	}

	doubleInputs := []any{
		float64(3.14),
		float32(2.5),
		int(8),
		int64(-12),
		uint64(100),
		json.Number("6.25"),
		" -1.75 ",
	}
	for _, in := range doubleInputs {
		if _, ok := coercePartitionDouble(in); !ok {
			t.Fatalf("expected coercePartitionDouble(%T=%v) to succeed", in, in)
		}
	}
	for _, bad := range []any{math.NaN(), float32(math.NaN()), json.Number("bad"), "nope", struct{}{}} {
		if _, ok := coercePartitionDouble(bad); ok {
			t.Fatalf("expected coercePartitionDouble(%v) to fail", bad)
		}
	}

	// Invalid partition boundaries
	if ESTermsPartitionMatch("x", "keyword", 0, 0) ||
		ESTermsPartitionMatch("x", "keyword", -1, 4) ||
		ESTermsPartitionMatch("x", "keyword", 4, 4) ||
		ESTermsPartitionMatch(nil, "keyword", 0, 4) {
		t.Fatalf("expected invalid partition arguments to return false")
	}

	// Across numPartitions=3, exactly one partition [0..2] must match for each value/type!
	type sample struct {
		val   any
		ftype string
	}
	for _, sm := range []sample{
		{int64(1001), "long"},
		{true, "boolean"},
		{"2025-02-01T00:00:00Z", "date"},
		{3.14159, "double"},
		{float32(1.5), "float"},
		{"192.168.1.10", "ip"},
		{"2001:db8::1", "ip"},
		{"not-an-ip", "ip"},
		{"alpha_term", "keyword"},
	} {
		matches := 0
		for p := 0; p < 3; p++ {
			if ESTermsPartitionMatch(sm.val, sm.ftype, p, 3) {
				matches++
			}
		}
		if matches != 1 {
			t.Fatalf("expected exactly 1 matching partition for (%v, %s), got %d", sm.val, sm.ftype, matches)
		}
	}
}

func TestRound60Coverage_FormatESDateWithNamedOrJavaPattern(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+30*60)
	est := time.FixedZone("EST", -5*3600)
	anonUTC := time.FixedZone("", 0)

	// Negative epochNanos and negative epochMillis
	if got := FormatESDateWithNamedOrJavaPattern(0, -1_500_000_001, "strict_date_optional_time_nanos", nil); !strings.HasPrefix(got, "1969-12-31T23:59:58.") {
		t.Fatalf("unexpected negative epochNanos formatted date: %s", got)
	}
	if got := FormatESDateWithNamedOrJavaPattern(-1500, 0, "", nil); got != "1969-12-31T23:59:58.500Z" {
		t.Fatalf("unexpected negative epochMillis formatted date: %s", got)
	}
	// Multi-format with ||
	if got := FormatESDateWithNamedOrJavaPattern(1704164645123, 0, "basic_date||epoch_millis", time.UTC); got != "20240102" {
		t.Fatalf("unexpected || format output: %s", got)
	}

	namedFormats := []string{
		"epoch_millis",
		"epoch_second",
		"iso8601",
		"strict_date_optional_time",
		"strict_date_optional_time_nanos",
		"date_time_no_millis",
		"basic_date",
		"basic_date_time",
		"basic_date_time_no_millis",
		"basic_time",
		"basic_time_no_millis",
		"date",
		"year_month",
		"year",
		"date_hour",
		"date_hour_minute",
		"date_hour_minute_second",
		"date_hour_minute_second_millis",
		"time",
		"time_no_millis",
		"hour_minute_second",
		"hour_minute_second_millis",
		"hour_minute",
		"hour",
		"ordinal_date",
		"ordinal_date_time",
		"ordinal_date_time_no_millis",
		"basic_ordinal_date",
		"basic_ordinal_date_time",
		"basic_ordinal_date_time_no_millis",
		"rfc1123",
	}
	for _, nf := range namedFormats {
		out := FormatESDateWithNamedOrJavaPattern(1704164645120, 1704164645123400000, nf, ist)
		if out == "" {
			t.Fatalf("named format %q returned empty string", nf)
		}
	}

	// Java DateTimeFormatter custom tokens across UTC, positive offset with minutes (IST), negative hour offset (EST), midnight & afternoon
	pattern1 := "'' 'at''time' y yy yyyy M MM MMM MMMM d dd D DDD H HH h hh K KK k kk m mm s ss S SSS SSSSSSSSSSS n nnnnnnnnn E EEEE a X XX XXX x xx xxx Z ZZZZ z V [lit]"
	if outUTC := FormatESDateWithNamedOrJavaPattern(0, 0, pattern1, anonUTC); !strings.Contains(outUTC, "UTC") || !strings.Contains(outUTC, "GMT") {
		t.Fatalf("unexpected custom pattern at UTC midnight: %s", outUTC)
	}
	if outIST := FormatESDateWithNamedOrJavaPattern(1704200645123, 0, pattern1, ist); !strings.Contains(outIST, "+0530") || !strings.Contains(outIST, "GMT+05:30") {
		t.Fatalf("unexpected custom pattern in IST: %s", outIST)
	}
	if outEST := FormatESDateWithNamedOrJavaPattern(1704200645123, 0, "X XX XXX x Z ZZZZ z", est); !strings.Contains(outEST, "-05") || !strings.Contains(outEST, "GMT-05:00") {
		t.Fatalf("unexpected custom pattern in EST: %s", outEST)
	}
}

func TestRound60Coverage_PercentilesAndHDR(t *testing.T) {
	badLow := -1
	badHigh := 6
	sig2 := 2

	// Empty values in ComputeESPercentiles
	emptyRes, err := ComputeESPercentiles([]float64{math.NaN(), math.Inf(1)}, nil, nil)
	if err != nil || emptyRes["50.0"] != nil {
		t.Fatalf("expected nil map entries on empty values, got %v, err=%v", emptyRes, err)
	}
	if _, err := ComputeESPercentiles(nil, []float64{50}, &esast.HDRConfig{NumberOfSignificantValueDigits: &badLow}); err == nil {
		t.Fatalf("expected invalid HDR sigDigits error on empty values")
	}
	if _, err := ComputeESPercentiles([]float64{-1.0, 2.0}, []float64{50}, &esast.HDRConfig{NumberOfSignificantValueDigits: &sig2}); err == nil {
		t.Fatalf("expected negative value error in HDR mode")
	}
	if _, err := newHDRDoubleHistogram(badHigh, []float64{1.0}); err == nil {
		t.Fatalf("expected newHDRDoubleHistogram sigDigits > 5 error")
	}

	// Empty HDR histogram methods directly
	emptyHist, err := newHDRDoubleHistogram(0, nil)
	if err != nil {
		t.Fatalf("unexpected empty hist error: %v", err)
	}
	if !math.IsNaN(emptyHist.valueAtPercentile(50)) || !math.IsNaN(emptyHist.percentileAtOrBelow(10)) {
		t.Fatalf("expected NaN on empty HDR histogram")
	}

	// HDR mode with wide dynamic range + 0.0 + NaN
	hdrRes, err := ComputeESPercentiles(
		[]float64{0.0, 1e-9, 1.5, 250.0, 1e20, math.NaN()},
		[]float64{-5, 0, 25, 50, 99, 105},
		&esast.HDRConfig{},
	)
	if err != nil || hdrRes["0.0"] == nil || hdrRes["50.0"] == nil {
		t.Fatalf("unexpected HDR percentiles result: %v, err=%v", hdrRes, err)
	}

	// TDigest mode ComputeESPercentiles
	tdRes, err := ComputeESPercentiles(
		[]float64{10, 20, 30, 40, 50},
		[]float64{0, 1, 50, 99, 100},
		nil,
	)
	if err != nil || tdRes["50.0"] != 30.0 || tdRes["0.0"] != 10.0 || tdRes["100.0"] != 50.0 {
		t.Fatalf("unexpected TDigest percentiles: %v, err=%v", tdRes, err)
	}

	// ComputeESPercentileRanks: empty values (keyed true & false + bad HDR)
	if _, err := ComputeESPercentileRanks(nil, []float64{10}, &esast.HDRConfig{NumberOfSignificantValueDigits: &badHigh}, true); err == nil {
		t.Fatalf("expected invalid HDR sigDigits error on empty ranks")
	}
	rkEmptyKeyed, err := ComputeESPercentileRanks(nil, []float64{10, 20.5}, nil, true)
	if err != nil || rkEmptyKeyed.(map[string]any)["10.0"] != nil {
		t.Fatalf("unexpected empty keyed percentile_ranks: %v, err=%v", rkEmptyKeyed, err)
	}
	rkEmptyArr, err := ComputeESPercentileRanks(nil, []float64{10}, nil, false)
	if err != nil || len(rkEmptyArr.([]map[string]any)) != 1 {
		t.Fatalf("unexpected empty unkeyed percentile_ranks: %v, err=%v", rkEmptyArr, err)
	}

	// ComputeESPercentileRanks: HDR mode (negative error + valid keyed/unkeyed)
	if _, err := ComputeESPercentileRanks([]float64{-5, 10}, []float64{5}, &esast.HDRConfig{}, true); err == nil {
		t.Fatalf("expected HDR negative value error in ComputeESPercentileRanks")
	}
	rkHDR, err := ComputeESPercentileRanks(
		[]float64{0.0, 5.0, 10.0, 100.0, math.NaN()},
		[]float64{-1.0, 0.0, 7.5, 50.0, 1e300},
		&esast.HDRConfig{NumberOfSignificantValueDigits: &sig2},
		true,
	)
	if err != nil || rkHDR.(map[string]any)["-1.0"] != 0.0 || rkHDR.(map[string]any)["50.0"] != 75.0 {
		t.Fatalf("unexpected HDR percentile_ranks: %v, err=%v", rkHDR, err)
	}

	// ComputeESPercentileRanks: TDigest mode with ties (keyed=false)
	rkTD, err := ComputeESPercentileRanks(
		[]float64{10, 10, 20, 20, 30},
		[]float64{5, 10, 15, 20, 25, 30, 35},
		nil,
		false,
	)
	if err != nil {
		t.Fatalf("TDigest percentile_ranks failed: %v", err)
	}
	rkSlice := rkTD.([]map[string]any)
	if len(rkSlice) != 7 || rkSlice[0]["value"] != 0.0 || rkSlice[6]["value"] != 100.0 {
		t.Fatalf("unexpected TDigest percentile_ranks slice: %v", rkSlice)
	}
}

func TestRound60Coverage_AnalyzersAndMetadataExists(t *testing.T) {
	if TokenizeByAnalyzer("", "keyword") != nil {
		t.Fatalf("expected nil for empty keyword")
	}
	if kw := TokenizeByAnalyzer("Exact Value", "keyword"); len(kw) != 1 || kw[0] != "Exact Value" {
		t.Fatalf("unexpected keyword tokens: %v", kw)
	}
	if TokenizeByAnalyzer("   ", "whitespace") != nil {
		t.Fatalf("expected nil for blank whitespace")
	}
	if ws := TokenizeByAnalyzer("Foo  Bar_1", "whitespace"); len(ws) != 2 || ws[0] != "Foo" {
		t.Fatalf("unexpected whitespace tokens: %v", ws)
	}
	if smp := TokenizeByAnalyzer("Hello123World!", "simple"); len(smp) != 2 || smp[0] != "hello" || smp[1] != "world" {
		t.Fatalf("unexpected simple tokens: %v", smp)
	}
	stopToks := TokenizeByAnalyzerWithPositions("The quick and brown", "stop")
	if len(stopToks) != 2 || stopToks[0].Term != "quick" || stopToks[0].Position != 1 || stopToks[1].Position != 3 {
		t.Fatalf("expected stopword position increments [1, 3], got %+v", stopToks)
	}
	if TokenizeByAnalyzer("---", "standard") != nil {
		t.Fatalf("expected nil for punctuation-only standard analyzer")
	}
	stdToks := TokenizeByAnalyzer("Value1_Foo don't it’s", "standard")
	if len(stdToks) != 3 || stdToks[0] != "value1_foo" || stdToks[1] != "don't" {
		t.Fatalf("unexpected standard UAX29 tokens: %v", stdToks)
	}
	if !hasInternalUnderscoreToken(stdToks) || hasInternalUnderscoreToken([]string{"plain"}) {
		t.Fatalf("unexpected hasInternalUnderscoreToken result")
	}

	if got := effectiveFieldSearchAnalyzer(schema.FieldBinding{Analyzer: "Whitespace"}); got != "whitespace" {
		t.Fatalf("expected analyzer fallback whitespace, got %q", got)
	}
	if got := effectiveFieldSearchAnalyzer(schema.FieldBinding{Analyzer: "standard", SearchAnalyzer: "Keyword"}); got != "keyword" {
		t.Fatalf("expected search_analyzer keyword, got %q", got)
	}

	reWS := buildAnalyzedTextWildcardRegex(`a\*b?c*`, "whitespace", true)
	reStd := buildAnalyzedTextWildcardRegex(`a\*b?c*`, "standard", false)
	if !strings.HasPrefix(reWS, "(?i)") || !strings.Contains(reStd, "[[:alnum:]_]") {
		t.Fatalf("unexpected wildcard regexes: ws=%q std=%q", reWS, reStd)
	}
	if !strings.Contains(buildAnalyzedTokenRegex("foo", true), "[[:space:]]") ||
		!strings.Contains(buildAnalyzedTokenRegex("foo", false), "[^[:alnum:]_]") {
		t.Fatalf("unexpected buildAnalyzedTokenRegex output")
	}

	// compileMetadataExistsPredicate with _source enabled vs _source disabled
	trEnabled := NewTranspiler(buildRound60CovSchema(t, false), TranspilerOptions{})
	trEnabled.inLenientQuery = true
	if sql, ok := trEnabled.compileMetadataExistsPredicate("_source"); !ok || sql != "FALSE" || trEnabled.searchErr != nil {
		t.Fatalf("unexpected lenient _source exists: sql=%q ok=%v err=%v", sql, ok, trEnabled.searchErr)
	}
	trEnabled.inLenientQuery = false
	if sql, ok := trEnabled.compileMetadataExistsPredicate("_source"); !ok || sql != "FALSE" || trEnabled.searchErr == nil {
		t.Fatalf("expected strict _source exists to set searchErr")
	}
	for _, meta := range []string{"_id", "_routing", "_ignored", "_field_names"} {
		if sql, ok := trEnabled.compileMetadataExistsPredicate(meta); !ok || sql == "" {
			t.Fatalf("expected metadata predicate for %s", meta)
		}
	}
	if _, ok := trEnabled.compileMetadataExistsPredicate("regular_field"); ok {
		t.Fatalf("expected regular_field not to match metadata exists")
	}

	trDisabled := NewTranspiler(buildRound60CovSchema(t, true), TranspilerOptions{})
	fnSQL, ok := trDisabled.compileMetadataExistsPredicate("_field_names")
	if !ok || !strings.Contains(fnSQL, "_all_text") || !strings.Contains(fnSQL, "array_size") {
		t.Fatalf("expected synthetic _field_names SQL when _source disabled, got %q", fnSQL)
	}
}

func TestRound60Coverage_IntervalsEvaluationAndScriptDetection(t *testing.T) {
	sc := &esast.ScriptSpec{Source: "interval.gaps == 0"}
	scriptFilter := &esast.IntervalsFilter{Script: sc}
	leafWithScript := &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "fox", Filter: scriptFilter}}
	leafNoScript := &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "fox"}}

	if RuleHasIntervalsScript(nil) || RuleHasIntervalsScript(leafNoScript) {
		t.Fatalf("expected false for nil/scriptless rule")
	}
	for _, r := range []*esast.IntervalsRule{
		leafWithScript,
		{Prefix: &esast.IntervalsPrefix{Prefix: "qu", Filter: &esast.IntervalsFilter{After: leafWithScript}}},
		{Wildcard: &esast.IntervalsWildcard{Pattern: "br*", Filter: scriptFilter}},
		{Fuzzy: &esast.IntervalsFuzzy{Term: "fux", Filter: scriptFilter}},
		{AllOf: &esast.IntervalsAllOf{Intervals: []esast.IntervalsRule{*leafWithScript}}},
		{AllOf: &esast.IntervalsAllOf{Intervals: []esast.IntervalsRule{*leafNoScript}, Filter: scriptFilter}},
		{AnyOf: &esast.IntervalsAnyOf{Intervals: []esast.IntervalsRule{*leafWithScript}}},
		{AnyOf: &esast.IntervalsAnyOf{Intervals: []esast.IntervalsRule{*leafNoScript}, Filter: scriptFilter}},
	} {
		if !RuleHasIntervalsScript(r) {
			t.Fatalf("expected RuleHasIntervalsScript=true for %+v", r)
		}
	}

	qScript := esast.Query{Intervals: map[string]esast.IntervalsRule{"title": *leafWithScript}}
	qPlain := esast.Query{Intervals: map[string]esast.IntervalsRule{"title": *leafNoScript}}
	if QueryHasIntervalsScript(nil) || QueryHasIntervalsScript(&qPlain) {
		t.Fatalf("expected false for nil/plain query")
	}
	for _, q := range []*esast.Query{
		&qScript,
		{Bool: &esast.BoolQuery{Must: esast.QuerySlice{qScript}}},
		{Bool: &esast.BoolQuery{Filter: esast.QuerySlice{qScript}}},
		{Bool: &esast.BoolQuery{Should: esast.QuerySlice{qScript}}},
		{Bool: &esast.BoolQuery{MustNot: esast.QuerySlice{qScript}}},
		{ConstantScore: &esast.ConstantScoreQuery{Filter: qScript}},
		{DisMax: &esast.DisMaxQuery{Queries: []esast.Query{qPlain, qScript}}},
		{Boosting: &esast.BoostingQuery{Positive: qPlain, Negative: qScript}},
		{FunctionScore: &esast.FunctionScoreQuery{Query: &qScript}},
		{Nested: &esast.NestedQuery{Path: "items", Query: qScript}},
	} {
		if !QueryHasIntervalsScript(q) {
			t.Fatalf("expected QueryHasIntervalsScript=true")
		}
	}

	// minimizeIntervalsSpans & combineSubIntervals & wildcardPatternRegex
	minSpans := minimizeIntervalsSpans([]IntervalsSpan{
		{Start: 0, End: 5, Gaps: 2},
		{Start: 1, End: 3, Gaps: 1},
		{Start: 1, End: 3, Gaps: 0},
	})
	if len(minSpans) != 1 || minSpans[0].Start != 1 || minSpans[0].End != 3 || minSpans[0].Gaps != 0 {
		t.Fatalf("unexpected minimized spans: %+v", minSpans)
	}
	if combineSubIntervals(nil, true, nil) != nil {
		t.Fatalf("expected nil for empty subLists")
	}
	maxGaps1 := 1
	singleFiltered := combineSubIntervals([][]IntervalsSpan{{{Start: 0, End: 4, Gaps: 3}, {Start: 1, End: 2, Gaps: 0}}}, true, &maxGaps1)
	if len(singleFiltered) != 1 || singleFiltered[0].Start != 1 {
		t.Fatalf("unexpected single subList maxGaps result: %+v", singleFiltered)
	}
	reWild := wildcardPatternRegex(`a\*b?c*`, true)
	if reWild == nil || !reWild.MatchString("A*BXCZZ") || reWild.MatchString("AXBXCZZ") {
		t.Fatalf("unexpected wildcardPatternRegex match behavior")
	}

	// EvaluateIntervalsRule across all rule types, analyzers, and 8 relational filters + script
	doc := "the quick brown fox jumps over the lazy dog"
	if spans, ok, err := EvaluateIntervalsRule(nil, doc, "standard", nil); err != nil || ok || spans != nil {
		t.Fatalf("expected nil rule to return empty")
	}
	if spans, ok, err := EvaluateIntervalsRule(leafNoScript, "   ", "whitespace", nil); err != nil || ok || spans != nil {
		t.Fatalf("expected empty doc to return empty")
	}
	if _, ok, err := EvaluateIntervalsRule(&esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "---"}}, doc, "standard", nil); err != nil || ok {
		t.Fatalf("expected empty query tokens not to match")
	}
	if _, ok, err := EvaluateIntervalsRule(&esast.IntervalsRule{AllOf: &esast.IntervalsAllOf{}}, doc, "standard", nil); err != nil || ok {
		t.Fatalf("expected empty AllOf not to match")
	}

	falseVal := false
	maxGaps3 := 3
	complexRule := &esast.IntervalsRule{
		AllOf: &esast.IntervalsAllOf{
			Ordered: false,
			MaxGaps: &maxGaps3,
			Intervals: []esast.IntervalsRule{
				{Fuzzy: &esast.IntervalsFuzzy{Term: "fux", Fuzziness: "AUTO", Transpositions: &falseVal}},
				{AnyOf: &esast.IntervalsAnyOf{
					Intervals: []esast.IntervalsRule{
						{Prefix: &esast.IntervalsPrefix{Prefix: "QU"}},
						{Wildcard: &esast.IntervalsWildcard{Pattern: "br*wn"}},
					},
				}},
			},
			Filter: &esast.IntervalsFilter{
				Containing:     &esast.IntervalsRule{Fuzzy: &esast.IntervalsFuzzy{Term: "brown", Fuzziness: 0}},
				NotContaining:  &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "lazy"}},
				ContainedBy:    &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "the fox", Ordered: true}},
				NotContainedBy: &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "lazy dog", Ordered: true}},
				Overlapping:    &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "brown jumps", Ordered: true}},
				NotOverlapping: &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "lazy dog", Ordered: true}},
				After:          &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "the"}},
				Before:         &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "over"}},
				Script:         sc,
			},
		},
	}

	spans, matched, err := EvaluateIntervalsRule(complexRule, doc, "standard", func(_ *esast.ScriptSpec, sp IntervalsSpan) (bool, error) {
		return sp.End >= sp.Start, nil
	})
	if err != nil || !matched || len(spans) == 0 {
		t.Fatalf("expected complex intervals rule to match, spans=%+v matched=%v err=%v", spans, matched, err)
	}

	// Script returning false filters out all spans
	_, matchedFalse, err := EvaluateIntervalsRule(complexRule, doc, "standard", func(_ *esast.ScriptSpec, _ IntervalsSpan) (bool, error) {
		return false, nil
	})
	if err != nil || matchedFalse {
		t.Fatalf("expected script=false to filter all spans")
	}

	// Script returning error propagates cleanly
	_, _, errBoom := EvaluateIntervalsRule(complexRule, doc, "standard", func(_ *esast.ScriptSpec, _ IntervalsSpan) (bool, error) {
		return false, errors.New("script boom")
	})
	if errBoom == nil {
		t.Fatalf("expected script error propagation")
	}
}

func TestRound60Coverage_LuceneAutomatonAndTranspilerHelpers(t *testing.T) {
	// 1. CompileLuceneRegexpToSQLPredicates & ScalarSQL (both scalar & tokenized text)
	validRegexps := []struct {
		pat   string
		flags string
		ci    bool
	}{
		{`ab{3}c{2,5}d{1,}`, "ALL", false},
		{`(?i)"foo+bar"|(?:ab|cd)+`, "ALL", false},
		{`~foo&bar`, "ALL", false},
		{`~~abc`, "ALL", false},
		{`#`, "ALL", false},
		{`~#`, "ALL", false},
		{`~@`, "ALL", false},
		{`@`, "ALL", true},
		{`#^$`, "NONE", false},
		{`<01-99>|<5-250>|<x>`, "INTERVAL", false},
		{`[a-z0-9][:digit:]`, "ALL", false},
		{`[^[:space:]\d\-\]\n\r\t\x]`, "ALL", false},
		{`\d\s\w\n\r\t\.`, "ALL", false},
	}
	for _, vr := range validRegexps {
		comp, err := CompileLuceneRegexpToSQLPredicates(vr.pat, vr.flags, vr.ci)
		if err != nil {
			t.Fatalf("CompileLuceneRegexpToSQLPredicates(%q, %q) failed: %v", vr.pat, vr.flags, err)
		}
		w1, s1, _ := comp.ScalarSQL("`col`", false, false)
		w2, s2, _ := comp.ScalarSQL("`col`", false, true)
		if w1 == "" || s1 == "" || w2 == "" || s2 == "" {
			t.Fatalf("expected non-empty SQL from ScalarSQL for %q", vr.pat)
		}
	}

	invalidRegexps := []struct {
		pat   string
		flags string
	}{
		{`a{`, "ALL"},
		{`a{}`, "ALL"},
		{`a{x}`, "ALL"},
		{`a{x,2}`, "ALL"},
		{`a{2,x}`, "ALL"},
		{`a{5,2}`, "ALL"},
		{`*abc`, "ALL"},
		{`"unclosed`, "ALL"},
		{`(abc`, "ALL"},
		{`abc\`, "ALL"},
		{`[unclosed`, "ALL"},
		{`[a\`, "ALL"},
		{`<99-10>`, "INTERVAL"},
		{`abc`, "BOGUS_FLAG"},
	}
	for _, ir := range invalidRegexps {
		if _, err := CompileLuceneRegexpToSQLPredicates(ir.pat, ir.flags, false); err == nil {
			t.Fatalf("expected error for invalid Lucene regexp (%q, %q)", ir.pat, ir.flags)
		}
	}

	// 2. hasUnclosedTopLevelBetween
	if !hasUnclosedTopLevelBetween("`x` BETWEEN 1") {
		t.Fatalf("expected top-level BETWEEN to be detected")
	}
	if hasUnclosedTopLevelBetween("(`x` BETWEEN 1 AND 2) AND 'BETWEEN\\'s ''quoted''' = `BETWEEN`") {
		t.Fatalf("expected parenthesized/quoted/backticked BETWEEN not to trigger unclosed top-level")
	}

	// 3. parseUnsignedLongRawBound & normalizeUnsignedLongRangeBounds
	for _, bnd := range []any{
		uint64(10), int(5), int(-3), int64(9), int64(-2),
		float64(4.0), float64(4.5), float64(-1.2), math.Inf(1),
		json.Number("18446744073709551615"), json.Number("-5"), json.Number("12.7"), json.Number("1e30"),
		"42", "-7", "9.5", "1e30",
	} {
		if _, _, _, _, _, ok := parseUnsignedLongRawBound(bnd); !ok {
			t.Fatalf("expected parseUnsignedLongRawBound(%T=%v) to succeed", bnd, bnd)
		}
	}
	for _, bad := range []any{math.NaN(), json.Number("bad"), "", "bad", struct{}{}} {
		if _, _, _, _, _, ok := parseUnsignedLongRawBound(bad); ok {
			t.Fatalf("expected parseUnsignedLongRawBound(%v) to fail", bad)
		}
	}
	if _, _, _, _, ok := normalizeUnsignedLongRangeBounds(1.5, -2, 100.7, uint64(90)); !ok {
		t.Fatalf("expected normalizeUnsignedLongRangeBounds valid bounds to succeed")
	}
	if _, _, _, _, ok := normalizeUnsignedLongRangeBounds(uint64(math.MaxUint64), nil, nil, nil); ok {
		t.Fatalf("expected gt=MaxUint64 to be unsatisfiable")
	}
	if _, _, _, _, ok := normalizeUnsignedLongRangeBounds(nil, nil, uint64(0), nil); ok {
		t.Fatalf("expected lt=0 to be unsatisfiable")
	}

	// 4. parseSafeThresholdExpr
	idx := buildRound60CovSchema(t, false)
	tr := NewTranspiler(idx, TranspilerOptions{})
	thresholdExprs := []string{
		"(int) (Math.min(params.num_terms, Math.max(1, doc['count_long'].value + 2 * 3 - 1)))",
		"-Math.floor(Math.ceil(Math.abs(Math.round(Math.sqrt(Math.log(Math.log10(Math.exp(1.0))))))))",
		"+Math.pow(doc['tags.name'].size(), doc['category'].length)",
	}
	for _, expr := range thresholdExprs {
		sqlExpr, ok := tr.parseSafeThresholdExpr(expr, map[string]any{"k": 2}, 5, nil, 0)
		if !ok || sqlExpr == "" {
			t.Fatalf("expected parseSafeThresholdExpr(%q) to succeed, got ok=%v sql=%q", expr, ok, sqlExpr)
		}
	}
	if _, ok := tr.parseSafeThresholdExpr("1", nil, 1, nil, 17); ok {
		t.Fatalf("expected depth > 16 to return false")
	}

	// 5. End-to-end BuildSearchPlan hitting distance_feature, query_string wildcards/regex/ranges/booleans, and aggregations
	queries := []string{
		`{
			"query": {
				"bool": {
					"must": [
						{"distance_feature": {"field": "location", "pivot": "10km", "origin": [-71.3, 41.15], "boost": 2.0}},
						{"distance_feature": {"field": "created_at", "pivot": "7d", "origin": "2025-01-01T00:00:00Z"}},
						{"distance_feature": {"field": "created_nanos", "pivot": "1h", "origin": 1704067200000}},
						{"query_string": {
							"query": "_exists_:title AND count_*:[1 TO 10] AND count_*:/.+/ AND active:true AND title:+(foo bar) AND category:-(baz)",
							"time_zone": "+02:00",
							"quote_field_suffix": ".keyword",
							"phrase_slop": 2
						}}
					]
				}
			},
			"aggs": {
				"by_cat": {
					"terms": {"field": "category", "size": 5},
					"aggs": {
						"p_hdr": {"percentiles": {"field": "score_double", "hdr": {"number_of_significant_value_digits": 3}}},
						"pr_td": {"percentile_ranks": {"field": "score_double", "values": [10, 50]}}
					}
				}
			}
		}`,
	}
	for _, qJSON := range queries {
		var req esast.SearchRequest
		if err := json.Unmarshal([]byte(qJSON), &req); err != nil {
			t.Fatalf("unmarshal search request failed: %v", err)
		}
		trPlan := NewTranspiler(idx, TranspilerOptions{})
		plan, err := trPlan.BuildSearchPlan(&req)
		if err != nil || plan.HitsSQL == "" || plan.AggsSQL == "" {
			t.Fatalf("BuildSearchPlan failed: err=%v hits=%q aggs=%q", err, plan.HitsSQL, plan.AggsSQL)
		}
	}
}
