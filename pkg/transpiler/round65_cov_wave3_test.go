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
	"math"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func buildRound65Wave3CovSchema(t *testing.T) *schema.IndexSchema {
	t.Helper()
	cfg, err := analysis.ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"sg": map[string]any{
					"type":     "synonym_graph",
					"synonyms": []any{"ny, new york", "fast, quick"},
				},
			},
			"analyzer": map[string]any{
				"syn_an": map[string]any{
					"tokenizer": "standard",
					"filter":    []any{"lowercase", "sg"},
				},
			},
			"normalizer": map[string]any{
				"lower_norm": map[string]any{
					"type":   "custom",
					"filter": []any{"lowercase"},
				},
			},
		},
	}, analysis.Options{})
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig failed: %v", err)
	}

	rawMapping := `{
		"properties": {
			"title":      {"type": "text", "analyzer": "standard", "fields": {"keyword": {"type": "keyword"}}},
			"title_eng":  {"type": "text", "analyzer": "english"},
			"title_syn":  {"type": "text", "analyzer": "syn_an"},
			"kw":         {"type": "keyword"},
			"kw_norm":    {"type": "keyword", "normalizer": "lower_norm"},
			"kw_arr":     {"type": "keyword"},
			"uid":        {"type": "unsigned_long"},
			"uid_arr":    {"type": "unsigned_long"},
			"cnt":        {"type": "long"},
			"ival":       {"type": "integer"},
			"price":      {"type": "double"},
			"flt":        {"type": "float"},
			"active":     {"type": "boolean"},
			"ts":         {"type": "date"},
			"ts_sec":     {"type": "date", "format": "epoch_second"},
			"ts_nanos":   {"type": "date_nanos"},
			"ts_nanos_a": {"type": "date_nanos"},
			"loc":        {"type": "geo_point"},
			"no_idx_dv":  {"type": "geo_point", "index": false, "doc_values": false},
			"lrange":     {"type": "long_range"},
			"irange":     {"type": "integer_range"},
			"hist":       {"type": "histogram"},
			"items": {
				"type": "nested",
				"properties": {
					"sku":    {"type": "keyword"},
					"active": {"type": "boolean"},
					"qty":    {"type": "long"},
					"price":  {"type": "double"},
					"hist":   {"type": "histogram"},
					"sub": {
						"type": "nested",
						"properties": {
							"code": {"type": "keyword"}
						}
					}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	sch := schema.CompileIndexSchema("es_db", "r65_w3_idx", &spec)
	sch.AnalysisConfig = cfg
	sch.IndexName = "r65_w3_idx"

	promote := func(name string, overrideType schema.DorisScalarType) {
		if fb, ok := sch.Fields[name]; ok {
			fb.Kind = schema.StoragePromotedArray
			fb.IsMultiValued = true
			fb.ColumnName = "arr__" + schema.SanitizeDorisIdentifier(name)
			if overrideType != "" {
				fb.DorisType = overrideType
			}
			sch.Fields[name] = fb
			for i := range sch.OrderedFields {
				if sch.OrderedFields[i].ESFieldPath == name {
					sch.OrderedFields[i] = fb
				}
			}
		}
	}
	promote("kw_arr", "")
	promote("uid_arr", schema.DorisLargeIntArray)
	promote("ts_nanos_a", "")
	return sch
}

func TestRound65CovTranspiler_LongRangeField(t *testing.T) {
	// Direct parseExactInt64RangeBoundR65 coverage
	cases := []struct {
		v       any
		isUpper bool
		want    int64
		wantOK  bool
	}{
		{int(42), false, 42, true},
		{int64(-99), true, -99, true},
		{uint64(100), false, 100, true},
		{uint64(math.MaxUint64), false, 0, false},
		{json.Number("12345"), false, 12345, true},
		{json.Number("12.7"), true, 12, true},
		{json.Number("12.2"), false, 13, true},
		{json.Number("bad"), false, 0, false},
		{" 999 ", false, 999, true},
		{"12.7", true, 12, true},
		{"12.2", false, 13, true},
		{"not-a-num", false, 0, false},
		{float64(10.8), true, 10, true},
		{float64(10.2), false, 11, true},
		{float64(1e30), true, math.MaxInt64, true},
		{float64(-1e30), false, math.MinInt64, true},
		{math.NaN(), false, 0, false},
		{math.Inf(1), true, 0, false},
		{true, false, 0, false},
	}
	for _, tc := range cases {
		got, ok := parseExactInt64RangeBoundR65(tc.v, tc.isUpper)
		if ok != tc.wantOK || (ok && got != tc.want) {
			t.Fatalf("parseExactInt64RangeBoundR65(%v, %v) = (%d, %v), want (%d, %v)", tc.v, tc.isUpper, got, ok, tc.want, tc.wantOK)
		}
	}

	// Direct evalInt64CmpR65 coverage
	if !evalInt64CmpR65(5, "<=", 5) || !evalInt64CmpR65(5, ">=", 5) ||
		!evalInt64CmpR65(4, "<", 5) || !evalInt64CmpR65(6, ">", 5) ||
		!evalInt64CmpR65(5, "=", 5) || evalInt64CmpR65(5, "!=", 5) {
		t.Fatal("unexpected evalInt64CmpR65 result")
	}

	sch := buildRound65Wave3CovSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// CompileQuery on long_range with INTERSECTS, CONTAINS, WITHIN, invalid/impossible bounds
	lrBinding := sch.Fields["lrange"]
	lrNoSrc := lrBinding
	lrNoSrc.SourceJSONPath = nil

	conds := []esast.RangeCond{
		{GTE: int64(10), LTE: int64(20), Relation: "INTERSECTS"},
		{GT: int64(10), LT: int64(30), Relation: "WITHIN"},
		{GTE: int64(5), LTE: int64(15), Relation: "CONTAINS"},
		{GTE: int64(5), Relation: "CONTAINS"},
		{LTE: int64(15), Relation: "CONTAINS"},
		// Boundary values triggering all 4 branches of cmpNullAware (MinInt64+1 / MinInt64 / MaxInt64-1 / MaxInt64)
		{GTE: int64(math.MinInt64), LTE: int64(math.MaxInt64), Relation: "INTERSECTS"},
		{GTE: int64(math.MinInt64 + 1), LTE: int64(math.MaxInt64 - 1), Relation: "WITHIN"},
		{GTE: int64(math.MinInt64), LTE: int64(math.MaxInt64), Relation: "CONTAINS"},
		// Impossible / invalid bounds -> FALSE
		{GTE: "bad_lo"},
		{GT: "bad_gt"},
		{GT: int64(math.MaxInt64)},
		{LTE: "bad_hi"},
		{LT: "bad_lt"},
		{LT: int64(math.MinInt64)},
		{GTE: int64(50), LTE: int64(10)},
	}
	for i, rc := range conds {
		sql := tr.compileLongRangeOnRangeFieldR65("lrange", lrBinding, rc)
		if i < 8 && (sql == "" || sql == "FALSE") {
			t.Fatalf("case %d expected non-FALSE SQL, got %s", i, sql)
		}
		if i >= 8 && sql != "FALSE" {
			t.Fatalf("case %d expected FALSE, got %s", i, sql)
		}
	}
	// Empty SourceJSONPath fallback + full CompileQuery path
	if sql := tr.compileLongRangeOnRangeFieldR65("lrange", lrNoSrc, esast.RangeCond{GTE: 1, LTE: 2}); !strings.Contains(sql, "array_exists") {
		t.Fatalf("expected array_exists for long_range, got %s", sql)
	}
	cp := tr.CompileQuery(&esast.Query{Range: map[string]esast.RangeCond{"lrange": {GTE: 100, LTE: 200, Relation: "WITHIN"}}}, true, nil)
	if cp.WhereSQL == "" || cp.WhereSQL == "FALSE" {
		t.Fatalf("unexpected CompileQuery result for long_range: %+v", cp)
	}
}

func TestRound65CovTranspiler_HistBucketsSchemaAndMissing(t *testing.T) {
	sch := buildRound65Wave3CovSchema(t)

	// formatHistogramBucketKeySQLR65 & formatHistogramBucketKeySQLWithRawParamsR65
	ulB := sch.Fields["uid"]
	dblB := sch.Fields["price"]
	if s := formatHistogramBucketKeySQLR65("col", 0, 10, dblB); !strings.Contains(s, "CAST(FLOOR") || strings.Contains(s, "LARGEINT") {
		t.Fatalf("unexpected double histogram bucket SQL: %s", s)
	}
	if s := formatHistogramBucketKeySQLWithRawParamsR65("col", 0, 10, RawHistParamStrings{Interval: "9223372036854775807"}, ulB); !strings.Contains(s, "AS LARGEINT") {
		t.Fatalf("expected LARGEINT cast for UL raw interval: %s", s)
	}
	if s := formatHistogramBucketKeySQLWithRawParamsR65("col", 5, 10, RawHistParamStrings{Interval: "100", Offset: "-5"}, ulB); !strings.Contains(s, "+ -5") {
		t.Fatalf("expected raw negative offset in LARGEINT SQL: %s", s)
	}
	if s := formatHistogramBucketKeySQLWithRawParamsR65("col", 1, 5, RawHistParamStrings{Interval: "-"}, ulB); !strings.Contains(s, "AS LARGEINT") {
		t.Fatalf("expected float integral LARGEINT fallback: %s", s)
	}
	if s := formatHistogramBucketKeySQLWithRawParamsR65("col", 0.5, 1.5, RawHistParamStrings{}, ulB); strings.Contains(s, "AS LARGEINT") {
		t.Fatalf("did not expect LARGEINT for fractional interval: %s", s)
	}

	// schemaHasNestedObjectPathR65
	if schemaHasNestedObjectPathR65(nil, "items") || schemaHasNestedObjectPathR65(sch, "") {
		t.Fatal("expected false for nil schema or empty path")
	}
	if !schemaHasNestedObjectPathR65(sch, "items") || !schemaHasNestedObjectPathR65(sch, "items.sub") {
		t.Fatal("expected true for items and items.sub")
	}
	if schemaHasNestedObjectPathR65(sch, "nonexistent.sub") {
		t.Fatal("expected false for nonexistent.sub")
	}
	// Fallback to sc.Fields when RawMapping lacks segment
	schNoRaw := &schema.IndexSchema{
		Fields: map[string]schema.FieldBinding{
			"a.b.c": {ESFieldPath: "a.b.c", NestedPath: "a.b"},
		},
		RawMapping: &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"other": {Type: "keyword"}}},
	}
	if !schemaHasNestedObjectPathR65(schNoRaw, "a") || !schemaHasNestedObjectPathR65(schNoRaw, "a.b") {
		t.Fatal("expected true via Fields NestedPath fallback")
	}

	// resolveUnsignedLongRangeAggMissingExact
	tr := NewTranspiler(sch, TranspilerOptions{})
	if _, ok := tr.resolveUnsignedLongRangeAggMissingExact("uid", nil); ok {
		t.Fatal("expected false on nil spec")
	}
	if _, ok := tr.resolveUnsignedLongRangeAggMissingExact("price", &esast.RangeAggSpec{Missing: 1}); ok {
		t.Fatal("expected false on non-unsigned_long field")
	}
	for _, tc := range []struct {
		v    any
		want uint64
		ok   bool
	}{
		{uint64(18446744073709551615), 18446744073709551615, true},
		{int(7), 7, true},
		{int(-1), 0, false},
		{int64(99), 99, true},
		{int64(-5), 0, false},
		{json.Number("18446744073709551610"), 18446744073709551610, true},
		{"123456", 123456, true},
		{float64(42.0), 42, true},
		{float64(-1.0), 0, false},
		{true, 0, false},
	} {
		got, ok := tr.resolveUnsignedLongRangeAggMissingExact("uid", &esast.RangeAggSpec{Missing: tc.v})
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("resolveUnsignedLongRangeAggMissingExact(%v) = (%d, %v), want (%d, %v)", tc.v, got, ok, tc.want, tc.ok)
		}
	}
}

func TestRound65CovTranspiler_Wave3AggsAndSubAggs(t *testing.T) {
	sch := buildRound65Wave3CovSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{
		RawHistBounds: map[string]RawHistParamStrings{
			"ul_hist":        {Interval: "9223372036854775807", Offset: "0"},
			"comp_ul.s_hist": {Interval: "9223372036854775807", Offset: "0"},
		},
	})

	reqJSON := `{
		"size": 0,
		"aggs": {
			"pct_hist": {"percentiles": {"field": "hist", "percents": [0, 50, 100], "hdr": {"number_of_significant_value_digits": 3}}},
			"pr_hist": {"percentile_ranks": {"field": "hist", "values": [10, 50], "hdr": {}}},
			"box_hist": {"boxplot": {"field": "hist"}},
			"rng_hist": {"range": {"field": "hist", "ranges": [{"to": 10}, {"from": 10, "to": 50}, {"from": 50}]}},
			"rng_hist_script": {"range": {"field": "hist", "script": {"source": "_value * 2"}, "ranges": [{"from": 0, "to": 100}]}},
			"rng_ul": {"range": {"field": "uid", "missing": "18446744073709551615", "ranges": [{"from": 0, "to": 100}, {"from": 100}]}},
			"rng_ul_arr": {"range": {"field": "uid_arr", "missing": 5, "ranges": [{"from": 0, "to": 100}]}},
			"ul_hist": {"histogram": {"field": "uid", "interval": 1000000}},
			"hist_missing_script": {
				"histogram": {
					"field": "price",
					"interval": 10,
					"missing": 5,
					"hard_bounds": {"min": 0, "max": 100},
					"script": {"source": "_value + 1"}
				}
			},
			"hist_script_only": {"histogram": {"interval": 10, "missing": 1, "script": {"source": "doc['price'].value * 2"}}},
			"ss_scalar_miss": {"string_stats": {"field": "kw", "missing": "none", "script": {"source": "_value + '_s'"}}},
			"ss_script_only": {"string_stats": {"missing": "fallback", "script": {"source": "doc['kw'].value"}}},
			"ss_arr_miss": {"string_stats": {"field": "kw_arr", "missing": "empty", "script": {"source": "_value + '_a'"}}},
			"named_filters": {
				"filters": {
					"other_bucket": true,
					"other_bucket_key": "other_grp",
					"filters": {
						"yes": {"term": {"active": true}},
						"high": {"range": {"cnt": {"gte": 10}}}
					}
				},
				"aggs": {
					"c": {"value_count": {"field": "cnt"}}
				}
			},
			"anon_filters": {
				"filters": {
					"other_bucket": true,
					"filters": [{"term": {"active": true}}, {"term": {"active": false}}]
				},
				"aggs": {
					"s": {"sum": {"field": "price"}}
				}
			},
			"mt_top": {
				"multi_terms": {
					"terms": [
						{"field": "active"},
						{"field": "uid"},
						{"field": "ival", "value_type": "long"},
						{"field": "flt", "value_type": "double"},
						{"field": "kw_norm"},
						{"field": "kw_arr", "missing": "none"},
						{"script": {"source": "doc['kw'].value"}, "value_type": "unsigned_long", "missing": "0"}
					],
					"min_doc_count": 2,
					"order": [{"_count": "asc"}, {"_key": "desc"}],
					"size": 5
				},
				"aggs": {
					"avg_p": {"avg": {"field": "price"}}
				}
			},
			"mt_subsort": {
				"multi_terms": {
					"terms": [{"field": "kw"}, {"field": "uid_arr"}],
					"order": {"avg_p": "desc"}
				},
				"aggs": {
					"avg_p": {"avg": {"field": "price"}}
				}
			},
			"comp_ul": {
				"composite": {
					"size": 5,
					"sources": [
						{"s_dh": {"date_histogram": {"field": "ts_nanos_a", "fixed_interval": "1h", "missing": "2026-01-01T00:00:00Z"}}},
						{"s_dh_missb": {"date_histogram": {"field": "ts", "fixed_interval": "1h", "missing_bucket": true, "script": {"source": "_value + 1"}}}},
						{"s_hist": {"histogram": {"field": "uid", "interval": 1000000, "missing": 0}}},
						{"s_hist_mb": {"histogram": {"field": "price", "interval": 5, "missing_bucket": true, "script": {"source": "_value + 1"}}}}
					]
				}
			},
			"by_kw": {
				"terms": {"field": "kw", "size": 5},
				"aggs": {
					"sub_pct_hist": {"percentiles": {"field": "hist", "percents": [0, 50, 100]}},
					"sub_box_hist": {"boxplot": {"field": "hist"}},
					"sub_rng_hist": {"range": {"field": "hist", "ranges": [{"from": 0, "to": 50}]}},
					"sub_rng_ul": {"range": {"field": "uid", "missing": "10", "ranges": [{"from": 0, "to": 20}]}},
					"sub_rng_ul_arr": {"range": {"field": "uid_arr", "missing": 10, "ranges": [{"from": 0, "to": 20}]}},
					"sub_hist_on_hist": {"histogram": {"field": "hist", "interval": 10, "hard_bounds": {"min": 0, "max": 50}}},
					"sub_hist_script_miss": {"histogram": {"interval": 10, "missing": 2, "script": {"source": "doc['price'].value"}}},
					"sub_ss_arr": {"string_stats": {"field": "kw_arr", "missing": "none", "script": {"source": "_value + '!'"}}},
					"sub_ss_scalar": {"string_stats": {"field": "kw", "missing": "none", "script": {"source": "_value + '!'"}}},
					"sub_ss_script": {"string_stats": {"missing": "none", "script": {"source": "doc['kw'].value"}}},
					"sub_mt": {
						"multi_terms": {
							"terms": [{"field": "active"}, {"field": "kw_arr"}],
							"min_doc_count": 2,
							"order": {"_count": "asc"}
						},
						"aggs": {"c": {"value_count": {"field": "cnt"}}}
					},
					"sub_filters_named": {
						"filters": {
							"other_bucket": true,
							"other_bucket_key": "rest",
							"filters": {"a": {"term": {"active": true}}}
						},
						"aggs": {"c": {"value_count": {"field": "cnt"}}}
					},
					"sub_filters_anon": {
						"filters": {
							"other_bucket": true,
							"filters": [{"term": {"active": true}}]
						},
						"aggs": {"c": {"value_count": {"field": "cnt"}}}
					}
				}
			},
			"by_items": {
				"nested": {"path": "items"},
				"aggs": {
					"rn_root": {"reverse_nested": {}, "aggs": {"c": {"value_count": {"field": "cnt"}}}},
					"rn_sub": {"reverse_nested": {"path": "items.sub"}, "aggs": {"c": {"value_count": {"field": "items.sub.code"}}}},
					"n_terms_bool": {"terms": {"field": "items.active"}},
					"n_terms_kw": {"terms": {"field": "items.sku"}},
					"n_pct": {"percentiles": {"field": "items.price", "missing": 0, "script": {"source": "_value * 2"}}},
					"n_pr": {"percentile_ranks": {"field": "items.price", "values": [10], "missing": 0, "script": {"source": "_value * 2"}}},
					"n_box": {"boxplot": {"field": "items.price", "missing": 0, "script": {"source": "_value * 2"}}},
					"n_ss": {"string_stats": {"field": "items.sku", "missing": "none", "script": {"source": "_value + '_x'"}}},
					"n_card": {"cardinality": {"field": "items.sku", "missing": "none", "script": {"source": "_value + '_c'"}}},
					"n_hist": {"histogram": {"field": "items.hist", "interval": 10}},
					"n_mad": {"median_absolute_deviation": {"field": "items.price", "missing": 1.0, "script": {"source": "_value + 1"}}}
				}
			},
			"dh_mov": {
				"date_histogram": {"field": "ts", "fixed_interval": "1h"},
				"aggs": {
					"avg_p": {"avg": {"field": "price"}},
					"mp": {"moving_percentiles": {"buckets_path": "avg_p", "percents": [50, 95], "window": 5}}
				}
			}
		}
	}`

	var req esast.SearchRequest
	dec := json.NewDecoder(strings.NewReader(reqJSON))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		t.Fatalf("decode req failed: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(plan.AggsSQL, "SPLIT_PART") || !strings.Contains(plan.AggsSQL, "CHAR_LENGTH") || !strings.Contains(plan.AggsSQL, "CONCAT_WS('|'") {
		t.Fatalf("missing expected Wave-3 SQL fragments:\n%s", plan.AggsSQL)
	}

	// ES8Compat mode for hard_bounds `<`
	trES8 := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	var reqES8 esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"h": {"histogram": {"field": "price", "interval": 10, "hard_bounds": {"min": 0, "max": 50}}},
			"t": {"terms": {"field": "kw"}, "aggs": {"sh": {"histogram": {"field": "price", "interval": 5, "hard_bounds": {"min": 0, "max": 25}}}}}
		}
	}`), &reqES8)
	if p8, err8 := trES8.BuildSearchPlan(&reqES8); err8 != nil || !strings.Contains(p8.AggsSQL, "< 50") {
		t.Fatalf("expected ES8Compat < upper hard_bound, err=%v sql=%s", err8, p8.AggsSQL)
	}

	// Direct check of TypedAggKeyPrefix for moving_percentiles & nested error path
	if fmtType := TypedAggKeyPrefix(&esast.AggSpec{MovingPercentiles: &esast.MovingPercentilesAggSpec{}}, sch); fmtType != "tdigest_percentiles" {
		t.Fatalf("unexpected MovingPercentiles format: %s", fmtType)
	}
	var badNestedReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size":0,"aggs":{"n":{"nested":{"path":"missing_path"}}}}`), &badNestedReq)
	if _, errN := tr.BuildSearchPlan(&badNestedReq); errN == nil {
		t.Fatal("expected error for missing nested path")
	}
}

func TestRound65CovTranspiler_QueryAndTermEdgeBranches(t *testing.T) {
	sch := buildRound65Wave3CovSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// 1. Common terms query branches (empty, stopwords-only with msm, mixed low/high freq, multi-field)
	for _, qJSON := range []string{
		`{"common":{"title":{"query":""}}}`,
		`{"common":{"title":{"query":"the and of","cutoff_frequency":0.001,"minimum_should_match":2,"boost":1.5}}}`,
		`{"common":{"title":{"query":"the and","cutoff_frequency":0.001,"high_freq_operator":"and"}}}`,
		`{"common":{"title":{"query":"the quick","cutoff_frequency":0.001,"low_freq_operator":"and","high_freq_operator":"and","boost":2.0}}}`,
		`{"common":{"title":{"query":"the quick","cutoff_frequency":0.001,"low_freq_operator":"and","high_freq_operator":"or"}}}`,
		`{"common":{"title":{"query":"the quick","cutoff_frequency":0.001,"low_freq_operator":"or","high_freq_operator":"and"}}}`,
		`{"common":{"title":{"query":"the quick","cutoff_frequency":0.001,"low_freq_operator":"or","high_freq_operator":"or"}}}`,
		`{"common":{"title":{"query":"quick fox"},"title_eng":{"query":"the brown"}}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(qJSON), &q); err != nil {
			t.Fatalf("unmarshal %s failed: %v", qJSON, err)
		}
		_ = tr.CompileQuery(&q, true, nil)
	}

	// 2. GeoGrid branches (geohash, geotile, invalid, unindexed error, wrong type error, ignore_unmapped)
	for _, qJSON := range []string{
		`{"geo_grid":{"loc":{"geohash":"u17"}}}`,
		`{"geo_grid":{"loc":{"geotile":"4/8/5"}}}`,
		`{"geo_grid":{"loc":{"geohash":"!"}}}`,
		`{"geo_grid":{"loc":{"geotile":"bad"}}}`,
		`{"geo_grid":{"unmapped_geo":{"geohash":"u17"},"ignore_unmapped":true}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(qJSON), &q); err != nil {
			t.Fatalf("unmarshal %s failed: %v", qJSON, err)
		}
		_ = tr.CompileQuery(&q, true, nil)
	}
	for _, errQ := range []string{
		`{"geo_grid":{"no_idx_dv":{"geohash":"u17"}}}`,
		`{"geo_grid":{"kw":{"geohash":"u17"}}}`,
	} {
		trErr := NewTranspiler(sch, TranspilerOptions{})
		var q esast.Query
		if err := json.Unmarshal([]byte(errQ), &q); err != nil {
			t.Fatalf("unmarshal %s failed: %v", errQ, err)
		}
		_ = trErr.CompileQuery(&q, true, nil)
		if trErr.searchErr == nil {
			t.Fatalf("expected error for %s", errQ)
		}
	}

	// 3. queryContainsScript and queryContainsNestedScoring across wrapper types
	scriptLeaf := esast.Query{Script: &esast.ScriptQuery{Script: esast.ScriptSpec{Source: "doc['cnt'].value > 0"}}}
	nestedLeaf := esast.Query{Nested: &esast.NestedQuery{Path: "items", ScoreMode: "avg", Query: esast.Query{MatchAll: map[string]any{}}}}
	for _, leaf := range []*esast.Query{&scriptLeaf, &nestedLeaf} {
		wrappers := []*esast.Query{
			{FunctionScore: &esast.FunctionScoreQuery{Query: leaf}},
			{ConstantScore: &esast.ConstantScoreQuery{Filter: *leaf}},
			{Nested: &esast.NestedQuery{Path: "items", ScoreMode: "none", Query: *leaf}},
			{Wrapper: &esast.WrapperQuery{Decoded: leaf}},
			{Pinned: &esast.PinnedQuery{Organic: leaf}},
			{Rule: &esast.RuleQuerySpec{Organic: leaf}},
			{HasChild: &esast.HasChildQuery{Type: "c", Query: *leaf}},
			{HasParent: &esast.HasParentQuery{ParentType: "p", Query: *leaf}},
			{SpanNear: &esast.SpanNearQuery{Clauses: []esast.Query{*leaf}}},
			{SpanOr: &esast.SpanOrQuery{Clauses: []esast.Query{*leaf}}},
			{SpanNot: &esast.SpanNotQuery{Include: leaf}},
			{SpanFirst: &esast.SpanFirstQuery{Match: leaf}},
			{SpanMulti: &esast.SpanMultiQuery{Match: leaf}},
			{SpanContaining: &esast.SpanPairQuery{Big: leaf}},
			{SpanWithin: &esast.SpanPairQuery{Little: leaf}},
			{FieldMaskingSpan: &esast.FieldMaskingSpanQuery{Field: "title", Query: leaf}},
			{DisMax: &esast.DisMaxQuery{Queries: []esast.Query{*leaf}}},
			{Boosting: &esast.BoostingQuery{Positive: *leaf, Negative: *leaf}},
			{Bool: &esast.BoolQuery{Must: []esast.Query{*leaf}}},
			{Bool: &esast.BoolQuery{Filter: []esast.Query{*leaf}}},
			{Bool: &esast.BoolQuery{Should: []esast.Query{*leaf}}},
			{Bool: &esast.BoolQuery{MustNot: []esast.Query{*leaf}}},
		}
		for i, wq := range wrappers {
			if !queryContainsScript(wq) && leaf == &scriptLeaf {
				t.Fatalf("wrapper %d expected queryContainsScript=true", i)
			}
			if !queryContainsNestedScoring(wq) && leaf == &nestedLeaf && i != 2 && i != 21 {
				t.Fatalf("wrapper %d expected queryContainsNestedScoring=true", i)
			}
		}
	}

	// 4. Term/Terms numeric & unsigned_long coercion branches + Range epoch_second/DorisInt/Double
	for _, qJSON := range []string{
		`{"term":{"uid":{"value":"18446744073709551615"}}}`,
		`{"term":{"uid":{"value":"100.0"}}}`,
		`{"term":{"uid":{"value":"bad_ul"}}}`,
		`{"term":{"uid":{"value":-1}}}`,
		`{"term":{"uid":{"value":12.5}}}`,
		`{"term":{"cnt":{"value":"100.0"}}}`,
		`{"term":{"cnt":{"value":"bad_cnt"}}}`,
		`{"term":{"price":{"value":"12.5"}}}`,
		`{"term":{"price":{"value":"bad_dbl"}}}`,
		`{"terms":{"uid":["18446744073709551615","10.0","-5","bad",100,-2,12.5,1e25]}}`,
		`{"terms":{"cnt":["10.0","bad",42]}}`,
		`{"terms":{"price":["10.5","bad"]}}`,
		`{"terms":{"ts":["bad_date","1700000000000"]}}`,
		`{"range":{"ts_sec":{"gte":1700000000,"lte":1700000100}}}`,
		`{"range":{"ts_sec":{"gte":1700000000.5,"lte":1700000100.5}}}`,
		`{"range":{"ival":{"gte":"10","lte":"20"}}}`,
		`{"range":{"price":{"gte":"1.5","lte":"9.5"}}}`,
		`{"range":{"kw_norm":{"gte":"Alpha","lte":"Zeta"}}}`,
		`{"match_phrase":{"title_syn":{"query":"ny fast"}}}`,
		`{"match_phrase":{"title":{"query":"the quick","analyzer":"english"}}}`,
	} {
		var q esast.Query
		dec := json.NewDecoder(strings.NewReader(qJSON))
		dec.UseNumber()
		if err := dec.Decode(&q); err != nil {
			t.Fatalf("decode %s failed: %v", qJSON, err)
		}
		_ = tr.CompileQuery(&q, true, nil)
	}
}

func TestRound65CovTranspiler_NestedPrefilterAndSortVariants(t *testing.T) {
	sch := buildRound65Wave3CovSchema(t)
	now := time.Now().UTC()

	// 1. normalizeNestedPrefilterValue across int/uint64/float64/json.Number/string/bool/ip
	cntB := sch.Fields["cnt"]
	uidB := sch.Fields["uid"]
	prcB := sch.Fields["price"]
	kwB := sch.Fields["kw"]
	tsB := sch.Fields["ts"]
	if _, ok := normalizeNestedPrefilterValue(cntB, nil, false, now); ok {
		t.Fatal("expected false on nil")
	}
	if _, ok := normalizeNestedPrefilterValue(sch.Fields["active"], "not_bool", false, now); ok {
		t.Fatal("expected false on bad bool")
	}
	if _, ok := normalizeNestedPrefilterValue(sch.Fields["loc"], "bad_ip", false, now); !ok {
		// loc is geo_point, check ip directly
		ipB := schema.FieldBinding{ESFieldPath: "ip", ESType: "ip", DorisType: schema.DorisVarchar}
		if _, okIP := normalizeNestedPrefilterValue(ipB, "bad_ip", false, now); okIP {
			t.Fatal("expected false on bad ip")
		}
	}
	for _, tc := range []struct {
		b      schema.FieldBinding
		v      any
		wantOK bool
	}{
		{cntB, int(7), true},
		{cntB, int64(8), true},
		{uidB, uint64(9), true},
		{cntB, float64(3.5), true},
		{cntB, math.NaN(), false},
		{cntB, json.Number("12"), true},
		{cntB, json.Number("12.0"), true},
		{cntB, json.Number("bad"), false},
		{uidB, json.Number("-1"), false},
		{uidB, json.Number("18446744073709551615"), true},
		{uidB, json.Number("bad"), false},
		{uidB, "18446744073709551615", true},
		{uidB, "50.0", true},
		{uidB, "-5", false},
		{uidB, "bad", false},
		{cntB, "42.0", true},
		{cntB, "bad", false},
		{prcB, json.Number("4.5"), true},
		{prcB, json.Number("bad"), false},
		{prcB, "3.25", true},
		{prcB, "bad", false},
		{tsB, "bad_date", false},
		{kwB, json.Number("10"), true},
		{kwB, struct{ X int }{1}, true},
	} {
		if _, ok := normalizeNestedPrefilterValue(tc.b, tc.v, true, now); ok != tc.wantOK {
			t.Fatalf("normalizeNestedPrefilterValue(%s, %v) ok=%v, want %v", tc.b.ESFieldPath, tc.v, ok, tc.wantOK)
		}
	}

	// 2. split_queries_on_whitespace & explicit analyzer on keyword in match
	splitTrue := true
	sch.RawMapping.Properties["title_split"] = esast.FieldProperty{
		Type:                     "keyword",
		SplitQueriesOnWhitespace: &splitTrue,
	}
	schSplit := schema.CompileIndexSchema("es_db", "r65_split", sch.RawMapping)
	trSplit := NewTranspiler(schSplit, TranspilerOptions{})
	cpSplit := trSplit.CompileQuery(&esast.Query{
		Match: map[string]esast.MatchEntry{
			"title_split": {Query: "foo bar", Operator: "and"},
		},
	}, true, nil)
	if !strings.Contains(cpSplit.WhereSQL, " AND ") {
		t.Fatalf("expected AND for split_queries_on_whitespace, got %s", cpSplit.WhereSQL)
	}
	cpExpAn := trSplit.CompileQuery(&esast.Query{
		Match: map[string]esast.MatchEntry{
			"kw": {Query: "foo bar", Operator: "and", Analyzer: "standard"},
		},
	}, true, nil)
	if !strings.Contains(cpExpAn.WhereSQL, " AND ") {
		t.Fatalf("expected AND for keyword explicit analyzer, got %s", cpExpAn.WhereSQL)
	}

	// 3. Dynamic nested sort with and without nested filter
	var sortReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"sort": [
			{"items.dyn_f": {"order": "asc", "unmapped_type": "long", "nested": {"path": "items", "filter": {"term": {"items.sku": "a"}}}}},
			{"items.dyn_f2": {"order": "desc", "unmapped_type": "long", "nested": {"path": "items"}}}
		]
	}`), &sortReq); err != nil {
		t.Fatalf("unmarshal sortReq failed: %v", err)
	}
	if _, err := trSplit.BuildSearchPlan(&sortReq); err != nil {
		t.Fatalf("BuildSearchPlan nested dynamic sort failed: %v", err)
	}

	// 4. Common query with TermDocFreqFn + match_bool_prefix + filter->percentile_ranks + resolveMaxEditDistance
	trFreq := NewTranspiler(sch, TranspilerOptions{
		TermDocFreqFn: func(_ string, terms []string, _ bool) (int, map[string]int) {
			dfs := make(map[string]int, len(terms))
			for _, tk := range terms {
				if tk == "the" || tk == "and" {
					dfs[tk] = 90
				} else {
					dfs[tk] = 1
				}
			}
			return 100, dfs
		},
	})
	for _, qJSON := range []string{
		`{"common":{"title":{"query":"the and","cutoff_frequency":0.1,"minimum_should_match":{"high_freq":1},"boost":1.5}}}`,
		`{"common":{"title":{"query":"the quick","cutoff_frequency":0.1,"low_freq_operator":"and","high_freq_operator":"and","boost":2.0}}}`,
		`{"common":{"title":{"query":"the quick","cutoff_frequency":0.1,"low_freq_operator":"and","high_freq_operator":"or"}}}`,
		`{"common":{"title":{"query":"the quick","cutoff_frequency":0.1,"low_freq_operator":"or","high_freq_operator":"and"}}}`,
		`{"common":{"title":{"query":"the quick","cutoff_frequency":0.1,"low_freq_operator":"or","high_freq_operator":"or"}}}`,
		`{"match_bool_prefix":{"title_syn":{"query":"ny fast","operator":"and"}}}`,
		`{"match_bool_prefix":{"title_syn":{"query":"ny","operator":"or"}}}`,
		`{"match":{"title_syn":{"query":"ny fast","operator":"and","auto_generate_synonyms_phrase_query":false}}}`,
		`{"match_phrase_prefix":{"kw":{"query":"foo"}}}`,
		`{"match_phrase_prefix":{"title_eng":{"query":"the","zero_terms_query":"all"}}}`,
		`{"match_phrase_prefix":{"title_eng":{"query":"the"}}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(qJSON), &q); err != nil {
			t.Fatalf("unmarshal %s failed: %v", qJSON, err)
		}
		_ = trFreq.CompileQuery(&q, true, nil)
	}

	var prReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"f": {
				"filter": {"term": {"active": true}},
				"aggs": {
					"pr_script": {"percentile_ranks": {"field": "price", "values": [10], "missing": 0, "script": {"source": "_value * 2"}}},
					"pr_script_only": {"percentile_ranks": {"values": [10], "missing": 5, "script": {"source": "doc['price'].value"}}}
				}
			}
		}
	}`), &prReq)
	if _, err := trFreq.BuildSearchPlan(&prReq); err != nil {
		t.Fatalf("BuildSearchPlan filter->percentile_ranks failed: %v", err)
	}

	for _, fv := range []any{
		nil,
		0, 1, 2,
		int64(0), int64(1), int64(2),
		float64(0), float64(1), float64(2),
		json.Number("0"), json.Number("1"), json.Number("2"), json.Number("0.5"), json.Number("2.5"),
		"0", "1", "2", "", "AUTO", "AUTO:2,5",
	} {
		_ = resolveFuzzyMaxEdits(fv, 2)
		_ = resolveFuzzyMaxEdits(fv, 4)
		_ = resolveFuzzyMaxEdits(fv, 7)
	}
}
