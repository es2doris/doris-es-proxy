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
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func r67T2TCompileSchema(t *testing.T, mappingJSON string) *schema.IndexSchema {
	t.Helper()
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(mappingJSON), &spec); err != nil {
		t.Fatalf("unmarshal mapping spec failed: %v", err)
	}
	return schema.CompileIndexSchema("es_db", "r67t2_tr_idx", &spec)
}

func r67T2TRichSchema(t *testing.T) *schema.IndexSchema {
	t.Helper()
	return r67T2TCompileSchema(t, `{
		"settings": {
			"analysis": {
				"normalizer": {
					"lc_norm": {"type": "custom", "filter": ["lowercase"]}
				},
				"filter": {
					"syn_graph": {
						"type": "synonym_graph",
						"synonyms": ["ny, new york", "fast => quick"]
					}
				},
				"analyzer": {
					"syn_an": {
						"tokenizer": "standard",
						"filter": ["lowercase", "syn_graph"]
					}
				}
			}
		},
		"properties": {
			"title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"title_syn": {"type": "text", "analyzer": "syn_an"},
			"title_eng": {"type": "text", "analyzer": "english"},
			"title_unidx": {"type": "text", "index": false},
			"status": {"type": "keyword"},
			"kw_arr": {"type": "keyword", "multi_valued": true},
			"ul_val": {"type": "unsigned_long"},
			"ul_arr": {"type": "unsigned_long", "multi_valued": true},
			"num": {"type": "long"},
			"num_arr": {"type": "long", "multi_valued": true},
			"dbl": {"type": "double"},
			"flag": {"type": "boolean"},
			"dt": {"type": "date"},
			"dt_sec": {"type": "date", "format": "epoch_second"},
			"dn": {"type": "date_nanos"},
			"dn_sec": {"type": "date_nanos", "format": "epoch_second"},
			"dn_ns": {"type": "date_nanos", "format": "epoch_nanos"},
			"ip_addr": {"type": "ip"},
			"ip_arr": {"type": "ip", "multi_valued": true},
			"ver": {"type": "version", "ignore_above": 12},
			"ver_arr": {"type": "version", "multi_valued": true},
			"geo_pt": {"type": "geo_point"},
			"geo_arr": {"type": "geo_point", "multi_valued": true},
			"geo_sh": {"type": "geo_shape"},
			"hist": {"type": "histogram"},
			"text_arr": {"type": "text", "multi_valued": true},
			"vec_i8": {"type": "dense_vector", "dims": 4, "index_options": {"type": "int8_hnsw"}},
			"items": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword", "normalizer": "lc_norm"},
					"tags": {"type": "text", "multi_valued": true},
					"qty": {"type": "long", "multi_valued": true},
					"qty_s": {"type": "long"},
					"ip_n": {"type": "ip", "multi_valued": true},
					"ver_n": {"type": "version", "multi_valued": true},
					"loc": {"type": "geo_point"},
					"sub": {
						"type": "nested",
						"properties": {
							"code": {"type": "keyword"}
						}
					}
				}
			},
			"items.flat": {"type": "keyword"}
		}
	}`)
}

func r67T2TUnmarshalReq(t *testing.T, raw string) *esast.SearchRequest {
	t.Helper()
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal SearchRequest failed: %v\nraw: %s", err, raw)
	}
	return &req
}

func TestRound67TopUp2Tr_SQLStringAndFromClauseHelpers(t *testing.T) {
	// 1. appendLateralViewToFromClause with quotes, escaped quotes, parens, and JOIN
	fromWithQuotes := "(SELECT 'it\\'s ''ok''' AS a, \"col\\\"x\" AS b, `tbl``1` AS c FROM t) INNER JOIN u ON t.id = u.id"
	got := appendLateralViewToFromClause(fromWithQuotes, "LATERAL VIEW EXPLODE(arr) _t AS _e")
	if !strings.Contains(got, "LATERAL VIEW EXPLODE(arr) _t AS _e INNER JOIN") {
		t.Fatalf("expected LATERAL VIEW before INNER JOIN, got %q", got)
	}
	gotNoJoin := appendLateralViewToFromClause("`base_matched`", "LATERAL VIEW EXPLODE(arr) _t AS _e")
	if !strings.HasSuffix(gotNoJoin, "LATERAL VIEW EXPLODE(arr) _t AS _e") {
		t.Fatalf("expected LATERAL VIEW appended, got %q", gotNoJoin)
	}

	// 2. unwrapOuterBalancedSQLParens, splitTopLevelSQLBoolOp, findTopLevelMatchOperatorIndex with double quotes & escapes
	unwrapped := unwrapOuterBalancedSQLParens(`(("a\"b" = 1))`)
	if unwrapped != `"a\"b" = 1` {
		t.Fatalf("unexpected unwrapped SQL: %q", unwrapped)
	}
	parts := splitTopLevelSQLBoolOp(`"a \"AND\" b" = 1 AND c = 2`, "AND")
	if len(parts) != 2 {
		t.Fatalf("expected 2 split parts, got %d (%v)", len(parts), parts)
	}
	idx := findTopLevelMatchOperatorIndex(`"col\"x" MATCH_ALL 'hi'`)
	if idx <= 0 {
		t.Fatalf("expected positive MATCH index, got %d", idx)
	}

	// 3. negateFulltextWhereSQL NOT(...) unwrap
	neg := negateFulltextWhereSQL(`NOT (` + "`title`" + ` MATCH_ALL 'foo')`)
	if !strings.Contains(neg, "MATCH_ALL") {
		t.Fatalf("unexpected negateFulltextWhereSQL: %q", neg)
	}
	negCoalesce := negateFulltextWhereSQL(`NOT COALESCE(x, FALSE)`)
	if negCoalesce != `COALESCE(x, FALSE)` {
		t.Fatalf("expected COALESCE unwrap, got %q", negCoalesce)
	}

	// 4. parseDateNanosNumericScalar integer & non-int branches
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if ns, ok := parseDateNanosNumericScalar("unparseable", 12, true, "epoch_second", now, false); !ok || ns != 12_000_000_000 {
		t.Fatalf("expected 12e9 ns, got (%d, %v)", ns, ok)
	}
	if ns, ok := parseDateNanosNumericScalar("unparseable", 12, true, "epoch_nanos", now, false); !ok || ns != 12 {
		t.Fatalf("expected 12 ns, got (%d, %v)", ns, ok)
	}
	if ns, ok := parseDateNanosNumericScalar("unparseable", 12, true, "strict_date_optional_time", now, false); !ok || ns != 12_000_000 {
		t.Fatalf("expected 12e6 ns, got (%d, %v)", ns, ok)
	}
	if _, ok := parseDateNanosNumericScalar("unparseable", 0, false, "strict_date_optional_time", now, false); ok {
		t.Fatalf("expected false for non-int unparseable")
	}

	// 5. parseIPv6CIDRHexBounds errors & valid CIDR
	if _, _, ok := parseIPv6CIDRHexBounds("not_ipv6"); ok {
		t.Fatalf("expected false for non-ipv6")
	}
	if _, _, ok := parseIPv6CIDRHexBounds("2001:db8::/999"); ok {
		t.Fatalf("expected false for invalid mask")
	}
	if s, e, ok := parseIPv6CIDRHexBounds("2001:db8::/32"); !ok || s == "" || e == "" {
		t.Fatalf("expected valid ipv6 bounds, got (%q, %q, %v)", s, e, ok)
	}

	// 6. normalizeUnsignedLongRangeBounds edge cases
	_, _, _, _, ok := normalizeUnsignedLongRangeBounds(nil, json.Number("18446744073709551616"), nil, nil)
	if ok {
		t.Fatalf("expected false for gte > MaxUint64")
	}
	_, gteOut, _, _, ok2 := normalizeUnsignedLongRangeBounds(nil, json.Number("10.5"), nil, nil)
	if !ok2 || gteOut != uint64(11) {
		t.Fatalf("expected gte ceil 11, got (%v, %v)", gteOut, ok2)
	}
	_, _, _, _, ok3 := normalizeUnsignedLongRangeBounds(nil, json.Number("18446744073709551615.5"), nil, nil)
	if ok3 {
		t.Fatalf("expected false for fractional > MaxUint64")
	}
	_, gteNeg, _, _, ok4 := normalizeUnsignedLongRangeBounds(nil, -5, nil, nil)
	if !ok4 || gteNeg != uint64(0) {
		t.Fatalf("expected gte clamped to 0, got (%v, %v)", gteNeg, ok4)
	}
}

func TestRound67TopUp2Tr_MatchBoolPrefixCommonAndExpensive(t *testing.T) {
	sch := r67T2TRichSchema(t)

	// 1. compileMatchBoolPrefixRound62Opts with DisableSynonymsPhraseQuery: true & multi-word alt in non-last AND last position + broken custom analyzer
	trNoSyn := NewTranspiler(sch, TranspilerOptions{
		ES8Compat:                  true,
		DisableSynonymsPhraseQuery: true,
	})
	for _, tc := range []struct {
		name string
		pe   esast.PhraseEntry
	}{
		{"mid_or", esast.PhraseEntry{Query: "ny train", Operator: "or", Boost: 1.5}},
		{"mid_and", esast.PhraseEntry{Query: "ny train", Operator: "and"}},
		{"last_or", esast.PhraseEntry{Query: "express ny", Operator: "or"}},
		{"last_and", esast.PhraseEntry{Query: "express ny", Operator: "and"}},
	} {
		cp := trNoSyn.compileMatchBoolPrefixRound62Opts("title_syn", tc.pe, nil, true, nil)
		if cp.WhereSQL == "" {
			t.Fatalf("%s: empty WhereSQL", tc.name)
		}
	}

	// Custom analyzer failure path in compileMatchBoolPrefixRound62Opts
	trBadAn := NewTranspiler(sch, TranspilerOptions{
		AnalysisConfig: &analysis.IndexAnalysisConfig{
			AnalyzerDefs: map[string]map[string]any{
				"broken_an": {"type": "custom", "tokenizer": "nonexistent_tokenizer"},
			},
		},
	})
	cpBad := trBadAn.compileMatchBoolPrefixRound62Opts("title", esast.PhraseEntry{Query: "hello", Analyzer: "broken_an"}, nil, true, nil)
	if cpBad.WhereSQL != "FALSE" || trBadAn.searchErr == nil {
		t.Fatalf("expected error on broken custom analyzer, got %+v", cpBad)
	}

	// Non-custom keyword analyzer path & exact keyword field
	cpKw := trNoSyn.compileMatchBoolPrefixRound62Opts("title", esast.PhraseEntry{Query: "Foo Bar", Analyzer: "keyword"}, nil, true, nil)
	if cpKw.WhereSQL == "FALSE" {
		t.Fatalf("expected non-FALSE for keyword analyzer match_bool_prefix")
	}

	// 2. formatAnalyzedBoolPrefixLuceneExplain with Synonym multi-term non-last + multi-term last
	if sch.AnalysisConfig != nil {
		got := formatAnalyzedBoolPrefixLuceneExplain("title_syn", "ny express", "and", "syn_an", sch.AnalysisConfig, analysis.Options{})
		if !strings.Contains(got, "title_syn:") {
			t.Fatalf("unexpected lucene explain: %q", got)
		}
	}

	// 3. compileCommonTermsQueryR64 where low or high is FALSE
	trCT := NewTranspiler(sch, TranspilerOptions{
		TermDocFreqFn: func(_ string, terms []string, _ bool) (int, map[string]int) {
			dfs := map[string]int{}
			for _, tk := range terms {
				if tk == "common" {
					dfs[tk] = 90
				} else {
					dfs[tk] = 1
				}
			}
			return 100, dfs
		},
	})
	if _, ok := trCT.compileCommonTermsQueryR64("title", "common rare", "or", "or", 0.5, nil, "", "", 1.0, true, nil, true); !ok {
		t.Fatalf("expected common terms to compile")
	}

	// 4. checkExpensiveQueryNode across Bool, ConstantScore, Boosting, DisMax, FunctionScore, Pinned, SpanMulti
	trExp := NewTranspiler(sch, TranspilerOptions{})
	expensiveLeaf := esast.Query{Range: map[string]esast.RangeCond{"title": {GTE: "a"}}}
	for _, tc := range []struct {
		name string
		q    esast.Query
	}{
		{"bool_must", esast.Query{Bool: &esast.BoolQuery{Must: []esast.Query{expensiveLeaf}}}},
		{"bool_filter", esast.Query{Bool: &esast.BoolQuery{Filter: []esast.Query{expensiveLeaf}}}},
		{"bool_should", esast.Query{Bool: &esast.BoolQuery{Should: []esast.Query{expensiveLeaf}}}},
		{"bool_mustnot", esast.Query{Bool: &esast.BoolQuery{MustNot: []esast.Query{expensiveLeaf}}}},
		{"cs", esast.Query{ConstantScore: &esast.ConstantScoreQuery{Filter: expensiveLeaf}}},
		{"boost_pos", esast.Query{Boosting: &esast.BoostingQuery{Positive: expensiveLeaf, Negative: esast.Query{MatchAll: map[string]any{}}}}},
		{"boost_neg", esast.Query{Boosting: &esast.BoostingQuery{Positive: esast.Query{MatchAll: map[string]any{}}, Negative: expensiveLeaf}}},
		{"dismax", esast.Query{DisMax: &esast.DisMaxQuery{Queries: []esast.Query{expensiveLeaf}}}},
		{"fs_script", esast.Query{FunctionScore: &esast.FunctionScoreQuery{Query: &esast.Query{MatchAll: map[string]any{}}, ScriptScore: &esast.ScriptScoreFunctionSpec{Script: map[string]any{"source": "1"}}}}},
		{"fs_fn_script", esast.Query{FunctionScore: &esast.FunctionScoreQuery{Query: &esast.Query{MatchAll: map[string]any{}}, Functions: []esast.ScoreFunctionSpec{{ScriptScore: &esast.ScriptScoreFunctionSpec{Script: map[string]any{"source": "1"}}}}}}},
		{"fs_fn_filter", esast.Query{FunctionScore: &esast.FunctionScoreQuery{Query: &esast.Query{MatchAll: map[string]any{}}, Functions: []esast.ScoreFunctionSpec{{Filter: &expensiveLeaf}}}}},
		{"pinned", esast.Query{Pinned: &esast.PinnedQuery{IDs: []string{"1"}, Organic: &expensiveLeaf}}},
		{"span_multi", esast.Query{SpanMulti: &esast.SpanMultiQuery{Match: &expensiveLeaf}}},
	} {
		if err := trExp.checkExpensiveQueryNode(&tc.q, nil); err == nil {
			t.Fatalf("%s: expected expensive query error", tc.name)
		}
	}
}

func TestRound67TopUp2Tr_PredicatesGeoSortAndScripts(t *testing.T) {
	sch := r67T2TRichSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	lambdaCtx := &nestedCtx{nestedPath: "items", elemVar: "_el", inLambda: true}
	nestedArrCtx := &nestedCtx{nestedPath: "items", elemVar: "_el", inLambda: false}

	// 1. lookupRawFieldPropertyR67 dotted properties
	props := map[string]esast.FieldProperty{
		"a.b": {Type: "keyword", Properties: map[string]esast.FieldProperty{"c": {Type: "long"}}},
	}
	if fp, ok := lookupRawFieldPropertyR67(props, []string{"a", "b"}); !ok || fp.Type != "keyword" {
		t.Fatalf("expected dotted match a.b, got (%+v, %v)", fp, ok)
	}
	if fp, ok := lookupRawFieldPropertyR67(props, []string{"a", "b", "c"}); !ok || fp.Type != "long" {
		t.Fatalf("expected dotted nested match a.b.c, got (%+v, %v)", fp, ok)
	}

	// 2. compileGeoPolygon in nestedCtx, lambdaCtx, and promoted array
	pts := [][2]float64{{40, -74}, {41, -74}, {41, -73}}
	for _, tc := range []struct {
		name  string
		field string
		ctx   *nestedCtx
	}{
		{"nested_elem", "items.loc", nestedArrCtx},
		{"lambda_arr", "geo_arr", lambdaCtx},
		{"flat_arr", "geo_arr", nil},
	} {
		cp := tr.compileGeoPolygon(&esast.GeoPolygonQuery{Field: tc.field, Points: pts}, true, tc.ctx)
		if cp.WhereSQL == "FALSE" || cp.WhereSQL == "" {
			t.Fatalf("%s: unexpected compileGeoPolygon result: %+v", tc.name, cp)
		}
	}

	// 3. compileGeoShape geometrycollection CONTAINS failure and DISJOINT empty children
	cpGCContainsFail := tr.compileGeoShape(&esast.GeoShapeQuery{
		Field:    "geo_sh",
		Relation: "CONTAINS",
		Shape: map[string]any{
			"type": "geometrycollection",
			"geometries": []map[string]any{
				{"type": "invalid_shape"},
			},
		},
	}, false, nil)
	if cpGCContainsFail.WhereSQL == "" {
		t.Fatalf("expected non-empty SQL for CONTAINS child, got %+v", cpGCContainsFail)
	}
	cpGCDisjoint := tr.compileGeoShape(&esast.GeoShapeQuery{
		Field:    "geo_sh",
		Relation: "DISJOINT",
		Shape: map[string]any{
			"type":       "geometrycollection",
			"geometries": []any{map[string]any{"type": "invalid_shape"}},
		},
	}, false, nil)
	if cpGCDisjoint.WhereSQL == "FALSE" {
		t.Fatalf("expected exists predicate for DISJOINT with no valid children, got %+v", cpGCDisjoint)
	}

	// 4. compileTermPredicate unsigned_long variants (int, int64, uint64, float64, json.Number)
	for _, v := range []any{int(5), int(-1), int64(6), int64(-2), uint64(7), float64(8.0), float64(8.5), json.Number("9"), json.Number("-1")} {
		_ = tr.compileTermPredicate("ul_val", v, false, nil)
	}
	// Version term predicate in array / nested / lambda
	for _, tc := range []struct {
		field string
		ctx   *nestedCtx
	}{
		{"ver_arr", nil},
		{"ver_arr", lambdaCtx},
		{"items.ver_n", nestedArrCtx},
		{"items.ver_n", lambdaCtx},
		{"items.ver_n", &nestedCtx{nestedPath: "other", elemVar: "_o"}},
	} {
		if pred := tr.compileTermPredicate(tc.field, "1.2.3+build", false, tc.ctx); pred == "FALSE" {
			t.Fatalf("expected version term pred for %s, got FALSE", tc.field)
		}
	}

	// 5. compileRangePredicate: DorisBigInt/LargeInt string & json.Number bounds, DynamicVariant array bounds, IP/Version array bounds
	for _, val := range []any{int(10), int64(20), uint64(30), float64(1.5), json.Number("42"), json.Number("42.5"), json.Number("18446744073709551615"), true} {
		_ = tr.compileRangePredicate("dyn_arr_field", esast.RangeCond{GTE: val, LTE: val}, lambdaCtx)
	}
	_ = tr.compileRangePredicate("ul_val", esast.RangeCond{GTE: "18446744073709551615", LTE: "999999999999999999999"}, nil)
	_ = tr.compileRangePredicate("ul_val", esast.RangeCond{GTE: json.Number("18446744073709551610"), LTE: "18446744073709551615"}, nil)
	_ = tr.compileRangePredicate("num", esast.RangeCond{GTE: "1e200", LTE: "-1e200"}, nil)
	_ = tr.compileRangePredicate("ver_arr", esast.RangeCond{GT: "1.0.0", GTE: "1.0.0", LT: "2.0.0", LTE: "2.0.0"}, lambdaCtx)
	_ = tr.compileRangePredicate("ver_arr", esast.RangeCond{GT: "1.0.0", LTE: "2.0.0"}, nil)
	_ = tr.compileRangePredicate("items.ver_n", esast.RangeCond{GTE: "1.0.0", LTE: "2.0.0"}, nestedArrCtx)
	_ = tr.compileRangePredicate("ip_arr", esast.RangeCond{GTE: "10.0.0.1", LTE: "10.0.0.2"}, lambdaCtx)
	_ = tr.compileRangePredicate("items.ip_n", esast.RangeCond{GTE: "10.0.0.1", LTE: "10.0.0.2"}, nestedArrCtx)

	// 6. compileWildcardPredicate on analyzed text arrays / lambda / nested multivalued
	_ = tr.compileWildcardPredicate("text_arr", "foo*", true, nil)
	_ = tr.compileWildcardPredicate("text_arr", "foo*", true, lambdaCtx)
	_ = tr.compileWildcardPredicate("items.tags", "foo*", true, nestedArrCtx)

	// 7. compileRegexp wildcard pattern on empty-field schema (falls back to _all_text)
	emptySch := r67T2TCompileSchema(t, `{"properties":{}}`)
	trEmpty := NewTranspiler(emptySch, TranspilerOptions{})
	cpReg := trEmpty.CompileQuery(&esast.Query{Regexp: map[string]esast.RegexpEntry{"*": {Value: "ab.*", Boost: 1.5, HasBoost: true}}}, true, nil)
	if cpReg.WhereSQL == "" {
		t.Fatalf("expected non-empty regexp SQL on empty schema")
	}

	// 8. compileMatchPhraseField with stopwords & english analyzer
	cpMPStop := tr.compileMatchPhraseField("title_eng", "the and", 0, 1.0, false, true, nil)
	if cpMPStop.WhereSQL != "FALSE" {
		t.Fatalf("expected FALSE for all-stopwords match_phrase, got %+v", cpMPStop)
	}
	cpMPEng := tr.compileMatchPhraseField("title_eng", "running fast horses", 1, 1.0, false, true, nil)
	if cpMPEng.WhereSQL == "FALSE" {
		t.Fatalf("expected non-FALSE for english match_phrase")
	}

	// 9. compileBool MustNot TRUE/FALSE & Nested inLambda with sibling path
	cpBool := tr.CompileQuery(&esast.Query{
		Bool: &esast.BoolQuery{
			MustNot: []esast.Query{
				{MatchAll: map[string]any{}},
				{MatchNone: map[string]any{}},
			},
		},
	}, true, nil)
	if cpBool.WhereSQL == "" {
		t.Fatalf("expected non-empty bool SQL")
	}
	cpNestLam := tr.CompileQuery(&esast.Query{
		Nested: &esast.NestedQuery{
			Path:      "items.sub",
			ScoreMode: "none",
			Query:     esast.Query{Term: map[string]esast.TermEntry{"items.sub.code": {Value: "x"}}},
		},
	}, true, lambdaCtx)
	if cpNestLam.ScoreSQL != "0.0" {
		t.Fatalf("expected ScoreSQL 0.0 for score_mode=none, got %q", cpNestLam.ScoreSQL)
	}
	boost2 := 2.0
	cpNestOther := tr.CompileQuery(&esast.Query{
		Nested: &esast.NestedQuery{
			Path:  "other_nested",
			Boost: &boost2,
			Query: esast.Query{MatchAll: map[string]any{}},
		},
	}, true, lambdaCtx)
	if cpNestOther.WhereSQL == "" {
		t.Fatalf("expected non-empty nested sibling SQL")
	}

	// 10. checkFieldPositionalSearchable _tsid & not indexed
	trErr := NewTranspiler(sch, TranspilerOptions{})
	if trErr.checkFieldPositionalSearchable("_tsid", schema.FieldBinding{}) {
		t.Fatalf("expected false for _tsid")
	}
	trErr2 := NewTranspiler(sch, TranspilerOptions{})
	if trErr2.checkFieldPositionalSearchable("title_unidx", schema.FieldBinding{NotIndexed: true}) {
		t.Fatalf("expected false for NotIndexed")
	}

	// 11. distance_feature & decay function & function_score boost_mode
	for _, orig := range []any{int(100), int64(200), float64(300), json.Number("400"), "500"} {
		dfQ := esast.Query{
			DistanceFeature: &esast.DistanceFeatureQuery{
				Field:  "dn",
				Origin: orig,
				Pivot:  "10s",
			},
		}
		if cp := tr.CompileQuery(&dfQ, true, nil); cp.ScoreSQL == "" {
			t.Fatalf("expected ScoreSQL for distance_feature origin %v", orig)
		}
	}
	_ = tr.CompileQuery(&esast.Query{
		DistanceFeature: &esast.DistanceFeatureQuery{
			Field:  "geo_arr",
			Origin: map[string]any{"lat": 40.0, "lon": -74.0},
			Pivot:  "1km",
		},
	}, true, lambdaCtx)

	_ = tr.compileDecayFunction("gauss", &esast.DecayFunctionSpec{
		Field:  "geo_arr",
		Origin: map[string]any{"lat": 40.0, "lon": -74.0},
		Scale:  "1km",
	}, lambdaCtx)

	for _, bm := range []string{"sum", "avg", "max", "min", "replace", "multiply"} {
		maxB := 2.0
		_ = tr.CompileQuery(&esast.Query{
			FunctionScore: &esast.FunctionScoreQuery{
				Query:     &esast.Query{MatchAll: map[string]any{}},
				BoostMode: bm,
				MaxBoost:  &maxB,
			},
		}, true, nil)
	}

	// 12. Scripts, Sort, TopHits, queryReferencesNestedPathR63
	if _, _, ok := tr.parseStringScriptExpr(`"hello\n\r\t\\\""`, nil, "title", "", nil, 0); !ok {
		t.Fatalf("expected escaped string script literal to parse")
	}
	if _, _, ok := tr.parseStringScriptExpr(`"bad\"quote" + "x"`, nil, "title", "", nil, 0); !ok {
		t.Fatalf("expected concat string script literal to parse")
	}
	if _, _, ok := tr.parseStringScriptExpr(`"unclosed\`, nil, "title", "", nil, 0); ok {
		t.Fatalf("expected trailing backslash literal to fail")
	}
	if _, ok := tr.parseSafeThresholdExpr("params.p1 + params.p2 + params.p3", map[string]any{
		"p1": int64(5),
		"p2": uint64(6),
		"p3": float64(1e20),
	}, 2, nil, 0); !ok {
		t.Fatalf("expected threshold params to compile")
	}
	_, _ = tr.resolveSortMissing(esast.SortSpec{Entry: esast.SortFieldSpec{Field: "dn", Missing: "1700000000"}}, schema.FieldBinding{ESType: "date_nanos"})
	_, _ = tr.resolveSortMissing(esast.SortSpec{Entry: esast.SortFieldSpec{Field: "dn", Missing: "invalid_date"}}, schema.FieldBinding{ESType: "date_nanos"})
	_ = tr.compileTopHitsOrderByWithNested([]esast.SortSpec{
		{Entry: esast.SortFieldSpec{Field: "items.dyn_f", Type: "double", Order: "asc"}},
		{Entry: esast.SortFieldSpec{Field: "items.dyn_f", Type: "unsigned_long", Order: "asc"}},
		{Entry: esast.SortFieldSpec{Field: "items.dyn_f", Type: "long", Order: "asc"}},
		{Entry: esast.SortFieldSpec{Field: "items.name", Order: "asc", Missing: "x"}},
	}, nestedArrCtx)
	_ = tr.sqlSortColumnRefWithType("items.dyn_nest_f", nil, false, "min", &esast.NestedSortSpec{Path: "items"}, "")
	_ = tr.queryReferencesNestedPathR63(&esast.Query{MatchPhrase: map[string]esast.PhraseEntry{"items.tags": {Query: "a"}}}, "items")
	_ = tr.queryReferencesNestedPathR63(&esast.Query{MatchPhrasePrefix: map[string]esast.PhraseEntry{"items.tags": {Query: "a"}}}, "items")
	_ = tr.queryReferencesNestedPathR63(&esast.Query{Exists: &esast.ExistsQuery{Field: "items.name"}}, "items")
	_ = tr.queryReferencesNestedPathR63(&esast.Query{KNN: &esast.KNNQuery{Field: "items.name"}}, "items")
}

func TestRound67TopUp2Tr_AggsLuceneAndIntervals(t *testing.T) {
	sch := r67T2TRichSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})

	// 1. TranspileSearch aggregations:
	// - grouped sub-aggs: weighted_avg, median_absolute_deviation (with script & missing), rare_terms on promoted array, auto_date_histogram (with script)
	// - top-level composite with after (json.Number, float64 int/uint64/frac, missing), date_histogram with missing+script, histogram with script, terms with script
	// - top-level percentile_ranks with script+missing (no field)
	// - top-level date_histogram with missing & script (no field)
	// - top-level auto_date_histogram & variable_width_histogram with script (no field)
	req := r67T2TUnmarshalReq(t, `{
		"size": 0,
		"aggs": {
			"by_status": {
				"terms": {"field": "status"},
				"aggs": {
					"wavg": {
						"weighted_avg": {
							"value": {"field": "num", "missing": 0, "script": {"source": "_value + 1"}},
							"weight": {"field": "dbl", "missing": 1, "script": {"source": "_value * 2"}}
						}
					},
					"mad": {
						"median_absolute_deviation": {
							"missing": 5,
							"script": {"source": "doc['num'].value + 1"}
						}
					},
					"rare_kw": {
						"rare_terms": {"field": "kw_arr", "max_doc_count": 2}
					},
					"adh_sub": {
						"auto_date_histogram": {
							"script": {"source": "doc['dt'].value + 1000"},
							"buckets": 5
						}
					}
				}
			},
			"comp": {
				"composite": {
					"size": 10,
					"after": {"k": "a", "d": 1700000000000, "f": 12.5, "big": 10000000000000000000},
					"sources": [
						{"k": {"terms": {"script": {"source": "doc['status'].value + '_x'"}}}},
						{"d": {"date_histogram": {"script": {"source": "doc['dt'].value + 1"}, "calendar_interval": "day", "missing": "2026-01-01"}}},
						{"f": {"histogram": {"script": {"source": "doc['dbl'].value + 1"}, "interval": 10}}},
						{"big": {"terms": {"field": "ul_val"}}}
					]
				}
			},
			"pr_script": {
				"percentile_ranks": {
					"values": [50],
					"script": {"source": "doc['num'].value * 2"},
					"missing": 10
				}
			},
			"dh_script": {
				"date_histogram": {
					"calendar_interval": "day",
					"script": {"source": "doc['dt'].value + 1000"},
					"missing": "2026-01-01"
				}
			},
			"adh_top": {
				"auto_date_histogram": {
					"script": {"source": "doc['dt'].value + 1000"},
					"buckets": 5
				}
			},
			"vwh_top": {
				"variable_width_histogram": {
					"script": {"source": "doc['dbl'].value + 1"},
					"buckets": 4
				}
			}
		}
	}`)
	planRes, err := tr.BuildSearchPlan(req)
	if err != nil {
		t.Fatalf("BuildSearchPlan aggs failed: %v", err)
	}
	sqlRes := planRes.AggsSQL
	if !strings.Contains(sqlRes, "PERCENTILE_APPROX") || !strings.Contains(sqlRes, "CONCAT_WS") {
		t.Fatalf("unexpected agg SQL: %s", sqlRes)
	}

	// 2. MoreLikeThis wildcard matching unsupported type (dense_vector) with fail_on_unsupported_field true/false
	mltSkip := esast.Query{
		MoreLikeThis: &esast.MoreLikeThisQuery{
			Fields:                 []string{"vec_*", "title^2"},
			Like:                   "hello world",
			FailOnUnsupportedField: func() *bool { b := false; return &b }(),
		},
	}
	if cp := tr.CompileQuery(&mltSkip, true, nil); cp.WhereSQL == "" {
		t.Fatalf("expected MLT skip unsupported SQL")
	}
	trMLTErr := NewTranspiler(sch, TranspilerOptions{})
	mltFail := esast.Query{
		MoreLikeThis: &esast.MoreLikeThisQuery{
			Fields:                 []string{"vec_*"},
			Like:                   "hello world",
			FailOnUnsupportedField: func() *bool { b := true; return &b }(),
		},
	}
	if cp := trMLTErr.CompileQuery(&mltFail, true, nil); cp.WhereSQL != "FALSE" {
		t.Fatalf("expected MLT fail_on_unsupported_field FALSE, got %+v", cp)
	}

	// 3. Lucene [* TO *] with fields containing *, _all_text, and field^boost
	if q := buildLuceneAtomQueryWithFlags("[* TO *]", "title", []string{"*", "_all_text^2", "title^1.5"}, "OR", 0, false, allSimpleQueryFlags()); q.Bool == nil {
		t.Fatalf("expected Bool query for multi-field [* TO *], got %+v", q)
	}
	if q := buildLuceneAtomQueryWithFlags("[* TO *]", "title", []string{"*"}, "OR", 0, false, allSimpleQueryFlags()); q.MatchAll == nil {
		t.Fatalf("expected MatchAll for single * field [* TO *], got %+v", q)
	}
	if q := buildLuceneAtomQueryWithFlags("[* TO *]^2", "*", nil, "OR", 0, false, allSimpleQueryFlags()); q.ConstantScore == nil {
		t.Fatalf("expected ConstantScore for boosted [* TO *]^2, got %+v", q)
	}
	if q := buildLuceneAtomQueryWithFlags("[* TO *]", "title", []string{"title^1.5"}, "OR", 0, false, allSimpleQueryFlags()); q.ConstantScore == nil {
		t.Fatalf("expected ConstantScore for boosted field [* TO *], got %+v", q)
	}

	// 4. EvaluateIntervalsRule & EvaluateIntervalsRuleForDoc filter error propagation across all filter clauses
	boom := errors.New("boom")
	subMatch := &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "beta"}}
	errFilterRule := &esast.IntervalsRule{
		Match: &esast.IntervalsMatch{
			Query:  "beta",
			Filter: &esast.IntervalsFilter{Script: &esast.ScriptSpec{Source: "fail"}},
		},
	}
	makeFilterRule := func(f *esast.IntervalsFilter) *esast.IntervalsRule {
		return &esast.IntervalsRule{
			Match: &esast.IntervalsMatch{
				Query:  "alpha",
				Filter: f,
			},
		}
	}
	// All filter branches success + error propagation
	allFilters := makeFilterRule(&esast.IntervalsFilter{
		Containing:     subMatch,
		NotContaining:  subMatch,
		ContainedBy:    subMatch,
		NotContainedBy: subMatch,
		Overlapping:    subMatch,
		NotOverlapping: subMatch,
		After:          subMatch,
		Before:         subMatch,
		Script:         &esast.ScriptSpec{Source: "ok"},
	})
	_, _, _ = EvaluateIntervalsRule(allFilters, "alpha beta", "standard", func(_ *esast.ScriptSpec, _ IntervalsSpan) (bool, error) {
		return true, nil
	})
	_, _, _ = EvaluateIntervalsRuleWithAnalysis("title", allFilters, func(_ string) ([]string, string) {
		return []string{"alpha beta"}, "standard"
	}, nil, analysis.Options{}, func(_ *esast.ScriptSpec, _ IntervalsSpan) (bool, error) {
		return true, nil
	})

	for _, f := range []*esast.IntervalsFilter{
		{Containing: errFilterRule},
		{NotContaining: errFilterRule},
		{ContainedBy: errFilterRule},
		{NotContainedBy: errFilterRule},
		{Overlapping: errFilterRule},
		{NotOverlapping: errFilterRule},
		{After: errFilterRule},
		{Before: errFilterRule},
		{Script: &esast.ScriptSpec{Source: "fail"}},
	} {
		r := makeFilterRule(f)
		if _, _, err := EvaluateIntervalsRule(r, "alpha beta", "standard", func(_ *esast.ScriptSpec, _ IntervalsSpan) (bool, error) {
			return false, boom
		}); err == nil {
			t.Fatalf("EvaluateIntervalsRule: expected error propagation")
		}
		if _, _, err := EvaluateIntervalsRuleWithAnalysis("title", r, func(_ string) ([]string, string) {
			return []string{"alpha beta"}, "standard"
		}, nil, analysis.Options{}, func(_ *esast.ScriptSpec, _ IntervalsSpan) (bool, error) {
			return false, boom
		}); err == nil {
			t.Fatalf("EvaluateIntervalsRuleWithAnalysis: expected error propagation")
		}
	}
}
