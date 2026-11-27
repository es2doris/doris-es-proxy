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

func r67TTrCompileSchema(t *testing.T, mappingJSON string) *schema.IndexSchema {
	t.Helper()
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(mappingJSON), &spec); err != nil {
		t.Fatalf("unmarshal mapping spec failed: %v", err)
	}
	return schema.CompileIndexSchema("es_db", "r67t_tr_idx", &spec)
}

func r67TTrRichSchema(t *testing.T) *schema.IndexSchema {
	t.Helper()
	sch := r67TTrCompileSchema(t, `{
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
		"runtime": {
			"rt_kw": {"type": "keyword"}
		},
		"properties": {
			"title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"title_syn": {"type": "text", "analyzer": "syn_an"},
			"title_eng": {"type": "text", "analyzer": "english"},
			"title_ws": {"type": "text", "analyzer": "whitespace"},
			"title_unidx": {"type": "text", "index": false},
			"mot": {"type": "match_only_text"},
			"sayt": {"type": "search_as_you_type", "max_shingle_size": 4},
			"status": {"type": "keyword"},
			"kw_lc": {"type": "keyword", "normalizer": "lc_norm", "ignore_above": 10},
			"kw_arr": {"type": "keyword", "multi_valued": true},
			"ul_val": {"type": "unsigned_long"},
			"ul_arr": {"type": "unsigned_long", "multi_valued": true},
			"num": {"type": "long"},
			"num_arr": {"type": "long", "multi_valued": true},
			"dbl": {"type": "double"},
			"flag": {"type": "boolean"},
			"dt": {"type": "date"},
			"dt_fmt": {"type": "date", "format": "yyyy-MM-dd"},
			"dt_sec": {"type": "date", "format": "epoch_second"},
			"dn": {"type": "date_nanos"},
			"dn_sec": {"type": "date_nanos", "format": "epoch_second"},
			"dn_ns": {"type": "date_nanos", "format": "epoch_nanos"},
			"ip_addr": {"type": "ip"},
			"ver": {"type": "version", "ignore_above": 12},
			"ver_arr": {"type": "version", "multi_valued": true},
			"geo_pt": {"type": "geo_point"},
			"geo_arr": {"type": "geo_point", "multi_valued": true},
			"sv": {"type": "sparse_vector"},
			"hist": {"type": "histogram"},
			"al_hist": {"type": "alias", "path": "hist"},
			"vec_i4": {"type": "dense_vector", "dims": 4, "index_options": {"type": "int4_hnsw"}},
			"vec_i8": {"type": "dense_vector", "dims": 4, "index_options": {"type": "int8_hnsw"}},
			"items": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword", "normalizer": "lc_norm"},
					"tags": {"type": "text", "analyzer": "whitespace"},
					"qty": {"type": "long", "multi_valued": true},
					"qty_s": {"type": "long"},
					"ul_n": {"type": "unsigned_long"},
					"flag_n": {"type": "boolean"},
					"ver_n": {"type": "version", "multi_valued": true},
					"loc": {"type": "geo_point"},
					"hist_n": {"type": "histogram"},
					"al_hist_n": {"type": "alias", "path": "items.hist_n"},
					"emb": {"type": "dense_vector", "dims": 2, "similarity": "cosine"},
					"bitvec": {"type": "dense_vector", "dims": 8, "element_type": "bit", "similarity": "l2_norm"},
					"bvec": {"type": "dense_vector", "dims": 2, "element_type": "byte", "similarity": "l2_norm"}
				}
			}
		}
	}`)
	return sch
}

func r67TTrUnmarshalReq(t *testing.T, raw string) *esast.SearchRequest {
	t.Helper()
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal SearchRequest failed: %v\nraw: %s", err, raw)
	}
	return &req
}

func r67TTrUnmarshalQuery(t *testing.T, raw string) *esast.Query {
	t.Helper()
	var q esast.Query
	if err := json.Unmarshal([]byte(raw), &q); err != nil {
		t.Fatalf("unmarshal Query failed: %v\nraw: %s", err, raw)
	}
	return &q
}

func TestRound67TopUpTranspiler_MatchBoolPrefixAndCommonTerms(t *testing.T) {
	sch := r67TTrRichSchema(t)

	// 1. round62_transpiler.go: L3039-3071 (multi-token graph alternative with DisableSynonymsPhraseQuery=true,
	// operator="or"/"and", scoring=true, and isLast vs non-last) + L3110-3139 (keyword analyzer, exact keyword field,
	// custom query analysis, broken analyzer error, stop/english analyzer).
	trNoSynPhrase := NewTranspiler(sch, TranspilerOptions{
		ES8Compat:                  true,
		DisableSynonymsPhraseQuery: true,
	})
	for _, tc := range []struct {
		name  string
		field string
		pe    esast.PhraseEntry
	}{
		{"syn_or", "title_syn", esast.PhraseEntry{Query: "ny express", Operator: "or", Boost: 1.5}},
		{"syn_and", "title_syn", esast.PhraseEntry{Query: "ny express", Operator: "and", Boost: 1.0}},
		{"syn_mid_multi", "title_syn", esast.PhraseEntry{Query: "ny train", Operator: "and"}},
		{"kw_an", "title", esast.PhraseEntry{Query: "Exact Value", Analyzer: "keyword"}},
		{"exact_kw", "status", esast.PhraseEntry{Query: "OPEN"}},
		{"eng_stop", "title_eng", esast.PhraseEntry{Query: "the quick fox", Analyzer: "english"}},
		{"stop_an", "title", esast.PhraseEntry{Query: "the and or", Analyzer: "stop", ZeroTermsQuery: "all"}},
		{"custom_an", "title", esast.PhraseEntry{Query: "ny", Analyzer: "syn_an"}},
	} {
		cp := trNoSynPhrase.compileMatchBoolPrefixRound62Opts(tc.field, tc.pe, nil, true, nil)
		if cp.WhereSQL == "" {
			t.Errorf("%s: empty WhereSQL", tc.name)
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
		t.Fatalf("expected error on broken custom analyzer, got cp=%+v err=%v", cpBad, trBadAn.searchErr)
	}

	// 2. round62_transpiler.go: L3528-3597 (Lucene explain formatters + date/numeric histogram bound ptr helpers)
	cfg := sch.AnalysisConfig
	if cfg != nil {
		gotBoolPfx := formatAnalyzedBoolPrefixLuceneExplain("title_syn", "fast ny", "and", "syn_an", cfg, analysis.Options{})
		if !strings.Contains(gotBoolPfx, "title_syn:") {
			t.Fatalf("unexpected formatAnalyzedBoolPrefixLuceneExplain: %q", gotBoolPfx)
		}
		gotQSPhrase := formatQueryStringLuceneExplain("title_syn", `"fast ny*"`, "or", "syn_an", cfg, analysis.Options{})
		if !strings.Contains(gotQSPhrase, "title_syn:") {
			t.Fatalf("unexpected formatQueryStringLuceneExplain phrase: %q", gotQSPhrase)
		}
		gotQSField := formatQueryStringLuceneExplain("title", "title_syn:ny", "and", "syn_an", cfg, analysis.Options{})
		if !strings.Contains(gotQSField, "title_syn:") {
			t.Fatalf("unexpected formatQueryStringLuceneExplain field: %q", gotQSField)
		}
	}
	if p := trNoSynPhrase.resolveDateHistogramBoundFloatPtr(schema.FieldBinding{Format: "yyyy-MM-dd"}, "", "2026-01-01"); p == nil || *p <= 0 {
		t.Fatalf("expected valid date histogram bound ptr, got %v", p)
	}
	if p := trNoSynPhrase.resolveDateHistogramBoundFloatPtr(schema.FieldBinding{}, "", nil); p != nil {
		t.Fatalf("expected nil for nil date bound, got %v", *p)
	}
	if p := trNoSynPhrase.resolveDateHistogramBoundFloatPtr(schema.FieldBinding{}, "", "not-a-date"); p != nil {
		t.Fatalf("expected nil for invalid date bound, got %v", *p)
	}
	if p := resolveHistogramBoundFloatPtr(42.5); p == nil || *p != 42.5 {
		t.Fatalf("expected 42.5, got %v", p)
	}
	if p := resolveHistogramBoundFloatPtr(nil); p != nil {
		t.Fatalf("expected nil for nil histogram bound")
	}
	if p := resolveHistogramBoundFloatPtr("bad"); p != nil {
		t.Fatalf("expected nil for invalid histogram bound")
	}

	// 3. round62_transpiler.go: L2753-2760 (common terms where low or high compiled == FALSE)
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
	if cp, ok := trCT.compileCommonTermsQueryR64("title", "common rare", "or", "or", 0.5, nil, "", "", 1.0, true, nil, true); !ok || cp.WhereSQL == "FALSE" {
		t.Fatalf("expected common terms low+high OR to compile, ok=%v cp=%+v", ok, cp)
	}
}

func TestRound67TopUpTranspiler_RegexpTermTermsRangeAndSort(t *testing.T) {
	sch := r67TTrRichSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	lambdaCtx := &nestedCtx{nestedPath: "items", elemVar: "_el", inLambda: true}
	nestedNonLambdaCtx := &nestedCtx{nestedPath: "items", elemVar: "_el", inLambda: false}

	// 1. transpiler.go: L735-754 (RE2 multiline helpers + flatArray helpers)
	if got := injectMultilineFlagRE2R67("(?i)abc"); got != "(?im)abc" {
		t.Fatalf("expected (?im)abc, got %q", got)
	}
	if got := injectMultilineFlagRE2R67("(?m)abc"); got != "(?m)abc" {
		t.Fatalf("expected (?m)abc, got %q", got)
	}
	if got := injectMultilineFlagRE2R67("abc"); got != "(?m)abc" {
		t.Fatalf("expected (?m)abc, got %q", got)
	}
	if got := flatArrayRegexpSQLR67("`f__kw_arr`", "^a.*"); !strings.Contains(got, "ARRAY_JOIN") {
		t.Fatalf("expected ARRAY_JOIN in flatArrayRegexpSQLR67, got %s", got)
	}
	if got := flatArrayExactCISQLR67("`f__kw_arr`", "Abc"); !strings.Contains(got, "LIKE") {
		t.Fatalf("expected LIKE in flatArrayExactCISQLR67, got %s", got)
	}

	// 2. transpiler.go: L1416-1443 & L1456-1474 (Regexp on _ignored raw/lucene/invalid + ul_arr/nestedCtx raw RE2)
	for _, tc := range []struct {
		name string
		q    *esast.Query
		nctx *nestedCtx
	}{
		{"ign_raw_re2", &esast.Query{Regexp: map[string]esast.RegexpEntry{"_ignored": {Value: "foo.*", Flags: internalRawRE2Flag, CaseInsensitive: true}}}, nil},
		{"ign_lucene", &esast.Query{Regexp: map[string]esast.RegexpEntry{"_ignored": {Value: "foo.*"}}}, nil},
		{"ign_bad_re", &esast.Query{Regexp: map[string]esast.RegexpEntry{"_ignored": {Value: "[unclosed"}}}, nil},
		{"unsearchable_vec", &esast.Query{Regexp: map[string]esast.RegexpEntry{"vec_i4": {Value: "1.*"}}}, nil},
		{"ul_arr_lambda", &esast.Query{Regexp: map[string]esast.RegexpEntry{"ul_arr": {Value: "12.*", Flags: internalRawRE2Flag, CaseInsensitive: true}}}, lambdaCtx},
		{"ul_arr_root", &esast.Query{Regexp: map[string]esast.RegexpEntry{"ul_arr": {Value: "12.*", Flags: internalRawRE2Flag}}}, nil},
		{"nested_mv_raw", &esast.Query{Regexp: map[string]esast.RegexpEntry{"items.qty": {Value: "5.*", Flags: internalRawRE2Flag}}}, nestedNonLambdaCtx},
	} {
		trLocal := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
		cp := trLocal.CompileQuery(tc.q, true, tc.nctx)
		if cp.WhereSQL == "" {
			t.Errorf("%s: empty WhereSQL", tc.name)
		}
	}

	// 3. transpiler.go: L1974-1985 (compileGeoBoundingBox on StoragePromotedArray in & out of lambda)
	bbox := &esast.GeoBoundingBoxQuery{Field: "geo_arr", Top: 50, Bottom: 10, Left: -10, Right: 20}
	if cp := tr.compileGeoBoundingBox(bbox, true, lambdaCtx); !strings.Contains(cp.WhereSQL, "element_at(") {
		t.Fatalf("expected element_at in lambda geo_bounding_box, got %s", cp.WhereSQL)
	}
	if cp := tr.compileGeoBoundingBox(bbox, true, nil); !strings.Contains(cp.WhereSQL, "array_exists(") {
		t.Fatalf("expected array_exists in root geo_bounding_box, got %s", cp.WhereSQL)
	}

	// 4. transpiler.go: L3490-3510 (compileMatchPhraseField english stopwords + builtin graph)
	if cp := tr.compileMatchPhraseField("title_eng", "the and of", 0, 1.0, false, true, nil); cp.WhereSQL != "FALSE" {
		t.Fatalf("expected all-stopword phrase -> FALSE, got %s", cp.WhereSQL)
	}
	if cp := tr.compileMatchPhraseField("title_eng", "the running foxes", 1, 1.0, false, true, nil); cp.WhereSQL == "FALSE" {
		t.Fatalf("expected english phrase with partial stopwords to compile, got %+v", cp)
	}

	// 5. transpiler.go: L4900-4909, L4983-4997 (parseBooleanScriptCond)
	for _, expr := range []string{
		"!(doc['num'].value > 5)",
		"!true",
		"!false",
		"params.ok",
		"doc['flag'].value",
	} {
		if sqlExpr, ok := tr.parseBooleanScriptCond(expr, map[string]any{"ok": true}, nil, 0); !ok || sqlExpr == "" {
			t.Errorf("parseBooleanScriptCond(%q) failed: ok=%v sql=%q", expr, ok, sqlExpr)
		}
	}

	// 6. transpiler.go: L6036-6056, L6186-6203, L6255-6297 (compileTermPredicate)
	termCases := []struct {
		field string
		val   any
		ci    bool
		nctx  *nestedCtx
	}{
		{"items.tags", "hello", false, nestedNonLambdaCtx},
		{"sv", "tok1", false, nil},
		{"sayt._index_prefix", "hel", false, nil},
		{"sayt", "   ", false, nil},
		{"sayt", "two words", false, nil},
		{"dt_fmt", "1700000000000", false, nil},
		{"dt_fmt", "bad-date", false, nil},
		{"dt_fmt", 1700000000000, false, nil},
		{"dt_fmt", int64(1700000000000), false, nil},
		{"dt_fmt", float64(1700000000000), false, nil},
		{"dt_fmt", json.Number("1700000000000"), false, nil},
		{"kw_lc", 123, false, nil},
		{"ul_val", json.Number("18446744073709551615"), false, nil},
		{"ul_val", json.Number("-5"), false, nil},
		{"ul_val", json.Number("10.0"), false, nil},
		{"ul_val", json.Number("bad"), false, nil},
		{"num", json.Number("notanint"), false, nil},
	}
	for _, tc := range termCases {
		if got := tr.compileTermPredicate(tc.field, tc.val, tc.ci, tc.nctx); got == "" {
			t.Errorf("empty compileTermPredicate(%s, %v)", tc.field, tc.val)
		}
	}

	// 7. transpiler.go: L6527-6541, L6560-6592, L6710-6753 (compileTermsPredicateWithCI)
	termsCases := []struct {
		field string
		vals  []any
		nctx  *nestedCtx
	}{
		{"vec_i4", []any{"1"}, nil},
		{"sayt._index_prefix", []any{"ab", "cd"}, nil},
		{"ver", []any{"1.0.0", "1.2.3.4.5.6.7.8.9"}, nil},
		{"ver_arr", []any{"1.0.0"}, lambdaCtx},
		{"ver_arr", []any{"1.0.0"}, nil},
		{"items.ver_n", []any{"1.0.0"}, nestedNonLambdaCtx},
		{"items.ver_n", []any{"1.0.0"}, lambdaCtx},
		{"kw_lc", []any{100, 200}, nil},
		{"ul_val", []any{int(-1), int64(-2), float64(3.5), float64(4.0), json.Number("18446744073709551615"), json.Number("-1"), json.Number("5.0"), json.Number("bad")}, nil},
		{"num", []any{json.Number("42"), json.Number("bad")}, nil},
	}
	for _, tc := range termsCases {
		if got := tr.compileTermsPredicateWithCI(tc.field, tc.vals, true, tc.nctx); got == "" {
			t.Errorf("empty compileTermsPredicateWithCI(%s)", tc.field)
		}
	}

	// 8. transpiler.go: L7576-7643 & L7772-7791 (compileRangeSingleField)
	rangeCases := []struct {
		field string
		rc    esast.RangeCond
		nctx  *nestedCtx
	}{
		{"ul_val", esast.RangeCond{GTE: "18446744073709551615", LTE: "18446744073709551615"}, nil},
		{"ul_val", esast.RangeCond{GTE: "9223372036854775808.0", LT: "18446744073709551616.0"}, nil},
		{"ul_val", esast.RangeCond{GTE: json.Number("18446744073709551615")}, nil},
		{"num", esast.RangeCond{GTE: "9223372036854775808.0", LTE: "-99999999999999999999.0"}, nil},
		{"unmapped_dt", esast.RangeCond{GTE: "2026-01-01", LTE: "2026-01-02", Format: "yyyy-MM-dd", TimeZone: "+02:00"}, nil},
		{"dt_sec", esast.RangeCond{GT: 100, GTE: int64(101), LT: float64(200), LTE: json.Number("201")}, nil},
		{"dt_sec", esast.RangeCond{GTE: json.Number("10.5")}, nil},
		// Unmapped array/nested range sampleBound inference (L7772-7791)
		{"items.unmapped_b", esast.RangeCond{GTE: true}, nestedNonLambdaCtx},
		{"items.unmapped_u", esast.RangeCond{GTE: uint64(5)}, nestedNonLambdaCtx},
		{"items.unmapped_i", esast.RangeCond{GTE: int64(5)}, nestedNonLambdaCtx},
		{"items.unmapped_fi", esast.RangeCond{GTE: float64(5.0)}, nestedNonLambdaCtx},
		{"items.unmapped_ff", esast.RangeCond{GTE: float64(5.5)}, nestedNonLambdaCtx},
		{"items.unmapped_ji", esast.RangeCond{GTE: json.Number("5")}, nestedNonLambdaCtx},
		{"items.unmapped_ju", esast.RangeCond{GTE: json.Number("18446744073709551615")}, nestedNonLambdaCtx},
		{"items.unmapped_jf", esast.RangeCond{GTE: json.Number("5.5")}, nestedNonLambdaCtx},
	}
	for _, tc := range rangeCases {
		if got := tr.compileRangeSingleField(tc.field, tc.rc, tc.nctx); got == "" {
			t.Errorf("empty compileRangeSingleField(%s)", tc.field)
		}
	}
}

func TestRound67TopUpTranspiler_AggsGeoNestedAndSQL(t *testing.T) {
	sch := r67TTrRichSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	lambdaCtx := &nestedCtx{nestedPath: "items", elemVar: "_el", inLambda: true}

	// 1. transpiler.go: L10228-10243, L10314-10333, L10378-10401, L12441-12468, L12586-12610
	reqAggs := r67TTrUnmarshalReq(t, `{
		"size": 0,
		"aggs": {
			"comp_after": {
				"composite": {
					"after": {"k1": 100, "k2": 9223372036854775808, "k3": null},
					"sources": [
						{"k1": {"terms": {"field": "num"}}},
						{"k2": {"terms": {"field": "ul_val"}}},
						{"k3": {"terms": {"field": "status"}}}
					]
				}
			},
			"comp_hist_dh": {
				"composite": {
					"sources": [
						{"dh_miss": {"date_histogram": {"field": "dt", "calendar_interval": "day", "missing": "2026-01-01"}}},
						{"dh_mb": {"date_histogram": {"field": "dt", "calendar_interval": "day", "missing_bucket": true}}},
						{"h_scr": {"histogram": {"script": {"source": "doc['num'].value * 2"}, "interval": 10}}}
					]
				},
				"aggs": {
					"sub_mad": {"median_absolute_deviation": {"script": {"source": "doc['dbl'].value + 1"}, "missing": 0}}
				}
			},
			"top_mad": {
				"median_absolute_deviation": {"script": {"source": "doc['dbl'].value * 2"}, "missing": 1.0}
			},
			"rare_arr": {
				"rare_terms": {"field": "kw_arr", "max_doc_count": 2},
				"aggs": {"avg_d": {"avg": {"field": "dbl"}}}
			},
			"rare_bool": {
				"rare_terms": {"field": "flag", "missing": false}
			},
			"rare_lc": {
				"rare_terms": {"field": "kw_lc", "missing": "none"}
			}
		}
	}`)
	// Force float64 integer values into comp_after.After to cover float64 branches at L10230-10237
	if compSpec := reqAggs.Aggs["comp_after"].Composite; compSpec != nil {
		compSpec.After["k1"] = float64(42)
		compSpec.After["k2"] = float64(18446744073709551616.0 / 2.0)
	}
	planAggs, err := tr.BuildSearchPlan(reqAggs)
	if err != nil {
		t.Fatalf("reqAggs BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(planAggs.AggsSQL, "PERCENTILE_APPROX") {
		t.Fatalf("expected PERCENTILE_APPROX in MAD agg SQL, got:\n%s", planAggs.AggsSQL)
	}

	// 2. transpiler.go: L12954-12971, L13033-13050, L13118-13167, L13258-13272, L13333-13352
	if ms, ok := tr.resolveDateHistogramMissingMs("date", float64(1700000000000)); !ok || ms != 1700000000000 {
		t.Fatalf("unexpected resolveDateHistogramMissingMs float64: %d %v", ms, ok)
	}
	if ms, ok := tr.resolveDateHistogramMissingMs("date", json.Number("1700000000000")); !ok || ms != 1700000000000 {
		t.Fatalf("unexpected resolveDateHistogramMissingMs json.Number int: %d %v", ms, ok)
	}
	if ms, ok := tr.resolveDateHistogramMissingMs("date", json.Number("1700000000000.0")); !ok || ms != 1700000000000 {
		t.Fatalf("unexpected resolveDateHistogramMissingMs json.Number float: %d %v", ms, ok)
	}
	if s, e, ok := parseIPv6CIDRHexBounds("::ffff:10.0.0.0/120"); !ok || s == "" || e == "" {
		t.Fatalf("expected valid IPv4-mapped IPv6 CIDR bounds, got %s %s %v", s, e, ok)
	}
	if _, _, ok := parseIPv6CIDRHexBounds("not-a-cidr"); ok {
		t.Fatalf("expected false for non-cidr")
	}
	if _, _, ok := parseIPv6CIDRHexBounds("2001:db8::/999"); ok {
		t.Fatalf("expected false for invalid IPv6 CIDR")
	}
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	for _, v := range []any{1700000000, int64(1700000000), float64(1700000000), float64(1700000000.5), json.Number("1700000000"), json.Number("1700000000.5"), true} {
		_, _ = parseDateNanosQueryScalar(v, "epoch_second", 0, now, false)
	}
	if ns, ok := parseDateNanosNumericScalar("1700000000", 1700000000, true, "epoch_nanos", now, false); !ok || ns == 0 {
		t.Fatalf("unexpected parseDateNanosNumericScalar epoch_nanos: %d %v", ns, ok)
	}
	if expr := tr.histogramArrayExpr("items.al_hist_n", sch.Fields["items.al_hist_n"], lambdaCtx); !strings.Contains(expr, "json_extract_string") {
		t.Fatalf("expected nested alias histogramArrayExpr, got %s", expr)
	}
	var topHitsSorts []esast.SortSpec
	_ = json.Unmarshal([]byte(`[
		{"items.unmapped_d": {"order": "asc", "numeric_type": "double", "missing": "_first"}},
		{"items.unmapped_u": {"order": "desc", "numeric_type": "unsigned_long"}},
		{"items.unmapped_l": {"order": "asc", "numeric_type": "long"}},
		{"items.name": {"order": "asc", "missing": "zzz"}}
	]`), &topHitsSorts)
	if ob := tr.compileTopHitsOrderByWithNested(topHitsSorts, lambdaCtx); !strings.Contains(ob, "NULLS FIRST") {
		t.Fatalf("unexpected compileTopHitsOrderByWithNested: %s", ob)
	}
	if v := tr.coerceRangeAggBoundWithNow("dn_sec", &esast.RangeAggSpec{Format: "epoch_second"}, json.Number("10"), now); v != int64(10000) {
		t.Fatalf("expected epoch_second json.Number 10 -> 10000, got %#v", v)
	}
	_ = tr.coerceRangeAggBoundWithNow("dn_ns", nil, "1700000000000000000", now)
	_ = tr.coerceRangeAggBoundWithNow("dn_sec", &esast.RangeAggSpec{Format: "epoch_second"}, 10, now)
	_ = tr.coerceRangeAggBoundWithNow("dn_sec", &esast.RangeAggSpec{Format: "epoch_second"}, int64(10), now)
	_ = tr.coerceRangeAggBoundWithNow("dn_sec", &esast.RangeAggSpec{Format: "epoch_second"}, float64(10), now)
	_ = tr.coerceRangeAggBoundWithNow("dn_sec", &esast.RangeAggSpec{Format: "epoch_second"}, json.Number("10.5"), now)

	// 3. transpiler.go: L15520-15536 (nested sort without prefilter + dynamic nested field sort)
	var sortSpecs []esast.SortSpec
	_ = json.Unmarshal([]byte(`[{"items.dyn_field": {"order": "asc"}}]`), &sortSpecs)
	if ob := tr.compileOrderBy(sortSpecs); !strings.Contains(ob, "items") || !strings.Contains(ob, "NULLS LAST") {
		t.Fatalf("unexpected nested dynamic sort: %s", ob)
	}

	// 4. transpiler.go: L16078-16102 & L16130-16141 (validateHistogramSpec & validateDateHistogramSpec errors)
	sz0 := 0
	for _, tc := range []esast.AggSpec{
		{Histogram: &esast.HistogramAggSpec{Field: "dbl", Interval: 10, HardBounds: &esast.HistogramBoundsSpec{Min: 0, Max: "bad"}}},
		{Histogram: &esast.HistogramAggSpec{Field: "dbl", Interval: 10, HardBounds: &esast.HistogramBoundsSpec{Min: 50, Max: 10}}},
		{DateHistogram: &esast.DateHistogramAggSpec{Field: "dt", CalendarInterval: "day", TimeZone: "Bad/Zone"}},
		{DateHistogram: &esast.DateHistogramAggSpec{Field: "dt", CalendarInterval: "day", ExtendedBounds: &esast.HistogramBoundsSpec{Min: "2026-01-01", Max: "bad-date"}}},
		{DateHistogram: &esast.DateHistogramAggSpec{Field: "dt", CalendarInterval: "day", HardBounds: &esast.HistogramBoundsSpec{Min: "2026-02-01", Max: "2026-01-01"}}},
	} {
		trErr := NewTranspiler(sch, TranspilerOptions{})
		if _, bErr := trErr.BuildSearchPlan(&esast.SearchRequest{Size: &sz0, Aggs: map[string]esast.AggSpec{"a": tc}}); bErr == nil {
			t.Errorf("expected BuildSearchPlan validation error for %+v", tc)
		}
	}

	// 5. transpiler.go: L16897-16913 (compileGeoPolygon in nestedCtx + StoragePromotedArray lambda & non-lambda)
	polyQ := &esast.GeoPolygonQuery{
		Field:  "geo_arr",
		Points: [][2]float64{{0, 0}, {0, 10}, {10, 10}, {10, 0}},
	}
	if cp := tr.compileGeoPolygon(polyQ, true, lambdaCtx); !strings.Contains(cp.WhereSQL, "element_at(") {
		t.Fatalf("expected element_at in lambda geo_polygon, got %s", cp.WhereSQL)
	}
	if cp := tr.compileGeoPolygon(polyQ, true, nil); !strings.Contains(cp.WhereSQL, "array_exists(") {
		t.Fatalf("expected array_exists in array geo_polygon, got %s", cp.WhereSQL)
	}
	nestedPolyQ := &esast.GeoPolygonQuery{
		Field:  "items.loc",
		Points: [][2]float64{{0, 0}, {0, 10}, {10, 10}, {10, 0}},
	}
	if cp := tr.compileGeoPolygon(nestedPolyQ, true, lambdaCtx); !strings.Contains(cp.WhereSQL, "json_extract_string") {
		t.Fatalf("expected json_extract_string in nested geo_polygon, got %s", cp.WhereSQL)
	}

	// 6. transpiler.go: L17452-17466 (geo_shape GeometryCollection CONTAINS / DISJOINT with empty child preds)
	for _, gsJSON := range []string{
		`{"geo_shape":{"geo_pt":{"shape":{"type":"geometrycollection","geometries":[{"type":"point","coordinates":[0,0]}]},"relation":"CONTAINS"}}}`,
		`{"geo_shape":{"geo_pt":{"shape":{"type":"geometrycollection","geometries":[{"type":"point","coordinates":[0,0]}]},"relation":"DISJOINT"}}}`,
	} {
		if cp := tr.CompileQuery(r67TTrUnmarshalQuery(t, gsJSON), true, nil); cp.WhereSQL == "" {
			t.Errorf("empty geo_shape SQL for %s", gsJSON)
		}
	}

	// 7. transpiler.go: L18062-18095 (intervals prefix/wildcard/fuzzy with unsearchable field + filter)
	for _, ivJSON := range []string{
		`{"intervals":{"title":{"prefix":{"prefix":"qu","use_field":"title_unidx"}}}}`,
		`{"intervals":{"title":{"wildcard":{"pattern":"qu*","use_field":"title_unidx"}}}}`,
		`{"intervals":{"title":{"fuzzy":{"term":"quik","use_field":"title_unidx"}}}}`,
		`{"intervals":{"title":{"prefix":{"prefix":"qu","filter":{"not_containing":{"match":{"query":"bad"}}}}}}}`,
		`{"intervals":{"title":{"wildcard":{"pattern":"qu*","filter":{"not_containing":{"match":{"query":"bad"}}}}}}}`,
		`{"intervals":{"title":{"fuzzy":{"term":"quik","fuzziness":1,"filter":{"not_containing":{"match":{"query":"bad"}}}}}}}`,
	} {
		trLocal := NewTranspiler(sch, TranspilerOptions{})
		if cp := trLocal.CompileQuery(r67TTrUnmarshalQuery(t, ivJSON), true, nil); cp.WhereSQL == "" {
			t.Errorf("empty intervals SQL for %s", ivJSON)
		}
	}

	// 8. transpiler.go: L18648-18661, L18711-18718, L19066-19073, L19169-19197
	for _, dfQ := range []*esast.Query{
		{DistanceFeature: &esast.DistanceFeatureQuery{Field: "dn", Origin: int64(1700000000000), Pivot: "badpivot"}},
		{DistanceFeature: &esast.DistanceFeatureQuery{Field: "dn", Origin: int64(1700000000), Pivot: "5d"}},
		{DistanceFeature: &esast.DistanceFeatureQuery{Field: "geo_pt", Origin: []any{1.0, 2.0}, Pivot: "5km"}},
	} {
		if cp := tr.CompileQuery(dfQ, true, nil); cp.WhereSQL == "" {
			t.Errorf("empty distance_feature SQL for %+v", dfQ.DistanceFeature)
		}
	}
	if d := parseDurationOrDistancePivotMs("5km"); d != 5000 {
		t.Fatalf("expected 5000m for 5km, got %v", d)
	}
	if d := parseDurationOrDistancePivotMs("invalid"); d != 1.0 {
		t.Fatalf("expected 1.0 fallback for invalid pivot, got %v", d)
	}
	svQ := r67TTrUnmarshalQuery(t, `{
		"sparse_vector": {
			"field": "sv",
			"query_vector": {"low": 0.1, "high": 0.9},
			"prune": true,
			"pruning_config": {"tokens_weight_threshold": 0.5, "only_score_pruned_tokens": true}
		}
	}`)
	if cp := tr.CompileQuery(svQ, true, nil); !strings.Contains(cp.WhereSQL, "> 0") {
		t.Fatalf("expected pruned sparse_vector query, got %s", cp.WhereSQL)
	}
	fromWithEscapes := "`tbl``q` INNER JOIN \"o\\\"t\" ON `tbl``q`.id = \"o\\\"t\".id AND 'a\\'b''c' = 'x'"
	if joined := appendLateralViewToFromClause(fromWithEscapes, "LATERAL VIEW EXPLODE(`arr`) _t AS _e"); !strings.Contains(joined, "LATERAL VIEW") {
		t.Fatalf("expected LATERAL VIEW inserted, got %s", joined)
	}

	// 9. round60_transpiler.go: L852-869, L1887-1917 & round61_transpiler.go: L1242-1291, L1382-1402, L1835-1865, L2199-2210
	tm := time.Date(2026, 11, 25, 14, 5, 6, 123000000, time.UTC)
	for _, pat := range []string{"e", "ee", "eee", "eeee", "c", "cc", "ccc", "cccc"} {
		if got := FormatESDateWithNamedOrJavaPattern(tm.UnixMilli(), 0, pat, time.UTC); got == "" {
			t.Errorf("empty FormatESDateWithNamedOrJavaPattern(%q)", pat)
		}
	}
	ivRule := &esast.IntervalsRule{}
	_ = json.Unmarshal([]byte(`{
		"match": {"query": "quick brown fox", "filter": {
			"containing": {"match": {"query": "brown"}},
			"not_containing": {"match": {"query": "zebra"}},
			"contained_by": {"match": {"query": "quick brown fox"}},
			"not_contained_by": {"match": {"query": "zebra"}},
			"overlapping": {"match": {"query": "quick"}},
			"not_overlapping": {"match": {"query": "zebra"}},
			"after": {"match": {"query": "alpha"}},
			"before": {"match": {"query": "omega"}}
		}}
	}`), ivRule)
	_, _, _ = EvaluateIntervalsRule(ivRule, "alpha quick brown fox omega", "standard", nil)
	_, _, _ = EvaluateIntervalsRuleWithAnalysis("title", ivRule, func(f string) ([]string, string) {
		return []string{"alpha quick brown fox omega"}, "standard"
	}, nil, analysis.Options{}, nil)

	if !isQuantizedVectorForANNR67(sch, "vec_i4", sch.Fields["vec_i4"]) {
		t.Fatalf("expected vec_i4 quantized")
	}
	if !isQuantizedVectorForANNR67(sch, "vec_i8", sch.Fields["vec_i8"]) {
		t.Fatalf("expected vec_i8 quantized")
	}
	if !isQuantizedVectorForANNR67(nil, "any", schema.FieldBinding{VectorIndexOptions: map[string]any{"type": "int8_hnsw"}}) {
		t.Fatalf("expected int8_hnsw quantized when schema nil")
	}
	if isQuantizedVectorForANNR67(sch, "title.keyword", schema.FieldBinding{VectorIndexOptions: map[string]any{"type": "int8_hnsw"}}) {
		t.Fatalf("expected false when RawMapping field has nil IndexOptions")
	}
	_, _, _, _, alwaysFalse := foldNumericRangeBoundsOutOfBounds(schema.FieldBinding{ESType: "byte"}, json.Number("200"), nil, nil, nil)
	if !alwaysFalse {
		t.Fatalf("expected byte > 200 to fold to alwaysFalse")
	}
	_, _, _, _, _ = foldNumericRangeBoundsOutOfBounds(schema.FieldBinding{ESType: "byte"}, int(1), int64(2), uint64(3), math.NaN())
	mltBad := tr.CompileQuery(r67TTrUnmarshalQuery(t, `{"more_like_this":{"fields":["vec_*"],"like":"hello"}}`), true, nil)
	if mltBad.WhereSQL == "" {
		t.Fatalf("unexpected empty MLT SQL")
	}

	// 10. round63_transpiler.go: L229-243, L1606-1627, L1851-1865, L1902-1927
	if !hasTopLevelOrderByInUnionBranchR64(`SELECT "a\"b", ` + "`c``d`" + ` FROM t ORDER BY x`) {
		t.Fatalf("expected top-level ORDER BY detected across double/backtick quotes")
	}
	if expr := tr.evalGeoPointPredForFieldWithRelationR63("geo_arr", "WITHIN", lambdaCtx, func(lat, lon string) string { return lat + " > 0" }); !strings.Contains(expr, "element_at(") {
		t.Fatalf("expected element_at in WITHIN lambda geo pred, got %s", expr)
	}
	if expr := tr.evalGeoPointPredForFieldWithRelationR63("geo_arr", "INTERSECTS", nil, func(lat, lon string) string { return lat + " > 0" }); !strings.Contains(expr, "array_exists(") {
		t.Fatalf("expected array_exists in INTERSECTS array geo pred, got %s", expr)
	}
	// Nested kNN validation & hex expansion paths (k < 0, num_candidates > 10000, k > num_candidates, CallerSize fallback, valid & invalid hex bit/byte)
	for _, kq := range []*esast.KNNQuery{
		{Field: "items.emb", QueryVector: []float64{1, 0}, K: -1},
		{Field: "items.emb", QueryVector: []float64{1, 0}, K: 2, NumCandidates: 20000},
		{Field: "items.emb", QueryVector: []float64{1, 0}, K: 5, NumCandidates: 2},
		{Field: "items.bitvec", QueryVectorFromHex: true, QueryVectorHex: "ZZZZ"},
		{Field: "items.bvec", QueryVectorFromHex: true, QueryVectorHex: "ZZZZ"},
	} {
		trLocal := NewTranspiler(sch, TranspilerOptions{})
		nq := &esast.Query{Nested: &esast.NestedQuery{Path: "items", Query: esast.Query{KNN: kq}}}
		_ = trLocal.CompileQuery(nq, true, nil)
		if trLocal.searchErr == nil {
			t.Errorf("expected searchErr for nested kNN %+v", kq)
		}
	}
	for _, kq := range []*esast.KNNQuery{
		{Field: "items.bitvec", QueryVectorFromHex: true, QueryVectorHex: "ff", K: 2},
		{Field: "items.bvec", QueryVectorFromHex: true, QueryVectorHex: "0102"},
	} {
		trLocal := NewTranspiler(sch, TranspilerOptions{CallerSize: 4})
		nq := &esast.Query{Nested: &esast.NestedQuery{Path: "items", Query: esast.Query{KNN: kq}}}
		cp := trLocal.CompileQuery(nq, true, nil)
		if trLocal.searchErr != nil || cp.WhereSQL == "" {
			t.Errorf("unexpected error for valid nested hex kNN %+v: err=%v cp=%+v", kq, trLocal.searchErr, cp)
		}
	}

	// 11. lucene.go: L1629-1655, L2208-2228
	flags := simpleQueryFlags{
		expandFields: func(_ string) []string { return []string{"*^2", "_all_text^3", "status"} },
	}
	for _, tok := range []string{"[* TO *]^2", "status:[* TO *]^2"} {
		_ = buildLuceneAtomQueryWithFlags(tok, "*", nil, "OR", 0, false, flags)
	}
	if canAcceptTrailingWSChunk("(a)") || canAcceptTrailingWSChunk("a:^2") || canAcceptTrailingWSChunk(`"abc"`) || !canAcceptTrailingWSChunk("hello") {
		t.Fatalf("unexpected canAcceptTrailingWSChunk result")
	}
}
