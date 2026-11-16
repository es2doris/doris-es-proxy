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

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func buildRound61TestSchema(t *testing.T) *schema.IndexSchema {
	t.Helper()
	raw := `{
		"properties": {
			"title": {"type": "text"},
			"subtitle": {"type": "text"},
			"category": {"type": "keyword"},
			"unindexed_kw": {"type": "keyword", "index": false},
			"unindexed_int": {"type": "integer", "index": false},
			"unindexed_ip": {"type": "ip", "index": false},
			"unindexed_bool": {"type": "boolean", "index": false},
			"unindexed_date": {"type": "date", "index": false},
			"unindexed_txt": {"type": "text", "index": false},
			"price": {"type": "double"},
			"qty": {"type": "integer"},
			"b_val": {"type": "byte"},
			"f_val": {"type": "float"},
			"hf_val": {"type": "half_float"},
			"sf_val": {"type": "scaled_float", "scaling_factor": 100},
			"year_dt": {"type": "date", "format": "uuuu"},
			"nanos_ts": {"type": "date_nanos"},
			"num_range": {"type": "integer_range"},
			"loc": {"type": "geo_point"},
			"pos_loc": {"type": "geo_point", "time_series_metric": "position"},
			"vec_cos": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "cosine"},
			"vec_l2": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "l2_norm"},
			"vec_dp": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "dot_product"},
			"vec_mip": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "max_inner_product"},
			"vec_byte_dp": {"type": "dense_vector", "element_type": "byte", "dims": 2, "index": true, "similarity": "dot_product"},
			"my_join": {"type": "join", "relations": {"question": "answer"}},
			"chunks": {
				"type": "nested",
				"properties": {
					"tag": {"type": "keyword"},
					"emb": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "l2_norm"}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		t.Fatalf("unmarshal mapping: %v", err)
	}
	return schema.CompileIndexSchema("es_db", "round61_idx", &spec)
}

func TestRound61_F19_SQLiEscapingAndDeterministicWildcard(t *testing.T) {
	got := EscapeDorisSQLString("foo\x00\\' OR 1=1--")
	want := `foo\\'' OR 1=1--`
	if got != want {
		t.Fatalf("EscapeDorisSQLString mismatch: got %q, want %q", got, want)
	}

	idx := buildRound61TestSchema(t)
	tr := NewTranspiler(idx, TranspilerOptions{})

	// parent_id with backslash-quote SQLi attempt must escape backslash BEFORE quote.
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"parent_id": {
				"type": "answer",
				"id": "p1\\' OR 1=1 -- "
			}
		}
	}`), &req); err != nil {
		t.Fatalf("unmarshal parent_id: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan parent_id: %v", err)
	}
	if !strings.Contains(plan.HitsSQL, `'p1\\'' OR 1=1 -- '`) {
		t.Fatalf("expected backslash-escaped SQL literal in HitsSQL, got:\n%s", plan.HitsSQL)
	}

	// Unmapped dynamic range field with single quote + backslash in field name.
	var rangeReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"range": {
				"dyn\\'fld": {"gte": 10}
			}
		}
	}`), &rangeReq); err != nil {
		t.Fatalf("unmarshal range: %v", err)
	}
	rangePlan, err := tr.BuildSearchPlan(&rangeReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan range: %v", err)
	}
	if !strings.Contains(rangePlan.HitsSQL, `dyn\\''fld`) {
		t.Fatalf("expected escaped dynamic field path in HitsSQL, got:\n%s", rangePlan.HitsSQL)
	}

	// Deterministic wildcard expansion in query_string across runs.
	var qsReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query": {"query_string": {"fields": ["*title*"], "query": "hello"}}}`), &qsReq); err != nil {
		t.Fatalf("unmarshal query_string: %v", err)
	}
	p1, err := tr.BuildSearchPlan(&qsReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan qs 1: %v", err)
	}
	for i := 0; i < 10; i++ {
		pi, err := tr.BuildSearchPlan(&qsReq)
		if err != nil {
			t.Fatalf("BuildSearchPlan qs %d: %v", i, err)
		}
		if pi.HitsSQL != p1.HitsSQL {
			t.Fatalf("non-deterministic wildcard SQL on run %d:\n%s\nvs\n%s", i, pi.HitsSQL, p1.HitsSQL)
		}
	}
}

func TestRound61_F10_F11_KNNTopKAndVectorScoring(t *testing.T) {
	idx := buildRound61TestSchema(t)
	tr := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})

	// 1. Top-level knn MUST NOT override size, and MUST emit ROW_NUMBER() <= k top-k bound!
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 10,
		"knn": {
			"field": "vec_l2",
			"query_vector": [1.0, 2.0],
			"k": 3,
			"num_candidates": 10
		}
	}`), &req); err != nil {
		t.Fatalf("unmarshal knn search: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan knn: %v", err)
	}
	if !strings.Contains(plan.HitsSQL, "LIMIT 10 OFFSET 0") {
		t.Fatalf("expected LIMIT 10 (not overridden to k=3), got:\n%s", plan.HitsSQL)
	}
	if !strings.Contains(plan.HitsSQL, "ROW_NUMBER() OVER (ORDER BY") || !strings.Contains(plan.HitsSQL, "`_rn` <= 3") {
		t.Fatalf("expected top-k ROW_NUMBER() <= 3 subquery, got:\n%s", plan.HitsSQL)
	}

	// 2. Validation: k > num_candidates rejected (both at AST parse time and when omitted k defaults to size); non-unit dot_product float rejected; hex byte vector accepted!
	var badK esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"knn": {"field": "vec_l2", "query_vector": [1, 2], "k": 10, "num_candidates": 5}}`), &badK); err == nil || !strings.Contains(err.Error(), "cannot be less than [k]") {
		t.Fatalf("expected unmarshal k > num_candidates error, got %v", err)
	}
	var badImplicitK esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"size": 20, "knn": {"field": "vec_l2", "query_vector": [1, 2], "num_candidates": 5}}`), &badImplicitK); err != nil {
		t.Fatalf("unmarshal implicit k: %v", err)
	}
	if _, err := tr.BuildSearchPlan(&badImplicitK); err == nil || !strings.Contains(err.Error(), "cannot be less than [k]") {
		t.Fatalf("expected implicit k=size(20) > num_candidates(5) error, got %v", err)
	}

	var nonUnitDP esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"knn": {"field": "vec_dp", "query_vector": [2.0, 2.0], "k": 2}}`), &nonUnitDP)
	if _, err := tr.BuildSearchPlan(&nonUnitDP); err == nil || !strings.Contains(err.Error(), "unit-length") {
		t.Fatalf("expected unit-length dot_product error, got %v", err)
	}

	var hexByteReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"knn": {"field": "vec_byte_dp", "query_vector": "7f80"}}`), &hexByteReq); err != nil {
		t.Fatalf("unmarshal hex byte knn: %v", err)
	}
	hexPlan, err := tr.BuildSearchPlan(&hexByteReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan hex byte knn: %v", err)
	}
	if !strings.Contains(hexPlan.HitsSQL, "127, -128") {
		t.Fatalf("expected decoded signed byte vector [127, -128], got:\n%s", hexPlan.HitsSQL)
	}

	// 3. Exact vector score & similarity threshold formulas
	scL2, ok := ComputeESVectorScore([]float64{1, 2}, []float64{4, 6}, "l2_norm", "float")
	if !ok || math.Abs(scL2-(1.0/26.0)) > 1e-9 {
		t.Fatalf("unexpected l2_norm score: %v (want 1/26)", scL2)
	}
	if !PassesESVectorSimilarity([]float64{1, 2}, []float64{4, 6}, "l2_norm", "float", 5.0) ||
		PassesESVectorSimilarity([]float64{1, 2}, []float64{4, 6}, "l2_norm", "float", 4.9) {
		t.Fatalf("l2_norm similarity threshold should compare Euclidean distance d=5.0")
	}

	scMIPNeg, _ := ComputeESVectorScore([]float64{1, 0}, []float64{-3, 0}, "max_inner_product", "float")
	if math.Abs(scMIPNeg-0.25) > 1e-9 {
		t.Fatalf("unexpected negative MIP score: %v (want 0.25)", scMIPNeg)
	}
	scMIPPos, _ := ComputeESVectorScore([]float64{1, 0}, []float64{3, 0}, "max_inner_product", "float")
	if math.Abs(scMIPPos-4.0) > 1e-9 {
		t.Fatalf("unexpected positive MIP score: %v (want 4.0)", scMIPPos)
	}

	scByteDP, _ := ComputeESVectorScore([]float64{127, -128}, []float64{127, -128}, "dot_product", "byte")
	wantByteDP := 0.5 + float64(127*127+128*128)/(32768.0*2.0)
	if math.Abs(scByteDP-wantByteDP) > 1e-9 {
		t.Fatalf("unexpected byte dot_product score: %v, want %v", scByteDP, wantByteDP)
	}

	// 4. Nested vector parent diversification helper
	best, matched, childHits := EvaluateNestedKNNParentScore(
		[]map[string]any{
			{"emb": []any{10.0, 10.0}},
			{"emb": []any{1.0, 2.0}},
		},
		"emb",
		[]float64{1.0, 2.0},
		"l2_norm",
		"float",
		nil,
		2.0,
	)
	if !matched || math.Abs(best-2.0) > 1e-9 || len(childHits) != 2 || childHits[0].Offset != 1 {
		t.Fatalf("unexpected nested parent diversification: best=%v matched=%v hits=%+v", best, matched, childHits)
	}
}

func TestRound61_F12_F13_F14_DocValuesIgnoredAndTSDB(t *testing.T) {
	idx := buildRound61TestSchema(t)

	// ES7 mode rejects index: false term query; ES8Compat allows doc-values-backed types!
	tr7 := NewTranspiler(idx, TranspilerOptions{ES8Compat: false})
	tr8 := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})

	for _, fieldJSON := range []string{
		`{"term": {"unindexed_kw": "a"}}`,
		`{"range": {"unindexed_int": {"gte": 5}}}`,
		`{"term": {"unindexed_ip": "10.0.0.1"}}`,
		`{"term": {"unindexed_bool": true}}`,
		`{"range": {"unindexed_date": {"gte": "2024-01-01"}}}`,
	} {
		var r esast.SearchRequest
		if err := json.Unmarshal([]byte(`{"query": `+fieldJSON+`}`), &r); err != nil {
			t.Fatalf("unmarshal %s: %v", fieldJSON, err)
		}
		if _, err := tr7.BuildSearchPlan(&r); err == nil {
			t.Fatalf("expected ES7 mode to reject index:false query %s", fieldJSON)
		}
		if _, err := tr8.BuildSearchPlan(&r); err != nil {
			t.Fatalf("expected ES8Compat to allow doc-values query %s, got %v", fieldJSON, err)
		}
	}

	// ES8Compat still rejects text (no doc_values) and positional intervals on index: false!
	for _, badJSON := range []string{
		`{"match": {"unindexed_txt": "hello"}}`,
		`{"intervals": {"unindexed_kw": {"match": {"query": "hello"}}}}`,
	} {
		var r esast.SearchRequest
		_ = json.Unmarshal([]byte(`{"query": `+badJSON+`}`), &r)
		if _, err := tr8.BuildSearchPlan(&r); err == nil {
			t.Fatalf("expected ES8Compat to reject %s", badJSON)
		}
	}

	// F13: _ignored regexp query
	var ignReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query": {"regexp": {"_ignored": "bad_.*"}}} `), &ignReq); err != nil {
		t.Fatalf("unmarshal _ignored regexp: %v", err)
	}
	ignPlan, err := tr8.BuildSearchPlan(&ignReq)
	if err != nil || !strings.Contains(ignPlan.HitsSQL, "`_ignored`") || !strings.Contains(ignPlan.HitsSQL, "REGEXP") {
		t.Fatalf("unexpected _ignored regexp plan (err=%v): %s", err, ignPlan.HitsSQL)
	}

	// F14: _tsid direct query error & position geo_point rejected in avg metric
	var tsidReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query": {"term": {"_tsid": "abc"}}}`), &tsidReq)
	if _, err := tr8.BuildSearchPlan(&tsidReq); err == nil || !strings.Contains(err.Error(), "_tsid") {
		t.Fatalf("expected _tsid search error, got %v", err)
	}

	var posAvgReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size": 0, "aggs": {"bad_avg": {"avg": {"field": "pos_loc"}}}}`), &posAvgReq)
	if _, err := tr8.BuildSearchPlan(&posAvgReq); err == nil {
		t.Fatalf("expected avg on geo_point position metric to fail")
	}
}

func TestRound61_F15_F16_AggsQuantilesGeotileAndMurmur3(t *testing.T) {
	// 1. Lucene MurmurHash3_x86_32 & partition coverage: every term belongs to exactly 1 partition in [0, N)
	for _, term := range []string{"alpha", "beta", "gamma", "delta", "12345", ""} {
		matched := 0
		for p := 0; p < 4; p++ {
			if TermsPartitionBucketMatch(term, false, p, 4) {
				matched++
			}
		}
		if matched != 1 {
			t.Fatalf("term %q matched %d partitions out of 4, want 1", term, matched)
		}
	}

	// 2. Web Mercator geotile_grid encoding
	tile0, ok := EncodeGeotileKey(52.374081, 4.912350, 0)
	if !ok || tile0 != "0/0/0" {
		t.Fatalf("unexpected zoom 0 tile: %q", tile0)
	}
	tile6, ok := EncodeGeotileKey(52.374081, 4.912350, 6)
	if !ok || tile6 != "6/32/21" {
		t.Fatalf("unexpected Amsterdam zoom 6 tile: got %q, want 6/32/21", tile6)
	}

	// 3. Raw values SQL companion branches + ParseCollectedFloatValues + ES7 vs ES8 quantiles + Boxplot + MAD
	idx := buildRound61TestSchema(t)
	tr := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})

	var aggReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"p": {"percentiles": {"field": "price", "percents": [25, 50, 75]}},
			"bp": {"boxplot": {"field": "price"}},
			"mad": {"median_absolute_deviation": {"field": "price"}},
			"scalar_hb": {"histogram": {"field": "price", "interval": 10, "hard_bounds": {"min": 0, "max": 30}}},
			"rng_hist": {"histogram": {"field": "num_range", "interval": 10, "hard_bounds": {"min": 0, "max": 30}}},
			"miss_with_default": {"missing": {"field": "category", "missing": "N/A"}},
			"comp_geo": {"composite": {"sources": [{"tile": {"geotile_grid": {"field": "loc", "precision": 6}}}]}},
			"nest": {
				"nested": {"path": "chunks"},
				"aggs": {
					"comp_nested": {"composite": {"sources": [{"t": {"terms": {"field": "chunks.tag"}}}]}}
				}
			}
		}
	}`), &aggReq); err != nil {
		t.Fatalf("unmarshal aggReq: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&aggReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan aggs: %v", err)
	}
	for _, wantSubstr := range []string{
		"__raw_vals__p",
		"__raw_vals__bp",
		"__raw_vals__mad",
		"ARRAY_RANGE(",
		"< 30", // exclusive upper hard_bounds.max
		"LN(TAN(PI() / 4.0",
		"LATERAL VIEW EXPLODE(`n__chunks`)",
	} {
		if !strings.Contains(plan.AggsSQL, wantSubstr) {
			t.Fatalf("expected AggsSQL to contain %q, got:\n%s", wantSubstr, plan.AggsSQL)
		}
	}

	pk, vals, ok := ParseCollectedFloatValues("grpA\x1f_vals:1,2,3,4,100")
	if !ok || pk != "grpA" || len(vals) != 5 {
		t.Fatalf("unexpected ParseCollectedFloatValues: pk=%q vals=%v ok=%v", pk, vals, ok)
	}

	bp := ComputeESBoxplotWithVersion([]float64{1, 2, 3, 4, 5, 100}, 100, true)
	if bp.Min == nil || *bp.Min != 1 || bp.Max == nil || *bp.Max != 100 || bp.Upper == nil || *bp.Upper != 5 {
		t.Fatalf("unexpected Tukey boxplot (outlier 100 should clamp upper whisker to 5): %+v", bp)
	}
	mad := ComputeESMedianAbsoluteDeviationWithVersion([]float64{1, 1, 2, 2, 4, 6, 9}, 1000, true)
	if mad == nil || *mad != 1.0 {
		t.Fatalf("expected MAD=1.0 for [1,1,2,2,4,6,9], got %v", mad)
	}
}

func TestRound61_F17_F19_RangeOutOfBoundsDateUUUUIntervalsAndMLT(t *testing.T) {
	idx := buildRound61TestSchema(t)
	tr := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})

	// 1. 500_date_range: numeric 1500 on format "uuuu" must parse as year 1500 AD (negative epoch ms), NOT 1500ms!
	var dtReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query": {"range": {"year_dt": {"gte": 1500, "lte": 1501}}}}`), &dtReq); err != nil {
		t.Fatalf("unmarshal uuuu range: %v", err)
	}
	dtPlan, err := tr.BuildSearchPlan(&dtReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan uuuu range: %v", err)
	}
	if !strings.Contains(dtPlan.HitsSQL, "-14831769600000") {
		t.Fatalf("expected year 1500 AD epoch ms (-14831769600000), got:\n%s", dtPlan.HitsSQL)
	}

	// 2. 510_range_query_out_of_bounds: byte gt: 127 -> FALSE; float gte: -1e100 -> clamped finite; integer gt: 1.5 -> gte: 2
	var oobByte esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query": {"range": {"b_val": {"gt": 127}}}}`), &oobByte)
	pByte, err := tr.BuildSearchPlan(&oobByte)
	if err != nil || !strings.Contains(pByte.HitsSQL, "AND (FALSE)") {
		t.Fatalf("expected byte gt:127 to fold to FALSE, got err=%v sql=%s", err, pByte.HitsSQL)
	}

	var hugeFloat esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query": {"range": {"f_val": {"gte": -1e100, "lte": 1e100}}}}`), &hugeFloat)
	pFloat, err := tr.BuildSearchPlan(&hugeFloat)
	if err != nil || strings.Contains(strings.ToUpper(pFloat.HitsSQL), "INF") {
		t.Fatalf("expected huge float bounds to clamp without Inf, got err=%v sql=%s", err, pFloat.HitsSQL)
	}

	// 3. 230_interval_query: non-minimal any_of ["big", "big bad"] + "wolf" with max_gaps:0 AND use_field
	var rule esast.IntervalsRule
	if err := json.Unmarshal([]byte(`{
		"all_of": {
			"ordered": true,
			"max_gaps": 0,
			"intervals": [
				{"any_of": {"intervals": [{"match": {"query": "big"}}, {"match": {"query": "big bad"}}]}},
				{"match": {"query": "wolf", "use_field": "subtitle"}}
			]
		}
	}`), &rule); err != nil {
		t.Fatalf("unmarshal intervals rule: %v", err)
	}
	spans, matched, err := EvaluateIntervalsRuleWithFieldLookup(
		"title",
		&rule,
		func(field string) ([]string, string) {
			if field == "subtitle" {
				return []string{"a", "b", "c"}, "standard" // "wolf" NOT here -> wait, test matching subtitle at pos 3!
			}
			return []string{"the big bad x"}, "standard"
		},
		nil,
	)
	if err != nil || matched || len(spans) != 0 {
		t.Fatalf("expected non-matching subtitle to fail, got matched=%v spans=%v err=%v", matched, spans, err)
	}
	spans, matched, err = EvaluateIntervalsRuleWithFieldLookup(
		"title",
		&rule,
		func(field string) ([]string, string) {
			if field == "subtitle" {
				return []string{"x y z wolf"}, "standard" // "wolf" at position 3!
			}
			return []string{"the big bad other"}, "standard" // "big bad" at positions 1..2!
		},
		nil,
	)
	if err != nil || !matched || len(spans) != 1 || spans[0].Start != 1 || spans[0].End != 3 {
		t.Fatalf("expected non-minimal any_of + use_field match [1..3], got matched=%v spans=%+v err=%v", matched, spans, err)
	}
	if sc := ScoreIntervalsSpans(spans, 2.0); math.Abs(sc-1.0) > 1e-9 {
		t.Fatalf("expected ScoreIntervalsSpans(gaps=0, boost=2.0) == 1.0, got %v", sc)
	}

	// 4. MoreLikeThis: unlike subtracts terms (not doc MUST_NOT), fail_on_unsupported_field, cross-index _id
	var mltBad esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query": {"more_like_this": {"fields": ["qty"], "like": "10"}}}`), &mltBad)
	if _, err := tr.BuildSearchPlan(&mltBad); err == nil || !strings.Contains(err.Error(), "MoreLikeThis") {
		t.Fatalf("expected fail_on_unsupported_field error on integer field, got %v", err)
	}

	var mltCross esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"more_like_this": {
				"fields": ["title"],
				"like": [{"_index": "other_idx", "_id": "doc1", "doc": {"title": "quick brown fox"}}],
				"unlike": "brown",
				"min_term_freq": 1
			}
		}
	}`), &mltCross); err != nil {
		t.Fatalf("unmarshal mlt: %v", err)
	}
	mltPlan, err := tr.BuildSearchPlan(&mltCross)
	if err != nil {
		t.Fatalf("BuildSearchPlan mlt: %v", err)
	}
	if strings.Contains(mltPlan.HitsSQL, "NOT IN ('doc1')") {
		t.Fatalf("cross-index _id must NOT exclude doc1 in target index:\n%s", mltPlan.HitsSQL)
	}
	if strings.Contains(mltPlan.HitsSQL, "brown") || !strings.Contains(mltPlan.HitsSQL, "quick") {
		t.Fatalf("unlike must subtract 'brown' while keeping 'quick':\n%s", mltPlan.HitsSQL)
	}
}

func TestRound61_CoverageJSONNumQuantilesPartitionsVectorsIntervalsAndMLT(t *testing.T) {
	// 1. IsSafeJSONNumberLiteral
	for _, valid := range []string{"0", "-42", "3.14159", "-0.5e+10", "1E-5", "1234567890"} {
		if !IsSafeJSONNumberLiteral(valid) {
			t.Fatalf("expected IsSafeJSONNumberLiteral(%q) == true", valid)
		}
	}
	for _, invalid := range []string{"", "-", ".5", "5.", "1e", "1e+", "12a", strings.Repeat("1", 130), "1 OR 1=1"} {
		if IsSafeJSONNumberLiteral(invalid) {
			t.Fatalf("expected IsSafeJSONNumberLiteral(%q) == false", invalid)
		}
	}

	// 2. ComputeESBoxplot & ComputeESMedianAbsoluteDeviation (ES7 wrappers + empty cases) + ParseCollectedFloatValues
	if bpEmpty := ComputeESBoxplot(nil, 100); bpEmpty.Min != nil {
		t.Fatalf("expected nil Min on empty ComputeESBoxplot")
	}
	if bp := ComputeESBoxplot([]float64{-100, 10, 12, 14, 16, 200}, 100); bp.Lower == nil || *bp.Lower != 10 || bp.Upper == nil || *bp.Upper != 16 {
		t.Fatalf("unexpected ComputeESBoxplot: %+v", bp)
	}
	if ComputeESMedianAbsoluteDeviation(nil, 100) != nil {
		t.Fatalf("expected nil MAD on empty slice")
	}
	if mad := ComputeESMedianAbsoluteDeviation([]float64{2, 4, 6, 8}, 100); mad == nil || *mad <= 0 {
		t.Fatalf("unexpected ComputeESMedianAbsoluteDeviation: %v", mad)
	}
	if pk, vals, ok := ParseCollectedFloatValues("_vals:1.5, 2.5"); !ok || pk != "" || len(vals) != 2 {
		t.Fatalf("unexpected top-level ParseCollectedFloatValues: pk=%q vals=%v ok=%v", pk, vals, ok)
	}
	if _, _, ok := ParseCollectedFloatValues("unrelated"); ok {
		t.Fatalf("expected ParseCollectedFloatValues('unrelated') == false")
	}

	// 3. TermsPartitionBucketMatch (numeric & bounds) + ParseTermsIncludePartition
	if TermsPartitionBucketMatch("10", true, -1, 4) || TermsPartitionBucketMatch("10", true, 0, 0) {
		t.Fatalf("expected out-of-range partition to return false")
	}
	numMatched := 0
	for p := 0; p < 4; p++ {
		if TermsPartitionBucketMatch("9876543210", true, p, 4) {
			numMatched++
		}
	}
	if numMatched != 1 {
		t.Fatalf("numeric term matched %d partitions, want 1", numMatched)
	}

	p0, np0, isP0, err := ParseTermsIncludePartition(nil)
	if err != nil || isP0 || p0 != 0 || np0 != 0 {
		t.Fatalf("unexpected nil ParseTermsIncludePartition")
	}
	var nilPtr *esast.TermsIncludePartition
	if _, _, isP, err := ParseTermsIncludePartition(nilPtr); err != nil || isP {
		t.Fatalf("unexpected nil *TermsIncludePartition")
	}
	p1 := 1
	np4 := 4
	if p, np, isP, err := ParseTermsIncludePartition(&esast.TermsIncludeExclude{Partition: &p1, NumPartitions: &np4}); err != nil || !isP || p != 1 || np != 4 {
		t.Fatalf("unexpected *TermsIncludeExclude: p=%d np=%d isP=%v err=%v", p, np, isP, err)
	}
	if _, _, _, err := ParseTermsIncludePartition(esast.TermsIncludeExclude{Partition: &p1}); err == nil {
		t.Fatalf("expected missing num_partitions error")
	}
	if p, np, isP, err := ParseTermsIncludePartition(map[string]any{"partition": float64(2), "num_partitions": int64(5)}); err != nil || !isP || p != 2 || np != 5 {
		t.Fatalf("unexpected map ParseTermsIncludePartition: p=%d np=%d isP=%v err=%v", p, np, isP, err)
	}
	for _, badInc := range []any{
		esast.TermsIncludePartition{Partition: 0, NumPartitions: 0},
		esast.TermsIncludePartition{Partition: 4, NumPartitions: 4},
		map[string]any{"partition": 1},
		map[string]any{"partition": "bad", "num_partitions": 4},
	} {
		if _, _, _, err := ParseTermsIncludePartition(badInc); err == nil {
			t.Fatalf("expected error for bad include partition %+v", badInc)
		}
	}

	// 4. EncodeGeotileKey & EncodeGeotileSQL edge cases
	if _, ok := EncodeGeotileKey(math.NaN(), 0, 5); ok {
		t.Fatalf("expected NaN lat to fail EncodeGeotileKey")
	}
	if _, ok := EncodeGeotileKey(95, 0, 5); ok {
		t.Fatalf("expected lat>90 to fail EncodeGeotileKey")
	}
	if k, ok := EncodeGeotileKey(89.9, 180.0, 35); !ok || !strings.HasPrefix(k, "29/") {
		t.Fatalf("expected clamped zoom 29 tile, got %q (%v)", k, ok)
	}
	if k, ok := EncodeGeotileKey(-89.9, -180.0, -1); !ok || !strings.HasPrefix(k, "7/") {
		t.Fatalf("expected default zoom 7 tile, got %q (%v)", k, ok)
	}
	if sql0 := EncodeGeotileSQL("lat", "lon", 0); !strings.Contains(sql0, "'0/0/0'") {
		t.Fatalf("unexpected zoom 0 SQL: %s", sql0)
	}
	if sqlDef := EncodeGeotileSQL("lat", "lon", -1); !strings.Contains(sqlDef, "'7/'") {
		t.Fatalf("unexpected default zoom SQL: %s", sqlDef)
	}

	// 5. Vector cosine & bit similarity + PassesESVectorSimilarity
	scCos, ok := ComputeESVectorScore([]float64{1, 0}, []float64{1, 0}, "cosine", "float")
	if !ok || math.Abs(scCos-1.0) > 1e-9 {
		t.Fatalf("expected cosine score 1.0, got %v", scCos)
	}
	if !PassesESVectorSimilarity([]float64{1, 0}, []float64{1, 0}, "cosine", "float", 0.9) ||
		!PassesESVectorSimilarity([]float64{1, 0}, []float64{3, 0}, "max_inner_product", "float", 2.5) ||
		!PassesESVectorSimilarity([]float64{1, 0}, []float64{1, 0}, "dot_product", "float", 0.9) {
		t.Fatalf("unexpected PassesESVectorSimilarity failure")
	}
	scBit, ok := ComputeESVectorScore([]float64{3, -1}, []float64{3, -1}, "l2_norm", "bit")
	if !ok || scBit <= 0 {
		t.Fatalf("unexpected bit vector score: %v (%v)", scBit, ok)
	}

	// 6. Intervals rules: prefix, wildcard, fuzzy, all filters (containing, not_containing, contained_by, not_contained_by, overlapping, not_overlapping, after, before, script)
	evalRuleJSON := func(rawJSON string) bool {
		var r esast.IntervalsRule
		if err := json.Unmarshal([]byte(rawJSON), &r); err != nil {
			t.Fatalf("unmarshal rule %s: %v", rawJSON, err)
		}
		_, matched, err := EvaluateIntervalsRule(&r, "alpha beta gamma delta epsilon", "standard", func(_ *esast.ScriptSpec, span IntervalsSpan) (bool, error) {
			return span.Start == 0 && span.End == 2 && span.Gaps == 1, nil
		})
		if err != nil {
			t.Fatalf("EvaluateIntervalsRule(%s) error: %v", rawJSON, err)
		}
		return matched
	}
	if !evalRuleJSON(`{"prefix":{"prefix":"alp"}}`) ||
		!evalRuleJSON(`{"wildcard":{"pattern":"g*ma"}}`) ||
		!evalRuleJSON(`{"fuzzy":{"term":"betx","fuzziness":1}}`) {
		t.Fatalf("expected prefix, wildcard, and fuzzy interval rules to match")
	}
	for _, fltRule := range []string{
		`{"all_of":{"intervals":[{"match":{"query":"alpha"}},{"match":{"query":"delta"}}],"filter":{"containing":{"match":{"query":"beta"}}}}}`,
		`{"all_of":{"intervals":[{"match":{"query":"alpha"}},{"match":{"query":"gamma"}}],"filter":{"not_containing":{"match":{"query":"epsilon"}}}}}`,
		`{"match":{"query":"beta","filter":{"contained_by":{"all_of":{"intervals":[{"match":{"query":"alpha"}},{"match":{"query":"delta"}}]}}}}}`,
		`{"match":{"query":"epsilon","filter":{"not_contained_by":{"all_of":{"intervals":[{"match":{"query":"alpha"}},{"match":{"query":"gamma"}}]}}}}}`,
		`{"all_of":{"intervals":[{"match":{"query":"beta"}},{"match":{"query":"delta"}}],"filter":{"overlapping":{"all_of":{"intervals":[{"match":{"query":"alpha"}},{"match":{"query":"gamma"}}]}}}}}`,
		`{"match":{"query":"epsilon","filter":{"not_overlapping":{"all_of":{"intervals":[{"match":{"query":"alpha"}},{"match":{"query":"gamma"}}]}}}}}`,
		`{"match":{"query":"delta","filter":{"after":{"match":{"query":"alpha"}}}}}`,
		`{"match":{"query":"alpha","filter":{"before":{"match":{"query":"delta"}}}}}`,
		`{"all_of":{"intervals":[{"match":{"query":"alpha"}},{"match":{"query":"gamma"}}],"filter":{"script":{"source":"interval.start == 0 && interval.end == 2 && interval.gaps == 1"}}}}`,
	} {
		if !evalRuleJSON(fltRule) {
			t.Fatalf("expected interval filter rule to match: %s", fltRule)
		}
	}

	// 7. MoreLikeThis wildcard fields, stop_words, minimum_should_match, include:true same-index exclusion
	idx := buildRound61TestSchema(t)
	tr := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})
	var mltFull esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"more_like_this": {
				"fields": ["*title*"],
				"like": ["alpha beta gamma delta", {"_index": "round61_idx", "_id": "same1"}],
				"stop_words": ["beta"],
				"min_term_freq": 1,
				"minimum_should_match": "2",
				"include": false
			}
		}
	}`), &mltFull); err != nil {
		t.Fatal(err)
	}
	mltPlan, err := tr.BuildSearchPlan(&mltFull)
	if err != nil || strings.Contains(mltPlan.HitsSQL, "beta") || !strings.Contains(mltPlan.HitsSQL, "same1") {
		t.Fatalf("unexpected mltFull plan (err=%v): %s", err, mltPlan.HitsSQL)
	}

	// 8. LowerRetrieverToSearchRequest, FormatSemverSortKey, CompareSemverStrings, isMappedField
	var retReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"retriever":{"standard":{"query":{"term":{"category":"news"}}}}}`), &retReq)
	LowerRetrieverToSearchRequest(&retReq)
	if retReq.Query == nil {
		t.Fatalf("expected LowerRetrieverToSearchRequest to populate Query")
	}
	if FormatSemverSortKey("1.0.0-alpha.1+build123") >= FormatSemverSortKey("1.0.0") || CompareSemverStrings("1.0.0-alpha", "1.0.0") >= 0 {
		t.Fatalf("unexpected SemVer comparison")
	}
	if !tr.isMappedField("title") || !tr.isMappedField("title.keyword") || tr.isMappedField("totally_unmapped_xyz") {
		t.Fatalf("unexpected isMappedField results")
	}
}
