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
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func buildRound67RichSchemaR67(t *testing.T) *schema.IndexSchema {
	t.Helper()
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"settings": {
			"analysis": {
				"normalizer": {
					"lc_norm": {"type": "custom", "filter": ["lowercase"]}
				},
				"filter": {
					"syn_filter": {
						"type": "synonym_graph",
						"synonyms": ["quick, fast"]
					}
				},
				"analyzer": {
					"syn_analyzer": {
						"tokenizer": "standard",
						"filter": ["lowercase", "syn_filter"]
					}
				}
			}
		},
		"properties": {
			"title": {
				"type": "text",
				"fields": {"keyword": {"type": "keyword"}}
			},
			"title_syn": {"type": "text", "analyzer": "syn_analyzer"},
			"body": {"type": "text"},
			"mot_field": {"type": "match_only_text"},
			"sayt": {"type": "search_as_you_type"},
			"kw_a": {"type": "keyword"},
			"kw_b": {"type": "keyword"},
			"norm_kw": {"type": "keyword", "normalizer": "lc_norm"},
			"status": {"type": "keyword"},
			"count": {"type": "integer"},
			"price": {"type": "double"},
			"created_at": {"type": "date"},
			"ip_addr": {"type": "ip"},
			"ver": {"type": "version"},
			"hist": {"type": "histogram"},
			"num_rng": {"type": "integer_range"},
			"geo_pt": {"type": "geo_point"},
			"shape_pt": {"type": "geo_point"},
			"shape_geo": {"type": "geo_shape"},
			"vec_l2": {"type": "dense_vector", "dims": 2, "similarity": "l2_norm"},
			"vec_dot": {"type": "dense_vector", "dims": 2, "similarity": "dot_product"},
			"vec_cos": {"type": "dense_vector", "dims": 2, "similarity": "cosine"},
			"vec_q8": {"type": "dense_vector", "dims": 2, "similarity": "l2_norm", "index_options": {"type": "int8_hnsw"}},
			"vec_bit": {"type": "dense_vector", "dims": 16, "element_type": "bit", "similarity": "hamming"},
			"vec_byte": {"type": "dense_vector", "dims": 2, "element_type": "byte", "similarity": "l2_norm"},
			"metrics_agg": {"type": "aggregate_metric_double", "metrics": ["min", "max"], "default_metric": "max"},
			"items": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword"},
					"code": {"type": "keyword", "fields": {"lc": {"type": "keyword", "normalizer": "lc_norm"}}},
					"tags": {"type": "text"},
					"loc": {"type": "geo_point"},
					"ip": {"type": "ip"},
					"ver": {"type": "version"},
					"hist": {"type": "histogram"},
					"price": {"type": "double"},
					"emb": {"type": "dense_vector", "dims": 2, "similarity": "l2_norm"},
					"sub": {
						"type": "nested",
						"properties": {
							"code": {"type": "keyword"},
							"qty": {"type": "integer"},
							"leaf": {
								"type": "nested",
								"properties": {
									"flag": {"type": "keyword"}
								}
							}
						}
					}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal rich mapping spec failed: %v", err)
	}
	return schema.CompileIndexSchema("es_db", "r67_rich", &spec)
}

func TestRound67_RedTeamSafetyAndANNFixes(t *testing.T) {
	sch := buildRound67RichSchemaR67(t)

	// P0-5: nestedRelativeJSONPath must safely quote every segment including injection payloads.
	trBase := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	p05Cases := []struct {
		field         string
		preferKeyword bool
		want          string
	}{
		{"items.*", false, `$."*"`},
		{"items..secret", false, `$.""."secret"`},
		{"items.foo-bar", false, `$."foo-bar"`},
		{`items."q"`, false, `$."\"q\""`},
		{`items.a\b`, false, `$."a\\b"`},
		{"items.code.lc", false, `$."code__lc"`},
	}
	for _, tc := range p05Cases {
		got := trBase.nestedRelativeJSONPath(tc.field, tc.preferKeyword, "items")
		if got != tc.want {
			t.Fatalf("P0-5 nestedRelativeJSONPath(%q) = %q, want %q", tc.field, got, tc.want)
		}
	}

	// P1-1: Under UseDoris4SearchFunc=true, score() must NEVER enter WHERE, aggs CTE, collapse _scored, or search_after _scored.
	trD4 := NewTranspiler(sch, TranspilerOptions{ES8Compat: true, UseDoris4SearchFunc: true})
	minSc := 0.25
	reqMinSc := mustUnmarshalSearchReqR62(t, `{
		"query": {"query_string": {"query": "title:hello"}},
		"min_score": 0.25
	}`)
	reqMinSc.MinScore = &minSc
	planMinSc, err := trD4.BuildSearchPlan(reqMinSc)
	if err != nil {
		t.Fatalf("P1-1 min_score BuildSearchPlan failed: %v", err)
	}
	whereIdx := strings.Index(planMinSc.HitsSQL, " WHERE ")
	if whereIdx < 0 || strings.Contains(planMinSc.HitsSQL[whereIdx:], "score(") {
		t.Fatalf("P1-1 min_score WHERE must not contain score(), got:\n%s", planMinSc.HitsSQL)
	}

	reqCollapse := mustUnmarshalSearchReqR62(t, `{
		"query": {"query_string": {"query": "title:hello"}},
		"collapse": {"field": "status"},
		"aggs": {"by_status": {"terms": {"field": "status"}}}
	}`)
	planCollapse, err := trD4.BuildSearchPlan(reqCollapse)
	if err != nil {
		t.Fatalf("P1-1 collapse BuildSearchPlan failed: %v", err)
	}
	if strings.Contains(planCollapse.HitsSQL, "score(") {
		t.Fatalf("P1-1 collapse _scored subquery must not contain score(), got:\n%s", planCollapse.HitsSQL)
	}
	if hasScoreInFromBaseMatchedR65(planCollapse.AggsSQL) || strings.Contains(planCollapse.AggsSQL, "score(") {
		t.Fatalf("P1-1 aggs CTE must not contain score(), got:\n%s", planCollapse.AggsSQL)
	}

	reqSA := mustUnmarshalSearchReqR62(t, `{
		"query": {"query_string": {"query": "title:hello"}},
		"sort": ["_score", {"_id": "asc"}],
		"search_after": [1.5, "doc-1"]
	}`)
	planSA, err := trD4.BuildSearchPlan(reqSA)
	if err != nil {
		t.Fatalf("P1-1 search_after BuildSearchPlan failed: %v", err)
	}
	if strings.Contains(planSA.HitsSQL, "score(") {
		t.Fatalf("P1-1 search_after _scored subquery must not contain score(), got:\n%s", planSA.HitsSQL)
	}

	// P1-2: Nested higher-order lambdas suppressed when inLambda=true + linear minimum_should_match >= 2 + nested kNN filter.
	reqNestedLambda := mustUnmarshalSearchReqR62(t, `{
		"query": {
			"nested": {
				"path": "items",
				"query": {
					"bool": {
						"minimum_should_match": 2,
						"should": [
							{"term": {"items.name": "bolt"}},
							{"match": {"items.tags": "steel alloy"}},
							{"nested": {"path": "items.sub", "query": {"term": {"items.sub.code": "S1"}}}}
						]
					}
				}
			}
		}
	}`)
	planNL, err := trBase.BuildSearchPlan(reqNestedLambda)
	if err != nil {
		t.Fatalf("P1-2 deep nested BuildSearchPlan failed: %v", err)
	}
	assertNoNestedLambdaSQLR66(t, planNL.HitsSQL)
	if strings.Contains(planNL.HitsSQL, "ARRAY_REPEAT(CONCAT(") {
		t.Fatalf("P1-2 expected linear ARRAY_SLICE/ARRAY_SORT minimum_should_match without O(K*M^2) ARRAY_REPEAT string blowup, got:\n%s", planNL.HitsSQL)
	}
	if !strings.Contains(planNL.HitsSQL, "ARRAY_SLICE(") {
		t.Fatalf("P1-2 expected ARRAY_SLICE in nested minimum_should_match=2 SQL, got:\n%s", planNL.HitsSQL)
	}

	reqNestedKNNFilter := mustUnmarshalSearchReqR62(t, `{
		"knn": {
			"field": "items.emb",
			"query_vector": [0.6, 0.8],
			"k": 3,
			"num_candidates": 5,
			"filter": {
				"bool": {
					"must": [
						{"match": {"items.tags": "fast bolt"}},
						{"geo_distance": {"distance": "5km", "items.loc": [0.0, 0.0]}},
						{"nested": {"path": "items.sub", "query": {"nested": {"path": "items.sub.leaf", "query": {"term": {"items.sub.leaf.flag": "on"}}}}}}
					]
				}
			}
		}
	}`)
	planNKNN, err := trBase.BuildSearchPlan(reqNestedKNNFilter)
	if err != nil {
		t.Fatalf("P1-2 nested KNN filter BuildSearchPlan failed: %v", err)
	}
	assertNoNestedLambdaSQLR66(t, planNKNN.HitsSQL)

	// P1-3: TRY_CAST in metric scripts/raw values & backtick escaping for DorisDB/DorisTable.
	var specEsc esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"price":{"type":"double"},"tag":{"type":"keyword"},"vec_l2":{"type":"dense_vector","dims":2,"similarity":"l2_norm"},"items":{"type":"nested","properties":{"emb":{"type":"dense_vector","dims":2,"similarity":"l2_norm"}}}}}`), &specEsc)
	schEsc := schema.CompileIndexSchema("es`db", "idx`tbl", &specEsc)
	schEsc.DorisTable = "idx`tbl"
	trEsc := NewTranspiler(schEsc, TranspilerOptions{ES8Compat: true})
	reqEsc := mustUnmarshalSearchReqR62(t, `{
		"query": {"match_all": {}},
		"aggs": {
			"sum_script": {"sum": {"script": {"source": "doc['price'].value * 2"}}},
			"pct_raw": {"percentiles": {"field": "price"}},
			"by_tag": {"terms": {"field": "tag"}, "aggs": {"grouped_pct": {"percentiles": {"field": "price"}}}}
		}
	}`)
	planEsc, err := trEsc.BuildSearchPlan(reqEsc)
	if err != nil {
		t.Fatalf("P1-3 escaped table BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(planEsc.HitsSQL, "`es``db`.`idx``tbl`") || !strings.Contains(planEsc.AggsSQL, "`es``db`.`idx``tbl`") {
		t.Fatalf("P1-3 expected escaped backticks in HitsSQL and AggsSQL, got hits=%s\naggs=%s", planEsc.HitsSQL, planEsc.AggsSQL)
	}
	if strings.Contains(planEsc.AggsSQL, "CAST((") && !strings.Contains(planEsc.AggsSQL, "TRY_CAST(") {
		t.Fatalf("P1-3 expected TRY_CAST in metric script/raw values, got:\n%s", planEsc.AggsSQL)
	}
	rawBranch := sqlCollectRawValuesBranch("pct_raw", "`f__price`", "`base_matched`", "")
	if !strings.Contains(rawBranch, "TRY_CAST(`f__price` AS DOUBLE)") {
		t.Fatalf("P1-3 expected TRY_CAST in sqlCollectRawValuesBranch, got:\n%s", rawBranch)
	}
	planEscKNN, err := trEsc.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"knn": {"field": "vec_l2", "query_vector": [1.0, 2.0], "k": 2, "num_candidates": 4}}`))
	if err != nil || !strings.Contains(planEscKNN.HitsSQL, "`es``db`.`idx``tbl`") {
		t.Fatalf("P1-3 expected escaped backticks in kNN HitsSQL, err=%v sql=%s", err, planEscKNN.HitsSQL)
	}
	planEscNKNN, err := trEsc.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"knn": {"field": "items.emb", "query_vector": [0.6, 0.8], "k": 2, "num_candidates": 4}}`))
	if err != nil || !strings.Contains(planEscNKNN.HitsSQL, "`es``db`.`idx``tbl`") {
		t.Fatalf("P1-3 expected escaped backticks in nested kNN HitsSQL, err=%v sql=%s", err, planEscNKNN.HitsSQL)
	}

	// P1-4a: UTF-8 byte-offset drift under Turkish dotless i (ı), long s (ſ), ligature (ﬀ), n preceded by apostrophe (ŉ), Kelvin (K).
	fromWithUTF8 := "`es_db`.`r67` `_t_ıſﬀŉK` INNER JOIN `es_db`.`dim` `_d` ON `_t_ıſﬀŉK`.`_id` = `_d`.`_id`"
	lvExpr := "LATERAL VIEW EXPLODE(`n__items`) `_nt` AS `_nel`"
	joinedUTF8 := appendLateralViewToFromClause(fromWithUTF8, lvExpr)
	if !utf8.ValidString(joinedUTF8) {
		t.Fatalf("P1-4a invalid UTF-8 produced: %q", joinedUTF8)
	}
	latIdx := findTopLevelKeywordOffsetR67(joinedUTF8, "LATERAL")
	joinIdx := findTopLevelKeywordOffsetR67(joinedUTF8, "JOIN")
	if latIdx < 0 || joinIdx < 0 || latIdx > joinIdx {
		t.Fatalf("P1-4a expected LATERAL VIEW inserted before INNER JOIN (lat=%d, join=%d), got: %s", latIdx, joinIdx, joinedUTF8)
	}

	// P1-6.1: max_result_window enforced even with search_after AND overflow-safe when from+size would wrap signed int.
	trWin := NewTranspiler(sch, TranspilerOptions{MaxResultWindow: 100})
	reqSAOver := mustUnmarshalSearchReqR62(t, `{"size": 101, "sort": ["_id"], "search_after": ["a"]}`)
	if _, err := trWin.BuildSearchPlan(reqSAOver); err == nil {
		t.Fatalf("P1-6.1 expected error when size > max_result_window with search_after")
	}
	hugeFrom := math.MaxInt - 5
	sz10 := 10
	reqOverflow := &esast.SearchRequest{From: &hugeFrom, Size: &sz10}
	if _, err := trWin.BuildSearchPlan(reqOverflow); err == nil {
		t.Fatalf("P1-6.1 expected error when from + size overflows signed int")
	}

	// F11: Doris 4.1 ANN pushdown vs exact fallback.
	for _, mode := range []string{"hnsw", "ivf"} {
		trANN := NewTranspiler(sch, TranspilerOptions{
			ES8Compat:        true,
			VectorANNMode:    mode,
			AllowANNPushdown: true,
		})
		reqL2 := mustUnmarshalSearchReqR62(t, `{
			"knn": {"field": "vec_l2", "query_vector": [1.0, 2.0], "k": 3, "num_candidates": 10, "filter": {"term": {"status": "open"}}}
		}`)
		planL2, err := trANN.BuildSearchPlan(reqL2)
		if err != nil {
			t.Fatalf("F11 L2 ANN (%s) failed: %v", mode, err)
		}
		if !strings.Contains(planL2.HitsSQL, "l2_distance_approximate(") || !strings.Contains(planL2.HitsSQL, "ASC") || !strings.Contains(planL2.HitsSQL, "LIMIT 3") {
			t.Fatalf("F11 expected l2_distance_approximate ... ASC LIMIT 3 for mode=%s, got:\n%s", mode, planL2.HitsSQL)
		}

		reqDot := mustUnmarshalSearchReqR62(t, `{
			"knn": {"field": "vec_dot", "query_vector": [0.6, 0.8], "k": 4, "num_candidates": 10}
		}`)
		planDot, err := trANN.BuildSearchPlan(reqDot)
		if err != nil {
			t.Fatalf("F11 dot ANN (%s) failed: %v", mode, err)
		}
		if !strings.Contains(planDot.HitsSQL, "inner_product_approximate(") || !strings.Contains(planDot.HitsSQL, "DESC") {
			t.Fatalf("F11 expected inner_product_approximate ... DESC for mode=%s, got:\n%s", mode, planDot.HitsSQL)
		}

		// Exact fallback checks: cosine, quantized (vec_q8), bit/byte, similarity threshold, min_score, off/disabled, nested.
		fallbackReqs := []string{
			`{"knn": {"field": "vec_cos", "query_vector": [0.6, 0.8], "k": 3, "num_candidates": 5}}`,
			`{"knn": {"field": "vec_q8", "query_vector": [1.0, 2.0], "k": 3, "num_candidates": 5}}`,
			`{"knn": {"field": "vec_bit", "query_vector": "ff00", "k": 3, "num_candidates": 5}}`,
			`{"knn": {"field": "vec_byte", "query_vector": "0102", "k": 3, "num_candidates": 5}}`,
			`{"knn": {"field": "vec_l2", "query_vector": [1.0, 2.0], "k": 3, "num_candidates": 5, "similarity": 0.5}}`,
			`{"min_score": 0.1, "knn": {"field": "vec_l2", "query_vector": [1.0, 2.0], "k": 3, "num_candidates": 5}}`,
			`{"knn": {"field": "items.emb", "query_vector": [1.0, 0.0], "k": 3, "num_candidates": 5}}`,
		}
		for i, raw := range fallbackReqs {
			reqFB := mustUnmarshalSearchReqR62(t, raw)
			planFB, err := trANN.BuildSearchPlan(reqFB)
			if err != nil {
				t.Fatalf("F11 fallback case %d failed: %v", i, err)
			}
			if strings.Contains(planFB.HitsSQL, "_approximate(") {
				t.Fatalf("F11 fallback case %d must NOT use ANN _approximate, got:\n%s", i, planFB.HitsSQL)
			}
		}
	}
	trOff := NewTranspiler(sch, TranspilerOptions{VectorANNMode: "off", AllowANNPushdown: true})
	planOff, err := trOff.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"knn": {"field": "vec_l2", "query_vector": [1.0, 2.0], "k": 3, "num_candidates": 5}}`))
	if err != nil || strings.Contains(planOff.HitsSQL, "_approximate(") {
		t.Fatalf("F11 expected exact fallback when VectorANNMode=off, err=%v sql=%s", err, planOff.HitsSQL)
	}

	// F5: Bounded regex rejects oversized >4096 patterns cleanly.
	hugePat := strings.Repeat("a", 4200)
	if re := wildcardPatternRegex(hugePat, true); re != nil {
		t.Fatalf("F5 expected wildcardPatternRegex to reject oversized >4096 pattern")
	}
	var ivFuzzyOK, ivFuzzyHuge esast.IntervalsRule
	if err := json.Unmarshal([]byte(`{"fuzzy": {"term": "qick", "fuzziness": 1}}`), &ivFuzzyOK); err != nil {
		t.Fatalf("unmarshal valid intervals fuzzy rule failed: %v", err)
	}
	if _, matched, err := EvaluateIntervalsRule(&ivFuzzyOK, "quick brown fox", "standard", nil); err != nil || !matched {
		t.Fatalf("F5 expected valid bounded fuzzy interval match, matched=%v err=%v", matched, err)
	}
	hugeTerm := strings.Repeat("*", 20) + "abcdefghijkl"
	if err := json.Unmarshal([]byte(`{"fuzzy": {"term": "`+hugeTerm+`", "prefix_length": 20, "fuzziness": 2, "analyzer": "whitespace"}}`), &ivFuzzyHuge); err != nil {
		t.Fatalf("unmarshal huge intervals fuzzy rule failed: %v", err)
	}
	if _, _, err := EvaluateIntervalsRule(&ivFuzzyHuge, "quick brown", "whitespace", nil); err == nil {
		t.Fatalf("F5 expected EvaluateIntervalsRule to reject >4096 fuzzy regex")
	}
	if _, _, err := EvaluateIntervalsRuleWithAnalysis("body", &ivFuzzyHuge, func(_ string) ([]string, string) { return []string{"quick"}, "whitespace" }, sch.AnalysisConfig, analysis.Options{}, nil); err == nil {
		t.Fatalf("F5 expected EvaluateIntervalsRuleWithAnalysis to reject >4096 fuzzy regex")
	}
}

func TestRound67_CovFlatNestedAndMatchBoolPrefix(t *testing.T) {
	sch := buildRound67RichSchemaR67(t)
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})

	// 1. compileFlatNestedMatchingIDs across wrapper queries, DisMax, Bool MSM variants, impossible MSM, and leaf fallback.
	if ids, _ := tr.compileFlatNestedMatchingIDs("items", "n__items", nil); !strings.Contains(ids, "n__items") || !strings.Contains(ids, "$._nested_id") {
		t.Fatalf("expected all-IDs fallback for nil query, got %s", ids)
	}
	wrapperQueries := []string{
		`{"constant_score": {"filter": {"nested": {"path": "items.sub", "query": {"term": {"items.sub.code": "A"}}}}}}`,
		`{"function_score": {"query": {"nested": {"path": "items.sub", "query": {"term": {"items.sub.code": "A"}}}}}}`,
		`{"script_score": {"query": {"nested": {"path": "items.sub", "query": {"term": {"items.sub.code": "A"}}}}, "script": {"source": "1.0"}}}`,
		`{"boosting": {"positive": {"nested": {"path": "items.sub", "query": {"term": {"items.sub.code": "A"}}}}, "negative": {"match_all": {}}, "negative_boost": 0.2}}`,
		`{"dis_max": {"queries": [{"nested": {"path": "items.sub", "query": {"term": {"items.sub.code": "A"}}}}, {"term": {"items.name": "bolt"}}]}}`,
		`{"bool": {"must": [{"term": {"items.name": "bolt"}}, {"nested": {"path": "items.sub", "query": {"term": {"items.sub.code": "A"}}}}], "must_not": [{"nested": {"path": "items.sub", "query": {"term": {"items.sub.code": "BAD"}}}}], "should": [{"term": {"items.code": "C1"}}, {"term": {"items.code": "C2"}}], "minimum_should_match": 2}}`,
		`{"bool": {"should": [{"term": {"items.name": "a"}}], "minimum_should_match": 3}}`,
	}
	for i, raw := range wrapperQueries {
		var q esast.Query
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("unmarshal wrapper query %d: %v", i, err)
		}
		ids, _ := tr.compileFlatNestedMatchingIDs("items", "n__items", &q)
		if ids == "" || !isBalancedBackticksAndParensR64(ids) {
			t.Fatalf("expected non-empty balanced IDs expression for wrapper %d (%s), got %s", i, raw, ids)
		}
		assertNoNestedLambdaSQLR66(t, ids)
	}

	// 2. compileMatchBoolPrefixRound62Opts across wildcards, SAYT shingles, numeric error/lenient, custom analyzer, operator/MSM, fuzziness.
	if cp := tr.compileMatchBoolPrefixRound62Opts("no_such_*", esast.PhraseEntry{Query: "hi"}, nil, true, nil); cp.WhereSQL != "FALSE" {
		t.Fatalf("expected FALSE for unmatched wildcard match_bool_prefix, got %+v", cp)
	}
	if cp := tr.compileMatchBoolPrefixRound62Opts("title*", esast.PhraseEntry{Query: "quick fox", Fuzziness: "1"}, nil, true, nil); !strings.Contains(cp.WhereSQL, " OR ") {
		t.Fatalf("expected OR across expanded wildcard match_bool_prefix fields, got %s", cp.WhereSQL)
	}
	if cp := tr.compileMatchBoolPrefixRound62Opts("sayt._3gram", esast.PhraseEntry{Query: "one two"}, nil, true, nil); cp.WhereSQL != "FALSE" {
		t.Fatalf("expected FALSE for 2-token query against sayt._3gram, got %s", cp.WhereSQL)
	}
	trNumErr := NewTranspiler(sch, TranspilerOptions{})
	_ = trNumErr.compileMatchBoolPrefixRound62Opts("count", esast.PhraseEntry{Query: "42"}, nil, true, nil)
	if trNumErr.searchErr == nil {
		t.Fatalf("expected error on numeric field match_bool_prefix without lenient=true")
	}
	lenientTrue := true
	trNumLen := NewTranspiler(sch, TranspilerOptions{})
	if cp := trNumLen.compileMatchBoolPrefixRound62Opts("count", esast.PhraseEntry{Query: "42", Lenient: &lenientTrue}, nil, true, nil); cp.WhereSQL != "FALSE" || trNumLen.searchErr != nil {
		t.Fatalf("expected lenient FALSE without searchErr on numeric match_bool_prefix, got cp=%+v err=%v", cp, trNumLen.searchErr)
	}
	autoSyn := true
	if cp := tr.compileMatchBoolPrefixRound62Opts("title_syn", esast.PhraseEntry{Query: "quick bro", Operator: "and"}, &autoSyn, true, nil); cp.WhereSQL == "FALSE" {
		t.Fatalf("expected syn_analyzer match_bool_prefix to compile, got %+v", cp)
	}
	if cp := tr.compileMatchBoolPrefixRound62Opts("title_syn", esast.PhraseEntry{Query: "   ", ZeroTermsQuery: "all"}, nil, true, nil); cp.WhereSQL != "TRUE" {
		t.Fatalf("expected zero_terms_query=all on empty custom-analyzed match_bool_prefix, got %+v", cp)
	}
}

func TestRound67_CovTermsAndRangeSingleField(t *testing.T) {
	sch := buildRound67RichSchemaR67(t)
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	inLam := &nestedCtx{nestedPath: "items", elemVar: "_el", inLambda: true}

	// 1. compileTermsPredicateWithCI: wildcard expansion, case-insensitive, IP, normalizer, nested inLambda.
	if w := tr.compileTermsPredicateWithCI("kw_*", []any{"Alpha", "Beta"}, true, nil); !strings.Contains(w, "lower(`f__kw_a`)") || !strings.Contains(w, "lower(`f__kw_b`)") {
		t.Fatalf("expected wildcard case-insensitive terms expansion on kw_a & kw_b, got %s", w)
	}
	if w := tr.compileTermsPredicateWithCI("no_match_*", []any{"x"}, false, nil); !strings.Contains(w, "_doc") && w != "FALSE" {
		t.Fatalf("expected dynamic fallback or FALSE for unmatched wildcard terms, got %s", w)
	}
	if w := tr.compileTermsPredicateWithCI("ip_addr", []any{"10.0.0.1", "2001:db8::1"}, false, nil); !strings.Contains(w, "IN ('10.0.0.1'") {
		t.Fatalf("expected IP exact terms predicate, got %s", w)
	}
	if w := tr.compileTermsPredicateWithCI("ip_addr", []any{"10.0.0.0/24"}, false, nil); !strings.Contains(w, "HEX(") {
		t.Fatalf("expected canonical IP CIDR hex terms predicate, got %s", w)
	}
	if w := tr.compileTermsPredicateWithCI("norm_kw", []any{"UPPER"}, false, nil); !strings.Contains(w, "'upper'") {
		t.Fatalf("expected lc_norm normalizer lowercasing 'UPPER' -> 'upper', got %s", w)
	}
	if w := tr.compileTermsPredicateWithCI("items.name", []any{"A", "B"}, true, inLam); strings.Contains(w, "array_exists(") {
		t.Fatalf("expected no nested array_exists inside inLambda terms, got %s", w)
	}

	// 2. compileRangeSingleField: unbounded -> exists, metric subpath -> FALSE, range field, histogram (top/inLambda/invalid), version (top/inLambda/invalid), ip (top/inLambda/invalid).
	if w := tr.compileRangeSingleField("status", esast.RangeCond{}, nil); !strings.Contains(w, "IS NOT NULL") {
		t.Fatalf("expected unbounded range to fall back to exists, got %s", w)
	}
	if w := tr.compileRangeSingleField("metrics_agg.min", esast.RangeCond{GTE: 1}, nil); w != "FALSE" {
		t.Fatalf("expected aggregate metric subpath range to return FALSE, got %s", w)
	}
	if w := tr.compileRangeSingleField("num_rng", esast.RangeCond{GTE: 5, LTE: 10, Relation: "WITHIN"}, nil); !strings.Contains(w, "_doc") && !strings.Contains(w, "COALESCE") {
		t.Fatalf("expected range on integer_range field, got %s", w)
	}
	if w := tr.compileRangeSingleField("hist", esast.RangeCond{GT: 1.0, LTE: 10.5}, nil); !strings.Contains(w, "SPLIT_PART(") {
		t.Fatalf("expected histogram range using SPLIT_PART, got %s", w)
	}
	if w := tr.compileRangeSingleField("items.hist", esast.RangeCond{GTE: 1.0, LT: 5.0}, inLam); !strings.Contains(w, "element_at(") || strings.Contains(w, "array_exists(") {
		t.Fatalf("expected histogram range inside inLambda to use element_at without array_exists, got %s", w)
	}
	trBadHist := NewTranspiler(sch, TranspilerOptions{})
	_ = trBadHist.compileRangeSingleField("hist", esast.RangeCond{GTE: "not_a_num"}, nil)
	if trBadHist.searchErr == nil {
		t.Fatalf("expected invalid histogram range bound error")
	}

	if w := tr.compileRangeSingleField("ver", esast.RangeCond{GT: "1.0.0", GTE: "1.0.0", LT: "2.0.0", LTE: "2.0.0"}, nil); !strings.Contains(w, "SPLIT_PART(") {
		t.Fatalf("expected version semver range predicate, got %s", w)
	}
	if w := tr.compileRangeSingleField("items.ver", esast.RangeCond{GTE: "1.2.3", LTE: "2.0.0"}, inLam); strings.Contains(w, "array_exists(") {
		t.Fatalf("expected no nested array_exists for version range inLambda, got %s", w)
	}
	trBadVer := NewTranspiler(sch, TranspilerOptions{})
	_ = trBadVer.compileRangeSingleField("ver", esast.RangeCond{LT: "not.a.semver.xyz.abc"}, nil)
	if trBadVer.searchErr == nil {
		t.Fatalf("expected invalid version range bound error")
	}

	if w := tr.compileRangeSingleField("items.ip", esast.RangeCond{GT: "10.0.0.1", LTE: "10.0.0.9"}, inLam); strings.Contains(w, "array_exists(") {
		t.Fatalf("expected no nested array_exists for ip range inLambda, got %s", w)
	}
	trBadIP := NewTranspiler(sch, TranspilerOptions{})
	_ = trBadIP.compileRangeSingleField("ip_addr", esast.RangeCond{GTE: "999.999.999.999"}, nil)
	if trBadIP.searchErr == nil {
		t.Fatalf("expected invalid IP range bound error")
	}
}

func TestRound67_CovGeoShapeLuceneSpanCommon(t *testing.T) {
	sch := buildRound67RichSchemaR67(t)
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})

	// 1. compileGeoShape: nil, ignore_unmapped, type mismatch error, indexed_shape, nil shape, geometrycollection, circle, polygon with hole, envelope (WITHIN across antimeridian / DISJOINT), multipoint, linestring.
	if cp := tr.compileGeoShape(nil, true, nil); cp.WhereSQL != "FALSE" {
		t.Fatalf("expected FALSE for nil GeoShapeQuery, got %+v", cp)
	}
	if cp := tr.compileGeoShape(&esast.GeoShapeQuery{Field: "unmapped_gs", IgnoreUnmapped: true}, false, nil); cp.WhereSQL != "FALSE" {
		t.Fatalf("expected FALSE for ignore_unmapped geo_shape, got %+v", cp)
	}
	trBadGS := NewTranspiler(sch, TranspilerOptions{})
	_ = trBadGS.compileGeoShape(&esast.GeoShapeQuery{Field: "count"}, false, nil)
	if trBadGS.searchErr == nil {
		t.Fatalf("expected error for geo_shape query on integer field")
	}
	if cp := tr.compileGeoShape(&esast.GeoShapeQuery{Field: "shape_pt", Shape: nil}, true, nil); !strings.Contains(cp.WhereSQL, "IS NOT NULL") {
		t.Fatalf("expected exists predicate for nil Shape on shape_pt, got %+v", cp)
	}
	geoPayloads := []string{
		`{"geo_shape":{"shape_pt":{"indexed_shape":{"id":"s1","index":"shapes","path":"shape"}}}}`,
		`{"geo_shape":{"shape_pt":{"shape":{"type":"circle","coordinates":[-74.0,40.7],"radius":"5km"},"relation":"DISJOINT"}}}`,
		`{"geo_shape":{"shape_pt":{"shape":{"type":"circle","coordinates":[-74.0,40.7],"radius":"5km"},"relation":"CONTAINS"}}}`,
		`{"geo_shape":{"shape_pt":{"shape":{"type":"polygon","coordinates":[[[0,0],[10,0],[10,10],[0,10],[0,0]],[[2,2],[4,2],[4,4],[2,4],[2,2]]]},"relation":"DISJOINT"}}}`,
		`{"geo_shape":{"shape_pt":{"shape":{"type":"polygon","coordinates":[[[0,0],[10,0],[10,10],[0,10],[0,0]]]},"relation":"CONTAINS"}}}`,
		`{"geo_shape":{"shape_pt":{"shape":{"type":"envelope","coordinates":[[170,10],[-170,0]]},"relation":"WITHIN"}}}`,
		`{"geo_shape":{"shape_pt":{"shape":{"type":"envelope","coordinates":[[-10,10],[10,0]]},"relation":"DISJOINT"}}}`,
		`{"geo_shape":{"shape_pt":{"shape":{"type":"multipoint","coordinates":[[-74,40],[-73,41]]},"relation":"DISJOINT"}}}`,
		`{"geo_shape":{"shape_pt":{"shape":{"type":"linestring","coordinates":[[-74,40],[-73,41]]},"relation":"INTERSECTS"}}}`,
		`{"geo_shape":{"shape_pt":{"shape":{"type":"geometrycollection","geometries":[{"type":"circle","coordinates":[-74,40],"radius":"1km"},{"type":"envelope","coordinates":[[-10,10],[10,0]]}]},"relation":"DISJOINT"}}}`,
	}
	for i, raw := range geoPayloads {
		var q esast.Query
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("unmarshal geo_shape %d: %v", i, err)
		}
		cp := tr.compileGeoShape(q.GeoShape, true, nil)
		if cp.WhereSQL == "" {
			t.Fatalf("empty SQL for geo_shape %d", i)
		}
	}

	// 2. buildLuceneAtomQueryWithFlags across parens, _exists_, wildcards, ranges, unary +/-/!, /regex/, groups, phrases, fuzziness, bools.
	flags := simpleQueryFlags{
		precedence:       true,
		timeZone:         "+02:00",
		phraseSlop:       2,
		quoteFieldSuffix: ".keyword",
		fuzziness:        "AUTO",
		expandFields: func(pat string) []string {
			if strings.HasPrefix(pat, "none") {
				return nil
			}
			return []string{"kw_a^2", "kw_b"}
		},
		checkRegexLen: func(_ string) {},
		isTextField: func(f string) bool {
			return f == "body"
		},
	}
	luceneTokens := []string{
		"(status:open OR status:closed)^2",
		"_exists_:title^3",
		"*:[* TO *]",
		"kw*:[* TO *]",
		"none*:[* TO *]",
		"kw*:[1 TO 10]",
		"none*:[1 TO 10]",
		"status:+open",
		"status:-closed",
		"count:-42",
		"kw*:/ab.*cd/",
		"none*:/xyz/",
		"status:/[a-z]+/",
		"kw*:(foo OR bar)",
		"status:-(bad OR err)",
		`title:"quick fox"`,
		"status:true",
		"body:true",
	}
	for _, tok := range luceneTokens {
		q := buildLuceneAtomQueryWithFlags(tok, "title", nil, "OR", 0, false, flags)
		cp := tr.CompileQuery(&q, true, nil)
		if cp.WhereSQL == "" {
			t.Fatalf("empty SQL for lucene token %q", tok)
		}
	}

	// 3. compileSpanQuery across all span variants including match_only_text rejection.
	if cp := tr.compileSpanQuery(nil, true, nil); cp.WhereSQL != "FALSE" {
		t.Fatalf("expected FALSE for nil span query, got %+v", cp)
	}
	spanPayloads := []string{
		`{"span_term":{"title":{"value":"hello","boost":2.0}}}`,
		`{"span_term":{"status":{"value":"open","case_insensitive":true}}}`,
		`{"span_near":{"clauses":[{"span_term":{"title":"quick"}},{"span_term":{"title":"fox"}}],"slop":0,"in_order":false,"boost":0}}`,
		`{"span_near":{"clauses":[{"span_term":{"title":"quick"}},{"span_term":{"body":"fox"}}],"slop":1}}`,
		`{"span_or":{"clauses":[{"span_term":{"title":"alpha"}},{"span_term":{"status":"open"}}],"boost":1.5}}`,
		`{"span_not":{"include":{"span_term":{"title":"alpha"}},"exclude":{"span_term":{"title":"beta"}},"boost":2.0}}`,
		`{"span_not":{"include":{"span_term":{"status":"open"}},"exclude":{"span_term":{"status":"closed"}}}}`,
		`{"span_first":{"match":{"span_term":{"title":"lead"}},"end":3,"boost":1.2}}`,
		`{"span_multi":{"match":{"prefix":{"status":"op"}},"boost":1.4}}`,
		`{"span_containing":{"big":{"span_term":{"title":"alpha"}},"little":{"span_term":{"body":"beta"}}}}`,
		`{"span_within":{"big":{"span_term":{"title":"alpha"}},"little":{"span_term":{"body":"beta"}}}}`,
		`{"field_masking_span":{"field":"body","query":{"span_term":{"title":"masked"}}}}`,
	}
	for i, raw := range spanPayloads {
		var q esast.Query
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("unmarshal span query %d: %v", i, err)
		}
		cp := tr.compileSpanQuery(&q, true, nil)
		if cp.WhereSQL == "" {
			t.Fatalf("empty SQL for span query %d", i)
		}
	}
	trSpanErr := NewTranspiler(sch, TranspilerOptions{})
	var badSpan esast.Query
	_ = json.Unmarshal([]byte(`{"span_term":{"mot_field":"hello"}}`), &badSpan)
	if cp := trSpanErr.compileSpanQuery(&badSpan, true, nil); cp.WhereSQL != "FALSE" || trSpanErr.searchErr == nil {
		t.Fatalf("expected span_term on match_only_text to error, cp=%+v err=%v", cp, trSpanErr.searchErr)
	}

	// 4. compileCommonTermsQueryR64 across non-text rejection, empty/zero_terms, corpus TermDocFreqFn, low/high MSM maps, scalar clamping.
	if _, ok := tr.compileCommonTermsQueryR64("title*", "quick fox", "or", "or", 0.1, nil, "", "", 1.0, true, nil, true); ok {
		t.Fatalf("expected wildcard field to return ok=false")
	}
	if _, ok := tr.compileCommonTermsQueryR64("status", "open", "or", "or", 0.1, nil, "", "", 1.0, true, nil, true); ok {
		t.Fatalf("expected keyword field to return ok=false")
	}
	if cp, ok := tr.compileCommonTermsQueryR64("title", "--- ---", "or", "or", 0.1, nil, "", "all", 1.0, true, nil, true); !ok || cp.WhereSQL != "TRUE" {
		t.Fatalf("expected empty token query with zero_terms_query=all -> TRUE, ok=%v cp=%+v", ok, cp)
	}
	if cp, ok := tr.compileCommonTermsQueryR64("title", "the quick brown fox", "and", "or", 0.1, 10, "", "none", 1.5, true, nil, false); !ok || cp.WhereSQL == "FALSE" {
		t.Fatalf("expected fallback stopword common terms query to compile, ok=%v cp=%+v", ok, cp)
	}
	trDF := NewTranspiler(sch, TranspilerOptions{
		ES8Compat: true,
		TermDocFreqFn: func(_ string, terms []string, _ bool) (int, map[string]int) {
			dfs := map[string]int{}
			for _, tm := range terms {
				if tm == "common" || tm == "verycommon" {
					dfs[tm] = 80
				} else {
					dfs[tm] = 2
				}
			}
			return 100, dfs
		},
	})
	if cp, ok := trDF.compileCommonTermsQueryR64("title", "common verycommon", "or", "", 0.5, map[string]any{"low_freq": 1, "high_freq": 1}, "", "", 2.0, true, nil, true); !ok || cp.WhereSQL == "FALSE" {
		t.Fatalf("expected all-high TermDocFreqFn common query with high_freq MSM to compile, ok=%v cp=%+v", ok, cp)
	}
	if cp, ok := trDF.compileCommonTermsQueryR64("title", "common verycommon", "or", "", 50, nil, "", "", 1.0, true, nil, true); !ok || cp.WhereSQL == "FALSE" {
		t.Fatalf("expected all-high absolute cutoff >=1 common query to compile, ok=%v cp=%+v", ok, cp)
	}
	if cp, ok := trDF.compileCommonTermsQueryR64("title", "rareterm common", "or", "and", 0.2, 5, "", "", 1.2, true, nil, false); !ok || cp.WhereSQL == "FALSE" {
		t.Fatalf("expected mixed low+high common query with scalar MSM clamping to compile, ok=%v cp=%+v", ok, cp)
	}
}
