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
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func mustDecodeSearchReqUseNumberR64(t *testing.T, raw string) *esast.SearchRequest {
	t.Helper()
	var req esast.SearchRequest
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		t.Fatalf("decode SearchRequest failed: %v\npayload: %s", err, raw)
	}
	return &req
}

func TestRound64_F10_P0InvariantsAndMissingUnsignedLong(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"title":   {"type": "text"},
			"kw":      {"type": "keyword"},
			"vec":     {"type": "dense_vector", "dims": 2},
			"pt":      {"type": "geo_point"},
			"uid":     {"type": "unsigned_long"},
			"tags":    {"type": "keyword"},
			"flt_arr": {"type": "float"},
			"dyn":     {"type": "object", "dynamic": true},
			"items": {
				"type": "nested",
				"properties": {
					"sub_kw": {"type": "keyword"},
					"qty":    {"type": "integer"},
					"price":  {"type": "double"},
					"emb":    {"type": "dense_vector", "dims": 2}
				}
			}
		}
	}`)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// P0-1 & P0-2 & P0-3:
	// - zero 1-arg JSON_TYPE
	// - post_filter, global, sampler, filter, filters, adjacency_matrix, background_filter on FROM base_matched use SafeWhere (no MATCH_*)
	// - keyword term emits exact '='
	// - buildAggsCTESQL wraps UNION ALL ORDER BY ... LIMIT branches cleanly
	req := mustUnmarshalSearchReqR62(t, `{
		"size": 2,
		"query": {"match": {"title": "laptop"}},
		"post_filter": {"bool": {"must": [{"match": {"title": "gaming"}}, {"term": {"kw": "ExactKW"}}]}},
		"aggs": {
			"top_k": {"top_hits": {"size": 2}},
			"by_kw": {"terms": {"field": "kw", "size": 5}},
			"flt": {"filter": {"match": {"title": "pro"}}},
			"flts": {"filters": {"filters": {"a": {"match": {"title": "air"}}}}},
			"adj": {"adjacency_matrix": {"filters": {"x": {"match": {"title": "x1"}}, "y": {"term": {"kw": "y1"}}}}},
			"glb": {"global": {}, "aggs": {"c": {"filter": {"match": {"title": "g1"}}}}},
			"smp": {"sampler": {"shard_size": 10}, "aggs": {"s_flt": {"filter": {"match": {"title": "s1"}}}}},
			"sig": {"significant_terms": {"field": "kw", "background_filter": {"match": {"title": "bg"}}}},
			"ex": {"filter": {"exists": {"field": "dyn.extra"}}}
		}
	}`)
	plan, err := tr.BuildSearchPlan(req)
	if err != nil {
		t.Fatalf("BuildSearchPlan F10 failed: %v", err)
	}
	if hasOneArgJSONTypeR64(plan.HitsSQL) || hasOneArgJSONTypeR64(plan.AggsSQL) {
		t.Fatalf("P0-1 regression: found 1-arg JSON_TYPE:\nhits=%s\naggs=%s", plan.HitsSQL, plan.AggsSQL)
	}
	if hasMatchInFromBaseMatchedR64(plan.AggsSQL) {
		t.Fatalf("P0-2 regression: found MATCH_* predicate inside FROM base_matched CTE consumer:\n%s", plan.AggsSQL)
	}
	if hasMatchInFromBaseMatchedR64("FROM base_matched WHERE " + tr.CompileQuery(req.PostFilter, false, nil).EffectiveSafeWhere()) {
		t.Fatalf("P0-2 regression: post_filter SafeWhere contains MATCH_*")
	}
	if !strings.Contains(plan.HitsSQL, "= 'ExactKW'") && !strings.Contains(tr.CompileQuery(&esast.Query{Term: map[string]esast.TermEntry{"kw": {Value: "ExactKW"}}}, false, nil).WhereSQL, "= 'ExactKW'") {
		t.Fatalf("P0-2 regression: expected exact '=' predicate for keyword term")
	}
	if hasUnparenthesizedOrderByInUnionAllR64(plan.AggsSQL) {
		t.Fatalf("P0-3 regression: unparenthesized ORDER BY ... LIMIT inside UNION ALL:\n%s", plan.AggsSQL)
	}

	// P0-4 & P1-6:
	// - TRY_CAST on strict-cast paths (nested metrics/range, geo SPLIT_PART, array_exists range DOUBLE)
	// - unsigned_long missing value max uint64 formatted accurately in CAST(... AS LARGEINT)
	rngReq := mustDecodeSearchReqUseNumberR64(t, `{
		"size": 0,
		"query": {"range": {"flt_arr": {"gte": 1.5, "lte": 3.5}}},
		"aggs": {
			"ul_rng": {
				"range": {
					"field": "uid",
					"missing": "18446744073709551615",
					"ranges": [{"from": 100, "to": "18446744073709551615"}]
				}
			},
			"ul_rng_num": {
				"range": {
					"field": "uid",
					"missing": 9223372036854775808,
					"ranges": [{"from": 100, "to": 10000000000000000000}]
				}
			},
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"avg_price": {"avg": {"field": "items.price"}},
					"price_rng": {"range": {"field": "items.price", "ranges": [{"from": 1.0, "to": 5.0}]}}
				}
			}
		}
	}`)
	rngPlan, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(rngReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan P0-4/P1-6 failed: %v", err)
	}
	if !strings.Contains(rngPlan.AggsSQL, "CAST(18446744073709551615 AS LARGEINT)") || !strings.Contains(rngPlan.AggsSQL, "CAST(9223372036854775808 AS LARGEINT)") {
		t.Fatalf("P1-6 regression: expected unsigned_long missing formatted accurately in CAST(... AS LARGEINT):\n%s", rngPlan.AggsSQL)
	}
	if !strings.Contains(rngPlan.AggsSQL, "TRY_CAST(") {
		t.Fatalf("P0-4 regression: expected TRY_CAST in nested metric/range AggsSQL:\n%s", rngPlan.AggsSQL)
	}
	geoWhere := NewTranspiler(sch, TranspilerOptions{}).CompileQuery(&esast.Query{
		GeoBoundingBox: &esast.GeoBoundingBoxQuery{Field: "pt", Top: 40, Bottom: 30, Left: -125, Right: -115},
	}, false, nil).WhereSQL
	if !strings.Contains(geoWhere, "TRY_CAST(SPLIT_PART(") {
		t.Fatalf("P0-4 regression: expected TRY_CAST(SPLIT_PART(...)) for geo_point, got: %s", geoWhere)
	}
}

func TestRound64_F8_UnsignedLongHistogram(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"kw":  {"type": "keyword"},
			"uid": {"type": "unsigned_long"}
		}
	}`)
	req := mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"ul_hist": {
				"histogram": {
					"field": "uid",
					"interval": 9223372036854776000
				}
			},
			"by_kw": {
				"terms": {"field": "kw", "size": 5},
				"aggs": {
					"sub_ul_hist": {
						"histogram": {
							"field": "uid",
							"interval": 9223372036854776000
						}
					}
				}
			},
			"comp": {
				"composite": {
					"size": 10,
					"sources": [
						{"uh": {"histogram": {"field": "uid", "interval": 9223372036854776000}}}
					]
				}
			}
		}
	}`)
	plan, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(req)
	if err != nil {
		t.Fatalf("BuildSearchPlan F8 failed: %v", err)
	}
	if !strings.Contains(plan.AggsSQL, "AS DOUBLE)") || !strings.Contains(plan.AggsSQL, "9223372036854776000") {
		t.Fatalf("F8 regression: expected unsigned_long histogram DOUBLE cast before division:\n%s", plan.AggsSQL)
	}
}

func TestRound64_F13_GeoGridAndGeoShapeRestrictions(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"loc":            {"type": "geo_point"},
			"shape_idx_f":    {"type": "geo_shape", "index": false},
			"shape_dv_f":     {"type": "geo_shape", "doc_values": false},
			"shape_disabled": {"type": "geo_shape", "index": false, "doc_values": false},
			"pt_plain":       {"type": "point"}
		}
	}`)

	for name, qJSON := range map[string]string{
		"geohash":     `{"geo_grid": {"loc": {"geohash": "u4pru"}}}`,
		"geotile":     `{"geo_grid": {"loc": {"geotile": "8/128/80"}}}`,
		"geohex":      `{"geo_grid": {"pt_plain": {"geohex": "881f1d4817fffff"}}}`,
		"shape_idx_f": `{"geo_shape": {"shape_idx_f": {"shape": {"type": "envelope", "coordinates": [[-10, 10], [10, -10]]}}}}`,
		"shape_dv_f":  `{"geo_shape": {"shape_dv_f": {"shape": {"type": "envelope", "coordinates": [[-10, 10], [10, -10]]}}}}`,
	} {
		req := mustUnmarshalSearchReqR62(t, `{"query": `+qJSON+`}`)
		plan, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(req)
		if err != nil {
			t.Fatalf("%s failed unexpectedly: %v", name, err)
		}
		if strings.TrimSpace(plan.HitsSQL) == "" || !isBalancedBackticksAndParensR64(plan.HitsSQL) {
			t.Fatalf("%s produced invalid HitsSQL:\n%s", name, plan.HitsSQL)
		}
	}

	disabledReq := mustUnmarshalSearchReqR62(t, `{"query": {"geo_shape": {"shape_disabled": {"shape": {"type": "envelope", "coordinates": [[-10, 10], [10, -10]]}}}}}`)
	if _, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(disabledReq); err == nil || !strings.Contains(err.Error(), "not indexed nor has doc values") {
		t.Fatalf("expected index:false+doc_values:false geo_shape error, got: %v", err)
	}
}

func TestRound64_F18_AnalysisGraphFallbackAndSAYT(t *testing.T) {
	cfg, err := analysis.ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"flat_syn": map[string]any{
					"type":     "synonym",
					"synonyms": []any{"sofa, couch"},
				},
				"graph_syn": map[string]any{
					"type":     "synonym_graph",
					"synonyms": []any{"ny, new york", "fast, quick"},
				},
			},
			"analyzer": map[string]any{
				"flat_an": map[string]any{
					"tokenizer": "standard",
					"filter":    []any{"lowercase", "flat_syn"},
				},
				"graph_an": map[string]any{
					"tokenizer": "standard",
					"filter":    []any{"lowercase", "graph_syn"},
				},
			},
			"normalizer": map[string]any{
				"lower_ascii": map[string]any{
					"type":   "custom",
					"filter": []any{"lowercase", "asciifolding"},
				},
			},
		},
	}, analysis.Options{})
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig failed: %v", err)
	}

	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"flat_txt":  {"type": "text", "search_analyzer": "flat_an"},
			"graph_txt": {"type": "text", "search_analyzer": "graph_an"},
			"norm_kw":   {"type": "keyword", "normalizer": "lower_ascii"},
			"sayt":      {"type": "search_as_you_type"}
		}
	}`)
	// Intentionally leave TranspilerOptions.AnalysisConfig == nil to test Schema fallback.
	sch.AnalysisConfig = cfg
	tr := NewTranspiler(sch, TranspilerOptions{})

	// 1. Query string auto_generate_synonyms_phrase_query: true vs false on synonym_graph
	qsPhrase := mustUnmarshalSearchReqR62(t, `{
		"query": {"query_string": {"default_field": "graph_txt", "query": "ny", "auto_generate_synonyms_phrase_query": true}}
	}`)
	qsPlanTrue, err := tr.BuildSearchPlan(qsPhrase)
	if err != nil {
		t.Fatalf("query_string auto_generate_synonyms_phrase_query=true failed: %v", err)
	}
	if !strings.Contains(qsPlanTrue.HitsSQL, "new[^[:alnum:]_]+york") && !strings.Contains(qsPlanTrue.HitsSQL, "MATCH_PHRASE") {
		t.Fatalf("expected phrase 'new york' expansion when auto_generate_synonyms_phrase_query=true:\n%s", qsPlanTrue.HitsSQL)
	}

	qsBool := mustUnmarshalSearchReqR62(t, `{
		"query": {"query_string": {"default_field": "graph_txt", "query": "ny", "auto_generate_synonyms_phrase_query": false}}
	}`)
	qsPlanFalse, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(qsBool)
	if err != nil {
		t.Fatalf("query_string auto_generate_synonyms_phrase_query=false failed: %v", err)
	}
	if !strings.Contains(qsPlanFalse.HitsSQL, "AND") || strings.Contains(qsPlanFalse.HitsSQL, "'new york'") {
		t.Fatalf("expected boolean AND expansion (not phrase) when auto_generate_synonyms_phrase_query=false:\n%s", qsPlanFalse.HitsSQL)
	}

	// 2. Flat synonym (match + match_phrase + common) + SAYT _2gram/_3gram + normalizer fallback
	req := mustUnmarshalSearchReqR62(t, `{
		"query": {
			"bool": {
				"must": [
					{"match": {"flat_txt": {"query": "sofa"}}},
					{"match_phrase": {"graph_txt": {"query": "ny ca", "slop": 1}}},
					{"match_phrase_prefix": {"graph_txt": {"query": "fast fo"}}},
					{"match_bool_prefix": {"graph_txt": {"query": "ny bo"}}},
					{"common": {"flat_txt": {"query": "sofa chair", "cutoff_frequency": 0.01}}},
					{"term": {"norm_kw": "CAFÉ"}},
					{"term": {"sayt._2gram": "quick fox"}},
					{"term": {"sayt._3gram": "quick brown fox"}}
				]
			}
		}
	}`)
	plan, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(req)
	if err != nil {
		t.Fatalf("BuildSearchPlan F18 combined failed: %v", err)
	}
	for _, want := range []string{"(sofa)", "(couch)", "'cafe'", "quick fox", "quick brown fox"} {
		if !strings.Contains(strings.ToLower(plan.HitsSQL), want) {
			t.Fatalf("F18 expected %q in HitsSQL:\n%s", want, plan.HitsSQL)
		}
	}
}

func TestRound64_F2_F4_F11_F16_F21_DownsampleTypesNestedAndSentinel(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"wc":  {"type": "wildcard", "null_value": "_null_wc_"},
			"ck":  {"type": "constant_keyword", "value": "v1"},
			"ts":  {"type": "date_nanos"},
			"uid": {"type": "unsigned_long"},
			"amd": {"type": "aggregate_metric_double", "metrics": ["min", "max", "sum", "value_count"], "default_metric": "max"}
		}
	}`)
	sch.IndexName = "r64_idx"

	// F2/F4/F11/F21 valid plan
	req := mustUnmarshalSearchReqR62(t, `{
		"min_score": 0.1,
		"query": {
			"function_score": {
				"query": {
					"bool": {
						"must": [
							{"term": {"wc": "_null_wc_"}},
							{"term": {"ck": "v1"}},
							{"range": {"ts": {"gte": "2026-01-01T00:00:00.123456789Z"}}},
							{"range": {"uid": {"gte": 1}}}
						]
					}
				},
				"field_value_factor": {"field": "uid", "modifier": "log"}
			}
		},
		"aggs": {
			"amd_max": {"max": {"field": "amd"}},
			"amd_avg": {"avg": {"field": "amd"}}
		}
	}`)
	plan, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(req)
	if err != nil {
		t.Fatalf("BuildSearchPlan F2/F4/F11/F21 failed: %v", err)
	}
	if !strings.Contains(plan.HitsSQL, "-1e308") || !strings.Contains(plan.HitsSQL, ">= 0.1") {
		t.Fatalf("F21 expected negative sentinel -1e308 and min_score >= 0.1 in HitsSQL:\n%s", plan.HitsSQL)
	}
	if strings.TrimSpace(plan.AggsSQL) == "" {
		t.Fatalf("F4 expected AggsSQL for aggregate_metric_double")
	}

	// F4 unsupported agg on aggregate_metric_double
	badAMD := mustUnmarshalSearchReqR62(t, `{"size": 0, "aggs": {"bad": {"cardinality": {"field": "amd"}}}}`)
	if _, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(badAMD); err == nil || !strings.Contains(err.Error(), "aggregate_metric_double") {
		t.Fatalf("F4 expected unsupported_aggregation_on_downsampled_index error, got: %v", err)
	}

	// F16 nested agg validation error on missing nested path
	badNested := mustUnmarshalSearchReqR62(t, `{"size": 0, "aggs": {"bad_n": {"nested": {"path": "missing_nested"}, "aggs": {"c": {"value_count": {"field": "uid"}}}}}}`)
	if _, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(badNested); err == nil || !strings.Contains(err.Error(), "failed to find nested object under path [missing_nested]") {
		t.Fatalf("F16 expected missing nested path error, got: %v", err)
	}
}
