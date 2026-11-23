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
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func buildRound65CovSchema(t *testing.T) *schema.IndexSchema {
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
				"custom_ws": map[string]any{
					"tokenizer": "whitespace",
					"filter":    []any{"lowercase"},
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
			"title":        {"type": "text", "analyzer": "standard", "fields": {"keyword": {"type": "keyword"}}},
			"title_ws":     {"type": "text", "analyzer": "whitespace"},
			"title_syn":    {"type": "text", "analyzer": "syn_an"},
			"title_only":   {"type": "text", "analyzer": "standard"},
			"title_mot":    {"type": "match_only_text"},
			"title_idx_p":  {"type": "text", "index_prefixes": {"min_chars": 2, "max_chars": 5}},
			"sayt":         {"type": "search_as_you_type"},
			"kw":           {"type": "keyword"},
			"kw_norm":      {"type": "keyword", "normalizer": "lower_norm"},
			"kw_ignore":    {"type": "keyword", "ignore_above": 5},
			"kw_arr":       {"type": "keyword"},
			"kw_norm_arr":  {"type": "keyword", "normalizer": "lower_norm"},
			"txt_arr":      {"type": "text", "analyzer": "standard"},
			"txt_ws_arr":   {"type": "text", "analyzer": "whitespace"},
			"wc":           {"type": "wildcard"},
			"ck":           {"type": "constant_keyword", "value": "pinned_const"},
			"no_idx":       {"type": "text", "index": false},
			"no_dv":        {"type": "keyword", "doc_values": false},
			"uid":          {"type": "unsigned_long"},
			"uid_arr":      {"type": "unsigned_long"},
			"cnt":          {"type": "long"},
			"cnt_arr":      {"type": "long"},
			"price":        {"type": "double"},
			"scores":       {"type": "double"},
			"flt":          {"type": "float"},
			"hf":           {"type": "half_float"},
			"sf":           {"type": "scaled_float", "scaling_factor": 100.0},
			"active":       {"type": "boolean"},
			"ts":           {"type": "date"},
			"ts_sec":       {"type": "date", "format": "epoch_second"},
			"ts_nanos":     {"type": "date_nanos"},
			"ts_arr":       {"type": "date"},
			"ip":           {"type": "ip"},
			"ip_arr":       {"type": "ip"},
			"ver":          {"type": "version"},
			"ver_arr":      {"type": "version"},
			"irange":       {"type": "integer_range"},
			"hist":         {"type": "histogram"},
			"amd":          {"type": "aggregate_metric_double", "metrics": ["min", "max", "sum", "value_count"], "default_metric": "max"},
			"amd_minonly":  {"type": "aggregate_metric_double", "metrics": ["min"], "default_metric": "min"},
			"mm3":          {"type": "murmur3"},
			"loc":          {"type": "geo_point"},
			"locs":         {"type": "geo_point"},
			"shape":        {"type": "geo_shape"},
			"rf":           {"type": "rank_feature", "positive_score_impact": true},
			"svec":         {"type": "sparse_vector"},
			"vec_cos":      {"type": "dense_vector", "dims": 3, "similarity": "cosine", "index_options": {"type": "hnsw"}},
			"vec_q8":       {"type": "dense_vector", "dims": 3, "similarity": "l2_norm", "index": true, "index_options": {"type": "int8_hnsw"}},
			"vec_q4":       {"type": "dense_vector", "dims": 3, "similarity": "l2_norm", "index": true, "index_options": {"type": "int4_flat"}},
			"vec_bit":      {"type": "dense_vector", "dims": 8, "element_type": "bit"},
			"vec_byte":     {"type": "dense_vector", "dims": 3, "element_type": "byte", "similarity": "dot_product"},
			"vec_mip":      {"type": "dense_vector", "dims": 3, "similarity": "max_inner_product"},
			"dyn":          {"type": "object", "dynamic": true},
			"items": {
				"type": "nested",
				"properties": {
					"sku":     {"type": "keyword"},
					"title":   {"type": "text"},
					"qty":     {"type": "integer"},
					"price":   {"type": "double"},
					"loc":     {"type": "geo_point"},
					"ver":     {"type": "version"},
					"ip":      {"type": "ip"},
					"emb_q8":  {"type": "dense_vector", "dims": 3, "similarity": "l2_norm", "index": true, "index_options": {"type": "int8_flat"}},
					"emb_mip": {"type": "dense_vector", "dims": 3, "similarity": "max_inner_product"}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	sch := schema.CompileIndexSchema("es_db", "r65_cov_idx", &spec)
	sch.AnalysisConfig = cfg
	sch.IndexName = "r65_cov_idx"

	promoteArray := func(name string, overrideType schema.DorisScalarType) {
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
	promoteArray("kw_arr", "")
	promoteArray("kw_norm_arr", "")
	promoteArray("txt_arr", "")
	promoteArray("txt_ws_arr", "")
	promoteArray("uid_arr", schema.DorisLargeIntArray)
	promoteArray("cnt_arr", "")
	promoteArray("scores", "")
	promoteArray("ts_arr", "")
	promoteArray("ip_arr", "")
	promoteArray("ver_arr", "")
	promoteArray("locs", "")

	if fb, ok := sch.Fields["items.ver"]; ok {
		fb.IsMultiValued = true
		sch.Fields["items.ver"] = fb
	}
	if fb, ok := sch.Fields["items.ip"]; ok {
		fb.IsMultiValued = true
		sch.Fields["items.ip"] = fb
	}
	return sch
}

func TestRound65_ProjectionSafeTextMatchSQL(t *testing.T) {
	sch := buildRound65CovSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// 1. Exact keyword ignore_above exceeded -> FALSE
	if got := tr.projectionSafeTextMatchSQL("kw_ignore", "toolongvalue", "or", nil); got != "FALSE" {
		t.Fatalf("expected FALSE when keyword exceeds ignore_above, got %s", got)
	}
	// 2. Exact keyword promoted array (with and without lowercase normalizer)
	if got := tr.projectionSafeTextMatchSQL("kw_norm_arr", "Foo", "or", nil); !strings.Contains(got, "array_exists(_x -> lower(_x) = lower('Foo'), `arr__kw_norm_arr`)") {
		t.Fatalf("expected lowercase array_exists on kw_norm_arr, got %s", got)
	}
	if got := tr.projectionSafeTextMatchSQL("kw_arr", "Foo", "or", nil); !strings.Contains(got, "array_exists(_x -> _x = 'Foo', `arr__kw_arr`)") {
		t.Fatalf("expected case-sensitive array_exists on kw_arr, got %s", got)
	}
	// 3. Exact keyword scalar
	if got := tr.projectionSafeTextMatchSQL("kw", "Alpha", "or", nil); !strings.Contains(got, "`f__kw` = 'Alpha'") {
		t.Fatalf("expected scalar exact term on kw, got %s", got)
	}
	// 4. Whitespace analyzer & standard analyzer with internal underscore (scalar + array)
	if got := tr.projectionSafeTextMatchSQL("title_ws", "Foo Bar", "and", nil); !strings.Contains(got, "REGEXP") || !strings.Contains(got, " AND ") {
		t.Fatalf("expected REGEXP AND on whitespace scalar, got %s", got)
	}
	if got := tr.projectionSafeTextMatchSQL("txt_ws_arr", "Foo Bar", "or", nil); !strings.Contains(got, "array_exists(_x -> _x IS NOT NULL AND _x REGEXP") || !strings.Contains(got, " OR ") {
		t.Fatalf("expected array_exists REGEXP OR on whitespace array, got %s", got)
	}
	if got := tr.projectionSafeTextMatchSQL("title_only", "foo_bar baz_qux", "and", nil); !strings.Contains(got, "REGEXP") || !strings.Contains(got, " AND ") {
		t.Fatalf("expected REGEXP AND for underscore token on standard text, got %s", got)
	}
	if got := tr.projectionSafeTextMatchSQL("txt_arr", "foo_bar baz", "or", nil); !strings.Contains(got, "array_exists(_x -> _x IS NOT NULL AND _x REGEXP") {
		t.Fatalf("expected array_exists REGEXP for underscore token on standard array, got %s", got)
	}
	// 5. Standard analyzer without underscore and phrase mode (scalar + array + nested)
	if got := tr.projectionSafeTextMatchSQL("txt_arr", "quick brown", "and", nil); !strings.Contains(got, "array_exists(_x -> lower(_x) LIKE lower('%quick%'), `arr__txt_arr`)") || !strings.Contains(got, " AND ") {
		t.Fatalf("expected array_exists LIKE AND on txt_arr, got %s", got)
	}
	if got := tr.projectionSafeTextMatchSQL("title_only", "quick brown", "phrase", nil); !strings.Contains(got, "lower(`f__title_only`) LIKE lower('%quick brown%')") {
		t.Fatalf("expected LIKE phrase on title_only, got %s", got)
	}
	nestedNctx := &nestedCtx{nestedPath: "items", elemVar: "_el"}
	if got := tr.projectionSafeTextMatchSQL("items.title", "alpha beta", "and", nestedNctx); !strings.Contains(got, "lower(json_extract_string(_el, '$.title')) LIKE lower('%alpha%')") {
		t.Fatalf("expected nested LIKE on items.title, got %s", got)
	}
}

func TestRound65_CombinedFieldsAndDecayFunction(t *testing.T) {
	sch := buildRound65CovSchema(t)

	// 1. compileCombinedFields: nil & empty fields (with matching schema, non-text schema, nil schema, conflicting schema)
	tr := NewTranspiler(sch, TranspilerOptions{})
	if cp := tr.compileCombinedFields(nil, true, nil); cp.WhereSQL != "FALSE" {
		t.Fatalf("expected FALSE for nil CombinedFieldsQuery, got %+v", cp)
	}
	// Empty fields on schema with conflicting analyzers (title=standard vs title_ws=whitespace) -> error
	trErr := NewTranspiler(sch, TranspilerOptions{})
	_ = trErr.compileCombinedFields(&esast.CombinedFieldsQuery{Query: "hello"}, true, nil)
	if trErr.searchErr == nil || !strings.Contains(trErr.searchErr.Error(), "different search analyzers") {
		t.Fatalf("expected different search analyzers error for empty fields on mixed schema, got %v", trErr.searchErr)
	}

	// Schema with only matching standard text fields -> empty fields succeeds
	var specTextOnly esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"a":{"type":"text"},"b":{"type":"match_only_text"}}}`), &specTextOnly)
	schTextOnly := schema.CompileIndexSchema("es_db", "t_only", &specTextOnly)
	trTextOnly := NewTranspiler(schTextOnly, TranspilerOptions{})
	cpEmpty := trTextOnly.compileCombinedFields(&esast.CombinedFieldsQuery{Query: "hello world"}, true, nil)
	if cpEmpty.WhereSQL == "FALSE" || trTextOnly.searchErr != nil {
		t.Fatalf("expected valid combined_fields on matching text-only schema, where=%s err=%v", cpEmpty.WhereSQL, trTextOnly.searchErr)
	}

	// Schema with NO text fields -> _all_text fallback
	var specNoText esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"k":{"type":"keyword"}}}`), &specNoText)
	trNoText := NewTranspiler(schema.CompileIndexSchema("es_db", "no_txt", &specNoText), TranspilerOptions{})
	_ = trNoText.compileCombinedFields(&esast.CombinedFieldsQuery{Query: "hello"}, true, nil)
	trNilSch := NewTranspiler(nil, TranspilerOptions{})
	_ = trNilSch.compileCombinedFields(&esast.CombinedFieldsQuery{Query: "hello"}, true, nil)

	// Non-text field error & mismatched explicit fields error
	trBadType := NewTranspiler(sch, TranspilerOptions{})
	_ = trBadType.compileCombinedFields(&esast.CombinedFieldsQuery{Query: "x", Fields: []string{"kw"}}, true, nil)
	if trBadType.searchErr == nil || !strings.Contains(trBadType.searchErr.Error(), "only supports [text] fields") {
		t.Fatalf("expected non-text field error, got %v", trBadType.searchErr)
	}
	trBadMix := NewTranspiler(sch, TranspilerOptions{})
	_ = trBadMix.compileCombinedFields(&esast.CombinedFieldsQuery{Query: "x", Fields: []string{"title_only", "title_ws"}}, true, nil)
	if trBadMix.searchErr == nil || !strings.Contains(trBadMix.searchErr.Error(), "different search analyzers") {
		t.Fatalf("expected analyzer mismatch error, got %v", trBadMix.searchErr)
	}

	// Wildcard * and prefix pattern with boost on uniform text schema
	trWild := NewTranspiler(schTextOnly, TranspilerOptions{})
	cpWildStar := trWild.compileCombinedFields(&esast.CombinedFieldsQuery{Query: "hello", Fields: []string{"*^2"}}, true, nil)
	if cpWildStar.WhereSQL == "FALSE" || trWild.searchErr != nil {
		t.Fatalf("expected wildcard *^2 combined_fields to succeed, where=%s err=%v", cpWildStar.WhereSQL, trWild.searchErr)
	}
	cpWildPat := trWild.compileCombinedFields(&esast.CombinedFieldsQuery{Query: "hello", Fields: []string{"a*^1.5", "b^3"}}, true, nil)
	if cpWildPat.WhereSQL == "FALSE" || trWild.searchErr != nil {
		t.Fatalf("expected wildcard a*^1.5 combined_fields to succeed, where=%s err=%v", cpWildPat.WhereSQL, trWild.searchErr)
	}
	// Wildcard * on schema with unindexed text field hits checkFieldSearchable error
	trWildErr := NewTranspiler(sch, TranspilerOptions{})
	_ = trWildErr.compileCombinedFields(&esast.CombinedFieldsQuery{Query: "hello", Fields: []string{"*"}}, true, nil)
	if trWildErr.searchErr == nil {
		t.Fatalf("expected searchErr on wildcard * including unindexed/mismatched fields")
	}
	trPatErr := NewTranspiler(sch, TranspilerOptions{})
	_ = trPatErr.compileCombinedFields(&esast.CombinedFieldsQuery{Query: "hello", Fields: []string{"no_*"}}, true, nil)
	if trPatErr.searchErr == nil {
		t.Fatalf("expected searchErr on pattern matching unindexed field")
	}

	// 2. compileDecayFunction: nil, dynamic geo, nested geo, array geo/date/num, invalid origin/scale, unknown type
	if got := tr.compileDecayFunction("gauss", nil, nil); got != "1.0" {
		t.Fatalf("expected 1.0 for nil decay spec, got %s", got)
	}
	if got := tr.compileDecayFunction("unknown", &esast.DecayFunctionSpec{Field: "price", Origin: 10, Scale: 5}, nil); got != "1.0" {
		t.Fatalf("expected 1.0 for unknown decay type, got %s", got)
	}
	// Dynamic variant inferred as geo_point
	dynGeo := tr.compileDecayFunction("gauss", &esast.DecayFunctionSpec{Field: "dyn.geo", Origin: "40.7,-74.0", Scale: "10km", Offset: "1km"}, nil)
	if !strings.Contains(dynGeo, "ST_Distance_Sphere") {
		t.Fatalf("expected ST_Distance_Sphere for dynamic geo decay, got %s", dynGeo)
	}
	// Invalid geo origin / scale
	if got := tr.compileDecayFunction("exp", &esast.DecayFunctionSpec{Field: "loc", Origin: "not_a_geo", Scale: "10km"}, nil); got != "1.0" {
		t.Fatalf("expected 1.0 for invalid geo origin, got %s", got)
	}
	if got := tr.compileDecayFunction("exp", &esast.DecayFunctionSpec{Field: "loc", Origin: "40.7,-74.0", Scale: "-5km"}, nil); got != "1.0" {
		t.Fatalf("expected 1.0 for non-positive geo scale, got %s", got)
	}
	// Nested geo_point decay
	nGeo := tr.compileDecayFunction("linear", &esast.DecayFunctionSpec{Field: "items.loc", Origin: "40.7,-74.0", Scale: "5km", Offset: "500m"}, &nestedCtx{nestedPath: "items", elemVar: "_el"})
	if !strings.Contains(nGeo, "TRY_CAST(SPLIT_PART(") || !strings.Contains(nGeo, "ST_Distance_Sphere") {
		t.Fatalf("expected nested TRY_CAST(SPLIT_PART) ST_Distance_Sphere, got %s", nGeo)
	}
	// Array geo_point decay with multi_value_mode
	for _, mvm := range []string{"min", "max", "avg", "sum"} {
		arrGeo := tr.compileDecayFunction("gauss", &esast.DecayFunctionSpec{Field: "locs", Origin: "40.7,-74.0", Scale: "5km", MultiValueMode: mvm}, nil)
		if !strings.Contains(arrGeo, "ST_Distance_Sphere") || !strings.Contains(arrGeo, "TRY_CAST(SPLIT_PART(") {
			t.Fatalf("expected array geo decay for mode %s, got %s", mvm, arrGeo)
		}
	}
	// Date & date_nanos decay (invalid origin/scale + array date + offset)
	if got := tr.compileDecayFunction("gauss", &esast.DecayFunctionSpec{Field: "ts", Origin: "not-a-date", Scale: "1d"}, nil); got != "1.0" {
		t.Fatalf("expected 1.0 for invalid date origin, got %s", got)
	}
	if got := tr.compileDecayFunction("gauss", &esast.DecayFunctionSpec{Field: "ts", Origin: "2026-01-01", Scale: "0s"}, nil); got != "1.0" {
		t.Fatalf("expected 1.0 for zero date scale, got %s", got)
	}
	arrDateDecay := tr.compileDecayFunction("exp", &esast.DecayFunctionSpec{Field: "ts_arr", Origin: "2026-01-01T00:00:00Z", Scale: "7d", Offset: "1d", MultiValueMode: "avg"}, nil)
	if !strings.Contains(arrDateDecay, "array_avg(array_map(_x -> ABS(TRY_CAST(_x AS DOUBLE)") {
		t.Fatalf("expected array date decay with TRY_CAST, got %s", arrDateDecay)
	}
	nanosDecay := tr.compileDecayFunction("linear", &esast.DecayFunctionSpec{Field: "ts_nanos", Origin: 1700000000000, Scale: "1d"}, nil)
	if !strings.Contains(nanosDecay, "GREATEST(0.0, 1.0 -") {
		t.Fatalf("expected linear decay for date_nanos, got %s", nanosDecay)
	}
	// Numeric decay invalid origin/scale + array numeric
	if got := tr.compileDecayFunction("gauss", &esast.DecayFunctionSpec{Field: "price", Origin: "bad_num", Scale: 10}, nil); got != "1.0" {
		t.Fatalf("expected 1.0 for invalid numeric origin, got %s", got)
	}
	if got := tr.compileDecayFunction("gauss", &esast.DecayFunctionSpec{Field: "price", Origin: 10, Scale: 0}, nil); got != "1.0" {
		t.Fatalf("expected 1.0 for zero numeric scale, got %s", got)
	}
	badDec := 1.5
	arrNumDecay := tr.compileDecayFunction("exp", &esast.DecayFunctionSpec{Field: "scores", Origin: 50, Scale: 10, Offset: 2, Decay: &badDec, MultiValueMode: "sum"}, nil)
	if !strings.Contains(arrNumDecay, "array_sum(array_map(_x -> ABS(TRY_CAST(_x AS DOUBLE)") {
		t.Fatalf("expected array numeric decay with TRY_CAST, got %s", arrNumDecay)
	}
}

func TestRound65_GeoPointLatLonCountedTermsAndSortEpoch(t *testing.T) {
	sch := buildRound65CovSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// 1. resolveGeoPointLatLonSQL inside nestedCtx + scalar
	latE, lonE, nn := tr.resolveGeoPointLatLonSQL("items.loc", &nestedCtx{nestedPath: "items", elemVar: "_el"})
	if !strings.Contains(latE, "TRY_CAST(SPLIT_PART(") || !strings.Contains(lonE, "SPLIT_PART") || !strings.Contains(nn, "IS NOT NULL") {
		t.Fatalf("unexpected nested resolveGeoPointLatLonSQL: lat=%s lon=%s nn=%s", latE, lonE, nn)
	}
	sLat, sLon, sNN := tr.resolveGeoPointLatLonSQL("loc", nil)
	if sLat == "" || sLon == "" || sNN == "" {
		t.Fatalf("unexpected scalar resolveGeoPointLatLonSQL: lat=%s lon=%s nn=%s", sLat, sLon, sNN)
	}
	// Also exercise via nested geo_bounds / geohash_grid agg
	nestedGeoReq := mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"n_items": {
				"nested": {"path": "items"},
				"aggs": {
					"gh": {"geohash_grid": {"field": "items.loc", "precision": 5}},
					"gt": {"geotile_grid": {"field": "items.loc", "precision": 5}},
					"gx": {"geohex_grid": {"field": "items.loc", "precision": 5}},
					"gb": {"geo_bounds": {"field": "items.loc"}},
					"gc": {"geo_centroid": {"field": "items.loc"}}
				}
			}
		}
	}`)
	geoPlan, err := tr.BuildSearchPlan(nestedGeoReq)
	if err != nil || strings.TrimSpace(geoPlan.AggsSQL) == "" {
		t.Fatalf("nested geo aggs failed: err=%v sql=%s", err, geoPlan.AggsSQL)
	}

	// 2. buildCountedTermsSourceArrayExprR63: promoted array vs scalar keyword vs dynamic
	if arrExpr, isProm := tr.buildCountedTermsSourceArrayExprR63("kw_arr", sch.Fields["kw_arr"]); !isProm || arrExpr != "arr__kw_arr" {
		t.Fatalf("expected promoted array for kw_arr, got (%s, %v)", arrExpr, isProm)
	}
	if arrExpr, isProm := tr.buildCountedTermsSourceArrayExprR63("kw", sch.Fields["kw"]); isProm || !strings.Contains(arrExpr, "TRY_CAST(") {
		t.Fatalf("expected CASE WHEN JSON_TYPE fallback for scalar kw, got (%s, %v)", arrExpr, isProm)
	}
	ctPlan, err := tr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"ct_scalar": {"counted_terms": {"field": "kw", "size": 5}},
			"by_active": {
				"terms": {"field": "active", "size": 2},
				"aggs": {
					"ct_sub": {"counted_terms": {"field": "dyn.tags", "size": 5}}
				}
			}
		}
	}`))
	if err != nil || !strings.Contains(ctPlan.AggsSQL, "TRY_CAST(") {
		t.Fatalf("counted_terms scalar/dynamic failed: err=%v sql=%s", err, ctPlan.AggsSQL)
	}

	// 3. normalizeEpochSecondSortValue: all types & formats
	bDate := schema.FieldBinding{ESType: "date", DorisType: schema.DorisBigInt, Format: "epoch_second"}
	bNanos := schema.FieldBinding{ESType: "date_nanos", DorisType: schema.DorisBigInt, Format: "epoch_second"}
	if got := normalizeEpochSecondSortValue("date", "", bDate, nil); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date", "", bDate, "2026-01-01"); got != "2026-01-01" {
		t.Fatalf("expected string unchanged, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("keyword", "", schema.FieldBinding{ESType: "keyword", DorisType: schema.DorisVarchar}, 5); got != 5 {
		t.Fatalf("expected non-date unchanged, got %v", got)
	}
	// date_nanos + explicit epoch_millis
	if got := normalizeEpochSecondSortValue("date_nanos", "epoch_millis", bNanos, int(42)); got != int64(42_000_000) {
		t.Fatalf("expected 42ms -> 42000000ns, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date_nanos", "epoch_millis", bNanos, int64(42)); got != int64(42_000_000) {
		t.Fatalf("expected int64 42ms -> 42000000ns, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date_nanos", "epoch_millis", bNanos, json.Number("42")); got != int64(42_000_000) {
		t.Fatalf("expected json.Number 42ms -> 42000000ns, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date_nanos", "epoch_millis", bNanos, int64(math.MaxInt64)); got != int64(math.MaxInt64) {
		t.Fatalf("expected overflow guard on epoch_millis, got %v", got)
	}
	// date & date_nanos + epoch_second
	if got := normalizeEpochSecondSortValue("date", "", bDate, int(10)); got != int64(10000) {
		t.Fatalf("expected int 10s -> 10000ms, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date", "", bDate, int64(10)); got != int64(10000) {
		t.Fatalf("expected int64 10s -> 10000ms, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date", "", bDate, float64(10.5)); got != int64(10500) {
		t.Fatalf("expected float64 10.5s -> 10500ms, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date", "", bDate, json.Number("10")); got != int64(10000) {
		t.Fatalf("expected json.Number 10s -> 10000ms, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date", "", bDate, json.Number("10.25")); got != int64(10250) {
		t.Fatalf("expected json.Number 10.25s -> 10250ms, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date_nanos", "", bNanos, int(7)); got != int64(7_000_000_000) {
		t.Fatalf("expected date_nanos 7s -> 7e9ns, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date_nanos", "", bNanos, int64(math.MaxInt64)); got != int64(math.MaxInt64) {
		t.Fatalf("expected date_nanos int64 overflow guard, got %v", got)
	}
	if got := normalizeEpochSecondSortValue("date_nanos", "", bNanos, json.Number("9223372036854775807")); got != int64(math.MaxInt64) {
		t.Fatalf("expected date_nanos json.Number overflow guard, got %v", got)
	}

	// 4. parseSortGeoPointLatLon & compileGeoDistanceSortExpr
	for _, rawOrigin := range []any{
		map[string]any{"lat": json.Number("40.7"), "lon": "-74.0"},
		[]any{int64(-74), int(41)},
		"POINT(-74.0 40.7)",
		"40.7, -74.0",
		"u4pruydqqvj",
	} {
		if _, _, ok := parseSortGeoPointLatLon(rawOrigin); !ok {
			t.Fatalf("parseSortGeoPointLatLon failed for %v", rawOrigin)
		}
	}
	if _, _, ok := parseSortGeoPointLatLon("invalid_geo"); ok {
		t.Fatalf("expected parseSortGeoPointLatLon false for invalid_geo")
	}
	geoSortReq := mustDecodeSearchReqUseNumberR64(t, `{
		"size": 3,
		"sort": [
			{"_geo_distance": {"locs": "40.7,-74.0", "mode": "median", "order": "asc"}},
			{"_geo_distance": {"locs": "40.7,-74.0", "mode": "avg", "order": "desc"}},
			{"_geo_distance": {"items.loc": [-74.0, 40.7], "mode": "max", "nested": {"path": "items", "filter": {"term": {"items.sku": "s1"}}}}},
			{"_geo_distance": {"loc": {"lat": 40.7, "lon": -74.0}, "missing": "5km"}}
		]
	}`)
	geoSortPlan, err := tr.BuildSearchPlan(geoSortReq)
	if err != nil || !strings.Contains(geoSortPlan.HitsSQL, "array_median") || !strings.Contains(geoSortPlan.HitsSQL, "array_filter") {
		t.Fatalf("geo sort plan failed: err=%v sql=%s", err, geoSortPlan.HitsSQL)
	}
}

func TestRound65_LuceneAutoNodeAndQueryStringDoris4(t *testing.T) {
	sch := buildRound65CovSchema(t)

	// 1. asSubRE2, renderLuceneAutoNodeSQL, renderLuceneAutoNodeTokenSQL
	// Complement over literal inside quantifier -> uses complRE2 via asSubRE2
	compLit, err := CompileLuceneRegexpToSQLPredicates(`(~"abc")+`, "ALL", false)
	if err != nil {
		t.Fatalf("expected (~\"abc\")+ to compile, got %v", err)
	}
	w, sw, _ := compLit.ScalarSQL("`f__kw`", false, false)
	if !strings.Contains(w, "REGEXP") || sw == "" {
		t.Fatalf("unexpected ScalarSQL for compLit: w=%s sw=%s", w, sw)
	}
	// Quantifier over non-RE2-convertible nodes -> regexp_syntax_exception (covers asSubRE2 false paths)
	for _, badQuant := range []string{`(~[a-z])+`, `(a&b)+`, `(a|(b&c))+`} {
		if _, errQ := CompileLuceneRegexpToSQLPredicates(badQuant, "ALL", false); errQ == nil {
			t.Fatalf("expected asSubRE2 failure for %s", badQuant)
		}
	}
	// Union of valid RE2 nodes inside quantifier
	if _, errU := CompileLuceneRegexpToSQLPredicates(`(~"a"|"b")+`, "ALL", false); errU != nil {
		t.Fatalf("expected (~\"a\"|\"b\")+ to compile, got %v", errU)
	}

	// Render Empty, RE2(isAnyStr), Compl, Inter, Union for BOTH ScalarSQL(..., isTokenizedText=false) & (..., isTokenizedText=true)
	for _, pat := range []string{`#`, `@`, `~foo`, `foo&bar`, `(foo&bar)|baz`} {
		compiled, errP := CompileLuceneRegexpToSQLPredicates(pat, "ALL", false)
		if errP != nil {
			t.Fatalf("CompileLuceneRegexpToSQLPredicates(%q) failed: %v", pat, errP)
		}
		wScalar, _, _ := compiled.ScalarSQL("`f__kw`", false, false)
		wTok, _, _ := compiled.ScalarSQL("`f__title`", false, true)
		if wScalar == "" || wTok == "" {
			t.Fatalf("empty SQL rendering for %q: scalar=%q tok=%q", pat, wScalar, wTok)
		}
	}
	// Default unknown kind and empty node coverage in renderLuceneAutoNodeSQL / renderLuceneAutoNodeTokenSQL / asSubRE2
	emptyNode := &luceneAutoNode{kind: luceneNodeEmpty}
	if renderLuceneAutoNodeSQL(emptyNode, "`c`", false) != "FALSE" || renderLuceneAutoNodeTokenSQL(emptyNode, "`c`") != "FALSE" {
		t.Fatal("expected FALSE for empty node in renderLuceneAutoNode*")
	}
	unknownNode := &luceneAutoNode{kind: luceneAutoNodeKind(99)}
	if _, ok := unknownNode.asSubRE2(); ok {
		t.Fatal("expected unknown kind asSubRE2=false")
	}
	if renderLuceneAutoNodeSQL(unknownNode, "`c`", false) != "FALSE" {
		t.Fatal("expected FALSE for unknown node in renderLuceneAutoNodeSQL")
	}
	if renderLuceneAutoNodeTokenSQL(unknownNode, "`c`") != "FALSE" {
		t.Fatal("expected FALSE for unknown node in renderLuceneAutoNodeTokenSQL")
	}

	// 2. Doris 4 SEARCH() multi-field disjunction & fielded clauses
	trD4 := NewTranspiler(sch, TranspilerOptions{UseDoris4SearchFunc: true})
	for _, qs := range []esast.QueryStringQuery{
		{Query: "(alpha OR beta)", Fields: []string{"title_only", "title_mot"}},
		{Query: "title_only:alpha AND title_mot:beta", Fields: []string{"title_only", "title_mot"}},
		{Query: "alpha AND beta", Fields: []string{"title_only", "title_mot"}, DefaultOperator: "AND"},
		{Query: "alpha", Fields: []string{"title_only", "kw_norm"}},
		{Query: "alpha", DefaultField: "title_*"},
		{Query: "alpha", DefaultField: "nonexistent_*"},
		{Query: "*alpha", DefaultField: "title_only", AllowLeadingWildcard: boolPtrR65(false)},
		{Query: "[1 TO 10", DefaultField: "cnt"},
		{Query: "a AND", DefaultField: "title_only"},
		{Query: `"quick fox"`, Fields: []string{"title*"}, QuoteFieldSuffix: ".keyword", QuoteAnalyzer: "whitespace"},
		{Query: `""`, Fields: []string{"title_only", "title_mot"}},
		{Query: "*:*", Fields: []string{"title_only^2", "*"}},
		{Query: "*", Fields: []string{"title_only^2", "kw"}},
		{Query: "alpha+beta", DefaultField: "title_only", SplitOnWhitespace: boolPtrR65(false), Escape: boolPtrR65(true)},
	} {
		qCopy := qs
		_ = trD4.CompileQuery(&esast.Query{QueryString: &qCopy}, true, nil)
		trD4.searchErr = nil
	}
	if canEmitMultiFieldDoris4SearchDisjunction("(+alpha beta)", "OR") {
		t.Fatal("expected false for + operator inside parens")
	}
	if canEmitMultiFieldDoris4SearchDisjunction("alpha beta", "AND") {
		t.Fatal("expected false for multi-clause AND in multi-field SEARCH")
	}
}

func TestRound65_F3_F4a_Regressions(t *testing.T) {
	sch := buildRound65CovSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// F3 (P0-4): verify ZERO raw CAST on untrusted array/json expressions across queries and aggs
	f3Req := mustDecodeSearchReqUseNumberR64(t, `{
		"size": 5,
		"query": {
			"bool": {
				"must": [
					{"term": {"uid_arr": "18446744073709551615"}},
					{"terms": {"uid_arr": ["10", "20"]}},
					{"range": {"uid_arr": {"gte": 1, "lte": 100}}},
					{"range": {"scores": {"gte": 1.0, "lte": 5.0}}},
					{"rank_feature": {"field": "rf"}},
					{"distance_feature": {"field": "ts_arr", "origin": "2026-01-01T00:00:00Z", "pivot": "1d"}},
					{"distance_feature": {"field": "locs", "origin": [0.0, 0.0], "pivot": "100m"}},
					{"sparse_vector": {"field": "svec", "query_vector": {"tok1": 1.5}}},
					{"term": {"svec.tok1": 0.5}},
					{"function_score": {"gauss": {"scores": {"origin": 50, "scale": 10}}}}
				]
			}
		},
		"sort": [
			{"cnt_arr": {"order": "asc", "mode": "avg"}},
			{"uid_arr": {"order": "desc", "mode": "max"}},
			{"scores": {"order": "asc", "mode": "median"}},
			{"dyn.num": {"order": "asc", "unmapped_type": "unsigned_long"}}
		],
		"aggs": {
			"sc_stats": {"stats": {"field": "scores"}},
			"sc_box": {"boxplot": {"field": "scores", "missing": 0.0}},
			"sc_pct": {"percentiles": {"field": "scores", "percents": [50, 95], "missing": 0.0}},
			"sc_ranks": {"percentile_ranks": {"field": "scores", "values": [10, 50], "missing": 0.0}},
			"ts_dh": {"date_histogram": {"field": "ts_arr", "fixed_interval": "1d"}},
			"sc_hist": {"histogram": {"field": "scores", "interval": 10, "missing": 0.0}},
			"sc_rng": {"range": {"field": "scores", "ranges": [{"from": 0, "to": 10}]}},
			"comp": {"composite": {"size": 5, "sources": [{"sc": {"histogram": {"field": "scores", "interval": 10}}}]}},
			"by_kw": {
				"terms": {"field": "kw", "size": 3},
				"aggs": {
					"sub_stats": {"stats": {"field": "scores", "missing": 1.0}},
					"sub_box": {"boxplot": {"field": "scores", "missing": 1.0}},
					"sub_pct": {"percentiles": {"field": "scores", "missing": 1.0}},
					"sub_ranks": {"percentile_ranks": {"field": "scores", "values": [10], "missing": 1.0}},
					"sub_dh": {"date_histogram": {"field": "ts_arr", "fixed_interval": "1d"}},
					"sub_hist": {"histogram": {"field": "scores", "interval": 10, "missing": 1.0}},
					"sub_rng": {"range": {"field": "scores", "ranges": [{"from": 0, "to": 10}]}}
				}
			}
		}
	}`)
	f3Plan, err := tr.BuildSearchPlan(f3Req)
	if err != nil {
		t.Fatalf("F3 BuildSearchPlan failed: %v", err)
	}
	for _, sqlOut := range []string{f3Plan.HitsSQL, f3Plan.AggsSQL} {
		if hasRawUntrustedCastR65(sqlOut) {
			t.Fatalf("F3 regression: raw CAST on untrusted expression in:\n%s", sqlOut)
		}
		if !strings.Contains(sqlOut, "TRY_CAST(") {
			t.Fatalf("F3 regression: expected TRY_CAST in:\n%s", sqlOut)
		}
	}

	// F4a (P1-4): score() never inside FROM base_matched / SafeWhereSQL / activeMainScoreSQL;
	// MATCH_* never inside CAST(COALESCE(...))
	trD4 := NewTranspiler(sch, TranspilerOptions{UseDoris4SearchFunc: true})
	f4Req := mustUnmarshalSearchReqR62(t, `{
		"size": 5,
		"min_score": 0.2,
		"query": {
			"bool": {
				"must": [
					{"match": {"title_only": "pizza"}},
					{"match": {"title_syn": {"query": "ny pizza", "minimum_should_match": 1}}},
					{"match_bool_prefix": {"title_syn": {"query": "fast ny pi", "fuzziness": "AUTO", "minimum_should_match": 2}}},
					{"common": {"title_syn": {"query": "ny fast", "cutoff_frequency": 0.001, "minimum_should_match": 1}}}
				]
			}
		},
		"post_filter": {"match": {"title_only": "laptop"}},
		"aggs": {
			"glb": {"global": {}, "aggs": {"flt": {"filter": {"match": {"title_only": "gaming"}}}}},
			"smp": {"sampler": {"shard_size": 10}, "aggs": {"c": {"value_count": {"field": "cnt"}}}},
			"by_kw": {"terms": {"field": "kw", "size": 3}}
		}
	}`)
	f4Plan, err := trD4.BuildSearchPlan(f4Req)
	if err != nil {
		t.Fatalf("F4a BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(f4Plan.HitsSQL, "score()") {
		t.Fatalf("expected score() in HitsSQL when UseDoris4SearchFunc=true, got:\n%s", f4Plan.HitsSQL)
	}
	if hasScoreInFromBaseMatchedR65(f4Plan.AggsSQL) || strings.Contains(trD4.activeMainScoreSQL, "score()") {
		t.Fatalf("F4a regression: score() leaked into AggsSQL FROM base_matched or activeMainScoreSQL:\nactiveMainScoreSQL=%s\nAggsSQL=%s", trD4.activeMainScoreSQL, f4Plan.AggsSQL)
	}
	if hasMatchInFromBaseMatchedR64(f4Plan.AggsSQL) || hasMatchInCastCoalesceR65(f4Plan.HitsSQL) || hasMatchInCastCoalesceR65(f4Plan.AggsSQL) {
		t.Fatalf("F4a regression: MATCH_* leaked into base_matched or CAST(COALESCE(...)):\nhits=%s\naggs=%s", f4Plan.HitsSQL, f4Plan.AggsSQL)
	}

	// combineMatchPredicatesR65 direct edge cases (impossible msm, reqCount==1, reqCount==len, AND)
	w, sw, imp := combineMatchPredicatesR65([]string{"a MATCH_ANY 'x'", "b MATCH_ANY 'y'"}, []string{"a LIKE '%x%'", "b LIKE '%y%'"}, false, 3)
	if !imp || w != "FALSE" || sw != "FALSE" {
		t.Fatalf("expected impossible=true for msm=3 on 2 preds, got (%s, %s, %v)", w, sw, imp)
	}
	w, sw, imp = combineMatchPredicatesR65([]string{"a MATCH_ANY 'x'", "b MATCH_ANY 'y'"}, []string{"a LIKE '%x%'", "b LIKE '%y%'"}, false, 2)
	if imp || !strings.Contains(w, " AND ") || strings.Contains(w, "COALESCE") {
		t.Fatalf("expected plain AND when reqCount==len, got (%s, %s, %v)", w, sw, imp)
	}
	w, sw, imp = combineMatchPredicatesR65([]string{"a MATCH_ANY 'x'", "b MATCH_ANY 'y'", "c MATCH_ANY 'z'"}, []string{"a LIKE '%x%'", "b LIKE '%y%'", "c LIKE '%z%'"}, false, 2)
	if imp || hasMatchInCastCoalesceR65(w) || hasMatchInCastCoalesceR65(sw) {
		t.Fatalf("expected safePreds inside CAST(COALESCE(...)), got w=%s sw=%s", w, sw)
	}
}

func TestRound65_L3_L5a_L6_L7_And_C_Regressions(t *testing.T) {
	sch := buildRound65CovSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// 1. ComputeESBoxplotWithExecutionHint ("high_accuracy" vs default ES8)
	vals := []float64{1, 2, 3, 4, 5, 6, 7, 8}
	bpDefault := ComputeESBoxplotWithExecutionHint(vals, 100, true, "")
	bpHighAcc := ComputeESBoxplotWithExecutionHint(vals, 100, true, "high_accuracy")
	if bpDefault.Min == nil || *bpDefault.Min != 1 || bpHighAcc.Max == nil || *bpHighAcc.Max != 8 {
		t.Fatalf("unexpected boxplot bounds: def=%+v high=%+v", bpDefault, bpHighAcc)
	}

	// 2. Quantized dense_vector kNN tolerance + vector fallback IF + bit/byte/mip kNN
	if !isQuantizedVectorIndexR65(sch.Fields["vec_q8"]) || !isQuantizedVectorIndexR65(sch.Fields["vec_q4"]) || isQuantizedVectorIndexR65(sch.Fields["vec_cos"]) || isQuantizedVectorIndexR65(sch.Fields["vec_bit"]) {
		t.Fatalf("unexpected isQuantizedVectorIndexR65 results")
	}
	if !PassesESVectorSimilarityWithBinding([]float64{1, 0, 0}, []float64{0, 0, 0}, sch.Fields["vec_q8"], 0.99) {
		t.Fatalf("expected quantized L2 similarity tolerance (0.99*1.02 >= 1.0) to pass")
	}
	if PassesESVectorSimilarityWithBinding([]float64{1, 0, 0}, []float64{0, 0, 0}, schema.FieldBinding{VectorMetric: "l2_norm", VectorIndexOptions: map[string]any{"type": "hnsw"}}, 0.99) {
		t.Fatalf("expected unquantized hnsw L2 similarity 0.99 < 1.0 to fail")
	}
	if PassesESVectorSimilarityWithBinding([]float64{1, 0, 0}, []float64{0, 0, 0}, sch.Fields["vec_cos"], 0.99) {
		t.Fatalf("expected cosine similarity 0.0 < 0.99 to fail")
	}
	if got := buildVectorSourceFallbackColExprR63("vec_cos", sch.Fields["vec_cos"]); !strings.Contains(got, "array_size(`") {
		t.Fatalf("expected IF(col IS NOT NULL AND array_size(col) > 0) fallback, got %s", got)
	}
	trKNN := NewTranspiler(sch, TranspilerOptions{})
	knnPlan, err := trKNN.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{
		"size": 3,
		"knn": [
			{"field": "vec_q8", "query_vector": [1, 0, 0], "k": 3, "num_candidates": 5, "similarity": 1.0},
			{"field": "vec_bit", "query_vector": "ff", "k": 2, "num_candidates": 4},
			{"field": "vec_byte", "query_vector": [1, 2, 3], "k": 2, "num_candidates": 4},
			{"field": "vec_mip", "query_vector": [1, 2, 3], "k": 2, "num_candidates": 4}
		],
		"query": {
			"nested": {
				"path": "items",
				"query": {"knn": {"field": "items.emb_q8", "query_vector": [1, 0, 0], "k": 2, "similarity": 1.0}}
			}
		}
	}`))
	if err != nil || !strings.Contains(knnPlan.HitsSQL, "1.02") {
		t.Fatalf("expected quantized similarity 1.02 in kNN SQL, err=%v sql=%s", err, knnPlan.HitsSQL)
	}
	// kNN validation error paths (AST direct + JSON-decoded)
	for _, badReq := range []*esast.SearchRequest{
		{KNN: []esast.KNNQuery{{Field: "vec_cos", QueryVector: []float64{1, 0, 0}, K: -1}}},
		{KNN: []esast.KNNQuery{{Field: "vec_cos", QueryVector: []float64{1, 0, 0}, NumCandidates: 20000}}},
		{KNN: []esast.KNNQuery{{Field: "vec_cos", QueryVector: []float64{1, 0, 0}, K: 5, NumCandidates: 2}}},
		{Query: &esast.Query{KNN: &esast.KNNQuery{Field: "vec_cos", QueryVector: []float64{1, 0, 0}, K: -1}}},
		{Query: &esast.Query{KNN: &esast.KNNQuery{Field: "vec_cos", QueryVector: []float64{1, 0, 0}, NumCandidates: 20000}}},
		{Query: &esast.Query{KNN: &esast.KNNQuery{Field: "vec_cos", QueryVector: []float64{1, 0, 0}, K: 5, NumCandidates: 2}}},
	} {
		trErr := NewTranspiler(sch, TranspilerOptions{})
		if _, errK := trErr.BuildSearchPlan(badReq); errK == nil {
			t.Fatalf("expected error for invalid kNN AST %+v", badReq)
		}
	}
	for _, badKNN := range []string{
		`{"knn":[{"field":"kw","query_vector":[1,0,0],"k":2,"num_candidates":4}]}`,
		`{"knn":[{"field":"vec_bit","query_vector":"ffff","k":2,"num_candidates":4}]}`,
		`{"knn":[{"field":"vec_bit","query_vector":[1,2],"k":2,"num_candidates":4}]}`,
		`{"knn":[{"field":"vec_byte","query_vector":[1,2],"k":2,"num_candidates":4}]}`,
	} {
		trErr := NewTranspiler(sch, TranspilerOptions{})
		if _, errK := trErr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, badKNN)); errK == nil {
			t.Fatalf("expected error for invalid kNN %s", badKNN)
		}
	}

	// 3. foldNumericRangeBoundsOutOfBounds (float, half_float, scaled_float)
	if _, _, _, _, af := foldNumericRangeBoundsOutOfBounds(sch.Fields["flt"], math.MaxFloat32, nil, nil, nil); !af {
		t.Fatal("expected alwaysFalse for float gt >= MaxFloat32")
	}
	if _, outGTE, _, _, af := foldNumericRangeBoundsOutOfBounds(sch.Fields["flt"], nil, 3.4028235e38, nil, nil); af || outGTE != float64(math.MaxFloat32) {
		t.Fatalf("expected 3.4028235e38 gte to clamp to MaxFloat32, got (%v, %v)", outGTE, af)
	}
	if _, _, outLT, outLTE, af := foldNumericRangeBoundsOutOfBounds(sch.Fields["flt"], nil, nil, 1e300, nil); af || outLT != nil || outLTE != 3.4028235e+38 {
		t.Fatalf("expected lt 1e300 to fold to lte 3.4028235e+38, got (%v, %v, %v)", outLT, outLTE, af)
	}
	if outGT, outGTE, _, _, af := foldNumericRangeBoundsOutOfBounds(sch.Fields["flt"], -1e300, nil, nil, nil); af || outGT != nil || outGTE != -3.4028235e+38 {
		t.Fatalf("expected gt -1e300 to fold to gte -3.4028235e+38, got (%v, %v, %v)", outGT, outGTE, af)
	}
	if _, _, _, _, af := foldNumericRangeBoundsOutOfBounds(sch.Fields["hf"], nil, 70000.0, nil, nil); !af {
		t.Fatal("expected alwaysFalse for half_float gte > 65504")
	}
	if _, _, _, _, af := foldNumericRangeBoundsOutOfBounds(sch.Fields["sf"], 1e18, nil, nil, nil); !af {
		t.Fatal("expected alwaysFalse for scaled_float gt out of int64 range")
	}
	if _, gteS, _, lteS, af := foldNumericRangeBoundsOutOfBounds(sch.Fields["sf"], nil, 1.234, nil, 9.876); af || gteS != 1.23 || lteS != 9.88 {
		t.Fatalf("expected scaled_float rounding to 2 decimals, got (%v, %v, %v)", gteS, lteS, af)
	}

	// 4. top_metrics validation + runtime_mappings keyword + non-numeric sort
	trTM := NewTranspiler(sch, TranspilerOptions{TopMetricsMaxSize: 5})
	for _, badTM := range []string{
		`{"size":0,"aggs":{"tm":{"top_metrics":{"metrics":[{"field":"price"}],"sort":[{"cnt":"desc"}],"size":6}}}}`,
		`{"size":0,"runtime_mappings":{"rt_kw":{"type":"keyword"}},"aggs":{"tm":{"top_metrics":{"metrics":[{"field":"rt_kw"}],"sort":[{"cnt":"desc"}]}}}}`,
		`{"size":0,"aggs":{"tm":{"top_metrics":{"metrics":[{"field":"price"}],"sort":[{"kw":"desc"}]}}}}`,
		`{"size":0,"aggs":{"tm":{"top_metrics":{"metrics":[{"field":"price"}],"sort":[{"_script":{"script":"doc['kw'].value","type":"string"}}]}}}}`,
	} {
		if _, errTM := trTM.BuildSearchPlan(mustUnmarshalSearchReqR62(t, badTM)); errTM == nil {
			t.Fatalf("expected top_metrics validation error for %s", badTM)
		}
	}

	// 5. histogram field type: rate (with ES8Compat doc_count + value_count) & range (top-level & sub-agg with dedup)
	trDocCnt := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	histRatePlan, err := trDocCnt.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"r_doc": {"rate": {"unit": "day"}},
			"r_hist": {"rate": {"field": "hist", "unit": "day", "mode": "value_count"}},
			"h_rng": {
				"range": {"field": "hist", "ranges": [{"from": 0, "to": 50}, {"from": 50}]},
				"aggs": {"avg_p": {"avg": {"field": "price"}}}
			},
			"by_kw": {
				"terms": {"field": "kw", "size": 3},
				"aggs": {
					"sub_rate": {"rate": {"unit": "hour"}},
					"sub_rate_h": {"rate": {"field": "hist", "unit": "hour", "mode": "value_count"}},
					"sub_hrng": {
						"range": {"field": "hist", "ranges": [{"from": 0, "to": 50}]},
						"aggs": {"sub_cnt": {"value_count": {"field": "price"}}}
					}
				}
			}
		}
	}`))
	if err != nil {
		t.Fatalf("histogram rate/range failed: %v", err)
	}
	if !strings.Contains(histRatePlan.AggsSQL, "_rn_dedup_") || !strings.Contains(histRatePlan.AggsSQL, "_doc_count") {
		t.Fatalf("expected _rn_dedup_ and doc_count sum in histogram rate/range SQL:\n%s", histRatePlan.AggsSQL)
	}

	// 6. multi_terms: value_type casts, promoted array, script, missing, min_doc_count, order (_count/_key/custom)
	mtPlan, err := tr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"mt1": {
				"multi_terms": {
					"terms": [
						{"field": "uid", "value_type": "unsigned_long"},
						{"field": "cnt_arr", "value_type": "long", "missing": 0},
						{"field": "scores", "value_type": "double"},
						{"field": "active", "value_type": "boolean"},
						{"field": "kw_norm"},
						{"script": "doc['cnt'].value", "value_type": "integer"}
					],
					"min_doc_count": 2,
					"order": [{"_count": "asc"}, {"_key": "desc"}]
				}
			},
			"by_kw": {
				"terms": {"field": "kw", "size": 3},
				"aggs": {
					"mt_sub": {
						"multi_terms": {
							"terms": [{"field": "kw_arr"}, {"field": "uid"}],
							"min_doc_count": 3,
							"order": [{"avg_p": "desc"}]
						},
						"aggs": {"avg_p": {"avg": {"field": "price"}}}
					}
				}
			}
		}
	}`))
	if err != nil {
		t.Fatalf("multi_terms failed: %v", err)
	}
	if !strings.Contains(mtPlan.AggsSQL, "HAVING") || !strings.Contains(mtPlan.AggsSQL, "TRY_CAST(") {
		t.Fatalf("expected HAVING and TRY_CAST in multi_terms SQL:\n%s", mtPlan.AggsSQL)
	}
	if ordMap, post := compileMultiTermsOrderByR65(map[string]any{"_count": "asc"}); post || !strings.Contains(ordMap, "`_doc_count` ASC") {
		t.Fatalf("expected map order _count ASC, got (%s, %v)", ordMap, post)
	}
	if ordSlice, post := compileMultiTermsOrderByR65([]map[string]any{{"_key": "desc"}}); post || !strings.Contains(ordSlice, "`_bucket_key` DESC") {
		t.Fatalf("expected []map order _key DESC, got (%s, %v)", ordSlice, post)
	}
	if vExpr, isCast := formatMultiTermValueExprR65("`f__cnt`", esast.MultiTermTermSpec{Field: "cnt", ValueType: "string"}, "cnt", sch.Fields["cnt"], false); isCast || vExpr != "`f__cnt`" {
		t.Fatalf("expected default multi_term formatting, got (%s, %v)", vExpr, isCast)
	}

	// 7. compileOrderByWithAfter tie-breaker & unsigned_long histogram LARGEINT bucket key
	ordNoTie := tr.compileOrderBy([]esast.SortSpec{{Entry: esast.SortFieldSpec{Field: "cnt", Order: "desc"}}})
	if !strings.HasSuffix(ordNoTie, "`_id` ASC") {
		t.Fatalf("expected automatic `_id` ASC tie-breaker, got %s", ordNoTie)
	}
	ordWithDoc := tr.compileOrderBy([]esast.SortSpec{{Entry: esast.SortFieldSpec{Field: "_doc", Order: "asc"}}})
	if strings.Count(ordWithDoc, "`_id`") != 1 {
		t.Fatalf("expected single `_id` sort when _doc is present, got %s", ordWithDoc)
	}
	ulHistPlan, err := tr.BuildSearchPlan(mustDecodeSearchReqUseNumberR64(t, `{
		"size": 0,
		"aggs": {
			"uh": {"histogram": {"field": "uid", "interval": 9223372036854775807}}
		}
	}`))
	if err != nil || !strings.Contains(ulHistPlan.AggsSQL, "AS LARGEINT)") {
		t.Fatalf("expected LARGEINT bucket arithmetic for unsigned_long histogram: err=%v sql=%s", err, ulHistPlan.AggsSQL)
	}

	// 8. compilePinnedQuery with ES 8.11+ omitted _index in docs (HasDocsMissingIndex)
	var pinnedOmit esast.Query
	if err := json.Unmarshal([]byte(`{
		"pinned": {
			"docs": [{"_id": "local_no_idx"}, {"_index": "other_idx", "_id": "foreign_doc"}],
			"organic": {"term": {"kw": "active"}}
		}
	}`), &pinnedOmit); err != nil {
		t.Fatalf("unmarshal pinned omitted _index failed: %v", err)
	}
	cpPin := tr.CompileQuery(&pinnedOmit, true, nil)
	if !strings.Contains(cpPin.WhereSQL, "local_no_idx") || strings.Contains(cpPin.WhereSQL, "foreign_doc") {
		t.Fatalf("expected pinned.docs with omitted _index to match current index and exclude foreign_idx, got %s", cpPin.WhereSQL)
	}
}

func TestRound65_AdditionalBranchCoverage(t *testing.T) {
	sch := buildRound65CovSchema(t)
	tr := NewTranspiler(sch, TranspilerOptions{MaxRegexLength: 64})

	// 1. compileRangeSingleField: version, ip, date_nanos, epoch_second, boolean, sampleBound variants
	for _, rJSON := range []string{
		`{"range":{"ver_arr":{"gte":"1.0.0","lt":"2.0.0"}}}`,
		`{"nested":{"path":"items","query":{"range":{"items.ver":{"gt":"1.0.0","lte":"3.0.0"}}}}}`,
		`{"range":{"ver":{"gt":"not_semver"}}}`,
		`{"range":{"ver":{"gte":"not_semver"}}}`,
		`{"range":{"ver":{"lt":"not_semver"}}}`,
		`{"range":{"ver":{"lte":"not_semver"}}}`,
		`{"range":{"ip_arr":{"gte":"10.0.0.1","lte":"10.0.0.255"}}}`,
		`{"nested":{"path":"items","query":{"range":{"items.ip":{"gt":"10.0.0.1","lt":"10.0.0.5"}}}}}`,
		`{"range":{"ip":{"gte":"not-an-ip"}}}`,
		`{"range":{"ts_nanos":{"gte":"bad-date"}}}`,
		`{"range":{"ts_sec":{"gte":1700000000,"lte":1700000100.5}}}`,
		`{"range":{"active":{"gte":"not_a_bool"}}}`,
		`{"range":{"dyn.bool_arr":{"gte":true}}}`,
		`{"range":{"dyn.u64":{"gte":18446744073709551615}}}`,
		`{"range":{"dyn.f64":{"gte":1.5}}}`,
		`{"range":{"cnt":{"time_zone":"+02:00","gte":1}}}`,
	} {
		var q esast.Query
		dec := json.NewDecoder(strings.NewReader(rJSON))
		dec.UseNumber()
		if err := dec.Decode(&q); err != nil {
			t.Fatalf("decode %s failed: %v", rJSON, err)
		}
		_ = tr.CompileQuery(&q, false, nil)
		tr.searchErr = nil
	}

	// 2. compileTermPredicate, compileTermsPredicateWithCI, compileMatchFieldWithAnalyzer
	trStrict := NewTranspiler(sch, TranspilerOptions{
		StrictTextTermRouting: true,
		DynamicTextFields:     map[string]bool{"dyn.txt": true},
		RuntimeMappings:       map[string]esast.FieldProperty{"rt_kw": {Type: "keyword"}},
	})
	for _, qJSON := range []string{
		`{"term":{"mm3":"hello"}}`,
		`{"term":{"sayt._2gram":"quick fox"}}`,
		`{"term":{"sayt._index_prefix":"qui"}}`,
		`{"term":{"sayt":"quick"}}`,
		`{"term":{"rt_kw":"abc"}}`,
		`{"term":{"irange":5}}`,
		`{"term":{"ip_arr":"10.0.0.0/24"}}`,
		`{"nested":{"path":"items","query":{"term":{"items.ip":"10.0.0.0/24"}}}}`,
		`{"term":{"ver_arr":"1.2.3+build1"}}`,
		`{"nested":{"path":"items","query":{"term":{"items.ver":"1.2.3"}}}}`,
		`{"term":{"title_only":"UPPER"}}`,
		`{"term":{"txt_arr":"alpha"}}`,
		`{"term":{"txt_ws_arr":"Alpha"}}`,
		`{"terms":{"uid_arr":["18446744073709551615","10"]}}`,
		`{"terms":{"ip_arr":["10.0.0.0/24","192.168.1.1"]}}`,
		`{"terms":{"ver_arr":["1.0.0","2.0.0"]}}`,
		`{"match":{"ip":"10.0.0.1 10.0.0.2"}}`,
		`{"match":{"cnt":"10 20"}}`,
		`{"match":{"irange":5}}`,
		`{"match":{"kw":{"query":"a b","analyzer":"whitespace"}}}`,
		`{"match":{"title_ws":{"query":"Alpha Beta","operator":"and"}}}`,
		`{"match":{"txt_ws_arr":{"query":"Alpha Beta"}}}`,
		`{"match":{"title_only":{"query":"foo_bar baz_qux","operator":"and"}}}`,
		`{"match":{"txt_arr":{"query":"foo_bar"}}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(qJSON), &q); err != nil {
			t.Fatalf("unmarshal %s failed: %v", qJSON, err)
		}
		_ = trStrict.CompileQuery(&q, true, nil)
		trStrict.searchErr = nil
	}

	// 3. checkExpensiveQueryNode & isWildcardFieldType
	trNoExp := NewTranspiler(sch, TranspilerOptions{DisallowExpensiveQueries: true})
	for _, expJSON := range []string{
		`{"query":{"nested":{"path":"items","query":{"match_all":{}}}}}`,
		`{"query":{"script":{"script":{"source":"doc['cnt'].value > 1"}}}}`,
		`{"query":{"fuzzy":{"title_only":{"value":"qui"}}}}`,
		`{"query":{"match":{"title_only":{"query":"quick","fuzziness":1}}}}`,
		`{"query":{"match_bool_prefix":{"title_only":"qui"}}}`,
		`{"query":{"multi_match":{"query":"qui","fields":["title_only"],"type":"bool_prefix"}}}`,
		`{"query":{"prefix":{"title_only":"qui"}}}`,
		`{"query":{"wildcard":{"title_only":"q*"}}}`,
		`{"query":{"regexp":{"title_only":"q.*"}}}`,
		`{"query":{"range":{"kw":{"gte":"a"}}}}`,
		`{"query":{"bool":{"filter":[{"wildcard":{"wc":"a*"}}]}}}`,
		`{"query":{"constant_score":{"filter":{"prefix":{"title_idx_p":"qu"}}}}}`,
		`{"query":{"boosting":{"positive":{"term":{"kw":"a"}},"negative":{"fuzzy":{"kw":"b"}},"negative_boost":0.2}}}`,
	} {
		_, _ = trNoExp.BuildSearchPlan(mustUnmarshalSearchReqR62(t, expJSON))
	}
	if !tr.isWildcardFieldType("wc", nil) || tr.isWildcardFieldType("kw", nil) || tr.isWildcardFieldType("nonexistent_*", nil) {
		t.Fatal("unexpected isWildcardFieldType results")
	}

	// 4. parseSafeThresholdExpr, parseBooleanScriptCond, parseMetricScriptExpr, normalizeNestedPrefilterValue
	params := map[string]any{"p_int": 3, "p_u64": uint64(5), "p_f": 2.5, "p_jn": json.Number("4"), "p_bool": true}
	for _, expr := range []string{
		"(+params.p_int + -1) * Math.min(params.num_terms, params.p_jn)",
		"Math.max(params.p_u64, params.p_f)",
		"doc['cnt'].empty ? 0 : doc['cnt'].value",
	} {
		_, _ = tr.parseSafeThresholdExpr(expr, params, 2, nil, 0)
		_, _ = tr.parseMetricScriptExpr(expr, params, "cnt", "", nil, 0)
	}
	for _, cond := range []string{
		"(doc['active'].value == params.p_bool) && !doc['cnt'].empty",
		"doc['cnt'].empty || false || true",
	} {
		_, _ = tr.parseBooleanScriptCond(cond, params, nil, 0)
	}
	if _, ok := normalizeNestedPrefilterValue(sch.Fields["active"], "true", true, time.Now()); !ok {
		t.Fatal("expected boolean nested prefilter normalization")
	}
	if _, ok := normalizeNestedPrefilterValue(sch.Fields["ip"], "10.0.0.1", true, time.Now()); !ok {
		t.Fatal("expected ip nested prefilter normalization")
	}
	if _, ok := normalizeNestedPrefilterValue(sch.Fields["uid"], "18446744073709551615", true, time.Now()); !ok {
		t.Fatal("expected uint64 nested prefilter normalization")
	}

	// 5. Additional aggs & sub-aggs coverage (rare_terms, mad, auto_date_histogram, variable_width_histogram, adjacency_matrix, geo_bounds, weighted_avg, amd sub-aggs)
	aggPlan, err := tr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"by_kw": {
				"terms": {"field": "kw", "size": 3},
				"aggs": {
					"rt_arr": {"rare_terms": {"field": "kw_arr", "max_doc_count": 2, "missing": "none"}, "aggs": {"c": {"value_count": {"field": "cnt"}}}},
					"rt_sc": {"rare_terms": {"field": "kw_norm", "max_doc_count": 2, "missing": "none"}, "aggs": {"c": {"value_count": {"field": "cnt"}}}},
					"mad": {"median_absolute_deviation": {"field": "price", "missing": 1.0}},
					"adh": {"auto_date_histogram": {"field": "ts", "buckets": 5}, "aggs": {"mx": {"max": {"field": "price"}}}},
					"vwh": {"variable_width_histogram": {"field": "price", "buckets": 5}, "aggs": {"mn": {"min": {"field": "price"}}}},
					"adj": {"adjacency_matrix": {"separator": "|", "filters": {"a": {"term": {"active": true}}, "b": {"term": {"kw": "x"}}}}, "aggs": {"s": {"sum": {"field": "cnt"}}}},
					"gb": {"geo_bounds": {"field": "loc"}},
					"wavg": {"weighted_avg": {"value": {"field": "price"}, "weight": {"field": "cnt"}}},
					"amd_stats": {"stats": {"field": "amd"}},
					"amd_vc": {"value_count": {"field": "amd"}}
				}
			}
		}
	}`))
	if err != nil || strings.TrimSpace(aggPlan.AggsSQL) == "" {
		t.Fatalf("additional sub-aggs failed: err=%v sql=%s", err, aggPlan.AggsSQL)
	}
	// Error path for missing sub-metric on aggregate_metric_double
	for _, m := range []string{"max", "sum", "value_count", "avg"} {
		trAMDErr := NewTranspiler(sch, TranspilerOptions{})
		reqStr := fmt.Sprintf(`{"size":0,"aggs":{"by_kw":{"terms":{"field":"kw"},"aggs":{"bad":{%q:{"field":"amd_minonly"}}}}}}`, m)
		if _, errA := trAMDErr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, reqStr)); errA == nil {
			t.Fatalf("expected error for %s on min-only aggregate_metric_double", m)
		}
	}

	// 6. EvaluateIntervalsRuleWithAnalysis (filters: containing, not_containing, contained_by, not_contained_by, overlapping, not_overlapping, after, before, script)
	lookup := func(field string) ([]string, string) {
		return []string{"the quick brown fox jumps over the lazy dog"}, "custom_ws"
	}
	rule := &esast.IntervalsRule{
		Match: &esast.IntervalsMatch{
			Query:   "quick brown fox",
			MaxGaps: intPtrR65(2),
			Filter: &esast.IntervalsFilter{
				Containing:     &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "brown"}},
				NotContaining:  &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "cat"}},
				ContainedBy:    &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "the quick brown fox jumps", MaxGaps: intPtrR65(5)}},
				NotContainedBy: &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "cat"}},
				Overlapping:    &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "quick"}},
				NotOverlapping: &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "dog"}},
				After:          &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "the"}},
				Before:         &esast.IntervalsRule{Match: &esast.IntervalsMatch{Query: "jumps"}},
				Script:         &esast.ScriptSpec{Source: "interval.start >= 0"},
			},
		},
	}
	spans, matched, err := EvaluateIntervalsRuleWithAnalysis("title", rule, lookup, sch.AnalysisConfig, analysis.Options{}, func(_ *esast.ScriptSpec, sp IntervalsSpan) (bool, error) {
		return sp.Start >= 0, nil
	})
	if err != nil || !matched || len(spans) == 0 {
		t.Fatalf("EvaluateIntervalsRuleWithAnalysis failed: matched=%v spans=%v err=%v", matched, spans, err)
	}
}

func boolPtrR65(b bool) *bool { return &b }
func intPtrR65(i int) *int    { return &i }
