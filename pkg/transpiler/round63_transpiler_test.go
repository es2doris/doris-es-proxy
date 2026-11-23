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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func mustCompileSchemaR63(t *testing.T, indexName string, rawMapping string) *schema.IndexSchema {
	t.Helper()
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatalf("unmarshal mapping: %v", err)
	}
	return schema.CompileIndexSchema("doris_es", indexName, &spec)
}

func unmarshalSearchReqR63(rawQueryJSON string) (*esast.SearchRequest, error) {
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(rawQueryJSON), &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func mustSearchPlanR63(t *testing.T, tr *Transpiler, rawQueryJSON string) *ExecutionPlan {
	t.Helper()
	req, err := unmarshalSearchReqR63(rawQueryJSON)
	if err != nil {
		t.Fatalf("unmarshal SearchRequest failed: %v\nJSON: %s", err, rawQueryJSON)
	}
	plan, err := tr.BuildSearchPlan(req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v\nJSON: %s", err, rawQueryJSON)
	}
	return plan
}

func TestRound63_F10_QuoteDorisJSONPathAndTSIDOrder(t *testing.T) {
	nested, dotted, hasDot := BuildQuotedDorisJSONPaths(`a"b\c.d*e[0]`)
	if !hasDot {
		t.Fatalf("expected hasDot=true")
	}
	if nested != `$."a\"b\\c"."d*e[0]"` {
		t.Fatalf("unexpected nestedPath: %s", nested)
	}
	if dotted != `$."a\"b\\c.d*e[0]"` {
		t.Fatalf("unexpected dottedPath: %s", dotted)
	}
	emptyNested, emptyDotted, emptyDot := BuildQuotedDorisJSONPaths("   ")
	if emptyNested != `$.""` || emptyDotted != "" || emptyDot {
		t.Fatalf("unexpected empty BuildQuotedDorisJSONPaths: %q %q %v", emptyNested, emptyDotted, emptyDot)
	}
	singleNested, _, singleDot := BuildQuotedDorisJSONPaths("plain")
	if singleNested != `$."plain"` || singleDot {
		t.Fatalf("unexpected single BuildQuotedDorisJSONPaths: %q %v", singleNested, singleDot)
	}

	if got := FormatSQLFloatR63(math.NaN()); got != "0" {
		t.Fatalf("expected NaN -> 0, got %s", got)
	}
	if got := FormatSQLFloatR63(math.Inf(1)); got != "0" {
		t.Fatalf("expected +Inf -> 0, got %s", got)
	}
	if got := FormatSQLFloatR63(math.Copysign(0, -1)); got != "0" {
		t.Fatalf("expected -0.0 -> 0, got %s", got)
	}
	if got := FormatSQLFloatR63(1e6); got != "1000000" {
		t.Fatalf("expected 1e6 -> 1000000, got %s", got)
	}

	arrPlain := sqlRuntimeSourceJSONTypeIsArrayExpr("tags")
	if !strings.Contains(arrPlain, "JSON_TYPE(TRY_CAST(`_source` AS JSON),") {
		t.Fatalf("unexpected arrPlain: %s", arrPlain)
	}
	arrDot := sqlRuntimeSourceJSONTypeIsArrayExpr("meta.tags")
	if !strings.Contains(arrDot, `JSON_TYPE(TRY_CAST(`+"`_source`"+` AS JSON), '$."meta"."tags"')`) ||
		!strings.Contains(arrDot, `JSON_TYPE(TRY_CAST(`+"`_source`"+` AS JSON), '$."meta.tags"')`) {
		t.Fatalf("unexpected arrDot: %s", arrDot)
	}
	msExpr := sqlRuntimeSourceDateMillisExpr("`s`")
	nsExpr := sqlRuntimeSourceDateNanosExpr("`s`")
	if !strings.Contains(msExpr, "DATETIMEV2(6)") || !strings.Contains(nsExpr, "1000000000") {
		t.Fatalf("unexpected date runtime exprs: %s / %s", msExpr, nsExpr)
	}

	for _, cidr := range []string{"fe80::1/10", "ffff:1234::/32", "2001:db8::1/128", "10.1.2.0/24"} {
		whereSQL, ok := BuildIPv6PrefixMaskWhereSQL("`f__ip`", cidr)
		if !ok || !strings.Contains(whereSQL, "CAST(CONV(SUBSTRING(") {
			t.Fatalf("expected valid IPv6/IPv4 CIDR SQL for %s, got ok=%v sql=%s", cidr, ok, whereSQL)
		}
	}
	if _, ok := BuildIPv6PrefixMaskWhereSQL("`f__ip`", "not-a-cidr"); ok {
		t.Fatalf("expected invalid CIDR to return ok=false")
	}

	if v := coerceJSONNumberExactIntOrUintR63(json.Number("42")); v != int64(42) {
		t.Fatalf("expected int64(42), got %T %v", v, v)
	}
	if v := coerceJSONNumberExactIntOrUintR63(json.Number("18446744073709551610")); v != uint64(18446744073709551610) {
		t.Fatalf("expected uint64, got %T %v", v, v)
	}
	if v := coerceJSONNumberExactIntOrUintR63(json.Number("3.25")); v != float64(3.25) {
		t.Fatalf("expected float64(3.25), got %T %v", v, v)
	}
	if v := coerceJSONNumberExactIntOrUintR63(json.Number("not_num")); v != "not_num" {
		t.Fatalf("expected raw string fallback, got %T %v", v, v)
	}

	wrapped := wrapUnionBranchesWithOuterOrderByR63([]string{
		"SELECT * FROM (SELECT 1) `_agg_sub_1` ORDER BY `_bucket_key` ASC LIMIT 10",
		"SELECT 2 AS `_agg_name`",
	})
	if !strings.HasPrefix(wrapped, "(SELECT * FROM") {
		t.Fatalf("expected parenthesized ORDER BY branch in UNION ALL, got: %s", wrapped)
	}

	// Property check: 128 random 128-bit binary Murmur3-like hashes must sort identically
	// under `TranslateBase64URLOrderR63` and raw `bytes.Compare`.
	samples := make([][16]byte, 128)
	for i := range samples {
		if _, err := rand.Read(samples[i][:]); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < len(samples); i++ {
		sA := base64.RawURLEncoding.EncodeToString(samples[i][:])
		kA := TranslateBase64URLOrderR63(sA)
		for j := i + 1; j < len(samples); j++ {
			sB := base64.RawURLEncoding.EncodeToString(samples[j][:])
			kB := TranslateBase64URLOrderR63(sB)
			wantCmp := bytes.Compare(samples[i][:], samples[j][:])
			gotCmp := strings.Compare(kA, kB)
			if (wantCmp < 0 && gotCmp >= 0) || (wantCmp > 0 && gotCmp <= 0) || (wantCmp == 0 && gotCmp != 0) {
				t.Fatalf("order mismatch for %x vs %x: want %d got %d", samples[i], samples[j], wantCmp, gotCmp)
			}
		}
	}

	// Runtime mappings with strict-cast `TRY_CAST` (`long`, `double`, `boolean`, `date`, `date_nanos`, `ip`).
	idx := mustCompileSchemaR63(t, "rt_idx", `{
		"runtime": {
			"rt_long": {"type": "long"},
			"rt_dbl": {"type": "double"},
			"rt_bool": {"type": "boolean"},
			"rt_date": {"type": "date"},
			"rt_ns": {"type": "date_nanos"},
			"rt_ip": {"type": "ip"}
		},
		"properties": {
			"host_ip": {"type": "ip"},
			"net_cidr": {"type": "ip_range"}
		}
	}`)
	tr := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})
	p := mustSearchPlanR63(t, tr, `{
		"query": {
			"bool": {
				"must": [
					{"range": {"rt_long": {"gte": 10}}},
					{"range": {"rt_dbl": {"lte": 99.5}}},
					{"term": {"rt_bool": true}},
					{"range": {"rt_date": {"gte": "2023-01-01T00:00:00Z"}}},
					{"range": {"rt_ns": {"gte": "2023-01-01T00:00:00.123456789Z"}}},
					{"term": {"host_ip": "fe80::/10"}},
					{"term": {"net_cidr": "fe80::1"}}
				]
			}
		}
	}`)
	if !strings.Contains(p.HitsSQL, "TRY_CAST") || !strings.Contains(p.HitsSQL, "DATETIMEV2(6)") || !strings.Contains(p.HitsSQL, "FE800000") {
		t.Fatalf("expected TRY_CAST, DATETIMEV2(6), and IPv6 hex in SQL:\n%s", p.HitsSQL)
	}
}

func TestRound63_F12_BM25ScoringAndCustomSimilarities(t *testing.T) {
	k1Custom := 1.8
	bCustom := 0.4
	idx := mustCompileSchemaR63(t, "bm25_idx", `{
		"properties": {
			"title": {"type": "text"},
			"no_norms": {"type": "text", "norms": false},
			"docs_only": {"type": "text", "index_options": "docs"},
			"bool_field": {"type": "text", "similarity": "boolean"},
			"custom_sim": {"type": "text", "similarity": "my_bm25"},
			"custom_bool": {"type": "text", "similarity": "my_bool"},
			"mot": {"type": "match_only_text"},
			"kw": {"type": "keyword"},
			"title_alias": {"type": "alias", "path": "title"},
			"nested_docs": {
				"type": "nested",
				"properties": {
					"body": {"type": "text"}
				}
			}
		}
	}`)
	tr := NewTranspiler(idx, TranspilerOptions{
		ES8Compat: true,
		Similarities: map[string]SimilarityConfig{
			"my_bm25": {Type: "BM25", K1: &k1Custom, B: &bCustom},
			"my_bool": {Type: "boolean"},
		},
	})

	// Single-term, multi-term match, match_phrase, term/terms on text, boost=0, custom similarities.
	queries := []string{
		`{"query":{"term":{"title":{"value":"fox","boost":2.5}}}}`,
		`{"query":{"term":{"title":{"value":"Fox","case_insensitive":false}}}}`,
		`{"query":{"term":{"title":{"value":"Fox","case_insensitive":true}}}}`,
		`{"query":{"term":{"title":{"value":"two words"}}}}`,
		`{"query":{"terms":{"title":["quick","brown","Upper"]}}}`,
		`{"query":{"match":{"title":{"query":"quick brown fox","operator":"or"}}}}`,
		`{"query":{"match":{"title":{"query":"quick brown","boost":0}}}}`,
		`{"query":{"match":{"no_norms":"quick fox"}}}`,
		`{"query":{"match":{"docs_only":"quick fox"}}}`,
		`{"query":{"match":{"bool_field":"quick fox"}}}`,
		`{"query":{"match":{"custom_sim":{"query":"quick fox","boost":0.0001}}}}`,
		`{"query":{"match":{"custom_bool":"quick fox"}}}`,
		`{"query":{"match":{"mot":"quick fox"}}}`,
		`{"query":{"match":{"title_alias":"quick fox"}}}`,
		`{"query":{"match_phrase":{"title":"quick brown fox"}}}`,
		`{"query":{"multi_match":{"query":"quick fox","fields":["title^2","custom_sim","kw"],"type":"best_fields"}}}`,
		`{"query":{"multi_match":{"query":"quick fox","fields":["title","no_norms"],"type":"most_fields"}}}`,
		`{"query":{"multi_match":{"query":"quick fox","fields":["title","custom_sim"],"type":"phrase"}}}`,
		`{"query":{"nested":{"path":"nested_docs","query":{"match":{"nested_docs.body":"quick fox"}}}}}`,
	}
	for _, q := range queries {
		plan := mustSearchPlanR63(t, tr, q)
		if plan.HitsSQL == "" {
			t.Fatalf("empty HitsSQL for %s", q)
		}
	}

	pBM25 := mustSearchPlanR63(t, tr, `{"query":{"match":{"custom_sim":"quick"}}}`)
	if !strings.Contains(pBM25.HitsSQL, "1.8") || !strings.Contains(pBM25.HitsSQL, "0.4") {
		t.Fatalf("expected custom BM25 k1=1.8 b=0.4 in SQL:\n%s", pBM25.HitsSQL)
	}
	pUpper := mustSearchPlanR63(t, tr, `{"query":{"term":{"title":{"value":"Upper"}}}}`)
	if !strings.Contains(pUpper.HitsSQL, "FALSE") {
		t.Fatalf("expected uppercase term on lowercase text field to fold to FALSE, got:\n%s", pUpper.HitsSQL)
	}
}

func TestRound63_F11_ExactMappersAndAggregations(t *testing.T) {
	// 1. `NormalizeUnsignedLongRangeBoundsExactR63` edge cases.
	if _, _, _, lte, ok := NormalizeUnsignedLongRangeBoundsExactR63(nil, nil, "18446744073709551614.5", nil); !ok || lte != uint64(18446744073709551614) {
		t.Fatalf("expected exact big.Rat floor 18446744073709551614, got ok=%v lte=%v", ok, lte)
	}
	if _, gte, _, _, ok := NormalizeUnsignedLongRangeBoundsExactR63("18446744073709551613.2", nil, nil, nil); !ok || gte != uint64(18446744073709551614) {
		t.Fatalf("expected exact big.Rat ceil 18446744073709551614, got ok=%v gte=%v", ok, gte)
	}
	if _, gte, _, lte, ok := NormalizeUnsignedLongRangeBoundsExactR63(-5, int64(-1), "+inf", math.Inf(1)); !ok || gte != uint64(0) || lte != uint64(math.MaxUint64) {
		t.Fatalf("unexpected inf/negative clamp: ok=%v gte=%v lte=%v", ok, gte, lte)
	}
	if _, _, _, _, ok := NormalizeUnsignedLongRangeBoundsExactR63(uint64(100), nil, uint64(50), nil); ok {
		t.Fatalf("expected inverted unsigned_long bounds to return ok=false")
	}
	if _, _, _, _, ok := NormalizeUnsignedLongRangeBoundsExactR63(math.NaN(), nil, nil, nil); ok {
		t.Fatalf("expected NaN bound to return ok=false")
	}
	if _, _, _, _, ok := NormalizeUnsignedLongRangeBoundsExactR63(nil, "-inf", "0", nil); ok {
		t.Fatalf("expected lt=0 on unsigned_long to return ok=false")
	}

	// 2. `NormalizeESVersionRangeBoundR63`.
	validVers := []any{"1.2.3", "9999", "1.2", "1.0.0-alpha.1+build.9", json.Number("2024"), 7, int64(8), uint64(9)}
	for _, vv := range validVers {
		if _, ok := NormalizeESVersionRangeBoundR63(vv); !ok {
			t.Fatalf("expected valid version bound %T(%v)", vv, vv)
		}
	}
	invalidVers := []any{nil, "", " 1.0.0", -1, int64(-2), "01.2.3", "1.0.0-01", "1.0.0+", "1.0.0-bad$char", struct{}{}}
	for _, iv := range invalidVers {
		if _, ok := NormalizeESVersionRangeBoundR63(iv); ok {
			t.Fatalf("expected invalid version bound %T(%v)", iv, iv)
		}
	}

	// 3. `CoerceMurmur3TermValueR63`.
	for _, mv := range []any{10, int64(-20), uint64(30), json.Number("40"), json.Number("3.14"), float64(50), "12345", "hello-murmur"} {
		if _, ok := CoerceMurmur3TermValueR63(mv); !ok {
			t.Fatalf("expected CoerceMurmur3TermValueR63 ok for %T(%v)", mv, mv)
		}
	}
	if _, ok := CoerceMurmur3TermValueR63(3.5); ok {
		t.Fatalf("expected fractional float64 to fail CoerceMurmur3TermValueR63")
	}
	if _, ok := CoerceMurmur3TermValueR63(math.NaN()); ok {
		t.Fatalf("expected NaN to fail CoerceMurmur3TermValueR63")
	}

	// 4. Schema with `_size`, `unsigned_long`, `version`, `constant_keyword`, `scaled_float`,
	// `murmur3`, `counted_keyword`, `aggregate_metric_double`, and `geo_shape`.
	idx := mustCompileSchemaR63(t, "exact_mappers_idx", `{
		"_size": {"enabled": true},
		"runtime": {
			"rt_geo": {"type": "geo_point"}
		},
		"properties": {
			"u_val": {"type": "unsigned_long"},
			"ver": {"type": "version"},
			"env": {"type": "constant_keyword", "value": "prod"},
			"meta": {
				"properties": {
					"env": {"type": "constant_keyword", "value": "staging"}
				}
			},
			"price": {"type": "scaled_float", "scaling_factor": 100},
			"hash": {"type": "murmur3"},
			"ckw": {"type": "counted_keyword"},
			"tags": {"type": "keyword"},
			"lat_metric": {
				"type": "aggregate_metric_double",
				"metrics": ["min", "max", "sum", "value_count"],
				"default_metric": "max"
			},
			"min_only_metric": {
				"type": "aggregate_metric_double",
				"metrics": ["min"],
				"default_metric": "min"
			},
			"region": {"type": "geo_shape"},
			"pts": {"type": "geo_point"}
		}
	}`)
	tr := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})

	if !IsSubpathUnderAggregateMetricDoubleR63(idx, "lat_metric.min") {
		t.Fatalf("expected lat_metric.min to be detected as subpath under aggregate_metric_double")
	}
	subpathReq, _ := unmarshalSearchReqR63(`{"query":{"term":{"lat_metric.min":1.0}}}`)
	_, _ = tr.BuildSearchPlan(subpathReq)

	// Queries & sorts over exact mappers.
	pExact := mustSearchPlanR63(t, tr, `{
		"query": {
			"bool": {
				"must": [
					{"range": {"u_val": {"gte": "9223372036854775810", "lte": "18446744073709551615"}}},
					{"range": {"ver": {"gte": "1.0.0-alpha", "lt": "9999"}}},
					{"term": {"env": "prod"}},
					{"exists": {"field": "meta.env"}},
					{"range": {"_size": {"gt": 10}}},
					{"term": {"hash": "hello"}},
					{"exists": {"field": "lat_metric"}},
					{"range": {"lat_metric": {"gte": 5.0}}}
				]
			}
		},
		"sort": [
			{"price": {"order": "asc", "numeric_type": "long"}},
			{"ver": {"order": "desc"}},
			{"_size": {"order": "desc"}},
			{"lat_metric": {"order": "desc"}}
		],
		"aggs": {
			"m_min": {"min": {"field": "lat_metric"}},
			"m_max": {"max": {"field": "lat_metric"}},
			"m_sum": {"sum": {"field": "lat_metric"}},
			"m_cnt": {"value_count": {"field": "lat_metric"}},
			"m_avg": {"avg": {"field": "lat_metric"}},
			"m_stats": {"stats": {"field": "lat_metric"}},
			"ct_top": {
				"counted_terms": {"field": "ckw", "size": 5},
				"aggs": {
					"sub_cnt": {"value_count": {"field": "lat_metric"}}
				}
			},
			"by_tag": {
				"terms": {"field": "tags"},
				"aggs": {
					"s_min": {"min": {"field": "lat_metric"}},
					"s_max": {"max": {"field": "lat_metric"}},
					"s_sum": {"sum": {"field": "lat_metric"}},
					"s_cnt": {"value_count": {"field": "lat_metric"}},
					"s_avg": {"avg": {"field": "lat_metric"}},
					"s_ct": {"counted_terms": {"field": "ckw", "size": 3}}
				}
			}
		}
	}`)
	if !strings.Contains(pExact.HitsSQL, "TRUNCATE") || !strings.Contains(pExact.HitsSQL, "f___size") {
		t.Fatalf("expected TRUNCATE and f___size in HitsSQL:\n%s", pExact.HitsSQL)
	}
	if !strings.Contains(pExact.AggsSQL, "EXPLODE") || !strings.Contains(pExact.AggsSQL, "f__lat_metric__sum") {
		t.Fatalf("expected EXPLODE and f__lat_metric__sum in AggsSQL:\n%s", pExact.AggsSQL)
	}

	// Unsupported metric (`avg` on `min_only_metric`) must return an error.
	badAvgReq, _ := unmarshalSearchReqR63(`{"size":0,"aggs":{"bad":{"avg":{"field":"min_only_metric"}}}}`)
	if _, err := tr.BuildSearchPlan(badAvgReq); err == nil {
		t.Fatalf("expected error computing avg on min-only aggregate_metric_double")
	}
	badSubReq, _ := unmarshalSearchReqR63(`{"size":0,"aggs":{"by_tag":{"terms":{"field":"tags"},"aggs":{"bad":{"max":{"field":"min_only_metric"}}}}}}`)
	if _, err := tr.BuildSearchPlan(badSubReq); err == nil {
		t.Fatalf("expected error computing sub-agg max on min-only aggregate_metric_double")
	}

	// `geo_shape` WKT & GeoJSON shapes + `WITHIN` / `INTERSECTS` / `DISJOINT` / `CONTAINS` + runtime `geo_point`.
	geoQueries := []string{
		`{"query":{"geo_shape":{"region":{"shape":"BBOX (-75.0, -70.0, 45.0, 40.0)","relation":"intersects"}}}}`,
		`{"query":{"geo_shape":{"region":{"shape":"POLYGON ((-75 40, -70 40, -70 45, -75 45, -75 40))","relation":"within"}}}}`,
		`{"query":{"geo_shape":{"region":{"shape":"POINT (-71.34 41.12)","relation":"contains"}}}}`,
		`{"query":{"geo_shape":{"region":{"shape":{"type":"circle","coordinates":[-71.34,41.12],"radius":"10km"},"relation":"disjoint"}}}}`,
		`{"query":{"geo_shape":{"rt_geo":{"shape":{"type":"envelope","coordinates":[[-75.0,45.0],[-70.0,40.0]]},"relation":"within"}}}}`,
		`{"query":{"geo_shape":{"rt_geo":{"shape":{"type":"envelope","coordinates":[[-75.0,45.0],[-70.0,40.0]]},"relation":"intersects"}}}}`,
		`{"query":{"geo_shape":{"unmapped_geo":{"shape":"POINT (0 0)","ignore_unmapped":true}}}}`,
	}
	for _, gq := range geoQueries {
		gp := mustSearchPlanR63(t, tr, gq)
		if gp.HitsSQL == "" {
			t.Fatalf("empty HitsSQL for %s", gq)
		}
	}
}

func TestRound63_F13_VectorSearchNestedQuantizedAndSparse(t *testing.T) {
	idx := mustCompileSchemaR63(t, "vec_idx", `{
		"properties": {
			"root_tag": {"type": "keyword"},
			"root_num": {"type": "integer"},
			"emb": {"type": "dense_vector", "dims": 3, "index": true, "similarity": "cosine"},
			"ml": {
				"properties": {
					"tokens": {"type": "sparse_vector"}
				}
			},
			"chunks": {
				"type": "nested",
				"properties": {
					"tag": {"type": "keyword"},
					"weight": {"type": "integer"},
					"txt": {"type": "text"},
					"vec_cos": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "cosine"},
					"vec_l2": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "l2_norm"},
					"vec_dp_byte": {"type": "dense_vector", "dims": 2, "element_type": "byte", "index": true, "similarity": "dot_product"},
					"vec_mip": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "max_inner_product"},
					"vec_bit": {"type": "dense_vector", "dims": 8, "element_type": "bit", "index": true, "similarity": "l2_norm"}
				}
			}
		}
	}`)
	trES8 := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})
	trDyn := NewTranspiler(idx, TranspilerOptions{ES8Compat: false})

	// Nested kNN across all metrics, score_modes, filters, and sibling post-filters.
	nestedQueries := []string{
		`{"size":4,"query":{"nested":{"path":"chunks","score_mode":"max","query":{"knn":{"field":"chunks.vec_cos","query_vector":[1.0,0.0],"similarity":0.5,"filter":[{"term":{"root_tag":"a"}},{"term":{"chunks.tag":"x"}}]}}}}}`,
		`{"size":4,"query":{"nested":{"path":"chunks","score_mode":"min","query":{"knn":{"field":"chunks.vec_l2","query_vector":[1.0,2.0],"k":3,"num_candidates":5,"similarity":2.0}}}}}`,
		`{"size":4,"query":{"nested":{"path":"chunks","score_mode":"avg","query":{"knn":{"field":"chunks.vec_dp_byte","query_vector":"0102","k":2,"num_candidates":4,"similarity":0.1}}}}}`,
		`{"size":4,"query":{"nested":{"path":"chunks","score_mode":"sum","query":{"knn":{"field":"chunks.vec_mip","query_vector":[0.5,-0.5],"k":2,"num_candidates":4,"similarity":-1.0}}}}}`,
		`{"size":4,"query":{"nested":{"path":"chunks","score_mode":"none","query":{"knn":{"field":"chunks.vec_bit","query_vector":"ff","k":2,"num_candidates":4,"similarity":0.5}}}}}`,
		`{"size":4,"query":{"nested":{"path":"chunks","query":{"bool":{"must":[{"knn":{"field":"chunks.vec_cos","query_vector":[1.0,0.0],"k":2,"num_candidates":4}}],"filter":[{"terms":{"chunks.tag":["x","y"]}},{"range":{"chunks.weight":{"gte":1}}},{"term":{"root_tag":"a"}}],"must_not":[{"prefix":{"chunks.tag":"bad"}},{"term":{"root_num":0}}],"should":[{"wildcard":{"chunks.tag":"x*"}},{"regexp":{"chunks.tag":"x.*"}},{"fuzzy":{"chunks.tag":{"value":"x"}}},{"match":{"chunks.txt":"hello"}},{"match_phrase":{"chunks.txt":"hello world"}},{"match_phrase_prefix":{"chunks.txt":"hel"}},{"exists":{"field":"chunks.tag"}}],"minimum_should_match":1}}}}}`,
		`{"query":{"nested":{"path":"unknown_nested","ignore_unmapped":true,"query":{"knn":{"field":"unknown_nested.v","query_vector":[1.0]}}}}}`,
		// Hybrid dis_max with nested kNN + keyword term + sparse_vector term & sparse_vector query.
		`{"query":{"dis_max":{"queries":[{"nested":{"path":"chunks","query":{"knn":{"field":"chunks.vec_cos","query_vector":[1.0,0.0],"k":2,"num_candidates":4}}}},{"term":{"root_tag":"a"}},{"term":{"ml.tokens":{"value":"walk","boost":1.5}}},{"sparse_vector":{"field":"ml.tokens","query_vector":{"walk":1.2,"run":0.8}}}]}}}`,
	}
	for _, nq := range nestedQueries {
		np := mustSearchPlanR63(t, trES8, nq)
		if np.HitsSQL == "" {
			t.Fatalf("empty HitsSQL for %s", nq)
		}
	}

	// Verify `queryReferencesNestedPathR63` compound branches (`constant_score`, `dis_max`, `boosting`, `knn`).
	var compoundRef esast.Query
	if err := json.Unmarshal([]byte(`{
		"boosting": {
			"positive": {"constant_score": {"filter": {"term": {"root_tag": "a"}}}},
			"negative": {"dis_max": {"queries": [{"knn": {"field": "chunks.vec_cos", "query_vector": [1, 0]}}]}},
			"negative_boost": 0.5
		}
	}`), &compoundRef); err != nil {
		t.Fatalf("unmarshal compoundRef: %v", err)
	}
	if !trES8.queryReferencesNestedPathR63(&compoundRef, "chunks") {
		t.Fatalf("expected compound query to reference nested path chunks")
	}
	if !queryContainsKNNTreeR63(&compoundRef) {
		t.Fatalf("expected queryContainsKNNTreeR63=true on boosting/dis_max kNN")
	}

	// Error cases on kNN / nested kNN.
	errQueries := []string{
		`{"knn":{"field":"nonexistent_vec","query_vector":[1,2,3],"k":2,"num_candidates":4}}`,
		`{"query":{"nested":{"path":"chunks","query":{"knn":{"field":"chunks.nonexistent","query_vector":[1,0],"k":2,"num_candidates":4}}}}}`,
		`{"query":{"nested":{"path":"chunks","query":{"knn":{"field":"chunks.vec_cos","query_vector":[1,0],"k":-1,"num_candidates":4}}}}}`,
		`{"query":{"nested":{"path":"chunks","query":{"knn":{"field":"chunks.vec_cos","query_vector":[1,0],"k":5,"num_candidates":2}}}}}`,
		`{"query":{"nested":{"path":"chunks","query":{"knn":{"field":"chunks.vec_cos","query_vector":[1,0],"k":2,"num_candidates":20000}}}}}`,
		`{"query":{"nested":{"path":"chunks","query":{"knn":{"field":"chunks.vec_cos","query_vector":[1,0,0],"k":2,"num_candidates":4}}}}}`,
		`{"query":{"nested":{"path":"unmapped_path","query":{"knn":{"field":"unmapped_path.v","query_vector":[1,0],"k":2,"num_candidates":4}}}}}`,
	}
	for _, eq := range errQueries {
		req, err := unmarshalSearchReqR63(eq)
		if err != nil {
			continue
		}
		if _, err := trES8.BuildSearchPlan(req); err == nil {
			t.Fatalf("expected ES8 error for %s", eq)
		}
	}

	// Dynamic fallback when `ES8Compat: false`.
	dynPlan := mustSearchPlanR63(t, trDyn, `{"knn":{"field":"dyn_vec","query_vector":[1,2,3],"k":2,"num_candidates":4}}`)
	if !strings.Contains(dynPlan.HitsSQL, "COALESCE(TRY_CAST(`_doc`['dyn_vec'] AS ARRAY<FLOAT>)") {
		t.Fatalf("expected dynamic vector _doc + _source fallback, got:\n%s", dynPlan.HitsSQL)
	}

	// Go runtime vector helpers (`EvaluateNestedKNNParentScore`, `PassesESVectorSimilarity`, `coerceDocVectorFloat64`).
	simMin := 0.1
	best, matched, hits := EvaluateNestedKNNParentScore(
		[]map[string]any{
			{"v": []any{1, 0}},
			{"v": []float64{0, 1}},
			{"v": "bad"},
			nil,
		},
		"v",
		[]float64{1, 0},
		"cosine",
		"float",
		&simMin,
		2.0,
	)
	if !matched || len(hits) != 1 || best < 1.99 {
		t.Fatalf("unexpected EvaluateNestedKNNParentScore: best=%v matched=%v hits=%d", best, matched, len(hits))
	}
	if _, ok := coerceDocVectorFloat64("ff00", "bit"); !ok {
		t.Fatalf("expected hex bit vector coercion to succeed")
	}
	if _, ok := coerceDocVectorFloat64("7f80", "byte"); !ok {
		t.Fatalf("expected hex byte vector coercion to succeed")
	}
	if _, ok := coerceDocVectorFloat64([]any{int64(255), "0"}, "bit"); !ok {
		t.Fatalf("expected slice bit vector coercion to succeed")
	}
}

func TestRound63_F17_F20_IntervalsAnalysisRangeAndBroadCoverage(t *testing.T) {
	// 1. Disjunction rewrite in `EvaluateIntervalsRuleWithFieldLookup` + `ScoreIntervalsSpans`.
	var rule esast.IntervalsRule
	if err := json.Unmarshal([]byte(`{
		"all_of": {
			"ordered": true,
			"intervals": [
				{"any_of": {"intervals": [{"match": {"query": "a"}}, {"match": {"query": "a b"}}]}},
				{"any_of": {"intervals": [{"match": {"query": "c"}}, {"match": {"query": "b c"}}]}}
			]
		}
	}`), &rule); err != nil {
		t.Fatal(err)
	}
	spans, matched, err := EvaluateIntervalsRuleWithFieldLookup("body", &rule, func(f string) ([]string, string) {
		if f == "alt" {
			return []string{"x y", "z w"}, "standard"
		}
		return []string{"a b c"}, "standard"
	}, nil)
	if err != nil || !matched || len(spans) < 2 {
		t.Fatalf("expected 2 distinct rewritten disjunction spans on 'a b c', got matched=%v spans=%+v err=%v", matched, spans, err)
	}
	sc := ScoreIntervalsSpans(spans, 1.0)
	if math.Abs(sc-(5.0/7.0)) > 1e-6 {
		t.Fatalf("expected ScoreIntervalsSpans = 5/7 (0.7142857) for rewritten disjunction branches, got %v", sc)
	}

	// Exercise `use_field`, `prefix`, `wildcard`, `fuzzy`, `filter` relations, and `QueryHasIntervals`.
	var complexRule esast.IntervalsRule
	if err := json.Unmarshal([]byte(`{
		"all_of": {
			"max_gaps": 5,
			"filter": {
				"not_containing": {"match": {"query": "forbidden"}},
				"overlapping": {"prefix": {"prefix": "qu", "use_field": "title"}},
				"not_overlapping": {"wildcard": {"pattern": "zzz*"}},
				"after": {"fuzzy": {"term": "start", "fuzziness": 1}},
				"before": {"fuzzy": {"term": "end", "fuzziness": 0}},
				"script": {"source": "interval.gaps >= 0"}
			},
			"intervals": [
				{"prefix": {"prefix": "qu", "use_field": "title"}},
				{"wildcard": {"pattern": "f*x", "use_field": "title"}}
			]
		}
	}`), &complexRule); err != nil {
		t.Fatal(err)
	}
	_, matchedComplex, err := EvaluateIntervalsRuleWithFieldLookup("body", &complexRule, func(f string) ([]string, string) {
		return []string{"start quick brown fox end"}, "standard"
	}, func(_ *esast.ScriptSpec, sp IntervalsSpan) (bool, error) {
		return sp.End >= sp.Start, nil
	})
	if err != nil || !matchedComplex {
		t.Fatalf("expected complexRule to match, matched=%v err=%v", matchedComplex, err)
	}

	var qHasIv esast.Query
	_ = json.Unmarshal([]byte(`{"bool":{"should":[{"constant_score":{"filter":{"intervals":{"body":{"match":{"query":"fox"}}}}}}]}}`), &qHasIv)
	if !QueryHasIntervals(&qHasIv) {
		t.Fatalf("expected QueryHasIntervals=true")
	}

	// 2. Built-in stemmer graph & analyzer flags.
	if toks, ok := analyzeTokensWithBuiltinGraphR63("foxes jumping", "snowball"); !ok || len(toks) != 2 {
		t.Fatalf("expected snowball stemmer tokens, got ok=%v toks=%+v", ok, toks)
	}
	if cs, ws := analyzerCaseAndWhitespaceFlagsR63("whitespace", nil, analysis.Options{}); !cs || !ws {
		t.Fatalf("expected whitespace -> cs=true ws=true, got %v %v", cs, ws)
	}
	if cs, ws := analyzerCaseAndWhitespaceFlagsR63("standard", nil, analysis.Options{}); cs || ws {
		t.Fatalf("expected standard -> cs=false ws=false, got %v %v", cs, ws)
	}
	if re := buildAnalyzedTokenRegexExactR63("a+b", true, true); !strings.Contains(re, `a\+b`) {
		t.Fatalf("expected escaped regex for a+b, got %s", re)
	}

	// 3. `date_histogram` on `date_range` (root + nested) & `sortedRangeAggIndicesAscR63`.
	idx := mustCompileSchemaR63(t, "rng_hist_idx", `{
		"properties": {
			"title": {"type": "text"},
			"tag": {"type": "keyword"},
			"tiny": {"type": "byte"},
			"num": {"type": "double"},
			"ts": {"type": "date"},
			"loc": {"type": "geo_point"},
			"dr": {"type": "date_range"},
			"nested_ev": {
				"type": "nested",
				"properties": {
					"dr": {"type": "date_range"}
				}
			}
		}
	}`)
	tr := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})
	nowFixed := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	var rngSpec esast.RangeAggSpec
	_ = json.Unmarshal([]byte(`{
		"field": "ts",
		"ranges": [
			{"from": "2020-01-01T00:00:00Z"},
			{"to": "2020-01-01T00:00:00Z"},
			{"from": "2019-01-01T00:00:00Z", "to": "2020-01-01T00:00:00Z"}
		]
	}`), &rngSpec)
	sortedIdxs := tr.sortedRangeAggIndicesAscR63("ts", &rngSpec, nowFixed)
	if len(sortedIdxs) != 3 || sortedIdxs[0] != 1 || sortedIdxs[1] != 2 || sortedIdxs[2] != 0 {
		t.Fatalf("expected sorted range agg indices [1 2 0], got %v", sortedIdxs)
	}
	_, _, rawLo, rawHi := dateRangeObjectBoundsSQLR63("nested_ev.dr", schema.FieldBinding{
		Kind:       schema.StorageNestedSubfield,
		ESType:     "date_range",
		NestedPath: "nested_ev",
	}, &nestedCtx{nestedPath: "nested_ev", elemVar: "_nel"})
	if !strings.Contains(rawLo, "_nel") || !strings.Contains(rawHi, "_nel") {
		t.Fatalf("expected nested _nel date_range bounds, got %s / %s", rawLo, rawHi)
	}

	// Broad search plan exercising `date_histogram` on `date_range`, `range` agg, `lucene`, `mlt`,
	// out-of-bounds `byte` folding, `distance_feature`, `pinned`, `combined_fields`, `span_near`,
	// `function_score`, `search_after`, `geo_distance` sort, and nested sub-aggs.
	broadPlan := mustSearchPlanR63(t, tr, `{
		"size": 5,
		"query": {
			"function_score": {
				"query": {
					"bool": {
						"must": [
							{"query_string": {"query": "title:(quick AND fox*) OR tag:/ab.+/", "analyze_wildcard": true}},
							{"simple_query_string": {"query": "\"quick fox\" +jump -lazy", "fields": ["title^2"]}}
						],
						"should": [
							{"more_like_this": {"fields": ["title"], "like": "quick brown fox", "min_term_freq": 1, "min_doc_freq": 1}},
							{"range": {"tiny": {"gt": -200, "lte": 500}}},
							{"distance_feature": {"field": "ts", "origin": "2024-01-01T00:00:00Z", "pivot": "7d"}},
							{"distance_feature": {"field": "loc", "origin": [-71.3, 41.1], "pivot": "10km"}},
							{"pinned": {"ids": ["1", "2"], "organic": {"term": {"tag": "featured"}}}},
							{"combined_fields": {"query": "quick fox", "fields": ["title"]}},
							{"span_near": {"clauses": [{"span_term": {"title": "quick"}}, {"span_term": {"title": "fox"}}], "slop": 2, "in_order": true}}
						]
					}
				},
				"functions": [
					{"gauss": {"num": {"origin": 10, "scale": 5, "offset": 1, "decay": 0.5}}},
					{"linear": {"ts": {"origin": "2024-01-01T00:00:00Z", "scale": "10d"}}}
				],
				"score_mode": "sum",
				"boost_mode": "multiply"
			}
		},
		"sort": [
			{"_geo_distance": {"loc": [-71.34, 41.12], "order": "asc", "unit": "km"}},
			{"_id": "asc"}
		],
		"search_after": [12.5, "doc_1"],
		"aggs": {
			"dh_on_dr": {
				"date_histogram": {
					"field": "dr",
					"calendar_interval": "month",
					"offset": "-2d"
				}
			},
			"by_tag": {
				"terms": {"field": "tag"},
				"aggs": {
					"st": {"stats": {"field": "num"}},
					"vc": {"value_count": {"field": "num", "missing": 0}},
					"th": {"top_hits": {"size": 1, "sort": [{"num": "desc"}]}}
				}
			}
		}
	}`)
	if broadPlan.HitsSQL == "" || broadPlan.AggsSQL == "" {
		t.Fatalf("expected non-empty HitsSQL & AggsSQL")
	}
}

func TestRound63_SubAggsHistogramLuceneAndScriptCoverage(t *testing.T) {
	anCfg, err := analysis.ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"my_syn": map[string]any{
					"type":     "synonym_graph",
					"synonyms": []any{"ny, new york", "quick, fast"},
				},
			},
			"analyzer": map[string]any{
				"syn_an": map[string]any{
					"tokenizer": "standard",
					"filter":    []any{"lowercase", "my_syn"},
				},
			},
		},
	}, analysis.Options{})
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig: %v", err)
	}

	idx := mustCompileSchemaR63(t, "rich_idx", `{
		"properties": {
			"title": {"type": "text", "analyzer": "syn_an", "fields": {"exact": {"type": "keyword"}}},
			"title2": {"type": "text"},
			"tag": {"type": "keyword"},
			"flag_a": {"type": "boolean"},
			"flag_b": {"type": "boolean"},
			"num_a": {"type": "double"},
			"num_b": {"type": "integer"},
			"short_f": {"type": "short"},
			"float_f": {"type": "float"},
			"ts": {"type": "date", "format": "epoch_second||strict_date_optional_time"},
			"ts_ns": {"type": "date_nanos"},
			"ip_addr": {"type": "ip"},
			"loc": {"type": "geo_point"},
			"flat": {"type": "flattened"},
			"hist": {"type": "histogram"},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"price": {"type": "double"},
					"qty": {"type": "integer"}
				}
			}
		}
	}`)

	tr := NewTranspiler(idx, TranspilerOptions{
		ES8Compat:      true,
		AnalysisConfig: anCfg,
	})
	trD4 := NewTranspiler(idx, TranspilerOptions{
		ES8Compat:           true,
		UseDoris4SearchFunc: true,
		AnalysisConfig:      anCfg,
	})

	// 1. Rich Lucene `query_string` wildcard field expansions, boolean/range/regex/exists/negated groups,
	// synonym graph `match`/`match_phrase`/`match_bool_prefix`, `date_nanos`, `flattened`, `script`, and `Doris4SearchFunc`.
	qsPayloads := []string{
		`{"query":{"query_string":{"query":"_exists_:title^2 AND *:*^1.5 AND title*:*^2 AND num*:[10 TO 50]^2 AND title*:/qu.*/^1.5 AND title:-bad AND title:!(foo OR bar) AND title*:(quick OR brown) AND flag*:true AND title:\"new york\"~2 AND title2:fox~1","quote_field_suffix":".exact","time_zone":"+02:00","fuzziness":"AUTO"}}}`,
		`{"query":{"bool":{"must":[{"match":{"title":{"query":"ny fast","operator":"and"}}},{"match_phrase":{"title":"new york"}},{"match_bool_prefix":{"title":"new yo"}},{"range":{"ts_ns":{"gte":"2024-01-01T00:00:00.123456789Z","lte":1704153600000000000}}},{"term":{"ts_ns":"2024-01-01T00:00:00.123456789Z"}},{"terms":{"tag":["A","B"],"case_insensitive":true}},{"term":{"flat":"abc"}},{"prefix":{"flat":"ab"}},{"wildcard":{"flat":"a*c"}},{"range":{"short_f":{"gt":-99999,"lt":99999}}},{"range":{"float_f":{"gte":-1e39,"lte":1e39}}},{"script":{"script":"doc['num_a'].value > 5 && doc['flag_a'].value == true"}}],"minimum_should_match":"75%"}}}`,
		`{"sort":[{"ts":{"order":"asc","missing":"_first"}},{"num_a":{"order":"desc","missing":"_last"}},{"_id":"asc"}],"search_after":[1704067200,42.5,"id_9"]}`,
	}
	for _, qp := range qsPayloads {
		if p := mustSearchPlanR63(t, tr, qp); p.HitsSQL == "" {
			t.Fatalf("empty HitsSQL for %s", qp)
		}
		if p4 := mustSearchPlanR63(t, trD4, qp); p4.HitsSQL == "" {
			t.Fatalf("empty Doris4 HitsSQL for %s", qp)
		}
	}

	// 2. Deep grouped sub-aggregations (`histogram` field, `nested` exploded metrics, promoted arrays,
	// `percentiles`, `boxplot`, `percentile_ranks`, `extended_stats`, `rate`, `filter`, `filters`,
	// `range`, `date_range`, `ip_range`, `histogram`, `date_histogram`, `missing`, `string_stats`, `geo_*`).
	aggPlan := mustSearchPlanR63(t, tr, `{
		"size": 0,
		"aggs": {
			"h_pct": {"percentiles": {"field": "hist"}},
			"h_bp": {"boxplot": {"field": "hist"}},
			"h_pr": {"percentile_ranks": {"field": "hist", "values": [10, 50]}},
			"h_st": {"stats": {"field": "hist"}},
			"top_es": {"extended_stats": {"field": "num_a", "missing": 0, "script": {"source": "_value * 2"}}},
			"top_pr": {"percentile_ranks": {"field": "num_a", "values": [5, 25], "missing": 0}},
			"top_mad": {"median_absolute_deviation": {"field": "num_a"}},
			"top_wavg": {"weighted_avg": {"value": {"field": "num_a"}, "weight": {"field": "num_b"}}},
			"top_ss": {"string_stats": {"field": "tag"}},
			"top_gb": {"geo_bounds": {"field": "loc"}},
			"top_gc": {"geo_centroid": {"field": "loc"}},
			"top_gh": {"geohash_grid": {"field": "loc", "precision": 4}},
			"top_gt": {"geotile_grid": {"field": "loc", "precision": 4}},
			"top_gd": {"geo_distance": {"field": "loc", "origin": "41.12,-71.34", "ranges": [{"to": 100}, {"from": 100}]}},
			"top_glob": {"global": {}, "aggs": {"c": {"value_count": {"field": "tag"}}}},
			"top_adh": {"auto_date_histogram": {"field": "ts", "buckets": 5}},
			"top_mt": {"multi_terms": {"terms": [{"field": "tag"}, {"field": "num_b"}]}},
			"top_rare": {"rare_terms": {"field": "tag", "max_doc_count": 2}},
			"top_sig": {"significant_terms": {"field": "tag"}},
			"top_comp": {"composite": {"sources": [{"t": {"terms": {"field": "tag"}}}, {"h": {"histogram": {"field": "num_a", "interval": 10}}}]}},
			"top_adj": {"adjacency_matrix": {"filters": {"a": {"term": {"flag_a": true}}, "b": {"term": {"flag_b": true}}}}},
			"top_samp": {"sampler": {"shard_size": 100}, "aggs": {"t": {"terms": {"field": "tag"}}}},
			"top_dsamp": {"diversified_sampler": {"field": "tag", "shard_size": 100}, "aggs": {"t": {"terms": {"field": "tag"}}}},
			"by_tag": {
				"terms": {"field": "tag"},
				"aggs": {
					"h_stats": {"stats": {"field": "hist"}},
					"num_es": {"extended_stats": {"field": "num_a"}},
					"h_pct": {"percentiles": {"field": "hist", "percents": [50, 95]}},
					"h_bp": {"boxplot": {"field": "hist"}},
					"h_pr": {"percentile_ranks": {"field": "hist", "values": [10, 50]}},
					"n_avg": {"avg": {"field": "num_a", "missing": 0, "script": {"source": "_value * 2"}}},
					"n_pct": {"percentiles": {"field": "num_a", "missing": 0, "script": {"source": "doc['num_a'].value + 1"}}},
					"n_bp": {"boxplot": {"field": "num_a", "missing": 0, "script": {"source": "doc['num_a'].value + 1"}}},
					"n_pr": {"percentile_ranks": {"field": "num_a", "values": [5, 20], "missing": 0}},
					"arr_avg": {"avg": {"field": "items.price", "missing": 0}},
					"arr_pct": {"percentiles": {"field": "items.price", "missing": 0}},
					"arr_bp": {"boxplot": {"field": "items.price", "missing": 0}},
					"arr_pr": {"percentile_ranks": {"field": "items.price", "values": [10, 20]}},
					"str_st": {"string_stats": {"field": "tag"}},
					"card": {"cardinality": {"field": "tag", "missing": "N/A"}},
					"gb": {"geo_bounds": {"field": "loc"}},
					"gc": {"geo_centroid": {"field": "loc"}},
					"sub_flt": {
						"filter": {"term": {"flag_a": true}},
						"aggs": {"s": {"sum": {"field": "num_a"}}}
					},
					"sub_flts": {
						"filters": {"filters": {"on": {"term": {"flag_a": true}}, "off": {"term": {"flag_a": false}}}},
						"aggs": {"s": {"sum": {"field": "num_a"}}}
					},
					"sub_miss": {
						"missing": {"field": "tag"},
						"aggs": {"c": {"value_count": {"field": "num_a"}}}
					},
					"sub_rng": {
						"range": {"field": "num_a", "ranges": [{"to": 10}, {"from": 10, "to": 50}, {"from": 50}]},
						"aggs": {"m": {"max": {"field": "num_b"}}}
					},
					"sub_ipr": {
						"ip_range": {"field": "ip_addr", "ranges": [{"mask": "10.0.0.0/8"}, {"from": "192.168.0.1", "to": "192.168.1.1"}]}
					},
					"sub_hist": {
						"histogram": {"field": "num_a", "interval": 10}
					},
					"sub_dh": {
						"date_histogram": {"field": "ts", "fixed_interval": "1h"},
						"aggs": {
							"r_doc": {"rate": {"unit": "minute"}},
							"r_vc": {"rate": {"field": "items.price", "unit": "minute", "mode": "value_count"}},
							"r_sum": {"rate": {"field": "num_a", "unit": "minute", "mode": "sum"}}
						}
					},
					"sub_nested": {
						"nested": {"path": "items"},
						"aggs": {
							"in_avg": {"avg": {"field": "items.price", "missing": 0, "script": {"source": "_value * 1.1"}}},
							"in_pct": {"percentiles": {"field": "items.price", "missing": 0}},
							"in_bp": {"boxplot": {"field": "items.price", "missing": 0}},
							"in_rate": {"rate": {"field": "items.sku", "unit": "hour", "mode": "value_count"}},
							"back": {
								"reverse_nested": {},
								"aggs": {"root_c": {"value_count": {"field": "tag"}}}
							}
						}
					}
				}
			}
		}
	}`)
	if aggPlan.AggsSQL == "" {
		t.Fatalf("expected non-empty AggsSQL")
	}
}

func TestRound63_AdditionalAggsPredicatesKNNAndMLTCoverage(t *testing.T) {
	idx := mustCompileSchemaR63(t, "cov_idx", `{
		"properties": {
			"title": {"type": "text"},
			"sayt": {"type": "search_as_you_type"},
			"tag": {"type": "keyword"},
			"flag_a": {"type": "boolean"},
			"flag_b": {"type": "boolean"},
			"u_val": {"type": "unsigned_long"},
			"byte_f": {"type": "byte"},
			"short_f": {"type": "short"},
			"int_f": {"type": "integer"},
			"long_f": {"type": "long"},
			"half_f": {"type": "half_float"},
			"float_f": {"type": "float"},
			"num_a": {"type": "double"},
			"ts": {"type": "date"},
			"ts_ns": {"type": "date_nanos"},
			"ip_addr": {"type": "ip"},
			"ver": {"type": "version"},
			"flat": {"type": "flattened"},
			"hist": {"type": "histogram"},
			"vec_l2": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "l2_norm"},
			"vec_dp_byte": {"type": "dense_vector", "dims": 2, "element_type": "byte", "index": true, "similarity": "dot_product"},
			"vec_mip": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "max_inner_product"},
			"vec_bit": {"type": "dense_vector", "dims": 8, "element_type": "bit", "index": true, "similarity": "l2_norm"},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"price": {"type": "double"},
					"ts_ns": {"type": "date_nanos"},
					"ip": {"type": "ip"},
					"ver": {"type": "version"},
					"sub": {
						"type": "nested",
						"properties": {
							"code": {"type": "keyword"}
						}
					}
				}
			}
		}
	}`)
	tr := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})

	// 1. Top-level & Query-level kNN across metrics/element_types, wildcard field term/terms,
	// `_ignored`, `search_as_you_type`, `flattened.sub`, array `ip`/`version`, `more_like_this`,
	// and out-of-bounds numeric range folding.
	queries := []string{
		`{"size":4,"knn":[{"field":"vec_l2","query_vector":[1,2],"similarity":5.0,"filter":[{"term":{"tag":"a"}}]},{"field":"vec_dp_byte","query_vector":"0102","k":2,"num_candidates":4,"similarity":0.1},{"field":"vec_mip","query_vector":[0.5,-0.5],"k":2,"num_candidates":4,"similarity":-1.0},{"field":"vec_bit","query_vector":"ff","k":2,"num_candidates":4,"similarity":0.5}]}`,
		`{"query":{"bool":{"must":[{"term":{"flag_*":true}},{"terms":{"flag_*":[true,false]}},{"term":{"_ignored":{"value":"big_field","case_insensitive":true}}},{"term":{"_ignored":"big_field"}},{"terms":{"_ignored":["f1","f2"],"case_insensitive":true}},{"term":{"sayt":"quick"}},{"term":{"sayt._index_prefix":"qui"}},{"term":{"flat.sub":{"value":"Val","case_insensitive":true}}},{"term":{"flat.sub":"Val"}},{"terms":{"flat.sub":["v1","v2"],"case_insensitive":true}},{"term":{"items.ip":"10.0.0.0/8"}},{"term":{"items.ver":"1.2.3+build1"}},{"terms":{"u_val":["18446744073709551610",42]}},{"terms":{"ver":["1.0.0","2.0.0"]}},{"terms":{"ip_addr":["10.0.0.1","192.168.0.0/16"]}},{"terms":{"ts_ns":["2024-01-01T00:00:00.123456789Z"]}}],"should":[{"range":{"byte_f":{"gte":-500,"lte":500}}},{"range":{"int_f":{"gt":-99999999999,"lt":99999999999}}},{"range":{"half_f":{"gt":-999999,"lt":999999}}},{"more_like_this":{"fields":["title","tag"],"like":[{"_id":"1","doc":{"title":"quick brown fox","tag":"news"}},"fast jumping dog"],"unlike":["lazy cat"],"stop_words":["the"],"min_term_freq":1,"min_doc_freq":1,"min_word_length":2,"max_word_length":15,"boost_terms":1.5,"include":true,"minimum_should_match":"50%"}}]}}}`,
	}
	for _, q := range queries {
		if p := mustSearchPlanR63(t, tr, q); p.HitsSQL == "" {
			t.Fatalf("empty HitsSQL for %s", q)
		}
	}

	// 2. Exhaustive nested & multi-level grouped sub-aggregations (`appendGroupedBucketSubAggsWithNested`).
	subAggPlan := mustSearchPlanR63(t, tr, `{
		"size": 0,
		"aggs": {
			"by_tag": {
				"terms": {"field": "tag"},
				"aggs": {
					"mad": {"median_absolute_deviation": {"field": "num_a", "missing": 0, "script": {"source": "_value * 2"}}},
					"ss_arr": {"string_stats": {"field": "items.sku", "missing": "none", "script": {"source": "_value"}}},
					"ss_sc": {"string_stats": {"field": "tag", "missing": "none", "script": {"source": "_value"}}},
					"vc_hist": {"value_count": {"field": "hist"}},
					"vc_arr": {"value_count": {"field": "items.sku", "missing": "none", "script": {"source": "_value"}}},
					"vc_sc": {"value_count": {"field": "tag", "missing": "none", "script": {"source": "_value"}}},
					"card_arr": {"cardinality": {"field": "items.sku", "missing": "none", "script": {"source": "_value"}}},
					"card_sc": {"cardinality": {"field": "tag", "missing": "none", "script": {"source": "_value"}}},
					"pr_arr": {"percentile_ranks": {"field": "items.price", "values": [10, 20], "missing": 0, "script": {"source": "_value * 2"}}},
					"pr_sc": {"percentile_ranks": {"field": "num_a", "values": [10, 20], "script": {"source": "_value * 2"}}},
					"samp": {
						"sampler": {"shard_size": 50},
						"aggs": {"c": {"value_count": {"field": "num_a"}}}
					},
					"t_arr": {
						"terms": {"field": "items.sku", "missing_bucket": true, "script": {"source": "_value"}},
						"aggs": {"s": {"sum": {"field": "num_a"}}}
					},
					"t_bool": {"terms": {"field": "flag_a", "missing": false}},
					"t_u": {
						"terms": {"field": "u_val", "missing_bucket": true},
						"aggs": {"c": {"value_count": {"field": "tag"}}}
					},
					"dh_arr": {
						"date_histogram": {
							"field": "items.ts_ns",
							"fixed_interval": "1d",
							"missing": "2024-01-01T00:00:00Z",
							"hard_bounds": {"min": "2024-01-01T00:00:00Z", "max": "2024-01-10T00:00:00Z"}
						},
						"aggs": {"s": {"sum": {"field": "num_a"}}}
					},
					"dh_sc": {
						"date_histogram": {
							"field": "ts",
							"fixed_interval": "1h",
							"missing": "2024-01-01T00:00:00Z",
							"script": {"source": "_value + 1000"},
							"hard_bounds": {"min": 1704067200000, "max": 1704153600000}
						}
					},
					"h_on_hist": {"histogram": {"field": "hist", "interval": 5}},
					"h_arr": {
						"histogram": {
							"field": "items.price",
							"interval": 10,
							"missing": 0,
							"hard_bounds": {"min": 0, "max": 100}
						},
						"aggs": {"c": {"value_count": {"field": "tag"}}}
					},
					"h_sc": {
						"histogram": {
							"field": "num_a",
							"interval": 5,
							"offset": 1,
							"missing": 0,
							"script": {"source": "_value * 2"},
							"hard_bounds": {"min": 0, "max": 100}
						}
					},
					"rng_arr": {"range": {"field": "items.price", "ranges": [{"to": 10}, {"from": 10}]}},
					"ipr_arr": {"ip_range": {"field": "items.ip", "ranges": [{"mask": "10.0.0.0/8"}, {"from": "10.0.0.1", "to": "10.0.0.9"}]}},
					"nest_outer": {
						"nested": {"path": "items"},
						"aggs": {
							"in_vc": {"value_count": {"field": "items.sku"}},
							"in_card": {"cardinality": {"field": "items.sku"}},
							"in_pr": {"percentile_ranks": {"field": "items.price", "values": [10]}},
							"in_dh": {"date_histogram": {"field": "items.ts_ns", "fixed_interval": "1d"}},
							"in_h": {"histogram": {"field": "items.price", "interval": 10}},
							"nest_inner": {
								"nested": {"path": "items.sub"},
								"aggs": {
									"rn_to_items": {
										"reverse_nested": {"path": "items"},
										"aggs": {"s": {"sum": {"field": "items.price"}}}
									}
								}
							}
						}
					}
				}
			}
		}
	}`)
	if subAggPlan.AggsSQL == "" {
		t.Fatalf("expected non-empty subAggPlan.AggsSQL")
	}
}

func TestRound63_DeepCompositeNestedPrefilterSpanAndGeoSortCoverage(t *testing.T) {
	idx := mustCompileSchemaR63(t, "deep_cov_idx", `{
		"runtime": {
			"rt_kw": {"type": "keyword"}
		},
		"properties": {
			"title": {"type": "text"},
			"tag": {"type": "keyword"},
			"flag_a": {"type": "boolean"},
			"num_a": {"type": "double"},
			"num_b": {"type": "integer"},
			"byte_f": {"type": "byte"},
			"short_f": {"type": "short"},
			"long_f": {"type": "long"},
			"float_f": {"type": "float"},
			"ts": {"type": "date"},
			"loc": {"type": "geo_point"},
			"flat": {"type": "flattened"},
			"vec_cos": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "cosine"},
			"vec_l2": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "l2_norm"},
			"vec_dp": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "dot_product"},
			"vec_mip": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "max_inner_product"},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"flag": {"type": "boolean"},
					"price": {"type": "double"},
					"u_val": {"type": "unsigned_long"},
					"ts": {"type": "date"},
					"ts_ns": {"type": "date_nanos"},
					"ip": {"type": "ip"},
					"ver": {"type": "version"},
					"loc": {"type": "geo_point"}
				}
			}
		}
	}`)
	tr := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})

	// 1. Nested prefilter normalization (`extractNestedPrefilter` + `normalizeNestedPrefilterValue`),
	// prefix/wildcard/regexp across `_ignored`, runtime `rt_kw`, `flattened`, promoted arrays, and wildcards,
	// `min_score` tree walkers (`queryContainsScript` / `queryContainsNestedScoring`), `Query.KNN`, and Lucene unfielded ranges/regexes.
	queries := []string{
		`{"query":{"nested":{"path":"items","query":{"bool":{"must":[{"terms":{"items.ver":["1.0.0+b1","2.0.0"]}},{"terms":{"items.ip":["10.0.0.1","192.168.1.1"]}},{"terms":{"items.flag":[true,"false"]}},{"terms":{"items.ts":["2024-01-01T00:00:00Z"]}},{"terms":{"items.u_val":["18446744073709551610",42]}},{"terms":{"items.price":["12.5",9.25]}},{"exists":{"field":"items.sku"}}],"filter":[{"terms":{"items.ip":["10.0.0.0/8"]}}]}}}}}`,
		`{"query":{"bool":{"must":[{"prefix":{"_ignored":{"value":"big","case_insensitive":true}}},{"prefix":{"_ignored":"big"}},{"prefix":{"rt_kw":{"value":"Ab","case_insensitive":true}}},{"prefix":{"rt_kw":"Ab"}},{"prefix":{"items.sku":{"value":"SK","case_insensitive":true}}},{"prefix":{"items.sku":"SK"}},{"prefix":{"flat":{"value":"fl","case_insensitive":true}}},{"prefix":{"flat.sub":{"value":"fl","case_insensitive":true}}},{"prefix":{"flat.sub":"fl"}},{"prefix":{"tag*":"pr"}},{"prefix":{"unmatched_*":"pr"}},{"wildcard":{"_ignored":{"value":"b*g","case_insensitive":true}}},{"wildcard":{"_ignored":"b*g"}},{"wildcard":{"rt_kw":{"value":"A*b","case_insensitive":true}}},{"wildcard":{"rt_kw":"A*b"}},{"wildcard":{"items.sku":{"value":"S*K","case_insensitive":true}}},{"wildcard":{"items.sku":"S*K"}},{"wildcard":{"flat":{"value":"f*l","case_insensitive":true}}},{"wildcard":{"flat":"f*l"}},{"wildcard":{"flat.sub":{"value":"f*l","case_insensitive":true}}},{"wildcard":{"flat.sub":"f*l"}},{"wildcard":{"title":"qu*ck"}},{"wildcard":{"tag*":"t*"}},{"wildcard":{"unmatched_*":"t*"}}]}}}`,
		`{"min_score":0.2,"query":{"bool":{"must":[{"constant_score":{"filter":{"term":{"tag":"a"}}}},{"function_score":{"query":{"term":{"tag":"a"}}}},{"pinned":{"ids":["1"],"organic":{"term":{"tag":"a"}}}},{"dis_max":{"queries":[{"term":{"tag":"a"}}]}},{"boosting":{"positive":{"term":{"tag":"a"}},"negative":{"term":{"tag":"b"}},"negative_boost":0.2}}],"should":[{"span_or":{"clauses":[{"span_first":{"match":{"span_term":{"title":"quick"}},"end":3}},{"span_not":{"include":{"span_term":{"title":"quick"}},"exclude":{"span_term":{"title":"fox"}}}},{"span_containing":{"big":{"span_near":{"clauses":[{"span_term":{"title":"quick"}},{"span_term":{"title":"fox"}}],"slop":3,"in_order":false}},"little":{"span_term":{"title":"brown"}}}},{"span_within":{"big":{"span_near":{"clauses":[{"span_term":{"title":"quick"}},{"span_term":{"title":"fox"}}],"slop":3,"in_order":false}},"little":{"span_multi":{"match":{"prefix":{"title":"br"}}}}}},{"field_masking_span":{"query":{"span_term":{"title":"quick"}},"field":"title"}}]}}],"filter":[{"term":{"tag":"a"}}],"must_not":[{"term":{"tag":"z"}}]}}}`,
		`{"query":{"bool":{"should":[{"knn":{"field":"vec_cos","query_vector":[1,0],"similarity":0.2}},{"knn":{"field":"vec_l2","query_vector":[1,0],"k":2,"num_candidates":4}},{"knn":{"field":"vec_dp","query_vector":[0.6,0.8],"k":2,"num_candidates":4}},{"knn":{"field":"vec_mip","query_vector":[1,2],"k":2,"num_candidates":4}},{"query_string":{"query":"[* TO *]^2 OR [10 TO 50]^1.5 OR /fo.+([a-z]{2,4}|bar)?/","fields":["title^2","num_a"],"lenient":true,"time_zone":"+01:00"}},{"query_string":{"query":"[* TO *]^2","fields":["*^1.5","title"]}},{"query_string":{"query":"[* TO *]^2 AND [10 TO 20] AND /ab.+/","default_field":"num_a"}},{"range":{"byte_f":{"gt":200}}},{"range":{"short_f":{"lte":-40000}}},{"range":{"long_f":{"gt":"99999999999999999999","lt":"-99999999999999999999"}}},{"range":{"float_f":{"gt":1e39}}}]}}}`,
		`{"sort":[{"_geo_distance":{"loc":"41.12,-71.34","order":"asc","mode":"min"}},{"_geo_distance":{"items.loc":[{"lat":41.12,"lon":-71.34},"drm3btev3e86"],"order":"desc","mode":"avg","distance_type":"plane"}}]}`,
	}
	for _, q := range queries {
		if p := mustSearchPlanR63(t, tr, q); p.HitsSQL == "" {
			t.Fatalf("empty HitsSQL for %s", q)
		}
	}

	// 2. Sub-weighted_avg, sub-rare_terms, sub-multi_terms, top-level composite, and nested `top_hits`.
	compPlan := mustSearchPlanR63(t, tr, `{
		"size": 0,
		"aggs": {
			"top_comp2": {
				"composite": {
					"sources": [
						{"dh": {"date_histogram": {"field": "ts", "fixed_interval": "1d", "missing_bucket": true}}},
						{"gt": {"geotile_grid": {"field": "loc", "precision": 5, "missing_bucket": true}}},
						{"b": {"terms": {"field": "flag_a", "missing_bucket": true}}},
						{"sku": {"terms": {"field": "items.sku", "missing_bucket": true}}}
					]
				}
			},
			"by_tag": {
				"terms": {"field": "tag"},
				"aggs": {
					"sub_wavg": {
						"weighted_avg": {
							"value": {"field": "num_a", "missing": 1, "script": {"source": "_value * 2"}},
							"weight": {"field": "num_b", "missing": 1, "script": {"source": "_value + 1"}}
						}
					},
					"sub_rare_arr": {
						"rare_terms": {"field": "items.sku", "max_doc_count": 2, "missing": "N/A"},
						"aggs": {"s": {"sum": {"field": "num_a"}}}
					},
					"sub_rare_sc": {
						"rare_terms": {"field": "flag_a", "max_doc_count": 2, "missing": false},
						"aggs": {"s": {"sum": {"field": "num_a"}}}
					},
					"sub_mt": {
						"multi_terms": {
							"terms": [
								{"field": "items.sku", "missing": "N/A"},
								{"field": "flag_a", "missing": false},
								{"field": "tag", "script": {"source": "_value"}}
							]
						},
						"aggs": {"s": {"sum": {"field": "num_a"}}}
					},
					"nest_th": {
						"nested": {"path": "items"},
						"aggs": {
							"th": {"top_hits": {"size": 2, "sort": [{"items.price": {"order": "desc"}}]}}
						}
					}
				}
			}
		}
	}`)
	if compPlan.AggsSQL == "" {
		t.Fatalf("expected non-empty compPlan.AggsSQL")
	}

	// Direct internal helper check for grouped composite sub-agg SQL generation.
	var subCompMap map[string]esast.AggSpec
	_ = json.Unmarshal([]byte(`{
		"sub_comp": {
			"composite": {
				"sources": [
					{"sku": {"terms": {"field": "items.sku", "missing_bucket": true}}},
					{"fl": {"terms": {"field": "flag_a", "missing": false}}},
					{"dh": {"date_histogram": {"field": "items.ts_ns", "fixed_interval": "1d", "missing_bucket": true, "script": {"source": "_value"}}}},
					{"h": {"histogram": {"field": "items.price", "interval": 10, "missing": 0, "script": {"source": "_value"}}}},
					{"gt": {"geotile_grid": {"field": "loc", "precision": 6, "missing_bucket": true}}}
				]
			},
			"aggs": {"c": {"value_count": {"field": "num_a"}}}
		}
	}`), &subCompMap)
	var directBranches []string
	directSubIdx := 0
	tr.appendGroupedBucketSubAggsWithNested(&directBranches, &directSubIdx, "by_tag", "`f__tag`", "`base_matched`", "1=1", nil, subCompMap)
	if len(directBranches) == 0 {
		t.Fatalf("expected non-empty directBranches for grouped composite")
	}

	// 3. `QueryHasIntervals` & `EvaluateIntervalsRuleWithFieldLookup` (`any_of` dedup + `containing` / `contained_by` / `not_contained_by`).
	for _, ivJSON := range []string{
		`{"bool":{"must":[{"intervals":{"title":{"match":{"query":"a"}}}}]}}`,
		`{"bool":{"filter":[{"intervals":{"title":{"match":{"query":"a"}}}}]}}`,
		`{"bool":{"must_not":[{"intervals":{"title":{"match":{"query":"a"}}}}]}}`,
		`{"boosting":{"positive":{"term":{"tag":"a"}},"negative":{"intervals":{"title":{"match":{"query":"a"}}}},"negative_boost":0.5}}`,
		`{"dis_max":{"queries":[{"intervals":{"title":{"match":{"query":"a"}}}}]}}`,
		`{"function_score":{"query":{"intervals":{"title":{"match":{"query":"a"}}}}}}`,
		`{"nested":{"path":"items","query":{"intervals":{"title":{"match":{"query":"a"}}}}}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(ivJSON), &q); err != nil || !QueryHasIntervals(&q) {
			t.Fatalf("expected QueryHasIntervals=true for %s (err=%v)", ivJSON, err)
		}
	}

	var anyRule esast.IntervalsRule
	_ = json.Unmarshal([]byte(`{
		"any_of": {
			"intervals": [
				{"match": {"query": "big"}},
				{"match": {"query": "big"}},
				{"match": {"query": "big bad"}}
			],
			"filter": {
				"containing": {"match": {"query": "big"}},
				"contained_by": {"match": {"query": "the big bad wolf", "max_gaps": 5}},
				"not_contained_by": {"match": {"query": "zzz"}}
			}
		}
	}`), &anyRule)
	if _, ok, err := EvaluateIntervalsRuleWithFieldLookup("title", &anyRule, func(_ string) ([]string, string) {
		return []string{"the big bad wolf"}, "standard"
	}, nil); err != nil || !ok {
		t.Fatalf("expected any_of rule with containing/contained_by/not_contained_by to match: ok=%v err=%v", ok, err)
	}
}

func TestRound63_MatchRangeFieldSortAndScriptTailCoverage(t *testing.T) {
	idx := mustCompileSchemaR63(t, "tail_cov_idx", `{
		"properties": {
			"title": {"type": "text", "analyzer": "stop"},
			"kw": {"type": "keyword", "ignore_above": 10},
			"flag": {"type": "boolean"},
			"num": {"type": "double"},
			"u_val": {"type": "unsigned_long"},
			"ts_sec": {"type": "date", "format": "epoch_second"},
			"ts_ns": {"type": "date_nanos"},
			"ip_addr": {"type": "ip"},
			"ir": {"type": "integer_range"},
			"dr": {"type": "date_range"},
			"ipr": {"type": "ip_range"},
			"items": {
				"type": "nested",
				"properties": {
					"tags": {"type": "keyword"},
					"nums": {"type": "integer"},
					"price": {"type": "double"},
					"flag": {"type": "boolean"}
				}
			}
		}
	}`)
	// Mark nested fields multi-valued to exercise nested multi-value JSON array SQL branches.
	if b, ok := idx.Fields["items.tags"]; ok {
		b.IsMultiValued = true
		idx.Fields["items.tags"] = b
	}
	if b, ok := idx.Fields["items.nums"]; ok {
		b.IsMultiValued = true
		idx.Fields["items.nums"] = b
	}
	tr := NewTranspiler(idx, TranspilerOptions{ES8Compat: true})

	queries := []string{
		// `match` on non-text types, fuzzy match, zero_terms_query, minimum_should_match.
		`{"query":{"bool":{"must":[{"match":{"kw":"hello"}},{"match":{"flag":true}},{"match":{"num":42.5}},{"match":{"u_val":"18446744073709551610"}},{"match":{"ts_sec":1704067200}},{"match":{"ip_addr":"10.0.0.1"}},{"match":{"title":{"query":"the","zero_terms_query":"all"}}},{"match":{"title":{"query":"quikc brwon fox","fuzziness":"AUTO","prefix_length":1,"minimum_should_match":"2<-25%"}}}]}}}`,
		// Range queries on range fields (`within`, `contains`, `intersects`), `ip`, `date_nanos`, `epoch_second`.
		`{"query":{"bool":{"must":[{"range":{"ir":{"gte":10,"lte":20,"relation":"within"}}},{"range":{"ir":{"gt":5,"lt":50,"relation":"contains"}}},{"range":{"dr":{"gte":"2024-01-01T00:00:00Z","lte":"2024-02-01T00:00:00Z","relation":"intersects"}}},{"range":{"ipr":{"gte":"10.0.0.1","lte":"10.0.0.254","relation":"within"}}},{"range":{"ip_addr":{"gte":"10.0.0.1","lte":"10.255.255.254"}}},{"range":{"ip_addr":{"gt":"fe80::1","lt":"fe80::ffff"}}},{"term":{"kw":"too_long_ignore_above_string"}},{"term":{"u_val":42}},{"term":{"ts_sec":1704067200}}]}}}`,
		// Multi-valued nested subfields (`term`, `prefix`, `wildcard`), boolean scripts, and `script_score`.
		`{"query":{"function_score":{"query":{"bool":{"must":[{"nested":{"path":"items","query":{"bool":{"must":[{"term":{"items.tags":{"value":"TagA","case_insensitive":true}}},{"term":{"items.tags":"123"}},{"term":{"items.nums":7}},{"prefix":{"items.tags":{"value":"Ta","case_insensitive":true}}},{"wildcard":{"items.tags":{"value":"T*A","case_insensitive":true}}}],"filter":[{"term":{"items.flag":true}}]}}}},{"script":{"script":{"source":"doc['num'].size() > 0 && (doc['num'].value >= params.min || doc['kw'].value != 'bad')","params":{"min":5}}}}]}},"script_score":{"script":{"source":"_score * doc['num'].value + params.b","params":{"b":1.5}}}}},"sort":[{"items.price":{"order":"asc","mode":"avg","nested":{"path":"items","filter":{"term":{"items.flag":true}}}}},{"items.price":{"order":"desc","mode":"median","nested":{"path":"items"}}},{"unmapped_num":{"order":"asc","unmapped_type":"long"}},{"_script":{"type":"number","script":{"source":"doc['num'].value * 2"},"order":"desc"}},{"_script":{"type":"string","script":{"source":"doc['kw'].value"},"order":"asc"}}]}`,
	}
	for _, q := range queries {
		if p := mustSearchPlanR63(t, tr, q); p.HitsSQL == "" {
			t.Fatalf("empty HitsSQL for %s", q)
		}
	}

	// Additional coverage for `common`, multi-key `match*`, wildcard `regexp`, `rank_feature`,
	// `date_nanos` timezone/epoch coercions, nested `top_hits` sorts, and `FormatLuceneValidateExplanation`.
	idx2 := mustCompileSchemaR63(t, "tail_cov_idx2", `{
		"properties": {
			"title": {"type": "text"},
			"body": {"type": "text"},
			"tag": {"type": "keyword"},
			"rf": {"type": "rank_feature"},
			"rfs": {"type": "rank_features"},
			"ts_sec": {"type": "date", "format": "epoch_second"},
			"ts_ns": {"type": "date_nanos"},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"flag": {"type": "boolean"},
					"u_val": {"type": "unsigned_long"},
					"ts": {"type": "date"},
					"ip": {"type": "ip"},
					"price": {"type": "double"}
				}
			}
		}
	}`)
	anCfg2, _ := analysis.ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"syn": map[string]any{"type": "synonym", "synonyms": []any{"quick, fast"}},
			},
			"analyzer": map[string]any{
				"syn_flat": map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "syn"}},
			},
		},
	}, analysis.Options{})
	tr2 := NewTranspiler(idx2, TranspilerOptions{ES8Compat: true, AnalysisConfig: anCfg2})
	extraQueries := []string{
		`{"query":{"bool":{"must":[{"common":{"title":{"query":"the quick brown","cutoff_frequency":0.01,"low_freq_operator":"and","high_freq_operator":"or"}}},{"common":{"title":{"query":"the and","cutoff_frequency":0.01}}},{"common":{"title":{"query":"fox"},"body":{"query":"dog"}}},{"match":{"title":"a","body":"b"}},{"match_phrase":{"title":"a b","body":"c d"}},{"match_phrase_prefix":{"title":"a b","body":"c d"}},{"match_bool_prefix":{"title":"a b","body":"c d"}},{"regexp":{"tag*":"ab.*"}},{"rank_feature":{"field":"rf","saturation":{"pivot":5}}},{"rank_feature":{"field":"rf","log":{"scaling_factor":2}}},{"rank_feature":{"field":"rf","sigmoid":{"pivot":4,"exponent":0.6}}},{"rank_feature":{"field":"rfs.math","linear":{}}},{"range":{"ts_ns":{"gte":"2024-01-01T00:00:00","lte":1704153600000,"time_zone":"+02:00"}}},{"span_near":{"clauses":[{"span_or":{"clauses":[{"span_term":{"title":"quick"}},{"span_term":{"title":"fast"}}],"boost":1.5}},{"span_term":{"title":"fox"}}],"slop":2}}]}}}`,
		`{"size":0,"aggs":{"dr_ns":{"date_range":{"field":"ts_ns","time_zone":"+02:00","ranges":[{"from":"2024-01-01T00:00:00","to":1704153600000000000}]}},"dr_sec":{"date_range":{"field":"ts_sec","format":"epoch_second","ranges":[{"from":1704067200,"to":"1704153600"}]}},"nest":{"nested":{"path":"items"},"aggs":{"th":{"top_hits":{"size":2,"sort":[{"_id":"asc"},{"items.ip":"asc"},{"items.u_val":"desc"},{"items.ts":"asc"},{"items.flag":"desc"},{"items.sku":{"order":"asc","missing":"_first"}},{"ts_sec":"desc"}]}}}}}}`,
	}
	for _, eq := range extraQueries {
		if p := mustSearchPlanR63(t, tr2, eq); p.HitsSQL == "" && p.AggsSQL == "" {
			t.Fatalf("empty plan for %s", eq)
		}
	}

	for _, expQ := range []string{
		`{"match_phrase":{"title":{"query":"quick fox","analyzer":"syn_flat"}}}`,
		`{"match_phrase_prefix":{"title":{"query":"quick fo","analyzer":"syn_flat"}}}`,
		`{"match_bool_prefix":{"title":{"query":"quick fo","operator":"and","analyzer":"syn_flat"}}}`,
		`{"query_string":{"query":"\"quick fox*\"","default_field":"title","analyzer":"syn_flat"}}`,
		`{"query_string":{"query":"title:quick","analyzer":"syn_flat"}}`,
		`{"match_phrase":{"title":{"query":"   ","analyzer":"stop"}}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(expQ), &q); err != nil {
			t.Fatalf("unmarshal explain query: %v", err)
		}
		if got := FormatLuceneValidateExplanation(&q, idx2, anCfg2, analysis.Options{}); got == "" {
			t.Fatalf("empty FormatLuceneValidateExplanation for %s", expQ)
		}
	}

	// `search_after` across `_score`, `_geo_distance` units, `_script`, `boolean`, `ip`, `version`, `date_nanos`, `unsigned_long`, `ignore_unmapped`, and top-level `date_histogram` array/script/missing.
	idx3 := mustCompileSchemaR63(t, "sa_cov_idx", `{
		"properties": {
			"flag": {"type": "boolean"},
			"ip": {"type": "ip"},
			"ver": {"type": "version"},
			"ts": {"type": "date"},
			"ts_ns": {"type": "date_nanos"},
			"u_val": {"type": "unsigned_long"},
			"loc": {"type": "geo_point"},
			"num": {"type": "double"},
			"items": {
				"type": "nested",
				"properties": {
					"ts_ns": {"type": "date_nanos"}
				}
			}
		}
	}`)
	tr3 := NewTranspiler(idx3, TranspilerOptions{ES8Compat: true})
	for _, saQ := range []string{
		`{"search_after":[1.5,"doc_1"]}`,
		`{"sort":[{"ghost":{"order":"asc","ignore_unmapped":true}},{"_score":"desc"},{"_geo_distance":{"loc":[0,0],"order":"asc","unit":"mi","missing":100}},{"_geo_distance":{"loc":[0,0],"order":"asc","unit":"yd"}},{"_geo_distance":{"loc":[0,0],"order":"asc","unit":"ft"}},{"_geo_distance":{"loc":[0,0],"order":"asc","unit":"in"}},{"_geo_distance":{"loc":[0,0],"order":"asc","unit":"nmi"}},{"_geo_distance":{"loc":[0,0],"order":"asc","unit":"cm"}},{"_geo_distance":{"loc":[0,0],"order":"asc","unit":"mm"}},{"_script":{"type":"number","script":{"source":"doc['num'].value"},"order":"asc"}},{"flag":"asc"},{"ip":"asc"},{"ver":"desc"},{"ts_ns":"asc"},{"ts":"asc"},{"u_val":"desc"},{"_id":"asc"}],"search_after":[1.0,5.0,10.0,15.0,20.0,2.0,50.0,500.0,3.5,"true","10.0.0.1","1.2.3","2024-01-01T00:00:00.123456789Z","2024-01-01T00:00:00Z","18446744073709551610","doc_2"]}`,
		`{"size":0,"aggs":{"dh_arr":{"date_histogram":{"field":"items.ts_ns","fixed_interval":"1d","missing":"2024-01-01T00:00:00Z","script":{"source":"_value"},"hard_bounds":{"min":"2024-01-01T00:00:00Z","max":"2024-01-10T00:00:00Z"}}},"dh_script_only":{"date_histogram":{"fixed_interval":"1h","missing":1704067200000,"script":{"source":"doc['ts'].value"}}}}}`,
	} {
		if p := mustSearchPlanR63(t, tr3, saQ); p.HitsSQL == "" && p.AggsSQL == "" {
			t.Fatalf("empty plan for %s", saQ)
		}
	}
	for _, mv := range []any{nil, "s", 1, int64(2), uint64(3), math.NaN(), 1e19, 3.25, json.Number("9"), true} {
		_ = formatMissingScalar(mv)
	}
	_, _, _ = parseCIDRBounds("10.0.0.0/8")
	_, _, _ = parseIPv6CIDRHexBounds("fe80::/10")
	_, _, _ = parseIPv6CIDRHexBounds("10.0.0.0/8")

	// Top-level array `terms` (`background_filter`, `missing_bucket`, string concat script), `distance_feature` on `date_nanos`, and histogram/date_histogram validation branches.
	extraTail := []string{
		`{"query":{"bool":{"should":[{"distance_feature":{"field":"ts_ns","origin":"1704067200000000000","pivot":1000}},{"distance_feature":{"field":"ts_ns","origin":1704067200000000000,"pivot":1000.5}}]}},"aggs":{"t_arr_miss":{"significant_terms":{"field":"items.ts_ns","background_filter":{"term":{"flag":true}}}},"t_arr_mb":{"terms":{"field":"items.ts_ns","missing_bucket":true},"aggs":{"c":{"value_count":{"field":"num"}}}},"t_str_script":{"terms":{"script":{"inline":"{ return ('p_' + doc['ver'].value); };"}}},"rn_top":{"reverse_nested":{},"aggs":{"c":{"value_count":{"field":"num"}}}}}}`,
	}
	for _, et := range extraTail {
		if p := mustSearchPlanR63(t, tr3, et); p.HitsSQL == "" || p.AggsSQL == "" {
			t.Fatalf("empty plan for %s", et)
		}
	}
	for _, dfOrigin := range []any{float64(1704067200000000000), int64(1704067200000000000), int(1704067200)} {
		_ = tr3.compileDistanceFeature(&esast.DistanceFeatureQuery{Field: "ts_ns", Origin: dfOrigin, Pivot: dfOrigin}, true, nil)
	}
	for _, badAgg := range []string{
		`{"size":0,"aggs":{"b":{"histogram":{"field":"num","interval":10,"hard_bounds":{"min":"bad"}}}}}`,
		`{"size":0,"aggs":{"b":{"histogram":{"field":"num","interval":10,"hard_bounds":{"max":"bad"}}}}}`,
		`{"size":0,"aggs":{"b":{"histogram":{"field":"num","interval":10,"hard_bounds":{"min":50,"max":10}}}}}`,
		`{"size":0,"aggs":{"b":{"date_histogram":{"field":"ts","fixed_interval":"1d","time_zone":"Mars/Phobos"}}}}`,
		`{"size":0,"aggs":{"b":{"date_histogram":{"field":"ts","fixed_interval":"1d","extended_bounds":{"min":"not_a_date"}}}}}`,
		`{"size":0,"aggs":{"b":{"date_histogram":{"field":"ts","fixed_interval":"1d","extended_bounds":{"max":"not_a_date"}}}}}`,
		`{"size":0,"aggs":{"b":{"date_histogram":{"field":"ts","fixed_interval":"1d","hard_bounds":{"min":"2024-02-01T00:00:00Z","max":"2024-01-01T00:00:00Z"}}}}}`,
	} {
		req, err := unmarshalSearchReqR63(badAgg)
		if err != nil {
			continue
		}
		if _, err := tr3.BuildSearchPlan(req); err == nil {
			t.Fatalf("expected validation error for %s", badAgg)
		}
	}

	// `combined_fields`, `simple_query_string` sanitization, `lucene` RE2 quantifier rewrites, and Doris4 `projectionSafeTextMatchSQL`.
	tr2D4 := NewTranspiler(idx2, TranspilerOptions{ES8Compat: true, UseDoris4SearchFunc: true})
	for _, moreQ := range []string{
		`{"query":{"combined_fields":{"query":"quick brown fox","fields":["title^2","body"],"operator":"and"}}}`,
		`{"query":{"combined_fields":{"query":"quick brown fox","fields":["title","body"],"minimum_should_match":2}}}`,
		`{"query":{"combined_fields":{"query":"   ","fields":["title","body"],"zero_terms_query":"all"}}}`,
		`{"query":{"simple_query_string":{"query":"(quick | brown) + \"fox*\" - (lazy\"dog) ~2","fields":["title","body"],"flags":"ALL","default_operator":"and","minimum_should_match":"50%"}}}`,
		`{"query":{"regexp":{"tag":{"value":"[a-z]+(foo|bar){1,3}\\d?.*"}}} }`,
		`{"query":{"bool":{"should":[{"match":{"title":"quick fox"}},{"match_phrase":{"body":"lazy dog"}}],"minimum_should_match":1}}}`,
	} {
		if p := mustSearchPlanR63(t, tr2D4, moreQ); p.HitsSQL == "" {
			t.Fatalf("empty Doris4 HitsSQL for %s", moreQ)
		}
	}

	// Top-level metric agg on promoted array (`items.ts_ns` with `missing` + `script` inside `filter` agg) + `AllowExpensiveQueries=false`.
	_ = mustSearchPlanR63(t, tr3, `{"size":0,"aggs":{"flt":{"filter":{"term":{"flag":true}},"aggs":{"a":{"avg":{"field":"items.ts_ns","missing":0,"script":{"source":"_value * 2"}}}}}}}`)
	trNoExp := NewTranspiler(idx2, TranspilerOptions{ES8Compat: true, DisallowExpensiveQueries: true})
	for _, expErrQ := range []string{
		`{"query":{"nested":{"path":"items","query":{"term":{"items.sku":"a"}}}}}`,
		`{"query":{"script":{"script":"true"}}}`,
		`{"query":{"fuzzy":{"tag":{"value":"ab"}}}}`,
		`{"query":{"match":{"title":{"query":"ab","fuzziness":"AUTO"}}}}`,
		`{"query":{"match_bool_prefix":{"title":{"query":"ab","fuzziness":1}}}}`,
		`{"query":{"match_bool_prefix":{"title":"ab"}}}`,
		`{"query":{"multi_match":{"query":"ab","fields":["title"],"fuzziness":"AUTO"}}}`,
		`{"query":{"multi_match":{"query":"ab","fields":["title"],"type":"bool_prefix"}}}`,
		`{"query":{"prefix":{"tag":"a"}}}`,
		`{"query":{"wildcard":{"tag":"a*"}}}`,
		`{"query":{"regexp":{"tag":"a.*"}}}`,
		`{"query":{"range":{"tag":{"gte":"a"}}}}`,
	} {
		req, err := unmarshalSearchReqR63(expErrQ)
		if err != nil {
			continue
		}
		if _, err := trNoExp.BuildSearchPlan(req); err == nil {
			t.Fatalf("expected AllowExpensiveQueries=false error for %s", expErrQ)
		}
	}
}
