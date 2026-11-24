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

package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound64_F8_DDLStopwordsNoneAndAlterWidening(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"body": {"type": "text"},
			"mot": {"type": "match_only_text"},
			"en_body": {"type": "text", "analyzer": "english"},
			"stop_body": {"type": "text", "analyzer": "stop"},
			"tag": {"type": "keyword"}
		}
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	idx := CompileIndexSchema("es_db", "r64_ddl_sw", &spec)
	ddl := GenerateCreateTableDDL(idx)

	for _, wantSub := range []string{
		"INDEX `idx_doc_variant` (`_doc`) USING INVERTED PROPERTIES(\"parser\" = \"unicode\", \"support_phrase\" = \"true\", \"stopwords\" = \"none\")",
		"INDEX `idx_all_text` (`_all_text`) USING INVERTED PROPERTIES(\"parser\" = \"standard\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\", \"stopwords\" = \"none\")",
		"INDEX `idx_f__body` (`f__body`) USING INVERTED PROPERTIES(\"parser\" = \"standard\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\", \"stopwords\" = \"none\")",
		"INDEX `idx_f__mot` (`f__mot`) USING INVERTED PROPERTIES(\"parser\" = \"standard\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\", \"stopwords\" = \"none\")",
		"INDEX `idx_f__en_body` (`f__en_body`) USING INVERTED PROPERTIES(\"parser\" = \"english\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\")",
		"INDEX `idx_f__stop_body` (`f__stop_body`) USING INVERTED PROPERTIES(\"parser\" = \"standard\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\")",
	} {
		if !strings.Contains(ddl, wantSub) {
			t.Fatalf("expected DDL to contain %s, got:\n%s", wantSub, ddl)
		}
	}
	if strings.Contains(ddl, "idx_f__en_body` (`f__en_body`) USING INVERTED PROPERTIES(\"parser\" = \"english\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\", \"stopwords\" = \"none\")") {
		t.Fatalf("did not expect stopwords=none on english analyzer column:\n%s", ddl)
	}
	if strings.Contains(ddl, "idx_f__stop_body` (`f__stop_body`) USING INVERTED PROPERTIES(\"parser\" = \"standard\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\", \"stopwords\" = \"none\")") {
		t.Fatalf("did not expect stopwords=none on stop analyzer column:\n%s", ddl)
	}

	// Widening ALTER DDL from VARCHAR keyword to STRING text must drop old keyword index and recreate fulltext index with stopwords=none
	var oldSpec, newSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"dyn_msg":{"type":"keyword"}}}`), &oldSpec)
	_ = json.Unmarshal([]byte(`{"properties":{"dyn_msg":{"type":"text"}}}`), &newSpec)
	oldSchema := CompileIndexSchema("es_db", "r64_widen", &oldSpec)
	newSchema := CompileIndexSchema("es_db", "r64_widen", &newSpec)
	alterStmts := GenerateAlterTableDDL(oldSchema, newSchema)
	joined := strings.Join(alterStmts, "\n")
	for _, wantAlter := range []string{
		"DROP INDEX `idx_f__dyn_msg`",
		"MODIFY COLUMN `f__dyn_msg` STRING NULL",
		"ADD INDEX `idx_f__dyn_msg` (`f__dyn_msg`) USING INVERTED PROPERTIES(\"parser\" = \"standard\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\", \"stopwords\" = \"none\")",
	} {
		if !strings.Contains(joined, wantAlter) {
			t.Fatalf("expected ALTER DDL to contain %s, got:\n%s", wantAlter, joined)
		}
	}
}

func TestRound64_F8_ES8DynamicStrings_DenseVector50Strings_And_MetricsNoSubobjects(t *testing.T) {
	// 1. ES8Mode infers dynamic short strings as text + .keyword(ignore_above:256)
	baseSpec := &esast.MappingSpec{Dynamic: true}
	idx8 := CompileIndexSchema("es_db", "r64_dyn8", baseSpec)
	idx8.ES8Mode = true
	res := InferMappingFromSampleDocsForSchema(idx8, []json.RawMessage{json.RawMessage(`{"label":"checkout_step","tag":"fast"}`)})
	if res == nil {
		t.Fatalf("expected ES8 dynamic inference mapping, got nil")
	}
	lbl := res.Properties["label"]
	if lbl.Type != "text" || lbl.Fields["keyword"].Type != "keyword" || lbl.Fields["keyword"].IgnoreAbove != 256 {
		t.Fatalf("expected ES8 short string to infer text + .keyword(256), got %+v", lbl)
	}

	// Non-ES8 short string remains keyword unless long or text-like
	idx7 := CompileIndexSchema("es_db", "r64_dyn7", baseSpec)
	idx7.ES8Mode = false
	res7 := InferMappingFromSampleDocsForSchema(idx7, []json.RawMessage{json.RawMessage(`{"label":"checkout_step"}`)})
	if res7.Properties["label"].Type != "keyword" {
		t.Fatalf("expected non-ES8 short string to infer keyword, got %+v", res7.Properties["label"])
	}

	// 2. 50-element dynamic string array -> text + .keyword (`60_dense_vector_dynamic_mapping.yml`)
	elems := make([]string, 50)
	for i := range elems {
		elems[i] = fmt.Sprintf("\"s%d\"", i)
	}
	doc50 := json.RawMessage(fmt.Sprintf(`{"arr":[%s]}`, strings.Join(elems, ",")))
	for _, es8 := range []bool{false, true} {
		idxArr := CompileIndexSchema("es_db", "r64_arr50", &esast.MappingSpec{Dynamic: true})
		idxArr.ES8Mode = es8
		r50 := InferMappingFromSampleDocsForSchema(idxArr, []json.RawMessage{doc50})
		arrProp := r50.Properties["arr"]
		if arrProp.Type != "text" || arrProp.Fields["keyword"].Type != "keyword" {
			t.Fatalf("es8=%v: expected 50-elem string array mapped as text+.keyword, got %+v", es8, arrProp)
		}
	}

	// 3. `91_metrics_no_subobjects.yml`: subobjects: false + dynamic_templates keeps declared dotted keyword properties
	var metricsSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"subobjects": false,
		"dynamic_templates": [
			{"strings_as_keywords": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}
		],
		"properties": {
			"host.name": {"type": "keyword"}
		}
	}`), &metricsSpec); err != nil {
		t.Fatal(err)
	}
	metricsIdx := CompileIndexSchema("es_db", "r64_metrics", &metricsSpec)
	metricsIdx.ES8Mode = true
	if b, ok := metricsIdx.Fields["host.name"]; !ok || b.ESType != "keyword" {
		t.Fatalf("expected declared dotted host.name keyword binding, got %+v (ok=%v)", b, ok)
	}
	rMetrics := InferMappingFromSampleDocsForSchema(metricsIdx, []json.RawMessage{json.RawMessage(`{"host.name":"web-01","host.os":"linux"}`)})
	if rMetrics.Properties["host.name"].Type != "keyword" {
		t.Fatalf("expected existing dotted host.name to stay keyword, got %+v", rMetrics.Properties["host.name"])
	}
	if rMetrics.Properties["host.os"].Type != "keyword" {
		t.Fatalf("expected dynamic dotted host.os matched by dynamic_template keyword, got %+v", rMetrics.Properties["host.os"])
	}
}

func TestRound64_F2_F14_F18_WildcardNullValue_RuntimeGeoShape_SelfCopyTo_CustomNormalizer(t *testing.T) {
	// 1. wildcard + null_value, self copy_to, runtime geo_shape, custom pattern_replace normalizer (`40_token_filters.yml`)
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"runtime": {
			"rt_shape": {"type": "geo_shape"}
		},
		"properties": {
			"wc": {"type": "wildcard", "null_value": "MISSING_WC"},
			"self_txt": {"type": "text", "copy_to": "self_txt"},
			"norm_code": {"type": "keyword", "normalizer": "strip_zeros"},
			"nested_items": {
				"type": "nested",
				"properties": {
					"code": {"type": "keyword", "normalizer": "strip_zeros"},
					"lbl": {"type": "text", "copy_to": "lbl"}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&spec); err != nil {
		t.Fatalf("ValidateMappingSpec failed: %v", err)
	}

	settings := map[string]any{
		"index": map[string]any{
			"analysis": map[string]any{
				"filter": map[string]any{
					"leading_zeros": map[string]any{
						"type":        "pattern_replace",
						"pattern":     "^0+",
						"replacement": "",
						"all":         true,
					},
				},
				"normalizer": map[string]any{
					"strip_zeros": map[string]any{
						"type":   "custom",
						"filter": []any{"leading_zeros", "lowercase"},
					},
				},
			},
		},
	}
	idx := CompileIndexSchemaWithSettings("es_db", "r64_f2_f18", &spec, settings)
	if idx.Fields["norm_code"].NormalizerName != "strip_zeros" {
		t.Fatalf("expected NormalizerName=strip_zeros, got %q", idx.Fields["norm_code"].NormalizerName)
	}

	shredBytes, err := ShredDocument(idx, "1", 1, false, []byte(`{
		"wc": null,
		"self_txt": "hello world",
		"norm_code": "000000111ABC",
		"nested_items": [{"code": "00042XYZ", "lbl": "item one"}]
	}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredBytes, &row); err != nil {
		t.Fatal(err)
	}
	if row["f__wc"] != "MISSING_WC" {
		t.Fatalf("expected wildcard null_value 'MISSING_WC', got %#v", row["f__wc"])
	}
	if row["f__self_txt"] != "hello world" {
		t.Fatalf("expected self copy_to without duplicating 'hello world', got %#v", row["f__self_txt"])
	}
	if row["f__norm_code"] != "111abc" {
		t.Fatalf("expected custom pattern_replace+lowercase normalizer -> '111abc', got %#v", row["f__norm_code"])
	}
	nestedArr, okN := row["n__nested_items"].([]any)
	if !okN || len(nestedArr) != 1 || !strings.Contains(fmt.Sprintf("%v", nestedArr[0]), `"code":"42xyz"`) {
		t.Fatalf("expected nested custom normalizer code='42xyz', got %#v", row["n__nested_items"])
	}
}

func TestRound64_F11_F15_F16_Dates_LocaleFR_DateNanosError_GeoPointNull_InnerHitsNoSource(t *testing.T) {
	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	// 1. `"2005||/y"` guard in Millis & Nanos + compound format
	loMs, okLo := ParseESDateBoundToEpochMillis("2005||/y", now, false)
	hiMs, okHi := ParseESDateBoundToEpochMillis("2005||/y", now, true)
	wantLo := time.Date(2005, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	wantHi := time.Date(2005, 12, 31, 23, 59, 59, 999_000_000, time.UTC).UnixMilli()
	if !okLo || !okHi || loMs != wantLo || hiMs != wantHi {
		t.Fatalf("2005||/y millis mismatch: got (%d,%v)-(%d,%v), want %d-%d", loMs, okLo, hiMs, okHi, wantLo, wantHi)
	}
	loC, okLC := ParseESDateBoundWithFormatToEpochMillis("2005||/y", "strict_date_optional_time_nanos||epoch_millis", now, false)
	hiC, okHC := ParseESDateBoundWithFormatToEpochMillis("2005||/y", "strict_date_optional_time_nanos||epoch_millis", now, true)
	if !okLC || !okHC || loC != wantLo || hiC != wantHi {
		t.Fatalf("compound 2005||/y mismatch: (%d,%v)-(%d,%v)", loC, okLC, hiC, okHC)
	}
	loNs, okLN := ParseESDateBoundToEpochNanos("2005||/y", now, false)
	hiNs, okHN := ParseESDateBoundToEpochNanos("2005||/y", now, true)
	if !okLN || !okHN || loNs != time.Date(2005, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano() || hiNs != time.Date(2005, 12, 31, 23, 59, 59, 999_999_999, time.UTC).UnixNano() {
		t.Fatalf("2005||/y nanos mismatch: (%d,%v)-(%d,%v)", loNs, okLN, hiNs, okHN)
	}

	// 2. `strict_date_time` without millis + `strict_date_time||strict_date`
	if _, ok := ParseESDateWithFormatToEpochMillis("2021-05-01T00:00:00Z", "strict_date_time", now); !ok {
		t.Fatalf("expected strict_date_time to accept 2021-05-01T00:00:00Z")
	}
	if _, ok := ParseESDateWithFormatToEpochMillis("2021-05-01", "strict_date_time", now); ok {
		t.Fatalf("expected strict_date_time alone to reject date-only 2021-05-01")
	}
	if ms, ok := ParseESDateWithFormatToEpochMillis("2021-05-01", "strict_date_time||strict_date", now); !ok || ms != time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC).UnixMilli() {
		t.Fatalf("expected strict_date_time||strict_date to accept 2021-05-01, got (%d,%v)", ms, ok)
	}
	if _, ok := ParseESDateWithFormatToEpochMillis("2021-05-01T00:00:00.123Z", "strict_date_time_no_millis", now); ok {
		t.Fatalf("expected strict_date_time_no_millis to reject fractional millis")
	}

	// 3. French locale `180_locale_dependent_mapping.yml`
	var frSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"date_field": {"type": "date", "format": "E, d MMM yyyy HH:mm:ss Z", "locale": "fr"}
		}
	}`), &frSpec); err != nil {
		t.Fatal(err)
	}
	if frSpec.Properties["date_field"].Locale != "fr" {
		t.Fatalf("expected FieldProperty.Locale='fr', got %q", frSpec.Properties["date_field"].Locale)
	}
	frIdx := CompileIndexSchema("es_db", "r64_fr", &frSpec)
	frRowBytes, err := ShredDocument(frIdx, "1", 1, false, []byte(`{"date_field":"mer., 6 déc. 2000 02:55:00 -0800"}`))
	if err != nil {
		t.Fatalf("expected French locale date to shred cleanly, got: %v", err)
	}
	var frRow map[string]any
	_ = json.Unmarshal(frRowBytes, &frRow)
	wantFR := float64(time.Date(2000, 12, 6, 10, 55, 0, 0, time.UTC).UnixMilli())
	if frRow["f__date_field"] != wantFR {
		t.Fatalf("expected French parsed ms %.0f, got %v", wantFR, frRow["f__date_field"])
	}
	for _, frExpr := range []string{
		"jeu., 7 déc. 2000 02:55:00 -0800",
		"mar., 5 déc. 2000 02:55:00 -0800",
		"ven., 8 déc. 2000 00:00:00 -0800",
	} {
		if _, ok := ParseESDateBoundWithFormatAndLocaleToEpochMillis(frExpr, "E, d MMM yyyy HH:mm:ss Z", "fr", now, false); !ok {
			t.Fatalf("failed parsing French date %q", frExpr)
		}
	}

	// 4. `date_nanos` structured error (`80_date_nanos.yml`)
	var dnSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"ts":{"type":"date_nanos"}}}`), &dnSpec)
	dnIdx := CompileIndexSchema("es_db", "r64_dn", &dnSpec)
	_, errPre := ShredDocument(dnIdx, "1", 1, false, []byte(`{"ts":"1969-10-28T12:12:12.123456789Z"}`))
	var spePre *StructuredParseError
	if !errors.As(errPre, &spePre) || spePre.ErrType != "document_parsing_exception" ||
		spePre.CausedByReason != "date[1969-10-28T12:12:12.123456789Z] is before the epoch in 1970 and cannot be stored in nanosecond resolution" {
		t.Fatalf("unexpected pre-1970 date_nanos error: %#v (raw: %v)", spePre, errPre)
	}
	_, errPost := ShredDocument(dnIdx, "2", 1, false, []byte(`{"ts":"2263-10-29T12:12:12.123456789Z"}`))
	var spePost *StructuredParseError
	if !errors.As(errPost, &spePost) ||
		spePost.CausedByReason != "date[2263-10-29T12:12:12.123456789Z] is after 2262-04-11T23:47:16.854775807 and cannot be stored in nanosecond resolution" {
		t.Fatalf("unexpected post-2262 date_nanos error: %#v (raw: %v)", spePost, errPost)
	}

	// 5. `geo_point` null_value on `null` and `[null, ...]` (`90_geo_point.yml`)
	var gpSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"point":{"type":"geo_point","null_value":{"lat":28.41951122705923,"lon":-81.58118930548268}}}}`), &gpSpec)
	gpIdx := CompileIndexSchema("es_db", "r64_gp", &gpSpec)
	gpNullBytes, err := ShredDocument(gpIdx, "1", 1, false, []byte(`{"point":null}`))
	if err != nil {
		t.Fatal(err)
	}
	var gpNullRow map[string]any
	_ = json.Unmarshal(gpNullBytes, &gpNullRow)
	if gpNullRow["f__point"] != "28.41951122705923,-81.58118930548268" {
		t.Fatalf("expected scalar null geo_point substituted, got %v", gpNullRow["f__point"])
	}
	gpArrBytes, err := ShredDocument(gpIdx, "2", 1, false, []byte(`{"point":[null,{"lat":-54.48979082798907,"lon":-37.07576688239972}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var gpArrRow map[string]any
	_ = json.Unmarshal(gpArrBytes, &gpArrRow)
	if gpArrRow["f__point"] != "28.41951122705923,-81.58118930548268" {
		t.Fatalf("expected [null, p2] column to get null_value first, got %v", gpArrRow["f__point"])
	}
	docMap, _ := gpArrRow["_doc"].(map[string]any)
	ptsInDoc, _ := docMap["point"].([]any)
	if len(ptsInDoc) != 2 {
		t.Fatalf("expected both substituted null_value and second point in _doc, got %#v", gpArrRow["_doc"])
	}
	if _, ok := ptsInDoc[0].(map[string]any); !ok {
		t.Fatalf("expected first element in _doc.point replaced with null_value map, got %#v", ptsInDoc[0])
	}

	// 6. `_source.enabled: false` preserves nested & sub-nested structure in `_doc` (`search.inner_hits/10_basic.yml`)
	var ihSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"_source": {"enabled": false},
		"properties": {
			"comments": {
				"type": "nested",
				"properties": {
					"author": {"type": "keyword"},
					"replies": {
						"type": "nested",
						"properties": {"body": {"type": "text"}}
					}
				}
			}
		}
	}`), &ihSpec)
	ihIdx := CompileIndexSchema("es_db", "r64_ih", &ihSpec)
	ihBytes, err := ShredDocument(ihIdx, "1", 1, false, []byte(`{"comments":[{"author":"alice","replies":[{"body":"hi"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var ihRow map[string]any
	_ = json.Unmarshal(ihBytes, &ihRow)
	if ihRow["_source"] != "" {
		t.Fatalf("expected empty _source when disabled, got %#v", ihRow["_source"])
	}
	ihDoc, _ := ihRow["_doc"].(map[string]any)
	comments, _ := ihDoc["comments"].([]any)
	if len(comments) != 1 || fmt.Sprintf("%v", comments[0]) == "" {
		t.Fatalf("expected nested structure preserved in _doc when _source disabled, got %#v", ihRow["_doc"])
	}
	if _, ok := ihRow["n__comments"].([]any); !ok {
		t.Fatalf("expected correlated nested column populated, got %#v", ihRow["n__comments"])
	}
	if _, ok := ihRow["n__comments__replies"].([]any); !ok {
		t.Fatalf("expected correlated sub-nested column populated, got %#v", ihRow["n__comments__replies"])
	}
}

func TestRound64_P1_9_And_F5_SyntheticSourceGaps(t *testing.T) {
	// P1-9: `aggregate_metric_double` value_count >= 2^63 must reject before int64(v) overflow
	var amdSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"m": {"type": "aggregate_metric_double", "metrics": ["min","max","sum","value_count"], "default_metric": "min"}
		}
	}`), &amdSpec)
	amdIdx := CompileIndexSchema("es_db", "r64_amd", &amdSpec)
	for _, huge := range []string{
		`{"m":{"min":1,"max":2,"sum":3,"value_count":9223372036854775808}}`,
		`{"m":{"min":1,"max":2,"sum":3,"value_count":1e20}}`,
	} {
		if _, err := ShredDocument(amdIdx, "1", 1, false, []byte(huge)); err == nil {
			t.Fatalf("expected value_count >= 2^63 error for %s", huge)
		}
	}

	// F5-1: ValidateMappingSpec rejects doc_values: false on synthetic-mode doc-values types without store/subfield,
	// and rejects synthetic_source_keep on match_only_text
	for _, badSynth := range []string{
		`{"_source":{"mode":"synthetic"},"properties":{"b":{"type":"boolean","doc_values":false}}}`,
		`{"_source":{"mode":"synthetic"},"properties":{"f":{"type":"ip","doc_values":false}}}`,
		`{"_source":{"mode":"synthetic"},"properties":{"m":{"type":"match_only_text","synthetic_source_keep":"all"}}}`,
		`{"_source":{"mode":"synthetic"},"properties":{"r":{"type":"double_range","doc_values":false}}}`,
	} {
		var sp esast.MappingSpec
		if err := json.Unmarshal([]byte(badSynth), &sp); err != nil {
			t.Fatal(err)
		}
		if err := ValidateMappingSpec(&sp); err == nil {
			t.Fatalf("expected synthetic source validation error for %s", badSynth)
		}
	}

	// F5-2: Synthetic source geo_point normalized to {lat,lon}, ignore_malformed object rejected cleanly,
	// scalar dedup & malformed ordering, rank_features & sparse_vector, dynamic:false object array preservation, and custom normalizer
	var synSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"gp": {"type": "geo_point", "ignore_malformed": true},
			"gs": {"type": "geo_shape", "ignore_malformed": true},
			"nums": {"type": "integer", "ignore_malformed": true},
			"ip_addr": {"type": "ip", "ignore_malformed": true},
			"dyn_off_arr": {"type": "object", "dynamic": false},
			"rf": {"type": "rank_features"},
			"sv": {"type": "sparse_vector"},
			"ncode": {"type": "keyword", "normalizer": "strip_zeros"}
		}
	}`), &synSpec); err != nil {
		t.Fatal(err)
	}
	synIdx := CompileIndexSchemaWithSettings("es_db", "r64_syn_f5", &synSpec, map[string]any{
		"index": map[string]any{
			"analysis": map[string]any{
				"filter": map[string]any{
					"lz": map[string]any{"type": "pattern_replace", "pattern": "^0+", "replacement": ""},
				},
				"normalizer": map[string]any{
					"strip_zeros": map[string]any{"type": "custom", "filter": []any{"lz", "lowercase"}},
				},
			},
		},
	})

	// ignore_malformed does NOT allow an object on a scalar/geo field!
	if _, err := ShredDocument(synIdx, "bad_obj", 1, false, []byte(`{"nums":{"unexpected":1}}`)); err == nil {
		t.Fatalf("expected mapper_parsing_exception when indexing object into scalar ignore_malformed field")
	}
	// rank_features weight <= 0 rejected cleanly
	if _, err := ShredDocument(synIdx, "bad_rf", 1, false, []byte(`{"rf":{"cat2":0}}`)); err == nil {
		t.Fatalf("expected mapper_parsing_exception for rank_features weight <= 0")
	}

	rawDoc := []byte(`{
		"gp": ["40.7,-74.0", [10.0, 20.0], "bad_geo", {"type":"Point","coordinates":[5.0,6.0]}],
		"gs": "bad_shape",
		"nums": [30, 10, "not_num", 10],
		"ip_addr": ["10.0.0.2", "bad_ip", "10.0.0.1", "10.0.0.2"],
		"dyn_off_arr": [{"b": 2}, {"a": 1}],
		"rf": {"cat1": 1.5, "cat2": 2},
		"sv": {},
		"ncode": "00099XYZ"
	}`)
	shredded, err := ShredDocument(synIdx, "1", 1, false, rawDoc)
	if err != nil {
		t.Fatalf("ShredDocument synthetic F5 failed: %v", err)
	}
	var row map[string]any
	_ = json.Unmarshal(shredded, &row)
	var got map[string]any
	dec := json.NewDecoder(bytes.NewReader([]byte(row["_source"].(string))))
	dec.UseNumber()
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got["nums"], []any{json.Number("10"), json.Number("10"), json.Number("30"), "not_num"}) {
		t.Fatalf("expected sorted SortedNumericDocValues ints preserving duplicates followed by malformed string, got %#v", got["nums"])
	}
	if !reflect.DeepEqual(got["ip_addr"], []any{"10.0.0.1", "10.0.0.2", "bad_ip"}) {
		t.Fatalf("expected sorted deduplicated IPs followed by malformed IP, got %#v", got["ip_addr"])
	}
	if got["gs"] != "bad_shape" {
		t.Fatalf("expected malformed geo_shape kept with ignore_malformed, got %#v", got["gs"])
	}
	if got["ncode"] != "99xyz" {
		t.Fatalf("expected synthetic source custom normalizer ncode='99xyz', got %#v", got["ncode"])
	}
	gpArr, _ := got["gp"].([]any)
	if len(gpArr) != 4 || gpArr[3] != "bad_geo" {
		t.Fatalf("expected 3 sorted {lat,lon} points + 'bad_geo' at end, got %#v", got["gp"])
	}
	for i := 0; i < 3; i++ {
		m, okM := gpArr[i].(map[string]any)
		if !okM {
			t.Fatalf("expected geo_point[%d] map{lat,lon}, got %#v", i, gpArr[i])
		}
		if _, hasType := m["type"]; hasType {
			t.Fatalf("expected geo_point normalized to {lat,lon}, not GeoJSON: %#v", m)
		}
	}
	dynArr, okDA := got["dyn_off_arr"].([]any)
	if !okDA || len(dynArr) != 2 {
		t.Fatalf("expected dynamic:false object array order preserved, got %#v", got["dyn_off_arr"])
	}
	if _, hasSV := got["sv"]; !hasSV {
		t.Fatalf("expected empty sparse_vector preserved in synthetic source, got %#v", got)
	}
	if math.IsNaN(0) {
		t.Fatal("unreachable")
	}
}
