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
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func r67TSchBoolPtr(b bool) *bool { return &b }

func r67TSchCompileMapping(t *testing.T, table, mappingJSON string) *IndexSchema {
	t.Helper()
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(mappingJSON), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	return CompileIndexSchema("es_db", table, &spec)
}

func r67TSchShredMap(t *testing.T, s *IndexSchema, id string, rawJSON string, now time.Time) (map[string]any, error) {
	t.Helper()
	b, err := ShredDocumentWithNow(s, id, 1, false, []byte(rawJSON), now)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if uErr := json.Unmarshal(b, &out); uErr != nil {
		t.Fatalf("unmarshal shredded row failed: %v", uErr)
	}
	return out, nil
}

func TestRound67TopUpSchema_ShredderScalarAndArrayPaths(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// 1. rank_feature array with ignore_malformed + aggregate_metric_double extra ignored + constant_keyword adoption mismatch
	idx1 := r67TSchCompileMapping(t, "r67t_shred1", `{
		"properties": {
			"rf": {"type": "rank_feature", "ignore_malformed": true},
			"agg_m": {"type": "aggregate_metric_double", "metrics": ["min", "max"], "default_metric": "max", "ignore_malformed": true},
			"ck_adopt": {"type": "constant_keyword"},
			"ck_adopt_ign": {"type": "constant_keyword", "ignore_malformed": true},
			"ck_arr": {"type": "constant_keyword", "value": "ok", "ignore_malformed": true},
			"comp": {"type": "completion", "ignore_above": 5, "null_value": "fallback_long", "ignore_malformed": true},
			"comp_strict": {"type": "completion"},
			"tc": {"type": "token_count", "ignore_malformed": true},
			"tc_strict": {"type": "token_count"},
			"kw_ign": {"type": "keyword", "ignore_above": 4, "ignore_malformed": true, "null_value": "TOOLONG_NV"},
			"kw_nv": {"type": "keyword", "ignore_above": 6, "ignore_malformed": true, "null_value": "OKNV"}
		}
	}`)
	if err := idx1.SetAnalysisSettings(map[string]any{
		"analysis": map[string]any{
			"normalizer": map[string]any{
				"lc": map[string]any{"type": "custom", "filter": []any{"lowercase"}},
			},
		},
	}); err != nil {
		t.Fatalf("SetAnalysisSettings failed: %v", err)
	}

	// Valid rank_feature array ignored, agg_m extra ignored -> modified, ck_adopt conflicting array -> error
	if _, err := r67TSchShredMap(t, idx1, "1", `{"ck_adopt":["a","b"]}`, now); err == nil {
		t.Fatalf("expected constant_keyword adoption conflict error")
	}
	// Invalid completion weight without ignore_malformed -> error
	if _, err := r67TSchShredMap(t, idx1, "2", `{"comp_strict":{"input":"hi","weight":-1}}`, now); err == nil {
		t.Fatalf("expected strict completion weight error")
	}
	// Invalid token_count without ignore_malformed -> error
	if _, err := r67TSchShredMap(t, idx1, "3", `{"tc_strict":true}`, now); err == nil {
		t.Fatalf("expected strict token_count parse error")
	}

	row, err := r67TSchShredMap(t, idx1, "4", `{
		"rf": [1.0, 2.0],
		"agg_m": {"min": 1.0, "max": 5.0, "extra": 99},
		"ck_adopt_ign": ["first", "second"],
		"ck_arr": {"bad": 1},
		"comp": {"input": ["hi", "toolongvalue"]},
		"tc": [true, "one two", false],
		"kw_ign": {"bad": 1},
		"kw_nv": null
	}`, now)
	if err != nil {
		t.Fatalf("shred idx1 doc 4 failed: %v", err)
	}
	if row["f__ck_adopt_ign"] != "first" {
		t.Fatalf("expected adopted constant_keyword 'first', got %v", row["f__ck_adopt_ign"])
	}
	if row["f__tc"] != float64(2) {
		t.Fatalf("expected token_count 2 after ignoring bools, got %v (%T)", row["f__tc"], row["f__tc"])
	}
	if row["f__comp"] != "hi" {
		t.Fatalf("expected completion 'hi' after ignore_above filtering, got %v", row["f__comp"])
	}
	if row["f__kw_nv"] != "OKNV" {
		t.Fatalf("expected null_value OKNV, got %v", row["f__kw_nv"])
	}

	// Completion scalar with explicit null and null_value > ignore_above, plus all-malformed token_count & ck_arr
	row2, err := r67TSchShredMap(t, idx1, "5", `{
		"comp": null,
		"tc": [true],
		"kw_ign": null,
		"ck_adopt_ign": {"bad": 1}
	}`, now)
	if err != nil {
		t.Fatalf("shred idx1 doc 5 failed: %v", err)
	}
	if _, hasComp := row2["f__comp"]; hasComp {
		t.Fatalf("expected completion null_value exceeding ignore_above to be omitted, got %v", row2["f__comp"])
	}
	if _, hasKW := row2["f__kw_ign"]; hasKW {
		t.Fatalf("expected kw_ign null_value exceeding ignore_above to be omitted, got %v", row2["f__kw_ign"])
	}

	// Direct custom IndexSchema to hit StoragePromotedScalar extractScalarValue fallback (L633-668),
	// StoragePromotedArray completion + hasObjAtPath, nested dense_vector error/AutoDims, and NestedRoots fallback (L1224-1242).
	customSch := &IndexSchema{
		DorisDB:    "es_db",
		DorisTable: "r67t_custom",
		OrderedFields: []FieldBinding{
			{
				ESFieldPath:    "meta",
				SourceJSONPath: []string{"meta"},
				Kind:           StoragePromotedScalar,
				ColumnName:     "f__meta",
				DorisType:      DorisVarchar,
				ESType:         "keyword",
				IgnoreAbove:    5,
			},
			{
				ESFieldPath:    "meta.sub",
				SourceJSONPath: []string{"meta", "sub"},
				Kind:           StoragePromotedScalar,
				ColumnName:     "f__meta__sub",
				DorisType:      DorisVarchar,
				ESType:         "keyword",
			},
			{
				ESFieldPath:     "dn_sub",
				SourceJSONPath:  []string{"dn_sub"},
				Kind:            StoragePromotedScalar,
				ColumnName:      "f__dn_sub",
				DorisType:       DorisBigInt,
				ESType:          "date_nanos",
				IgnoreMalformed: r67TSchBoolPtr(true),
			},
			{
				ESFieldPath:    "dn_sub.x",
				SourceJSONPath: []string{"dn_sub", "x"},
				Kind:           StoragePromotedScalar,
				ColumnName:     "f__dn_sub__x",
				DorisType:      DorisVarchar,
				ESType:         "keyword",
			},
			{
				ESFieldPath:    "dn_sub_strict",
				SourceJSONPath: []string{"dn_sub_strict"},
				Kind:           StoragePromotedScalar,
				ColumnName:     "f__dn_sub_strict",
				DorisType:      DorisBigInt,
				ESType:         "date_nanos",
			},
			{
				ESFieldPath:    "dn_sub_strict.x",
				SourceJSONPath: []string{"dn_sub_strict", "x"},
				Kind:           StoragePromotedScalar,
				ColumnName:     "f__dn_sub_strict__x",
				DorisType:      DorisVarchar,
				ESType:         "keyword",
			},
			{
				ESFieldPath:    "blank_num",
				SourceJSONPath: []string{"blank_num"},
				Kind:           StoragePromotedScalar,
				ColumnName:     "f__blank_num",
				DorisType:      DorisBigInt,
				ESType:         "long",
				NullValue:      int64(7),
			},
			{
				ESFieldPath:     "arr_comp",
				SourceJSONPath:  []string{"arr_comp"},
				Kind:            StoragePromotedArray,
				ColumnName:      "f__arr_comp",
				DorisType:       DorisString,
				ESType:          "completion",
				IgnoreMalformed: r67TSchBoolPtr(true),
			},
			{
				ESFieldPath:    "arr_comp_strict",
				SourceJSONPath: []string{"arr_comp_strict"},
				Kind:           StoragePromotedArray,
				ColumnName:     "f__arr_comp_strict",
				DorisType:      DorisString,
				ESType:         "completion",
			},
			{
				ESFieldPath:     "arr_kw",
				SourceJSONPath:  []string{"arr_kw"},
				Kind:            StoragePromotedArray,
				ColumnName:      "f__arr_kw",
				DorisType:       DorisString,
				ESType:          "keyword",
				IgnoreAbove:     4,
				IgnoreMalformed: r67TSchBoolPtr(true),
			},
			{
				ESFieldPath:      "ck_arr_prim",
				SourceJSONPath:   []string{"ck_arr_prim"},
				Kind:             StoragePromotedArray,
				ColumnName:       "f__ck_arr_prim",
				DorisType:        DorisString,
				ESType:           "constant_keyword",
				ConstantValue:    "only",
				HasConstantValue: true,
				IgnoreMalformed:  r67TSchBoolPtr(true),
			},
			{
				ESFieldPath:      "items.kw",
				SourceJSONPath:   []string{"items", "kw"},
				Kind:             StorageNestedSubfield,
				ColumnName:       "n__items__kw",
				DorisType:        DorisString,
				ESType:           "keyword",
				NestedPath:       "items",
				RelativeJSONPath: []string{"kw"},
				IgnoreMalformed:  r67TSchBoolPtr(true),
			},
			{
				ESFieldPath:        "items.vec",
				SourceJSONPath:     []string{"items", "vec"},
				Kind:               StorageNestedSubfield,
				ColumnName:         "n__items__vec",
				DorisType:          DorisFloatArray,
				ESType:             "dense_vector",
				NestedPath:         "items",
				RelativeJSONPath:   []string{"vec"},
				AutoDims:           true,
				VectorElementType:  "float",
				VectorIndexOptions: map[string]any{"type": "int4_hnsw"},
			},
			{
				ESFieldPath:      "items.vec_ign",
				SourceJSONPath:   []string{"items", "vec_ign"},
				Kind:             StorageNestedSubfield,
				ColumnName:       "n__items__vec_ign",
				DorisType:        DorisFloatArray,
				ESType:           "dense_vector",
				NestedPath:       "items",
				RelativeJSONPath: []string{"vec_ign"},
				VectorDims:       2,
				IgnoreMalformed:  r67TSchBoolPtr(true),
			},
			{
				ESFieldPath:        "root_vec_auto",
				SourceJSONPath:     []string{"root_vec_auto"},
				Kind:               StoragePromotedVector,
				ColumnName:         "f__root_vec_auto",
				DorisType:          DorisFloatArray,
				ESType:             "dense_vector",
				AutoDims:           true,
				VectorElementType:  "float",
				VectorIndexOptions: map[string]any{"type": "int4_hnsw"},
			},
			{
				ESFieldPath:     "root_vec_ign",
				SourceJSONPath:  []string{"root_vec_ign"},
				Kind:            StoragePromotedVector,
				ColumnName:      "f__root_vec_ign",
				DorisType:       DorisFloatArray,
				ESType:          "dense_vector",
				VectorDims:      2,
				IgnoreMalformed: r67TSchBoolPtr(true),
			},
		},
		NestedRoots: map[string]string{
			"items":     "n__items",
			"items.sub": "n__items__sub",
		},
	}
	customSch.Fields = make(map[string]FieldBinding, len(customSch.OrderedFields))
	for _, b := range customSch.OrderedFields {
		customSch.Fields[b.ESFieldPath] = b
	}

	cRow, err := r67TSchShredMap(t, customSch, "c1", `{
		"meta": {"name": "toolong_name", "sub": "ok"},
		"dn_sub": {"name": "bad", "x": "ok"},
		"blank_num": "   ",
		"arr_comp": {"input": "ok", "weight": -5},
		"arr_kw": [{"bad": 1}, "hi", "toolong"],
		"ck_arr_prim": [{"bad": 1}, "only"],
		"root_vec_ign": [1.0],
		"items": [
			{"kw": [{"bad": 1}, "v1"], "vec_ign": [1.0], "sub": [{"x": 1}]}
		]
	}`, now)
	if err != nil {
		t.Fatalf("customSch shred c1 failed: %v", err)
	}
	if cRow["f__ck_arr_prim"] == nil {
		t.Fatalf("expected ck_arr_prim populated with valid slice")
	}
	if cRow["n__items"] == nil || cRow["n__items__sub"] == nil {
		t.Fatalf("expected NestedRoots fallback columns populated, got %+v", cRow)
	}

	// Hit extractScalarValue -> date_nanos parse error & out-of-range error + strict completion error + AutoDims bit mod-8 error
	if _, err := r67TSchShredMap(t, customSch, "c2", `{"dn_sub_strict": {"name": "not-a-date", "x": "ok"}}`, now); err == nil {
		t.Fatalf("expected date_nanos parse error from extractScalarValue")
	}
	if _, err := r67TSchShredMap(t, customSch, "c2b", `{"dn_sub_strict": {"name": "-5", "x": "ok"}}`, now); err == nil {
		t.Fatalf("expected date_nanos out-of-range error from extractScalarValue")
	}
	if _, err := r67TSchShredMap(t, customSch, "c3", `{"arr_comp_strict": {"input": "x", "weight": -1}}`, now); err == nil {
		t.Fatalf("expected strict array completion error")
	}
	if _, err := r67TSchShredMap(t, customSch, "c4", `{"items": [{"vec": [1, 0, 1]}]}`, now); err == nil {
		t.Fatalf("expected nested bit AutoDims mod-8 validation error")
	}
	if _, err := r67TSchShredMap(t, customSch, "c5", `{"root_vec_auto": [1, 0, 1]}`, now); err == nil {
		t.Fatalf("expected root bit AutoDims mod-8 validation error")
	}
	if _, err := r67TSchShredMap(t, customSch, "c6", `{"items": [{"kw": {"bad": 1}}]}`, now); err != nil {
		t.Fatalf("expected nested kw ignore_malformed to succeed: %v", err)
	}

	// CopyTo inside ShredDocument: nested relative copy_to, alias copy_to target, enabled:false copy_to target,
	// typed non-string copy_to target (ignore_above, blank, ignore_malformed, parse error), and KeywordCompanion copy_to target.
	copySch := r67TSchCompileMapping(t, "r67t_copyto", `{
		"properties": {
			"src_txt": {"type": "keyword", "copy_to": ["tgt_int", "tgt_int_ign", "tgt_alias", "tgt_disabled", "tgt_kw_txt"]},
			"src_blank": {"type": "keyword", "copy_to": ["tgt_int"]},
			"tgt_int": {"type": "integer"},
			"tgt_int_ign": {"type": "integer", "ignore_malformed": true, "ignore_above": 6},
			"tgt_real": {"type": "text", "fields": {"keyword": {"type": "keyword", "normalizer": "lc", "ignore_above": 5}}},
			"tgt_alias": {"type": "alias", "path": "tgt_real"},
			"tgt_disabled": {"type": "object", "enabled": false},
			"tgt_kw_txt": {"type": "text", "fields": {"keyword": {"type": "keyword", "normalizer": "lc", "ignore_above": 5}}},
			"items": {
				"type": "nested",
				"properties": {
					"src": {"type": "keyword", "copy_to": ["dst"]},
					"dst": {"type": "keyword"}
				}
			}
		}
	}`)
	if err := copySch.SetAnalysisSettings(map[string]any{
		"analysis": map[string]any{
			"normalizer": map[string]any{
				"lc": map[string]any{"type": "custom", "filter": []any{"lowercase"}},
			},
		},
	}); err != nil {
		t.Fatalf("copySch SetAnalysisSettings failed: %v", err)
	}
	// Make tgt_kw_txt and tgt_real scalar so keyword companion scalar path is hit
	if b, ok := copySch.Fields["tgt_kw_txt.keyword"]; ok {
		b.Kind = StoragePromotedScalar
		b.DorisType = DorisVarchar
		copySch.Fields["tgt_kw_txt.keyword"] = b
	}
	if b, ok := copySch.Fields["tgt_kw_txt"]; ok {
		b.Kind = StoragePromotedScalar
		copySch.Fields["tgt_kw_txt"] = b
	}
	for i := range copySch.OrderedFields {
		if updated, ok := copySch.Fields[copySch.OrderedFields[i].ESFieldPath]; ok {
			copySch.OrderedFields[i] = updated
		}
	}

	cpRow, err := r67TSchShredMap(t, copySch, "cp1", `{
		"src_txt": ["notanint", "42", "1234567"],
		"tgt_kw_txt": "PRE",
		"items": [{"src": "nestedval"}]
	}`, now)
	if err == nil {
		t.Fatalf("expected error copying 'notanint' into strict tgt_int, got %+v", cpRow)
	}
	// Now test with valid numeric + blank + disabled + alias + keyword companion scalar
	copySch2 := r67TSchCompileMapping(t, "r67t_copyto2", `{
		"properties": {
			"src_a": {"type": "keyword", "copy_to": ["tgt_int_ign", "tgt_alias", "tgt_disabled", "tgt_kw_txt"]},
			"src_b": {"type": "keyword", "copy_to": ["tgt_int_ign", "tgt_kw_txt"]},
			"tgt_int_ign": {"type": "integer", "ignore_malformed": true, "ignore_above": 6},
			"tgt_real": {"type": "text"},
			"tgt_alias": {"type": "alias", "path": "tgt_real"},
			"tgt_disabled": {"type": "object", "enabled": false},
			"tgt_kw_txt": {"type": "text", "fields": {"keyword": {"type": "keyword", "normalizer": "lc", "ignore_above": 5}}}
		}
	}`)
	_ = copySch2.SetAnalysisSettings(map[string]any{
		"analysis": map[string]any{
			"normalizer": map[string]any{
				"lc": map[string]any{"type": "custom", "filter": []any{"lowercase"}},
			},
		},
	})
	for _, fn := range []string{"tgt_kw_txt", "tgt_kw_txt.keyword", "tgt_int_ign", "tgt_real"} {
		if b, ok := copySch2.Fields[fn]; ok {
			b.Kind = StoragePromotedScalar
			copySch2.Fields[fn] = b
		}
	}
	for i := range copySch2.OrderedFields {
		if updated, ok := copySch2.Fields[copySch2.OrderedFields[i].ESFieldPath]; ok {
			copySch2.OrderedFields[i] = updated
		}
	}
	cpRow2, err := r67TSchShredMap(t, copySch2, "cp2", `{
		"src_a": ["   ", "bad", "1234567", "99", "ABC"],
		"src_b": "DEF",
		"tgt_kw_txt": "INIT"
	}`, now)
	if err != nil {
		t.Fatalf("copySch2 shred failed: %v", err)
	}
	if cpRow2["f__tgt_int_ign"] == nil || cpRow2["f__tgt_kw_txt__keyword"] == nil {
		t.Fatalf("expected tgt_int_ign and tgt_kw_txt__keyword populated, got %+v", cpRow2)
	}
}

func TestRound67TopUpSchema_CoerceAndDatesAndNestedNormalize(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// 1. coerceScalarBindingForDorisWithSchema: unsigned_long, signed int strings, date_nanos, date with FromScript/FromRuntime
	coerceF := false
	coerceT := true
	for _, tc := range []struct {
		name string
		b    FieldBinding
		val  any
		want any
	}{
		{"ul_float_nocoerce", FieldBinding{ESType: "unsigned_long", Coerce: &coerceF}, float64(1.5), nil},
		{"ul_neg_int64", FieldBinding{ESType: "unsigned_long"}, int64(-1), nil},
		{"ul_neg_int", FieldBinding{ESType: "unsigned_long"}, int(-2), nil},
		{"ul_uint64", FieldBinding{ESType: "unsigned_long"}, uint64(42), uint64(42)},
		{"int_empty_str", FieldBinding{ESType: "integer"}, "   ", nil},
		{"int_dec_nocoerce", FieldBinding{ESType: "integer", Coerce: &coerceF}, "12.0", nil},
		{"int_dec_emptyfrac", FieldBinding{ESType: "integer", Coerce: &coerceT}, "12.", nil},
		{"int_dec_badfrac", FieldBinding{ESType: "integer", Coerce: &coerceT}, "12.ab", nil},
		{"int_dec_dot_only", FieldBinding{ESType: "integer", Coerce: &coerceT}, ".5", 0},
		{"int_dec_plus_dot", FieldBinding{ESType: "integer", Coerce: &coerceT}, "+.5", 0},
		{"int_dec_minus_dot", FieldBinding{ESType: "integer", Coerce: &coerceT}, "-.5", 0},
		{"int_sci_ok", FieldBinding{ESType: "integer", Coerce: &coerceT}, "1.5e2", 150},
		{"int_sci_bad", FieldBinding{ESType: "integer", Coerce: &coerceT}, "bad_e2", nil},
		{"int_bool_nil", FieldBinding{ESType: "integer"}, true, nil},
		{"dn_int64", FieldBinding{ESType: "date_nanos"}, int64(1700000000), int64(1700000000000000)},
		{"dn_int", FieldBinding{ESType: "date_nanos"}, int(1700000000), int64(1700000000000000)},
		{"dn_float", FieldBinding{ESType: "date_nanos"}, float64(1700000000), int64(1700000000000000)},
		{"dn_jn", FieldBinding{ESType: "date_nanos"}, json.Number("1700000000"), int64(1700000000000000)},
		{"dt_script_int64", FieldBinding{ESType: "date", Format: "yyyy-MM-dd", FromScript: true}, int64(12345), int64(12345)},
		{"dt_script_int", FieldBinding{ESType: "date", Format: "yyyy-MM-dd", FromRuntime: true}, int(6789), int64(6789)},
		{"dt_script_jn", FieldBinding{ESType: "date", Format: "yyyy-MM-dd", FromScript: true}, json.Number("4567"), int64(4567)},
		{"dt_fmt_float", FieldBinding{ESType: "date", Format: "epoch_millis"}, float64(1700000000000), int64(1700000000000)},
		{"dt_fmt_int", FieldBinding{ESType: "date", Format: "epoch_millis"}, int(1000), int64(1000)},
	} {
		got := coerceScalarBindingForDorisWithSchema(nil, tc.val, tc.b, now)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %#v (%T), want %#v (%T)", tc.name, got, got, tc.want, tc.want)
		}
	}

	// 2. validateStrictDynamicObjectWithRuntime with dotted sub-properties in props
	dynTrue := true
	subObjTrue := true
	props := map[string]esast.FieldProperty{
		"user.name": {Type: "keyword"},
		"user":      {Type: "object", Properties: map[string]esast.FieldProperty{"id": {Type: "integer"}}},
	}
	doc := map[string]any{
		"user": map[string]any{"name": "alice", "id": 1},
	}
	if _, err := validateStrictDynamicObjectWithRuntime(doc, props, nil, dynTrue, &subObjTrue, ""); err != nil {
		t.Fatalf("expected dotted subprop merge to pass strict validation, got %v", err)
	}
	propsOnlyDot := map[string]esast.FieldProperty{
		"meta.tag": {Type: "keyword"},
	}
	docOnlyDot := map[string]any{
		"meta": map[string]any{"tag": "v1"},
	}
	if _, err := validateStrictDynamicObjectWithRuntime(docOnlyDot, propsOnlyDot, nil, "strict", &subObjTrue, ""); err != nil {
		t.Fatalf("expected synthetic object prop from dotted key to pass strict validation, got %v", err)
	}

	// 3. hasExplicitNullAtPath with dotted intermediate and slice
	if !hasExplicitNullAtPath(map[string]any{"a.b": map[string]any{"c": nil}}, []string{"a", "b", "c"}) {
		t.Fatalf("expected true for nested dotted null path")
	}
	if hasExplicitNullAtPath([]any{"not_a_map"}, []string{"a"}) {
		t.Fatalf("expected false for non-map slice element")
	}

	// 4. ESDateFormatToGoLayout tokens
	if got := ESDateFormatToGoLayout("EEEE, dd MMMM yyyy h:mm:ss.SSS a ZZZZ x xxx SSSSS"); !strings.Contains(got, "Monday") || !strings.Contains(got, "January") || !strings.Contains(got, "00000") {
		t.Fatalf("unexpected ESDateFormatToGoLayout: %q", got)
	}
	if got := ESDateFormatToGoLayout("E MMM d H:m:s Z"); !strings.Contains(got, "Mon") || !strings.Contains(got, "Jan") || !strings.Contains(got, "-0700") {
		t.Fatalf("unexpected short ESDateFormatToGoLayout: %q", got)
	}

	// 5. ParseESDateBoundWithFormatAndLocaleToEpochNanos formats
	for _, tc := range []struct {
		input, fmtStr string
		roundUp       bool
	}{
		{"2026-03-01T10:20:30.123Z", "strict_date_time", false},
		{"2026-03-01T10:20:30Z", "strict_date_time_no_millis", false},
		{"2026-03-01", "strict_date", true},
		{"2026/03/01", "date", true},
		{"20260301T102030Z", "basic_date_time_no_millis", false},
		{"20260301T102030.123Z", "basic_date_time", false},
		{"20260301", "basic_date", false},
		{"1700000000||+1s", "epoch_second", false},
		{"1700000000000||+1s", "epoch_millis", false},
		{"1700000000000000000||+1s", "epoch_nanos", false},
	} {
		if _, ok := ParseESDateBoundWithFormatAndLocaleToEpochNanos(tc.input, tc.fmtStr, "", now, tc.roundUp); !ok {
			t.Errorf("ParseESDateBoundWithFormatAndLocaleToEpochNanos(%q, %q) failed", tc.input, tc.fmtStr)
		}
	}
	if _, ok := ParseESDateBoundWithFormatAndLocaleToEpochNanos("-5", "epoch_nanos", "", now, false); ok {
		t.Fatalf("expected negative epoch_nanos to fail")
	}
	if _, ok := ParseESDateBoundWithFormatAndLocaleToEpochNanos("-5", "epoch_millis", "", now, false); ok {
		t.Fatalf("expected negative epoch_millis to fail")
	}
	if _, ok := ParseESDateBoundWithFormatAndLocaleToEpochNanos("-5", "epoch_second", "", now, false); ok {
		t.Fatalf("expected negative epoch_second to fail")
	}
}

func TestRound67TopUpSchema_CopyToMultiFieldsVariantAndNestedCopyTo(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	getNow := func() time.Time { return now }

	// 1. propagateCopyToCustomMultiFields (L4426-4462)
	mfSch := r67TSchCompileMapping(t, "r67t_mf", `{
		"properties": {
			"target": {
				"type": "text",
				"fields": {
					"num": {"type": "integer", "ignore_above": 5, "ignore_malformed": true},
					"num_strict": {"type": "integer"},
					"norm": {"type": "keyword", "normalizer": "lc", "ignore_above": 5}
				}
			}
		}
	}`)
	_ = mfSch.SetAnalysisSettings(map[string]any{
		"analysis": map[string]any{
			"normalizer": map[string]any{
				"lc": map[string]any{"type": "custom", "filter": []any{"lowercase"}},
			},
		},
	})
	for _, fn := range []string{"target.num", "target.num_strict", "target.norm"} {
		b := mfSch.Fields[fn]
		b.Kind = StoragePromotedScalar
		mfSch.Fields[fn] = b
	}
	rowMF := map[string]any{"f__target__norm": "init"}
	var ignoredMF []string
	err := propagateCopyToCustomMultiFields(mfSch, rowMF, "target", []any{nil, "123456", "  ", "bad", "42", "ABC", "TOOLONG"}, getNow, func(s string) {
		ignoredMF = append(ignoredMF, s)
	})
	if err == nil {
		t.Fatalf("expected strict num_strict parse error in propagateCopyToCustomMultiFields")
	}
	delete(mfSch.Fields, "target.num_strict")
	rowMF2 := map[string]any{"f__target__norm": "init"}
	if err := propagateCopyToCustomMultiFields(mfSch, rowMF2, "target", []any{nil, "123456", "  ", "bad", "42", "ABC", "TOOLONG"}, getNow, func(s string) {
		ignoredMF = append(ignoredMF, s)
	}); err != nil {
		t.Fatalf("unexpected propagateCopyToCustomMultiFields error: %v", err)
	}
	if rowMF2["f__target__num"] != 42 || rowMF2["f__target__norm"] != "init    bad 42 abc" {
		t.Fatalf("unexpected rowMF2=%+v", rowMF2)
	}

	// 2. buildVariantDocPayloadInternal (L4533-4559)
	efIdx := r67TSchCompileMapping(t, "r67t_var", `{
		"properties": {
			"secret": {"type": "object", "enabled": false},
			"ok": {"type": "keyword"}
		}
	}`)
	rawVar := []byte(`{"a.b": 1, "secret": {"x": 2}, "ok": "yes"}`)
	var parsedVar map[string]any
	_ = json.Unmarshal(rawVar, &parsedVar)
	resVar, err := buildVariantDocPayloadInternal(rawVar, parsedVar, false, efIdx, false)
	if err != nil || strings.Contains(string(resVar), "secret") || !strings.Contains(string(resVar), `"a"`) {
		t.Fatalf("unexpected buildVariantDocPayloadInternal result: %s err=%v", string(resVar), err)
	}
	// Invalid JSON trimmed fallback with allowInPlace=false
	if resInvalid, err := buildVariantDocPayloadInternal([]byte("not-json"), map[string]any{"a.b": 1}, false, efIdx, false); err != nil || string(resInvalid) != "not-json" {
		t.Fatalf("expected raw passthrough on non-json trimmed, got %q err=%v", string(resInvalid), err)
	}

	// 3. cleanMalformedNestedLeafInMap (L4842-4861)
	intB := FieldBinding{ESFieldPath: "x", ESType: "integer", IgnoreMalformed: r67TSchBoolPtr(true)}
	cm := map[string]any{
		"bad": "xyz",
		"arr": []any{"xyz", "12"},
		"nested": map[string]any{
			"leaf": "bad",
		},
	}
	if !cleanMalformedNestedLeafInMap(cm, []string{"bad"}, intB, now) {
		t.Fatalf("expected bad key deleted")
	}
	if !cleanMalformedNestedLeafInMap(cm, []string{"arr"}, intB, now) {
		t.Fatalf("expected arr filtered to [12]")
	}
	if cleanMalformedNestedLeafInMap(cm, []string{"missing", "sub"}, intB, now) {
		t.Fatalf("expected false for missing path")
	}
	if !cleanMalformedNestedLeafInMap(cm, []string{"nested", "leaf"}, intB, now) {
		t.Fatalf("expected nested map leaf cleaned")
	}

	// 4. FilterSourceBytesIncludesExcludes (L5377-5404)
	if got := FilterSourceBytesIncludesExcludes([]byte(`{"a":1}`), nil, nil); string(got) != `{"a":1}` {
		t.Fatalf("expected unmodified passthrough")
	}
	if got := FilterSourceBytesIncludesExcludes([]byte("   "), []string{"a"}, nil); string(got) != "   " {
		t.Fatalf("expected whitespace passthrough")
	}
	if got := FilterSourceBytesIncludesExcludes([]byte("not-json"), []string{"a"}, nil); string(got) != "not-json" {
		t.Fatalf("expected invalid JSON passthrough")
	}
	if got := FilterSourceBytesIncludesExcludes([]byte(`{"a":1}`), []string{"b*"}, nil); string(got) != "{}" {
		t.Fatalf("expected empty JSON object when all excluded, got %s", string(got))
	}

	// 5. normalizeNestedElementForStorage -> nested copy_to relative + alias + multi-segment appendNestedCopyToAtPath + applyNestedCompanionNormalizationAtPath
	nestedCopySch := r67TSchCompileMapping(t, "r67t_nc", `{
		"properties": {
			"items": {
				"type": "nested",
				"properties": {
					"src": {"type": "keyword", "copy_to": ["deep.dst_kw", "al_dst"]},
					"deep": {
						"properties": {
							"dst_kw": {"type": "keyword"},
							"sub": {
								"properties": {
									"code": {"type": "text", "fields": {"lc": {"type": "keyword", "normalizer": "lc"}}}
								}
							}
						}
					},
					"dst_real": {"type": "keyword"},
					"al_dst": {"type": "alias", "path": "items.dst_real"}
				}
			}
		}
	}`)
	_ = nestedCopySch.SetAnalysisSettings(map[string]any{
		"analysis": map[string]any{
			"normalizer": map[string]any{
				"lc": map[string]any{"type": "custom", "filter": []any{"lowercase"}},
			},
		},
	})
	elem := map[string]any{
		"src": "VAL1",
		"deep": map[string]any{
			"sub": []any{
				map[string]any{"code": "MIXED"},
			},
		},
	}
	normElem := normalizeNestedElementForStorage(nestedCopySch, "items", []string{"items"}, elem, getNow)
	if normElem["dst_real"] != "VAL1" {
		t.Fatalf("expected alias copy_to target dst_real=VAL1, got %#v", normElem)
	}
	// Directly test appendNestedCopyToAtPath multi-segment creation & slice element descent
	testCurr := map[string]any{
		"arr": []any{map[string]any{"k": "old"}},
	}
	appendNestedCopyToAtPath(nestedCopySch, testCurr, []string{"missing", "deep", "k"}, []string{"a", "b"}, FieldBinding{ESType: "keyword"})
	appendNestedCopyToAtPath(nestedCopySch, testCurr, []string{"arr", "k"}, []string{"c"}, FieldBinding{ESType: "keyword"})
	if testCurr["missing"] == nil {
		t.Fatalf("expected missing intermediate map created")
	}

	// 6. normalizeNestedLeafValueWithSchema (L6080-6097), replaceNullsAtPathInMap (L6201-6210), traverseFieldInDocMap (L6334-6351)
	ignTrue := r67TSchBoolPtr(true)
	if got := normalizeNestedLeafValueWithSchema(nil, "bad-date", FieldBinding{ESType: "date_nanos", IgnoreMalformed: ignTrue}, getNow); got != nil {
		t.Fatalf("expected nil for bad date_nanos with ignore_malformed")
	}
	if got := normalizeNestedLeafValueWithSchema(nil, "bad-date", FieldBinding{ESType: "date", Format: "yyyy-MM-dd", IgnoreMalformed: ignTrue}, getNow); got != nil {
		t.Fatalf("expected nil for bad date with format & ignore_malformed")
	}
	if got := normalizeNestedLeafValueWithSchema(nil, "bad-date", FieldBinding{ESType: "date", IgnoreMalformed: ignTrue}, getNow); got != nil {
		t.Fatalf("expected nil for bad default date with ignore_malformed")
	}
	if got := normalizeNestedLeafValueWithSchema(nil, "maybe", FieldBinding{ESType: "boolean", IgnoreMalformed: ignTrue}, getNow); got != nil {
		t.Fatalf("expected nil for bad boolean with ignore_malformed")
	}
	if got := normalizeNestedLeafValueWithSchema(nil, "bad-sf", FieldBinding{ESType: "scaled_float", ScalingFactor: 10, IgnoreMalformed: ignTrue}, getNow); got != nil {
		t.Fatalf("expected nil for bad scaled_float with ignore_malformed")
	}
	if got := normalizeNestedLeafValueWithSchema(nil, "bad-sf", FieldBinding{ESType: "scaled_float", ScalingFactor: 10, Coerce: r67TSchBoolPtr(false)}, getNow); got != nil {
		t.Fatalf("expected nil for bad scaled_float with coerce=false")
	}
	if replaceNullsAtPathInMap(map[string]any{"a.b": "nonnull"}, []string{"a", "b"}, "nv") {
		t.Fatalf("expected false when dotted key is non-null")
	}
	if !replaceNullsAtPathInMap(map[string]any{"x": "old", "y": nil}, []string{"y"}, "nv") {
		t.Fatalf("expected true when single key is nil")
	}
	tdMap := map[string]any{
		"a.b": []any{map[string]any{"c": 1}},
	}
	if _, err := traverseFieldInDocMap(tdMap, []string{"a", "b", "c"}, func(m map[string]any, k string) (bool, error) {
		return true, nil
	}); err != nil {
		t.Fatalf("unexpected traverseFieldInDocMap error: %v", err)
	}

	// 7. validateAndNormalizeHistogramValue non-increasing json.Number & mergeFlattenedObjectMaps
	if _, _, err := validateAndNormalizeHistogramValue(map[string]any{
		"values": []any{json.Number("10"), json.Number("5")},
		"counts": []any{1, 1},
	}, FieldBinding{ESFieldPath: "h"}); err == nil {
		t.Fatalf("expected non-increasing histogram values error")
	}
	mDst := map[string]any{
		"sub":  map[string]any{"a": 1},
		"arr":  []any{"x"},
		"scal": "s1",
	}
	mSrc := map[string]any{
		"sub":  map[string]any{"b": 2},
		"arr":  "y",
		"scal": []any{"s2"},
	}
	mergeFlattenedObjectMaps(mDst, mSrc)
	if len(mDst["arr"].([]any)) != 2 || len(mDst["scal"].([]any)) != 2 {
		t.Fatalf("unexpected mergeFlattenedObjectMaps result: %#v", mDst)
	}
}

func TestRound67TopUpSchema_ValidationAndInferenceAndClone(t *testing.T) {
	// 1. ValidateMappingSpec: join relations errors, copy_to slice errors, dynamic_templates []string, _source patterns, runtime TSDB errors, multi-fields alias
	badSpecs := []*esast.MappingSpec{
		{Properties: map[string]esast.FieldProperty{"j": {Type: "join", Relations: map[string]any{"": "c"}}}},
		{Properties: map[string]esast.FieldProperty{"j": {Type: "join", Relations: map[string]any{"p": []any{123}}}}},
		{Properties: map[string]esast.FieldProperty{"j": {Type: "join", Relations: map[string]any{"p": 123}}}},
		{Properties: map[string]esast.FieldProperty{"j": {Type: "join", Relations: map[string]any{"p": []string{}}}}},
		{Properties: map[string]esast.FieldProperty{"k": {Type: "keyword", CopyTo: []string{}}}},
		{Properties: map[string]esast.FieldProperty{"k": {Type: "keyword", CopyTo: []string{""}}}},
		{Properties: map[string]esast.FieldProperty{"k": {Type: "keyword", CopyTo: []any{}}}},
		{DynamicTemplates: []map[string]any{{"t": map[string]any{"match_mapping_type": []string{}, "mapping": map[string]any{"type": "keyword"}}}}},
		{DynamicTemplates: []map[string]any{{"t": map[string]any{"match_mapping_type": []string{"invalid"}, "mapping": map[string]any{"type": "keyword"}}}}},
		{Source: map[string]any{"includes": []any{123}}},
		{Runtime: map[string]esast.FieldProperty{"r": {Type: "keyword", TimeSeriesDimensions: []string{"x"}}}},
		{Runtime: map[string]esast.FieldProperty{"r": {Type: "keyword", TimeSeriesMetric: "gauge"}}},
		{Runtime: map[string]esast.FieldProperty{"r": {Type: "keyword", Script: 123}}},
		{Properties: map[string]esast.FieldProperty{"t": {Type: "text", Fields: map[string]esast.FieldProperty{"al": {Type: "alias"}}}}},
		{Properties: map[string]esast.FieldProperty{"t": {Type: "text", Fields: map[string]esast.FieldProperty{"al": {Type: "alias", Path: "t.al"}}}}},
	}
	for i, sp := range badSpecs {
		if err := ValidateMappingSpec(sp); err == nil {
			t.Errorf("badSpecs[%d] expected validation error", i)
		}
	}
	// Valid _source includes as string and []string, and valid subfield alias
	if err := ValidateMappingSpec(&esast.MappingSpec{
		Source: map[string]any{"includes": "a.*", "excludes": []string{"b.*"}},
		Properties: map[string]esast.FieldProperty{
			"t": {Type: "text", Fields: map[string]esast.FieldProperty{"kw": {Type: "keyword"}, "al": {Type: "alias", Path: "t.kw"}}},
		},
	}); err != nil {
		t.Fatalf("expected valid _source + subfield alias, got %v", err)
	}

	// 2. ValidateMappingLimits
	limSch := &IndexSchema{MaxTotalFields: 100, MaxNestedFields: 10, MaxDepth: 2, MaxFieldNameLength: 5}
	for _, limSpec := range []*esast.MappingSpec{
		{Properties: map[string]esast.FieldProperty{"": {Type: "keyword"}}},
		{Properties: map[string]esast.FieldProperty{"a..b": {Type: "keyword"}}},
		{Properties: map[string]esast.FieldProperty{"toolong": {Type: "keyword"}}},
		{Properties: map[string]esast.FieldProperty{"a.toolong": {Type: "keyword"}}},
		{Runtime: map[string]esast.FieldProperty{"a.b.c": {Type: "keyword"}}},
		{Runtime: map[string]esast.FieldProperty{"toolongrt": {Type: "keyword"}}},
	} {
		if err := ValidateMappingLimits(limSch, limSpec); err == nil {
			t.Errorf("expected limit error for %+v", limSpec)
		}
	}

	// 3. ValidateMappingUpdateCompatibility (_size, subobjects, time_series_dimension/metric, element_type)
	oldC := &esast.MappingSpec{
		Size:       map[string]any{"enabled": true},
		Subobjects: r67TSchBoolPtr(true),
		Properties: map[string]esast.FieldProperty{
			"dim": {Type: "keyword", TimeSeriesDimension: r67TSchBoolPtr(false)},
			"met": {Type: "double", TimeSeriesMetric: "gauge"},
			"vec": {Type: "dense_vector", Dims: 4},
		},
	}
	for _, badNew := range []*esast.MappingSpec{
		{Size: map[string]any{"enabled": false}},
		{Subobjects: r67TSchBoolPtr(false)},
		{Properties: map[string]esast.FieldProperty{"dim": {Type: "keyword", TimeSeriesDimension: r67TSchBoolPtr(true)}}},
		{Properties: map[string]esast.FieldProperty{"met": {Type: "double", TimeSeriesMetric: "counter"}}},
		{Properties: map[string]esast.FieldProperty{"vec": {Type: "dense_vector", Dims: 4, ElementType: "byte"}}},
	} {
		if err := ValidateMappingUpdateCompatibility(oldC, badNew); err == nil {
			t.Errorf("expected ValidateMappingUpdateCompatibility error for %+v", badNew)
		}
	}

	// 4. IsDynamicFalseUnmappedField with SAYT subfields & flattened
	dynFalseIdx := r67TSchCompileMapping(t, "r67t_dynf", `{
		"dynamic": false,
		"properties": {
			"sayt": {"type": "search_as_you_type", "max_shingle_size": 4},
			"flat": {"type": "flattened"}
		}
	}`)
	if dynFalseIdx.IsDynamicFalseUnmappedField("sayt._4gram") {
		t.Fatalf("expected sayt._4gram mapped")
	}
	if dynFalseIdx.IsDynamicFalseUnmappedField("flat.anything") {
		t.Fatalf("expected flattened child not dynamic-false unmapped")
	}
	if !dynFalseIdx.IsDynamicFalseUnmappedField("unknown_field") {
		t.Fatalf("expected unknown_field dynamic-false unmapped")
	}

	// 5. DeepMergeMappingProperties covering remaining fields (L3147-3223)
	merged := DeepMergeMappingProperties(
		map[string]esast.FieldProperty{
			"f": {Type: "keyword"},
		},
		map[string]esast.FieldProperty{
			"f": {
				Type:                     "keyword",
				Norms:                    r67TSchBoolPtr(false),
				Boost:                    float64(2.0),
				EagerGlobalOrdinals:      r67TSchBoolPtr(true),
				Fielddata:                true,
				TimeZone:                 "UTC",
				SplitQueriesOnWhitespace: r67TSchBoolPtr(true),
				EnablePositionIncrements: r67TSchBoolPtr(false),
				StoreArraySource:         r67TSchBoolPtr(true),
				SyntheticSourceKeep:      "all",
				TimeSeriesDimension:      r67TSchBoolPtr(true),
				TimeSeriesDimensions:     []string{"a"},
				TimeSeriesMetric:         "gauge",
				TargetIndex:              "idx2",
				InputField:               "in",
				TargetField:              "tf",
				KeyField:                 "kf",
				FetchFields:              []map[string]any{{"field": "x"}},
				Metrics:                  []string{"min"},
				DefaultMetric:            "min",
			},
		},
	)
	if merged["f"].TargetIndex != "idx2" || merged["f"].DefaultMetric != "min" || merged["f"].SyntheticSourceKeep != "all" {
		t.Fatalf("unexpected DeepMergeMappingProperties result: %+v", merged["f"])
	}

	// 6. Inference helpers (non-ES8 & ES8)
	baseInf := &esast.MappingSpec{
		DynamicDateFormats: []string{"yyyy/MM/dd"},
		Runtime:            map[string]esast.FieldProperty{"rt": {Type: "keyword"}},
		DynamicTemplates: []map[string]any{
			{
				"ct_tmpl": map[string]any{
					"match_mapping_type": []string{"string"},
					"mapping": map[string]any{
						"type":    "{dynamic_type}",
						"path":    "alias_{name}",
						"copy_to": []string{"all_{name}_{dynamic_type}"},
					},
				},
			},
		},
	}
	if inf := InferMappingFromSampleDocs([]json.RawMessage{[]byte(`{"big": 99999999999999999999.0, "txt": "hello"}`)}, baseInf); inf == nil || len(inf.Runtime) == 0 {
		t.Fatalf("expected inferred spec with runtime fields preserved")
	}
	if infEmpty := InferMappingFromSampleDocs([]json.RawMessage{[]byte(`{}`)}, &esast.MappingSpec{Runtime: map[string]esast.FieldProperty{"rt": {Type: "keyword"}}}); infEmpty == nil || len(infEmpty.Runtime) == 0 {
		t.Fatalf("expected baseSpec returned with runtime preserved on empty doc")
	}
	if dt := detectDynamicMappingType(map[string]any{"x": 1}, inferOptions{}); dt != "object" {
		t.Fatalf("expected object, got %s", dt)
	}
	if dt := detectDynamicMappingType([]any{nil, "hi"}, inferOptions{}); dt != "string" {
		t.Fatalf("expected string from slice, got %s", dt)
	}
	if _, ok := matchInferredDateFormat("20260101", []string{"yyyy/MM/dd"}); ok {
		t.Fatalf("expected numeric string to not match custom dynamic_date_formats")
	}
	if _, ok := matchInferredDateFormat("2026.5", []string{"yyyy/MM/dd"}); ok {
		t.Fatalf("expected float string to not match custom dynamic_date_formats")
	}
	if !matchesDynamicMappingType([]string{"double"}, "float") || matchesDynamicMappingType([]string{"long"}, "string") {
		t.Fatalf("unexpected matchesDynamicMappingType([]string) result")
	}
	mp := mergeFieldProperty(
		esast.FieldProperty{Properties: map[string]esast.FieldProperty{"a": {Type: "long"}}},
		esast.FieldProperty{MultiValued: true, Properties: map[string]esast.FieldProperty{"a": {Type: "long"}, "b": {Type: "keyword"}}},
	)
	if !mp.MultiValued || !mp.Properties["b"].MultiValued {
		t.Fatalf("expected mergeFieldProperty to mark nested properties MultiValued: %+v", mp)
	}
}

func TestRound67TopUpSchema_Round60To63AndDDL(t *testing.T) {
	// 1. round60_schema.go: ReconstructSyntheticSource from _doc (json.RawMessage, []byte, string), syntheticScalarsEqual, semver > 20 digits
	synthSch := r67TSchCompileMapping(t, "r67t_synth", `{
		"settings": {"index": {"mapping": {"ignore_malformed": false}}},
		"_source": {"mode": "synthetic"},
		"properties": {
			"dt": {"type": "date", "format": "yyyy-MM-dd"},
			"ver": {"type": "version"},
			"ck": {"type": "counted_keyword", "ignore_above": 4},
			"fr": {"type": "float_range"},
			"dr": {"type": "double_range"},
			"ipr": {"type": "ip_range"}
		}
	}`)
	if b, ok := synthSch.Fields["ver"]; ok {
		b.LowercaseNormalizer = true
		synthSch.Fields["ver"] = b
	}
	for _, docVal := range []any{
		json.RawMessage(`{"dt":"2026-01-01","ver":"1.2.3-ALPHA"}`),
		[]byte(`{"dt":"2026-01-01"}`),
		`{"dt":"2026-01-01"}`,
	} {
		out := ReconstructSyntheticSource(synthSch, nil, map[string]any{"_doc": docVal})
		if out["dt"] != "2026-01-01" {
			t.Fatalf("expected synthetic dt=2026-01-01 for %T, got %#v", docVal, out)
		}
	}
	if !syntheticScalarsEqual(int64(1), int64(1)) || !syntheticScalarsEqual(float64(1.5), float64(1.5)) ||
		!syntheticScalarsEqual(true, true) || !syntheticScalarsEqual("a", "a") ||
		!syntheticScalarsEqual(json.Number("2"), json.Number("2")) || syntheticScalarsEqual(int64(1), "1") {
		t.Fatalf("unexpected syntheticScalarsEqual result")
	}
	if v, valid, keep := normalizeSyntheticScalarWithValidity(synthSch, "bad-date", "dt", synthSch.Fields["dt"], true, "date", map[string]bool{"dt": true}); valid || keep || v != nil {
		t.Fatalf("expected excluded bad date in ignoredSet, got v=%v valid=%v keep=%v", v, valid, keep)
	}
	if v, _, _ := normalizeSyntheticScalarWithValidity(synthSch, "1.2.3-RC1", "ver", synthSch.Fields["ver"], true, "version", nil); v != "1.2.3-rc1" {
		t.Fatalf("expected lowercased version, got %v", v)
	}
	if CompareSemverForSynthetic("123456789012345678901.0.0", "1.0.0") <= 0 {
		t.Fatalf("expected >20 digit version segment to sort higher")
	}
	if CompareSemverForSynthetic("", "1.0.0") <= 0 {
		t.Fatalf("expected non-semver empty version to sort after numeric")
	}

	// 2. round61_schema.go: LockAutoDims errors + dotted mapping, canonicalizeSingleSyntheticRange float/double/ip_range, formatRawTSDBSettingValue, ValidateTSDBMapping
	autoIdx := r67TSchCompileMapping(t, "r67t_auto", `{
		"properties": {
			"bit_v": {"type": "dense_vector", "element_type": "bit"},
			"i4_v": {"type": "dense_vector", "index_options": {"type": "int4_hnsw"}},
			"obj.sub_v": {"type": "dense_vector"}
		}
	}`)
	if err := autoIdx.LockAutoDims("bit_v", 7); err == nil {
		t.Fatalf("expected bit non-multiple-of-8 error")
	}
	if err := autoIdx.LockAutoDims("i4_v", 3); err == nil {
		t.Fatalf("expected int4_hnsw odd dims error")
	}
	if err := autoIdx.LockAutoDims("obj.sub_v", 4); err != nil || autoIdx.Fields["obj.sub_v"].VectorDims != 4 {
		t.Fatalf("expected dotted LockAutoDims to succeed, err=%v", err)
	}
	if infES8 := InferMappingFromSampleDocsES8([]json.RawMessage{[]byte(`{}`)}, &esast.MappingSpec{Runtime: map[string]esast.FieldProperty{"r": {Type: "keyword"}}}); infES8 == nil || len(infES8.Runtime) == 0 {
		t.Fatalf("expected InferMappingFromSampleDocsES8 baseSpec with runtime")
	}

	// Range canonicalization for float_range, double_range, ip_range
	for _, tc := range []struct {
		esType string
		item   any
		wantOK bool
	}{
		{"float_range", map[string]any{"gt": float64(1.0), "lt": float64(5.0)}, true},
		{"double_range", map[string]any{"gt": float64(1.0), "lt": float64(5.0)}, true},
		{"float_range", map[string]any{"gte": float64(5.0), "lte": float64(1.0)}, false},
		{"float_range", map[string]any{"gt": "notnum"}, false},
		{"float_range", map[string]any{"lt": "notnum"}, false},
		{"ip_range", map[string]any{"gt": "10.0.0.1", "lt": "10.0.0.5"}, true},
		{"ip_range", map[string]any{"gte": "10.0.0.5", "lte": "10.0.0.1"}, false},
		{"ip_range", map[string]any{"gt": "badip"}, false},
		{"ip_range", map[string]any{"lt": "badip"}, false},
		{"ip_range", map[string]any{"gte": "::"}, true},
	} {
		_, ok := canonicalizeSingleSyntheticRange(tc.item, FieldBinding{ESType: tc.esType}, tc.esType)
		if ok != tc.wantOK {
			t.Errorf("canonicalizeSingleSyntheticRange(%s, %#v) ok=%v, want %v", tc.esType, tc.item, ok, tc.wantOK)
		}
	}

	if _, _, _, _, err := ExtractTSDBSettings(map[string]any{
		"index.mode":                   "time_series",
		"index.routing_path":           []any{json.Number("1"), int64(2), uint64(3), float64(4.0), float32(5.5)},
		"index.time_series.start_time": int(1700000000000),
		"index.time_series.end_time":   int64(1700001000000),
	}); err != nil {
		t.Fatalf("expected valid ExtractTSDBSettings, got %v", err)
	}
	if err := ValidateTSDBMapping(&esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"labels": {Type: "flattened", TimeSeriesDimensions: []string{"host"}},
		},
	}, []string{"labels.missing_sub"}); err == nil {
		t.Fatalf("expected ValidateTSDBMapping missing flattened routing_path dimension error")
	}

	// 3. round62_schema.go: InspectAutoDimsAndDynamicVectors + extractTSDBTypedDimensionsFromDoc constant_keyword
	es8DynIdx := r67TSchCompileMapping(t, "r67t_es8dyn", `{
		"dynamic_templates": [
			{"num_t": {"match_mapping_type": "double", "match": "tmpl_*", "mapping": {"type": "double"}}}
		],
		"properties": {
			"copy_src": {"type": "double", "copy_to": "copy_vec"}
		}
	}`)
	es8DynIdx.ES8Mode = true
	vec128 := make([]float64, 128)
	vec128[0] = 1.5
	zeroStrs := make([]string, 128)
	for i := range zeroStrs {
		zeroStrs[i] = "0.0"
	}
	rawValidVecDoc, _ := json.Marshal(map[string]any{"dyn_v": vec128, "tmpl_v": vec128, "copy_vec": vec128})
	rawZeroVecDoc := []byte(`{"dyn_z":[` + strings.Join(zeroStrs, ",") + `]}`)
	if _, dynVecs, err := InspectAutoDimsAndDynamicVectors(es8DynIdx, [][]byte{rawValidVecDoc}); err != nil || dynVecs["dyn_v"] != 128 {
		t.Fatalf("expected dyn_v=128, got dynVecs=%v err=%v", dynVecs, err)
	}
	if _, _, err := InspectAutoDimsAndDynamicVectors(es8DynIdx, [][]byte{rawZeroVecDoc}); err == nil {
		t.Fatalf("expected zero-magnitude cosine vector error")
	}
	// constant_keyword in extractTSDBTypedDimensionsFromDoc
	ckTSDBIdx := r67TSchCompileMapping(t, "r67t_ck_tsdb", `{
		"properties": {
			"ck": {"type": "constant_keyword", "value": "prod", "time_series_dimension": true}
		}
	}`)
	if tds, err := extractTSDBTypedDimensionsFromDoc(ckTSDBIdx, map[string]any{"ck": "prod"}); err != nil || len(tds) != 1 || tds[0].canon != "prod" {
		t.Fatalf("unexpected ck TSDB dims (present): %+v err=%v", tds, err)
	}
	if tds, err := extractTSDBTypedDimensionsFromDoc(ckTSDBIdx, map[string]any{}); err != nil || len(tds) != 1 || tds[0].canon != "prod" {
		t.Fatalf("unexpected ck TSDB dims (absent): %+v err=%v", tds, err)
	}

	// 4. round63_schema.go: CapDynamicMappingAtTotalFieldsLimit, extractExcessDynamicFieldsToIgnoredSource,
	// mergeIgnoredSourceIntoSynthetic, reconstructSyntheticCountedKeywordValue, formatSyntheticDateValue, flattenAndParseTSDBDimensionValues
	capBase := &esast.MappingSpec{Properties: map[string]esast.FieldProperty{"a": {Type: "keyword"}}}
	capCand := &esast.MappingSpec{Properties: map[string]esast.FieldProperty{
		"a":   {Type: "keyword"},
		"obj": {Properties: map[string]esast.FieldProperty{"x": {Type: "keyword"}, "y": {Type: "keyword"}}},
	}}
	capped := CapDynamicMappingAtTotalFieldsLimit(&IndexSchema{IgnoreDynamicBeyondLimit: true, MaxTotalFields: 2}, capBase, capCand)
	if _, hasObj := capped.Properties["obj"]; hasObj {
		t.Fatalf("expected dynamic obj removed when total fields limit leaves no room for its subfields")
	}

	exSch := r67TSchCompileMapping(t, "r67t_excess", `{
		"properties": {
			"flat": {"type": "flattened"},
			"parent": {"properties": {"mapped": {"type": "keyword"}}},
			"arr": {"properties": {"mapped": {"type": "keyword"}}}
		}
	}`)
	exSch.IgnoreDynamicBeyondLimit = true
	exDoc := map[string]any{
		"flat":   map[string]any{"dyn": 1},
		"parent": map[string]any{"mapped": "ok", "extra": "drop"},
		"arr":    []any{map[string]any{"mapped": "ok", "extra2": 2}, "scalar"},
	}
	ignSrc := extractExcessDynamicFieldsToIgnoredSource(exSch, exDoc)
	if ignSrc == nil || ignSrc["parent"] == nil || ignSrc["arr"] == nil {
		t.Fatalf("expected excess fields extracted from parent and arr, got %#v", ignSrc)
	}
	dstSynth := map[string]any{
		"parent": map[string]any{"mapped": "ok"},
		"arr":    []any{map[string]any{"mapped": "ok"}, map[string]any{}},
	}
	mergeIgnoredSourceIntoSynthetic(exSch, dstSynth, map[string]any{
		"__ignored_source": `{"parent":{"extra":"drop"},"arr":[{"extra2":2},{}]}`,
	})
	if dstSynth["parent"].(map[string]any)["extra"] != "drop" {
		t.Fatalf("expected merged ignored source back into dstSynth, got %#v", dstSynth)
	}

	if ckVal, ok := reconstructSyntheticCountedKeywordValue(synthSch, []any{[]any{"B", nil, "A", "TOOLONG"}}, FieldBinding{ESType: "counted_keyword", IgnoreAbove: 4, LowercaseNormalizer: true}); !ok || len(ckVal.([]any)) != 3 {
		t.Fatalf("unexpected counted_keyword reconstruction: %#v ok=%v", ckVal, ok)
	}
	for _, df := range []string{"epoch_second", "date_optional_time_nanos", "date_time_no_millis", "yyyy/MM/dd"} {
		if _, ok := formatSyntheticDateValue("2026-03-01T10:00:00.000Z", FieldBinding{ESType: "date_nanos", Format: df}, nil, "dt"); !ok {
			t.Errorf("formatSyntheticDateValue(%s) failed", df)
		}
	}
	if _, err := flattenAndParseTSDBDimensionValues(nil, "d", FieldBinding{ESType: "integer", NullValue: 5}, []any{nil, []any{"   ", "10"}}); err != nil {
		t.Fatalf("unexpected flattenAndParseTSDBDimensionValues error: %v", err)
	}
	if _, err := flattenAndParseTSDBDimensionValues(nil, "d", FieldBinding{ESType: "integer", IgnoreMalformed: r67TSchBoolPtr(true)}, []any{"bad"}); err != nil {
		t.Fatalf("expected ignore_malformed nil error, got %v", err)
	}
	if _, err := flattenAndParseTSDBDimensionValues(nil, "d", FieldBinding{ESType: "integer"}, []any{"bad"}); err == nil {
		t.Fatalf("expected parse error without ignore_malformed")
	}

	// 5. ddl.go: GenerateAlterTableDDL (upgrade scalar->array on .keyword + alias, Varchar->String, NotIndexed->Indexed, time_series add cols)
	// & GeneratePromoteVariantFieldDDL (text + keyword companion, array)
	oldDDL := r67TSchCompileMapping(t, "r67t_ddl", `{
		"properties": {
			"tag": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"al": {"type": "alias", "path": "tag"},
			"raw": {"type": "keyword", "index": false}
		}
	}`)
	newDDL := r67TSchCompileMapping(t, "r67t_ddl", `{
		"properties": {
			"tag": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"al": {"type": "alias", "path": "tag"},
			"raw": {"type": "keyword"}
		}
	}`)
	newDDL.IndexMode = "time_series"
	if b, ok := newDDL.Fields["tag.keyword"]; ok {
		b.Kind = StoragePromotedArray
		b.DorisType = DorisString
		newDDL.Fields["tag.keyword"] = b
	}
	if b, ok := newDDL.Fields["raw"]; ok {
		b.DorisType = DorisString
		newDDL.Fields["raw"] = b
	}
	alterStmts := GenerateAlterTableDDL(oldDDL, newDDL)
	if len(alterStmts) == 0 {
		t.Fatalf("expected GenerateAlterTableDDL statements")
	}
	promStmts := GeneratePromoteVariantFieldDDL(oldDDL, "dyn_msg", "text")
	if len(promStmts) < 2 {
		t.Fatalf("expected GeneratePromoteVariantFieldDDL statements for text + keyword companion, got %v", promStmts)
	}
}
