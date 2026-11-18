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
	"math"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound60Coverage_SourceConfigDottedAndSerialization(t *testing.T) {
	t.Parallel()

	// ParseSourceConfig
	sc, err := ParseSourceConfig(map[string]any{
		"enabled":            true,
		"includes":           []any{"a.*", "b"},
		"excludes":           []any{"a.secret"},
		"compress":           true,
		"compress_threshold": "512b",
	})
	if err != nil || sc == nil || sc.Compress == nil || !*sc.Compress || sc.CompressThreshold != "512b" {
		t.Fatalf("unexpected ParseSourceConfig: %+v, err=%v", sc, err)
	}
	if _, err := ParseSourceConfig(map[string]any{"unknown_source_key": true}); err == nil {
		t.Fatal("expected ParseSourceConfig error on unknown key")
	}

	// clone helpers & completionContextsEqual
	if cloneStringMap(nil) != nil {
		t.Fatal("expected nil from cloneStringMap(nil)")
	}
	if cloneCompletionContexts(nil) != nil {
		t.Fatal("expected nil from cloneCompletionContexts(nil)")
	}
	c1 := []esast.CompletionContextDef{{Name: "cat", Type: "category", Path: "c", Precision: 3, Default: "x"}}
	c2 := cloneCompletionContexts(c1)
	if !completionContextsEqual(c1, c2) {
		t.Fatal("expected cloned contexts to be equal")
	}
	if completionContextsEqual(c1, nil) {
		t.Fatal("expected different length contexts unequal")
	}
	if completionContextsEqual(c1, []esast.CompletionContextDef{{Name: "other", Type: "category", Path: "c", Precision: 3, Default: "x"}}) {
		t.Fatal("expected different Name contexts unequal")
	}
	if completionContextsEqual(c1, []esast.CompletionContextDef{{Name: "cat", Type: "category", Path: "c", Precision: 4, Default: "x"}}) {
		t.Fatal("expected different Precision contexts unequal")
	}
	if completionContextsEqual(c1, []esast.CompletionContextDef{{Name: "cat", Type: "category", Path: "c", Precision: 3, Default: "y"}}) {
		t.Fatal("expected different Default contexts unequal")
	}

	// validateCompletionContextsMapping
	if err := validateCompletionContextsMapping("f", "keyword", nil); err != nil {
		t.Fatalf("unexpected error on empty contexts: %v", err)
	}
	if err := validateCompletionContextsMapping("f", "keyword", c1); err == nil {
		t.Fatal("expected error for contexts on non-completion field")
	}
	if err := validateCompletionContextsMapping("f", "completion", []esast.CompletionContextDef{{Name: " ", Type: "category"}}); err == nil {
		t.Fatal("expected error for blank context name")
	}
	if err := validateCompletionContextsMapping("f", "completion", []esast.CompletionContextDef{{Name: "c", Type: "category"}, {Name: "c", Type: "geo"}}); err == nil {
		t.Fatal("expected error for duplicate context name")
	}
	if err := validateCompletionContextsMapping("f", "completion", []esast.CompletionContextDef{{Name: "c", Type: "invalid"}}); err == nil {
		t.Fatal("expected error for unsupported context type")
	}
	if err := validateCompletionContextsMapping("f", "completion", []esast.CompletionContextDef{{Name: "c", Type: "category"}, {Name: "g", Type: "geo"}}); err != nil {
		t.Fatalf("unexpected valid completion contexts error: %v", err)
	}

	// ValidateEmptyPropertyNames & ExpandDottedProperties
	for _, badProps := range []map[string]esast.FieldProperty{
		{"": {Type: "keyword"}},
		{"a..b": {Type: "keyword"}},
		{".leading": {Type: "keyword"}},
		{"ok": {Type: "text", Fields: map[string]esast.FieldProperty{"": {Type: "keyword"}}}},
		{"nested_bad": {Properties: map[string]esast.FieldProperty{"": {Type: "keyword"}}}},
	} {
		if err := ValidateEmptyPropertyNames(badProps); err == nil {
			t.Fatalf("expected empty property name error for %+v", badProps)
		}
		if _, err := ExpandDottedProperties(badProps); err == nil {
			t.Fatalf("expected ExpandDottedProperties error for %+v", badProps)
		}
	}

	if exp, err := ExpandDottedProperties(nil); err != nil || exp != nil {
		t.Fatalf("expected nil from empty ExpandDottedProperties, got %v, err=%v", exp, err)
	}
	flatNoDots := map[string]esast.FieldProperty{"title": {Type: "text"}}
	if exp, err := ExpandDottedProperties(flatNoDots); err != nil || len(exp) != 1 {
		t.Fatalf("unexpected flatNoDots: %v, err=%v", exp, err)
	}

	fBool := false
	// Scalar + dotted coexistence & nested subobjects:false
	mixedProps := map[string]esast.FieldProperty{
		"scalar_head":     {Type: "keyword"},
		"scalar_head.sub": {Type: "text"},
		"obj_head":        {Type: "object", Properties: map[string]esast.FieldProperty{"x": {Type: "integer"}}},
		"obj_head.y.z":    {Type: "keyword"},
		"no_sub":          {Subobjects: &fBool, Properties: map[string]esast.FieldProperty{"a.b": {Type: "keyword"}}},
	}
	expMixed, err := ExpandDottedProperties(mixedProps)
	if err != nil {
		t.Fatalf("ExpandDottedProperties failed: %v", err)
	}
	if _, keptFlat := expMixed["scalar_head.sub"]; !keptFlat {
		t.Fatalf("expected scalar_head.sub preserved flat, got %+v", expMixed)
	}
	if _, keptNoSub := expMixed["no_sub"].Properties["a.b"]; !keptNoSub {
		t.Fatalf("expected a.b unexpanded under subobjects:false, got %+v", expMixed["no_sub"])
	}

	// expandDottedPropertiesWithBase when base has scalar and subobjects:false
	baseProps := map[string]esast.FieldProperty{
		"base_scalar": {Type: "long"},
		"base_nosub":  {Subobjects: &fBool},
	}
	withBase, err := expandDottedPropertiesWithBase(map[string]esast.FieldProperty{
		"base_scalar.leaf": {Type: "keyword"},
		"base_nosub.a.b":   {Type: "keyword"},
		"base_nosub":       {Properties: map[string]esast.FieldProperty{"c.d": {Type: "keyword"}}},
	}, baseProps, false)
	if err != nil || withBase["base_scalar.leaf"].Type != "keyword" {
		t.Fatalf("unexpected expandDottedPropertiesWithBase: %+v, err=%v", withBase, err)
	}

	// checkObjectMergeConflict both directions
	if err := checkObjectMergeConflict("f", esast.FieldProperty{Type: "keyword"}, esast.FieldProperty{Properties: map[string]esast.FieldProperty{"a": {Type: "text"}}}); err == nil {
		t.Fatal("expected merge conflict (scalar then object)")
	}
	if err := checkObjectMergeConflict("f", esast.FieldProperty{Properties: map[string]esast.FieldProperty{"a": {Type: "text"}}}, esast.FieldProperty{Type: "keyword"}); err == nil {
		t.Fatal("expected merge conflict (object then scalar)")
	}

	// SerializeMappings on nil, empty, fallback Fields, and full MappingSpec
	if m := SerializeMappings(nil); len(m) != 0 {
		t.Fatalf("expected empty map for nil IndexSchema, got %v", m)
	}
	emptyIdx := &IndexSchema{}
	if m := emptyIdx.SerializeMappings(); len(m) != 0 {
		t.Fatalf("expected empty map for empty IndexSchema, got %v", m)
	}
	fallbackIdx := &IndexSchema{
		Fields: map[string]FieldBinding{
			"suggest": {
				ESFieldPath: "suggest",
				ESType:      "completion",
				Meta:        map[string]string{"unit": "ms"},
				Contexts:    c1,
			},
			"suggest.sub": {
				ESFieldPath: "suggest.sub",
				ESType:      "keyword",
			},
		},
	}
	fbMap := fallbackIdx.SerializeMappings()
	if _, hasProps := fbMap["properties"]; !hasProps {
		t.Fatalf("expected properties in fallback SerializeMappings, got %v", fbMap)
	}
	if len(SerializeMappingSpec(nil)) != 0 {
		t.Fatal("expected empty map from SerializeMappingSpec(nil)")
	}

	// Full MappingSpec & FieldProperty serialization via JSON unmarshal -> SerializeMappingSpec
	var fullMS esast.MappingSpec
	msJSON := `{
		"dynamic": "strict",
		"subobjects": true,
		"_routing": {"required": true},
		"_meta": {"version": 1},
		"_source": {"mode": "synthetic", "includes": ["a*"], "excludes": ["b*"], "compress": true, "compress_threshold": "1kb"},
		"dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
		"date_detection": true,
		"numeric_detection": true,
		"dynamic_date_formats": ["yyyy/MM/dd"],
		"runtime": {
			"rt_day": {"type": "keyword", "script": {"source": "emit('mon')"}}
		},
		"properties": {
			"full_field": {
				"type": "text",
				"dynamic": true,
				"subobjects": true,
				"enabled": true,
				"index": true,
				"doc_values": false,
				"store": true,
				"analyzer": "standard",
				"search_analyzer": "standard",
				"normalizer": "lowercase",
				"format": "strict_date_optional_time",
				"time_zone": "UTC",
				"dims": 4,
				"similarity": "BM25",
				"element_type": "float",
				"copy_to": "all_text",
				"null_value": "NULL",
				"ignore_above": 256,
				"ignore_malformed": true,
				"coerce": true,
				"scaling_factor": 100,
				"meta": {"owner": "search"},
				"index_prefixes": {"min_chars": 2, "max_chars": 5},
				"index_phrases": true,
				"index_options": "offsets",
				"norms": false,
				"boost": 1.5,
				"eager_global_ordinals": true,
				"fielddata": true,
				"split_queries_on_whitespace": false,
				"enable_position_increments": true,
				"positive_score_impact": true,
				"max_shingle_size": 3,
				"depth_limit": 10,
				"relations": {"question": "answer"},
				"fields": {"raw": {"type": "keyword"}},
				"properties": {"child": {"type": "long"}}
			},
			"const_f": {"type": "constant_keyword", "value": "prod"},
			"alias_f": {"type": "alias", "path": "full_field"}
		}
	}`
	if err := json.Unmarshal([]byte(msJSON), &fullMS); err != nil {
		t.Fatalf("unmarshal fullMS failed: %v", err)
	}
	serMS := SerializeMappingSpec(&fullMS)
	if serMS["dynamic"] != "strict" || serMS["runtime"] == nil || serMS["properties"] == nil {
		t.Fatalf("unexpected SerializeMappingSpec: %+v", serMS)
	}
	// Also test Dimension fallback & serializeSourceMap branches
	fpDim := SerializeFieldProperty(esast.FieldProperty{Type: "dense_vector", Dimension: 8, Contexts: c1})
	if fpDim["dims"] != 8 || fpDim["contexts"] == nil {
		t.Fatalf("expected dims=8 and contexts, got %+v", fpDim)
	}
	if m := serializeSourceMap(map[string]any{"enabled": false}); m["enabled"] != false {
		t.Fatalf("expected enabled:false, got %v", m)
	}
	if m := serializeSourceMap(map[string]any{"mode": "disabled", "enabled": false}); m["enabled"] != false {
		t.Fatalf("expected enabled:false with mode:disabled, got %v", m)
	}
	if m := serializeSourceMap(map[string]any{"invalid_src_key": 1}); m["invalid_src_key"] != 1 {
		t.Fatalf("expected fallback copy on invalid source map, got %v", m)
	}
}

func TestRound60Coverage_SyntheticSourceAndCompletionValidation(t *testing.T) {
	t.Parallel()

	fBool := false
	tBool := true

	// Disabled _source returns nil
	disabledSchema := &IndexSchema{SourceMode: "disabled"}
	if got := ReconstructSyntheticSource(disabledSchema, map[string]any{"a": 1}, nil); got != nil {
		t.Fatalf("expected nil when _source disabled, got %v", got)
	}

	// Build rich schema for ReconstructSyntheticSource
	rawMS := &esast.MappingSpec{
		Dynamic: false,
		Source:  map[string]any{"includes": []any{"*"}, "excludes": []any{"secret_excluded"}},
		Properties: map[string]esast.FieldProperty{
			"stored_dv_false": {Type: "keyword", DocValues: &fBool, Store: &tBool},
			"nested_dot.leaf": {Type: "keyword", DocValues: &fBool, Store: &tBool},
		},
	}
	idxSchema := &IndexSchema{
		RawMapping:  rawMS,
		NestedRoots: map[string]string{"items": "n__items"},
		Fields: map[string]FieldBinding{
			"disabled_obj":     {ESFieldPath: "disabled_obj", ESType: "object", EnabledFalse: true},
			"alias_f":          {ESFieldPath: "alias_f", ESType: "alias", AliasTarget: "num_long"},
			"dv_false_kw":      {ESFieldPath: "dv_false_kw", ESType: "keyword", DocValuesFalse: true},
			"dv_false_txt_ni":  {ESFieldPath: "dv_false_txt_ni", ESType: "text", DocValuesFalse: true, NotIndexed: true},
			"dv_false_txt_ok":  {ESFieldPath: "dv_false_txt_ok", ESType: "text", DocValuesFalse: true, NotIndexed: false},
			"stored_dv_false":  {ESFieldPath: "stored_dv_false", ESType: "keyword", DocValuesFalse: true},
			"nested_dot.leaf":  {ESFieldPath: "nested_dot.leaf", ESType: "keyword", DocValuesFalse: true},
			"const_kw":         {ESFieldPath: "const_kw", ESType: "constant_keyword", HasConstantValue: true, ConstantValue: "fixed"},
			"pin":              {ESFieldPath: "pin", ESType: "geo_point"},
			"pin_ignored":      {ESFieldPath: "pin_ignored", ESType: "geo_point"},
			"rng":              {ESFieldPath: "rng", ESType: "integer_range"},
			"rng_ignored":      {ESFieldPath: "rng_ignored", ESType: "integer_range"},
			"flat":             {ESFieldPath: "flat", ESType: "flattened"},
			"flat_empty":       {ESFieldPath: "flat_empty", ESType: "flattened"},
			"items":            {ESFieldPath: "items", ESType: "nested"},
			"items.sku":        {ESFieldPath: "items.sku", ESType: "keyword"},
			"objs":             {ESFieldPath: "objs", ESType: "object"},
			"objs.k":           {ESFieldPath: "objs.k", ESType: "keyword", LowercaseNormalizer: true},
			"num_long":         {ESFieldPath: "num_long", ESType: "long"},
			"num_nocoerce":     {ESFieldPath: "num_nocoerce", ESType: "integer", Coerce: &fBool},
			"ulong_small":      {ESFieldPath: "ulong_small", ESType: "unsigned_long"},
			"ulong_big":        {ESFieldPath: "ulong_big", ESType: "unsigned_long"},
			"sfloat":           {ESFieldPath: "sfloat", ESType: "scaled_float", ScalingFactor: 100},
			"flt":              {ESFieldPath: "flt", ESType: "float"},
			"bools":            {ESFieldPath: "bools", ESType: "boolean"},
			"short_ig":         {ESFieldPath: "short_ig", ESType: "keyword", IgnoreAbove: 3},
			"txt_unsorted":     {ESFieldPath: "txt_unsorted", ESType: "text"},
			"secret_excluded":  {ESFieldPath: "secret_excluded", ESType: "keyword"},
			"bad_num_ignored":  {ESFieldPath: "bad_num_ignored", ESType: "long"},
			"bad_bool_ignored": {ESFieldPath: "bad_bool_ignored", ESType: "boolean"},
		},
	}

	rawDoc := map[string]any{
		"unmapped_dyn_false": "dropped",
		"disabled_obj":       map[string]any{"inner": 1},
		"alias_f":            "x",
		"dv_false_kw":        "dropped",
		"dv_false_txt_ni":    "dropped",
		"dv_false_txt_ok":    "kept_text",
		"stored_dv_false":    "kept_stored",
		"nested_dot":         map[string]any{"leaf": "kept_dot"},
		"const_kw":           "anything",
		"pin":                []any{-74.0, 40.7},
		"pin_ignored":        "bad",
		"rng":                map[string]any{"gte": 1, "lte": 5},
		"rng_ignored":        "bad",
		"flat":               map[string]any{"env": "prod"},
		"flat_empty":         map[string]any{},
		"items":              []any{map[string]any{"sku": "B"}, map[string]any{"sku": "A"}},
		"objs":               []any{map[string]any{"k": "HELLO"}, nil},
		"num_long":           []any{[]any{int64(30), float32(10)}, []any{uint64(20), nil}},
		"num_nocoerce":       "123",
		"ulong_small":        "42",
		"ulong_big":          "18446744073709551615",
		"sfloat":             12.3456,
		"flt":                [1]float64{1.5}[0],
		"bools":              []any{"true", false},
		"short_ig":           "toolong",
		"txt_unsorted":       []any{"zeta", "alpha"},
		"secret_excluded":    "hidden",
		"bad_num_ignored":    "nan_str",
		"bad_bool_ignored":   "not_bool",
	}
	shreddedRow := map[string]any{
		"_ignored": []any{"pin_ignored", "rng_ignored", "bad_num_ignored", "bad_bool_ignored"},
	}
	got := ReconstructSyntheticSource(idxSchema, rawDoc, shreddedRow)
	if _, exists := got["unmapped_dyn_false"]; !exists {
		t.Fatal("expected unmapped_dyn_false to be retained in ES 8.4+ synthetic _source")
	}
	if _, exists := got["secret_excluded"]; exists {
		t.Fatal("expected secret_excluded to be filtered out")
	}
	if got["const_kw"] != "fixed" || got["stored_dv_false"] != "kept_stored" {
		t.Fatalf("unexpected synthetic fields: %+v", got)
	}
	// Fallback from shreddedRow["_source"] and shreddedRow["_doc"]
	fromSrcStr := ReconstructSyntheticSource(nil, nil, map[string]any{
		"_source":  `{"num_int": 7, "num_flt": 2.5, "arr_one": [9]}`,
		"_ignored": []string{"none"},
	})
	if fromSrcStr["arr_one"] != int64(9) {
		t.Fatalf("expected single-element array unwrapped to 9, got %+v", fromSrcStr)
	}
	fromDocMap := ReconstructSyntheticSource(nil, nil, map[string]any{
		"_doc": map[string]any{"x": 1},
	})
	if fromDocMap["x"] != 1 {
		t.Fatalf("expected _doc fallback, got %+v", fromDocMap)
	}
	if empty := ReconstructSyntheticSource(nil, nil, nil); len(empty) != 0 {
		t.Fatalf("expected empty map when both rawDoc and shreddedRow are nil, got %v", empty)
	}

	// Completion weight, contexts, and path collection
	goodWeights := []any{0, 5, int64(10), float64(3.0), json.Number("7"), json.Number("8.0"), "12"}
	for _, w := range goodWeights {
		if err := parseCompletionWeight(w, "suggest"); err != nil {
			t.Fatalf("unexpected error on valid weight %v (%T): %v", w, w, err)
		}
	}
	badWeights := []any{nil, true, -1, int64(-5), math.NaN(), 1.5, -2.0, json.Number("-3"), json.Number("2.5"), json.Number("-4.0"), "", "abc", "-9", []any{1}}
	for _, w := range badWeights {
		if err := parseCompletionWeight(w, "suggest"); err == nil {
			t.Fatalf("expected error on invalid weight %v (%T)", w, w)
		}
	}

	// hasNonEmptyCompletionContextValue
	if ok, err := hasNonEmptyCompletionContextValue(nil, "category"); err != nil || ok {
		t.Fatalf("expected false,nil on nil, got %v,%v", ok, err)
	}
	if ok, err := hasNonEmptyCompletionContextValue([]any{}, "category"); err != nil || ok {
		t.Fatalf("expected false,nil on empty slice, got %v,%v", ok, err)
	}
	if ok, err := hasNonEmptyCompletionContextValue([]any{"", "music"}, "category"); err != nil || !ok {
		t.Fatalf("expected true,nil on slice, got %v,%v", ok, err)
	}
	if ok, err := hasNonEmptyCompletionContextValue([]string{"", "rock"}, "category"); err != nil || !ok {
		t.Fatalf("expected true,nil on []string, got %v,%v", ok, err)
	}
	if ok, err := hasNonEmptyCompletionContextValue([]string{"  "}, "category"); err != nil || ok {
		t.Fatalf("expected false,nil on blank []string, got %v,%v", ok, err)
	}
	if ok, err := hasNonEmptyCompletionContextValue(map[string]any{"lat": 40.7, "lon": -74.0}, "geo"); err != nil || !ok {
		t.Fatalf("expected true,nil on valid geo, got %v,%v", ok, err)
	}
	if _, err := hasNonEmptyCompletionContextValue("not_a_geo_point!!!", "geo"); err == nil {
		t.Fatal("expected error on invalid geo context value")
	}
	if _, err := hasNonEmptyCompletionContextValue(map[string]any{"bad": 1}, "category"); err == nil {
		t.Fatal("expected error on object category context value")
	}
	if ok, err := hasNonEmptyCompletionContextValue(42, "category"); err != nil || !ok {
		t.Fatalf("expected true,nil on scalar int category, got %v,%v", ok, err)
	}

	// validateCompletionValueWithContexts & collectAndValidateCompletionAtPath
	noCtxBinding := FieldBinding{ESFieldPath: "suggest", ESType: "completion"}
	if _, err := validateCompletionValueWithContexts(nil, map[string]any{"input": "hi", "contexts": map[string]any{"c": "x"}}, nil, true, nil, noCtxBinding); err == nil {
		t.Fatal("expected error when inline contexts provided on completion field without context mappings")
	}

	ctxBinding := FieldBinding{
		ESFieldPath: "suggest",
		ESType:      "completion",
		Contexts: []esast.CompletionContextDef{
			{Name: "cat", Type: "category", Path: "meta.cat"},
			{Name: "loc", Type: "geo", Path: "meta.pin"},
			{Name: "def_cat", Type: "category", Default: "general"},
		},
	}
	docRoot := map[string]any{
		"meta": map[string]any{
			"cat": "TECH",
			"pin": map[string]any{"lat": 37.77, "lon": -122.41},
		},
		"nested.suggest": []any{
			"Hello",
			map[string]any{"input": []any{"World", nil, 123}, "weight": 5, "contexts": map[string]any{"cat": "music"}},
		},
		"arr": []any{
			map[string]any{"suggest": 999},
		},
	}
	vals, err := validateCompletionValueWithContexts(docRoot, docRoot, []string{"nested", "suggest"}, true, "DEF", ctxBinding)
	if err != nil || len(vals) != 3 || vals[0] != "hello" {
		t.Fatalf("unexpected completion values: %v, err=%v", vals, err)
	}
	if vals2, err := validateCompletionValueWithContexts(docRoot, docRoot, []string{"arr", "suggest"}, true, nil, ctxBinding); err != nil || len(vals2) != 1 || vals2[0] != "999" {
		t.Fatalf("unexpected array-traversed completion values: %v, err=%v", vals2, err)
	}
	if valsNull, err := validateCompletionValueWithContexts(docRoot, nil, nil, true, "FALLBACK", ctxBinding); err != nil || len(valsNull) != 1 || valsNull[0] != "fallback" {
		t.Fatalf("unexpected null_value completion values: %v, err=%v", valsNull, err)
	}

	// Completion error branches
	badCompletionEntries := []any{
		map[string]any{"weight": 1},
		map[string]any{"input": "a", "unknown_key": 1},
		map[string]any{"input": "a", "contexts": "not_map"},
		map[string]any{"input": "a", "contexts": map[string]any{"unknown_ctx": "x"}},
		map[string]any{"input": []any{map[string]any{"nested": 1}}},
		map[string]any{"input": 12345},
	}
	for _, entry := range badCompletionEntries {
		if _, err := validateCompletionValueWithContexts(docRoot, entry, nil, true, nil, ctxBinding); err == nil {
			t.Fatalf("expected completion error for entry %+v", entry)
		}
	}
	// Missing mandatory context when docRoot lacks meta.cat
	if _, err := validateCompletionValueWithContexts(map[string]any{}, "hi", nil, true, nil, ctxBinding); err == nil {
		t.Fatal("expected missing mandatory context error")
	}
}

func TestRound60Coverage_ShredderDateNanosAndFormats(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 6, 15, 12, 30, 45, 123456789, time.UTC)

	// ESDateFormatToGoLayout across all token branches
	layout := ESDateFormatToGoLayout("'Date:' yyyy/uuuu-yy-uu MM-M dd-d 'T' HH-hh-h:mm-m:ss-s.SSS Z X XX XXX")
	if !strings.Contains(layout, "2006") || !strings.Contains(layout, "000") || !strings.Contains(layout, "-0700") || !strings.Contains(layout, "Z07:00") {
		t.Fatalf("unexpected Go layout: %q", layout)
	}

	// ParseESDateBoundWithFormatToEpochMillis
	millisCases := []struct {
		in      string
		fmt     string
		roundUp bool
		wantOK  bool
	}{
		{"", "epoch_millis", false, false},
		{"now/d", "epoch_millis", true, true},
		{"1700000000.25", "epoch_second", false, true},
		{"1700000000000", "epoch_millis", false, true},
		{"1700000000000000000", "epoch_nanos", false, true},
		{"20240510", "basic_date", true, true},
		{"20240510||+2d", "basic_date", true, true},
		{"20240510T102030.500Z", "basic_date_time", false, true},
		{"20240510T102030Z", "basic_date_time_no_millis", false, true},
		{"2024-05", "strict_date_optional_time", true, true},
		{"15/05/2024", "|| dd/MM/yyyy", true, true},
		{"15/05/2024||invalid_math", "dd/MM/yyyy", false, false},
		{"not-a-date", "dd/MM/yyyy", false, false},
	}
	for _, tc := range millisCases {
		_, ok := ParseESDateBoundWithFormatToEpochMillis(tc.in, tc.fmt, now, tc.roundUp)
		if ok != tc.wantOK {
			t.Errorf("ParseESDateBoundWithFormatToEpochMillis(%q, %q, roundUp=%v) ok=%v, want %v", tc.in, tc.fmt, tc.roundUp, ok, tc.wantOK)
		}
	}

	// ParseESDateBoundWithFormatToEpochNanos & ParseESDateWithFormatToEpochNanos
	nanosFmtCases := []struct {
		in      string
		fmt     string
		roundUp bool
		wantOK  bool
	}{
		{"", "epoch_nanos", false, false},
		{"now/h", "epoch_nanos", true, true},
		{"1700000000123456789", "epoch_nanos", false, true},
		{"1700000000123456789||+1h", "epoch_nanos", false, true},
		{"1700000000123.456", "epoch_millis", false, true},
		{"1700000000123||+1s", "epoch_millis", false, true},
		{"1700000000.123456789", "epoch_second", false, true},
		{"1700000000||+2s", "epoch_second", false, true},
		{"20240510", "basic_date", true, true},
		{"20240510||+1d", "basic_date", true, true},
		{"20240510T102030.123456789+0000", "basic_date_time", false, true},
		{"20240510T102030Z", "basic_date_time_no_millis", false, true},
		{"2024-05", "strict_date_optional_time_nanos", true, true},
		{"2024-05-10||+3d", "strict_date_optional_time_nanos", true, true},
		{"15/05/2024", "|| dd/MM/yyyy", true, true},
		{"15/05/2024||badmath", "dd/MM/yyyy", true, false},
		{"nope", "dd/MM/yyyy", false, false},
		{"2024-05-10T01:02:03.123456789Z", "", false, true},
	}
	for _, tc := range nanosFmtCases {
		_, ok := ParseESDateBoundWithFormatToEpochNanos(tc.in, tc.fmt, now, tc.roundUp)
		if ok != tc.wantOK {
			t.Errorf("ParseESDateBoundWithFormatToEpochNanos(%q, %q, roundUp=%v) ok=%v, want %v", tc.in, tc.fmt, tc.roundUp, ok, tc.wantOK)
		}
	}
	if _, ok := ParseESDateWithFormatToEpochNanos("2024-05-10T00:00:00Z", "", now); !ok {
		t.Fatal("expected ParseESDateWithFormatToEpochNanos to succeed")
	}

	// ParseESDateBoundToEpochNanos
	nanosDefaultCases := []struct {
		in      string
		roundUp bool
		wantOK  bool
	}{
		{"", false, false},
		{"2024", false, true},
		{"2024", true, true},
		{"1700000000000", false, true},
		{"1700000000123456789", false, true},
		{"now+1y-2M+1w-3d+4h-5m+6s/d", true, true},
		{"now_invalid", false, false},
		{"1700000000000||+1d", false, true},
		{"1700000000123456789||/h", true, true},
		{"2024-05-10||+2d", true, true},
		{"2024-05||", true, true},
		{"bad_prefix||+1d", false, false},
		{"2024-05-10", true, true},
		{"not-a-date", false, false},
	}
	for _, tc := range nanosDefaultCases {
		_, ok := ParseESDateBoundToEpochNanos(tc.in, now, tc.roundUp)
		if ok != tc.wantOK {
			t.Errorf("ParseESDateBoundToEpochNanos(%q, roundUp=%v) ok=%v, want %v", tc.in, tc.roundUp, ok, tc.wantOK)
		}
	}

	// parseScaledDecimalEpochToNanos
	scaledCases := []struct {
		s          string
		pow10      int
		allowNanos bool
		wantOK     bool
	}{
		{"", 6, true, false},
		{"1000", 6, true, true},
		{"1700000000123456789", 9, true, true},
		{"1700000000123456789", 9, false, false},
		{"-12.345678999", 6, false, true},
		{"+0.25", 9, false, true},
		{".5", 6, false, true},
		{".", 6, false, false},
		{"12.34x", 6, false, false},
		{"1.5e3", 6, false, true},
		{"not_num", 6, false, false},
	}
	for _, tc := range scaledCases {
		if _, ok := parseScaledDecimalEpochToNanos(tc.s, tc.pow10, tc.allowNanos); ok != tc.wantOK {
			t.Errorf("parseScaledDecimalEpochToNanos(%q, %d, %v) ok=%v, want %v", tc.s, tc.pow10, tc.allowNanos, ok, tc.wantOK)
		}
	}

	// applyESDateMathWithRoundNanos invalid math branches
	for _, badMath := range []string{"/", "/x", "1d", "+d", "+200000d", "+1x"} {
		if _, ok := applyESDateMathWithRoundNanos(now, badMath, true); ok {
			t.Errorf("expected applyESDateMathWithRoundNanos(%q) to fail", badMath)
		}
	}
}

func TestRound60Coverage_ShredderVectorsRangesNestedAndCoercion(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	getNow := func() time.Time { return now }
	fBool := false
	tBool := true

	// replacePathSliceInMap & cleanMalformedNestedLeafInMap & cleanMalformedNestedLeafValue
	mReplace := map[string]any{
		"a.b": []any{1, 2},
		"arr": []any{map[string]any{"k": "old"}},
		"sub": map[string]any{"leaf": "old"},
	}
	if !replacePathSliceInMap(mReplace, []string{"a", "b"}, []any{3}) {
		t.Fatal("expected dotted path replacement")
	}
	if !replacePathSliceInMap(mReplace, []string{"arr", "k"}, []any{"new"}) {
		t.Fatal("expected slice element path replacement")
	}
	if !replacePathSliceInMap(mReplace, []string{"sub", "leaf"}, []any{"new"}) {
		t.Fatal("expected nested map path replacement")
	}
	if replacePathSliceInMap(nil, []string{"a"}, []any{1}) || replacePathSliceInMap(mReplace, []string{"missing", "x"}, []any{1}) {
		t.Fatal("expected false on nil/missing replacePathSliceInMap")
	}

	intBind := FieldBinding{ESFieldPath: "n.x", ESType: "integer", DorisType: DorisInt}
	geoBind := FieldBinding{ESFieldPath: "n.pin", ESType: "geo_point"}
	mClean := map[string]any{
		"a.b": "bad_int",
		"arr": []any{map[string]any{"x": []any{"10", "bad_int"}}},
		"sub": map[string]any{"x": ""},
	}
	if !cleanMalformedNestedLeafInMap(mClean, []string{"a", "b"}, intBind, now) {
		t.Fatal("expected dotted malformed leaf cleaned")
	}
	if !cleanMalformedNestedLeafInMap(mClean, []string{"arr", "x"}, intBind, now) {
		t.Fatal("expected array malformed leaf partially cleaned")
	}
	if !cleanMalformedNestedLeafInMap(mClean, []string{"sub", "x"}, intBind, now) {
		t.Fatal("expected empty string on integer leaf cleaned")
	}
	if _, keep, _ := cleanMalformedNestedLeafValue([]any{200.0, 200.0}, geoBind, now); keep {
		t.Fatal("expected out-of-bounds geo array dropped")
	}
	if _, keep, _ := cleanMalformedNestedLeafValue(map[string]any{"lat": 40.0, "lon": -70.0}, geoBind, now); !keep {
		t.Fatal("expected valid geo map kept")
	}
	if _, keep, _ := cleanMalformedNestedLeafValue(map[string]any{"bad": 1}, geoBind, now); keep {
		t.Fatal("expected invalid geo map dropped")
	}
	if _, keep, _ := cleanMalformedNestedLeafValue("40.0,-70.0", geoBind, now); !keep {
		t.Fatal("expected valid geo string kept")
	}
	if _, keep, _ := cleanMalformedNestedLeafValue("bad_geo", geoBind, now); keep {
		t.Fatal("expected invalid geo string dropped")
	}
	if _, keep, _ := cleanMalformedNestedLeafValue(map[string]any{"obj": 1}, intBind, now); keep {
		t.Fatal("expected map on integer binding dropped")
	}

	// extractAndValidateTypedVectorValues: bit, byte, float, cosine zero-mag, dot_product non-unit
	bitBind := FieldBinding{ESFieldPath: "vec_bit", ESType: "dense_vector", VectorElementType: "bit", VectorDims: 16}
	if v, pres, err := extractAndValidateTypedVectorValues("ff00", nil, bitBind); err != nil || !pres || len(v) != 16 {
		t.Fatalf("bit hex vector failed: v=%v, pres=%v, err=%v", v, pres, err)
	}
	if v, pres, err := extractAndValidateTypedVectorValues([]any{-1, 0}, nil, bitBind); err != nil || !pres || len(v) != 16 {
		t.Fatalf("bit byte-array vector failed: v=%v, pres=%v, err=%v", v, pres, err)
	}
	for _, badBit := range []any{"zz", "ff", []any{}, []any{1}, []any{200, 0}, 123} {
		if _, _, err := extractAndValidateTypedVectorValues(badBit, nil, bitBind); err == nil {
			t.Fatalf("expected bit vector error on %v", badBit)
		}
	}

	byteBind := FieldBinding{ESFieldPath: "vec_byte", ESType: "dense_vector", VectorElementType: "byte", VectorDims: 2, VectorMetric: "l2_norm"}
	if v, pres, err := extractAndValidateTypedVectorValues([]any{-128, 127}, nil, byteBind); err != nil || !pres || len(v) != 2 {
		t.Fatalf("byte vector failed: %v, %v, %v", v, pres, err)
	}
	for _, badByte := range []any{"not_arr", []any{1}, []any{1, 300}} {
		if _, _, err := extractAndValidateTypedVectorValues(badByte, nil, byteBind); err == nil {
			t.Fatalf("expected byte vector error on %v", badByte)
		}
	}

	cosBind := FieldBinding{ESFieldPath: "a.b", ESType: "dense_vector", VectorDims: 2, VectorMetric: "cosine"}
	if _, _, err := extractAndValidateTypedVectorValues(map[string]any{"a.b": []any{0.0, 0.0}}, []string{"a", "b"}, cosBind); err == nil {
		t.Fatal("expected cosine zero-magnitude error")
	}
	dotBind := FieldBinding{ESFieldPath: "vec_dot", ESType: "dense_vector", VectorDims: 2, VectorMetric: "dot_product"}
	if _, _, err := extractAndValidateTypedVectorValues([]any{2.0, 0.0}, nil, dotBind); err == nil {
		t.Fatal("expected dot_product non-unit error")
	}
	if v, _, err := extractAndValidateTypedVectorValues([]any{int(1), json.Number("0.0")}, nil, dotBind); err != nil || len(v) != 2 {
		t.Fatalf("expected unit dot_product vector to pass: %v, %v", v, err)
	}

	// FilterSourceBytesIncludesExcludes with nested objects & arrays
	srcJSON := `{"user":{"profile":{"name":"alice","secret":"pw"},"age":30},"items":[{"sku":"S1","internal":true},"raw_str"]}`
	filtered := FilterSourceBytesIncludesExcludes([]byte(srcJSON), []string{"user.profile.*", "items.sku"}, []string{"user.profile.secret"})
	if strings.Contains(string(filtered), "secret") || !strings.Contains(string(filtered), "alice") || !strings.Contains(string(filtered), "S1") {
		t.Fatalf("unexpected filtered source: %s", string(filtered))
	}
	filteredExcOnly := FilterSourceBytesIncludesExcludes([]byte(srcJSON), nil, []string{"user.profile.secret", "items.internal"})
	if strings.Contains(string(filteredExcOnly), "internal") || !strings.Contains(string(filteredExcOnly), "raw_str") {
		t.Fatalf("unexpected exclude-only filtered source: %s", string(filteredExcOnly))
	}

	// Histogram strict helpers
	for _, okF := range []any{1.5, int(2), int64(3), json.Number("4.5")} {
		if _, ok := parseStrictHistogramFloat(okF); !ok {
			t.Fatalf("expected valid histogram float %v", okF)
		}
	}
	for _, badF := range []any{math.NaN(), json.Number("bad"), "1.5"} {
		if _, ok := parseStrictHistogramFloat(badF); ok {
			t.Fatalf("expected invalid histogram float %v", badF)
		}
	}
	for _, okC := range []any{int(0), int64(5), float64(4.0), json.Number("10")} {
		if _, ok := parseStrictHistogramCount(okC); !ok {
			t.Fatalf("expected valid histogram count %v", okC)
		}
	}
	for _, badC := range []any{int(-1), int64(-2), float64(1.5), float64(-1), json.Number("1.0"), json.Number("-1"), "5"} {
		if _, ok := parseStrictHistogramCount(badC); ok {
			t.Fatalf("expected invalid histogram count %v", badC)
		}
	}

	// Flattened normalization & merge
	flatBind := FieldBinding{
		ESFieldPath:         "flat",
		ESType:              "flattened",
		NullValue:           "NULL_VAL",
		LowercaseNormalizer: true,
		IgnoreAbove:         10,
		DepthLimit:          3,
	}
	var ignored []string
	recIg := func(f string) { ignored = append(ignored, f) }
	flatInput := []any{
		map[string]any{
			"k":        "VAL1",
			"null_k":   nil,
			"long_str": "exceeds_ten_chars",
			"long_num": 123456789012345,
			"arr":      []any{map[string]any{"sub": "A"}, map[string]any{"sub": "B"}},
		},
		map[string]any{
			"k": "VAL2",
		},
	}
	normFlat, _, err := validateAndNormalizeFlattenedValue(flatInput, flatBind, recIg)
	if err != nil || normFlat == nil || len(ignored) != 2 {
		t.Fatalf("unexpected flattened result: %+v, ignored=%v, err=%v", normFlat, ignored, err)
	}
	// Exceed depth limit
	deepFlat := map[string]any{"l1": map[string]any{"l2": map[string]any{"l3": map[string]any{"l4": "x"}}}}
	if _, _, err := validateAndNormalizeFlattenedValue(deepFlat, flatBind, nil); err == nil {
		t.Fatal("expected flattened depth limit error")
	}

	// Range validation across all 6 range types
	rangeCases := []struct {
		b      FieldBinding
		val    any
		wantOK bool
	}{
		{FieldBinding{ESFieldPath: "ir", ESType: "integer_range"}, map[string]any{"gt": json.Number("1"), "lt": float64(10)}, true},
		{FieldBinding{ESFieldPath: "ir", ESType: "integer_range"}, map[string]any{"gt": int64(math.MaxInt32)}, false},
		{FieldBinding{ESFieldPath: "ir", ESType: "integer_range"}, map[string]any{"lt": int64(math.MinInt32)}, false},
		{FieldBinding{ESFieldPath: "lr", ESType: "long_range"}, map[string]any{"gte": "-100", "lte": "200"}, true},
		{FieldBinding{ESFieldPath: "fr", ESType: "float_range"}, map[string]any{"gt": json.Number("1.5"), "lt": "9.5"}, true},
		{FieldBinding{ESFieldPath: "dr", ESType: "double_range"}, map[string]any{"gte": 1.25, "lte": 2.75}, true},
		{FieldBinding{ESFieldPath: "dt_fmt", ESType: "date_range", Format: "dd/MM/yyyy"}, map[string]any{"gte": "01/05/2024", "lte": "10/05/2024"}, true},
		{FieldBinding{ESFieldPath: "dt", ESType: "date_range"}, map[string]any{"gte": json.Number("1700000000000"), "lte": float64(1700000100000)}, true},
		{FieldBinding{ESFieldPath: "ipr", ESType: "ip_range"}, "192.168.1.0/24", true},
		{FieldBinding{ESFieldPath: "ipr", ESType: "ip_range"}, []any{"10.0.0.0/8", map[string]any{"gt": "10.0.0.1", "lt": "10.0.0.9"}}, true},
		{FieldBinding{ESFieldPath: "ipr", ESType: "ip_range"}, "bad_cidr", false},
		{FieldBinding{ESFieldPath: "ir", ESType: "integer_range"}, map[string]any{"gt": 1, "gte": 2}, false},
		{FieldBinding{ESFieldPath: "ir", ESType: "integer_range"}, map[string]any{"unknown": 1}, false},
	}
	for _, tc := range rangeCases {
		_, _, rErr := validateAndNormalizeRangeValue(tc.val, tc.b, getNow)
		if (rErr == nil) != tc.wantOK {
			t.Errorf("validateAndNormalizeRangeValue(%s, %v) err=%v, wantOK=%v", tc.b.ESType, tc.val, rErr, tc.wantOK)
		}
	}

	// normalizeNestedLeafValue & coerceScalarBindingForDoris & coerceScalarForDoris
	constBind := FieldBinding{ESFieldPath: "c", ESType: "constant_keyword", ConstantValue: "PROD", LowercaseNormalizer: true}
	if got := normalizeNestedLeafValue([]any{"prod", "dev"}, constBind, getNow); got == nil {
		t.Fatal("expected matching constant_keyword array item kept")
	}
	dnNoCoerce := FieldBinding{ESFieldPath: "dn", ESType: "date_nanos", Format: "strict_date_optional_time_nanos", Coerce: &fBool, IgnoreMalformed: &tBool}
	if got := normalizeNestedLeafValue(12345, dnNoCoerce, getNow); got != nil {
		t.Fatalf("expected numeric rejected on date_nanos with coerce:false, got %v", got)
	}
	if got := normalizeNestedLeafValue("2024-05-10T01:02:03.123456789Z", dnNoCoerce, getNow); got == nil {
		t.Fatal("expected valid ISO nanos accepted on date_nanos")
	}
	boolNoCoerce := FieldBinding{ESFieldPath: "b", ESType: "boolean", DorisType: DorisBoolean, Coerce: &fBool, IgnoreMalformed: &tBool}
	if got := normalizeNestedLeafValue("true", boolNoCoerce, getNow); got != nil {
		t.Fatalf("expected string rejected on boolean with coerce:false, got %v", got)
	}
	ulongNested := FieldBinding{ESFieldPath: "u", ESType: "unsigned_long", DorisType: DorisLargeInt}
	if got := normalizeNestedLeafValue(uint64(math.MaxUint64), ulongNested, getNow); got != json.Number("18446744073709551615") {
		t.Fatalf("expected MaxUint64 json.Number, got %v (%T)", got, got)
	}

	// coerceScalarBindingForDoris across token_count, ip, version, rank_feature, unsigned_long, integer/short/byte, date_nanos
	tcBind := FieldBinding{ESType: "token_count", Analyzer: "standard"}
	if coerceScalarBindingForDoris([]string{"hello world", "foo"}, tcBind, now) != int64(3) {
		t.Fatal("unexpected token_count for []string")
	}
	if coerceScalarBindingForDoris([]any{"one two"}, tcBind, now) != int64(2) {
		t.Fatal("unexpected token_count for []any")
	}
	if coerceScalarBindingForDoris("192.168.0.1", FieldBinding{ESType: "ip"}, now) != "192.168.0.1" {
		t.Fatal("unexpected ip coercion")
	}
	if coerceScalarBindingForDoris("1.2.3-alpha.1", FieldBinding{ESType: "version"}, now) != "1.2.3-alpha.1" {
		t.Fatal("unexpected version coercion")
	}
	if coerceScalarBindingForDoris("2.5", FieldBinding{ESType: "rank_feature"}, now) != 2.5 {
		t.Fatal("unexpected rank_feature string coercion")
	}
	if coerceScalarBindingForDoris("-1", FieldBinding{ESType: "rank_feature"}, now) != nil {
		t.Fatal("expected non-positive rank_feature rejected")
	}
	if coerceScalarBindingForDoris("12.9", FieldBinding{ESType: "short"}, now) != 12 {
		t.Fatal("expected fractional string truncated on short with coerce:true")
	}
	if coerceScalarBindingForDoris("1e2", FieldBinding{ESType: "byte"}, now) != 100 {
		t.Fatal("expected scientific string coerced on byte")
	}
	if coerceScalarBindingForDoris(200, FieldBinding{ESType: "byte"}, now) != nil {
		t.Fatal("expected 200 out-of-bounds on byte")
	}
	if coerceScalarBindingForDoris(json.Number("1700000000123456789"), FieldBinding{ESType: "date_nanos"}, now) == nil {
		t.Fatal("expected json.Number date_nanos coerced")
	}
	if coerceScalarForDoris("18446744073709551615", DorisLargeInt, false, now) != uint64(math.MaxUint64) {
		t.Fatal("expected MaxUint64 for DorisLargeInt")
	}
	if coerceScalarForDoris("18446744073709551615", DorisBigInt, false, now) != int64(math.MaxInt64) {
		t.Fatal("expected clamped MaxInt64 for DorisBigInt")
	}
}
