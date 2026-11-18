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
	"net/netip"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound61_F10_DenseVectorAutoDimsDefaultsAndTransitions(t *testing.T) {
	// 1. Indexed dense_vector without dims (`AutoDims: true`) + materialized ES8 defaults
	var autoSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{"properties":{"vec":{"type":"dense_vector"}}}`), &autoSpec); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&autoSpec); err != nil {
		t.Fatalf("expected auto-dims indexed dense_vector to be valid, got %v", err)
	}
	serialized := SerializeFieldProperty(autoSpec.Properties["vec"])
	if serialized["index"] != true || serialized["similarity"] != "cosine" {
		t.Fatalf("unexpected serialized defaults: %+v", serialized)
	}
	if _, hasDims := serialized["dims"]; hasDims {
		t.Fatalf("expected dims to be omitted when AutoDims unlocked, got %+v", serialized)
	}
	idxOpts, ok := serialized["index_options"].(map[string]any)
	if !ok || idxOpts["type"] != "int8_hnsw" || idxOpts["m"] != 16 || idxOpts["ef_construction"] != 100 {
		t.Fatalf("expected int8_hnsw(m=16,ef=100) materialized defaults, got %+v", serialized["index_options"])
	}

	idx := CompileIndexSchema("es_db", "r61_vec", &autoSpec)
	if !idx.Fields["vec"].AutoDims || idx.Fields["vec"].VectorDims != 0 {
		t.Fatalf("expected AutoDims=true VectorDims=0, got %+v", idx.Fields["vec"])
	}
	// First document validates locally without mutating idx, and InspectAutoDimsAndDynamicVectors + CloneWithLockedAutoDims locks AutoDims to 3 on a new clone
	if _, err := ShredDocument(idx, "1", 1, false, []byte(`{"vec":[0.1,0.2,0.3]}`)); err != nil {
		t.Fatalf("shred first auto-dims doc failed: %v", err)
	}
	if !idx.Fields["vec"].AutoDims || idx.Fields["vec"].VectorDims != 0 {
		t.Fatalf("expected ShredDocument not to mutate shared IndexSchema in place, got %+v", idx.Fields["vec"])
	}
	lockedMap, _, inspErr := InspectAutoDimsAndDynamicVectors(idx, [][]byte{[]byte(`{"vec":[0.1,0.2,0.3]}`)})
	if inspErr != nil || lockedMap["vec"] != 3 {
		t.Fatalf("expected InspectAutoDimsAndDynamicVectors to discover vec=3, got %+v (err=%v)", lockedMap, inspErr)
	}
	idx, _ = idx.CloneWithLockedAutoDims(lockedMap)
	if idx.Fields["vec"].VectorDims != 3 || idx.Fields["vec"].AutoDims {
		t.Fatalf("expected AutoDims locked to 3 on clone, got %+v", idx.Fields["vec"])
	}
	// Second document with >3 dims -> exact ES8 > dims error
	if _, err := ShredDocument(idx, "2", 1, false, []byte(`{"vec":[0.1,0.2,0.3,0.4]}`)); err == nil || !strings.Contains(err.Error(), "more dimensions than defined in the mapping: [4] > [3]") {
		t.Fatalf("expected >dims error, got %v", err)
	}
	// Third document with <3 dims -> exact ES8 < dims error
	if _, err := ShredDocument(idx, "3", 1, false, []byte(`{"vec":[0.1,0.2]}`)); err == nil || !strings.Contains(err.Error(), "different number of dimensions [2] than defined in the mapping [3]") {
		t.Fatalf("expected <dims error, got %v", err)
	}
	// String on float vector -> START_ARRAY vs VALUE_STRING
	if _, err := ShredDocument(idx, "4", 1, false, []byte(`{"vec":"010203"}`)); err == nil || !strings.Contains(err.Error(), "START_ARRAY") {
		t.Fatalf("expected START_ARRAY error on float vector hex string, got %v", err)
	}

	// 2. Explicit dims: 0 must fail, index: false + similarity/index_options must fail with exact ES8 error
	for _, tc := range []struct {
		raw     string
		wantSub string
	}{
		{`{"properties":{"v":{"type":"dense_vector","dims":0}}}`, "requires [dims] in [1, 4096]"},
		{`{"properties":{"v":{"type":"dense_vector","index":false,"similarity":"cosine"}}}`, "Field [similarity] can only be specified for a field of type [dense_vector] when it is indexed"},
		{`{"properties":{"v":{"type":"dense_vector","index":false,"index_options":{"type":"flat"}}}}`, "Field [index_options] can only be specified for a field of type [dense_vector] when it is indexed"},
		{`{"properties":{"v":{"type":"dense_vector","dims":3,"index_options":{"type":"int4_hnsw"}}}}`, "even integer"},
		{`{"properties":{"v":{"type":"dense_vector","dims":4,"index_options":{"type":"flat","m":16}}}}`, "Cannot set [m]"},
	} {
		var bad esast.MappingSpec
		if err := json.Unmarshal([]byte(tc.raw), &bad); err != nil {
			t.Fatalf("unmarshal %s: %v", tc.raw, err)
		}
		err := ValidateMappingSpec(&bad)
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("for %s expected error containing %q, got %v", tc.raw, tc.wantSub, err)
		}
	}

	// 3. Upgrade matrix: flat -> int8_flat -> hnsw -> int8_hnsw -> int4_hnsw allowed; downgrades & decreasing m rejected
	parseSpec := func(raw string) *esast.MappingSpec {
		var s esast.MappingSpec
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			t.Fatal(err)
		}
		if err := ValidateMappingSpec(&s); err != nil {
			t.Fatalf("valid spec %s failed: %v", raw, err)
		}
		return &s
	}
	sFlat := parseSpec(`{"properties":{"v":{"type":"dense_vector","dims":4,"index_options":{"type":"flat"}}}}`)
	sInt8Flat := parseSpec(`{"properties":{"v":{"type":"dense_vector","dims":4,"index_options":{"type":"int8_flat","confidence_interval":0.3}}}}`)
	sHNSW32 := parseSpec(`{"properties":{"v":{"type":"dense_vector","dims":4,"index_options":{"type":"hnsw","m":32,"ef_construction":200}}}}`)
	sInt8HNSW16 := parseSpec(`{"properties":{"v":{"type":"dense_vector","dims":4,"index_options":{"type":"int8_hnsw"}}}}`)
	sInt8HNSW32 := parseSpec(`{"properties":{"v":{"type":"dense_vector","dims":4,"index_options":{"type":"int8_hnsw","m":32}}}}`)

	if err := ValidateMappingUpdateCompatibility(sFlat, sInt8Flat); err != nil {
		t.Fatalf("flat -> int8_flat should succeed: %v", err)
	}
	if err := ValidateMappingUpdateCompatibility(sInt8Flat, sHNSW32); err != nil {
		t.Fatalf("int8_flat -> hnsw should succeed: %v", err)
	}
	if err := ValidateMappingUpdateCompatibility(sHNSW32, sInt8HNSW32); err != nil {
		t.Fatalf("hnsw(m=32) -> int8_hnsw(m=32) should succeed: %v", err)
	}
	if err := ValidateMappingUpdateCompatibility(sHNSW32, sInt8HNSW16); err == nil || !strings.Contains(err.Error(), "Cannot decrease [m]") {
		t.Fatalf("expected decreasing m 32->16 to fail, got %v", err)
	}
	if err := ValidateMappingUpdateCompatibility(sInt8HNSW16, sFlat); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("expected int8_hnsw -> flat downgrade to fail, got %v", err)
	}
	if err := ValidateMappingUpdateCompatibility(sInt8HNSW16, sHNSW32); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("expected int8_hnsw -> hnsw downgrade to fail, got %v", err)
	}

	// 4. Hex-encoded signed byte vector shredding + dot_product on byte
	sByte := parseSpec(`{"properties":{"bv":{"type":"dense_vector","dims":4,"element_type":"byte","similarity":"dot_product"}}}`)
	byteIdx := CompileIndexSchema("es_db", "r61_byte", sByte)
	rawRow, err := ShredDocument(byteIdx, "b1", 1, false, []byte(`{"bv":"7f80ff00"}`))
	if err != nil {
		t.Fatalf("hex byte vector shred failed: %v", err)
	}
	var decodedRow map[string]any
	_ = json.Unmarshal(rawRow, &decodedRow)
	vecSlice, ok := decodedRow["f__bv"].([]any)
	if !ok || len(vecSlice) != 4 || vecSlice[0] != float64(127) || vecSlice[1] != float64(-128) || vecSlice[2] != float64(-1) || vecSlice[3] != float64(0) {
		t.Fatalf("unexpected decoded hex byte vector: %+v", decodedRow["f__bv"])
	}
}

func TestRound61_F10_ES8DynamicDenseVectorInference(t *testing.T) {
	makeFloatDoc := func(field string, n int) json.RawMessage {
		vals := make([]string, n)
		for i := 0; i < n; i++ {
			vals[i] = "0.25"
		}
		return json.RawMessage(`{"` + field + `":[` + strings.Join(vals, ",") + `]}`)
	}
	m127 := InferMappingFromSampleDocsES8([]json.RawMessage{makeFloatDoc("v127", 127)})
	if m127.Properties["v127"].Type != "float" {
		t.Fatalf("expected 127 floats -> float, got %+v", m127.Properties["v127"])
	}
	m128 := InferMappingFromSampleDocsES8([]json.RawMessage{makeFloatDoc("v128", 128)})
	if m128.Properties["v128"].Type != "dense_vector" || m128.Properties["v128"].Dims != 128 {
		t.Fatalf("expected 128 floats -> dense_vector(128), got %+v", m128.Properties["v128"])
	}
	m2049 := InferMappingFromSampleDocsES8([]json.RawMessage{makeFloatDoc("v2049", 2049)})
	if m2049.Properties["v2049"].Type != "float" {
		t.Fatalf("expected 2049 floats -> float, got %+v", m2049.Properties["v2049"])
	}
	// 2D nested array must NOT infer dense_vector
	m2D := InferMappingFromSampleDocsES8([]json.RawMessage{json.RawMessage(`{"mat":[` + string(makeFloatDoc("x", 128))[5:len(makeFloatDoc("x", 128))-1] + `]}`)})
	if m2D.Properties["mat"].Type != "float" {
		t.Fatalf("expected 2D float array -> float, got %+v", m2D.Properties["mat"])
	}
	// copy_to target exclusion
	var baseCopy esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"src":{"type":"float","copy_to":"dst"}}}`), &baseCopy)
	mCopy := InferMappingFromSampleDocsES8([]json.RawMessage{
		json.RawMessage(`{"src":1.5,"dst":` + string(makeFloatDoc("x", 128))[5:len(makeFloatDoc("x", 128))-1] + `}`),
	}, &baseCopy)
	if mCopy.Properties["dst"].Type != "float" {
		t.Fatalf("expected copy_to target dst -> float, got %+v", mCopy.Properties["dst"])
	}
}

func TestRound61_F12_F13_F14_DocValuesSyntheticSourceAndTSDB(t *testing.T) {
	// F12: SupportsDocValuesQueriesInES8 & ExpandFieldPattern
	var dvSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"kw_unidx":{"type":"keyword","index":false},"kw_nodv":{"type":"keyword","index":false,"doc_values":false},"txt_unidx":{"type":"text","index":false}}}`), &dvSpec)
	dvIdx := CompileIndexSchema("es_db", "r61_dv", &dvSpec)
	dvIdx.ES8Mode = true
	if !SupportsDocValuesQueriesInES8(dvIdx.Fields["kw_unidx"]) {
		t.Fatalf("expected kw_unidx to support doc_values queries in ES8")
	}
	if SupportsDocValuesQueriesInES8(dvIdx.Fields["kw_nodv"]) || SupportsDocValuesQueriesInES8(dvIdx.Fields["txt_unidx"]) {
		t.Fatalf("expected kw_nodv and txt_unidx not to support doc_values queries")
	}
	exp := dvIdx.ExpandFieldPattern("kw_*")
	if len(exp) != 1 || exp[0].Field != "kw_unidx" {
		t.Fatalf("expected ES8Mode wildcard expansion to include kw_unidx only, got %+v", exp)
	}

	// F13: Synthetic _source validation (reject text with synthetic_source_keep=none, reject percolator, reject force_synthetic_source on stored text), dotted expansion, CIDR/range canonicalization, ignore_above retention
	for _, badSynth := range []string{
		`{"_source":{"mode":"synthetic"},"properties":{"t":{"type":"text","synthetic_source_keep":"none"}}}`,
		`{"_source":{"mode":"synthetic"},"properties":{"m":{"type":"murmur3"}}}`,
	} {
		var bad esast.MappingSpec
		_ = json.Unmarshal([]byte(badSynth), &bad)
		if err := ValidateMappingSpec(&bad); err == nil {
			t.Fatalf("expected synthetic source mapping %s to fail", badSynth)
		}
	}
	var storedTextSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"_source":{"mode":"stored"},"properties":{"t":{"type":"text"}}}`), &storedTextSpec)
	if err := ValidateMappingSpec(&storedTextSpec); err != nil {
		t.Fatalf("expected stored _source with text to succeed, got %v", err)
	}
	storedTextIdx := CompileIndexSchema("es_db", "r61_stored_txt", &storedTextSpec)
	if err := ValidateForceSyntheticSource(storedTextIdx); err == nil {
		t.Fatalf("expected ValidateForceSyntheticSource to reject unstored text on mode=stored index")
	}
	var okSynth esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"t": {"type": "text", "synthetic_source_keep": "arrays"},
			"kwd": {"type": "keyword", "ignore_above": 5},
			"ipr": {"type": "ip_range"},
			"ir": {"type": "integer_range"},
			"obj": {"properties": {"sub": {"type": "keyword"}}}
		}
	}`), &okSynth); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&okSynth); err != nil {
		t.Fatalf("expected valid synthetic source mapping, got %v", err)
	}
	synthIdx := CompileIndexSchema("es_db", "r61_synth", &okSynth)
	shredBytes, err := ShredDocument(synthIdx, "s1", 1, false, []byte(`{
		"_doc_count": 3,
		"t": ["b", "a", "b"],
		"kwd": ["toolongvalue", "ok", "a"],
		"ipr": "192.168.1.0/24",
		"ir": {"gt": 1, "lt": 5},
		"obj.sub": "dotted"
	}`))
	if err != nil {
		t.Fatalf("synthetic shred failed: %v", err)
	}
	var shredMap map[string]any
	_ = json.Unmarshal(shredBytes, &shredMap)
	var synthSrc map[string]any
	if err := json.Unmarshal([]byte(shredMap["_source"].(string)), &synthSrc); err != nil {
		t.Fatal(err)
	}
	if synthSrc["_doc_count"] != float64(3) {
		t.Fatalf("expected _doc_count=3, got %v", synthSrc["_doc_count"])
	}
	kwdOut, _ := synthSrc["kwd"].([]any)
	if len(kwdOut) != 3 || kwdOut[0] != "a" || kwdOut[1] != "ok" || kwdOut[2] != "toolongvalue" {
		t.Fatalf("expected sorted valid kwd followed by ignore_above value, got %+v", synthSrc["kwd"])
	}
	iprOut, _ := synthSrc["ipr"].(map[string]any)
	if iprOut["gte"] != "192.168.1.0" || iprOut["lte"] != "192.168.1.255" {
		t.Fatalf("expected canonicalized CIDR ip_range, got %+v", synthSrc["ipr"])
	}
	irOut, _ := synthSrc["ir"].(map[string]any)
	if irOut["gte"] != float64(2) || irOut["lte"] != float64(4) {
		t.Fatalf("expected canonicalized integer_range [2,4], got %+v", synthSrc["ir"])
	}
	objOut, _ := synthSrc["obj"].(map[string]any)
	if objOut["sub"] != "dotted" {
		t.Fatalf("expected expanded dotted key obj.sub, got %+v", synthSrc)
	}

	// F14: TSDB mapping validation, position geo_point synthetic source & ComputeTSDBIdentity
	var badRT esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"runtime":{"host":{"type":"keyword","time_series_dimension":true}}}`), &badRT)
	if err := ValidateMappingSpec(&badRT); err == nil || !strings.Contains(err.Error(), "unknown parameter [time_series_dimension] on runtime field") {
		t.Fatalf("expected runtime time_series_dimension error, got %v", err)
	}
	var tsSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"city": {"type": "keyword", "time_series_dimension": true},
			"name": {"type": "keyword", "time_series_dimension": true},
			"location": {"type": "geo_point", "time_series_metric": "position"},
			"req": {"type": "long", "time_series_metric": "counter"}
		}
	}`), &tsSpec); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&tsSpec); err != nil {
		t.Fatalf("TSDB mapping validation failed: %v", err)
	}
	if err := ValidateTSDBMapping(&tsSpec, []string{"city", "req"}); err == nil || !strings.Contains(err.Error(), "[req] was not a dimension") {
		t.Fatalf("expected non-dimension routing_path error, got %v", err)
	}
	if err := ValidateTSDBMapping(&tsSpec, []string{"city", "name"}); err != nil {
		t.Fatalf("expected valid TSDB routing_path, got %v", err)
	}
	tsIdx := CompileIndexSchema("es_db", "locations", &tsSpec)
	tsIdx.IndexMode = "time_series"
	tsIdx.RoutingPath = []string{"city", "name"}
	tsIdx.TimeSeriesStartTime = "2023-01-01T00:00:00Z"
	tsIdx.TimeSeriesEndTime = "2024-01-01T00:00:00Z"

	doc := map[string]any{
		"@timestamp": "2023-01-01T12:00:00Z",
		"city":       "Amsterdam",
		"name":       "NEMO",
		"location":   "POINT(4.912350 52.374081)",
		"req":        10,
	}
	tsid1, id1, rk1, err := ComputeTSDBIdentity(tsIdx, doc, nil)
	if err != nil || tsid1 == "" || id1 == "" || rk1 != "city=Amsterdam,name=NEMO" {
		t.Fatalf("ComputeTSDBIdentity failed: tsid=%q id=%q rk=%q err=%v", tsid1, id1, rk1, err)
	}
	if err := ValidateTSDBDocID(id1, "locations"); err != nil {
		t.Fatalf("expected generated TSDB _id %q to pass ValidateTSDBDocID: %v", id1, err)
	}
	// Half-open [start_time, end_time) check: end_time itself is rejected
	docAtEnd := map[string]any{"@timestamp": "2024-01-01T00:00:00Z", "city": "Amsterdam", "name": "NEMO"}
	if _, _, _, err := ComputeTSDBIdentity(tsIdx, docAtEnd, nil); err == nil {
		t.Fatalf("expected @timestamp == end_time to fail")
	}
	// Position geo_point: single-element array allowed, 2-element array rejected, synthetic _source emits {lat, lon}
	posRowBytes, err := ShredDocument(tsIdx, id1, 1, false, []byte(`{"@timestamp":"2023-01-01T12:00:00Z","city":"Amsterdam","name":"NEMO","location":"POINT(4.912350 52.374081)"}`))
	if err != nil {
		t.Fatalf("TSDB position WKT shred failed: %v", err)
	}
	var posRow map[string]any
	_ = json.Unmarshal(posRowBytes, &posRow)
	var posSynth map[string]any
	_ = json.Unmarshal([]byte(posRow["_source"].(string)), &posSynth)
	locObj, _ := posSynth["location"].(map[string]any)
	if locObj["lat"] != 52.374081 || locObj["lon"] != 4.91235 {
		t.Fatalf("expected synthetic _source position {lat, lon} instead of WKT, got %+v", posSynth["location"])
	}
	if _, err := ShredDocument(tsIdx, id1, 1, false, []byte(`{"@timestamp":"2023-01-01T12:00:00Z","city":"A","name":"B","location":[{"lat":13,"lon":34},{"lat":14,"lon":35}]}`)); err == nil || !strings.Contains(err.Error(), "does not accept more than single value") {
		t.Fatalf("expected multi-valued position geo_point to fail, got %v", err)
	}
}

func TestRound61_CoverageSyntheticRangesTSDBScalarsAndPathHelpers(t *testing.T) {
	// 1. setNestedRawProperty & synthetic source validation edge cases
	props := make(map[string]esast.FieldProperty)
	setNestedRawProperty(nil, []string{"a"}, esast.FieldProperty{Type: "keyword"})
	setNestedRawProperty(props, nil, esast.FieldProperty{Type: "keyword"})
	setNestedRawProperty(props, []string{"lvl1", "lvl2", "leaf"}, esast.FieldProperty{Type: "keyword"})
	if props["lvl1"].Properties["lvl2"].Properties["leaf"].Type != "keyword" {
		t.Fatalf("unexpected setNestedRawProperty result: %+v", props)
	}

	fTrue := true
	fFalse := false
	for _, tc := range []struct {
		prop    esast.FieldProperty
		wantErr bool
	}{
		{esast.FieldProperty{Type: "text", SyntheticSourceKeep: "bogus"}, true},
		{esast.FieldProperty{Type: "keyword", SyntheticSourceKeep: "all"}, true},
		{esast.FieldProperty{Type: "token_count", Store: &fTrue}, false},
		{esast.FieldProperty{Type: "token_count", Fields: map[string]esast.FieldProperty{"kw": {Type: "keyword"}}}, false},
		{esast.FieldProperty{Type: "flattened", DocValues: &fFalse}, true},
		{esast.FieldProperty{Type: "flattened", DocValues: &fFalse, Store: &fTrue}, false},
		{esast.FieldProperty{Type: "text", SyntheticSourceKeep: "none", Fields: map[string]esast.FieldProperty{"raw": {Type: "text", SyntheticSourceKeep: "arrays"}}}, false},
	} {
		err := validateSingleSyntheticSourceProp("fld", tc.prop)
		if (err != nil) != tc.wantErr {
			t.Fatalf("validateSingleSyntheticSourceProp(%+v): err=%v wantErr=%v", tc.prop, err, tc.wantErr)
		}
	}

	// 2. reconstructSyntheticPositionGeoPoint & expandDottedKeysForSyntheticObject / mergeSyntheticExpandedMaps
	if pos, ok := reconstructSyntheticPositionGeoPoint([]any{4.9, 52.3}); !ok || pos == nil {
		t.Fatalf("expected numeric [lon,lat] position geo_point reconstruction")
	}
	if pos, ok := reconstructSyntheticPositionGeoPoint([]any{"52.3,4.9"}); !ok || pos == nil {
		t.Fatalf("expected single-element array position geo_point reconstruction")
	}
	if _, ok := reconstructSyntheticPositionGeoPoint("not-a-point"); ok {
		t.Fatalf("expected invalid geo_point to fail reconstruction")
	}
	merged := expandDottedKeysForSyntheticObject(nil, map[string]any{
		"a":     map[string]any{"x": 1, "sub": map[string]any{"p": 1}},
		"a.y":   2,
		"a.sub": map[string]any{"q": 2},
	}, "")
	aMap, _ := merged["a"].(map[string]any)
	subMap, _ := aMap["sub"].(map[string]any)
	if aMap["x"] != 1 || aMap["y"] != 2 || subMap["p"] != 1 || subMap["q"] != 2 {
		t.Fatalf("unexpected merged synthetic object: %+v", merged)
	}

	// 3. Synthetic ranges: integer_range, long_range, float_range, double_range, date_range, ip_range (IPv4 & IPv6)
	if formatWholeSyntheticFloatNumber(5.0, true) != json.Number("5.0") || formatWholeSyntheticFloatNumber(5.25, false) != json.Number("5.25") {
		t.Fatalf("unexpected formatWholeSyntheticFloatNumber")
	}
	bDate := FieldBinding{ESType: "date_range", Format: "strict_date_optional_time||epoch_millis"}
	for _, tc := range []struct {
		esType string
		b      FieldBinding
		raw    any
	}{
		{"long_range", FieldBinding{ESType: "long_range"}, []any{map[string]any{"gt": "10", "lt": json.Number("20")}, map[string]any{"gte": 1.0, "lte": 5}}},
		{"float_range", FieldBinding{ESType: "float_range"}, map[string]any{"gt": 1.5, "lt": 3.5}},
		{"double_range", FieldBinding{ESType: "double_range"}, map[string]any{"gte": 2.0, "lte": 4.0}},
		{"date_range", bDate, []any{map[string]any{"gt": "2023-01-01T00:00:00Z", "lt": "2023-01-02T00:00:00Z"}, map[string]any{"gte": int64(1000), "lte": float64(2000)}}},
		{"ip_range", FieldBinding{ESType: "ip_range"}, []any{"2001:db8::/120", map[string]any{"gt": "10.0.0.1", "lt": "10.0.0.10"}, map[string]any{"gte": "10.0.0.20"}, map[string]any{"lte": "10.0.0.5"}}},
	} {
		out, ok := reconstructSyntheticRangeValue(nil, tc.raw, "rng", tc.b, tc.esType, nil)
		if !ok || out == nil {
			t.Fatalf("reconstructSyntheticRangeValue(%s) failed for %+v", tc.esType, tc.raw)
		}
	}
	// Inverted / conflicting bounds return ok=false
	if _, ok := canonicalizeSingleSyntheticRange(map[string]any{"gte": 10, "gt": 5}, FieldBinding{}, "integer_range"); ok {
		t.Fatalf("expected conflicting gte+gt to fail")
	}
	if _, ok := canonicalizeSingleSyntheticRange(map[string]any{"gte": 20, "lte": 10}, FieldBinding{}, "integer_range"); ok {
		t.Fatalf("expected inverted integer_range to fail")
	}
	if compareIP128(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")) >= 0 {
		t.Fatalf("unexpected compareIP128 order")
	}

	// 4. extractSingleDocPathValue, parseTSDBTimestampMillis, canonicalizeTSDBDimensionScalar, extractTSDBDimensionsFromDoc, extractTSDBRoutingPairs, ValidateTSDBDocID
	nestedDoc := map[string]any{
		"a":     map[string]any{"b": map[string]any{"c": "deep"}},
		"x.y.z": "literal_three",
		"p.q":   map[string]any{"r": "joined_prefix"},
	}
	if v, ok := extractSingleDocPathValue(nil, []string{"a"}); ok || v != nil {
		t.Fatalf("expected nil node to return false")
	}
	if v, ok := extractSingleDocPathValue("root_scalar", nil); !ok || v != "root_scalar" {
		t.Fatalf("expected empty parts to return node")
	}
	if v, ok := extractSingleDocPathValue(nestedDoc, []string{"a", "b", "c"}); !ok || v != "deep" {
		t.Fatalf("expected deep value, got %v (%v)", v, ok)
	}
	if v, ok := extractSingleDocPathValue(nestedDoc, []string{"x", "y", "z"}); !ok || v != "literal_three" {
		t.Fatalf("expected literal_three, got %v (%v)", v, ok)
	}
	if v, ok := extractSingleDocPathValue(nestedDoc, []string{"p", "q", "r"}); !ok || v != "joined_prefix" {
		t.Fatalf("expected joined_prefix, got %v (%v)", v, ok)
	}

	for _, tsRaw := range []any{int(1700000000000), int64(1700000000000), float64(1700000000000), json.Number("1700000000000"), "2023-11-14T22:13:20.123456789Z"} {
		if _, ok := parseTSDBTimestampMillis(tsRaw, "date_nanos", ""); !ok {
			t.Fatalf("parseTSDBTimestampMillis failed on %T %v", tsRaw, tsRaw)
		}
	}

	for _, tc := range []struct {
		b    FieldBinding
		raw  any
		want string
	}{
		{FieldBinding{ESType: "long"}, []any{json.Number("42")}, "42"},
		{FieldBinding{ESType: "integer"}, "100", "100"},
		{FieldBinding{ESType: "integer"}, float64(7), "7"},
		{FieldBinding{ESType: "unsigned_long"}, "18446744073709551615", "18446744073709551615"},
		{FieldBinding{ESType: "ip"}, "::ffff:10.0.0.1", "10.0.0.1"},
		{FieldBinding{ESType: "boolean"}, true, "true"},
		{FieldBinding{ESType: "boolean"}, "FALSE", "false"},
		{FieldBinding{ESType: "date"}, "1970-01-01T00:00:01Z", "1000"},
		{FieldBinding{ESType: "keyword", LowercaseNormalizer: true}, "HeLLo", "hello"},
	} {
		got, err := canonicalizeTSDBDimensionScalar("dim", tc.b, tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("canonicalizeTSDBDimensionScalar(%s, %v) = %q, %v (want %q)", tc.b.ESType, tc.raw, got, err, tc.want)
		}
	}
	if _, err := canonicalizeTSDBDimensionScalar("dim", FieldBinding{ESType: "keyword"}, []any{"a", "b"}); err == nil {
		t.Fatalf("expected multi-value array dimension error")
	}
	if _, err := canonicalizeTSDBDimensionScalar("dim", FieldBinding{ESType: "keyword"}, map[string]any{"k": "v"}); err == nil {
		t.Fatalf("expected object dimension error")
	}

	var advTSSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"env": {"type": "constant_keyword", "value": "prod", "time_series_dimension": true},
			"labels": {"type": "flattened", "time_series_dimensions": ["region", "zone"]},
			"host": {"type": "keyword", "time_series_dimension": true}
		}
	}`), &advTSSpec); err != nil {
		t.Fatal(err)
	}
	advTSIdx := CompileIndexSchema("es_db", "ts_adv", &advTSSpec)
	advTSIdx.IndexMode = "time_series"
	advTSIdx.RoutingPath = []string{"host", "env"}
	dims, err := ExtractTSDBDimensionKeyMap(advTSIdx, map[string]any{
		"labels": map[string]any{"region": "us-east", "zone": "1a"},
		"host":   "web-01",
	})
	if err != nil || len(dims) != 4 {
		t.Fatalf("expected 4 extracted TSDB dims (including constant_keyword + flattened), got %+v (err=%v)", dims, err)
	}
	var rPairs []string
	if err := extractTSDBRoutingPairs(advTSIdx, map[string]any{"host": []any{"a", "b"}}, []string{"host"}, &rPairs); err == nil {
		t.Fatalf("expected array routing value error")
	}
	if err := ValidateTSDBDocID("short", "ts_adv"); err == nil {
		t.Fatalf("expected short TSDB _id to fail validation")
	}
}
