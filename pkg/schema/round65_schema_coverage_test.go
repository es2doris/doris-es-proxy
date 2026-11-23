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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound65_VariantPayloadDedup_And_F12_Fixes(t *testing.T) {
	// 1. F6-L4: buildVariantDocPayload deduplicates flat dotted vs nested object keys in `_doc`,
	// while leaving `_source` completely untouched (`search/330_fetch_fields.yml`).
	var objSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"obj": {
				"properties": {
					"products": {"type": "keyword"}
				}
			}
		}
	}`), &objSpec); err != nil {
		t.Fatal(err)
	}
	objIdx := CompileIndexSchema("es_db", "r65_variant_dedup", &objSpec)
	rawDup := `{"obj":{"products":["first"]},"obj.products":["second"],"obj.nested.sub":1,"obj":{"nested":{"other":2},"products":["first"]}}`
	// Include both overlapping `"obj.products"` and `"obj":{"products":...}` in a single JSON doc.
	rawBoth := `{"obj.products":["flat"],"obj":{"products":["nested"],"nested":{"other":2}},"obj.nested.sub":1}`
	rowBytes, err := ShredDocument(objIdx, "1", 1, false, []byte(rawBoth))
	if err != nil {
		t.Fatalf("ShredDocument overlapping dotted/nested failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(rowBytes, &row); err != nil {
		t.Fatal(err)
	}
	// `_source` must stay verbatim (contains `"obj.products"` and nested `"obj"`).
	if srcStr, _ := row["_source"].(string); srcStr != rawBoth {
		t.Fatalf("expected _source untouched %q, got %q", rawBoth, srcStr)
	}
	_ = rawDup
	// `_doc` must not retain duplicate top-level `"obj.products"` or `"obj.nested.sub"`.
	var docMap map[string]any
	docJSON, _ := json.Marshal(row["_doc"])
	if err := json.Unmarshal(docJSON, &docMap); err != nil {
		t.Fatalf("decode _doc failed: %v", err)
	}
	if _, hasFlat := docMap["obj.products"]; hasFlat {
		t.Fatalf("expected top-level dotted key obj.products normalized away in _doc, got %#v", docMap)
	}
	if _, hasFlatSub := docMap["obj.nested.sub"]; hasFlatSub {
		t.Fatalf("expected top-level dotted key obj.nested.sub normalized away in _doc, got %#v", docMap)
	}
	objMap, _ := docMap["obj"].(map[string]any)
	if _, hasProd := objMap["products"]; !hasProd {
		t.Fatalf("expected obj.products in normalized _doc, got %#v", docMap)
	}
	nestedMap, _ := objMap["nested"].(map[string]any)
	if nestedMap == nil || nestedMap["sub"] == nil || nestedMap["other"] == nil {
		t.Fatalf("expected merged obj.nested.{sub,other} in _doc, got %#v", objMap)
	}

	// Verify normalizeVariantDocMap preserves `subobjects: false` literal dotted keys.
	var noSubSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"metrics": {
				"type": "object",
				"subobjects": false,
				"properties": {
					"host.name": {"type": "keyword"}
				}
			}
		}
	}`), &noSubSpec)
	noSubIdx := CompileIndexSchema("es_db", "r65_nosub", &noSubSpec)
	noSubDoc := `{"metrics.host.name":"web01","metrics":{"host.id":7}}`
	noSubRowBytes, err := ShredDocument(noSubIdx, "1", 1, false, []byte(noSubDoc))
	if err != nil {
		t.Fatalf("ShredDocument subobjects:false failed: %v", err)
	}
	var noSubRow map[string]any
	_ = json.Unmarshal(noSubRowBytes, &noSubRow)
	docNoSubJSON, _ := json.Marshal(noSubRow["_doc"])
	var docNoSub map[string]any
	_ = json.Unmarshal(docNoSubJSON, &docNoSub)
	metricsDocMap, _ := docNoSub["metrics"].(map[string]any)
	if metricsDocMap["host.name"] != "web01" || metricsDocMap["host.id"] == nil {
		t.Fatalf("expected subobjects:false dotted leaf preserved under metrics in _doc, got %#v", docNoSub)
	}

	// Verify mergeVariantValue merging slices & maps directly.
	merged := mergeVariantValue(
		map[string]any{"a": []any{"x"}, "nested": map[string]any{"k1": 1}},
		map[string]any{"a": []any{"y"}, "nested": map[string]any{"k2": 2}},
	).(map[string]any)
	if !reflect.DeepEqual(merged["a"], []any{"x", "y"}) {
		t.Fatalf("expected merged slice, got %#v", merged["a"])
	}
	if nm := merged["nested"].(map[string]any); nm["k1"] != 1 || nm["k2"] != 2 {
		t.Fatalf("expected deep merged nested map, got %#v", nm)
	}
	normArr, normArrMod := normalizeVariantDocSlice([]any{map[string]any{"a.b": 1, "a": map[string]any{"c": 2}}}, noSubIdx, "items")
	if !normArrMod || len(normArr) != 1 {
		t.Fatalf("expected normalized slice mod=true len=1, got mod=%v %#v", normArrMod, normArr)
	}

	// 2. F12 (`aggregations/ignored_metadata_field.yml` doc 011): empty string `""` on `ip` with `ignore_malformed: true`
	// must trigger `_ignored` instead of skipping as blank.
	var ipSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"ip_address":{"type":"ip","ignore_malformed":true},"flat":{"type":"flattened","normalizer":"lowercase"}}}`), &ipSpec)
	ipIdx := CompileIndexSchema("es_db", "r65_f12", &ipSpec)
	ipRowBytes, err := ShredDocument(ipIdx, "11", 1, false, []byte(`{"ip_address":"","flat":{"mixedNum":123,"UPPER":"ABC"}}`))
	if err != nil {
		t.Fatalf("ShredDocument empty ip + flattened failed: %v", err)
	}
	var ipRow map[string]any
	_ = json.Unmarshal(ipRowBytes, &ipRow)
	ignList, _ := ipRow["_ignored"].([]any)
	if !reflect.DeepEqual(ignList, []any{"ip_address"}) {
		t.Fatalf("expected _ignored=[ip_address] for empty string ip, got %#v", ipRow["_ignored"])
	}
	ipDocMap, _ := ipRow["_doc"].(map[string]any)
	ipFlatMap, _ := ipDocMap["flat"].(map[string]any)
	if ipFlatMap == nil || ipFlatMap["UPPER"] != "abc" {
		t.Fatalf("expected flattened normalizer to lowercase string in _doc, got %#v", ipDocMap)
	}
	// Test flattened normalizer mutating non-string scalar via pattern_replace normalizer (`SetAnalysisSettings`)
	var flatPatSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"flat":{"type":"flattened","normalizer":"strip_zeros"}}}`), &flatPatSpec)
	flatPatIdx := CompileIndexSchema("es_db", "r65_flat_pat", &flatPatSpec)
	if err := flatPatIdx.SetAnalysisSettings(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"z": map[string]any{"type": "pattern_replace", "pattern": "^1", "replacement": "9"},
			},
			"normalizer": map[string]any{
				"strip_zeros": map[string]any{"type": "custom", "filter": []any{"lowercase", "z"}},
			},
		},
	}); err != nil {
		t.Fatalf("SetAnalysisSettings failed: %v", err)
	}
	flatPatBytes, err := ShredDocument(flatPatIdx, "1", 1, false, []byte(`{"flat":{"num":123}}`))
	if err != nil {
		t.Fatalf("ShredDocument flattened pattern_replace failed: %v", err)
	}
	var flatPatRow map[string]any
	_ = json.Unmarshal(flatPatBytes, &flatPatRow)
	if fpm, _ := flatPatRow["_doc"].(map[string]any); fpm == nil || fpm["flat"].(map[string]any)["num"] != "923" {
		t.Fatalf("expected flattened non-string normalized \"923\" in _doc, got %#v", flatPatRow["_doc"])
	}
}

func TestRound65_TSDB_F13a_Validation_And_Identity(t *testing.T) {
	// 1. Passthrough TSDB dimensions + subobjects:true error + auto-flatten subobjects + dynamic_templates with matcher params inside mapping
	if !IsValidTSDBDimensionFieldType("passthrough") {
		t.Fatal("expected passthrough to be valid TSDB dimension type")
	}
	var badPassSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"attributes":{"type":"passthrough","subobjects":true}}}`), &badPassSpec)
	if err := ValidateMappingSpec(&badPassSpec); err == nil || !strings.Contains(err.Error(), "has unsupported parameters:  [subobjects : true]") {
		t.Fatalf("expected subobjects:true rejection on passthrough, got %v", err)
	}

	var passthroughAutoSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"attributes": {
				"type": "passthrough",
				"time_series_dimension": true,
				"properties": {
					"subcategory": {
						"type": "object",
						"properties": {
							"dim": {"type": "keyword"}
						}
					}
				}
			}
		},
		"dynamic_templates": [
			{
				"strings_as_keyword": {
					"mapping": {
						"type": "keyword",
						"ignore_above": 1024,
						"match_mapping_type": "string",
						"path_match": "*attributes.*"
					}
				}
			}
		]
	}`), &passthroughAutoSpec); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&passthroughAutoSpec); err != nil {
		t.Fatalf("expected passthrough + strings_as_keyword mapping valid, got %v", err)
	}
	if _, flatOK := passthroughAutoSpec.Properties["attributes"].Properties["subcategory.dim"]; !flatOK {
		t.Fatalf("expected passthrough subobject flattened to subcategory.dim, got %+v", passthroughAutoSpec.Properties["attributes"].Properties)
	}
	inferredAttr := InferMappingFromSampleDocsES8(
		[]json.RawMessage{json.RawMessage(`{"attributes":{"body":"hello"},"other":"world"}`)},
		&passthroughAutoSpec,
	)
	if bProp, ok := inferredAttr.Properties["attributes"].Properties["body"]; !ok || bProp.Type != "keyword" || bProp.IgnoreAbove != 1024 {
		t.Fatalf("expected dynamic template matcher inside mapping to map attributes.body to keyword(1024), got %+v", inferredAttr.Properties["attributes"].Properties)
	}
	if oProp, ok := inferredAttr.Properties["other"]; !ok || oProp.Type == "keyword" {
		t.Fatalf("expected non-attributes field 'other' NOT to match path_match '*attributes.*', got %+v", oProp)
	}

	// 2. ValidateIndexModeSettings: ES8 exact wording, non-empty routing_path, empty datetime, sort/partitioning
	for _, tc := range []struct {
		mode     string
		settings map[string]any
		wantSub  string
	}{
		{"time_series", nil, "requires a non-empty [index.routing_path]"},
		{"time_series", map[string]any{"index.mode": "time_series"}, "requires a non-empty [index.routing_path]"},
		{"time_series", map[string]any{"index.mode": "time_series", "index.routing_path": []any{}}, "requires a non-empty [index.routing_path]"},
		{"time_series", map[string]any{"index.mode": "time_series", "index.routing_path": []any{}, "index.time_series.start_time": ""}, "cannot parse empty datetime"},
		{"time_series", map[string]any{"index.mode": "time_series", "index.routing_path": "d", "index.time_series.end_time": ""}, "cannot parse empty datetime"},
		{"time_series", map[string]any{"index.mode": "time_series", "index.routing_path": "d", "index.sort.field": "a"}, "[index.mode=time_series] is incompatible with [index.sort.field]"},
		{"time_series", map[string]any{"index.mode": "time_series", "index.routing_path": "d", "index.sort.order": "asc"}, "[index.mode=time_series] is incompatible with [index.sort.order]"},
		{"time_series", map[string]any{"index.mode": "time_series", "index.routing_path": "d", "index.sort.mode": "min"}, "[index.mode=time_series] is incompatible with [index.sort.mode]"},
		{"time_series", map[string]any{"index.mode": "time_series", "index.routing_path": "d", "index.sort.missing": "_last"}, "[index.mode=time_series] is incompatible with [index.sort.missing]"},
		{"time_series", map[string]any{"index.mode": "time_series", "index.routing_path": "d", "index.routing_partition_size": 2}, "[index.mode=time_series] is incompatible with [index.routing_partition_size]"},
		{"standard", map[string]any{"index.time_series.end_time": 1632625782000}, "[index.time_series.end_time] requires [index.mode=time_series]"},
		{"standard", map[string]any{"index.time_series.start_time": ""}, "[index.time_series.start_time] requires [index.mode=time_series]"},
	} {
		err := ValidateIndexModeSettings(tc.mode, tc.settings)
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("ValidateIndexModeSettings(%q, %+v) = %v, want %q", tc.mode, tc.settings, err, tc.wantSub)
		}
	}

	// 3. ExtractTSDBSettings numeric epoch millis (float64) + negative year `-9999-01-01T00:00:00Z` + ValidateTSDBEndTimeUpdate
	mode, rp, st, et, err := ExtractTSDBSettings(map[string]any{
		"index": map[string]any{
			"mode":         "time_series",
			"routing_path": []any{"metricset"},
			"time_series": map[string]any{
				"start_time": float64(1632625782000),
				"end_time":   float64(1632625792000),
			},
		},
	})
	if err != nil || mode != "time_series" || len(rp) != 1 || st != "1632625782000" || et != "1632625792000" {
		t.Fatalf("ExtractTSDBSettings float64 failed: mode=%q rp=%v st=%q et=%q err=%v", mode, rp, st, et, err)
	}
	if _, _, _, _, err := ExtractTSDBSettings(map[string]any{
		"index.mode":                   "time_series",
		"index.time_series.start_time": "-9999-01-01T00:00:00Z",
		"index.time_series.end_time":   "9999-12-31T23:59:59.999Z",
	}); err != nil {
		t.Fatalf("expected extreme ISO bounds valid with omitted data_stream routing_path, got %v", err)
	}
	if err := ValidateTSDBEndTimeUpdate(int64(1632625793000), int64(1632625792000)); err == nil || !strings.Contains(err.Error(), "must be larger than current value [1632625793000]") {
		t.Fatalf("expected end_time decrease error, got %v", err)
	}
	if err := ValidateTSDBEndTimeUpdate(int64(1632625792000), int64(1632625793000)); err != nil {
		t.Fatalf("expected end_time increase valid, got %v", err)
	}

	// 4. ValidateTSDBMapping + ValidateMappingSpec nested/runtime checks + ComputeTSDBIdentityWithRoutingHash dynamic/bounds checks
	var nonTSDBNestedDim esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"nested":{"type":"nested","properties":{"dim":{"type":"keyword","time_series_dimension":true}}}}}`), &nonTSDBNestedDim)
	if err := ValidateMappingSpec(&nonTSDBNestedDim); err == nil || !strings.Contains(err.Error(), "time_series_dimension can't be configured in nested field [nested.dim]") {
		t.Fatalf("expected nested dim rejection in ValidateMappingSpec, got %v", err)
	}

	var exactObjSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"@timestamp":{"type":"date"},"dim":{"properties":{"uid":{"type":"keyword","time_series_dimension":true}}}}}`), &exactObjSpec)
	if err := ValidateTSDBMapping(&exactObjSpec, []string{"dim"}); err == nil || !strings.Contains(err.Error(), "[dim] was [object].") {
		t.Fatalf("expected exact object routing_path rejection, got %v", err)
	}
	if err := ValidateTSDBMapping(&exactObjSpec, []string{"dim*"}); err != nil {
		t.Fatalf("expected wildcard routing_path 'dim*' over object valid, got %v", err)
	}

	var nestedTSDBSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"dim":{"type":"keyword","time_series_dimension":true},"n":{"type":"nested","properties":{"foo":{"type":"keyword"}}}}}`), &nestedTSDBSpec)
	if err := ValidateTSDBMapping(&nestedTSDBSpec, []string{"dim"}); err == nil || !strings.Contains(err.Error(), "cannot have nested fields when index is in [index.mode=time_series]") {
		t.Fatalf("expected TSDB nested field rejection, got %v", err)
	}
	if err := ValidateTSDBRuntimeFieldsRoutingPath([]string{"dim.*"}, map[string]esast.FieldProperty{"dim.bar": {Type: "keyword"}}); err == nil || !strings.Contains(err.Error(), "runtime fields may not match [routing_path] but [dim.bar] matched") {
		t.Fatalf("expected runtime routing_path error, got %v", err)
	}

	// ValidateTSDBRuntimeShadowing
	shadowIdx := CompileIndexSchema("es_db", "r65_shadow", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"d": {Type: "keyword", TimeSeriesDimension: boolPtrSchema(true)},
			"m": {Type: "long", TimeSeriesMetric: "gauge"},
		},
	})
	if err := ValidateTSDBRuntimeShadowing(shadowIdx, map[string]esast.FieldProperty{"d": {Type: "keyword"}}); err == nil || !strings.Contains(err.Error(), "attempted to shadow a time_series_dimension") {
		t.Fatalf("expected runtime shadowing dimension error, got %v", err)
	}
	if err := ValidateTSDBRuntimeShadowing(shadowIdx, map[string]esast.FieldProperty{"m": {Type: "long"}}); err == nil || !strings.Contains(err.Error(), "attempted to shadow a time_series_metric") {
		t.Fatalf("expected runtime shadowing metric error, got %v", err)
	}

	// Bounds + date_nanos formatting + dynamic:false / dynamic:runtime routing_path on ComputeTSDBIdentityWithRoutingHash
	var nanoTSDBSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date_nanos"},
			"metricset": {"type": "keyword", "time_series_dimension": true}
		}
	}`), &nanoTSDBSpec)
	nanoIdx := CompileIndexSchema("es_db", "r65_nano_ts", &nanoTSDBSpec)
	nanoIdx.IndexMode = "time_series"
	nanoIdx.RoutingPath = []string{"metricset"}
	nanoIdx.TimeSeriesStartTime = "1632625782000"
	nanoIdx.TimeSeriesEndTime = "1632625792000"
	if _, _, _, _, err := ComputeTSDBIdentityWithRoutingHash(nanoIdx, map[string]any{"@timestamp": "2010-09-26T03:09:52.123456789Z", "metricset": "pod"}, nil); err == nil ||
		!strings.Contains(err.Error(), "time series index @timestamp value [2010-09-26T03:09:52.123456789Z] must be larger than 2021-09-26T03:09:42Z") {
		t.Fatalf("expected ES8 start_time bound error, got %v", err)
	}
	if _, _, _, _, err := ComputeTSDBIdentityWithRoutingHash(nanoIdx, map[string]any{"@timestamp": "2021-09-26T03:09:52.123456789Z", "metricset": "pod"}, nil); err == nil ||
		!strings.Contains(err.Error(), "time series index @timestamp value [2021-09-26T03:09:52.123456789Z] must be smaller than 2021-09-26T03:09:52Z") {
		t.Fatalf("expected ES8 end_time bound error, got %v", err)
	}

	var dynFalseTSDBSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"@timestamp":{"type":"date"},"dim":{"type":"object","dynamic":false}}}`), &dynFalseTSDBSpec)
	dfIdx := CompileIndexSchema("es_db", "r65_df_ts", &dynFalseTSDBSpec)
	dfIdx.IndexMode = "time_series"
	dfIdx.RoutingPath = []string{"dim.*"}
	if _, _, _, _, err := ComputeTSDBIdentityWithRoutingHash(dfIdx, map[string]any{"@timestamp": "2021-04-28T18:50:04.467Z", "dim": map[string]any{"foo": map[string]any{"bar": "a"}}}, nil); err == nil ||
		!strings.Contains(err.Error(), "All fields matching [routing_path] must be mapped but [dim.foo] was declared as [dynamic: false]") {
		t.Fatalf("expected dynamic:false routing_path error, got %v", err)
	}

	var dynRTTSDBSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"@timestamp":{"type":"date"},"dim_kw":{"type":"keyword","time_series_dimension":true},"dim":{"type":"object","dynamic":"runtime"}}}`), &dynRTTSDBSpec)
	drtIdx := CompileIndexSchema("es_db", "r65_drt_ts", &dynRTTSDBSpec)
	drtIdx.IndexMode = "time_series"
	drtIdx.RoutingPath = []string{"dim.*"}
	if _, _, _, _, err := ComputeTSDBIdentityWithRoutingHash(drtIdx, map[string]any{"@timestamp": "2021-04-28T18:50:04.467Z", "dim_kw": "ok", "dim": map[string]any{"foo": "a"}}, nil); err == nil ||
		!strings.Contains(err.Error(), "[dim.foo] was a runtime [keyword].") {
		t.Fatalf("expected dynamic:runtime routing_path error, got %v", err)
	}
}

func TestRound65_SyntheticSource_F20a(t *testing.T) {
	// 1. store_array_source:true preserves numbers/booleans (not stringified `"200"`), while sibling keyword stringifies
	var arrSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"a": {"type": "keyword"},
			"flags": {"type": "boolean"},
			"b": {
				"store_array_source": true,
				"properties": {
					"aa": {"type": "keyword"},
					"bb": {"type": "keyword"},
					"ok": {"type": "boolean"}
				}
			}
		}
	}`), &arrSpec); err != nil {
		t.Fatal(err)
	}
	arrIdx := CompileIndexSchema("es_db", "r65_store_arr", &arrSpec)
	arrIdx.ES8Mode = true
	shredArr, err := ShredDocument(arrIdx, "1", 1, false, []byte(`{"a":2,"flags":[true,false,true],"b":[{"bb":100,"aa":200,"ok":true},{"aa":300,"bb":400,"ok":false}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var rowArr map[string]any
	_ = json.Unmarshal(shredArr, &rowArr)
	var gotArr map[string]any
	dec := json.NewDecoder(strings.NewReader(rowArr["_source"].(string)))
	dec.UseNumber()
	_ = dec.Decode(&gotArr)
	if gotArr["a"] != "2" {
		t.Fatalf("expected top-level keyword stringified \"2\", got %#v", gotArr["a"])
	}
	if !reflect.DeepEqual(gotArr["flags"], []any{false, true, true}) {
		t.Fatalf("expected ES8 synthetic boolean array to preserve duplicates sorted [false, true, true], got %#v", gotArr["flags"])
	}
	bSlice := gotArr["b"].([]any)
	b0 := bSlice[0].(map[string]any)
	if aaN, ok := b0["aa"].(json.Number); !ok || aaN.String() != "200" || b0["ok"] != true {
		t.Fatalf("expected numeric aa=200 and bool ok=true under store_array_source, got %#v", b0)
	}

	// 2. histogram zero-count stripping & ignore_malformed array reconstruction + rank_features empty slice
	var histSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"latency": {"type": "histogram", "ignore_malformed": true},
			"tags": {"type": "rank_features"},
			"ip": {"type": "ip", "ignore_malformed": true}
		}
	}`), &histSpec); err != nil {
		t.Fatal(err)
	}
	histIdx := CompileIndexSchema("es_db", "r65_histo", &histSpec)
	// Sparse zero counts (`[0,7,0,6,0]`)
	h1Bytes, err := ShredDocument(histIdx, "1", 1, false, []byte(`{"latency":{"values":[0.1,0.2,0.3,0.4,0.5],"counts":[0,7,0,6,0]},"tags":[],"ip":["10.10.1.1","192.8.1.2","hot garbage",7]}`))
	if err != nil {
		t.Fatal(err)
	}
	var h1Row map[string]any
	_ = json.Unmarshal(h1Bytes, &h1Row)
	var h1Src map[string]any
	_ = json.Unmarshal([]byte(h1Row["_source"].(string)), &h1Src)
	lat1 := h1Src["latency"].(map[string]any)
	if !reflect.DeepEqual(lat1["values"], []any{0.2, 0.4}) || !reflect.DeepEqual(lat1["counts"], []any{float64(7), float64(6)}) {
		t.Fatalf("expected sparse histogram zero counts stripped, got %#v", lat1)
	}
	if tagsSlice, ok := h1Src["tags"].([]any); !ok || len(tagsSlice) != 0 {
		t.Fatalf("expected empty rank_features [] preserved, got %#v", h1Src["tags"])
	}
	wantIPs := []any{"10.10.1.1", "192.8.1.2", "hot garbage", float64(7)}
	if !reflect.DeepEqual(h1Src["ip"], wantIPs) {
		t.Fatalf("expected malformed scalars preserved in input order %v, got %#v", wantIPs, h1Src["ip"])
	}

	// Mixed valid + malformed histogram array (`analytics/histogram.yml:340, 359`)
	h2Bytes, err := ShredDocument(histIdx, "2", 1, false, []byte(`{"latency":[{"values":[1.0],"counts":[1],"hello":"world"},[123,456],{"values":[2.0],"counts":[2]},"fox"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var h2Row map[string]any
	_ = json.Unmarshal(h2Bytes, &h2Row)
	if ign, _ := h2Row["_ignored"].([]any); !reflect.DeepEqual(ign, []any{"latency"}) {
		t.Fatalf("expected _ignored=[latency], got %#v", h2Row["_ignored"])
	}
	var h2Src map[string]any
	_ = json.Unmarshal([]byte(h2Row["_source"].(string)), &h2Src)
	lat2, _ := h2Src["latency"].([]any)
	if len(lat2) != 5 || lat2[2] != float64(123) || lat2[3] != float64(456) || lat2[4] != "fox" {
		t.Fatalf("unexpected mixed histogram synthetic _source: %#v", lat2)
	}
	if v0, _ := lat2[0].(map[string]any); v0 == nil || !reflect.DeepEqual(v0["values"], []any{2.0}) {
		t.Fatalf("expected valid histogram first in latency array, got %#v", lat2[0])
	}
	if v1, _ := lat2[1].(map[string]any); v1 == nil || v1["hello"] != "world" {
		t.Fatalf("expected malformed object with extra key preserved second, got %#v", lat2[1])
	}
}

func TestRound65_OfflineCoverage_Hotspots_W4(t *testing.T) {
	// 1. parseESWeekDatePatternR63
	if tm, dateOnly, ok := parseESWeekDatePatternR63("2024-W05-3", "YYYY-'W'ww-e"); !ok || !dateOnly || tm.Year() != 2024 || tm.Month() != time.January || tm.Day() != 31 {
		t.Fatalf("unexpected YYYY-'W'ww-e parse: tm=%v dateOnly=%v ok=%v", tm, dateOnly, ok)
	}
	if tm, dateOnly, ok := parseESWeekDatePatternR63("75-02-MonT08:09:10.123+02:00", "yy-ww-E'T'HH:mm:ss.SSSXXX"); !ok || dateOnly || tm.Year() != 1975 || tm.Hour() != 8 {
		t.Fatalf("unexpected yy-ww-E time parse: tm=%v dateOnly=%v ok=%v", tm, dateOnly, ok)
	}
	if tm, _, ok := parseESWeekDatePatternR63("24'01-Sun 23:59:59Z", "yy''ww-E HH:mm:ssX"); !ok || tm.Year() != 2024 {
		t.Fatalf("unexpected escaped quote + Sun parse: tm=%v ok=%v", tm, ok)
	}
	for _, day := range []struct {
		s string
		p string
	}{
		{"2024-01-Tue", "YYYY-ww-E"},
		{"2024-01-Wed", "YYYY-ww-E"},
		{"2024-01-Thu", "YYYY-ww-E"},
		{"2024-01-Fri", "YYYY-ww-E"},
		{"2024-01-Sat", "YYYY-ww-E"},
	} {
		if _, _, ok := parseESWeekDatePatternR63(day.s, day.p); !ok {
			t.Fatalf("expected week-day parse success for %q", day.s)
		}
	}
	for _, bad := range []struct{ in, pat string }{
		{"2024-01-01", "yyyy-MM-dd"},
		{"bad", "YYYY-'unclosed"},
		{"2024-99-1", "YYYY-ww-e"},
		{"2024-01-9", "YYYY-ww-e"},
		{"2024-01-Funday", "YYYY-ww-E"},
		{"2024-01-1 25:00:00", "YYYY-ww-e HH:mm:ss"},
		{"2024-01-1 10:61:00", "YYYY-ww-e HH:mm:ss"},
		{"2024-01-1 10:00:65", "YYYY-ww-e HH:mm:ss"},
	} {
		if _, _, ok := parseESWeekDatePatternR63(bad.in, bad.pat); ok {
			t.Fatalf("expected parseESWeekDatePatternR63 failure for (%q, %q)", bad.in, bad.pat)
		}
	}

	// 2. translateLocalizedDateInput & translateLocalizedDateInputForPattern
	if got := translateLocalizedDateInput("lun. 15 févr. 2024", ""); got != "lun. 15 févr. 2024" {
		t.Fatalf("expected empty locale passthrough, got %q", got)
	}
	if got := translateLocalizedDateInput("Mon 15 Feb", "en_US"); got != "Mon 15 Feb" {
		t.Fatalf("expected non-fr locale passthrough, got %q", got)
	}
	if got := translateLocalizedDateInput("lundi 15 février 2024", "fr-FR"); got != "Mon 15 Feb 2024" {
		t.Fatalf("unexpected short French translation: %q", got)
	}
	if got := translateLocalizedDateInputForPattern("dimanche 31 décembre 2023", "fr", "EEEE dd MMMM yyyy"); got != "Sunday 31 December 2023" {
		t.Fatalf("unexpected full French translation: %q", got)
	}
	for _, frCase := range []string{
		"mar. janv.", "mer. mars", "jeu. avr.", "ven. mai", "sam. juin", "juil. août", "sept. oct. nov.",
	} {
		if out := translateLocalizedDateInputForPattern(frCase, "fr", "E MMM"); out == frCase {
			t.Fatalf("expected translation for %q, got unchanged", frCase)
		}
	}

	// 3. replaceNullsAtPathInMap
	mNull := map[string]any{
		"flat.leaf": nil,
		"single":    []any{nil, "ok"},
		"nested.sub": map[string]any{
			"leaf": nil,
		},
		"arr": map[string]any{
			"items": []any{map[string]any{"x": nil}, "scalar"},
		},
	}
	if !replaceNullsAtPathInMap(mNull, []string{"flat", "leaf"}, "DEF") || mNull["flat.leaf"] != "DEF" {
		t.Fatalf("expected flat dotted null replaced, got %#v", mNull)
	}
	if !replaceNullsAtPathInMap(mNull, []string{"single"}, "DEF") {
		t.Fatalf("expected single slice null replaced, got %#v", mNull["single"])
	}
	if !replaceNullsAtPathInMap(mNull, []string{"nested", "sub", "leaf"}, 99) || mNull["nested.sub"].(map[string]any)["leaf"] != 99 {
		t.Fatalf("expected nested dotted prefix null replaced, got %#v", mNull["nested.sub"])
	}
	if !replaceNullsAtPathInMap(mNull, []string{"arr", "items", "x"}, 0) {
		t.Fatalf("expected slice map null replaced, got %#v", mNull["arr"])
	}
	if replaceNullsAtPathInMap(nil, []string{"a"}, 1) || replaceNullsAtPathInMap(mNull, nil, 1) || replaceNullsAtPathInMap(mNull, []string{"missing", "x"}, 1) {
		t.Fatal("expected false for nil/missing replaceNullsAtPathInMap")
	}

	// 4. extractExcessDynamicFieldsToIgnoredSource & shouldPreserveSyntheticObjectArray
	var limSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"runtime": {"rt_f": {"type": "keyword"}},
		"properties": {
			"dis": {"enabled": false},
			"arr": {"properties": {"known": {"type": "keyword"}}},
			"dyn_false": {"dynamic": false, "properties": {"a": {"type": "keyword"}}}
		}
	}`), &limSpec)
	limIdx := CompileIndexSchema("es_db", "r65_lim", &limSpec)
	limIdx.IgnoreDynamicBeyondLimit = true
	limIdx.NestedRoots["nest_root"] = "nest_root"
	docExcess := map[string]any{
		"_id":   "skip",
		"dis":   map[string]any{"kept": 1},
		"rt_f":  "runtime_val",
		"empty": map[string]any{},
		"arr": []any{
			map[string]any{"known": "k1", "extra": 123},
			"non_map",
		},
		"extra_top": "boom",
	}
	excess := extractExcessDynamicFieldsToIgnoredSource(limIdx, docExcess)
	if excess["extra_top"] != "boom" {
		t.Fatalf("expected extra_top extracted, got %#v", excess)
	}
	if _, hasRT := excess["rt_f"]; hasRT {
		t.Fatalf("expected runtime field excluded from excess ignored source, got %#v", excess)
	}
	if arrEx, ok := excess["arr"].([]any); !ok || len(arrEx) != 2 {
		t.Fatalf("expected array excess ignored entries, got %#v", excess["arr"])
	}
	if !shouldPreserveSyntheticObjectArray(limIdx, "dyn_false", nil) {
		t.Fatal("expected dynamic:false parent preserved by shouldPreserveSyntheticObjectArray")
	}
	if !shouldPreserveSyntheticObjectArray(limIdx, "arr", []any{map[string]any{"unmapped_sub": 1}}) {
		t.Fatal("expected IgnoreDynamicBeyondLimit unmapped sub-element preserved")
	}

	// 5. syntheticNumericOrderVal
	if v, ok := syntheticNumericOrderVal(uint64(9)); !ok || v != 9 {
		t.Fatalf("unexpected uint64 order val: %v %v", v, ok)
	}
	if v, ok := syntheticNumericOrderVal(float32(3.5)); !ok || math.Abs(v-3.5) > 1e-6 {
		t.Fatalf("unexpected float32 order val: %v %v", v, ok)
	}
	if _, ok := syntheticNumericOrderVal("not_num"); ok {
		t.Fatal("expected false for string syntheticNumericOrderVal")
	}

	// 6. diagnoseDateNanosOutOfRangeError + CausedBy
	dnDefault := FieldBinding{ESFieldPath: "dn", ESType: "date_nanos"}
	dnCustomFR := FieldBinding{ESFieldPath: "dn", ESType: "date_nanos", Format: " ||dd MMM yyyy", Locale: "fr"}
	for _, tc := range []struct {
		raw any
		b   FieldBinding
	}{
		{"-10", dnDefault},
		{"9223372036855", dnDefault},
		{"18446744073709551615", dnDefault},
		{"1969-12-31T23:59:59Z", dnDefault},
		{"2262-04-11T23:47:16.854775808Z", dnDefault},
		{"15 février 1960", dnCustomFR},
		{"12 avril 2262", dnCustomFR},
	} {
		err := diagnoseDateNanosOutOfRangeError(tc.raw, tc.b)
		if err == nil {
			t.Fatalf("expected out-of-range StructuredParseError for %v", tc.raw)
		}
		spe, ok := err.(*StructuredParseError)
		if !ok {
			t.Fatalf("expected *StructuredParseError, got %T", err)
		}
		et, er := spe.CausedBy()
		if et != "illegal_argument_exception" || er == "" || spe.Error() == "" {
			t.Fatalf("unexpected CausedBy/Error on %v: et=%q er=%q err=%q", tc.raw, et, er, spe.Error())
		}
	}
	if err := diagnoseDateNanosOutOfRangeError("15 février 2024", dnCustomFR); err != nil {
		t.Fatalf("expected in-range French localized date valid, got %v", err)
	}
}

func TestRound65_PassthroughPriority(t *testing.T) {
	// 1. Valid distinct priorities including explicit 0 across nested/dotted paths,
	// plus SerializeFieldProperty, deepCloneFieldProperty, and DeepMergeMappingProperties.
	validJSON := `{
		"properties": {
			"attributes": {"type": "passthrough", "priority": 0},
			"scope": {
				"properties": {
					"attributes": {"type": "passthrough", "priority": 1}
				}
			},
			"resource.attributes": {"type": "passthrough", "priority": 2},
			"metrics": {"type": "passthrough", "priority": 3},
			"plain_pass": {"type": "passthrough"}
		}
	}`
	var validSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(validJSON), &validSpec); err != nil {
		t.Fatalf("unmarshal valid passthrough priorities: %v", err)
	}
	if validSpec.Properties["attributes"].Priority == nil || *validSpec.Properties["attributes"].Priority != 0 {
		t.Fatalf("expected attributes priority *0, got %v", validSpec.Properties["attributes"].Priority)
	}
	if validSpec.Properties["plain_pass"].Priority != nil {
		t.Fatalf("expected plain_pass priority nil, got %v", validSpec.Properties["plain_pass"].Priority)
	}
	if err := ValidateMappingSpec(&validSpec); err != nil {
		t.Fatalf("expected distinct passthrough priorities to pass ValidateMappingSpec, got %v", err)
	}

	serZero := SerializeFieldProperty(validSpec.Properties["attributes"])
	if p, ok := serZero["priority"]; !ok || p != 0 {
		t.Fatalf("SerializeFieldProperty must emit explicit priority 0, got %#v", serZero)
	}
	serNil := SerializeFieldProperty(validSpec.Properties["plain_pass"])
	if _, ok := serNil["priority"]; ok {
		t.Fatalf("SerializeFieldProperty must omit nil priority, got %#v", serNil)
	}

	cloned := deepCloneFieldProperty(validSpec.Properties["attributes"])
	if cloned.Priority == nil || *cloned.Priority != 0 {
		t.Fatalf("deepCloneFieldProperty lost *0 priority: %#v", cloned.Priority)
	}
	*cloned.Priority = 99
	if *validSpec.Properties["attributes"].Priority != 0 {
		t.Fatalf("mutating cloned Priority mutated original: %d", *validSpec.Properties["attributes"].Priority)
	}

	merged := DeepMergeMappingProperties(
		map[string]esast.FieldProperty{
			"attributes": validSpec.Properties["attributes"],
		},
		map[string]esast.FieldProperty{
			"metrics": validSpec.Properties["metrics"],
		},
	)
	if merged["attributes"].Priority == nil || *merged["attributes"].Priority != 0 {
		t.Fatalf("DeepMergeMappingProperties lost *0 priority: %#v", merged["attributes"].Priority)
	}
	if merged["metrics"].Priority == nil || *merged["metrics"].Priority != 3 {
		t.Fatalf("DeepMergeMappingProperties lost *3 priority: %#v", merged["metrics"].Priority)
	}

	// 2. Duplicate passthrough priority across attributes and resource.attributes (data_stream/150_tsdb.yml:936-960).
	dupJSON := `{
		"properties": {
			"attributes": {"type": "passthrough", "priority": 1},
			"resource.attributes": {"type": "passthrough", "priority": 1}
		}
	}`
	var dupSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(dupJSON), &dupSpec); err != nil {
		t.Fatalf("unmarshal dup priority spec: %v", err)
	}
	err := ValidateMappingSpec(&dupSpec)
	if err == nil || !strings.Contains(err.Error(), "has a conflicting param") || !strings.Contains(err.Error(), "[priority: 1]") {
		t.Fatalf("expected conflicting param [priority: 1] error, got %v", err)
	}

	// 3. Invalid priority on non-passthrough field or negative priority on passthrough.
	p1 := 1
	if err := ValidateMappingSpec(&esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title": {Type: "keyword", Priority: &p1},
		},
	}); err == nil || !strings.Contains(err.Error(), "priority") {
		t.Fatalf("expected error for priority on keyword field, got %v", err)
	}
	neg := -1
	if err := ValidateMappingSpec(&esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"attributes": {Type: "passthrough", Priority: &neg},
		},
	}); err == nil || !strings.Contains(err.Error(), "[priority] must be >= 0") {
		t.Fatalf("expected >= 0 error for negative priority, got %v", err)
	}

	// 4. ValidateMappingUpdateCompatibility rejects priority mutation and newly conflicting priority across fields.
	p0 := 0
	p2 := 2
	oldSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"attributes": {Type: "passthrough", Priority: &p0},
		},
	}
	if err := ValidateMappingUpdateCompatibility(oldSpec, &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"attributes": {Type: "passthrough", Priority: &p2},
		},
	}); err == nil || !strings.Contains(err.Error(), "cannot update parameter [priority] from [0] to [2]") {
		t.Fatalf("expected priority update conflict error, got %v", err)
	}
	if err := ValidateMappingUpdateCompatibility(oldSpec, &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"resource": {
				Type: "object",
				Properties: map[string]esast.FieldProperty{
					"attributes": {Type: "passthrough", Priority: &p0},
				},
			},
		},
	}); err == nil || !strings.Contains(err.Error(), "has a conflicting param") {
		t.Fatalf("expected conflicting param error when adding duplicate passthrough priority via put_mapping, got %v", err)
	}

	// 5. Dynamic template with passthrough priority preserves cleanly through ValidateMappingSpec.
	dtJSON := `{
		"dynamic_templates": [
			{
				"attrs": {
					"path_match": "attributes*",
					"mapping": {"type": "passthrough", "priority": 2}
				}
			}
		]
	}`
	var dtSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(dtJSON), &dtSpec); err != nil {
		t.Fatalf("unmarshal dynamic_templates priority spec: %v", err)
	}
	if err := ValidateMappingSpec(&dtSpec); err != nil {
		t.Fatalf("expected dynamic_templates with passthrough priority to validate cleanly, got %v", err)
	}
}

func TestRound65Wave3CTimestampMappingAndPassthroughTSDB(t *testing.T) {
	// 1. _data_stream_timestamp validation + TSDB rules
	if err := ValidateMappingSpec(&esast.MappingSpec{DataStreamTimestamp: "enabled"}); err == nil || !strings.Contains(err.Error(), "[_data_stream_timestamp] config must be an object") {
		t.Fatalf("expected non-object _data_stream_timestamp error, got %v", err)
	}
	if err := ValidateTSDBMapping(&esast.MappingSpec{DataStreamTimestamp: map[string]any{"enabled": false}}, []string{"metricset"}); err == nil || !strings.Contains(err.Error(), "[_data_stream_timestamp] meta field has been disabled") {
		t.Fatalf("expected disabled _data_stream_timestamp error, got %v", err)
	}
	if err := ValidateTSDBMapping(&esast.MappingSpec{Properties: map[string]esast.FieldProperty{"@timestamp": {Type: "long"}}}, []string{"metricset"}); err == nil || !strings.Contains(err.Error(), "is of type [long], but [date,date_nanos] is expected") {
		t.Fatalf("expected wrong @timestamp type error, got %v", err)
	}
	trueVal := true
	if err := ValidateTSDBMapping(&esast.MappingSpec{
		Runtime:    map[string]esast.FieldProperty{"@timestamp": {Type: "date"}},
		Properties: map[string]esast.FieldProperty{"@timestamp": {Type: "date"}, "metricset": {Type: "keyword", TimeSeriesDimension: &trueVal}},
	}, []string{"metricset"}); err == nil || !strings.Contains(err.Error(), "docvalues not found for index sort field:[@timestamp]") {
		t.Fatalf("expected @timestamp runtime rejection, got %v", err)
	}
	if err := ValidateTSDBMapping(&esast.MappingSpec{
		Source:     map[string]any{"includes": []any{"a"}},
		Properties: map[string]esast.FieldProperty{"@timestamp": {Type: "date"}, "metricset": {Type: "keyword", TimeSeriesDimension: &trueVal}},
	}, []string{"metricset"}); err == nil || !strings.Contains(err.Error(), "filtering the stored _source is incompatible with synthetic source") {
		t.Fatalf("expected _source.includes TSDB rejection, got %v", err)
	}

	// 2. ApplyIndexModeDefaults auto-adds @timestamp + _data_stream_timestamp
	var autoTSDB esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"metricset":{"type":"keyword","time_series_dimension":true}}}`), &autoTSDB)
	idxTSDB := CompileIndexSchema("es_db", "r65_tsdb", &autoTSDB)
	idxTSDB.IndexMode = "time_series"
	ApplyIndexModeDefaults(idxTSDB)
	ser := SerializeMappings(idxTSDB)
	dstMap, _ := ser["_data_stream_timestamp"].(map[string]any)
	if enabled, _ := dstMap["enabled"].(bool); !enabled {
		t.Fatalf("expected _data_stream_timestamp.enabled=true in serialized TSDB mapping, got %+v", ser)
	}
	if _, hasTS := idxTSDB.Fields["@timestamp"]; !hasTS {
		t.Fatal("expected @timestamp field auto-added by ApplyIndexModeDefaults")
	}
	if _, _, _, _, err := ComputeTSDBIdentityWithRoutingHash(idxTSDB, map[string]any{"metricset": "pod"}, nil); err == nil || !strings.Contains(err.Error(), "data stream timestamp field [@timestamp] is missing") {
		t.Fatalf("expected data stream timestamp missing error, got %v", err)
	}

	// 3. ignore_above does NOT suppress distinct _tsid hashing on keyword dimensions
	var iaSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"attributes": {
				"type": "passthrough",
				"time_series_dimension": true,
				"priority": 0,
				"properties": {
					"kw_ignored": {"type": "keyword", "ignore_above": 2}
				}
			}
		}
	}`), &iaSpec)
	iaIdx := CompileIndexSchema("es_db", "r65_ia", &iaSpec)
	iaIdx.IndexMode = "time_series"
	ApplyIndexModeDefaults(iaIdx)
	tsid1, _, _, _, err1 := ComputeTSDBIdentityWithRoutingHash(iaIdx, map[string]any{"@timestamp": "2023-09-01T00:00:00Z", "attributes": map[string]any{"kw_ignored": "ignored"}}, nil)
	tsid2, _, _, _, err2 := ComputeTSDBIdentityWithRoutingHash(iaIdx, map[string]any{"@timestamp": "2023-09-01T00:00:00Z", "attributes": map[string]any{"kw_ignored": "ignored too"}}, nil)
	if err1 != nil || err2 != nil || tsid1 == "" || tsid1 == tsid2 {
		t.Fatalf("expected distinct non-empty _tsid beyond ignore_above, got tsid1=%q(%v) tsid2=%q(%v)", tsid1, err1, tsid2, err2)
	}

	// 4. Passthrough dynamic inference, priority conflict winner, and concrete top-level preservation
	var passSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"body": {"type": "match_only_text"},
			"attributes": {"type": "passthrough", "dynamic": true, "time_series_dimension": true, "priority": 2},
			"resource_attributes": {"type": "passthrough", "dynamic": true, "time_series_dimension": true, "priority": 1}
		}
	}`), &passSpec)
	inferred := InferMappingFromSampleDocsES8([]json.RawMessage{json.RawMessage(`{
		"@timestamp": "2023-09-01T00:00:00Z",
		"body": "top",
		"attributes.dim": "A",
		"resource_attributes.dim": "C",
		"attributes": {"body": "attr"}
	}`)}, &passSpec)
	pIdx := CompileIndexSchema("es_db", "r65_pass", inferred)
	if dimB, ok := pIdx.Fields["dim"]; !ok || dimB.AliasTarget != "attributes.dim" {
		t.Fatalf("expected dim alias -> attributes.dim (priority 2 > 1), got %+v", dimB)
	}
	if bodyB, ok := pIdx.Fields["body"]; !ok || bodyB.IsPassthroughAlias || bodyB.ESType != "match_only_text" {
		t.Fatalf("expected concrete top-level body preserved without passthrough overwrite, got %+v", bodyB)
	}
}
