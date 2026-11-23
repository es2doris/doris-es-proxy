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
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound63_F29_RecursiveDeepCloneZeroSharedReferences(t *testing.T) {
	var spec esast.MappingSpec
	err := json.Unmarshal([]byte(`{
		"_size": {"enabled": true},
		"_meta": {"owner": "analytics", "nested": {"tags": ["a", "b"]}},
		"_source": {"mode": "synthetic", "includes": ["*"], "excludes": ["secret.*"]},
		"dynamic_templates": [
			{
				"strings_as_kw": {
					"match_mapping_type": "string",
					"mapping": {"type": "keyword", "meta": {"k": "v"}}
				}
			}
		],
		"runtime": {
			"lk": {
				"type": "lookup",
				"target_index": "users",
				"input_field": "uid",
				"target_field": "id",
				"fetch_fields": [{"field": "email", "format": "raw"}]
			}
		},
		"properties": {
			"scripted": {
				"type": "keyword",
				"script": {"source": "emit(params.p)", "params": {"p": "orig", "arr": ["x", "y"]}},
				"copy_to": ["all_kw"],
				"fielddata": {"format": "disabled"},
				"index_options": {"docs": true},
				"index_prefixes": {"min_chars": 2, "max_chars": 5},
				"relations": {"question": ["answer", "comment"]}
			},
			"all_kw": {"type": "keyword"},
			"vec": {
				"type": "dense_vector",
				"dims": 4,
				"index": true,
				"similarity": "cosine",
				"index_options": {"type": "int8_hnsw", "m": 16, "ef_construction": 100}
			},
			"agg_m": {
				"type": "aggregate_metric_double",
				"metrics": ["min", "max", "sum", "value_count"],
				"default_metric": "max"
			}
		}
	}`), &spec)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	orig := CompileIndexSchema("es_db", "r63_clone", &spec)
	cloned := orig.CloneIndexSchema()

	// Mutate nested maps/slices in `cloned` and verify `orig` is 100% untouched!
	cloned.RawMapping.Size["enabled"] = false
	cloned.RawMapping.Meta["nested"].(map[string]any)["tags"].([]any)[0] = "MUTATED"
	cloned.RawMapping.Source["includes"].([]any)[0] = "MUTATED_INC"
	cloned.RawMapping.DynamicTemplates[0]["strings_as_kw"].(map[string]any)["mapping"].(map[string]any)["type"] = "text"

	lkClone := cloned.RawMapping.Runtime["lk"]
	lkClone.FetchFields[0]["field"] = "MUTATED_FETCH"
	cloned.RawMapping.Runtime["lk"] = lkClone

	scClone := cloned.RawMapping.Properties["scripted"]
	scClone.Script.(map[string]any)["params"].(map[string]any)["p"] = "MUTATED_PARAM"
	scClone.Script.(map[string]any)["params"].(map[string]any)["arr"].([]any)[0] = "MUTATED_ARR"
	scClone.CopyTo.([]any)[0] = "MUTATED_COPY"
	scClone.Fielddata.(map[string]any)["format"] = "paged_bytes"
	scClone.IndexOptions.(map[string]any)["docs"] = false
	scClone.IndexPrefixes["min_chars"] = float64(99)
	scClone.Relations["question"].([]any)[0] = "MUTATED_REL"
	cloned.RawMapping.Properties["scripted"] = scClone

	amClone := cloned.RawMapping.Properties["agg_m"]
	amClone.Metrics[0] = "avg"
	cloned.RawMapping.Properties["agg_m"] = amClone

	vecBinding := cloned.Fields["vec"]
	vecBinding.VectorIndexOptions["m"] = 64
	cloned.Fields["vec"] = vecBinding

	// Verify `orig` retained every original value
	if orig.RawMapping.Size["enabled"] != true {
		t.Fatalf("orig Size mutated: %+v", orig.RawMapping.Size)
	}
	if orig.RawMapping.Meta["nested"].(map[string]any)["tags"].([]any)[0] != "a" {
		t.Fatalf("orig Meta nested slice mutated: %+v", orig.RawMapping.Meta)
	}
	if orig.RawMapping.Source["includes"].([]any)[0] != "*" {
		t.Fatalf("orig Source includes mutated: %+v", orig.RawMapping.Source)
	}
	if orig.RawMapping.DynamicTemplates[0]["strings_as_kw"].(map[string]any)["mapping"].(map[string]any)["type"] != "keyword" {
		t.Fatalf("orig DynamicTemplates[0] mutated: %+v", orig.RawMapping.DynamicTemplates)
	}
	if orig.RawMapping.Runtime["lk"].FetchFields[0]["field"] != "email" {
		t.Fatalf("orig Runtime lookup FetchFields mutated: %+v", orig.RawMapping.Runtime["lk"].FetchFields)
	}
	origSc := orig.RawMapping.Properties["scripted"]
	if origSc.Script.(map[string]any)["params"].(map[string]any)["p"] != "orig" ||
		origSc.Script.(map[string]any)["params"].(map[string]any)["arr"].([]any)[0] != "x" {
		t.Fatalf("orig Script params mutated: %+v", origSc.Script)
	}
	if origSc.CopyTo.([]any)[0] != "all_kw" {
		t.Fatalf("orig CopyTo mutated: %+v", origSc.CopyTo)
	}
	if origSc.Fielddata.(map[string]any)["format"] != "disabled" {
		t.Fatalf("orig Fielddata mutated: %+v", origSc.Fielddata)
	}
	if origSc.IndexOptions.(map[string]any)["docs"] != true {
		t.Fatalf("orig IndexOptions mutated: %+v", origSc.IndexOptions)
	}
	if origSc.IndexPrefixes["min_chars"] != float64(2) {
		t.Fatalf("orig IndexPrefixes mutated: %+v", origSc.IndexPrefixes)
	}
	if origSc.Relations["question"].([]any)[0] != "answer" {
		t.Fatalf("orig Relations mutated: %+v", origSc.Relations)
	}
	if orig.RawMapping.Properties["agg_m"].Metrics[0] != "min" {
		t.Fatalf("orig Metrics mutated: %+v", orig.RawMapping.Properties["agg_m"].Metrics)
	}
	if orig.Fields["vec"].VectorIndexOptions["m"] != 16 {
		t.Fatalf("orig Fields[vec].VectorIndexOptions mutated: %+v", orig.Fields["vec"].VectorIndexOptions)
	}

	// Verify direct deepCloneAny on []string and map[string]string
	inSS := []string{"s1", "s2"}
	outSS := deepCloneAny(inSS).([]string)
	outSS[0] = "changed"
	if inSS[0] != "s1" {
		t.Fatal("deepCloneAny([]string) shared slice backing array")
	}
	inMS := map[string]string{"k": "v"}
	outMS := deepCloneAny(inMS).(map[string]string)
	outMS["k"] = "changed"
	if inMS["k"] != "v" {
		t.Fatal("deepCloneAny(map[string]string) shared map")
	}
}

func TestRound63_F27_SchemaAwareScriptEvaluatorAndLookupSerialization(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"runtime": {
			"enrich_user": {
				"type": "lookup",
				"target_index": "users_idx",
				"input_field": "user_id",
				"target_field": "uid",
				"fetch_fields": [{"field": "country"}, {"field": "tier"}]
			}
		},
		"properties": {
			"user_id": {"type": "keyword"},
			"computed_tag": {"type": "keyword", "script": "emit('tag')"}
		}
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&spec); err != nil {
		t.Fatalf("ValidateMappingSpec with lookup runtime failed: %v", err)
	}
	idx := CompileIndexSchema("es_db", "orders_idx", &spec)

	// Verify SerializeMappings round-trips lookup runtime fields cleanly
	ser := SerializeMappings(idx)
	rtOut := ser["runtime"].(map[string]any)["enrich_user"].(map[string]any)
	if rtOut["target_index"] != "users_idx" || rtOut["input_field"] != "user_id" || rtOut["target_field"] != "uid" {
		t.Fatalf("unexpected serialized lookup runtime field: %+v", rtOut)
	}
	ffOut, ok := rtOut["fetch_fields"].([]map[string]any)
	if !ok || len(ffOut) != 2 || ffOut[0]["field"] != "country" {
		t.Fatalf("unexpected serialized fetch_fields: %#v", rtOut["fetch_fields"])
	}

	// Verify invalid lookup runtime field configs rejected
	for _, bad := range []string{
		`{"runtime":{"lk":{"type":"lookup","script":"emit(1)"}}}`,
		`{"runtime":{"lk":{"type":"lookup","input_field":"u","target_field":"id","fetch_fields":["a"]}}}`,
		`{"runtime":{"lk":{"type":"lookup","target_index":"t","target_field":"id","fetch_fields":["a"]}}}`,
		`{"runtime":{"lk":{"type":"lookup","target_index":"t","input_field":"u","fetch_fields":["a"]}}}`,
		`{"runtime":{"lk":{"type":"lookup","target_index":"t","input_field":"u","target_field":"id"}}}`,
	} {
		var badSpec esast.MappingSpec
		_ = json.Unmarshal([]byte(bad), &badSpec)
		if err := ValidateMappingSpec(&badSpec); err == nil {
			t.Fatalf("expected error for invalid lookup runtime spec %s", bad)
		}
	}

	// Verify RegisterIndexFieldScriptWithSchemaEvaluator takes precedence over legacy evaluator and receives `idx` directly!
	prevSchemaEval := GetIndexFieldScriptWithSchemaEvaluator()
	prevLegacyEval := GetIndexFieldScriptEvaluator()
	defer RegisterIndexFieldScriptWithSchemaEvaluator(prevSchemaEval)
	defer RegisterIndexFieldScriptEvaluator(prevLegacyEval)

	RegisterIndexFieldScriptEvaluator(func(fieldPath, esType string, scriptSpec any, onScriptError string, sourceDoc map[string]any) ([]any, error) {
		return []any{"LEGACY_SHOULD_NOT_WIN"}, nil
	})
	RegisterIndexFieldScriptWithSchemaEvaluator(func(idxSchema *IndexSchema, fieldPath, esType string, scriptSpec any, onScriptError string, sourceDoc map[string]any) ([]any, error) {
		if idxSchema == nil || idxSchema.IndexName != "orders_idx" {
			return nil, fmt.Errorf("missing expected IndexSchema")
		}
		return []any{"from_" + idxSchema.IndexName + "_" + fmt.Sprintf("%v", sourceDoc["user_id"])}, nil
	})

	shredded, err := ShredDocument(idx, "1", 1, false, []byte(`{"user_id":"u42"}`))
	if err != nil {
		t.Fatalf("ShredDocument with schema-aware script hook failed: %v", err)
	}
	var row map[string]any
	_ = json.Unmarshal(shredded, &row)
	gotTags, _ := row["f__computed_tag"].([]any)
	if len(gotTags) != 1 || gotTags[0] != "from_orders_idx_u42" {
		t.Fatalf("expected f__computed_tag=[\"from_orders_idx_u42\"], got %#v", row["f__computed_tag"])
	}
}

func TestRound63_F5_SyntheticSourceFidelity(t *testing.T) {
	// 1. Invalid `_source.mode` rejected even when `properties` is empty
	var badSrcSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"_source":{"mode":"bogus"}}`), &badSrcSpec)
	if err := ValidateMappingSpec(&badSrcSpec); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("expected 400 mapper_parsing_exception for invalid _source.mode, got %v", err)
	}

	// 2. `ignore_dynamic_beyond_limit: true` caps dynamic fields & merges `_ignored_source` in synthetic `_source`
	val, present, err := ExtractIgnoreDynamicBeyondLimitSetting(map[string]any{
		"index": map[string]any{"mapping.total_fields.ignore_dynamic_beyond_limit": "true"},
	})
	if err != nil || !present || !val {
		t.Fatalf("ExtractIgnoreDynamicBeyondLimitSetting failed: val=%v present=%v err=%v", val, present, err)
	}
	var dynBase esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"f1": {"type": "keyword"}
		}
	}`), &dynBase)
	dynIdx := CompileIndexSchema("es_db", "r63_ign_dyn", &dynBase)
	dynIdx.ES8Mode = true
	dynIdx.MaxTotalFields = 2
	dynIdx.IgnoreDynamicBeyondLimit = true

	sampleDoc := json.RawMessage(`{"f1":"v1","f2":10,"f3":"excess_str","f4":{"nested_excess":99}}`)
	cappedSpec := InferMappingFromSampleDocsForSchema(dynIdx, []json.RawMessage{sampleDoc})
	if err := ValidateMappingLimits(dynIdx, cappedSpec); err != nil {
		t.Fatalf("expected ValidateMappingLimits to cap & pass with IgnoreDynamicBeyondLimit=true, got: %v", err)
	}
	if CountTotalMappingFields(cappedSpec) > 2 {
		t.Fatalf("expected total fields <= 2, got %d (%+v)", CountTotalMappingFields(cappedSpec), cappedSpec.Properties)
	}
	dynIdx2 := CompileIndexSchema("es_db", "r63_ign_dyn", cappedSpec)
	dynIdx2.CopyIndexMappingSettingsFrom(dynIdx)

	shredBytes, err := ShredDocument(dynIdx2, "1", 1, false, sampleDoc)
	if err != nil {
		t.Fatalf("ShredDocument with IgnoreDynamicBeyondLimit failed: %v", err)
	}
	var row map[string]any
	rowDec := json.NewDecoder(bytes.NewReader(shredBytes))
	rowDec.UseNumber()
	_ = rowDec.Decode(&row)
	// Reconstruct purely from `shreddedRow` (`rawDoc == nil`) to verify `_doc["__ignored_source"]` round-trip!
	rowWithoutSource := map[string]any{"_doc": row["_doc"]}
	reconstructedFromDoc := ReconstructSyntheticSource(dynIdx2, nil, rowWithoutSource)
	if reconstructedFromDoc["f1"] != "v1" || reconstructedFromDoc["f2"] != int64(10) || reconstructedFromDoc["f3"] != "excess_str" {
		t.Fatalf("expected excess dynamic fields merged from __ignored_source, got %#v", reconstructedFromDoc)
	}
	f4Map, ok := reconstructedFromDoc["f4"].(map[string]any)
	if !ok || f4Map["nested_excess"] != int64(99) {
		t.Fatalf("expected f4.nested_excess=99 from __ignored_source, got %#v", reconstructedFromDoc["f4"])
	}

	// 3. Reject JSON object `{...}` passed to scalar fields even when `ignore_malformed: true` (`get/100_synthetic_source.yml:769`)
	var scalarIgnoreSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"ip": {"type": "ip", "ignore_malformed": true},
			"num": {"type": "long", "ignore_malformed": true},
			"flag": {"type": "boolean", "ignore_malformed": true}
		}
	}`), &scalarIgnoreSpec)
	scalarIdx := CompileIndexSchema("es_db", "r63_scalar_obj", &scalarIgnoreSpec)
	scalarIdx.ES8Mode = true
	for _, badDoc := range []string{
		`{"ip": {"object": "wow"}}`,
		`{"ip": ["10.0.0.1", {"object": "wow"}]}`,
		`{"num": {"nested": 1}}`,
		`{"flag": {"nested": true}}`,
	} {
		if _, err := ShredDocument(scalarIdx, "bad", 1, false, []byte(badDoc)); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
			t.Fatalf("expected mapper_parsing_exception for object on scalar field %s, got %v", badDoc, err)
		}
	}

	// 4. `flattened` dedup & sort + object array merge + `ip_range` null bounds + empty `rank_features` + `search_as_you_type` order + `constant_keyword` omission + multi-value `sparse_vector` + `date` `.000Z` + exact `float`
	var richSynthSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"flat": {"type": "flattened", "ignore_above": 10},
			"ipr": {"type": "ip_range"},
			"rfs": {"type": "rank_features"},
			"sayt": {"type": "search_as_you_type"},
			"ck": {"type": "constant_keyword", "value": "fixed_val"},
			"sv": {"type": "sparse_vector"},
			"ts": {"type": "date"},
			"flt": {"type": "float"}
		}
	}`), &richSynthSpec); err != nil {
		t.Fatal(err)
	}
	richIdx := CompileIndexSchema("es_db", "r63_rich_synth", &richSynthSpec)
	richIdx.ES8Mode = true

	richDoc := `{
		"flat": {
			"list1": ["789", "1011", "1213", "1213", "very_long_ignored_val"],
			"num": 42,
			"objs": [{"id": 1, "tag": "b"}, {"id": 2, "tag": "a"}]
		},
		"ipr": [{"lte": "10.10.10.10"}, {"gte": "2001:db8::"}],
		"rfs": [],
		"sayt": ["quick brown", "fox", "jumps"],
		"sv": [{"t1": 0.5, "t2": 1.25}, {"t1": 1.5, "t2": 0.2}],
		"ts": "2024-02-12T10:30:00Z",
		"flt": 300.33
	}`
	shredRich, err := ShredDocument(richIdx, "1", 1, false, []byte(richDoc))
	if err != nil {
		t.Fatalf("ShredDocument rich synthetic failed: %v", err)
	}
	var richRow map[string]any
	_ = json.Unmarshal(shredRich, &richRow)
	var gotRich map[string]any
	dec := json.NewDecoder(strings.NewReader(richRow["_source"].(string)))
	dec.UseNumber()
	_ = dec.Decode(&gotRich)

	// constant_keyword omitted when absent from doc; empty rank_features `[]` preserved (`rank_features/20_synthetic_source.yml:54`)
	if _, hasCK := gotRich["ck"]; hasCK {
		t.Fatalf("expected absent constant_keyword omitted from synthetic _source, got %#v", gotRich["ck"])
	}
	if rfsSlice, okRFS := gotRich["rfs"].([]any); !okRFS || len(rfsSlice) != 0 {
		t.Fatalf("expected empty rank_features `[]` preserved in synthetic _source, got %#v", gotRich["rfs"])
	}
	// search_as_you_type preserves exact input array order
	if !reflect.DeepEqual(gotRich["sayt"], []any{"quick brown", "fox", "jumps"}) {
		t.Fatalf("expected search_as_you_type array order preserved, got %#v", gotRich["sayt"])
	}
	// flattened deduplicates & sorts doc-values strings, appends ignore_above after, stringifies scalars, merges object arrays
	flatOut := gotRich["flat"].(map[string]any)
	if flatOut["num"] != "42" {
		t.Fatalf("expected flattened scalar stringified to \"42\", got %#v", flatOut["num"])
	}
	wantList1 := []any{"1011", "1213", "789", "very_long_ignored_val"}
	if !reflect.DeepEqual(flatOut["list1"], wantList1) {
		t.Fatalf("expected flattened list1=%v, got %#v", wantList1, flatOut["list1"])
	}
	objsOut := flatOut["objs"].(map[string]any)
	if !reflect.DeepEqual(objsOut["id"], []any{"1", "2"}) || !reflect.DeepEqual(objsOut["tag"], []any{"a", "b"}) {
		t.Fatalf("unexpected flattened merged object array: %#v", objsOut)
	}
	// ip_range preserves explicit null bounds
	iprSlice, ok := gotRich["ipr"].([]any)
	if !ok || len(iprSlice) != 2 {
		t.Fatalf("expected 2 ip_range items, got %#v", gotRich["ipr"])
	}
	r0 := iprSlice[0].(map[string]any)
	r1 := iprSlice[1].(map[string]any)
	if r0["gte"] != nil || r0["lte"] != "10.10.10.10" || r1["gte"] != "2001:db8::" || r1["lte"] != nil {
		t.Fatalf("expected null bounds on ip_range, got r0=%#v r1=%#v", r0, r1)
	}
	// multi-value sparse_vector merges keeping max positive weight
	svOut := gotRich["sv"].(map[string]any)
	if svOut["t1"] != json.Number("1.5") || svOut["t2"] != json.Number("1.25") {
		t.Fatalf("unexpected merged sparse_vector in synthetic _source: %#v", svOut)
	}
	// date normalized to .000Z & float avoids 300.3299865722656 artifact
	if gotRich["ts"] != "2024-02-12T10:30:00.000Z" {
		t.Fatalf("expected normalized .000Z date, got %#v", gotRich["ts"])
	}
	if gotRich["flt"] != json.Number("300.33") {
		t.Fatalf("expected exact float 300.33 in synthetic _source, got %#v", gotRich["flt"])
	}
}

func TestRound63_F4_TSDBExactHashesMultiDimsRoutingAndLogsDBSort(t *testing.T) {
	// 1. Exact upstream `_tsid` for `unsigned_long` (`mapper-unsigned-long/70_time_series.yml`)
	var ulSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"metricset": {"type": "keyword", "time_series_dimension": true},
			"ul": {"type": "unsigned_long", "time_series_dimension": true}
		}
	}`), &ulSpec)
	ulIdx := CompileIndexSchema("es_db", "ts_ul", &ulSpec)
	ulIdx.IndexMode = "time_series"

	for _, tc := range []struct {
		ul       string
		wantTSID string
	}{
		{"9223372036854775807", "KEgPmt8JTKe7WA6iB8FLYKbvei62ccUzlcoJwx6Ltf34ddg5heNyQIA"},
		{"9223372036854775808", "KEgPmt8JTKe7WA6iB8FLYKbvei62xbkMpink-I2ckSWnx-vXF67HQ-U"},
		{"18446744073709551614", "KEgPmt8JTKe7WA6iB8FLYKbvei62erJQlP1_gz9tjb7S743_9tpXyfM"},
		{"18446744073709551615", "KEgPmt8JTKe7WA6iB8FLYKbvei62VWzfUKafNxTRdD8v6_Z8PbKJ6TQ"},
	} {
		var doc map[string]any
		dec := json.NewDecoder(strings.NewReader(fmt.Sprintf(`{"@timestamp":"2021-04-28T18:35:24.467Z","metricset":"aa","ul":%s}`, tc.ul)))
		dec.UseNumber()
		_ = dec.Decode(&doc)
		gotTSID, _, _, _, err := ComputeTSDBIdentityWithRoutingHash(ulIdx, doc, nil)
		if err != nil || gotTSID != tc.wantTSID {
			t.Fatalf("ul=%s: expected exact ES _tsid=%s, got %s (err=%v)", tc.ul, tc.wantTSID, gotTSID, err)
		}
	}

	// 2. Exact upstream `_tsid` for `ip` (`tsdb/70_dimension_types.yml:574,577`)
	var ipSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"ip": {"type": "ip", "time_series_dimension": true},
			"metricset": {"type": "keyword", "time_series_dimension": true}
		}
	}`), &ipSpec)
	ipIdx := CompileIndexSchema("es_db", "ts_ip", &ipSpec)
	ipIdx.IndexMode = "time_series"
	for _, tc := range []struct {
		ip       string
		wantTSID string
	}{
		{"10.10.1.1", "KLVrd7E8oZLyd-tfSm0H6jDaaOFK73outkqpG8R65Gm4VUhpyuc11zw"},
		{"::ffff:10.10.1.1", "KLVrd7E8oZLyd-tfSm0H6jDaaOFK73outkqpG8R65Gm4VUhpyuc11zw"},
		{"2001:db8:85a3::8a2e:370:7334", "KLVrd7E8oZLyd-tfSm0H6jDYzb-v73outosB-eDb_nzTrIVsJFVQR2c"},
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "KLVrd7E8oZLyd-tfSm0H6jDYzb-v73outosB-eDb_nzTrIVsJFVQR2c"},
	} {
		var doc map[string]any
		_ = json.Unmarshal([]byte(fmt.Sprintf(`{"@timestamp":"2021-04-28T18:35:24.467Z","metricset":"aa","ip":%q}`, tc.ip)), &doc)
		gotTSID, _, _, _, err := ComputeTSDBIdentityWithRoutingHash(ipIdx, doc, nil)
		if err != nil || gotTSID != tc.wantTSID {
			t.Fatalf("ip=%s: expected exact ES _tsid=%s, got %s (err=%v)", tc.ip, tc.wantTSID, gotTSID, err)
		}
	}

	// 3. Multi-value canonically sorted & deduplicated dimensions (including flattened object arrays) produce identical _tsid & _id regardless of input order
	var mvSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"tags": {"type": "keyword", "time_series_dimension": true},
			"meta": {"type": "flattened", "time_series_dimensions": ["env"]}
		}
	}`), &mvSpec)
	mvIdx := CompileIndexSchema("es_db", "ts_mv", &mvSpec)
	mvIdx.IndexMode = "time_series"

	var d1, d2 map[string]any
	_ = json.Unmarshal([]byte(`{"@timestamp":"2021-04-28T18:50:04.467Z","tags":["z","a","z"],"meta":[{"env":"prod"},{"env":"canary"}]}`), &d1)
	_ = json.Unmarshal([]byte(`{"@timestamp":"2021-04-28T18:50:04.467Z","tags":["a","z"],"meta":[{"env":"canary"},{"env":"prod"}]}`), &d2)
	tsid1, id1, rk1, _, err1 := ComputeTSDBIdentityWithRoutingHash(mvIdx, d1, nil)
	tsid2, id2, rk2, _, err2 := ComputeTSDBIdentityWithRoutingHash(mvIdx, d2, nil)
	if err1 != nil || err2 != nil || tsid1 != tsid2 || id1 != id2 || rk1 != rk2 {
		t.Fatalf("expected identical TSDB identity for reordered/duplicate multi-value dims: (%s,%s,%s,%v) vs (%s,%s,%s,%v)",
			tsid1, id1, rk1, err1, tsid2, id2, rk2, err2)
	}

	// 4. `logsdb` explicit `index.sort.field` validation (`logsdb/10_settings.yml:195,439`)
	var logsSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"host.name": {"type": "keyword"},
			"nested": {
				"type": "nested",
				"properties": {"keywords": {"type": "keyword"}}
			}
		}
	}`), &logsSpec)
	logsIdx := CompileIndexSchema("es_db", "logs_test", &logsSpec)
	logsIdx.IndexMode = "logsdb"
	ApplyIndexModeDefaults(logsIdx)

	errMissingSort := ValidateIndexSortFields(logsIdx, map[string]any{
		"index": map[string]any{"sort": map[string]any{"field": []any{"host_name"}}},
	})
	if errMissingSort == nil || !strings.Contains(errMissingSort.Error(), "unknown index sort field:[host_name]") {
		t.Fatalf("expected 'unknown index sort field:[host_name]', got %v", errMissingSort)
	}
	errNestedSort := ValidateIndexSortFields(logsIdx, map[string]any{
		"index": map[string]any{"sort": map[string]any{"field": []any{"host.name", "nested", "@timestamp"}}},
	})
	if errNestedSort == nil || !strings.Contains(errNestedSort.Error(), "cannot apply index sort to field [nested] under nested object [nested]") {
		t.Fatalf("expected nested sort error, got %v", errNestedSort)
	}
	if errOK := ValidateIndexSortFields(logsIdx, map[string]any{
		"index": map[string]any{"sort": map[string]any{"field": []any{"host.name", "@timestamp"}}},
	}); errOK != nil {
		t.Fatalf("expected valid logsdb sort fields to pass, got %v", errOK)
	}
}

func TestRound63_F11_HexByteAutoDimsAndNullValues(t *testing.T) {
	// 1. Hex `byte` dynamic Auto-Dims works for BOTH `index: false` and `index: true` (`170_knn_search_hex_encoded_byte_vectors.yml:209-210`)
	var hexSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"my_vector_byte": {"type": "dense_vector", "index": false, "element_type": "byte"},
			"my_vector_byte_indexed": {"type": "dense_vector", "index": true, "element_type": "byte", "similarity": "l2_norm"}
		}
	}`), &hexSpec)
	hexIdx := CompileIndexSchema("es_db", "knn_hex_dyn", &hexSpec)
	hexIdx.ES8Mode = true

	rawHexDoc := []byte(`{"my_vector_byte":"807f0a","my_vector_byte_indexed":"807f0a"}`)
	locked, dynVecs, err := InspectAutoDimsAndDynamicVectors(hexIdx, [][]byte{rawHexDoc})
	if err != nil {
		t.Fatalf("InspectAutoDimsAndDynamicVectors failed: %v", err)
	}
	if locked["my_vector_byte"] != 3 || locked["my_vector_byte_indexed"] != 3 {
		t.Fatalf("expected both indexed and non-indexed byte vectors to lock dims=3, got %+v", locked)
	}
	updatedHexIdx, _ := hexIdx.CloneWithAutoDimsAndDynamicVectors(locked, dynVecs)
	serHex := SerializeMappings(updatedHexIdx)
	propsHex := serHex["properties"].(map[string]any)
	if propsHex["my_vector_byte"].(map[string]any)["dims"] != 3 || propsHex["my_vector_byte_indexed"].(map[string]any)["dims"] != 3 {
		t.Fatalf("expected serialized mapping dims=3 on both vectors, got %+v", propsHex)
	}
	// Dimension mismatch in ES8Mode returns `document_parsing_exception` (`painless/160_*` & `165_*`)
	if _, err := ShredDocument(updatedHexIdx, "bad", 1, false, []byte(`{"my_vector_byte":"807f"}`)); err == nil || !strings.HasPrefix(err.Error(), "document_parsing_exception:") {
		t.Fatalf("expected document_parsing_exception on ES8 vector dim mismatch, got %v", err)
	}

	// 2. `null_value` on `unsigned_long` (`17446744073709551615`, null + empty string `""`), `geo_point`, and `rank_feature` (`V8-5`)
	var nvSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"ul": {"type": "unsigned_long", "null_value": 17446744073709551615},
			"gp": {"type": "geo_point", "null_value": {"lat": 28.4195, "lon": -81.5811}},
			"rf": {"type": "rank_feature", "null_value": 100}
		}
	}`), &nvSpec); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMappingSpec(&nvSpec); err != nil {
		t.Fatalf("ValidateMappingSpec for null_value failed: %v", err)
	}
	nvIdx := CompileIndexSchema("es_db", "r63_nv", &nvSpec)
	nvIdx.ES8Mode = true

	// Explicit null on all 3
	shredNull, err := ShredDocument(nvIdx, "1", 1, false, []byte(`{"ul":null,"gp":null,"rf":null}`))
	if err != nil {
		t.Fatalf("ShredDocument null failed: %v", err)
	}
	var rowNull map[string]any
	decN := json.NewDecoder(bytes.NewReader(shredNull))
	decN.UseNumber()
	_ = decN.Decode(&rowNull)
	if fmt.Sprintf("%v", rowNull["f__ul"]) != "17446744073709551615" {
		t.Fatalf("expected exact uint64 f__ul=17446744073709551615, got %v", rowNull["f__ul"])
	}
	if rowNull["f__gp"] != "28.4195,-81.5811" {
		t.Fatalf("expected f__gp=28.4195,-81.5811, got %v", rowNull["f__gp"])
	}
	if rowNull["f__rf"] != json.Number("100") {
		t.Fatalf("expected f__rf=100, got %v", rowNull["f__rf"])
	}

	// Empty string `""` on `unsigned_long` substitutes `null_value` (`20_null_value.yml:27`)
	shredEmptyUL, err := ShredDocument(nvIdx, "2", 1, false, []byte(`{"ul":""}`))
	if err != nil {
		t.Fatalf("ShredDocument ul=\"\" failed: %v", err)
	}
	var rowEmptyUL map[string]any
	decE := json.NewDecoder(bytes.NewReader(shredEmptyUL))
	decE.UseNumber()
	_ = decE.Decode(&rowEmptyUL)
	if fmt.Sprintf("%v", rowEmptyUL["f__ul"]) != "17446744073709551615" {
		t.Fatalf("expected ul=\"\" to substitute null_value 17446744073709551615, got %v", rowEmptyUL["f__ul"])
	}

	// Empty string `""` on `rank_feature` fails with mapper_parsing_exception (`rank_feature/20_null_value.yml:60`)
	if _, err := ShredDocument(nvIdx, "3", 1, false, []byte(`{"rf":""}`)); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("expected mapper_parsing_exception for empty string on rank_feature, got %v", err)
	}
}

func TestRound63_F1_SizeMurmur3CountedKeywordAggregateMetricAndAnnotatedText(t *testing.T) {
	// 1. `_size`, `murmur3`, `counted_keyword`, `aggregate_metric_double`, and `annotated_text`
	var spec esast.MappingSpec
	err := json.Unmarshal([]byte(`{
		"_size": {"enabled": true},
		"_source": {"mode": "synthetic"},
		"properties": {
			"foo": {
				"type": "keyword",
				"fields": {
					"hash": {"type": "murmur3"}
				}
			},
			"events": {"type": "counted_keyword", "index": false},
			"latency": {
				"type": "aggregate_metric_double",
				"metrics": ["min", "max", "sum", "value_count", "avg"],
				"default_metric": "avg"
			},
			"notes_stored": {"type": "annotated_text", "store": true},
			"notes_kw": {
				"type": "annotated_text",
				"fields": {"keyword": {"type": "keyword"}}
			}
		}
	}`), &spec)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if err := ValidateMappingSpec(&spec); err != nil {
		t.Fatalf("ValidateMappingSpec failed: %v", err)
	}

	idx := CompileIndexSchema("es_db", "r63_mappers", &spec)
	idx.ES8Mode = true

	// Verify DDL emits `f___size`, `f__foo__hash`, `f__events` ARRAY<STRING>, and `f__latency` + `__min/__max/__sum/__value_count`
	ddl := GenerateCreateTableDDL(idx)
	for _, wantCol := range []string{
		"`f___size` BIGINT NULL",
		"`f__foo__hash` BIGINT NULL",
		"`f__events` ARRAY<STRING> NULL",
		"`f__latency` DOUBLE NULL",
		"`f__latency__min` DOUBLE NULL",
		"`f__latency__max` DOUBLE NULL",
		"`f__latency__sum` DOUBLE NULL",
		"`f__latency__value_count` BIGINT NULL",
	} {
		if !strings.Contains(ddl, wantCol) {
			t.Fatalf("expected DDL to contain %s, got:\n%s", wantCol, ddl)
		}
	}
	if sizeB := idx.ResolveField("_size"); sizeB.ColumnName != "f___size" || sizeB.DorisType != DorisBigInt {
		t.Fatalf("unexpected _size ResolveField: %+v", sizeB)
	}

	rawPayload := []byte(`{"foo":"a quick brown fox","events":["b","a","b"],"latency":{"min":10.5,"max":30.5,"sum":41.0,"value_count":2},"notes_stored":["world","hello","world"],"notes_kw":["world","hello","world"]}`)
	shredded, err := ShredDocument(idx, "doc1", 1, false, rawPayload)
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	dec := json.NewDecoder(bytes.NewReader(shredded))
	dec.UseNumber()
	_ = dec.Decode(&row)

	// `_size` == exact byte length of rawPayload
	if row["f___size"] != json.Number(fmt.Sprintf("%d", len(rawPayload))) {
		t.Fatalf("expected f___size=%d, got %v", len(rawPayload), row["f___size"])
	}
	// `murmur3` exact upstream hash for "a quick brown fox" == -3758089825743606896 (`mapper_murmur3/10_basic.yml:166`)
	if row["f__foo__hash"] != json.Number("-3758089825743606896") {
		t.Fatalf("expected f__foo__hash=-3758089825743606896, got %v", row["f__foo__hash"])
	}
	if ComputeESMurmur3Hash("foo") != -2129773440516405919 {
		t.Fatalf("expected ComputeESMurmur3Hash('foo')=-2129773440516405919, got %d", ComputeESMurmur3Hash("foo"))
	}
	// `counted_keyword` preserves duplicate counts (`["b", "a", "b"]`)
	if !reflect.DeepEqual(row["f__events"], []any{"b", "a", "b"}) {
		t.Fatalf("expected counted_keyword to preserve duplicates, got %#v", row["f__events"])
	}
	// `aggregate_metric_double` sub-columns + default_metric ("avg" = 41.0 / 2 = 20.5)
	if row["f__latency__min"] != json.Number("10.5") ||
		row["f__latency__max"] != json.Number("30.5") ||
		row["f__latency__sum"] != json.Number("41") ||
		row["f__latency__value_count"] != json.Number("2") ||
		row["f__latency"] != json.Number("20.5") {
		t.Fatalf("unexpected aggregate_metric_double columns: min=%v max=%v sum=%v vc=%v def=%v",
			row["f__latency__min"], row["f__latency__max"], row["f__latency__sum"], row["f__latency__value_count"], row["f__latency"])
	}

	// Synthetic `_source` verification:
	// - `_size` not injected into `_source`
	// - `events` (`counted_keyword`) keeps duplicate `"b"` sorted: `["a", "b", "b"]`
	// - `notes_stored` (`annotated_text` `store: true`) preserves order & duplicates: `["world", "hello", "world"]`
	// - `notes_kw` (`annotated_text` via `.keyword` doc_values) deduplicates & sorts: `["hello", "world"]` (`mapper_annotatedtext/20_synthetic_source.yml:109-130`)
	var gotSrc map[string]any
	decS := json.NewDecoder(strings.NewReader(row["_source"].(string)))
	decS.UseNumber()
	_ = decS.Decode(&gotSrc)
	if _, hasSize := gotSrc["_size"]; hasSize {
		t.Fatalf("did not expect _size in synthetic _source: %#v", gotSrc)
	}
	if !reflect.DeepEqual(gotSrc["events"], []any{"a", "b", "b"}) {
		t.Fatalf("expected counted_keyword synthetic _source [a, b, b], got %#v", gotSrc["events"])
	}
	if !reflect.DeepEqual(gotSrc["notes_stored"], []any{"world", "hello", "world"}) {
		t.Fatalf("expected stored annotated_text [world, hello, world], got %#v", gotSrc["notes_stored"])
	}
	if !reflect.DeepEqual(gotSrc["notes_kw"], []any{"hello", "world"}) {
		t.Fatalf("expected keyword-docvalues annotated_text [hello, world], got %#v", gotSrc["notes_kw"])
	}

	// `aggregate_metric_double` with `ignore_malformed: true` (`100_synthetic_source.yml:80-123`) & TSDB `time_series_metric` validation (`90_tsdb_mappings.yml:46`)
	var badTSMAgg esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"m":{"type":"aggregate_metric_double","metrics":["min","max"],"default_metric":"max","time_series_metric":"counter"}}}`), &badTSMAgg)
	if err := ValidateMappingSpec(&badTSMAgg); err == nil || !strings.Contains(err.Error(), "accepted values are [gauge]") {
		t.Fatalf("expected aggregate_metric_double time_series_metric error, got %v", err)
	}
	var ignAggSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"_source":{"mode":"synthetic"},"properties":{"metric":{"type":"aggregate_metric_double","metrics":["min","max","value_count"],"default_metric":"max","ignore_malformed":true}}}`), &ignAggSpec)
	ignAggIdx := CompileIndexSchema("es_db", "r63_ign_agg", &ignAggSpec)
	shredIgnAgg, err := ShredDocument(ignAggIdx, "2", 1, false, []byte(`{"metric":["hey",{"value_count":1,"min":18.2,"max":100},[123,456]]}`))
	if err != nil {
		t.Fatalf("ignore_malformed aggregate_metric_double failed: %v", err)
	}
	var ignAggRow, ignAggSrc map[string]any
	_ = json.Unmarshal(shredIgnAgg, &ignAggRow)
	_ = json.Unmarshal([]byte(ignAggRow["_source"].(string)), &ignAggSrc)
	mArr, ok := ignAggSrc["metric"].([]any)
	if !ok || len(mArr) != 4 || mArr[1] != "hey" || mArr[2] != float64(123) || mArr[3] != float64(456) {
		t.Fatalf("unexpected ignore_malformed aggregate_metric_double synthetic _source: %#v", ignAggSrc["metric"])
	}
}

func TestRound63_AdditionalValidationSyntheticTSDBAndAlterCoverage(t *testing.T) {
	// 1. `ValidateSizeMetaSpec` & `ExtractIgnoreDynamicBeyondLimitSetting` edge cases
	if enabled, explicit, err := ValidateSizeMetaSpec(map[string]any{"enabled": "true"}); err != nil || !enabled || !explicit {
		t.Fatalf("expected _size.enabled=\"true\" valid, got %v %v %v", enabled, explicit, err)
	}
	if enabled, explicit, err := ValidateSizeMetaSpec(map[string]any{"enabled": "false"}); err != nil || enabled || !explicit {
		t.Fatalf("expected _size.enabled=\"false\" valid, got %v %v %v", enabled, explicit, err)
	}
	for _, badSize := range []map[string]any{
		{"unknown": true},
		{"enabled": "not_bool"},
		{"enabled": 123},
	} {
		if _, _, err := ValidateSizeMetaSpec(badSize); err == nil {
			t.Fatalf("expected ValidateSizeMetaSpec error for %+v", badSize)
		}
	}

	if val, pres, err := ExtractIgnoreDynamicBeyondLimitSetting(map[string]any{
		"index": map[string]any{"mapping.total_fields.ignore_dynamic_beyond_limit": "true"},
	}); err != nil || !pres || !val {
		t.Fatalf("expected ignore_dynamic_beyond_limit=true, got %v %v %v", val, pres, err)
	}
	if val, pres, err := ExtractIgnoreDynamicBeyondLimitSetting(map[string]any{
		"index.mapping.total_fields.ignore_dynamic_beyond_limit": "false",
	}); err != nil || !pres || val {
		t.Fatalf("expected ignore_dynamic_beyond_limit=false, got %v %v %v", val, pres, err)
	}
	if _, _, err := ExtractIgnoreDynamicBeyondLimitSetting(map[string]any{
		"index.mapping.total_fields.ignore_dynamic_beyond_limit": "invalid",
	}); err == nil {
		t.Fatal("expected error for invalid ignore_dynamic_beyond_limit setting")
	}

	// 2. `aggregate_metric_double` validation, update compatibility, multi-entry array merging, and default_metric variants
	for _, badAM := range []string{
		`{"properties":{"m":{"type":"aggregate_metric_double"}}}`,
		`{"properties":{"m":{"type":"aggregate_metric_double","metrics":["bad"],"default_metric":"bad"}}}`,
		`{"properties":{"m":{"type":"aggregate_metric_double","metrics":["min","min"],"default_metric":"min"}}}`,
		`{"properties":{"m":{"type":"aggregate_metric_double","metrics":["min"]}}}`,
		`{"properties":{"m":{"type":"aggregate_metric_double","metrics":["min"],"default_metric":"max"}}}`,
		`{"properties":{"m":{"type":"aggregate_metric_double","metrics":["min"],"default_metric":"min","index":false}}}`,
		`{"properties":{"m":{"type":"aggregate_metric_double","metrics":["min"],"default_metric":"min","doc_values":false}}}`,
	} {
		var s esast.MappingSpec
		_ = json.Unmarshal([]byte(badAM), &s)
		if err := ValidateMappingSpec(&s); err == nil {
			t.Fatalf("expected ValidateMappingSpec error for %s", badAM)
		}
	}
	var amOld, amBadDef, amBadMetrics esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"m":{"type":"aggregate_metric_double","metrics":["min","max"],"default_metric":"min"}}}`), &amOld)
	_ = json.Unmarshal([]byte(`{"properties":{"m":{"type":"aggregate_metric_double","metrics":["min","max"],"default_metric":"max"}}}`), &amBadDef)
	_ = json.Unmarshal([]byte(`{"properties":{"m":{"type":"aggregate_metric_double","metrics":["min","sum"],"default_metric":"min"}}}`), &amBadMetrics)
	if err := ValidateMappingUpdateCompatibility(&amOld, &amBadDef); err == nil {
		t.Fatal("expected conflict updating aggregate_metric_double default_metric")
	}
	if err := ValidateMappingUpdateCompatibility(&amOld, &amBadMetrics); err == nil {
		t.Fatal("expected conflict updating aggregate_metric_double metrics")
	}

	var amMultiSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"m_min": {"type": "aggregate_metric_double", "metrics": ["min", "max", "sum", "value_count"], "default_metric": "min"},
			"m_sum": {"type": "aggregate_metric_double", "metrics": ["sum", "value_count"], "default_metric": "sum"},
			"m_vc": {"type": "aggregate_metric_double", "metrics": ["value_count"], "default_metric": "value_count"}
		}
	}`), &amMultiSpec)
	amMultiIdx := CompileIndexSchema("es_db", "r63_am_multi", &amMultiSpec)
	shredAM, err := ShredDocument(amMultiIdx, "1", 1, false, []byte(`{
		"m_min": [{"min": 5, "max": 10, "sum": 15, "value_count": 2}, {"min": 2, "max": 20, "sum": 22, "value_count": "3"}],
		"m_sum": {"sum": 7.5, "value_count": 1.0},
		"m_vc": {"value_count": 4}
	}`))
	if err != nil {
		t.Fatalf("multi-entry aggregate_metric_double shred failed: %v", err)
	}
	var amRow map[string]any
	_ = json.Unmarshal(shredAM, &amRow)
	if amRow["f__m_min"] != float64(2) || amRow["f__m_min__max"] != float64(20) || amRow["f__m_min__value_count"] != float64(5) || amRow["f__m_sum"] != float64(7.5) || amRow["f__m_vc"] != float64(4) {
		t.Fatalf("unexpected multi-entry aggregate_metric_double row: %+v", amRow)
	}
	for _, badAMDoc := range []string{
		`{"m_min": {"min": 20, "max": 10, "sum": 30, "value_count": 2}}`,
		`{"m_min": {"min": 1, "max": 2, "sum": 3, "value_count": 0}}`,
		`{"m_min": {"min": 1, "max": 2, "sum": 3, "value_count": 1, "extra": 9}}`,
		`{"m_min": "not_an_object"}`,
	} {
		if _, err := ShredDocument(amMultiIdx, "bad", 1, false, []byte(badAMDoc)); err == nil {
			t.Fatalf("expected error for malformed aggregate_metric_double doc %s", badAMDoc)
		}
	}

	// 3. Synthetic `_source` additional types: `version` semver sort, single-map `sparse_vector`, `date` epoch_millis/epoch_second/custom format, `counted_keyword` lowercase & ignore_above, `annotated_text` stored subfield
	var extraSynthSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"ver": {"type": "version"},
			"sv": {"type": "sparse_vector"},
			"d_ms": {"type": "date", "format": "epoch_millis"},
			"d_sec": {"type": "date", "format": "epoch_second"},
			"d_ymd": {"type": "date", "format": "yyyy/MM/dd"},
			"ck_norm": {"type": "counted_keyword", "ignore_above": 5, "normalizer": "lowercase"},
			"at_sub": {
				"type": "annotated_text",
				"fields": {"stored_kw": {"type": "keyword", "doc_values": false, "store": true}}
			}
		}
	}`), &extraSynthSpec)
	extraSynthIdx := CompileIndexSchema("es_db", "r63_extra_synth", &extraSynthSpec)
	shredES, err := ShredDocument(extraSynthIdx, "1", 1, false, []byte(`{
		"ver": ["1.10.0", "1.2.0-alpha.1", "1.2.0"],
		"sv": {"tok_a": 0.75},
		"d_ms": 1700000000123,
		"d_sec": 1700000000,
		"d_ymd": "2024/05/06",
		"ck_norm": ["FOO", "BAR", "FOO", "TOO_LONG_VAL"],
		"at_sub": ["z", "a", "z"]
	}`))
	if err != nil {
		t.Fatalf("extra synthetic shred failed: %v", err)
	}
	var esRow, esGot map[string]any
	_ = json.Unmarshal(shredES, &esRow)
	_ = json.Unmarshal([]byte(esRow["_source"].(string)), &esGot)
	if !reflect.DeepEqual(esGot["ver"], []any{"1.2.0-alpha.1", "1.2.0", "1.10.0"}) {
		t.Fatalf("expected semver-sorted version array, got %#v", esGot["ver"])
	}
	if !reflect.DeepEqual(esGot["ck_norm"], []any{"bar", "foo", "foo", "TOO_LONG_VAL"}) {
		t.Fatalf("unexpected counted_keyword normalized synthetic: %#v", esGot["ck_norm"])
	}
	if !reflect.DeepEqual(esGot["at_sub"], []any{"z", "a", "z"}) {
		t.Fatalf("expected stored subfield annotated_text to preserve order & dups, got %#v", esGot["at_sub"])
	}
	if esGot["d_ymd"] != "2024/05/06" {
		t.Fatalf("expected custom date format preserved, got %#v", esGot["d_ymd"])
	}

	// Also test mergeIgnoredSourceIntoSynthetic with string `_doc`
	synthFromStrDoc := ReconstructSyntheticSource(extraSynthIdx, nil, map[string]any{
		"_doc": `{"ver":"2.0.0","__ignored_source":{"dyn_extra":[1,2]}}`,
	})
	if synthFromStrDoc["ver"] != "2.0.0" || !reflect.DeepEqual(synthFromStrDoc["dyn_extra"], []any{int64(1), int64(2)}) {
		t.Fatalf("unexpected ReconstructSyntheticSource from string _doc: %#v", synthFromStrDoc)
	}

	// 4. TSDB settings, field param validation, multi-value typed dimensions (`long`, `unsigned_long`, `boolean`, `ip`), `ValidateTSDBMapping`, `ExtractTSDBDimensionKeyMap`, `ValidateIndexSortFields`
	if _, _, _, _, err := ExtractTSDBSettings(map[string]any{
		"index.mode":                   "time_series",
		"index.routing_path":           "d1,d2",
		"index.time_series.start_time": "2021-04-29T00:00:00Z",
		"index.time_series.end_time":   "2021-04-28T00:00:00Z",
	}); err == nil {
		t.Fatal("expected error when start_time >= end_time")
	}
	for _, badTSProp := range []struct {
		ft   string
		json string
	}{
		{"keyword", `{"type":"keyword","time_series_dimension":true,"script":"emit('a')"}`},
		{"text", `{"type":"text","time_series_dimension":true}`},
		{"keyword", `{"type":"keyword","time_series_dimensions":["a"]}`},
		{"keyword", `{"type":"keyword","time_series_metric":"counter"}`},
		{"keyword", `{"type":"keyword","time_series_metric":"gauge"}`},
		{"keyword", `{"type":"keyword","time_series_metric":"position"}`},
		{"long", `{"type":"long","time_series_metric":"unknown_metric"}`},
	} {
		var fp esast.FieldProperty
		_ = json.Unmarshal([]byte(badTSProp.json), &fp)
		if err := ValidateTSDBFieldParams("f", badTSProp.ft, fp); err == nil {
			t.Fatalf("expected ValidateTSDBFieldParams error for %s", badTSProp.json)
		}
	}

	var nonDimRP esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"@timestamp":{"type":"date"},"host":{"type":"keyword"},"flat":{"type":"flattened"}}}`), &nonDimRP)
	if err := ValidateTSDBMapping(&nonDimRP, []string{"host"}); err == nil {
		t.Fatal("expected ValidateTSDBMapping to reject non-dimension routing_path")
	}
	if err := ValidateTSDBMapping(&nonDimRP, []string{"flat.env"}); err == nil {
		t.Fatal("expected ValidateTSDBMapping to reject flattened without time_series_dimensions")
	}

	var mvTypedSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"@timestamp": {"type": "date"},
			"l": {"type": "long", "time_series_dimension": true},
			"ul": {"type": "unsigned_long", "time_series_dimension": true},
			"b": {"type": "boolean", "time_series_dimension": true},
			"ip": {"type": "ip", "time_series_dimension": true}
		}
	}`), &mvTypedSpec)
	mvTypedIdx := CompileIndexSchema("es_db", "ts_mv_typed", &mvTypedSpec)
	mvTypedIdx.IndexMode = "time_series"
	var mvt1, mvt2 map[string]any
	_ = json.Unmarshal([]byte(`{"@timestamp":"2021-04-28T10:00:00Z","l":[20,10,20],"ul":[100,50],"b":[true,false],"ip":["10.0.0.2","10.0.0.1"]}`), &mvt1)
	_ = json.Unmarshal([]byte(`{"@timestamp":"2021-04-28T10:00:00Z","l":[10,20],"ul":[50,100],"b":[false,true],"ip":["10.0.0.1","10.0.0.2"]}`), &mvt2)
	t1, _, _, _, e1 := ComputeTSDBIdentityWithRoutingHash(mvTypedIdx, mvt1, nil)
	t2, _, _, _, e2 := ComputeTSDBIdentityWithRoutingHash(mvTypedIdx, mvt2, nil)
	if e1 != nil || e2 != nil || t1 != t2 {
		t.Fatalf("expected identical TSID for multi-value typed dimensions: %s (%v) vs %s (%v)", t1, e1, t2, e2)
	}
	dimMap, errDimMap := ExtractTSDBDimensionKeyMap(mvTypedIdx, mvt1)
	if errDimMap != nil || len(dimMap) != 4 {
		t.Fatalf("expected 4 entries in ExtractTSDBDimensionKeyMap, got %+v (%v)", dimMap, errDimMap)
	}

	// Sort field validation on doc_values:false and text
	var sortBadSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"nodv":{"type":"keyword","doc_values":false},"txt":{"type":"text"}}}`), &sortBadSpec)
	sortBadIdx := CompileIndexSchema("es_db", "sort_bad", &sortBadSpec)
	if err := ValidateIndexSortFields(sortBadIdx, map[string]any{"index.sort.field": "nodv"}); err == nil || !strings.Contains(err.Error(), "doc_values are disabled") {
		t.Fatalf("expected doc_values disabled sort error, got %v", err)
	}
	if err := ValidateIndexSortFields(sortBadIdx, map[string]any{"index.sort.field": []string{"txt"}}); err == nil || !strings.Contains(err.Error(), "of type [text]") {
		t.Fatalf("expected text sort error, got %v", err)
	}

	// 5. `GenerateAlterTableDDL`, `MergeMappingSpecs`, `LockAutoDims`, `DecodeGeohashLatLon`, `ResolveEffectiveField`
	var alterOldSpec, alterNewSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"k":{"type":"keyword"},"v":{"type":"dense_vector"}}}`), &alterOldSpec)
	_ = json.Unmarshal([]byte(`{
		"_size": {"enabled": true},
		"runtime": {"lk": {"type": "lookup", "target_index": "u", "input_field": "k", "target_field": "id", "fetch_fields": ["name"]}},
		"properties": {
			"k": {"type": "keyword", "multi_valued": true},
			"v": {"type": "dense_vector"},
			"h": {"type": "murmur3"},
			"am": {"type": "aggregate_metric_double", "metrics": ["min", "max"], "default_metric": "max"},
			"al": {"type": "alias", "path": "k"}
		}
	}`), &alterNewSpec)
	mergedMS := MergeMappingSpecs(&alterOldSpec, &alterNewSpec)
	if !IsSizeMetadataEnabled(mergedMS) || !mergedMS.Runtime["lk"].IsLookupRuntime() {
		t.Fatalf("unexpected MergeMappingSpecs result: %+v", mergedMS)
	}
	oldIdx := CompileIndexSchema("es_db", "alter_t", &alterOldSpec)
	_ = oldIdx.LockAutoDims("v", 8)
	if oldIdx.Fields["v"].VectorDims != 8 {
		t.Fatalf("expected LockAutoDims to set dims=8, got %+v", oldIdx.Fields["v"])
	}
	newIdx := CompileIndexSchema("es_db", "alter_t", mergedMS)
	alterStmts := GenerateAlterTableDDL(oldIdx, newIdx)
	joinedAlter := strings.Join(alterStmts, "\n")
	for _, wantSub := range []string{"f___size", "f__h", "f__am__min", "f__am__max", "f__arr__k"} {
		if !strings.Contains(joinedAlter, wantSub) {
			t.Fatalf("expected ALTER DDL to contain %s, got:\n%s", wantSub, joinedAlter)
		}
	}
	if effB := newIdx.ResolveEffectiveField("al", true); effB.ColumnName != "f__arr__k" || effB.AliasTarget != "k" {
		t.Fatalf("expected ResolveEffectiveField('al') -> f__arr__k (target k), got %+v", effB)
	}
	if lat, lon, ok := DecodeGeohashLatLon("drm3btev3e86"); !ok || lat == 0 || lon == 0 {
		t.Fatalf("expected DecodeGeohashLatLon valid, got %v %v %v", lat, lon, ok)
	}
}

func TestRound63_SchemaInferDynamicRuntimeTemplatesAndNestedShredCoverage(t *testing.T) {
	// 1. `InferDynamicRuntimeFieldsFromDocs` (`dynamic: "runtime"`) across scalar types, arrays, nested objects, and type widening
	var rtBase esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"dynamic": "runtime",
		"numeric_detection": true,
		"properties": {
			"known_obj": {
				"properties": {"mapped_k": {"type": "keyword"}}
			}
		}
	}`), &rtBase)
	rtMap, added := InferDynamicRuntimeFieldsFromDocs([]json.RawMessage{
		json.RawMessage(`{
			"b": true,
			"l": 42,
			"d": 3.14,
			"ul": 17446744073709551615,
			"dt": "2024-02-12T10:30:00Z",
			"ip": "10.0.0.1",
			"num_str": "123",
			"flt_str": "45.67",
			"widen_num": [1, 2.5],
			"widen_kw": [1, "abc"],
			"sub": {"inner": "val"},
			"sub_arr": [{"arr_k": "v"}],
			"known_obj": {"mapped_k": "ok", "dyn_rt": "hello"}
		}`),
	}, &rtBase)
	if !added || rtMap["b"].Type != "boolean" || rtMap["ul"].Type != "unsigned_long" || rtMap["ip"].Type != "ip" ||
		rtMap["widen_num"].Type != "double" || rtMap["widen_kw"].Type != "keyword" || rtMap["known_obj.dyn_rt"].Type != "keyword" {
		t.Fatalf("unexpected inferred dynamic runtime fields: %+v", rtMap)
	}

	// 2. `dynamic_templates` with `match_pattern: "regex"` and `{name}` / `{dynamic_type}` placeholders in `type`, `copy_to`, `fields`
	var regexDT esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"dynamic_templates": [
			{
				"regex_tmpl": {
					"match_pattern": "regex",
					"match": "^str_.*",
					"match_mapping_type": "string",
					"mapping": {
						"type": "{dynamic_type}",
						"copy_to": ["all_{name}", "type_{dynamic_type}"],
						"fields": {
							"{name}_kw": {"type": "keyword"}
						}
					}
				}
			}
		]
	}`), &regexDT)
	infRegex := InferMappingFromSampleDocs([]json.RawMessage{json.RawMessage(`{"str_title":"hello world","num_x":10}`)}, &regexDT)
	stProp := infRegex.Properties["str_title"]
	if stProp.Type != "text" || stProp.Fields["str_title_kw"].Type != "keyword" {
		t.Fatalf("unexpected regex dynamic_template result: %+v", stProp)
	}

	// 3. `dynamic: "strict"` allowing declared runtime fields & nested `copy_to` / `constant_keyword` / `geo_point` / `range` / `histogram` normalization
	var strictNestedSpec esast.MappingSpec
	err := json.Unmarshal([]byte(`{
		"dynamic": "strict",
		"runtime": {
			"rt.sub": {"type": "keyword", "script": "emit('x')"}
		},
		"properties": {
			"items": {
				"type": "nested",
				"properties": {
					"tag": {"type": "keyword", "copy_to": ["items.all_kw", "items.all_txt"]},
					"all_kw": {"type": "keyword"},
					"all_txt": {
						"type": "text",
						"fields": {
							"keyword": {"type": "keyword"},
							"raw": {"type": "keyword"}
						}
					},
					"ck": {"type": "constant_keyword", "value": "CONST", "normalizer": "lowercase"},
					"gp": {"type": "geo_point"},
					"rng": {"type": "integer_range"},
					"hist": {"type": "histogram"},
					"flat": {"type": "flattened"},
					"nv_kw": {"type": "keyword", "null_value": "MISSING"}
				}
			}
		}
	}`), &strictNestedSpec)
	if err != nil {
		t.Fatal(err)
	}
	strictIdx := CompileIndexSchema("es_db", "strict_nested", &strictNestedSpec)
	shredSN, err := ShredDocument(strictIdx, "1", 1, false, []byte(`{
		"rt": {"sub": "allowed_by_runtime"},
		"items": [
			{
				"tag": "alpha",
				"gp": [-71.34, 41.12],
				"rng": {"gte": 1, "lte": 10},
				"hist": {"values": [1.0, 2.0], "counts": [3, 4]},
				"flat": {"k": "v"},
				"nv_kw": null
			}
		]
	}`))
	if err != nil {
		t.Fatalf("strict nested ShredDocument failed: %v", err)
	}
	var snRow map[string]any
	_ = json.Unmarshal(shredSN, &snRow)
	nItems, ok := snRow["n__items"].([]any)
	if !ok || len(nItems) != 1 {
		t.Fatalf("expected 1 nested item in n__items, got %#v", snRow["n__items"])
	}

	// 4. `ValidateDenseVectorIndexOptions`, `inferUnmappedCopyToTargetsFromPresentFields`, `ValidateForceSyntheticSource`, `CopyIndexMappingSettingsFrom`, `ValidateIndexModeSettings`, `IsDynamicFalseUnmappedField`
	for _, vOpts := range []struct {
		elem string
		dims int
		opts any
		ok   bool
	}{
		{"float", 4, map[string]any{"type": "int8_hnsw", "m": 16, "ef_construction": 100, "confidence_interval": 0.99}, true},
		{"float", 4, map[string]any{"type": "int4_flat", "confidence_interval": "dynamic"}, true},
		{"float", 4, map[string]any{"type": "bbq_hnsw", "rescore_vector": map[string]any{"oversample": 2.0}}, true},
		{"float", 3, map[string]any{"type": "int4_hnsw"}, false},
		{"byte", 4, map[string]any{"type": "int8_hnsw"}, false},
		{"float", 4, map[string]any{"type": "flat", "m": 16}, false},
		{"float", 4, map[string]any{"type": "flat", "ef_construction": 100}, false},
		{"float", 4, map[string]any{"type": "hnsw", "confidence_interval": 0.95}, false},
		{"float", 4, map[string]any{"type": "unknown_idx"}, false},
		{"float", 4, "not_map", false},
	} {
		_, err := ValidateDenseVectorIndexOptions("vec", "dense_vector", vOpts.elem, vOpts.dims, vOpts.opts)
		if vOpts.ok && err != nil {
			t.Fatalf("expected valid index_options %+v, got %v", vOpts, err)
		}
		if !vOpts.ok && err == nil {
			t.Fatalf("expected invalid index_options %+v", vOpts)
		}
	}

	// CopyTo target inference across float/long/unsigned_long/boolean/date in ES8 mode (when target is absent from doc)
	var ctBase esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"f": {"type": "float", "copy_to": "ct_f"},
			"l": {"type": "long", "copy_to": "ct_l"},
			"u": {"type": "unsigned_long", "copy_to": "ct_u"},
			"b": {"type": "boolean", "copy_to": "ct_b"},
			"d": {"type": "date", "copy_to": "ct_d"}
		}
	}`), &ctBase)
	infCT := InferMappingFromSampleDocsES8([]json.RawMessage{
		json.RawMessage(`{"f":1.5,"l":10,"u":17446744073709551615,"b":true,"d":"2024-01-01"}`),
	}, &ctBase)
	if infCT.Properties["ct_f"].Type != "float" || infCT.Properties["ct_l"].Type != "long" ||
		infCT.Properties["ct_u"].Type != "unsigned_long" || infCT.Properties["ct_b"].Type != "boolean" || infCT.Properties["ct_d"].Type != "date" {
		t.Fatalf("unexpected inferred copy_to target types: %+v", infCT.Properties)
	}

	// ValidateForceSyntheticSource rejects non-synthetic `text` without store/keep/subfield
	var nonSynthTxtSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"sub":{"properties":{"body":{"type":"text"}}}}}`), &nonSynthTxtSpec)
	nonSynthTxtIdx := CompileIndexSchema("es_db", "non_synth_txt", &nonSynthTxtSpec)
	if err := ValidateForceSyntheticSource(nonSynthTxtIdx); err == nil {
		t.Fatal("expected ValidateForceSyntheticSource to reject unstored text field")
	}

	// CopyIndexMappingSettingsFrom full settings transfer + zero shared SourceConfig slice
	tBool := true
	fBool := false
	srcCfgIdx := &IndexSchema{
		MaxTotalFields:           500,
		MaxNestedFields:          25,
		HasExplicitNestedLimit:   true,
		MaxNestedObjects:         5000,
		MaxDepth:                 15,
		MaxFieldNameLength:       256,
		MaxTermsCount:            1024,
		MaxResultWindow:          20000,
		MaxDocvalueFieldsSearch:  50,
		MaxScriptFields:          16,
		MaxRegexLength:           500,
		DefaultCoerce:            &tBool,
		DefaultIgnoreMalformed:   &fBool,
		SourceMode:               "synthetic",
		SyntheticSource:          true,
		SourceConfig:             &SourceConfig{Mode: "synthetic", Includes: []string{"a*"}, Excludes: []string{"b*"}},
		LegacyTypeName:           "_doc",
		FieldAddedAtSeqNo:        map[string]int64{"f": 3},
		ES8Mode:                  true,
		IndexMode:                "time_series",
		RoutingPath:              []string{"dim1"},
		TimeSeriesStartTime:      "2024-01-01T00:00:00Z",
		TimeSeriesEndTime:        "2024-01-02T00:00:00Z",
		IgnoreDynamicBeyondLimit: true,
		IsRuntimeEvalSchema:      true,
	}
	dstCfgIdx := &IndexSchema{}
	dstCfgIdx.CopyIndexMappingSettingsFrom(srcCfgIdx)
	dstCfgIdx.SourceConfig.Includes[0] = "mutated"
	if srcCfgIdx.SourceConfig.Includes[0] != "a*" || !dstCfgIdx.IgnoreDynamicBeyondLimit || !dstCfgIdx.IsRuntimeEvalSchema || dstCfgIdx.MaxTotalFields != 500 {
		t.Fatalf("unexpected CopyIndexMappingSettingsFrom result: dst=%+v src=%+v", dstCfgIdx, srcCfgIdx)
	}

	// ValidateIndexModeSettings + IsDynamicFalseUnmappedField + FilterSourceBytesIncludesExcludes
	if err := ValidateIndexModeSettings("invalid_mode", nil); err == nil {
		t.Fatal("expected invalid index.mode error")
	}
	if err := ValidateIndexModeSettings("logsdb", map[string]any{"index.routing_path": "d1"}); err == nil {
		t.Fatal("expected logsdb to reject routing_path")
	}
	var dynFalseSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"dynamic":false,"properties":{"mapped":{"type":"keyword"},"sub":{"dynamic":true,"properties":{}}}}`), &dynFalseSpec)
	dynFalseIdx := CompileIndexSchema("es_db", "dyn_false", &dynFalseSpec)
	if !dynFalseIdx.IsDynamicFalseUnmappedField("unmapped.leaf") || dynFalseIdx.IsDynamicFalseUnmappedField("sub.allowed") {
		t.Fatal("unexpected IsDynamicFalseUnmappedField result")
	}
	filteredSrc := FilterSourceBytesIncludesExcludes([]byte(`{"keep":{"a":1,"secret":2},"drop":3}`), []string{"keep.*"}, []string{"keep.secret"})
	if strings.Contains(string(filteredSrc), "secret") || strings.Contains(string(filteredSrc), "drop") || !strings.Contains(string(filteredSrc), `"a":1`) {
		t.Fatalf("unexpected FilterSourceBytesIncludesExcludes output: %s", string(filteredSrc))
	}

	// 5. `MergeMappingSpecs` nil/rich branches, cartesian `point` `null_value` formats, `ValidateMappingLimits`, `coerceScalarForDoris`, `parseUnsignedLongString`, `extractAndValidateVectorValues`
	if mNil := MergeMappingSpecs(nil, nil); mNil == nil || mNil.Properties == nil {
		t.Fatal("expected non-nil empty MappingSpec from MergeMappingSpecs(nil, nil)")
	}
	var richBase esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"enabled": true,
		"dynamic": true,
		"subobjects": true,
		"_routing": {"required": true},
		"_size": {"enabled": true},
		"_meta": {"v": 1},
		"_source": {"mode": "synthetic"},
		"_data_stream_timestamp": {"enabled": true},
		"dynamic_templates": [{"t": {"match": "x*", "mapping": {"type": "keyword"}}}],
		"date_detection": true,
		"numeric_detection": false,
		"dynamic_date_formats": ["yyyy-MM-dd"],
		"properties": {"a": {"type": "keyword"}}
	}`), &richBase)
	if mLeft := MergeMappingSpecs(nil, &richBase); mLeft == nil || mLeft.Properties["a"].Type != "keyword" {
		t.Fatal("unexpected MergeMappingSpecs(nil, richBase)")
	}
	if mRight := MergeMappingSpecs(&richBase, nil); mRight == nil || mRight.Properties["a"].Type != "keyword" {
		t.Fatal("unexpected MergeMappingSpecs(richBase, nil)")
	}
	var richUpdate esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"enabled": true,
		"dynamic": "strict",
		"subobjects": true,
		"_routing": {"required": false},
		"_size": {"enabled": false},
		"_meta": {"v": 2},
		"_source": {"mode": "synthetic"},
		"_data_stream_timestamp": {"enabled": true},
		"dynamic_templates": [{"t2": {"match": "y*", "mapping": {"type": "long"}}}],
		"date_detection": false,
		"numeric_detection": true,
		"dynamic_date_formats": ["yyyy/MM/dd"],
		"properties": {"b": {"type": "long"}}
	}`), &richUpdate)
	if mBoth := MergeMappingSpecs(&richBase, &richUpdate); mBoth.Properties["a"].Type != "keyword" || mBoth.Properties["b"].Type != "long" {
		t.Fatalf("unexpected MergeMappingSpecs(richBase, richUpdate): %+v", mBoth)
	}

	// Cartesian `point` `null_value` across GeoJSON, {x,y}, [x,y], WKT POINT, and "x,y"
	for _, ptJSON := range []string{
		`{"properties":{"p":{"type":"point","null_value":{"type":"Point","coordinates":[1.5,2.5]}}}}`,
		`{"properties":{"p":{"type":"point","null_value":{"x":1.5,"y":2.5}}}}`,
		`{"properties":{"p":{"type":"point","null_value":[1.5,2.5]}}}`,
		`{"properties":{"p":{"type":"point","null_value":"POINT (1.5 2.5)"}}}`,
		`{"properties":{"p":{"type":"point","null_value":"1.5, 2.5"}}}`,
	} {
		var ps esast.MappingSpec
		_ = json.Unmarshal([]byte(ptJSON), &ps)
		if err := ValidateMappingSpec(&ps); err != nil {
			t.Fatalf("expected valid point null_value %s, got %v", ptJSON, err)
		}
	}

	// ValidateMappingLimits depth, nested_fields, and field_name_length limits
	limIdx := &IndexSchema{MaxNestedFields: 1, HasExplicitNestedLimit: true, MaxDepth: 2, MaxFieldNameLength: 5}
	var badNameSpec, badDepthSpec, badNestedSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"too_long_name":{"type":"keyword"}}}`), &badNameSpec)
	_ = json.Unmarshal([]byte(`{"properties":{"a":{"properties":{"b":{"properties":{"c":{"type":"keyword"}}}}}}}`), &badDepthSpec)
	_ = json.Unmarshal([]byte(`{"properties":{"n1":{"type":"nested"},"n2":{"type":"nested"}}}`), &badNestedSpec)
	if ValidateMappingLimits(limIdx, &badNameSpec) == nil || ValidateMappingLimits(limIdx, &badDepthSpec) == nil || ValidateMappingLimits(limIdx, &badNestedSpec) == nil {
		t.Fatal("expected ValidateMappingLimits to enforce field_name_length, depth, and nested_fields limits")
	}

	// `parseUnsignedLongString`, `coerceScalarForDoris`, `extractAndValidateVectorValues`
	if u, ok := parseUnsignedLongString("+42.00", true); !ok || u != 42 {
		t.Fatalf("expected +42.00 -> 42, got %d %v", u, ok)
	}
	if u, ok := parseUnsignedLongString("1e3", true); !ok || u != 1000 {
		t.Fatalf("expected 1e3 -> 1000, got %d %v", u, ok)
	}
	for _, dt := range []DorisScalarType{DorisLargeInt, DorisBigInt, DorisInt, DorisDouble, DorisBoolean, DorisVarchar} {
		for _, inp := range []any{int(5), int64(10), uint64(20), float64(3.5), json.Number("7"), "true", "42", strings.Repeat("x", 1100)} {
			_ = coerceScalarForDoris(inp, dt, true, time.Now().UTC())
		}
	}
	vecDoc := map[string]any{"a.b": []any{int(1), int64(2), float64(3.5), json.Number("4.5")}}
	if vec, pres, valid := extractAndValidateVectorValues(vecDoc, []string{"a", "b"}, 4); !pres || !valid || len(vec) != 4 {
		t.Fatalf("unexpected extractAndValidateVectorValues: %v %v %v", vec, pres, valid)
	}

	// `extractScalarValue` / `normalizeScalar` / `parseSyntheticEpochMillis` / `inspectES8DynamicVectorsInMap` on object arrays
	scalarDoc := map[string]any{
		"a.b":  []any{nil, map[string]any{"name": "join_parent"}},
		"arr":  []any{map[string]any{"c": map[string]any{"k": 1}}},
		"null": nil,
	}
	if gotJoin := extractScalarValue(scalarDoc, []string{"a", "b"}); gotJoin != "join_parent" {
		t.Fatalf("expected join_parent, got %#v", gotJoin)
	}
	if gotJSON := extractScalarValue(scalarDoc, []string{"arr", "c"}); gotJSON != `{"k":1}` {
		t.Fatalf("expected {\"k\":1}, got %#v", gotJSON)
	}
	for _, dv := range []any{int(1700000000000), int64(1700000000000), float64(1700000000000), json.Number("1700000000000"), "2024-02-12T10:00:00Z"} {
		if _, ok := formatSyntheticDateValue(dv, FieldBinding{ESType: "date"}, nil, "ts"); !ok {
			t.Fatalf("expected formatSyntheticDateValue(%T) ok", dv)
		}
	}
	vals128 := make([]string, 128)
	for i := range vals128 {
		vals128[i] = "0.5"
	}
	var dynVecParentSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"known_arr":{"type":"nested"}}}`), &dynVecParentSpec)
	dynVecParentIdx := CompileIndexSchema("es_db", "dyn_vec_arr", &dynVecParentSpec)
	dynVecParentIdx.ES8Mode = true
	_, newDynArrVecs, err := InspectAutoDimsAndDynamicVectors(dynVecParentIdx, [][]byte{
		[]byte(fmt.Sprintf(`{"known_arr":[{"emb":[%s]}],"unmapped_arr":[{"emb2":[%s]}]}`, strings.Join(vals128, ","), strings.Join(vals128, ","))),
	})
	if err != nil || newDynArrVecs["known_arr.emb"] != 128 || newDynArrVecs["unmapped_arr.emb2"] != 128 {
		t.Fatalf("unexpected InspectAutoDimsAndDynamicVectors on object arrays: %+v (%v)", newDynArrVecs, err)
	}

	// `lockAutoDimsInProps` (multi-field & subobjects:false dotted path) + `LockAutoDims` > 4096 + `propagateCopyToCustomMultiFields`
	var lockSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"subobjects": false,
		"properties": {
			"txt": {
				"type": "keyword",
				"fields": {"vec": {"type": "dense_vector"}}
			},
			"dot.vec": {"type": "dense_vector"}
		}
	}`), &lockSpec)
	LockAutoDimsInMapping(&lockSpec, "txt.vec", 6)
	LockAutoDimsInMapping(&lockSpec, "dot.vec", 10)
	if lockSpec.Properties["txt"].Fields["vec"].Dims != 6 || lockSpec.Properties["dot.vec"].Dims != 10 {
		t.Fatalf("unexpected LockAutoDimsInMapping result: %+v", lockSpec.Properties)
	}
	lockIdx := CompileIndexSchema("es_db", "lock_t", &lockSpec)
	if err := lockIdx.LockAutoDims("dot.vec", 5000); err == nil {
		t.Fatal("expected LockAutoDims > 4096 error")
	}

	var ctMultiSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"src": {"type": "keyword", "copy_to": "dest"},
			"dest": {
				"type": "text",
				"fields": {
					"num": {"type": "long", "ignore_malformed": true},
					"ul_arr": {"type": "unsigned_long", "multi_valued": true}
				}
			}
		}
	}`), &ctMultiSpec)
	ctMultiIdx := CompileIndexSchema("es_db", "ct_multi", &ctMultiSpec)
	shredCTM, err := ShredDocument(ctMultiIdx, "1", 1, false, []byte(`{"src":["42","17446744073709551615"]}`))
	if err != nil || len(shredCTM) == 0 {
		t.Fatalf("propagateCopyToCustomMultiFields shred failed: %v", err)
	}
}
