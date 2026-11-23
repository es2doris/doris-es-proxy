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

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound60_F11_SyntheticSource_SerializeMappings_DottedProperties(t *testing.T) {
	// 1. Empty SerializeMappings omits "properties": {}
	emptySchema := CompileIndexSchema("db", "empty_idx", &esast.MappingSpec{})
	if got := SerializeMappings(emptySchema); len(got) != 0 {
		t.Fatalf("expected empty SerializeMappings() == {}, got: %#v", got)
	}

	// 2. Empty property name rejected with 400
	var badEmptySpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties": {"": {"type": "keyword"}}}`), &badEmptySpec)
	if err := ValidateMappingSpec(&badEmptySpec); err == nil || !strings.Contains(err.Error(), "Field name cannot be an empty string") {
		t.Fatalf("expected empty field name error, got: %v", err)
	}

	// 3. Dotted property key expansion during parsing, compilation, and serialization
	var invalidSynSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"secret": {"type": "keyword", "doc_values": false}
		}
	}`), &invalidSynSpec); err != nil {
		t.Fatalf("unmarshal invalidSynSpec failed: %v", err)
	}
	if err := ValidateMappingSpec(&invalidSynSpec); err == nil {
		t.Fatalf("expected ValidateMappingSpec to reject doc_values:false without store:true under synthetic _source")
	}

	var dottedSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"_source": {"mode": "synthetic"},
		"properties": {
			"subfield.text3": {"type": "text", "meta": {"owner": "search"}},
			"subfield.num": {"type": "integer"},
			"tags": {"type": "keyword"},
			"disabled_obj": {"type": "object", "enabled": false}
		}
	}`), &dottedSpec); err != nil {
		t.Fatalf("unmarshal dottedSpec failed: %v", err)
	}
	if err := ValidateMappingSpec(&dottedSpec); err != nil {
		t.Fatalf("ValidateMappingSpec failed: %v", err)
	}
	idx := CompileIndexSchema("db", "syn_idx", &dottedSpec)
	if !idx.SyntheticSource || idx.SourceMode != "synthetic" || idx.SourceConfig == nil || idx.SourceConfig.Mode != "synthetic" {
		t.Fatalf("expected SyntheticSource=true and SourceMode='synthetic', got %+v", idx)
	}
	if b, ok := idx.Fields["subfield.text3"]; !ok || b.ESType != "text" || b.Meta["owner"] != "search" {
		t.Fatalf("expected expanded field subfield.text3 with meta, got: %+v (ok=%v)", b, ok)
	}
	serialized := idx.SerializeMappings()
	propsMap, _ := serialized["properties"].(map[string]any)
	subObj, _ := propsMap["subfield"].(map[string]any)
	subProps, _ := subObj["properties"].(map[string]any)
	if _, ok := subProps["text3"]; !ok {
		t.Fatalf("expected nested properties.subfield.properties.text3 in SerializeMappings, got: %#v", serialized)
	}

	// 4. Unknown _source.mode rejected; mode="disabled" disables _source
	var badModeSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"_source": {"mode": "invalid_mode"}}`), &badModeSpec)
	if err := ValidateMappingSpec(&badModeSpec); err == nil {
		t.Fatalf("expected unknown _source.mode to fail")
	}
	var disModeSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"_source": {"mode": "disabled"}}`), &disModeSpec)
	if err := ValidateMappingSpec(&disModeSpec); err != nil {
		t.Fatalf("expected _source.mode=disabled to succeed, got: %v", err)
	}
	disIdx := CompileIndexSchema("db", "dis_idx", &disModeSpec)
	if !disIdx.SourceDisabled() {
		t.Fatalf("expected SourceDisabled()=true for _source.mode=disabled")
	}

	// 5. ReconstructSyntheticSource & ShredDocument deterministic sorting + omitting doc_values:false / enabled:false
	rawDoc := []byte(`{
		"tags": ["zeta", "alpha", "beta"],
		"subfield": {"text3": "hello", "num": [30, 10, 20]},
		"disabled_obj": {"foo": "bar"}
	}`)
	shreddedBytes, err := ShredDocument(idx, "1", 1, false, rawDoc)
	if err != nil {
		t.Fatalf("ShredDocument synthetic failed: %v", err)
	}
	var shreddedRow map[string]any
	if err := json.Unmarshal(shreddedBytes, &shreddedRow); err != nil {
		t.Fatalf("unmarshal shreddedRow failed: %v", err)
	}
	var gotSyn map[string]any
	if err := json.Unmarshal([]byte(shreddedRow["_source"].(string)), &gotSyn); err != nil {
		t.Fatalf("unmarshal synthetic _source failed: %v", err)
	}
	if disMap, ok := gotSyn["disabled_obj"].(map[string]any); !ok || disMap["foo"] != "bar" {
		t.Fatalf("expected enabled:false object 'disabled_obj' retained in ES 8.4+ synthetic _source, got %#v", gotSyn["disabled_obj"])
	}
	wantTags := []any{"alpha", "beta", "zeta"}
	if !reflect.DeepEqual(gotSyn["tags"], wantTags) {
		t.Fatalf("expected sorted tags %v, got %#v", wantTags, gotSyn["tags"])
	}
	gotSub, _ := gotSyn["subfield"].(map[string]any)
	wantNums := []any{float64(10), float64(20), float64(30)}
	if !reflect.DeepEqual(gotSub["num"], wantNums) {
		t.Fatalf("expected sorted numeric array %v, got %#v", wantNums, gotSub["num"])
	}
}

func TestRound60_F17_F18_IgnoredDDLAndCompletionContexts(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"code": {"type": "keyword", "ignore_above": 5},
			"num": {"type": "integer", "ignore_malformed": true},
			"cat": {"type": "keyword"},
			"suggest": {
				"type": "completion",
				"contexts": [
					{"name": "category", "type": "category"},
					{"name": "defaulted_cat", "type": "category", "default": ["general"]}
				]
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	if err := ValidateMappingSpec(&spec); err != nil {
		t.Fatalf("ValidateMappingSpec failed: %v", err)
	}
	idx := CompileIndexSchema("db", "comp_idx", &spec)

	// F17: DDL contains `_ignored` ARRAY<STRING> NULL and inverted index
	ddl := GenerateCreateTableDDL(idx)
	if !strings.Contains(ddl, "`_ignored` ARRAY<STRING> NULL") || !strings.Contains(ddl, "INDEX `idx__ignored` (`_ignored`) USING INVERTED") {
		t.Fatalf("expected _ignored column and inverted index in DDL, got:\n%s", ddl)
	}

	// F17: Shredding populates row["_ignored"]
	shreddedBytes, err := ShredDocument(idx, "1", 1, false, []byte(`{"code": "TOO_LONG_CODE", "num": "not_an_int", "suggest": {"input": "pizza", "weight": 5, "contexts": {"category": "food"}}}`))
	if err != nil {
		t.Fatalf("ShredDocument valid completion + ignored failed: %v", err)
	}
	var shreddedRow map[string]any
	if err := json.Unmarshal(shreddedBytes, &shreddedRow); err != nil {
		t.Fatalf("unmarshal shreddedRow failed: %v", err)
	}
	igRow, ok := shreddedRow["_ignored"].([]any)
	if !ok || len(igRow) != 2 || igRow[0] != "code" || igRow[1] != "num" {
		t.Fatalf("expected row[\"_ignored\"] == [\"code\", \"num\"], got %#v", shreddedRow["_ignored"])
	}

	// F18: Negative completion weight rejected with 400
	if _, err := ShredDocument(idx, "2", 1, false, []byte(`{"suggest": {"input": "pizza", "weight": -1, "contexts": {"category": "food"}}}`)); err == nil || !strings.Contains(err.Error(), "weight") {
		t.Fatalf("expected negative completion weight to fail, got: %v", err)
	}

	// F18: Missing mandatory completion context (without default or path) rejected with 400
	if _, err := ShredDocument(idx, "3", 1, false, []byte(`{"suggest": {"input": "pizza", "weight": 1}}`)); err == nil || !strings.Contains(err.Error(), "category") {
		t.Fatalf("expected missing mandatory completion context error, got: %v", err)
	}
}
