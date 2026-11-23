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
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestRound64W3SingleObjectNestedParentID(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"nested_field": {
				"type": "nested",
				"properties": {
					"sub_nested_field": {
						"type": "nested",
						"properties": {
							"val": {"type": "keyword"}
						}
					}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatal(err)
	}
	idx := CompileIndexSchema("es_db", "r64_nested_single", &spec)
	shredBytes, err := ShredDocument(idx, "1", 1, false, []byte(`{
		"nested_field": {
			"sub_nested_field": [{"val": "a"}, {"val": "b"}]
		}
	}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredBytes, &row); err != nil {
		t.Fatal(err)
	}
	rawSub, ok := row["n__nested_field__sub_nested_field"].([]any)
	if !ok || len(rawSub) != 2 {
		t.Fatalf("expected 2 sub-nested objects in row, got %#v (row=%#v)", row["n__nested_field__sub_nested_field"], row)
	}
	for i, item := range rawSub {
		m, isMap := item.(map[string]any)
		if !isMap {
			if s, isStr := item.(string); isStr {
				_ = json.Unmarshal([]byte(s), &m)
			}
		}
		if got, _ := m["_parent_id"].(string); got != "0" {
			t.Fatalf("sub-nested element %d expected _parent_id=\"0\", got %#v (item=%#v)", i, m["_parent_id"], item)
		}
	}
}
