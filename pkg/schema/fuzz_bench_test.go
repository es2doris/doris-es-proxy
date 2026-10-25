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
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func TestShredDocument_Preserves64BitIntegerPrecisionAndDottedNestedProps(t *testing.T) {
	// 1. Verify dotted property name inside `nested` does not panic with slice bounds out of range
	mappingJSON := []byte(`{
		"properties": {
			"snowflakeId": {"type": "long"},
			"a.b": {
				"type": "nested",
				"properties": {
					"c.d": {"type": "keyword"}
				}
			}
		}
	}`)
	var spec esast.MappingSpec
	if err := json.Unmarshal(mappingJSON, &spec); err != nil {
		t.Fatalf("unmarshal mapping: %v", err)
	}
	idxSchema := CompileIndexSchema("es_compat", "precision_test", &spec)
	ddl := GenerateCreateTableDDL(idxSchema)
	if !strings.Contains(ddl, "CREATE TABLE") {
		t.Fatalf("unexpected DDL: %s", ddl)
	}

	// 2. Verify 64-bit integer > 2^53 (9007199254740993) is preserved without float64 mantissa truncation
	rawDoc := []byte(`{"snowflakeId": 9007199254740993, "a.b": [{"c.d": "val1", "nestedTs": 1729773296789123456}]}`)
	shredded, err := ShredDocument(idxSchema, "doc-64", 1, false, rawDoc)
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	if !bytes.Contains(shredded, []byte(`"f__snowflakeId":9007199254740993`)) {
		t.Fatalf("expected exact 64-bit integer 9007199254740993 in shredded output, got: %s", string(shredded))
	}
	if !bytes.Contains(shredded, []byte(`1729773296789123456`)) {
		t.Fatalf("expected exact 64-bit nested integer in shredded output, got: %s", string(shredded))
	}
}

func FuzzShredDocument(f *testing.F) {
	f.Add([]byte(`{"name":"orders","deleted":false,"updatedAt":"2026-01-02T15:04:05Z","tags":[{"tagFQN":"PII.Sensitive"}]}`))
	f.Add([]byte(`{"name":"users","updatedAt":"now-7d/d","snowflakeId":9007199254740993}`))

	mappingJSON := []byte(`{
		"properties": {
			"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"deleted": {"type": "boolean"},
			"updatedAt": {"type": "date"},
			"snowflakeId": {"type": "long"}
		}
	}`)
	var spec esast.MappingSpec
	_ = json.Unmarshal(mappingJSON, &spec)
	idxSchema := CompileIndexSchema("es_compat", "table_search_index", &spec)

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ShredDocument(idxSchema, "fuzz-id", 1, false, raw)
	})
}

func BenchmarkShredDocument(b *testing.B) {
	mappingJSON := []byte(`{
		"properties": {
			"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"serviceType": {"type": "keyword"},
			"deleted": {"type": "boolean"},
			"updatedAt": {"type": "date"},
			"columns": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword"},
					"dataType": {"type": "keyword"}
				}
			}
		}
	}`)
	var spec esast.MappingSpec
	_ = json.Unmarshal(mappingJSON, &spec)
	idxSchema := CompileIndexSchema("es_compat", "table_search_index", &spec)

	doc := []byte(`{
		"name": "fact_orders",
		"serviceType": "BigQuery",
		"deleted": false,
		"updatedAt": 1700000000000,
		"tags": [{"tagFQN": "PII.Sensitive"}, {"tagFQN": "Tier.Tier1"}],
		"columns": [
			{"name": "order_id", "dataType": "BIGINT"},
			{"name": "customer_email", "dataType": "VARCHAR"}
		]
	}`)

	b.ReportAllocs()
	b.SetBytes(int64(len(doc)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ShredDocument(idxSchema, "doc-1", int64(i+1), false, doc); err != nil {
			b.Fatal(err)
		}
	}
}
