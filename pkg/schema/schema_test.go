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
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func buildOpenMetadataTestSchema(t *testing.T) *IndexSchema {
	t.Helper()
	rawMapping := `{
		"properties": {
			"name": {
				"type": "text",
				"analyzer": "standard",
				"fields": {
					"keyword": {"type": "keyword", "normalizer": "lowercase_normalizer"},
					"ngram": {"type": "text", "analyzer": "ngram_analyzer"}
				}
			},
			"displayName": {
				"type": "text",
				"fields": {
					"keyword": {"type": "keyword"}
				}
			},
			"serviceType": {"type": "keyword"},
			"deleted": {"type": "boolean"},
			"updatedAt": {"type": "long"},
			"tier": {
				"properties": {
					"tagFQN": {"type": "keyword"}
				}
			},
			"tags": {
				"properties": {
					"tagFQN": {"type": "keyword"}
				}
			},
			"usageSummary": {
				"properties": {
					"weeklyStats": {
						"properties": {
							"count": {"type": "long"}
						}
					}
				}
			},
			"columns": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword"},
					"dataType": {"type": "keyword"},
					"tags": {
						"properties": {
							"tagFQN": {"type": "keyword"}
						}
					}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatalf("failed to unmarshal test mapping: %v", err)
	}
	return CompileIndexSchema("es_compat", "table_search_index", &spec)
}

func TestGenerateCreateTableDDL(t *testing.T) {
	s := buildOpenMetadataTestSchema(t)
	ddl := GenerateCreateTableDDL(s)

	expectedSnippets := []string{
		"CREATE TABLE IF NOT EXISTS `es_compat`.`table_search_index`",
		"`_id` VARCHAR(512) NOT NULL",
		"`_source` STRING NOT NULL",
		"`_doc` VARIANT NOT NULL",
		"`f__name` STRING NULL",
		"`f__name__keyword` VARCHAR(1024) NULL",
		"`f__name__ngram` STRING NULL",
		"`f__tags__tagFQN` ARRAY<STRING> NULL",
		"`n__columns` ARRAY<STRING> NULL",
		"`n__columns__name` ARRAY<STRING> NULL",
		"`n__columns__tags__tagFQN` ARRAY<STRING> NULL",
		"UNIQUE KEY(`_id`)",
		"\"enable_unique_key_merge_on_write\" = \"true\"",
		"\"store_row_column\" = \"true\"",
		"\"function_column.sequence_col\" = \"_version\"",
	}
	for _, snip := range expectedSnippets {
		if !strings.Contains(ddl, snip) {
			t.Errorf("expected DDL to contain %q, got:\n%s", snip, ddl)
		}
	}
}

func TestShredDocument_PreservesSourceAndPopulatesPromotedAndNestedColumns(t *testing.T) {
	s := buildOpenMetadataTestSchema(t)
	rawDoc := `{"name":"Customer_Orders","serviceType":"BigQuery","deleted":false,"tags":[{"tagFQN":"PII.Sensitive"},{"tagFQN":"Finance"}],"columns":[{"name":"user_id","dataType":"INT","tags":[{"tagFQN":"PII.Sensitive"}]},{"name":"created_at","dataType":"TIMESTAMP","tags":[{"tagFQN":"Tier.Tier1"}]}]}`

	shreddedBytes, err := ShredDocument(s, "tbl-123", 3, false, json.RawMessage(rawDoc))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}

	var row map[string]any
	if err := json.Unmarshal(shreddedBytes, &row); err != nil {
		t.Fatalf("failed to unmarshal shredded row: %v", err)
	}

	if row["_id"] != "tbl-123" {
		t.Errorf("expected _id tbl-123, got %v", row["_id"])
	}
	if row["_source"] != rawDoc {
		t.Errorf("expected verbatim _source %s, got %v", rawDoc, row["_source"])
	}
	// Verify lowercase normalizer applied to f__name__keyword while f__name retains original case
	if row["f__name"] != "Customer_Orders" {
		t.Errorf("expected f__name Customer_Orders, got %v", row["f__name"])
	}
	if row["f__name__keyword"] != "customer_orders" {
		t.Errorf("expected lowercase f__name__keyword customer_orders, got %v", row["f__name__keyword"])
	}
	// Verify multi-valued tags.tagFQN array extraction
	tags, ok := row["f__tags__tagFQN"].([]any)
	if !ok || len(tags) != 2 || tags[0] != "PII.Sensitive" || tags[1] != "Finance" {
		t.Errorf("unexpected f__tags__tagFQN: %+v", row["f__tags__tagFQN"])
	}
	// Verify nested correlated elements array `n__columns`
	nestedCols, ok := row["n__columns"].([]any)
	if !ok || len(nestedCols) != 2 {
		t.Fatalf("expected 2 correlated nested elements in n__columns, got %+v", row["n__columns"])
	}
}
