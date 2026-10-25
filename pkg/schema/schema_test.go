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
	"time"

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

func TestInferMergeAlterPromoteAndDateMath(t *testing.T) {
	// 1. InferMappingFromSampleDocs across strings, long text, ISO dates, ints, floats, booleans, nested objects, and arrays
	longText := strings.Repeat("word ", 30)
	samples := []json.RawMessage{
		json.RawMessage(`{"service":"checkout","msg":"` + longText + `","created_at":"2026-10-25T12:00:00Z","count":42,"latency":12.5,"ok":true,"meta":{"region":"us-east-1"},"tags":["a","b"],"items":[{"sku":"s1"}]}`),
		json.RawMessage(`{"service":"payments","count":10.5,"meta":{"zone":"az1"}}`),
	}
	inferred := InferMappingFromSampleDocs(samples)
	if inferred == nil {
		t.Fatalf("expected non-nil inferred mapping")
	}
	if inferred.Properties["service"].Type != "keyword" ||
		inferred.Properties["msg"].Type != "text" ||
		inferred.Properties["created_at"].Type != "date" ||
		inferred.Properties["count"].Type != "double" ||
		inferred.Properties["ok"].Type != "boolean" ||
		len(inferred.Properties["meta"].Properties) != 2 {
		t.Fatalf("unexpected inferred mapping properties: %+v", inferred.Properties)
	}

	// 2. MergeMappingSpecs & DeepMergeMappingProperties
	extraSpec := &esast.MappingSpec{
		Dynamic: true,
		Properties: map[string]esast.FieldProperty{
			"embedding": {Type: "dense_vector", Dims: 3, Similarity: "cosine"},
			"rank":      {Type: "integer"},
			"chinese":   {Type: "text", Analyzer: "ik_max_word"},
			"english":   {Type: "text", Analyzer: "english"},
			"meta": {
				Properties: map[string]esast.FieldProperty{
					"env": {Type: "keyword"},
				},
			},
		},
	}
	merged := MergeMappingSpecs(inferred, extraSpec)
	if merged == nil || len(merged.Properties["meta"].Properties) != 3 {
		t.Fatalf("expected merged meta to have 3 properties, got %+v", merged)
	}
	if MergeMappingSpecs(nil, nil) == nil || MergeMappingSpecs(nil, extraSpec) == nil || MergeMappingSpecs(extraSpec, nil) == nil {
		t.Fatalf("expected nil-safe MergeMappingSpecs")
	}

	// 3. CompileIndexSchema, GenerateAlterTableDDL, GeneratePromoteVariantFieldDDL, ResolveField, ExpandFieldPattern
	oldSchema := CompileIndexSchema("es_compat", "events", inferred)
	newSchema := CompileIndexSchema("es_compat", "events", merged)
	alterStmts := GenerateAlterTableDDL(oldSchema, newSchema)
	if len(alterStmts) == 0 {
		t.Fatalf("expected ALTER TABLE statements when adding embedding/rank/chinese/english/meta.env")
	}
	promoteStmts := GeneratePromoteVariantFieldDDL(newSchema, "unmapped_field.keyword", "keyword")
	if len(promoteStmts) != 2 || !strings.Contains(promoteStmts[0], "ADD COLUMN `f__unmapped_field`") {
		t.Fatalf("unexpected promote statements: %+v", promoteStmts)
	}
	promoteArrStmts := GeneratePromoteVariantFieldDDL(newSchema, "tags.tagFQN", "")
	if len(promoteArrStmts) != 2 || !strings.Contains(promoteArrStmts[0], "ARRAY<STRING>") {
		t.Fatalf("unexpected multi-valued promote statements: %+v", promoteArrStmts)
	}

	// Verify ResolveField for `.keyword` fallback and unmapped fields
	if b := newSchema.ResolveField("service.keyword"); b.ColumnName != "f__service" {
		t.Fatalf("expected service.keyword to fall back to f__service, got %+v", b)
	}
	if b := newSchema.ResolveField("unknown.keyword"); b.Kind != StorageDynamicVariant || len(b.SourceJSONPath) != 1 || b.SourceJSONPath[0] != "unknown" {
		t.Fatalf("expected unknown.keyword to strip .keyword in SourceJSONPath, got %+v", b)
	}
	if expanded := newSchema.ExpandFieldPattern("meta.*^3.5"); len(expanded) != 3 || expanded[0].Boost != 3.5 {
		t.Fatalf("expected 3 expanded meta.* fields with boost 3.5, got %+v", expanded)
	}

	// 4. SanitizeDorisIdentifier long name truncation and special characters
	longIdent := SanitizeDorisIdentifier("very.long-index/name$with@special!chars_" + strings.Repeat("x", 60))
	if len(longIdent) > 56 || SanitizeDorisIdentifier("") != "_unnamed" {
		t.Fatalf("unexpected SanitizeDorisIdentifier: %q", longIdent)
	}

	// 5. ParseESDateToEpochMillis with date math (+/-/rounding across y, M, w, d, h, m, s)
	dateExprs := []string{
		"1729773296789",
		"2026-10-25T12:00:00Z",
		"2026-10-25",
		"2026/10/25",
		"now",
		"now-7d/d",
		"now+2h/h",
		"now-1y/y",
		"now-3M/M",
		"now-2w/w",
		"now-15m/m",
		"now-30s/s",
		"2026-10-25T12:00:00Z||+1d/d",
	}
	for _, expr := range dateExprs {
		if _, ok := ParseESDateToEpochMillis(expr, mustNow()); !ok {
			t.Fatalf("expected ParseESDateToEpochMillis(%q) to succeed", expr)
		}
	}
	if _, ok := ParseESDateToEpochMillis("not-a-date", mustNow()); ok {
		t.Fatalf("expected invalid date string to return false")
	}

	// 6. ShredDocument with vectors, numbers, strings, booleans, dates, and tombstone delete
	shredded, err := ShredDocument(newSchema, "doc-1", 1, false, json.RawMessage(`{
		"service": "checkout",
		"created_at": "2026-10-25T12:00:00Z",
		"count": "42.5",
		"rank": "7",
		"ok": "true",
		"embedding": [0.1, 0.2, 0.3]
	}`))
	if err != nil || !strings.Contains(string(shredded), `"f__embedding":[0.1,0.2,0.3]`) {
		t.Fatalf("unexpected ShredDocument result: %s (err=%v)", string(shredded), err)
	}
	tombstone, err := ShredDocument(newSchema, "doc-1", 2, true, nil)
	if err != nil || !strings.Contains(string(tombstone), `"__DORIS_DELETE_SIGN__":1`) {
		t.Fatalf("expected tombstone delete sign=1, got %s (err=%v)", string(tombstone), err)
	}
}

func mustNow() (t time.Time) {
	t, _ = time.Parse(time.RFC3339, "2026-10-25T12:00:00Z")
	return t
}
