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

	// 7. EffectiveLowercase with .keyword normalizer, ParseESDateBoundToEpochMillis (roundUp + /w), and nested []any shredding
	kwNormMapping := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"host": {
				Type: "text",
				Fields: map[string]esast.FieldProperty{
					"keyword": {Type: "keyword", Normalizer: "lowercase"},
				},
			},
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"sku": {Type: "keyword"},
				},
			},
			"vec": {Type: "dense_vector", Dims: 3},
		},
	}
	kwSchema := CompileIndexSchema("logs_db", "kw_idx", kwNormMapping)
	hostBind := kwSchema.ResolveField("host")
	if !hostBind.EffectiveLowercase(true) {
		t.Fatalf("expected EffectiveLowercase(true) to honor .keyword companion lowercase normalizer")
	}
	expanded := kwSchema.ExpandFieldPattern("*")
	for _, f := range expanded {
		if f.Field == "vec" {
			t.Fatalf("expected ExpandFieldPattern(\"*\") to skip dense_vector field 'vec', got %v", expanded)
		}
	}
	lowerDay, ok1 := ParseESDateBoundToEpochMillis("2026-10-25T12:00:00Z||/d", mustNow(), false)
	upperDay, ok2 := ParseESDateBoundToEpochMillis("2026-10-25T12:00:00Z||/d", mustNow(), true)
	if !ok1 || !ok2 || upperDay-lowerDay != 86400*1000-1 {
		t.Fatalf("expected inclusive /d upper bound to be end-of-day (+86399999ms), got lower=%d upper=%d", lowerDay, upperDay)
	}
	if _, ok := ParseESDateBoundToEpochMillis("1729773296789||/w", mustNow(), true); !ok {
		t.Fatalf("expected epoch_millis||/w date math to succeed")
	}
	if _, err := ShredDocument(kwSchema, "bad", 1, false, json.RawMessage(`null`)); err == nil {
		t.Fatalf("expected ShredDocument to reject JSON null document")
	}
	nestedShred, err := ShredDocument(kwSchema, "n1", 1, false, json.RawMessage(`{"items":[{"sku":"A1"},{"sku":"B2"}]}`))
	if err != nil || !strings.Contains(string(nestedShred), `"n__items__sku":["A1","B2"]`) {
		t.Fatalf("expected nested []any array to populate prefilter array column, got %s (err=%v)", string(nestedShred), err)
	}
}

func mustNow() (t time.Time) {
	t, _ = time.Parse(time.RFC3339, "2026-10-25T12:00:00Z")
	return t
}

func TestSchemaRound28ComprehensiveCoverage(t *testing.T) {
	now := mustNow()

	// 1. coerceScalarForDoris across DorisBigInt, DorisInt (32-bit clamping), DorisDouble, DorisBoolean, DorisVarchar, DorisString
	if got := coerceScalarForDoris(uint64(math.MaxUint64), DorisBigInt, false, now); got != int64(math.MaxInt64) {
		t.Fatalf("expected MaxInt64 for uint64 overflow, got %#v", got)
	}
	if got := coerceScalarForDoris(math.NaN(), DorisBigInt, false, now); got != nil {
		t.Fatalf("expected nil for NaN on DorisBigInt, got %#v", got)
	}
	if got := coerceScalarForDoris(float64(1e25), DorisBigInt, false, now); got != int64(math.MaxInt64) {
		t.Fatalf("expected MaxInt64 for +1e25 on DorisBigInt, got %#v", got)
	}
	if got := coerceScalarForDoris(float64(-1e25), DorisBigInt, false, now); got != int64(math.MinInt64) {
		t.Fatalf("expected MinInt64 for -1e25 on DorisBigInt, got %#v", got)
	}
	if got := coerceScalarForDoris(json.Number("18446744073709551615"), DorisBigInt, false, now); got != int64(math.MaxInt64) {
		t.Fatalf("expected MaxInt64 for uint64 json.Number on DorisBigInt, got %#v", got)
	}
	if got := coerceScalarForDoris(json.Number("1e25"), DorisBigInt, false, now); got != int64(math.MaxInt64) {
		t.Fatalf("expected MaxInt64 for 1e25 json.Number on DorisBigInt, got %#v", got)
	}
	if got := coerceScalarForDoris("18446744073709551615", DorisBigInt, false, now); got != int64(math.MaxInt64) {
		t.Fatalf("expected MaxInt64 for uint64 string on DorisBigInt, got %#v", got)
	}
	if got := coerceScalarForDoris("1e25", DorisBigInt, false, now); got != int64(math.MaxInt64) {
		t.Fatalf("expected MaxInt64 for 1e25 string on DorisBigInt, got %#v", got)
	}

	// DorisInt 32-bit clamping
	if got := coerceScalarForDoris(int64(5_000_000_000), DorisInt, false, now); got != int(math.MaxInt32) {
		t.Fatalf("expected MaxInt32 for int64 overflow on DorisInt, got %#v", got)
	}
	if got := coerceScalarForDoris(int64(-5_000_000_000), DorisInt, false, now); got != int(math.MinInt32) {
		t.Fatalf("expected MinInt32 for int64 underflow on DorisInt, got %#v", got)
	}
	if got := coerceScalarForDoris(uint64(5_000_000_000), DorisInt, false, now); got != int(math.MaxInt32) {
		t.Fatalf("expected MaxInt32 for uint64 overflow on DorisInt, got %#v", got)
	}
	if got := coerceScalarForDoris(float64(5e12), DorisInt, false, now); got != int(math.MaxInt32) {
		t.Fatalf("expected MaxInt32 for float64 overflow on DorisInt, got %#v", got)
	}
	if got := coerceScalarForDoris(math.Inf(1), DorisInt, false, now); got != nil {
		t.Fatalf("expected nil for +Inf on DorisInt, got %#v", got)
	}
	if got := coerceScalarForDoris(json.Number("5000000000"), DorisInt, false, now); got != int(math.MaxInt32) {
		t.Fatalf("expected MaxInt32 for json.Number overflow on DorisInt, got %#v", got)
	}
	if got := coerceScalarForDoris(json.Number("-5000000000"), DorisInt, false, now); got != int(math.MinInt32) {
		t.Fatalf("expected MinInt32 for json.Number underflow on DorisInt, got %#v", got)
	}
	if got := coerceScalarForDoris(json.Number("42.8"), DorisInt, false, now); got != 42 {
		t.Fatalf("expected 42 for json.Number(42.8) on DorisInt, got %#v", got)
	}
	if got := coerceScalarForDoris("5000000000", DorisInt, false, now); got != int(math.MaxInt32) {
		t.Fatalf("expected MaxInt32 for string overflow on DorisInt, got %#v", got)
	}
	if got := coerceScalarForDoris("19.9", DorisInt, false, now); got != 19 {
		t.Fatalf("expected 19 for string 19.9 on DorisInt, got %#v", got)
	}

	// DorisDouble & DorisBoolean (including json.Number("0.0"))
	if got := coerceScalarForDoris(math.NaN(), DorisDouble, false, now); got != nil {
		t.Fatalf("expected nil for NaN on DorisDouble, got %#v", got)
	}
	if got := coerceScalarForDoris(int64(123), DorisDouble, false, now); got != float64(123) {
		t.Fatalf("expected 123.0 on DorisDouble, got %#v", got)
	}
	if got := coerceScalarForDoris(json.Number("0.0"), DorisBoolean, false, now); got != false {
		t.Fatalf("expected false for json.Number(\"0.0\") on DorisBoolean, got %#v", got)
	}
	if got := coerceScalarForDoris(json.Number("1.0"), DorisBoolean, false, now); got != true {
		t.Fatalf("expected true for json.Number(\"1.0\") on DorisBoolean, got %#v", got)
	}
	if got := coerceScalarForDoris("false", DorisBoolean, false, now); got != false {
		t.Fatalf("expected false for \"false\" on DorisBoolean, got %#v", got)
	}
	if got := coerceScalarForDoris(0, DorisBoolean, false, now); got != false {
		t.Fatalf("expected false for 0 on DorisBoolean, got %#v", got)
	}
	longUTF8 := strings.Repeat("é", 600) // 1200 UTF-8 bytes
	truncVal, ok := coerceScalarForDoris(longUTF8, DorisVarchar, true, now).(string)
	if !ok || len(truncVal) > 1024 {
		t.Fatalf("expected DorisVarchar string truncated to <= 1024 bytes, got len=%d", len(truncVal))
	}

	// 2. GeneratePromoteVariantFieldDDL guards (existing promoted field, nested root, vector types)
	sch := buildOpenMetadataTestSchema(t)
	if ddls := GeneratePromoteVariantFieldDDL(nil, "x", "keyword"); ddls != nil {
		t.Fatalf("expected nil DDLs for nil schema")
	}
	if ddls := GeneratePromoteVariantFieldDDL(sch, "", "keyword"); ddls != nil {
		t.Fatalf("expected nil DDLs for empty field path")
	}
	if ddls := GeneratePromoteVariantFieldDDL(sch, "name", "keyword"); ddls != nil {
		t.Fatalf("expected nil DDLs for already-promoted field 'name'")
	}
	if ddls := GeneratePromoteVariantFieldDDL(sch, "columns.name", "keyword"); ddls != nil {
		t.Fatalf("expected nil DDLs for nested subfield 'columns.name'")
	}
	if ddls := GeneratePromoteVariantFieldDDL(sch, "dyn_vec", "dense_vector"); ddls != nil {
		t.Fatalf("expected nil DDLs for dense_vector promotion")
	}
	if ddls := GeneratePromoteVariantFieldDDL(sch, "dyn_tags", "array"); len(ddls) != 2 || !strings.Contains(ddls[0], "ARRAY<STRING>") {
		t.Fatalf("expected ARRAY<STRING> DDL for array promotion, got %v", ddls)
	}

	// 3. EffectiveArrayColumn(preferKeyword) with KeywordNormalizer
	b := FieldBinding{
		ESFieldPath:       "items.title",
		Kind:              StorageNestedSubfield,
		ColumnName:        "n__items__title",
		PrefilterArrayCol: "n__items__title",
		KeywordCompanion:  "n__items__title__keyword",
		KeywordNormalizer: true,
	}
	if got := b.EffectiveArrayColumn(false); got != "n__items__title" {
		t.Fatalf("EffectiveArrayColumn(false) = %q, want \"n__items__title\"", got)
	}
	if got := b.EffectiveArrayColumn(true); got != "n__items__title__keyword" {
		t.Fatalf("EffectiveArrayColumn(true) = %q, want \"n__items__title__keyword\"", got)
	}

	// 4. InferMappingFromSampleDocs & MergeMappingSpecs
	inferred := InferMappingFromSampleDocs([]json.RawMessage{
		json.RawMessage(`{
			"ts": "2026-10-25T12:00:00Z",
			"client_ip": "192.168.1.10",
			"price": 19.99,
			"qty": 5,
			"active": true,
			"title": "Quick brown fox jumps over lazy dog",
			"code": "ABC-123",
			"tags": ["alpha", "beta"],
			"items": [{"sku": "S1", "cost": 10.5}]
		}`),
	})
	if inferred == nil || len(inferred.Properties) == 0 {
		t.Fatalf("expected non-empty inferred mapping")
	}
	merged := MergeMappingSpecs(inferred, sch.RawMapping)
	if merged == nil || len(merged.Properties) < len(inferred.Properties) {
		t.Fatalf("unexpected MergeMappingSpecs result")
	}
}

func TestRound29SchemaPromoteVariantNestedRootGuardNilResolveAndShredIgnoreAbove(t *testing.T) {
	rawMap := `{
		"properties": {
			"code": {"type": "keyword", "ignore_above": 5, "copy_to": "summary"},
			"summary": {
				"type": "text",
				"fields": {
					"keyword": {"type": "keyword", "ignore_above": 6, "normalizer": "lowercase"}
				}
			},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword", "ignore_above": 4, "normalizer": "lowercase"},
					"name": {"type": "text"}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMap), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	sch := CompileIndexSchema("db", "r29_idx", &spec)

	// 1. GeneratePromoteVariantFieldDDL must block nested root ("items") and nested subpaths ("items.extra")
	if ddls := GeneratePromoteVariantFieldDDL(sch, "items", "keyword"); len(ddls) != 0 {
		t.Fatalf("expected nil DDL when promoting nested root 'items', got %v", ddls)
	}
	if ddls := GeneratePromoteVariantFieldDDL(sch, "items.extra", "keyword"); len(ddls) != 0 {
		t.Fatalf("expected nil DDL when promoting nested subpath 'items.extra', got %v", ddls)
	}

	// 2. Nil receiver guard on ResolveField
	var nilSchema *IndexSchema
	nilBinding := nilSchema.ResolveField("dyn.field.keyword")
	if nilBinding.Kind != StorageDynamicVariant || len(nilBinding.SourceJSONPath) != 2 {
		t.Fatalf("expected nil IndexSchema.ResolveField to return StorageDynamicVariant, got %+v", nilBinding)
	}

	// 3. ShredDocument: numeric scalar exceeding ignore_above on keyword column & scalar .keyword companion copy_to
	shredBytes, err := ShredDocument(sch, "doc1", 1, false, json.RawMessage(`{
		"code": 1234567,
		"items": [
			{"sku": 98765, "name": "TooLongSku"},
			{"sku": "AB12", "name": "ValidSku"}
		]
	}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredBytes, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	if _, exists := row["f__code"]; exists {
		t.Fatalf("expected numeric code 1234567 (7 chars > ignore_above 5) to be omitted from f__code, got %v", row["f__code"])
	}
	// Now test copy_to where source ignore_above is not exceeded, or test direct copy_to into summary.keyword
	rawMap2 := `{
		"properties": {
			"tag": {"type": "keyword", "copy_to": "summary"},
			"summary": {
				"type": "text",
				"fields": {
					"keyword": {"type": "keyword", "ignore_above": 5, "normalizer": "lowercase"}
				}
			}
		}
	}`
	var spec2 esast.MappingSpec
	_ = json.Unmarshal([]byte(rawMap2), &spec2)
	sch2 := CompileIndexSchema("db", "r29_idx2", &spec2)
	shredBytes2, err := ShredDocument(sch2, "doc2", 1, false, json.RawMessage(`{"tag": "TOOLONGVAL"}`))
	if err != nil {
		t.Fatalf("ShredDocument 2 failed: %v", err)
	}
	var row2 map[string]any
	_ = json.Unmarshal(shredBytes2, &row2)
	if kwVal, hasKw := row2["f__summary__keyword"]; hasKw && kwVal != nil && kwVal != "" {
		t.Fatalf("expected summary.keyword ignore_above=5 to skip 'TOOLONGVAL', got %v", kwVal)
	}

	// 4. GenerateAddColumnsDDL & GeneratePromoteVariantFieldDDL
	promoteDDLs := GeneratePromoteVariantFieldDDL(sch2, "new_dyn_str", "text")
	if len(promoteDDLs) < 2 {
		t.Fatalf("expected GeneratePromoteVariantFieldDDL for text to include companion .keyword, got %v", promoteDDLs)
	}
}

func TestRound30CopyToKeywordCompanionAndNestedTextKeywordArray(t *testing.T) {
	// 1. Non-text copy_to target with .keyword companion AND nested text copy_to target with .keyword companion
	rawMap := `{
		"properties": {
			"src_a": {"type": "keyword", "copy_to": "combined_kw"},
			"src_b": {"type": "keyword", "copy_to": "combined_kw"},
			"combined_kw": {
				"type": "keyword",
				"fields": {
					"keyword": {"type": "keyword"}
				}
			},
			"items": {
				"type": "nested",
				"properties": {
					"brand": {"type": "keyword", "copy_to": "items.all_text"},
					"category": {"type": "keyword", "copy_to": "items.all_text"},
					"all_text": {
						"type": "text",
						"fields": {
							"keyword": {"type": "keyword", "ignore_above": 10, "normalizer": "lowercase"}
						}
					}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMap), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	sch := CompileIndexSchema("db", "r30_idx", &spec)

	// Verify combined_kw.keyword was promoted to StoragePromotedArray
	kwBinding := sch.ResolveEffectiveField("combined_kw.keyword", true)
	if kwBinding.Kind != StoragePromotedArray || !kwBinding.IsMultiValued {
		t.Fatalf("expected combined_kw.keyword to be StoragePromotedArray / IsMultiValued=true, got %+v", kwBinding)
	}
	// Verify items.all_text.keyword has IsMultiValued=true
	nestedKwBinding := sch.ResolveEffectiveField("items.all_text.keyword", true)
	if !nestedKwBinding.IsMultiValued {
		t.Fatalf("expected items.all_text.keyword to have IsMultiValued=true, got %+v", nestedKwBinding)
	}

	shredBytes, err := ShredDocument(sch, "doc1", 1, false, json.RawMessage(`{
		"src_a": "alpha",
		"src_b": "beta",
		"items": [
			{"brand": "ACME", "category": "WIDGETS_LONG_IGNORED"}
		]
	}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredBytes, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	nItems, ok := row["n__items"].([]any)
	if !ok || len(nItems) != 1 {
		t.Fatalf("expected 1 nested item in n__items, got %v", row["n__items"])
	}
	var elem map[string]any
	if s, isStr := nItems[0].(string); isStr {
		_ = json.Unmarshal([]byte(s), &elem)
	} else if m, isMap := nItems[0].(map[string]any); isMap {
		elem = m
	}
	kwArr, ok := elem["all_text__keyword"].([]any)
	if !ok || len(kwArr) != 1 || kwArr[0] != "acme" {
		t.Fatalf("expected all_text__keyword=['acme'] (lowercased, 'WIDGETS_LONG_IGNORED' filtered by ignore_above=10), got %v", elem["all_text__keyword"])
	}

	// 2. truncateUTF8Bytes multi-byte rune boundary safety
	trunc := truncateUTF8Bytes("a€b", 3) // 'a' (1 byte) + '€' (3 bytes) = 4 bytes -> should truncate before '€'
	if trunc != "a" {
		t.Fatalf("expected truncateUTF8Bytes('a€b', 3) == 'a', got %q", trunc)
	}
}

func TestRound31PromoteTextVariantNestedCopyToNormalizerAndTypeWidening(t *testing.T) {
	// Fix 6: GeneratePromoteVariantFieldDDL for "text" creates companion f__<field>__keyword column + inverted index,
	// and promoting "<field>.keyword" when <field> is already promoted creates f__<field>__keyword
	sch := CompileIndexSchema("db", "r31_promote_idx", &esast.MappingSpec{})
	ddls := GeneratePromoteVariantFieldDDL(sch, "dyn_msg", "text")
	if len(ddls) != 4 {
		t.Fatalf("expected 4 DDL statements (text col + text idx + keyword col + keyword idx), got %d: %v", len(ddls), ddls)
	}
	joined := strings.Join(ddls, "\n")
	if !strings.Contains(joined, "ADD COLUMN `f__dyn_msg` STRING NULL") || !strings.Contains(joined, "ADD COLUMN `f__dyn_msg__keyword` VARCHAR(1024) NULL") {
		t.Fatalf("expected both f__dyn_msg and f__dyn_msg__keyword in DDL, got:\n%s", joined)
	}

	// Also test promoting <field>.keyword on an existing scalar field that initially lacked a .keyword companion
	sch2 := CompileIndexSchema("db", "r31_promote_idx2", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"plain_text": {Type: "text"},
		},
	})
	ddls2 := GeneratePromoteVariantFieldDDL(sch2, "plain_text.keyword", "keyword")
	if len(ddls2) != 2 || !strings.Contains(ddls2[0], "ADD COLUMN `f__plain_text__keyword` VARCHAR(1024) NULL") {
		t.Fatalf("expected promoting plain_text.keyword on existing text field to add f__plain_text__keyword, got %v", ddls2)
	}

	// Fix 7: Nested copy_to from a source field with LowercaseNormalizer to a case-sensitive target field preserves original casing
	var nestedSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"items": {
				"type": "nested",
				"properties": {
					"code": {"type": "keyword", "normalizer": "lowercase", "copy_to": "raw_code"},
					"raw_code": {"type": "keyword"}
				}
			}
		}
	}`), &nestedSpec); err != nil {
		t.Fatalf("unmarshal nestedSpec failed: %v", err)
	}
	nestedSch := CompileIndexSchema("db", "r31_nested_copy", &nestedSpec)
	shredBytes, err := ShredDocument(nestedSch, "1", 1, false, json.RawMessage(`{"items":[{"code":"AbC_123"}]}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredBytes, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	nItems, _ := row["n__items"].([]any)
	if len(nItems) != 1 {
		t.Fatalf("expected 1 nested item, got %v", row["n__items"])
	}
	var elem map[string]any
	if s, ok := nItems[0].(string); ok {
		_ = json.Unmarshal([]byte(s), &elem)
	}
	if elem["code"] != "abc_123" {
		t.Fatalf("expected normalized source field 'code' == 'abc_123', got %v", elem["code"])
	}
	if elem["raw_code"] != "AbC_123" {
		t.Fatalf("expected un-normalized copy_to target 'raw_code' == 'AbC_123', got %v", elem["raw_code"])
	}
	rawPre, _ := row["n__items__raw_code"].([]any)
	if len(rawPre) != 1 || rawPre[0] != "AbC_123" {
		t.Fatalf("expected prefilter array n__items__raw_code == ['AbC_123'], got %v", row["n__items__raw_code"])
	}

	// Fix 8: InferMappingFromSampleDocs widens incompatible scalar types (boolean + long, date + long, boolean + date) to keyword
	inferred := InferMappingFromSampleDocs([]json.RawMessage{
		json.RawMessage(`{"bool_num": true, "date_num": "2026-03-15T10:00:00Z", "bool_date": false}`),
		json.RawMessage(`{"bool_num": 42, "date_num": 99, "bool_date": "2026-03-15T10:00:00Z"}`),
	})
	if inferred == nil {
		t.Fatalf("expected non-nil inferred mapping")
	}
	for _, f := range []string{"bool_num", "date_num", "bool_date"} {
		if got := inferred.Properties[f].Type; got != "keyword" {
			t.Fatalf("expected heterogeneous field %q to widen to 'keyword', got %q", f, got)
		}
	}
}

func TestRound32NullLeadingArraysNestedKwNullValueAndCopyToAlterDDL(t *testing.T) {
	// Fix 3 & Fix 4: ShredDocument handles [null, 42] on scalar fields, [null, "hello"] on text fields,
	// and nested .keyword companion null_value without clobbering parent text field
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"count": {"type": "long", "null_value": -1},
			"title": {"type": "text"},
			"items": {
				"type": "nested",
				"properties": {
					"name": {
						"type": "text",
						"fields": {
							"keyword": {"type": "keyword", "null_value": "MISSING_KW"}
						}
					}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := CompileIndexSchema("db", "r32_shred", &spec)
	raw, err := ShredDocument(sch, "doc-1", 1, false, json.RawMessage(`{"count":[null, 42],"title":[null, "hello"],"items":[{"name":null},{"name":"actual"}]}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	if row["f__count"] != float64(42) {
		t.Fatalf("expected f__count == 42 from [null, 42], got %v", row["f__count"])
	}
	if row["f__title"] != "hello" {
		t.Fatalf("expected f__title == 'hello' from [null, 'hello'], got %v", row["f__title"])
	}
	nItems, _ := row["n__items"].([]any)
	if len(nItems) != 2 {
		t.Fatalf("expected 2 nested items, got %v", row["n__items"])
	}
	var el0 map[string]any
	_ = json.Unmarshal([]byte(nItems[0].(string)), &el0)
	if el0["name"] != nil || el0["name__keyword"] != "MISSING_KW" {
		t.Fatalf("expected el0.name == nil and el0.name__keyword == 'MISSING_KW', got %+v", el0)
	}
	preKw, _ := row["n__items__name__keyword"].([]any)
	if len(preKw) != 2 || preKw[0] != "MISSING_KW" || preKw[1] != "actual" {
		t.Fatalf("expected n__items__name__keyword == ['MISSING_KW', 'actual'], got %v", preKw)
	}

	// Fix 9: GenerateAlterTableDDL when a .keyword companion is upgraded from StoragePromotedScalar to StoragePromotedArray via copy_to
	var oldSpec, newSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"full":{"type":"text","fields":{"keyword":{"type":"keyword"}}}}}`), &oldSpec)
	_ = json.Unmarshal([]byte(`{"properties":{"full":{"type":"text","fields":{"keyword":{"type":"keyword"}}},"part":{"type":"keyword","copy_to":"full"}}}`), &newSpec)
	oldSch := CompileIndexSchema("db", "r32_evolve", &oldSpec)
	newSch := CompileIndexSchema("db", "r32_evolve", &newSpec)
	ddls := GenerateAlterTableDDL(oldSch, newSch)
	foundArrDDL := false
	for _, d := range ddls {
		if strings.Contains(d, "f__arr__full__keyword") && strings.Contains(d, "ARRAY<STRING>") {
			foundArrDDL = true
		}
	}
	if !foundArrDDL || newSch.Fields["full.keyword"].ColumnName != "f__arr__full__keyword" {
		t.Fatalf("expected ALTER TABLE ADD COLUMN f__arr__full__keyword ARRAY<STRING>, got ddls=%v binding=%+v", ddls, newSch.Fields["full.keyword"])
	}
}

func TestRound33CustomDateFormatCoerceAndIgnoreMalformed(t *testing.T) {
	// F1: Custom date formats ("yyyy/MM/dd||epoch_millis", "dd/MM/yyyy", "basic_date", "epoch_second")
	// and F2: coerce: false, ignore_malformed: true, and DeepMergeMappingProperties preserving scaling_factor/coerce/ignore_malformed
	var baseSpec, extraSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"slash_date": {"type": "date", "format": "yyyy/MM/dd||epoch_millis"},
			"euro_date": {"type": "date", "format": "dd/MM/yyyy"},
			"basic_dt": {"type": "date", "format": "basic_date"},
			"sec_dt": {"type": "date", "format": "epoch_second"},
			"strict_int": {"type": "integer", "coerce": false},
			"lenient_int": {"type": "integer", "coerce": false, "ignore_malformed": true},
			"bad_num": {"type": "long", "ignore_malformed": true},
			"price": {"type": "scaled_float", "scaling_factor": 100}
		}
	}`), &baseSpec); err != nil {
		t.Fatalf("unmarshal baseSpec failed: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"properties": {"extra": {"type": "keyword"}}}`), &extraSpec); err != nil {
		t.Fatalf("unmarshal extraSpec failed: %v", err)
	}
	merged := DeepMergeMappingProperties(baseSpec.Properties, extraSpec.Properties)
	sch := CompileIndexSchema("db", "r33_schema", &esast.MappingSpec{Properties: merged})

	if sch.Fields["price"].ScalingFactor != 100 {
		t.Fatalf("expected ScalingFactor=100 preserved after DeepMergeMappingProperties, got %v", sch.Fields["price"].ScalingFactor)
	}
	if sch.Fields["strict_int"].Coerce == nil || *sch.Fields["strict_int"].Coerce {
		t.Fatalf("expected strict_int Coerce=false preserved, got %+v", sch.Fields["strict_int"].Coerce)
	}

	// 1. Strict integer with string "42" should fail when coerce=false and ignore_malformed=false
	if _, err := ShredDocument(sch, "bad-1", 1, false, json.RawMessage(`{"strict_int": "42"}`)); err == nil {
		t.Fatalf("expected ShredDocument to reject string '42' on strict_int (coerce=false)")
	}
	// 2. Strict integer with float 42.7 should fail when coerce=false
	if _, err := ShredDocument(sch, "bad-2", 1, false, json.RawMessage(`{"strict_int": 42.7}`)); err == nil {
		t.Fatalf("expected ShredDocument to reject fractional 42.7 on strict_int (coerce=false)")
	}
	// 3. Valid custom dates + lenient_int (coerce=false, ignore_malformed=true) + bad_num (ignore_malformed=true)
	raw, err := ShredDocument(sch, "ok-1", 1, false, json.RawMessage(`{
		"slash_date": "2026/03/15",
		"euro_date": "15/03/2026",
		"basic_dt": "20260315",
		"sec_dt": 1773532800,
		"strict_int": 42,
		"lenient_int": "42",
		"bad_num": "not-a-number"
	}`))
	if err != nil {
		t.Fatalf("expected ShredDocument to succeed with custom dates and ignore_malformed=true, got: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	expectedMs := float64(1773532800000) // 2026-03-15T00:00:00Z
	for _, col := range []string{"f__slash_date", "f__euro_date", "f__basic_dt", "f__sec_dt"} {
		if row[col] != expectedMs {
			t.Fatalf("expected %s == %v, got %v", col, expectedMs, row[col])
		}
	}
	if row["f__strict_int"] != float64(42) {
		t.Fatalf("expected f__strict_int == 42, got %v", row["f__strict_int"])
	}
	if row["f__lenient_int"] != nil || row["f__bad_num"] != nil {
		t.Fatalf("expected malformed coerced fields with ignore_malformed=true to be nil, got lenient_int=%v bad_num=%v", row["f__lenient_int"], row["f__bad_num"])
	}
}

func TestRound34FlatDottedKeysDateNanosEpochNanosAndAliasKeyword(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"service": {
				"properties": {
					"name": {"type": "keyword"}
				}
			},
			"tags": {
				"properties": {
					"env": {"type": "keyword"}
				}
			},
			"vec": {
				"properties": {
					"emb": {"type": "dense_vector", "dims": 2}
				}
			},
			"ts_nanos": {
				"type": "date_nanos",
				"format": "strict_date_optional_time||epoch_nanos||epoch_millis",
				"copy_to": ["ts_copy"]
			},
			"ts_copy": {
				"type": "date_nanos",
				"format": "strict_date_optional_time||epoch_millis"
			},
			"mapped_code": {"type": "keyword"},
			"alias_to_mapped_kw": {"type": "alias", "path": "mapped_code.keyword"},
			"alias_to_unmapped_kw": {"type": "alias", "path": "dyn.sub.keyword"}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := CompileIndexSchema("db", "r34_schema", &spec)
	// Make tags.env and ts_nanos promoted arrays to verify array paths as well
	bTags := sch.Fields["tags.env"]
	bTags.Kind = StoragePromotedArray
	sch.Fields["tags.env"] = bTags
	bNanos := sch.Fields["ts_nanos"]
	bNanos.Kind = StoragePromotedArray
	sch.Fields["ts_nanos"] = bNanos
	sch.finalizeCompiledSlices()

	// F9: alias resolution for mapped_code.keyword and dyn.sub.keyword
	if sch.Fields["alias_to_mapped_kw"].ColumnName != "f__mapped_code" {
		t.Fatalf("expected alias_to_mapped_kw to resolve to f__mapped_code, got %+v", sch.Fields["alias_to_mapped_kw"])
	}
	unmappedAlias := sch.Fields["alias_to_unmapped_kw"]
	if len(unmappedAlias.SourceJSONPath) != 2 || unmappedAlias.SourceJSONPath[0] != "dyn" || unmappedAlias.SourceJSONPath[1] != "sub" {
		t.Fatalf("expected alias_to_unmapped_kw SourceJSONPath=[dyn sub], got %+v", unmappedAlias.SourceJSONPath)
	}

	// F2 & F6: Flat dotted JSON keys in _source + date_nanos with Format + epoch_nanos
	raw, err := ShredDocument(sch, "d1", 1, false, json.RawMessage(`{
		"service.name": "auth-api",
		"tags.env": ["prod", "staging"],
		"vec.emb": [0.25, 0.75],
		"ts_nanos": ["1700000000123456789"]
	}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	if row["f__service__name"] != "auth-api" {
		t.Fatalf("expected f__service__name == 'auth-api', got %v", row["f__service__name"])
	}
	envSlice, _ := row["f__tags__env"].([]any)
	if len(envSlice) != 2 || envSlice[0] != "prod" || envSlice[1] != "staging" {
		t.Fatalf("expected f__tags__env == [prod staging], got %v", row["f__tags__env"])
	}
	vecSlice, _ := row["f__vec__emb"].([]any)
	if len(vecSlice) != 2 || vecSlice[0] != 0.25 || vecSlice[1] != 0.75 {
		t.Fatalf("expected f__vec__emb == [0.25 0.75], got %v", row["f__vec__emb"])
	}
	nanosSlice, _ := row["f__ts_nanos"].([]any)
	if len(nanosSlice) != 1 || nanosSlice[0] != "1700000000123" {
		t.Fatalf("expected f__ts_nanos == ['1700000000123'], got %v", row["f__ts_nanos"])
	}
	copySlice, _ := row["f__ts_copy"].([]any)
	if len(copySlice) != 1 || copySlice[0] != "1700000000123" {
		t.Fatalf("expected f__ts_copy == ['1700000000123'], got %v", row["f__ts_copy"])
	}
}

func TestRound41ShredderStrictValidationDynamicFalseDenseVectorAndDDL(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"dynamic": false,
		"properties": {
			"count": {"type": "long"},
			"lenient_num": {"type": "long", "ignore_malformed": true},
			"emb": {"type": "dense_vector", "dims": 3},
			"no_idx": {"type": "keyword", "index": false},
			"user": {
				"properties": {
					"name": {"type": "keyword"}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := CompileIndexSchema("db", "r41_idx", &spec)

	// F2: ShredDocument rejects malformed long when ignore_malformed is false
	if _, err := ShredDocument(sch, "1", 1, false, json.RawMessage(`{"count": "not_a_number"}`)); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("F2 expected mapper_parsing_exception for malformed long, got %v", err)
	}

	// F2 + F3: ignore_malformed: true records _ignored and prunes from _doc; dynamic: false prunes unmapped fields from _doc
	raw, err := ShredDocument(sch, "2", 1, false, json.RawMessage(`{
		"count": 42,
		"lenient_num": "bad_long",
		"unmapped_secret": "should_not_enter_doc",
		"user": {"name": "alice", "extra": "pruned"}
	}`))
	if err != nil {
		t.Fatalf("ShredDocument valid+ignored failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatalf("unmarshal row failed: %v", err)
	}
	docVariant, ok := row["_doc"].(map[string]any)
	if !ok {
		t.Fatalf("expected _doc to unmarshal as map[string]any, got %T", row["_doc"])
	}
	if _, exists := docVariant["unmapped_secret"]; exists {
		t.Fatalf("F3 expected unmapped_secret pruned from _doc under dynamic:false, got %+v", docVariant)
	}
	if _, exists := docVariant["lenient_num"]; exists {
		t.Fatalf("F2 expected ignore_malformed field lenient_num pruned from _doc, got %+v", docVariant)
	}
	if userMap, ok := docVariant["user"].(map[string]any); ok {
		if _, exists := userMap["extra"]; exists {
			t.Fatalf("F3 expected user.extra pruned from _doc under dynamic:false, got %+v", userMap)
		}
	}

	// F4: dense_vector dimensionality validation
	if _, err := ShredDocument(sch, "3", 1, false, json.RawMessage(`{"emb": [0.1, 0.2]}`)); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("F4 expected mapper_parsing_exception for dense_vector dim mismatch (2 != 3), got %v", err)
	}

	// F5: GenerateAlterTableDDL emits ADD INDEX when NotIndexed transitions from true to false
	var specIdxTrue esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"dynamic": false,
		"properties": {
			"count": {"type": "long"},
			"lenient_num": {"type": "long", "ignore_malformed": true},
			"emb": {"type": "dense_vector", "dims": 3},
			"no_idx": {"type": "keyword", "index": true},
			"user": {
				"properties": {
					"name": {"type": "keyword"}
				}
			}
		}
	}`), &specIdxTrue)
	sch2 := CompileIndexSchema("db", "r41_idx", &specIdxTrue)
	alterStmts := GenerateAlterTableDDL(sch, sch2)
	foundAddIdx := false
	for _, stmt := range alterStmts {
		if strings.Contains(stmt, "ADD INDEX `idx_f__no_idx`") {
			foundAddIdx = true
		}
	}
	if !foundAddIdx {
		t.Fatalf("F5 expected ADD INDEX idx_f__no_idx in GenerateAlterTableDDL, got %v", alterStmts)
	}

	// F6: MergeMappingSpecs recursively merges nested object properties
	var overlay esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"user": {
				"properties": {
					"age": {"type": "integer"}
				}
			}
		}
	}`), &overlay)
	merged := MergeMappingSpecs(&spec, &overlay)
	if _, hasName := merged.Properties["user"].Properties["name"]; !hasName {
		t.Fatalf("F6 expected MergeMappingSpecs to preserve user.name when adding user.age, got %+v", merged.Properties["user"].Properties)
	}
	if _, hasAge := merged.Properties["user"].Properties["age"]; !hasAge {
		t.Fatalf("F6 expected MergeMappingSpecs to include user.age, got %+v", merged.Properties["user"].Properties)
	}

	// F11: ValidateMappingUpdateCompatibility rejects type changes
	var badUpdate esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"count": {"type": "keyword"}
		}
	}`), &badUpdate)
	if err := ValidateMappingUpdateCompatibility(&spec, &badUpdate); err == nil || !strings.Contains(err.Error(), "cannot be changed from type [long] to [keyword]") {
		t.Fatalf("F11 expected type conflict error, got %v", err)
	}
}

func TestRound42ShredderNestedEnabledFalseMultiFieldIgnoreMalformedMappingCompatAndPromoteDDL(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"dynamic": false,
		"properties": {
			"raw_val": {
				"type": "keyword",
				"fields": {
					"num": {"type": "integer", "ignore_malformed": true}
				}
			},
			"scores": {
				"type": "integer",
				"ignore_malformed": true
			},
			"payload": {
				"type": "object",
				"enabled": false
			},
			"no_idx": {
				"type": "keyword",
				"index": false
			},
			"emb": {
				"type": "dense_vector",
				"dims": 3
			},
			"price": {
				"type": "scaled_float",
				"scaling_factor": 100
			},
			"price_alias": {
				"type": "alias",
				"path": "price"
			},
			"ts_nano": {
				"type": "date_nanos"
			},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"secret": {"type": "keyword", "index": false},
					"meta": {"type": "object", "enabled": false}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := CompileIndexSchema("db", "r42_idx", &spec)

	// F1: buildColumnAndIndexDDL skips USING INVERTED for index: false fields (no_idx and items.secret)
	createDDL := GenerateCreateTableDDL(sch)
	if strings.Contains(createDDL, "idx_f__no_idx") || strings.Contains(createDDL, "idx_f__items__secret") {
		t.Fatalf("F1 expected no USING INVERTED index for index:false fields, got:\n%s", createDDL)
	}

	// F2 & F8: ShredDocument preserves primary field when multi-field ignore_malformed fails,
	// keeps valid array elements, and normalizes default-format date_nanos epoch nanos to millis.
	shredded, err := ShredDocument(sch, "1", 1, false, json.RawMessage(`{
		"raw_val": "hello",
		"scores": [10, "bad_int", 20],
		"ts_nano": 1700000000123456789,
		"items": [
			{"sku": "A1", "secret": "hidden", "meta": {"blob": "ignored"}, "extra_unmapped": "drop_me"}
		]
	}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredded, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	if row["f__raw_val"] != "hello" {
		t.Fatalf("F2 expected f__raw_val == 'hello', got %v", row["f__raw_val"])
	}
	if row["f__raw_val__num"] != nil {
		t.Fatalf("F2 expected f__raw_val__num == nil for malformed integer, got %v", row["f__raw_val__num"])
	}
	if row["f__ts_nano"] != float64(1700000000123) {
		t.Fatalf("F8 expected f__ts_nano normalized to epoch millis 1700000000123, got %v", row["f__ts_nano"])
	}
	docVariant, ok := row["_doc"].(map[string]any)
	if !ok {
		t.Fatalf("expected _doc to be map[string]any, got %T", row["_doc"])
	}
	if docVariant["raw_val"] != "hello" {
		t.Fatalf("F2 expected _doc.raw_val preserved as 'hello', got %v", docVariant["raw_val"])
	}
	scoresArr, ok := docVariant["scores"].([]any)
	if !ok || len(scoresArr) != 2 {
		t.Fatalf("F2 expected _doc.scores to retain 2 valid elements [10, 20], got %+v", docVariant["scores"])
	}
	// F1: GenerateAlterTableDDL emits ADD INDEX when transitioning index: false -> true
	var updatedSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"no_idx": {"type": "keyword", "index": true}
		}
	}`), &updatedSpec)
	newSch := CompileIndexSchema("db", "r42_idx", &updatedSpec)
	alterStmts := GenerateAlterTableDDL(sch, newSch)
	if len(alterStmts) == 0 || !strings.Contains(strings.Join(alterStmts, "; "), "ADD INDEX `idx_f__no_idx`") {
		t.Fatalf("F1 expected ADD INDEX idx_f__no_idx on index:false -> true transition, got %v", alterStmts)
	}

	// F3: ValidateMappingUpdateCompatibility rejects incompatible updates on enabled, alias.path, dims, scaling_factor, and multi-fields
	incompatSpecs := []string{
		`{"properties": {"payload": {"type": "object", "enabled": true}}}`,
		`{"properties": {"payload": {"type": "keyword"}}}`,
		`{"properties": {"price_alias": {"type": "alias", "path": "raw_val"}}}`,
		`{"properties": {"emb": {"type": "dense_vector", "dims": 5}}}`,
		`{"properties": {"price": {"type": "scaled_float", "scaling_factor": 10}}}`,
		`{"properties": {"raw_val": {"type": "keyword", "fields": {"num": {"type": "keyword"}}}}}`,
	}
	for _, rawIncompat := range incompatSpecs {
		var inc esast.MappingSpec
		if err := json.Unmarshal([]byte(rawIncompat), &inc); err != nil {
			t.Fatalf("unmarshal incompat spec %s failed: %v", rawIncompat, err)
		}
		if err := ValidateMappingUpdateCompatibility(&spec, &inc); err == nil {
			t.Fatalf("F3 expected compatibility error for %s, got nil", rawIncompat)
		}
	}

	// F4: GeneratePromoteVariantFieldDDL skips enabled:false descendants, index:false fields, and unmapped fields under dynamic:false
	for _, skipField := range []string{"payload.sub", "no_idx", "unmapped_dynamic_false"} {
		if stmts := GeneratePromoteVariantFieldDDL(sch, skipField, "keyword"); len(stmts) != 0 {
			t.Fatalf("F4 expected empty DDL for %q, got %v", skipField, stmts)
		}
	}
}

func TestRound43TextPromotionGuardImplicitObjectEnabledCopyToMultiFieldsAllTextAndGeohash(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"meta_obj": {
				"properties": {
					"k": {"type": "keyword"}
				}
			},
			"src_tag": {
				"type": "keyword",
				"copy_to": "agg_target"
			},
			"agg_target": {
				"type": "text",
				"fields": {
					"num": {"type": "integer"},
					"safe_num": {"type": "integer", "ignore_malformed": true},
					"kw": {"type": "keyword", "ignore_above": 5}
				}
			},
			"raw_unindexed": {
				"type": "text",
				"index": false,
				"fields": {
					"keyword": {"type": "keyword"}
				}
			},
			"status": {
				"type": "keyword",
				"null_value": "NULL_STATUS"
			},
			"loc": {
				"type": "geo_point"
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := CompileIndexSchema("db", "r43_idx", &spec)

	// F4: registerLeafField and copy_to must not promote "text" or "match_only_text" to StoragePromotedArray (ARRAY<STRING>)
	if bAgg, ok := sch.Fields["agg_target"]; !ok || bAgg.Kind != StoragePromotedScalar {
		t.Fatalf("F4 expected copy_to text target agg_target to remain StoragePromotedScalar, got %+v", bAgg)
	}
	var mvTextSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"owners": {
				"properties": {
					"displayName": {"type": "text"}
				}
			},
			"log_msg": {"type": "match_only_text", "multi_valued": true}
		}
	}`), &mvTextSpec)
	mvSch := CompileIndexSchema("db", "r43_mv_text", &mvTextSpec)
	for _, fName := range []string{"owners.displayName", "log_msg"} {
		if fb, ok := mvSch.Fields[fName]; !ok || fb.Kind != StoragePromotedScalar {
			t.Fatalf("F4 expected %s to be StoragePromotedScalar, got %+v", fName, fb)
		}
	}

	// F5: ValidateMappingUpdateCompatibility rejects changing implicit enabled:true object to enabled:false
	var disableObjSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"meta_obj": {
				"type": "object",
				"enabled": false
			}
		}
	}`), &disableObjSpec)
	if err := ValidateMappingUpdateCompatibility(&spec, &disableObjSpec); err == nil {
		t.Fatalf("F5 expected error when changing implicit enabled:true object to enabled:false")
	}

	// F6, F7, F8: ShredDocument with copy_to typed multi-fields, index:false + .keyword in _all_text, null_value in _all_text, and geohash geo_point
	outBytes, err := ShredDocument(sch, "1", 1, false, []byte(`{
		"src_tag": "42",
		"raw_unindexed": "searchable_via_keyword",
		"status": null,
		"loc": "u4pruydqqvj"
	}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(outBytes, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	arrNum, okArr := row["f__agg_target__num"].([]any)
	if !okArr || len(arrNum) != 1 || arrNum[0] != "42" {
		t.Fatalf("F6 expected f__agg_target__num == [\"42\"], got %T %v", row["f__agg_target__num"], row["f__agg_target__num"])
	}
	allText, _ := row["_all_text"].(string)
	if !strings.Contains(allText, "searchable_via_keyword") || !strings.Contains(allText, "NULL_STATUS") {
		t.Fatalf("F7 expected _all_text to contain searchable_via_keyword and NULL_STATUS, got %q", allText)
	}
	locStr, _ := row["f__loc"].(string)
	if !strings.HasPrefix(locStr, "57.64911") || !strings.Contains(locStr, ",10.40743") {
		t.Fatalf("F8 expected geohash 'u4pruydqqvj' decoded to ~57.64911,10.407439, got %q", locStr)
	}

	// F6: Malformed copy_to into non-ignore_malformed sub-field returns error
	if _, err := ShredDocument(sch, "2", 1, false, []byte(`{"src_tag": "not_an_int"}`)); err == nil {
		t.Fatalf("F6 expected error when copy_to value 'not_an_int' fails integer sub-field coercion")
	}
}

func TestRound44SchemaNestedCompatibilityPromoteTextAndShredderAllText(t *testing.T) {
	// F4: ValidateMappingUpdateCompatibility allows adding sub-properties to an existing nested field without repeating "type": "nested"
	var oldNestedSpec, newNestedSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"}
				}
			},
			"dyn_obj": {
				"dynamic": true
			}
		}
	}`), &oldNestedSpec)
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"items": {
				"properties": {
					"qty": {"type": "integer"}
				}
			},
			"dyn_obj": {
				"type": "object",
				"properties": {
					"sub": {"type": "keyword"}
				}
			}
		}
	}`), &newNestedSpec)
	if err := ValidateMappingUpdateCompatibility(&oldNestedSpec, &newNestedSpec); err != nil {
		t.Fatalf("F4 expected compatible nested sub-property update and implicit dynamic object, got %v", err)
	}

	// F5: GeneratePromoteVariantFieldDDL promotes "text" and "match_only_text" on DefaultMultiValuedPaths ("tags") as scalar STRING, not ARRAY<STRING>
	emptySch := CompileIndexSchema("db", "r44_ddl", &esast.MappingSpec{})
	textDDLs := GeneratePromoteVariantFieldDDL(emptySch, "tags", "text")
	joinedDDL := strings.Join(textDDLs, "\n")
	if strings.Contains(joinedDDL, "ARRAY<") || !strings.Contains(joinedDDL, "`f__tags` STRING") || !strings.Contains(joinedDDL, "`f__tags__keyword` VARCHAR") {
		t.Fatalf("F5 expected scalar STRING + .keyword VARCHAR DDL for promoted text field 'tags', got:\n%s", joinedDDL)
	}
	motDDLs := GeneratePromoteVariantFieldDDL(emptySch, "tags", "match_only_text")
	if strings.Contains(strings.Join(motDDLs, "\n"), "ARRAY<") {
		t.Fatalf("F5 expected scalar TEXT DDL for match_only_text field 'tags', got:\n%v", motDDLs)
	}

	// F6: ShredDocument excludes ignore_malformed values (and strings exceeding ignore_above) from _all_text and _doc
	var f6Spec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"age": {"type": "integer", "ignore_malformed": true},
			"title": {"type": "text", "ignore_malformed": true},
			"tags": {"type": "keyword", "ignore_malformed": true},
			"code": {"type": "keyword", "ignore_above": 5},
			"valid_note": {"type": "keyword"}
		}
	}`), &f6Spec)
	f6Sch := CompileIndexSchema("db", "r44_f6", &f6Spec)
	shredded, err := ShredDocument(f6Sch, "1", 1, false, []byte(`{
		"age": "malformed_age_token",
		"title": {"bad_obj": "malformed_title_obj"},
		"tags": [{"bad_tag_obj": "malformed_tag_obj"}],
		"code": "TOO_LONG_FOR_IGNORE_ABOVE",
		"valid_note": "keep_me"
	}`))
	if err != nil {
		t.Fatalf("F6 ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredded, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	allText, _ := row["_all_text"].(string)
	for _, banned := range []string{"malformed_age_token", "malformed_title_obj", "malformed_tag_obj", "TOO_LONG_FOR_IGNORE_ABOVE"} {
		if strings.Contains(allText, banned) {
			t.Fatalf("F6 expected _all_text to exclude %q, got %q", banned, allText)
		}
	}
	if !strings.Contains(allText, "keep_me") {
		t.Fatalf("F6 expected _all_text to contain 'keep_me', got %q", allText)
	}
	docMap, _ := row["_doc"].(map[string]any)
	if _, hasAge := docMap["age"]; hasAge {
		t.Fatalf("F6 expected malformed age removed from _doc, got %+v", docMap)
	}
	if _, hasTitle := docMap["title"]; hasTitle {
		t.Fatalf("F6 expected malformed object title removed from _doc, got %+v", docMap)
	}
}

func TestRound45SchemaWildcardsNumericBoundsAndIgnoreMalformed(t *testing.T) {
	ignoreMalformedTrue := true
	ignoreMalformedFalse := false
	spec := esast.MappingSpec{
		Dynamic: true,
		Runtime: map[string]esast.FieldProperty{
			"computed_day": {
				Type:   "keyword",
				Script: map[string]any{"source": "emit('monday')"},
			},
		},
		Properties: map[string]esast.FieldProperty{
			"foo_123_bar_456_baz": {Type: "keyword"},
			"b_val":               {Type: "byte"},
			"s_val":               {Type: "short"},
			"i_val":               {Type: "integer"},
			"l_val":               {Type: "long"},
			"u_val":               {Type: "unsigned_long"},
			"f_bad":               {Type: "float", IgnoreMalformed: &ignoreMalformedFalse},
			"f_ignore":            {Type: "float", IgnoreMalformed: &ignoreMalformedTrue},
			"ip_ignore":           {Type: "ip", IgnoreMalformed: &ignoreMalformedTrue},
			"ip_strict":           {Type: "ip", IgnoreMalformed: &ignoreMalformedFalse},
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"qty": {Type: "integer", IgnoreMalformed: &ignoreMalformedTrue},
				},
			},
		},
	}
	sch := CompileIndexSchema("db", "r45_schema_idx", &spec)

	// F6: Multi-wildcard ExpandFieldPattern ("foo*bar*baz^2")
	expanded := sch.ExpandFieldPattern("foo*bar*baz^2")
	if len(expanded) != 1 || expanded[0].Field != "foo_123_bar_456_baz" || expanded[0].Boost != 2.0 {
		t.Fatalf("F6 multi-wildcard ExpandFieldPattern failed: %+v", expanded)
	}

	// F7: Numeric bounds enforcement for byte, short, integer, long, unsigned_long
	for _, tc := range []struct {
		doc string
		msg string
	}{
		{`{"b_val": 200}`, "mapper_parsing_exception"},
		{`{"b_val": -200}`, "mapper_parsing_exception"},
		{`{"s_val": 40000}`, "mapper_parsing_exception"},
		{`{"i_val": 3000000000}`, "mapper_parsing_exception"},
		{`{"u_val": -1}`, "mapper_parsing_exception"},
		{`{"f_bad": "NaN"}`, "mapper_parsing_exception"},
		{`{"f_bad": "Infinity"}`, "mapper_parsing_exception"},
		{`{"ip_strict": "not-an-ip"}`, "mapper_parsing_exception"},
	} {
		if _, err := ShredDocument(sch, "1", 1, false, []byte(tc.doc)); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.msg)) {
			t.Fatalf("F7 expected error containing %q for %s, got %v", tc.msg, tc.doc, err)
		}
	}

	// F8: Runtime mappings preserved in RawMapping
	if sch.RawMapping == nil || len(sch.RawMapping.Runtime) != 1 || sch.RawMapping.Runtime["computed_day"].Type != "keyword" {
		t.Fatalf("F8 expected Runtime preserved on RawMapping, got %+v", sch.RawMapping)
	}

	// F9: ignore_malformed on float ("NaN"), ip ("not-an-ip"), and nested subfields ("items.qty") drops malformed value cleanly
	shredded, err := ShredDocument(sch, "2", 1, false, []byte(`{
		"b_val": 120,
		"f_ignore": "NaN",
		"ip_ignore": "not-an-ip",
		"items": [{"qty": "not-a-number"}, {"qty": 5}]
	}`))
	if err != nil {
		t.Fatalf("F9 ShredDocument with ignore_malformed=true failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredded, &row); err != nil {
		t.Fatalf("F9 unmarshal row failed: %v", err)
	}
	if row["f__f_ignore"] != nil || row["f__ip_ignore"] != nil {
		t.Fatalf("F9 expected malformed f__f_ignore and f__ip_ignore to be nil, got f_ignore=%v ip_ignore=%v", row["f__f_ignore"], row["f__ip_ignore"])
	}
}

func TestRound46SchemaDottedMappingsDateMathAndNestedIgnoreMalformed(t *testing.T) {
	ignoreMalformedTrue := true
	spec := esast.MappingSpec{
		Dynamic: "strict",
		Properties: map[string]esast.FieldProperty{
			"user.name":  {Type: "keyword"},
			"user.score": {Type: "integer", IgnoreMalformed: &ignoreMalformedTrue},
			"event_date": {Type: "date"},
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"sku":   {Type: "keyword"},
					"price": {Type: "integer", IgnoreMalformed: &ignoreMalformedTrue},
				},
			},
		},
	}
	sch := CompileIndexSchema("db", "r46_sch_idx", &spec)

	// F5: Dotted mapping property names ("user.name") work with both nested JSON {"user":{"name":"alice"}} and flat {"user.name":"bob"} under dynamic: "strict"
	shredNested, err := ShredDocument(sch, "1", 1, false, []byte(`{
		"user": {"name": "alice", "score": "bad_int"},
		"event_date": "2025-03-10||+1M/d",
		"items": [
			{"sku": "A", "price": 10},
			{"sku": "B", "price": "not_an_int"},
			{"sku": "C", "price": 30}
		]
	}`))
	if err != nil {
		t.Fatalf("F5/F6/F7 ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredNested, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	if row["f__user__name"] != "alice" {
		t.Fatalf("F5 expected f__user__name='alice', got %v", row["f__user__name"])
	}
	// F7: 2025-03-10 + 1M /d -> 2025-04-10T00:00:00Z (1744243200000)
	if row["f__event_date"] != float64(1744243200000) {
		t.Fatalf("F7 expected f__event_date=1744243200000 for 2025-03-10||+1M/d, got %v", row["f__event_date"])
	}
	// F6: Nested subfield ignore_malformed preserves each element's scalar price in _doc without overwriting with slice [10, 30]
	docMap, _ := row["_doc"].(map[string]any)
	itemsArr, _ := docMap["items"].([]any)
	if len(itemsArr) != 3 {
		t.Fatalf("F6 expected 3 items in _doc.items, got %+v", itemsArr)
	}
	item0, _ := itemsArr[0].(map[string]any)
	item1, _ := itemsArr[1].(map[string]any)
	item2, _ := itemsArr[2].(map[string]any)
	if item0["price"] != float64(10) || item1["price"] != nil || item2["price"] != float64(30) {
		t.Fatalf("F6 expected item0.price=10, item1.price omitted, item2.price=30, got items=%+v", itemsArr)
	}

	// Also verify flat key {"user.name": "bob"} works and unmapped {"user": {"unknown": 1}} is rejected by strict
	shredFlat, err := ShredDocument(sch, "2", 1, false, []byte(`{"user.name": "bob"}`))
	if err != nil {
		t.Fatalf("F5 flat dotted key ShredDocument failed: %v", err)
	}
	var rowFlat map[string]any
	_ = json.Unmarshal(shredFlat, &rowFlat)
	if rowFlat["f__user__name"] != "bob" {
		t.Fatalf("F5 expected f__user__name='bob', got %v", rowFlat["f__user__name"])
	}
	if _, err := ShredDocument(sch, "3", 1, false, []byte(`{"user": {"unmapped_sub": "val"}}`)); err == nil {
		t.Fatalf("F5 expected strict_dynamic_mapping_exception for unmapped sub-property under user")
	}

	// F7: Date math roundUp on month (/M) and year (/y)
	msEndMonth, okM := ParseESDateBoundWithFormatToEpochMillis("2025-02-15||/M", "", time.Now().UTC(), true)
	msEndYear, okY := ParseESDateBoundWithFormatToEpochMillis("2025-06-15||/y", "", time.Now().UTC(), true)
	if !okM || msEndMonth != 1740787199999 { // 2025-02-28T23:59:59.999Z
		t.Fatalf("F7 expected 2025-02-15||/M roundUp = 1740787199999, got %d (ok=%v)", msEndMonth, okM)
	}
	if !okY || msEndYear != 1767225599999 { // 2025-12-31T23:59:59.999Z
		t.Fatalf("F7 expected 2025-06-15||/y roundUp = 1767225599999, got %d (ok=%v)", msEndYear, okY)
	}
}

func TestRound47SchemaAndShredderSpecCompliance(t *testing.T) {
	// F5 & F6 & F9: Range field types, search_as_you_type, completion, token_count, annotated-text, nested constant_keyword, flat dotted nested keys, empty nested prefilter guard
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"int_rng":    {"type": "integer_range"},
			"date_rng":   {"type": "date_range"},
			"ip_rng":     {"type": "ip_range"},
			"sayt":       {"type": "search_as_you_type"},
			"suggest":    {"type": "completion"},
			"annotated":  {"type": "annotated-text"},
			"tok_cnt":    {"type": "token_count", "analyzer": "standard"},
			"items": {
				"type": "nested",
				"properties": {
					"kind": {"type": "constant_keyword", "value": "BOOK"},
					"meta": {
						"properties": {
							"tag": {"type": "keyword"}
						}
					}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("F5/F6/F9 mapping unmarshal failed: %v", err)
	}
	sch := CompileIndexSchema("db", "r47_sch_idx", &spec)

	// F5: Range types map to DorisVariant (StorageDynamicVariant)
	for _, rf := range []string{"int_rng", "date_rng", "ip_rng"} {
		b := sch.ResolveField(rf)
		if b.Kind != StorageDynamicVariant || b.DorisType != DorisVariant {
			t.Fatalf("F5 expected %s to resolve to StorageDynamicVariant/DorisVariant, got %+v", rf, b)
		}
	}

	// F6: search_as_you_type subfields resolve to base field
	for _, sub := range []string{"sayt._index_prefix", "sayt._2gram", "sayt._3gram"} {
		b := sch.ResolveField(sub)
		if b.ColumnName != "f__sayt" {
			t.Fatalf("F6 expected %s to resolve to f__sayt, got %+v", sub, b)
		}
		eb := sch.ResolveEffectiveField(sub, false)
		if eb.ColumnName != "f__sayt" {
			t.Fatalf("F6 expected effective field for %s to resolve to f__sayt, got %+v", sub, eb)
		}
	}

	// F6: token_count maps to DorisInt
	if tcB := sch.ResolveField("tok_cnt"); tcB.DorisType != DorisInt {
		t.Fatalf("F6 expected tok_cnt DorisInt, got %+v", tcB)
	}

	// Shred document with range fields, completion object, array sayt/annotated-text, token_count, and flat dotted key in nested element
	shredBytes, err := ShredDocument(sch, "1", 1, false, []byte(`{
		"int_rng": {"gt": 10, "lte": 20},
		"date_rng": {"gte": "2025-01-01T00:00:00Z", "lt": "2025-01-02T00:00:00Z"},
		"ip_rng": {"gte": "10.0.0.1", "lte": "10.0.0.255"},
		"sayt": ["quick", "brown", "fox"],
		"suggest": {"input": ["foo", "bar"], "weight": 10},
		"annotated": ["hello", "world"],
		"tok_cnt": "one two three four",
		"items": [{"meta.tag": "scifi"}]
	}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredBytes, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	if row["f__sayt"] != "quick brown fox" {
		t.Fatalf("F6 expected f__sayt='quick brown fox', got %v", row["f__sayt"])
	}
	if row["f__suggest"] != "foo bar" {
		t.Fatalf("F6 expected f__suggest='foo bar', got %v", row["f__suggest"])
	}
	if row["f__annotated"] != "hello world" {
		t.Fatalf("F6 expected f__annotated='hello world', got %v", row["f__annotated"])
	}
	if row["f__tok_cnt"] != float64(4) {
		t.Fatalf("F6 expected f__tok_cnt=4, got %v", row["f__tok_cnt"])
	}
	docObj, _ := row["_doc"].(map[string]any)
	intRngObj, _ := docObj["int_rng"].(map[string]any)
	if intRngObj["_gte"] != float64(11) || intRngObj["_lte"] != float64(20) {
		t.Fatalf("F5 expected int_rng._gte=11 and _lte=20, got %+v", intRngObj)
	}
	// F9: Nested element in n__items has expanded meta.tag and injected constant_keyword kind="BOOK"
	nestedElems, _ := row["n__items"].([]any)
	if len(nestedElems) != 1 {
		t.Fatalf("F9 expected 1 nested item in n__items, got %+v", row["n__items"])
	}
	var elem0 map[string]any
	if err := json.Unmarshal([]byte(nestedElems[0].(string)), &elem0); err != nil {
		t.Fatalf("F9 unmarshal nested element failed: %v", err)
	}
	if elem0["kind"] != "BOOK" {
		t.Fatalf("F9 expected nested constant_keyword kind='BOOK', got %+v", elem0)
	}
	metaMap, _ := elem0["meta"].(map[string]any)
	if metaMap["tag"] != "scifi" {
		t.Fatalf("F9 expected expanded nested meta.tag='scifi', got %+v", elem0)
	}

	// F9: Empty nested array does NOT populate nested constant_keyword prefilter column
	shredEmptyNested, err := ShredDocument(sch, "2", 1, false, []byte(`{"sayt": "only top"}`))
	if err != nil {
		t.Fatalf("ShredDocument empty nested failed: %v", err)
	}
	var rowEmpty map[string]any
	_ = json.Unmarshal(shredEmptyNested, &rowEmpty)
	if v, has := rowEmpty["n__items__kind"]; has && v != nil {
		t.Fatalf("F9 expected n__items__kind to be empty when items is absent, got %v", v)
	}

	// F5: Invalid range bounds (lower > upper or unknown key) rejected with mapper_parsing_exception
	if _, err := ShredDocument(sch, "3", 1, false, []byte(`{"int_rng": {"gte": 30, "lte": 20}}`)); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("F5 expected mapper_parsing_exception for gte > lte, got %v", err)
	}
	if _, err := ShredDocument(sch, "4", 1, false, []byte(`{"int_rng": {"gt": 20, "lte": 20}}`)); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("F5 expected mapper_parsing_exception for gt == lte, got %v", err)
	}

	// F7: InferMappingFromSampleDocs with DateDetection=false, NumericDetection=true, DynamicTemplates
	fFalse := false
	fTrue := true
	existing := &esast.MappingSpec{
		DateDetection:    &fFalse,
		NumericDetection: &fTrue,
		DynamicTemplates: []map[string]any{
			{
				"code_as_keyword": map[string]any{
					"match":   "code_*",
					"mapping": map[string]any{"type": "keyword"},
				},
			},
		},
	}
	inferred := InferMappingFromSampleDocs([]json.RawMessage{
		json.RawMessage(`{"created": "2025-01-01T00:00:00Z", "count_str": "42", "ratio_str": "3.14", "code_id": "ABC"}`),
	}, existing)
	if inferred.Properties["created"].Type == "date" {
		t.Fatalf("F7 expected DateDetection=false to prevent date inference on created, got %+v", inferred.Properties["created"])
	}
	if inferred.Properties["count_str"].Type != "long" || inferred.Properties["ratio_str"].Type != "float" {
		t.Fatalf("F7 expected NumericDetection=true to infer long and float, got count=%s ratio=%s", inferred.Properties["count_str"].Type, inferred.Properties["ratio_str"].Type)
	}
	if inferred.Properties["code_id"].Type != "keyword" {
		t.Fatalf("F7 expected dynamic_template to map code_id as keyword, got %+v", inferred.Properties["code_id"])
	}

	// F8: ValidateMappingUpdateCompatibility rejects immutable parameter changes
	baseSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"kw":      {Type: "keyword", Normalizer: "lowercase"},
			"txt":     {Type: "text", Analyzer: "standard"},
			"sf":      {Type: "scaled_float", ScalingFactor: 100},
			"vec":     {Type: "dense_vector", Dims: 3, Similarity: "cosine"},
			"indexed": {Type: "keyword"},
		},
	}
	for _, badUpdate := range []*esast.MappingSpec{
		{Properties: map[string]esast.FieldProperty{"kw": {Type: "keyword", Normalizer: "my_norm"}}},
		{Properties: map[string]esast.FieldProperty{"txt": {Type: "text", Analyzer: "whitespace"}}},
		{Properties: map[string]esast.FieldProperty{"sf": {Type: "scaled_float", ScalingFactor: 10}}},
		{Properties: map[string]esast.FieldProperty{"vec": {Type: "dense_vector", Dims: 4, Similarity: "cosine"}}},
		{Properties: map[string]esast.FieldProperty{"vec": {Type: "dense_vector", Dims: 3, Similarity: "l2_norm"}}},
		{Properties: map[string]esast.FieldProperty{"indexed": {Type: "keyword", Index: &fFalse}}},
		{Properties: map[string]esast.FieldProperty{"indexed": {Type: "keyword", DocValues: &fFalse}}},
	} {
		if err := ValidateMappingUpdateCompatibility(baseSpec, badUpdate); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
			t.Fatalf("F8 expected illegal_argument_exception for incompatible mapping update %+v, got %v", badUpdate, err)
		}
	}

	// Additional range shredder coverage: CIDR string on ip_range, array of ranges, float_range, and IPv6
	spec.Properties["flt_rng"] = esast.FieldProperty{Type: "float_range"}
	sch2 := CompileIndexSchema("db", "r47_idx2", &spec)
	if _, err := ShredDocument(sch2, "5", 1, false, []byte(`{
		"ip_rng": ["192.168.1.0/24", {"gt": "2001:db8::1", "lt": "2001:db8::ff"}],
		"flt_rng": {"gt": 1.25, "lt": 5.75},
		"date_rng": {"gt": 1700000000000, "lte": 1700000099999}
	}`)); err != nil {
		t.Fatalf("ShredDocument CIDR/float_range/IPv6 failed: %v", err)
	}
}

func TestRound48SchemaAndShredderSpecCompliance(t *testing.T) {
	// F14, F15, F16, F17
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"dynamic": "strict",
		"properties": {
			"date_rng": {"type": "date_range"},
			"flt_rng":  {"type": "float_range"},
			"labels":   {"type": "flattened"},
			"queries":  {"type": "percolator"},
			"rel":      {"type": "join", "relations": {"question": "answer"}},
			"ver":      {"type": "version"},
			"sayt":     {"type": "search_as_you_type"},
			"nested_items": {
				"type": "nested",
				"properties": {
					"attrs": {"type": "flattened"},
					"win":   {"type": "integer_range"}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("F14-F17 mapping unmarshal failed: %v", err)
	}
	sch := CompileIndexSchema("db", "r48_sch_idx", &spec)

	// F15: flattened sub-key resolves with ESType="flattened" and NestedPath preserved
	if b := sch.ResolveField("labels.env"); b.ESType != "flattened" || b.Kind != StorageDynamicVariant {
		t.Fatalf("F15 expected labels.env to resolve as flattened StorageDynamicVariant, got %+v", b)
	}
	if b := sch.ResolveField("nested_items.attrs.color"); b.ESType != "flattened" || b.NestedPath != "nested_items" {
		t.Fatalf("F15 expected nested_items.attrs.color to preserve NestedPath='nested_items', got %+v", b)
	}
	if b := sch.ResolveField("nested_items.win"); b.ESType != "integer_range" || b.NestedPath != "nested_items" {
		t.Fatalf("F14 expected nested_items.win to preserve NestedPath='nested_items', got %+v", b)
	}

	// F17: search_as_you_type default analyzer is "standard", version is DorisVarchar
	if b := sch.ResolveField("sayt"); b.Analyzer != "standard" {
		t.Fatalf("F17 expected sayt Analyzer='standard', got %q", b.Analyzer)
	}
	if b := sch.ResolveField("ver"); b.DorisType != DorisVarchar {
		t.Fatalf("F17 expected ver DorisVarchar, got %+v", b)
	}

	// F14 & F17: Shred document under dynamic: "strict" with percolator object, join object {"name":"answer","parent":"1"}, date_range lte rounding, float_range exclusive Nextafter
	shredBytes, err := ShredDocument(sch, "1", 1, false, []byte(`{
		"date_rng": {"gt": "2026-01-01T00:00:00Z", "lte": "2026-01-02"},
		"flt_rng": {"gt": 1.0, "lt": 2.0},
		"labels": {"env": ["prod", "staging"], "tier": "backend"},
		"queries": {"match": {"sayt": "hello"}},
		"rel": {"name": "answer", "parent": "1"},
		"ver": "1.2.3",
		"sayt": "hello world",
		"nested_items": [{"attrs": {"color": ["red", "blue"]}, "win": {"gte": 1, "lte": 10}}]
	}`))
	if err != nil {
		t.Fatalf("F14/F17 ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredBytes, &row); err != nil {
		t.Fatalf("unmarshal shredded row failed: %v", err)
	}
	if row["f__rel"] != "answer" {
		t.Fatalf("F17 expected join object to normalize f__rel='answer', got %v", row["f__rel"])
	}
	docMap, _ := row["_doc"].(map[string]any)
	dateRngMap, _ := docMap["date_rng"].(map[string]any)
	// gt "2026-01-01T00:00:00Z" (1767225600000) + 1ms = 1767225600001; lte "2026-01-02" rounds up to 2026-01-02T23:59:59.999Z (1767398399999)
	if dateRngMap["_gte"] != float64(1767225600001) || dateRngMap["_lte"] != float64(1767398399999) {
		t.Fatalf("F14 unexpected date_rng bounds: %+v", dateRngMap)
	}
	fltRngMap, _ := docMap["flt_rng"].(map[string]any)
	if fltRngMap["_gte"].(float64) <= 1.0 || fltRngMap["_lte"].(float64) >= 2.0 {
		t.Fatalf("F14 expected exclusive float_range bounds to be shifted via Nextafter, got %+v", fltRngMap)
	}

	// F16: InferMappingFromSampleDocs preserves existing explicit mappings, supports match_mapping_type array, {name}/{dynamic_type} placeholders, and object-level templates
	existing := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"existing_kw": {Type: "keyword", DocValues: nil},
		},
		DynamicTemplates: []map[string]any{
			{
				"flatten_meta": map[string]any{
					"match_mapping_type": "object",
					"match":              "meta_*",
					"mapping":            map[string]any{"type": "flattened"},
				},
			},
			{
				"num_array_types": map[string]any{
					"match_mapping_type": []any{"long", "double"},
					"match":              "metric_*",
					"mapping": map[string]any{
						"type":    "{dynamic_type}",
						"copy_to": "{name}_all",
					},
				},
			},
		},
	}
	inferred := InferMappingFromSampleDocs([]json.RawMessage{
		json.RawMessage(`{"existing_kw": "2026-01-01T00:00:00Z", "meta_tags": {"a": "b"}, "metric_cpu": 42}`),
	}, existing)
	if inferred.Properties["existing_kw"].Type != "keyword" {
		t.Fatalf("F16 expected existing_kw to remain keyword, got %+v", inferred.Properties["existing_kw"])
	}
	if inferred.Properties["meta_tags"].Type != "flattened" {
		t.Fatalf("F16 expected object template meta_tags to map as flattened, got %+v", inferred.Properties["meta_tags"])
	}
	if inferred.Properties["metric_cpu"].Type != "long" || inferred.Properties["metric_cpu"].CopyTo != "metric_cpu_all" {
		t.Fatalf("F16 expected placeholder substitution on metric_cpu, got %+v", inferred.Properties["metric_cpu"])
	}
}

func TestRound49SchemaAndShredderSpecCompliance(t *testing.T) {
	// F13: unsigned_long in (math.MaxInt64, math.MaxUint64] preserved in _doc, array, and nested subfield
	var uSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"u_scalar": {"type": "unsigned_long"},
			"u_arr":    {"type": "unsigned_long", "multi_valued": true},
			"items": {
				"type": "nested",
				"properties": {
					"u_nested": {"type": "unsigned_long"}
				}
			}
		}
	}`), &uSpec)
	uSch := CompileIndexSchema("db", "r49_u_idx", &uSpec)
	uRowBytes, err := ShredDocument(uSch, "1", 1, false, []byte(`{
		"u_scalar": "18446744073709551615",
		"u_arr": ["10000000000000000000", "18446744073709551615"],
		"items": [{"u_nested": "18446744073709551615"}]
	}`))
	if err != nil {
		t.Fatalf("F13 ShredDocument failed: %v", err)
	}
	var uRow map[string]any
	_ = json.Unmarshal(uRowBytes, &uRow)
	uArr, _ := uRow["f__u_arr"].([]any)
	if len(uArr) != 2 || uArr[0] != "10000000000000000000" || uArr[1] != "18446744073709551615" {
		t.Fatalf("F13 expected exact uint64 strings in f__u_arr, got %+v", uArr)
	}
	uNestedPre, _ := uRow["n__items__u_nested"].([]any)
	if len(uNestedPre) != 1 || uNestedPre[0] != "18446744073709551615" {
		t.Fatalf("F13 expected exact uint64 string in n__items__u_nested, got %+v", uNestedPre)
	}

	// F17: ExpandFieldPattern expands search_as_you_type subfields (_2gram, _3gram, _index_prefix)
	var saytSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties": {"suggest": {"type": "search_as_you_type"}}}`), &saytSpec)
	saytSch := CompileIndexSchema("db", "r49_sayt_idx", &saytSpec)
	expSayt := saytSch.ExpandFieldPattern("suggest.*")
	if len(expSayt) != 3 {
		t.Fatalf("F17 expected 3 subfields for suggest.*, got %+v", expSayt)
	}

	// F20: token_count enable_position_increments: false stopword filtering, null_value, object rejection, and multi-field
	var tcSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"tc_default": {"type": "token_count", "analyzer": "standard", "null_value": 0},
			"tc_no_pos":  {"type": "token_count", "analyzer": "standard", "enable_position_increments": false},
			"title": {
				"type": "text",
				"fields": {
					"words": {"type": "token_count", "analyzer": "standard", "enable_position_increments": false}
				}
			}
		}
	}`), &tcSpec)
	tcSch := CompileIndexSchema("db", "r49_tc_idx", &tcSpec)
	tcBytes, err := ShredDocument(tcSch, "1", 1, false, []byte(`{
		"tc_default": null,
		"tc_no_pos": "the quick and brown fox",
		"title": "the quick and brown fox"
	}`))
	if err != nil {
		t.Fatalf("F20 ShredDocument failed: %v", err)
	}
	var tcRow map[string]any
	_ = json.Unmarshal(tcBytes, &tcRow)
	// "the" and "and" are stopwords; 3 non-stopword tokens remain ("quick", "brown", "fox")
	if tcRow["f__tc_default"] != float64(0) || tcRow["f__tc_no_pos"] != float64(3) || tcRow["f__title__words"] != float64(3) {
		t.Fatalf("F20 unexpected token_count values: default=%v no_pos=%v title.words=%v", tcRow["f__tc_default"], tcRow["f__tc_no_pos"], tcRow["f__title__words"])
	}
	if _, err := ShredDocument(tcSch, "2", 1, false, []byte(`{"tc_default": {"bad": "object"}}`)); err == nil {
		t.Fatalf("F20 expected mapper_parsing_exception when indexing object into token_count field")
	}

	// F21: InferMappingFromSampleDocs respects dynamic: "false" / "runtime", dynamic_templates double array vs dense_vector, and preserves multi-fields
	var baseSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"dynamic": "true",
		"dynamic_templates": [
			{
				"float_arrays_as_double": {
					"match": "scores_*",
					"mapping": {"type": "double"}
				}
			}
		],
		"properties": {
			"frozen_obj": {
				"type": "object",
				"dynamic": "false",
				"properties": {
					"known": {"type": "keyword"}
				}
			},
			"tags": {
				"type": "text",
				"fields": {
					"raw": {"type": "keyword"}
				}
			}
		}
	}`), &baseSpec)
	inf := InferMappingFromSampleDocs([]json.RawMessage{
		json.RawMessage(`{
			"frozen_obj": {"known": "ok", "secret": "do_not_infer"},
			"scores_vec": [0.1, 0.2, 0.3],
			"tags": ["a", "b"]
		}`),
	}, &baseSpec)
	if _, hasSecret := inf.Properties["frozen_obj"].Properties["secret"]; hasSecret {
		t.Fatalf("F21 expected dynamic:false sub-object to skip inferring 'secret', got %+v", inf.Properties["frozen_obj"].Properties)
	}
	if inf.Properties["scores_vec"].Type != "double" {
		t.Fatalf("F21 expected dynamic_template to map scores_vec as double instead of dense_vector, got %+v", inf.Properties["scores_vec"])
	}
	if _, hasRaw := inf.Properties["tags"].Fields["raw"]; !hasRaw {
		t.Fatalf("F21 expected tags.fields.raw to be preserved when upgraded to multi-valued, got %+v", inf.Properties["tags"])
	}
}

func TestRound50ShredderNestedRangeArrayNullValueAndCopyToGuards(t *testing.T) {
	ignoreTrue := true
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"age": {
				"type": "integer",
				"ignore_malformed": true,
				"null_value": -1,
				"copy_to": "all_copied"
			},
			"const_env": {
				"type": "constant_keyword",
				"value": "production",
				"copy_to": "all_copied"
			},
			"all_copied": {
				"type": "keyword"
			},
			"items": {
				"type": "nested",
				"properties": {
					"window": {
						"type": "integer_range"
					}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	_ = ignoreTrue
	idxSchema := CompileIndexSchema("db", "r50_idx", &spec)

	// 1. F18: [null] array applies null_value (-1), constant_keyword omitted in _source still copies "production" to copy_to
	shredded1, err := ShredDocument(idxSchema, "1", 1, false, []byte(`{
		"age": [null],
		"items": [{"window": {"gt": 10, "lt": 20}}]
	}`))
	if err != nil {
		t.Fatalf("ShredDocument 1 failed: %v", err)
	}
	var row1 map[string]any
	if err := json.Unmarshal(shredded1, &row1); err != nil {
		t.Fatalf("unmarshal row1 failed: %v", err)
	}
	if gotAge, _ := row1["f__age"].(float64); gotAge != -1 {
		t.Fatalf("F18 expected f__age == -1 for [null] with null_value=-1, got %v", row1["f__age"])
	}
	copied1, _ := row1["f__all_copied"].([]any)
	hasProd := false
	for _, v := range copied1 {
		if v == "production" {
			hasProd = true
		}
	}
	if !hasProd {
		t.Fatalf("F18 expected omitted constant_keyword to copy 'production' to f__all_copied, got %v", row1["f__all_copied"])
	}
	// F12: nested range subfield normalized with _gte and _lte in nested JSON element
	nestedItems, _ := row1["n__items"].([]any)
	if len(nestedItems) != 1 || !strings.Contains(nestedItems[0].(string), `"_gte":11`) || !strings.Contains(nestedItems[0].(string), `"_lte":19`) {
		t.Fatalf("F12 expected nested integer_range element to contain _gte:11 and _lte:19, got %v", nestedItems)
	}

	// 2. F18: malformed field with ignore_malformed=true must NOT copy raw malformed value into copy_to target
	shredded2, err := ShredDocument(idxSchema, "2", 1, false, []byte(`{
		"age": "not_an_int"
	}`))
	if err != nil {
		t.Fatalf("ShredDocument 2 failed: %v", err)
	}
	var row2 map[string]any
	if err := json.Unmarshal(shredded2, &row2); err != nil {
		t.Fatalf("unmarshal row2 failed: %v", err)
	}
	for _, v := range row2["f__all_copied"].([]any) {
		if v == "not_an_int" {
			t.Fatalf("F18 expected malformed age not to be copied to f__all_copied, got %v", row2["f__all_copied"])
		}
	}
}

func TestRound51SchemaAliasAndShredderF15F16(t *testing.T) {
	// F15: ValidateMappingSpec rejects invalid alias mappings
	invalidAliases := []*esast.MappingSpec{
		// Missing path
		{Properties: map[string]esast.FieldProperty{
			"a": {Type: "alias"},
		}},
		// Self-referencing path
		{Properties: map[string]esast.FieldProperty{
			"a": {Type: "alias", Path: "a"},
		}},
		// Chained alias -> alias
		{Properties: map[string]esast.FieldProperty{
			"real": {Type: "keyword"},
			"a1":   {Type: "alias", Path: "real"},
			"a2":   {Type: "alias", Path: "a1"},
		}},
		// Cyclic alias a -> b -> a
		{Properties: map[string]esast.FieldProperty{
			"a": {Type: "alias", Path: "b"},
			"b": {Type: "alias", Path: "a"},
		}},
		// Dangling target field
		{Properties: map[string]esast.FieldProperty{
			"real": {Type: "keyword"},
			"bad":  {Type: "alias", Path: "non_existent"},
		}},
	}
	for i, spec := range invalidAliases {
		if err := ValidateMappingSpec(spec); err == nil {
			t.Fatalf("F15 case %d: expected ValidateMappingSpec error for %+v", i, spec)
		}
	}

	// Valid alias mapping
	validAliasSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title": {
				Type: "text",
				Fields: map[string]esast.FieldProperty{
					"keyword": {Type: "keyword"},
				},
			},
			"title_alias":    {Type: "alias", Path: "title"},
			"title_kw_alias": {Type: "alias", Path: "title.keyword"},
		},
	}
	if err := ValidateMappingSpec(validAliasSpec); err != nil {
		t.Fatalf("F15 valid alias spec failed: %v", err)
	}

	// CompileIndexSchema cycle safety & ResolveField guard against empty ColumnName
	cyclicSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"a": {Type: "alias", Path: "b"},
			"b": {Type: "alias", Path: "a"},
		},
	}
	cyclicSchema := CompileIndexSchema("db", "cyclic_idx", cyclicSpec)
	b := cyclicSchema.ResolveField("a")
	if b.ESType == "alias" || (b.Kind == StoragePromotedScalar && b.ColumnName == "") {
		t.Fatalf("F15 expected unresolved alias to fall back to variant instead of empty ColumnName, got %+v", b)
	}

	// F16: ShredDocument rejects JSON object or array of objects for concrete scalar fields
	scalarSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"name":  {Type: "keyword"},
			"count": {Type: "long"},
			"raw": {
				Type:    "object",
				Enabled: func() *bool { f := false; return &f }(),
			},
		},
	}
	// Even if InferMappingFromSampleDocs sees an object for "name", it must not corrupt scalar type
	inferred := InferMappingFromSampleDocs([]json.RawMessage{
		json.RawMessage(`{"name":{"nested":"bad"},"count":[{"nested":1}]}`),
	}, scalarSpec)
	sSchema := CompileIndexSchema("db", "scalar_idx", inferred)
	if _, err := ShredDocument(sSchema, "1", 1, false, []byte(`{"name":{"nested":"bad"}}`)); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("F16 expected mapper_parsing_exception for object in keyword field, got %v", err)
	}
	if _, err := ShredDocument(sSchema, "2", 1, false, []byte(`{"count":[{"nested":1}]}`)); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
		t.Fatalf("F16 expected mapper_parsing_exception for array of objects in long field, got %v", err)
	}

	// F16: enabled: false subtree bypasses strict/subobjects validation
	subobjectsFalse := false
	strictDisabledSpec := &esast.MappingSpec{
		Dynamic:    "strict",
		Subobjects: &subobjectsFalse,
		Properties: map[string]esast.FieldProperty{
			"payload": {
				Type:    "object",
				Enabled: func() *bool { f := false; return &f }(),
			},
		},
	}
	sdSchema := CompileIndexSchema("db", "strict_disabled_idx", strictDisabledSpec)
	if _, err := ShredDocument(sdSchema, "1", 1, false, []byte(`{"payload":{"a.b.c":{"deep":123}}}`)); err != nil {
		t.Fatalf("F16 expected enabled:false subtree to bypass strict/subobjects validation, got %v", err)
	}
}

func TestRound52SchemaAndShredderF15ToF17(t *testing.T) {
	// F15: scaled_float requires scaling_factor > 0; constant_keyword rejects non-scalar value
	for _, badMapping := range []string{
		`{"properties":{"price":{"type":"scaled_float"}}}`,
		`{"properties":{"price":{"type":"scaled_float","scaling_factor":0}}}`,
		`{"properties":{"price":{"type":"scaled_float","scaling_factor":-10}}}`,
		`{"properties":{"env":{"type":"constant_keyword","value":{"nested":"bad"}}}}`,
		`{"properties":{"env":{"type":"constant_keyword","value":["a","b"]}}}`,
	} {
		var ms esast.MappingSpec
		if err := json.Unmarshal([]byte(badMapping), &ms); err != nil {
			t.Fatalf("unmarshal mapping %s failed: %v", badMapping, err)
		}
		if err := ValidateMappingSpec(&ms); err == nil {
			t.Fatalf("F15 expected ValidateMappingSpec error for %s", badMapping)
		}
	}

	// F15: constant_keyword inside nested objects populated & validated by ShredDocument
	var ckNestedSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"items": {
				"type": "nested",
				"properties": {
					"env": {"type": "constant_keyword", "value": "prod"},
					"name": {"type": "keyword"}
				}
			}
		}
	}`), &ckNestedSpec)
	if err := ValidateMappingSpec(&ckNestedSpec); err != nil {
		t.Fatalf("F15 valid nested constant_keyword mapping failed: %v", err)
	}
	ckSchema := CompileIndexSchema("db", "ck_nested_idx", &ckNestedSpec)
	rowCK, err := ShredDocument(ckSchema, "1", 1, false, []byte(`{"items":[{"name":"a"},{"name":"b","env":"prod"}]}`))
	if err != nil {
		t.Fatalf("F15 ShredDocument nested constant_keyword failed: %v", err)
	}
	if !strings.Contains(string(rowCK), `"n__items__env":["prod"]`) || !strings.Contains(string(rowCK), `\"env\":\"prod\"`) {
		t.Fatalf("F15 expected n__items__env = ['prod'] and nested env = 'prod', got %s", string(rowCK))
	}
	if _, err := ShredDocument(ckSchema, "2", 1, false, []byte(`{"items":[{"name":"a","env":"staging"}]}`)); err == nil {
		t.Fatalf("F15 expected ShredDocument to reject mismatched nested constant_keyword value")
	}

	// F16: flattened field rejects root scalar / scalar array, strips null leaves, and merges array-of-objects
	var flatSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"labels": {"type": "flattened"}
		}
	}`), &flatSpec)
	flatSchema := CompileIndexSchema("db", "flat_idx", &flatSpec)
	for _, badDoc := range []string{
		`{"labels":"scalar_str"}`,
		`{"labels":123}`,
		`{"labels":true}`,
		`{"labels":["a","b"]}`,
	} {
		if _, err := ShredDocument(flatSchema, "1", 1, false, []byte(badDoc)); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
			t.Fatalf("F16 expected mapper_parsing_exception for flattened root scalar %s, got %v", badDoc, err)
		}
	}
	// Null-only leaves removed from _doc
	rowNullFlat, err := ShredDocument(flatSchema, "2", 1, false, []byte(`{"labels":{"a":null,"b":[null]}}`))
	if err != nil {
		t.Fatalf("F16 ShredDocument null-only flattened failed: %v", err)
	}
	var nullFlatMap map[string]any
	_ = json.Unmarshal(rowNullFlat, &nullFlatMap)
	if docMap, ok := nullFlatMap["_doc"].(map[string]any); ok {
		if _, hasLabels := docMap["labels"]; hasLabels {
			t.Fatalf("F16 expected null-only flattened object to be omitted from _doc, got %s", string(rowNullFlat))
		}
	}
	// Array of objects merged in _doc
	rowArrFlat, err := ShredDocument(flatSchema, "3", 1, false, []byte(`{"labels":[{"env":"prod"},{"env":"dev","tier":"1"}]}`))
	if err != nil {
		t.Fatalf("F16 ShredDocument array-of-objects flattened failed: %v", err)
	}
	var arrFlatMap map[string]any
	_ = json.Unmarshal(rowArrFlat, &arrFlatMap)
	docMap, _ := arrFlatMap["_doc"].(map[string]any)
	labelsMap, _ := docMap["labels"].(map[string]any)
	envSlice, _ := labelsMap["env"].([]any)
	if len(envSlice) != 2 || envSlice[0] != "prod" || envSlice[1] != "dev" {
		t.Fatalf("F16 expected flattened array-of-objects to merge into {\"env\":[\"prod\",\"dev\"]} in _doc, got %s", string(rowArrFlat))
	}

	// F17: unsigned_long precision and 2^64 overflow rejection
	var ulSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"u":{"type":"unsigned_long"}}}`), &ulSpec)
	ulSchema := CompileIndexSchema("db", "ul_idx", &ulSpec)
	for _, badUL := range []string{
		`{"u":18446744073709551616}`,
		`{"u":"18446744073709551616"}`,
		`{"u":"18446744073709551616.0"}`,
		`{"u":-1}`,
	} {
		if _, err := ShredDocument(ulSchema, "1", 1, false, []byte(badUL)); err == nil {
			t.Fatalf("F17 expected error for out-of-range unsigned_long %s", badUL)
		}
	}
	rowMaxUL, err := ShredDocument(ulSchema, "2", 1, false, []byte(`{"u":"18446744073709551615.0"}`))
	if err != nil {
		t.Fatalf("F17 expected MaxUint64 decimal string '18446744073709551615.0' to succeed, got %v", err)
	}
	if !strings.Contains(string(rowMaxUL), `"f__u":9223372036854775807`) {
		t.Fatalf("F17 expected MaxUint64 clamped to MaxInt64 in f__u, got %s", string(rowMaxUL))
	}
}

func TestRound53SchemaAndShredderF15F16(t *testing.T) {
	// F15: ValidateMappingSpec rejects unknown types, invalid dynamic modes, bad dense_vector dims/similarity,
	// null_value on text/flattened/nested/object, negative ignore_above, invalid index_prefixes, and invalid join relations.
	for _, badMapping := range []string{
		`{"properties":{"f":{"type":"nonexistent_type"}}}`,
		`{"dynamic":"bogus","properties":{"f":{"type":"keyword"}}}`,
		`{"properties":{"obj":{"type":"object","dynamic":"bogus"}}}`,
		`{"properties":{"vec":{"type":"dense_vector","dims":0}}}`,
		`{"properties":{"vec":{"type":"dense_vector","dims":5000}}}`,
		`{"properties":{"vec":{"type":"dense_vector","dims":3,"similarity":"manhattan"}}}`,
		`{"properties":{"txt":{"type":"text","null_value":"N/A"}}}`,
		`{"properties":{"flat":{"type":"flattened","null_value":"N/A"}}}`,
		`{"properties":{"nest":{"type":"nested","null_value":"N/A"}}}`,
		`{"properties":{"obj":{"type":"object","null_value":"N/A"}}}`,
		`{"properties":{"kw":{"type":"keyword","ignore_above":-5}}}`,
		`{"properties":{"txt":{"type":"text","index_prefixes":{"min_chars":0,"max_chars":5}}}}`,
		`{"properties":{"txt":{"type":"text","index_prefixes":{"min_chars":2,"max_chars":20}}}}`,
		`{"properties":{"txt":{"type":"text","index_prefixes":{"min_chars":6,"max_chars":3}}}}`,
		`{"properties":{"txt":{"type":"text","index_prefixes":{"unknown":1}}}}`,
		`{"properties":{"j":{"type":"join"}}}`,
		`{"properties":{"j":{"type":"join","relations":{}}}}`,
		`{"properties":{"j":{"type":"join","relations":{"q":""}}}}`,
		`{"properties":{"j":{"type":"join","relations":{"q":"q"}}}}`,
	} {
		var ms esast.MappingSpec
		if err := json.Unmarshal([]byte(badMapping), &ms); err != nil {
			t.Fatalf("unmarshal mapping %s failed: %v", badMapping, err)
		}
		if err := ValidateMappingSpec(&ms); err == nil {
			t.Fatalf("F15 expected ValidateMappingSpec error for %s", badMapping)
		}
	}

	// Valid F15 & F16 mapping with sparse_vector, rank_features, dense_vector, index_prefixes, join
	var validSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"dynamic": "strict",
		"properties": {
			"ml_tokens": {"type": "sparse_vector"},
			"topics":    {"type": "rank_features"},
			"vec":       {"type": "dense_vector", "dims": 3, "similarity": "dot_product"},
			"title":     {"type": "text", "index_prefixes": {"min_chars": 2, "max_chars": 5}},
			"rel":       {"type": "join", "relations": {"question": ["answer", "comment"]}},
			"items": {
				"type": "nested",
				"properties": {
					"sub_tokens": {"type": "sparse_vector"}
				}
			}
		}
	}`), &validSpec); err != nil {
		t.Fatalf("unmarshal validSpec failed: %v", err)
	}
	if err := ValidateMappingSpec(&validSpec); err != nil {
		t.Fatalf("F15 expected validSpec to pass ValidateMappingSpec, got %v", err)
	}

	// F16: CompileIndexSchema & ResolveField for sparse_vector / rank_features + sub-key resolution + ShredDocument validation
	sch := CompileIndexSchema("db", "r53_sparse_idx", &validSpec)
	if b := sch.ResolveField("ml_tokens"); b.ESType != "sparse_vector" || b.Kind != StorageDynamicVariant {
		t.Fatalf("F16 expected ml_tokens ESType=sparse_vector StorageDynamicVariant, got %+v", b)
	}
	if b := sch.ResolveField("ml_tokens.shoes"); b.ESType != "sparse_vector" || b.ESFieldPath != "ml_tokens.shoes" || b.DorisType != DorisDouble {
		t.Fatalf("F16 expected ml_tokens.shoes to resolve as sparse_vector DorisDouble sub-key, got %+v", b)
	}
	if b := sch.ResolveField("topics.sports"); b.ESType != "rank_features" || b.ESFieldPath != "topics.sports" || b.DorisType != DorisDouble {
		t.Fatalf("F16 expected topics.sports to resolve as rank_features DorisDouble sub-key, got %+v", b)
	}
	if b := sch.ResolveField("items.sub_tokens.boots"); b.ESType != "sparse_vector" || b.NestedPath != "items" {
		t.Fatalf("F16 expected items.sub_tokens.boots to preserve NestedPath='items', got %+v", b)
	}

	// Shred valid sparse_vector & rank_features document under dynamic: "strict"
	shredOK, err := ShredDocument(sch, "1", 1, false, []byte(`{
		"ml_tokens": {"shoes": 1.5, "running": "0.75"},
		"topics": {"sports": 2.5},
		"vec": [0.1, 0.2, 0.3],
		"title": "running shoes",
		"rel": "question",
		"items": [{"sub_tokens": {"boots": 1.2}}]
	}`))
	if err != nil {
		t.Fatalf("F16 ShredDocument valid sparse_vector/rank_features failed: %v", err)
	}
	if !strings.Contains(string(shredOK), `"running":0.75`) {
		t.Fatalf("F16 expected numeric string token weight coerced to float 0.75, got %s", string(shredOK))
	}

	// Shred invalid sparse_vector & rank_features documents
	for _, badDoc := range []string{
		`{"ml_tokens": "not_an_object"}`,
		`{"ml_tokens": ["a", "b"]}`,
		`{"ml_tokens": {"shoes": "not_a_number"}}`,
		`{"ml_tokens": {"": 1.0}}`,
		`{"topics": {"sports": 0}}`,
		`{"topics": {"sports": -1.5}}`,
		`{"items": [{"sub_tokens": "bad"}]}`,
	} {
		if _, err := ShredDocument(sch, "2", 1, false, []byte(badDoc)); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
			t.Fatalf("F16 expected mapper_parsing_exception for %s, got %v", badDoc, err)
		}
	}
}

func TestRound54SchemaAndShredderF12F13F14(t *testing.T) {
	// F12: ValidateMappingSpec validates runtime and dynamic_templates even when properties is empty, plus copy_to validation
	for _, badMapping := range []string{
		`{"runtime":{"bad_rt":{"type":"nonexistent_rt_type"}}}`,
		`{"dynamic_templates":[{"t1":{"mapping":{"type":"keyword"}},"t2":{"mapping":{"type":"text"}}}]}`,
		`{"dynamic_templates":[{"t1":"not_an_object"}]}`,
		`{"dynamic_templates":[{"t1":{"unknown_key":1,"mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"match":"*"}}]}`,
		`{"dynamic_templates":[{"t1":{"match_mapping_type":"bogus_type","mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_pattern":"glob","mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_pattern":"regex","match":"[unclosed","mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_pattern":"regex","unmatch":"[unclosed","mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"match":"*","mapping":{"type":"nonexistent_type"}}}]}`,
		`{"properties":{"obj":{"type":"object","copy_to":"dest"},"dest":{"type":"text"}}}`,
		`{"properties":{"nest":{"type":"nested","copy_to":"dest"},"dest":{"type":"text"}}}`,
		`{"properties":{"al":{"type":"alias","path":"dest","copy_to":"dest"},"dest":{"type":"text"}}}`,
		`{"properties":{"f":{"type":"keyword","copy_to":""}}}`,
		`{"properties":{"f":{"type":"keyword","copy_to":123}}}`,
		`{"properties":{"f":{"type":"keyword","copy_to":["ok",""]}}}`,
		`{"properties":{"f":{"type":"keyword","copy_to":"f"}}}`,
		`{"properties":{"f":{"type":"keyword","copy_to":"obj"},"obj":{"type":"object"}}}`,
		`{"properties":{"f":{"type":"keyword","copy_to":"nest"},"nest":{"type":"nested"}}}`,
		`{"properties":{"f":{"type":"keyword","copy_to":"al"},"al":{"type":"alias","path":"f"}}}`,
	} {
		var ms esast.MappingSpec
		if err := json.Unmarshal([]byte(badMapping), &ms); err != nil {
			t.Fatalf("F12 unmarshal %s failed: %v", badMapping, err)
		}
		if err := ValidateMappingSpec(&ms); err == nil {
			t.Fatalf("F12 expected ValidateMappingSpec error for %s", badMapping)
		}
	}

	var validDTAndCopySpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"dynamic_templates": [
			{
				"strings_as_kw": {
					"match_mapping_type": "string",
					"match_pattern": "regex",
					"match": "^kw_.*",
					"unmatch": ".*_ignore$",
					"mapping": {"type": "{dynamic_type}"}
				}
			}
		],
		"properties": {
			"src": {"type": "keyword", "copy_to": ["full_text"]},
			"full_text": {"type": "text"}
		}
	}`), &validDTAndCopySpec); err != nil {
		t.Fatalf("F12 valid unmarshal failed: %v", err)
	}
	if err := ValidateMappingSpec(&validDTAndCopySpec); err != nil {
		t.Fatalf("F12 expected valid dynamic_templates and copy_to to pass, got %v", err)
	}

	// F13: coerce:false decimal JSON tokens on integer/nested integer, nested date coerce:false, float/half_float overflow, and constant_keyword ignore_malformed
	var f13Spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"int_no_coerce": {"type": "integer", "coerce": false},
			"flt":           {"type": "float"},
			"hflt":          {"type": "half_float"},
			"ck_ignore":     {"type": "constant_keyword", "value": "prod"},
			"items": {
				"type": "nested",
				"properties": {
					"n_int": {"type": "integer", "coerce": false},
					"n_dt":  {"type": "date", "format": "strict_date", "coerce": false},
					"n_flt": {"type": "half_float"},
					"n_ck":  {"type": "constant_keyword", "value": "v1"}
				}
			}
		}
	}`), &f13Spec); err != nil {
		t.Fatalf("F13 unmarshal failed: %v", err)
	}
	f13Schema := CompileIndexSchema("db", "r54_f13_idx", &f13Spec)
	for _, badDoc := range []string{
		`{"int_no_coerce": 5.0}`,
		`{"int_no_coerce": 1e2}`,
		`{"flt": 1e39}`,
		`{"hflt": 70000}`,
		`{"items": [{"n_int": 5.0}]}`,
		`{"items": [{"n_dt": 1700000000000}]}`,
		`{"items": [{"n_flt": 70000}]}`,
		`{"items": [{"n_ck": "v2"}]}`,
	} {
		if _, err := ShredDocument(f13Schema, "1", 1, false, []byte(badDoc)); err == nil {
			t.Fatalf("F13 expected ShredDocument error for %s", badDoc)
		}
	}
	// constant_keyword with ignore_malformed=true and mismatched value should NOT populate f__ck_ignore
	rowCKMalformed, err := ShredDocument(f13Schema, "2", 1, true, []byte(`{"ck_ignore": "staging"}`))
	if err != nil {
		t.Fatalf("F13 expected ignore_malformed=true on constant_keyword not to return error, got %v", err)
	}
	if strings.Contains(string(rowCKMalformed), `"f__ck_ignore":"prod"`) {
		t.Fatalf("F13 expected mismatched constant_keyword with ignore_malformed=true not to populate f__ck_ignore, got %s", string(rowCKMalformed))
	}

	// F14: dotted/multi-level nested_objects.limit, MaxDepth, and MaxFieldNameLength in ShredDocumentWithNow
	var f14Spec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"group": {
				"properties": {
					"items": {
						"type": "nested",
						"properties": {
							"replies": {
								"type": "nested",
								"properties": {
									"msg": {"type": "keyword"}
								}
							}
						}
					}
				}
			}
		}
	}`), &f14Spec)
	f14Schema := CompileIndexSchema("db", "r54_f14_idx", &f14Spec)
	f14Schema.MaxNestedObjects = 2
	if _, err := ShredDocument(f14Schema, "1", 1, false, []byte(`{"group":{"items":[{"replies":[{"msg":"a"},{"msg":"b"}]}]}}`)); err == nil || !strings.Contains(err.Error(), "nested documents") {
		t.Fatalf("F14 expected nested_objects.limit error on multi-level nested doc (1 item + 2 replies = 3 > 2), got %v", err)
	}
	f14Schema.MaxNestedObjects = 100
	f14Schema.MaxDepth = 2
	if _, err := ShredDocument(f14Schema, "2", 1, false, []byte(`{"a":{"b":{"c":"too_deep"}}}`)); err == nil || !strings.Contains(err.Error(), "depth [2]") {
		t.Fatalf("F14 expected MaxDepth error in ShredDocument, got %v", err)
	}
	f14Schema.MaxDepth = 20
	f14Schema.MaxFieldNameLength = 5
	if _, err := ShredDocument(f14Schema, "3", 1, false, []byte(`{"toolongname":"val"}`)); err == nil || !strings.Contains(err.Error(), "longer than the limit of [5]") {
		t.Fatalf("F14 expected MaxFieldNameLength error in ShredDocument, got %v", err)
	}
}

func TestRound55SchemaAndShredderF12ToF14(t *testing.T) {
	// F12 & F13: finalizeCompiledSlices sets DorisType=DorisString on copy_to StoragePromotedArray targets,
	// visits flattened copy_to sources, and preserves exact uint64 (> math.MaxInt64) on unsigned_long copy_to targets.
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"labels": {
				"type": "flattened",
				"copy_to": "all_tags"
			},
			"all_tags": {
				"type": "keyword"
			},
			"src_num": {
				"type": "long",
				"copy_to": "dst_num"
			},
			"dst_num": {
				"type": "long"
			},
			"src_u64": {
				"type": "unsigned_long",
				"copy_to": ["dst_u64", "dst_parent"]
			},
			"dst_u64": {
				"type": "unsigned_long"
			},
			"dst_parent": {
				"type": "keyword",
				"fields": {
					"u64": {
						"type": "unsigned_long"
					}
				}
			},
			"outer": {
				"properties": {
					"my_range": {"type": "integer_range"},
					"my_flat":  {"type": "flattened", "normalizer": "lowercase"},
					"my_vec":   {"type": "rank_features"}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("Round 55 mapping unmarshal failed: %v", err)
	}
	sc := CompileIndexSchema("db", "r55_idx", &spec)

	// F12(1): dst_num and dst_u64 and dst_parent.u64 upgraded to StoragePromotedArray must have DorisType == DorisString
	for _, fieldName := range []string{"dst_num", "dst_u64", "dst_parent.u64"} {
		b, ok := sc.Fields[fieldName]
		if !ok {
			t.Fatalf("F12 missing field %s", fieldName)
		}
		if b.Kind != StoragePromotedArray || b.DorisType != DorisString {
			t.Fatalf("F12 expected %s to have Kind=StoragePromotedArray and DorisType=DorisString, got Kind=%v DorisType=%v", fieldName, b.Kind, b.DorisType)
		}
	}

	// F12(2) & F13: Shred document with flattened copy_to and unsigned_long > math.MaxInt64 copy_to
	rowBytes, err := ShredDocument(sc, "doc1", 1, false, []byte(`{
		"labels": {"env": "prod", "team": ["core", "search"]},
		"src_u64": 18446744073709551610
	}`))
	if err != nil {
		t.Fatalf("F12/F13 ShredDocument failed: %v", err)
	}
	rowStr := string(rowBytes)
	if !strings.Contains(rowStr, `"prod"`) || !strings.Contains(rowStr, `"core"`) || !strings.Contains(rowStr, `"search"`) {
		t.Fatalf("F12 expected flattened copy_to values in all_tags, got %s", rowStr)
	}
	if strings.Contains(rowStr, `"9223372036854775807"`) || !strings.Contains(rowStr, `"18446744073709551610"`) {
		t.Fatalf("F13 expected unsigned_long > MaxInt64 to preserve 18446744073709551610 in copy_to array, got %s", rowStr)
	}

	// F14: Flat dotted keys in _source for sub-object range, flattened, and sparse_vector/rank_features
	if _, err := ShredDocument(sc, "bad_range", 1, false, []byte(`{"outer.my_range": {"gte": 20, "lte": 10}}`)); err == nil {
		t.Fatalf("F14 expected error for flat dotted key outer.my_range with gte > lte")
	}
	if _, err := ShredDocument(sc, "bad_flat", 1, false, []byte(`{"outer.my_flat": "not_an_object"}`)); err == nil {
		t.Fatalf("F14 expected error for flat dotted key outer.my_flat with scalar value")
	}
	if _, err := ShredDocument(sc, "bad_vec", 1, false, []byte(`{"outer.my_vec": {"tok": -1.5}}`)); err == nil {
		t.Fatalf("F14 expected error for flat dotted key outer.my_vec with non-positive rank_features weight")
	}
	validDottedBytes, err := ShredDocument(sc, "ok_dotted", 1, false, []byte(`{
		"outer.my_range": {"gte": 5, "lte": 15},
		"outer.my_flat": {"Key": "UPPER_VAL"},
		"outer.my_vec": {"tok": "2.5"}
	}`))
	if err != nil {
		t.Fatalf("F14 expected valid flat dotted keys to shred cleanly, got %v", err)
	}
	validDottedStr := string(validDottedBytes)
	if !strings.Contains(validDottedStr, `"_gte":5`) || !strings.Contains(validDottedStr, `"upper_val"`) {
		t.Fatalf("F14 expected normalized _gte and lowercased flattened value in _doc, got %s", validDottedStr)
	}
}

func TestRound56SchemaAndShredderF12ToF16(t *testing.T) {
	// --- F12: subobjects: false in ValidateMappingSpec & ShredDocument ---
	invalidSubobjMappings := []string{
		`{"properties":{"k":{"type":"keyword","subobjects":false}}}`,
		`{"properties":{"n":{"type":"nested","subobjects":false}}}`,
		`{"subobjects":false,"properties":{"obj":{"type":"object"}}}`,
		`{"subobjects":false,"properties":{"obj":{"properties":{"a":{"type":"keyword"}}}}}`,
		`{"subobjects":false,"properties":{"items":{"type":"nested","properties":{"a":{"type":"keyword"}}}}}`,
		`{"properties":{"metrics":{"type":"object","subobjects":false,"properties":{"child":{"type":"object"}}}}}`,
		`{"properties":{"metrics":{"type":"object","subobjects":false,"properties":{"child":{"properties":{"x":{"type":"long"}}}}}}}`,
		`{"properties":{"metrics":{"type":"object","subobjects":false,"properties":{"items":{"type":"nested"}}}}}`,
	}
	for _, raw := range invalidSubobjMappings {
		var spec esast.MappingSpec
		if err := json.Unmarshal([]byte(raw), &spec); err != nil {
			t.Fatalf("F12 unmarshal %s failed: %v", raw, err)
		}
		if err := ValidateMappingSpec(&spec); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
			t.Fatalf("F12 expected mapper_parsing_exception for %s, got %v", raw, err)
		}
	}

	var subobjSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"dynamic": "strict",
		"properties": {
			"metrics": {
				"type": "object",
				"subobjects": false,
				"properties": {
					"time":     {"type": "long"},
					"time.min": {"type": "long"},
					"labels":   {"type": "flattened"},
					"loc":      {"type": "geo_point"},
					"raw_blob": {"type": "object", "enabled": false}
				}
			},
			"tag":      {"type": "keyword"},
			"tag.sub":  {"type": "keyword"},
			"geo":      {"type": "geo_point"},
			"geo.alt":  {"type": "geo_point"},
			"flat":     {"type": "flattened"},
			"flat.sub": {"type": "flattened"},
			"nv.leaf":  {"type": "keyword", "null_value": "WAS_NULL"},
			"nv":       {"type": "keyword"}
		}
	}`), &subobjSpec); err != nil {
		t.Fatalf("F12 valid mapping unmarshal failed: %v", err)
	}
	if err := ValidateMappingSpec(&subobjSpec); err != nil {
		t.Fatalf("F12 expected valid subobjects:false mapping, got %v", err)
	}
	subobjSchema := CompileIndexSchema("db", "r56_subobj", &subobjSpec)

	// Flat dotted keys + object-accepting leaf types + scalar/dotted coexistence succeed without data loss
	coexistBytes, err := ShredDocument(subobjSchema, "d1", 1, false, []byte(`{
		"metrics": {
			"time": 100,
			"time.min": 10,
			"labels": {"env": "prod"},
			"loc": {"lat": 40.7, "lon": -74.0},
			"raw_blob": {"nested": {"anything": true}}
		},
		"tag": "parent_tag",
		"tag.sub": "child_tag",
		"geo": "40.0,-70.0",
		"geo.alt": "41.0,-71.0",
		"flat": {"k1": "v1"},
		"flat.sub": {"k2": "v2"},
		"nv": "parent_nv",
		"nv.leaf": null
	}`))
	if err != nil {
		t.Fatalf("F12 ShredDocument valid subobjects:false & scalar+dotted coexistence failed: %v", err)
	}
	var coexistRow map[string]any
	if err := json.Unmarshal(coexistBytes, &coexistRow); err != nil {
		t.Fatalf("F12 unmarshal shredded row failed: %v", err)
	}
	if coexistRow["f__metrics__time"] != float64(100) || coexistRow["f__metrics__time__min"] != float64(10) {
		t.Fatalf("F12 lost scalar/dotted numeric values: %+v", coexistRow)
	}
	if coexistRow["f__tag"] != "parent_tag" || coexistRow["f__tag__sub"] != "child_tag" {
		t.Fatalf("F12 lost scalar/dotted string values: %+v", coexistRow)
	}
	if coexistRow["f__geo"] != "40,-70" || coexistRow["f__geo__alt"] != "41,-71" {
		t.Fatalf("F12 lost scalar/dotted geo_point values: %+v", coexistRow)
	}
	if coexistRow["f__nv"] != "parent_nv" || coexistRow["f__nv__leaf"] != "WAS_NULL" {
		t.Fatalf("F12 lost scalar/dotted explicit null_value handling: %+v", coexistRow)
	}

	// Reject nested sub-object or array-of-objects inside subobjects:false
	for _, badDoc := range []string{
		`{"metrics":{"time":{"min":10}}}`,
		`{"metrics":{"time":[{"min":10}]}}`,
	} {
		if _, err := ShredDocument(subobjSchema, "bad", 1, false, []byte(badDoc)); err == nil {
			t.Fatalf("F12 expected subobjects:false to reject nested object in %s", badDoc)
		}
	}

	// --- F13: ValidateMappingUpdateCompatibility root validation & subobjects immutability ---
	var oldCompat esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"grp": {
				"type": "object",
				"properties": {"a": {"type": "keyword"}}
			},
			"flat_grp": {
				"type": "object",
				"subobjects": false,
				"properties": {"b.c": {"type": "keyword"}}
			}
		}
	}`), &oldCompat)

	// Valid idempotent updates (default true -> explicit true; false -> false)
	for _, okUpd := range []string{
		`{"subobjects":true,"properties":{"grp":{"type":"object","subobjects":true},"flat_grp":{"type":"object","subobjects":false}}}`,
	} {
		var upd esast.MappingSpec
		_ = json.Unmarshal([]byte(okUpd), &upd)
		if err := ValidateMappingUpdateCompatibility(&oldCompat, &upd); err != nil {
			t.Fatalf("F13 expected idempotent subobjects update to succeed, got %v", err)
		}
	}

	// Invalid updates: root dynamic invalid, root runtime invalid, root subobjects flip, field subobjects flip
	invalidUpdates := []struct {
		raw     string
		wantSub string
	}{
		{`{"dynamic":"invalid_mode"}`, "dynamic"},
		{`{"runtime":{"bad_rt":{"type":"not_a_runtime_type"}}}`, "mapper_parsing_exception"},
		{`{"subobjects":false}`, "Cannot update parameter [subobjects]"},
		{`{"properties":{"grp":{"type":"object","subobjects":false}}}`, "Cannot update parameter [subobjects]"},
		{`{"properties":{"flat_grp":{"type":"object","subobjects":true}}}`, "Cannot update parameter [subobjects]"},
	}
	for _, tc := range invalidUpdates {
		var upd esast.MappingSpec
		if err := json.Unmarshal([]byte(tc.raw), &upd); err != nil {
			t.Fatalf("F13 unmarshal %s failed: %v", tc.raw, err)
		}
		err := ValidateMappingUpdateCompatibility(&oldCompat, &upd)
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("F13 expected error containing %q for %s, got %v", tc.wantSub, tc.raw, err)
		}
	}

	// --- F14: ValidateMappingSpec null_value validation ---
	validNullValueMappings := []string{
		`{"properties":{"gp1":{"type":"geo_point","null_value":"40.7128,-74.0060"},"gp2":{"type":"geo_point","null_value":{"lat":40.7,"lon":-74.0}},"gp3":{"type":"geo_point","null_value":[-74.0,40.7]}}}`,
		`{"properties":{"pt1":{"type":"point","null_value":"POINT (1.5 2.5)"},"pt2":{"type":"point","null_value":[1.5,2.5]},"pt3":{"type":"point","null_value":{"x":1.5,"y":2.5}}}}`,
		`{"properties":{"b":{"type":"boolean","null_value":"false"},"ip":{"type":"ip","null_value":"2001:db8::1"},"v":{"type":"version","null_value":"1.2.3-rc.1+b2"}}}`,
		`{"properties":{"by":{"type":"byte","null_value":127},"u64":{"type":"unsigned_long","null_value":"18446744073709551615"},"sf":{"type":"scaled_float","scaling_factor":100,"null_value":12.34}}}`,
		`{"properties":{"d1":{"type":"date","null_value":"2025-01-15"},"d2":{"type":"date","format":"yyyy/MM/dd","null_value":"2025/01/15"},"dn":{"type":"date_nanos","null_value":"2025-01-15T00:00:00.123456789Z"}}}`,
	}
	for _, raw := range validNullValueMappings {
		var spec esast.MappingSpec
		if err := json.Unmarshal([]byte(raw), &spec); err != nil {
			t.Fatalf("F14 unmarshal valid %s failed: %v", raw, err)
		}
		if err := ValidateMappingSpec(&spec); err != nil {
			t.Fatalf("F14 expected valid null_value mapping %s, got %v", raw, err)
		}
	}

	invalidNullValueMappings := []string{
		// Unsupported types
		`{"properties":{"x":{"type":"keyword"},"a":{"type":"alias","path":"x","null_value":"v"}}}`,
		`{"properties":{"f":{"type":"binary","null_value":"YWJj"}}}`,
		`{"properties":{"f":{"type":"wildcard","null_value":"v"}}}`,
		`{"properties":{"f":{"type":"completion","null_value":"v"}}}`,
		`{"properties":{"f":{"type":"token_count","null_value":0}}}`,
		`{"properties":{"f":{"type":"murmur3","null_value":0}}}`,
		`{"properties":{"f":{"type":"histogram","null_value":"v"}}}`,
		`{"properties":{"f":{"type":"aggregate_metric_double","metrics":["min"],"default_metric":"min","null_value":0}}}`,
		`{"properties":{"f":{"type":"geo_shape","null_value":"POINT (0 0)"}}}`,
		`{"properties":{"f":{"type":"shape","null_value":"POINT (0 0)"}}}`,
		`{"properties":{"f":{"type":"constant_keyword","value":"k","null_value":"k"}}}`,
		// Invalid geo_point / point null_value
		`{"properties":{"f":{"type":"geo_point","null_value":"not_a_geo"}}}`,
		`{"properties":{"f":{"type":"geo_point","null_value":{"lat":200,"lon":0}}}}`,
		`{"properties":{"f":{"type":"geo_point","null_value":[1]}}}`,
		`{"properties":{"f":{"type":"point","null_value":"NOT_A_POINT"}}}`,
		// Invalid scalar/bounds/format null_value
		`{"properties":{"f":{"type":"keyword","null_value":{"a":1}}}}`,
		`{"properties":{"f":{"type":"keyword","null_value":["a"]}}}`,
		`{"properties":{"f":{"type":"boolean","null_value":"maybe"}}}`,
		`{"properties":{"f":{"type":"boolean","null_value":123}}}`,
		`{"properties":{"f":{"type":"ip","null_value":"999.999.999.999"}}}`,
		`{"properties":{"f":{"type":"version","null_value":"01.2.3"}}}`,
		`{"properties":{"f":{"type":"byte","null_value":128}}}`,
		`{"properties":{"f":{"type":"short","null_value":40000}}}`,
		`{"properties":{"f":{"type":"integer","null_value":3000000000}}}`,
		`{"properties":{"f":{"type":"integer","coerce":false,"null_value":"42"}}}`,
		`{"properties":{"f":{"type":"unsigned_long","null_value":-1}}}`,
		`{"properties":{"f":{"type":"unsigned_long","null_value":"18446744073709551616"}}}`,
		`{"properties":{"f":{"type":"scaled_float","scaling_factor":100,"null_value":"abc"}}}`,
		`{"properties":{"f":{"type":"date","null_value":"not-a-date"}}}`,
		`{"properties":{"f":{"type":"date","format":"yyyy/MM/dd","null_value":"2025-01-15"}}}`,
		`{"properties":{"f":{"type":"date_nanos","null_value":"bad-nanos"}}}`,
	}
	for _, raw := range invalidNullValueMappings {
		var spec esast.MappingSpec
		if err := json.Unmarshal([]byte(raw), &spec); err != nil {
			t.Fatalf("F14 unmarshal invalid %s failed: %v", raw, err)
		}
		if err := ValidateMappingSpec(&spec); err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
			t.Fatalf("F14 expected mapper_parsing_exception for %s, got %v", raw, err)
		}
	}

	// --- F15.1-2 & F16.1: ValidateSemver, version shredding validation, and ip canonicalization ---
	for _, okVer := range []string{"0.0.0", "1.2.3", "1.2.3-alpha.1", "1.2.3-0a", "1.2.3+20130313", "1.2.3-rc.10+exp.sha.5114f85"} {
		if !ValidateSemver(okVer) {
			t.Fatalf("F15 expected ValidateSemver(%q)=true", okVer)
		}
	}
	for _, badVer := range []string{"", "1.2", "1.2.3.4", "v1.2.3", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "1.2.3-", "1.2.3+", "1.2.3-rc..1"} {
		if ValidateSemver(badVer) {
			t.Fatalf("F15 expected ValidateSemver(%q)=false", badVer)
		}
	}

	var verIPSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"ver_scalar": {"type": "version"},
			"ver":        {"type": "version"},
			"ver_lenient":{"type": "version", "ignore_malformed": true},
			"src_str":    {"type": "keyword", "copy_to": "ver"},
			"items": {
				"type": "nested",
				"properties": {
					"nver": {"type": "version"}
				}
			},
			"client_ip":  {"type": "ip"}
		}
	}`), &verIPSpec); err != nil {
		t.Fatalf("F15/F16 mapping unmarshal failed: %v", err)
	}
	verIPSchema := CompileIndexSchema("db", "r56_ver_ip", &verIPSpec)

	// Invalid SemVer rejected across scalar, array, copy_to, and nested
	for _, badDoc := range []string{
		`{"ver_scalar":"01.2.3"}`,
		`{"ver_scalar":123}`,
		`{"ver":["1.0.0","1.0.0-01"]}`,
		`{"src_str":"not_semver"}`,
		`{"items":[{"nver":"bad_nested_ver"}]}`,
	} {
		if _, err := ShredDocument(verIPSchema, "bad", 1, false, []byte(badDoc)); err == nil {
			t.Fatalf("F15 expected invalid version error for %s", badDoc)
		}
	}

	// ignore_malformed: true skips malformed SemVer while keeping valid SemVer, and ip canonicalizes IPv6
	okVerIPBytes, err := ShredDocument(verIPSchema, "ok1", 1, false, []byte(`{
		"ver_scalar": "1.2.3-rc.2+build.7",
		"src_str": "3.0.0+copy",
		"ver_lenient": "01.2.3",
		"items": [{"nver": "2.0.0-alpha.1"}],
		"client_ip": "2001:0db8:0000:0000:0000:0000:0000:0001"
	}`))
	if err != nil {
		t.Fatalf("F15/F16 ShredDocument failed: %v", err)
	}
	var verIPRow map[string]any
	if err := json.Unmarshal(okVerIPBytes, &verIPRow); err != nil {
		t.Fatalf("F15/F16 unmarshal row failed: %v", err)
	}
	if verIPRow["f__ver_scalar"] != "1.2.3-rc.2+build.7" {
		t.Fatalf("F15 expected f__ver_scalar='1.2.3-rc.2+build.7', got %v", verIPRow["f__ver_scalar"])
	}
	verArr, okArr := verIPRow["f__ver"].([]any)
	if !okArr || len(verArr) != 1 || verArr[0] != "3.0.0+copy" {
		t.Fatalf("F15 expected f__ver=['3.0.0+copy'], got %v", verIPRow["f__ver"])
	}
	if _, exists := verIPRow["f__ver_lenient"]; exists && verIPRow["f__ver_lenient"] != nil {
		t.Fatalf("F15 expected malformed ver_lenient to be omitted/null, got %v", verIPRow["f__ver_lenient"])
	}
	if verIPRow["f__client_ip"] != "2001:db8::1" {
		t.Fatalf("F16 expected canonicalized IPv6 '2001:db8::1', got %v", verIPRow["f__client_ip"])
	}
}

func TestRound57SchemaAndShredderValidation(t *testing.T) {
	// F13: alias mapping rejects any parameter other than type and path
	badAliasMappings := []string{
		`{"properties":{"real":{"type":"keyword"},"al":{"type":"alias","path":"real","index":true}}}`,
		`{"properties":{"real":{"type":"keyword"},"al":{"type":"alias","path":"real","doc_values":false}}}`,
		`{"properties":{"real":{"type":"keyword"},"al":{"type":"alias","path":"real","store":true}}}`,
		`{"properties":{"real":{"type":"text"},"al":{"type":"alias","path":"real","analyzer":"standard"}}}`,
		`{"properties":{"real":{"type":"keyword"},"al":{"type":"alias","path":"real","normalizer":"lowercase"}}}`,
		`{"properties":{"real":{"type":"date"},"al":{"type":"alias","path":"real","format":"epoch_millis"}}}`,
		`{"properties":{"real":{"type":"keyword"},"al":{"type":"alias","path":"real","ignore_above":256}}}`,
		`{"properties":{"real":{"type":"long"},"al":{"type":"alias","path":"real","coerce":false}}}`,
		`{"properties":{"real":{"type":"text"},"al":{"type":"alias","path":"real","boost":2.0}}}`,
		`{"properties":{"real":{"type":"text"},"al":{"type":"alias","path":"real","norms":false}}}`,
		`{"properties":{"real":{"type":"text"},"al":{"type":"alias","path":"real","index_options":"freqs"}}}`,
		`{"properties":{"real":{"type":"keyword"},"al":{"type":"alias","path":"real","eager_global_ordinals":true}}}`,
		`{"properties":{"real":{"type":"text"},"al":{"type":"alias","path":"real","fielddata":true}}}`,
		`{"properties":{"real":{"type":"keyword"},"al":{"type":"alias","path":"real","meta":{"unit":"ms"}}}}`,
		`{"properties":{"real":{"type":"keyword"},"al":{"type":"alias","path":"real","copy_to":"other"}}}`,
	}
	for _, raw := range badAliasMappings {
		var spec esast.MappingSpec
		if err := json.Unmarshal([]byte(raw), &spec); err != nil {
			t.Fatalf("F13 unmarshal %s failed: %v", raw, err)
		}
		err := ValidateMappingSpec(&spec)
		if err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception: Mapping definition for [al] has unsupported parameters") {
			t.Fatalf("F13 expected unsupported parameters error for %s, got %v", raw, err)
		}
	}

	// F13: ShredDocument rejects writes to top-level, nested, array-of-maps, null, and dotted alias paths
	var aliasSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"real_name": {"type": "keyword"},
			"name_alias": {"type": "alias", "path": "real_name"},
			"obj": {
				"properties": {
					"sub": {
						"properties": {
							"leaf": {"type": "keyword"},
							"leaf_alias": {"type": "alias", "path": "obj.sub.leaf"}
						}
					}
				}
			}
		}
	}`), &aliasSpec); err != nil {
		t.Fatalf("F13 unmarshal valid alias failed: %v", err)
	}
	if err := ValidateMappingSpec(&aliasSpec); err != nil {
		t.Fatalf("F13 ValidateMappingSpec valid alias failed: %v", err)
	}
	aliasSchema := CompileIndexSchema("es_db", "r57_alias_idx", &aliasSpec)
	if _, err := ShredDocument(aliasSchema, "ok1", 1, false, []byte(`{"real_name":"alice","obj":{"sub":{"leaf":"v"}}}`)); err != nil {
		t.Fatalf("F13 expected write to real target fields to succeed, got %v", err)
	}
	if _, err := ShredDocument(aliasSchema, "ok2", 1, false, []byte(`{"real_name":"bob","obj":[{"sub":{"leaf":"v"}},{"other":"x"}]}`)); err != nil {
		t.Fatalf("F13 expected write to array of real target objects to succeed, got %v", err)
	}
	badAliasDocs := []struct {
		doc       string
		wantAlias string
	}{
		{`{"name_alias":"alice"}`, "name_alias"},
		{`{"name_alias":null}`, "name_alias"},
		{`{"obj":{"sub":{"leaf_alias":"v"}}}`, "obj.sub.leaf_alias"},
		{`{"obj":[{"sub":{"leaf_alias":"v"}}]}`, "obj.sub.leaf_alias"},
		{`{"obj.sub.leaf_alias":"v"}`, "obj.sub.leaf_alias"},
		{`{"obj.sub":{"leaf_alias":"v"}}`, "obj.sub.leaf_alias"},
	}
	for _, tc := range badAliasDocs {
		_, err := ShredDocument(aliasSchema, "bad1", 1, false, []byte(tc.doc))
		if err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception: Cannot write to a field alias ["+tc.wantAlias+"]") {
			t.Fatalf("F13 expected alias write rejection for %s on %s, got %v", tc.wantAlias, tc.doc, err)
		}
	}

	// F14: PUT _mapping immutability for constant_keyword.value, store, format, and default dense_vector.similarity
	var baseSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"env": {"type": "constant_keyword", "value": "prod"},
			"title": {"type": "keyword"},
			"stored_kw": {"type": "keyword", "store": true},
			"created_at": {"type": "date"},
			"nano_ts": {"type": "date_nanos"},
			"win": {"type": "date_range"},
			"emb": {"type": "dense_vector", "dims": 3}
		}
	}`), &baseSpec); err != nil {
		t.Fatalf("F14 unmarshal base mapping failed: %v", err)
	}

	incompatibleUpdates := []struct {
		raw     string
		wantSub string
	}{
		{`{"properties":{"env":{"type":"constant_keyword","value":"staging"}}}`, "Cannot update parameter [value]"},
		{`{"properties":{"title":{"type":"keyword","store":true}}}`, "Cannot update parameter [store]"},
		{`{"properties":{"stored_kw":{"type":"keyword","store":false}}}`, "Cannot update parameter [store]"},
		{`{"properties":{"created_at":{"type":"date","format":"yyyy-MM-dd"}}}`, "Cannot update parameter [format]"},
		{`{"properties":{"nano_ts":{"type":"date_nanos","format":"epoch_millis"}}}`, "Cannot update parameter [format]"},
		{`{"properties":{"win":{"type":"date_range","format":"yyyy-MM-dd"}}}`, "Cannot update parameter [format]"},
		{`{"properties":{"emb":{"type":"dense_vector","dims":3,"similarity":"dot_product"}}}`, "Cannot update parameter [similarity]"},
	}
	for _, tc := range incompatibleUpdates {
		var upd esast.MappingSpec
		if err := json.Unmarshal([]byte(tc.raw), &upd); err != nil {
			t.Fatalf("F14 unmarshal update %s failed: %v", tc.raw, err)
		}
		err := validatePropertiesCompatibility(baseSpec.Properties, upd.Properties, "")
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("F14 expected %q for %s, got %v", tc.wantSub, tc.raw, err)
		}
	}

	// Idempotent updates with explicit defaults must succeed, and DeepMergeMappingProperties preserves Store
	var idemUpd esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"env": {"type": "constant_keyword", "value": "prod"},
			"title": {"type": "keyword", "store": false},
			"stored_kw": {"type": "keyword", "store": true},
			"created_at": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
			"nano_ts": {"type": "date_nanos", "format": "strict_date_optional_time_nanos||epoch_millis"},
			"win": {"type": "date_range", "format": "strict_date_optional_time||epoch_millis"},
			"emb": {"type": "dense_vector", "dims": 3, "similarity": "cosine"},
			"new_stored": {"type": "keyword", "store": true}
		}
	}`), &idemUpd); err != nil {
		t.Fatalf("F14 unmarshal idempotent update failed: %v", err)
	}
	if err := validatePropertiesCompatibility(baseSpec.Properties, idemUpd.Properties, ""); err != nil {
		t.Fatalf("F14 expected idempotent mapping update to succeed, got %v", err)
	}
	mergedProps := DeepMergeMappingProperties(baseSpec.Properties, idemUpd.Properties)
	if mergedProps["new_stored"].Store == nil || !*mergedProps["new_stored"].Store {
		t.Fatalf("F14 expected DeepMergeMappingProperties to copy Store=true, got %+v", mergedProps["new_stored"].Store)
	}

	// F15: dynamic_templates validation
	badDynTemplates := []string{
		`{"dynamic_templates":[{"t1":{"match":123,"mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"unmatch":["a"],"mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"path_match":true,"mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"path_unmatch":{},"mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_pattern":"regex","path_match":"[unclosed","mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_pattern":"regex","path_unmatch":"(unclosed","mapping":{"type":"keyword"}}}]}`,
		`{"dynamic_templates":[{"t1":{"match":"*","mapping":{"type":"keyword","unknown_field":true}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_mapping_type":"double","mapping":{"type":"{dynamic_type}","scaling_factor":-5}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_mapping_type":"string","mapping":{"type":"{dynamic_type}","ignore_above":-1}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_mapping_type":"long","mapping":{"type":"{dynamic_type}","null_value":"not_a_long"}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_mapping_type":"long","mapping":{"type":"{dynamic_type}","scaling_factor":10}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_mapping_type":"object","mapping":{"type":"{dynamic_type}","copy_to":"other"}}}]}`,
		`{"dynamic_templates":[{"t1":{"match_mapping_type":"string","mapping":{"doc_values":true}}}]}`,
	}
	for _, raw := range badDynTemplates {
		var spec esast.MappingSpec
		if err := json.Unmarshal([]byte(raw), &spec); err != nil {
			t.Fatalf("F15 unmarshal %s failed: %v", raw, err)
		}
		err := ValidateMappingSpec(&spec)
		if err == nil || !strings.Contains(err.Error(), "mapper_parsing_exception") {
			t.Fatalf("F15 expected mapper_parsing_exception for %s, got %v", raw, err)
		}
	}

	var okDTSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{"dynamic_templates":[
		{"r1":{"match_pattern":"regex","path_match":"^metrics\\..*","path_unmatch":"^metrics\\.raw$","match_mapping_type":"double","mapping":{"type":"{dynamic_type}"}}},
		{"r2":{"match_mapping_type":"object","mapping":{"enabled":true}}},
		{"r3":{"match_mapping_type":"*","mapping":{"doc_values":true}}},
		{"r4":{"match_mapping_type":"boolean","mapping":{"type":"{dynamic_type}"}}},
		{"r5":{"match_mapping_type":"date","mapping":{"type":"{dynamic_type}"}}}
	]}`), &okDTSpec); err != nil {
		t.Fatalf("F15 unmarshal valid dynamic_templates failed: %v", err)
	}
	if err := ValidateMappingSpec(&okDTSpec); err != nil {
		t.Fatalf("F15 expected valid dynamic_templates to succeed, got %v", err)
	}

	// F16: cosine zero-magnitude vector rejection on ingest (respecting ignore_malformed and non-cosine metrics)
	var vecSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"cos_vec": {"type": "dense_vector", "dims": 3},
			"cos_lenient": {"type": "dense_vector", "dims": 3, "ignore_malformed": true},
			"l2_vec": {"type": "dense_vector", "dims": 3, "similarity": "l2_norm"},
			"dot_vec": {"type": "dense_vector", "dims": 3, "similarity": "dot_product"}
		}
	}`), &vecSpec); err != nil {
		t.Fatalf("F16 unmarshal vecSpec failed: %v", err)
	}
	vecSchema := CompileIndexSchema("es_db", "r57_vec_idx", &vecSpec)
	if _, err := ShredDocument(vecSchema, "z1", 1, false, []byte(`{"cos_vec":[0,0,0]}`)); err == nil || !strings.Contains(err.Error(), "Zero-magnitude vectors are not supported when using [cosine] similarity") {
		t.Fatalf("F16 expected zero-magnitude cosine vector rejection, got %v", err)
	}
	okVecBytes, err := ShredDocument(vecSchema, "z2", 1, false, []byte(`{
		"cos_vec": [0, 1, 0],
		"cos_lenient": [0, 0, 0],
		"l2_vec": [0, 0, 0],
		"dot_vec": [2.0, 3.0, 4.0]
	}`))
	if err != nil {
		t.Fatalf("F16 expected lenient cosine + l2 zero + non-unit dot_product to succeed, got %v", err)
	}
	var okVecRow map[string]any
	if err := json.Unmarshal(okVecBytes, &okVecRow); err != nil {
		t.Fatalf("F16 unmarshal row failed: %v", err)
	}
	if _, exists := okVecRow["v__cos_lenient"]; exists && okVecRow["v__cos_lenient"] != nil {
		t.Fatalf("F16 expected cos_lenient zero vector to be skipped when ignore_malformed=true, got %v", okVecRow["v__cos_lenient"])
	}
}
