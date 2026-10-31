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
