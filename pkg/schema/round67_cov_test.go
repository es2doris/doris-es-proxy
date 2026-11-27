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

func boolPtrR67(b bool) *bool { return &b }

func TestRound67DorisDDLOptionsAndANN(t *testing.T) {
	if got := GenerateCreateTableDDLWithOptions(nil, DorisDDLOptions{}); got != "" {
		t.Fatalf("expected empty DDL for nil schema, got %q", got)
	}

	spec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":         {Type: "text"},
			"vec_cos":       {Type: "dense_vector", Dims: 128, Similarity: "cosine"},
			"vec_l2":        {Type: "dense_vector", Dims: 64, Similarity: "l2_norm"},
			"vec_dot":       {Type: "dense_vector", Dims: 32, Similarity: "dot_product"},
			"vec_mip":       {Type: "dense_vector", Dims: 16, Similarity: "max_inner_product"},
			"vec_bit":       {Type: "dense_vector", Dims: 16, ElementType: "bit"},
			"vec_byte":      {Type: "dense_vector", Dims: 8, ElementType: "byte"},
			"vec_int4q":     {Type: "dense_vector", Dims: 8, ElementType: "int4_quantized"},
			"vec_int8q":     {Type: "dense_vector", Dims: 8, ElementType: "int8_quantized"},
			"vec_unindexed": {Type: "dense_vector", Dims: 8, Index: boolPtrR67(false)},
			"vec_autodims":  {Type: "dense_vector"},
			"very_long_vector_column_name_exceeding_sixty_four_characters_total_len": {Type: "dense_vector", Dims: 12, Similarity: "l2_norm"},
		},
	}
	sc := CompileIndexSchema("es_db", "round67_ddl_idx", spec)

	// Zero-value options must preserve exact legacy output.
	legacyDDL := GenerateCreateTableDDL(sc)
	zeroOptsDDL := GenerateCreateTableDDLWithOptions(sc, DorisDDLOptions{})
	if legacyDDL != zeroOptsDDL {
		t.Fatalf("expected zero-value DorisDDLOptions to match GenerateCreateTableDDL\nlegacy:\n%s\nzero:\n%s", legacyDDL, zeroOptsDDL)
	}
	if !strings.Contains(legacyDDL, `"replication_num" = "1"`) ||
		!strings.Contains(legacyDDL, `"store_row_column" = "true"`) ||
		!strings.Contains(legacyDDL, `UNIQUE KEY(`+"`_id`"+`)`) ||
		!strings.Contains(legacyDDL, `BUCKETS 8`) ||
		strings.Contains(legacyDDL, `USING ANN`) {
		t.Fatalf("unexpected default DDL:\n%s", legacyDDL)
	}

	// Replication lines helper: CloudMode, ReplicationAllocation escaping, ReplicationNum.
	if lines := FormatReplicationPropertyLines(DorisDDLOptions{CloudMode: true, ReplicationNum: 3, ReplicationAllocation: "tag.location.default:3"}); len(lines) != 0 {
		t.Fatalf("expected nil replication lines in CloudMode, got %v", lines)
	}
	escapedLines := FormatReplicationPropertyLines(DorisDDLOptions{
		ReplicationNum:        3,
		ReplicationAllocation: "tag.location.a:2\"bad\\\r\n",
	})
	if len(escapedLines) != 1 || escapedLines[0] != `"replication_allocation" = "tag.location.a:2\"bad\\"` {
		t.Fatalf("unexpected escaped replication_allocation: %v", escapedLines)
	}
	numLines := FormatReplicationPropertyLines(DorisDDLOptions{ReplicationNum: 3})
	if len(numLines) != 1 || numLines[0] != `"replication_num" = "3"` {
		t.Fatalf("unexpected replication_num line: %v", numLines)
	}

	// Duplicate key + HNSW ANN + CloudMode + BucketsAuto (when s.Buckets == 0) + StoreRowColumn=false.
	scAutoBuckets := sc.CloneIndexSchema()
	scAutoBuckets.Buckets = 0
	dupHNSW := GenerateCreateTableDDLWithOptions(scAutoBuckets, DorisDDLOptions{
		CloudMode:      true,
		BucketsAuto:    true,
		StoreRowColumn: boolPtrR67(false),
		VectorANNMode:  "hnsw",
		TableKeyModel:  "duplicate",
	})
	for _, want := range []string{
		"DUPLICATE KEY(`_id`)",
		"DISTRIBUTED BY HASH(`_id`) BUCKETS AUTO",
		`"store_row_column" = "false"`,
		"`f__vec_cos` ARRAY<FLOAT> NOT NULL",
		"INDEX `idx_ann_f__vec_cos` (`f__vec_cos`) USING ANN PROPERTIES(\"index_type\" = \"hnsw\", \"metric_type\" = \"inner_product\", \"dim\" = \"128\")",
		"INDEX `idx_ann_f__vec_l2` (`f__vec_l2`) USING ANN PROPERTIES(\"index_type\" = \"hnsw\", \"metric_type\" = \"l2_distance\", \"dim\" = \"64\")",
		"INDEX `idx_ann_f__vec_dot` (`f__vec_dot`) USING ANN PROPERTIES(\"index_type\" = \"hnsw\", \"metric_type\" = \"inner_product\", \"dim\" = \"32\")",
		"INDEX `idx_ann_f__vec_mip` (`f__vec_mip`) USING ANN PROPERTIES(\"index_type\" = \"hnsw\", \"metric_type\" = \"inner_product\", \"dim\" = \"16\")",
		"`f__vec_bit` ARRAY<FLOAT> NULL",
		"`f__vec_byte` ARRAY<FLOAT> NULL",
		"`f__vec_int4q` ARRAY<FLOAT> NULL",
		"`f__vec_int8q` ARRAY<FLOAT> NULL",
		"`f__vec_unindexed` ARRAY<FLOAT> NULL",
		"`f__vec_autodims` ARRAY<FLOAT> NULL",
	} {
		if !strings.Contains(dupHNSW, want) {
			t.Fatalf("expected %q in duplicate HNSW DDL:\n%s", want, dupHNSW)
		}
	}
	for _, forbid := range []string{
		"replication_num",
		"replication_allocation",
		"enable_unique_key_merge_on_write",
		"function_column.sequence_col",
		"idx_ann_f__vec_bit",
		"idx_ann_f__vec_byte",
		"idx_ann_f__vec_int4q",
		"idx_ann_f__vec_int8q",
		"idx_ann_f__vec_unindexed",
		"idx_ann_f__vec_autodims",
	} {
		if strings.Contains(dupHNSW, forbid) {
			t.Fatalf("did not expect %q in duplicate HNSW CloudMode DDL:\n%s", forbid, dupHNSW)
		}
	}
	// Long column ANN index name must be bounded <= 64 chars.
	longCol := "f__very_long_vector_column_name_exceeding_sixty_four_characters_total_len"
	if annName := annIndexNameForColumn(longCol); len(annName) > 64 {
		t.Fatalf("expected annIndexNameForColumn <= 64 chars, got %d (%q)", len(annName), annName)
	}
	if invName := invertedIndexNameForColumn(longCol); len(invName) > 60 {
		t.Fatalf("expected invertedIndexNameForColumn <= 60 chars, got %d (%q)", len(invName), invName)
	}

	// BucketsAuto does NOT override explicit s.Buckets > 0.
	explicitBucketDDL := GenerateCreateTableDDLWithOptions(sc, DorisDDLOptions{
		BucketsAuto:   true,
		VectorANNMode: "off",
	})
	if !strings.Contains(explicitBucketDDL, "BUCKETS 8") || strings.Contains(explicitBucketDDL, "BUCKETS AUTO") {
		t.Fatalf("expected explicit s.Buckets=8 preserved over BucketsAuto:\n%s", explicitBucketDDL)
	}

	// Unique Key + AllowUniqueKeyANN=false (Doris <= 4.1.3 fallback) disables ANN.
	uniqueBlocked := GenerateCreateTableDDLWithOptions(sc, DorisDDLOptions{
		VectorANNMode:     "ivf",
		TableKeyModel:     "unique",
		AllowUniqueKeyANN: false,
	})
	if strings.Contains(uniqueBlocked, "USING ANN") || strings.Contains(uniqueBlocked, "ARRAY<FLOAT> NOT NULL") {
		t.Fatalf("expected Unique Key without AllowUniqueKeyANN to skip ANN:\n%s", uniqueBlocked)
	}

	// Unique Key + AllowUniqueKeyANN=true (Doris >= 4.1.4) enables IVF ANN.
	uniqueAllowed := GenerateCreateTableDDLWithOptions(sc, DorisDDLOptions{
		ReplicationAllocation: "tag.location.ssd:3",
		VectorANNMode:         "ivf",
		TableKeyModel:         "unique",
		AllowUniqueKeyANN:     true,
	})
	if !strings.Contains(uniqueAllowed, `"replication_allocation" = "tag.location.ssd:3"`) ||
		!strings.Contains(uniqueAllowed, "UNIQUE KEY(`_id`)") ||
		!strings.Contains(uniqueAllowed, `"enable_unique_key_merge_on_write" = "true"`) ||
		!strings.Contains(uniqueAllowed, "INDEX `idx_ann_f__vec_cos` (`f__vec_cos`) USING ANN PROPERTIES(\"index_type\" = \"ivf\"") {
		t.Fatalf("expected Unique Key IVF ANN with replication_allocation:\n%s", uniqueAllowed)
	}
}

func TestRound67MappingHashAndPrecomputations(t *testing.T) {
	mkSpec := func() *esast.MappingSpec {
		return &esast.MappingSpec{
			Properties: map[string]esast.FieldProperty{
				"tags_flat":  {Type: "flattened"},
				"meta_flat":  {Type: "flattened"},
				"sparse_b":   {Type: "sparse_vector"},
				"rank_a":     {Type: "rank_features"},
				"title":      {Type: "text"},
				"alias_z":    {Type: "alias", Path: "title"},
				"alias_a":    {Type: "alias", Path: "tags_flat"},
				"vec_auto":   {Type: "dense_vector"},
				"disabled_o": {Type: "object", Enabled: boolPtrR67(false)},
				"ts":         {Type: "date"},
			},
		}
	}
	sc1 := CompileIndexSchema("es_db", "r67_hash", mkSpec())
	sc2 := CompileIndexSchema("es_db", "r67_hash", mkSpec())
	if sc1.MappingHash == "" || sc1.MappingHash != sc2.MappingHash {
		t.Fatalf("expected stable deterministic MappingHash, got %q vs %q", sc1.MappingHash, sc2.MappingHash)
	}

	// Verify precomputed sorted slices.
	if strings.Join(sc1.AliasFieldKeys, ",") != "alias_a,alias_z" {
		t.Fatalf("unexpected AliasFieldKeys: %v", sc1.AliasFieldKeys)
	}
	if strings.Join(sc1.FlattenedFieldKeys, ",") != "meta_flat,tags_flat" {
		t.Fatalf("unexpected FlattenedFieldKeys: %v", sc1.FlattenedFieldKeys)
	}
	if strings.Join(sc1.SparseFieldKeys, ",") != "rank_a,sparse_b" {
		t.Fatalf("unexpected SparseFieldKeys: %v", sc1.SparseFieldKeys)
	}

	// Empty compiled schema must keep precomputed slices non-nil so CloneIndexSchema preserves them.
	emptyCompiled := CompileIndexSchema("es_db", "empty_r67", &esast.MappingSpec{Properties: map[string]esast.FieldProperty{
		"name": {Type: "keyword"},
	}})
	if emptyCompiled.AliasFieldKeys == nil || emptyCompiled.FlattenedFieldKeys == nil || emptyCompiled.SparseFieldKeys == nil {
		t.Fatalf("expected non-nil empty precomputed slices on compiled schema")
	}
	clonedEmpty := emptyCompiled.CloneIndexSchema()
	if clonedEmpty.AliasFieldKeys == nil || clonedEmpty.FlattenedFieldKeys == nil || clonedEmpty.SparseFieldKeys == nil {
		t.Fatalf("expected CloneIndexSchema to preserve non-nil empty slices")
	}

	// Mutations must refresh MappingHash.
	h0 := sc1.MappingHash
	if err := sc1.SetAnalysisSettings(map[string]any{
		"analysis": map[string]any{
			"normalizer": map[string]any{
				"lc_norm": map[string]any{"type": "custom", "filter": []any{"lowercase"}},
			},
		},
	}); err != nil {
		t.Fatalf("SetAnalysisSettings failed: %v", err)
	}
	if sc1.MappingHash == h0 {
		t.Fatalf("expected SetAnalysisSettings to change MappingHash")
	}

	hBeforeAuto := sc1.MappingHash
	if err := sc1.LockAutoDims("vec_auto", 4); err != nil {
		t.Fatalf("LockAutoDims failed: %v", err)
	}
	if sc1.MappingHash == hBeforeAuto {
		t.Fatalf("expected LockAutoDims to update MappingHash")
	}

	scClone, _ := sc2.CloneWithLockedAutoDims(map[string]int{"vec_auto": 4, "dyn_vec": 8})
	if scClone.MappingHash == "" || scClone.MappingHash == sc2.MappingHash {
		t.Fatalf("expected CloneWithLockedAutoDims to produce updated MappingHash")
	}

	scCopyTarget := CompileIndexSchema("es_db", "r67_hash", mkSpec())
	scCopySrc := CompileIndexSchema("es_db", "r67_hash", mkSpec())
	scCopySrc.MaxResultWindow = 25000
	hBeforeCopy := scCopyTarget.MappingHash
	scCopyTarget.CopyIndexMappingSettingsFrom(scCopySrc)
	if scCopyTarget.MappingHash == hBeforeCopy {
		t.Fatalf("expected CopyIndexMappingSettingsFrom to refresh MappingHash")
	}

	// ApplyIndexModeDefaults + BindTSDBFields refresh MappingHash.
	scTSDB := CompileIndexSchema("es_db", "r67_tsdb_mode", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"host": {Type: "keyword", TimeSeriesDimension: boolPtrR67(true)},
		},
	})
	scTSDB.IndexMode = "time_series"
	hBeforeTSDB := scTSDB.MappingHash
	ApplyIndexModeDefaults(scTSDB)
	if scTSDB.MappingHash == hBeforeTSDB {
		t.Fatalf("expected ApplyIndexModeDefaults to update MappingHash")
	}

	// GenerateAlterTableDDL array upgrade mutation refreshes MappingHash.
	oldScalar := CompileIndexSchema("es_db", "r67_arr", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{"tag": {Type: "keyword"}},
	})
	newArr := CompileIndexSchema("es_db", "r67_arr", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{"tag": {Type: "keyword", MultiValued: true}},
	})
	hBeforeAlter := newArr.MappingHash
	_ = GenerateAlterTableDDL(oldScalar, newArr)
	if newArr.MappingHash == hBeforeAlter {
		t.Fatalf("expected GenerateAlterTableDDL array upgrade to refresh MappingHash")
	}

	// Manual uncompiled IndexSchema (nil precomputed slices) fallback behaves identically.
	manualSchema := &IndexSchema{
		IndexName:  "manual",
		DorisDB:    "es_db",
		DorisTable: "manual",
		Fields: map[string]FieldBinding{
			"flat": {ESFieldPath: "flat", SourceJSONPath: []string{"flat"}, Kind: StorageDynamicVariant, ESType: "flattened"},
			"sv":   {ESFieldPath: "sv", SourceJSONPath: []string{"sv"}, Kind: StorageDynamicVariant, ESType: "sparse_vector"},
			"rng":  {ESFieldPath: "rng", SourceJSONPath: []string{"rng"}, Kind: StorageDynamicVariant, ESType: "integer_range"},
			"dst":  {ESFieldPath: "dst", SourceJSONPath: []string{"dst"}, Kind: StoragePromotedArray, ColumnName: "f__dst", DorisType: DorisString, ESType: "keyword", IsMultiValued: true},
			"src":  {ESFieldPath: "src", SourceJSONPath: []string{"src"}, Kind: StoragePromotedScalar, ColumnName: "f__src", DorisType: DorisVarchar, ESType: "keyword", CopyTo: []string{"dst"}},
		},
	}
	rawDoc := json.RawMessage(`{"flat":{"k":{"sub":1}},"sv":{"tok":2.0},"rng":{"gte":1,"lte":5},"src":"hello"}`)
	out, err := ShredDocumentWithNow(manualSchema, "m1", 1, false, rawDoc, time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("manual uncompiled ShredDocumentWithNow failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(out, &row); err != nil {
		t.Fatalf("invalid row JSON from manual schema: %v", err)
	}
	if _, ok := row["f__dst"]; !ok {
		t.Fatalf("expected copy_to destination populated in manual fallback row: %v", row)
	}
}

func TestRound67ShredderSyntheticTSDBLogsDBAndEdgePaths(t *testing.T) {
	RegisterIndexFieldScriptEvaluator(nil)
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// 1. Synthetic _source + copy_to + dotted keys + enabled:false + ignore_above + null_value + coerce:false
	spec := &esast.MappingSpec{
		Dynamic: "true",
		Source:  map[string]any{"mode": "synthetic"},
		Properties: map[string]esast.FieldProperty{
			"src_a": {Type: "keyword", CopyTo: "mid_b", IgnoreAbove: 8},
			"mid_b": {Type: "text", CopyTo: "dest_c", Fields: map[string]esast.FieldProperty{
				"keyword": {Type: "keyword", IgnoreAbove: 20},
			}},
			"dest_c": {Type: "text", Fields: map[string]esast.FieldProperty{
				"keyword": {Type: "keyword"},
				"ngram":   {Type: "text", Analyzer: "standard"},
			}},
			"num_strict": {Type: "integer", Coerce: boolPtrR67(false), IgnoreMalformed: boolPtrR67(true)},
			"k_null":     {Type: "keyword", NullValue: "fallback_v"},
			"disabled":   {Type: "object", Enabled: boolPtrR67(false)},
			"flat":       {Type: "flattened", IgnoreMalformed: boolPtrR67(true)},
			"sv":         {Type: "sparse_vector", IgnoreMalformed: boolPtrR67(true)},
			"hist":       {Type: "histogram", IgnoreMalformed: boolPtrR67(true)},
			"rng":        {Type: "integer_range", IgnoreMalformed: boolPtrR67(true)},
			"agg":        {Type: "aggregate_metric_double", Metrics: []string{"min", "max", "sum", "value_count"}, DefaultMetric: "max"},
			"shape_arr":  {Type: "geo_shape"},
		},
	}
	sc := CompileIndexSchema("es_db", "r67_synth", spec)

	doc := json.RawMessage(`{
		"src_a": "ok",
		"src_too_long": "keep_dyn",
		"num_strict": "not_an_int",
		"k_null": null,
		"disabled": {"secret": "hidden"},
		"flat": {"inner": {"x": 42}},
		"sv": {"tok1": 1.5},
		"hist": {"values": [1, 2], "counts": [3, 4]},
		"rng": {"gte": 10, "lte": 20},
		"agg": {"min": 1.0, "max": 9.0, "sum": 15.0, "value_count": 3},
		"nested.dot": "dotted_val",
		"shape_arr": {"type": "polygon", "coordinates": [[[0,0],[1,0],[1,1],[0,0]]]}
	}`)
	out, err := ShredDocumentWithNow(sc, "doc-1", 2, false, doc, now)
	if err != nil {
		t.Fatalf("ShredDocumentWithNow failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(out, &row); err != nil {
		t.Fatalf("invalid NDJSON row: %v", err)
	}
	srcStr, _ := row["_source"].(string)
	if srcStr == "" || strings.Contains(srcStr, `"k_null"`) || !strings.Contains(srcStr, `"secret"`) {
		t.Fatalf("unexpected synthetic _source (null omitted, enabled:false preserved): %s", srcStr)
	}
	if row["f__k_null"] != "fallback_v" {
		t.Fatalf("expected null_value populated on promoted column f__k_null, got %v", row["f__k_null"])
	}
	docBytes, _ := json.Marshal(row["_doc"])
	if strings.Contains(string(docBytes), `"disabled"`) {
		t.Fatalf("expected enabled:false object excluded from _doc, got %s", string(docBytes))
	}
	if _, hasIgnored := row["_ignored"]; !hasIgnored {
		t.Fatalf("expected _ignored for num_strict string when coerce=false + ignore_malformed=true, row=%v", row)
	}
	if !strings.Contains(srcStr, "20") || row["f__dest_c"] == nil {
		t.Fatalf("expected copy_to chain src_a -> mid_b -> dest_c and range populated, row=%v", row)
	}

	// 2. Implicit time_series synthetic source + __tsid / __tsid_key
	tsSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"region": {Type: "keyword", TimeSeriesDimension: boolPtrR67(true)},
			"rack":   {Type: "integer", TimeSeriesDimension: boolPtrR67(true)},
			"cpu":    {Type: "double", TimeSeriesMetric: "gauge"},
		},
	}
	scTS := CompileIndexSchema("es_db", "r67_ts", tsSpec)
	scTS.IndexMode = "time_series"
	ApplyIndexModeDefaults(scTS)
	tsOut, err := ShredDocumentWithNow(scTS, "ts-1", 1, false, json.RawMessage(`{"@timestamp":"2026-11-25T12:00:00Z","region":"us-east","rack":7,"cpu":0.85}`), now)
	if err != nil {
		t.Fatalf("TSDB ShredDocumentWithNow failed: %v", err)
	}
	var tsRow map[string]any
	if err := json.Unmarshal(tsOut, &tsRow); err != nil {
		t.Fatalf("invalid TSDB row: %v", err)
	}
	if tsRow["__tsid"] == nil || tsRow["__tsid_key"] == nil || tsRow["_source"] == "" {
		t.Fatalf("expected __tsid, __tsid_key, synthetic _source on TSDB row: %v", tsRow)
	}

	// 3. Implicit logsdb synthetic source
	logSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"host": {Properties: map[string]esast.FieldProperty{"name": {Type: "keyword"}}},
			"msg":  {Type: "text"},
		},
	}
	scLogs := CompileIndexSchema("es_db", "r67_logs", logSpec)
	scLogs.IndexMode = "logsdb"
	ApplyIndexModeDefaults(scLogs)
	logsOut, err := ShredDocumentWithNow(scLogs, "log-1", 1, false, json.RawMessage(`{"host":{"name":"web-1"},"msg":"ok"}`), now)
	if err != nil {
		t.Fatalf("logsdb ShredDocumentWithNow failed: %v", err)
	}
	var logsRow map[string]any
	if err := json.Unmarshal(logsOut, &logsRow); err != nil || logsRow["_source"] == "" {
		t.Fatalf("expected synthetic _source on logsdb row, got %v err=%v", logsRow, err)
	}

	// 4. subobjects:false + dotted keys + strict dynamic rejection
	subFalseSpec := &esast.MappingSpec{
		Subobjects: boolPtrR67(false),
		Dynamic:    "strict",
		Properties: map[string]esast.FieldProperty{
			"a.b": {Type: "keyword"},
		},
	}
	scSubFalse := CompileIndexSchema("es_db", "r67_subfalse", subFalseSpec)
	if _, err := ShredDocumentWithNow(scSubFalse, "sf-ok", 1, false, json.RawMessage(`{"a.b":"val"}`), now); err != nil {
		t.Fatalf("expected subobjects:false dotted key accepted, got %v", err)
	}
	if _, err := ShredDocumentWithNow(scSubFalse, "sf-err", 1, false, json.RawMessage(`{"a":{"b":"val"},"extra":1}`), now); err == nil {
		t.Fatalf("expected strict mapping error on unmapped key under subobjects:false")
	}
}

func TestRound67SchemaHighROIClusters(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

	// coerceScalarBindingForDorisWithSchema branches
	if got := coerceScalarBindingForDorisWithSchema(nil, []string{"one two", "three"}, FieldBinding{ESType: "token_count"}, now); got != int64(3) {
		t.Fatalf("token_count []string expected 3, got %v", got)
	}
	if got := coerceScalarBindingForDorisWithSchema(nil, []any{"a b", 123}, FieldBinding{ESType: "token_count"}, now); got != int64(2) {
		t.Fatalf("token_count []any expected 2, got %v", got)
	}
	if got := coerceScalarBindingForDorisWithSchema(nil, json.Number("123"), FieldBinding{ESType: "murmur3"}, now); got == nil {
		t.Fatalf("expected murmur3 json.Number hash")
	}
	if got := coerceScalarBindingForDorisWithSchema(nil, true, FieldBinding{ESType: "murmur3"}, now); got == nil {
		t.Fatalf("expected murmur3 bool hash")
	}
	if got := coerceScalarBindingForDorisWithSchema(nil, 42, FieldBinding{ESType: "murmur3"}, now); got == nil {
		t.Fatalf("expected murmur3 int hash")
	}
	if got := coerceScalarBindingForDorisWithSchema(nil, map[string]any{}, FieldBinding{ESType: "murmur3"}, now); got != nil {
		t.Fatalf("expected nil murmur3 for unsupported map, got %v", got)
	}
	coerceFalse := false
	for _, tc := range []struct {
		b   FieldBinding
		val any
	}{
		{FieldBinding{ESType: "long", DorisType: DorisBigInt, Coerce: &coerceFalse}, json.Number("1.5")},
		{FieldBinding{ESType: "long", DorisType: DorisBigInt, Coerce: &coerceFalse}, json.Number("notanint")},
		{FieldBinding{ESType: "long", DorisType: DorisBigInt, Coerce: &coerceFalse}, float64(1.25)},
		{FieldBinding{ESType: "double", DorisType: DorisDouble, Coerce: &coerceFalse}, "1.5"},
		{FieldBinding{ESType: "boolean", DorisType: DorisBoolean, Coerce: &coerceFalse}, "true"},
		{FieldBinding{ESType: "ip", DorisType: DorisVarchar}, 123},
		{FieldBinding{ESType: "ip", DorisType: DorisVarchar}, "not-an-ip"},
	} {
		if got := coerceScalarBindingForDorisWithSchema(nil, tc.val, tc.b, now); got != nil {
			t.Fatalf("expected nil for %+v val=%v, got %v", tc.b.ESType, tc.val, got)
		}
	}
	if got := coerceScalarBindingForDorisWithSchema(nil, " 2001:0db8::1 ", FieldBinding{ESType: "ip", DorisType: DorisVarchar}, now); got != "2001:db8::1" {
		t.Fatalf("expected canonical IPv6, got %v", got)
	}

	// normalizeNestedLeafValueWithSchema branches
	getNow := func() time.Time { return now }
	ckB := FieldBinding{ESType: "constant_keyword", ConstantValue: "fixed", LowercaseNormalizer: true}
	if got := normalizeNestedLeafValueWithSchema(nil, []any{"FIXED", "wrong"}, ckB, getNow); len(got.([]any)) != 1 {
		t.Fatalf("expected filtered constant_keyword slice, got %v", got)
	}
	if got := normalizeNestedLeafValueWithSchema(nil, []any{"wrong"}, ckB, getNow); got != nil {
		t.Fatalf("expected nil when all constant_keyword elements mismatch, got %v", got)
	}
	if got := normalizeNestedLeafValueWithSchema(nil, nil, FieldBinding{ESType: "keyword", NullValue: "nv"}, getNow); got != "nv" {
		t.Fatalf("expected null_value substitution, got %v", got)
	}
	if got := normalizeNestedLeafValueWithSchema(nil, []any{1.0, 2.0}, FieldBinding{ESType: "dense_vector", VectorDims: 2, NotIndexed: true}, getNow); got == nil {
		t.Fatalf("expected normalized vector slice")
	}
	if got := normalizeNestedLeafValueWithSchema(nil, []any{"bad"}, FieldBinding{ESType: "flattened", IgnoreMalformed: boolPtrR67(true)}, getNow); got != nil {
		t.Fatalf("expected nil malformed flattened nested leaf with ignore_malformed=true, got %v", got)
	}
	if got := normalizeNestedLeafValueWithSchema(nil, []any{-122.4, 37.7}, FieldBinding{ESType: "geo_point"}, getNow); got == nil {
		t.Fatalf("expected geo_point formatted")
	}
	if got := normalizeNestedLeafValueWithSchema(nil, map[string]any{"gte": "bad"}, FieldBinding{ESType: "integer_range", IgnoreMalformed: boolPtrR67(true)}, getNow); got != nil {
		t.Fatalf("expected nil for malformed nested range with ignore_malformed, got %v", got)
	}
	if got := normalizeNestedLeafValueWithSchema(nil, map[string]any{"values": []any{1}}, FieldBinding{ESType: "histogram", IgnoreMalformed: boolPtrR67(true)}, getNow); got != nil {
		t.Fatalf("expected nil for malformed nested histogram with ignore_malformed, got %v", got)
	}

	// parseSingleAggregateMetricObject branches
	aggB := FieldBinding{ESFieldPath: "latency", ESType: "aggregate_metric_double", AggregateMetrics: []string{"min", "max", "sum", "value_count"}}
	if _, _, err := parseSingleAggregateMetricObject(map[string]any{
		"min": 1.0, "max": 2.0, "sum": 3.0, "value_count": json.Number("1e2"), "extra": 9,
	}, aggB, false); err == nil {
		t.Fatalf("expected error on unsupported sub-field without allowExtraIgnored")
	}
	if parsed, hadExtra, err := parseSingleAggregateMetricObject(map[string]any{
		"min": json.Number("1"), "max": "5.5", "sum": int64(6), "value_count": json.Number("1e1"), "extra": "x",
	}, aggB, true); err != nil || !hadExtra || parsed.vcVal != 10 {
		t.Fatalf("unexpected parseSingleAggregateMetricObject result: %+v hadExtra=%v err=%v", parsed, hadExtra, err)
	}
	for _, badVC := range []any{0, int64(-1), json.Number("1.5"), json.Number("0"), float64(1.5), "bad", true} {
		if _, _, err := parseSingleAggregateMetricObject(map[string]any{
			"min": 1.0, "max": 1.0, "sum": 1.0, "value_count": badVC,
		}, aggB, false); err == nil {
			t.Fatalf("expected error for invalid value_count=%v", badVC)
		}
	}

	// reconstructSyntheticFlattenedValue & reconstructSyntheticSparseVectorValue
	flatB := FieldBinding{ESType: "flattened", IgnoreAbove: 5, LowercaseNormalizer: true}
	if _, ok := reconstructSyntheticFlattenedValue(nil, nil, flatB); ok {
		t.Fatalf("expected false for nil flattened")
	}
	flatVal, ok := reconstructSyntheticFlattenedValue(nil, []any{
		map[string]any{"a": "HELLO"},
		map[string]any{"b": "toolongval"},
		"ScalarB",
		nil,
	}, flatB)
	if !ok || flatVal == nil {
		t.Fatalf("expected mixed object/scalar flattened reconstruction, got %v %v", flatVal, ok)
	}
	svRec, okSV := reconstructSyntheticSparseVectorValue(nil, []any{
		map[string]any{"a": 1.0, "neg": -2.0, "bad": "nan"},
		map[string]any{"a": 3.5},
	})
	if !okSV || svRec.(map[string]any)["a"].(float64) != 3.5 {
		t.Fatalf("expected max-deduped sparse vector map, got %v %v", svRec, okSV)
	}
	if _, okBad := reconstructSyntheticSparseVectorValue(nil, map[string]any{"zero": 0.0}); okBad {
		t.Fatalf("expected false when all sparse vector weights <= 0")
	}

	// ValidateMappingSpec & validateSingleFieldProperty & validateDataStreamTimestampSpec
	if err := validateDataStreamTimestampSpec("bad"); err == nil {
		t.Fatalf("expected error on non-object _data_stream_timestamp")
	}
	if err := validateDataStreamTimestampSpec(map[string]any{"extra": true}); err == nil {
		t.Fatalf("expected error on unknown _data_stream_timestamp key")
	}
	if err := validateDataStreamTimestampSpec(map[string]any{"enabled": "maybe"}); err == nil {
		t.Fatalf("expected error on non-bool _data_stream_timestamp.enabled")
	}
	for _, badProp := range []struct {
		name string
		prop esast.FieldProperty
	}{
		{"bad_type", esast.FieldProperty{Type: "not_a_real_type"}},
		{"bad_alias_props", esast.FieldProperty{Type: "alias", Path: "x", Properties: map[string]esast.FieldProperty{"y": {Type: "keyword"}}}},
		{"bad_alias_copyto", esast.FieldProperty{Type: "alias", Path: "x", CopyTo: "y"}},
		{"bad_alias_analyzer", esast.FieldProperty{Type: "alias", Path: "x", Analyzer: "standard"}},
		{"bad_inc_parent", esast.FieldProperty{Type: "object", IncludeInParent: boolPtrR67(true)}},
		{"bad_inc_root", esast.FieldProperty{Type: "keyword", IncludeInRoot: boolPtrR67(true)}},
		{"bad_script_err", esast.FieldProperty{Type: "keyword", OnScriptError: "fail"}},
		{"bad_script_empty", esast.FieldProperty{Type: "keyword", Script: "   "}},
		{"bad_script_map", esast.FieldProperty{Type: "keyword", Script: map[string]any{"lang": "painless"}}},
		{"bad_pos_impact", esast.FieldProperty{Type: "keyword", PositiveScoreImpact: boolPtrR67(false)}},
		{"bad_shingle_type", esast.FieldProperty{Type: "text", MaxShingleSize: func() *int { v := 2; return &v }()}},
		{"bad_shingle_range", esast.FieldProperty{Type: "search_as_you_type", MaxShingleSize: func() *int { v := 9; return &v }()}},
		{"bad_depth_type", esast.FieldProperty{Type: "keyword", DepthLimit: func() *int { v := 5; return &v }()}},
	} {
		if err := validateSingleFieldProperty(badProp.name, badProp.prop.Type, badProp.prop); err == nil {
			t.Fatalf("expected error for %s", badProp.name)
		}
	}
	if err := ValidateMappingSpec(&esast.MappingSpec{
		Runtime: map[string]esast.FieldProperty{
			"bad_comp": {Type: "composite", Fields: map[string]esast.FieldProperty{"sub": {Type: "lookup"}}},
		},
	}); err == nil {
		t.Fatalf("expected composite runtime lookup sub-field error")
	}
	if err := ValidateMappingSpec(&esast.MappingSpec{
		Subobjects: boolPtrR67(false),
		Properties: map[string]esast.FieldProperty{
			"obj": {Type: "object", Properties: map[string]esast.FieldProperty{"x": {Type: "keyword"}}},
		},
	}); err == nil {
		t.Fatalf("expected error for object sub-properties under subobjects:false")
	}

	// deepMergeMappingPropertiesWithSubobjects & mergeFieldProperty
	merged := deepMergeMappingPropertiesWithSubobjects(
		map[string]esast.FieldProperty{
			"count":    {Type: "long"},
			"vec":      {Type: "dense_vector", Dims: 4},
			"label":    {Type: "keyword"},
			"leaf_obj": {Type: "object", Properties: map[string]esast.FieldProperty{"a": {Type: "float"}}},
		},
		map[string]esast.FieldProperty{
			"count":    {Type: "unsigned_long"},
			"vec":      {Type: "dense_vector", Dims: 8},
			"label":    {Type: "text", MultiValued: true},
			"leaf_obj": {Type: "object", MultiValued: true, Properties: map[string]esast.FieldProperty{"b": {Type: "double"}}},
		},
		false,
	)
	if merged["count"].Type != "unsigned_long" || merged["vec"].Dims != 8 || merged["label"].Type != "text" || !merged["label"].MultiValued || !merged["leaf_obj"].MultiValued {
		t.Fatalf("unexpected merged mapping properties: %+v", merged)
	}
	if wVec := mergeFieldProperty(esast.FieldProperty{Type: "dense_vector", Dims: 4}, esast.FieldProperty{Type: "dense_vector", Dims: 8}); wVec.Type != "double" || !wVec.MultiValued {
		t.Fatalf("expected conflicting dense_vector dims widening to double MultiValued, got %+v", wVec)
	}
	if w := mergeFieldProperty(esast.FieldProperty{Type: "dense_vector", Dims: 4}, esast.FieldProperty{Type: "float"}); w.Type != "float" || !w.MultiValued {
		t.Fatalf("expected vector+float widening to multi-valued float, got %+v", w)
	}

	// ResolveEffectiveField, writeNormalizedVectorIntoNestedMap, TSDB helpers, path helpers
	saytIdx := CompileIndexSchema("es_db", "r67_sayt", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title": {Type: "search_as_you_type", MaxShingleSize: func() *int { v := 4; return &v }()},
			"msg":   {Type: "text", Fields: map[string]esast.FieldProperty{"keyword": {Type: "keyword"}}},
			"al":    {Type: "alias", Path: "msg"},
		},
	})
	if eff := saytIdx.ResolveEffectiveField("title._3gram", false); eff.ESFieldPath != "title._3gram" {
		t.Fatalf("unexpected ResolveEffectiveField SAYT: %+v", eff)
	}
	if eff := saytIdx.ResolveEffectiveField("al", true); eff.KeywordCompanion == "" && eff.ColumnName == "" {
		t.Fatalf("unexpected ResolveEffectiveField alias keyword: %+v", eff)
	}

	nestDoc := map[string]any{
		"sub": []any{map[string]any{"v": []any{1, 2}}},
		"a.b": []any{3, 4},
	}
	writeNormalizedVectorIntoNestedMap(nestDoc, []string{"sub", "v"}, []float64{1, 2})
	writeNormalizedVectorIntoNestedMap(nestDoc, []string{"a", "b"}, []float64{3, 4})

	if schemaHasAnyTSDBDimension(&IndexSchema{}) {
		t.Fatalf("expected false for schema without TSDB dims")
	}
	if !schemaHasAnyTSDBDimension(&IndexSchema{Fields: map[string]FieldBinding{"d": {TimeSeriesDimension: boolPtrR67(true)}}}) {
		t.Fatalf("expected true when schema has TSDB dimension")
	}
	if lt := inferTSDBRuntimeDynamicLeafType(json.Number("3.14"), true); lt != "float" {
		t.Fatalf("expected float in es8Mode for fractional json.Number, got %s", lt)
	}
	if lt := inferTSDBRuntimeDynamicLeafType(float64(5.0), false); lt != "long" {
		t.Fatalf("expected long for integral float64, got %s", lt)
	}
	if _, ms, ok := parseTSDBTimestampTime(int64(1700000000000000000), "date_nanos", ""); !ok || ms != 1700000000000 {
		t.Fatalf("expected date_nanos int64 nanos conversion, got ms=%d ok=%v", ms, ok)
	}
	if _, ms, ok := parseTSDBTimestampTime(json.Number("1700000000000000000"), "date_nanos", ""); !ok || ms != 1700000000000 {
		t.Fatalf("expected date_nanos json.Number nanos conversion, got ms=%d ok=%v", ms, ok)
	}
	if _, _, ok := parseTSDBTimestampTime("not-a-date", "date", ""); ok {
		t.Fatalf("expected false for invalid date")
	}

	nullCheckDoc := map[string]any{
		"a.b": nil,
		"arr": []any{map[string]any{"x": nil}},
	}
	if !hasExplicitNullAtPath(nullCheckDoc, []string{"a", "b"}) || !hasExplicitNullAtPath(nullCheckDoc, []string{"arr", "x"}) {
		t.Fatalf("expected hasExplicitNullAtPath true for dotted and array-nested nil")
	}
	cleanTarget := map[string]any{
		"k.sub": "bad_int",
		"sub":   []any{map[string]any{"n": "bad_int"}},
	}
	intB := FieldBinding{ESFieldPath: "n", ESType: "integer", IgnoreMalformed: boolPtrR67(true)}
	if !cleanMalformedNestedLeafInMap(cleanTarget, []string{"k", "sub"}, intB, now) {
		t.Fatalf("expected cleanMalformedNestedLeafInMap to prune malformed dotted leaf")
	}
	if !cleanMalformedNestedLeafInMap(cleanTarget, []string{"sub", "n"}, intB, now) {
		t.Fatalf("expected cleanMalformedNestedLeafInMap to prune malformed slice element leaf")
	}
	for _, badTSDB := range []*esast.MappingSpec{
		{DataStreamTimestamp: map[string]any{"enabled": false}},
		{Source: map[string]any{"includes": []string{"a"}}},
		{Properties: map[string]esast.FieldProperty{"@timestamp": {Type: "keyword"}}},
		{Properties: map[string]esast.FieldProperty{"items": {Type: "nested", Properties: map[string]esast.FieldProperty{"id": {Type: "keyword"}}}}},
		{Properties: map[string]esast.FieldProperty{"obj": {Type: "object", Properties: map[string]esast.FieldProperty{"x": {Type: "keyword"}}}}},
	} {
		var rPaths []string
		if _, hasObj := badTSDB.Properties["obj"]; hasObj {
			rPaths = []string{"obj"}
		}
		if err := ValidateTSDBMapping(badTSDB, rPaths); err == nil {
			t.Fatalf("expected ValidateTSDBMapping error for %+v", badTSDB)
		}
	}
}
