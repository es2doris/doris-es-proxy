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
	"fmt"
	"hash/fnv"
	"sort"
	"strings"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

// DorisDDLOptions configures Apache Doris CREATE TABLE DDL properties, distribution,
// key model, and capability-gated vector ANN index pushdown.
type DorisDDLOptions struct {
	ReplicationNum        int
	ReplicationAllocation string
	CloudMode             bool
	BucketsAuto           bool
	StoreRowColumn        *bool  // nil -> true (existing default)
	VectorANNMode         string // "", "off", "hnsw", "ivf"
	TableKeyModel         string // "", "unique", "duplicate"
	AllowUniqueKeyANN     bool   // true only on Doris >= 4.1.4
}

func escapeDorisDDLString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n', '\r', '\x00':
			continue
		default:
			if r < 0x20 || r == 0x7f {
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// FormatReplicationPropertyLines formats Doris replication properties (unindented `"key" = "val"` entries)
// according to opts. When opts.CloudMode is true, replication properties are omitted.
func FormatReplicationPropertyLines(opts DorisDDLOptions) []string {
	if opts.CloudMode {
		return nil
	}
	if alloc := strings.TrimSpace(opts.ReplicationAllocation); alloc != "" {
		return []string{fmt.Sprintf(`"replication_allocation" = "%s"`, escapeDorisDDLString(alloc))}
	}
	repNum := opts.ReplicationNum
	if repNum <= 0 {
		repNum = 1
	}
	return []string{fmt.Sprintf(`"replication_num" = "%d"`, repNum)}
}

// GenerateCreateTableDDL produces the Apache Doris `CREATE TABLE` DDL for an `IndexSchema`
// using legacy default table properties.
func GenerateCreateTableDDL(s *IndexSchema) string {
	return GenerateCreateTableDDLWithOptions(s, DorisDDLOptions{})
}

// GenerateCreateTableDDLWithOptions produces the Apache Doris `CREATE TABLE` DDL for an `IndexSchema`
// with configurable replication, bucket, key-model, row-store, and ANN vector index options.
func GenerateCreateTableDDLWithOptions(s *IndexSchema, opts DorisDDLOptions) string {
	if s == nil {
		return ""
	}
	var cols []string
	var idxs []string

	// 1. System & Document Fidelity Columns
	cols = append(cols,
		"    `_id` VARCHAR(512) NOT NULL COMMENT 'ES _id primary key'",
		"    `_version` BIGINT NOT NULL DEFAULT \"1\" COMMENT 'ES _version sequence column'",
		"    `_routing` VARCHAR(256) NULL COMMENT 'ES _routing'",
		"    `_indexed_at` DATETIMEV2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP",
		"    `_source` STRING NOT NULL COMMENT 'Verbatim raw JSON document for exact _source retrieval'",
		"    `_doc` VARIANT NOT NULL COMMENT 'Auto-shredded dynamic sub-columns for unmapped fields'",
		"    `_all_text` STRING NULL COMMENT 'Catch-all text column for wildcard query_string'",
		"    `_ignored` ARRAY<STRING> NULL COMMENT 'ES _ignored malformed/ignore_above fields'",
	)

	idxs = append(idxs,
		"    INDEX `idx_doc_variant` (`_doc`) USING INVERTED PROPERTIES(\"parser\" = \"unicode\", \"support_phrase\" = \"true\", \"stopwords\" = \"none\")",
		"    INDEX `idx_all_text` (`_all_text`) USING INVERTED PROPERTIES(\"parser\" = \"standard\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\", \"stopwords\" = \"none\")",
		"    INDEX `idx__ignored` (`_ignored`) USING INVERTED",
	)

	// 2. Promoted Scalar, Array, and Nested Pre-filter Columns (sorted deterministically)
	fieldPaths := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		fieldPaths = append(fieldPaths, k)
	}
	sort.Strings(fieldPaths)

	seenCols := make(map[string]bool)
	if strings.EqualFold(strings.TrimSpace(s.IndexMode), "time_series") {
		seenCols["__tsid"] = true
		seenCols["__tsid_key"] = true
		cols = append(cols,
			"    `__tsid` VARCHAR(512) NULL COMMENT 'ES TSDB _tsid'",
			"    `__tsid_key` STRING NULL COMMENT 'ES TSDB canonical dimension key JSON'",
		)
		idxs = append(idxs,
			"    INDEX `idx___tsid` (`__tsid`) USING INVERTED",
		)
	}
	for _, fp := range fieldPaths {
		b := s.Fields[fp]
		if b.AliasTarget != "" || b.ColumnName == "" || seenCols[b.ColumnName] {
			continue
		}
		seenCols[b.ColumnName] = true
		colDef, idxDef := buildColumnAndIndexDDLWithOptions(b, opts)
		cols = append(cols, "    "+colDef)
		if idxDef != "" {
			idxs = append(idxs, "    "+idxDef)
		}
		for _, subB := range AggregateMetricSubColumns(b) {
			if seenCols[subB.ColumnName] {
				continue
			}
			seenCols[subB.ColumnName] = true
			sCol, sIdx := buildColumnAndIndexDDLWithOptions(subB, opts)
			cols = append(cols, "    "+sCol)
			if sIdx != "" {
				idxs = append(idxs, "    "+sIdx)
			}
		}
	}

	// 3. Nested Correlated Element Array Columns (`n__<nested_path> ARRAY<STRING>`)
	nestedPaths := make([]string, 0, len(s.NestedRoots))
	for np := range s.NestedRoots {
		nestedPaths = append(nestedPaths, np)
	}
	sort.Strings(nestedPaths)
	for _, np := range nestedPaths {
		corrCol := s.NestedRoots[np]
		if !seenCols[corrCol] {
			seenCols[corrCol] = true
			cols = append(cols, fmt.Sprintf("    `%s` ARRAY<STRING> NULL COMMENT 'Correlated nested JSON elements for %s'", corrCol, escapeDDLComment(np)))
		}
	}

	allDefs := append(cols, idxs...)

	keyModel := strings.ToLower(strings.TrimSpace(opts.TableKeyModel))
	keyClause := "UNIQUE KEY(`_id`)"
	if keyModel == "duplicate" {
		keyClause = "DUPLICATE KEY(`_id`)"
	}

	var bucketClause string
	if opts.BucketsAuto && s.Buckets <= 0 {
		bucketClause = "DISTRIBUTED BY HASH(`_id`) BUCKETS AUTO"
	} else {
		buckets := s.Buckets
		if buckets <= 0 {
			buckets = 8
		}
		bucketClause = fmt.Sprintf("DISTRIBUTED BY HASH(`_id`) BUCKETS %d", buckets)
	}

	var props []string
	for _, repProp := range FormatReplicationPropertyLines(opts) {
		props = append(props, "    "+repProp)
	}
	if keyModel != "duplicate" {
		props = append(props, `    "enable_unique_key_merge_on_write" = "true"`)
	}
	storeRowCol := "true"
	if opts.StoreRowColumn != nil && !*opts.StoreRowColumn {
		storeRowCol = "false"
	}
	props = append(props, fmt.Sprintf(`    "store_row_column" = "%s"`, storeRowCol))
	props = append(props, `    "compression" = "zstd"`)
	if keyModel != "duplicate" {
		props = append(props, `    "function_column.sequence_col" = "_version"`)
	}

	return fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS `%s`.`%s` (\n%s\n)\n"+
			"ENGINE = OLAP\n"+
			"%s\n"+
			"%s\n"+
			"PROPERTIES (\n"+
			"%s\n"+
			");",
		escapeDorisBacktickIdent(s.DorisDB),
		escapeDorisBacktickIdent(s.DorisTable),
		strings.Join(allDefs, ",\n"),
		keyClause,
		bucketClause,
		strings.Join(props, ",\n"),
	)
}

// GenerateAlterTableDDL computes non-blocking Light Schema Change `ALTER TABLE` statements
// when new fields or nested roots are added via `PUT /<index>/_mapping`.
func GenerateAlterTableDDL(oldSchema, newSchema *IndexSchema) []string {
	if newSchema == nil {
		return nil
	}
	var stmts []string
	newKeys := make([]string, 0, len(newSchema.Fields))
	for k := range newSchema.Fields {
		newKeys = append(newKeys, k)
	}
	sort.Strings(newKeys)

	existingCols := make(map[string]bool)
	if oldSchema != nil {
		if strings.EqualFold(strings.TrimSpace(oldSchema.IndexMode), "time_series") {
			existingCols["__tsid"] = true
			existingCols["__tsid_key"] = true
		}
		for _, b := range oldSchema.Fields {
			existingCols[b.ColumnName] = true
			for _, subB := range AggregateMetricSubColumns(b) {
				existingCols[subB.ColumnName] = true
			}
		}
		for _, c := range oldSchema.NestedRoots {
			existingCols[c] = true
		}
	}
	newDBIdent := escapeDorisBacktickIdent(newSchema.DorisDB)
	newTblIdent := escapeDorisBacktickIdent(newSchema.DorisTable)
	if strings.EqualFold(strings.TrimSpace(newSchema.IndexMode), "time_series") {
		if !existingCols["__tsid"] {
			existingCols["__tsid"] = true
			stmts = append(stmts,
				fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD COLUMN `__tsid` VARCHAR(512) NULL COMMENT 'ES TSDB _tsid';", newDBIdent, newTblIdent),
				fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD INDEX `idx___tsid` (`__tsid`) USING INVERTED;", newDBIdent, newTblIdent),
			)
		}
		if !existingCols["__tsid_key"] {
			existingCols["__tsid_key"] = true
			stmts = append(stmts,
				fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD COLUMN `__tsid_key` STRING NULL COMMENT 'ES TSDB canonical dimension key JSON';", newDBIdent, newTblIdent),
			)
		}
	}

	upgradedRawMapping := false
	for _, k := range newKeys {
		b := newSchema.Fields[k]
		if oldSchema != nil {
			if oldB, hadOld := oldSchema.Fields[k]; hadOld &&
				oldB.Kind == StoragePromotedScalar &&
				b.Kind == StoragePromotedArray &&
				b.ColumnName == oldB.ColumnName {
				b.ColumnName = "f__arr__" + SanitizeDorisIdentifier(k)
				newSchema.Fields[k] = b
				markRawMappingUpgradedArray(newSchema.RawMapping, k, b.SourceJSONPath)
				upgradedRawMapping = true
				baseName := strings.TrimSuffix(k, ".keyword")
				if strings.HasSuffix(k, ".keyword") {
					if baseB, ok := newSchema.Fields[baseName]; ok && baseB.KeywordCompanion == oldB.ColumnName {
						baseB.KeywordCompanion = b.ColumnName
						newSchema.Fields[baseName] = baseB
					}
				}
				for ak, ab := range newSchema.Fields {
					if ab.AliasTarget == k && ab.ColumnName == oldB.ColumnName {
						ab.ColumnName = b.ColumnName
						newSchema.Fields[ak] = ab
					} else if strings.HasSuffix(k, ".keyword") && ab.AliasTarget == baseName && ab.KeywordCompanion == oldB.ColumnName {
						ab.KeywordCompanion = b.ColumnName
						newSchema.Fields[ak] = ab
					}
				}
				for i := range newSchema.OrderedFields {
					if updated, ok := newSchema.Fields[newSchema.OrderedFields[i].ESFieldPath]; ok {
						newSchema.OrderedFields[i] = updated
					}
				}
			}
		}
		if b.AliasTarget != "" || b.ColumnName == "" {
			continue
		}
		if existingCols[b.ColumnName] {
			if oldSchema != nil {
				if oldB, hadOld := oldSchema.Fields[k]; hadOld {
					if oldB.DorisType == DorisVarchar && b.DorisType == DorisString {
						if !oldB.NotIndexed {
							stmts = append(stmts, fmt.Sprintf(
								"ALTER TABLE `%s`.`%s` DROP INDEX `%s`;",
								newDBIdent, newTblIdent, invertedIndexNameForColumn(b.ColumnName),
							))
						}
						stmts = append(stmts, fmt.Sprintf(
							"ALTER TABLE `%s`.`%s` MODIFY COLUMN `%s` %s NULL;",
							newDBIdent, newTblIdent, b.ColumnName, b.DorisType,
						))
						if !b.NotIndexed {
							_, idxDef := buildColumnAndIndexDDL(b)
							if idxDef != "" {
								stmts = append(stmts, fmt.Sprintf(
									"ALTER TABLE `%s`.`%s` ADD %s;",
									newDBIdent, newTblIdent, idxDef,
								))
							}
						}
					} else if oldB.NotIndexed && !b.NotIndexed {
						_, idxDef := buildColumnAndIndexDDL(b)
						if idxDef != "" {
							stmts = append(stmts, fmt.Sprintf(
								"ALTER TABLE `%s`.`%s` ADD %s;",
								newDBIdent, newTblIdent, idxDef,
							))
						}
					}
				}
			}
			continue
		}
		existingCols[b.ColumnName] = true
		colDef, idxDef := buildColumnAndIndexDDL(b)
		stmts = append(stmts, fmt.Sprintf(
			"ALTER TABLE `%s`.`%s` ADD COLUMN %s;",
			newDBIdent, newTblIdent, colDef,
		))
		if idxDef != "" {
			stmts = append(stmts, fmt.Sprintf(
				"ALTER TABLE `%s`.`%s` ADD %s;",
				newDBIdent, newTblIdent, idxDef,
			))
		}
		for _, subB := range AggregateMetricSubColumns(b) {
			if existingCols[subB.ColumnName] {
				continue
			}
			existingCols[subB.ColumnName] = true
			sCol, sIdx := buildColumnAndIndexDDL(subB)
			stmts = append(stmts, fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD COLUMN %s;", newDBIdent, newTblIdent, sCol))
			if sIdx != "" {
				stmts = append(stmts, fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD %s;", newDBIdent, newTblIdent, sIdx))
			}
		}
	}

	nestedPaths := make([]string, 0, len(newSchema.NestedRoots))
	for np := range newSchema.NestedRoots {
		nestedPaths = append(nestedPaths, np)
	}
	sort.Strings(nestedPaths)
	for _, np := range nestedPaths {
		corrCol := newSchema.NestedRoots[np]
		if corrCol == "" || existingCols[corrCol] {
			continue
		}
		existingCols[corrCol] = true
		stmts = append(stmts, fmt.Sprintf(
			"ALTER TABLE `%s`.`%s` ADD COLUMN `%s` ARRAY<STRING> NULL COMMENT 'Correlated nested JSON elements for %s';",
			newDBIdent, newTblIdent, corrCol, escapeDDLComment(np),
		))
	}

	if upgradedRawMapping {
		newSchema.RefreshMappingHash()
	}

	return partitionAlterDDLColumnsBeforeIndexes(stmts)
}

// partitionAlterDDLColumnsBeforeIndexes orders DROP INDEX / MODIFY COLUMN / ADD COLUMN
// statements ahead of ADD INDEX statements so batched ALTER TABLE execution in Doris 4.x
// does not stall later column changes behind asynchronous index builds.
func partitionAlterDDLColumnsBeforeIndexes(stmts []string) []string {
	if len(stmts) <= 1 {
		return stmts
	}
	nonIdx := make([]string, 0, len(stmts))
	idx := make([]string, 0, len(stmts))
	for _, stmt := range stmts {
		if strings.Contains(strings.ToUpper(stmt), " ADD INDEX ") {
			idx = append(idx, stmt)
			continue
		}
		nonIdx = append(nonIdx, stmt)
	}
	return append(nonIdx, idx...)
}

func markRawMappingUpgradedArray(spec *esast.MappingSpec, esFieldPath string, sourceJSONPath []string) {
	if spec == nil || len(spec.Properties) == 0 {
		return
	}
	path := sourceJSONPath
	if len(path) == 0 {
		path = strings.Split(esFieldPath, ".")
	}
	dotSource := strings.Join(path, ".")
	subField := ""
	if esFieldPath != dotSource && strings.HasPrefix(esFieldPath, dotSource+".") {
		subField = strings.TrimPrefix(esFieldPath, dotSource+".")
	}
	markPropsUpgradedArrayAtPath(spec.Properties, path, subField)
}

func markPropsUpgradedArrayAtPath(props map[string]esast.FieldProperty, path []string, subField string) {
	if len(path) == 0 || len(props) == 0 {
		return
	}
	prop, ok := props[path[0]]
	if !ok {
		return
	}
	if len(path) == 1 {
		if subField != "" {
			if len(prop.Fields) > 0 {
				if sf, hasSF := prop.Fields[subField]; hasSF {
					sf.MultiValued = true
					sf.UpgradedArray = true
					prop.Fields[subField] = sf
					props[path[0]] = prop
				}
			}
			return
		}
		prop.MultiValued = true
		prop.UpgradedArray = true
		props[path[0]] = prop
		return
	}
	if len(prop.Properties) > 0 {
		markPropsUpgradedArrayAtPath(prop.Properties, path[1:], subField)
		props[path[0]] = prop
	}
}

// GeneratePromoteVariantFieldDDL generates `ALTER TABLE` statements to promote a frequently
// queried dynamic `_doc['...']` `VARIANT` field to a dedicated physical column with `USING INVERTED`.
func GeneratePromoteVariantFieldDDL(s *IndexSchema, esFieldPath string, esType string) []string {
	if s == nil {
		return nil
	}
	hasKeywordSuffix := strings.HasSuffix(esFieldPath, ".keyword")
	cleanPath := strings.TrimSuffix(esFieldPath, ".keyword")
	if cleanPath == "" {
		return nil
	}
	isExplicitKeyword := false
	if hasKeywordSuffix {
		if existingBase, ok := s.Fields[cleanPath]; ok && existingBase.Kind != StorageDynamicVariant {
			isExplicitKeyword = true
		}
	}
	checkPath := cleanPath
	if isExplicitKeyword {
		checkPath = esFieldPath
	}
	if existing, ok := s.Fields[checkPath]; ok && existing.Kind != StorageDynamicVariant {
		return nil
	}
	if resolved := s.ResolveField(checkPath); resolved.EnabledFalse || resolved.NotIndexed {
		return nil
	}
	if s.IsDynamicFalseUnmappedField(checkPath) || isUnpromotableDynamicScope(s, checkPath) {
		return nil
	}
	for root := range s.NestedRoots {
		if cleanPath == root || strings.HasPrefix(cleanPath, root+".") {
			return nil
		}
	}
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "dense_vector", "knn_vector", "nested", "object", "flattened", "join", "percolator":
		return nil
	}
	colName := "f__" + SanitizeDorisIdentifier(cleanPath)
	if isExplicitKeyword {
		colName += "__keyword"
		esType = "keyword"
	} else if esType == "" {
		esType = "keyword"
	}
	binding := FieldBinding{
		ESFieldPath: checkPath,
		ColumnName:  colName,
		Kind:        StoragePromotedScalar,
		DorisType:   mapESTypeToDoris(esType),
		ESType:      strings.ToLower(strings.TrimSpace(esType)),
	}
	if (DefaultMultiValuedPaths[cleanPath] && !strings.EqualFold(esType, "text") && !strings.EqualFold(esType, "match_only_text")) || strings.EqualFold(esType, "array") {
		binding.Kind = StoragePromotedArray
		binding.DorisType = DorisString
	}
	dbIdent := escapeDorisBacktickIdent(s.DorisDB)
	tblIdent := escapeDorisBacktickIdent(s.DorisTable)
	colDef, idxDef := buildColumnAndIndexDDL(binding)
	var stmts []string
	if colDef != "" {
		stmts = append(stmts, fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD COLUMN %s;", dbIdent, tblIdent, colDef))
	}
	if idxDef != "" {
		stmts = append(stmts, fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD %s;", dbIdent, tblIdent, idxDef))
	}
	if !isExplicitKeyword && strings.EqualFold(esType, "text") {
		kwPath := cleanPath + ".keyword"
		if existingKw, ok := s.Fields[kwPath]; !ok || existingKw.Kind == StorageDynamicVariant {
			kwBinding := FieldBinding{
				ESFieldPath: kwPath,
				ColumnName:  colName + "__keyword",
				Kind:        binding.Kind,
				DorisType:   DorisVarchar,
				ESType:      "keyword",
			}
			if kwBinding.Kind == StoragePromotedArray {
				kwBinding.DorisType = DorisString
			}
			kwColDef, kwIdxDef := buildColumnAndIndexDDL(kwBinding)
			if kwColDef != "" {
				stmts = append(stmts, fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD COLUMN %s;", dbIdent, tblIdent, kwColDef))
			}
			if kwIdxDef != "" {
				stmts = append(stmts, fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD %s;", dbIdent, tblIdent, kwIdxDef))
			}
		}
	}

	return partitionAlterDDLColumnsBeforeIndexes(stmts)
}

func escapeDDLComment(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	return s
}

func invertedIndexNameForColumn(colName string) string {
	idxName := "idx_" + colName
	if len(idxName) > 60 {
		h := fnv.New32a()
		_, _ = h.Write([]byte(colName))
		idxName = fmt.Sprintf("%s_%08x", idxName[:51], h.Sum32())
	}
	return idxName
}

func annIndexNameForColumn(colName string) string {
	idxName := "idx_ann_" + colName
	if len(idxName) > 64 {
		h := fnv.New32a()
		_, _ = h.Write([]byte(colName))
		idxName = fmt.Sprintf("%s_%08x", idxName[:55], h.Sum32())
	}
	return idxName
}

func buildColumnAndIndexDDL(b FieldBinding) (string, string) {
	return buildColumnAndIndexDDLWithOptions(b, DorisDDLOptions{})
}

func buildColumnAndIndexDDLWithOptions(b FieldBinding, opts DorisDDLOptions) (string, string) {
	idxName := invertedIndexNameForColumn(b.ColumnName)

	switch b.Kind {
	case StoragePromotedVector:
		annMode := strings.ToLower(strings.TrimSpace(opts.VectorANNMode))
		keyModel := strings.ToLower(strings.TrimSpace(opts.TableKeyModel))
		annActive := (annMode == "hnsw" || annMode == "ivf") && (keyModel == "duplicate" || opts.AllowUniqueKeyANN)
		elemType := strings.ToLower(strings.TrimSpace(b.VectorElementType))
		isFloatVector := elemType == "" || elemType == "float"
		if annActive && !b.NotIndexed && isFloatVector && b.VectorDims > 0 {
			colDef := fmt.Sprintf("`%s` ARRAY<FLOAT> NOT NULL", b.ColumnName)
			metricType := "inner_product"
			switch strings.ToLower(strings.TrimSpace(b.VectorMetric)) {
			case "l2_norm", "l2_distance":
				metricType = "l2_distance"
			case "dot_product", "cosine", "max_inner_product", "":
				metricType = "inner_product"
			}
			annIdxName := annIndexNameForColumn(b.ColumnName)
			idxDef := fmt.Sprintf(
				"INDEX `%s` (`%s`) USING ANN PROPERTIES(\"index_type\" = \"%s\", \"metric_type\" = \"%s\", \"dim\" = \"%d\")",
				annIdxName, b.ColumnName, annMode, metricType, b.VectorDims,
			)
			return colDef, idxDef
		}
		colDef := fmt.Sprintf("`%s` ARRAY<FLOAT> NULL", b.ColumnName)
		return colDef, ""

	case StoragePromotedArray, StorageNestedSubfield:
		arrColType := "ARRAY<STRING>"
		if b.Kind == StoragePromotedArray && (b.DorisType == DorisLargeInt || b.DorisType == DorisLargeIntArray) {
			arrColType = "ARRAY<LARGEINT>"
		}
		colDef := fmt.Sprintf("`%s` %s NULL", b.ColumnName, arrColType)
		if b.NotIndexed {
			return colDef, ""
		}
		idxDef := fmt.Sprintf("INDEX `%s` (`%s`) USING INVERTED", idxName, b.ColumnName)
		return colDef, idxDef

	case StoragePromotedScalar:
		colDef := fmt.Sprintf("`%s` %s NULL", b.ColumnName, b.DorisType)
		if b.NotIndexed || b.DorisType == DorisDouble {
			// Apache Doris BKD inverted index does not support IEEE-754 floating-point columns.
			return colDef, ""
		}
		if b.DorisType == DorisString {
			parser := mapESAnalyzerToDorisParser(b.Analyzer)
			aLower := strings.ToLower(strings.TrimSpace(b.Analyzer))
			if aLower == "english" || aLower == "stop" {
				idxDef := fmt.Sprintf(
					"INDEX `%s` (`%s`) USING INVERTED PROPERTIES(\"parser\" = \"%s\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\")",
					idxName, b.ColumnName, parser,
				)
				return colDef, idxDef
			}
			idxDef := fmt.Sprintf(
				"INDEX `%s` (`%s`) USING INVERTED PROPERTIES(\"parser\" = \"%s\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\", \"stopwords\" = \"none\")",
				idxName, b.ColumnName, parser,
			)
			return colDef, idxDef
		}
		idxDef := fmt.Sprintf("INDEX `%s` (`%s`) USING INVERTED", idxName, b.ColumnName)
		return colDef, idxDef
	default:
		return "", ""
	}
}

func mapESAnalyzerToDorisParser(analyzer string) string {
	a := strings.ToLower(analyzer)
	switch {
	case strings.Contains(a, "ngram") || strings.Contains(a, "unicode") || strings.Contains(a, "icu"):
		// Doris USING INVERTED supports unicode tokenization with phrase support for CJK/substring/ngram fields.
		return "unicode"
	case strings.Contains(a, "ik") || strings.Contains(a, "chinese") || strings.Contains(a, "smartcn"):
		return "chinese"
	case strings.Contains(a, "english"):
		return "english"
	default:
		return "standard"
	}
}

func isUnpromotableDynamicScope(s *IndexSchema, esFieldPath string) bool {
	if s == nil || s.RawMapping == nil {
		return false
	}
	cleanPath := strings.TrimSuffix(strings.TrimSuffix(esFieldPath, ".keyword"), ".ngram")
	if cleanPath == "" || strings.HasPrefix(cleanPath, "_") {
		return false
	}
	if _, ok := s.Fields[esFieldPath]; ok {
		return false
	}
	if _, ok := s.Fields[cleanPath]; ok {
		return false
	}
	mode := normalizeDynamicMode(s.RawMapping.Dynamic)
	props := s.RawMapping.Properties
	for _, seg := range strings.Split(cleanPath, ".") {
		prop, ok := props[seg]
		if !ok {
			return mode == "false" || mode == "strict"
		}
		if strings.EqualFold(prop.Type, "flattened") {
			return false
		}
		if prop.Dynamic != nil {
			mode = normalizeDynamicMode(prop.Dynamic)
		}
		props = prop.Properties
	}
	return false
}
