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
)

// GenerateCreateTableDDL produces the Apache Doris `CREATE TABLE` DDL for an `IndexSchema`.
func GenerateCreateTableDDL(s *IndexSchema) string {
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
	)

	idxs = append(idxs,
		"    INDEX `idx_doc_variant` (`_doc`) USING INVERTED PROPERTIES(\"parser\" = \"unicode\", \"support_phrase\" = \"true\")",
		"    INDEX `idx_all_text` (`_all_text`) USING INVERTED PROPERTIES(\"parser\" = \"standard\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\")",
	)

	// 2. Promoted Scalar, Array, and Nested Pre-filter Columns (sorted deterministically)
	fieldPaths := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		fieldPaths = append(fieldPaths, k)
	}
	sort.Strings(fieldPaths)

	seenCols := make(map[string]bool)
	for _, fp := range fieldPaths {
		b := s.Fields[fp]
		if b.AliasTarget != "" || b.ColumnName == "" || seenCols[b.ColumnName] {
			continue
		}
		seenCols[b.ColumnName] = true
		colDef, idxDef := buildColumnAndIndexDDL(b)
		cols = append(cols, "    "+colDef)
		if idxDef != "" {
			idxs = append(idxs, "    "+idxDef)
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
	buckets := s.Buckets
	if buckets <= 0 {
		buckets = 8
	}

	return fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS `%s`.`%s` (\n%s\n)\n"+
			"ENGINE = OLAP\n"+
			"UNIQUE KEY(`_id`)\n"+
			"DISTRIBUTED BY HASH(`_id`) BUCKETS %d\n"+
			"PROPERTIES (\n"+
			"    \"replication_num\" = \"1\",\n"+
			"    \"enable_unique_key_merge_on_write\" = \"true\",\n"+
			"    \"store_row_column\" = \"true\",\n"+
			"    \"compression\" = \"zstd\",\n"+
			"    \"function_column.sequence_col\" = \"_version\"\n"+
			");",
		s.DorisDB,
		s.DorisTable,
		strings.Join(allDefs, ",\n"),
		buckets,
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
		for _, b := range oldSchema.Fields {
			existingCols[b.ColumnName] = true
		}
		for _, c := range oldSchema.NestedRoots {
			existingCols[c] = true
		}
	}

	for _, k := range newKeys {
		b := newSchema.Fields[k]
		if b.AliasTarget != "" || b.ColumnName == "" || existingCols[b.ColumnName] {
			continue
		}
		existingCols[b.ColumnName] = true
		colDef, idxDef := buildColumnAndIndexDDL(b)
		stmts = append(stmts, fmt.Sprintf(
			"ALTER TABLE `%s`.`%s` ADD COLUMN %s;",
			newSchema.DorisDB, newSchema.DorisTable, colDef,
		))
		if idxDef != "" {
			stmts = append(stmts, fmt.Sprintf(
				"ALTER TABLE `%s`.`%s` ADD %s;",
				newSchema.DorisDB, newSchema.DorisTable, idxDef,
			))
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
			newSchema.DorisDB, newSchema.DorisTable, corrCol, escapeDDLComment(np),
		))
	}

	return stmts
}

// GeneratePromoteVariantFieldDDL generates `ALTER TABLE` statements to promote a frequently
// queried dynamic `_doc['...']` `VARIANT` field to a dedicated physical column with `USING INVERTED`.
func GeneratePromoteVariantFieldDDL(s *IndexSchema, esFieldPath string, esType string) []string {
	if s == nil {
		return nil
	}
	cleanPath := strings.TrimSuffix(esFieldPath, ".keyword")
	if existing, ok := s.Fields[cleanPath]; ok && existing.Kind != StorageDynamicVariant {
		return nil
	}
	colName := "f__" + SanitizeDorisIdentifier(cleanPath)
	if esType == "" {
		esType = "keyword"
	}
	binding := FieldBinding{
		ESFieldPath: cleanPath,
		ColumnName:  colName,
		Kind:        StoragePromotedScalar,
		DorisType:   mapESTypeToDoris(esType),
	}
	if DefaultMultiValuedPaths[cleanPath] || strings.EqualFold(esType, "array") {
		binding.Kind = StoragePromotedArray
		binding.DorisType = DorisString
	}
	colDef, idxDef := buildColumnAndIndexDDL(binding)
	var stmts []string
	if colDef != "" {
		stmts = append(stmts, fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD COLUMN %s;", s.DorisDB, s.DorisTable, colDef))
	}
	if idxDef != "" {
		stmts = append(stmts, fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD %s;", s.DorisDB, s.DorisTable, idxDef))
	}
	return stmts
}

func escapeDDLComment(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	return s
}

func buildColumnAndIndexDDL(b FieldBinding) (string, string) {
	idxName := "idx_" + b.ColumnName
	if len(idxName) > 60 {
		h := fnv.New32a()
		_, _ = h.Write([]byte(b.ColumnName))
		idxName = fmt.Sprintf("%s_%08x", idxName[:51], h.Sum32())
	}

	switch b.Kind {
	case StoragePromotedVector:
		colDef := fmt.Sprintf("`%s` ARRAY<FLOAT> NULL", b.ColumnName)
		return colDef, ""

	case StoragePromotedArray, StorageNestedSubfield:
		colDef := fmt.Sprintf("`%s` ARRAY<STRING> NULL", b.ColumnName)
		idxDef := fmt.Sprintf("INDEX `%s` (`%s`) USING INVERTED", idxName, b.ColumnName)
		return colDef, idxDef

	case StoragePromotedScalar:
		colDef := fmt.Sprintf("`%s` %s NULL", b.ColumnName, b.DorisType)
		if b.DorisType == DorisDouble {
			// Apache Doris BKD inverted index does not support IEEE-754 floating-point columns.
			return colDef, ""
		}
		if b.DorisType == DorisString {
			parser := mapESAnalyzerToDorisParser(b.Analyzer)
			idxDef := fmt.Sprintf(
				"INDEX `%s` (`%s`) USING INVERTED PROPERTIES(\"parser\" = \"%s\", \"support_phrase\" = \"true\", \"lower_case\" = \"true\")",
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
