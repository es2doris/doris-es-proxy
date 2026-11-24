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
	"reflect"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

func assertAlterColumnsBeforeIndexesR66(t *testing.T, stmts []string) {
	t.Helper()
	if len(stmts) == 0 {
		t.Fatalf("expected non-empty ALTER statements")
	}
	seenAddIndex := false
	for i, stmt := range stmts {
		upper := strings.ToUpper(stmt)
		isAddIndex := strings.Contains(upper, " ADD INDEX ")
		if isAddIndex {
			seenAddIndex = true
			continue
		}
		if seenAddIndex {
			t.Fatalf("expected all ADD/MODIFY COLUMN and DROP INDEX statements before ADD INDEX, but stmt[%d] %q appeared after ADD INDEX in %v", i, stmt, stmts)
		}
	}
	if !seenAddIndex {
		t.Fatalf("expected at least one ADD INDEX statement in %v", stmts)
	}
}

func TestRound66GenerateAlterTableDDLColumnsBeforeIndexes(t *testing.T) {
	oldSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"legacy": {Type: "keyword", Index: ptrBoolR66Schema(false)},
		},
	}
	newSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"legacy": {Type: "keyword"},
			"title":  {Type: "text"},
			"count":  {Type: "long"},
			"paragraphs": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"body":   {Type: "text"},
					"vector": {Type: "dense_vector", Dims: 2},
				},
			},
		},
	}
	oldSchema := CompileIndexSchema("es_db", "tbl", oldSpec)
	newSchema := CompileIndexSchema("es_db", "tbl", newSpec)
	newSchema.IndexMode = "time_series"

	stmts := GenerateAlterTableDDL(oldSchema, newSchema)
	assertAlterColumnsBeforeIndexesR66(t, stmts)

	joined := strings.Join(stmts, "\n")
	for _, wantCol := range []string{"ADD COLUMN `__tsid`", "ADD COLUMN `__tsid_key`", "ADD COLUMN `f__title`", "ADD COLUMN `n__paragraphs`"} {
		if !strings.Contains(joined, wantCol) {
			t.Fatalf("expected %q in ALTER statements, got:\n%s", wantCol, joined)
		}
	}
}

func TestRound66GeneratePromoteVariantFieldDDLColumnsBeforeIndexes(t *testing.T) {
	sch := CompileIndexSchema("es_db", "tbl", &esast.MappingSpec{})
	stmts := GeneratePromoteVariantFieldDDL(sch, "dyn_title", "text")
	assertAlterColumnsBeforeIndexesR66(t, stmts)
	if len(stmts) < 4 {
		t.Fatalf("expected companion text+keyword ADD COLUMN and ADD INDEX statements, got %v", stmts)
	}
}

func TestRound66PartitionAlterDDLColumnsBeforeIndexes(t *testing.T) {
	if got := partitionAlterDDLColumnsBeforeIndexes(nil); got != nil {
		t.Fatalf("expected nil slice for nil input, got %v", got)
	}
	single := []string{"ALTER TABLE `db`.`t` ADD INDEX `i` (`c`);"}
	if got := partitionAlterDDLColumnsBeforeIndexes(single); !reflect.DeepEqual(got, single) {
		t.Fatalf("expected single statement unchanged, got %v", got)
	}

	input := []string{
		"ALTER TABLE `db`.`t` DROP INDEX `idx_old`;",
		"ALTER TABLE `db`.`t` ADD INDEX `idx_a` (`a`);",
		"ALTER TABLE `db`.`t` MODIFY COLUMN `c` BIGINT;",
		"ALTER TABLE `db`.`t` ADD COLUMN `d` STRING;",
		"ALTER TABLE `db`.`t` ADD INDEX `idx_d` (`d`);",
	}
	want := []string{
		"ALTER TABLE `db`.`t` DROP INDEX `idx_old`;",
		"ALTER TABLE `db`.`t` MODIFY COLUMN `c` BIGINT;",
		"ALTER TABLE `db`.`t` ADD COLUMN `d` STRING;",
		"ALTER TABLE `db`.`t` ADD INDEX `idx_a` (`a`);",
		"ALTER TABLE `db`.`t` ADD INDEX `idx_d` (`d`);",
	}
	if got := partitionAlterDDLColumnsBeforeIndexes(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected partition order:\ngot:  %v\nwant: %v", got, want)
	}
}

func ptrBoolR66Schema(v bool) *bool {
	return &v
}
