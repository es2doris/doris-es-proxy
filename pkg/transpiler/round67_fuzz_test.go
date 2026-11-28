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

package transpiler

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// assertQuotedJSONPathBalancedR67 verifies that a Doris JSONPath string returned by
// BuildQuotedDorisJSONPaths or nestedRelativeJSONPath starts with "$." and consists
// solely of properly double-quoted, escape-balanced JSONPath segments.
func assertQuotedJSONPathBalancedR67(t *testing.T, jp string) {
	t.Helper()
	if !strings.HasPrefix(jp, "$.") {
		t.Fatalf("expected JSONPath to start with '$.', got %q", jp)
	}
	rest := jp[2:]
	if rest == "" {
		t.Fatalf("expected at least one quoted segment after '$.', got %q", jp)
	}
	i := 0
	for {
		if i >= len(rest) || rest[i] != '"' {
			t.Fatalf("expected opening '\"' at offset %d in JSONPath %q", i, jp)
		}
		i++
		closed := false
		for i < len(rest) {
			if rest[i] == '\\' {
				i += 2
				continue
			}
			if rest[i] == '"' {
				closed = true
				i++
				break
			}
			i++
		}
		if !closed {
			t.Fatalf("unbalanced double quote in JSONPath %q", jp)
		}
		if i == len(rest) {
			return
		}
		if rest[i] != '.' {
			t.Fatalf("expected '.' separator or end of JSONPath at offset %d in %q", i, jp)
		}
		i++
	}
}

// findTopLevelKeywordOffsetR67 returns the byte offset of the first standalone top-level
// occurrence (outside quotes, backticks, and parentheses) of keyword kw (ASCII case-insensitive),
// or -1 if absent.
func findTopLevelKeywordOffsetR67(sqlStr, kw string) int {
	depth := 0
	inSingle := false
	inBacktick := false
	for i := 0; i < len(sqlStr); i++ {
		ch := sqlStr[i]
		if inSingle {
			if ch == '\\' {
				i++
				continue
			}
			if ch == '\'' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inBacktick {
			if ch == '`' {
				if i+1 < len(sqlStr) && sqlStr[i+1] == '`' {
					i++
					continue
				}
				inBacktick = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '`':
			inBacktick = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && len(sqlStr)-i >= len(kw) && strings.EqualFold(sqlStr[i:i+len(kw)], kw) {
				beforeOK := i == 0 || sqlStr[i-1] == ' ' || sqlStr[i-1] == '\t' || sqlStr[i-1] == '\n' || sqlStr[i-1] == '\r' || sqlStr[i-1] == ')'
				afterIdx := i + len(kw)
				afterOK := afterIdx == len(sqlStr) || sqlStr[afterIdx] == ' ' || sqlStr[afterIdx] == '\t' || sqlStr[afterIdx] == '\n' || sqlStr[afterIdx] == '\r' || sqlStr[afterIdx] == '(' || sqlStr[afterIdx] == '`'
				if beforeOK && afterOK {
					return i
				}
			}
		}
	}
	return -1
}

// FuzzJSONPathAndNestedSQLSafety fuzzes JSONPath quoting, exists/negation SQL balance,
// UTF-8-safe LATERAL VIEW placement before JOIN, flat nested ID queries, and nested kNN SQL.
func FuzzJSONPathAndNestedSQLSafety(f *testing.F) {
	seeds := []struct {
		rawField  string
		termVal   string
		extraText string
	}{
		{"items.*", "val", "ı"},
		{"items..secret", "x' OR '1'='1", "ſ"},
		{"items.foo-bar", "hello\\world", "ﬀ"},
		{`items."q"`, `quoted"val`, "ŉ"},
		{"items.x') FROM mysql.user --", "admin", "K"},
		{"items.sub.leaf", "tag`inject", "ıſﬀŉK"},
		{`a.b.c\d"e`, "foo bar", "normal_alias"},
		{"", "", "ı_prefix"},
	}
	for _, s := range seeds {
		f.Add(s.rawField, s.termVal, s.extraText)
	}

	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"title": {"type": "text"},
			"items": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword"},
					"tags": {"type": "text"},
					"loc": {"type": "geo_point"},
					"emb": {"type": "dense_vector", "dims": 2, "similarity": "l2_norm"},
					"sub": {
						"type": "nested",
						"properties": {
							"code": {"type": "keyword"},
							"qty": {"type": "integer"},
							"leaf": {
								"type": "nested",
								"properties": {
									"flag": {"type": "keyword"}
								}
							}
						}
					}
				}
			}
		}
	}`), &spec); err != nil {
		f.Fatalf("unmarshal mapping spec: %v", err)
	}
	idxSchema := schema.CompileIndexSchema("db", "r67_fuzz_idx", &spec)

	f.Fuzz(func(t *testing.T, rawField, termVal, extraText string) {
		if len(rawField) > 128 {
			rawField = rawField[:128]
		}
		if len(termVal) > 128 {
			termVal = termVal[:128]
		}
		if len(extraText) > 64 {
			extraText = extraText[:64]
		}
		tr := NewTranspiler(idxSchema, TranspilerOptions{ES8Compat: true})

		// 1. BuildQuotedDorisJSONPaths & nestedRelativeJSONPath must return balanced quoted segments.
		nestedPath, dottedPath, hasDot := BuildQuotedDorisJSONPaths(rawField)
		assertQuotedJSONPathBalancedR67(t, nestedPath)
		if hasDot {
			assertQuotedJSONPathBalancedR67(t, dottedPath)
		}
		relField := rawField
		if strings.TrimSpace(rawField) == "" || strings.HasPrefix(strings.TrimSpace(rawField), "items") {
			relPath := tr.nestedRelativeJSONPath(relField, false, "items")
			assertQuotedJSONPathBalancedR67(t, relPath)
		} else {
			relPath := tr.nestedRelativeJSONPath("items."+relField, false, "items")
			assertQuotedJSONPathBalancedR67(t, relPath)
		}

		// 2. compileExistsPredicate & negateBoolClauseSQLR66 must maintain balanced quotes/backticks/parens and no nested lambdas.
		safeNestedField := "items." + strings.ReplaceAll(rawField, "`", "")
		for _, nctx := range []*nestedCtx{nil, {nestedPath: "items", elemVar: "_el"}, {nestedPath: "items", elemVar: "_el", inLambda: true}} {
			exSQL := tr.compileExistsPredicate(safeNestedField, nctx)
			if !isBalancedBackticksAndParensR64(exSQL) {
				t.Fatalf("unbalanced compileExistsPredicate(%q) SQL: %s", safeNestedField, exSQL)
			}
			assertNoNestedLambdaSQLR66(t, exSQL)

			negSQL := negateBoolClauseSQLR66(exSQL)
			if !isBalancedBackticksAndParensR64(negSQL) {
				t.Fatalf("unbalanced negateBoolClauseSQLR66 SQL: %s", negSQL)
			}
			assertNoNestedLambdaSQLR66(t, negSQL)
		}

		// 3. appendLateralViewToFromClause with UTF-8 case-expanding runes (ı, ſ, ﬀ, ŉ, K) before JOIN must never drift bytes or emit LATERAL VIEW after JOIN.
		safeExtra := strings.Map(func(r rune) rune {
			if r == '`' || r == '\'' || r == '(' || r == ')' || r == '\n' || r == '\r' || r == 0 || !utf8.ValidRune(r) {
				return -1
			}
			return r
		}, extraText)
		if !utf8.ValidString(safeExtra) {
			safeExtra = "ıſﬀŉK"
		}
		fromCases := []string{
			"`db`.`r67_fuzz_idx` AS `_base_" + safeExtra + "` LEFT JOIN `db`.`dim` AS `_d` ON `_base_" + safeExtra + "`.`_id` = `_d`.`_id`",
			"`db`.`r67_fuzz_idx` `_t_ıſﬀŉK_" + safeExtra + "` INNER JOIN `db`.`dim` `_d` ON `_d`.`_id` = `_t_ıſﬀŉK_" + safeExtra + "`.`_id`",
			"`db`.`r67_fuzz_idx` `_a` STRAIGHT_JOIN `db`.`dim` `_b` ON `_a`.`_id` = `_b`.`_id`",
		}
		lv := "LATERAL VIEW EXPLODE(`n__items`) `_nt` AS `_nel`"
		for _, fc := range fromCases {
			joined := appendLateralViewToFromClause(fc, lv)
			if utf8.ValidString(fc) && !utf8.ValidString(joined) {
				t.Fatalf("appendLateralViewToFromClause produced invalid UTF-8 on %q -> %q", fc, joined)
			}
			if !isBalancedBackticksAndParensR64(joined) {
				t.Fatalf("appendLateralViewToFromClause produced unbalanced SQL: %s", joined)
			}
			latIdx := findTopLevelKeywordOffsetR67(joined, "LATERAL")
			joinIdx := findTopLevelKeywordOffsetR67(joined, "JOIN")
			if joinIdx >= 0 && (latIdx < 0 || latIdx > joinIdx) {
				t.Fatalf("LATERAL VIEW placed after top-level JOIN (lat=%d, join=%d): %s", latIdx, joinIdx, joined)
			}
		}

		// 4. compileFlatNestedMatchingIDs with multi-should + multi-level sub/leaf + dynamic/multi-valued predicates must never nest lambdas.
		msm := "2"
		flatQ := &esast.Query{
			Bool: &esast.BoolQuery{
				MinimumShouldMatch: msm,
				Should: []esast.Query{
					{Term: map[string]esast.TermEntry{"items.name": {Value: termVal}}},
					{Match: map[string]esast.MatchEntry{"items.tags": {Query: termVal}}},
					{Nested: &esast.NestedQuery{
						Path: "items.sub",
						Query: esast.Query{
							Bool: &esast.BoolQuery{
								Must: []esast.Query{
									{Term: map[string]esast.TermEntry{"items.sub.code": {Value: termVal}}},
									{Nested: &esast.NestedQuery{
										Path:  "items.sub.leaf",
										Query: esast.Query{Term: map[string]esast.TermEntry{"items.sub.leaf.flag": {Value: "ok"}}},
									}},
								},
							},
						},
					}},
				},
			},
		}
		if idsSQL, _ := tr.compileFlatNestedMatchingIDs("items", "$._nested_id", flatQ); idsSQL != "" {
			if !isBalancedBackticksAndParensR64(idsSQL) {
				t.Fatalf("unbalanced compileFlatNestedMatchingIDs SQL: %s", idsSQL)
			}
			assertNoNestedLambdaSQLR66(t, idsSQL)
		}

		// 5. compileNestedKNNQueryR63 with nested filter / multi-valued filter inside must never emit nested lambdas.
		knnReq := &esast.KNNQuery{
			Field:            "items.emb",
			QueryVector:      []float64{1.0, 0.5},
			K:                3,
			HasK:             true,
			NumCandidates:    5,
			HasNumCandidates: true,
			Filter: esast.QuerySlice{
				{
					Bool: &esast.BoolQuery{
						Must: []esast.Query{
							{Match: map[string]esast.MatchEntry{"items.tags": {Query: termVal}}},
							{GeoDistance: &esast.GeoDistanceQuery{
								Field:          "items.loc",
								Lat:            0.0,
								Lon:            0.0,
								Distance:       "10km",
								DistanceMeters: 10000,
							}},
							{Nested: &esast.NestedQuery{
								Path:  "items.sub",
								Query: esast.Query{Term: map[string]esast.TermEntry{"items.sub.code": {Value: termVal}}},
							}},
						},
					},
				},
			},
		}
		nestedKNN := &esast.NestedQuery{
			Path:  "items",
			Query: esast.Query{KNN: knnReq},
		}
		if cpKNN, ok := tr.compileNestedKNNQueryR63(nestedKNN, true); ok {
			for _, part := range []string{cpKNN.WhereSQL, cpKNN.EffectiveSafeWhere(), cpKNN.ScoreSQL} {
				if !isBalancedBackticksAndParensR64(part) {
					t.Fatalf("unbalanced compileNestedKNNQueryR63 SQL part: %s", part)
				}
				assertNoNestedLambdaSQLR66(t, part)
			}
		}
	})
}
