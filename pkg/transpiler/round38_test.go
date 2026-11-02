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

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func TestRound38_F7_F8_LuceneWildcardFieldExpansionAndDoris4SearchGuard(t *testing.T) {
	var mapping esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"meta_ip": {"type": "ip"},
			"meta_tag": {"type": "keyword"},
			"meta_num": {"type": "integer"},
			"meta_flag": {"type": "boolean"},
			"title": {"type": "text"}
		}
	}`), &mapping); err != nil {
		t.Fatalf("unmarshal mapping: %v", err)
	}
	idxSchema := schema.CompileIndexSchema("es_compat", "r38_lucene", &mapping)

	// F7: Lucene query_string with wildcard field prefixes on range, regexp, boolean, and field group.
	tr := NewTranspiler(idxSchema, TranspilerOptions{})
	var srLucene esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"meta_num*:[10 TO 20] AND meta_tag*:/foo.*/ AND meta_flag*:true AND meta_*:(alpha OR beta)"}}}`), &srLucene)
	planLucene, err := tr.BuildSearchPlan(&srLucene)
	if err != nil {
		t.Fatalf("BuildSearchPlan lucene wildcard failed: %v", err)
	}
	if !strings.Contains(planLucene.HitsSQL, "`f__meta_num`") || !strings.Contains(planLucene.HitsSQL, "`f__meta_tag`") || !strings.Contains(planLucene.HitsSQL, "`f__meta_flag`") {
		t.Fatalf("expected wildcard field expansion in Lucene query SQL, got: %s", planLucene.HitsSQL)
	}

	// F8: Doris 4.0 SEARCH() rewrite guard rejects empty value, field groups, and quoted phrases on keyword fields.
	trDoris4 := NewTranspiler(idxSchema, TranspilerOptions{UseDoris4SearchFunc: true})
	var srGroup esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"meta_tag:(a b)"}}}`), &srGroup)
	planGroup, err := trDoris4.BuildSearchPlan(&srGroup)
	if err != nil {
		t.Fatalf("BuildSearchPlan group failed: %v", err)
	}
	if strings.Contains(planGroup.HitsSQL, "SEARCH(") {
		t.Fatalf("expected Doris 4 SEARCH() rewrite to reject parenthesized field group, got: %s", planGroup.HitsSQL)
	}

	var srPhraseKeyword esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"meta_tag:\"hello world\""}}}`), &srPhraseKeyword)
	planPK, err := trDoris4.BuildSearchPlan(&srPhraseKeyword)
	if err != nil {
		t.Fatalf("BuildSearchPlan keyword phrase failed: %v", err)
	}
	if strings.Contains(planPK.HitsSQL, "SEARCH(") {
		t.Fatalf("expected Doris 4 SEARCH() rewrite to reject quoted phrase on keyword column, got: %s", planPK.HitsSQL)
	}

	var srPhraseText esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"title:\"hello world\""}}}`), &srPhraseText)
	planPT, err := trDoris4.BuildSearchPlan(&srPhraseText)
	if err != nil {
		t.Fatalf("BuildSearchPlan text phrase failed: %v", err)
	}
	if !strings.Contains(planPT.HitsSQL, "SEARCH(") {
		t.Fatalf("expected Doris 4 SEARCH() rewrite to accept quoted phrase on text column, got: %s", planPT.HitsSQL)
	}
}

func TestRound38_F9_F10_NestedRangeAggMultiLevelSortAndScaledFloatSearchAfter(t *testing.T) {
	var mapping esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"price": {"type": "scaled_float", "scaling_factor": 100},
			"items": {
				"type": "nested",
				"properties": {
					"qty": {"type": "integer"},
					"ts": {"type": "date"},
					"specs": {
						"type": "nested",
						"properties": {
							"weight": {"type": "double"}
						}
					}
				}
			}
		}
	}`), &mapping); err != nil {
		t.Fatalf("unmarshal mapping: %v", err)
	}
	idxSchema := schema.CompileIndexSchema("es_compat", "r38_nested", &mapping)
	for _, fn := range []string{"items.qty", "items.ts"} {
		b := idxSchema.Fields[fn]
		b.IsMultiValued = true
		idxSchema.Fields[fn] = b
	}
	tr := NewTranspiler(idxSchema, TranspilerOptions{})

	// F9: Nested range and date_range sub-aggregations + multi-level nested sort.
	var sr esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"sort": [
			{
				"items.specs.weight": {
					"order": "asc",
					"nested": {
						"path": "items",
						"filter": {"range": {"items.qty": {"gte": 2}}},
						"nested": {
							"path": "items.specs",
							"max_children": 3,
							"filter": {"range": {"items.specs.weight": {"gt": 1.5}}}
						}
					}
				}
			}
		],
		"aggs": {
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"qty_ranges": {
						"range": {
							"field": "items.qty",
							"ranges": [{"to": 10}, {"from": 10, "to": 50}]
						}
					},
					"ts_ranges": {
						"date_range": {
							"field": "items.ts",
							"ranges": [{"to": "2026-01-01T00:00:00Z"}, {"from": "2026-01-01T00:00:00Z"}]
						}
					}
				}
			}
		}
	}`), &sr); err != nil {
		t.Fatalf("unmarshal search request: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&sr)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(plan.AggsSQL, "array_exists") {
		t.Fatalf("expected nested range/date_range sub-aggs to use array_exists, got: %s", plan.AggsSQL)
	}
	if !strings.Contains(plan.HitsSQL, "$.qty") || !strings.Contains(plan.HitsSQL, "$.weight") {
		t.Fatalf("expected multi-level nested sort filter conditions in HitsSQL, got: %s", plan.HitsSQL)
	}

	// F10: Unsorted K<V minimum_should_match spec ("4<75% 2<2") and scaled_float sort missing + search_after.
	if got := parseMinShouldMatch("4<75% 2<2", 3, false); got != 2 {
		t.Fatalf("expected parseMinShouldMatch('4<75%% 2<2', 3) == 2, got %d", got)
	}
	if got := parseMinShouldMatch("4<75% 2<2", 5, false); got != 3 {
		t.Fatalf("expected parseMinShouldMatch('4<75%% 2<2', 5) == 3, got %d", got)
	}

	var srScaled esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"sort": [{"price": {"order": "asc", "missing": 19.99}}],
		"search_after": [19.99]
	}`), &srScaled); err != nil {
		t.Fatalf("unmarshal scaled_float search request: %v", err)
	}
	planScaled, err := tr.BuildSearchPlan(&srScaled)
	if err != nil {
		t.Fatalf("BuildSearchPlan scaled_float failed: %v", err)
	}
	if strings.Contains(planScaled.HitsSQL, "1999") {
		t.Fatalf("expected scaled_float missing/search_after not to multiply by 100 on DOUBLE column, got: %s", planScaled.HitsSQL)
	}
	if !strings.Contains(planScaled.HitsSQL, "19.99") {
		t.Fatalf("expected unscaled 19.99 in HitsSQL, got: %s", planScaled.HitsSQL)
	}
}
