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

func buildTestTranspiler(t *testing.T) *Transpiler {
	t.Helper()
	rawMapping := `{
		"properties": {
			"name": {
				"type": "text",
				"fields": {
					"keyword": {"type": "keyword", "normalizer": "lowercase_normalizer"}
				}
			},
			"displayName": {"type": "text"},
			"description": {"type": "text"},
			"serviceType": {"type": "keyword"},
			"deleted": {"type": "boolean"},
			"updatedAt": {"type": "long"},
			"tier": {"properties": {"tagFQN": {"type": "keyword"}}},
			"tags": {"properties": {"tagFQN": {"type": "keyword"}}},
			"usageSummary": {
				"properties": {
					"weeklyStats": {"properties": {"count": {"type": "long"}}}
				}
			},
			"columns": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword"},
					"dataType": {"type": "keyword"},
					"tags": {"properties": {"tagFQN": {"type": "keyword"}}}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatalf("failed to unmarshal test mapping: %v", err)
	}
	idxSchema := schema.CompileIndexSchema("es_compat", "table_search_index", &spec)
	return NewTranspiler(idxSchema, TranspilerOptions{})
}

func TestTranspileOpenMetadataSearchAndFacetAggregations(t *testing.T) {
	tr := buildTestTranspiler(t)
	searchJSON := `{
		"from": 0,
		"size": 20,
		"query": {
			"function_score": {
				"query": {
					"bool": {
						"must": [
							{
								"multi_match": {
									"query": "orders",
									"fields": ["name^10", "displayName^5", "description^2"],
									"operator": "and"
								}
							},
							{
								"nested": {
									"path": "columns",
									"query": {
										"bool": {
											"must": [
												{"term": {"columns.name": "user_id"}},
												{"term": {"columns.dataType": "INT"}}
											]
										}
									}
								}
							}
						],
						"filter": [
							{"term": {"deleted": false}},
							{"term": {"tags.tagFQN": "PII.Sensitive"}},
							{" terms ": {"serviceType": ["BigQuery", "Snowflake"], "boost": 1.0}}
						]
					}
				},
				"functions": [
					{
						"filter": {"term": {"tier.tagFQN": "Tier.Tier1"}},
						"weight": 3.0
					},
					{
						"field_value_factor": {
							"field": "usageSummary.weeklyStats.count",
							"factor": 0.05,
							"modifier": "log1p",
							"missing": 0
						}
					}
				],
				"score_mode": "sum",
				"boost_mode": "multiply"
			}
		},
		"aggs": {
			"serviceType": {"terms": {"field": "serviceType", "size": 10}},
			"tags": {"terms": {"field": "tags.tagFQN", "size": 20}},
			"distinct_services": {"cardinality": {"field": "serviceType"}},
			"columns_by_type": {
				"nested": {"path": "columns"},
				"aggs": {
					"dataTypes": {"terms": {"field": "columns.dataType", "size": 15}}
				}
			}
		},
		"sort": [{"_score": "desc"}, {"updatedAt": "desc"}]
	}`
	searchJSON = strings.ReplaceAll(searchJSON, `" terms "`, `"terms"`)

	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(searchJSON), &req); err != nil {
		t.Fatalf("failed to parse search JSON: %v", err)
	}

	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}

	// Verify HitsSQL contains fulltext MATCH_ALL in WHERE, projection-safe LIKE in SELECT _score,
	// nested pre-filter + array_exists, array_contains on tags, and function_score
	expectedHitsSubstrings := []string{
		"CASE WHEN (lower(`f__name`) LIKE lower('%orders%')) THEN 10.0000 ELSE 0.0 END",
		"`f__name` MATCH_ALL 'orders'",
		"`f__displayName` MATCH_ALL 'orders'",
		"array_contains(`n__columns__name`, 'user_id') AND array_contains(`n__columns__dataType`, 'INT')",
		"array_exists(_el -> (json_extract_string(_el, '$.name') = 'user_id') AND (json_extract_string(_el, '$.dataType') = 'INT'), `n__columns`)",
		"array_contains(`f__tags__tagFQN`, 'PII.Sensitive')",
		"`f__serviceType` IN ('BigQuery', 'Snowflake')",
		"LOG10(1.0 + GREATEST(0.0, (0.0500 * COALESCE(`f__usageSummary__weeklyStats__count`, 0.0000))))",
		"ORDER BY `_score` DESC, `f__updatedAt` DESC",
		"LIMIT 20 OFFSET 0",
	}
	for _, sub := range expectedHitsSubstrings {
		if !strings.Contains(plan.HitsSQL, sub) {
			t.Errorf("expected HitsSQL to contain %q, got:\n%s", sub, plan.HitsSQL)
		}
	}

	// Verify MATCH_* never appears inside SELECT projection before FROM
	fromIdx := strings.Index(plan.HitsSQL, " FROM ")
	if fromIdx > 0 && strings.Contains(plan.HitsSQL[:fromIdx], "MATCH_") {
		t.Errorf("SELECT projection must not contain MATCH_* predicate, got:\n%s", plan.HitsSQL[:fromIdx])
	}

	// Verify AggsSQL uses Nereids Multi-Cast CTE (`WITH base_matched AS (...)`) + LATERAL VIEW EXPLODE + subquery wrapping
	expectedAggsSubstrings := []string{
		"WITH `base_matched` AS (SELECT * FROM `es_compat`.`table_search_index`",
		"FROM `base_matched` LATERAL VIEW EXPLODE(`f__tags__tagFQN`) `_t` AS `_elem`",
		"FROM `base_matched` LATERAL VIEW EXPLODE(`n__columns`) `_nt` AS `_nel`",
		"json_extract_string(`_nel`, '$.dataType') AS `_bucket_key`",
		"COUNT(DISTINCT `f__serviceType`)",
	}
	for _, sub := range expectedAggsSubstrings {
		if !strings.Contains(plan.AggsSQL, sub) {
			t.Errorf("expected AggsSQL to contain %q, got:\n%s", sub, plan.AggsSQL)
		}
	}
}
