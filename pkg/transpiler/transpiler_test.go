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

func TestTranspileAllClauses_KNN_Lucene_Aggs_Collapse_SearchAfter(t *testing.T) {
	rawMapping := `{
		"properties": {
			"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"serviceType": {"type": "keyword"},
			"deleted": {"type": "boolean"},
			"updatedAt": {"type": "date"},
			"latency": {"type": "double"},
			"tags": {"properties": {"tagFQN": {"type": "keyword"}}},
			"embedding": {"type": "dense_vector", "dims": 3, "similarity": "cosine"},
			"l2_vec": {"type": "knn_vector", "dimension": 3, "similarity": "l2_norm"},
			"columns": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword"},
					"dataType": {"type": "keyword"}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatal(err)
	}
	idxSchema := schema.CompileIndexSchema("es_compat", "table_search_index", &spec)
	tr := NewTranspiler(idxSchema, TranspilerOptions{})

	payload := `{
		"size": 10,
		"query": {
			"boosting": {
				"positive": {
					"dis_max": {
						"tie_breaker": 0.3,
						"queries": [
							{
								"bool": {
									"should": [
										{"exists": {"field": "serviceType"}},
										{"exists": {"field": "tags.tagFQN"}},
										{"exists": {"field": "columns.name"}},
										{"prefix": {"serviceType": {"value": "Big", "case_insensitive": true}}},
										{"wildcard": {"name.keyword": {"value": "cust_100%*", "case_insensitive": true}}},
										{"regexp": {"serviceType": "Big.*"}},
										{"regexp": {"tags.tagFQN": "PII.*"}},
										{"ids": {"values": ["id-1", "id-2"]}},
										{"range": {"updatedAt": {"gte": "now-7d/d", "lt": "now"}}},
										{"match_phrase": {"name": {"query": "customer orders", "slop": 2}}},
										{"match_phrase_prefix": {"name": "cust ord"}},
										{"match_bool_prefix": {"name": "cust ord"}},
										{"simple_query_string": {"query": "+orders -legacy serviceType:BigQuery updatedAt:[100 TO 200] \"exact phrase\" cust* (foo OR bar)"}},
										{"constant_score": {"filter": {"term": {"deleted": false}}, "boost": 2.0}},
										{"knn": {"field": "l2_vec", "query_vector": [1.0, 0.0, 0.0], "k": 3, "similarity": 0.5, "filter": {"term": {"deleted": false}}}}
									],
									"must_not": [
										{"term": {"deleted": true}}
									],
									"minimum_should_match": "2"
								}
							}
						]
					}
				},
				"negative": {"term": {"unmapped_field": "bad"}},
				"negative_boost": 0.2
			}
		},
		"knn": [
			{"field": "embedding", "query_vector": [0.9, 0.1, 0.0], "k": 5, "similarity": 0.8, "boost": 1.5},
			{"field": "unmapped_vec", "query_vector": [0.1, 0.2, 0.3], "k": 2}
		],
		"post_filter": {"term": {"serviceType": "BigQuery"}},
		"collapse": {"field": "serviceType"},
		"search_after": [null, "2026-10-25T00:00:00Z"],
		"sort": [{"serviceType": "asc"}, {"updatedAt": "desc"}],
		"aggs": {
			"by_date": {
				"date_histogram": {"field": "updatedAt", "fixed_interval": "1h"},
				"aggs": {"avg_lat": {"avg": {"field": "latency"}}}
			},
			"by_hist": {
				"histogram": {"field": "latency", "interval": 10},
				"aggs": {"max_lat": {"max": {"field": "latency"}}}
			},
			"by_range": {
				"range": {"field": "latency", "ranges": [{"to": 50}, {"from": 50, "to": 100}, {"from": 100}]},
				"aggs": {"min_lat": {"min": {"field": "latency"}}}
			},
			"by_date_range": {
				"date_range": {"field": "updatedAt", "ranges": [{"to": "now-1d"}, {"from": "now-1d"}]}
			},
			"only_active": {
				"filter": {"term": {"deleted": false}},
				"aggs": {"sum_lat": {"sum": {"field": "latency"}}}
			},
			"named_filters": {
				"filters": {
					"filters": {
						"bq": {"term": {"serviceType": "BigQuery"}},
						"sf": {"term": {"serviceType": "Snowflake"}}
					}
				},
				"aggs": {"cnt": {"value_count": {"field": "serviceType"}}}
			},
			"missing_svc": {
				"missing": {"field": "serviceType"},
				"aggs": {"top_missing": {"top_hits": {"size": 1}}}
			},
			"comp": {
				"composite": {
					"size": 5,
					"after": {"svc": "BigQuery"},
					"sources": [{"svc": {"terms": {"field": "serviceType"}}}]
				}
			},
			"lat_stats": {"stats": {"field": "latency"}},
			"lat_pct": {"percentiles": {"field": "latency", "percents": [50, 95]}},
			"top_docs": {"top_hits": {"size": 2, "sort": [{"latency": "desc"}]}}
		}
	}`

	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("failed to unmarshal complex search request: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	for _, want := range []string{
		"COSINE_DISTANCE",
		"L2_DISTANCE",
		"CAST(`_doc`['unmapped_vec'] AS ARRAY<FLOAT>)",
		"ROW_NUMBER() OVER (PARTITION BY `f__serviceType`",
		"`f__serviceType` IS NULL",
	} {
		if !strings.Contains(plan.HitsSQL, want) {
			t.Fatalf("expected HitsSQL to contain %q, got:\n%s", want, plan.HitsSQL)
		}
	}
	if len(plan.UnindexedVariantFields) == 0 {
		t.Fatalf("expected unindexed variant fields to be recorded")
	}

	// Also test Doris 4.0 SEARCH() function pushdown mode and all function_score modifiers
	trDoris4 := NewTranspiler(idxSchema, TranspilerOptions{UseDoris4SearchFunc: true})
	for _, mod := range []string{"none", "log", "log1p", "log2p", "ln", "ln1p", "ln2p", "square", "sqrt", "reciprocal"} {
		for _, sm := range []string{"multiply", "sum", "avg", "max", "min", "first"} {
			for _, bm := range []string{"multiply", "replace", "sum", "avg", "max", "min"} {
				qJSON := `{
					"query": {
						"function_score": {
							"query": {"query_string": {"query": "name:orders AND serviceType:BigQuery"}},
							"functions": [{"field_value_factor": {"field": "latency", "modifier": "` + mod + `"}}],
							"score_mode": "` + sm + `",
							"boost_mode": "` + bm + `"
						}
					}
				}`
				var sr esast.SearchRequest
				if err := json.Unmarshal([]byte(qJSON), &sr); err != nil {
					t.Fatal(err)
				}
				p, err := trDoris4.BuildSearchPlan(&sr)
				if err != nil || !strings.Contains(p.HitsSQL, "SEARCH(") {
					t.Fatalf("expected SEARCH() in Doris4 mode (mod=%s sm=%s bm=%s): %v", mod, sm, bm, err)
				}
			}
		}
	}
}
