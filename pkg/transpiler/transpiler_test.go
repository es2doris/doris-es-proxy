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

func TestCriticalBug2_FulltextInSelect_MinimumShouldMatch_LuceneRangeAndExists_DotProduct(t *testing.T) {
	mappingJSON := `{
		"properties": {
			"title": {"type": "text"},
			"serviceType": {"type": "keyword"},
			"latency": {"type": "long"},
			"embedding": {"type": "dense_vector", "dims": 3, "similarity": "dot_product"}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(mappingJSON), &spec); err != nil {
		t.Fatal(err)
	}
	idxSchema := schema.CompileIndexSchema("es_compat", "test_idx", &spec)
	tr := NewTranspiler(idxSchema, TranspilerOptions{})

	// 1. Boosting with fulltext negative clause must NOT leak MATCH_ into SELECT ... AS _score
	boostJSON := `{
		"query": {
			"boosting": {
				"positive": {"match": {"title": "orders"}},
				"negative": {"match": {"title": "deprecated"}},
				"negative_boost": 0.2
			}
		}
	}`
	var boostReq esast.SearchRequest
	if err := json.Unmarshal([]byte(boostJSON), &boostReq); err != nil {
		t.Fatal(err)
	}
	boostPlan, err := tr.BuildSearchPlan(&boostReq)
	if err != nil {
		t.Fatal(err)
	}
	selectPart := strings.Split(boostPlan.HitsSQL, " FROM ")[0]
	if strings.Contains(selectPart, "MATCH_") {
		t.Fatalf("SELECT projection must never contain MATCH_ predicate, got:\n%s", boostPlan.HitsSQL)
	}

	// 2. kNN with fulltext filter and dot_product similarity must NOT leak MATCH_ into SELECT and must use INNER_PRODUCT
	knnJSON := `{
		"knn": {
			"field": "embedding",
			"query_vector": [0.5, 0.5, 0.0],
			"k": 5,
			"filter": {"match": {"title": "orders"}}
		}
	}`
	var knnReq esast.SearchRequest
	if err := json.Unmarshal([]byte(knnJSON), &knnReq); err != nil {
		t.Fatal(err)
	}
	knnPlan, err := tr.BuildSearchPlan(&knnReq)
	if err != nil {
		t.Fatal(err)
	}
	knnSelect := strings.Split(knnPlan.HitsSQL, " FROM ")[0]
	if strings.Contains(knnSelect, "MATCH_") {
		t.Fatalf("kNN SELECT projection must never contain MATCH_ predicate, got:\n%s", knnPlan.HitsSQL)
	}
	if !strings.Contains(knnPlan.HitsSQL, "INNER_PRODUCT") {
		t.Fatalf("expected dot_product vector field to use INNER_PRODUCT, got:\n%s", knnPlan.HitsSQL)
	}

	// 3. Regexp and constant_score inside bool.should with minimum_should_match must not emit unconditional (1.0) > 0
	msmJSON := `{
		"query": {
			"bool": {
				"should": [
					{"regexp": {"serviceType": "Big.*"}},
					{"constant_score": {"filter": {"term": {"serviceType": "Snowflake"}}, "boost": 2.0}}
				],
				"minimum_should_match": 2
			}
		}
	}`
	var msmReq esast.SearchRequest
	if err := json.Unmarshal([]byte(msmJSON), &msmReq); err != nil {
		t.Fatal(err)
	}
	msmPlan, err := tr.BuildSearchPlan(&msmReq)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msmPlan.HitsSQL, "WHEN (1.0) > 0") || strings.Contains(msmPlan.HitsSQL, "WHEN (2.0000) > 0") {
		t.Fatalf("expected row-conditional ScoreSQL in minimum_should_match, got:\n%s", msmPlan.HitsSQL)
	}

	// 4. Lucene query_string with [min TO max] range and _exists_:field
	qsJSON := `{
		"query": {
			"query_string": {
				"query": "latency:[100 TO 500] AND _exists_:serviceType AND latency:{10 TO *}"
			}
		}
	}`
	var qsReq esast.SearchRequest
	if err := json.Unmarshal([]byte(qsJSON), &qsReq); err != nil {
		t.Fatal(err)
	}
	qsPlan, err := tr.BuildSearchPlan(&qsReq)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"`f__latency` >= 100",
		"`f__latency` <= 500",
		"`f__serviceType` IS NOT NULL",
		"`f__latency` > 10",
	} {
		if !strings.Contains(qsPlan.HitsSQL, want) {
			t.Fatalf("expected Lucene range/exists SQL to contain %q, got:\n%s", want, qsPlan.HitsSQL)
		}
	}

	// 5. Deep-dive regressions:
	//    - minimum_should_match with ids/range/exists/prefix/wildcard/bool(filter+must_not)
	//    - array sub-aggregations (LATERAL VIEW EXPLODE(`...`) `_sub_t` AS `_sub_elem`)
	//    - dynamic search_after type alignment & post_filter in __meta_total
	//    - nested query numeric range cast, dynamic subfield, and case_insensitive
	//    - Lucene mixed AND/OR precedence and ^boost
	var deepSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"group": {"type": "keyword", "normalizer": "lowercase_normalizer"},
			"tags": {"type": "keyword"},
			"title": {"type": "text"},
			"emb": {"type": "dense_vector", "dims": 2},
			"comments": {
				"type": "nested",
				"properties": {
					"author": {"type": "keyword", "normalizer": "lowercase_normalizer"},
					"likes": {"type": "integer"}
				}
			}
		}
	}`), &deepSpec); err != nil {
		t.Fatal(err)
	}
	tagsProp := deepSpec.Properties["tags"]
	tagsProp.MultiValued = true
	deepSpec.Properties["tags"] = tagsProp
	deepSchema := schema.CompileIndexSchema("es_compat", "deep_idx", &deepSpec)
	deepTr := NewTranspiler(deepSchema, TranspilerOptions{})

	deepJSON := `{
		"size": 0,
		"knn": {"field": "emb", "query_vector": [1.0, 0.0], "k": 5},
		"query": {
			"bool": {
				"must": [{"match": {"title": "hello"}}],
				"should": [
					{"ids": {"values": ["id-1"]}},
					{"range": {"comments.likes": {"gte": 10}}},
					{"exists": {"field": "group"}},
					{"prefix": {"group": "adm"}},
					{"wildcard": {"group": "adm*"}},
					{"bool": {"filter": [{"term": {"group": "admin"}}], "must_not": [{"term": {"group": "banned"}}]}},
					{"nested": {
						"path": "comments",
						"query": {
							"bool": {
								"must": [
									{"range": {"comments.likes": {"gte": 10}}},
									{"term": {"comments.author": {"value": "ALICE", "case_insensitive": true}}},
									{"term": {"comments.dyn_flag": "yes"}}
								]
							}
						}
					}}
				],
				"minimum_should_match": 2
			}
		},
		"post_filter": {"term": {"group": "Admin"}},
		"sort": [{"group": "asc"}, {"dyn_num": "asc"}],
		"search_after": ["Admin", 42],
		"aggs": {
			"by_group": {
				"terms": {"field": "group"},
				"aggs": {
					"top_tags": {"terms": {"field": "tags"}},
					"uniq_tags": {"cardinality": {"field": "tags"}},
					"cnt_tags": {"value_count": {"field": "tags"}}
				}
			}
		}
	}`
	var deepReq esast.SearchRequest
	if err := json.Unmarshal([]byte(deepJSON), &deepReq); err != nil {
		t.Fatal(err)
	}
	deepPlan, err := deepTr.BuildSearchPlan(&deepReq)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(deepPlan.AggsSQL, "WHEN (1.0) > 0") {
		t.Fatalf("expected no constant WHEN (1.0) > 0 in minimum_should_match SQL, got:\n%s", deepPlan.AggsSQL)
	}
	for _, want := range []string{
		"LATERAL VIEW EXPLODE(`f__tags`) `_sub_t` AS `_sub_elem`",
		"SELECT '__meta_total' AS `_agg_name`, '_count' AS `_bucket_key`, CAST(COUNT(*) AS DOUBLE) AS `_doc_count` FROM `base_matched` WHERE `f__group` = 'admin'",
		"CAST(json_extract_string(_el, '$.likes') AS BIGINT) >= 10",
		"lower(json_extract_string(_el, '$.author')) = lower('alice')",
		"json_extract_string(_el, '$.dyn_flag') = 'yes'",
	} {
		if !strings.Contains(deepPlan.AggsSQL, want) {
			t.Fatalf("expected deepPlan.AggsSQL to contain %q, got:\n%s", want, deepPlan.AggsSQL)
		}
	}

	// Verify dynamic search_after cast & lowercase normalizer when size > 0
	one := 1
	deepReq.Size = &one
	deepReq.KNN = nil
	deepPlanHits, err := deepTr.BuildSearchPlan(&deepReq)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"`f__group` > 'admin'",
		"CAST(`_doc`['dyn_num'] AS BIGINT) > 42",
		"CAST(`_doc`['dyn_num'] AS BIGINT) ASC",
	} {
		if !strings.Contains(deepPlanHits.HitsSQL, want) {
			t.Fatalf("expected deepPlanHits.HitsSQL to contain %q, got:\n%s", want, deepPlanHits.HitsSQL)
		}
	}

	// Verify Lucene mixed AND/OR precedence and ^boost suffix
	luceneMixedJSON := `{
		"query": {
			"query_string": {
				"query": "group:admin^2.5 AND tags:go OR group:ops^1.5"
			}
		}
	}`
	var luceneMixedReq esast.SearchRequest
	if err := json.Unmarshal([]byte(luceneMixedJSON), &luceneMixedReq); err != nil {
		t.Fatal(err)
	}
	luceneMixedPlan, err := deepTr.BuildSearchPlan(&luceneMixedReq)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(luceneMixedPlan.HitsSQL, "admin^2.5") || !strings.Contains(luceneMixedPlan.HitsSQL, " OR ") {
		t.Fatalf("expected Lucene mixed AND/OR + ^boost to strip boost suffix and preserve OR branch, got:\n%s", luceneMixedPlan.HitsSQL)
	}
}
