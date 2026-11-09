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

func TestTranspiler_DeepEvalCorrectnessFixes(t *testing.T) {
	mappingJSON := `{
		"properties": {
			"host": {
				"type": "text",
				"fields": {
					"keyword": {"type": "keyword", "normalizer": "lowercase"}
				}
			},
			"tags": {"type": "keyword", "multi_valued": true},
			"created_at": {"type": "date"},
			"views": {"type": "integer"},
			"comments": {
				"type": "nested",
				"properties": {
					"author": {"type": "keyword", "normalizer": "lowercase"},
					"labels": {"type": "keyword", "multi_valued": true}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(mappingJSON), &spec); err != nil {
		t.Fatal(err)
	}
	idxSchema := schema.CompileIndexSchema("logs_db", "deep_eval_idx", &spec)
	tr := NewTranspiler(idxSchema, TranspilerOptions{})

	// 1. preferKeyword queries (term, terms, prefix, wildcard, search_after) on text field with .keyword lowercase normalizer
	req1JSON := `{
		"query": {
			"bool": {
				"must": [
					{"term": {"host": "Web-01"}},
					{"terms": {"host": ["Web-01", "API-02"]}},
					{"prefix": {"host": "Web-"}},
					{"wildcard": {"host": "Web*"}},
					{"range": {"tags": {"gte": "b", "lte": "z"}}},
					{"range": {"created_at": {"gte": 1700000000, "format": "epoch_second"}}}
				],
				"should": [
					{"match": {"host": "web"}},
					{"match": {"host": "api"}}
				],
				"minimum_should_match": "75%"
			}
		},
		"sort": [{"host": "asc"}],
		"search_after": ["Web-01"],
		"aggs": {
			"missing_host": {
				"missing": {"field": "host"},
				"aggs": {
					"avg_views": {"avg": {"field": "views"}}
				}
			}
		}
	}`
	var req1 esast.SearchRequest
	if err := json.Unmarshal([]byte(req1JSON), &req1); err != nil {
		t.Fatal(err)
	}
	plan1, err := tr.BuildSearchPlan(&req1)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"`f__host__keyword` = 'web-01'",
		"`f__host__keyword` IN ('web-01', 'api-02')",
		"`f__host__keyword` LIKE 'web-%'",
		"array_exists(_x -> _x >= 'b' AND _x <= 'z', `f__tags`)",
		"`f__created_at` >= 1700000000000",
		"`f__host__keyword` > 'web-01'",
	} {
		if !strings.Contains(plan1.HitsSQL, want) {
			t.Fatalf("expected plan1.HitsSQL to contain %q, got:\n%s", want, plan1.HitsSQL)
		}
	}
	if !strings.Contains(plan1.AggsSQL, "missing_host.avg_views") {
		t.Fatalf("expected missing aggregation to compile sub-aggregations, got:\n%s", plan1.AggsSQL)
	}

	// 2. function_score multi-function multiply & empty match query
	req2JSON := `{
		"query": {
			"function_score": {
				"query": {"match": {"host": ""}},
				"score_mode": "multiply",
				"functions": [
					{"weight": 2},
					{"weight": 3}
				]
			}
		}
	}`
	var req2 esast.SearchRequest
	if err := json.Unmarshal([]byte(req2JSON), &req2); err != nil {
		t.Fatal(err)
	}
	plan2, err := tr.BuildSearchPlan(&req2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan2.HitsSQL, "WHERE `__DORIS_DELETE_SIGN__` = 0 AND (FALSE)") || !strings.Contains(plan2.HitsSQL, "2.0000 * 3.0000") || strings.Contains(plan2.HitsSQL, "1.0 + (2") {
		t.Fatalf("expected empty match to emit FALSE and function_score multiply to emit 2.0000 * 3.0000, got:\n%s", plan2.HitsSQL)
	}

	// 3. Nested terms on multi-valued & normalizer fields + single-quote prefilter escaping
	req3JSON := `{
		"query": {
			"nested": {
				"path": "comments",
				"query": {
					"bool": {
						"must": [
							{"term": {"comments.author": "O'Brien"}},
							{"terms": {"comments.labels": ["Urgent", "Bug"]}}
						]
					}
				}
			}
		}
	}`
	var req3 esast.SearchRequest
	if err := json.Unmarshal([]byte(req3JSON), &req3); err != nil {
		t.Fatal(err)
	}
	plan3, err := tr.BuildSearchPlan(&req3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan3.HitsSQL, "array_contains(`n__comments__author`, 'o''brien')") ||
		!strings.Contains(plan3.HitsSQL, "arrays_overlap(`n__comments__labels`, ['Urgent', 'Bug'])") {
		t.Fatalf("expected plan3.HitsSQL to contain nested prefilter and arrays_overlap, got:\n%s", plan3.HitsSQL)
	}
}

func TestTranspiler_Round3DeepEvalFixes(t *testing.T) {
	rawMapping := `{
		"properties": {
			"title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"tags": {"type": "text", "multi_valued": true, "fields": {"keyword": {"type": "keyword"}}},
			"service": {"type": "keyword"},
			"env": {"type": "keyword"},
			"events": {
				"type": "nested",
				"properties": {
					"ts": {"type": "date"},
					"kind": {"type": "keyword"}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatal(err)
	}
	idxSchema := schema.CompileIndexSchema("db", "idx", &spec)

	// 1. Multi-field `tags.keyword` inherits `MultiValued = true` (`StoragePromotedArray`) from parent `tags`
	tagsKw := idxSchema.ResolveField("tags.keyword")
	if tagsKw.Kind != schema.StoragePromotedArray {
		t.Fatalf("expected tags.keyword to inherit StoragePromotedArray, got %+v", tagsKw)
	}

	tr := NewTranspiler(idxSchema, TranspilerOptions{})

	// 2. bool with minimum_should_match > len(should) compiles to FALSE;
	//    MATCH_ANY quotes single quotes ('O''Brien');
	//    wildcard escapes literal %, _, \, and trailing \
	req1JSON := `{
		"query": {
			"bool": {
				"must": [
					{"match": {"title": "O'Brien"}},
					{"wildcard": {"service": "pay_100%\\"}}
				],
				"should": [
					{"term": {"env": "prod"}}
				],
				"minimum_should_match": 2
			}
		}
	}`
	var req1 esast.SearchRequest
	if err := json.Unmarshal([]byte(req1JSON), &req1); err != nil {
		t.Fatal(err)
	}
	plan1, err := tr.BuildSearchPlan(&req1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan1.HitsSQL, "MATCH_ANY 'O''Brien'") {
		t.Fatalf("expected MATCH_ANY to quote single quote ('O''Brien'), got:\n%s", plan1.HitsSQL)
	}
	if !strings.Contains(plan1.HitsSQL, `LIKE 'pay\\_100\\%\\\\'`) {
		t.Fatalf("expected wildcard to escape _, %%, and trailing \\, got:\n%s", plan1.HitsSQL)
	}
	if !strings.Contains(plan1.HitsSQL, "AND FALSE)") {
		t.Fatalf("expected minimum_should_match=2 with 1 should clause to emit FALSE, got:\n%s", plan1.HitsSQL)
	}

	// 3. function_score: score_mode="first", boost_mode="multiply" (else 1.0), and weight < 1.0 demotion
	req2JSON := `{
		"query": {
			"function_score": {
				"query": {"term": {"service": "checkout"}},
				"score_mode": "first",
				"boost_mode": "multiply",
				"functions": [
					{"filter": {"term": {"env": "prod"}}, "weight": 0.25},
					{"filter": {"term": {"env": "staging"}}, "weight": 2.0}
				]
			}
		}
	}`
	var req2 esast.SearchRequest
	if err := json.Unmarshal([]byte(req2JSON), &req2); err != nil {
		t.Fatal(err)
	}
	plan2, err := tr.BuildSearchPlan(&req2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan2.HitsSQL, "CASE WHEN `f__env` = 'prod' THEN 0.2500 WHEN `f__env` = 'staging' THEN 2.0000 ELSE 1.0 END") {
		t.Fatalf("expected score_mode=first multi-branch CASE WHEN with 0.2500 demotion and ELSE 1.0, got:\n%s", plan2.HitsSQL)
	}

	// 4. Nested date field preserves ISO string inside json_extract_string; nested agg strips .keyword;
	//    terms missing uses COALESCE; composite after adds > cursor filter
	req3JSON := `{
		"query": {
			"nested": {
				"path": "events",
				"query": {
					"range": {"events.ts": {"gte": "2026-10-01T00:00:00Z"}}
				}
			}
		},
		"aggs": {
			"by_env": {
				"terms": {"field": "env", "missing": "N/A"}
			},
			"nested_kinds": {
				"nested": {"path": "events"},
				"aggs": {
					"kinds": {"terms": {"field": "events.kind.keyword"}}
				}
			},
			"comp": {
				"composite": {
					"sources": [
						{"service": {"terms": {"field": "service"}}},
						{"env": {"terms": {"field": "env"}}}
					],
					"after": {"service": "checkout", "env": "prod"}
				}
			}
		}
	}`
	var req3 esast.SearchRequest
	if err := json.Unmarshal([]byte(req3JSON), &req3); err != nil {
		t.Fatal(err)
	}
	plan3, err := tr.BuildSearchPlan(&req3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan3.HitsSQL, "CAST(json_extract_string(_el, '$.ts') AS BIGINT) >= 1790812800000") {
		t.Fatalf("expected nested date range to normalize ISO string to epoch millis in json_extract_string, got:\n%s", plan3.HitsSQL)
	}
	if !strings.Contains(plan3.AggsSQL, "COALESCE(CAST(`f__env` AS STRING), 'N/A')") {
		t.Fatalf("expected terms missing to emit COALESCE(CAST(`f__env` AS STRING), 'N/A'), got:\n%s", plan3.AggsSQL)
	}
	if !strings.Contains(plan3.AggsSQL, "json_extract_string(`_nel`, '$.kind')") {
		t.Fatalf("expected nested terms agg to strip .keyword suffix ('$.kind'), got:\n%s", plan3.AggsSQL)
	}
	if !strings.Contains(plan3.AggsSQL, "> 'checkout\x1fprod'") {
		t.Fatalf("expected composite after cursor filter > 'checkout\\x1fprod', got:\n%s", plan3.AggsSQL)
	}
}

func TestTranspilerRound28ComprehensiveCoverage(t *testing.T) {
	mappingJSON := `{
		"properties": {
			"service": {"type": "keyword"},
			"env": {"type": "keyword"},
			"title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"latency": {"type": "double"},
			"status": {"type": "integer"},
			"ok": {"type": "boolean"},
			"client_ip": {"type": "ip"},
			"created_at": {"type": "date"},
			"location": {"type": "geo_point"},
			"tags": {"type": "keyword"},
			"embedding": {"type": "dense_vector", "dims": 3},
			"events": {
				"type": "nested",
				"properties": {
					"kind": {"type": "keyword"},
					"ms": {"type": "long"}
				}
			}
		}
	}`
	var mSpec esast.MappingSpec
	if err := json.Unmarshal([]byte(mappingJSON), &mSpec); err != nil {
		t.Fatal(err)
	}
	idxSchema := schema.CompileIndexSchema("logs_db", "round28_idx", &mSpec)
	tr := NewTranspiler(idxSchema, TranspilerOptions{})

	// 1. Lucene query_string parser (field groups, ranges, regex, wildcards, _exists_, boolean ops, boosts, fuzzy, sloppy phrases)
	luceneQueries := []string{
		`service:checkout AND (env:prod OR env:staging) AND NOT status:500`,
		`title:(+database -timeout "connection pool"~2)^2.5`,
		`latency:[10 TO 500} AND status:{100 TO *] AND _exists_:service`,
		`service:/check.*/ AND service:check* AND title:quikc~1`,
		`latency:>=100 AND latency:<500 AND ok:0.0`,
	}
	for _, lq := range luceneQueries {
		var req esast.SearchRequest
		raw := `{"query":{"query_string":{"query":` + mustJSONString(lq) + `,"default_field":"title"}}}`
		if err := json.Unmarshal([]byte(raw), &req); err != nil {
			t.Fatalf("unmarshal lucene query %q failed: %v", lq, err)
		}
		plan, err := tr.BuildSearchPlan(&req)
		if err != nil || plan.HitsSQL == "" {
			t.Fatalf("BuildSearchPlan(%q) failed: %v", lq, err)
		}
	}

	// 2. simple_query_string, combined_fields, match_bool_prefix, match_phrase_prefix, terms_set, dis_max, boosting, function_score, knn
	complexQueryJSON := `{
		"query": {
			"bool": {
				"must": [
					{"simple_query_string": {"query": "\"error\" + (timeout | retry) -fatal*", "fields": ["title^2", "service"]}},
					{"combined_fields": {"query": "checkout prod", "fields": ["title", "service"], "operator": "and"}},
					{"match_bool_prefix": {"title": {"query": "quick brown fox", "operator": "and"}}},
					{"match_phrase_prefix": {"title": {"query": "quick br", "slop": 1}}},
					{"terms_set": {"tags": {"terms": ["go", "doris"], "minimum_should_match_script": {"source": "Math.min(params.num_terms, 1)"}}}}
				],
				"filter": [
					{"dis_max": {"tie_breaker": 0.3, "queries": [{"term": {"service": "checkout"}}, {"prefix": {"service": "pay"}}]}},
					{"boosting": {"positive": {"match": {"title": "database"}}, "negative": {"term": {"status": 500}}, "negative_boost": 0.2}},
					{"function_score": {"query": {"match_all": {}}, "functions": [{"filter": {"term": {"service": "checkout"}}, "weight": 2.0}, {"field_value_factor": {"field": "latency", "factor": 1.2, "modifier": "log1p", "missing": 1.0}}], "score_mode": "sum", "boost_mode": "multiply"}},
					{"fuzzy": {"title": {"value": "databse", "fuzziness": 1}}},
					{"term": {"ok": 0.0}}
				]
			}
		},
		"knn": [
			{"field": "embedding", "query_vector": [0.1, 0.2, 0.3], "k": 5, "num_candidates": 10}
		]
	}`
	var reqComplex esast.SearchRequest
	dec := json.NewDecoder(strings.NewReader(complexQueryJSON))
	dec.UseNumber()
	if err := dec.Decode(&reqComplex); err != nil {
		t.Fatalf("decode complexQueryJSON failed: %v", err)
	}
	planComplex, err := tr.BuildSearchPlan(&reqComplex)
	if err != nil {
		t.Fatalf("BuildSearchPlan(complex) failed: %v", err)
	}
	if !strings.Contains(planComplex.HitsSQL, "`f__ok` = FALSE") {
		t.Fatalf("expected json.Number(\"0.0\") on boolean term query to compile to `f__ok` = FALSE, got:\n%s", planComplex.HitsSQL)
	}

	// 3. Advanced aggregations & script expression with escaped single quote (\')
	aggsJSON := `{
		"size": 0,
		"aggs": {
			"by_hour": {
				"date_histogram": {"field": "created_at", "fixed_interval": "1h", "offset": "+15m", "time_zone": "+02:00"},
				"aggs": {
					"req_rate": {"rate": {"field": "latency", "unit": "minute", "mode": "sum"}}
				}
			},
			"by_date_range": {
				"date_range": {
					"field": "created_at",
					"ranges": [{"from": "2026-10-01T00:00:00Z", "to": "2026-10-25T00:00:00Z", "key": "oct"}]
				}
			},
			"by_ip_range": {
				"ip_range": {
					"field": "client_ip",
					"ranges": [{"mask": "10.0.0.0/8"}, {"from": "192.168.1.1", "to": "192.168.1.255"}]
				}
			},
			"named_filters": {
				"filters": {
					"filters": {
						"prod": {"term": {"env": "prod"}},
						"stage": {"term": {"env": "staging"}}
					},
					"other_bucket": true
				}
			},
			"adj": {
				"adjacency_matrix": {
					"filters": {
						"a": {"term": {"service": "checkout"}},
						"b": {"term": {"env": "prod"}}
					}
				}
			},
			"rare": {"rare_terms": {"field": "service", "max_doc_count": 5}},
			"sig": {"significant_terms": {"field": "service", "size": 5}},
			"top_m": {"top_metrics": {"metrics": [{"field": "latency"}, {"field": "status"}], "sort": [{"created_at": "desc"}], "size": 2}},
			"box": {"boxplot": {"field": "latency"}},
			"sstats": {"string_stats": {"field": "service"}},
			"pranks": {"percentile_ranks": {"field": "latency", "values": [50, 100, 250]}},
			"ttest": {
				"t_test": {
					"a": {"field": "latency", "filter": {"term": {"env": "prod"}}},
					"b": {"field": "latency", "filter": {"term": {"env": "staging"}}},
					"type": "heteroscedastic"
				}
			},
			"escaped_quote_sum": {
				"sum": {
					"script": {
						"source": "(doc['latency'].value + params['a\\'b']) * 2",
						"params": {"a'b": 10}
					}
				}
			}
		}
	}`
	var reqAggs esast.SearchRequest
	if err := json.Unmarshal([]byte(aggsJSON), &reqAggs); err != nil {
		t.Fatalf("unmarshal aggsJSON failed: %v", err)
	}
	planAggs, err := tr.BuildSearchPlan(&reqAggs)
	if err != nil {
		t.Fatalf("BuildSearchPlan(aggs) failed: %v", err)
	}
	if !strings.Contains(planAggs.AggsSQL, "+ 10)) * 2)") {
		t.Fatalf("expected escaped quote param params['a\\'b'] to compile to (+ 10)) * 2), got:\n%s", planAggs.AggsSQL)
	}
}

func TestRound29TranspilerNestedDateBoundsRelativeNestedPathsLuceneExistsAndSubAggs(t *testing.T) {
	rawMapping := `{
		"properties": {
			"service": {"type": "keyword"},
			"latency": {"type": "long"},
			"created_at": {"type": "date"},
			"client_ip": {"type": "ip"},
			"tags": {"type": "keyword", "multi_valued": true},
			"items": {
				"type": "nested",
				"properties": {
					"ts": {"type": "date"},
					"price": {"type": "double"},
					"title": {
						"type": "text",
						"fields": {
							"keyword": {"type": "keyword", "normalizer": "lowercase", "ignore_above": 64}
						}
					},
					"title_alias": {"type": "alias", "path": "items.title"}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatal(err)
	}
	sch := schema.CompileIndexSchema("db", "r29_tr", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// 1. Nested date range with ISO-8601 'T' strings on gt and lte (roundUp=true) must stay ISO strings
	var reqNestedRange esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"nested": {
				"path": "items",
				"query": {
					"bool": {
						"must": [
							{"range": {"items.ts": {"gt": "2026-10-01T00:00:00Z", "lte": "2026-10-02T23:59:59Z"}}},
							{"regexp": {"title.keyword": {"value": "widg.*"}}},
							{"term": {"title_alias.keyword": "Widget"}}
						]
					}
				}
			}
		},
		"sort": [
			{
				"items.title.keyword": {
					"order": "asc",
					"nested": {
						"path": "items",
						"filter": {"term": {"title.keyword": "Widget"}}
					}
				}
			}
		]
	}`), &reqNestedRange)
	planNR, err := tr.BuildSearchPlan(&reqNestedRange)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqNestedRange) failed: %v", err)
	}
	if !strings.Contains(planNR.HitsSQL, "1790812800000") || !strings.Contains(planNR.HitsSQL, "1790985599000") {
		t.Fatalf("expected nested date gt/lte ISO bounds to normalize to epoch millis, got:\n%s", planNR.HitsSQL)
	}
	if !strings.Contains(planNR.HitsSQL, "$.title__keyword") {
		t.Fatalf("expected relative nested title.keyword and nested sort filter to route to $.title__keyword, got:\n%s", planNR.HitsSQL)
	}

	// 2. Lucene unbounded range field:[* TO *], field:{* TO *}, field:*, *:*, *:[* TO *]
	for _, qs := range []string{`service:[* TO *]`, `service:{* TO *}`, `service:*`} {
		var reqQS esast.SearchRequest
		_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"`+qs+`"}}}`), &reqQS)
		p, err := tr.BuildSearchPlan(&reqQS)
		if err != nil {
			t.Fatalf("BuildSearchPlan(%s) failed: %v", qs, err)
		}
		if !strings.Contains(p.HitsSQL, "`f__service` IS NOT NULL") {
			t.Fatalf("expected %s to compile to Exists (`f__service` IS NOT NULL), got:\n%s", qs, p.HitsSQL)
		}
	}
	for _, qsAll := range []string{`*:*`, `*:[* TO *]`} {
		var reqAll esast.SearchRequest
		_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"`+qsAll+`"}}}`), &reqAll)
		p, err := tr.BuildSearchPlan(&reqAll)
		if err != nil || !strings.Contains(p.HitsSQL, "TRUE") || strings.Contains(p.HitsSQL, "LIKE") || strings.Contains(p.HitsSQL, ">=") {
			t.Fatalf("expected %s to compile to MatchAll TRUE without LIKE/>=, got err=%v sql=%s", qsAll, err, p.HitsSQL)
		}
	}

	// 3. IdsQuery with numeric IDs + boost, and match_bool_prefix / multi_match bool_prefix with fuzziness
	var reqIdsFuzz esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"ids": {"values": [10, 20], "boost": 3.5}},
					{"match_bool_prefix": {"service": {"query": "check out", "fuzziness": 1}}},
					{"multi_match": {"query": "pay gate", "type": "bool_prefix", "fields": ["service"], "fuzziness": 1}}
				]
			}
		}
	}`), &reqIdsFuzz)
	planIF, err := tr.BuildSearchPlan(&reqIdsFuzz)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqIdsFuzz) failed: %v", err)
	}
	if !strings.Contains(planIF.HitsSQL, "`_id` IN ('10', '20')") || !strings.Contains(planIF.HitsSQL, "3.5000") || !strings.Contains(planIF.HitsSQL, "REGEXP") {
		t.Fatalf("expected numeric ids + boost 3.5000 + fuzzy REGEXP in HitsSQL, got:\n%s", planIF.HitsSQL)
	}

	// 4. Nested sub-aggregations across terms, histogram, date_histogram, range, filters, nested, reverse_nested
	var reqDeepAggs esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"by_tag": {
				"terms": {"field": "tags", "size": 5},
				"aggs": {
					"avg_lat": {"avg": {"field": "latency"}},
					"pct_lat": {"percentiles": {"field": "latency", "percents": [50, 95]}},
					"prank_lat": {"percentile_ranks": {"field": "latency", "values": [100]}},
					"box_lat": {"boxplot": {"field": "latency"}},
					"sstats_svc": {"string_stats": {"field": "service"}},
					"top_h": {"top_hits": {"size": 1, "sort": [{"latency": "desc"}]}},
					"top_m": {"top_metrics": {"metrics": [{"field": "latency"}], "sort": [{"created_at": "desc"}]}},
					"sub_hist": {"histogram": {"field": "latency", "interval": 50}},
					"sub_dhist": {"date_histogram": {"field": "created_at", "fixed_interval": "1h"}},
					"sub_range": {"range": {"field": "latency", "ranges": [{"to": 100}, {"from": 100}]}},
					"sub_ip_range": {"ip_range": {"field": "client_ip", "ranges": [{"mask": "10.0.0.0/8"}]}},
					"sub_filter": {"filter": {"term": {"service": "api"}}, "aggs": {"s": {"sum": {"field": "latency"}}}},
					"sub_missing": {"missing": {"field": "service"}},
					"sub_nested": {
						"nested": {"path": "items"},
						"aggs": {
							"min_p": {"min": {"field": "items.price"}},
							"back": {"reverse_nested": {}, "aggs": {"c": {"value_count": {"field": "service"}}}}
						}
					}
				}
			}
		}
	}`), &reqDeepAggs)
	planDA, err := tr.BuildSearchPlan(&reqDeepAggs)
	if err != nil || planDA.AggsSQL == "" {
		t.Fatalf("BuildSearchPlan(reqDeepAggs) failed: err=%v sql=%s", err, planDA.AggsSQL)
	}
}

func TestRound30BoostZeroFuzzyCaseInsensitiveTermsSetAndRelativeNestedSubAggs(t *testing.T) {
	rawMap := `{
		"properties": {
			"service": {"type": "keyword"},
			"tags": {"type": "keyword", "multi_valued": true},
			"req_count": {"type": "integer"},
			"vec": {"type": "dense_vector", "dims": 3},
			"events": {
				"type": "nested",
				"properties": {
					"code": {"type": "keyword", "normalizer": "lowercase"},
					"flag": {"type": "boolean"},
					"ms": {"type": "long"},
					"ts": {"type": "date_nanos"}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMap), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r30_tr_idx", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// 1. Explicit boost: 0 on prefix, wildcard, and regexp queries + fuzzy case_insensitive: true + range on vector field
	var req1 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"should": [
					{"prefix": {"service": {"prefix": "api", "boost": 0}}},
					{"wildcard": {"service": {"wildcard": "*web*", "boost": 0}}},
					{"regexp": {"service": {"regexp": "auth.*", "boost": 0}}},
					{"fuzzy": {"service": {"value": "PayMent", "fuzziness": 1, "case_insensitive": true}}},
					{"range": {"vec": {"gte": 0, "lte": 1}}}
				]
			}
		}
	}`), &req1); err != nil {
		t.Fatalf("unmarshal req1 failed: %v", err)
	}
	plan1, err := tr.BuildSearchPlan(&req1)
	if err != nil {
		t.Fatalf("BuildSearchPlan(req1) failed: %v", err)
	}
	if strings.Contains(plan1.HitsSQL, "THEN 1.0000") && !strings.Contains(plan1.HitsSQL, "THEN 0.0000") {
		t.Fatalf("expected explicit boost:0 to emit THEN 0.0000, got:\n%s", plan1.HitsSQL)
	}
	if !strings.Contains(plan1.HitsSQL, "REGEXP '(?i)^(PayMent|") {
		t.Fatalf("expected fuzzy case_insensitive:true to use (?i) REGEXP, got:\n%s", plan1.HitsSQL)
	}
	if strings.Contains(plan1.HitsSQL, "f__vec") {
		t.Fatalf("expected range query on dense_vector field 'vec' to compile to FALSE without referencing f__vec, got:\n%s", plan1.HitsSQL)
	}

	// 2. terms_set minimum_should_match_script on unmapped dynamic field (CAST AS DOUBLE) and scalar .size()
	var req2 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{
						"terms_set": {
							"tags": {
								"terms": ["a", "b"],
								"minimum_should_match_script": {"source": "doc['dyn_thresh'].value"}
							}
						}
					},
					{
						"terms_set": {
							"tags": {
								"terms": ["a", "b"],
								"minimum_should_match_script": {"source": "doc['req_count'].size()"}
							}
						}
					}
				]
			}
		}
	}`), &req2); err != nil {
		t.Fatalf("unmarshal req2 failed: %v", err)
	}
	plan2, err := tr.BuildSearchPlan(&req2)
	if err != nil {
		t.Fatalf("BuildSearchPlan(req2) failed: %v", err)
	}
	if !strings.Contains(plan2.HitsSQL, "COALESCE(CAST(`_doc`['dyn_thresh'] AS DOUBLE), 1)") {
		t.Fatalf("expected numeric column ref in COALESCE for dyn_thresh, got:\n%s", plan2.HitsSQL)
	}
	if !strings.Contains(plan2.HitsSQL, "(CASE WHEN `f__req_count` IS NOT NULL THEN 1 ELSE 0 END)") {
		t.Fatalf("expected scalar .size() CASE WHEN IS NOT NULL expression, got:\n%s", plan2.HitsSQL)
	}

	// 3. Relative field names inside nested sub-aggregations + escaped quote in string script
	var req3 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"n_events": {
				"nested": {"path": "events"},
				"aggs": {
					"by_flag": {
						"terms": {"field": "flag"},
						"aggs": {
							"by_code": {"terms": {"field": "code"}},
							"by_ts": {"date_histogram": {"field": "ts", "fixed_interval": "1s"}},
							"avg_ms": {"avg": {"field": "ms"}},
							"quoted": {"terms": {"script": {"source": "doc['code'].value + 'a\\'b'"}}}
						}
					}
				}
			}
		}
	}`), &req3); err != nil {
		t.Fatalf("unmarshal req3 failed: %v", err)
	}
	plan3, err := tr.BuildSearchPlan(&req3)
	if err != nil {
		t.Fatalf("BuildSearchPlan(req3) failed: %v", err)
	}
	if strings.Contains(plan3.AggsSQL, "`_doc`['flag']") || strings.Contains(plan3.AggsSQL, "`_doc`['code']") || strings.Contains(plan3.AggsSQL, "`_doc`['ms']") {
		t.Fatalf("expected relative nested sub-agg fields ('flag', 'code', 'ms') to resolve against nested element _nel_0, got:\n%s", plan3.AggsSQL)
	}
	if !strings.Contains(plan3.AggsSQL, "LOWER(") {
		t.Fatalf("expected relative nested field 'code' with lowercase normalizer to wrap in LOWER(...), got:\n%s", plan3.AggsSQL)
	}
}

func TestRound31BugFixesAndUntestedSubsystems(t *testing.T) {
	rawMap := `{
		"properties": {
			"svc_name":   {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"svc_region": {"type": "keyword", "normalizer": "lowercase"},
			"status":     {"type": "keyword"},
			"req_count":  {"type": "long"},
			"latency":    {"type": "double"},
			"active":     {"type": "boolean"},
			"client_ip":  {"type": "ip"},
			"ip_list":    {"type": "ip", "multi_valued": true},
			"ts":         {"type": "date"},
			"ts_nanos":   {"type": "date_nanos"},
			"tags":       {"type": "keyword", "multi_valued": true},
			"scores":     {"type": "double", "multi_valued": true},
			"vec_cos":    {"type": "dense_vector", "dims": 2, "similarity": "cosine"},
			"vec_l2":     {"type": "dense_vector", "dims": 2, "similarity": "l2_norm"},
			"vec_dot":    {"type": "dense_vector", "dims": 2, "similarity": "dot_product"},
			"events": {
				"type": "nested",
				"properties": {
					"code": {"type": "keyword", "normalizer": "lowercase"},
					"msg":  {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
					"ms":   {"type": "long"},
					"flag": {"type": "boolean"},
					"ts":   {"type": "date"},
					"tags": {"type": "keyword", "multi_valued": true}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMap), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	sc := schema.CompileIndexSchema("logs_db", "r31_idx", &spec)
	tr := NewTranspiler(sc, TranspilerOptions{})

	// Fix 1: Wildcard & caret-boost on match, match_phrase, match_phrase_prefix, match_bool_prefix, and fuzzy
	var reqFix1 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"should": [
					{"match": {"svc*^2.5": {"query": "payment api", "boost": 2.0}}},
					{"match_phrase": {"svc*^1.5": {"query": "payment api", "slop": 2}}},
					{"match_phrase_prefix": {"svc*^2.0": {"query": "pay"}}},
					{"match_bool_prefix": {"svc_name^3.0": {"query": "payment gateway", "operator": "and"}}},
					{"fuzzy": {"svc*^2.0": {"value": "payment", "fuzziness": 1}}}
				]
			}
		}
	}`), &reqFix1); err != nil {
		t.Fatalf("unmarshal reqFix1 failed: %v", err)
	}
	planFix1, err := tr.BuildSearchPlan(&reqFix1)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqFix1) failed: %v", err)
	}
	if strings.Contains(planFix1.HitsSQL, "`_doc`['svc*") {
		t.Fatalf("expected wildcard field svc* to expand to mapped fields instead of literal _doc['svc*'], got:\n%s", planFix1.HitsSQL)
	}
	if !strings.Contains(planFix1.HitsSQL, "5.0000") {
		t.Fatalf("expected svc*^2.5 with boost:2.0 to combine to 5.0000, got:\n%s", planFix1.HitsSQL)
	}

	// Fix 2: script_score (Script, Boost, MinScore, _score) and function_score (ScriptScore, Functions.ScriptScore, Boost, MinScore)
	var reqFix2 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{
						"script_score": {
							"query": {"term": {"status": "ok"}},
							"script": {"source": "_score * 2 + doc['req_count'].value * params.factor", "params": {"factor": 3}},
							"boost": 1.5,
							"min_score": 10.0
						}
					},
					{
						"function_score": {
							"query": {"term": {"status": "ok"}},
							"functions": [
								{
									"filter": {"term": {"active": true}},
									"script_score": {"script": {"source": "doc['latency'].value + 5"}}
								},
								{
									"field_value_factor": {"field": "req_count", "factor": 1.2, "modifier": "log1p", "missing": 1.0}
								}
							],
							"score_mode": "sum",
							"boost_mode": "replace",
							"max_boost": 100.0,
							"boost": 2.0,
							"min_score": 5.0
						}
					}
				]
			}
		}
	}`), &reqFix2); err != nil {
		t.Fatalf("unmarshal reqFix2 failed: %v", err)
	}
	planFix2, err := tr.BuildSearchPlan(&reqFix2)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqFix2) failed: %v", err)
	}
	if !strings.Contains(planFix2.HitsSQL, ">= 10") || !strings.Contains(planFix2.HitsSQL, ">= 5") {
		t.Fatalf("expected script_score and function_score min_score predicates in WHERE, got:\n%s", planFix2.HitsSQL)
	}
	if !strings.Contains(planFix2.HitsSQL, "1.5000") || !strings.Contains(planFix2.HitsSQL, "2.0000") {
		t.Fatalf("expected script_score and function_score boost multipliers in ScoreSQL, got:\n%s", planFix2.HitsSQL)
	}

	// Fix 3: Nested prefilter with relative field names
	var reqFix3 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"nested": {
				"path": "events",
				"score_mode": "sum",
				"query": {
					"bool": {
						"must": [
							{"term": {"code": "ERR_TIMEOUT"}},
							{"terms": {"tags": ["net", "db"]}},
							{"exists": {"field": "msg"}},
							{"prefix": {"code": "ERR"}},
							{"wildcard": {"code": "ERR*"}},
							{"regexp": {"code": "ERR.*"}},
							{"match": {"msg": "timeout"}}
						]
					}
				}
			}
		}
	}`), &reqFix3); err != nil {
		t.Fatalf("unmarshal reqFix3 failed: %v", err)
	}
	planFix3, err := tr.BuildSearchPlan(&reqFix3)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqFix3) failed: %v", err)
	}
	if !strings.Contains(planFix3.HitsSQL, "n__events__code") {
		t.Fatalf("expected relative nested field 'code' to use prefilter array column n__events__code, got:\n%s", planFix3.HitsSQL)
	}

	// Fix 4: Multi-field term, range, prefix, wildcard, and regexp additive scoring & caret boosts
	var reqFix4 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"term": {"status^2.0": {"value": "ok"}, "svc_region^3.0": {"value": "US-EAST"}}},
					{"range": {"req_count^1.5": {"gte": 10}, "latency^2.5": {"lte": 500}}},
					{"prefix": {"status^2.0": {"value": "o"}, "svc_region^3.0": {"value": "us"}}},
					{"wildcard": {"status^2.0": {"value": "o*"}, "svc_region^3.0": {"value": "us*"}}},
					{"regexp": {"status^2.0": {"value": "o.*"}, "svc_region^3.0": {"value": "us.*"}}}
				]
			}
		}
	}`), &reqFix4); err != nil {
		t.Fatalf("unmarshal reqFix4 failed: %v", err)
	}
	planFix4, err := tr.BuildSearchPlan(&reqFix4)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqFix4) failed: %v", err)
	}
	if !strings.Contains(planFix4.HitsSQL, "2.0000") || !strings.Contains(planFix4.HitsSQL, "3.0000") || !strings.Contains(planFix4.HitsSQL, " + ") {
		t.Fatalf("expected multi-field leaf queries to accumulate per-field caret-boosted scores with '+', got:\n%s", planFix4.HitsSQL)
	}

	// Fix 5: Wildcard field exists in Lucene query_string (svc*:[* TO *], svc*:{* TO *}, svc*:*) and non-matching wildcard exists -> FALSE
	var reqFix5 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"query_string": {"query": "svc*:[* TO *] AND svc*:{* TO *} AND svc*:*"}},
					{"exists": {"field": "nonexistent_prefix_*"}}
				]
			}
		}
	}`), &reqFix5); err != nil {
		t.Fatalf("unmarshal reqFix5 failed: %v", err)
	}
	planFix5, err := tr.BuildSearchPlan(&reqFix5)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqFix5) failed: %v", err)
	}
	if !strings.Contains(planFix5.HitsSQL, "IS NOT NULL") {
		t.Fatalf("expected svc*:[* TO *] and svc*:* to compile to IS NOT NULL exists checks, got:\n%s", planFix5.HitsSQL)
	}
	if !strings.Contains(planFix5.HitsSQL, "FALSE") {
		t.Fatalf("expected exists on unmatched wildcard pattern nonexistent_prefix_* to compile to FALSE, got:\n%s", planFix5.HitsSQL)
	}

	// Coverage expansion: KNN (cosine, l2, dot_product, dynamic vector), Script query, IP CIDR term/terms, Collapse, PIT Sorts, Array Sort Modes, SearchAfter, and Comprehensive Aggregations
	var reqCov1 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"pit": {"id": "r31_idx", "keep_alive": "1m"},
		"query": {
			"bool": {
				"must": [
					{"knn": {"field": "vec_cos", "query_vector": [0.1, 0.2], "k": 5, "similarity": 0.8, "filter": [{"term": {"status": "ok"}}], "boost": 1.5}},
					{"knn": {"field": "vec_l2", "query_vector": [0.3, 0.4], "k": 5, "similarity": 1.5}},
					{"knn": {"field": "vec_dot", "query_vector": [0.5, 0.6], "k": 5, "similarity": 0.5}},
					{"knn": {"field": "unmapped_vec", "query_vector": [0.7, 0.8], "k": 5}},
					{"term": {"client_ip": "10.0.0.0/8"}},
					{"term": {"ip_list": "192.168.1.0/24"}},
					{"terms": {"client_ip": ["10.0.0.0/8", "172.16.0.1"]}},
					{"script": {"script": {"source": "doc['req_count'].value + params.inc >= 10 && !doc['status'].empty && doc['tags'].size() > 0", "params": {"inc": 2}}}}
				]
			}
		},
		"collapse": {
			"field": "status",
			"inner_hits": {"name": "top_by_lat", "size": 3, "sort": [{"latency": "desc"}]}
		},
		"sort": [
			{"_script": {"type": "number", "script": {"source": "doc['req_count'].value * 2"}, "order": "desc", "missing": 0}},
			{"_script": {"type": "string", "script": {"source": "doc['status'].value + '_x'"}, "order": "asc", "missing": "_first"}},
			{"scores": {"order": "desc", "mode": "avg"}},
			{"scores": {"order": "asc", "mode": "median"}},
			{"scores": {"order": "desc", "mode": "sum"}},
			{"client_ip": {"order": "asc", "missing": "127.0.0.1"}},
			{"ts_nanos": {"order": "desc", "missing": "2026-01-01T00:00:00Z"}},
			{"events.ms": {"order": "desc", "mode": "max", "nested": {"path": "events", "filter": {"term": {"events.flag": true}}}}}
		],
		"search_after": [100, "ok_x", 50.5, 25.0, 150.0, "10.0.0.1", "2026-01-02T00:00:00Z", 200, "doc_1"]
	}`), &reqCov1); err != nil {
		t.Fatalf("unmarshal reqCov1 failed: %v", err)
	}
	planCov1, err := tr.BuildSearchPlan(&reqCov1)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqCov1) failed: %v", err)
	}
	if !strings.Contains(planCov1.HitsSQL, "COSINE_DISTANCE") || !strings.Contains(planCov1.HitsSQL, "L2_DISTANCE") || !strings.Contains(planCov1.HitsSQL, "INNER_PRODUCT") {
		t.Fatalf("expected KNN distance functions in HitsSQL, got:\n%s", planCov1.HitsSQL)
	}
	if !strings.Contains(planCov1.HitsSQL, "IPV4_STRING_TO_NUM_OR_NULL") {
		t.Fatalf("expected IPv4 CIDR conversion in HitsSQL, got:\n%s", planCov1.HitsSQL)
	}
	if !strings.Contains(planCov1.HitsSQL, "array_avg") || !strings.Contains(planCov1.HitsSQL, "array_median") || !strings.Contains(planCov1.HitsSQL, "array_sum") {
		t.Fatalf("expected array sort functions in HitsSQL, got:\n%s", planCov1.HitsSQL)
	}

	// Coverage expansion: Top-level and nested/bucket sub-aggregations
	var reqCov2 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"global_all": {
				"global": {},
				"aggs": {
					"avg_lat": {"avg": {"field": "latency", "missing": 0, "script": {"source": "_value * 2"}}}
				}
			},
			"sampled": {
				"sampler": {"shard_size": 100},
				"aggs": {
					"by_status": {
						"terms": {"field": "status", "missing": "N/A"},
						"aggs": {
							"sub_sampler": {"diversified_sampler": {"shard_size": 50, "field": "svc_region"}},
							"sub_missing": {"missing": {"field": "latency"}},
							"sub_filter": {"filter": {"term": {"active": true}}},
							"sub_filters_anon": {"filters": {"other_bucket": true, "filters": [{"term": {"active": true}}, {"term": {"active": false}}]}},
							"sub_filters_named": {"filters": {"other_bucket": true, "other_bucket_key": "rest", "filters": {"on": {"term": {"active": true}}}}},
							"sub_ip_range": {"ip_range": {"field": "client_ip", "ranges": [{"mask": "10.0.0.0/8"}, {"from": "192.168.0.1", "to": "192.168.255.255"}]}},
							"sub_ip_arr_range": {"ip_range": {"field": "ip_list", "ranges": [{"mask": "10.0.0.0/8"}, {"from": "192.168.0.1", "to": "192.168.255.255"}]}},
							"sub_arr_range": {"range": {"field": "scores", "missing": 0, "script": {"source": "_value + 1"}, "ranges": [{"from": 0, "to": 50}, {"from": 50}]}},
							"sub_dh_arr": {"date_histogram": {"field": "ts", "fixed_interval": "1h", "time_zone": "+02:00", "offset": "+15m", "missing": "2026-01-01T00:00:00Z", "script": {"source": "_value + 1000"}}},
							"sub_hist_arr": {"histogram": {"field": "scores", "interval": 10, "offset": 2, "missing": 0, "script": {"source": "_value * 1.5"}}},
							"sub_pct_arr": {"percentiles": {"field": "scores", "percents": [50, 95], "missing": 0, "script": {"source": "_value + 1"}}},
							"sub_pr_arr": {"percentile_ranks": {"field": "scores", "values": [25, 75], "missing": 0, "script": {"source": "_value + 1"}}},
							"sub_str_stats_arr": {"string_stats": {"field": "tags"}},
							"sub_str_stats_scalar": {"string_stats": {"field": "status"}},
							"sub_vc_arr": {"value_count": {"field": "tags", "missing": "none", "script": {"source": "doc['tags'].value + '_v'"}}},
							"sub_card_arr": {"cardinality": {"field": "tags", "missing": "none", "script": {"source": "doc['tags'].value + '_c'"}}},
							"sub_terms_arr": {"terms": {"field": "tags", "missing": "none", "script": {"source": "doc['tags'].value.toUpperCase()"}}},
							"sub_top_hits": {"top_hits": {"size": 2, "sort": [{"latency": "desc"}]}},
							"sub_top_metrics": {"top_metrics": {"metrics": {"field": "latency"}, "size": 1, "sort": [{"req_count": "desc"}]}}
						}
					}
				}
			},
			"top_ip_range": {"ip_range": {"field": "client_ip", "ranges": [{"mask": "10.0.0.0/8"}, {"from": "172.16.0.1", "to": "172.16.255.255"}]}},
			"top_ip_arr_range": {"ip_range": {"field": "ip_list", "ranges": [{"mask": "10.0.0.0/8"}, {"from": "172.16.0.1", "to": "172.16.255.255"}]}},
			"top_arr_range": {"range": {"field": "scores", "missing": 0, "script": {"source": "_value + 1"}, "ranges": [{"from": 0, "to": 100}]}},
			"top_date_range": {"date_range": {"field": "ts", "format": "epoch_second", "time_zone": "+01:00", "missing": "1700000000", "ranges": [{"from": "1700000000", "to": "1800000000"}]}},
			"top_dh": {"date_histogram": {"field": "ts", "fixed_interval": "1h", "time_zone": "+01:00", "offset": "+10m", "missing": "2026-01-01T00:00:00Z", "script": {"source": "_value + 500"}}},
			"top_hist_arr": {"histogram": {"field": "scores", "interval": 10, "missing": 0, "script": {"source": "_value * 2"}}},
			"top_pct_arr": {"percentiles": {"field": "scores", "percents": [50, 90], "missing": 0, "script": {"source": "_value * 2"}}},
			"top_pr_arr": {"percentile_ranks": {"field": "scores", "values": [10, 50], "missing": 0, "script": {"source": "_value * 2"}}},
			"top_box_arr": {"boxplot": {"field": "scores", "missing": 0, "script": {"source": "_value * 2"}}},
			"top_box_scalar": {"boxplot": {"field": "latency", "missing": 0, "script": {"source": "_value * 2"}}},
			"top_ext_stats_arr": {"extended_stats": {"field": "scores", "missing": 0, "script": {"source": "_value * 2"}}},
			"top_str_stats_arr": {"string_stats": {"field": "tags"}},
			"top_str_stats_scalar": {"string_stats": {"field": "status"}},
			"top_card_arr": {"cardinality": {"field": "tags", "missing": "none", "script": {"source": "doc['tags'].value.toLowerCase()"}}},
			"top_rate_count": {"rate": {"unit": "second"}},
			"top_rate_vc": {"rate": {"field": "req_count", "mode": "value_count", "unit": "minute"}},
			"top_rate_sum": {"rate": {"field": "req_count", "mode": "sum", "unit": "hour"}},
			"top_filters_anon": {"filters": {"other_bucket": true, "filters": [{"term": {"active": true}}, {"term": {"active": false}}]}},
			"top_comp": {
				"composite": {
					"size": 10,
					"after": {"s_tag": "a", "s_ts": 1700000000000, "s_hist": 10},
					"sources": [
						{"s_tag": {"terms": {"field": "tags", "missing_bucket": true}}},
						{"s_ts": {"date_histogram": {"field": "ts", "fixed_interval": "1h", "time_zone": "+01:00", "missing_bucket": true}}},
						{"s_hist": {"histogram": {"field": "latency", "interval": 10, "missing_bucket": true}}}
					]
				},
				"aggs": {
					"avg_req": {"avg": {"field": "req_count"}}
				}
			},
			"nested_ev": {
				"nested": {"path": "events"},
				"aggs": {
					"n_pct": {"percentiles": {"field": "events.ms", "missing": 0, "script": {"source": "doc['events.ms'].value * 2"}}},
					"n_pr": {"percentile_ranks": {"field": "events.ms", "values": [10, 100], "missing": 0, "script": {"source": "doc['events.ms'].value * 2"}}},
					"n_box": {"boxplot": {"field": "events.ms", "missing": 0, "script": {"source": "doc['events.ms'].value * 2"}}},
					"n_str": {"string_stats": {"field": "events.code"}},
					"n_card": {"cardinality": {"field": "events.code", "missing": "none", "script": {"source": "doc['events.code'].value.trim()"}}},
					"n_vc": {"value_count": {"field": "events.code", "missing": "none", "script": {"source": "doc['events.code'].value"}}},
					"n_rev": {
						"reverse_nested": {},
						"aggs": {
							"root_ statuses": {"terms": {"field": "status"}}
						}
					}
				}
			}
		}
	}`), &reqCov2); err != nil {
		t.Fatalf("unmarshal reqCov2 failed: %v", err)
	}
	planCov2, err := tr.BuildSearchPlan(&reqCov2)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqCov2) failed: %v", err)
	}
	if !strings.Contains(planCov2.AggsSQL, "PERCENTILE_APPROX") || !strings.Contains(planCov2.AggsSQL, "STDDEV_POP") || !strings.Contains(planCov2.AggsSQL, "CHAR_LENGTH") {
		t.Fatalf("expected PERCENTILE_APPROX, STDDEV_POP, and CHAR_LENGTH in AggsSQL, got:\n%s", planCov2.AggsSQL)
	}

	// Additional coverage for sub-agg scalar/array variants, function_score modes & modifiers, multi_match types, simple_query_string, combined_fields, post_filter, and script math functions
	var reqCov3 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"multi_match": {"query": "payment gateway", "fields": ["svc_name^2", "svc_region"], "type": "best_fields", "tie_breaker": 0.3}},
					{"multi_match": {"query": "payment gateway", "fields": ["svc_name", "svc_region"], "type": "most_fields"}},
					{"multi_match": {"query": "payment gateway", "fields": ["svc_name", "svc_region"], "type": "cross_fields", "operator": "and"}},
					{"multi_match": {"query": "payment gateway", "fields": ["svc_name", "svc_region"], "type": "phrase", "slop": 1}},
					{"multi_match": {"query": "payment gateway", "fields": ["svc_name", "svc_region"], "type": "phrase_prefix"}},
					{"multi_match": {"query": "payment gateway", "fields": ["svc_name", "svc_region"], "type": "bool_prefix"}},
					{"combined_fields": {"query": "payment api", "fields": ["svc_name", "svc_region"], "operator": "or"}},
					{"simple_query_string": {"query": "\"payment api\" +gateway -legacy | status:(ok|warn) pay* ~2", "fields": ["svc_name^2", "status"]}},
					{"constant_score": {"filter": {"term": {"status": "ok"}}, "boost": 2.5}},
					{
						"function_score": {
							"query": {"term": {"status": "ok"}},
							"score_mode": "avg",
							"boost_mode": "sum",
							"functions": [
								{"filter": {"term": {"active": true}}, "field_value_factor": {"field": "req_count", "modifier": "log"}},
								{"filter": {"term": {"active": false}}, "field_value_factor": {"field": "req_count", "modifier": "log2p"}},
								{"field_value_factor": {"field": "req_count", "modifier": "ln"}},
								{"field_value_factor": {"field": "req_count", "modifier": "ln1p"}},
								{"field_value_factor": {"field": "req_count", "modifier": "ln2p"}},
								{"field_value_factor": {"field": "req_count", "modifier": "square"}},
								{"field_value_factor": {"field": "req_count", "modifier": "sqrt"}},
								{"field_value_factor": {"field": "req_count", "modifier": "reciprocal"}}
							]
						}
					},
					{
						"function_score": {
							"query": {"term": {"status": "ok"}},
							"score_mode": "first",
							"boost_mode": "max",
							"functions": [
								{"filter": {"term": {"active": true}}, "weight": 3.0},
								{"weight": 1.5}
							]
						}
					},
					{
						"function_score": {
							"query": {"term": {"status": "ok"}},
							"score_mode": "min",
							"boost_mode": "min",
							"functions": [
								{"filter": {"term": {"active": true}}, "weight": 3.0},
								{"filter": {"term": {"active": false}}, "weight": 1.5}
							]
						}
					}
				]
			}
		},
		"post_filter": {"term": {"active": true}},
		"aggs": {
			"by_status": {
				"terms": {"field": "status"},
				"aggs": {
					"avg_arr": {"avg": {"field": "scores", "missing": 0, "script": {"source": "Math.min(Math.max(Math.abs(_value), 1), 100) + Math.floor(Math.ceil(Math.round(Math.sqrt(Math.log(Math.log10(Math.exp(1)))))))"}}},
					"ext_arr": {"extended_stats": {"field": "scores", "missing": 0, "script": {"source": "_value + 1"}}},
					"ext_scalar": {"extended_stats": {"field": "latency", "missing": 0, "script": {"source": "_value + 1"}}},
					"pct_scalar": {"percentiles": {"field": "latency", "percents": [50, 99], "missing": 0, "script": {"source": "_value + 1"}}},
					"pr_scalar": {"percentile_ranks": {"field": "latency", "values": [10, 100], "missing": 0, "script": {"source": "_value + 1"}}},
					"box_arr": {"boxplot": {"field": "scores", "missing": 0, "script": {"source": "_value + 1"}}},
					"box_scalar": {"boxplot": {"field": "latency", "missing": 0, "script": {"source": "_value + 1"}}},
					"rate_cnt": {"rate": {"unit": "second"}},
					"rate_vc_arr": {"rate": {"field": "tags", "mode": "value_count", "unit": "minute"}},
					"rate_vc_scalar": {"rate": {"field": "status", "mode": "value_count", "unit": "minute"}},
					"rate_sum": {"rate": {"field": "req_count", "mode": "sum", "unit": "hour"}},
					"vc_scalar": {"value_count": {"field": "status", "missing": "none", "script": {"source": "doc['status'].value"}}},
					"card_scalar": {"cardinality": {"field": "status", "missing": "none", "script": {"source": "doc['status'].value"}}},
					"dh_scalar": {"date_histogram": {"field": "ts", "fixed_interval": "1h", "missing": "2026-01-01T00:00:00Z", "script": {"source": "_value + 1000"}}},
					"hist_scalar": {"histogram": {"field": "latency", "interval": 10, "missing": 0, "script": {"source": "_value + 5"}}},
					"rng_scalar": {"range": {"field": "latency", "missing": 0, "script": {"source": "_value + 1"}, "ranges": [{"from": 0, "to": 50}, {"from": 50}]}}
				}
			},
			"nested_ev": {
				"nested": {"path": "events"},
				"aggs": {
					"n_avg": {"avg": {"field": "events.ms", "missing": 0, "script": {"source": "doc['events.ms'].value + 1"}}},
					"n_ext": {"extended_stats": {"field": "events.ms", "missing": 0, "script": {"source": "doc['events.ms'].value + 1"}}},
					"n_terms": {
						"terms": {"field": "events.code", "missing": "none", "script": {"source": "doc['events.code'].value"}},
						"aggs": {
							"inner_avg": {"avg": {"field": "events.ms", "missing": 0, "script": {"source": "doc['events.ms'].value + 1"}}},
							"inner_pct": {"percentiles": {"field": "events.ms", "missing": 0, "script": {"source": "doc['events.ms'].value + 1"}}},
							"inner_pr": {"percentile_ranks": {"field": "events.ms", "values": [10], "missing": 0, "script": {"source": "doc['events.ms'].value + 1"}}},
							"inner_box": {"boxplot": {"field": "events.ms", "missing": 0, "script": {"source": "doc['events.ms'].value + 1"}}},
							"inner_dh": {"date_histogram": {"field": "events.ts", "fixed_interval": "1h"}},
							"inner_hist": {"histogram": {"field": "events.ms", "interval": 10}},
							"inner_rev": {"reverse_nested": {}, "aggs": {"root_c": {"value_count": {"field": "status"}}}}
						}
					}
				}
			}
		}
	}`), &reqCov3); err != nil {
		t.Fatalf("unmarshal reqCov3 failed: %v", err)
	}
	planCov3, err := tr.BuildSearchPlan(&reqCov3)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqCov3) failed: %v", err)
	}
	if !strings.Contains(planCov3.HitsSQL, "GREATEST") || !strings.Contains(planCov3.AggsSQL, "LEAST") {
		t.Fatalf("expected GREATEST and LEAST in planCov3 SQL, got:\n%s", planCov3.HitsSQL)
	}
}

func mustJSONString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestRound32NestedDateQueriesMultiValuedIPsLuceneAndStringStats(t *testing.T) {
	rawMapping := `{
		"properties": {
			"status": {"type": "constant_keyword", "value": "active"},
			"tags": {"type": "keyword", "multi_valued": true},
			"created_at": {"type": "date"},
			"items": {
				"type": "nested",
				"properties": {
					"ts": {"type": "date"},
					"ts_nanos": {"type": "date_nanos"},
					"ips": {"type": "ip", "multi_valued": true},
					"name": {
						"type": "text",
						"fields": {
							"keyword": {"type": "keyword", "null_value": "UNKNOWN"}
						}
					}
				}
			}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	idxSchema := schema.CompileIndexSchema("es_compat", "r32_idx", &spec)
	tr := NewTranspiler(idxSchema, TranspilerOptions{})

	// Fix 1 & Fix 4 & Fix 5: Correlated nested date/date_nanos term/terms/range epoch millis, nested .keyword null_value path, and multi-valued nested IP range/CIDR/ip_range
	var req1 esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{
						"nested": {
							"path": "items",
							"query": {
								"bool": {
									"must": [
										{"term": {"items.ts": "2026-01-01T00:00:00Z"}},
										{"terms": {"items.ts_nanos": ["2026-01-01T00:00:00Z"]}},
										{"range": {"items.ts": {"gte": "2026-01-01T00:00:00Z", "lte": "2026-01-02||/d"}}},
										{"term": {"items.name.keyword": "UNKNOWN"}},
										{"term": {"items.ips": "10.0.0.0/8"}},
										{"range": {"items.ips": {"gte": "10.0.0.1", "lte": "10.0.0.254"}}}
									]
								}
							}
						}
					},
					{"match": {"status": "active"}},
					{"match": {"tags": "foo bar"}}
				]
			}
		},
		"aggs": {
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"ip_Sub": {
						"ip_range": {
							"field": "items.ips",
							"ranges": [{"mask": "10.0.0.0/8"}]
						}
					},
					"sstats_sub": {
						"string_stats": {
							"field": "items.name.keyword",
							"missing": "NONE",
							"script": {"source": "doc['items.name.keyword'].value + '_s'"}
						}
					}
				}
			},
			"top_sstats": {
				"string_stats": {
					"field": "status",
					"missing": "EMPTY",
					"script": {"source": "_value + '_top'"}
				}
			}
		}
	}`), &req1); err != nil {
		t.Fatalf("unmarshal req1 failed: %v", err)
	}
	plan1, err := tr.BuildSearchPlan(&req1)
	if err != nil {
		t.Fatalf("BuildSearchPlan(req1) failed: %v", err)
	}
	// Verify Fix 1: nested date term/terms/range uses epoch milliseconds (1767225600000 and 1767398399999)
	if !strings.Contains(plan1.HitsSQL, "1767225600000") || !strings.Contains(plan1.HitsSQL, "1767398399999") {
		t.Fatalf("expected nested date queries to use epoch millis 1767225600000 and 1767398399999, got:\n%s", plan1.HitsSQL)
	}
	// Verify Fix 4: nested .keyword with null_value uses $.name__keyword
	if !strings.Contains(plan1.HitsSQL, "$.name__keyword") {
		t.Fatalf("expected $.name__keyword in HitsSQL for nested .keyword with null_value, got:\n%s", plan1.HitsSQL)
	}
	// Verify Fix 5: multi-valued nested IP uses array_exists with IPV4_STRING_TO_NUM_OR_NULL
	if !strings.Contains(plan1.HitsSQL, "IPV4_STRING_TO_NUM_OR_NULL(_x)") || !strings.Contains(plan1.AggsSQL, "IPV4_STRING_TO_NUM_OR_NULL(_x)") {
		t.Fatalf("expected IPV4_STRING_TO_NUM_OR_NULL(_x) for multi-valued nested IP in HitsSQL and AggsSQL, got:\nHits: %s\nAggs: %s", plan1.HitsSQL, plan1.AggsSQL)
	}
	// Verify Fix 8: string_stats missing & script SQL pushdown
	if !strings.Contains(plan1.AggsSQL, "'EMPTY'") || !strings.Contains(plan1.AggsSQL, "'_top'") {
		t.Fatalf("expected string_stats missing and script in AggsSQL, got:\n%s", plan1.AggsSQL)
	}

	// Fix 6 & Fix 7: Lucene query_string time_zone, phrase_slop, fuzziness, lenient, NOT +foo, and standalone dangling "NOT" / "-"
	var reqLucene esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{
						"query_string": {
							"query": "NOT +legacy created_at:[2026-01-01 TO 2026-01-02]",
							"default_field": "status",
							"time_zone": "+09:00"
						}
					},
					{
						"query_string": {
							"query": "NOT",
							"default_field": "status"
						}
					}
				]
			}
		}
	}`), &reqLucene); err != nil {
		t.Fatalf("unmarshal reqLucene failed: %v", err)
	}
	planLucene, err := tr.BuildSearchPlan(&reqLucene)
	if err != nil {
		t.Fatalf("BuildSearchPlan(reqLucene) failed: %v", err)
	}
	// NOT +legacy must search for 'legacy' (not '+legacy'), and standalone "NOT" must compile to FALSE / 1 = 0
	if strings.Contains(planLucene.HitsSQL, "+legacy") || !strings.Contains(planLucene.HitsSQL, "FALSE") {
		t.Fatalf("unexpected Lucene HitsSQL:\n%s", planLucene.HitsSQL)
	}
}

func TestRound33TranspilerDateFormatsNestedNullsMultiTermsMsmAndLucene(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"slash_date": {"type": "date", "format": "yyyy/MM/dd||epoch_millis"},
			"status": {"type": "keyword", "null_value": "MISSING_STATUS"},
			"title": {"type": "text"},
			"tags": {"type": "keyword", "copy_to": "all_tags"},
			"all_tags": {"type": "keyword"},
			"score_val": {"type": "double"},
			"items": {
				"type": "nested",
				"properties": {
					"code": {"type": "keyword", "null_value": "MISSING_CODE"},
					"name": {
						"type": "text",
						"fields": {
							"keyword": {"type": "keyword", "null_value": "MISSING_KW"}
						}
					},
					"val": {"type": "long"}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r33_tr", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// F1, F3, F4, F5, F6, F7, F8, F10
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"range": {"slash_date": {"gte": "2026/03/15", "lte": "2026/03/16"}}},
					{"term": {"slash_date": "2026/03/15"}},
					{"terms_set": {"status": {"terms": ["MISSING_STATUS", "active"], "minimum_should_match_script": {"source": "Math.min(params.num_terms, 1)"}}}},
					{"match": {"title": {"query": "alpha beta gamma", "operator": "or", "minimum_should_match": "2"}}},
					{"match": {"status": {"query": "open closed", "operator": "and"}}},
					{"match": {"all_tags": "foo bar"}},
					{"match": {"unmapped_dyn": "hello world"}},
					{"match_bool_prefix": {"title^2.5": "quick brown"}},
					{
						"nested": {
							"path": "items",
							"query": {
								"bool": {
									"must": [
										{"exists": {"field": "items.code"}},
										{"exists": {"field": "items.name.keyword"}},
										{"wildcard": {"items.code": "MISS*"}},
										{"prefix": {"items.name.keyword": "MISS"}},
										{"regexp": {"items.code": "MISS.*"}},
										{"script": {"script": "doc['val'].value > 5"}}
									]
								}
							}
						}
					},
					{
						"query_string": {
							"query": "*^3.5",
							"default_field": "status"
						}
					},
					{
						"query_string": {
							"query": "alpha OR beta OR gamma",
							"default_field": "title",
							"default_operator": "AND",
							"minimum_should_match": "2"
						}
					},
					{
						"query_string": {
							"query": "exact~0",
							"default_field": "status",
							"fuzziness": "AUTO"
						}
					}
				]
			}
		},
		"sort": [
			{"slash_date": {"order": "asc", "missing": "2026/01/01"}},
			{"all_tags": {"order": "asc", "mode": "min", "type": "double"}},
			{"items.val": {"order": "desc", "mode": "median", "nested": {"path": "items", "filter": {"term": {"items.code": "MISSING_CODE"}}}}}
		],
		"search_after": ["2026/03/15", 1.5, 10],
		"aggs": {
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"code_terms": {"terms": {"field": "items.code"}},
					"kw_terms": {"terms": {"field": "items.name.keyword"}},
					"code_card": {"cardinality": {"field": "items.code"}},
					"script_sum": {"sum": {"script": "doc['val'].value"}},
					"nested_comp": {
						"composite": {
							"sources": [
								{"c": {"terms": {"field": "code"}}}
							]
						}
					}
				}
			}
		}
	}`), &req); err != nil {
		t.Fatalf("unmarshal req failed: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	// F1: custom date format 2026/03/15 -> 1773532800000 and 2026/03/16 upper bound -> 1773619199999, sort missing 2026/01/01 -> 1767225600000
	if !strings.Contains(plan.HitsSQL, "1773532800000") || !strings.Contains(plan.HitsSQL, "1767225600000") {
		t.Fatalf("expected custom date format millis in HitsSQL, got:\n%s", plan.HitsSQL)
	}
	// F3: match on multi-valued keyword uses array_contains and unmapped dynamic variant uses LIKE
	if !strings.Contains(plan.HitsSQL, "array_contains(`f__all_tags`, 'foo bar')") || !strings.Contains(plan.HitsSQL, "LIKE lower('%hello%')") {
		t.Fatalf("expected array_contains on multi-valued keyword and LIKE on unmapped dynamic field, got:\n%s", plan.HitsSQL)
	}
	// F4 & F5: nested script pushdown and direct nested script-only metric sub-agg
	if !strings.Contains(plan.AggsSQL, "script_sum") || !strings.Contains(plan.AggsSQL, "nested_comp") {
		t.Fatalf("expected script_sum and nested_comp in AggsSQL, got:\n%s", plan.AggsSQL)
	}
	// F6: array sort with explicit type: double casts array elements to DOUBLE
	if !strings.Contains(plan.HitsSQL, "AS DOUBLE") {
		t.Fatalf("expected AS DOUBLE for array sort with explicit type:double, got:\n%s", plan.HitsSQL)
	}
	// F8: *^3.5 boost and exact~0 (no fuzzy expansion despite fuzziness:AUTO)
	if !strings.Contains(plan.HitsSQL, "3.5000") || strings.Contains(plan.HitsSQL, "%e%x%a%c%t%") {
		t.Fatalf("expected *^3.5 boost and exact~0 exact match in HitsSQL, got:\n%s", plan.HitsSQL)
	}
	// F10: nested sort mode median with filter uses array_median(array_map(..., array_filter(...)))
	if !strings.Contains(plan.HitsSQL, "array_median(") || !strings.Contains(plan.HitsSQL, "array_filter(") {
		t.Fatalf("expected array_median with array_filter for filtered nested sort in HitsSQL, got:\n%s", plan.HitsSQL)
	}
}

func TestRound34NestedParentCorrelationTermsCaseInsensitiveLuceneEscapedRangeMustNotNullAndDateSortAfter(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"title": {"type": "text"},
			"status": {"type": "keyword"},
			"tags": {"type": "keyword"},
			"euro_date": {"type": "date", "format": "dd/MM/yyyy"},
			"ts": {"type": "date"},
			"columns": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword"},
					"tags": {
						"type": "nested",
						"properties": {
							"key": {"type": "keyword"}
						}
					}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r34_tr", &spec)
	bTags := sch.Fields["tags"]
	bTags.Kind = schema.StoragePromotedArray
	sch.Fields["tags"] = bTags
	tr := NewTranspiler(sch, TranspilerOptions{})

	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{
						"nested": {
							"path": "columns",
							"query": {
								"bool": {
									"must": [
										{"term": {"columns.name": "email"}},
										{
											"nested": {
												"path": "columns.tags",
												"query": {"term": {"columns.tags.key": "pii"}}
											}
										}
									]
								}
							}
						}
					},
					{"terms": {"status": ["ACTIVE", "Pending"], "case_insensitive": true}},
					{"terms": {"tags": ["PROD", "Staging"], "case_insensitive": true}},
					{"query_string": {"query": "ts:[2024\\-01\\-01T00\\:00\\:00Z TO 2024\\-01\\-02T00\\:00\\:00Z]"}}
				],
				"must_not": [
					{"match": {"title": "deprecated"}}
				]
			}
		},
		"sort": [
			{"euro_date": {"order": "asc", "missing": "01/01/2020"}}
		],
		"search_after": ["15/03/2024"]
	}`), &req); err != nil {
		t.Fatalf("unmarshal req failed: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	// F1: multi-level nested query parent correlation
	if !strings.Contains(plan.HitsSQL, "json_extract_string(_el2, '$._parent_id') = json_extract_string(_el, '$._nested_id')") {
		t.Fatalf("expected multi-level nested parent correlation in HitsSQL, got:\n%s", plan.HitsSQL)
	}
	// F4: case_insensitive terms on scalar and array columns
	if !strings.Contains(plan.HitsSQL, "lower(`f__status`) IN ('active', 'pending')") ||
		!strings.Contains(plan.HitsSQL, "array_exists(_x -> lower(_x) IN ('prod', 'staging'), `f__tags`)") {
		t.Fatalf("expected case_insensitive terms predicates in HitsSQL, got:\n%s", plan.HitsSQL)
	}
	// F7: Lucene escaped range bounds parsed to epoch millis (1704067200000 and 1704153600000)
	if !strings.Contains(plan.HitsSQL, "1704067200000") || !strings.Contains(plan.HitsSQL, "1704153600000") {
		t.Fatalf("expected Lucene escaped ISO range bounds converted to epoch millis, got:\n%s", plan.HitsSQL)
	}
	// F8: must_not fulltext match preserves NULL rows
	if !strings.Contains(plan.HitsSQL, "(`f__title` IS NULL OR NOT (`f__title` MATCH_ANY 'deprecated'))") {
		t.Fatalf("expected null-safe fulltext must_not in HitsSQL, got:\n%s", plan.HitsSQL)
	}
	// F10: custom date format in sort missing (01/01/2020 -> 1577836800000) and search_after (15/03/2024 -> 1710460800000)
	if !strings.Contains(plan.HitsSQL, "1577836800000") || !strings.Contains(plan.HitsSQL, "1710460800000") {
		t.Fatalf("expected custom date format in sort missing and search_after converted to epoch millis, got:\n%s", plan.HitsSQL)
	}
}

func TestRound41TranspilerNestedNotIndexedLuceneMetaSortUnmappedAndPhraseSlop(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"title": {"type": "text"},
			"body": {"type": "text"},
			"items": {
				"type": "nested",
				"properties": {
					"secret": {"type": "keyword", "index": false},
					"sku": {"type": "keyword"}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r41_tr", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// F7: nested subfield with index: false emits FALSE in CompileQuery and returns not-indexed error in BuildSearchPlan
	var nestedReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"nested": {
				"path": "items",
				"query": {"term": {"items.secret": "hidden"}}
			}
		}
	}`), &nestedReq)
	cqNested := tr.CompileQuery(nestedReq.Query, false, nil)
	if strings.Contains(cqNested.WhereSQL, "hidden") || !strings.Contains(cqNested.WhereSQL, "FALSE") {
		t.Fatalf("F7 expected FALSE in CompileQuery for index:false nested subfield, got:\n%s", cqNested.WhereSQL)
	}
	if _, err := tr.BuildSearchPlan(&nestedReq); err == nil || !strings.Contains(err.Error(), "cannot search on field [items.secret] since it is not indexed") {
		t.Fatalf("F7 expected not indexed error from BuildSearchPlan, got %v", err)
	}

	// F8: Lucene query_string with _id and _routing meta fields
	var luceneMetaReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"query": "_id:(doc-1 OR doc-2) AND _routing:shard-a"
			}
		}
	}`), &luceneMetaReq)
	lucenePlan, err := tr.BuildSearchPlan(&luceneMetaReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan lucene meta failed: %v", err)
	}
	if !strings.Contains(lucenePlan.HitsSQL, "`_id` = 'doc-1'") || !strings.Contains(lucenePlan.HitsSQL, "`_routing` = 'shard-a'") {
		t.Fatalf("F8 expected _id and _routing system columns in Lucene SQL, got:\n%s", lucenePlan.HitsSQL)
	}

	// F9: Sort on unmapped field without unmapped_type or ignore_unmapped returns search_phase_execution_exception
	var badSortReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"sort": [{"unmapped_sort_field": {"order": "asc"}}]
	}`), &badSortReq)
	if _, err := tr.BuildSearchPlan(&badSortReq); err == nil || !strings.Contains(err.Error(), "no mapping found for [unmapped_sort_field] in order to sort on") {
		t.Fatalf("F9 expected search_phase_execution_exception for unmapped sort field, got %v", err)
	}

	// F10: multi_match phrase with slop > 0 emits ~slop in MATCH_PHRASE
	var mmPhraseSlop esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"multi_match": {
				"query": "quick fox",
				"fields": ["title^2", "body"],
				"type": "phrase",
				"slop": 2
			}
		}
	}`), &mmPhraseSlop)
	mmPlan, err := tr.BuildSearchPlan(&mmPhraseSlop)
	if err != nil {
		t.Fatalf("BuildSearchPlan multi_match phrase slop failed: %v", err)
	}
	if !strings.Contains(mmPlan.HitsSQL, "MATCH_PHRASE 'quick fox ~2'") {
		t.Fatalf("F10 expected MATCH_PHRASE 'quick fox ~2' in HitsSQL, got:\n%s", mmPlan.HitsSQL)
	}
}

func TestRound42LuceneDocValuesScaledFloatSortSearchAfterTermsSetDedupAndNullValueMatch(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"title": {"type": "text"},
			"status": {"type": "keyword", "null_value": "missing"},
			"tag": {"type": "keyword"},
			"no_dv": {"type": "integer", "doc_values": false},
			"price": {"type": "scaled_float", "scaling_factor": 100}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r42_tr", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// F6: default_operator: OR with +title:hello and status:open AND NOT status:closed preserves Must and MustNot
	var luceneNotReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"default_operator": "OR",
				"query": "+title:hello status:open AND NOT status:closed"
			}
		}
	}`), &luceneNotReq)
	cqNot := tr.CompileQuery(luceneNotReq.Query, false, nil)
	if !strings.Contains(cqNot.WhereSQL, "open") || !strings.Contains(cqNot.WhereSQL, "NOT") || !strings.Contains(cqNot.WhereSQL, "closed") || !strings.Contains(cqNot.WhereSQL, "hello") {
		t.Fatalf("F6 expected status:open, NOT status:closed, and +title:hello in WhereSQL, got:\n%s", cqNot.WhereSQL)
	}

	// F7: doc_values: false validation enforced on script doc['no_dv'], field_value_factor, terms_set.minimum_should_match_field, and aggregations
	dvInvalidReqs := []string{
		`{"query": {"script_score": {"query": {"match_all": {}}, "script": {"source": "doc['no_dv'].value * 2"}}}}`,
		`{"query": {"function_score": {"query": {"match_all": {}}, "field_value_factor": {"field": "no_dv"}}}}`,
		`{"query": {"terms_set": {"tag": {"terms": ["a", "b"], "minimum_should_match_field": "no_dv"}}}}`,
		`{"size": 0, "aggs": {"st": {"significant_terms": {"field": "no_dv"}}}}`,
		`{"size": 0, "aggs": {"tm": {"top_metrics": {"metrics": {"field": "no_dv"}, "sort": [{"tag": "asc"}]}}}}`,
		`{"size": 0, "aggs": {"bp": {"boxplot": {"field": "no_dv"}}}}`,
	}
	for _, rawReq := range dvInvalidReqs {
		var req esast.SearchRequest
		if err := json.Unmarshal([]byte(rawReq), &req); err != nil {
			t.Fatalf("unmarshal %s failed: %v", rawReq, err)
		}
		trDV := NewTranspiler(sch, TranspilerOptions{})
		if _, err := trDV.BuildSearchPlan(&req); err == nil || !strings.Contains(err.Error(), "doc_values") {
			t.Fatalf("F7 expected doc_values error for %s, got %v", rawReq, err)
		}
	}

	// F8 & F9: Sort missing: "10.556" and search_after on scaled_float apply scaling_factor,
	// and compileSearchAfterPredicate skips ignore_unmapped: true unmapped sort fields without emitting WHERE FALSE
	var sortAfterReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"sort": [
			{"unmapped_sort": {"order": "asc", "ignore_unmapped": true}},
			{"price": {"order": "asc", "missing": "10.556"}}
		],
		"search_after": ["ignored_cursor", 12.346]
	}`), &sortAfterReq)
	planSA, err := tr.BuildSearchPlan(&sortAfterReq)
	if err != nil {
		t.Fatalf("F8/F9 BuildSearchPlan failed: %v", err)
	}
	if strings.Contains(planSA.HitsSQL, "WHERE FALSE") || !strings.Contains(planSA.HitsSQL, "10.56") || !strings.Contains(planSA.HitsSQL, "12.35") {
		t.Fatalf("F8/F9 expected scaled missing (10.56) and search_after (12.35) without WHERE FALSE, got:\n%s", planSA.HitsSQL)
	}

	// F10: terms_set deduplicates duplicate terms, and compileMatchField on keyword with null_value includes IS NULL
	var tsDedupReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"terms_set": {
				"tag": {
					"terms": ["go", "go"],
					"minimum_should_match_script": {"source": "2"}
				}
			}
		}
	}`), &tsDedupReq)
	cqTS := tr.CompileQuery(tsDedupReq.Query, false, nil)
	if strings.Count(cqTS.WhereSQL, "CAST(COALESCE") != 1 {
		t.Fatalf("F10 expected deduplicated 'go' term in terms_set WhereSQL, got:\n%s", cqTS.WhereSQL)
	}

	var matchNullValReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"match": {
				"status": "missing"
			}
		}
	}`), &matchNullValReq)
	cqNullMatch := tr.CompileQuery(matchNullValReq.Query, false, nil)
	if !strings.Contains(cqNullMatch.WhereSQL, "= 'missing'") || strings.Contains(cqNullMatch.WhereSQL, "MATCH_ANY") {
		t.Fatalf("F10 expected match on keyword with null_value='missing' to use term equality (= 'missing'), got:\n%s", cqNullMatch.WhereSQL)
	}
}

func TestRound43ScriptSortNestedGeoSortGeohashMissingBucketLuceneAndCollapseArray(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"items": {
				"type": "nested",
				"properties": {
					"active": {"type": "boolean"},
					"price": {"type": "double"}
				}
			},
			"tags": {"type": "keyword", "multi_valued": true, "upgraded_array": true},
			"labels": {"type": "keyword"},
			"loc": {"type": "geo_point"},
			"env": {"type": "keyword"},
			"level": {"type": "keyword"},
			"age": {"type": "integer"},
			"ts": {"type": "date"}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r43_tr", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// F1: _script sort with nested path resolves relative subfield via sortNCtx
	var scriptSortReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"sort": [
			{
				"_script": {
					"type": "number",
					"order": "desc",
					"mode": "max",
					"nested": {
						"path": "items",
						"filter": {"term": {"items.active": true}}
					},
					"script": "doc['price'].value * 2"
				}
			}
		]
	}`), &scriptSortReq)
	planF1, err := tr.BuildSearchPlan(&scriptSortReq)
	if err != nil {
		t.Fatalf("F1 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(planF1.HitsSQL, "`n__items__price`") {
		t.Fatalf("F1 expected relative 'price' in _script nested sort to resolve to `n__items__price`, got:\n%s", planF1.HitsSQL)
	}

	// F2 & F10: terms_set with string minimum_should_match_script and multi-field boost summation
	var tsReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"terms_set": {
				"tags": {
					"terms": ["a", "b", "c"],
					"minimum_should_match_script": "Math.min(params.num_terms, 2)",
					"boost": 2.0
				},
				"labels": {
					"terms": ["x"],
					"minimum_should_match": 1,
					"boost": 3.0
				}
			}
		}
	}`), &tsReq)
	cqF2 := tr.CompileQuery(tsReq.Query, true, nil)
	if !strings.Contains(cqF2.WhereSQL, ">= GREATEST(1, LEAST(3, 2))") || !strings.Contains(cqF2.ScoreSQL, "2.0000") || !strings.Contains(cqF2.ScoreSQL, "3.0000") {
		t.Fatalf("F2/F10 expected threshold >= GREATEST(1, LEAST(3, 2)) and both field boosts (2.0000 and 3.0000) in terms_set compilation, got WhereSQL=%s ScoreSQL=%s", cqF2.WhereSQL, cqF2.ScoreSQL)
	}

	// F8: _geo_distance sort with geohash origin and SPLIT_PART
	var geoSortReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"sort": [
			{
				"_geo_distance": {
					"loc": "u4pruydqqvj",
					"order": "asc",
					"unit": "km"
				}
			}
		]
	}`), &geoSortReq)
	planF8, err := tr.BuildSearchPlan(&geoSortReq)
	if err != nil {
		t.Fatalf("F8 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(planF8.HitsSQL, "SPLIT_PART(") || !strings.Contains(planF8.HitsSQL, "57.64911") {
		t.Fatalf("F8 expected SPLIT_PART and decoded geohash coordinates in _geo_distance sort SQL, got:\n%s", planF8.HitsSQL)
	}

	// F9 & F18: terms agg with missing_bucket:true and rate sub-agg in value_count mode with script
	var aggReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"by_env": {
				"terms": {
					"field": "env",
					"missing_bucket": true
				}
			},
			"by_hour": {
				"date_histogram": {
					"field": "ts",
					"fixed_interval": "1h"
				},
				"aggs": {
					"r": {
						"rate": {
							"mode": "value_count",
							"unit": "1h",
							"script": "doc['age'].value"
						}
					}
				}
			}
		}
	}`), &aggReq)
	planF9, err := tr.BuildSearchPlan(&aggReq)
	if err != nil {
		t.Fatalf("F9/F18 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(planF9.AggsSQL, `'__ES_MISSING_BUCKET__'`) {
		t.Fatalf("F9 expected missing_bucket sentinel in AggsSQL, got:\n%s", planF9.AggsSQL)
	}
	if !strings.Contains(planF9.AggsSQL, "COUNT(`f__age`)") {
		t.Fatalf("F18 expected COUNT(`f__age`) for rate value_count with script, got:\n%s", planF9.AggsSQL)
	}

	// F10: Lucene NOT env:prod OR level:error, unfielded [* TO *], and empty-bounds range query
	qLuceneDisj := parseSimpleLuceneToASTWithFlags("NOT env:prod OR level:error", "", nil, "OR", 0, false, simpleQueryFlags{})
	if qLuceneDisj.Bool == nil || len(qLuceneDisj.Bool.Should) != 2 || len(qLuceneDisj.Bool.MustNot) != 0 {
		t.Fatalf("F10 expected 2 Should disjuncts and 0 top-level MustNot for 'NOT env:prod OR level:error', got %+v", qLuceneDisj.Bool)
	}
	qLuceneRangeAll := parseSimpleLuceneToASTWithFlags("[* TO *]", "age", nil, "OR", 0, false, simpleQueryFlags{})
	if qLuceneRangeAll.Bool == nil || len(qLuceneRangeAll.Bool.Should) != 1 || qLuceneRangeAll.Bool.Should[0].Exists == nil || qLuceneRangeAll.Bool.Should[0].Exists.Field != "age" {
		t.Fatalf("F10 expected ExistsQuery(age) in Bool.Should[0] for [* TO *] with defaultField='age', got %+v", qLuceneRangeAll)
	}
	var emptyRangeReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query": {"range": {"age": {"boost": 2.5}}}}`), &emptyRangeReq)
	cqEmptyRange := tr.CompileQuery(emptyRangeReq.Query, true, nil)
	if !strings.Contains(cqEmptyRange.WhereSQL, "`f__age` IS NOT NULL") || strings.Contains(cqEmptyRange.WhereSQL, "TRUE") {
		t.Fatalf("F10 expected IS NOT NULL for empty-bounds range query, got %s", cqEmptyRange.WhereSQL)
	}

	// F20: collapse on promoted array field uses element_at(f__arr__tags, 1)
	var colReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"collapse": {"field": "tags"}
	}`), &colReq)
	planF20, err := tr.BuildSearchPlan(&colReq)
	if err != nil {
		t.Fatalf("F20 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(planF20.HitsSQL, "PARTITION BY element_at(`f__arr__tags`, 1)") {
		t.Fatalf("F20 expected PARTITION BY element_at(`f__arr__tags`, 1) in collapse SQL, got:\n%s", planF20.HitsSQL)
	}
}

func TestRound44TranspilerNestedMultiFieldLuceneRangeDateZoneDoris4SearchAndMinScore(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"zip": {"type": "keyword"},
			"lc_kw": {"type": "keyword", "normalizer": "lowercase"},
			"title": {"type": "text"},
			"body": {"type": "text"},
			"dt_basic": {"type": "date", "format": "basic_date||epoch_millis"},
			"dt_iso": {"type": "date"},
			"items": {
				"type": "nested",
				"properties": {
					"code": {
						"type": "keyword",
						"fields": {
							"lc": {"type": "keyword", "normalizer": "lowercase"}
						}
					},
					"price": {"type": "double"},
					"qty": {"type": "integer"},
					"active": {"type": "boolean"}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r44_tr", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// F7: Correlated nested query on custom multi-field (items.code.lc) resolves relative companion path $.code__lc and lowercases value
	var nestedMFReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"nested": {
				"path": "items",
				"query": {
					"bool": {
						"must": [
							{"term": {"items.code.lc": "SKU-1"}},
							{"term": {"items.price": 10}}
						]
					}
				}
			}
		}
	}`), &nestedMFReq)
	cqNestedMF := tr.CompileQuery(nestedMFReq.Query, false, nil)
	if !strings.Contains(cqNestedMF.WhereSQL, "json_extract_string(_el, '$.code__lc')") || !strings.Contains(cqNestedMF.WhereSQL, "'sku-1'") {
		t.Fatalf("F7 expected correlated nested custom multi-field items.code.lc to extract $.code__lc with 'sku-1', got:\n%s", cqNestedMF.WhereSQL)
	}

	// F8: Lucene range preserves leading-zero keyword strings, basic_date strings, and lowercases normalizer range bounds
	qZip := parseSimpleLuceneToASTWithFlags("zip:[01000 TO 02000]", "", nil, "OR", 0, false, simpleQueryFlags{})
	cqZip := tr.CompileQuery(&qZip, false, nil)
	if !strings.Contains(cqZip.WhereSQL, ">= '01000'") || !strings.Contains(cqZip.WhereSQL, "<= '02000'") {
		t.Fatalf("F8 expected leading-zero keyword range bounds '01000'..'02000', got:\n%s", cqZip.WhereSQL)
	}
	qBasicDate := parseSimpleLuceneToASTWithFlags("dt_basic:[20260101 TO 20260102]", "", nil, "OR", 0, false, simpleQueryFlags{})
	cqBasicDate := tr.CompileQuery(&qBasicDate, false, nil)
	if !strings.Contains(cqBasicDate.WhereSQL, "1767225600000") {
		t.Fatalf("F8 expected basic_date '20260101' in Lucene range to parse to 1767225600000, got:\n%s", cqBasicDate.WhereSQL)
	}
	var lcRangeReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"range": {
				"lc_kw": {"gte": "ABC", "lte": "XYZ"}
			}
		}
	}`), &lcRangeReq)
	cqLcRange := tr.CompileQuery(lcRangeReq.Query, false, nil)
	if !strings.Contains(cqLcRange.WhereSQL, ">= 'abc'") || !strings.Contains(cqLcRange.WhereSQL, "<= 'xyz'") {
		t.Fatalf("F8 expected lowercase normalizer range bounds 'abc'..'xyz', got:\n%s", cqLcRange.WhereSQL)
	}

	// F9: Date range epoch numeric string not shifted by time_zone when format is set, and 4-digit year string "2026" parsed as 2026-01-01T00:00:00Z
	var dateRangeReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"range": {"dt_basic": {"gte": "1700000000000", "time_zone": "+02:00"}}},
					{"range": {"dt_iso": {"gte": "2026"}}}
				]
			}
		}
	}`), &dateRangeReq)
	cqDateRange := tr.CompileQuery(dateRangeReq.Query, false, nil)
	if !strings.Contains(cqDateRange.WhereSQL, "`f__dt_basic` >= 1700000000000") || !strings.Contains(cqDateRange.WhereSQL, "`f__dt_iso` >= 1767225600000") {
		t.Fatalf("F9 expected unshifted epoch string 1700000000000 and 2026-01-01 epoch 1767225600000, got:\n%s", cqDateRange.WhereSQL)
	}

	// F10: extractNestedPrefilter coerces numeric/boolean string literals on nested subfields
	var nestedCoerceReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"nested": {
				"path": "items",
				"query": {
					"bool": {
						"must": [
							{"term": {"items.price": "42.0"}},
							{"term": {"items.qty": "010"}},
							{"term": {"items.active": "TRUE"}}
						]
					}
				}
			}
		}
	}`), &nestedCoerceReq)
	cqNestedCoerce := tr.CompileQuery(nestedCoerceReq.Query, false, nil)
	if !strings.Contains(cqNestedCoerce.WhereSQL, "array_contains(`n__items__price`, '42')") ||
		!strings.Contains(cqNestedCoerce.WhereSQL, "array_contains(`n__items__qty`, '10')") ||
		!strings.Contains(cqNestedCoerce.WhereSQL, "array_contains(`n__items__active`, 'true')") {
		t.Fatalf("F10 expected canonical coerced prefilters '42', '10', 'true', got:\n%s", cqNestedCoerce.WhereSQL)
	}

	// F11: BoostingQuery negative_boost: 0 emits * 0.0000, and empty function_score applies max_boost + boost_mode
	var f11Req esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"should": [
					{
						"boosting": {
							"positive": {"term": {"zip": "10001"}},
							"negative": {"term": {"lc_kw": "bad"}},
							"negative_boost": 0
						}
					},
					{
						"function_score": {
							"query": {"term": {"zip": {"value": "10001", "boost": 3.0}}},
							"max_boost": 0.5,
							"boost_mode": "replace"
						}
					}
				]
			}
		}
	}`), &f11Req)
	cqF11 := tr.CompileQuery(f11Req.Query, true, nil)
	if !strings.Contains(cqF11.ScoreSQL, "THEN 0.0000 ELSE 1.0 END") || !strings.Contains(cqF11.ScoreSQL, "LEAST(0.5000, 1.0)") {
		t.Fatalf("F11 expected 'THEN 0.0000 ELSE 1.0 END' and 'LEAST(0.5000, 1.0)', got:\n%s", cqF11.ScoreSQL)
	}

	// F12: Doris 4 SEARCH fast-path on multi-field query_string with explicit field prefix and quoted phrase on fielded text column
	trDoris4 := NewTranspiler(sch, TranspilerOptions{UseDoris4SearchFunc: true})
	var qsDoris4Req esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"default_field": "zip",
				"fields": ["title", "body"],
				"query": "title:\"hello world\""
			}
		}
	}`), &qsDoris4Req)
	cqDoris4 := trDoris4.CompileQuery(qsDoris4Req.Query, false, nil)
	if !strings.Contains(cqDoris4.WhereSQL, "SEARCH(") {
		t.Fatalf("F12 expected Doris 4 SEARCH(...) pushdown for fielded phrase on text column, got:\n%s", cqDoris4.WhereSQL)
	}

	// F13: BuildSearchPlan skips SQL min_score pushdown when queryContainsNestedScoring is true
	var minScoreNestedReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"min_score": 1.5,
		"query": {
			"nested": {
				"path": "items",
				"score_mode": "sum",
				"query": {"term": {"items.code": "A"}}
			}
		}
	}`), &minScoreNestedReq)
	planF13, err := tr.BuildSearchPlan(&minScoreNestedReq)
	if err != nil {
		t.Fatalf("F13 BuildSearchPlan failed: %v", err)
	}
	if strings.Contains(planF13.HitsSQL, ">= 1.5000") {
		t.Fatalf("F13 expected min_score SQL pushdown skipped for nested scoring query, got:\n%s", planF13.HitsSQL)
	}
}

func TestRound45TranspilerLuceneDateMathRangeBoostsAndNestedSort(t *testing.T) {
	spec := esast.MappingSpec{
		Dynamic: true,
		Properties: map[string]esast.FieldProperty{
			"title":      {Type: "text"},
			"status":     {Type: "keyword"},
			"age":        {Type: "integer"},
			"created_at": {Type: "date"},
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"price":  {Type: "double"},
					"active": {Type: "boolean"},
				},
			},
		},
	}
	sch := schema.CompileIndexSchema("db", "r45_tr_idx", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// F10: Lucene query_string with date math inside range [2025-01-01T00:00:00Z||+1d/d TO 2025-01-10T00:00:00Z] and field:(...)^boost
	var qsDateMath esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"query": "created_at:[2025-01-01T00:00:00Z||+1d/d TO 2025-01-10T00:00:00Z] AND status:(open closed)^2.5"
			}
		}
	}`), &qsDateMath); err != nil {
		t.Fatalf("F10 unmarshal failed: %v", err)
	}
	cqF10 := tr.CompileQuery(qsDateMath.Query, true, nil)
	// 2025-01-02T00:00:00Z in epoch millis is 1735776000000
	if strings.Contains(cqF10.WhereSQL, "1=0") || !strings.Contains(cqF10.WhereSQL, "1735776000000") {
		t.Fatalf("F10 expected date math resolved in Lucene range query, got WhereSQL=%s", cqF10.WhereSQL)
	}
	if !strings.Contains(cqF10.ScoreSQL, "2.5") {
		t.Fatalf("F10 expected parenthesized group boost 2.5 in ScoreSQL, got ScoreSQL=%s", cqF10.ScoreSQL)
	}

	// F11: Range query on date field with time_zone offset and boost
	var rangeTZ esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"range": {
				"created_at": {
					"gte": "2025-05-01T00:00:00",
					"lt": "2025-05-02T00:00:00",
					"time_zone": "+02:00",
					"boost": 3.5
				}
			}
		}
	}`), &rangeTZ); err != nil {
		t.Fatalf("F11 unmarshal failed: %v", err)
	}
	cqF11 := tr.CompileQuery(rangeTZ.Query, true, nil)
	// 2025-05-01T00:00:00+02:00 is 2025-04-30T22:00:00Z = 1746050400000
	if !strings.Contains(cqF11.WhereSQL, "1746050400000") {
		t.Fatalf("F11 expected time_zone +02:00 shifted to UTC epoch 1746050400000, got WhereSQL=%s", cqF11.WhereSQL)
	}
	if !strings.Contains(cqF11.ScoreSQL, "3.5") {
		t.Fatalf("F11 expected range boost 3.5 in ScoreSQL, got ScoreSQL=%s", cqF11.ScoreSQL)
	}

	// F12: Boost propagation for prefix, wildcard, regexp, fuzzy, terms, exists, ids
	for _, qJSON := range []string{
		`{"query": {"prefix": {"status": {"value": "ac", "boost": 4.25}}}}`,
		`{"query": {"wildcard": {"status": {"value": "ac*", "boost": 4.25}}}}`,
		`{"query": {"regexp": {"status": {"value": "ac.*", "boost": 4.25}}}}`,
		`{"query": {"fuzzy": {"status": {"value": "act", "boost": 4.25}}}}`,
		`{"query": {"terms": {"status": ["a", "b"], "boost": 4.25}}}`,
		`{"query": {"exists": {"field": "status", "boost": 4.25}}}`,
		`{"query": {"ids": {"values": ["1", "2"], "boost": 4.25}}}`,
	} {
		var req esast.SearchRequest
		if err := json.Unmarshal([]byte(qJSON), &req); err != nil {
			t.Fatalf("F12 unmarshal %s failed: %v", qJSON, err)
		}
		cq := tr.CompileQuery(req.Query, true, nil)
		if !strings.Contains(cq.ScoreSQL, "4.25") {
			t.Fatalf("F12 expected ScoreSQL to contain 4.25 for %s, got %s", qJSON, cq.ScoreSQL)
		}
	}

	// F14: Nested sort with filter and max_children compiles without losing nested context
	var nestedSortReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"sort": [
			{
				"items.price": {
					"order": "asc",
					"mode": "min",
					"nested": {
						"path": "items",
						"max_children": 2,
						"filter": {"term": {"items.active": true}}
					}
				}
			}
		]
	}`), &nestedSortReq); err != nil {
		t.Fatalf("F14 unmarshal nested sort failed: %v", err)
	}
	planF14, err := tr.BuildSearchPlan(&nestedSortReq)
	if err != nil {
		t.Fatalf("F14 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(strings.ToUpper(planF14.HitsSQL), "ARRAY_MIN") {
		t.Fatalf("F14 expected ARRAY_MIN in HitsSQL for nested sort mode min, got:\n%s", planF14.HitsSQL)
	}
}

func TestRound46TranspilerGeoDecayLuceneAndTermsAggNormalizer(t *testing.T) {
	spec := esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":      {Type: "text"},
			"status":     {Type: "keyword", Normalizer: "lowercase"},
			"active":     {Type: "boolean"},
			"price":      {Type: "double"},
			"created_at": {Type: "date"},
			"loc":        {Type: "geo_point"},
			"vec":        {Type: "dense_vector", Dims: 3, Similarity: "cosine"},
		},
	}
	sch := schema.CompileIndexSchema("db", "r46_tr_idx", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// F1 & F2: geo_distance and geo_bounding_box transpilation
	var geoReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"geo_distance": {"distance": "10km", "loc": {"lat": 40.7128, "lon": -74.0060}, "boost": 2.5}},
					{"geo_bounding_box": {"loc": {"top_left": {"lat": 41.0, "lon": -75.0}, "bottom_right": {"lat": 40.0, "lon": -73.0}}}}
				]
			}
		}
	}`), &geoReq); err != nil {
		t.Fatalf("F1/F2 unmarshal failed: %v", err)
	}
	cqGeo := tr.CompileQuery(geoReq.Query, true, nil)
	if !strings.Contains(cqGeo.WhereSQL, "ST_Distance_Sphere") || !strings.Contains(cqGeo.WhereSQL, "10000") || !strings.Contains(cqGeo.ScoreSQL, "2.5") {
		t.Fatalf("F1/F2 unexpected geo WhereSQL=%s ScoreSQL=%s", cqGeo.WhereSQL, cqGeo.ScoreSQL)
	}

	// F8 & F9: Lucene field:-term, field:+term, field:!term, and single-clause boosted group (title:foo)^3.5
	var qsReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"query_string": {
				"query": "status:+open status:-closed (title:foo)^3.5"
			}
		}
	}`), &qsReq); err != nil {
		t.Fatalf("F8/F9 unmarshal failed: %v", err)
	}
	cqQS := tr.CompileQuery(qsReq.Query, true, nil)
	if (!strings.Contains(cqQS.WhereSQL, "NOT (") && !strings.Contains(cqQS.WhereSQL, "NOT COALESCE(")) || !strings.Contains(cqQS.ScoreSQL, "3.5") {
		t.Fatalf("F8/F9 expected NOT COALESCE for status:-closed and 3.5 boost for (title:foo)^3.5, got WhereSQL=%s ScoreSQL=%s", cqQS.WhereSQL, cqQS.ScoreSQL)
	}

	// F10: function_score with gauss / exp / linear decay on numeric, date, and geo_point fields
	var decayReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"function_score": {
				"query": {"match_all": {}},
				"functions": [
					{"gauss": {"price": {"origin": 100, "scale": 20, "offset": 5, "decay": 0.5}}},
					{"exp": {"created_at": {"origin": "2025-01-01T00:00:00Z", "scale": "10d", "offset": "1d", "decay": 0.5}}},
					{"linear": {"loc": {"origin": "40.7128,-74.0060", "scale": "5km", "offset": "500m", "decay": 0.5}}}
				],
				"score_mode": "sum",
				"boost_mode": "replace"
			}
		}
	}`), &decayReq); err != nil {
		t.Fatalf("F10 unmarshal failed: %v", err)
	}
	cqDecay := tr.CompileQuery(decayReq.Query, true, nil)
	if !strings.Contains(cqDecay.ScoreSQL, "EXP(") || !strings.Contains(cqDecay.ScoreSQL, "ST_Distance_Sphere") || !strings.Contains(cqDecay.ScoreSQL, "GREATEST(0.0") {
		t.Fatalf("F10 expected EXP, ST_Distance_Sphere, and GREATEST(0.0 in decay ScoreSQL, got %s", cqDecay.ScoreSQL)
	}

	// F11: kNN dimension mismatch returns error via BuildSearchPlan
	var badKNN esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"knn": {"field": "vec", "query_vector": [1.0, 2.0], "k": 5}}`), &badKNN); err != nil {
		t.Fatalf("F11 unmarshal failed: %v", err)
	}
	if _, err := tr.BuildSearchPlan(&badKNN); err == nil || !strings.Contains(err.Error(), "dimension") {
		t.Fatalf("F11 expected dimension mismatch error from BuildSearchPlan, got %v", err)
	}

	// F12: Top-level terms agg on boolean and lowercase-normalizer keyword
	var aggReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"by_active": {"terms": {"field": "active"}},
			"by_status": {"terms": {"field": "status"}}
		}
	}`), &aggReq); err != nil {
		t.Fatalf("F12 unmarshal failed: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&aggReq)
	if err != nil {
		t.Fatalf("F12 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(plan.AggsSQL, "THEN 'true' ELSE 'false'") || !strings.Contains(plan.AggsSQL, "LOWER(") {
		t.Fatalf("F12 expected boolean ('true'/'false') and LOWER() normalization in AggsSQL, got %s", plan.AggsSQL)
	}

	// Additional geo_distance / geo_bounding_box / decay branches (dynamic geo, array geo, dateline crossing, duration units)
	var dynGeoReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {
			"bool": {
				"must": [
					{"geo_distance": {"distance": "5km", "unmapped_loc": "40.7,-74.0"}},
					{"geo_bounding_box": {"unmapped_loc": {"top_left": [170.0, 45.0], "bottom_right": [-170.0, 35.0]}, "boost": 2.0}}
				]
			}
		}
	}`), &dynGeoReq); err != nil {
		t.Fatalf("dynGeoReq unmarshal failed: %v", err)
	}
	cqDynGeo := tr.CompileQuery(dynGeoReq.Query, true, nil)
	if !strings.Contains(cqDynGeo.WhereSQL, "OR") || !strings.Contains(cqDynGeo.ScoreSQL, "2.0") {
		t.Fatalf("expected dateline OR and boost 2.0 in dynGeo query, got where=%s score=%s", cqDynGeo.WhereSQL, cqDynGeo.ScoreSQL)
	}
	for _, u := range []string{"100ms", "30s", "5m", "2h", "3d", "1w", "1M", "1y"} {
		if ms, ok := parseDecayDurationMillis(u); !ok || ms <= 0 {
			t.Fatalf("expected valid decay duration for %s, got %v (%v)", u, ms, ok)
		}
	}
	sfBinding := schema.FieldBinding{ESType: "scaled_float", ScalingFactor: 100}
	for _, v := range []any{float64(1.234), int(5), int64(6), json.Number("7.891"), "9.876"} {
		_ = normalizeScaledFloatValue(sfBinding, v)
	}
	for _, v := range []any{true, false, int(1), int(0), int64(1), float64(1.0), json.Number("1"), "true", "false", "1", "0", "invalid"} {
		_, _ = normalizeBooleanQueryValue(v)
	}
	_ = wildcardToLike(`a\*b\?c\%d\_e\\f\`)
}

func TestRound47TranspilerSpecCompliance(t *testing.T) {
	spec := esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"title":      {Type: "text"},
			"sayt":       {Type: "search_as_you_type"},
			"status":     {Type: "keyword", IgnoreAbove: 5},
			"int_rng":    {Type: "integer_range"},
			"date_rng":   {Type: "date_range"},
			"ip_rng":     {Type: "ip_range"},
			"pagerank":   {Type: "rank_feature"},
			"created_at": {Type: "date"},
			"loc":        {Type: "geo_point"},
			"join_field": {Type: "join"},
			"query":      {Type: "percolator"},
			"items": {
				Type: "nested",
				Properties: map[string]esast.FieldProperty{
					"cat":   {Type: "keyword"},
					"price": {Type: "double"},
				},
			},
		},
	}
	sch := schema.CompileIndexSchema("db", "r47_tr_idx", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{UseDoris4SearchFunc: true})

	// F5: term and range queries (INTERSECTS, CONTAINS, WITHIN) on range fields
	for _, tc := range []struct {
		raw      string
		wantSub1 string
		wantSub2 string
	}{
		{`{"term": {"int_rng": 15}}`, "<= 15", ">= 15"},
		{`{"range": {"int_rng": {"gte": 10, "lte": 20, "relation": "INTERSECTS"}}}`, "<= 20", ">= 10"},
		{`{"range": {"int_rng": {"gte": 10, "lte": 20, "relation": "CONTAINS"}}}`, "<= 10", ">= 20"},
		{`{"range": {"int_rng": {"gte": 10, "lte": 20, "relation": "WITHIN"}}}`, ">= 10", "<= 20"},
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(tc.raw), &q); err != nil {
			t.Fatalf("F5 unmarshal %s failed: %v", tc.raw, err)
		}
		cq := tr.CompileQuery(&q, false, nil)
		if !strings.Contains(cq.WhereSQL, tc.wantSub1) || !strings.Contains(cq.WhereSQL, tc.wantSub2) {
			t.Fatalf("F5 query %s expected %q and %q in WhereSQL=%s", tc.raw, tc.wantSub1, tc.wantSub2, cq.WhereSQL)
		}
	}

	// F6: search_as_you_type subfields resolve to f__sayt
	var saytQ esast.Query
	_ = json.Unmarshal([]byte(`{"match": {"sayt._2gram": "quick fox"}}`), &saytQ)
	cqSayt := tr.CompileQuery(&saytQ, false, nil)
	if !strings.Contains(cqSayt.WhereSQL, "`f__sayt`") {
		t.Fatalf("F6 expected sayt._2gram to query `f__sayt`, got %s", cqSayt.WhereSQL)
	}

	// F10: match_bool_prefix with fuzziness compiles non-last tokens as fuzzy regex and last token as prefix
	var mbpQ esast.Query
	if err := json.Unmarshal([]byte(`{"match_bool_prefix": {"title": {"query": "quikc fo", "fuzziness": "AUTO"}}}`), &mbpQ); err != nil {
		t.Fatalf("F10 unmarshal failed: %v", err)
	}
	cqMBP := tr.CompileQuery(&mbpQ, false, nil)
	if !strings.Contains(cqMBP.WhereSQL, "REGEXP") || !strings.Contains(cqMBP.WhereSQL, "MATCH_PHRASE_PREFIX 'fo'") {
		t.Fatalf("F10 expected fuzzy REGEXP for non-last token and MATCH_PHRASE_PREFIX 'fo' for last token, got %s", cqMBP.WhereSQL)
	}

	// F11: Fuzzy edit distance 2, prefix_length, transpositions:false, and Lucene ~2
	var fzQ esast.Query
	if err := json.Unmarshal([]byte(`{"fuzzy": {"title": {"value": "abcdef", "fuzziness": 2, "prefix_length": 2, "transpositions": false}}}`), &fzQ); err != nil {
		t.Fatalf("F11 unmarshal failed: %v", err)
	}
	cqFZ := tr.CompileQuery(&fzQ, false, nil)
	if !strings.Contains(cqFZ.WhereSQL, "abcd") {
		t.Fatalf("F11 expected distance-2 deletions (e.g. abcd) in fuzzy regex, got %s", cqFZ.WhereSQL)
	}
	var luceneFzQ esast.Query
	_ = json.Unmarshal([]byte(`{"query_string": {"default_field": "title", "query": "abcdef~2"}}`), &luceneFzQ)
	cqLuceneFZ := tr.CompileQuery(&luceneFzQ, false, nil)
	if !strings.Contains(cqLuceneFZ.WhereSQL, "abcd") {
		t.Fatalf("F11 expected Lucene ~2 to generate distance-2 fuzzy regex, got %s", cqLuceneFZ.WhereSQL)
	}

	// F12: Compile all new Query DSL clauses
	f12Queries := []string{
		`{"geo_polygon": {"loc": {"points": [{"lat": 40, "lon": -70}, {"lat": 41, "lon": -71}, {"lat": 39, "lon": -72}]}}}`,
		`{"geo_shape": {"loc": {"shape": {"type": "envelope", "coordinates": [[-75.0, 41.0], [-73.0, 40.0]]}, "relation": "DISJOINT"}}}`,
		`{"wrapper": {"query": "eyJtYXRjaCI6eyJ0aXRsZSI6InF1aWNrIn19"}}`,
		`{"pinned": {"ids": ["doc-1", "doc-2"], "organic": {"match": {"title": "quick"}}}}`,
		`{"more_like_this": {"fields": ["title"], "like": "quick brown fox"}}`,
		`{"intervals": {"title": {"all_of": {"ordered": true, "intervals": [{"match": {"query": "quick"}}, {"prefix": {"prefix": "fo"}}]}}}}`,
		`{"span_near": {"clauses": [{"span_term": {"title": "quick"}}, {"span_or": {"clauses": [{"span_term": {"title": "fox"}}, {"span_not": {"include": {"span_term": {"title": "dog"}}, "exclude": {"span_term": {"title": "lazy"}}}}]}}], "slop": 2}}`,
		`{"span_first": {"match": {"span_term": {"title": "quick"}}, "end": 3}}`,
		`{"span_multi": {"match": {"prefix": {"title": "qu"}}}}`,
		`{"span_containing": {"little": {"span_term": {"title": "fox"}}, "big": {"span_term": {"title": "quick"}}}}`,
		`{"span_within": {"little": {"span_term": {"title": "fox"}}, "big": {"span_term": {"title": "quick"}}}}`,
		`{"field_masking_span": {"query": {"span_term": {"title": "quick"}}, "field": "title"}}`,
		`{"rank_feature": {"field": "pagerank", "saturation": {"pivot": 5}}}`,
		`{"distance_feature": {"field": "created_at", "origin": "2025-01-01T00:00:00Z", "pivot": "7d"}}`,
		`{"distance_feature": {"field": "loc", "origin": {"lat": 40.7, "lon": -74.0}, "pivot": "10km"}}`,
		`{"has_child": {"type": "child", "query": {"match": {"title": "quick"}}, "score_mode": "max"}}`,
		`{"has_parent": {"parent_type": "parent", "query": {"match": {"title": "quick"}}, "score": true}}`,
		`{"parent_id": {"type": "child", "id": "p1"}}`,
		`{"percolate": {"field": "query", "document": {"title": "quick"}}}`,
	}
	for _, raw := range f12Queries {
		var q esast.Query
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("F12 unmarshal %s failed: %v", raw, err)
		}
		cq := tr.CompileQuery(&q, true, nil)
		if cq.WhereSQL == "" || cq.WhereSQL == "FALSE" {
			t.Fatalf("F12 expected non-FALSE WhereSQL for %s, got WhereSQL=%s ScoreSQL=%s", raw, cq.WhereSQL, cq.ScoreSQL)
		}
	}

	// F13: match on keyword uses exact term equality, and IgnoreAbove > 5 returns FALSE
	var kwMatchQ esast.Query
	_ = json.Unmarshal([]byte(`{"match": {"status": "open"}}`), &kwMatchQ)
	cqKwMatch := tr.CompileQuery(&kwMatchQ, false, nil)
	if cqKwMatch.WhereSQL != "`f__status` = 'open'" {
		t.Fatalf("F13 expected exact term match `f__status` = 'open', got %s", cqKwMatch.WhereSQL)
	}
	var kwIgnoreAboveQ esast.Query
	_ = json.Unmarshal([]byte(`{"term": {"status": "too_long_value"}}`), &kwIgnoreAboveQ)
	if cqIA := tr.CompileQuery(&kwIgnoreAboveQ, false, nil); cqIA.WhereSQL != "FALSE" {
		t.Fatalf("F13 expected FALSE for term exceeding ignore_above=5, got %s", cqIA.WhereSQL)
	}

	// F14: simple_query_string mid-word wildcard literal, unquoted ^ literal, and quoted phrase match
	var sqsQ esast.Query
	_ = json.Unmarshal([]byte(`{"simple_query_string": {"fields": ["title"], "query": "\"quick fox\" foo*bar baz*"}}`), &sqsQ)
	cqSQS := tr.CompileQuery(&sqsQ, false, nil)
	if !strings.Contains(cqSQS.WhereSQL, "MATCH_PHRASE") || strings.Contains(cqSQS.WhereSQL, "foo%bar") || !strings.Contains(cqSQS.WhereSQL, "baz%") {
		t.Fatalf("F14 expected MATCH_PHRASE for quoted phrase, no mid-word LIKE foo%%bar, and prefix LIKE baz%%, got %s", cqSQS.WhereSQL)
	}

	// F15: nested -> terms -> top_hits and terms -> nested -> avg sub-aggregations
	var nestedSubAggReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"nested_items": {
				"nested": {"path": "items"},
				"aggs": {
					"by_cat": {
						"terms": {"field": "items.cat"},
						"aggs": {
							"top_items": {"top_hits": {"size": 2, "sort": [{"items.price": "desc"}]}}
						}
					}
				}
			},
			"by_status": {
				"terms": {"field": "status"},
				"aggs": {
					"nested_avg": {
						"nested": {"path": "items"},
						"aggs": {
							"avg_price": {"avg": {"field": "items.price"}}
						}
					}
				}
			}
		}
	}`), &nestedSubAggReq); err != nil {
		t.Fatalf("F15 unmarshal failed: %v", err)
	}
	planF15, err := tr.BuildSearchPlan(&nestedSubAggReq)
	if err != nil {
		t.Fatalf("F15 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(planF15.AggsSQL, "top_items") || !strings.Contains(planF15.AggsSQL, "avg_price") {
		t.Fatalf("F15 expected top_items and avg_price in AggsSQL, got:\n%s", planF15.AggsSQL)
	}

	// Additional coverage for range field types, intervals rules/filters, rank_feature modes, and Lucene boost application
	spec.Properties["flt_rng"] = esast.FieldProperty{Type: "float_range"}
	sch = schema.CompileIndexSchema("db", "r47_tr_idx", &spec)
	tr = NewTranspiler(sch, TranspilerOptions{UseDoris4SearchFunc: true})
	extraQueries := []string{
		`{"range": {"flt_rng": {"gt": 1.5, "lt": 9.5, "relation": "WITHIN"}}}`,
		`{"range": {"date_rng": {"gt": "2025-01-01T00:00:00Z", "lt": "2025-01-02T00:00:00Z"}}}`,
		`{"range": {"ip_rng": {"gt": "10.0.0.1", "lt": "10.0.0.254"}}}`,
		`{"range": {"ip_rng": {"gte": "10.0.0.0/24", "lte": "10.0.0.0/24"}}}`,
		`{"intervals": {"title": {"any_of": {"intervals": [{"wildcard": {"pattern": "qu*"}}, {"fuzzy": {"term": "fox", "fuzziness": 1}}], "filter": {"containing": {"match": {"query": "brown"}}, "not_containing": {"match": {"query": "lazy"}}}}}}}`,
		`{"rank_feature": {"field": "pagerank", "log": {"scaling_factor": 2}, "boost": 1.5}}`,
		`{"rank_feature": {"field": "pagerank", "sigmoid": {"pivot": 2, "exponent": 0.5}}}`,
		`{"rank_feature": {"field": "pagerank", "linear": {}}}`,
		`{"simple_query_string": {"fields": ["title^2", "status"], "query": "\"quick fox\"~2 +bar* -baz~1", "flags": "PHRASE|PREFIX|FUZZY|WHITESPACE|NOT"}}`,
		`{"query_string": {"fields": ["title"], "query": "(title:quick)^2.0 OR status:[a TO z]^1.5 OR title:/qu.*/^2.0 OR title:qu*^1.2 OR title:fox~1^1.3 OR _exists_:title^1.1"}}`,
		`{"has_child": {"type": "c", "query": {"match": {"title": "fox"}}, "score_mode": "max", "boost": 2.0}}`,
		`{"has_parent": {"parent_type": "p", "query": {"match": {"title": "fox"}}, "score": true, "boost": 2.0}}`,
		`{"distance_feature": {"field": "location", "origin": {"lat": 40.7, "lon": -74.0}, "pivot": "10km", "boost": 1.5}}`,
		`{"geo_shape": {"location": {"shape": {"type": "point", "coordinates": [-74.0, 40.7]}}, "boost": 1.5}}`,
		`{"percolate": {"field": "query", "documents": [{"title": "fox"}], "boost": 1.5}}`,
	}
	for _, raw := range extraQueries {
		var q esast.Query
		if err := json.Unmarshal([]byte(raw), &q); err != nil {
			t.Fatalf("extra unmarshal %s failed: %v", raw, err)
		}
		cq := tr.CompileQuery(&q, true, nil)
		if cq.WhereSQL == "" || cq.WhereSQL == "FALSE" {
			t.Fatalf("expected non-FALSE WhereSQL for %s, got %s", raw, cq.WhereSQL)
		}
	}
}

func TestRound48TranspilerSpecCompliance(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"title":      {"type": "text", "analyzer": "stop"},
			"body":       {"type": "text"},
			"age":        {"type": "integer"},
			"location":   {"type": "geo_point"},
			"region":     {"type": "geo_shape"},
			"labels":     {"type": "flattened"},
			"date_rng":   {"type": "date_range"},
			"rng_alias":  {"type": "alias", "path": "date_rng"},
			"items": {
				"type": "nested",
				"properties": {
					"attrs": {"type": "flattened"},
					"win":   {"type": "integer_range"}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("mapping unmarshal failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r48_tr_idx", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{UseDoris4SearchFunc: true})

	// F8: WrapperQuery.Decoded compilation and queryContainsScript / queryContainsNestedScoring traversal
	var wq esast.Query
	if err := json.Unmarshal([]byte(`{"wrapper": {"query": "eyJzY3JpcHQiOnsic2NyaXB0IjoiZG9jWydhZ2UnXS52YWx1ZSA+IDEwIn19"}}`), &wq); err != nil {
		t.Fatalf("F8 wrapper unmarshal failed: %v", err)
	}
	if !queryContainsScript(&wq) {
		t.Fatalf("F8 expected queryContainsScript to traverse Wrapper.Decoded")
	}
	cqWrap := tr.CompileQuery(&wq, true, nil)
	if !strings.Contains(cqWrap.WhereSQL, "f__age") {
		t.Fatalf("F8 expected WrapperQuery.Decoded to compile script condition on f__age, got %s", cqWrap.WhereSQL)
	}

	// F11: MoreLikeThisQuery array/nested doc fields, minimum_should_match, unlike, and include=false _id exclusion
	var mltQ esast.Query
	if err := json.Unmarshal([]byte(`{
		"more_like_this": {
			"fields": ["body", "meta.tags"],
			"like": [
				{"_id": "doc-1", "doc": {"body": ["alpha beta", "gamma"], "meta": {"tags": ["delta"]}}}
			],
			"unlike": ["poison"],
			"minimum_should_match": 2,
			"include": false
		}
	}`), &mltQ); err != nil {
		t.Fatalf("F11 MLT unmarshal failed: %v", err)
	}
	cqMLT := tr.CompileQuery(&mltQ, true, nil)
	if !strings.Contains(cqMLT.WhereSQL, ">= 2") || !strings.Contains(cqMLT.WhereSQL, "NOT COALESCE") || !strings.Contains(cqMLT.WhereSQL, "`_id` NOT IN ('doc-1')") {
		t.Fatalf("F11 expected MSM >= 2, NOT COALESCE for unlike, and _id NOT IN ('doc-1'), got %s", cqMLT.WhereSQL)
	}

	// F12: GeoShapeQuery circle radius, polygon ray-casting, geometrycollection, CONTAINS on geo_point, and _doc geo_shape evaluation
	var gsCircle, gsPoly, gsColl, gsContains, gsDocShape esast.Query
	_ = json.Unmarshal([]byte(`{"geo_shape": {"location": {"shape": {"type": "circle", "coordinates": [-74.0, 40.7], "radius": "5km"}}}}`), &gsCircle)
	_ = json.Unmarshal([]byte(`{"geo_shape": {"location": {"shape": "POLYGON ((-75 40, -73 40, -73 42, -75 42, -75 40))"}}}`), &gsPoly)
	_ = json.Unmarshal([]byte(`{"geo_shape": {"location": {"shape": "GEOMETRYCOLLECTION (POINT (-74 40.7), POINT (-73.9 40.8))"}}}`), &gsColl)
	_ = json.Unmarshal([]byte(`{"geo_shape": {"location": {"shape": "POLYGON ((-75 40, -73 40, -73 42, -75 42, -75 40))", "relation": "CONTAINS"}}}`), &gsContains)
	_ = json.Unmarshal([]byte(`{"geo_shape": {"region": {"shape": {"type": "envelope", "coordinates": [[-75.0, 42.0], [-73.0, 40.0]]}}}}`), &gsDocShape)

	if w := tr.CompileQuery(&gsCircle, false, nil).WhereSQL; !strings.Contains(w, "ST_Distance_Sphere") || !strings.Contains(w, "5000") {
		t.Fatalf("F12 expected circle GeoShapeQuery to emit ST_Distance_Sphere <= 5000, got %s", w)
	}
	if w := tr.CompileQuery(&gsPoly, false, nil).WhereSQL; !strings.Contains(w, "% 2 = 1") {
		t.Fatalf("F12 expected polygon GeoShapeQuery to emit ray-casting parity check, got %s", w)
	}
	if w := tr.CompileQuery(&gsColl, false, nil).WhereSQL; !strings.Contains(w, " OR ") {
		t.Fatalf("F12 expected geometrycollection GeoShapeQuery to combine child shapes with OR, got %s", w)
	}
	if w := tr.CompileQuery(&gsContains, false, nil).WhereSQL; w != "FALSE" {
		t.Fatalf("F12 expected geo_point CONTAINS non-point polygon to be FALSE, got %s", w)
	}
	if w := tr.CompileQuery(&gsDocShape, false, nil).WhereSQL; !strings.Contains(w, "['coordinates']") {
		t.Fatalf("F12 expected _doc geo_shape field to extract coordinates from _doc, got %s", w)
	}

	// F13: lenient: true on single-field query_string / match and zero_terms_query: "all" after stopword filtering
	var qsLenient, matchLenient, matchStopAll, matchStopNone esast.Query
	_ = json.Unmarshal([]byte(`{"query_string": {"default_field": "age", "query": "not_an_int", "lenient": true}}`), &qsLenient)
	_ = json.Unmarshal([]byte(`{"match": {"age": {"query": "not_an_int 42", "lenient": true}}}`), &matchLenient)
	_ = json.Unmarshal([]byte(`{"match": {"body": {"query": "the and of", "zero_terms_query": "all"}}}`), &matchStopAll)
	_ = json.Unmarshal([]byte(`{"match": {"title": {"query": "the and of"}}}`), &matchStopNone)

	if w := tr.CompileQuery(&qsLenient, false, nil).WhereSQL; w != "FALSE" {
		t.Fatalf("F13 expected lenient query_string on integer field with non-int to return FALSE, got %s", w)
	}
	if w := tr.CompileQuery(&matchLenient, false, nil).WhereSQL; !strings.Contains(w, "`f__age` = 42") {
		t.Fatalf("F13 expected lenient multi-token match on integer field to keep valid token 42, got %s", w)
	}
	if w := tr.CompileQuery(&matchStopAll, false, nil).WhereSQL; w != "TRUE" {
		t.Fatalf("F13 expected stopword-only match with zero_terms_query='all' to return TRUE, got %s", w)
	}
	if w := tr.CompileQuery(&matchStopNone, false, nil).WhereSQL; w != "FALSE" {
		t.Fatalf("F13 expected stopword-only match on stop-analyzed field with zero_terms_query='none' to return FALSE, got %s", w)
	}

	// F14: Range field inside nested query, alias to range field, and date_range with explicit Z timezone + time_zone param
	var nestedRangeQ, aliasRangeQ esast.Query
	_ = json.Unmarshal([]byte(`{"nested": {"path": "items", "query": {"range": {"win": {"gte": 2, "lte": 8}}}}}`), &nestedRangeQ)
	_ = json.Unmarshal([]byte(`{"range": {"rng_alias": {"gte": "2026-01-01T00:00:00Z", "lte": "2026-01-01", "time_zone": "+02:00"}}}`), &aliasRangeQ)

	if w := tr.CompileQuery(&nestedRangeQ, false, nil).WhereSQL; !strings.Contains(w, "$.win._gte") || !strings.Contains(w, "n__items") {
		t.Fatalf("F14 expected nested range query to read $.win._gte from correlated nested element, got %s", w)
	}
	wAliasRng := tr.CompileQuery(&aliasRangeQ, false, nil).WhereSQL
	// 2026-01-01T00:00:00Z has explicit Z so it must NOT subtract +02:00 (stays 1767225600000), while "2026-01-01" has no explicit TZ so it rounds up and subtracts +02:00
	if !strings.Contains(wAliasRng, "['date_rng']") || !strings.Contains(wAliasRng, "1767225600000") {
		t.Fatalf("F14 expected alias range query to resolve ['date_rng'] and preserve explicit Z timestamp 1767225600000, got %s", wAliasRng)
	}

	// F15: Flattened root leaf search, sub-key array matching, and nested flattened sub-key matching
	var flatRootQ, flatSubKeyQ, flatNestedQ esast.Query
	_ = json.Unmarshal([]byte(`{"term": {"labels": "prod"}}`), &flatRootQ)
	_ = json.Unmarshal([]byte(`{"term": {"labels.env": "prod"}}`), &flatSubKeyQ)
	_ = json.Unmarshal([]byte(`{"nested": {"path": "items", "query": {"term": {"attrs.color": "red"}}}}`), &flatNestedQ)

	if w := tr.CompileQuery(&flatRootQ, false, nil).WhereSQL; !strings.Contains(w, `LIKE '%"prod"%'`) {
		t.Fatalf("F15 expected root flattened term query to match JSON leaf string, got %s", w)
	}
	if w := tr.CompileQuery(&flatSubKeyQ, false, nil).WhereSQL; !strings.Contains(w, "array_contains(CAST(`_doc`['labels']['env'] AS ARRAY<STRING>), 'prod')") {
		t.Fatalf("F15 expected flattened sub-key term query to check array_contains on _doc['labels']['env'], got %s", w)
	}
	if w := tr.CompileQuery(&flatNestedQ, false, nil).WhereSQL; !strings.Contains(w, "$.attrs.color") || !strings.Contains(w, "ARRAY<STRING>") {
		t.Fatalf("F15 expected nested flattened sub-key query to extract $.attrs.color and check ARRAY<STRING>, got %s", w)
	}
}

func TestRound49TranspilerSpecCompliance(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"title":      {"type": "text", "analyzer": "stop"},
			"body":       {"type": "text"},
			"sayt":       {"type": "search_as_you_type"},
			"u_val":      {"type": "unsigned_long"},
			"ver":        {"type": "version"},
			"labels":     {"type": "flattened"},
			"loc":        {"type": "geo_point"},
			"perc_query": {"type": "percolator"},
			"my_join": {
				"type": "join",
				"relations": {
					"question": ["answer", "comment"]
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("mapping unmarshal failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r49_tr_idx", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{UseDoris4SearchFunc: true})

	// F5-AST: IdsQuery with ResolvedScores emits CASE WHEN `_id` = ... score expression
	idsQ := esast.Query{
		Ids: &esast.IdsQuery{
			Values:         []string{"p1", "p2"},
			ResolvedScores: map[string]float64{"p1": 3.5, "p2": 1.25},
		},
	}
	cqIds := tr.CompileQuery(&idsQ, true, nil)
	if !strings.Contains(cqIds.ScoreSQL, "WHEN `_id` = 'p1' THEN 3.5") {
		t.Fatalf("F5 expected ResolvedScores CASE expression in ScoreSQL, got %s", cqIds.ScoreSQL)
	}

	// F12: MoreLikeThis per-item fields override, min_term_freq, max_query_terms, boost_terms, like_text, ids
	var mltQ esast.Query
	if err := json.Unmarshal([]byte(`{
		"more_like_this": {
			"fields": ["body"],
			"like": [
				{"_id": "1", "fields": ["title"], "doc": {"title": "alpha alpha beta", "body": "ignored_body"}}
			],
			"min_term_freq": 2,
			"max_query_terms": 1,
			"boost_terms": 2.5
		}
	}`), &mltQ); err != nil {
		t.Fatalf("F12 MLT unmarshal failed: %v", err)
	}
	cqMLT := tr.CompileQuery(&mltQ, true, nil)
	if !strings.Contains(cqMLT.WhereSQL, "alpha") || strings.Contains(cqMLT.WhereSQL, "beta") || strings.Contains(cqMLT.WhereSQL, "ignored_body") {
		t.Fatalf("F12 expected MLT to use item fields=['title'] and filter min_term_freq=2 (keeping only 'alpha'), got %s", cqMLT.WhereSQL)
	}

	// F13: unsigned_long in (math.MaxInt64, math.MaxUint64] uses CAST(`_doc`['u_val'] AS LARGEINT) and exact uint64 literal
	var uTermQ, uRangeQ esast.Query
	_ = json.Unmarshal([]byte(`{"term": {"u_val": "18446744073709551615"}}`), &uTermQ)
	_ = json.Unmarshal([]byte(`{"range": {"u_val": {"gt": "9223372036854775807", "lte": "18446744073709551615"}}}`), &uRangeQ)
	if w := tr.CompileQuery(&uTermQ, false, nil).WhereSQL; !strings.Contains(w, "LARGEINT") || !strings.Contains(w, "18446744073709551615") || strings.Contains(w, "-9223372036854775808") {
		t.Fatalf("F13 expected LARGEINT and exact uint64 literal in term query, got %s", w)
	}
	if w := tr.CompileQuery(&uRangeQ, false, nil).WhereSQL; !strings.Contains(w, "LARGEINT") || !strings.Contains(w, "9223372036854775807") || !strings.Contains(w, "18446744073709551615") || strings.Contains(w, "-9223372036854775808") {
		t.Fatalf("F13 expected LARGEINT and no int64 overflow in range query, got %s", w)
	}

	// F14: parent_id does not emit bare OR `_routing` = '...' when join field is mapped; unmapped child type errors unless ignore_unmapped:true; percolate validates field type
	var pidQ, pidBadQ, pidIgnoreQ, percBadQ esast.Query
	_ = json.Unmarshal([]byte(`{"parent_id": {"type": "answer", "id": "q1"}}`), &pidQ)
	_ = json.Unmarshal([]byte(`{"parent_id": {"type": "unknown_child", "id": "q1"}}`), &pidBadQ)
	_ = json.Unmarshal([]byte(`{"parent_id": {"type": "unknown_child", "id": "q1", "ignore_unmapped": true}}`), &pidIgnoreQ)
	_ = json.Unmarshal([]byte(`{"percolate": {"field": "title", "document": {"title": "hello"}}}`), &percBadQ)

	if w := tr.CompileQuery(&pidQ, false, nil).WhereSQL; strings.Contains(w, "_routing") || !strings.Contains(w, "['my_join']") {
		t.Fatalf("F14 expected parent_id with mapped join field to omit bare _routing fallback, got %s", w)
	}
	if _, err := tr.BuildSearchPlan(&esast.SearchRequest{Query: &pidBadQ}); err == nil {
		t.Fatalf("F14 expected error for parent_id with unconfigured child type when ignore_unmapped=false")
	}
	if plan, err := tr.BuildSearchPlan(&esast.SearchRequest{Query: &pidIgnoreQ}); err != nil || !strings.Contains(plan.HitsSQL, "FALSE") {
		t.Fatalf("F14 expected FALSE without error for parent_id with ignore_unmapped=true, got err=%v", err)
	}
	if _, err := tr.BuildSearchPlan(&esast.SearchRequest{Query: &percBadQ}); err == nil {
		t.Fatalf("F14 expected error when percolate targets non-percolator field 'title'")
	}

	// F15: GeoShape polygon with interior hole ring, anti-meridian envelope, and multipoint
	var gsHole, gsAntiEnv, gsMultiPt esast.Query
	_ = json.Unmarshal([]byte(`{"geo_shape": {"loc": {"shape": "POLYGON ((0 0, 10 0, 10 10, 0 10, 0 0), (2 2, 8 2, 8 8, 2 8, 2 2))"}}}`), &gsHole)
	_ = json.Unmarshal([]byte(`{"geo_shape": {"loc": {"shape": {"type": "envelope", "coordinates": [[170.0, 20.0], [-170.0, -20.0]]}}}}`), &gsAntiEnv)
	_ = json.Unmarshal([]byte(`{"geo_shape": {"loc": {"shape": "MULTIPOINT ((-74 40), (-73 41))"}}}`), &gsMultiPt)

	if w := tr.CompileQuery(&gsHole, false, nil).WhereSQL; !strings.Contains(w, "AND NOT ") {
		t.Fatalf("F15 expected polygon with hole to emit AND NOT hole condition, got %s", w)
	}
	if w := tr.CompileQuery(&gsAntiEnv, false, nil).WhereSQL; !strings.Contains(w, ">= 170 OR ") || !strings.Contains(w, "<= -170") {
		t.Fatalf("F15 expected anti-meridian envelope to emit OR across dateline, got %s", w)
	}
	if w := tr.CompileQuery(&gsMultiPt, false, nil).WhereSQL; !strings.Contains(w, " OR ") {
		t.Fatalf("F15 expected multipoint to emit OR of point predicates, got %s", w)
	}

	// F16: Stopword filtering in match_phrase & common terms query compilation
	var mpStopQ, commonQ esast.Query
	_ = json.Unmarshal([]byte(`{"match_phrase": {"title": "quick the fox"}}`), &mpStopQ)
	_ = json.Unmarshal([]byte(`{"common": {"body": {"query": "the quick brown", "low_freq_operator": "and"}}}`), &commonQ)
	if w := tr.CompileQuery(&mpStopQ, false, nil).WhereSQL; !strings.Contains(w, "quick fox") {
		t.Fatalf("F16 expected match_phrase on stop-analyzed field to strip stopword 'the', got %s", w)
	}
	if w := tr.CompileQuery(&commonQ, false, nil).WhereSQL; !strings.Contains(w, "quick") || !strings.Contains(w, "brown") {
		t.Fatalf("F16 expected common query to compile low-freq terms 'quick' and 'brown', got %s", w)
	}

	// F17: search_as_you_type ._index_prefix in match and term queries
	var saytPrefixTerm esast.Query
	_ = json.Unmarshal([]byte(`{"term": {"sayt._index_prefix": "qui"}}`), &saytPrefixTerm)
	if w := tr.CompileQuery(&saytPrefixTerm, false, nil).WhereSQL; !strings.Contains(w, "LIKE") || !strings.Contains(w, "qui%") {
		t.Fatalf("F17 expected term on sayt._index_prefix to compile as prefix LIKE 'qui%%', got %s", w)
	}

	// F18: version semantic version range query (1.2.0 < 1.10.0, 1.0.0-alpha < 1.0.0)
	var verRangeQ esast.Query
	_ = json.Unmarshal([]byte(`{"range": {"ver": {"gt": "1.2.0", "lte": "1.10.0"}}}`), &verRangeQ)
	wVer := tr.CompileQuery(&verRangeQ, false, nil).WhereSQL
	if !strings.Contains(wVer, "LPAD") || !strings.Contains(wVer, "0000000001.0000000002.0000000000~") || !strings.Contains(wVer, "0000000001.0000000010.0000000000~") {
		t.Fatalf("F18 expected semver padded sort key comparison in range query on version field, got %s", wVer)
	}

	// F19: flattened sub-key range query supports both scalar and array values
	var flatRangeQ esast.Query
	_ = json.Unmarshal([]byte(`{"range": {"labels.tier": {"gte": "a", "lte": "m"}}}`), &flatRangeQ)
	if w := tr.CompileQuery(&flatRangeQ, false, nil).WhereSQL; !strings.Contains(w, "array_exists") || !strings.Contains(w, "ARRAY<STRING>") {
		t.Fatalf("F19 expected flattened sub-key range query to include array_exists over ARRAY<STRING>, got %s", w)
	}
}

func TestRound50TranspilerGeoPolygonRangeContainsNestedSpanSortAndTermsSet(t *testing.T) {
	var spec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"title": {"type": "text"},
			"status": {"type": "keyword"},
			"price": {"type": "double"},
			"loc": {"type": "geo_point"},
			"valid_period": {"type": "integer_range"},
			"tags": {"type": "keyword"},
			"req_matches": {"type": "integer"},
			"items": {
				"type": "nested",
				"properties": {
					"name": {"type": "keyword"},
					"window": {"type": "integer_range"}
				}
			}
		}
	}`), &spec)
	idxSchema := schema.CompileIndexSchema("db", "r50_tr", &spec)
	tr := NewTranspiler(idxSchema, TranspilerOptions{UseDoris4SearchFunc: true})

	// F10: BoostingQuery _name in matched_queries
	var boostReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"query": {
			"boosting": {
				"positive": {"term": {"status": "active"}},
				"negative": {"term": {"status": "archived"}},
				"negative_boost": 0.5,
				"_name": "my_boosting"
			}
		}
	}`), &boostReq)
	planF10, err := tr.BuildSearchPlan(&boostReq)
	if err != nil || boostReq.Query.Name != "my_boosting" || !strings.Contains(planF10.HitsSQL, "0.5000") {
		t.Fatalf("F10 expected Query.Name == 'my_boosting' and negative_boost 0.5000 in HitsSQL, got plan=%+v err=%v", planF10, err)
	}

	// F11: compileGeoPolygon combines bounding box AND ray-casting point-in-polygon SQL
	var polyQ esast.Query
	_ = json.Unmarshal([]byte(`{
		"geo_polygon": {
			"loc": {
				"points": [
					{"lat": 40.0, "lon": -70.0},
					{"lat": 45.0, "lon": -70.0},
					{"lat": 45.0, "lon": -80.0}
				]
			}
		}
	}`), &polyQ)
	cqPoly := tr.CompileQuery(&polyQ, false, nil)
	if !strings.Contains(cqPoly.WhereSQL, ">= 40") || !strings.Contains(cqPoly.WhereSQL, "% 2 = 1") {
		t.Fatalf("F11 expected geo_polygon to include both bbox and ray-casting (... %% 2 = 1), got %s", cqPoly.WhereSQL)
	}

	// F12: Range query on range field with single-bound CONTAINS & nested range subfield bounds
	var rangeContainsQ, nestedRangeQ esast.Query
	_ = json.Unmarshal([]byte(`{"range": {"valid_period": {"gte": 10, "relation": "CONTAINS"}}}`), &rangeContainsQ)
	cqRC := tr.CompileQuery(&rangeContainsQ, false, nil)
	if !strings.Contains(cqRC.WhereSQL, "<= 10") || !strings.Contains(cqRC.WhereSQL, ">= 1e99") {
		t.Fatalf("F12 expected single-bound CONTAINS range query to require upper >= 1e99, got %s", cqRC.WhereSQL)
	}
	_ = json.Unmarshal([]byte(`{"nested": {"path": "items", "query": {"range": {"items.window": {"gte": 5, "lte": 15}}}}}`), &nestedRangeQ)
	cqNR := tr.CompileQuery(&nestedRangeQ, false, nil)
	if !strings.Contains(cqNR.WhereSQL, "$.window._gte") || !strings.Contains(cqNR.WhereSQL, "-1e100") || !strings.Contains(cqNR.WhereSQL, "1e100") {
		t.Fatalf("F12 expected nested range subfield query to extract _gte/_lte with -1e100/1e100 fallback, got %s", cqNR.WhereSQL)
	}

	// F13: nested query and nested agg on non-nested or unmapped path returns error unless ignore_unmapped=true
	var badNestedReq, ignoredNestedReq, badNestedAggReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query": {"nested": {"path": "status", "query": {"match_all": {}}}}}`), &badNestedReq)
	if _, err := tr.BuildSearchPlan(&badNestedReq); err == nil || !strings.Contains(err.Error(), "failed to find nested object under path [status]") {
		t.Fatalf("F13 expected nested query error on non-nested path 'status', got %v", err)
	}
	_ = json.Unmarshal([]byte(`{"query": {"nested": {"path": "unmapped_nested", "ignore_unmapped": true, "query": {"match_all": {}}}}}`), &ignoredNestedReq)
	if planIU, err := tr.BuildSearchPlan(&ignoredNestedReq); err != nil || !strings.Contains(planIU.HitsSQL, "FALSE") {
		t.Fatalf("F13 expected ignore_unmapped=true nested query to succeed with FALSE, got plan=%+v err=%v", planIU, err)
	}
	_ = json.Unmarshal([]byte(`{"size": 0, "aggs": {"bad_n": {"nested": {"path": "status"}}}}`), &badNestedAggReq)
	if _, err := tr.BuildSearchPlan(&badNestedAggReq); err == nil || !strings.Contains(err.Error(), "failed to find nested object under path [status]") {
		t.Fatalf("F13 expected nested agg error on non-nested path 'status', got %v", err)
	}

	// F14: SpanNear phrase compilation & SpanNot COALESCE null-safety
	var spanNearQ, spanNotQ esast.Query
	_ = json.Unmarshal([]byte(`{
		"span_near": {
			"clauses": [
				{"span_term": {"title": "quick"}},
				{"span_term": {"title": "fox"}}
			],
			"slop": 2,
			"in_order": true
		}
	}`), &spanNearQ)
	cqSN := tr.CompileQuery(&spanNearQ, false, nil)
	if !strings.Contains(cqSN.WhereSQL, "MATCH_PHRASE") || !strings.Contains(cqSN.WhereSQL, "quick fox ~2") {
		t.Fatalf("F14 expected span_near to compile via MATCH_PHRASE with slop 2, got %s", cqSN.WhereSQL)
	}
	_ = json.Unmarshal([]byte(`{
		"span_not": {
			"include": {"span_term": {"title": "quick"}},
			"exclude": {"span_term": {"title": "lazy"}}
		}
	}`), &spanNotQ)
	cqSNot := tr.CompileQuery(&spanNotQ, false, nil)
	if !strings.Contains(cqSNot.WhereSQL, "NOT COALESCE(") {
		t.Fatalf("F14 expected span_not to use NOT COALESCE(..., FALSE), got %s", cqSNot.WhereSQL)
	}

	// F16: Sort numeric_type cast and _geo_distance validation / missing
	var numTypeSortReq, badGeoSortReq, unmappedGeoSortReq, missingGeoSortReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"sort": [{"price": {"order": "asc", "numeric_type": "long"}}]}`), &numTypeSortReq)
	planNT, err := tr.BuildSearchPlan(&numTypeSortReq)
	if err != nil || !strings.Contains(planNT.HitsSQL, "CAST(`f__price` AS BIGINT)") {
		t.Fatalf("F16 expected numeric_type=long on double field to emit CAST(`f__price` AS BIGINT), got plan=%+v err=%v", planNT, err)
	}
	_ = json.Unmarshal([]byte(`{"sort": [{"_geo_distance": {"status": [0, 0], "order": "asc"}}]}`), &badGeoSortReq)
	if _, err := tr.BuildSearchPlan(&badGeoSortReq); err == nil || !strings.Contains(err.Error(), "failed to find mapper for [status] for geo distance based sort") {
		t.Fatalf("F16 expected error sorting _geo_distance on non-geo_point field, got %v", err)
	}
	_ = json.Unmarshal([]byte(`{"sort": [{"_geo_distance": {"unknown_geo": [0, 0], "order": "asc"}}]}`), &unmappedGeoSortReq)
	if _, err := tr.BuildSearchPlan(&unmappedGeoSortReq); err == nil || !strings.Contains(err.Error(), "no mapping found for [unknown_geo] in order to sort on") {
		t.Fatalf("F16 expected error sorting _geo_distance on unmapped field without ignore_unmapped, got %v", err)
	}
	_ = json.Unmarshal([]byte(`{"sort": [{"_geo_distance": {"loc": [0, 0], "order": "asc", "unit": "km", "missing": "500km"}}]}`), &missingGeoSortReq)
	planMG, err := tr.BuildSearchPlan(&missingGeoSortReq)
	if err != nil || !strings.Contains(planMG.HitsSQL, "COALESCE(") || !strings.Contains(planMG.HitsSQL, ", 500000)") {
		t.Fatalf("F16 expected _geo_distance with missing='500km' to wrap in COALESCE(..., 500000), got plan=%+v err=%v", planMG, err)
	}

	// F19: terms_set minimum_should_match_field clamped to >= 1 via GREATEST(1, ...)
	var tsFieldQ esast.Query
	_ = json.Unmarshal([]byte(`{"terms_set": {"tags": {"terms": ["a", "b"], "minimum_should_match_field": "req_matches"}}}`), &tsFieldQ)
	cqTSF := tr.CompileQuery(&tsFieldQ, false, nil)
	if !strings.Contains(cqTSF.WhereSQL, "GREATEST(1, COALESCE(`f__req_matches`, 1))") {
		t.Fatalf("F19 expected terms_set minimum_should_match_field to be wrapped in GREATEST(1, ...), got %s", cqTSF.WhereSQL)
	}

	// Additional wrapper and distance_feature branch coverage
	b2 := 2.0
	b0 := 0.0
	tr.CompileQuery(&esast.Query{Wrapper: &esast.WrapperQuery{Query: `{"term":{"status":"active"}}`, Boost: &b2}}, true, nil)
	tr.CompileQuery(&esast.Query{Wrapper: &esast.WrapperQuery{Query: `{"term":{"status":"active"}}`, Boost: &b0}}, true, nil)
	tr.CompileQuery(&esast.Query{Wrapper: &esast.WrapperQuery{Query: "!!!bad_base64"}}, true, nil)
	tr.CompileQuery(&esast.Query{DistanceFeature: &esast.DistanceFeatureQuery{Field: "price", Origin: 100, Pivot: "10d", Boost: &b2}}, true, nil)
	tr.CompileQuery(&esast.Query{DistanceFeature: &esast.DistanceFeatureQuery{Field: "price", Origin: "100", Pivot: 50, Boost: &b2}}, true, nil)
	tr.CompileQuery(&esast.Query{DistanceFeature: &esast.DistanceFeatureQuery{Field: "loc", Origin: []any{-70.0, 40.0}, Pivot: "5km", Boost: &b2}}, true, nil)
}

func TestRound51TranspilerF10ToF18(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"title":     {"type": "text"},
			"body":      {"type": "text"},
			"pagerank":  {"type": "rank_feature"},
			"price":     {"type": "double"},
			"scores":    {"type": "double", "multi_valued": true},
			"ts":        {"type": "date"},
			"ts_nanos":  {"type": "date_nanos"},
			"loc":       {"type": "geo_point"},
			"locs":      {"type": "geo_point", "multi_valued": true},
			"perc_q":    {"type": "percolator"},
			"places": {
				"type": "nested",
				"properties": {
					"pin": {"type": "geo_point"}
				}
			}
		}
	}`), &spec); err != nil {
		t.Fatalf("mapping unmarshal failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r51_tr_idx", &spec)
	tr := NewTranspiler(sch, TranspilerOptions{UseDoris4SearchFunc: true})

	// F10: rank_feature on non-rank_feature field returns query_shard_exception
	var badRFReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"rank_feature":{"field":"price"}}}`), &badRFReq)
	if _, err := tr.BuildSearchPlan(&badRFReq); err == nil || !strings.Contains(err.Error(), "query_shard_exception") {
		t.Fatalf("F10 expected query_shard_exception for rank_feature on double field, got %v", err)
	}

	// F11: distance_feature on non-date/geo_point field returns query_shard_exception
	var badDFReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"distance_feature":{"field":"price","origin":100,"pivot":10}}}`), &badDFReq)
	if _, err := tr.BuildSearchPlan(&badDFReq); err == nil || !strings.Contains(err.Error(), "query_shard_exception") {
		t.Fatalf("F11 expected query_shard_exception for distance_feature on double field, got %v", err)
	}
	// F11: distance_feature on date_nanos normalizes nanosecond origin to milliseconds
	var nanosDFQ, arrGeoDFQ, nestedGeoDFQ esast.Query
	_ = json.Unmarshal([]byte(`{"distance_feature":{"field":"ts_nanos","origin":1700000000000000000,"pivot":"1d"}}`), &nanosDFQ)
	cqNanos := tr.CompileQuery(&nanosDFQ, true, nil)
	if !strings.Contains(cqNanos.ScoreSQL, "1.7e+12") || strings.Contains(cqNanos.ScoreSQL, "1.7e+18") {
		t.Fatalf("F11 expected date_nanos numeric origin to normalize to 1.7e+12 ms, got %s", cqNanos.ScoreSQL)
	}
	_ = json.Unmarshal([]byte(`{"distance_feature":{"field":"locs","origin":[-74.0,40.7],"pivot":"1000m"}}`), &arrGeoDFQ)
	cqArrGeo := tr.CompileQuery(&arrGeoDFQ, true, nil)
	if !strings.Contains(cqArrGeo.WhereSQL, "array_size(`f__locs`) > 0") || !strings.Contains(cqArrGeo.ScoreSQL, "array_min") {
		t.Fatalf("F11 expected multi-valued geo_point distance_feature to use array_size > 0 and array_min, got where=%s score=%s", cqArrGeo.WhereSQL, cqArrGeo.ScoreSQL)
	}
	_ = json.Unmarshal([]byte(`{"nested":{"path":"places","query":{"distance_feature":{"field":"places.pin","origin":[-74.0,40.7],"pivot":"1000m"}}}}`), &nestedGeoDFQ)
	cqNestedGeo := tr.CompileQuery(&nestedGeoDFQ, true, nil)
	cqInnerGeo := tr.CompileQuery(&nestedGeoDFQ.Nested.Query, true, &nestedCtx{nestedPath: "places", elemVar: "_el"})
	if !strings.Contains(cqNestedGeo.WhereSQL, "$.pin") || !strings.Contains(cqInnerGeo.ScoreSQL, "ST_Distance_Sphere") {
		t.Fatalf("F11 expected nested geo_point distance_feature to extract $.pin and compute ST_Distance_Sphere, got where=%s score=%s", cqNestedGeo.WhereSQL, cqInnerGeo.ScoreSQL)
	}

	// F12: function_score decay wraps NULL check (ELSE 0.0) and honors multi_value_mode on array numeric field
	var decayQ esast.Query
	_ = json.Unmarshal([]byte(`{
		"function_score": {
			"gauss": {
				"scores": {"origin": 50, "scale": 10},
				"multi_value_mode": "max"
			}
		}
	}`), &decayQ)
	cqDecay := tr.CompileQuery(&decayQ, true, nil)
	if !strings.Contains(cqDecay.ScoreSQL, "CASE WHEN") || !strings.Contains(cqDecay.ScoreSQL, "ELSE 0.0 END") || !strings.Contains(cqDecay.ScoreSQL, "array_max(array_map(") {
		t.Fatalf("F12 expected decay function to wrap in CASE WHEN ... ELSE 0.0 END and use array_max(array_map(...)), got %s", cqDecay.ScoreSQL)
	}

	// F13: intervals use_field override and ordered match with max_gaps -> MATCH_PHRASE ~slop
	var ivQ esast.Query
	_ = json.Unmarshal([]byte(`{
		"intervals": {
			"title": {
				"all_of": {
					"intervals": [
						{"match": {"query": "quick fox", "ordered": true, "max_gaps": 3, "use_field": "body"}},
						{"prefix": {"prefix": "br", "use_field": "body"}}
					]
				}
			}
		}
	}`), &ivQ)
	cqIv := tr.CompileQuery(&ivQ, false, nil)
	if !strings.Contains(cqIv.WhereSQL, "`f__body`") || !strings.Contains(cqIv.WhereSQL, "MATCH_PHRASE") || !strings.Contains(cqIv.WhereSQL, "~3") {
		t.Fatalf("F13 expected intervals use_field='body' and ordered max_gaps=3 to emit `f__body` MATCH_PHRASE ... ~3, got %s", cqIv.WhereSQL)
	}

	// F14: percolate on unmapped field returns query_shard_exception unless ignore_unmapped=true
	var badPercReq, ignoredPercReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"percolate":{"field":"unmapped_perc","document":{"title":"fox"}}}}`), &badPercReq)
	if _, err := tr.BuildSearchPlan(&badPercReq); err == nil || !strings.Contains(err.Error(), "query_shard_exception") {
		t.Fatalf("F14 expected query_shard_exception for unmapped percolate field, got %v", err)
	}
	_ = json.Unmarshal([]byte(`{"query":{"percolate":{"field":"unmapped_perc","ignore_unmapped":true,"document":{"title":"fox"}}}}`), &ignoredPercReq)
	if planP, err := tr.BuildSearchPlan(&ignoredPercReq); err != nil || !strings.Contains(planP.HitsSQL, "FALSE") {
		t.Fatalf("F14 expected ignore_unmapped=true percolate to succeed with FALSE, got plan=%+v err=%v", planP, err)
	}

	// F17: histogram hard_bounds emits SQL WHERE filter in both top-level and sub-aggregation
	var histBoundsReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"price_hist": {
				"histogram": {
					"field": "price",
					"interval": 10,
					"hard_bounds": {"min": 20, "max": 100}
				},
				"aggs": {
					"sub_hist": {
						"histogram": {
							"field": "price",
							"interval": 5,
							"hard_bounds": {"min": 30, "max": 80}
						}
					}
				}
			}
		}
	}`), &histBoundsReq)
	planHB, err := tr.BuildSearchPlan(&histBoundsReq)
	if err != nil {
		t.Fatalf("F17 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(planHB.AggsSQL, ">= 20") || !strings.Contains(planHB.AggsSQL, "<= 100") {
		t.Fatalf("F17 expected top-level histogram SQL to filter hard_bounds [20, 100], got %s", planHB.AggsSQL)
	}
	if !strings.Contains(planHB.AggsSQL, ">= 30") || !strings.Contains(planHB.AggsSQL, "<= 80") {
		t.Fatalf("F17 expected sub-histogram SQL to filter hard_bounds [30, 80], got %s", planHB.AggsSQL)
	}

	// F18: composite agg with missing_bucket: true and after: {"k": null} routes through postProcessCompositeAgg (LIMIT 10000)
	var compAfterNullReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"comp": {
				"composite": {
					"size": 2,
					"after": {"t": null},
					"sources": [
						{"t": {"terms": {"field": "title", "missing_bucket": true}}}
					]
				}
			}
		}
	}`), &compAfterNullReq)
	planComp, err := tr.BuildSearchPlan(&compAfterNullReq)
	if err != nil || !strings.Contains(planComp.AggsSQL, "LIMIT 10000") {
		t.Fatalf("F18 expected composite agg with after={t:null} and missing_bucket=true to use post-process LIMIT 10000, got sql=%s err=%v", planComp.AggsSQL, err)
	}
}

func TestRound52TranspilerF12AndF15ToF19(t *testing.T) {
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"title":   {"type": "text"},
			"body":    {"type": "text"},
			"ts":      {"type": "date"},
			"labels":  {"type": "flattened"},
			"no_dv":   {"type": "keyword", "doc_values": false},
			"no_dv_n": {"type": "double", "doc_values": false}
		}
	}`), &spec); err != nil {
		t.Fatalf("mapping unmarshal failed: %v", err)
	}
	sch := schema.CompileIndexSchema("db", "r52_tr_idx", &spec)
	// Add a dynamic variant constant_keyword field (> MaxPromotedColumns simulation)
	constVal := "production"
	sch.Fields["dyn_env"] = schema.FieldBinding{
		ESFieldPath:    "dyn_env",
		ESType:         "constant_keyword",
		Kind:           schema.StorageDynamicVariant,
		DorisType:      schema.DorisString,
		ConstantValue:  constVal,
		SourceJSONPath: []string{"dyn_env"},
	}
	tr := NewTranspiler(sch, TranspilerOptions{UseDoris4SearchFunc: true})

	// F12: date_histogram hard_bounds emits SQL WHERE filter in both top-level and sub-aggregation
	var dhBoundsReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"dh": {
				"date_histogram": {
					"field": "ts",
					"calendar_interval": "1d",
					"hard_bounds": {"min": "2025-01-01T00:00:00Z", "max": "2025-01-10T00:00:00Z"}
				},
				"aggs": {
					"sub_dh": {
						"date_histogram": {
							"field": "ts",
							"calendar_interval": "1h",
							"hard_bounds": {"min": 1735689600000, "max": 1735776000000}
						}
					}
				}
			}
		}
	}`), &dhBoundsReq)
	planDH, err := tr.BuildSearchPlan(&dhBoundsReq)
	if err != nil {
		t.Fatalf("F12 BuildSearchPlan failed: %v", err)
	}
	if !strings.Contains(planDH.AggsSQL, ">= 1735689600000") || !strings.Contains(planDH.AggsSQL, "<= 1736467200000") || !strings.Contains(planDH.AggsSQL, "<= 1735776000000") {
		t.Fatalf("F12 expected date_histogram hard_bounds SQL filter, got %s", planDH.AggsSQL)
	}

	// F15: dynamic variant constant_keyword coalesces with ConstantValue
	var ckQ esast.Query
	_ = json.Unmarshal([]byte(`{"term":{"dyn_env":"production"}}`), &ckQ)
	if w := tr.CompileQuery(&ckQ, false, nil).WhereSQL; !strings.Contains(w, "COALESCE(") || !strings.Contains(w, "'production'") {
		t.Fatalf("F15 expected COALESCE with 'production' for dynamic variant constant_keyword, got %s", w)
	}

	// F16: exists on flattened field excludes '{}' and 'null'
	var flatExistsQ esast.Query
	_ = json.Unmarshal([]byte(`{"exists":{"field":"labels"}}`), &flatExistsQ)
	if w := tr.CompileQuery(&flatExistsQ, false, nil).WhereSQL; !strings.Contains(w, "!= '{}'") || !strings.Contains(w, "!= 'null'") {
		t.Fatalf("F16 expected flattened exists predicate to exclude '{}' and 'null', got %s", w)
	}

	// F18: doc_values: false rejected across all 13 aggregation types
	for _, dvAgg := range []string{
		`{"size":0,"aggs":{"a":{"multi_terms":{"terms":[{"field":"no_dv"},{"field":"title"}]}}}}`,
		`{"size":0,"aggs":{"a":{"rare_terms":{"field":"no_dv"}}}}`,
		`{"size":0,"aggs":{"a":{"auto_date_histogram":{"field":"no_dv"}}}}`,
		`{"size":0,"aggs":{"a":{"variable_width_histogram":{"field":"no_dv_n","buckets":5}}}}`,
		`{"size":0,"aggs":{"a":{"median_absolute_deviation":{"field":"no_dv_n"}}}}`,
		`{"size":0,"aggs":{"a":{"weighted_avg":{"value":{"field":"no_dv_n"},"weight":{"field":"ts"}}}}}`,
		`{"size":0,"aggs":{"a":{"matrix_stats":{"fields":["no_dv_n","ts"]}}}}`,
		`{"size":0,"aggs":{"a":{"t_test":{"a":{"field":"no_dv_n"},"b":{"field":"ts"}}}}}`,
		`{"size":0,"aggs":{"a":{"geo_bounds":{"field":"no_dv"}}}}`,
		`{"size":0,"aggs":{"a":{"geo_centroid":{"field":"no_dv"}}}}`,
		`{"size":0,"aggs":{"a":{"geo_distance":{"field":"no_dv","origin":"0,0","ranges":[{"to":100}]}}}}`,
		`{"size":0,"aggs":{"a":{"geohash_grid":{"field":"no_dv"}}}}`,
		`{"size":0,"aggs":{"a":{"geotile_grid":{"field":"no_dv"}}}}`,
	} {
		var sr esast.SearchRequest
		if err := json.Unmarshal([]byte(dvAgg), &sr); err != nil {
			t.Fatalf("F18 unmarshal %s failed: %v", dvAgg, err)
		}
		if _, err := tr.BuildSearchPlan(&sr); err == nil {
			t.Fatalf("F18 expected doc_values=false error for %s", dvAgg)
		}
	}

	// F18: compileBool with FALSE conjunct + MustNot returns FALSE; single-token match/query_string/simple_query_string with minimum_should_match: 2 returns FALSE
	for _, falseQ := range []string{
		`{"bool":{"must":[{"match_none":{}}],"must_not":[{"term":{"title":"fox"}}]}}`,
		`{"match":{"title*":{"query":"fox","minimum_should_match":2}}}`,
		`{"query_string":{"default_field":"title","query":"fox","minimum_should_match":2}}`,
		`{"simple_query_string":{"fields":["title"],"query":"fox","minimum_should_match":2}}`,
	} {
		var q esast.Query
		if err := json.Unmarshal([]byte(falseQ), &q); err != nil {
			t.Fatalf("F18 unmarshal %s failed: %v", falseQ, err)
		}
		if w := tr.CompileQuery(&q, false, nil).WhereSQL; w != "FALSE" {
			t.Fatalf("F18 expected WhereSQL == FALSE for %s, got %s", falseQ, w)
		}
	}

	// F19: field^boost in query_string exists (title^3:*), default_field: "title^3", and nil-schema Transpiler
	var qsExistsBoost, qsDefFieldBoost esast.Query
	_ = json.Unmarshal([]byte(`{"query_string":{"query":"title^3:*"}}`), &qsExistsBoost)
	cqEB := tr.CompileQuery(&qsExistsBoost, true, nil)
	if strings.Contains(cqEB.WhereSQL, "^3") || !strings.Contains(cqEB.ScoreSQL, "3.0000") {
		t.Fatalf("F19 expected query_string 'title^3:*' to strip ^3 from column and apply 3.0000 boost, got where=%s score=%s", cqEB.WhereSQL, cqEB.ScoreSQL)
	}
	_ = json.Unmarshal([]byte(`{"query_string":{"default_field":"title^3","query":"fox"}}`), &qsDefFieldBoost)
	cqDFB := tr.CompileQuery(&qsDefFieldBoost, true, nil)
	if !strings.Contains(cqDFB.ScoreSQL, "3.0000") {
		t.Fatalf("F19 expected query_string default_field='title^3' to apply 3.0000 boost, got score=%s", cqDFB.ScoreSQL)
	}
	nilTr := NewTranspiler(nil, TranspilerOptions{})
	var mmBoost esast.Query
	_ = json.Unmarshal([]byte(`{"multi_match":{"query":"fox","fields":["title^4"]}}`), &mmBoost)
	cqNilMM := nilTr.CompileQuery(&mmBoost, true, nil)
	if strings.Contains(cqNilMM.WhereSQL, "^4") || !strings.Contains(cqNilMM.ScoreSQL, "4.0000") {
		t.Fatalf("F19 expected nil-schema multi_match fields=['title^4'] to strip ^4 and apply 4.0000 boost, got where=%s score=%s", cqNilMM.WhereSQL, cqNilMM.ScoreSQL)
	}
}
