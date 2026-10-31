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
	if !strings.Contains(plan3.HitsSQL, "json_extract_string(_el, '$.ts') >= '2026-10-01T00:00:00Z'") {
		t.Fatalf("expected nested date range to preserve ISO string in json_extract_string, got:\n%s", plan3.HitsSQL)
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
	if !strings.Contains(planNR.HitsSQL, "'2026-10-01T00:00:00Z'") || !strings.Contains(planNR.HitsSQL, "'2026-10-02T23:59:59Z'") {
		t.Fatalf("expected nested date gt/lte ISO bounds to remain ISO strings, got:\n%s", planNR.HitsSQL)
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
