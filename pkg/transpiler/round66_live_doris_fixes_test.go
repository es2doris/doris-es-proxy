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
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// assertNoNestedLambdaSQLR66 verifies SQL never embeds one higher-order lambda (`->`)
// inside the argument list of an outer lambda, which triggers Doris 4.1.3 BE crashes.
func assertNoNestedLambdaSQLR66(t *testing.T, sqlStr string) {
	t.Helper()
	var lambdaDepths []int
	depth := 0
	inSingle := false
	inBacktick := false
	for i := 0; i < len(sqlStr); i++ {
		ch := sqlStr[i]
		if inSingle {
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
			depth--
			for len(lambdaDepths) > 0 && depth < lambdaDepths[len(lambdaDepths)-1] {
				lambdaDepths = lambdaDepths[:len(lambdaDepths)-1]
			}
		case ',':
			for len(lambdaDepths) > 0 && depth <= lambdaDepths[len(lambdaDepths)-1] {
				lambdaDepths = lambdaDepths[:len(lambdaDepths)-1]
			}
		case '-':
			if i+1 < len(sqlStr) && sqlStr[i+1] == '>' {
				if len(lambdaDepths) > 0 {
					t.Fatalf("detected nested lambda `->` inside active lambda in SQL:\n%s", sqlStr)
				}
				lambdaDepths = append(lambdaDepths, depth)
				i++
			}
		}
	}
}

func TestRound66FlatNestedKNNAndCosineL2GuardSQL(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"publish_date": {"type": "keyword"},
			"paragraphs": {
				"type": "nested",
				"properties": {
					"category": {"type": "keyword"},
					"text": {"type": "text"},
					"vector": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "cosine"}
				}
			}
		}
	}`)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// 1. Nested kNN with child post-filter (must stay flat: sibling array_map, no nested ->).
	reqNestedFilter := mustUnmarshalSearchReqR62(t, `{
		"knn": {
			"field": "paragraphs.vector",
			"query_vector": [1.0, 2.0],
			"k": 10,
			"num_candidates": 10,
			"filter": {
				"term": {"paragraphs.category": "tech"}
			}
		}
	}`)
	planNested, err := tr.BuildSearchPlan(reqNestedFilter)
	if err != nil {
		t.Fatalf("BuildSearchPlan nested kNN filter failed: %v", err)
	}
	assertNoNestedLambdaSQLR66(t, planNested.HitsSQL)
	if !strings.Contains(planNested.HitsSQL, "ARRAY_MAX(array_map(_nel ->") {
		t.Fatalf("expected flat sibling ARRAY_MAX(array_map(_nel -> ...)) in SQL, got:\n%s", planNested.HitsSQL)
	}
	if strings.Contains(planNested.HitsSQL, "INNER_PRODUCT(") {
		t.Fatalf("unexpected INNER_PRODUCT in cosine nested kNN SQL:\n%s", planNested.HitsSQL)
	}
	if !strings.Contains(planNested.HitsSQL, "L2_DISTANCE(") {
		t.Fatalf("expected L2_DISTANCE zero-norm guard in cosine nested kNN SQL:\n%s", planNested.HitsSQL)
	}

	// 2. Root must_not exists filter (100_knn_nested_search.yml Section 7 shape).
	reqRootFilter := mustUnmarshalSearchReqR62(t, `{
		"knn": {
			"field": "paragraphs.vector",
			"query_vector": [1.0, 2.0],
			"k": 10,
			"num_candidates": 10,
			"filter": {
				"bool": {
					"must_not": {
						"exists": {"field": "publish_date"}
					}
				}
			}
		}
	}`)
	planRoot, err := tr.BuildSearchPlan(reqRootFilter)
	if err != nil {
		t.Fatalf("BuildSearchPlan root filter nested kNN failed: %v", err)
	}
	assertNoNestedLambdaSQLR66(t, planRoot.HitsSQL)
	if strings.Contains(planRoot.HitsSQL, "INNER_PRODUCT(") {
		t.Fatalf("unexpected INNER_PRODUCT in cosine nested kNN SQL:\n%s", planRoot.HitsSQL)
	}
	if !strings.Contains(planRoot.HitsSQL, "`f__publish_date` IS NULL") {
		t.Fatalf("expected direct `f__publish_date` IS NULL negation in SQL:\n%s", planRoot.HitsSQL)
	}
	if strings.Contains(planRoot.HitsSQL, "NOT COALESCE(`f__publish_date` IS NOT NULL, FALSE)") {
		t.Fatalf("unexpected NOT COALESCE wrapper around single-column IS NOT NULL in SQL:\n%s", planRoot.HitsSQL)
	}
}

func TestRound66FlatMultiLevelNestedAndSortSQL(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"src_uid": {"type": "keyword", "copy_to": "uids"},
			"uids": {"type": "unsigned_long"},
			"items": {
				"type": "nested",
				"properties": {
					"active": {"type": "boolean"},
					"price": {"type": "double"},
					"loc": {"type": "geo_point"},
					"sub": {
						"type": "nested",
						"properties": {
							"tag": {"type": "keyword"},
							"leaf": {
								"type": "nested",
								"properties": {
									"code": {"type": "keyword"}
								}
							}
						}
					}
				}
			}
		}
	}`)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// (a) 3-level nested bool (must/should/must_not) + 1-level numeric nested sort.
	reqNested := mustUnmarshalSearchReqR62(t, `{
		"query": {
			"nested": {
				"path": "items",
				"query": {
					"bool": {
						"must": [
							{"term": {"items.active": true}},
							{"nested": {
								"path": "items.sub",
								"query": {
									"bool": {
										"should": [
											{"term": {"items.sub.tag": "a"}},
											{"nested": {
												"path": "items.sub.leaf",
												"query": {"term": {"items.sub.leaf.code": "x"}}
											}}
										],
										"must_not": [
											{"term": {"items.sub.tag": "blocked"}}
										]
									}
								}
							}}
						]
					}
				}
			}
		},
		"sort": [
			{
				"items.price": {
					"order": "desc",
					"nested": {
						"path": "items",
						"filter": {"term": {"items.active": true}}
					}
				}
			}
		]
	}`)
	plan, err := tr.BuildSearchPlan(reqNested)
	if err != nil {
		t.Fatalf("BuildSearchPlan 3-level nested + sort failed: %v", err)
	}
	assertNoNestedLambdaSQLR66(t, plan.HitsSQL)
	for _, want := range []string{
		"ARRAY_INTERSECT(", "ARRAY_UNION(", "ARRAY_EXCEPT(", "ARRAY_REMOVE(", "SPLIT_BY_STRING(",
		`TRY_CAST(json_extract_string(_el, '$."price"') AS DOUBLE)`, "TRY_CAST(NULL AS DOUBLE)",
	} {
		if !strings.Contains(plan.HitsSQL, want) {
			t.Fatalf("expected flat nested operator %q in SQL:\n%s", want, plan.HitsSQL)
		}
	}

	// (b) 2-level nested sort with ancestor filter uses ARRAY_REPEAT + __DORIS_NESTED_SKIP__.
	reqAncSort := mustUnmarshalSearchReqR62(t, `{
		"sort": [
			{
				"items.sub.tag": {
					"order": "asc",
					"mode": "min",
					"nested": {
						"path": "items",
						"filter": {"term": {"items.active": true}},
						"nested": {
							"path": "items.sub",
							"filter": {"term": {"items.sub.tag": "a"}}
						}
					}
				}
			}
		]
	}`)
	planAnc, err := tr.BuildSearchPlan(reqAncSort)
	if err != nil {
		t.Fatalf("BuildSearchPlan 2-level nested ancestor sort failed: %v", err)
	}
	assertNoNestedLambdaSQLR66(t, planAnc.HitsSQL)
	for _, want := range []string{"ARRAY_REPEAT(", "__DORIS_NESTED_SKIP__", "ARRAY_REMOVE("} {
		if !strings.Contains(planAnc.HitsSQL, want) {
			t.Fatalf("expected %q in 2-level nested sort SQL:\n%s", want, planAnc.HitsSQL)
		}
	}

	// (c) Nested geo_distance sort with nested.filter emits a single flat lambda.
	reqGeoSort := mustUnmarshalSearchReqR62(t, `{
		"sort": [
			{
				"_geo_distance": {
					"items.loc": [0.0, 0.0],
					"order": "asc",
					"nested": {
						"path": "items",
						"filter": {"term": {"items.active": true}}
					}
				}
			}
		]
	}`)
	planGeo, err := tr.BuildSearchPlan(reqGeoSort)
	if err != nil {
		t.Fatalf("BuildSearchPlan nested geo_distance sort failed: %v", err)
	}
	assertNoNestedLambdaSQLR66(t, planGeo.HitsSQL)
	for _, want := range []string{"ST_Distance_Sphere(", "CAST(NULL AS DOUBLE)"} {
		if !strings.Contains(planGeo.HitsSQL, want) {
			t.Fatalf("expected %q in nested geo sort SQL:\n%s", want, planGeo.HitsSQL)
		}
	}

	// (d) Regexp on unsigned_long array casts elements inline without wrapping array_map.
	ulSch := mustCompileTestSchemaR62(t, `{"properties": {"uids": {"type": "unsigned_long"}}}`)
	ulBinding := ulSch.Fields["uids"]
	ulBinding.Kind = schema.StoragePromotedArray
	ulBinding.DorisType = schema.DorisLargeIntArray
	ulBinding.IsMultiValued = true
	ulSch.Fields["uids"] = ulBinding
	reqRegexp := mustUnmarshalSearchReqR62(t, `{"query": {"regexp": {"uids": "12.*"}}}`)
	planRegexp, err := NewTranspiler(ulSch, TranspilerOptions{}).BuildSearchPlan(reqRegexp)
	if err != nil {
		t.Fatalf("BuildSearchPlan unsigned_long regexp failed: %v", err)
	}
	assertNoNestedLambdaSQLR66(t, planRegexp.HitsSQL)
	if !strings.Contains(planRegexp.HitsSQL, "CAST(_x AS STRING)") {
		t.Fatalf("expected inline CAST(_x AS STRING) in unsigned_long array regexp SQL:\n%s", planRegexp.HitsSQL)
	}
}

func TestRound66AppendLateralViewToFromClause(t *testing.T) {
	lv := "LATERAL VIEW EXPLODE(`f__tags`) `_lv` AS `_tag`"
	if got, want := appendLateralViewToFromClause("`db`.`tbl`", lv), "`db`.`tbl` "+lv; got != want {
		t.Fatalf("plain table:\ngot:  %s\nwant: %s", got, want)
	}
	joined := "`dedup_cte` INNER JOIN `db`.`tbl` ON `dedup_cte`.`_id` = `db`.`tbl`.`_id`"
	gotJoined := appendLateralViewToFromClause(joined, lv)
	lvPos := strings.Index(gotJoined, "LATERAL VIEW")
	joinPos := strings.Index(gotJoined, "INNER JOIN")
	if lvPos < 0 || joinPos < 0 || lvPos > joinPos {
		t.Fatalf("expected LATERAL VIEW before INNER JOIN, got: %s", gotJoined)
	}

	leftJoined := "`base_matched` `_bm` LEFT JOIN `db`.`other` ON `_bm`.`_id` = `db`.`other`.`_id`"
	gotLeft := appendLateralViewToFromClause(leftJoined, lv)
	if strings.Index(gotLeft, "LATERAL VIEW") > strings.Index(gotLeft, "LEFT JOIN") {
		t.Fatalf("expected LATERAL VIEW before LEFT JOIN, got: %s", gotLeft)
	}
}

func TestRound66EmptyNestedAggAvgWeightCastAndTSIDSort(t *testing.T) {
	// 1. Unmapped empty-index nested agg should still emit AggsSQL when DorisTable != "".
	emptySch := schema.CompileIndexSchema("es_db", "empty_tbl", &esast.MappingSpec{})
	trEmpty := NewTranspiler(emptySch, TranspilerOptions{})
	reqNestedAgg := mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"n": {
				"nested": {"path": "comments"},
				"aggs": {"c": {"terms": {"field": "comments.author"}}}
			}
		}
	}`)
	planEmpty, err := trEmpty.BuildSearchPlan(reqNestedAgg)
	if err != nil {
		t.Fatalf("empty index nested agg BuildSearchPlan failed: %v", err)
	}
	if strings.TrimSpace(planEmpty.AggsSQL) == "" {
		t.Fatalf("expected non-empty AggsSQL for unmapped empty index nested agg")
	}

	// 2. AVG weight branches + BIGINT SUM/AVG DOUBLE cast + aggregate_metric_double.
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"grp": {"type": "keyword"},
			"qty": {"type": "long"},
			"amd": {"type": "aggregate_metric_double", "metrics": ["min", "max", "sum", "value_count", "avg"], "default_metric": "avg"}
		}
	}`)
	tr := NewTranspiler(sch, TranspilerOptions{})
	reqAgg := mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"top_sum": {"sum": {"field": "qty"}},
			"top_avg": {"avg": {"field": "qty"}},
			"top_amd_avg": {"avg": {"field": "amd"}},
			"by_grp": {
				"terms": {"field": "grp"},
				"aggs": {
					"sub_avg": {"avg": {"field": "qty"}},
					"sub_amd_avg": {"avg": {"field": "amd"}}
				}
			}
		}
	}`)
	planAgg, err := tr.BuildSearchPlan(reqAgg)
	if err != nil {
		t.Fatalf("avg/cast agg BuildSearchPlan failed: %v", err)
	}
	for _, want := range []string{
		"'_avg_weight'",
		"'by_grp.sub_avg._avg_weight'",
		"'by_grp.sub_amd_avg._avg_weight'",
		"SUM(CAST(`f__qty` AS DOUBLE))",
	} {
		if !strings.Contains(planAgg.AggsSQL, want) {
			t.Fatalf("expected %q in AggsSQL, got:\n%s", want, planAgg.AggsSQL)
		}
	}

	// 3. _tsid ORDER BY and search_after encoding.
	tsdbSch := mustCompileTestSchemaR62(t, `{"properties": {"@timestamp": {"type": "date"}, "val": {"type": "double"}}}`)
	tsdbSch.IndexMode = "time_series"
	trTSDB := NewTranspiler(tsdbSch, TranspilerOptions{})
	reqTSID := mustUnmarshalSearchReqR62(t, `{
		"sort": [{"_tsid": "asc"}, {"_doc": "asc"}],
		"search_after": ["AbC-9_", "42"]
	}`)
	planTSID, err := trTSDB.BuildSearchPlan(reqTSID)
	if err != nil {
		t.Fatalf("BuildSearchPlan _tsid sort+search_after failed: %v", err)
	}
	if !strings.Contains(planTSID.HitsSQL, "TRANSLATE(`__tsid`") {
		t.Fatalf("expected TRANSLATE(`__tsid`...) sort/search_after SQL, got:\n%s", planTSID.HitsSQL)
	}
	wantTranslated := TranslateBase64URLOrderR63("AbC-9_")
	if !strings.Contains(planTSID.HitsSQL, wantTranslated) {
		t.Fatalf("expected translated _tsid search_after literal %q in SQL:\n%s", wantTranslated, planTSID.HitsSQL)
	}
}

func TestRound66LowerJSONTypeAndIsNullNegationSQL(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"publish_date": {"type": "keyword"},
			"tags": {"type": "keyword", "multi_valued": true},
			"ml.tokens": {"type": "sparse_vector"}
		}
	}`)
	tr := NewTranspiler(sch, TranspilerOptions{})

	// 1. sparse_vector / dynamic VARIANT exists uses LOWER(JSON_TYPE(...)) against Doris 4.1.3 lowercase 'null'/'array'.
	existsSparse := mustUnmarshalSearchReqR62(t, `{"query": {"exists": {"field": "ml.tokens"}}}`)
	planSparse, err := tr.BuildSearchPlan(existsSparse)
	if err != nil {
		t.Fatalf("BuildSearchPlan sparse exists failed: %v", err)
	}
	if !strings.Contains(planSparse.HitsSQL, "LOWER(JSON_TYPE(TRY_CAST(`_source` AS JSON),") ||
		!strings.Contains(planSparse.HitsSQL, "!= 'null'") ||
		!strings.Contains(planSparse.HitsSQL, "!= 'array'") {
		t.Fatalf("expected LOWER(JSON_TYPE(...)) != 'null'/'array' in sparse_vector exists SQL:\n%s", planSparse.HitsSQL)
	}

	// 2. Runtime JSON array and geo_point array checks use LOWER(JSON_TYPE(...)) = 'array'.
	if arrExpr := sqlRuntimeSourceJSONTypeIsArrayExpr("dyn.arr"); !strings.Contains(arrExpr, "LOWER(JSON_TYPE(TRY_CAST(`_source` AS JSON),") || !strings.Contains(arrExpr, "= 'array'") {
		t.Fatalf("expected LOWER(JSON_TYPE(...)) = 'array' in sqlRuntimeSourceJSONTypeIsArrayExpr, got: %s", arrExpr)
	}
	_, lonExpr := buildSingleGeoScalarLatLonSQLR63("`f__loc`")
	if !strings.Contains(lonExpr, "LOWER(JSON_TYPE(TRY_CAST(`f__loc` AS JSON), '$')) = 'array'") {
		t.Fatalf("expected LOWER(JSON_TYPE(...)) = 'array' in geo_point lon expr, got: %s", lonExpr)
	}

	// 3. Single-column IS NOT NULL must_not simplifies to IS NULL; compound must_not keeps NOT COALESCE(..., FALSE).
	if got := negateBoolClauseSQLR66("(`f__publish_date` IS NOT NULL)"); got != "`f__publish_date` IS NULL" {
		t.Fatalf("expected `f__publish_date` IS NULL, got %q", got)
	}
	if got := negateBoolClauseSQLR66("`f__a` IS NOT NULL AND `f__b` IS NOT NULL"); got != "NOT COALESCE(`f__a` IS NOT NULL AND `f__b` IS NOT NULL, FALSE)" {
		t.Fatalf("compound IS NOT NULL must keep NOT COALESCE, got %q", got)
	}
	reqTermNeg := mustUnmarshalSearchReqR62(t, `{"query": {"bool": {"must_not": [{"term": {"publish_date": "1"}}, {"exists": {"field": "tags"}}, {"exists": {"field": "ml.tokens"}}]}}}`)
	planNeg, err := tr.BuildSearchPlan(reqTermNeg)
	if err != nil {
		t.Fatalf("BuildSearchPlan compound must_not failed: %v", err)
	}
	if !strings.Contains(planNeg.HitsSQL, "NOT COALESCE(") {
		t.Fatalf("expected NOT COALESCE for non-scalar must_not clauses, got:\n%s", planNeg.HitsSQL)
	}
}
