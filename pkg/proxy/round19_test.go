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

package proxy

import (
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound19_ScriptSortSearchAfterAndMissing(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r19_script_sort", `{
		"mappings": {
			"properties": {
				"price": {"type": "double"},
				"qty":   {"type": "long"}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r19_script_sort/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"price":10,"qty":2}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"price":20,"qty":2}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"price":10,"qty":2}`+"\n"+
			`{"index":{"_id":"4"}}`+"\n"+`{"qty":2}`+"\n")

	// 1. Verify SQL-pushed _script sort with custom numeric "missing" COALESCE and search_after tie-breaking
	idxSchema := srv.getOrCompileReadOnlySchema(t.Context(), "r19_script_sort")
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	var req esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"size": 2,
		"sort": [
			{"_script": {"type": "number", "script": "doc['price'].value * 2", "order": "asc", "missing": -5}},
			{"_id": "asc"}
		],
		"search_after": [20, "1"]
	}`), &req)
	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("unexpected BuildSearchPlan error: %v", err)
	}
	if !strings.Contains(plan.HitsSQL, "COALESCE(") || !strings.Contains(plan.HitsSQL, "-5") {
		t.Fatalf("expected custom _script sort missing COALESCE(..., -5) in HitsSQL, got: %s", plan.HitsSQL)
	}
	if !strings.Contains(plan.HitsSQL, "> 20") || !strings.Contains(plan.HitsSQL, "`_id` > '1'") {
		t.Fatalf("expected search_after predicate on SQL-pushable _script sort + _id tie-breaker in HitsSQL, got: %s", plan.HitsSQL)
	}

	// 2. Verify end-to-end runtime/proxy _script sort with custom numeric "missing" and search_after pagination
	page1 := doJSON(t, srv, http.MethodPost, "/r19_script_sort/_search", `{
		"size": 2,
		"sort": [
			{"_script": {"script": "doc['price'].value * 2", "order": "asc", "missing": -5}},
			{"_id": "asc"}
		]
	}`)
	hits1 := page1["hits"].(map[string]any)["hits"].([]any)
	if len(hits1) != 2 {
		t.Fatalf("expected 2 hits on page 1, got %d", len(hits1))
	}
	// Doc "4" is missing price -> missing = -5 (numeric), Doc "1" has 20
	if hits1[0].(map[string]any)["_id"] != "4" || hits1[1].(map[string]any)["_id"] != "1" {
		t.Fatalf("expected page 1 IDs [4, 1], got [%v, %v]", hits1[0].(map[string]any)["_id"], hits1[1].(map[string]any)["_id"])
	}
	sortVals0 := hits1[0].(map[string]any)["sort"].([]any)
	if sortVals0[0] != float64(-5) {
		t.Fatalf("expected numeric sort missing value -5, got %T (%v)", sortVals0[0], sortVals0[0])
	}

	page2 := doJSON(t, srv, http.MethodPost, "/r19_script_sort/_search", `{
		"size": 2,
		"sort": [
			{"_script": {"script": "doc['price'].value * 2", "order": "asc", "missing": -5}},
			{"_id": "asc"}
		],
		"search_after": [20, "1"]
	}`)
	hits2 := page2["hits"].(map[string]any)["hits"].([]any)
	if len(hits2) != 2 {
		t.Fatalf("expected 2 hits on page 2 after [20, '1'], got %d", len(hits2))
	}
	if hits2[0].(map[string]any)["_id"] != "3" || hits2[1].(map[string]any)["_id"] != "2" {
		t.Fatalf("expected page 2 IDs [3, 2], got [%v, %v]", hits2[0].(map[string]any)["_id"], hits2[1].(map[string]any)["_id"])
	}
}

func TestRound19_Doris4SearchMultiFieldAndLuceneWildcards(t *testing.T) {
	var mSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"title_en": {"type": "text"},
			"title_fr": {"type": "text"},
			"views":    {"type": "long"}
		}
	}`), &mSpec)
	idxSchema := schema.CompileIndexSchema("es_compat", "r19_lucene", &mSpec)

	trDoris4 := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{
		UseDoris4SearchFunc: true,
	})

	// 1. Pure disjunction across multiple text fields CAN emit SEARCH(...) OR SEARCH(...)
	var qOr esast.Query
	_ = json.Unmarshal([]byte(`{
		"query_string": {
			"query": "alpha beta",
			"fields": ["title_*"],
			"default_operator": "OR"
		}
	}`), &qOr)
	resOr := trDoris4.CompileQuery(&qOr, true, nil)
	if !strings.Contains(resOr.WhereSQL, "SEARCH(") {
		t.Fatalf("expected pure OR multi-field query to emit Doris 4 SEARCH(), got: %s", resOr.WhereSQL)
	}

	// 2. Multi-field conjunction (`default_operator: "AND"` or `+a -b`) MUST NOT emit per-column `SEARCH(q, col, 'AND') OR ...`
	var qAnd esast.Query
	_ = json.Unmarshal([]byte(`{
		"query_string": {
			"query": "alpha beta",
			"fields": ["title_*"],
			"default_operator": "AND"
		}
	}`), &qAnd)
	resAnd := trDoris4.CompileQuery(&qAnd, true, nil)
	if strings.Contains(resAnd.WhereSQL, "SEARCH('alpha beta'") {
		t.Fatalf("expected cross-field AND query to expand per-term disjunctions instead of single-column SEARCH('alpha beta', col, 'AND'), got: %s", resAnd.WhereSQL)
	}
	if !strings.Contains(resAnd.WhereSQL, "f__title_en") || !strings.Contains(resAnd.WhereSQL, "f__title_fr") {
		t.Fatalf("expected both title_en and title_fr in cross-field AND SQL, got: %s", resAnd.WhereSQL)
	}

	// 3. Explicit wildcard `fields: ["nonexistent_*"]` matching 0 fields must compile to FALSE (0 hits), not _all_text
	var qNoMatch esast.Query
	_ = json.Unmarshal([]byte(`{
		"query_string": {
			"query": "alpha",
			"fields": ["nonexistent_*"]
		}
	}`), &qNoMatch)
	resNoMatch := trDoris4.CompileQuery(&qNoMatch, true, nil)
	if !strings.Contains(resNoMatch.WhereSQL, "FALSE") || strings.Contains(resNoMatch.WhereSQL, "_all_text") {
		t.Fatalf("expected unmatched wildcard fields to compile to FALSE, got: %s", resNoMatch.WhereSQL)
	}

	// 4. Wildcard `default_field: "title_*^3"` expands to all matching fields with boost
	var qWildDF esast.Query
	_ = json.Unmarshal([]byte(`{
		"query_string": {
			"query": "alpha*",
			"default_field": "title_*^3"
		}
	}`), &qWildDF)
	resWildDF := trDoris4.CompileQuery(&qWildDF, true, nil)
	if !strings.Contains(resWildDF.WhereSQL, "f__title_en") || !strings.Contains(resWildDF.WhereSQL, "f__title_fr") {
		t.Fatalf("expected wildcard default_field to expand to both title_en and title_fr, got: %s", resWildDF.WhereSQL)
	}
	if !strings.Contains(resWildDF.ScoreSQL, "3") {
		t.Fatalf("expected per-field boost ^3 in ScoreSQL for wildcard atom, got: %s", resWildDF.ScoreSQL)
	}

	// 5. Per-field `^boost` on range and regexp atoms in `fields`
	var qRangeBoost esast.Query
	_ = json.Unmarshal([]byte(`{
		"query_string": {
			"query": "[10 TO 100]",
			"fields": ["views^4"]
		}
	}`), &qRangeBoost)
	resRangeBoost := trDoris4.CompileQuery(&qRangeBoost, true, nil)
	if !strings.Contains(resRangeBoost.ScoreSQL, "4") {
		t.Fatalf("expected per-field boost ^4 on range atom ScoreSQL, got: %s", resRangeBoost.ScoreSQL)
	}
}

func TestRound19_DateRangeTimeZoneEpochSecondAndCompositeScript(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r19_dates", `{
		"mappings": {
			"properties": {
				"ts":       {"type": "date"},
				"ts_nanos": {"type": "date_nanos"},
				"category": {"type": "keyword"},
				"amount":   {"type": "double"}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r19_dates/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"ts":"2026-01-01T01:00:00Z","ts_nanos":1767229200000000000,"category":"a","amount":10}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"ts":"2026-01-01T10:00:00Z","ts_nanos":1767261600000000000,"category":"b","amount":25}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"category":"a","amount":5}`+"\n")

	// 1. date_range with format: "epoch_second" and ISO missing
	resEpochSec := doJSON(t, srv, http.MethodPost, "/r19_dates/_search", `{
		"size": 0,
		"aggs": {
			"by_sec": {
				"date_range": {
					"field": "ts",
					"format": "epoch_second",
					"missing": "2026-01-01T00:30:00Z",
					"ranges": [
						{"key": "early", "from": 1767225600, "to": 1767240000},
						{"key": "late",  "from": 1767240000}
					]
				}
			},
			"by_tz": {
				"date_range": {
					"field": "ts",
					"time_zone": "+02:00",
					"ranges": [
						{"key": "local_morning", "from": "2026-01-01T00:00:00", "to": "2026-01-01T06:00:00"},
						{"key": "local_day",     "from": "2026-01-01T06:00:00"}
					]
				}
			}
		}
	}`)
	aggs := resEpochSec["aggregations"].(map[string]any)
	secBuckets := aggs["by_sec"].(map[string]any)["buckets"].([]any)
	// doc 1 (01:00Z = 1767229200s) + doc 3 (missing -> 00:30Z = 1767227400s) -> 2 in "early", doc 2 (10:00Z) -> 1 in "late"
	if secBuckets[0].(map[string]any)["doc_count"] != float64(2) || secBuckets[1].(map[string]any)["doc_count"] != float64(1) {
		t.Fatalf("expected by_sec counts [2, 1], got %+v", secBuckets)
	}
	tzBuckets := aggs["by_tz"].(map[string]any)["buckets"].([]any)
	// 2026-01-01T06:00:00+02:00 is 04:00:00Z -> doc 1 (01:00Z) is in local_morning (1), doc 2 (10:00Z) is in local_day (1)
	if tzBuckets[0].(map[string]any)["doc_count"] != float64(1) || tzBuckets[1].(map[string]any)["doc_count"] != float64(1) {
		t.Fatalf("expected by_tz counts [1, 1], got %+v", tzBuckets)
	}

	// 2. composite aggregation with script source and date_nanos date_histogram source
	resComp := doJSON(t, srv, http.MethodPost, "/r19_dates/_search", `{
		"size": 0,
		"aggs": {
			"comp_agg": {
				"composite": {
					"sources": [
						{"cat_upper": {"terms": {"script": "doc['category'].value.toUpperCase()"}}},
						{"day_nanos": {"date_histogram": {"field": "ts_nanos", "calendar_interval": "1d"}}}
					]
				}
			}
		}
	}`)
	compBuckets := resComp["aggregations"].(map[string]any)["comp_agg"].(map[string]any)["buckets"].([]any)
	if len(compBuckets) != 2 {
		t.Fatalf("expected 2 composite buckets (docs with both category and ts_nanos), got %+v", compBuckets)
	}
	firstKey := compBuckets[0].(map[string]any)["key"].(map[string]any)
	if firstKey["cat_upper"] != "A" {
		t.Fatalf("expected first composite bucket cat_upper='A', got %+v", firstKey)
	}
}

func TestRound19_PolymorphicStringScriptPushdown(t *testing.T) {
	srv, _ := newTestServer()

	doJSON(t, srv, http.MethodPut, "/r19_str_script", `{
		"mappings": {
			"properties": {
				"env":     {"type": "keyword"},
				"service": {"type": "keyword"}
			}
		}
	}`)
	doJSON(t, srv, http.MethodPost, "/r19_str_script/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"env":"  PROD  ","service":"Auth"}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"env":"prod","service":"AUTH"}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"env":"Staging","service":"Billing"}`+"\n")

	// Verify SQL pushdown of .trim(), .toLowerCase(), .toUpperCase(), and string '+' concatenation
	res := doJSON(t, srv, http.MethodPost, "/r19_str_script/_search?doris_explain=true", `{
		"size": 0,
		"aggs": {
			"norm_env": {
				"terms": {
					"script": "doc['env'].value.trim().toLowerCase()"
				}
			},
			"concat_key": {
				"cardinality": {
					"script": "doc['env'].value.trim().toUpperCase() + ':' + doc['service'].value.toLowerCase()"
				}
			}
		}
	}`)
	explain := res["_doris_explain"].(map[string]any)
	aggsSQL, _ := explain["aggs_sql"].(string)
	if !strings.Contains(aggsSQL, "LOWER(CAST(TRIM(") || !strings.Contains(aggsSQL, "CONCAT(") {
		t.Fatalf("expected LOWER(CAST(TRIM(...))) and CONCAT(...) in AggsSQL, got: %s", aggsSQL)
	}

	aggs := res["aggregations"].(map[string]any)
	envBuckets := aggs["norm_env"].(map[string]any)["buckets"].([]any)
	if len(envBuckets) != 2 || envBuckets[0].(map[string]any)["key"] != "prod" || envBuckets[0].(map[string]any)["doc_count"] != float64(2) {
		t.Fatalf("expected normalized 'prod' bucket with doc_count=2, got %+v", envBuckets)
	}
	if aggs["concat_key"].(map[string]any)["value"] != float64(2) {
		t.Fatalf("expected cardinality of CONCAT key to be 2 ('PROD:auth' and 'STAGING:billing'), got %+v", aggs["concat_key"])
	}
}

func TestRound19_MultiIndexEmptyShardMetricsAndRuntimeSubAggs(t *testing.T) {
	srv, _ := newTestServer()

	// 1. Multi-index search where shard_a has matching docs and shard_b has the field mapped
	//    Plus a `global` agg so shard_b's agg rows enter the multi-index merge loop with idxTotal == 0!
	doJSON(t, srv, http.MethodPut, "/r19_shard_a", `{
		"mappings": {"properties": {"price": {"type": "double"}, "env": {"type": "keyword"}}}
	}`)
	doJSON(t, srv, http.MethodPut, "/r19_shard_b", `{
		"mappings": {"properties": {"price": {"type": "double"}, "env": {"type": "keyword"}}}
	}`)
	doJSON(t, srv, http.MethodPost, "/r19_shard_a/_bulk?refresh=true",
		`{"index":{"_id":"a1"}}`+"\n"+`{"price":100,"env":"prod"}`+"\n"+
			`{"index":{"_id":"a2"}}`+"\n"+`{"price":200,"env":"prod"}`+"\n")
	doJSON(t, srv, http.MethodPost, "/r19_shard_b/_bulk?refresh=true",
		`{"index":{"_id":"b1"}}`+"\n"+`{"price":50,"env":"dev"}`+"\n")

	resMulti := doJSON(t, srv, http.MethodPost, "/r19_shard_a,r19_shard_b/_search", `{
		"size": 0,
		"query": {"term": {"env": "prod"}},
		"aggs": {
			"min_price": {"min": {"field": "price"}},
			"avg_price": {"avg": {"field": "price"}},
			"all_docs":  {"global": {}}
		}
	}`)
	mAggs := resMulti["aggregations"].(map[string]any)
	// shard_b has 0 matching docs for env="prod". Its SQL COALESCE(MIN(price), 0) must NOT clobber min_price to 0!
	if mAggs["min_price"].(map[string]any)["value"] != float64(100) {
		t.Fatalf("expected multi-index min_price=100 (not clobbered by empty shard_b 0), got %+v", mAggs["min_price"])
	}
	if mAggs["avg_price"].(map[string]any)["value"] != float64(150) {
		t.Fatalf("expected multi-index avg_price=150, got %+v", mAggs["avg_price"])
	}

	// 2. Anonymous `filters` with runtime script + `top_hits` / `top_metrics` with runtime `_script` sort
	resRuntime := doJSON(t, srv, http.MethodPost, "/r19_shard_a/_search", `{
		"size": 0,
		"aggs": {
			"anon_filters": {
				"filters": {
					"other_bucket": true,
					"filters": [
						{"script": {"script": "int p = (int) doc['price'].value; return p >= 150;"}}
					]
				},
				"aggs": {
					"top_doc": {
						"top_hits": {
							"size": 1
						}
					}
				}
			},
			"best_metric": {
				"top_metrics": {
					"metrics": {"field": "price"},
					"sort": [
						{"_script": {"script": "int p = (int) doc['price'].value; return p * 2;", "order": "desc"}}
					]
				}
			}
		}
	}`)
	rAggs := resRuntime["aggregations"].(map[string]any)
	anonBuckets := rAggs["anon_filters"].(map[string]any)["buckets"].([]any)
	if len(anonBuckets) != 2 || anonBuckets[0].(map[string]any)["doc_count"] != float64(1) || anonBuckets[1].(map[string]any)["doc_count"] != float64(1) {
		t.Fatalf("expected anonymous filters with runtime script to have [1, 1] doc_counts, got %+v", anonBuckets)
	}
	topHitsInBucket := anonBuckets[0].(map[string]any)["top_doc"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)
	if len(topHitsInBucket) != 1 || topHitsInBucket[0].(map[string]any)["_id"] != "a2" {
		t.Fatalf("expected top_hits inside runtime script bucket to return doc a2, got %+v", topHitsInBucket)
	}
	bestTop := rAggs["best_metric"].(map[string]any)["top"].([]any)
	if len(bestTop) != 1 || bestTop[0].(map[string]any)["metrics"].(map[string]any)["price"] != float64(200) {
		t.Fatalf("expected top_metrics with runtime _script sort to return price=200, got %+v", bestTop)
	}
}

func TestRound19_PainlessDynamicCtxOpRemoveEqualsAndNoopSource(t *testing.T) {
	// 1. Dynamic ctx.op from params/ternary + unchanged _source on noop
	origSrc := json.RawMessage(`{"status":"locked","temp":1}`)
	updReq := &painless.UpdateRequest{
		Script: &painless.ScriptSpec{
			Source: `
				ctx._source.temp = 999;
				if ("LOCKED".equalsIgnoreCase(ctx._source.status) && !"unlocked".equals(ctx._source.status)) {
					ctx.op = params.target_op;
				}
			`,
			Params: map[string]any{"target_op": "noop"},
		},
	}
	outSrc, opRes, err := painless.ApplyUpdateWithResult(origSrc, updReq, true)
	if err != nil {
		t.Fatalf("unexpected ApplyUpdateWithResult error: %v", err)
	}
	if opRes != "noop" {
		t.Fatalf("expected dynamic ctx.op = params.target_op to yield 'noop', got %q", opRes)
	}
	if string(outSrc) != string(origSrc) {
		t.Fatalf("expected noop update to preserve original _source %s, got %s", string(origSrc), string(outSrc))
	}

	// 2. Expression-level Map.remove(key), List.remove(idx), List.set(idx, val), .concat(), .compareTo()
	src2 := json.RawMessage(`{"old_name":"alice","items":["x","y","z"],"code":"A"}`)
	updReq2 := &painless.UpdateRequest{
		Script: &painless.ScriptSpec{
			Source: `
				ctx._source.new_name = ctx._source.remove('old_name').concat('-verified');
				ctx._source.removed_item = ctx._source.items.remove(1);
				ctx._source.prev_first = ctx._source.items.set(0, 'first');
				ctx._source.cmp = ctx._source.code.compareTo('B');
			`,
		},
	}
	outSrc2, opRes2, err := painless.ApplyUpdateWithResult(src2, updReq2, true)
	if err != nil || opRes2 != "updated" {
		t.Fatalf("unexpected ApplyUpdateWithResult(2): op=%q err=%v", opRes2, err)
	}
	var doc2 map[string]any
	_ = json.Unmarshal(outSrc2, &doc2)
	if _, hasOld := doc2["old_name"]; hasOld {
		t.Fatalf("expected old_name to be removed, got %+v", doc2)
	}
	if doc2["new_name"] != "alice-verified" {
		t.Fatalf("expected new_name='alice-verified', got %v", doc2["new_name"])
	}
	if doc2["removed_item"] != "y" || doc2["prev_first"] != "x" {
		t.Fatalf("expected removed_item='y' and prev_first='x', got %+v", doc2)
	}
	items2, _ := doc2["items"].([]any)
	if len(items2) != 2 || items2[0] != "first" || items2[1] != "z" {
		t.Fatalf("expected items=['first','z'], got %+v", items2)
	}
	if cmpVal, ok := toFloat64(doc2["cmp"]); !ok || cmpVal >= 0 {
		t.Fatalf("expected 'A'.compareTo('B') < 0, got %v", doc2["cmp"])
	}
}

func TestRound19_UpdateScriptedUpsertIngestDotExpanderReindexAndTerminateAfter(t *testing.T) {
	srv, _ := newTestServer()

	// 1. _update & _bulk on non-existent document with scripted_upsert setting ctx.op = "noop" or "delete"
	doJSON(t, srv, http.MethodPut, "/r19_ops", `{
		"mappings": {"properties": {"val": {"type": "long"}}}
	}`)
	resNoopUpsert := doJSON(t, srv, http.MethodPost, "/r19_ops/_update/missing-1?_source=true&refresh=true", `{
		"scripted_upsert": true,
		"script": {
			"source": "ctx.op = 'noop'"
		},
		"upsert": {}
	}`)
	if resNoopUpsert["result"] != "noop" {
		t.Fatalf("expected result='noop', got %v", resNoopUpsert["result"])
	}
	if getObj, ok := resNoopUpsert["get"].(map[string]any); !ok || getObj["found"] != false {
		t.Fatalf("expected get.found=false when scripted_upsert noops on non-existent doc, got %+v", resNoopUpsert["get"])
	}

	resDelUpsert := doJSON(t, srv, http.MethodPost, "/r19_ops/_update/missing-2?refresh=true", `{
		"scripted_upsert": true,
		"script": {
			"source": "ctx.op = 'delete'"
		},
		"upsert": {}
	}`)
	if resDelUpsert["result"] != "noop" {
		t.Fatalf("expected scripted_upsert with ctx.op='delete' on non-existent doc to return 'noop', got %v", resDelUpsert["result"])
	}

	// 2. Ingest dot_expander with field: "*" and deep merge into existing nested map
	simRes := doJSON(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"dot_expander": {"field": "*"}}
			]
		},
		"docs": [
			{"_source": {"a": {"existing": 1}, "a.b.c": 2, "x.y": "hello"}}
		]
	}`)
	simDoc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	aMap, _ := simDoc["a"].(map[string]any)
	bMap, _ := aMap["b"].(map[string]any)
	if aMap["existing"] != float64(1) || bMap["c"] != float64(2) {
		t.Fatalf("expected dot_expander field='*' to deep-merge into existing 'a' map, got %+v", simDoc)
	}
	xMap, _ := simDoc["x"].(map[string]any)
	if xMap["y"] != "hello" {
		t.Fatalf("expected dot_expander field='*' to expand 'x.y', got %+v", simDoc)
	}

	// 3. _reindex with bracket ctx['_id'] and ctx.op = 'noop' tracking
	doJSON(t, srv, http.MethodPost, "/r19_ops/_bulk?refresh=true",
		`{"index":{"_id":"1"}}`+"\n"+`{"val":10}`+"\n"+
			`{"index":{"_id":"2"}}`+"\n"+`{"val":20}`+"\n"+
			`{"index":{"_id":"3"}}`+"\n"+`{"val":30}`+"\n")

	reidxRes := doJSON(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "r19_ops"},
		"dest":   {"index": "r19_ops_dest"},
		"script": {
			"source": "if (ctx._source.val == 20) { ctx.op = 'noop'; } else { ctx['_id'] = 'pref-' + ctx['_id']; }"
		}
	}`)
	if reidxRes["noops"] != float64(1) || reidxRes["created"] != float64(2) {
		t.Fatalf("expected _reindex noops=1 and created=2, got %+v", reidxRes)
	}
	destGet := doJSON(t, srv, http.MethodGet, "/r19_ops_dest/_doc/pref-1", "")
	if destGet["found"] != true {
		t.Fatalf("expected pref-1 in r19_ops_dest from ctx['_id'] rewrite, got %+v", destGet)
	}

	// 4. _count and _msearch with terminate_after
	cntRes := doJSON(t, srv, http.MethodPost, "/r19_ops/_count?terminate_after=2", `{}`)
	if cntRes["count"] != float64(2) || cntRes["terminated_early"] != true {
		t.Fatalf("expected _count?terminate_after=2 to return count=2 and terminated_early=true, got %+v", cntRes)
	}
	msearchRes := doJSON(t, srv, http.MethodPost, "/r19_ops/_msearch",
		`{"terminate_after":1}`+"\n"+`{"query":{"match_all":{}}}`+"\n")
	msItem := msearchRes["responses"].([]any)[0].(map[string]any)
	if msItem["terminated_early"] != true || msItem["hits"].(map[string]any)["total"].(map[string]any)["value"] != float64(1) {
		t.Fatalf("expected _msearch with terminate_after=1 to cap total=1 and set terminated_early=true, got %+v", msItem)
	}

	// 5. Shredder uint64 overflow clamping and float-formatted integer string coercion
	var sSpec esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties":{"big":{"type":"long"},"small":{"type":"integer"}}}`), &sSpec)
	sSchema := schema.CompileIndexSchema("es_compat", "r19_shred", &sSpec)
	shredded, err := schema.ShredDocument(sSchema, "u1", 1, false, json.RawMessage(`{"big":18446744073709551615,"small":"42.9"}`))
	if err != nil {
		t.Fatalf("unexpected ShredDocument error: %v", err)
	}
	var shreddedMap map[string]any
	_ = json.Unmarshal(shredded, &shreddedMap)
	if shreddedMap["f__big"] != float64(math.MaxInt64) && shreddedMap["f__big"] != int64(math.MaxInt64) {
		// Check via int64 conversion that it is positive (clamped to MaxInt64, not negative -1)
		if fv, ok := toFloat64(shreddedMap["f__big"]); !ok || fv <= 0 {
			t.Fatalf("expected uint64 > MaxInt64 to clamp to positive MaxInt64, got %v", shreddedMap["f__big"])
		}
	}
	if shreddedMap["f__small"] != float64(42) {
		t.Fatalf("expected float-formatted integer string '42.9' to coerce to 42, got %v", shreddedMap["f__small"])
	}
}
