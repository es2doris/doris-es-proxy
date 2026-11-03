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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doReq(t *testing.T, srv *Server, method, path, body string) (int, map[string]any) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var out map[string]any
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	return w.Code, out
}

func TestRound37_F1_F2_BoostFieldPreservationAndKNNOpenSearchUnmarshal(t *testing.T) {
	// F1: Multi-field leaf query or named leaf query on a document field literally named "boost"
	// with a string value must not drop the "boost" field predicate, while string-encoded numeric
	// boost ("boost": "2.5") must be parsed as the clause boost.
	var q1 esast.Query
	if err := json.Unmarshal([]byte(`{"term": {"boost": "turbo", "_name": "q1"}}`), &q1); err != nil {
		t.Fatalf("failed to unmarshal term on field 'boost': %v", err)
	}
	if q1.Term == nil || q1.Term["boost"].Value != "turbo" {
		t.Fatalf("expected term on field 'boost'='turbo', got %+v", q1.Term)
	}
	var q2 esast.Query
	if err := json.Unmarshal([]byte(`{"term": {"status": "active", "boost": "2.5"}}`), &q2); err != nil {
		t.Fatalf("failed to unmarshal string boost: %v", err)
	}
	if q2.Term == nil || q2.Term["status"].Value != "active" || q2.Term["status"].Boost != 2.5 {
		t.Fatalf("expected status='active' with boost=2.5, got %+v", q2.Term)
	}

	// F2: OpenSearch field-keyed knn syntax with sibling "_name" and top-level "boost".
	var qKNN esast.Query
	if err := json.Unmarshal([]byte(`{"knn": {"embedding": {"vector": [0.1, 0.2], "k": 5}, "_name": "vec_q", "boost": 2.0}}`), &qKNN); err != nil {
		t.Fatalf("failed to unmarshal OpenSearch knn query: %v", err)
	}
	if qKNN.KNN == nil || qKNN.KNN.Field != "embedding" || qKNN.KNN.K != 5 || qKNN.KNN.Boost == nil || *qKNN.KNN.Boost != 2.0 {
		t.Fatalf("expected knn field='embedding' k=5 boost=2.0, got %+v", qKNN.KNN)
	}
}

func TestRound37_F3_F4_InferMappingMultiValuedAndNestedRelativeAlias(t *testing.T) {
	// F3: Mixed object-array and single-object samples + variable-length float arrays.
	inferred := schema.InferMappingFromSampleDocs([]json.RawMessage{
		json.RawMessage(`{"items": [{"a": 1}], "vec": [1.5, 2.5]}`),
		json.RawMessage(`{"items": {"a": 2, "b": 3}, "vec": [1.5, 2.5, 3.5]}`),
	})
	itemsProp := inferred.Properties["items"]
	if !itemsProp.MultiValued || !itemsProp.Properties["b"].MultiValued {
		t.Fatalf("expected items and items.b to have MultiValued=true, got %+v", itemsProp)
	}
	vecProp := inferred.Properties["vec"]
	if vecProp.Type != "double" || !vecProp.MultiValued {
		t.Fatalf("expected variable-length float arrays to widen to multi-valued double, got %+v", vecProp)
	}

	// F4: Nested field alias with relative path ("code" inside nested "items") and no inherited CopyTo.
	var mapping esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"all_codes": {"type": "keyword"},
			"items": {
				"type": "nested",
				"properties": {
					"code": {"type": "keyword", "copy_to": "all_codes"},
					"code_alias": {"type": "alias", "path": "code"}
				}
			}
		}
	}`), &mapping); err != nil {
		t.Fatalf("unmarshal mapping: %v", err)
	}
	idxSchema := schema.CompileIndexSchema("logs", "doris_es", &mapping)
	aliasBinding := idxSchema.ResolveField("items.code_alias")
	if aliasBinding.Kind != schema.StorageNestedSubfield || aliasBinding.NestedPath != "items" || len(aliasBinding.RelativeJSONPath) != 1 || aliasBinding.RelativeJSONPath[0] != "code" {
		t.Fatalf("expected nested relative alias to resolve to items.code nested subfield, got %+v", aliasBinding)
	}
	if len(aliasBinding.CopyTo) != 0 {
		t.Fatalf("expected resolved alias binding to have empty CopyTo, got %+v", aliasBinding.CopyTo)
	}
}

func TestRound37_F5_F6_ShredderNullArrayNullValueAndNestedKwCompanionOrder(t *testing.T) {
	var mapping esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"status": {"type": "keyword", "null_value": "MISSING"},
			"items": {
				"type": "nested",
				"properties": {
					"name": {
						"type": "keyword",
						"ignore_above": 3,
						"fields": {
							"keyword": {"type": "keyword", "ignore_above": 20}
						}
					}
				}
			}
		}
	}`), &mapping); err != nil {
		t.Fatalf("unmarshal mapping: %v", err)
	}
	idxSchema := schema.CompileIndexSchema("nested_idx", "doris_es", &mapping)
	shredded, err := schema.ShredDocument(idxSchema, "1", 1, false, json.RawMessage(`{
		"status": [null],
		"items": [
			{"name": "LONG_NAME"}
		]
	}`))
	if err != nil {
		t.Fatalf("ShredDocument failed: %v", err)
	}
	var row map[string]any
	if err := json.Unmarshal(shredded, &row); err != nil {
		t.Fatalf("unmarshal shredded: %v", err)
	}
	// F5: scalar field with null_value receiving [null] must substitute null_value ("MISSING").
	if row["f__status"] != "MISSING" {
		t.Fatalf("expected f__status='MISSING' for [null] with null_value, got %#v", row["f__status"])
	}
	// F6: base nested field items.name has ignore_above: 3 (omitted), while companion items.name.keyword has ignore_above: 20 ("LONG_NAME" preserved in name__keyword).
	nestedArr, _ := row["n__items"].([]any)
	if len(nestedArr) != 1 {
		t.Fatalf("expected 1 nested element in n__items, got %#v", row["n__items"])
	}
	var elem0 map[string]any
	_ = json.Unmarshal([]byte(nestedArr[0].(string)), &elem0)
	if elem0["name__keyword"] != "LONG_NAME" {
		t.Fatalf("expected elem0['name__keyword']='LONG_NAME', got %#v", elem0)
	}
	if elem0["name"] != nil {
		t.Fatalf("expected elem0['name'] to be nil due to base ignore_above=3, got %#v", elem0)
	}

	// Verify transpiler nested query on items.name.keyword references $.name__keyword.
	tr := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{})
	var sr esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query": {"nested": {"path": "items", "query": {"term": {"items.name.keyword": "LONG_NAME"}}}}}`), &sr); err != nil {
		t.Fatalf("unmarshal search: %v", err)
	}
	plan, err := tr.BuildSearchPlan(&sr)
	if err != nil {
		t.Fatalf("BuildSearchPlan: %v", err)
	}
	if !strings.Contains(plan.HitsSQL, "$.name__keyword") {
		t.Fatalf("expected nested SQL to reference $.name__keyword, got %s", plan.HitsSQL)
	}
}

func TestRound37_F7_F8_F9_F10_LuceneZeroBoostFieldUnarySearchAfterTotalAndNumericArrayScript(t *testing.T) {
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/logs", `{
		"mappings": {
			"properties": {
				"env": {"type": "keyword"},
				"rank": {"type": "integer"},
				"scores": {"type": "integer"}
			}
		}
	}`)
	doReq(t, srv, http.MethodPut, "/logs/_doc/1?refresh=true", `{"env": "prod", "rank": 1, "scores": [10, 20]}`)
	doReq(t, srv, http.MethodPut, "/logs/_doc/2?refresh=true", `{"env": "legacy", "rank": 2, "scores": [30]}`)
	doReq(t, srv, http.MethodPut, "/logs/_doc/3?refresh=true", `{"env": "prod", "rank": 3, "scores": [40]}`)

	// F7 & F8: Lucene zero boost (^0) and field-scoped unary negation (`env:-legacy`).
	_, res := doReq(t, srv, http.MethodPost, "/logs/_search", `{
		"query": {"query_string": {"query": "env:prod^0 AND env:-legacy"}}
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 2 {
		t.Fatalf("expected 2 docs for env:prod^0 AND env:-legacy, got %+v", hits)
	}

	// F9: search_after without collapse must still report total matching documents (3), not just remaining documents after cursor (2).
	_, resSA := doReq(t, srv, http.MethodPost, "/logs/_search", `{
		"size": 1,
		"sort": [{"rank": "asc"}],
		"search_after": [1]
	}`)
	hitsMap := resSA["hits"].(map[string]any)
	totalVal := hitsMap["total"].(map[string]any)["value"].(float64)
	if totalVal != 3 {
		t.Fatalf("expected hits.total.value=3 when paginating with search_after, got %v", totalVal)
	}

	// F10: parseStringScriptExpr on numeric multi-valued field (`doc['scores'].value + 5`) must perform numeric addition, not string CONCAT.
	var mapping esast.MappingSpec
	_ = json.Unmarshal([]byte(`{"properties": {"scores": {"type": "integer"}}}`), &mapping)
	s := schema.CompileIndexSchema("logs", "doris_es", &mapping)
	sb := s.Fields["scores"]
	sb.Kind = schema.StoragePromotedArray
	sb.IsMultiValued = true
	sb.ColumnName = "f__arr__scores"
	s.Fields["scores"] = sb
	tr := transpiler.NewTranspiler(s, transpiler.TranspilerOptions{})
	var aggReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"plus_five": {
				"terms": {
					"field": "scores",
					"script": {"source": "_value + params.bonus", "params": {"bonus": 5}}
				}
			}
		}
	}`), &aggReq)
	plan, err := tr.BuildSearchPlan(&aggReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan failed: %v", err)
	}
	if strings.Contains(plan.AggsSQL, "CONCAT(") {
		t.Fatalf("expected numeric array _value + params.bonus to compile as arithmetic addition, not CONCAT, got: %s", plan.AggsSQL)
	}
}

func TestRound37_F11_F12_F20_MemBackendCompositeHavingAndCollapse(t *testing.T) {
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/items", `{
		"mappings": {
			"properties": {
				"group": {"type": "keyword"},
				"empty_group": {"type": "keyword"},
				"tags": {"type": "keyword"},
				"price": {"type": "integer"}
			}
		}
	}`)
	doReq(t, srv, http.MethodPut, "/items/_doc/1?refresh=true", `{"group": "g0", "empty_group": "", "tags": ["b", "a"], "price": 10}`)
	doReq(t, srv, http.MethodPut, "/items/_doc/2?refresh=true", `{"group": "g0", "empty_group": "", "tags": ["c"], "price": 20}`)
	doReq(t, srv, http.MethodPut, "/items/_doc/3?refresh=true", `{"group": "g1", "empty_group": "g1", "tags": ["a"], "price": 30}`)
	// Doc 4 has null tags -> must be excluded from composite agg when missing_bucket is false!
	doReq(t, srv, http.MethodPut, "/items/_doc/4?refresh=true", `{"group": "g1", "empty_group": "g1", "price": 40}`)

	// F11: composite aggregation over multi-valued `tags` and `group` must expand array elements and skip doc 4 where `tags` is missing.
	_, resComp := doReq(t, srv, http.MethodPost, "/items/_search", `{
		"size": 0,
		"aggs": {
			"comp": {
				"composite": {
					"sources": [
						{"g": {"terms": {"field": "group"}}},
						{"t": {"terms": {"field": "tags"}}}
					]
				}
			}
		}
	}`)
	compBuckets := resComp["aggregations"].(map[string]any)["comp"].(map[string]any)["buckets"].([]any)
	// Expected combinations: ("g0", "a"), ("g0", "b"), ("g0", "c"), ("g1", "a") -> 4 buckets, no bucket with empty/nil t!
	if len(compBuckets) != 4 {
		t.Fatalf("expected 4 composite buckets (multi-valued expanded, missing excluded), got %+v", compBuckets)
	}

	// F12: terms aggregation on multi-valued `tags` with `min_doc_count: 2` and `size: 1` must filter HAVING before truncating to size 1.
	_, resHaving := doReq(t, srv, http.MethodPost, "/items/_search", `{
		"size": 0,
		"aggs": {
			"popular_tags": {
				"terms": {"field": "tags", "min_doc_count": 2, "size": 1, "order": {"_key": "desc"}}
			}
		}
	}`)
	popBuckets := resHaving["aggregations"].(map[string]any)["popular_tags"].(map[string]any)["buckets"].([]any)
	if len(popBuckets) != 1 || popBuckets[0].(map[string]any)["key"] != "a" {
		t.Fatalf("expected tag 'a' (count 2) to survive min_doc_count=2 with size=1 even under _key desc order, got %+v", popBuckets)
	}

	// F20: field collapse on `empty_group` must deduplicate empty-string `""` keys (docs 1 and 2 collapse into 1 hit, docs 3 and 4 collapse into 1 hit).
	_, resCollapse := doReq(t, srv, http.MethodPost, "/items/_search", `{
		"collapse": {"field": "empty_group"},
		"sort": [{"price": "asc"}]
	}`)
	collapseHits := resCollapse["hits"].(map[string]any)["hits"].([]any)
	if len(collapseHits) != 2 {
		t.Fatalf("expected 2 collapsed hits (one for empty_group='', one for empty_group='g1'), got %+v", collapseHits)
	}
}

func TestRound37_F13_F14_MultiIndexRuntimeScriptEmptyStatsAndStringStats(t *testing.T) {
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/idx_empty", `{"mappings": {"properties": {"k": {"type": "keyword"}, "v": {"type": "integer"}}}}`)
	doReq(t, srv, http.MethodPut, "/idx_populated", `{"mappings": {"properties": {"k": {"type": "keyword"}, "v": {"type": "integer"}}}}`)
	// idx_empty has a matching doc for the bucket, but the runtime script returns null for that doc!
	doReq(t, srv, http.MethodPut, "/idx_empty/_doc/1?refresh=true", `{"k": "g1"}`)
	doReq(t, srv, http.MethodPut, "/idx_populated/_doc/2?refresh=true", `{"k": "g1", "v": 100, "s": "hello"}`)

	_, res := doReq(t, srv, http.MethodPost, "/idx_empty,idx_populated/_search", `{
		"size": 0,
		"aggs": {
			"by_k": {
				"terms": {"field": "k"},
				"aggs": {
					"min_v": {"min": {"script": "doc['v'].size() > 0 ? doc['v'].value : null"}},
					"avg_v": {"avg": {"script": "doc['v'].size() > 0 ? doc['v'].value : null"}},
					"st_v": {"stats": {"script": "doc['v'].size() > 0 ? doc['v'].value : null"}},
					"str_st": {"string_stats": {"script": "params._source.s"}}
				}
			},
			"top_str": {
				"string_stats": {"script": "params._source.s"}
			}
		}
	}`)
	aggs := res["aggregations"].(map[string]any)
	buckets := aggs["by_k"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %+v", buckets)
	}
	b0 := buckets[0].(map[string]any)
	if b0["min_v"].(map[string]any)["value"] != float64(100) {
		t.Fatalf("expected min_v=100 (not polluted by 0 from empty index), got %+v", b0["min_v"])
	}
	if b0["avg_v"].(map[string]any)["value"] != float64(100) {
		t.Fatalf("expected avg_v=100, got %+v", b0["avg_v"])
	}
	stV := b0["st_v"].(map[string]any)
	if stV["min"] != float64(100) || stV["avg"] != float64(100) || stV["count"] != float64(1) {
		t.Fatalf("expected stats min=100 avg=100 count=1, got %+v", stV)
	}
	strSt := b0["str_st"].(map[string]any)
	if strSt["count"] != float64(1) || strSt["min_length"] != float64(5) || strSt["max_length"] != float64(5) || strSt["avg_length"] != float64(5) {
		t.Fatalf("expected bucket string_stats count=1 min=5 max=5 avg=5, got %+v", strSt)
	}
	topStr := aggs["top_str"].(map[string]any)
	if topStr["count"] != float64(1) || topStr["min_length"] != float64(5) || topStr["max_length"] != float64(5) || topStr["avg_length"] != float64(5) {
		t.Fatalf("expected top string_stats count=1 min=5 max=5 avg=5, got %+v", topStr)
	}
}

func TestRound37_F15_MultiIndexTopHitsAndTopMetricsSameDocIDNoCollision(t *testing.T) {
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/m_idx_a", `{"mappings": {"properties": {"cat": {"type": "keyword"}, "val": {"type": "integer"}}}}`)
	doReq(t, srv, http.MethodPut, "/m_idx_b", `{"mappings": {"properties": {"cat": {"type": "keyword"}, "val": {"type": "integer"}}}}`)
	// Both indices have doc with _id="shared_1", but in different categories and with different values!
	doReq(t, srv, http.MethodPut, "/m_idx_a/_doc/shared_1?refresh=true", `{"cat": "alpha", "val": 10}`)
	doReq(t, srv, http.MethodPut, "/m_idx_b/_doc/shared_1?refresh=true", `{"cat": "beta", "val": 99}`)

	_, res := doReq(t, srv, http.MethodPost, "/m_idx_a,m_idx_b/_search", `{
		"size": 0,
		"aggs": {
			"by_cat": {
				"terms": {"field": "cat", "order": {"_key": "asc"}},
				"aggs": {
					"th": {"top_hits": {"size": 1}},
					"tm": {"top_metrics": {"metrics": {"field": "val"}, "sort": [{"val": "desc"}]}}
				}
			}
		}
	}`)
	buckets := res["aggregations"].(map[string]any)["by_cat"].(map[string]any)["buckets"].([]any)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %+v", buckets)
	}
	bAlpha := buckets[0].(map[string]any)
	bBeta := buckets[1].(map[string]any)
	thAlphaHit := bAlpha["th"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	thBetaHit := bBeta["th"].(map[string]any)["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	if thAlphaHit["_index"] != "m_idx_a" || thAlphaHit["_id"] != "shared_1" || thAlphaHit["_source"].(map[string]any)["val"] != float64(10) {
		t.Fatalf("expected alpha bucket top_hits to resolve m_idx_a doc (val=10), got %+v", thAlphaHit)
	}
	if thBetaHit["_index"] != "m_idx_b" || thBetaHit["_id"] != "shared_1" || thBetaHit["_source"].(map[string]any)["val"] != float64(99) {
		t.Fatalf("expected beta bucket top_hits to resolve m_idx_b doc (val=99), got %+v", thBetaHit)
	}
	tmAlpha := bAlpha["tm"].(map[string]any)["top"].([]any)[0].(map[string]any)["metrics"].(map[string]any)
	tmBeta := bBeta["tm"].(map[string]any)["top"].([]any)[0].(map[string]any)["metrics"].(map[string]any)
	if tmAlpha["val"] != float64(10) || tmBeta["val"] != float64(99) {
		t.Fatalf("expected top_metrics alpha=10 beta=99, got alpha=%+v beta=%+v", tmAlpha, tmBeta)
	}
}

func TestRound37_F16_PrepareDocForRuntimeScriptPreservesArrayOfObjectsUnderIgnoreAbove(t *testing.T) {
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/arr_ia", `{
		"mappings": {
			"properties": {
				"items": {
					"properties": {
						"code": {"type": "keyword", "ignore_above": 5},
						"qty": {"type": "integer"}
					}
				}
			}
		}
	}`)
	doReq(t, srv, http.MethodPut, "/arr_ia/_doc/1?refresh=true", `{
		"items": [
			{"code": "TOO_LONG_STRING", "qty": 42}
		]
	}`)
	_, res := doReq(t, srv, http.MethodPost, "/arr_ia/_search", `{
		"query": {
			"script": {
				"script": "doc['items.qty'].value == 42 && doc['items.code'].size() == 0"
			}
		}
	}`)
	hits := res["hits"].(map[string]any)["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("expected doc 1 to match script (items.qty preserved when sibling items.code exceeds ignore_above), got %+v", hits)
	}
}

func TestRound37_F17_F18_NowDetectionAndCoalescerCanceledWaiterAbort(t *testing.T) {
	// F17: SearchRequestContainsNow detects whitespace-prefixed " now-1h", Painless wall-clock calls, and range/composite date aggs.
	for _, raw := range []string{
		`{"query": {"range": {"ts": {"gte": " now-1h"}}}}`,
		`{"query": {"script": {"script": "System.currentTimeMillis() > 0"}}}`,
		`{"query": {"script": {"script": "Instant.now().toEpochMilli() > 0"}}}`,
		`{"aggs": {"r": {"range": {"field": "ts", "ranges": [{"from": "now-1d"}]}}}}`,
	} {
		var sr esast.SearchRequest
		if err := json.Unmarshal([]byte(raw), &sr); err != nil {
			t.Fatalf("unmarshal %s: %v", raw, err)
		}
		if !containsNowDateMath(&sr, []byte(raw)) {
			t.Fatalf("expected containsNowDateMath=true for %s", raw)
		}
	}

	// F18: If all callers in a pending timer batch cancel their contexts before onTimerFlush fires,
	// onTimerFlush must abort the batch without invoking loadFn.
	var flushes int64
	coal := newStreamLoadCoalescer(func(ctx context.Context, table string, ndjson []byte, syncRefresh bool) error {
		atomic.AddInt64(&flushes, 1)
		return nil
	})
	coal.Configure(40*time.Millisecond, 1024*1024)
	defer func() { _ = coal.Close(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := coal.Submit(ctx, "tbl_cancel", []byte(`{"_id":"1"}`), false); err == nil {
		t.Fatalf("expected Submit with 5ms timeout to return context error")
	}
	time.Sleep(60 * time.Millisecond)
	if got := atomic.LoadInt64(&flushes); got != 0 {
		t.Fatalf("expected 0 backend flushes when sole waiter canceled before timer fired, got %d", got)
	}
}

func TestRound37_F19_PostFilterExcludesDocFromMaxScore(t *testing.T) {
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/pf_max", `{"mappings": {"properties": {"env": {"type": "keyword"}, "boost_v": {"type": "double"}}}}`)
	doReq(t, srv, http.MethodPut, "/pf_max/_doc/1?refresh=true", `{"env": "dev", "boost_v": 100.0}`)
	doReq(t, srv, http.MethodPut, "/pf_max/_doc/2?refresh=true", `{"env": "prod", "boost_v": 5.0}`)
	doReq(t, srv, http.MethodPut, "/pf_max/_doc/3?refresh=true", `{"env": "prod", "boost_v": 1.0}`)

	// Doc 1 has score 100 but is excluded by post_filter (env=prod).
	// With from=1, size=1, the page returns doc 3 (score 1.0), while max_score across post_filter hits is doc 2 (score 5.0), NOT 100.0!
	_, res := doReq(t, srv, http.MethodPost, "/pf_max/_search", `{
		"from": 1,
		"size": 1,
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"script": {"source": "doc['boost_v'].value"}
			}
		},
		"post_filter": {"term": {"env": "prod"}}
	}`)
	hitsEnv := res["hits"].(map[string]any)
	if hitsEnv["max_score"] != 5.0 {
		t.Fatalf("expected max_score=5.0 (highest post_filter hit), got %v", hitsEnv["max_score"])
	}
}

func TestRound37_F21_F22_F23_F24_PainlessUserFunctionsLambdaCtxRegexAndUTF8(t *testing.T) {
	// F21: User-defined functions in Painless scripts (value-returning and void).
	docFn := map[string]any{"n": int64(6)}
	_, err := painless.EvalPainlessWithOp(docFn, `
		int doubleIt(int x) { return x * 2; }
		void writeOut(Map src, int v) { src.result = v + 1; }
		int d = doubleIt(ctx._source.n);
		writeOut(ctx._source, d);
	`, nil)
	if err != nil {
		t.Fatalf("EvalPainlessWithOp with user functions failed: %v", err)
	}
	if docFn["result"] != int64(13) {
		t.Fatalf("expected user functions to set result=13, got %+v", docFn)
	}

	// F22: removeIf lambda mutating outer local counter and subsequent top-level ctx._index mutation.
	docLambda := map[string]any{"tags": []any{"keep", "drop_me"}}
	_, err = painless.EvalPainlessWithOp(docLambda, `
		int removed = 0;
		ctx._source.tags.removeIf(t -> {
			if (t == 'drop_me') {
				removed += 1;
				return true;
			}
			return false;
		});
		ctx._source.removed_count = removed;
	`, nil)
	if err != nil {
		t.Fatalf("EvalPainlessWithOp with removeIf block lambda failed: %v", err)
	}
	if docLambda["removed_count"] != int64(1) {
		t.Fatalf("expected outer variable removed_count=1 after removeIf lambda, got %+v", docLambda)
	}

	// F23: Regex literal assigned to variable (`def p = /^([a-z]+)-(\d+)$/`) + `.matcher()` / `.matches()` / `.group(1)`.
	val, err := painless.Eval(map[string]any{"s": "item-42"}, `
		def p = /^([a-z]+)-(\d+)$/;
		def m = p.matcher(doc['s'].value);
		return m.matches() ? m.group(1) + ":" + m.group(2) : "no";
	`, nil)
	if err != nil || val != "item:42" {
		t.Fatalf("expected regex variable + matcher to return 'item:42', got val=%v err=%v", val, err)
	}

	// F24: UTF-8 rune-aware String.length(), substring(), charAt(), indexOf(), lastIndexOf().
	utfVal, err := painless.Eval(map[string]any{"s": "ééaé"}, `
		String s = doc['s'].value;
		return s.length() + ":" + s.substring(0, 2) + ":" + s.charAt(2) + ":" + s.indexOf('a') + ":" + s.lastIndexOf('é');
	`, nil)
	if err != nil || utfVal != "4:éé:a:2:3" {
		t.Fatalf("expected UTF-8 string methods to return '4:éé:a:2:3', got val=%v err=%v", utfVal, err)
	}
}

func TestRound37_F25_F26_F27_IngestDedupCompactCtxNowAndEnrichDottedPaths(t *testing.T) {
	srv, _ := newTestServer()

	// F25 & F26: dedup processor, recursive compact processor, and ctx._now in script processor without leaking internal _ingest keys.
	doReq(t, srv, http.MethodPut, "/_ingest/pipeline/dedup_compact_pipe", `{
		"processors": [
			{
				"dedup": {
					"field": "tags",
					"target_field": "unique_tags"
				}
			},
			{
				"compact": {
					"field": "meta"
				}
			},
			{
				"script": {
					"source": "ctx.has_now = (ctx._now != null); ctx.ingest_keys = ctx._ingest.keySet().size();"
				}
			}
		]
	}`)
	_, simRes := doReq(t, srv, http.MethodPost, "/_ingest/pipeline/dedup_compact_pipe/_simulate", `{
		"docs": [{
			"_source": {
				"tags": ["a", "b", "a", "c", "b"],
				"meta": {"keep": "yes", "empty_str": "", "null_val": null, "empty_obj": {"nested_null": null}, "empty_arr": []}
			}
		}]
	}`)
	simDoc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	uTags, _ := simDoc["unique_tags"].([]any)
	if len(uTags) != 3 || uTags[0] != "a" || uTags[1] != "b" || uTags[2] != "c" {
		t.Fatalf("expected unique_tags=[a b c], got %+v", simDoc["unique_tags"])
	}
	metaMap, _ := simDoc["meta"].(map[string]any)
	if len(metaMap) != 1 || metaMap["keep"] != "yes" {
		t.Fatalf("expected compact processor to prune null/empty string/empty nested map/empty array, got %+v", metaMap)
	}
	if simDoc["has_now"] != true || simDoc["ingest_keys"] != float64(1) {
		t.Fatalf("expected ctx._now!=null and ctx._ingest to only contain 'timestamp' (size 1), got has_now=%v ingest_keys=%v", simDoc["has_now"], simDoc["ingest_keys"])
	}

	// F27: enrich processor with dotted match_field and enrich_fields (`user.id`, `user.tier`).
	doReq(t, srv, http.MethodPut, "/users_lookup/_doc/1?refresh=true", `{"user": {"id": "u1", "tier": "gold", "secret": "hidden"}}`)
	doReq(t, srv, http.MethodPut, "/_enrich/policy/user_policy", `{
		"match": {
			"indices": "users_lookup",
			"match_field": "user.id",
			"enrich_fields": ["user.tier"]
		}
	}`)
	doReq(t, srv, http.MethodPost, "/_enrich/policy/user_policy/_execute", "")
	doReq(t, srv, http.MethodPut, "/_ingest/pipeline/enrich_dotted_pipe", `{
		"processors": [
			{
				"enrich": {
					"policy_name": "user_policy",
					"field": "uid",
					"target_field": "enriched"
				}
			}
		]
	}`)
	_, simEnrich := doReq(t, srv, http.MethodPost, "/_ingest/pipeline/enrich_dotted_pipe/_simulate", `{
		"docs": [{"_source": {"uid": "u1"}}]
	}`)
	enrichDoc := simEnrich["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	enrichedUser, _ := enrichDoc["enriched"].(map[string]any)["user"].(map[string]any)
	if enrichedUser["id"] != "u1" || enrichedUser["tier"] != "gold" {
		t.Fatalf("expected dotted enrich fields user.id='u1' and user.tier='gold', got %+v", enrichDoc["enriched"])
	}
	if _, hasSecret := enrichedUser["secret"]; hasSecret {
		t.Fatalf("expected unconfigured dotted field user.secret to be excluded, got %+v", enrichedUser)
	}
}

func TestRound37_F28_DynamicMappingEnforcementStrictFalseRuntime(t *testing.T) {
	srv, _ := newTestServer()

	// 1. dynamic: "strict" rejects unmapped fields with 400 strict_dynamic_mapping_exception
	doReq(t, srv, http.MethodPut, "/strict_idx", `{
		"mappings": {
			"dynamic": "strict",
			"properties": {
				"known": {"type": "keyword"},
				"obj": {
					"type": "object",
					"properties": {"sub": {"type": "integer"}}
				}
			}
		}
	}`)
	code, errRes := doReq(t, srv, http.MethodPut, "/strict_idx/_doc/1", `{"known": "ok", "unmapped": "bad"}`)
	if code != http.StatusBadRequest || errRes["error"].(map[string]any)["type"] != "strict_dynamic_mapping_exception" {
		t.Fatalf("expected 400 strict_dynamic_mapping_exception for top-level unmapped field, got %d %+v", code, errRes)
	}
	code2, errRes2 := doReq(t, srv, http.MethodPut, "/strict_idx/_doc/1", `{"known": "ok", "obj": {"sub": 1, "extra": "bad"}}`)
	if code2 != http.StatusBadRequest || errRes2["error"].(map[string]any)["type"] != "strict_dynamic_mapping_exception" {
		t.Fatalf("expected 400 strict_dynamic_mapping_exception for nested unmapped field, got %d %+v", code2, errRes2)
	}
	// Known fields succeed
	codeOK, _ := doReq(t, srv, http.MethodPut, "/strict_idx/_doc/1?refresh=true", `{"known": "ok", "obj": {"sub": 1}}`)
	if codeOK != http.StatusCreated {
		t.Fatalf("expected 201 for valid doc on strict index, got %d", codeOK)
	}

	// 2. dynamic: false keeps unmapped fields in _source, omits them from _doc, and does not auto-infer mapping columns
	doReq(t, srv, http.MethodPut, "/false_idx", `{
		"mappings": {
			"dynamic": false,
			"properties": {
				"known": {"type": "keyword"}
			}
		}
	}`)
	doReq(t, srv, http.MethodPut, "/false_idx/_doc/1?refresh=true", `{"known": "yes", "ignored_field": "secret"}`)
	_, getMappingRes := doReq(t, srv, http.MethodGet, "/false_idx/_mapping", "")
	props := getMappingRes["false_idx"].(map[string]any)["mappings"].(map[string]any)["properties"].(map[string]any)
	if _, hasIgnored := props["ignored_field"]; hasIgnored {
		t.Fatalf("expected dynamic:false not to add ignored_field to mapping properties, got %+v", props)
	}
	// _source still preserves ignored_field
	_, getDocRes := doReq(t, srv, http.MethodGet, "/false_idx/_doc/1", "")
	if getDocRes["_source"].(map[string]any)["ignored_field"] != "secret" {
		t.Fatalf("expected _source to preserve ignored_field under dynamic:false, got %+v", getDocRes["_source"])
	}
}

func TestRound37_F29_RoutingRequiredEnforcementAndPropagation(t *testing.T) {
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/routed_idx", `{
		"mappings": {
			"_routing": {"required": true},
			"properties": {"title": {"type": "keyword"}}
		}
	}`)

	// Missing routing on PUT _doc -> 400 routing_missing_exception
	code, errRes := doReq(t, srv, http.MethodPut, "/routed_idx/_doc/1", `{"title": "hello"}`)
	if code != http.StatusBadRequest || errRes["error"].(map[string]any)["type"] != "routing_missing_exception" {
		t.Fatalf("expected 400 routing_missing_exception when routing is omitted, got %d %+v", code, errRes)
	}

	// PUT _doc with ?routing=shard-a succeeds and returns _routing
	codeOK, putRes := doReq(t, srv, http.MethodPut, "/routed_idx/_doc/1?routing=shard-a&refresh=true", `{"title": "hello"}`)
	if codeOK != http.StatusCreated || putRes["_routing"] != "shard-a" {
		t.Fatalf("expected 201 with _routing='shard-a', got %d %+v", codeOK, putRes)
	}

	// GET _doc returns _routing
	_, getRes := doReq(t, srv, http.MethodGet, "/routed_idx/_doc/1?routing=shard-a", "")
	if getRes["_routing"] != "shard-a" {
		t.Fatalf("expected GET _doc to include _routing='shard-a', got %+v", getRes)
	}

	// _search hits return _routing
	_, searchRes := doReq(t, srv, http.MethodPost, "/routed_idx/_search", `{"query": {"match_all": {}}}`)
	hit0 := searchRes["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)
	if hit0["_routing"] != "shard-a" {
		t.Fatalf("expected search hit to include _routing='shard-a', got %+v", hit0)
	}

	// _bulk enforces _routing.required per item and returns _routing when supplied
	bulkBody := strings.Join([]string{
		`{"index": {"_index": "routed_idx", "_id": "2"}}`,
		`{"title": "missing_routing"}`,
		`{"index": {"_index": "routed_idx", "_id": "3", "routing": "shard-b"}}`,
		`{"title": "has_routing"}`,
	}, "\n") + "\n"
	_, bulkRes := doReq(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	items := bulkRes["items"].([]any)
	item0 := items[0].(map[string]any)["index"].(map[string]any)
	item1 := items[1].(map[string]any)["index"].(map[string]any)
	if item0["status"] != float64(400) || item0["error"].(map[string]any)["type"] != "routing_missing_exception" {
		t.Fatalf("expected bulk item 0 to fail with 400 routing_missing_exception, got %+v", item0)
	}
	if item1["status"] != float64(201) || item1["_routing"] != "shard-b" {
		t.Fatalf("expected bulk item 1 to succeed with _routing='shard-b', got %+v", item1)
	}
}

func TestRound37_F30_BulkExternalVersionDeleteThenIndexAndReindexScriptVersion(t *testing.T) {
	srv, _ := newTestServer()
	doReq(t, srv, http.MethodPut, "/ver_idx/_doc/1?refresh=true", `{"v": 1}`)

	// 1. Same-batch _bulk delete at v11 followed by index with version_type=external and version=5 must fail with 409 Conflict!
	bulkBody := strings.Join([]string{
		`{"index": {"_index": "ver_idx", "_id": "ext1", "version": 10, "version_type": "external"}}`,
		`{"x": 1}`,
		`{"delete": {"_index": "ver_idx", "_id": "ext1", "version": 11, "version_type": "external"}}`,
		`{"index": {"_index": "ver_idx", "_id": "ext1", "version": 5, "version_type": "external"}}`,
		`{"x": 2}`,
	}, "\n") + "\n"
	_, bulkRes := doReq(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody)
	items := bulkRes["items"].([]any)
	item2 := items[2].(map[string]any)["index"].(map[string]any)
	if item2["status"] != float64(http.StatusConflict) {
		t.Fatalf("expected stale external version=5 after delete at version=11 to fail with 409 Conflict, got %+v", item2)
	}

	// 2. _reindex script mutating ctx._version (e.g. ctx._version = 7) honors the script-assigned version on destination!
	doReq(t, srv, http.MethodPost, "/_reindex?refresh=true", `{
		"source": {"index": "ver_idx", "query": {"ids": {"values": ["1"]}}},
		"dest": {"index": "ver_dest"},
		"script": {"source": "ctx._version = 7"}
	}`)
	_, destDoc := doReq(t, srv, http.MethodGet, "/ver_dest/_doc/1", "")
	if destDoc["_version"] != float64(7) {
		t.Fatalf("expected _reindex with ctx._version=7 to write _version=7, got %+v", destDoc)
	}
}

func TestRound37_AdditionalBranchCoverage(t *testing.T) {
	srv, _ := newTestServer()

	// 1. F1 & F2: KNNQuery OpenSearch syntax with query_vector and inner boost, plus InferMappingFromSampleDocs double + dense_vector widening
	var qKNN2 esast.Query
	if err := json.Unmarshal([]byte(`{"knn": {"embedding": {"query_vector": [0.5, 0.6], "k": 3, "boost": 1.5}, "_name": "knn2"}}`), &qKNN2); err != nil {
		t.Fatalf("unmarshal knn2: %v", err)
	}
	if qKNN2.KNN == nil || qKNN2.KNN.Boost == nil || *qKNN2.KNN.Boost != 1.5 {
		t.Fatalf("expected knn2 boost=1.5, got %+v", qKNN2.KNN)
	}
	inferred2 := schema.InferMappingFromSampleDocs([]json.RawMessage{
		json.RawMessage(`{"v": [1.5], "v2": [1.0, 2.0]}`),
		json.RawMessage(`{"v": [1.5, 2.5], "v2": [3.0]}`),
	})
	if inferred2.Properties["v"].Type != "double" || inferred2.Properties["v2"].Type != "double" {
		t.Fatalf("expected double+dense_vector to widen to double, got %+v", inferred2.Properties)
	}

	// 2. F6: Nested .keyword companion with normalizer and null_value
	var nestedMap esast.MappingSpec
	_ = json.Unmarshal([]byte(`{
		"properties": {
			"items": {
				"type": "nested",
				"properties": {
					"tag": {
						"type": "text",
						"fields": {
							"keyword": {"type": "keyword", "normalizer": "lowercase", "null_value": "NONE"}
						}
					}
				}
			}
		}
	}`), &nestedMap)
	nSchema := schema.CompileIndexSchema("n_idx", "doris_es", &nestedMap)
	shredN, err := schema.ShredDocument(nSchema, "1", 1, false, json.RawMessage(`{"items": [{"tag": "HELLO"}, {"tag": null}]}`))
	if err != nil {
		t.Fatalf("ShredDocument nested companion: %v", err)
	}
	if !strings.Contains(string(shredN), `"n__items__tag__keyword":["hello","none"]`) {
		t.Fatalf("expected lowercase and null_value on nested tag__keyword, got %s", string(shredN))
	}

	// 3. F7 & F8: Lucene ^0 boost on wildcard, regexp, phrase, range + field-scoped unary !, +, -/regex/
	doReq(t, srv, http.MethodPut, "/luc_cov", `{
		"mappings": {
			"properties": {
				"env": {"type": "keyword"},
				"msg": {"type": "text"},
				"num": {"type": "integer"},
				"ts": {"type": "date"},
				"arr_tags": {"type": "keyword"}
			}
		}
	}`)
	doReq(t, srv, http.MethodPut, "/luc_cov/_doc/1?refresh=true", `{"env": "prod", "msg": "payment api", "num": 15, "ts": "2026-01-01T00:00:00Z", "arr_tags": ["z", "a"]}`)
	doReq(t, srv, http.MethodPut, "/luc_cov/_doc/2?refresh=true", `{"env": "staging", "msg": "legacy system", "num": 25, "ts": "2026-01-02T00:00:00Z", "arr_tags": ["m", "b"]}`)

	_, lucRes := doReq(t, srv, http.MethodPost, "/luc_cov/_search", `{
		"query": {
			"query_string": {
				"query": "env:pr*^0 AND env:/pr.*/^0 AND msg:\"payment api\"^0 AND num:[10 TO 20]^0 AND env:!staging AND env:+prod AND env:-/stag.*/"
			}
		}
	}`)
	if len(lucRes["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("expected 1 hit for lucene zero boost + unary operators, got %+v", lucRes)
	}

	// 4. F12 & F20: min_doc_count HAVING on histogram, date_histogram, scalar missing, array missing + collapse on array field (minimum value selection)
	_, histRes := doReq(t, srv, http.MethodPost, "/luc_cov/_search", `{
		"size": 10,
		"collapse": {"field": "arr_tags"},
		"sort": [{"num": "asc"}],
		"aggs": {
			"h": {"histogram": {"field": "num", "interval": 10, "min_doc_count": 2}},
			"dh": {"date_histogram": {"field": "ts", "fixed_interval": "1d", "min_doc_count": 2}},
			"tm_miss": {"terms": {"field": "env", "missing": "N/A", "min_doc_count": 2}},
			"arr_miss": {"terms": {"field": "arr_tags", "missing": "N/A", "min_doc_count": 2}}
		}
	}`)
	hBuckets := histRes["aggregations"].(map[string]any)["h"].(map[string]any)["buckets"].([]any)
	dhBuckets := histRes["aggregations"].(map[string]any)["dh"].(map[string]any)["buckets"].([]any)
	if len(hBuckets) != 0 || len(dhBuckets) != 0 {
		t.Fatalf("expected 0 buckets with min_doc_count=2 when each bucket has 1 doc, got h=%+v dh=%+v", hBuckets, dhBuckets)
	}

	// 5. F16: prepareDocForRuntimeScript with ignore_above on string array + nested array of objects
	doReq(t, srv, http.MethodPut, "/ia_cov", `{
		"mappings": {
			"properties": {
				"tags": {"type": "keyword", "ignore_above": 4},
				"status": {"type": "keyword", "null_value": "NULL_STAT"},
				"nested_items": {
					"type": "object",
					"dynamic": false,
					"properties": {
						"k": {"type": "keyword", "ignore_above": 4}
					}
				}
			}
		}
	}`)
	doReq(t, srv, http.MethodPut, "/ia_cov/_doc/1?refresh=true", `{
		"tags": ["LONG_TAG_1", "ok"],
		"status": null,
		"nested_items": {"k": "LONG_K", "ignored_sub": "x"}
	}`)
	doReq(t, srv, http.MethodPut, "/ia_cov/_doc/2?refresh=true", `{
		"tags": ["LONG_TAG_1", "LONG_TAG_2"],
		"status": "active"
	}`)
	_, iaRes := doReq(t, srv, http.MethodPost, "/ia_cov/_search", `{
		"query": {
			"script": {
				"script": "doc['status'].value == 'NULL_STAT' && doc['tags'].value == 'ok'"
			}
		}
	}`)
	if len(iaRes["hits"].(map[string]any)["hits"].([]any)) != 1 {
		t.Fatalf("expected 1 hit for ignore_above array filtering + null_value in runtime script, got %+v", iaRes)
	}

	// 6. F28 & F29: dynamic:strict on array of objects, alias index_routing, ingest pipeline setting ctx._routing, _update and _update_by_query preserving routing
	codeStrictArr, _ := doReq(t, srv, http.MethodPut, "/strict_arr_idx", `{
		"mappings": {
			"properties": {
				"list": {
					"type": "object",
					"dynamic": "strict",
					"properties": {"id": {"type": "integer"}}
				}
			}
		}
	}`)
	if codeStrictArr != http.StatusOK {
		t.Fatalf("expected 200 creating strict_arr_idx, got %d", codeStrictArr)
	}
	if c, _ := doReq(t, srv, http.MethodPut, "/strict_arr_idx/_doc/1", `{"list": [{"id": 1, "bad": "x"}]}`); c != http.StatusBadRequest {
		t.Fatalf("expected 400 for unmapped field inside array of strict objects, got %d", c)
	}

	doReq(t, srv, http.MethodPut, "/_ingest/pipeline/route_pipe", `{
		"processors": [
			{"script": {"source": "ctx._routing = ctx.tenant"}}
		]
	}`)
	doReq(t, srv, http.MethodPut, "/route_cov_idx", `{
		"mappings": {
			"_routing": {"required": true},
			"properties": {"tenant": {"type": "keyword"}, "v": {"type": "integer"}}
		},
		"aliases": {
			"route_cov_alias": {"index_routing": "alias-shard"}
		}
	}`)
	// Write via ingest pipeline that populates ctx._routing even without ?routing= query param
	cPipeRoute, pipeRouteRes := doReq(t, srv, http.MethodPut, "/route_cov_idx/_doc/1?pipeline=route_pipe&refresh=true", `{"tenant": "t-100", "v": 1}`)
	if cPipeRoute != http.StatusCreated || pipeRouteRes["_routing"] != "t-100" {
		t.Fatalf("expected ingest pipeline ctx._routing to satisfy _routing.required and return 't-100', got %d %+v", cPipeRoute, pipeRouteRes)
	}
	// Write via alias with index_routing
	cAliasRoute, aliasRouteRes := doReq(t, srv, http.MethodPut, "/route_cov_alias/_doc/2?refresh=true", `{"tenant": "t-200", "v": 2}`)
	if cAliasRoute != http.StatusCreated || aliasRouteRes["_routing"] != "alias-shard" {
		t.Fatalf("expected alias index_routing to satisfy _routing.required, got %d %+v", cAliasRoute, aliasRouteRes)
	}
	// _update with routing
	cUpdMissing, _ := doReq(t, srv, http.MethodPost, "/route_cov_idx/_update/1", `{"doc": {"v": 10}}`)
	if cUpdMissing != http.StatusBadRequest {
		t.Fatalf("expected _update without routing on _routing.required index to return 400, got %d", cUpdMissing)
	}
	cUpdOK, updRes := doReq(t, srv, http.MethodPost, "/route_cov_idx/_update/1?routing=t-100&refresh=true", `{"doc": {"v": 10}}`)
	if cUpdOK != http.StatusOK || updRes["_routing"] != "t-100" {
		t.Fatalf("expected _update with routing to return 200 and _routing='t-100', got %d %+v", cUpdOK, updRes)
	}
	// _update_by_query preserves existing document _routing
	cUBQ, _ := doReq(t, srv, http.MethodPost, "/route_cov_idx/_update_by_query?refresh=true", `{
		"script": {"source": "ctx._source.v = ctx._source.v + 1"}
	}`)
	if cUBQ != http.StatusOK {
		t.Fatalf("expected _update_by_query on routed index to succeed, got %d", cUBQ)
	}

	// 7. F25: dedup (dedupe alias, map elements, ignore_empty:false, error on non-array) & compact (array of maps, error on scalar)
	_, simRes := doReq(t, srv, http.MethodPost, "/_ingest/pipeline/_simulate", `{
		"pipeline": {
			"processors": [
				{"dedupe": {"field": "items", "target_field": "unique_items", "ignore_empty": false}},
				{"compact": {"field": "arr_of_maps", "target_field": "clean_arr"}}
			]
		},
		"docs": [
			{
				"_source": {
					"items": [{"id": 1}, {"id": 1}, {"id": 2}, ""],
					"arr_of_maps": [{"a": "", "b": "keep"}, {"c": null}]
				}
			}
		]
	}`)
	simDoc := simRes["docs"].([]any)[0].(map[string]any)["doc"].(map[string]any)["_source"].(map[string]any)
	if len(simDoc["unique_items"].([]any)) != 3 {
		t.Fatalf("expected unique_items length 3, got %+v", simDoc["unique_items"])
	}
	if len(simDoc["clean_arr"].([]any)) != 1 {
		t.Fatalf("expected clean_arr length 1 after compacting empty map element, got %+v", simDoc["clean_arr"])
	}

	// 8. F21, F22, F23, F24: Painless Pattern.compile, Matcher.find/replaceAll/replaceFirst/start/end/named group, sort lambda outer var, forEach + ctx._index, and UTF-8 indexOf/lastIndexOf with fromIndex
	pVal, err := painless.Eval(map[string]any{"s": "ééaé"}, `
		Pattern p = Pattern.compile("(?<word>[a-z]+)-(\\d+)");
		def m = p.matcher("id:foo-12,id:bar-34");
		String first = m.replaceFirst("$1");
		String all = m.replaceAll("$1");
		int found = 0;
		while (m.find()) {
			found += 1;
		}
		def m2 = p.matcher("foo-12");
		String grp = m2.matches() ? m2.group("word") + ":" + m2.start(1) + ":" + m2.end(1) : "none";
		String u = doc['s'].value;
		return first + "|" + all + "|" + found + "|" + grp + "|" + u.indexOf('é', 1) + "|" + u.lastIndexOf('é', 2);
	`, nil)
	if err != nil || pVal != "id:foo,id:bar-34|id:foo,id:bar|2|foo:0:3|1|1" {
		t.Fatalf("unexpected Painless Pattern/Matcher/UTF-8 result: val=%v err=%v", pVal, err)
	}

	docSort := map[string]any{"nums": []any{int64(3), int64(1), int64(2)}}
	sortParams := map[string]any{"_ctx_index": "orig_idx"}
	_, err = painless.EvalPainlessWithOp(docSort, `
		int comparisons = 0;
		ctx._source.nums.sort((a, b) -> {
			comparisons += 1;
			return a - b;
		});
		ctx._index = 'rerouted_idx';
		ctx._source.cmp_ok = (comparisons > 0);
	`, sortParams)
	if err != nil || docSort["cmp_ok"] != true || sortParams["_ctx_index"] != "rerouted_idx" {
		t.Fatalf("expected sort lambda to propagate outer var and preserve subsequent ctx._index='rerouted_idx', got doc=%+v params=%+v err=%v", docSort, sortParams, err)
	}
}
