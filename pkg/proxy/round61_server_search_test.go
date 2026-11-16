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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func mustCompileSchemaR61Search(t *testing.T, indexName string, rawMapping string) *schema.IndexSchema {
	t.Helper()
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatalf("unmarshal mapping for %s: %v", indexName, err)
	}
	return schema.CompileIndexSchema("es_db", indexName, &spec)
}

func mustParseSearchReqR61Search(t *testing.T, rawBody string) *esast.SearchRequest {
	t.Helper()
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(rawBody), &req); err != nil {
		t.Fatalf("SearchRequest Unmarshal failed: %v\nbody=%s", err, rawBody)
	}
	return &req
}

func mustDecodeJSONDocR61Search(t *testing.T, raw string) map[string]any {
	t.Helper()
	var doc map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode json doc: %v", err)
	}
	return doc
}

// ============================================================================
// F11: Hybrid `knn` Validation & Nested Vector `inner_hits`
// ============================================================================

func TestR61Search_F11_KNNValidationAndNestedInnerHits(t *testing.T) {
	knnReq := mustParseSearchReqR61Search(t, `{
		"knn": {
			"field": "chunks.vec",
			"query_vector": [1.0, 0.0],
			"k": 2,
			"num_candidates": 5,
			"inner_hits": {
				"name": "best_chunks",
				"size": 2,
				"fields": ["chunks.text"],
				"docvalue_fields": ["chunks.rank"]
			}
		}
	}`)

	// 1. Explicit `?search_type=` with top-level `knn` must fail with exact 400 illegal_argument_exception
	httpReqWithST := httptest.NewRequest(http.MethodPost, "/idx/_search?search_type=query_then_fetch", nil)
	st, errT, errR := validateSearchKNNRequestR61Search(httpReqWithST, knnReq)
	if st != http.StatusBadRequest || errT != "illegal_argument_exception" ||
		errR != "cannot set [search_type] when using [knn] search, since the search type is determined automatically" {
		t.Fatalf("unexpected search_type knn validation result: status=%d type=%q reason=%q", st, errT, errR)
	}

	// Without `?search_type=`, valid `k <= num_candidates` succeeds
	httpReqClean := httptest.NewRequest(http.MethodPost, "/idx/_search", nil)
	if st, errT, errR := validateSearchKNNRequestR61Search(httpReqClean, knnReq); st != 0 {
		t.Fatalf("expected valid knn request, got %d %s: %s", st, errT, errR)
	}

	// 2. `k > num_candidates` rejected on both top-level `knn` and query-level `knn`
	badTopKNN := &esast.SearchRequest{
		KNN: []esast.KNNSearchSpec{
			{Field: "chunks.vec", QueryVector: []float64{1.0, 0.0}, K: 10, HasK: true, NumCandidates: 5, HasNumCandidates: true},
		},
	}
	if st, errT, errR := validateSearchKNNRequestR61Search(httpReqClean, badTopKNN); st != http.StatusBadRequest || errT != "illegal_argument_exception" || !strings.Contains(errR, "num_candidates") {
		t.Fatalf("expected k > num_candidates error on top-level knn, got %d %s: %s", st, errT, errR)
	}

	badQueryKNN := &esast.SearchRequest{
		Query: &esast.Query{
			Bool: &esast.BoolQuery{
				Should: []esast.Query{
					{KNN: &esast.KNNQuery{Field: "chunks.vec", QueryVector: []float64{1.0, 0.0}, K: 8, HasK: true, NumCandidates: 3, HasNumCandidates: true}},
				},
			},
		},
	}
	if st, errT, errR := validateSearchKNNRequestR61Search(httpReqClean, badQueryKNN); st != http.StatusBadRequest || errT != "illegal_argument_exception" {
		t.Fatalf("expected k > num_candidates error on query knn, got %d %s: %s", st, errT, errR)
	}

	// 3. Nested float32 & byte vector `inner_hits` population
	idxSchema := mustCompileSchemaR61Search(t, "docs_vec", `{
		"properties": {
			"title": {"type": "keyword"},
			"chunks": {
				"type": "nested",
				"properties": {
					"text": {"type": "keyword"},
					"rank": {"type": "integer"},
					"vec": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "cosine"},
					"bvec": {"type": "dense_vector", "dims": 2, "element_type": "byte", "index": true, "similarity": "dot_product"}
				}
			}
		}
	}`)

	rawDoc := `{
		"title": "parent-1",
		"chunks": [
			{"text": "orthogonal", "rank": 20, "vec": [0.0, 1.0], "bvec": [0, 10]},
			{"text": "aligned", "rank": 10, "vec": [1.0, 0.0], "bvec": [10, 0]},
			{"text": "diagonal", "rank": 15, "vec": [0.7071, 0.7071], "bvec": [5, 5]}
		]
	}`
	doc := mustDecodeJSONDocR61Search(t, rawDoc)
	hit := HitRow{
		ID:     "doc-1",
		Index:  "docs_vec",
		Score:  1.0,
		Source: json.RawMessage(rawDoc),
	}

	innerOut := populateNestedKNNInnerHitsR61Search(&hit, doc, idxSchema, knnReq)
	bc, ok := innerOut["best_chunks"].(map[string]any)
	if !ok {
		t.Fatalf("expected inner_hits.best_chunks, got %+v", innerOut)
	}
	hitsWrapper, _ := bc["hits"].(map[string]any)
	totalMap, _ := hitsWrapper["total"].(map[string]any)
	if totalMap["value"] != int64(3) {
		t.Fatalf("expected inner_hits total=3, got %+v", totalMap)
	}
	innerList, ok := hitsWrapper["hits"].([]map[string]any)
	if !ok || len(innerList) != 2 {
		t.Fatalf("expected 2 sized inner hits, got %+v", hitsWrapper["hits"])
	}
	// Best child is offset 1 ("aligned", cosine=1.0 -> ES score (1+1)/2 = 1.0)
	nestedMeta0, _ := innerList[0]["_nested"].(map[string]any)
	if nestedMeta0["field"] != "chunks" || nestedMeta0["offset"] != 1 {
		t.Fatalf("expected top inner hit offset=1 on chunks, got %+v", nestedMeta0)
	}
	if sc0, _ := innerList[0]["_score"].(float64); math.Abs(sc0-1.0) > 1e-5 {
		t.Fatalf("expected top inner hit _score=1.0, got %v", sc0)
	}
	fields0, _ := innerList[0]["fields"].(map[string][]any)
	if !reflect.DeepEqual(fields0["chunks.text"], []any{"aligned"}) {
		t.Fatalf("expected fields[chunks.text]=[aligned], got %+v", fields0)
	}
	if !reflect.DeepEqual(fields0["chunks.rank"], []any{int64(10)}) {
		t.Fatalf("expected docvalue_fields chunks.rank=[10], got %+v", fields0)
	}

	// Query-level nested `byte` vector `inner_hits`
	byteQueryReq := mustParseSearchReqR61Search(t, `{
		"query": {
			"knn": {
				"field": "chunks.bvec",
				"query_vector": [10, 0],
				"k": 1,
				"num_candidates": 3,
				"inner_hits": {"size": 1, "_source": ["text"]}
			}
		}
	}`)
	innerByteOut := populateNestedKNNInnerHitsR61Search(&hit, doc, idxSchema, byteQueryReq)
	defInner, ok := innerByteOut["chunks"].(map[string]any)
	if !ok {
		t.Fatalf("expected default inner_hits key chunks, got %+v", innerByteOut)
	}
	bHits, _ := defInner["hits"].(map[string]any)["hits"].([]map[string]any)
	if len(bHits) != 1 || bHits[0]["_nested"].(map[string]any)["offset"] != 1 {
		t.Fatalf("unexpected byte knn inner_hits: %+v", bHits)
	}
	srcFiltered, _ := bHits[0]["_source"].(map[string]any)
	if srcFiltered["text"] != "aligned" || len(srcFiltered) != 1 {
		t.Fatalf("expected filtered child _source={text:aligned}, got %+v", srcFiltered)
	}
}

// ============================================================================
// F13: Unified Search Fetch Pipeline, `stored_fields`, Synthetic `_source` & `_ignored`
// ============================================================================

func TestR61Search_F13_UnifiedFetchStoredFieldsSyntheticAndIgnored(t *testing.T) {
	// 1. `?force_synthetic_source=true` validation & reconstruction
	unstoredTextSchema := mustCompileSchemaR61Search(t, "bad_synth", `{
		"properties": {
			"body": {"type": "text"}
		}
	}`)
	reqSynthURL := httptest.NewRequest(http.MethodPost, "/bad_synth/_search?force_synthetic_source=true", nil)
	if force, st, errT, errR := validateAndResolveForceSyntheticSourceR61Search(reqSynthURL, []*schema.IndexSchema{unstoredTextSchema}); st != http.StatusBadRequest || errT != "illegal_argument_exception" || force {
		t.Fatalf("expected 400 illegal_argument_exception on unstored text force_synthetic_source, got force=%v st=%d %s: %s", force, st, errT, errR)
	}

	reqBadBool := httptest.NewRequest(http.MethodPost, "/ok_synth/_search?force_synthetic_source=notabool", nil)
	if _, st, errT, _ := validateAndResolveForceSyntheticSourceR61Search(reqBadBool, nil); st != http.StatusBadRequest || errT != "illegal_argument_exception" {
		t.Fatalf("expected 400 on invalid force_synthetic_source bool, got %d %s", st, errT)
	}

	synthSchema := mustCompileSchemaR61Search(t, "ok_synth", `{
		"_source": {"mode": "synthetic"},
		"properties": {
			"tags": {"type": "keyword"},
			"env": {"type": "constant_keyword", "value": "prod"},
			"ip_addr": {"type": "ip"}
		}
	}`)
	if force, st, errT, errR := validateAndResolveForceSyntheticSourceR61Search(reqSynthURL, []*schema.IndexSchema{synthSchema}); !force || st != 0 {
		t.Fatalf("expected force=true st=0 on valid synthetic schema, got force=%v st=%d %s: %s", force, st, errT, errR)
	}

	reconBytes := reconstructHitSyntheticSourceR61Search(
		json.RawMessage(`{"tags":["zeta","alpha"],"ip_addr":"2001:0db8:0000:0000:0000:0000:0000:0001"}`),
		synthSchema,
	)
	reconMap := mustDecodeJSONDocR61Search(t, string(reconBytes))
	if reconMap["env"] != "prod" {
		t.Fatalf("expected missing constant_keyword env=prod injected in synthetic source, got %+v", reconMap)
	}
	if reconMap["ip_addr"] != "2001:db8::1" {
		t.Fatalf("expected canonical IPv6 2001:db8::1 in synthetic source, got %v", reconMap["ip_addr"])
	}
	if !reflect.DeepEqual(reconMap["tags"], []any{"alpha", "zeta"}) {
		t.Fatalf("expected sorted tags [alpha, zeta], got %+v", reconMap["tags"])
	}

	// 2. `stored_fields` separation (`_none_`, `[]`, `store: true` + `_routing`)
	fetchSchema := mustCompileSchemaR61Search(t, "fetch_idx", `{
		"properties": {
			"stored_kw": {"type": "keyword", "store": true},
			"unstored_kw": {"type": "keyword"},
			"ts_ns": {"type": "date_nanos"},
			"big_long": {"type": "long"},
			"big_ulong": {"type": "unsigned_long"},
			"f32": {"type": "float"},
			"hf16": {"type": "half_float"},
			"sf": {"type": "scaled_float", "scaling_factor": 100},
			"flag": {"type": "boolean"},
			"client_ip": {"type": "ip"},
			"ver": {"type": "version"},
			"const_k": {"type": "constant_keyword", "value": "fixed-const"},
			"flat": {"type": "flattened"},
			"tc": {"type": "token_count", "analyzer": "standard"},
			"short_kw": {"type": "keyword", "ignore_above": 5},
			"safe_int": {"type": "integer", "ignore_malformed": true},
			"items": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"qty": {"type": "integer"}
				}
			}
		}
	}`)

	rawFetchDoc := `{
		"stored_kw": "kept-in-store",
		"unstored_kw": "only-in-source",
		"ts_ns": "2023-05-01T12:34:56.123456789Z",
		"big_long": 9223372036854775806,
		"big_ulong": 18446744073709551614,
		"f32": 1.23456789,
		"hf16": 1.5,
		"sf": 12.346,
		"flag": "true",
		"client_ip": "::ffff:192.168.1.42",
		"ver": "1.2.0",
		"flat": {"host": "web-01", "ports": [443, 80]},
		"tc": "quick brown fox",
		"short_kw": "exceeds_limit",
		"safe_int": "not_an_int",
		"items": [
			{"sku": "B2", "qty": 2},
			{"sku": "A1", "qty": 5}
		]
	}`
	fetchHit := HitRow{
		ID:      "h1",
		Index:   "fetch_idx",
		Routing: "shard-key-7",
		Version: 1,
		Source:  json.RawMessage(rawFetchDoc),
	}

	sfNone, supNone, hasNone := extractStoredFieldsOnlyR61Search(fetchHit, "fetch_idx", "_none_", fetchSchema)
	if sfNone != nil || !supNone || !hasNone {
		t.Fatalf("expected (_none_) -> (nil, true, true), got (%v, %v, %v)", sfNone, supNone, hasNone)
	}
	sfEmpty, supEmpty, hasNoneEmpty := extractStoredFieldsOnlyR61Search(fetchHit, "fetch_idx", []any{}, fetchSchema)
	if sfEmpty != nil || !supEmpty || hasNoneEmpty {
		t.Fatalf("expected ([]) -> (nil, true, false), got (%v, %v, %v)", sfEmpty, supEmpty, hasNoneEmpty)
	}
	sfExplicit, supExp, hasNoneExp := extractStoredFieldsOnlyR61Search(
		fetchHit,
		"fetch_idx",
		[]any{"stored_kw", "unstored_kw", "_routing", "_id"},
		fetchSchema,
	)
	if !supExp || hasNoneExp {
		t.Fatalf("unexpected flags on explicit stored_fields: sup=%v hasNone=%v", supExp, hasNoneExp)
	}
	if !reflect.DeepEqual(sfExplicit["stored_kw"], []any{"kept-in-store"}) {
		t.Fatalf("expected stored_kw=[kept-in-store], got %+v", sfExplicit)
	}
	if !reflect.DeepEqual(sfExplicit["_routing"], []any{"shard-key-7"}) {
		t.Fatalf("expected _routing=[shard-key-7], got %+v", sfExplicit)
	}
	if _, leaked := sfExplicit["unstored_kw"]; leaked {
		t.Fatalf("unstored_kw must NOT be returned by stored_fields: %+v", sfExplicit)
	}
	if _, leakedID := sfExplicit["_id"]; leakedID {
		t.Fatalf("_id must NOT be returned as a stored field: %+v", sfExplicit)
	}

	// 3. `extractUnifiedFieldsR61Search`: exact 64-bit precision, `date_nanos`, `constant_keyword`, `flattened`, `nested`, `runtime`
	unifiedReq := mustParseSearchReqR61Search(t, `{
		"fields": [
			"ts_ns",
			{"field": "ts_ns", "format": "epoch_nanos"},
			"big_long",
			"big_ulong",
			"f32",
			"hf16",
			"sf",
			"flag",
			"client_ip",
			"ver",
			"const_k",
			"flat",
			"flat.ports",
			"tc",
			"items.sku",
			"rt_double"
		],
		"docvalue_fields": [
			{"field": "ts_ns", "format": "epoch_millis"},
			"items.qty"
		]
	}`)
	runtimeDoc := map[string]any{"rt_double": []any{float64(42.5)}}
	uFields, st, errT, errR := extractUnifiedFieldsR61Search(fetchHit, "fetch_idx", unifiedReq, fetchSchema, runtimeDoc)
	if st != 0 {
		t.Fatalf("extractUnifiedFieldsR61Search failed: %d %s: %s", st, errT, errR)
	}
	// Note: second `ts_ns` entry in `fields` had `epoch_nanos`, and `docvalue_fields` had `epoch_millis`; test individual calls too for exact isolation!
	isoOnlyReq := mustParseSearchReqR61Search(t, `{"fields": ["ts_ns"]}`)
	isoFields, st, _, _ := extractUnifiedFieldsR61Search(fetchHit, "fetch_idx", isoOnlyReq, fetchSchema, nil)
	if st != 0 || !reflect.DeepEqual(isoFields["ts_ns"], []any{"2023-05-01T12:34:56.123456789Z"}) {
		t.Fatalf("expected exact ISO-8601 nanos string, got st=%d fields=%+v", st, isoFields["ts_ns"])
	}
	nanosReq := mustParseSearchReqR61Search(t, `{"fields": [{"field": "ts_ns", "format": "epoch_nanos"}]}`)
	nanosFields, st, _, _ := extractUnifiedFieldsR61Search(fetchHit, "fetch_idx", nanosReq, fetchSchema, nil)
	if st != 0 || !reflect.DeepEqual(nanosFields["ts_ns"], []any{int64(1682944496123456789)}) {
		t.Fatalf("expected exact int64 epoch_nanos=1682944496123456789, got %T %+v", nanosFields["ts_ns"][0], nanosFields["ts_ns"])
	}
	millisReq := mustParseSearchReqR61Search(t, `{"docvalue_fields": [{"field": "ts_ns", "format": "epoch_millis"}]}`)
	millisFields, st, _, _ := extractUnifiedFieldsR61Search(fetchHit, "fetch_idx", millisReq, fetchSchema, nil)
	if st != 0 || !reflect.DeepEqual(millisFields["ts_ns"], []any{int64(1682944496123)}) {
		t.Fatalf("expected exact int64 epoch_millis=1682944496123, got %+v", millisFields["ts_ns"])
	}

	if !reflect.DeepEqual(uFields["big_long"], []any{int64(9223372036854775806)}) {
		t.Fatalf("expected exact int64 big_long, got %T %+v", uFields["big_long"][0], uFields["big_long"])
	}
	if !reflect.DeepEqual(uFields["big_ulong"], []any{uint64(18446744073709551614)}) {
		t.Fatalf("expected exact uint64 big_ulong, got %T %+v", uFields["big_ulong"][0], uFields["big_ulong"])
	}
	if !reflect.DeepEqual(uFields["flag"], []any{true}) {
		t.Fatalf("expected boolean flag=[true], got %+v", uFields["flag"])
	}
	if !reflect.DeepEqual(uFields["client_ip"], []any{"192.168.1.42"}) {
		t.Fatalf("expected canonical IPv4 192.168.1.42, got %+v", uFields["client_ip"])
	}
	if !reflect.DeepEqual(uFields["const_k"], []any{"fixed-const"}) {
		t.Fatalf("expected constant_keyword [fixed-const] even when absent from _source, got %+v", uFields["const_k"])
	}
	if !reflect.DeepEqual(uFields["sf"], []any{float64(12.35)}) {
		t.Fatalf("expected scaled_float [12.35], got %+v", uFields["sf"])
	}
	if !reflect.DeepEqual(uFields["tc"], []any{int64(3)}) {
		t.Fatalf("expected token_count [3], got %+v", uFields["tc"])
	}
	if !reflect.DeepEqual(uFields["flat.ports"], []any{"443", "80"}) {
		t.Fatalf("expected flattened subkey leaf slice [443, 80], got %+v", uFields["flat.ports"])
	}
	if len(uFields["flat"]) != 1 {
		t.Fatalf("expected whole flattened object in fields[flat], got %+v", uFields["flat"])
	}
	// Nested `fields` groups under `items` whereas `docvalue_fields` flattens to `items.qty`
	if len(uFields["items"]) != 2 {
		t.Fatalf("expected hierarchical nested fields[items] len=2, got %+v", uFields["items"])
	}
	if !reflect.DeepEqual(uFields["items.qty"], []any{int64(2), int64(5)}) {
		t.Fatalf("expected flat docvalue_fields[items.qty]=[2, 5], got %+v", uFields["items.qty"])
	}
	if !reflect.DeepEqual(uFields["rt_double"], []any{float64(42.5)}) {
		t.Fatalf("expected runtime field rt_double=[42.5], got %+v", uFields["rt_double"])
	}

	// Format validation error on incompatible field type
	badFmtReq := mustParseSearchReqR61Search(t, `{"fields": [{"field": "stored_kw", "format": "yyyy-MM-dd"}]}`)
	if _, st, errT, errR := extractUnifiedFieldsR61Search(fetchHit, "fetch_idx", badFmtReq, fetchSchema, nil); st != http.StatusBadRequest || errT != "illegal_argument_exception" || !strings.Contains(errR, "doesn't support formats") {
		t.Fatalf("expected 400 illegal_argument_exception on date format over keyword, got %d %s: %s", st, errT, errR)
	}

	// 4. `_ignored` extraction (`short_kw` exceeded `ignore_above: 5`, `safe_int` triggered `ignore_malformed: true`)
	ignored := extractHitIgnoredFieldsR61Search(fetchHit, fetchSchema)
	if !reflect.DeepEqual(ignored, []string{"safe_int", "short_kw"}) {
		t.Fatalf("expected sorted _ignored=[safe_int, short_kw], got %+v", ignored)
	}
}

// ============================================================================
// F15 & F16: Exact Quantiles, Pipeline Guards, `moving_fn`, `typed_keys` & Nested `top_hits`
// ============================================================================

func TestR61Search_F15_F16_ExactQuantilesPipelineMovingFnAndNestedTopHits(t *testing.T) {
	// 1. `stripAndApplyExactQuantilesR61Search`: strips `__raw_vals__*` and computes exact TDigest/HDR/boxplot/MAD
	qReq := mustParseSearchReqR61Search(t, `{
		"aggs": {
			"p_tdigest": {"percentiles": {"field": "v", "percents": [50, 95]}},
			"pr": {"percentile_ranks": {"field": "v", "values": [25, 75]}},
			"box": {"boxplot": {"field": "v"}},
			"mad": {"median_absolute_deviation": {"field": "v"}},
			"by_cat": {
				"terms": {"field": "cat"},
				"aggs": {
					"sub_p": {"percentiles": {"field": "v", "percents": [50]}}
				}
			}
		}
	}`)

	aggRows := []AggRow{
		{AggName: "p_tdigest", BucketKey: "_global", DocCount: 5},
		{AggName: transpiler.RawValuesAggPrefix + "p_tdigest", BucketKey: "_vals:10,20,30,40,50", DocCount: 5},
		{AggName: transpiler.RawValuesAggPrefix + "pr", BucketKey: "_vals:10,20,30,40,50", DocCount: 5},
		{AggName: transpiler.RawValuesAggPrefix + "box", BucketKey: "_vals:10,20,30,40,50", DocCount: 5},
		{AggName: transpiler.RawValuesAggPrefix + "mad", BucketKey: "_vals:10,20,30,40,50", DocCount: 5},
		{AggName: "by_cat", BucketKey: "alpha", DocCount: 3},
		{AggName: transpiler.RawValuesAggPrefix + "by_cat.sub_p", BucketKey: "alpha\x1f_vals:5,15,25", DocCount: 3},
	}
	builtAggs := map[string]any{
		"p_tdigest": map[string]any{"values": map[string]any{"50.0": 999.0}},
		"pr":        map[string]any{"values": map[string]any{}},
		"box":       map[string]any{"min": nil},
		"mad":       map[string]any{"value": nil},
		"by_cat": map[string]any{
			"buckets": []map[string]any{
				{
					"key":       "alpha",
					"doc_count": int64(3),
					"sub_p":     map[string]any{"values": map[string]any{"50.0": 0.0}},
				},
			},
		},
	}

	cleanedRows, err := stripAndApplyExactQuantilesR61Search(aggRows, qReq.Aggs, builtAggs, true)
	if err != nil {
		t.Fatalf("stripAndApplyExactQuantilesR61Search failed: %v", err)
	}
	if len(cleanedRows) != 2 {
		t.Fatalf("expected all __raw_vals__ rows stripped (leaving 2 rows), got %d: %+v", len(cleanedRows), cleanedRows)
	}
	for _, r := range cleanedRows {
		if strings.HasPrefix(r.AggName, transpiler.RawValuesAggPrefix) {
			t.Fatalf("leaked internal raw values agg row: %+v", r)
		}
	}
	pVals := builtAggs["p_tdigest"].(map[string]any)["values"].(map[string]any)
	if pVals["50.0"] != float64(30) {
		t.Fatalf("expected exact 50th percentile = 30, got %+v", pVals)
	}
	boxMap := builtAggs["box"].(map[string]any)
	if boxMap["min"] != float64(10) || boxMap["q2"] != float64(30) || boxMap["max"] != float64(50) {
		t.Fatalf("unexpected boxplot exact values: %+v", boxMap)
	}
	madMap := builtAggs["mad"].(map[string]any)
	if madMap["value"] != float64(10) {
		t.Fatalf("expected exact MAD = 10, got %+v", madMap)
	}
	subPVals := builtAggs["by_cat"].(map[string]any)["buckets"].([]map[string]any)[0]["sub_p"].(map[string]any)["values"].(map[string]any)
	if subPVals["50.0"] != float64(15) {
		t.Fatalf("expected nested bucket exact 50th percentile = 15, got %+v", subPVals)
	}

	// Negative value in HDR percentiles -> `illegal_argument_exception`
	hdrReq := mustParseSearchReqR61Search(t, `{
		"aggs": {"p_hdr": {"percentiles": {"field": "v", "hdr": {"number_of_significant_value_digits": 3}}}}
	}`)
	hdrRows := []AggRow{
		{AggName: transpiler.RawValuesAggPrefix + "p_hdr", BucketKey: "_vals:-5,10,20", DocCount: 3},
	}
	hdrBuilt := map[string]any{"p_hdr": map[string]any{"values": map[string]any{}}}
	if _, err := stripAndApplyExactQuantilesR61Search(hdrRows, hdrReq.Aggs, hdrBuilt, true); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("expected illegal_argument_exception on negative HDR values, got %v", err)
	}

	// 2. `validatePipelineAndSamplerAggsR61Search`
	invalidPipeCases := []struct {
		name string
		json string
	}{
		{
			name: "single_bucket_parent_filter_with_derivative",
			json: `{"aggs":{"f":{"filter":{"term":{"a":"b"}},"aggs":{"s":{"sum":{"field":"x"}},"d":{"derivative":{"buckets_path":"s"}}}}}}`,
		},
		{
			name: "top_level_moving_fn_without_parent",
			json: `{"aggs":{"avg_v":{"avg":{"field":"v"}},"mf":{"moving_fn":{"buckets_path":"avg_v","window":2,"script":"MovingFunctions.max(values)"}}}}`,
		},
		{
			name: "multi_value_stats_without_submetric",
			json: `{"aggs":{"h":{"histogram":{"field":"v","interval":10},"aggs":{"st":{"stats":{"field":"v"}}}},"avg_s":{"avg_bucket":{"buckets_path":"h>st"}}}}`,
		},
	}
	for _, tc := range invalidPipeCases {
		r := mustParseSearchReqR61Search(t, tc.json)
		if st, _, _ := validatePipelineAndSamplerAggsR61Search(r.Aggs); st != http.StatusBadRequest {
			t.Fatalf("case %s: expected 400 validation error, got status=%d", tc.name, st)
		}
	}
	// Programmatic `moving_fn` window <= 0 and `diversified_sampler` max_docs_per_value <= 0 checks
	if st, _, _ := validatePipelineAndSamplerAggsR61Search(map[string]esast.AggSpec{
		"h": {
			Histogram: &esast.HistogramAggSpec{Field: "v", Interval: 10},
			Aggs: map[string]esast.AggSpec{
				"a":  {Avg: &esast.MetricAggSpec{Field: "v"}},
				"mf": {MovingFn: &esast.MovingAvgAggSpec{BucketsPath: "a", Window: 0, Script: "MovingFunctions.min(values)"}},
			},
		},
	}); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on moving_fn window=0, got %d", st)
	}
	if st, _, _ := validatePipelineAndSamplerAggsR61Search(map[string]esast.AggSpec{
		"ds": {DiversifiedSampler: &esast.SamplerAggSpec{Field: "k", MaxDocsPerValue: -1}},
	}); st != http.StatusBadRequest {
		t.Fatalf("expected 400 on diversified_sampler max_docs_per_value=-1, got %d", st)
	}

	// Valid `buckets_path` with `>` sub-metric and `[99.9]` bracket percentile selector must pass!
	validPipeReq := mustParseSearchReqR61Search(t, `{
		"aggs": {
			"h": {
				"histogram": {"field": "v", "interval": 10},
				"aggs": {
					"p": {"percentiles": {"field": "v", "percents": [50, 99.9]}},
					"mf": {"moving_fn": {"buckets_path": "p[99.9]", "window": 2, "script": "MovingFunctions.min(values)"}}
				}
			},
			"ab": {"avg_bucket": {"buckets_path": "h>p[50]"}}
		}
	}`)
	if st, errT, errR := validatePipelineAndSamplerAggsR61Search(validPipeReq.Aggs); st != 0 {
		t.Fatalf("expected valid bracket buckets_path to succeed, got %d %s: %s", st, errT, errR)
	}

	// 3. `evalMovingFnWindowR61Search` exact ES `MovingFunctions` semantics
	sumZero, err := evalMovingFnWindowR61Search(nil, &esast.MovingAvgAggSpec{Window: 2, Script: "MovingFunctions.sum(values)"})
	if err != nil || sumZero != float64(0) {
		t.Fatalf("expected MovingFunctions.sum([]) == 0.0, got %v (err=%v)", sumZero, err)
	}
	for _, fn := range []string{
		"MovingFunctions.min(values)",
		"MovingFunctions.max(values)",
		"MovingFunctions.unweightedAvg(values)",
		"MovingFunctions.linearWeightedAvg(values)",
		"MovingFunctions.ewma(values, 0.3)",
		"MovingFunctions.holt(values, 0.3, 0.1)",
		"MovingFunctions.holtWinters(values, 0.3, 0.1, 0.1, 2, false)",
		"MovingFunctions.stdDev(values, MovingFunctions.unweightedAvg(values))",
	} {
		got, err := evalMovingFnWindowR61Search(nil, &esast.MovingAvgAggSpec{Window: 3, Script: fn})
		if err != nil || got != nil {
			t.Fatalf("expected %s on empty window to return (nil, nil), got (%v, %v)", fn, got, err)
		}
	}

	// `linearWeightedAvg`: [1]->0.5, [1,2]->1.25, [1,2,1]->8/7 (~1.142857)
	lwa1, _ := evalMovingFnWindowR61Search([]float64{1}, &esast.MovingAvgAggSpec{Window: 3, Script: "MovingFunctions.linearWeightedAvg(values)"})
	lwa2, _ := evalMovingFnWindowR61Search([]float64{1, 2}, &esast.MovingAvgAggSpec{Window: 3, Script: "MovingFunctions.linearWeightedAvg(values)"})
	lwa3, _ := evalMovingFnWindowR61Search([]float64{1, 2, 1}, &esast.MovingAvgAggSpec{Window: 3, Script: "MovingFunctions.linearWeightedAvg(values)"})
	if math.Abs(lwa1.(float64)-0.5) > 1e-6 || math.Abs(lwa2.(float64)-1.25) > 1e-6 || math.Abs(lwa3.(float64)-(8.0/7.0)) > 1e-6 {
		t.Fatalf("unexpected linearWeightedAvg values: %v, %v, %v", lwa1, lwa2, lwa3)
	}

	// `holt` on `moving_fn.yml` windows -> 1.000, 1.300, 1.231, 2.369
	holtSpec := &esast.MovingAvgAggSpec{Window: 3, Script: "MovingFunctions.holt(values, 0.3, 0.1)"}
	for _, tc := range []struct {
		win  []float64
		want float64
	}{
		{[]float64{1}, 1.000},
		{[]float64{1, 2}, 1.300},
		{[]float64{1, 2, 1}, 1.231},
		{[]float64{2, 1, 4}, 2.369},
		{[]float64{1, 4, 5}, 2.893},
	} {
		got, err := evalMovingFnWindowR61Search(tc.win, holtSpec)
		if err != nil || math.Abs(got.(float64)-tc.want) > 0.0005 {
			t.Fatalf("holt(%v): expected %.3f ± 0.0005, got %v (err=%v)", tc.win, tc.want, got, err)
		}
	}

	// `holtWinters` guarded by `if (values.length > 4)` (`moving_fn.yml:445-454`)
	hwSpec := &esast.MovingAvgAggSpec{
		Window: 5,
		Script: "if (values.length > 4) {MovingFunctions.holtWinters(values, 0.3, 0.1, 0.1, 2, false)}",
	}
	hwShort, err := evalMovingFnWindowR61Search([]float64{1, 2}, hwSpec)
	if err != nil || hwShort != float64(0) {
		t.Fatalf("expected guarded holtWinters on len=2 to return 0.0, got %v (err=%v)", hwShort, err)
	}
	hwFull, err := evalMovingFnWindowR61Search([]float64{1, 2, 1, 4, 5}, hwSpec)
	if err != nil || math.Abs(hwFull.(float64)-4.028) > 0.0005 {
		t.Fatalf("expected holtWinters([1,2,1,4,5]) == 4.028 ± 0.0005, got %v (err=%v)", hwFull, err)
	}

	// 4. `normalizeTypedKeysForPipelineLookupR61Search`
	typedIn := map[string]any{
		"sterms#by_tag": map[string]any{
			"buckets": map[string]any{
				"c#lang": map[string]any{
					"doc_count": int64(4),
					"avg#a":     map[string]any{"value": 12.5},
				},
			},
		},
	}
	normTyped := normalizeTypedKeysForPipelineLookupR61Search(typedIn)
	byTag := normTyped["by_tag"].(map[string]any)
	cLangBucket := byTag["buckets"].(map[string]any)["c#lang"].(map[string]any)
	if cLangBucket["a"].(map[string]any)["value"] != 12.5 {
		t.Fatalf("expected typed prefix stripped on agg names while preserving bucket key c#lang: %+v", normTyped)
	}

	// 5. `evaluateNestedTopHitsAggR61Search`
	nestedSchema := mustCompileSchemaR61Search(t, "orders", `{
		"properties": {
			"lines": {
				"type": "nested",
				"properties": {
					"sku": {"type": "keyword"},
					"price": {"type": "double"}
				}
			}
		}
	}`)
	parentHits := []HitRow{
		{
			ID:     "ord-1",
			Index:  "orders",
			Score:  1.0,
			Source: json.RawMessage(`{"lines":[{"sku":"cheap","price":5.0},{"sku":"premium","price":99.0}]}`),
		},
	}
	filterReq := mustParseSearchReqR61Search(t, `{
		"query": {"range": {"lines.price": {"gte": 20}}},
		"aggs": {"th": {"top_hits": {"size": 2}}}
	}`)
	nthOut := evaluateNestedTopHitsAggR61Search("lines", parentHits, filterReq.Query, filterReq.Aggs["th"].TopHits, nestedSchema)
	nthHits := nthOut["hits"].(map[string]any)["hits"].([]map[string]any)
	if len(nthHits) != 1 {
		t.Fatalf("expected 1 filtered nested child hit, got %+v", nthHits)
	}
	if nthHits[0]["_nested"].(map[string]any)["offset"] != 1 || nthHits[0]["_nested"].(map[string]any)["field"] != "lines" {
		t.Fatalf("expected nested child offset=1 on field=lines, got %+v", nthHits[0]["_nested"])
	}

	// 6. `collectAggDeprecationWarningsR61Search`
	depReq := mustParseSearchReqR61Search(t, `{"aggs":{"t":{"terms":{"field":"k","order":{"_term":"asc"}}}}}`)
	w7 := collectAggDeprecationWarningsR61Search(depReq.Aggs, false)
	w8 := collectAggDeprecationWarningsR61Search(depReq.Aggs, true)
	if len(w7) != 1 || w7[0] != "Deprecated aggregation order key [_term] used, replaced by [_key]" || len(w8) != 0 {
		t.Fatalf("unexpected deprecation warnings: w7=%+v w8=%+v", w7, w8)
	}
}

// ============================================================================
// F17: `intervals` Queries Routing & Span Saturation Scoring
// ============================================================================

func TestR61Search_F17_IntervalsEvalAndScoring(t *testing.T) {
	ivSchema := mustCompileSchemaR61Search(t, "iv_idx", `{
		"properties": {
			"body": {"type": "text"},
			"title": {"type": "text"},
			"min_len": {"type": "integer"}
		}
	}`)
	ivReq := mustParseSearchReqR61Search(t, `{
		"query": {
			"bool": {
				"must": [
					{
						"intervals": {
							"body": {
								"all_of": {
									"ordered": true,
									"max_gaps": 2,
									"intervals": [
										{"match": {"query": "quick"}},
										{"prefix": {"prefix": "fo"}},
										{"match": {"query": "urgent", "use_field": "title"}}
									],
									"filter": {
										"script": {
											"source": "interval.gaps <= doc['min_len'].value"
										}
									}
								}
							}
						}
					}
				]
			}
		}
	}`)

	if !queryNeedsIntervalsEvalR61Search(ivReq.Query) {
		t.Fatalf("expected queryNeedsIntervalsEvalR61Search=true")
	}

	matchDoc := mustDecodeJSONDocR61Search(t, `{"body":"the quick brown fox jumps","title":"a b c d e urgent dispatch","min_len":5}`)
	matched, score, err := evalAndScoreIntervalsQueryOnDocR61Search(ivSchema, matchDoc, ivReq.Query, true)
	if err != nil || !matched || score <= 0 || score > 1.0 {
		t.Fatalf("expected intervals match with (0, 1] saturation score, got matched=%v score=%v err=%v", matched, score, err)
	}

	missDoc := mustDecodeJSONDocR61Search(t, `{"body":"the fox jumps over quick dog","title":"a b c d e urgent dispatch","min_len":5}`)
	matchedMiss, scoreMiss, err := evalAndScoreIntervalsQueryOnDocR61Search(ivSchema, missDoc, ivReq.Query, true)
	if err != nil || matchedMiss || scoreMiss != 0 {
		t.Fatalf("expected unordered doc not to match ordered all_of intervals, got matched=%v score=%v err=%v", matchedMiss, scoreMiss, err)
	}
}

// ============================================================================
// F18: Highlighter Validation / `max_analyzed_offset` & `completion` Suggester
// ============================================================================

func TestR61Search_F18_HighlightAndCompletionSuggest(t *testing.T) {
	hlSchema := mustCompileSchemaR61Search(t, "hl_idx", `{
		"_source": {"mode": "synthetic"},
		"properties": {
			"body": {"type": "text", "synthetic_source_keep": "arrays"},
			"short_tag": {"type": "keyword", "ignore_above": 4}
		}
	}`)
	customSettings := map[string]map[string]any{
		"hl_idx": {
			"index.highlight.max_analyzed_offset": 20,
			"__term_vector.body":                  "no",
		},
	}

	// 1. Empty / mismatched tags rejected
	mismatchedTagsReq := &esast.SearchRequest{
		Highlight: &esast.HighlightSpec{
			PreTags:  []string{"<em>", "<strong>"},
			PostTags: []string{"</em>"},
			Fields:   map[string]any{"body": map[string]any{}},
		},
	}
	if st, errT, _ := validateHighlightRequestR61Search(mismatchedTagsReq, []*schema.IndexSchema{hlSchema}, customSettings); st != http.StatusBadRequest || errT != "illegal_argument_exception" {
		t.Fatalf("expected 400 on mismatched pre_tags/post_tags, got %d %s", st, errT)
	}

	// 2. Request `max_analyzed_offset` > index `index.highlight.max_analyzed_offset` -> 400
	exceedIdxMaxReq := mustParseSearchReqR61Search(t, `{
		"highlight": {
			"max_analyzed_offset": 50,
			"fields": {"body": {}}
		}
	}`)
	if st, errT, _ := validateHighlightRequestR61Search(exceedIdxMaxReq, []*schema.IndexSchema{hlSchema}, customSettings); st != http.StatusBadRequest || errT != "illegal_argument_exception" {
		t.Fatalf("expected 400 when request max_analyzed_offset > index setting, got %d %s", st, errT)
	}

	// 3. FVH without `with_positions_offsets` -> 400
	fvhBadReq := mustParseSearchReqR61Search(t, `{
		"highlight": {"fields": {"body": {"type": "fvh"}}}
	}`)
	if st, errT, _ := validateHighlightRequestR61Search(fvhBadReq, []*schema.IndexSchema{hlSchema}, customSettings); st != http.StatusBadRequest || errT != "illegal_argument_exception" {
		t.Fatalf("expected 400 for FVH without term_vector=with_positions_offsets, got %d %s", st, errT)
	}

	// 4. `checkHighlightDocMaxAnalyzedOffsetR61Search`: errors when doc > index max without request truncation, truncates when request `max_analyzed_offset` set
	longDoc := mustDecodeJSONDocR61Search(t, `{"body":"this document text is way longer than twenty characters","short_tag":"superlongignored"}`)
	plainHLReq := mustParseSearchReqR61Search(t, `{"highlight": {"fields": {"body": {}, "short_tag": {}}}}`)
	if _, st, errT, _ := checkHighlightDocMaxAnalyzedOffsetR61Search(longDoc, plainHLReq, hlSchema, 20); st != http.StatusBadRequest || errT != "illegal_argument_exception" {
		t.Fatalf("expected 400 when doc length > index.highlight.max_analyzed_offset, got %d %s", st, errT)
	}
	// If only `short_tag` is highlighted and its value exceeds `ignore_above: 4`, it is ignored and must NOT trip `max_analyzed_offset`!
	ignOnlyReq := mustParseSearchReqR61Search(t, `{"highlight": {"fields": {"short_tag": {}}}}`)
	if _, st, _, _ := checkHighlightDocMaxAnalyzedOffsetR61Search(longDoc, ignOnlyReq, hlSchema, 10); st != 0 {
		t.Fatalf("expected ignored field exceeding ignore_above not to fail max_analyzed_offset, got %d", st)
	}
	// Request `max_analyzed_offset: 15` <= index limit 20 -> returns `truncLimit == 15` without error!
	reqTrunc := mustParseSearchReqR61Search(t, `{"highlight": {"max_analyzed_offset": 15, "fields": {"body": {}}}}`)
	if trunc, st, _, _ := checkHighlightDocMaxAnalyzedOffsetR61Search(longDoc, reqTrunc, hlSchema, 20); st != 0 || trunc != 15 {
		t.Fatalf("expected truncLimit=15 st=0, got trunc=%d st=%d", trunc, st)
	}

	// 5. `evaluateCompletionSuggestSpecR61Search`: weighted inputs, mandatory contexts, category + geo neighbours, fuzzy, regex, skip_duplicates
	srv, handler := newRound60MemoryServer(t, "8.15.5")
	code, _, _, raw := doRound60Req(t, handler, http.MethodPut, "/places_sug", `{
		"mappings": {
			"properties": {
				"suggest_cat": {
					"type": "completion",
					"contexts": [
						{"name": "place_type", "type": "category", "path": "cat"},
						{"name": "loc", "type": "geo", "precision": 6}
					]
				},
				"suggest_plain": {
					"type": "completion"
				},
				"cat": {"type": "keyword"}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("create places_sug failed: %d %s", code, raw)
	}

	for id, docBody := range map[string]string{
		"1": `{"cat":"cafe","suggest_cat":{"input":["Starbucks Reserve","Starbucks"],"weight":10,"contexts":{"loc":{"lat":40.7128,"lon":-74.0060}}},"suggest_plain":["Starbucks","Starlight"]}`,
		"2": `{"cat":"restaurant","suggest_cat":{"input":"Star Diner","weight":5,"contexts":{"loc":{"lat":40.7130,"lon":-74.0062}}},"suggest_plain":{"input":"Starbucks","weight":20}}`,
	} {
		c, _, _, r := doRound60Req(t, handler, http.MethodPut, "/places_sug/_doc/"+id+"?refresh=true", docBody, nil)
		if c != http.StatusCreated {
			t.Fatalf("index doc %s failed: %d %s", id, c, r)
		}
	}

	// Missing mandatory contexts -> 400 illegal_argument_exception
	missingCtxReq := mustParseSearchReqR61Search(t, `{
		"suggest": {
			"s": {"prefix": "star", "completion": {"field": "suggest_cat"}}
		}
	}`)
	if _, st, errT, _ := evaluateCompletionSuggestSpecR61Search(srv, context.Background(), []string{"places_sug"}, "", missingCtxReq.Suggest["s"]); st != http.StatusBadRequest || errT != "illegal_argument_exception" {
		t.Fatalf("expected 400 when mandatory contexts omitted, got %d %s", st, errT)
	}

	// Category boost + geo neighbours
	ctxSugReq := mustParseSearchReqR61Search(t, `{
		"suggest": {
			"s": {
				"prefix": "star",
				"completion": {
					"field": "suggest_cat",
					"contexts": {
						"place_type": [{"context": "cafe", "boost": 3}],
						"loc": [{"context": {"lat": 40.7129, "lon": -74.0061}, "precision": 6, "neighbours": [6], "boost": 2}]
					}
				}
			}
		}
	}`)
	entries, st, errT, errR := evaluateCompletionSuggestSpecR61Search(srv, context.Background(), []string{"places_sug"}, "", ctxSugReq.Suggest["s"])
	if st != 0 || len(entries) != 1 {
		t.Fatalf("context completion failed: st=%d %s: %s entries=%+v", st, errT, errR, entries)
	}
	opts, _ := entries[0]["options"].([]map[string]any)
	if len(opts) == 0 || opts[0]["_id"] != "1" || opts[0]["_score"].(float64) != 30.0 {
		t.Fatalf("expected doc 1 with weight(10)*boost(3)=30.0 first, got %+v", opts)
	}

	// Fuzzy + `skip_duplicates: true` on `suggest_plain` ("strab" -> transposition fuzzy match on "starbucks")
	fuzzySugReq := mustParseSearchReqR61Search(t, `{
		"suggest": {
			"s": {
				"prefix": "strab",
				"completion": {
					"field": "suggest_plain",
					"skip_duplicates": true,
					"fuzzy": {"fuzziness": 1, "transpositions": true}
				}
			}
		}
	}`)
	fEntries, st, errT, errR := evaluateCompletionSuggestSpecR61Search(srv, context.Background(), []string{"places_sug"}, "", fuzzySugReq.Suggest["s"])
	if st != 0 {
		t.Fatalf("fuzzy completion failed: %d %s: %s", st, errT, errR)
	}
	fOpts := fEntries[0]["options"].([]map[string]any)
	if len(fOpts) != 1 || fOpts[0]["text"] != "Starbucks" || fOpts[0]["_score"].(float64) != 20.0 {
		t.Fatalf("expected deduplicated Starbucks with highest weight 20.0, got %+v", fOpts)
	}

	// Regex completion
	regexSugReq := mustParseSearchReqR61Search(t, `{
		"suggest": {
			"s": {
				"regex": "starl.*",
				"completion": {"field": "suggest_plain"}
			}
		}
	}`)
	rEntries, st, _, _ := evaluateCompletionSuggestSpecR61Search(srv, context.Background(), []string{"places_sug"}, "", regexSugReq.Suggest["s"])
	if st != 0 || len(rEntries[0]["options"].([]map[string]any)) != 1 {
		t.Fatalf("expected 1 regex completion match for starl.*, got st=%d %+v", st, rEntries)
	}
}

// ============================================================================
// F19: PIT, Collapse, Profile, `_name` Scores, Multi-Doc Percolate & `_rank_eval`
// ============================================================================

func TestR61Search_F19_PITCollapseProfileMatchedQueriesPercolateRankEval(t *testing.T) {
	// 1. PIT validation & `_shard_doc` tie-breaker
	pitReq := mustParseSearchReqR61Search(t, `{"pit": {"id": "pit-abc"}}`)
	if st, errT, errR := validatePITWithIndexPathR61Search("my_idx", pitReq); st != http.StatusBadRequest || errT != "illegal_argument_exception" || !strings.Contains(errR, "[pit] cannot be used with index") {
		t.Fatalf("expected 400 when PIT used with index path, got %d %s: %s", st, errT, errR)
	}
	if st, _, _ := validatePITWithIndexPathR61Search("", pitReq); st != 0 {
		t.Fatalf("expected valid PIT without index path, got %d", st)
	}
	ensurePITShardDocTieBreakerR61Search(pitReq)
	if len(pitReq.Sort) != 2 || pitReq.Sort[0].Entry.Field != "_score" || pitReq.Sort[1].Entry.Field != "_shard_doc" || pitReq.Sort[1].Entry.Order != "asc" {
		t.Fatalf("expected [_score desc, _shard_doc asc] injected for PIT, got %+v", pitReq.Sort)
	}

	// 2. Collapse array of `inner_hits` + second-level `collapse`
	colSchema := mustCompileSchemaR61Search(t, "col_idx", `{
		"properties": {
			"tenant": {"type": "keyword"},
			"region": {"type": "keyword"},
			"price": {"type": "double"}
		}
	}`)
	colReq := mustParseSearchReqR61Search(t, `{
		"collapse": {
			"field": "tenant",
			"inner_hits": [
				{
					"name": "cheapest_by_region",
					"size": 5,
					"sort": [{"price": "asc"}],
					"collapse": {"field": "region"}
				},
				{
					"name": "most_expensive",
					"size": 1,
					"sort": [{"price": "desc"}]
				}
			]
		}
	}`)
	groupHits := []HitRow{
		{ID: "1", Index: "col_idx", Score: 2.0, Source: json.RawMessage(`{"tenant":"t1","region":"us","price":30}`)},
		{ID: "2", Index: "col_idx", Score: 1.5, Source: json.RawMessage(`{"tenant":"t1","region":"us","price":10}`)},
		{ID: "3", Index: "col_idx", Score: 1.2, Source: json.RawMessage(`{"tenant":"t1","region":"eu","price":20}`)},
	}
	colInner := expandCollapseInnerHitsAndSecondLevelR61Search(groupHits[0], groupHits, colReq.Collapse, colSchema, nil)
	byReg := colInner["cheapest_by_region"].(map[string]any)["hits"].(map[string]any)["hits"].([]map[string]any)
	if len(byReg) != 2 || byReg[0]["_id"] != "2" || byReg[1]["_id"] != "3" {
		t.Fatalf("expected 2 second-level collapsed region hits [doc2(us,10), doc3(eu,20)], got %+v", byReg)
	}
	mostExp := colInner["most_expensive"].(map[string]any)["hits"].(map[string]any)["hits"].([]map[string]any)
	if len(mostExp) != 1 || mostExp[0]["_id"] != "1" {
		t.Fatalf("expected most_expensive=[doc1], got %+v", mostExp)
	}

	// 3. `buildSearchProfilePayloadR61Search`
	profNoneReq := mustParseSearchReqR61Search(t, `{"profile": true, "stored_fields": "_none_", "knn": {"field": "v", "query_vector": [1, 0], "k": 2, "num_candidates": 4}}`)
	profOut := buildSearchProfilePayloadR61Search("prof_idx", profNoneReq, 250_000)
	shard0 := profOut["shards"].([]map[string]any)[0]
	if _, hasDFS := shard0["dfs"]; !hasDFS {
		t.Fatalf("expected dfs profile section when knn present: %+v", shard0)
	}
	fetchObj := shard0["fetch"].(map[string]any)
	if _, hasChildren := fetchObj["children"]; hasChildren {
		t.Fatalf("expected no FetchSourcePhase children when stored_fields=_none_, got %+v", fetchObj)
	}
	if sfDbg := fetchObj["debug"].(map[string]any)["stored_fields"].([]string); len(sfDbg) != 0 {
		t.Fatalf("expected empty debug.stored_fields when stored_fields=_none_, got %+v", sfDbg)
	}

	// 4. `formatMatchedQueriesWithScoresR61Search`
	nqSchema := mustCompileSchemaR61Search(t, "nq_idx", `{"properties":{"tag":{"type":"keyword"}}}`)
	nqReq := mustParseSearchReqR61Search(t, `{
		"query": {
			"bool": {
				"should": [
					{"term": {"tag": {"value": "go", "_name": "q_go", "boost": 2.5}}},
					{"term": {"tag": {"value": "rust", "_name": "q_rust", "boost": 4.0}}}
				]
			}
		}
	}`)
	nqDoc := mustDecodeJSONDocR61Search(t, `{"tag":"go"}`)
	namesOnly := formatMatchedQueriesWithScoresR61Search(nqDoc, nqSchema, nqReq.Query, false)
	if !reflect.DeepEqual(namesOnly, []string{"q_go"}) {
		t.Fatalf("expected []string{q_go}, got %+v", namesOnly)
	}
	namesScored := formatMatchedQueriesWithScoresR61Search(nqDoc, nqSchema, nqReq.Query, true).(map[string]float64)
	if namesScored["q_go"] <= 0 {
		t.Fatalf("expected positive score map for q_go, got %+v", namesScored)
	}

	// 5. `evalMultiDocPercolateR61Search`
	percSchema := mustCompileSchemaR61Search(t, "perc_idx", `{
		"properties": {
			"query": {"type": "percolator"},
			"severity": {"type": "keyword"}
		}
	}`)
	percReq := mustParseSearchReqR61Search(t, `{
		"query": {
			"percolate": {
				"field": "query",
				"documents": [
					{"severity": "info"},
					{"severity": "critical"},
					{"severity": "critical"}
				]
			}
		}
	}`)
	storedQueryDoc := mustDecodeJSONDocR61Search(t, `{"query": {"term": {"severity": {"value": "critical", "boost": 3.0}}}}`)
	pMatched, pBest, pSlots, pSlotScores := evalMultiDocPercolateR61Search(percSchema, storedQueryDoc, percReq.Query.Percolate)
	if !pMatched || !reflect.DeepEqual(pSlots, []int{1, 2}) || pBest <= 0 || len(pSlotScores) != 2 {
		t.Fatalf("unexpected multi-doc percolate result: matched=%v best=%v slots=%v scores=%v", pMatched, pBest, pSlots, pSlotScores)
	}

	// 6. `computeRankEvalMetricR61Search` (`ndcg` full-ideal IDCG + `expected_reciprocal_rank`)
	// Suppose query has 2 relevant docs in corpus ("d1":3, "d_unretrieved":3), and search only returns ["d1"] at rank 1 (`k=2`).
	// DCG = (2^3 - 1)/log2(2) = 7.0; Full-ideal IDCG across ALL positive ratings up to k=2 is 7.0/log2(2) + 7.0/log2(3) = 7.0 + 7.0/1.5849625 = 11.416508!
	ndcgScore, _, err := computeRankEvalMetricR61Search(
		"ndcg",
		map[string]any{"k": 2},
		[]string{"d1"},
		map[string]float64{"d1": 3, "d_unretrieved": 3},
	)
	if err != nil {
		t.Fatalf("ndcg failed: %v", err)
	}
	wantNDCG := 7.0 / (7.0 + 7.0/math.Log2(3.0))
	if math.Abs(ndcgScore-wantNDCG) > 1e-6 {
		t.Fatalf("expected full-ideal ndcg=%v, got %v", wantNDCG, ndcgScore)
	}

	// `expected_reciprocal_rank` (`ERR`): `maximum_relevance = 3` (`2^3 = 8`), hit1 rating=2 (`R = 3/8`), hit2 rating=3 (`R = 7/8`):
	// ERR = 1*(3/8)/1 + (1 - 3/8)*(7/8)/2 = 0.375 + (5/8)*(7/16) = 0.375 + 35/128 = 0.6484375
	errScore, _, err := computeRankEvalMetricR61Search(
		"expected_reciprocal_rank",
		map[string]any{"maximum_relevance": 3, "k": 5},
		[]string{"h1", "h2"},
		map[string]float64{"h1": 2, "h2": 3},
	)
	if err != nil || math.Abs(errScore-0.6484375) > 1e-9 {
		t.Fatalf("expected ERR=0.6484375, got %v (err=%v)", errScore, err)
	}
}

// ============================================================================
// F24, F25, F26, F28: `script_fields`, `script_score` & `_explain`
// ============================================================================

func TestR61Search_F24_F25_F26_F28_ScriptFieldsScriptScoreAndExplain(t *testing.T) {
	srv, _ := newRound60MemoryServer(t, "8.15.5")
	scSchema := mustCompileSchemaR61Search(t, "sc_idx", `{
		"properties": {
			"price": {"type": "double"},
			"qty": {"type": "long"}
		}
	}`)
	hits := []HitRow{
		{ID: "1", Index: "sc_idx", Score: 2.0, Source: json.RawMessage(`{"price":12.5,"qty":4}`)},
	}
	schemas := map[string]*schema.IndexSchema{"sc_idx": scSchema}
	httpReq := httptest.NewRequest(http.MethodPost, "/sc_idx/_search", nil)

	// 1. `evalSearchScriptFieldsR61Search` success + `ignore_failure: true` + phase error when `ignore_failure: false`
	sfReq := mustParseSearchReqR61Search(t, `{
		"script_fields": {
			"total": {"script": {"source": "doc['price'].value * doc['qty'].value"}},
			"ignored_err": {"script": {"source": "1 / 0"}, "ignore_failure": true}
		}
	}`)
	sfOut, st, errPayload := evalSearchScriptFieldsR61Search(srv, httpReq, hits, schemas, sfReq)
	if st != 0 || errPayload != nil {
		t.Fatalf("expected script_fields success, got st=%d err=%+v", st, errPayload)
	}
	if !reflect.DeepEqual(sfOut[0]["total"], []any{float64(50)}) {
		t.Fatalf("expected script_fields total=[50], got %+v", sfOut)
	}
	if _, hasIgnored := sfOut[0]["ignored_err"]; hasIgnored {
		t.Fatalf("expected ignored_err omitted when ignore_failure=true, got %+v", sfOut[0])
	}

	sfFailReq := mustParseSearchReqR61Search(t, `{
		"script_fields": {
			"boom": {"script": {"source": "1 / 0"}}
		}
	}`)
	if _, st, errPayload := evalSearchScriptFieldsR61Search(srv, httpReq, hits, schemas, sfFailReq); st != http.StatusBadRequest || errPayload == nil {
		t.Fatalf("expected 400 search_phase_execution_exception on script_fields runtime error, got st=%d payload=%+v", st, errPayload)
	}

	// 2. `evalAndValidateSearchScriptScoreR61Search`: single boost multiplication + negative score rejection
	doc := mustDecodeJSONDocR61Search(t, `{"price":10.0,"qty":3}`)
	ssReq := mustParseSearchReqR61Search(t, `{
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"boost": 2.5,
				"script": {"source": "doc['qty'].value * 4.0"}
			}
		}
	}`)
	scVal, matched, st, errPayload := evalAndValidateSearchScriptScoreR61Search(scSchema, doc, ssReq.Query, 1.0, true)
	// Script returns 12.0; boost=2.5 applied ONCE -> 30.0 (NOT 75.0!)
	if st != 0 || !matched || math.Abs(scVal-30.0) > 1e-9 {
		t.Fatalf("expected single-boosted script_score=30.0, got sc=%v matched=%v st=%d err=%+v", scVal, matched, st, errPayload)
	}

	negReq := mustParseSearchReqR61Search(t, `{
		"query": {
			"script_score": {
				"query": {"match_all": {}},
				"script": {"source": "-1.0"}
			}
		}
	}`)
	if _, _, st, errPayload := evalAndValidateSearchScriptScoreR61Search(scSchema, doc, negReq.Query, 1.0, true); st != http.StatusBadRequest || errPayload == nil {
		t.Fatalf("expected 400 error on negative script_score, got st=%d payload=%+v", st, errPayload)
	}

	// 3. `formatTermWeightExplainDescriptionR61Search` & `buildScriptScoreExplainTreeR61Search`
	desc := formatTermWeightExplainDescriptionR61Search("title", "doris", 0)
	if desc != "weight(title:doris in 0) [PerFieldSimilarity], result of:" {
		t.Fatalf("unexpected PerFieldSimilarity explain description: %q", desc)
	}
	subExp := map[string]any{"value": 1.0, "description": "*:*", "details": []map[string]any{}}
	expNode, st, errPayload := buildScriptScoreExplainTreeR61Search(scSchema, doc, ssReq.Query, 1.0, subExp, true)
	if st != 0 || errPayload != nil || expNode["value"] != float64(30.0) {
		t.Fatalf("unexpected script_score explain node: st=%d node=%+v err=%+v", st, expNode, errPayload)
	}
}

// ============================================================================
// Race Detector Concurrency Verification
// ============================================================================

func TestR61Search_ConcurrentRaceSafety(t *testing.T) {
	sc := mustCompileSchemaR61Search(t, "race_idx", `{
		"_source": {"mode": "synthetic"},
		"properties": {
			"k": {"type": "keyword", "store": true},
			"ts": {"type": "date_nanos"},
			"v": {"type": "long"},
			"body": {"type": "text", "synthetic_source_keep": "arrays"}
		}
	}`)
	req := mustParseSearchReqR61Search(t, `{
		"fields": ["k", "ts", "v"],
		"query": {
			"intervals": {
				"body": {"match": {"query": "hello world", "ordered": true}}
			}
		}
	}`)
	mfSpec := &esast.MovingAvgAggSpec{
		Window: 5,
		Script: "MovingFunctions.holtWinters(values, 0.3, 0.1, 0.1, 2, false)",
	}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			raw := fmt.Sprintf(`{"k":"val-%d","ts":"2024-01-02T03:04:05.123456789Z","v":%d,"body":"hello world again"}`, id, 100+id)
			var doc map[string]any
			dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
			dec.UseNumber()
			_ = dec.Decode(&doc)
			h := HitRow{ID: fmt.Sprintf("%d", id), Index: "race_idx", Score: 1.0, Source: json.RawMessage(raw)}

			_ = reconstructHitSyntheticSourceR61Search(h.Source, sc)
			_, _, _ = extractStoredFieldsOnlyR61Search(h, "race_idx", []any{"k"}, sc)
			_, _, _, _ = extractUnifiedFieldsR61Search(h, "race_idx", req, sc, nil)
			_, _, _ = evalAndScoreIntervalsQueryOnDocR61Search(sc, doc, req.Query, true)
			_, _ = evalMovingFnWindowR61Search([]float64{1, 2, 1, 4, 5}, mfSpec)
			_, _, _ = computeRankEvalMetricR61Search("ndcg", map[string]any{"k": 3}, []string{"a", "b"}, map[string]float64{"a": 3, "c": 2})
		}(g)
	}
	wg.Wait()
}
