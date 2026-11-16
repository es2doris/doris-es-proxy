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
	"math"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func loadDocsIntoMemoryBackend(t *testing.T, mb *MemoryBackend, idx *schema.IndexSchema, docs map[string]string) {
	t.Helper()
	ctx := context.Background()
	if err := mb.ExecDDL(ctx, schema.GenerateCreateTableDDL(idx)); err != nil {
		t.Fatalf("ExecDDL: %v", err)
	}
	var ndjson bytes.Buffer
	for id, raw := range docs {
		rowBytes, err := schema.ShredDocument(idx, id, 1, false, []byte(raw))
		if err != nil {
			t.Fatalf("ShredDocument(%s): %v", id, err)
		}
		ndjson.Write(rowBytes)
		ndjson.WriteByte('\n')
	}
	if err := mb.StreamLoad(ctx, idx.DorisTable, ndjson.Bytes(), false); err != nil {
		t.Fatalf("StreamLoad: %v", err)
	}
}

func TestRound61_MemBackend_KNNTopKHybridAndNestedVectors(t *testing.T) {
	ctx := context.Background()
	var ms esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"tag": {"type": "keyword"},
			"vec_l2": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "l2_norm"},
			"vec_cos": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "cosine"},
			"vec_mip": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "max_inner_product"},
			"vec_byte_dp": {"type": "dense_vector", "dims": 2, "element_type": "byte", "index": true, "similarity": "dot_product"},
			"chunks": {
				"type": "nested",
				"properties": {
					"emb": {"type": "dense_vector", "dims": 2, "index": true, "similarity": "l2_norm"}
				}
			}
		}
	}`), &ms); err != nil {
		t.Fatal(err)
	}
	idx := schema.CompileIndexSchema("es_db", "r61_knn_mem", &ms)
	idx.ES8Mode = true
	mb := NewMemoryBackend(false)

	loadDocsIntoMemoryBackend(t, mb, idx, map[string]string{
		"d1": `{"tag":"alpha","vec_l2":[1.0,2.0],"vec_cos":[1.0,0.0],"vec_mip":[3.0,0.0],"vec_byte_dp":"7f80","chunks":[{"emb":[10.0,10.0]},{"emb":[1.0,2.0]}]}`,
		"d2": `{"tag":"alpha","vec_l2":[4.0,6.0],"vec_cos":[0.0,1.0],"vec_mip":[1.0,0.0],"vec_byte_dp":"0000","chunks":[{"emb":[4.0,6.0]}]}`,
		"d3": `{"tag":"beta","vec_l2":[1.0,3.0],"vec_cos":[-1.0,0.0],"vec_mip":[-3.0,0.0],"vec_byte_dp":"807f","chunks":[{"emb":[1.0,2.5]}]}`,
		"d4": `{"tag":"gamma","vec_l2":[20.0,20.0],"vec_cos":[0.6,0.8],"vec_mip":[0.0,0.0],"vec_byte_dp":"0101","chunks":[{"emb":[50.0,50.0]}]}`,
	})

	tr := transpiler.NewTranspiler(idx, transpiler.TranspilerOptions{ES8Compat: true})

	// 1. Top-k bounding: k=2 with size=10 MUST return at most 2 hits (`d1` score=1.0, `d3` score=0.5).
	var topKReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 10,
		"knn": {"field": "vec_l2", "query_vector": [1.0, 2.0], "k": 2, "num_candidates": 4}
	}`), &topKReq); err != nil {
		t.Fatal(err)
	}
	plan, err := tr.BuildSearchPlan(&topKReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan top-k: %v", err)
	}
	hits, err := mb.QueryHits(ctx, plan.HitsSQL)
	if err != nil {
		t.Fatalf("QueryHits top-k: %v", err)
	}
	if len(hits) != 2 || hits[0].ID != "d1" || hits[1].ID != "d3" {
		t.Fatalf("expected top-2 hits [d1, d3], got %+v", hits)
	}
	if math.Abs(hits[0].Score-1.0) > 1e-6 || math.Abs(hits[1].Score-0.5) > 1e-6 {
		t.Fatalf("unexpected l2_norm scores: d1=%v (want 1.0), d3=%v (want 0.5)", hits[0].Score, hits[1].Score)
	}

	// 2. Hybrid req.KNN (k=1 -> d1) + req.Query (tag:gamma -> d4) with size=10 returns BOTH d1 and d4!
	var hybridReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 10,
		"query": {"term": {"tag": "gamma"}},
		"knn": {"field": "vec_l2", "query_vector": [1.0, 2.0], "k": 1, "num_candidates": 4}
	}`), &hybridReq); err != nil {
		t.Fatal(err)
	}
	hPlan, err := tr.BuildSearchPlan(&hybridReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan hybrid: %v", err)
	}
	hHits, err := mb.QueryHits(ctx, hPlan.HitsSQL)
	if err != nil {
		t.Fatalf("QueryHits hybrid: %v", err)
	}
	if len(hHits) != 2 {
		t.Fatalf("expected 2 hybrid hits (d1 from k=1 knn + d4 from query), got %+v", hHits)
	}

	// 3. Exact cosine, MIP (positive & negative inner product), and hex byte dot_product scores in MemoryBackend
	var cosReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size": 10, "knn": {"field": "vec_cos", "query_vector": [1.0, 0.0], "k": 4, "num_candidates": 4}}`), &cosReq)
	cosPlan, err := tr.BuildSearchPlan(&cosReq)
	if err != nil {
		t.Fatal(err)
	}
	cosHits, err := mb.QueryHits(ctx, cosPlan.HitsSQL)
	if err != nil || len(cosHits) != 4 {
		t.Fatalf("QueryHits cosine: err=%v hits=%+v", err, cosHits)
	}
	// d1: cos=1 -> 1.0, d4: cos=0.6 -> 0.8, d2: cos=0 -> 0.5, d3: cos=-1 -> 0.0
	if cosHits[0].ID != "d1" || math.Abs(cosHits[0].Score-1.0) > 1e-6 ||
		cosHits[1].ID != "d4" || math.Abs(cosHits[1].Score-0.8) > 1e-6 ||
		cosHits[2].ID != "d2" || math.Abs(cosHits[2].Score-0.5) > 1e-6 ||
		cosHits[3].ID != "d3" || math.Abs(cosHits[3].Score-0.0) > 1e-6 {
		t.Fatalf("unexpected cosine scores: %+v", cosHits)
	}

	var mipReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size": 10, "knn": {"field": "vec_mip", "query_vector": [1.0, 0.0], "k": 4, "num_candidates": 4}}`), &mipReq)
	mipPlan, err := tr.BuildSearchPlan(&mipReq)
	if err != nil {
		t.Fatal(err)
	}
	mipHits, err := mb.QueryHits(ctx, mipPlan.HitsSQL)
	if err != nil || len(mipHits) != 4 {
		t.Fatalf("QueryHits mip: err=%v hits=%+v", err, mipHits)
	}
	// d1: ip=3 -> 4.0, d2: ip=1 -> 2.0, d4: ip=0 -> 1.0, d3: ip=-3 -> 1/(1 - (-3)) = 0.25
	if math.Abs(mipHits[0].Score-4.0) > 1e-6 || math.Abs(mipHits[3].Score-0.25) > 1e-6 {
		t.Fatalf("unexpected MIP scores: %+v", mipHits)
	}

	var byteReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size": 10, "knn": {"field": "vec_byte_dp", "query_vector": "7f80", "k": 2, "num_candidates": 4}}`), &byteReq)
	bytePlan, err := tr.BuildSearchPlan(&byteReq)
	if err != nil {
		t.Fatal(err)
	}
	byteHits, err := mb.QueryHits(ctx, bytePlan.HitsSQL)
	if err != nil || len(byteHits) != 2 || byteHits[0].ID != "d1" {
		t.Fatalf("QueryHits byte dot_product: err=%v hits=%+v", err, byteHits)
	}
	wantByteScore := 0.5 + float64(127*127+128*128)/(32768.0*2.0)
	if math.Abs(byteHits[0].Score-wantByteScore) > 1e-6 {
		t.Fatalf("unexpected byte dot_product score: got %v, want %v", byteHits[0].Score, wantByteScore)
	}

	// 4. Nested child vector kNN with parent diversification (`ARRAY_MAX(array_map(_nel -> ...))`) + root filter
	var nestedReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 10,
		"knn": {
			"field": "chunks.emb",
			"query_vector": [1.0, 2.0],
			"k": 1,
			"num_candidates": 4,
			"filter": {"term": {"tag": "alpha"}},
			"boost": 2.0
		}
	}`), &nestedReq); err != nil {
		t.Fatal(err)
	}
	nPlan, err := tr.BuildSearchPlan(&nestedReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan nested knn: %v", err)
	}
	nHits, err := mb.QueryHits(ctx, nPlan.HitsSQL)
	if err != nil {
		t.Fatalf("QueryHits nested knn: %v", err)
	}
	if len(nHits) != 1 || nHits[0].ID != "d1" || math.Abs(nHits[0].Score-2.0) > 1e-6 {
		t.Fatalf("expected nested top-1 hit d1 with boosted score 2.0, got %+v", nHits)
	}
}

func TestRound61_MemBackend_RawValuesQuantilesRangeHistogramAndGeotile(t *testing.T) {
	ctx := context.Background()
	var ms esast.MappingSpec
	if err := json.Unmarshal([]byte(`{
		"properties": {
			"grp": {"type": "keyword"},
			"val": {"type": "double"},
			"rng": {"type": "integer_range"},
			"loc": {"type": "geo_point"}
		}
	}`), &ms); err != nil {
		t.Fatal(err)
	}
	idx := schema.CompileIndexSchema("es_db", "r61_agg_mem", &ms)
	mb := NewMemoryBackend(false)

	loadDocsIntoMemoryBackend(t, mb, idx, map[string]string{
		"1": `{"grp":"A","val":10,"rng":{"lte":10},"loc":{"lat":52.374081,"lon":4.912350}}`,
		"2": `{"grp":"A","val":20,"rng":{"gte":15},"loc":{"lat":52.374081,"lon":4.912350}}`,
		"3": `{"grp":"B","val":100,"rng":{"gte":5,"lte":7},"loc":{"lat":40.7128,"lon":-74.0060}}`,
	})

	tr := transpiler.NewTranspiler(idx, transpiler.TranspilerOptions{ES8Compat: true})

	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"size": 0,
		"aggs": {
			"p": {"percentiles": {"field": "val", "percents": [50, 95]}},
			"bp": {"boxplot": {"field": "val"}},
			"mad": {"median_absolute_deviation": {"field": "val"}},
			"by_grp": {
				"terms": {"field": "grp"},
				"aggs": {
					"sub_p": {"percentiles": {"field": "val", "percents": [50]}}
				}
			},
			"rng_hist": {
				"histogram": {
					"field": "rng",
					"interval": 5,
					"hard_bounds": {"min": 0, "max": 20}
				}
			},
			"tiles": {
				"composite": {
					"sources": [
						{"tile": {"geotile_grid": {"field": "loc", "precision": 6}}}
					]
				}
			}
		}
	}`), &req); err != nil {
		t.Fatal(err)
	}

	plan, err := tr.BuildSearchPlan(&req)
	if err != nil {
		t.Fatalf("BuildSearchPlan aggs: %v", err)
	}
	rows, err := mb.QueryAggs(ctx, plan.AggsSQL)
	if err != nil {
		t.Fatalf("QueryAggs: %v\nSQL:\n%s", err, plan.AggsSQL)
	}

	var topRawVals []float64
	groupedRawVals := make(map[string][]float64)
	rngHistCounts := make(map[string]int64)
	tileCounts := make(map[string]int64)

	for _, r := range rows {
		switch r.AggName {
		case transpiler.RawValuesAggPrefix + "p":
			_, vals, ok := transpiler.ParseCollectedFloatValues(r.BucketKey)
			if !ok {
				t.Fatalf("failed to parse top-level raw values from %q", r.BucketKey)
			}
			topRawVals = vals
		case transpiler.RawValuesAggPrefix + "by_grp.sub_p":
			pKey, vals, ok := transpiler.ParseCollectedFloatValues(r.BucketKey)
			if !ok {
				t.Fatalf("failed to parse grouped raw values from %q", r.BucketKey)
			}
			groupedRawVals[pKey] = vals
		case "rng_hist":
			rngHistCounts[r.BucketKey] = r.DocCount
		case "tiles":
			tileCounts[r.BucketKey] = r.DocCount
		}
	}

	if len(topRawVals) != 3 {
		t.Fatalf("expected 3 top-level collected values, got %v", topRawVals)
	}
	bp := transpiler.ComputeESBoxplotWithVersion(topRawVals, 100, true)
	if bp.Min == nil || *bp.Min != 10 || bp.Q2 == nil || *bp.Q2 != 20 || bp.Max == nil || *bp.Max != 100 {
		t.Fatalf("unexpected boxplot from collected values: %+v", bp)
	}
	mad := transpiler.ComputeESMedianAbsoluteDeviationWithVersion(topRawVals, 1000, true)
	if mad == nil || *mad != 10 {
		t.Fatalf("unexpected MAD from collected values: %v (want 10)", mad)
	}
	if len(groupedRawVals["A"]) != 2 || len(groupedRawVals["B"]) != 1 {
		t.Fatalf("unexpected grouped raw values: %+v", groupedRawVals)
	}

	// rng_hist with interval=5, hard_bounds=[0, 20]:
	// doc 1 (lte:10 -> [0,10]): buckets 0, 5, 10
	// doc 2 (gte:15 -> [15,20]): buckets 15, 20
	// doc 3 ([5,7]): bucket 5
	if rngHistCounts["0"] != 1 || rngHistCounts["5"] != 2 || rngHistCounts["10"] != 1 || rngHistCounts["15"] != 1 || rngHistCounts["20"] != 1 {
		t.Fatalf("unexpected integer_range histogram counts: %+v", rngHistCounts)
	}

	// Amsterdam zoom 6 tile = "6/32/21" (2 docs), NYC zoom 6 tile = "6/18/24" (1 doc)
	if tileCounts["6/32/21"] != 2 || tileCounts["6/18/24"] != 1 {
		t.Fatalf("unexpected composite geotile_grid buckets: %+v", tileCounts)
	}
}

func TestRound61_MemBackend_IgnoredDateNanosPrecisionAndSQLiEscape(t *testing.T) {
	ctx := context.Background()
	mal := true
	var ms esast.MappingSpec
	ms.Properties = map[string]esast.FieldProperty{
		"kw":      {Type: "keyword", IgnoreAbove: 5},
		"num":     {Type: "integer", IgnoreMalformed: &mal},
		"ts_nano": {Type: "date_nanos"},
	}
	idx := schema.CompileIndexSchema("es_db", "r61_misc_mem", &ms)
	mb := NewMemoryBackend(false)

	loadDocsIntoMemoryBackend(t, mb, idx, map[string]string{
		"1":    `{"kw":"too_long_value","num":42,"ts_nano":1700000000000000001}`,
		"2":    `{"kw":"ok","num":"not_an_int","ts_nano":1700000000000000002}`,
		`id\'`: `{"kw":"ok","num":7,"ts_nano":1700000000000000003}`,
	})

	tr := transpiler.NewTranspiler(idx, transpiler.TranspilerOptions{ES8Compat: true})

	// 1. _ignored regexp & exists queries
	var regReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query": {"regexp": {"_ignored": "k.*"}}}`), &regReq)
	regPlan, err := tr.BuildSearchPlan(&regReq)
	if err != nil {
		t.Fatal(err)
	}
	regHits, err := mb.QueryHits(ctx, regPlan.HitsSQL)
	if err != nil || len(regHits) != 1 || regHits[0].ID != "1" {
		t.Fatalf("expected _ignored regexp 'k.*' to match doc 1, got err=%v hits=%+v", err, regHits)
	}

	var exReq esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query": {"exists": {"field": "_ignored"}}}`), &exReq)
	exPlan, err := tr.BuildSearchPlan(&exReq)
	if err != nil {
		t.Fatal(err)
	}
	exHits, err := mb.QueryHits(ctx, exPlan.HitsSQL)
	if err != nil || len(exHits) != 2 {
		t.Fatalf("expected _ignored exists to match docs 1 and 2, got err=%v hits=%+v", err, exHits)
	}

	// 2. Full 64-bit nanosecond precision on date_nanos (1700000000000000001 vs 1700000000000000002)
	var nanoReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"query": {"range": {"ts_nano": {"gt": 1700000000000000001, "lte": 1700000000000000002}}}
	}`), &nanoReq); err != nil {
		t.Fatal(err)
	}
	nanoPlan, err := tr.BuildSearchPlan(&nanoReq)
	if err != nil {
		t.Fatal(err)
	}
	nanoHits, err := mb.QueryHits(ctx, nanoPlan.HitsSQL)
	if err != nil || len(nanoHits) != 1 || nanoHits[0].ID != "2" {
		t.Fatalf("expected exact nanosecond range (gt ..001, lte ..002] to match only doc 2, got err=%v hits=%+v\nSQL: %s", err, nanoHits, nanoPlan.HitsSQL)
	}

	// 3. Backslash-quote (\') ID lookup safety
	var sqliReq esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query": {"ids": {"values": ["id\\'"]}}}`), &sqliReq); err != nil {
		t.Fatal(err)
	}
	sqliPlan, err := tr.BuildSearchPlan(&sqliReq)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sqliPlan.HitsSQL, `'id\\'''`) {
		t.Fatalf("expected EscapeDorisSQLString escaping 'id\\\\''', got: %s", sqliPlan.HitsSQL)
	}
	sqliHits, err := mb.QueryHits(ctx, sqliPlan.HitsSQL)
	if err != nil || len(sqliHits) != 1 || sqliHits[0].ID != `id\'` {
		t.Fatalf("expected exact match for id\\', got err=%v hits=%+v", err, sqliHits)
	}
}
