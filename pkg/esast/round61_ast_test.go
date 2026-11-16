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

package esast

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRound61SearchStatsAndSliceStrings(t *testing.T) {
	var req SearchRequest
	if err := json.Unmarshal([]byte(`{
		"stats": ["g1", "g2"],
		"slice": {"id": "1", "max": "4"},
		"highlight": {"max_analyzed_offset": "20", "fields": {"msg": {"max_analyzed_offset": "15"}}}
	}`), &req); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if len(req.Stats) != 2 || req.Stats[0] != "g1" || req.Stats[1] != "g2" {
		t.Fatalf("unexpected stats: %+v", req.Stats)
	}
	if req.Slice == nil || req.Slice.ID != 1 || req.Slice.Max != 4 {
		t.Fatalf("unexpected slice: %+v", req.Slice)
	}
	if req.Highlight == nil || req.Highlight.MaxAnalyzedOffset == nil || *req.Highlight.MaxAnalyzedOffset != 20 {
		t.Fatalf("unexpected highlight max_analyzed_offset: %+v", req.Highlight)
	}
	if fs := req.Highlight.FieldSpec("msg"); fs.MaxAnalyzedOffset == nil || *fs.MaxAnalyzedOffset != 15 {
		t.Fatalf("unexpected highlight field max_analyzed_offset: %+v", fs)
	}
	if err := json.Unmarshal([]byte(`{"highlight": {"max_analyzed_offset": -1, "fields": {"msg": {}}}}`), &req); err == nil || !strings.Contains(err.Error(), "[max_analyzed_offset] must be a positive integer") {
		t.Fatalf("expected negative max_analyzed_offset error, got %v", err)
	}
	if err := json.Unmarshal([]byte(`{"stats": [123]}`), &req); err == nil {
		t.Fatalf("expected non-string stats element to fail")
	}
}

func TestRound61StandardAndKNNRetriever(t *testing.T) {
	var req SearchRequest
	if err := json.Unmarshal([]byte(`{
		"retriever": {
			"standard": {
				"query": {"match_all": {}},
				"filter": {"term": {"status": "ok"}},
				"sort": [{"age": "desc"}],
				"search_after": [42],
				"terminate_after": 5,
				"collapse": {"field": "grp"}
			}
		}
	}`), &req); err != nil {
		t.Fatalf("unexpected standard retriever error: %v", err)
	}
	if len(req.Sort) != 1 || len(req.SearchAfter) != 1 || req.TerminateAfter == nil || *req.TerminateAfter != 5 || req.Collapse == nil {
		t.Fatalf("standard retriever fields not lowered: %+v", req)
	}

	var knnReq SearchRequest
	if err := json.Unmarshal([]byte(`{
		"retriever": {
			"knn": {
				"field": "vec",
				"query_vector": "01ff80",
				"num_candidates": 25,
				"inner_hits": {"size": 2}
			}
		}
	}`), &knnReq); err != nil {
		t.Fatalf("unexpected knn retriever error: %v", err)
	}
	if len(knnReq.KNN) != 1 || knnReq.KNN[0].HasK || !knnReq.KNN[0].HasNumCandidates || knnReq.KNN[0].QueryVectorHex != "01ff80" || knnReq.KNN[0].InnerHits == nil {
		t.Fatalf("unexpected lowered knn spec: %+v", knnReq.KNN)
	}
}

func TestRound61DecodeHexSignedByteVectorAndQueryStringDepth(t *testing.T) {
	vec, err := DecodeHexSignedByteVector("01ff807f")
	if err != nil {
		t.Fatalf("unexpected DecodeHexSignedByteVector error: %v", err)
	}
	want := []float64{1, -1, -128, 127}
	for i := range want {
		if vec[i] != want[i] {
			t.Fatalf("vec[%d] = %v, want %v", i, vec[i], want[i])
		}
	}
	if _, err := DecodeHexSignedByteVector("abc"); err == nil {
		t.Fatalf("expected odd-length hex error")
	}

	deep := strings.Repeat("(", 65) + "foo" + strings.Repeat(")", 65)
	var q Query
	if err := json.Unmarshal([]byte(`{"query_string": {"query": "`+deep+`"}}`), &q); err == nil {
		t.Fatalf("expected depth > 64 error")
	}
	ok64 := strings.Repeat("(", 64) + "foo" + strings.Repeat(")", 64)
	if err := json.Unmarshal([]byte(`{"query_string": {"query": "`+ok64+`"}}`), &q); err != nil {
		t.Fatalf("expected depth == 64 to succeed, got %v", err)
	}
}

func TestRound61AggParsingAndFieldPropertyStrict(t *testing.T) {
	var req SearchRequest
	if err := json.Unmarshal([]byte(`{
		"aggs": {
			"ip_r": {
				"ip_range": {
					"field": "ip",
					"ranges": {
						"local": {"mask": "10.0.0.0/8"},
						"high": {"from": "192.168.0.1"}
					}
				}
			},
			"h": {"histogram": {"field": "price", "interval": "10.5"}},
			"st": {"significant_text": {"field": "txt", "filter_duplicate_text": true}},
			"mad": {"median_absolute_deviation": {"field": "price", "compression": 200}},
			"num_r": {"range": {"field": "price", "ranges": [{"to": 50}, {"from": 50, "to": 100}]}}
		}
	}`), &req); err != nil {
		t.Fatalf("unexpected agg unmarshal error: %v", err)
	}
	ipAgg := req.Aggs["ip_r"]
	if ipAgg.IPRange == nil || !ipAgg.IPRange.Keyed || len(ipAgg.IPRange.Ranges) != 2 || ipAgg.IPRange.Ranges[0].Key != "local" || ipAgg.IPRange.Ranges[1].Key != "high" {
		t.Fatalf("unexpected keyed ip_range: %+v", ipAgg.IPRange)
	}
	if req.Aggs["h"].Histogram == nil || req.Aggs["h"].Histogram.Interval != 10.5 {
		t.Fatalf("unexpected string histogram interval: %+v", req.Aggs["h"].Histogram)
	}
	if req.Aggs["st"].SignificantText == nil || req.Aggs["st"].SignificantText.FilterDuplicateText == nil || !*req.Aggs["st"].SignificantText.FilterDuplicateText {
		t.Fatalf("unexpected filter_duplicate_text: %+v", req.Aggs["st"].SignificantText)
	}
	if req.Aggs["mad"].MedianAbsoluteDeviation == nil || req.Aggs["mad"].MedianAbsoluteDeviation.Compression == nil || *req.Aggs["mad"].MedianAbsoluteDeviation.Compression != 200 {
		t.Fatalf("unexpected MAD compression: %+v", req.Aggs["mad"].MedianAbsoluteDeviation)
	}
	if got := req.Aggs["num_r"].Range.Ranges[0].EffectiveKey(); got != "*-50.0" {
		t.Fatalf("expected *-50.0, got %q", got)
	}
	if got := req.Aggs["num_r"].Range.Ranges[1].EffectiveKey(); got != "50.0-100.0" {
		t.Fatalf("expected 50.0-100.0, got %q", got)
	}

	// Empty filter / missing / filters validation
	for _, bad := range []string{
		`{"aggs": {"f": {"filter": {}}}}`,
		`{"aggs": {"m": {"missing": {}}}}`,
		`{"aggs": {"fs": {"filters": {"filters": [{}]}}}}`,
		`{"aggs": {"t": {"terms": {"field": "k", "include": "[unclosed"}}}}`,
	} {
		var badReq SearchRequest
		if err := json.Unmarshal([]byte(bad), &badReq); err == nil {
			t.Fatalf("expected error for %s", bad)
		}
	}

	// Strict FieldProperty TSDB & synthetic_source fields
	fp, err := UnmarshalFieldPropertyStrict([]byte(`{
		"type": "keyword",
		"time_series_dimension": true,
		"store_array_source": true
	}`))
	if err != nil {
		t.Fatalf("unexpected strict FieldProperty error: %v", err)
	}
	if fp.TimeSeriesDimension == nil || !*fp.TimeSeriesDimension || fp.StoreArraySource == nil || !*fp.StoreArraySource || fp.ExplicitDims {
		t.Fatalf("unexpected FieldProperty: %+v", fp)
	}
}
