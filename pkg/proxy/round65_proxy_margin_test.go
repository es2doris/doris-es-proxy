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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func doR65MarginReq(t *testing.T, srv *Server, method, path, body string, headers ...[2]string) (int, map[string]any, string) {
	t.Helper()
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	} else {
		bodyReader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	if len(bytes.TrimSpace(rec.Body.Bytes())) > 0 {
		dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
		dec.UseNumber()
		_ = dec.Decode(&parsed)
	}
	return rec.Code, parsed, raw
}

func TestRound65_Wave1A_RRFWindowPinnedMovingPercentilesCumulativeAndLegacySort(t *testing.T) {
	srv, _ := newTestServer()
	srv.SetTargetESVersion("8.15.5")

	st, _, raw := doR65MarginReq(t, srv, http.MethodPut, "/r65_w1a", `{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"tag": {"type": "keyword"},
				"ts": {"type": "date"},
				"step": {"type": "long"},
				"price": {"type": "double"},
				"user": {"type": "keyword"},
				"items": {
					"type": "nested",
					"properties": {
						"tag": {"type": "keyword"},
						"score": {"type": "double"}
					}
				}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create index failed: %d %s", st, raw)
	}

	bulkBody := strings.Join([]string{
		`{"index":{"_index":"r65_w1a","_id":"1"}}`,
		`{"title":"alpha beta","tag":"a","ts":"2026-01-01T00:00:00Z","step":0,"price":10,"user":"u1","items":[{"tag":"x","score":1}]}`,
		`{"index":{"_index":"r65_w1a","_id":"2"}}`,
		`{"title":"alpha gamma","tag":"b","ts":"2026-01-01T01:00:00Z","step":10,"price":20,"user":"u1","items":[{"tag":"x","score":2}]}`,
		`{"index":{"_index":"r65_w1a","_id":"3"}}`,
		`{"title":"beta gamma","tag":"b","ts":"2026-01-01T01:00:00Z","step":10,"price":40,"user":"u2","items":[{"tag":"y","score":5}]}`,
		`{"index":{"_index":"r65_w1a","_id":"4"}}`,
		`{"title":"delta","tag":"c","ts":"2026-01-01T03:00:00Z","step":30,"price":80,"user":"u3","items":[{"tag":"y","score":9}]}`,
		"",
	}, "\n")
	if bst, _, braw := doR65MarginReq(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody); bst != http.StatusOK {
		t.Fatalf("bulk failed: %d %s", bst, braw)
	}

	// 1. ValidateRRFWindowSize with URL `?size=1` override vs window_size=2
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/r65_w1a/_search?size=1", `{
		"sub_searches": [
			{"query": {"match": {"title": "alpha"}}},
			{"query": {"term": {"tag": "c"}}}
		],
		"rank": {
			"rrf": {"window_size": 2, "rank_constant": 20}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("expected ?size=1 override with rrf.window_size=2 to succeed, got %d: %s", st, raw)
	}
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/r65_w1a/_search", `{
		"size": 5,
		"sub_searches": [{"query": {"match_all": {}}}],
		"rank": {"rrf": {"window_size": 2}}
	}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "rank_window_size") {
		t.Fatalf("expected 400 rank_window_size error, got %d: %s", st, raw)
	}
	st, mRes, raw := doR65MarginReq(t, srv, http.MethodPost, "/_msearch", "{\"index\":\"r65_w1a\"}\n{\"size\":5,\"sub_searches\":[{\"query\":{\"match_all\":{}}}],\"rank\":{\"rrf\":{\"window_size\":2}}}\n")
	if st != http.StatusOK {
		t.Fatalf("expected _msearch 200 envelope, got %d: %s", st, raw)
	}
	mItems, _ := mRes["responses"].([]any)
	if len(mItems) != 1 || mItems[0].(map[string]any)["error"] == nil {
		t.Fatalf("expected _msearch per-item error on RRF window violation, got %v", mRes)
	}

	// 2. PinnedQuery omitted _index: allowed in ES 8.15.5, rejected pre-8.11
	st, pRes, raw := doR65MarginReq(t, srv, http.MethodPost, "/r65_w1a/_search", `{
		"query": {
			"pinned": {
				"docs": [{"_id": "4"}],
				"organic": {"match_all": {}}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("expected pinned query with omitted _index to succeed in 8.15.5, got %d: %s", st, raw)
	}
	pHits := pRes["hits"].(map[string]any)["hits"].([]any)
	if len(pHits) == 0 || pHits[0].(map[string]any)["_id"] != "4" {
		t.Fatalf("expected pinned doc 4 ranked first, got %v", pHits)
	}
	// Verify pinnedRankForDoc handles omitted _index cleanly even when target schema/index is set
	rankIdx, okPin := pinnedRankForDoc(nil, map[string]any{"_id": "4"}, &esast.PinnedQuery{Docs: []map[string]any{{"_id": "4"}}})
	if !okPin || rankIdx != 0 {
		t.Fatalf("expected pinnedRankForDoc omitted _index match at rank 0, got (%d, %v)", rankIdx, okPin)
	}

	srvOld, _ := newTestServer()
	srvOld.SetTargetESVersion("8.10.0")
	_, _, _ = doR65MarginReq(t, srvOld, http.MethodPut, "/r65_w1a_old", `{"mappings":{"properties":{"title":{"type":"text"}}}}`)
	st, _, raw = doR65MarginReq(t, srvOld, http.MethodPost, "/r65_w1a_old/_search", `{
		"query": {"pinned": {"docs": [{"_id": "4"}], "organic": {"match_all": {}}}}
	}`)
	if st != http.StatusBadRequest || (!strings.Contains(raw, "missing [_index]") && !strings.Contains(raw, "must not be null or empty")) {
		t.Fatalf("expected 400 missing [_index] on ES 8.10.0, got %d: %s", st, raw)
	}

	// 3. MovingPercentiles + True CumulativeCardinality (set union over buckets!)
	st, aggRes, raw := doR65MarginReq(t, srv, http.MethodPost, "/r65_w1a/_search", `{
		"size": 0,
		"aggs": {
			"by_step": {
				"histogram": {"field": "step", "interval": 10},
				"aggs": {
					"p": {"percentiles": {"field": "price", "percents": [50]}},
					"mp": {"moving_percentiles": {"buckets_path": "p", "window": 2, "shift": 1}},
					"uniq_users": {"cardinality": {"field": "user"}},
					"cum_users": {"cumulative_cardinality": {"buckets_path": "uniq_users"}}
				}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("moving_percentiles + cumulative_cardinality failed: %d %s", st, raw)
	}
	stepBuckets := aggRes["aggregations"].(map[string]any)["by_step"].(map[string]any)["buckets"].([]any)
	// Step 0 has u1 -> cum 1. Step 10 has u1, u2 -> union cum 2 (NOT 1+2=3!). Step 20 empty gap -> skipped! Step 30 has u3 -> union cum 3!
	if len(stepBuckets) != 4 {
		t.Fatalf("expected 4 histogram buckets (0,10,20,30), got %d: %v", len(stepBuckets), stepBuckets)
	}
	b0 := stepBuckets[0].(map[string]any)
	b10 := stepBuckets[1].(map[string]any)
	b20 := stepBuckets[2].(map[string]any)
	b30 := stepBuckets[3].(map[string]any)
	if cc10, _ := toFloat64(b10["cum_users"].(map[string]any)["value"]); cc10 != 2 {
		t.Fatalf("expected step 10 cumulative_cardinality set-union == 2 (u1,u2), got %v (%v)", cc10, b10)
	}
	if _, hasGap := b20["cum_users"]; hasGap {
		t.Fatalf("expected empty step 20 bucket to skip cumulative_cardinality by default, got %v", b20)
	}
	if cc30, _ := toFloat64(b30["cum_users"].(map[string]any)["value"]); cc30 != 3 {
		t.Fatalf("expected step 30 cumulative_cardinality set-union == 3, got %v", cc30)
	}
	if _, hasMP := b10["mp"]; !hasMP {
		t.Fatalf("expected moving_percentiles on step 10, got %v", b10)
	}
	_ = b0

	// Validate invalid parent for moving_percentiles (terms parent -> 400)
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/r65_w1a/_search", `{
		"size": 0,
		"aggs": {
			"by_tag": {
				"terms": {"field": "tag"},
				"aggs": {
					"p": {"percentiles": {"field": "price"}},
					"mp": {"moving_percentiles": {"buckets_path": "p", "window": 2}}
				}
			}
		}
	}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "moving_percentiles") {
		t.Fatalf("expected 400 for moving_percentiles under terms parent, got %d: %s", st, raw)
	}

	// Unit fallback check for evalMovingPercentilesFallbackR65 (keyed and unkeyed)
	fbBuckets := []map[string]any{
		{"key": 0.0, "p": map[string]any{"values": map[string]any{"50.0": 10.0}}},
		{"key": 10.0, "p": map[string]any{"values": map[string]any{"50.0": 30.0}}},
	}
	w2, s1 := 2, 1
	evalMovingPercentilesFallbackR65(fbBuckets, "mp", &esast.MovingPercentilesAggSpec{
		BucketsPath: "p",
		Window:      &w2,
		Shift:       &s1,
	})
	if v50, _ := toFloat64(fbBuckets[1]["mp"].(map[string]any)["values"].(map[string]any)["50.0"]); v50 != 20.0 {
		t.Fatalf("expected fallback moving_percentiles avg=20.0, got %v (%v)", v50, fbBuckets[1])
	}
	unkeyedBuckets := []map[string]any{
		{"key": 0.0, "p": map[string]any{"values": []map[string]any{{"key": 90.0, "value": 4.0}}}},
		{"key": 10.0, "p": map[string]any{"values": []map[string]any{{"key": 90.0, "value": 8.0}}}},
	}
	evalMovingPercentilesFallbackR65(unkeyedBuckets, "mp", &esast.MovingPercentilesAggSpec{
		BucketsPath: "p",
		Window:      &w2,
		Shift:       &s1,
	})
	mpValsArr, okMP := unkeyedBuckets[1]["mp"].(map[string]any)["values"].([]map[string]any)
	if !okMP || len(mpValsArr) != 1 || mpValsArr[0]["value"] != 6.0 {
		t.Fatalf("expected unkeyed fallback moving_percentiles value=6.0, got %#v", unkeyedBuckets[1]["mp"])
	}

	// Highlight matched_fields rejected when require_field_match=false
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/r65_w1a/_search", `{
		"query": {"match": {"title": "alpha"}},
		"highlight": {"require_field_match": false, "fields": {"title": {"matched_fields": ["title"]}}}
	}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "Matched fields are not supported when [require_field_match] is set to [false]") {
		t.Fatalf("expected 400 matched_fields + require_field_match=false error, got %d: %s", st, raw)
	}

	// 4. Legacy SortFieldSpec WasLegacyNestedPath / WasLegacyNestedFilter + removed ES 8 search constructs
	for _, badSearch := range []struct {
		name string
		body string
		want string
	}{
		{"legacy_nested_path", `{"sort":[{"items.score":{"nested_path":"items"}}]}`, "nested"},
		{"legacy_nested_filter", `{"sort":[{"items.score":{"nested_filter":{"term":{"items.tag":"x"}}}}]}`, "nested"},
		{"removed_common", `{"query":{"common":{"title":{"query":"alpha"}}}}`, "Common Terms Query"},
		{"removed_cutoff_match", `{"query":{"match":{"title":{"query":"alpha","cutoff_frequency":0.1}}}}`, "cutoff_freqency"},
		{"removed_cutoff_multi_match", `{"query":{"multi_match":{"query":"alpha","fields":["title"],"cutoff_frequency":0.1}}}`, "cutoff_freqency"},
		{"removed_moving_avg", `{"size":0,"aggs":{"h":{"histogram":{"field":"step","interval":10},"aggs":{"s":{"sum":{"field":"price"}},"m":{"moving_avg":{"buckets_path":"s"}}}}}}`, "Moving Average aggregation"},
	} {
		st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/r65_w1a/_search", badSearch.body)
		if st != http.StatusBadRequest || !strings.Contains(raw, badSearch.want) {
			t.Fatalf("%s: expected 400 containing %q, got %d: %s", badSearch.name, badSearch.want, st, raw)
		}
	}

	// Verify collapse + rescore ALLOWED in ES 8.15.5, rejected in ES 7.10.2
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/r65_w1a/_search", `{
		"collapse": {"field": "tag"},
		"rescore": {"query": {"rescore_query": {"match_all": {}}}}
	}`)
	if st != http.StatusOK {
		t.Fatalf("expected collapse+rescore allowed in ES 8.15.5, got %d: %s", st, raw)
	}
	srv7, _ := newTestServer()
	srv7.SetTargetESVersion("7.10.2")
	_, _, _ = doR65MarginReq(t, srv7, http.MethodPut, "/r65_w1a_7", `{"mappings":{"properties":{"tag":{"type":"keyword"}}}}`)
	st, _, raw = doR65MarginReq(t, srv7, http.MethodPost, "/r65_w1a_7/_search", `{
		"collapse": {"field": "tag"},
		"rescore": {"query": {"rescore_query": {"match_all": {}}}}
	}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "collapse") {
		t.Fatalf("expected collapse+rescore rejected in ES 7.10.2, got %d: %s", st, raw)
	}
}

func TestRound65_Wave1B_DenseVectorElementTypesAndScriptUpsertDefaultOp(t *testing.T) {
	srv, _ := newTestServer()
	srv.SetTargetESVersion("8.15.5")

	st, _, raw := doR65MarginReq(t, srv, http.MethodPut, "/r65_w1b", `{
		"mappings": {
			"properties": {
				"bit_vec": {"type": "dense_vector", "dims": 8, "element_type": "bit"},
				"byte_vec": {"type": "dense_vector", "dims": 2, "element_type": "byte"},
				"cnt": {"type": "long"}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create r65_w1b failed: %d %s", st, raw)
	}

	// Verify PrepareDocForRuntimeScriptRound61 populates __vector_element_types for bit & byte
	idxSchema := srv.getOrCompileReadOnlySchema(context.Background(), "r65_w1b")
	prepDoc := PrepareDocForRuntimeScriptRound61(idxSchema, map[string]any{
		"bit_vec":  []any{1, 0, 1, 0, 1, 0, 1, 0},
		"byte_vec": []any{3, 4},
	}, true)
	vet, okVET := prepDoc["__vector_element_types"].(map[string]string)
	if !okVET || vet["bit_vec"] != "bit" || vet["byte_vec"] != "byte" {
		t.Fatalf("expected __vector_element_types bit/byte populated, got %#v", prepDoc["__vector_element_types"])
	}

	// Verify evalRuntimeSearchScoreWithErrorRound59 runs with __vector_element_types populated
	score, err := evalRuntimeSearchScoreWithErrorRound59(idxSchema, map[string]any{
		"bit_vec":  []any{1, 0, 1, 0, 1, 0, 1, 0},
		"byte_vec": []any{3, 4},
	}, &esast.Query{
		ScriptScore: &esast.ScriptScoreQuery{
			Script: map[string]any{"source": "doc['byte_vec'].size() + 1.0"},
		},
	}, 1.0)
	if err != nil || score <= 0 {
		t.Fatalf("expected runtime script_score using __vector_element_types to succeed, got score=%v err=%v", score, err)
	}

	// Verify scripted_upsert with ctx.op = 'create' on missing doc (`painless/25_script_upsert.yml`)
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/r65_w1b/_update/up_create", `{
		"scripted_upsert": true,
		"upsert": {"cnt": 1},
		"script": {
			"source": "if (ctx.op == 'create') { ctx._source.cnt = 42; }"
		}
	}`)
	if st != http.StatusCreated && st != http.StatusOK {
		t.Fatalf("expected scripted upsert with ctx.op=='create' to succeed, got %d: %s", st, raw)
	}
	st, getRes, raw := doR65MarginReq(t, srv, http.MethodGet, "/r65_w1b/_doc/up_create", "")
	if st != http.StatusOK || getRes["_source"].(map[string]any)["cnt"] != json.Number("42") {
		t.Fatalf("expected scripted upsert to write cnt=42, got %d: %s", st, raw)
	}
}

func TestRound65_Wave1C_TSDBSettingsMappingsAnalysisNoSubobjectsAndSyntheticIP(t *testing.T) {
	srv, _ := newTestServer()
	srv.SetTargetESVersion("8.15.5")

	// 1. TSDB creation rejects _routing and non-synthetic source with ES8 exact message
	st, _, raw := doR65MarginReq(t, srv, http.MethodPut, "/r65_tsdb_bad_route", `{
		"settings": {"index": {"mode": "time_series", "routing_path": ["host"]}},
		"mappings": {
			"_routing": {"required": true},
			"properties": {"@timestamp": {"type": "date"}, "host": {"type": "keyword", "time_series_dimension": true}}
		}
	}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "routing is forbidden on CRUD operations that target indices in [index.mode=time_series]") {
		t.Fatalf("expected TSDB _routing rejection, got %d: %s", st, raw)
	}

	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_tsdb_bad_src", `{
		"settings": {"index": {"mode": "time_series", "routing_path": ["host"]}},
		"mappings": {
			"_source": {"mode": "stored"},
			"properties": {"@timestamp": {"type": "date"}, "host": {"type": "keyword", "time_series_dimension": true}}
		}
	}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "time series indices only support synthetic source") {
		t.Fatalf("expected exact synthetic source message, got %d: %s", st, raw)
	}

	// 2. Valid TSDB index sets _source.mode=synthetic, supports end_time updates, rejects non-dynamic updates
	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_tsdb_ok", `{
		"settings": {
			"index": {
				"mode": "time_series",
				"routing_path": ["host"],
				"time_series": {
					"start_time": "2026-01-01T00:00:00Z",
					"end_time": "2026-01-05T00:00:00Z"
				}
			}
		},
		"mappings": {
			"properties": {
				"@timestamp": {"type": "date"},
				"host": {"type": "keyword", "time_series_dimension": true},
				"cpu": {"type": "double", "time_series_metric": "gauge"}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create valid TSDB failed: %d %s", st, raw)
	}

	st, mapRes, raw := doR65MarginReq(t, srv, http.MethodGet, "/r65_tsdb_ok/_mapping", "")
	if st != http.StatusOK {
		t.Fatalf("get mapping failed: %d %s", st, raw)
	}
	srcMode, _ := mapRes["r65_tsdb_ok"].(map[string]any)["mappings"].(map[string]any)["_source"].(map[string]any)["mode"].(string)
	if srcMode != "synthetic" {
		t.Fatalf("expected serialized _source.mode=synthetic, got %v (%s)", srcMode, raw)
	}

	// Open index rejects non-dynamic mode/time_series.start_time
	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_tsdb_ok/_settings", `{"index.time_series.start_time":"2026-01-01T00:00:00Z"}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "Can't update non dynamic settings") {
		t.Fatalf("expected non-dynamic open error for time_series.start_time, got %d: %s", st, raw)
	}
	// Earlier end_time rejected via ValidateTSDBEndTimeUpdate
	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_tsdb_ok/_settings", `{"index.time_series.end_time":"2026-01-04T00:00:00Z"}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "must be larger than current value") {
		t.Fatalf("expected TSDB end_time increase check, got %d: %s", st, raw)
	}
	// Invalid top_metrics_max_size rejected
	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_tsdb_ok/_settings", `{"index.top_metrics_max_size":0}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "top_metrics_max_size") {
		t.Fatalf("expected 400 on top_metrics_max_size=0, got %d: %s", st, raw)
	}
	// Valid end_time update succeeds
	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_tsdb_ok/_settings", `{"index.time_series.end_time":"2026-01-10T00:00:00Z"}`)
	if st != http.StatusOK {
		t.Fatalf("expected later end_time update to succeed, got %d: %s", st, raw)
	}
	// Runtime field matching routing_path rejected in _mapping and _search
	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_tsdb_ok/_mapping", `{"runtime":{"host":{"type":"keyword"}}}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "routing_path") {
		t.Fatalf("expected runtime routing_path error on _mapping, got %d: %s", st, raw)
	}
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/r65_tsdb_ok/_search", `{"runtime_mappings":{"host":{"type":"keyword","script":"emit('a')"}}}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "routing_path") {
		t.Fatalf("expected runtime routing_path error on _search, got %d: %s", st, raw)
	}
	// Close TSDB index and check final setting rejection wording
	_, _, _ = doR65MarginReq(t, srv, http.MethodPost, "/r65_tsdb_ok/_close", "")
	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_tsdb_ok/_settings", `{"index.time_series.start_time":"2026-01-01T00:00:00Z"}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "not updateable") {
		t.Fatalf("expected final not updateable on closed TSDB index, got %d: %s", st, raw)
	}

	// 3. Non-TSDB dimension shadowing via ValidateTSDBRuntimeShadowing
	_, _, _ = doR65MarginReq(t, srv, http.MethodPut, "/r65_non_tsdb_dim", `{
		"mappings":{"properties":{"dim":{"type":"keyword","time_series_dimension":true}}}
	}`)
	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_non_tsdb_dim/_mapping", `{"runtime":{"dim":{"type":"keyword"}}}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "attempted to shadow") {
		t.Fatalf("expected non-TSDB runtime shadowing rejection, got %d: %s", st, raw)
	}

	// 4. SetAnalysisSettings on CreateIndex
	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_analysis_ok", `{
		"settings": {
			"analysis": {
				"filter": {"my_len": {"type": "length", "min": 2}},
				"normalizer": {"my_norm": {"type": "custom", "filter": ["lowercase"]}}
			}
		},
		"mappings": {"properties": {"tag": {"type": "keyword", "normalizer": "my_norm"}}}
	}`)
	if st != http.StatusOK {
		t.Fatalf("expected custom analysis index creation to succeed, got %d: %s", st, raw)
	}
	anaSchema := srv.getOrCompileReadOnlySchema(context.Background(), "r65_analysis_ok")
	if anaSchema.AnalysisConfig == nil {
		t.Fatalf("expected SetAnalysisSettings to populate AnalysisConfig on created schema")
	}

	// 5. Dynamic template subobjects:false (`metrics.host.name`) is NOT marked in dynamicTextFieldsByIdx
	_, _, _ = doR65MarginReq(t, srv, http.MethodPut, "/r65_no_subobj", `{
		"mappings": {
			"dynamic_templates": [{
				"strings_as_kw": {
					"match_mapping_type": "string",
					"mapping": {"type": "keyword"}
				}
			}],
			"properties": {
				"metrics": {"type": "object", "subobjects": false}
			}
		}
	}`)
	prevSpec := &esast.MappingSpec{
		DynamicTemplates: []map[string]any{
			{"strings_as_kw": map[string]any{"match_mapping_type": "string", "mapping": map[string]any{"type": "keyword"}}},
		},
	}
	inferredSpec := &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{
			"metrics": {
				Type: "object",
				Properties: map[string]esast.FieldProperty{
					"host.name": {Type: "keyword"},
				},
			},
		},
	}
	srv.recordDynamicallyInferredFieldsWave3R63("r65_no_subobj", prevSpec, inferredSpec, []json.RawMessage{json.RawMessage(`{"metrics":{"host.name":"edge-1"}}`)})
	dynMap := srv.dynamicTextFieldsCopyWave3R63("r65_no_subobj")
	if dynMap["metrics.host.name"] {
		t.Fatalf("expected dynamic_template keyword metrics.host.name not to be added to dynamicTextFieldsByIdx, got %v", dynMap)
	}

	// 6. canonicalizeSyntheticIPsInMapR61Search preserves malformed IPs in ip arrays
	ipSchema := schema.CompileIndexSchema("es_compat", "r65_ip", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{"addrs": {Type: "ip"}},
	})
	docIP := map[string]any{"addrs": []any{"2001:0db8:0000:0000:0000:0000:0000:0001", "not-an-ip", "1.2.3.4"}}
	canonicalizeSyntheticIPsInMapR61Search(docIP, ipSchema)
	gotIPs, _ := docIP["addrs"].([]any)
	wantIPs := []any{"1.2.3.4", "2001:db8::1", "not-an-ip"}
	if !reflect.DeepEqual(gotIPs, wantIPs) {
		t.Fatalf("expected canonical sorted IPs + preserved malformed IP %v, got %v", wantIPs, gotIPs)
	}
}

func TestRound65_Wave1D_BoxplotHintTopMetricsMaxSizeAndMultiTermsPostSort(t *testing.T) {
	srv, _ := newTestServer()
	srv.SetTargetESVersion("8.15.5")

	st, _, raw := doR65MarginReq(t, srv, http.MethodPut, "/r65_w1d", `{
		"settings": {"index.top_metrics_max_size": 2},
		"mappings": {
			"properties": {
				"cat": {"type": "keyword"},
				"sub": {"type": "keyword"},
				"ts": {"type": "long"},
				"val": {"type": "double"}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create r65_w1d failed: %d %s", st, raw)
	}
	bulkBody := strings.Join([]string{
		`{"index":{"_index":"r65_w1d","_id":"1"}}`, `{"cat":"a","sub":"x","ts":1,"val":10}`,
		`{"index":{"_index":"r65_w1d","_id":"2"}}`, `{"cat":"a","sub":"x","ts":2,"val":20}`,
		`{"index":{"_index":"r65_w1d","_id":"3"}}`, `{"cat":"b","sub":"y","ts":3,"val":50}`,
		`{"index":{"_index":"r65_w1d","_id":"4"}}`, `{"cat":"c","sub":"z","ts":4,"val":100}`,
		"",
	}, "\n")
	if bst, _, braw := doR65MarginReq(t, srv, http.MethodPost, "/_bulk?refresh=true", bulkBody); bst != http.StatusOK {
		t.Fatalf("bulk failed: %d %s", bst, braw)
	}

	// 1. Boxplot execution_hint via search & buildExactQuantileMetricObjectR61Search
	st, bxRes, raw := doR65MarginReq(t, srv, http.MethodPost, "/r65_w1d/_search", `{
		"size": 0,
		"aggs": {
			"bx": {"boxplot": {"field": "val", "execution_hint": "high_accuracy"}}
		}
	}`)
	if st != http.StatusOK || bxRes["aggregations"].(map[string]any)["bx"].(map[string]any)["q2"] == nil {
		t.Fatalf("boxplot execution_hint failed: %d %s", st, raw)
	}
	bxUnit, err := buildExactQuantileMetricObjectR61Search(esast.AggSpec{
		Boxplot: &esast.MetricAggSpec{Field: "val", ExecutionHint: "high_accuracy"},
	}, []float64{10, 20, 50, 100}, true)
	if err != nil || bxUnit["min"] == nil {
		t.Fatalf("buildExactQuantileMetricObjectR61Search boxplot high_accuracy failed: err=%v res=%v", err, bxUnit)
	}

	// 2. TopMetricsMaxSize limit enforcement (`size: 3` > `index.top_metrics_max_size: 2`)
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/r65_w1d/_search", `{
		"size": 0,
		"aggs": {
			"tm": {"top_metrics": {"metrics": {"field": "val"}, "sort": {"ts": "desc"}, "size": 3}}
		}
	}`)
	if st != http.StatusBadRequest || !strings.Contains(raw, "top_metrics") {
		t.Fatalf("expected 400 when top_metrics.size exceeds index.top_metrics_max_size=2, got %d: %s", st, raw)
	}

	// 3. multi_terms custom sub-agg order post-sort + size truncation + sum_other_doc_count + show_term_doc_count_error
	st, mtRes, raw := doR65MarginReq(t, srv, http.MethodPost, "/r65_w1d/_search", `{
		"size": 0,
		"aggs": {
			"mt": {
				"multi_terms": {
					"terms": [{"field": "cat"}, {"field": "sub"}],
					"size": 2,
					"order": {"max_val": "desc"},
					"show_term_doc_count_error": true
				},
				"aggs": {
					"max_val": {"max": {"field": "val"}}
				}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("multi_terms custom order failed: %d %s", st, raw)
	}
	mtObj := mtRes["aggregations"].(map[string]any)["mt"].(map[string]any)
	mtBuckets := mtObj["buckets"].([]any)
	if len(mtBuckets) != 2 {
		t.Fatalf("expected size=2 multi_terms buckets, got %d (%v)", len(mtBuckets), mtBuckets)
	}
	if mtBuckets[0].(map[string]any)["key_as_string"] != "c|z" {
		t.Fatalf("expected highest max_val bucket c|z first, got %v", mtBuckets[0])
	}
	if _, hasErr := mtBuckets[0].(map[string]any)["doc_count_error_upper_bound"]; !hasErr {
		t.Fatalf("expected show_term_doc_count_error per-bucket field, got %v", mtBuckets[0])
	}
	if sodc, _ := toFloat64(mtObj["sum_other_doc_count"]); sodc != 2 {
		t.Fatalf("expected sum_other_doc_count=2 for dropped a|x (2 docs), got %v", sodc)
	}

	// Verify SQL pipe-delimited multi_terms key formatting in formatRuntimeBucketAggObjectWithSchema
	sqlMT := formatRuntimeBucketAggObjectWithSchema("r65_w1d", "mt", "", esast.AggSpec{
		MultiTerms: &esast.MultiTermsAggSpec{
			Terms: []esast.MultiTermTermSpec{{Field: "cat"}, {Field: "ts"}},
			Size:  2,
			Order: map[string]any{"m": "asc"},
		},
		Aggs: map[string]esast.AggSpec{
			"m": {Max: &esast.MetricAggSpec{Field: "val"}},
		},
	}, []AggRow{
		{AggName: "mt", BucketKey: "b|10", DocCount: 1},
		{AggName: "mt", BucketKey: "a|5", DocCount: 2},
	}, map[string][]AggRow{
		"mt.m": {
			{AggName: "mt.m", BucketKey: "b|10", DocCount: 1, Value: 5},
			{AggName: "mt.m", BucketKey: "a|5", DocCount: 2, Value: 50},
		},
	}, nil, srv.getOrCompileReadOnlySchema(context.Background(), "r65_w1d"))
	sqlBuckets := sqlMT["buckets"].([]map[string]any)
	if len(sqlBuckets) != 2 || sqlBuckets[0]["key_as_string"] != "b|10" {
		t.Fatalf("expected SQL multi_terms tuple sorted by m asc -> b|10 first, got %v", sqlBuckets)
	}
}

func TestRound65_Track123_MonitoringRoutesHistogramULAndAdminCoverage(t *testing.T) {
	srv, _ := newTestServer()
	srv.SetTargetESVersion("8.15.5")

	// Configure security roles & users to test F11-mon monitoring bulk RBAC
	srv.mu.Lock()
	srv.securityRoles = map[string]map[string]any{
		"monitor_only": {"cluster": []string{"monitor"}},
		"mon_writer":   {"cluster": []string{"cluster:admin/xpack/monitoring/bulk"}},
	}
	srv.securityUsers = map[string]map[string]any{
		"reader": {"roles": []string{"monitor_only"}},
		"writer": {"roles": []string{"mon_writer"}},
		"agent":  {"roles": []string{"remote_monitoring_agent"}},
	}
	srv.mu.Unlock()

	authHeader := func(u, p string) [2]string {
		return [2]string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))}
	}

	// 1. F11-mon: _monitoring/bulk validation, RBAC 403, _data skip, closed index 500 export_exception, normal bulk 200
	st, _, raw := doR65MarginReq(t, srv, http.MethodPost, "/_monitoring/bulk?system_id=beats&system_api_version=7&interval=10s",
		`{"index":{"_index":"_data"}}`+"\n"+`{"foo":1}`+"\n",
		authHeader("reader", "pass"))
	if st != http.StatusForbidden || !strings.Contains(raw, "security_exception") {
		t.Fatalf("expected 403 security_exception for monitor_only user, got %d: %s", st, raw)
	}
	for _, missingURL := range []string{
		"/_monitoring/bulk?system_api_version=7&interval=10s",
		"/_monitoring/bulk?system_id=beats&interval=10s",
		"/_monitoring/bulk?system_id=beats&system_api_version=7",
		"/_monitoring/bulk?system_id=beats&system_api_version=7&interval=bad",
	} {
		st, _, _ = doR65MarginReq(t, srv, http.MethodPost, missingURL, "{}\n{}\n", authHeader("agent", "pass"))
		if st != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d", missingURL, st)
		}
	}
	// Invalid HTTP method & odd NDJSON lines
	st, _, _ = doR65MarginReq(t, srv, http.MethodGet, "/_monitoring/bulk?system_id=beats&system_api_version=7&interval=10s", "", authHeader("agent", "pass"))
	if st != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET _monitoring/bulk, got %d", st)
	}
	st, _, _ = doR65MarginReq(t, srv, http.MethodPost, "/_monitoring/bulk?system_id=beats&system_api_version=7&interval=10s", `{"index":{}}`+"\n", authHeader("agent", "pass"))
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on unterminated bulk lines, got %d", st)
	}
	// _data only -> skipped 200
	st, mRes, raw := doR65MarginReq(t, srv, http.MethodPost, "/_monitoring/bulk?system_id=beats&system_api_version=7&interval=10s",
		`{"index":{"_index":"_data"}}`+"\n"+`{"skip":true}`+"\n",
		authHeader("writer", "pass"))
	if st != http.StatusOK || mRes["errors"] != false {
		t.Fatalf("expected 200 on _data skip, got %d: %s", st, raw)
	}
	// typed route `/_monitoring/beats/bulk` + `/_xpack/monitoring/bulk`
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/_monitoring/beats/bulk?system_id=beats&system_api_version=7&interval=10s",
		`{"index":{"_id":"m1"}}`+"\n"+`{"metrics":{"cpu":1.0}}`+"\n",
		authHeader("agent", "pass"))
	if st != http.StatusOK {
		t.Fatalf("expected 200 on typed _monitoring/beats/bulk, got %d: %s", st, raw)
	}
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/_xpack/monitoring/beats/bulk?system_id=beats&system_api_version=7&interval=10s",
		`{"index":{"_id":"m2"}}`+"\n"+`{"metrics":{"cpu":2.0}}`+"\n",
		authHeader("agent", "pass"))
	if st != http.StatusOK {
		t.Fatalf("expected 200 on _xpack/monitoring/beats/bulk, got %d: %s", st, raw)
	}
	// Closed monitoring index -> 500 export_exception
	_, _, _ = doR65MarginReq(t, srv, http.MethodPut, "/.monitoring-kibana-7-2026.11.22", `{}`)
	_, _, _ = doR65MarginReq(t, srv, http.MethodPost, "/.monitoring-kibana-7-2026.11.22/_close", ``)
	st, _, raw = doR65MarginReq(t, srv, http.MethodPost, "/_monitoring/bulk?system_id=kibana&system_api_version=7&interval=10s",
		`{"index":{}}`+"\n"+`{"status":"green"}`+"\n",
		authHeader("agent", "pass"))
	if st != http.StatusInternalServerError || !strings.Contains(raw, "export_exception") {
		t.Fatalf("expected 500 export_exception on closed monitoring index, got %d: %s", st, raw)
	}

	// 2. F25-route: underscore _repositories_metering & _clear_repositories_metering_archive routes
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/_nodes/_repositories_metering"},
		{http.MethodGet, "/_nodes/doris-fe-1/_repositories_metering"},
		{http.MethodDelete, "/_nodes/_clear_repositories_metering_archive/1"},
		{http.MethodDelete, "/_nodes/doris-fe-1/_clear_repositories_metering_archive/1"},
	} {
		st, _, raw = doR65MarginReq(t, srv, tc.method, tc.path, "")
		if st != http.StatusOK {
			t.Fatalf("%s %s failed: %d %s", tc.method, tc.path, st, raw)
		}
	}

	// 3. F6-L5b: unsigned_long histogram large interval (9223372036854775807) exact bucket preservation
	ulRows := synthesizeHistogramBuckets([]AggRow{
		{BucketKey: "0", DocCount: 1},
		{BucketKey: "18446744073709551614", DocCount: 2},
	}, &esast.HistogramAggSpec{
		Field:    "uid",
		Interval: 9223372036854775807,
	})
	if len(ulRows) != 3 {
		t.Fatalf("expected 3 buckets (0, 9223372036854775807, 18446744073709551614), got %d: %+v", len(ulRows), ulRows)
	}
	if ulRows[0].BucketKey != "0" || (ulRows[1].BucketKey != "9223372036854775807" && ulRows[1].BucketKey != "9223372036854775808") || ulRows[2].BucketKey != "18446744073709551614" {
		t.Fatalf("expected exact large integer bucket keys, got %+v", ulRows)
	}
	ulSchema := schema.CompileIndexSchema("es_compat", "r65_ul", &esast.MappingSpec{
		Properties: map[string]esast.FieldProperty{"uid": {Type: "unsigned_long"}},
	})
	kAny := formatHistogramBucketKeyAnyR65("18446744073709551614", 0, &esast.HistogramAggSpec{Field: "uid", Interval: 9223372036854775807}, ulSchema)
	if uVal, okU := kAny.(uint64); !okU || uVal != uint64(18446744073709551614) {
		t.Fatalf("expected exact uint64 18446744073709551614, got %T %v", kAny, kAny)
	}
	if !isExactLargeHistIntR65("9223372036854775807") || isExactLargeHistIntR65("42.5") || isExactLargeHistIntR65("100") {
		t.Fatalf("unexpected isExactLargeHistIntR65 classification")
	}
	if math.Abs(roundHistFloatKeyR65(1.1234567890123)-1.123456789012) > 1e-12 || roundHistFloatKeyR65(1.5e9) != 1.5e9 {
		t.Fatalf("unexpected roundHistFloatKeyR65 results")
	}

	// 4. Bulk date_nanos ES8 document_parsing_exception caused_by + offline hotspot coverage endpoints
	st, _, raw = doR65MarginReq(t, srv, http.MethodPut, "/r65_cov_idx", `{
		"mappings": {
			"properties": {
				"title": {"type": "text"},
				"score": {"type": "double"},
				"ts_ns": {"type": "date_nanos"}
			}
		}
	}`)
	if st != http.StatusOK {
		t.Fatalf("create r65_cov_idx failed: %d %s", st, raw)
	}
	_, _, _ = doR65MarginReq(t, srv, http.MethodPost, "/_bulk?refresh=true",
		`{"index":{"_index":"r65_cov_idx","_id":"1"}}`+"\n"+`{"title":"alpha","score":10}`+"\n"+
			`{"index":{"_index":"r65_cov_idx","_id":"2"}}`+"\n"+`{"title":"alpha beta","score":20}`+"\n")
	// Overflow date_nanos in ES8 bulk -> check caused_by on document_parsing_exception
	st, bErr, _ := doR65MarginReq(t, srv, http.MethodPost, "/_bulk",
		`{"index":{"_index":"r65_cov_idx","_id":"bad_ns"}}`+"\n"+`{"ts_ns":"2500-01-01T00:00:00Z"}`+"\n")
	if st == http.StatusOK && bErr["errors"] == true {
		itemErr := bErr["items"].([]any)[0].(map[string]any)["index"].(map[string]any)["error"].(map[string]any)
		if (itemErr["type"] == "document_parsing_exception" || itemErr["type"] == "mapper_parsing_exception") && itemErr["caused_by"] == nil {
			t.Fatalf("expected caused_by on date_nanos overflow bulk item, got %v", itemErr)
		}
	}

	// _count (`min_score`, `?min_score=`, unknown key 400)
	st, cntRes, raw := doR65MarginReq(t, srv, http.MethodPost, "/r65_cov_idx/_count", `{"query":{"match":{"title":"alpha"}},"min_score":0.1}`)
	if st != http.StatusOK || cntRes["count"] == nil {
		t.Fatalf("_count min_score failed: %d %s", st, raw)
	}
	st, _, _ = doR65MarginReq(t, srv, http.MethodPost, "/r65_cov_idx/_count", `{"unknown_field":1}`)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on unknown _count field, got %d", st)
	}

	// _resolve/index, _doris/explain, _cat/segments, _cat/thread_pool, _segments, _shard_stores
	for _, ep := range []string{
		"/_resolve/index/r65_*",
		"/r65_cov_idx/_doris/explain",
		"/_cat/segments?format=json",
		"/_cat/thread_pool?format=json",
		"/r65_cov_idx/_segments",
		"/r65_cov_idx/_shard_stores",
	} {
		st, _, raw = doR65MarginReq(t, srv, http.MethodGet, ep, "")
		if st != http.StatusOK {
			t.Fatalf("GET %s failed: %d %s", ep, st, raw)
		}
	}

	// evalNormalizeOnBuckets & sortMultiTermsBucketsR65 unit coverage
	normBuckets := []map[string]any{
		{"key": "a", "s": map[string]any{"value": 10.0}},
		{"key": "b", "s": map[string]any{"value": 30.0}},
	}
	for _, method := range []string{"percent_of_sum", "rescale_0_1", "rescale_0_100", "mean", "z-score", "atan"} {
		evalNormalizeOnBuckets(normBuckets, "n_"+method, &esast.NormalizeAggSpec{
			BucketsPath: "s",
			Method:      method,
		})
	}
	if _, ok := normBuckets[0]["n_rescale_0_1"]; !ok {
		t.Fatalf("expected normalize output keys on bucket, got %v", normBuckets[0])
	}
	mtSortB := []map[string]any{
		{"key": []any{"b", 2}, "key_as_string": "b|2", "doc_count": int64(5), "m": map[string]any{"value": 10.0}},
		{"key": []any{"a", 1}, "key_as_string": "a|1", "doc_count": int64(1), "m": map[string]any{"value": 50.0}},
	}
	sortedMT := sortMultiTermsBucketsR65(mtSortB, []any{map[string]any{"m": "desc"}, map[string]any{"_key": "asc"}})
	if sortedMT[0]["key_as_string"] != "a|1" {
		t.Fatalf("expected sortMultiTermsBucketsR65 m desc -> a|1 first, got %v", sortedMT)
	}
	_ = fmt.Sprintf("verified %d buckets", len(sortedMT))
}
