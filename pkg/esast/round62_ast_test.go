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
	"math"
	"strings"
	"testing"
)

func TestRound62_FlexibleDateHistogramOffsetAndPercents(t *testing.T) {
	// 1. DateHistogram numeric & string offset
	var dhNum SearchRequest
	if err := json.Unmarshal([]byte(`{
		"aggs": {
			"dow": {
				"date_histogram": {
					"field": "date",
					"calendar_interval": "week",
					"offset": -25200000
				}
			}
		}
	}`), &dhNum); err != nil {
		t.Fatalf("numeric date_histogram offset failed: %v", err)
	}
	if got := dhNum.Aggs["dow"].DateHistogram.Offset; got != "-25200000ms" {
		t.Fatalf("expected offset '-25200000ms', got %q", got)
	}

	var dhFloat DateHistogramAggSpec
	if err := json.Unmarshal([]byte(`{"field":"ts","fixed_interval":"1d","offset":3600000.0}`), &dhFloat); err != nil {
		t.Fatalf("float integral offset failed: %v", err)
	}
	if dhFloat.Offset != "3600000ms" {
		t.Fatalf("expected '3600000ms', got %q", dhFloat.Offset)
	}

	var dhStr DateHistogramAggSpec
	if err := json.Unmarshal([]byte(`{"field":"ts","fixed_interval":"1d","offset":"-7h"}`), &dhStr); err != nil {
		t.Fatalf("string offset failed: %v", err)
	}
	if dhStr.Offset != "-7h" {
		t.Fatalf("expected '-7h', got %q", dhStr.Offset)
	}

	var dhFrac DateHistogramAggSpec
	if err := json.Unmarshal([]byte(`{"field":"ts","fixed_interval":"1d","offset":12.5}`), &dhFrac); err != nil || dhFrac.Offset != "13ms" {
		t.Fatalf("expected rounded fractional ms offset '13ms', got %q (err=%v)", dhFrac.Offset, err)
	}
	for _, bad := range []string{
		`{"field":"ts","fixed_interval":"1d","offset":true}`,
		`{"field":"ts","fixed_interval":"1d","offset":[1]}`,
	} {
		var badDH DateHistogramAggSpec
		if err := json.Unmarshal([]byte(bad), &badDH); err == nil {
			t.Fatalf("expected error for invalid offset %s", bad)
		}
	}

	// 2. Percentiles & PercentilesBucket single number vs array
	var pSingle SearchRequest
	if err := json.Unmarshal([]byte(`{
		"aggs": {
			"p95": {"percentiles": {"field": "latency", "percents": 95}},
			"pb50": {"percentiles_bucket": {"buckets_path": "the_sum", "percents": 50}}
		}
	}`), &pSingle); err != nil {
		t.Fatalf("single number percents failed: %v", err)
	}
	if got := pSingle.Aggs["p95"].Percentiles.Percents; len(got) != 1 || got[0] != 95 {
		t.Fatalf("expected [95], got %+v", got)
	}
	if got := pSingle.Aggs["pb50"].PercentilesBucket.Percents; len(got) != 1 || got[0] != 50 {
		t.Fatalf("expected [50], got %+v", got)
	}

	var pArr PercentilesAggSpec
	if err := json.Unmarshal([]byte(`{"field":"latency","percents":[25, 50, 99.9]}`), &pArr); err != nil {
		t.Fatalf("array percents failed: %v", err)
	}
	if len(pArr.Percents) != 3 || pArr.Percents[2] != 99.9 {
		t.Fatalf("unexpected array percents: %+v", pArr.Percents)
	}

	for _, bad := range []string{
		`{"field":"latency","percents":[]}`,
		`{"field":"latency","percents":105}`,
		`{"field":"latency","percents":-1}`,
		`{"field":"latency","percents":"bad"}`,
	} {
		var badP PercentilesAggSpec
		if err := json.Unmarshal([]byte(bad), &badP); err == nil {
			t.Fatalf("expected error for invalid percents %s", bad)
		}
	}
}

func TestRound62_TermsLookupTypeAndFieldPropertyAdditions(t *testing.T) {
	// F19: TermsLookupSpec "type" key
	var q Query
	if err := json.Unmarshal([]byte(`{
		"terms": {
			"color": {
				"index": "lookup_idx",
				"type": "_doc",
				"id": "1",
				"path": "colors",
				"routing": "r1",
				"store": true
			}
		}
	}`), &q); err != nil {
		t.Fatalf("terms lookup with type failed: %v", err)
	}
	lk, hasLK := q.Terms.Lookups["color"]
	if !hasLK || lk.Type != "_doc" || lk.Index != "lookup_idx" || lk.ID != "1" || lk.Path != "colors" {
		t.Fatalf("unexpected TermsLookupSpec: %+v", lk)
	}

	// F4, F17, F21-F23: MappingSpec.Enabled, FieldProperty IncludeInParent/IncludeInRoot, Script/OnScriptError, Composite Runtime, RankFeatureNullValue
	var ms MappingSpec
	if err := json.Unmarshal([]byte(`{
		"enabled": false,
		"runtime": {
			"comp": {
				"type": "composite",
				"script": "emit(Map.of('k', 'v'))",
				"on_script_error": "continue",
				"fields": {
					"k": {"type": "keyword"}
				}
			}
		},
		"properties": {
			"nest": {
				"type": "nested",
				"include_in_parent": true,
				"include_in_root": false
			},
			"calc": {
				"type": "long",
				"script": {"source": "emit(10)"},
				"on_script_error": "fail"
			},
			"rf": {
				"type": "rank_feature",
				"null_value": 2.5
			}
		}
	}`), &ms); err != nil {
		t.Fatalf("MappingSpec unmarshal failed: %v", err)
	}
	if ms.Enabled == nil || *ms.Enabled {
		t.Fatalf("expected MappingSpec.Enabled=false, got %+v", ms.Enabled)
	}
	comp := ms.Runtime["comp"]
	if !comp.IsCompositeRuntime() || comp.OnScriptError != "continue" || comp.Fields["k"].Type != "keyword" {
		t.Fatalf("unexpected composite runtime field: %+v", comp)
	}
	nest := ms.Properties["nest"]
	if nest.IncludeInParent == nil || !*nest.IncludeInParent || nest.IncludeInRoot == nil || *nest.IncludeInRoot {
		t.Fatalf("unexpected nested include flags: %+v", nest)
	}
	calc := ms.Properties["calc"]
	if calc.OnScriptError != "fail" || calc.Script == nil {
		t.Fatalf("unexpected calc script field: %+v", calc)
	}
	rf := ms.Properties["rf"]
	nv, err := rf.RankFeatureNullValue()
	if err != nil || nv == nil || *nv != 2.5 {
		t.Fatalf("expected rank_feature null_value=2.5, got %v (err=%v)", nv, err)
	}

	var badFP FieldProperty
	if err := json.Unmarshal([]byte(`{"type":"long","script":"emit(1)","on_script_error":"ignore"}`), &badFP); err == nil || !strings.Contains(err.Error(), "on_script_error") {
		t.Fatalf("expected invalid on_script_error error, got %v", err)
	}

	normStr, err := NormalizeFieldScriptObject("emit(42)")
	if err != nil || normStr["lang"] != "painless" || normStr["source"] != "emit(42)" {
		t.Fatalf("unexpected normalized string script: %+v (err=%v)", normStr, err)
	}
	normMap, err := NormalizeFieldScriptObject(map[string]any{"source": "emit(params.x)", "params": map[string]any{"x": 1}})
	if err != nil || normMap["lang"] != "painless" {
		t.Fatalf("unexpected normalized map script: %+v (err=%v)", normMap, err)
	}
	if nilMap, err := NormalizeFieldScriptObject(nil); err != nil || nilMap != nil {
		t.Fatalf("expected nil,nil for nil script, got %+v, %v", nilMap, err)
	}
	for _, badScript := range []any{
		map[string]any{"unknown": 1},
		map[string]any{"lang": "painless"},
		map[string]any{"source": "a", "id": "b"},
		map[string]any{"source": 123},
		12345,
	} {
		if _, err := NormalizeFieldScriptObject(badScript); err == nil {
			t.Fatalf("expected error for bad script %#v", badScript)
		}
	}

	for _, okVal := range []any{float32(1.5), int(3), int64(4), json.Number("5.5"), "6.5"} {
		v, err := (FieldProperty{NullValue: okVal}).RankFeatureNullValue()
		if err != nil || v == nil || *v <= 0 {
			t.Fatalf("expected valid RankFeatureNullValue for %#v, got %v, %v", okVal, v, err)
		}
	}
	if v, err := (FieldProperty{}).RankFeatureNullValue(); err != nil || v != nil {
		t.Fatalf("expected nil,nil for unset NullValue, got %v, %v", v, err)
	}
	for _, badNV := range []any{0.0, -1.0, math.NaN(), math.Inf(1), math.MaxFloat64, "abc", json.Number("bad"), true} {
		if _, err := (FieldProperty{NullValue: badNV}).RankFeatureNullValue(); err == nil {
			t.Fatalf("expected error for invalid rank_feature null_value %#v", badNV)
		}
	}
}

func TestRound62_NewAggSpecs_IPPrefix_TimeSeries_Children_Parent(t *testing.T) {
	var req SearchRequest
	if err := json.Unmarshal([]byte(`{
		"aggs": {
			"v4_nets": {
				"ip_prefix": {
					"field": "client_ip",
					"prefix_length": 24,
					"keyed": true,
					"min_doc_count": 0,
					"append_prefix_length": true,
					"format": "strict"
				},
				"aggs": {
					"avg_bytes": {"avg": {"field": "bytes"}}
				}
			},
			"v6_nets": {
				"ip_prefix": {
					"field": "client_ip6",
					"prefix_length": 64,
					"is_ipv6": true
				}
			},
			"ts": {
				"time_series": {
					"size": 100,
					"shard_size": 200,
					"keyed": false
				}
			},
			"ts_default": {
				"time_series": {}
			},
			"to_answers": {
				"children": {"type": "answer"}
			},
			"to_question": {
				"parent": {"type": "question"}
			}
		}
	}`), &req); err != nil {
		t.Fatalf("unmarshal new aggs failed: %v", err)
	}

	v4 := req.Aggs["v4_nets"].IPPrefix
	if v4 == nil || v4.Field != "client_ip" || v4.PrefixLength != 24 || v4.IsIPv6 || !v4.EffectiveKeyed() || v4.EffectiveMinDocCount() != 0 || !v4.EffectiveAppendPrefixLength() || v4.Format != "strict" {
		t.Fatalf("unexpected v4 ip_prefix spec: %+v", v4)
	}
	if req.Aggs["v4_nets"].Aggs["avg_bytes"].Avg == nil {
		t.Fatalf("expected sub-aggregation under ip_prefix")
	}
	v6 := req.Aggs["v6_nets"].IPPrefix
	if v6 == nil || !v6.IsIPv6 || v6.PrefixLength != 64 || v6.EffectiveKeyed() || v6.EffectiveMinDocCount() != 1 || v6.EffectiveAppendPrefixLength() {
		t.Fatalf("unexpected v6 ip_prefix defaults: %+v", v6)
	}

	ts := req.Aggs["ts"].TimeSeries
	if ts == nil || ts.EffectiveSize() != 100 || *ts.ShardSize != 200 || ts.EffectiveKeyed() {
		t.Fatalf("unexpected time_series spec: %+v", ts)
	}
	tsDef := req.Aggs["ts_default"].TimeSeries
	if tsDef == nil || tsDef.EffectiveSize() != 10000 || !tsDef.EffectiveKeyed() {
		t.Fatalf("unexpected default time_series spec: %+v", tsDef)
	}

	if ch := req.Aggs["to_answers"].Children; ch == nil || ch.Type != "answer" {
		t.Fatalf("unexpected children agg: %+v", ch)
	}
	if pa := req.Aggs["to_question"].Parent; pa == nil || pa.Type != "question" {
		t.Fatalf("unexpected parent agg: %+v", pa)
	}

	var nilIP *IPPrefixAggSpec
	if nilIP.EffectiveKeyed() || nilIP.EffectiveMinDocCount() != 1 || nilIP.EffectiveAppendPrefixLength() {
		t.Fatal("unexpected nil IPPrefixAggSpec defaults")
	}
	var nilTS *TimeSeriesAggSpec
	if nilTS.EffectiveSize() != 10000 || !nilTS.EffectiveKeyed() {
		t.Fatal("unexpected nil TimeSeriesAggSpec defaults")
	}

	for _, bad := range []string{
		`{"aggs":{"a":{"ip_prefix":{"prefix_length":24}}}}`,
		`{"aggs":{"a":{"ip_prefix":{"field":"ip"}}}}`,
		`{"aggs":{"a":{"ip_prefix":{"field":"ip","prefix_length":33}}}}`,
		`{"aggs":{"a":{"ip_prefix":{"field":"ip","prefix_length":-1}}}}`,
		`{"aggs":{"a":{"ip_prefix":{"field":"ip","prefix_length":129,"is_ipv6":true}}}}`,
		`{"aggs":{"a":{"ip_prefix":{"field":"ip","prefix_length":24,"min_doc_count":-1}}}}`,
		`{"aggs":{"a":{"ip_prefix":{"field":"ip","prefix_length":24,"unknown":1}}}}`,
		`{"aggs":{"a":{"ip_prefix":{"field":"ip","prefix_length":24,"is_ipv6":"bad"}}}}`,
		`{"aggs":{"a":{"ip_prefix":{"field":"ip","prefix_length":24,"keyed":"bad"}}}}`,
		`{"aggs":{"a":{"ip_prefix":{"field":"ip","prefix_length":24,"append_prefix_length":"bad"}}}}`,
		`{"aggs":{"a":{"time_series":{"size":0}}}}`,
		`{"aggs":{"a":{"time_series":{"shard_size":0}}}}`,
		`{"aggs":{"a":{"time_series":{"size":50,"shard_size":10}}}}`,
		`{"aggs":{"a":{"time_series":{"keyed":"bad"}}}}`,
		`{"aggs":{"a":{"time_series":{"unknown":1}}}}`,
		`{"aggs":{"a":{"children":{}}}}`,
		`{"aggs":{"a":{"children":{"type":"ans","unknown":1}}}}`,
		`{"aggs":{"a":{"parent":{}}}}`,
		`{"aggs":{"a":{"parent":{"type":"q","unknown":1}}}}`,
	} {
		var badReq SearchRequest
		if err := json.Unmarshal([]byte(bad), &badReq); err == nil {
			t.Fatalf("expected validation error for %s", bad)
		}
	}
}
