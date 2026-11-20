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
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func mustCompileTestSchemaR62(t *testing.T, rawMapping string) *schema.IndexSchema {
	t.Helper()
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(rawMapping), &spec); err != nil {
		t.Fatalf("unmarshal mapping failed: %v", err)
	}
	return schema.CompileIndexSchema("db", "r62_idx", &spec)
}

func mustUnmarshalSearchReqR62(t *testing.T, raw string) *esast.SearchRequest {
	t.Helper()
	var req esast.SearchRequest
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		t.Fatalf("unmarshal SearchRequest failed: %v\npayload: %s", err, raw)
	}
	return &req
}

func TestRound62_F10_RawValuesKNNAndRangeHistogramFixes(t *testing.T) {
	// 1. Raw value collection 50k guard, CHAR(31) separation, and ParseCollectedFloatValues
	topRaw := sqlCollectRawValuesBranch("p1", "`f__val`", "`base_matched`", "`f__val` IS NOT NULL")
	if !strings.Contains(topRaw, "COUNT(`f__val`) <= 50000") || !strings.Contains(topRaw, "':OVERFLOW:'") {
		t.Fatalf("expected 50000 row guard and :OVERFLOW: sentinel in topRaw, got: %s", topRaw)
	}
	topRawWhere := sqlCollectRawValuesBranch("p1", "`f__val`", "`base_matched`", "WHERE `f__val` > 0")
	if !strings.Contains(topRawWhere, " FROM `base_matched` WHERE `f__val` > 0") {
		t.Fatalf("expected clean WHERE prefix handling, got: %s", topRawWhere)
	}
	grpRaw := sqlCollectGroupedRawValuesBranch("by_k.p1", "`f__k`", "`f__val`", "`base_matched`", "1=1")
	if !strings.Contains(grpRaw, `'\x1f', '_vals:'`) || !strings.Contains(grpRaw, "':OVERFLOW:'") {
		t.Fatalf("expected separated '\\x1f', '_vals:' and :OVERFLOW: in grpRaw, got: %s", grpRaw)
	}

	if pk, vals, ok := ParseCollectedFloatValues("_vals:1.25, 2.5"); !ok || pk != "" || len(vals) != 2 || vals[0] != 1.25 || vals[1] != 2.5 {
		t.Fatalf("unexpected top-level ParseCollectedFloatValues: pk=%q vals=%v ok=%v", pk, vals, ok)
	}
	if pk, vals, ok := ParseCollectedFloatValues("compA\x1fcompB\x1f_vals:10,20,30"); !ok || pk != "compA\x1fcompB" || len(vals) != 3 {
		t.Fatalf("expected LastIndex parent key preservation, got pk=%q vals=%v ok=%v", pk, vals, ok)
	}
	if pk, vals, ok := ParseCollectedFloatValues("_vals:"); !ok || pk != "" || len(vals) != 0 {
		t.Fatalf("expected empty 0-doc rawPart to return ok=true with nil vals, got pk=%q vals=%v ok=%v", pk, vals, ok)
	}
	if _, _, ok := ParseCollectedFloatValues("_vals::OVERFLOW:"); ok {
		t.Fatalf("expected :OVERFLOW: top-level sentinel to return ok=false so caller falls back to PERCENTILE_APPROX")
	}
	if _, _, ok := ParseCollectedFloatValues("b1\x1f_vals::OVERFLOW:"); ok {
		t.Fatalf("expected :OVERFLOW: grouped sentinel to return ok=false")
	}
	if _, _, ok := ParseCollectedFloatValues("plain_bucket"); ok {
		t.Fatalf("expected non-_vals key to return ok=false")
	}

	// 2. Nested kNN (`json_extract_string`, single window subquery, small boost, zero-norm guard) + nested histogramArrayExpr
	schKNN := mustCompileTestSchemaR62(t, `{
		"properties": {
			"dyn_vec": {"type": "dense_vector", "dims": 3, "index": false},
			"chunks": {
				"type": "nested",
				"properties": {
					"emb": {"type": "dense_vector", "dims": 2, "similarity": "cosine"},
					"bvec": {"type": "dense_vector", "dims": 2, "element_type": "byte", "similarity": "l2_norm"},
					"bitvec": {"type": "dense_vector", "dims": 8, "element_type": "bit", "similarity": "l2_norm"},
					"hist": {"type": "histogram"}
				}
			}
		}
	}`)
	trKNN := NewTranspiler(schKNN, TranspilerOptions{})

	reqNestedKNN := mustUnmarshalSearchReqR62(t, `{
		"knn": {
			"field": "chunks.emb",
			"query_vector": [0.6, 0.8],
			"k": 2,
			"num_candidates": 5,
			"boost": 0.00001
		},
		"aggs": {
			"n_chunks": {
				"nested": {"path": "chunks"},
				"aggs": {
					"by_bvec": {
						"terms": {"field": "chunks.bvec"},
						"aggs": {
							"h_avg": {"avg": {"field": "chunks.hist"}}
						}
					}
				}
			}
		}
	}`)
	planKNN, err := trKNN.BuildSearchPlan(reqNestedKNN)
	if err != nil {
		t.Fatalf("BuildSearchPlan nested knn failed: %v", err)
	}
	if !strings.Contains(planKNN.HitsSQL, "json_extract_string(_nel, '$.emb')") {
		t.Fatalf("expected json_extract_string(_nel, '$.emb') in nested knn SQL, got:\n%s", planKNN.HitsSQL)
	}
	if strings.Count(planKNN.HitsSQL, "ROW_NUMBER() OVER") != 1 {
		t.Fatalf("expected ROW_NUMBER() OVER window subquery only once (not duplicated in ScoreSQL), got count=%d:\n%s",
			strings.Count(planKNN.HitsSQL, "ROW_NUMBER() OVER"), planKNN.HitsSQL)
	}
	if !strings.Contains(planKNN.HitsSQL, "1e-05") {
		t.Fatalf("expected small boost 1e-05 preserved without %%.4f truncation, got:\n%s", planKNN.HitsSQL)
	}
	if !strings.Contains(planKNN.AggsSQL, "json_extract_string(`_nel`, '$.hist._h')") {
		t.Fatalf("expected json_extract_string for nested histogramArrayExpr, got:\n%s", planKNN.AggsSQL)
	}

	// Unindexed / dynamic cosine zero-norm guard (`INNER_PRODUCT(col, col) > 0`) and hex byte / bit nested knn
	var scriptKNN esast.SearchRequest
	if err := json.Unmarshal([]byte(`{
		"knn": [
			{"field": "chunks.bvec", "query_vector": "017f", "k": 2, "num_candidates": 4},
			{"field": "chunks.bitvec", "query_vector": "ff", "k": 2, "num_candidates": 4}
		]
	}`), &scriptKNN); err != nil {
		t.Fatalf("unmarshal byte/bit nested knn failed: %v", err)
	}
	planByteBit, err := trKNN.BuildSearchPlan(&scriptKNN)
	if err != nil || !strings.Contains(planByteBit.HitsSQL, "json_extract_string(_nel") {
		t.Fatalf("expected clean byte/bit nested knn plan, err=%v sql=%s", err, planByteBit.HitsSQL)
	}

	trDynKNN := NewTranspiler(mustCompileTestSchemaR62(t, `{"properties": {"tag": {"type": "keyword"}}}`), TranspilerOptions{})
	reqDynCos := mustUnmarshalSearchReqR62(t, `{"knn": {"field": "unmapped_vec", "query_vector": [1.0, 0.0], "k": 3, "num_candidates": 5}}`)
	if planDyn, err := trDynKNN.BuildSearchPlan(reqDynCos); err == nil && !strings.Contains(planDyn.HitsSQL, "INNER_PRODUCT(") {
		t.Fatalf("expected INNER_PRODUCT zero-norm guard on dynamic cosine knn, got:\n%s", planDyn.HitsSQL)
	}

	// 3. `*_range` sub-second BIGINT offset explosion, half-open bounds clamping, and `_rn_dedup_` sub-agg deduplication
	schRange := mustCompileTestSchemaR62(t, `{
		"properties": {
			"ts_rng": {"type": "date_range"},
			"num_rng": {"type": "integer_range"},
			"metric": {"type": "double"}
		}
	}`)
	trRange := NewTranspiler(schRange, TranspilerOptions{ES8Compat: true})
	reqRangeHist := mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"dh_100ms": {
				"date_histogram": {
					"field": "ts_rng",
					"fixed_interval": "100ms",
					"hard_bounds": {"min": "2026-05-01T00:00:00.000Z", "max": "2026-05-01T00:00:01.000Z"},
					"extended_bounds": {"min": "2026-05-01T00:00:00.000Z", "max": "2026-05-01T00:00:01.000Z"}
				},
				"aggs": {
					"avg_m": {"avg": {"field": "metric"}}
				}
			},
			"h_num": {
				"histogram": {
					"field": "num_rng",
					"interval": 5,
					"offset": 1,
					"hard_bounds": {"min": 0, "max": 50},
					"extended_bounds": {"min": 0, "max": 50}
				},
				"aggs": {
					"sum_m": {"sum": {"field": "metric"}}
				}
			}
		}
	}`)
	planRH, err := trRange.BuildSearchPlan(reqRangeHist)
	if err != nil {
		t.Fatalf("BuildSearchPlan range histograms failed: %v", err)
	}
	if !strings.Contains(planRH.AggsSQL, "AS BIGINT)") || !strings.Contains(planRH.AggsSQL, "ARRAY_RANGE(0,") || !strings.Contains(planRH.AggsSQL, "AS `_off`") {
		t.Fatalf("expected BIGINT bucket index + zero-based _off ARRAY_RANGE(0, ...), got:\n%s", planRH.AggsSQL)
	}
	if strings.Contains(planRH.AggsSQL, "1e100") || strings.Contains(planRH.AggsSQL, "1e+100") {
		t.Fatalf("expected half-open range bounds to clamp without ±1e100 sentinel, got:\n%s", planRH.AggsSQL)
	}
	if strings.Count(planRH.AggsSQL, "_rn_dedup_") < 2 {
		t.Fatalf("expected _rn_dedup_ deduplication join for both date_histogram and histogram sub-aggs on *_range, got:\n%s", planRH.AggsSQL)
	}
	from0, col0 := buildRangeBucketExplodeSQL("`base_matched`", "10", "20", 0, 0)
	if !strings.Contains(from0, "`_off`") || !strings.Contains(col0, "1.0") {
		t.Fatalf("expected interval<=0 fallback to 1.0, got from=%s col=%s", from0, col0)
	}
}

func TestRound62_F12_DocCountAndIgnoredAggs(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"k": {"type": "keyword"},
			"v": {"type": "long"}
		}
	}`)
	sch.ES8Mode = true
	tr := NewTranspiler(sch, TranspilerOptions{ES8Compat: true})
	req := mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"t_k": {"terms": {"field": "k"}},
			"t_k_miss": {"terms": {"field": "k", "missing": "N/A"}},
			"f_one": {"filter": {"term": {"k": "a"}}},
			"f_multi": {
				"filters": {
					"other_bucket": true,
					"filters": {"a": {"term": {"k": "a"}}}
				}
			},
			"f_anon": {
				"filters": {
					"filters": [{"term": {"k": "b"}}]
				}
			},
			"comp": {
				"composite": {
					"sources": [{"k": {"terms": {"field": "k"}}}]
				}
			},
			"ign_terms": {"terms": {"field": "_ignored"}},
			"ign_card": {"cardinality": {"field": "_ignored"}},
			"ign_vc": {"value_count": {"field": "_ignored"}}
		}
	}`)
	plan, err := tr.BuildSearchPlan(req)
	if err != nil {
		t.Fatalf("BuildSearchPlan F12 failed: %v", err)
	}
	if strings.Count(plan.AggsSQL, `$."_doc_count"`) < 6 || !strings.Contains(plan.AggsSQL, "TRY_CAST(json_extract_string(`_source`, '$."+`"_doc_count"`+"') AS BIGINT)") {
		t.Fatalf("expected _doc_count SUM expression across terms/filter/filters/composite, got:\n%s", plan.AggsSQL)
	}
	if strings.Count(plan.AggsSQL, "LATERAL VIEW EXPLODE(`_ignored`)") < 3 {
		t.Fatalf("expected LATERAL VIEW EXPLODE(`_ignored`) across terms/cardinality/value_count, got:\n%s", plan.AggsSQL)
	}

	// Verify SourceDisabled disables _doc_count extraction
	schNoSrc := mustCompileTestSchemaR62(t, `{"_source": {"enabled": false}, "properties": {"k": {"type": "keyword"}}}`)
	schNoSrc.ES8Mode = true
	trNoSrc := NewTranspiler(schNoSrc, TranspilerOptions{ES8Compat: true})
	planNoSrc, err := trNoSrc.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"size": 0, "aggs": {"t": {"terms": {"field": "k"}}}}`))
	if err != nil || strings.Contains(planNoSrc.AggsSQL, "_doc_count'") || strings.Contains(planNoSrc.AggsSQL, `"_doc_count"`) {
		t.Fatalf("expected _source disabled to fall back to COUNT(*), err=%v sql=%s", err, planNoSrc.AggsSQL)
	}
}

func TestRound62_F13_IPPrefixAggregation(t *testing.T) {
	if IPv4PrefixNetmask(0) != "0.0.0.0" || IPv4PrefixNetmask(24) != "255.255.255.0" || IPv4PrefixNetmask(32) != "255.255.255.255" {
		t.Fatalf("unexpected IPv4PrefixNetmask values")
	}
	if k, ok := FormatIPPrefixBucketKey("192.168.1.42", 24, false, false); !ok || k != "192.168.1.0" {
		t.Fatalf("expected 192.168.1.0, got %q ok=%v", k, ok)
	}
	if k, ok := FormatIPPrefixBucketKey("192.168.1.42", 24, false, true); !ok || k != "192.168.1.0/24" {
		t.Fatalf("expected 192.168.1.0/24, got %q ok=%v", k, ok)
	}
	if k, ok := FormatIPPrefixBucketKey("192.168.1.42", 112, true, true); !ok || k != "::ffff:192.168.0.0/112" {
		t.Fatalf("expected IPv4-mapped IPv6 network ::ffff:192.168.0.0/112, got %q ok=%v", k, ok)
	}
	if k, ok := FormatIPPrefixBucketKey("2001:db8:85a3::8a2e:370:7334", 44, true, false); !ok || k != "2001:db8:85a0::" {
		t.Fatalf("expected 2001:db8:85a0::, got %q ok=%v", k, ok)
	}
	if _, ok := FormatIPPrefixBucketKey("not-an-ip", 24, false, false); ok {
		t.Fatalf("expected invalid IP to return false")
	}
	if _, ok := FormatIPPrefixBucketKey("10.0.0.1", 33, false, false); ok {
		t.Fatalf("expected out-of-range IPv4 prefix_length=33 to return false")
	}
	if _, ok := FormatIPPrefixBucketKey("::1", 129, true, false); ok {
		t.Fatalf("expected out-of-range IPv6 prefix_length=129 to return false")
	}
	if CanonicalIPPrefixSortHex("10.0.0.0/8") >= CanonicalIPPrefixSortHex("192.168.0.0/16") {
		t.Fatalf("expected 10.0.0.0/8 < 192.168.0.0/16 in CanonicalIPPrefixSortHex")
	}
	if CanonicalIPPrefixSortHex("bad") != "bad" {
		t.Fatalf("expected invalid key passthrough")
	}

	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"addr": {"type": "ip"},
			"addrs": {"type": "ip", "multi_valued": true},
			"host": {"type": "keyword"},
			"lat": {"type": "double"}
		}
	}`)
	tr := NewTranspiler(sch, TranspilerOptions{})
	req := mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"aggs": {
			"v4_nets": {
				"ip_prefix": {"field": "addr", "prefix_length": 24, "append_prefix_length": true},
				"aggs": {"avg_lat": {"avg": {"field": "lat"}}}
			},
			"v6_arr": {
				"ip_prefix": {"field": "addrs", "prefix_length": 48, "is_ipv6": true},
				"aggs": {"avg_lat": {"avg": {"field": "lat"}}}
			},
			"by_host": {
				"terms": {"field": "host"},
				"aggs": {
					"sub_v4": {
						"ip_prefix": {"field": "addr", "prefix_length": 16},
						"aggs": {"max_lat": {"max": {"field": "lat"}}}
					},
					"sub_v6_arr": {
						"ip_prefix": {"field": "addrs", "prefix_length": 64, "is_ipv6": true},
						"aggs": {"min_lat": {"min": {"field": "lat"}}}
					}
				}
			}
		}
	}`)
	plan, err := tr.BuildSearchPlan(req)
	if err != nil {
		t.Fatalf("BuildSearchPlan ip_prefix failed: %v", err)
	}
	if !strings.Contains(plan.AggsSQL, "IPV4_NUM_TO_STRING") || !strings.Contains(plan.AggsSQL, "IPV6_NUM_TO_STRING") {
		t.Fatalf("expected IPV4_NUM_TO_STRING and IPV6_NUM_TO_STRING in ip_prefix SQL, got:\n%s", plan.AggsSQL)
	}
	spec := req.Aggs["v4_nets"]
	if got := TypedAggKeyPrefix(&spec, sch); got != "ip_prefix" {
		t.Fatalf("expected TypedAggKeyPrefix=ip_prefix, got %q", got)
	}

	// Error cases (unmarshal-time or BuildSearchPlan validation)
	for _, badJSON := range []string{
		`{"aggs": {"bad": {"ip_prefix": {"field": "addr", "prefix_length": 33}}}}`,
		`{"aggs": {"bad": {"ip_prefix": {"field": "addr", "prefix_length": -1}}}}`,
		`{"aggs": {"bad": {"ip_prefix": {"field": "addr", "prefix_length": 129, "is_ipv6": true}}}}`,
		`{"aggs": {"bad": {"ip_prefix": {"field": "host", "prefix_length": 24}}}}`,
	} {
		var badReq esast.SearchRequest
		if err := json.Unmarshal([]byte(badJSON), &badReq); err != nil {
			continue
		}
		if _, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(&badReq); err == nil {
			t.Fatalf("expected validation error for %s", badJSON)
		}
	}
	// Also test struct-level ip_prefix > 32 directly against BuildSearchPlan
	if _, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(&esast.SearchRequest{
		Aggs: map[string]esast.AggSpec{
			"bad33": {IPPrefix: &esast.IPPrefixAggSpec{Field: "addr", PrefixLength: 33}},
		},
	}); err == nil {
		t.Fatalf("expected BuildSearchPlan error for IPv4 prefix_length=33")
	}
}

func TestRound62_F14_RandomAndDiversifiedSamplers(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"author": {"type": "keyword"},
			"tags": {"type": "keyword", "multi_valued": true},
			"views": {"type": "long"}
		}
	}`)
	req := mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"query": {"match_all": {}},
		"aggs": {
			"rs": {
				"random_sampler": {"probability": 0.2, "seed": 99},
				"aggs": {"avg_v": {"avg": {"field": "views"}}}
			},
			"rs_half": {
				"random_sampler": {"probability": 0.5},
				"aggs": {"sum_v": {"sum": {"field": "views"}}}
			},
			"plain_s": {
				"sampler": {"shard_size": 50},
				"aggs": {"top_a": {"terms": {"field": "author"}}}
			},
			"div_scalar": {
				"diversified_sampler": {"shard_size": 100, "field": "author", "max_docs_per_value": 2},
				"aggs": {"top_a": {"terms": {"field": "author"}}}
			},
			"div_arr_script": {
				"diversified_sampler": {"shard_size": 25, "field": "tags", "script": {"source": "doc['author'].value"}},
				"aggs": {"avg_v": {"avg": {"field": "views"}}}
			}
		}
	}`)
	plan, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(req)
	if err != nil {
		t.Fatalf("BuildSearchPlan samplers failed: %v", err)
	}
	if !strings.Contains(plan.AggsSQL, "MURMUR_HASH3_32(`_id`, '99')") || !strings.Contains(plan.AggsSQL, "`_ds_rn` <= 2") || !strings.Contains(plan.AggsSQL, "`_smp_top`") {
		t.Fatalf("expected MURMUR_HASH3_32, _ds_rn <= 2, and _smp_top in sampler SQL:\n%s", plan.AggsSQL)
	}

	for _, badJSON := range []string{
		`{"aggs": {"rs": {"random_sampler": {"probability": 0.2}}}}`,
		`{"aggs": {"rs": {"random_sampler": {"probability": 0.0}, "aggs": {"c": {"value_count": {"field": "views"}}}}}}`,
		`{"aggs": {"rs": {"random_sampler": {"probability": 0.7}, "aggs": {"c": {"value_count": {"field": "views"}}}}}}`,
		`{"aggs": {"rs": {"random_sampler": {"probability": 1.0}, "aggs": {"c": {"value_count": {"field": "views"}}}}}}`,
		`{"aggs": {"p": {"terms": {"field": "author"}, "aggs": {"rs": {"random_sampler": {"probability": 0.1}, "aggs": {"c": {"avg": {"field": "views"}}}}}}}}`,
		`{"aggs": {"rs": {"random_sampler": {"probability": 0.1}, "aggs": {"s2": {"sampler": {"shard_size": 10}}}}}}`,
		`{"aggs": {"s": {"sampler": {"shard_size": -5}}}}`,
		`{"aggs": {"ds": {"diversified_sampler": {"field": "author", "max_docs_per_value": -1}}}}`,
	} {
		var badReq esast.SearchRequest
		if err := json.Unmarshal([]byte(badJSON), &badReq); err != nil {
			continue
		}
		if _, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(&badReq); err == nil {
			t.Fatalf("expected sampler validation error for %s", badJSON)
		}
	}
}

func TestRound62_F15_TimeSeriesAndTSID(t *testing.T) {
	tsidA := base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x01, 0xff})
	tsidB := base64.RawURLEncoding.EncodeToString([]byte{0x80, 0x00, 0x01})
	if DecodeTSIDRawHex(tsidA) >= DecodeTSIDRawHex(tsidB) {
		t.Fatalf("expected binary _tsid sort hex %s < %s", DecodeTSIDRawHex(tsidA), DecodeTSIDRawHex(tsidB))
	}
	if DecodeTSIDRawHex("%%%invalid%%%") != "%%%invalid%%%" {
		t.Fatalf("expected invalid base64 passthrough")
	}
	id, km := ParseTimeSeriesBucketKey(`abc123|{"host":"h1","rack":4,"load":0.75}`)
	if id != "abc123" || km["host"] != "h1" || km["rack"] != int64(4) || km["load"] != 0.75 {
		t.Fatalf("unexpected ParseTimeSeriesBucketKey: id=%q km=%+v", id, km)
	}
	if id2, km2 := ParseTimeSeriesBucketKey(`{"host":"only_json"}`); id2 != "" || km2["host"] != "only_json" {
		t.Fatalf("unexpected JSON-only ParseTimeSeriesBucketKey: id=%q km=%+v", id2, km2)
	}
	if id3, km3 := ParseTimeSeriesBucketKey("bare_tsid"); id3 != "bare_tsid" || len(km3) != 0 {
		t.Fatalf("unexpected bare ParseTimeSeriesBucketKey: id=%q km=%+v", id3, km3)
	}

	schTS := mustCompileTestSchemaR62(t, `{
		"properties": {
			"@timestamp": {"type": "date"},
			"host": {"type": "keyword", "time_series_dimension": true},
			"cpu": {"type": "double", "time_series_metric": "gauge"}
		}
	}`)
	schTS.IndexName = "metrics-tsdb"
	schTS.IndexMode = "time_series"

	// _tsid is aggregatable & sortable, NOT searchable!
	planTS, err := NewTranspiler(schTS, TranspilerOptions{}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{
		"size": 5,
		"sort": [{"_tsid": "asc"}],
		"aggs": {
			"by_tsid": {"terms": {"field": "_tsid"}},
			"ts": {
				"time_series": {"size": 10, "shard_size": 20, "keyed": false},
				"aggs": {"avg_cpu": {"avg": {"field": "cpu"}}}
			},
			"by_host": {
				"terms": {"field": "host"},
				"aggs": {
					"sub_ts": {
						"time_series": {"size": 5},
						"aggs": {"max_cpu": {"max": {"field": "cpu"}}}
					}
				}
			}
		}
	}`))
	if err != nil {
		t.Fatalf("BuildSearchPlan TSDB failed: %v", err)
	}
	if !strings.Contains(planTS.HitsSQL, "`__tsid` ASC") || !strings.Contains(planTS.AggsSQL, "GROUP BY `__tsid`, `__tsid_key`") || !strings.Contains(planTS.AggsSQL, "TRANSLATE(`__tsid`") {
		t.Fatalf("expected __tsid sort, __tsid/__tsid_key GROUP BY, and TRANSLATE binary sort in SQL:\nhits=%s\naggs=%s", planTS.HitsSQL, planTS.AggsSQL)
	}

	// Searching _tsid directly must fail with [_tsid] is not searchable
	if _, err := NewTranspiler(schTS, TranspilerOptions{}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"query": {"term": {"_tsid": "abc"}}}`)); err == nil || !strings.Contains(err.Error(), "[_tsid] is not searchable") {
		t.Fatalf("expected [_tsid] is not searchable error, got %v", err)
	}

	// Incompatible time_series combinations
	schNormal := mustCompileTestSchemaR62(t, `{"properties": {"host": {"type": "keyword"}}}`)
	schNormal.IndexName = "regular-idx"
	if _, err := NewTranspiler(schNormal, TranspilerOptions{}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"aggs": {"ts": {"time_series": {}}}}`)); err == nil || !strings.Contains(err.Error(), "index.mode: time_series") {
		t.Fatalf("expected non-TSDB error, got %v", err)
	}
	for _, badTS := range []string{
		`{"aggs": {"g": {"global": {}, "aggs": {"ts": {"time_series": {}}}}}}`,
		`{"aggs": {"c": {"composite": {"sources": [{"h": {"terms": {"field": "host"}}}]}, "aggs": {"ts": {"time_series": {}}}}}}`,
		`{"aggs": {"a": {"auto_date_histogram": {"field": "@timestamp"}, "aggs": {"ts": {"time_series": {}}}}}}`,
		`{"aggs": {"s": {"sampler": {}, "aggs": {"ts": {"time_series": {}}}}}}`,
		`{"aggs": {"ts": {"time_series": {}, "aggs": {"rt": {"rare_terms": {"field": "host"}}}}}}`,
	} {
		if _, err := NewTranspiler(schTS, TranspilerOptions{}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, badTS)); err == nil {
			t.Fatalf("expected time_series incompatibility error for %s", badTS)
		}
	}
}

func TestRound62_F18_ParentJoinAggsAndDisallowExpensiveQueries(t *testing.T) {
	schJoin := mustCompileTestSchemaR62(t, `{
		"properties": {
			"my_join": {
				"type": "join",
				"relations": {
					"question": ["answer", "comment"],
					"answer": "vote"
				}
			},
			"tag": {"type": "keyword"},
			"score_val": {"type": "integer"},
			"txt": {"type": "text"},
			"opt_txt": {"type": "text", "index_prefixes": {}},
			"sayt": {"type": "search_as_you_type"},
			"wild": {"type": "wildcard"},
			"nested_arr": {"type": "nested", "properties": {"k": {"type": "keyword"}}}
		}
	}`)

	reqJoinAggs := mustUnmarshalSearchReqR62(t, `{
		"size": 0,
		"query": {"term": {"tag": "java"}},
		"aggs": {
			"to_answers": {
				"children": {"type": "answer"},
				"aggs": {
					"avg_s": {"avg": {"field": "score_val"}},
					"to_votes": {"children": {"type": "vote"}}
				}
			},
			"to_questions": {
				"parent": {"type": "answer"},
				"aggs": {"by_tag": {"terms": {"field": "tag"}}}
			},
			"unmapped_rel": {
				"children": {"type": "non_existent"}
			},
			"by_tag": {
				"terms": {"field": "tag"},
				"aggs": {
					"sub_children": {
						"children": {"type": "comment"},
						"aggs": {"sum_s": {"sum": {"field": "score_val"}}}
					},
					"sub_parent": {
						"parent": {"type": "answer"},
						"aggs": {"max_s": {"max": {"field": "score_val"}}}
					},
					"sub_unmapped_c": {"children": {"type": "none"}},
					"sub_unmapped_p": {"parent": {"type": "none"}}
				}
			}
		}
	}`)
	planJ, err := NewTranspiler(schJoin, TranspilerOptions{}).BuildSearchPlan(reqJoinAggs)
	if err != nil {
		t.Fatalf("BuildSearchPlan parent-join aggs failed: %v", err)
	}
	// CTE must NOT filter by user query `tag = 'java'` at CTE root because children/parents live in separate rows!
	cteHeader := strings.SplitN(planJ.AggsSQL, "\n", 2)[0]
	if strings.Contains(cteHeader, "java") {
		t.Fatalf("expected unfiltered CTE header for children/parent join aggs, got: %s", cteHeader)
	}
	if !strings.Contains(planJ.AggsSQL, "'_children'") || !strings.Contains(planJ.AggsSQL, "'_parent'") || !strings.Contains(planJ.AggsSQL, "`_jp_") || !strings.Contains(planJ.AggsSQL, "`_jc_") {
		t.Fatalf("expected top-level and grouped children/parent join branches in SQL:\n%s", planJ.AggsSQL)
	}

	// DisallowExpensiveQueries == true
	expensiveBlocked := []struct {
		raw     string
		wantSub string
	}{
		{`{"script_fields": {"sf": {"script": "1"}}}`, "[script] queries cannot be executed"},
		{`{"query": {"script": {"script": "true"}}}`, "[script] queries cannot be executed"},
		{`{"query": {"script_score": {"query": {"match_all": {}}, "script": {"source": "1"}}}}`, "[script] queries cannot be executed"},
		{`{"query": {"function_score": {"script_score": {"script": "1"}}}}`, "[script] queries cannot be executed"},
		{`{"query": {"function_score": {"functions": [{"script_score": {"script": "1"}}]}}}`, "[script] queries cannot be executed"},
		{`{"query": {"nested": {"path": "nested_arr", "query": {"match_all": {}}}}}`, "[joining] queries cannot be executed"},
		{`{"query": {"has_child": {"type": "answer", "query": {"match_all": {}}}}}`, "[joining] queries cannot be executed"},
		{`{"query": {"has_parent": {"parent_type": "question", "query": {"match_all": {}}}}}`, "[joining] queries cannot be executed"},
		{`{"aggs": {"c": {"children": {"type": "answer"}}}}`, "[joining] queries cannot be executed"},
		{`{"query": {"fuzzy": {"txt": {"value": "abc"}}}}`, "[fuzzy] queries cannot be executed"},
		{`{"query": {"match": {"txt": {"query": "abc", "fuzziness": 1}}}}`, "[fuzzy] queries cannot be executed"},
		{`{"query": {"multi_match": {"query": "abc", "fields": ["txt"], "fuzziness": "AUTO"}}}`, "[fuzzy] queries cannot be executed"},
		{`{"query": {"match_bool_prefix": {"opt_txt": {"query": "abc", "fuzziness": 1}}}}`, "[fuzzy] queries cannot be executed"},
		{`{"query": {"prefix": {"txt": {"value": "ab"}}}}`, "[prefix] queries cannot be executed"},
		{`{"query": {"match_bool_prefix": {"txt": {"query": "ab cd"}}}}`, "[prefix] queries cannot be executed"},
		{`{"query": {"multi_match": {"query": "ab cd", "type": "bool_prefix", "fields": ["txt"]}}}`, "[prefix] queries cannot be executed"},
		{`{"query": {"wildcard": {"txt": {"value": "a*b"}}}}`, "[wildcard] queries cannot be executed"},
		{`{"query": {"regexp": {"txt": {"value": "a.*"}}}}`, "[regexp] queries cannot be executed"},
		{`{"query": {"range": {"tag": {"gte": "a", "lte": "z"}}}}`, "[range] queries on [text] or [keyword]"},
		{`{"query": {"query_string": {"query": "txt:/ab.*/"}}}`, "[regexp] queries cannot be executed"},
		{`{"query": {"query_string": {"default_field": "txt", "query": "/ab.*/"}}}`, "[regexp] queries cannot be executed"},
		{`{"query": {"query_string": {"query": "tag:[a TO z]"}}}`, "[range] queries on [text] or [keyword]"},
		{`{"query": {"query_string": {"query": "txt:abc~1"}}}`, "[fuzzy] queries cannot be executed"},
		{`{"query": {"query_string": {"default_field": "txt", "query": "abc~2"}}}`, "[fuzzy] queries cannot be executed"},
		{`{"query": {"query_string": {"query": "txt:abc*"}}}`, "[prefix] queries cannot be executed"},
		{`{"query": {"query_string": {"query": "txt:a?c"}}}`, "[wildcard] queries cannot be executed"},
		{`{"query": {"query_string": {"default_field": "txt", "query": "abc*"}}}`, "[prefix] queries cannot be executed"},
		{`{"query": {"query_string": {"default_field": "txt", "query": "a?c"}}}`, "[wildcard] queries cannot be executed"},
		{`{"post_filter": {"wildcard": {"tag": {"value": "a*"}}}}`, "[wildcard] queries cannot be executed"},
		{`{"rescore": {"query": {"rescore_query": {"fuzzy": {"txt": {"value": "abc"}}}}}}`, "[fuzzy] queries cannot be executed"},
		{`{"aggs": {"f": {"filter": {"regexp": {"tag": {"value": "a.*"}}}}}}`, "[regexp] queries cannot be executed"},
	}
	for _, tc := range expensiveBlocked {
		_, err := NewTranspiler(schJoin, TranspilerOptions{DisallowExpensiveQueries: true}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, tc.raw))
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("DisallowExpensiveQueries expected %q for %s, got %v", tc.wantSub, tc.raw, err)
		}
	}

	// Allowed queries when DisallowExpensiveQueries == true (`index_prefixes`, `search_as_you_type`, `wildcard` field, numeric `range`)
	expensiveAllowed := []string{
		`{"query": {"prefix": {"opt_txt": {"value": "ab"}}}}`,
		`{"query": {"prefix": {"sayt": {"value": "ab"}}}}`,
		`{"query": {"match_bool_prefix": {"opt_txt": {"query": "ab cd", "fuzziness": 0}}}}`,
		`{"query": {"wildcard": {"wild": {"value": "*abc*"}}}}`,
		`{"query": {"regexp": {"wild": {"value": "ab.*"}}}}`,
		`{"query": {"range": {"score_val": {"gte": 1, "lte": 10}}}}`,
		`{"query": {"query_string": {"default_field": "wild", "query": "/ab.*/ AND a?c AND abc*"}}}`,
		`{"query": {"bool": {"must": [{"constant_score": {"filter": {"term": {"tag": "x"}}}}], "should": [{"dis_max": {"queries": [{"term": {"tag": "y"}}]}}]}}}`,
	}
	for _, raw := range expensiveAllowed {
		if _, err := NewTranspiler(schJoin, TranspilerOptions{DisallowExpensiveQueries: true}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, raw)); err != nil {
			t.Fatalf("DisallowExpensiveQueries unexpectedly rejected %s: %v", raw, err)
		}
	}
}

func TestRound62_F17_MapperExtrasAndF22RuntimeFields(t *testing.T) {
	sch := mustCompileTestSchemaR62(t, `{
		"runtime": {
			"rt_long": {"type": "long"},
			"rt_dbl": {"type": "double"},
			"rt_bool": {"type": "boolean"},
			"rt_date": {"type": "date"},
			"rt_ip": {"type": "ip"},
			"rt.dotted": {"type": "keyword"},
			"rt_comp": {
				"type": "composite",
				"fields": {
					"sub_kw": {"type": "keyword"},
					"sub_num": {"type": "long"}
				}
			}
		},
		"properties": {
			"sayt": {"type": "search_as_you_type", "max_shingle_size": 4},
			"mot": {"type": "match_only_text"},
			"rf": {"type": "rank_feature", "null_value": 2.5},
			"neg_rf": {"type": "rank_features", "positive_score_impact": false},
			"sf": {"type": "scaled_float", "scaling_factor": 100}
		}
	}`)

	tr := NewTranspiler(sch, TranspilerOptions{})

	// 1. search_as_you_type: short & >20-char ._index_prefix, root prefix, shingle subfields, multi_match bool_prefix expansion
	pShort := tr.CompileQuery(&esast.Query{Term: map[string]esast.TermEntry{"sayt._index_prefix": {Value: "quick br"}}}, false, nil)
	if !strings.Contains(pShort.WhereSQL, "array_contains(`f__sayt___index_prefix`, 'quick br')") {
		t.Fatalf("expected array_contains on f__sayt___index_prefix, got %s", pShort.WhereSQL)
	}
	pLong := tr.CompileQuery(&esast.Query{Term: map[string]esast.TermEntry{"sayt._index_prefix": {Value: "quick brown fox jump lazy"}}}, false, nil)
	if !strings.Contains(pLong.WhereSQL, "f__sayt___4gram") {
		t.Fatalf("expected >20 rune _index_prefix term to fall back to _4gram + root prefix, got %s", pLong.WhereSQL)
	}
	mmPlan, err := tr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{
		"query": {
			"multi_match": {
				"query": "quick brown fox ju",
				"type": "bool_prefix",
				"fields": ["sayt"]
			}
		}
	}`))
	if err != nil || !strings.Contains(mmPlan.HitsSQL, "f__sayt___2gram") || !strings.Contains(mmPlan.HitsSQL, "f__sayt___3gram") || !strings.Contains(mmPlan.HitsSQL, "f__sayt___4gram") {
		t.Fatalf("expected multi_match bool_prefix on sayt to expand _2gram/_3gram/_4gram, err=%v sql=%s", err, mmPlan.HitsSQL)
	}
	var badMM esast.SearchRequest
	if err := json.Unmarshal([]byte(`{"query": {"multi_match": {"query": "a b", "type": "bool_prefix", "fields": ["sayt"], "slop": 2}}}`), &badMM); err == nil {
		if _, err := tr.BuildSearchPlan(&badMM); err == nil {
			t.Fatalf("expected slop on multi_match bool_prefix to return error")
		}
	}
	if _, err := tr.BuildSearchPlan(&esast.SearchRequest{
		Query: &esast.Query{
			MultiMatch: &esast.MultiMatchQuery{
				Query:  "a b",
				Type:   "bool_prefix",
				Fields: []string{"sayt"},
				Slop:   2,
			},
		},
	}); err == nil {
		t.Fatalf("expected struct-level slop on multi_match bool_prefix to return error")
	}

	// 2. match_only_text: prefix allowed, span_* rejected!
	motPfx, err := tr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"query": {"prefix": {"mot": {"value": "luc"}}}}`))
	if err != nil || !strings.Contains(motPfx.HitsSQL, "REGEXP") {
		t.Fatalf("expected prefix on match_only_text to succeed with token-boundary REGEXP, err=%v sql=%s", err, motPfx.HitsSQL)
	}
	for _, spanBad := range []string{
		`{"query": {"span_term": {"mot": {"value": "lucene"}}}}`,
		`{"query": {"span_near": {"clauses": [{"span_term": {"mot": {"value": "apache"}}}, {"span_term": {"mot": {"value": "lucene"}}}], "slop": 1}}}`,
		`{"query": {"span_multi": {"match": {"prefix": {"mot": {"value": "luc"}}}}}}`,
	} {
		if _, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, spanBad)); err == nil || !strings.Contains(err.Error(), "match_only_text") {
			t.Fatalf("expected span query on match_only_text to fail for %s, got %v", spanBad, err)
		}
	}

	// 3. rank_feature null_value + rank_features dotted child with positive_score_impact: false & linear: {}
	rfPlan, err := tr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{
		"query": {
			"bool": {
				"should": [
					{"rank_feature": {"field": "rf"}},
					{"rank_feature": {"field": "neg_rf.1star", "linear": {}}}
				]
			}
		}
	}`))
	if err != nil || !strings.Contains(rfPlan.HitsSQL, "IS NULL OR") || !strings.Contains(rfPlan.HitsSQL, "2.5") || !strings.Contains(rfPlan.HitsSQL, "1.0 /") {
		t.Fatalf("expected rank_feature null_value=2.5 COALESCE and neg_rf.1star 1.0/x linear inverse score, err=%v sql=%s", err, rfPlan.HitsSQL)
	}

	// 4. scaled_float sort & search_after with numeric_type: "long"
	sfPlan, err := tr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{
		"sort": [{"sf": {"order": "asc", "numeric_type": "long"}}],
		"search_after": [-2]
	}`))
	if err != nil || strings.Count(sfPlan.HitsSQL, "CAST(TRUNCATE(`f__sf`, 0) AS BIGINT)") < 2 {
		t.Fatalf("expected CAST(TRUNCATE(`f__sf`, 0) AS BIGINT) in both ORDER BY and search_after, err=%v sql=%s", err, sfPlan.HitsSQL)
	}

	// 5. F22 Scriptless Runtime Fields (index-level & search-request runtime_mappings + composite subfields + dotted keys)
	rtPlan, err := tr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{
		"runtime_mappings": {
			"req_kw": {"type": "keyword"}
		},
		"query": {
			"bool": {
				"must": [
					{"term": {"req_kw": {"value": "Alpha", "case_insensitive": true}}},
					{"terms": {"rt.dotted": ["x", "y"]}},
					{"prefix": {"rt_comp.sub_kw": {"value": "pre"}}},
					{"wildcard": {"req_kw": {"value": "A*a"}}},
					{"range": {"rt_long": {"gte": 10, "lt": 100}}},
					{"range": {"rt_dbl": {"gt": 1.5}}},
					{"term": {"rt_bool": true}},
					{"exists": {"field": "rt_date"}}
				]
			}
		},
		"sort": [{"rt_comp.sub_num": "desc"}],
		"aggs": {
			"by_rt": {"terms": {"field": "rt.dotted"}},
			"avg_rt": {"avg": {"field": "rt_dbl"}}
		}
	}`))
	if err != nil {
		t.Fatalf("BuildSearchPlan scriptless runtime fields failed: %v", err)
	}
	if !strings.Contains(rtPlan.HitsSQL, `json_extract_string(`+"`_source`"+`, '$."req_kw"')`) ||
		!strings.Contains(rtPlan.HitsSQL, `$."rt.dotted"`) ||
		!strings.Contains(rtPlan.HitsSQL, `$."rt_comp"."sub_kw"`) ||
		!strings.Contains(rtPlan.AggsSQL, `$."rt_dbl"`) {
		t.Fatalf("expected _source json_extract_string pushdown across runtime queries/sort/aggs:\nhits=%s\naggs=%s", rtPlan.HitsSQL, rtPlan.AggsSQL)
	}
}

func TestRound62_F20_F19_CustomAnalysisValidateExplainAndSearchTail(t *testing.T) {
	cfg, err := analysis.ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"my_syn": map[string]any{
					"type":     "synonym_graph",
					"synonyms": []any{"ny, new york", "fast, quick, speedy"},
				},
			},
			"analyzer": map[string]any{
				"syn_an": map[string]any{
					"tokenizer": "standard",
					"filter":    []any{"lowercase", "my_syn"},
				},
				"default_search": map[string]any{
					"tokenizer": "standard",
					"filter":    []any{"lowercase"},
				},
			},
			"normalizer": map[string]any{
				"folding_norm": map[string]any{
					"type":   "custom",
					"filter": []any{"lowercase", "asciifolding"},
				},
			},
		},
	}, analysis.Options{})
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig failed: %v", err)
	}

	sch := mustCompileTestSchemaR62(t, `{
		"properties": {
			"body": {"type": "text", "search_analyzer": "syn_an"},
			"code": {"type": "keyword", "normalizer": "folding_norm"},
			"pfx_text": {"type": "text", "index_prefixes": {}},
			"ws_text": {"type": "text", "analyzer": "whitespace"}
		}
	}`)
	tr := NewTranspiler(sch, TranspilerOptions{AnalysisConfig: cfg, MaxRegexLength: 5})

	// 1. Custom synonym_graph match, match_phrase, match_phrase_prefix, match_bool_prefix, and normalizer term/terms/prefix
	synReq := mustUnmarshalSearchReqR62(t, `{
		"query": {
			"bool": {
				"must": [
					{"match": {"body": {"query": "ny pizza", "minimum_should_match": 2}}},
					{"match_phrase": {"body": {"query": "ny cafe"}}},
					{"match_phrase_prefix": {"body": {"query": "fast fo"}}},
					{"match_bool_prefix": {"body": {"query": "fast fo", "operator": "and"}}},
					{"match_bool_prefix": {"ws_text": {"query": "CaseCheck Pfx", "minimum_should_match": 1}}},
					{"term": {"code": "CAFÉ"}},
					{"terms": {"code": ["CAFÉ", "NAÏVE"]}},
					{"prefix": {"code": "CAFÉ"}},
					{"exists": {"field": "_routing"}},
					{"span_multi": {"match": {"prefix": {"pfx_text": {"value": "ind"}}}}}
				]
			}
		}
	}`)
	synPlan, err := tr.BuildSearchPlan(synReq)
	if err != nil {
		t.Fatalf("BuildSearchPlan custom analysis failed: %v", err)
	}
	if !strings.Contains(synPlan.HitsSQL, "new") || !strings.Contains(synPlan.HitsSQL, "york") {
		t.Fatalf("expected multi-word synonym_graph 'new york' expansion in HitsSQL:\n%s", synPlan.HitsSQL)
	}
	if !strings.Contains(synPlan.HitsSQL, "'cafe'") || !strings.Contains(synPlan.HitsSQL, "'naive'") {
		t.Fatalf("expected asciifolding+lowercase normalizer to rewrite CAFÉ->cafe and NAÏVE->naive:\n%s", synPlan.HitsSQL)
	}
	if !strings.Contains(synPlan.HitsSQL, "`_routing` IS NOT NULL AND `_routing` != ''") {
		t.Fatalf("expected exists:_routing predicate, got:\n%s", synPlan.HitsSQL)
	}

	// DisableSynonymsPhraseQuery: true
	trNoPhrase := NewTranspiler(sch, TranspilerOptions{AnalysisConfig: cfg, DisableSynonymsPhraseQuery: true})
	noPhrasePlan, err := trNoPhrase.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"query": {"match": {"body": {"query": "ny", "operator": "and"}}}}`))
	if err != nil || !strings.Contains(noPhrasePlan.HitsSQL, "AND") {
		t.Fatalf("expected DisableSynonymsPhraseQuery boolean expansion, err=%v sql=%s", err, noPhrasePlan.HitsSQL)
	}

	// 2. max_regex_length error suffix & exists:_source error
	if _, err := tr.BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"query": {"regexp": {"code": {"value": "123456789"}}}}`)); err == nil || !strings.Contains(err.Error(), "[index.max_regex_length] index level setting.") {
		t.Fatalf("expected max_regex_length setting suffix in error, got %v", err)
	}
	if _, err := NewTranspiler(sch, TranspilerOptions{}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"query": {"exists": {"field": "_source"}}}`)); err == nil || !strings.Contains(err.Error(), "Field [_source] is not supported in [exists] queries") {
		t.Fatalf("expected Field [_source] is not supported in [exists] queries, got %v", err)
	}

	// 3. FormatLuceneValidateExplanation coverage across query variants
	explainCases := []struct {
		raw  string
		want string
	}{
		{`{"match_all": {}}`, "*:*"},
		{`{"match_none": {}}`, "MatchNoDocsQuery"},
		{`{"term": {"code": "abc"}}`, "code:abc"},
		{`{"prefix": {"code": "ab"}}`, "code:ab*"},
		{`{"match": {"body": "ny"}}`, `body:"new york"`},
		{`{"match": {"body": "fast"}}`, "Synonym("},
		{`{"match_phrase": {"body": "ny trip"}}`, `body:"new york trip"`},
		{`{"match_phrase": {"body": "fast"}}`, "fast"},
		{`{"match_phrase_prefix": {"body": "ny tr"}}`, `body:"new york tr*"`},
		{`{"match_bool_prefix": {"body": {"query": "fast tr", "operator": "and"}}}`, "+Synonym("},
		{`{"query_string": {"default_field": "body", "query": "body:\"ny trip\""}}`, `body:"new york trip"`},
		{`{"bool": {"must": [{"term": {"code": "a"}}], "filter": [{"term": {"code": "b"}}], "should": [{"term": {"code": "c"}}], "must_not": [{"term": {"code": "d"}}]}}`, "+code:a #code:b code:c -code:d"},
	}
	for _, tc := range explainCases {
		var q esast.Query
		if err := json.Unmarshal([]byte(tc.raw), &q); err != nil {
			t.Fatalf("unmarshal explain query %s failed: %v", tc.raw, err)
		}
		got := FormatLuceneValidateExplanation(&q, sch, cfg, analysis.Options{})
		if !strings.Contains(got, tc.want) {
			t.Fatalf("FormatLuceneValidateExplanation(%s) = %q, expected substring %q", tc.raw, got, tc.want)
		}
	}
	if gotNil := FormatLuceneValidateExplanation(nil, sch, cfg, analysis.Options{}); gotNil != "*:*" {
		t.Fatalf("expected nil query explain *:* got %q", gotNil)
	}
}

func TestRound62_AdditionalBranchCoverage(t *testing.T) {
	// 1. Range bounds clamping variants (extended_bounds only, unbounded, string bounds)
	schRange := mustCompileTestSchemaR62(t, `{
		"properties": {
			"ts_rng": {"type": "date_range"},
			"num_rng": {"type": "integer_range"}
		}
	}`)
	trRange := NewTranspiler(schRange, TranspilerOptions{})
	for _, raw := range []string{
		`{"size": 0, "aggs": {"dh": {"date_histogram": {"field": "ts_rng", "fixed_interval": "1s", "extended_bounds": {"min": "1000", "max": "5000"}}}}}`,
		`{"size": 0, "aggs": {"dh": {"date_histogram": {"field": "ts_rng", "fixed_interval": "1s"}}}}`,
		`{"size": 0, "aggs": {"h": {"histogram": {"field": "num_rng", "interval": 10, "extended_bounds": {"min": 0, "max": 100}}}}}`,
		`{"size": 0, "aggs": {"h": {"histogram": {"field": "num_rng", "interval": 10}}}}`,
	} {
		if _, err := trRange.BuildSearchPlan(mustUnmarshalSearchReqR62(t, raw)); err != nil {
			t.Fatalf("range histogram variant failed for %s: %v", raw, err)
		}
	}

	// 2. DisallowExpensiveQueries nested agg filters, fuzziness variants, and wildcard/prefix edge cases
	schExp := mustCompileTestSchemaR62(t, `{
		"properties": {
			"txt": {"type": "text"},
			"kw": {"type": "keyword"},
			"wild": {"type": "wildcard"}
		}
	}`)
	for _, blocked := range []string{
		`{"aggs": {"f": {"filters": {"filters": {"k": {"wildcard": {"kw": {"value": "a*"}}}}}}}}`,
		`{"aggs": {"f": {"filters": {"filters": [{"fuzzy": {"txt": {"value": "abc"}}}]}}}}`,
		`{"aggs": {"t": {"terms": {"field": "kw"}, "aggs": {"sub": {"filter": {"prefix": {"txt": {"value": "ab"}}}}}}}}`,
		`{"query": {"match": {"txt": {"query": "abc", "fuzziness": "AUTO:3,6"}}}}`,
		`{"query": {"simple_query_string": {"query": "abc*", "fields": ["txt"]}}}`,
	} {
		if _, err := NewTranspiler(schExp, TranspilerOptions{DisallowExpensiveQueries: true}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, blocked)); err == nil {
			t.Fatalf("expected DisallowExpensiveQueries error for %s", blocked)
		}
	}
	for _, allowed := range []string{
		`{"query": {"match": {"txt": {"query": "abc", "fuzziness": "0"}}}}`,
		`{"query": {"match": {"txt": {"query": "abc", "fuzziness": 0.0}}}}`,
	} {
		if _, err := NewTranspiler(schExp, TranspilerOptions{DisallowExpensiveQueries: true}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, allowed)); err != nil {
			t.Fatalf("unexpected DisallowExpensiveQueries error for %s: %v", allowed, err)
		}
	}

	// 3. SAYT root prefix lengths (_2gram, _3gram, whitespace, empty), analyzed prefix alias, span_multi variants, rank_feature variants
	schMisc := mustCompileTestSchemaR62(t, `{
		"runtime": {
			"rt_arr": {"type": "keyword"},
			"rt_ns": {"type": "date_nanos"}
		},
		"properties": {
			"sayt3": {"type": "search_as_you_type", "max_shingle_size": 3},
			"sayt2": {"type": "search_as_you_type", "max_shingle_size": 2},
			"arr_txt": {"type": "text", "multi_valued": true},
			"txt_alias": {"type": "alias", "path": "arr_txt"},
			"num": {"type": "long"},
			"kw": {"type": "keyword"},
			"mot": {"type": "match_only_text"},
			"rf_plain": {"type": "rank_feature"},
			"pos_rf": {"type": "rank_features", "positive_score_impact": true}
		}
	}`)
	trMisc := NewTranspiler(schMisc, TranspilerOptions{})
	for _, raw := range []string{
		`{"query": {"prefix": {"sayt3": {"value": "one two three"}}}}`,
		`{"query": {"prefix": {"sayt2": {"value": "one two"}}}}`,
		`{"query": {"prefix": {"sayt2": {"value": ""}}}}`,
		`{"query": {"prefix": {"txt_alias": {"value": "tok"}}}}`,
		`{"query": {"prefix": {"arr_txt": {"value": "alpha beta"}}}}`,
		`{"query": {"match_bool_prefix": {"sayt*": {"query": "alpha beta", "minimum_should_match": "75%"}}}}`,
		`{"query": {"match_bool_prefix": {"kw": {"query": "exact prefix", "operator": "and"}}}}`,
		`{"query": {"match_bool_prefix": {"arr_txt": {"query": "one two three", "fuzziness": 1}}}}`,
		`{"query": {"match_bool_prefix": {"num": {"query": "not_a_num", "lenient": true}}}}`,
		`{"query": {"bool": {"should": [{"rank_feature": {"field": "rf_plain"}}, {"rank_feature": {"field": "pos_rf.topic"}}]}}}`,
		`{"query": {"terms": {"rt_arr": ["a", "b"]}}, "aggs": {"avg_ns": {"avg": {"field": "rt_ns"}}, "arr_rt": {"terms": {"field": "rt_arr"}}}}`,
	} {
		if _, err := trMisc.BuildSearchPlan(mustUnmarshalSearchReqR62(t, raw)); err != nil {
			t.Fatalf("unexpected BuildSearchPlan error for %s: %v", raw, err)
		}
	}
	// Numeric match_bool_prefix without lenient -> error
	if _, err := NewTranspiler(schMisc, TranspilerOptions{}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, `{"query": {"match_bool_prefix": {"num": {"query": "not_a_num"}}}}`)); err == nil {
		t.Fatalf("expected numeric parse error on match_bool_prefix without lenient")
	}
	// span_multi wildcard/regexp/fuzzy/term on match_only_text -> error
	for _, sm := range []string{
		`{"query": {"span_multi": {"match": {"wildcard": {"mot": {"value": "lu*"}}}}}}`,
		`{"query": {"span_multi": {"match": {"regexp": {"mot": {"value": "lu.*"}}}}}}`,
		`{"query": {"span_multi": {"match": {"fuzzy": {"mot": {"value": "luc"}}}}}}`,
		`{"query": {"span_multi": {"match": {"range": {"mot": {"gte": "a"}}}}}}`,
	} {
		if _, err := NewTranspiler(schMisc, TranspilerOptions{}).BuildSearchPlan(mustUnmarshalSearchReqR62(t, sm)); err == nil {
			t.Fatalf("expected span_multi on match_only_text error for %s", sm)
		}
	}
}
