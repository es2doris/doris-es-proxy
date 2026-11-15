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
	"math"
	"strings"
	"testing"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

func buildRound60TestSchema(t *testing.T) *schema.IndexSchema {
	t.Helper()
	raw := `{
		"properties": {
			"title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
			"ws_text": {"type": "text", "analyzer": "whitespace"},
			"kw": {"type": "keyword"},
			"ip_addr": {"type": "ip"},
			"price": {"type": "double"},
			"qty": {"type": "long"},
			"uqty": {"type": "unsigned_long"},
			"created_at": {"type": "date"},
			"flag": {"type": "boolean"}
		}
	}`
	var spec esast.MappingSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		t.Fatalf("unmarshal test mapping: %v", err)
	}
	return schema.CompileIndexSchema("db", "r60_idx", &spec)
}

func TestRound60_F10_F19_CollapseAndSearchLimits(t *testing.T) {
	idx := buildRound60TestSchema(t)
	tr := NewTranspiler(idx, TranspilerOptions{
		MaxResultWindow:         100,
		MaxDocvalueFieldsSearch: 2,
		MaxScriptFields:         1,
		MaxRegexLength:          10,
	})

	// F19: max_result_window returns 400 error instead of clamping
	var srWin esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"from": 90, "size": 20}`), &srWin)
	if _, err := tr.BuildSearchPlan(&srWin); err == nil || !strings.Contains(err.Error(), "Result window is too large") {
		t.Fatalf("expected max_result_window error, got: %v", err)
	}

	// F19: max_docvalue_fields_search
	var srDV esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"docvalue_fields": ["kw", "qty", "price"]}`), &srDV)
	if _, err := tr.BuildSearchPlan(&srDV); err == nil || !strings.Contains(err.Error(), "Trying to retrieve too many docvalue_fields") {
		t.Fatalf("expected max_docvalue_fields_search error, got: %v", err)
	}

	// F19: max_script_fields
	var srSF esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"script_fields": {"s1": {"script": "1"}, "s2": {"script": "2"}}}`), &srSF)
	if _, err := tr.BuildSearchPlan(&srSF); err == nil || !strings.Contains(err.Error(), "Trying to retrieve too many script_fields") {
		t.Fatalf("expected max_script_fields error, got: %v", err)
	}

	// F19: max_regex_length on regexp query AND Lucene /regex/
	for _, badRE := range []string{
		`{"query": {"regexp": {"kw": "abcdefghijk"}}}`,
		`{"query": {"query_string": {"query": "kw:/abcdefghijk/"}}}`,
	} {
		var srRE esast.SearchRequest
		_ = json.Unmarshal([]byte(badRE), &srRE)
		if _, err := tr.BuildSearchPlan(&srRE); err == nil || !strings.Contains(err.Error(), "max_regex_length") {
			t.Fatalf("expected max_regex_length error for %s, got: %v", badRE, err)
		}
	}

	// F10: collapse validation with rescore, slice, and incompatible search_after
	for _, badCol := range []string{
		`{"collapse": {"field": "kw"}, "rescore": {"window_size": 10, "query": {"rescore_query": {"match_all": {}}}}}`,
		`{"collapse": {"field": "kw"}, "slice": {"id": 0, "max": 2}}`,
		`{"collapse": {"field": "kw"}, "sort": [{"qty": "asc"}], "search_after": [10]}`,
	} {
		var srCol esast.SearchRequest
		_ = json.Unmarshal([]byte(badCol), &srCol)
		if _, err := tr.BuildSearchPlan(&srCol); err == nil || !strings.Contains(err.Error(), "collapse") {
			t.Fatalf("expected collapse validation error for %s, got: %v", badCol, err)
		}
	}
	// Compatible collapse + sort on collapse field + search_after succeeds
	var srColOK esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"collapse": {"field": "kw"}, "sort": [{"kw": "asc"}], "search_after": ["abc"]}`), &srColOK)
	if _, err := tr.BuildSearchPlan(&srColOK); err != nil {
		t.Fatalf("expected compatible collapse + search_after to succeed, got: %v", err)
	}
}

func TestRound60_F12_F13_F14_F15_AggValidationTypedKeysPartitionsDatesPercentiles(t *testing.T) {
	idx := buildRound60TestSchema(t)
	tr := NewTranspiler(idx, TranspilerOptions{MaxAggBuckets: 50})

	// F12: Numeric metric agg on keyword/text/ip rejected when no script
	for _, badAgg := range []string{
		`{"size":0,"aggs":{"bad":{"avg":{"field":"kw"}}}}`,
		`{"size":0,"aggs":{"bad":{"sum":{"field":"title"}}}}`,
		`{"size":0,"aggs":{"bad":{"percentiles":{"field":"ip_addr"}}}}`,
	} {
		var sr esast.SearchRequest
		_ = json.Unmarshal([]byte(badAgg), &sr)
		if _, err := tr.BuildSearchPlan(&sr); err == nil || !strings.Contains(err.Error(), "is not supported for aggregation") {
			t.Fatalf("expected numeric metric field-type error for %s, got: %v", badAgg, err)
		}
	}

	// F12: TypedAggKeyPrefix
	var srTyped esast.SearchRequest
	_ = json.Unmarshal([]byte(`{
		"aggs": {
			"t_long": {"terms": {"field": "qty"}},
			"t_ulong": {"terms": {"field": "uqty"}},
			"t_dbl": {"terms": {"field": "price"}},
			"t_str": {"terms": {"field": "kw"}},
			"st_long": {"significant_terms": {"field": "qty"}},
			"st_str": {"significant_terms": {"field": "kw"}},
			"p_td": {"percentiles": {"field": "price"}},
			"p_hdr": {"percentiles": {"field": "price", "hdr": {"number_of_significant_value_digits": 3}}},
			"pr_hdr": {"percentile_ranks": {"field": "price", "values": [10], "hdr": {}}},
			"mb": {"min_bucket": {"buckets_path": "t_long>_count"}},
			"ab": {"avg_bucket": {"buckets_path": "t_long>_count"}}
		}
	}`), &srTyped)
	wantPrefixes := map[string]string{
		"t_long":  "lterms",
		"t_ulong": "uterms",
		"t_dbl":   "dterms",
		"t_str":   "sterms",
		"st_long": "siglterms",
		"st_str":  "sigsterms",
		"p_td":    "tdigest_percentiles",
		"p_hdr":   "hdr_percentiles",
		"pr_hdr":  "hdr_percentile_ranks",
		"mb":      "bucket_metric_value",
		"ab":      "simple_value",
	}
	for k, want := range wantPrefixes {
		a := srTyped.Aggs[k]
		if got := TypedAggKeyPrefix(&a, idx); got != want {
			t.Fatalf("TypedAggKeyPrefix(%s) = %q, want %q", k, got, want)
		}
	}

	// F13: terms include/exclude regex rejected on ip/numeric/date/boolean; array allowed
	var srBadTerms esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size":0,"aggs":{"ips":{"terms":{"field":"ip_addr","include":"127.*"}}}}`), &srBadTerms)
	if _, err := tr.BuildSearchPlan(&srBadTerms); err == nil || !strings.Contains(err.Error(), "include/exclude") {
		t.Fatalf("expected terms regex include error on ip field, got: %v", err)
	}
	var srOKTerms esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"size":0,"aggs":{"ips":{"terms":{"field":"ip_addr","include":["127.0.0.1"]}}}}`), &srOKTerms)
	if _, err := tr.BuildSearchPlan(&srOKTerms); err != nil {
		t.Fatalf("expected terms array include on ip field to succeed, got: %v", err)
	}

	// F13: ESTermsPartitionMatch exact partitioning (every value lands in exactly 1 partition)
	matchedPartitions := 0
	for p := 0; p < 4; p++ {
		if ESTermsPartitionMatch("hello", "keyword", p, 4) {
			matchedPartitions++
		}
	}
	if matchedPartitions != 1 {
		t.Fatalf("expected string value to match exactly 1 partition, got %d", matchedPartitions)
	}
	matchedLongPartitions := 0
	for p := 0; p < 4; p++ {
		if ESTermsPartitionMatch(int64(42), "long", p, 4) {
			matchedLongPartitions++
		}
	}
	if matchedLongPartitions != 1 {
		t.Fatalf("expected long value to match exactly 1 partition, got %d", matchedLongPartitions)
	}

	// F14: composite inside parent agg & composite.size > maxBuckets rejected
	for _, badComp := range []string{
		`{"size":0,"aggs":{"outer":{"terms":{"field":"kw"},"aggs":{"inner":{"composite":{"sources":[{"q":{"terms":{"field":"qty"}}}]}}}}}}`,
		`{"size":0,"aggs":{"comp":{"composite":{"size":51,"sources":[{"q":{"terms":{"field":"qty"}}}]}}}}`,
	} {
		var sr esast.SearchRequest
		_ = json.Unmarshal([]byte(badComp), &sr)
		if _, err := tr.BuildSearchPlan(&sr); err == nil || !strings.Contains(err.Error(), "composite") {
			t.Fatalf("expected composite validation error for %s, got: %v", badComp, err)
		}
	}

	// F14: FormatESDateWithNamedOrJavaPattern preserves iso8601 and handles SSSSSSSSS..S longest-first
	ms := time.Date(2025, 5, 10, 14, 30, 45, 123000000, time.UTC).UnixMilli()
	if got := FormatESDateWithNamedOrJavaPattern(ms, 0, "iso8601", time.UTC); got != "2025-05-10T14:30:45.123Z" {
		t.Fatalf("expected iso8601 formatted date, got %q", got)
	}
	if got := FormatESDateWithNamedOrJavaPattern(ms, 0, "basic_date", time.UTC); got != "20250510" {
		t.Fatalf("expected basic_date '20250510', got %q", got)
	}
	if got := FormatESDateWithNamedOrJavaPattern(ms, 0, "yyyy-MM-dd'T'HH:mm:ss.SSS", time.UTC); got != "2025-05-10T14:30:45.123" {
		t.Fatalf("expected Java pattern formatted date, got %q", got)
	}

	// F15: ComputeESPercentiles & ComputeESPercentileRanks (empty, TDigest, HDR, negative HDR error)
	emptyPct, err := ComputeESPercentiles(nil, []float64{50, 99}, nil)
	if err != nil || emptyPct["50.0"] != nil || emptyPct["99.0"] != nil {
		t.Fatalf("expected nil values for empty percentiles, got %v (err=%v)", emptyPct, err)
	}
	tdPct, err := ComputeESPercentiles([]float64{10, 20, 30, 40}, []float64{50}, nil)
	if err != nil || math.Abs(tdPct["50.0"].(float64)-25.0) > 1e-9 {
		t.Fatalf("expected TDigest median 25.0, got %v (err=%v)", tdPct, err)
	}
	tdRanks, err := ComputeESPercentileRanks([]float64{10, 20, 30, 40}, []float64{5, 25, 40}, nil, true)
	if err != nil {
		t.Fatalf("ComputeESPercentileRanks failed: %v", err)
	}
	rm := tdRanks.(map[string]any)
	if rm["5.0"].(float64) != 0.0 || math.Abs(rm["25.0"].(float64)-50.0) > 1e-9 || rm["40.0"].(float64) != 100.0 {
		t.Fatalf("unexpected TDigest percentile_ranks: %#v", rm)
	}
	sig3 := 3
	if _, err := ComputeESPercentiles([]float64{-1, 10}, []float64{50}, &esast.HDRConfig{NumberOfSignificantValueDigits: &sig3}); err == nil || !strings.Contains(err.Error(), "array_index_out_of_bounds_exception") {
		t.Fatalf("expected negative HDR value to return array_index_out_of_bounds_exception, got: %v", err)
	}
}

func TestRound60_F16_F17_F25_F26_Queries_Ignored_Whitespace_UAX29_Intervals(t *testing.T) {
	idx := buildRound60TestSchema(t)
	tr := NewTranspiler(idx, TranspilerOptions{})

	// F16 & F26: wildcard on analyzed text emits token-bounded (?i) RE2 on f__title; whitespace stays case-sensitive
	var srWC esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"title:BA*"}}}`), &srWC)
	planWC, err := tr.BuildSearchPlan(&srWC)
	if err != nil || !strings.Contains(planWC.HitsSQL, "`f__title` REGEXP '(?i)(^|[^[:alnum:]_])(BA[[:alnum:]_]*)($|[^[:alnum:]_])'") {
		t.Fatalf("expected token-bounded case-insensitive REGEXP on f__title, got sql=%s err=%v", planWC.HitsSQL, err)
	}

	var srWS esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"query_string":{"query":"ws_text:BA*"}}}`), &srWS)
	planWS, err := tr.BuildSearchPlan(&srWS)
	if err != nil || strings.Contains(planWS.HitsSQL, "(?i)") || !strings.Contains(planWS.HitsSQL, "`f__ws_text` REGEXP '(^|[[:space:]])(BA[^[:space:]]*)($|[[:space:]])'") {
		t.Fatalf("expected case-sensitive whitespace REGEXP on f__ws_text, got sql=%s err=%v", planWS.HitsSQL, err)
	}

	// F16 & F26: UAX#29 keeps internal '_' in single token ("value1_foo")
	toks := TokenizeByAnalyzer("Hello value1_foo world", "standard")
	if len(toks) != 3 || toks[1] != "value1_foo" {
		t.Fatalf("expected UAX#29 token 'value1_foo', got %#v", toks)
	}
	wsToks := TokenizeByAnalyzer("Hello World", "whitespace")
	if len(wsToks) != 2 || wsToks[0] != "Hello" || wsToks[1] != "World" {
		t.Fatalf("expected case-preserved whitespace tokens, got %#v", wsToks)
	}

	// F16 & F17: _ignored term/terms/exists & metadata exists (_source rejected)
	var srIg esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"bool":{"must":[{"exists":{"field":"_ignored"}},{"term":{"_ignored":"kw"}},{"terms":{"_ignored":["kw","price"]}},{"exists":{"field":"_id"}},{"exists":{"field":"_field_names"}}]}}}`), &srIg)
	planIg, err := tr.BuildSearchPlan(&srIg)
	if err != nil {
		t.Fatalf("BuildSearchPlan _ignored/meta exists failed: %v", err)
	}
	for _, want := range []string{
		"array_size(`_ignored`) > 0",
		"array_contains(`_ignored`, 'kw')",
		"arrays_overlap(`_ignored`, ['kw', 'price'])",
		"`_source` != '{}'",
	} {
		if !strings.Contains(planIg.HitsSQL, want) {
			t.Fatalf("expected %q in HitsSQL, got:\n%s", want, planIg.HitsSQL)
		}
	}
	var srBadSrc esast.SearchRequest
	_ = json.Unmarshal([]byte(`{"query":{"exists":{"field":"_source"}}}`), &srBadSrc)
	if _, err := tr.BuildSearchPlan(&srBadSrc); err == nil || !strings.Contains(err.Error(), "[_source]") {
		t.Fatalf("expected exists on _source to return 400 error, got: %v", err)
	}

	// F25: EvaluateIntervalsRule with filter.script computing exact start, end, gaps
	var qInt esast.Query
	_ = json.Unmarshal([]byte(`{
		"intervals": {
			"title": {
				"all_of": {
					"ordered": true,
					"intervals": [
						{"match": {"query": "quick"}},
						{"match": {"query": "fox"}}
					],
					"filter": {
						"script": "interval.start == 1 && interval.end == 3 && interval.gaps == 1"
					}
				}
			}
		}
	}`), &qInt)
	if !QueryHasIntervalsScript(&qInt) {
		t.Fatalf("expected QueryHasIntervalsScript=true")
	}
	rule := qInt.Intervals["title"]
	spans, matched, err := EvaluateIntervalsRule(&rule, "the quick brown fox jumps", "standard", func(sc *esast.ScriptSpec, sp IntervalsSpan) (bool, error) {
		return sp.Start == 1 && sp.End == 3 && sp.Gaps == 1, nil
	})
	if err != nil || !matched || len(spans) != 1 || spans[0] != (IntervalsSpan{Start: 1, End: 3, Gaps: 1}) {
		t.Fatalf("unexpected EvaluateIntervalsRule result: spans=%+v matched=%v err=%v", spans, matched, err)
	}
}
