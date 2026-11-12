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
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func doRound57MemReq(t *testing.T, srv *Server, method, path, body string) (int, string, map[string]any) {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		if strings.Contains(body, "\n") && !strings.HasPrefix(strings.TrimSpace(body), "{") {
			req.Header.Set("Content-Type", "application/x-ndjson")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	raw := rec.Body.String()
	var parsed map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	_ = dec.Decode(&parsed)
	return rec.Code, raw, parsed
}

func extractRound57HitIDs(t *testing.T, res map[string]any) []string {
	t.Helper()
	hitsObj, _ := res["hits"].(map[string]any)
	hitsArr, _ := hitsObj["hits"].([]any)
	out := make([]string, 0, len(hitsArr))
	for _, h := range hitsArr {
		hm, _ := h.(map[string]any)
		if id, ok := hm["_id"].(string); ok {
			out = append(out, id)
		}
	}
	return out
}

func TestRound57MemBackendUnsignedLongExactPrecision(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	code, raw, _ := doRound57MemReq(t, srv, http.MethodPut, "/r57_ulong", `{
		"mappings": {
			"properties": {
				"grp": {"type": "keyword"},
				"u_val": {"type": "unsigned_long"},
				"u_arr": {"type": "unsigned_long"}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("PUT /r57_ulong failed (%d): %s", code, raw)
	}

	docs := []struct {
		id   string
		body string
	}{
		{"d0", `{"grp":"g1","u_val":0,"u_arr":[0,42]}`},
		{"d1", `{"grp":"g1","u_val":9223372036854775807,"u_arr":[9223372036854775807]}`},
		{"d2", `{"grp":"g1","u_val":9223372036854775808,"u_arr":[9223372036854775808]}`},
		{"d3", `{"grp":"g2","u_val":18446744073709551614,"u_arr":[18446744073709551614]}`},
		{"d4", `{"grp":"g2","u_val":18446744073709551615,"u_arr":[42,18446744073709551615]}`},
	}
	for _, d := range docs {
		c, r, _ := doRound57MemReq(t, srv, http.MethodPut, "/r57_ulong/_doc/"+d.id+"?refresh=true", d.body)
		if c != http.StatusCreated && c != http.StatusOK {
			t.Fatalf("index %s failed (%d): %s", d.id, c, r)
		}
	}

	// 1. term: MaxInt64 must NOT match values > MaxInt64 that clamped in BIGINT f__u_val
	code, raw, res := doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{"query":{"term":{"u_val":9223372036854775807}}}`)
	if code != http.StatusOK {
		t.Fatalf("search term MaxInt64 failed (%d): %s", code, raw)
	}
	if ids := extractRound57HitIDs(t, res); !reflect.DeepEqual(ids, []string{"d1"}) {
		t.Fatalf("expected [d1] for term MaxInt64, got %v (raw=%s)", ids, raw)
	}

	// 2. term: MaxUint64 - 1 vs MaxUint64 (verifies 64-bit integer comparison without float64 53-bit truncation)
	code, raw, res = doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{"query":{"term":{"u_val":"18446744073709551614"}}}`)
	if code != http.StatusOK {
		t.Fatalf("search term MaxUint64-1 failed (%d): %s", code, raw)
	}
	if ids := extractRound57HitIDs(t, res); !reflect.DeepEqual(ids, []string{"d3"}) {
		t.Fatalf("expected [d3] for term MaxUint64-1, got %v (raw=%s)", ids, raw)
	}

	// 3. terms query across signed/unsigned boundary
	code, raw, res = doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{
		"query": {"terms": {"u_val": ["9223372036854775808", "18446744073709551615"]}},
		"sort": [{"u_val": "asc"}]
	}`)
	if code != http.StatusOK {
		t.Fatalf("search terms failed (%d): %s", code, raw)
	}
	if ids := extractRound57HitIDs(t, res); !reflect.DeepEqual(ids, []string{"d2", "d4"}) {
		t.Fatalf("expected [d2 d4] for terms query, got %v", ids)
	}

	// 4. range lte: MaxInt64 and gt: MaxUint64 - 1 (scalar & multi-valued array)
	_, _, resLte := doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{
		"query": {"range": {"u_val": {"lte": 9223372036854775807}}},
		"sort": [{"u_val": "asc"}]
	}`)
	if ids := extractRound57HitIDs(t, resLte); !reflect.DeepEqual(ids, []string{"d0", "d1"}) {
		t.Fatalf("expected [d0 d1] for range lte MaxInt64, got %v", ids)
	}
	_, _, resGt := doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{
		"query": {"range": {"u_val": {"gt": "18446744073709551614"}}}
	}`)
	if ids := extractRound57HitIDs(t, resGt); !reflect.DeepEqual(ids, []string{"d4"}) {
		t.Fatalf("expected [d4] for range gt MaxUint64-1, got %v", ids)
	}
	_, _, resArrRange := doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{
		"query": {"range": {"u_arr": {"gt": "18446744073709551614"}}}
	}`)
	if ids := extractRound57HitIDs(t, resArrRange); !reflect.DeepEqual(ids, []string{"d4"}) {
		t.Fatalf("expected [d4] for multi-valued u_arr range gt MaxUint64-1, got %v", ids)
	}

	// 5. sort ASC, sort DESC, sort on multi-valued u_arr, and search_after at MaxUint64-1
	_, _, resSortAsc := doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{"sort":[{"u_val":"asc"}]}`)
	if ids := extractRound57HitIDs(t, resSortAsc); !reflect.DeepEqual(ids, []string{"d0", "d1", "d2", "d3", "d4"}) {
		t.Fatalf("expected ASC order [d0 d1 d2 d3 d4], got %v", ids)
	}
	_, _, resSortDesc := doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{"sort":[{"u_val":"desc"}]}`)
	if ids := extractRound57HitIDs(t, resSortDesc); !reflect.DeepEqual(ids, []string{"d4", "d3", "d2", "d1", "d0"}) {
		t.Fatalf("expected DESC order [d4 d3 d2 d1 d0], got %v", ids)
	}
	_, _, resAfter := doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{
		"sort": [{"u_val": "asc"}],
		"search_after": ["18446744073709551614"]
	}`)
	if ids := extractRound57HitIDs(t, resAfter); !reflect.DeepEqual(ids, []string{"d4"}) {
		t.Fatalf("expected [d4] after 18446744073709551614, got %v", ids)
	}
	_, _, resArrSort := doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{"sort":[{"u_arr":{"order":"desc","mode":"max"}}]}`)
	if ids := extractRound57HitIDs(t, resArrSort); !reflect.DeepEqual(ids, []string{"d4", "d3", "d2", "d1", "d0"}) {
		t.Fatalf("expected u_arr max DESC order [d4 d3 d2 d1 d0], got %v", ids)
	}

	// 6. Top-level and sub-aggregation terms preserve exact 20-digit unsigned_long bucket keys
	code, raw, resAgg := doRound57MemReq(t, srv, http.MethodPost, "/r57_ulong/_search", `{
		"size": 0,
		"aggs": {
			"u_buckets": {"terms": {"field": "u_val", "size": 10}},
			"by_grp": {
				"terms": {"field": "grp"},
				"aggs": {"sub_u": {"terms": {"field": "u_val", "size": 10}}}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("terms agg failed (%d): %s", code, raw)
	}
	aggsMap, _ := resAgg["aggregations"].(map[string]any)
	uBucketsObj, _ := aggsMap["u_buckets"].(map[string]any)
	uBuckets, _ := uBucketsObj["buckets"].([]any)
	if len(uBuckets) != 5 {
		t.Fatalf("expected 5 distinct u_val buckets (no MaxInt64 clamping collision), got %d: %s", len(uBuckets), raw)
	}
	seenKeys := make(map[string]bool)
	for _, b := range uBuckets {
		bm, _ := b.(map[string]any)
		seenKeys[strings.TrimSpace(jsonStringifyKey(bm["key"]))] = true
	}
	for _, wantK := range []string{"0", "9223372036854775807", "9223372036854775808", "18446744073709551614", "18446744073709551615"} {
		if !seenKeys[wantK] {
			t.Fatalf("missing expected unsigned_long bucket key %s in %v (raw=%s)", wantK, seenKeys, raw)
		}
	}

	byGrpObj, _ := aggsMap["by_grp"].(map[string]any)
	grpBuckets, _ := byGrpObj["buckets"].([]any)
	foundG2SubKeys := make(map[string]bool)
	for _, gb := range grpBuckets {
		gbm, _ := gb.(map[string]any)
		if gbm["key"] == "g2" {
			subU, _ := gbm["sub_u"].(map[string]any)
			subBuckets, _ := subU["buckets"].([]any)
			for _, sb := range subBuckets {
				sbm, _ := sb.(map[string]any)
				foundG2SubKeys[strings.TrimSpace(jsonStringifyKey(sbm["key"]))] = true
			}
		}
	}
	if !foundG2SubKeys["18446744073709551614"] || !foundG2SubKeys["18446744073709551615"] {
		t.Fatalf("expected sub-agg sub_u under g2 to preserve exact MaxUint64-1 and MaxUint64 keys, got %v (raw=%s)", foundG2SubKeys, raw)
	}
}

func jsonStringifyKey(v any) string {
	switch tv := v.(type) {
	case string:
		return tv
	case json.Number:
		return tv.String()
	default:
		b, _ := json.Marshal(v)
		return strings.Trim(string(b), `"`)
	}
}

func TestRound57MemBackendMultiValuedAndOpenFloatRangeFields(t *testing.T) {
	mb := NewMemoryBackend(false)
	srv := NewServer("es_db", mb, transpiler.TranspilerOptions{})

	code, raw, _ := doRound57MemReq(t, srv, http.MethodPut, "/r57_ranges", `{
		"mappings": {
			"properties": {
				"avail": {"type": "integer_range"},
				"f_win": {"type": "float_range"},
				"d_win": {"type": "double_range"}
			}
		}
	}`)
	if code != http.StatusOK {
		t.Fatalf("PUT /r57_ranges failed (%d): %s", code, raw)
	}

	rangeDocs := []struct {
		id   string
		body string
	}{
		{"r1", `{"avail":[{"gte":1,"lte":5},{"gte":10,"lte":20}],"f_win":{"gt":10.0,"lt":20.0},"d_win":{"gt":10.0,"lt":20.0}}`},
		{"r2", `{"avail":{"gte":6,"lte":9},"f_win":{"gt":10.5,"lt":20.0},"d_win":{"gt":10.0,"lt":19.5}}`},
		{"r3", `{"f_win":[{"gt":1.0,"lt":3.0},{"gt":10.0,"lt":20.0}],"d_win":[{"gte":10.0,"lte":20.0}]}`},
	}
	for _, d := range rangeDocs {
		c, r, _ := doRound57MemReq(t, srv, http.MethodPut, "/r57_ranges/_doc/"+d.id+"?refresh=true", d.body)
		if c != http.StatusCreated && c != http.StatusOK {
			t.Fatalf("index %s failed (%d): %s", d.id, c, r)
		}
	}

	// 1. Multi-valued array of range objects: [12, 15] intersects second element of r1
	_, raw, resHit := doRound57MemReq(t, srv, http.MethodPost, "/r57_ranges/_search", `{
		"query": {"range": {"avail": {"gte": 12, "lte": 15, "relation": "intersects"}}}
	}`)
	if ids := extractRound57HitIDs(t, resHit); !reflect.DeepEqual(ids, []string{"r1"}) {
		t.Fatalf("expected [r1] for [12, 15] intersects, got %v (raw=%s)", ids, raw)
	}

	// 2. Gap [7, 8] between [1, 5] and [10, 20] must NOT match r1, and MUST match single-object r2 ([6, 9])
	_, raw, resGap := doRound57MemReq(t, srv, http.MethodPost, "/r57_ranges/_search", `{
		"query": {"range": {"avail": {"gte": 7, "lte": 8, "relation": "intersects"}}}
	}`)
	if ids := extractRound57HitIDs(t, resGap); !reflect.DeepEqual(ids, []string{"r2"}) {
		t.Fatalf("expected ONLY [r2] for gap [7, 8] intersects (no cross-element mix on r1), got %v (raw=%s)", ids, raw)
	}

	// 3. within and contains per-element correlation on r1
	_, _, resWithin := doRound57MemReq(t, srv, http.MethodPost, "/r57_ranges/_search", `{
		"query": {"range": {"avail": {"gte": 0, "lte": 6, "relation": "within"}}}
	}`)
	if ids := extractRound57HitIDs(t, resWithin); !reflect.DeepEqual(ids, []string{"r1"}) {
		t.Fatalf("expected [r1] for within [0, 6], got %v", ids)
	}
	_, _, resSpanContains := doRound57MemReq(t, srv, http.MethodPost, "/r57_ranges/_search", `{
		"query": {"range": {"avail": {"gte": 2, "lte": 15, "relation": "contains"}}}
	}`)
	if ids := extractRound57HitIDs(t, resSpanContains); len(ids) != 0 {
		t.Fatalf("expected [] for spanning [2, 15] contains, got %v", ids)
	}

	// 4. Open float_range & double_range (10.0, 20.0) CONTAINS (10.0, 20.0) matches r1 and r3, not r2
	_, raw, resFloatContains := doRound57MemReq(t, srv, http.MethodPost, "/r57_ranges/_search", `{
		"query": {"range": {"f_win": {"gt": 10.0, "lt": 20.0, "relation": "contains"}}},
		"sort": [{"_id": "asc"}]
	}`)
	if ids := extractRound57HitIDs(t, resFloatContains); !reflect.DeepEqual(ids, []string{"r1", "r3"}) {
		t.Fatalf("expected [r1 r3] for float_range open CONTAINS (10.0, 20.0), got %v (raw=%s)", ids, raw)
	}
	_, raw, resDoubleContains := doRound57MemReq(t, srv, http.MethodPost, "/r57_ranges/_search", `{
		"query": {"range": {"d_win": {"gt": 10.0, "lt": 20.0, "relation": "contains"}}},
		"sort": [{"_id": "asc"}]
	}`)
	if ids := extractRound57HitIDs(t, resDoubleContains); !reflect.DeepEqual(ids, []string{"r1", "r3"}) {
		t.Fatalf("expected [r1 r3] for double_range open CONTAINS (10.0, 20.0), got %v (raw=%s)", ids, raw)
	}
}

func TestRound57MemBackendLargeIntAndArrayCoercionUnit(t *testing.T) {
	if memIsSignedASCIIDigits("") || memIsSignedASCIIDigits("-") || memIsSignedASCIIDigits("+") || memIsSignedASCIIDigits("12a") {
		t.Fatalf("expected memIsSignedASCIIDigits false for invalid inputs")
	}
	if !memIsSignedASCIIDigits("+123") || !memIsSignedASCIIDigits("-456") {
		t.Fatalf("expected memIsSignedASCIIDigits true for signed integers")
	}
	if memNormalizeExactIntValue(nil) != nil {
		t.Fatalf("expected nil from memNormalizeExactIntValue(nil)")
	}
	huge, _ := new(big.Int).SetString("340282366920938463463374607431768211455", 10) // 2^128 - 1
	if got := memNormalizeExactIntValue(huge); got != huge {
		t.Fatalf("expected *big.Int preserved beyond uint64, got %T %v", got, got)
	}
	var nilBig *big.Int
	if _, ok := memParseExactBigInt(nilBig); ok {
		t.Fatalf("expected false for nil *big.Int")
	}
	if _, ok := memParseExactBigInt(json.Number("3.14")); ok {
		t.Fatalf("expected false for float json.Number")
	}
	if _, ok := memParseExactBigInt("3.14"); ok {
		t.Fatalf("expected false for float string")
	}
	if bi, ok := memParseExactBigInt(42); !ok || bi.Int64() != 42 {
		t.Fatalf("expected 42 from int, got %v %v", bi, ok)
	}
	if bi, ok := memParseExactBigInt(huge); !ok || bi.Cmp(huge) != 0 {
		t.Fatalf("expected huge *big.Int roundtrip")
	}
	if got := memCoerceSQLLargeInt([]any{float64(10), "18446744073709551615", "bad"}); !reflect.DeepEqual(got, []any{int64(10), uint64(math.MaxUint64)}) {
		t.Fatalf("unexpected memCoerceSQLLargeInt slice result: %#v", got)
	}
	if got := memCoerceSQLLargeInt([]any{"not_a_number"}); got != nil {
		t.Fatalf("expected nil for uncoercible slice, got %#v", got)
	}
	if got := memCoerceSQLLargeInt(float64(25)); got != int64(25) {
		t.Fatalf("expected int64(25) from integral float64, got %#v", got)
	}
	if got := memCoerceSQLLargeInt("not_a_number"); got != nil {
		t.Fatalf("expected nil from invalid scalar, got %#v", got)
	}

	if memCoerceVariantToArrayOfString(nil) != nil || memCoerceVariantToArrayOfString(map[string]any{"_gte": 1}) != nil {
		t.Fatalf("expected nil for nil and map[string]any in memCoerceVariantToArrayOfString")
	}
	if got := memCoerceVariantToArrayOfString([]string{"a", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("expected []string passthrough, got %#v", got)
	}
	nestedArr := []any{nil, []any{map[string]any{"_gte": 1}}, "plain"}
	if got := memCoerceVariantToArrayOfString(nestedArr); !reflect.DeepEqual(got, []string{`{"_gte":1}`, "plain"}) {
		t.Fatalf("unexpected nested memCoerceVariantToArrayOfString result: %#v", got)
	}
	if got := memCoerceVariantToArrayOfString(99); !reflect.DeepEqual(got, []string{"99"}) {
		t.Fatalf("unexpected scalar memCoerceVariantToArrayOfString result: %#v", got)
	}

	if i, ok := toInt64(uint64(42)); !ok || i != 42 {
		t.Fatalf("expected toInt64(uint64(42))=42, got %d %v", i, ok)
	}
	if _, ok := toInt64(uint64(math.MaxUint64)); ok {
		t.Fatalf("expected toInt64(MaxUint64) false")
	}
	if f, ok := toFloat(uint64(100)); !ok || f != 100 {
		t.Fatalf("expected toFloat(uint64(100))=100, got %v %v", f, ok)
	}
	if f, ok := toFloat(big.NewInt(200)); !ok || f != 200 {
		t.Fatalf("expected toFloat(*big.Int)=200, got %v %v", f, ok)
	}
	if compareAny(uint64(math.MaxUint64)-1, uint64(math.MaxUint64)) >= 0 {
		t.Fatalf("expected MaxUint64-1 < MaxUint64 in compareAny")
	}
}
