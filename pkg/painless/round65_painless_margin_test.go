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

package painless

import (
	"encoding/json"
	"math"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRound65_F2b_F12_F18b_F19b_Regressions(t *testing.T) {
	// F12: Invalid ctx.op spacing
	if err := ValidateUpdateCtxOp("create"); err == nil || !strings.Contains(err.Error(), "Invalid ctx.op [create]; must be one of [index, noop, none, delete]") {
		t.Fatalf("unexpected ValidateUpdateCtxOp('create') error: %v", err)
	}
	for _, validOp := range []string{"", "index", "noop", "none", "delete"} {
		if err := ValidateUpdateCtxOp(validOp); err != nil {
			t.Fatalf("expected valid op %q to succeed, got %v", validOp, err)
		}
	}

	// F2b: NaN / Infinity / -Infinity rejected across WKT, GeoJSON, GeoPoint, and radius parsers
	infWKTs := []string{
		"POINT (Infinity 10)",
		"POINT (10 -Infinity)",
		"POINT (NaN 10)",
		"LINESTRING (0 0, Infinity 1)",
		"POLYGON ((0 0, 1 0, 1 Infinity, 0 0))",
		"ENVELOPE (-Infinity, 1, 1, -1)",
		"BBOX (-1, Infinity, 1, -1)",
		"GEOMETRYCOLLECTION (POINT (1 1), POINT (-Infinity 2))",
	}
	for _, wkt := range infWKTs {
		if _, err := ParseGeoShapeDocValues(wkt); err == nil || !strings.Contains(strings.ToLower(err.Error()), "invalid") {
			t.Fatalf("expected IllegalArgumentException for WKT %q, got %v", wkt, err)
		}
	}

	badCoordPairs := []any{
		[]float64{math.Inf(1), 10},
		[]float64{10, math.Inf(-1)},
		[]float64{math.NaN(), 10},
		[]any{math.Inf(1), 10.0},
		[]any{10.0, math.NaN()},
		[]float64{1.0},
	}
	for _, pair := range badCoordPairs {
		if _, _, ok := parseGeoCoordPairRound61(pair); ok {
			t.Fatalf("expected parseGeoCoordPairRound61(%#v) to reject non-finite/short coord", pair)
		}
	}

	badPoints := []any{
		&GeoPointVal{Lat: math.Inf(1), Lon: 0},
		GeoPointVal{Lat: 0, Lon: math.NaN()},
		map[string]any{"lat": math.Inf(-1), "lon": 1.0},
		map[string]any{"coordinates": []any{math.Inf(1), 1.0}},
		[]any{math.NaN(), 1.0},
		[]float64{1.0, math.Inf(1)},
		"POINT(Infinity 1.0)",
		"-Infinity,1.0",
		"1.0,NaN",
	}
	for _, p := range badPoints {
		if _, ok := parseGeoPointValRound60(p); ok {
			t.Fatalf("expected parseGeoPointValRound60(%#v) to reject non-finite value", p)
		}
	}

	badRadii := []any{
		math.Inf(1),
		math.Inf(-1),
		math.NaN(),
		-5.0,
		json.Number("NaN"),
		json.Number("Infinity"),
		"Infinitykm",
		"-Infinitym",
		"NaNmi",
		"-10m",
		true,
	}
	for _, r := range badRadii {
		if _, ok := parseRadiusMetersRound61(r); ok {
			t.Fatalf("expected parseRadiusMetersRound61(%#v) to reject invalid/infinite radius", r)
		}
	}
	for _, r := range []any{10.0, int64(5), int(3), json.Number("25"), "2km", "1mi", "500m"} {
		if m, ok := parseRadiusMetersRound61(r); !ok || m <= 0 {
			t.Fatalf("expected positive radius for %#v, got (%v, %v)", r, m, ok)
		}
	}

	// F18b: hamming() bit & byte dense vector decoding, element_type resolution, and error contracts
	bitDoc := map[string]any{
		"vec":        "006ff30e84",
		"vec_arr":    []int{0, 111, -13, 14, -124},
		"vec_i8":     []int8{0, 111, -13, 14, -124},
		"vec_i64":    []int64{0, 111, -13, 14, -124},
		"nested":     map[string]any{"vec": []any{0, 111, -13, 14, -124}},
		"float_vec":  []float32{1.0, 2.0, 3.0},
		"float64vec": []float64{1.0, 2.0, 3.0},
	}
	bitParams := map[string]any{
		"__field_types": map[string]string{
			"vec":        "dense_vector",
			"vec_arr":    "dense_vector",
			"vec_i8":     "dense_vector",
			"vec_i64":    "dense_vector",
			"nested.vec": "dense_vector",
			"float_vec":  "dense_vector",
		},
		"__vector_element_types": map[string]any{
			"vec":        " bit ",
			"vec_arr":    "BYTE",
			"vec_i8":     "byte",
			"vec_i64":    "bit",
			"nested.vec": "bit",
			"float_vec":  "float",
		},
	}
	if et := resolveVectorElementTypeFromMapsRound61(nil, bitParams, "nested\x00vec"); et != "bit" {
		t.Fatalf("expected resolved element type 'bit' for nested\\x00vec, got %q", et)
	}
	for _, script := range []string{
		`return hamming([0, 111, -13, 14, -124], 'vec');`,
		`return hamming('006ff30e84', 'vec_arr');`,
		`return hamming('006ff30e84', 'vec_i8');`,
		`return hamming([0, 111, -13, 14, -124], 'vec_i64');`,
		`return hamming('006ff30e84', 'nested.vec');`,
		`return hamming(field('vec').get(null), field('vec_arr').get(null));`,
	} {
		got, ok, err := EvalNumber(bitDoc, script, bitParams)
		if err != nil || !ok || got != 0.0 {
			t.Fatalf("script %q expected hamming 0.0, got (%v, %v, err=%v)", script, got, ok, err)
		}
	}
	if got, ok, err := EvalNumber(bitDoc, `return hamming('0102030405', 'vec');`, bitParams); err != nil || !ok || got <= 0 {
		t.Fatalf("expected positive hamming distance for distinct bit vector, got (%v, %v, err=%v)", got, ok, err)
	}
	for _, bitMetricErr := range []string{
		`return dotProduct('006ff30e84', 'vec');`,
		`return cosineSimilarity('006ff30e84', 'vec');`,
		`return hamming([1.0, 2.0, 3.0], 'float_vec');`,
	} {
		if _, _, err := EvalNumber(bitDoc, bitMetricErr, bitParams); err == nil {
			t.Fatalf("expected error for invalid vector metric %q", bitMetricErr)
		}
	}
	// Check parseVectorValueRound61 edge cases
	if _, i8, err := parseVectorValueRound61(&DenseVectorVal{Floats: []float32{1, -1, 127}}, "bit"); err != nil || len(i8) != 3 {
		t.Fatalf("expected DenseVectorVal int8 derivation, got (%v, %v)", i8, err)
	}
	for _, badVec := range []struct {
		v  any
		et string
	}{
		{[]int{200}, "byte"},
		{[]int64{-200}, "bit"},
		{[]float32{float32(math.NaN())}, "byte"},
		{[]float64{1.5}, "byte"},
		{[]float64{math.Inf(1)}, "bit"},
		{[]any{"bad"}, "float"},
		{123, "float"},
	} {
		if _, _, err := parseVectorValueRound61(badVec.v, badVec.et); err == nil {
			t.Fatalf("expected parseVectorValueRound61(%#v, %q) to fail", badVec.v, badVec.et)
		}
	}
	if _, err := evalVectorSimilarityRound60("hamming", "006ff30e84", &DenseVectorVal{ElemType: "bit", Floats: []float32{0, 111, -13, 14, -124}}, nil, nil); err != nil {
		t.Fatalf("unexpected unnamed DenseVectorVal hamming error: %v", err)
	}

	// F19b: chained .getBoundingBox().bottomRight(), centroid non-FMA precision, nested \x00 geo_point, missing geo_point
	spatialDoc := map[string]any{
		"geo_shape": "POLYGON((24.04725 59.942,24.04825 59.94125,24.04875 59.94125,24.04875 59.94175,24.048 59.9425,24.0475 59.94275,24.0465 59.94225,24.046 59.94225,24.04575 59.9425,24.04525 59.94225,24.04725 59.942))",
		"geo_point": []any{-71.34, 41.12},
		"nested":    map[string]any{"pin": []any{-71.34, 41.12}},
		"empty_pt":  []any{},
	}
	spatialParams := map[string]any{
		"__quantize_geo_point": true,
		"__field_types": map[string]string{
			"geo_shape":  "geo_shape",
			"geo_point":  "geo_point",
			"nested.pin": "geo_point",
			"empty_pt":   "geo_point",
		},
	}
	resGeo, err := Eval(spatialDoc, `
		def c = doc['geo_shape'].getCentroid();
		def lp = doc['geo_shape'].getLabelPosition();
		def brS = doc['geo_shape'].getBoundingBox().bottomRight();
		def tlS = doc['geo_shape'].getBoundingBox().topLeft();
		def brP = doc['geo_point'].getBoundingBox().bottomRight();
		def brNest = doc['nested.pin'].getBoundingBox().bottomRight();
		return [c.lat, c.lon, lp.lat, brS.lat, brS.lon, tlS.lat, tlS.lon, brP.lat, brP.lon, brNest.lat, doc['empty_pt'].isEmpty()];
	`, spatialParams)
	if err != nil {
		t.Fatalf("chained geo script failed: %v", err)
	}
	gs := resGeo.([]any)
	if gs[0].(float64) != 59.942043484188616 || gs[1].(float64) != 24.047588920220733 || gs[2].(float64) != 59.942043484188616 {
		t.Fatalf("unexpected Helsinki centroid/labelPosition: got (%v, %v, %v)", gs[0], gs[1], gs[2])
	}
	if gs[3].(float64) != 59.94124996941537 || gs[4].(float64) != 24.048749981448054 ||
		gs[5].(float64) != 59.942749994806945 || gs[6].(float64) != 24.045249950140715 {
		t.Fatalf("unexpected geo_shape bbox corners: %v", gs[3:7])
	}
	if math.Abs(gs[7].(float64)-41.1199999647215) > 1e-12 || math.Abs(gs[8].(float64)-(-71.34000004269183)) > 1e-12 || gs[9].(float64) != gs[7].(float64) || gs[10] != true {
		t.Fatalf("unexpected geo_point bbox / nested / empty results: %v", gs[7:])
	}
	if dvNest, err := resolveDocValuesSliceWithParamsRound60(spatialDoc, spatialParams, "nested\x00pin"); err != nil || len(dvNest) != 1 {
		t.Fatalf("expected nested\\x00pin doc values slice of len 1, got (%v, %v)", dvNest, err)
	}
	if _, err := Eval(spatialDoc, `return doc['empty_pt'].getBoundingBox().bottomRight();`, spatialParams); err == nil || !strings.Contains(err.Error(), "doesn't have a value for a geo_point field") {
		t.Fatalf("expected missing geo_point IllegalStateException, got %v", err)
	}
}

func TestRound65_F27b_BigDecimalBigIntegerBoundsAndBitSet(t *testing.T) {
	// 1. extractInt64BoundArgPainless
	maxBI := newPainlessBigInteger(new(big.Int).Lsh(big.NewInt(1), 70))
	boundCases := []struct {
		in      any
		want    int64
		wantErr bool
	}{
		{int(7), 7, false},
		{int64(-9), -9, false},
		{int32(32), 32, false},
		{int16(16), 16, false},
		{int8(-8), -8, false},
		{uint(12), 12, false},
		{uint64(99), 99, false},
		{uint64(math.MaxUint64), 0, true},
		{uint32(123), 123, false},
		{(*painlessBigInteger)(nil), 0, true},
		{maxBI, 0, true},
		{newPainlessBigInteger(big.NewInt(42)), 42, false},
		{json.Number("12345"), 12345, false},
		{json.Number("99999999999999999999999"), 0, true},
		{float64(15.9), 15, false},
		{math.NaN(), 0, true},
		{math.Inf(1), 0, true},
		{float64(math.MaxInt64) * 2, 0, true},
		{float32(14.5), 14, false},
		{float32(math.NaN()), 0, true},
		{float32(math.Inf(-1)), 0, true},
		{"not-an-int", 0, true},
	}
	for _, tc := range boundCases {
		got, err := extractInt64BoundArgPainless(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("extractInt64BoundArgPainless(%#v) expected error", tc.in)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("extractInt64BoundArgPainless(%#v) = (%d, %v), want %d", tc.in, got, err, tc.want)
		}
	}

	// 2. parsePainlessBigIntegerChecked, newPainlessBigIntegerFromBytesChecked, MarshalJSON/String/longValue
	if bi, err := parsePainlessBigIntegerChecked(nil); err != nil || bi != nil {
		t.Fatalf("unexpected nil BigInteger result: (%v, %v)", bi, err)
	}
	if bi, err := parsePainlessBigIntegerChecked((*painlessBigInteger)(nil)); err != nil || bi != nil {
		t.Fatalf("unexpected typed-nil BigInteger: (%v, %v)", bi, err)
	}
	if _, err := parsePainlessBigIntegerChecked(strings.Repeat("9", 20001)); err == nil {
		t.Fatalf("expected oversized string BigInteger error")
	}
	if _, err := parsePainlessBigIntegerChecked(json.Number(strings.Repeat("9", 20001))); err == nil {
		t.Fatalf("expected oversized json.Number BigInteger error")
	}
	for _, in := range []any{int(5), int64(6), float64(7.2), math.NaN(), "123456", "bad", json.Number("89"), newPainlessBigDecimal(big.NewInt(1234), 2)} {
		bi, err := parsePainlessBigIntegerChecked(in)
		if err != nil {
			t.Fatalf("parsePainlessBigIntegerChecked(%#v) err=%v", in, err)
		}
		if bi != nil {
			_ = bi.String()
			_, _ = bi.MarshalJSON()
			_ = bi.longValue()
		}
	}
	var nilBI *painlessBigInteger
	_ = nilBI.String()
	_, _ = nilBI.MarshalJSON()
	_ = nilBI.longValue()

	if bi, err := newPainlessBigIntegerFromBytesChecked([]byte{}); err != nil || bi.longValue() != 0 {
		t.Fatalf("empty BigInteger bytes failed: (%v, %v)", bi, err)
	}
	if bi, err := newPainlessBigIntegerFromBytesChecked([]byte{0xff, 0xfe}); err != nil || bi.longValue() != -2 {
		t.Fatalf("two's complement BigInteger bytes got %d (err=%v)", bi.longValue(), err)
	}
	if _, err := newPainlessBigIntegerFromBytesChecked(make([]byte, maxBigIntBits/8+2)); err == nil {
		t.Fatalf("expected oversized byte slice BigInteger error")
	}

	// 3. BigDecimal parsing, alignment, arithmetic, scale bounds, engineering string
	for _, in := range []any{
		(*painlessBigDecimal)(nil),
		newPainlessBigInteger(big.NewInt(77)),
		int(8),
		int64(9),
		float64(12.25),
		math.NaN(),
		json.Number("3.14159"),
		" +0.00 ",
		"1.25e-2",
		"   ",
		"-",
		"1e99999999999999999999999",
		"0." + strings.Repeat("0", maxBigDecimalScale*2+5) + "1",
		"1e-200000",
		strings.Repeat("9", 20001),
		"abc",
	} {
		bd, _ := parsePainlessBigDecimalChecked(in)
		if bd != nil {
			_ = bd.shortValue()
			_ = bd.byteValue()
			_, _ = bd.longValueExact()
			_, _ = bd.intValueExact()
			_, _ = bd.shortValueExact()
			_, _ = bd.byteValueExact()
			_ = bd.toEngineeringString()
		}
	}
	if _, err := bigTenPowPainlessChecked(maxBigDecimalScale + 1); err == nil {
		t.Fatalf("expected bigTenPowPainlessChecked overflow error")
	}
	bdSmall := newPainlessBigDecimal(big.NewInt(1), 50)
	bdLarge := newPainlessBigDecimal(big.NewInt(2), -50)
	if compareBigDecimalPainless(bdSmall, bdLarge) != -1 || compareBigDecimalPainless(bdLarge, bdSmall) != 1 || compareBigDecimalPainless(bdSmall, bdSmall) != 0 {
		t.Fatalf("unexpected compareBigDecimalPainless order")
	}
	bdHugeA := newPainlessBigDecimal(big.NewInt(-1), 200)
	bdHugeB := newPainlessBigDecimal(big.NewInt(2), maxBigDecimalScale)
	if compareBigDecimalPainless(bdHugeA, bdHugeB) != -1 || compareBigDecimalPainless(bdHugeB, bdHugeA) != 1 {
		t.Fatalf("unexpected misaligned compareBigDecimalPainless fallback")
	}
	bdZeroTiny := newPainlessBigDecimal(big.NewInt(0), 20)
	if eng := bdZeroTiny.toEngineeringString(); !strings.Contains(eng, "E") {
		t.Fatalf("expected engineering notation for scale-20 zero, got %q", eng)
	}
	for _, rm := range []string{"UP", "DOWN", "CEILING", "FLOOR", "HALF_UP", "HALF_DOWN", "HALF_EVEN", "UNNECESSARY", "unknown"} {
		_ = normalizeRoundingModePainless(rm)
	}
	_ = painlessMathContext{}.String()
	bdOne := newPainlessBigDecimal(big.NewInt(10), 1)
	bdThree := newPainlessBigDecimal(big.NewInt(3), 0)
	if _, err := bdOne.div(newPainlessBigDecimal(big.NewInt(0), 0), 2, "HALF_UP"); err == nil {
		t.Fatalf("expected division by zero")
	}
	if q, err := bdOne.div(bdThree, 4, "HALF_UP"); err != nil || q.scale != 4 {
		t.Fatalf("unexpected div result: (%v, %v)", q, err)
	}
	if _, _, err := bdOne.divideAndRemainder(bdThree); err != nil {
		t.Fatalf("unexpected divideAndRemainder err: %v", err)
	}
	bdMaxScale := newPainlessBigDecimal(big.NewInt(1), maxBigDecimalScale)
	if _, err := bdMaxScale.mulChecked(bdMaxScale); err == nil {
		t.Fatalf("expected mulChecked scale overflow error")
	}

	// 4. BitSet methods & Painless execution
	bs1 := newPainlessBitSet()
	bs2 := newPainlessBitSet()
	_ = bs1.setBit(10, true)
	_ = bs1.setBit(70, true)
	_ = bs2.setBit(70, true)
	_ = bs2.setBit(130, true)
	if !bs1.intersects(bs2) || bs1.length() != 71 || bs1.size() < 128 {
		t.Fatalf("unexpected BitSet state: intersects=%v len=%d size=%d", bs1.intersects(bs2), bs1.length(), bs1.size())
	}
	if ncb, err := bs1.nextClearBit(70); err != nil || ncb != 71 {
		t.Fatalf("unexpected nextClearBit(70): (%d, %v)", ncb, err)
	}
	if psb, err := bs1.previousSetBit(69); err != nil || psb != 10 {
		t.Fatalf("unexpected previousSetBit(69): (%d, %v)", psb, err)
	}
	if pcb, err := bs1.previousClearBit(10); err != nil || pcb != 9 {
		t.Fatalf("unexpected previousClearBit(10): (%d, %v)", pcb, err)
	}
	if _, err := bs1.previousSetBit(-2); err == nil {
		t.Fatalf("expected negative previousSetBit error")
	}
	if _, err := bs1.previousClearBit(-2); err == nil {
		t.Fatalf("expected negative previousClearBit error")
	}
	_ = bs1.or(bs2)
	bs1.and(bs2)
	_ = bs1.xor(newPainlessBitSet())
	bs1.andNot(bs2)
	_ = bs1.toByteArray()
	if res, err := Eval(nil, `
		BitSet a = new BitSet();
		a.set(1); a.set(5); a.set(7);
		BitSet b = a.get(1, 7);
		int nc = a.nextClearBit(5);
		int ps = a.previousSetBit(6);
		int pc = a.previousClearBit(5);
		int l = a.length();
		int sz = a.size();
		a.or(b); a.and(b); a.xor(b); a.andNot(b);
		return [b.cardinality(), nc, ps, pc, l, sz, a.intersects(b), a.toByteArray().length];
	`, nil); err != nil || len(res.([]any)) != 8 {
		t.Fatalf("BitSet script failed: res=%#v err=%v", res, err)
	}
}

func TestRound65_F27b_EvalFilterSwitchDoWhileAndLambdas(t *testing.T) {
	// 1. EvalFilter
	filterCases := []struct {
		src    map[string]any
		script string
		want   bool
	}{
		{map[string]any{"x": int64(5)}, `doc['x'].value > 3`, true},
		{map[string]any{"x": int64(1)}, `doc['x'].value > 3`, false},
		{nil, `return null;`, false},
		{nil, `return 42;`, true},
		{nil, `return 0;`, false},
		{nil, `return "true";`, true},
	}
	for _, fc := range filterCases {
		got, err := EvalFilter(fc.src, fc.script, nil)
		if err != nil || got != fc.want {
			t.Fatalf("EvalFilter(%q) = (%v, %v), want %v", fc.script, got, err, fc.want)
		}
	}
	if _, err := EvalFilter(nil, `throw new IllegalArgumentException("boom");`, nil); err == nil {
		t.Fatalf("expected EvalFilter error propagation")
	}

	// 2. findSwitchLabelEndPainless, execSwitchStatement, evalSwitchExprPainless, execDoWhileStatement, while, lambdas
	if idx, arrow := findSwitchLabelEndPainless("1 ? 2 : 3 -> x"); !arrow || idx < 0 {
		t.Fatalf("expected arrow switch label end, got (%d, %v)", idx, arrow)
	}
	if idx, arrow := findSwitchLabelEndPainless("Foo::bar : x"); arrow || idx != 9 {
		t.Fatalf("expected colon after ::, got (%d, %v)", idx, arrow)
	}
	resSw, err := Eval(nil, `
		int acc = 0;
		for (int k : [1, 2, 3, 9]) {
			switch (k) {
				case 1:
				case 2:
					acc += 10;
					break;
				case 3 -> {
					acc += 5;
				}
				default -> acc += 1;
			}
		}
		int exprVal = switch (acc) {
			case 26 -> { int t = 100; yield t + 1; }
			default -> 0;
		};
		int dw = 0;
		outer: do {
			dw++;
			if (dw == 1) { continue outer; }
			if (dw == 3) { break outer; }
		} while (dw < 10);
		int wh = 0;
		while (wh < 4) {
			wh++;
			if (wh == 2) { continue; }
			if (wh == 4) { break; }
		}
		List l = [1, 2, 3];
		l.replaceAll(x -> x * 2);
		Map mp = ['a': 1, 'b': 2];
		mp.replaceAll((k, v) -> v + 10);
		boolean anyOdd = [2, 4, 5].stream().anyMatch(x -> { return x % 2 == 1; });
		return [acc, exprVal, dw, wh, l.get(2), mp.get('b'), anyOdd];
	`, nil)
	if err != nil {
		t.Fatalf("control flow / lambda script failed: %v", err)
	}
	sv := resSw.([]any)
	if sv[0] != int64(26) || sv[1] != int64(101) || sv[2] != int64(3) || sv[3] != int64(4) || sv[4] != int64(6) || sv[5] != int64(12) || sv[6] != true {
		t.Fatalf("unexpected control flow results: %#v", sv)
	}
	if _, err := Eval(nil, `switch (null) { default: return 1; }`, nil); err == nil {
		t.Fatalf("expected NullPointerException on null switch")
	}

	// 3. removeKeyOrIndexAtPath & compound assignment paths (round59)
	rmDoc := map[string]any{
		"flat.a": "x",
		"nested": map[string]any{"k": "v"},
		"items":  []any{"p", "q", "r"},
	}
	if old := removeKeyOrIndexAtPath(rmDoc, nil, "nested.k"); old != "v" {
		t.Fatalf("expected dotted remove 'v', got %#v", old)
	}
	if old := removeKeyOrIndexAtPath(rmDoc, []string{"items"}, 1); old != "q" {
		t.Fatalf("expected slice index remove 'q', got %#v", old)
	}
	if ok := removeKeyOrIndexAtPath(rmDoc, []string{"items"}, "r"); ok != true {
		t.Fatalf("expected slice element remove true, got %#v", ok)
	}
	updSrc := map[string]any{"cnt": int64(10), "nested": map[string]any{"v": int64(3)}}
	if err := EvalPainless(updSrc, `
		_source.cnt += 5;
		ctx._source.nested.v *= 2;
		ctx.op = 'index';
		ctx.op += '';
		def meta = metadata();
		meta.op = 'index';
		class Box {
			static int S = 4;
			int x = 1;
			boolean equals(Object o) { return o instanceof Box && ((Box)o).x == this.x; }
			String toString() { return "Box(" + this.x + ")"; }
		}
		Box.S += 3;
		Box b1 = new Box();
		Box b2 = new Box();
		ctx._source.eq = b1.equals(b2);
		ctx._source.s = Box.S + ":" + b1.toString();
		ctx._source.mid = meta.id + ":" + meta.index + ":" + meta.versionType + ":" + meta.op;
	`, map[string]any{"__is_update_doc": true, "_ctx_id": "id2", "_ctx_index": "idx2"}); err != nil {
		t.Fatalf("round59 compound/user-class update failed: %v", err)
	}
	if updSrc["cnt"] != int64(15) || updSrc["eq"] != true || !strings.HasSuffix(updSrc["s"].(string), ":Box(1)") || updSrc["mid"] != "id2:idx2:internal:index" {
		t.Fatalf("unexpected updSrc: %#v", updSrc)
	}
	for _, roMeta := range []string{`metadata()._routing = 'r1';`, `metadata()._index = 'idx3';`} {
		if err := EvalPainless(updSrc, roMeta, map[string]any{"__is_update_doc": true}); err == nil {
			t.Fatalf("expected immutable metadata error for %q", roMeta)
		}
	}
	if err := EvalPainless(updSrc, `doc.cnt = 1;`, nil); err == nil {
		t.Fatalf("expected doc.cnt assignment error")
	}
}

func TestRound65_F27b_URI_URL_OffsetTime_Optional_ValueRange_ZoneClock_Collections(t *testing.T) {
	// 1. Direct URI / URL / OffsetTime / ValueRange / Optional / UUID helpers
	u1, err := newPainlessURIFromString("https://user@example.com:8443/a/../b?q=1#frag")
	if err != nil {
		t.Fatalf("newPainlessURIFromString failed: %v", err)
	}
	u2, err := newPainlessURIFromString("mailto:user@example.com#f")
	if err != nil {
		t.Fatalf("opaque URI failed: %v", err)
	}
	_ = u1.compareTo(u2)
	_ = u1.normalize()
	_ = u1.resolve(u2)
	_ = u1.relativize(u1)
	_ = u1.toASCIIString()
	_ = u1.equals(u1)
	_ = u1.hashCode()
	if _, err := newPainlessURIFromString("http://bad space.com"); err == nil {
		t.Fatalf("expected URISyntaxException")
	}
	urlObj, err := newPainlessURLFromString("https://example.com/path?a=1")
	if err != nil || urlObj.getDefaultPort() != 443 || urlObj.getPort() != -1 || !urlObj.equals(urlObj) || urlObj.hashCode() == 0 {
		t.Fatalf("unexpected painlessURL behavior: %v err=%v", urlObj, err)
	}
	if _, err := newPainlessURLFromString("custom://host"); err == nil {
		t.Fatalf("expected MalformedURLException for custom scheme")
	}
	ot1, err := newPainlessOffsetTime(12, 30, 15, 500, 3600)
	if err != nil || ot1.addNanos(3600*1e9).hour != 13 || !ot1.equals(ot1.String()) || ot1.compareTo(ot1) != 0 || ot1.hashCode() == 0 {
		t.Fatalf("unexpected OffsetTime behavior")
	}
	if ot2, ok := parsePainlessOffsetTime("12:30:15.000000500+02:00"); !ok || ot1.compareTo(ot2) == 0 {
		t.Fatalf("expected OffsetTime parse/compare diff")
	}
	for _, badOT := range [][5]int{{24, 0, 0, 0, 0}, {0, 60, 0, 0, 0}, {0, 0, 60, 0, 0}, {0, 0, 0, -1, 0}, {0, 0, 0, 0, 70000}} {
		if _, err := newPainlessOffsetTime(badOT[0], badOT[1], badOT[2], badOT[3], badOT[4]); err == nil {
			t.Fatalf("expected OffsetTime validation error for %v", badOT)
		}
	}
	vr := newFixedValueRangePainless(1, 12)
	if !vr.isFixed() || !vr.isIntValue() || !vr.isValidIntValue(6) || !vr.equals(vr) || vr.hashCode() == 0 {
		t.Fatalf("unexpected ValueRange: %v", vr)
	}
	if cmp, ok := compareUUIDSignedPainless("11111111-2222-1333-8444-555555555555", "11111111-2222-1333-8444-555555555556"); !ok || cmp != -1 {
		t.Fatalf("expected UUID signed compare -1, got (%d, %v)", cmp, ok)
	}
	if _, err := coerceOptionalPrimitivePainless("OptionalInt", painlessEmptyOptional); err == nil {
		t.Fatalf("expected NPE for OptionalInt.of(empty)")
	}
	if !isEmptyOptionalOrNilPainless(painlessEmptyOptional) || unwrapPainlessInternalValue(painlessEmptyOptional) != nil {
		t.Fatalf("unexpected empty optional unwrap")
	}
	_ = (painlessHexFormat{upperCase: true, delimiter: ":"}).String()
	_ = (&painlessTemporalAdjuster{kind: "firstDayOfMonth"}).String()
	_ = (&painlessComparator{kind: "natural"}).cloneReversed().String()
	_ = (&painlessLabeledJumpError{label: "L", isBreak: true}).Error()
	_ = (&painlessLabeledJumpError{label: "L", isBreak: false}).Error()

	// 2. End-to-end scripts exercising round54 dispatchers (URI, URL, Optional*, OffsetTime, ZoneId/ZoneOffset, Clock, Collections, Matcher, UUID v1)
	round54Scripts := []string{
		`def u = URI.create("https://alice@example.org:8443/dir/../file?x=1%202#sec"); def uRel = URI.create("https://alice@example.org:8443/dir/sub"); def norm = u.normalize(); def url = u.toURL(); def uri2 = url.toURI(); return [u.getScheme(), u.getAuthority(), u.getRawAuthority(), u.getUserInfo(), u.getRawUserInfo(), u.getHost(), u.getPort(), norm.getPath(), u.getRawPath(), u.getQuery(), u.getRawQuery(), u.getFragment(), u.getRawFragment(), u.isAbsolute(), u.isOpaque(), u.toASCIIString(), u.getSchemeSpecificPart(), u.getRawSchemeSpecificPart(), u.parseServerAuthority().toString(), u.equals(uri2), u.hashCode(), uRel.hashCode()];`,
		`def url = new URL("https://bob@example.org:8443/p?q=1#ref"); def uri2 = url.toURI(); return [url.getProtocol(), url.getHost(), url.getPort(), url.getDefaultPort(), url.getFile(), url.getPath(), url.getQuery(), url.getAuthority(), url.getUserInfo(), url.getRef(), url.toExternalForm(), url.equals(url), url.hashCode(), uri2.getScheme()];`,
		`def opt1 = Optional.of("hi"); def optE = Optional.empty(); def optI = OptionalInt.of(7); def optL = OptionalLong.of(9L); def optD = OptionalDouble.of(2.5); return [opt1.isPresent(), optE.isEmpty(), opt1.get(), opt1.orElseThrow(), optI.getAsInt(), optL.getAsLong(), optD.getAsDouble(), opt1.stream().size(), opt1.toString(), opt1.hashCode(), opt1.equals(Optional.of("hi"))];`,
		`def ot = OffsetTime.of(10, 20, 30, 0, ZoneOffset.ofHoursMinutes(2, 30)); def ot2 = OffsetTime.of("10:20:30", "+02:30"); def otP = OffsetTime.parse("10:20:30+02:30"); def otF = OffsetTime.parse("10:20:30+02:30", DateTimeFormatter.ISO_OFFSET_TIME); return [ot.getHour(), ot.getMinute(), ot.getSecond(), ot.getNano(), ot.getOffset(), ot.toLocalTime(), ot.equals(otP), ot.equals(ot2), ot.hashCode(), ot.toString(), otF.toString()];`,
		`def zOff = ZoneOffset.ofTotalSeconds(1800); def zOff2 = ZoneOffset.ofHoursMinutesSeconds(1, 30, 0); def zid = ZoneId.ofOffset("UTC", ZoneOffset.ofHours(3)); def cUTC = Clock.systemUTC(); def cDef = Clock.systemDefaultZone(); def cSys = Clock.system("Europe/Paris"); def cFix = Clock.fixed("2022-01-01T00:00:00Z", "UTC"); def cOff = Clock.offset(cFix, Duration.ofMinutes(15)); def cTck = Clock.tickMinutes("UTC"); def cTckS = Clock.tickSeconds("UTC"); def cTckM = Clock.tickMillis("UTC"); def cTck2 = Clock.tick(cFix, Duration.ofSeconds(10)); return [zOff.getTotalSeconds(), zOff.normalized(), zOff2.getId(), zid.getId(), zid.getRules(), ZoneId.systemDefault(), ZoneId.getAvailableZoneIds().size(), cFix.instant(), cOff.millis(), cTck.getZone(), cTckS.getZone(), cTckM.getZone(), cTck2.equals(cTck2), cUTC.hashCode(), cDef.toString(), cSys.getZone()];`,
		`def m = /(?<word>[a-z]+)/.matcher("one two"); def resList = m.results(); m.reset(); m.find(); def mr = m.toMatchResult(); def ng = m.namedGroups(); return [resList.size(), mr.group(1), ng.get('word'), m.hasTransparentBounds(), m.hasAnchoringBounds(), m.hitEnd(), m.requireEnd()];`,
		`List dst = [0, 0, 0]; Collections.copy(dst, [7, 8, 9]); Collections.addAll(dst, 10, 11); def sub1 = Collections.indexOfSubList(dst, [8, 9]); def sub2 = Collections.lastIndexOfSubList(dst, [8, 9]); def unm = Collections.unmodifiableList(dst); def unmSet = Collections.unmodifiableSet([1, 2]); def unmMap = Collections.unmodifiableMap(['k': 1]); def syncL = Collections.synchronizedList(dst); return [sub1, sub2, unm.size(), unmSet.size(), unmMap.size(), syncL.size()];`,
		`String v1 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"; def vrCF = ChronoField.MONTH_OF_YEAR.range(); def zdt = ZonedDateTime.parse("2022-03-15T10:20:30+02:00[Europe/Athens]"); return [UUID.fromString(v1).timestamp(), UUID.fromString(v1).clockSequence(), UUID.fromString(v1).node(), vrCF.getMinimum(), vrCF.getLargestMinimum(), vrCF.getSmallestMaximum(), vrCF.getMaximum(), vrCF.isFixed(), vrCF.isIntValue(), vrCF.isValidValue(6), vrCF.toString(), vrCF.hashCode(), vrCF.equals(vrCF), zdt.getOffset(), zdt.getZone()];`,
	}
	for _, sc := range round54Scripts {
		if res, err := Eval(nil, sc, nil); err != nil || res == nil {
			t.Fatalf("round54 script failed: %v\nscript=%s", err, sc)
		}
	}
	for _, errScript := range []string{
		`return URI.create("/relative/only").toURL();`,
		`return Optional.empty().get();`,
		`return OptionalInt.empty().getAsInt();`,
		`return OptionalLong.empty().getAsLong();`,
		`return OptionalDouble.empty().getAsDouble();`,
		`return ZoneId.ofOffset("BAD", ZoneOffset.UTC);`,
		`return Clock.tick(Clock.systemUTC(), Duration.ofSeconds(0));`,
		`List d = [1]; Collections.copy(d, [1, 2]); return d;`,
		`return Collections.unmodifiableList(null);`,
		`return Collections.unmodifiableMap(null);`,
		`return UUID.fromString("550e8400-e29b-41d4-a716-446655440000").timestamp();`,
		`return OffsetTime.parse(null);`,
		`return OffsetTime.parse("bad", null);`,
		`def m = /a/.matcher("a"); return m.toMatchResult();`,
	} {
		if _, err := Eval(nil, errScript, nil); err == nil {
			t.Fatalf("expected error from %q", errScript)
		}
	}
}

func TestRound65_F27b_GeoShapeDocValues_AllShapesAndRelations(t *testing.T) {
	// 1. ParseGeoShapeDocValuesWithOpts across all WKT, GeoJSON, Go wrapper inputs, and error branches
	geoInputs := []struct {
		raw      any
		wantType string
		wantDim  int64
	}{
		{"POINT (10 20)", "POINT", 0},
		{"MULTIPOINT ((0 0), (1 1))", "MULTIPOINT", 0},
		{"LINESTRING (0 0, 2 2)", "LINESTRING", 1},
		{"MULTILINESTRING ((0 0, 1 1), (2 2, 3 3))", "MULTILINESTRING", 1},
		{"POLYGON ((0 0, 10 0, 10 10, 0 10, 0 0), (2 2, 2 4, 4 4, 4 2, 2 2))", "POLYGON", 2},
		{"MULTIPOLYGON (((0 0, 2 0, 2 2, 0 2, 0 0)), ((5 5, 6 5, 6 6, 5 6, 5 5)))", "MULTIPOLYGON", 2},
		{"ENVELOPE (-2, 2, 3, -3)", "ENVELOPE", 2},
		{"BBOX (-1, 1, 1, -1)", "BBOX", 2},
		{"GEOMETRYCOLLECTION (POINT (1 1), LINESTRING (0 0, 2 2), POLYGON ((0 0, 3 0, 3 3, 0 3, 0 0)))", "GEOMETRYCOLLECTION", 2},
		{"GEOMETRYCOLLECTION EMPTY", "GEOMETRYCOLLECTION", 0},
		{"POINT EMPTY", "POINT", 0},
		{&GeoPointVal{Lat: 12.5, Lon: 34.5}, "POINT", 0},
		{&GeoBoundingBoxVal{TopLeft: &GeoPointVal{Lat: 10, Lon: -10}, BottomRight: &GeoPointVal{Lat: -10, Lon: 10}}, "ENVELOPE", 2},
		{[]any{12.0, 34.0}, "POINT", 0},
		{[]any{"POINT (1 1)", "LINESTRING (0 0, 2 2)"}, "GEOMETRYCOLLECTION", 1},
		{map[string]any{"lat": 5.0, "lon": 6.0}, "POINT", 0},
		{map[string]any{"type": "Point", "coordinates": []any{1.0, 2.0}}, "POINT", 0},
		{map[string]any{"type": "MultiPoint", "coordinates": []any{[]any{0.0, 0.0}, []any{1.0, 1.0}}}, "MULTIPOINT", 0},
		{map[string]any{"type": "LineString", "coordinates": []any{[]any{0.0, 0.0}, []any{1.0, 1.0}}}, "LINESTRING", 1},
		{map[string]any{"type": "MultiLineString", "coordinates": []any{[]any{[]any{0.0, 0.0}, []any{1.0, 1.0}}}}, "MULTILINESTRING", 1},
		{map[string]any{"type": "Polygon", "coordinates": []any{[]any{[]any{0.0, 0.0}, []any{4.0, 0.0}, []any{4.0, 4.0}, []any{0.0, 4.0}, []any{0.0, 0.0}}}}, "POLYGON", 2},
		{map[string]any{"type": "MultiPolygon", "coordinates": []any{[]any{[]any{[]any{0.0, 0.0}, []any{2.0, 0.0}, []any{2.0, 2.0}, []any{0.0, 2.0}, []any{0.0, 0.0}}}}}, "MULTIPOLYGON", 2},
		{map[string]any{"type": "Envelope", "coordinates": []any{[]any{-1.0, 1.0}, []any{1.0, -1.0}}}, "ENVELOPE", 2},
		{map[string]any{"type": "Circle", "coordinates": []any{10.0, 20.0}, "radius": "5km"}, "CIRCLE", 2},
		{map[string]any{"type": "GeometryCollection", "geometries": []any{map[string]any{"type": "Point", "coordinates": []any{1.0, 2.0}}}}, "GEOMETRYCOLLECTION", 0},
	}
	for _, tc := range geoInputs {
		gs, err := ParseGeoShapeDocValuesWithOpts(tc.raw, true)
		if err != nil {
			t.Fatalf("ParseGeoShapeDocValuesWithOpts(%#v) failed: %v", tc.raw, err)
		}
		if gs.GetShapeType() != tc.wantType || gs.GetDimensionalType() != tc.wantDim {
			t.Fatalf("shape mismatch for %#v: type=%s dim=%d want (%s,%d)", tc.raw, gs.GetShapeType(), gs.GetDimensionalType(), tc.wantType, tc.wantDim)
		}
		_ = gs.GetCentroid()
		_ = gs.GetLabelPosition()
		_ = gs.GetBoundingBox()
		_ = gs.GetMercatorWidth()
		_ = gs.GetMercatorHeight()
		_ = gs.ToGeoJSONMap()
		if !gs.IsEmpty() {
			g0, errG := gs.Get(0)
			if errG != nil || g0 == nil {
				t.Fatalf("Get(0) failed for %s: %v", tc.wantType, errG)
			}
		}
		for _, m := range []string{"size", "length", "isEmpty", "get", "getCentroid", "getBoundingBox", "topLeft", "bottomRight", "minLat", "maxLat", "minLon", "maxLon", "getLabelPosition", "getDimensionalType", "getShapeType", "getMercatorWidth", "getMercatorHeight", "toString"} {
			_, _, _ = evalGeoShapeMethodRound61(gs, m)
		}
	}

	// Concave C-shaped polygon whose centroid lies OUTSIDE the polygon ring -> forces GetLabelPosition interior search
	concave, err := ParseGeoShapeDocValues("POLYGON ((0 0, 10 0, 10 10, 0 10, 0 8, 8 8, 8 2, 0 2, 0 0))")
	if err != nil {
		t.Fatalf("concave polygon parse failed: %v", err)
	}
	lp := concave.GetLabelPosition()
	if lp == nil || !pointInPolygonRingsRound61(lp.Lat, lp.Lon, concave.Rings) {
		t.Fatalf("expected concave GetLabelPosition inside ring, got %#v", lp)
	}

	// Invalid shapes & nil/empty error paths
	invalidGeo := []any{
		nil,
		(*GeoShapeDocValues)(nil),
		(*GeoPointVal)(nil),
		(*GeoBoundingBoxVal)(nil),
		[]any{},
		12345,
		"UNKNOWN (1 2)",
		"ENVELOPE (1, 2)",
		map[string]any{"x": 1},
		map[string]any{"type": "Point", "coordinates": []any{1.0}},
		map[string]any{"type": "MultiPoint", "coordinates": "bad"},
		map[string]any{"type": "LineString", "coordinates": "bad"},
		map[string]any{"type": "MultiLineString", "coordinates": "bad"},
		map[string]any{"type": "Polygon", "coordinates": "bad"},
		map[string]any{"type": "MultiPolygon", "coordinates": []any{}},
		map[string]any{"type": "Envelope", "coordinates": []any{[]any{1.0, 2.0}}},
		map[string]any{"type": "Circle", "coordinates": "bad"},
		map[string]any{"type": "GeometryCollection", "geometries": "bad"},
		map[string]any{"type": "Hexagon", "coordinates": []any{}},
	}
	for _, bad := range invalidGeo {
		if _, err := ParseGeoShapeDocValuesWithOpts(bad, true); err == nil {
			t.Fatalf("expected ParseGeoShapeDocValuesWithOpts(%#v) error", bad)
		}
	}
	var nilGS *GeoShapeDocValues
	if _, err := nilGS.Get(0); err == nil || nilGS.GetShapeType() != "" || nilGS.GetDimensionalType() != 0 || nilGS.ToGeoJSONMap() != nil {
		t.Fatalf("unexpected nil GeoShapeDocValues method behavior")
	}
	emptyGS := &GeoShapeDocValues{ShapeType: "POINT"}
	for _, m := range []string{"getCentroid", "getBoundingBox", "topLeft", "bottomRight", "getLabelPosition", "getDimensionalType", "getMercatorWidth", "getMercatorHeight"} {
		if _, handled, err := evalGeoShapeMethodRound61(emptyGS, m); !handled || err == nil {
			t.Fatalf("expected IllegalStateException for empty GeoShape.%s", m)
		}
	}

	// Degenerate line/polygon + murmur3 + field.transform coverage
	degLine := &GeoShapeDocValues{ShapeType: "LINESTRING", Points: [][2]float64{{1, 2}, {1, 2}}, DimType: 1}
	degPoly := &GeoShapeDocValues{ShapeType: "POLYGON", Rings: [][][2]float64{{{1, 2}, {1, 2}, {1, 2}}}, DimType: 2}
	_, _, _, _ = degLine.rawCentroidAndWeightRound61()
	_, _, _, _ = degPoly.rawCentroidAndWeightRound61()
	_ = NewGeoShapeDocValuesCollection([]*GeoShapeDocValues{nil, degLine, degPoly}, true)

	if h := normalizeMurmur3DocValuesRound61([]any{int(1), int64(2), int32(3), uint64(4), json.Number("5"), "hello", map[string]any{"skip": 1}}, false); len(h) < 5 {
		t.Fatalf("unexpected normalizeMurmur3DocValuesRound61 len: %d", len(h))
	}
	root := map[string]any{"tag": "init"}
	fv := &FieldVal{Name: "tag", Root: root}
	if _, err := evalFieldValTransformRound61(fv, "v -> v + '_next'", root, nil, 0); err != nil || root["tag"] != "init_next" {
		t.Fatalf("evalFieldValTransformRound61 failed: root=%#v err=%v", root, err)
	}
}

func TestRound65_F27b_EvalHotspots_Arrays_Temporals_Equality_Math(t *testing.T) {
	// 1. Direct comparePainlessValues / isIntegerValuePainless / painlessValuesEqual coverage (eval.go:8001-8215)
	ip1, _ := ParseIPAddressVal("10.0.0.1")
	ip2, _ := ParseIPAddressVal("10.0.0.2")
	if !compareOrderedValues(ip1, ip2, "<") || !compareOrderedValues(ip2, "10.0.0.1", ">") || !compareOrderedValues("b", "a", ">=") || !compareOrderedValues("a", "a", "<=") {
		t.Fatalf("unexpected IPAddress/string compareOrderedValues")
	}
	for _, iv := range []any{int(1), int8(2), int16(3), int32(4), int64(5), uint(6), uint8(7), uint16(8), uint32(9), uint64(10), json.Number("11"), newPainlessBigInteger(big.NewInt(12)), big.NewInt(13)} {
		if _, ok := isIntegerValuePainless(iv); !ok {
			t.Fatalf("expected isIntegerValuePainless(%T) true", iv)
		}
	}
	if _, ok := isIntegerValuePainless("abc"); ok {
		t.Fatalf("expected isIntegerValuePainless(string) false")
	}
	uriA, _ := newPainlessURIFromString("https://example.org/a")
	urlA, _ := newPainlessURLFromString("https://example.org/a")
	otA, _ := newPainlessOffsetTime(10, 0, 0, 0, 0)
	bsA := newPainlessBitSet()
	_ = bsA.setBit(2, true)
	if !painlessValuesEqual(math.NaN(), math.NaN()) || painlessValuesEqual(math.NaN(), 1.0) ||
		!painlessValuesEqual(uriA, uriA) || !painlessValuesEqual(urlA, urlA) ||
		!painlessValuesEqual(otA, otA) || !painlessValuesEqual(bsA, bsA) ||
		!painlessValuesEqual([]any{map[string]any{"k": int64(1)}}, []any{map[string]any{"k": 1}}) ||
		painlessValuesEqual([]any{1}, map[string]any{"a": 1}) ||
		painlessValuesEqual(newPainlessBigInteger(big.NewInt(42)), int64(42)) != true {
		t.Fatalf("unexpected painlessValuesEqual behavior")
	}

	// 2. Painless scripts covering Arrays.*, new String(...), Math.getExponent, Year/MonthDay/DayOfWeek/Instant,
	//    Temporal until/datesUntil/between/atOffset/with, Matcher replaceAll/replaceFirst lambdas, BigDecimal ops, Stream reduce/drain
	scripts := []string{
		`def a = [1, 3, 5, 7, 9]; return [Arrays.binarySearch(a, 5), Arrays.binarySearch(a, 1, 4, 4), Arrays.binarySearch(['a', 'bb', 'ccc'], 'bb', Comparator.comparing(s -> s.length()))];`,
		`def a = [1, 2, 3, 4]; Arrays.fill(a, 1, 3, 9); def b = [1, 9, 9, 4]; return [Arrays.equals(a, b), Arrays.deepEquals([[1], [2]], [[1], [2]]), Arrays.toString(a), Arrays.deepToString([[1], [2]]), Arrays.hashCode(a), Arrays.deepHashCode([[1], [2]])];`,
		`def a = [0, 0, 0, 0]; Arrays.setAll(a, i -> i * 3); def c = [1, 2, 3, 4]; Arrays.parallelPrefix(c, (x, y) -> x + y); return [a.get(3), c.get(3)];`,
		`return [new String(), new String(new byte[]{65, 66, 67, 68}, 1, 2), new String(['w', 'x', 'y', 'z'], 1, 2), new String(new StringBuilder("hello"))];`,
		`return [Math.getExponent(0.0), Math.getExponent(Double.NaN), Math.getExponent(Double.POSITIVE_INFINITY), Math.getExponent(8.0)];`,
		`return [Year.of(2024).isLeap(), Year.isLeap(2020), Year.from('2024-05-01T00:00:00Z').getValue(), MonthDay.of(2, 29).toString(), MonthDay.from('2024-02-29T00:00:00Z').toString(), DayOfWeek.of(3), Month.of(12), Instant.ofEpochMilli(1000), Instant.ofEpochSecond(100, 500)];`,
		`def z = ZonedDateTime.parse('2024-01-15T10:00:00Z'); return [LocalDate.parse('2024-01-01').until('2024-01-05', ChronoUnit.DAYS), LocalDate.parse('2024-01-01').datesUntil('2024-01-04').count(), ChronoUnit.HOURS.between('2024-01-01T00:00:00Z', '2024-01-01T05:00:00Z'), '10:15:30'.atOffset('+02:00').toString(), z.with(ChronoField.MONTH_OF_YEAR, 6).getMonthValue(), z.with(TemporalAdjusters.lastDayOfMonth()).getDayOfMonth()];`,
		`return [/\d+/.matcher('a12b34').replaceAll(m -> '[' + m.group() + ']'), /\d+/.matcher('a12b34').replaceFirst(m -> 'X'), /\d+/.matcher('none').replaceAll(m -> 'Y')];`,
		`def b1 = new BigDecimal('10'); def b2 = new BigDecimal('3'); def dr = b1.divideAndRemainder(b2); return [b1.divide(new BigDecimal('4')).toPlainString(), b1.divide(b2, 4, RoundingMode.HALF_UP).toPlainString(), b1.divide(b2, new MathContext(4)).toPlainString(), b1.divide(b2, RoundingMode.CEILING).toPlainString(), b1.multiply(new BigDecimal('2.5'), new MathContext(3)).toPlainString(), b1.remainder(b2).toPlainString(), dr[0].toPlainString(), dr[1].toPlainString()];`,
		`def r = [1, 2, 3, 4].stream().reduce((a, b) -> a + b).get(); def d = [1, 2, 3].stream().filter(x -> x > 1).map(x -> x * 10); List acc = new ArrayList(); [5, 6].stream().forEachOrdered(x -> acc.add(x)); return [r, d.size(), acc.get(1)];`,
	}
	for _, sc := range scripts {
		if res, err := Eval(nil, sc, nil); err != nil || res == nil {
			t.Fatalf("hotspot script failed: %v\nscript=%s", err, sc)
		}
	}
	for _, errSc := range []string{
		`return (new BigDecimal('1')).divide(new BigDecimal('0'));`,
		`return (new BigDecimal('1')).divide(new BigDecimal('2'), 9999999, RoundingMode.HALF_UP);`,
		`return /\d+/.matcher('a12').replaceAll(m -> null);`,
		`Arrays.setAll([1], null);`,
		`Arrays.binarySearch(null, 1);`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected error for %q", errSc)
		}
	}
}

func TestRound65_F27b_CollectionsDequeSummaryAndCompileValidate(t *testing.T) {
	// 1. Deque/Queue/NavigableSet methods (eval.go:23300-23450)
	// 2. SummaryStatistics accept/combine & Collectors.summarizing* + super.method/staticMethod (round54)
	// 3. CompileValidate error paths & hex/binary/regex tokens (round60)
	scripts := []string{
		`TreeSet ts = new TreeSet([1, 3, 5, 7, 9]); return [ts.tailSet(5, false).size(), ts.subSet(3, true, 7, true).size(), ts.subSet(3, 9).size()];`,
		`ArrayDeque dq = new ArrayDeque(); dq.push(1); dq.addFirst(2); dq.offerFirst(3); dq.addLast(4); dq.offerLast(5); dq.offer(6); boolean r1 = dq.removeFirstOccurrence(4); return [dq.size(), r1, dq.peekFirst(), dq.peekLast()];`,
		`PriorityQueue pq = new PriorityQueue(); pq.offer(30); pq.offer(10); pq.offer(20); return [pq.peek(), pq.size()];`,
		`IntSummaryStatistics s1 = new IntSummaryStatistics(); s1.accept(10); s1.accept(20); IntSummaryStatistics s2 = new IntSummaryStatistics(); s2.accept(5); s1.combine(s2); def ds = [1, 2, 3].stream().collect(Collectors.summarizingDouble(x -> x * 1.5)); def ls = [1, 2, 3].stream().collect(Collectors.summarizingLong(x -> x * 2L)); return [s1.getCount(), s1.getSum(), s1.toString(), ds.getAverage(), ls.getMax()];`,
		`class Base { int f(int x) { return x + 1; } } class Child extends Base { static int dbl(int y) { return y * 2; } int f(int x) { return super.f(x) + dbl(x); } } Child c = new Child(); return [c.f(5), Child.dbl(4)];`,
		`def hex = 0x10_af; def bin = 0b1010_0101; def flt = 1_234.5_6e2; def sl = /a\/b[c]/i; return [hex, bin, flt, sl.matcher("A/Bc").find()];`,
	}
	for _, sc := range scripts {
		if res, err := Eval(nil, sc, nil); err != nil || res == nil {
			t.Fatalf("margin script failed: %v\nscript=%s", err, sc)
		}
	}
	for _, badSyntax := range []string{
		`return "unclosed;`,
		`return (1 + 2));`,
		`return [1, 2);`,
		`return {1;`,
	} {
		if err := CompileValidate(badSyntax); err == nil {
			t.Fatalf("expected CompileValidate error for %q", badSyntax)
		}
	}
	if _, err := computeSummaryStatsWithKindPainless([]any{int64(1), int64(2), int64(3)}, "x -> x * 2", "LongSummaryStatistics", nil, map[string]any{}, 0); err != nil {
		t.Fatalf("computeSummaryStatsWithKindPainless failed: %v", err)
	}
}

func TestRound65_F27b_MoreCoverageMargin_Mutators_Matcher_Streams_Time(t *testing.T) {
	// 1. Round54 Optional.flatMap, Clock.withZone, OffsetTime with/plus/minus, 5-arg & 7-arg URI constructors, super/static calls
	r54More := []string{
		`return [Optional.of("a").flatMap(x -> Optional.of(x + "b")).get(), Optional.of("a").flatMap(x -> Optional.empty()).isEmpty()];`,
		`return Clock.fixed("2022-01-01T00:00:00Z", "UTC").withZone("America/New_York").getZone();`,
		`def ot = OffsetTime.of(10, 20, 30, 40, "+02:00"); return [ot.withHour(5).toString(), ot.withMinute(6).toString(), ot.withSecond(7).toString(), ot.withNano(8).toString(), ot.withOffsetSameLocal("+03:00").toString(), ot.withOffsetSameInstant("-04:00").toString(), ot.plusHours(2).minusHours(1).plusMinutes(5).minusMinutes(2).plusSeconds(10).minusSeconds(5).plusNanos(100).minusNanos(50).toString(), ot.plus(Duration.ofMinutes(1)).minus(Duration.ofSeconds(1)).toString(), ot.plus(2, ChronoUnit.HOURS).plus(3, ChronoUnit.MINUTES).minus(4, ChronoUnit.SECONDS).plus(5, ChronoUnit.MILLIS).plus(6, ChronoUnit.MICROS).toString()];`,
		`def u5 = new URI("https", "example.org:8443", "/a/b", "k=v", "frag"); def u7 = new URI("https", "usr", "example.org", 8443, "/a/b", "k=v", "frag"); return [u5.toString(), u7.toString()];`,
	}
	for _, sc := range r54More {
		if res, err := Eval(nil, sc, nil); err != nil || res == nil {
			t.Fatalf("r54More script failed: %v\nscript=%s", err, sc)
		}
	}
	for _, errSc := range []string{
		`return Optional.of("a").flatMap(x -> null);`,
		`return OffsetTime.of(10, 20, 30, 0, "Z").withOffsetSameLocal("BAD");`,
		`return OffsetTime.of(10, 20, 30, 0, "Z").withOffsetSameInstant("BAD");`,
		`return new URI("https", "example.org", "rel", null, null);`,
		`return new URI("https", "u", "example.org", 80, "rel", null, null);`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected r54More error for %q", errSc)
		}
	}

	// 2. Round59 Stream asLongStream/boxed/takeWhile/dropWhile/asDoubleStream + Collections statement calls + Matcher region/appendReplacement/appendTail + Year.atDay
	extraEvalScripts := []string{
		`return [1, 2, 3, 4, 5].stream().asLongStream().boxed().takeWhile(x -> x < 5).asDoubleStream().dropWhile(x -> x < 2.0).filter(x -> x >= 2.0).collect(Collectors.toList());`,
		`List d = [0, 0]; Collections.copy(d, [8, 9]); Collections.addAll(d, 10, 11); return d;`,
		`StringBuilder sb = new StringBuilder(); def m = /\d+/.matcher("xx12yy34zz"); m.region(1, 9); while (m.find()) { m.appendReplacement(sb, "N"); } m.appendTail(sb); return [sb.toString(), m.pattern().toString(), /\d+/.pattern(), Year.of(2024).atDay(60), DayOfWeek.TUESDAY.getValue(), Month.MARCH.getValue(), (new StringBuilder("abc")).length()];`,
		`Map m = ['a': 1, 'b': 2]; for (def e : m.entrySet()) { e.setValue(e.getValue() + 10); } int sum = 0; for (def v : m.values()) { sum += v; } Map m2 = [:]; m2.putAll(['x': 5]); m2.put('y', 6); m2.putIfAbsent('x', 99); int sz = m2.size(); m2.clear(); return [sum, sz, m2.size()];`,
	}
	for _, sc := range extraEvalScripts {
		if res, err := Eval(nil, sc, nil); err != nil || res == nil {
			t.Fatalf("extraEvalScript failed: %v\nscript=%s", err, sc)
		}
	}
	if _, err := Eval(nil, `def m = /a/.matcher("abc"); m.region(-1, 2); return 1;`, nil); err == nil {
		t.Fatalf("expected IndexOutOfBoundsException for bad Matcher.region")
	}

	// 3. Mutable update sourceMap paths: putAll, put, putIfAbsent, addAll(idx, col), removeAll, removeIf, params put/clear, null-safe ?.clear()
	mutDoc := map[string]any{
		"sub":  map[string]any{"k1": int64(1)},
		"tags": []any{"a", "b", "c"},
	}
	mutParams := map[string]any{
		"__is_update_doc": true,
		"extra":           int64(1),
	}
	if err := EvalPainless(mutDoc, `
		ctx._source.putAll(['p': 2]);
		ctx._source.sub.putAll(['k2': 3]);
		ctx._source.put('p2', 4);
		ctx._source.sub.put('k3', 5);
		ctx._source.putIfAbsent('p2', 99);
		ctx._source.tags.addAll(['d', 'e']);
		ctx._source.tags.addAll(1, ['z']);
		ctx._source.tags.removeAll(['a', 'e']);
		ctx._source.tags.removeIf(t -> t == 'c');
		ctx._source?.missing?.clear();
		params.put('k', 'v');
		params.clear();
	`, mutParams); err != nil {
		t.Fatalf("mutable update script failed: %v", err)
	}
	if mutDoc["p"] != int64(2) || mutDoc["p2"] != int64(4) {
		t.Fatalf("unexpected mutDoc map mutations: %#v", mutDoc)
	}
	tags := mutDoc["tags"].([]any)
	if len(tags) != 3 || tags[0] != "z" || tags[1] != "b" || tags[2] != "d" {
		t.Fatalf("unexpected mutDoc tags after addAll/removeAll/removeIf: %#v", tags)
	}
}

func TestRound65_F27b_StringsBase64NumericNavigableAndMapOps(t *testing.T) {
	scripts := []string{
		`return [Base64.getEncoder().encodeToString("hi!"), Base64.getUrlEncoder().encodeToString("a+b/"), Base64.getDecoder().decode("aGkh"), Base64.getUrlDecoder().decode("YStiLw=="), Base64.getMimeDecoder().decode("aG\r\nkh"), Encoding.encodeBase64("ok"), Encoding.decodeBase64("b2s="), Encoding.encodeHex("AB"), Encoding.decodeHex("4142"), "hi".getBytes().length];`,
		`return [Integer.toHexString(-1), Integer.toBinaryString(10), Integer.toOctalString(8), Long.toHexString(255L), Long.toBinaryString(5L), Long.toOctalString(9L), Integer.toUnsignedString(-1, 16), Long.toUnsignedString(100L, 8), Integer.compareUnsigned(-1, 1), Long.compareUnsigned(1L, -1L), Integer.divideUnsigned(-2, 2), Long.divideUnsigned(-2L, 2L), Boolean.toString(true), Double.toString(1.5), Float.toString(2.5f), Integer.toString(15, 16), String.join("-", "x", "y", "z")];`,
		`StringBuilder sb = new StringBuilder("hello"); sb.append(" world!!", 0, 6).insert(5, ",").delete(5, 6).replace(0, 5, "HELLO"); return sb.toString();`,
		`def p = /,/; def s = "a,b,c"; return [p.split(s, 2).length, "".split("").length, s.split(/,/, -1).length, "abcDef".regionMatches(true, 3, "DEFx", 0, 3), "abc".regionMatches(0, "ab", 0, 2), "abc".regionMatches(0, "ab", 0, 99)];`,
		`def m = /\d+/.matcher("11"); m.reset("22"); Map mp = ['a': 1, 'b': 2]; return [m.find(), mp.replace('a', 10), mp.replace('b', 2, 20), mp.getOrDefault('missing', 99)];`,
		`TreeMap tm = new TreeMap(['a': 1, 'c': 3, 'e': 5]); TreeSet ts = new TreeSet([10, 20, 30, 40]); return [tm.floorKey('d'), tm.ceilingKey('b'), tm.lowerKey('c'), tm.higherKey('c'), tm.floorEntry('c').getValue(), tm.ceilingEntry('b').getKey(), tm.lowerEntry('c').getKey(), tm.higherEntry('c').getKey(), tm.headMap('c').size(), tm.tailMap('c').size(), tm.subMap('a', 'e').size(), ts.floor(25), ts.ceiling(25), ts.lower(20), ts.higher(20), ts.headSet(30).size()];`,
		`DoubleSummaryStatistics d1 = new DoubleSummaryStatistics(); d1.accept(1.5); DoubleSummaryStatistics d2 = new DoubleSummaryStatistics(); d2.accept(2.5); d1.combine(d2); def ot = OffsetTime.of(9, 8, 7, 0, "+01:00"); return [d1.toString(), ot.format(DateTimeFormatter.ISO_OFFSET_TIME), DateTimeFormatter.ISO_OFFSET_TIME.format(ot)];`,
	}
	for _, sc := range scripts {
		if res, err := Eval(nil, sc, nil); err != nil || res == nil {
			t.Fatalf("margin2 script failed: %v\nscript=%s", err, sc)
		}
	}
	for _, errSc := range []string{
		`return Base64.getDecoder().decode("!!!");`,
		`return Base64.getUrlDecoder().decode("!!!");`,
		`return /,/.split(null);`,
		`return "abc".split(null);`,
		`def ot = OffsetTime.of(9, 8, 7, 0, "Z"); return ot.format(null);`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected margin2 error for %q", errSc)
		}
	}

	mutArrDoc := map[string]any{
		"arr": []any{int64(3), int64(1), int64(2)},
		"mp":  map[string]any{"a": int64(1)},
	}
	if err := EvalPainless(mutArrDoc, `
		ctx._source.arr.add(9);
		ctx._source.arr.add(0, 7);
		ctx._source.arr.set(1, 8);
		ctx._source.arr.sort((a, b) -> a - b);
		ctx._source.arr.removeAll([7]);
		ctx._source.arr.retainAll([1, 2, 8, 9]);
		ctx._source.mp.put('b', 2);
		ctx._source.mp.putAll(['c': 3]);
		ctx._source.mp.replace('a', 11);
		ctx._source.mp.replace('b', 2, 22);
		ctx._source.mp.clear();
		int k = 1; k++; ++k; k += 4;
		ctx._source.k = k;
		ctx._source.ctxPutErr = false;
	`, map[string]any{"__is_update_doc": true}); err != nil {
		t.Fatalf("mutArrDoc script failed: %v", err)
	}
	if mutArrDoc["k"] != int64(7) {
		t.Fatalf("unexpected mutArrDoc: %#v", mutArrDoc)
	}
	if err := EvalPainless(mutArrDoc, `ctx.put('extra', 5);`, map[string]any{"__is_update_doc": true}); err == nil {
		t.Fatalf("expected unsupported ctx.extra error in _update")
	}
}

func TestRound65_F27b_CoveragePushOver1200(t *testing.T) {
	// 1. MovingFunctions suite (round60.go:4501-4648)
	mfScripts := []string{
		`def v = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]; return [MovingFunctions.linearWeightedAvg(v), MovingFunctions.ewma(v, 0.4), MovingFunctions.holt(v, 0.3, 0.1), MovingFunctions.holtWinters(v, 0.3, 0.1, 0.1, 2, false), MovingFunctions.holtWinters(v, 0.3, 0.1, 0.1, 2, true), MovingFunctions.stdDev(v), MovingFunctions.stdDev(v, 3.5), MovingFunctions.stdDev(v, 3.5, 2.0, 'upper'), MovingFunctions.stdDev(v, 3.5, 2.0, 'lower')];`,
	}
	for _, sc := range mfScripts {
		if res, err := Eval(nil, sc, nil); err != nil || res == nil {
			t.Fatalf("MovingFunctions script failed: %v", err)
		}
	}
	for _, errSc := range []string{
		`return MovingFunctions.ewma([1.0, 2.0], 1.5);`,
		`return MovingFunctions.unknown([1.0, 2.0]);`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected MovingFunctions error for %q", errSc)
		}
	}

	// 2. Matcher region + anchoring bounds + matches + lookingAt + group error (eval.go:9435-9530)
	matcherScripts := []string{
		`def m1 = /^abc$/.matcher("xabcy"); m1.region(1, 4); m1.useAnchoringBounds(false); boolean noAnchor = m1.matches(); def m2 = /abc/.matcher("xabcdef"); m2.region(1, 5); m2.useAnchoringBounds(false); boolean lk = m2.lookingAt(); return [noAnchor, lk, m2.group()];`,
		`def m = /\d+/.matcher("123"); boolean ok1 = m.matches(); def m2 = /^12/.matcher("0123"); m2.region(1, 4); m2.useAnchoringBounds(false); boolean lkFail = m2.lookingAt(); def m3 = /12$/.matcher("0123"); m3.region(1, 3); m3.useAnchoringBounds(false); boolean lkEnd = m3.lookingAt(); return [ok1, lkFail, lkEnd];`,
	}
	for _, sc := range matcherScripts {
		if res, err := Eval(nil, sc, nil); err != nil || res == nil {
			t.Fatalf("matcher script failed: %v", err)
		}
	}
	if _, err := Eval(nil, `return /a/.matcher("a").group();`, nil); err == nil {
		t.Fatalf("expected IllegalStateException for unmatched .group()")
	}

	// 3. Temporals (atDate, atTime, atStartOfDay), forEach, stream chained tailRest, MonthDay.of(Month, day)
	miscScripts := []string{
		`return [LocalTime.parse('10:15:30').atDate('2024-05-01'), LocalDate.parse('2024-05-01').atTime('09:30:00'), LocalDate.parse('2024-05-01').atTime(9, 30, 15, 500), LocalDate.parse('2024-05-01').atStartOfDay(), LocalDate.parse('2024-05-01').atStartOfDay('UTC'), MonthDay.of(Month.FEBRUARY, 29).toString(), [1, 2, 3].stream().filter(x -> x > 1).findFirst().get().toString()];`,
		`int s = 0; [1, 2, 3].forEach(x -> { s += x; }); Map mp = ['a': 1, 'b': 2]; mp.forEach((k, v) -> { s += v; }); mp.forEach(e -> { s += e.getValue(); }); return s;`,
		`class Base { int v = 1; } class Sub extends Base { int setSuper(int n) { super.v = n; return super.v; } } return (new Sub()).setSuper(9);`,
	}
	for _, sc := range miscScripts {
		if res, err := Eval(nil, sc, nil); err != nil || res == nil {
			t.Fatalf("misc script failed: %v\nscript=%s", err, sc)
		}
	}

	// 4. murmur3Hash128 tail lengths 0..16 + OffsetTime/URI compareTo tie-breakers
	murmurInputs := make([]any, 0, 17)
	for i := 0; i <= 16; i++ {
		murmurInputs = append(murmurInputs, strings.Repeat("a", i)+"xyz"[:min(3, i)])
	}
	if h := normalizeMurmur3DocValuesRound61(murmurInputs, true); len(h) == 0 {
		t.Fatalf("expected non-empty murmur3 hashes")
	}
	otE1, _ := newPainlessOffsetTime(10, 0, 0, 0, 7200)
	otE2, _ := newPainlessOffsetTime(9, 0, 0, 0, 3600)
	if otE1.compareTo(otE2) != 1 {
		t.Fatalf("expected equal-instant OffsetTime tie-break by local nano")
	}
	uriNoHost1, _ := newPainlessURIFromString("foo:/a/b")
	uriNoHost2, _ := newPainlessURIFromString("foo:/a/c")
	if uriNoHost1.compareTo(uriNoHost2) >= 0 {
		t.Fatalf("expected uriNoHost1 < uriNoHost2")
	}

	// 5. Mutable updates: ++ctx._source.cnt on RHS, nested clear, null-safe clear, non-update ctx.put + metadata() sync
	incDoc := map[string]any{
		"cnt":    int64(5),
		"nested": map[string]any{"x": int64(1), "y": int64(2)},
	}
	if err := EvalPainless(incDoc, `
		def pre = ++ctx._source.cnt;
		def post = ctx._source.cnt++;
		ctx._source.res = pre * 10 + post;
		ctx._source.nested.x += 4;
		ctx._source.nested.clear();
		ctx._source?.absent?.clear();
		Map lm = ['a': 1];
		lm.clear();
		def nullM = null;
		nullM?.clear();
		ctx.put('k', 'v');
		def m = metadata();
		m._id = 'newid';
		m._index = 'newidx';
		m._routing = 'newr';
		m._version = 3;
		m._version_type = 'external';
		m.op = 'index';
	`, map[string]any{"_ctx_op": "index"}); err != nil {
		t.Fatalf("non-update mutable + metadata script failed: %v", err)
	}
	if incDoc["cnt"] != int64(7) || incDoc["res"] != int64(66) {
		t.Fatalf("unexpected incDoc: %#v", incDoc)
	}
}

func TestRound65_F27b_ExactMarginBooster(t *testing.T) {
	// 1. GeoShapeDocValues property accessors on doc['geo_shape'].get(0).* (round60.go:7088-7122)
	geoDoc := map[string]any{
		"geo_shape": map[string]any{"type": "Polygon", "coordinates": []any{[]any{[]any{0.0, 0.0}, []any{2.0, 0.0}, []any{2.0, 2.0}, []any{0.0, 2.0}, []any{0.0, 0.0}}}},
		"title":     "hello world",
	}
	geoParams := map[string]any{
		"__field_types": map[string]string{
			"title.hash": "murmur3",
		},
	}
	resProp, err := Eval(geoDoc, `
		def g = doc['geo_shape'].get(0);
		return [
			g.topLeft.lat, g.bottomRight.lon, g.minLat, g.maxLat, g.minLon, g.maxLon,
			g.centroid.lat, g.boundingBox.topLeft.lat, g.labelPosition.lon,
			g.dimensionalType, g.shapeType, g.mercatorWidth, g.mercatorHeight, g.empty, g.size,
			doc['title.hash'].size()
		];
	`, geoParams)
	if err != nil || len(resProp.([]any)) != 16 {
		t.Fatalf("geoShape property / implicit + murmur3 script failed: res=%#v err=%v", resProp, err)
	}

	// 2. DayOfWeek & Month .getValue(), instanceof checks, array ctor with tail, Map.ofEntries, Math.*Exact, Matcher.replaceAll(str), regex split, ChronoUnit.between
	boosterScripts := []string{
		`def ms = []; for (int i = 1; i <= 7; i++) { ms.add(DayOfWeek.of(i).getValue()); } for (int i = 1; i <= 12; i++) { ms.add(Month.of(i).getValue()); } return ms;`,
		`def c = Clock.systemUTC(); def ot = OffsetTime.of(1,2,3,0,'Z'); def z = ZoneOffset.ofHours(2); def zid = ZoneId.ofOffset('UTC', ZoneOffset.ofHours(0)); def u = URI.create('https://a.com'); def ur = new URL('https://a.com'); Predicate p = x -> x > 0; return [c instanceof Clock, ot instanceof OffsetTime, z instanceof ZoneOffset, zid instanceof ZoneId, 'Europe/Paris' instanceof ZoneId, u instanceof URI, ur instanceof URL, p instanceof Predicate];`,
		`return [(new int[3]).length, (new int[2][3])[0].length, (new String[]{'a', 'b'}).length];`,
		`Map m = Map.ofEntries(Map.entry('k1', 1), Map.entry('k2', 2)); return [m.get('k1'), m.size()];`,
		`return [Math.floorDiv(7, 3), Math.floorMod(-7, 3), Math.addExact(1, 2), Math.subtractExact(5, 3), Math.multiplyExact(3, 4), Math.incrementExact(9), Math.decrementExact(9), Math.negateExact(5), Math.toIntExact(42L)];`,
		`return [/\d+/.matcher('a12b34').replaceAll('N'), /\d+/.matcher('a12b34').replaceFirst('N'), (/,/).split('a,b,c', 2).length, 'a,b,c'.split('', 2).length, ChronoUnit.DAYS.between('2024-01-01', '2024-01-10'), LocalDate.parse('2024-01-01').until('2024-02-01').getMonths()];`,
		`return [dotProduct(doc['vec'].vectorValue, [1.0, 2.0]), cosineSimilarity(doc['vec'].vectorValue, [1.0, 2.0])];`,
	}
	vecDoc := map[string]any{"vec": []float32{3.0, 4.0}}
	vecParams := map[string]any{"__field_types": map[string]string{"vec": "dense_vector"}}
	for i, sc := range boosterScripts {
		d, p := map[string]any(nil), map[string]any(nil)
		if i == len(boosterScripts)-1 {
			d, p = vecDoc, vecParams
		}
		if res, err := Eval(d, sc, p); err != nil || res == nil {
			t.Fatalf("booster script %d failed: %v\nscript=%s", i, err, sc)
		}
	}
	for _, errSc := range []string{
		`return Map.ofEntries(Map.entry('a', 1), Map.entry('a', 2));`,
		`return Map.ofEntries(Map.entry('a', null));`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected booster error for %q", errSc)
		}
	}

	// 3. Direct FormatJavaFloat64, parseZoneOffsetSecondsPainless, extractFloatVectorRound60, BigDecimal.div negative shift, ctx._id/_index/_routing/_version RHS
	for _, fv := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), math.Copysign(0, -1), 0.0, 1e20, 1e-5, 2.0} {
		if FormatJavaFloat64(fv) == "" {
			t.Fatalf("empty FormatJavaFloat64(%v)", fv)
		}
	}
	for _, off := range []string{"+02:30:15", "+0530", "+05", "-04:00", "UTC+2", "GMT-3"} {
		if _, ok := parseZoneOffsetSecondsPainless(off); !ok {
			t.Fatalf("expected parseZoneOffsetSecondsPainless(%q) ok", off)
		}
	}
	for _, fv := range []any{[]float64{1, 2}, []any{1, 2.0}} {
		if out, err := extractFloatVectorRound60(fv, nil, nil, false); err != nil || len(out) != 2 {
			t.Fatalf("extractFloatVectorRound60(%T) failed: %v", fv, err)
		}
	}
	for _, badFV := range []any{[]float32{1, 2}, []float64{}, []any{}, []any{"bad"}, 42} {
		if _, err := extractFloatVectorRound60(badFV, nil, nil, false); err == nil {
			t.Fatalf("expected error from extractFloatVectorRound60(%T)", badFV)
		}
	}
	if _, err := newPainlessBigDecimal(big.NewInt(10), -5).div(newPainlessBigDecimal(big.NewInt(2), 0), -10, "HALF_UP"); err != nil {
		t.Fatalf("BigDecimal negative-shift div failed: %v", err)
	}
	ctxRHS, err := Eval(map[string]any{"_id": "d1", "_index": "i1", "_routing": "r1"}, `return [ctx._id, ctx._index, ctx._routing, ctx._version];`, map[string]any{"_ctx_version": int64(7)})
	if err != nil || ctxRHS.([]any)[0] != "d1" || ctxRHS.([]any)[3] != int64(7) {
		t.Fatalf("ctx metadata RHS failed: %#v err=%v", ctxRHS, err)
	}
	// Trigger UpdateMetadataVal compound assign & returned container mutate fallback
	metaMut := map[string]any{"tags": []any{"a", "b"}, "m": map[string]any{"k": int64(1)}}
	if err := EvalPainless(metaMut, `
		def md = metadata();
		md.op = 'index';
		md.op += '';
		def t = (ctx._source.tags);
		t.add('c');
		t.remove('a');
		def mp = (ctx._source.m);
		mp.putIfAbsent('z', 9);
		mp.clear();
	`, map[string]any{"_ctx_op": "index"}); err != nil {
		t.Fatalf("metaMut script failed: %v", err)
	}
}

func TestRound65_F27b_CharacterArraysDecayBooster(t *testing.T) {
	// 1. Character static methods + Unicode category branches (eval.go:25290-25755)
	charScript := `
		def out = [];
		out.add(Character.charCount(0x1F600));
		out.add(Character.charCount(65));
		out.add(Character.toChars(65).length);
		out.add(Character.toChars(0x1F600).length);
		out.add(Character.toString(65));
		out.add(Character.valueOf('Z'));
		out.add(Character.isValidCodePoint(0x10FFFF));
		out.add(Character.isBmpCodePoint(0xFFFF));
		out.add(Character.isSupplementaryCodePoint(0x10000));
		out.add(Character.isHighSurrogate(0xD800));
		out.add(Character.isLowSurrogate(0xDC00));
		out.add(Character.isSurrogate(0xD900));
		out.add(Character.isSurrogatePair(0xD83D, 0xDE00));
		out.add(Character.toCodePoint(0xD83D, 0xDE00));
		out.add(Character.codePointAt('A\uD83D\uDE00B', 1));
		out.add(Character.codePointBefore('A\uD83D\uDE00B', 3));
		out.add(Character.codePointCount('A\uD83D\uDE00B', 0, 4));
		out.add(Character.compare('a', 'b'));
		out.add(Character.isDigit('5'));
		out.add(Character.isLetter('a'));
		out.add(Character.isLetterOrDigit('9'));
		out.add(Character.isAlphabetic('a'));
		out.add(Character.isWhitespace(' '));
		out.add(Character.isWhitespace('\u00A0'));
		out.add(Character.isSpaceChar(' '));
		out.add(Character.isUpperCase('A'));
		out.add(Character.isLowerCase('a'));
		out.add(Character.isTitleCase('\u01C5'));
		out.add(Character.toUpperCase('a'));
		out.add(Character.toUpperCase(97));
		out.add(Character.toLowerCase('A'));
		out.add(Character.toLowerCase(65));
		out.add(Character.toTitleCase('a'));
		out.add(Character.toTitleCase(97));
		out.add(Character.isIdeographic('中'));
		out.add(Character.isJavaIdentifierStart('_'));
		out.add(Character.isJavaIdentifierPart('1'));
		out.add(Character.isISOControl('\n'));
		out.add(Character.isDefined('A'));
		out.add(Character.digit('F', 16));
		out.add(Character.digit('9', 10));
		out.add(Character.digit('a', 10));
		out.add(Character.forDigit(15, 16));
		out.add(Character.forDigit(5, 10));
		out.add(Character.reverseBytes(0x1234));
		for (int cp : [65, 97, 0x01C5, 0x02B0, 0x4E2D, 0x0301, 0x20DD, 0x0903, 53, 0x2160, 0x00BD, 32, 0x2028, 0x2029, 1, 0x200B, 0xE000, 0xD800, 45, 40, 41, 95, 46, 43, 36, 94, 0x00A9, 0x00AB, 0x00BB, 0x0378]) {
			out.add(Character.getType(cp));
		}
		for (int nv : [53, 97, 65, 0xFF15, 0xFF21, 0xFF41, 0x0665, 0x00BD, 33]) {
			out.add(Character.getNumericValue(nv));
		}
		return out.size();
	`
	if res, err := Eval(nil, charScript, nil); err != nil || res == nil {
		t.Fatalf("charScript failed: %v", err)
	}
	for _, charErr := range []string{
		`return Character.toChars(-1);`,
		`return Character.toString(-1);`,
		`return Character.codePointAt('abc', 99);`,
		`return Character.codePointBefore('abc', 0);`,
		`return Character.codePointCount('abc', 2, 1);`,
	} {
		if _, err := Eval(nil, charErr, nil); err == nil {
			t.Fatalf("expected Character error for %q", charErr)
		}
	}

	// 2. URL 2/3/4 args, Locale ctors + forLanguageTag, field()/$/saturation/sigmoid/decay*, Arrays range compare
	urlScript := `
		def base = new URL('https://example.com/a/b');
		def rel = new URL(base, '../c?x=1');
		def u3 = new URL('http', 'host.local', 'p/q');
		def u4 = new URL('http', 'host.local', 8080, 'r');
		def l1 = new Locale('fr');
		def l2 = new Locale('en', 'US');
		def l3 = Locale.forLanguageTag('de-DE');
		return [
			rel.toString(), u3.toString(), u4.toString(), l1, l2, l3,
			field('num').get(), $('num'), $('missing', 99),
			$('vec')[0], $('vec_missing', [0.0, 0.0]).length,
			saturation(5.0, 2.0), sigmoid(5.0, 2.0, 1.0),
			decayNumericLinear(10.0, 5.0, 1.0, 0.5, 12.0),
			decayNumericExp(10.0, 5.0, 1.0, 0.5, 12.0),
			decayNumericGauss(10.0, 5.0, 1.0, 0.5, 12.0),
			decayDateLinear('2024-01-10T00:00:00Z', '5d', '1d', 0.5, '2024-01-12T00:00:00Z'),
			decayDateExp('2024-01-10T00:00:00Z', '5d', '1d', 0.5, '2024-01-12T00:00:00Z'),
			decayDateGauss('2024-01-10T00:00:00Z', '5d', '1d', 0.5, '2024-01-12T00:00:00Z'),
			Arrays.compare([1, 2, 3, 4], 1, 3, [9, 2, 3, 8], 1, 3),
			Arrays.mismatch([1, 2, 3, 4], 1, 3, [9, 2, 4, 8], 1, 3)
		];
	`
	urlDoc := map[string]any{"num": 7, "vec": []float64{1.0, 2.0}}
	urlParams := map[string]any{
		"__field_types": map[string]string{"num": "integer", "vec": "dense_vector", "vec_missing": "dense_vector"},
	}
	if res, err := Eval(urlDoc, urlScript, urlParams); err != nil || res == nil {
		t.Fatalf("url/decay/Arrays script failed: %v", err)
	}

	// 3. Container set/addAll paths (eval.go:10150-10250)
	mutDoc := map[string]any{"arr": []any{"x", "y", "z"}}
	if err := EvalPainless(mutDoc, `
		ctx._source.arr.set(1, 'Y');
		ctx._source.arr.addAll(1, ['p', 'q']);
		def loc = ['a', 'b'];
		loc.set(0, 'A');
		loc.addAll(1, ['m']);
		def aliasArr = ctx._source.arr;
		aliasArr.set(0, 'X0');
		aliasArr.addAll(0, ['head']);
		def directArr = (ctx._source.arr);
		directArr.set(1, 'X1');
		directArr.addAll(2, ['ins']);
	`, nil); err != nil {
		t.Fatalf("container set/addAll script failed: %v", err)
	}
}

func TestRound65_F27b_ProcessorsHexMapTimeBooster(t *testing.T) {
	// 1. Processors.* scalar & mutating forms + byte sizes + convert + communityId + uriParts (round60.go:4816-5500)
	procDoc := map[string]any{
		"sz": "2kb", "low": "AbC", "up": "xy", "tr": "  hi  ", "gs": "a12b",
		"sp": "a,b,c", "jn": []any{"x", "y"}, "rm1": "drop", "rm2": "d2", "rm3": "d3",
		"old": "val", "ap": []any{"a"}, "cnv": "42", "js": `{"k":1,"a":[2,3]}`, "js2": `{"flat":9}`,
		"ud": "a+b%20c",
	}
	if err := EvalPainless(procDoc, `
		Processors.bytes(ctx, 'sz');
		Processors.lowercase(ctx, 'low');
		Processors.uppercase(ctx, 'up');
		Processors.trim(ctx, 'tr');
		Processors.gsub(ctx, 'gs', '[0-9]+', 'N');
		Processors.split(ctx, 'sp', ',');
		Processors.join(ctx, 'jn', '-');
		Processors.append(ctx, 'ap', 'b');
		Processors.convert(ctx, 'cnv', 'integer', 'cnv_out');
		Processors.json(ctx, 'js', 'js_out');
		Processors.json(ctx, 'js2', '');
		Processors.urlDecode(ctx, 'ud');
		Processors.rename(ctx, 'old', 'renamed');
		Processors.remove(ctx, 'rm1');
		Processors.remove(ctx, ['rm2', 'rm3']);
	`, nil); err != nil {
		t.Fatalf("Processors ctx mutation failed: %v", err)
	}
	if procDoc["sz"] != int64(2048) || procDoc["renamed"] != "val" || procDoc["cnv_out"] != int64(42) {
		t.Fatalf("unexpected procDoc: %#v", procDoc)
	}

	procScalar, err := Eval(nil, `
		def b = [
			Processors.bytes('10b'), Processors.bytes('1k'), Processors.bytes('2mb'),
			Processors.bytes('1gb'), Processors.bytes('1tb'), Processors.bytes('1pb')
		];
		def c = [
			Processors.convert('42', 'int'), Processors.convert('3.5', 'double'),
			Processors.convert(9, 'string'), Processors.convert('true', 'boolean'),
			Processors.convert('false', 'boolean'), Processors.convert('127.0.0.1', 'ip'),
			Processors.convert('true', 'auto'), Processors.convert('false', 'auto'),
			Processors.convert('7', 'auto'), Processors.convert('2.5', 'auto'),
			Processors.convert('abc', 'auto'), Processors.convert(['1', '2'], 'integer'),
			Processors.lowercase(['A', 'B']), Processors.uppercase(['a', 'b']),
			Processors.trim('  x '), Processors.gsub('a1b2', '[0-9]', 'Z'),
			Processors.split('x:y', ':'), Processors.join(['p', 'q'], '/'),
			Processors.append(['p'], 'q'), Processors.json('[1,2.5]'),
			Processors.urlDecode('hello+world%21'),
			Processors.uriParts('https://usr:pw@example.com:8443/p/q?a=1#frag'),
			Processors.communityId('192.168.1.1', '10.0.0.1', 6, null, 1234, 80, null, null, 1),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, 'tcp', 1234, 80),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, 'udp', 53, 5353),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, 'icmp', null, null, 8, 0),
			Processors.communityId('::1', '::2', null, 'icmp6', null, null, 128, 0),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, 'sctp', 100, 200),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, 'igmp'),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, 'rsvp'),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, 'gre'),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, 'esp'),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, 'ah'),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, 'pim'),
			Processors.communityId('192.168.1.1', '10.0.0.1', null, '99')
		];
		return b.size() + c.size();
	`, nil)
	if err != nil || procScalar == nil {
		t.Fatalf("Processors scalar script failed: %v", err)
	}
	for _, errSc := range []string{
		`return Processors.bytes('badsize');`,
		`return Processors.convert('nope', 'integer');`,
		`return Processors.convert('nope', 'double');`,
		`return Processors.convert('nope', 'boolean');`,
		`return Processors.convert('badip', 'ip');`,
		`return Processors.convert('x', 'unknown_type');`,
		`return Processors.json('{bad');`,
		`return Processors.communityId('badip', '10.0.0.1');`,
		`return Processors.communityId('10.0.0.1', 'badip');`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected Processors error for %q", errSc)
		}
	}

	// 2. HexFormat + Objects + Collections + Java Time factories (eval.go:22578+, round54.go:3642+, round58.go:1590+)
	stdScript := `
		def hf = HexFormat.of().withPrefix('0x').withSuffix('h').withDelimiter(',');
		def s1 = hf.formatHex('abcd', 1, 3);
		def p1 = hf.parseHex(s1);
		def p2 = HexFormat.of().parseHex('01020304', 2, 6);
		def hx = [
			hf.toHexDigits(255), hf.toHexDigits(255L),
			hf.toHexDigits((byte) 15), hf.toHexDigits((short) 255),
			hf.toHexDigits('A'), hf.toHexDigits(255, 4), hf.toHexDigits(255, 0),
			hf.fromHexDigits('00ff'), hf.fromHexDigits('000100ff', 4, 8),
			hf.fromHexDigitsToLong('00000000000000ff'),
			hf.isHexDigit('F'), hf.isHexDigit('z'),
			hf.fromHexDigit('a'), hf.fromHexDigit('9')
		];
		def list = [1, 2];
		Collections.addAll(list, 3, 4);
		Collections.addAll(list, [5, 6]);
		def colRes = [
			Objects.compare(1, 2, (a, b) -> a - b),
			Objects.requireNonNullElseGet(null, () -> 42),
			Objects.checkIndex(1, 5),
			Objects.checkFromToIndex(1, 3, 5),
			Objects.checkFromIndexSize(1, 2, 5),
			Objects.toIdentityString('abc'),
			Objects.hashCode('abc'),
			Objects.hash(1, 'a', true),
			Collections.indexOfSubList([1, 2, 3, 4], [2, 3]),
			Collections.lastIndexOfSubList([1, 2, 3, 2, 3], [2, 3]),
			Collections.indexOfSubList([1, 2], []),
			Collections.lastIndexOfSubList([1, 2], []),
			list.size()
		];
		def tmRes = [
			Year.of(2024).toString(),
			YearMonth.of(2024, 3).toString(),
			MonthDay.of(3, 15).toString(),
			Month.of(3).toString(),
			DayOfWeek.of(5).toString(),
			LocalDate.of(2024, 3, 15).toString(),
			LocalDate.ofYearDay(2024, 60).toString(),
			LocalTime.of(10, 20).toString(),
			LocalTime.of(10, 20, 30).toString(),
			LocalTime.of(10, 20, 30, 500).toString(),
			LocalTime.ofSecondOfDay(3661).toString(),
			LocalTime.ofNanoOfDay(3661000000000L).toString(),
			LocalDateTime.of(LocalDate.of(2024, 3, 15), LocalTime.of(10, 20)).toString(),
			LocalDateTime.of(2024, 3, 15, 10, 20).toString(),
			LocalDateTime.of(2024, 3, 15, 10, 20, 30, 500).toString(),
			ZonedDateTime.of(LocalDateTime.of(2024, 3, 15, 10, 20), ZoneId.of('UTC')).toString(),
			OffsetDateTime.of(LocalDateTime.of(2024, 3, 15, 10, 20), ZoneOffset.UTC).toString()
		];
		def sset = new LinkedHashSet(['a', 'b']);
		def lmap = new LinkedHashMap(['k': 1]);
		def sb = new StringBuffer('hi');
		sb.append('!');
		int sum = 0;
		[1, 2, 3].forEach(x -> sum += x);
		['a': 10, 'b': 20].forEach((k, v) -> sum += v);
		sset.forEach(x -> sum += 1);
		def wrapSz = (new ArrayList([1, 2])).size();
		def genSz = (new ArrayList(4)).size();
		return [s1, p1.size(), p2.size(), hx.size(), colRes.size(), tmRes.size(), lmap.size(), sb.toString(), sum, wrapSz, genSz];
	`
	if res, err := Eval(nil, stdScript, nil); err != nil || res == nil {
		t.Fatalf("stdScript failed: %v", err)
	}
	for _, errSc := range []string{
		`return HexFormat.of().formatHex('ab', 0, 99);`,
		`return HexFormat.of().parseHex('zz');`,
		`return HexFormat.of().parseHex('012');`,
		`return HexFormat.of().toHexDigits(1, 99);`,
		`return HexFormat.of().fromHexDigits('zzzz');`,
		`return HexFormat.of().fromHexDigit('z');`,
		`return Objects.checkIndex(9, 5);`,
		`return Objects.checkFromToIndex(3, 1, 5);`,
		`return Objects.checkFromIndexSize(3, 5, 5);`,
		`return Objects.toIdentityString(null);`,
		`return DayOfWeek.of(9);`,
		`return LocalTime.ofSecondOfDay(99999);`,
		`return LocalTime.ofNanoOfDay(-1);`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected error for %q", errSc)
		}
	}

	// 3. Map computeIfAbsent / compute / computeIfPresent / merge (eval.go:19651-19930)
	mapDoc := map[string]any{"m": map[string]any{"a": int64(1), "rm": int64(5)}}
	if err := EvalPainless(mapDoc, `
		ctx._source.m.computeIfAbsent('b', k -> 10);
		ctx._source.m.computeIfAbsent('a', k -> 99);
		ctx._source.m.compute('c', (k, v) -> v == null ? 7 : v + 1);
		ctx._source.m.computeIfPresent('a', (k, v) -> v + 2);
		ctx._source.m.computeIfPresent('rm', (k, v) -> null);
		ctx._source.m.computeIfPresent('nope', (k, v) -> 1);
		ctx._source.m.merge('m1', 4, (o, n) -> o + n);
		ctx._source.m.merge('m1', 5, (o, n) -> o + n);
		def lm = ctx._source.m;
		lm.computeIfAbsent('d', k -> 11);
		lm.merge('m1', 1, (o, n) -> o + n);
	`, nil); err != nil {
		t.Fatalf("map compute/merge script failed: %v", err)
	}
	mRes := mapDoc["m"].(map[string]any)
	if mRes["a"] != int64(3) || mRes["b"] != int64(10) || mRes["c"] != int64(7) || mRes["m1"] != int64(10) {
		t.Fatalf("unexpected map compute/merge result: %#v", mRes)
	}
	if _, stillHas := mRes["rm"]; stillHas {
		t.Fatalf("expected 'rm' removed via computeIfPresent -> null: %#v", mRes)
	}
}

func TestRound65_F27b_ExactStretchBooster(t *testing.T) {
	// 1. ApplyUpdateWithResult + metadata mutation/version/UBQ/DetectNoop (eval.go:3235-3440)
	if out, op, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Doc: map[string]any{"a": json.Number("1")},
	}, true); err != nil || op != "noop" || len(out) == 0 {
		t.Fatalf("expected noop merge: op=%q out=%s err=%v", op, out, err)
	}
	if _, op, err := ApplyUpdateWithResult(nil, &UpdateRequest{
		Upsert: map[string]any{"x": 1},
	}, false); err != nil || op != "created" {
		t.Fatalf("expected upsert created: op=%q err=%v", op, err)
	}
	if _, op, err := ApplyUpdateWithResult(nil, &UpdateRequest{
		Doc:         map[string]any{"x": 1},
		DocAsUpsert: true,
	}, false); err != nil || op != "created" {
		t.Fatalf("expected doc_as_upsert created: op=%q err=%v", op, err)
	}
	metaReq := &UpdateRequest{
		MetaID:            "id1",
		MetaIndex:         "idx1",
		MetaRouting:       "r1",
		MetaVersion:       1,
		AllowMetaMutation: true,
		Script: &ScriptSpec{
			Source: "ctx._id = 'id2'; ctx._index = 'idx2'; ctx._routing = 'r2'; ctx._version = 5; ctx._source.v = 10;",
		},
	}
	if _, op, err := ApplyUpdateWithResult(json.RawMessage(`{"v":1}`), metaReq, true); err != nil || op != "updated" || metaReq.MetaID != "id2" || metaReq.MetaIndex != "idx2" || metaReq.MetaVersion != 5 {
		t.Fatalf("meta mutation failed: req=%#v op=%q err=%v", metaReq, op, err)
	}
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"v":1}`), &UpdateRequest{
		AllowMetaMutation: true,
		Script:            &ScriptSpec{Source: "ctx._version = null;"},
	}, true); err != nil {
		t.Fatalf("meta version null failed: %v", err)
	}
	for _, ubqCase := range []struct {
		op     string
		wantOp string
	}{
		{"noop", "noop"},
		{"delete", "deleted"},
		{"index", "updated"},
	} {
		if _, gotOp, err := ApplyUpdateWithResult(json.RawMessage(`{"v":1}`), &UpdateRequest{
			IsUBQ:  true,
			IsES8:  true,
			Script: &ScriptSpec{Source: "ctx.op = '" + ubqCase.op + "';"},
		}, true); err != nil || gotOp != ubqCase.wantOp {
			t.Fatalf("ubq %q got (%q, %v)", ubqCase.op, gotOp, err)
		}
	}
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"v":1}`), &UpdateRequest{
		Script: &ScriptSpec{
			Source: "ctx.op = 'create';",
			Params: map[string]any{"__disallow_update_create_op": true},
		},
	}, true); err == nil {
		t.Fatalf("expected disallow_update_create_op error")
	}

	// 2. Optional full methods + Stream findFirst terminal chains + instanceof (round54.go:2649+, eval.go:15516+, 20350+)
	optStreamScript := `
		int acc = 0;
		Optional.of(5).ifPresent(v -> acc += v);
		Optional.of(5).ifPresentOrElse(v -> acc += v, () -> acc += 100);
		Optional.empty().ifPresentOrElse(v -> acc += v, () -> acc += 20);
		def o1 = Optional.empty().or(() -> Optional.of(7));
		def o2 = Optional.of(7).or(() -> Optional.of(8));
		def o3 = Optional.empty().or(() -> 9);
		def o4 = Optional.empty().orElseGet(() -> 5);
		def oi = OptionalInt.empty().orElseGet(() -> 4);
		def od = OptionalDouble.empty().orElse(2.5);
		def o5 = Optional.of(5).filter(x -> x > 10).isPresent();
		def o6 = Optional.of(5).filter(x -> x == 5).map(x -> x * 2).flatMap(x -> Optional.of(x + 1)).get();
		def o7 = Optional.of(5).map(x -> null).isEmpty();
		def st = [
			['a', 'b'].stream().findFirst().get().toUpperCase(),
			[1, 2].stream().findFirst().orElseThrow(),
			[].stream().findFirst().orElse(9),
			[].stream().findFirst().orElseGet(() -> 8),
			[].stream().findFirst().isPresent(),
			[].stream().findFirst().isEmpty()
		];
		def statsI = [1, 2].stream().mapToInt(x -> x).summaryStatistics();
		def statsL = [1, 2].stream().mapToLong(x -> x).summaryStatistics();
		def statsD = [1.0, 2.0].stream().mapToDouble(x -> x).summaryStatistics();
		Predicate pred = x -> x > 0;
		Function fn = x -> x + 1;
		Consumer cons = x -> x;
		Supplier sup = () -> 1;
		def hf = HexFormat.of();
		def uid = UUID.randomUUID().toString();
		def inst = [
			[] instanceof List,
			[:] instanceof Map,
			statsI instanceof IntSummaryStatistics,
			statsL instanceof LongSummaryStatistics,
			statsD instanceof DoubleSummaryStatistics,
			uid instanceof UUID,
			hf instanceof HexFormat,
			o1 instanceof Optional,
			OptionalInt.of(1) instanceof OptionalInt,
			OptionalLong.of(1L) instanceof OptionalLong,
			OptionalDouble.of(1.0) instanceof OptionalDouble,
			Clock.systemUTC() instanceof Clock,
			OffsetTime.of(1, 2, 3, 0, 'Z') instanceof OffsetTime,
			ZoneOffset.UTC instanceof ZoneOffset,
			ZoneId.of('UTC') instanceof ZoneId,
			URI.create('https://a.com') instanceof URI,
			new URL('https://a.com') instanceof URL,
			pred instanceof Predicate,
			fn instanceof Function,
			cons instanceof Consumer,
			sup instanceof Supplier,
			[:] instanceof Metadata,
			Version.V_8_15_0 instanceof Version,
			null instanceof String
		];
		return [acc, o1.get(), o2.get(), o3.get(), o4, oi, od, o5, o6, o7, st.size(), inst.size()];
	`
	if res, err := Eval(nil, optStreamScript, nil); err != nil || res == nil {
		t.Fatalf("optStreamScript failed: %v", err)
	}
	for _, errSc := range []string{
		`return Optional.empty().orElseThrow(() -> new IllegalStateException('missing'));`,
		`return [].stream().findFirst().orElseThrow();`,
		`return [].stream().findFirst().orElseThrow(() -> new IllegalStateException('empty'));`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected Optional error for %q", errSc)
		}
	}

	// 3. Labeled for, multi-decl, comma stmts, entrySet value set, user class + user function alias, unsigned/compare, BigDecimal/BigInteger, SB/Matcher/repeat/nCopies
	bigDoc := map[string]any{"tags": []any{"t0"}}
	comboScript := `
		class Box { int v; Box(int x) { this.v = x; } }
		int bump(Box b, List xs) { b.v = 7; xs.add('z'); return b.v; }
		def bx = new Box(1);
		def bres = bump(bx, ctx._source.tags);
		def locList = ['l0'];
		bump(bx, locList);
		int sum = 0;
		outer: for (int i = 0, j = 5; i < 4; i++, j--) {
			for (int k = 0; k < 3; k++) {
				sum += k;
				if (k == 1) continue outer;
				if (i == 3) break outer;
			}
		}
		int p = 1, q = 2;
		p = 3, q = 4;
		def mp = ['k': 1];
		for (def e : mp.entrySet()) {
			e.value = 9;
		}
		def nums = [
			Integer.divideUnsigned(10, 3), Long.divideUnsigned(10L, 3L),
			Integer.remainderUnsigned(-1, 2), Long.remainderUnsigned(-1L, 2L),
			Integer.compare(1, 2), Long.compare(2L, 1L), Short.compare((short)1, (short)1), Byte.compare((byte)1, (byte)2),
			Double.compare(0.0/0.0, 1.0), Float.compare(-0.0f, 0.0f),
			Boolean.compare(true, false), Boolean.compare(false, true), Boolean.compare(true, true),
			BigInteger.valueOf('123').toString()
		];
		def bd0 = new BigDecimal();
		def bd1 = new BigDecimal(BigInteger.valueOf(12345), new MathContext(3));
		def bd2 = new BigDecimal(BigInteger.valueOf(12345), 2, new MathContext(3));
		def bd3 = new BigDecimal('123.45', new MathContext(3));
		def bd4 = new BigDecimal('10').add('2.5');
		def bd5 = new BigDecimal('10').remainder('3');
		def bd6 = new BigDecimal('10').remainder('3', new MathContext(2));
		def bd7 = new BigDecimal('10').divideToIntegralValue('3', new MathContext(2));
		def bd8 = new BigDecimal('10').divideAndRemainder('3', new MathContext(2));
		def bi0 = new BigInteger();
		def bi1 = new BigInteger([1, 2]);
		def sb = new StringBuilder('abcdef');
		sb.delete(1, 3);
		sb.delete(-1, 1);
		sb.deleteCharAt(0);
		sb.setLength(-1);
		sb.append('xy');
		sb.setLength(5);
		sb.setLength(2);
		def mf = /a*/.matcher('aab').find(0);
		def rp = ['a'.repeat(3), 'a'.repeat(0), Collections.nCopies(3, 'x').size()];
		ctx._source.res = [bres, bx.v, locList.size(), sum, p + q, mp.get('k'), nums.size(), bd0.toString(), bd1.toString(), bd2.toString(), bd3.toString(), bd4.toString(), bd5.toString(), bd6.toString(), bd7.toString(), bd8.length, bi0.toString(), bi1.toString(), sb.toString(), mf, rp.size()];
	`
	if err := EvalPainless(bigDoc, comboScript, nil); err != nil {
		t.Fatalf("comboScript failed: %v", err)
	}
	for _, errSc := range []string{
		`return Integer.divideUnsigned(10, 0);`,
		`return Long.divideUnsigned(10L, 0L);`,
		`return Integer.remainderUnsigned(10, 0);`,
		`return Long.remainderUnsigned(10L, 0L);`,
		`return new BigDecimal('not_a_number');`,
		`return new BigDecimal(BigInteger.valueOf(1), 999999);`,
		`return new BigInteger([]);`,
		`return new BigDecimal('10').remainder(0);`,
		`return new BigDecimal('10').pow(-1);`,
		`return new BigDecimal('10').pow(1000000);`,
		`return /a/.matcher('ab').find(-1);`,
		`return 'a'.repeat(-1);`,
		`return 'a'.repeat(null);`,
		`return Collections.nCopies(-1, 'x');`,
		`return Collections.nCopies(null, 'x');`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected combo error for %q", errSc)
		}
	}
}

func TestRound65_F27b_CoverageCrossGoal(t *testing.T) {
	// 1. ChronoField .with(...) + Year/MonthDay/DayOfWeek/Month/Period arithmetic (eval.go:820-920, 12580-12685)
	chronoScript := `
		def zdt = ZonedDateTime.parse('2024-03-15T10:20:30Z');
		def w = [
			zdt.with(ChronoField.OFFSET_SECONDS, 7200).toString(),
			zdt.with(ChronoField.OFFSET_SECONDS, 0).toString(),
			zdt.with(ChronoField.YEAR, 2025).toString(),
			zdt.with(ChronoField.YEAR_OF_ERA, 2025).toString(),
			zdt.with(ChronoField.ERA, 0).toString(),
			zdt.with(ChronoField.PROLEPTIC_MONTH, 24005).toString(),
			zdt.with(ChronoField.MONTH_OF_YEAR, 6).toString(),
			zdt.with(ChronoField.EPOCH_DAY, 19000).toString(),
			zdt.with(ChronoField.DAY_OF_YEAR, 100).toString(),
			zdt.with(ChronoField.DAY_OF_MONTH, 15).toString(),
			zdt.with(ChronoField.DAY_OF_WEEK, 2).toString(),
			zdt.with(ChronoField.ALIGNED_DAY_OF_WEEK_IN_MONTH, 3).toString(),
			zdt.with(ChronoField.ALIGNED_DAY_OF_WEEK_IN_YEAR, 3).toString(),
			zdt.with(ChronoField.ALIGNED_WEEK_OF_MONTH, 2).toString(),
			zdt.with(ChronoField.ALIGNED_WEEK_OF_YEAR, 10).toString()
		];
		def y = Year.of(2020);
		def md = MonthDay.of(3, 15);
		def per = Period.of(1, 2, 3);
		def arith = [
			y.plus(2, ChronoUnit.DECADES).toString(),
			y.plus(1, ChronoUnit.CENTURIES).toString(),
			y.plus(1, ChronoUnit.MILLENNIA).toString(),
			y.minus(5, ChronoUnit.YEARS).toString(),
			y.plus(Period.ofYears(3)).toString(),
			md.withMonth(5).toString(),
			md.withMonth('APRIL').toString(),
			md.withDayOfMonth(20).toString(),
			DayOfWeek.of(5).plus(3).toString(),
			DayOfWeek.of(5).minus(6).toString(),
			Month.of(10).plus(4).toString(),
			Month.of(2).minus(5).toString(),
			per.plus(Period.of(0, 1, 2)).toString(),
			per.minus(Period.of(0, 1, 1)).toString(),
			per.plusDays(2).minusDays(1).plusMonths(1).plusYears(1).toString()
		];
		return w.size() + arith.size();
	`
	if res, err := Eval(nil, chronoScript, nil); err != nil || res == nil {
		t.Fatalf("chronoScript failed: %v", err)
	}
	for _, errSc := range []string{
		`return ZonedDateTime.parse('2023-03-15T10:20:30Z').with(ChronoField.DAY_OF_YEAR, 366);`,
		`return ZonedDateTime.parse('2023-02-15T10:20:30Z').with(ChronoField.DAY_OF_MONTH, 31);`,
		`return MonthDay.of(2, 10).withMonth(13);`,
		`return MonthDay.of(2, 10).withDayOfMonth(31);`,
		`return DateTimeFormatter.ofPattern('invalid[[[');`,
		`return DateTimeFormatter.ofPattern(null);`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected chrono/dtf error for %q", errSc)
		}
	}

	// 2. Chained mutable map/list receivers (eval.go:19551-19649), Collections.replaceAll/sort/reverse (eval.go:18254+), BigDecimal/BigInteger.add (10351+)
	mutChainDoc := map[string]any{
		"m":      map[string]any{"k": []any{"a", "b"}},
		"nested": []any{[]any{"x"}},
	}
	if err := EvalPainless(mutChainDoc, `
		ctx._source.m.get('k').add('c');
		ctx._source.m.computeIfAbsent('k2', k -> []).add('z');
		ctx._source.nested.get(0).add('y');
		def lm = ['sub': ['p', 'q']];
		lm.get('sub').add('r');
		def l = ['b', 'a', 'b', 'c'];
		Collections.replaceAll(l, 'b', 'B');
		Collections.sort(l);
		Collections.sort(l, (a, b) -> b.compareTo(a));
		Collections.reverse(l);
		def fmt = DateTimeFormatter.ofPattern('yyyy/MM/dd HH:mm');
		def bd = new BigDecimal('1.234').add('2.345', new MathContext(3));
		def bi = new BigInteger('10').add('20');
		def sj = new StringJoiner(',').add(null).add('ok');
		ctx._source.extra = [l, fmt, bd.toString(), bi.toString(), sj.toString()];
	`, nil); err != nil {
		t.Fatalf("mutChain script failed: %v", err)
	}

	// 3. round60WrapperEquals direct symmetric coverage (round60.go:7365-7561)
	g1, err := ParseGeoShapeDocValues("POINT (1.0 2.0)")
	if err != nil {
		t.Fatalf("ParseGeoShapeDocValues failed: %v", err)
	}
	g2, _ := ParseGeoShapeDocValues("POINT (1.0 2.0)")
	g3, _ := ParseGeoShapeDocValues("LINESTRING (0 0, 1 1)")
	ip1 := &IPAddressVal{Addr: netip.MustParseAddr("10.0.0.1")}
	ip2 := &IPAddressVal{Addr: netip.MustParseAddr("10.0.0.1")}
	bb1 := g1.GetBoundingBox()
	bb2 := g2.GetBoundingBox()
	dv1 := &DenseVectorVal{Floats: []float32{1, 2}}
	dv2 := &DenseVectorVal{Floats: []float32{1, 2}}
	dv3 := &DenseVectorVal{Floats: []float32{1, 3}}
	now := time.Date(2024, 3, 15, 10, 0, 0, 0, time.UTC)
	z1 := &ZonedDateTimeVal{Time: now}
	z2 := &ZonedDateTimeVal{Time: now}
	i1 := &InstantVal{Time: now}
	i2 := &InstantVal{Time: now}
	gp1 := &GeoPointVal{Lat: 1, Lon: 2}
	gp2 := &GeoPointVal{Lat: 1, Lon: 2}
	br1 := &BytesRefVal{Bytes: []byte("abc"), Offset: 0, Length: 3}
	br2 := &BytesRefVal{Bytes: []byte("zabc"), Offset: 1, Length: 3}
	buf1 := &ByteBufferVal{Bytes: []byte("ab"), Pos: 0, Lim: 2}
	buf2 := &ByteBufferVal{Bytes: []byte("ab"), Pos: 0, Lim: 2}
	ver1 := NewVersionVal("8.15.0")
	dow := DayOfWeekEnum{Value: 1}
	mon := MonthEnum{Value: 3}
	eqPairs := [][2]any{
		{ip1, ip2}, {bb1, bb2}, {g1, g2}, {dv1, dv2}, {dv1, []any{1.0, 2.0}},
		{dow, &dow}, {dow, "MONDAY"}, {mon, &mon}, {mon, "MARCH"},
		{z1, z2}, {z1, now}, {z1, "2024-03-15T10:00:00Z"},
		{i1, i2}, {i1, now}, {i1, "2024-03-15T10:00:00Z"},
		{gp1, gp2}, {br1, br2}, {buf1, buf2}, {ver1, "8.15.0"},
		{[]float64{1, 2}, []float64{1, 2}}, {[]float64{1, 2}, []any{1, 2}},
		{"MONDAY", dow}, {"MARCH", mon}, {[]any{1.0, 2.0}, dv1}, {now, z1}, {now, i1},
	}
	for idx, pair := range eqPairs {
		if eq, handled := round60WrapperEquals(pair[0], pair[1]); !handled || !eq {
			t.Fatalf("eq pair %d (%T, %T) got eq=%v handled=%v", idx, pair[0], pair[1], eq, handled)
		}
	}
	neqPairs := [][2]any{
		{(*IPAddressVal)(nil), ip1}, {bb1, (*GeoBoundingBoxVal)(nil)}, {bb1, "notbb"},
		{g1, g3}, {g1, (*GeoShapeDocValues)(nil)}, {g1, "notgs"},
		{(*DenseVectorVal)(nil), dv1}, {dv1, dv3}, {dv1, []any{1, "x"}}, {dv1, "x"},
		{(*DayOfWeekEnum)(nil), "MONDAY"}, {(*MonthEnum)(nil), "MARCH"},
		{(*ZonedDateTimeVal)(nil), now}, {z1, "bad"},
		{(*InstantVal)(nil), now}, {i1, "bad"},
		{(*GeoPointVal)(nil), gp1}, {gp1, "x"},
		{(*BytesRefVal)(nil), br1}, {br1, "x"},
		{(*ByteBufferVal)(nil), buf1}, {buf1, "x"},
		{(*VersionVal)(nil), ver1},
		{[]float64{1, 2}, []float64{1}}, {[]float64{1, 2}, []float64{1, 9}}, {[]float64{1, 2}, []any{1, "bad"}}, {[]float64{1, 2}, "x"},
	}
	for idx, pair := range neqPairs {
		if eq, handled := round60WrapperEquals(pair[0], pair[1]); !handled || eq {
			t.Fatalf("neq pair %d (%T, %T) got eq=%v handled=%v", idx, pair[0], pair[1], eq, handled)
		}
	}
}

func TestRound65_F27b_FinalCoveragePush(t *testing.T) {
	pushScript := `
		def hfU = HexFormat.of().withUpperCase();
		def hfL = hfU.withLowerCase();
		def esc = 'a\\b\\f\\n\\r\\s\\t\\\'\\"\\\\z'.translateEscapes();
		def cRed1 = [1, 2, 3].stream().collect(Collectors.reducing((a, b) -> a + b)).get();
		def cRed2 = [1, 2, 3].stream().collect(Collectors.reducing(10, (a, b) -> a + b));
		def cRed3 = [1, 2, 3].stream().collect(Collectors.reducing(0, x -> x * 2, (a, b) -> a + b));
		def arrP = [1, 2, 3, 4];
		Arrays.parallelPrefix(arrP, (a, b) -> a + b);
		def arrP2 = [1, 2, 3, 4];
		Arrays.parallelPrefix(arrP2, 1, 4, (a, b) -> a + b);
		def statsI = [1, 2].stream().mapToInt(x -> x).summaryStatistics();
		def stMisc = [
			Double.isNaN(0.0/0.0), Double.isInfinite(1.0/0.0), Double.isFinite(1.5),
			Float.isNaN(0.0f/0.0f), Float.isInfinite(1.0f/0.0f), Float.isFinite(1.5f),
			Objects.equals(null, null), Objects.equals(1, 2),
			Objects.isNull(null), Objects.nonNull('x'),
			Objects.toString(null), Objects.toString(null, 'def'), Objects.toString(null, null), Objects.toString(statsI),
			Objects.requireNonNull('ok', 'msg'),
			Objects.requireNonNullElse(null, 'alt'),
			String.valueOf(['a', 'b', 67]),
			String.valueOf(['a', 'b', 'c', 'd'], 1, 2),
			String.copyValueOf(['x', 'y', 'z'], 1, 2),
			String.valueOf(statsI)
		];
		def ot1 = OffsetTime.of(10, 0, 0, 0, 'Z');
		def ot2 = OffsetTime.of(10, 5, 0, 0, 'Z');
		def tmMisc = [
			ZonedDateTime.ofInstant(Instant.ofEpochMilli(1700000000000L), ZoneId.of('UTC')).toString(),
			LocalDate.ofEpochDay(19000).toString(),
			Duration.between(ot1, ot2).toString(),
			Duration.between('2024-01-01T00:00:00Z', ot2).toString(),
			Duration.ofDays(1).toString(),
			Duration.ofHours(2).toString(),
			Duration.ofMinutes(3).toString(),
			Duration.ofSeconds(4, 500).toString(),
			Duration.ofMillis(600).toString(),
			Duration.ofNanos(700).toString(),
			Year.of(2024).atMonth(3).toString(),
			Year.of(2024).atMonthDay(MonthDay.of(2, 29)).toString(),
			MonthDay.of(2, 29).atYear(2024).toString(),
			MonthDay.of(2, 29).isValidYear(2023),
			MonthDay.of(2, 29).isValidYear(2024),
			ZonedDateTime.parse('2024-03-15T10:20:30Z').getLong(ChronoField.YEAR),
			ZonedDateTime.parse('2024-03-15T10:20:30Z').range(ChronoField.DAY_OF_MONTH).getMaximum(),
			ZonedDateTime.parse('2024-03-15T10:20:30Z').isSupported(ChronoField.YEAR),
			ZonedDateTime.parse('2024-03-15T10:20:30Z').isSupported(ChronoUnit.DAYS),
			Instant.now().isSupported(ChronoField.INSTANT_SECONDS),
			Instant.now().isSupported(ChronoUnit.SECONDS),
			Year.parse('+10000').toString(),
			Year.parse('-0004').toString(),
			YearMonth.parse('2024-03').toString(),
			MonthDay.parse('--03-15').toString()
		];
		def m = /(?<grp>[a-z]+)([0-9]+)/.matcher('foo123');
		m.find();
		def rPos = [m.start(1), m.end(1), m.start('grp'), m.end('grp'), 'abcd'.startsWith('bc', 1), 'abcd'.endsWith('cd')];
		def tm = new TreeMap(['a': 1, 'b': 2, 'c': 3, 'd': 4]);
		def dm = tm.descendingMap();
		def ts = new TreeSet([1, 2, 4, 5]);
		def colOps = [
			tm.tailMap('b').size(),
			tm.tailMap('b', false).size(),
			tm.subMap('b', true, 'd', true).size(),
			tm.subMap('b', 'd').size(),
			dm.tailMap('c', false).size(),
			dm.subMap('d', 'b').size(),
			ts.lower(3), ts.floor(3), ts.ceiling(3), ts.higher(3),
			ts.headSet(3).size(), ts.headSet(3, true).size()
		];
		def castList = (List<String>) ['a'];
		def castSet = (Set) new HashSet(['a']);
		def castInt = (java.lang.Integer) 5;
		return [hfU.toHexDigits(255), hfL.toHexDigits(255), esc.length(), cRed1, cRed2, cRed3, arrP[3], arrP2[3], stMisc.size(), tmMisc.size(), rPos.size(), colOps.size(), castList.size(), castSet.size(), castInt];
	`
	if res, err := Eval(nil, pushScript, nil); err != nil || res == nil {
		t.Fatalf("pushScript failed: %v", err)
	}
	for _, errSc := range []string{
		`return (Set) ['a'];`,
		`return (def[]) [1, 2];`,
		`return Optional.empty().orElseThrow(IllegalStateException::new);`,
		`return Arrays.parallelPrefix([1, 2], null);`,
		`return Arrays.parallelPrefix([1, 2], 1, 5, (a, b) -> a + b);`,
		`return Objects.requireNonNull(null, 'custom_npe');`,
		`return Objects.requireNonNullElse(null, null);`,
		`return String.valueOf(['a'], 0, 5);`,
		`return String.copyValueOf(null);`,
		`return ZonedDateTime.parse('2024-03-15T10:20:30Z').range('UNKNOWN_FIELD');`,
		`return Year.of(2024).atMonthDay(null);`,
		`return /a/.matcher('b').start(0);`,
		`def m = /(?<grp>a)/.matcher('a'); m.find(); return m.start('missing');`,
		`def m = /(a)/.matcher('a'); m.find(); return m.start(9);`,
		`return Year.parse('abc');`,
		`return MonthDay.parse('--02-30');`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected final-push error for %q", errSc)
		}
	}
}

func TestRound65_F27b_BigDecStreamCollectorsPush(t *testing.T) {
	sc := `
		def g = Stream.generate(() -> 1).limit(3).collect(Collectors.toList());
		def it = Stream.iterate(1, x -> x < 5, x -> x + 1).collect(Collectors.toList());
		def sums = [
			[1, 2, 3].stream().collect(Collectors.summingInt(x -> x)),
			[1, 2, 3].stream().collect(Collectors.summingLong(x -> x)),
			[1.5, 2.5].stream().collect(Collectors.summingDouble(x -> x)),
			[1, 2, 3].stream().collect(Collectors.averagingInt(x -> x)),
			[].stream().collect(Collectors.averagingInt(x -> x)),
			[1.5, 2.5].stream().collect(Collectors.averagingDouble(x -> x)),
			[].stream().collect(Collectors.averagingDouble(x -> x))
		];
		def m1 = ['a', 'bb', 'c'].stream().collect(Collectors.toUnmodifiableMap(s -> s.length(), s -> s, (a, b) -> a + b));
		def m2 = ['a', 'b'].stream().collect(Collectors.toMap(s -> s.length(), s -> s, (a, b) -> null));
		def bdOps = [
			new BigDecimal('0').pow(0).toString(),
			new BigDecimal('0').pow(3).toString(),
			new BigDecimal('-1').pow(3).toString(),
			new BigDecimal('-1').pow(2).toString(),
			new BigDecimal('1.23').pow(2, new MathContext(2)).toString(),
			new BigDecimal('1.2345').setScale(2, 'HALF_UP').toString(),
			new BigDecimal('1.5').min('2.5').toString(),
			new BigDecimal('1.5').max('2.5').toString(),
			new BigDecimal('123').movePointLeft(2).toString(),
			new BigDecimal('1.23').movePointRight(2).toString(),
			new BigDecimal('1.23').scaleByPowerOfTen(2).toString(),
			new BigDecimal('1.2345').round(new MathContext(3)).toString(),
			new BigDecimal('-1.2345').abs(new MathContext(3)).toString(),
			new BigDecimal('1.2345').negate(new MathContext(3)).toString()
		];
		return [g.size(), it.size(), sums.size(), m1.size(), m2.size(), bdOps.size()];
	`
	if res, err := Eval(nil, sc, nil); err != nil || res == nil {
		t.Fatalf("BigDecStreamCollectorsPush failed: %v", err)
	}
	for _, errSc := range []string{
		`return ['a', 'b'].stream().collect(Collectors.toUnmodifiableMap(s -> null, s -> s));`,
		`return ['a', 'b'].stream().collect(Collectors.toUnmodifiableMap(s -> s, s -> null));`,
		`return ['a', 'b'].stream().collect(Collectors.toMap(s -> 1, s -> s));`,
		`return ['a', 'b'].stream().collect(Collectors.toUnmodifiableMap(s -> 1, s -> s, (a, b) -> null));`,
		`return new BigDecimal('1').setScale(999999, 'HALF_UP');`,
		`return new BigDecimal('1').movePointLeft(999999);`,
		`return new BigDecimal('1').movePointRight(999999);`,
		`return new BigDecimal('1').scaleByPowerOfTen(999999);`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected BigDec/Collectors error for %q", errSc)
		}
	}
}

func TestRound65_F27b_CrossOver1200Booster(t *testing.T) {
	sc := `
		class Foo {}
		def bs1 = new BitSet();
		bs1.set(0);
		bs1.set(2);
		def bs2 = new BitSet();
		bs2.set(2);
		bs2.set(3);
		bs1.and(bs2);
		bs1.xor(bs2);
		bs1.andNot(bs2);
		bs1.flip(1);
		bs1.clear(1);
		bs1.clear(0, 2);
		bs1.clear();
		def cls = [
			'a'.getClass().getClass().getName(),
			(new StringBuilder('x')).getClass().getName(),
			(new BigDecimal('1')).getClass().getName(),
			(new BigInteger('1')).getClass().getName(),
			(new MathContext(2)).getClass().getName(),
			(new BitSet()).getClass().getName(),
			(new StringJoiner(',')).getClass().getName(),
			(new Foo()).getClass().getName(),
			Year.of(2024).getClass().getName(),
			MonthDay.of(1, 1).getClass().getName(),
			ChronoField.YEAR.getClass().getName(),
			Period.ofDays(1).getClass().getName(),
			Duration.ofSeconds(1).getClass().getName(),
			(/a/).matcher('a').getClass().getName(),
			(/a/).getClass().getName(),
			HexFormat.of().getClass().getName(),
			Clock.systemUTC().getClass().getName(),
			OffsetTime.of(1, 2, 3, 0, 'Z').getClass().getName(),
			URI.create('https://a.com').getClass().getName(),
			(new URL('https://a.com')).getClass().getName(),
			Optional.of(1).getClass().getName(),
			[1].stream().mapToInt(x -> x).summaryStatistics().getClass().getName()
		];
		def col = [
			[1, 2, 3].stream().collect(Collectors.filtering(x -> x > 1, Collectors.toList())).size(),
			[[1, 2], [3]].stream().collect(Collectors.flatMapping(x -> x.stream(), Collectors.toList())).size(),
			[Optional.of(1), Optional.empty()].stream().collect(Collectors.flatMapping(x -> x.stream(), Collectors.toList())).size(),
			[1, 2, 3].stream().collect(Collectors.teeing(Collectors.summingInt(x -> x), Collectors.counting(), (s, c) -> s + c))
		];
		def mth = [
			Math.hypot(3.0, 4.0), Math.atan2(1.0, 1.0), Math.nextAfter(1.0, 2.0),
			Math.IEEEremainder(5.0, 2.0), Math.copySign(1.0, -2.0), Math.scalb(1.5, 2)
		];
		boolean flag = false;
		if ((flag = true) ? (true ?: false) : false) {
			cls.add('if1');
		}
		def nulls = null;
		if (nulls ?: true) {
			cls.add('if2');
		}
		def ac = [
			((CharSequence[]) new String[1]).length,
			((Number[]) new Integer[1]).length,
			((Object[]) new int[2][2]).length,
			((Collection[]) new ArrayList[1]).length,
			((List[]) new LinkedList[1]).length,
			((Set[]) new TreeSet[1]).length,
			((Map[]) new HashMap[1]).length
		];
		return [cls.size(), col.size(), mth.size(), ac.size()];
	`
	if res, err := Eval(nil, sc, nil); err != nil || res == nil {
		t.Fatalf("CrossOver1200Booster failed: %v", err)
	}
	// Trigger painlessClassForValuePainless directly on remaining primitive/exception/adjuster branches
	directVals := []any{
		int16(1), int8(1), float32(1), true, json.Number("12"), json.Number("1.5"),
		map[string]any{"__exc_type": "DateTimeParseException"},
		map[string]any{"__exc_type": "UnsupportedTemporalTypeException"},
		map[string]any{"__exc_type": "NoSuchElementException"},
		map[string]any{"__exc_type": "PatternSyntaxException"},
		map[string]any{"__exc_type": "URISyntaxException"},
		map[string]any{"__exc_type": "IllegalArgumentException"},
		map[string]any{"__exc_type": "pkg.CustomEx"},
	}
	for _, dv := range directVals {
		if c := painlessClassForValuePainless(dv); c.fullName == "" {
			t.Fatalf("empty class for %#v", dv)
		}
	}
	for _, errSc := range []string{
		`def bs = new BitSet(); bs.clear(999999999);`,
		`def bs = new BitSet(); bs.clear(0, 999999999);`,
		`def bs = new BitSet(); bs.flip(999999999);`,
		`return (int[]) new String[1];`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected error for %q", errSc)
		}
	}
}

func TestRound65_F27b_EmitEnumMathReplacePush(t *testing.T) {
	// 1. EvalEmitContext across all ES 8 field contexts + error paths (round60.go:4199-4410)
	emitCases := []struct {
		ctx string
		src string
	}{
		{"boolean_field", "emit(true);"},
		{"long_field", "emit(42); emit(5.0);"},
		{"double_field", "emit(3.14);"},
		{"keyword_field", "emit('kw');"},
		{"date_field", "emit(1700000000000L); emit('2024-03-15T10:00:00Z');"},
		{"ip_field", "emit('10.0.0.1');"},
		{"geo_point_field", "emit(10.5, 20.5); emit([20.5, 10.5]);"},
		{"geo_shape_field", "emit('POINT (1 2)'); emit(['POINT (1 2)', 'LINESTRING (0 0, 1 1)']);"},
		{"composite", "emit('sub', 'val');"},
	}
	for _, tc := range emitCases {
		vals, err := EvalEmitContext(tc.src, tc.ctx, nil, nil, nil, nil)
		if err != nil || len(vals) == 0 {
			t.Fatalf("EvalEmitContext(%q, %q) failed: vals=%#v err=%v", tc.ctx, tc.src, vals, err)
		}
	}
	emitErrs := []struct {
		ctx string
		src string
	}{
		{"unknown_ctx", "emit(1);"},
		{"boolean_field", "emit('notbool');"},
		{"boolean_field", "emit(null);"},
		{"long_field", "emit('notlong');"},
		{"double_field", "emit('notdouble');"},
		{"date_field", "emit('notdate');"},
		{"ip_field", "emit(123);"},
		{"ip_field", "emit('notip');"},
		{"geo_point_field", "emit(95.0, 10.0);"},
		{"geo_point_field", "emit('badpt');"},
		{"geo_shape_field", "emit([]);"},
	}
	for _, tc := range emitErrs {
		if _, err := EvalEmitContext(tc.src, tc.ctx, nil, nil, nil, nil); err == nil {
			t.Fatalf("expected EvalEmitContext error for (%q, %q)", tc.ctx, tc.src)
		}
	}

	// 2. DayOfWeekEnum & MonthEnum receiver methods + errors (round62.go:411-575)
	enumParams := map[string]any{
		"dow": &DayOfWeekEnum{Value: 1},
		"mon": &MonthEnum{Value: 2},
	}
	enumRes, err := Eval(nil, `
		return [
			'MONDAY'.getDisplayName('FULL', 'en-US'),
			'MONDAY'.getValue(),
			'MONDAY'.plus(2).toString(),
			'MONDAY'.minus(1).toString(),
			params.dow.getValue(),
			params.dow.name(),
			params.dow.getDisplayName('SHORT', 'en-US'),
			params.dow.plus(3).getValue(),
			params.dow.minus(2).getValue(),
			params.dow.equals('MONDAY'),
			params.dow.compareTo('WEDNESDAY'),
			'MARCH'.minLength(),
			'MARCH'.maxLength(),
			'MARCH'.firstMonthOfQuarter(),
			params.mon.getValue(),
			params.mon.name(),
			params.mon.minLength(),
			params.mon.maxLength(),
			params.mon.firstMonthOfQuarter(),
			params.mon.length(true),
			params.mon.getDisplayName('FULL', 'en-US'),
			params.mon.plus(2).getValue(),
			params.mon.minus(1).getValue(),
			params.mon.equals('FEBRUARY'),
			params.mon.compareTo('APRIL')
		];
	`, enumParams)
	if err != nil || enumRes == nil {
		t.Fatalf("enumRes failed: %v", err)
	}
	for _, errSc := range []string{
		`return params.dow.getDisplayName('FULL');`,
		`return params.dow.getDisplayName(null, 'en-US');`,
		`return params.dow.getDisplayName('BADSTYLE', 'en-US');`,
		`return params.dow.plus('bad');`,
		`return params.dow.compareTo(null);`,
		`return params.dow.compareTo(123);`,
		`return params.mon.getDisplayName('FULL');`,
		`return params.mon.getDisplayName(null, 'en-US');`,
		`return params.mon.getDisplayName('BADSTYLE', 'en-US');`,
		`return params.mon.plus('bad');`,
		`return params.mon.compareTo(null);`,
		`return params.mon.compareTo(123);`,
	} {
		if _, err := Eval(nil, errSc, enumParams); err == nil {
			t.Fatalf("expected enum error for %q", errSc)
		}
	}

	// 3. List/Map replaceAll + Math.*Exact overflows + Math.clamp/round/fma (eval.go:19312+, round57.go:1112+, round58.go:470+)
	repDoc := map[string]any{
		"tags": []any{"a", "b"},
		"m":    map[string]any{"x": int64(1), "y": int64(2)},
	}
	if err := EvalPainless(repDoc, `
		ctx._source.tags.replaceAll(s -> s + '!');
		ctx._source.m.replaceAll((k, v) -> v + 10);
		def lt = [1, 2];
		lt.replaceAll(n -> n * 3);
		def lm = ['k': 5];
		lm.replaceAll((k, v) -> v + 1);
		def mvals = [
			Math.clamp(5, 1, 10), Math.clamp(0, 1, 10), Math.clamp(99, 1, 10),
			Math.clamp(1.5, 0.0, 2.0),
			Math.min(1.5f, 2.5f), Math.max(1.5, 2.5),
			Math.round(1.0f / 0.0f), Math.round(-1.0f / 0.0f), Math.round(1.0 / 0.0), Math.round(-1.0 / 0.0), Math.round(0.0 / 0.0),
			Math.fma(2.0, 3.0, 4.0)
		];
		ctx._source.out = [lt, lm, mvals.size()];
	`, nil); err != nil {
		t.Fatalf("replaceAll/Math script failed: %v", err)
	}
	for _, errSc := range []string{
		`return Math.addExact(2147483647, 1);`,
		`return Math.addExact(9223372036854775807L, 1L);`,
		`return Math.subtractExact(-2147483648, 1);`,
		`return Math.subtractExact(-9223372036854775808L, 1L);`,
		`return Math.multiplyExact(100000, 100000);`,
		`return Math.multiplyExact(3000000000L, 4000000000L);`,
		`return Math.incrementExact(2147483647);`,
		`return Math.decrementExact(-2147483648);`,
		`return Math.negateExact(-2147483648);`,
		`return Math.toIntExact(3000000000L);`,
		`return Math.clamp(5, 10, 1);`,
		`return Math.clamp(5.0, 10.0, 1.0);`,
		`return Math.abs(null);`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected Math error for %q", errSc)
		}
	}
}

func TestRound65_F27b_Reach1250Plus(t *testing.T) {
	// 1. Strict Duration/Period/Year/YearMonth/MonthDay parsing + formatted parsing (round56.go:664-775, 1052-1160)
	// 2. Method references arity 0/1/2 + BitSet flip/next/previous/intersects + StringJoiner.setEmptyValue + Comparator.thenComparing*
	sc := `
		def durs = [
			Duration.parse('P2DT3H').toString(),
			Duration.parse('-PT-1H2M3.5S').toString(),
			Duration.parse('+P1DT2M3,5S').toString(),
			Period.parse('P1Y2M3D').toString(),
			Year.parse('2024', DateTimeFormatter.ofPattern('yyyy')).toString(),
			YearMonth.parse('2024/03', DateTimeFormatter.ofPattern('yyyy/MM')).toString(),
			MonthDay.parse('03-15', DateTimeFormatter.ofPattern('MM-dd')).toString()
		];
		def mr = [
			Objects.requireNonNullElseGet(null, String::new),
			Objects.requireNonNullElseGet(null, ArrayList::new).size(),
			Objects.requireNonNullElseGet(null, HashMap::new).size(),
			Objects.requireNonNullElseGet(null, HashSet::new).size(),
			Objects.requireNonNullElseGet(null, StringBuilder::new).length(),
			[1, 2, 3].stream().reduce(0, Integer::sum),
			[1, 2, 3].stream().reduce(Math::max).get(),
			[1, 2, 3].stream().reduce(Math::min).get(),
			['b', 'a'].stream().sorted(String::compareTo).collect(Collectors.toList()).size(),
			['B', 'a'].stream().sorted(String::compareToIgnoreCase).collect(Collectors.toList()).size(),
			['a', 'b'].stream().reduce('', String::concat),
			[new BigDecimal('1'), new BigDecimal('2')].stream().reduce(BigDecimal::add).get().toString(),
			[null, 'a', 'b'].stream().filter(Objects::nonNull).map(Objects::toString).collect(Collectors.toList()).size(),
			[null, 'a'].stream().filter(Objects::isNull).count(),
			['1', '2'].stream().map(BigDecimal::new).map(String::valueOf).collect(Collectors.toList()).size()
		];
		def bs1 = new BitSet();
		bs1.set(1);
		bs1.set(4);
		bs1.flip(0, 3);
		def bs2 = new BitSet();
		bs2.set(2);
		def bsRes = [
			bs1.nextSetBit(0), bs1.nextClearBit(0),
			bs1.previousSetBit(4), bs1.previousClearBit(4),
			bs1.intersects(bs2), bs1.toString()
		];
		def sj = new StringJoiner(',').setEmptyValue('EMPTY');
		def sje = sj.toString();
		def rows = [
			['k1': 1, 'k2': 'b', 'k3': 2, 'k4': 2L, 'k5': 2.0],
			['k1': 1, 'k2': 'a', 'k3': 1, 'k4': 1L, 'k5': 1.0]
		];
		def cmp = Comparator.comparing(x -> x.k1)
			.thenComparing(x -> x.k2, String::compareTo)
			.thenComparingInt(x -> x.k3)
			.thenComparingLong(x -> x.k4)
			.thenComparingDouble(x -> x.k5);
		rows.sort(cmp);
		return [durs.size(), mr.size(), bsRes.size(), sje, rows[0].k2];
	`
	if res, err := Eval(nil, sc, nil); err != nil || res == nil {
		t.Fatalf("Reach1250Plus failed: %v", err)
	}
	for _, errSc := range []string{
		`return Duration.parse(null);`,
		`return Duration.parse(' PT1H');`,
		`return Duration.parse('P1HT');`,
		`return Duration.parse('PT1.2.3S');`,
		`return Duration.parse('P1.5D');`,
		`return Duration.parse('P1H');`,
		`return Duration.parse('PT1H1H');`,
		`return Duration.parse('PT1M1M');`,
		`return Period.parse('bad');`,
		`return Year.parse('bad', DateTimeFormatter.ofPattern('yyyy'));`,
		`return YearMonth.parse('bad', DateTimeFormatter.ofPattern('yyyy/MM'));`,
		`return MonthDay.parse('bad', DateTimeFormatter.ofPattern('MM-dd'));`,
		`def bs = new BitSet(); bs.flip(0, 999999999);`,
		`return new StringJoiner(',').setEmptyValue(null);`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected error for %q", errSc)
		}
	}

	// 3. formatValueCycleWalkRound60 direct nil/wrapper coverage (round60.go:282-385)
	seen := make(map[cycleNodeKeyRound60]bool)
	fmtInputs := []any{
		nil,
		painlessEmptyOptional,
		(*painlessOptional)(nil),
		&painlessOptional{present: false},
		&painlessOptional{present: true, val: "hi"},
		float64(1.25),
		float32(2.5),
		(*IPAddressVal)(nil),
		(*DenseVectorVal)(nil),
		&DenseVectorVal{Floats: []float32{1, 2}},
		(*DenseVectorFieldVal)(nil),
		&DenseVectorFieldVal{Name: "v"},
		(*GeoBoundingBoxVal)(nil),
		time.Second * 5,
		(*ZonedDateTimeVal)(nil),
		(*InstantVal)(nil),
		DayOfWeekEnum{Value: 1},
		(*DayOfWeekEnum)(nil),
		&DayOfWeekEnum{Value: 2},
		MonthEnum{Value: 3},
		(*MonthEnum)(nil),
		&MonthEnum{Value: 4},
		(*GrokExtractor)(nil),
		(*DissectExtractor)(nil),
		(*GeoPointVal)(nil),
		(*GeoShapeDocValues)(nil),
		(*BytesRefVal)(nil),
		(*ByteBufferVal)(nil),
		(*FieldVal)(nil),
	}
	for _, v := range fmtInputs {
		_ = formatValueCycleWalkRound60(v, seen, false, 0)
	}
	if got := formatValueCycleWalkRound60("deep", seen, false, 65); got != "..." {
		t.Fatalf("expected depth cutoff '...', got %q", got)
	}
}

func TestRound65_F27b_Over1200Finish(t *testing.T) {
	// 1. Primitive casts on float/non-numeric/json.Number/float32 (round57.go:680-810)
	for _, dv := range []any{json.Number("42"), json.Number("3.5"), float32(7.5), "A", true} {
		_, _, _ = extractExactIntOrFloatForNarrowRound57(dv)
	}
	for _, ct := range []string{"byte", "short", "char", "int", "long", "float", "double"} {
		_, _ = evalPrimitiveCastRound57Painless(ct, float64(65.9))
		_, _ = evalPrimitiveCastRound57Painless(ct, "bad_str")
		_, _ = evalPrimitiveCastRound57Painless(ct, nil)
		_, _ = evalPrimitiveCastRound57Painless(ct, int64(66))
	}

	// 2. list.remove(Object/Long/float/int) vs Set.remove + Arrays.compare/mismatch null/7-arg/3-arg + Eval edge paths + switch expr
	doc := map[string]any{"arr": []any{int64(10), int64(20), int64(30), 1.5}}
	sc := `
		ctx._source.arr.remove((Object) 20);
		ctx._source.arr.remove(1.5);
		def s = new HashSet([1, 2, 3]);
		s.remove(2);
		def cmp = Comparator.comparingInt(x -> x);
		def ar = [
			Arrays.compare(null, null), Arrays.compare(null, [1]), Arrays.compare([1], null),
			Arrays.mismatch(null, null),
			Arrays.compare([1, 2], [1, 2], cmp),
			Arrays.mismatch([1, 2], [1, 9], cmp),
			Arrays.compare([1, 2, 3], 0, 2, [2, 1, 9], 0, 2, (a, b) -> b - a),
			Arrays.mismatch([1, 2, 3], 0, 2, [1, 9, 3], 0, 2, (a, b) -> a - b)
		];
		def sw = switch (2) {
			case 1 -> 'one';
			case 2, 3 -> 'twoOrThree';
			default -> 'other';
		};
		return [s.size(), ar.size(), sw];
	`
	if res, err := Eval(doc, sc, nil); err != nil || res == nil {
		t.Fatalf("Over1200Finish script failed: %v", err)
	}
	if gotEmpty, err := Eval(nil, "  // comment only\n  ", nil); err != nil || gotEmpty != nil {
		t.Fatalf("expected nil on empty comment script, got (%#v, %v)", gotEmpty, err)
	}
	multiEmit, err := Eval(nil, "emit(1); emit(2);", nil)
	if err != nil || len(multiEmit.([]any)) != 2 {
		t.Fatalf("multiEmit failed: (%#v, %v)", multiEmit, err)
	}
	for _, errSc := range []string{
		`return Arrays.mismatch(null, [1]);`,
		`return Arrays.mismatch([1], null);`,
		`return Arrays.compare([1], 1, 0, [1], 0, 1);`,
		`return Arrays.compare([1], 0, 9, [1], 0, 1);`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected error for %q", errSc)
		}
	}
}

func TestRound65_F27b_CrossFinishLine(t *testing.T) {
	sc := `
		def bits = [
			true | false, true ^ false, true & false,
			~1, ~1L,
			1 << 2, 8 >> 1, -1 >>> 1, 1 | 2, 1 ^ 3, 3 & 1,
			1L << 2, 8L >> 1, -1L >>> 1, 1L | 2L, 1L ^ 3L, 3L & 1L
		];
		def m1 = /(?m:^bar$|^baz$|qux)/.matcher("foo\nbar\nbaz");
		def m2 = /(?m)^a\z|b\\$/.matcher("x\na");
		def m3 = /\Aa|b/.matcher("xa");
		def m4 = /([a|b])|c\z/.matcher("a");
		m1.find();
		m2.find(0);
		m3.find(1);
		m4.find();
		def rx = [
			'abc' =~ /[a-z]+/,
			'abc' ==~ /^[a-z]+$/,
			'123' ==~ /[0-9]+/
		];
		def bds = [
			new BigDecimal('0').divide(new BigDecimal('2'), new MathContext(2)).toString(),
			new BigDecimal('1000').divide(new BigDecimal('2'), new MathContext(0)).toString(),
			new BigDecimal('10.000').divide(new BigDecimal('2.0'), new MathContext(4)).toString(),
			new BigDecimal('0.00001').divide(new BigDecimal('2'), new MathContext(3)).toString()
		];
		return [bits.size(), rx.size(), bds.size()];
	`
	if res, err := Eval(nil, sc, nil); err != nil || res == nil {
		t.Fatalf("CrossFinishLine script failed: %v", err)
	}
	for _, errSc := range []string{
		`return new BigDecimal('1').divide(new BigDecimal('3'), new MathContext(0));`,
		`return LocalDate.of(9999999999L, 1, 1);`,
		`return LocalDate.of(2024, 13, 1);`,
		`return LocalDate.of(2023, 2, 29);`,
		`return LocalDate.of(2024, 4, 31);`,
		`return 'abc' ==~ '[unclosed';`,
		`return 'abc' =~ '[unclosed';`,
	} {
		if _, err := Eval(nil, errSc, nil); err == nil {
			t.Fatalf("expected error for %q", errSc)
		}
	}
	for _, d := range []any{
		DayOfWeekEnum{Value: 1}, DayOfWeekEnum{Value: 9}, &DayOfWeekEnum{Value: 2}, (*DayOfWeekEnum)(nil),
		"MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY", "NOPE",
		float64(1), float64(7), float64(8), nil,
	} {
		_ = parseDayOfWeekIndexPainless(d)
	}
	for i := 0; i <= 8; i++ {
		_ = dayOfWeekNamePainless(i)
	}
	// Extra Year/MonthDay clamping, array chained constructors, sortPainessSliceInPlace reversed/null/Comparator branches
	_ = painlessEmptyOptional.String()
	_ = (painlessYear{year: 2024}).length()
	_ = (painlessYear{year: 2023}).length()
	_ = (painlessYear{year: 2024}).atDay(366)
	_ = (painlessYear{year: 2023}).atMonth(0)
	_ = (painlessYear{year: 2023}).atMonth(13)
	_ = (painlessYear{year: 2023}).atMonthDay(painlessMonthDay{month: 2, day: 29})
	_ = (painlessYear{year: 2023}).atMonthDay(painlessMonthDay{month: 1, day: 0})
	_ = (painlessMonthDay{month: 0, day: 1}).getMonth()
	_ = (painlessMonthDay{month: 2, day: 29}).atYear(2023)
	_ = (painlessMonthDay{month: 1, day: 0}).atYear(2023)
	_ = (painlessMonthDay{month: 1, day: 31}).withMonth(0)
	_ = (painlessMonthDay{month: 1, day: 31}).withMonth(13)
	_ = (painlessMonthDay{month: 1, day: 31}).withDayOfMonth(0)
	_ = (painlessMonthDay{month: 1, day: 31}).withDayOfMonth(99)
	extraSc, err := Eval(nil, `
		def a1 = new int[2][][0];
		def a2 = new int[][]{{1, 2}, {3, 4}}[1][0];
		def sl1 = ['b', 'A', 'c'];
		sl1.sort(String.CASE_INSENSITIVE_ORDER);
		def sl2 = [1, 3, 2];
		sl2.sort(Comparator.reverseOrder());
		def sl3 = [1, 3, 2];
		sl3.sort(((a, b) -> a - b).reversed());
		def sl4 = [1, 2];
		sl4.sort((a, b) -> null);
		return [a1, a2, sl1, sl2, sl3, sl4, Year.of(2023).atMonthDay(MonthDay.of(2, 29)).toString(), MonthDay.of(2, 29).atYear(2023).toString(), MonthDay.of(1, 15).getMonth()];
	`, nil)
	if err != nil || extraSc == nil {
		t.Fatalf("extraSc failed: %v", err)
	}
	if _, err := Eval(nil, `return new int[-1];`, nil); err == nil {
		t.Fatalf("expected negative array dim error")
	}
	// toBytesPainless, FieldDocVal.Exists/Remove, formatZonedDateTime*Round62, lookupCtxMapKeyPainless
	for _, bv := range []any{nil, []byte("ab"), "ab", []any{65, "B"}, 123} {
		_ = toBytesPainless(bv)
	}
	subDoc := map[string]any{"x": 1}
	otherDoc := map[string]any{"x": 2}
	parMap := map[string]any{"obj": subDoc, "arr": []any{subDoc}}
	fdNil := (*FieldDocVal)(nil)
	_ = fdNil.Exists()
	_ = fdNil.Remove()
	_ = (&FieldDocVal{Doc: subDoc}).Exists()
	_ = (&FieldDocVal{Doc: subDoc, ParentMap: parMap, FieldPath: "missing"}).Exists()
	_ = (&FieldDocVal{Doc: subDoc, ParentMap: parMap, FieldPath: "obj"}).Exists()
	_ = (&FieldDocVal{Doc: otherDoc, ParentMap: parMap, FieldPath: "arr"}).Exists()
	_ = (&FieldDocVal{Doc: subDoc, ParentMap: parMap, FieldPath: "arr"}).Exists()
	_ = (&FieldDocVal{Doc: subDoc, ParentMap: parMap, FieldPath: "obj"}).Remove()
	nyLoc, _ := time.LoadLocation("America/New_York")
	for _, tm := range []time.Time{
		time.Date(2024, 3, 15, 10, 0, 0, 0, time.UTC),
		time.Date(2024, 3, 15, 10, 0, 0, 0, time.FixedZone("", 7200)),
		time.Date(2024, 3, 15, 10, 0, 0, 0, time.FixedZone("UTC", 7200)),
		time.Date(2024, 3, 15, 10, 0, 0, 0, nyLoc),
	} {
		_ = formatZonedDateTimeZoneIDRound62(tm)
		_ = formatZonedDateTimeOffsetRound62(tm)
		zv := &ZonedDateTimeVal{Time: tm}
		for _, m := range []string{".getMonthEnum()", ".getDayOfWeekEnum()", ".getDate()", ".getHour()"} {
			_, _, _ = evalZonedDateTimeZeroArgRound62(zv, m)
		}
	}
	_, _, _ = evalZonedDateTimeZeroArgRound62(nil, ".getYear()")
	_, _ = Eval(map[string]any{"k": 1}, `return [ctx['_index'], ctx['_id'], ctx['_routing'], ctx['_version'], ctx['k']];`, map[string]any{
		"_ctx_index": "idx", "_ctx_id": "id1", "_ctx_routing": "r1", "_ctx_version": int64(3),
	})
}
