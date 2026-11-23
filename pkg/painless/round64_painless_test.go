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
	"testing"
)

func TestRound64_P0_7_BigDecimalBigIntegerBitSetRepeatAndNaNGuards(t *testing.T) {
	t.Run("BigDecimal_HardBounds", func(t *testing.T) {
		oobScripts := []string{
			`return new BigDecimal('1e2147483647');`,
			`return new BigDecimal('1e10001');`,
			`return new BigDecimal('1e-10001');`,
			`return new BigDecimal('1.' + '0'.repeat(15000));`,
			`return new BigDecimal('9'.repeat(25000));`,
			`return BigDecimal.valueOf(1L, 10001);`,
			`return new BigDecimal('1').movePointLeft(10001);`,
			`return new BigDecimal('1').movePointRight(10001);`,
			`return new BigDecimal('1').scaleByPowerOfTen(10001);`,
			`return new BigDecimal('1').scaleByPowerOfTen(-10001);`,
			`return new BigDecimal('1').setScale(10001);`,
			`return new BigDecimal('1').setScale(-10001);`,
			`return new BigDecimal('2').pow(10001);`,
			`return new BigDecimal('1000').pow(10000);`,
			`return new BigDecimal('1e10000').multiply(new BigDecimal('1e10000'));`,
			`return new BigDecimal('1e-6000').add(new BigDecimal('1e6000'));`,
			`return new BigDecimal('1e-6000').subtract(new BigDecimal('1e6000'));`,
			`return new BigDecimal('1').divide(new BigDecimal('3'), 10001, RoundingMode.HALF_UP);`,
			`return new BigDecimal('1' + '0'.repeat(10000) + 'e10000').toBigInteger();`,
			`return new BigDecimal('1' + '0'.repeat(10000) + 'e10000').toBigIntegerExact();`,
		}
		for _, src := range oobScripts {
			if val, err := Eval(nil, src, nil); err == nil {
				t.Fatalf("expected bounds error for %q, got val=%#v", src, val)
			}
		}

		// Valid at exact boundary
		validScripts := []string{
			`return new BigDecimal('1e10000').scale();`,
			`return new BigDecimal('1e10000').toBigInteger().bitLength();`,
			`return new BigDecimal('1').movePointLeft(10000).toPlainString().length();`,
			`return new BigDecimal('1').setScale(10000).scale();`,
			`return new BigDecimal('0.1').pow(10000).scale();`,
		}
		for _, src := range validScripts {
			if _, err := Eval(nil, src, nil); err != nil {
				t.Fatalf("unexpected error at allowed boundary %q: %v", src, err)
			}
		}

		// Direct toPlainString / toPlainStringChecked on malformed scale must not OOM or panic
		badBD := &painlessBigDecimal{unscaled: big.NewInt(1), scale: 1000000000}
		if _, err := badBD.toPlainStringChecked(); err == nil {
			t.Fatal("expected error from toPlainStringChecked on out-of-bounds scale")
		}
		if s := badBD.toPlainString(); s == "" || len(s) > 64 {
			t.Fatalf("expected bounded fallback from toPlainString, got len=%d", len(s))
		}
	})

	t.Run("BigInteger_HardBounds", func(t *testing.T) {
		oobScripts := []string{
			`return BigInteger.valueOf(2).pow(65536);`,
			`return BigInteger.ONE.shiftLeft(65536);`,
			`return BigInteger.ONE.shiftLeft(1 << 30);`,
			`return BigInteger.ONE.shiftRight(-65536);`,
			`return BigInteger.ONE.shiftRight(100000);`,
			`return BigInteger.ZERO.setBit(65536);`,
			`return BigInteger.ONE.clearBit(65536);`,
			`return BigInteger.ZERO.flipBit(65536);`,
			`def a = BigInteger.ONE.shiftLeft(40000); return a.multiply(a);`,
		}
		for _, src := range oobScripts {
			if val, err := Eval(nil, src, nil); err == nil {
				t.Fatalf("expected BigInteger bounds error for %q, got %#v", src, val)
			}
		}

		v, err := Eval(nil, `return BigInteger.ONE.shiftLeft(65535).bitLength();`, nil)
		if err != nil || v != int64(65536) {
			t.Fatalf("expected 65536 at boundary, got (%#v, %v)", v, err)
		}
	})

	t.Run("BitSet_HardBoundsAndBudgetStep", func(t *testing.T) {
		oobScripts := []string{
			`BitSet bs = new BitSet(); bs.set(1 << 20); return bs.cardinality();`,
			`BitSet bs = new BitSet(); bs.set(0, (1 << 20) + 1); return bs.cardinality();`,
			`BitSet bs = new BitSet(); bs.flip(1 << 20); return bs.cardinality();`,
			`BitSet bs = new BitSet(); bs.flip(0, (1 << 20) + 1); return bs.cardinality();`,
			`return new BitSet((1 << 20) + 1).size();`,
			// Loop step budget enforcement inside setRange / flipRange
			`BitSet bs = new BitSet(); bs.set(0, 20000); return bs.cardinality();`,
			`BitSet bs = new BitSet(); bs.flip(0, 20000); return bs.cardinality();`,
		}
		for _, src := range oobScripts {
			if val, err := Eval(nil, src, nil); err == nil {
				t.Fatalf("expected BitSet error for %q, got %#v", src, val)
			}
		}

		// Valid max bit (1<<20 - 1) works cleanly
		v, err := Eval(nil, `BitSet bs = new BitSet(); bs.set((1 << 20) - 1); return bs.get((1 << 20) - 1);`, nil)
		if err != nil || v != true {
			t.Fatalf("expected BitSet bit (1<<20)-1 = true, got (%#v, %v)", v, err)
		}

		bs := newPainlessBitSet()
		if err := bs.ensureWord(maxBitSetBits / 64); err == nil {
			t.Fatal("expected ensureWord to fail at maxBitSetBits/64")
		}
	})

	t.Run("StringRepeatOverflowAndNaNCoercion", func(t *testing.T) {
		res, err := Eval(nil, `return 'abc'.repeat(1L << 62);`, nil)
		if err != nil {
			t.Fatalf("String.repeat(1<<62) failed: %v", err)
		}
		s, ok := res.(string)
		wantLen := ((MaxPainlessSliceItems * 64) / 3) * 3
		if !ok || len(s) != wantLen {
			t.Fatalf("expected clamped length %d, got ok=%v len=%d", wantLen, ok, len(s))
		}

		if out, err := evalStringRepeatRound58("xy", int64(1)<<62); err != nil || len(out.(string)) != ((MaxPainlessSliceItems*64)/2)*2 {
			t.Fatalf("evalStringRepeatRound58 overflow guard failed: (%v, %v)", err, out)
		}

		for _, badVal := range []any{math.NaN(), math.Inf(1), math.Inf(-1), float32(math.NaN()), float32(math.Inf(1))} {
			if _, err := coerceToBigIntegerRound63(badVal, "num"); err == nil {
				t.Fatalf("expected error from coerceToBigIntegerRound63(%v), got nil", badVal)
			}
		}
	})
}

func TestRound64_F14_GeoShapeDocValuesAndRuntime(t *testing.T) {
	// Concave/offset triangle polygon verifying shoelace centroid != bbox midpoint, plus quantized BBox & Mercator extent
	polyDoc := map[string]any{
		"geo_shape": map[string]any{
			"type": "polygon",
			"coordinates": []any{
				[]any{
					[]any{24.04525, 59.94125},
					[]any{24.04875, 59.94125},
					[]any{24.04875, 59.94275},
					[]any{24.04525, 59.94275},
					[]any{24.04525, 59.94125},
				},
			},
		},
	}
	// ES 8 70_script_doc_values.yml also tests an irregular polygon: let's test the exact BBox + Mercator math on that bbox!
	params := map[string]any{
		"__field_types": map[string]string{
			"geo_shape": "geo_shape",
		},
	}

	// BoundingBox topLeft / bottomRight & property/method accessors
	resTL, err := Eval(polyDoc, `GeoBoundingBox bbox = doc['geo_shape'].getBoundingBox(); return [bbox.topLeft().getLat(), bbox.topLeft().getLon(), bbox.bottomRight().getLat(), bbox.bottomRight().getLon(), bbox.minLat, bbox.maxLat, bbox.minLon, bbox.maxLon];`, params)
	if err != nil {
		t.Fatalf("getBoundingBox script failed: %v", err)
	}
	tlSlice := resTL.([]any)
	wantTLLat, wantTLLon := QuantizeLuceneGeoPoint(59.94275, 24.04525)
	wantBRLat, wantBRLon := QuantizeLuceneGeoPoint(59.94125, 24.04875)
	if tlSlice[0] != wantTLLat || tlSlice[1] != wantTLLon || tlSlice[2] != wantBRLat || tlSlice[3] != wantBRLon {
		t.Fatalf("unexpected quantized bbox: got %v, want [%v %v %v %v]", tlSlice[:4], wantTLLat, wantTLLon, wantBRLat, wantBRLon)
	}
	if tlSlice[4] != wantBRLat || tlSlice[5] != wantTLLat || tlSlice[6] != wantTLLon || tlSlice[7] != wantBRLon {
		t.Fatalf("unexpected bbox min/max fields: %v", tlSlice[4:])
	}

	// Direct topLeft / bottomRight, getCentroid, getLabelPosition, getDimensionalType, getMercatorWidth/Height, size, isEmpty
	resMethods, err := Eval(polyDoc, `
		def c = doc['geo_shape'].getCentroid();
		def lp = doc['geo_shape'].getLabelPosition();
		def tl = doc['geo_shape'].topLeft();
		def br = doc['geo_shape'].bottomRight();
		return [
			c.lat, c.lon,
			lp.lat, lp.lon,
			tl.getLat(), br.getLon(),
			doc['geo_shape'].getDimensionalType(),
			doc['geo_shape'].getMercatorWidth(),
			doc['geo_shape'].getMercatorHeight(),
			doc['geo_shape'].size(),
			doc['geo_shape'].isEmpty()
		];
	`, params)
	if err != nil {
		t.Fatalf("geo_shape methods failed: %v", err)
	}
	ms := resMethods.([]any)
	if ms[6] != int64(2) {
		t.Fatalf("expected getDimensionalType() == 2, got %#v", ms[6])
	}
	mw, okW := ms[7].(float64)
	mh, okH := ms[8].(float64)
	if !okW || !okH || math.Abs(mw-389.621702839) > 1e-6 || math.Abs(mh-333.37976841) > 1e-6 {
		t.Fatalf("unexpected Mercator width/height: (%v, %v)", ms[7], ms[8])
	}
	if ms[9] != int64(1) || ms[10] != false {
		t.Fatalf("expected size=1 isEmpty=false, got (%v, %v)", ms[9], ms[10])
	}

	// <unserializable> representation for doc['geo_shape'].get(0), field('geo_shape').get(null), $('geo_shape', null)
	for _, unserializableScript := range []string{
		`return doc['geo_shape'].get(0);`,
		`return field('geo_shape').get(null);`,
		`return $('geo_shape', null);`,
	} {
		uv, uErr := Eval(polyDoc, unserializableScript, params)
		if uErr != nil {
			t.Fatalf("%q failed: %v", unserializableScript, uErr)
		}
		jb, jErr := json.Marshal(uv)
		if jErr != nil {
			t.Fatalf("%q json.Marshal failed: %v", unserializableScript, jErr)
		}
		var decoded string
		if uErr := json.Unmarshal(jb, &decoded); uErr != nil || decoded != "<unserializable>" {
			t.Fatalf("%q json round-trip got (%q, %v), raw JSON=%s", unserializableScript, decoded, uErr, string(jb))
		}
		if FormatValueSafe(uv) != "<unserializable>" {
			t.Fatalf("%q FormatValueSafe got %q, want <unserializable>", unserializableScript, FormatValueSafe(uv))
		}
	}

	// All canonical shape types: POINT, LINESTRING, POLYGON, MULTIPOINT, MULTILINESTRING, MULTIPOLYGON, GEOMETRYCOLLECTION, ENVELOPE
	shapeCases := []struct {
		raw      any
		wantType string
		wantDim  int64
	}{
		{"POINT (10 20)", "POINT", 0},
		{"LINESTRING (0 0, 10 10)", "LINESTRING", 1},
		{"POLYGON ((0 0, 10 0, 10 10, 0 10, 0 0))", "POLYGON", 2},
		{"MULTIPOINT ((0 0), (5 5))", "MULTIPOINT", 0},
		{"MULTILINESTRING ((0 0, 1 1), (2 2, 3 3))", "MULTILINESTRING", 1},
		{"MULTIPOLYGON (((0 0, 2 0, 2 2, 0 2, 0 0)), ((3 3, 4 3, 4 4, 3 4, 3 3)))", "MULTIPOLYGON", 2},
		{"GEOMETRYCOLLECTION (POINT (1 1), LINESTRING (0 0, 2 2))", "GEOMETRYCOLLECTION", 1},
		{"ENVELOPE (-1, 1, 1, -1)", "ENVELOPE", 2},
	}
	for _, tc := range shapeCases {
		gs, err := ParseGeoShapeDocValues(tc.raw)
		if err != nil {
			t.Fatalf("ParseGeoShapeDocValues(%v) failed: %v", tc.raw, err)
		}
		if gs.GetShapeType() != tc.wantType {
			t.Fatalf("ShapeType got %q want %q", gs.GetShapeType(), tc.wantType)
		}
		if gs.GetDimensionalType() != tc.wantDim {
			t.Fatalf("%s DimensionalType got %d want %d", tc.wantType, gs.GetDimensionalType(), tc.wantDim)
		}
	}

	// Runtime geo_shape field emit context (130_geo_shape_runtime.yml)
	twoPolySource := map[string]any{
		"geometry": []any{
			map[string]any{
				"type": "polygon",
				"coordinates": []any{[]any{
					[]any{-1.0, -1.0}, []any{1.0, -1.0}, []any{1.0, 1.0}, []any{-1.0, 1.0}, []any{-1.0, -1.0},
				}},
			},
			map[string]any{
				"type": "polygon",
				"coordinates": []any{[]any{
					[]any{5.0, 5.0}, []any{6.0, 5.0}, []any{6.0, 6.0}, []any{5.0, 6.0}, []any{5.0, 5.0},
				}},
			},
		},
	}
	emitted, err := EvalEmitContext(`emit(params._source.geometry);`, "geo_shape", nil, twoPolySource, nil, nil)
	if err != nil {
		t.Fatalf("EvalEmitContext geo_shape failed: %v", err)
	}
	if len(emitted) != 2 {
		t.Fatalf("expected 2 emitted polygons, got %d: %#v", len(emitted), emitted)
	}
	rtDoc := map[string]any{"geometry": emitted}
	rtOut, err := EvalEmitContext(
		`GeoBoundingBox bbox = doc["geometry"].getBoundingBox(); emit("BBOX(" + bbox.topLeft().getLon() + "," + bbox.topLeft().getLat() + "," + bbox.bottomRight().getLon() + "," + bbox.bottomRight().getLat() + ")");`,
		"keyword",
		rtDoc,
		twoPolySource,
		nil,
		map[string]string{"geometry": "geo_shape"},
	)
	if err != nil || len(rtOut) != 1 {
		t.Fatalf("runtime geometry BBOX script failed: out=%v err=%v", rtOut, err)
	}
	sOut := rtOut[0].(string)
	wantRuntimeTLLat, wantRuntimeTLLon := QuantizeLuceneGeoPoint(6.0, -1.0)
	wantRuntimeBRLat, wantRuntimeBRLon := QuantizeLuceneGeoPoint(-1.0, 6.0)
	wantBBoxStr := "BBOX(" + FormatJavaFloat64(wantRuntimeTLLon) + "," + FormatJavaFloat64(wantRuntimeTLLat) + "," + FormatJavaFloat64(wantRuntimeBRLon) + "," + FormatJavaFloat64(wantRuntimeBRLat) + ")"
	if sOut != wantBBoxStr {
		t.Fatalf("unexpected quantized runtime BBOX string: %q, want %q", sOut, wantBBoxStr)
	}
}

func TestRound64_F21_JavaMapFormattingDoubleToStringAndMurmur3(t *testing.T) {
	// 1. Java {k=v} Map toString / String.valueOf / runtime_fields emission (top_hits.yml)
	src := map[string]any{
		"page": json.Number("1"),
		"text": "the quick brown fox",
	}
	emitted, err := EvalEmitContext(`emit(params['_source'].toString());`, "keyword", src, src, nil, nil)
	if err != nil || len(emitted) != 1 || emitted[0] != "{page=1, text=the quick brown fox}" {
		t.Fatalf("unexpected runtime map toString: out=%#v err=%v", emitted, err)
	}
	valStr, err := Eval(nil, `Map m = [page: 1, text: 'hello']; return [m.toString(), String.valueOf(m)];`, nil)
	if err != nil {
		t.Fatalf("Map string formatting failed: %v", err)
	}
	if FormatValueSafe(valStr) != "[{page=1, text=hello}, {page=1, text=hello}]" {
		t.Fatalf("unexpected Map toString/String.valueOf: %s", FormatValueSafe(valStr))
	}

	// 2. Painless float64 Double.toString formatting: "2.0" (aggregations/painless_execute.yml)
	maxVal, err := Eval(nil, `MovingFunctions.max(new double[] {1.0, 2.0, -1234})`, nil)
	if err != nil {
		t.Fatalf("MovingFunctions.max failed: %v", err)
	}
	if FormatValueSafe(maxVal) != "2.0" {
		t.Fatalf("expected FormatValueSafe(2.0) == \"2.0\", got %q", FormatValueSafe(maxVal))
	}
	dStr, err := Eval(nil, `return [Double.toString(2.0), String.valueOf(2.0)];`, nil)
	if err != nil {
		t.Fatalf("Double.toString/String.valueOf failed: %v", err)
	}
	if FormatValueSafe(dStr) != "[2.0, 2.0]" {
		t.Fatalf("expected [2.0, 2.0], got %s", FormatValueSafe(dStr))
	}

	// 3. Murmur3 field('foo.hash').get(10L) (mapper_murmur3/10_basic.yml)
	if h := ComputePainlessMurmur3Hash("foo"); h != -2129773440516405919 {
		t.Fatalf("ComputePainlessMurmur3Hash(\"foo\") = %d, want -2129773440516405919", h)
	}
	if h := ComputePainlessMurmur3Hash("a quick brown fox"); h != -3758089825743606896 {
		t.Fatalf("ComputePainlessMurmur3Hash(\"a quick brown fox\") = %d, want -3758089825743606896", h)
	}
	ftParams := map[string]any{
		"__field_types": map[string]string{
			"foo":      "text",
			"foo.hash": "murmur3",
		},
	}
	if got, err := Eval(map[string]any{"foo": "foo"}, `field('foo.hash').get(10L)`, ftParams); err != nil || got != int64(-2129773440516405919) {
		t.Fatalf("field('foo.hash').get(10L) for 'foo' got (%#v, %v)", got, err)
	}
	if got, err := Eval(map[string]any{"foo": "a quick brown fox"}, `field('foo.hash').get(10L)`, ftParams); err != nil || got != int64(-3758089825743606896) {
		t.Fatalf("field('foo.hash').get(10L) for 'a quick brown fox' got (%#v, %v)", got, err)
	}
	if got, err := Eval(map[string]any{}, `field('foo.hash').get(10L)`, ftParams); err != nil || got != int64(10) {
		t.Fatalf("field('foo.hash').get(10L) for missing field got (%#v, %v)", got, err)
	}
}
