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
	"errors"
	"math"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func evalRound57Return(t *testing.T, script string, params map[string]any) any {
	t.Helper()
	doc := map[string]any{}
	got, err := Eval(doc, script, params)
	if err != nil {
		t.Fatalf("Eval failed for script:\n%s\nerr: %v", script, err)
	}
	return got
}

func evalRound57Out(t *testing.T, script string, params map[string]any) any {
	t.Helper()
	doc := map[string]any{}
	if _, err := Eval(doc, script, params); err != nil {
		t.Fatalf("Eval failed for script:\n%s\nerr: %v", script, err)
	}
	return doc["out"]
}

func assertRound57EvalErr(t *testing.T, script string, params map[string]any, wantSubstr string) {
	t.Helper()
	doc := map[string]any{}
	got, err := Eval(doc, script, params)
	if err == nil {
		t.Fatalf("expected error containing %q for script:\n%s\ngot nil (ret=%#v, out=%#v)", wantSubstr, script, got, doc["out"])
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("expected error containing %q for script:\n%s\ngot: %v", wantSubstr, script, err)
	}
}

func TestRound57_F20_BitwiseShiftsAndExact64BitOps(t *testing.T) {
	t.Run("Int32ShiftMaskingAndUnsignedRightShift", func(t *testing.T) {
		got := evalRound57Out(t, `
			ctx._source.out = [
				'shl32': 1 << 32,
				'shl31': 1 << 31,
				'ushrNeg1': -1 >>> 1,
				'ushrNeg1Zero': -1 >>> 0,
				'shlNeg1': 1 << -1,
				'shrNeg8': -8 >> 1,
				'hexMaskShift': 0xffffffff << 1,
				'shortShift': ((short) 1) << 31,
				'byteShift': ((byte) 1) << 31,
				'charShift': ((char) 65) << 1,
				'intCallShift': Integer.parseInt('1') << 32
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"shl32":        int64(1),
			"shl31":        int64(-2147483648),
			"ushrNeg1":     int64(2147483647),
			"ushrNeg1Zero": int64(-1),
			"shlNeg1":      int64(-2147483648),
			"shrNeg8":      int64(-4),
			"hexMaskShift": int64(-2),
			"shortShift":   int64(-2147483648),
			"byteShift":    int64(-2147483648),
			"charShift":    int64(130),
			"intCallShift": int64(1),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}
	})

	t.Run("Long64ShiftMaskingAndExactBitwise", func(t *testing.T) {
		got := evalRound57Out(t, `
			long lv = 1L;
			ctx._source.out = [
				'lshl64': 1L << 64,
				'lshl63': 1L << 63,
				'lshl32': 1L << 32,
				'lushrNeg1': -1L >>> 1,
				'lushrNeg1Zero': -1L >>> 0,
				'lshlNeg1': 1L << -1,
				'castLongShift': ((long) 1) << 32,
				'varLongShift': lv << 40,
				'paramBigShift': params.big >> 1,
				'andExact': 9223372036854775807L & 1L,
				'orExact': 9223372036854775806L | 1L,
				'xorExact': 9223372036854775807L ^ 1L,
				'notLongExact': ~9223372036854775806L,
				'notIntZero': ~0,
				'notLongZero': ~0L,
				'boolAnd': true & false,
				'boolOr': true | false,
				'boolXor': true ^ true
			];
		`, map[string]any{"big": int64(8589934592)}).(map[string]any)

		want := map[string]any{
			"lshl64":        int64(1),
			"lshl63":        int64(math.MinInt64),
			"lshl32":        int64(4294967296),
			"lushrNeg1":     int64(math.MaxInt64),
			"lushrNeg1Zero": int64(-1),
			"lshlNeg1":      int64(math.MinInt64),
			"castLongShift": int64(4294967296),
			"varLongShift":  int64(1) << 40,
			"paramBigShift": int64(4294967296),
			"andExact":      int64(1),
			"orExact":       int64(9223372036854775807),
			"xorExact":      int64(9223372036854775806),
			"notLongExact":  int64(-9223372036854775807),
			"notIntZero":    int64(-1),
			"notLongZero":   int64(-1),
			"boolAnd":       false,
			"boolOr":        true,
			"boolXor":       false,
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}
	})

	t.Run("CompoundBitwiseAssignments", func(t *testing.T) {
		doc := map[string]any{"flags": int64(9223372036854775806)}
		_, err := Eval(doc, `
			int i = 1;
			i <<= 31;
			int u = -1;
			u >>>= 1;
			long l = 1L;
			l <<= 64;
			byte b = -1;
			b >>>= 24;
			ctx._source.flags |= 1L;
			ctx._source.out = [i, u, l, b, ctx._source.flags];
		`, nil)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		want := []any{int64(-2147483648), int64(2147483647), int64(1), int64(-1), int64(9223372036854775807)}
		if !reflect.DeepEqual(doc["out"], want) {
			t.Fatalf("got %#v, want %#v", doc["out"], want)
		}
	})

	t.Run("HelperTypeVariants", func(t *testing.T) {
		cases := []struct {
			in   any
			want int64
			ok   bool
		}{
			{int8(-5), -5, true},
			{int16(300), 300, true},
			{int32(-70000), -70000, true},
			{uint8(250), 250, true},
			{uint16(65000), 65000, true},
			{uint32(4000000000), 4000000000, true},
			{uint64(42), 42, true},
			{uint64(math.MaxUint64), -1, true},
			{struct{}{}, 0, false},
			{json.Number("9223372036854775806"), 9223372036854775806, true},
			{json.Number("12.0"), 12, true},
			{json.Number("12.5"), 0, false},
			{float32(8.0), 8, true},
			{float64(1.5), 0, false},
			{newPainlessBigInteger(big.NewInt(77)), 77, true},
			{newPainlessBigDecimal(big.NewInt(125), 1), 0, false},
			{"Z", int64('Z'), true},
			{"ZZ", 0, false},
		}
		for _, tc := range cases {
			got, ok := extractExactIntegralPainless(tc.in, true)
			if ok != tc.ok || (ok && got != tc.want) {
				t.Fatalf("extractExactIntegralPainless(%#v) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		}
		if iv, _, kind := extractExactIntOrFloatForNarrowRound57(newPainlessBigDecimal(big.NewInt(125), 1)); kind != 'i' || iv != 12 {
			t.Fatalf("extractExactIntOrFloatForNarrowRound57(12.5) = (%d, %c), want (12, 'i')", iv, kind)
		}
		if !isLongExprPainless("true ? 1L : 2", int64(1), nil) {
			t.Fatalf("expected ternary with long branch to promote to long")
		}
		if !isLongExprPainless("0x1_0000_0000L", int64(4294967296), nil) {
			t.Fatalf("expected hex L literal to be long")
		}
		if isLongExprPainless("0xffffffff", int64(0xffffffff), nil) {
			t.Fatalf("expected unsuffixed 32-bit hex literal to be int")
		}
	})
}

func TestRound57_F21_PrimitiveNarrowingCastsAndTypedLocalVars(t *testing.T) {
	t.Run("ExactIntegerAndJLS513FloatNarrowingCasts", func(t *testing.T) {
		got := evalRound57Out(t, `
			ctx._source.out = [
				'intFromLong': (int) 3000000000L,
				'longExact': (long) 9223372036854775806L,
				'byteWrap': (byte) 128,
				'shortWrap': (short) 32768,
				'charNeg1ToInt': (int) (char) -1,
				'intSatPos': (int) 5e9,
				'intSatNeg': (int) -5e9,
				'intNaN': (int) Double.NaN,
				'byteFrom5e9': (byte) 5e9,
				'byteFromNeg5e9': (byte) -5e9,
				'byteFromNaN': (byte) Double.NaN,
				'shortFrom5e9': (short) 5e9,
				'shortFromNeg5e9': (short) -5e9,
				'charFrom5e9': (int) (char) 5e9,
				'charFromNeg5e9': (int) (char) -5e9,
				'longSatPos': (long) 1e30,
				'longSatNeg': (long) -1e30,
				'longNaN': (long) Double.NaN,
				'floatRound': (float) 1.5,
				'numIntVal': (3000000000L).intValue(),
				'numLongVal': (9223372036854775806L).longValue(),
				'numByteVal': (5e9).byteValue(),
				'numShortVal': (5e9).shortValue(),
				'bdByteVal': new BigDecimal('129.9').byteValue(),
				'biShortVal': new BigInteger('32768').shortValue()
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"intFromLong":     int64(-1294967296),
			"longExact":       int64(9223372036854775806),
			"byteWrap":        int64(-128),
			"shortWrap":       int64(-32768),
			"charNeg1ToInt":   int64(65535),
			"intSatPos":       int64(math.MaxInt32),
			"intSatNeg":       int64(math.MinInt32),
			"intNaN":          int64(0),
			"byteFrom5e9":     int64(-1),
			"byteFromNeg5e9":  int64(0),
			"byteFromNaN":     int64(0),
			"shortFrom5e9":    int64(-1),
			"shortFromNeg5e9": int64(0),
			"charFrom5e9":     int64(65535),
			"charFromNeg5e9":  int64(0),
			"longSatPos":      int64(math.MaxInt64),
			"longSatNeg":      int64(math.MinInt64),
			"longNaN":         int64(0),
			"floatRound":      float64(1.5),
			"numIntVal":       int64(-1294967296),
			"numLongVal":      int64(9223372036854775806),
			"numByteVal":      int64(-1),
			"numShortVal":     int64(-1),
			"bdByteVal":       int64(-127),
			"biShortVal":      int64(-32768),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}
	})

	t.Run("TypedLocalVarOverflowCompoundAssignIncDecAndScoping", func(t *testing.T) {
		got := evalRound57Out(t, `
			byte b = 127;
			byte postB = b++;
			byte afterPostB = b;
			byte preB = ++b;

			short s = 32767;
			s++;

			int x = 2147483647;
			x++;

			char ch = (char) 65535;
			ch++;

			byte c = 100;
			c += 50;
			byte cf = 10;
			cf += 2.9;

			int minInt = -2147483648;
			minInt /= -1;

			long minLong = -9223372036854775808L;
			minLong /= -1L;

			byte dfltB;
			char dfltC;
			boolean dfltZ;

			// Block scope & for-loop scope cleanup: inner byte/int must not leak to sibling def/long
			{
				byte scoped = 127;
				scoped++;
			}
			def scoped = 3000000000L;

			for (int loopVar = 2147483647; loopVar == 2147483647; loopVar++) {
				break;
			}
			def loopVar = 3000000000L;

			ctx._source.out = [
				'postB': postB,
				'afterPostB': afterPostB,
				'preB': preB,
				's': s,
				'x': x,
				'chCode': (int) ch,
				'c': c,
				'cf': cf,
				'minInt': minInt,
				'minLong': minLong,
				'dfltB': dfltB,
				'dfltCCode': (int) dfltC,
				'dfltZ': dfltZ,
				'scopedAfter': scoped,
				'loopVarAfter': loopVar
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"postB":        int64(127),
			"afterPostB":   int64(-128),
			"preB":         int64(-127),
			"s":            int64(-32768),
			"x":            int64(-2147483648),
			"chCode":       int64(0),
			"c":            int64(-106),
			"cf":           int64(12),
			"minInt":       int64(-2147483648),
			"minLong":      int64(math.MinInt64),
			"dfltB":        int64(0),
			"dfltCCode":    int64(0),
			"dfltZ":        false,
			"scopedAfter":  int64(3000000000),
			"loopVarAfter": int64(3000000000),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}

		assertRound57EvalErr(t, `int x = 10; x /= 0; return x;`, nil, "ArithmeticException")
	})

	t.Run("TypedUserClassFieldsOverflow", func(t *testing.T) {
		got := evalRound57Return(t, `
			class Counter {
				byte b = 127;
				int i = 2147483647;
				int bump() {
					b++;
					i += 1;
					return b + i;
				}
			}
			Counter c = new Counter();
			int r = c.bump();
			c.b = 200;
			return [r, c.b, c.i];
		`, nil)
		want := []any{int64(2147483520), int64(-56), int64(-2147483648)}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})
}

func TestRound57_F22_MathAndStrictMathExactAndFloorDivMod(t *testing.T) {
	t.Run("IntAndLongExactSuccessPaths", func(t *testing.T) {
		got := evalRound57Out(t, `
			ctx._source.out = [
				'addInt': Math.addExact(100, 200),
				'addLong': Math.addExact(2147483647L, 1L),
				'subInt': StrictMath.subtractExact(10, 25),
				'subLong': StrictMath.subtractExact(-2147483648L, 1L),
				'mulInt': Math.multiplyExact(1000, 1000),
				'mulLong': StrictMath.multiplyExact(100000L, 100000L),
				'incInt': Math.incrementExact(41),
				'incLong': StrictMath.incrementExact(2147483647L),
				'decInt': Math.decrementExact(-41),
				'decLong': StrictMath.decrementExact(-2147483648L),
				'negInt': Math.negateExact(2147483647),
				'negLong': StrictMath.negateExact(-2147483648L),
				'toInt': Math.toIntExact(2147483647L)
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"addInt":  int64(300),
			"addLong": int64(2147483648),
			"subInt":  int64(-15),
			"subLong": int64(-2147483649),
			"mulInt":  int64(1000000),
			"mulLong": int64(10000000000),
			"incInt":  int64(42),
			"incLong": int64(2147483648),
			"decInt":  int64(-42),
			"decLong": int64(-2147483649),
			"negInt":  int64(-2147483647),
			"negLong": int64(2147483648),
			"toInt":   int64(2147483647),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}
	})

	t.Run("IntVsLongExactOverflowExceptions", func(t *testing.T) {
		intOverflows := []string{
			`return Math.addExact(2147483647, 1);`,
			`return StrictMath.subtractExact(-2147483648, 1);`,
			`return Math.multiplyExact(100000, 100000);`,
			`return StrictMath.incrementExact(2147483647);`,
			`return Math.decrementExact(-2147483648);`,
			`return StrictMath.negateExact(-2147483648);`,
			`return Math.toIntExact(2147483648L);`,
		}
		for _, s := range intOverflows {
			assertRound57EvalErr(t, s, nil, "integer overflow")
		}

		longOverflows := []string{
			`return Math.addExact(9223372036854775807L, 1L);`,
			`return StrictMath.subtractExact(-9223372036854775808L, 1L);`,
			`return Math.multiplyExact(9223372036854775807L, 2L);`,
			`return StrictMath.incrementExact(9223372036854775807L);`,
			`return Math.decrementExact(-9223372036854775808L);`,
			`return StrictMath.negateExact(-9223372036854775808L);`,
		}
		for _, s := range longOverflows {
			assertRound57EvalErr(t, s, nil, "long overflow")
		}
	})

	t.Run("FloorDivAndFloorModExactAndEdgeCases", func(t *testing.T) {
		got := evalRound57Out(t, `
			ctx._source.out = [
				'fdNegPos': Math.floorDiv(-7, 3),
				'fmNegPos': Math.floorMod(-7, 3),
				'fdPosNeg': StrictMath.floorDiv(7, -3),
				'fmPosNeg': StrictMath.floorMod(7, -3),
				'fdMinInt': Math.floorDiv(-2147483648, -1),
				'fmMinInt': Math.floorMod(-2147483648, -1),
				'fdMinLong': Math.floorDiv(-9223372036854775808L, -1L),
				'fmMinLong': Math.floorMod(-9223372036854775808L, -1L),
				'fmLargeLong': Math.floorMod(9223372036854775806L, 10L),
				'fdLongInt': StrictMath.floorDiv(-9223372036854775807L, 2)
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"fdNegPos":    int64(-3),
			"fmNegPos":    int64(2),
			"fdPosNeg":    int64(-3),
			"fmPosNeg":    int64(-2),
			"fdMinInt":    int64(-2147483648),
			"fmMinInt":    int64(0),
			"fdMinLong":   int64(math.MinInt64),
			"fmMinLong":   int64(0),
			"fmLargeLong": int64(6),
			"fdLongInt":   int64(-4611686018427387904),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}

		assertRound57EvalErr(t, `return Math.floorDiv(10, 0);`, nil, "/ by zero")
		assertRound57EvalErr(t, `return StrictMath.floorMod(10L, 0L);`, nil, "/ by zero")
		assertRound57EvalErr(t, `return Math.addExact(Integer.parseInt("bad"), 1);`, nil, "NumberFormatException")
	})
}

func TestRound57_F23_BigDecimalExactDivideAndScaleStrictEquals(t *testing.T) {
	t.Run("ExactDivideAndMathContextUnlimited", func(t *testing.T) {
		got := evalRound57Out(t, `
			BigDecimal q1 = new BigDecimal("1").divide(new BigDecimal("8"));
			BigDecimal q2 = new BigDecimal("1.0000").divide(new BigDecimal("2"));
			BigDecimal q3 = new BigDecimal("100").divide(new BigDecimal("20"));
			BigDecimal q4 = new BigDecimal("0.00").divide(new BigDecimal("2"));
			BigDecimal q5 = new BigDecimal("1").divide(new BigDecimal("8"), MathContext.UNLIMITED);
			BigDecimal q6 = new BigDecimal("-3").divide(new BigDecimal("80"));
			ctx._source.out = [
				'q1': q1.toPlainString(), 'q1Scale': q1.scale(),
				'q2': q2.toPlainString(), 'q2Scale': q2.scale(),
				'q3': q3.toPlainString(), 'q3Scale': q3.scale(),
				'q4': q4.toPlainString(), 'q4Scale': q4.scale(),
				'q5': q5.toPlainString(), 'q5Scale': q5.scale(),
				'q6': q6.toPlainString(), 'q6Scale': q6.scale()
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"q1": "0.125", "q1Scale": int64(3),
			"q2": "0.5000", "q2Scale": int64(4),
			"q3": "5", "q3Scale": int64(0),
			"q4": "0.00", "q4Scale": int64(2),
			"q5": "0.125", "q5Scale": int64(3),
			"q6": "-0.0375", "q6Scale": int64(4),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}

		assertRound57EvalErr(t, `return new BigDecimal("1").divide(new BigDecimal("3"));`, nil, "Non-terminating decimal expansion")
		assertRound57EvalErr(t, `return new BigDecimal("1").divide(new BigDecimal("3"), MathContext.UNLIMITED);`, nil, "Non-terminating decimal expansion")
	})

	t.Run("CatchableArithmeticExceptionAcrossBigDecimalAndBigInteger", func(t *testing.T) {
		got := evalRound57Return(t, `
			int caught = 0;
			try { new BigDecimal("1").divide(BigDecimal.ZERO); } catch (ArithmeticException e) { caught++; }
			try { new BigDecimal("1").divide(new BigDecimal("3")); } catch (ArithmeticException e) { caught++; }
			try { new BigDecimal("2").pow(-1); } catch (ArithmeticException e) { caught++; }
			try { BigInteger.TEN.divide(BigInteger.ZERO); } catch (ArithmeticException e) { caught++; }
			try { BigInteger.TEN.remainder(BigInteger.ZERO); } catch (ArithmeticException e) { caught++; }
			try { BigInteger.TEN.mod(BigInteger.ZERO); } catch (ArithmeticException e) { caught++; }
			try { BigInteger.valueOf(4).modInverse(BigInteger.valueOf(6)); } catch (ArithmeticException e) { caught++; }
			try { BigInteger.TWO.pow(-1); } catch (ArithmeticException e) { caught++; }
			try { BigInteger.ONE.testBit(-1); } catch (ArithmeticException e) { caught++; }
			return caught;
		`, nil)
		if got != int64(9) {
			t.Fatalf("expected all 9 ArithmeticExceptions to be caught, got %#v", got)
		}
	})

	t.Run("ScaleStrictBigDecimalEqualsAndCollectionParity", func(t *testing.T) {
		got := evalRound57Out(t, `
			BigDecimal a = new BigDecimal("1.0");
			BigDecimal b = new BigDecimal("1.00");
			BigDecimal a2 = new BigDecimal("1.0");

			List list = [a];
			Set set = new HashSet([a, b]);
			Map map = new HashMap();
			map.put(a, "oneDP");
			map.put(b, "twoDP");

			Map imm = Map.of(a, 10, b, 20);
			Set immSet = Set.of(a, b);

			ctx._source.out = [
				'opEq': a == b,
				'dotEqDiffScale': a.equals(b),
				'dotEqSameScale': a.equals(a2),
				'objEqDiff': Objects.equals(a, b),
				'objEqSame': Objects.equals(a, a2),
				'arrEqDiff': Arrays.equals([a], [b]),
				'arrDeepEqDiff': Arrays.deepEquals([[a]], [[b]]),
				'arrDeepEqSame': Arrays.deepEquals([[a]], [[a2]]),
				'listContainsB': list.contains(b),
				'listContainsA2': list.contains(a2),
				'listIndexOfB': list.indexOf(b),
				'listIndexOfA2': list.indexOf(a2),
				'setSize': set.size(),
				'mapSize': map.size(),
				'mapGetA': map.get(a2),
				'mapGetB': map.get(b),
				'immSize': imm.size(),
				'immSetSize': immSet.size(),
				'freqDiff': Collections.frequency(list, b),
				'freqSame': Collections.frequency(list, a2),
				'bdVsIntEq': new BigDecimal("1").equals(1),
				'biVsIntEq': new BigInteger("5").equals(5),
				'intOpDoubleEq': 1 == 1.0,
				'optEqDiff': Optional.of(a).equals(Optional.of(b)),
				'optEqSame': Optional.of(a).equals(Optional.of(a2))
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"opEq":           true,
			"dotEqDiffScale": false,
			"dotEqSameScale": true,
			"objEqDiff":      false,
			"objEqSame":      true,
			"arrEqDiff":      false,
			"arrDeepEqDiff":  false,
			"arrDeepEqSame":  true,
			"listContainsB":  false,
			"listContainsA2": true,
			"listIndexOfB":   int64(-1),
			"listIndexOfA2":  int64(0),
			"setSize":        int64(2),
			"mapSize":        int64(2),
			"mapGetA":        "oneDP",
			"mapGetB":        "twoDP",
			"immSize":        int64(2),
			"immSetSize":     int64(2),
			"freqDiff":       int64(0),
			"freqSame":       int64(1),
			"bdVsIntEq":      false,
			"biVsIntEq":      false,
			"intOpDoubleEq":  true,
			"optEqDiff":      false,
			"optEqSame":      true,
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}
	})
}

func TestRound57_F24_RegexSplitAndReplacementSemantics(t *testing.T) {
	t.Run("Java8StringAndPatternSplit", func(t *testing.T) {
		got := evalRound57Out(t, `
			Pattern pComma = Pattern.compile(",");
			Pattern pEmpty = Pattern.compile("");
			ctx._source.out = [
				'emptyOnEmpty': "".split(""),
				'abcEmpty0': "abc".split(""),
				'abcEmptyNeg1': "abc".split("", -1),
				'abcEmpty2': "abc".split("", 2),
				'dotRegex': "a.b".split("."),
				'dotEscaped': "a.b".split("\\."),
				'pipeRegex': "a|b".split("|"),
				'trailingComma0': "a,b,,".split(","),
				'trailingCommaNeg1': "a,b,,".split(",", -1),
				'allColons0': ":::".split(":"),
				'emptyInputComma': "".split(","),
				'slashRegexSplit': /,/.split("a,b,,"),
				'patComma0': pComma.split("a,b,,"),
				'patEmptyNeg1': pEmpty.split("abc", -1)
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"emptyOnEmpty":      []any{""},
			"abcEmpty0":         []any{"a", "b", "c"},
			"abcEmptyNeg1":      []any{"a", "b", "c", ""},
			"abcEmpty2":         []any{"a", "bc"},
			"dotRegex":          []any{},
			"dotEscaped":        []any{"a", "b"},
			"pipeRegex":         []any{"a", "|", "b"},
			"trailingComma0":    []any{"a", "b"},
			"trailingCommaNeg1": []any{"a", "b", "", ""},
			"allColons0":        []any{},
			"emptyInputComma":   []any{""},
			"slashRegexSplit":   []any{"a", "b"},
			"patComma0":         []any{"a", "b"},
			"patEmptyNeg1":      []any{"a", "b", "c", ""},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}

		assertRound57EvalErr(t, `return "abc".split("[");`, nil, "PatternSyntaxException")
		assertRound57EvalErr(t, `return Pattern.compile("[");`, nil, "PatternSyntaxException")
		assertRound57EvalErr(t, `return "abc".split(null);`, nil, "NullPointerException")
		assertRound57EvalErr(t, `return Pattern.compile(",").split(null);`, nil, "NullPointerException")
	})

	t.Run("ReplaceAllReplaceFirstAndAppendReplacementGroupAndEscapeRules", func(t *testing.T) {
		got := evalRound57Out(t, `
			String s1 = "foo123bar".replaceAll("([a-z]+)(\\d+)", "$2-$1-\\$99-\\\\");
			String s2 = "foo123".replaceFirst("([a-z]+)", "$10");
			String s3 = "2026-11".replaceAll("(?<yr>\\d{4})-(?<mo>\\d{2})", "${mo}/${yr}");

			Matcher m = Pattern.compile("(\\w+)").matcher("hi there");
			StringBuilder sb = new StringBuilder();
			while (m.find()) {
				m.appendReplacement(sb, "[$1:\\$]");
			}
			m.appendTail(sb);

			Matcher m2 = Pattern.compile("(\\d+)").matcher("v=42");
			String lam = m2.replaceAll(mr -> "<" + mr.group(1) + ">");

			ctx._source.out = [
				's1': s1,
				's2': s2,
				's3': s3,
				'sb': sb.toString(),
				'lam': lam
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"s1":  `123-foo-$99-\bar`,
			"s2":  "foo0123",
			"s3":  "11/2026",
			"sb":  "[hi:$] [there:$]",
			"lam": "v=<42>",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}

		assertRound57EvalErr(t, `return "abc".replaceAll("[", "x");`, nil, "PatternSyntaxException")
		assertRound57EvalErr(t, `return "abc".replaceAll("(a)", "\\");`, nil, "IllegalArgumentException")
		assertRound57EvalErr(t, `return "abc".replaceAll("(a)", "$");`, nil, "IllegalArgumentException")
		assertRound57EvalErr(t, `return "abc".replaceAll("(a)", "$x");`, nil, "IllegalArgumentException")
		assertRound57EvalErr(t, `return "abc".replaceAll("(a)", "${unclosed");`, nil, "IllegalArgumentException")
		assertRound57EvalErr(t, `return "abc".replaceAll("(a)", "${nope}");`, nil, "IllegalArgumentException")
		assertRound57EvalErr(t, `return "abc".replaceAll("(a)", "$2");`, nil, "IndexOutOfBoundsException")

		// appendReplacement must not partially mutate StringBuilder when replacement expansion throws
		unchanged := evalRound57Return(t, `
			Matcher m = Pattern.compile("(b)").matcher("abc");
			m.find();
			StringBuilder sb = new StringBuilder("init:");
			try {
				m.appendReplacement(sb, "$5");
			} catch (IndexOutOfBoundsException e) {
				return sb.toString();
			}
			return "bad";
		`, nil)
		if unchanged != "init:" {
			t.Fatalf("expected StringBuilder to remain 'init:', got %#v", unchanged)
		}
	})
}

func TestRound57_F25_TryCatchFinallyHierarchyAbruptFlowAndClassInit(t *testing.T) {
	t.Run("StrictJavaExceptionHierarchyAndUserExceptions", func(t *testing.T) {
		got := evalRound57Out(t, `
			class AppException extends RuntimeException {
				AppException(String m) { super(m); }
			}
			class DomainException extends AppException {
				DomainException(String m) { super(m); }
			}

			String r1 = "none";
			try {
				Integer.parseInt("not-a-number");
			} catch (NullPointerException e) {
				r1 = "wrong-npe";
			} catch (IllegalArgumentException e) {
				r1 = "iae:" + e.type;
			}

			// Error msg containing "NullPointerException" must NOT match catch (NullPointerException)
			String r2 = "none";
			try {
				throw new IllegalStateException("mentions NullPointerException in message");
			} catch (NullPointerException e) {
				r2 = "wrong-msg-match";
			} catch (IllegalStateException e) {
				r2 = "ise";
			}

			String r3 = "none";
			try {
				throw new DomainException("boom");
			} catch (NullPointerException | ArithmeticException e) {
				r3 = "wrong-multi";
			} catch (AppException e) {
				r3 = "app:" + e.message;
			}

			ctx._source.out = [r1, r2, r3];
		`, nil)

		want := []any{"iae:NumberFormatException", "ise", "app:boom"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})

	t.Run("AbruptReturnBreakContinueAndFinallySemantics", func(t *testing.T) {
		got := evalRound57Out(t, `
			int f(List log) {
				try {
					log.add("try");
					return 42;
				} catch (Exception e) {
					log.add("catch-must-not-run");
					return -1;
				} finally {
					log.add("finally");
				}
			}

			int fOverride() {
				try {
					return 1;
				} finally {
					return 99;
				}
			}

			List log = [];
			int v1 = f(log);
			int v2 = fOverride();

			int loopFin = 0;
			for (int i = 0; i < 3; i++) {
				try {
					if (i == 1) {
						break;
					}
				} catch (Exception e) {
					loopFin = -100;
				} finally {
					loopFin += 10;
				}
			}

			// finally break overrides try return
			int fBreakOverride() {
				while (true) {
					try {
						return 777;
					} finally {
						break;
					}
				}
				return 55;
			}

			ctx._source.out = [
				'v1': v1,
				'log': log,
				'v2': v2,
				'loopFin': loopFin,
				'breakOverride': fBreakOverride()
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"v1":            int64(42),
			"log":           []any{"try", "finally"},
			"v2":            int64(99),
			"loopFin":       int64(20),
			"breakOverride": int64(55),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}
	})

	t.Run("ChainedReceiverErrorNullUserObjectNPEAndPostSuperFieldInit", func(t *testing.T) {
		got := evalRound57Out(t, `
			class Base {
				int observedDuringSuper = -1;
				Base() {
					hook();
				}
				void hook() {}
			}
			class Sub extends Base {
				int fieldWithInit = 42;
				Sub() {
					super();
				}
				Sub(int custom) {
					this();
					fieldWithInit = custom;
				}
				void hook() {
					observedDuringSuper = fieldWithInit;
				}
				Sub boom() {
					throw new IllegalStateException("boom-in-chain");
				}
				Sub nilSub() {
					return null;
				}
				int val() {
					return fieldWithInit;
				}
			}

			Sub s1 = new Sub();
			Sub s2 = new Sub(99);

			String chainErr = "none";
			try {
				s1.boom().val();
			} catch (IllegalStateException e) {
				chainErr = e.message;
			}

			String nullMethodErr = "none";
			try {
				Sub n = null;
				n.val();
			} catch (NullPointerException e) {
				nullMethodErr = "npe-var";
			}

			String nullChainErr = "none";
			try {
				s1.nilSub().val();
			} catch (NullPointerException e) {
				nullChainErr = "npe-chain";
			}

			Sub safeNil = null;
			def safeVal = safeNil?.val();

			ctx._source.out = [
				'duringSuper': s1.observedDuringSuper,
				'afterSuper': s1.fieldWithInit,
				'delegatedDuringSuper': s2.observedDuringSuper,
				'delegatedFinal': s2.fieldWithInit,
				'chainErr': chainErr,
				'nullMethodErr': nullMethodErr,
				'nullChainErr': nullChainErr,
				'safeVal': safeVal
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"duringSuper":          int64(0),
			"afterSuper":           int64(42),
			"delegatedDuringSuper": int64(0),
			"delegatedFinal":       int64(99),
			"chainErr":             "boom-in-chain",
			"nullMethodErr":        "npe-var",
			"nullChainErr":         "npe-chain",
			"safeVal":              nil,
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}
	})
}

func TestRound57_F26_MapComputeMergeAndGroupingByContracts(t *testing.T) {
	t.Run("MapComputeAndMergeNPEAndNullKeyTypedKeyContracts", func(t *testing.T) {
		assertRound57EvalErr(t, `Map m = ['a': 1]; return m.computeIfAbsent('a', null);`, nil, "NullPointerException")
		assertRound57EvalErr(t, `Map m = [:]; return m.computeIfPresent('a', null);`, nil, "NullPointerException")
		assertRound57EvalErr(t, `Map m = [:]; return m.compute('a', null);`, nil, "NullPointerException")
		assertRound57EvalErr(t, `Map m = [:]; return m.merge('a', null, (x, y) -> x);`, nil, "NullPointerException")
		assertRound57EvalErr(t, `Map m = [:]; return m.merge('a', 1, null);`, nil, "NullPointerException")

		got := evalRound57Out(t, `
			Map m = new HashMap();
			// Null key must be passed as null (NOT "<nil>") to mappingFunction!
			def nilMapped = m.computeIfAbsent(null, k -> k == null ? "wasNull" : "bad:" + k);
			boolean hasNullKey = m.containsKey(null);

			// Typed BigDecimal key must preserve type & scale inside lambda
			BigDecimal bd1 = new BigDecimal("1.50");
			def scaleMapped = m.computeIfAbsent(bd1, k -> k.scale());

			// compute returning null deletes existing entry
			def afterDelete = m.compute(null, (k, v) -> null);
			boolean hasNullAfterDelete = m.containsKey(null);

			// merge inserts when absent, remaps when present, deletes when remapper returns null
			m.merge("cnt", 10, (a, b) -> a + b);
			m.merge("cnt", 5, (a, b) -> a + b);
			int mergedCnt = m.get("cnt");
			m.merge("cnt", 1, (a, b) -> null);
			boolean hasCntAfterNullMerge = m.containsKey("cnt");

			ctx._source.out = [
				'nilMapped': nilMapped,
				'hasNullKey': hasNullKey,
				'scaleMapped': scaleMapped,
				'afterDelete': afterDelete,
				'hasNullAfterDelete': hasNullAfterDelete,
				'mergedCnt': mergedCnt,
				'hasCntAfterNullMerge': hasCntAfterNullMerge,
				'keys': m.keySet().size()
			];
		`, nil).(map[string]any)

		want := map[string]any{
			"nilMapped":            "wasNull",
			"hasNullKey":           true,
			"scaleMapped":          int64(2),
			"afterDelete":          nil,
			"hasNullAfterDelete":   false,
			"mergedCnt":            int64(15),
			"hasCntAfterNullMerge": false,
			"keys":                 int64(1),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", got, want)
		}
	})

	t.Run("CollectorsGroupingByNullKeyNPEAndBigDecimalScaleKeys", func(t *testing.T) {
		assertRound57EvalErr(t, `
			return ["a", "b"].stream().collect(Collectors.groupingBy(s -> s == "b" ? null : s));
		`, nil, "NullPointerException")
		assertRound57EvalErr(t, `
			return ["a"].stream().collect(Collectors.groupingBy(null));
		`, nil, "NullPointerException")

		got := evalRound57Return(t, `
			List items = [new BigDecimal("1.0"), new BigDecimal("1.00"), new BigDecimal("1.0")];
			Map grouped = items.stream().collect(Collectors.groupingBy(x -> x));
			return [grouped.size(), grouped.get(new BigDecimal("1.0")).size(), grouped.get(new BigDecimal("1.00")).size(), grouped[new BigDecimal("1.0")].size()];
		`, nil)
		want := []any{int64(2), int64(2), int64(1), int64(2)}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})
}

func TestRound57_HelperBranchCoverage(t *testing.T) {
	t.Run("ExtractExactIntegralAndNarrowBranches", func(t *testing.T) {
		if _, ok := extractExactIntegralPainless(nil, true); ok {
			t.Fatal("expected nil to return false")
		}
		if _, ok := extractExactIntegralPainless(painlessEmptyOptional, true); ok {
			t.Fatal("expected empty optional sentinel to return false")
		}
		if _, ok := extractExactIntegralPainless(&painlessOptional{present: false}, true); ok {
			t.Fatal("expected absent optional to return false")
		}
		if v, ok := extractExactIntegralPainless(&painlessOptional{present: true, val: int64(19)}, true); !ok || v != 19 {
			t.Fatalf("got (%d, %v), want (19, true)", v, ok)
		}
		if _, ok := extractExactIntegralPainless((*painlessBigInteger)(nil), true); ok {
			t.Fatal("expected nil BigInteger to return false")
		}
		if _, ok := extractExactIntegralPainless(float32(1.5), true); ok {
			t.Fatal("expected non-integral float32 to return false")
		}

		narrowCases := []struct {
			in       any
			wantKind byte
			wantInt  int64
		}{
			{nil, 0, 0},
			{painlessEmptyOptional, 0, 0},
			{&painlessOptional{present: false}, 0, 0},
			{&painlessOptional{present: true, val: int(7)}, 'i', 7},
			{int64(11), 'i', 11},
			{int(12), 'i', 12},
			{int32(-13), 'i', -13},
			{int16(-14), 'i', -14},
			{int8(-15), 'i', -15},
			{uint(16), 'i', 16},
			{uint64(17), 'i', 17},
			{uint32(18), 'i', 18},
			{uint16(19), 'i', 19},
			{uint8(20), 'i', 20},
			{newPainlessBigInteger(big.NewInt(21)), 'i', 21},
			{(*painlessBigInteger)(nil), 0, 0},
			{newPainlessBigDecimal(big.NewInt(225), 1), 'i', 22},
			{(*painlessBigDecimal)(nil), 0, 0},
			{json.Number("23"), 'i', 23},
			{json.Number("23.5"), 'f', 0},
			{json.Number("not-a-number"), 0, 0},
			{float64(24.5), 'f', 0},
			{float32(25.5), 'f', 0},
			{"A", 'i', 65},
			{"AB", 0, 0},
			{struct{}{}, 0, 0},
		}
		for _, tc := range narrowCases {
			iv, _, kind := extractExactIntOrFloatForNarrowRound57(tc.in)
			if kind != tc.wantKind || (kind == 'i' && iv != tc.wantInt) {
				t.Fatalf("extractExactIntOrFloatForNarrowRound57(%#v) = (%d, %c), want (%d, %c)", tc.in, iv, kind, tc.wantInt, tc.wantKind)
			}
		}
	})

	t.Run("LiteralAndLongPromotionBranches", func(t *testing.T) {
		litCases := []struct {
			in       string
			wantLong bool
			wantLit  bool
		}{
			{"", false, false},
			{"+", false, false},
			{"-", false, false},
			{"L", false, false},
			{"0xL", false, false},
			{"0xZZL", false, false},
			{"0x1fL", true, true},
			{"0bL", false, false},
			{"0b12L", false, false},
			{"0b101L", true, true},
			{"12aL", false, false},
			{"42l", true, true},
			{"0x", false, false},
			{"0x1.0p2", false, false},
			{"0xZZ", false, false},
			{"0x10000000000000000", true, true},
			{"-0x80000000", false, true},
			{"-0x80000001", true, true},
			{"0x1_0000_0000", true, true},
			{"0b", false, false},
			{"0b12", false, false},
			{"0b10000000000000000000000000000000000000000000000000000000000000000", true, true},
			{"-0b10000000000000000000000000000000", false, true},
			{"-0b10000000000000000000000000000001", true, true},
			{"0b1_0000_0000_0000_0000_0000_0000_0000_0000", true, true},
			{"1.5", false, false},
			{"12x", false, false},
			{"99999999999999999999999", true, true},
			{"+42", false, true},
		}
		for _, tc := range litCases {
			gotL, gotLit := classifyNumericLiteralLongRound57(tc.in)
			if gotL != tc.wantLong || gotLit != tc.wantLit {
				t.Fatalf("classifyNumericLiteralLongRound57(%q) = (%v, %v), want (%v, %v)", tc.in, gotL, gotLit, tc.wantLong, tc.wantLit)
			}
		}

		arithCases := []struct {
			in     string
			wantOp byte
		}{
			{"'a+b' + 1", '+'},
			{"(1 + 2) * 3", '*'},
			{"1e-5 + 2", '+'},
			{"x++ + 1", '+'},
			{"x += 1", 0},
			{"x *= 2", 0},
			{"-5", 0},
			{"a / b", '/'},
		}
		for _, tc := range arithCases {
			_, op := findLastTopLevelBinaryArithRound57(tc.in)
			if op != tc.wantOp {
				t.Fatalf("findLastTopLevelBinaryArithRound57(%q) op = %q, want %q", tc.in, op, tc.wantOp)
			}
		}

		budget := &evalBudget{
			userFuncs: map[string]*painlessUserFunc{
				"retLong": {returnType: "long"},
				"retInt":  {returnType: "int"},
			},
		}
		cls := &painlessUserClass{
			fields: []painlessUserField{
				{name: "lf", typeName: "long"},
				{name: "ifld", typeName: "int"},
			},
		}
		uo := &painlessUserObject{
			class:  cls,
			fields: map[string]any{"lf": int64(1), "ifld": int64(2)},
		}
		params := map[string]any{
			"__eval_budget": budget,
			"__var_type_lv": "long",
			"__var_type_iv": "int",
			"bigUntyped":    int64(math.MaxInt64),
			"smallUntyped":  int64(5),
			"this":          uo,
		}
		longExprCases := []struct {
			expr string
			val  any
			want bool
		}{
			{"", int64(math.MaxInt64), true},
			{"", "str", false},
			{"(long) 1", int64(1), true},
			{"(int) 1L", int64(1), false},
			{"(def) 1L", int64(1), true},
			{"++lv", nil, true},
			{"iv--", nil, false},
			{"~1L", nil, true},
			{"1 | 2L", nil, true},
			{"1L << 2", nil, true},
			{"1 << 2L", nil, false},
			{"1 + 2L", nil, true},
			{"java.lang.Long.MAX_VALUE", nil, true},
			{"java.lang.Integer.MAX_VALUE", nil, false},
			{"lv", nil, true},
			{"iv", nil, false},
			{"lf", nil, true},
			{"ifld", nil, false},
			{"bigUntyped", nil, true},
			{"smallUntyped", nil, false},
			{"java.lang.Long.bitCount(1L)", nil, false},
			{"Integer.toUnsignedLong(1)", nil, true},
			{"Math.toIntExact(1L)", nil, false},
			{"StrictMath.addExact(1, 2L)", nil, true},
			{"Math.addExact(1, 2)", nil, false},
			{"Math.negateExact(1L)", nil, true},
			{"Long.parseLong('1')", nil, true},
			{"Integer.parseInt('1')", nil, false},
			{"retLong()", nil, true},
			{"retInt()", nil, false},
			{"x.longValue()", nil, true},
			{"x.intValue()", nil, false},
			{"x.getLong(0)", nil, true},
			{"x.toEpochSecond(z)", nil, true},
			{"x.fromHexDigitsToLong(s)", nil, true},
			{"x.compareTo(y)", nil, false},
			{"doc['ts'].value", int64(math.MaxInt64), true},
			{"doc['ts'].value", "not-int", false},
		}
		for _, tc := range longExprCases {
			if got := isLongExprPainless(tc.expr, tc.val, params); got != tc.want {
				t.Fatalf("isLongExprPainless(%q) = %v, want %v", tc.expr, got, tc.want)
			}
		}

		if gotUO, ft := resolveUnshadowedThisFieldTypeRound57(params, "lf"); gotUO != uo || ft != "long" {
			t.Fatalf("resolveUnshadowedThisFieldTypeRound57(lf) = (%v, %q), want (uo, 'long')", gotUO, ft)
		}
		params["__method_params"] = map[string]bool{"lf": true}
		if gotUO, _ := resolveUnshadowedThisFieldTypeRound57(params, "lf"); gotUO != nil {
			t.Fatal("expected shadowed method param to return nil")
		}
		delete(params, "__method_params")
		params["__script_locals"] = map[string]bool{"lf": true}
		if gotUO, _ := resolveUnshadowedThisFieldTypeRound57(params, "lf"); gotUO != nil {
			t.Fatal("expected shadowed script local to return nil")
		}
	})

	t.Run("IncDecEqualsSplitExceptionAndMapHelpers", func(t *testing.T) {
		for _, dt := range []string{"byte", "short", "char", "int", "long", "float", "double", ""} {
			next, prev := applyIncDecRound57Painless(int64(5), true, dt)
			if next == nil || prev == nil {
				t.Fatalf("applyIncDecRound57Painless(%q) returned nil", dt)
			}
		}
		_, _ = applyIncDecRound57Painless(int(5), false, "")
		_, _ = applyIncDecRound57Painless(json.Number("5"), true, "")
		_, _ = applyIncDecRound57Painless(float64(2.5), true, "")

		opt1 := &painlessOptional{present: true, val: int64(1)}
		opt2 := &painlessOptional{present: true, val: int64(1)}
		if !painlessJavaObjectEquals(opt1, opt2) || painlessJavaObjectEquals(int64(1), opt1) {
			t.Fatal("unexpected Optional equality result")
		}
		if !painlessJavaObjectEquals(painlessEmptyOptional, painlessEmptyOptional) || painlessJavaObjectEquals(painlessEmptyOptional, int64(1)) {
			t.Fatal("unexpected painlessEmptyOptional equality result")
		}
		bd1 := newPainlessBigDecimal(big.NewInt(10), 1)
		bd2 := newPainlessBigDecimal(big.NewInt(100), 2)
		if painlessJavaObjectEquals(bd1, bd2) || painlessJavaObjectEquals(bd1, int64(1)) || painlessJavaObjectEquals(int64(1), bd1) {
			t.Fatal("unexpected BigDecimal equality result")
		}
		if !painlessJavaObjectEquals((*painlessBigDecimal)(nil), (*painlessBigDecimal)(nil)) {
			t.Fatal("expected nil BigDecimals to be equal")
		}
		bi1 := newPainlessBigInteger(big.NewInt(7))
		if painlessJavaObjectEquals(bi1, int64(7)) || painlessJavaObjectEquals(int64(7), bi1) || !painlessJavaObjectEquals((*painlessBigInteger)(nil), (*painlessBigInteger)(nil)) {
			t.Fatal("unexpected BigInteger equality result")
		}
		if !painlessJavaObjectEquals([]any{int64(1)}, []any{int64(1)}) || painlessJavaObjectEquals([]any{int64(1)}, []any{int64(2)}) || painlessJavaObjectEquals([]any{int64(1)}, []any{int64(1), int64(2)}) {
			t.Fatal("unexpected slice equality result")
		}
		mA := map[string]any{"a": bd1}
		mB := map[string]any{"a": newPainlessBigDecimal(big.NewInt(10), 1)}
		mC := map[string]any{"a": bd2}
		mD := map[string]any{"a": bd1, "b": int64(2)}
		if !painlessJavaObjectEquals(mA, mB) || painlessJavaObjectEquals(mA, mC) || painlessJavaObjectEquals(mA, mD) || painlessJavaObjectEquals(mA, "nope") {
			t.Fatal("unexpected map equality result")
		}

		for _, lim := range []int{1, 2, 10, -1, 0} {
			if res := javaSplitEmptyPatternRound57("abc", lim); len(res) == 0 {
				t.Fatalf("javaSplitEmptyPatternRound57('abc', %d) returned empty", lim)
			}
		}
		if res := javaSplitEmptyPatternRound57("", 0); !reflect.DeepEqual(res, []any{""}) {
			t.Fatalf("javaSplitEmptyPatternRound57('', 0) = %#v", res)
		}

		excBudget := &evalBudget{
			userClasses: map[string]*painlessUserClass{
				"MySubEx": {name: "MySubEx", parentName: "java.lang.IllegalStateException"},
			},
		}
		excParents := map[string]string{
			"MySubEx":                        "IllegalStateException",
			"NumberFormatException":          "IllegalArgumentException",
			"ArrayIndexOutOfBoundsException": "IndexOutOfBoundsException",
			"DateTimeParseException":         "DateTimeException",
			"InputMismatchException":         "NoSuchElementException",
			"IllegalArgumentException":       "RuntimeException",
			"MalformedURLException":          "IOException",
			"RuntimeException":               "Exception",
			"AssertionError":                 "Error",
			"Exception":                      "Throwable",
			"Throwable":                      "Object",
			"Object":                         "",
			"CustomFatalError":               "Error",
			"CustomCheckedException":         "RuntimeException",
			"NotAThrowable":                  "",
		}
		for child, wantParent := range excParents {
			if got := parentJavaExceptionTypeRound57(child, excBudget); got != wantParent {
				t.Fatalf("parentJavaExceptionTypeRound57(%q) = %q, want %q", child, got, wantParent)
			}
		}
		if !painlessExceptionIsAssignableTo("", "RuntimeException", excBudget) || !painlessExceptionIsAssignableTo("MySubEx", "Exception", excBudget) {
			t.Fatal("expected assignable exception hierarchy")
		}
		if et, msg := extractThrownExceptionTypeAndMsgRound57(nil); et != "" || msg != "" {
			t.Fatalf("expected empty for nil error, got (%q, %q)", et, msg)
		}
		if et, _ := extractThrownExceptionTypeAndMsgRound57(&painlessExceptionError{exType: "", message: "x"}); et != "RuntimeException" {
			t.Fatalf("expected default RuntimeException, got %q", et)
		}
		if et, msg := extractThrownExceptionTypeAndMsgRound57(errors.New("IllegalArgumentException: bad input")); et != "IllegalArgumentException" || msg != "bad input" {
			t.Fatalf("got (%q, %q)", et, msg)
		}
		if et, _ := extractThrownExceptionTypeAndMsgRound57(errors.New("plain failure")); et != "RuntimeException" {
			t.Fatalf("got %q", et)
		}
		if !matchesCatchExceptionRound57(errors.New("plain"), nil, excBudget) {
			t.Fatal("expected empty catch list to match")
		}

		for _, kv := range []any{nil, painlessEmptyOptional, &painlessOptional{present: false}, bd1, bi1, "k"} {
			enc := encodePainlessMapKeyRound57(kv)
			dec := decodePainlessMapKeyRound57(enc)
			if kv == "k" && dec != "k" {
				t.Fatalf("round-trip failed for string key: %#v", dec)
			}
		}
		if _, _, err := validateAndNormalizeMapLambdaRound57("", 1, "fn", nil, nil, 0); err == nil {
			t.Fatal("expected NPE on empty lambda")
		}
		if _, _, err := validateAndNormalizeMapLambdaRound57("fnVar", 1, "fn", nil, map[string]any{"fnVar": nil}, 0); err == nil {
			t.Fatal("expected NPE when lambda variable evaluates to nil")
		}
		if _, _, err := validateAndNormalizeMapLambdaRound57("fnVar", 1, "fn", nil, map[string]any{"fnVar": "nonNull"}, 0); err != nil {
			t.Fatalf("unexpected error on non-null variable: %v", err)
		}
	})
}
