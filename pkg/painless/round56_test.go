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
	"reflect"
	"strings"
	"testing"
)

func evalRound56Out(t *testing.T, script string, params map[string]any) any {
	t.Helper()
	doc := map[string]any{}
	if _, err := Eval(doc, script, params); err != nil {
		t.Fatalf("Eval failed for script:\n%s\nerr: %v", script, err)
	}
	return doc["out"]
}

func assertRound56EvalErr(t *testing.T, script string, params map[string]any, wantSubstr string) {
	t.Helper()
	doc := map[string]any{}
	_, err := Eval(doc, script, params)
	if err == nil {
		t.Fatalf("expected error containing %q for script:\n%s\ngot nil (out=%#v)", wantSubstr, script, doc["out"])
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("expected error containing %q for script:\n%s\ngot: %v", wantSubstr, script, err)
	}
}

func TestRound56_F20_IEEE754NaNAndInfinity(t *testing.T) {
	t.Run("EqualityAndRelationalOperators", func(t *testing.T) {
		got := evalRound56Out(t, `
			double nan = Double.NaN;
			float fnan = Float.NaN;
			double pinf = Double.POSITIVE_INFINITY;
			double ninf = Double.NEGATIVE_INFINITY;
			float fpinf = Float.POSITIVE_INFINITY;
			float fninf = Float.NEGATIVE_INFINITY;

			boolean eqNaN = (nan == nan);
			boolean neNaN = (nan != nan);
			boolean eqFNaN = (fnan == fnan);
			boolean neFNaN = (fnan != fnan);
			boolean eqCrossNaN = (nan == fnan);
			boolean neCrossNaN = (nan != fnan);
			boolean refEqNaN = (nan === nan);
			boolean refNeNaN = (nan !== nan);
			boolean eqNaNZero = (nan == 0.0);
			boolean neNaNZero = (nan != 0.0);

			boolean eqPInf = (pinf == pinf);
			boolean eqNInf = (ninf == ninf);
			boolean eqCrossInf = (pinf == fpinf) && (ninf == fninf);
			boolean eqOppInf = (pinf == ninf);
			boolean neOppInf = (pinf != ninf);
			boolean negZeroEqPosZero = (-0.0 == 0.0);

			// IEEE-754 float division by zero produces +Infinity (Round 58 F21)
			double finiteDivZero = 1.0 / 0.0;
			boolean regDivZeroFinite = Double.isInfinite(finiteDivZero) && finiteDivZero == Double.POSITIVE_INFINITY;

			// Relational operators with NaN -> all false
			boolean relNaN = (nan < 1.0) || (nan <= 1.0) || (nan > 1.0) || (nan >= 1.0) ||
				(1.0 < nan) || (1.0 <= nan) || (1.0 > nan) || (1.0 >= nan) ||
				(nan < nan) || (nan <= nan) || (nan > nan) || (nan >= nan);

			// Relational operators with +-Infinity
			boolean relInf = (ninf < -1000000.0) && (-1000000.0 < 0.0) && (0.0 < 1000000.0) &&
				(1000000.0 < pinf) && (ninf <= ninf) && (pinf >= pinf) && !(pinf < ninf);

			ctx._source.out = [
				'eqNaN': eqNaN,
				'neNaN': neNaN,
				'eqFNaN': eqFNaN,
				'neFNaN': neFNaN,
				'eqCrossNaN': eqCrossNaN,
				'neCrossNaN': neCrossNaN,
				'refEqNaN': refEqNaN,
				'refNeNaN': refNeNaN,
				'eqNaNZero': eqNaNZero,
				'neNaNZero': neNaNZero,
				'eqPInf': eqPInf,
				'eqNInf': eqNInf,
				'eqCrossInf': eqCrossInf,
				'eqOppInf': eqOppInf,
				'neOppInf': neOppInf,
				'negZeroEqPosZero': negZeroEqPosZero,
				'regDivZeroFinite': regDivZeroFinite,
				'relNaN': relNaN,
				'relInf': relInf
			];
		`, nil)
		m := got.(map[string]any)
		want := map[string]any{
			"eqNaN":            false,
			"neNaN":            true,
			"eqFNaN":           false,
			"neFNaN":           true,
			"eqCrossNaN":       false,
			"neCrossNaN":       true,
			"refEqNaN":         false,
			"refNeNaN":         true,
			"eqNaNZero":        false,
			"neNaNZero":        true,
			"eqPInf":           true,
			"eqNInf":           true,
			"eqCrossInf":       true,
			"eqOppInf":         false,
			"neOppInf":         true,
			"negZeroEqPosZero": true,
			"regDivZeroFinite": true,
			"relNaN":           false,
			"relInf":           true,
		}
		if !reflect.DeepEqual(m, want) {
			t.Fatalf("unexpected equality/relational IEEE-754 results:\ngot:  %#v\nwant: %#v", m, want)
		}
	})

	t.Run("ObjectsEqualsCollectionsAndSetsWithNaNAndInfinity", func(t *testing.T) {
		got := evalRound56Out(t, `
			boolean objEqNaN = Objects.equals(Double.NaN, Double.NaN);
			boolean dblEqNaN = Double.valueOf(Double.NaN).equals(Double.NaN);
			boolean fltEqNaN = Float.valueOf(Float.NaN).equals(Float.NaN);
			boolean objEqInf = Objects.equals(Double.POSITIVE_INFINITY, Double.POSITIVE_INFINITY);
			boolean objNeInf = Objects.equals(Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY);

			List list = new ArrayList();
			list.add(1.0);
			list.add(Double.NaN);
			list.add(Double.POSITIVE_INFINITY);
			list.add(Double.NEGATIVE_INFINITY);

			boolean hasNaN = list.contains(Double.NaN);
			int idxNaN = list.indexOf(Double.NaN);
			boolean hasPInf = list.contains(Double.POSITIVE_INFINITY);
			int idxNInf = list.indexOf(Double.NEGATIVE_INFINITY);

			Set set = new HashSet();
			set.add(Double.NaN);
			set.add(Double.NaN);
			set.add(Double.POSITIVE_INFINITY);
			set.add(Double.NEGATIVE_INFINITY);
			boolean setContainsNaN = set.contains(Double.NaN);
			int setSize = set.size();

			ctx._source.out = [
				'objEqNaN': objEqNaN,
				'dblEqNaN': dblEqNaN,
				'fltEqNaN': fltEqNaN,
				'objEqInf': objEqInf,
				'objNeInf': objNeInf,
				'hasNaN': hasNaN,
				'idxNaN': idxNaN,
				'hasPInf': hasPInf,
				'idxNInf': idxNInf,
				'setContainsNaN': setContainsNaN,
				'setSize': setSize
			];
		`, nil)
		m := got.(map[string]any)
		want := map[string]any{
			"objEqNaN":       true,
			"dblEqNaN":       true,
			"fltEqNaN":       true,
			"objEqInf":       true,
			"objNeInf":       false,
			"hasNaN":         true,
			"idxNaN":         int64(1),
			"hasPInf":        true,
			"idxNInf":        int64(3),
			"setContainsNaN": true,
			"setSize":        int64(3),
		}
		if !reflect.DeepEqual(m, want) {
			t.Fatalf("unexpected collection/Objects.equals IEEE-754 results:\ngot:  %#v\nwant: %#v", m, want)
		}
	})

	t.Run("ParsingValueOfAndFormatting", func(t *testing.T) {
		got := evalRound56Out(t, `
			double pNaN = Double.parseDouble("NaN");
			double pInf = Double.parseDouble("Infinity");
			double pPlusInf = Double.parseDouble("+Infinity");
			double pNegInf = Double.parseDouble("  -Infinity \n");
			double vNaN = Double.valueOf(Double.NaN);
			double vStrInf = Double.valueOf("Infinity");
			float fpNaN = Float.parseFloat("NaN");
			float fpInf = Float.parseFloat("Infinity");
			float fpNegInf = Float.parseFloat("-Infinity");
			float fvNaN = Float.valueOf(Float.NaN);
			float fvInf = Float.valueOf(Float.POSITIVE_INFINITY);

			// Reject Go-only spellings with NumberFormatException
			List badTokens = ["Inf", "+Inf", "-Inf", "nan", "NAN", "infinity", "INFINITY", ""];
			int nfeCount = 0;
			for (String tok : badTokens) {
				try {
					Double.parseDouble(tok);
				} catch (NumberFormatException e) {
					nfeCount = nfeCount + 1;
				}
			}
			int fnfeCount = 0;
			for (String tok : badTokens) {
				try {
					Float.parseFloat(tok);
				} catch (NumberFormatException e) {
					fnfeCount = fnfeCount + 1;
				}
			}

			// String formatting across all stringification paths
			List strs = [
				Double.toString(pNaN),
				Double.toString(pInf),
				Double.toString(pNegInf),
				Float.toString(fpNaN),
				Float.toString(fpInf),
				Float.toString(fpNegInf),
				Double.valueOf(pInf).toString(),
				Double.valueOf(pNegInf).toString(),
				Double.valueOf(pNaN).toString(),
				String.valueOf(pInf),
				String.valueOf(pNegInf),
				String.valueOf(pNaN),
				Objects.toString(pInf),
				Objects.toString(pNegInf),
				Objects.toString(pNaN),
				"x=" + pInf + "," + pNegInf + "," + pNaN,
				OptionalDouble.of(pNaN).toString(),
				OptionalDouble.of(pInf).toString(),
				OptionalDouble.of(pNegInf).toString()
			];

			ctx._source.out = [
				'parsed': [
					Double.isNaN(pNaN),
					pInf == Double.POSITIVE_INFINITY,
					pPlusInf == Double.POSITIVE_INFINITY,
					pNegInf == Double.NEGATIVE_INFINITY,
					Double.isNaN(vNaN),
					vStrInf == Double.POSITIVE_INFINITY,
					Float.isNaN(fpNaN),
					fpInf == Float.POSITIVE_INFINITY,
					fpNegInf == Float.NEGATIVE_INFINITY,
					Float.isNaN(fvNaN),
					fvInf == Float.POSITIVE_INFINITY
				],
				'nfeCount': nfeCount,
				'fnfeCount': fnfeCount,
				'strs': strs
			];
		`, nil)
		m := got.(map[string]any)
		for i, v := range m["parsed"].([]any) {
			if v != true {
				t.Fatalf("parsed[%d] = %#v, want true", i, v)
			}
		}
		if m["nfeCount"] != int64(8) || m["fnfeCount"] != int64(8) {
			t.Fatalf("expected 8 NumberFormatExceptions for Double and Float, got %#v / %#v", m["nfeCount"], m["fnfeCount"])
		}
		wantStrs := []any{
			"NaN", "Infinity", "-Infinity",
			"NaN", "Infinity", "-Infinity",
			"Infinity", "-Infinity", "NaN",
			"Infinity", "-Infinity", "NaN",
			"Infinity", "-Infinity", "NaN",
			"x=Infinity,-Infinity,NaN",
			"OptionalDouble[NaN]",
			"OptionalDouble[Infinity]",
			"OptionalDouble[-Infinity]",
		}
		if !reflect.DeepEqual(m["strs"], wantStrs) {
			t.Fatalf("unexpected IEEE-754 string formatting:\ngot:  %#v\nwant: %#v", m["strs"], wantStrs)
		}
	})

	t.Run("CompareMinMaxStreamsCollectorsAndCasts", func(t *testing.T) {
		got := evalRound56Out(t, `
			// Total order: -Infinity < -0.0 < +0.0 < +Infinity < NaN
			double negZero = -1.0 * 0.0;
			double posZero = 0.0;
			boolean cmp1 = Double.compare(Double.NEGATIVE_INFINITY, negZero) < 0;
			boolean cmp2 = Double.compare(negZero, posZero) < 0;
			boolean cmp3 = Double.compare(posZero, Double.POSITIVE_INFINITY) < 0;
			boolean cmp4 = Double.compare(Double.POSITIVE_INFINITY, Double.NaN) < 0;
			boolean cmp5 = Double.compare(Double.NaN, Double.NaN) == 0;
			boolean cmpTo = Double.valueOf(Double.NaN).compareTo(Double.POSITIVE_INFINITY) > 0;
			boolean fcmp1 = Float.compare(Float.POSITIVE_INFINITY, Float.NaN) < 0;
			boolean fcmp2 = Float.compare(Float.NaN, Float.NaN) == 0;

			List sortList = [Double.NaN, 1.5, Double.NEGATIVE_INFINITY, Double.POSITIVE_INFINITY, -1.5];
			Collections.sort(sortList);
			List sortedStrs = sortList.stream().map(x -> String.valueOf(x)).collect(Collectors.toList());

			// sum / max / min with NaN propagation and signed zero
			boolean dSumNaN = Double.isNaN(Double.sum(1.5, Double.NaN));
			boolean dMaxNaN = Double.isNaN(Double.max(1.5, Double.NaN));
			boolean dMinNaN = Double.isNaN(Double.min(1.5, Double.NaN));
			boolean dMaxInf = Double.max(1.5, Double.POSITIVE_INFINITY) == Double.POSITIVE_INFINITY;
			boolean dMinInf = Double.min(1.5, Double.NEGATIVE_INFINITY) == Double.NEGATIVE_INFINITY;
			boolean fSumNaN = Float.isNaN(Float.sum(1.5f, Float.NaN));
			boolean fMaxNaN = Float.isNaN(Float.max(1.5f, Float.NaN));
			boolean fMinNaN = Float.isNaN(Float.min(1.5f, Float.NaN));

			// DoubleStream & Collectors
			double dsSumInf = DoubleStream.of(1.0, Double.POSITIVE_INFINITY).sum();
			double dsSumNaN = DoubleStream.of(1.0, Double.NaN).sum();
			OptionalDouble dsAvgNaN = DoubleStream.of(1.0, Double.NaN).average();
			OptionalDouble dsAvgInf = DoubleStream.of(1.0, Double.POSITIVE_INFINITY).average();

			List numsWithNaN = [1.0, Double.NaN, 3.0];
			double colSumNaN = numsWithNaN.stream().collect(Collectors.summingDouble(x -> x));
			double colAvgNaN = numsWithNaN.stream().collect(Collectors.averagingDouble(x -> x));

			List numsWithInf = [1.0, Double.POSITIVE_INFINITY];
			double colSumInf = numsWithInf.stream().collect(Collectors.summingDouble(x -> x));
			double colAvgInf = numsWithInf.stream().collect(Collectors.averagingDouble(x -> x));

			// Narrowing primitive casts per JLS 5.1.3
			int castIntNaN = (int) Double.NaN;
			int castIntPInf = (int) Double.POSITIVE_INFINITY;
			int castIntNInf = (int) Double.NEGATIVE_INFINITY;
			long castLongNaN = (long) Double.NaN;
			long castLongPInf = (long) Double.POSITIVE_INFINITY;
			long castLongNInf = (long) Double.NEGATIVE_INFINITY;

			ctx._source.out = [
				'cmps': [cmp1, cmp2, cmp3, cmp4, cmp5, cmpTo, fcmp1, fcmp2],
				'sortedStrs': sortedStrs,
				'math': [dSumNaN, dMaxNaN, dMinNaN, dMaxInf, dMinInf, fSumNaN, fMaxNaN, fMinNaN],
				'streams': [
					dsSumInf == Double.POSITIVE_INFINITY,
					Double.isNaN(dsSumNaN),
					dsAvgNaN.isPresent() && Double.isNaN(dsAvgNaN.getAsDouble()),
					dsAvgInf.isPresent() && dsAvgInf.getAsDouble() == Double.POSITIVE_INFINITY,
					Double.isNaN(colSumNaN),
					Double.isNaN(colAvgNaN),
					colSumInf == Double.POSITIVE_INFINITY,
					colAvgInf == Double.POSITIVE_INFINITY
				],
				'casts': [castIntNaN, castIntPInf, castIntNInf, castLongNaN, castLongPInf, castLongNInf]
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["cmps"], []any{true, true, true, true, true, true, true, true}) {
			t.Fatalf("unexpected total-order comparisons: %#v", m["cmps"])
		}
		if !reflect.DeepEqual(m["sortedStrs"], []any{"-Infinity", "-1.5", "1.5", "Infinity", "NaN"}) {
			t.Fatalf("unexpected sorted IEEE-754 list: %#v", m["sortedStrs"])
		}
		if !reflect.DeepEqual(m["math"], []any{true, true, true, true, true, true, true, true}) {
			t.Fatalf("unexpected sum/max/min results: %#v", m["math"])
		}
		if !reflect.DeepEqual(m["streams"], []any{true, true, true, true, true, true, true, true}) {
			t.Fatalf("unexpected DoubleStream / Collectors results: %#v", m["streams"])
		}
		wantCasts := []any{
			int64(0),
			int64(math.MaxInt32),
			int64(math.MinInt32),
			int64(0),
			int64(math.MaxInt64),
			int64(math.MinInt64),
		}
		if !reflect.DeepEqual(m["casts"], wantCasts) {
			t.Fatalf("unexpected IEEE-754 narrowing casts:\ngot:  %#v\nwant: %#v", m["casts"], wantCasts)
		}
	})
}

func TestRound56_F21_IntegralParsingAndDecoding(t *testing.T) {
	t.Run("SignedAndUnsignedParseAndValueOf", func(t *testing.T) {
		got := evalRound56Out(t, `
			int iMax = Integer.parseInt("2147483647");
			int iMin = Integer.parseInt("-2147483648");
			int iRad2 = Integer.parseInt("1010", 2);
			int iRad36 = Integer.valueOf("z", 36);
			long lMax = Long.parseLong("9223372036854775807");
			long lMin = Long.parseLong("-9223372036854775808");
			short sMax = Short.parseShort("32767");
			short sMin = Short.parseShort("-32768");
			byte bMax = Byte.parseByte("127");
			byte bMin = Byte.parseByte("-128");
			int uIntMax = Integer.parseUnsignedInt("4294967295");
			long uLongMax = Long.parseUnsignedLong("18446744073709551615");

			// Regression guards: Integer.toString(i, badRadix) and BigInteger.toString(badRadix) still fall back to base 10
			String regIntToStr = Integer.toString(42, 1);
			String regBigToStr = BigInteger.valueOf(42).toString(99);

			int nfe = 0;
			try { Integer.parseInt("2147483648"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.parseInt("-2147483649"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.valueOf("2147483648"); } catch (NumberFormatException e) { nfe++; }
			try { Short.parseShort("32768"); } catch (NumberFormatException e) { nfe++; }
			try { Short.parseShort("-32769"); } catch (NumberFormatException e) { nfe++; }
			try { Short.valueOf("40000"); } catch (NumberFormatException e) { nfe++; }
			try { Byte.parseByte("128"); } catch (NumberFormatException e) { nfe++; }
			try { Byte.parseByte("-129"); } catch (NumberFormatException e) { nfe++; }
			try { Byte.valueOf("200"); } catch (NumberFormatException e) { nfe++; }
			try { Long.parseLong("9223372036854775808"); } catch (NumberFormatException e) { nfe++; }
			try { Long.parseLong("-9223372036854775809"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.parseUnsignedInt("4294967296"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.parseUnsignedInt("-1"); } catch (NumberFormatException e) { nfe++; }
			try { Long.parseUnsignedLong("18446744073709551616"); } catch (NumberFormatException e) { nfe++; }
			try { Long.parseUnsignedLong("-1"); } catch (NumberFormatException e) { nfe++; }

			// Radix validation [2, 36]
			try { Integer.parseInt("10", 1); } catch (NumberFormatException e) { nfe++; }
			try { Integer.parseInt("10", 37); } catch (NumberFormatException e) { nfe++; }
			try { Long.parseLong("10", 0); } catch (NumberFormatException e) { nfe++; }
			try { Short.parseShort("10", 37); } catch (NumberFormatException e) { nfe++; }
			try { Byte.parseByte("10", 1); } catch (NumberFormatException e) { nfe++; }
			try { Integer.parseUnsignedInt("10", 37); } catch (NumberFormatException e) { nfe++; }
			try { Long.parseUnsignedLong("10", 1); } catch (NumberFormatException e) { nfe++; }

			// Reject null, whitespace, and underscores
			String nullStr = null;
			try { Integer.parseInt(nullStr); } catch (NumberFormatException e) { nfe++; }
			try { Long.parseLong(nullStr); } catch (NumberFormatException e) { nfe++; }
			try { Short.parseShort(nullStr); } catch (NumberFormatException e) { nfe++; }
			try { Byte.parseByte(nullStr); } catch (NumberFormatException e) { nfe++; }
			try { Integer.parseInt(" 1"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.parseInt("1 "); } catch (NumberFormatException e) { nfe++; }
			try { Integer.parseInt("1_000"); } catch (NumberFormatException e) { nfe++; }
			try { Long.parseLong("1_000"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.parseUnsignedInt("1_000"); } catch (NumberFormatException e) { nfe++; }

			ctx._source.out = [
				'vals': [iMax, iMin, iRad2, iRad36, lMax, lMin, sMax, sMin, bMax, bMin, uIntMax, uLongMax],
				'reg': [regIntToStr, regBigToStr],
				'nfe': nfe
			];
		`, nil)
		m := got.(map[string]any)
		wantVals := []any{
			int64(2147483647), int64(-2147483648), int64(10), int64(35),
			int64(9223372036854775807), int64(-9223372036854775808),
			int64(32767), int64(-32768),
			int64(127), int64(-128),
			int64(-1), int64(-1),
		}
		if !reflect.DeepEqual(m["vals"], wantVals) {
			t.Fatalf("unexpected parsed integral values:\ngot:  %#v\nwant: %#v", m["vals"], wantVals)
		}
		if !reflect.DeepEqual(m["reg"], []any{"42", "42"}) {
			t.Fatalf("unexpected radix fallback regression results: %#v", m["reg"])
		}
		if m["nfe"] != int64(31) {
			t.Fatalf("expected 31 NumberFormatExceptions, got %#v", m["nfe"])
		}
	})

	t.Run("DecodeHexOctalDecimalNullAndOverflow", func(t *testing.T) {
		got := evalRound56Out(t, `
			int dHex = Integer.decode("0x7fffffff");
			int dNegHex = Integer.decode("-0x80000000");
			int dHash = Integer.decode("#ff");
			int dPlusHex = Integer.decode("+0X10");
			int dOct = Integer.decode("010");
			int dNegOct = Integer.decode("-077");
			int dZero = Integer.decode("0");
			long lMinHex = Long.decode("-0x8000000000000000");
			short sMaxHex = Short.decode("0x7fff");
			short sMinHex = Short.decode("-0x8000");
			byte bMaxHex = Byte.decode("0x7f");
			byte bMinHex = Byte.decode("-0x80");

			String nullStr = null;
			int npe = 0;
			try { Integer.decode(nullStr); } catch (NullPointerException e) { npe++; }
			try { Long.decode(nullStr); } catch (NullPointerException e) { npe++; }
			try { Short.decode(nullStr); } catch (NullPointerException e) { npe++; }
			try { Byte.decode(nullStr); } catch (NullPointerException e) { npe++; }

			int nfe = 0;
			try { Integer.decode("0x80000000"); } catch (NumberFormatException e) { nfe++; }
			try { Long.decode("0x8000000000000000"); } catch (NumberFormatException e) { nfe++; }
			try { Short.decode("0x8000"); } catch (NumberFormatException e) { nfe++; }
			try { Byte.decode("0x80"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.decode("0x1_0"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.decode(" 0x10"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.decode("0x-1"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.decode("0x+1"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.decode("0x"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.decode("#"); } catch (NumberFormatException e) { nfe++; }
			try { Integer.decode(""); } catch (NumberFormatException e) { nfe++; }
			try { Integer.decode("09"); } catch (NumberFormatException e) { nfe++; }

			ctx._source.out = [
				'vals': [dHex, dNegHex, dHash, dPlusHex, dOct, dNegOct, dZero, lMinHex, sMaxHex, sMinHex, bMaxHex, bMinHex],
				'npe': npe,
				'nfe': nfe
			];
		`, nil)
		m := got.(map[string]any)
		wantVals := []any{
			int64(2147483647), int64(-2147483648), int64(255), int64(16),
			int64(8), int64(-63), int64(0),
			int64(-9223372036854775808),
			int64(32767), int64(-32768),
			int64(127), int64(-128),
		}
		if !reflect.DeepEqual(m["vals"], wantVals) {
			t.Fatalf("unexpected decoded integral values:\ngot:  %#v\nwant: %#v", m["vals"], wantVals)
		}
		if m["npe"] != int64(4) {
			t.Fatalf("expected 4 NullPointerExceptions from decode(null), got %#v", m["npe"])
		}
		if m["nfe"] != int64(12) {
			t.Fatalf("expected 12 NumberFormatExceptions from decode, got %#v", m["nfe"])
		}
	})
}

func TestRound56_F22_BigDecimalJSR13CanonicalScientificNotation(t *testing.T) {
	got := evalRound56Out(t, `
		BigDecimal bdPlain1 = new BigDecimal("123.45");
		BigDecimal bdPlainEdge = new BigDecimal("0.000001");     // scale=6, adjusted=-6 -> plain
		BigDecimal bdSciSmall = new BigDecimal("0.0000001");     // scale=7, adjusted=-7 -> 1E-7
		BigDecimal bdSciNeg = new BigDecimal("-0.000000123");    // scale=9, adjusted=-7 -> -1.23E-7
		BigDecimal bdNegScale1 = new BigDecimal("123E+2");       // scale=-2, adjusted=+4 -> 1.23E+4
		BigDecimal bdNegScaleSingle = BigDecimal.valueOf(5, -3); // scale=-3, adjusted=+3 -> 5E+3
		BigDecimal bdZeroSciNeg = new BigDecimal("0E-7");        // scale=7, adjusted=-7 -> 0E-7
		BigDecimal bdZeroSciPos = new BigDecimal("0E+3");        // scale=-3 -> 0E+3
		BigDecimal bdZeroPlain = new BigDecimal("0.000000");     // scale=6, adjusted=-6 -> 0.000000

		ctx._source.out = [
			'toString': [
				bdPlain1.toString(),
				bdPlainEdge.toString(),
				bdSciSmall.toString(),
				bdSciNeg.toString(),
				bdNegScale1.toString(),
				bdNegScaleSingle.toString(),
				bdZeroSciNeg.toString(),
				bdZeroSciPos.toString(),
				bdZeroPlain.toString(),
				String.valueOf(bdSciSmall),
				"v=" + bdNegScale1
			],
			'plain': [
				bdSciSmall.toPlainString(),
				bdNegScale1.toPlainString()
			],
			'eng': [
				bdSciSmall.toEngineeringString(),
				bdNegScale1.toEngineeringString()
			]
		];
	`, nil)
	m := got.(map[string]any)
	wantToString := []any{
		"123.45",
		"0.000001",
		"1E-7",
		"-1.23E-7",
		"1.23E+4",
		"5E+3",
		"0E-7",
		"0E+3",
		"0.000000",
		"1E-7",
		"v=1.23E+4",
	}
	if !reflect.DeepEqual(m["toString"], wantToString) {
		t.Fatalf("unexpected BigDecimal JSR-13 toString():\ngot:  %#v\nwant: %#v", m["toString"], wantToString)
	}
	if !reflect.DeepEqual(m["plain"], []any{"0.0000001", "12300"}) {
		t.Fatalf("unexpected BigDecimal toPlainString(): %#v", m["plain"])
	}
	if !reflect.DeepEqual(m["eng"], []any{"100E-9", "12.3E+3"}) {
		t.Fatalf("unexpected BigDecimal toEngineeringString(): %#v", m["eng"])
	}
}

func TestRound56_F23_LocalDateTimeZoneLessAndTemporalWithChronoField(t *testing.T) {
	t.Run("LocalDateTimeZoneLessPreservationAndZonedDateTimeBracketPreservation", func(t *testing.T) {
		got := evalRound56Out(t, `
			LocalDateTime ldt = LocalDateTime.parse("2026-03-15T10:20:30.123");
			boolean isLdt = ldt instanceof LocalDateTime;
			boolean isZdt = ldt instanceof ZonedDateTime;
			String s0 = ldt.toString();
			String sPlus = ldt.plusHours(2).toString();
			String sMinus = ldt.minusMinutes(5).toString();
			String sWithHr = ldt.withHour(8).toString();
			String sTrunc = ldt.truncatedTo(ChronoUnit.HOURS).toString();
			String sWithField = ldt.with(ChronoField.MINUTE_OF_HOUR, 45).toString();
			boolean plusStillLdt = ldt.plusDays(1) instanceof LocalDateTime;

			ZonedDateTime zdt = ZonedDateTime.parse("2026-01-15T10:20:30+01:00[Europe/Berlin]");
			String zPlus = zdt.plusHours(1).toString();
			String zWith = zdt.with(ChronoField.MINUTE_OF_HOUR, 5).toString();

			ctx._source.out = [
				'types': [isLdt, isZdt, plusStillLdt],
				'ldt': [s0, sPlus, sMinus, sWithHr, sTrunc, sWithField],
				'zdt': [zPlus.endsWith("[Europe/Berlin]"), zWith.endsWith("[Europe/Berlin]")]
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["types"], []any{true, false, true}) {
			t.Fatalf("unexpected LocalDateTime instanceof checks: %#v", m["types"])
		}
		wantLDT := []any{
			"2026-03-15T10:20:30.123",
			"2026-03-15T12:20:30.123",
			"2026-03-15T10:15:30.123",
			"2026-03-15T08:20:30.123",
			"2026-03-15T10:00:00",
			"2026-03-15T10:45:30.123",
		}
		if !reflect.DeepEqual(m["ldt"], wantLDT) {
			t.Fatalf("unexpected LocalDateTime mutator strings:\ngot:  %#v\nwant: %#v", m["ldt"], wantLDT)
		}
		if !reflect.DeepEqual(m["zdt"], []any{true, true}) {
			t.Fatalf("expected ZonedDateTime [Europe/Berlin] suffix preservation, got %#v", m["zdt"])
		}
	})

	t.Run("TemporalWithChronoFieldAdjustmentsValidationAndUnsupported", func(t *testing.T) {
		got := evalRound56Out(t, `
			LocalDate ld = LocalDate.parse("2026-03-15"); // Sunday (7)
			String ldEpoch = ld.with(ChronoField.EPOCH_DAY, 0).toString();
			String ldProleptic = LocalDate.parse("2026-01-31").with(ChronoField.PROLEPTIC_MONTH, 2026 * 12 + 1).toString(); // Feb 2026 -> clamp 28
			String ldDoy = ld.with(ChronoField.DAY_OF_YEAR, 32).toString();
			String ldDow = ld.with(ChronoField.DAY_OF_WEEK, 1).toString(); // Monday of same ISO week -> 2026-03-09

			LocalTime lt = LocalTime.parse("14:20:30.123456789");
			String ltMilliSec = lt.with(ChronoField.MILLI_OF_SECOND, 500).toString();
			String ltMicroSec = lt.with(ChronoField.MICRO_OF_SECOND, 2500).toString();
			String ltMilliDay = lt.with(ChronoField.MILLI_OF_DAY, 3661500).toString();
			String ltSecDay = lt.with(ChronoField.SECOND_OF_DAY, 3661).toString();
			String ltMinDay = LocalTime.parse("14:20:30").with(ChronoField.MINUTE_OF_DAY, 90).toString();
			String ltHourAmPm = LocalTime.parse("14:20:30").with(ChronoField.HOUR_OF_AMPM, 5).toString(); // PM + 5 -> 17:20:30
			String ltClock24 = LocalTime.parse("14:20:30").with(ChronoField.CLOCK_HOUR_OF_DAY, 24).toString(); // 00:20:30
			String ltAmPm = LocalTime.parse("14:20:30").with(ChronoField.AMPM_OF_DAY, 0).toString(); // 02:20:30

			OffsetDateTime odt = OffsetDateTime.parse("2026-03-15T10:00:00+02:00");
			String odtOff = odt.with(ChronoField.OFFSET_SECONDS, 3600).toString();
			Instant inst = Instant.parse("2026-03-15T10:00:00.500Z");
			String instSec = inst.with(ChronoField.INSTANT_SECONDS, 0).toString();

			int unsupported = 0;
			try { ld.with(ChronoField.HOUR_OF_DAY, 5); } catch (UnsupportedTemporalTypeException e) { unsupported++; }
			try { lt.with(ChronoField.YEAR, 2025); } catch (UnsupportedTemporalTypeException e) { unsupported++; }
			try { LocalDateTime.parse("2026-03-15T10:00:00").with(ChronoField.OFFSET_SECONDS, 0); } catch (UnsupportedTemporalTypeException e) { unsupported++; }
			try { inst.with(ChronoField.YEAR, 2025); } catch (UnsupportedTemporalTypeException e) { unsupported++; }

			int rangeErr = 0;
			try { ld.with(ChronoField.MONTH_OF_YEAR, 13); } catch (DateTimeException e) { rangeErr++; }
			try { ld.with(ChronoField.DAY_OF_WEEK, 8); } catch (DateTimeException e) { rangeErr++; }
			try { lt.with(ChronoField.HOUR_OF_DAY, 24); } catch (DateTimeException e) { rangeErr++; }
			try { lt.with(ChronoField.MINUTE_OF_HOUR, -1); } catch (DateTimeException e) { rangeErr++; }
			try { lt.with(ChronoField.CLOCK_HOUR_OF_DAY, 0); } catch (DateTimeException e) { rangeErr++; }
			try { odt.with(ChronoField.OFFSET_SECONDS, 99999); } catch (DateTimeException e) { rangeErr++; }

			ctx._source.out = [
				'ld': [ldEpoch, ldProleptic, ldDoy, ldDow],
				'lt': [ltMilliSec, ltMicroSec, ltMilliDay, ltSecDay, ltMinDay, ltHourAmPm, ltClock24, ltAmPm],
				'odtOff': odtOff,
				'instSec': instSec,
				'unsupported': unsupported,
				'rangeErr': rangeErr
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["ld"], []any{"1970-01-01", "2026-02-28", "2026-02-01", "2026-03-09"}) {
			t.Fatalf("unexpected LocalDate.with(ChronoField): %#v", m["ld"])
		}
		wantLT := []any{
			"14:20:30.5",
			"14:20:30.0025",
			"01:01:01.5",
			"01:01:01.123456789",
			"01:30:30",
			"17:20:30",
			"00:20:30",
			"02:20:30",
		}
		if !reflect.DeepEqual(m["lt"], wantLT) {
			t.Fatalf("unexpected LocalTime.with(ChronoField):\ngot:  %#v\nwant: %#v", m["lt"], wantLT)
		}
		if m["odtOff"] != "2026-03-15T10:00:00+01:00" {
			t.Fatalf("unexpected OffsetDateTime OFFSET_SECONDS adjustment: %#v", m["odtOff"])
		}
		if m["instSec"] != "1970-01-01T00:00:00.5Z" {
			t.Fatalf("unexpected Instant INSTANT_SECONDS adjustment: %#v", m["instSec"])
		}
		if m["unsupported"] != int64(4) {
			t.Fatalf("expected 4 UnsupportedTemporalTypeExceptions, got %#v", m["unsupported"])
		}
		if m["rangeErr"] != int64(6) {
			t.Fatalf("expected 6 DateTimeExceptions on out-of-range values, got %#v", m["rangeErr"])
		}
	})
}

func TestRound56_F24_NegativeDurationFormattingAndJavaTimeParseExceptions(t *testing.T) {
	t.Run("NegativeMultiPartDurationISO8601AndStringConversions", func(t *testing.T) {
		got := evalRound56Out(t, `
			Duration dNeg90m = Duration.ofMinutes(-90);
			Duration dNegMillis = Duration.ofMillis(-61500);
			Duration dNegSubSec = Duration.ofMillis(-500);
			Duration dParsed1 = Duration.parse("PT-1H-30M");
			Duration dParsed2 = Duration.parse("-PT1H30M");
			Duration dParsed3 = Duration.parse("-PT-1H-30M");

			ctx._source.out = [
				'strs': [
					dNeg90m.toString(),
					dNegMillis.toString(),
					dNegSubSec.toString(),
					String.valueOf(dNeg90m),
					Objects.toString(dNeg90m),
					"dur=" + dNeg90m
				],
				'mins': [
					dParsed1.toMinutes(),
					dParsed2.toMinutes(),
					dParsed3.toMinutes()
				]
			];
		`, nil)
		m := got.(map[string]any)
		wantStrs := []any{
			"PT-1H-30M",
			"PT-1M-1.5S",
			"PT-0.5S",
			"PT-1H-30M",
			"PT-1H-30M",
			"dur=PT-1H-30M",
		}
		if !reflect.DeepEqual(m["strs"], wantStrs) {
			t.Fatalf("unexpected Duration ISO-8601 string formatting:\ngot:  %#v\nwant: %#v", m["strs"], wantStrs)
		}
		if !reflect.DeepEqual(m["mins"], []any{int64(-90), int64(-90), int64(90)}) {
			t.Fatalf("unexpected Duration.parse results: %#v", m["mins"])
		}
	})

	t.Run("JavaTimeParseNullPointerAndDateTimeParseExceptions", func(t *testing.T) {
		got := evalRound56Out(t, `
			String ns = null;
			DateTimeFormatter nf = null;

			int npe = 0;
			try { Instant.parse(ns); } catch (NullPointerException e) { npe++; }
			try { ZonedDateTime.parse(ns); } catch (NullPointerException e) { npe++; }
			try { ZonedDateTime.parse("2026-03-15T10:00:00Z", nf); } catch (NullPointerException e) { npe++; }
			try { OffsetDateTime.parse(ns); } catch (NullPointerException e) { npe++; }
			try { OffsetDateTime.parse("2026-03-15T10:00:00Z", nf); } catch (NullPointerException e) { npe++; }
			try { LocalDateTime.parse(ns); } catch (NullPointerException e) { npe++; }
			try { LocalDateTime.parse("2026-03-15T10:00:00", nf); } catch (NullPointerException e) { npe++; }
			try { LocalDate.parse(ns); } catch (NullPointerException e) { npe++; }
			try { LocalDate.parse("2026-03-15", nf); } catch (NullPointerException e) { npe++; }
			try { LocalTime.parse(ns); } catch (NullPointerException e) { npe++; }
			try { LocalTime.parse("10:00:00", nf); } catch (NullPointerException e) { npe++; }
			try { Year.parse(ns); } catch (NullPointerException e) { npe++; }
			try { YearMonth.parse(ns); } catch (NullPointerException e) { npe++; }
			try { MonthDay.parse(ns); } catch (NullPointerException e) { npe++; }
			try { Duration.parse(ns); } catch (NullPointerException e) { npe++; }
			try { Period.parse(ns); } catch (NullPointerException e) { npe++; }

			int dtpe = 0;
			try { Instant.parse("not-an-instant"); } catch (DateTimeParseException e) { dtpe++; }
			try { Instant.parse("2026-03-15T10:00:00"); } catch (DateTimeParseException e) { dtpe++; }
			try { ZonedDateTime.parse("not-a-zdt"); } catch (DateTimeParseException e) { dtpe++; }
			try { ZonedDateTime.parse("2026-03-15T10:00:00"); } catch (DateTimeParseException e) { dtpe++; }
			try { OffsetDateTime.parse("not-an-odt"); } catch (DateTimeParseException e) { dtpe++; }
			try { OffsetDateTime.parse("2026-03-15T10:00:00"); } catch (DateTimeParseException e) { dtpe++; }
			try { LocalDateTime.parse("not-a-ldt"); } catch (DateTimeParseException e) { dtpe++; }
			try { LocalDateTime.parse("2026-03-15T10:00:00Z"); } catch (DateTimeParseException e) { dtpe++; }
			try { LocalDate.parse("not-a-date"); } catch (DateTimeParseException e) { dtpe++; }
			try { LocalDate.parse("2026-02-30"); } catch (DateTimeParseException e) { dtpe++; }
			try { LocalTime.parse("not-a-time"); } catch (DateTimeParseException e) { dtpe++; }
			try { LocalTime.parse("25:00:00"); } catch (DateTimeParseException e) { dtpe++; }
			try { Year.parse("abcd"); } catch (DateTimeParseException e) { dtpe++; }
			try { YearMonth.parse("2026-13"); } catch (DateTimeParseException e) { dtpe++; }
			try { MonthDay.parse("--02-30"); } catch (DateTimeParseException e) { dtpe++; }
			try { Duration.parse("bad-duration"); } catch (DateTimeParseException e) { dtpe++; }
			try { Period.parse("bad-period"); } catch (DateTimeParseException e) { dtpe++; }

			ctx._source.out = ['npe': npe, 'dtpe': dtpe];
		`, nil)
		m := got.(map[string]any)
		if m["npe"] != int64(16) {
			t.Fatalf("expected 16 NullPointerExceptions from java.time.*.parse, got %#v", m["npe"])
		}
		if m["dtpe"] != int64(17) {
			t.Fatalf("expected 17 DateTimeParseExceptions from java.time.*.parse, got %#v", m["dtpe"])
		}
	})
}

func TestRound56_F25_UserDefinedClassCollectionAndMapStatementDispatch(t *testing.T) {
	got := evalRound56Out(t, `
		class BaseContainer {
			List log = new ArrayList();
			void put(String k, int v) {
				this.log.add("put:" + k + "=" + v);
			}
			void putAll(Map m) {
				this.log.add("putAll:" + m.size());
			}
			void remove(String k) {
				this.log.add("remove1:" + k);
			}
			boolean remove(String k, int v) {
				this.log.add("remove2:" + k + "=" + v);
				return true;
			}
		}

		class SubContainer extends BaseContainer {
			boolean addAll(List items) {
				this.log.add("addAll:" + items.size());
				return true;
			}
			boolean removeAll(List items) {
				this.log.add("removeAll:" + items.size());
				return true;
			}
			boolean retainAll(List items) {
				this.log.add("retainAll:" + items.size());
				return true;
			}
			boolean removeIf(Predicate p) {
				this.log.add("removeIf:" + p.test(5));
				return true;
			}
		}

		SubContainer c = new SubContainer();
		c.put("alpha", 10);
		c.putAll(['x': 1, 'y': 2]);
		c.remove("alpha");
		c.remove("alpha", 10);
		c.addAll([1, 2, 3]);
		c.removeAll([2]);
		c.retainAll([1, 3]);
		c.removeIf(x -> x > 3);

		ctx._source.out = c.log;
	`, nil)
	want := []any{
		"put:alpha=10",
		"putAll:2",
		"remove1:alpha",
		"remove2:alpha=10",
		"addAll:3",
		"removeAll:1",
		"retainAll:2",
		"removeIf:true",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected user-defined statement method dispatch log:\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestRound56_F26_UnmodifiableCollectionsAndMaps(t *testing.T) {
	t.Run("NullRejectionDuplicateKeyChecksAndRegressionGuards", func(t *testing.T) {
		got := evalRound56Out(t, `
			// Regression guards: Set.copyOf deduplicates, Arrays.asList & Stream.of allow null
			int setDedup1 = Set.copyOf(["a", "b", "a"]).size();
			int setDedup2 = Set.copyOf([1, "1", 1L]).size();
			int asListNull = Arrays.asList(null, "x").size();
			long streamNull = Stream.of(null, "x").count();

			int npe = 0;
			List listWithNull = new ArrayList();
			listWithNull.add("a");
			listWithNull.add(null);
			Map mapWithNullVal = new HashMap();
			mapWithNullVal.put("a", null);
			List nullList = null;
			Map nullMap = null;

			try { List.of("a", null); } catch (NullPointerException e) { npe++; }
			try { Set.of("a", null); } catch (NullPointerException e) { npe++; }
			try { List.copyOf(nullList); } catch (NullPointerException e) { npe++; }
			try { List.copyOf(listWithNull); } catch (NullPointerException e) { npe++; }
			try { Set.copyOf(nullList); } catch (NullPointerException e) { npe++; }
			try { Set.copyOf(listWithNull); } catch (NullPointerException e) { npe++; }
			try { Map.copyOf(nullMap); } catch (NullPointerException e) { npe++; }
			try { Map.copyOf(mapWithNullVal); } catch (NullPointerException e) { npe++; }
			try { Map.of(null, 1); } catch (NullPointerException e) { npe++; }
			try { Map.of("a", null); } catch (NullPointerException e) { npe++; }
			try { Map.entry(null, 1); } catch (NullPointerException e) { npe++; }
			try { Map.entry("a", null); } catch (NullPointerException e) { npe++; }
			try { Map.ofEntries(Map.entry("a", 1), null); } catch (NullPointerException e) { npe++; }
			try { listWithNull.stream().collect(Collectors.toUnmodifiableList()); } catch (NullPointerException e) { npe++; }
			try { listWithNull.stream().collect(Collectors.toUnmodifiableSet()); } catch (NullPointerException e) { npe++; }
			try { ["a"].stream().collect(Collectors.toUnmodifiableMap(x -> x, x -> null)); } catch (NullPointerException e) { npe++; }

			int iae = 0;
			try { Map.of("k", 1, "k", 2); } catch (IllegalArgumentException e) { iae++; }
			try { Map.of("oddOnly"); } catch (IllegalArgumentException e) { iae++; }
			try { Map.ofEntries(Map.entry("k", 1), Map.entry("k", 2)); } catch (IllegalArgumentException e) { iae++; }
			try { Set.of("a", "b", "a"); } catch (IllegalArgumentException e) { iae++; }

			ctx._source.out = [
				'reg': [setDedup1, setDedup2, asListNull, streamNull],
				'npe': npe,
				'iae': iae
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["reg"], []any{int64(2), int64(2), int64(2), int64(2)}) {
			t.Fatalf("unexpected regression guard results: %#v", m["reg"])
		}
		if m["npe"] != int64(16) {
			t.Fatalf("expected 16 NullPointerExceptions from unmodifiable factories, got %#v", m["npe"])
		}
		if m["iae"] != int64(4) {
			t.Fatalf("expected 4 IllegalArgumentExceptions from Map.of / Map.ofEntries / Set.of, got %#v", m["iae"])
		}
	})

	t.Run("UnsupportedOperationExceptionOnMutatorsAndMutableBackingPreservation", func(t *testing.T) {
		got := evalRound56Out(t, `
			List emptyImmutable = List.of();
			List immList = List.of(3, 1, 2);
			Set immSet = Set.of("x", "y");
			List copyList = List.copyOf([10, 20]);
			Set copySet = Set.copyOf([10, 20]);
			Map immMap = Map.of("a", 1, "b", 2);
			Map copyMap = Map.copyOf(['a': 1]);
			Map entriesMap = Map.ofEntries(Map.entry("k", 9));
			def entry = Map.entry("ek", 42);

			List colEmptyList = Collections.emptyList();
			Set colEmptySet = Collections.emptySet();
			Map colEmptyMap = Collections.emptyMap();
			List colSingleList = Collections.singletonList("only");
			Set colSingleSet = Collections.singleton("only");
			Map colSingleMap = Collections.singletonMap("k", "v");

			List backingList = new ArrayList();
			backingList.add(1);
			List unmodViewList = Collections.unmodifiableList(backingList);

			Map backingMap = new HashMap();
			backingMap.put("a", 1);
			Map unmodViewMap = Collections.unmodifiableMap(backingMap);

			List streamImmList = [1, 2].stream().collect(Collectors.toUnmodifiableList());
			Set streamImmSet = [1, 2].stream().collect(Collectors.toUnmodifiableSet());
			Map streamImmMap = ["a", "b"].stream().collect(Collectors.toUnmodifiableMap(x -> x, x -> x.length()));

			int uoe = 0;
			// Empty immutable list has distinct pointer from fresh mutable ArrayList
			try { emptyImmutable.add(1); } catch (UnsupportedOperationException e) { uoe++; }
			List freshMutable = new ArrayList();
			freshMutable.add(99);

			// List mutators (statement & expression level)
			try { immList.add(4); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList.set(0, 9); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList.remove(0); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList.clear(); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList.addAll([5]); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList.removeAll([1]); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList.retainAll([1]); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList.removeIf(x -> x > 0); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList.replaceAll(x -> x + 1); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList.sort((a, b) -> Integer.compare(a, b)); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList[0] = 99; } catch (UnsupportedOperationException e) { uoe++; }
			try { Collections.sort(immList); } catch (UnsupportedOperationException e) { uoe++; }
			try { Collections.reverse(immList); } catch (UnsupportedOperationException e) { uoe++; }
			try { Collections.fill(immList, 0); } catch (UnsupportedOperationException e) { uoe++; }
			try { Collections.addAll(immList, 7); } catch (UnsupportedOperationException e) { uoe++; }
			try { immList.subList(0, 2).clear(); } catch (UnsupportedOperationException e) { uoe++; }

			// Set / copyOf / Collections / Collectors mutators
			try { immSet.add("z"); } catch (UnsupportedOperationException e) { uoe++; }
			try { copyList.add(30); } catch (UnsupportedOperationException e) { uoe++; }
			try { copySet.clear(); } catch (UnsupportedOperationException e) { uoe++; }
			try { colEmptyList.add(1); } catch (UnsupportedOperationException e) { uoe++; }
			try { colEmptySet.add(1); } catch (UnsupportedOperationException e) { uoe++; }
			try { colSingleList.set(0, "no"); } catch (UnsupportedOperationException e) { uoe++; }
			try { colSingleSet.remove("only"); } catch (UnsupportedOperationException e) { uoe++; }
			try { unmodViewList.add(2); } catch (UnsupportedOperationException e) { uoe++; }
			try { streamImmList.add(3); } catch (UnsupportedOperationException e) { uoe++; }
			try { streamImmSet.clear(); } catch (UnsupportedOperationException e) { uoe++; }

			// Map & Map.Entry mutators
			try { immMap.put("c", 3); } catch (UnsupportedOperationException e) { uoe++; }
			try { immMap.putAll(['d': 4]); } catch (UnsupportedOperationException e) { uoe++; }
			try { immMap.remove("a"); } catch (UnsupportedOperationException e) { uoe++; }
			try { immMap.remove("a", 1); } catch (UnsupportedOperationException e) { uoe++; }
			try { immMap.clear(); } catch (UnsupportedOperationException e) { uoe++; }
			try { immMap.replace("a", 99); } catch (UnsupportedOperationException e) { uoe++; }
			try { immMap.putIfAbsent("c", 3); } catch (UnsupportedOperationException e) { uoe++; }
			try { immMap.computeIfAbsent("c", k -> 3); } catch (UnsupportedOperationException e) { uoe++; }
			try { immMap.merge("a", 5, (x, y) -> x + y); } catch (UnsupportedOperationException e) { uoe++; }
			try { immMap['a'] = 99; } catch (UnsupportedOperationException e) { uoe++; }
			try { copyMap.put("b", 2); } catch (UnsupportedOperationException e) { uoe++; }
			try { entriesMap.clear(); } catch (UnsupportedOperationException e) { uoe++; }
			try { entry.setValue(100); } catch (UnsupportedOperationException e) { uoe++; }
			try { colEmptyMap.put("a", 1); } catch (UnsupportedOperationException e) { uoe++; }
			try { colSingleMap.remove("k"); } catch (UnsupportedOperationException e) { uoe++; }
			try { unmodViewMap.put("b", 2); } catch (UnsupportedOperationException e) { uoe++; }
			try { streamImmMap.put("c", 1); } catch (UnsupportedOperationException e) { uoe++; }

			// Backing mutable list & map remain mutable after Collections.unmodifiable*
			backingList.add(2);
			backingMap.put("b", 2);

			ctx._source.out = [
				'uoe': uoe,
				'freshSize': freshMutable.size(),
				'backingListSize': backingList.size(),
				'backingMapSize': backingMap.size()
			];
		`, nil)
		m := got.(map[string]any)
		if m["uoe"] != int64(44) {
			t.Fatalf("expected 44 UnsupportedOperationExceptions across unmodifiable containers, got %#v", m["uoe"])
		}
		if m["freshSize"] != int64(1) || m["backingListSize"] != int64(2) || m["backingMapSize"] != int64(2) {
			t.Fatalf("expected mutable containers to remain mutable, got %#v", m)
		}

		// Also verify uncaught UnsupportedOperationException surfaces cleanly from Eval
		assertRound56EvalErr(t, `List x = List.of(1, 2); x.add(3);`, nil, "UnsupportedOperationException")
		assertRound56EvalErr(t, `Map m = Map.of("a", 1); m.put("b", 2);`, nil, "UnsupportedOperationException")
	})
}

func TestRound56_AdditionalNumericAndTemporalFormatterBranches(t *testing.T) {
	params := map[string]any{
		"f32":    float32(2.5),
		"f32NaN": float32(math.NaN()),
		"f32Inf": float32(math.Inf(1)),
		"f32Neg": float32(math.Inf(-1)),
		"i":      int(42),
		"i32":    int32(32),
		"i16":    int16(16),
		"i8":     int8(8),
		"u":      uint(7),
		"u64":    uint64(64),
		"u32":    uint32(32),
		"u16":    uint16(16),
		"u8":     uint8(8),
		"jnum":   json.Number("123.5"),
		"jint":   json.Number("99"),
		"bigI":   big.NewInt(777),
	}
	got := evalRound56Out(t, `
		double sumTypes = Double.valueOf(params.f32) + Double.valueOf(params.i) +
			Double.valueOf(params.i32) + Double.valueOf(params.i16) + Double.valueOf(params.i8) +
			Double.valueOf(params.u) + Double.valueOf(params.u64) + Double.valueOf(params.u32) +
			Double.valueOf(params.u16) + Double.valueOf(params.u8) + Double.valueOf(params.jnum) +
			Double.valueOf(params.bigI) + Double.valueOf(new BigDecimal("1.5")) + Double.valueOf(new BigInteger("10"));
		String f32Strs = String.valueOf(params.f32) + "|" + String.valueOf(params.f32NaN) + "|" +
			String.valueOf(params.f32Inf) + "|" + String.valueOf(params.f32Neg);
		String ovf32Pos = Float.toString(1e300);
		String ovf32Neg = Float.toString(-1e300);
		double fValInf = Float.valueOf(1e300);
		double fParseNum = Float.parseFloat(params.f32);
		double fUnder = Float.parseFloat("1e-60");
		double fHex = Double.parseDouble("0x1.0p2f");

		int boxedInt = Integer.valueOf(params.i);
		int boxedI32 = Integer.valueOf(params.i32);
		int boxedI16 = Short.valueOf(params.i16);
		int boxedI8 = Byte.valueOf(params.i8);
		long boxedLong = Long.valueOf(100L);
		int boxedF64 = Integer.valueOf(12.0);
		int boxedF32 = Integer.valueOf(params.f32);
		int boxedJInt = Integer.valueOf(params.jint);
		int boxedJNum = Integer.valueOf(params.jnum);
		int radFloat = Integer.parseInt("ff", 16.0);
		int uPlus = Integer.parseUnsignedInt("+42", 10);

		int radNpe = 0;
		try { Integer.parseInt("10", null); } catch (NullPointerException e) { radNpe++; }

		DateTimeFormatter yFmt = DateTimeFormatter.ofPattern("yyyy");
		DateTimeFormatter ymFmt = DateTimeFormatter.ofPattern("yyyy/MM");
		DateTimeFormatter mdFmt = DateTimeFormatter.ofPattern("MM/dd");
		DateTimeFormatter ldFmt = DateTimeFormatter.ofPattern("yyyy/MM/dd");
		DateTimeFormatter ltFmt = DateTimeFormatter.ofPattern("HH:mm:ss");
		DateTimeFormatter ldtFmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
		DateTimeFormatter odtFmt = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
		Year yParsed = Year.parse("2025", yFmt);
		def ymParsed = YearMonth.parse("2025/08", ymFmt);
		MonthDay mdParsed = MonthDay.parse("02/29", mdFmt);
		def ldParsed = LocalDate.parse("2025/08/19", ldFmt);
		def ltParsed = LocalTime.parse("14:30:05", ltFmt);
		def ldtParsed = LocalDateTime.parse("2025-08-19 14:30:05", ldtFmt);
		def odtParsed = OffsetDateTime.parse("2025-08-19T14:30:05+02:00", odtFmt);
		def zdtParsedFmt = ZonedDateTime.parse("2025-08-19T14:30:05+02:00[UTC+02:00]", odtFmt);
		def zdtUTC = ZonedDateTime.parse("2025-08-19T14:30:05Z[UTC]");
		def zdtOff = ZonedDateTime.parse("2025-08-19T14:30:05+02:00[+02:00]");
		def zdtIANA = ZonedDateTime.parse("2025-08-19T14:30:05-04:00[America/New_York]");

		Duration dComplex = Duration.parse("+P2DT+3H-4M+5,25S");
		Period pComplex = Period.parse("-P1Y+2M-3W+4D");

		int dtErrs = 0;
		try { ZonedDateTime.parse("2025-08-19T14:30:05Z[Invalid/Zone_X]"); } catch (DateTimeParseException e) { dtErrs++; }
		try { ZonedDateTime.parse("2025-08-19T14:30:05Z[GMT+99:99]"); } catch (DateTimeParseException e) { dtErrs++; }
		try { LocalDate.parse("", ldFmt); } catch (DateTimeParseException e) { dtErrs++; }
		try { LocalDate.parse("2025-08-19", null); } catch (NullPointerException e) { dtErrs++; }
		try { Duration.parse("PT1.5H"); } catch (DateTimeParseException e) { dtErrs++; }
		try { Duration.parse("PT1..5S"); } catch (DateTimeParseException e) { dtErrs++; }
		try { Duration.parse("PT"); } catch (DateTimeParseException e) { dtErrs++; }
		try { Period.parse("P1YT2H"); } catch (DateTimeParseException e) { dtErrs++; }
		try { Period.parse("P1D2Y"); } catch (DateTimeParseException e) { dtErrs++; }

		def stats = DoubleStream.of(1.0, 3.0).summaryStatistics();
		String statsStr = String.valueOf(stats);
		String excStr = "";
		try { Integer.parseInt("bad"); } catch (NumberFormatException e) { excStr = String.valueOf(e); }

		ctx._source.out = [
			'sumOk': sumTypes > 1000.0,
			'f32Strs': f32Strs,
			'ovf': [ovf32Pos, ovf32Neg, Double.isInfinite(fValInf), fParseNum, fUnder, fHex],
			'boxed': [boxedInt, boxedI32, boxedI16, boxedI8, boxedLong, boxedF64, boxedF32, boxedJInt, boxedJNum, radFloat, uPlus, radNpe],
			'dt': [yParsed.getValue(), ymParsed.toString(), mdParsed.toString(), ldParsed.toString(), ltParsed.toString(), ldtParsed.toString(), odtParsed != null, zdtParsedFmt != null, zdtUTC != null, zdtOff != null, zdtIANA != null],
			'durSec': dComplex.getSeconds(),
			'perMonths': pComplex.getMonths(),
			'dtErrs': dtErrs,
			'statsOk': statsStr.contains("DoubleSummaryStatistics"),
			'excOk': excStr.contains("NumberFormatException")
		];
	`, params)
	m := got.(map[string]any)
	if m["sumOk"] != true || m["f32Strs"] != "2.5|NaN|Infinity|-Infinity" {
		t.Fatalf("unexpected float conversion result: %#v", m)
	}
	if m["dtErrs"] != int64(9) || m["statsOk"] != true || m["excOk"] != true {
		t.Fatalf("unexpected formatter/exception result: %#v", m)
	}
}
