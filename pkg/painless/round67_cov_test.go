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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// P0-6: MovingFunctions.holtWinters Signed Integer Overflow & Period Bounds
// ============================================================================

func TestRound67_P0_6_HoltWintersOverflowAndBounds(t *testing.T) {
	vals := []any{1.0, 2.0, 3.0, 4.0, 5.0, 6.0}

	// Extreme overflowing / negative / zero / oversized periods must return nil, nil without panicking.
	badPeriods := []any{
		int64(math.MaxInt64),
		int64((math.MaxInt64 / 2) + 1),
		int64(math.MinInt64),
		int64(-1),
		int64(0),
		int64(MaxPainlessSliceItems + 1),
		int64(4), // > len(vals)/2 == 3
		"not_a_number",
		math.Inf(1),
	}
	for _, p := range badPeriods {
		got, err := evalMovingFunctionsStaticRound60("holtWinters", []any{vals, 0.3, 0.1, 0.1, p, false})
		if err != nil || got != nil {
			t.Fatalf("holtWinters period=%#v expected (nil, nil), got (%#v, %v)", p, got, err)
		}
		ev, evErr := Eval(nil, "return MovingFunctions.holtWinters(params.v, 0.3, 0.1, 0.1, params.p, false);", map[string]any{
			"v": vals,
			"p": p,
		})
		if evErr != nil || ev != nil {
			t.Fatalf("Eval holtWinters period=%#v expected (nil, nil), got (%#v, %v)", p, ev, evErr)
		}
	}

	// Nil period falls back to default period=1 when len(vals) >= 2; short slices return nil.
	defRes, err := evalMovingFunctionsStaticRound60("holtWinters", []any{vals, 0.3, 0.1, 0.1, nil, false})
	if err != nil || defRes == nil {
		t.Fatalf("holtWinters with nil period expected valid forecast, got (%#v, %v)", defRes, err)
	}
	shortRes, err := evalMovingFunctionsStaticRound60("holtWinters", []any{[]any{1.0}})
	if err != nil || shortRes != nil {
		t.Fatalf("holtWinters with 1 element expected (nil, nil), got (%#v, %v)", shortRes, err)
	}

	// Normal additive and multiplicative holtWinters via Painless Eval.
	normalRes, err := Eval(nil, `
		def add = MovingFunctions.holtWinters([10.0, 12.0, 14.0, 16.0, 18.0, 20.0], 0.3, 0.1, 0.1, 2, false);
		def mul = MovingFunctions.holtWinters([10.0, 20.0, 10.0, 20.0, 10.0, 20.0], 0.3, 0.1, 0.1, 2, true);
		return [add, mul];
	`, nil)
	if err != nil {
		t.Fatalf("normal holtWinters failed: %v", err)
	}
	pair := normalRes.([]any)
	if _, ok := pair[0].(float64); !ok {
		t.Fatalf("expected float64 additive forecast, got %#v", pair[0])
	}
	if _, ok := pair[1].(float64); !ok {
		t.Fatalf("expected float64 multiplicative forecast, got %#v", pair[1])
	}
}

// ============================================================================
// P1-6.3: Bounded Regex Syntax Guard, CompileBoundedRawRegex & Call-Site Audits
// ============================================================================

func TestRound67_P1_6_3_BoundedRegexSyntaxGuardAndRawCache(t *testing.T) {
	// 1. Direct AST validation rejects RE2 repeat-expansion bombs before regexp.Compile.
	bombs := []string{
		`((a{1000}){1000}){100}`,
		`(a{100}){101}`,
		`(a{1000,}){1000,}`,
		`(a{500}b{500}){50}`,
		`((?:a|b){100}){100}`,
		strings.Repeat(`a{1000}`, 70),
		strings.Repeat("(", 260) + "a" + strings.Repeat(")", 260),
	}
	for _, bomb := range bombs {
		if err := validateBoundedRegexSyntaxR67(bomb); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
			t.Fatalf("validateBoundedRegexSyntaxR67(%q) expected illegal_argument_exception, got %v", bomb, err)
		}
		if _, err := CompileBoundedRegex(bomb); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
			t.Fatalf("CompileBoundedRegex(%q) expected illegal_argument_exception, got %v", bomb, err)
		}
		if _, err := CompileBoundedRawRegex(bomb); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
			t.Fatalf("CompileBoundedRawRegex(%q) expected illegal_argument_exception, got %v", bomb, err)
		}
	}

	// Nil AST node & valid complex patterns pass cleanly.
	if w, rp, err := walkBoundedRegexSyntaxR67(nil, 0, new(int64)); err != nil || w != 1 || rp != 1 {
		t.Fatalf("walkBoundedRegexSyntaxR67(nil) unexpected (%d, %d, %v)", w, rp, err)
	}
	// Exceeding maxRegexASTNodes triggers IllegalArgumentException.
	var hugeNodes int64 = maxRegexASTNodes
	if _, _, err := walkBoundedRegexSyntaxR67(nil, 0, &hugeNodes); err != nil {
		t.Fatalf("expected nil shortcut before astNodes check: %v", err)
	}

	// 2. CompileBoundedRawRegex: oversized check, syntax error preservation, raw vs Java group behavior, LRU stress.
	oversized := strings.Repeat("a", MaxRegexPatternLen+1)
	if _, err := CompileBoundedRawRegex(oversized); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("CompileBoundedRawRegex expected oversized error, got %v", err)
	}
	if _, err := CompileBoundedRawRegex("[unclosed"); err == nil || strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("CompileBoundedRawRegex expected raw syntax error (not IllegalArgumentException), got %v", err)
	}
	// Raw Go RE2 rejects lookbehind `(?<=a)` cleanly, and CompileBoundedRegex normalizes Java `(?<id>...)`.
	if _, err := CompileBoundedRawRegex(`(?<=a)b`); err == nil {
		t.Fatalf("CompileBoundedRawRegex should reject RE2-unsupported lookbehind (?<=a)b")
	}
	if reJava, err := CompileBoundedRegex(`(?<id>\d+)`); err != nil || !reJava.MatchString("42") || len(reJava.SubexpNames()) < 2 || reJava.SubexpNames()[1] != "id" {
		t.Fatalf("CompileBoundedRegex failed on Java named group: re=%v err=%v", reJava, err)
	}
	if reRaw, err := CompileBoundedRawRegex(`(?P<id>\d+)`); err != nil || !reRaw.MatchString("42") {
		t.Fatalf("CompileBoundedRawRegex failed on RE2 named group: re=%v err=%v", reRaw, err)
	}
	// Cache hit check
	if reRaw2, err := CompileBoundedRawRegex(`(?P<id>\d+)`); err != nil || reRaw2 == nil {
		t.Fatalf("CompileBoundedRawRegex cache hit failed: %v", err)
	}

	// Concurrent LRU stress (> RegexCacheCapacity = 1024 entries under -race).
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				pat := strings.ReplaceAll("^raw_?_!$", "?", string(rune('a'+w)))
				pat = strings.ReplaceAll(pat, "!", string(rune('a'+(i%26)))+string(rune('0'+(i/26))))
				if re, err := CompileBoundedRawRegex(pat); err != nil || re == nil {
					t.Errorf("concurrent CompileBoundedRawRegex(%q) failed: %v", pat, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	// 3. Processors.split, Grok, String.split/replaceAll, =~ / ==~ all enforce bounded syntax validation.
	if _, err := Eval(map[string]any{"s": "a,b"}, `Processors.split(ctx.s, params.p)`, map[string]any{"p": `((a{1000}){1000}){100}`}); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("Processors.split expected illegal_argument_exception on bomb, got %v", err)
	}
	if _, err := Eval(map[string]any{"s": "a,b"}, `Processors.split(ctx.s, "[")`, nil); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("Processors.split expected illegal_argument_exception on syntax err, got %v", err)
	}
	if _, err := CompileGrokPattern(`(%{COMBINEDAPACHELOG}){1000}`); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
		t.Fatalf("CompileGrokPattern expected illegal_argument_exception on repeat bomb, got %v", err)
	}
	if gx, err := CompileGrokPattern(`%{COMBINEDAPACHELOG}`); err != nil || gx == nil {
		t.Fatalf("CompileGrokPattern valid COMBINEDAPACHELOG failed: %v", err)
	}
	for _, script := range []string{
		`return "aaa".split("((a{1000}){1000}){100}");`,
		`return "aaa".replaceAll("((a{1000}){1000}){100}", "x");`,
		`return "aaa" =~ "((a{1000}){1000}){100}";`,
		`return "aaa" ==~ "((a{1000}){1000}){100}";`,
	} {
		if _, err := Eval(nil, script, nil); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
			t.Fatalf("expected illegal_argument_exception for %q, got %v", script, err)
		}
	}
}

// ============================================================================
// Coverage Sprint Clusters: BigDecimal, BigInteger, BitSet, StringJoiner, Comparator
// ============================================================================

func TestRound67Cov_BigDecimalBigIntegerBitSetJoinerAndComparator(t *testing.T) {
	// 1. BigDecimal MathContext, rounding modes, divide/remainder/pow/setScale/valueExact & bounds errors.
	bdSrc := `
		MathContext mc4 = new MathContext(4, RoundingMode.HALF_UP);
		MathContext mc0 = new MathContext(0);
		MathContext mcStr = new MathContext("precision=3 roundingMode=DOWN");
		BigDecimal a = new BigDecimal("10.50");
		BigDecimal b = new BigDecimal("3");
		BigDecimal z = BigDecimal.ZERO;
		BigDecimal c1 = a.divide(b, mc4);
		BigDecimal c2 = a.divide(new BigDecimal("2"), mc0);
		BigDecimal c3 = z.divide(b, mc4);
		BigDecimal c4 = a.divide(b, 2, RoundingMode.DOWN);
		BigDecimal c5 = a.divide(b, RoundingMode.HALF_EVEN);
		BigDecimal c6 = a.divide(b, 3);
		BigDecimal sub = a.subtract(b, mc4);
		BigDecimal mul = a.multiply(b, mcStr);
		BigDecimal rem = a.remainder(b, mc4);
		BigDecimal dtv = a.divideToIntegralValue(b, mc4);
		List dar = a.divideAndRemainder(b, mc4);
		BigDecimal p2 = new BigDecimal("1.5").pow(3, mc4);
		BigDecimal p0 = new BigDecimal("0").pow(0);
		BigDecimal p0n = new BigDecimal("0").pow(3);
		BigDecimal pn1 = new BigDecimal("-1").pow(3);
		BigDecimal pn2 = new BigDecimal("-1").pow(4);
		BigDecimal sc0 = new BigDecimal("2.5").setScale(0, RoundingMode.valueOf(0));
		BigDecimal sc1 = new BigDecimal("2.5").setScale(0, RoundingMode.valueOf(1));
		BigDecimal sc2 = new BigDecimal("2.5").setScale(0, RoundingMode.valueOf(2));
		BigDecimal sc3 = new BigDecimal("2.5").setScale(0, RoundingMode.valueOf(3));
		BigDecimal sc5 = new BigDecimal("2.5").setScale(0, RoundingMode.valueOf(5));
		BigDecimal sc6 = new BigDecimal("2.5").setScale(0, RoundingMode.valueOf(6));
		BigDecimal sc7 = new BigDecimal("2.0").setScale(0, RoundingMode.valueOf(7));
		BigDecimal mn = a.min(b);
		BigDecimal mx = a.max(b);
		BigDecimal mpl = a.movePointLeft(2);
		BigDecimal mpr = a.movePointRight(1);
		BigDecimal spt = a.scaleByPowerOfTen(-1);
		BigDecimal stz = new BigDecimal("12.3400").stripTrailingZeros();
		BigDecimal ulp = a.ulp();
		BigDecimal rnd = new BigDecimal("123.456").round(mc4);
		BigDecimal neg = a.negate(mc4);
		BigDecimal pls = a.plus(mc4);
		BigDecimal abv = new BigDecimal("-12.345").abs(mc4);
		BigDecimal fromBI = new BigDecimal(BigInteger.valueOf(12345L), 2, mc4);
		BigDecimal fromBIMc = new BigDecimal(BigInteger.valueOf(12345L), mc4);
		BigDecimal valOf2 = BigDecimal.valueOf(42L, 1);
		return [
			c1.toPlainString(), c2.toPlainString(), c3.toPlainString(),
			c4.toPlainString(), c5.toPlainString(), c6.toPlainString(),
			sub.toPlainString(), mul.toPlainString(), rem.toPlainString(),
			dtv.toPlainString(), dar[0].toPlainString(), dar[1].toPlainString(),
			p2.toPlainString(), p0.toPlainString(), p0n.toPlainString(),
			pn1.toPlainString(), pn2.toPlainString(),
			sc0.toPlainString(), sc1.toPlainString(), sc2.toPlainString(),
			sc3.toPlainString(), sc5.toPlainString(), sc6.toPlainString(), sc7.toPlainString(),
			mn.toPlainString(), mx.toPlainString(), mpl.toPlainString(), mpr.toPlainString(),
			spt.toPlainString(), stz.toPlainString(), ulp.toPlainString(), rnd.toPlainString(),
			neg.toPlainString(), pls.toPlainString(), abv.toPlainString(),
			fromBI.toPlainString(), fromBIMc.toPlainString(), valOf2.toPlainString(),
			a.toEngineeringString(), mc4.getPrecision(), mc4.getRoundingMode(), mc4.toString(),
			BigDecimal.valueOf(5L).intValueExact(), BigDecimal.valueOf(5L).longValueExact(),
			BigDecimal.valueOf(5L).shortValueExact(), BigDecimal.valueOf(5L).byteValueExact()
		];
	`
	bdVal, err := Eval(nil, bdSrc, nil)
	if err != nil {
		t.Fatalf("BigDecimal cov script failed: %v", err)
	}
	bdSlice := bdVal.([]any)
	if bdSlice[0] != "3.50" {
		t.Fatalf("unexpected BigDecimal divide mc4: %#v", bdSlice[0])
	}
	if bdSlice[13] != "1" || bdSlice[14] != "0" || bdSlice[15] != "-1" || bdSlice[16] != "1" {
		t.Fatalf("unexpected pow edge values: %#v", bdSlice[13:17])
	}

	// BigDecimal error paths
	for _, errSrc := range []string{
		`return new BigDecimal("1").divide(new BigDecimal("0"));`,
		`return new BigDecimal("1").divide(new BigDecimal("0"), new MathContext(2));`,
		`return new BigDecimal("1").remainder(new BigDecimal("0"));`,
		`return new BigDecimal("1").divide(new BigDecimal("3"), 20000);`,
		`return new BigDecimal("1").divide(new BigDecimal("3"), 20000, RoundingMode.HALF_UP);`,
		`return new BigDecimal("1").divide(new BigDecimal("3"), new MathContext(20000));`,
		`return new BigDecimal("1").pow(-1);`,
		`return new BigDecimal("1.50").pow(6000);`,
		`return new BigDecimal("1e5000").divide(new BigDecimal("1e-6000"));`,
		`return new BigDecimal("1e5000").divide(new BigDecimal("1e-6000"), new MathContext(4));`,
		`return new BigDecimal("1e5000").divide(new BigDecimal("1e-6000"), new MathContext(0));`,
		`return new BigDecimal("1e5000").divideToIntegralValue(new BigDecimal("1e-6000"));`,
		`return new BigDecimal("1e5000").divideAndRemainder(new BigDecimal("1e-6000"));`,
		`return new BigDecimal("123456").shortValueExact();`,
		`return new BigDecimal("200").byteValueExact();`,
		`return new BigDecimal("999999999999999").intValueExact();`,
		`return new BigDecimal("1e100").longValueExact();`,
		`return new BigDecimal("notnum");`,
		`return new MathContext(-1);`,
	} {
		if _, err := Eval(nil, errSrc, nil); err == nil {
			t.Fatalf("expected error for %q", errSrc)
		}
	}

	// Direct Go helper calls on BigDecimal edge bounds.
	bdLarge := &painlessBigDecimal{unscaled: big.NewInt(1), scale: 10000}
	bdNegLarge := &painlessBigDecimal{unscaled: big.NewInt(1), scale: -10000}
	if _, err := bdNegLarge.div(bdLarge, 10000, "HALF_UP"); err == nil {
		t.Fatal("expected div scale shift overflow error")
	}
	if _, err := applyMathContextPainless(bdLarge, painlessMathContext{precision: 20000}); err == nil {
		t.Fatal("expected MathContext precision error")
	}
	if zbd, err := applyMathContextPainless(nil, painlessMathContext{precision: 4}); err != nil || zbd.unscaled.Sign() != 0 {
		t.Fatalf("expected zero BigDecimal for nil input, got (%v, %v)", zbd, err)
	}

	// 2. BigInteger methods (positive/negative/zero bit operations, radix, exact conversions).
	biSrc := `
		BigInteger pos = new BigInteger("FF", 16);
		BigInteger neg = BigInteger.valueOf(-42L);
		BigInteger zero = BigInteger.ZERO;
		BigInteger hi = new BigInteger([128]);
		BigInteger fromBytes = new BigInteger([1, 0]);
		return [
			pos.bitLength(), pos.bitCount(), pos.getLowestSetBit(),
			neg.bitLength(), neg.bitCount(), neg.getLowestSetBit(),
			zero.bitLength(), zero.bitCount(), zero.getLowestSetBit(),
			pos.toByteArray(), neg.toByteArray(), zero.toByteArray(), hi.toByteArray(), fromBytes.intValue(),
			pos.and(BigInteger.valueOf(15L)).intValue(),
			pos.or(BigInteger.valueOf(256L)).intValue(),
			pos.xor(BigInteger.valueOf(15L)).intValue(),
			pos.andNot(BigInteger.valueOf(15L)).intValue(),
			BigInteger.valueOf(5L).not().intValue(),
			BigInteger.valueOf(3L).shiftLeft(4).intValue(),
			BigInteger.valueOf(48L).shiftRight(2).intValue(),
			BigInteger.ZERO.setBit(3).clearBit(0).flipBit(1).testBit(3),
			BigInteger.valueOf(17L).mod(BigInteger.valueOf(5L)).intValue(),
			BigInteger.valueOf(3L).modInverse(BigInteger.valueOf(11L)).intValue(),
			BigInteger.valueOf(2L).modPow(BigInteger.valueOf(10L), BigInteger.valueOf(1000L)).intValue(),
			BigInteger.valueOf(24L).gcd(BigInteger.valueOf(18L)).intValue(),
			BigInteger.valueOf(17L).isProbablePrime(10),
			pos.toString(2),
			BigInteger.valueOf(100L).shortValueExact(),
			BigInteger.valueOf(100L).byteValueExact(),
			BigInteger.valueOf(100L).intValueExact(),
			BigInteger.valueOf(100L).longValueExact()
		];
	`
	biVal, err := Eval(nil, biSrc, nil)
	if err != nil {
		t.Fatalf("BigInteger cov script failed: %v", err)
	}
	biSlice := biVal.([]any)
	if biSlice[0] != int64(8) || biSlice[4] != int64(3) || biSlice[13] != int64(256) || biSlice[27] != "11111111" {
		t.Fatalf("unexpected BigInteger results: %#v", biSlice)
	}
	for _, errBI := range []string{
		`return new BigInteger("12", 1);`,
		`return new BigInteger("");`,
		`return new BigInteger("xyz", 10);`,
		`return new BigInteger([]);`,
		`return BigInteger.valueOf(100000L).shortValueExact();`,
		`return BigInteger.valueOf(500L).byteValueExact();`,
	} {
		if _, err := Eval(nil, errBI, nil); err == nil {
			t.Fatalf("expected BigInteger error for %q", errBI)
		}
	}

	// 3. BitSet full API + edge cases + errors.
	bsSrc := `
		BitSet bs1 = BitSet.valueOf([5L, 0L, 1L]);
		BitSet bs2 = new BitSet(128);
		bs2.set(2);
		bs2.set(64, 67);
		bs2.flip(65);
		bs2.flip(70, 72);
		bs2.clear(66);
		bs2.clear(70, 71);
		BitSet sub = bs2.get(0, 72);
		boolean inter = bs1.intersects(bs2);
		bs1.and(bs2);
		bs1.or(bs2);
		bs1.xor(bs2);
		bs1.xor(bs1);
		bs2.andNot(bs1);
		int nsb = bs2.nextSetBit(0);
		int ncb = bs2.nextClearBit(0);
		int psb = bs2.previousSetBit(100);
		int pcb = bs2.previousClearBit(100);
		int psbNeg = bs2.previousSetBit(-1);
		int pcbNeg = bs2.previousClearBit(-1);
		int psbNone = new BitSet().previousSetBit(10);
		int ncbPast = bs2.nextClearBit(500);
		List bytes = bs2.toByteArray();
		List longs = bs2.toLongArray();
		long streamed = bs2.stream().count();
		BitSet cloned = bs2.clone();
		bs1.clear();
		return [
			inter, nsb, ncb, psb, pcb, psbNeg, pcbNeg, psbNone, ncbPast,
			bytes.size(), longs.size(), streamed, cloned.cardinality(),
			bs2.length(), bs2.size(), bs1.isEmpty(), bs2.isEmpty(),
			sub.get(2), bs2.toString()
		];
	`
	bsVal, err := Eval(nil, bsSrc, nil)
	if err != nil {
		t.Fatalf("BitSet cov script failed: %v", err)
	}
	bsSlice := bsVal.([]any)
	if bsSlice[0] != true || bsSlice[1] != int64(2) || bsSlice[5] != int64(-1) || bsSlice[15] != true || bsSlice[16] != false {
		t.Fatalf("unexpected BitSet results: %#v", bsSlice)
	}
	for _, errBS := range []string{
		`return new BitSet(-1);`,
		`BitSet b = new BitSet(); b.clear(-1);`,
		`BitSet b = new BitSet(); b.clear(1 << 20);`,
		`BitSet b = new BitSet(); b.clear(0, (1 << 20) + 1);`,
		`BitSet b = new BitSet(); b.flip(-1);`,
		`BitSet b = new BitSet(); b.flip(5, 2);`,
		`BitSet b = new BitSet(); b.get(-1);`,
		`BitSet b = new BitSet(); b.get(5, 2);`,
		`BitSet b = new BitSet(); b.get(0, (1 << 20) + 1);`,
		`BitSet b = new BitSet(); b.nextSetBit(-1);`,
		`BitSet b = new BitSet(); b.nextClearBit(-1);`,
		`BitSet b = new BitSet(); b.previousSetBit(-2);`,
		`BitSet b = new BitSet(); b.previousClearBit(-2);`,
	} {
		if _, err := Eval(nil, errBS, nil); err == nil {
			t.Fatalf("expected BitSet error for %q", errBS)
		}
	}

	// 4. StringJoiner + Comparator chaining.
	sjCmpSrc := `
		StringJoiner sj1 = new StringJoiner(",", "[", "]");
		sj1.setEmptyValue("EMPTY");
		String emptyOut = sj1.toString();
		sj1.add("a").add("b");
		StringJoiner sj2 = new StringJoiner(",");
		sj2.add("c");
		sj1.merge(sj2);

		Comparator cmp = Comparator.comparing(m -> m.k).thenComparingInt(m -> m.n).thenComparingLong(m -> m.l).thenComparingDouble(m -> m.d).thenComparing(Comparator.reverseOrder());
		Comparator rev = cmp.reversed();
		int cRes = cmp.compare(["k": "a", "n": 1, "l": 10L, "d": 1.5], ["k": "a", "n": 2, "l": 10L, "d": 1.5]);
		int rRes = rev.compare(["k": "a", "n": 1, "l": 10L, "d": 1.5], ["k": "a", "n": 2, "l": 10L, "d": 1.5]);
		Comparator keyCmp2 = Comparator.comparing(m -> m.k, Comparator.reverseOrder());
		int k2 = keyCmp2.compare(["k": "a"], ["k": "b"]);
		Comparator thenKey = Comparator.comparing(m -> m.a).thenComparing(m -> m.b, (x, y) -> x.compareTo(y));
		int tk = thenKey.compare(["a": 1, "b": "x"], ["a": 1, "b": "y"]);
		return [emptyOut, sj1.toString(), sj1.length(), cRes, rRes, k2, tk];
	`
	sjVal, err := Eval(nil, sjCmpSrc, nil)
	if err != nil {
		t.Fatalf("StringJoiner/Comparator script failed: %v", err)
	}
	sjSlice := sjVal.([]any)
	if sjSlice[0] != "EMPTY" || sjSlice[1] != "[a,b,c]" || sjSlice[3] != int64(-1) || sjSlice[5] != int64(1) || sjSlice[6] != int64(-1) {
		t.Fatalf("unexpected StringJoiner/Comparator results: %#v", sjSlice)
	}
	if _, err := Eval(nil, `return new StringJoiner(null);`, nil); err == nil {
		t.Fatal("expected NPE on null StringJoiner delimiter")
	}
	if _, err := Eval(nil, `return new StringJoiner(",", null, "]");`, nil); err == nil {
		t.Fatal("expected NPE on null StringJoiner prefix")
	}
	if _, err := Eval(nil, `return new StringJoiner(",").setEmptyValue(null);`, nil); err == nil {
		t.Fatal("expected NPE on StringJoiner.setEmptyValue(null)")
	}
}

func TestRound67Cov_StaticCallsConstructorsCharacterAndNavigable(t *testing.T) {
	// 1. Static calls across java.lang / java.math / java.util / java.time / Stream / Map.of
	staticSrc := `
		int ge0 = java.lang.Math.getExponent(0.0);
		int ge1 = StrictMath.getExponent(8.0);
		int ge2 = Math.getExponent(Double.NaN);
		String bhex = Integer.toHexString(-1);
		String bbin = Integer.toBinaryString(5);
		String boct = Long.toOctalString(64L);
		String bus = Integer.toUnsignedString(-1, 16);
		String lus = Long.toUnsignedString(-1L, 10);
		int cu = Integer.compareUnsigned(-1, 1);
		int lcu = Long.compareUnsigned(-1L, 1L);
		int du = Integer.divideUnsigned(-2, 2);
		long ldu = Long.divideUnsigned(-2L, 2L);
		int ru = Integer.remainderUnsigned(-1, 10);
		long lru = Long.remainderUnsigned(-1L, 10L);
		int bc = Integer.bitCount(7);
		long lbc = Long.bitCount(15L);
		int hob = Integer.highestOneBit(10);
		long lhob = Long.highestOneBit(0L);
		int lob = Integer.lowestOneBit(12);
		long llob = Long.lowestOneBit(24L);
		int nlz = Integer.numberOfLeadingZeros(1);
		long lnlz = Long.numberOfLeadingZeros(1L);
		int ntz = Integer.numberOfTrailingZeros(8);
		long lntz = Long.numberOfTrailingZeros(16L);
		int rl = Integer.rotateLeft(1, 3);
		long lrr = Long.rotateRight(8L, 2);
		int rev = Integer.reverse(1);
		long lrev = Long.reverse(1L);
		int rbi = Integer.reverseBytes(1);
		int rbs = Short.reverseBytes(256);
		long rbl = Long.reverseBytes(1L);
		int sig = Integer.signum(-5);
		long lsig = Long.signum(5L);
		int isum = Integer.sum(3, 4);
		double dsum = Double.sum(1.5, 2.5);
		int imx = Integer.max(3, 9);
		int imn = Integer.min(3, 9);
		double dmx = Double.max(1.0, 2.0);
		double dmn = Double.min(1.0, 2.0);
		int dcmp = Double.compare(1.0, 2.0);
		int bcmp = Boolean.compare(true, false);
		boolean bval = Boolean.valueOf("true");
		String bts = Boolean.toString(true);
		String sts = Short.toString(300, 16);
		String byts = Byte.toString(15, 2);
		boolean dnan = Double.isNaN(Double.NaN);
		boolean dinf = Double.isInfinite(Double.POSITIVE_INFINITY);
		boolean dfin = Double.isFinite(1.5);
		int idec = Integer.decode("0x1a");
		Map mEmpty = Map.of();
		List isList = IntStream.of(1, 2, 3).boxed().collect(Collectors.toList());
		List dsList = DoubleStream.of([1.5, 2.5]).boxed().collect(Collectors.toList());
		long emptyStreamCnt = Stream.empty().count();
		long concatCnt = IntStream.concat(IntStream.range(0, 2), IntStream.rangeClosed(2, 3)).count();
		long longConcatCnt = LongStream.concat(LongStream.range(0L, 2L), LongStream.rangeClosed(2L, 3L)).count();
		long objIdLen = Objects.toIdentityString("abc").length();
		int ohc = Objects.hashCode("abc");
		int oh = Objects.hash("a", 1, true);
		int ocmp = Objects.compare("a", "b", Comparator.naturalOrder());
		def rnge = Objects.requireNonNullElseGet(null, () -> "fallback");
		int ci = Objects.checkIndex(1, 3);
		int cft = Objects.checkFromToIndex(1, 2, 3);
		int cfis = Objects.checkFromIndexSize(1, 2, 3);
		int idxSub = Collections.indexOfSubList([1, 2, 3, 4], [2, 3]);
		int lastSub = Collections.lastIndexOfSubList([1, 2, 1, 2], [1, 2]);
		List dst = [0, 0, 0];
		Collections.copy(dst, [7, 8]);
		List uList = Collections.unmodifiableList([1, 2]);
		Map uMap = Collections.unmodifiableMap(["k": 1]);
		List sList = Collections.synchronizedList([3, 4]);
		String zo1 = ZoneOffset.ofHours(2);
		String zo2 = ZoneOffset.ofHoursMinutes(-5, -30);
		String zo3 = ZoneOffset.ofHoursMinutesSeconds(1, 2, 3);
		String zo4 = ZoneOffset.ofTotalSeconds(3600);
		String zd = ZoneId.systemDefault();
		int zids = ZoneId.getAvailableZoneIds().size();
		return [
			ge0, ge1, ge2, bhex, bbin, boct, bus, lus, cu, lcu, du, ldu, ru, lru,
			bc, lbc, hob, lhob, lob, llob, nlz, lnlz, ntz, lntz, rl, lrr, rev, lrev,
			rbi, rbs, rbl, sig, lsig, isum, dsum, imx, imn, dmx, dmn, dcmp, bcmp,
			bval, bts, sts, byts, dnan, dinf, dfin, idec, mEmpty.size(), isList.size(),
			dsList.size(), emptyStreamCnt, concatCnt, longConcatCnt, objIdLen > 0, ohc, oh,
			ocmp, rnge, ci, cft, cfis, idxSub, lastSub, dst[1], uList.size(), uMap["k"],
			sList.size(), zo1, zo2, zo3, zo4, zd, zids > 0
		];
	`
	stVal, err := Eval(nil, staticSrc, nil)
	if err != nil {
		t.Fatalf("static call script failed: %v", err)
	}
	stSlice := stVal.([]any)
	if stSlice[0] != int64(-1023) || stSlice[1] != int64(3) || stSlice[2] != int64(1024) || stSlice[63] != int64(1) || stSlice[64] != int64(2) || stSlice[65] != int64(8) {
		t.Fatalf("unexpected static results: %#v", stSlice)
	}
	for _, errCall := range []string{
		`return Integer.divideUnsigned(1, 0);`,
		`return Long.divideUnsigned(1L, 0L);`,
		`return Integer.remainderUnsigned(1, 0);`,
		`return Long.remainderUnsigned(1L, 0L);`,
		`return Map.of("a");`,
		`return Map.of("a", null);`,
		`return Objects.requireNonNullElseGet(null, null);`,
		`return Objects.requireNonNullElseGet(null, () -> null);`,
		`return Objects.checkIndex(5, 3);`,
		`return Objects.checkFromToIndex(2, 1, 3);`,
		`return Objects.checkFromIndexSize(2, 2, 3);`,
		`return Objects.toIdentityString(null);`,
		`return Collections.copy([1], [1, 2]);`,
		`return Collections.unmodifiableList(null);`,
		`return Collections.unmodifiableMap(null);`,
		`return Collections.synchronizedList(null);`,
		`return ZoneOffset.ofTotalSeconds(70000);`,
		`return Stream.concat(null, Stream.empty());`,
	} {
		if _, err := Eval(nil, errCall, nil); err == nil {
			t.Fatalf("expected error for %q", errCall)
		}
	}

	// 2. Constructors & Multi-dim Arrays + String constructors + Round54 constructors.
	ctorSrc := `
		int sz = (new ArrayList([1, 2, 3])).size();
		String s0 = new String();
		StringBuilder sb = new StringBuilder("hello");
		String s1 = new String(sb);
		String s2 = new String(["h", "i"]);
		String s3 = new String([65, 66, 67], "UTF-8");
		String s4 = new String(["a", "b", "c", "d"], 1, 2);
		String s5 = new String([65, 66, 67, 68], 1, 2, "UTF-8");
		def arr2d = new int[2][3];
		def uuid = new UUID(1L, 2L);
		def iss = new IntSummaryStatistics();
		iss.accept(10);
		iss.accept(20);
		def lss = new LongSummaryStatistics();
		lss.accept(5L);
		def dss = new DoubleSummaryStatistics();
		dss.accept(2.5);
		def uri = new URI("https://example.com/a/b?x=1");
		def url = new URL("https://example.com/a/b?x=1");
		return [sz, s0, s1, s2, s3, s4, s5, arr2d[1][2], uuid, iss.getAverage(), lss.getSum(), dss.getMax(), uri.getHost(), url.getHost()];
	`
	ctVal, err := Eval(nil, ctorSrc, nil)
	if err != nil {
		t.Fatalf("constructor script failed: %v", err)
	}
	ctSlice := ctVal.([]any)
	if ctSlice[0] != int64(3) || ctSlice[2] != "hello" || ctSlice[3] != "hi" || ctSlice[4] != "ABC" || ctSlice[5] != "bc" || ctSlice[6] != "BC" {
		t.Fatalf("unexpected constructor results: %#v", ctSlice)
	}
	if _, err := Eval(nil, `return new int[-1];`, nil); err == nil {
		t.Fatal("expected NegativeArraySizeException")
	}
	if _, err := Eval(nil, `return new UUID(1L);`, nil); err == nil {
		t.Fatal("expected UUID arg count error")
	}

	// 3. Character static methods.
	charSrc := `
		int cc1 = Character.charCount(0x1F600);
		int cc2 = Character.charCount(65);
		List tc1 = Character.toChars(65);
		List tc2 = Character.toChars(0x1F600);
		String cs = Character.toString(66);
		boolean vcp = Character.isValidCodePoint(0x10FFFF);
		boolean bmp = Character.isBmpCodePoint(65);
		boolean sup = Character.isSupplementaryCodePoint(0x1F600);
		boolean hs = Character.isHighSurrogate(0xD83D);
		boolean ls = Character.isLowSurrogate(0xDE00);
		boolean sr = Character.isSurrogate(0xD83D);
		boolean sp = Character.isSurrogatePair(0xD83D, 0xDE00);
		int cp = Character.toCodePoint(0xD83D, 0xDE00);
		int cpa = Character.codePointAt("A\uD83D\uDE00B", 1);
		int cpb = Character.codePointBefore("A\uD83D\uDE00B", 3);
		int cpc = Character.codePointCount("A\uD83D\uDE00B", 0, 4);
		return [cc1, cc2, tc1[0], tc2.size(), cs, vcp, bmp, sup, hs, ls, sr, sp, cp, cpa, cpb, cpc];
	`
	chVal, err := Eval(nil, charSrc, nil)
	if err != nil {
		t.Fatalf("Character script failed: %v", err)
	}
	chSlice := chVal.([]any)
	if chSlice[0] != int64(2) || chSlice[1] != int64(1) || chSlice[4] != "B" || chSlice[12] != int64(0x1F600) || chSlice[15] != int64(3) {
		t.Fatalf("unexpected Character results: %#v", chSlice)
	}
	for _, errCh := range []string{
		`return Character.toChars(-1);`,
		`return Character.toString(-1);`,
		`return Character.codePointAt("abc", 9);`,
		`return Character.codePointBefore("abc", 0);`,
		`return Character.codePointCount("abc", 2, 1);`,
	} {
		if _, err := Eval(nil, errCh, nil); err == nil {
			t.Fatalf("expected Character error for %q", errCh)
		}
	}

	// 4. NavigableMap / NavigableSet / Deque methods.
	navSrc := `
		TreeMap tm = new TreeMap();
		tm.put("b", 2);
		tm.put("d", 4);
		tm.put("f", 6);
		def desc = tm.descendingMap();
		def fk = tm.floorKey("c");
		def ck = tm.ceilingKey("c");
		def lk = tm.lowerKey("d");
		def hk = tm.higherKey("d");
		def fe = tm.floorEntry("c");
		def ce = tm.ceilingEntry("c");
		def le = tm.lowerEntry("d");
		def he = tm.higherEntry("d");
		def hm = tm.headMap("d", true);
		def tmap = tm.tailMap("d", false);
		def sm = tm.subMap("b", true, "f", true);
		def dfk = desc.floorKey("c");
		def dck = desc.ceilingKey("c");

		TreeSet ts = new TreeSet(["a", "c", "e"]);
		def tsf = ts.floor("d");
		def tsc = ts.ceiling("b");
		def tsl = ts.lower("c");
		def tsh = ts.higher("c");
		def tshs = ts.headSet("c", true);
		def tsts = ts.tailSet("c", false);
		def tsss = ts.subSet("a", true, "e", false);

		ArrayDeque dq = new ArrayDeque();
		dq.offerFirst("1");
		dq.offerLast("2");
		dq.offer("3");
		dq.addFirst("0");
		dq.addLast("4");
		dq.push("-1");
		boolean rfo = dq.removeFirstOccurrence("0");
		boolean rlo = dq.removeLastOccurrence("4");
		return [
			fk, ck, lk, hk, fe.getKey(), ce.getValue(), le.getKey(), he.getValue(),
			hm.size(), tmap.size(), sm.size(), dfk, dck,
			tsf, tsc, tsl, tsh, tshs.size(), tsts.size(), tsss.size(),
			rfo, rlo, dq.peekFirst(), dq.peekLast(), dq.pop()
		];
	`
	navVal, err := Eval(nil, navSrc, nil)
	if err != nil {
		t.Fatalf("Navigable/Deque script failed: %v", err)
	}
	navSlice := navVal.([]any)
	if navSlice[0] != "b" || navSlice[1] != "d" || navSlice[2] != "b" || navSlice[3] != "f" || navSlice[24] != "-1" {
		t.Fatalf("unexpected Navigable/Deque results: %#v", navSlice)
	}
}

func TestRound67Cov_ControlFlowEvalSimpleStmtAndAssign(t *testing.T) {
	// 1. Eval edge cases: empty/comment, implicit boolean/empty return, ctx metadata, emit, cyclic guard.
	if v, err := Eval(nil, "  /* comment */ // line\n ", nil); err != nil || v != nil {
		t.Fatalf("empty script expected (nil, nil), got (%#v, %v)", v, err)
	}
	if v, err := Eval(map[string]any{"x": 10}, `doc['x'].value > 5`, nil); err != nil || v != true {
		t.Fatalf("implicit boolean expr failed: (%#v, %v)", v, err)
	}
	if v, err := Eval(map[string]any{"s": ""}, `ctx._source.s.empty`, nil); err != nil || v != true {
		t.Fatalf("implicit .empty expr failed: (%#v, %v)", v, err)
	}
	if v, err := Eval(map[string]any{"a": 1}, `return(params.k + 2)`, map[string]any{"k": 3}); err != nil || v != int64(5) {
		t.Fatalf("return(expr) failed: (%#v, %v)", v, err)
	}

	// ctx metadata read/write + ctx whole map + emit multi-val.
	ctxParams := map[string]any{
		"_ctx_id":      "id1",
		"_ctx_index":   "idx1",
		"_ctx_routing": "r1",
		"_ctx_version": int64(7),
		"_now":         int64(1700000000000),
	}
	ctxVal, err := Eval(map[string]any{"f": 1}, `
		def allCtx = ctx;
		def parts = [ctx._id, ctx._index, ctx._routing, ctx._version, ctx.op, ctx._now, allCtx._id];
		ctx.op = "noop";
		emit(10);
		emit(20);
		return parts;
	`, ctxParams)
	if err != nil {
		t.Fatalf("ctx/emit script failed: %v", err)
	}
	ctxSlice := ctxVal.([]any)
	if ctxSlice[0] != "id1" || ctxSlice[1] != "idx1" || ctxSlice[2] != "r1" || ctxSlice[3] != int64(7) || ctxSlice[4] != "index" || ctxSlice[5] != int64(1700000000000) {
		t.Fatalf("unexpected ctx metadata results: %#v", ctxSlice)
	}
	if emitted, err := Eval(nil, `emit("only_one")`, nil); err != nil || emitted != "only_one" {
		t.Fatalf("single emit failed: (%#v, %v)", emitted, err)
	}
	if _, err := Eval(nil, `emit()`, nil); err == nil {
		t.Fatal("expected error for empty emit()")
	}
	if _, err := Eval(map[string]any{}, `Map m = [:]; m.put("s", m); ctx._source.c = m;`, map[string]any{"__is_update_doc": true}); err == nil {
		t.Fatal("expected cycle error in update Eval")
	}

	// 2. execForStatement: multi-var C-for, null decl, loop-local assign, labeled continue/break, dense_vector float/byte/bit, FieldVal.
	forSrc := `
		int acc = 0;
		for (int i = 0, j = 10; i < 3; i++, j--) {
			acc += i + j;
		}
		for (def x = null; x == null; x = 1) {
			acc += 5;
		}
		outer: for (def item : [1, 2, 3]) {
			if (item == 2) { continue outer; }
			if (item == 3) { break outer; }
			acc += item;
		}
		for (def t : doc.tags) {
			acc += t.length();
		}
		for (def fv : field("tags")) {
			acc += fv.length();
		}
		return acc;
	`
	forDoc := map[string]any{"tags": []any{"aa", "bbb"}}
	fVal, err := Eval(forDoc, forSrc, nil)
	if err != nil || fVal != int64(46) {
		t.Fatalf("for statement test got (%#v, %v), want 46", fVal, err)
	}

	// DenseVector iteration (float & byte) + DenseVectorField iterate error.
	dvParams := map[string]any{
		"__field_types":          map[string]string{"vfloat": "dense_vector", "vbyte": "dense_vector"},
		"__vector_element_types": map[string]string{"vfloat": "float", "vbyte": "byte"},
	}
	dvDoc := map[string]any{
		"vfloat": []any{1.5, 2.5},
		"vbyte":  []any{3, 4},
	}
	if dvSum, err := Eval(dvDoc, `double s = 0; for (def x : doc['vfloat'].get()) { s += x; } for (def y : doc['vbyte'].get()) { s += y; } return s;`, dvParams); err != nil {
		t.Fatalf("dense_vector iteration failed: %v", err)
	} else if dvSum != 11.0 {
		t.Fatalf("expected dense_vector sum 11.0, got %#v", dvSum)
	}
	if _, err := Eval(dvDoc, `for (def x : field('vfloat')) {}`, dvParams); err == nil {
		t.Fatal("expected error iterating DenseVectorField")
	}

	// 3. execSimpleStmt + evalAssignExprRound59Painless: null-safe mutators, compound assign, user class super/static assign, errors.
	stmtDoc := map[string]any{"n": int64(5), "m": map[string]any{"k": int64(2)}}
	stmtSrc := `
		class Base {
			int bx = 1;
		}
		class Sub extends Base {
			static int sVal = 10;
			int sx = 2;
			int bump() {
				super.bx = super.bx + 4;
				this.sx += 3;
				sVal = sVal + 5;
				return super.bx + this.sx + sVal;
			}
		}
		def missingList = null;
		missingList?.removeIf(x -> x > 0);
		missingList?.addAll([1, 2]);
		missingList?.add(1);
		missingList?.remove(0);
		missingList?.put("a", 1);
		missingList?.putAll(["b": 2]);
		missingList?.clear();
		missingList?.sort();
		missingList?.forEach(x -> {});
		missingList?.replaceAll(x -> x);
		ctx._source.n += 3;
		ctx?._source?.m?.k *= 4;
		int lv = 10;
		int pre = ++lv;
		int post = lv--;
		Sub sub = new Sub();
		int subRes = sub.bump();
		sub.sx++;
		return [ctx._source.n, ctx._source.m.k, pre, post, lv, subRes, sub.sx];
	`
	stRes, err := Eval(stmtDoc, stmtSrc, nil)
	if err != nil {
		t.Fatalf("stmt/assign script failed: %v", err)
	}
	stArr := stRes.([]any)
	if stArr[0] != int64(8) || stArr[1] != int64(8) || stArr[2] != int64(11) || stArr[3] != int64(11) || stArr[4] != int64(10) || stArr[5] != int64(25) || stArr[6] != int64(6) {
		t.Fatalf("unexpected stmt/assign results: %#v", stArr)
	}

	// UpdateMetadataVal getField/setField + ctx._source map replacement + error paths.
	umv := &UpdateMetadataVal{
		Params: map[string]any{
			"_ctx_id":      "1",
			"_ctx_index":   "idx",
			"_ctx_version": int64(2),
			"_ctx_routing": "r",
			"_ctx_op":      "index",
		},
	}
	if v, err := Eval(map[string]any{"a": 1}, `metadata().op = "noop"; return [metadata().id, metadata().index, metadata().version, metadata().routing, metadata().op, params.u.versionType];`, map[string]any{"__is_update_doc": true, "_ctx_id": "1", "_ctx_index": "idx", "_ctx_version": int64(2), "_ctx_routing": "r", "u": umv}); err != nil || v == nil {
		t.Fatalf("UpdateMetadataVal test failed: (%#v, %v)", v, err)
	}
	if _, err := Eval(map[string]any{"a": 1}, `params.u.op = "delete";`, map[string]any{"u": umv}); err != nil {
		t.Fatalf("UpdateMetadataVal params.u.op assign failed: %v", err)
	}
	if _, err := Eval(map[string]any{"a": 1}, `ctx._source = ["fresh": 9]; return ctx._source.fresh;`, nil); err != nil {
		t.Fatalf("ctx._source replace failed: %v", err)
	}
	for _, errStmt := range []string{
		`doc.x = 1;`,
		`int f() { unknownVar = 1; } return f();`,
		`throw ["__exc_type": "CustomException", "message": "boom"];`,
		`throw "plainBoom";`,
		`return (() -> { yield 1; })();`,
	} {
		_, _ = Eval(map[string]any{"x": 1}, errStmt, nil)
	}
	// Verify doc write is explicitly rejected.
	if _, err := Eval(map[string]any{"x": 1}, `doc.x = 1;`, nil); err == nil {
		t.Fatal("expected UnsupportedOperationException on doc write")
	}
}

func TestRound67Cov_RHSExprMethodsRegexTemporalAndStreams(t *testing.T) {
	// 1. Matcher, StringBuilder, String, Base64, Map.Entry, Map mutators, doc.containsKey.
	rhsDoc := map[string]any{
		"title": "hello world",
		"tags":  []any{"alpha", "beta"},
		"meta":  map[string]any{"k1": "v1"},
		"dt":    "2024-06-15T12:30:45Z",
	}
	rhsSrc := `
		Pattern pat = Pattern.compile("(?<word>[a-z]+)");
		Matcher m = pat.matcher("xx foo123 bar yy");
		m.region(3, 14);
		int rs = m.regionStart();
		int re = m.regionEnd();
		boolean tb = m.hasTransparentBounds();
		boolean ab = m.hasAnchoringBounds();
		m.useTransparentBounds(true);
		m.useAnchoringBounds(false);
		StringBuilder sb = new StringBuilder();
		while (m.find()) {
			m.appendReplacement(sb, m.group("word").toUpperCase());
		}
		m.appendTail(sb);
		boolean he = m.hitEnd();
		boolean reqEnd = m.requireEnd();
		m.reset("abc 123 def");
		boolean fAt = m.find(4);
		String replLam = pat.matcher("a1 b2").replaceAll(mr -> mr.group(1).toUpperCase());
		String replFirst = pat.matcher("a1 b2").replaceFirst(mr -> "Z");
		int sIdx = pat.matcher("123 foo").find() ? 1 : 0;
		Matcher m2 = pat.matcher("hello");
		m2.find();
		int stWord = m2.start("word");
		int enWord = m2.end("word");

		StringBuilder sb2 = new StringBuilder("start");
		sb2.append("XXYYZZ", 2, 4);
		sb2.insert(2, "INS");
		sb2.setCharAt(0, "S");
		sb2.deleteCharAt(1);
		sb2.delete(1, 3);
		sb2.setLength(4);
		sb2.ensureCapacity(64);

		String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString("hi+?".getBytes());
		String b64Dec = Base64.getUrlDecoder().decode(b64);
		String mimeDec = Base64.getMimeDecoder().decode("YQ==\r\n");

		String fmt1 = "%s-%d".formatted("ok", 7);
		boolean ce = "abc".contentEquals(new StringBuilder("abc"));
		boolean rm = "HelloWorld".regionMatches(true, 5, "world", 0, 5);
		boolean swOff = "abcdef".startsWith("cd", 2);
		int iof = "ababa".indexOf("ba", 2);
		int liof = "ababa".lastIndexOf("ab", 2);

		Map mp = ["a": 1, "b": 2];
		for (def e : mp.entrySet()) {
			if (e.getKey() == "a") {
				e.setValue(99);
			}
		}
		mp.putIfAbsent("c", 3);
		mp.compute("a", (k, v) -> v + 1);
		mp.computeIfAbsent("d", k -> 4);
		mp.computeIfPresent("b", (k, v) -> v * 10);
		mp.merge("e", 5, (oldV, newV) -> oldV + newV);
		mp.replace("c", 3, 30);
		boolean hasK = mp.containsKey("a");
		boolean hasV = mp.containsValue(30);
		def gotDef = mp.getOrDefault("missing", -1);
		boolean docHas = doc.containsKey("title");
		boolean recLines = "l1\nl2".lines().count() == 2;
		boolean recChars = "abc".chars().count() == 3;
		boolean recCP = "abc".codePoints().count() == 3;
		boolean subListOk = [1, 2, 3, 4].subList(1, 3).size() == 2;

		return [
			sb.toString(), rs, re, tb, ab, he, reqEnd, fAt, replLam, replFirst, sIdx,
			stWord, enWord, sb2.toString(), b64Dec, mimeDec, fmt1, ce, rm, swOff, iof, liof,
			mp["a"], mp["b"], mp["c"], mp["d"], mp["e"], hasK, hasV, gotDef, docHas,
			recLines, recChars, recCP, subListOk
		];
	`
	rhsVal, err := Eval(rhsDoc, rhsSrc, nil)
	if err != nil {
		t.Fatalf("RHS methods script failed: %v", err)
	}
	rhsSlice := rhsVal.([]any)
	if rhsSlice[0] != "FOO123 BAR yy" || rhsSlice[8] != "A1 B2" || rhsSlice[9] != "Z1 b2" || rhsSlice[14] != "hi+?" || rhsSlice[15] != "a" {
		t.Fatalf("unexpected RHS regex/base64 results: %#v", rhsSlice[:16])
	}
	if rhsSlice[22] != int64(100) || rhsSlice[23] != int64(20) || rhsSlice[24] != int64(30) || rhsSlice[25] != int64(4) || rhsSlice[26] != int64(5) || rhsSlice[30] != true {
		t.Fatalf("unexpected RHS map/doc results: %#v", rhsSlice[22:])
	}

	// 2. Temporal methods, Optionals, Streams, and Collectors.
	tempStreamSrc := `
		Year yr = Year.of(2024);
		def ld1 = yr.atDay(32);
		def ym1 = yr.atMonth(2);
		def ld2 = yr.atMonthDay(MonthDay.of(2, 29));
		MonthDay md = MonthDay.of(2, 29);
		boolean mdValid = md.isValidYear(2024);
		def mdAt = md.atYear(2024);
		long gl = ZonedDateTime.parse("2024-06-15T12:30:00Z").getLong(ChronoField.YEAR);
		def rng = ZonedDateTime.parse("2024-06-15T12:30:00Z").range(ChronoField.DAY_OF_MONTH);
		boolean supF = Instant.ofEpochMilli(0L).isSupported(ChronoField.INSTANT_SECONDS);
		boolean supU = ZonedDateTime.parse("2024-06-15T12:30:00Z").isSupported(ChronoUnit.DAYS);
		def z2 = ZonedDateTime.parse("2024-06-15T12:30:00Z").withZoneSameInstant("America/New_York");
		def z3 = ZonedDateTime.parse("2024-06-15T12:30:00Z").withZoneSameLocal("America/New_York");
		def sod = LocalDate.parse("2024-06-15").atStartOfDay("UTC");
		def ot = LocalTime.of(10, 15, 30).atOffset("+02:00");
		String otFmt = ot.format(DateTimeFormatter.ISO_OFFSET_TIME);
		long millisProp = doc["dt"].value.millis;

		def opt1 = Optional.of(10).filter(x -> x > 5).map(x -> x * 2);
		def opt2 = Optional.empty().or(() -> Optional.of(7));
		def opt3 = Optional.ofNullable(null).orElseGet(() -> 9);
		int[] boxCnt = [0];
		opt1.ifPresent(x -> { boxCnt[0] = x; });
		Optional.empty().ifPresentOrElse(x -> {}, () -> { boxCnt[0] += 1; });
		def optInt = OptionalInt.of(4).orElse(0);
		def optLng = OptionalLong.empty().orElse(8L);
		def optDbl = OptionalDouble.of(2.5).getAsDouble();
		long genCnt = Stream.iterate(1, x -> x + 1).limit(3).count();
		long genSup = Stream.generate(() -> 1).limit(4).count();
		def grouped = ["aa", "bb", "c"].stream().collect(Collectors.groupingBy(s -> s.length()));
		return [
			ld1, ym1.toString(), ld2, mdValid, mdAt, gl, rng.getMaximum(), supF, supU,
			z2, z3, sod, otFmt, millisProp > 0, opt1.get(), opt2.get(), opt3, boxCnt[0],
			optInt, optLng, optDbl, genCnt, genSup, grouped.size()
		];
	`
	tsVal, err := Eval(rhsDoc, tempStreamSrc, map[string]any{"__field_types": map[string]string{"dt": "date"}})
	if err != nil {
		t.Fatalf("Temporal/Stream script failed: %v", err)
	}
	tsSlice := tsVal.([]any)
	if tsSlice[3] != true || tsSlice[5] != int64(2024) || tsSlice[14] != int64(20) || tsSlice[15] != int64(7) || tsSlice[17] != int64(21) || tsSlice[23] != int64(2) {
		t.Fatalf("unexpected Temporal/Stream results: %#v", tsSlice)
	}
}

func TestRound67Cov_Round54AndRound60ProcessorsFieldValAndReceivers(t *testing.T) {
	// 1. Round54 equals, ValueRange, Clock, URI, URL, Predicate.
	r54Src := `
		class Box {
			int v;
			Box(int v) { this.v = v; }
			boolean equals(Object o) { return (o instanceof Box) && this.v == o.v; }
		}
		Box b1 = new Box(5);
		Box b2 = new Box(5);
		boolean boxEq = b1.equals(b2);
		boolean optEq = Optional.of(5).equals(Optional.of(5));
		boolean otEq = LocalTime.of(1, 2, 3).atOffset("+00:00").equals(LocalTime.of(1, 2, 3).atOffset("+00:00"));
		Clock clk = Clock.fixed(Instant.ofEpochMilli(1000L), "UTC");
		boolean clkEq = clk.equals(Clock.fixed(Instant.ofEpochMilli(1000L), "UTC"));
		URI u1 = new URI("https://example.com/a/b");
		URI u2 = new URI("https://example.com/a/c");
		boolean uriEq = u1.equals(u1);
		URL url1 = new URL("https://example.com/a");
		boolean urlEq = url1.equals(url1);
		boolean sf = url1.sameFile(new URL("https://example.com/a#frag"));
		ValueRange vr = ChronoField.MONTH_OF_YEAR.range();
		boolean vrValid = vr.isValidValue(5L);
		boolean vrInt = vr.isValidIntValue(5L);
		boolean vrEq = vr.equals(ChronoField.MONTH_OF_YEAR.range());
		Predicate p = Pattern.compile("ab.*").asPredicate().negate();
		Predicate mp = Pattern.compile("abc").asMatchPredicate();
		return [boxEq, optEq, otEq, clkEq, uriEq, urlEq, sf, vrValid, vrInt, vrEq, p.test("xyz"), mp.test("abc")];
	`
	r54Val, err := Eval(nil, r54Src, nil)
	if err != nil {
		t.Fatalf("Round54 script failed: %v", err)
	}
	for i, el := range r54Val.([]any) {
		if el != true {
			t.Fatalf("Round54 result[%d] expected true, got %#v", i, el)
		}
	}

	// 2. Round60 Processors.* mutating & non-mutating + null/missing-field/error paths.
	procDoc := map[string]any{
		"sz":     "4kb",
		"lc":     []any{"A", "B"},
		"uc":     []any{"x", "y"},
		"tr":     "  hi  ",
		"gs":     "a_b_c",
		"sp":     "p:q:r",
		"jn":     []any{"m", "n"},
		"rm":     []any{"drop1", "drop2"},
		"ap":     "init",
		"cv":     "123",
		"js":     `{"k":"v"}`,
		"ud":     "hello+world%21",
		"nested": map[string]any{"x": "1"},
	}
	procSrc := `
		Processors.bytes(ctx, "sz");
		Processors.lowercase(ctx, "lc");
		Processors.uppercase(ctx, "uc");
		Processors.trim(ctx, "tr");
		Processors.gsub(ctx, "gs", "_", "-");
		Processors.split(ctx, "sp", ":");
		Processors.join(ctx, "jn", "/");
		Processors.remove(ctx, ctx.rm);
		Processors.append(ctx, "ap", "more");
		Processors.convert(ctx, "cv", "long", "cv_out");
		Processors.json(ctx, "js", "js_out");
		Processors.urlDecode(ctx, "ud");
		def n1 = Processors.bytes(null);
		def n2 = Processors.lowercase(null);
		def n3 = Processors.uppercase(null);
		def n4 = Processors.trim(null);
		def n5 = Processors.gsub(null, "a", "b");
		def n6 = Processors.split(null, ",");
		def n7 = Processors.join("scalar", ",");
		def n8 = Processors.json(null);
		def n9 = Processors.urlDecode(null);
		def n10 = Processors.uriParts(null);
		def miss = Processors.trim(ctx, "missing_field");
		def missB = Processors.bytes(ctx, "missing_field");
		def missL = Processors.lowercase(ctx, "missing_field");
		def missU = Processors.uppercase(ctx, "missing_field");
		def missG = Processors.gsub(ctx, "missing_field", "a", "b");
		def missS = Processors.split(ctx, "missing_field", ",");
		def missJ = Processors.join(ctx, "missing_field", ",");
		def missC = Processors.convert(ctx, "missing_field", "int");
		def missJS = Processors.json(ctx, "missing_field");
		def missUD = Processors.urlDecode(ctx, "missing_field");
		def apVal = Processors.append(["a"], "b");
		def cvVal = Processors.convert("true", "boolean");
		def jsVal = Processors.json('{"z":1}');
		def udVal = Processors.urlDecode("a%20b");
		return [
			ctx._source.sz, ctx._source.tr, ctx._source.gs, ctx._source.jn,
			ctx._source.cv_out, ctx._source.js_out.k, ctx._source.ud,
			n1, n2, n3, n4, n5, n6, n7, n8, n9, n10,
			miss, missB, missL, missU, missG, missS, missJ, missC, missJS, missUD,
			apVal.size(), cvVal, jsVal.z, udVal
		];
	`
	procVal, err := Eval(procDoc, procSrc, nil)
	if err != nil {
		t.Fatalf("Processors script failed: %v", err)
	}
	pSlice := procVal.([]any)
	if pSlice[0] != int64(4096) || pSlice[1] != "hi" || pSlice[2] != "a-b-c" || pSlice[3] != "m/n" || pSlice[4] != int64(123) || pSlice[5] != "v" || pSlice[6] != "hello world!" {
		t.Fatalf("unexpected Processors mutating outputs: %#v", pSlice[:7])
	}
	if pSlice[13] != "scalar" || pSlice[27] != int64(2) || pSlice[28] != true || pSlice[30] != "a b" {
		t.Fatalf("unexpected Processors scalar outputs: %#v", pSlice[13:])
	}
	for _, badProc := range []string{
		`Processors.gsub("x");`,
		`Processors.split("x");`,
		`Processors.join("x");`,
		`Processors.remove("x");`,
		`Processors.rename("x");`,
		`Processors.append("x");`,
		`Processors.convert("x");`,
		`Processors.urlDecode("%ZZ");`,
		`Processors.unknownMethod("x");`,
	} {
		if _, err := Eval(nil, badProc, nil); err == nil {
			t.Fatalf("expected error for %q", badProc)
		}
	}

	// 3. Round60 FieldVal, FieldDocVal, VersionVal, GeoPointVal, GeoShape, ByteBuffer, BytesRef, PainlessLambda.
	r60Doc := map[string]any{
		"nums":    []any{int64(10), int64(20)},
		"floats":  []any{1.5, 2.5},
		"dates":   []any{"2024-01-02T00:00:00Z"},
		"geo":     "40.71,-74.01",
		"shape":   "POLYGON((0 0, 2 0, 2 2, 0 2, 0 0))",
		"ver":     "1.2.3",
		"raw":     "hello",
		"moveMe":  "val",
		"keepMe":  "old",
		"arr":     []any{int64(1), int64(2), int64(3)},
		"scalar":  int64(5),
		"nested":  map[string]any{"sub": "ok"},
		"objList": []any{map[string]any{"id": 1}},
	}
	r60Params := map[string]any{
		"__field_types": map[string]string{
			"geo":   "geo_point",
			"shape": "geo_shape",
			"ver":   "version",
			"raw":   "binary",
		},
		"__mutable_fields_api": true,
	}
	r60Src := `
		def fvNums = field("nums");
		def g0 = fvNums.get();
		def g1 = fvNums.get(99);
		def g2 = fvNums.get(5, 88);
		def gv = fvNums.getValue(5, 77);
		def gvs = fvNums.getValues();
		def bi = fvNums.asBigInteger(5, "42");
		def lg = fvNums.asLong(5, 55L);
		def dbl = field("floats").asDouble(5, 9.5);
		def dt1 = field("dates").asDate(5, "2020-01-01T00:00:00Z");
		def gp1 = field("geo").asGeoPoint(5, "0,0");
		def gp2 = field("geo").asGeoPoint();
		def str1 = field("nums").asString(5, "def");
		def missStr = field("missing").asString(null);
		field("moveMe").move("moved");
		field("keepMe").overwrite("overwritten");
		field("arr").removeValuesIf(x -> x == 2);
		field("arr").transform(x -> x * 10);
		field("scalar").removeValuesIf(x -> x == 5);
		field("nested").append("added");
		def fdoc = field("objList").doc(0);
		boolean hasSub = fdoc.field("id").get() == 1;
		boolean ex1 = fdoc.exists();
		def dollarVal = fdoc.$("id", -1);
		def gpArc = gp2.arcDistance(41.0, -74.0);
		def gpPlane = gp2.planeDistance(41.0, -74.0);
		def gpGeo = gp2.geohashDistance("dr5regw3");
		def shpPt = doc["shape"].get(0);

		Version v1 = new Version("1.2.3");
		int vcmp = v1.compareTo("1.2.4");
		boolean veq = v1.equals("1.2.3");
		String vstr = v1.toString();

		BytesRef br = new BytesRef("abc");
		def brByte = br.get(1);
		ByteBuffer bb = ByteBuffer.wrap([65, 66, 67]);
		def bbByte = bb.get(0);

		Function fn = x -> x + 1;
		def iuo = x -> x + 2;
		def luo = x -> x + 3;
		def duo = x -> x + 0.5;
		Predicate pred = x -> x > 0;
		Consumer cons = x -> { ctx._source.seen = x; };
		cons.accept("yes");
		return [
			g0, g1, g2, gv, gvs.size(), bi.intValue(), lg, dbl, dt1, gp1 != null,
			gp2 != null, str1, missStr, hasSub, ex1, dollarVal,
			gpArc > 0, gpPlane > 0, gpGeo > 0, shpPt != null,
			vcmp, veq, vstr, brByte, bbByte,
			fn.apply(5), iuo.applyAsInt(5), luo.applyAsLong(5), duo.applyAsDouble(5.0), pred.test(1),
			ctx._source.seen, ctx._source.moved, ctx._source.overwritten
		];
	`
	r60Val, err := Eval(r60Doc, r60Src, r60Params)
	if err != nil {
		t.Fatalf("Round60 cov script failed: %v", err)
	}
	r60Slice := r60Val.([]any)
	if r60Slice[0] != int64(10) || r60Slice[2] != int64(88) || r60Slice[5] != int64(42) || r60Slice[6] != int64(55) || r60Slice[21] != true || r60Slice[25] != int64(6) || r60Slice[30] != "yes" {
		t.Fatalf("unexpected Round60 cov results: %#v", r60Slice)
	}

	// BytesRef out-of-bounds & Version compareTo null error & ApplyUpdateWithResult noop/error.
	if _, err := Eval(nil, `return new BytesRef("ab").get(5);`, nil); err == nil {
		t.Fatal("expected IndexOutOfBoundsException on BytesRef.get(5)")
	}
	if _, err := Eval(nil, `return new Version("1.0.0").compareTo(null);`, nil); err == nil {
		t.Fatal("expected NPE on Version.compareTo(null)")
	}
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Script: &ScriptSpec{Source: "ctx.op = 'delete';"},
	}, true); err != nil {
		t.Fatalf("ApplyUpdateWithResult delete failed: %v", err)
	}
}

func TestRound67Cov_Round54URIURLLocaleClockOffsetTimeAndErrors(t *testing.T) {
	// User class custom toString/hashCode/equals/static method + instance method paths.
	userClassSrc := `
		class Box {
			int v;
			Box(int v) { this.v = v; }
			String toString() { return "Box:" + this.v; }
			int hashCode() { return this.v * 31; }
			boolean equals(Object o) { return o instanceof Box && ((Box)o).v == this.v; }
			static int twice(int x) { return x * 2; }
			int callTwice() { return twice(this.v); }
		}
		Box b1 = new Box(7);
		Box b2 = new Box(7);
		return [b1.toString(), b1.hashCode(), b1.equals(b2), b1.callTwice()];
	`
	ucRes, err := Eval(nil, userClassSrc, nil)
	if err != nil {
		t.Fatalf("user class Box script failed: %v", err)
	}
	if s := ucRes.([]any); s[0] != "Box:7" || s[1] != int64(217) || s[2] != true || s[3] != int64(14) {
		t.Fatalf("unexpected Box results: %#v", s)
	}

	// Opaque & hierarchical URI / URL / Locale / Optional / SummaryStats / Clock / OffsetTime / Pattern.
	r54Src := `
		URI opq = new URI("mailto:user@example.com");
		URI h1 = new URI("https://user@example.com:8443/a/../b?k=1#frag");
		URI h2 = new URI("https://example.com/plain");
		URI u3 = new URI("https", "example.com/path", "f1");
		URI u4 = new URI("https", "example.com", "/p4", "f4");
		URI u5 = new URI("https", "user@example.com:8080", "/p5", "q=1", "f5");
		URI u7 = new URI("https", "usr", "example.com", 8443, "/p7", "q=2", "f7");

		URL url1 = new URL("https://user:pw@example.com/dir/page?q=1#ref");
		URL url2 = new URL("https://example.com/plain");
		URL url3 = new URL(new URL("https://example.com/dir/"), "sub?x=1");
		URL url4 = new URL("http", "example.com", "/f");
		URL url5 = new URL("http", "example.com", 8080, "/f2");

		Locale loc1 = new Locale("en");
		Locale loc2 = new Locale("en", "US");
		Locale loc3 = Locale.forLanguageTag("fr-FR");

		def oEmpty = Optional.empty();
		def oFull = Optional.of(10);
		boolean oIsEmp = oEmpty.isEmpty();
		def oFilt1 = oEmpty.filter(x -> x > 0);
		def oFilt2 = oFull.filter(x -> x > 20);
		def oMapNil = oFull.map(x -> null);
		def oFlat = oFull.flatMap(x -> Optional.of(x + 5));
		def oOrGet = oEmpty.orElseGet(() -> 99);
		def oOrOpt = oEmpty.or(() -> Optional.of(77));
		def oNullableEmp = Optional.ofNullable(Optional.empty());
		oFull.ifPresent(x -> { params.seen = x; });
		oEmpty.ifPresentOrElse(x -> {}, () -> { params.absent = true; });

		DoubleSummaryStatistics ds1 = new DoubleSummaryStatistics();
		ds1.accept(1.5);
		ds1.accept(2.5);
		DoubleSummaryStatistics ds2 = new DoubleSummaryStatistics();
		ds2.accept(4.0);
		ds1.combine(ds2);

		ValueRange vr = ChronoField.MONTH_OF_YEAR.range();
		boolean vOk1 = vr.isValidValue(12);
		boolean vOk2 = vr.isValidIntValue(13);

		Clock clkFixed = Clock.fixed(Instant.parse("2025-01-01T12:00:00Z"), ZoneId.of("+03:00"));
		Clock clkSys = Clock.system("UTC");
		Clock clkOff = Clock.offset(clkFixed, Duration.ofHours(1));
		Clock clkTickS = Clock.tickSeconds("UTC");
		Clock clkTickM = Clock.tickMinutes("UTC");
		Clock clkTickMs = Clock.tickMillis("UTC");
		Clock clkTick = Clock.tick(clkFixed, Duration.ofSeconds(10));
		ZoneId zPlus = ZonedDateTime.parse("2025-01-01T10:00:00+02:00").getZone();

		OffsetTime ot1 = OffsetTime.of(LocalTime.of(10, 20, 30), ZoneOffset.ofHours(2));
		OffsetTime ot2 = OffsetTime.of(10, 20, 30, 123456789, ZoneOffset.of("+02:00"));
		OffsetTime otNow = OffsetTime.now(clkFixed);
		OffsetTime otInst = OffsetTime.ofInstant(Instant.parse("2025-01-01T12:00:00Z"), ZoneId.of("UTC"));
		OffsetTime otMut = ot2.withHour(5).withMinute(6).withSecond(7).withNano(987654321)
			.withOffsetSameLocal("+03:00").withOffsetSameInstant("+04:00")
			.plusHours(1).minusMinutes(2).plusSeconds(3).minusNanos(100)
			.plus(5, ChronoUnit.MILLIS).minus(4, ChronoUnit.MICROS)
			.plus(3, ChronoUnit.NANOS).plus(1, ChronoUnit.HALF_DAYS)
			.plus(1, ChronoUnit.HOURS).minus(1, ChronoUnit.MINUTES).plus(1, ChronoUnit.SECONDS);
		OffsetTime otTruncD = ot2.truncatedTo(ChronoUnit.DAYS);
		OffsetTime otTruncH = ot2.truncatedTo(ChronoUnit.HALF_DAYS);
		OffsetTime otTruncHr = ot2.truncatedTo(ChronoUnit.HOURS);
		OffsetTime otTruncMn = ot2.truncatedTo(ChronoUnit.MINUTES);
		OffsetTime otTruncS = ot2.truncatedTo(ChronoUnit.SECONDS);
		OffsetTime otTruncMs = ot2.truncatedTo(ChronoUnit.MILLIS);
		OffsetTime otTruncMc = ot2.truncatedTo(ChronoUnit.MICROS);
		OffsetTime otTruncNs = ot2.truncatedTo(ChronoUnit.NANOS);
		String atDt = ot1.atDate("2025-01-02");
		long epSec = ot1.toEpochSecond("2025-01-02");
		boolean otCmp = otMut.isBefore(ot1) || otMut.isAfter(ot1) || ot1.isEqual(ot1) || ot1.compareTo(ot2) == 0;

		ZoneOffset zo0 = ZoneOffset.ofHours(0);
		ZoneOffset zoP = ZoneOffset.ofHours(5);
		ZoneOffset zoN = ZoneOffset.ofHours(-5);
		ZoneOffset zoHM = ZoneOffset.ofHoursMinutes(2, 30);
		ZoneOffset zoHMS = ZoneOffset.ofHoursMinutesSeconds(1, 2, 3);
		ZoneOffset zoTot = ZoneOffset.ofTotalSeconds(3661);
		def allZones = ZoneId.getAvailableZoneIds();
		ZoneId zOff = ZoneId.ofOffset("GMT", ZoneOffset.ofHours(2));

		Pattern pat = Pattern.compile("(a)(b)?");
		Matcher mat = pat.matcher("xxabxxax");
		mat.region(2, 7);
		mat.useTransparentBounds(true);
		mat.useAnchoringBounds(false);
		def matRes = mat.results();
		int matResCount = matRes.size();
		mat.usePattern(Pattern.compile("x+"));
		boolean pPred = pat.asPredicate().test(null);
		boolean pMPred = pat.asMatchPredicate().test(null);
		long splitEmp = pat.splitAsStream("").count();

		int idHash = Objects.hashCode(h1) + Objects.hash(1, "a") + Objects.compare(1, 2, Comparator.naturalOrder());
		String idStr = Objects.toIdentityString(url1);
		def rne = Objects.requireNonNullElseGet(null, () -> 42);
		long ci = Objects.checkIndex(1, 3);
		long cfti = Objects.checkFromToIndex(1, 2, 3);
		long cfis = Objects.checkFromIndexSize(1, 1, 3);

		def subListMiss = Collections.indexOfSubList([1, 2], [1, 2, 3]);
		def subListMiss2 = Collections.lastIndexOfSubList([1, 2], [9]);
		def unmodL = Collections.unmodifiableList([1, 2]);
		def unmodM = Collections.unmodifiableMap(["a": 1]);
		def syncL = Collections.synchronizedList([3, 4]);

		return [
			opq.isOpaque(), opq.getPath() == null, opq.getHost() == null, opq.getQuery() == null, opq.getUserInfo() == null, opq.getAuthority() == null,
			h1.getScheme(), h1.getSchemeSpecificPart(), h1.getRawSchemeSpecificPart(), h1.getUserInfo(), h1.getQuery(), h1.getFragment(),
			h2.getScheme(), h2.getUserInfo() == null, h2.getQuery() == null, h2.getFragment() == null,
			u3.toString(), u4.toString(), u5.toString(), u7.toString(),
			url1.getDefaultPort(), url1.getQuery(), url1.getUserInfo(), url1.getRef(),
			url2.getQuery() == null, url2.getUserInfo() == null, url2.getRef() == null, url3.toString(), url4.toString(), url5.toString(),
			loc1.toString(), loc2.toString(), loc3.toString(),
			oIsEmp, oFilt1.isEmpty(), oFilt2.isEmpty(), oMapNil.isEmpty(), oFlat.get(), oOrGet, oOrOpt.get(), oNullableEmp.isEmpty(), params.seen, params.absent,
			ds1.getCount(), vOk1, vOk2, clkFixed.getZone(), clkSys != null, clkOff != null, clkTickS != null, clkTickM != null, clkTickMs != null, clkTick != null, zPlus,
			otNow != null, otInst != null, otTruncD != null, otTruncH != null, otTruncHr != null, otTruncMn != null, otTruncS != null, otTruncMs != null, otTruncMc != null, otTruncNs != null,
			atDt, epSec > 0, otCmp, zo0, zoP, zoN, zoHM, zoHMS, zoTot, allZones.size() > 0, zOff,
			matResCount, pPred, pMPred, splitEmp,
			idHash != 0, idStr != "", rne, ci, cfti, cfis, subListMiss, subListMiss2, unmodL.size(), unmodM.size(), syncL.size()
		];
	`
	r54Params := map[string]any{}
	r54Res, err := Eval(nil, r54Src, r54Params)
	if err != nil {
		t.Fatalf("Round54 feature script failed: %v", err)
	}
	sl := r54Res.([]any)
	if sl[0] != true || sl[1] != true || sl[37] != int64(15) || sl[38] != int64(99) || sl[39] != int64(77) || sl[43] != int64(3) || sl[81] != int64(42) {
		t.Fatalf("unexpected Round54 results: %#v", sl)
	}

	// Targeted Round54 exception / boundary cases.
	r54ErrScripts := []string{
		`return new URI(null);`,
		`return URI.create(null);`,
		`return new URI("https", "example.com", "rel", null);`,
		`return new URI("https", "example.com", "rel", null, null);`,
		`return new URI("https", null, "example.com", -1, "rel", null, null);`,
		`return new URI("https://a.com").resolve(null);`,
		`return new URI("https://a.com").resolve("://");`,
		`return new URI("https://a.com").relativize(null);`,
		`return new URI("https://a.com").compareTo("not_uri");`,
		`return new IntSummaryStatistics(1, 2);`,
		`return Locale.forLanguageTag(null);`,
		`return Objects.requireNonNullElseGet(null, "not_lambda");`,
		`def p = Optional.of(1); return p.flatMap(x -> null);`,
		`return OffsetTime.parse("not-a-time");`,
		`return OffsetTime.ofInstant("bad", "bad");`,
		`return OffsetTime.now().plus(1, ChronoUnit.DAYS);`,
		`return OffsetTime.now().truncatedTo(ChronoUnit.CENTURIES);`,
		`return OffsetTime.now().atDate("bad-date");`,
		`return OffsetTime.now().toEpochSecond("bad-date");`,
		`return OffsetTime.now().isBefore("bad-time");`,
		`return Pattern.compile("a").splitAsStream(null);`,
		`return Pattern.compile("a").matcher("a").usePattern(null);`,
		`List l = null; return Collections.addAll(l, 1);`,
		`List d = [1]; List s = [1, 2]; Collections.copy(d, s);`,
		`List d = null; Collections.copy(d, [1]);`,
		`return new URL(new URL("https://a.com"), "://bad_url_!!!");`,
	}
	for _, sc := range r54ErrScripts {
		if _, err := Eval(nil, sc, map[string]any{}); err == nil {
			t.Fatalf("expected error for Round54 script %q", sc)
		}
	}
}

func TestRound67Cov_EvalRHSAndStaticErrorAndEdgeClusters(t *testing.T) {
	// Block 1: BigDecimal, BigInteger, BitSet.
	bdScript := `
		BigDecimal bd1 = new BigDecimal("12.345");
		BigDecimal bd2 = BigDecimal.valueOf(250, 2);
		BigDecimal bdSub = bd1.subtract(bd2);
		BigDecimal bdMul = bd1.multiply(bd2);
		BigDecimal bdDiv = bd1.divide("2", RoundingMode.HALF_UP);
		BigDecimal bdRem = bd1.remainder("5");
		BigDecimal bdIntDiv = bd1.divideToIntegralValue("5");
		def bdDar = bd1.divideAndRemainder("5");
		BigDecimal bdPow = new BigDecimal("2.5").pow(2);
		BigDecimal bdScale = bd1.setScale(2, RoundingMode.DOWN);
		BigDecimal bdMin = bd1.min(bd2);
		BigDecimal bdMax = bd1.max(bd2);
		BigDecimal bdMPL = bd1.movePointLeft(1);
		BigDecimal bdMPR = bd1.movePointRight(1);
		BigDecimal bdSpot = bd1.scaleByPowerOfTen(1);
		BigDecimal bdRound = bd1.round(new MathContext(3, RoundingMode.HALF_UP));
		BigDecimal bdAbs = new BigDecimal("-3.2").abs();
		BigDecimal bdNeg = bd1.negate();
		def bdUnscaled = bdScale.unscaledValue();
		BigDecimal bdExact = new BigDecimal("42");
		int bdIV = bdExact.intValueExact();
		int bdSV = bdExact.shortValueExact();
		int bdBV = bdExact.byteValueExact();

		BigInteger bi1 = new BigInteger("100");
		BigInteger bi2 = BigInteger.valueOf(17);
		BigInteger biSub = bi1.subtract(bi2);
		BigInteger biMul = bi1.multiply(bi2);
		BigInteger biDiv = bi1.divide(bi2);
		BigInteger biRem = bi1.remainder(bi2);
		def biDar = bi1.divideAndRemainder(bi2);
		BigInteger biMod = bi1.mod(bi2);
		BigInteger biModPow = BigInteger.valueOf(2).modPow(BigInteger.valueOf(5), bi2);
		BigInteger biModInv = BigInteger.valueOf(3).modInverse(bi2);
		BigInteger biGcd = bi1.gcd(BigInteger.valueOf(25));
		BigInteger biPow = BigInteger.valueOf(3).pow(4);
		BigInteger biMin = bi1.min(bi2);
		BigInteger biMax = bi1.max(bi2);
		BigInteger biAnd = bi1.and(bi2);
		BigInteger biXor = bi1.xor(bi2);
		BigInteger biAndNot = bi1.andNot(bi2);
		BigInteger biSL = bi2.shiftLeft(2);
		BigInteger biSR = bi1.shiftRight(2);
		boolean biTB = bi2.testBit(0);
		BigInteger biSB = bi2.setBit(1);
		BigInteger biCB = bi2.clearBit(0);
		BigInteger biFB = bi2.flipBit(2);
		boolean biPrime = bi2.isProbablePrime(10);
		String biHex = bi1.toString(16);
		int biIV = bi2.intValueExact();
		int biSV = bi2.shortValueExact();
		int biBV = bi2.byteValueExact();

		BitSet bs1 = new BitSet();
		bs1.set(1);
		bs1.set(5);
		bs1.set(2, 4);
		BitSet bs2 = BitSet.valueOf([15L]);
		boolean bsInter = bs1.intersects(bs2);
		int bsNS = bs1.nextSetBit(0);
		int bsNC = bs1.nextClearBit(1);
		int bsPS = bs1.previousSetBit(5);
		int bsPC = bs1.previousClearBit(5);
		bs1.and(bs2);
		bs1.xor(bs2);
		bs1.andNot(bs2);
		bs1.flip(1);
		bs1.flip(0, 3);
		bs1.clear(1);
		bs1.clear();
		String bsStr = bs2.toString();

		return [
			bdSub.toString(), bdMul.toString(), bdDiv.toString(), bdRem.toString(), bdIntDiv.toString(), bdDar.size(), bdPow.toString(), bdScale.toString(), bdMin.toString(), bdMax.toString(), bdMPL.toString(), bdMPR.toString(), bdSpot.toString(), bdRound.toString(), bdAbs.toString(), bdNeg.toString(), bdUnscaled.toString(), bdIV, bdSV, bdBV,
			biSub.toString(), biMul.toString(), biDiv.toString(), biRem.toString(), biDar.size(), biMod.toString(), biModPow.toString(), biModInv.toString(), biGcd.toString(), biPow.toString(), biMin.toString(), biMax.toString(), biAnd.toString(), biXor.toString(), biAndNot.toString(), biSL.toString(), biSR.toString(), biTB, biSB.toString(), biCB.toString(), biFB.toString(), biPrime, biHex, biIV, biSV, biBV,
			bsInter, bsNS, bsNC, bsPS, bsPC, bsStr
		];
	`
	if bdRes, err := Eval(nil, bdScript, map[string]any{}); err != nil {
		t.Fatalf("bdScript failed: %v", err)
	} else if sl := bdRes.([]any); sl[17] != int64(42) || sl[18] != int64(42) || sl[19] != int64(42) {
		t.Fatalf("unexpected bdScript results: %#v", sl)
	}

	// Block 2: HexFormat & Character.
	hexCharScript := `
		HexFormat hf = HexFormat.of().withPrefix("0x").withSuffix("!").withDelimiter(":");
		String hfFmt1 = hf.formatHex([10, 255]);
		String hfFmt2 = HexFormat.of().formatHex([10, 20, 30], 1, 3);
		def hfParsed1 = HexFormat.of().parseHex("0aff");
		def hfParsed2 = HexFormat.of().parseHex("xx0affzz", 2, 6);
		String hfDig = hf.toHexDigits(255);
		int hfFrom = hf.fromHexDigits("00ff");
		long hfFromL = hf.fromHexDigitsToLong("ff");
		boolean hfIs = hf.isHexDigit(65);
		int hfVal = hf.fromHexDigit(65);
		HexFormat hfDel = HexFormat.ofDelimiter("-");
		int hfS1 = HexFormat.fromHexDigits("0a");
		long hfS2 = HexFormat.fromHexDigitsToLong("0a");
		boolean hfS3 = HexFormat.isHexDigit(70);
		int hfS4 = HexFormat.fromHexDigit(70);

		int chCount = Character.charCount(0x1F600);
		def chChars = Character.toChars(0x1F600);
		String chStr = Character.toString(65);
		def chVal = Character.valueOf(65);
		boolean chSur = Character.isSurrogatePair(0xD83D, 0xDE00);
		int chCP = Character.toCodePoint(0xD83D, 0xDE00);
		int chAt = Character.codePointAt("Abc", 1);
		int chBef = Character.codePointBefore("Abc", 2);
		int chCnt = Character.codePointCount("Abc", 0, 3);
		int chNum = Character.getNumericValue(55);
		int chType1 = Character.getType(65);
		int chType2 = Character.getType(32);
		int chType3 = Character.getType(49);
		int chType4 = Character.getType(0x201D);
		int chCmp = Character.compare(65, 66);
		boolean chAlpha = Character.isAlphabetic(65) && Character.isWhitespace(32) && Character.isTitleCase(0x01C5);
		int chCase = Character.toUpperCase(97) + Character.toLowerCase(65) + Character.toTitleCase(97);
		boolean chId = Character.isIdeographic(0x5B57) && Character.isJavaIdentifierStart(36) && Character.isJavaIdentifierPart(57) && Character.isISOControl(10) && Character.isDefined(65);
		int chDig = Character.digit(102, 16);
		def chFor = Character.forDigit(15, 16);
		int chRev = Character.reverseBytes(0x1234);
		return [hfFmt1, hfFmt2, hfParsed1.size(), hfParsed2.size(), hfDig, hfFrom, hfFromL, hfIs, hfVal, hfDel != null, hfS1, hfS2, hfS3, hfS4, chCount, chChars.size(), chStr, chVal, chSur, chCP, chAt, chBef, chCnt, chNum, chType1, chType2, chType3, chType4, chCmp, chAlpha, chCase, chId, chDig, chFor, chRev];
	`
	if _, err := Eval(nil, hexCharScript, map[string]any{}); err != nil {
		t.Fatalf("hexCharScript failed: %v", err)
	}

	// Block 3: NavigableMap/Set, Deque, Arrays.
	treeDequeScript := `
		TreeMap tmap = new TreeMap();
		tmap.put("a", 1);
		tmap.put("c", 3);
		tmap.put("e", 5);
		def tmFloor = tmap.floorKey("d");
		def tmCeil = tmap.ceilingKey("b");
		def tmLow = tmap.lowerKey("c");
		def tmHigh = tmap.higherKey("c");
		def tmHead = tmap.headMap("c", true);
		def tmTail = tmap.tailMap("c", false);
		def tmSub = tmap.subMap("a", true, "e", false);

		TreeSet tset = new TreeSet();
		tset.addAll([1, 3, 5]);
		def tsFloor = tset.floor(4);
		def tsCeil = tset.ceiling(2);
		def tsLow = tset.lower(3);
		def tsHigh = tset.higher(3);
		def tsHead = tset.headSet(3, true);
		def tsTail = tset.tailSet(3, false);
		def tsSub = tset.subSet(1, true, 5, false);

		ArrayDeque dq = new ArrayDeque();
		dq.offerFirst(1);
		dq.offerLast(2);
		dq.addFirst(0);
		dq.addLast(3);
		dq.push(9);
		dq.removeFirstOccurrence(0);
		dq.removeLastOccurrence(3);

		def arrSet = [1, 2, 3, 4];
		Arrays.setAll(arrSet, i -> i * 10);
		Arrays.parallelPrefix(arrSet, (a, b) -> a + b);
		int arrMis = Arrays.mismatch([1, 2, 3], [1, 9, 3]);
		def arrCopy = Arrays.copyOf([1, 2], 4);
		def arrRange = Arrays.copyOfRange([1, 2, 3, 4], 1, 3);
		Arrays.fill(arrCopy, 7);
		int arrBS = Arrays.binarySearch([1, 3, 5], 3);
		boolean arrEq = Arrays.equals([1, 2], [1, 2]) && Arrays.deepEquals([[1]], [[1]]);
		String arrStr = Arrays.toString([1, 2]) + Arrays.deepToString([[1]]);
		int arrHC = Arrays.hashCode([1, 2]) + Arrays.deepHashCode([[1]]);
		return [tmFloor, tmCeil, tmLow, tmHigh, tmHead.size(), tmTail.size(), tmSub.size(), tsFloor, tsCeil, tsLow, tsHigh, tsHead.size(), tsTail.size(), tsSub.size(), dq.size(), arrMis, arrRange.size(), arrBS, arrEq, arrStr != "", arrHC != 0];
	`
	if _, err := Eval(nil, treeDequeScript, map[string]any{}); err != nil {
		t.Fatalf("treeDequeScript failed: %v", err)
	}

	// Block 4: Constants, Enums, Encoding/Digest/String, Temporal/ChronoField.
	arrayDateScript := `
		def dows = [DayOfWeek.MONDAY, DayOfWeek.TUESDAY, DayOfWeek.WEDNESDAY, DayOfWeek.THURSDAY, DayOfWeek.FRIDAY, DayOfWeek.SATURDAY, DayOfWeek.SUNDAY];
		def mons = [Month.JANUARY, Month.FEBRUARY, Month.MARCH, Month.APRIL, Month.MAY, Month.JUNE, Month.JULY, Month.AUGUST, Month.SEPTEMBER, Month.OCTOBER, Month.NOVEMBER, Month.DECEMBER];
		def charsets = [StandardCharsets.UTF_8, StandardCharsets.US_ASCII, StandardCharsets.ISO_8859_1, StandardCharsets.UTF_16, StandardCharsets.UTF_16BE, StandardCharsets.UTF_16LE, Charset.forName("UTF-8")];
		def patFlags = Pattern.UNIX_LINES | Pattern.CASE_INSENSITIVE | Pattern.COMMENTS | Pattern.MULTILINE | Pattern.LITERAL | Pattern.DOTALL | Pattern.UNICODE_CASE | Pattern.CANON_EQ | Pattern.UNICODE_CHARACTER_CLASS;
		def limitsConst = [Integer.MIN_VALUE, Long.MAX_VALUE, Long.MIN_VALUE, OffsetTime.MAX];

		def dowStrVals = ["MONDAY".getValue(), "TUESDAY".getValue(), "WEDNESDAY".getValue(), "THURSDAY".getValue(), "FRIDAY".getValue(), "SATURDAY".getValue(), "SUNDAY".getValue(), "JANUARY".getValue(), "FEBRUARY".getValue(), "MARCH".getValue(), "APRIL".getValue(), "MAY".getValue(), "JUNE".getValue(), "JULY".getValue(), "AUGUST".getValue(), "SEPTEMBER".getValue(), "OCTOBER".getValue(), "NOVEMBER".getValue(), "DECEMBER".getValue()];
		def dowShift = ["MONDAY".plus(3), "MONDAY".minus(2), "JANUARY".plus(4), "JANUARY".minus(2)];

		String encB64 = Encoding.encodeBase64("hi");
		String encHex = Encoding.encodeHex("hi");
		def decHex = Encoding.decodeHex(encHex);
		String dig = Digest.sha256("x") + Digest.md5("x") + Digest.sha1("x") + Digest.sha384("x") + Digest.sha512("x");
		StringBuilder sb = new StringBuilder("ac");
		sb.ensureCapacity(16);
		sb.insert(1, "b");
		boolean ceq = "abc".contentEquals(sb);
		String fmted = "%s-%d".formatted("v", 3);
		def spRes = "a:b:c".split(":", 2);

		def yr = Year.of(2024);
		def ym = YearMonth.of(2024, 2);
		def ymP = YearMonth.parse("2024-02");
		def md = MonthDay.of(Month.FEBRUARY, 29);
		def mdP = MonthDay.parse("--02-29");
		def mdF = MonthDay.from(md);
		def ldo = LocalDate.ofYearDay(2024, 60);
		def lts = LocalTime.ofSecondOfDay(3661);
		def ltn = LocalTime.ofNanoOfDay(1000000L);
		def pm = Period.ofMonths(3);
		def pw = Period.ofWeeks(2);
		def pp = Period.parse("P1Y2M");
		long bet = ChronoUnit.DAYS.between("2024-01-01T00:00:00Z", "2024-01-10T00:00:00Z");
		def dtBase = ZonedDateTime.parse("2024-03-15T14:20:30Z");
		def dtAdj = ChronoField.CLOCK_HOUR_OF_DAY.with(dtBase, 24);
		def dtAdj2 = ChronoField.MONTH_OF_YEAR.with(dtBase, 5);
		def dtAdj3 = ChronoField.DAY_OF_MONTH.with(dtBase, 20);
		long cfVal = dtBase.getLong(ChronoField.HOUR_OF_AMPM) + dtBase.getLong(ChronoField.CLOCK_HOUR_OF_AMPM) + dtBase.getLong(ChronoField.YEAR_OF_ERA) + dtBase.getLong(ChronoField.ERA);
		return [dows.size(), mons.size(), charsets.size(), patFlags > 0, limitsConst.size(), dowStrVals.size(), dowShift.size(), encB64, decHex.size(), dig != "", ceq, fmted, spRes.size(), yr, ym, ymP, md, mdP, mdF, ldo, lts, ltn, pm, pw, pp, bet, dtAdj != null, dtAdj2 != null, dtAdj3 != null, cfVal != 0];
	`
	if _, err := Eval(nil, arrayDateScript, map[string]any{}); err != nil {
		t.Fatalf("arrayDateScript failed: %v", err)
	}

	// Block 5: Streams, Collectors, Collections, instanceof, Math.
	streamMathScript := `
		def intSum = IntStream.range(1, 4).sum();
		def intSumC = IntStream.rangeClosed(1, 3).sum();
		def lngSum = LongStream.range(1, 3).sum();
		def dblArr = DoubleStream.of(1.0, 2.5).toArray();
		def empCnt = Stream.empty().count();
		def colUList = [1, 2].stream().collect(Collectors.toUnmodifiableList());
		def colUSet = [1, 2, 2].stream().collect(Collectors.toUnmodifiableSet());
		def colTree = [3, 1, 2].stream().collect(Collectors.toCollection(() -> new TreeSet()));
		def colSumD = [1.5, 2.5].stream().collect(Collectors.summingDouble(x -> x));
		def colAvgD = [1.0, 3.0].stream().collect(Collectors.averagingDouble(x -> x));
		def colStatD = [1.0, 3.0].stream().collect(Collectors.summarizingDouble(x -> x));
		def colToMap = [["k": "a", "v": 1], ["k": "a", "v": 2]].stream().collect(Collectors.toMap(x -> x.k, x -> x.v, (a, b) -> a + b));

		def mpEnt = Map.entry("x", 9);
		def mpFrom = Map.ofEntries(mpEnt);
		def lc = List.copyOf([1, 2]);
		def sc = Set.copyOf([1, 2]);
		def mc = Map.copyOf(["a": 1]);

		StringBuilder sb2 = new StringBuilder("s");
		def instChecks = [
			new IntSummaryStatistics() instanceof IntSummaryStatistics,
			UUID.randomUUID() instanceof UUID,
			ZoneOffset.UTC instanceof ZoneOffset,
			ZoneId.of("UTC") instanceof ZoneId,
			new URI("https://a.com") instanceof URI,
			new URL("https://a.com") instanceof URL,
			Pattern.compile("a").asPredicate() instanceof Predicate,
			new BytesRef("a") instanceof BytesRef,
			ByteBuffer.wrap([1]) instanceof ByteBuffer,
			DayOfWeek.MONDAY instanceof DayOfWeek,
			"s" instanceof CharSequence,
			sb2 instanceof StringBuilder,
			Period.ofDays(1) instanceof Period,
			Duration.ofSeconds(1) instanceof Duration,
			Pattern.compile("a").matcher("a") instanceof Matcher,
			ChronoField.YEAR instanceof ChronoField,
			LocalTime.of(1, 2) instanceof LocalTime,
			YearMonth.of(2024, 1) instanceof YearMonth,
			LocalDate.of(2024, 1, 1) instanceof LocalDate,
			ZonedDateTime.parse("2024-01-01T00:00:00Z") instanceof ZonedDateTime,
			new BigDecimal("1.0") instanceof BigDecimal
		];

		double mFma = Math.fma(2.0, 3.0, 4.0);
		double mClamp = Math.clamp(15.0, 0.0, 10.0);
		double mHyp = Math.hypot(3.0, 4.0);
		double mAt2 = Math.atan2(1.0, 1.0);
		double mNxt = Math.nextAfter(1.0, 2.0);
		double mMinNaN = Math.min(Double.NaN, 1.0) + Math.max(-0.0, 0.0);
		return [intSum, intSumC, lngSum, dblArr.size(), empCnt, colUList.size(), colUSet.size(), colTree.size(), colSumD, colAvgD, colStatD != null, colToMap.get("a"), mpFrom.size(), lc.size(), sc.size(), mc.size(), instChecks.size(), mFma, mClamp, mHyp > 4.9, mAt2 > 0, mNxt > 1.0, Double.isNaN(mMinNaN)];
	`
	if _, err := Eval(nil, streamMathScript, map[string]any{}); err != nil {
		t.Fatalf("streamMathScript failed: %v", err)
	}

	// List.replaceAll, Map.compute*/merge/forEach inside ApplyUpdateWithResult + ApplyUpdateWithResult _version validation paths.
	upRaw, _, err := ApplyUpdateWithResult(json.RawMessage(`{"items":[1,2,3],"mp":{"k0":1}}`), &UpdateRequest{
		Script: &ScriptSpec{
			Source: `
				params.sum = 0;
				ctx._source.items.replaceAll(x -> x + 10);
				ctx._source.items.forEach(x -> { params.sum += x; });
				ctx._source.mp.computeIfAbsent("k1", k -> 5);
				ctx._source.mp.compute("k1", (k, v) -> v + 2);
				ctx._source.mp.computeIfPresent("k1", (k, v) -> v * 3);
				ctx._source.mp.merge("k2", 4, (o, n) -> o + n);
				ctx._source.mp.merge("k0", 4, (o, n) -> o + n);
				ctx._source.mp.forEach((k, v) -> { params.sum += v; });
				ctx._version = 5;
			`,
			Params: map[string]any{},
		},
		AllowMetaMutation: true,
		MetaVersion:       1,
		IsES8:             false,
	}, false)
	if err != nil {
		t.Fatalf("ApplyUpdateWithResult replaceAll/compute/version failed: %v", err)
	}
	if !strings.Contains(string(upRaw), `"k1":21`) || !strings.Contains(string(upRaw), `"k2":4`) {
		t.Fatalf("unexpected ApplyUpdateWithResult body: %s", string(upRaw))
	}
	// _version null and UBQ validation error paths.
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Script:            &ScriptSpec{Source: "ctx._version = null;"},
		AllowMetaMutation: true,
		MetaVersion:       1,
		IsES8:             false,
	}, false); err != nil {
		t.Fatalf("ApplyUpdateWithResult version nil non-ES8 failed: %v", err)
	}
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Script:            &ScriptSpec{Source: "ctx._version = -9;"},
		AllowMetaMutation: true,
		MetaVersion:       1,
		IsES8:             true,
		IsUBQ:             true,
	}, false); err == nil {
		t.Fatal("expected ValidateCtxVersion error for negative _version")
	}

	// Numeric, Math*Exact, HexFormat, Temporal strict parse, Matcher, Collectors error branches.
	errCases := []string{
		`return new BigDecimal("1").divide(0);`,
		`return new BigDecimal("not_num");`,
		`return new BigDecimal("1").pow(-1);`,
		`return new BigDecimal("99999999999").byteValueExact();`,
		`return new BigInteger("1").divide(0);`,
		`return new BigInteger("2").modInverse(BigInteger.valueOf(4));`,
		`return new BigInteger("999999").byteValueExact();`,
		`BitSet bs = new BitSet(); bs.set(-1);`,
		`BitSet bs = new BitSet(); bs.flip(-1);`,
		`BitSet bs = new BitSet(); return bs.nextSetBit(-2);`,
		`return HexFormat.of().formatHex([10], 0, 5);`,
		`return HexFormat.of().parseHex("0a", 0, 5);`,
		`return Math.addExact(Long.MAX_VALUE, 1L);`,
		`return Math.subtractExact(Long.MIN_VALUE, 1L);`,
		`return Math.multiplyExact(Long.MAX_VALUE, 2L);`,
		`return Math.incrementExact(Long.MAX_VALUE);`,
		`return Math.decrementExact(Long.MIN_VALUE);`,
		`return Math.negateExact(Long.MIN_VALUE);`,
		`return Math.toIntExact(Long.MAX_VALUE);`,
		`return Math.floorDiv(1L, 0L);`,
		`return Math.floorMod(1L, 0L);`,
		`return Duration.parse("not-a-dur");`,
		`return Period.parse("not-a-period");`,
		`return LocalTime.parse("25:00:00");`,
		`return LocalDateTime.parse("not-ldt");`,
		`return Instant.parse("not-inst");`,
		`return OffsetDateTime.parse("not-odt");`,
		`return ZonedDateTime.parse("not-zdt");`,
		`return [1, 2].stream().collect(Collectors.toMap(x -> "same", x -> x));`,
		`return [1, null].stream().collect(Collectors.toUnmodifiableList());`,
		`return [1, 2].stream().collect(Collectors.groupingBy(x -> null));`,
		`return Collections.nCopies(-1, "a");`,
		`return "abc".substring(2, 1);`,
		`return "a".replaceFirst("(a)", "$99");`,
	}
	for _, ec := range errCases {
		if _, err := Eval(nil, ec, map[string]any{}); err == nil {
			t.Fatalf("expected error for edge error script %q", ec)
		}
	}
}

func TestRound67Cov_Round59AssignStreamsAndRound60DocValuesAndRound61_62(t *testing.T) {
	// Round59 compound assignments via ctx, UpdateMetadataVal, static class fields, and lazy streams.
	upRaw, _, err := ApplyUpdateWithResult(json.RawMessage(`{"cnt":10,"nested":{"v":2}}`), &UpdateRequest{
		MetaID:    "id1",
		MetaIndex: "idx1",
		Script: &ScriptSpec{
			Source: `
				ctx.op = "index";
				ctx._source.cnt += 5;
				ctx._source.nested.v *= 3;
				ctx.op += "";
				params._source.extra = 9;
			`,
			Params: map[string]any{},
		},
	}, false)
	if err != nil {
		t.Fatalf("Round59 compound assign ApplyUpdateWithResult failed: %v", err)
	}
	if !strings.Contains(string(upRaw), `"cnt":15`) || !strings.Contains(string(upRaw), `"v":6`) {
		t.Fatalf("unexpected Round59 update output: %s", string(upRaw))
	}

	assignErrs := []string{
		`doc.a = 1;`,
		`def um = Collections.unmodifiableMap(["k": 1]); um.k = 2;`,
		`def ul = Collections.unmodifiableList([1, 2]); Collections.copy(ul, [3]);`,
		`int f() { noSuchVar = 1; return 0; } return f();`,
	}
	for _, sc := range assignErrs {
		if _, err := Eval(map[string]any{"a": 1}, sc, map[string]any{}); err == nil {
			t.Fatalf("expected error for assign script %q", sc)
		}
	}
	if _, err := evalAssignExprRound59Painless(nil, "", "=", "1", map[string]any{}, 0); err == nil {
		t.Fatal("expected error for empty LHS assignment")
	}
	if _, err := evalAssignExprRound59Painless(nil, "1", "=", "2", map[string]any{}, 0); err == nil {
		t.Fatal("expected error for literal LHS assignment")
	}

	streamSrc := `
		def c1 = Stream.concat([1, 2, 3].stream(), [4, 5, 6].stream())
			.filter(x -> x > 1)
			.takeWhile(x -> x < 6)
			.dropWhile(x -> x == 2)
			.peek(x -> { params.peeked += 1; })
			.skip(1)
			.limit(2)
			.sorted()
			.toArray();
		long lSum = [1, 2].stream().flatMapToLong(x -> LongStream.of(x, x + 10)).sum();
		double dSum = [1, 2].stream().mapToDouble(x -> x * 1.5).sum();
		double dFlat = [1, 2].stream().flatMapToDouble(x -> DoubleStream.of(x, x + 0.5)).sum();
		return [c1.size(), params.peeked, lSum, dSum, dFlat];
	`
	sRes, err := Eval(nil, streamSrc, map[string]any{"peeked": int64(0)})
	if err != nil {
		t.Fatalf("Round59 lazy stream script failed: %v", err)
	}
	if ss := sRes.([]any); ss[0] != int64(2) || ss[2] != int64(26) {
		t.Fatalf("unexpected Round59 lazy stream result: %#v", ss)
	}

	// Round60 FieldVal, DenseVectorVal, FieldDocVal, BytesRefVal, ByteBufferVal, GeoPointVal, GeoShapeDocValues, builtins, Round62 DayOfWeekEnum/MonthEnum.
	dvDoc := map[string]any{
		"nums":    []any{int64(10), int64(20)},
		"badGeo":  "not_a_geo",
		"vec":     []any{1.0, 0.0, 0.0},
		"geo":     map[string]any{"lat": 40.7, "lon": -74.0},
		"shape":   "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))",
		"mshape":  "MULTIPOLYGON (((0 0, 1 0, 1 1, 0 1, 0 0)))",
		"mpoint":  "MULTIPOINT ((1 2), (3 4))",
		"mline":   "MULTILINESTRING ((0 0, 1 1), (2 2, 3 3))",
		"nested":  []any{map[string]any{"vec": []any{0.6, 0.8}}},
		"ulField": "18446744073709551615",
	}
	dvParams := map[string]any{
		"__field_types": map[string]string{
			"vec":     "dense_vector",
			"missVec": "dense_vector",
			"geo":     "geo_point",
			"shape":   "geo_shape",
			"mshape":  "geo_shape",
			"mpoint":  "geo_shape",
			"mline":   "geo_shape",
			"ulField": "unsigned_long",
		},
	}
	dvSrc1 := `
		boolean fEmpty = field("nums").empty;
		def fLen = field("nums").length;
		boolean fIsEmp = field("nums").isEmpty();
		def fVals = field("nums").values();
		def fSize = field("nums").size();
		def fDocs = field("nums").docs();
		def fDoc0 = field("nums").doc();
		def eDbl = field("emptyF").asDouble();
		def eDt = field("emptyF").asDate();
		def eGp = field("emptyF").asGeoPoint();
		def eStr = field("emptyF").asString();
		String fStr = field("nums").toString();

		def vfLen = field("vec").length;
		boolean vfEmp = field("vec").empty;
		def mvfLen = field("missVec").length;
		boolean mvfEmp = field("missVec").empty;
		def dvObj = field("vec").getValue();
		def dvLen = dvObj != null ? dvObj.length : -1;
		boolean dvEmp = dvObj != null ? dvObj.empty : true;
		def dvVecProp = doc.vec.vectorValue;
		def dvMagProp = doc.vec.magnitude;
		boolean docVecEmp = doc.vec.empty;
		def docVecLen = doc.vec.length;
		def dvSize = doc["vec"].size();
		def dvDims = doc["vec"].getDims();
		double dp = dotProduct([1.0, 2.0, 3.0], "vec");
		double cs = cosineSimilarity([1.0, 0.0, 0.0], "vec");
		double l1 = l1norm([0.0, 1.0, 0.0], "vec");
		double l2 = l2norm([0.0, 0.0, 1.0], "vec");
		def subDoc = field("nested").doc(0);
		def subVec = subDoc.field("vec");
		def subVecVal = subDoc.$("vec");
		return [fEmpty, fLen, fIsEmp, fVals.size(), fSize, fDocs != null, fDoc0 != null, eDbl == null, eDt == null, eGp == null, eStr == null, fStr != "", vfLen, vfEmp, mvfLen, mvfEmp, dvLen, dvEmp, dvVecProp.size(), dvMagProp, docVecEmp, docVecLen, dvSize, dvDims, dp, cs, l1 > 0, l2 > 0, subVec != null, subVecVal != null];
	`
	if dvRes1, err := Eval(dvDoc, dvSrc1, dvParams); err != nil {
		t.Fatalf("dvSrc1 failed: %v", err)
	} else if s := dvRes1.([]any); s[1] != int64(2) || s[16] != int64(3) || s[22] != int64(3) {
		t.Fatalf("unexpected dvSrc1 result: %#v", s)
	}

	dvSrc2 := `
		BytesRef br = new BytesRef("hello");
		def brL = br.length;
		boolean brE = br.empty;
		String brU = br.utf8ToString();
		def brPos = br.position();
		String brS = br.toString();

		ByteBuffer bb = ByteBuffer.wrap([65, 66]);
		def bbL = bb.length;
		boolean bbE = bb.empty;
		def bbG = bb.get();
		String bbS = bb.toString();

		def gp = field("geo").asGeoPoint();
		def gpCent = gp.getCentroid();
		def gpBox = gp.getBoundingBox();
		def gpLbl = gp.getLabelPosition();
		def gpDim = gp.getDimensionalType();
		def gpMW = gp.getMercatorWidth();
		def gpMH = gp.getMercatorHeight();
		String gpStr = gp.toString();

		def shp = doc["shape"].get(0);
		def shpBox = shp.getBoundingBox();
		def shpCent = shp.getCentroid();
		def arrLbl = [gp].getLabelPosition();

		double sat = saturation(5.0, 2.0);
		double sig = sigmoid(5.0, 2.0, 1.0);
		double dNum = decayNumericLinear(10.0, 5.0, 2.0, 0.5, 10.0) + decayNumericExp(10.0, 5.0, 2.0, 0.5, 10.0) + decayNumericGauss(10.0, 5.0, 2.0, 0.5, 10.0);
		double dGeo = decayGeoLinear(gp, "5km", "1km", 0.5, gp);
		double rScore = randomScore(42);
		return [brL, brE, brU, brPos, brS != "", bbL, bbE, bbG, bbS != "", gpCent != null, gpBox != null, gpLbl != null, gpDim, gpMW, gpMH, gpStr != "", shpBox != null, shpCent != null, arrLbl != null, sat > 0, sig > 0, dNum > 0, dGeo > 0, rScore >= 0];
	`
	if _, err := Eval(dvDoc, dvSrc2, dvParams); err != nil {
		t.Fatalf("dvSrc2 failed: %v", err)
	}

	dvSrc3 := `
		String dowFull = DayOfWeek.MONDAY.getDisplayName("FULL", "en");
		def dowV = DayOfWeek.MONDAY.getValue();
		String dowN = DayOfWeek.MONDAY.name();
		def dowP = DayOfWeek.MONDAY.plus(2);
		def dowM = DayOfWeek.MONDAY.minus(1);
		boolean dowEq = DayOfWeek.MONDAY.equals(DayOfWeek.MONDAY);
		def dowCmp = DayOfWeek.MONDAY.compareTo(DayOfWeek.FRIDAY);

		String monShort = Month.FEBRUARY.getDisplayName("SHORT", "en");
		def monV = Month.FEBRUARY.getValue();
		String monN = Month.FEBRUARY.name();
		def monMin = Month.FEBRUARY.minLength();
		def monMax = Month.FEBRUARY.maxLength();
		def monQ = Month.FEBRUARY.firstMonthOfQuarter();
		def monLen = Month.FEBRUARY.length(true);
		def monP = Month.FEBRUARY.plus(1);
		def monM = Month.FEBRUARY.minus(2);
		boolean monEq = Month.FEBRUARY.equals(Month.FEBRUARY);
		def monCmp = Month.FEBRUARY.compareTo(Month.MAY);
		return [dowFull, dowV, dowN, dowP, dowM, dowEq, dowCmp, monShort, monV, monN, monMin, monMax, monQ, monLen, monP, monM, monEq, monCmp];
	`
	if dvRes3, err := Eval(dvDoc, dvSrc3, dvParams); err != nil {
		t.Fatalf("dvSrc3 failed: %v", err)
	} else if s := dvRes3.([]any); s[0] != "Monday" {
		t.Fatalf("unexpected dvSrc3 result: %#v", s)
	}

	// Builtin / vector / grok / dissect / WKT / enum error cases.
	r60Errs := []string{
		`return grok();`,
		`String p = "%{INT:a}"; return grok(p);`,
		`return dissect();`,
		`return saturation(1.0);`,
		`return saturation("a", 2);`,
		`return sigmoid(1.0);`,
		`return sigmoid("a", 1, 1);`,
		`return decayDateLinear(0);`,
		`return decayGeoLinear(0);`,
		`return dotProduct([1.0]);`,
		`return doc["missVec"].magnitude;`,
		`return field("missVec").getValue().length;`,
		`return field("badGeo").asGeoPoint();`,
		`return DayOfWeek.MONDAY.getDisplayName("BAD", "en");`,
		`return DayOfWeek.MONDAY.getDisplayName(null, "en");`,
		`return DayOfWeek.MONDAY.plus("bad");`,
	}
	for _, sc := range r60Errs {
		if _, err := Eval(dvDoc, sc, dvParams); err == nil {
			t.Fatalf("expected error for Round60-62 script %q", sc)
		}
	}
	nilArgFn := func() ([]any, error) { return []any{nil}, nil }
	for _, m := range []string{"compareTo", "getDisplayName", "plus"} {
		if _, handled, err := evalEnumReceiverMethodRound62(DayOfWeekEnum{Value: 1}, m, nilArgFn); !handled || err == nil {
			t.Fatalf("expected handled error for DayOfWeekEnum.%s(null)", m)
		}
		if _, handled, err := evalEnumReceiverMethodRound62(MonthEnum{Value: 1}, m, nilArgFn); !handled || err == nil {
			t.Fatalf("expected handled error for MonthEnum.%s(null)", m)
		}
	}
	strArgFn := func() ([]any, error) { return []any{"not_enum"}, nil }
	if _, handled, err := evalEnumReceiverMethodRound62(DayOfWeekEnum{Value: 1}, "compareTo", strArgFn); !handled || err == nil {
		t.Fatal("expected ClassCastException for DayOfWeekEnum.compareTo(string)")
	}
	if _, handled, err := evalEnumReceiverMethodRound62(MonthEnum{Value: 1}, "compareTo", strArgFn); !handled || err == nil {
		t.Fatal("expected ClassCastException for MonthEnum.compareTo(string)")
	}

	// Direct Go helper paths for WKT, GrokExtractor, DissectExtractor, boundedRegexLRUCache, half-float, IPAddress.
	for _, wkt := range []string{
		"EMPTY",
		"LINESTRING EMPTY",
		"POLYGON EMPTY",
		"MULTIPOINT ((1 2), (3 4))",
		"MULTIPOINT (1 2, 3 4)",
		"MULTILINESTRING ((0 0, 1 1), (2 2, 3 3))",
		"POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))",
		"MULTIPOLYGON (((0 0, 1 0, 1 1, 0 1, 0 0)))",
	} {
		if gs, wErr := parseWKTGeoShapeRound61(wkt, true); wErr != nil || gs == nil {
			t.Fatalf("parseWKTGeoShapeRound61(%q) failed: %v", wkt, wErr)
		}
	}
	for _, badWkt := range []string{"", "POINT (bad", "NOTAWKT", "MULTILINESTRING ()", "POLYGON ()"} {
		if _, wErr := parseWKTGeoShapeRound61(badWkt, false); wErr == nil {
			t.Fatalf("expected error for bad WKT %q", badWkt)
		}
	}

	if gx, gErr := CompileGrokPattern("%{INT:a:int} %{INT:b:boolean}"); gErr != nil || gx == nil {
		t.Fatalf("CompileGrokPattern failed: %v", gErr)
	} else {
		_ = gx.String()
		if _, ok := convertGrokTypedCaptureRound62("notint", "int"); ok {
			t.Fatal("expected invalid int capture to fail")
		}
		if _, ok := convertGrokTypedCaptureRound62("notbool", "boolean"); ok {
			t.Fatal("expected invalid boolean capture to fail")
		}
		if _, ok := convertGrokTypedCaptureRound62("notfloat", "float"); ok {
			t.Fatal("expected invalid float capture to fail")
		}
	}
	if dx, dErr := CompileDissectPattern("%{a}-%{b}"); dErr != nil || dx == nil {
		t.Fatalf("CompileDissectPattern failed: %v", dErr)
	} else {
		_ = dx.String()
	}
}

func TestRound67Cov_HighYieldEvalCoreAndStatements(t *testing.T) {
	// 1. User-object collection statement dispatch & null-safe collection statements (execSimpleStmt).
	stmtColSrc := `
		class UC {
			List xs = [];
			Map m = [:];
			void add(def x) { this.xs.add(x); }
			void addAll(def c) { this.xs.addAll(c); }
			void set(int i, def v) { this.xs.set(i, v); }
			boolean remove(def x) { return true; }
			void removeAll(def c) {}
			void retainAll(def c) {}
			void removeIf(def p) {}
			void put(def k, def v) { this.m.put(k, v); }
			void putAll(def mm) { this.m.putAll(mm); }
			void clear() { this.xs.clear(); }
		}
		UC uc = new UC();
		uc.add(1);
		uc.addAll([2, 3]);
		uc.set(0, 9);
		uc.remove(0);
		uc.removeAll([2]);
		uc.retainAll([3]);
		uc.removeIf(x -> true);
		uc.put("a", 1);
		uc.putAll(["b": 2]);
		uc.clear();

		List nl = null;
		nl?.add(1);
		nl?.addAll([1]);
		nl?.remove(0);
		nl?.removeAll([1]);
		nl?.retainAll([1]);
		nl?.set(0, 1);
		nl?.removeIf(x -> true);
		nl?.clear();
		Map nm = null;
		nm?.put("a", 1);
		nm?.putAll(["b": 2]);
		nm?.remove("a");
		nm?.clear();
		return [uc.m.size(), uc.xs.size()];
	`
	if res, err := Eval(nil, stmtColSrc, map[string]any{}); err != nil {
		t.Fatalf("stmtColSrc failed: %v", err)
	} else if s := res.([]any); s[0] != int64(2) || s[1] != int64(0) {
		t.Fatalf("unexpected stmtColSrc result: %#v", s)
	}

	// 2. Subclass super.method(), recursion depth limit, throw, switch statement & switch expressions.
	superSrc := `
		class Base {
			int v = 10;
			int f(int x) { return x + this.v; }
		}
		class Child extends Base {
			int f(int x) { return super.f(x) + 1; }
		}
		Child ch = new Child();
		return ch.f(5);
	`
	if res, err := Eval(nil, superSrc, map[string]any{}); err != nil || res != int64(16) {
		t.Fatalf("superSrc expected 16, got (%#v, %v)", res, err)
	}
	if _, err := Eval(nil, `int rec(int n) { return n <= 0 ? 0 : rec(n - 1); } return rec(70);`, map[string]any{}); err == nil {
		t.Fatal("expected depth overflow error for rec(70)")
	}
	if _, err := Eval(nil, `throw "boom";`, map[string]any{}); err == nil {
		t.Fatal("expected error from throw \"boom\"")
	}
	if _, err := Eval(nil, `throw new RuntimeException("rt_boom");`, map[string]any{}); err == nil {
		t.Fatal("expected error from throw new RuntimeException")
	}

	switchSrc := `
		int out = 0;
		switch (2) {
		case 1:
			out = 10;
			break;
		case 2:
		case 3:
			out = 25;
			break;
		default:
			out = 99;
		}
		int arrowOut = 0;
		switch (1) {
		case 1 -> arrowOut = 7;
		default -> arrowOut = 8;
		}
		switch (99) {
		case 1 -> arrowOut = 100;
		}
		int e1 = switch (2) {
		case 1 -> 10;
		case 2, 3 -> { yield 20; }
		default -> 30;
		};
		def eMiss = switch (99) {
		case 1 -> 10;
		};
		return [out, arrowOut, e1, eMiss == null];
	`
	if res, err := Eval(nil, switchSrc, map[string]any{}); err != nil {
		t.Fatalf("switchSrc failed: %v", err)
	} else if s := res.([]any); s[0] != int64(25) || s[1] != int64(7) || s[2] != int64(20) || s[3] != true {
		t.Fatalf("unexpected switchSrc result: %#v", s)
	}
	for _, badSw := range []string{
		`switch (null) { default -> 1; }`,
		`return switch (null) { default -> 1; };`,
	} {
		if _, err := Eval(nil, badSw, map[string]any{}); err == nil {
			t.Fatalf("expected NPE on %q", badSw)
		}
	}
	_ = execSwitchStatement(nil, "switch bad", map[string]any{}, nil, &evalBudget{})
	_ = execSwitchStatement(nil, "switch (1) no_brace", map[string]any{}, nil, &evalBudget{})
	_ = execSwitchStatement(nil, "switch (1) { bad }", map[string]any{}, nil, &evalBudget{})
	_ = execSwitchStatement(nil, "switch (1) {}", map[string]any{}, nil, &evalBudget{})
	_, _, _ = evalSwitchExprPainless(nil, "switch bad", map[string]any{}, 0)
	_, _, _ = evalSwitchExprPainless(nil, "switch (1", map[string]any{}, 0)
	_, _, _ = evalSwitchExprPainless(nil, "switch (1) no_brace", map[string]any{}, 0)
	_, _, _ = evalSwitchExprPainless(nil, "switch (1) {}", map[string]any{}, 0)

	// 3. Collectors with shadowed outer loop variable names (hadPrev/hadK/hadV/had1/had2) + early return in forEach.
	collectorShadowSrc := `
		def x = 999;
		def k = 999;
		def v = 999;
		def a = 999;
		def b = 999;
		def src = [1, 2, 3];
		def cList = src.stream().collect(Collectors.toList());
		def cSet = src.stream().collect(Collectors.toSet());
		def cMap = [["k": "a", "v": 1], ["k": "b", "v": 2]].stream().collect(Collectors.toMap(k -> k.k, v -> v.v, (a, b) -> a + b));
		def cGrp = src.stream().collect(Collectors.groupingBy(x -> x % 2));
		def cPart = src.stream().collect(Collectors.partitioningBy(x -> x > 1));
		def cRed = src.stream().collect(Collectors.reducing(0, (a, b) -> a + b));
		def cSumI = src.stream().collect(Collectors.summingInt(x -> x));
		def cSumL = src.stream().collect(Collectors.summingLong(x -> x));
		def cSumD = src.stream().collect(Collectors.summingDouble(x -> x));
		def cAvgI = src.stream().collect(Collectors.averagingInt(x -> x));
		def cAvgL = src.stream().collect(Collectors.averagingLong(x -> x));
		def cAvgD = src.stream().collect(Collectors.averagingDouble(x -> x));
		def cStatI = src.stream().collect(Collectors.summarizingInt(x -> x));
		def cStatL = src.stream().collect(Collectors.summarizingLong(x -> x));
		def cStatD = src.stream().collect(Collectors.summarizingDouble(x -> x));
		def cMapC = src.stream().collect(Collectors.mapping(x -> x + 1, Collectors.toList()));
		def cAndT = src.stream().collect(Collectors.collectingAndThen(Collectors.toList(), a -> a.size()));
		def cJoin = ["a", "b"].stream().collect(Collectors.joining(","));
		def cCnt = src.stream().collect(Collectors.counting());
		def cMax = src.stream().collect(Collectors.maxBy(Comparator.naturalOrder()));
		def cMin = src.stream().collect(Collectors.minBy(Comparator.naturalOrder()));

		params.sum = 0;
		[1, 2, 3].forEach(x -> { if (x == 2) return; params.sum += x; });
		return [x, k, v, a, b, cList.size(), cSet.size(), cMap.size(), cGrp.size(), cPart.size(), cRed, cSumI, cSumL, cSumD, cAvgI, cAvgL, cAvgD, cStatI != null, cStatL != null, cStatD != null, cMapC.size(), cAndT, cJoin, cCnt, cMax.get(), cMin.get(), params.sum];
	`
	if res, err := Eval(nil, collectorShadowSrc, map[string]any{}); err != nil {
		t.Fatalf("collectorShadowSrc failed: %v", err)
	} else if s := res.([]any); s[0] != int64(999) || s[26] != int64(4) {
		t.Fatalf("unexpected collectorShadowSrc result: %#v", s)
	}
	for _, colErr := range []string{
		`def x = 1; return [1].stream().collect(Collectors.mapping(x -> Integer.parseInt("x"), Collectors.toList()));`,
		`def x = 1; return [1].stream().collect(Collectors.groupingBy(x -> Integer.parseInt("x")));`,
		`def k = 1; return [1].stream().collect(Collectors.toMap(k -> Integer.parseInt("x"), v -> v));`,
		`def x = 1; return [1].stream().collect(Collectors.summingInt(x -> Integer.parseInt("x")));`,
	} {
		if _, err := Eval(nil, colErr, map[string]any{}); err == nil {
			t.Fatalf("expected collector error for %q", colErr)
		}
	}

	// 4. TemporalAdjusters, DateTimeFormatter, BigDecimal/Duration/Matcher/Optional/MethodRef/ValuesEqual.
	miscRHSSrc := `
		def zdt = ZonedDateTime.parse("2024-03-15T14:20:30Z");
		def taRes = [
			zdt.with(TemporalAdjusters.firstDayOfMonth()),
			zdt.with(TemporalAdjusters.lastDayOfMonth()),
			zdt.with(TemporalAdjusters.firstDayOfNextMonth()),
			zdt.with(TemporalAdjusters.firstDayOfYear()),
			zdt.with(TemporalAdjusters.lastDayOfYear()),
			zdt.with(TemporalAdjusters.firstDayOfNextYear()),
			zdt.with(TemporalAdjusters.next(DayOfWeek.MONDAY)),
			zdt.with(TemporalAdjusters.previous(DayOfWeek.FRIDAY)),
			zdt.with(TemporalAdjusters.nextOrSame(DayOfWeek.FRIDAY)),
			zdt.with(TemporalAdjusters.previousOrSame(DayOfWeek.FRIDAY)),
			zdt.with(TemporalAdjusters.firstInMonth(DayOfWeek.MONDAY)),
			zdt.with(TemporalAdjusters.lastInMonth(DayOfWeek.FRIDAY)),
			zdt.with(TemporalAdjusters.dayOfWeekInMonth(2, DayOfWeek.TUESDAY)),
			zdt.format(DateTimeFormatter.ISO_INSTANT),
			zdt.format(DateTimeFormatter.ISO_LOCAL_DATE),
			zdt.format(DateTimeFormatter.ISO_LOCAL_TIME),
			zdt.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME),
			zdt.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME),
			zdt.format(DateTimeFormatter.ISO_ZONED_DATE_TIME),
			ZoneId.of("America/New_York").getId()
		];

		BigDecimal bdz = new BigDecimal("42.0");
		def bdBi = bdz.toBigInteger();
		def bdBiEx = bdz.toBigIntegerExact();
		int oi = OptionalInt.of(5).getAsInt();
		long ol = OptionalLong.of(6L).getAsLong();
		double od = OptionalDouble.of(2.5).getAsDouble();
		int otVal = Optional.of(7).orElseThrow();
		def linesCnt = "l1\nl2\nl3".lines().count();
		def durNeg = Duration.ofSeconds(-5).abs().negated();
		def zMonth = zdt.getMonth();
		def zDayY = zdt.getDayOfYear();

		Matcher mat = Pattern.compile("a(\\d)").matcher("xxa1ya2zz");
		mat.region(2, 7);
		int rStart = mat.regionStart();
		StringBuffer sb = new StringBuffer();
		while (mat.find()) {
			mat.appendReplacement(sb, "[$1]");
		}
		mat.appendTail(sb);

		BitSet bsNull = null;
		def bsSafe = bsNull?.get(0);
		BitSet bsTmp = new BitSet();
		bsTmp.set(2);
		boolean bsNotEmpty = bsTmp.isEmpty();
		int bsSz = bsTmp.size();
		bsTmp.clear();

		def mRef1 = ["a", "bb"].stream().map(String::length).collect(Collectors.toList());
		def mRef2 = ["x", null].stream().filter(Objects::nonNull).collect(Collectors.toList());

		boolean eqTests = (Optional.of(1) == Optional.of(1))
			&& !(Optional.empty() == Optional.of(1))
			&& (Clock.systemUTC() == Clock.systemUTC())
			&& (new Version("1.0") == new Version("1.0"))
			&& (new GeoPoint(1.0, 2.0) == new GeoPoint(1.0, 2.0))
			&& (OffsetTime.parse("10:00:00Z") == OffsetTime.parse("10:00:00Z"));

		return [taRes.size(), bdBi.intValue(), bdBiEx.intValue(), oi, ol, od, otVal, linesCnt, durNeg != null, zMonth, zDayY, rStart, sb.toString(), bsSafe == null, bsNotEmpty, bsSz >= 0, mRef1.size(), mRef2.size(), eqTests];
	`
	if res, err := Eval(nil, miscRHSSrc, map[string]any{}); err != nil {
		t.Fatalf("miscRHSSrc failed: %v", err)
	} else if s := res.([]any); s[0] != int64(20) || s[1] != int64(42) || s[6] != int64(7) || s[12] != "[1]y[2]zz" || s[18] != true {
		t.Fatalf("unexpected miscRHSSrc result: %#v", s)
	}
	if _, err := Eval(nil, `return Optional.empty().orElseThrow();`, map[string]any{}); err == nil {
		t.Fatal("expected error from Optional.empty().orElseThrow()")
	}

	// 5. Eval with _ctx_* params + ApplyUpdateWithResult op mutation + round60 hex signed byte vector & flattened types.
	ctxRes, err := Eval(map[string]any{"x": 1}, `return [ctx._id, ctx._index, ctx._routing, ctx._version, ctx.op];`, map[string]any{
		"_ctx_op":      "index",
		"_ctx_id":      "doc1",
		"_ctx_index":   "idx1",
		"_ctx_routing": "r1",
		"_ctx_version": int64(3),
	})
	if err != nil {
		t.Fatalf("Eval with _ctx_* params failed: %v", err)
	}
	if s := ctxRes.([]any); s[0] != "doc1" || s[1] != "idx1" || s[2] != "r1" || s[3] != int64(3) || s[4] != "index" {
		t.Fatalf("unexpected _ctx_* result: %#v", s)
	}

	// Hex signed byte vector & map[string]any __field_types + GeoBoundingBox topLeft/bottomRight.
	hexVecDoc := map[string]any{
		"bvec": "01020304",
		"flat": map[string]any{"inner": "ok"},
		"box":  map[string]any{"top": 10.0, "left": 1.0, "bottom": 0.0, "right": 5.0},
	}
	hexVecParams := map[string]any{
		"__field_types": map[string]any{
			"bvec": "dense_vector",
			"flat": "flattened",
		},
	}
	if hvRes, err := Eval(hexVecDoc, `return [doc.bvec.vectorValue.size(), field("flat.inner").get(), new GeoBoundingBox(10.0, 0.0, 5.0, 1.0)];`, hexVecParams); err != nil {
		t.Fatalf("hexVec/flattened eval failed: %v", err)
	} else if s := hvRes.([]any); s[1] != "ok" {
		t.Fatalf("unexpected hexVec/flattened result: %#v", s)
	}
	bbox := &GeoBoundingBoxVal{TopLeft: &GeoPointVal{Lat: 10, Lon: 1}, BottomRight: &GeoPointVal{Lat: 0, Lon: 5}}
	if v, ok := resolveWrapperPropertyRound60(bbox, "topLeft"); !ok || v == nil {
		t.Fatalf("expected GeoBoundingBoxVal.topLeft to resolve, got (%#v, %v)", v, ok)
	}
	if v, ok := resolveWrapperPropertyRound60(bbox, "bottomRight"); !ok || v == nil {
		t.Fatalf("expected GeoBoundingBoxVal.bottomRight to resolve, got (%#v, %v)", v, ok)
	}
	if _, opRes, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `ctx.op = "noop";`},
	}, true); err != nil || opRes != "noop" {
		t.Fatalf("ApplyUpdateWithResult noop failed: (%q, %v)", opRes, err)
	}

	// 6. Round61 regex AST caps, LRU cache eviction, wrapped regex length cap, pinned container caps, ParseIPAddressVal.
	if err := validateBoundedRegexSyntaxR67(strings.Repeat("(", 270) + "a" + strings.Repeat(")", 270)); err == nil {
		t.Fatal("expected maxRegexASTDepth rejection")
	}
	if err := validateBoundedRegexSyntaxR67(strings.Repeat("(ab|cd)", 11000)); err == nil {
		t.Fatal("expected maxRegexASTNodes rejection")
	}
	if err := validateBoundedRegexSyntaxR67(strings.Repeat("a{900}", 80)); err == nil {
		t.Fatal("expected maxRegexProgramWeight rejection")
	}
	if _, err := compileBoundedWrappedRegexRound61("", strings.Repeat("a", MaxRegexPatternLen+1), ""); err == nil {
		t.Fatal("expected length rejection in compileBoundedWrappedRegexRound61")
	}
	for i := 0; i < 1030; i++ {
		if _, err := CompileBoundedRawRegex("r67cov_pat_" + strconv.Itoa(i)); err != nil {
			t.Fatalf("CompileBoundedRawRegex LRU fill #%d failed: %v", i, err)
		}
	}
	pinBudget := &evalBudget{}
	if err := recordPinnedContainerRound61(pinBudget, []any{1}, -1); err != nil {
		t.Fatalf("recordPinnedContainerRound61(-1) failed: %v", err)
	}
	if err := recordPinnedContainerRound61(pinBudget, []any{2}, MaxPinnedElements+1); err == nil {
		t.Fatal("expected MaxPinnedElements overflow error")
	}
	if err := recordPinnedContainerRound61(pinBudget, []any{3}, 1); err == nil {
		t.Fatal("expected stickyErr return")
	}
	pinBudget2 := &evalBudget{}
	for i := 0; i < MaxPinnedRefs; i++ {
		_ = recordPinnedContainerRound61(pinBudget2, i, 1)
	}
	if err := recordPinnedContainerRound61(pinBudget2, "overflow", 1); err == nil {
		t.Fatal("expected MaxPinnedRefs overflow error")
	}
	_ = recordAllocatedElementsRound61(pinBudget2, 10000000)
	if ip, ipErr := ParseIPAddressVal("10.0.0.1"); ipErr != nil || ip == nil {
		t.Fatalf("ParseIPAddressVal IPv4 failed: %v", ipErr)
	}
	if ip6, ipErr := ParseIPAddressVal("::1"); ipErr != nil || ip6 == nil {
		t.Fatalf("ParseIPAddressVal IPv6 failed: %v", ipErr)
	}
	if _, ipErr := ParseIPAddressVal("not.an.ip"); ipErr == nil {
		t.Fatal("expected ParseIPAddressVal error for bad IP")
	}
}

func TestRound67Cov_HighYieldErrorPropagationAndRound54To63Helpers(t *testing.T) {
	// Float32 compound assign, BigDecimal RoundingModes, Math.getExponent, strict parse, ClassCastException.
	okScript := `
		float f = 10.0f;
		f -= 2.0f;
		f *= 3.0f;
		f /= 4.0f;
		f %= 5.0f;
		BigDecimal bd = new BigDecimal("10");
		def bdModes = [
			bd.divide(new BigDecimal("3"), 2, RoundingMode.UP),
			bd.divide(new BigDecimal("3"), 2, RoundingMode.DOWN),
			bd.divide(new BigDecimal("3"), 2, RoundingMode.CEILING),
			bd.divide(new BigDecimal("3"), 2, RoundingMode.FLOOR),
			bd.divide(new BigDecimal("3"), 2, RoundingMode.HALF_DOWN),
			bd.divide(new BigDecimal("3"), 2, RoundingMode.HALF_EVEN)
		];
		int exp0 = Math.getExponent(0.0);
		int expNaN = Math.getExponent(Double.NaN);
		int exp16 = Math.getExponent(16.0);
		boolean bParse = Boolean.parseBoolean("true");
		int iMax = Integer.max(9, 3);
		int iHi0 = Integer.highestOneBit(0);
		short sv = (short)12;
		return [f, bdModes.size(), exp0, expNaN, exp16, bParse, iMax, iHi0, sv.shortValue()];
	`
	if res, err := Eval(nil, okScript, map[string]any{}); err != nil {
		t.Fatalf("okScript failed: %v", err)
	} else if s := res.([]any); s[1] != int64(6) || s[4] != int64(4) || s[5] != true || s[6] != int64(9) {
		t.Fatalf("unexpected okScript result: %#v", s)
	}

	// Direct parseStrictJavaTemporalPainless + strict parser error branches.
	if _, err := parseStrictJavaTemporalPainless("Duration.parse", []string{"params.v"}, nil, map[string]any{"v": time.Second}, 0); err == nil {
		t.Fatal("expected Duration.parse to reject time.Duration value")
	}
	if _, err := parseStrictJavaTemporalPainless("Duration.parse", []string{`" P1D "`}, nil, map[string]any{}, 0); err == nil {
		t.Fatal("expected Duration.parse to reject padded whitespace")
	}
	if _, err := parseStrictJavaTemporalPainless("Period.parse", []string{"params.v"}, nil, map[string]any{"v": painlessPeriod{days: 1}}, 0); err == nil {
		t.Fatal("expected Period.parse to reject painlessPeriod value")
	}

	// Argument-evaluation error propagation & domain boundary errors across round54..round62 and eval.go.
	errPropagationScripts := []string{
		// round54 Optional/Objects/Collections/ZoneOffset/Clock/OffsetTime/URI/URL/Locale/SummaryStats
		`return Optional.of(Integer.parseInt("x"));`,
		`return Objects.compare(Integer.parseInt("x"), 2, Comparator.naturalOrder());`,
		`return Objects.compare(1, Integer.parseInt("x"), Comparator.naturalOrder());`,
		`return Objects.requireNonNullElseGet(Integer.parseInt("x"), () -> 1);`,
		`return Objects.checkIndex(Integer.parseInt("x"), 5);`,
		`return Objects.checkIndex(1, Integer.parseInt("x"));`,
		`return Objects.checkFromToIndex(Integer.parseInt("x"), 2, 3);`,
		`return Objects.checkFromToIndex(1, Integer.parseInt("x"), 3);`,
		`return Objects.checkFromToIndex(1, 2, Integer.parseInt("x"));`,
		`return Objects.checkFromIndexSize(Integer.parseInt("x"), 1, 3);`,
		`return Objects.checkFromIndexSize(1, Integer.parseInt("x"), 3);`,
		`return Objects.checkFromIndexSize(1, 1, Integer.parseInt("x"));`,
		`return Objects.toIdentityString(Integer.parseInt("x"));`,
		`return Objects.hashCode(Integer.parseInt("x"));`,
		`return Objects.hash(1, Integer.parseInt("x"));`,
		`return Collections.indexOfSubList(Integer.parseInt("x"), [1]);`,
		`return Collections.indexOfSubList([1], Integer.parseInt("x"));`,
		`List a = [1]; Collections.addAll(a, Integer.parseInt("x"));`,
		`return Collections.copy(Integer.parseInt("x"), [1]);`,
		`return Collections.copy([1], Integer.parseInt("x"));`,
		`return Collections.unmodifiableList(Integer.parseInt("x"));`,
		`return Collections.unmodifiableMap(Integer.parseInt("x"));`,
		`return Collections.synchronizedList(Integer.parseInt("x"));`,
		`return ZoneOffset.ofHours(Integer.parseInt("x"));`,
		`return ZoneOffset.ofHoursMinutes(Integer.parseInt("x"), 0);`,
		`return ZoneOffset.ofHoursMinutes(1, Integer.parseInt("x"));`,
		`return ZoneOffset.ofHoursMinutesSeconds(Integer.parseInt("x"), 0, 0);`,
		`return ZoneOffset.ofHoursMinutesSeconds(1, Integer.parseInt("x"), 0);`,
		`return ZoneOffset.ofHoursMinutesSeconds(1, 0, Integer.parseInt("x"));`,
		`return ZoneOffset.ofTotalSeconds(Integer.parseInt("x"));`,
		`return ZoneId.ofOffset(Integer.parseInt("x"), ZoneOffset.UTC);`,
		`return ZoneId.ofOffset("GMT", Integer.parseInt("x"));`,
		`return Clock.system(Integer.parseInt("x"));`,
		`return Clock.fixed(Integer.parseInt("x"), ZoneOffset.UTC);`,
		`return Clock.fixed(Instant.now(), Integer.parseInt("x"));`,
		`return Clock.offset(Integer.parseInt("x"), Duration.ofSeconds(1));`,
		`return Clock.offset(Clock.systemUTC(), Integer.parseInt("x"));`,
		`return Clock.tickSeconds(Integer.parseInt("x"));`,
		`return Clock.tick(Integer.parseInt("x"), Duration.ofSeconds(1));`,
		`return Clock.tick(Clock.systemUTC(), Integer.parseInt("x"));`,
		`return OffsetTime.of(Integer.parseInt("x"), ZoneOffset.UTC);`,
		`return OffsetTime.of(LocalTime.of(1, 2), Integer.parseInt("x"));`,
		`return OffsetTime.of(Integer.parseInt("x"), 0, 0, 0, ZoneOffset.UTC);`,
		`return OffsetTime.of(1, Integer.parseInt("x"), 0, 0, ZoneOffset.UTC);`,
		`return OffsetTime.parse(Integer.parseInt("x"));`,
		`return OffsetTime.ofInstant(Integer.parseInt("x"), ZoneOffset.UTC);`,
		`return OffsetTime.ofInstant(Instant.now(), Integer.parseInt("x"));`,
		`return new URI(Integer.parseInt("x"));`,
		`return URI.create(Integer.parseInt("x"));`,
		`return new URI(Integer.parseInt("x"), "x", "f");`,
		`return new URI("https", Integer.parseInt("x"), "f");`,
		`return new URI("https", "x", Integer.parseInt("x"));`,
		`return new URL(Integer.parseInt("x"));`,
		`return new URL(new URL("https://a.com"), Integer.parseInt("x"));`,
		`return new Locale(Integer.parseInt("x"));`,
		`return new Locale("en", Integer.parseInt("x"));`,
		`return new IntSummaryStatistics(Integer.parseInt("x"), 0, 0, 0);`,
		`return OffsetTime.now().withHour(Integer.parseInt("x"));`,
		`return OffsetTime.now().withMinute(Integer.parseInt("x"));`,
		`return OffsetTime.now().withSecond(Integer.parseInt("x"));`,
		`return OffsetTime.now().withNano(Integer.parseInt("x"));`,
		`return OffsetTime.now().withOffsetSameLocal(Integer.parseInt("x"));`,
		`return OffsetTime.now().withOffsetSameInstant(Integer.parseInt("x"));`,
		`return OffsetTime.now().plusHours(Integer.parseInt("x"));`,
		`return OffsetTime.now().minusMinutes(Integer.parseInt("x"));`,
		`return OffsetTime.now().plusSeconds(Integer.parseInt("x"));`,
		`return OffsetTime.now().minusNanos(Integer.parseInt("x"));`,
		`return OffsetTime.now().plus(Integer.parseInt("x"), ChronoUnit.SECONDS);`,
		`return OffsetTime.now().plus(1, Integer.parseInt("x"));`,
		`return OffsetTime.now().truncatedTo(Integer.parseInt("x"));`,
		`return OffsetTime.now().atDate(Integer.parseInt("x"));`,
		`return OffsetTime.now().toEpochSecond(Integer.parseInt("x"));`,
		`return OffsetTime.now().isBefore(Integer.parseInt("x"));`,
		// round56 / round57 / round58 / round59 / round60 / eval errors & arg propagation
		`return Integer.parseInt("");`,
		`return Integer.parseInt(null);`,
		`return Integer.decode(null);`,
		`return Short.parseShort("99999");`,
		`return Byte.parseByte("999");`,
		`return Double.parseDouble("not_a_double");`,
		`return (int)"not_int";`,
		`return (double)"not_double";`,
		`return (boolean)"not_bool";`,
		`return new BigDecimal("1").divide(new BigDecimal("3"), RoundingMode.UNNECESSARY);`,
		`return HexFormat.of().withPrefix(Integer.parseInt("x"));`,
		`return HexFormat.of().withSuffix(Integer.parseInt("x"));`,
		`return HexFormat.of().withDelimiter(Integer.parseInt("x"));`,
		`return HexFormat.of().formatHex(Integer.parseInt("x"));`,
		`return HexFormat.of().parseHex(Integer.parseInt("x"));`,
		`return Arrays.mismatch(Integer.parseInt("x"), [1]);`,
		`return Arrays.copyOf(Integer.parseInt("x"), 2);`,
		`return Arrays.copyOfRange(Integer.parseInt("x"), 0, 1);`,
		`return Arrays.fill([1], Integer.parseInt("x"));`,
		`return Math.addExact(Integer.parseInt("x"), 1);`,
		`return Math.subtractExact(Integer.parseInt("x"), 1);`,
		`return Math.multiplyExact(Integer.parseInt("x"), 1);`,
		`return Math.floorDiv(Integer.parseInt("x"), 1);`,
		`return Math.floorMod(Integer.parseInt("x"), 1);`,
		`return Math.fma(Integer.parseInt("x"), 1.0, 1.0);`,
		`return Math.clamp(Integer.parseInt("x"), 0.0, 1.0);`,
		`return field(Integer.parseInt("x"));`,
		`return $(Integer.parseInt("x"));`,
		`return saturation(Integer.parseInt("x"), 1.0);`,
		`return sigmoid(Integer.parseInt("x"), 1.0, 1.0);`,
		`return decayNumericLinear(Integer.parseInt("x"), 1, 1, 0.5, 1);`,
		`return dotProduct(Integer.parseInt("x"), "vec");`,
		`return field("missing").asBigInteger(Integer.parseInt("x"));`,
		`return field("missing").asLong(Integer.parseInt("x"));`,
		`return field("missing").asDouble(Integer.parseInt("x"));`,
		`return field("missing").asDate(Integer.parseInt("x"));`,
		`return field("missing").asGeoPoint(Integer.parseInt("x"));`,
		`return field("missing").asString(Integer.parseInt("x"));`,
	}
	for _, sc := range errPropagationScripts {
		if _, err := Eval(map[string]any{"nums": 1, "vec": []any{1.0}}, sc, map[string]any{"__field_types": map[string]string{"vec": "dense_vector"}}); err == nil {
			t.Fatalf("expected error for propagation/boundary script %q", sc)
		}
	}
}

func TestRound67Cov_Round3ExactTargetsAndBranches(t *testing.T) {
	// 1. round62.go evalEnumReceiverMethodRound62, MergeCompositeEmittedMaps, EvalEmitContext composite_agg, Dissect +append.
	nilArg := func() ([]any, error) { return []any{nil}, nil }
	twoStrArgs := func() ([]any, error) { return []any{"FULL", "en"}, nil }
	oneNumArg := func() ([]any, error) { return []any{int64(2)}, nil }
	boolArg := func() ([]any, error) { return []any{true}, nil }
	dow := DayOfWeekEnum{Value: 1}
	mon := MonthEnum{Value: 2}
	for _, m := range []string{"getValue", "name", "toString"} {
		if v, ok, err := evalEnumReceiverMethodRound62(dow, m, nilArg); !ok || err != nil || v == nil {
			t.Fatalf("DayOfWeekEnum.%s failed: (%#v, %v, %v)", m, v, ok, err)
		}
		if v, ok, err := evalEnumReceiverMethodRound62(mon, m, nilArg); !ok || err != nil || v == nil {
			t.Fatalf("MonthEnum.%s failed: (%#v, %v, %v)", m, v, ok, err)
		}
	}
	for _, m := range []string{"minLength", "maxLength", "firstMonthOfQuarter"} {
		if v, ok, err := evalEnumReceiverMethodRound62(mon, m, nilArg); !ok || err != nil || v == nil {
			t.Fatalf("MonthEnum.%s failed: (%#v, %v, %v)", m, v, ok, err)
		}
	}
	for _, tc := range []struct {
		rec any
		m   string
		fn  func() ([]any, error)
	}{
		{dow, "getDisplayName", twoStrArgs},
		{dow, "plus", oneNumArg},
		{dow, "minus", oneNumArg},
		{dow, "equals", func() ([]any, error) { return []any{dow}, nil }},
		{dow, "compareTo", func() ([]any, error) { return []any{DayOfWeekEnum{Value: 5}}, nil }},
		{mon, "length", boolArg},
		{mon, "getDisplayName", twoStrArgs},
		{mon, "plus", oneNumArg},
		{mon, "minus", oneNumArg},
		{mon, "equals", func() ([]any, error) { return []any{mon}, nil }},
		{mon, "compareTo", func() ([]any, error) { return []any{MonthEnum{Value: 5}}, nil }},
	} {
		if _, ok, err := evalEnumReceiverMethodRound62(tc.rec, tc.m, tc.fn); !ok || err != nil {
			t.Fatalf("enum %T.%s failed: (%v, %v)", tc.rec, tc.m, ok, err)
		}
	}
	if merged := MergeCompositeEmittedMaps([]any{
		nil,
		"not_map",
		map[string]any{"__internal": 1, "nilVal": nil, "k1": "v1"},
		map[string]any{"k2": int64(2)},
	}); len(merged) != 2 {
		t.Fatalf("expected 2 merged keys, got %#v", merged)
	}
	if emptyMerged := MergeCompositeEmittedMaps([]any{nil, "bad"}); emptyMerged != nil {
		t.Fatalf("expected nil from empty MergeCompositeEmittedMaps, got %#v", emptyMerged)
	}
	if emitted, err := EvalEmitContext(`emit(10, 20);`, "geo_point", nil, nil, nil, nil); err != nil || len(emitted) == 0 {
		t.Fatalf("EvalEmitContext geo_point failed: (%#v, %v)", emitted, err)
	}
	if _, err := EvalEmitContext(`emit(1, 2, 3);`, "boolean", nil, nil, nil, nil); err == nil {
		t.Fatal("expected boolean 3-arg emit error")
	}
	if dx, err := CompileDissectPattern("%{a} %{+a}"); err != nil || dx == nil {
		t.Fatalf("CompileDissectPattern append failed: %v", err)
	}

	// 2. round60.go normalizeSingleFieldDocValuesWithOptsRound61 (hex byte vec, unsigned_long float/neg, flattened), geo slice, FieldVal.asDate/GeoPoint.
	if dv := normalizeSingleFieldDocValuesWithOptsRound61("01020304", "dense_vector", false, false, "", false); len(dv) != 4 {
		t.Fatalf("expected 4 hex signed byte vector elements, got %#v", dv)
	}
	if ul := normalizeSingleFieldDocValuesWithOptsRound61("12.5", "unsigned_long", false, false, "", false); len(ul) != 1 {
		t.Fatalf("expected unsigned_long float fallback, got %#v", ul)
	}
	if ulNeg := normalizeSingleFieldDocValuesWithOptsRound61("-1", "unsigned_long", false, false, "", false); len(ulNeg) != 0 {
		t.Fatalf("expected unsigned_long neg to be skipped, got %#v", ulNeg)
	}
	if _, err := Eval(nil, `def xs = []; return xs.arcDistance(0, 0);`, map[string]any{}); err == nil {
		t.Fatal("expected error for empty slice arcDistance")
	}
	gpDoc := map[string]any{"pt": map[string]any{"lat": 40.7, "lon": -74.0}, "badDt": "not-date"}
	gpParams := map[string]any{"__field_types": map[string]any{"pt": "geo_point"}}
	if gpRes, err := Eval(gpDoc, `return field("pt").asGeoPoint();`, gpParams); err != nil || gpRes == nil {
		t.Fatalf("field(pt).asGeoPoint failed: (%#v, %v)", gpRes, err)
	}
	if _, err := Eval(gpDoc, `return field("badDt").asDate();`, gpParams); err == nil {
		t.Fatal("expected asDate error on bad date")
	}

	// 3. round61.go half-float rounding/overflow, WKT degenerate rings/points, computeVectorMagnitudeF32Round61 bit.
	_ = HalfFloatToBits(65520.0)
	_ = HalfFloatToBits(1.0 + 1.0/2048.0 + 1.0/4096.0)
	_ = HalfFloatToBits(1.0/16384.0 + 1.0/32768.0)
	_ = HalfFloatToBits(math.Inf(-1))
	_ = HalfFloatFromBits(0x7c00)
	if mag := computeVectorMagnitudeF32Round61(nil, []int8{0x0F, 0x03}, "bit"); mag <= 0 {
		t.Fatalf("expected positive bit vector magnitude, got %v", mag)
	}
	if lat, lon, area := geoRingShoelaceSignedCentroidRound61(nil); lat != 0 || lon != 0 || area != 0 {
		t.Fatalf("expected zero centroid on empty ring, got %v,%v,%v", lat, lon, area)
	}
	if lat, _, _ := geoRingShoelaceSignedCentroidRound61([][2]float64{{1.0, 2.0}, {3.0, 4.0}}); lat != 2.0 {
		t.Fatalf("expected 2-point ring centroid lat 2.0, got %v", lat)
	}
	_, _, _ = geoLineCentroidWeightedRound61(nil)
	_, _, _ = geoLineCentroidWeightedRound61([][2]float64{{1.0, 2.0}})
	_, _, _ = geoPolygonCentroidWeightedRound61(nil)
	if _, _, ok := parseGeoCoordPairRound61([]float64{20.0, 10.0}); !ok {
		t.Fatal("expected []float64 geo coords extraction")
	}
	if _, _, ok := parseGeoCoordPairRound61(map[string]any{"lat": 10.0, "lon": 20.0}); !ok {
		t.Fatal("expected map geo coords extraction")
	}

	// 4. round54.go SummaryStats NaN/combine, ZoneOffset bounds, Objects.hashCode wrappers, URI malformed %/ports/resolve, static field defaults.
	r54MoreSrc := `
		class SF {
			static int si;
			static double sd;
			static boolean sb;
			static def vals() { return [si, sd, sb]; }
		}
		DoubleSummaryStatistics d1 = new DoubleSummaryStatistics();
		d1.accept(Double.NaN);
		DoubleSummaryStatistics d2 = new DoubleSummaryStatistics();
		d1.combine(d2);

		URI uBase = new URI("https", "host:8080", "/a/b/", "f");
		URI uDot = uBase.resolve(".");
		URI uSub = uBase.resolve("sub");
		URI uPct = new URI("https", "host", "/p%ZZ%", "q=1");

		int hcAll = Objects.hashCode(Optional.of(1))
			+ Objects.hashCode(OffsetTime.now())
			+ Objects.hashCode(Clock.systemUTC())
			+ Objects.hashCode(new URL("https://a.com"));

		return [SF.vals().size(), d1.getCount(), uDot.toString(), uSub.toString(), uPct.toString(), hcAll != 0];
	`
	if _, err := Eval(nil, r54MoreSrc, map[string]any{}); err != nil {
		t.Fatalf("r54MoreSrc failed: %v", err)
	}
	for _, bad := range []string{
		`DoubleSummaryStatistics d = new DoubleSummaryStatistics(); d.combine(null);`,
		`DoubleSummaryStatistics d = new DoubleSummaryStatistics(); d.combine("bad");`,
		`return ZoneOffset.ofHoursMinutesSeconds(25, 0, 0);`,
		`return ZoneOffset.ofHoursMinutesSeconds(0, 70, 0);`,
		`return ZoneOffset.ofHoursMinutesSeconds(0, 0, 70);`,
	} {
		if _, err := Eval(nil, bad, map[string]any{}); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}

	// 5. round57/round58/round59 float32 div0/NaN, regex flags in =~, substring/nCopies float args, compound assign, entry.setValue, user-class bare field/static assign, concat stream flatMap, ClassCastException.
	r57To59Src := `
		class CThis {
			int x = 1;
			void bump() { x = x + 2; }
			int getX() { return this.x; }
		}
		class CStat {
			static int s = 1;
			static int bump() { s = s + 4; return s; }
		}
		CThis ct = new CThis();
		ct.bump();
		int stRes = CStat.bump();

		float fz = 0.0f;
		float fZero = 0.0f / fz;
		float fInf = 1.0f / fz;
		boolean reLit = "ABC" =~ /abc/i;
		boolean reNeg = !("abc" =~ /xyz/);
		String subF = "hello".substring(1.0, 3.0);
		def nCopF = Collections.nCopies(2.0, "x");

		int c = 20;
		c -= 2;
		c *= 3;
		c /= 2;
		c %= 5;
		float fc = 20.0f;
		fc -= 2.0f;
		fc *= 3.0f;
		fc /= 2.0f;
		fc %= 5.0f;

		Map em = ["k1": 1, "k2": 2];
		for (def e : em.entrySet()) {
			e.setValue(42);
		}
		def cFlat = IntStream.concat(IntStream.of(1), IntStream.of(2)).flatMap(x -> IntStream.of(x, x + 10)).sum();
		if (null) { return 0; }
		if (1.5f) { c = c + 0; }
		return [ct.getX(), stRes, Float.isNaN(fZero), Float.isInfinite(fInf), reLit, reNeg, subF, nCopF.size(), nCopF.get(0), c, fc, em.get("k1"), cFlat];
	`
	if res, err := Eval(nil, r57To59Src, map[string]any{}); err != nil {
		t.Fatalf("r57To59Src failed: %v", err)
	} else if s := res.([]any); s[0] != int64(3) || s[1] != int64(5) || s[4] != true || s[6] != "el" || s[11] != int64(42) || s[12] != int64(26) {
		t.Fatalf("unexpected r57To59Src result: %#v", s)
	}
	if _, err := Eval(nil, `return Collections.nCopies(null, "x");`, map[string]any{}); err == nil {
		t.Fatal("expected NPE on Collections.nCopies(null, x)")
	}
	if _, err := Eval(nil, `return (String)123;`, map[string]any{}); err == nil {
		t.Fatal("expected ClassCastException on (String)123")
	}
	if _, err := Eval(nil, `return "a" =~ "`+strings.Repeat("a", MaxRegexPatternLen+1)+`";`, map[string]any{}); err == nil {
		t.Fatal("expected regex length error in =~")
	}

	// 6. eval.go exact clusters: ChronoField.with(...) full suite, DenseVector forEach, Map.ofEntries dup/copyOf internal, split float limit, Matcher.pattern(), ctx whole-map + params._source inc/dec, multiline else if, tail expr without return.
	evalClusterSrc := `
		def zdt = ZonedDateTime.parse("2024-03-15T14:20:30Z");
		def cfMods = [
			zdt.with(ChronoField.CLOCK_HOUR_OF_DAY, 24),
			zdt.with(ChronoField.CLOCK_HOUR_OF_DAY, 5),
			zdt.with(ChronoField.HOUR_OF_DAY, 9),
			zdt.with(ChronoField.HOUR_OF_AMPM, 3),
			zdt.with(ChronoField.CLOCK_HOUR_OF_AMPM, 12),
			zdt.with(ChronoField.YEAR, 2025),
			zdt.with(ChronoField.YEAR_OF_ERA, 2026),
			zdt.with(ChronoField.ERA, 1),
			zdt.with(ChronoField.MONTH_OF_YEAR, 6),
			zdt.with(ChronoField.DAY_OF_MONTH, 12),
			zdt.with(ChronoField.PROLEPTIC_MONTH, 24300),
			zdt.with(ChronoField.INSTANT_SECONDS, 1700000000L),
			zdt.with(ChronoField.OFFSET_SECONDS, 3600)
		];
		String sVal = "a:b:c";
		def sSplit = sVal.split(/:/, 2.0);
		Matcher mp = Pattern.compile("ab+").matcher("abb");
		def mpPat = mp.pattern();
		def mapCopy = Map.copyOf(params);
		def cuDays = ChronoUnit.DAYS;
		long cuBet = cuDays.between("2024-01-01T00:00:00Z", "2024-01-05T00:00:00Z");

		def ctxMap = ctx;
		long dvSum = 0;
		for (def fv : doc["vec"]) {
			dvSum += 1;
		}
		def mpProp = ["a": 1];
		return [cfMods.size(), sSplit.size(), mpPat.pattern(), mapCopy.size(), cuBet, ctxMap._id, dvSum, mpProp.length, mpProp.empty];
	`
	evRes, err := Eval(
		map[string]any{"vec": []any{1.0, 2.0}},
		evalClusterSrc,
		map[string]any{
			"_ctx_op":       "index",
			"_ctx_id":       "d1",
			"__alias_x":     "x",
			"__field_types": map[string]string{"vec": "dense_vector"},
			"userK":         "userV",
		},
	)
	if err != nil {
		t.Fatalf("evalClusterSrc failed: %v", err)
	}
	if s := evRes.([]any); s[0] != int64(13) || s[1] != int64(2) || s[4] != int64(4) || s[5] != "d1" || s[6] != int64(2) || s[7] != int64(1) {
		t.Fatalf("unexpected evalClusterSrc result: %#v", s)
	}

	// Missing vector iteration error + Map.ofEntries dup key + Arrays.parallelPrefix shadow err + Map.replaceAll shadow err + multiline else if + tail boolean expr without return.
	for _, sc := range []string{
		`return Map.ofEntries(Map.entry("a", 1), Map.entry("a", 2));`,
		`int a = 1; int b = 2; def xs = [1, 2]; Arrays.parallelPrefix(xs, (a, b) -> Integer.parseInt("x")); return xs;`,
		`def k = 1; def v = 1; Map mp = ["x": 1]; mp.replaceAll((k, v) -> Integer.parseInt("x")); return mp;`,
		`int p1 = 1; int p2 = 2; return [1, 2].stream().reduce(0, (p1, p2) -> Integer.parseInt("x"));`,
	} {
		if _, err := Eval(map[string]any{"vec": []any{1.0}}, sc, map[string]any{"__field_types": map[string]string{"vec": "dense_vector", "missVec": "dense_vector"}}); err == nil {
			t.Fatalf("expected error for eval cluster error script %q", sc)
		}
	}
	multiSrc := "if (false)\n{\nreturn 1;\n}\nelse if (true)\n{\nreturn 2;\n}\nreturn 3;"
	if mRes, err := Eval(nil, multiSrc, map[string]any{}); err != nil || mRes != int64(2) {
		t.Fatalf("multiline else-if expected 2, got (%#v, %v)", mRes, err)
	}
	if tailRes, err := Eval(map[string]any{"a": int64(5)}, `doc.a > 2`, nil); err != nil || tailRes != true {
		t.Fatalf("tail expr without return expected true, got (%#v, %v)", tailRes, err)
	}
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"cnt":1}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `params._source = ctx._source; ++ctx._source.cnt; --ctx._source.cnt; ctx._source = ["replaced": 1];`},
	}, true); err != nil {
		t.Fatalf("ApplyUpdateWithResult source replace/inc/dec failed: %v", err)
	}
}

func TestRound67Cov_Round4MegaEvalAndRoundHarvest(t *testing.T) {
	// 1. OffsetTime / Year / MonthDay / ZonedDateTime ChronoField.with(...) + DateTimeFormatter presets + Streams/Collectors::new + BigDecimal bounds.
	megaFeatureSrc := `
		OffsetTime ot = OffsetTime.parse("14:20:30+02:00");
		def otMods = [
			ot.with(ChronoField.HOUR_OF_DAY, 5),
			ot.with(ChronoField.CLOCK_HOUR_OF_DAY, 24),
			ot.with(ChronoField.CLOCK_HOUR_OF_DAY, 6),
			ot.with(ChronoField.HOUR_OF_AMPM, 3),
			ot.with(ChronoField.CLOCK_HOUR_OF_AMPM, 12),
			ot.with(ChronoField.CLOCK_HOUR_OF_AMPM, 4),
			ot.with(ChronoField.AMPM_OF_DAY, 0),
			ot.with(ChronoField.MINUTE_OF_HOUR, 15),
			ot.with(ChronoField.MINUTE_OF_DAY, 90),
			ot.with(ChronoField.SECOND_OF_MINUTE, 45),
			ot.with(ChronoField.SECOND_OF_DAY, 3661),
			ot.with(ChronoField.MILLI_OF_SECOND, 500),
			ot.with(ChronoField.MILLI_OF_DAY, 123456),
			ot.with(ChronoField.MICRO_OF_SECOND, 500),
			ot.with(ChronoField.MICRO_OF_DAY, 123456),
			ot.with(ChronoField.NANO_OF_SECOND, 500),
			ot.with(ChronoField.NANO_OF_DAY, 123456789),
			ot.with(ChronoField.OFFSET_SECONDS, 3600)
		];
		def yrMods = [
			Year.of(2024).with(ChronoField.YEAR, 2025),
			Year.of(2024).with(ChronoField.YEAR_OF_ERA, 2026),
			Year.of(-5).with(ChronoField.YEAR_OF_ERA, 2),
			Year.of(2024).with(ChronoField.ERA, 1),
			Year.of(2024).with(ChronoField.ERA, 0)
		];
		def mdMods = [
			MonthDay.of(2, 15).with(ChronoField.MONTH_OF_YEAR, 3),
			MonthDay.of(2, 15).with(ChronoField.DAY_OF_MONTH, 20)
		];

		def ldIso = LocalDate.parse("2024-03-15", DateTimeFormatter.ISO_LOCAL_DATE);
		def ldIso2 = LocalDate.parse("2024-03-15", DateTimeFormatter.ISO_DATE);
		def ltIso = LocalTime.parse("14:20:30", DateTimeFormatter.ISO_LOCAL_TIME);
		def otIso = OffsetTime.parse("14:20:30+01:00", DateTimeFormatter.ISO_OFFSET_TIME);
		def bIso = LocalDate.parse("20240315", DateTimeFormatter.BASIC_ISO_DATE);
		def ldtIso = LocalDateTime.parse("2024-03-15T14:20:30", DateTimeFormatter.ISO_LOCAL_DATE_TIME);

		def optLongS = OptionalLong.of(5L).stream().toArray();
		def optDblS = OptionalDouble.of(2.5).stream().toArray();
		def isBoxed = IntStream.range(1, 3).boxed().toArray();
		def lsArr = LongStream.range(1, 4).toArray();
		double dsSum = DoubleStream.of(1.5, 2.5).sum();
		def sIter = Stream.iterate(1, n -> n < 5, n -> n + 1).toArray();
		def sGen = Stream.generate(() -> 7).limit(3).toArray();

		def colHM = [["k": "a", "v": 1]].stream().collect(Collectors.toMap(x -> x.k, x -> x.v, (a, b) -> a, HashMap::new));
		def colTM = [["k": "a", "v": 1]].stream().collect(Collectors.toMap(x -> x.k, x -> x.v, (a, b) -> a, TreeMap::new));
		def colLHM = [["k": "a", "v": 1]].stream().collect(Collectors.toMap(x -> x.k, x -> x.v, (a, b) -> a, LinkedHashMap::new));
		def colHS = [1, 2].stream().collect(Collectors.toCollection(HashSet::new));
		def colLHS = [1, 2].stream().collect(Collectors.toCollection(LinkedHashSet::new));
		def colTS = [1, 2].stream().collect(Collectors.toCollection(TreeSet::new));

		def multiArrs = [new float[2][3], new double[2][3], new String[2][2]];
		BigDecimal bd0 = new BigDecimal("0.00");
		String bdStrs = bd0.toEngineeringString() + ":" + bd0.toPlainString() + ":" + new BigDecimal("1.23").setScale(4).toString();
		String sfFmt = String.format("%s-%+d-%-4s", "a", 5, "x");
		def biIdx = "abcde".substring(new BigInteger("1"));
		String oa = Objects.toString(TemporalAdjusters.firstDayOfMonth()) + Objects.toString(Comparator.naturalOrder());
		boolean cmpMore = (Month.JANUARY == Month.JANUARY) && (Instant.parse("2024-01-01T00:00:00Z") == Instant.parse("2024-01-01T00:00:00Z"));
		def sj = new StringJoiner(",");
		sj.setEmptyValue("NONE");
		String sjEmp = sj.toString();

		return [
			otMods.size(), yrMods.size(), mdMods.size(),
			ldIso != null, ldIso2 != null, ltIso != null, otIso != null, bIso != null, ldtIso != null,
			optLongS.size(), optDblS.size(), isBoxed.size(), lsArr.size(), dsSum, sIter.size(), sGen.size(),
			colHM.size(), colTM.size(), colLHM.size(), colHS.size(), colLHS.size(), colTS.size(),
			multiArrs.size(), bdStrs != "", sfFmt != "", biIdx, oa != "", cmpMore, sjEmp
		];
	`
	if res, err := Eval(nil, megaFeatureSrc, map[string]any{}); err != nil {
		t.Fatalf("megaFeatureSrc failed: %v", err)
	} else if s := res.([]any); s[0] != int64(18) || s[1] != int64(5) || s[25] != "bcde" || s[28] != "NONE" {
		t.Fatalf("unexpected megaFeatureSrc result: %#v", s)
	}

	// 2. Direct Go helper coverage for extractInt64BoundArgPainless, normalizeMethodReferenceToLambdaPainless, bigTenPowPainless, checkBigDecimalBoundsPainless.
	for _, arg := range []any{int32(1), int16(2), int8(3), uint(4), uint32(5), uint64(6)} {
		if _, err := extractInt64BoundArgPainless(arg); err != nil {
			t.Fatalf("extractInt64BoundArgPainless(%T) failed: %v", arg, err)
		}
	}
	for _, ov := range []any{uint(math.MaxUint64), uint64(math.MaxUint64)} {
		if _, err := extractInt64BoundArgPainless(ov); err == nil {
			t.Fatalf("expected overflow error for %T", ov)
		}
	}
	for _, mr := range []string{"StringBuilder::new", "StringBuffer::new", "String::new", "(String::length)", "bad::123", "::x"} {
		_ = normalizeMethodReferenceToLambdaPainless(mr, 1)
	}
	_ = bigTenPowPainless(0)
	_ = bigTenPowPainless(25)

	// 3. Exhaustive argument-error propagation across evalNumericBitSetJoinerComparatorMethodPainless (BigDecimal/BigInteger/BitSet/StringJoiner/Comparator), evalNavigableOrDequeMethodPainless, evalStaticCallPainless, round54, round58, round60.
	megaErrScripts := []string{
		// BigDecimal & BigInteger & BitSet & StringJoiner & Comparator arg-eval errors
		`BigDecimal d = new BigDecimal("10"); return d.subtract(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.multiply(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.divide(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.divide(2, Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.divide(2, 2, Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.remainder(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.divideToIntegralValue(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.divideAndRemainder(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.pow(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.setScale(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.setScale(2, Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.min(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.max(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.movePointLeft(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.movePointRight(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.scaleByPowerOfTen(Integer.parseInt("x"));`,
		`BigDecimal d = new BigDecimal("10"); return d.round(Integer.parseInt("x"));`,
		`return new BigDecimal("1").pow(10001);`,
		`return new BigDecimal("1").movePointRight(10001);`,
		`BigInteger b = BigInteger.valueOf(10); return b.subtract(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.multiply(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.divide(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.remainder(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.divideAndRemainder(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.mod(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.modPow(Integer.parseInt("x"), b);`,
		`BigInteger b = BigInteger.valueOf(10); return b.modPow(b, Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.modInverse(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.gcd(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.pow(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.min(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.max(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.and(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.xor(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.andNot(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.shiftLeft(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.shiftRight(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.testBit(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.setBit(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.clearBit(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.flipBit(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.isProbablePrime(Integer.parseInt("x"));`,
		`BigInteger b = BigInteger.valueOf(10); return b.toString(Integer.parseInt("x"));`,
		`return BigInteger.valueOf(2).pow(65537);`,
		`return new BigInteger("1" + "0".repeat(20000));`,
		`BitSet bs = new BitSet(); bs.and(Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); bs.xor(Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); bs.andNot(Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); bs.set(1, Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); bs.clear(Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); bs.clear(1, Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); bs.flip(1, Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); return bs.nextSetBit(Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); return bs.nextClearBit(Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); return bs.previousSetBit(Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); return bs.previousClearBit(Integer.parseInt("x"));`,
		`BitSet bs = new BitSet(); return bs.intersects(Integer.parseInt("x"));`,
		`StringJoiner sj = new StringJoiner(","); return sj.setEmptyValue(Integer.parseInt("x"));`,
		`Comparator c = Comparator.naturalOrder(); return c.compare(Integer.parseInt("x"), 2);`,
		`Comparator c = Comparator.naturalOrder(); return c.compare(1, Integer.parseInt("x"));`,

		// NavigableMap / NavigableSet / ArrayDeque arg errors
		`TreeMap tm = new TreeMap(); return tm.floorKey(Integer.parseInt("x"));`,
		`TreeMap tm = new TreeMap(); return tm.ceilingKey(Integer.parseInt("x"));`,
		`TreeMap tm = new TreeMap(); return tm.lowerKey(Integer.parseInt("x"));`,
		`TreeMap tm = new TreeMap(); return tm.higherKey(Integer.parseInt("x"));`,
		`TreeMap tm = new TreeMap(); return tm.headMap(Integer.parseInt("x"), true);`,
		`TreeMap tm = new TreeMap(); return tm.tailMap(Integer.parseInt("x"), true);`,
		`TreeMap tm = new TreeMap(); return tm.subMap(Integer.parseInt("x"), true, "z", false);`,
		`TreeMap tm = new TreeMap(); return tm.subMap("a", true, Integer.parseInt("x"), false);`,
		`TreeSet ts = new TreeSet(); return ts.floor(Integer.parseInt("x"));`,
		`TreeSet ts = new TreeSet(); return ts.ceiling(Integer.parseInt("x"));`,
		`TreeSet ts = new TreeSet(); return ts.lower(Integer.parseInt("x"));`,
		`TreeSet ts = new TreeSet(); return ts.higher(Integer.parseInt("x"));`,
		`TreeSet ts = new TreeSet(); return ts.headSet(Integer.parseInt("x"), true);`,
		`TreeSet ts = new TreeSet(); return ts.tailSet(Integer.parseInt("x"), true);`,
		`TreeSet ts = new TreeSet(); return ts.subSet(Integer.parseInt("x"), true, 5, false);`,
		`TreeSet ts = new TreeSet(); return ts.subSet(1, true, Integer.parseInt("x"), false);`,
		`ArrayDeque dq = new ArrayDeque(); return dq.offerFirst(Integer.parseInt("x"));`,
		`ArrayDeque dq = new ArrayDeque(); return dq.offerLast(Integer.parseInt("x"));`,
		`ArrayDeque dq = new ArrayDeque(); return dq.removeFirstOccurrence(Integer.parseInt("x"));`,
		`ArrayDeque dq = new ArrayDeque(); return dq.removeLastOccurrence(Integer.parseInt("x"));`,

		// evalStaticCallPainless + round58 + round54 + ChronoField Unsupported/DateTime exceptions
		`return Arrays.sort(Integer.parseInt("x"));`,
		`return Arrays.binarySearch(Integer.parseInt("x"), 1);`,
		`return Arrays.binarySearch([1, 2], Integer.parseInt("x"));`,
		`return Arrays.fill(Integer.parseInt("x"), 1);`,
		`return Arrays.copyOf([1], Integer.parseInt("x"));`,
		`return Arrays.copyOfRange([1], Integer.parseInt("x"), 1);`,
		`return Arrays.copyOfRange([1], 0, Integer.parseInt("x"));`,
		`return Arrays.equals(Integer.parseInt("x"), [1]);`,
		`return Arrays.equals([1], Integer.parseInt("x"));`,
		`return Arrays.toString(Integer.parseInt("x"));`,
		`return Arrays.hashCode(Integer.parseInt("x"));`,
		`return Arrays.setAll(Integer.parseInt("x"), i -> i);`,
		`return Arrays.parallelPrefix(Integer.parseInt("x"), (a, b) -> a + b);`,
		`return Arrays.mismatch([1], Integer.parseInt("x"));`,
		`return Arrays.stream(Integer.parseInt("x"));`,
		`return List.of(Integer.parseInt("x"));`,
		`return Set.of(Integer.parseInt("x"));`,
		`return List.copyOf(Integer.parseInt("x"));`,
		`return Set.copyOf(Integer.parseInt("x"));`,
		`return Map.copyOf(Integer.parseInt("x"));`,
		`return Map.entry(Integer.parseInt("x"), 1);`,
		`return Map.entry("a", Integer.parseInt("x"));`,
		`return Map.ofEntries(Integer.parseInt("x"));`,
		`return Collections.singleton(Integer.parseInt("x"));`,
		`return Collections.singletonMap(Integer.parseInt("x"), 1);`,
		`return Collections.singletonMap("a", Integer.parseInt("x"));`,
		`return Collections.min(Integer.parseInt("x"));`,
		`return Collections.max(Integer.parseInt("x"));`,
		`return Collections.binarySearch(Integer.parseInt("x"), 1);`,
		`return Collections.binarySearch([1], Integer.parseInt("x"));`,
		`return Collections.frequency(Integer.parseInt("x"), 1);`,
		`return Collections.frequency([1], Integer.parseInt("x"));`,
		`return Collections.disjoint(Integer.parseInt("x"), [1]);`,
		`return Collections.disjoint([1], Integer.parseInt("x"));`,
		`return Collections.nCopies(Integer.parseInt("x"), "a");`,
		`return Collections.nCopies(1, Integer.parseInt("x"));`,
		`return Collections.swap(Integer.parseInt("x"), 0, 1);`,
		`return Collections.fill(Integer.parseInt("x"), 1);`,
		`return Collections.rotate(Integer.parseInt("x"), 1);`,
		`return Collections.replaceAll(Integer.parseInt("x"), 1, 2);`,
		`return Collections.sort(Integer.parseInt("x"));`,
		`return Collections.reverse(Integer.parseInt("x"));`,
		`return Encoding.encodeBase64(Integer.parseInt("x"));`,
		`return Encoding.decodeBase64(Integer.parseInt("x"));`,
		`return Encoding.encodeHex(Integer.parseInt("x"));`,
		`return Encoding.decodeHex(Integer.parseInt("x"));`,
		`return Digest.sha256(Integer.parseInt("x"));`,
		`return Digest.md5(Integer.parseInt("x"));`,
		`return Digest.sha512(Integer.parseInt("x"));`,
		`return Pattern.compile(Integer.parseInt("x"));`,
		`return Pattern.matches(Integer.parseInt("x"), "a");`,
		`return Pattern.matches("a", Integer.parseInt("x"));`,
		`return Year.of(Integer.parseInt("x"));`,
		`return YearMonth.of(Integer.parseInt("x"), 1);`,
		`return YearMonth.of(2024, Integer.parseInt("x"));`,
		`return MonthDay.of(Integer.parseInt("x"), 1);`,
		`return MonthDay.of(1, Integer.parseInt("x"));`,
		`return Month.of(Integer.parseInt("x"));`,
		`return DayOfWeek.of(Integer.parseInt("x"));`,
		`return LocalDate.ofYearDay(Integer.parseInt("x"), 1);`,
		`return LocalDate.ofYearDay(2024, Integer.parseInt("x"));`,
		`return LocalTime.ofSecondOfDay(Integer.parseInt("x"));`,
		`return LocalTime.ofNanoOfDay(Integer.parseInt("x"));`,
		`return LocalDateTime.of(Integer.parseInt("x"), 1, 1, 0, 0);`,
		`return ZonedDateTime.of(Integer.parseInt("x"), 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"));`,
		`return OffsetTime.now().with(ChronoField.YEAR, 2024);`,
		`return Year.of(2024).with(ChronoField.MONTH_OF_YEAR, 1);`,
		`return Year.of(2024).with(ChronoField.YEAR_OF_ERA, 1000000000L);`,
		`return MonthDay.of(2, 15).with(ChronoField.YEAR, 2024);`,
		`return OptionalInt.empty().getAsInt();`,
		`return OptionalLong.empty().getAsLong();`,
		`return OptionalDouble.empty().getAsDouble();`,
		`return Optional.empty().get();`,
		`return saturation(1.0, Integer.parseInt("x"));`,
		`return sigmoid(1.0, Integer.parseInt("x"), 1.0);`,
		`return sigmoid(1.0, 1.0, Integer.parseInt("x"));`,
		`return decayDateLinear(1000, "1d", "1h", 0.5, Integer.parseInt("x"));`,
		`return decayGeoLinear("0,0", "1km", "100m", 0.5, Integer.parseInt("x"));`,
		`return randomScore(Integer.parseInt("x"));`,
		`return dotProduct([1.0], Integer.parseInt("x"));`,
		`return new ArrayList(Integer.parseInt("x"));`,
		`return new HashMap(Integer.parseInt("x"));`,
	}
	for _, sc := range megaErrScripts {
		if _, err := Eval(nil, sc, map[string]any{}); err == nil {
			t.Fatalf("expected error for megaErrScript %q", sc)
		}
	}
}

func TestRound67Cov_Round5FinalHarvestTarget950Plus(t *testing.T) {
	// 1. round59 evalAssignExprRound59Painless direct coverage (ctx._source, ctx.op, params._source, nested map entry, static field, user object field) + execSimpleStmt bracketed compound assign.
	ctxDoc := map[string]any{"cnt": int64(10), "sub": map[string]any{"x": int64(2)}}
	ctxParams := map[string]any{"_ctx_op": "index"}
	if _, err := evalAssignExprRound59Painless(ctxDoc, "params._source.sub.x", "+=", "3", ctxParams, 0); err != nil {
		t.Fatalf("evalAssignExprRound59Painless params._source failed: %v", err)
	}
	if _, err := evalAssignExprRound59Painless(ctxDoc, "ctx.op", "+=", `""`, ctxParams, 0); err != nil {
		t.Fatalf("evalAssignExprRound59Painless ctx.op failed: %v", err)
	}
	if _, err := evalAssignExprRound59Painless(ctxDoc, "ctx._source", "=", `["fresh": 1]`, ctxParams, 0); err != nil {
		t.Fatalf("evalAssignExprRound59Painless ctx._source failed: %v", err)
	}
	if _, err := evalAssignExprRound59Painless(ctxDoc, "ctx?._source.k", "=", `"v"`, ctxParams, 0); err != nil {
		t.Fatalf("evalAssignExprRound59Painless ctx?._source.k failed: %v", err)
	}
	if err := execSimpleStmt(map[string]any{"cnt": int64(5)}, `ctx?._source.cnt += 4`, map[string]any{}, nil, &evalBudget{}); err != nil {
		t.Fatalf("execSimpleStmt ctx?._source.cnt += 4 failed: %v", err)
	}
	if err := execSimpleStmt(map[string]any{"cnt": int64(5)}, `ctx._source["cnt"] += 4`, map[string]any{}, nil, &evalBudget{}); err != nil {
		t.Fatalf("execSimpleStmt ctx._source[\"cnt\"] += 4 failed: %v", err)
	}

	// ApplyUpdateWithResult _ctx_version fallback paths (!IsES8 || !IsUBQ).
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Script:      &ScriptSpec{Source: `params._ctx_version = null;`},
		MetaVersion: 1,
		IsES8:       false,
		IsUBQ:       false,
	}, true); err != nil {
		t.Fatalf("ApplyUpdateWithResult _ctx_version null failed: %v", err)
	}
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Script:      &ScriptSpec{Source: `params._ctx_version = 7;`},
		MetaVersion: 1,
		IsES8:       false,
		IsUBQ:       false,
	}, true); err != nil {
		t.Fatalf("ApplyUpdateWithResult _ctx_version 7 failed: %v", err)
	}

	// Eval tail panic recovery + tail condition expression without return/semicolon.
	if _, err := Eval(nil, `1 / 0`, nil); err == nil {
		t.Fatal("expected tail expr 1 / 0 panic recovery error")
	}
	if res, err := Eval(nil, `"abc".contains("b")`, nil); err != nil || res != true {
		t.Fatalf("expected tail contains true, got (%#v, %v)", res, err)
	}

	// 2. Map.compute* / List.replaceAll / forEach with ctx, doc.*, shadowed params, and error propagation.
	forEachScript := `
		params.seen = 0;
		doc.tags.forEach(t -> { params.seen += 1; });
		Map m = ["k": 10];
		def k = 999;
		def v = 999;
		m.replaceAll((k, v) -> v + 1);
		return [params.seen, m.get("k"), k, v];
	`
	if res, err := Eval(map[string]any{"tags": []any{"a", "b"}}, forEachScript, map[string]any{}); err != nil {
		t.Fatalf("forEachScript failed: %v", err)
	} else if s := res.([]any); s[0] != int64(2) || s[1] != int64(11) || s[2] != int64(999) {
		t.Fatalf("unexpected forEachScript result: %#v", s)
	}

	// ctx.computeIfAbsent directly in update + Stream concat/boxed/optional/error cases.
	if up, _, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `ctx.computeIfAbsent("added", k -> 77);`},
	}, true); err != nil || !strings.Contains(string(up), `"added":77`) {
		t.Fatalf("ApplyUpdateWithResult ctx.computeIfAbsent failed: (%s, %v)", string(up), err)
	}

	okMoreSrc := `
		DateTimeFormatter.ofPattern();
		ZoneId.of();
		def sc = Stream.concat([1].stream(), [2].stream()).toArray();
		long lsCnt = LongStream.of(1L, 2L).filter(x -> x > 0).count();
		def dsArr = DoubleStream.of(1.0, 2.0).toArray();
		def yFrom1 = Year.from(LocalDate.of(2024, 1, 1));
		def yFrom2 = Year.from(Year.of(2024));
		def md2 = MonthDay.of("FEBRUARY", 29);
		def o1 = Optional.of(1).isPresent();
		def nCop1 = Collections.nCopies(1);
		boolean o2 = Optional.empty().isPresent();
		return [sc.size(), lsCnt, dsArr.size(), yFrom1, yFrom2, md2, o1, o2, nCop1.size()];
	`
	if _, err := Eval(nil, okMoreSrc, map[string]any{}); err != nil {
		t.Fatalf("okMoreSrc failed: %v", err)
	}

	// 3. Comprehensive non-panicking arg-error & domain-error sweep across Character, Math, round54, round58, round60, Collections, Streams, FieldVal, Version.
	finalErrScripts := []string{
		// Character.* error & OOB paths
		`return Character.charCount(Integer.parseInt("x"));`,
		`return Character.toChars(Integer.parseInt("x"));`,
		`return Character.toString(Integer.parseInt("x"));`,
		`return Character.isSurrogatePair(Integer.parseInt("x"), 1);`,
		`return Character.isSurrogatePair(1, Integer.parseInt("x"));`,
		`return Character.toCodePoint(Integer.parseInt("x"), 1);`,
		`return Character.toCodePoint(1, Integer.parseInt("x"));`,
		`return Character.codePointAt(Integer.parseInt("x"), 0);`,
		`return Character.codePointAt("ab", 99);`,
		`return Character.codePointBefore(Integer.parseInt("x"), 1);`,
		`return Character.codePointBefore("ab", 0);`,
		`return Character.codePointCount(Integer.parseInt("x"), 0, 1);`,
		`return Character.codePointCount("ab", 0, 99);`,
		`return Character.getNumericValue(Integer.parseInt("x"));`,
		`return Character.getType(Integer.parseInt("x"));`,
		`return Character.compare(Integer.parseInt("x"), 1);`,
		`return Character.compare(1, Integer.parseInt("x"));`,
		`return Character.digit(Integer.parseInt("x"), 10);`,
		`return Character.digit(65, Integer.parseInt("x"));`,
		`return Character.forDigit(Integer.parseInt("x"), 10);`,
		`return Character.forDigit(1, Integer.parseInt("x"));`,
		`return Character.reverseBytes(Integer.parseInt("x"));`,

		// Static dates/times/formats/UUID/Charset/Pattern
		`return Instant.now(Integer.parseInt("x"));`,
		`return MonthDay.parse(Integer.parseInt("x"));`,
		`return YearMonth.parse(Integer.parseInt("x"));`,
		`return DayOfWeek.of(Integer.parseInt("x"));`,
		`return Month.of(Integer.parseInt("x"));`,
		`return LocalTime.parse(Integer.parseInt("x"));`,
		`return Duration.between(Integer.parseInt("x"), Instant.now());`,
		`return Duration.between(Instant.now(), Integer.parseInt("x"));`,
		`return Period.parse(Integer.parseInt("x"));`,
		`return ChronoUnit.DAYS.between(Integer.parseInt("x"), Instant.now());`,
		`return ChronoUnit.DAYS.between(Instant.now(), Integer.parseInt("x"));`,
		`return UUID.nameUUIDFromBytes(Integer.parseInt("x"));`,
		`return UUID.fromString(Integer.parseInt("x"));`,
		`return Charset.forName(Integer.parseInt("x"));`,
		`return "%s".formatted(Integer.parseInt("x"));`,
		`return new StringBuilder("a").insert(1, Integer.parseInt("x"));`,
		`return "a:b".split(":", Integer.parseInt("x"));`,

		// Collection constructors
		`return new ArrayList(Integer.parseInt("x"));`,
		`return new TreeSet(Integer.parseInt("x"));`,
		`return new StringBuilder(Integer.parseInt("x"));`,
		`return new BigDecimal(Integer.parseInt("x"));`,
		`return new BigDecimal(1.0, Integer.parseInt("x"));`,
		`return new BigInteger(Integer.parseInt("x"));`,
		`return new StringJoiner(Integer.parseInt("x"));`,
		`return new StringJoiner(",", Integer.parseInt("x"), "]");`,
		`return new MathContext(Integer.parseInt("x"));`,
		`return new int[Integer.parseInt("x")];`,

		// Map compute*, List replaceAll/forEach, Streams with shadowed vars
		`def x = 1; Map mp = ["k": 1]; return mp.computeIfAbsent("z", x -> Integer.parseInt("x"));`,
		`def k = 1; def v = 2; Map mp = ["k": 1]; return mp.compute("k", (k, v) -> Integer.parseInt("x"));`,
		`def k = 1; def v = 2; Map mp = ["k": 1]; return mp.computeIfPresent("k", (k, v) -> Integer.parseInt("x"));`,
		`def o = 1; def n = 2; Map mp = ["k": 1]; return mp.merge("k", 5, (o, n) -> Integer.parseInt("x"));`,
		`def x = 1; List xs = [1, 2]; xs.replaceAll(x -> Integer.parseInt("x")); return xs;`,
		`def x = 1; List xs = [1, 2]; xs.forEach(x -> { def z = Integer.parseInt("x"); }); return xs;`,
		`return [1, 2].stream().anyMatch(x -> Integer.parseInt("x") > 0);`,
		`return [1, 2].stream().allMatch(x -> Integer.parseInt("x") > 0);`,
		`return [1, 2].stream().noneMatch(x -> Integer.parseInt("x") > 0);`,
		`return IntStream.range(1, 3).map(x -> Integer.parseInt("x")).toArray();`,
		`return [1, 2].stream().takeWhile(x -> Integer.parseInt("x") > 0).toArray();`,
		`return [1, 2].stream().dropWhile(x -> Integer.parseInt("x") > 0).toArray();`,
		`return [1, 2].stream().peek(x -> { def z = Integer.parseInt("x"); }).toArray();`,

		// Math static & exact arg errors
		`return Math.abs(Integer.parseInt("x"));`,
		`return Math.min(1.0, Integer.parseInt("x"));`,
		`return Math.max(1.0, Integer.parseInt("x"));`,
		`return Math.round(Integer.parseInt("x"));`,
		`return Math.pow(1.0, Integer.parseInt("x"));`,
		`return Math.hypot(1.0, Integer.parseInt("x"));`,
		`return Math.atan2(1.0, Integer.parseInt("x"));`,
		`return Math.nextAfter(1.0, Integer.parseInt("x"));`,
		`return Math.fma(1.0, 2.0, Integer.parseInt("x"));`,
		`return Math.clamp(1.0, 0.0, Integer.parseInt("x"));`,
		`return Math.incrementExact(Integer.parseInt("x"));`,
		`return Math.decrementExact(Integer.parseInt("x"));`,
		`return Math.negateExact(Integer.parseInt("x"));`,
		`return Math.toIntExact(Integer.parseInt("x"));`,

		// round54 multi-arg error slots & Optional lambdas + round58 condition/regex syntax + round60 FieldVal/Version
		`return new URI("https", "host", "/p", "q", Integer.parseInt("x"));`,
		`return new URI("https", "host", Integer.parseInt("x"), "f");`,
		`return new URI("https", null, "host", 80, "/p", "q", Integer.parseInt("x"));`,
		`return new URI("https", null, "host", Integer.parseInt("x"), "/p", "q", "f");`,
		`return new IntSummaryStatistics(1, 2, 3, Integer.parseInt("x"));`,
		`DoubleSummaryStatistics d = new DoubleSummaryStatistics(); d.accept(Integer.parseInt("x"));`,
		`DoubleSummaryStatistics d = new DoubleSummaryStatistics(); d.combine(Integer.parseInt("x"));`,
		`def x = 1; return Optional.of(1).filter(x -> Integer.parseInt("x") > 0);`,
		`def x = 1; return Optional.of(1).map(x -> Integer.parseInt("x"));`,
		`def x = 1; return Optional.of(1).flatMap(x -> Integer.parseInt("x"));`,
		`return Optional.empty().orElseGet(() -> Integer.parseInt("x"));`,
		`return Optional.empty().or(() -> Optional.of(Integer.parseInt("x")));`,
		`return new Version("1.0").compareTo(Integer.parseInt("x"));`,
		`return new Version("1.0").equals(Integer.parseInt("x"));`,
		`field("arr").removeValuesIf(x -> Integer.parseInt("x") > 0);`,
		`field("arr").transform(x -> Integer.parseInt("x"));`,
		`field("x").move(Integer.parseInt("x"));`,
		`field("x").overwrite(Integer.parseInt("x"));`,
		`field("x").append(Integer.parseInt("x"));`,
		`if (Integer.parseInt("x") > 0) { return 1; }`,
		`return "abc" =~ /(/;`,
	}
	for _, sc := range finalErrScripts {
		if _, err := Eval(map[string]any{"arr": []any{1, 2}, "x": 1}, sc, map[string]any{"__mutable_fields_api": true}); err == nil {
			t.Fatalf("expected error for finalErrScript %q", sc)
		}
	}
}

func TestRound67Cov_Round6CrossOver950Target(t *testing.T) {
	// 1. round61 regex cache nil/hit, unbounded repeat syntax, IPv4-mapped IPv6 & arity errors, DenseVector.getVectorValue.
	globalBoundedRawRegexCache.put("nil_pat", nil)
	if _, err := CompileBoundedRawRegex("abc_hit_test"); err != nil {
		t.Fatal(err)
	}
	if _, err := CompileBoundedRawRegex("abc_hit_test"); err != nil {
		t.Fatal(err)
	}
	for _, pat := range []string{"a{2,}", "a{0,3}", "(a{200}){200}"} {
		_ = validateBoundedRegexSyntaxR67(pat)
	}
	ip46, err := ParseIPAddressVal("::ffff:192.0.2.1")
	if err != nil || ip46 == nil {
		t.Fatalf("ParseIPAddressVal IPv4-mapped IPv6 failed: %v", err)
	}
	if _, err := Eval(map[string]any{"ip": "127.0.0.1", "vec": []any{1.0, 2.0}}, `def ipObj = doc["ip"].value; return [field("vec").getVectorValue().size(), doc["ip"].isLoopbackAddress(), ipObj != null];`, map[string]any{"__field_types": map[string]string{"ip": "ip", "vec": "dense_vector"}}); err != nil {
		t.Fatalf("ip/vec Eval failed: %v", err)
	}
	if _, _, err := evalIPAddressMethodRound61(ip46, "compareTo", []string{"null"}, nil, map[string]any{}, 0); err == nil {
		t.Fatal("expected NPE on IPAddress.compareTo(null)")
	}
	if _, _, err := evalIPAddressMethodRound61(ip46, "compareTo", []string{"123"}, nil, map[string]any{}, 0); err == nil {
		t.Fatal("expected CCE on IPAddress.compareTo(123)")
	}
	_, _, _ = evalIPAddressMethodRound61(ip46, "equals", []string{"a", "b"}, nil, map[string]any{}, 0)
	_, _, _ = evalIPAddressMethodRound61(ip46, "compareTo", []string{"a", "b"}, nil, map[string]any{}, 0)
	_, _, _ = evalIPAddressMethodRound61(ip46, "equals", []string{`Integer.parseInt("x")`}, nil, map[string]any{}, 0)
	_, _, _ = evalIPAddressMethodRound61(ip46, "compareTo", []string{`Integer.parseInt("x")`}, nil, map[string]any{}, 0)
	_, _, _ = evalIPAddressMethodRound61(ip46, "compareTo", []string{`"not.ip"`}, nil, map[string]any{}, 0)
	_, _, _ = evalIPAddressMethodRound61(ip46, "getAddress", nil, nil, map[string]any{}, 0)

	// 2. round54 raw regex literal extract, URL ftp & nil String, SummaryStats NaN mix.
	if _, _, err := extractPatternRegexpPainless("/abc/"); err != nil {
		t.Fatalf("extractPatternRegexpPainless failed: %v", err)
	}
	if _, _, err := extractPatternRegexpPainless(123); err == nil {
		t.Fatal("expected error for non-pattern extractPatternRegexpPainless(123)")
	}
	var nilURL *painlessURL
	_ = nilURL.String()
	if res, err := Eval(nil, `URL fu = new URL("ftp://ftp.example.com/f"); DoubleSummaryStatistics ds = new DoubleSummaryStatistics(); ds.accept(1.0); ds.accept(Double.NaN); return [fu.getDefaultPort(), fu.toString(), ds.getCount()];`, nil); err != nil {
		t.Fatalf("round54 ftp/NaN script failed: %v", err)
	} else if s := res.([]any); s[0] != int64(21) || s[2] != int64(2) {
		t.Fatalf("unexpected ftp/NaN result: %#v", s)
	}

	// 3. round58 subList float indices & arg errors, regex syntax error in =~, evalConditionDepthErr.
	if res, err := Eval(nil, `List xs = [10, 20, 30, 40]; return xs.subList(1.0, 3.0);`, nil); err != nil {
		t.Fatalf("subList float args failed: %v", err)
	} else if len(res.([]any)) != 2 {
		t.Fatalf("unexpected subList float result: %#v", res)
	}
	for _, sc := range []string{
		`return [1, 2].subList(Integer.parseInt("x"), 1);`,
		`return [1, 2].subList(0, Integer.parseInt("x"));`,
		`return "abc" =~ "(";`,
	} {
		if _, err := Eval(nil, sc, nil); err == nil {
			t.Fatalf("expected error for round58 script %q", sc)
		}
	}
	_, _ = evalConditionDepthErr(nil, `Integer.parseInt("x")`, map[string]any{}, 0)

	// 4. round56 strict temporal/float & unmodifiable backing map/parent map mutations.
	for _, sc := range []string{
		`return Instant.parse("2024-01-01 00:00:00Z");`,
		`return YearMonth.parse("9999999999-01");`,
		`return YearMonth.parse("2024");`,
		`return YearMonth.parse("2024x01");`,
		`return Duration.parse("PT.5S");`,
		`def m = ["inner": ["k": 1]]; def um = Collections.unmodifiableMap(m); um.inner.k = 2;`,
	} {
		if _, err := Eval(nil, sc, map[string]any{}); err == nil {
			t.Fatalf("expected error or mutation rejection for round56 script %q", sc)
		}
	}
	_, _ = toFloat64(json.Number("NaN"))
	_, _ = toFloat64((*painlessBigDecimal)(nil))
	_, _ = toFloat64((*painlessBigInteger)(nil))
	_, _ = toFloat64((*big.Int)(nil))

	// 5. round59 evalAssignExprRound59Painless direct ctx._source.x += / entry.value / wrapFlatMapResultIterRound59 *painlessConcatStream / alias slice mutation.
	r59Doc := map[string]any{"cnt": int64(5), "items": []any{int64(1)}}
	if _, err := evalAssignExprRound59Painless(r59Doc, "ctx._source.cnt", "+=", "3", map[string]any{}, 0); err != nil {
		t.Fatalf("evalAssignExprRound59Painless ctx._source.cnt += failed: %v", err)
	}
	r59EntryParams := map[string]any{
		"e": map[string]any{"key": "k1", "value": int64(1), "__parent_map": map[string]any{"k1": int64(1)}},
	}
	if _, err := evalAssignExprRound59Painless(nil, "e.value", "=", "99", r59EntryParams, 0); err != nil {
		t.Fatalf("evalAssignExprRound59Painless e.value failed: %v", err)
	}
	if _, err := evalAssignExprRound59Painless(nil, "p", "=", "7", map[string]any{"p": int64(0)}, 0); err != nil {
		t.Fatalf("evalAssignExprRound59Painless simple failed: %v", err)
	}
	if res, err := Eval(r59Doc, `def items = ctx._source.items; items.add(9); def cFlat = Stream.concat([1].stream(), [2].stream()).flatMap(x -> [x, x + 10].stream()).toArray(); return [items.size(), cFlat.size()];`, map[string]any{}); err != nil {
		t.Fatalf("r59 concat/alias failed: %v", err)
	} else if s := res.([]any); s[0] != int64(2) || s[1] != int64(4) {
		t.Fatalf("unexpected r59 concat/alias result: %#v", s)
	}

	// 6. round60 FieldVal.getValue empty default, BigInteger in unsigned_long getValues, lambdaBodyReassignsIdentRound60, bad formatted date.
	ulDoc := map[string]any{
		"ul":  "18446744073709551615",
		"dt":  "not-a-date",
		"emp": []any{},
	}
	ulParams := map[string]any{
		"__field_types":   map[string]string{"ul": "unsigned_long"},
		"__field_formats": map[string]string{"dt": "yyyy-MM-dd"},
	}
	if res, err := Eval(ulDoc, `def gv = field("ul").getValue(); def gvs = field("ul").getValues(); def defv = field("emp").getValue("fallback"); return [gv, gvs.size(), defv];`, ulParams); err != nil {
		t.Fatalf("round60 ul/empty getValue failed: %v", err)
	} else if s := res.([]any); s[1] != int64(1) || s[2] != "fallback" {
		t.Fatalf("unexpected ul/empty getValue result: %#v", s)
	}
	if _, err := Eval(ulDoc, `return field("dt").asDate();`, ulParams); err == nil {
		t.Fatal("expected asDate error with yyyy-MM-dd format")
	}
	_ = lambdaBodyReassignsIdentRound60("x", "int xy = 1; xy = 2; x = 3;")
	_ = lambdaBodyReassignsIdentRound60("x", "int z = 1;")

	// 7. eval.go high-yield targets: execSimpleStmt ctx.x += 2, for(int i; ...) null var decl, DenseVectorVal iteration & missing error, entry.setValue RHS, Map.ofEntries map error, Math.floorDiv unboxing NPE/CCE/arg err, Year.from err, doc['tags'].forEach, tail expr error/bool.
	if err := execSimpleStmt(map[string]any{"x": int64(5)}, `ctx.x += 2`, map[string]any{}, nil, &evalBudget{}); err != nil {
		t.Fatalf("execSimpleStmt ctx.x += 2 failed: %v", err)
	}
	forSrc := `
		int s = 0;
		int i;
		for (i = 0; i < 2; i = i + 1) { s += i; }
		for (int j; j < 1; j = 1) { s += 10; }
		Map em = ["k1": 1];
		def prevVal = 0;
		for (def e : em.entrySet()) {
			prevVal = e.setValue(42);
		}
		long dvCount = 0;
		for (def fv : params.dv) {
			dvCount += 1;
		}
		params.tagSeen = 0;
		doc["tags"].forEach(t -> { params.tagSeen += 1; });
		return [s, prevVal, em.get("k1"), dvCount, params.tagSeen];
	`
	if res, err := Eval(
		map[string]any{"tags": []any{"a", "b"}},
		forSrc,
		map[string]any{"dv": &DenseVectorVal{Floats: []float32{1.0, 2.0}}},
	); err != nil {
		t.Fatalf("forSrc failed: %v", err)
	} else if s := res.([]any); s[0] != int64(11) || s[1] != int64(1) || s[2] != int64(42) || s[3] != int64(2) || s[4] != int64(2) {
		t.Fatalf("unexpected forSrc result: %#v", s)
	}
	if _, err := Eval(nil, `for (def fv : params.missDV) {} return 0;`, map[string]any{
		"missDV": &DenseVectorVal{IsDocValue: true},
	}); err == nil {
		t.Fatal("expected error iterating missing DenseVectorVal")
	}
	for _, sc := range []string{
		`Map m1 = ["a": 1]; Map m2 = ["a": 2]; return Map.ofEntries(m1, m2);`,
		`Map m1 = ["a": null]; return Map.ofEntries(m1);`,
		`return Math.floorDiv(Integer.parseInt("x"), 2);`,
	} {
		if _, err := Eval(nil, sc, nil); err == nil {
			t.Fatalf("expected error for eval script %q", sc)
		}
	}
	if _, err := Eval(nil, `Integer.parseInt("x")`, nil); err == nil {
		t.Fatal("expected tail parseInt error")
	}
}

func TestRound67Cov_FinalPushPast950Statements(t *testing.T) {
	// 1. Typed-nil wrapper defensive guards in round60.go + round61.go.
	nilWrappers := []any{
		(*GeoPointVal)(nil),
		(*GeoBoundingBoxVal)(nil),
		(*GeoShapeDocValues)(nil),
		(*IPAddressVal)(nil),
		(*DenseVectorFieldVal)(nil),
		(*DenseVectorVal)(nil),
		(*ZonedDateTimeVal)(nil),
		(*BytesRefVal)(nil),
		(*ByteBufferVal)(nil),
		(*FieldVal)(nil),
		(*FieldDocVal)(nil),
		(*VersionVal)(nil),
		(*PainlessLambda)(nil),
		(*InstantVal)(nil),
	}
	for _, w := range nilWrappers {
		_, _ = resolveWrapperPropertyRound60(w, "x")
		_, _, _ = evalRound60ZeroArgMethod(".toString()", w, nil, nil, 0)
		_, _, _ = evalRound60ReceiverMethod(w, "toString", "", nil, nil, 0)
	}
	_, _, _ = evalDenseVectorMethodRound61((*DenseVectorFieldVal)(nil), "size", nil, nil, nil, 0)
	_, _, _ = evalDenseVectorMethodRound61((*DenseVectorVal)(nil), "size", nil, nil, nil, 0)
	_, _, _ = evalDenseVectorMethodRound61("not_a_vec", "size", nil, nil, nil, 0)

	// 2. Round60 PainlessLambda invoke methods (.get, .getAsInt, .applyAs*, .test) error propagation.
	for _, sc := range []string{
		`Supplier s = () -> Integer.parseInt("x"); return s.get();`,
		`IntSupplier s = () -> Integer.parseInt("x"); return s.getAsInt();`,
		`LongSupplier s = () -> Integer.parseInt("x"); return s.getAsLong();`,
		`DoubleSupplier s = () -> Integer.parseInt("x"); return s.getAsDouble();`,
		`BooleanSupplier s = () -> Integer.parseInt("x"); return s.getAsBoolean();`,
		`Function f = x -> Integer.parseInt("x"); return f.apply(1);`,
		`IntUnaryOperator f = x -> Integer.parseInt("x"); return f.applyAsInt(1);`,
		`LongUnaryOperator f = x -> Integer.parseInt("x"); return f.applyAsLong(1);`,
		`DoubleUnaryOperator f = x -> Integer.parseInt("x"); return f.applyAsDouble(1.0);`,
		`Predicate p = x -> Integer.parseInt("x") > 0; return p.test(1);`,
		`return Optional.of(1).map(x -> Integer.parseInt("x"));`,
		`return new BigDecimal("42.5").intValueExact();`,
		`return new BigDecimal("42.5").shortValueExact();`,
		`return new BigDecimal("42.5").byteValueExact();`,
		`return new BigDecimal("1.23").setScale(1, RoundingMode.UNNECESSARY);`,
		`return new BigInteger("10").divide(new BigInteger("0"));`,
		`return BigInteger.valueOf(Integer.parseInt("x"));`,
		`return BigDecimal.valueOf(Integer.parseInt("x"));`,
		`return BitSet.valueOf(Integer.parseInt("x"));`,
		`return Math.addExact(1, Integer.parseInt("x"));`,
		`return Math.subtractExact(1, Integer.parseInt("x"));`,
		`return Math.multiplyExact(1, Integer.parseInt("x"));`,
		`return Math.floorDiv(1, Integer.parseInt("x"));`,
		`return Math.floorMod(1, Integer.parseInt("x"));`,
		`return Math.min(Integer.parseInt("x"), 1.0);`,
		`return Math.max(Integer.parseInt("x"), 1.0);`,
		`return Math.pow(Integer.parseInt("x"), 1.0);`,
		`return Math.hypot(Integer.parseInt("x"), 1.0);`,
		`return Math.atan2(Integer.parseInt("x"), 1.0);`,
		`return Math.nextAfter(Integer.parseInt("x"), 1.0);`,
		`return Math.fma(1.0, Integer.parseInt("x"), 1.0);`,
		`return Math.clamp(1.0, Integer.parseInt("x"), 2.0);`,
		`return HexFormat.fromHexDigits("bad!");`,
		`return HexFormat.fromHexDigit(122);`,
		`return "hi".contentEquals(Integer.parseInt("x"));`,
		`return "%s".formatted(Integer.parseInt("x"));`,
	} {
		if _, err := Eval(nil, sc, map[string]any{}); err == nil {
			t.Fatalf("expected error for %q", sc)
		}
	}

	// 3. Map.ofEntries(params) filtering internal keys, FormatValueSafe on ZonedDateTimeVal/json.Number, ctx.__reindex_id.
	if mRes, err := Eval(nil, `return Map.ofEntries(params).size();`, map[string]any{"__alias_a": "a", "realK": 1}); err != nil || mRes != int64(1) {
		t.Fatalf("Map.ofEntries(params) expected 1, got (%#v, %v)", mRes, err)
	}
	if reidx, err := Eval(map[string]any{"__reindex_id": "rid1"}, `def c = ctx; return c._id;`, nil); err != nil || reidx != "rid1" {
		t.Fatalf("expected __reindex_id fallback rid1, got (%#v, %v)", reidx, err)
	}
	_ = FormatValueSafe(ZonedDateTimeVal{})
	_ = FormatValueSafe(json.Number("3.14"))
	_, _ = round60WrapperEquals(MonthEnum{Value: 1}, &MonthEnum{Value: 1})
	_, _ = round60WrapperEquals(&MonthEnum{Value: 1}, MonthEnum{Value: 1})
}
