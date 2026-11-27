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
	"math"
	"strings"
	"testing"
)

func FuzzPainlessBuiltinsAndRegexBombs(f *testing.F) {
	type fuzzSeed struct {
		pattern string
		input   string
		n       int64
		period  int64
		scale   int64
	}
	seeds := []fuzzSeed{
		// Nested RE2 bombs & valid regexes
		{`((a{1000}){1000}){100}`, "aaa", 3, 2, 2},
		{`(a{100}){101}`, "aaaa", 10, 1, 0},
		{`(a{1000,}){1000,}`, "aaa", 0, 0, -1},
		{`(a{500}b{500}){50}`, "ab", -1, -5, 10001},
		{`((?:a|b){100}){100}`, "abab", 10000, math.MaxInt64, -10001},
		{`(?<id>[0-9]+)-[a-z]+`, "123-abc", 10001, (math.MaxInt64 / 2) + 1, 5},
		{`,`, "a,b,c", 1 << 62, math.MinInt64, 10000},
		{`[unclosed`, "hello", math.MaxInt64, 10001, math.MaxInt32},
		{``, "", -100, 3, math.MinInt32},
		{`^foo.*bar$`, "foobar", 5, 2, 3},
		{`(%{COMBINEDAPACHELOG}){1000}`, "127.0.0.1 - - [01/Jan/2020:00:00:00 +0000] \"GET / HTTP/1.1\" 200 123", 1, 2, 1},
		{`1e2147483647`, "9.99", 2, 2, 2},
	}
	for _, s := range seeds {
		f.Add(s.pattern, s.input, s.n, s.period, s.scale)
	}

	f.Fuzz(func(t *testing.T, pattern, input string, n, period, scale int64) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("unexpected panic in FuzzPainlessBuiltinsAndRegexBombs(pattern=%q, n=%d, period=%d, scale=%d): %v",
					pattern, n, period, scale, r)
			}
		}()

		if len(pattern) > 8192 {
			pattern = pattern[:8192]
		}
		if len(input) > 4096 {
			input = input[:4096]
		}

		// 1. Bounded regex compilation (Java-normalized and raw) & Grok compilation.
		if re, err := CompileBoundedRegex(pattern); err == nil && re != nil {
			_ = re.FindStringIndex(input)
		} else if len(pattern) > MaxRegexPatternLen && err == nil {
			t.Fatalf("CompileBoundedRegex accepted oversized pattern len=%d", len(pattern))
		}

		if rawRe, err := CompileBoundedRawRegex(pattern); err == nil && rawRe != nil {
			_ = rawRe.FindStringIndex(input)
		} else if len(pattern) > MaxRegexPatternLen && err == nil {
			t.Fatalf("CompileBoundedRawRegex accepted oversized pattern len=%d", len(pattern))
		}

		if gx, err := CompileGrokPattern(pattern); err == nil && gx != nil {
			_, _ = gx.ExtractChecked(input)
		}

		// 2. Processors.split (direct + Painless Eval).
		if parts, err := splitProcessorRegexRound60(input, pattern); err == nil && parts != nil {
			if len(parts) > len(input)+1 {
				t.Fatalf("splitProcessorRegexRound60 produced unexpected part count %d for input len %d", len(parts), len(input))
			}
		}
		_, _ = Eval(map[string]any{"s": input}, "Processors.split(ctx.s, params.p)", map[string]any{"p": pattern})

		// 3. MovingFunctions.* including holtWinters with fuzzed and extreme periods.
		vals := []any{1.0, 2.0, 3.0, 4.0, 5.0, 6.0}
		for _, fn := range []string{"sum", "min", "max", "unweightedAvg", "linearWeightedAvg", "ewma", "holt", "stdDev"} {
			_, _ = evalMovingFunctionsStaticRound60(fn, []any{vals, 0.3, 0.1})
		}
		for _, pTest := range []int64{period, math.MaxInt64, (math.MaxInt64 / 2) + 1, -1, 0} {
			gotHW, errHW := evalMovingFunctionsStaticRound60("holtWinters", []any{vals, 0.3, 0.1, 0.1, pTest, false})
			if errHW != nil {
				t.Fatalf("holtWinters unexpected error for period=%d: %v", pTest, errHW)
			}
			if (pTest <= 0 || pTest > int64(len(vals)/2) || pTest > MaxPainlessSliceItems) && gotHW != nil {
				t.Fatalf("holtWinters expected nil for invalid period=%d, got %#v", pTest, gotHW)
			}
		}
		_, _ = Eval(nil, "return MovingFunctions.holtWinters(params.v, 0.3, 0.1, 0.1, params.p, false);", map[string]any{"v": vals, "p": period})

		// 4. String.repeat & Collections.nCopies bounds.
		if repVal, err := Eval(nil, "return params.s.repeat(params.n);", map[string]any{"s": input, "n": n}); err == nil {
			if repStr, ok := repVal.(string); ok && len(repStr) > MaxPainlessSliceItems*64 {
				t.Fatalf("String.repeat exceeded max output length: %d", len(repStr))
			}
		}
		if copiesVal, err := Eval(nil, "return Collections.nCopies(params.n, params.v);", map[string]any{"n": n, "v": input}); err == nil {
			if sl, ok := copiesVal.([]any); ok && len(sl) > MaxPainlessSliceItems {
				t.Fatalf("Collections.nCopies exceeded MaxPainlessSliceItems: %d", len(sl))
			}
		}

		// 5. BigDecimal & BigInteger bounded arithmetic.
		_, _ = Eval(nil, "return new BigDecimal(params.p);", map[string]any{"p": strings.TrimSpace(pattern)})
		_, _ = Eval(nil, "return new BigDecimal('1.5').setScale(params.s, RoundingMode.HALF_UP).add(new BigDecimal('2.25')).multiply(new BigDecimal('3'));", map[string]any{"s": scale})
		_, _ = Eval(nil, "return new BigDecimal('2').pow(params.s);", map[string]any{"s": scale})
		_, _ = Eval(nil, "return BigInteger.valueOf(3L).pow(params.s).add(BigInteger.ONE).shiftLeft(params.n);", map[string]any{"s": scale, "n": n})
	})
}
