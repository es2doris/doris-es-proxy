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
	"regexp"
	"testing"
	"time"
)

func r67TPMappedParams() map[string]any {
	return map[string]any{
		"_field_types": map[string]string{
			"tags":    "keyword",
			"cnt":     "long",
			"score":   "double",
			"created": "date",
			"loc":     "geo_point",
			"vec":     "dense_vector",
		},
		"_field_formats": map[string]string{
			"created": "yyyy/MM/dd",
		},
	}
}

func r67TPAssertErrScripts(t *testing.T, sourceMap map[string]any, params map[string]any, scripts []string) {
	t.Helper()
	for _, src := range scripts {
		if _, err := Eval(sourceMap, src, params); err == nil {
			t.Fatalf("expected error for script %q, got nil", src)
		}
	}
}

func TestRound67TopUpPainless_RHSOperatorsMatcherDateAndErrorPaths(t *testing.T) {
	// 1. Recursion depth > 64 guards in evalRHSExprDepth & evalConditionDepthErr
	if _, err := evalRHSExprDepth(nil, "1", nil, 65); err == nil {
		t.Fatal("expected recursion depth error in evalRHSExprDepth")
	}
	if _, err := evalConditionDepthErr(nil, "true", nil, 65); err == nil {
		t.Fatal("expected recursion depth error in evalConditionDepthErr")
	}

	// 2. Systematic error propagation in RHS operators, casts, unary ops, conditions, and method chains
	bad := `Integer.parseInt("bad")`
	errExprs := []string{
		bad + ` ?: 1`,
		`1 + ` + bad,
		bad + ` + 1`,
		`1 - ` + bad,
		bad + ` - 1`,
		`2 * ` + bad,
		bad + ` * 2`,
		`4 / ` + bad,
		bad + ` / 2`,
		`5 % ` + bad,
		`(int)(` + bad + `)`,
		`+(` + bad + `)`,
		`-(` + bad + `)`,
		`~(` + bad + `)`,
		`!(` + bad + ` == 1)`,
		bad + ` == 1`,
		`1 == ` + bad,
		bad + ` != 1`,
		`1 === ` + bad,
		`1 !== ` + bad,
		bad + ` < 1`,
		`1 < ` + bad,
		`true && (` + bad + ` > 0)`,
		`false || (` + bad + ` > 0)`,
		`true ? ` + bad + ` : 2`,
		`false ? 1 : ` + bad,
		`(` + bad + ` > 0) ? 1 : 2`,
		`("a" =~ ` + bad + `)`,
		`(` + bad + ` =~ /a/)`,
		`("a" ==~ ` + bad + `)`,
		`("a" !~ ` + bad + `)`,
		`true & (` + bad + ` > 0)`,
		`false | (` + bad + ` > 0)`,
		`true ^ (` + bad + ` > 0)`,
		`[` + bad + `]`,
		`["k": ` + bad + `]`,
		`[` + bad + `: 1]`,
		`doc.containsKey(` + bad + `)`,
		`ctx.op = ` + bad,
		`throw ` + bad,
		`throw new IllegalArgumentException(` + bad + `)`,
		`switch (1) { case 1 -> { yield ` + bad + `; } }`,
		`def sw = switch (1) { case 1 -> { yield ` + bad + `; } };`,
	}
	r67TPAssertErrScripts(t, map[string]any{"x": 1}, r67TPMappedParams(), errExprs)

	// 3. Unary + / - on float32 and raw float, doc.containsKey(null), params._source aliases
	srcDoc := map[string]any{"a": int64(10), "tags": []any{"x", "y"}, "m": map[string]any{"k": "v"}}
	okScripts := []string{
		`+1.5f == 1.5f && -1.5f == -1.5f`,
		`def f = (float) 2.5; return (+f) > 0 && (-f) < 0;`,
		`!doc.containsKey(null) && !doc?.containsKey(null)`,
		`params._source.a == 10 && params?._source?.a == 10 && params._source.size() > 0`,
		`params._source.added = 99; return ctx._source.added == 99;`,
		`def sj1 = new StringJoiner(","); sj1.add("a"); def sj2 = new StringJoiner(","); sj2.add("b"); sj1.merge(sj2); return sj1.toString() == "a,b";`,
		`"MONDAY".getValue() == 1 && "WEDNESDAY".getValue() == 3 && "SUNDAY".getValue() == 7 && "JANUARY".getValue() == 1 && "FEBRUARY".getValue() == 2 && "APRIL".getValue() == 4 && "MAY".getValue() == 5 && "JUNE".getValue() == 6 && "JULY".getValue() == 7 && "AUGUST".getValue() == 8 && "DECEMBER".getValue() == 12`,
		`'/a\\/b/'.pattern() == 'a/b' && "abc".flags() == 0 && "abc".clone() == "abc" && "abc".getSimpleName() != null && "abc".name() == "abc"`,
		`def m = /a/.matcher("aba"); return m.pattern() != null && m.groupCount() == 0 && m.regionStart() == 0 && m.regionEnd() == 3 && m.find() && m.start() == 0 && m.end() == 1 && m.group() == "a" && m.reset() != null;`,
		`def m2 = /ab*/.matcher("ab"); return m2.lookingAt() && m2.matches() && m2.reset("zz") != null && !m2.find() && !m2.matches() && !m2.lookingAt();`,
		`def m3 = Pattern.compile("").matcher("ab"); return m3.find() && m3.find() && m3.find();`,
		`def ot = OffsetTime.parse("10:15:30+01:00"); def f1 = ot.format("ISO_OFFSET_TIME"); def f2 = DateTimeFormatter.ISO_OFFSET_TIME.format(ot); def f3 = DateTimeFormatter.ofPattern("HH:mm").withZone("UTC").format(ot); return f1 != "" && f2 != "" && f3 != "";`,
		`def zdt = ZonedDateTime.parse("2026-01-15T10:20:30Z"); return DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone("America/New_York").format(zdt) != "";`,
		`def dec = Base64.getDecoder(); return dec.decode("aGVsbG8") == "hello";`,
		`DayOfWeek.MONDAY.plus(1.0) == "TUESDAY" && Month.MARCH.minus(2.0) == "JANUARY"`,
		`new BigDecimal("42").intValueExact() == 42`,
		`def lst = [1, 2, 3, 4]; lst.removeIf(x -> x > 2); lst.removeAll([1]); lst.retainAll([2]); return lst.size() == 1 && lst[0] == 2;`,
		`def sum = 0; [1, 2, 3].forEach(x -> { sum += x; }); return sum == 6;`,
		`def bd = new BigDecimal("10"); return bd.toString() == "10";`,
	}
	for _, s := range okScripts {
		docCopy := map[string]any{"a": int64(10), "tags": []any{"x", "y"}, "m": map[string]any{"k": "v"}}
		if _, err := Eval(docCopy, s, r67TPMappedParams()); err != nil {
			t.Fatalf("unexpected error for %q: %v", s, err)
		}
	}

	// 4. Matcher edge cases via direct painlessMatcher + .isEmpty() on special receiver types + Base64 byte array decode
	pmNilRe := &painlessMatcher{input: "abc"}
	for _, m := range []string{".find()", ".matches()", ".lookingAt()", ".groupCount()", ".regionStart()", ".regionEnd()"} {
		if _, err := evalRHSExprDepth(nil, "pm"+m, map[string]any{"pm": pmNilRe}, 0); err != nil {
			t.Fatalf("pmNilRe%s failed: %v", m, err)
		}
	}
	for _, m := range []string{".group()", ".start()", ".end()"} {
		if _, err := evalRHSExprDepth(nil, "pm"+m, map[string]any{"pm": pmNilRe}, 0); err == nil {
			t.Fatalf("expected IllegalStateException for pmNilRe%s", m)
		}
	}
	pmReg := &painlessMatcher{
		re:          regexp.MustCompile("a"),
		input:       "xxayy",
		curPos:      0,
		hasRegion:   true,
		regionStart: 2,
		regionEnd:   3,
	}
	if got, err := evalRHSExprDepth(nil, "pm.find()", map[string]any{"pm": pmReg}, 0); err != nil || got != true {
		t.Fatalf("expected region find=true, got %v err=%v", got, err)
	}
	if got, err := evalRHSExprDepth(nil, "pm.regionStart()", map[string]any{"pm": pmReg}, 0); err != nil || got != int64(2) {
		t.Fatalf("expected regionStart=2, got %v err=%v", got, err)
	}
	if got, err := evalRHSExprDepth(nil, "pm.regionEnd()", map[string]any{"pm": pmReg}, 0); err != nil || got != int64(3) {
		t.Fatalf("expected regionEnd=3, got %v err=%v", got, err)
	}

	// .isEmpty() across special types
	emptyParams := map[string]any{
		"eopt":  painlessEmptyOptional,
		"sb":    &painlessStringBuilder{},
		"f64":   []float64{},
		"br":    &BytesRefVal{},
		"bb":    &ByteBufferVal{},
		"num":   int64(5),
		"b64b":  []any{int64('a'), int64('G'), int64('V'), int64('s'), int64('b'), int64('G'), int64('8'), int64('=')},
		"ctxmp": map[string]any{"k": 1},
	}
	for expr, want := range map[string]any{
		"eopt.isEmpty()": true,
		"sb.isEmpty()":   true,
		"f64.isEmpty()":  true,
		"br.isEmpty()":   true,
		"bb.isEmpty()":   true,
		"num.isEmpty()":  false,
	} {
		got, err := evalRHSExprDepth(nil, expr, emptyParams, 0)
		if err != nil || got != want {
			t.Fatalf("%s expected %v, got %v err=%v", expr, want, got, err)
		}
	}
	if got, err := evalRHSExprDepth(nil, `Base64.getDecoder().decode(b64b)`, emptyParams, 0); err != nil || got != "hello" {
		t.Fatalf("expected base64 []any decode=hello, got %v err=%v", got, err)
	}

	// .clear() on ctx, ctx._source, local var, and unmodifiable error
	clearDoc := map[string]any{"a": 1, "sub": []any{1, 2}}
	if _, err := Eval(clearDoc, `ctx._source.sub.clear(); ctx._source.clear();`, nil); err != nil {
		t.Fatalf("clear failed: %v", err)
	}
	if _, err := Eval(nil, `def s = List.of(1, 2); s.clear();`, nil); err == nil {
		t.Fatal("expected clear error on unmodifiable list")
	}
	_ = srcDoc
}

func TestRound67TopUpPainless_StaticCallsConstructorsAndInstanceOf(t *testing.T) {
	bad := `Integer.parseInt("bad")`
	// 1. Static call error paths + missing-arg fallbacks + edge variants
	errStatic := []string{
		`Math.getExponent(` + bad + `)`,
		`Double.parseDouble(` + bad + `)`,
		`Boolean.valueOf(` + bad + `)`,
		`Integer.toString(` + bad + `)`,
		`Double.toString(` + bad + `)`,
		`Boolean.toString(` + bad + `)`,
		`Objects.equals(` + bad + `, 1)`,
		`Objects.equals(1, ` + bad + `)`,
		`Objects.hashCode(` + bad + `)`,
		`Objects.isNull(` + bad + `)`,
		`Objects.nonNull(` + bad + `)`,
		`Objects.toString(` + bad + `)`,
		`Objects.toString(null, ` + bad + `)`,
		`Objects.requireNonNull(` + bad + `)`,
		`Objects.requireNonNullElse(` + bad + `, 1)`,
		`Objects.requireNonNullElse(null, ` + bad + `)`,
		`String.valueOf(` + bad + `)`,
		`String.valueOf([65], ` + bad + `, 1)`,
		`String.valueOf([65], 0, ` + bad + `)`,
		`Encoding.encodeBase64(` + bad + `)`,
		`Encoding.decodeBase64(` + bad + `)`,
		`Encoding.encodeHex(` + bad + `)`,
		`Encoding.decodeHex(` + bad + `)`,
		`HexFormat.ofDelimiter(` + bad + `)`,
		`Digest.sha256(` + bad + `)`,
		`Arrays.asList(` + bad + `)`,
		`Arrays.asList(null)`,
		`List.of(` + bad + `)`,
		`List.of(null)`,
		`Set.of(1, 1)`,
		`Set.of(null)`,
		`List.copyOf()`,
		`List.copyOf(` + bad + `)`,
		`List.copyOf(null)`,
		`List.copyOf("not_a_list")`,
		`List.copyOf([null])`,
		`Set.copyOf([null])`,
		`Map.copyOf()`,
		`Map.copyOf(` + bad + `)`,
		`Map.copyOf(null)`,
		`Map.copyOf("not_a_map")`,
		`Map.copyOf(["k": null])`,
		`Map.of("a", 1, "a", 2)`,
		`Map.entry("only_one")`,
		`Map.ofEntries("not_entry")`,
		`Map.ofEntries(Map.entry("k", null))`,
		`Map.ofEntries(Map.entry("k", 1), Map.entry("k", 2))`,
		`Arrays.sort(` + bad + `)`,
		`Arrays.sort(List.of(2, 1))`,
		`Arrays.sort([2, 1], ` + bad + `, 1)`,
		`Arrays.sort([2, 1], 0, ` + bad + `)`,
		`IntStream.range(` + bad + `, 2)`,
		`IntStream.range(0, ` + bad + `)`,
		`Stream.concat(` + bad + `, [1])`,
		`Stream.concat([1], ` + bad + `)`,
		`Instant.now(` + bad + `)`,
		`ZonedDateTime.now(` + bad + `)`,
		`Year.of()`,
		`MonthDay.of("BAD", 1)`,
		`DayOfWeek.of(` + bad + `)`,
		`Month.of(` + bad + `)`,
		`Duration.between(` + bad + `, Instant.now())`,
		`Duration.between(Instant.now(), ` + bad + `)`,
		`DateTimeFormatter.ofPattern(` + bad + `)`,
		`DateTimeFormatter.ofPattern(null)`,
	}
	r67TPAssertErrScripts(t, nil, nil, errStatic)

	// 2. Valid static calls covering uncovered fallbacks & branches
	var jnInt json.Number = "42"
	var jnFloat json.Number = "3.5"
	p := map[string]any{
		"jnInt":   jnInt,
		"jnFloat": jnFloat,
		"docTags": []any{"a", "b"},
	}
	docMap := map[string]any{"tags": []any{"t1", "t2"}}
	okStatic := []string{
		`Math.getExponent() == 0 && Math.getExponent(0.0) == -1023 && Math.getExponent(Double.NaN) == 1024 && Math.getExponent(Double.POSITIVE_INFINITY) == 1024 && Math.getExponent(8.0) == 3`,
		`Double.parseDouble() == 0 && Boolean.valueOf() == false && Integer.toString() == "" && Integer.toString("abc") == "abc" && Double.toString() == "" && Double.toString("abc") == "abc" && Boolean.toString() == "false" && Boolean.toString("true") == "true" && Boolean.toString("no") == "false"`,
		`Integer.toHexString() == "0" && Integer.toUnsignedString() == "0" && Integer.compareUnsigned() == 0 && Integer.divideUnsigned() == 0 && Integer.remainderUnsigned() == 0 && Integer.compare() == 0 && Double.compare() == 0 && Boolean.compare() == 0`,
		`String.valueOf() == "" && String.valueOf([65, "B"]) == "AB" && String.valueOf(null) == "null"`,
		`String.format("%d-%.1f", params.jnInt, params.jnFloat) == "42-3.5"`,
		`String.join(",", doc.tags) == "t1,t2" && String.join(",", "single") == "single" && String.join() == ""`,
		`Encoding.decodeBase64("aGVsbG8td29ybGQ") == "hello-world" && Encoding.decodeBase64("aGVsbG8td29ybGQ=") == "hello-world" && Encoding.decodeBase64() == "" && Encoding.encodeBase64() == "" && Digest.sha256() == ""`,
		`Arrays.asList().size() == 0 && Arrays.asList((String) null).size() == 1`,
		`def ia = new String[]{"x", "y"}; return Arrays.asList(ia).size() == 2;`,
		`List.of().size() == 0 && Set.of().size() == 0 && List.copyOf([1, 2]).size() == 2 && Set.copyOf([1, 1, 2]).size() == 2`,
		`Map.ofEntries().size() == 0 && Map.copyOf(["a": 1]).size() == 1`,
		`Charset.defaultCharset() == "UTF-8" && Charset.forName() == "UTF-8" && Collections.singleton().size() == 0`,
		`IntStream.of().count() == 0 && DoubleStream.of().count() == 0 && IntStream.range().count() == 0 && Stream.concat().count() == 0`,
		`IntStream.of(1.0, 2.0).sum() == 3 && DoubleStream.of(1, 2.5).sum() == 3.5`,
		`ZoneOffset.ofHours(0) == "UTC" && ZoneOffset.ofHours(3) == "+03:00" && ZoneOffset.ofHours(-5) == "-05:00" && ZoneOffset.of() == "UTC"`,
		`Year.isLeap() == false && Year.from("bad") == null && MonthDay.from("bad") == null`,
		`Instant.ofEpochMilli() == null && Instant.ofEpochSecond() == null && ZonedDateTime.ofInstant("bad", "UTC") == null && LocalDate.ofEpochDay() == null`,
	}
	for _, badDateScript := range []string{
		`DayOfWeek.of("BAD")`,
		`Month.of("BAD")`,
		`DayOfWeek.MONDAY.plus("bad")`,
		`Month.JANUARY.minus("bad")`,
	} {
		if _, err := Eval(docMap, badDateScript, p); err == nil {
			t.Fatalf("expected error for invalid temporal call %q", badDateScript)
		}
	}
	for _, s := range okStatic {
		if _, err := Eval(docMap, s, p); err != nil {
			t.Fatalf("unexpected error in static script %q: %v", s, err)
		}
	}

	// 3. Collection / String / BigDecimal constructors + error paths
	ctorOK := []string{
		`new String(null) == ""`,
		`def sb = new StringBuilder("hi"); return new String(sb) == "hi";`,
		`new String(["a", "b", "c"], 1, 2) == "bc"`,
		`new String(["a", "b"], -5, 10) == "ab"`,
		`new String([65, 66, 67], 1, 2) == "BC"`,
		`new String([65, 66], -1, 10) == "AB"`,
		`new ArrayList(doc.tags).size() == 2`,
		`new ArrayList([]).size() == 0`,
		`def mc = new MathContext(3, RoundingMode.HALF_UP); return new BigDecimal(new BigInteger("12345"), 2, mc).toString() != "";`,
		`new BigDecimal(new BigInteger("123"), 2).toString() == "1.23"`,
	}
	for _, s := range ctorOK {
		if _, err := Eval(docMap, s, r67TPMappedParams()); err != nil {
			t.Fatalf("unexpected error in ctor script %q: %v", s, err)
		}
	}
	r67TPAssertErrScripts(t, docMap, nil, []string{
		`new String("a", ` + bad + `)`,
		`new String("a", 0, 1, ` + bad + `)`,
		`new BigDecimal(new BigInteger("1"), ` + bad + `)`,
		`new BigDecimal(new BigInteger("1"), 1, ` + bad + `)`,
	})
	if _, handled, _ := evalCollectionConstructorPainless(nil, "not_new", nil, 0); handled {
		t.Fatal("expected handled=false for non-new")
	}
	if _, handled, _ := evalCollectionConstructorPainless(nil, "new UnknownCls()", nil, 0); handled {
		t.Fatal("expected handled=false for UnknownCls")
	}
	if _, handled, _ := evalCollectionConstructorPainless(nil, "new String", nil, 0); handled {
		t.Fatal("expected handled=false for missing parens")
	}

	// 4. evalInstanceOfPainless edge cases
	ioCases := []struct {
		val  any
		typ  string
		want bool
	}{
		{painlessEmptyOptional, "Optional", true},
		{painlessEmptyOptional, "String", false},
		{[]float64{1.0}, "double[]", true},
		{[]float64{1.0}, "int[]", false},
		{map[string]any{"__type": "IntSummaryStatistics"}, "IntSummaryStatistics", true},
		{int64(1), "IntSummaryStatistics", false},
		{int64(1), "UUID", false},
		{"America/New_York", "ZoneId", true},
		{"Not/A_Real_Zone_XYZ", "ZoneId", false},
		{int64(1), "ZoneId", false},
		{DayOfWeekEnum{Value: 1, NameStr: "MONDAY"}, "DayOfWeek", true},
		{int64(1), "DayOfWeek", false},
		{int64(1), "LocalDate", false},
		{int64(1), "LocalTime", false},
		{int64(1), "LocalDateTime", false},
		{time.Now(), "ZonedDateTime", true},
		{int64(1), "ZonedDateTime", false},
	}
	for _, tc := range ioCases {
		if got := evalInstanceOfPainless(tc.val, tc.typ); got != tc.want {
			t.Fatalf("evalInstanceOfPainless(%#v, %q) = %v, want %v", tc.val, tc.typ, got, tc.want)
		}
	}
}

func TestRound67TopUpPainless_SimpleStatementsAndAssignments(t *testing.T) {
	// 1. Null-safe statement methods on missing ctx._source paths + error args + user object method stmt dispatch
	bad := `Integer.parseInt("bad")`
	okStmts := []string{
		`ctx._source.missing?.removeIf(x -> x == 1);`,
		`ctx._source.missing?.addAll([1, 2]);`,
		`ctx._source.missing?.removeAll([1]);`,
		`ctx._source.missing?.retainAll([1]);`,
		`ctx._source.missing?.add(1);`,
		`ctx._source.missing?.set(0, 1);`,
		`ctx._source.missing?.putAll(["k": 1]);`,
		`ctx._source.missing?.put("k", 1);`,
		`ctx._source.missing?.remove("k");`,
		`ctx._source.missing?.clear();`,
		`ctx._source.list.addAll(0, [10, 20]);`,
		`ctx._source.list.add(1, 15);`,
		`ctx._source.list.set(0, 99);`,
		`ctx._source.map.remove("a", 1);`,
		`ctx.op = null;`,
		`def locList = [1, 2, 3]; locList?.removeIf(x -> x == 2); locList?.addAll(0, [0]); return locList;`,
		`def locNull = null; locNull?.removeIf(x -> true); locNull?.addAll([1]);`,
		`class Box { int v = 1; void add(int x) { this.v += x; } void put(String k, int x) { this.v += x; } } def b = new Box(); b.add(5); b.put("k", 2); return b.v;`,
	}
	for _, s := range okStmts {
		sm := map[string]any{"list": []any{1, 2}, "map": map[string]any{"a": 1, "b": 2}}
		if _, err := Eval(sm, s, nil); err != nil {
			t.Fatalf("unexpected stmt error for %q: %v", s, err)
		}
	}

	errStmts := []string{
		`ctx._source.list.addAll(` + bad + `, [1]);`,
		`ctx._source.list.addAll(0, ` + bad + `);`,
		`ctx._source.list.addAll(` + bad + `);`,
		`ctx._source.list.removeAll(` + bad + `);`,
		`ctx._source.list.retainAll(` + bad + `);`,
		`ctx._source.list.add(` + bad + `, 1);`,
		`ctx._source.list.add(0, ` + bad + `);`,
		`ctx._source.list.add(` + bad + `);`,
		`ctx._source.list.set(` + bad + `, 1);`,
		`ctx._source.list.set(0, ` + bad + `);`,
		`ctx._source.map.putAll(` + bad + `);`,
		`ctx._source.map.put(` + bad + `, 1);`,
		`ctx._source.map.put("k", ` + bad + `);`,
		`ctx._source.map.remove(` + bad + `, 1);`,
		`ctx._source.map.remove("a", ` + bad + `);`,
		`ctx._source.map.remove(` + bad + `);`,
		`def locNull = null; locNull.removeIf(x -> true);`,
		`def locNull = null; locNull.addAll([1]);`,
		`ctx._source.frozen = List.of(1, 2); ctx._source.frozen.removeIf(x -> true);`,
		`ctx._source.frozen = List.of(1, 2); ctx._source.frozen.addAll([1]);`,
		`ctx._source.frozen = List.of(1, 2); ctx._source.frozen.removeAll([1]);`,
		`ctx._source.frozen = List.of(1, 2); ctx._source.frozen.retainAll([1]);`,
		`ctx._source.frozen = List.of(1, 2); ctx._source.frozen.add(1);`,
		`ctx._source.frozen = List.of(1, 2); ctx._source.frozen.set(0, 1);`,
		`ctx._source.frozenM = Map.of("a", 1); ctx._source.frozenM.putAll(["b": 2]);`,
		`ctx._source.frozenM = Map.of("a", 1); ctx._source.frozenM.put("b", 2);`,
		`ctx._source.frozenM = Map.of("a", 1); ctx._source.frozenM.remove("a");`,
		`ctx._source.frozenM = Map.of("a", 1); ctx._source.frozenM.clear();`,
	}
	r67TPAssertErrScripts(t, map[string]any{"list": []any{1, 2}, "map": map[string]any{"a": 1}}, nil, errStmts)

	// 2. evalAssignExprRound59Painless direct & script edge cases
	if _, err := evalAssignExprRound59Painless(nil, "", "=", "1", nil, 0); err == nil {
		t.Fatal("expected invalid empty assignment target error")
	}
	if _, err := evalAssignExprRound59Painless(nil, "doc.x", "=", "1", nil, 0); err == nil {
		t.Fatal("expected doc read-only assignment error")
	}
	if _, err := evalAssignExprRound59Painless(nil, "x", "=", "1", nil, 0); err == nil {
		t.Fatal("expected nil params error")
	}
	if _, err := evalAssignExprRound59Painless(nil, "bad target!", "=", "1", map[string]any{}, 0); err == nil {
		t.Fatal("expected invalid identifier assignment error")
	}
	if _, err := evalAssignExprRound59Painless(nil, "x", "=", "1", map[string]any{"__out_of_scope_vars": map[string]bool{"x": true}}, 0); err == nil {
		t.Fatal("expected out of scope variable error")
	}

	assignScripts := []string{
		`Map getMap() { return ["x": 1]; } getMap().x = 5; getMap().x += 2; return 1;`,
		`class BaseA { int v = 10; } class SubA extends BaseA { int bump() { super.v = 20; super.v += 5; return super.v; } } return new SubA().bump();`,
		`class StA { static int c = 1; static int inc() { c += 2; return c; } } StA.c = 10; StA.c += 5; return StA.inc() + StA.c;`,
		`def m = ["k": 1]; for (def e : m.entrySet()) { e.value = 99; } return m["k"];`,
		`_source.a = 7; _source.a += 3; return _source.a;`,
		`def x = 1; if (x = 0) { return 0; } if (x = null) { return 0; } return 1;`,
	}
	for _, s := range assignScripts {
		sm := map[string]any{"a": int64(1)}
		if _, err := Eval(sm, s, nil); err != nil {
			t.Fatalf("assign script %q failed: %v", s, err)
		}
	}

	r67TPAssertErrScripts(t, map[string]any{"a": 1}, nil, []string{
		`Map getNull() { return null; } def z = (getNull().k = 1);`,
		`def getFrozen() { return Map.of("k", 1); } getFrozen().k = 2;`,
		`Map getMap() { return ["x": 1]; } getMap().x = ` + bad + `;`,
		`Map getMap() { return ["x": 1]; } def z = (getMap().x += ` + bad + `);`,
		`Map m = null; def z = (m.k = 1);`,
		`ctx._source = ` + bad,
		`_source.a = ` + bad,
		`_source.a += ` + bad,
		`ctx.op = ` + bad,
		`ctx.op += ` + bad,
		`class StB { static int c = 1; } StB.c = ` + bad + `;`,
		`class StC { static String s = "a"; } StC.s = ` + bad + `;`,
	})
}

func TestRound67TopUpPainless_NumericBitSetHexNavigableCharAndArrays(t *testing.T) {
	bad := `Integer.parseInt("bad")`
	// 1. BigDecimal & BigInteger methods + bounds/error branches
	bdBiOK := []string{
		`def a = new BigDecimal("10.50"); def b = new BigDecimal("2.5"); def mc = new MathContext(4, RoundingMode.HALF_UP); return a.subtract(b, mc).toString() + ":" + a.multiply(b, mc).toString() + ":" + a.divide(b).toString() + ":" + a.divide(b, "HALF_UP").toString() + ":" + a.divide(b, 2).toString() + ":" + a.divide(b, 2, "HALF_UP").toString() + ":" + a.divide(b, mc).toString();`,
		`def a = new BigDecimal("10.5"); def b = new BigDecimal("3"); def mc = new MathContext(4, RoundingMode.HALF_UP); return a.remainder(b, mc).toString() + ":" + a.divideToIntegralValue(b, mc).toString() + ":" + a.divideAndRemainder(b, mc).length;`,
		`def a = new BigDecimal("2.0"); def mc = new MathContext(3, RoundingMode.HALF_UP); return a.pow(3, mc).toString() + ":" + new BigDecimal("0").pow(0).toString() + ":" + new BigDecimal("0").pow(2).toString() + ":" + new BigDecimal("1").pow(5).toString() + ":" + new BigDecimal("-1").pow(3).toString() + ":" + new BigDecimal("-1").pow(2).toString();`,
		`def a = new BigDecimal("1.25"); return a.setScale(1, "HALF_UP").toString() + ":" + a.min(new BigDecimal("2")).toString() + ":" + a.max(new BigDecimal("2")).toString() + ":" + a.movePointLeft(1).toString() + ":" + a.movePointRight(1).toString() + ":" + a.scaleByPowerOfTen(2).toString() + ":" + a.abs(new MathContext(2, RoundingMode.HALF_UP)).toString() + ":" + a.negate(new MathContext(2, RoundingMode.HALF_UP)).toString();`,
		`def x = new BigInteger("25"); def y = new BigInteger("7"); return x.subtract(y).toString() + ":" + x.multiply(y).toString() + ":" + x.divide(y).toString() + ":" + x.remainder(y).toString() + ":" + x.divideAndRemainder(y).length + ":" + x.mod(y).toString() + ":" + x.modPow(new BigInteger("-1"), y).toString() + ":" + x.modPow(y, new BigInteger("1")).toString() + ":" + x.modInverse(y).toString() + ":" + x.modInverse(new BigInteger("1")).toString();`,
		`def x = new BigInteger("12"); def z = new BigInteger("0"); return z.gcd(x).toString() + ":" + x.gcd(z).toString() + ":" + x.min(new BigInteger("5")).toString() + ":" + x.max(new BigInteger("20")).toString() + ":" + x.and(new BigInteger("10")).toString() + ":" + x.xor(new BigInteger("10")).toString() + ":" + x.andNot(new BigInteger("4")).toString();`,
		`def x = new BigInteger("8"); return x.shiftLeft(2).toString() + ":" + x.shiftLeft(-1).toString() + ":" + x.shiftRight(1).toString() + ":" + x.shiftRight(-1).toString() + ":" + x.testBit(3) + ":" + x.testBit(3000000000L) + ":" + x.setBit(0).toString() + ":" + x.clearBit(3).toString() + ":" + x.flipBit(0).toString() + ":" + x.isProbablePrime(10) + ":" + x.isProbablePrime(0) + ":" + new BigInteger("-5").isProbablePrime(5) + ":" + x.toString(16) + ":" + x.toString(99);`,
		`def bs1 = BitSet.valueOf([7L]); def bs2 = BitSet.valueOf([3L]); bs1.xor(bs2); bs1.and(bs2); bs1.andNot(bs2); bs1.flip(1); bs1.flip(0, 3); bs1.clear(0); bs1.clear(0, 2); return bs1.nextSetBit(0) + bs1.nextClearBit(0);`,
	}
	for _, s := range bdBiOK {
		if _, err := Eval(nil, s, nil); err != nil {
			t.Fatalf("BigDecimal/BigInteger/BitSet script %q failed: %v", s, err)
		}
	}
	r67TPAssertErrScripts(t, nil, nil, []string{
		`new BigDecimal("1").divide(new BigDecimal("0"))`,
		`new BigDecimal("1").divide(new BigDecimal("2"), 999999)`,
		`new BigDecimal("1").divide(new BigDecimal("2"), 999999, "HALF_UP")`,
		`new BigDecimal("1").remainder(new BigDecimal("0"))`,
		`new BigDecimal("2").pow(-1)`,
		`new BigDecimal("2").pow(999999)`,
		`new BigDecimal("1.2").setScale(999999)`,
		`new BigDecimal("1").movePointLeft(999999)`,
		`new BigDecimal("1").movePointRight(999999)`,
		`new BigDecimal("1").scaleByPowerOfTen(999999)`,
		`new BigDecimal("1").subtract(` + bad + `)`,
		`new BigDecimal("1").multiply(` + bad + `)`,
		`new BigDecimal("1").divide(` + bad + `)`,
		`new BigDecimal("1").setScale(` + bad + `)`,
		`new BigDecimal("1").min(` + bad + `)`,
		`new BigDecimal("1").max(` + bad + `)`,
		`new BigDecimal("1").abs(` + bad + `)`,
		`new BigDecimal("1").negate(` + bad + `)`,
		`new BigInteger("5").divide(new BigInteger("0"))`,
		`new BigInteger("5").remainder(new BigInteger("0"))`,
		`new BigInteger("5").divideAndRemainder(new BigInteger("0"))`,
		`new BigInteger("5").mod(new BigInteger("0"))`,
		`new BigInteger("2").modPow(new BigInteger("2"), new BigInteger("0"))`,
		`new BigInteger("2").modPow(new BigInteger("-1"), new BigInteger("4"))`,
		`new BigInteger("2").modInverse(new BigInteger("0"))`,
		`new BigInteger("2").modInverse(new BigInteger("4"))`,
		`new BigInteger("2").pow(100000)`,
		`new BigInteger("2").shiftLeft(1000000)`,
		`new BigInteger("2").shiftRight(-1000000)`,
		`new BigInteger("2").testBit(-1)`,
		`new BigInteger("2").setBit(-1)`,
		`new BigInteger("2").setBit(1000000)`,
		`new BigInteger("2").clearBit(-1)`,
		`new BigInteger("2").clearBit(1000000)`,
		`new BigInteger("2").flipBit(-1)`,
		`new BigInteger("2").flipBit(1000000)`,
		`BitSet.valueOf([1L]).clear(999999999)`,
		`BitSet.valueOf([1L]).clear(0, 999999999)`,
		`BitSet.valueOf([1L]).flip(999999999)`,
		`BitSet.valueOf([1L]).flip(0, 999999999)`,
	})

	// 2. HexFormat direct + script coverage
	hf := painlessHexFormat{delimiter: ":", prefix: "0x", suffix: "h", upperCase: true}
	if got, err := evalHexFormatMethodPainless(".formatHex(", hf, `""`, nil, nil, 0); err != nil || got != "" {
		t.Fatalf("empty formatHex failed: %v %v", got, err)
	}
	if got, err := evalHexFormatMethodPainless(".formatHex(", hf, `[10, 255, 16], 1, 3`, nil, nil, 0); err != nil || got != "0xFFh:0x10h" {
		t.Fatalf("range formatHex failed: %v %v", got, err)
	}
	if _, err := evalHexFormatMethodPainless(".formatHex(", hf, `[10], 0, 5`, nil, nil, 0); err == nil {
		t.Fatal("expected OOB on formatHex")
	}
	if got, err := evalHexFormatMethodPainless(".parseHex(", hf, `"0xFFh:0x10h", 0, 11`, nil, nil, 0); err != nil || len(got.([]any)) != 2 {
		t.Fatalf("parseHex range failed: %v %v", got, err)
	}
	if got, err := evalHexFormatMethodPainless(".parseHex(", hf, `""`, nil, nil, 0); err != nil || len(got.([]any)) != 0 {
		t.Fatalf("parseHex empty failed: %v %v", got, err)
	}
	for _, badHexArg := range []string{`"0xFFh:0x1"`, `"0xZZh"`, `"x"`} {
		if _, err := evalHexFormatMethodPainless(".parseHex(", hf, badHexArg, nil, nil, 0); err == nil {
			t.Fatalf("expected parseHex error for %s", badHexArg)
		}
	}
	if _, err := evalHexFormatMethodPainless(".parseHex(", painlessHexFormat{}, `"abc"`, nil, nil, 0); err == nil {
		t.Fatal("expected odd length parseHex error")
	}
	if got, err := evalHexFormatMethodPainless(".toHexDigits(", hf, `(byte) 15`, nil, nil, 0); err != nil || got != "0F" {
		t.Fatalf("toHexDigits byte failed: %v %v", got, err)
	}
	if got, err := evalHexFormatMethodPainless(".toHexDigits(", hf, `(short) 15`, nil, nil, 0); err != nil || got != "000F" {
		t.Fatalf("toHexDigits short failed: %v %v", got, err)
	}
	if got, err := evalHexFormatMethodPainless(".toHexDigits(", hf, `15L`, nil, nil, 0); err != nil || got != "000000000000000F" {
		t.Fatalf("toHexDigits long failed: %v %v", got, err)
	}
	if got, err := evalHexFormatMethodPainless(".toHexDigits(", hf, `"A"`, nil, nil, 0); err != nil || got != "0041" {
		t.Fatalf("toHexDigits char failed: %v %v", got, err)
	}
	if got, err := evalHexFormatMethodPainless(".toHexDigits(", hf, `15, 0`, nil, nil, 0); err != nil || got != "" {
		t.Fatalf("toHexDigits 0 digits failed: %v %v", got, err)
	}
	if _, err := evalHexFormatMethodPainless(".toHexDigits(", hf, `15, 99`, nil, nil, 0); err == nil {
		t.Fatal("expected digits out of range error")
	}
	if _, err := evalHexFormatMethodPainless(".fromHexDigits(", hf, `"FF", 0, 99`, nil, nil, 0); err == nil {
		t.Fatal("expected OOB fromHexDigits")
	}
	if _, err := evalHexFormatMethodPainless(".fromHexDigits(", hf, `"123456789"`, nil, nil, 0); err == nil {
		t.Fatal("expected too-long fromHexDigits")
	}
	if _, err := evalHexFormatMethodPainless(".fromHexDigits(", hf, `"ZZ"`, nil, nil, 0); err == nil {
		t.Fatal("expected invalid fromHexDigits")
	}
	if got, err := evalHexFormatMethodPainless(".fromHexDigitsToLong(", hf, `"ff", 0, 2`, nil, nil, 0); err != nil || got != int64(255) {
		t.Fatalf("fromHexDigitsToLong failed: %v %v", got, err)
	}
	if _, err := evalHexFormatMethodPainless(".fromHexDigit(", hf, `"z"`, nil, nil, 0); err == nil {
		t.Fatal("expected invalid fromHexDigit")
	}
	if got, err := evalHexFormatMethodPainless(".isHexDigit(", hf, `"F"`, nil, nil, 0); err != nil || got != true {
		t.Fatalf("isHexDigit failed: %v %v", got, err)
	}

	// 3. NavigableMap / NavigableSet / Deque / PriorityQueue
	navScripts := []string{
		`def tm = new TreeMap(); tm.put("a", 1); tm.put("b", 2); tm.put("c", 3);
		 def d = tm.descendingMap();
		 return tm.floorKey("b") == "b" && tm.ceilingKey("b") == "b" && tm.lowerKey("b") == "a" && tm.higherKey("b") == "c" &&
		        tm.floorEntry("b").getValue() == 2 && tm.lowerEntry("a") == null &&
		        d.lowerKey("b") == "c" && d.higherKey("b") == "a" &&
		        tm.headMap("b", true).size() == 2 && tm.tailMap("b", false).size() == 1 &&
		        tm.subMap("a", true, "c", false).size() == 2 && tm.subMap("a", "c").size() == 2 &&
		        d.headMap("b", true).size() == 2 && d.tailMap("b", false).size() == 1 && d.subMap("c", true, "a", false).size() == 2;`,
		`def ts = new TreeSet(); ts.add(10); ts.add(20); ts.add(30);
		 return ts.floor(20) == 20 && ts.ceiling(20) == 20 && ts.lower(20) == 10 && ts.higher(20) == 30 && ts.lower(10) == null &&
		        ts.headSet(20, true).size() == 2 && ts.tailSet(20, false).size() == 1 &&
		        ts.subSet(10, true, 30, false).size() == 2 && ts.subSet(10, 30).size() == 2;`,
		`def dq = new ArrayDeque(); dq.offerFirst(1); dq.addFirst(0); dq.push(-1); dq.offerLast(2); dq.offer(3); dq.addLast(4);
		 dq.removeFirstOccurrence(1); dq.removeLastOccurrence(3); dq.removeFirstOccurrence(999); dq.removeLastOccurrence(999);
		 return dq.size() == 4;`,
		`def pq = new PriorityQueue(); pq.offer(30); pq.offer(10); pq.offer(20); return pq.peek() == 10;`,
	}
	for _, s := range navScripts {
		if _, err := Eval(nil, s, nil); err != nil {
			t.Fatalf("navigable/deque script failed: %v\nscript: %s", err, s)
		}
	}
	if _, err := evalNavigableOrDequeMethodPainless(".offerFirst(", "x", []any{1}, bad, nil, nil, 0); err == nil {
		t.Fatal("expected error from offerFirst bad arg")
	}

	// 4. Character static methods & Arrays.compare / mismatch
	charScripts := []string{
		`Character.charCount(0x1F600) == 2 && Character.charCount(65) == 1 && Character.charCount("bad") == null`,
		`Character.toChars(0x1F600).length == 2 && Character.toChars(65).length == 1 && Character.toChars("bad") == null`,
		`Character.toString(65) == "A" && Character.valueOf("bad") == "bad"`,
		`Character.codePointAt("hi\uD83D\uDE00", 2) == 128512 && Character.codePointBefore("hi\uD83D\uDE00", 4) == 128512 && Character.codePointBefore("hi", 1) == 104`,
		`Character.codePointCount("a\uD83D\uDE00b", 0, 4) == 3`,
		`Character.getNumericValue("bad") == -1 && Character.getNumericValue("9") == 9 && Character.getNumericValue("z") == 35 && Character.getNumericValue("Z") == 35 && Character.getNumericValue(" ") == -1`,
		`Character.getType("A") == 1 && Character.getType("a") == 2 && Character.getType("0") == 9 && Character.getType(" ") == 12 && Character.getType("-") == 20 && Character.getType("(") == 21 && Character.getType(")") == 22 && Character.getType("_") == 23 && Character.getType(".") == 24 && Character.getType("+") == 25 && Character.getType("$") == 26 && Character.getType("^") == 27 && Character.getType("bad") == 0`,
		`Character.compare("b", "a") == 1 && Character.compare() == 0`,
		`Character.isDigit(48) && Character.isLetter(65) && Character.isLetterOrDigit(48) && Character.isAlphabetic(65)`,
		`Character.isWhitespace(32) && !Character.isWhitespace(0x00A0) && !Character.isWhitespace("bad") && Character.isSpaceChar(32) && Character.isUpperCase("A") && Character.isLowerCase("a")`,
		`Character.toUpperCase("a") == "A" && Character.toUpperCase(97) == 65 && Character.toUpperCase("bad") == "bad" && Character.toLowerCase("A") == "a" && Character.toLowerCase(65) == 97 && Character.toLowerCase("bad") == "bad"`,
		`Character.toTitleCase("a") == "A" && Character.toTitleCase(97) == 65 && Character.isIdeographic(0x4E2D) && Character.isJavaIdentifierStart("_") && Character.isJavaIdentifierPart("1") && Character.isISOControl(10) && Character.isDefined(65) && Character.digit("f", 16) == 15 && Character.digit("z", 16) == -1 && Character.digit("1", 99) == -1 && Character.forDigit(15, 16) == "f" && Character.forDigit(5, 10) == "5" && Character.forDigit(99, 10) != "5" && Character.reverseBytes(0x0102) == 0x0201`,
		`Arrays.compare(null, null) == 0 && Arrays.compare(null, [1]) == -1 && Arrays.compare([1], null) == 1 && Arrays.compare("a", "b") == 0 && Arrays.compare([1], [1, 2]) == -1 && Arrays.compare([1, 2], [1]) == 1`,
		`Arrays.mismatch(null, null) == -1 && Arrays.mismatch([1, 2], [1]) == 1 && Arrays.mismatch([1, 2], [1, 2], (a, b) -> a - b) == -1`,
	}
	for _, s := range charScripts {
		v, err := Eval(nil, s, nil)
		if err != nil {
			t.Fatalf("char/arrays script %q failed: %v", s, err)
		}
		if b, ok := v.(bool); ok && !b {
			t.Fatalf("expected true for %q", s)
		}
	}
	r67TPAssertErrScripts(t, nil, nil, []string{
		`Character.toChars(-1)`,
		`Character.toString(-1)`,
		`Character.codePointAt("hi", 99)`,
		`Character.codePointBefore("hi", 0)`,
		`Character.codePointCount("hi", 2, 1)`,
		`Arrays.mismatch(null, [1])`,
		`Arrays.mismatch([1], null)`,
		`Arrays.compare(null, 0, 1, [1], 0, 1)`,
		`Arrays.compare([1], 0, 1, null, 0, 1)`,
		`Arrays.compare([1], ` + bad + `)`,
	})
}

func TestRound67TopUpPainless_StreamsCollectorsMapComputeAndWrappers(t *testing.T) {
	bad := `Integer.parseInt("bad")`
	// 1. Stream pipelines, Optional chaining, Collectors, Map compute/merge, forEach, replaceAll
	streamAndMapScripts := []string{
		`doc.tags.stream().collect(Collectors.toList()).size() == 2`,
		`OptionalInt.of(5).stream().map(x -> x * 2).findFirst().orElse(0) == 10`,
		`OptionalLong.of(5L).stream().findFirst().getAsLong() == 5L`,
		`OptionalDouble.of(2.5).stream().findFirst().getAsDouble() == 2.5`,
		`Optional.empty().stream().map(x -> x + 1).filter(x -> true).count() == 0`,
		`Optional.empty().or(() -> Optional.of(42)).orElseGet(() -> 99) == 42`,
		`Optional.of(5).stream().findFirst().filter(x -> x > 10).orElse(7) == 7`,
		`def seen = 0; Optional.of(5).stream().findFirst().ifPresent(x -> { seen = x; }); return seen == 5;`,
		`def seen = 0; Optional.empty().stream().findFirst().ifPresentOrElse(x -> { seen = 1; }, () -> { seen = 2; }); return seen == 2;`,
		`def seen = 0; Optional.of(3).stream().findFirst().ifPresentOrElse(x -> { seen = x; }, () -> { seen = -1; }); return seen == 3;`,
		`Optional.of(5).stream().findFirst().isPresent() && !Optional.empty().stream().findFirst().isPresent() && Optional.empty().stream().findFirst().isEmpty()`,
		`Optional.of(4).stream().findFirst().stream().count() == 1`,
		`["a", "ab", "b"].stream().collect(Collectors.toMap(s -> s.length(), s -> s, (a, b) -> a + "," + b)).size() == 2`,
		`["a", "ab"].stream().collect(Collectors.toUnmodifiableMap(s -> s.length(), s -> s)).size() == 2`,
		`["a", "aa", "b"].stream().collect(Collectors.groupingBy(s -> s.length(), Collectors.counting())).size() == 2`,
		`[1, 2, 3, 4].stream().collect(Collectors.partitioningBy(x -> x % 2 == 0, Collectors.counting()))["true"] == 2`,
		`[1, 2, 3].stream().collect(Collectors.summarizingInt(x -> x)).getSum() == 6`,
		`[1, 2, 3].stream().collect(Collectors.summarizingLong(x -> x)).getCount() == 3`,
		`[1.0, 2.0].stream().collect(Collectors.summarizingDouble(x -> x)).getAverage() == 1.5`,
		`[1, 2, 3].stream().collect(Collectors.collectingAndThen(Collectors.toList(), l -> l.size())) == 3`,
		`[1, 2, 3].stream().collect(Collectors.reducing((a, b) -> a + b)).get() == 6`,
		`[1, 2, 3].stream().reduce(Integer::sum).get() == 6`,
		`[1, null, 2].stream().filter(Objects::nonNull).collect(Collectors.mapping(String::valueOf, Collectors.toList())).size() == 2`,
		`["a", "b"].stream().reduce(String::concat).get() == "ab"`,
		`Optional.empty().orElseGet(StringBuilder::new) != null`,
		`[1, 2, 3].stream().collect(Collectors.reducing(10, x -> x * 2, (a, b) -> a + b)) == 22`,
		`["a", "bb"].stream().collect(Collectors.mapping(s -> s.length(), Collectors.toList())).size() == 2`,
		`IntStream.range(1, 5).takeWhile(x -> x < 4).dropWhile(x -> x < 2).peek(x -> {}).limit(10).skip(0).summaryStatistics().getSum() == 5`,
		`def m = ["a": 1]; m.computeIfAbsent("b", k -> 2); m.compute("a", (k, v) -> v + 10); m.compute("z", (k, v) -> null); m.merge("a", 5, (v1, v2) -> v1 + v2); m.merge("c", 7, (v1, v2) -> null); m.merge("a", 1, (v1, v2) -> null); return !m.containsKey("a") && m["b"] == 2 && m["c"] == 7;`,
		`def total = 0; ["a": 1, "b": 2].forEach((k, v) -> { if (k == "a") { return; } total += v; }); return total == 2;`,
		`def sum = 0; doc.tags.forEach(t -> { sum++; }); return sum == 2;`,
		`def l = [1, 2]; l.replaceAll(x -> x * 3); return l[1] == 6;`,
		`ctx._source.tags.replaceAll(t -> t.toUpperCase()); return ctx._source.tags[0] == "T1";`,
	}
	for _, s := range streamAndMapScripts {
		docMap := map[string]any{"tags": []any{"t1", "t2"}}
		v, err := Eval(docMap, s, r67TPMappedParams())
		if err != nil {
			t.Fatalf("stream/map script %q failed: %v", s, err)
		}
		if b, ok := v.(bool); ok && !b {
			t.Fatalf("expected true for %q", s)
		}
	}

	r67TPAssertErrScripts(t, map[string]any{"tags": []any{"a"}}, r67TPMappedParams(), []string{
		`["a", "b"].stream().collect(Collectors.toMap(s -> 1, s -> s))`,
		`["a", "b"].stream().collect(Collectors.toUnmodifiableMap(s -> 1, s -> s, (x, y) -> null))`,
		`[null].stream().collect(Collectors.toUnmodifiableMap(x -> x, x -> 1))`,
		`[1].stream().collect(Collectors.toMap(x -> x, x -> null))`,
		`[1].stream().collect(Collectors.toMap(x -> ` + bad + `, x -> 1))`,
		`[1].stream().collect(Collectors.toMap(x -> 1, x -> ` + bad + `))`,
		`["a", "b"].stream().collect(Collectors.toMap(x -> 1, x -> 1, (a, b) -> ` + bad + `))`,
		`[null].stream().collect(Collectors.groupingBy(x -> x))`,
		`[1].stream().collect(Collectors.groupingBy(x -> ` + bad + `))`,
		`[1].stream().collect(Collectors.partitioningBy(x -> ` + bad + ` > 0))`,
		`[1].stream().collect(Collectors.reducing(0, x -> ` + bad + `, (a, b) -> a + b))`,
		`[1, 2].stream().collect(Collectors.reducing(0, (a, b) -> ` + bad + `))`,
		`[1].stream().collect(Collectors.mapping(x -> ` + bad + `, Collectors.toList()))`,
		`Optional.empty().stream().findFirst().orElse(` + bad + `)`,
		`Optional.empty().stream().findFirst().orElseThrow()`,
		`Optional.empty().stream().findFirst().orElseThrow(() -> new IllegalStateException("nope"))`,
		`Optional.empty().stream().findFirst().get()`,
		`[1].stream().filter(x -> ` + bad + ` > 0).toList()`,
		`[1].stream().takeWhile(x -> ` + bad + ` > 0).toList()`,
		`[1].stream().dropWhile(x -> ` + bad + ` > 0).toList()`,
		`[1].stream().map(x -> ` + bad + `).toList()`,
		`[1].stream().flatMap(x -> ` + bad + `).toList()`,
		`def m = ["a": 1]; m.computeIfAbsent("b", k -> ` + bad + `);`,
		`def m = ["a": 1]; m.compute("a", (k, v) -> ` + bad + `);`,
		`def m = ["a": 1]; m.merge("a", 1, (x, y) -> ` + bad + `);`,
		`[1].forEach(x -> { throw new IllegalStateException("boom"); });`,
		`[1].replaceAll(x -> ` + bad + `);`,
	})

	// 2. Round54 equals, ValueRange, Optional, URI, URL, Locale
	vr := newFixedValueRangePainless(1, 10)
	if res, handled, err := evalRound54ParamMethodPreArgPainless(".equals(", "vr", vr, "vr2", nil, map[string]any{"vr2": vr}, 0); !handled || err != nil || res != true {
		t.Fatalf("ValueRange.equals failed: %v %v %v", res, handled, err)
	}
	if res, handled, err := evalRound54ParamMethodPreArgPainless(".isValidValue(", "vr", vr, "5", nil, nil, 0); !handled || err != nil || res != true {
		t.Fatalf("ValueRange.isValidValue failed: %v %v %v", res, handled, err)
	}
	if res, handled, err := evalRound54ParamMethodPreArgPainless(".isValidIntValue(", "vr", vr, `"bad"`, nil, nil, 0); !handled || err != nil || res != false {
		t.Fatalf("ValueRange.isValidIntValue failed: %v %v %v", res, handled, err)
	}
	round54Scripts := []string{
		`class EqBox { int x = 1; boolean equals(Object o) { return o != null; } } def a = new EqBox(); return a.equals(a);`,
		`OptionalInt.empty().orElse("5") == 5 && OptionalInt.empty().orElseGet(() -> "6") == 6`,
		`Optional.empty().or(() -> Optional.of(9)).get() == 9 && Optional.empty().or(() -> 11).get() == 11`,
		`def r = 0; Optional.of(5).ifPresent(x -> { r = x; }); Optional.empty().ifPresentOrElse(x -> {}, () -> { r += 2; }); return r == 7;`,
		`Optional.of(5).filter(x -> x > 10).isEmpty() && Optional.of(5).flatMap(x -> Optional.empty()).isEmpty() && Optional.of(5).flatMap(x -> Optional.of(8)).get() == 8`,
		`def st = new IntSummaryStatistics(2, 1, 5, 6); return st.getCount() == 2 && st.getAverage() == 3.0;`,
		`def u1 = new URI("https", "example.com", "/path", "frag"); def u3 = new URI("mailto", "user@example.com", null); def u5 = new URI("https", "example.com", "/p", "q=1", "f"); return u1 != null && u3 != null && u5 != null;`,
		`def base = new URL("https://example.com/a/b"); def rel = new URL(base, "c"); def u3 = new URL("https", "example.com", "page"); def u4 = new URL("https", "example.com", 8443, "page"); return rel.toString() != "" && u3 != null && u4 != null;`,
		`new Locale("en") == "en" && new Locale("en", "US") == "en_US"`,
	}
	for _, s := range round54Scripts {
		if _, err := Eval(nil, s, nil); err != nil {
			t.Fatalf("round54 script %q failed: %v", s, err)
		}
	}
	r67TPAssertErrScripts(t, nil, nil, []string{
		`new IntSummaryStatistics(1)`,
		`new URI(null)`,
		`new URI("https", "example.com", "rel", null)`,
		`new URI("https", "example.com", "rel", null, null)`,
		`new URL(null)`,
		`new Locale(null)`,
		`new Locale("en", null)`,
		`Optional.empty().or(() -> null)`,
		`Optional.of(1).equals(` + bad + `)`,
		`OffsetTime.parse("10:15:30+01:00").equals(` + bad + `)`,
		`Clock.systemUTC().equals(` + bad + `)`,
		`new URI("https://example.com").equals(` + bad + `)`,
		`new URL("https://example.com").equals(` + bad + `)`,
	})

	// 3. FieldVal & DenseVectorFieldVal / DenseVectorVal & evalJavaTimeFactoryRound58
	srcDoc := map[string]any{
		"num":  []any{"10", "20"},
		"dt":   []any{"2026/01/15"},
		"geo":  []any{"41.12,-71.34"},
		"move": "hello",
		"dst":  "existing",
	}
	fvParams := r67TPMappedParams()
	fvNum := &FieldVal{Name: "num", Values: []any{"10", "20"}, Root: srcDoc, Params: fvParams, FieldType: "long"}
	fvEmpty := &FieldVal{Name: "empty", Values: []any{}, Root: srcDoc, Params: fvParams}
	fvDate := &FieldVal{Name: "created", Values: []any{"2026/01/15"}, Root: srcDoc, Params: fvParams, FieldType: "date"}
	fvBadDate := &FieldVal{Name: "created", Values: []any{"not-a-date"}, Root: srcDoc, Params: fvParams, FieldType: "date"}
	fvGeo := &FieldVal{Name: "loc", Values: []any{"41.12,-71.34"}, Root: srcDoc, Params: fvParams, FieldType: "geo_point"}
	fvBadGeo := &FieldVal{Name: "loc", Values: []any{"not-a-geo"}, Root: srcDoc, Params: fvParams, FieldType: "geo_point"}
	fvMove := &FieldVal{Name: "move", Values: []any{"hello"}, Root: srcDoc, Params: fvParams}
	fvDst := &FieldVal{Name: "dst", Values: []any{"existing"}, Root: srcDoc, Params: fvParams}

	noArgs := func() ([]any, error) { return nil, nil }
	oneArg := func(v any) func() ([]any, error) { return func() ([]any, error) { return []any{v}, nil } }
	twoArgs := func(a, b any) func() ([]any, error) { return func() ([]any, error) { return []any{a, b}, nil } }

	for _, call := range []struct {
		fv   *FieldVal
		m    string
		args func() ([]any, error)
	}{
		{fvNum, "get", noArgs},
		{fvNum, "get", oneArg(int64(99))},
		{fvNum, "get", twoArgs(int64(5), int64(99))},
		{fvNum, "getValue", noArgs},
		{fvEmpty, "getValue", noArgs},
		{fvEmpty, "getValue", oneArg(int64(7))},
		{fvNum, "getValue", twoArgs(int64(5), int64(7))},
		{fvNum, "getValues", noArgs},
		{fvNum, "asBigInteger", noArgs},
		{fvEmpty, "asBigInteger", noArgs},
		{fvEmpty, "asBigInteger", oneArg("12")},
		{fvNum, "asBigInteger", twoArgs(int64(5), "12")},
		{fvNum, "asBigInteger", twoArgs(int64(0), "12")},
		{fvNum, "asLong", noArgs},
		{fvDate, "asDate", noArgs},
		{fvEmpty, "asDate", noArgs},
		{fvEmpty, "asDate", oneArg("def")},
		{fvDate, "asDate", twoArgs(int64(5), "def")},
		{fvGeo, "asGeoPoint", noArgs},
		{fvEmpty, "asGeoPoint", noArgs},
		{fvEmpty, "asGeoPoint", oneArg("def")},
		{fvGeo, "asGeoPoint", twoArgs(int64(5), "def")},
		{fvNum, "asString", noArgs},
		{fvEmpty, "asString", noArgs},
		{fvEmpty, "asString", oneArg(nil)},
		{fvEmpty, "asString", oneArg("def")},
		{fvNum, "asString", twoArgs(int64(5), nil)},
		{fvNum, "asString", twoArgs(int64(5), "def")},
		{fvNum, "set", oneArg("30")},
		{fvNum, "append", oneArg("40")},
		{fvMove, "move", oneArg(fvDst)},
		{fvMove, "overwrite", oneArg(fvDst)},
	} {
		if _, handled, err := evalFieldValMethodRound60(call.fv, call.m, "", call.args, srcDoc, fvParams, 0); !handled || err != nil {
			t.Fatalf("FieldVal.%s failed: handled=%v err=%v", call.m, handled, err)
		}
	}
	if _, _, err := evalFieldValMethodRound60(fvBadDate, "asDate", "", noArgs, srcDoc, fvParams, 0); err == nil {
		t.Fatal("expected error on fvBadDate.asDate()")
	}
	if _, _, err := evalFieldValMethodRound60(fvBadDate, "asDate", "", twoArgs(int64(0), "def"), srcDoc, fvParams, 0); err == nil {
		t.Fatal("expected error on fvBadDate.asDate(0, def)")
	}
	if _, _, err := evalFieldValMethodRound60(fvBadGeo, "asGeoPoint", "", noArgs, srcDoc, fvParams, 0); err == nil {
		t.Fatal("expected error on fvBadGeo.asGeoPoint()")
	}
	if _, _, err := evalFieldValMethodRound60(fvBadGeo, "asGeoPoint", "", twoArgs(int64(0), "def"), srcDoc, fvParams, 0); err == nil {
		t.Fatal("expected error on fvBadGeo.asGeoPoint(0, def)")
	}

	// DenseVectorFieldVal & DenseVectorVal
	dvVal := &DenseVectorVal{Name: "vec", ElemType: "float", Floats: []float32{3, -4}, Present: true}
	dvField := &DenseVectorFieldVal{Name: "vec", ElemType: "float", Present: true, Vec: dvVal}
	dvEmptyField := &DenseVectorFieldVal{Name: "vec", ElemType: "float", Present: false}
	dvBit := &DenseVectorVal{Name: "bvec", ElemType: "bit", Floats: []float32{1, 0}, Bytes: []int8{0x0F}, Present: true}
	dvMissingDV := &DenseVectorVal{Name: "vec", ElemType: "float", Present: false, IsDocValue: true}
	for _, m := range []string{"isEmpty", "size", "getDims", "getVector", "getMagnitude", "get", "l1Norm", "l2Norm"} {
		if _, handled, err := evalDenseVectorMethodRound61(dvField, m, nil, nil, nil, 0); !handled || err != nil {
			t.Fatalf("dvField.%s failed: handled=%v err=%v", m, handled, err)
		}
		if _, handled, err := evalDenseVectorMethodRound61(dvVal, m, nil, nil, nil, 0); !handled || err != nil {
			t.Fatalf("dvVal.%s failed: handled=%v err=%v", m, handled, err)
		}
	}
	_, _, _ = evalDenseVectorMethodRound61(dvEmptyField, "get", nil, nil, nil, 0)
	_, _, _ = evalDenseVectorMethodRound61(dvEmptyField, "get", []string{"null"}, nil, nil, 0)
	_, _, _ = evalDenseVectorMethodRound61(dvEmptyField, "get", []string{"0", "0.0"}, nil, nil, 0)
	_, _, _ = evalDenseVectorMethodRound61(dvField, "get", []string{"0"}, nil, nil, 0)
	_, _, _ = evalDenseVectorMethodRound61(dvField, "get", []string{"0", "[1.0, 2.0]"}, nil, nil, 0)
	_, _, _ = evalDenseVectorMethodRound61(dvField, "get", []string{"9", "0.5"}, nil, nil, 0)
	_, _, _ = evalDenseVectorMethodRound61(dvBit, "l1Norm", nil, nil, nil, 0)
	if _, _, err := evalDenseVectorMethodRound61(dvField, "iterator", nil, nil, nil, 0); err == nil {
		t.Fatal("expected UnsupportedOperationException for dvField.iterator()")
	}
	if _, _, err := evalDenseVectorMethodRound61(dvMissingDV, "getDims", nil, nil, nil, 0); err == nil {
		t.Fatal("expected missing vector error for dvMissingDV.getDims()")
	}
	if _, _, err := evalDenseVectorMethodRound61(dvVal, "get", []string{"99"}, nil, nil, 0); err == nil {
		t.Fatal("expected IndexOutOfBoundsException for dvVal.get(99)")
	}

	// evalJavaTimeFactoryRound58 coverage
	jtScripts := []string{
		`Year.of(2026).getValue() == 2026 && YearMonth.of(2026, 3) == "2026-03" && MonthDay.of(3, 15) != null && Month.of(3) == "MARCH" && DayOfWeek.of(3) == "WEDNESDAY"`,
		`LocalDate.of(2026, 3, 15) == "2026-03-15" && LocalDate.ofYearDay(2026, 32) == "2026-02-01"`,
		`LocalTime.of(10, 20) == "10:20" && LocalTime.of(10, 20, 30) == "10:20:30" && LocalTime.of(10, 20, 30, 500) != ""`,
		`LocalTime.ofSecondOfDay(3661) == "01:01:01" && LocalTime.ofNanoOfDay(1000000000L) == "00:00:01"`,
		`LocalDateTime.of(LocalDate.of(2026, 1, 2), LocalTime.of(3, 4)) != "" && LocalDateTime.of(2026, 1, 2, 3, 4, 5, 6) != ""`,
		`ZonedDateTime.of(LocalDateTime.of(2026, 1, 2, 3, 4), "UTC") != "" && ZonedDateTime.of(LocalDate.of(2026, 1, 2), LocalTime.of(3, 4), "UTC") != ""`,
		`OffsetDateTime.of(LocalDateTime.of(2026, 1, 2, 3, 4), "+02:00") != "" && OffsetDateTime.of(2026, 1, 2, 3, 4, 5, 0, "+02:00") != ""`,
	}
	for _, s := range jtScripts {
		v, err := Eval(nil, s, nil)
		if err != nil {
			t.Fatalf("java.time factory script %q failed: %v", s, err)
		}
		if b, ok := v.(bool); ok && !b {
			t.Fatalf("expected true for %q", s)
		}
	}
	r67TPAssertErrScripts(t, nil, nil, []string{
		`Year.of(null)`,
		`Year.of("bad")`,
		`YearMonth.of(2026, null)`,
		`YearMonth.of(2026, 13)`,
		`DayOfWeek.of(9)`,
		`LocalDate.of(2026, 2, 30)`,
		`LocalDate.ofYearDay(2025, 366)`,
		`LocalTime.of(10)`,
		`LocalTime.ofSecondOfDay(90000)`,
		`LocalTime.ofNanoOfDay(-1)`,
		`LocalDateTime.of(null, LocalTime.of(1, 2))`,
		`LocalDateTime.of("bad", "bad")`,
		`ZonedDateTime.of(null, "UTC")`,
		`ZonedDateTime.of("bad", "UTC")`,
		`OffsetDateTime.of(LocalDateTime.of(2026, 1, 2, 3, 4), "Invalid/Zone")`,
	})
	_ = math.NaN()
	_ = big.NewInt(1)
}
