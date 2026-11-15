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
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestRound60CoverageCycleCloneFormatEqualsAndHash(t *testing.T) {
	t.Run("ContainerNodeKeysAndAcyclicWalk", func(t *testing.T) {
		var nilMap map[string]any
		var nilTypedMap map[string]string
		var nilSlice []any
		var nilIntSlice []int
		if _, ok := containerNodeKeyRound60(nil); ok {
			t.Fatal("expected false for nil")
		}
		if _, ok := containerNodeKeyRound60(nilMap); ok {
			t.Fatal("expected false for nil map[string]any")
		}
		if _, ok := containerNodeKeyRound60([]any{}); ok {
			t.Fatal("expected false for empty []any")
		}
		if _, ok := containerNodeKeyRound60(nilSlice); ok {
			t.Fatal("expected false for nil []any")
		}
		var nilUserObj *painlessUserObject
		if _, ok := containerNodeKeyRound60(nilUserObj); ok {
			t.Fatal("expected false for nil *painlessUserObject")
		}
		if _, ok := containerNodeKeyRound60(nilTypedMap); ok {
			t.Fatal("expected false for nil reflect.Map")
		}
		if _, ok := containerNodeKeyRound60(map[string]string{"a": "b"}); !ok {
			t.Fatal("expected true for non-nil reflect.Map")
		}
		if _, ok := containerNodeKeyRound60(nilIntSlice); ok {
			t.Fatal("expected false for empty reflect.Slice")
		}
		if _, ok := containerNodeKeyRound60([]int{1, 2}); !ok {
			t.Fatal("expected true for non-empty reflect.Slice")
		}
		if _, ok := containerNodeKeyRound60(42); ok {
			t.Fatal("expected false for scalar int")
		}

		if err := validateAcyclicWalkRound60(map[string]any{"a": 1}, make(map[cycleNodeKeyRound60]bool), 513); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected depth overflow cycle error, got %v", err)
		}

		optEmpty, err := Eval(nil, "return Optional.empty();", nil)
		if err != nil {
			t.Fatalf("Optional.empty eval failed: %v", err)
		}
		if err := ValidateAcyclicValue(optEmpty); err != nil {
			t.Fatalf("unexpected error on empty optional: %v", err)
		}

		cycMap := map[string]any{}
		cycMap["self"] = cycMap
		optCyc := &painlessOptional{present: true, val: cycMap}
		if err := ValidateAcyclicValue(optCyc); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected cycle error inside Optional, got %v", err)
		}
		var nilOpt *painlessOptional
		if err := ValidateAcyclicValue(nilOpt); err != nil {
			t.Fatalf("unexpected error on nil *painlessOptional: %v", err)
		}

		withMeta := map[string]any{
			"__internal":   cycMap,
			"__parent_map": cycMap,
			"bytes":        []byte{1, 2, 3},
			"floats":       []float64{1.5, 2.5},
			"typed_map":    map[int]any{1: "ok"},
			"typed_slice":  []string{"x", "y"},
		}
		if err := ValidateAcyclicValue(withMeta); err != nil {
			t.Fatalf("unexpected error on acyclic typed containers: %v", err)
		}
		badTypedMap := map[int]any{1: cycMap}
		if err := ValidateAcyclicValue(badTypedMap); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected cycle error on reflect.Map, got %v", err)
		}
		badTypedSlice := []map[string]any{cycMap}
		if err := ValidateAcyclicValue(badTypedSlice); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected cycle error on reflect.Slice, got %v", err)
		}

		userCyc, err := Eval(nil, "class Box { def child; } Box b = new Box(); b.child = b; return b;", nil)
		if err != nil {
			t.Fatalf("user class eval failed: %v", err)
		}
		if err := ValidateAcyclicValue(userCyc); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected cycle error on cyclic user object, got %v", err)
		}
		_ = FormatValueSafe(map[string]any{"u": userCyc, "u2": userCyc})
	})

	t.Run("CloneValueWalkAllTypes", func(t *testing.T) {
		if _, err := cloneValueWalkRound60("x", make(map[cycleNodeKeyRound60]bool), 513); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected depth overflow error, got %v", err)
		}
		var nilOpt *painlessOptional
		var nilZDT *ZonedDateTimeVal
		var nilGP *GeoPointVal
		var nilBR *BytesRefVal
		var nilBB *ByteBufferVal
		now := time.Date(2024, 5, 10, 14, 20, 30, 123456789, time.UTC)
		src := map[string]any{
			"__hidden": "skip",
			"opt_nil":  nilOpt,
			"opt_emp":  &painlessOptional{present: false},
			"opt_val":  &painlessOptional{present: true, val: []float64{1.25, 2.5}},
			"zdt":      &ZonedDateTimeVal{Time: now, IsNano: true},
			"zdt_nil":  nilZDT,
			"gp":       &GeoPointVal{Lat: 37.77, Lon: -122.41},
			"gp_nil":   nilGP,
			"br":       newBytesRefValRound60([]byte("hello")),
			"br_nil":   nilBR,
			"bb":       newByteBufferValRound60([]byte("world")),
			"bb_nil":   nilBB,
			"arr":      []any{"a", int64(7)},
		}
		clonedRaw, err := CloneValueCycleSafe(src)
		if err != nil {
			t.Fatalf("CloneValueCycleSafe failed: %v", err)
		}
		cloned := clonedRaw.(map[string]any)
		if _, exists := cloned["__hidden"]; exists {
			t.Fatal("expected internal __hidden key to be skipped")
		}
		if len(cloned["opt_val"].([]float64)) != 2 {
			t.Fatalf("unexpected cloned float64 slice: %#v", cloned["opt_val"])
		}

		cyc := map[string]any{}
		cyc["self"] = []any{cyc}
		if _, err := CloneValueCycleSafe(cyc); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected cycle error on nested slice/map, got %v", err)
		}
	})

	t.Run("FormatValueAndArraysCycleSafe", func(t *testing.T) {
		var (
			nilOpt    *painlessOptional
			nilZDT    *ZonedDateTimeVal
			nilInst   *InstantVal
			nilDOW    *DayOfWeekEnum
			nilGP     *GeoPointVal
			nilBR     *BytesRefVal
			nilBB     *ByteBufferVal
			nilFV     *FieldVal
			nilLambda *PainlessLambda
			nilArr    []any
			nilMap    map[string]any
			nilUObj   *painlessUserObject
		)
		dow := DayOfWeekEnum{Value: 3, NameStr: "WEDNESDAY"}
		ts := time.Date(2024, 6, 1, 8, 9, 10, 500, time.UTC)
		vals := []any{
			nil,
			painlessEmptyOptional,
			nilOpt,
			&painlessOptional{present: true, val: "inner"},
			math.NaN(),
			math.Inf(1),
			math.Inf(-1),
			float64(3.5),
			float32(math.NaN()),
			float32(math.Inf(1)),
			float32(math.Inf(-1)),
			float32(2.25),
			90 * time.Second,
			nilZDT,
			&ZonedDateTimeVal{Time: ts, IsNano: true},
			nilInst,
			&InstantVal{Time: ts},
			dow,
			nilDOW,
			&dow,
			nilGP,
			&GeoPointVal{Lat: 10.5, Lon: 20.5},
			nilBR,
			newBytesRefValRound60([]byte{0xde, 0xad}),
			nilBB,
			newByteBufferValRound60([]byte("abc")),
			nilFV,
			&FieldVal{Name: "f", Values: []any{1, 2}},
			nilLambda,
			&PainlessLambda{ParamNames: []string{"x"}, Body: "x + 1"},
			&PainlessLambda{MethodRef: "String::valueOf"},
			[]float64{1.0, 2.0},
			nilArr,
			nilMap,
			nilUObj,
			map[string]any{"__exc_type": "IllegalArgumentException", "message": "bad"},
			map[string]any{"__exc_type": "NullPointerException"},
		}
		for _, v := range vals {
			_ = FormatValueSafe(v)
		}
		if got := formatValueCycleWalkRound60("deep", make(map[cycleNodeKeyRound60]bool), true, 65); got != "..." {
			t.Fatalf("expected '...' at depth 65, got %q", got)
		}
		braceStr := formatValueCycleWalkRound60(map[string]any{"k": "v"}, make(map[cycleNodeKeyRound60]bool), true, 0)
		if braceStr != "{k=v}" {
			t.Fatalf("expected Java brace map {k=v}, got %q", braceStr)
		}

		cycSlice := make([]any, 1)
		cycSlice[0] = cycSlice
		if got := FormatValueSafe(cycSlice); !strings.Contains(got, "(this Collection)") {
			t.Fatalf("expected (this Collection), got %q", got)
		}
		if got := formatArraysToStringCycleSafeRound60(nil, false); got != "null" {
			t.Fatalf("expected null, got %q", got)
		}
		if got := formatArraysToStringWalkRound60(nil, false, make(map[cycleNodeKeyRound60]bool), 0); got != "null" {
			t.Fatalf("expected null, got %q", got)
		}
		if got := formatArraysToStringWalkRound60([]any{1}, false, make(map[cycleNodeKeyRound60]bool), 65); got != "[...]" {
			t.Fatalf("expected [...], got %q", got)
		}
		arrWithNilAndCycle := []any{nil, cycSlice}
		_ = formatArraysToStringCycleSafeRound60(cycSlice, false)
		_ = formatArraysToStringCycleSafeRound60(cycSlice, true)
		_ = formatArraysToStringCycleSafeRound60(arrWithNilAndCycle, true)

		statsVal, err := Eval(nil, "return [1, 2, 3].stream().mapToInt(x -> x).summaryStatistics().toString();", nil)
		if err != nil || statsVal == nil {
			t.Fatalf("summaryStatistics eval failed: %v", err)
		}
	})

	t.Run("EqualityAndHashCodes", func(t *testing.T) {
		eqFn := func(a, b any, seen map[cyclePairKeyRound60]bool, depth int) bool {
			return a == b
		}
		s1 := []any{1, 2}
		s2 := []any{1, 2}
		s3 := []any{1, 3}
		if slicesEqualCycleSafeRound60(s1, []any{1}, eqFn, nil, 0) {
			t.Fatal("expected unequal length slices to be false")
		}
		if !slicesEqualCycleSafeRound60(s1, s2, eqFn, nil, 65) {
			t.Fatal("expected true beyond max depth")
		}
		if !slicesEqualCycleSafeRound60(s1, s1, eqFn, nil, 0) {
			t.Fatal("expected identical slice pointer to be true")
		}
		if slicesEqualCycleSafeRound60(s1, s3, eqFn, nil, 0) {
			t.Fatal("expected differing slices to be false")
		}

		m1 := map[string]any{"a": 1, "__meta": "ignore"}
		m2 := map[string]any{"a": 1}
		m3 := map[string]any{"a": 2}
		if mapsEqualCycleSafeRound60(m1, map[string]any{"a": 1, "b": 2}, eqFn, nil, 0) {
			t.Fatal("expected unequal map len to be false")
		}
		if !mapsEqualCycleSafeRound60(m1, m2, eqFn, nil, 65) {
			t.Fatal("expected true beyond max depth")
		}
		if !mapsEqualCycleSafeRound60(m1, m1, eqFn, nil, 0) {
			t.Fatal("expected same map pointer to be true")
		}
		if !mapsEqualCycleSafeRound60(m1, m2, eqFn, nil, 0) {
			t.Fatal("expected equal visible map entries to be true")
		}
		if mapsEqualCycleSafeRound60(m1, m3, eqFn, nil, 0) {
			t.Fatal("expected differing map entries to be false")
		}

		optVal, _ := Eval(nil, "return Optional.of('abc');", nil)
		offTimeVal, _ := Eval(nil, "return OffsetTime.parse('10:15:30+01:00');", nil)
		clockVal, _ := Eval(nil, "return Clock.systemUTC();", nil)
		uriVal, _ := Eval(nil, "return new URI('https://example.com/a');", nil)
		urlVal, _ := Eval(nil, "return new URL('https://example.com/a');", nil)

		var nilDOW *DayOfWeekEnum
		var nilZDT *ZonedDateTimeVal
		var nilGP *GeoPointVal
		dow := DayOfWeekEnum{Value: 5, NameStr: "FRIDAY"}
		zdt := &ZonedDateTimeVal{Time: time.UnixMilli(1700000000000).UTC()}
		gp := &GeoPointVal{Lat: 40.7128, Lon: -74.0060}

		hashInputs := []any{
			optVal,
			offTimeVal,
			clockVal,
			uriVal,
			urlVal,
			dow,
			nilDOW,
			&dow,
			nilZDT,
			zdt,
			nilGP,
			gp,
			true,
			false,
			int(123),
			int32(456),
			int64(7890123456789),
			float64(3.14159),
			math.NaN(),
			"hello",
			struct{ X int }{X: 9},
		}
		for _, in := range hashInputs {
			_ = computeJavaHashCodeScalarRound60(in)
			_ = computeJavaHashCodeCycleSafeRound60(in, nil, 0)
		}
		if got := computeJavaHashCodeCycleSafeRound60("x", nil, 65); got != 0 {
			t.Fatalf("expected 0 at depth > 64, got %d", got)
		}
		cycArr := make([]any, 1)
		cycArr[0] = cycArr
		_ = evalArraysHashCodeCycleSafeRound60(nil, true, nil, nil, 0, nil)
		_ = evalArraysHashCodeCycleSafeRound60("not-array", false, nil, nil, 0, nil)
		_ = evalArraysHashCodeCycleSafeRound60([]any{[]any{int64(1), int64(2)}, cycArr}, true, nil, nil, 0, nil)

		// Exercise syncSliceHeaderAliasesRound60 branches
		syncSliceHeaderAliasesRound60(nil, []any{}, []any{1})
		oldS := make([]any, 1, 4)
		oldS[0] = "x"
		newS := append(oldS, "y")
		rootAlias := map[string]any{
			"__skip": oldS,
			"direct": oldS,
			"nested": []any{oldS, map[string]any{"leaf": oldS}},
		}
		syncSliceHeaderAliasesRound60(rootAlias, oldS, newS)
	})
}

func TestRound60CoverageCompileValidateAndUpdateCtx(t *testing.T) {
	var nilCompErr *ScriptCompileError
	if nilCompErr.Error() != "" {
		t.Fatalf("expected empty string on nil ScriptCompileError")
	}
	ce1 := newScriptCompileErrorAtRound60("line1\n0123456789abcdefghijklmnopqrstuvwxyz0123456789\nline3", -5, "bad token")
	if !strings.Contains(ce1.Error(), "compile error:") || ce1.Position == nil {
		t.Fatalf("unexpected compile error formatting: %#v", ce1)
	}
	ce2 := newScriptCompileErrorAtRound60("line1\n0123456789abcdefghijklmnopqrstuvwxyz0123456789\nline3", 35, "compile error: mid line")
	if ce2.Position.Start == 0 {
		t.Fatalf("expected clamped multiline start > 0, got %#v", ce2.Position)
	}
	_ = newScriptCompileErrorAtRound60("short", 999, "past end")

	validScripts := []string{
		"",
		"   ",
		"// comment only\n/* block comment */",
		`class Helper { int x; } List<String>[] makeArr(java.util.List items, Map<String, List<Integer>> m, int[] nums) { return null; } return 1;`,
		`int zeroArg() { return 7; } return zeroArg();`,
		`def s = """hello \"world\" line"""; return s;`,
		`def r = /[a-z\/]+/i; return r != null;`,
		`int a = 0x1A_F; int b = 0b1010_01; double c = 1.5e-2d; long d = 42L; a >>>= 1; return a + b + (int)c + (int)d;`,
		`try { int x = 1; } catch (IllegalArgumentException | NullPointerException e) { return 0; } return 1;`,
		`int i = 0; while (true) { i++; if (i > 2) break; } for (;;) { return i; }`,
		`boolean cond = true; if (cond) String s = "ok"; return 1;`,
		`Supplier f = String::new; Predicate p = x -> x != null; return p.test(f);`,
		`Map m = ['a': 1]; return m?.a;`,
	}
	for _, src := range validScripts {
		if err := CompileValidate(src); err != nil {
			t.Fatalf("expected valid script %q, got error: %v", src, err)
		}
	}

	invalidScripts := []string{
		"/* unclosed comment",
		`"""unclosed text block`,
		`'unclosed single quote`,
		"'newline\nin string'",
		`'trailing backslash\`,
		"(1 + 2]",
		"[1, 2)",
		"{ int x = 1; )",
		"1 + 2)",
		"(1 + 2",
		"1.2e+",
		"123abc",
		"$$$",
		"@invalid",
		"* 2",
		"1 +",
		"if x { return 1; }",
		"if () { return 1; }",
		"def[] = 1;",
		"def 123 = 1;",
		"int x = 1 + ;",
		"int x = 1 + * 2;",
		"int x = (* 2);",
		"UnknownBogusType x = 1;",
		"UnknownReturnType foo() { return null; }",
		"int foo(onlyname) { return 1; }",
		"int foo(UnknownParamType x) { return 1; }",
		"int foo(int return) { return 1; }",
		"int dup(int a) { return a; } int dup(int b) { return b; }",
		"while (true) { int x = 1; }",
		"while (true) x = 1;",
		"for (;;) { int y = 2; }",
		"for (;;) y = 2;",
	}
	for _, src := range invalidScripts {
		if err := CompileValidate(src); err == nil {
			t.Fatalf("expected compile error for invalid script %q, got nil", src)
		}
	}

	t.Run("ValidateUpdateCtxMutations", func(t *testing.T) {
		if err := ValidateUpdateCtxMutations("1", nil); err != nil {
			t.Fatalf("expected nil on nil map, got %v", err)
		}
		if err := ValidateUpdateCtxMutations("1", map[string]any{
			"_id":         "1",
			"op":          "noop",
			"_source":     map[string]any{"a": 1},
			"__internal":  true,
			"_ctx_helper": true,
		}); err != nil {
			t.Fatalf("unexpected valid ctx error: %v", err)
		}
		if err := ValidateUpdateCtxMutations("1", map[string]any{"_id": "2"}); err == nil {
			t.Fatal("expected error when _id modified")
		}
		if err := ValidateUpdateCtxMutations("1", map[string]any{"_id": nil}); err == nil {
			t.Fatal("expected error when _id cleared to nil")
		}
		if err := ValidateUpdateCtxMutations("1", map[string]any{"bogus_key": 1}); err == nil {
			t.Fatal("expected error on unsupported top-level ctx key")
		}
		if err := ValidateUpdateCtxMutations("1", map[string]any{"op": "create"}); err == nil {
			t.Fatal("expected error on op=create without __allow_create_op")
		}
		if err := ValidateUpdateCtxMutations("1", map[string]any{"op": "create", "__allow_create_op": true}); err != nil {
			t.Fatalf("expected op=create allowed with flag, got %v", err)
		}
		if err := ValidateUpdateCtxMutations("1", map[string]any{"op": "invalid_op"}); err == nil {
			t.Fatal("expected error on invalid ctx.op")
		}
		cycSrc := map[string]any{}
		cycSrc["self"] = cycSrc
		if err := ValidateUpdateCtxMutations("1", map[string]any{"_source": cycSrc}); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected cycle error on _source, got %v", err)
		}
	})
}

func TestRound60CoverageWrappersDocValuesAndFieldsAPI(t *testing.T) {
	t.Run("DayOfWeekInstantAndZonedDateTimeMethods", func(t *testing.T) {
		sunday := newDayOfWeekEnumFromWeekdayRound60(time.Sunday)
		if sunday.GetValue() != 7 || sunday.Name() != "SUNDAY" || sunday.String() != "SUNDAY" {
			t.Fatalf("unexpected Sunday enum: %#v", sunday)
		}
		unnamed := DayOfWeekEnum{Value: 2}
		if unnamed.String() != "TUESDAY" {
			t.Fatalf("expected TUESDAY, got %q", unnamed.String())
		}
		outOfRange := DayOfWeekEnum{Value: 99}
		if outOfRange.String() != "MONDAY" {
			t.Fatalf("expected fallback MONDAY, got %q", outOfRange.String())
		}
		if b, err := sunday.MarshalJSON(); err != nil || string(b) != `"SUNDAY"` {
			t.Fatalf("unexpected DayOfWeekEnum JSON: %s (%v)", string(b), err)
		}

		var nilInst *InstantVal
		if nilInst.ToEpochMilli() != 0 || nilInst.String() != "null" {
			t.Fatal("unexpected nil InstantVal methods")
		}
		if b, err := nilInst.MarshalJSON(); err != nil || string(b) != "null" {
			t.Fatalf("unexpected nil InstantVal JSON: %s (%v)", string(b), err)
		}
		inst := &InstantVal{Time: time.Date(2024, 3, 15, 12, 30, 45, 0, time.UTC)}
		if inst.ToEpochMilli() == 0 || !strings.HasPrefix(inst.String(), "2024-03-15") {
			t.Fatalf("unexpected InstantVal: %v", inst)
		}
		if _, err := inst.MarshalJSON(); err != nil {
			t.Fatalf("InstantVal.MarshalJSON failed: %v", err)
		}

		var nilZDT *ZonedDateTimeVal
		if nilZDT.GetYear() != 0 || nilZDT.GetMonthValue() != 0 || nilZDT.GetDayOfMonth() != 0 ||
			nilZDT.GetDayOfYear() != 0 || nilZDT.GetDayOfWeek() != 1 || nilZDT.GetDayOfWeekEnum().Value != 1 ||
			nilZDT.GetHour() != 0 || nilZDT.GetMinute() != 0 || nilZDT.GetSecond() != 0 ||
			nilZDT.GetNano() != 0 || nilZDT.ToEpochMilli() != 0 || nilZDT.String() != "null" ||
			nilZDT.ToInstant() == nil {
			t.Fatal("unexpected nil ZonedDateTimeVal receiver behavior")
		}
		if b, err := nilZDT.MarshalJSON(); err != nil || string(b) != "null" {
			t.Fatalf("unexpected nil ZonedDateTimeVal JSON: %s (%v)", string(b), err)
		}

		tmNano := time.Date(2024, 3, 15, 12, 30, 45, 123456789, time.UTC)
		zNano := &ZonedDateTimeVal{Time: tmNano, IsNano: true}
		if zNano.GetYear() != 2024 || zNano.GetMonthValue() != 3 || zNano.GetDayOfMonth() != 15 ||
			zNano.GetDayOfYear() == 0 || zNano.GetDayOfWeek() != 5 || zNano.GetDayOfWeekEnum().NameStr != "FRIDAY" ||
			zNano.GetHour() != 12 || zNano.GetMinute() != 30 || zNano.GetSecond() != 45 ||
			zNano.GetNano() != 123456789 || zNano.ToEpochMilli() == 0 || zNano.ToInstant().ToEpochMilli() == 0 {
			t.Fatalf("unexpected ZonedDateTimeVal getters: %#v", zNano)
		}
		if !strings.Contains(zNano.String(), ".123456789Z") {
			t.Fatalf("expected nano string, got %q", zNano.String())
		}
		zMilli := &ZonedDateTimeVal{Time: tmNano, IsNano: false}
		if !strings.HasSuffix(zMilli.String(), ".123Z") {
			t.Fatalf("expected milli string, got %q", zMilli.String())
		}
		if _, err := zMilli.MarshalJSON(); err != nil {
			t.Fatalf("zMilli.MarshalJSON failed: %v", err)
		}

		dateInputs := []any{
			zNano,
			*zNano,
			inst,
			tmNano,
			"1700000000000",
			"2024/03/15 12:30:45Z",
			"2024/03/15T12:30:45+00:00",
			"2024/03/15 12:30:45",
			"2024/03/15T12:30:45",
			"2024/03/15",
			"2024-03-15T12:30:45Z",
			int64(1700000000000),
			float64(1700000000000),
		}
		for _, in := range dateInputs {
			if _, ok := parseZonedDateTimeValRound60(in, false); !ok {
				t.Fatalf("expected date input %#v to parse", in)
			}
		}
		if _, ok := parseZonedDateTimeValRound60(nil, false); ok {
			t.Fatal("expected nil parseZonedDateTimeValRound60 to fail")
		}
		for _, bad := range []any{nilZDT, nilInst, "", "   ", "not-a-date", struct{}{}} {
			if _, ok := parseFlexibleESDateTimeRound60(bad); ok {
				t.Fatalf("expected bad date input %#v to fail", bad)
			}
		}
	})

	t.Run("GeoPointBytesRefAndByteBuffer", func(t *testing.T) {
		var nilGP *GeoPointVal
		if nilGP.GetLat() != 0 || nilGP.GetLon() != 0 || nilGP.ArcDistance(0, 0) != 0 ||
			nilGP.PlaneDistance(0, 0) != 0 || nilGP.String() != "null" {
			t.Fatal("unexpected nil GeoPointVal behavior")
		}
		if d, err := nilGP.GeohashDistance("u4pruydqqvj"); err != nil || d != 0 {
			t.Fatalf("unexpected nil GeohashDistance: %v, %v", d, err)
		}

		gpInputs := []any{
			&GeoPointVal{Lat: 12.3, Lon: 45.6},
			GeoPointVal{Lat: 12.3, Lon: 45.6},
			map[string]any{"lat": 12.3, "lon": 45.6},
			map[string]any{"lat": 12.3, "lng": 45.6},
			map[string]any{"type": "Point", "coordinates": []any{45.6, 12.3}},
			[]any{45.6, 12.3},
			[]float64{45.6, 12.3},
			"POINT (45.6 12.3)",
			"12.3, 45.6",
			"u4pruydqqvj",
		}
		for _, in := range gpInputs {
			gp, ok := parseGeoPointValRound60(in)
			if !ok || gp == nil {
				t.Fatalf("expected geo_point %#v to parse", in)
			}
			_ = gp.GetLat()
			_ = gp.GetLon()
			_ = gp.ArcDistance(0, 0)
			_ = gp.PlaneDistance(0, 0)
			_ = gp.String()
			if _, err := gp.GeohashDistance("u4pruydqqvj"); err != nil {
				t.Fatalf("unexpected GeohashDistance error: %v", err)
			}
			if _, err := gp.GeohashDistance("invalid_geohash_chars!!!"); err == nil {
				t.Fatal("expected error on invalid geohash")
			}
		}
		for _, bad := range []any{nil, nilGP, "", "POINT (bad)", "12.3,bad", "a", "0123456789defg", map[string]any{"lat": "x"}} {
			if _, ok := parseGeoPointValRound60(bad); ok {
				t.Fatalf("expected invalid geo_point %#v to fail", bad)
			}
		}

		var nilBR *BytesRefVal
		var nilBB *ByteBufferVal
		if nilBR.String() != "null" || nilBR.Utf8ToString() != "" {
			t.Fatal("unexpected nil BytesRefVal")
		}
		if b, err := nilBR.MarshalJSON(); err != nil || string(b) != "null" {
			t.Fatalf("unexpected nil BytesRefVal JSON: %s (%v)", string(b), err)
		}
		br := &BytesRefVal{Bytes: []byte("hello"), Offset: 1, Length: 10}
		if br.Utf8ToString() != "ello" || len(br.byteSliceForPainless()) != 4 {
			t.Fatalf("unexpected sliced BytesRefVal: %q", br.Utf8ToString())
		}
		brBad := &BytesRefVal{Bytes: []byte("hi"), Offset: -1, Length: 2}
		if brBad.slice() != nil {
			t.Fatal("expected nil slice on negative offset")
		}
		_ = br.String()
		_, _ = br.MarshalJSON()

		if nilBB.Limit() != 0 || nilBB.Capacity() != 0 || nilBB.Position() != 0 ||
			nilBB.Remaining() != 0 || nilBB.Utf8ToString() != "" || nilBB.String() != "null" {
			t.Fatal("unexpected nil ByteBufferVal")
		}
		if _, err := nilBB.Get(0); err == nil {
			t.Fatal("expected error on nil ByteBufferVal.Get")
		}
		if b, err := nilBB.MarshalJSON(); err != nil || string(b) != "null" {
			t.Fatalf("unexpected nil ByteBufferVal JSON: %s (%v)", string(b), err)
		}
		bb := newByteBufferValRound60([]byte("xyz"))
		if v, err := bb.Get(1); err != nil || v != int64('y') {
			t.Fatalf("unexpected ByteBufferVal.Get(1): %v, %v", v, err)
		}
		if _, err := bb.Get(99); err == nil {
			t.Fatal("expected OOB error on ByteBufferVal.Get(99)")
		}
		_ = bb.Limit()
		_ = bb.Capacity()
		_ = bb.Position()
		_ = bb.Remaining()
		_ = bb.Utf8ToString()
		_ = bb.String()
		_, _ = bb.MarshalJSON()

		rawB64 := base64.RawStdEncoding.EncodeToString([]byte("raw-bytes"))
		for _, binIn := range []any{br, bb, []byte("b"), base64.StdEncoding.EncodeToString([]byte("std")), rawB64, "not!base64!"} {
			if _, ok := decodeBase64BinaryRound60(binIn); !ok {
				t.Fatalf("expected binary decode success for %#v", binIn)
			}
		}
		for _, badBin := range []any{nilBR, nilBB, 12345} {
			if _, ok := decodeBase64BinaryRound60(badBin); ok {
				t.Fatalf("expected binary decode failure for %#v", badBin)
			}
		}
	})

	t.Run("NormalizeDocValuesAndFieldsAPIEval", func(t *testing.T) {
		if NormalizeDocValuesForScript(nil, nil) != nil {
			t.Fatal("expected nil for nil doc")
		}
		doc := map[string]any{
			"__meta":         "keep",
			"vec":            []any{1.0, 2.0, 3.0},
			"nums":           []any{int64(10), int64(2), int64(10)},
			"floats":         []float64{3.5, 1.25},
			"dates":          []any{"2024-05-02T00:00:00Z", "2024-05-01T00:00:00Z"},
			"nanos":          "2024-05-01T00:00:00.123456789Z",
			"geos":           []any{"40.0,-70.0", "10.0,-20.0"},
			"bins":           base64.StdEncoding.EncodeToString([]byte("bin")),
			"bools":          []any{true, false, true},
			"bdups":          []any{true, false, true},
			"ips":            []any{"192.168.1.10", "10.0.0.1", "192.168.1.10"},
			"kws":            []any{"b", "a", "b"},
			"txt":            "hello world",
			"untyped_date":   "2024-01-02T03:04:05Z",
			"location":       []float64{-73.9857, 40.7484},
			"payload_binary": base64.StdEncoding.EncodeToString([]byte("hi")),
		}
		ft := map[string]string{
			"vec":    "dense_vector",
			"nums":   "long",
			"floats": "double",
			"dates":  "date",
			"nanos":  "date_nanos",
			"geos":   "geo_point",
			"bins":   "binary",
			"bools":  "boolean",
			"bdups":  "boolean_dup",
			"ips":    "ip",
			"kws":    "keyword",
			"txt":    "text",
		}
		norm := NormalizeDocValuesForScript(doc, ft)
		scripts := []string{
			"return doc['dates'].value.getYear() + doc['dates'].value.monthValue + doc['dates'].value.dayOfMonth + doc['dates'].value.dayOfYear + doc['dates'].value.dayOfWeek + doc['dates'].value.hour + doc['dates'].value.minute + doc['dates'].value.second + doc['dates'].value.nano;",
			"return doc['dates'].value.getDayOfWeekEnum().getValue() + doc['dates'].value.toInstant().getEpochSecond() + doc['dates'].value.toInstant().getNano() + doc['dates'].value.getMillis() + doc['dates'].value.getEpochSecond();",
			"return doc['dates'].value.dayOfWeekEnum.name() + ':' + doc['dates'].value.toInstant().toString();",
			"return doc['geos'].value.getLat() + doc['geos'].value.getLon() + doc['geos'].value.lat + doc['geos'].value.lon + doc['geos'].arcDistance(0.0, 0.0) + doc['geos'].planeDistance(0.0, 0.0) + doc['geos'].geohashDistance('s000');",
			"GeoPoint p = new GeoPoint(10.0, -20.0); GeoPoint p2 = new GeoPoint('10.0,-20.0'); GeoPoint p0 = new GeoPoint(); return doc['geos'].value.arcDistance(p) + p2.planeDistance(p0) + doc['geos'].getCentroid().lat;",
			"BytesRef b1 = new BytesRef('abc'); BytesRef b2 = new BytesRef([97, 98]); BytesRef b0 = new BytesRef(); return doc['bins'].value.utf8ToString() + ':' + b1.utf8ToString() + ':' + b2.length + ':' + b0.offset + ':' + doc['bins'].value.bytes.size();",
			"return field('payload_binary').get().utf8ToString() + ':' + field('payload_binary').get().limit() + ':' + field('payload_binary').get().capacity() + ':' + field('payload_binary').get().remaining() + ':' + field('payload_binary').get().position() + ':' + field('payload_binary').get().hasRemaining() + ':' + field('payload_binary').get().get(0);",
			"return field('kws').size() + ':' + field('kws').isEmpty() + ':' + field('kws').exists() + ':' + field('missing').get('def') + ':' + field('kws').get(1, 'fb') + ':' + $('kws', 'fb') + ':' + field('dates').asDate().getYear() + ':' + field('missing').asDate('2022-01-01T00:00:00Z').getYear() + ':' + field('geos').asGeoPoint().lat + ':' + field('missing').asGeoPoint('1.0,2.0').lon + ':' + field('nums').asString() + ':' + field('nums').asStrings().size();",
			"return doc['vec'].vectorValue.size() + ':' + (doc['vec'].magnitude > 0);",
		}
		for _, sc := range scripts {
			if _, err := Eval(norm, sc, nil); err != nil {
				t.Fatalf("script %q failed: %v", sc, err)
			}
		}

		// Legacy Joda getters must raise UnsupportedOperationException
		for _, legacy := range []string{
			"return doc['dates'].value.getMinuteOfHour();",
			"return doc['dates'].value.getMonthOfYear();",
			"return doc['dates'].value.getHourOfDay();",
			"return doc['dates'].value.getSecondOfMinute();",
		} {
			if _, err := Eval(norm, legacy, nil); err == nil {
				t.Fatalf("expected legacy Joda getter %q to fail", legacy)
			}
		}
		if _, handled, err := evalRound60ZeroArgMethod(".getSecondOfDay()", &ZonedDateTimeVal{Time: time.Now()}, nil, nil, 0); !handled || err == nil {
			t.Fatalf("expected .getSecondOfDay() error on ZonedDateTimeVal, got handled=%v err=%v", handled, err)
		}

		// Mutable ES 8 Fields API methods & sub-doc navigation
		mutDoc := map[string]any{
			"tags":    []any{"b", "a", "b"},
			"nums":    []any{int64(-2), int64(3), int64(5)},
			"src":     "move_me",
			"a.b":     "flat_dotted",
			"nested":  map[string]any{"k": "v"},
			"records": []any{map[string]any{"sub": "val1"}, map[string]any{"sub": "val2"}},
		}
		mutScript := `
			field('tags').deduplicate();
			field('tags').append('c');
			field('nums').removeValuesIf(x -> x < 0);
			field('nums').transform(x -> x * 10);
			field('src').move('dst');
			field(' fresh ').set('trimmed');
			field('nested.k').remove();
			String d0 = field('records').doc(0).$('sub', 'none');
			String d1 = field('records').doc(1).field('sub').get('none');
			int dCount = field('records').docs().size();
			return d0 + ':' + d1 + ':' + dCount + ':' + field('dst').get('none') + ':' + field('nums').values.size();
		`
		res, err := Eval(mutDoc, mutScript, nil)
		if err != nil {
			t.Fatalf("mutable Fields API script failed: %v", err)
		}
		if res != "val1:val2:2:move_me:2" {
			t.Fatalf("unexpected mutable Fields API result: %v", res)
		}

		// Direct FieldVal edge helpers
		var nilFV *FieldVal
		if nilFV.Size() != 0 || !nilFV.IsEmpty() || nilFV.GetDefault("d") != "d" ||
			nilFV.GetAt(0, "d") != "d" || nilFV.Exists() || nilFV.Remove() || nilFV.String() != "[]" {
			t.Fatal("unexpected nil FieldVal behavior")
		}
		nilFV.Set("noop")
		flatMap := map[string]any{"x.y": 1}
		if !hasPathInMapRound60(flatMap, []string{"x", "y"}) {
			t.Fatal("expected flat dotted key to be found")
		}
		if !deletePathInMapRound60(flatMap, []string{"x", "y"}) {
			t.Fatal("expected flat dotted key to be deleted")
		}

		// Strict mapping check variants
		for _, mappedSpec := range []any{
			map[string]bool{"ok": true},
			map[string]string{"ok": "keyword"},
			map[string]any{"ok": true},
			[]string{"ok"},
			true,
		} {
			sMap := map[string]any{
				"__strict_doc_fields": mappedSpec,
				"__field_types":       map[string]string{"ok": "keyword"},
				"ok":                  "v",
			}
			if err := checkStrictDocFieldMappingRound60(sMap, nil, "ok"); err != nil {
				t.Fatalf("expected mapped field 'ok' to pass for %T, got %v", mappedSpec, err)
			}
			if err := checkStrictDocFieldMappingRound60(sMap, nil, "missing_f"); err == nil {
				t.Fatalf("expected strict doc field error for spec %T", mappedSpec)
			}
		}
	})

	t.Run("FunctionalInterfacesAndMethodReferences", func(t *testing.T) {
		var nilPL *PainlessLambda
		if _, err := nilPL.Invoke(nil, nil, nil, 0); err == nil {
			t.Fatal("expected error invoking nil PainlessLambda")
		}
		scripts := []string{
			"def s = () -> 'supplied'; def is = () -> 7; def ls = () -> 9L; def ds = () -> 2.5; def bs = () -> true; return s.get() + ':' + is.getAsInt() + ':' + ls.getAsLong() + ':' + ds.getAsDouble() + ':' + bs.getAsBoolean();",
			"def f = (int x) -> { return x * 3; }; def iu = x -> x + 1; def lu = x -> x + 2L; def du = x -> x * 2.0; def p = x -> x > 0; return f.apply(4) + iu.applyAsInt(1) + (int)lu.applyAsLong(2L) + (int)du.applyAsDouble(1.5) + (p.test(5) ? 1 : 0);",
			"List items = []; def r = () -> { items.add('ran'); }; def c = x -> { items.add(x); }; r.run(); c.accept('accepted'); return items.join(',');",
			"def f1 = String::valueOf; def f2 = String::toLowerCase; String prefix = 'hi-'; def f3 = prefix::concat; return f1.apply(123) + ':' + f2.apply('ABC') + ':' + f3.apply('there');",
		}
		for _, sc := range scripts {
			if _, err := Eval(map[string]any{}, sc, nil); err != nil {
				t.Fatalf("lambda script %q failed: %v", sc, err)
			}
		}
	})
}

func TestRound60CoverageScoreEmitMovingAndIngestProcessors(t *testing.T) {
	t.Run("ScriptScoreBuiltinsAndUnits", func(t *testing.T) {
		durCases := []string{"100ns", "100us", "50ms", "2s", "3m", "1h", "2d", "1w", "250"}
		for _, d := range durCases {
			if _, err := parseESDurationMillisRound60(d); err != nil {
				t.Fatalf("duration %q failed: %v", d, err)
			}
		}
		if _, err := parseESDurationMillisRound60("bad_dur"); err == nil {
			t.Fatal("expected error on bad duration")
		}

		distCases := []string{"10m", "2km", "1mi", "1nmi", "10yd", "30ft", "12in", "100cm", "1000mm", "50"}
		for _, d := range distCases {
			if _, err := parseESDistanceMetersRound60(d); err != nil {
				t.Fatalf("distance %q failed: %v", d, err)
			}
		}
		if _, err := parseESDistanceMetersRound60("bad_dist"); err == nil {
			t.Fatal("expected error on bad distance")
		}

		// MurmurHash3 tail lengths 0, 1, 2, 3
		for _, s := range []string{"", "a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg"} {
			_ = murmurHash3x8632Round60([]byte(s), 42)
		}

		scoreDoc := NormalizeDocValuesForScript(map[string]any{
			"__doc_id": "doc-1",
			"_seq_no":  int64(7),
			"num":      float64(15),
			"dt":       "2024-03-10T00:00:00Z",
			"geo":      "40.7128,-74.0060",
			"vec":      []float64{3.0, 4.0},
			"zero_vec": []float64{0.0, 0.0},
		}, map[string]string{
			"num":      "double",
			"dt":       "date",
			"geo":      "geo_point",
			"vec":      "dense_vector",
			"zero_vec": "dense_vector",
		})
		scoreScripts := []string{
			"return saturation(10.0, 5.0) + sigmoid(10.0, 2.0, 0.5);",
			"return decayNumericLinear(10.0, 5.0, 1.0, 0.5, doc['num'].value) + decayNumericExp(10.0, 5.0, 1.0, 0.5, doc['num'].value) + decayNumericGauss(10.0, 5.0, 1.0, 0.5, doc['num'].value);",
			"return decayDateLinear('2024-03-10T00:00:00Z', '5d', '1d', 0.5, doc['dt'].value) + decayDateExp('2024-03-12T00:00:00Z', '5d', '0d', 0.5, doc['dt'].value) + decayDateGauss('2024-03-12T00:00:00Z', '5d', '0d', 0.5, doc['dt'].value);",
			"return decayGeoLinear('40.7,-74.0', '10km', '1km', 0.5, doc['geo'].value) + decayGeoExp('40.7,-74.0', '10km', '0m', 0.5, doc['geo'].value) + decayGeoGauss('40.7,-74.0', '10km', '0m', 0.5, doc['geo'].value);",
			"return randomScore(123) + randomScore(123, '_seq_no') + randomScore(123, 'num');",
			"return dotProduct([1.0, 2.0], 'vec') + cosineSimilarity([3.0, 4.0], 'vec') + l1norm([1.0, 2.0], 'vec') + l2norm([1.0, 2.0], 'vec');",
		}
		for _, sc := range scoreScripts {
			if _, err := Eval(scoreDoc, sc, nil); err != nil {
				t.Fatalf("score script %q failed: %v", sc, err)
			}
		}

		errScoreScripts := []string{
			"return saturation(1.0, 0.0);",
			"return sigmoid(1.0, 0.0, 1.0);",
			"return decayNumericLinear(0.0, -5.0, 0.0, 0.5, 1.0);",
			"return decayNumericLinear(0.0, 5.0, 0.0, 1.5, 1.0);",
			"return randomScore(1, '');",
			"return cosineSimilarity([1.0, 0.0], 'zero_vec');",
			"return dotProduct([1.0, 2.0, 3.0], 'vec');",
			"return dotProduct([], 'vec');",
			"return dotProduct([1.0, 2.0], 'missing_vec');",
		}
		for _, sc := range errScoreScripts {
			if _, err := Eval(scoreDoc, sc, nil); err == nil {
				t.Fatalf("expected error for score script %q", sc)
			}
		}
	})

	t.Run("EvalEmitContextAllFieldTypes", func(t *testing.T) {
		doc := map[string]any{"x": int64(42), "dt": "2024-04-01T00:00:00Z"}
		cases := []struct {
			ctxType string
			script  string
		}{
			{"boolean_field", "emit(true); emit(false); emit(true);"},
			{"long_field", "emit(doc['x'].value); emit(10.0);"},
			{"double_field", "emit(1.5); emit(2);"},
			{"keyword_field", "emit('alpha'); emit(123);"},
			{"date_field", "emit(1700000000000L); emit(doc['dt'].value); emit(1700000005000.0);"},
			{"ip_field", "emit('192.168.0.1'); emit('::1');"},
			{"geo_point_field", "emit(40.7128, -74.0060); emit('37.7749,-122.4194');"},
		}
		for _, tc := range cases {
			vals, err := EvalEmitContext(tc.script, tc.ctxType, doc, doc, map[string]any{"p": 1}, map[string]string{"x": "long", "dt": "date"})
			if err != nil || len(vals) == 0 {
				t.Fatalf("EvalEmitContext(%s) failed: vals=%v, err=%v", tc.ctxType, vals, err)
			}
			if tc.ctxType == "boolean_field" && (vals[0] != false || vals[1] != true) {
				t.Fatalf("expected boolean_field sorted false before true, got %v", vals)
			}
		}

		badCases := []struct {
			ctxType string
			script  string
		}{
			{"unsupported_field", "emit(1);"},
			{"keyword_field", "emit(null);"},
			{"boolean_field", "emit('not_bool');"},
			{"long_field", "emit(1.5);"},
			{"double_field", "emit('not_num');"},
			{"date_field", "emit('not_date');"},
			{"ip_field", "emit('not_an_ip');"},
			{"ip_field", "emit(123);"},
			{"geo_point_field", "emit(95.0, 0.0);"},
			{"geo_point_field", "emit('bad_geo');"},
			{"keyword_field", "if ("},
		}
		for _, bc := range badCases {
			if _, err := EvalEmitContext(bc.script, bc.ctxType, doc, doc, nil, nil); err == nil {
				t.Fatalf("expected error for bad EvalEmitContext(%s, %q)", bc.ctxType, bc.script)
			}
		}
	})

	t.Run("MovingFunctionsAndIngestProcessors", func(t *testing.T) {
		movingScripts := []string{
			"return MovingFunctions.sum([]) + MovingFunctions.sum([1.0, 2.0, 3.0]);",
			"return MovingFunctions.max([1.0, 5.0, 2.0]) + MovingFunctions.min([1.0, 5.0, 2.0]);",
			"return MovingFunctions.unweightedAvg([2.0, 4.0]) + MovingFunctions.linearWeightedAvg([2.0, 4.0, 6.0]);",
			"return MovingFunctions.ewma([1.0, 2.0, 3.0], 0.3) + MovingFunctions.holt([1.0, 2.0, 3.0], 0.3, 0.1);",
			"return MovingFunctions.holtWinters([1.0, 2.0, 3.0, 4.0, 5.0, 6.0], 0.3, 0.1, 0.1, 2, false) + MovingFunctions.holtWinters([2.0, 4.0, 3.0, 6.0, 4.0, 8.0], 0.3, 0.1, 0.1, 2, true);",
			"return MovingFunctions.stdDev([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0], 5.0, 2.0, 'upper_bound');",
			"return MovingFunctions.max([]) == null || Double.isNaN(MovingFunctions.unweightedAvg([]));",
		}
		for _, sc := range movingScripts {
			if _, err := Eval(nil, sc, nil); err != nil {
				t.Fatalf("MovingFunctions script %q failed: %v", sc, err)
			}
		}
		for _, badM := range []string{
			"return MovingFunctions.ewma([1.0, 2.0], 1.5);",
			"return MovingFunctions.sum('not_list');",
			"return MovingFunctions.sum(['not_num']);",
		} {
			if _, err := Eval(nil, badM, nil); err == nil {
				t.Fatalf("expected error for MovingFunctions script %q", badM)
			}
		}

		// ICMPv4 & ICMPv6 reply port mappings
		for _, t4 := range []uint8{8, 0, 13, 14, 15, 16, 17, 18, 3} {
			_, _ = icmpEquivalentReplyPortRound60(false, t4, 1)
		}
		for _, t6 := range []uint8{128, 129, 133, 134, 135, 136, 1} {
			_, _ = icmpEquivalentReplyPortRound60(true, t6, 0)
		}

		procDoc := map[string]any{
			"size_str": "2kb",
			"low":      []any{"A", "B"},
			"up":       []any{"a", "b"},
			"ws":       "  hi  ",
			"txt":      "foo-123-bar",
			"csv":      "a,b,c",
			"arr":      []any{"x", "y"},
			"old_k":    "val",
			"rm1":      1,
			"rm2":      2,
			"num_s":    "42",
			"flt_s":    "3.5",
			"bool_s":   "true",
			"ip_s":     "10.0.0.1",
			"auto_l":   []any{"true", "12", "2.5", "raw"},
			"json_s":   `{"nested": 99, "flt": 1.25, "arr": [1, 2]}`,
			"enc":      "hello%20world",
			"uri":      "https://alice:secret@example.com:8443/dir/file.tar.gz?x=1#frag",
		}
		procScript := `
			Map meta = metadata();
			meta['_id'] = 'new-id';
			meta['_index'] = 'new-idx';
			meta['_routing'] = 'r1';
			meta['_version'] = 3;
			meta['_version_type'] = 'external';
			meta['op'] = 'index';
			Processors.bytes(ctx, 'size_str');
			Processors.lowercase(ctx, 'low');
			Processors.uppercase(ctx, 'up');
			Processors.trim(ctx, 'ws');
			Processors.gsub(ctx, 'txt', '[0-9]+', 'NUM');
			Processors.split(ctx, 'csv', ',');
			Processors.join(ctx, 'arr', '|');
			Processors.rename(ctx, 'old_k', 'new_k');
			Processors.remove(ctx, ['rm1', 'rm2']);
			Processors.append(ctx, 'arr', 'z');
			Processors.convert(ctx, 'num_s', 'integer');
			Processors.convert(ctx, 'flt_s', 'float');
			Processors.convert(ctx, 'bool_s', 'boolean');
			Processors.convert(ctx, 'ip_s', 'ip');
			Processors.convert(ctx, 'auto_l', 'auto', 'auto_out');
			Processors.json(ctx, 'json_s', 'json_out');
			Processors.urlDecode(ctx, 'enc');
			Map uriOut = Processors.uriParts(ctx['uri']);
			ctx['uri_out'] = uriOut;
			String cid1 = Processors.communityId('10.0.0.2', '10.0.0.1', null, 'tcp', 443, 50000, null, null, 1);
			String cid2 = Processors.communityId('10.0.0.1', '10.0.0.1', null, 'udp', 9000, 80, null, null, 0);
			String cid3 = Processors.communityId('2001:db8::2', '2001:db8::1', null, 'icmpv6', null, null, 128, 0, 0);
			String cid4 = Processors.communityId('10.0.0.1', '10.0.0.2', null, 'icmp', null, null, 3, 4, 0);
			long b = Processors.bytes('5mb');
			long t = System.currentTimeMillis() + System.nanoTime();
			return cid1 + ':' + cid2 + ':' + cid3 + ':' + cid4 + ':' + b + ':' + (t > 0);
		`
		params := map[string]any{"ctx": procDoc}
		if _, err := Eval(procDoc, procScript, params); err != nil {
			t.Fatalf("Processors.* script failed: %v", err)
		}

		// Protocol name coverage for communityId
		for _, protoName := range []string{"igmp", "rsvp", "gre", "esp", "ah", "pim", "sctp", "41"} {
			_, err := evalCommunityIDProcessorRound60([]any{"10.0.0.1", "10.0.0.2", nil, protoName, 100, 200})
			if err != nil {
				t.Fatalf("communityId(%s) failed: %v", protoName, err)
			}
		}

		// Readonly metadata guard
		roEvalParams := map[string]any{"__readonly_ctx_meta": true, "_ctx_id": "orig", "_ctx_index": "idx1"}
		roBudget := getOrInitEvalBudget(roEvalParams)
		roMeta := getOrInitMetadataMapRound60(nil, roEvalParams)
		roMeta["_id"] = "changed"
		if err := syncMetadataMapToParamsRound60(roBudget, roEvalParams, roEvalParams); err == nil {
			t.Fatal("expected error mutating readonly metadata()['_id']")
		}
		roMeta["_id"] = "orig"
		roMeta["_index"] = "changed-idx"
		if err := syncMetadataMapToParamsRound60(roBudget, roEvalParams, roEvalParams); err == nil {
			t.Fatal("expected error mutating readonly metadata()['_index']")
		}
	})
}

func TestRound60CoverageWrapperEqualsMatrix(t *testing.T) {
	tm := time.Date(2024, 7, 4, 12, 0, 0, 0, time.UTC)
	dow1 := DayOfWeekEnum{Value: 4, NameStr: "THURSDAY"}
	dow2 := DayOfWeekEnum{Value: 5, NameStr: "FRIDAY"}
	var nilDOW *DayOfWeekEnum

	zdt1 := &ZonedDateTimeVal{Time: tm}
	zdt2 := &ZonedDateTimeVal{Time: tm.Add(time.Hour)}
	var nilZDT *ZonedDateTimeVal

	inst1 := &InstantVal{Time: tm}
	inst2 := &InstantVal{Time: tm.Add(time.Hour)}
	var nilInst *InstantVal

	gp1 := &GeoPointVal{Lat: 1.0, Lon: 2.0}
	gp2 := &GeoPointVal{Lat: 1.0, Lon: 3.0}
	var nilGP *GeoPointVal

	br1 := newBytesRefValRound60([]byte("abc"))
	br2 := newBytesRefValRound60([]byte("xyz"))
	var nilBR *BytesRefVal

	bb1 := newByteBufferValRound60([]byte("abc"))
	bb2 := newByteBufferValRound60([]byte("xyz"))
	var nilBB *ByteBufferVal

	cases := []struct {
		a, b    any
		eq, hit bool
	}{
		{dow1, dow1, true, true},
		{dow1, &dow1, true, true},
		{dow1, dow2, false, true},
		{dow1, "thursday", true, true},
		{"thursday", dow1, true, true},
		{dow1, 4, false, true},
		{nilDOW, nil, true, true},
		{&dow1, dow1, true, true},
		{nilZDT, nil, true, true},
		{zdt1, zdt1, true, true},
		{zdt1, zdt2, false, true},
		{zdt1, tm, true, true},
		{tm, zdt1, true, true},
		{zdt1, "2024-07-04T12:00:00Z", true, true},
		{"2024-07-04T12:00:00Z", zdt1, true, true},
		{zdt1, 123, false, true},
		{nilInst, nil, true, true},
		{inst1, inst1, true, true},
		{inst1, inst2, false, true},
		{inst1, tm, true, true},
		{inst1, "2024-07-04T12:00:00Z", true, true},
		{"2024-07-04T12:00:00Z", inst1, true, true},
		{inst1, 123, false, true},
		{gp1, gp1, true, true},
		{gp1, gp2, false, true},
		{gp1, nilGP, false, true},
		{nilGP, nilGP, true, true},
		{gp1, "1.0,2.0", false, true},
		{br1, br1, true, true},
		{br1, br2, false, true},
		{br1, nilBR, false, true},
		{br1, "abc", false, true},
		{bb1, bb1, true, true},
		{bb1, bb2, false, true},
		{bb1, nilBB, false, true},
		{bb1, "abc", false, true},
		{[]float64{1.0, 2.0}, []float64{1.0, 2.0}, true, true},
		{[]float64{1.0, 2.0}, []float64{1.0}, false, true},
		{[]float64{1.0, 2.0}, []float64{1.0, 3.0}, false, true},
		{[]float64{1.0, 2.0}, []any{int64(1), float64(2.0)}, true, true},
		{[]any{int64(1), float64(2.0)}, []float64{1.0, 2.0}, true, true},
		{[]float64{1.0, 2.0}, []any{1.0}, false, true},
		{[]float64{1.0, 2.0}, []any{"bad", 2.0}, false, true},
		{[]float64{1.0}, "not-slice", false, true},
		{"plain", "plain", false, false},
	}
	for i, tc := range cases {
		eq, hit := round60WrapperEquals(tc.a, tc.b)
		if eq != tc.eq || hit != tc.hit {
			t.Fatalf("case %d (%T vs %T): got (%v, %v), want (%v, %v)", i, tc.a, tc.b, eq, hit, tc.eq, tc.hit)
		}
	}

	// Verify JSON marshaling of a mixed wrapper map
	rawJSON, err := json.Marshal(map[string]any{
		"dow":  dow1,
		"zdt":  zdt1,
		"inst": inst1,
		"gp":   gp1,
		"br":   br1,
		"bb":   bb1,
	})
	if err != nil || len(rawJSON) == 0 {
		t.Fatalf("wrapper json.Marshal failed: %v", err)
	}
}

func TestRound60CoverageStdlibScripts(t *testing.T) {
	scripts := []string{
		`return String.format('%s-%04d-%.2f', 'id', 7, 3.14159);`,
		`Pattern p = Pattern.compile('([a-z]+)-(\\d+)'); Matcher m = p.matcher('abc-42'); return m.find() ? m.group(1) + ':' + m.group(2) : 'none';`,
		`List nums = [5, 1, 4, 2, 3]; return nums.stream().filter(x -> x > 1).map(x -> x * 2).sorted().collect(Collectors.toList()).join(',');`,
		`return StrictMath.hypot(3.0, 4.0) + Math.fma(2.0, 3.0, 4.0) + Math.floorMod(-7, 3);`,
		`BigDecimal a = new BigDecimal('10.50'); BigDecimal b = new BigDecimal('2.25'); return a.add(b).subtract(new BigDecimal('0.75')).toPlainString();`,
		`List l = new ArrayList([3, 1, 2]); Collections.sort(l); Collections.reverse(l); return Arrays.toString([1, 2, 3]) + ':' + l.join('-');`,
	}
	for _, sc := range scripts {
		if _, err := Eval(map[string]any{}, sc, nil); err != nil {
			t.Fatalf("stdlib script %q failed: %v", sc, err)
		}
	}
}

func TestRound60CoverageImplicitDocWrappersAndProperties(t *testing.T) {
	rawDoc := map[string]any{
		"created_at": []any{"2024-02-01T00:00:00Z", "2024-01-01T00:00:00Z"},
		"p1":         []any{"20.0,30.0", "10.0,15.0"},
		"obj_geo":    map[string]any{"lat": 5.5, "lon": 6.5},
		"raw_binary": []any{
			base64.StdEncoding.EncodeToString([]byte("zz")),
			base64.StdEncoding.EncodeToString([]byte("aa")),
		},
		"scalar_num": int64(5),
		"scalar_rm":  int64(-3),
		"src_ov":     "ov_val",
		"dst_ov":     "old_val",
		"bad_dt":     "not_a_date",
		"bad_gp":     "not_a_geo",
		"recs":       []any{map[string]any{"k": "v0"}},
	}
	script := `
		int y = doc['created_at'].value.year;
		String m = doc['created_at'].value.getMonth() + ':' + doc['created_at'].value.month;
		long dowV = doc['created_at'].value.getDayOfWeekEnum().value;
		double lat = doc['p1'].value.lat + doc['p1'].getCentroid().lon + doc['obj_geo'].value.lon;
		BytesRef br = doc['raw_binary'].value;
		int b0 = br.get(0);
		def bb = field('raw_binary').get();
		int seq0 = bb.get();
		field('src_ov').overwrite(field('dst_ov'));
		field('scalar_num').transform(x -> x * 4);
		field('scalar_rm').removeValuesIf(x -> x < 0);
		String k0 = field('recs').doc().$('k', 'd');
		return y + ':' + m + ':' + dowV + ':' + (lat > 0) + ':' + b0 + ':' + seq0 + ':' +
			field('dst_ov').value + ':' + field('dst_ov').empty + ':' + field('dst_ov').length + ':' +
			field('missing').asString('fb') + ':' + k0;
	`
	if _, err := Eval(rawDoc, script, nil); err != nil {
		t.Fatalf("implicit wrapper script failed: %v", err)
	}

	// Error branches on BytesRef.get OOB, ByteBuffer underflow, bad asDate / asGeoPoint
	errScripts := []string{
		"return doc['raw_binary'].value.get(99);",
		"def bb = field('raw_binary').get(); bb.get(); bb.get(); return bb.get();",
		"return field('bad_dt').asDate();",
		"return field('bad_gp').asGeoPoint();",
	}
	for _, es := range errScripts {
		if _, err := Eval(rawDoc, es, nil); err == nil {
			t.Fatalf("expected error for %q", es)
		}
	}

	// Direct resolveWrapperPropertyRound60 coverage across []float64, *FieldVal, *DayOfWeekEnum, *ZonedDateTimeVal
	vec := []float64{3.0, 4.0}
	for _, seg := range []string{"0", "length", "empty", "vectorValue", "magnitude", "unknown"} {
		_, _ = resolveWrapperPropertyRound60(vec, seg)
	}
	dow := DayOfWeekEnum{Value: 2, NameStr: "TUESDAY"}
	_, _ = resolveWrapperPropertyRound60(&dow, "value")
	zdt := &ZonedDateTimeVal{Time: time.Date(2024, 8, 9, 10, 11, 12, 13, time.UTC)}
	for _, seg := range []string{"year", "monthOfYear", "month", "date", "dayOfYear", "dayOfWeek", "dayOfWeekEnum", "hourOfDay", "minuteOfHour", "secondOfMinute", "nano", "millis"} {
		_, _ = resolveWrapperPropertyRound60(zdt, seg)
	}
	fv := &FieldVal{Name: "x", Values: []any{"v0", "v1"}}
	for _, seg := range []string{"value", "values", "empty", "length", "1"} {
		_, _ = resolveWrapperPropertyRound60(fv, seg)
	}
}
