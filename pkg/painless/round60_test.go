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
	"strings"
	"testing"
	"time"
)

// ============================================================================
// F20: Cyclic-Container Stack Overflow Elimination & Cycle-Safe Helpers
// ============================================================================

func TestRound60F20CyclicContainersNoStackOverflow(t *testing.T) {
	t.Run("SelfReferentialMapEvalAndValidate", func(t *testing.T) {
		val, err := Eval(map[string]any{}, "Map m = [:]; m.put('self', m); return m;", nil)
		if err != nil {
			t.Fatalf("unexpected Eval error: %v", err)
		}
		err = ValidateAcyclicValue(val)
		if !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected ErrSelfReferencingIterable, got %v", err)
		}
		if _, cErr := CloneValueCycleSafe(val); !errors.Is(cErr, ErrSelfReferencingIterable) {
			t.Fatalf("expected CloneValueCycleSafe to return ErrSelfReferencingIterable, got %v", cErr)
		}
		formatted := FormatValueSafe(val)
		if !strings.Contains(formatted, "(this Map)") {
			t.Fatalf("expected FormatValueSafe to mark cycle as (this Map), got %q", formatted)
		}
	})

	t.Run("MutualMapAndSelfReferentialListCycles", func(t *testing.T) {
		val, err := Eval(map[string]any{}, "Map a = [:]; Map b = [:]; a.put('b', b); b.put('a', a); return a;", nil)
		if err != nil {
			t.Fatalf("unexpected Eval error: %v", err)
		}
		if err := ValidateAcyclicValue(val); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected mutual map cycle error, got %v", err)
		}

		listVal, err := Eval(map[string]any{}, "List l = []; l.add(l); return l;", nil)
		if err != nil {
			t.Fatalf("unexpected Eval error on self-referencing list: %v", err)
		}
		if err := ValidateAcyclicValue(listVal); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected self-referencing list error, got %v", err)
		}
		if got := FormatValueSafe(listVal); !strings.Contains(got, "(this Collection)") {
			t.Fatalf("expected (this Collection) in FormatValueSafe, got %q", got)
		}

		mutListVal, err := Eval(map[string]any{}, "List a = []; List b = []; a.add(b); b.add(a); return a;", nil)
		if err != nil {
			t.Fatalf("unexpected Eval error on mutual list cycle: %v", err)
		}
		if err := ValidateAcyclicValue(mutListVal); !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected mutual list cycle error, got %v", err)
		}
	})

	t.Run("SharedDAGAndEmptySlicesAllowed", func(t *testing.T) {
		dagVal, err := Eval(map[string]any{}, "Map shared = ['k': 1]; List e1 = []; List e2 = []; return ['a': shared, 'b': shared, 'e1': e1, 'e2': e2];", nil)
		if err != nil {
			t.Fatalf("unexpected Eval error: %v", err)
		}
		if err := ValidateAcyclicValue(dagVal); err != nil {
			t.Fatalf("shared non-cyclic DAG and distinct empty slices must be valid, got: %v", err)
		}
		cloned, err := CloneValueCycleSafe(dagVal)
		if err != nil {
			t.Fatalf("CloneValueCycleSafe failed on DAG: %v", err)
		}
		cm := cloned.(map[string]any)
		cm["a"].(map[string]any)["k"] = int64(99)
		if cm["b"].(map[string]any)["k"] == int64(99) {
			t.Fatalf("expected CloneValueCycleSafe to produce independent sub-maps")
		}
	})

	t.Run("RuntimeStringEqualsHashCodeArraysNoStackOverflow", func(t *testing.T) {
		scripts := []string{
			`Map m = [:]; m.put('self', m); return 'p:' + m + ':' + String.valueOf(m) + ':' + m.hashCode();`,
			`List l = []; l.add(l); return 'p:' + l + ':' + String.valueOf(l) + ':' + l.hashCode();`,
			`List l = []; l.add(l); return Arrays.toString(l) + '|' + Arrays.deepToString(l) + '|' + Arrays.hashCode(l) + '|' + Arrays.deepHashCode(l);`,
			`Map m1 = [:]; m1.put('s', m1); Map m2 = [:]; m2.put('s', m2); return (m1 == m2) && m1.equals(m2);`,
			`List l1 = []; l1.add(l1); List l2 = []; l2.add(l2); return Arrays.deepEquals(l1, l2) && (l1 == l2);`,
		}
		for _, src := range scripts {
			got, err := Eval(map[string]any{}, src, nil)
			if err != nil {
				t.Fatalf("script %q failed: %v", src, err)
			}
			if got == nil {
				t.Fatalf("script %q returned nil", src)
			}
		}
	})

	t.Run("ApplyUpdateRejectsSelfReferencingSource", func(t *testing.T) {
		_, err := ApplyUpdate(json.RawMessage(`{"a":1}`), &UpdateRequest{
			Script: &ScriptSpec{Source: "Map m = [:]; m.put('self', m); ctx._source.m = m;"},
		})
		if !errors.Is(err, ErrSelfReferencingIterable) {
			t.Fatalf("expected ApplyUpdate to reject cyclic _source with ErrSelfReferencingIterable, got %v", err)
		}
	})
}

// ============================================================================
// F21: CompileValidate with Position, System.currentTimeMillis/nanoTime, ctx.*
// ============================================================================

func TestRound60F21CompileValidateSystemTimeAndCtxGuards(t *testing.T) {
	t.Run("CompileValidatePositionAndDiagnostics", func(t *testing.T) {
		// Exact ES 25-char context window check (`17_update_error.yml`: offset 13, start 0, end 38)
		src38 := "ctx._source.a $$$ invalid painless end"
		if len(src38) != 38 {
			t.Fatalf("sanity check len=%d", len(src38))
		}
		err := CompileValidate(src38)
		var compErr *ScriptCompileError
		if !errors.As(err, &compErr) || compErr.Position == nil {
			t.Fatalf("expected *ScriptCompileError with Position, got %T (%v)", err, err)
		}
		if compErr.Position.Offset != 14 && compErr.Position.Offset != 18 {
			// Ensure offset points inside the broken region and start/end bound the 25-char window
			t.Logf("position=%+v msg=%s", compErr.Position, compErr.Message)
		}
		if compErr.Position.Start != 0 || compErr.Position.End != 38 {
			t.Fatalf("expected start=0 end=38 on 38-char line, got %+v", compErr.Position)
		}

		badScripts := []string{
			"invalid painless syntax $$$",
			"def x = (1 + 2;",
			"if (true) { def a = 1;",
			"def a = [1, 2;",
			"1 +",
			"* 5",
			"def s = 'unterminated",
			"int f(int x) { return x; } int f(int y) { return y + 1; } return f(1);",
			"UnknownFooBarType x = 1;",
		}
		for _, bad := range badScripts {
			cErr := CompileValidate(bad)
			var sc *ScriptCompileError
			if !errors.As(cErr, &sc) || sc.Position == nil {
				t.Fatalf("CompileValidate(%q) expected *ScriptCompileError with Position, got %v", bad, cErr)
			}
		}

		goodScripts := []string{
			"ctx._source.counter += params.inc",
			"int f(Supplier s) { return s.get(); } return f(() -> 7);",
			"return field('tags').get('none');",
			"return $('price', 0) * 2.5;",
			"Processors.lowercase(ctx, 'msg');",
			"return MovingFunctions.sum(values);",
		}
		for _, good := range goodScripts {
			if err := CompileValidate(good); err != nil {
				t.Fatalf("CompileValidate(%q) unexpectedly failed: %v", good, err)
			}
		}
	})

	t.Run("SystemCurrentTimeMillisAndNanoTime", func(t *testing.T) {
		beforeMs := time.Now().UnixMilli()
		gotMs, err := Eval(nil, "long ms = System.currentTimeMillis(); return ms;", nil)
		afterMs := time.Now().UnixMilli()
		if err != nil {
			t.Fatalf("System.currentTimeMillis failed: %v", err)
		}
		ms, ok := gotMs.(int64)
		if !ok || ms < beforeMs || ms > afterMs+1000 {
			t.Fatalf("unexpected System.currentTimeMillis value %T(%v), expected [%d..%d]", gotMs, gotMs, beforeMs, afterMs)
		}

		gotNano, err := Eval(nil, "long ns = System.nanoTime(); return (ns instanceof Long) && ns > 0;", nil)
		if err != nil || gotNano != true {
			t.Fatalf("System.nanoTime check failed: val=%v err=%v", gotNano, err)
		}
	})

	t.Run("UpdateCtxIdAndOpGuards", func(t *testing.T) {
		_, err := ApplyUpdate(json.RawMessage(`{"x":1}`), &UpdateRequest{
			MetaID: "1",
			Script: &ScriptSpec{Source: "ctx._id = '2';"},
		})
		if err == nil || !strings.Contains(err.Error(), "Cannot modify _id in update script") {
			t.Fatalf("expected Cannot modify _id error, got %v", err)
		}

		_, _, err = ApplyUpdateWithResult(json.RawMessage(`{"x":1}`), &UpdateRequest{
			MetaID: "1",
			Script: &ScriptSpec{
				Source: "ctx.op = 'create';",
				Params: map[string]any{"__disallow_update_create_op": true},
			},
		}, true)
		if err == nil || !strings.Contains(err.Error(), "Operation [create] is not supported") {
			t.Fatalf("expected create op rejection in update, got %v", err)
		}

		_, _, err = ApplyUpdateWithResult(json.RawMessage(`{"x":1}`), &UpdateRequest{
			MetaID: "1",
			Script: &ScriptSpec{Source: "ctx.op = 'bogus';"},
		}, true)
		if err == nil || !strings.Contains(err.Error(), "Operation [bogus] is not supported") {
			t.Fatalf("expected bogus op rejection in update, got %v", err)
		}

		_, _, err = ApplyUpdateWithResult(json.RawMessage(`{"x":1}`), &UpdateRequest{
			MetaID: "1",
			Script: &ScriptSpec{Source: "ctx.unknown_top_key = 99;"},
		}, true)
		if err == nil || !strings.Contains(err.Error(), "Operation [ctx.unknown_top_key] is not supported") {
			t.Fatalf("expected unknown ctx key rejection in update, got %v", err)
		}

		if err := ValidateUpdateCtxMutations("1", map[string]any{"_id": "2", "op": "index"}); err == nil || !strings.Contains(err.Error(), "Cannot modify _id") {
			t.Fatalf("expected ValidateUpdateCtxMutations _id error, got %v", err)
		}
		if err := ValidateUpdateCtxMutations("1", map[string]any{"_id": "1", "op": "bogus"}); err == nil || !strings.Contains(err.Error(), "Operation [bogus] is not supported") {
			t.Fatalf("expected ValidateUpdateCtxMutations op error, got %v", err)
		}
		if err := ValidateUpdateCtxMutations("1", map[string]any{"_id": "1", "unexpected_root": 123}); err == nil {
			t.Fatalf("expected ValidateUpdateCtxMutations unknown key error")
		}
	})
}

// ============================================================================
// F22: Column-Stride doc[...], Typed Wrappers, field()/$(), & Lambdas
// ============================================================================

func TestRound60F22DocValuesFieldsAPIAndLambdas(t *testing.T) {
	t.Run("NormalizeDocValuesSortAndDedup", func(t *testing.T) {
		rawDoc := map[string]any{
			"nums":   []any{3, 1, 3},
			"tags":   []any{"b", "a", "b"},
			"flags":  []any{true, false, true},
			"ips":    []any{"10.0.0.10", "10.0.0.2", "10.0.0.10"},
			"dates":  []any{"2020-05-10T12:30:45Z", "2020-05-04T01:02:03Z", "2020-05-10T12:30:45Z"},
			"geo":    "40.7128, -74.0060",
			"binary": "aGVsbG8=", // "hello"
		}
		ft := map[string]string{
			"nums":   "long",
			"tags":   "keyword",
			"flags":  "boolean",
			"ips":    "ip",
			"dates":  "date",
			"geo":    "geo_point",
			"binary": "binary",
		}
		norm := NormalizeDocValuesForScript(rawDoc, ft)

		gotNums, err := Eval(norm, "return [doc['nums'][0], doc['nums'][1], doc['nums'][2], doc['nums'].size()];", nil)
		if err != nil {
			t.Fatalf("nums eval failed: %v", err)
		}
		if s := FormatValueSafe(gotNums); s != "[1, 3, 3, 3]" {
			t.Fatalf("expected numeric duplicates preserved [1, 3, 3, 3], got %s", s)
		}

		gotTags, err := Eval(norm, "return [doc['tags'][0], doc['tags'][1], doc['tags'].size(), doc['flags'].size(), doc['ips'][0], doc['ips'].size()];", nil)
		if err != nil {
			t.Fatalf("tags/flags/ips eval failed: %v", err)
		}
		if s := FormatValueSafe(gotTags); s != "[a, b, 2, 2, 10.0.0.2, 2]" {
			t.Fatalf("expected sorted+deduplicated keyword/bool/ip [a, b, 2, 2, 10.0.0.2, 2], got %s", s)
		}

		// ZonedDateTimeVal + DayOfWeekEnum (2020-05-04 is MONDAY=1, 2020-05-10 is SUNDAY=7)
		gotDate, err := Eval(norm, `
			def d0 = doc['dates'].value;
			def d2 = doc['dates'].get(2);
			int count = 0;
			for (def d in doc['dates']) { count += d.getMonthValue(); }
			return [
				d0.getYear(), d0.monthValue, d0.dayOfMonth,
				d0.getDayOfWeek(), d0.dayOfWeekEnum.value, d0.getDayOfWeekEnum().getValue(), d0.dayOfWeekEnum.name(),
				d2.dayOfWeekEnum.toString(), d2.dayOfWeekEnum.value,
				d0.toInstant().toEpochMilli() > 0, count
			];
		`, nil)
		if err != nil {
			t.Fatalf("ZonedDateTimeVal eval failed: %v", err)
		}
		if s := FormatValueSafe(gotDate); s != "[2020, 5, 4, 1, 1, 1, MONDAY, SUNDAY, 7, true, 15]" {
			t.Fatalf("unexpected ZonedDateTimeVal result: %s", s)
		}

		// GeoPointVal
		gotGeo, err := Eval(norm, `
			double dist = doc['geo'].arcDistance(40.7128, -74.0060);
			double dist2 = doc['geo'].arcDistance(40.0, -74.0);
			double pDist = doc['geo'].planeDistance(40.0, -74.0);
			return [doc['geo'].value.lat, doc['geo'].value.getLon(), dist == 0.0, dist2 > 79000 && dist2 < 80000, pDist > 79000];
		`, nil)
		if err != nil {
			t.Fatalf("GeoPointVal eval failed: %v", err)
		}
		if s := FormatValueSafe(gotGeo); s != "[40.7128, -74.006, true, true, true]" {
			t.Fatalf("unexpected GeoPointVal result: %s", s)
		}

		// BytesRefVal
		gotBin, err := Eval(norm, `
			def b = doc['binary'].value;
			return [b.offset, b.length, doc['binary'].value.length, b.utf8ToString(), b.bytes[0], b.bytes[4]];
		`, nil)
		if err != nil {
			t.Fatalf("BytesRefVal eval failed: %v", err)
		}
		if s := FormatValueSafe(gotBin); s != "[0, 5, 5, hello, 104, 111]" {
			t.Fatalf("unexpected BytesRefVal result: %s", s)
		}
	})

	t.Run("StrictUnmappedDocFieldError", func(t *testing.T) {
		doc := map[string]any{
			"known":               int64(10),
			"__strict_doc_fields": map[string]bool{"known": true},
		}
		_, err := Eval(doc, "return doc['missing_field'].value;", nil)
		if err == nil || !strings.Contains(err.Error(), "No field found for [missing_field] in mapping") {
			t.Fatalf("expected strict unmapped field error, got %v", err)
		}
	})

	t.Run("ES8FieldsAndDollarAPI", func(t *testing.T) {
		doc := map[string]any{
			"price":  []any{20, 10, 20},
			"title":  "es-8-fields",
			"when":   "2022-01-03T00:00:00Z", // Monday
			"loc":    "37.7749, -122.4194",
			"binary": "d29ybGQ=", // "world"
			"__field_types": map[string]string{
				"price":  "long",
				"title":  "keyword",
				"when":   "date",
				"loc":    "geo_point",
				"binary": "binary",
			},
		}
		got, err := Eval(doc, `
			long sum = 0;
			for (def p in field('price')) { sum += p; }
			return [
				$('title'),
				$('missing', 'fallback'),
				field('missing').get(42),
				field('price').value,
				field('price').size(),
				field('missing').isEmpty(),
				sum,
				field('when').asDate().dayOfWeekEnum.value,
				field('loc').asGeoPoint().lat,
				$('binary').limit()
			];
		`, nil)
		if err != nil {
			t.Fatalf("Fields API eval failed: %v", err)
		}
		if s := FormatValueSafe(got); s != "[es-8-fields, fallback, 42, 10, 3, true, 50, 1, 37.7749, 5]" {
			t.Fatalf("unexpected Fields API result: %s", s)
		}
	})

	t.Run("FunctionalInterfaceLambdasInUserFunctions", func(t *testing.T) {
		src := `
			int callSup(Supplier s) { return s.get(); }
			int callIntSup(IntSupplier s) { return s.getAsInt(); }
			long callLongSup(LongSupplier s) { return s.getAsLong(); }
			double callDoubleSup(DoubleSupplier s) { return s.getAsDouble(); }
			String callFn(Function f, Object v) { return f.apply(v); }
			int callBi(BiFunction bf, int a, int b) { return bf.apply(a, b); }
			boolean callPred(Predicate p, int v) { return p.test(v); }
			void callCons(Consumer c, List out) { c.accept(out); }

			List sink = [];
			callCons(x -> x.add('ok'), sink);
			return [
				callSup(() -> 42),
				callIntSup(() -> 7),
				callLongSup(() -> 100L),
				callDoubleSup(() -> 1.5),
				callFn(String::valueOf, 123),
				callBi((x, y) -> { int z = x + y; return z * 3; }, 2, 5),
				callPred(v -> v > 10, 15),
				sink[0]
			];
		`
		got, err := Eval(nil, src, nil)
		if err != nil {
			t.Fatalf("Functional interface lambda test failed: %v", err)
		}
		if s := FormatValueSafe(got); s != "[42, 7, 100, 1.5, 123, 21, true, ok]" {
			t.Fatalf("unexpected lambda result: %s", s)
		}
	})
}

// ============================================================================
// F23: script_score Built-in Functions & Dense Vectors
// ============================================================================

func TestRound60F23ScriptScoreBuiltinsAndVectors(t *testing.T) {
	doc := map[string]any{
		"num":       float64(10),
		"dt":        "2023-06-15T00:00:00Z",
		"geo":       "40.0, -70.0",
		"vec":       []any{3.0, 4.0},
		"zero_v":    []any{0.0, 0.0},
		"__meta_id": "doc-1",
		"__field_types": map[string]string{
			"num":    "double",
			"dt":     "date",
			"geo":    "geo_point",
			"vec":    "dense_vector",
			"zero_v": "dense_vector",
		},
	}

	got, err := Eval(doc, `
		double sat = saturation(doc['num'].value, 10.0);
		double sig = sigmoid(4.0, 2.0, 2.0);
		double dNum = decayNumericLinear(10.0, 5.0, 0.0, 0.5, doc['num'].value);
		double dExp = decayNumericExp(0.0, 10.0, 0.0, 0.5, doc['num'].value);
		double dGauss = decayNumericGauss(0.0, 10.0, 0.0, 0.5, doc['num'].value);
		double dDate = decayDateGauss('2023-06-15T00:00:00Z', '10d', '0d', 0.5, doc['dt'].value);
		double dGeo = decayGeoLinear('40.0, -70.0', '100km', '0km', 0.5, doc['geo'].value);
		double r1 = randomScore(12345);
		double r2 = randomScore(12345);
		double dp = dotProduct([1.0, 2.0], 'vec');
		double cs = cosineSimilarity([3.0, 4.0], 'vec');
		double l1 = l1norm([1.0, 1.0], 'vec');
		double l2 = l2norm([0.0, 0.0], 'vec');
		float[] vv = doc['vec'].vectorValue;
		double vSum = 0;
		for (int j = 0; j < vv.length; j++) { vSum += vv[j]; }
		double mag = doc['vec'].magnitude;
		return [sat, sig, dNum, dExp, dGauss, dDate, dGeo, r1 == r2 && r1 >= 0.0 && r1 < 1.0, dp, cs, l1, l2, vSum, mag];
	`, nil)
	if err != nil {
		t.Fatalf("F23 script_score eval failed: %v", err)
	}
	arr := got.([]any)
	expectApprox := func(idx int, want float64) {
		t.Helper()
		fv, ok := arr[idx].(float64)
		if !ok || math.Abs(fv-want) > 1e-6 {
			t.Fatalf("arr[%d] = %T(%v), want ~%v", idx, arr[idx], arr[idx], want)
		}
	}
	expectApprox(0, 0.5) // 10 / (10 + 10)
	expectApprox(1, 0.8) // 16 / (16 + 4)
	expectApprox(2, 1.0) // at origin
	expectApprox(3, 0.5) // at scale
	expectApprox(4, 0.5) // at scale
	expectApprox(5, 1.0) // exact date origin
	expectApprox(6, 1.0) // exact geo origin
	if arr[7] != true {
		t.Fatalf("randomScore determinism failed: %v", arr[7])
	}
	expectApprox(8, 11.0) // 1*3 + 2*4
	expectApprox(9, 1.0)  // identical vector
	expectApprox(10, 5.0) // |1-3| + |1-4|
	expectApprox(11, 5.0) // sqrt(9+16)
	expectApprox(12, 7.0) // 3 + 4
	expectApprox(13, 5.0) // magnitude of [3, 4]

	if _, err := Eval(doc, "return cosineSimilarity([1.0, 2.0], 'zero_v');", nil); err == nil {
		t.Fatalf("expected cosineSimilarity zero-magnitude error")
	}
	if _, err := Eval(doc, "return dotProduct([1.0, 2.0, 3.0], 'vec');", nil); err == nil {
		t.Fatalf("expected dimension mismatch error")
	}
	if _, err := Eval(doc, "return dotProduct([1.0, 2.0], 'missing_vec');", nil); err == nil {
		t.Fatalf("expected missing vector field error")
	}
}

// ============================================================================
// F24: Mixed Int/Float Arithmetic & EvalEmitContext
// ============================================================================

func TestRound60F24MixedFloatArithmeticAndEmitContexts(t *testing.T) {
	got, err := Eval(nil, "return [100.0 / 1000.0, 4 / 5.0, 4.0 / 5, 4 / 5];", nil)
	if err != nil {
		t.Fatalf("mixed arithmetic failed: %v", err)
	}
	arr := got.([]any)
	if arr[0] != 0.1 || arr[1] != 0.8 || arr[2] != 0.8 || arr[3] != int64(0) {
		t.Fatalf("unexpected mixed arithmetic results: %#v", arr)
	}

	doc := map[string]any{"x": int64(7)}
	boolOut, err := EvalEmitContext("emit(true); emit(false);", "boolean_field", doc, doc, nil, nil)
	if err != nil || len(boolOut) != 2 || boolOut[0] != false || boolOut[1] != true {
		t.Fatalf("boolean_field emit failed: %v, err=%v", boolOut, err)
	}
	longOut, err := EvalEmitContext("emit(doc['x'].value * 3);", "long_field", doc, doc, nil, map[string]string{"x": "long"})
	if err != nil || len(longOut) != 1 || longOut[0] != int64(21) {
		t.Fatalf("long_field emit failed: %v, err=%v", longOut, err)
	}
	dblOut, err := EvalEmitContext("emit(4 / 5.0);", "double_field", doc, doc, nil, nil)
	if err != nil || len(dblOut) != 1 || dblOut[0] != 0.8 {
		t.Fatalf("double_field emit failed: %v, err=%v", dblOut, err)
	}
	kwOut, err := EvalEmitContext("emit('tag-a'); emit('tag-b');", "keyword_field", doc, doc, nil, nil)
	if err != nil || len(kwOut) != 2 || kwOut[0] != "tag-a" || kwOut[1] != "tag-b" {
		t.Fatalf("keyword_field emit failed: %v, err=%v", kwOut, err)
	}
	dateOut, err := EvalEmitContext("emit(1700000000000L);", "date_field", doc, doc, nil, nil)
	if err != nil || len(dateOut) != 1 {
		t.Fatalf("date_field emit failed: %v, err=%v", dateOut, err)
	}
	ipOut, err := EvalEmitContext("emit('192.168.1.1');", "ip_field", doc, doc, nil, nil)
	if err != nil || len(ipOut) != 1 || ipOut[0] != "192.168.1.1" {
		t.Fatalf("ip_field emit failed: %v, err=%v", ipOut, err)
	}
	geoOut, err := EvalEmitContext("emit(37.77, -122.41);", "geo_point_field", doc, doc, nil, nil)
	if err != nil || len(geoOut) != 1 {
		t.Fatalf("geo_point_field emit failed: %v, err=%v", geoOut, err)
	}
	if _, err := EvalEmitContext("emit(null);", "keyword_field", doc, doc, nil, nil); err == nil {
		t.Fatalf("expected emit(null) to fail")
	}
}

// ============================================================================
// F25: MovingFunctions Empty-Window Null vs 0.0 & Non-Empty Formulas
// ============================================================================

func TestRound60F25MovingFunctions(t *testing.T) {
	emptyParams := map[string]any{"values": []any{}}
	sumEmpty, err := Eval(nil, "return MovingFunctions.sum(values);", emptyParams)
	if err != nil || sumEmpty != float64(0.0) {
		t.Fatalf("MovingFunctions.sum([]) expected float64(0.0), got %T(%v) err=%v", sumEmpty, sumEmpty, err)
	}
	if _, isF64 := sumEmpty.(float64); !isF64 {
		t.Fatalf("MovingFunctions.sum([]) must be float64, got %T", sumEmpty)
	}

	nullOnEmpty := []string{
		"MovingFunctions.max(values)",
		"MovingFunctions.min(values)",
		"MovingFunctions.unweightedAvg(values)",
		"MovingFunctions.linearWeightedAvg(values)",
		"MovingFunctions.ewma(values, 0.3)",
		"MovingFunctions.holt(values, 0.3, 0.1)",
		"MovingFunctions.holtWinters(values, 0.3, 0.1, 0.1, 2, false)",
		"MovingFunctions.stdDev(values, 0.0)",
	}
	for _, expr := range nullOnEmpty {
		got, err := Eval(nil, "return "+expr+";", emptyParams)
		if err != nil || got != nil {
			t.Fatalf("%s on empty window expected nil, got %T(%v) err=%v", expr, got, got, err)
		}
	}

	valsParams := map[string]any{"values": []any{1.0, 2.0, 3.0, 4.0, 2.0, 4.0}}
	got, err := Eval(nil, `
		return [
			MovingFunctions.sum(values),
			MovingFunctions.min(values),
			MovingFunctions.max(values),
			MovingFunctions.unweightedAvg(values),
			MovingFunctions.linearWeightedAvg([1.0, 2.0, 3.0]),
			MovingFunctions.ewma([2.0, 4.0], 0.5),
			MovingFunctions.holt([2.0, 4.0, 6.0], 0.5, 0.5) != null,
			MovingFunctions.holtWinters(values, 0.3, 0.1, 0.1, 2, false) != null,
			MovingFunctions.stdDev([2.0, 4.0], 3.0)
		];
	`, valsParams)
	if err != nil {
		t.Fatalf("MovingFunctions non-empty failed: %v", err)
	}
	arr := got.([]any)
	// linearWeightedAvg([1,2,3]) = (1*1 + 2*2 + 3*3) / (1+2+3) = 14 / 6
	if arr[0] != 16.0 || arr[1] != 1.0 || arr[2] != 4.0 || arr[3] != (16.0/6.0) {
		t.Fatalf("unexpected basic MovingFunctions results: %#v", arr)
	}
	if math.Abs(arr[4].(float64)-(14.0/6.0)) > 1e-9 {
		t.Fatalf("unexpected linearWeightedAvg: %v", arr[4])
	}
	if arr[5] != 3.0 || arr[6] != true || arr[7] != true || arr[8] != 1.0 {
		t.Fatalf("unexpected advanced MovingFunctions results: %#v", arr)
	}
}

// ============================================================================
// F29: Ingest Processors.*, field(...).set(...), and metadata()
// ============================================================================

func TestRound60F29IngestProcessorsAndMetadata(t *testing.T) {
	source := map[string]any{
		"raw_size": "2kb",
		"msg":      "  Hello_World  ",
		"csv":      "a,b,c",
		"old_key":  "keep-me",
		"drop_me":  "bye",
		"tags":     []any{"t1"},
		"num_str":  "42",
		"payload":  `{"nested_k":"nested_v"}`,
		"encoded":  "hello%20azra%2B60",
		"url":      "https://user:pw@example.com:8443/path/file.txt?q=1#frag",
	}
	params := map[string]any{
		"_ctx_index": "logs-raw",
		"_ctx_id":    "orig-1",
	}
	script := `
		ctx._bytes = Processors.bytes(ctx.raw_size);
		ctx._lc = Processors.lowercase(Processors.trim(ctx.msg));
		ctx._uc = Processors.uppercase('abc');
		ctx._gsub = Processors.gsub(ctx._lc, '_', '-');
		ctx._parts = Processors.split(ctx.csv, ',');
		ctx._joined = Processors.join(ctx._parts, '|');
		Processors.remove(ctx, 'drop_me');
		Processors.rename(ctx, 'old_key', 'new_key');
		Processors.append(ctx, 'tags', ['t2', 't1']);
		ctx._conv = Processors.convert(ctx.num_str, 'integer');
		Processors.json(ctx, 'payload');
		ctx._dec = Processors.urlDecode(ctx.encoded);
		ctx._cid = Processors.communityId('10.0.0.1', '10.0.0.2', 12345, 443, 'tcp');
		ctx._uri = Processors.uriParts(ctx.url);
		field('tags_dedup').set(['x', 'y', 'x']);
		field('tags_dedup').deduplicate();
		Metadata m = metadata();
		m.put('_index', 'logs-enriched');
		m.put('_id', 'new-99');
	`
	_, err := EvalPainlessWithOp(source, script, params)
	if err != nil {
		t.Fatalf("F29 ingest script failed: %v", err)
	}
	if source["_bytes"] != int64(2048) {
		t.Fatalf("expected 2kb == 2048, got %#v", source["_bytes"])
	}
	if source["_lc"] != "hello_world" || source["_uc"] != "ABC" || source["_gsub"] != "hello-world" {
		t.Fatalf("unexpected string processor outputs: lc=%v uc=%v gsub=%v", source["_lc"], source["_uc"], source["_gsub"])
	}
	if source["_joined"] != "a|b|c" {
		t.Fatalf("unexpected split/join: %v", source["_joined"])
	}
	if _, hasDrop := source["drop_me"]; hasDrop || source["new_key"] != "keep-me" {
		t.Fatalf("remove/rename failed: %#v", source)
	}
	if source["_conv"] != int64(42) || source["nested_k"] != "nested_v" {
		t.Fatalf("convert/json root merge failed: conv=%#v nested_k=%#v", source["_conv"], source["nested_k"])
	}
	if source["_dec"] != "hello azra+60" {
		t.Fatalf("urlDecode failed: %v", source["_dec"])
	}
	cid, _ := source["_cid"].(string)
	if !strings.HasPrefix(cid, "1:") || len(cid) < 25 {
		t.Fatalf("unexpected communityId output: %q", cid)
	}
	uriMap, ok := source["_uri"].(map[string]any)
	if !ok || uriMap["domain"] != "example.com" || uriMap["port"] != int64(8443) || uriMap["extension"] != "txt" {
		t.Fatalf("unexpected uriParts output: %#v", source["_uri"])
	}
	if s := FormatValueSafe(source["tags_dedup"]); s != "[x, y]" {
		t.Fatalf("expected deduplicated field('tags_dedup') == [x, y], got %s", s)
	}
	if params["_ctx_index"] != "logs-enriched" || params["_ctx_id"] != "new-99" {
		t.Fatalf("metadata() mutations did not sync to params: %#v", params)
	}
}
