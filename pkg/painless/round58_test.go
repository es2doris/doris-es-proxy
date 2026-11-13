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
	"reflect"
	"strings"
	"testing"
)

func evalRound58Out(t *testing.T, script string, params map[string]any) map[string]any {
	t.Helper()
	doc := map[string]any{}
	if _, err := Eval(doc, script, params); err != nil {
		t.Fatalf("Eval failed unexpectedly: %v\nscript:\n%s", err, script)
	}
	out, ok := doc["out"].(map[string]any)
	if !ok {
		t.Fatalf("expected ctx._source.out to be map[string]any, got %#v", doc["out"])
	}
	return out
}

func assertEvalThrowsRound58(t *testing.T, script string, wantExType string) {
	t.Helper()
	_, err := Eval(map[string]any{}, script, nil)
	if err == nil {
		t.Fatalf("expected %s error, got nil for script:\n%s", wantExType, script)
	}
	if !strings.Contains(err.Error(), wantExType) {
		t.Fatalf("expected error containing %q, got %v for script:\n%s", wantExType, err, script)
	}
}

func TestRound58_F20_ReferenceIdentityTypeSafeEqualityOptionalAndElvis(t *testing.T) {
	t.Run("ReferenceIdentityOperator", func(t *testing.T) {
		out := evalRound58Out(t, `
			class Box {
				int v;
				Box(int v) { this.v = v; }
			}
			def emptyA = [];
			def emptyB = [];
			def listA = [1, 2];
			def listAlias = listA;
			def mapA = ['a': 1];
			def mapAlias = mapA;
			StringBuilder sb1 = new StringBuilder("hi");
			StringBuilder sb2 = new StringBuilder("hi");
			def opt1 = Optional.of("x");
			def opt2 = Optional.of("x");
			Pattern pat1 = Pattern.compile("a+");
			Pattern pat2 = Pattern.compile("a+");
			Matcher mat1 = pat1.matcher("aaa");
			Matcher mat2 = pat1.matcher("aaa");
			Box b1 = new Box(7);
			Box b2 = new Box(7);

			ctx._source.out = [
				'null_null': (null === null),
				'null_ne_null': (null !== null),
				'null_zero': (null === 0),
				'null_str': (null === ""),
				'null_bool': (null === false),
				'int_int': (1 === 1),
				'int_long': (1 === 1L),
				'int_double': (1 === 1.0),
				'str_str': ("abc" === "abc"),
				'str_int': ("1" === 1),
				'str_int_ne': ("1" !== 1),
				'bool_str': ("true" === true),
				'nan_nan': (Double.NaN === Double.NaN),
				'nan_ne_nan': (Double.NaN !== Double.NaN),
				'neg_pos_zero': (-0.0 === 0.0),
				'lit_empty_lists': ([] === []),
				'lit_empty_lists_ne': ([] !== []),
				'lit_lists': ([1, 2] === [1, 2]),
				'empty_self': (emptyA === emptyA),
				'empty_distinct': (emptyA === emptyB),
				'list_alias': (listA === listAlias),
				'lit_empty_maps': ([:] === [:]),
				'lit_maps': (['a': 1] === ['a': 1]),
				'map_alias': (mapA === mapAlias),
				'sb_distinct': (sb1 === sb2),
				'sb_self': (sb1 === sb1),
				'opt_distinct': (opt1 === opt2),
				'opt_self': (opt1 === opt1),
				'opt_empty_singleton': (Optional.empty() === Optional.empty()),
				'pat_distinct': (pat1 === pat2),
				'pat_self': (pat1 === pat1),
				'mat_distinct': (mat1 === mat2),
				'mat_self': (mat1 === mat1),
				'box_distinct': (b1 === b2),
				'box_self': (b1 === b1)
			];
		`, nil)

		want := map[string]any{
			"null_null":           true,
			"null_ne_null":        false,
			"null_zero":           false,
			"null_str":            false,
			"null_bool":           false,
			"int_int":             true,
			"int_long":            true,
			"int_double":          true,
			"str_str":             true,
			"str_int":             false,
			"str_int_ne":          true,
			"bool_str":            false,
			"nan_nan":             false,
			"nan_ne_nan":          true,
			"neg_pos_zero":        true,
			"lit_empty_lists":     false,
			"lit_empty_lists_ne":  true,
			"lit_lists":           false,
			"empty_self":          true,
			"empty_distinct":      false,
			"list_alias":          true,
			"lit_empty_maps":      false,
			"lit_maps":            false,
			"map_alias":           true,
			"sb_distinct":         false,
			"sb_self":             true,
			"opt_distinct":        false,
			"opt_self":            true,
			"opt_empty_singleton": true,
			"pat_distinct":        false,
			"pat_self":            true,
			"mat_distinct":        false,
			"mat_self":            true,
			"box_distinct":        false,
			"box_self":            true,
		}
		if !reflect.DeepEqual(out, want) {
			for k, w := range want {
				if out[k] != w {
					t.Errorf("key %q: got %#v, want %#v", k, out[k], w)
				}
			}
		}
	})

	t.Run("TypeSafeValuesEqualOptionalEqualityAndElvis", func(t *testing.T) {
		out := evalRound58Out(t, `
			def elvisEmptyOpt = Optional.empty() ?: "fallback";
			def elvisPresentOpt = Optional.of("val") ?: "fallback";
			def elvisNull = null ?: "fallback";
			def elvisFalse = false ?: true;
			def elvisZero = 0 ?: 99;
			def elvisEmptyStr = "" ?: "nonempty";

			ctx._source.out = [
				'str_num_eq': ("123" == 123),
				'str_num_ne': ("123" != 123),
				'str_bool_eq': ("true" == true),
				'fmt_list_collision': (["a b"] == ["a", "b"]),
				'nested_list_eq': ([1, ["x", 2L]] == [1L, ["x", 2.0]]),
				'nested_list_type_ne': ([1, ["2"]] == [1, [2]]),
				'nested_map_eq': (['a': 1, 'b': [2, 3]] == ['b': [2L, 3], 'a': 1.0]),
				'nested_map_type_ne': (['a': "1"] == ['a': 1]),
				'opt_empty_eq_null': (Optional.empty() == null),
				'opt_empty_ne_null': (Optional.empty() != null),
				'null_eq_opt_empty': (null == Optional.empty()),
				'opt_val_eq_raw': (Optional.of("x") == "x"),
				'raw_eq_opt_val': ("x" == Optional.of("x")),
				'opt_empty_eq_empty': (Optional.empty() == Optional.empty()),
				'opt_val_eq_same': (Optional.of("x") == Optional.of("x")),
				'opt_val_eq_diff': (Optional.of("x") == Optional.of("y")),
				'opt_val_type_mismatch': (Optional.of("1") == Optional.of(1)),
				'opt_val_numeric_eq': (Optional.of(1) == Optional.of(1L)),
				'elvis_empty_is_opt': (elvisEmptyOpt instanceof Optional),
				'elvis_empty_present': elvisEmptyOpt.isPresent(),
				'elvis_present_get': elvisPresentOpt.get(),
				'elvis_null': elvisNull,
				'elvis_false': elvisFalse,
				'elvis_zero': elvisZero,
				'elvis_empty_str': elvisEmptyStr
			];
		`, nil)

		want := map[string]any{
			"str_num_eq":            false,
			"str_num_ne":            true,
			"str_bool_eq":           false,
			"fmt_list_collision":    false,
			"nested_list_eq":        true,
			"nested_list_type_ne":   false,
			"nested_map_eq":         true,
			"nested_map_type_ne":    false,
			"opt_empty_eq_null":     false,
			"opt_empty_ne_null":     true,
			"null_eq_opt_empty":     false,
			"opt_val_eq_raw":        false,
			"raw_eq_opt_val":        false,
			"opt_empty_eq_empty":    true,
			"opt_val_eq_same":       true,
			"opt_val_eq_diff":       false,
			"opt_val_type_mismatch": false,
			"opt_val_numeric_eq":    true,
			"elvis_empty_is_opt":    true,
			"elvis_empty_present":   false,
			"elvis_present_get":     "val",
			"elvis_null":            "fallback",
			"elvis_false":           false,
			"elvis_zero":            int64(0),
			"elvis_empty_str":       "",
		}
		if !reflect.DeepEqual(out, want) {
			for k, w := range want {
				if !reflect.DeepEqual(out[k], w) {
					t.Errorf("key %q: got %#v, want %#v", k, out[k], w)
				}
			}
		}
	})
}

func TestRound58_F21_IEEE754FloatArithmeticOverflowWholeFloatRetentionAndMath(t *testing.T) {
	t.Run("IEEE754DivisionModuloOverflowAndTypeRetention", func(t *testing.T) {
		resWhole, err := Eval(nil, `return 1.5 + 1.5;`, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f, ok := resWhole.(float64); !ok || f != 3.0 {
			t.Fatalf("expected 1.5 + 1.5 to retain float64(3.0), got %T(%#v)", resWhole, resWhole)
		}

		resFloatLit, err := Eval(nil, `return 1.5f + 1.5f;`, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f, ok := resFloatLit.(float64); !ok || f != 3.0 {
			t.Fatalf("expected 1.5f + 1.5f to retain floating-point 3.0 (not int64), got %T(%#v)", resFloatLit, resFloatLit)
		}

		resFloat32Params, err := Eval(nil, `return params.a + params.b;`, map[string]any{"a": float32(1.5), "b": float32(1.5)})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f32, ok := resFloat32Params.(float32); !ok || f32 != float32(3.0) {
			t.Fatalf("expected float32 params 1.5 + 1.5 to retain float32(3.0), got %T(%#v)", resFloat32Params, resFloat32Params)
		}

		resPosInf, err := Eval(nil, `return 1.0 / 0.0;`, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f, ok := resPosInf.(float64); !ok || !math.IsInf(f, 1) {
			t.Fatalf("expected +Inf float64, got %T(%#v)", resPosInf, resPosInf)
		}

		resNegInf, err := Eval(nil, `return -1.0 / 0.0;`, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f, ok := resNegInf.(float64); !ok || !math.IsInf(f, -1) {
			t.Fatalf("expected -Inf float64, got %T(%#v)", resNegInf, resNegInf)
		}

		resNegZeroDiv, err := Eval(nil, `return 1.0 / -0.0;`, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f, ok := resNegZeroDiv.(float64); !ok || !math.IsInf(f, -1) {
			t.Fatalf("expected 1.0 / -0.0 -> -Inf, got %T(%#v)", resNegZeroDiv, resNegZeroDiv)
		}

		resZeroOverZero, err := Eval(nil, `return 0.0 / 0.0;`, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f, ok := resZeroOverZero.(float64); !ok || !math.IsNaN(f) {
			t.Fatalf("expected NaN float64, got %T(%#v)", resZeroOverZero, resZeroOverZero)
		}

		resModZero, err := Eval(nil, `return 5.0 % 0.0;`, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f, ok := resModZero.(float64); !ok || !math.IsNaN(f) {
			t.Fatalf("expected 5.0 %% 0.0 -> NaN float64, got %T(%#v)", resModZero, resModZero)
		}

		out := evalRound58Out(t, `
			double overflowPos = 1e308 * 10.0;
			double overflowNeg = -1e308 * 10.0;
			double overflowAdd = 1e308 + 1e308;
			double wholeChain = (1.5 + 1.5) / 2;
			double subChain = (4.0 - 1.0) / 2;
			double mulChain = (1.5 * 2.0) / 2;
			double negWhole = (-3.0) / 2;
			double dSuffix = 3d / 2;
			double logZero = Math.log(0.0);
			double logNeg = Math.log(-1.0);
			double sqrtNeg = Math.sqrt(-1.0);
			double sqrtChain = Math.sqrt(9.0) / 2;
			double powChain = Math.pow(2.0, 2.0) / 8;
			double floorChain = Math.floor(3.9) / 2;
			double ceilChain = Math.ceil(2.1) / 2;
			double rintChain = Math.rint(2.6) / 2;
			double expOverflow = Math.exp(1000.0);

			int intDivCaught = 0;
			try { int x = 1 / 0; } catch (ArithmeticException e) { intDivCaught++; }
			try { int y = 1 % 0; } catch (ArithmeticException e) { intDivCaught++; }

			ctx._source.out = [
				'overflow_pos': overflowPos == Double.POSITIVE_INFINITY,
				'overflow_neg': overflowNeg == Double.NEGATIVE_INFINITY,
				'overflow_add': overflowAdd == Double.POSITIVE_INFINITY,
				'whole_chain': wholeChain,
				'sub_chain': subChain,
				'mul_chain': mulChain,
				'neg_whole': negWhole,
				'd_suffix': dSuffix,
				'log_zero_neg_inf': logZero == Double.NEGATIVE_INFINITY,
				'log_neg_nan': Double.isNaN(logNeg),
				'sqrt_neg_nan': Double.isNaN(sqrtNeg),
				'sqrt_chain': sqrtChain,
				'pow_chain': powChain,
				'floor_chain': floorChain,
				'ceil_chain': ceilChain,
				'rint_chain': rintChain,
				'exp_overflow': expOverflow == Double.POSITIVE_INFINITY,
				'int_div_caught': intDivCaught
			];
		`, nil)

		want := map[string]any{
			"overflow_pos":     true,
			"overflow_neg":     true,
			"overflow_add":     true,
			"whole_chain":      1.5,
			"sub_chain":        1.5,
			"mul_chain":        1.5,
			"neg_whole":        -1.5,
			"d_suffix":         1.5,
			"log_zero_neg_inf": true,
			"log_neg_nan":      true,
			"sqrt_neg_nan":     true,
			"sqrt_chain":       1.5,
			"pow_chain":        0.5,
			"floor_chain":      1.5,
			"ceil_chain":       1.5,
			"rint_chain":       1.5,
			"exp_overflow":     true,
			"int_div_caught":   int64(2),
		}
		if !reflect.DeepEqual(out, want) {
			for k, w := range want {
				if !reflect.DeepEqual(out[k], w) {
					t.Errorf("key %q: got %#v, want %#v", k, out[k], w)
				}
			}
		}
	})
}

func TestRound58_F22_ConditionExceptionPropagationAndShortCircuiting(t *testing.T) {
	t.Run("CaughtConditionExceptionsAndShortCircuiting", func(t *testing.T) {
		out := evalRound58Out(t, `
			int nfe = 0;
			int nsee = 0;
			int ae = 0;
			int npe = 0;

			try { boolean b = (Integer.parseInt("abc") == 0); } catch (NumberFormatException e) { nfe++; }
			try { if (Integer.parseInt("xyz") != 1) { nfe = -999; } } catch (NumberFormatException e) { nfe++; }
			try { boolean b = (Optional.empty().get() == null); } catch (NoSuchElementException e) { nsee++; }

			try { boolean b = ((1 / 0) == 0); } catch (ArithmeticException e) { ae++; }
			try { boolean b = ((1 / 0) != 0); } catch (ArithmeticException e) { ae++; }
			try { boolean b = ((1 / 0) === 0); } catch (ArithmeticException e) { ae++; }
			try { boolean b = ((1 / 0) !== 0); } catch (ArithmeticException e) { ae++; }
			try { boolean b = ((1 / 0) < 5); } catch (ArithmeticException e) { ae++; }
			try { boolean b = ((1 / 0) instanceof Integer); } catch (ArithmeticException e) { ae++; }
			try { boolean b = !((1 / 0) == 0); } catch (ArithmeticException e) { ae++; }
			try { int v = (Integer.parseInt("bad") > 0) ? 1 : 2; } catch (NumberFormatException e) { nfe++; }
			try { while (Integer.parseInt("bad") > 0) { break; } } catch (NumberFormatException e) { nfe++; }
			try { do { int ok = 1; } while (Integer.parseInt("bad") > 0); } catch (NumberFormatException e) { nfe++; }
			try { for (int i = 0; Integer.parseInt("bad") < 3; i++) { break; } } catch (NumberFormatException e) { nfe++; }

			try { boolean b = (null < 1); } catch (NullPointerException e) { npe++; }
			try { boolean b = (1 <= null); } catch (NullPointerException e) { npe++; }
			try { boolean b = (null > 1); } catch (NullPointerException e) { npe++; }
			try { boolean b = (1 >= null); } catch (NullPointerException e) { npe++; }

			boolean scOrTrue = true || ((1 / 0) == 0);
			boolean scAndFalse = false && ((1 / 0) == 0);
			try { boolean b = false || ((1 / 0) == 0); } catch (ArithmeticException e) { ae++; }
			try { boolean b = true && ((1 / 0) == 0); } catch (ArithmeticException e) { ae++; }

			try { ["1", "bad"].removeIf(x -> Integer.parseInt(x) > 0); } catch (NumberFormatException e) { nfe++; }

			ctx._source.out = [
				'nfe': nfe,
				'nsee': nsee,
				'ae': ae,
				'npe': npe,
				'sc_or_true': scOrTrue,
				'sc_and_false': scAndFalse
			];
		`, nil)

		want := map[string]any{
			"nfe":          int64(7),
			"nsee":         int64(1),
			"ae":           int64(9),
			"npe":          int64(4),
			"sc_or_true":   true,
			"sc_and_false": false,
		}
		if !reflect.DeepEqual(out, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", out, want)
		}
	})

	t.Run("UncaughtTopLevelConditionExceptions", func(t *testing.T) {
		assertEvalThrowsRound58(t, `Integer.parseInt("abc") == 0`, "NumberFormatException")
		assertEvalThrowsRound58(t, `Optional.empty().get() == null`, "NoSuchElementException")
		assertEvalThrowsRound58(t, `false || (1 / 0 == 0)`, "ArithmeticException")
		assertEvalThrowsRound58(t, `true && (1 / 0 == 0)`, "ArithmeticException")
	})
}

func TestRound58_F23_NullSafeNavigationLazyShortCircuitNullNPEAndBooleanNull(t *testing.T) {
	t.Run("SafeNavShortCircuitsArgsAndReturnsNullForBooleans", func(t *testing.T) {
		out := evalRound58Out(t, `
			Map m = null;
			List l = null;
			String s = null;
			int sideEffects = 0;

			def exprPut = m?.put('k', ++sideEffects);
			m?.put('k2', ++sideEffects);
			m?.remove('k');
			m?.clear();

			def exprAdd = l?.add(++sideEffects);
			l?.add(++sideEffects);
			l?.set(0, ++sideEffects);
			l?.remove(0);
			l?.clear();

			def exprSub = s?.substring(1 / 0);
			def exprRep = s?.replace("a", "" + (1 / 0));

			def bIsEmpty = s?.isEmpty();
			def bIsBlank = s?.isBlank();
			def bStarts = s?.startsWith("a");
			def bEnds = s?.endsWith("a");
			def bContains = s?.contains("a");
			def bEquals = s?.equals("a");
			def bEqIgn = s?.equalsIgnoreCase("a");
			def bMatches = s?.matches(".*");
			def lEmpty = l?.isEmpty();
			def lContains = l?.contains(1);
			def mEmpty = m?.isEmpty();
			def mHasKey = m?.containsKey("k");
			def mHasVal = m?.containsValue(1);

			StringJoiner sj = new StringJoiner(", ");
			sj.add("one").add("two").add("three");

			ctx._source.out = [
				'side_effects': sideEffects,
				'm_still_null': (m === null),
				'l_still_null': (l === null),
				'expr_put_null': (exprPut === null),
				'expr_add_null': (exprAdd === null),
				'expr_sub_null': (exprSub === null),
				'expr_rep_null': (exprRep === null),
				'b_is_empty_null': (bIsEmpty === null),
				'b_is_blank_null': (bIsBlank === null),
				'b_starts_null': (bStarts === null),
				'b_ends_null': (bEnds === null),
				'b_contains_null': (bContains === null),
				'b_equals_null': (bEquals === null),
				'b_eq_ign_null': (bEqIgn === null),
				'b_matches_null': (bMatches === null),
				'l_empty_null': (lEmpty === null),
				'l_contains_null': (lContains === null),
				'm_empty_null': (mEmpty === null),
				'm_has_key_null': (mHasKey === null),
				'm_has_val_null': (mHasVal === null),
				'sj_joined': sj.toString()
			];
		`, nil)

		want := map[string]any{
			"side_effects":    int64(0),
			"m_still_null":    true,
			"l_still_null":    true,
			"expr_put_null":   true,
			"expr_add_null":   true,
			"expr_sub_null":   true,
			"expr_rep_null":   true,
			"b_is_empty_null": true,
			"b_is_blank_null": true,
			"b_starts_null":   true,
			"b_ends_null":     true,
			"b_contains_null": true,
			"b_equals_null":   true,
			"b_eq_ign_null":   true,
			"b_matches_null":  true,
			"l_empty_null":    true,
			"l_contains_null": true,
			"m_empty_null":    true,
			"m_has_key_null":  true,
			"m_has_val_null":  true,
			"sj_joined":       "one, two, three",
		}
		if !reflect.DeepEqual(out, want) {
			for k, w := range want {
				if !reflect.DeepEqual(out[k], w) {
					t.Errorf("key %q: got %#v, want %#v", k, out[k], w)
				}
			}
		}
	})

	t.Run("NonNullSafeDotOnNullThrowsNPEWithoutAutoVivifying", func(t *testing.T) {
		out := evalRound58Out(t, `
			Map m = null;
			List l = null;
			String s = null;
			int npe = 0;
			int argEval = 0;

			try { m.put('k', ++argEval); } catch (NullPointerException e) { npe++; }
			try { def x = m.put('k', ++argEval); } catch (NullPointerException e) { npe++; }
			try { m.remove('k'); } catch (NullPointerException e) { npe++; }
			try { m.clear(); } catch (NullPointerException e) { npe++; }
			try { l.add(++argEval); } catch (NullPointerException e) { npe++; }
			try { def x = l.add(++argEval); } catch (NullPointerException e) { npe++; }
			try { l.set(0, ++argEval); } catch (NullPointerException e) { npe++; }
			try { l.remove(0); } catch (NullPointerException e) { npe++; }
			try { l.clear(); } catch (NullPointerException e) { npe++; }
			try { def x = s.length(); } catch (NullPointerException e) { npe++; }
			try { def x = s.isEmpty(); } catch (NullPointerException e) { npe++; }
			try { def x = s.substring(0); } catch (NullPointerException e) { npe++; }

			ctx._source.out = [
				'npe': npe,
				'arg_eval': argEval,
				'm_null': (m === null),
				'l_null': (l === null)
			];
		`, nil)

		want := map[string]any{
			"npe":      int64(12),
			"arg_eval": int64(0),
			"m_null":   true,
			"l_null":   true,
		}
		if !reflect.DeepEqual(out, want) {
			t.Fatalf("mismatch:\ngot:  %#v\nwant: %#v", out, want)
		}
	})
}

func TestRound58_F24_RegexLiteralFlagsNullNPEAndPatternSyntaxException(t *testing.T) {
	out := evalRound58Out(t, `
		boolean findCaseIns = ("HELLO world" =~ /hello/i);
		boolean fullCaseIns = ("HELLO" ==~ /hello/i);
		boolean findCaseSens = ("HELLO" =~ /hello/);
		boolean multiLine = ("alpha\nbeta\ngamma" =~ /^beta$/m);
		boolean noMultiLine = ("alpha\nbeta\ngamma" =~ /^beta$/);
		boolean dotAll = ("a\nb" ==~ /a.b/s);
		boolean noDotAll = ("a\nb" ==~ /a.b/);
		boolean commentsMode = ("ab" ==~ /a   b # inline comment/x) && Pattern.compile("a # line comment\n b", Pattern.COMMENTS).matcher("ab").matches();

		Pattern pFlags = /^foo.bar$/imsudcU;
		boolean patMatched = pFlags.matcher("FOO\nBAR").matches();

		int npe = 0;
		String nullStr = null;
		Pattern nullPat = null;
		try { boolean b = (nullStr =~ /null/); } catch (NullPointerException e) { npe++; }
		try { boolean b = ("abc" =~ nullPat); } catch (NullPointerException e) { npe++; }
		try { boolean b = (nullStr ==~ /null/); } catch (NullPointerException e) { npe++; }
		try { boolean b = ("abc" ==~ nullPat); } catch (NullPointerException e) { npe++; }

		int pse = 0;
		try { Pattern bad = Pattern.compile("[unclosed"); } catch (PatternSyntaxException e) { pse++; }
		try { boolean b = Pattern.matches("[unclosed", "a"); } catch (PatternSyntaxException e) { pse++; }
		try { boolean b = "a".matches("[unclosed"); } catch (PatternSyntaxException e) { pse++; }
		try { boolean b = ("a" =~ "[unclosed"); } catch (PatternSyntaxException e) { pse++; }
		try { boolean b = ("a" ==~ "[unclosed"); } catch (PatternSyntaxException e) { pse++; }

		ctx._source.out = [
			'find_ci': findCaseIns,
			'full_ci': fullCaseIns,
			'find_cs': findCaseSens,
			'multiline': multiLine,
			'no_multiline': noMultiLine,
			'dotall': dotAll,
			'no_dotall': noDotAll,
			'comments': commentsMode,
			'pat_instance': (pFlags instanceof Pattern),
			'pat_matched': patMatched,
			'npe': npe,
			'pse': pse
		];
	`, nil)

	want := map[string]any{
		"find_ci":      true,
		"full_ci":      true,
		"find_cs":      false,
		"multiline":    true,
		"no_multiline": false,
		"dotall":       true,
		"no_dotall":    false,
		"comments":     true,
		"pat_instance": true,
		"pat_matched":  true,
		"npe":          int64(4),
		"pse":          int64(5),
	}
	if !reflect.DeepEqual(out, want) {
		for k, w := range want {
			if !reflect.DeepEqual(out[k], w) {
				t.Errorf("key %q: got %#v, want %#v", k, out[k], w)
			}
		}
	}

	assertEvalThrowsRound58(t, `return "abc" =~ /abc/z;`, "PatternSyntaxException")
	assertEvalThrowsRound58(t, `return /[unclosed/;`, "PatternSyntaxException")
	assertEvalThrowsRound58(t, `return null =~ /null/;`, "NullPointerException")
}

func TestRound58_F25_JavaTimeRangeValidationAndDateTimeFormatterValidation(t *testing.T) {
	out := evalRound58Out(t, `
		String leapValid = LocalDate.of(2020, 2, 29).toString();
		String leap2000 = LocalDate.of(2000, 2, 29).toString();
		String yearDayLeap = LocalDate.ofYearDay(2020, 366).toString();
		String mdFeb29 = MonthDay.of(2, 29).toString();
		String mdAtNonLeap = MonthDay.of(2, 29).atYear(2021).toString();
		String withYearClamp = LocalDate.of(2020, 2, 29).withYear(2021).toString();
		String withMonthClamp = LocalDate.of(2023, 3, 31).withMonth(4).toString();

		DateTimeFormatter validFmt = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss[.SSS]XXX");
		String formatted = ZonedDateTime.of(2024, 2, 29, 14, 30, 0, 0, ZoneId.of("UTC")).format(validFmt);

		int dte = 0;
		try { LocalDate.of(2021, 2, 29); } catch (DateTimeException e) { dte++; }
		try { LocalDate.of(1900, 2, 29); } catch (DateTimeException e) { dte++; }
		try { LocalDate.of(2023, 4, 31); } catch (DateTimeException e) { dte++; }
		try { LocalDate.of(2023, 0, 1); } catch (DateTimeException e) { dte++; }
		try { LocalDate.of(2023, 13, 1); } catch (DateTimeException e) { dte++; }
		try { LocalDate.of(2023, 1, 0); } catch (DateTimeException e) { dte++; }
		try { LocalDate.of(2023, 1, 32); } catch (DateTimeException e) { dte++; }
		try { LocalDate.ofYearDay(2021, 366); } catch (DateTimeException e) { dte++; }
		try { LocalDate.ofYearDay(2021, 0); } catch (DateTimeException e) { dte++; }
		try { LocalTime.of(24, 0); } catch (DateTimeException e) { dte++; }
		try { LocalTime.of(-1, 0); } catch (DateTimeException e) { dte++; }
		try { LocalTime.of(12, 60); } catch (DateTimeException e) { dte++; }
		try { LocalTime.of(12, 0, 60); } catch (DateTimeException e) { dte++; }
		try { LocalTime.of(12, 0, 0, 1000000000); } catch (DateTimeException e) { dte++; }
		try { LocalTime.ofSecondOfDay(86400); } catch (DateTimeException e) { dte++; }
		try { LocalTime.ofSecondOfDay(-1); } catch (DateTimeException e) { dte++; }
		try { LocalTime.ofNanoOfDay(-1L); } catch (DateTimeException e) { dte++; }
		try { LocalTime.ofNanoOfDay(86400000000000L); } catch (DateTimeException e) { dte++; }
		try { LocalDateTime.of(2021, 2, 29, 10, 0); } catch (DateTimeException e) { dte++; }
		try { LocalDateTime.of(2021, 3, 1, 25, 0); } catch (DateTimeException e) { dte++; }
		try { ZonedDateTime.of(2021, 2, 29, 10, 0, 0, 0, ZoneId.of("UTC")); } catch (DateTimeException e) { dte++; }
		try { OffsetDateTime.of(2023, 4, 31, 10, 0, 0, 0, ZoneOffset.UTC); } catch (DateTimeException e) { dte++; }
		try { YearMonth.of(2023, 13); } catch (DateTimeException e) { dte++; }
		try { YearMonth.of(2023, 4).atDay(31); } catch (DateTimeException e) { dte++; }
		try { MonthDay.of(2, 30); } catch (DateTimeException e) { dte++; }
		try { MonthDay.of(4, 31); } catch (DateTimeException e) { dte++; }
		try { Year.of(2021).atDay(366); } catch (DateTimeException e) { dte++; }
		try { LocalDate.of(2023, 4, 15).withDayOfMonth(31); } catch (DateTimeException e) { dte++; }
		try { LocalDate.of(2023, 4, 15).withMonth(13); } catch (DateTimeException e) { dte++; }
		try { LocalDate.of(2021, 1, 1).withDayOfYear(366); } catch (DateTimeException e) { dte++; }
		try { LocalTime.of(10, 0).withHour(24); } catch (DateTimeException e) { dte++; }
		try { LocalTime.of(10, 0).withMinute(60); } catch (DateTimeException e) { dte++; }
		try { LocalTime.of(10, 0).withSecond(60); } catch (DateTimeException e) { dte++; }
		try { LocalTime.of(10, 0).withNano(-1); } catch (DateTimeException e) { dte++; }

		int fmtIae = 0;
		try { DateTimeFormatter.ofPattern("yyyy-JJ-dd"); } catch (IllegalArgumentException e) { fmtIae++; }
		try { DateTimeFormatter.ofPattern("Cf"); } catch (IllegalArgumentException e) { fmtIae++; }
		try { DateTimeFormatter.ofPattern("yyyy-'unclosed"); } catch (IllegalArgumentException e) { fmtIae++; }
		try { DateTimeFormatter.ofPattern("yyyy-{MM}"); } catch (IllegalArgumentException e) { fmtIae++; }
		try { DateTimeFormatter.ofPattern("yyyy#MM"); } catch (IllegalArgumentException e) { fmtIae++; }
		try { DateTimeFormatter.ofPattern("yyyy]MM"); } catch (IllegalArgumentException e) { fmtIae++; }

		ctx._source.out = [
			'leap_valid': leapValid,
			'leap_2000': leap2000,
			'year_day_leap': yearDayLeap,
			'md_feb29': mdFeb29,
			'md_at_non_leap': mdAtNonLeap,
			'with_year_clamp': withYearClamp,
			'with_month_clamp': withMonthClamp,
			'formatted_not_empty': formatted.startsWith("2024-02-29T14:30:00"),
			'dte': dte,
			'fmt_iae': fmtIae
		];
	`, nil)

	want := map[string]any{
		"leap_valid":          "2020-02-29",
		"leap_2000":           "2000-02-29",
		"year_day_leap":       "2020-12-31",
		"md_feb29":            "--02-29",
		"md_at_non_leap":      "2021-02-28",
		"with_year_clamp":     "2021-02-28",
		"with_month_clamp":    "2023-04-30",
		"formatted_not_empty": true,
		"dte":                 int64(34),
		"fmt_iae":             int64(6),
	}
	if !reflect.DeepEqual(out, want) {
		for k, w := range want {
			if !reflect.DeepEqual(out[k], w) {
				t.Errorf("key %q: got %#v, want %#v", k, out[k], w)
			}
		}
	}
}

func TestRound58_F26_CollectionStringAndStreamBoundsAndImmutability(t *testing.T) {
	out := evalRound58Out(t, `
		List base = [10, 20, 30, 40];
		List sub = base.subList(1, 3);
		String rep0 = "abc".repeat(0);
		String rep3 = "abc".repeat(3);
		List nCopiesList = Collections.nCopies(3, "z");
		List streamList = Stream.of(1, 2, 3).toList();

		int iae = 0;
		int ioobe = 0;
		int sioobe = 0;
		int uoe = 0;
		int npe = 0;

		try { Set.of("a", "b", "a"); } catch (IllegalArgumentException e) { iae++; }
		try { Set.of(1, 1L); } catch (IllegalArgumentException e) { iae++; }
		try { Set.of("a", null); } catch (NullPointerException e) { npe++; }
		List withNull = new ArrayList();
		withNull.add("a");
		withNull.add(null);
		try { Set.copyOf(withNull); } catch (NullPointerException e) { npe++; }

		try { base.subList(-1, 2); } catch (IndexOutOfBoundsException e) { ioobe++; }
		try { base.subList(0, 5); } catch (IndexOutOfBoundsException e) { ioobe++; }
		try { base.subList(3, 1); } catch (IllegalArgumentException e) { iae++; }

		try { "abcd".substring(-1); } catch (StringIndexOutOfBoundsException e) { sioobe++; }
		try { "abcd".substring(5); } catch (StringIndexOutOfBoundsException e) { sioobe++; }
		try { "abcd".substring(0, 5); } catch (StringIndexOutOfBoundsException e) { sioobe++; }
		try { "abcd".substring(3, 1); } catch (StringIndexOutOfBoundsException e) { sioobe++; }
		try { "abcd".subSequence(-1, 2); } catch (StringIndexOutOfBoundsException e) { sioobe++; }
		try { "abcd".charAt(-1); } catch (StringIndexOutOfBoundsException e) { sioobe++; }
		try { "abcd".charAt(4); } catch (StringIndexOutOfBoundsException e) { sioobe++; }
		try { "abcd".codePointAt(-1); } catch (StringIndexOutOfBoundsException e) { sioobe++; }
		try { "abcd".codePointAt(4); } catch (StringIndexOutOfBoundsException e) { sioobe++; }

		try { "abc".repeat(-1); } catch (IllegalArgumentException e) { iae++; }
		try { Stream.of(1, 2, 3).limit(-1).toList(); } catch (IllegalArgumentException e) { iae++; }
		try { Stream.of(1, 2, 3).skip(-1).toList(); } catch (IllegalArgumentException e) { iae++; }
		try { Collections.nCopies(-1, "x"); } catch (IllegalArgumentException e) { iae++; }

		try { nCopiesList.add("w"); } catch (UnsupportedOperationException e) { uoe++; }
		try { nCopiesList.set(0, "w"); } catch (UnsupportedOperationException e) { uoe++; }
		try { nCopiesList.remove(0); } catch (UnsupportedOperationException e) { uoe++; }
		try { nCopiesList.clear(); } catch (UnsupportedOperationException e) { uoe++; }

		try { streamList.add(4); } catch (UnsupportedOperationException e) { uoe++; }
		try { streamList.set(0, 99); } catch (UnsupportedOperationException e) { uoe++; }
		try { streamList.remove(0); } catch (UnsupportedOperationException e) { uoe++; }
		try { streamList.clear(); } catch (UnsupportedOperationException e) { uoe++; }

		ctx._source.out = [
			'sub': sub,
			'rep0': rep0,
			'rep3': rep3,
			'ncopies': nCopiesList,
			'stream_list': streamList,
			'iae': iae,
			'ioobe': ioobe,
			'sioobe': sioobe,
			'uoe': uoe,
			'npe': npe
		];
	`, nil)

	want := map[string]any{
		"sub":         []any{int64(20), int64(30)},
		"rep0":        "",
		"rep3":        "abcabcabc",
		"ncopies":     []any{"z", "z", "z"},
		"stream_list": []any{int64(1), int64(2), int64(3)},
		"iae":         int64(7),
		"ioobe":       int64(2),
		"sioobe":      int64(9),
		"uoe":         int64(8),
		"npe":         int64(2),
	}
	if !reflect.DeepEqual(out, want) {
		for k, w := range want {
			if !reflect.DeepEqual(out[k], w) {
				t.Errorf("key %q: got %#v, want %#v", k, out[k], w)
			}
		}
	}
}

func TestRound58_ExtendedHelperAndOverloadCoverage(t *testing.T) {
	out := evalRound58Out(t, `
		double mTrig = Math.sin(0.0) + Math.cos(0.0) + Math.tan(0.0) + Math.asin(0.0) + Math.acos(1.0) + Math.atan(0.0) + Math.atan2(0.0, 1.0);
		double mHyp = Math.sinh(0.0) + Math.cosh(0.0) + Math.tanh(0.0) + Math.cbrt(8.0) + Math.hypot(3.0, 4.0);
		double mLogs = Math.log10(100.0) + Math.log1p(0.0) + Math.expm1(0.0);
		double mMisc = Math.signum(-5.0) + Math.signum(5.0) + Math.signum(0.0) + Math.copySign(2.0, -1.0) + Math.toDegrees(Math.toRadians(180.0));
		double mUlp = Math.nextUp(1.0) + Math.nextDown(1.0) + Math.nextAfter(1.0, 2.0) + Math.ulp(1.0) + Math.scalb(1.5, 2) + Math.IEEEremainder(5.0, 2.0) + Math.fma(2.0, 3.0, 1.0);
		int mExp = Math.getExponent(8.0);
		long mRound = Math.round(2.6) + StrictMath.abs(-4L) + Math.min(3, 5) + Math.max(3, 5);
		double mMinMaxF = Math.min(1.5, 2.5) + Math.max(1.5, 2.5) + (Math.random() >= 0.0 ? 1.0 : 0.0);
		int mExact = Math.addExact(2, 3) + Math.subtractExact(5, 2) + Math.multiplyExact(2, 4) + Math.incrementExact(1) + Math.decrementExact(2) + Math.negateExact(-3) + Math.toIntExact(7L) + Math.floorDiv(-7, 3) + Math.floorMod(-7, 3);

		LocalDate d = LocalDate.of(2024, Month.FEBRUARY, 29);
		LocalTime tm2 = LocalTime.of(10, 20);
		LocalTime tm3 = LocalTime.of(10, 20, 30);
		LocalTime tm4 = LocalTime.of(10, 20, 30, 500);
		LocalTime tmSec = LocalTime.ofSecondOfDay(3661);
		LocalTime tmNano = LocalTime.ofNanoOfDay(3661000000000L);
		LocalDateTime ldt2 = LocalDateTime.of(d, tm3);
		LocalDateTime ldt5 = LocalDateTime.of(2024, 2, 29, 10, 20);
		LocalDateTime ldt6 = LocalDateTime.of(2024, 2, 29, 10, 20, 30);
		LocalDateTime ldt7 = LocalDateTime.of(2024, 2, 29, 10, 20, 30, 0);
		ZonedDateTime zdt2 = ZonedDateTime.of(ldt6, ZoneId.of("+02:30"));
		ZonedDateTime zdt3 = ZonedDateTime.of(d, tm3, ZoneId.of("-05:00"));
		OffsetDateTime odt2 = OffsetDateTime.of(ldt6, ZoneOffset.of("+01:00"));
		OffsetDateTime odt3 = OffsetDateTime.of(d, tm3, ZoneOffset.of("-04:00"));
		Year yr = Year.of(2024);
		String ymFromYr = yr.atMonth(2).toString();
		String ldFromYrMd = yr.atMonthDay(MonthDay.of(2, 29)).toString();
		String mdMut = MonthDay.of(3, 15).withMonth(4).withDayOfMonth(30).toString();

		BigDecimal bd1 = new BigDecimal("10.50");
		BigDecimal bd2 = new BigDecimal("10.5");
		BigInteger bi1 = new BigInteger("12345678901234567890");
		BigInteger bi2 = new BigInteger("12345678901234567890");
		BitSet bs1 = new BitSet();
		bs1.set(3);
		BitSet bs2 = new BitSet();
		bs2.set(3);
		URI u1 = URI.create("https://example.com/a");
		URI u2 = URI.create("https://example.com/a");
		StringBuffer sbuf1 = new StringBuffer("q");
		StringBuffer sbuf2 = new StringBuffer("q");

		boolean bwCond = ((1 == 1) & (2 == 2)) && ((1 == 2) | (2 == 2)) && ((1 == 1) ^ (1 == 2));
		boolean negRegex = ("hello" !~ /\d+/);
		boolean patCharClassSlash = ("a/b" ==~ /[a\/b]+/i);

		int extraErrs = 0;
		try { Year.of(1000000000); } catch (DateTimeException e) { extraErrs++; }
		try { MonthDay.of(4, 15).withDayOfMonth(31); } catch (DateTimeException e) { extraErrs++; }
		try { MonthDay.of(4, 15).withMonth(13); } catch (DateTimeException e) { extraErrs++; }
		try { ZonedDateTime.of(ldt6, ZoneId.of("Invalid/NoSuchZone")); } catch (DateTimeException e) { extraErrs++; }

		ctx._source.out = [
			'm_trig': mTrig,
			'm_hyp': mHyp,
			'm_logs': mLogs,
			'm_misc': mMisc,
			'm_ulp_finite': !Double.isNaN(mUlp),
			'm_exp': mExp,
			'm_round': mRound,
			'm_minmax_f': mMinMaxF,
			'm_exact': mExact,
			'ldt_eq': ldt2.toString() == ldt6.toString() && ldt6.toString() == ldt7.toString() && ldt5.toString().startsWith("2024-02-29T10:20"),
			'tm_ok': tm2.toString().startsWith("10:20") && tm4.getNano() == 500 && tmSec.toString() == "01:01:01" && tmNano.toString() == "01:01:01",
			'zdt_odt_ok': zdt2.toString().contains("+02:30") && zdt3.toString().contains("-05:00") && odt2.toString().contains("+01:00") && odt3.toString().contains("-04:00"),
			'yr_helpers': ymFromYr == "2024-02" && ldFromYrMd == "2024-02-29" && mdMut == "--04-30",
			'bd_eq_val_not_scale': (bd1 == bd2) && !(bd1 === bd2),
			'bi_eq': (bi1 == bi2) && !(bi1 === bi2),
			'bs_eq': (bs1 == bs2) && !(bs1 === bs2),
			'uri_eq': (u1 == u2) && !(u1 === u2),
			'sbuf_ref': !(sbuf1 === sbuf2) && (sbuf1 === sbuf1),
			'bw_cond': bwCond,
			'neg_regex': negRegex,
			'pat_class_slash': patCharClassSlash,
			'extra_errs': extraErrs
		];
	`, nil)

	if out["ldt_eq"] != true || out["tm_ok"] != true || out["zdt_odt_ok"] != true || out["yr_helpers"] != true ||
		out["bd_eq_val_not_scale"] != true || out["bi_eq"] != true || out["bs_eq"] != true || out["uri_eq"] != true ||
		out["sbuf_ref"] != true || out["bw_cond"] != true || out["neg_regex"] != true || out["pat_class_slash"] != true ||
		out["extra_errs"] != int64(4) {
		t.Fatalf("extended coverage assertions failed: %#v", out)
	}
}

func TestRound58_BranchAndErrorPropagationMatrix(t *testing.T) {
	// 1. Direct unit coverage of painlessRefEqual and valuesEqualRound58 cross-type branches.
	optEmpty := &painlessOptional{kind: "Optional", present: false}
	optIntEmpty := &painlessOptional{kind: "OptionalInt", present: false}
	optX := &painlessOptional{kind: "Optional", present: true, val: "x"}
	if !painlessRefEqual(optEmpty, painlessEmptyOptional) || !painlessRefEqual(painlessEmptyOptional, optEmpty) {
		t.Fatal("expected Optional.empty() === painlessEmptyOptional")
	}
	if painlessRefEqual(optIntEmpty, painlessEmptyOptional) || painlessRefEqual(painlessEmptyOptional, optIntEmpty) {
		t.Fatal("expected OptionalInt.empty() !== painlessEmptyOptional")
	}
	if !painlessRefEqual(painlessEmptyOptional, painlessEmptyOptional) || painlessRefEqual(painlessEmptyOptional, "x") || painlessRefEqual("x", painlessEmptyOptional) {
		t.Fatal("unexpected painlessEmptyOptional ref equality")
	}
	if painlessRefEqual(optX, "x") || painlessRefEqual("x", optX) {
		t.Fatal("expected Optional.of('x') !== 'x'")
	}
	if !valuesEqualRound58(painlessEmptyOptional, painlessEmptyOptional) || valuesEqualRound58(painlessEmptyOptional, "x") || valuesEqualRound58("x", painlessEmptyOptional) {
		t.Fatal("unexpected painlessEmptyOptional value equality")
	}
	if painlessRefEqual([]any{1}, "not-slice") || painlessRefEqual("not-slice", []any{1}) {
		t.Fatal("slice vs non-slice must be false")
	}
	if painlessRefEqual(map[string]any{"a": 1}, "not-map") || painlessRefEqual("not-map", map[string]any{"a": 1}) {
		t.Fatal("map vs non-map must be false")
	}
	if painlessRefEqual(true, 1) || painlessRefEqual("a", 1) || painlessRefEqual(1, "a") {
		t.Fatal("primitive cross-family ref equality must be false")
	}
	if painlessRefEqual(math.NaN(), math.NaN()) || !painlessRefEqual(1.0, int64(1)) {
		t.Fatal("NaN === NaN must be false and 1.0 === 1L true")
	}
	if !painlessRefEqual(painlessYear{year: 2024}, painlessYear{year: 2024}) || painlessRefEqual(painlessYear{year: 2024}, painlessMonthDay{month: 2, day: 29}) {
		t.Fatal("struct value ref equality check failed")
	}

	// valuesEqualRound58 across OffsetTime, Clock, URI, URL, ValueRange, BitSet, UserObject, BigDecimal, BigInteger.
	out := evalRound58Out(t, `
		class Box {
			int v;
			Box(int x) { this.v = x; }
			boolean equals(def o) { return o instanceof Box && o.v == this.v; }
		}
		class RawBox {
			int v;
			RawBox(int x) { this.v = x; }
		}
		Box b1 = new Box(7);
		Box b2 = new Box(7);
		RawBox rb1 = new RawBox(7);
		RawBox rb2 = new RawBox(7);
		OffsetTime ot1 = OffsetTime.of(10, 20, 30, 0, ZoneOffset.UTC);
		OffsetTime ot2 = OffsetTime.of(10, 20, 30, 0, ZoneOffset.UTC);
		Clock c1 = Clock.fixed(Instant.ofEpochSecond(100), ZoneOffset.UTC);
		Clock c2 = Clock.fixed(Instant.ofEpochSecond(100), ZoneOffset.UTC);
		URL u1 = new URL("https://example.com/p");
		URL u2 = new URL("https://example.com/p");
		ValueRange vr1 = ValueRange.of(1, 10);
		ValueRange vr2 = ValueRange.of(1, 10);
		BigDecimal bd = new BigDecimal("5.0");
		BigInteger bi = new BigInteger("5");

		ctx._source.out = [
			'box_eq': (b1 == b2) && !(b1 == "x") && !("x" == b1),
			'rawbox_eq': !(rb1 == rb2) && (rb1 == rb1),
			'ot_eq': (ot1 == ot2) && !(ot1 == "x") && !("x" == ot1),
			'clk_eq': (c1 == c2) && !(c1 == "x") && !("x" == c1),
			'url_eq': (u1 == u2) && !(u1 == "x") && !("x" == u1),
			'vr_eq': (vr1 == vr2) && !(vr1 == "x") && !("x" == vr1),
			'num_bd_bi': (5 == bd) && (bd == 5) && (5 == bi) && (bi == 5) && !(5 == "5") && !("5" == 5),
			'nan_eq': !(Double.NaN == Double.NaN) && !(1.5 == 2.5) && (1.5 == 1.5),
			'map_diff': !(['a': 1] == ['a': 2]) && !(['a': 1] == 'x') && !('x' == ['a': 1]),
			'list_diff': !([1, 2] == [1, 3]) && !([1] == 'x') && !('x' == [1]),
			'comments_regex': ("a#b c" ==~ /a\#b\ [c # d]/x)
		];
	`, nil)
	for k, v := range out {
		if v != true {
			t.Fatalf("expected %s == true, got %#v", k, v)
		}
	}

	// 2. Boolean/conditional ternary & Elvis inside condition, bitwise error propagation, and regex/arg exceptions.
	condCases := []struct {
		cond    string
		params  map[string]any
		want    bool
		wantErr string
	}{
		{cond: `true ? true : (1 / 0 == 0)`, want: true},
		{cond: `false ? (1 / 0 == 0) : true`, want: true},
		{cond: `(1 / 0 == 0) ? true : false`, wantErr: "ArithmeticException"},
		{cond: `params.t ?: false`, params: map[string]any{"t": true}, want: true},
		{cond: `params.z ?: false`, params: map[string]any{"z": 0}, want: false},
		{cond: `params.s ?: false`, params: map[string]any{"s": "nonempty"}, want: true},
		{cond: `params.n ?: true`, params: map[string]any{"n": nil}, want: true},
		{cond: `(1 / 0) ?: true`, wantErr: "ArithmeticException"},
		{cond: `(1 == 1) | ((1 / 0) == 0)`, wantErr: "ArithmeticException"},
		{cond: `((1 / 0) == 0) | (1 == 1)`, wantErr: "ArithmeticException"},
		{cond: `(1 / 0) !== 1`, wantErr: "ArithmeticException"},
		{cond: `1 !== (1 / 0)`, wantErr: "ArithmeticException"},
		{cond: `(1 / 0) === 1`, wantErr: "ArithmeticException"},
		{cond: `1 === (1 / 0)`, wantErr: "ArithmeticException"},
		{cond: `1 != (1 / 0)`, wantErr: "ArithmeticException"},
		{cond: `1 == (1 / 0)`, wantErr: "ArithmeticException"},
		{cond: `(1 / 0) ==~ /a/`, wantErr: "ArithmeticException"},
		{cond: `"a" ==~ (1 / 0)`, wantErr: "ArithmeticException"},
		{cond: `(1 / 0) =~ /a/`, wantErr: "ArithmeticException"},
		{cond: `(1 / 0) !~ /a/`, wantErr: "ArithmeticException"},
		{cond: `"a" !~ (1 / 0)`, wantErr: "ArithmeticException"},
		{cond: `1 < (1 / 0)`, wantErr: "ArithmeticException"},
		{cond: `!(1 / 0 == 0)`, wantErr: "ArithmeticException"},
		{cond: `(1 / 0) instanceof Integer`, wantErr: "ArithmeticException"},
		{cond: `params.f32`, params: map[string]any{"f32": float32(2.5)}, want: true},
		{cond: `params.obj`, params: map[string]any{"obj": painlessYear{year: 2024}}, want: true},
	}
	for _, tc := range condCases {
		got, err := evalConditionErr(map[string]any{}, tc.cond, tc.params)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("cond %q: expected error %q, got res=%v err=%v", tc.cond, tc.wantErr, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("cond %q: expected %v, got %v (err=%v)", tc.cond, tc.want, got, err)
		}
	}

	// 3. Error propagation & edge cases across Math.*, java.time factories, subList, String.*, and Collections.nCopies.
	errScripts := []struct {
		script  string
		wantErr string
	}{
		{`return Math.abs(null);`, "NullPointerException"},
		{`return Math.min(1 / 0, 2);`, "ArithmeticException"},
		{`return Math.min(1, 1 / 0);`, "ArithmeticException"},
		{`return Math.clamp(5, 10, 2);`, "IllegalArgumentException"},
		{`return Math.clamp(5.0, Double.NaN, 10.0);`, "IllegalArgumentException"},
		{`return Math.pow(1 / 0, 2);`, "ArithmeticException"},
		{`return Math.pow(2, 1 / 0);`, "ArithmeticException"},
		{`return Math.floor(1 / 0);`, "ArithmeticException"},
		{`return Math.getExponent(1 / 0);`, "ArithmeticException"},
		{`return Month.of(13);`, "DateTimeException"},
		{`return DayOfWeek.of(8);`, "DateTimeException"},
		{`return LocalDate.of(null, 1, 1);`, "NullPointerException"},
		{`return LocalDate.of(2024, null, 1);`, "NullPointerException"},
		{`return LocalDate.of(2024, "BAD_MONTH", 1);`, "DateTimeException"},
		{`return LocalDateTime.of(null, LocalTime.of(1, 2));`, "NullPointerException"},
		{`return ZonedDateTime.of(null, ZoneOffset.UTC);`, "NullPointerException"},
		{`return ZonedDateTime.of(LocalDate.of(2024, 1, 1), null, ZoneOffset.UTC);`, "NullPointerException"},
		{`return OffsetDateTime.of(2024, 1, 1, 0, 0, 0, 0, "America/New_York");`, "DateTimeException"},
		{`return OffsetDateTime.of(2024, 1, 1, 0, 0, 0, 0, "+99:99");`, "DateTimeException"},
		{`return OffsetDateTime.of(2024, 1, 1, 0, 0, 0, 0, null);`, "NullPointerException"},
		{`return ZonedDateTime.of(2024, 1, 1, 0, 0, 0, 0, "");`, "DateTimeException"},
		{`return ZonedDateTime.of("bad", ZoneOffset.UTC);`, "DateTimeException"},
		{`return ZonedDateTime.of("bad", LocalTime.of(1, 2), ZoneOffset.UTC);`, "DateTimeException"},
		{`return LocalDateTime.of("bad", "bad");`, "DateTimeException"},
		{`return LocalTime.of(1);`, "IllegalArgumentException"},
		{`return DateTimeFormatter.ofPattern("yyyy]MM");`, "IllegalArgumentException"},
		{`List u = List.of(1, 2, 3).subList(0, 2); u.add(4); return u;`, "UnsupportedOperationException"},
		{`return [1, 2, 3].subList(1 / 0, 2);`, "ArithmeticException"},
		{`return [1, 2, 3].subList(0, 1 / 0);`, "ArithmeticException"},
		{`return "abc".substring(1 / 0);`, "ArithmeticException"},
		{`return "abc".substring(0, 1 / 0);`, "ArithmeticException"},
		{`return "abc".charAt(null);`, "NullPointerException"},
		{`return "abc".charAt("bad");`, "IllegalArgumentException"},
		{`return "abc".repeat(null);`, "NullPointerException"},
		{`return Collections.nCopies(null, "x");`, "NullPointerException"},
		{`return Collections.nCopies(1 / 0, "x");`, "ArithmeticException"},
		{`return Collections.nCopies(2, 1 / 0);`, "ArithmeticException"},
	}
	for _, tc := range errScripts {
		_, err := Eval(map[string]any{}, tc.script, nil)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("script %q: expected error %q, got %v", tc.script, tc.wantErr, err)
		}
	}

	// 4. Float32 Math.abs / Math.round / Math.clamp & empty subList / float-indexed helpers.
	f32Params := map[string]any{"f": float32(-3.5), "fpos": float32(1e20), "fneg": float32(-1e20)}
	resVal, err := Eval(map[string]any{}, `
		def a = Math.abs(params.f);
		def r1 = Math.round(params.f);
		def r2 = Math.round(params.fpos);
		def r3 = Math.round(params.fneg);
		def r4 = Math.round(Double.POSITIVE_INFINITY);
		def r5 = Math.round(Double.NEGATIVE_INFINITY);
		def c1 = Math.clamp(5, 1, 10);
		def c2 = Math.clamp(-5, 1, 10);
		def c3 = Math.clamp(50, 1, 10);
		def c4 = Math.clamp(5.5, 1.0, 10.0);
		def sl = [1, 2, 3].subList(1, 1);
		def m = Month.of(2);
		def dow = DayOfWeek.of(3);
		def dFloatMonth = LocalDate.of(2024, 2.0, 29);
		def sSub = "abcd".substring(1.0, 3.0) + ":" + "abcd".substring(2.0) + ":" + "abcd".charAt(1.0) + ":" + "a".repeat(2.0) + ":" + "".repeat(5) + ":" + "x".repeat(0);
		def nc = Collections.nCopies(2.0, "z");
		return [a, r1, r2, r3, r4, r5, c1, c2, c3, c4, sl.size(), m, dow, dFloatMonth.toString(), sSub, nc.size()];
	`, f32Params)
	if err != nil {
		t.Fatalf("unexpected error in float32/clamp/subList matrix: %v", err)
	}
	gotSlice, ok := resVal.([]any)
	if !ok || len(gotSlice) != 16 || gotSlice[0] != float32(3.5) || gotSlice[10] != int64(0) || gotSlice[11] != "FEBRUARY" || gotSlice[12] != "WEDNESDAY" || gotSlice[13] != "2024-02-29" || gotSlice[14] != "bc:cd:b:aa::" || gotSlice[15] != int64(2) {
		t.Fatalf("unexpected float32/clamp/subList results: %#v", resVal)
	}
}
