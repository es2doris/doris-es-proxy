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
	"reflect"
	"strings"
	"testing"
)

func evalRound59Out(t *testing.T, script string, params map[string]any) map[string]any {
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

func assertEvalThrowsRound59(t *testing.T, script string, params map[string]any, wantExType string) {
	t.Helper()
	_, err := Eval(map[string]any{}, script, params)
	if err == nil {
		t.Fatalf("expected %s error, got nil for script:\n%s", wantExType, script)
	}
	if !strings.Contains(err.Error(), wantExType) {
		t.Fatalf("expected error containing %q, got %v for script:\n%s", wantExType, err, script)
	}
}

func TestRound59_F20_RightAssocAssignmentsAndLeftAssocChaining(t *testing.T) {
	t.Run("LeftAssociativeEqualityAndRelationalChaining", func(t *testing.T) {
		out := evalRound59Out(t, `
			boolean eq1 = 1 == 1 == true;
			boolean eq2 = 1 != 2 == false;
			boolean eq3 = 1 === 2 == false;
			boolean eq4 = 1 !== 2 == true;
			boolean eq5 = 1 == 2 != true;
			boolean eq6 = 1 === 1 !== false;
			boolean rel1 = (1 < 2) == true;
			boolean rel2 = 3 >= 2 == false;
			boolean rel3 = 2 <= 2 == true;
			boolean rel4 = 5 > 1 == true;
			boolean shiftRel = (1 << 2 > 3) == true && (16 >> 2 <= 4) == true && (16 >>> 2 >= 4) == true;
			boolean quotesAndRegex = ("a==b" != "x===y" == true) && ("ab12" =~ /[a-z]+==?/ || "ab==" =~ /ab==/) == true;

			ctx._source.out = [
				'eq1': eq1,
				'eq2': eq2,
				'eq3': eq3,
				'eq4': eq4,
				'eq5': eq5,
				'eq6': eq6,
				'rel1': rel1,
				'rel2': rel2,
				'rel3': rel3,
				'rel4': rel4,
				'shiftRel': shiftRel,
				'quotesAndRegex': quotesAndRegex
			];
		`, nil)

		want := map[string]any{
			"eq1":            true,
			"eq2":            false,
			"eq3":            true,
			"eq4":            true,
			"eq5":            true,
			"eq6":            true,
			"rel1":           true,
			"rel2":           false,
			"rel3":           true,
			"rel4":           true,
			"shiftRel":       true,
			"quotesAndRegex": true,
		}
		for k, w := range want {
			if !reflect.DeepEqual(out[k], w) {
				t.Errorf("key %q: got %#v, want %#v", k, out[k], w)
			}
		}
	})

	t.Run("RightAssociativeAssignmentAndCompoundAssignmentExpressions", func(t *testing.T) {
		out := evalRound59Out(t, `
			class Counter {
				static int shared = 1;
				int v;
				Counter(int v) { this.v = v; }
				int addInExpr(int delta) { return (v += delta); }
				int setSuperLike(int x) { return (this.v = x); }
			}
			class SubCounter extends Counter {
				SubCounter(int v) { super(v); }
				int setViaSuper(int x) { return (super.v = x); }
				int addViaSuper(int d) { return (super.v += d); }
			}
			Map holder() { return params.box; }

			int a = 0;
			int b = 0;
			int chainRes = (a = b = 5);

			int cSrcRes = (ctx._source.a = ctx._source.b = 42);

			int p1 = 2;
			int p2 = 3;
			int compChain = (p1 += p2 += 4);

			int selfComp = 1;
			selfComp += selfComp += 4;

			int x = 0;
			int exprVal = (x = 5) + 1;

			byte narrowB = 0;
			int narrowExpr = (narrowB = 300);

			int bw = 12;
			int bw1 = (bw -= 2);
			int bw2 = (bw *= 3);
			int bw3 = (bw /= 5);
			int bw4 = (bw %= 4);
			int bw5 = (bw |= 8);
			int bw6 = (bw &= 10);
			int bw7 = (bw ^= 3);
			int bw8 = (bw <<= 2);
			int bw9 = (bw >>= 1);
			int bw10 = (bw >>>= 1);

			Map m = [:];
			int mapChain = (m['k1'] = m['k2'] = 11);
			int mapComp = (m['k1'] += 9);

			List arr = [10, 20, 30];
			int arrComp = (arr[1] += 5);

			Counter cnt = new Counter(10);
			int fieldSet = (cnt.v = 25);
			int fieldAdd = (cnt.v += 5);
			int methodAdd = cnt.addInExpr(7);
			int staticSet = (Counter.shared = 10);
			int staticAdd = (Counter.shared += 5);
			SubCounter sub = new SubCounter(1);
			int supSet = sub.setViaSuper(8);
			int supAdd = sub.addViaSuper(4);

			int postCallSet = (holder().num = 15);
			int postCallAdd = (holder().num += 5);

			boolean flag = true;
			int ternLeft = 0;
			int ternRight = 0;
			int ternVal = flag ? (ternLeft = 77) : (ternRight = 88);

			List queue = ["p", "q", "r"];
			List drained = [];
			def cur;
			while (!queue.isEmpty() && (cur = queue.remove(0)) != null) {
				drained.add(cur);
			}

			String opSet = (ctx.op = "index");

			ctx._source.out = [
				'a': a, 'b': b, 'chainRes': chainRes,
				'srcA': ctx._source.a, 'srcB': ctx._source.b, 'cSrcRes': cSrcRes,
				'p1': p1, 'p2': p2, 'compChain': compChain,
				'selfComp': selfComp,
				'x': x, 'exprVal': exprVal,
				'narrowB': narrowB, 'narrowExpr': narrowExpr,
				'bwOps': [bw1, bw2, bw3, bw4, bw5, bw6, bw7, bw8, bw9, bw10],
				'mK1': m['k1'], 'mK2': m['k2'], 'mapChain': mapChain, 'mapComp': mapComp,
				'arr': arr, 'arrComp': arrComp,
				'cntV': cnt.v, 'fieldSet': fieldSet, 'fieldAdd': fieldAdd, 'methodAdd': methodAdd,
				'staticVal': Counter.shared, 'staticSet': staticSet, 'staticAdd': staticAdd,
				'supVal': sub.v, 'supSet': supSet, 'supAdd': supAdd,
				'boxNum': params.box.num, 'postCallSet': postCallSet, 'postCallAdd': postCallAdd,
				'ternLeft': ternLeft, 'ternRight': ternRight, 'ternVal': ternVal,
				'drained': drained,
				'opSet': opSet
			];
		`, map[string]any{"box": map[string]any{"num": int64(0)}})

		if out["a"] != int64(5) || out["b"] != int64(5) || out["chainRes"] != int64(5) {
			t.Fatalf("unexpected chain a/b: %#v", out)
		}
		if out["srcA"] != int64(42) || out["srcB"] != int64(42) || out["cSrcRes"] != int64(42) {
			t.Fatalf("unexpected ctx._source chain: %#v", out)
		}
		if out["p1"] != int64(9) || out["p2"] != int64(7) || out["compChain"] != int64(9) {
			t.Fatalf("unexpected compound chain: p1=%v p2=%v compChain=%v", out["p1"], out["p2"], out["compChain"])
		}
		if out["selfComp"] != int64(6) {
			t.Fatalf("expected selfComp=6 per JLS §15.26.2, got %#v", out["selfComp"])
		}
		if out["x"] != int64(5) || out["exprVal"] != int64(6) {
			t.Fatalf("unexpected (x=5)+1: x=%v exprVal=%v", out["x"], out["exprVal"])
		}
		if out["narrowB"] != int64(44) || out["narrowExpr"] != int64(44) {
			t.Fatalf("expected byte narrowing of 300 -> 44, got narrowB=%v narrowExpr=%v", out["narrowB"], out["narrowExpr"])
		}
		if out["mK1"] != int64(20) || out["mK2"] != int64(11) || out["mapChain"] != int64(11) || out["mapComp"] != int64(20) {
			t.Fatalf("unexpected map assignment results: %#v", out)
		}
		if !reflect.DeepEqual(out["arr"], []any{int64(10), int64(25), int64(30)}) || out["arrComp"] != int64(25) {
			t.Fatalf("unexpected list index compound assignment: %#v", out["arr"])
		}
		if out["cntV"] != int64(37) || out["staticVal"] != int64(15) || out["supVal"] != int64(12) {
			t.Fatalf("unexpected user object/static/super assignment: cntV=%v static=%v sup=%v", out["cntV"], out["staticVal"], out["supVal"])
		}
		if out["boxNum"] != int64(20) || out["postCallSet"] != int64(15) || out["postCallAdd"] != int64(20) {
			t.Fatalf("unexpected post-call assignment: %#v", out)
		}
		if out["ternLeft"] != int64(77) || out["ternRight"] != int64(0) || out["ternVal"] != int64(77) {
			t.Fatalf("unexpected ternary + assignment: %#v", out)
		}
		if !reflect.DeepEqual(out["drained"], []any{"p", "q", "r"}) {
			t.Fatalf("unexpected while assignment drain: %#v", out["drained"])
		}

		// Also verify direct `_source.x = _source.y = 9` when `_source` is not pre-bound in params
		rawDoc := map[string]any{}
		gotExpr, err := evalRHSExpr(rawDoc, "_source.x = _source.y = 9", map[string]any{})
		if err != nil || gotExpr != int64(9) || rawDoc["x"] != int64(9) || rawDoc["y"] != int64(9) {
			t.Fatalf("unexpected _source direct expr assign: val=%#v err=%v doc=%#v", gotExpr, err, rawDoc)
		}
	})

	t.Run("AssignmentValidationErrors", func(t *testing.T) {
		assertEvalThrowsRound59(t, `
			class Dog {}
			class Cat {}
			Dog d = new Dog();
			def z = (d = new Cat());
		`, nil, "ClassCastException")

		assertEvalThrowsRound59(t, `
			int n = 1;
			def z = (n = null);
		`, nil, "NullPointerException")

		assertEvalThrowsRound59(t, `
			int n = 1;
			def z = (n = "not_an_int");
		`, nil, "ClassCastException")

		assertEvalThrowsRound59(t, `
			def z = (doc['x'].value = 5);
		`, nil, "UnsupportedOperationException")

		assertEvalThrowsRound59(t, `
			Map m = null;
			def z = (m.k = 1);
		`, nil, "NullPointerException")

		assertEvalThrowsRound59(t, `
			Map getNull() { return null; }
			def z = (getNull().k = 1);
		`, nil, "NullPointerException")
	})
}

func TestRound59_F21_TypeCasts(t *testing.T) {
	t.Run("NullReferenceCastsSucceedAndPrimitiveNullThrowsNPE", func(t *testing.T) {
		out := evalRound59Out(t, `
			class Item {}
			def n = null;
			ctx._source.out = [
				'str': (String) n,
				'cs': (CharSequence) n,
				'obj': (Object) n,
				'defc': (def) n,
				'list': (List) n,
				'map': (Map) n,
				'set': (Set) n,
				'col': (Collection) n,
				'num': (Number) n,
				'bd': (BigDecimal) n,
				'bi': (BigInteger) n,
				'bByte': (Byte) n,
				'bShort': (Short) n,
				'bInt': (Integer) n,
				'bLong': (Long) n,
				'bFloat': (Float) n,
				'bDouble': (Double) n,
				'bChar': (Character) n,
				'bBool': (Boolean) n,
				'intArr': (int[]) n,
				'strArr': (String[]) n,
				'objArr': (Object[]) n,
				'int2D': (int[][]) n,
				'userCls': (Item) n
			];
		`, nil)
		for k, v := range out {
			if v != nil {
				t.Errorf("expected null reference cast %q to return nil, got %#v", k, v)
			}
		}

		for _, prim := range []string{"byte", "short", "int", "long", "float", "double", "char", "boolean"} {
			assertEvalThrowsRound59(t, "def n = null; def x = ("+prim+") n;", nil, "NullPointerException")
		}
	})

	t.Run("ValidReferenceCollectionArrayUserClassCastsAndGrouping", func(t *testing.T) {
		out := evalRound59Out(t, `
			class Animal { String kind() { return "animal"; } }
			class Dog extends Animal { String bark() { return "woof"; } }

			int localVar = 41;
			int grouped = (localVar) + 1;

			boolean bTrue = (boolean) 1;
			boolean bFalse = (boolean) 0;
			Boolean boxedBool = (Boolean) true;

			Set s = new HashSet([1, 2]);
			List l = [3, 4];
			Map m = ['k': 9];
			int[] ia = new int[] { 10, 20 };
			String[] sa = new String[] { "x", "y" };
			int[][] mat = new int[2][3];
			Dog[] dogs = new Dog[] { new Dog() };

			Collection cFromSet = (Collection) s;
			Collection cFromList = (Collection) l;
			Set sCast = (Set) s;
			List lCast = (List) l;
			Map mCast = (Map) m;
			Number numInt = (Number) 42;
			Number numDec = (Number) new BigDecimal("3.14");
			CharSequence cs1 = (CharSequence) "hello";
			CharSequence cs2 = (CharSequence) new StringBuilder("sb");

			int[] iaCast = (int[]) ia;
			Object[] oaFromStr = (Object[]) sa;
			CharSequence[] csaFromStr = (CharSequence[]) sa;
			Object[] oaFromMat = (Object[]) mat;
			Animal[] animalsFromDogs = (Animal[]) dogs;

			Object rawDog = new Dog();
			Animal asAnimal = (Animal) rawDog;
			String barked = ((Dog) asAnimal).bark();

			char chA = (char) 'A';
			int chCode = (int) chA;
			Character boxedCh = (Character) 'Z';

			ctx._source.out = [
				'grouped': grouped,
				'bTrue': bTrue,
				'bFalse': bFalse,
				'boxedBool': boxedBool,
				'cSetSize': cFromSet.size(),
				'cListSize': cFromList.size(),
				'sCastSize': sCast.size(),
				'lCastSize': lCast.size(),
				'mCastVal': mCast['k'],
				'numInt': numInt,
				'numDec': numDec.toPlainString(),
				'cs1': cs1.length(),
				'cs2': cs2.toString(),
				'iaLen': iaCast.length,
				'oaStrLen': oaFromStr.length,
				'csaLen': csaFromStr.length,
				'oaMatLen': oaFromMat.length,
				'animArrLen': animalsFromDogs.length,
				'barked': barked,
				'chA': chA,
				'chCode': chCode,
				'boxedCh': boxedCh
			];
		`, nil)

		if out["grouped"] != int64(42) {
			t.Fatalf("expected (localVar) + 1 == 42, got %#v", out["grouped"])
		}
		if out["bTrue"] != true || out["bFalse"] != false || out["boxedBool"] != true {
			t.Fatalf("unexpected boolean casts: %#v", out)
		}
		if out["barked"] != "woof" || out["chCode"] != int64(65) || out["boxedCh"] != "Z" {
			t.Fatalf("unexpected user-class/char casts: %#v", out)
		}
	})

	t.Run("IncompatibleNonNullCastsThrowClassCastException", func(t *testing.T) {
		badScripts := []string{
			`def x = (String) 123;`,
			`def x = (CharSequence) 123;`,
			`def x = (List) ['a': 1];`,
			`Set s = new HashSet([1]); def x = (List) s;`,
			`int[] a = new int[]{1}; def x = (List) a;`,
			`def x = (Set) [1, 2];`,
			`def x = (Collection) "abc";`,
			`int[] a = new int[]{1}; def x = (Collection) a;`,
			`def x = (Map) [1, 2];`,
			`def s = new IntSummaryStatistics(); def x = (Map) s;`,
			`def x = (Number) "123";`,
			`def x = (BigDecimal) 123;`,
			`def x = (BigInteger) 123;`,
			`def x = (Boolean) 1;`,
			`def x = (boolean) "true";`,
			`def x = (int) "123";`,
			`def x = (Integer) "123";`,
			`def x = (double) [1];`,
			`def x = (char) "ab";`,
			`def x = (char) "";`,
			`def x = (char) true;`,
			`def x = (Character) "A";`,
			`def x = (Character) 65;`,
			`def x = (int[]) [1, 2];`,
			`int[] a = new int[]{1}; def x = (String[]) a;`,
			`int[] a = new int[]{1}; def x = (Object[]) a;`,
			`Set s = new HashSet([1]); def x = (Object[]) s;`,
			`class Animal {} class Dog extends Animal {} Animal a = new Animal(); def d = (Dog) a;`,
			`class Dog {} def d = (Dog) "not_a_dog";`,
		}
		for _, sc := range badScripts {
			assertEvalThrowsRound59(t, sc, nil, "ClassCastException")
		}
	})
}

func TestRound59_F22_SwitchNullNonCoerciveAndBlockScope(t *testing.T) {
	t.Run("SwitchNullSelectorThrowsNPE", func(t *testing.T) {
		assertEvalThrowsRound59(t, `
			def s = null;
			switch (s) {
				case 1: break;
				default: break;
			}
		`, nil, "NullPointerException")

		assertEvalThrowsRound59(t, `
			def s = null;
			def r = switch (s) {
				case 1 -> "one";
				default -> "other";
			};
		`, nil, "NullPointerException")
	})

	t.Run("NonCoerciveCaseMatchingAndErrorPropagation", func(t *testing.T) {
		out := evalRound59Out(t, `
			def m1 = switch ("01") {
				case "1" -> "wrong";
				default -> "no_match";
			};
			def m2 = switch ("1.0") {
				case 1 -> "wrong";
				default -> "no_match";
			};
			def m3 = switch ("2025-01-01T00:00:00Z") {
				case "2025-01-01" -> "wrong";
				default -> "no_match";
			};
			String stRes = "none";
			switch ("01") {
				case "1":
					stRes = "wrong";
					break;
				case "01":
					stRes = "exact";
					break;
			}
			int numSel = 65;
			String charMatch = switch (numSel) {
				case 'A' -> "matched_A";
				default -> "miss";
			};
			char chSel = 'B';
			String intMatch = switch (chSel) {
				case 66 -> "matched_66";
				default -> "miss";
			};
			ctx._source.out = [
				'm1': m1, 'm2': m2, 'm3': m3, 'stRes': stRes,
				'charMatch': charMatch, 'intMatch': intMatch
			];
		`, nil)

		if out["m1"] != "no_match" || out["m2"] != "no_match" || out["m3"] != "no_match" {
			t.Fatalf("unexpected coercive switch match: %#v", out)
		}
		if out["stRes"] != "exact" || out["charMatch"] != "matched_A" || out["intMatch"] != "matched_66" {
			t.Fatalf("unexpected exact/char switch results: %#v", out)
		}

		// Case expression evaluation error must propagate
		assertEvalThrowsRound59(t, `
			int x = 5;
			switch (x) {
				case 1 / 0:
					break;
				default:
					break;
			}
		`, nil, "ArithmeticException")

		assertEvalThrowsRound59(t, `
			int x = 5;
			def y = switch (x) {
				case 1 / 0 -> 1;
				default -> 2;
			};
		`, nil, "ArithmeticException")
	})

	t.Run("SwitchBlockScopedLocalsDoNotLeak", func(t *testing.T) {
		// Statement switch block-declared local cannot be read after exiting switch
		assertEvalThrowsRound59(t, `
			int sel = 1;
			switch (sel) {
				case 1:
					int inner = 99;
					break;
			}
			ctx._source.leak = inner;
		`, nil, "IllegalArgumentException")

		// Expression switch block-declared local cannot be read after exiting switch
		assertEvalThrowsRound59(t, `
			int sel = 1;
			int r = switch (sel) {
				case 1 -> {
					int innerExprVar = 77;
					yield innerExprVar;
				}
				default -> 0;
			};
			ctx._source.leak = innerExprVar;
		`, nil, "IllegalArgumentException")

		// Redeclaring the variable after switch and preserving outer mutated vars both succeed
		out := evalRound59Out(t, `
			int outer = 10;
			switch (1) {
				case 1:
					int scoped = 50;
					outer = outer + scoped;
					break;
			}
			String scoped = "redeclared_cleanly";
			int exprOut = switch (2) {
				case 2 -> {
					int scoped2 = 12;
					outer += scoped2;
					yield scoped2 * 2;
				}
				default -> 0;
			};
			String scoped2 = "also_redeclared";
			ctx._source.out = [
				'outer': outer,
				'scoped': scoped,
				'exprOut': exprOut,
				'scoped2': scoped2
			];
		`, nil)

		if out["outer"] != int64(72) || out["scoped"] != "redeclared_cleanly" || out["exprOut"] != int64(24) || out["scoped2"] != "also_redeclared" {
			t.Fatalf("unexpected switch block scope behavior: %#v", out)
		}
	})
}

func TestRound59_F23_UserFunctionsOverloadingTypesAndScope(t *testing.T) {
	t.Run("OverloadingByArityAndStrictArityErrors", func(t *testing.T) {
		out := evalRound59Out(t, `
			int compute() { return 10; }
			int compute(int a) { return a * 2; }
			int compute(int a, int b) { return a + b; }
			void bumpList(List items, int v) {
				items.add(v);
				return;
			}

			List bag = [1];
			def voidRes = bumpList(bag, 2);

			ctx._source.out = [
				'c0': compute(),
				'c1': compute(7),
				'c2': compute(3, 4),
				'bag': bag,
				'voidRes': voidRes
			];
		`, nil)

		if out["c0"] != int64(10) || out["c1"] != int64(14) || out["c2"] != int64(7) {
			t.Fatalf("unexpected overload dispatch results: %#v", out)
		}
		if !reflect.DeepEqual(out["bag"], []any{int64(1), int64(2)}) || out["voidRes"] != nil {
			t.Fatalf("unexpected void function result: %#v", out)
		}

		// Duplicate (name, arity) definition fails
		assertEvalThrowsRound59(t, `
			int dup(int a) { return a; }
			int dup(int x) { return x + 1; }
			ctx._source.out = ['v': dup(1)];
		`, nil, "IllegalArgumentException")

		// Calling existing function with unregistered arity throws IllegalArgumentException
		assertEvalThrowsRound59(t, `
			int add(int a, int b) { return a + b; }
			ctx._source.v = add(1, 2, 3);
		`, nil, "IllegalArgumentException")

		assertEvalThrowsRound59(t, `
			int add(int a, int b) { return a + b; }
			ctx._source.v = add(1);
		`, nil, "IllegalArgumentException")
	})

	t.Run("ParameterAndReturnTypeValidationAndVoidEnforcement", func(t *testing.T) {
		out := evalRound59Out(t, `
			class Badge {
				String code;
				Badge(String c) { this.code = c; }
			}
			byte toByte(int x) { return (byte) x; }
			String badgeCode(Badge b) { return b == null ? "none" : b.code; }
			Badge makeBadge(String c) { return new Badge(c); }

			ctx._source.out = [
				'narrow': toByte(300),
				'nullRefArg': badgeCode(null),
				'made': makeBadge("VIP").code
			];
		`, nil)

		if out["narrow"] != int64(44) || out["nullRefArg"] != "none" || out["made"] != "VIP" {
			t.Fatalf("unexpected typed user function results: %#v", out)
		}

		// Incompatible parameter types
		assertEvalThrowsRound59(t, `
			int f(int a) { return a; }
			ctx._source.v = f("bad");
		`, nil, "ClassCastException")

		assertEvalThrowsRound59(t, `
			int f(int a) { return a; }
			ctx._source.v = f(3.5);
		`, nil, "ClassCastException")

		assertEvalThrowsRound59(t, `
			int f(int a) { return a; }
			ctx._source.v = f(null);
		`, nil, "NullPointerException")

		assertEvalThrowsRound59(t, `
			boolean f(boolean b) { return b; }
			ctx._source.v = f(1);
		`, nil, "ClassCastException")

		// Incompatible return types & void return violations
		assertEvalThrowsRound59(t, `
			int badRet() { return "nope"; }
			ctx._source.v = badRet();
		`, nil, "ClassCastException")

		assertEvalThrowsRound59(t, `
			int nullPrimRet() { return null; }
			ctx._source.v = nullPrimRet();
		`, nil, "NullPointerException")

		assertEvalThrowsRound59(t, `
			void badVoid() { return 42; }
			badVoid();
		`, nil, "IllegalArgumentException")

		assertEvalThrowsRound59(t, `
			int emptyNonVoid() { return; }
			ctx._source.v = emptyNonVoid();
		`, nil, "IllegalArgumentException")
	})

	t.Run("StaticScopeIsolationPreservingParamsCtxAndDoc", func(t *testing.T) {
		// Caller script local variable is NOT visible inside static user function (read)
		assertEvalThrowsRound59(t, `
			int leakRead() { return callerSecret + 1; }
			int callerSecret = 42;
			ctx._source.v = leakRead();
		`, nil, "IllegalArgumentException")

		// Undeclared variable write inside static user function is rejected
		assertEvalThrowsRound59(t, `
			void leakWrite() { callerSecret = 99; }
			int callerSecret = 42;
			leakWrite();
		`, nil, "IllegalArgumentException")

		// Explicit params, ctx._source, and doc remain accessible inside user functions
		doc := map[string]any{"base": int64(100)}
		_, err := Eval(doc, `
			int calc(int x) {
				int localTmp = x * params.factor;
				return localTmp + (int) doc['base'].value + (int) ctx._source.base;
			}
			int callerOnly = 999;
			ctx._source.res = calc(5);
		`, map[string]any{"factor": int64(3)})
		if err != nil {
			t.Fatalf("unexpected error accessing params/doc/ctx._source in user func: %v", err)
		}
		if doc["res"] != int64(215) {
			t.Fatalf("expected 5*3 + 100 + 100 = 215, got %#v", doc["res"])
		}
	})
}

func TestRound59_F24_ArraysBoundsAndNullNPE(t *testing.T) {
	t.Run("NullArrayThrowsNPEWhileNullTolerantMethodsWork", func(t *testing.T) {
		npeScripts := []string{
			`int[] a = null; Arrays.sort(a);`,
			`int[] a = null; Arrays.sort(a, 0, 0);`,
			`int[] a = null; def i = Arrays.binarySearch(a, 1);`,
			`int[] a = null; def i = Arrays.binarySearch(a, 0, 0, 1);`,
			`int[] a = null; Arrays.fill(a, 1);`,
			`int[] a = null; Arrays.fill(a, 0, 0, 1);`,
			`int[] a = null; def c = Arrays.copyOf(a, 2);`,
			`int[] a = null; def c = Arrays.copyOfRange(a, 0, 1);`,
			`int[] a = null; def s = Arrays.stream(a).count();`,
			`int[] a = null; def s = Arrays.stream(a, 0, 0).count();`,
			`def l = Arrays.asList(null);`,
			`Object[] a = null; def l = Arrays.asList(a);`,
			`int[] a = null; Arrays.setAll(a, i -> i);`,
			`int[] a = null; Arrays.parallelPrefix(a, (x, y) -> x + y);`,
		}
		for _, sc := range npeScripts {
			assertEvalThrowsRound59(t, sc, nil, "NullPointerException")
		}

		// Null-tolerant methods and single-null-element varargs `Arrays.asList((Object) null)` continue to succeed
		out := evalRound59Out(t, `
			int[] a = null;
			int[] b = new int[]{1, 2};
			int[][] nested = new int[][]{new int[]{1, 2}, new int[]{3}};
			List singleNull = Arrays.asList((Object) null);
			ctx._source.out = [
				'toStr': Arrays.toString(a),
				'deepStr': Arrays.deepToString(a),
				'eq': Arrays.equals(a, null),
				'deepEq': Arrays.deepEquals(a, null),
				'hc': Arrays.hashCode(a),
				'hcNonNull': Arrays.hashCode(b),
				'deepHc': Arrays.deepHashCode(nested),
				'singleNullLen': singleNull.size(),
				'singleNullElem': singleNull.get(0)
			];
		`, nil)

		if out["toStr"] != "null" || out["deepStr"] != "null" || out["eq"] != true || out["deepEq"] != true || out["hc"] != int64(0) {
			t.Fatalf("unexpected null-tolerant Arrays behavior: %#v", out)
		}
		if out["hcNonNull"] != int64(31*(31+1)+2) || out["deepHc"] != int64(31*(31+994)+(31+3)) {
			t.Fatalf("unexpected Arrays.hashCode/deepHashCode: %#v", out)
		}
		if out["singleNullLen"] != int64(1) || out["singleNullElem"] != nil {
			t.Fatalf("unexpected Arrays.asList((Object) null): %#v", out)
		}
	})

	t.Run("CopyOfCopyOfRangeAndRangeCheckExceptionsAndPadding", func(t *testing.T) {
		assertEvalThrowsRound59(t, `
			int[] a = new int[] { 1, 2, 3 };
			def b = Arrays.copyOf(a, -1);
		`, nil, "NegativeArraySizeException")

		// copyOfRange: from > to -> IllegalArgumentException FIRST (even when from < 0 or from > len)
		assertEvalThrowsRound59(t, `
			int[] a = new int[] { 1, 2, 3 };
			def b = Arrays.copyOfRange(a, 3, 1);
		`, nil, "IllegalArgumentException")
		assertEvalThrowsRound59(t, `
			int[] a = new int[] { 1, 2, 3 };
			def b = Arrays.copyOfRange(a, -1, -2);
		`, nil, "IllegalArgumentException")
		assertEvalThrowsRound59(t, `
			int[] a = new int[] { 1, 2, 3 };
			def b = Arrays.copyOfRange(a, 5, 4);
		`, nil, "IllegalArgumentException")

		// copyOfRange: from < 0 || from > len -> ArrayIndexOutOfBoundsException
		assertEvalThrowsRound59(t, `
			int[] a = new int[] { 1, 2, 3 };
			def b = Arrays.copyOfRange(a, -1, 2);
		`, nil, "ArrayIndexOutOfBoundsException")
		assertEvalThrowsRound59(t, `
			int[] a = new int[] { 1, 2, 3 };
			def b = Arrays.copyOfRange(a, 4, 5);
		`, nil, "ArrayIndexOutOfBoundsException")

		// Range-taking sort, binarySearch, fill, stream, parallelPrefix
		rangeIllegalScripts := []string{
			`int[] a = new int[]{3, 1, 2}; Arrays.sort(a, 2, 1);`,
			`int[] a = new int[]{1, 2, 3}; def i = Arrays.binarySearch(a, 2, 1, 2);`,
			`int[] a = new int[]{1, 2, 3}; Arrays.fill(a, 2, 1, 9);`,
			`int[] a = new int[]{1, 2, 3}; def c = Arrays.stream(a, 2, 1).count();`,
			`int[] a = new int[]{1, 2, 3}; Arrays.parallelPrefix(a, 2, 1, (x, y) -> x + y);`,
		}
		for _, sc := range rangeIllegalScripts {
			assertEvalThrowsRound59(t, sc, nil, "IllegalArgumentException")
		}

		rangeOOBScripts := []string{
			`int[] a = new int[]{3, 1, 2}; Arrays.sort(a, -1, 2);`,
			`int[] a = new int[]{3, 1, 2}; Arrays.sort(a, 0, 4);`,
			`int[] a = new int[]{1, 2, 3}; def i = Arrays.binarySearch(a, -1, 2, 2);`,
			`int[] a = new int[]{1, 2, 3}; def i = Arrays.binarySearch(a, 0, 4, 2);`,
			`int[] a = new int[]{1, 2, 3}; Arrays.fill(a, -1, 2, 9);`,
			`int[] a = new int[]{1, 2, 3}; Arrays.fill(a, 0, 4, 9);`,
			`int[] a = new int[]{1, 2, 3}; def c = Arrays.stream(a, -1, 2).count();`,
			`int[] a = new int[]{1, 2, 3}; def c = Arrays.stream(a, 0, 4).count();`,
			`int[] a = new int[]{1, 2, 3}; Arrays.parallelPrefix(a, 0, 4, (x, y) -> x + y);`,
		}
		for _, sc := range rangeOOBScripts {
			assertEvalThrowsRound59(t, sc, nil, "ArrayIndexOutOfBoundsException")
		}

		// Valid copyOf / copyOfRange with typed default padding + valid subrange sort/fill/binarySearch/stream
		out := evalRound59Out(t, `
			int[] ia = new int[] { 5, 2, 8, 1 };
			int[] cpInt = Arrays.copyOf(ia, 6);
			int[] cprInt = Arrays.copyOfRange(ia, 2, 5);
			int[] emptyAtEnd = Arrays.copyOfRange(ia, 4, 4);
			boolean[] ba = new boolean[] { true };
			boolean[] cpBool = Arrays.copyOf(ba, 3);
			String[] sa = new String[] { "a" };
			String[] cpStr = Arrays.copyOfRange(sa, 0, 3);

			Arrays.sort(ia, 1, 4);
			int bsIdx = Arrays.binarySearch(ia, 1, 4, 2);
			long subSum = Arrays.stream(ia, 1, 3).sum();
			Arrays.fill(ia, 0, 2, 9);

			ctx._source.out = [
				'cpInt': cpInt,
				'cprInt': cprInt,
				'emptyAtEnd': emptyAtEnd,
				'cpBool': cpBool,
				'cpStr': cpStr,
				'iaAfter': ia,
				'bsIdx': bsIdx,
				'subSum': subSum
			];
		`, nil)

		if !reflect.DeepEqual(out["cpInt"], []any{int64(5), int64(2), int64(8), int64(1), int64(0), int64(0)}) {
			t.Fatalf("unexpected cpInt padding: %#v", out["cpInt"])
		}
		if !reflect.DeepEqual(out["cprInt"], []any{int64(8), int64(1), int64(0)}) {
			t.Fatalf("unexpected cprInt padding: %#v", out["cprInt"])
		}
		if !reflect.DeepEqual(out["emptyAtEnd"], []any{}) {
			t.Fatalf("expected empty copyOfRange(4, 4), got %#v", out["emptyAtEnd"])
		}
		if !reflect.DeepEqual(out["cpBool"], []any{true, false, false}) {
			t.Fatalf("unexpected cpBool padding: %#v", out["cpBool"])
		}
		if !reflect.DeepEqual(out["cpStr"], []any{"a", nil, nil}) {
			t.Fatalf("unexpected cpStr padding: %#v", out["cpStr"])
		}
		if out["bsIdx"] != int64(2) || out["subSum"] != int64(3) || !reflect.DeepEqual(out["iaAfter"], []any{int64(9), int64(9), int64(2), int64(8)}) {
			t.Fatalf("unexpected range sort/bs/stream/fill results: %#v", out)
		}
	})
}

func TestRound59_F25_ListCollectionMapBoundsAndNullNPE(t *testing.T) {
	t.Run("StrictListIndexBoundsAndSetVsListRemoveOverloads", func(t *testing.T) {
		oobScripts := []string{
			`List l = [10, 20]; def x = l.get(-1);`,
			`List l = [10, 20]; def x = l.get(2);`,
			`def x = [10, 20].get(-1);`,
			`List l = [10, 20]; l.set(-1, 99);`,
			`List l = [10, 20]; def old = l.set(2, 99);`,
			`List l = [10, 20]; l.remove(-1);`,
			`List l = [10, 20]; def r = l.remove(2);`,
			`ctx._source.l = [10, 20]; ctx._source.l.remove(5);`,
			`List l = [10, 20]; l.add(-1, 5);`,
			`List l = [10, 20]; l.add(3, 5);`,
			`ctx._source.l = [10, 20]; ctx._source.l.add(3, 5);`,
			`List l = [10, 20]; l.addAll(-1, []);`,
			`List l = [10, 20]; l.addAll(3, []);`,
			`List l = [10, 20]; boolean c = l.addAll(99, []);`,
			`ctx._source.l = [10, 20]; ctx._source.l.addAll(99, []);`,
		}
		for _, sc := range oobScripts {
			assertEvalThrowsRound59(t, sc, nil, "IndexOutOfBoundsException")
		}

		// Valid boundary operations + Set.remove(int) by element + List.remove(Object) for non-int
		out := evalRound59Out(t, `
			List l = [10, 20, 30];
			int removedAt1 = l.remove(1);
			l.add(2, 40);
			boolean emptyAddedAtEnd = l.addAll(3, []);
			boolean addedAtStart = l.addAll(0, [5]);
			int oldAt2 = l.set(2, 35);

			List strList = ["a", "b", "c"];
			boolean remStrHit = strList.remove("b");
			boolean remStrMiss = strList.remove("z");
			boolean remBoxedInt = l.remove(Integer.valueOf(40));

			Set s = new HashSet([10, 20, 30]);
			boolean setRemHit = s.remove(20);
			boolean setRemMiss = s.remove(99);

			ctx._source.out = [
				'removedAt1': removedAt1,
				'emptyAddedAtEnd': emptyAddedAtEnd,
				'addedAtStart': addedAtStart,
				'oldAt2': oldAt2,
				'l': l,
				'strList': strList,
				'remStrHit': remStrHit,
				'remStrMiss': remStrMiss,
				'remBoxedInt': remBoxedInt,
				'sSize': s.size(),
				'setRemHit': setRemHit,
				'setRemMiss': setRemMiss
			];
		`, nil)

		if out["removedAt1"] != int64(20) || out["emptyAddedAtEnd"] != false || out["addedAtStart"] != true || out["oldAt2"] != int64(30) {
			t.Fatalf("unexpected List index operations: %#v", out)
		}
		if !reflect.DeepEqual(out["l"], []any{int64(5), int64(10), int64(35)}) || out["remBoxedInt"] != true {
			t.Fatalf("unexpected List contents after Integer.valueOf remove: %#v", out["l"])
		}
		if !reflect.DeepEqual(out["strList"], []any{"a", "c"}) || out["remStrHit"] != true || out["remStrMiss"] != false {
			t.Fatalf("unexpected List.remove(String): %#v", out)
		}
		if out["sSize"] != int64(2) || out["setRemHit"] != true || out["setRemMiss"] != false {
			t.Fatalf("unexpected Set.remove(10): %#v", out)
		}
	})

	t.Run("NullCollectionAndMapArgumentsThrowNPE", func(t *testing.T) {
		npeColMapScripts := []string{
			`List l = [1, 2]; l.addAll(null);`,
			`List l = [1, 2]; boolean c = l.addAll(null);`,
			`List l = [1, 2]; l.addAll(1, null);`,
			`List l = [1, 2]; boolean c = l.addAll(1, null);`,
			`ctx._source.l = [1, 2]; ctx._source.l.addAll(null);`,
			`ctx._source.l = [1, 2]; ctx._source.l.addAll(0, null);`,
			`List l = [1, 2]; l.removeAll(null);`,
			`List l = [1, 2]; boolean c = l.removeAll(null);`,
			`ctx._source.l = [1, 2]; ctx._source.l.removeAll(null);`,
			`List l = [1, 2]; l.retainAll(null);`,
			`List l = [1, 2]; boolean c = l.retainAll(null);`,
			`ctx._source.l = [1, 2]; ctx._source.l.retainAll(null);`,
			`List l = [1, 2]; boolean c = l.containsAll(null);`,
			`Map m = ['a': 1]; m.putAll(null);`,
			`Map m = ['a': 1]; def x = m.putAll(null);`,
			`ctx._source.m = ['a': 1]; ctx._source.m.putAll(null);`,
		}
		for _, sc := range npeColMapScripts {
			assertEvalThrowsRound59(t, sc, nil, "NullPointerException")
		}

		// Also verify addAll(badIdx, null) checks index bounds first per JDK ArrayList.addAll(index, c)
		assertEvalThrowsRound59(t, `
			List l = [1, 2];
			l.addAll(5, null);
		`, nil, "IndexOutOfBoundsException")
	})
}

func TestRound59_F26_LazyStreamsUnboundedRangeAndFlatMap(t *testing.T) {
	t.Run("LazyShortCircuitingStopsUpstreamEvaluationImmediately", func(t *testing.T) {
		out := evalRound59Out(t, `
			// findFirst / findAny do not evaluate downstream elements that would divide by zero
			int firstSafe = [2, 5, 0].stream().map(x -> 10 / x).findFirst().get();
			int anySafe = [4, 0].stream().map(x -> 20 / x).findAny().get();

			// limit(n) & limit(0) stop pulling upstream elements immediately
			List visitedLimit2 = [];
			List lim2 = [1, 2, 3, 4, 5].stream().peek(x -> visitedLimit2.add(x)).limit(2).toList();

			List visitedLimit0 = [];
			List lim0 = [1, 2, 3].stream().peek(x -> visitedLimit0.add(x)).map(x -> 1 / 0).limit(0).toList();

			// takeWhile stops on first false predicate without pulling remaining elements
			List visitedTake = [];
			List taken = [2, 4, 7, 0].stream().peek(x -> visitedTake.add(x)).takeWhile(x -> x < 5).map(x -> 100 / x).toList();

			// anyMatch, allMatch, noneMatch short-circuit immediately without evaluating trailing 1 / x on 0
			boolean anyHit = [1, 2, 0].stream().map(x -> 10 / x).anyMatch(v -> v == 5);
			boolean allFailFast = [2, 5, 0].stream().map(x -> 10 / x).allMatch(v -> v == 5);
			boolean noneFailFast = [2, 5, 0].stream().map(x -> 10 / x).noneMatch(v -> v == 2);

			// Pipeline combining dropWhile, skip, distinct, sorted barrier, mapToInt/Double, forEach
			List afterBarrier = [5, 3, 3, 1, 4, 2, 1].stream()
				.distinct()
				.sorted()
				.skip(1)
				.limit(3)
				.toList();

			double dblSum = [1, 2, 3].stream().mapToDouble(x -> x * 1.5).sum();
			long asLongSum = IntStream.rangeClosed(1, 4).asLongStream().sum();
			double asDblSum = IntStream.rangeClosed(1, 3).asDoubleStream().sum();
			List dropped = [1, 2, 5, 1, 6].stream().dropWhile(x -> x < 4).toList();

			List feOut = [];
			IntStream.range(1, 100000).limit(4).forEach(x -> { feOut.add(x * 10); });

			ctx._source.out = [
				'firstSafe': firstSafe,
				'anySafe': anySafe,
				'lim2': lim2,
				'visitedLimit2': visitedLimit2,
				'lim0': lim0,
				'visitedLimit0': visitedLimit0,
				'taken': taken,
				'visitedTake': visitedTake,
				'anyHit': anyHit,
				'allFailFast': allFailFast,
				'noneFailFast': noneFailFast,
				'afterBarrier': afterBarrier,
				'dblSum': dblSum,
				'asLongSum': asLongSum,
				'asDblSum': asDblSum,
				'dropped': dropped,
				'feOut': feOut
			];
		`, nil)

		if out["firstSafe"] != int64(5) || out["anySafe"] != int64(5) {
			t.Fatalf("unexpected findFirst/findAny results: %#v", out)
		}
		if !reflect.DeepEqual(out["lim2"], []any{int64(1), int64(2)}) || !reflect.DeepEqual(out["visitedLimit2"], []any{int64(1), int64(2)}) {
			t.Fatalf("expected limit(2) to visit only 2 elements, got lim2=%#v visited=%#v", out["lim2"], out["visitedLimit2"])
		}
		if !reflect.DeepEqual(out["lim0"], []any{}) || !reflect.DeepEqual(out["visitedLimit0"], []any{}) {
			t.Fatalf("expected limit(0) to pull 0 elements, got lim0=%#v visited=%#v", out["lim0"], out["visitedLimit0"])
		}
		if !reflect.DeepEqual(out["taken"], []any{int64(50), int64(25)}) || !reflect.DeepEqual(out["visitedTake"], []any{int64(2), int64(4), int64(7)}) {
			t.Fatalf("unexpected takeWhile short-circuit: taken=%#v visited=%#v", out["taken"], out["visitedTake"])
		}
		if out["anyHit"] != true || out["allFailFast"] != false || out["noneFailFast"] != false {
			t.Fatalf("unexpected match short-circuit results: %#v", out)
		}
		if !reflect.DeepEqual(out["afterBarrier"], []any{int64(2), int64(3), int64(4)}) {
			t.Fatalf("unexpected distinct+sorted+skip+limit: %#v", out["afterBarrier"])
		}
		if out["dblSum"] != float64(9.0) || out["asLongSum"] != int64(10) || out["asDblSum"] != float64(6.0) {
			t.Fatalf("unexpected primitive stream conversions: %#v", out)
		}
		if !reflect.DeepEqual(out["dropped"], []any{int64(5), int64(1), int64(6)}) {
			t.Fatalf("unexpected dropWhile: %#v", out["dropped"])
		}
		if !reflect.DeepEqual(out["feOut"], []any{int64(10), int64(20), int64(30), int64(40)}) {
			t.Fatalf("unexpected lazy forEach: %#v", out["feOut"])
		}
	})

	t.Run("UnboundedLazyIntAndLongRangesAndMaterializationCap", func(t *testing.T) {
		out := evalRound59Out(t, `
			long sum20k = IntStream.rangeClosed(1, 20000).sum();
			long cnt15k = IntStream.range(0, 15000).count();
			List hugePrefix = LongStream.range(0L, 1000000000L).limit(3).boxed().toList();
			List emptyRange = IntStream.range(5, 2).boxed().toList();
			List emptyClosed = LongStream.rangeClosed(5L, 4L).boxed().toList();
			List catPrefix = IntStream.concat(IntStream.range(1, 3), IntStream.range(100, 100000000)).limit(4).boxed().toList();

			ctx._source.out = [
				'sum20k': sum20k,
				'cnt15k': cnt15k,
				'hugePrefix': hugePrefix,
				'emptyRange': emptyRange,
				'emptyClosed': emptyClosed,
				'catPrefix': catPrefix
			];
		`, nil)

		if out["sum20k"] != int64(200010000) {
			t.Fatalf("expected IntStream.rangeClosed(1, 20000).sum() == 200010000, got %#v", out["sum20k"])
		}
		if out["cnt15k"] != int64(15000) {
			t.Fatalf("expected IntStream.range(0, 15000).count() == 15000, got %#v", out["cnt15k"])
		}
		if !reflect.DeepEqual(out["hugePrefix"], []any{int64(0), int64(1), int64(2)}) {
			t.Fatalf("unexpected LongStream.range(0, 1e9).limit(3): %#v", out["hugePrefix"])
		}
		if !reflect.DeepEqual(out["emptyRange"], []any{}) || !reflect.DeepEqual(out["emptyClosed"], []any{}) {
			t.Fatalf("expected empty inverted ranges, got %#v / %#v", out["emptyRange"], out["emptyClosed"])
		}
		if !reflect.DeepEqual(out["catPrefix"], []any{int64(1), int64(2), int64(100), int64(101)}) {
			t.Fatalf("unexpected IntStream.concat lazy prefix: %#v", out["catPrefix"])
		}

		// Materializing > MaxPainlessSliceItems fails cleanly
		_, err := Eval(map[string]any{}, `ctx._source.big = IntStream.range(0, 20000).boxed().toList();`, nil)
		if err == nil {
			t.Fatal("expected error when materializing 20,000 stream elements into toList()")
		}

		// Negative limit / skip throw IllegalArgumentException
		assertEvalThrowsRound59(t, `ctx._source.v = [1, 2].stream().limit(-1).toList();`, nil, "IllegalArgumentException")
		assertEvalThrowsRound59(t, `ctx._source.v = [1, 2].stream().skip(-1).toList();`, nil, "IllegalArgumentException")
	})

	t.Run("FlatMapLazyShortCircuitNullEmptyAndInvalidReturnClassCastException", func(t *testing.T) {
		out := evalRound59Out(t, `
			// flatMap accepts null (treated as empty stream), Stream, List, Set, typed array, and range streams lazily
			List flatNullAndStreams = [null, [1, 2], [], [3]].stream()
				.flatMap(x -> x == null ? null : x.stream())
				.toList();

			List flatRangeShortCircuit = [1, 2, 0].stream()
				.flatMapToInt(x -> IntStream.range(10 / x, (10 / x) + 1000000))
				.limit(3)
				.boxed()
				.toList();

			long flatLongSum = [1, 2].stream()
				.flatMapToLong(x -> LongStream.rangeClosed(1L, (long) x))
				.sum();

			double flatDblSum = [[1.5, 2.5], null, [3.0]].stream()
				.flatMapToDouble(x -> x == null ? null : x.stream())
				.sum();

			ctx._source.out = [
				'flatNullAndStreams': flatNullAndStreams,
				'flatRangeShortCircuit': flatRangeShortCircuit,
				'flatLongSum': flatLongSum,
				'flatDblSum': flatDblSum
			];
		`, nil)

		if !reflect.DeepEqual(out["flatNullAndStreams"], []any{int64(1), int64(2), int64(3)}) {
			t.Fatalf("unexpected flatNullAndStreams: %#v", out["flatNullAndStreams"])
		}
		if !reflect.DeepEqual(out["flatRangeShortCircuit"], []any{int64(10), int64(11), int64(12)}) {
			t.Fatalf("unexpected flatRangeShortCircuit: %#v", out["flatRangeShortCircuit"])
		}
		if out["flatLongSum"] != int64(4) || out["flatDblSum"] != float64(7.0) {
			t.Fatalf("unexpected flatMapToLong/Double sums: %#v", out)
		}

		// Non-null non-stream scalar or Map return from flatMap throws ClassCastException
		assertEvalThrowsRound59(t, `
			ctx._source.v = [1, 2].stream().flatMap(x -> x * 2).toList();
		`, nil, "ClassCastException")

		assertEvalThrowsRound59(t, `
			ctx._source.v = [1, 2].stream().flatMap(x -> "not_a_stream").toList();
		`, nil, "ClassCastException")

		assertEvalThrowsRound59(t, `
			ctx._source.v = [1, 2].stream().flatMap(x -> ['a': x]).toList();
		`, nil, "ClassCastException")
	})
}
