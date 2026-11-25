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
	"fmt"
	"strings"
	"testing"
)

func TestRound66_EvalClearBitSetListTemporalBranches(t *testing.T) {
	// 1. Update scripts exercising ctx._source.clear(), relPath clear(), BitSet clear/set ranges, List.set(), and compound assign
	srcJSON := json.RawMessage(`{
		"sub": {"k": "v"},
		"arr": ["a", "b", "c"],
		"cnt": 10,
		"items": [{"qty": 3}],
		"tags": ["t1", "t2"]
	}`)
	out, op, err := ApplyUpdateWithResult(srcJSON, &UpdateRequest{
		Script: &ScriptSpec{
			Source: `
				ctx._source.sub.clear();
				ctx._source.cnt += 5;
				ctx._source.items[0].qty += 4;
				ctx._source.arr.set(1, 'B');
				List localList = new ArrayList();
				localList.add('x');
				localList.add('y');
				String prev = localList.set(0, 'X');
				localList.clear();
				Map localMap = new HashMap();
				localMap.put('a', 1);
				localMap.clear();
				BitSet bs = new BitSet();
				bs.set(1);
				bs.set(3, 6);
				bs.set(4, 7, false);
				bs.set(8, 10, true);
				bs.clear();
				ctx._source.prev = prev;
				ctx._source.tags.clear();
			`,
		},
	}, true)
	if err != nil || op != "updated" {
		t.Fatalf("ApplyUpdateWithResult failed: op=%q err=%v out=%s", op, err, string(out))
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal updated doc failed: %v", err)
	}
	if cnt, _ := doc["cnt"].(float64); cnt != 15 {
		t.Fatalf("expected cnt=15, got %v", doc["cnt"])
	}
	if doc["prev"] != "x" {
		t.Fatalf("expected prev='x', got %v", doc["prev"])
	}
	if sub, _ := doc["sub"].(map[string]any); len(sub) != 0 {
		t.Fatalf("expected sub cleared, got %v", sub)
	}
	if arr, _ := doc["arr"].([]any); len(arr) != 3 || arr[1] != "B" {
		t.Fatalf("expected arr[1]='B', got %v", arr)
	}
	if tags, _ := doc["tags"].([]any); len(tags) != 0 {
		t.Fatalf("expected tags cleared, got %v", tags)
	}

	// NullPointerException on null.clear() vs safe-nav clear()
	if _, err := Eval(nil, `def m = null; m?.clear(); return 'ok';`, nil); err != nil {
		t.Fatalf("expected safe-nav null?.clear() to succeed, got %v", err)
	}
	for _, errScript := range []string{
		`def m = null; m.clear(); return 1;`,
		`BitSet bs = new BitSet(); bs.set(0, 99999999);`,
		`BitSet bs = new BitSet(); bs.set(0, 99999999, true);`,
	} {
		if _, err := Eval(map[string]any{}, errScript, map[string]any{}); err == nil {
			t.Fatalf("expected error for script %s", errScript)
		}
	}
	for _, errUpd := range []string{
		`ctx.items[0].qty += 4;`,
	} {
		if _, _, err := ApplyUpdateWithResult(srcJSON, &UpdateRequest{Script: &ScriptSpec{Source: errUpd}}, true); err == nil {
			t.Fatalf("expected error for update script %s", errUpd)
		}
	}

	// 2. Clear top-level ctx._source
	cleared, _, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `ctx._source.clear();`},
	}, true)
	if err != nil || strings.TrimSpace(string(cleared)) != "{}" {
		t.Fatalf("expected ctx._source.clear() -> {}, got %s (err=%v)", string(cleared), err)
	}

	// 3. Local compound assignment and update metadata get/error guards
	resLocal, err := Eval(nil, `int s = 2; s += 3; s *= 4; s -= 2; s /= 3; return s;`, nil)
	if err != nil || resLocal != int64(6) {
		t.Fatalf("expected local compound arithmetic = 6, got %#v (err=%v)", resLocal, err)
	}

	// 4. Temporal isSupported / with / until / datesUntil / ChronoUnit.between / atOffset (eval.go:11400-11500)
	tempRes, err := Eval(nil, `
		def zdt = ZonedDateTime.parse('2025-03-01T10:15:30Z');
		def inst = zdt.toInstant();
		def ld1 = LocalDate.of(2025, 3, 1);
		def ld2 = LocalDate.of(2025, 3, 5);
		def withDay = ld1.with(ChronoField.DAY_OF_MONTH, 15);
		def withAdj = ld1.with(TemporalAdjusters.lastDayOfMonth());
		def untilP = ld1.until(ld2);
		def untilDays = ld1.until(ld2, ChronoUnit.DAYS);
		def betHours = ChronoUnit.HOURS.between(zdt, zdt.plusHours(3));
		def datesList = ld1.datesUntil(ld2).collect(Collectors.toList());
		def datesStep = ld1.datesUntil(ld2, Period.ofDays(2)).collect(Collectors.toList());
		def supInstYear = inst.isSupported(ChronoField.YEAR);
		def supInstMillis = inst.isSupported(ChronoUnit.MILLIS);
		def supZdtMonth = zdt.isSupported(ChronoField.MONTH_OF_YEAR);
		def ldtOff = LocalDateTime.of(2025, 3, 1, 12, 0).atOffset(ZoneOffset.ofHours(-5));
		return [
			'withDay': withDay.getDayOfMonth(),
			'withAdj': withAdj.getDayOfMonth(),
			'untilP': untilP.getDays(),
			'untilDays': untilDays,
			'betHours': betHours,
			'datesLen': datesList.size(),
			'datesStepLen': datesStep.size(),
			'supInstYear': supInstYear,
			'supInstMillis': supInstMillis,
			'supZdtMonth': supZdtMonth,
			'ldtOff': ldtOff.toString()
		];
	`, nil)
	if err != nil {
		t.Fatalf("temporal eval failed: %v", err)
	}
	tm, _ := tempRes.(map[string]any)
	if tm["withDay"] != int64(15) || tm["withAdj"] != int64(31) || tm["untilP"] != int64(4) ||
		tm["untilDays"] != int64(4) || tm["betHours"] != int64(3) || tm["datesLen"] != int64(4) ||
		tm["datesStepLen"] != int64(2) || tm["supInstYear"] != false || tm["supInstMillis"] != true || tm["supZdtMonth"] != true {
		t.Fatalf("unexpected temporal eval map: %+v", tm)
	}
	for _, errTemp := range []string{
		`Instant.ofEpochMilli(1000).with(ChronoField.YEAR, 2025);`,
		`ZonedDateTime.parse('2025-03-01T00:00:00Z').with(null, 1);`,
	} {
		if _, err := Eval(nil, errTemp, nil); err == nil {
			t.Fatalf("expected error for %s", errTemp)
		}
	}
}

func TestRound66_Round60FieldValLambdasDecayVectorBranches(t *testing.T) {
	// 1. Lambdas: apply, accept, applyAsInt, applyAsLong, applyAsDouble, test
	lamRes, err := Eval(nil, `
		def f = x -> x + '!';
		def st = [:];
		def c = x -> { st.seen = x; };
		c.accept('hi');
		def iu = x -> x + 1;
		def lu = x -> x + 2L;
		def du = x -> x * 2.5;
		def p = x -> x > 3;
		return [
			'f': f.apply('ok'),
			'iu': iu.applyAsInt(4),
			'lu': lu.applyAsLong(5L),
			'du': du.applyAsDouble(2.0),
			'p': p.test(5),
			'seen': st.seen
		];
	`, map[string]any{})
	if err != nil {
		t.Fatalf("lambda eval failed: %v", err)
	}
	lm, _ := lamRes.(map[string]any)
	if lm["f"] != "ok!" || lm["iu"] != int64(5) || lm["lu"] != int64(7) || lm["du"] != 5.0 || lm["p"] != true || lm["seen"] != "hi" {
		t.Fatalf("unexpected lambda result: %+v", lm)
	}

	// 2. FieldVal asBigInteger / asLong / asDouble / asDate / asGeoPoint / asString / getValues / deduplicate + FieldDocVal write/read
	doc := map[string]any{
		"num":    "42",
		"dbl":    "3.5",
		"dt":     "2025-02-01T00:00:00Z",
		"gp":     "37.7,-122.4",
		"empty":  nil,
		"dup":    []any{1, 2, 1},
		"vec":    []any{1.0, 0.0, 0.0},
		"badnum": "not_num",
	}
	fTypes := map[string]string{"num": "keyword", "dbl": "keyword", "dt": "keyword", "gp": "keyword", "empty": "keyword", "dup": "long", "vec": "dense_vector", "badnum": "keyword"}
	emitted, err := EvalEmitContext(`
		def bi0 = field('num').asBigInteger();
		def bi2 = field('empty').asBigInteger(9, '99');
		def biMiss = field('empty').asBigInteger('77');
		def l0 = field('num').asLong();
		def l2 = field('num').asLong(5, 88L);
		def d0 = field('dbl').asDouble();
		def d2 = field('dbl').asDouble(5, 9.5);
		def dt0 = field('dt').asDate();
		def dt2 = field('dt').asDate(5, ZonedDateTime.parse('2020-01-01T00:00:00Z'));
		def gp0 = field('gp').asGeoPoint();
		def gp2 = field('gp').asGeoPoint(5, 'default_gp');
		def s0 = field('num').asString();
		def s2 = field('empty').asString(5, null);
		def sMiss = field('empty').asString('fallback');
		def vals = field('dup').deduplicate().getValues();
		emit(bi0.toString() + ':' + bi2.toString() + ':' + biMiss.toString() + ':' + l0 + ':' + l2 + ':' + d0 + ':' + d2 + ':' + dt0.getYear() + ':' + dt2.getYear() + ':' + gp0.getLat() + ':' + gp2 + ':' + s0 + ':' + (s2 == null) + ':' + sMiss + ':' + vals.size());
	`, "keyword", doc, doc, map[string]any{}, fTypes)
	if err != nil || len(emitted) != 1 || emitted[0] != "42:99:77:42:88:3.5:9.5:2025:2020:37.7:default_gp:42:true:fallback:2" {
		t.Fatalf("unexpected FieldVal emit: emitted=%v err=%v", emitted, err)
	}

	// FieldVal error paths (cannot parse as double / date / geo_point)
	for _, badSrc := range []string{
		`return field('badnum').asDouble();`,
		`return field('badnum').asDate();`,
		`return field('badnum').asGeoPoint();`,
	} {
		if _, err := EvalEmitContext(badSrc, "keyword", doc, doc, nil, fTypes); err == nil {
			t.Fatalf("expected parse error for %s", badSrc)
		}
	}

	// 3. decayNumeric / decayDate / decayGeo / randomScore / vector similarity errors
	decRes, err := Eval(doc, `
		def dn = decayNumericLinear(10.0, 5.0, 1.0, 0.5, 13.0);
		def de = decayNumericExp(10.0, 5.0, 1.0, 0.5, 13.0);
		def dg = decayNumericGauss(10.0, 5.0, 1.0, 0.5, 13.0);
		def dd = decayDateLinear('2025-01-01T00:00:00Z', '2d', '0d', 0.5, '2025-01-02T00:00:00Z');
		def dgeo = decayGeoExp('37.7,-122.4', '10km', '0km', 0.5, '37.75,-122.4');
		def rs1 = randomScore(42);
		def rs2 = randomScore(42, 'num');
		def rsSeq = randomScore(42, '_seq_no');
		return ['dn': dn, 'de': de, 'dg': dg, 'dd': dd, 'dgeo': dgeo, 'rs': (rs1 >= 0 && rs1 < 1 && rs2 >= 0 && rsSeq >= 0)];
	`, map[string]any{"_seq_no": int64(7)})
	if err != nil {
		t.Fatalf("decay/randomScore eval failed: %v", err)
	}
	dm, _ := decRes.(map[string]any)
	if dm["rs"] != true {
		t.Fatalf("expected valid randomScore outputs, got %+v", dm)
	}
	for _, errDecay := range []string{
		`decayNumericLinear(10.0, 5.0);`,
		`decayNumericLinear('bad', 5.0, 1.0, 0.5, 10.0);`,
		`decayDateLinear('bad', '1d', '0d', 0.5, '2025-01-01');`,
		`decayDateLinear('2025-01-01', 'bad', '0d', 0.5, '2025-01-01');`,
		`decayDateLinear('2025-01-01', '1d', '0d', 0.5, 'bad');`,
		`decayGeoLinear('bad', '1km', '0km', 0.5, '0,0');`,
		`decayGeoLinear('0,0', 'bad', '0km', 0.5, '0,0');`,
		`decayGeoLinear('0,0', '1km', '0km', 0.5, 'bad');`,
		`randomScore('not_int');`,
		`randomScore(1, 2, 3);`,
	} {
		if _, err := Eval(doc, errDecay, nil); err == nil {
			t.Fatalf("expected decay/randomScore error for %s", errDecay)
		}
	}

	// Vector extraction error paths
	if _, err := EvalEmitContext("", "long", nil, nil, nil, nil); err != nil {
		t.Fatalf("empty EvalEmitContext failed: %v", err)
	}
	for _, errVec := range []string{
		`cosineSimilarity([1.0, 2.0], []);`,
		`cosineSimilarity([1.0, 2.0], ['bad', 1.0]);`,
		`cosineSimilarity([1.0, 2.0], 123);`,
		`cosineSimilarity([1.0, 2.0], 'missing_vec');`,
	} {
		if _, err := Eval(map[string]any{}, errVec, map[string]any{}); err == nil {
			t.Fatalf("expected vector error for %s", errVec)
		}
	}
}

func TestRound66_Round54TimeZoneClockOptionalURIAndCollectionsBranches(t *testing.T) {
	// 1. ZoneOffset / ZoneId / Clock / OffsetTime / Optional / URI / Collections / SummaryStatistics
	res, err := Eval(nil, `
		def zo1 = ZoneOffset.ofHours(-5);
		def zo2 = ZoneOffset.ofHoursMinutes(5, 30);
		def zo3 = ZoneOffset.ofHoursMinutesSeconds(1, 2, 3);
		def zo4 = ZoneOffset.ofTotalSeconds(-18000);
		def zDef = ZoneId.systemDefault();
		def zAvail = ZoneId.getAvailableZoneIds();
		def zOff1 = ZoneId.ofOffset('', '+00:00');
		def zOff2 = ZoneId.ofOffset('UTC', '+02:00');
		def zOff3 = ZoneId.ofOffset('GMT', 'Z');
		def cSys = Clock.system('UTC');
		def cFix = Clock.fixed('2025-01-01T00:00:00Z', 'UTC');
		def cOff = Clock.offset(cFix, Duration.ofHours(2));
		def cTick1 = Clock.tickMinutes('UTC');
		def cTick2 = Clock.tickMillis('UTC');
		def cTick3 = Clock.tick(cFix, Duration.ofSeconds(10));
		def ot1 = OffsetTime.of(LocalTime.of(12, 30, 0), '-04:00');
		def ot2 = OffsetTime.of(8, 15, 0, 0, '+02:00');
		def ot3 = OffsetTime.parse('10:15:30+01:00');
		def oi = OptionalInt.of(7);
		def ol = OptionalLong.of(9L);
		def od = OptionalDouble.of(2.5);
		def u1 = URI.create('https://Example.COM/a/b/../c?q=1#f');
		def uNorm = u1.normalize();
		def uRes = uNorm.resolve(URI.create('/d/e'));
		def uBase = URI.create('https://Example.COM/a/');
		def uChild = URI.create('https://Example.COM/a/x/y?k=1#z');
		def uRel = uBase.relativize(uChild);
		def uEq = URI.create('https://example.com/a/').equals(uBase);
		def uHost = uBase.getHost();
		def ul = Collections.unmodifiableList(['a', 'b']);
		def um = Collections.unmodifiableMap(['k': 1]);
		def sl = Collections.synchronizedList(['x']);
		def stats = [1, 2, 3].stream().collect(Collectors.summarizingInt(x -> x * 2));
		return [
			'zo': zo1 + '|' + zo2 + '|' + zo3 + '|' + zo4,
			'zOff': zDef + '|' + zAvail.size() + '|' + zOff1 + '|' + zOff2 + '|' + zOff3,
			'clk': cSys.getZone() + '|' + cOff.instant().toString() + '|' + cTick1.getZone() + '|' + cTick2.getZone() + '|' + cTick3.instant().toString(),
			'ot': ot1.toString() + '|' + ot2.toString() + '|' + ot3.toString(),
			'opt': oi.toString() + '|' + ol.toString() + '|' + od.toString(),
			'uri': uNorm.toString() + '|' + uRes.toString() + '|' + uRel.toString() + '|' + uEq + '|' + uHost + '|' + (uNorm.hashCode() != 0),
			'col': ul.size() + '|' + um.get('k') + '|' + sl.size(),
			'sum': stats.getSum()
		];
	`, nil)
	if err != nil {
		t.Fatalf("Round54 suite failed: %v", err)
	}
	m, _ := res.(map[string]any)
	if m["zo"] != "-05:00|+05:30|+01:02:03|-05:00" {
		t.Fatalf("unexpected zo: %v", m["zo"])
	}
	if !strings.Contains(m["zOff"].(string), "UTC|13|Z|UTC+02:00|GMT") {
		t.Fatalf("unexpected zOff: %v", m["zOff"])
	}
	if m["opt"] != "OptionalInt[7]|OptionalLong[9]|OptionalDouble[2.5]" {
		t.Fatalf("unexpected opt strings: %v", m["opt"])
	}
	if m["sum"] != int64(12) || m["col"] != "2|1|1" {
		t.Fatalf("unexpected sum/col: %v / %v", m["sum"], m["col"])
	}

	// Error cases across round54 ZoneOffset/ZoneId/Clock/OffsetTime/Optional/Collections
	for _, bad := range []string{
		`ZoneOffset.ofTotalSeconds(70000);`,
		`ZoneId.ofOffset('BAD', '+01:00');`,
		`ZoneId.ofOffset('UTC', 'not_offset');`,
		`ZoneId.ofOffset(null, '+01:00');`,
		`Clock.system(null);`,
		`Clock.fixed(null, 'UTC');`,
		`Clock.fixed('not_date', 'UTC');`,
		`Clock.offset(null, Duration.ofHours(1));`,
		`Clock.tickMinutes(null);`,
		`Clock.tick(Clock.systemUTC(), Duration.ofSeconds(-1));`,
		`Clock.tick(null, Duration.ofSeconds(1));`,
		`OffsetTime.of('bad', '+01:00');`,
		`OffsetTime.of('10:00:00', 'bad_off');`,
		`OffsetTime.of(10, 0, 0, 0, 'bad_off');`,
		`OffsetTime.of(10);`,
		`OffsetTime.parse(null);`,
		`OffsetTime.parse('10:00', null);`,
		`OffsetTime.parse('not_time', DateTimeFormatter.ISO_OFFSET_TIME);`,
		`OptionalInt.of(null);`,
		`OptionalInt.of('abc');`,
		`OptionalLong.of('abc');`,
		`OptionalDouble.of('abc');`,
		`Collections.unmodifiableList(null);`,
		`Collections.unmodifiableMap(null);`,
		`Collections.synchronizedList(null);`,
	} {
		if _, err := Eval(nil, bad, nil); err == nil {
			t.Fatalf("expected error for %s", bad)
		}
	}
}

func TestRound66_EvalMapSplitExponentReduceTemporalAndLambdas(t *testing.T) {
	// 1. Expression-level .clear() NPE & safe-nav on ctx._source + map/list .values()/.entrySet()/.getKey()/.getValue()/.length()
	docClear := map[string]any{"tags": []any{"a", "b"}}
	if _, err := Eval(docClear, `return ctx._source.missing.clear();`, map[string]any{}); err == nil {
		t.Fatalf("expected NPE on expr ctx._source.missing.clear()")
	}
	resClear, err := Eval(docClear, `
		def okSafe = ctx?._source?.missing?.clear();
		def sj = new StringJoiner(',');
		sj.add('ab');
		def yr = Year.of(2024);
		def sb = new StringBuilder('abc');
		def m = ['k1': 10, 'k2': 20];
		def es = m.entrySet();
		def firstK = '';
		def firstV = 0;
		for (e in es) {
			if (firstK == '') {
				firstK = e.getKey();
				firstV = e.getValue();
			}
		}
		def mv = m.values();
		def lv = [1, 2].values();
		def iv = (123).values();
		def days = ['MONDAY'.getValue(), 'TUESDAY'.getValue(), 'WEDNESDAY'.getValue(), 'THURSDAY'.getValue(), 'FRIDAY'.getValue(), 'SATURDAY'.getValue(), 'SUNDAY'.getValue(), 'AUGUST'.getValue(), 'SEPTEMBER'.getValue(), 'OCTOBER'.getValue(), 'NOVEMBER'.getValue(), 'DECEMBER'.getValue()];
		return [
			'okSafe': okSafe == null,
			'sjLen': sj.length(),
			'yrVal': yr.getValue(),
			'yrLen': yr.length(),
			'sbLen': sb.length(),
			'firstK': firstK,
			'firstV': firstV,
			'mvSz': mv.size(),
			'lvSz': lv.size(),
			'ivSz': iv.size(),
			'numVal': (42.9).getValue(),
			'mon': days[0],
			'dec': days[11]
		];
	`, map[string]any{})
	if err != nil {
		t.Fatalf("values/entrySet/getValue eval failed: %v", err)
	}
	cm, _ := resClear.(map[string]any)
	if cm["okSafe"] != true || cm["yrVal"] != int64(2024) || cm["sbLen"] != int64(3) || cm["mon"] != int64(1) || cm["dec"] != int64(12) {
		t.Fatalf("unexpected clear/map/enum result: %+v", cm)
	}

	// 2. add(idx, val) & add(val) in ApplyUpdateWithResult + local list + inline expr
	updOut, _, err := ApplyUpdateWithResult(json.RawMessage(`{"arr":["a","c"]}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `
			ctx._source.arr.add(1, 'b');
			ctx._source.arr.add('d');
			List xs = new ArrayList();
			xs.add('y');
			xs.add(0, 'x');
			def tail = (['p', 'q']).add(1, 'r');
			ctx._source.xs = xs;
			ctx._source.tailOk = tail;
		`},
	}, true)
	if err != nil || !strings.Contains(string(updOut), `"xs":["x","y"]`) {
		t.Fatalf("update add(idx,val) failed: err=%v out=%s", err, string(updOut))
	}

	// 3. Regex/Pattern/String split + NPEs + Math.getExponent + Float/Boolean + 2-arg stream reduce/forEach/drain
	resSplitMathStream, err := Eval(nil, `
		def p = /[,-]/;
		def pSplit = p.split('a,b-c', 2);
		def pEmptySplit = Pattern.compile('').split('xy', 2);
		def rawRe = /:/;
		def rSplit = rawRe.split('u:v:w', 2);
		def sSplit = '1:2:3'.split(':', 2);
		def sEmpty = 'ab'.split('', 2);

		def e0 = Math.getExponent(0.0);
		def eInf = Math.getExponent(Double.POSITIVE_INFINITY);
		def eNaN = Math.getExponent(Double.NaN);
		def e8 = Math.getExponent(8.0);
		def flt1 = Float.parseFloat('1.25');
		def flt2 = Float.valueOf('2.5');
		def b1 = Boolean.valueOf(true);
		def b2 = Boolean.parseBoolean('TRUE');

		def sum2 = [1, 2, 3, 4].stream().reduce((a, b) -> a + b).get();
		def emptyRed = [].stream().reduce((a, b) -> a + b).isPresent();
		def acc = 0;
		[10, 20].stream().forEach(x -> { acc += x; });
		def unterminated = [1, 2].stream().map(x -> x * 3);

		def sup = () -> 42;
		def bSup = () -> true;
		def dSup = () -> 3.5;
		def seen = 0;
		def rSup = () -> { seen = 1; };
		rSup.run();

		return [
			'pSplitLen': pSplit.length,
			'pEmptyLen': pEmptySplit.length,
			'rSplitLen': rSplit.length,
			'sSplitLen': sSplit.length,
			'sEmptyLen': sEmpty.length,
			'e0': e0,
			'eInf': eInf,
			'eNaN': eNaN,
			'e8': e8,
			'eNil': eNil,
			'flt': flt1 + flt2,
			'b1': b1,
			'b2': b2,
			'sum2': sum2,
			'emptyRed': emptyRed,
			'utSz': unterminated.size(),
			'sup': sup.get(),
			'iSup': sup.getAsInt(),
			'lSup': sup.getAsLong(),
			'dSup': dSup.getAsDouble(),
			'bSup': bSup.getAsBoolean(),
			'seen': seen
		];
	`, map[string]any{})
	if err != nil {
		t.Fatalf("split/math/stream/lambda eval failed: %v", err)
	}
	sm, _ := resSplitMathStream.(map[string]any)
	if sm["e0"] != int64(-1023) || sm["eInf"] != int64(1024) || sm["e8"] != int64(3) ||
		sm["sum2"] != int64(10) || sm["emptyRed"] != false || sm["sup"] != int64(42) || sm["bSup"] != true {
		t.Fatalf("unexpected split/math/stream/lambda result: %+v", sm)
	}

	// 4. Temporal isSupported(ChronoUnit), with(TemporalAdjuster), LocalDate.until(end), LocalDateTime.atOffset
	resTemp2, err := Eval(nil, `
		def inst = Instant.ofEpochMilli(1000);
		def ld1 = LocalDate.of(2025, 1, 1);
		def ld2 = LocalDate.of(2025, 1, 5);
		def zdt = ZonedDateTime.parse('2025-03-15T10:00:00Z');
		def adj = zdt.with(TemporalAdjusters.firstDayOfMonth());
		def ldt = LocalDateTime.of(2025, 3, 1, 12, 0, 0);
		def odt = ldt.atOffset(ZoneOffset.ofHours(2));
		return [
			'instDays': inst.isSupported(ChronoUnit.DAYS),
			'instMs': inst.isSupported(ChronoField.MILLI_OF_SECOND),
			'ldPeriodDays': ld1.until(ld2).getDays(),
			'zdtUntilHours': ZonedDateTime.parse('2025-03-01T00:00:00Z').until(ZonedDateTime.parse('2025-03-01T05:00:00Z'), ChronoUnit.HOURS),
			'adjDay': adj.getDayOfMonth(),
			'odtHour': odt.getHour()
		];
	`, nil)
	if err != nil {
		t.Fatalf("temporal2 eval failed: %v", err)
	}
	tm2, _ := resTemp2.(map[string]any)
	if tm2["instDays"] != true || tm2["ldPeriodDays"] != int64(4) || tm2["zdtUntilHours"] != int64(5) || tm2["adjDay"] != int64(1) {
		t.Fatalf("unexpected temporal2 result: %+v", tm2)
	}

	// 5. FieldDocVal docs(), get(idx), exists(), field(), $(), remove(), error paths on split/lambda
	nestedDoc := map[string]any{
		"items": []any{
			map[string]any{"sku": "A1", "qty": 2},
			map[string]any{"sku": "B2", "qty": 5},
		},
	}
	fTypes := map[string]string{"items": "nested", "items.sku": "keyword", "items.qty": "long"}
	emittedDocs, err := EvalEmitContext(`
		def docs = field('items').docs();
		def d0 = docs.get(0);
		def exists0 = d0.exists();
		def sku0 = d0.$('sku', 'none');
		def qty0 = d0.field('qty').asLong();
		emit(docs.size() + ':' + exists0 + ':' + sku0 + ':' + qty0);
	`, "keyword", nestedDoc, nestedDoc, map[string]any{}, fTypes)
	if err != nil || len(emittedDocs) != 1 || emittedDocs[0] != "2:true:A1:2" {
		t.Fatalf("unexpected FieldDocVal emit: %v err=%v", emittedDocs, err)
	}
	for _, errExpr := range []string{
		`(/a/).split(null);`,
		`def r = /a/; r.split(null);`,
		`'abc'.split(null);`,
		`def f = x -> { return ((String)null).length(); }; f.applyAsInt(1);`,
		`def f = x -> { return ((String)null).length(); }; f.applyAsLong(1L);`,
		`def f = x -> { return ((String)null).length(); }; f.applyAsDouble(1.0);`,
		`def f = x -> { return ((String)null).length(); }; f.test(1);`,
		`[1, 2].stream().reduce((a, b) -> { return ((String)null).length(); });`,
		`Double.parseDouble('not_a_double');`,
		`Math.getExponent(null);`,
		`Optional.of(1).flatMap(x -> null);`,
		`Clock.systemUTC().withZone(null);`,
		`new URL(null);`,
		`new Locale(null);`,
		`new Locale('en', null);`,
	} {
		if _, err := Eval(nil, errExpr, nil); err == nil {
			t.Fatalf("expected error for %s", errExpr)
		}
	}
}

func TestRound66_SwitchURLOptionalClockReplaceAll(t *testing.T) {
	// 1. Switch expressions (arrow single, arrow block+yield, colon fallthrough+break/yield, null NPE, throw)
	swRes, err := Eval(nil, `
		def a = switch (2) { case 1 -> 10; case 2 -> { yield 20; } default -> 30; };
		def b = switch ('x') { case 'x': case 'y': yield 99; default: yield 0; };
		return ['a': a, 'b': b];
	`, nil)
	if err != nil {
		t.Fatalf("switch expression failed: %v", err)
	}
	sm, _ := swRes.(map[string]any)
	if sm["a"] != int64(20) || sm["b"] != int64(99) {
		t.Fatalf("unexpected switch result: %+v", sm)
	}
	for _, swErr := range []string{
		`def x = null; return switch (x) { case 1 -> 2; };`,
		`return switch (1) { case 1 -> throw new IllegalArgumentException('boom'); default -> 0; };`,
	} {
		if _, err := Eval(nil, swErr, nil); err == nil {
			t.Fatalf("expected switch error for %s", swErr)
		}
	}

	// 2. Optional.flatMap, SummaryStatistics accept/combine, Clock.withZone, OffsetTime.withHour/withMinute, new URL/Locale
	r54Res, err := Eval(nil, `
		def opt1 = Optional.of(5).flatMap(x -> Optional.of(x * 2)).get();
		def opt2 = Optional.empty().flatMap(x -> Optional.of(1)).isPresent();
		def s1 = new DoubleSummaryStatistics();
		s1.accept(2.0);
		def s2 = new DoubleSummaryStatistics();
		s2.accept(4.0);
		s1.combine(s2);
		def clk = Clock.systemUTC().withZone('America/New_York');
		def ot = OffsetTime.of(10, 20, 30, 0, ZoneOffset.UTC).withHour(14).withMinute(45);
		def u1 = new URL('https://example.com/a/b');
		def u2 = new URL(u1, 'c');
		def u3 = new URL('https', 'example.com', 'docs/page');
		def u4 = new URL('https', 'example.com', 8443, 'api');
		def l1 = new Locale('fr');
		def l2 = new Locale('fr', 'CA');
		return [
			'opt1': opt1,
			'opt2': opt2,
			'sum': s1.getSum(),
			'clkZ': clk.getZone().toString(),
			'otH': ot.getHour(),
			'otM': ot.getMinute(),
			'u2': u2.toString(),
			'u3': u3.toString(),
			'u4': u4.toString(),
			'l1': l1.toString(),
			'l2': l2.toString()
		];
	`, nil)
	if err != nil {
		t.Fatalf("round54 coverage eval failed: %v", err)
	}
	r54m, _ := r54Res.(map[string]any)
	if r54m["opt1"] != int64(10) || r54m["opt2"] != false || r54m["sum"] != 6.0 ||
		r54m["otH"] != int64(14) || r54m["otM"] != int64(45) ||
		r54m["l1"] != "fr" || r54m["l2"] != "fr_CA" {
		t.Fatalf("unexpected round54 eval result: %+v", r54m)
	}

	// 3. Map.replaceAll on local map and ctx._source.sub
	updRA, _, err := ApplyUpdateWithResult(json.RawMessage(`{"sub":{"a":1,"b":2}}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `
			ctx._source.sub.replaceAll((k, v) -> v * 10);
			def lm = ['x': 3];
			lm.replaceAll((k, v) -> v + 1);
			ctx._source.lx = lm['x'];
		`},
	}, true)
	if err != nil || !strings.Contains(string(updRA), `"lx":4`) || !strings.Contains(string(updRA), `"a":10`) {
		t.Fatalf("replaceAll update failed: err=%v out=%s", err, string(updRA))
	}
}

func TestRound66_EvalPeriodDurationTemporalAddAllBigDecimal(t *testing.T) {
	// 1. Period & Duration zero-arg accessors + BigDecimal/BigInteger .abs()/.divideAndRemainder() + SummaryStatistics.toString()
	res, err := Eval(map[string]any{"x": int64(42)}, `
		def per = Period.parse('P1Y15M2D');
		def pNorm = per.normalized();
		def pNeg = Period.ofDays(-3);
		def dur = Duration.ofSeconds(-5, 200);
		def durPos = Duration.ofHours(25);
		def bdNeg = new BigDecimal('-12.50').abs();
		def biNeg = new BigInteger('-99').abs();
		def qr = new BigDecimal('10.00').divideAndRemainder(new BigDecimal('3.0'));
		def ds = new DoubleSummaryStatistics();
		ds.accept(2.0);
		def dsStr = ds.toString();

		def yn = Year.now();
		def mdn = MonthDay.now();
		def ldtNow = LocalDateTime.now();
		def yLeap = Year.isLeap(2024);
		def yFrom = Year.from(ZonedDateTime.parse('2026-04-05T00:00:00Z'));
		def md = MonthDay.of(3, 15);
		def mdFrom = MonthDay.from(ZonedDateTime.parse('2026-07-04T00:00:00Z'));
		def dow = DayOfWeek.of(3);
		def mon = Month.of(11);
		def inst2 = Instant.ofEpochSecond(100, 500);
		def pSrc = params._source;

		return [
			'py': per.getYears(),
			'pm': per.getMonths(),
			'pd': per.getDays(),
			'ptm': per.toTotalMonths(),
			'pny': pNorm.getYears(),
			'pnm': pNorm.getMonths(),
			'pZero': Period.ZERO.isZero(),
			'pNeg': pNeg.isNegative(),
			'pNegAbs': pNeg.negated().getDays(),
			'dSec': dur.getSeconds(),
			'dNeg': dur.isNegative(),
			'dZero': Duration.ZERO.isZero(),
			'dDays': durPos.toDays(),
			'dHrs': durPos.toHours(),
			'dMins': durPos.toMinutes(),
			'dSecs': durPos.toSeconds(),
			'dMs': durPos.toMillis(),
			'dNs': durPos.toNanos(),
			'dAbs': dur.abs().toSeconds(),
			'dNegated': durPos.negated().isNegative(),
			'bdAbs': bdNeg.toString(),
			'biAbs': biNeg.toString(),
			'q0': qr[0].toString(),
			'hasDs': dsStr.length() > 0,
			'ynPos': yn.getValue() >= 2024,
			'mdnOk': mdn != null && ldtNow != null,
			'yLeap': yLeap,
			'yFrom': yFrom.getValue(),
			'mdM': md.getMonthValue(),
			'mdFromD': mdFrom.getDayOfMonth(),
			'dow': dow,
			'mon': mon,
			'inst2Ok': inst2 != null,
			'pSrcX': pSrc.x
		];
	`, map[string]any{})
	if err != nil {
		t.Fatalf("period/duration/temporal/bd eval failed: %v", err)
	}
	m, _ := res.(map[string]any)
	if m["py"] != int64(1) || m["pm"] != int64(15) || m["pd"] != int64(2) || m["ptm"] != int64(27) ||
		m["pny"] != int64(2) || m["pnm"] != int64(3) || m["pZero"] != true || m["pNeg"] != true ||
		m["dDays"] != int64(1) || m["dHrs"] != int64(25) || m["dNeg"] != true || m["dZero"] != true ||
		m["bdAbs"] != "12.50" || m["biAbs"] != "99" || m["yLeap"] != true || m["yFrom"] != int64(2026) ||
		m["dow"] == nil || fmt.Sprintf("%v", m["dow"]) != "WEDNESDAY" ||
		m["mon"] == nil || fmt.Sprintf("%v", m["mon"]) != "NOVEMBER" || m["pSrcX"] != int64(42) {
		t.Fatalf("unexpected period/duration/temporal result: %+v", m)
	}

	// 2. Year/MonthDay/ChronoField/IsoFields/ZoneOffset/Objects/Collections/BitSet.get(range)
	extraRes, err := Eval(nil, `
		def ym = Year.of(2024).atMonth(5);
		def ldA = Year.of(2024).atMonthDay(MonthDay.of(2, 29));
		def ldB = MonthDay.of(2, 29).atYear(2024);
		def validLeap = MonthDay.of(2, 29).isValidYear(2023);
		def z = ZonedDateTime.parse('2025-05-15T10:00:00Z');
		def qtr = z.get(IsoFields.QUARTER_OF_YEAR);
		def epDay = z.getLong(ChronoField.EPOCH_DAY);
		def rngMax = z.range(ChronoField.DAY_OF_MONTH).getMaximum();
		def off1 = ZoneOffset.ofHoursMinutesSeconds(2, 30, 15);
		def off2 = ZoneOffset.of('+02:30:15');
		def off3 = ZoneOffset.of('+023015');
		def c1 = Objects.checkFromToIndex(1, 3, 5);
		def c2 = Objects.checkFromIndexSize(1, 2, 5);
		def idStr = Objects.toIdentityString('abc');
		def hc = Objects.hashCode('a');
		def hs = Objects.hash('a', 1);
		def iSub = Collections.indexOfSubList([1, 2, 3, 2, 3], [2, 3]);
		def lSub = Collections.lastIndexOfSubList([1, 2, 3, 2, 3], [2, 3]);
		def bs = new BitSet();
		bs.set(1, 4);
		def bsSlice = bs.get(0, 3);
		def bsBit = bs.get(1);
		def otBase = OffsetTime.of(10, 20, 30, 500, ZoneOffset.UTC);
		def otTrunc = otBase.truncatedTo(ChronoUnit.MINUTES);
		def otAtD = otBase.atDate(LocalDate.of(2025, 1, 1));
		def otEpS = otBase.toEpochSecond(LocalDate.of(2025, 1, 1));
		def otCmp = otBase.isBefore(OffsetTime.of(12, 0, 0, 0, ZoneOffset.UTC));
		def sas = Pattern.compile(',').splitAsStream('p,q,r').collect(Collectors.toList());
		return [
			'ymOk': ym != null,
			'ldA': ldA.toString(),
			'ldB': ldB.toString(),
			'validLeap': validLeap,
			'qtr': qtr,
			'epDayPos': epDay > 0,
			'rngMax': rngMax,
			'offOk': off1 != null && off2 != null && off3 != null,
			'c1': c1,
			'c2': c2,
			'idHasAt': idStr.indexOf('@') > 0,
			'hcNonZero': hc != 0 || hs != 0,
			'iSub': iSub,
			'lSub': lSub,
			'bsBit': bsBit,
			'bsSlice': bsSlice != null,
			'otCmp': otTrunc != null && otAtD != null && otEpS > 0 && otCmp,
			'sasSz': sas.size()
		];
	`, nil)
	if err != nil {
		t.Fatalf("extra round54/eval branches failed: %v", err)
	}
	em, _ := extraRes.(map[string]any)
	if em["validLeap"] != false || em["qtr"] != int64(2) || em["rngMax"] != int64(31) || em["offOk"] != true ||
		em["iSub"] != int64(1) || em["lSub"] != int64(3) || em["bsBit"] != true {
		t.Fatalf("unexpected extra branches result: %+v", em)
	}
	for _, extraErr := range []string{
		`Year.of(2024).atMonth(null);`,
		`Year.of(2024).atMonthDay(null);`,
		`Objects.checkFromToIndex(3, 1, 5);`,
		`Objects.checkFromIndexSize(3, 4, 5);`,
		`Objects.toIdentityString(null);`,
		`Collections.indexOfSubList(null, [1]);`,
		`ZoneOffset.ofHoursMinutesSeconds(1, -1, 0);`,
		`ZoneOffset.ofHoursMinutesSeconds(-1, 1, 0);`,
		`ZoneOffset.ofHoursMinutesSeconds(0, 1, -1);`,
		`ZoneOffset.ofHoursMinutesSeconds(18, 1, 0);`,
		`new BitSet().get(0, 99999999);`,
	} {
		if _, err := Eval(nil, extraErr, nil); err == nil {
			t.Fatalf("expected error for %s", extraErr)
		}
	}

	// 3. addAll(idx, col), addAll(col), removeIf, removeAll, retainAll across ctx._source, local list, and inline list expr
	updAddAll, _, err := ApplyUpdateWithResult(json.RawMessage(`{"arr":["a","d"]}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `
			ctx._source.arr.addAll(1, ['b', 'c']);
			ctx._source.arr.addAll(['e']);
			ctx._source.arr.removeAll(['e']);
			ctx._source.arr.retainAll(['a', 'b', 'c', 'd']);
			ctx._source.arr.removeIf(x -> x == 'z');
			ctx._source.missing?.add('noop');
			List l = new ArrayList();
			l.addAll(['1', '4']);
			l.addAll(1, ['2', '3']);
			def inlineOk = (['x', 'z']).addAll(1, ['y']);
			def u0 = new URI('https://example.com/a%20b?x=1#frag');
			def u1 = new URI('https://example.com/b');
			ctx._source.l = l;
			ctx._source.inlineOk = inlineOk && u0.compareTo(u1) != 0;
		`},
	}, true)
	if err != nil || !strings.Contains(string(updAddAll), `"arr":["a","b","c","d"]`) || !strings.Contains(string(updAddAll), `"l":["1","2","3","4"]`) {
		t.Fatalf("addAll update failed: err=%v out=%s", err, string(updAddAll))
	}
}

func TestRound66_EvalRegexClassCloneFormatNavigable(t *testing.T) {
	// 1. Update expression-level clear, putIfAbsent (existing + missing nested map), inline remove/set, sort
	updOut, _, err := ApplyUpdateWithResult(json.RawMessage(`{"tags":["x","y"],"sub":{"a":1},"nums":[3,1,2]}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `
			def _clr1 = ctx._source.tags.clear();
			def m = ['k': 1];
			def _clr2 = m.clear();
			ctx._source.sub.putIfAbsent('b', 2);
			ctx._source.sub.putIfAbsent('a', 99);
			def loc = ['n': [:]];
			loc.n.putIfAbsent('x', 7);
			def inlineRm = (['p', 'q']).remove(0);
			def inlineSet = (['r', 's']).set(1, 'S');
			def inlinePut = (['x': 1]).putIfAbsent('y', 2);
			ctx._source.nums.sort((a, b) -> b - a);
			ctx._source.res = inlineRm + ':' + inlineSet + ':' + (inlinePut == null);
		`},
	}, true)
	if err != nil || !strings.Contains(string(updOut), `"b":2`) || !strings.Contains(string(updOut), `"a":1`) || !strings.Contains(string(updOut), `"nums":[3,2,1]`) {
		t.Fatalf("putIfAbsent/clear/sort update failed: err=%v out=%s", err, string(updOut))
	}

	// 2. Pattern/Matcher region anchoring bounds, clone(), getClass(), contentEquals, formatted, append(s, start, end), BigInteger.or, TreeMap/TreeSet/Deque
	res, err := Eval(nil, `
		def pat = Pattern.compile('foo', Pattern.CASE_INSENSITIVE);
		def rawP = '/a\\/b/';
		def pf = pat.flags();
		def bs = new BitSet();
		bs.set(2);
		def bsC = bs.clone();
		def arrC = [1, 2].clone();
		def mapC = ['a': 1].clone();
		def clsName = (123).getClass().getName();
		def clsSimple = (123).getClass().getSimpleName();
		def cfName = ChronoField.YEAR.name();
		def mat = Pattern.compile('abc$').matcher("abc\ndef");
		mat.region(0, 3);
		mat.useAnchoringBounds(false);
		def foundNoAnchor = mat.find();

		def biOr = new BigInteger('3').or(new BigInteger('5')).toString();
		def ce1 = 'hello'.contentEquals(new StringBuilder('hello'));
		def ce2 = 'hello'.contentEquals('hello');
		def ce3 = 'hello'.contentEquals(null);
		def fmtS = 'hi %s %d'.formatted('go', 42);
		def sbSub = new StringBuilder().append('abcdef', 1, 4).toString();

		def tm = new TreeMap();
		tm.put('a', 1);
		tm.put('c', 3);
		def fk = tm.floorKey('b');
		def ck = tm.ceilingKey('b');
		def ts = new TreeSet();
		ts.add(1);
		ts.add(5);
		def fl = ts.floor(3);
		def cl = ts.ceiling(3);
		def dq = new ArrayDeque();
		dq.offerFirst('x');
		dq.offerLast('y');
		dq.removeFirstOccurrence('x');

		return [
			'rawP': rawP.toString(),
			'pf': pf,
			'bs2': bsC.get(2),
			'arrSz': arrC.size(),
			'mapA': mapC['a'],
			'clsOk': clsName != '' && clsSimple != '' && cfName == 'YEAR',
			'foundNoAnchor': foundNoAnchor,
			'biOr': biOr,
			'ceOk': ce1 && ce2 && !ce3,
			'fmtS': fmtS,
			'sbSub': sbSub,
			'navOk': fk == 'a' && ck == 'c' && fl == 1 && cl == 5 && dq.size() == 1
		];
	`, nil)
	if err != nil {
		t.Fatalf("regex/clone/formatted/nav eval failed: %v", err)
	}
	rm, _ := res.(map[string]any)
	if rm["bs2"] != true || rm["biOr"] != "7" || rm["ceOk"] != true || rm["fmtS"] != "hi go 42" ||
		rm["sbSub"] != "bcd" || rm["navOk"] != true || rm["foundNoAnchor"] != false {
		t.Fatalf("unexpected regex/clone/formatted/nav result: %+v", rm)
	}
}

func TestRound66_OffsetTimeListReplaceAllTemporalAccessors(t *testing.T) {
	// 1. List.replaceAll on ctx._source.nums & local list + ctx.forEach
	updOut, _, err := ApplyUpdateWithResult(json.RawMessage(`{"nums":[1,2,3]}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `
			ctx._source.nums.replaceAll(x -> x * 10);
			def loc = [4, 5];
			loc.replaceAll(x -> x + 1);
			def sum = 0;
			loc.forEach(x -> { sum += x; });
			ctx._source.loc = loc;
			ctx._source.sum = sum;
		`},
	}, true)
	if err != nil || !strings.Contains(string(updOut), `"nums":[10,20,30]`) || !strings.Contains(string(updOut), `"sum":11`) {
		t.Fatalf("list replaceAll/forEach failed: err=%v out=%s", err, string(updOut))
	}

	// 2. OffsetTime mutators/arithmetic & Year/MonthDay/ZonedDateTime zero-arg accessors
	res, err := Eval(nil, `
		def ot = OffsetTime.of(10, 20, 30, 0, ZoneOffset.UTC);
		def ot1 = ot.withSecond(45).withNano(500).withOffsetSameLocal('+02:00').withOffsetSameInstant('-01:00');
		def ot2 = ot.plusHours(1).minusHours(1).plusMinutes(5).minusMinutes(2).plusSeconds(10).minusSeconds(5).plusNanos(100).minusNanos(50);
		def ot3 = ot.plus(Duration.ofMinutes(3)).minus(Duration.ofMinutes(1)).plus(2, ChronoUnit.HOURS).minus(1, ChronoUnit.MINUTES);

		def yr = Year.of(2024);
		def md = MonthDay.of(7, 4);
		def z = ZonedDateTime.parse('2024-02-15T08:09:10.000000123Z');
		return [
			'ot1Ok': ot1 != null && ot2 != null && ot3 != null,
			'yrVal': yr.getYear(),
			'yrLeap': yr.isLeapYear(),
			'yrLen': yr.lengthOfYear(),
			'mdM': md.getMonthValue(),
			'mdD': md.getDayOfMonth(),
			'zDoy': z.getDayOfYear(),
			'zSec': z.getSecond(),
			'zNano': z.getNano(),
			'zDow': z.getDayOfWeek(),
			'zEpDay': z.toEpochDay() > 0,
			'zLD': z.toLocalDate(),
			'zLDT': z.toLocalDateTime(),
			'zLT': z.toLocalTime(),
			'zSOD': z.toSecondOfDay(),
			'zNOD': z.toNanoOfDay() > 0,
			'zASD': z.atStartOfDay(),
			'zLeap': z.isLeapYear(),
			'zLY': z.lengthOfYear(),
			'zLM': z.lengthOfMonth(),
			'zAEM': z.atEndOfMonth(),
			'me': z.getMonthEnum(),
			'dwe': z.getDayOfWeekEnum()
		];
	`, nil)
	if err != nil {
		t.Fatalf("OffsetTime/temporal accessor eval failed: %v", err)
	}
	m, _ := res.(map[string]any)
	if m["ot1Ok"] != true || m["yrVal"] != int64(2024) || m["yrLeap"] != true || m["yrLen"] != int64(366) ||
		m["mdM"] != int64(7) || m["mdD"] != int64(4) || m["zLY"] != int64(366) || m["zLM"] != int64(29) ||
		m["zAEM"] != "2024-02-29" {
		t.Fatalf("unexpected OffsetTime/temporal accessor result: %+v", m)
	}
	for _, badOT := range []string{
		`OffsetTime.of(10, 0, 0, 0, ZoneOffset.UTC).withOffsetSameLocal('BAD');`,
		`OffsetTime.of(10, 0, 0, 0, ZoneOffset.UTC).withOffsetSameInstant('BAD');`,
		`OffsetTime.of(10, 0, 0, 0, ZoneOffset.UTC).plus(1, ChronoUnit.DAYS);`,
		`params.br.get(99);`,
	} {
		if _, err := Eval(nil, badOT, map[string]any{"br": newBytesRefValRound60([]byte("hi"))}); err == nil {
			t.Fatalf("expected error for %s", badOT)
		}
	}

	// 3. Map.forEach (1-arg & 2-arg), URI.compareTo deep paths, BytesRef/ByteBuffer.get, Matcher.region, regionMatches, geo distances
	finRes, err := Eval(map[string]any{"geo": "37.7,-122.4", "x": int64(7)}, `
		def sumV = 0;
		['a': 2, 'b': 3].forEach((k, v) -> { sumV += v; });
		def cntE = 0;
		['x': 1, 'y': 2].forEach(e -> { cntE += 1; });

		def uA = new URI('https://usr@example.com:443/p?q=1#f1');
		def uB = new URI('https://usr@example.com:443/p?q=1#f2');
		def uOpq1 = new URI('mailto:a@example.com#1');
		def uOpq2 = new URI('mailto:b@example.com#2');
		def uAscii = new URI("https://example.com/caf\u00e9").toASCIIString();
		def pEmpty = new URI('https://example.com:/p').getPort();

		def m = Pattern.compile('\\d+').matcher('x 12 y 34 z');
		m.region(1, 10);
		def f1 = m.find();
		def f2 = m.find();
		def f3 = m.find();

		def rm1 = 'HelloWorld'.regionMatches(true, 0, 'hello', 0, 5);
		def rm2 = 'HelloWorld'.regionMatches(5, 'World', 0, 5);
		def rmBad = 'Hi'.regionMatches(-1, 'a', 0, 1);
		def ctxDef = ctx.getOrDefault('nope', 'fallback');
		def docGeo = doc['geo'];
		def dArc = docGeo.arcDistance(38.0, -122.0);
		def dPlane = docGeo.planeDistance(38.0, -122.0);
		def dHash = docGeo.geohashDistance('9q8yy');
		def sl = [10, 20, 30, 40].subList(1, 3);
		def sbRepl = new StringBuilder('hello world').replace(6, 11, 'doris').toString();
		def mp = ['x': 1];
		def oldX = mp.replace('x', 2);
		def matM1 = Pattern.compile('^abc$').matcher('xabcy').region(1, 4).useAnchoringBounds(false).matches();
		def matM2 = Pattern.compile('abc').matcher('xabcy').region(1, 4).matches();
		def matL1 = Pattern.compile('^abc').matcher('xabcy').region(1, 5).useAnchoringBounds(false).lookingAt();
		def matL2 = Pattern.compile('abc$').matcher('xabcy').region(1, 4).useAnchoringBounds(false).lookingAt();
		def mL3 = Pattern.compile('(ab)').matcher('xabcy').region(1, 5);
		def matL3 = mL3.lookingAt();
		def mGrp = mL3.group();
		def mGc = mL3.groupCount();
		def mSt = mL3.start();
		def mEn = mL3.end();
		def matFail1 = Pattern.compile('xyz').matcher('abc').region(0, 3).matches();
		def matFail2 = Pattern.compile('abc$').matcher('xabcy').region(1, 4).useAnchoringBounds(false).matches();
		def chArr = 'ab'.chars();
		def cpArr = 'ab'.codePoints();
		def bArr = 'ab'.getBytes();
		def tcArr = 'ab'.toCharArray();
		def stL = '  hi'.stripLeading();
		def stT = 'hi  '.stripTrailing();
		def blnk = '  '.isBlank();
		def noPad = Base64.getEncoder().withoutPadding().encodeToString('hi'.getBytes());
		def ctxIdGet = ctx.get('_id');
		def tailChain = [1, 2, 3].stream().collect(Collectors.toList()).size();
		def mdStr = MonthDay.of('MARCH', 15);
		def lamArr = x -> [x, x + 1];

		def u3 = new URI('mailto', 'a@b.com', 'sec1');
		def u4 = new URI('https', 'example.com', '/docs/a b', 'frag');
		def u5 = new URI('https', 'usr@example.com', '/p', 'a=1&b=2', 'top');
		def u7 = new URI('https', 'u:p', 'example.com', 8443, '/api', 'k=v', 'end');
		def xs = [1];
		Collections.addAll(xs, 2, 3);
		Collections.addAll(xs, [4, 5]);
		def dest = [0, 0];
		Collections.copy(dest, [8, 9]);
		def dStats = new DoubleSummaryStatistics(2L, 1.0, 5.0, 6.0);
		m.usePattern(Pattern.compile('[a-z]+')).useTransparentBounds(true);
		def uBase = new URI('https://example.com/a/b');
		def uRes1 = uBase.resolve('c');
		def uRes2 = uBase.resolve(new URI('/root'));
		def uRel = new URI('https://example.com/a/').relativize(uBase);
		def uuidCmp = '00000000-0000-0000-0000-000000000001'.compareTo('80000000-0000-0000-0000-000000000000');
		def nestedMap = ['arr': [1, 2]];
		Collections.addAll(nestedMap.get('arr'), 3);
		def lol = [[10]];
		Collections.addAll(lol.get(0), 20);

		return [
			'sumV': sumV,
			'cntE': cntE,
			'cmpAB': uA.compareTo(uB) < 0,
			'cmpOpq': uOpq1.compareTo(uOpq2) < 0,
			'hasAsc': uAscii.length() > 0,
			'pEmpty': pEmpty,
			'mRes': f1 && f2 && !f3,
			'bb0': params.bb.get(0),
			'br1': params.br.get(1),
			'rmOk': rm1 && rm2 && !rmBad,
			'ctxDef': ctxDef,
			'geoOk': dArc > 0 && dPlane > 0 && dHash > 0,
			'slSz': sl.size(),
			'sbRepl': sbRepl,
			'oldX': oldX,
			'matOk': !matM1 && matM2 && !matL1 && !matL2 && matL3 && mGrp == 'ab' && mGc == 1 && mSt == 1 && mEn == 3 && !matFail1 && !matFail2,
			'strOps': chArr.length == 2 && cpArr.length == 2 && bArr.length == 2 && tcArr.length == 2 && stL == 'hi' && stT == 'hi' && blnk && noPad != '' && tailChain == 3 && mdStr.getMonthValue() == 3 && lamArr.apply(2).size() == 2 && ctxIdGet == null,
			'uriColsOk': u3 != null && u4 != null && u5 != null && u7 != null && xs.size() == 5 && dest[1] == 9 && dStats.getCount() == 2 && uRes1 != null && uRes2 != null && uRel != null && uuidCmp > 0 && nestedMap['arr'].size() == 3 && lol[0].size() == 2
		];
	`, map[string]any{
		"br": newBytesRefValRound60([]byte("hello")),
		"bb": newByteBufferValRound60([]byte("world")),
	})
	if err != nil {
		t.Fatalf("Map.forEach/URI/BytesRef eval failed: %v", err)
	}
	fm, _ := finRes.(map[string]any)
	if fm["sumV"] != int64(5) || fm["cntE"] != int64(2) || fm["cmpAB"] != true ||
		fm["cmpOpq"] != true || fm["mRes"] != true || fm["br1"] != int64('e') ||
		fm["rmOk"] != true || fm["ctxDef"] != "fallback" || fm["geoOk"] != true ||
		fm["sbRepl"] != "hello doris" || fm["matOk"] != true || fm["uriColsOk"] != true {
		t.Fatalf("unexpected Map.forEach/URI/BytesRef result: %+v", fm)
	}
}

func BenchmarkEvalPainless(b *testing.B) {
	doc := map[string]any{
		"price": 19.95,
		"qty":   int64(4),
		"title": "Apache Doris Vector Search",
		"tags":  []any{"olap", "search", "doris"},
	}
	params := map[string]any{"tax": 1.08}

	b.Run("ScoreArithmetic", func(b *testing.B) {
		src := `return (doc['price'].value * doc['qty'].value) * params.tax;`
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := EvalScore(doc, src, params); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("StreamMapFilter", func(b *testing.B) {
		src := `return doc['tags'].stream().filter(t -> t.length() > 4).map(t -> t.toUpperCase()).collect(Collectors.toList());`
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := Eval(doc, src, params); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("DateTimeParseAndFormat", func(b *testing.B) {
		src := `def zdt = ZonedDateTime.parse('2025-03-08T12:30:00Z'); return zdt.plusDays(1).getDayOfMonth();`
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := Eval(doc, src, params); err != nil {
				b.Fatal(err)
			}
		}
	})
}
