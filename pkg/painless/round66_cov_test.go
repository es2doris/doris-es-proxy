package painless

import (
	"encoding/json"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRound66CovPainless_ControlFlowOperatorsAndStatements(t *testing.T) {
	// Labeled break / continue, return, switch yield, throw, compound ops, casts, regex literals.
	src := `
		int sum = 0;
		outer: for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				if (j == 1) { continue; }
				if (i == 2 && j == 2) { break outer; }
				sum += (int)(i + j);
			}
		}
		int bits = (5 | 2) ^ (3 & 1);
		bits <<= 1;
		bits >>= 1;
		int u = -8 >>> 1;
		int ter = sum > 0 ? (bits > 0 ? 10 : 20) : 30;
		def elv = params.missing ?: "fallback";
		def sw = switch (ter) {
			case 10 -> { yield 100; }
			default -> 200;
		};
		def re = /foo.*bar/i;
		boolean matched = "FOO123BAR" =~ /foo.*bar/i;
		return ["sum": sum, "bits": bits, "u": u, "ter": ter, "elv": elv, "sw": sw, "matched": matched, "re": re != null];
	`
	val, err := Eval(map[string]any{"x": 1}, src, map[string]any{"missing": nil})
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}
	resMap, ok := val.(map[string]any)
	if !ok || resMap["elv"] != "fallback" || resMap["sw"] != int64(100) || resMap["matched"] != true {
		t.Fatalf("unexpected eval result: %#v", val)
	}

	// Empty return + ctx.op + prefix/postfix inc/dec + replaceAll on Map and List + throw handling.
	op, err := EvalPainlessWithOp(map[string]any{"n": 1, "m": map[string]any{"a": 2, "b": 3}, "lst": []any{1, 2, 3}}, `
		ctx.m.replaceAll((k, v) -> v + 10);
		ctx.lst.replaceAll(x -> x * 2);
		++ctx.n;
		ctx.op = "noop";
		return;
	`, nil)
	if err != nil || op != "noop" {
		t.Fatalf("unexpected EvalPainlessWithOp op=%q err=%v", op, err)
	}

	// Immutable replaceAll error + throw new Exception.
	for _, failSrc := range []string{
		`throw new IllegalArgumentException("bad arg")`,
		`List.of(1, 2).replaceAll(x -> x + 1)`,
		`Optional.empty().orElseThrow()`,
		`Optional.empty().orElseThrow(IllegalStateException::new)`,
		`Optional.empty().orElseThrow(() -> new IllegalArgumentException("none"))`,
		`Optional.ofNullable(null).orElseThrow(() -> { return new IllegalStateException("nope"); })`,
	} {
		if _, err := Eval(nil, failSrc, nil); err == nil {
			t.Fatalf("expected error for %q", failSrc)
		}
	}
}

func TestRound66CovPainless_MathParsingEscapesStreamsAndEmitContext(t *testing.T) {
	src := `
		long a = Math.floorDiv(-7L, 2L);
		long b = Math.floorMod(-7L, 2L);
		long c = StrictMath.addExact(3L, 4L);
		long d = Math.subtractExact(10L, 4L);
		long e = Math.multiplyExact(3L, 5L);
		long f = Math.incrementExact(9L);
		long g = Math.decrementExact(9L);
		long h = Math.negateExact(-5L);
		int i = Math.toIntExact(42L);
		int e0 = Math.getExponent(0.0);
		int e1 = Math.getExponent(8.0);
		int e2 = Math.getExponent(Double.NaN);
		int p1 = Integer.parseInt("2a", 16);
		long p2 = Long.parseLong("-123");
		double p3 = Double.parseDouble("3.25");
		def p4 = Float.valueOf("1.5");
		def sSet = new HashSet(Arrays.asList("a", "b", "a"));
		String esc = translateEscapesPainlessDummy("ok");
		return ["a": a, "b": b, "c": c, "d": d, "e": e, "f": f, "g": g, "h": h, "i": i, "e0": e0, "e1": e1, "e2": e2, "p1": p1, "p2": p2, "p3": p3, "p4": p4, "setSize": sSet.size()];
	`
	// Remove non-builtin dummy call and call String literal replace/translateEscapes + Go helper directly.
	src = strings.ReplaceAll(src, `String esc = translateEscapesPainlessDummy("ok");`, `String esc = "a\nb\tc";`)
	val, err := Eval(nil, src, nil)
	if err != nil {
		t.Fatalf("unexpected static call eval error: %v", err)
	}
	resMap, ok := val.(map[string]any)
	if !ok || resMap["p1"] != int64(42) || resMap["a"] != int64(-4) || resMap["setSize"] != int64(2) {
		t.Fatalf("unexpected static results: %#v", val)
	}

	// Direct translateEscapesPainless escape sequences.
	gotEsc := translateEscapesPainless(`\b\f\n\r\s\t\'\"\\` + "\\\n" + "\\\r\nok")
	if gotEsc != "\b\f\n\r \t'\"\\ok" {
		t.Fatalf("unexpected translateEscapesPainless output: %q", gotEsc)
	}

	// EvalFilter, EvalNumber, CompileValidate, ApplyUpdateWithResult, EvalEmitContext.
	if bRes, err := EvalFilter(map[string]any{"cnt": 5}, `doc['cnt'].value > 3`, nil); err != nil || !bRes {
		t.Fatalf("EvalFilter failed: bRes=%v err=%v", bRes, err)
	}
	if nRes, hasN, err := EvalNumber(map[string]any{"cnt": 5}, `doc['cnt'].value * 2`, nil); err != nil || !hasN || nRes != 10 {
		t.Fatalf("EvalNumber failed: nRes=%v hasN=%v err=%v", nRes, hasN, err)
	}
	if err := CompileValidate(`return params.a + 1;`); err != nil {
		t.Fatalf("CompileValidate unexpected error: %v", err)
	}
	if err := CompileValidate(`return (;`); err == nil {
		t.Fatal("expected syntax error from CompileValidate")
	}

	emitted, err := EvalEmitContext(`emit(doc['score'].value * 2);`, "long", map[string]any{"score": 7}, nil, nil, map[string]string{"score": "long"})
	if err != nil || len(emitted) != 1 {
		t.Fatalf("EvalEmitContext failed: emitted=%v err=%v", emitted, err)
	}

	updatedRaw, resOp, err := ApplyUpdateWithResult(json.RawMessage(`{"tags":["x"]}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `ctx._source.tags.add(params.t)`, Params: map[string]any{"t": "y"}},
	}, true)
	if err != nil || resOp != "updated" || !strings.Contains(string(updatedRaw), `"y"`) {
		t.Fatalf("ApplyUpdateWithResult failed: raw=%s op=%s err=%v", updatedRaw, resOp, err)
	}

	// Collections constructors, Arrays.* static utilities, java.math / java.util classes.
	utilSrc := `
		def dq = new ArrayDeque();
		dq.add("a"); dq.add("b");
		def pq = new PriorityQueue();
		pq.add(3); pq.add(1);
		def ts = new TreeSet();
		ts.add("z"); ts.add("a");
		def lhm = new LinkedHashMap();
		lhm.put("k", 1); lhm.put("k2", 2);
		lhm.remove("k", 1);
		def sb = new StringBuilder("hi");
		sb.append("-there");
		def sj = new StringJoiner(",", "[", "]");
		sj.add("1"); sj.add("2");
		def bs = new BitSet();
		bs.set(3);
		def bd = new BigDecimal("12.34");
		def bi = new BigInteger("42");
		def stats = new LongSummaryStatistics();
		stats.accept(10L); stats.accept(20L);
		def a1 = [1, 2, 3, 4];
		def cp = Arrays.copyOf(a1, 2);
		def cpr = Arrays.copyOfRange(a1, 1, 3);
		boolean eq = Arrays.equals([1, 2], [1, 2]);
		boolean deq = Arrays.deepEquals([[1]], [[1]]);
		String s1 = Arrays.toString(a1);
		String s2 = Arrays.deepToString([[1, 2]]);
		long hc = Arrays.hashCode(a1);
		long dhc = Arrays.deepHashCode([[1, 2]]);
		def outArr = [0, 0, 0];
		Arrays.setAll(outArr, idx -> idx * 10);
		return ["dq": dq.size(), "ts": ts.size(), "sb": sb.toString(), "sj": sj.toString(), "eq": eq, "deq": deq, "s1": s1, "s2": s2, "cp": cp.size(), "cpr": cpr.size(), "hc": hc, "dhc": dhc, "outArr": outArr, "bd": bd.toString(), "bi": bi.toString(), "lhm": lhm.size()];
	`
	uVal, err := Eval(nil, utilSrc, nil)
	if err != nil {
		t.Fatalf("unexpected util eval error: %v", err)
	}
	uMap, ok := uVal.(map[string]any)
	if !ok || uMap["sb"] != "hi-there" || uMap["sj"] != "[1,2]" || uMap["eq"] != true || uMap["deq"] != true {
		t.Fatalf("unexpected util eval map: %#v", uVal)
	}
}

func TestRound66CovPainless_TemporalsBigDecStreamsAndErrors(t *testing.T) {
	// 1. Temporals: DayOfWeek/Month plus/minus/getValue, ChronoUnit.between, ZoneOffset, MonthDay, Year, Instant
	tSrc := `
		def z = ZonedDateTime.now();
		def inst = Instant.now();
		def zid = ZoneId.of("America/New_York");
		def z0 = ZoneOffset.ofHours(0);
		def zp = ZoneOffset.ofHours(5);
		def zn = ZoneOffset.ofHours(-4);
		def z6 = ZoneOffset.of("+053000");
		def z6n = ZoneOffset.of("-040000");
		def md1 = MonthDay.of(3, 15);
		def md2 = MonthDay.parse("--03-15");
		def md3 = MonthDay.from(LocalDate.of(2026, 3, 15));
		def yr = Year.from(ZonedDateTime.parse("2026-03-15T10:00:00Z"));
		def dowPlus = DayOfWeek.MONDAY.plus(2);
		def dowMinus = DayOfWeek.WEDNESDAY.minus(1);
		def mPlus = Month.JANUARY.plus(3);
		def mMinus = Month.MARCH.minus(2);
		def daysBetween = ChronoUnit.DAYS.between(LocalDate.of(2026, 1, 1), LocalDate.of(2026, 1, 10));
		return [
			"z": z != null, "inst": inst != null, "zid": zid, "z0": z0, "zp": zp, "zn": zn,
			"z6": z6, "z6n": z6n, "md1": md1 != null, "md2": md2 != null, "md3": md3 != null,
			"yr": yr != null, "dowPlus": dowPlus, "dowMinus": dowMinus, "mPlus": mPlus,
			"mMinus": mMinus, "days": daysBetween
		];
	`
	tv, err := Eval(nil, tSrc, nil)
	if err != nil {
		t.Fatalf("temporal eval failed: %v", err)
	}
	tm, _ := tv.(map[string]any)
	if tm["days"] != int64(9) || tm["z0"] != "Z" || tm["zp"] != "+05:00" || tm["zn"] != "-04:00" {
		t.Fatalf("unexpected temporal result: %#v", tm)
	}
	if sec, ok := parseZoneOffsetSecondsPainless("+053000"); !ok || sec != 5*3600+30*60 {
		t.Fatalf("expected 5h30m offset, got %d %v", sec, ok)
	}
	if sec, ok := parseZoneOffsetSecondsPainless("+250000"); ok || sec != 0 {
		t.Fatalf("expected out-of-range offset rejected, got %d %v", sec, ok)
	}

	// 2. Math.*Exact, getExponent, parse*, BigDecimal, BigInteger, Arrays.compare/mismatch, regex split, Streams, Optional
	mSrc := `
		int fd = Math.floorDiv(-7, 3);
		int fm = Math.floorMod(-7, 3);
		long ae = Math.addExact(10L, 20L);
		long se = Math.subtractExact(20L, 5L);
		long me = Math.multiplyExact(6L, 7L);
		long ie = Math.incrementExact(9L);
		long de = Math.decrementExact(9L);
		long ne = Math.negateExact(5L);
		int ti = Math.toIntExact(42L);
		int e0 = Math.getExponent(0.0);
		int e8 = Math.getExponent(8.0);
		int enan = Math.getExponent(Double.NaN);
		int pi = Integer.parseInt("42");
		long pl = Long.valueOf("99");
		def ps = Short.parseShort("12");
		def pb = Byte.parseByte("7");
		double pd = Double.parseDouble("3.5");
		def pf = Float.parseFloat("2.5");
		boolean pbool = Boolean.parseBoolean("true");
		def bdDiv = new BigDecimal("1").divide(new BigDecimal("3"), 5, RoundingMode.HALF_UP);
		def bi0 = new BigInteger("0").pow(0);
		def bi05 = new BigInteger("0").pow(5);
		def bim1 = new BigInteger("-1").pow(3);
		def sp1 = /[,;]+/.split("a,b;c,d", 3);
		def stSum = Stream.concat([1, 2].stream(), [3, 4].stream()).flatMap(x -> [x, x * 10]).reduce((a, b) -> a + b).get();
		def cmp = Arrays.compare([1, 2, 3], 0, 2, [1, 4, 3], 0, 2);
		def mis = Arrays.mismatch([1, 2, 3], 0, 3, [1, 2, 9], 0, 3);
		def u = new URI("https", "usr", "example.com", 443, "/p", "q=1", "f");
		def stats = new LongSummaryStatistics();
		stats?.accept(4L);
		return [
			"fd": fd, "fm": fm, "ae": ae, "se": se, "me": me, "ie": ie, "de": de, "ne": ne, "ti": ti,
			"e0": e0, "e8": e8, "enan": enan, "pi": pi, "pl": pl, "pd": pd, "pbool": pbool,
			"bd": bdDiv.toString(), "bi0": bi0.toString(), "bi05": bi05.toString(), "bim1": bim1.toString(),
			"sp1": sp1.length, "stSum": stSum, "cmp": cmp, "mis": mis, "u": u.getHost(),
			"ps": ps, "pb": pb, "pf": pf
		];
	`
	mv, err := Eval(nil, mSrc, nil)
	if err != nil {
		t.Fatalf("math/stream eval failed: %v", err)
	}
	mm, _ := mv.(map[string]any)
	if mm["stSum"] != int64(110) || mm["mis"] != int64(2) || mm["bi0"] != "1" || mm["e0"] != int64(-1023) || mm["enan"] != int64(1024) {
		t.Fatalf("unexpected math/stream map: %#v", mm)
	}

	// 3. Error branches: Optional.orElseThrow supplier, Arrays out of bounds / null / inverted, BigInteger negative pow, URI relative path, summary stats bad elem, stream error, labeled while/for loops
	errScripts := []string{
		`Optional.empty().orElseThrow(() -> ["__exc_type": "IllegalStateException", "message": "boom"])`,
		`Arrays.compare(null, 0, 1, [1], 0, 1)`,
		`Arrays.compare([1], 0, 1, null, 0, 1)`,
		`Arrays.compare([1, 2], 2, 1, [1, 2], 0, 1)`,
		`Arrays.mismatch([1, 2], 0, 5, [1, 2], 0, 1)`,
		`new BigInteger("2").pow(-1)`,
		`new URI("https", null, "example.com", -1, "relpath", null, null)`,
		`[1, "bad"].stream().mapToInt(x -> Integer.parseInt(x.toString())).summaryStatistics()`,
		`[1, 2].stream().reduce((a, b) -> { throw ["__exc_type": "IllegalArgumentException", "message": "bad"]; })`,
		`throw ["__exc_type": "CustomException", "message": "thrown_map"]`,
		`LongSummaryStatistics s = null; s.accept(1L);`,
	}
	for _, es := range errScripts {
		if _, err := Eval(nil, es, nil); err == nil {
			t.Fatalf("expected error for script %s", es)
		}
	}
	// Null-safe accept on nil stats must succeed cleanly.
	if _, err := Eval(nil, `LongSummaryStatistics s = null; s?.accept(1L); return 1;`, nil); err != nil {
		t.Fatalf("null-safe accept failed: %v", err)
	}

	// 4. Labeled while/for, DenseVector missing loop error, FieldVal.length, GeoBoundingBoxVal methods, direct internal helpers
	wVal, err := Eval(map[string]any{"tag": []any{"x", "y"}}, `
		int w = 0;
		outerW: while (w < 5) {
			w++;
			int k = 0;
			while (k < 3) {
				k++;
				if (k == 1) { continue outerW; }
				break outerW;
			}
		}
		int flen = doc['tag'].length;
		return w * 10 + flen;
	`, map[string]any{"_field_types": map[string]any{"tag": "keyword"}})
	if err != nil || wVal != int64(52) {
		t.Fatalf("labeled while / FieldVal.length failed: val=%v err=%v", wVal, err)
	}

	// UpdateMetadataVal assignment + ctx._source compound + error path
	rawDoc := json.RawMessage(`{"scalar":"abc","nested":{"cnt":3}}`)
	resRaw, ctxOp, err := ApplyUpdateWithResult(rawDoc, &UpdateRequest{
		Script: &ScriptSpec{Source: `ctx._source.nested.cnt += 4; ctx._source.added = 'hi'; ctx.op = 'index';`},
	}, true)
	if err != nil || ctxOp != "updated" {
		t.Fatalf("ApplyUpdateWithResult failed: op=%s err=%v", ctxOp, err)
	}
	var resMap map[string]any
	if err := json.Unmarshal(resRaw, &resMap); err != nil {
		t.Fatalf("unmarshal updated raw failed: %v", err)
	}
	if nMap, ok := resMap["nested"].(map[string]any); !ok || fmtNumR66(nMap["cnt"]) != "7" {
		t.Fatalf("expected nested.cnt=7, got %#v", resMap)
	}
	if _, _, err := ApplyUpdateWithResult(rawDoc, &UpdateRequest{
		Script: &ScriptSpec{Source: `ctx._source.frozen = Collections.unmodifiableMap(['k': 1]); ctx._source.frozen.k = 2;`},
	}, true); err == nil {
		t.Fatal("expected unmodifiable container parent assignment error")
	}
	// UpdateMetadataVal direct property assignment + EvalUpdate on _source.*
	srcMap := map[string]any{"x": int64(2), "s": "abc"}
	umv := &UpdateMetadataVal{Params: map[string]any{"_ctx_op": "index", "_ctx_id": "1"}, SourceMap: srcMap}
	if _, err := evalAssignExprRound59Painless(srcMap, "ctx.op", "=", "'none'", map[string]any{"ctx": umv}, 0); err != nil {
		t.Fatalf("UpdateMetadataVal assignment failed: %v", err)
	}
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"x":2,"s":"abc"}`), &UpdateRequest{
		Script: &ScriptSpec{Source: `_source.x += 5; _source.added = "ok";`},
	}, true); err != nil {
		t.Fatalf("ApplyUpdateWithResult _source assignment failed: %v", err)
	}

	// Direct internal helper coverage: BigDecimal overflow/compare, comparePainlessValues, extractPatternRegexpPainless, GeoBoundingBoxVal, DenseVectorVal missing
	bdBig := newPainlessBigDecimal(big.NewInt(1), -50)
	bdSmall := newPainlessBigDecimal(big.NewInt(1), 50000)
	if compareBigDecimalPainless(bdBig, bdSmall) != 1 || compareBigDecimalPainless(bdSmall, bdBig) != -1 {
		t.Fatal("unexpected compareBigDecimalPainless fallback result")
	}
	bdTooBig := newPainlessBigDecimal(big.NewInt(1), -500000)
	_ = compareBigDecimalPainless(bdTooBig, bdSmall)
	if _, err := bdTooBig.div(bdSmall, 0, "HALF_UP"); err == nil {
		t.Fatal("expected BigDecimal divide overflow error")
	}
	if comparePainlessValues(newPainlessBigDecimal(big.NewInt(15), 1), "1.50") != 0 {
		t.Fatal("expected BigDecimal == string via comparePainlessValues")
	}
	if re, pat, err := extractPatternRegexpPainless(regexp.MustCompile("abc")); err != nil || re == nil || pat != "abc" {
		t.Fatalf("extractPatternRegexpPainless failed: %v %s", err, pat)
	}
	bbox := &GeoBoundingBoxVal{
		TopLeft:     &GeoPointVal{Lat: 20, Lon: -50},
		BottomRight: &GeoPointVal{Lat: 10, Lon: -30},
	}
	for _, m := range []string{"getTopLeft", "getBottomRight", "getTop", "getBottom", "getLeft", "getRight", "getMinLat", "getMaxLat"} {
		_, handled, _ := evalRound60ReceiverMethod(bbox, m, "", nil, nil, 0)
		if !handled {
			t.Fatalf("expected GeoBoundingBoxVal method %s handled", m)
		}
	}
	_, _ = evalRHSExprDepth(nil, "dv", map[string]any{"dv": &DenseVectorFieldVal{Present: false}}, 0)
	_ = formatValueCycleWalkRound60(map[string]any{"a": 1, "b": "x"}, map[cycleNodeKeyRound60]bool{}, false, 0)
	_ = time.UTC
}

func fmtNumR66(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestRound66CovPainless_MathRegexOptionalsCharactersAndWrappers(t *testing.T) {
	// 1. Math static helpers, getExponent, BigInteger, BitSet, BigDecimal bounds
	okScripts := []string{
		`Math.floorDiv(7, 3) + Math.floorMod(7, 3) + Math.addExact(1, 2) + Math.subtractExact(5, 2) + Math.multiplyExact(3, 4) + Math.incrementExact(4) + Math.decrementExact(4) + Math.negateExact(-3) + Math.toIntExact(6L)`,
		`Math.getExponent(0.0) + Math.getExponent(42.5) + Math.getExponent(Double.POSITIVE_INFINITY) + Math.getExponent(Double.NaN)`,
		`BigInteger.valueOf(42L).intValue() + BigDecimal.valueOf(12345L, 2).scale()`,
		`BitSet.valueOf([5L, 3L]).stream().count() == 4`,
		`Character.isValidCodePoint(65) && Character.isBmpCodePoint(65) && Character.isSupplementaryCodePoint(128512) && Character.isHighSurrogate(0xD83D) && Character.isLowSurrogate(0xDE00) && Character.isSurrogate(0xD83D) && Character.isSurrogatePair(0xD83D, 0xDE00) && Character.toCodePoint(0xD83D, 0xDE00) == 128512 && Character.codePointAt("hi", 0) == 104`,
		`/;/.split("a;b;c", 2).length + //.split("ab", 3).length`,
		`Objects.equals("a", "a") && Objects.isNull(null) && Objects.nonNull(1) && Objects.toString(null, "d") == "d"`,
		`Arrays.equals(Arrays.copyOf([1, 2, 3], 2), [1, 2]) && Arrays.equals(Arrays.copyOfRange([1, 2, 3, 4], 1, 3), [2, 3]) && Arrays.deepEquals([[1, 2]], [[1, 2]])`,
		`Optional.of(7).isPresent() && Optional.of(7).stream().count() == 1 && Optional.empty().stream().count() == 0 && Optional.of(7).orElseThrow() == 7`,
		`"a\nb".lines().count() == 2 && "abc".chars().count() == 3`,
		`LocalDate.parse("2026-01-01").datesUntil(LocalDate.parse("2026-01-05"), Period.ofDays(2)).size() + ChronoUnit.DAYS.between(LocalDate.parse("2026-01-01"), LocalDate.parse("2026-01-05"))`,
		`LocalDateTime.parse("2026-01-01T12:00:00").atOffset("+02:00") != null`,
		`DayOfWeek.MONDAY.plus(2) + ":" + DayOfWeek.MONDAY.minus(1) + ":" + Month.JANUARY.plus(1) + ":" + Month.MARCH.minus(2) + ":" + DayOfWeek.WEDNESDAY.getValue() + ":" + Month.DECEMBER.getValue()`,
	}
	for _, src := range okScripts {
		v, err := Eval(map[string]any{"x": 1}, src, nil)
		if err != nil {
			t.Fatalf("unexpected Eval error for %q: %v", src, err)
		}
		if b, ok := v.(bool); ok && !b {
			t.Fatalf("expected true for %q", src)
		}
	}

	// 2. Compound assignment on ctx._source + forEach over ctx + list replaceAll
	docSrc := map[string]any{
		"count": 10,
		"tags":  []any{"a", "b"},
	}
	if _, err := Eval(docSrc, `ctx._source.count += 5; ctx._source.tags.replaceAll(x -> x.toUpperCase()); int n = 0; for (def t : ctx._source.tags) { n++; } return n;`, map[string]any{"__is_ingest": true}); err != nil {
		t.Fatalf("compound ctx/_source script failed: %v", err)
	}
	if _, err := Eval(map[string]any{"a": 1}, `ctx.bad += 1`, map[string]any{"__is_update_doc": true}); err == nil {
		t.Fatal("expected unsupported ctx.bad error in update doc mode")
	}

	// 3. Expected exceptions: null regex split input, Optional orElseThrow / OptionalInt empty, Map.ofEntries dup/null, scale bounds
	errScripts := []string{
		`/,/.split(null, 2)`,
		`Optional.empty().orElseThrow()`,
		`OptionalInt.empty().getAsInt()`,
		`Map.ofEntries(Map.entry("k", null))`,
		`Map.ofEntries(Map.entry("k", 1), Map.entry("k", 2))`,
		`BigDecimal.valueOf(1L, 1000000)`,
		`LocalDateTime.parse("2026-01-01T00:00:00").atOffset("bad_zone")`,
	}
	for _, src := range errScripts {
		if _, err := Eval(map[string]any{}, src, nil); err == nil {
			t.Fatalf("expected error for %q", src)
		}
	}

	// 4. Direct receiver wrapper coverage: FieldDocVal, DenseVectorFieldVal, DenseVectorVal, GeoShapeDocValues
	dvMissing := &DenseVectorVal{Name: "v"}
	if !dvMissing.isMissingVectorRound62() {
		t.Fatal("expected empty DenseVectorVal to be missing")
	}
	_, _ = evalRHSExprDepth(nil, "dv.length()", map[string]any{"dv": &DenseVectorFieldVal{Present: false}}, 0)
	_, _ = evalRHSExprDepth(nil, "dv.isEmpty()", map[string]any{"dv": &DenseVectorFieldVal{Present: false}}, 0)
	_, _ = evalRHSExprDepth(nil, "dv.length()", map[string]any{"dv": &DenseVectorFieldVal{Present: true, Vec: &DenseVectorVal{Floats: []float32{1, 2}}}}, 0)
	_, _ = evalRHSExprDepth(nil, "dv.length()", map[string]any{"dv": dvMissing}, 0)
	_, _ = evalRHSExprDepth(nil, "dv.isEmpty()", map[string]any{"dv": dvMissing}, 0)

	fDoc := &FieldDocVal{
		Doc:       map[string]any{"name": "alpha"},
		Params:    map[string]any{},
		FieldPath: "items",
		WriteMode: false,
	}
	for _, m := range []string{"exists", "remove"} {
		if _, handled, _ := evalRound60ReceiverMethod(fDoc, m, "", nil, nil, 0); !handled {
			t.Fatalf("expected FieldDocVal %s handled", m)
		}
	}
	if _, handled, err := evalRound60ReceiverMethod(fDoc, "field", `"name"`, nil, nil, 0); !handled || err != nil {
		t.Fatalf("expected FieldDocVal field() handled without err, got handled=%v err=%v", handled, err)
	}
	if _, handled, _ := evalRound60ReceiverMethod(fDoc, "$", `"name"`, nil, nil, 0); !handled {
		t.Fatal("expected FieldDocVal $() handled")
	}
	if _, handled, err := evalRound60ReceiverMethod(fDoc, "field", "", nil, nil, 0); !handled || err == nil {
		t.Fatalf("expected FieldDocVal missing arg error, got handled=%v err=%v", handled, err)
	}

	gsdv := &GeoShapeDocValues{ShapeType: "Point", Points: [][2]float64{{10, 20}}, HasBBox: true, MinLat: 10, MaxLat: 10, MinLon: 20, MaxLon: 20}
	if s := gsdv.String(); s != "<unserializable>" {
		t.Fatalf("unexpected GeoShapeDocValues String(): %s", s)
	}
	_, _, _ = evalRound60ReceiverMethod(gsdv, "get", "0", nil, nil, 0)
}

func TestRound66CovPainless_TemporalsAdjustersStreamsMapLambdasAndWrappers(t *testing.T) {
	// 1. TemporalAdjusters, ZoneOffset, MonthDay, Hex/Base64, URI components, Day/Month .getValue()
	scripts := []string{
		`ZoneOffset.ofHours(0) != null && ZoneOffset.ofHours(2) != null && ZoneOffset.ofHours(-3) != null`,
		`MonthDay.of("MARCH", 15) != null && TemporalAdjusters.firstDayOfMonth() != null && TemporalAdjusters.lastDayOfMonth() != null && TemporalAdjusters.firstDayOfNextMonth() != null && TemporalAdjusters.firstDayOfYear() != null && TemporalAdjusters.lastDayOfYear() != null && TemporalAdjusters.firstDayOfNextYear() != null`,
		`TemporalAdjusters.next("MONDAY") != null && TemporalAdjusters.previousOrSame("FRIDAY") != null && TemporalAdjusters.dayOfWeekInMonth(2, "TUESDAY") != null`,
		`Encoding.decodeHex(Encoding.encodeHex("doris")) == "doris" && Hex.encodeHexString("ab") == "6162"`,
		`def u = new URI("http", "user", "example.com", 8080, "/p", "q=1", "f"); u.getPort() == 8080 && u.getPath() == "/p" && u.getRawPath() == "/p" && u.getQuery() == "q=1" && u.getRawQuery() == "q=1" && u.getFragment() == "f" && u.getRawFragment() == "f" && u.isAbsolute()`,
		`"MONDAY".getValue() == 1 && "TUESDAY".getValue() == 2 && "THURSDAY".getValue() == 4 && "FRIDAY".getValue() == 5 && "SATURDAY".getValue() == 6 && "SUNDAY".getValue() == 7 && "AUGUST".getValue() == 8 && "SEPTEMBER".getValue() == 9 && "OCTOBER".getValue() == 10 && "NOVEMBER".getValue() == 11`,
		`def arr = [1, 2, 3, 4]; Arrays.parallelPrefix(arr, (a, b) -> a + b); return arr[3] == 10`,
		`[1, 2, 3].stream().toArray(int[]::new).length == 3`,
		`Optional.of(5).stream().map(x -> x + 1).findFirst().get() == 6`,
		`def m = ["a": 1, "b": 2]; m.replaceAll((k, v) -> v * 2); m.computeIfPresent("a", (k, v) -> null); m.merge("b", 5, (x, y) -> x + y); return !m.containsKey("a") && m["b"] == 9`,
		`[1, 2, 3].stream().collect(Collectors.reducing(0, (a, b) -> a + b)) == 6`,
		`class BaseR66 { int f(int x) { return x + 1; } static int stat() { return 9; } } class ChildR66 extends BaseR66 { int f(int x) { return super.f(x) * 2; } } return new ChildR66().f(3) + BaseR66.stat() == 17`,
	}
	for _, src := range scripts {
		v, err := Eval(map[string]any{}, src, nil)
		if err != nil {
			t.Fatalf("script %q failed: %v", src, err)
		}
		if b, ok := v.(bool); ok && !b {
			t.Fatalf("expected true for %q", src)
		}
	}

	// 2. Direct wrapper coverage: ByteBufferVal, FieldVal asLong/deduplicate/asDouble, extractFloatVectorRound60, UpdateMetadataVal compound assign
	bb := newByteBufferValRound60([]byte{10, 20})
	if v, err := bb.Get(0); err != nil || v != 10 {
		t.Fatalf("ByteBufferVal.Get failed: %d err=%v", v, err)
	}
	_, _, _ = evalRound60ReceiverMethod(bb, "get", "0", nil, nil, 0)
	_, _, _ = evalRound60ReceiverMethod(bb, "equals", "123", nil, nil, 0)
	_, _, _ = evalRound60ReceiverMethod(bb, "toString", "", nil, nil, 0)

	fv := &FieldVal{Name: "num", Values: []any{"10", "10", "20"}, FieldType: "long"}
	_, _, _ = evalRound60ReceiverMethod(fv, "deduplicate", "", nil, nil, 0)
	_, _, _ = evalRound60ReceiverMethod(fv, "asLong", "0, 99", nil, nil, 0)
	_, _, _ = evalRound60ReceiverMethod(fv, "asLong", "5, 99", nil, nil, 0)
	_, _, _ = evalRound60ReceiverMethod(&FieldVal{Name: "empty"}, "asLong", "7", nil, nil, 0)
	_, _, _ = evalRound60ReceiverMethod(fv, "asDouble", "0, 1.5", nil, nil, 0)
	_, _, _ = evalRound60ReceiverMethod(fv, "asDouble", "5, 1.5", nil, nil, 0)
	_, _, _ = evalRound60ReceiverMethod(&FieldVal{Name: "empty"}, "asDouble", "2.5", nil, nil, 0)
	_, _, _ = evalRound60ReceiverMethod(&FieldVal{Name: "bad", Values: []any{"bad"}}, "asDouble", "", nil, nil, 0)

	if vec, err := extractFloatVectorRound60("vec", map[string]any{"vec": []any{1.0, 2.0}}, map[string]any{}, true); err != nil || len(vec) != 2 {
		t.Fatalf("extractFloatVectorRound60 failed: %v err=%v", vec, err)
	}
	if _, err := extractFloatVectorRound60("missing_vec", map[string]any{}, map[string]any{}, true); err == nil {
		t.Fatal("expected missing vector error")
	}

	srcMap := map[string]any{"x": int64(2)}
	umv := &UpdateMetadataVal{Params: map[string]any{"_ctx_op": "del", "_ctx_id": "1"}, SourceMap: srcMap}
	if _, err := evalAssignExprRound59Painless(srcMap, "ctx.op", "+=", "'ete'", map[string]any{"ctx": umv}, 0); err != nil {
		t.Fatalf("UpdateMetadataVal compound assign failed: %v", err)
	}
	if _, err := evalAssignExprRound59Painless(srcMap, "ctx.op", "+=", "'!'", map[string]any{"ctx": umv}, 0); err == nil {
		t.Fatal("expected invalid op error on delete!")
	}
}

func TestRound66CovPainless_FallbackNilAndErrorEdges(t *testing.T) {
	// Nil/missing-arg/error fallback branches across Character, Math, BigInteger, BitSet, Arrays, Objects, ZoneOffset, MonthDay, Encoding, Stream, ByteBufferVal
	nilOrBoolScripts := []string{
		`!Character.isValidCodePoint("bad") && !Character.isBmpCodePoint("bad") && !Character.isSupplementaryCodePoint("bad")`,
		`!Character.isHighSurrogate("bad") && !Character.isLowSurrogate("bad") && !Character.isSurrogate("bad")`,
		`!Character.isSurrogatePair(1) && !Character.isSurrogatePair("bad", 1) && Character.toCodePoint(1) == 0 && Character.toCodePoint("bad", 1) == 0 && Character.codePointAt("hi") == 0`,
		`BigInteger.valueOf().intValue() == 0 && BitSet.valueOf().cardinality() == 0`,
		`Arrays.copyOf().length == 0 && Arrays.copyOfRange().length == 0 && !Arrays.equals() && Objects.equals() == false && Objects.isNull() && !Objects.nonNull()`,
		`Objects.toString() == "null" && Objects.toString(null) == "null" && Objects.toString(null, null) == null`,
		`ZoneOffset.ofHours() == "Z" && Encoding.encodeHex() == "" && Encoding.decodeHex("bad_hex") == ""`,
		`"MARCH".getValue() == 3 && "DECEMBER".getValue() == 12`,
	}
	for _, src := range nilOrBoolScripts {
		v, err := Eval(map[string]any{}, src, nil)
		if err != nil {
			t.Fatalf("fallback script %q failed: %v", src, err)
		}
		if b, ok := v.(bool); ok && !b {
			t.Fatalf("expected true for %q", src)
		}
	}
	for _, errSrc := range []string{
		`Math.getExponent(null)`,
		`MonthDay.of("BAD_MONTH", 1)`,
	} {
		if _, err := Eval(map[string]any{}, errSrc, nil); err == nil {
			t.Fatalf("expected error for %q", errSrc)
		}
	}

	bb := newByteBufferValRound60([]byte{65, 66, 67})
	if l, ok, err := evalRound60ZeroArgMethod(".limit()", bb, nil, nil, 0); !ok || err != nil || fmtNumR66(l) != "3" {
		t.Fatalf("unexpected ByteBufferVal limit: %v ok=%v err=%v", l, ok, err)
	}
	if hr, ok, err := evalRound60ZeroArgMethod(".hasRemaining()", bb, nil, nil, 0); !ok || err != nil || hr != true {
		t.Fatalf("unexpected ByteBufferVal hasRemaining: %v ok=%v err=%v", hr, ok, err)
	}
	if g, ok, err := evalRound60ReceiverMethod(bb, "get", "1", nil, nil, 0); !ok || err != nil || fmtNumR66(g) != "66" {
		t.Fatalf("unexpected ByteBufferVal get(1): %v ok=%v err=%v", g, ok, err)
	}
	if g0, ok, err := evalRound60ReceiverMethod(bb, "get", "", nil, nil, 0); !ok || err != nil || fmtNumR66(g0) != "65" {
		t.Fatalf("unexpected ByteBufferVal get(): %v ok=%v err=%v", g0, ok, err)
	}
	if s, ok, err := evalRound60ZeroArgMethod(".utf8ToString()", bb, nil, nil, 0); !ok || err != nil || s != "BC" {
		t.Fatalf("unexpected ByteBufferVal utf8ToString: %v ok=%v err=%v", s, ok, err)
	}
}

func TestRound66CovPainless_UpdateMetadataGetSetAndSummaryStats(t *testing.T) {
	// 1. UpdateMetadataVal.getField & setField edge cases
	var nilUM *UpdateMetadataVal
	if _, ok, _ := nilUM.getField("id"); ok {
		t.Fatal("expected ok=false for nil UpdateMetadataVal")
	}
	_ = nilUM.setField("op", "index")

	um := &UpdateMetadataVal{
		Params: map[string]any{},
		SourceMap: map[string]any{
			"_id":      "src_1",
			"_index":   "src_idx",
			"_version": int64(7),
		},
		Budget: &evalBudget{hasCtxOp: true, ctxOp: "create"},
	}
	for _, prop := range []string{"id", "index", "version", "versionType", "op", "now", "unknown_prop"} {
		_, _, _ = um.getField(prop)
	}
	umFallback := &UpdateMetadataVal{Params: map[string]any{}}
	for _, prop := range []string{"id", "index", "version", "op", "routing"} {
		_, _, _ = umFallback.getField(prop)
	}
	umUpsert := &UpdateMetadataVal{Params: map[string]any{"__upsert_insert_mode": true, "_ctx_routing": ""}}
	if _, _, err := umUpsert.getField("routing"); err == nil {
		t.Fatal("expected IllegalArgumentException for missing routing during upsert insert")
	}
	umForbid := &UpdateMetadataVal{Params: map[string]any{"__forbid_metadata_routing": true}}
	if _, _, err := umForbid.getField("routing"); err == nil {
		t.Fatal("expected IllegalArgumentException when routing is forbidden")
	}
	if err := um.setField("op", "noop"); err != nil {
		t.Fatalf("unexpected error setting op=noop: %v", err)
	}
	if err := um.setField("op", "invalid_op"); err == nil {
		t.Fatal("expected error for invalid op in doc mode")
	}
	umUBQ := &UpdateMetadataVal{Params: map[string]any{"__is_ubq": true, "__is_es8": true}}
	if err := umUBQ.setField("op", "create"); err == nil {
		t.Fatal("expected error for op=create in UBQ ES8 mode")
	}

	// 2. computeSummaryStatsWithKindPainless for Int/Long/Double summary stats + nil/error paths
	if m, err := computeSummaryStatsWithKindPainless([]any{1, 5, 3}, "", "", map[string]any{}, map[string]any{}, 0); err != nil || fmtNumR66(m["sum"]) != "9" {
		t.Fatalf("unexpected IntSummaryStatistics: %#v err=%v", m, err)
	}
	if m, err := computeSummaryStatsWithKindPainless([]any{int64(2), int64(4)}, "x -> x * 2", "DoubleSummaryStatistics", map[string]any{}, map[string]any{}, 0); err != nil || fmtNumR66(m["count"]) != "2" {
		t.Fatalf("unexpected mapped DoubleSummaryStatistics: %#v err=%v", m, err)
	}
	if m, err := computeSummaryStatsWithKindPainless([]any{int64(10), int64(20)}, "", "LongSummaryStatistics", map[string]any{}, map[string]any{}, 0); err != nil || fmtNumR66(m["count"]) != "2" {
		t.Fatalf("unexpected LongSummaryStatistics: %#v err=%v", m, err)
	}
	if _, err := computeSummaryStatsWithKindPainless([]any{nil}, "", "LongSummaryStatistics", map[string]any{}, map[string]any{}, 0); err == nil {
		t.Fatal("expected error passing nil element to LongSummaryStatistics")
	}
	if _, err := computeSummaryStatsWithKindPainless([]any{"bad"}, "x -> Integer.parseInt(x)", "IntSummaryStatistics", map[string]any{}, map[string]any{}, 0); err == nil {
		t.Fatal("expected lambda parse error in computeSummaryStatsWithKindPainless")
	}
}
