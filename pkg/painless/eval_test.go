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
	"strings"
	"testing"
)

func TestEvalPainless_OpenMetadataTagAndSoftDeleteMutations(t *testing.T) {
	initial := `{"name":"orders","deleted":false,"updatedAt":1729773296789,"tier":{"tagFQN":"Tier.Tier2"},"tags":[{"tagFQN":"PII.Sensitive"},{"tagFQN":"Legacy"}],"followers":["u1","u2"]}`

	req := &UpdateRequest{
		Script: &ScriptSpec{
			Source: `
				ctx._source.deleted = params.deleted;
				ctx._source.remove('tier');
				ctx._source.tags.removeIf(t -> t.tagFQN == params.removeTag);
				if (ctx._source.tags == null) { ctx._source.tags = []; }
				if (!ctx._source.tags.contains(params.newTag)) {
					ctx._source.tags.add(params.newTag);
				}
				ctx._source.followers.removeIf(u -> u == params.removeFollower);
			`,
			Params: map[string]any{
				"deleted":        true,
				"removeTag":      "Legacy",
				"newTag":         map[string]any{"tagFQN": "Tier.Tier1"},
				"removeFollower": "u1",
			},
		},
	}

	updatedBytes, err := ApplyUpdate(json.RawMessage(initial), req)
	if err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}
	// Verify 13-digit epoch timestamp was not corrupted into scientific notation
	if !strings.Contains(string(updatedBytes), `"updatedAt":1729773296789`) {
		t.Errorf("expected exact updatedAt integer in JSON, got %s", string(updatedBytes))
	}

	var out map[string]any
	if err := json.Unmarshal(updatedBytes, &out); err != nil {
		t.Fatalf("failed to unmarshal updated doc: %v", err)
	}

	if out["deleted"] != true {
		t.Errorf("expected deleted=true, got %v", out["deleted"])
	}
	if _, hasTier := out["tier"]; hasTier {
		t.Errorf("expected tier to be removed, still present: %v", out["tier"])
	}
	tags, ok := out["tags"].([]any)
	if !ok || len(tags) != 2 {
		t.Fatalf("expected 2 tags after removeIf + add, got %+v", out["tags"])
	}
	followers, ok := out["followers"].([]any)
	if !ok || len(followers) != 1 || followers[0] != "u2" {
		t.Fatalf("expected followers [u2] after scalar removeIf, got %+v", out["followers"])
	}
}

func TestEvalPainless_PutAll_AddAll_CompoundAssign_Loops_And_Upserts(t *testing.T) {
	initial := `{"count":10,"score":2.5,"nested":{"a":1,"b":2},"items":["x"]}`
	req := &UpdateRequest{
		Doc: map[string]any{
			"nested": map[string]any{"b": 20, "c": 30},
		},
		Script: &ScriptSpec{
			Source: `
				ctx._source.count += 5;
				ctx._source.score -= 0.5;
				ctx._source.nested.put('d', 40);
				ctx._source.extra.putAll(params.extraMap);
				ctx._source.items.addAll(params.moreItems);
				for (tag in params.loopTags) {
					if (tag != 'skip') {
						ctx._source.items.add(tag);
					} else {
						ctx._source.skipped = true;
					}
				}
			`,
			Params: map[string]any{
				"extraMap":  map[string]any{"k1": "v1", "k2": 99},
				"moreItems": []any{"y", "z"},
				"loopTags":  []any{"t1", "skip", "t2"},
			},
		},
	}

	updated, opRes, err := ApplyUpdateWithResult(json.RawMessage(initial), req, true)
	if err != nil || opRes != "updated" {
		t.Fatalf("ApplyUpdateWithResult failed: opRes=%q err=%v", opRes, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(updated, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["count"] != float64(15) || doc["score"] != float64(2) || doc["skipped"] != true {
		t.Fatalf("unexpected arithmetic/loop state: %+v", doc)
	}
	nestedMap := doc["nested"].(map[string]any)
	if nestedMap["a"] != float64(1) || nestedMap["b"] != float64(20) || nestedMap["c"] != float64(30) || nestedMap["d"] != float64(40) {
		t.Fatalf("unexpected deepMergeMap + put result: %+v", nestedMap)
	}
	extraMap := doc["extra"].(map[string]any)
	if extraMap["k1"] != "v1" || extraMap["k2"] != float64(99) {
		t.Fatalf("unexpected putAll result: %+v", extraMap)
	}
	items := doc["items"].([]any)
	if len(items) != 5 {
		t.Fatalf("expected 5 items after addAll + for loop, got %+v", items)
	}

	// Test doc_as_upsert when document does not exist
	upsertBytes, opRes2, err := ApplyUpdateWithResult(nil, &UpdateRequest{
		Doc:         map[string]any{"title": "upserted"},
		DocAsUpsert: true,
	}, false)
	if err != nil || opRes2 != "created" || !strings.Contains(string(upsertBytes), `"title":"upserted"`) {
		t.Fatalf("unexpected doc_as_upsert result: op=%q body=%s err=%v", opRes2, string(upsertBytes), err)
	}

	// Test explicit upsert without scripted_upsert
	upsertBytes2, opRes3, err := ApplyUpdateWithResult(nil, &UpdateRequest{
		Upsert: map[string]any{"status": "seeded"},
		Script: &ScriptSpec{Source: "ctx._source.status = 'mutated'"},
	}, false)
	if err != nil || opRes3 != "created" || !strings.Contains(string(upsertBytes2), `"status":"seeded"`) {
		t.Fatalf("unexpected upsert result: op=%q body=%s err=%v", opRes3, string(upsertBytes2), err)
	}

	// Test ctx.op = 'noop' and ctx.op = 'delete'
	_, noopRes, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Script: &ScriptSpec{Source: "ctx.op = 'noop'"},
	}, true)
	if err != nil || noopRes != "noop" {
		t.Fatalf("expected noop, got %q (err=%v)", noopRes, err)
	}
	_, delRes, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), &UpdateRequest{
		Script: &ScriptSpec{Source: "ctx.op = 'delete'"},
	}, true)
	if err != nil || delRes != "deleted" {
		t.Fatalf("expected deleted, got %q (err=%v)", delRes, err)
	}
}

func TestEvalCondition_PrecedenceAndRelationalOperators(t *testing.T) {
	initial := `{"a":true,"b":true,"c":false,"count":15}`
	req := &UpdateRequest{
		Script: &ScriptSpec{
			Source: `
				if (ctx._source.a == true || ctx._source.b == true && ctx._source.c == true) {
					ctx._source.precedence_ok = true;
				}
				if (ctx._source.count >= 15 && ctx._source.count < 20 && ctx._source.count > 10 && ctx._source.count <= 15) {
					ctx._source.range_ok = true;
				}
			`,
		},
	}
	updated, opRes, err := ApplyUpdateWithResult(json.RawMessage(initial), req, true)
	if err != nil || opRes != "updated" {
		t.Fatalf("ApplyUpdateWithResult failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(updated, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["precedence_ok"] != true {
		t.Fatalf("expected true || true && false to evaluate to true (`&&` binds tighter than `||`), got: %+v", doc)
	}
	if doc["range_ok"] != true {
		t.Fatalf("expected relational operators (>=, <=, >, <) to evaluate to true, got: %+v", doc)
	}
}

func TestEval_LeftAssociativeSubStringConcatParensUpsertAndRemove(t *testing.T) {
	initial := `{"a":1,"b":0,"c":0,"tags":["x","y","z"],"temp":"drop_me"}`
	req := &UpdateRequest{
		Script: &ScriptSpec{
			Source: `
				ctx._source.sub_chain = 10 - 3 - 2;
				ctx._source.sub_add = 10 - 3 + 2;
				ctx._source.str_concat = '10' + '20';
				if ((ctx._source.a == 1 || ctx._source.b == 1) && ctx._source.c == 1) {
					ctx._source.paren_cond = true;
				} else {
					ctx._source.paren_cond = false;
				}
				if (!(ctx._source.c == 1)) {
					ctx._source.neg_cond = true;
				}
				ctx._source.remove(params.rm_field);
				ctx._source.tags.remove(1);
			`,
			Params: map[string]any{"rm_field": "temp"},
		},
	}
	updated, opRes, err := ApplyUpdateWithResult(json.RawMessage(initial), req, true)
	if err != nil || opRes != "updated" {
		t.Fatalf("ApplyUpdateWithResult failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(updated, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["sub_chain"] != float64(5) {
		t.Fatalf("expected 10 - 3 - 2 == 5, got %v", doc["sub_chain"])
	}
	if doc["sub_add"] != float64(9) {
		t.Fatalf("expected 10 - 3 + 2 == 9, got %v", doc["sub_add"])
	}
	if doc["str_concat"] != "1020" {
		t.Fatalf("expected '10' + '20' == \"1020\", got %v", doc["str_concat"])
	}
	if doc["paren_cond"] != false {
		t.Fatalf("expected ((1 || 0) && 0) == false, got %v", doc["paren_cond"])
	}
	if doc["neg_cond"] != true {
		t.Fatalf("expected !(0 == 1) == true, got %v", doc["neg_cond"])
	}
	if _, exists := doc["temp"]; exists {
		t.Fatalf("expected params.rm_field ('temp') to be removed, got %+v", doc)
	}
	tags, _ := doc["tags"].([]any)
	if len(tags) != 2 || tags[0] != "x" || tags[1] != "z" {
		t.Fatalf("expected tags.remove(1) to leave [x, z], got %+v", tags)
	}

	// Verify empty upsert: {} with scripted_upsert: true creates document
	upserted, upRes, err := ApplyUpdateWithResult(nil, &UpdateRequest{
		ScriptedUpsert: true,
		Upsert:         map[string]any{},
		Script:         &ScriptSpec{Source: "ctx._source.created = 'yes'"},
	}, false)
	if err != nil || upRes != "created" || string(upserted) != `{"created":"yes"}` {
		t.Fatalf("expected empty upsert: {} with scripted_upsert to create doc, got %s (%s, err=%v)", string(upserted), upRes, err)
	}
}

func TestEval_BracketAccessParenthesizedRHSAndMultilineElse(t *testing.T) {
	initial := `{"count":4,"status":"pending"}`
	req := &UpdateRequest{
		Script: &ScriptSpec{
			Source: `
				ctx._source['computed'] = (ctx._source['count'] + 1) * 2;
				ctx._source["from_param"] = params['label'];
				if (ctx._source['count'] > 10) {
					ctx._source['branch'] = 'high';
				}
				else {
					ctx._source['branch'] = 'low';
				}
			`,
			Params: map[string]any{"label": "ok-bracket"},
		},
	}
	updated, opRes, err := ApplyUpdateWithResult(json.RawMessage(initial), req, true)
	if err != nil || opRes != "updated" {
		t.Fatalf("ApplyUpdateWithResult failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(updated, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["computed"] != float64(10) {
		t.Fatalf("expected (4 + 1) * 2 == 10, got %v", doc["computed"])
	}
	if doc["from_param"] != "ok-bracket" {
		t.Fatalf("expected params['label'] == \"ok-bracket\", got %v", doc["from_param"])
	}
	if doc["branch"] != "low" {
		t.Fatalf("expected multiline }\\nelse { to execute else branch ('low'), got %v", doc["branch"])
	}
}

func TestPainlessRound28ComprehensiveCoverage(t *testing.T) {
	// 1. Round-28 Fix: removeIf returns boolean (true when removed, false when unchanged)
	// in standalone return, if-condition, and variable assignment.
	srcDoc := map[string]any{
		"tags":   []any{"keep", "stale", "active"},
		"scores": []any{float64(1), float64(5), float64(2), float64(8)},
	}
	resVal, err := Eval(srcDoc, `
		List nums = new ArrayList();
		nums.add(1);
		nums.add(5);
		nums.add(2);
		boolean removedAny = nums.removeIf(x -> x < 3);
		boolean removedAgain = nums.removeIf(x -> x < 3);
		return removedAny && !removedAgain && nums.size() == 1 && nums.get(0) == 5;
	`, nil)
	if err != nil || resVal != true {
		t.Fatalf("expected removeIf boolean return test to yield true, got %v (err=%v)", resVal, err)
	}

	updBytes, opRes, err := ApplyUpdateWithResult(
		json.RawMessage(`{"tags":["keep","stale","active"]," untouched":["a","b"]}`),
		&UpdateRequest{
			Script: &ScriptSpec{
				Source: `
					if (ctx._source.tags.removeIf(t -> t == 'stale')) {
						ctx._source.cleaned = true;
					}
					if (ctx._source.tags.removeIf(t -> t == 'nonexistent')) {
						ctx._source.unexpected = true;
					}
				`,
			},
		},
		true,
	)
	if err != nil || opRes != "updated" {
		t.Fatalf("ApplyUpdateWithResult removeIf in if-cond failed: %v", err)
	}
	var updMap map[string]any
	if err := json.Unmarshal(updBytes, &updMap); err != nil {
		t.Fatal(err)
	}
	if updMap["cleaned"] != true || updMap["unexpected"] != nil {
		t.Fatalf("expected cleaned=true and unexpected=nil, got %+v", updMap)
	}

	// 2. Round-28 Fix: ZonedDateTime.parse preserves parsed timezone offset and supports +0000 / -0700 compact offsets.
	tzRes, err := Eval(map[string]any{}, `
		ZonedDateTime zTokyo = ZonedDateTime.parse('2026-10-30T15:30:45+09:00');
		ZonedDateTime zCompact = ZonedDateTime.parse('2026-10-30T08:15:00-0700');
		ZonedDateTime zUTCCompact = ZonedDateTime.parse('2026-10-30T15:15:00+0000');
		return zTokyo.getHour() == 15 && zTokyo.getMinute() == 30 &&
			zCompact.getHour() == 8 && zCompact.getMinute() == 15 &&
			zCompact.toInstant().toEpochMilli() == zUTCCompact.toInstant().toEpochMilli();
	`, nil)
	if err != nil || tzRes != true {
		t.Fatalf("expected ZonedDateTime.parse timezone & compact offset check to return true, got %v (err=%v)", tzRes, err)
	}

	// 3. Round-28 Fix: params.clear() preserves _source and __-prefixed internal state
	clearRes, err := Eval(map[string]any{"price": float64(42)}, `
		params.clear();
		return params._source.price;
	`, map[string]any{"user_param": "temp", "__internal_flag": true})
	if err != nil || clearRes != float64(42) {
		t.Fatalf("expected params.clear() to preserve params._source.price == 42, got %v (err=%v)", clearRes, err)
	}

	// 4. Direct EvalNumber and EvalFilter coverage: loops, bitwise/shift ops, entrySet, Math, strings
	numDoc := map[string]any{
		"a":      float64(10),
		"b":      float64(3),
		"items":  []any{float64(1), float64(2), float64(3), float64(4), float64(5)},
		"code":   "ERR-404-TIMEOUT",
		"nested": map[string]any{"k1": float64(7), "k2": float64(8)},
	}
	numVal, ok, err := EvalNumber(numDoc, `
		int sum = 0;
		for (int i = 0; i < 5; i++) {
			if (i == 1) { continue; }
			if (i == 4) { break; }
			sum += i;
		}
		int w = 0;
		int count = 0;
		while (w < 6) {
			w += 2;
			count++;
		}
		int bits = ((1 << 4) | 3) & 7;
		int mapSum = 0;
		for (entry in doc['nested'].value.entrySet()) {
			mapSum += entry.getValue();
		}
		int itemSum = 0;
		for (x in params._source.items) {
			if (x >= 2) {
				itemSum += x * 2;
			}
		}
		return sum + count + bits + mapSum + itemSum;
	`, nil)
	// sum = 0 + 2 + 3 = 5; count = 3; bits = (16|3)&7 = 19&7 = 3; mapSum = 15; itemSum = (2+3+4+5)*2 = 28 => total = 54
	if err != nil || !ok || numVal != 54 {
		t.Fatalf("expected EvalNumber == 54, got val=%v ok=%v err=%v", numVal, ok, err)
	}

	// 5. EvalFilter with regex, String methods, Collections, sorting, putAll, clear
	filterOK, err := EvalFilter(numDoc, `
		if (!(doc['code'].value =~ /ERR-\d+-[A-Z]+/)) { return false; }
		List parts = doc['code'].value.split('-');
		int errCode = Integer.parseInt(parts.get(1));
		String label = parts.get(2).toLowerCase().trim();
		List list = new ArrayList();
		list.add(30);
		list.add(10);
		list.add(20);
		list.sort((x, y) -> x - y);
		Map m1 = new HashMap();
		m1.put('a', 1);
		Map m2 = new HashMap();
		m2.putAll(m1);
		m1.clear();
		return errCode == 404 && label.startsWith('time') && list.get(0) == 10 && list.get(2) == 30 && m2.get('a') == 1 && m1.isEmpty();
	`, nil)
	if err != nil || !filterOK {
		t.Fatalf("expected EvalFilter == true, got %v (err=%v)", filterOK, err)
	}

	// 6. Comprehensive coverage of Math, String, Collections, DateTime, Casts, Elvis/Ternary, Bitwise Assigns
	richOut, err := Eval(numDoc, `
		// Single-line comment
		/* Multi-line
		   comment */
		int bw = 5;
		bw |= 2;
		bw &= 6;
		bw ^= 1;
		bw <<= 1;
		bw >>= 1;
		bw >>>= 1;
		int mulAssign = 10;
		mulAssign *= 3;
		mulAssign /= 2;
		mulAssign %= 4;
		int preInc = ++mulAssign;
		int postInc = mulAssign++;
		int negAndNot = -preInc + ~0;
		double mVal = Math.abs(-4) + Math.min(2, 9) + Math.max(3, 8) + Math.round(2.6) + Math.floor(3.9) + Math.ceil(1.1) +
			Math.pow(2, 3) + Math.sqrt(16) + Math.hypot(3, 4) + Math.signum(-5) + Math.clamp(15, 0, 10) +
			Math.log(1) + Math.log10(100) + Math.exp(0);
		String s = '  Hello-World-123  '.strip().replaceAll(/(\d+)/, '#$1').replaceFirst('Hello', 'Hi');
		String sLead = '  abc  '.stripLeading().stripTrailing();
		boolean blankCheck = '   '.isBlank() && !sLead.isBlank();
		String subStr = sLead.substring(0, 2).concat('Z').replace('a', 'A').repeat(2);
		String chAt = subStr.charAt(0);
		int strIdx = subStr.indexOf('Z', 1);
		int strLastIdx = subStr.lastIndexOf('Z', 5);
		boolean eqCheck = subStr.equals('AbZAbZ') && subStr.equalsIgnoreCase('abzabz') && 'b'.compareTo('a') > 0;
		List tokParts = 'a::b::c'.splitOnToken('::');
		List parts = s.split('-', 2);
		String joined = String.join(':', parts);
		String fmtStr = String.format('%s-%d', 'id', 7);
		double parsedD = Double.parseDouble('3.5') + Float.parseFloat('1.5') + Long.parseLong('10');
		List sub = tokParts.subList(0, 2);
		sub.add(1, 'mid');
		sub.set(0, 'first');
		boolean listOps = sub.contains('mid') && sub.containsAll(['first', 'mid']) && sub.indexOf('mid') == 1 && sub.lastIndexOf('mid') == 1;
		sub.retainAll(['first', 'mid']);
		sub.removeAll(['mid']);
		Collections.reverse(tokParts);
		Collections.sort(tokParts);
		boolean hasMatch = s =~ /#123/ && s ==~ /Hi-World-#123/ && s.matches('Hi-.*');
		boolean inst = parts instanceof List && params._source instanceof Map && s instanceof String && true instanceof Boolean && 5 instanceof Number && params.missing_key == null;
		String elvisVal = params.missing_key ?: 'fallback';
		String ternVal = (mVal > 10) ? 'big' : 'small';
		ZonedDateTime dt1 = ZonedDateTime.parse('2026-10-01T00:00:00Z');
		ZonedDateTime dt2 = dt1.plusDays(5).plusHours(2).minusMinutes(30).plusSeconds(10).plusMillis(500);
		Instant instEpoch = Instant.ofEpochMilli(1700000000000L);
		Instant instSec = Instant.ofEpochSecond(1700000000L);
		Instant instParsed = Instant.parse('2026-10-01T00:00:00Z');
		LocalDate ldParsed = LocalDate.parse('2026-10-01');
		long daysBetween = ChronoUnit.DAYS.between(dt1, dt2);
		long hoursBetween = ChronoUnit.HOURS.between(dt1, dt2);
		long minsBetween = ChronoUnit.MINUTES.between(dt1, dt2);
		long secsBetween = ChronoUnit.SECONDS.between(dt1, dt2);
		long msBetween = ChronoUnit.MILLIS.between(dt1, dt2);
		boolean dateCmp = dt2.isAfter(dt1) && dt1.isBefore(dt2) && !dt1.isEqual(dt2) &&
			dt1.getYear() == 2026 && dt1.getMonthValue() == 10 && dt1.getDayOfMonth() == 1 &&
			dt1.getDate() == 1 && dt1.getSecond() == 0 && dt1.getDayOfWeek() == 4 &&
			dt1.getDayOfWeekEnum() == 'THURSDAY' && dt1.getMillis() > 0 &&
			instEpoch != null && instSec != null && instParsed != null && ldParsed != null;
		Map kv = ['x': 10, 'y': 20];
		kv.putIfAbsent('x', 99);
		kv.putIfAbsent('z', 30);
		int defV = kv.getOrDefault('missing', 77);
		boolean mapChecks = kv.containsKey('x') && kv.containsValue(20);
		List kSet = kv.keySet();
		List vSet = kv.values();
		kv.remove('y');
		boolean docChecks = doc.containsKey('items') && !doc['items'].empty && doc['items'].length == 5 && doc['items'].values[0] == 1;
		return [
			'bw': bw >= 0,
			'postInc': postInc == 4,
			'negAndNot': negAndNot < 0,
			'mVal': mVal > 30,
			'blank': blankCheck,
			'chAt': chAt == 'A',
			'strIdx': strIdx == 2,
			'strLastIdx': strLastIdx == 5,
			'eqCheck': eqCheck,
			'joined': joined == 'Hi:World-#123',
			'fmtStr': fmtStr == 'id-7',
			'parsedD': parsedD == 15.0,
			'listOps': listOps && sub.size() == 1,
			'hasMatch': hasMatch,
			'inst': inst,
			'elvis': elvisVal == 'fallback' && ternVal == 'big',
			'between': daysBetween == 5 && hoursBetween > 100 && minsBetween > 6000 && secsBetween > 360000 && msBetween > 360000000,
			'dateCmp': dateCmp,
			'kv': kv.get('x') == 10 && kv.get('z') == 30 && defV == 77 && mapChecks && kSet.size() == 3 && vSet.size() == 3,
			'docChecks': docChecks,
			'epochSec': Instant.ofEpochMilli(1700000000000L).getEpochSecond() == 1700000000,
			'casts': (int) 3.9 == 3 && (double) 3 == 3.0 && (boolean) 1 == true && String.valueOf(42) == '42'
		];
	`, nil)
	if err != nil {
		t.Fatalf("expected richOut err == nil, got %v", err)
	}
	richMap, ok := richOut.(map[string]any)
	if !ok {
		t.Fatalf("expected map from richOut, got %T (%v)", richOut, richOut)
	}
	for k, v := range richMap {
		if v != true {
			t.Fatalf("expected richMap[%q] == true, got %v (all=%+v)", k, v, richMap)
		}
	}

	// 6b. Direct ApplyUpdate, DocAsUpsert, DetectNoop, and ctx._source array/map mutation statements
	mutInitial := json.RawMessage(`{"arr":[1,2,3],"map":{"k1":"v1"},"counter":5}`)
	mutUpdated, err := ApplyUpdate(mutInitial, &UpdateRequest{
		Script: &ScriptSpec{
			Source: `
				ctx._source.counter++;
				++ctx._source.counter;
				ctx._source.counter *= 2;
				ctx._source.counter /= 2;
				ctx._source.counter %= 5;
				ctx._source.counter |= 8;
				ctx._source.counter &= 15;
				ctx._source.counter ^= 1;
				ctx._source.counter <<= 1;
				ctx._source.counter >>= 1;
				ctx._source.counter >>>= 1;
				ctx._source.arr.add(1, 99);
				ctx._source.arr.set(0, 11);
				ctx._source.arr.retainAll([11, 99, 2]);
				ctx._source.arr.removeAll([2]);
				ctx._source.map.put('k2', 'v2');
				ctx._source.map.putIfAbsent('k2', 'v999');
				ctx._source.map.putAll(['k3': 'v3']);
				ctx._source.map.clear();
			`,
		},
	})
	if err != nil {
		t.Fatalf("ApplyUpdate mutation script failed: %v", err)
	}
	var mutDoc map[string]any
	if err := json.Unmarshal(mutUpdated, &mutDoc); err != nil {
		t.Fatal(err)
	}
	if len(mutDoc["arr"].([]any)) != 2 || len(mutDoc["map"].(map[string]any)) != 0 {
		t.Fatalf("unexpected mutDoc after ctx._source mutations: %+v", mutDoc)
	}

	// DetectNoop on identical partial doc merge
	noopMergeBytes, noopMergeOp, err := ApplyUpdateWithResult(
		json.RawMessage(`{"a":1}`),
		&UpdateRequest{Doc: map[string]any{"a": 1}},
		true,
	)
	if err != nil || noopMergeOp != "noop" || string(noopMergeBytes) != `{"a":1}` {
		t.Fatalf("expected detect_noop partial doc merge to return noop, got op=%s body=%s err=%v", noopMergeOp, string(noopMergeBytes), err)
	}

	// DocAsUpsert when doc does not exist
	upsertDocBytes, upsertDocOp, err := ApplyUpdateWithResult(
		nil,
		&UpdateRequest{Doc: map[string]any{"created_via_doc": true}, DocAsUpsert: true},
		false,
	)
	if err != nil || upsertDocOp != "created" || !strings.Contains(string(upsertDocBytes), "created_via_doc") {
		t.Fatalf("expected DocAsUpsert to create doc, got op=%s body=%s err=%v", upsertDocOp, string(upsertDocBytes), err)
	}

	// 7. EvalPainless with ctx.op = 'noop' and 'delete', plus step budget enforcement
	noopBytes, noopOp, err := ApplyUpdateWithResult(
		json.RawMessage(`{"x":1}`),
		&UpdateRequest{Script: &ScriptSpec{Source: `ctx.op = 'noop'`}},
		true,
	)
	if err != nil || noopOp != "noop" || string(noopBytes) != `{"x":1}` {
		t.Fatalf("expected noop update, got op=%s body=%s err=%v", noopOp, string(noopBytes), err)
	}
	_, delOp, err := ApplyUpdateWithResult(
		json.RawMessage(`{"x":1}`),
		&UpdateRequest{Script: &ScriptSpec{Source: `ctx.op = 'delete'`}},
		true,
	)
	if err != nil || delOp != "deleted" {
		t.Fatalf("expected deleted update, got op=%s err=%v", delOp, err)
	}

	// Infinite loop hits step budget error
	if _, err := Eval(map[string]any{}, `while (true) { }`, nil); err == nil {
		t.Fatalf("expected infinite while loop to fail with step budget error")
	}
}

func TestRound29PainlessShiftCompoundAssignGenericTypesAndNullVarDecl(t *testing.T) {
	// 1. Compound shift assignments as final statement and inside scripts
	out, err := Eval(map[string]any{}, `
		int a = 4;
		a <<= 2;
		int b = 32;
		b >>= 2;
		int c = 64;
		c >>>= 3;
		return a + b + c;
	`, nil)
	if err != nil || out != int64(32) {
		t.Fatalf("expected a(16)+b(8)+c(8) == 32, got %v (err=%v)", out, err)
	}
	// Ensure a trailing compound shift assignment is recognized as an assignment statement
	if !isTopLevelAssignmentStmt("x <<= 2") || !isTopLevelAssignmentStmt("x >>= 1") || !isTopLevelAssignmentStmt("x >>>= 1") {
		t.Fatalf("expected <<= / >>= / >>>= to be classified as top-level assignment statements")
	}
	if isTopLevelAssignmentStmt("x <= 2") || isTopLevelAssignmentStmt("x >= 2") || isTopLevelAssignmentStmt("x == 2") || isTopLevelAssignmentStmt("x != 2") {
		t.Fatalf("expected <= / >= / == / != not to be classified as top-level assignment statements")
	}

	// 2. Generic type arguments (List<String>, Map<String, Object>), array types (String[]), and uninitialized declarations (def res; String label;)
	genOut, err := Eval(map[string]any{}, `
		List<String> items = ['alpha', 'beta'];
		Map<String, Object> meta = ['k1': 10, 'k2': 20];
		String[] parts = 'a,b,c'.split(',');
		String chosen;
		int total = 0;
		for (Map.Entry<String, Object> entry : meta.entrySet()) {
			total += entry.getValue();
		}
		for (String item : items) {
			if (item == 'beta') {
				chosen = item;
			}
		}
		return chosen + ':' + total + ':' + parts.length;
	`, nil)
	if err != nil || genOut != "beta:30:3" {
		t.Fatalf("expected generic/array/uninitialized script to return 'beta:30:3', got %v (err=%v)", genOut, err)
	}
}

func TestRound30PainlessUnaryNotPrecedenceAliasDollarAndPrefixGet(t *testing.T) {
	// 1. Unary ! precedence with ==, !=, and instanceof
	ok1, err := EvalFilter(map[string]any{"flag": false}, `!doc['flag'].value == true && !doc['flag'].value != false && !doc['flag'].value instanceof String && (!doc['flag'].value) instanceof Boolean`, nil)
	if err != nil || !ok1 {
		t.Fatalf("expected !doc['flag'].value == true && !doc['flag'].value != false && !doc['flag'].value instanceof String && (!doc['flag'].value) instanceof Boolean to be true, got %v (err=%v)", ok1, err)
	}
	ok2, err := EvalFilter(map[string]any{"flag": true}, `!doc['flag'].value == false`, nil)
	if err != nil || !ok2 {
		t.Fatalf("expected !true == false to evaluate as (!true) == false -> true, got %v (err=%v)", ok2, err)
	}

	// 2. Local List/Map alias assigned TO ctx._source.<field> and mutated via local variable (including inside for loop)
	updated, op, err := ApplyUpdateWithResult(
		json.RawMessage(`{"existing":1}`),
		&UpdateRequest{
			Script: &ScriptSpec{
				Source: `
					def list = ['a'];
					ctx._source.tags = list;
					list.add('b');
					for (int i = 0; i < 2; i++) {
						list.add('item-' + i);
					}
				`,
			},
		},
		true,
	)
	if err != nil || op != "updated" {
		t.Fatalf("expected updated result for local list alias, got op=%s err=%v", op, err)
	}
	var doc2 map[string]any
	_ = json.Unmarshal(updated, &doc2)
	tags, _ := doc2["tags"].([]any)
	if len(tags) != 4 || tags[0] != "a" || tags[1] != "b" || tags[2] != "item-0" || tags[3] != "item-1" {
		t.Fatalf("expected tags=['a','b','item-0','item-1'], got %v", doc2["tags"])
	}

	// 3. $-prefixed field names ($schema, $ref, $id) and prefix ++/-- on .get('field')
	updated3, op3, err := ApplyUpdateWithResult(
		json.RawMessage(`{"$id":"doc-1","count":10}`),
		&UpdateRequest{
			Script: &ScriptSpec{
				Source: `
					def $local = 'https://example.com/schema.json';
					ctx._source.$schema = $local;
					++ctx._source.get('count');
				`,
			},
		},
		true,
	)
	if err != nil || op3 != "updated" {
		t.Fatalf("expected updated result for $schema and ++ctx._source.get('count'), got op=%s err=%v", op3, err)
	}
	var doc3 map[string]any
	_ = json.Unmarshal(updated3, &doc3)
	if doc3["$schema"] != "https://example.com/schema.json" || doc3["count"] != float64(11) {
		t.Fatalf("expected $schema set and count=11, got %+v", doc3)
	}
}

func TestRound31PainlessFixes(t *testing.T) {
	// Fix 17: Lambda parameters inside Collections.sort / removeIf with bracket indexing (e.g. a['k'], x[0])
	updated17, op17, err := ApplyUpdateWithResult(
		json.RawMessage(`{
			"items": [{"k": 30, "name": "c"}, {"k": 10, "name": "a"}, {"k": 20, "name": "b"}],
			"pairs": [[1, "drop"], [2, "keep"], [3, "drop"]]
		}`),
		&UpdateRequest{
			Script: &ScriptSpec{
				Source: `
					Collections.sort(ctx._source.items, (a, b) -> a['k'] - b['k']);
					ctx._source.pairs.removeIf(x -> x[1] == 'drop');
				`,
			},
		},
		true,
	)
	if err != nil || op17 != "updated" {
		t.Fatalf("Fix 17 update failed: op=%s err=%v", op17, err)
	}
	var doc17 map[string]any
	_ = json.Unmarshal(updated17, &doc17)
	items17, _ := doc17["items"].([]any)
	if len(items17) != 3 || items17[0].(map[string]any)["name"] != "a" || items17[1].(map[string]any)["name"] != "b" || items17[2].(map[string]any)["name"] != "c" {
		t.Fatalf("expected items sorted by a['k'] - b['k'] -> a, b, c; got %v", items17)
	}
	pairs17, _ := doc17["pairs"].([]any)
	if len(pairs17) != 1 || pairs17[0].([]any)[0] != float64(2) {
		t.Fatalf("expected pairs filtered by x[1] == 'drop' -> [[2,'keep']], got %v", pairs17)
	}

	// Fix 18: Ternary operator ?: inside if (...) and EvalFilter
	ok18a, err := EvalFilter(map[string]any{"flag": true, "a": 10, "b": 2}, `doc['flag'].value ? doc['a'].value > 5 : doc['b'].value > 5`, nil)
	if err != nil || !ok18a {
		t.Fatalf("expected ternary condition in EvalFilter (true branch) to be true, got %v (err=%v)", ok18a, err)
	}
	ok18b, err := EvalFilter(map[string]any{"flag": false, "a": 10, "b": 2}, `doc['flag'].value ? doc['a'].value > 5 : doc['b'].value > 5`, nil)
	if err != nil || ok18b {
		t.Fatalf("expected ternary condition in EvalFilter (false branch) to be false, got %v (err=%v)", ok18b, err)
	}
	val18, err := Eval(map[string]any{"flag": true}, `int r = 0; if (doc['flag'].value ? true : false) { r = 42; } return r;`, nil)
	if err != nil || val18 != int64(42) {
		t.Fatalf("expected if (ternary) to execute true branch (42), got %v (err=%v)", val18, err)
	}

	// Fix 19: Eval single-evaluation of side-effecting bracket expressions (a[i++]) and compound assignments (x += 5)
	val19a, err := Eval(nil, `def a = [10, 20, 30]; int i = 0; a[i++]`, nil)
	if err != nil || val19a != int64(10) {
		t.Fatalf("expected a[i++] to evaluate once and return 10, got %v (err=%v)", val19a, err)
	}
	val19b, err := Eval(nil, `int x = 10; x += 5`, nil)
	if err != nil || (val19b != int64(15) && val19b != float64(15)) {
		t.Fatalf("expected trailing compound assignment x += 5 to return 15, got %v (err=%v)", val19b, err)
	}

	// Fix 20: Safe-navigation bracket indexing ?.[...], keyword return['a','b'], and ternary cond ?['a']:['b']
	val20a, err := Eval(map[string]any{"nested": map[string]any{"k": "val_ok"}}, `params._source?.['nested']?.['k']`, nil)
	if err != nil || val20a != "val_ok" {
		t.Fatalf("expected params._source?.['nested']?.['k'] == 'val_ok', got %v (err=%v)", val20a, err)
	}
	val20b, err := Eval(map[string]any{}, `params._source?.['missing']?.['k']`, nil)
	if err != nil || val20b != nil {
		t.Fatalf("expected safe-navigation ?.[missing] to return nil, got %v (err=%v)", val20b, err)
	}
	val20c, err := Eval(nil, `return['a', 'b']`, nil)
	if err != nil {
		t.Fatalf("expected return['a', 'b'] to succeed, got err=%v", err)
	}
	if arr, ok := val20c.([]any); !ok || len(arr) != 2 || arr[0] != "a" || arr[1] != "b" {
		t.Fatalf("expected return['a', 'b'] == ['a', 'b'], got %v", val20c)
	}
	val20d, err := Eval(nil, `true ?['x']:['y']`, nil)
	if err != nil {
		t.Fatalf("expected true ?['x']:['y'] to succeed, got err=%v", err)
	}
	if arr, ok := val20d.([]any); !ok || len(arr) != 1 || arr[0] != "x" {
		t.Fatalf("expected true ?['x']:['y'] == ['x'], got %v", val20d)
	}

	// Fix 21: Read-only metadata access ctx._id, ctx._index, and ctx._version in ApplyUpdateWithResult
	updated21, op21, err := ApplyUpdateWithResult(
		json.RawMessage(`{"msg":"hello"}`),
		&UpdateRequest{
			MetaID:      "doc-42",
			MetaIndex:   "orders-2026",
			MetaVersion: 7,
			Script: &ScriptSpec{
				Source: `ctx._source.meta = ctx._index + ':' + ctx._id + ':v' + ctx._version`,
			},
		},
		true,
	)
	if err != nil || op21 != "updated" {
		t.Fatalf("Fix 21 update failed: op=%s err=%v", op21, err)
	}
	var doc21 map[string]any
	_ = json.Unmarshal(updated21, &doc21)
	if doc21["meta"] != "orders-2026:doc-42:v7" {
		t.Fatalf("expected meta == 'orders-2026:doc-42:v7', got %v", doc21["meta"])
	}
}

func TestRound32PainlessControlFlowStreamsConstantsAndUpdateNoop(t *testing.T) {
	// Fix 18: Multi-variable declarations (int a = 1, b = 2; int c, d;) and for-loop variable shadowing
	res18, _, err := ApplyUpdateWithResult(
		json.RawMessage(`{}`),
		&UpdateRequest{
			Script: &ScriptSpec{
				Source: `
					int a = 10, b = 20;
					int c, d = 5;
					int sum = 0;
					for (int a = 1; a <= 3; a++) {
						int innerOnly = a * 2;
						sum += innerOnly;
					}
					ctx._source.outer_a = a;
					ctx._source.b = b;
					ctx._source.d = d;
					ctx._source.sum = sum;
				`,
			},
		},
		true,
	)
	if err != nil {
		t.Fatalf("Fix 18 failed: %v", err)
	}
	var doc18 map[string]any
	_ = json.Unmarshal(res18, &doc18)
	if doc18["outer_a"] != float64(10) || doc18["b"] != float64(20) || doc18["d"] != float64(5) || doc18["sum"] != float64(12) {
		t.Fatalf("unexpected Fix 18 doc: %+v", doc18)
	}

	// Fix 19: try / catch / finally, throw new IllegalArgumentException(...), do { ... } while (...);, and catchable Integer.parseInt error
	res19, _, err := ApplyUpdateWithResult(
		json.RawMessage(`{"raw":"not_a_number"}`),
		&UpdateRequest{
			Script: &ScriptSpec{
				Source: `
					int parsed = -1;
					String errMsg = "";
					int finallyRan = 0;
					try {
						parsed = Integer.parseInt(ctx._source.raw);
					} catch (NumberFormatException e) {
						errMsg = e.getMessage();
						parsed = 99;
					} finally {
						finallyRan = 1;
					}
					int count = 0;
					do {
						count++;
					} while (count < 3);
					ctx._source.parsed = parsed;
					ctx._source.has_err = errMsg.length() > 0;
					ctx._source.finally_ran = finallyRan;
					ctx._source.do_count = count;
				`,
			},
		},
		true,
	)
	if err != nil {
		t.Fatalf("Fix 19 failed: %v", err)
	}
	var doc19 map[string]any
	_ = json.Unmarshal(res19, &doc19)
	if doc19["parsed"] != float64(99) || doc19["has_err"] != true || doc19["finally_ran"] != float64(1) || doc19["do_count"] != float64(3) {
		t.Fatalf("unexpected Fix 19 doc: %+v", doc19)
	}

	// Fix 20: List.replaceAll(x -> ...), .forEach(...), Map.computeIfAbsent / computeIfPresent / merge, and .stream() pipelines
	res20, _, err := ApplyUpdateWithResult(
		json.RawMessage(`{"tags":["a","b"],"nums":[1,2,3,4,2]}`),
		&UpdateRequest{
			Script: &ScriptSpec{
				Source: `
					ctx._source.tags.replaceAll(t -> t.toUpperCase());
					int streamSum = ctx._source.nums.stream().distinct().filter(x -> x > 1).map(x -> x * 10).sum();
					List collected = ctx._source.nums.stream().sorted().limit(3).collect(Collectors.toList());
					boolean anyBig = ctx._source.nums.stream().anyMatch(x -> x >= 4);
					Map m = [:];
					m.computeIfAbsent('k1', k -> 100);
					m.computeIfPresent('k1', (k, v) -> v + 50);
					m.merge('k1', 25, (oldV, newV) -> oldV + newV);
					int forEachSum = 0;
					ctx._source.nums.forEach(n -> { forEachSum += n; });
					ctx._source.stream_sum = streamSum;
					ctx._source.collected = collected;
					ctx._source.any_big = anyBig;
					ctx._source.k1 = m.get('k1');
					ctx._source.fe_sum = forEachSum;
				`,
			},
		},
		true,
	)
	if err != nil {
		t.Fatalf("Fix 20 failed: %v", err)
	}
	var doc20 map[string]any
	_ = json.Unmarshal(res20, &doc20)
	tags20, _ := doc20["tags"].([]any)
	if len(tags20) != 2 || tags20[0] != "A" || tags20[1] != "B" || doc20["stream_sum"] != float64(90) || doc20["any_big"] != true || doc20["k1"] != float64(175) || doc20["fe_sum"] != float64(12) {
		t.Fatalf("unexpected Fix 20 doc: %+v", doc20)
	}

	// Fix 21: Hex (0xFF) / binary (0b1010) literals, Math.PI / Integer.MAX_VALUE, Math.sin/cos/floorDiv/floorMod, and ctx._source slice alias sync
	res21, _, err := ApplyUpdateWithResult(
		json.RawMessage(`{"arr":[1,2,3]}`),
		&UpdateRequest{
			Script: &ScriptSpec{
				Source: `
					def localRef = ctx._source.arr;
					ctx._source.arr.remove(0);
					ctx._source.local_len = localRef.size();
					ctx._source.hex = 0xFF;
					ctx._source.bin = 0b1010;
					ctx._source.fdiv = Math.floorDiv(-7, 2);
					ctx._source.fmod = Math.floorMod(-7, 2);
					ctx._source.cos0 = Math.round(Math.cos(0));
					ctx._source.has_pi = Math.PI > 3.14;
					ctx._source.max_int = Integer.MAX_VALUE;
				`,
			},
		},
		true,
	)
	if err != nil {
		t.Fatalf("Fix 21 failed: %v", err)
	}
	var doc21 map[string]any
	_ = json.Unmarshal(res21, &doc21)
	if doc21["local_len"] != float64(2) || doc21["hex"] != float64(255) || doc21["bin"] != float64(10) || doc21["fdiv"] != float64(-4) || doc21["fmod"] != float64(1) || doc21["cos0"] != float64(1) || doc21["has_pi"] != true || doc21["max_int"] != float64(2147483647) {
		t.Fatalf("unexpected Fix 21 doc: %+v", doc21)
	}

	// Fix 22: {"doc": {}} is a noop on existing docs and creates {} when doc_as_upsert: true
	_, op22a, err := ApplyUpdateWithResult(
		json.RawMessage(`{"a":1}`),
		&UpdateRequest{Doc: map[string]any{}},
		true,
	)
	if err != nil || op22a != "noop" {
		t.Fatalf("expected noop for empty doc update on existing doc, got op=%s err=%v", op22a, err)
	}
	created22b, op22b, err := ApplyUpdateWithResult(
		nil,
		&UpdateRequest{Doc: map[string]any{}, DocAsUpsert: true},
		false,
	)
	if err != nil || op22b != "created" || string(created22b) != "{}" {
		t.Fatalf("expected created '{}' for empty doc_as_upsert on missing doc, got op=%s body=%s err=%v", op22b, string(created22b), err)
	}
}

func TestRound33PainlessHardening(t *testing.T) {
	// F17: Postfix ++ / -- on LHS of binary + / - arithmetic (x++ + 10, y-- - 2)
	// F18: Collection constructors with generics (new ArrayList<>(), new HashMap<String, Object>()) and copy constructors (new ArrayList(list), new HashSet(list), new HashMap(map))
	// F19: switch / case / default / break statement support (including fallthrough)
	// F20: while and do-while loops block-scoped local variable declarations (do not leak into outer scope)
	// F21: ctx._source alias synchronization on +=, .put(), .putAll(), and ++/--
	res, _, err := ApplyUpdateWithResult(
		json.RawMessage(`{"items":[10,20,10],"tags":["a"],"meta":{"k1":"v1"},"counter":5,"tier":"silver"}`),
		&UpdateRequest{
			Script: &ScriptSpec{
				Source: `
					// F17: Postfix ++/-- on LHS of binary +/-
					int x = 5;
					int postAdd = x++ + 10;
					int y = 8;
					int postSub = y-- - 3;

					// F18: Generic diamond constructors & copy/dedup constructors
					List genList = new ArrayList<>();
					genList.add('first');
					List copiedList = new ArrayList(ctx._source.items);
					Set dedupSet = new HashSet(ctx._source.items);
					Map copiedMap = new HashMap(ctx._source.meta);
					copiedMap.put('k2', 'v2');

					// F19: switch / case / default / break + fallthrough
					int bonus = 0;
					switch (ctx._source.tier) {
						case 'bronze':
							bonus = 10;
							break;
						case 'silver':
							bonus += 20;
						case 'gold':
							bonus += 30;
							break;
						default:
							bonus = 1;
					}

					// F20: while and do-while block-scoped variable declarations do not leak
					int wCount = 0;
					while (wCount < 2) {
						int innerVar = 99;
						wCount += 1;
					}
					int dwCount = 0;
					do {
						int innerDoVar = 77;
						dwCount += 1;
					} while (dwCount < 2);

					// F21: ctx._source alias synchronization on +=, .put(), .putAll(), ++
					def tagsAlias = ctx._source.tags;
					ctx._source.tags += ['b'];
					int aliasLenAfterPlusEq = tagsAlias.size();
					def metaAlias = ctx._source.meta;
					ctx._source.meta.put('k3', 'v3');
					ctx._source.counter++;

					ctx._source.post_add = postAdd;
					ctx._source.x_after = x;
					ctx._source.post_sub = postSub;
					ctx._source.y_after = y;
					ctx._source.gen_size = genList.size();
					ctx._source.copied_size = copiedList.size();
					ctx._source.dedup_size = dedupSet.size();
					ctx._source.copied_map_k2 = copiedMap['k2'];
					ctx._source.bonus = bonus;
					ctx._source.w_count = wCount;
					ctx._source.dw_count = dwCount;
					ctx._source.alias_len = aliasLenAfterPlusEq;
					ctx._source.meta_k3 = metaAlias['k3'];
				`,
			},
		},
		true,
	)
	if err != nil {
		t.Fatalf("TestRound33PainlessHardening failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(res, &doc); err != nil {
		t.Fatalf("unmarshal result failed: %v", err)
	}
	if doc["post_add"] != float64(15) || doc["x_after"] != float64(6) || doc["post_sub"] != float64(5) || doc["y_after"] != float64(7) {
		t.Fatalf("F17 assertions failed: %+v", doc)
	}
	if doc["gen_size"] != float64(1) || doc["copied_size"] != float64(3) || doc["dedup_size"] != float64(2) || doc["copied_map_k2"] != "v2" {
		t.Fatalf("F18 assertions failed: %+v", doc)
	}
	if doc["bonus"] != float64(50) {
		t.Fatalf("F19 switch assertions failed (expected fallthrough 20+30=50): %+v", doc)
	}
	if doc["w_count"] != float64(2) || doc["dw_count"] != float64(2) || doc["innerVar"] != nil || doc["innerDoVar"] != nil {
		t.Fatalf("F20 loop scoping assertions failed: %+v", doc)
	}
	if doc["alias_len"] != float64(2) || doc["meta_k3"] != "v3" || doc["counter"] != float64(6) {
		t.Fatalf("F21 ctx._source alias sync assertions failed: %+v", doc)
	}
}

func TestRound34PainlessAllocationBudgetBitwiseAndNoop(t *testing.T) {
	// F21: Slice and string concatenation are bounded at MaxPainlessSliceItems and MaxPainlessStringBytes
	val, err := Eval(map[string]any{}, `
		def a = [1, 2];
		for (int i = 0; i < 16; i++) {
			a = a + a;
		}
		def s = 'abcd';
		for (int i = 0; i < 20; i++) {
			s = s.concat(s);
		}
		return [a.size(), s.length()];
	`, nil)
	if err != nil {
		t.Fatalf("F21 bounded concat failed: %v", err)
	}
	resSlice, ok := val.([]any)
	if !ok || len(resSlice) != 2 || resSlice[0] != int64(MaxPainlessSliceItems) || resSlice[1] != int64(MaxPainlessStringBytes) {
		t.Fatalf("F21 expected [%d, %d], got %+v", MaxPainlessSliceItems, MaxPainlessStringBytes, val)
	}

	// F22: Shared evalBudget across nested forEach / lambdas enforces MaxPainlessSteps
	_, err = Eval(map[string]any{}, `
		def xs = [];
		for (int i = 0; i < 120; i++) { xs.add(i); }
		int sum = 0;
		xs.forEach(x -> {
			xs.forEach(y -> {
				sum += 1;
			});
		});
		return sum;
	`, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeded maximum step budget") {
		t.Fatalf("F22 expected step budget error from nested forEach, got: %v", err)
	}

	// F23: Boolean bitwise operators (&, |, ^) truthiness and precedence with comparisons
	bwVal, err := Eval(map[string]any{"a": int64(1), "b": int64(2), "flags": int64(2)}, `
		boolean c1 = false & false;
		boolean c2 = (doc['a'].value == 1 & doc['b'].value == 2);
		boolean c3 = (doc['a'].value == 1 & doc['b'].value == 99);
		boolean c4 = (doc['a'].value == 99 | doc['b'].value == 2);
		boolean c5 = (doc['a'].value == 1 ^ doc['b'].value == 2);
		boolean c6 = false;
		if (doc['flags'].value & 4) {
			c6 = true;
		}
		return [c1, c2, c3, c4, c5, c6];
	`, nil)
	if err != nil {
		t.Fatalf("F23 boolean bitwise eval failed: %v", err)
	}
	bwArr, ok := bwVal.([]any)
	if !ok || len(bwArr) != 6 || bwArr[0] != false || bwArr[1] != true || bwArr[2] != false || bwArr[3] != true || bwArr[4] != false || bwArr[5] != false {
		t.Fatalf("F23 unexpected boolean bitwise results: %+v", bwVal)
	}

	// F24: ApplyUpdateWithResult semantic JSON noop detection for float 10.0 vs 10
	detectNoop := true
	_, opRes, err := ApplyUpdateWithResult(
		json.RawMessage(`{"price":10.0}`),
		&UpdateRequest{
			Doc:        map[string]any{"price": float64(10)},
			DetectNoop: &detectNoop,
		},
		true,
	)
	if err != nil {
		t.Fatalf("F24 ApplyUpdateWithResult failed: %v", err)
	}
	if opRes != "noop" {
		t.Fatalf("F24 expected noop for 10.0 vs 10, got %q", opRes)
	}
}

func TestRound41PainlessTokenizerMapVarKeyForLoopPlusAndConvertBoolean(t *testing.T) {
	// F21: Escaped backslashes before quote and semicolons inside regex literal
	val, err := Eval(map[string]any{"msg": "a;b;c"}, `
		String slash = 'x\\';
		def parts = doc['msg'].value.split(/;/);
		return [slash, parts.length];
	`, nil)
	if err != nil {
		t.Fatalf("F21 Eval failed: %v", err)
	}
	arr, ok := val.([]any)
	if !ok || len(arr) != 2 || arr[0] != `x\` || arr[1] != int64(3) {
		t.Fatalf("F21 unexpected result: %+v", val)
	}

	// F22 & F23: Dynamic variable key in map bracket assignment + i = i + 1 in for-loop header + regex with '+'
	val2, err := Eval(map[string]any{"text": "foo   bar"}, `
		def m = [:];
		for (int i = 0; i < 3; i = i + 1) {
			String k = 'k' + i;
			m[k] = i * 10;
		}
		String norm = doc['text'].value.replaceAll(/\s+/, '-');
		int idx = 1;
		String dynKey = 'k' + idx;
		return [m['k0'], m[dynKey], m['k2'], norm];
	`, nil)
	if err != nil {
		t.Fatalf("F22/F23 Eval failed: %v", err)
	}
	arr2, ok := val2.([]any)
	if !ok || len(arr2) != 4 || arr2[0] != int64(0) || arr2[1] != int64(10) || arr2[2] != int64(20) || arr2[3] != "foo-bar" {
		t.Fatalf("F22/F23 unexpected result: %+v", val2)
	}

	// F24: ctx._source.remove('nested.child') removes nested path
	doc := map[string]any{
		"nested": map[string]any{"child": "drop_me", "keep": "stay"},
	}
	if err := EvalPainless(doc, `ctx._source.remove('nested.child');`, nil); err != nil {
		t.Fatalf("F24 remove('nested.child') failed: %v", err)
	}
	nestedMap, _ := doc["nested"].(map[string]any)
	if _, exists := nestedMap["child"]; exists || nestedMap["keep"] != "stay" {
		t.Fatalf("F24 expected nested.child removed and nested.keep preserved, got %+v", nestedMap)
	}
}

func TestRound42PainlessParamsIsolationBracketAliasCtxMapMutationsAndSortVoid(t *testing.T) {
	// F21: Lambda params and user function params do not leak into or overwrite caller params
	params := map[string]any{"x": int64(5), "drop_me": "bye"}
	val, err := Eval(map[string]any{}, `
		int f(int x) {
			params.remove('drop_me');
			return x * 2;
		}
		def arr = [1, 2, 3];
		arr.removeIf(x -> params.size() != 2 || x == 2);
		int res = f(10);
		return [params.x, params.size(), res, arr.size()];
	`, params)
	if err != nil {
		t.Fatalf("F21 Eval failed: %v", err)
	}
	resArr, ok := val.([]any)
	if !ok || len(resArr) != 4 || resArr[0] != int64(5) || resArr[1] != int64(1) || resArr[2] != int64(20) || resArr[3] != int64(2) {
		t.Fatalf("F21 unexpected result: %+v", val)
	}

	// F22: Bracket alias tracking (`def tags = ctx._source['tags']`), escaped bracket key, and `params._source.a = 99`
	doc := map[string]any{
		"tags": []any{"a"},
		"a\nb": "line_val",
		"a":    int64(1),
	}
	if err := EvalPainless(doc, `
		def tags = ctx._source['tags'];
		tags.add('b');
		params._source.a = 99;
		ctx._source.copied = ctx._source['a\nb'];
	`, nil); err != nil {
		t.Fatalf("F22 EvalPainless failed: %v", err)
	}
	tagsSlice, _ := doc["tags"].([]any)
	if len(tagsSlice) != 2 || tagsSlice[1] != "b" || doc["a"] != int64(99) || doc["copied"] != "line_val" {
		t.Fatalf("F22 unexpected doc state: %+v", doc)
	}

	// F23: Direct map mutations on ctx (`ctx.put`, `ctx.remove`, `ctx.putIfAbsent`, `ctx.putAll`) and clearing MetaID with `ctx._id = ""`
	updReq := &UpdateRequest{
		Script: &ScriptSpec{
			Source: `ctx.put('_routing', 'r2'); ctx.putIfAbsent('_routing', 'r3'); ctx.putAll(['_index': 'idx2']); ctx.remove('_id');`,
		},
		MetaID:            "orig-id",
		MetaIndex:         "idx",
		AllowMetaMutation: true,
	}
	_, _, err = ApplyUpdateWithResult(json.RawMessage(`{"x":1}`), updReq, true)
	if err != nil {
		t.Fatalf("F23 ApplyUpdateWithResult failed: %v", err)
	}
	if updReq.MetaRouting != "r2" || updReq.MetaID != "" || updReq.MetaIndex != "idx2" {
		t.Fatalf("F23 expected MetaRouting='r2', MetaID='', MetaIndex='idx2', got MetaRouting=%q MetaID=%q MetaIndex=%q", updReq.MetaRouting, updReq.MetaID, updReq.MetaIndex)
	}
	opParams := map[string]any{"__readonly_ctx_meta": true}
	if _, err := Eval(map[string]any{}, `ctx.put('_id', 'x');`, opParams); err == nil {
		t.Fatalf("F23 expected readonly _id error on ctx.put")
	}
	if _, err := Eval(map[string]any{}, `ctx.remove('_id');`, opParams); err == nil {
		t.Fatalf("F23 expected readonly _id error on ctx.remove")
	}

	// F30: List.sort returns nil (void) and propagates comparator errors
	sortVal, err := Eval(map[string]any{}, `
		def items = [3, 1, 2];
		items.sort((a, b) -> a - b);
	`, nil)
	if err != nil || sortVal != nil {
		t.Fatalf("F30 expected nil, nil from trailing items.sort, got val=%v err=%v", sortVal, err)
	}
	if _, err := Eval(map[string]any{}, `
		def items = [3, 1, 2];
		items.sort((a, b) -> { throw new IllegalArgumentException('bad cmp'); });
	`, nil); err == nil || !strings.Contains(err.Error(), "bad cmp") {
		t.Fatalf("F30 expected comparator error from items.sort, got %v", err)
	}
	if _, err := Eval(map[string]any{}, `
		[3, 1, 2].stream().sorted((a, b) -> { throw new IllegalArgumentException('bad stream sort'); }).toList();
	`, nil); err == nil || !strings.Contains(err.Error(), "bad stream sort") {
		t.Fatalf("F30 expected comparator error from stream().sorted, got %v", err)
	}
	if _, err := Eval(map[string]any{}, `
		[3, 1, 2].stream().min((a, b) -> { throw new IllegalArgumentException('bad stream min'); });
	`, nil); err == nil || !strings.Contains(err.Error(), "bad stream min") {
		t.Fatalf("F30 expected comparator error from stream().min, got %v", err)
	}
}

func TestRound43MultiLineFluentChainsRemoveAllRetainAllRemoveIfExprMapEmptyAndInvalidCtxOp(t *testing.T) {
	// F21: Multi-line fluent stream chain and multi-line binary/bitwise continuation operators
	docF21 := map[string]any{
		"nums": []any{int64(1), int64(2), int64(3), int64(4)},
	}
	if err := EvalPainless(docF21, `
		ctx._source.evens = ctx._source.nums.stream()
			.filter(x -> x % 2 == 0)
			.map(x -> x * 10)
			.collect(Collectors.toList());
		ctx._source.math = 100 /
			5 %
			7 + (6 &
			3) + (1 <<
			2);
	`, nil); err != nil {
		t.Fatalf("F21 EvalPainless failed: %v", err)
	}
	evens, _ := docF21["evens"].([]any)
	if len(evens) != 2 || evens[0] != int64(20) || evens[1] != int64(40) || docF21["math"] != int64(12) {
		t.Fatalf("F21 unexpected docF21 state: %+v", docF21)
	}

	// F22: removeIf, removeAll, and retainAll mutate backing list when evaluated in expression context
	docF22 := map[string]any{
		"tags": []any{"a", "b", "c", "d"},
	}
	if err := EvalPainless(docF22, `
		if (ctx._source.tags.removeIf(x -> x == 'b')) {
			ctx._source.removed_b = true;
		}
		def remC = ctx._source.tags.removeAll(['c']);
		if (ctx._source.tags.retainAll(['a'])) {
			ctx._source.retained_only_a = remC;
		}
	`, nil); err != nil {
		t.Fatalf("F22 EvalPainless failed: %v", err)
	}
	tagsOut, _ := docF22["tags"].([]any)
	if len(tagsOut) != 1 || tagsOut[0] != "a" || docF22["removed_b"] != true || docF22["retained_only_a"] != true {
		t.Fatalf("F22 unexpected docF22 state: %+v", docF22)
	}

	// F23: .empty and .length on map[string]any via resolveParamPath
	docF23 := map[string]any{
		"empty_map": map[string]any{},
		"full_map":  map[string]any{"k1": "v1", "k2": "v2"},
	}
	if err := EvalPainless(docF23, `
		ctx._source.is_empty = ctx._source.empty_map.empty;
		ctx._source.is_not_empty = !ctx._source.full_map.empty;
		ctx._source.map_len = ctx._source.full_map.length;
	`, nil); err != nil {
		t.Fatalf("F23 EvalPainless failed: %v", err)
	}
	if docF23["is_empty"] != true || docF23["is_not_empty"] != true || docF23["map_len"] != int64(2) {
		t.Fatalf("F23 unexpected docF23 state: %+v", docF23)
	}

	// F24: ApplyUpdateWithResult rejects unsupported ctx.op values
	badUpd := &UpdateRequest{
		Script: &ScriptSpec{
			Source: `ctx.op = 'bogus_op';`,
		},
	}
	if _, _, err := ApplyUpdateWithResult(json.RawMessage(`{"a":1}`), badUpd, true); err == nil || !strings.Contains(strings.ToLower(err.Error()), "operation [bogus_op] is not supported") {
		t.Fatalf("F24 expected unsupported ctx.op error, got %v", err)
	}
}

func TestRound44PainlessEmptyMapUnderscoreLiteralsDottedKeysDocMetaAndUpdateRouting(t *testing.T) {
	// F24: Whitespace empty map literal [ : ] and underscore numeric literals (1_000_000, 1_000.50, 1_000L)
	docF24 := map[string]any{}
	if err := EvalPainless(docF24, `
		def m = [ : ];
		ctx._source.is_map = (m instanceof Map) && m.isEmpty();
		ctx._source.int_val = 1_000_000 + 2_000;
		ctx._source.float_val = 1_000.50;
		ctx._source.long_val = 1_000L;
	`, nil); err != nil {
		t.Fatalf("F24 EvalPainless failed: %v", err)
	}
	if docF24["is_map"] != true || docF24["int_val"] != int64(1002000) || docF24["float_val"] != float64(1000.5) || docF24["long_val"] != int64(1000) {
		t.Fatalf("F24 unexpected state: %+v", docF24)
	}

	// F25: Dotted bracket key read/write symmetry and put('a.b', ...) on nested & flat maps
	docF25 := map[string]any{
		"a": map[string]any{"b": int64(10)},
	}
	if err := EvalPainless(docF25, `
		ctx._source['a.b'] = ctx._source['a.b'] + 5;
		ctx._source.put('a.b', ctx._source['a.b'] + 5);
		def flat = [ : ];
		flat.put('x.y', 42);
		ctx._source.flat_xy = flat['x.y'];
	`, nil); err != nil {
		t.Fatalf("F25 EvalPainless failed: %v", err)
	}
	if _, hasFlatAB := docF25["a.b"]; hasFlatAB {
		t.Fatalf("F25 expected no duplicate flat key 'a.b' when nested a.b existed, got %+v", docF25)
	}
	nestedA, _ := docF25["a"].(map[string]any)
	if nestedA["b"] != int64(20) || docF25["flat_xy"] != int64(42) {
		t.Fatalf("F25 expected nested a.b=20 and flat_xy=42, got %+v", docF25)
	}

	// F34: doc['_index'].value and doc['_version'].value resolution
	docF34 := map[string]any{
		"__meta_id":      "doc-1",
		"__meta_index":   "orders_v1",
		"__meta_version": int64(7),
	}
	okFilter, err := EvalFilter(docF34, `doc['_index'].value == 'orders_v1' && doc['_version'].value == 7 && doc['_id'].value == 'doc-1'`, nil)
	if err != nil || !okFilter {
		t.Fatalf("F34 expected doc['_index'].value and doc['_version'].value filter to match, got %v (err=%v)", okFilter, err)
	}

	// F35: ApplyUpdateWithResult mutates req.MetaRouting in-place
	updReq := &UpdateRequest{
		MetaRouting: "old-shard",
		Script: &ScriptSpec{
			Source: `ctx._routing = 'new-shard'; ctx._source.v = 2;`,
		},
	}
	outBytes, opRes, err := ApplyUpdateWithResult(json.RawMessage(`{"v":1}`), updReq, true)
	if err != nil || opRes != "updated" {
		t.Fatalf("F35 ApplyUpdateWithResult failed: opRes=%q err=%v", opRes, err)
	}
	if updReq.MetaRouting != "new-shard" || !strings.Contains(string(outBytes), `"v":2`) {
		t.Fatalf("F35 expected updReq.MetaRouting='new-shard' and v=2, got routing=%q body=%s", updReq.MetaRouting, string(outBytes))
	}
}

func TestRound45PainlessMultiCatchThrowStringSplitAndEmit(t *testing.T) {
	// F26: Multiple catch blocks & typed exception matching + throw Statement
	doc := map[string]any{"x": int64(10)}
	res, err := Eval(doc, `
		try {
			throw new IllegalArgumentException("bad_arg");
		} catch (NullPointerException e) {
			return "caught_npe";
		} catch (IllegalArgumentException e) {
			return "caught_iae:" + e.getMessage();
		}
	`, nil)
	if err != nil || res != "caught_iae:bad_arg" {
		t.Fatalf("F26 expected 'caught_iae:bad_arg', got %v (err=%v)", res, err)
	}

	// F26: Multi-exception pipe syntax catch (ArithmeticException | NullPointerException e)
	resPipe, err := Eval(doc, `
		try {
			throw new NullPointerException("missing_ref");
		} catch (IllegalArgumentException e) {
			return "wrong";
		} catch (ArithmeticException | NullPointerException e) {
			return "multi:" + e.getMessage();
		}
	`, nil)
	if err != nil || resPipe != "multi:missing_ref" {
		t.Fatalf("F26 expected 'multi:missing_ref', got %v (err=%v)", resPipe, err)
	}

	// F27: Java String.split(regex) strips trailing empty strings while split(regex, -1) preserves them, and splitOnToken works
	resSplitDefault, err := Eval(doc, `"a,b,c,,".split(",").length`, nil)
	if err != nil || resSplitDefault != int64(3) {
		t.Fatalf("F27 expected default split length 3 (trailing empties stripped), got %v (err=%v)", resSplitDefault, err)
	}
	resSplitNeg, err := Eval(doc, `"a,b,c,,".split(",", -1).length`, nil)
	if err != nil || resSplitNeg != int64(5) {
		t.Fatalf("F27 expected split(_, -1) length 5, got %v (err=%v)", resSplitNeg, err)
	}
	resSplitLim, err := Eval(doc, `"a,b,c".split(",", 2).length`, nil)
	if err != nil || resSplitLim != int64(2) {
		t.Fatalf("F27 expected split(_, 2) length 2, got %v (err=%v)", resSplitLim, err)
	}
	resSplitTok, err := Eval(doc, `"a..b".splitOnToken(".").length`, nil)
	if err != nil || resSplitTok != int64(3) {
		t.Fatalf("F27 expected splitOnToken length 3, got %v (err=%v)", resSplitTok, err)
	}

	// F28: Compound bitwise assignment &=, |=, ^= and shift assignment <<=, >>=, >>>= on map/nested properties
	docBit := map[string]any{
		"flags": int64(10),
		"mask":  int64(5),
		"sh":    int64(2),
	}
	if err := EvalPainless(docBit, `
		ctx._source.flags |= ctx._source.mask;
		ctx._source.flags &= 7;
		ctx._source.flags ^= 1;
		ctx._source.sh <<= 3;
		ctx._source.sh >>= 1;
	`, nil); err != nil {
		t.Fatalf("F28 EvalPainless failed: %v", err)
	}
	// 10 | 5 = 15; 15 & 7 = 7; 7 ^ 1 = 6
	if docBit["flags"] != int64(6) || docBit["sh"] != int64(8) {
		t.Fatalf("F28 expected flags=6 and sh=8, got flags=%v sh=%v", docBit["flags"], docBit["sh"])
	}

	// Runtime field emit(...) accumulation
	emitted, err := Eval(map[string]any{"tags": []any{"go", "doris"}}, `
		for (def t : doc['tags'].values) {
			emit(t.toUpperCase());
		}
	`, nil)
	if err != nil {
		t.Fatalf("emit(...) eval failed: %v", err)
	}
	emittedSlice, ok := emitted.([]any)
	if !ok || len(emittedSlice) != 2 || emittedSlice[0] != "GO" || emittedSlice[1] != "DORIS" {
		t.Fatalf("expected emitted slice [GO DORIS], got %#v", emitted)
	}
}

func TestRound46PainlessPrecedenceWrappersMapKeysAndDeterministicNow(t *testing.T) {
	// F26: Unary `!` precedence over binary `+` and relational/`instanceof` operators
	docF26 := map[string]any{"active": false}
	valF26, err := Eval(docF26, `
		def s = !ctx._source.active + '_state';
		def isBool = (!ctx._source.active) instanceof Boolean;
		def notInst = !(ctx._source.active instanceof String);
		return [s, isBool, notInst];
	`, nil)
	if err != nil {
		t.Fatalf("F26 Eval failed: %v", err)
	}
	arrF26, ok := valF26.([]any)
	if !ok || len(arrF26) != 3 || arrF26[0] != "true_state" || arrF26[1] != true || arrF26[2] != true {
		t.Fatalf("F26 unexpected result: %#v", valF26)
	}

	// F27: Number instance conversion methods and static wrapper methods
	valF27, err := Eval(map[string]any{"d": float64(42.9), "neg": float64(-15.7)}, `
		int iv = ctx._source.d.intValue();
		long lv = ctx._source.neg.longValue();
		double dv = (10).doubleValue();
		float fv = (10).floatValue();
		short sv = (32768).shortValue();
		byte bv = (128).byteValue();
		def iVal = Integer.valueOf("ff", 16);
		def lVal = Long.valueOf("1010", 2);
		def dVal = Double.valueOf("3.5");
		def bVal = Boolean.valueOf("TRUE");
		def bParse = Boolean.parseBoolean("false");
		def hexStr = Integer.toHexString(255);
		def binStr = Integer.toBinaryString(5);
		def octStr = Integer.toOctalString(8);
		def lHex = Long.toHexString(256);
		def iStr = Integer.toString(42);
		def dStr = Double.toString(3.25);
		def bStr = Boolean.toString(true);
		def cmpI = Integer.compare(1, 2);
		def cmpL = Long.compare(5, 5);
		def cmpD = Double.compare(3.0, 1.0);
		def cmpB = Boolean.compare(true, false);
		def objEq = Objects.equals("a", "a");
		def objNull = Objects.isNull(null);
		def objNonNull = Objects.nonNull("x");
		def objStr = Objects.toString(null, "fallback");
		return [iv, lv, dv, fv, sv, bv, iVal, lVal, dVal, bVal, bParse, hexStr, binStr, octStr, lHex, iStr, dStr, bStr, cmpI, cmpL, cmpD, cmpB, objEq, objNull, objNonNull, objStr];
	`, nil)
	if err != nil {
		t.Fatalf("F27 Eval failed: %v", err)
	}
	arrF27, ok := valF27.([]any)
	if !ok || len(arrF27) != 26 {
		t.Fatalf("F27 unexpected result slice: %#v", valF27)
	}
	if arrF27[0] != int64(42) || arrF27[1] != int64(-15) || arrF27[2] != float64(10) || arrF27[3] != float64(10) ||
		arrF27[4] != int64(-32768) || arrF27[5] != int64(-128) || arrF27[6] != int64(255) || arrF27[7] != int64(10) ||
		arrF27[8] != float64(3.5) || arrF27[9] != true || arrF27[10] != false ||
		arrF27[11] != "ff" || arrF27[12] != "101" || arrF27[13] != "10" || arrF27[14] != "100" ||
		arrF27[15] != "42" || arrF27[16] != "3.25" || arrF27[17] != "true" ||
		arrF27[18] != int64(-1) || arrF27[19] != int64(0) || arrF27[20] != int64(1) || arrF27[21] != int64(1) ||
		arrF27[22] != true || arrF27[23] != true || arrF27[24] != true || arrF27[25] != "fallback" {
		t.Fatalf("F27 values mismatch: %#v", arrF27)
	}

	// F28: Map.put / Map.putIfAbsent / Map.remove dotted-key & ?-key handling and String methods (.toCharArray, .codePointAt, .compareToIgnoreCase)
	docF28 := map[string]any{
		"a": map[string]any{"b": int64(1)},
	}
	valF28, err := Eval(docF28, `
		ctx.put('a.b', 2);
		ctx.put('why?', 10);
		ctx.putIfAbsent('why?', 99);
		def m = ['a': ['b': 1]];
		m.put('a.b', 5);
		m.put('q?', 7);
		m.putIfAbsent('q?', 8);
		def remMissing = m.remove('a.c');
		def chars = "Az".toCharArray();
		def cp = "Az".codePointAt(0);
		def cmpIC = "Hello".compareToIgnoreCase("hello");
		return [ctx['a.b'], ctx['why?'], m['a.b'], m['a']['b'], m['q?'], remMissing, chars, cp, cmpIC];
	`, nil)
	if err != nil {
		t.Fatalf("F28 Eval failed: %v", err)
	}
	arrF28, ok := valF28.([]any)
	if !ok || len(arrF28) != 9 {
		t.Fatalf("F28 unexpected result: %#v", valF28)
	}
	charsSlice, _ := arrF28[6].([]any)
	if arrF28[0] != int64(2) || arrF28[1] != int64(10) || arrF28[2] != int64(5) || arrF28[3] != int64(1) ||
		arrF28[4] != int64(7) || arrF28[5] != nil || len(charsSlice) != 2 || charsSlice[0] != "A" || charsSlice[1] != "z" ||
		arrF28[7] != int64(65) || arrF28[8] != int64(0) {
		t.Fatalf("F28 values mismatch: %#v", arrF28)
	}

	// F29: Deterministic ctx._now across multiple reads in a single script execution
	valF29, err := Eval(map[string]any{}, `
		long t1 = ctx._now;
		long sum = 0;
		for (int i = 0; i < 200; i++) {
			sum += i;
		}
		long t2 = ctx['_now'];
		return [t1 == t2, t1 > 0];
	`, nil)
	if err != nil {
		t.Fatalf("F29 Eval failed: %v", err)
	}
	arrF29, ok := valF29.([]any)
	if !ok || len(arrF29) != 2 || arrF29[0] != true || arrF29[1] != true {
		t.Fatalf("F29 expected identical positive ctx._now reads, got %#v", valF29)
	}
	valF29Fixed, err := Eval(map[string]any{}, `return ctx._now - ctx['_now'] + ctx._now;`, map[string]any{"_ctx_now": int64(1700000000123)})
	if err != nil || valF29Fixed != int64(1700000000123) {
		t.Fatalf("F29 expected fixed _ctx_now=1700000000123, got %v (err=%v)", valF29Fixed, err)
	}
}

func TestRound47PainlessEvaluatorFindings(t *testing.T) {
	// F25: Encoding, Base64, Digest, StrictMath, Arrays.asList, List.of, Set.of, Map.of, Collections.*
	docF25 := map[string]any{
		"nums": []any{int64(1), int64(2), int64(3), int64(4)},
		"tags": []any{"a", "b", "a"},
	}
	valF25, err := Eval(docF25, `
		def b64 = Encoding.encodeBase64("hello");
		def decB64 = Encoding.decodeBase64(b64);
		def hexEnc = Encoding.encodeHex("abc");
		def hexDec = Encoding.decodeHex(hexEnc);
		def stdEnc = Base64.getEncoder().encodeToString("foo+bar?".getBytes());
		def stdDec = Base64.getDecoder().decode(stdEnc);
		def urlEnc = Base64.getUrlEncoder().withoutPadding().encodeToString("a?b/c");
		def urlDec = Base64.getUrlDecoder().decode(urlEnc);
		def sha256Hex = Digest.sha256("hello");
		def md5Hex = Digest.md5("hello");
		def sha1Hex = Digest.sha1("hello");
		def sha384Hex = Digest.sha384("hello");
		def sha512Hex = Digest.sha512("hello");
		def hexStr = Hex.encodeHexString("Hi");
		def sm = StrictMath.abs(-5) + (StrictMath.PI > 3.14 ? 1 : 0) + (StrictMath.E > 2.71 ? 1 : 0);
		def asL = Arrays.asList(10, 20);
		def lOf = List.of("x", "y");
		def sOf = Set.of("a", "b", "a");
		def mOf = Map.of("k1", 1, "k2", 2);
		def eList = Collections.emptyList();
		def eSet = Collections.emptySet();
		def eMap = Collections.emptyMap();
		def sList = Collections.singletonList(99);
		def sSet = Collections.singleton("z");
		def sMap = Collections.singletonMap("only", 7);
		def cMin = Collections.min(ctx._source.nums);
		def cMax = Collections.max(ctx._source.nums);
		def cFreq = Collections.frequency(ctx._source.tags, "a");
		def cDis1 = Collections.disjoint([1, 2], [3, 4]);
		def cDis2 = Collections.disjoint([1, 2], [2, 3]);
		def nCop = Collections.nCopies(3, "v");
		Collections.swap(ctx._source.nums, 0, 3);
		Collections.rotate(ctx._source.nums, 1);
		def repChanged = Collections.replaceAll(ctx._source.tags, "a", "A");
		def fillTarget = [1, 2, 3];
		Collections.fill(fillTarget, 0);
		return [
			b64, decB64, hexEnc, hexDec, stdDec, urlEnc, urlDec,
			sha256Hex, md5Hex, sha1Hex, sha384Hex.length(), sha512Hex.length(), hexStr,
			sm, asL.size(), lOf.size(), sOf.size(), mOf.get("k2"),
			eList.size(), eSet.size(), eMap.size(), sList.get(0), sSet.get(0), sMap.get("only"),
			cMin, cMax, cFreq, cDis1, cDis2, nCop.size(), repChanged, fillTarget
		];
	`, nil)
	if err != nil {
		t.Fatalf("Round47 F25 Eval failed: %v", err)
	}
	arrF25, ok := valF25.([]any)
	if !ok || len(arrF25) != 32 {
		t.Fatalf("Round47 F25 unexpected result: %#v", valF25)
	}
	if arrF25[0] != "aGVsbG8=" || arrF25[1] != "hello" || arrF25[2] != "616263" || arrF25[3] != "abc" ||
		arrF25[4] != "foo+bar?" || arrF25[5] != "YT9iL2M" || arrF25[6] != "a?b/c" ||
		arrF25[7] != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" ||
		arrF25[8] != "5d41402abc4b2a76b9719d911017c592" ||
		arrF25[9] != "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" ||
		arrF25[10] != int64(96) || arrF25[11] != int64(128) || arrF25[12] != "4869" ||
		arrF25[13] != int64(7) || arrF25[14] != int64(2) || arrF25[15] != int64(2) || arrF25[16] != int64(2) || arrF25[17] != int64(2) ||
		arrF25[18] != int64(0) || arrF25[19] != int64(0) || arrF25[20] != int64(0) ||
		arrF25[21] != int64(99) || arrF25[22] != "z" || arrF25[23] != int64(7) ||
		arrF25[24] != int64(1) || arrF25[25] != int64(4) || arrF25[26] != int64(2) ||
		arrF25[27] != true || arrF25[28] != false || arrF25[29] != int64(3) || arrF25[30] != true {
		t.Fatalf("Round47 F25 values mismatch: %#v", arrF25)
	}
	numsAfter, _ := docF25["nums"].([]any)
	tagsAfter, _ := docF25["tags"].([]any)
	// [1,2,3,4] -> swap(0,3) -> [4,2,3,1] -> rotate(1) -> [1,4,2,3]
	if len(numsAfter) != 4 || numsAfter[0] != int64(1) || numsAfter[1] != int64(4) || numsAfter[2] != int64(2) || numsAfter[3] != int64(3) {
		t.Fatalf("Round47 F25 nums mutation mismatch: %#v", numsAfter)
	}
	if len(tagsAfter) != 3 || tagsAfter[0] != "A" || tagsAfter[1] != "b" || tagsAfter[2] != "A" {
		t.Fatalf("Round47 F25 tags mutation mismatch: %#v", tagsAfter)
	}

	// F26: String code-point indexOf/lastIndexOf overload, .regionMatches, .lines(), .chars(), .codePoints(), .getBytes()
	valF26, err := Eval(map[string]any{}, `
		def s = "abca";
		def idx1 = s.indexOf(98);
		def idx2 = s.indexOf(97, 1);
		def lidx1 = s.lastIndexOf(97);
		def lidx2 = s.lastIndexOf(97, 2);
		def rm1 = "HelloWorld".regionMatches(5, "WorldPeace", 0, 5);
		def rm2 = "HelloWorld".regionMatches(true, 5, "worldpeace", 0, 5);
		def rm3 = "Hello".regionMatches(-1, "Hello", 0, 2);
		def lineList = "l1\nl2\r\nl3\n".lines().filter(x -> x != "l2").collect(Collectors.toList());
		def charSum = "AB".chars().sum();
		def cpCount = "XYZ".codePoints().count();
		def bytes1 = "AB".getBytes();
		def bytes2 = "AB".getBytes("UTF-8");
		return [idx1, idx2, lidx1, lidx2, rm1, rm2, rm3, lineList, charSum, cpCount, bytes1, bytes2];
	`, nil)
	if err != nil {
		t.Fatalf("Round47 F26 Eval failed: %v", err)
	}
	arrF26, ok := valF26.([]any)
	if !ok || len(arrF26) != 12 {
		t.Fatalf("Round47 F26 unexpected result: %#v", valF26)
	}
	lineList, _ := arrF26[7].([]any)
	bytes1, _ := arrF26[10].([]any)
	bytes2, _ := arrF26[11].([]any)
	if arrF26[0] != int64(1) || arrF26[1] != int64(3) || arrF26[2] != int64(3) || arrF26[3] != int64(0) ||
		arrF26[4] != true || arrF26[5] != true || arrF26[6] != false ||
		len(lineList) != 2 || lineList[0] != "l1" || lineList[1] != "l3" ||
		arrF26[8] != int64(131) || arrF26[9] != int64(3) ||
		len(bytes1) != 2 || bytes1[0] != int64(65) || bytes1[1] != int64(66) ||
		len(bytes2) != 2 || bytes2[0] != int64(65) {
		t.Fatalf("Round47 F26 values mismatch: %#v", arrF26)
	}

	// F27: DateTimeFormatter, Duration, ZonedDateTime/LocalDate/LocalDateTime factories & .format(formatter)
	valF27, err := Eval(map[string]any{}, `
		DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
		def ldt = LocalDateTime.parse("2025/03/15 14:30:00", fmt);
		def formatted = ldt.format(DateTimeFormatter.ofPattern("dd-MM-yyyy"));
		def isoFmt = ldt.format(DateTimeFormatter.ISO_LOCAL_DATE);
		def ld = LocalDate.of(2025, 3, 15);
		def epochDay = ld.toEpochDay();
		def ldFromEpoch = LocalDate.ofEpochDay(epochDay);
		def zdt = ZonedDateTime.of(2025, 3, 15, 12, 0, 0, 0, ZoneOffset.UTC);
		def zdtShifted = zdt.withZoneSameInstant("+02:00");
		def dur = Duration.between("2025-03-15T10:00:00Z", "2025-03-16T12:30:00Z");
		def durHours = dur.toHours();
		def durDays = dur.toDays();
		def durParsed = Duration.parse("PT1H30M").plusMinutes(15).minusSeconds(30);
		def negDur = Duration.parse("-PT5S");
		return [
			formatted, isoFmt, ld, epochDay, ldFromEpoch,
			zdt.toLocalDate(), zdtShifted.getHour(),
			durHours, durDays, durParsed.toSeconds(),
			negDur.isNegative(), negDur.abs().toSeconds(), Duration.ofDays(2).plusHours(3).toHours()
		];
	`, nil)
	if err != nil {
		t.Fatalf("Round47 F27 Eval failed: %v", err)
	}
	arrF27, ok := valF27.([]any)
	if !ok || len(arrF27) != 13 {
		t.Fatalf("Round47 F27 unexpected result: %#v", valF27)
	}
	if arrF27[0] != "15-03-2025" || arrF27[1] != "2025-03-15" || arrF27[2] != "2025-03-15" ||
		arrF27[3] != int64(20162) || arrF27[4] != "2025-03-15" ||
		arrF27[5] != "2025-03-15" || arrF27[6] != int64(14) ||
		arrF27[7] != int64(26) || arrF27[8] != int64(1) || arrF27[9] != int64(6270) ||
		arrF27[10] != true || arrF27[11] != int64(5) || arrF27[12] != int64(51) {
		t.Fatalf("Round47 F27 values mismatch: %#v", arrF27)
	}

	// F28: Pattern flags & Matcher methods (.lookingAt, .find(start), .reset(input), Pattern.matches, Pattern.quote, Matcher.quoteReplacement)
	valF28, err := Eval(map[string]any{}, `
		def p = Pattern.compile("^hello.*world$", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
		def m = p.matcher("HELLO\nWORLD");
		def okMatch = m.matches();
		def m2 = Pattern.compile("foo").matcher("foobar foo");
		def lookOk = m2.lookingAt();
		def findFrom3 = m2.find(3);
		def findStart = m2.start();
		m2.reset("xxfoo");
		def lookFail = m2.lookingAt();
		def findReset = m2.find();
		def patMatches = Pattern.matches("\\d+", "12345");
		def quotedPat = Pattern.compile(Pattern.quote("a+b")).matcher("a+b").matches();
		def qRepl = "price: 10".replaceAll("10", Matcher.quoteReplacement("$10"));
		return [okMatch, lookOk, findFrom3, findStart, lookFail, findReset, patMatches, quotedPat, qRepl];
	`, nil)
	if err != nil {
		t.Fatalf("Round47 F28 Eval failed: %v", err)
	}
	arrF28, ok := valF28.([]any)
	if !ok || len(arrF28) != 9 {
		t.Fatalf("Round47 F28 unexpected result: %#v", valF28)
	}
	if arrF28[0] != true || arrF28[1] != true || arrF28[2] != true || arrF28[3] != int64(7) ||
		arrF28[4] != false || arrF28[5] != true || arrF28[6] != true || arrF28[7] != true || arrF28[8] != "price: $10" {
		t.Fatalf("Round47 F28 values mismatch: %#v", arrF28)
	}

	// F29: Map.replace(k, v), Map.replace(k, oldV, newV), and ctx._source.replaceAll((k, v) -> ...)
	docF29 := map[string]any{
		"a": int64(1),
		"b": int64(2),
	}
	valF29, err := Eval(docF29, `
		def oldA = ctx._source.replace("a", 10);
		def miss = ctx._source.replace("missing", 99);
		def ok3 = ctx._source.replace("b", 2, 20);
		def fail3 = ctx._source.replace("b", 999, 30);
		ctx._source.replaceAll((k, v) -> v + 1);
		return [oldA, miss, ok3, fail3, ctx._source.a, ctx._source.b];
	`, nil)
	if err != nil {
		t.Fatalf("Round47 F29 Eval failed: %v", err)
	}
	arrF29, ok := valF29.([]any)
	if !ok || len(arrF29) != 6 {
		t.Fatalf("Round47 F29 unexpected result: %#v", valF29)
	}
	if arrF29[0] != int64(1) || arrF29[1] != nil || arrF29[2] != true || arrF29[3] != false ||
		arrF29[4] != int64(11) || arrF29[5] != int64(21) || docF29["a"] != int64(11) || docF29["b"] != int64(21) {
		t.Fatalf("Round47 F29 values mismatch: %#v (doc=%#v)", arrF29, docF29)
	}

	// F30 & F32: scripted_upsert ctx.op = "create", doc_as_upsert + scripted_upsert, and ctx.get/getOrDefault/containsKey metadata support
	upsertRaw, opRes, err := ApplyUpdateWithResult(nil, &UpdateRequest{
		ScriptedUpsert: true,
		DocAsUpsert:    true,
		Doc:            map[string]any{"base": int64(10)},
		MetaID:         "doc-1",
		MetaIndex:      "idx-1",
		MetaRouting:    "r-1",
		MetaVersion:    int64(1),
		Script: &ScriptSpec{
			Source: `
				ctx._source.seen_op = ctx.get("op");
				ctx._source.seen_id = ctx.get("_id");
				ctx._source.seen_idx = ctx.getOrDefault("_index", "none");
				ctx._source.has_src = ctx.containsKey("_source");
				ctx._source.has_now = ctx.containsKey("_now");
				ctx._source.base = ctx._source.base + 5;
			`,
		},
	}, false)
	if err != nil {
		t.Fatalf("Round47 F30/F32 ApplyUpdateWithResult failed: %v", err)
	}
	var upsertDoc map[string]any
	if uErr := json.Unmarshal(upsertRaw, &upsertDoc); uErr != nil {
		t.Fatalf("Round47 F30/F32 json.Unmarshal failed: %v", uErr)
	}
	if opRes != "created" || upsertDoc["seen_op"] != "create" || upsertDoc["seen_id"] != "doc-1" ||
		upsertDoc["seen_idx"] != "idx-1" || upsertDoc["has_src"] != true ||
		upsertDoc["has_now"] != true || upsertDoc["base"] != float64(15) {
		t.Fatalf("Round47 F30/F32 unexpected upsert doc (opRes=%s): %#v", opRes, upsertDoc)
	}

	// Additional coverage for DateTimeFormatter pattern tokens and ctx Map methods
	_, err = Eval(map[string]any{"k": "v"}, `
		def f = DateTimeFormatter.ofPattern("yy-MMM-MMMM-d-h-m-s-S-a-EEE-EEEE-X-XX-XXX-x-xx-xxx-Z-ZZZZ-z-'lit''q'");
		def z = ZonedDateTime.of(2025, 3, 15, 14, 5, 6, 0, "UTC-05:00");
		def c1 = (0 == new ArrayList<String>().size());
		def c2 = ctx.get("_routing") + ":" + ctx.get("_version") + ":" + ctx.get("k");
		def c3 = "abc".indexOf(98) + "abc".lastIndexOf(99);
		return z.format(f) + ":" + c1 + ":" + c2 + ":" + c3;
	`, map[string]any{"_ctx_routing": "r1", "_ctx_version": int64(2)})
	if err != nil {
		t.Fatalf("DateTimeFormatter extended tokens failed: %v", err)
	}
}

func TestRound48PainlessTrack5Findings(t *testing.T) {
	// F18: Matcher start-anchored (^ / \A) slicing, UTF-8 zero-length advance, & named group start(String) / end(String)
	valF18, err := Eval(nil, `
		def mCaret = Pattern.compile("^foo").matcher("foofoo");
		def c1 = mCaret.find();
		def c2 = mCaret.find();
		def c3 = mCaret.find(3);
		def mAbs = Pattern.compile("\\Afoo").matcher("foo\nfoo");
		def a1 = mAbs.find();
		def a2 = mAbs.find();
		def mMulti = Pattern.compile("(?m)^foo").matcher("foofoo\nfoo");
		def ml1 = mMulti.find();
		def ml1Start = mMulti.start();
		def ml2 = mMulti.find();
		def ml2Start = mMulti.start();
		def mZero = Pattern.compile("a*").matcher("éa");
		def zMatches = [];
		while (mZero.find()) {
			zMatches.add(mZero.start() + ":" + mZero.end() + ":" + mZero.group());
		}
		def mNamed = Pattern.compile("(?<prefix>é+)-(?<num>\\d+)").matcher("xx éé-42 yy");
		def nFound = mNamed.find();
		def nGrp = mNamed.group("num");
		def nStart = mNamed.start("num");
		def nEnd = mNamed.end("num");
		return [c1, c2, c3, a1, a2, ml1, ml1Start, ml2, ml2Start, zMatches, nFound, nGrp, nStart, nEnd];
	`, nil)
	if err != nil {
		t.Fatalf("Round48 F18 Eval failed: %v", err)
	}
	arrF18, ok := valF18.([]any)
	if !ok || len(arrF18) != 14 {
		t.Fatalf("Round48 F18 unexpected result: %#v", valF18)
	}
	if arrF18[0] != true || arrF18[1] != false || arrF18[2] != false ||
		arrF18[3] != true || arrF18[4] != false ||
		arrF18[5] != true || arrF18[6] != int64(0) || arrF18[7] != true || arrF18[8] != int64(7) ||
		arrF18[10] != true || arrF18[11] != "42" || arrF18[12] != int64(6) || arrF18[13] != int64(8) {
		t.Fatalf("Round48 F18 values mismatch: %#v", arrF18)
	}
	zSlice, _ := arrF18[9].([]any)
	if len(zSlice) != 3 || zSlice[0] != "0:0:" || zSlice[1] != "1:2:a" || zSlice[2] != "2:2:" {
		t.Fatalf("Round48 F18 zero-length UTF-8 matches mismatch: %#v", zSlice)
	}

	// F19: Arrays.* static methods & stream pipelines
	docF19 := map[string]any{
		"nums": []any{int64(4), int64(1), int64(3), int64(2)},
	}
	valF19, err := Eval(docF19, `
		Arrays.sort(ctx._source.nums);
		def bsHit = Arrays.binarySearch(ctx._source.nums, 3);
		def bsMiss = Arrays.binarySearch(ctx._source.nums, 5);
		def cp1 = Arrays.copyOf(ctx._source.nums, 2);
		def cp2 = Arrays.copyOf(ctx._source.nums, 6);
		def cpr = Arrays.copyOfRange(ctx._source.nums, 1, 3);
		def eqOk = Arrays.equals(cp1, [1, 2]);
		def deepEqOk = Arrays.deepEquals([[1, 2], [3]], [[1, 2], [3]]);
		def str1 = Arrays.toString(cp1);
		def strDeep = Arrays.deepToString([[1, 2], [null, "a"]]);
		def filled = [0, 0, 0, 0];
		Arrays.fill(filled, 1, 3, 9);
		def streamSum = Arrays.stream(ctx._source.nums, 1, 4).map(x -> x * 10).sum();
		def rangeList = IntStream.range(1, 4).map(x -> x + 1).collect(Collectors.toList());
		def rangeClosedSum = IntStream.rangeClosed(1, 4).sum();
		def streamOfJoined = Stream.of("a", "b", "c").collect(Collectors.joining("-"));
		return [bsHit, bsMiss, cp1, cp2, cpr, eqOk, deepEqOk, str1, strDeep, filled, streamSum, rangeList, rangeClosedSum, streamOfJoined];
	`, nil)
	if err != nil {
		t.Fatalf("Round48 F19 Eval failed: %v", err)
	}
	arrF19, ok := valF19.([]any)
	if !ok || len(arrF19) != 14 {
		t.Fatalf("Round48 F19 unexpected result: %#v", valF19)
	}
	if arrF19[0] != int64(2) || arrF19[1] != int64(-5) || arrF19[5] != true || arrF19[6] != true ||
		arrF19[7] != "[1, 2]" || arrF19[8] != "[[1, 2], [null, a]]" || arrF19[10] != int64(90) ||
		arrF19[12] != int64(10) || arrF19[13] != "a-b-c" {
		t.Fatalf("Round48 F19 values mismatch: %#v", arrF19)
	}

	// F20: Period.*, DateTimeFormatter.withZone / withLocale, Temporal.plus / minus, ChronoUnit.MICROS / NANOS
	valF20, err := Eval(nil, `
		Period p = Period.of(1, 14, 5).normalized();
		def pYears = p.getYears();
		def pMonths = p.getMonths();
		def pDays = p.getDays();
		def pTotalMonths = p.toTotalMonths();
		def pStr = p.toString();
		def pBetween = Period.between("2024-01-15", "2025-03-20").toString();
		def pParsed = Period.parse("P2W3D").getDays();
		def dPlusP = LocalDate.parse("2025-01-31").plus(Period.ofMonths(1)).toString();
		def dMinusU = LocalDate.parse("2025-03-10").minus(10, ChronoUnit.DAYS);
		def dtPlusDur = Instant.parse("2025-01-01T00:00:00Z").plus(Duration.ofMinutes(90));
		def fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone("UTC+02:00").withLocale("en_US");
		def formatted = Instant.parse("2025-01-01T10:30:00Z").format(fmt);
		def micros = ChronoUnit.MICROS.between("2025-01-01T00:00:00Z", "2025-01-01T00:00:00.001500Z");
		def nanos = ChronoUnit.NANOS.between("2025-01-01T00:00:00Z", "2025-01-01T00:00:00.000001500Z");
		return [pYears, pMonths, pDays, pTotalMonths, pStr, pBetween, pParsed, dPlusP, dMinusU, dtPlusDur, formatted, micros, nanos];
	`, nil)
	if err != nil {
		t.Fatalf("Round48 F20 Eval failed: %v", err)
	}
	arrF20, ok := valF20.([]any)
	if !ok || len(arrF20) != 13 {
		t.Fatalf("Round48 F20 unexpected result: %#v", valF20)
	}
	if arrF20[0] != int64(2) || arrF20[1] != int64(2) || arrF20[2] != int64(5) || arrF20[3] != int64(26) ||
		arrF20[4] != "P2Y2M5D" || arrF20[5] != "P1Y2M5D" || arrF20[6] != int64(17) ||
		arrF20[7] != "2025-02-28" || arrF20[8] != "2025-02-28" || arrF20[9] != "2025-01-01T01:30:00Z" ||
		arrF20[10] != "2025-01-01 12:30" || arrF20[11] != int64(1500) || arrF20[12] != int64(1500) {
		t.Fatalf("Round48 F20 values mismatch: %#v", arrF20)
	}

	// F21: Collection constructor capacity vs copy constructor
	valF21, err := Eval(nil, `
		def lCap = new ArrayList(10);
		def lCopy = new ArrayList([1, 2, 3]);
		def sCap = new HashSet(16);
		def sCopy = new LinkedHashSet([1, 2, 1, 3]);
		def mCap = new HashMap(16);
		def mCapLoad = new LinkedHashMap(16, 0.75);
		def mCopy = new TreeMap(["a": 1, "b": 2]);
		return [lCap.size(), lCopy.size(), sCap.size(), sCopy, mCap.size(), mCapLoad.size(), mCopy.size(), mCopy instanceof Map, sCopy instanceof Set];
	`, nil)
	if err != nil {
		t.Fatalf("Round48 F21 Eval failed: %v", err)
	}
	arrF21, ok := valF21.([]any)
	if !ok || len(arrF21) != 9 {
		t.Fatalf("Round48 F21 unexpected result: %#v", valF21)
	}
	if arrF21[0] != int64(0) || arrF21[1] != int64(3) || arrF21[2] != int64(0) ||
		arrF21[4] != int64(0) || arrF21[5] != int64(0) || arrF21[6] != int64(2) ||
		arrF21[7] != true || arrF21[8] != true {
		t.Fatalf("Round48 F21 values mismatch: %#v", arrF21)
	}

	// F22: StringBuilder & UUID static methods
	valF22, err := Eval(nil, `
		StringBuilder sb = new StringBuilder(32);
		sb.append("hello").append(" ").append("world", 0, 5);
		sb.insert(5, ",");
		sb.replace(0, 5, "hi");
		sb.deleteCharAt(2);
		def sub = sb.substring(0, 2);
		def ch = sb.charAt(0);
		def idx = sb.indexOf("world");
		def rev = new StringBuilder("abc").reverse().toString();
		UUID u1 = UUID.randomUUID();
		def u2 = UUID.nameUUIDFromBytes("test-seed");
		def u3 = UUID.fromString("123e4567-e89b-12d3-a456-426614174000");
		return [sb.toString(), sb.length(), sub, ch, idx, rev, u1.length() == 36, u2, u3, sb instanceof StringBuilder];
	`, nil)
	if err != nil {
		t.Fatalf("Round48 F22 Eval failed: %v", err)
	}
	arrF22, ok := valF22.([]any)
	if !ok || len(arrF22) != 10 {
		t.Fatalf("Round48 F22 unexpected result: %#v", valF22)
	}
	if arrF22[0] != "hi world" || arrF22[1] != int64(8) || arrF22[2] != "hi" || arrF22[3] != "h" ||
		arrF22[4] != int64(3) || arrF22[5] != "cba" || arrF22[6] != true ||
		arrF22[7] != "bfe71b97-a2d8-3474-b154-45d05efa6c45" ||
		arrF22[8] != "123e4567-e89b-12d3-a456-426614174000" || arrF22[9] != true {
		t.Fatalf("Round48 F22 values mismatch: %#v", arrF22)
	}

	// F23: Math.*Exact, Math.ulp/nextAfter/nextUp/nextDown/IEEEremainder, unsigned Integer/Long, Objects.requireNonNull*, List/Set/Map.copyOf
	valF23, err := Eval(nil, `
		def addOk = Math.addExact(10, 20);
		def subOk = Math.subtractExact(50, 15);
		def mulOk = Math.multiplyExact(6, 7);
		def incOk = Math.incrementExact(9);
		def decOk = Math.decrementExact(9);
		def negOk = Math.negateExact(-5);
		def toIntOk = Math.toIntExact(12345);
		def overflowCaught = false;
		try {
			def x = Math.addExact(Long.MAX_VALUE, 1);
		} catch (ArithmeticException e) {
			overflowCaught = true;
		}
		def uIntStr = Integer.toUnsignedString(-1);
		def uDiv = Integer.divideUnsigned(-2, 2);
		def uRem = Integer.remainderUnsigned(-2, 3);
		def uCmp = Integer.compareUnsigned(-1, 1);
		def reqDef = Objects.requireNonNullElse(null, "fallback");
		def npeCaught = false;
		try {
			def y = Objects.requireNonNull(null, "must not be null");
		} catch (NullPointerException e) {
			npeCaught = true;
		}
		def setCp = Set.copyOf([1, 2, 1, 3]);
		return [addOk, subOk, mulOk, incOk, decOk, negOk, toIntOk, overflowCaught, uIntStr, uDiv, uRem, uCmp > 0, reqDef, npeCaught, setCp.size()];
	`, nil)
	if err != nil {
		t.Fatalf("Round48 F23 Eval failed: %v", err)
	}
	arrF23, ok := valF23.([]any)
	if !ok || len(arrF23) != 15 {
		t.Fatalf("Round48 F23 unexpected result: %#v", valF23)
	}
	if arrF23[0] != int64(30) || arrF23[1] != int64(35) || arrF23[2] != int64(42) ||
		arrF23[3] != int64(10) || arrF23[4] != int64(8) || arrF23[5] != int64(5) ||
		arrF23[6] != int64(12345) || arrF23[7] != true || arrF23[8] != "4294967295" ||
		arrF23[9] != int64(2147483647) || arrF23[10] != int64(2) || arrF23[11] != true ||
		arrF23[12] != "fallback" || arrF23[13] != true || arrF23[14] != int64(3) {
		t.Fatalf("Round48 F23 values mismatch: %#v", arrF23)
	}

	// F24 (Painless part): Ingest/Update chained ctx.get('nested').put(...) / ctx.get('nested').field = ...
	docF24 := map[string]any{
		"nested": map[string]any{"a": int64(1)},
		"items":  []any{"x"},
	}
	_, err = Eval(docF24, `
		ctx.get("nested").put("b", 2);
		ctx.get("nested").c = 3;
		ctx.get("items").add("y");
		ctx.get("_source").put("top", "ok");
	`, nil)
	if err != nil {
		t.Fatalf("Round48 F24 Eval failed: %v", err)
	}
	nestedMap, _ := docF24["nested"].(map[string]any)
	itemsSlice, _ := docF24["items"].([]any)
	if nestedMap["a"] != int64(1) || nestedMap["b"] != int64(2) || nestedMap["c"] != int64(3) ||
		len(itemsSlice) != 2 || itemsSlice[1] != "y" || docF24["top"] != "ok" {
		t.Fatalf("Round48 F24 document mutation mismatch: %#v", docF24)
	}
}

func TestRound48PainlessDeepStdlibAndMutationsCoverage(t *testing.T) {
	// 1. Map & List mutations on ctx, ctx._source, ctx._source.sub, params, and local vars
	doc := map[string]any{
		"arr":    []any{10, 20, 30},
		"nested": map[string]any{"k1": "v1", "k2": "v2"},
		"top":    "keep",
		"drop":   "gone",
	}
	params := map[string]any{
		"p1":      "val1",
		"p2":      "val2",
		"parr":    []any{"a", "b"},
		"pmap":    map[string]any{"x": 1},
		"_ctx_op": "update",
	}
	_, err := Eval(doc, `
		ctx._source.remove("drop");
		ctx._source.nested.remove("k1", "v1");
		ctx._source.nested.put("k3", "v3");
		ctx._source.nested.putIfAbsent("k2", "ignored");
		ctx._source.nested.putIfAbsent("k4", "v4");
		ctx._source.nested.putAll(["k5": "v5"]);
		ctx._source.put("added_top", 100);
		ctx._source.putIfAbsent("added_top", 200);
		ctx._source.putIfAbsent("new_top", 300);
		ctx._source.putAll(["batch1": 1, "batch2": 2]);
		ctx._source.arr.set(1, 25);
		ctx._source.arr.add(1, 15);
		ctx._source.arr.add(40);
		ctx._source.arr.addAll([50, 60]);
		ctx._source.arr.addAll(0, [5]);
		ctx._source.arr.sort((a, b) -> b - a);
		params.remove("p1");
		params.remove("p2", "val2");
		params.put("p3", "v3");
		params.putIfAbsent("p3", "ignored");
		params.putIfAbsent("p4", "v4");
		params.putAll(["p5": "v5"]);
		def localArr = [3, 1, 2];
		localArr.set(0, 9);
		localArr.add(1, 8);
		localArr.addAll([7, 6]);
		localArr.addAll(0, [10]);
		localArr.sort();
		def localMap = ["a": 1];
		localMap.put("b", 2);
		localMap.putIfAbsent("b", 99);
		localMap.putIfAbsent("c", 3);
		localMap.putAll(["d": 4]);
		localMap.remove("a", 1);
		localMap.remove("b");
	`, params)
	if err != nil {
		t.Fatalf("mutations script failed: %v", err)
	}

	// 2. Period, Duration, ZonedDateTime, LocalDate, LocalDateTime, Instant, ChronoUnit
	dtRes, err := Eval(nil, `
		def p = Period.of(1, 2, 3)
			.plus(Period.ofDays(4))
			.minus(Period.ofMonths(1))
			.plusYears(1).minusYears(1)
			.plusMonths(2).minusMonths(1)
			.plusDays(5).minusDays(2)
			.multipliedBy(2);
		def d = Duration.ofHours(2)
			.plus(30, ChronoUnit.MINUTES)
			.minus(10, ChronoUnit.SECONDS)
			.plus(1, ChronoUnit.DAYS)
			.plus(1, ChronoUnit.HOURS)
			.plus(1, ChronoUnit.MILLIS)
			.plus(1, ChronoUnit.MICROS)
			.plus(1, ChronoUnit.NANOS)
			.plus(Duration.ofMinutes(5))
			.plusDays(1).minusHours(1).plusMinutes(1).minusSeconds(1).plusMillis(100).minusNanos(50)
			.multipliedBy(2);
		def zdt = ZonedDateTime.parse("2025-03-15T14:30:45.123456789Z");
		def tDays = zdt.truncatedTo(ChronoUnit.DAYS);
		def tHours = zdt.truncatedTo(ChronoUnit.HOURS);
		def tMins = zdt.truncatedTo(ChronoUnit.MINUTES);
		def tSecs = zdt.truncatedTo(ChronoUnit.SECONDS);
		def tMillis = zdt.truncatedTo(ChronoUnit.MILLIS);
		def tMicros = zdt.truncatedTo(ChronoUnit.MICROS);
		def zdt2 = zdt
			.plus(1, ChronoUnit.YEARS)
			.plus(1, ChronoUnit.MONTHS)
			.plus(1, ChronoUnit.WEEKS)
			.plus(1, ChronoUnit.DAYS)
			.plus(1, ChronoUnit.HOURS)
			.plus(1, ChronoUnit.MINUTES)
			.plus(1, ChronoUnit.SECONDS)
			.plus(1, ChronoUnit.MILLIS)
			.plus(1, ChronoUnit.MICROS)
			.plus(1, ChronoUnit.NANOS)
			.plus(Period.ofDays(2))
			.plus(Duration.ofHours(3))
			.plusYears(1).minusMonths(1).plusWeeks(1).minusDays(1)
			.plusHours(1).minusMinutes(1).plusSeconds(1).minusMillis(1).plusNanos(1)
			.withYear(2026).withMonth(6).withDayOfMonth(10)
			.withHour(8).withMinute(15).withSecond(20).withNano(500);
		def cmpAfter = zdt2.isAfter(zdt);
		def cmpBefore = zdt.isBefore(zdt2);
		def cmpEq = zdt.isEqual(zdt);
		def props = [zdt2.year, zdt2.monthValue, zdt2.month, zdt2.dayOfMonth, zdt2.dayOfYear, zdt2.hour, zdt2.minute, zdt2.second, zdt2.nano, zdt2.dayOfWeek, zdt2.dayOfWeekEnum];
		def cu = [
			ChronoUnit.YEARS.between(zdt, zdt2),
			ChronoUnit.MONTHS.between(zdt, zdt2),
			ChronoUnit.WEEKS.between(zdt, zdt2),
			ChronoUnit.DAYS.between(zdt, zdt2),
			ChronoUnit.HOURS.between(zdt, zdt2),
			ChronoUnit.MINUTES.between(zdt, zdt2),
			ChronoUnit.SECONDS.between(zdt, zdt2),
			ChronoUnit.MILLIS.between(zdt, zdt2),
			ChronoUnit.MICROS.between(zdt, zdt2),
			ChronoUnit.NANOS.between(zdt, zdt2)
		];
		def zOf = ZonedDateTime.of(2025, 1, 2, 3, 4, 5, 0, ZoneId.of("UTC"));
		def zInst = ZonedDateTime.ofInstant(Instant.ofEpochSecond(1700000000, 500), ZoneOffset.ofHours(2));
		def ld1 = LocalDate.of(2025, 5, 10);
		def ld2 = LocalDate.ofEpochDay(100);
		def ldt = LocalDateTime.of(2025, 5, 10, 12, 30, 15, 100);
		def dBet = Duration.between(zdt, zdt2);
		def pBet = Period.between("2024-01-20", "2025-03-10");
		return [p.getYears(), d != null, tDays != null, tHours != null, tMins != null, tSecs != null, tMillis != null, tMicros != null, cmpAfter, cmpBefore, cmpEq, props.size(), cu.size(), zOf != null, zInst != null, ld1, ld2, ldt != null, dBet != null, pBet.getYears()];
	`, nil)
	if err != nil {
		t.Fatalf("datetime & period script failed: %v", err)
	}
	if arr, ok := dtRes.([]any); !ok || len(arr) != 20 {
		t.Fatalf("unexpected dtRes: %#v", dtRes)
	}

	// 3. Math, Integer/Long/Short/Byte/Double/Float/Boolean, Objects, Collections, and Stream operations
	stdRes, err := Eval(nil, `
		def m = [
			Math.toRadians(180),
			Math.toDegrees(3.141592653589793),
			Math.floorDiv(-7, 3),
			Math.floorMod(-7, 3),
			Math.ulp(1.0),
			Math.nextAfter(1.0, 2.0),
			Math.nextUp(1.0),
			Math.nextDown(1.0),
			Math.IEEEremainder(10.0, 3.0),
			Math.copySign(5.0, -1.0),
			Math.scalb(1.5, 2),
			Math.getExponent(8.0),
			Math.getExponent(0.0)
		];
		def nums = [
			Integer.parseInt("ff", 16),
			Long.parseLong("1010", 2),
			Short.parseShort("123"),
			Byte.parseByte("12"),
			Double.parseDouble("3.5"),
			Float.parseFloat("2.5"),
			Boolean.parseBoolean("true"),
			Integer.toString(255, 16),
			Double.toString(1.5),
			Boolean.toString(true),
			Integer.toHexString(255),
			Integer.toBinaryString(5),
			Integer.toOctalString(8),
			Long.toHexString(255),
			Long.toUnsignedString(-1),
			Integer.parseUnsignedInt("4294967295"),
			Long.parseUnsignedLong("100"),
			Long.compareUnsigned(-1, 1),
			Long.divideUnsigned(100, 3),
			Long.remainderUnsigned(100, 3),
			Integer.compare(1, 2),
			Boolean.compare(true, false)
		];
		def objs = [
			Objects.equals("a", "a"),
			Objects.isNull(null),
			Objects.nonNull("x"),
			Objects.toString(null, "def"),
			Objects.toString("hi")
		];
		def colList = [1, 2, 3, 4];
		Collections.rotate(colList, 1);
		Collections.replaceAll(colList, 2, 20);
		Collections.reverse(colList);
		Collections.sort(colList);
		def fillList = [1, 2, 3];
		Collections.fill(fillList, 9);

		def s1 = [1, 2, 2, 3, 4, 5].stream()
			.filter(x -> x > 1)
			.distinct()
			.sorted()
			.skip(1)
			.limit(3)
			.mapToInt(x -> x * 2)
			.sum();
		def s2 = [2.0, 4.0, 6.0].stream().mapToDouble(x -> x).average().orElse(0.0);
		def s3 = [3, 1, 4].stream().min().orElse(0);
		def s4 = [3, 1, 4].stream().max().orElse(0);
		def s5 = [3, 1, 4].stream().findFirst().orElse(0);
		def s6 = [1, 2, 3].stream().anyMatch(x -> x == 2);
		def s7 = [1, 2, 3].stream().allMatch(x -> x > 0);
		def s8 = [1, 2, 3].stream().noneMatch(x -> x < 0);
		def s9 = [1, 2, 3, 4].stream().reduce(0, (a, b) -> a + b);
		def s10 = ["a", "b", "c"].stream().collect(Collectors.joining(",", "[", "]"));
		def s11 = [1, 1, 2].stream().collect(Collectors.toSet());
		def s12 = [[1, 2], [3, 4]].stream().flatMap(x -> x.stream()).count();
		return [m.size(), nums.size(), objs.size(), colList.size(), fillList[0], s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11.size(), s12];
	`, nil)
	if err != nil {
		t.Fatalf("stdlib & stream script failed: %v", err)
	}
	if arr, ok := stdRes.([]any); !ok || len(arr) != 17 {
		t.Fatalf("unexpected stdRes: %#v", stdRes)
	}
}

func TestRound49PainlessFindingsF23ToF29(t *testing.T) {
	// F23: Chained mutators on method-call receivers (.computeIfAbsent, .compute, .get, .getOrDefault)
	t.Run("F23_ChainedMutatorsOnMethodReceivers", func(t *testing.T) {
		doc := map[string]any{
			"nested": map[string]any{},
		}
		_, err := Eval(doc, `
			Map m = new HashMap();
			m.computeIfAbsent('tags', k -> new ArrayList()).add('a');
			m.computeIfAbsent('tags', k -> new ArrayList()).add('b');
			m.computeIfAbsent('tags', k -> new ArrayList()).addAll(['c', 'd']);
			m.get('tags').add(0, 'z');
			m.get('tags').addAll(1, ['x', 'y']);
			m.get('tags').removeIf(v -> v == 'z');
			m.get('tags').removeAll(['x', 'y']);
			m.get('tags').retainAll(['a', 'b', 'c', 'd']);
			m.get('tags').set(1, 'B');
			m.get('tags').remove('c');
			m.computeIfAbsent('meta', k -> new HashMap()).put('k1', 10);
			m.get('meta').putIfAbsent('k2', 20);
			m.get('meta').putAll(['k3': 30, 'k4': 40, 'k5': 50]);
			m.get('meta').remove('k4', 40);
			m.get('meta').remove('k5');
			ctx._source.nested.computeIfAbsent('items', k -> new ArrayList()).add(100);
			ctx._source.nested.get('items').add(200);
			ctx._source.m = m;
		`, nil)
		if err != nil {
			t.Fatalf("F23 Eval failed: %v", err)
		}
		m, ok := doc["m"].(map[string]any)
		if !ok {
			t.Fatalf("expected map m in doc, got %#v", doc["m"])
		}
		tags, ok := m["tags"].([]any)
		if !ok || len(tags) != 3 || tags[0] != "a" || tags[1] != "B" || tags[2] != "d" {
			t.Fatalf("unexpected tags slice: %#v", m["tags"])
		}
		meta, ok := m["meta"].(map[string]any)
		if !ok || meta["k1"] != int64(10) || meta["k2"] != int64(20) || meta["k3"] != int64(30) {
			t.Fatalf("unexpected meta map: %#v", m["meta"])
		}
		nested, _ := doc["nested"].(map[string]any)
		items, _ := nested["items"].([]any)
		if len(items) != 2 || items[0] != int64(100) || items[1] != int64(200) {
			t.Fatalf("unexpected nested.items: %#v", nested["items"])
		}
	})

	// F24: Direct ctx.<mapMethod> resolution & hiding internal _ingest key from map inspection
	t.Run("F24_DirectCtxMapMethodsAndHideIngestKey", func(t *testing.T) {
		doc := map[string]any{
			"_ingest": map[string]any{"timestamp": "2026-01-01T00:00:00Z"},
			"a":       int64(1),
			"b":       int64(2),
		}
		_, err := Eval(doc, `
			int sz1 = ctx._source.size();
			int sz2 = ctx.size();
			boolean emp = ctx.isEmpty();
			boolean hasVal = ctx.containsValue(2);
			def ks = new ArrayList(ctx.keySet());
			ctx.replace('a', 10);
			ctx.computeIfAbsent('c', k -> 30);
			ctx.computeIfPresent('b', (k, v) -> v + 20);
			ctx.merge('c', 5, (oldV, newV) -> oldV + newV);
			int sum = 0;
			ctx.forEach((k, v) -> { sum += v; });
			String ts = ctx._ingest.timestamp;
			ctx.clear();
			ctx._source.summary = [sz1, sz2, emp, hasVal, ks.size(), sum, ts, ctx.isEmpty()];
		`, nil)
		if err != nil {
			t.Fatalf("F24 Eval failed: %v", err)
		}
		if _, hasIngest := doc["_ingest"]; !hasIngest {
			t.Fatalf("expected _ingest to be preserved after ctx.clear()")
		}
		if _, hasA := doc["a"]; hasA {
			t.Fatalf("expected 'a' to be cleared by ctx.clear()")
		}
		summary, ok := doc["summary"].([]any)
		if !ok || len(summary) != 8 {
			t.Fatalf("unexpected summary: %#v", doc["summary"])
		}
		if summary[0] != int64(2) || summary[1] != int64(2) || summary[2] != false || summary[3] != true ||
			summary[4] != int64(2) || summary[5] != int64(67) || summary[6] != "2026-01-01T00:00:00Z" || summary[7] != true {
			t.Fatalf("unexpected F24 summary values: %#v", summary)
		}
	})

	// F25: DateTimeFormatter.format(temporal) inverted receiver, .now(), YearMonth, DayOfWeek, Month
	t.Run("F25_DateTimeFormatterAndYearMonthDayOfWeekMonth", func(t *testing.T) {
		res, err := Eval(nil, `
			DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy/MM/dd");
			LocalDate ld = LocalDate.of(2024, Month.FEBRUARY, 15);
			String s1 = fmt.format(ld);
			String s2 = ld.format(fmt);
			YearMonth ym = YearMonth.of(2024, 2);
			YearMonth ym2 = YearMonth.parse("2024-02").plusMonths(1);
			DayOfWeek dow = DayOfWeek.of(3);
			Month m = Month.of(12);
			int enumVals = DayOfWeek.MONDAY.getValue() + DayOfWeek.TUESDAY.getValue() + DayOfWeek.WEDNESDAY.getValue() +
				DayOfWeek.THURSDAY.getValue() + DayOfWeek.FRIDAY.getValue() + DayOfWeek.SATURDAY.getValue() + DayOfWeek.SUNDAY.getValue() +
				Month.JANUARY.getValue() + Month.FEBRUARY.getValue() + Month.MARCH.getValue() + Month.APRIL.getValue() +
				Month.MAY.getValue() + Month.JUNE.getValue() + Month.JULY.getValue() + Month.AUGUST.getValue() +
				Month.SEPTEMBER.getValue() + Month.OCTOBER.getValue() + Month.NOVEMBER.getValue() + Month.DECEMBER.getValue();
			boolean nowOk = Instant.now() != null && ZonedDateTime.now() != null && LocalDate.now() != null && YearMonth.now() != null && enumVals == 106;
			return [
				s1, s2,
				ym.lengthOfMonth(), ym.lengthOfYear(), ym.isLeapYear(), ym.atDay(10), ym.atEndOfMonth(),
				ym2.toString(),
				dow, DayOfWeek.MONDAY, dow.getValue(),
				m, Month.JANUARY, m.getValue(),
				nowOk
			];
		`, nil)
		if err != nil {
			t.Fatalf("F25 Eval failed: %v", err)
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != 15 {
			t.Fatalf("unexpected F25 result: %#v", res)
		}
		if arr[0] != "2024/02/15" || arr[1] != "2024/02/15" ||
			arr[2] != int64(29) || arr[3] != int64(366) || arr[4] != true ||
			arr[5] != "2024-02-10" || arr[6] != "2024-02-29" || arr[7] != "2024-03" ||
			arr[8] != "WEDNESDAY" || arr[9] != "MONDAY" || arr[10] != int64(3) ||
			arr[11] != "DECEMBER" || arr[12] != "JANUARY" || arr[13] != int64(12) || arr[14] != true {
			t.Fatalf("unexpected F25 values: %#v", arr)
		}
	})

	// F26: Base64 & new String(bytes[, charset]), StandardCharsets.*, Charset.forName
	t.Run("F26_NewStringBytesAndStandardCharsets", func(t *testing.T) {
		res, err := Eval(nil, `
			Charset cs = StandardCharsets.UTF_8;
			Charset cs2 = Charset.forName("UTF-8");
			byte[] raw = "hello world".getBytes(cs);
			String b64 = Base64.getEncoder().encodeToString(raw);
			byte[] decoded = Base64.getDecoder().decode(b64);
			String roundTrip = new String(decoded, StandardCharsets.UTF_8);
			String sliced = new String(decoded, 6, 5, cs2);
			String emptyStr = new String();
			return [roundTrip, sliced, emptyStr, cs, cs2];
		`, nil)
		if err != nil {
			t.Fatalf("F26 Eval failed: %v", err)
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != 5 {
			t.Fatalf("unexpected F26 result: %#v", res)
		}
		if arr[0] != "hello world" || arr[1] != "world" || arr[2] != "" || arr[3] != "UTF-8" || arr[4] != "UTF-8" {
			t.Fatalf("unexpected F26 values: %#v", arr)
		}
	})

	// F27: StringBuilder .setCharAt, .subSequence, .capacity, .ensureCapacity, .trimToSize, .codePointAt
	t.Run("F27_StringBuilderMethods", func(t *testing.T) {
		res, err := Eval(nil, `
			StringBuilder sb = new StringBuilder("abcde");
			sb.setCharAt(1, 'B');
			sb.ensureCapacity(100);
			sb.trimToSize();
			int cp = sb.codePointAt(1);
			String sub = sb.subSequence(1, 4);
			boolean capOk = sb.capacity() >= 5;
			return [sb.toString(), cp, sub, capOk];
		`, nil)
		if err != nil {
			t.Fatalf("F27 Eval failed: %v", err)
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != 4 {
			t.Fatalf("unexpected F27 result: %#v", res)
		}
		if arr[0] != "aBcde" || arr[1] != int64('B') || arr[2] != "Bcd" || arr[3] != true {
			t.Fatalf("unexpected F27 values: %#v", arr)
		}
	})

	// F28: Pattern.split(input[, limit]), Matcher.replaceAll(Function)/replaceFirst(Function), appendReplacement/appendTail, region
	t.Run("F28_PatternSplitAndMatcherEnhancements", func(t *testing.T) {
		res, err := Eval(nil, `
			Pattern p = Pattern.compile(",\\s*");
			def parts = p.split("a, b, c", 2);
			Pattern wordPat = Pattern.compile("(\\w+)");
			Matcher m1 = wordPat.matcher("hello world");
			String repAll = m1.replaceAll(mr -> mr.group(1).toUpperCase());
			Matcher m2 = wordPat.matcher("hello world");
			String repFirst = m2.replaceFirst(mr -> mr.group(0).toUpperCase());

			Matcher m3 = Pattern.compile("cat").matcher("one cat two cats");
			StringBuilder sb = new StringBuilder();
			while (m3.find()) {
				m3.appendReplacement(sb, "dog");
			}
			m3.appendTail(sb);

			Matcher m4 = wordPat.matcher("aa bb cc");
			m4.region(3, 5);
			int rStart = m4.regionStart();
			int rEnd = m4.regionEnd();
			boolean foundInRegion = m4.find();
			String regMatch = m4.group();

			return [parts.size(), parts[0], parts[1], repAll, repFirst, sb.toString(), rStart, rEnd, foundInRegion, regMatch];
		`, nil)
		if err != nil {
			t.Fatalf("F28 Eval failed: %v", err)
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != 10 {
			t.Fatalf("unexpected F28 result: %#v", res)
		}
		if arr[0] != int64(2) || arr[1] != "a" || arr[2] != "b, c" ||
			arr[3] != "HELLO WORLD" || arr[4] != "HELLO world" ||
			arr[5] != "one dog two dogs" || arr[6] != int64(3) || arr[7] != int64(5) ||
			arr[8] != true || arr[9] != "bb" {
			t.Fatalf("unexpected F28 values: %#v", arr)
		}
	})

	// F29: IntStream/LongStream/DoubleStream.of, Stream.empty/concat, summaryStatistics, Collectors.summarizing*, collectingAndThen, reducing, Map.entry/ofEntries, Optional
	t.Run("F29_StreamsCollectorsMapEntriesAndOptional", func(t *testing.T) {
		res, err := Eval(nil, `
			int isSum = IntStream.of(1, 2, 3, 4).sum();
			long lsSum = LongStream.of(10L, 20L).sum();
			double dsSum = DoubleStream.of(1.5, 2.5).sum();
			long empCount = Stream.empty().count();
			def catList = Stream.concat(Stream.of("a", "b"), Stream.of("c")).collect(Collectors.toList());

			IntSummaryStatistics stats1 = IntStream.of(2, 4, 6).summaryStatistics();
			def statsL = LongStream.of(2L, 4L, 6L).summaryStatistics();
			def statsD = DoubleStream.of(2.0, 4.0, 6.0).summaryStatistics();
			def stats2 = ["a", "bb", "ccc"].stream().collect(Collectors.summarizingInt(s -> s.length()));
			def stats3 = ["a", "bb", "ccc"].stream().collect(Collectors.summarizingLong(s -> s.length()));
			def stats4 = ["a", "bb", "ccc"].stream().collect(Collectors.summarizingDouble(s -> s.length() * 1.0));

			int catSize = [1, 2, 2, 3].stream().collect(Collectors.collectingAndThen(Collectors.toSet(), s -> s.size()));
			int red1 = [1, 2, 3, 4].stream().collect(Collectors.reducing((a, b) -> a + b)).orElse(0);
			int red2 = [1, 2, 3, 4].stream().collect(Collectors.reducing(10, (a, b) -> a + b));
			int red3 = ["a", "bb", "ccc"].stream().collect(Collectors.reducing(0, s -> s.length(), (a, b) -> a + b));

			Map m = Map.ofEntries(Map.entry("k1", 100), Map.entry("k2", 200));
			Optional opt1 = Optional.of("val");
			Optional opt2 = Optional.ofNullable(null);
			def seen = [];
			opt1.ifPresent(v -> seen.add(v));
			String lazyVal = opt2.orElseGet(() -> "lazy");
			boolean statsExtraOk = statsL.getSum() == 12 && statsD.getSum() == 12.0 && stats3.getSum() == 6 && stats4.getSum() == 6.0 && seen.size() == 1 && lazyVal == "lazy";

			return [
				isSum, lsSum, dsSum, empCount, catList.size(),
				stats1.getCount(), stats1.getSum(), stats1.getMin(), stats1.getMax(), stats1.getAverage(),
				stats2.getCount(), stats2.getSum(),
				catSize, red1, red2, red3,
				m.get("k1"), m.get("k2"),
				opt1.isPresent(), opt1.get(), opt2.isPresent(), statsExtraOk ? opt2.orElse("fallback") : "bad"
			];
		`, nil)
		if err != nil {
			t.Fatalf("F29 Eval failed: %v", err)
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != 22 {
			t.Fatalf("unexpected F29 result: %#v", res)
		}
		if arr[0] != int64(10) || arr[1] != int64(30) || arr[2] != float64(4.0) ||
			arr[3] != int64(0) || arr[4] != int64(3) ||
			arr[5] != int64(3) || arr[6] != int64(12) || arr[7] != int64(2) || arr[8] != int64(6) || arr[9] != float64(4.0) ||
			arr[10] != int64(3) || arr[11] != int64(6) ||
			arr[12] != int64(3) || arr[13] != int64(10) || arr[14] != int64(20) || arr[15] != int64(6) ||
			arr[16] != int64(100) || arr[17] != int64(200) ||
			arr[18] != true || arr[19] != "val" || arr[20] != false || arr[21] != "fallback" {
			t.Fatalf("unexpected F29 values: %#v", arr)
		}
	})

	t.Run("ArraysCollectionsDigestsAndEncodings", func(t *testing.T) {
		res, err := Eval(nil, `
			def a = [4, 2, 1, 3];
			Arrays.sort(a, 0, 3);
			Arrays.sort(a);
			int bs1 = Arrays.binarySearch(a, 3);
			int bs2 = Arrays.binarySearch(a, 0, 3, 2);
			def fArr = [0, 0, 0, 0];
			Arrays.fill(fArr, 1, 3, 9);
			def cp1 = Arrays.copyOf(a, 2);
			def cp2 = Arrays.copyOfRange(a, 1, 3);
			boolean eq1 = Arrays.equals([1, 2], [1, 2]);
			boolean eq2 = Arrays.deepEquals([[1]], [[1]]);
			String ts1 = Arrays.toString([1, null, 2]);
			String ts2 = Arrays.deepToString([[1, 2], [3]]);
			long asSum = Arrays.stream([10, 20, 30, 40], 1, 3).mapToInt(x -> x).sum();
			long isArr = IntStream.of([1, 2, 3]).sum();
			double dsArr = DoubleStream.of([1.5, 2.5]).sum();
			def empIS = IntStream.empty().summaryStatistics();
			def empDS = DoubleStream.empty().summaryStatistics();
			def lc = List.copyOf([1, 2, 2]);
			def sc = Set.copyOf([1, 2, 2]);
			def mc = Map.copyOf(['a': 1]);
			def el = Collections.emptyList();
			def es = Collections.emptySet();
			def em = Collections.emptyMap();
			def sl = Collections.singletonList("x");
			def sm = Collections.singletonMap("k", "v");
			def d1 = Digest.sha256("abc");
			def d2 = Digest.md5("abc");
			def d3 = Digest.sha1("abc");
			def d4 = Digest.sha384("abc");
			def d5 = Digest.sha512("abc");
			def eb = Encoding.encodeBase64("hi");
			def db = Encoding.decodeBase64(eb);
			def eh = Encoding.encodeHex("hi");
			def dh = Encoding.decodeHex(eh);
			def ub = Base64.getUrlEncoder().encodeToString("hi?".getBytes());
			def udb = Base64.getUrlDecoder().decode(ub);
			def dcs = Charset.defaultCharset();
			def oe = Optional.empty();
			def minByV = [3, 1, 2].stream().collect(Collectors.minBy((x, y) -> Integer.compare(x, y))).orElse(0);
			def maxByV = [3, 1, 2].stream().collect(Collectors.maxBy((x, y) -> Integer.compare(x, y))).orElse(0);
			def mappedCol = ["aa", "b"].stream().collect(Collectors.mapping(s -> s.length(), Collectors.toList()));
			def partCol = [1, 2, 3, 4].stream().collect(Collectors.partitioningBy(x -> x % 2 == 0, Collectors.counting()));
			return [bs1, bs2, fArr[1], cp1.size(), cp2.size(), eq1, eq2, ts1.length() > 0, ts2.length() > 0, asSum, isArr, dsArr, empIS.getCount(), empDS.getCount(), lc.size(), sc.size(), mc.size(), el.size(), es.size(), em.size(), sl.size(), sm.size(), d1.length() > 0 && d2.length() > 0 && d3.length() > 0 && d4.length() > 0 && d5.length() > 0, db, dh, udb, dcs, oe == null, minByV, maxByV, mappedCol.size(), partCol.get("true")];
		`, nil)
		if err != nil {
			t.Fatalf("ArraysCollectionsDigestsAndEncodings failed: %v", err)
		}
		if arr, ok := res.([]any); !ok || len(arr) != 32 {
			t.Fatalf("unexpected ArraysCollectionsDigestsAndEncodings result: %#v", res)
		}
	})
}

func TestRound50PainlessFindings(t *testing.T) {
	t.Run("F20_MethodReferencesStreamTakeDropWhileAndOptional", func(t *testing.T) {
		res, err := Eval(nil, `
			List<String> raw = ["  Alpha ", null, "BETA", "  gamma "];
			List<String> cleaned = raw.stream()
				.filter(Objects::nonNull)
				.map(String::trim)
				.map(String::toLowerCase)
				.collect(Collectors.toList());

			int sumParsed = ["10", "20", "30"].stream()
				.mapToInt(Integer::parseInt)
				.sum();

			int redSum = [1, 2, 3, 4].stream()
				.reduce(0, Integer::sum);

			List<Integer> taken = [1, 2, 3, 10, 4, 5].stream()
				.takeWhile(x -> x < 5)
				.collect(Collectors.toList());

			List<Integer> dropped = [1, 2, 3, 10, 4, 5].stream()
				.dropWhile(x -> x < 5)
				.collect(Collectors.toList());

			int flatSum = [[1, 2], [3, 4]].stream()
				.flatMapToInt(List::stream)
				.sum();

			List<String> words = ["bb", "a", "ccc"];
			words.sort(Comparator.comparingInt(String::length).reversed());

			List<String> mutList = ["a", null, "b"];
			mutList.removeIf(Objects::isNull);
			mutList.replaceAll(String::toUpperCase);

			Map<String, List<String>> grouped = new HashMap();
			grouped.computeIfAbsent("k", ArrayList::new).add("v1");
			Map<String, Integer> counts = new HashMap();
			counts.merge("hits", 2, Integer::sum);
			counts.merge("hits", 3, Integer::sum);

			def log = [];
			Optional.of("present").ifPresentOrElse(log::add, () -> log.add("empty"));
			Optional.empty().ifPresentOrElse(log::add, () -> log.add("fallback_action"));
			String orVal = Optional.empty().or(() -> Optional.of("recovered")).orElse("none");
			List<String> optStreamList = Optional.of("item").stream().map(String::toUpperCase).collect(Collectors.toList());

			return [
				String.join(",", cleaned),
				sumParsed,
				redSum,
				taken.size(),
				dropped.size(),
				flatSum,
				String.join(",", words),
				String.join(",", mutList),
				grouped.get("k").get(0),
				counts.get("hits"),
				String.join(",", log),
				orVal,
				optStreamList.get(0)
			];
		`, nil)
		if err != nil {
			t.Fatalf("F20 Eval failed: %v", err)
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != 13 {
			t.Fatalf("unexpected F20 result: %#v", res)
		}
		if arr[0] != "alpha,beta,gamma" ||
			arr[1] != int64(60) ||
			arr[2] != int64(10) ||
			arr[3] != int64(3) ||
			arr[4] != int64(3) ||
			arr[5] != int64(10) ||
			arr[6] != "ccc,bb,a" ||
			arr[7] != "A,B" ||
			arr[8] != "v1" ||
			arr[9] != int64(5) ||
			arr[10] != "present,fallback_action" ||
			arr[11] != "recovered" ||
			arr[12] != "ITEM" {
			t.Fatalf("unexpected F20 values: %#v", arr)
		}
	})

	t.Run("F21_LocalTimeAndTemporalBridges", func(t *testing.T) {
		res, err := Eval(nil, `
			LocalTime t1 = LocalTime.of(14, 30, 15);
			LocalTime t2 = LocalTime.parse("09:05");
			LocalTime t3 = t2.plusHours(2).plusMinutes(10).withSecond(30);
			int secOfDay = t1.toSecondOfDay();
			long nanoOfDay = LocalTime.of(0, 0, 1, 500).toNanoOfDay();
			LocalTime fromSec = LocalTime.ofSecondOfDay(3661);
			LocalDate d = LocalDate.of(2025, 3, 15);
			String dt1 = d.atTime(t2);
			String dt2 = d.atTime(18, 45);
			String dt3 = t1.atDate(d);
			String dt4 = LocalDateTime.of(d, t1);
			String sod = d.atStartOfDay();
			LocalTime extracted = ZonedDateTime.parse("2025-03-15T16:20:00Z").toLocalTime();
			boolean isLt = t1 instanceof LocalTime;
			return [
				t1.toString(),
				t2.toString(),
				t3.toString(),
				secOfDay,
				nanoOfDay,
				fromSec.toString(),
				dt1,
				dt2,
				dt3,
				dt4,
				sod,
				extracted.toString(),
				LocalTime.MIDNIGHT,
				LocalTime.NOON,
				isLt
			];
		`, nil)
		if err != nil {
			t.Fatalf("F21 Eval failed: %v", err)
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != 15 {
			t.Fatalf("unexpected F21 result: %#v", res)
		}
		if arr[0] != "14:30:15" ||
			arr[1] != "09:05" ||
			arr[2] != "11:15:30" ||
			arr[3] != int64(52215) ||
			arr[4] != int64(1_000_000_500) ||
			arr[5] != "01:01:01" ||
			arr[6] != "2025-03-15T09:05" ||
			arr[7] != "2025-03-15T18:45" ||
			arr[8] != "2025-03-15T14:30:15" ||
			arr[9] != "2025-03-15T14:30:15" ||
			arr[10] != "2025-03-15T00:00" ||
			arr[11] != "16:20" ||
			arr[12] != "00:00" ||
			arr[13] != "12:00" ||
			arr[14] != true {
			t.Fatalf("unexpected F21 values: %#v", arr)
		}
	})

	t.Run("F22_BigDecimalAndRoundingMode", func(t *testing.T) {
		res, err := Eval(nil, `
			BigDecimal price = new BigDecimal("19.99");
			BigDecimal tax = price.multiply(new BigDecimal("0.0825")).setScale(2, RoundingMode.HALF_UP);
			BigDecimal total = price.add(tax);
			BigDecimal q = new BigDecimal("10").divide(new BigDecimal("3"), 4, RoundingMode.HALF_UP);
			BigDecimal stripped = new BigDecimal("12.3400").stripTrailingZeros();
			BigDecimal viaVal = BigDecimal.valueOf(12345, 2);
			int cmp = total.compareTo(new BigDecimal("21.64"));
			boolean isBd = total instanceof BigDecimal && total instanceof Number;
			return [
				tax.toPlainString(),
				total.toString(),
				total.doubleValue(),
				q.toPlainString(),
				stripped.toPlainString(),
				viaVal.toPlainString(),
				total.scale(),
				total.precision(),
				total.signum(),
				cmp,
				BigDecimal.TEN.subtract(BigDecimal.ONE).intValue(),
				isBd
			];
		`, nil)
		if err != nil {
			t.Fatalf("F22 Eval failed: %v", err)
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != 12 {
			t.Fatalf("unexpected F22 result: %#v", res)
		}
		if arr[0] != "1.65" ||
			arr[1] != "21.64" ||
			arr[2] != float64(21.64) ||
			arr[3] != "3.3333" ||
			arr[4] != "12.34" ||
			arr[5] != "123.45" ||
			arr[6] != int64(2) ||
			arr[7] != int64(4) ||
			arr[8] != int64(1) ||
			arr[9] != int64(0) ||
			arr[10] != int64(9) ||
			arr[11] != true {
			t.Fatalf("unexpected F22 values: %#v", arr)
		}
	})

	t.Run("F23_NumericWrapperStaticMethodsAndConstants", func(t *testing.T) {
		res, err := Eval(nil, `
			int bc = Integer.bitCount(255);
			long lbc = Long.bitCount(255L);
			int hob = Integer.highestOneBit(20);
			int lob = Integer.lowestOneBit(20);
			int nlz = Integer.numberOfLeadingZeros(1);
			int ntz = Integer.numberOfTrailingZeros(8);
			int rotL = Integer.rotateLeft(1, 4);
			int rotR = Integer.rotateRight(16, 2);
			int sgn = Integer.signum(-42);
			int decHex = Integer.decode("0xFF");
			int decHash = Integer.decode("#10");
			boolean nanCheck = Double.isNaN(Double.NaN);
			boolean infCheck = Double.isInfinite(Double.POSITIVE_INFINITY);
			boolean finCheck = Double.isFinite(42.5) && !Double.isFinite(Double.NEGATIVE_INFINITY);
			return [
				bc, lbc, hob, lob, nlz, ntz, rotL, rotR, sgn, decHex, decHash,
				nanCheck, infCheck, finCheck,
				Integer.BYTES, Long.SIZE, Short.MAX_VALUE, Byte.MIN_VALUE
			];
		`, nil)
		if err != nil {
			t.Fatalf("F23 Eval failed: %v", err)
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != 18 {
			t.Fatalf("unexpected F23 result: %#v", res)
		}
		if arr[0] != int64(8) ||
			arr[1] != int64(8) ||
			arr[2] != int64(16) ||
			arr[3] != int64(4) ||
			arr[4] != int64(31) ||
			arr[5] != int64(3) ||
			arr[6] != int64(16) ||
			arr[7] != int64(4) ||
			arr[8] != int64(-1) ||
			arr[9] != int64(255) ||
			arr[10] != int64(16) ||
			arr[11] != true ||
			arr[12] != true ||
			arr[13] != true ||
			arr[14] != int64(4) ||
			arr[15] != int64(64) ||
			arr[16] != int64(32767) ||
			arr[17] != int64(-128) {
			t.Fatalf("unexpected F23 values: %#v", arr)
		}
	})

	t.Run("F26_ParamsSourceRawUnflattenedNestedArrayAccess", func(t *testing.T) {
		rawNested := map[string]any{
			"items": []any{
				map[string]any{"price": int64(10), "qty": int64(2)},
				map[string]any{"price": int64(5), "qty": int64(3)},
			},
		}
		flattenedDoc := map[string]any{
			"items.price":  []any{int64(10), int64(5)},
			"items.qty":    []any{int64(2), int64(3)},
			"__raw_source": rawNested,
		}
		res, err := Eval(flattenedDoc, `
			int total = 0;
			for (def item : params._source.items) {
				total += item.price * item.qty;
			}
			return total + params._source['items'][0]['price'];
		`, nil)
		if err != nil {
			t.Fatalf("F26 Eval failed: %v", err)
		}
		if res != int64(45) {
			t.Fatalf("expected 45 from params._source.items loop, got %#v", res)
		}
	})

	t.Run("F20_F21_F22_F23_ExtendedBranchCoverage", func(t *testing.T) {
		res, err := Eval(nil, `
			BigDecimal a = new BigDecimal(100);
			BigDecimal b = new BigDecimal(12.5);
			BigDecimal c = new BigDecimal("+1.25e2");
			BigDecimal d = new BigDecimal("-0.005");
			BigDecimal z = new BigDecimal("0.00").stripTrailingZeros();
			BigDecimal negScale = new BigDecimal("100").stripTrailingZeros();
			BigDecimal sUp = new BigDecimal("1.234").setScale(2, RoundingMode.UP);
			BigDecimal sDown = new BigDecimal("1.239").setScale(2, RoundingMode.DOWN);
			BigDecimal sCeil = new BigDecimal("-1.234").setScale(2, RoundingMode.CEILING);
			BigDecimal sFloor = new BigDecimal("-1.234").setScale(2, RoundingMode.FLOOR);
			BigDecimal sHalfDown = new BigDecimal("1.235").setScale(2, RoundingMode.HALF_DOWN);
			BigDecimal sHalfEven = new BigDecimal("1.225").setScale(2, RoundingMode.HALF_EVEN);
			BigDecimal sUnnec = new BigDecimal("1.20").setScale(1, RoundingMode.UNNECESSARY);
			BigDecimal sSame = sUnnec.setScale(1, RoundingMode.HALF_UP);
			BigDecimal sWider = sUnnec.setScale(3, RoundingMode.HALF_UP);
			List<String> Modes = new ArrayList();
			for (int i = 0; i < 8; i++) {
				Modes.add(RoundingMode.valueOf(i));
			}
			BigDecimal alignedSum = new BigDecimal("1.2").add(new BigDecimal("3.456")).add(new BigDecimal("0.1"));
			BigDecimal rem = new BigDecimal("10.5").remainder(new BigDecimal("3"));
			BigDecimal p = new BigDecimal("1.5").pow(2);
			BigDecimal mn = a.min(b);
			BigDecimal mx = a.max(b);
			long lv = negScale.longValue() + sWider.longValue();
			double fv = d.floatValue();
			BigDecimal absD = d.abs();
			BigDecimal negD = d.negate();
			BigDecimal plusD = d.plus();

			def optList = Optional.empty().orElseGet(ArrayList::new);
			def optMap = Optional.empty().orElseGet(HashMap::new);
			def optSet = Optional.empty().orElseGet(HashSet::new);
			def optSb = Optional.empty().orElseGet(StringBuilder::new);
			def optStr = Optional.empty().orElseGet(String::new);

			def parsedLongs = ["10", "20"].stream().map(Long::parseLong).collect(Collectors.toList());
			def parsedDoubles = ["1.5", "2.5"].stream().map(Double::parseDouble).collect(Collectors.toList());
			def parsedFloats = ["1.5"].stream().map(Float::parseFloat).collect(Collectors.toList());
			def parsedShorts = ["5"].stream().map(Short::parseShort).collect(Collectors.toList());
			def parsedBytes = ["3"].stream().map(Byte::parseByte).collect(Collectors.toList());
			def parsedBools = ["true", "false"].stream().map(Boolean::parseBoolean).collect(Collectors.toList());
			def parsedBds = ["1.25", "2.75"].stream().map(BigDecimal::new).collect(Collectors.toList());
			def bdValOf = [10, 20].stream().map(BigDecimal::valueOf).reduce(BigDecimal.ZERO, BigDecimal::add);
			def nullCnt = [null, "a", null].stream().filter(Objects::isNull).count();
			def strVals = [1, 2].stream().map(String::valueOf).map(Objects::toString).collect(Collectors.toList());
			def absVals = [-5, 3].stream().map(Math::abs).collect(Collectors.toList());
			def longSum = [10L, 20L].stream().reduce(0L, Long::sum);
			def dblSum = [1.5, 2.5].stream().reduce(0.0, Double::sum);
			def minVal = [5, 2, 8].stream().reduce(99, Math::min);
			def catStr = ["a", "b", "c"].stream().reduce("", String::concat);
			def words = ["b", "A", "c"];
			words.sort(String::compareToIgnoreCase);
			def nums = [3, 1, 2];
			nums.sort(Integer::compare);

			long wSum = Integer.sum(1, 2) + Long.sum(3L, 4L) + Integer.max(1, 5) + Long.max(2L, 6L) + Integer.min(1, 5) + Long.min(2L, 6L);
			double dSum = Double.sum(1.0, 2.0) + Float.sum(1.0, 2.0) + Double.max(1.0, 5.0) + Double.min(1.0, 5.0);
			long bitOps = Long.highestOneBit(32L) + Long.lowestOneBit(24L) + Long.numberOfLeadingZeros(1L) + Long.numberOfTrailingZeros(16L) +
				Long.rotateLeft(1L, 2) + Long.rotateRight(8L, 1) + Integer.reverse(1) + Long.reverse(1L) +
				Integer.reverseBytes(256) + Long.reverseBytes(256L) + Short.reverseBytes(256) + Long.signum(-5L) +
				Long.decode("-0x10") + Short.decode("010") + Byte.decode("+12");

			LocalTime ltNano = LocalTime.of(14, 30, 15, 123000000);
			LocalTime ltNow = LocalTime.now(ZoneId.of("UTC"));
			String ltMax = LocalTime.MAX;

			return [
				d.toPlainString(), z.toPlainString(), negScale.toPlainString(),
				sUp.toPlainString(), sDown.toPlainString(), sCeil.toPlainString(), sFloor.toPlainString(),
				sHalfDown.toPlainString(), sHalfEven.toPlainString(), sSame.toPlainString(), sWider.toPlainString(),
				Modes.size(), alignedSum.toPlainString(), rem.toPlainString(), p.toPlainString(),
				mn.toPlainString(), mx.toPlainString(), lv, fv < 0, absD.toPlainString(), negD.toPlainString(), plusD.toPlainString(),
				optList.size(), optMap.size(), optSet.size(), optSb.length(), optStr.length(),
				parsedLongs.size(), parsedDoubles.size(), parsedFloats.size(), parsedShorts.size(), parsedBytes.size(), parsedBools.size(), parsedBds.size(),
				bdValOf.toPlainString(), nullCnt, strVals.size(), absVals[0], longSum, dblSum, minVal, catStr, words[0], nums[0],
				wSum > 0, dSum > 0, bitOps != 0, ltNano.startsWith("14:30:15"), ltNow.length() >= 5, ltMax.startsWith("23:59:59")
			];
		`, nil)
		if err != nil {
			t.Fatalf("Extended branch coverage Eval failed: %v", err)
		}
		if arr, ok := res.([]any); !ok || len(arr) == 0 {
			t.Fatalf("unexpected extended result: %#v", res)
		}

		// Also test ApplyUpdate JSON marshaling of BigDecimal, StringBuilder, and Period
		updated, err := ApplyUpdate(json.RawMessage(`{"x": 1}`), &UpdateRequest{
			Script: &ScriptSpec{
				Source: `
					ctx._source.bd = new BigDecimal("42.50");
					ctx._source.sb = new StringBuilder("hello").append("!");
					ctx._source.per = Period.ofDays(3);
				`,
			},
		})
		if err != nil || !strings.Contains(string(updated), "42.50") || !strings.Contains(string(updated), "hello!") || !strings.Contains(string(updated), "P3D") {
			t.Fatalf("ApplyUpdate MarshalJSON failed: %s err=%v", string(updated), err)
		}
	})
}
