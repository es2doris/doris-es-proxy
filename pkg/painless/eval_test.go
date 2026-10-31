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
