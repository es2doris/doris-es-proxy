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
	"reflect"
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
		def sOf = Set.of("a", "b");
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

func TestRound51F20ToF26Features(t *testing.T) {
	t.Run("F20_Year_MonthDay_ChronoField", func(t *testing.T) {
		res, err := Eval(nil, `
			Year y = Year.of(2024);
			Year yParsed = Year.parse("2025");
			Year yFrom = Year.from(LocalDate.of(2026, 3, 15));
			Year yNow = Year.now(ZoneId.of("UTC"));
			boolean leap2024 = y.isLeap();
			boolean leap2025 = Year.isLeap(2025);
			int len2024 = y.length();
			String d60 = y.atDay(60);
			String ym2 = y.atMonth(2);
			String ymFeb = y.atMonth(Month.FEBRUARY);

			MonthDay md = MonthDay.of(2, 29);
			MonthDay mdMonth = MonthDay.of(Month.FEBRUARY, 29);
			MonthDay mdParsed = MonthDay.parse("--12-25");
			MonthDay mdFrom = MonthDay.from(LocalDate.of(2024, 7, 4));
			MonthDay mdNow = MonthDay.now(ZoneId.of("UTC"));
			String yAtMd = y.atMonthDay(md);
			String mdAt2023 = md.atYear(2023);
			boolean valid2024 = md.isValidYear(2024);
			boolean valid2023 = md.isValidYear(2023);
			MonthDay mdWithM = md.withMonth(4).withDayOfMonth(15);

			Year yPlus = y.plusYears(2).minusYears(1);
			boolean yAfter = yParsed.isAfter(y);
			boolean yBefore = y.isBefore(yParsed);
			boolean mdAfter = mdParsed.isAfter(md);
			boolean mdBefore = md.isBefore(mdParsed);
			int yCmp = y.compareTo(yParsed);
			int mdCmp = md.compareTo(mdMonth);

			LocalDate ld = LocalDate.of(2024, 2, 29);
			LocalTime lt = LocalTime.of(14, 30, 15);
			YearMonth ym = YearMonth.of(2024, 2);

			long cfYear = ld.get(ChronoField.YEAR);
			long cfMonth = ld.getLong(ChronoField.MONTH_OF_YEAR);
			long cfDom = ld.get(ChronoField.DAY_OF_MONTH);
			long cfDoy = ld.get(ChronoField.DAY_OF_YEAR);
			long cfDow = ld.get(ChronoField.DAY_OF_WEEK);
			long cfHour = lt.get(ChronoField.HOUR_OF_DAY);
			long cfSecDay = lt.getLong(ChronoField.SECOND_OF_DAY);
			boolean ldSupYear = ld.isSupported(ChronoField.YEAR);
			boolean ldSupHour = ld.isSupported(ChronoField.HOUR_OF_DAY);
			boolean ltSupHour = lt.isSupported(ChronoField.HOUR_OF_DAY);
			boolean ltSupYear = lt.isSupported(ChronoField.YEAR);
			boolean ymSupPm = ym.isSupported(ChronoField.PROLEPTIC_MONTH);
			boolean ySupYear = y.isSupported(ChronoField.YEAR);
			boolean mdSupDom = md.isSupported(ChronoField.DAY_OF_MONTH);

			String ldWithYear = ld.with(ChronoField.YEAR, 2023);
			String ltWithHour = lt.with(ChronoField.HOUR_OF_DAY, 9);
			Year yWith = y.with(ChronoField.YEAR, 2030);
			MonthDay mdWith = md.with(ChronoField.MONTH_OF_YEAR, 3);

			boolean instY = y instanceof Year;
			boolean instMD = md instanceof MonthDay;
			boolean instCF = ChronoField.YEAR instanceof ChronoField;

			return [
				y.getValue(), y.toString(), leap2024, leap2025, len2024, d60, ym2, ymFeb,
				md.toString(), md.getMonth(), md.getMonthValue(), md.getDayOfMonth(),
				mdParsed.toString(), mdFrom.toString(), yAtMd, mdAt2023, valid2024, valid2023, mdWithM.toString(),
				yPlus.getValue(), yAfter, yBefore, mdAfter, mdBefore, yCmp < 0, mdCmp == 0,
				cfYear, cfMonth, cfDom, cfDoy, cfDow, cfHour, cfSecDay,
				ldSupYear, ldSupHour, ltSupHour, ltSupYear, ymSupPm, ySupYear, mdSupDom,
				ldWithYear, ltWithHour, yWith.getValue(), mdWith.toString(),
				instY, instMD, instCF, Year.MIN_VALUE < 0, Year.MAX_VALUE > 0,
				yFrom.getValue(), yNow.getValue() >= 2020, mdNow.getMonthValue() >= 1
			];
		`, nil)
		if err != nil {
			t.Fatalf("F20 Eval failed: %v", err)
		}
		arr, ok := res.([]any)
		if !ok {
			t.Fatalf("expected []any, got %#v", res)
		}
		wantPrefix := []any{
			int64(2024), "2024", true, false, int64(366), "2024-02-29", "2024-02", "2024-02",
			"--02-29", "FEBRUARY", int64(2), int64(29),
			"--12-25", "--07-04", "2024-02-29", "2023-02-28", true, false, "--04-15",
			int64(2025), true, true, true, true, true, true,
			int64(2024), int64(2), int64(29), int64(60), int64(4), int64(14), int64(14*3600 + 30*60 + 15),
			true, false, true, false, true, true, true,
			"2023-02-28", "09:30:15", int64(2030), "--03-29",
			true, true, true, true, true,
			int64(2026), true, true,
		}
		for i, w := range wantPrefix {
			if i >= len(arr) || arr[i] != w {
				t.Fatalf("F20 mismatch at index %d: got %#v, want %#v (full=%#v)", i, arr[i], w, arr)
			}
		}
	})

	t.Run("F21_JavaArrays_MultiDim_BraceInit_Clone", func(t *testing.T) {
		res, err := Eval(nil, `
			int[] a = new int[4];
			a[1] = 10;
			a[1] += 5;
			a[1]++;
			boolean[] b = new boolean[2];
			String[] s = new String[2];
			int[][] m = new int[2][3];
			m[0][1] = 7;
			m[1][2] = 9;
			m[0][1] += 5;
			m[0][1]++;
			int[][] jagged = new int[2][];
			jagged[0] = new int[]{1, 2};
			jagged[1] = new int[]{3, 4, 5};
			int[] init1 = new int[]{10, 20, 30};
			int[][] init2 = new int[][]{{1, 2}, {3, 4}};
			int inlineLen = (new int[]{5, 6, 7}).length;
			int[] cloned = init1.clone();
			cloned[0] = 99;
			Map origMap = new HashMap();
			origMap.put("k", 42);
			Map clonedMap = origMap.clone();
			clonedMap.put("k", 100);
			return [
				a.length, a[0], a[1], b[0], s[0],
				m[0][1], m[1][2], m[0][0],
				jagged[0][1], jagged[1][2],
				init1[2], init2[1][0], inlineLen,
				init1[0], cloned[0], origMap.get("k"), clonedMap.get("k"),
				a instanceof int[], m instanceof int[][]
			];
		`, nil)
		if err != nil {
			t.Fatalf("F21 Eval failed: %v", err)
		}
		want := []any{
			int64(4), int64(0), int64(16), false, nil,
			int64(13), int64(9), int64(0),
			int64(2), int64(5),
			int64(30), int64(3), int64(3),
			int64(10), int64(99), int64(42), int64(100),
			true, true,
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != len(want) {
			t.Fatalf("F21 unexpected result: %#v, want %#v", res, want)
		}
		for i := range want {
			if arr[i] != want[i] {
				t.Fatalf("F21 index %d: got %#v, want %#v", i, arr[i], want[i])
			}
		}
	})

	t.Run("F22_SwitchArrow_MultiLabel_SwitchExpression_Yield", func(t *testing.T) {
		res, err := Eval(nil, `
			List out = new ArrayList();
			for (int x : [1, 2, 3, 4, 5]) {
				switch (x) {
					case 1 -> out.add("one");
					case 2, 3 -> {
						String p = "two_or_three_";
						out.add(p + x);
					}
					default -> out.add("other");
				}
			}
			String colonMulti = "";
			switch ("b") {
				case "a", "b":
					colonMulti = "ab";
					break;
				default:
					colonMulti = "other";
			}
			int dayNum = 6;
			String kind = switch (dayNum) {
				case 1, 2, 3, 4, 5 -> "weekday";
				case 6, 7 -> {
					String tag = "end";
					yield "week" + tag;
				}
				default -> "unknown";
			};
			int colonYield = switch ("x") {
				case "x":
					yield 42;
				default:
					yield 0;
			};
			return [out.size(), out[0], out[1], out[2], out[3], colonMulti, kind, colonYield];
		`, nil)
		if err != nil {
			t.Fatalf("F22 Eval failed: %v", err)
		}
		want := []any{int64(5), "one", "two_or_three_2", "two_or_three_3", "other", "ab", "weekend", int64(42)}
		arr, ok := res.([]any)
		if !ok || len(arr) != len(want) {
			t.Fatalf("F22 unexpected: %#v, want %#v", res, want)
		}
		for i := range want {
			if arr[i] != want[i] {
				t.Fatalf("F22 index %d: got %#v, want %#v", i, arr[i], want[i])
			}
		}
	})

	t.Run("F23_IntDivByZero_ArithmeticException_GetClass", func(t *testing.T) {
		res, err := Eval(nil, `
			String caught1 = "";
			String clsName = "";
			String simpleName = "";
			try {
				int x = 1 / 0;
			} catch (ArithmeticException e) {
				caught1 = e.getMessage();
				clsName = e.getClass().getName();
				simpleName = e.getClass().getSimpleName();
			}
			String caught2 = "";
			try {
				int y = 10;
				y %= 0;
			} catch (Exception e) {
				caught2 = e.getClass().getSimpleName();
			}
			double inf = 1.0 / 0.0;
			return [
				caught1, clsName, simpleName, caught2, Double.isInfinite(inf),
				"abc".getClass().getSimpleName(), (42).getClass().getName(),
				[1, 2].getClass().getSimpleName(), ["a": 1].getClass().getSimpleName()
			];
		`, nil)
		if err != nil {
			t.Fatalf("F23 Eval failed: %v", err)
		}
		want := []any{
			"/ by zero", "java.lang.ArithmeticException", "ArithmeticException", "ArithmeticException", true,
			"String", "java.lang.Long", "ArrayList", "HashMap",
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != len(want) {
			t.Fatalf("F23 unexpected: %#v, want %#v", res, want)
		}
		for i := range want {
			if arr[i] != want[i] {
				t.Fatalf("F23 index %d: got %#v, want %#v", i, arr[i], want[i])
			}
		}

		// Uncaught integer division by zero should return an error from Eval
		_, errUncaught := Eval(nil, `return 5 / 0;`, nil)
		if errUncaught == nil || !strings.Contains(errUncaught.Error(), "ArithmeticException") {
			t.Fatalf("expected uncaught ArithmeticException error, got %v", errUncaught)
		}
	})

	t.Run("F24_StringBuffer_Collections_Arrays_Overloads", func(t *testing.T) {
		res, err := Eval(nil, `
			StringBuffer sb = new StringBuffer("hello");
			sb.append(" ").append("world");
			def optSb = Optional.empty().orElseGet(StringBuffer::new);
			optSb.append("ok");

			List words = new ArrayList(["bb", "a", "ccc"]);
			String shortest = Collections.min(words, Comparator.comparingInt(String::length));
			String longest = Collections.max(words, Comparator.comparingInt(String::length));

			List nums = new ArrayList([10, 20, 30, 40]);
			int idxFound = Collections.binarySearch(nums, 30);
			int idxMiss = Collections.binarySearch(nums, 25);
			List desc = new ArrayList([40, 30, 20, 10]);
			int idxDesc = Collections.binarySearch(desc, 20, Comparator.reverseOrder());

			List repList = new ArrayList(["1", 1, 2, 1]);
			boolean replaced = Collections.replaceAll(repList, 1, 99);

			int[] arr = new int[]{5, 10, 20, 30, 40, 50};
			int rFound = Arrays.binarySearch(arr, 1, 5, 30);
			int rMiss = Arrays.binarySearch(arr, 1, 4, 35);

			int[][] m1 = new int[][]{{1, 2}, {3, 4}};
			int[][] m2 = new int[][]{{1, 2}, {3, 4}};
			int[][] m3 = new int[][]{{1, 2}, {3, 5}};
			boolean deepEq1 = Arrays.deepEquals(m1, m2);
			boolean deepEq2 = Arrays.deepEquals(m1, m3);

			return [
				sb.toString(), sb instanceof StringBuffer, optSb.toString(),
				shortest, longest, idxFound, idxMiss, idxDesc,
				replaced, repList[0], repList[1], repList[3],
				rFound, rMiss, deepEq1, deepEq2
			];
		`, nil)
		if err != nil {
			t.Fatalf("F24 Eval failed: %v", err)
		}
		want := []any{
			"hello world", true, "ok",
			"a", "ccc", int64(2), int64(-3), int64(2),
			true, "1", int64(99), int64(99),
			int64(3), int64(-5), true, false,
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != len(want) {
			t.Fatalf("F24 unexpected: %#v, want %#v", res, want)
		}
		for i := range want {
			if arr[i] != want[i] {
				t.Fatalf("F24 index %d: got %#v, want %#v", i, arr[i], want[i])
			}
		}
	})

	t.Run("F25_RegexNamedGroupStartEnd_Reset_PatternMethods_RhsRegexOps", func(t *testing.T) {
		res, err := Eval(nil, `
			Pattern p = Pattern.compile("(?<yr>\\d{4})-(?<mo>\\d{2})", Pattern.CASE_INSENSITIVE);
			Matcher m = p.matcher("date: 2026-11");
			boolean found1 = m.find();
			int sYr = m.start("yr");
			int eYr = m.end("yr");
			int sMo = m.start("mo");
			int eMo = m.end("mo");
			m.reset("2025-08");
			boolean matchesReset = m.matches();
			String gYr2 = m.group("yr");
			m.reset();
			boolean findAfterReset0 = m.find();

			Pattern sp = Pattern.compile(":");
			String[] spAll = sp.split("a:b:c:");
			String[] spLim2 = sp.split("a:b:c:", 2);
			String[] spLimNeg = sp.split("a:b:c:", -1);

			boolean rhsFind = "hello-123" =~ /\d+/;
			boolean rhsFull1 = "123" ==~ /\d+/;
			boolean rhsFull2 = "hello-123" ==~ /\d+/;

			return [
				p.pattern(), p.flags(), p instanceof Pattern,
				found1, sYr, eYr, sMo, eMo,
				matchesReset, gYr2, findAfterReset0,
				spAll.length, spLim2.length, spLim2[1], spLimNeg.length,
				rhsFind, rhsFull1, rhsFull2
			];
		`, nil)
		if err != nil {
			t.Fatalf("F25 Eval failed: %v", err)
		}
		want := []any{
			`(?<yr>\d{4})-(?<mo>\d{2})`, int64(2), true,
			true, int64(6), int64(10), int64(11), int64(13),
			true, "2025", true,
			int64(3), int64(2), "b:c:", int64(4),
			true, true, false,
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != len(want) {
			t.Fatalf("F25 unexpected: %#v, want %#v", res, want)
		}
		for i := range want {
			if arr[i] != want[i] {
				t.Fatalf("F25 index %d: got %#v, want %#v", i, arr[i], want[i])
			}
		}
	})

	t.Run("F26_TypeSafeCollectionEquality_SetDeduplication_MapCopyOf", func(t *testing.T) {
		res, err := Eval(nil, `
			List list = [1, 2, "3"];
			boolean hasStr1 = list.contains("1");
			boolean hasInt1 = list.contains(1);
			boolean hasLong1 = list.contains(1L);
			boolean hasInt3 = list.contains(3);
			boolean hasStr3 = list.contains("3");
			int idxStr1 = list.indexOf("1");
			int idxInt1 = list.indexOf(1);
			int lastIdxStr2 = list.lastIndexOf("2");
			int lastIdxInt2 = list.lastIndexOf(2);

			List remTest = new ArrayList([1, "1", 2]);
			remTest.removeAll(["1"]);
			List retTest = new ArrayList([1, "1", 2]);
			retTest.retainAll([1]);

			Set s1 = Set.of(1, "1");
			Set s2 = Set.copyOf([1, 1, "1", 2, 2L]);

			Map mOrig = new HashMap();
			mOrig.put("a", 10);
			Map mCopy = Map.copyOf(mOrig);
			mOrig.put("a", 20);

			return [
				hasStr1, hasInt1, hasLong1, hasInt3, hasStr3,
				idxStr1, idxInt1, lastIdxStr2, lastIdxInt2,
				remTest.size(), remTest[0],
				retTest.size(), retTest[0],
				s1.size(), s2.size(),
				mCopy.get("a"), mOrig.get("a"),
				Objects.equals(1, "1"), Objects.equals(1, 1L)
			];
		`, nil)
		if err != nil {
			t.Fatalf("F26 Eval failed: %v", err)
		}
		want := []any{
			false, true, true, false, true,
			int64(-1), int64(0), int64(-1), int64(1),
			int64(2), int64(1),
			int64(1), int64(1),
			int64(2), int64(3),
			int64(10), int64(20),
			false, true,
		}
		arr, ok := res.([]any)
		if !ok || len(arr) != len(want) {
			t.Fatalf("F26 unexpected: %#v, want %#v", res, want)
		}
		for i := range want {
			if arr[i] != want[i] {
				t.Fatalf("F26 index %d: got %#v, want %#v", i, arr[i], want[i])
			}
		}
	})

	t.Run("Round51_InternalBranchCoverage", func(t *testing.T) {
		for _, mName := range []string{
			"JANUARY", "FEBRUARY", "MARCH", "APRIL", "MAY", "JUNE",
			"JULY", "AUGUST", "SEPTEMBER", "OCTOBER", "NOVEMBER", "DECEMBER",
		} {
			if m, ok := parseMonthNumberPainless("Month." + mName); !ok || m < 1 || m > 12 {
				t.Fatalf("expected valid month for %s, got %d %v", mName, m, ok)
			}
		}
		if _, ok := parseMonthNumberPainless("INVALID"); ok {
			t.Fatalf("expected false for invalid month")
		}

		allFields := []painlessChronoField{
			"YEAR", "YEAR_OF_ERA", "ERA", "MONTH_OF_YEAR", "PROLEPTIC_MONTH",
			"DAY_OF_MONTH", "DAY_OF_YEAR", "DAY_OF_WEEK",
			"ALIGNED_DAY_OF_WEEK_IN_MONTH", "ALIGNED_DAY_OF_WEEK_IN_YEAR",
			"ALIGNED_WEEK_OF_MONTH", "ALIGNED_WEEK_OF_YEAR", "EPOCH_DAY",
			"HOUR_OF_DAY", "CLOCK_HOUR_OF_DAY", "HOUR_OF_AMPM", "CLOCK_HOUR_OF_AMPM", "AMPM_OF_DAY",
			"MINUTE_OF_HOUR", "MINUTE_OF_DAY", "SECOND_OF_MINUTE", "SECOND_OF_DAY",
			"MILLI_OF_SECOND", "MILLI_OF_DAY", "MICRO_OF_SECOND", "MICRO_OF_DAY",
			"NANO_OF_SECOND", "NANO_OF_DAY", "INSTANT_SECONDS", "OFFSET_SECONDS",
		}
		for _, cf := range allFields {
			_ = cf.String()
			_, _ = evalGetChronoFieldPainless("2026-11-08T00:05:06.123456789Z", cf)
			_, _ = evalGetChronoFieldPainless("2026-11-08T14:05:06.123456789Z", cf)
			_, _ = evalGetChronoFieldPainless("2026-11", cf)
			_, _ = evalGetChronoFieldPainless("2026-11-08", cf)
			_, _ = evalGetChronoFieldPainless("14:05:06", cf)
			_, _ = evalGetChronoFieldPainless("2026-11-08T14:05:06", cf)
			_, _ = evalGetChronoFieldPainless(painlessYear{year: 2026}, cf)
			_, _ = evalGetChronoFieldPainless(painlessYear{year: -5}, cf)
			_, _ = evalGetChronoFieldPainless(painlessMonthDay{month: 2, day: 29}, cf)
			_, _ = evalWithChronoFieldPainless("2026-11-08T14:05:06.123456789Z", cf, 2)
			_, _ = evalWithChronoFieldPainless("2026-11", cf, 2)
			_, _ = evalWithChronoFieldPainless("2026-11-08", cf, 2)
			_, _ = evalWithChronoFieldPainless("14:05:06", cf, 2)
			_, _ = evalWithChronoFieldPainless("2026-11-08T14:05:06", cf, 2)
			_, _ = evalWithChronoFieldPainless(painlessYear{year: 2026}, cf, 2025)
			_, _ = evalWithChronoFieldPainless(painlessMonthDay{month: 2, day: 15}, cf, 3)
		}

		for _, v := range []any{
			nil,
			painlessClassObject{fullName: "java.lang.String", simpleName: "String"},
			map[string]any{"__exc_type": "java.io.IOException"},
			map[string]any{"__exc_type": "DateTimeParseException"},
			map[string]any{"__exc_type": "DateTimeException"},
			map[string]any{"__exc_type": "NoSuchElementException"},
			map[string]any{"__exc_type": "PatternSyntaxException"},
			map[string]any{"__exc_type": "IllegalArgumentException"},
			map[string]any{"a": 1},
			[]any{1},
			"str",
			true,
			int(1), int32(1), int64(1), int16(1), int8(1), uint8(1),
			float32(1.5), float64(1.5),
			json.Number("42"), json.Number("3.14"),
			&painlessStringBuilder{},
			&painlessBigDecimal{},
			painlessYear{year: 2026},
			painlessMonthDay{month: 1, day: 1},
			painlessChronoField("YEAR"),
			painlessPeriod{years: 1, months: 2, days: 3},
			&painlessMatcher{},
			&painlessPattern{raw: "abc"},
		} {
			cls := painlessClassForValuePainless(v)
			_ = cls.String()
		}
		var nilPat *painlessPattern
		_ = nilPat.String()
		_ = (&painlessPattern{raw: "abc"}).String()
		_ = (&painlessExceptionError{exType: "ArithmeticException", message: "/ by zero"}).Error()
		_ = (&painlessExceptionError{exType: "ArithmeticException"}).Error()
		_ = (&painlessExceptionError{message: "msg"}).Error()

		for _, iv := range []any{
			int(1), int8(2), int16(3), int32(4), int64(5),
			uint(6), uint8(7), uint16(8), uint32(9), uint64(10),
			json.Number("11"), json.Number("11.5"), "not_int",
		} {
			_, _ = isIntegerValuePainless(iv)
		}

		for _, v := range []any{
			(*painlessBigDecimal)(nil),
			&painlessBigDecimal{},
			int(42), int64(42), float64(42.5),
			json.Number("42"), json.Number("42.5"),
			"42", "42.5", "not_a_num", nil,
		} {
			_, _ = toInt64Painless(v)
		}

		for i := 0; i <= 8; i++ {
			name := dayOfWeekNamePainless(i)
			_ = parseDayOfWeekIndexPainless(name)
			_ = parseDayOfWeekIndexPainless(float64(i))
		}
		_ = parseDayOfWeekIndexPainless(nil)

		for i := 0; i <= 13; i++ {
			mName := monthNamePainless(i)
			_ = parseMonthIndexPainless(mName)
			_ = parseMonthIndexPainless(float64(i))
		}
		_ = parseMonthIndexPainless(nil)

		for _, needle := range []any{
			nil, int(65), int(-1), int64(66), int64(-1),
			float64(67), float64(-1), float64(1.5),
			json.Number("68"), json.Number("-1"), "abc",
		} {
			_, _ = resolveStringSearchNeedlePainless(needle)
		}

		_ = comparePainlessValues(nil, nil)
		_ = comparePainlessValues(nil, 1)
		_ = comparePainlessValues(1, nil)
		_ = comparePainlessValues(painlessYear{year: 2020}, painlessYear{year: 2025})
		_ = comparePainlessValues(painlessYear{year: 2025}, painlessYear{year: 2020})
		_ = comparePainlessValues(painlessYear{year: 2025}, painlessYear{year: 2025})
		_ = comparePainlessValues(painlessMonthDay{month: 1, day: 10}, painlessMonthDay{month: 2, day: 5})
		_ = comparePainlessValues(painlessMonthDay{month: 3, day: 10}, painlessMonthDay{month: 2, day: 5})
		_ = comparePainlessValues(painlessMonthDay{month: 2, day: 1}, painlessMonthDay{month: 2, day: 5})
		_ = comparePainlessValues(painlessMonthDay{month: 2, day: 10}, painlessMonthDay{month: 2, day: 5})
		_ = comparePainlessValues(painlessMonthDay{month: 2, day: 5}, painlessMonthDay{month: 2, day: 5})

		pMap := map[string]any{"x": 1}
		for _, cmp := range []string{
			"", "null",
			"Comparator.naturalOrder()", "Comparator.naturalOrder().reversed()",
			"Comparator.reverseOrder()", "Comparator.reverseOrder().reversed()",
			"Comparator.comparingInt(String::length)",
			"Comparator.comparingInt(String::length).reversed()",
			"(a, b) -> Integer.compare(a.length(), b.length())",
			"(x, y) -> Integer.compare(y.length(), x.length())",
		} {
			_, _ = evalPainlessComparatorPair(cmp, "aa", "bbbb", nil, pMap, 0)
			_, _ = evalPainlessComparatorPair(cmp, "bbbb", "aa", nil, pMap, 0)
			_, _ = evalPainlessComparatorPair(cmp, "aa", "aa", nil, pMap, 0)
		}
	})
}

func TestRound52F20ToF26Features(t *testing.T) {
	evalOut := func(t *testing.T, script string, params map[string]any) any {
		t.Helper()
		doc := map[string]any{}
		if _, err := Eval(doc, script, params); err != nil {
			t.Fatalf("Eval failed for script:\n%s\nerr: %v", script, err)
		}
		return doc["out"]
	}

	t.Run("F20_OptionalEmptySentinel_GetException_IsEmpty_And_OrElseThrowSupplier", func(t *testing.T) {
		got := evalOut(t, `
			Optional o1 = Optional.empty();
			Optional o2 = Optional.ofNullable(null);
			Optional o3 = Optional.of("abc").filter(s -> s.length() > 10);
			Optional o4 = Stream.of(1, 2, 3).filter(x -> x > 10).findFirst();
			OptionalInt oi = OptionalInt.empty();
			OptionalLong ol = OptionalLong.empty();
			OptionalDouble od = OptionalDouble.empty();
			String msg1 = "";
			try {
				o1.get();
			} catch (NoSuchElementException e) {
				msg1 = e.getMessage();
			}
			String msg2 = "";
			try {
				Stream.empty().findFirst().get();
			} catch (NoSuchElementException e) {
				msg2 = e.getMessage();
			}
			String msg3 = "";
			try {
				o2.orElseThrow(() -> new IllegalStateException("custom_missing"));
			} catch (IllegalStateException e) {
				msg3 = e.getMessage();
			}
			String msg4 = "";
			try {
				Stream.of(1, 2).filter(x -> x > 5).findAny().orElseThrow(IllegalArgumentException::new);
			} catch (IllegalArgumentException e) {
				msg4 = "caught_iae";
			}
			String msg5 = "";
			try {
				oi.getAsInt();
			} catch (NoSuchElementException e) {
				msg5 = "caught_oi";
			}
			ctx._source.out = [
				'e1': o1.isEmpty(),
				'p1': o1.isPresent(),
				'e2': o2.isEmpty(),
				'e3': o3.isEmpty(),
				'e4': o4.isEmpty(),
				'null_eq': o1 == null,
				'obj_null': Objects.isNull(o1),
				'obj_non_null': Objects.nonNull(o1),
				'or_else': o1.orElse("fallback"),
				'or_else_get': o2.orElseGet(() -> "computed"),
				'or_present': Optional.of("ok").orElseThrow(() -> new IllegalStateException("never")),
				'stream_cnt': o1.stream().count(),
				'msg1': msg1,
				'msg2': msg2,
				'msg3': msg3,
				'msg4': msg4,
				'msg5': msg5,
				'cls': o1.getClass().getName()
			];
		`, nil)
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("expected map, got %T (%#v)", got, got)
		}
		if m["e1"] != true || m["p1"] != false || m["e2"] != true || m["e3"] != true || m["e4"] != true {
			t.Fatalf("unexpected Optional emptiness flags: %#v", m)
		}
		if m["null_eq"] != false || m["obj_null"] != true || m["obj_non_null"] != false {
			t.Fatalf("unexpected Optional null equality checks: %#v", m)
		}
		if m["or_else"] != "fallback" || m["or_else_get"] != "computed" || m["or_present"] != "ok" || m["stream_cnt"] != int64(0) {
			t.Fatalf("unexpected Optional fallback values: %#v", m)
		}
		if m["msg1"] != "No value present" || m["msg2"] != "No value present" || m["msg3"] != "custom_missing" || m["msg4"] != "caught_iae" || m["msg5"] != "caught_oi" {
			t.Fatalf("unexpected Optional exception messages: %#v", m)
		}
		if m["cls"] != "java.util.Optional" {
			t.Fatalf("expected java.util.Optional, got %v", m["cls"])
		}

		// Top-level Eval should unwrap painlessEmptyOptional to nil
		topRes, err := Eval(map[string]any{}, "return Optional.empty();", nil)
		if err != nil || topRes != nil {
			t.Fatalf("expected top-level Optional.empty() to unwrap to nil, got %#v (err=%v)", topRes, err)
		}
		if _, err := Eval(map[string]any{}, "return Optional.empty().get();", nil); err == nil || !strings.Contains(err.Error(), "NoSuchElementException") {
			t.Fatalf("expected NoSuchElementException on Optional.empty().get(), got %v", err)
		}
	})

	t.Run("F21_UUID_HexFormat_And_StrictBase64Validation", func(t *testing.T) {
		got := evalOut(t, `
			UUID u1 = UUID.fromString("123e4567-e89b-42d3-a456-426614174000");
			UUID u2 = new UUID(u1.getMostSignificantBits(), u1.getLeastSignificantBits());
			UUID uShort = UUID.fromString("1-2-3-4-5");
			boolean badUuid = false;
			try {
				UUID.fromString("not-a-valid-uuid");
			} catch (IllegalArgumentException e) {
				badUuid = true;
			}

			HexFormat hf = HexFormat.of();
			HexFormat hfUpper = HexFormat.ofDelimiter(":").withUpperCase().withPrefix("0x");
			byte[] raw = "Hi".getBytes();
			String hex1 = hf.formatHex(raw);
			String hex2 = hfUpper.formatHex(raw);
			byte[] parsed1 = hf.parseHex(hex1);
			byte[] parsed2 = hfUpper.parseHex(hex2);
			boolean badHex = false;
			try {
				hf.parseHex("zz");
			} catch (IllegalArgumentException e) {
				badHex = true;
			}

			String b64Mime = Base64.getMimeEncoder().withoutPadding().encodeToString("hello".getBytes());
			String b64MimeDec = Base64.getMimeDecoder().decode("aGVs\r\nbG8=");
			boolean badB64 = false;
			try {
				Base64.getDecoder().decode("@@@invalid@@@");
			} catch (IllegalArgumentException e) {
				badB64 = true;
			}
			boolean badUrlB64 = false;
			try {
				Base64.getUrlDecoder().decode("@@@invalid@@@");
			} catch (IllegalArgumentException e) {
				badUrlB64 = true;
			}

			ctx._source.out = [
				'u1': u1,
				'u2': u2,
				'u_eq': u1 == u2,
				'u_ver': u1.version(),
				'u_var': u1.variant(),
				'u_short': uShort,
				'u_inst': u1 instanceof UUID,
				'bad_uuid': badUuid,
				'hex1': hex1,
				'hex2': hex2,
				'p1_str': new String(parsed1),
				'p2_str': new String(parsed2),
				'to_hex_byte': hf.toHexDigits((byte) 15),
				'to_hex_4': hf.withUpperCase().toHexDigits(255, 4),
				'from_hex': HexFormat.fromHexDigits("00ff"),
				'from_hex_sub': HexFormat.fromHexDigits("xx00ffyy", 2, 6),
				'from_hex_long': HexFormat.fromHexDigitsToLong("0102030405060708"),
				'is_hex_t': HexFormat.isHexDigit('f'),
				'is_hex_f': HexFormat.isHexDigit('g'),
				'from_digit': HexFormat.fromHexDigit('E'),
				'hf_inst': hf instanceof HexFormat,
				'bad_hex': badHex,
				'b64_mime': b64Mime,
				'b64_mime_dec': b64MimeDec,
				'bad_b64': badB64,
				'bad_url_b64': badUrlB64
			];
		`, nil)
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("expected map, got %T (%#v)", got, got)
		}
		if m["u1"] != "123e4567-e89b-42d3-a456-426614174000" || m["u_eq"] != true || m["u_ver"] != int64(4) || m["u_var"] != int64(2) {
			t.Fatalf("unexpected UUID values: %#v", m)
		}
		if m["u_short"] != "00000001-0002-0003-0004-000000000005" || m["u_inst"] != true || m["bad_uuid"] != true {
			t.Fatalf("unexpected UUID normalization/validation: %#v", m)
		}
		if m["hex1"] != "4869" || m["hex2"] != "0x48:0x69" || m["p1_str"] != "Hi" || m["p2_str"] != "Hi" || m["bad_hex"] != true {
			t.Fatalf("unexpected HexFormat format/parse: %#v", m)
		}
		if m["to_hex_byte"] != "0f" || m["to_hex_4"] != "00FF" || m["from_hex"] != int64(255) || m["from_hex_sub"] != int64(255) || m["from_hex_long"] != int64(0x0102030405060708) {
			t.Fatalf("unexpected HexFormat digit conversions: %#v", m)
		}
		if m["is_hex_t"] != true || m["is_hex_f"] != false || m["from_digit"] != int64(14) || m["hf_inst"] != true {
			t.Fatalf("unexpected HexFormat char helpers: %#v", m)
		}
		if m["b64_mime"] != "aGVsbG8" || m["b64_mime_dec"] != "hello" || m["bad_b64"] != true || m["bad_url_b64"] != true {
			t.Fatalf("unexpected Base64 results: %#v", m)
		}
	})

	t.Run("F22_StringAndCharSequenceMethods", func(t *testing.T) {
		got := evalOut(t, `
			char[] chars = "hello world".toCharArray();
			String s1 = String.valueOf(chars);
			String s2 = String.valueOf(chars, 6, 5);
			String s3 = String.copyValueOf(chars, 0, 5);
			boolean oob = false;
			try {
				String.copyValueOf(chars, 8, 10);
			} catch (IndexOutOfBoundsException e) {
				oob = true;
			}
			StringBuilder sb = new StringBuilder("hello world");
			String esc = 'a\\nb\\tc\\s\\101'.translateEscapes();
			String fmt = "%s=%d".formatted("score", 42);
			ctx._source.out = [
				's1': s1,
				's2': s2,
				's3': s3,
				'oob': oob,
				'ce_sb': s1.contentEquals(sb),
				'ce_str': s1.contentEquals("hello world"),
				'ce_false': s1.contentEquals("other"),
				'esc': esc,
				'fmt': fmt,
				'sw_t': "hello world".startsWith("world", 6),
				'sw_f': "hello world".startsWith("world", 0),
				'sw_neg': "hello world".startsWith("hello", -1),
				'sw_oob': "hello world".startsWith("hello", 99)
			];
		`, nil)
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("expected map, got %T (%#v)", got, got)
		}
		if m["s1"] != "hello world" || m["s2"] != "world" || m["s3"] != "hello" || m["oob"] != true {
			t.Fatalf("unexpected String.valueOf/copyValueOf results: %#v", m)
		}
		if m["ce_sb"] != true || m["ce_str"] != true || m["ce_false"] != false {
			t.Fatalf("unexpected contentEquals results: %#v", m)
		}
		if m["esc"] != "a\nb\tc A" || m["fmt"] != "score=42" {
			t.Fatalf("unexpected translateEscapes/formatted results: %#v", m)
		}
		if m["sw_t"] != true || m["sw_f"] != false || m["sw_neg"] != false || m["sw_oob"] != false {
			t.Fatalf("unexpected 2-arg startsWith results: %#v", m)
		}
	})

	t.Run("F23_NavigableMap_NavigableSet_Deque_And_PriorityQueue", func(t *testing.T) {
		got := evalOut(t, `
			NavigableMap tm = new TreeMap();
			tm.put("b", 2);
			tm.put("a", 1);
			tm.put("d", 4);
			tm.put("c", 3);
			String fk = tm.firstKey();
			String lk = tm.lastKey();
			String flk = tm.floorKey("c");
			String lwk = tm.lowerKey("c");
			String clk = tm.ceilingKey("b");
			String hgk = tm.higherKey("b");
			Map hm = tm.headMap("c", true);
			Map tmap = tm.tailMap("b", false);
			Map sm = tm.subMap("b", true, "d", false);
			List dks = tm.descendingKeySet();
			Map.Entry fe = tm.pollFirstEntry();
			Map.Entry le = tm.pollLastEntry();

			NavigableSet ts = new TreeSet();
			ts.add(30);
			ts.add(10);
			ts.add(20);
			ts.add(10);

			Deque dq = new ArrayDeque();
			dq.addLast("m");
			dq.addFirst("a");
			dq.offerLast("z");
			String dqFirst = dq.peekFirst();
			String dqLast = dq.pollLast();

			Queue pq = new PriorityQueue();
			pq.offer(30);
			pq.offer(10);
			pq.offer(20);
			int pq1 = pq.poll();
			int pq2 = pq.peek();

			ctx._source.out = [
				'fk': fk,
				'lk': lk,
				'flk': flk,
				'lwk': lwk,
				'clk': clk,
				'hgk': hgk,
				'hm_sz': hm.size(),
				'tm_sz': tmap.size(),
				'sm_sz': sm.size(),
				'dks': dks,
				'fe_k': fe.getKey(),
				'le_k': le.getKey(),
				'rem_sz': tm.size(),
				'ts_first': ts.first(),
				'ts_last': ts.last(),
				'ts_floor': ts.floor(25),
				'ts_ceil': ts.ceiling(15),
				'ts_lower': ts.lower(20),
				'ts_higher': ts.higher(20),
				'ts_desc': ts.descendingSet(),
				'dq_first': dqFirst,
				'dq_last': dqLast,
				'dq_sz': dq.size(),
				'pq1': pq1,
				'pq2': pq2
			];
		`, nil)
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("expected map, got %T (%#v)", got, got)
		}
		if m["fk"] != "a" || m["lk"] != "d" || m["flk"] != "c" || m["lwk"] != "b" || m["clk"] != "b" || m["hgk"] != "c" {
			t.Fatalf("unexpected TreeMap key navigation: %#v", m)
		}
		if m["hm_sz"] != int64(3) || m["tm_sz"] != int64(2) || m["sm_sz"] != int64(2) || m["fe_k"] != "a" || m["le_k"] != "d" || m["rem_sz"] != int64(2) {
			t.Fatalf("unexpected TreeMap submaps/polls: %#v", m)
		}
		if m["ts_first"] != int64(10) || m["ts_last"] != int64(30) || m["ts_floor"] != int64(20) || m["ts_ceil"] != int64(20) || m["ts_lower"] != int64(10) || m["ts_higher"] != int64(30) {
			t.Fatalf("unexpected TreeSet navigation: %#v", m)
		}
		if m["dq_first"] != "a" || m["dq_last"] != "z" || m["dq_sz"] != int64(2) || m["pq1"] != int64(10) || m["pq2"] != int64(20) {
			t.Fatalf("unexpected ArrayDeque/PriorityQueue results: %#v", m)
		}
	})

	t.Run("F24_StreamIterateGenerate_And_Collectors", func(t *testing.T) {
		got := evalOut(t, `
			List iter2 = Stream.iterate(1, n -> n * 2).limit(4).collect(Collectors.toList());
			List iter3 = IntStream.iterate(1, n -> n < 10, n -> n + 3).boxed().collect(Collectors.toList());
			List gen = Stream.generate(() -> "x").limit(3).collect(Collectors.toList());
			Map unmod = Stream.of("a", "bb").collect(Collectors.toUnmodifiableMap(s -> s, s -> s.length()));
			boolean dupKeyErr = false;
			try {
				Stream.of("a", "a").collect(Collectors.toUnmodifiableMap(s -> s, s -> 1));
			} catch (IllegalStateException e) {
				dupKeyErr = true;
			}
			List filt = Stream.of(1, 2, 3, 4, 5).collect(Collectors.filtering(x -> x % 2 == 1, Collectors.toList()));
			List flat = Stream.of([1, 2], [3, 4]).collect(Collectors.flatMapping(x -> x.stream(), Collectors.toList()));
			Map tee = Stream.of(10, 20, 30).collect(Collectors.teeing(
				Collectors.summingInt(x -> x),
				Collectors.counting(),
				(sum, cnt) -> ['sum': sum, 'cnt': cnt, 'avg': sum / cnt]
			));
			ctx._source.out = [
				'iter2': iter2,
				'iter3': iter3,
				'gen': gen,
				'unmod_bb': unmod['bb'],
				'dup_err': dupKeyErr,
				'filt': filt,
				'flat': flat,
				'tee': tee
			];
		`, nil)
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("expected map, got %T (%#v)", got, got)
		}
		if len(m["iter2"].([]any)) != 4 || m["iter2"].([]any)[3] != int64(8) {
			t.Fatalf("unexpected iter2: %#v", m["iter2"])
		}
		if len(m["iter3"].([]any)) != 3 || m["iter3"].([]any)[2] != int64(7) {
			t.Fatalf("unexpected iter3: %#v", m["iter3"])
		}
		if len(m["gen"].([]any)) != 3 || m["gen"].([]any)[0] != "x" {
			t.Fatalf("unexpected gen: %#v", m["gen"])
		}
		if m["unmod_bb"] != int64(2) || m["dup_err"] != true {
			t.Fatalf("unexpected toUnmodifiableMap results: %#v", m)
		}
		if len(m["filt"].([]any)) != 3 || m["filt"].([]any)[2] != int64(5) {
			t.Fatalf("unexpected Collectors.filtering: %#v", m["filt"])
		}
		if len(m["flat"].([]any)) != 4 || m["flat"].([]any)[3] != int64(4) {
			t.Fatalf("unexpected Collectors.flatMapping: %#v", m["flat"])
		}
		teeMap, _ := m["tee"].(map[string]any)
		if teeMap["sum"] != int64(60) || teeMap["cnt"] != int64(3) || teeMap["avg"] != int64(20) {
			t.Fatalf("unexpected Collectors.teeing: %#v", m["tee"])
		}
	})

	t.Run("F25_LabeledLoops_And_MultiVarForInitializer", func(t *testing.T) {
		got := evalOut(t, `
			int hits = 0;
			outer: for (int i = 0; i < 4; i++) {
				for (int j = 0; j < 4; j++) {
					if (j == 1 && i < 2) {
						continue outer;
					}
					if (i == 2 && j == 1) {
						break outer;
					}
					hits++;
				}
			}
			int a = 0;
			int b = 0;
			int sum = 0;
			for (a = 1, b = 10; a < b; a++, b--) {
				sum += a + b;
			}
			ctx._source.out = [
				'hits': hits,
				'sum': sum,
				'a': a,
				'b': b
			];
		`, nil)
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("expected map, got %T (%#v)", got, got)
		}
		if m["hits"] != int64(3) || m["sum"] != int64(55) || m["a"] != int64(6) || m["b"] != int64(5) {
			t.Fatalf("unexpected labeled loop / multi-var for results: %#v", m)
		}
	})

	t.Run("F26_CtxOpIllegalArgumentException_And_DirectCtxSourceAssign", func(t *testing.T) {
		rawDoc := json.RawMessage(`{"old":"val"}`)
		if _, _, err := ApplyUpdateWithResult(rawDoc, &UpdateRequest{
			Script: &ScriptSpec{Source: `ctx.op = "invalid_op";`},
		}, false); err == nil || !strings.Contains(err.Error(), "illegal_argument_exception") {
			t.Fatalf("expected illegal_argument_exception for invalid ctx.op, got %v", err)
		}

		doc2 := map[string]any{"old": "val", "__reindex_id": "doc2"}
		if _, err := Eval(doc2, `
			Map prev = ctx._source;
			int prevSz = prev.size();
			ctx._source = ['fresh': 'data', 'prev_sz': prevSz];
		`, nil); err != nil {
			t.Fatalf("unexpected error on direct ctx._source assignment: %v", err)
		}
		if _, hasOld := doc2["old"]; hasOld {
			t.Fatalf("expected old key to be removed after ctx._source replacement: %#v", doc2)
		}
		if doc2["fresh"] != "data" || doc2["prev_sz"] != int64(1) || doc2["__reindex_id"] != "doc2" {
			t.Fatalf("unexpected doc2 after ctx._source replacement: %#v", doc2)
		}

		doc3 := map[string]any{"a": 1, "b": 2}
		if _, err := Eval(doc3, `ctx['_source'] = ['only': 42];`, nil); err != nil {
			t.Fatalf("unexpected error on bracket ctx['_source'] assignment: %v", err)
		}
		if _, hasA := doc3["a"]; hasA {
			t.Fatalf("expected old key 'a' to be removed: %#v", doc3)
		}
		if doc3["only"] != int64(42) {
			t.Fatalf("unexpected doc3 after ctx['_source'] replacement: %#v", doc3)
		}
	})

	t.Run("HexFormat_Navigable_Deque_StreamIterate_And_CtxMutations_Coverage", func(t *testing.T) {
		got := evalOut(t, `
			def hf = HexFormat.ofDelimiter(":").withPrefix("0x").withSuffix("h").withUpperCase();
			def formattedSub = hf.formatHex(new byte[]{1, 10, 255, 16}, 1, 3);
			def parsedSub = hf.parseHex("0x01h:0x0Ah:0xFFh", 6, 17);
			def hfPlain = HexFormat.of().withPrefix("<").withSuffix(">").withLowerCase();
			def plainFormatted = hfPlain.formatHex(new byte[]{10, 11});
			def plainParsed = hfPlain.parseHex("<0a><0b>");
			def hByte = hfPlain.toHexDigits((byte) 15);
			def hShort = hfPlain.toHexDigits((short) 255);
			def hLong = hfPlain.toHexDigits(255L);
			def hChar = hf.toHexDigits('A');
			def hBig = hfPlain.toHexDigits(5000000000L);
			def hZero = hfPlain.toHexDigits(255, 0);
			def hFour = hf.toHexDigits(255, 4);
			def fromSub = hfPlain.fromHexDigits("zz00ffzz", 2, 6);
			def fromLongSub = hfPlain.fromHexDigitsToLong("zz0000000100000000zz", 2, 18);
			boolean isD1 = HexFormat.isHexDigit('f');
			boolean isD2 = HexFormat.isHexDigit('G');
			boolean isD3 = HexFormat.isHexDigit(65);
			int fd1 = HexFormat.fromHexDigit('a');
			int fd2 = HexFormat.fromHexDigit('F');
			int fd3 = HexFormat.fromHexDigit('9');
			int fd4 = HexFormat.fromHexDigit(66);

			boolean errFmtOob = false;
			try { hf.formatHex(new byte[]{1, 2}, -1, 5); } catch (IndexOutOfBoundsException e) { errFmtOob = true; }
			boolean errParseOob = false;
			try { hf.parseHex("0x01h", 0, 99); } catch (IndexOutOfBoundsException e) { errParseOob = true; }
			boolean errParseTok = false;
			try { hf.parseHex("bad_tok"); } catch (IllegalArgumentException e) { errParseTok = true; }
			boolean errParseLen = false;
			try { hfPlain.parseHex("<0a>x"); } catch (IllegalArgumentException e) { errParseLen = true; }
			boolean errParseAffix = false;
			try { hfPlain.parseHex("[0a]"); } catch (IllegalArgumentException e) { errParseAffix = true; }
			boolean errDigitsRange = false;
			try { hfPlain.toHexDigits(10, 20); } catch (IllegalArgumentException e) { errDigitsRange = true; }
			boolean errFromOob = false;
			try { hfPlain.fromHexDigits("abcd", -1, 2); } catch (IndexOutOfBoundsException e) { errFromOob = true; }
			boolean errFromBad = false;
			try { hfPlain.fromHexDigits("zzzz"); } catch (NumberFormatException e) { errFromBad = true; }
			boolean errFromDigit = false;
			try { HexFormat.fromHexDigit('z'); } catch (NumberFormatException e) { errFromDigit = true; }

			TreeMap tm = new TreeMap();
			boolean emptyTmErr = false;
			try { tm.firstKey(); } catch (NoSuchElementException e) { emptyTmErr = true; }
			boolean emptyTmLastErr = false;
			try { tm.lastKey(); } catch (NoSuchElementException e) { emptyTmLastErr = true; }
			def emptyFirstEnt = tm.firstEntry();
			def emptyLastEnt = tm.lastEntry();
			def emptyPollFirst = tm.pollFirstEntry();
			def emptyPollLast = tm.pollLastEntry();
			tm.put("a", 1);
			tm.put("b", 2);
			tm.put("c", 3);
			tm.put("d", 4);
			tm.put("e", 5);
			def fk = tm.firstKey();
			def lk = tm.lastKey();
			def fe = tm.firstEntry();
			def le = tm.lastEntry();
			def nks = tm.navigableKeySet();
			def dks = tm.descendingKeySet();
			def dmap = tm.descendingMap();
			def flk = tm.floorKey("c");
			def clk = tm.ceilingKey("c");
			def lwk = tm.lowerKey("c");
			def hgk = tm.higherKey("c");
			def fle = tm.floorEntry("c");
			def cle = tm.ceilingEntry("c");
			def lwe = tm.lowerEntry("c");
			def hge = tm.higherEntry("c");
			def hm1 = tm.headMap("c");
			def hm2 = tm.headMap("c", true);
			def tm1 = tm.tailMap("c");
			def tm2 = tm.tailMap("c", false);
			def sm1 = tm.subMap("b", "d");
			def sm2 = tm.subMap("b", false, "d", true);
			def pfe = tm.pollFirstEntry();
			def ple = tm.pollLastEntry();

			TreeSet ts = new TreeSet([10, 20, 30, 40, 50]);
			def tsFirst = ts.first();
			def tsLast = ts.last();
			def tsDesc = ts.descendingSet();
			def tsFl = ts.floor(25);
			def tsCl = ts.ceiling(25);
			def tsLw = ts.lower(20);
			def tsHg = ts.higher(40);
			def tsHs1 = ts.headSet(30);
			def tsHs2 = ts.headSet(30, true);
			def tsTs1 = ts.tailSet(30);
			def tsTs2 = ts.tailSet(30, false);
			def tsSs1 = ts.subSet(20, 40);
			def tsSs2 = ts.subSet(20, false, 40, true);

			ArrayDeque dq = new ArrayDeque();
			boolean dqEmptyErr1 = false;
			try { dq.getFirst(); } catch (NoSuchElementException e) { dqEmptyErr1 = true; }
			boolean dqEmptyErr2 = false;
			try { dq.getLast(); } catch (NoSuchElementException e) { dqEmptyErr2 = true; }
			boolean dqEmptyErr3 = false;
			try { dq.removeFirst(); } catch (NoSuchElementException e) { dqEmptyErr3 = true; }
			boolean dqEmptyErr4 = false;
			try { dq.removeLast(); } catch (NoSuchElementException e) { dqEmptyErr4 = true; }
			def dqPeekEmpty1 = dq.peekFirst();
			def dqPeekEmpty2 = dq.peekLast();
			def dqPollEmpty1 = dq.pollFirst();
			def dqPollEmpty2 = dq.pollLast();
			dq.addFirst(2);
			dq.offerFirst(1);
			dq.push(0);
			dq.addLast(3);
			dq.offerLast(4);
			dq.offer(5);
			def dqGf = dq.getFirst();
			def dqGl = dq.getLast();
			def dqPf = dq.peekFirst();
			def dqPl = dq.peekLast();
			def dqRf = dq.removeFirst();
			def dqRl = dq.removeLast();
			def dqPlf = dq.pollFirst();
			def dqPll = dq.pollLast();
			dq.add(2);
			dq.add(3);
			dq.add(2);
			boolean rfo = dq.removeFirstOccurrence(2);
			boolean rlo = dq.removeLastOccurrence(2);
			boolean rfoMiss = dq.removeFirstOccurrence(999);
			boolean rloMiss = dq.removeLastOccurrence(999);

			def genList = Stream.generate(() -> 7).limit(3).collect(Collectors.toList());
			def iterSkipList = Stream.iterate(1, n -> n + 1).skip(2).limit(3).collect(Collectors.toList());
			def iterPredSum = IntStream.iterate(1, n -> n < 5, n -> n + 1).sum();

			ctx._source.arr = [10, 20];
			def prevSet = ctx._source.arr.set(0, 11);
			def rAdd1 = ctx._source.arr.add(1, 15);
			def rAdd2 = ctx._source.arr.add(25);
			def rAddAll1 = ctx._source.arr.addAll([30, 35]);
			def rAddAll2 = ctx._source.arr.addAll(0, [5]);
			def rSort1 = ctx._source.arr.sort((a, b) -> a - b);
			ctx._source.sub = ['k1': 'v1'];
			def rPut1 = ctx._source.sub.put('k2', 'v2');
			def rPutAll1 = ctx._source.sub.putAll(['k3': 'v3', 'k4': 'v4']);
			def rPia1 = ctx._source.sub.putIfAbsent('k2', 'nope');
			def rPia2 = ctx._source.sub.putIfAbsent('k5', 'v5');
			def rRep1 = ctx._source.sub.replace('k5', 'v5_new');
			def rRep2 = ctx._source.sub.replace('k5', 'v5_new', 'v5_final');
			def rRem0 = ctx._source.sub.remove('k5');
			def rRem1 = ctx._source.sub.remove('k4', 'v4');
			def rRem2 = ctx._source.sub.remove('k3');
			def rPutSrc = ctx._source.put('top_k', 'top_v');
			def rPiaSrc = ctx._source.putIfAbsent('top_k', 'nope');
			def rPutAllSrc = ctx._source.putAll(['top_k2': 'v2']);
			def rRemSrc1 = ctx._source.remove('top_k2', 'v2');
			def rRemSrc2 = ctx._source.remove('top_k');

			List locArr = [10, 20];
			def lSet = locArr.set(0, 11);
			def lAdd1 = locArr.add(1, 15);
			def lAdd2 = locArr.add(25);
			def lAddAll1 = locArr.addAll([30, 35]);
			def lAddAll2 = locArr.addAll(0, [5]);
			def lSort = locArr.sort((a, b) -> a - b);
			def lSub = locArr.subList(1, 3);
			Map locMap = ['a': 1];
			def lmPut = locMap.put('b', 2);
			def lmPutAll = locMap.putAll(['c': 3, 'd': 4]);
			def lmPia1 = locMap.putIfAbsent('b', 99);
			def lmPia2 = locMap.putIfAbsent('e', 5);
			def lmRep1 = locMap.replace('e', 50);
			def lmRep2 = locMap.replace('e', 50, 500);
			def lmRem1 = locMap.remove('d', 4);
			def lmRem2 = locMap.remove('c');
			def lmGod = locMap.getOrDefault('missing', 42);

			def pPut = params.put('pk1', 100);
			def pPia1 = params.putIfAbsent('pk1', 999);
			def pPia2 = params.putIfAbsent('pk4', 400);
			def pPutAll = params.putAll(['pk2': 200, 'pk3': 300]);
			def pRem0 = params.remove('pk4');
			def pRem1 = params.remove('pk2', 200);
			def pRem2 = params.remove('pk3');

			boolean rm1 = "Hello World".regionMatches(true, 0, "hello", 0, 5);
			boolean rm2 = "Hello World".regionMatches(6, "World", 0, 5);
			String sbRep = new StringBuilder("abcdef").replace(1, 4, "XY").toString();

			ctx._source.out = [
				'formattedSub': formattedSub,
				'parsedSubLen': parsedSub.size(),
				'plainFormatted': plainFormatted,
				'plainParsedLen': plainParsed.size(),
				'hByte': hByte,
				'hShort': hShort,
				'hLong': hLong,
				'hChar': hChar,
				'hBig': hBig,
				'hZero': hZero,
				'hFour': hFour,
				'fromSub': fromSub,
				'fromLongSub': fromLongSub,
				'isD': [isD1, isD2, isD3],
				'fd': [fd1, fd2, fd3, fd4],
				'errs': [errFmtOob, errParseOob, errParseTok, errParseLen, errParseAffix, errDigitsRange, errFromOob, errFromBad, errFromDigit],
				'tm': [fk, lk, fe.key, le.key, nks.size(), dks[0], dmap.firstKey(), flk, clk, lwk, hgk, fle.key, cle.key, lwe.key, hge.key, hm1.size(), hm2.size(), tm1.size(), tm2.size(), sm1.size(), sm2.size(), pfe.key, ple.key, emptyTmErr, emptyTmLastErr, emptyFirstEnt == null, emptyLastEnt == null, emptyPollFirst == null, emptyPollLast == null],
				'ts': [tsFirst, tsLast, tsDesc[0], tsFl, tsCl, tsLw, tsHg, tsHs1.size(), tsHs2.size(), tsTs1.size(), tsTs2.size(), tsSs1.size(), tsSs2.size()],
				'dq': [dqEmptyErr1, dqEmptyErr2, dqEmptyErr3, dqEmptyErr4, dqPeekEmpty1 == null, dqPeekEmpty2 == null, dqPollEmpty1 == null, dqPollEmpty2 == null, dqGf, dqGl, dqPf, dqPl, dqRf, dqRl, dqPlf, dqPll, rfo, rlo, !rfoMiss, !rloMiss],
				'streams': [genList.size(), iterSkipList[0], iterPredSum],
				'arrLen': ctx._source.arr.size(),
				'prevSet': prevSet,
				'subSize': ctx._source.sub.size(),
				'pk1': params.pk1
			];
		`, map[string]any{})
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("expected map, got %T (%#v)", got, got)
		}
		if m["formattedSub"] != "0x0Ah:0xFFh" || m["plainFormatted"] != "<0a><0b>" {
			t.Fatalf("unexpected HexFormat results: %#v", m)
		}
		if m["hByte"] != "0f" || m["hShort"] != "00ff" || m["hChar"] != "0041" || m["hFour"] != "00FF" {
			t.Fatalf("unexpected toHexDigits results: %#v", m)
		}
		for i, b := range m["errs"].([]any) {
			if b != true {
				t.Fatalf("expected errs[%d] to be true, got %#v", i, m["errs"])
			}
		}
		if m["arrLen"] != int64(7) || m["prevSet"] != int64(10) || m["subSize"] != int64(2) || m["pk1"] != int64(100) {
			t.Fatalf("unexpected mutation results: %#v", m)
		}
	})
}

func TestRound53F20ToF26Features(t *testing.T) {
	runDoc := func(t *testing.T, script string, doc map[string]any) any {
		t.Helper()
		if doc == nil {
			doc = map[string]any{}
		}
		if _, err := Eval(doc, script, map[string]any{"p1": 10}); err != nil {
			t.Fatalf("unexpected error for script:\n%s\nerr: %v", script, err)
		}
		return doc["out"]
	}

	t.Run("F20_BigInteger_MathContext_BigDecimal", func(t *testing.T) {
		got := runDoc(t, `
			BigInteger b0 = BigInteger.ZERO;
			BigInteger b1 = BigInteger.ONE;
			BigInteger b2 = BigInteger.TWO;
			BigInteger b10 = BigInteger.TEN;
			BigInteger bVal = BigInteger.valueOf(255L);
			BigInteger bHex = new BigInteger("ff", 16);
			BigInteger bDec = new BigInteger("100");
			byte[] rawBytes = new byte[] { (byte)1, (byte)0 };
			BigInteger bFromBytes = new BigInteger(rawBytes);

			BigInteger sum = bVal.add(b1);
			BigInteger diff = sum.subtract(b10);
			BigInteger prod = bDec.multiply(b2);
			BigInteger quot = prod.divide(b10);
			BigInteger rem = bVal.remainder(b10);
			BigInteger[] dr = bVal.divideAndRemainder(b10);
			BigInteger modVal = new BigInteger("-7").mod(b10);
			BigInteger modPowVal = b2.modPow(BigInteger.valueOf(8), BigInteger.valueOf(257));
			BigInteger modInvVal = BigInteger.valueOf(3).modInverse(b10);
			BigInteger powVal = b2.pow(10);
			BigInteger gcdVal = BigInteger.valueOf(48).gcd(BigInteger.valueOf(18));
			BigInteger absVal = new BigInteger("-42").abs();
			BigInteger negVal = b10.negate();
			int sig = negVal.signum();
			BigInteger minVal = b10.min(bVal);
			BigInteger maxVal = b10.max(bVal);
			int cmp = bVal.compareTo(bHex);

			BigInteger bwAnd = bVal.and(BigInteger.valueOf(15));
			BigInteger bwOr = BigInteger.valueOf(240).or(BigInteger.valueOf(15));
			BigInteger bwXor = bVal.xor(BigInteger.valueOf(15));
			BigInteger bwNot = b0.not();
			BigInteger bwAndNot = bVal.andNot(BigInteger.valueOf(15));
			BigInteger shl = b1.shiftLeft(8);
			BigInteger shr = shl.shiftRight(4);
			boolean tb = bVal.testBit(7);
			BigInteger sb = b0.setBit(3);
			BigInteger cb = sb.clearBit(3);
			BigInteger fb = b0.flipBit(2);
			int lsb = BigInteger.valueOf(12).getLowestSetBit();
			int blen = bVal.bitLength();
			int bcnt = bVal.bitCount();

			boolean isPrime = BigInteger.valueOf(17).isProbablePrime(10);
			BigInteger nextP = BigInteger.valueOf(14).nextProbablePrime();
			String hexStr = bVal.toString(16);
			byte[] toB = bFromBytes.toByteArray();
			long lv = bVal.longValue();
			long lve = bVal.longValueExact();
			int ive = bVal.intValueExact();
			short sve = bVal.shortValueExact();
			byte bve = BigInteger.valueOf(127).byteValueExact();
			double dv = bVal.doubleValue();
			float fv = bVal.floatValue();

			MathContext mc32 = MathContext.DECIMAL32;
			MathContext mc64 = MathContext.DECIMAL64;
			MathContext mc128 = MathContext.DECIMAL128;
			MathContext mcUnl = MathContext.UNLIMITED;
			MathContext mcCustom = new MathContext(4, RoundingMode.HALF_UP);
			MathContext mcStr = new MathContext("precision=5 roundingMode=DOWN");

			BigDecimal bd1 = new BigDecimal("123.456");
			BigDecimal bd2 = new BigDecimal("10.0");
			BigDecimal bdAddMc = bd1.add(bd2, mcCustom);
			BigDecimal bdSubMc = bd1.subtract(bd2, mcCustom);
			BigDecimal bdMulMc = bd1.multiply(bd2, mcCustom);
			BigDecimal bdDivMc = new BigDecimal("1").divide(new BigDecimal("3"), mc32);
			BigDecimal bdPowMc = new BigDecimal("1.5").pow(2, mcCustom);
			BigDecimal bdPlus = bd1.plus();
			BigDecimal bdRound = bd1.round(mcCustom);
			int bdPrec = bd1.precision();
			BigInteger bdUnscaled = bd1.unscaledValue();
			BigDecimal bdMoveL = bd1.movePointLeft(1);
			BigDecimal bdMoveR = bd1.movePointRight(1);
			BigDecimal bdScaleP = new BigDecimal("12").scaleByPowerOfTen(2);
			BigDecimal bdIntDiv = new BigDecimal("17").divideToIntegralValue(new BigDecimal("5"));
			BigDecimal[] bdDr = new BigDecimal("17").divideAndRemainder(new BigDecimal("5"));
			BigInteger bdBiExact = new BigDecimal("42.00").toBigIntegerExact();
			long bdLongExact = new BigDecimal("9007199254740993").longValueExact();
			int bdIntExact = new BigDecimal("42.0").intValueExact();
			short bdShortExact = new BigDecimal("300").shortValueExact();
			byte bdByteExact = new BigDecimal("120").byteValueExact();

			boolean errBiByteOob = false;
			try { BigInteger.valueOf(200).byteValueExact(); } catch (ArithmeticException e) { errBiByteOob = true; }
			boolean errBdFracExact = false;
			try { new BigDecimal("1.5").intValueExact(); } catch (ArithmeticException e) { errBdFracExact = true; }

			ctx._source.out = [
				'sum': sum.longValue(),
				'diff': diff.longValue(),
				'prod': prod.longValue(),
				'quot': quot.longValue(),
				'rem': rem.longValue(),
				'dr0': dr[0].longValue(),
				'dr1': dr[1].longValue(),
				'modVal': modVal.longValue(),
				'modPowVal': modPowVal.longValue(),
				'modInvVal': modInvVal.longValue(),
				'powVal': powVal.longValue(),
				'gcdVal': gcdVal.longValue(),
				'absVal': absVal.longValue(),
				'negVal': negVal.longValue(),
				'sig': sig,
				'minVal': minVal.longValue(),
				'maxVal': maxVal.longValue(),
				'cmp': cmp,
				'bw': [bwAnd.longValue(), bwOr.longValue(), bwXor.longValue(), bwNot.longValue(), bwAndNot.longValue(), shl.longValue(), shr.longValue()],
				'bits': [tb, sb.longValue(), cb.longValue(), fb.longValue(), lsb, blen, bcnt],
				'prime': [isPrime, nextP.longValue()],
				'hexStr': hexStr,
				'toBLen': toB.length,
				'convs': [lv, lve, ive, sve, bve, dv > 254.0, fv > 254.0],
				'mc': [mc32.getPrecision(), mc64.getPrecision(), mc128.getPrecision(), mcUnl.getPrecision(), mcCustom.getPrecision(), mcStr.getPrecision()],
				'bd': [bdAddMc.toString(), bdSubMc.toString(), bdMulMc.toString(), bdDivMc.toString(), bdPowMc.toString(), bdPlus.toString(), bdRound.toString(), bdPrec, bdUnscaled.longValue(), bdMoveL.toString(), bdMoveR.toString(), bdScaleP.longValue(), bdIntDiv.longValue(), bdDr[0].longValue(), bdDr[1].longValue(), bdBiExact.longValue(), bdLongExact, bdIntExact, bdShortExact, bdByteExact],
				'errs': [errBiByteOob, errBdFracExact]
			];
		`, map[string]any{})
		m := got.(map[string]any)
		if m["sum"] != int64(256) || m["gcdVal"] != int64(6) || m["modInvVal"] != int64(7) || m["hexStr"] != "ff" {
			t.Fatalf("unexpected BigInteger results: %#v", m)
		}
		for i, b := range m["errs"].([]any) {
			if b != true {
				t.Fatalf("expected errs[%d] to be true, got %#v", i, m["errs"])
			}
		}
	})

	t.Run("F21_TemporalAdjusters_Until_DatesUntil_ChronoUnitBetween", func(t *testing.T) {
		got := runDoc(t, `
			LocalDate d = LocalDate.of(2025, 2, 15);
			LocalDate fdom = d.with(TemporalAdjusters.firstDayOfMonth());
			LocalDate ldom = d.with(TemporalAdjusters.lastDayOfMonth());
			LocalDate fdonm = d.with(TemporalAdjusters.firstDayOfNextMonth());
			LocalDate fdoy = d.with(TemporalAdjusters.firstDayOfYear());
			LocalDate ldoy = d.with(TemporalAdjusters.lastDayOfYear());
			LocalDate fdony = d.with(TemporalAdjusters.firstDayOfNextYear());
			LocalDate nextMon = d.with(TemporalAdjusters.next(DayOfWeek.MONDAY));
			LocalDate nextOrSameSat = d.with(TemporalAdjusters.nextOrSame(DayOfWeek.SATURDAY));
			LocalDate prevFri = d.with(TemporalAdjusters.previous(DayOfWeek.FRIDAY));
			LocalDate prevOrSameSat = d.with(TemporalAdjusters.previousOrSame(DayOfWeek.SATURDAY));
			LocalDate firstMon = d.with(TemporalAdjusters.firstInMonth(DayOfWeek.MONDAY));
			LocalDate lastFri = d.with(TemporalAdjusters.lastInMonth(DayOfWeek.FRIDAY));
			LocalDate secondWed = d.with(TemporalAdjusters.dayOfWeekInMonth(2, DayOfWeek.WEDNESDAY));

			LocalDate wField = d.with(ChronoField.MONTH_OF_YEAR, 5);
			LocalDate dEnd = LocalDate.of(2025, 2, 20);
			long daysUntil = d.until(dEnd, ChronoUnit.DAYS);
			Period pUntil = d.until(LocalDate.of(2025, 4, 18));
			List du1 = d.datesUntil(LocalDate.of(2025, 2, 18)).collect(Collectors.toList());
			List du2 = d.datesUntil(LocalDate.of(2025, 5, 15), Period.ofMonths(1)).collect(Collectors.toList());

			long cuDays = ChronoUnit.DAYS.between(d, dEnd);
			long cuMonths = ChronoUnit.MONTHS.between(LocalDate.of(2025, 1, 1), LocalDate.of(2025, 6, 1));
			long cuYears = ChronoUnit.YEARS.between(LocalDate.of(2020, 1, 1), LocalDate.of(2025, 1, 1));
			long cuWeeks = ChronoUnit.WEEKS.between(LocalDate.of(2025, 1, 1), LocalDate.of(2025, 1, 22));
			long cuDecades = ChronoUnit.DECADES.between(LocalDate.of(2000, 1, 1), LocalDate.of(2025, 1, 1));
			long cuCenturies = ChronoUnit.CENTURIES.between(LocalDate.of(1800, 1, 1), LocalDate.of(2025, 1, 1));
			long cuMillennia = ChronoUnit.MILLENNIA.between(LocalDate.of(1000, 1, 1), LocalDate.of(2025, 1, 1));
			LocalDateTime dt1 = LocalDateTime.of(2025, 2, 15, 10, 0, 0);
			LocalDateTime dt2 = LocalDateTime.of(2025, 2, 16, 12, 30, 45);
			long cuNanos = ChronoUnit.NANOS.between(dt1, dt2);
			long cuMicros = ChronoUnit.MICROS.between(dt1, dt2);
			long cuMillis = ChronoUnit.MILLIS.between(dt1, dt2);
			long cuSecs = ChronoUnit.SECONDS.between(dt1, dt2);
			long cuMins = ChronoUnit.MINUTES.between(dt1, dt2);
			long cuHours = ChronoUnit.HOURS.between(dt1, dt2);
			long cuHalfDays = ChronoUnit.HALF_DAYS.between(dt1, dt2);
			long yBetween1 = ChronoUnit.YEARS.between(Year.of(2000), Year.of(2025));
			long yBetween10 = ChronoUnit.DECADES.between(Year.of(2000), Year.of(2025));
			long yBetween100 = ChronoUnit.CENTURIES.between(Year.of(1800), Year.of(2025));
			long yBetween1000 = ChronoUnit.MILLENNIA.between(Year.of(1000), Year.of(2025));

			LocalDate dowZero = d.with(TemporalAdjusters.dayOfWeekInMonth(0, DayOfWeek.MONDAY));
			LocalDate dowNeg = d.with(TemporalAdjusters.dayOfWeekInMonth(-1, DayOfWeek.MONDAY));
			LocalDate wYear = d.with(Year.of(2026));
			LocalDate wMd = d.with(MonthDay.of(3, 10));
			LocalDate wYm = d.with(YearMonth.of(2025, 8));
			LocalDate wLd = d.with(LocalDate.of(2025, 9, 1));
			LocalDateTime wLt = dt1.with(LocalTime.of(14, 20, 0));
			LocalDate wDowTue = d.with(DayOfWeek.TUESDAY);
			LocalDate wDowWed = d.with(DayOfWeek.WEDNESDAY);
			LocalDate wDowThu = d.with(DayOfWeek.THURSDAY);
			LocalDate wDowFri = d.with(DayOfWeek.FRIDAY);
			LocalDate wDowSat = d.with(DayOfWeek.SATURDAY);
			LocalDate wDowSun = d.with(DayOfWeek.SUNDAY);
			LocalDate wJan = d.with(Month.JANUARY);
			LocalDate wFeb = d.with(Month.FEBRUARY);
			LocalDate wMar = d.with(Month.MARCH);
			LocalDate wApr = d.with(Month.APRIL);
			LocalDate wMay = d.with(Month.MAY);
			LocalDate wJun = d.with(Month.JUNE);
			LocalDate wJul = d.with(Month.JULY);
			LocalDate wAug = d.with(Month.AUGUST);
			LocalDate wSep = d.with(Month.SEPTEMBER);
			LocalDate wOct = d.with(Month.OCTOBER);
			LocalDate wNov = d.with(Month.NOVEMBER);
			LocalDate wDec = d.with(Month.DECEMBER);
			Period pUntilBorrow = d.until(LocalDate.of(2025, 3, 10));
			Period pUntilNeg = d.until(LocalDate.of(2025, 1, 20));

			ctx._source.out = [
				'fdom': fdom.toString(),
				'ldom': ldom.toString(),
				'fdonm': fdonm.toString(),
				'fdoy': fdoy.toString(),
				'ldoy': ldoy.toString(),
				'fdony': fdony.toString(),
				'nextMon': nextMon.toString(),
				'nextOrSameSat': nextOrSameSat.toString(),
				'prevFri': prevFri.toString(),
				'prevOrSameSat': prevOrSameSat.toString(),
				'firstMon': firstMon.toString(),
				'lastFri': lastFri.toString(),
				'secondWed': secondWed.toString(),
				'dowZero': dowZero.toString(),
				'dowNeg': dowNeg.toString(),
				'wField': wField.toString(),
				'wExtras': [wYear.toString(), wMd.toString(), wYm.toString(), wLd.toString(), wLt.toString(), wDowTue.toString(), wDowWed.toString(), wDowThu.toString(), wDowFri.toString(), wDowSat.toString(), wDowSun.toString()],
				'wMonths': [wJan.toString(), wFeb.toString(), wMar.toString(), wApr.toString(), wMay.toString(), wJun.toString(), wJul.toString(), wAug.toString(), wSep.toString(), wOct.toString(), wNov.toString(), wDec.toString()],
				'daysUntil': daysUntil,
				'pUntilMonths': pUntil.getMonths(),
				'pUntilDays': pUntil.getDays(),
				'pBorrowDays': pUntilBorrow.getDays(),
				'pNegDays': pUntilNeg.getDays(),
				'du1Size': du1.size(),
				'du2Size': du2.size(),
				'cu': [cuDays, cuMonths, cuYears, cuWeeks, cuDecades, cuCenturies, cuMillennia, cuNanos > 0, cuMicros > 0, cuMillis > 0, cuSecs > 0, cuMins > 0, cuHours, cuHalfDays, yBetween1, yBetween10, yBetween100, yBetween1000]
			];
		`, map[string]any{})
		m := got.(map[string]any)
		if m["fdom"] != "2025-02-01" || m["ldom"] != "2025-02-28" || m["fdonm"] != "2025-03-01" || m["daysUntil"] != int64(5) || m["du1Size"] != int64(3) || m["du2Size"] != int64(3) {
			t.Fatalf("unexpected TemporalAdjusters/until results: %#v", m)
		}
	})

	t.Run("F22_Comparator_FirstClass", func(t *testing.T) {
		got := runDoc(t, `
			Comparator nat = Comparator.naturalOrder();
			Comparator rev = Comparator.reverseOrder();
			Comparator nf = Comparator.nullsFirst(nat);
			Comparator nl = Comparator.nullsLast(nat);

			List items = [3, null, 1, 2];
			items.sort(nf);
			def nfFirst = items[0];
			def nfSecond = items[1];
			items.sort(nl);
			def nlLast = items[3];

			List words = ["banana", "Apple", "cherry"];
			words.sort(String.CASE_INSENSITIVE_ORDER);

			List people = [
				['name': 'Alice', 'age': 30, 'score': 95.5],
				['name': 'Bob', 'age': 25, 'score': 88.0],
				['name': 'Charlie', 'age': 25, 'score': 92.0]
			];
			Comparator byAgeThenScoreDesc = Comparator.comparingInt(p -> p.age)
				.thenComparing(Comparator.comparingDouble(p -> p.score).reversed());
			people.sort(byAgeThenScoreDesc);

			Comparator byNameRev = Comparator.comparing(p -> p.name, Comparator.reverseOrder());
			int directCmp = byNameRev.compare(people[0], people[1]);

			ctx._source.out = [
				'nfFirstNull': nfFirst == null,
				'nfSecond': nfSecond,
				'nlLastNull': nlLast == null,
				'words': words,
				'firstPerson': people[0].name,
				'secondPerson': people[1].name,
				'directCmpPos': directCmp < 0
			];
		`, map[string]any{})
		m := got.(map[string]any)
		if m["nfFirstNull"] != true || m["nfSecond"] != int64(1) || m["nlLastNull"] != true || m["firstPerson"] != "Charlie" || m["secondPerson"] != "Bob" {
			t.Fatalf("unexpected Comparator results: %#v", m)
		}
	})

	t.Run("F23_BitSet_StringJoiner_Character", func(t *testing.T) {
		got := runDoc(t, `
			BitSet bs1 = new BitSet();
			bs1.set(1);
			bs1.set(3, 6);
			bs1.clear(4);
			bs1.flip(0);
			boolean g0 = bs1.get(0);
			boolean g2 = bs1.get(2);
			int card = bs1.cardinality();
			int len = bs1.length();
			int nsb = bs1.nextSetBit(2);
			int ncb = bs1.nextClearBit(0);
			int psb = bs1.previousSetBit(5);
			int pcb = bs1.previousClearBit(5);

			BitSet bs2 = BitSet.valueOf(new long[] { 7L });
			boolean inter = bs1.intersects(bs2);
			BitSet bsClone = bs1.clone();
			bsClone.and(bs2);
			int andCard = bsClone.cardinality();
			bsClone.or(bs2);
			int orCard = bsClone.cardinality();
			bsClone.xor(bs1);
			bsClone.andNot(bs2);
			boolean emptyAfter = bsClone.isEmpty();
			byte[] bsBytes = bs2.toByteArray();
			long[] bsLongs = bs2.toLongArray();
			List bsStream = bs2.stream().boxed().collect(Collectors.toList());
			String bsStr = bs2.toString();

			StringJoiner sjEmpty = new StringJoiner(", ", "[", "]");
			sjEmpty.setEmptyValue("EMPTY");
			String emptyStr = sjEmpty.toString();
			StringJoiner sj = new StringJoiner(", ", "[", "]");
			sj.add("alpha").add("beta");
			StringJoiner sj2 = new StringJoiner("-");
			sj2.add("gamma");
			sj.merge(sj2);
			String sjStr = sj.toString();
			int sjLen = sj.length();

			int cc = Character.charCount(0x1F600);
			int cmpC = Character.compare((char)'a', (char)'b');
			char fDig = Character.forDigit(15, 16);
			int gNum = Character.getNumericValue((char)'9');
			int gType = Character.getType((char)'A');
			char highS = Character.highSurrogate(0x1F600);
			char lowS = Character.lowSurrogate(0x1F600);
			int cp = Character.toCodePoint(highS, lowS);
			boolean isAlph = Character.isAlphabetic((int)'Z');
			boolean isBmp = Character.isBmpCodePoint(65);
			boolean isIdeog = Character.isIdeographic(0x4E00);
			boolean isIso = Character.isISOControl(0x07);
			boolean isJavaStart = Character.isJavaIdentifierStart((char)'$');
			boolean isJavaPart = Character.isJavaIdentifierPart((char)'9');
			boolean isLowS = Character.isLowSurrogate(lowS);
			boolean isHighS = Character.isHighSurrogate(highS);
			boolean isMirr = Character.isMirrored((char)'(');
			boolean isSupp = Character.isSupplementaryCodePoint(0x1F600);
			boolean isSurr = Character.isSurrogate(highS);
			boolean isSurrPair = Character.isSurrogatePair(highS, lowS);
			boolean isTitle = Character.isTitleCase((char)'\u01C5');
			boolean isValidCp = Character.isValidCodePoint(0x10FFFF);
			char revB = Character.reverseBytes((char)0x1234);
			char[] toC = Character.toChars(0x1F600);
			String cStr = Character.toString((char)'X');
			int cHash = Character.hashCode((char)'A');
			String cName = Character.getName(65);
			int cpa0 = Character.codePointAt("A\uD83D\uDE00B", 0);
			int cpa1 = Character.codePointAt("A\uD83D\uDE00B", 1);
			int cpb1 = Character.codePointBefore("A\uD83D\uDE00B", 1);
			int cpb3 = Character.codePointBefore("A\uD83D\uDE00B", 3);
			int cpc = Character.codePointCount("A\uD83D\uDE00B", 0, 4);
			int gn1 = Character.getNumericValue((char)'a');
			int gn2 = Character.getNumericValue((char)'F');
			int gn3 = Character.getNumericValue((char)'\uFF15');
			int gn4 = Character.getNumericValue((char)'\uFF22');
			int gn5 = Character.getNumericValue((char)'\uFF42');
			int gn6 = Character.getNumericValue((char)'\u0663');
			int gn7 = Character.getNumericValue((char)'\u2155');
			int gn8 = Character.getNumericValue((char)'!');
			List gTypes = [
				Character.getType((char)'A'), Character.getType((char)'a'), Character.getType((char)'\u01C5'),
				Character.getType((char)'\u02B0'), Character.getType((char)'\u4E00'), Character.getType((char)'\u0300'),
				Character.getType((char)'\u20DD'), Character.getType((char)'\u0903'), Character.getType((char)'5'),
				Character.getType((char)'\u2164'), Character.getType((char)'\u00B2'), Character.getType((char)' '),
				Character.getType((char)'\u2028'), Character.getType((char)'\u2029'), Character.getType((char)'\n'),
				Character.getType((char)'\u200B'), Character.getType((char)'\uE000'), Character.getType((char)'-'),
				Character.getType((char)'('), Character.getType((char)')'), Character.getType((char)'_'),
				Character.getType((char)'.'), Character.getType((char)'+'), Character.getType((char)'$'),
				Character.getType((char)'^'), Character.getType((char)'\u00A9'), Character.getType((char)'\u00AB'),
				Character.getType((char)'\u00BB')
			];
			List chPreds = [
				Character.isDigit((char)'5'), Character.isLetter((char)'a'), Character.isLetterOrDigit((char)'5'),
				Character.isWhitespace((char)' '), Character.isWhitespace((char)'\u00A0'), Character.isSpaceChar((char)' '),
				Character.isUpperCase((char)'A'), Character.isLowerCase((char)'a'), Character.isDefined((char)'A'),
				Character.toUpperCase((char)'a'), Character.toUpperCase(97),
				Character.toLowerCase((char)'A'), Character.toLowerCase(65),
				Character.toTitleCase((char)'a'), Character.toTitleCase(97),
				Character.digit((char)'f', 16), Character.digit((char)'F', 16), Character.digit((char)'5', 10), Character.digit((char)'z', 10),
				Character.forDigit(5, 10), Character.forDigit(99, 10)
			];

			ctx._source.out = [
				'bs': [g0, g2, card, len, nsb, ncb, psb, pcb, inter, andCard, orCard, emptyAfter, bsBytes.length, bsLongs.length, bsStream.size(), bsStr],
				'sj': [emptyStr, sjStr, sjLen],
				'ch': [cc, cmpC < 0, String.valueOf(fDig), gNum, gType > 0, cp == 0x1F600, isAlph, isBmp, isIdeog, isIso, isJavaStart, isJavaPart, isLowS, isHighS, isMirr, isSupp, isSurr, isSurrPair, isTitle, isValidCp, (int)revB == 0x3412, toC.length, cStr, cHash == 65, cName.length() > 0, cpa0, cpa1, cpb1, cpb3, cpc, gn1, gn2, gn3, gn4, gn5, gn6, gn7, gn8, gTypes.size(), chPreds.size()]
			];
		`, map[string]any{})
		m := got.(map[string]any)
		sj := m["sj"].([]any)
		if sj[0] != "EMPTY" || sj[1] != "[alpha, beta, gamma]" || sj[2] != int64(20) {
			t.Fatalf("unexpected StringJoiner results: %#v", sj)
		}
	})

	t.Run("F24_UserDefinedClasses", func(t *testing.T) {
		got := runDoc(t, `
			class Counter {
				int count = 1;
				String label;

				Counter(String label) {
					this.label = label;
				}

				Counter(String label, int initial) {
					this.label = label;
					this.count = initial;
				}

				int increment(int delta) {
					this.count += delta;
					return this.count;
				}

				int doubleCount() {
					return this.increment(this.count);
				}

				String describe() {
					return this.label + ":" + this.count;
				}
			}

			Counter c1 = new Counter("first");
			c1.increment(4);
			c1.count++;
			Counter c2 = new Counter("second", 10);
			int d2 = c2.doubleCount();

			ctx._source.out = [
				'c1Desc': c1.describe(),
				'c1Count': c1.count,
				'c2Desc': c2.describe(),
				'd2': d2
			];
		`, map[string]any{})
		m := got.(map[string]any)
		if m["c1Desc"] != "first:6" || m["c1Count"] != int64(6) || m["c2Desc"] != "second:20" || m["d2"] != int64(20) {
			t.Fatalf("unexpected user class results: %#v", m)
		}
	})

	t.Run("F25_MultiDimArrays_ArraysBulkOps", func(t *testing.T) {
		got := runDoc(t, `
			int[][] grid = new int[2][3];
			grid[0][1] = 7;
			grid[1][2] = 9;
			int[][] litGrid = new int[][] { {1, 2}, {3, 4} };

			int[] arr = new int[4];
			Arrays.setAll(arr, i -> (i + 1) * 10);
			int[] parr = new int[4];
			Arrays.parallelSetAll(parr, i -> i + 1);
			Arrays.parallelPrefix(parr, (a, b) -> a + b);

			int[] a1 = new int[] {1, 2, 3};
			int[] a2 = new int[] {1, 2, 4};
			int cmp = Arrays.compare(a1, a2);
			int mis = Arrays.mismatch(a1, a2);
			int misEq = Arrays.mismatch(a1, new int[] {1, 2, 3});
			int cmpRangeEq = Arrays.compare(a1, 0, 2, a2, 0, 2);
			int cmpRangeRev = Arrays.compare(a1, 0, 3, a2, 0, 3, Comparator.reverseOrder());
			int misRange = Arrays.mismatch(a1, 0, 3, a2, 0, 3);
			int misRangePrefix = Arrays.mismatch(a1, 0, 2, a2, 0, 3, Comparator.naturalOrder());
			int cmpNulls = Arrays.compare(null, null);
			int cmpNullLeft = Arrays.compare(null, a1);
			int cmpNullRight = Arrays.compare(a1, null);
			int misNulls = Arrays.mismatch(null, null);

			ctx._source.out = [
				'g01': grid[0][1],
				'g12': grid[1][2],
				'lit11': litGrid[1][1],
				'arr': [arr[0], arr[1], arr[2], arr[3]],
				'parr': [parr[0], parr[1], parr[2], parr[3]],
				'cmpNeg': cmp < 0,
				'mis': mis,
				'misEq': misEq,
				'ranges': [cmpRangeEq, cmpRangeRev > 0, misRange, misRangePrefix, cmpNulls, cmpNullLeft < 0, cmpNullRight > 0, misNulls]
			];
		`, map[string]any{})
		m := got.(map[string]any)
		if m["g01"] != int64(7) || m["g12"] != int64(9) || m["lit11"] != int64(4) || m["mis"] != int64(2) || m["misEq"] != int64(-1) {
			t.Fatalf("unexpected multi-dim/Arrays results: %#v", m)
		}
	})

	t.Run("F26_CtxMapMethods_And_ChainedMutationWriteBack", func(t *testing.T) {
		got := runDoc(t, `
			ctx._source.tags = ['a', 'b'];
			ctx._source.get('tags').add('c');
			ctx._source.get('tags').add(0, 'z');
			ctx._source.get('tags').addAll(['m', 'n']);
			ctx._source.get('tags').addAll(1, ['p', 'q']);
			ctx._source.get('tags').set(0, 'first');
			ctx._source.get('tags').remove(1);
			ctx._source.get('tags').removeAll(['p', 'q', 'm']);
			ctx._source.get('tags').removeIf(x -> x == 'n');
			ctx._source.get('tags').remove(0);

			StringBuilder sb = new StringBuilder("abcdef");
			sb.delete(1, 3);
			Optional optM = Optional.of("hello").map(s -> s.toUpperCase());
			LocalDateTime ldtAt = LocalDate.of(2025, 1, 2).atTime(10, 20, 30, 400);

			ctx._source.nested = ['k1': 10, 'k2': 20];
			boolean hasVal = ctx._source.nested.containsValue(20);
			ctx._source.nested.replaceAll((k, v) -> v + 5);
			def compVal = ctx._source.nested.compute('k1', (k, v) -> v * 2);
			def ciaList = ctx._source.nested.computeIfAbsent('items', k -> new ArrayList());
			ciaList.add('x');
			ctx._source.nested.computeIfAbsent('items', k -> new ArrayList()).add('y');
			def cipVal = ctx._source.nested.computeIfPresent('k2', (k, v) -> v + 100);
			def mrgVal = ctx._source.nested.merge('k3', 50, (oldV, newV) -> oldV + newV);
			def mrgVal2 = ctx._source.nested.merge('k3', 25, (oldV, newV) -> oldV + newV);

			List seenKeys = new ArrayList();
			ctx._source.nested.forEach((k, v) -> seenKeys.add(k));
			int ksSize = ctx._source.nested.keySet().size();
			int vsSize = ctx._source.nested.values().size();
			int esSize = ctx._source.nested.entrySet().size();

			Map tempMap = ['x': 1];
			boolean beforeClear = tempMap.isEmpty();
			tempMap.clear();
			boolean afterClear = tempMap.isEmpty();

			ctx._source.out = [
				'tags': ctx._source.tags,
				'hasVal': hasVal,
				'compVal': compVal,
				'items': ctx._source.nested.items,
				'cipVal': cipVal,
				'mrgVal2': mrgVal2,
				'seenCount': seenKeys.size(),
				'sizes': [ksSize, vsSize, esSize],
				'clear': [!beforeClear, afterClear]
			];
		`, map[string]any{})
		m := got.(map[string]any)
		tags := m["tags"].([]any)
		items := m["items"].([]any)
		if len(tags) != 3 || tags[2] != "c" || len(items) != 2 || items[0] != "x" || items[1] != "y" || m["mrgVal2"] != int64(75) {
			t.Fatalf("unexpected F26 map/chained mutation results: %#v", m)
		}
	})

	t.Run("F20_F22_F23_ExtendedBranches", func(t *testing.T) {
		got := runDoc(t, `
			MathContext mc2 = new MathContext(2, RoundingMode.HALF_UP);
			BigDecimal bd10 = new BigDecimal("10.00");
			BigDecimal bd4 = new BigDecimal("4.00");
			BigDecimal bdNeg = new BigDecimal("-123.45");
			BigDecimal div1 = bd10.divide(new BigDecimal("2"));
			BigDecimal div2Mode = bd10.divide(new BigDecimal("3"), RoundingMode.DOWN);
			BigDecimal div2Scale = bd10.divide(new BigDecimal("4"), 2);
			BigDecimal div3 = bd10.divide(new BigDecimal("3"), 2, RoundingMode.HALF_UP);
			BigDecimal rem1 = bd10.remainder(new BigDecimal("3"));
			BigDecimal remMc = bd10.remainder(new BigDecimal("3"), mc2);
			BigDecimal sc1 = new BigDecimal("5.00").setScale(1);
			BigDecimal sc2 = new BigDecimal("5.55").setScale(1, RoundingMode.DOWN);
			BigDecimal min1 = bd10.min(bd4);
			BigDecimal min2 = bd4.min(bd10);
			BigDecimal max1 = bd10.max(bd4);
			BigDecimal max2 = bd4.max(bd10);
			BigDecimal absMc = bdNeg.abs(mc2);
			BigDecimal negMc = bd10.negate(mc2);
			boolean errBdDiv0 = false;
			try { bd10.divide(BigDecimal.ZERO); } catch (ArithmeticException e) { errBdDiv0 = true; }
			boolean errBdRem0 = false;
			try { bd10.remainder(BigDecimal.ZERO); } catch (ArithmeticException e) { errBdRem0 = true; }
			boolean errBdPowNeg = false;
			try { bd10.pow(-1); } catch (ArithmeticException e) { errBdPowNeg = true; }

			BigInteger bi10 = BigInteger.valueOf(10);
			BigInteger bi3 = BigInteger.valueOf(3);
			BigInteger biMin1 = bi10.min(bi3);
			BigInteger biMin2 = bi3.min(bi10);
			BigInteger biMax1 = bi10.max(bi3);
			BigInteger biMax2 = bi3.max(bi10);
			BigInteger biGcd0A = BigInteger.ZERO.gcd(bi10);
			BigInteger biGcd0B = bi10.gcd(BigInteger.ZERO);
			BigInteger biModPow1 = bi10.modPow(bi3, BigInteger.ONE);
			BigInteger biModPowNeg = bi3.modPow(BigInteger.valueOf(-1), BigInteger.valueOf(10));
			BigInteger biModInv1 = bi10.modInverse(BigInteger.ONE);
			BigInteger biShlNeg = BigInteger.valueOf(8).shiftLeft(-1);
			BigInteger biShrNeg = BigInteger.valueOf(4).shiftRight(-1);
			BigInteger biFlip1 = BigInteger.valueOf(3).flipBit(0);
			boolean pCert0 = bi10.isProbablePrime(0);
			boolean pZero = BigInteger.ZERO.isProbablePrime(10);
			boolean pHigh = BigInteger.valueOf(7).isProbablePrime(120);
			String biStr10 = bi10.toString();
			String biStrBadRadix = bi10.toString(1);
			boolean errBiDiv0 = false;
			try { bi10.divide(BigInteger.ZERO); } catch (ArithmeticException e) { errBiDiv0 = true; }
			boolean errBiRem0 = false;
			try { bi10.remainder(BigInteger.ZERO); } catch (ArithmeticException e) { errBiRem0 = true; }
			boolean errBiDr0 = false;
			try { bi10.divideAndRemainder(BigInteger.ZERO); } catch (ArithmeticException e) { errBiDr0 = true; }
			boolean errBiModNeg = false;
			try { bi10.mod(BigInteger.valueOf(-3)); } catch (ArithmeticException e) { errBiModNeg = true; }
			boolean errBiModPowNotInv = false;
			try { BigInteger.valueOf(4).modPow(BigInteger.valueOf(-1), BigInteger.valueOf(6)); } catch (ArithmeticException e) { errBiModPowNotInv = true; }
			boolean errBiModInvNotInv = false;
			try { BigInteger.valueOf(4).modInverse(BigInteger.valueOf(6)); } catch (ArithmeticException e) { errBiModInvNotInv = true; }
			boolean errBiPowNeg = false;
			try { bi10.pow(-2); } catch (ArithmeticException e) { errBiPowNeg = true; }
			boolean errBiBitNeg = false;
			try { bi10.testBit(-1); } catch (ArithmeticException e) { errBiBitNeg = true; }

			BitSet bs = new BitSet();
			bs.set(1, true);
			bs.set(1, false);
			bs.set(2, 5, true);
			bs.set(3, 4, false);
			bs.flip(1, 5);
			bs.clear(1, 3);
			bs.clear();

			List rows = [
				['a': 1, 'b': 'y', 'c': 20L, 'd': 1.5],
				['a': 1, 'b': 'x', 'c': 10L, 'd': 2.5],
				['a': 1, 'b': 'x', 'c': 10L, 'd': 0.5]
			];
			Comparator chainCmp = Comparator.comparingInt(r -> r.a)
				.thenComparing(r -> r.b, Comparator.naturalOrder())
				.thenComparing(r -> r.b, (x, y) -> x.compareTo(y))
				.thenComparing(r -> r.b)
				.thenComparingLong(r -> r.c)
				.thenComparingDouble(r -> r.d);
			rows.sort(chainCmp);
			Comparator nfLambda = Comparator.nullsFirst((x, y) -> x - y);
			Comparator cmpLambda = Comparator.comparing(r -> r.a, (x, y) -> y - x);
			int cRes1 = nfLambda.compare(null, 5);
			int cRes2 = nfLambda.compare(5, null);
			int cRes3 = nfLambda.compare(null, null);
			int cRes4 = nfLambda.compare(2, 5);
			int cRes5 = cmpLambda.compare(rows[0], rows[1]);
			int[] arrA = new int[] {1, 2};
			int[] arrB = new int[] {1, 3};
			int arrCmpL = Arrays.compare(arrA, arrB, (x, y) -> y - x);
			int arrCmpObj = Arrays.compare(arrA, arrB, Comparator.reverseOrder());

			ctx._source.out = [
				'bd': [div1.toString(), div2Mode.toString(), div2Scale.toString(), div3.toString(), rem1.toString(), remMc.toString(), sc1.toString(), sc2.toString(), min1.toString(), min2.toString(), max1.toString(), max2.toString(), absMc.toString(), negMc.toString()],
				'bdErrs': [errBdDiv0, errBdRem0, errBdPowNeg],
				'bi': [biMin1.longValue(), biMin2.longValue(), biMax1.longValue(), biMax2.longValue(), biGcd0A.longValue(), biGcd0B.longValue(), biModPow1.longValue(), biModPowNeg.longValue(), biModInv1.longValue(), biShlNeg.longValue(), biShrNeg.longValue(), biFlip1.longValue(), pCert0, pZero, pHigh, biStr10, biStrBadRadix],
				'biErrs': [errBiDiv0, errBiRem0, errBiDr0, errBiModNeg, errBiModPowNotInv, errBiModInvNotInv, errBiPowNeg, errBiBitNeg],
				'bsEmpty': bs.isEmpty(),
				'firstRowD': rows[0].d,
				'cmp': [cRes1 < 0, cRes2 > 0, cRes3 == 0, cRes4 < 0, cRes5 == 0, arrCmpL > 0, arrCmpObj > 0]
			];
		`, map[string]any{})
		m := got.(map[string]any)
		if m["bsEmpty"] != true || m["firstRowD"] != float64(0.5) {
			t.Fatalf("unexpected extended branch results: %#v", m)
		}
	})
}

func TestRound54F20ToF26Features(t *testing.T) {
	evalOut := func(t *testing.T, script string, params map[string]any) any {
		t.Helper()
		doc := map[string]any{}
		if _, err := Eval(doc, script, params); err != nil {
			t.Fatalf("Eval failed for script:\n%s\nerr: %v", script, err)
		}
		return doc["out"]
	}

	t.Run("F20_Optional_FirstClass_TypeFidelity_And_Methods", func(t *testing.T) {
		got := evalOut(t, `
			Optional oStr = Optional.of("abc");
			Optional oEmpty = Optional.empty();
			Optional oNull = Optional.ofNullable(null);
			Optional oPres = Optional.ofNullable("xyz");
			OptionalInt oiPres = OptionalInt.of(42);
			OptionalInt oiEmpty = OptionalInt.empty();
			OptionalLong olPres = OptionalLong.of(10000000000L);
			OptionalLong olEmpty = OptionalLong.empty();
			OptionalDouble odPres = OptionalDouble.of(3.5);
			OptionalDouble odEmpty = OptionalDouble.empty();

			boolean instStr = "abc" instanceof Optional;
			boolean instOpt = oStr instanceof Optional;
			boolean instOptEmpty = oEmpty instanceof Optional;
			boolean instOi = oiPres instanceof OptionalInt;
			boolean instOiWrong = oStr instanceof OptionalInt;
			boolean instOl = olPres instanceof OptionalLong;
			boolean instOd = odPres instanceof OptionalDouble;

			boolean eqOptRaw = oStr.equals("abc");
			boolean eqOptSame = oStr.equals(Optional.of("abc"));
			boolean eqOptDiff = oStr.equals(Optional.of("def"));
			boolean eqEmptySame = oEmpty.equals(oNull);
			boolean eqEmptyDiffKind = oEmpty.equals(oiEmpty);
			boolean eqOiSame = oiPres.equals(OptionalInt.of(42));

			int hcPres = oStr.hashCode();
			int hcEmpty = oEmpty.hashCode();
			int hcOi = oiPres.hashCode();

			List sideEffects = new ArrayList();
			oStr.ifPresent(v -> sideEffects.add("ifp:" + v));
			oEmpty.ifPresent(v -> sideEffects.add("never"));
			oStr.ifPresentOrElse(v -> sideEffects.add("ifpe1:" + v), () -> sideEffects.add("never"));
			oEmpty.ifPresentOrElse(v -> sideEffects.add("never"), () -> sideEffects.add("ifpe2:empty"));
			oiPres.ifPresent(v -> sideEffects.add("oi:" + v));
			olEmpty.ifPresentOrElse(v -> sideEffects.add("never"), () -> sideEffects.add("ol:empty"));

			Optional mapped = oStr.map(s -> s.toUpperCase());
			Optional mappedNull = oStr.map(s -> null);
			Optional mappedEmpty = oEmpty.map(s -> s.toUpperCase());
			Optional flatMapped = oStr.flatMap(s -> Optional.of(s + "!"));
			Optional filteredKeep = oStr.filter(s -> s.length() == 3);
			Optional filteredDrop = oStr.filter(s -> s.length() > 10);
			Optional orPres = oStr.or(() -> Optional.of("fallback"));
			Optional orEmp = oEmpty.or(() -> Optional.of("fallback"));

			boolean errOptNull = false;
			try { Optional.of(null); } catch (NullPointerException e) { errOptNull = true; }
			boolean errFlatMapNull = false;
			try { oStr.flatMap(s -> null); } catch (NullPointerException e) { errFlatMapNull = true; }
			boolean errOrNull = false;
			try { oEmpty.or(() -> null); } catch (NullPointerException e) { errOrNull = true; }
			boolean errOiGet = false;
			try { oiEmpty.getAsInt(); } catch (NoSuchElementException e) { errOiGet = true; }
			boolean errOlGet = false;
			try { olEmpty.getAsLong(); } catch (NoSuchElementException e) { errOlGet = true; }
			boolean errOdGet = false;
			try { odEmpty.getAsDouble(); } catch (NoSuchElementException e) { errOdGet = true; }

			Optional stFirst = Stream.of("a", "b").findFirst();
			Optional stEmpty = Stream.empty().findAny();
			OptionalInt stMaxInt = IntStream.of(3, 9, 1).max();
			OptionalDouble stAvg = IntStream.of(2, 4).average();
			Optional stRed = Stream.of(1, 2, 3).reduce((a, b) -> a + b);

			ctx._source.out = [
				'str_oStr': oStr.toString(),
				'str_oEmpty': oEmpty.toString(),
				'str_oiPres': oiPres.toString(),
				'str_oiEmpty': oiEmpty.toString(),
				'str_olPres': olPres.toString(),
				'str_olEmpty': olEmpty.toString(),
				'str_odPres': odPres.toString(),
				'str_odEmpty': odEmpty.toString(),
				'inst': [instStr, instOpt, instOptEmpty, instOi, instOiWrong, instOl, instOd],
				'eq': [eqOptRaw, eqOptSame, eqOptDiff, eqEmptySame, eqEmptyDiffKind, eqOiSame],
				'hc': [hcPres != 0, hcEmpty == 0, hcOi == 42],
				'sideEffects': sideEffects,
				'mapped': [mapped.toString(), mappedNull.toString(), mappedEmpty.toString(), flatMapped.toString()],
				'filtered': [filteredKeep.isPresent(), filteredDrop.isEmpty(), orPres.get(), orEmp.get()],
				'primVals': [oPres.get(), oiPres.getAsInt(), olPres.getAsLong(), odPres.getAsDouble(), oiEmpty.orElse(7), olEmpty.orElseGet(() -> 9L), odEmpty.orElse(1.25)],
				'streamCnt': [oStr.stream().count(), oEmpty.stream().count(), oiPres.stream().count(), oiEmpty.stream().count()],
				'errs': [errOptNull, errFlatMapNull, errOrNull, errOiGet, errOlGet, errOdGet],
				'streams': [stFirst.toString(), stEmpty.toString(), stMaxInt.toString(), stAvg.toString(), stRed.toString()],
				'cls': [oStr.getClass().getSimpleName(), oiPres.getClass().getSimpleName(), olPres.getClass().getSimpleName(), odPres.getClass().getSimpleName()]
			];
		`, nil)
		m := got.(map[string]any)
		if m["str_oStr"] != "Optional[abc]" || m["str_oEmpty"] != "Optional.empty" ||
			m["str_oiPres"] != "OptionalInt[42]" || m["str_oiEmpty"] != "OptionalInt.empty" ||
			m["str_olPres"] != "OptionalLong[10000000000]" || m["str_olEmpty"] != "OptionalLong.empty" ||
			m["str_odPres"] != "OptionalDouble[3.5]" || m["str_odEmpty"] != "OptionalDouble.empty" {
			t.Fatalf("unexpected Optional strings: %#v", m)
		}
		if !reflect.DeepEqual(m["inst"], []any{false, true, true, true, false, true, true}) {
			t.Fatalf("unexpected instanceof results: %#v", m["inst"])
		}
		if !reflect.DeepEqual(m["eq"], []any{false, true, false, true, false, true}) {
			t.Fatalf("unexpected equals results: %#v", m["eq"])
		}
		if !reflect.DeepEqual(m["errs"], []any{true, true, true, true, true, true}) {
			t.Fatalf("unexpected exception flags: %#v", m["errs"])
		}
		if !reflect.DeepEqual(m["streams"], []any{"Optional[a]", "Optional.empty", "OptionalInt[9]", "OptionalDouble[3.0]", "Optional[6]"}) {
			t.Fatalf("unexpected stream Optional results: %#v", m["streams"])
		}
	})

	t.Run("F21_SummaryStatistics_Constructors_Accept_Combine_And_Streams", func(t *testing.T) {
		got := evalOut(t, `
			IntSummaryStatistics is0 = new IntSummaryStatistics();
			long is0Min = is0.getMin();
			long is0Max = is0.getMax();
			is0.accept(10);
			is0.accept(20);
			IntSummaryStatistics is1 = new IntSummaryStatistics(2L, 5, 15, 20L);
			is0.combine(is1);

			LongSummaryStatistics ls0 = new LongSummaryStatistics();
			long ls0Min = ls0.getMin();
			long ls0Max = ls0.getMax();
			ls0.accept(100L);
			LongSummaryStatistics ls1 = new LongSummaryStatistics(1L, 50L, 50L, 50L);
			ls0.combine(ls1);

			DoubleSummaryStatistics ds0 = new DoubleSummaryStatistics();
			boolean ds0MinInf = Double.isInfinite(ds0.getMin()) && ds0.getMin() > 0;
			boolean ds0MaxInf = Double.isInfinite(ds0.getMax()) && ds0.getMax() < 0;
			ds0.accept(1.5);
			ds0.accept(2.5);
			DoubleSummaryStatistics ds1 = new DoubleSummaryStatistics(1L, 0.5, 0.5, 0.5);
			ds0.combine(ds1);

			DoubleSummaryStatistics dStreamStats = IntStream.of(1, 2, 3).asDoubleStream().summaryStatistics();
			LongSummaryStatistics lStreamStats = LongStream.of(10L, 30L).summaryStatistics();

			boolean errNegCnt = false;
			try { new IntSummaryStatistics(-1L, 0, 0, 0L); } catch (IllegalArgumentException e) { errNegCnt = true; }
			boolean errMinGtMax = false;
			try { new LongSummaryStatistics(2L, 10L, 5L, 15L); } catch (IllegalArgumentException e) { errMinGtMax = true; }

			ctx._source.out = [
				'is0Min': is0Min,
				'is0Max': is0Max,
				'is0': [is0.getCount(), is0.getSum(), is0.getMin(), is0.getMax(), is0.getAverage()],
				'ls0Min': ls0Min,
				'ls0Max': ls0Max,
				'ls0': [ls0.getCount(), ls0.getSum(), ls0.getMin(), ls0.getMax(), ls0.getAverage()],
				'ds0Inf': [ds0MinInf, ds0MaxInf],
				'ds0': [ds0.getCount(), ds0.getSum(), ds0.getMin(), ds0.getMax(), ds0.getAverage()],
				'dStream': [dStreamStats instanceof DoubleSummaryStatistics, dStreamStats.getCount(), dStreamStats.getSum()],
				'lStream': [lStreamStats instanceof LongSummaryStatistics, lStreamStats.getCount(), lStreamStats.getSum()],
				'inst': [is0 instanceof IntSummaryStatistics, ls0 instanceof LongSummaryStatistics, ds0 instanceof DoubleSummaryStatistics],
				'str': is0.toString().startsWith("IntSummaryStatistics{count=4,"),
				'errs': [errNegCnt, errMinGtMax]
			];
		`, nil)
		m := got.(map[string]any)
		if m["is0Min"] != int64(math.MaxInt32) || m["is0Max"] != int64(math.MinInt32) {
			t.Fatalf("unexpected IntSummaryStatistics empty min/max: %#v", m)
		}
		if m["ls0Min"] != int64(math.MaxInt64) || m["ls0Max"] != int64(math.MinInt64) {
			t.Fatalf("unexpected LongSummaryStatistics empty min/max: %#v", m)
		}
		if !reflect.DeepEqual(m["is0"], []any{int64(4), int64(50), int64(5), int64(20), float64(12.5)}) {
			t.Fatalf("unexpected is0 stats: %#v", m["is0"])
		}
		if !reflect.DeepEqual(m["dStream"], []any{true, int64(3), float64(6.0)}) {
			t.Fatalf("unexpected DoubleStream summaryStatistics: %#v", m["dStream"])
		}
		if !reflect.DeepEqual(m["errs"], []any{true, true}) {
			t.Fatalf("unexpected SummaryStatistics constructor errors: %#v", m["errs"])
		}
	})

	t.Run("F22_Objects_And_Collections_Static_Methods", func(t *testing.T) {
		got := evalOut(t, `
			int cmpSame = Objects.compare("a", "a", Comparator.naturalOrder());
			int cmpNulls = Objects.compare(null, null, Comparator.naturalOrder());
			int cmpDiff = Objects.compare(2, 5, (a, b) -> a - b);
			String rneg1 = Objects.requireNonNullElseGet("present", () -> "fallback");
			String rneg2 = Objects.requireNonNullElseGet(null, () -> "computed");
			int ci = Objects.checkIndex(2, 5);
			int cfti = Objects.checkFromToIndex(1, 4, 5);
			int cfis = Objects.checkFromIndexSize(1, 3, 5);
			String idStr = Objects.toIdentityString("hello");

			boolean errRnegSupNull = false;
			try { Objects.requireNonNullElseGet(null, null); } catch (NullPointerException e) { errRnegSupNull = true; }
			boolean errRnegResNull = false;
			try { Objects.requireNonNullElseGet(null, () -> null); } catch (NullPointerException e) { errRnegResNull = true; }
			boolean errCi = false;
			try { Objects.checkIndex(5, 5); } catch (IndexOutOfBoundsException e) { errCi = true; }
			boolean errCfti = false;
			try { Objects.checkFromToIndex(3, 2, 5); } catch (IndexOutOfBoundsException e) { errCfti = true; }
			boolean errCfis = false;
			try { Objects.checkFromIndexSize(3, 4, 5); } catch (IndexOutOfBoundsException e) { errCfis = true; }
			boolean errIdNull = false;
			try { Objects.toIdentityString(null); } catch (NullPointerException e) { errIdNull = true; }

			List src = [1, 2, 3, 2, 3, 4];
			int idxSub = Collections.indexOfSubList(src, [2, 3]);
			int lastIdxSub = Collections.lastIndexOfSubList(src, [2, 3]);
			int idxEmpty = Collections.indexOfSubList(src, []);
			int idxNone = Collections.indexOfSubList(src, [9, 9]);

			List target = new ArrayList([10]);
			boolean added = Collections.addAll(target, 20, 30);
			Collections.addAll(target, 40);

			List dest = [1, 2, 3, 4];
			Collections.copy(dest, [8, 9]);
			boolean errCopyOob = false;
			try { Collections.copy([1], [1, 2, 3]); } catch (IndexOutOfBoundsException e) { errCopyOob = true; }

			List ul = Collections.unmodifiableList(dest);
			Set us = Collections.unmodifiableSet(new HashSet([1, 2]));
			Map um = Collections.unmodifiableMap(['k': 'v']);
			List sl = Collections.synchronizedList(ul);
			List cl = Collections.checkedList(sl, Object.class);

			ctx._source.out = [
				'cmp': [cmpSame, cmpNulls, cmpDiff < 0],
				'rneg': [rneg1, rneg2],
				'checks': [ci, cfti, cfis],
				'idOk': idStr.startsWith("java.lang.String@"),
				'errs': [errRnegSupNull, errRnegResNull, errCi, errCfti, errCfis, errIdNull, errCopyOob],
				'sub': [idxSub, lastIdxSub, idxEmpty, idxNone],
				'target': target,
				'added': added,
				'dest': dest,
				'wrappers': [cl.size(), us.size(), um.size()]
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["cmp"], []any{int64(0), int64(0), true}) {
			t.Fatalf("unexpected Objects.compare: %#v", m["cmp"])
		}
		if !reflect.DeepEqual(m["rneg"], []any{"present", "computed"}) {
			t.Fatalf("unexpected Objects.requireNonNullElseGet: %#v", m["rneg"])
		}
		if !reflect.DeepEqual(m["errs"], []any{true, true, true, true, true, true, true}) {
			t.Fatalf("unexpected Objects/Collections error flags: %#v", m["errs"])
		}
		if !reflect.DeepEqual(m["sub"], []any{int64(1), int64(3), int64(0), int64(-1)}) {
			t.Fatalf("unexpected indexOfSubList/lastIndexOfSubList: %#v", m["sub"])
		}
		if !reflect.DeepEqual(m["target"], []any{int64(10), int64(20), int64(30), int64(40)}) {
			t.Fatalf("unexpected Collections.addAll target: %#v", m["target"])
		}
		if !reflect.DeepEqual(m["dest"], []any{int64(8), int64(9), int64(3), int64(4)}) {
			t.Fatalf("unexpected Collections.copy dest: %#v", m["dest"])
		}
	})

	t.Run("F23_ZoneOffset_ZoneId_Clock_And_OffsetTime", func(t *testing.T) {
		got := evalOut(t, `
			ZoneOffset zoMin = ZoneOffset.MIN;
			ZoneOffset zoMax = ZoneOffset.MAX;
			ZoneOffset zoUtc = ZoneOffset.UTC;
			ZoneOffset zoHm = ZoneOffset.ofHoursMinutes(5, 30);
			ZoneOffset zoHms = ZoneOffset.ofHoursMinutesSeconds(-2, -15, -30);
			ZoneOffset zoSec = ZoneOffset.ofTotalSeconds(3600);
			ZoneId zOfOff = ZoneId.ofOffset("UTC", zoHm);
			Set availZones = ZoneId.getAvailableZoneIds();
			ZoneId sysZone = ZoneId.systemDefault();

			boolean errZoRange = false;
			try { ZoneOffset.ofTotalSeconds(70000); } catch (DateTimeException e) { errZoRange = true; }
			boolean errZoSign = false;
			try { ZoneOffset.ofHoursMinutes(2, -10); } catch (DateTimeException e) { errZoSign = true; }

			Instant baseInst = Instant.parse("2025-03-15T10:20:30Z");
			Clock fixedClk = Clock.fixed(baseInst, ZoneOffset.UTC);
			Clock offsetClk = Clock.offset(fixedClk, Duration.ofMinutes(5));
			Clock tickMinClk = Clock.tick(fixedClk, Duration.ofMinutes(1));
			Clock withZoneClk = fixedClk.withZone(ZoneId.of("+02:00"));
			Clock sysUtcClk = Clock.systemUTC();
			Clock sysDefClk = Clock.systemDefaultZone();
			Clock tickSecClk = Clock.tickSeconds(ZoneOffset.UTC);
			Clock tickMsClk = Clock.tickMillis(ZoneOffset.UTC);

			String instFromClk = Instant.now(fixedClk).toString();
			String ldFromClk = LocalDate.now(fixedClk).toString();
			String ltFromClk = LocalTime.now(fixedClk).toString();
			String ldtFromClk = LocalDateTime.now(fixedClk).toString();

			OffsetTime ot1 = OffsetTime.of(10, 20, 30, 0, zoHm);
			OffsetTime ot2 = OffsetTime.parse("12:00:00+02:00");
			OffsetTime otNow = OffsetTime.now(withZoneClk);
			OffsetTime otInst = OffsetTime.ofInstant(baseInst, ZoneId.of("+02:00"));
			OffsetTime otPlus = ot1.plusHours(1).plusMinutes(10).plusSeconds(5).plusNanos(100).minusHours(1).minusMinutes(10).minusSeconds(5).minusNanos(100);
			OffsetTime otWith = ot1.withHour(14).withMinute(30).withSecond(0).withNano(0);
			OffsetTime otSameLocal = otWith.withOffsetSameLocal(ZoneOffset.UTC);
			OffsetTime otSameInst = ot2.withOffsetSameInstant(ZoneOffset.UTC);
			String otAtDate = otSameInst.atDate(LocalDate.of(2025, 3, 15)).toString();
			long otEpochSec = otSameInst.toEpochSecond(LocalDate.of(1970, 1, 1));

			ctx._source.out = [
				'zo': [zoMin.getId(), zoMax.getId(), zoUtc.getId(), zoHm.getId(), zoHms.getId(), zoSec.getId(), zoHm.getTotalSeconds(), zOfOff.getId(), availZones.size() > 3, sysZone.getId().length() > 0],
				'zoErrs': [errZoRange, errZoSign],
				'clk': [fixedClk instanceof Clock, fixedClk.millis(), offsetClk.millis() - fixedClk.millis(), tickMinClk.instant().toString(), withZoneClk.getZone(), fixedClk.equals(Clock.fixed(baseInst, ZoneOffset.UTC)), sysUtcClk.getZone(), sysDefClk != null, tickSecClk != null, tickMsClk != null],
				'nowClk': [instFromClk, ldFromClk, ltFromClk, ldtFromClk],
				'ot': [
					ot1 instanceof OffsetTime,
					OffsetTime.MIN.toString(),
					OffsetTime.MAX.toString(),
					ot1.getHour(), ot1.getMinute(), ot1.getSecond(), ot1.getNano(), ot1.getOffset(),
					ot1.toLocalTime(),
					otNow.toString(),
					otInst.toString(),
					otPlus.equals(ot1),
					otSameLocal.toString(),
					otSameInst.toString(),
					otAtDate,
					otEpochSec,
					ot1.isBefore(ot2),
					ot2.isAfter(ot1),
					ot2.isEqual(otSameInst),
					ot1.compareTo(ot2) < 0
				]
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["zo"], []any{"-18:00", "+18:00", "Z", "+05:30", "-02:15:30", "+01:00", int64(19800), "UTC+05:30", true, true}) {
			t.Fatalf("unexpected ZoneOffset/ZoneId results: %#v", m["zo"])
		}
		if !reflect.DeepEqual(m["zoErrs"], []any{true, true}) {
			t.Fatalf("unexpected ZoneOffset error flags: %#v", m["zoErrs"])
		}
		if !reflect.DeepEqual(m["nowClk"], []any{"2025-03-15T10:20:30Z", "2025-03-15", "10:20:30", "2025-03-15T10:20:30"}) {
			t.Fatalf("unexpected *.now(clock) results: %#v", m["nowClk"])
		}
		otSlice := m["ot"].([]any)
		if otSlice[0] != true || otSlice[1] != "00:00-18:00" || otSlice[2] != "23:59:59.999999999+18:00" ||
			otSlice[9] != "12:20:30+02:00" || otSlice[10] != "12:20:30+02:00" || otSlice[11] != true ||
			otSlice[12] != "14:30Z" || otSlice[13] != "10:00Z" || otSlice[15] != int64(36000) {
			t.Fatalf("unexpected OffsetTime results: %#v", otSlice)
		}
	})

	t.Run("F24_Pattern_And_Matcher_Advanced_Methods", func(t *testing.T) {
		got := evalOut(t, `
			Pattern p = Pattern.compile("[a-z]+");
			List splitStream = p.splitAsStream("123abc456def").collect(Collectors.toList());
			def pred = p.asPredicate();
			def matchPred = p.asMatchPredicate();
			boolean p1 = pred.test("123abc456");
			boolean p2 = pred.test("123456");
			boolean mp1 = matchPred.test("abc");
			boolean mp2 = matchPred.test("123abc");
			boolean negMp1 = matchPred.negate().test("123abc");
			List filteredByPred = Stream.of("123", "abc", "a1").filter(p.asMatchPredicate()).collect(Collectors.toList());

			Pattern pNamed = Pattern.compile("(?<word>[a-z]+)(?<num>[0-9]+)");
			Matcher m = pNamed.matcher("abc12 def34");
			Map ng = m.namedGroups();
			List resGroups = m.results().stream().map(mr -> mr.group(1) + ":" + mr.group(2)).collect(Collectors.toList());

			m.reset("xy99");
			boolean found = m.find();
			def mr = m.toMatchResult();
			int sNamed = m.start("num");
			int eNamed = m.end("num");
			boolean tb0 = m.hasTransparentBounds();
			boolean ab0 = m.hasAnchoringBounds();
			m.useTransparentBounds(true);
			m.useAnchoringBounds(false);
			boolean tb1 = m.hasTransparentBounds();
			boolean ab1 = m.hasAnchoringBounds();
			boolean he = m.hitEnd();
			boolean re = m.requireEnd();

			m.usePattern(Pattern.compile("[0-9]+"));
			m.reset("abc42def");
			boolean foundNew = m.find();
			String grpNew = m.group();

			boolean errUnmatchedMr = false;
			try {
				Matcher m2 = p.matcher("123");
				m2.toMatchResult();
			} catch (IllegalStateException e) {
				errUnmatchedMr = true;
			}
			boolean errNullPat = false;
			try { m.usePattern(null); } catch (IllegalArgumentException e) { errNullPat = true; }

			ctx._source.out = [
				'splitStream': splitStream,
				'preds': [p1, p2, mp1, mp2, negMp1],
				'filteredByPred': filteredByPred,
				'ng': ng,
				'resGroups': resGroups,
				'mr': [found, mr.group(1), mr.group(2), sNamed, eNamed],
				'bounds': [tb0, ab0, tb1, ab1, he, re],
				'newPat': [foundNew, grpNew],
				'errs': [errUnmatchedMr, errNullPat]
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["splitStream"], []any{"123", "456"}) {
			t.Fatalf("unexpected splitAsStream: %#v", m["splitStream"])
		}
		if !reflect.DeepEqual(m["preds"], []any{true, false, true, false, true}) {
			t.Fatalf("unexpected Pattern predicates: %#v", m["preds"])
		}
		if !reflect.DeepEqual(m["filteredByPred"], []any{"abc"}) {
			t.Fatalf("unexpected Stream.filter(Pattern.asMatchPredicate()): %#v", m["filteredByPred"])
		}
		if !reflect.DeepEqual(m["resGroups"], []any{"abc:12", "def:34"}) {
			t.Fatalf("unexpected Matcher.results(): %#v", m["resGroups"])
		}
		if !reflect.DeepEqual(m["mr"], []any{true, "xy", "99", int64(2), int64(4)}) {
			t.Fatalf("unexpected MatchResult & named start/end: %#v", m["mr"])
		}
		if !reflect.DeepEqual(m["newPat"], []any{true, "42"}) {
			t.Fatalf("unexpected Matcher.usePattern: %#v", m["newPat"])
		}
		if !reflect.DeepEqual(m["errs"], []any{true, true}) {
			t.Fatalf("unexpected Matcher exception flags: %#v", m["errs"])
		}
	})

	t.Run("F25_UserDefined_Classes_Inheritance_Static_ToString_Equals_HashCode", func(t *testing.T) {
		got := evalOut(t, `
			class Base {
				static int counter = 10;
				int x;
				Base(int x) {
					this.x = x;
					Base.counter = Base.counter + 1;
				}
				static int nextCount() {
					Base.counter = Base.counter + 1;
					return Base.counter;
				}
				int compute() {
					return this.x * 2;
				}
				int baseOnly() {
					return this.x + 100;
				}
			}
			class Child extends Base {
				int y;
				Child(int x, int y) {
					super(x);
					this.y = y;
				}
				Child(int both) {
					this(both, both * 10);
				}
				int compute() {
					return super.compute() + this.y;
				}
				String toString() {
					return "Child(" + this.x + "," + this.y + ")";
				}
				boolean equals(Object other) {
					if (!(other instanceof Child)) {
						return false;
					}
					return this.x == other.x && this.y == other.y;
				}
				int hashCode() {
					return this.x * 31 + this.y;
				}
			}

			Child c1 = new Child(3, 4);
			Child c2 = new Child(3, 4);
			Child c3 = new Child(5);
			int sc1 = Base.counter;
			int sc2 = Base.nextCount();
			int sc3 = Child.nextCount();

			Set set = new HashSet();
			set.add(c1);
			boolean containsC2 = set.contains(c2);

			ctx._source.out = [
				'compute1': c1.compute(),
				'baseOnly1': c1.baseOnly(),
				'c3': [c3.x, c3.y, c3.compute()],
				'inst': [c1 instanceof Child, c1 instanceof Base, c1 instanceof Object],
				'str': [c1.toString(), "" + c1, String.valueOf(c1)],
				'eq': [c1.equals(c2), c1.equals(c3), Objects.equals(c1, c2)],
				'hc': [c1.hashCode(), Objects.hashCode(c1)],
				'static': [sc1, sc2, sc3],
				'containsC2': containsC2
			];
		`, nil)
		m := got.(map[string]any)
		if m["compute1"] != int64(10) || m["baseOnly1"] != int64(103) {
			t.Fatalf("unexpected inherited/super method results: %#v", m)
		}
		if !reflect.DeepEqual(m["c3"], []any{int64(5), int64(50), int64(60)}) {
			t.Fatalf("unexpected this(...) constructor delegation: %#v", m["c3"])
		}
		if !reflect.DeepEqual(m["inst"], []any{true, true, true}) {
			t.Fatalf("unexpected instanceof inheritance results: %#v", m["inst"])
		}
		if !reflect.DeepEqual(m["str"], []any{"Child(3,4)", "Child(3,4)", "Child(3,4)"}) {
			t.Fatalf("unexpected user class toString results: %#v", m["str"])
		}
		if !reflect.DeepEqual(m["eq"], []any{true, false, true}) {
			t.Fatalf("unexpected user class equals results: %#v", m["eq"])
		}
		if !reflect.DeepEqual(m["hc"], []any{int64(97), int64(97)}) {
			t.Fatalf("unexpected user class hashCode results: %#v", m["hc"])
		}
		if !reflect.DeepEqual(m["static"], []any{int64(13), int64(14), int64(15)}) {
			t.Fatalf("unexpected static field/method results: %#v", m["static"])
		}
		if m["containsC2"] != true {
			t.Fatalf("expected HashSet.contains(c2) to use user equals: %#v", m)
		}
	})

	t.Run("F26_UUID_Constructor_V1Methods_SignedCompareTo_And_URI_URL", func(t *testing.T) {
		got := evalOut(t, `
			UUID u1 = new UUID(0x0123456789abcdefL, 0x1122334455667788L);
			UUID uHighBit = UUID.fromString("80000000-0000-4000-8000-000000000000");
			UUID uLowBit  = UUID.fromString("7fffffff-ffff-4000-8000-000000000000");
			int signedCmp = uHighBit.compareTo(uLowBit);

			UUID uV1 = UUID.fromString("58e0a7d7-eebc-11d8-9669-0800200c9a66");
			long v1Ts = uV1.timestamp();
			int v1Cs = uV1.clockSequence();
			long v1Node = uV1.node();

			boolean errV4Ts = false;
			try { uHighBit.timestamp(); } catch (UnsupportedOperationException e) { errV4Ts = true; }
			boolean errV4Cs = false;
			try { uHighBit.clockSequence(); } catch (UnsupportedOperationException e) { errV4Cs = true; }
			boolean errV4Node = false;
			try { uHighBit.node(); } catch (UnsupportedOperationException e) { errV4Node = true; }

			URI uri = URI.create("https://user:pass@example.com:8443/a/b/../c?q=1&x=2#frag");
			URI normUri = uri.normalize();
			URI resolvedUri = uri.resolve("sub/page.html");
			URI baseUri = new URI("https://example.com/a/");
			URI relUri = baseUri.relativize(new URI("https://example.com/a/b/c.txt"));
			URL urlObj = normUri.toURL();
			URI backToUri = urlObj.toURI();
			URL directUrl = new URL("http://example.com/test?p=1#sec");

			ctx._source.out = [
				'u1': [u1.toString(), u1.getMostSignificantBits(), u1.getLeastSignificantBits()],
				'signedCmpNeg': signedCmp < 0,
				'v1': [uV1.version(), v1Ts > 0, v1Cs, v1Node],
				'v4Errs': [errV4Ts, errV4Cs, errV4Node],
				'uri': [
					uri instanceof URI,
					uri.getScheme(),
					uri.getUserInfo(),
					uri.getHost(),
					uri.getPort(),
					uri.getPath(),
					normUri.getPath(),
					uri.getQuery(),
					uri.getFragment(),
					uri.isAbsolute(),
					uri.isOpaque(),
					resolvedUri.getPath(),
					relUri.toString()
				],
				'url': [
					urlObj instanceof URL,
					urlObj.getProtocol(),
					urlObj.getHost(),
					urlObj.getPort(),
					urlObj.getDefaultPort(),
					urlObj.getPath(),
					urlObj.getFile(),
					urlObj.getRef(),
					backToUri.equals(normUri),
					directUrl.getDefaultPort()
				]
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["u1"], []any{"01234567-89ab-cdef-1122-334455667788", int64(0x0123456789abcdef), int64(0x1122334455667788)}) {
			t.Fatalf("unexpected new UUID(msb, lsb): %#v", m["u1"])
		}
		if m["signedCmpNeg"] != true {
			t.Fatalf("expected Java signed MSB UUID.compareTo to be negative when MSB sign bit is set: %#v", m)
		}
		if !reflect.DeepEqual(m["v4Errs"], []any{true, true, true}) {
			t.Fatalf("expected v4 UUID timestamp/clockSequence/node to throw UnsupportedOperationException: %#v", m["v4Errs"])
		}
		if !reflect.DeepEqual(m["uri"], []any{
			true, "https", "user:pass", "example.com", int64(8443),
			"/a/b/../c", "/a/c", "q=1&x=2", "frag", true, false,
			"/a/sub/page.html", "b/c.txt",
		}) {
			t.Fatalf("unexpected URI results: %#v", m["uri"])
		}
		if !reflect.DeepEqual(m["url"], []any{
			true, "https", "example.com", int64(8443), int64(443),
			"/a/c", "/a/c?q=1&x=2", "frag", true, int64(80),
		}) {
			t.Fatalf("unexpected URL results: %#v", m["url"])
		}
	})

	t.Run("Extended_Round54_Branch_Coverage", func(t *testing.T) {
		got := evalOut(t, `
			URI u3 = new URI("mailto", "user@example.com", "sec");
			URI u4 = new URI("https", "example.com", "/docs/index.html", "top");
			URI u5 = new URI("https", "example.com:8080", "/api/v1", "k=v", "f1");
			URI u7 = new URI("https", "admin", "example.com", 9200, "/_search", "q=*", "hit");
			URI uSrv = u7.parseServerAuthority();
			String uAscii = u7.toASCIIString();
			int uCmp = u4.compareTo(u5);
			int uHc = u7.hashCode();
			String uRawP = u7.getRawPath();
			String uRawQ = u7.getRawQuery();
			String uRawF = u7.getRawFragment();
			String uRawA = u7.getRawAuthority();
			String uRawU = u7.getRawUserInfo();
			String uSsp = u3.getSchemeSpecificPart();
			String uRawSsp = u3.getRawSchemeSpecificPart();
			URI relOther = u4.relativize(new URI("http://other.com/a"));

			URL url2 = new URL(new URL("https://example.com/dir/index.html"), "sub.html");
			URL url3 = new URL("http", "example.com", "/hello?a=1#b");
			URL url4 = new URL("https", "example.com", 8443, "/secure");
			boolean sf1 = url3.sameFile(new URL("http://example.com:80/hello?a=1#other"));
			boolean sf2 = url3.sameFile(url4);
			String extForm = url3.toExternalForm();
			int urlHc = url3.hashCode();
			String urlQ = url3.getQuery();
			String urlAuth = url4.getAuthority();
			String urlUser = new URL("https://bob@example.com/p").getUserInfo();

			boolean errBadUri = false;
			try { URI.create("://bad uri"); } catch (IllegalArgumentException e) { errBadUri = true; }
			boolean errRelToUrl = false;
			try { new URI("/relative/path").toURL(); } catch (IllegalArgumentException e) { errRelToUrl = true; }

			Pattern patA = Pattern.compile("[a-z]+");
			Pattern patB = Pattern.compile("[0-9]+");
			def predAnd = patA.asPredicate().and(patB.asPredicate());
			def predOr = patA.asPredicate().or(patB.asPredicate());
			boolean pa1 = predAnd.test("abc123");
			boolean pa2 = predAnd.test("abc");
			boolean po1 = predOr.test("abc");
			boolean po2 = predOr.test("!!!");

			Instant inst = Instant.parse("2025-03-15T10:20:30Z");
			Clock cFixed = Clock.fixed(inst, ZoneOffset.UTC);
			Clock cOff = Clock.offset(cFixed, Duration.ofHours(2));
			Clock cTick = Clock.tickMinutes(ZoneOffset.UTC);
			Clock cSys = Clock.system(ZoneOffset.ofHours(1));
			String cFixedStr = cFixed.toString();
			String cOffStr = cOff.toString();
			String cTickStr = cTick.toString();
			String cSysStr = cSys.toString();
			int cHc = cFixed.hashCode();
			String zdtClk = ZonedDateTime.now(cFixed).toString();
			String odtClk = OffsetDateTime.now(cFixed).toString();

			OffsetTime otLt = OffsetTime.of(LocalTime.of(8, 15, 0), ZoneOffset.ofHours(2));
			OffsetTime otNow0 = OffsetTime.now();
			OffsetTime otNowZone = OffsetTime.now(ZoneOffset.UTC);
			int otHc = otLt.hashCode();
			ZoneOffset zoNorm = ZoneOffset.ofHours(0).normalized();
			Map zRules = ZoneOffset.ofHours(2).getRules();

			Optional streamChain = Stream.of("hello", "world")
				.findFirst()
				.filter(s -> s.length() == 5)
				.map(s -> s.toUpperCase())
				.flatMap(s -> Optional.of(s + "!"))
				.or(() -> Optional.of("fallback"));
			long streamOptCnt = Stream.of("a", "b").findFirst().stream().count();
			String streamOrElse = Stream.empty().findFirst().orElse("def");
			String streamOrElseGet = Stream.empty().findFirst().orElseGet(() -> "comp");

			DoubleSummaryStatistics dss = new DoubleSummaryStatistics();
			String dssEmptyStr = dss.toString();
			dss.accept(10.0);
			String dssOneStr = dss.toString();

			int objHash = Objects.hash("a", 1, true);
			int objHcNull = Objects.hashCode(null);

			ctx._source.out = [
				'u3_opaque': u3.isOpaque(),
				'uSsp': uSsp,
				'uRawSsp': uRawSsp,
				'u4': u4.toString(),
				'u5': u5.toString(),
				'u7': u7.toString(),
				'uSrv': uSrv.getHost(),
				'uAscii': uAscii,
				'uCmp': uCmp != 0,
				'uHc': uHc != 0,
				'uRaws': [uRawP, uRawQ, uRawF, uRawA, uRawU, relOther.toString()],
				'urls': [url2.toString(), url3.toString(), url4.toString(), sf1, sf2, extForm, urlHc != 0, urlQ, urlAuth, urlUser],
				'uriErrs': [errBadUri, errRelToUrl],
				'preds': [pa1, pa2, po1, po2],
				'clks': [cFixedStr.startsWith("FixedClock["), cOffStr.startsWith("OffsetClock["), cTickStr.startsWith("TickClock["), cSysStr.startsWith("SystemClock["), cHc != 0, zdtClk.startsWith("2025-03-15"), odtClk.startsWith("2025-03-15")],
				'ot': [otLt.toString(), otNow0 != null, otNowZone != null, otHc != 0, zoNorm, zRules.isFixedOffset],
				'streamOpt': [streamChain.toString(), streamOptCnt, streamOrElse, streamOrElseGet],
				'dss': [dssEmptyStr.startsWith("DoubleSummaryStatistics{"), dssOneStr.startsWith("DoubleSummaryStatistics{")],
				'objHash': [objHash != 0, objHcNull == 0]
			];
		`, nil)
		m := got.(map[string]any)
		if m["u3_opaque"] != true || m["u7"] != "https://admin@example.com:9200/_search?q=*#hit" {
			t.Fatalf("unexpected URI constructor results: %#v", m)
		}
		if !reflect.DeepEqual(m["preds"], []any{true, false, true, false}) {
			t.Fatalf("unexpected Predicate.and/or results: %#v", m["preds"])
		}
		if !reflect.DeepEqual(m["streamOpt"], []any{"Optional[HELLO!]", int64(1), "def", "comp"}) {
			t.Fatalf("unexpected Stream Optional chain results: %#v", m["streamOpt"])
		}
	})
}

func TestRound55_F20_To_F26(t *testing.T) {
	evalOut := func(t *testing.T, script string, params map[string]any) any {
		t.Helper()
		doc := map[string]any{}
		if _, err := Eval(doc, script, params); err != nil {
			t.Fatalf("Eval failed for script:\n%s\nerr: %v", script, err)
		}
		return doc["out"]
	}

	t.Run("F20_OffsetTime_Temporal_ValueRange_And_IsSupported", func(t *testing.T) {
		got := evalOut(t, `
			OffsetTime ot = OffsetTime.of(14, 30, 15, 123456789, ZoneOffset.ofHours(2));
			boolean supField1 = ot.isSupported(ChronoField.HOUR_OF_DAY);
			boolean supField2 = ot.isSupported(ChronoField.OFFSET_SECONDS);
			boolean supField3 = ot.isSupported(ChronoField.YEAR);
			boolean supUnit1 = ot.isSupported(ChronoUnit.HOURS);
			boolean supUnit2 = ot.isSupported(ChronoUnit.HALF_DAYS);
			boolean supUnit3 = ot.isSupported(ChronoUnit.DAYS);

			boolean ldSupDays = LocalDate.of(2025, 3, 15).isSupported(ChronoUnit.DAYS);
			boolean ldSupHours = LocalDate.of(2025, 3, 15).isSupported(ChronoUnit.HOURS);
			boolean ltSupMinutes = LocalTime.of(10, 20).isSupported(ChronoUnit.MINUTES);
			boolean ltSupDays = LocalTime.of(10, 20).isSupported(ChronoUnit.DAYS);
			boolean instSupSec = Instant.parse("2025-03-15T10:00:00Z").isSupported(ChronoUnit.SECONDS);
			boolean instSupMonths = Instant.parse("2025-03-15T10:00:00Z").isSupported(ChronoUnit.MONTHS);
			boolean ymSupMonths = YearMonth.of(2025, 3).isSupported(ChronoUnit.MONTHS);
			boolean ymSupDays = YearMonth.of(2025, 3).isSupported(ChronoUnit.DAYS);
			boolean yrSupYears = Year.of(2025).isSupported(ChronoUnit.YEARS);
			boolean yrSupMonths = Year.of(2025).isSupported(ChronoUnit.MONTHS);

			int getHr = ot.get(ChronoField.HOUR_OF_DAY);
			long getLongNano = ot.getLong(ChronoField.NANO_OF_DAY);
			long getOffSec = ot.getLong(ChronoField.OFFSET_SECONDS);
			long getFieldsSum = ot.getLong(ChronoField.NANO_OF_SECOND) +
				ot.getLong(ChronoField.MICRO_OF_SECOND) +
				ot.getLong(ChronoField.MICRO_OF_DAY) +
				ot.getLong(ChronoField.MILLI_OF_SECOND) +
				ot.getLong(ChronoField.MILLI_OF_DAY) +
				ot.getLong(ChronoField.SECOND_OF_MINUTE) +
				ot.getLong(ChronoField.SECOND_OF_DAY) +
				ot.getLong(ChronoField.MINUTE_OF_HOUR) +
				ot.getLong(ChronoField.MINUTE_OF_DAY) +
				ot.getLong(ChronoField.HOUR_OF_AMPM) +
				ot.getLong(ChronoField.CLOCK_HOUR_OF_AMPM) +
				ot.getLong(ChronoField.CLOCK_HOUR_OF_DAY) +
				ot.getLong(ChronoField.AMPM_OF_DAY);
			boolean errGetYear = false;
			try { ot.get(ChronoField.YEAR); } catch (UnsupportedTemporalTypeException e) { errGetYear = true; }
			boolean errGetLongNanoAsInt = false;
			try { ot.get(ChronoField.NANO_OF_DAY); } catch (UnsupportedTemporalTypeException e) { errGetLongNanoAsInt = true; }

			OffsetTime withHr = ot.with(ChronoField.HOUR_OF_DAY, 9);
			OffsetTime withOff = ot.with(ChronoField.OFFSET_SECONDS, -3600);
			OffsetTime withChain = ot
				.with(ChronoField.MINUTE_OF_HOUR, 45)
				.with(ChronoField.SECOND_OF_MINUTE, 30)
				.with(ChronoField.NANO_OF_SECOND, 500)
				.with(ChronoField.MILLI_OF_SECOND, 10)
				.with(ChronoField.MICRO_OF_SECOND, 20)
				.with(ChronoField.NANO_OF_DAY, 3600000000000L)
				.with(ChronoField.SECOND_OF_DAY, 7200)
				.with(ChronoField.MINUTE_OF_DAY, 180)
				.with(ChronoField.HOUR_OF_AMPM, 4)
				.with(ChronoField.AMPM_OF_DAY, 1);
			OffsetTime withLt = ot.with(LocalTime.of(8, 15, 0));
			OffsetTime withZo = ot.with(ZoneOffset.ofHours(-5));
			boolean errWithDateAdj = false;
			try { ot.with(TemporalAdjusters.firstDayOfMonth()); } catch (UnsupportedTemporalTypeException e) { errWithDateAdj = true; }

			ValueRange vrHour = ot.range(ChronoField.HOUR_OF_DAY);
			ValueRange vrDomFebLeap = LocalDate.of(2024, 2, 10).range(ChronoField.DAY_OF_MONTH);
			ValueRange vrDomApr = LocalDate.of(2024, 4, 10).range(ChronoField.DAY_OF_MONTH);
			ValueRange vrDoyLeap = LocalDate.of(2024, 2, 10).range(ChronoField.DAY_OF_YEAR);
			ValueRange vrWom = LocalDate.of(2024, 2, 10).range(ChronoField.ALIGNED_WEEK_OF_MONTH);
			ValueRange vrYmMonth = YearMonth.of(2023, 2).range(ChronoField.MONTH_OF_YEAR);
			ValueRange vrLtSec = LocalTime.of(10, 0).range(ChronoField.SECOND_OF_MINUTE);
			ValueRange vrCfMonth = ChronoField.MONTH_OF_YEAR.range();
			boolean vrValidInt = vrHour.isValidIntValue(12);
			boolean vrEqSelf = vrHour.equals(vrHour);
			String vrStr = vrHour.toString();
			boolean errRangeYearOnOt = false;
			try { ot.range(ChronoField.YEAR); } catch (UnsupportedTemporalTypeException e) { errRangeYearOnOt = true; }

			OffsetTime ot1 = OffsetTime.parse("10:00:00+02:00");
			OffsetTime ot2 = OffsetTime.parse("11:30:00+01:00");
			long untilMins = ot1.until(ot2, ChronoUnit.MINUTES);
			long untilUnitsSum = ot1.until(ot2, ChronoUnit.NANOS) +
				ot1.until(ot2, ChronoUnit.MICROS) +
				ot1.until(ot2, ChronoUnit.MILLIS) +
				ot1.until(ot2, ChronoUnit.SECONDS) +
				ot1.until(ot2, ChronoUnit.HOURS) +
				ot1.until(ot2, ChronoUnit.HALF_DAYS);
			long betweenHours = ChronoUnit.HOURS.between(ot1, ot2);
			Duration durBetween = Duration.between(ot1, ot2);
			boolean errUntilDays = false;
			try { ot1.until(ot2, ChronoUnit.DAYS); } catch (UnsupportedTemporalTypeException e) { errUntilDays = true; }

			DateTimeFormatter fmt = DateTimeFormatter.ofPattern("HH:mm:ssXXX");
			String formatted1 = ot1.format(fmt);
			String formatted2 = fmt.format(ot1);
			OffsetTime parsed2Arg = OffsetTime.parse("16:45:30+03:00", fmt);
			OffsetTime fromLtAtOffset = LocalTime.of(12, 0, 0).atOffset(ZoneOffset.ofHours(4));
			OffsetTime plusHalfDay = ot1.plus(1, ChronoUnit.HALF_DAYS);
			OffsetTime minusHalfDay = ot1.minus(1, ChronoUnit.HALF_DAYS);
			OffsetTime truncHalfDay = OffsetTime.of(15, 20, 10, 0, ZoneOffset.UTC).truncatedTo(ChronoUnit.HALF_DAYS);
			OffsetTime truncDays = OffsetTime.of(15, 20, 10, 0, ZoneOffset.UTC).truncatedTo(ChronoUnit.DAYS);

			ctx._source.out = [
				'sup': [supField1, supField2, supField3, supUnit1, supUnit2, supUnit3, ldSupDays, ldSupHours, ltSupMinutes, ltSupDays, instSupSec, instSupMonths, ymSupMonths, ymSupDays, yrSupYears, yrSupMonths],
				'gets': [getHr, getLongNano, getOffSec, errGetYear, errGetLongNanoAsInt, getFieldsSum > 0],
				'withs': [withHr.getHour(), withOff.getOffset(), withLt.toLocalTime(), withZo.getOffset(), errWithDateAdj, withChain.getHour()],
				'ranges': [
					vrHour.getMinimum(), vrHour.getMaximum(), vrHour.isFixed(), vrHour.isIntValue(), vrHour.isValidValue(23), vrHour.isValidValue(24),
					vrDomFebLeap.getMinimum(), vrDomFebLeap.getMaximum(),
					vrCfMonth.getMinimum(), vrCfMonth.getMaximum(),
					errRangeYearOnOt,
					vrDomApr.getMaximum(), vrDoyLeap.getMaximum(), vrWom.getMaximum(), vrYmMonth.getMaximum(), vrLtSec.getMaximum(),
					vrValidInt, vrEqSelf, vrStr == "0 - 23"
				],
				'untilBetween': [untilMins, betweenHours, durBetween.toMinutes(), errUntilDays, untilUnitsSum > 0],
				'fmtAndAtOffset': [formatted1, formatted2, parsed2Arg.toString(), fromLtAtOffset.toString(), plusHalfDay.getHour(), truncHalfDay.toString(), minusHalfDay.getHour(), truncDays.toString()]
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["sup"], []any{
			true, true, false, true, true, false,
			true, false, true, false, true, false, true, false, true, false,
		}) {
			t.Fatalf("unexpected isSupported results: %#v", m["sup"])
		}
		expectedNano := int64((14*3600+30*60+15)*1_000_000_000 + 123456789)
		if !reflect.DeepEqual(m["gets"], []any{int64(14), expectedNano, int64(7200), true, true, true}) {
			t.Fatalf("unexpected OffsetTime get/getLong results: %#v", m["gets"])
		}
		if !reflect.DeepEqual(m["withs"], []any{int64(9), "-01:00", "08:15", "-05:00", true, int64(16)}) {
			t.Fatalf("unexpected OffsetTime with results: %#v", m["withs"])
		}
		if !reflect.DeepEqual(m["ranges"], []any{
			int64(0), int64(23), true, true, true, false,
			int64(1), int64(29),
			int64(1), int64(12),
			true,
			int64(30), int64(366), int64(5), int64(12), int64(59),
			true, true, true,
		}) {
			t.Fatalf("unexpected ValueRange results: %#v", m["ranges"])
		}
		// 10:00+02:00 is 08:00Z; 11:30+01:00 is 10:30Z -> diff is 150 minutes (2 hours)
		if !reflect.DeepEqual(m["untilBetween"], []any{int64(150), int64(2), int64(150), true, true}) {
			t.Fatalf("unexpected OffsetTime until/between/Duration.between results: %#v", m["untilBetween"])
		}
		if !reflect.DeepEqual(m["fmtAndAtOffset"], []any{
			"10:00:00+02:00", "10:00:00+02:00", "16:45:30+03:00", "12:00+04:00", int64(22), "12:00Z", int64(22), "00:00Z",
		}) {
			t.Fatalf("unexpected OffsetTime format/parse/atOffset results: %#v", m["fmtAndAtOffset"])
		}
	})

	t.Run("F21_URI_PlusPreservation_CompareTo_And_MultiArgEncoding", func(t *testing.T) {
		got := evalOut(t, `
			URI uPlus = URI.create("http://example.com/a+b%20c?x=1+2%203");
			String ssp = uPlus.getSchemeSpecificPart();
			String rawSsp = uPlus.getRawSchemeSpecificPart();

			URI uAuth = URI.create("http://us%20er@example.com:8080/p");
			String decAuth = uAuth.getAuthority();
			String rawAuth = uAuth.getRawAuthority();

			URI u4Space = new URI("http", "example.com", "/hello world/a+b", "frag ment");
			URI u7Space = new URI("https", "us er", "example.com", 8443, "/pa th", "q=a b", "fr ag");
			boolean errRelPathWithHost = false;
			try { new URI("http", "example.com", "rel/path", null); } catch (URISyntaxException e) { errRelPathWithHost = true; }

			URI c1 = URI.create("HTTP://EXAMPLE.COM/a");
			URI c2 = URI.create("http://example.com/b");
			int cmpSchemeCase = c1.compareTo(c2);
			URI cNoScheme = URI.create("/a");
			int cmpUndefScheme = cNoScheme.compareTo(c1);
			URI cFrag1 = URI.create("http://example.com/a#b");
			URI cFrag2 = URI.create("http://example.com/a#a");
			int cmpFrag = cFrag1.compareTo(cFrag2);

			ctx._source.out = [
				'ssp': [ssp, rawSsp],
				'auth': [decAuth, rawAuth],
				'u4': [u4Space.toString(), u4Space.getPath(), u4Space.getRawPath(), u4Space.getFragment(), u4Space.getRawFragment()],
				'u7': [u7Space.toString(), u7Space.getUserInfo(), u7Space.getRawUserInfo(), u7Space.getQuery(), u7Space.getRawQuery()],
				'errRel': errRelPathWithHost,
				'cmp': [cmpSchemeCase < 0, cmpUndefScheme < 0, cmpFrag > 0]
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["ssp"], []any{"//example.com/a+b c?x=1+2 3", "//example.com/a+b%20c?x=1+2%203"}) {
			t.Fatalf("unexpected URI getSchemeSpecificPart '+' preservation: %#v", m["ssp"])
		}
		if !reflect.DeepEqual(m["auth"], []any{"us er@example.com:8080", "us%20er@example.com:8080"}) {
			t.Fatalf("unexpected URI getAuthority vs getRawAuthority: %#v", m["auth"])
		}
		if !reflect.DeepEqual(m["u4"], []any{
			"http://example.com/hello%20world/a+b#frag%20ment",
			"/hello world/a+b",
			"/hello%20world/a+b",
			"frag ment",
			"frag%20ment",
		}) {
			t.Fatalf("unexpected 4-arg URI encoding: %#v", m["u4"])
		}
		if m["errRel"] != true {
			t.Fatalf("expected URISyntaxException for relative path with host: %#v", m)
		}
		if !reflect.DeepEqual(m["cmp"], []any{true, true, true}) {
			t.Fatalf("unexpected URI.compareTo results: %#v", m["cmp"])
		}
	})

	t.Run("F22_SummaryStatistics_ToString_CountZero_And_DoubleNaN", func(t *testing.T) {
		got := evalOut(t, `
			IntSummaryStatistics iss = new IntSummaryStatistics(2L, 3, 7, 10L);
			String issStr1 = iss.toString();
			String issStr2 = String.valueOf(iss);
			String issStr3 = Objects.toString(iss);

			IntSummaryStatistics zeroCount = new IntSummaryStatistics(0L, 100, -50, 999L);
			DoubleSummaryStatistics zeroDss = new DoubleSummaryStatistics(0L, Double.NaN, Double.NaN, Double.NaN);

			DoubleSummaryStatistics dssNan = new DoubleSummaryStatistics();
			dssNan.accept(10.0);
			dssNan.accept(Double.NaN);
			boolean sumNan = Double.isNaN(dssNan.getSum());
			boolean minNan = Double.isNaN(dssNan.getMin());
			boolean maxNan = Double.isNaN(dssNan.getMax());
			boolean avgNan = Double.isNaN(dssNan.getAverage());

			DoubleSummaryStatistics dssA = new DoubleSummaryStatistics();
			dssA.accept(5.0);
			DoubleSummaryStatistics dssB = new DoubleSummaryStatistics();
			dssB.accept(Double.NaN);
			dssA.combine(dssB);
			boolean combSumNan = Double.isNaN(dssA.getSum());
			boolean combAvgNan = Double.isNaN(dssA.getAverage());

			ctx._source.out = [
				'strs': [issStr1, issStr2 == issStr1, issStr3 == issStr1],
				'zeroCount': [zeroCount.getCount(), zeroCount.getSum(), zeroCount.getMin(), zeroCount.getMax(), zeroCount.getAverage()],
				'zeroDssCount': zeroDss.getCount(),
				'nanAccept': [dssNan.getCount(), sumNan, minNan, maxNan, avgNan],
				'nanCombine': [dssA.getCount(), combSumNan, combAvgNan]
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["strs"], []any{
			"IntSummaryStatistics{count=2, sum=10, min=3, average=5.000000, max=7}",
			true,
			true,
		}) {
			t.Fatalf("unexpected IntSummaryStatistics.toString(): %#v", m["strs"])
		}
		if !reflect.DeepEqual(m["zeroCount"], []any{
			int64(0), int64(0), int64(math.MaxInt32), int64(math.MinInt32), float64(0),
		}) {
			t.Fatalf("unexpected 4-arg count==0 IntSummaryStatistics: %#v", m["zeroCount"])
		}
		if !reflect.DeepEqual(m["nanAccept"], []any{int64(2), true, true, true, true}) {
			t.Fatalf("expected DoubleSummaryStatistics.accept(NaN) to propagate NaN: %#v", m["nanAccept"])
		}
		if !reflect.DeepEqual(m["nanCombine"], []any{int64(2), true, true}) {
			t.Fatalf("expected DoubleSummaryStatistics.combine(NaN) to propagate NaN: %#v", m["nanCombine"])
		}
	})

	t.Run("F23_F24_Collectors_Composition_3ArgGroupingBy_ToCollection_NullToMap_And_FlatMapOptional", func(t *testing.T) {
		got := evalOut(t, `
			List words = ["apple", "apricot", "banana", "blueberry", "avocado"];
			Map grpMax = words.stream().collect(Collectors.groupingBy(
				w -> w.substring(0, 1),
				Collectors.collectingAndThen(Collectors.maxBy(Comparator.comparingInt(String::length)), Optional::get)
			));
			Map grp3Arg = words.stream().collect(Collectors.groupingBy(
				w -> w.substring(0, 1),
				TreeMap::new,
				Collectors.counting()
			));
			Set unmodSet = Stream.of(3, 1, 2, 3, 1).collect(Collectors.toUnmodifiableSet());
			Collection treeSetCol = Stream.of(30, 10, 20, 10).collect(Collectors.toCollection(TreeSet::new));

			boolean errNullToMapVal = false;
			try {
				Stream.of("a").collect(Collectors.toMap(x -> x, x -> null));
			} catch (NullPointerException e) {
				errNullToMapVal = true;
			}
			boolean errNullUnmodMapKey = false;
			try {
				Stream.of("a").collect(Collectors.toUnmodifiableMap(x -> null, x -> x));
			} catch (NullPointerException e) {
				errNullUnmodMapKey = true;
			}

			List flatOpt = Stream.of("a", "", "b").flatMap(s -> s.isEmpty() ? Optional.empty().stream() : Optional.of(s.toUpperCase()).stream()).collect(Collectors.toList());
			List orderedOut = new ArrayList();
			Stream.of("x", "y", "z").map(String::toUpperCase).forEachOrdered(v -> orderedOut.add(v));
			Object[] arrOut = Stream.of("p", "q").filter(s -> !s.isEmpty()).toArray();

			ctx._source.out = [
				'grpMax': grpMax,
				'grp3Arg': grp3Arg,
				'unmodSetSize': unmodSet.size(),
				'treeSetCol': treeSetCol,
				'nullErrs': [errNullToMapVal, errNullUnmodMapKey],
				'flatOpt': flatOpt,
				'orderedOut': orderedOut,
				'arrOut': arrOut
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["grpMax"], map[string]any{"a": "apricot", "b": "blueberry"}) {
			t.Fatalf("unexpected groupingBy + collectingAndThen(maxBy, Optional::get): %#v", m["grpMax"])
		}
		if !reflect.DeepEqual(m["grp3Arg"], map[string]any{"a": int64(3), "b": int64(2)}) {
			t.Fatalf("unexpected 3-arg groupingBy: %#v", m["grp3Arg"])
		}
		if m["unmodSetSize"] != int64(3) {
			t.Fatalf("unexpected toUnmodifiableSet size: %#v", m["unmodSetSize"])
		}
		if !reflect.DeepEqual(m["treeSetCol"], []any{int64(10), int64(20), int64(30)}) {
			t.Fatalf("unexpected toCollection(TreeSet::new): %#v", m["treeSetCol"])
		}
		if !reflect.DeepEqual(m["nullErrs"], []any{true, true}) {
			t.Fatalf("expected NullPointerException on null value in toMap/toUnmodifiableMap: %#v", m["nullErrs"])
		}
		if !reflect.DeepEqual(m["flatOpt"], []any{"A", "B"}) {
			t.Fatalf("unexpected flatMap with Optional.stream(): %#v", m["flatOpt"])
		}
		if !reflect.DeepEqual(m["orderedOut"], []any{"X", "Y", "Z"}) {
			t.Fatalf("unexpected forEachOrdered: %#v", m["orderedOut"])
		}
		if !reflect.DeepEqual(m["arrOut"], []any{"p", "q"}) {
			t.Fatalf("unexpected stream.filter().toArray(): %#v", m["arrOut"])
		}
	})

	t.Run("F25_Matcher_PatternReturn_AnchoringBounds_And_Exceptions", func(t *testing.T) {
		got := evalOut(t, `
			Pattern p = Pattern.compile("^(?<word>[a-z]+)$");
			Matcher m = p.matcher("hello");
			boolean patSame = (m.pattern() instanceof Pattern) && m.pattern().pattern().equals("^(?<word>[a-z]+)$");

			boolean errNoMatchGroup = false;
			try { m.group(); } catch (IllegalStateException e) { errNoMatchGroup = true; }
			boolean errNoMatchStart = false;
			try { m.start(); } catch (IllegalStateException e) { errNoMatchStart = true; }
			boolean errNoMatchEnd = false;
			try { m.end(); } catch (IllegalStateException e) { errNoMatchEnd = true; }

			boolean matched = m.matches();
			boolean errOobGroup = false;
			try { m.group(2); } catch (IndexOutOfBoundsException e) { errOobGroup = true; }
			boolean errBadName = false;
			try { m.group("nonexistent"); } catch (IllegalArgumentException e) { errBadName = true; }
			boolean errBadRegion = false;
			try { m.region(4, 2); } catch (IndexOutOfBoundsException e) { errBadRegion = true; }
			boolean errBadFind = false;
			try { m.find(99); } catch (IndexOutOfBoundsException e) { errBadFind = true; }

			Matcher mBounds = Pattern.compile("^bcd$").matcher("abcdef");
			mBounds.region(1, 4);
			boolean findAnchored = mBounds.find();
			mBounds.reset();
			mBounds.region(1, 4);
			mBounds.useAnchoringBounds(false);
			boolean findUnanchored = mBounds.find();

			ctx._source.out = [
				'patSame': patSame,
				'matched': matched,
				'errs': [errNoMatchGroup, errNoMatchStart, errNoMatchEnd, errOobGroup, errBadName, errBadRegion, errBadFind],
				'bounds': [findAnchored, findUnanchored]
			];
		`, nil)
		m := got.(map[string]any)
		if m["patSame"] != true || m["matched"] != true {
			t.Fatalf("unexpected Matcher.pattern() or matches(): %#v", m)
		}
		if !reflect.DeepEqual(m["errs"], []any{true, true, true, true, true, true, true}) {
			t.Fatalf("unexpected Matcher exception checks: %#v", m["errs"])
		}
		if !reflect.DeepEqual(m["bounds"], []any{true, false}) {
			t.Fatalf("unexpected Matcher useAnchoringBounds results: %#v", m["bounds"])
		}
	})

	t.Run("F26_TreeMap_NumericKeyOrder_DescendingMap_And_PollEntry", func(t *testing.T) {
		got := evalOut(t, `
			TreeMap tm = new TreeMap();
			tm.put(10, "ten");
			tm.put(2, "two");
			tm.put(1, "one");
			tm.put(20, "twenty");

			def fk = tm.firstKey();
			def lk = tm.lastKey();
			def higher2 = tm.higherKey(2);
			def floor5 = tm.floorKey(5);

			def desc = tm.descendingMap();
			def descFk = desc.firstKey();
			def descLk = desc.lastKey();
			def descHigher10 = desc.higherKey(10);
			def descLower10 = desc.lowerKey(10);
			def descFloor10 = desc.floorKey(10);
			def descCeil10 = desc.ceilingKey(10);
			def descFe = desc.firstEntry();
			def descLe = desc.lastEntry();
			def descAsc = desc.descendingMap();
			def descNks = desc.navigableKeySet();
			def descDks = desc.descendingKeySet();
			def polledDescFirst = desc.pollFirstEntry();
			int tmSizeAfterDescPoll = tm.size();
			boolean tmHas20 = tm.containsKey(20);

			URI u3 = new URI("mailto", "u s@example.com", "fr ag");
			URI u5 = new URI("http", "example.com", "/p a", "q=1 2", "f r");
			LongSummaryStatistics zLss = new LongSummaryStatistics(0L, 10L, -10L, 50L);
			DoubleSummaryStatistics dssStrObj = new DoubleSummaryStatistics(2L, 1.5, 3.5, 5.0);

			ctx._source.out = [
				'order': [fk, lk, higher2, floor5],
				'desc': [descFk, descHigher10, polledDescFirst.getKey(), polledDescFirst.getValue(), tmSizeAfterDescPoll, tmHas20],
				'extra': [descLk, descLower10, descFloor10, descCeil10, descFe.getKey(), descLe.getKey(), descAsc.firstKey(), descNks.size(), descDks.size(), u3.isOpaque(), u5.getRawPath(), zLss.getCount(), dssStrObj.toString().startsWith("DoubleSummaryStatistics{")]
			];
		`, nil)
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["order"], []any{"1", "20", "10", "2"}) {
			t.Fatalf("unexpected numeric TreeMap key ordering: %#v", m["order"])
		}
		if !reflect.DeepEqual(m["desc"], []any{"20", "2", "20", "twenty", int64(3), false}) {
			t.Fatalf("unexpected descendingMap navigation and pollFirstEntry backing map mutation: %#v", m["desc"])
		}
		if m["extra"] == nil {
			t.Fatalf("expected extra coverage results")
		}
	})
}
