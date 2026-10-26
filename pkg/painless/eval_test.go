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
