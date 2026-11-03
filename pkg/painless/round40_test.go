package painless

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRound40_F21_InternalSentinelKeysFilteredFromCtxSourceMapMethods(t *testing.T) {
	script := `
		def x = 42;
		ctx._source.sz = ctx._source.size();
		ctx._source.empty_check = ctx._source.isEmpty();
		ctx._source.has_locals = ctx._source.containsKey('__script_locals');
		ctx._source.has_id = ctx._source.containsKey('__meta_id');
		def keys = [];
		for (k in ctx._source.keySet()) {
			if (k == 'a') {
				keys.add(k);
			}
			if (k.startsWith('__')) {
				ctx._source.leaked_key = k;
			}
		}
		ctx._source.keys = keys;
		def entryKeys = [];
		ctx._source.forEach((k, v) -> {
			if (k.startsWith('__')) {
				ctx._source.leaked_foreach = k;
			}
		});
	`
	req := &UpdateRequest{
		Script:      &ScriptSpec{Source: script},
		MetaID:      "doc-1",
		MetaIndex:   "idx-1",
		MetaRouting: "r-1",
		MetaVersion: 3,
	}
	outBytes, opRes, err := ApplyUpdateWithResult(json.RawMessage(`{"a": 1}`), req, true)
	if err != nil {
		t.Fatalf("ApplyUpdateWithResult failed: %v", err)
	}
	if opRes != "updated" {
		t.Fatalf("expected opRes='updated', got %q", opRes)
	}
	var out map[string]any
	if err := json.Unmarshal(outBytes, &out); err != nil {
		t.Fatal(err)
	}
	if out["sz"] != float64(1) {
		t.Fatalf("expected ctx._source.size() == 1 before mutations, got %v", out["sz"])
	}
	if out["empty_check"] != false {
		t.Fatalf("expected isEmpty()==false, got %v", out["empty_check"])
	}
	if out["has_locals"] != false || out["has_id"] != false {
		t.Fatalf("expected containsKey on internal sentinels to be false, got has_locals=%v has_id=%v", out["has_locals"], out["has_id"])
	}
	if _, leaked := out["leaked_key"]; leaked {
		t.Fatalf("internal key leaked into keySet(): %v", out["leaked_key"])
	}
	if _, leaked := out["leaked_foreach"]; leaked {
		t.Fatalf("internal key leaked into forEach(): %v", out["leaked_foreach"])
	}
}

func TestRound40_F22_LambdaParameterDoesNotClobberOuterLocal(t *testing.T) {
	script := `
		def x = 100;
		ctx._source.arr.removeIf(x -> x < 2);
		ctx._source.list2.forEach(x -> { def tmp = x + 1; });
		ctx._source.x_after = x;
	`
	out := applyRound39Update(t, `{"arr": [1, 2, 3], "list2": [10, 20]}`, script, nil)
	if out["x_after"] != float64(100) {
		t.Fatalf("expected outer local x to remain 100 after removeIf/forEach lambdas with param x, got %v", out["x_after"])
	}
	if !reflect.DeepEqual(out["arr"], []any{float64(2), float64(3)}) {
		t.Fatalf("unexpected arr after removeIf: %v", out["arr"])
	}
}

func TestRound40_F23_F26_CtxRoutingInLoopAndMetaOp(t *testing.T) {
	req := &UpdateRequest{
		Script: &ScriptSpec{
			Source: `
				for (int i = 0; i < 1; i++) {
					ctx._routing = 'loop-route';
				}
				ctx.op = 'create';
				ctx._source.v = 2;
			`,
		},
		MetaID:      "1",
		MetaIndex:   "idx",
		MetaRouting: "initial-route",
	}
	_, opRes, err := ApplyUpdateWithResult(json.RawMessage(`{"v": 1}`), req, true)
	if err != nil {
		t.Fatalf("ApplyUpdateWithResult failed: %v", err)
	}
	if req.MetaRouting != "loop-route" {
		t.Fatalf("expected MetaRouting='loop-route' after for loop mutation, got %q", req.MetaRouting)
	}
	if req.MetaOp != "create" || opRes != "created" {
		t.Fatalf("expected MetaOp='create' and opRes='created', got MetaOp=%q opRes=%q", req.MetaOp, opRes)
	}
}

func TestRound40_F27_F30_SourceBracketAccessAndListRemoveInUpdate(t *testing.T) {
	script := `
		def k = 'tags';
		_source[k].remove(1);
		_source['tags'].remove('drop_val');
		_source[k].add('added');
	`
	out := applyRound39Update(t, `{"tags": ["first", "second", "drop_val", "third"]}`, script, nil)
	want := []any{"first", "third", "added"}
	if !reflect.DeepEqual(out["tags"], want) {
		t.Fatalf("expected tags=%v, got %v", want, out["tags"])
	}
}
