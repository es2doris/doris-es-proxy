package painless

import (
	"encoding/json"
	"reflect"
	"testing"
)

func applyRound39Update(t *testing.T, initialJSON string, script string, params map[string]any) map[string]any {
	t.Helper()
	outBytes, err := ApplyUpdate(json.RawMessage(initialJSON), &UpdateRequest{
		Script: &ScriptSpec{
			Source: script,
			Params: params,
		},
	})
	if err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(outBytes, &out); err != nil {
		t.Fatalf("unmarshal updated JSON failed: %v", err)
	}
	return out
}

func TestRound39_F21_StringLengthRuneCount(t *testing.T) {
	// 1. Eval doc['f'].value.length and params.p.length return Unicode code point count
	doc := map[string]any{"msg": "日本", "emoji": "é"}
	val1, err := Eval(doc, "doc['msg'].value.length", map[string]any{"p": "日本"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val1 != int64(2) {
		t.Fatalf("expected doc['msg'].value.length=2 for '日本', got %v (%T)", val1, val1)
	}
	val2, err := Eval(doc, "params.p.length", map[string]any{"p": "日本"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val2 != int64(2) {
		t.Fatalf("expected params.p.length=2 for '日本', got %v (%T)", val2, val2)
	}

	// 2. ApplyUpdate local string variable .length
	out := applyRound39Update(t, `{"s":"日本語"}`, `def x = ctx._source.s; ctx._source.len = x.length;`, nil)
	if out["len"] != float64(3) {
		t.Fatalf("expected len=3 for '日本語', got %v (%T)", out["len"], out["len"])
	}
}

func TestRound39_F22_TypedLambdaRemoveIf(t *testing.T) {
	script := `
		ctx._source.nums.removeIf((def x) -> x < 3);
		def t = ctx._source.tags;
		boolean removed = t.removeIf((String s) -> s.startsWith('drop'));
		ctx._source.removed = removed;
	`
	out := applyRound39Update(t, `{"nums":[1,2,3,4],"tags":["keep","drop_me","also_keep"]}`, script, nil)
	wantNums := []any{float64(3), float64(4)}
	if !reflect.DeepEqual(out["nums"], wantNums) {
		t.Fatalf("expected nums=%v, got %v", wantNums, out["nums"])
	}
	wantTags := []any{"keep", "also_keep"}
	if !reflect.DeepEqual(out["tags"], wantTags) {
		t.Fatalf("expected tags=%v, got %v", wantTags, out["tags"])
	}
	if out["removed"] != true {
		t.Fatalf("expected removed=true, got %v", out["removed"])
	}
}

func TestRound39_F23_F24_RootAliasPutAndComputeSync(t *testing.T) {
	script := `
		def root = ctx._source;
		root.put('b', 2);
		root.putIfAbsent('c', 3);
		ctx._source?.put('d', 4);
		def sub = ctx._source.m;
		sub.compute('k', (k, v) -> v + 5);
		ctx._source.seen_b = root.b;
		ctx._source.seen_k = sub.k;
	`
	out := applyRound39Update(t, `{"a":1,"m":{"k":10}}`, script, nil)
	if out["b"] != float64(2) || out["c"] != float64(3) || out["d"] != float64(4) {
		t.Fatalf("expected root.put/putIfAbsent/ctx._source?.put mutations on Source, got %+v", out)
	}
	if out["seen_b"] != float64(2) {
		t.Fatalf("expected root alias to see seen_b=2, got %v", out["seen_b"])
	}
	if out["seen_k"] != float64(15) {
		t.Fatalf("expected sub alias to see seen_k=15 after compute, got %v", out["seen_k"])
	}
}
