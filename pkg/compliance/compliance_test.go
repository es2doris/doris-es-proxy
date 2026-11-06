package compliance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/es2doris/doris-es-proxy/pkg/proxy"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRunEmbeddedSuite(t *testing.T) {
	backend := proxy.NewMemoryBackend(false)
	srv := proxy.NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	RunEmbeddedSuite(t, ts.URL)

	report := RunSuiteFS(t, EmbeddedSpecsFS, ts.URL)
	if report.FilesRun != 10 {
		t.Fatalf("expected 10 embedded spec files, got %d", report.FilesRun)
	}
	if report.SectionsRun < 50 {
		t.Fatalf("expected at least 50 spec test sections, got %d", report.SectionsRun)
	}
}

func TestYAMLParserFeaturesAndEdgeCases(t *testing.T) {
	yamlText := `
# Header comment
---
setup:
  - do:
      indices.create:
        index: 'single''quoted_idx'
        body:
          settings: { number_of_shards: 1, "quoted_key": "line1\nline2\r\t\b\f\u0041\/\\" }
teardown:
  - do:
      indices.delete:
        index: 'single''quoted_idx'
---
"Literal and folded blocks":
  - do:
      bulk:
        body: |
          {"index":{"_index":"idx1","_id":"1"}}
          {"msg":"hello"}
  - match:
      folded_str: >-
        hello
        world
      literal_strip: |-
        lineA
        lineB
      literal_keep: |+
        lineC

      null_val: ~
      empty_key:
      bool_true: TRUE
      bool_false: False
      float_val: 3.14
      seq_dash:
        -
          nested_k: nested_v
        - |-
          seq_block_scalar
        - [ 1, 2, { a: "b" } ]
        -
...
`
	spec, err := ParseSpecFile(yamlText)
	if err != nil {
		t.Fatalf("ParseSpecFile failed: %v", err)
	}
	if len(spec.Setup) != 1 || len(spec.Teardown) != 1 || len(spec.Sections) != 1 {
		t.Fatalf("unexpected spec counts: setup=%d teardown=%d sections=%d", len(spec.Setup), len(spec.Teardown), len(spec.Sections))
	}

	native := ToNative(spec.Sections[0].Steps[1].Value).(map[string]any)
	if native["folded_str"] != "hello world" {
		t.Fatalf("unexpected folded_str: %q", native["folded_str"])
	}
	if native["literal_strip"] != "lineA\nlineB" {
		t.Fatalf("unexpected literal_strip: %q", native["literal_strip"])
	}
	if !strings.HasPrefix(native["literal_keep"].(string), "lineC\n") {
		t.Fatalf("unexpected literal_keep: %q", native["literal_keep"])
	}
	if native["null_val"] != nil || native["empty_key"] != nil || native["bool_true"] != true || native["bool_false"] != false {
		t.Fatalf("unexpected scalar types in %#v", native)
	}

	// Test OrderedMap update existing key & ToNative on value OrderedMap
	om := NewOrderedMap()
	om.Set("a", 1)
	om.Set("a", 2)
	if v, ok := om.Get("a"); !ok || v != 2 {
		t.Fatalf("expected updated key a=2, got %v (%v)", v, ok)
	}
	if _, ok := om.Get("missing"); ok {
		t.Fatalf("expected missing key to return false")
	}
	if _, ok := (*OrderedMap)(nil).Get("a"); ok {
		t.Fatalf("expected nil OrderedMap.Get to return false")
	}
	_ = ToNative(*om)
	_ = ToNative((*OrderedMap)(nil))
	_ = ToNative(map[string]any{"nested": *om})

	// Error cases in YAML parser
	badYAMLs := []string{
		"- not_a_top_level_map\n",
		"sec:\n  not_a_seq: 1\n",
		"sec:\n  - just_a_scalar\n",
		"sec:\n  - do: { unclosed\n",
		"sec:\n  - do: [ 1, 2\n",
		"sec:\n  - do: \"\\u12\"\n",
		"sec:\n  - do: \"trailing\\\"\n",
		"sec:\n  - do:\n      a: 1\n        bad_indent: 2\n",
	}
	for _, bad := range badYAMLs {
		if _, err := ParseSpecFile(bad); err == nil {
			t.Errorf("expected error for invalid YAML %q", bad)
		}
	}
}

func TestRunnerAssertionsAndCatchVariants(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name": "doris-es-proxy",
			"indices": {
				"my.dotted.idx": {
					"count": 15,
					"ratio": 0.75,
					"tags": ["a", "b"],
					"meta": {"k": "v"}
				}
			}
		}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	specFS := fstest.MapFS{
		"specs/custom.yml": &fstest.MapFile{
			Data: []byte(`---
setup:
  - do:
      info: {}
teardown:
  - do:
      indices.delete:
        index: non_existent_teardown_idx
---
"Escaped dot paths comparisons and headers":
  - do:
      headers:
        X-Custom-Test: "1"
      ignore: [ 200, "404" ]
      info: {}
  - set: { "indices.my\\.dotted\\.idx.count": cnt }
  - match: { "indices.my\\.dotted\\.idx.count": $cnt }
  - match: { "indices.my\\.dotted\\.idx.tags": [ "a", "b" ] }
  - match: { "indices.my\\.dotted\\.idx.meta": { k: "v" } }
  - length: { name: 14 }
  - length: { "indices.my\\.dotted\\.idx.tags": 2 }
  - length: { "indices.my\\.dotted\\.idx.meta": 1 }
  - gt: { "indices.my\\.dotted\\.idx.count": 10 }
  - gte: { "indices.my\\.dotted\\.idx.count": 15 }
  - lt: { "indices.my\\.dotted\\.idx.count": 20 }
  - lte: { "indices.my\\.dotted\\.idx.count": 15 }
  - gt: { "indices.my\\.dotted\\.idx.ratio": 0.5 }
`),
		},
	}

	rep := RunSuiteFS(t, specFS, ts.URL)
	if rep.FilesRun != 1 || rep.SectionsRun != 1 {
		t.Fatalf("unexpected report: %+v", rep)
	}

	// Direct unit tests for verifyCatch, assertions, and buildActionRequest branches
	ctx := newRunnerContext(ts.Client(), ts.URL)
	if err := ctx.verifyCatch("forbidden", "test", http.StatusForbidden, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := ctx.verifyCatch("unauthorized", "test", http.StatusUnauthorized, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := ctx.verifyCatch("request_timeout", "test", http.StatusRequestTimeout, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := ctx.verifyCatch("/security_exception/", "test", http.StatusForbidden, `{"error":{"type":"security_exception","reason":"denied"}}`, map[string]any{
		"error": map[string]any{"type": "security_exception", "reason": "denied"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ctx.verifyCatch("/str_err/", "test", http.StatusBadRequest, `{"error":"str_err"}`, map[string]any{
		"error": "str_err",
	}); err != nil {
		t.Fatal(err)
	}
	// Negative catch tests
	for _, negCatch := range []string{"missing", "bad_request", "conflict", "forbidden", "unauthorized", "request_timeout", "/regex/", "unknown_catch"} {
		if err := ctx.verifyCatch(negCatch, "test", http.StatusOK, "ok", nil); err == nil {
			t.Fatalf("expected error for verifyCatch(%q) on 200 OK", negCatch)
		}
	}

	// Negative step assertion tests
	ctx.lastResponse = map[string]any{"num": int64(5), "flag": true, "str": "abc"}
	ctx.lastMethod = http.MethodGet
	ctx.lastStatus = http.StatusOK
	if err := ctx.execStep(SpecStep{Op: "unknown_op"}, false); err == nil {
		t.Fatal("expected error on unknown op")
	}
	if err := ctx.execCompare("gt", map[string]any{"num": 10}); err == nil {
		t.Fatal("expected gt failure")
	}
	if err := ctx.execCompare("lt", map[string]any{"num": 1}); err == nil {
		t.Fatal("expected lt failure")
	}
	if err := ctx.execLength(map[string]any{"str": 99}); err == nil {
		t.Fatal("expected length mismatch failure")
	}
	if err := ctx.execMatch(map[string]any{"str": "xyz"}); err == nil {
		t.Fatal("expected match mismatch failure")
	}
	if err := ctx.execMatch(map[string]any{"str": "/^xyz$/"}); err == nil {
		t.Fatal("expected regex match mismatch failure")
	}
	if err := ctx.execIsTrue("missing_field"); err == nil {
		t.Fatal("expected is_true failure on missing field")
	}
	if err := ctx.execIsFalse("flag"); err == nil {
		t.Fatal("expected is_false failure on true flag")
	}
	if _, ok := toFloat64(json.Number("12.5")); !ok {
		t.Fatal("expected json.Number conversion to succeed")
	}
	if _, ok := toFloat64("12.5"); !ok {
		t.Fatal("expected string float conversion to succeed")
	}
	_ = parseIgnoreStatuses(404)
	_ = parseIgnoreStatuses(int64(404))
	_ = parseIgnoreStatuses(float64(404))

	// Exercise remaining action builders with default/optional parameters and missing required parameters
	actionsToBuild := []struct {
		action string
		params map[string]any
	}{
		{"indices.get_mapping", map[string]any{}},
		{"indices.get_mapping", map[string]any{"index": "idx"}},
		{"indices.get_field_mapping", map[string]any{"fields": "f1"}},
		{"indices.get_field_mapping", map[string]any{"index": "idx", "fields": []any{"f1", "f2"}}},
		{"indices.get_settings", map[string]any{}},
		{"indices.get_settings", map[string]any{"index": "idx"}},
		{"indices.put_settings", map[string]any{}},
		{"indices.put_settings", map[string]any{"index": "idx", "body": `{"index":{}}`}},
		{"indices.get_alias", map[string]any{}},
		{"indices.get_alias", map[string]any{"index": "idx"}},
		{"indices.get_alias", map[string]any{"name": "al"}},
		{"indices.get_alias", map[string]any{"index": "idx", "name": "al"}},
		{"indices.exists_alias", map[string]any{}},
		{"indices.exists_alias", map[string]any{"index": "idx"}},
		{"indices.exists_alias", map[string]any{"name": "al"}},
		{"indices.exists_alias", map[string]any{"index": "idx", "name": "al"}},
		{"indices.refresh", map[string]any{}},
		{"indices.refresh", map[string]any{"index": "idx"}},
		{"indices.flush", map[string]any{}},
		{"indices.flush", map[string]any{"index": "idx"}},
		{"indices.forcemerge", map[string]any{}},
		{"indices.forcemerge", map[string]any{"index": "idx"}},
		{"indices.stats", map[string]any{}},
		{"indices.stats", map[string]any{"index": "idx"}},
		{"indices.validate_query", map[string]any{}},
		{"indices.validate_query", map[string]any{"index": "idx"}},
		{"indices.analyze", map[string]any{"text": "hello world", "analyzer": "standard"}},
		{"indices.analyze", map[string]any{"index": "idx", "body": map[string]any{"text": "hi"}}},
		{"indices.rollover", map[string]any{"alias": "al"}},
		{"indices.rollover", map[string]any{"alias": "al", "new_index": "idx2"}},
		{"indices.get_index_template", map[string]any{}},
		{"indices.get_index_template", map[string]any{"name": "t1"}},
		{"cluster.get_component_template", map[string]any{}},
		{"cluster.get_component_template", map[string]any{"name": "ct1"}},
		{"cluster.health", map[string]any{"index": "idx"}},
		{"mget", map[string]any{}},
		{"mget", map[string]any{"index": "idx"}},
		{"bulk", map[string]any{"body": `{"index":{"_index":"i","_id":"1"}}` + "\n" + `{"a":1}`}},
		{"bulk", map[string]any{"index": "idx", "body": []any{`{"index":{"_index":"i","_id":"1"}}`, map[string]any{"a": 1}}}},
		{"bulk", map[string]any{"body": map[string]any{"index": map[string]any{"_index": "i"}}}},
		{"search", map[string]any{}},
		{"search", map[string]any{"index": "idx", "ignore": nil}},
		{"msearch", map[string]any{}},
		{"msearch", map[string]any{"index": "idx"}},
		{"count", map[string]any{}},
		{"count", map[string]any{"index": "idx"}},
		{"field_caps", map[string]any{"body": map[string]any{"fields": []any{"*"}}}},
		{"field_caps", map[string]any{"index": "idx"}},
		{"scroll", map[string]any{"scroll_id": "s1", "scroll": "1m"}},
		{"clear_scroll", map[string]any{"scroll_id": "s1"}},
		{"ingest.get_pipeline", map[string]any{}},
		{"ingest.get_pipeline", map[string]any{"id": "p1"}},
		{"ingest.simulate", map[string]any{"id": "p1"}},
		{"ingest.simulate", map[string]any{}},
		{"cat.indices", map[string]any{}},
		{"cat.indices", map[string]any{"index": "idx"}},
		{"cat.aliases", map[string]any{}},
		{"cat.aliases", map[string]any{"name": "al"}},
		{"cat.count", map[string]any{}},
		{"cat.count", map[string]any{"index": "idx"}},
		{"cat.shards", map[string]any{}},
		{"cat.shards", map[string]any{"index": "idx"}},
		{"close_point_in_time", map[string]any{"id": "pit1"}},
	}
	for _, tc := range actionsToBuild {
		if _, err := ctx.buildActionRequest(tc.action, tc.params); err != nil {
			t.Fatalf("buildActionRequest(%s) failed: %v", tc.action, err)
		}
	}

	// Missing parameter error paths in buildActionRequest
	errActions := []string{
		"indices.create", "indices.delete", "indices.exists", "indices.get",
		"indices.put_mapping", "indices.get_field_mapping", "indices.put_alias",
		"indices.delete_alias", "indices.rollover", "indices.put_index_template",
		"indices.delete_index_template", "indices.exists_index_template",
		"cluster.put_component_template", "cluster.delete_component_template",
		"cluster.exists_component_template", "index", "create", "get", "get_source",
		"exists", "exists_source", "delete", "update", "explain", "terms_enum",
		"open_point_in_time", "update_by_query", "delete_by_query",
		"ingest.put_pipeline", "ingest.delete_pipeline", "nonexistent.action",
	}
	for _, act := range errActions {
		if _, err := ctx.buildActionRequest(act, map[string]any{}); err == nil {
			t.Fatalf("expected error for buildActionRequest(%s) with empty params", act)
		}
	}

	// Exercise resource tracking, stash expansion, lookupResponsePath, valuesEqual, and isTruthy edge cases
	ctx.trackCreatedResources("indices.create", map[string]any{"index": "idx1,idx2"}, nil)
	ctx.trackCreatedResources("bulk", map[string]any{
		"index": "idx_bulk",
		"body":  []any{map[string]any{"index": map[string]any{"_index": "idx_b2"}}},
	}, nil)
	ctx.trackCreatedResources("reindex", map[string]any{
		"body": map[string]any{"dest": map[string]any{"index": "idx_re"}},
	}, nil)
	ctx.trackCreatedResources("indices.rollover", map[string]any{"new_index": "idx_ro1"}, map[string]any{"new_index": "idx_ro2"})
	ctx.trackCreatedResources("indices.put_alias", map[string]any{"index": "idx1", "name": "al1"}, nil)
	ctx.trackCreatedResources("indices.put_index_template", map[string]any{"name": "tpl1"}, nil)
	ctx.trackCreatedResources("cluster.put_component_template", map[string]any{"name": "ct1"}, nil)
	ctx.trackCreatedResources("ingest.put_pipeline", map[string]any{"id": "pipe1"}, nil)
	ctx.cleanupAll()

	ctx.stash["k"] = "v"
	omVal := NewOrderedMap()
	omVal.Set("$k", "$k/sub")
	_ = ctx.expandStash(omVal)
	_ = ctx.expandStash(*omVal)
	_ = ctx.expandStash((*OrderedMap)(nil))
	_ = ctx.expandStash(map[string]any{"$k": []any{"$k", "$missing"}})

	ctx.lastResponse = map[string]any{"arr": []any{map[string]any{"x": 1}}}
	if v, ok := ctx.lookupResponsePath("$body"); !ok || v == nil {
		t.Fatal("expected $body lookup to succeed")
	}
	if v, ok := ctx.lookupResponsePath("arr.0.x"); !ok || v != 1 {
		t.Fatalf("expected arr.0.x=1, got %v (%v)", v, ok)
	}
	if _, ok := ctx.lookupResponsePath("arr.99.x"); ok {
		t.Fatal("expected out-of-bounds array index to fail")
	}
	if _, ok := ctx.lookupResponsePath("arr.0.x.sub"); ok {
		t.Fatal("expected scalar traversal to fail")
	}
	for _, tv := range []any{nil, false, true, 0, 1, int64(0), int64(2), float64(0), float64(1.5), "", "false", "0", "yes", struct{}{}} {
		_ = isTruthy(tv)
	}
	_ = valuesEqual(nil, nil)
	_ = valuesEqual(nil, 1)
	_ = valuesEqual(map[string]any{"a": 1}, map[string]any{"a": 1, "b": 2})
	_ = valuesEqual(map[string]any{"a": 1}, map[string]any{"b": 1})
	_ = valuesEqual([]any{1}, []any{1, 2})
	_ = valuesEqual([]any{1}, []any{2})
}
