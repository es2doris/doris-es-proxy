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

package compliance

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

type round60ErrFS struct {
	walkErr bool
	readErr bool
}

func (e round60ErrFS) Open(name string) (fs.File, error) {
	if e.walkErr {
		return nil, errors.New("synthetic walk open failure")
	}
	m := fstest.MapFS{
		"search/10_read_err.yml": &fstest.MapFile{Data: []byte("do:\n  ping: {}\n")},
	}
	if e.readErr && name == "search/10_read_err.yml" {
		return nil, errors.New("synthetic file read failure")
	}
	return m.Open(name)
}

func TestRound60Coverage_ScorecardAndDirectories(t *testing.T) {
	t.Parallel()

	// deriveSpecCategory branches
	catCases := []struct {
		root string
		rel  string
		want string
	}{
		{"/corpus", "specs/search/10_basic.yml", "search"},
		{"/corpus", "./indices.create/10_basic.yml", "indices.create"},
		{"/repo/modules/ingest-common/src/test", "10_basic.yml", "ingest-common"},
		{"/repo/modules/mapper-size", "10_basic.yaml", "mapper-size"},
		{"/tmp/cat.health", "10_basic.yml", "cat.health"},
		{"/tmp/test", "10_basic.yml", "root"},
		{".", "10_basic.yml", "root"},
	}
	for _, tc := range catCases {
		if got := deriveSpecCategory(tc.root, tc.rel); got != tc.want {
			t.Errorf("deriveSpecCategory(%q, %q) = %q, want %q", tc.root, tc.rel, got, tc.want)
		}
	}

	// Nil handler validation
	if _, err := ScoreDirectories(SuiteOptions{}, t.TempDir()); err == nil {
		t.Fatal("expected error when SuiteOptions.NewHandler is nil in ScoreDirectories")
	}
	if _, err := ScoreSuiteFS(SuiteOptions{}, fstest.MapFS{}); err == nil {
		t.Fatal("expected error when SuiteOptions.NewHandler is nil in ScoreSuiteFS")
	}

	stubHandler := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "fail500") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":{"type":"internal_error","reason":"boom"}}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"acknowledged":true,"count":5,"tagline":"You Know, for Search"}`))
		})
	}

	// Missing directory walk error
	if _, err := ScoreDirectories(SuiteOptions{NewHandler: stubHandler}, filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected walk error on nonexistent directory")
	}

	// ScoreSuiteFS walk error and read error
	if _, err := ScoreSuiteFS(SuiteOptions{NewHandler: stubHandler}, round60ErrFS{walkErr: true}); err == nil {
		t.Fatal("expected walk error from round60ErrFS")
	}
	scReadErr, err := ScoreSuiteFS(SuiteOptions{NewHandler: stubHandler}, round60ErrFS{readErr: true})
	if err != nil || scReadErr.ParseErrors != 1 {
		t.Fatalf("expected 1 read/parse error, got %+v, err=%v", scReadErr, err)
	}

	// Populate synthetic directory corpus for ScoreDirectories
	rootDir := t.TempDir()
	flatCatDir := filepath.Join(t.TempDir(), "flatcat")
	if err := os.MkdirAll(flatCatDir, 0o750); err != nil {
		t.Fatal(err)
	}

	writeFixture := func(base, rel, content string) {
		t.Helper()
		full := filepath.Join(base, filepath.FromSlash(rel))
		if mkErr := os.MkdirAll(filepath.Dir(full), 0o750); mkErr != nil {
			t.Fatal(mkErr)
		}
		if wrErr := os.WriteFile(full, []byte(content), 0o600); wrErr != nil {
			t.Fatal(wrErr)
		}
	}

	// Ignored .git directory and non-YAML file
	writeFixture(rootDir, ".git/should_ignore.yml", "invalid: [")
	writeFixture(rootDir, "README.md", "# Not a YAML spec\n")

	// Flat file in named category directory (exercises disp = cat + "/" + relSlash)
	writeFixture(flatCatDir, "10_flat.yml", strings.Join([]string{
		"---",
		"\"Flat pass\":",
		"  - do:",
		"      info: {}",
		"  - match: { tagline: \"You Know, for Search\" }",
		"",
	}, "\n"))

	// Passing + skipped + failing sections (with pipe and long message)
	writeFixture(rootDir, "specs/search/10_mixed.yaml", strings.Join([]string{
		"---",
		"\"Pass section\":",
		"  - do:",
		"      count: {}",
		"  - match: { count: 5 }",
		"---",
		"\"Skipped section\":",
		"  - skip:",
		"      version: \"all\"",
		"      reason: \"intentionally skipped\"",
		"  - do:",
		"      count: {}",
		"---",
		"\"Failed|section\":",
		"  - do:",
		"      count: {}",
		"  - match: { tagline: \"" + strings.Repeat("expected_mismatch_with_pipe|char_", 7) + "\" }",
		"",
	}, "\n"))

	// File-level skip via top-level skip
	writeFixture(rootDir, "specs/indices/10_skip_file.yml", strings.Join([]string{
		"---",
		"skip:",
		"  version: \"all\"",
		"  reason: \"skip whole file\"",
		"---",
		"\"Never runs\":",
		"  - do:",
		"      info: {}",
		"",
	}, "\n"))

	// File-level skip via top-level requires
	writeFixture(rootDir, "specs/indices/20_requires_file.yml", strings.Join([]string{
		"---",
		"requires:",
		"  cluster_features: [\"missing_round60_cluster_feature\"]",
		"  reason: \"feature not supported\"",
		"---",
		"\"Never runs requires\":",
		"  - do:",
		"      info: {}",
		"",
	}, "\n"))

	// File-level skip via setup skip step
	writeFixture(rootDir, "specs/indices/30_setup_skip.yml", strings.Join([]string{
		"---",
		"setup:",
		"  - skip:",
		"      features: [\"unsupported_runner_feature_xyz\"]",
		"---",
		"\"Skipped via setup\":",
		"  - do:",
		"      info: {}",
		"",
	}, "\n"))

	// Parse error YAML
	writeFixture(rootDir, "specs/indices/40_broken.yml", "---\n\"Broken\":\n  - do: [unclosed\n")

	// Setup failure & teardown failure
	writeFixture(rootDir, "specs/cluster/10_setup_err.yml", strings.Join([]string{
		"---",
		"setup:",
		"  - do:",
		"      indices.create:",
		"        index: fail500",
		"---",
		"\"After failed setup\":",
		"  - do:",
		"      info: {}",
		"",
	}, "\n"))

	writeFixture(rootDir, "specs/cluster/20_teardown_err.yml", strings.Join([]string{
		"---",
		"teardown:",
		"  - do:",
		"      indices.delete:",
		"        index: fail500",
		"---",
		"\"Fails in teardown\":",
		"  - do:",
		"      info: {}",
		"",
	}, "\n"))

	// Excluded by Categories filter
	writeFixture(rootDir, "specs/filtered_out/10_ignored.yml", "---\n\"Ignored\":\n  - do:\n      info: {}\n")

	sc, err := ScoreDirectories(SuiteOptions{
		CorpusName:    "",
		TargetVersion: "",
		Categories:    []string{"flatcat", "search", "indices", "cluster"},
		NewHandler:    stubHandler,
	}, rootDir, flatCatDir)
	if err != nil {
		t.Fatalf("ScoreDirectories failed: %v", err)
	}
	if sc.Corpus != "rest-api-spec" || sc.TargetVersion != defaultScorecardTargetVersion {
		t.Fatalf("unexpected defaults: corpus=%q target=%q", sc.Corpus, sc.TargetVersion)
	}
	if sc.FilesSkipped != 3 || sc.ParseErrors != 1 || sc.SectionsPassed != 2 || sc.SectionsFailed < 3 {
		t.Fatalf("unexpected scorecard counts: %+v", sc)
	}

	// ScoreSuiteFS happy path with .git and non-yaml ignored
	mapFS := fstest.MapFS{
		".git/config":          &fstest.MapFile{Data: []byte("ignore")},
		"notes.txt":            &fstest.MapFile{Data: []byte("ignore")},
		"ping/10_ping_ok.yaml": &fstest.MapFile{Data: []byte("---\n\"Ping\":\n  - do:\n      info: {}\n")},
	}
	scFS, err := ScoreSuiteFS(SuiteOptions{
		CorpusName:                  "mem-fs",
		TargetVersion:               "8.15.0",
		SupportedClusterFeatures:    map[string]bool{"gte_v8.0.0": true},
		SupportedTestRunnerFeatures: map[string]bool{"warnings": true},
		NewHandler:                  stubHandler,
	}, mapFS)
	if err != nil || scFS.SectionsPassed != 1 {
		t.Fatalf("unexpected ScoreSuiteFS result: %+v, err=%v", scFS, err)
	}

	// executeScoredSection panic recovery & setup skip inside executeScoredSection
	panicHandler := func() http.Handler { panic("synthetic handler panic") }
	if skipped, pErr := executeScoredSection(panicHandler, "7.17.0", nil, nil, &SpecDocument{}, SpecSection{Name: "p"}); skipped || pErr == nil || !strings.Contains(pErr.Error(), "panic:") {
		t.Fatalf("expected recovered panic error, got skipped=%v, err=%v", skipped, pErr)
	}
	setupSkipDoc, err := ParseSpecFile("---\nsetup:\n  - skip:\n      version: all\n      reason: skip in setup\n")
	if err != nil {
		t.Fatalf("ParseSpecFile setupSkipDoc failed: %v", err)
	}
	if skipped, sErr := executeScoredSection(stubHandler, "7.17.0", nil, nil, setupSkipDoc, SpecSection{Name: "s"}); !skipped || sErr != nil {
		t.Fatalf("expected setup skip inside executeScoredSection, got skipped=%v, err=%v", skipped, sErr)
	}

	// FormatMarkdown & WriteJSON edge cases
	var nilSC *SuiteScorecard
	if nilSC.FormatMarkdown() != "" {
		t.Fatal("expected empty string from nil SuiteScorecard.FormatMarkdown")
	}
	if err := nilSC.WriteJSON(filepath.Join(t.TempDir(), "out.json")); err == nil {
		t.Fatal("expected error writing nil SuiteScorecard")
	}
	if computePassRatePct(0, 0) != 0 {
		t.Fatal("expected 0 pass rate when passed+failed == 0")
	}

	for i := 0; i < 30; i++ {
		sc.FailureSamples = append(sc.FailureSamples, SectionFailure{
			File:     fmt.Sprintf("cat/file_%d.yml", i),
			Category: "cat",
			Section:  "sec|pipe",
			Error:    "line1\nline2|" + strings.Repeat("x", 190),
		})
	}
	md := sc.FormatMarkdown()
	if !strings.Contains(md, "showing 25 of") || !strings.Contains(md, "...") {
		t.Fatalf("expected truncated FailureSamples in Markdown, got:\n%s", md)
	}

	jsonOutPath := filepath.Join(t.TempDir(), "sub", "nested", "scorecard.json")
	if err := sc.WriteJSON(jsonOutPath); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if raw, err := os.ReadFile(jsonOutPath); err != nil || len(raw) == 0 { // #nosec G304 -- temp test file
		t.Fatalf("failed reading written scorecard JSON: %v", err)
	}
	// WriteJSON error when target path is an existing directory
	if err := sc.WriteJSON(t.TempDir()); err == nil {
		t.Fatal("expected error when WriteJSON path is a directory")
	}
}

func TestRound60Coverage_SpecSchemaValidatorBranches(t *testing.T) {
	t.Parallel()

	// specTypeKey.String with and without namespace
	if got := (specTypeKey{Name: "Plain"}).String(); got != "Plain" {
		t.Fatalf("expected Plain, got %q", got)
	}
	if got := (specTypeKey{Namespace: "ns", Name: "Plain"}).String(); got != "ns.Plain" {
		t.Fatalf("expected ns.Plain, got %q", got)
	}

	// ParseSpecSchemaValidator error paths
	for _, badSchema := range []string{
		`{bad_json`,
		`{"types":[{"kind":"type_alias","name":{"name":"A","namespace":"t"},"type":{"kind":"array_of","value":123}}]}`,
		`{"types":[{"kind":"type_alias","name":{"name":"A","namespace":"t"},"type":{"kind":"literal_value","value":{bad}}}]}`,
	} {
		if _, err := ParseSpecSchemaValidator([]byte(badSchema)); err == nil {
			t.Fatalf("expected ParseSpecSchemaValidator error on %s", badSchema)
		}
	}

	// LoadSpecSchemaValidator missing file + valid synthetic schema file in t.TempDir()
	if _, err := LoadSpecSchemaValidator(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected LoadSpecSchemaValidator error on missing file")
	}

	const richSchema = `{
  "endpoints": [
    { "name": "" },
    {
      "name": "cat.plain_only",
      "response": { "name": "CatTextResponse", "namespace": "cat" },
      "responseMediaType": ["text/plain"]
    },
    {
      "name": "cat.dual",
      "response": { "name": "CatDualResponse", "namespace": "cat" },
      "responseMediaType": ["text/plain", "application/json"]
    },
    {
      "name": "cat.dual_obj",
      "response": { "name": "ObjResponse", "namespace": "test" },
      "responseMediaType": ["text/plain", "application/json"]
    },
    {
      "name": "untyped.text",
      "response": null,
      "responseMediaType": ["text/plain"]
    },
    {
      "name": "missing.resp",
      "response": { "name": "DoesNotExist", "namespace": "test" },
      "responseMediaType": ["application/json"]
    },
    {
      "name": "test.obj",
      "response": { "name": "ObjResponse", "namespace": "test" },
      "responseMediaType": ["application/json"]
    },
    {
      "name": "test.int_dict",
      "response": { "name": "IntKeyDictResponse", "namespace": "test" }
    },
    {
      "name": "test.bool_dict",
      "response": { "name": "BoolKeyDictResponse", "namespace": "test" }
    },
    {
      "name": "test.union_ifaces",
      "response": { "name": "UnionIfaceResponse", "namespace": "test" }
    },
    {
      "name": "test.inherited_nobody",
      "response": { "name": "InheritedResponseNoBody", "namespace": "test" }
    }
  ],
  "types": [
    { "kind": "interface", "name": { "name": "", "namespace": "skip" } },
    {
      "kind": "type_alias",
      "name": { "name": "CatTextResponse", "namespace": "cat" },
      "type": { "kind": "instance_of", "type": { "name": "string", "namespace": "_builtins" } }
    },
    {
      "kind": "type_alias",
      "name": { "name": "CatDualResponse", "namespace": "cat" },
      "type": { "kind": "instance_of", "type": { "name": "string", "namespace": "_builtins" } }
    },
    {
      "kind": "type_alias",
      "name": { "name": "integer", "namespace": "_types" },
      "type": { "kind": "instance_of", "type": { "name": "number", "namespace": "_builtins" } }
    },
    {
      "kind": "enum",
      "name": { "name": "BoolEnum", "namespace": "test" },
      "isOpen": false,
      "members": [
        { "name": "only_str" },
        { "name": "true" }
      ]
    },
    {
      "kind": "response",
      "name": { "name": "ParentRespProps", "namespace": "test" },
      "generics": [
        { "name": "TGen", "namespace": "test.ParentRespProps" },
        { "name": "TUnbound", "namespace": "test.ParentRespProps" }
      ],
      "body": {
        "kind": "properties",
        "properties": [
          {
            "name": "overridden",
            "required": false,
            "type": { "kind": "instance_of", "type": { "name": "string", "namespace": "_builtins" } }
          },
          {
            "name": "gen_dict",
            "required": false,
            "type": {
              "kind": "dictionary_of",
              "key": { "kind": "instance_of", "type": { "name": "string", "namespace": "_builtins" } },
              "value": { "kind": "instance_of", "type": { "name": "TGen", "namespace": "test.ParentRespProps" } }
            }
          },
          {
            "name": "gen_union",
            "required": false,
            "type": {
              "kind": "union_of",
              "items": [
                { "kind": "instance_of", "type": { "name": "TGen", "namespace": "test.ParentRespProps" } },
                { "kind": "instance_of", "type": { "name": "null", "namespace": "_builtins" } }
              ]
            }
          }
        ]
      }
    },
    {
      "kind": "response",
      "name": { "name": "ObjResponse", "namespace": "test" },
      "inherits": {
        "type": { "name": "ParentRespProps", "namespace": "test" },
        "generics": [
          { "kind": "instance_of", "type": { "name": "integer", "namespace": "_types" } }
        ]
      },
      "body": {
        "kind": "properties",
        "properties": [
          {
            "name": "overridden",
            "required": false,
            "type": { "kind": "instance_of", "type": { "name": "boolean", "namespace": "_builtins" } }
          },
          {
            "name": "opt_str",
            "required": false,
            "type": { "kind": "instance_of", "type": { "name": "string", "namespace": "_builtins" } }
          },
          {
            "name": "bin_field",
            "required": false,
            "type": { "kind": "instance_of", "type": { "name": "binary", "namespace": "_builtins" } }
          },
          {
            "name": "void_field",
            "required": false,
            "type": { "kind": "instance_of", "type": { "name": "void", "namespace": "_builtins" } }
          },
          {
            "name": "bool_enum",
            "required": false,
            "type": { "kind": "instance_of", "type": { "name": "BoolEnum", "namespace": "test" } }
          }
        ]
      }
    },
    {
      "kind": "response",
      "name": { "name": "InheritedResponseNoBody", "namespace": "test" },
      "inherits": {
        "type": { "name": "ParentRespProps", "namespace": "test" },
        "generics": [
          { "kind": "instance_of", "type": { "name": "string", "namespace": "_builtins" } }
        ]
      }
    },
    {
      "kind": "response",
      "name": { "name": "IntKeyDictResponse", "namespace": "test" },
      "body": {
        "kind": "value",
        "value": {
          "kind": "dictionary_of",
          "key": { "kind": "instance_of", "type": { "name": "integer", "namespace": "_types" } },
          "value": { "kind": "instance_of", "type": { "name": "string", "namespace": "_builtins" } }
        }
      }
    },
    {
      "kind": "response",
      "name": { "name": "BoolKeyDictResponse", "namespace": "test" },
      "body": {
        "kind": "value",
        "value": {
          "kind": "dictionary_of",
          "key": { "kind": "instance_of", "type": { "name": "boolean", "namespace": "_builtins" } },
          "value": { "kind": "instance_of", "type": { "name": "boolean", "namespace": "_builtins" } }
        }
      }
    },
    {
      "kind": "interface",
      "name": { "name": "VariantA", "namespace": "test" },
      "properties": [
        { "name": "alpha_only", "required": false, "type": { "kind": "instance_of", "type": { "name": "string", "namespace": "_builtins" } } }
      ]
    },
    {
      "kind": "interface",
      "name": { "name": "VariantB", "namespace": "test" },
      "properties": [
        { "name": "beta_only", "required": false, "type": { "kind": "instance_of", "type": { "name": "number", "namespace": "_builtins" } } }
      ]
    },
    {
      "kind": "response",
      "name": { "name": "UnionIfaceResponse", "namespace": "test" },
      "body": {
        "kind": "value",
        "value": {
          "kind": "union_of",
          "items": [
            { "kind": "instance_of", "type": { "name": "VariantA", "namespace": "test" } },
            { "kind": "instance_of", "type": { "name": "VariantB", "namespace": "test" } }
          ]
        }
      }
    }
  ]
}`

	schemaFile := filepath.Join(t.TempDir(), "schema.json")
	if err := os.WriteFile(schemaFile, []byte(richSchema), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := LoadSpecSchemaValidator(schemaFile)
	if err != nil {
		t.Fatalf("LoadSpecSchemaValidator failed: %v", err)
	}

	// Media-type and untyped branches
	if err := v.ValidateEndpointResponse("untyped.text", nil); err != nil {
		t.Fatalf("untyped empty failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("untyped.text", []byte("plain text output\n")); err != nil {
		t.Fatalf("untyped plain text failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("untyped.text", []byte("{malformed")); err == nil {
		t.Fatal("expected error on malformed JSON starting with '{' on untyped.text")
	}
	if err := v.ValidateEndpointResponse("missing.resp", []byte(`{}`)); err == nil {
		t.Fatal("expected error when endpoint response type is missing")
	}
	if err := v.ValidateEndpointResponse("cat.plain_only", nil); err != nil {
		t.Fatalf("cat.plain_only empty failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("cat.plain_only", []byte("green open idx\n")); err != nil {
		t.Fatalf("cat.plain_only non-empty failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("cat.dual", []byte("green open idx\n")); err != nil {
		t.Fatalf("cat.dual text fallback failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("cat.dual_obj", []byte("not json and not string response")); err == nil {
		t.Fatal("expected cat.dual_obj non-JSON text to fail object response validation")
	}

	// test.obj: overridden property, optional explicit null, binary, void, bool enum, substituted dictionary & union
	validObj := `{
		"overridden": true,
		"opt_str": null,
		"bin_field": "YWJj",
		"void_field": {},
		"bool_enum": true,
		"gen_dict": {"a": 10},
		"gen_union": null
	}`
	if err := v.ValidateEndpointResponse("test.obj", []byte(validObj)); err != nil {
		t.Fatalf("validObj failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("test.obj", []byte(`{"bin_field":[1,2],"void_field":null,"gen_union":5}`)); err != nil {
		t.Fatalf("validObj byte-array binary failed: %v", err)
	}
	for _, badObj := range []string{
		`{"bin_field": 123}`,
		`{"void_field": {"non_empty": 1}}`,
		`{"bool_enum": false}`,
		`{"bool_enum": 123}`,
		`{"gen_dict": {"a": null}}`,
		`{"gen_dict": "not_a_dict"}`,
		`{} {bad`,
	} {
		if err := v.ValidateEndpointResponse("test.obj", []byte(badObj)); err == nil {
			t.Fatalf("expected error on test.obj payload %s", badObj)
		}
	}

	// Numeric & boolean dictionary keys
	if err := v.ValidateEndpointResponse("test.int_dict", []byte(`{"0": "shard0", "200": "ok"}`)); err != nil {
		t.Fatalf("int_dict valid failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("test.int_dict", []byte(`{"not_int": "x"}`)); err == nil {
		t.Fatal("expected int_dict non-integer key error")
	}
	if err := v.ValidateEndpointResponse("test.bool_dict", []byte(`{"true": true, "false": false}`)); err != nil {
		t.Fatalf("bool_dict valid failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("test.bool_dict", []byte(`{"maybe": true}`)); err == nil {
		t.Fatal("expected bool_dict non-boolean key error")
	}

	// Union of all-optional interfaces (exercises matchedDeclared == 0 rejection)
	if err := v.ValidateEndpointResponse("test.union_ifaces", []byte(`{"beta_only": 42}`)); err != nil {
		t.Fatalf("union_ifaces VariantB failed: %v", err)
	}
	if err := v.ValidateEndpointResponse("test.union_ifaces", []byte(`{"completely_unrelated": 1}`)); err == nil {
		t.Fatal("expected union_ifaces unrelated key error")
	}
	if err := v.ValidateEndpointResponse("test.inherited_nobody", []byte(`{"gen_dict":{"k":"v"}}`)); err != nil {
		t.Fatalf("inherited_nobody valid failed: %v", err)
	}

	// Direct internal helper edge cases for complete coverage of schemavalidator.go
	if err := v.validateTypeExpr("$", "x", specTypeExpr{Kind: "instance_of"}, nil, maxSchemaTypeExpansionDepth+1); err != nil {
		t.Fatalf("expected depth guard nil, got %v", err)
	}
	if err := v.validateTypeExpr("$", []any{1, 2}, specTypeExpr{Kind: "array_of"}, nil, 0); err != nil {
		t.Fatalf("expected untyped array_of nil, got %v", err)
	}
	if err := v.validateTypeExpr("$", "x", specTypeExpr{Kind: "union_of"}, nil, 0); err != nil {
		t.Fatalf("expected empty union_of nil, got %v", err)
	}
	if err := v.validateTypeExpr("$", "x", specTypeExpr{Kind: "instance_of", Type: nil}, nil, 0); err != nil {
		t.Fatalf("expected nil-Type instance_of nil, got %v", err)
	}
	if err := v.validateTypeExpr("$", "x", specTypeExpr{Kind: "instance_of", Type: &specTypeName{Name: "Ghost", Namespace: "ns"}}, nil, 0); err == nil {
		t.Fatal("expected missing schema type error")
	}
	if err := v.validateTypeExpr("$", "x", specTypeExpr{Kind: "unsupported_expr_kind"}, nil, 0); err == nil {
		t.Fatal("expected unsupported expr kind error")
	}
	if err := v.validateDictionaryKey("$", "k", specTypeExpr{Kind: "user_defined_value"}, maxSchemaTypeExpansionDepth+1); err != nil {
		t.Fatalf("expected dictionary key depth guard nil, got %v", err)
	}
	if err := v.validateNamedType("$", "x", specTypeDef{Kind: "type_alias"}, nil, maxSchemaTypeExpansionDepth+1); err != nil {
		t.Fatalf("expected namedType depth guard nil, got %v", err)
	}
	if err := v.validateNamedType("$", "x", specTypeDef{Kind: "type_alias", Type: nil}, nil, 0); err != nil {
		t.Fatalf("expected nil type_alias nil, got %v", err)
	}
	if err := v.validateNamedType("$", "x", specTypeDef{Kind: "response", Body: nil}, nil, 0); err != nil {
		t.Fatalf("expected nil response body nil, got %v", err)
	}
	if err := v.validateNamedType("$", nil, specTypeDef{Kind: "response", Body: &specResponseBody{Kind: "no_body"}}, nil, 0); err != nil {
		t.Fatalf("expected nil value on no_body response nil, got %v", err)
	}
	if err := v.validateNamedType("$", "non_nil", specTypeDef{Kind: "response", Body: &specResponseBody{Kind: "no_body"}}, nil, 0); err == nil {
		t.Fatal("expected error for non-nil value on no_body response")
	}
	if err := v.validateNamedType("$", "x", specTypeDef{Kind: "response", Body: &specResponseBody{Kind: "value", Value: nil}}, nil, 0); err != nil {
		t.Fatalf("expected nil value-expr response nil, got %v", err)
	}
	if err := v.validateNamedType("$", "x", specTypeDef{Kind: "response", Body: &specResponseBody{Kind: "weird_body"}}, nil, 0); err == nil {
		t.Fatal("expected unsupported response body kind error")
	}
	if err := v.validateNamedType("$", "x", specTypeDef{Kind: "other_def_kind"}, nil, 0); err != nil {
		t.Fatalf("expected unknown def kind nil, got %v", err)
	}
	if err := validateBuiltinType("$", 1, "unknown_builtin"); err == nil {
		t.Fatal("expected unknown builtin error")
	}

	// Cyclic & missing parent in collectObjectHierarchy
	v.types[specTypeKey{Namespace: "cyc", Name: "A"}] = specTypeDef{
		Kind:     "interface",
		Name:     specTypeName{Namespace: "cyc", Name: "A"},
		Inherits: &specInheritsSpec{Type: specTypeName{Namespace: "cyc", Name: "B"}},
	}
	v.types[specTypeKey{Namespace: "cyc", Name: "B"}] = specTypeDef{
		Kind:     "interface",
		Name:     specTypeName{Namespace: "cyc", Name: "B"},
		Inherits: &specInheritsSpec{Type: specTypeName{Namespace: "cyc", Name: "A"}},
	}
	if _, _, err := v.collectObjectHierarchy(v.types[specTypeKey{Namespace: "cyc", Name: "A"}], nil, nil, make(map[specTypeKey]bool)); err != nil {
		t.Fatalf("expected cyclic hierarchy termination, got %v", err)
	}
	missingParentDef := specTypeDef{
		Kind:     "interface",
		Name:     specTypeName{Namespace: "cyc", Name: "Orphan"},
		Inherits: &specInheritsSpec{Type: specTypeName{Namespace: "cyc", Name: "MissingParent"}},
	}
	if _, _, err := v.collectObjectHierarchy(missingParentDef, nil, nil, make(map[specTypeKey]bool)); err == nil {
		t.Fatal("expected missing parent hierarchy error")
	}

	// Numeric, literal, and JSON-kind helpers
	for _, n := range []any{json.Number("42"), json.Number("18446744073709551615"), json.Number("4.0"), float64(8), int(3), int64(-2), uint(5), uint64(9)} {
		if !isSchemaJSONNumber(n) {
			t.Fatalf("expected isSchemaJSONNumber(%v)=true", n)
		}
		if ok, _ := isIntegralNumber(n); !ok {
			t.Fatalf("expected isIntegralNumber(%v)=true", n)
		}
	}
	if isValidJSONNumber("") || isSchemaJSONNumber(math.NaN()) || isSchemaJSONNumber("str") {
		t.Fatal("expected non-numbers to return false")
	}
	if ok, _ := isIntegralNumber(json.Number("not_num")); ok {
		t.Fatal("expected non-numeric json.Number integral=false")
	}
	if ok, _ := isIntegralNumber(math.Inf(1)); ok {
		t.Fatal("expected +Inf integral=false")
	}
	if ok, _ := isIntegralNumber("str"); ok {
		t.Fatal("expected string integral=false")
	}

	if !schemaLiteralEquals(nil, nil) || schemaLiteralEquals(nil, 1) {
		t.Fatal("unexpected nil literal equality")
	}
	if !schemaLiteralEquals(true, true) || !schemaLiteralEquals(float64(5), float64(5)) || !schemaLiteralEquals(json.Number("5"), json.Number("5")) {
		t.Fatal("unexpected scalar literal equality")
	}
	if schemaLiteralEquals("x", json.Number("5")) || schemaLiteralEquals("x", float64(5)) {
		t.Fatal("unexpected mismatched literal equality")
	}

	kinds := []any{nil, true, "short", strings.Repeat("long_string_", 5), json.Number("12"), float64(3.5), []any{1}, map[string]any{"a": 1}, struct{}{}}
	for _, kv := range kinds {
		if s := describeJSONKind(kv); s == "" {
			t.Fatalf("expected non-empty describeJSONKind for %T", kv)
		}
	}
}

func TestRound60Coverage_YAMLAnchorsMergesAndFolding(t *testing.T) {
	t.Parallel()

	yamlDoc := strings.Join([]string{
		"---",
		"header_note: |",
		"  setup header doc",
		"---",
		"\"Anchors and merges\":",
		"  - do:",
		"      index:",
		"        index: &idx_name",
		"          orders_idx",
		"        id: &inline_id 101",
		"        body:",
		"          base1: &b1",
		"            a: 1",
		"            nested: [10, 20]",
		"          base2: &b2",
		"            b: 'it''s quoted'",
		"          merged:",
		"            <<: [*b1, *b2]",
		"            c: \"line1\\",
		"              ",
		"              line2\\t  \"",
		"          flow_arr: [&fa 'x''y', *fa]",
		"          empty_at_dedent:",
		"          after_empty: *idx_name",
		"",
	}, "\n")

	docs, err := ParseYAMLDocuments(yamlDoc)
	if err != nil || len(docs) != 2 {
		t.Fatalf("ParseYAMLDocuments failed: len=%d, err=%v", len(docs), err)
	}
}
