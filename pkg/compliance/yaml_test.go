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
	"os"
	"path/filepath"
	"testing"
)

func TestYAMLMultilinePlainScalarContinuation(t *testing.T) {
	t.Parallel()
	src := `---
"Create index without soft deletes":
  - skip:
      version: " - 7.5.99"
      reason: indices without soft deletes
        are deprecated in 7.6
  - do:
      warnings:
        - Creating indices with soft-deletes disabled is deprecated and will be removed in future Elasticsearch versions.
          Please do not specify value for setting [index.soft_deletes.enabled] of index [test_index].
      indices.create:
        index: test_index
`
	doc, err := ParseSpecFile(src)
	if err != nil {
		t.Fatalf("ParseSpecFile failed: %v", err)
	}
	if len(doc.Sections) != 1 {
		t.Fatalf("expected 1 section, got %d", len(doc.Sections))
	}
	steps := doc.Sections[0].Steps
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}
	skipMap := ToNative(steps[0].Value).(map[string]any)
	if got := skipMap["reason"]; got != "indices without soft deletes are deprecated in 7.6" {
		t.Fatalf("unexpected folded mapping reason: %q", got)
	}
	doMap := ToNative(steps[1].Value).(map[string]any)
	warns := doMap["warnings"].([]any)
	wantWarn := "Creating indices with soft-deletes disabled is deprecated and will be removed in future Elasticsearch versions. Please do not specify value for setting [index.soft_deletes.enabled] of index [test_index]."
	if len(warns) != 1 || warns[0] != wantWarn {
		t.Fatalf("unexpected folded sequence warning: %#v", warns)
	}
}

func TestYAMLTokenBoundaryApostrophesAndUnreadTrailingLines(t *testing.T) {
	t.Parallel()
	src := `---
Test token_count inside nested field doesn't fail:
  - requires:
      cluster_features: "gte_v7.12.0"
      reason: 'fix introduced in 7.12.0'
  - do:
      search:
        index: test
---
can't shadow dimensions:
  - requires:
      cluster_features: ["gte_v8.1.0"]
      reason: introduced in 8.1.0
  - do:
      catch: /time_series_dimension can't be configured in nested field \[nested.dim\]/
      indices.create:
        index: test
`
	doc, err := ParseSpecFile(src)
	if err != nil {
		t.Fatalf("ParseSpecFile failed on mid-word apostrophes: %v", err)
	}
	if len(doc.Sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(doc.Sections))
	}
	if doc.Sections[0].Name != "Test token_count inside nested field doesn't fail" {
		t.Fatalf("unexpected first section name: %q", doc.Sections[0].Name)
	}
	if doc.Sections[1].Name != "can't shadow dimensions" {
		t.Fatalf("unexpected second section name: %q", doc.Sections[1].Name)
	}

	// Unread trailing content after a scalar root document must error rather than silently truncating.
	bad := "just a scalar\n  key: unexpected_trailing_mapping\n"
	if _, err := ParseYAMLDocuments(bad); err == nil {
		t.Fatalf("expected error on unread trailing mapping lines after root scalar")
	}
}

func TestYAMLFlowSequenceSinglePairMaps(t *testing.T) {
	t.Parallel()
	src := `---
"Simple Composite aggregation":
  - do:
      search:
        index: test
        body:
          aggregations:
            test:
              composite:
                sources: [
                  "histo": {
                    histogram: {
                      field: "val",
                      interval: 5
                    }
                  },
                  plain_key: { terms: { field: "kw" } }
                ]
`
	doc, err := ParseSpecFile(src)
	if err != nil {
		t.Fatalf("ParseSpecFile failed on flow-pair sequence: %v", err)
	}
	doMap := ToNative(doc.Sections[0].Steps[0].Value).(map[string]any)
	searchMap := doMap["search"].(map[string]any)
	bodyMap := searchMap["body"].(map[string]any)
	aggsMap := bodyMap["aggregations"].(map[string]any)
	testAgg := aggsMap["test"].(map[string]any)
	comp := testAgg["composite"].(map[string]any)
	sources, ok := comp["sources"].([]any)
	if !ok || len(sources) != 2 {
		t.Fatalf("expected 2 composite sources, got %#v", comp["sources"])
	}
	first, ok := sources[0].(map[string]any)
	if !ok || first["histo"] == nil {
		t.Fatalf("expected first source to be map with key 'histo', got %#v", sources[0])
	}
	second, ok := sources[1].(map[string]any)
	if !ok || second["plain_key"] == nil {
		t.Fatalf("expected second source to be map with key 'plain_key', got %#v", sources[1])
	}
}

func TestYAMLUpstreamRegressionFilesIfCached(t *testing.T) {
	t.Parallel()
	repoRoot := filepath.Join("..", "..")
	candidates := []string{
		".cache/es-v7.10.2/rest-api-spec/src/main/resources/rest-api-spec/test/indices.create/10_basic.yml",
		".cache/es-v7.10.2/rest-api-spec/src/main/resources/rest-api-spec/test/indices.stats/20_translog.yml",
		".cache/es-v7.10.2/modules/reindex/src/yamlRestTest/resources/rest-api-spec/test/reindex/30_search.yml",
		".cache/es-v7.10.2/rest-api-spec/src/main/resources/rest-api-spec/test/search.aggregation/230_composite.yml",
		".cache/es-v8.15.5/rest-api-spec/src/yamlRestTest/resources/rest-api-spec/test/search/330_fetch_fields.yml",
		".cache/es-v8.15.5/rest-api-spec/src/yamlRestTest/resources/rest-api-spec/test/tsdb/05_dimension_and_metric_in_non_tsdb_index.yml",
		".cache/es-v8.15.5/rest-api-spec/src/yamlRestTest/resources/rest-api-spec/test/indices.put_index_template/15_composition.yml",
	}
	checked := 0
	for _, rel := range candidates {
		full := filepath.Join(repoRoot, rel)
		raw, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		checked++
		specDoc, err := ParseSpecFile(string(raw))
		if err != nil {
			t.Errorf("ParseSpecFile(%s) failed: %v", rel, err)
			continue
		}
		if len(specDoc.Sections) == 0 {
			t.Errorf("ParseSpecFile(%s) returned 0 sections", rel)
		}
	}
	if checked == 0 {
		t.Skip("upstream .cache corpora not present")
	}
}
