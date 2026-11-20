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

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

func TestRound63Wave3_EndToEndCrossSliceStitchAndPolish(t *testing.T) {
	backend := NewMemoryBackend(false)
	srv := NewServer("es_compat", backend, transpiler.TranspilerOptions{})
	srv.SetTargetESVersion("8.15.5")
	t.Cleanup(func() { _ = srv.Close(context.Background()) })
	h := srv.Handler()

	// 1. Deprecation warnings on create index: `unicodeSetFilter` & `aggregate_metric_double` multifields
	code, hdrs, _ := doTestJSONReqR63(t, h, http.MethodPut, "/warn_idx", `{
		"settings": {
			"analysis": {
				"char_filter": {
					"cf": {"type": "icu_normalizer", "unicodeSetFilter": "[a-z]"}
				}
			}
		},
		"mappings": {
			"properties": {
				"agg_m": {
					"type": "aggregate_metric_double",
					"metrics": ["min", "max"],
					"default_metric": "max",
					"fields": {"sub": {"type": "double"}}
				}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 creating warn_idx, got %d", code)
	}
	warnJoined := strings.Join(hdrs.Values("Warning"), " | ")
	if !strings.Contains(warnJoined, "unicodeSetFilter") || !strings.Contains(warnJoined, "aggregate_metric_double") {
		t.Fatalf("expected unicodeSetFilter and aggregate_metric_double warnings, got %q", warnJoined)
	}

	// 2. `_size` mapper metadata persisted across catalog sync & returned via `stored_fields=_size`
	code, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/size_idx", `{"mappings":{"_size":{"enabled":true}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 creating size_idx, got %d", code)
	}
	code, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/size_idx/_doc/1?refresh=true&routing=r_one", `{"foo":"bar"}`, nil)
	if code != http.StatusCreated && code != http.StatusOK {
		t.Fatalf("expected 201 indexing size_idx, got %d", code)
	}
	code, _, getRes := doTestJSONReqR63(t, h, http.MethodGet, "/size_idx/_doc/1?stored_fields=_size&routing=r_one", "", nil)
	if code != http.StatusOK || getRes["_size"] == nil {
		t.Fatalf("expected _size in GET response, got code=%d body=%+v", code, getRes)
	}
	// Verify `exists` on `_routing`
	code, _, rtRes := doTestJSONReqR63(t, h, http.MethodPost, "/size_idx/_search", `{"query":{"exists":{"field":"_routing"}}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 searching _routing exists, got %d", code)
	}
	if hitsEnv, _ := rtRes["hits"].(map[string]any); hitsEnv == nil {
		t.Fatalf("missing hits on _routing exists: %+v", rtRes)
	}

	// 3. `annotated_text` indexing, `annotated` highlighter, and `significant_text` annotations
	code, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ann_idx", `{
		"mappings": {
			"properties": {
				"text": {"type": "annotated_text"},
				"entity": {"type": "keyword"}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 creating ann_idx, got %d", code)
	}
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ann_idx/_doc/1?refresh=true",
		`{"text":"The [quick brown fox](entity_3789&Apple+Inc) is brown.","entity":"entity_3789"}`, nil)

	code, _, annHL1 := doTestJSONReqR63(t, h, http.MethodPost, "/ann_idx/_search", `{
		"query": {"term": {"entity": "entity_3789"}},
		"highlight": {"type": "annotated", "require_field_match": false, "fields": {"text": {}}}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 on annotated highlight 1, got %d", code)
	}
	hits1, _ := annHL1["hits"].(map[string]any)["hits"].([]any)
	if len(hits1) != 1 {
		t.Fatalf("expected 1 hit on ann_idx, got %+v", annHL1)
	}
	hlMap1, _ := hits1[0].(map[string]any)["highlight"].(map[string]any)
	if !strings.Contains(jsonStringifyTestWave3(hlMap1), "_hit_term=entity_3789") {
		t.Fatalf("expected _hit_term=entity_3789 in highlight, got %+v", hlMap1)
	}

	code, _, annHL2 := doTestJSONReqR63(t, h, http.MethodPost, "/ann_idx/_search", `{
		"query": {"term": {"text": "quick"}},
		"aggs": {"sig": {"significant_text": {"field": "text", "min_doc_count": 1}}},
		"highlight": {"type": "annotated", "require_field_match": false, "fields": {"text": {}}, "max_analyzed_offset": 30}
	}`, nil)
	if code != http.StatusOK || !strings.Contains(jsonStringifyTestWave3(annHL2), "_hit_term=quick") {
		t.Fatalf("expected _hit_term=quick in highlight, got code=%d body=%+v", code, annHL2)
	}

	// 4. Custom `ngram` tokenizer & token filter highlighting + `copy_to`
	code, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ng_idx", `{
		"settings": {
			"index.max_ngram_diff": 10,
			"analysis": {
				"tokenizer": {
					"my_ngt": {"type": "ngram", "min_gram": 2, "max_gram": 6, "token_chars": "letter,digit"}
				},
				"filter": {
					"my_ngf": {"type": "ngram", "min_gram": 2, "max_gram": 6}
				},
				"analyzer": {
					"an_tok": {"tokenizer": "my_ngt"},
					"an_flt": {"tokenizer": "whitespace", "filter": ["my_ngf"]},
					"an_ws":  {"tokenizer": "whitespace"}
				}
			}
		},
		"mappings": {
			"properties": {
				"src": {"type": "text", "copy_to": "name"},
				"name": {"type": "text", "analyzer": "an_tok", "search_analyzer": "an_ws"},
				"name2": {"type": "text", "analyzer": "an_flt", "search_analyzer": "an_ws"}
			}
		}
	}`, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200 creating ng_idx, got %d", code)
	}
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ng_idx/_doc/1?refresh=true",
		`{"src":"extra","name":"logicacmg company","name2":"logicacmg company"}`, nil)
	code, _, ngRes := doTestJSONReqR63(t, h, http.MethodPost, "/ng_idx/_search", `{
		"query": {"bool": {"must": [{"match": {"name": "logica"}}, {"match_phrase": {"name2": "logica"}}]}},
		"highlight": {"encoder": "html", "fields": {"name": {}, "name2": {}}}
	}`, nil)
	ngDump := fmt.Sprintf("%v", ngRes)
	if code != http.StatusOK || !strings.Contains(ngDump, "<em>logica</em>cmg") || !strings.Contains(ngDump, "<em>logicacmg</em>") {
		t.Fatalf("expected ngram tokenizer and filter highlights, got code=%d body=%+v", code, ngRes)
	}

	// 5. Multi-index + multi-value `matrix_stats` (float32 dynamic precision + reverse field order)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ms_a", `{"mappings":{"properties":{"val1":{"type":"double"},"val2":{"type":"float"}}}}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ms_b", `{}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ms_a/_doc/1?refresh=true", `{"val1":1.5,"val2":2.5,"vals":[1.9,16.143]}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/ms_a/_doc/2?refresh=true", `{"val1":3.5,"val2":4.5,"vals":[2.1,8.5]}`, nil)
	code, _, msRes := doTestJSONReqR63(t, h, http.MethodPost, "/ms_a,ms_b/_search", `{
		"size": 0,
		"aggs": {"mfs": {"matrix_stats": {"fields": ["val1", "val2", "vals"], "mode": "max"}}}
	}`, nil)
	if code != http.StatusOK || !strings.Contains(jsonStringifyTestWave3(msRes), `"doc_count":2`) {
		t.Fatalf("expected multi-index matrix_stats doc_count=2, got code=%d body=%+v", code, msRes)
	}

	// 6. HDR `percentiles` partial shard survival when one shard has negative values
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPut, "/hdr_idx", `{
		"settings": {"number_of_shards": 3, "number_of_replicas": 0},
		"mappings": {"properties": {"n": {"type": "integer"}}}
	}`, nil)
	_, _, _ = doTestJSONReqR63(t, h, http.MethodPost, "/hdr_idx/_bulk?refresh=true",
		strings.Join([]string{
			`{"index":{"_id":"1"}}`, `{"n":10}`,
			`{"index":{"_id":"2"}}`, `{"n":20}`,
			`{"index":{"_id":"3"}}`, `{"n":-5}`,
		}, "\n")+"\n", nil)
	code, _, hdrRes := doTestJSONReqR63(t, h, http.MethodPost, "/hdr_idx/_search", `{
		"aggs": {"p": {"percentiles": {"field": "n", "hdr": {}}}}
	}`, nil)
	if code != http.StatusOK || !strings.Contains(jsonStringifyTestWave3(hdrRes), "array_index_out_of_bounds_exception") {
		t.Fatalf("expected 200 partial shard failure on HDR negative value, got code=%d body=%+v", code, hdrRes)
	}

	// 7. ES7 dynamic string `_field_caps` & `date` `docvalue_fields` `epoch_millis` string formatting
	srv7 := NewServer("es_compat_v7", NewMemoryBackend(false), transpiler.TranspilerOptions{})
	srv7.SetTargetESVersion("7.10.2")
	t.Cleanup(func() { _ = srv7.Close(context.Background()) })
	h7 := srv7.Handler()
	_, _, _ = doTestJSONReqR63(t, h7, http.MethodPut, "/fc_dyn/_doc/1?refresh=true", `{"dyn_str":"hello world","num":3.25}`, nil)
	code, _, fcRes := doTestJSONReqR63(t, h7, http.MethodGet, "/fc_dyn/_field_caps?fields=*", "", nil)
	if code != http.StatusOK || !strings.Contains(jsonStringifyTestWave3(fcRes), `"dyn_str.keyword"`) {
		t.Fatalf("expected dyn_str.keyword in v7 _field_caps, got code=%d body=%+v", code, fcRes)
	}
	_, _, _ = doTestJSONReqR63(t, h7, http.MethodPut, "/dt_idx", `{"mappings":{"properties":{"d":{"type":"date"}}}}`, nil)
	_, _, _ = doTestJSONReqR63(t, h7, http.MethodPut, "/dt_idx/_doc/1?refresh=true", `{"d":"2018-10-29T12:12:12.987Z"}`, nil)
	code, _, dtRes := doTestJSONReqR63(t, h7, http.MethodPost, "/dt_idx/_search", `{"docvalue_fields":[{"field":"d","format":"epoch_millis"}]}`, nil)
	if code != http.StatusOK || !strings.Contains(jsonStringifyTestWave3(dtRes), `"1540815132987"`) {
		t.Fatalf("expected string epoch_millis in docvalue_fields, got code=%d body=%+v", code, dtRes)
	}
}

func TestRound63Wave3_HelperEdgeCases(t *testing.T) {
	var nilSrv *Server
	if nilSrv.getOrCreateWave3PolishStateR63() != nil {
		t.Fatal("expected nil state on nil server")
	}
	nilSrv.recordDynamicallyInferredFieldsWave3R63("idx", nil, nil, nil)
	if nilSrv.isDynamicallyInferredStringFieldWave3R63("idx", "f") {
		t.Fatal("expected false on nil server")
	}
	if nilSrv.dynamicTextFieldsCopyWave3R63("idx") != nil {
		t.Fatal("expected nil map on nil server")
	}
	if nilSrv.isDynamicallyInferredFloatFieldWave3R63("idx", "f") {
		t.Fatal("expected false float on nil server")
	}
	if isCustomOrPluginIndexAnalyzerWave3R63("", nil) || isCustomOrPluginIndexAnalyzerWave3R63("standard", nil) {
		t.Fatal("standard/empty analyzer must not be custom")
	}
	if !isCustomOrPluginIndexAnalyzerWave3R63("polish", analysis.DefaultIndexAnalysisConfig()) {
		t.Fatal("polish must be recognized as plugin analyzer")
	}
	if got := expandAnnotatedTextForIndexWave3R63("plain text"); got != "plain text" {
		t.Fatalf("unexpected plain expansion: %q", got)
	}
	if got := decodeSingleAnnotationTokenWave3R63("%ZZ+bad"); got != "%ZZ bad" {
		t.Fatalf("unexpected fallback decode: %q", got)
	}
	var complexQ esast.Query
	_ = json.Unmarshal([]byte(`{
		"bool": {
			"should": [
				{"match_phrase_prefix": {"t": "alp bet"}},
				{"constant_score": {"filter": {"term": {"k": 42}}}},
				{"dis_max": {"queries": [{"boosting": {"positive": {"match": {"m": "gam"}}, "negative": {"term": {"n": "x"}}, "negative_boost": 0.2}}]}},
				{"function_score": {"query": {"term": {"f": "del"}}}}
			]
		}
	}`), &complexQ)
	terms := collectQueryHighlightTermsWave3R63(&complexQ)
	if len(terms) < 4 {
		t.Fatalf("expected extracted highlight terms from compound query, got %v", terms)
	}
}

func jsonStringifyTestWave3(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
