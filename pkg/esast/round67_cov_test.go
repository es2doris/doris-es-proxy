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

package esast

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestRound67CovEsast_SearchRequestAndHelpers(t *testing.T) {
	// 1. parseStrictSearchIntJSON
	for _, tc := range []struct {
		name    string
		raw     string
		wantNil bool
		want    int
		wantErr bool
	}{
		{"empty", "", true, 0, false},
		{"null", "null", true, 0, false},
		{"int", "42", false, 42, false},
		{"string_int", `"17"`, false, 17, false},
		{"float_fail", "1.5", false, 0, true},
		{"string_bad", `"abc"`, false, 0, true},
		{"malformed_quote", `"abc`, false, 0, true},
		{"bool_fail", "true", false, 0, true},
	} {
		got, err := parseStrictSearchIntJSON(json.RawMessage(tc.raw), "from")
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseStrictSearchIntJSON(%s) err=%v wantErr=%v", tc.name, err, tc.wantErr)
		}
		if !tc.wantErr {
			if tc.wantNil && got != nil {
				t.Fatalf("%s expected nil, got %d", tc.name, *got)
			}
			if !tc.wantNil && (got == nil || *got != tc.want) {
				t.Fatalf("%s got %v, want %d", tc.name, got, tc.want)
			}
		}
	}

	// 2. parseStrictSearchFloatJSON
	for _, tc := range []struct {
		name    string
		raw     string
		wantNil bool
		want    float64
		wantErr bool
	}{
		{"empty", "", true, 0, false},
		{"null", "null", true, 0, false},
		{"num", "3.5", false, 3.5, false},
		{"str_num", `"2.25"`, false, 2.25, false},
		{"str_nan", `"NaN"`, false, 0, true},
		{"str_inf", `"Infinity"`, false, 0, true},
		{"str_bad", `"bad"`, false, 0, true},
		{"bad_quote", `"1.0`, false, 0, true},
		{"obj", `{}`, false, 0, true},
		{"bool", `false`, false, 0, true},
	} {
		got, err := parseStrictSearchFloatJSON(json.RawMessage(tc.raw), "min_score")
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseStrictSearchFloatJSON(%s) err=%v wantErr=%v", tc.name, err, tc.wantErr)
		}
		if !tc.wantErr && !tc.wantNil && (got == nil || *got != tc.want) {
			t.Fatalf("%s got %v, want %v", tc.name, got, tc.want)
		}
	}

	// 3. parseTrackTotalHitsJSON
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"empty", "", false},
		{"null", "null", false},
		{"bool_true", "true", false},
		{"bool_false", "false", false},
		{"str_true", `"TRUE"`, false},
		{"str_false", `"false"`, false},
		{"str_num", `"500"`, false},
		{"num_neg1", "-1", false},
		{"num_zero", "0", false},
		{"num_pos", "100", false},
		{"str_bad", `"abc"`, true},
		{"str_neg2", `"-2"`, true},
		{"num_neg2", "-2", true},
		{"bad_quote", `"true`, true},
		{"array", "[]", true},
	} {
		_, err := parseTrackTotalHitsJSON(json.RawMessage(tc.raw))
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseTrackTotalHitsJSON(%s) err=%v wantErr=%v", tc.name, err, tc.wantErr)
		}
	}

	// 4. validateScriptFieldsMap
	for _, tc := range []struct {
		name    string
		sf      map[string]any
		wantErr bool
	}{
		{"nil", nil, false},
		{"valid", map[string]any{"f1": map[string]any{"script": map[string]any{"source": "1+1"}, "ignore_failure": true}}, false},
		{"blank_field", map[string]any{" ": map[string]any{"script": "1"}}, true},
		{"not_obj", map[string]any{"f1": "bad"}, true},
		{"unknown_key", map[string]any{"f1": map[string]any{"script": "1", "foo": 1}}, true},
		{"missing_script", map[string]any{"f1": map[string]any{"ignore_failure": false}}, true},
		{"bad_script", map[string]any{"f1": map[string]any{"script": 123}}, true},
		{"ignore_null", map[string]any{"f1": map[string]any{"script": "1", "ignore_failure": nil}}, true},
		{"ignore_bad", map[string]any{"f1": map[string]any{"script": "1", "ignore_failure": "maybe"}}, true},
	} {
		err := validateScriptFieldsMap(tc.sf, "search")
		if (err != nil) != tc.wantErr {
			t.Fatalf("validateScriptFieldsMap(%s) err=%v wantErr=%v", tc.name, err, tc.wantErr)
		}
	}

	// 5. parseIndicesBoost
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"null", "null", false},
		{"obj_ok", `{"idx1": 1.5, "idx2": 0}`, false},
		{"arr_ok", `[{"idx1": 2.0}, {"idx2": 0.5}]`, false},
		{"empty_arr_elem", `[{}]`, true},
		{"blank_idx", `{" ": 1.0}`, true},
		{"neg_boost", `{"idx1": -1.0}`, true},
		{"arr_non_obj", `["idx1"]`, true},
		{"bad_arr", `[invalid]`, true},
		{"bad_obj", `{invalid}`, true},
		{"arr_bad_elem", `[{invalid}]`, true},
		{"scalar", `123`, true},
	} {
		_, err := parseIndicesBoost(json.RawMessage(tc.raw))
		if (err != nil) != tc.wantErr {
			t.Fatalf("parseIndicesBoost(%s) err=%v wantErr=%v", tc.name, err, tc.wantErr)
		}
	}

	// 6. SearchRequest error & edge paths
	for _, tc := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"null", "null", false},
		{"unknown_key", `{"bogus": 1}`, true},
		{"pit_conflict", `{"pit":{"id":"p"},"point_in_time":{"id":"p"}}`, true},
		{"retriever_query", `{"retriever":{"standard":{}},"query":{"match_all":{}}}`, true},
		{"retriever_knn", `{"retriever":{"standard":{}},"knn":{"field":"v","query_vector":[1]}}`, true},
		{"retriever_sub", `{"retriever":{"standard":{}},"sub_searches":[{"query":{"match_all":{}}}]}`, true},
		{"retriever_rank", `{"retriever":{"standard":{}},"rank":{"rrf":{}}}`, true},
		{"neg_from", `{"from": -1}`, true},
		{"neg_size", `{"size": -1}`, true},
		{"zero_terminate", `{"terminate_after": 0}`, true},
		{"small_batched", `{"batched_reduce_size": 1}`, true},
		{"bad_stats", `{"stats": [123]}`, true},
		{"sub_and_rank_ok", `{"sub_searches":[{"query":{"match_all":{}},"_name":"s1"}],"rank":{"rrf":{"rank_window_size":50,"rank_constant":20}}}`, false},
	} {
		var sr SearchRequest
		err := json.Unmarshal([]byte(tc.body), &sr)
		if (err != nil) != tc.wantErr {
			t.Fatalf("SearchRequest(%s) err=%v wantErr=%v", tc.name, err, tc.wantErr)
		}
	}

	// 7. SubSearchSpec, RankSpec, RRFSpec error paths
	for _, body := range []string{
		`null`,
		`"not-an-obj"`,
		`{"unknown":1,"query":{"match_all":{}}}`,
		`{"_name":"n"}`,
		`{"query":{}}`,
		`{"query":{"match_all":{}},"_name":123}`,
	} {
		var ss SubSearchSpec
		if err := json.Unmarshal([]byte(body), &ss); err == nil {
			t.Fatalf("expected SubSearchSpec error for %s", body)
		}
	}
	for _, body := range []string{
		`not-json`,
		`{}`,
		`{"rrf":{},"extra":{}}`,
		`{"rrf":null}`,
		`{"unknown":{}}`,
	} {
		var r RankSpec
		if err := json.Unmarshal([]byte(body), &r); err == nil {
			t.Fatalf("expected RankSpec error for %s", body)
		}
	}
	var nullRank RankSpec
	if err := json.Unmarshal([]byte("null"), &nullRank); err != nil {
		t.Fatalf("unexpected RankSpec null err: %v", err)
	}
	for _, body := range []string{
		`[]`,
		`{"bad":1}`,
		`{"window_size":10,"rank_window_size":10}`,
		`{"window_size":0}`,
		`{"rank_constant":0}`,
	} {
		var rrf RRFSpec
		if err := json.Unmarshal([]byte(body), &rrf); err == nil {
			t.Fatalf("expected RRFSpec error for %s", body)
		}
	}

	// 8. Large int normalization helpers & ParseBulkNDJSON
	if s, ok := formatExactFloatInt(math.NaN()); ok || s != "" {
		t.Fatalf("expected NaN false, got %q %v", s, ok)
	}
	if s, ok := formatExactFloatInt(1.25); ok || s != "" {
		t.Fatalf("expected fractional false, got %q %v", s, ok)
	}
	if s, ok := formatExactFloatInt(math.Ldexp(1, 63)); !ok || s == "" {
		t.Fatalf("expected >= 2^63 uint64 true, got %q %v", s, ok)
	}
	if s, ok := formatExactFloatInt(math.Ldexp(1, 64)); ok || s != "" {
		t.Fatalf("expected >= 2^64 false, got %q %v", s, ok)
	}
	norm := normalizeDecodedNumbersPreservingLargeInts(map[string]any{
		"big":   json.Number("17446744073709551615"),
		"small": json.Number("42"),
		"flt":   json.Number("3.14"),
		"arr":   []any{json.Number("9007199254740993")},
	})
	mNorm := norm.(map[string]any)
	if _, ok := mNorm["big"].(json.Number); !ok {
		t.Fatalf("expected big uint64 json.Number preserved, got %T", mNorm["big"])
	}
	var dest any
	if err := unmarshalPreservingLargeInts([]byte(`{"a":1}{"b":2}`), &dest); err == nil || !strings.Contains(err.Error(), "trailing JSON value") {
		t.Fatalf("expected trailing JSON value error, got %v", err)
	}
	if err := unmarshalPreservingLargeInts([]byte(`{"a":1}`), &dest); err != nil {
		t.Fatalf("unexpected unmarshalPreservingLargeInts err: %v", err)
	}

	// ParseBulkNDJSON edge/error cases
	bulkOK := strings.Join([]string{
		`{"index":{"_index":"i1","_id":"1","op_type":"create","require_alias":"true","detect_noop":false,"_source_includes":"a,b","_source_excludes":["c"]}}`,
		`{"field":"val"}`,
		`{"update":{"_id":"2","doc_as_upsert":"true","retry_on_conflict":2}}`,
		`{"doc":{"x":1}}`,
		`{"delete":{"_id":"3"}}`,
		``,
	}, "\n")
	ops, err := ParseBulkNDJSON(strings.NewReader(bulkOK), "def")
	if err != nil || len(ops) != 3 || ops[0].Action != "create" || ops[0].SourceFilter == nil {
		t.Fatalf("unexpected ParseBulkNDJSON ok: ops=%+v err=%v", ops, err)
	}
	for _, badBulk := range []string{
		`{}` + "\n",
		`{"index":{},"create":{}}` + "\n",
		`{"unknown":{}}` + "\n",
		`{"delete":{"_id":"1","op_type":"create"}}` + "\n",
		`{"index":{"_id":"1","op_type":"bad"}}` + "\n",
		`{"index":{"_id":"1"}}` + "\n", // EOF waiting for source
		"not-json\n",
	} {
		if _, err := ParseBulkNDJSON(strings.NewReader(badBulk), "def"); err == nil {
			t.Fatalf("expected ParseBulkNDJSON error for %q", badBulk)
		}
	}
	if opsBadSrc, err := ParseBulkNDJSON(strings.NewReader(`{"update":{}}`+"\n"+`{invalid}`+"\n"), "def"); err != nil || len(opsBadSrc) != 1 || opsBadSrc[0].ParseErr == "" {
		t.Fatalf("expected ParseErr on missing id + invalid source, got ops=%+v err=%v", opsBadSrc, err)
	}
}

func TestRound67CovEsast_RetrieverHighlightRescoreSuggestSource(t *testing.T) {
	// 1. RetrieverSpec + LowerRetrieverToSearchRequest
	reqBody := `{
		"retriever": {
			"text_similarity_reranker": {
				"field": "body",
				"inference_id": "rerank-1",
				"inference_text": "hello",
				"rank_window_size": 10,
				"min_score": 0.2,
				"filter": {"term": {"tenant": "t1"}},
				"retriever": {
					"rule": {
						"ruleset_ids": ["r1"],
						"match_criteria": {"q": "hello"},
						"retriever": {
							"rrf": {
								"rank_window_size": 50,
								"rank_constant": 20,
								"filter": {"term": {"active": true}},
								"retrievers": [
									{
										"standard": {
											"query": {"match": {"body": "hello"}},
											"filter": [{"term": {"lang": "en"}}],
											"sort": ["_score"],
											"search_after": [17446744073709551615],
											"terminate_after": 10,
											"min_score": 0.1,
											"rank_window_size": 25
										}
									},
									{
										"knn": {
											"field": "vec",
											"query_vector": [1.0, 2.0],
											"k": 5,
											"num_candidates": 20,
											"boost": 1.5
										}
									}
								]
							}
						}
					}
				}
			}
		}
	}`
	var sr SearchRequest
	if err := json.Unmarshal([]byte(reqBody), &sr); err != nil {
		t.Fatalf("unexpected valid retriever err: %v", err)
	}
	LowerRetrieverToSearchRequest(&sr)
	LowerRetrieverToSearchRequest(&sr) // idempotent
	if len(sr.KNN) != 1 || sr.Rank == nil || len(sr.SubSearches) != 1 || sr.Query == nil {
		t.Fatalf("unexpected lowered retriever state: %+v", sr)
	}
	var stdOnly SearchRequest
	if err := json.Unmarshal([]byte(`{"retriever":{"standard":{"sort":["_score"],"search_after":[1],"terminate_after":5,"min_score":0.5}}}`), &stdOnly); err != nil {
		t.Fatal(err)
	}
	LowerRetrieverToSearchRequest(&stdOnly)
	if stdOnly.Query == nil || stdOnly.Query.MatchAll == nil {
		t.Fatalf("expected default match_all from standard retriever: %+v", stdOnly.Query)
	}
	for _, badRet := range []string{
		`[]`,
		`{}`,
		`{"standard":{},"knn":{"field":"v","query_vector":[1]}}`,
		`{"unknown":{}}`,
		`{"standard":"bad"}`,
		`{"standard":{"foo":1}}`,
		`{"standard":{"terminate_after":"bad"}}`,
		`{"standard":{"terminate_after":0}}`,
		`{"standard":{"rank_window_size":0}}`,
		`{"knn":"bad"}`,
		`{"knn":{"foo":1}}`,
		`{"knn":{"query_vector":[1]}}`,
		`{"knn":{"field":"v"}}`,
		`{"knn":{"field":"v","query_vector":[1],"query_vector_builder":{"text":"hi"}}}`,
		`{"knn":{"field":"v","query_vector":[1],"k":0}}`,
		`{"knn":{"field":"v","query_vector":[1],"k":10001}}`,
		`{"knn":{"field":"v","query_vector":[1],"num_candidates":0}}`,
		`{"knn":{"field":"v","query_vector":[1],"num_candidates":10001}}`,
		`{"knn":{"field":"v","query_vector":[1],"k":10,"num_candidates":5}}`,
		`{"knn":{"field":"v","query_vector":[1],"boost":-1}}`,
		`{"rrf":"bad"}`,
		`{"rrf":{"foo":1}}`,
		`{"rrf":{"retrievers":[]}}`,
		`{"rrf":{"retrievers":[{"standard":{}}],"rank_window_size":0}}`,
		`{"rrf":{"retrievers":[{"standard":{}}],"rank_constant":0}}`,
		`{"rule":"bad"}`,
		`{"rule":{"foo":1}}`,
		`{"rule":{"ruleset_id":"a","ruleset_ids":["b"],"retriever":{"standard":{}}}}`,
		`{"rule":{"retriever":{"standard":{}}}}`,
		`{"rule":{"ruleset_ids":[" "],"retriever":{"standard":{}}}}`,
		`{"text_similarity_reranker":"bad"}`,
		`{"text_similarity_reranker":{"foo":1}}`,
		`{"text_similarity_reranker":{"field":"f"}}`,
		`{"text_similarity_reranker":{"retriever":{"standard":{}},"field":"f","inference_id":"id","inference_text":"txt","rank_window_size":0}}`,
		`{"text_similarity_reranker":{"retriever":{"standard":{}},"field":"f","inference_id":"id","inference_text":"txt","min_score":-1}}`,
	} {
		var ret RetrieverSpec
		if err := json.Unmarshal([]byte(badRet), &ret); err == nil {
			t.Fatalf("expected RetrieverSpec error for %s", badRet)
		}
	}

	// 2. RescoreSlice / RescoreSpec / RescoreQuerySpec
	var resSingle, resArr RescoreSlice
	if err := json.Unmarshal([]byte(`{"window_size":10,"query":{"rescore_query":{"match_all":{}},"score_mode":"AVG"}}`), &resSingle); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`[{"query":{"rescore_query":{"match_all":{}},"score_mode":"Total"}}]`), &resArr); err != nil {
		t.Fatal(err)
	}
	for _, badRes := range []string{
		`[bad`,
		`{"bad_field":1,"query":{"rescore_query":{"match_all":{}}}}`,
		`{"window_size":-1,"query":{"rescore_query":{"match_all":{}}}}`,
		`{"window_size":1}`,
		`{"query":{"unknown":1,"rescore_query":{"match_all":{}}}}`,
		`{"query":{}}`,
		`{"query":{"rescore_query":{"match_all":{}},"score_mode":"bogus"}}`,
	} {
		var rs RescoreSlice
		if err := json.Unmarshal([]byte(badRes), &rs); err == nil {
			t.Fatalf("expected RescoreSlice error for %s", badRes)
		}
	}

	// 3. Highlight & parseFlexibleStringSlice & parseFlexibleHighlightFields
	if _, err := parseFlexibleStringSlice(123); err == nil {
		t.Fatalf("expected parseFlexibleStringSlice error on int")
	}
	if got, ordered, err := parseFlexibleHighlightFields(json.RawMessage(`[{"f1":{"number_of_fragments":2}},{"f2":{"fragment_size":50}}]`)); err != nil || len(ordered) != 2 || len(got) != 2 {
		t.Fatalf("unexpected parseFlexibleHighlightFields array: got=%v ordered=%v err=%v", got, ordered, err)
	}
	for _, badHF := range []string{
		`123`,
		`[invalid]`,
		`["str"]`,
		`[{invalid}]`,
		`[{"a":{},"b":{}}]`,
		`[{" ":{}}]`,
		`{"a":{"type":"bogus"}}`,
	} {
		if _, _, err := parseFlexibleHighlightFields(json.RawMessage(badHF)); err == nil {
			t.Fatalf("expected parseFlexibleHighlightFields error for %s", badHF)
		}
	}
	for _, badH := range []string{
		`{"type":"invalid"}`,
		`{"order":"invalid"}`,
		`{"encoder":"invalid"}`,
		`{"boundary_scanner":"invalid"}`,
		`{"fragmenter":"invalid"}`,
		`{"tag_schema":"invalid"}`,
		`{"pre_tags":["<b>"],"post_tags":["</b>","</i>"]}`,
		`{"pre_tags":123}`,
		`{"post_tags":123}`,
		`{"matched_fields":123}`,
		`{"fragment_size":-1}`,
		`{"number_of_fragments":-1}`,
		`{"no_match_size":-1}`,
		`{"boundary_max_scan":-1}`,
		`{"fragment_offset":-1}`,
		`{"max_analyzed_offset":-2}`,
		`{"phrase_limit":-1}`,
	} {
		var hfs HighlightFieldSpec
		if err := json.Unmarshal([]byte(badH), &hfs); err == nil {
			t.Fatalf("expected HighlightFieldSpec error for %s", badH)
		}
	}

	// 4. PhraseSuggestSpec, PhraseHighlightSpec, CompletionFuzzySpec, CompletionRegexSpec
	for _, badPS := range []string{
		`{"unknown":1,"field":"f"}`,
		`{"size":1}`,
		`{"field":"f","size":0}`,
		`{"field":"f","gram_size":0}`,
		`{"field":"f","max_errors":-1}`,
		`{"field":"f","confidence":-1}`,
	} {
		var ps PhraseSuggestSpec
		if err := json.Unmarshal([]byte(badPS), &ps); err == nil {
			t.Fatalf("expected PhraseSuggestSpec error for %s", badPS)
		}
	}
	var phs PhraseHighlightSpec
	if err := json.Unmarshal([]byte(`{"pre_tag":"<b>","post_tag":"</b>"}`), &phs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"bad":1}`), &phs); err == nil {
		t.Fatalf("expected PhraseHighlightSpec error")
	}
	var cf CompletionFuzzySpec
	if err := json.Unmarshal([]byte(`"true"`), &cf); err != nil || !cf.Enabled {
		t.Fatalf("unexpected CompletionFuzzySpec bool str: %+v err=%v", cf, err)
	}
	for _, badCF := range []string{
		`"badbool"`,
		`{"unknown":1}`,
		`{"fuzziness":3}`,
		`{"fuzziness":"BAD"}`,
		`{"fuzziness":[]}`,
		`{"transpositions":"bad"}`,
		`{"min_length":-1}`,
		`{"prefix_length":-1}`,
		`{"unicode_aware":"bad"}`,
	} {
		var c CompletionFuzzySpec
		if err := json.Unmarshal([]byte(badCF), &c); err == nil {
			t.Fatalf("expected CompletionFuzzySpec error for %s", badCF)
		}
	}
	var cr CompletionRegexSpec
	if err := json.Unmarshal([]byte(`{"flags":"ALL","max_determinized_states":1000}`), &cr); err != nil {
		t.Fatal(err)
	}
	for _, badCR := range []string{`"str"`, `{"unknown":1}`, `{"max_determinized_states":0}`} {
		var c CompletionRegexSpec
		if err := json.Unmarshal([]byte(badCR), &c); err == nil {
			t.Fatalf("expected CompletionRegexSpec error for %s", badCR)
		}
	}

	// 5. SourceFilter
	var sfFalse, sfStr SourceFilter
	_ = json.Unmarshal([]byte(`false`), &sfFalse)
	_ = json.Unmarshal([]byte(`"title"`), &sfStr)
	bFalse, _ := json.Marshal(sfFalse)
	if string(bFalse) != "false" {
		t.Fatalf("expected false marshal, got %s", bFalse)
	}
	for _, badSF := range []string{`[123]`, `[bad`, `{"unknown":1}`, `{"includes":[1]}`, `{"includes":123}`, `{"excludes":[1]}`, `123`} {
		var sf SourceFilter
		if err := json.Unmarshal([]byte(badSF), &sf); err == nil {
			t.Fatalf("expected SourceFilter error for %s", badSF)
		}
	}
}

func TestRound67CovEsast_QueriesIntervalsSpanGeoFunctions(t *testing.T) {
	// 1. Valid Intervals & Span queries through Query.UnmarshalJSON
	validQueries := []string{
		`{"intervals":{"body":{"match":{"query":"quick fox","max_gaps":2},"boost":1.5,"_name":"iv1"}}}`,
		`{"intervals":{"body":{"prefix":{"prefix":"qu"}}}}`,
		`{"intervals":{"body":{"wildcard":{"pattern":"qu*"}}}}`,
		`{"intervals":{"body":{"fuzzy":{"term":"quik","prefix_length":1,"fuzziness":"AUTO"}}}}`,
		`{"intervals":{"body":{"all_of":{"intervals":[{"match":{"query":"a"}}],"max_gaps":1,"filter":{"script":{"source":"true"}}}}}}`,
		`{"intervals":{"body":{"any_of":{"intervals":[{"match":{"query":"a"}},{"prefix":{"prefix":"b"}}]}}}}`,
		`{"span_near":{"clauses":[{"span_term":{"f":"a"}},{"span_term":{"f":"b"}}],"slop":1,"in_order":true,"boost":1.2}}`,
		`{"span_or":{"clauses":[{"span_term":{"f":"a"}}],"boost":1.0}}`,
		`{"span_not":{"include":{"span_term":{"f":"a"}},"exclude":{"span_term":{"f":"b"}},"pre":1,"post":1,"dist":2,"boost":1.0}}`,
		`{"span_first":{"match":{"span_term":{"f":"a"}},"end":3,"boost":1.0}}`,
		`{"span_multi":{"match":{"prefix":{"f":"pre"}},"boost":1.0}}`,
		`{"span_containing":{"little":{"span_term":{"f":"a"}},"big":{"span_term":{"f":"b"}},"boost":1.0}}`,
		`{"span_within":{"little":{"span_term":{"f":"a"}},"big":{"span_term":{"f":"b"}},"boost":1.0}}`,
		`{"field_masking_span":{"query":{"span_term":{"f":"a"}},"field":"alt","boost":1.0}}`,
		`{"rule":{"ruleset_id":"rs1","match_criteria":{"q":"hi"},"organic":{"match_all":{}},"boost":1.1}}`,
		`{"sparse_vector":{"ml.tokens":{"model_id":"elser","model_text":"hi","prune":true,"pruning_config":{"tokens_freq_ratio_threshold":5,"tokens_weight_threshold":0.5,"only_score_pruned_tokens":true},"boost":1.0}}}`,
		`{"knn":{"field":"vec","query_vector":[0.5,0.5],"k":3,"num_candidates":10,"boost":1.0}}`,
		`{"knn":{"vec":{"vector":[0.5,0.5],"k":3}}}`,
		`{"geo_grid":{"pin":{"geotile":"3/4/5"},"ignore_unmapped":"true","boost":1.2,"_name":"gg"}}`,
		`{"rank_feature":{"field":"popularity","saturation":{"pivot":10},"boost":1.5}}`,
		`{"rank_feature":{"field":"popularity","log":{"scaling_factor":2.0}}}`,
		`{"rank_feature":{"field":"popularity","sigmoid":{"pivot":10,"exponent":0.5}}}`,
		`{"rank_feature":{"field":"popularity","linear":{}}}`,
		`{"distance_feature":{"field":"date","origin":"now","pivot":"7d","boost":1.0}}`,
		`{"distance_feature":{"field":"loc","origin":[-70.0,40.0],"pivot":"10km"}}`,
		`{"has_child":{"type":"comment","query":{"match_all":{}},"score_mode":"avg","min_children":1,"max_children":5,"ignore_unmapped":true,"boost":1.0}}`,
		`{"has_parent":{"parent_type":"blog","query":{"match_all":{}},"score":true,"ignore_unmapped":"false","boost":1.0}}`,
		`{"parent_id":{"type":"comment","id":123,"ignore_unmapped":true,"boost":1.0}}`,
		`{"percolate":{"field":"query","document":{"body":"hello"},"ignore_unmapped":"true","name":"pq","boost":1.0}}`,
		`{"nested":{"path":"items","query":{"match_all":{}},"score_mode":"max","ignore_unmapped":"true","boost":1.0}}`,
		`{"constant_score":{"filter":{"match_all":{}},"boost":2.0}}`,
		`{"function_score":{"query":{"match_all":{}},"score_mode":"sum","boost_mode":"replace","max_boost":10,"min_score":0.1,"boost":1.0,"functions":[{"filter":{"match_all":{}},"weight":1.5},{"random_score":{"seed":42,"field":"id"}}]}}`,
		`{"function_score":{"query":{"match_all":{}},"weight":2}}`,
		`{"script_score":{"query":{"match_all":{}},"script":{"source":"1.0"},"min_score":0.1,"boost":1.0}}`,
		`{"script":"doc['a'].value > 0"}`,
		`{"boosting":{"positive":{"match_all":{}},"negative":{"match_none":{}},"negative_boost":0.2,"boost":1.0}}`,
		`{"common":{"body":{"query":"hello","cutoff_frequency":0.001,"type":"low","low_freq_operator":"and","high_freq_operator":"or","minimum_should_match":{"low_freq":2,"high_freq":"50%"},"boost":1.5}}}`,
		`{"exists":{"field":"title","boost":1.0}}`,
		`{"range":{"age":{"gte":1,"lte":10,"relation":"INTERSECTS","boost":1.0}}}`,
	}
	for _, jq := range validQueries {
		var q Query
		if err := json.Unmarshal([]byte(jq), &q); err != nil {
			t.Fatalf("expected valid query for %s, got %v", jq, err)
		}
	}

	// 2. Malformed/invalid query paths across Intervals, Span, Join, Geo, Functions, Script
	badQueries := []string{
		// Intervals errors
		`{"intervals":{"f":{"match":{"query":"a"},"prefix":{"prefix":"b"}}}}`,
		`{"intervals":{"f":{"boost":-1,"match":{"query":"a"}}}}`,
		`{"intervals":{"f":{}}}`,
		`{"intervals":{"f":{"match":{"unknown":1,"query":"a"}}}}`,
		`{"intervals":{"f":{"match":{"query":""}}}}`,
		`{"intervals":{"f":{"match":{"query":"a","max_gaps":-2}}}}`,
		`{"intervals":{"f":{"prefix":{"unknown":1,"prefix":"a"}}}}`,
		`{"intervals":{"f":{"prefix":{"prefix":""}}}}`,
		`{"intervals":{"f":{"wildcard":{"unknown":1,"pattern":"a"}}}}`,
		`{"intervals":{"f":{"wildcard":{"pattern":""}}}}`,
		`{"intervals":{"f":{"fuzzy":{"unknown":1,"term":"a"}}}}`,
		`{"intervals":{"f":{"fuzzy":{"term":""}}}}`,
		`{"intervals":{"f":{"fuzzy":{"term":"a","prefix_length":-1}}}}`,
		`{"intervals":{"f":{"fuzzy":{"term":"a","fuzziness":"99"}}}}`,
		`{"intervals":{"f":{"all_of":{"unknown":1,"intervals":[]}}}}`,
		`{"intervals":{"f":{"all_of":{"intervals":[]}}}}`,
		`{"intervals":{"f":{"all_of":{"intervals":[{"match":{"query":"a"}}],"max_gaps":-2}}}}`,
		`{"intervals":{"f":{"any_of":{"unknown":1,"intervals":[]}}}}`,
		`{"intervals":{"f":{"any_of":{"intervals":[]}}}}`,
		`{"intervals":{"f":{"all_of":{"intervals":[{"match":{"query":"a"}}],"filter":{"unknown":1}}}}}`,
		`{"intervals":{"f":{"all_of":{"intervals":[{"match":{"query":"a"}}],"filter":{}}}}}`,
		`{"intervals":{"f":{"all_of":{"intervals":[{"match":{"query":"a"}}],"filter":{"script":null}}}}}`,
		// Span errors
		`{"span_near":{"unknown":1,"clauses":[{"span_term":{"f":"a"}}]}}`,
		`{"span_near":{"clauses":[]}}`,
		`{"span_near":{"clauses":[{"span_term":{"f":"a"}}],"slop":-1}}`,
		`{"span_near":{"clauses":[{"span_term":{"f":"a"}}],"boost":-1}}`,
		`{"span_or":{"unknown":1,"clauses":[]}}`,
		`{"span_or":{"clauses":null}}`,
		`{"span_or":{"clauses":[{"span_term":{"f":"a"}}],"boost":-1}}`,
		`{"span_not":{"unknown":1}}`,
		`{"span_not":{"include":{"span_term":{"f":"a"}}}}`,
		`{"span_not":{"include":{"span_term":{"f":"a"}},"exclude":{"span_term":{"f":"b"}},"pre":-1}}`,
		`{"span_not":{"include":{"span_term":{"f":"a"}},"exclude":{"span_term":{"f":"b"}},"boost":-1}}`,
		`{"span_first":{"unknown":1}}`,
		`{"span_first":{"end":2}}`,
		`{"span_first":{"match":{"span_term":{"f":"a"}},"end":0}}`,
		`{"span_first":{"match":{"span_term":{"f":"a"}},"end":2,"boost":-1}}`,
		`{"span_multi":{"unknown":1}}`,
		`{"span_multi":{}}`,
		`{"span_multi":{"match":{"term":{"f":"a"}}}}`,
		`{"span_multi":{"match":{"prefix":{"f":"a"}},"boost":-1}}`,
		`{"span_containing":{"unknown":1}}`,
		`{"span_containing":{"little":{"span_term":{"f":"a"}}}}`,
		`{"span_containing":{"little":{"span_term":{"f":"a"}},"big":{"span_term":{"f":"b"}},"boost":-1}}`,
		`{"field_masking_span":{"unknown":1}}`,
		`{"field_masking_span":{"field":"alt"}}`,
		`{"field_masking_span":{"query":{"span_term":{"f":"a"}},"field":"alt","boost":-1}}`,
		// Rule & SparseVector & KNN errors
		`{"rule":{"unknown":1}}`,
		`{"rule":{"ruleset_id":"a","ruleset_ids":["b"],"match_criteria":{"q":"x"},"organic":{"match_all":{}}}}`,
		`{"rule":{"ruleset_ids":[],"match_criteria":{"q":"x"},"organic":{"match_all":{}}}}`,
		`{"rule":{"ruleset_ids":[" "],"match_criteria":{"q":"x"},"organic":{"match_all":{}}}}`,
		`{"rule":{"match_criteria":{"q":"x"},"organic":{"match_all":{}}}}`,
		`{"rule":{"ruleset_id":"a","organic":{"match_all":{}}}}`,
		`{"rule":{"ruleset_id":"a","match_criteria":{"q":"x"}}}`,
		`{"rule":{"ruleset_id":"a","match_criteria":{"q":"x"},"organic":{"match_all":{}},"boost":-1}}`,
		`{"sparse_vector":{"unknown":1,"field":"f"}}`,
		`{"sparse_vector":{}}`,
		`{"sparse_vector":{"field":"f"}}`,
		`{"sparse_vector":{"field":"f","query":"hi","tokens":{"a":1}}}`,
		`{"sparse_vector":{"field":"f","query":"hi"}}`,
		`{"sparse_vector":{"field":"f","tokens":{"a":1},"prune":"maybe"}}`,
		`{"sparse_vector":{"field":"f","tokens":{"a":1},"pruning_config":{"tokens_freq_ratio_threshold":0.5}}}`,
		`{"sparse_vector":{"field":"f","tokens":{"a":1},"pruning_config":{"tokens_weight_threshold":-1}}}`,
		`{"sparse_vector":{"field":"f","tokens":{"a":1},"pruning_config":{"only_score_pruned_tokens":"bad"}}}`,
		`{"sparse_vector":{"field":"f","tokens":{"a":1},"pruning_config":{"bad":1}}}`,
		`{"sparse_vector":{"field":"f","tokens":{"a":1},"boost":-1}}`,
		`{"knn":{"field":"v","unknown":1,"query_vector":[1]}}`,
		`{"knn":{"field":"v","query_vector":[1],"boost":-1}}`,
		`{"knn":{"query_vector":[1],"k":1}}`,
		`{"knn":{"field":"v","k":1}}`,
		`{"knn":{"field":"v","query_vector":[1],"k":0}}`,
		`{"knn":{"field":"v","query_vector":[1],"k":10001}}`,
		`{"knn":{"field":"v","query_vector":[1],"num_candidates":0}}`,
		`{"knn":{"field":"v","query_vector":[1],"num_candidates":10001}}`,
		`{"knn":{"field":"v","query_vector":[1],"k":5,"num_candidates":2}}`,
		// GeoGrid errors
		`{"geo_grid":{"a":{"geohash":"u"},"b":{"geohash":"u"}}}`,
		`{"geo_grid":{"pin":"notobj"}}`,
		`{"geo_grid":{"pin":{"unknown":1,"geohash":"u"}}}`,
		`{"geo_grid":{"pin":{"geohash":"u","geotile":"1/1/1"}}}`,
		`{"geo_grid":{"pin":{"geohash":"u"},"ignore_unmapped":"maybe"}}`,
		`{"geo_grid":{"pin":{"geohash":"u"},"boost":-1}}`,
		`{"geo_grid":{"pin":{"geohash":"u"},"_name":123}}`,
		// RankFeature & DistanceFeature errors
		`{"rank_feature":{"field":"f","unknown":1}}`,
		`{"rank_feature":{"field":"f","saturation":{},"linear":{}}}`,
		`{"rank_feature":{"field":"f","saturation":"bad"}}`,
		`{"rank_feature":{"field":"f","saturation":{"bad":1}}}`,
		`{"rank_feature":{"field":"f","saturation":{"pivot":0}}}`,
		`{"rank_feature":{"field":"f","log":"bad"}}`,
		`{"rank_feature":{"field":"f","log":{}}}`,
		`{"rank_feature":{"field":"f","log":{"scaling_factor":-1}}}`,
		`{"rank_feature":{"field":"f","sigmoid":"bad"}}`,
		`{"rank_feature":{"field":"f","sigmoid":{"pivot":1}}}`,
		`{"rank_feature":{"field":"f","linear":"bad"}}`,
		`{"rank_feature":{"field":"f","linear":{"x":1}}}`,
		`{"rank_feature":{"linear":{}}}`,
		`{"distance_feature":{"unknown":1}}`,
		`{"distance_feature":{"field":"f"}}`,
		`{"distance_feature":{"field":"f","origin":true,"pivot":"1d"}}`,
		`{"distance_feature":{"field":"f","origin":"now","pivot":0}}`,
		// HasChild, HasParent, ParentID, Percolate errors
		`{"has_child":{"unknown":1,"type":"c","query":{"match_all":{}}}}`,
		`{"has_child":{"type":"c"}}`,
		`{"has_child":{"query":{"match_all":{}}}}`,
		`{"has_child":{"type":"c","query":{"match_all":{}},"score_mode":"bad"}}`,
		`{"has_child":{"type":"c","query":{"match_all":{}},"min_children":-1}}`,
		`{"has_child":{"type":"c","query":{"match_all":{}},"max_children":-1}}`,
		`{"has_child":{"type":"c","query":{"match_all":{}},"min_children":5,"max_children":2}}`,
		`{"has_parent":{"unknown":1}}`,
		`{"has_parent":{"parent_type":"p"}}`,
		`{"has_parent":{"query":{"match_all":{}}}}`,
		`{"parent_id":{"unknown":1}}`,
		`{"parent_id":{"type":"c"}}`,
		`{"parent_id":{"type":"c","id":" "}}`,
		`{"parent_id":{"type":"c","id":{}}}`,
		`{"percolate":{"unknown":1}}`,
		`{"percolate":{"field":"f","document":{},"documents":[{}]}}`,
		`{"percolate":{"field":"f","document":{},"index":"i"}}`,
		`{"percolate":{"document":{}}}`,
		`{"percolate":{"field":"f","document":null}}`,
		`{"percolate":{"field":"f","documents":[]}}`,
		`{"percolate":{"field":"f","index":"i"}}`,
		// Nested, ConstantScore, FunctionScore, ScriptScore, Boosting, Common, Exists, Range errors
		`{"nested":{"unknown":1,"path":"p","query":{"match_all":{}}}}`,
		`{"nested":{"path":"p"}}`,
		`{"nested":{"query":{"match_all":{}}}}`,
		`{"nested":{"path":"p","query":{"match_all":{}},"score_mode":"bad"}}`,
		`{"constant_score":{"unknown":1,"filter":{"match_all":{}}}}`,
		`{"constant_score":{}}`,
		`{"function_score":{"unknown":1}}`,
		`{"function_score":{"score_mode":"bad"}}`,
		`{"function_score":{"boost_mode":"bad"}}`,
		`{"function_score":{"max_boost":-1}}`,
		`{"function_score":{"min_score":-1}}`,
		`{"function_score":{"weight":-1}}`,
		`{"function_score":{"functions":[{}]}}`,
		`{"function_score":{"functions":[{"random_score":{"seed":null}}],"weight":1}}`,
		`{"function_score":{"functions":[{"weight":1,"random_score":{"seed":"  "}}]}}`,
		`{"function_score":{"functions":[{"field_value_factor":{"field":"f","modifier":"bad"}}]}}`,
		`{"function_score":{"functions":[{"field_value_factor":{"field":"f","factor":-1}}]}}`,
		`{"function_score":{"functions":[{"field_value_factor":{}}]}}`,
		`{"function_score":{"functions":[{"script_score":{"unknown":1}}]}}`,
		`{"function_score":{"functions":[{"script_score":{}}]}}`,
		`{"script_score":{"unknown":1,"query":{"match_all":{}},"script":"1"}}`,
		`{"script_score":{"script":"1"}}`,
		`{"script_score":{"query":{"match_all":{}}}}`,
		`{"script_score":{"query":{"match_all":{}},"script":{"source":"1","id":"2"}}}`,
		`{"script_score":{"query":{"match_all":{}},"script":"1","min_score":-1}}`,
		`{"script":{"unknown":1,"script":"1"}}`,
		`{"boosting":{"unknown":1}}`,
		`{"boosting":{"positive":{"match_all":{}}}}`,
		`{"common":{"f":{"unknown":1,"query":"x"}}}`,
		`{"common":{"f":{}}}`,
		`{"common":{"f":{"query":null}}}`,
		`{"common":{"f":{"query":"x","type":"low"}}}`,
		`{"common":{"f":{"query":"x","low_freq_operator":"bad"}}}`,
		`{"common":{"f":{"query":"x","minimum_should_match":{}}}}`,
		`{"common":{"f":{"query":"x","minimum_should_match":{"bad":1}}}}`,
		`{"common":{"f":{"query":"x","minimum_should_match":{"low_freq":null}}}}`,
		`{"exists":{"unknown":1,"field":"f"}}`,
		`{"exists":{}}`,
		`{"range":{"f":{"unknown":1}}}`,
		`{"range":{"f":{"relation":"BAD"}}}`,
	}
	for _, jq := range badQueries {
		var q Query
		if err := json.Unmarshal([]byte(jq), &q); err == nil {
			t.Fatalf("expected error unmarshaling invalid query: %s", jq)
		}
	}

	// 3. Direct helper checks: GeoGrid methods, geo coords, QuerySlice, query names, QueryStringDepth
	var nilGG *GeoGridQuery
	if nilGG.GridType() != "" || nilGG.GridValue() != "" {
		t.Fatalf("expected empty nil GeoGridQuery")
	}
	ggHash := GeoGridQuery{Field: "loc", Geohash: "u4pruyd"}
	ggHex := GeoGridQuery{Field: "loc", Geohex: "85283473fffffff"}
	if ggHash.GridType() != "geohash" || ggHash.GridValue() != "u4pruyd" || ggHex.GridType() != "geohex" || ggHex.GridValue() != "85283473fffffff" {
		t.Fatalf("unexpected GeoGridType/Value")
	}
	if lat, lon, err := validateAndNormalizeGeoPoint(95, 200, "COERCE"); err != nil || lat != 90 || lon != -160 {
		t.Fatalf("unexpected COERCE normalization: %v %v err=%v", lat, lon, err)
	}
	if _, _, err := validateAndNormalizeGeoPoint(95, 0, "STRICT"); err == nil {
		t.Fatalf("expected illegal latitude error")
	}
	if _, _, err := ParseGeoDistanceMeters(nil); err == nil {
		t.Fatalf("expected nil geo_distance error")
	}
	if _, _, err := ParseGeoDistanceMeters(-5); err == nil {
		t.Fatalf("expected negative int geo_distance error")
	}
	if _, _, err := ParseGeoDistanceMeters(int64(0)); err == nil {
		t.Fatalf("expected zero int64 geo_distance error")
	}
	var qs QuerySlice
	if err := json.Unmarshal([]byte(`123`), &qs); err == nil {
		t.Fatalf("expected QuerySlice error on int")
	}
	if qName := extractQueryNameFromRaw(map[string]json.RawMessage{"_name": json.RawMessage(`"q1"`)}); qName != "q1" {
		t.Fatalf("expected q1, got %q", qName)
	}
	if qName := extractQueryNameFromRaw(map[string]json.RawMessage{"term": json.RawMessage(`{"a":{"_name":"q2"}}`)}); qName != "q2" {
		t.Fatalf("expected nested q2, got %q", qName)
	}
	if _, boostPtr, err := stripNamedQueryAndMapBoost(json.RawMessage(`{"_name":"n","boost":2.0,"f":"v"}`), true); err != nil || boostPtr == nil || *boostPtr != 2.0 {
		t.Fatalf("unexpected stripNamedQueryAndMapBoost: boost=%v err=%v", boostPtr, err)
	}
	if _, _, err := stripNamedQueryAndMapBoost(json.RawMessage(`{"boost":"-2","f":"v"}`), true); err == nil {
		t.Fatalf("expected negative string boost error")
	}
	if err := ValidateQueryStringDepth(`"/a\/b/ ((\"c\")) /unclosed` + "\n" + `a"`); err != nil {
		t.Fatal(err)
	}
	deep := strings.Repeat("(", MaxQueryStringDepth+2) + "x" + strings.Repeat(")", MaxQueryStringDepth+2)
	if err := ValidateQueryStringDepth(deep); err == nil {
		t.Fatalf("expected max depth error")
	}
	if err := validateOriginValue([]any{1.0}, "[test]"); err == nil {
		t.Fatalf("expected 1-elem origin array error")
	}
	if err := validateOriginValue(map[string]any{}, "[test]"); err == nil {
		t.Fatalf("expected empty map origin error")
	}
	if err := validateNonNegativeOffset("-1d", "[test]"); err == nil {
		t.Fatalf("expected negative offset error")
	}
	if err := validateNonNegativeOffset(math.NaN(), "[test]"); err == nil {
		t.Fatalf("expected NaN offset error")
	}
}

func TestRound67CovEsast_AggregationsAndPipelineAggs(t *testing.T) {
	// 1. Valid advanced metric/bucket/pipeline aggs
	validAggs := map[string]string{
		"cat": `{
			"categorize_text": {
				"field":"msg","size":5,"shard_size":10,"min_doc_count":2,"shard_min_doc_count":1,"max_matched_tokens":10,"similarity_threshold":50
			}
		}`,
		"fis": `{
			"frequent_item_sets": {
				"fields":[{"field":"tags"}],"minimum_set_size":2,"support":0.2,"size":10
			}
		}`,
		"mp": `{
			"moving_percentiles": {
				"buckets_path":"the_pct","window":5,"shift":1,"percents":[50,95],"script":{"source":"1"},"gap_policy":"skip"
			}
		}`,
		"gl": `{
			"geo_line": {
				"point":{"field":"loc"},"sort":{"field":"ts"},"sort_order":"desc","size":50,"include_sort":true
			}
		}`,
		"rs":   `{"random_sampler":{"probability":0.25,"seed":7}}`,
		"rt":   `{"rare_terms":{"field":"tag","max_doc_count":3}}`,
		"adh":  `{"auto_date_histogram":{"field":"ts","buckets":20,"minimum_interval":"hour"}}`,
		"vwh":  `{"variable_width_histogram":{"field":"price","buckets":15,"initial_buffer":10,"shard_size":30}}`,
		"wav":  `{"weighted_avg":{"value":{"field":"v"},"weight":{"field":"w"}}}`,
		"adj":  `{"adjacency_matrix":{"filters":{"a":{"term":{"f":"1"}}},"keyed":"true","separator":"&"}}`,
		"mt":   `{"multi_terms":{"terms":[{"field":"a"},{"script":{"source":"1"}}]}}`,
		"ms":   `{"matrix_stats":{"fields":["a","b"],"mode":"median"}}`,
		"tt":   `{"t_test":{"a":{"field":"x"},"b":{"field":"y"},"type":"paired"}}`,
		"th":   `{"top_hits":{"size":5,"from":1,"version":"true","seq_no_primary_term":"true","explain":"true","stored_fields":["_none_"],"fields":[{"field":"a"}],"docvalue_fields":[{"field":"b"}],"script_fields":{"s":{"script":"1"}}}}`,
		"tm":   `{"top_metrics":{"metrics":{"field":"val"},"size":3,"sort":["ts"]}}`,
		"rt2":  `{"rate":{"field":"bytes","unit":"1M","mode":"sum"}}`,
		"pct":  `{"percentiles":{"field":"lat","percents":95,"tdigest":{"compression":100,"execution_hint":"high_accuracy"}}}`,
		"prk":  `{"percentile_ranks":{"field":"lat","values":[10,50],"hdr":{"number_of_significant_value_digits":3}}}`,
		"flt":  `{"filters":{"filters":[{"match_all":{}}],"other_bucket":true}}`,
		"dh":   `{"date_histogram":{"field":"ts","calendar_interval":"1d","offset":-3600000,"time_zone":"+05:30","min_doc_count":0,"order":[{"_count":"desc"}]}}`,
		"hg":   `{"histogram":{"field":"num","interval":"10","offset":"2.5","order":{"_key":"asc"},"missing_order":"last"}}`,
		"rng":  `{"range":{"field":"num","ranges":{"low":{"to":10},"high":{"from":10}},"format":"0.0"}}`,
		"nst":  `{"nested":{"path":"items"}}`,
		"crd":  `{"cardinality":{"field":"id","precision_threshold":100}}`,
		"mavg": `{"moving_avg":{"buckets_path":"s","window":4,"shift":1,"model":"simple","gap_policy":"insert_zeros"}}`,
		"sm":   `{"scripted_metric":{"init_script":"1","map_script":"1","combine_script":"1","reduce_script":"1"}}`,
		"sd":   `{"serial_diff":{"buckets_path":"s","lag":2,"gap_policy":"skip"}}`,
		"nrm":  `{"normalize":{"buckets_path":"s","method":"z-score","gap_policy":"skip"}}`,
		"pb":   `{"percentiles_bucket":{"buckets_path":"s","percents":[25,75],"gap_policy":"skip"}}`,
		"bs":   `{"bucket_sort":{"sort":["_key"],"from":0,"size":5,"gap_policy":"skip"}}`,
		"sb":   `{"stats_bucket":{"buckets_path":"s","sigma":2.0,"gap_policy":"skip"}}`,
		"bsl":  `{"bucket_selector":{"buckets_path":{"a":"sub>avg"},"script":"params.a > 0","gap_policy":"skip"}}`,
		"cmp":  `{"composite":{"size":10,"sources":[{"d":{"terms":{"field":"k"}}}]}}`,
	}
	for name, specJSON := range validAggs {
		var a AggSpec
		if err := json.Unmarshal([]byte(specJSON), &a); err != nil {
			t.Fatalf("expected valid agg %s, got %v", name, err)
		}
	}

	// Verify getter fallbacks & effective defaults
	var nilMP *MovingPercentilesAggSpec
	if nilMP.EffectivePath() != "" || nilMP.EffectiveWindow() != 10 || nilMP.EffectiveShift() != 0 || nilMP.EffectivePercents() != nil {
		t.Fatalf("unexpected nil MovingPercentiles getters")
	}
	mp := MovingPercentilesAggSpec{BucketsPath: "p", Percentiles: []float64{50}}
	if mp.EffectivePath() != "p" || len(mp.EffectivePercents()) != 1 {
		t.Fatalf("unexpected MovingPercentiles getters: %+v", mp)
	}
	if ((*RareTermsAggSpec)(nil)).EffectiveMaxDocCount() != 1 ||
		((*AutoDateHistogramAggSpec)(nil)).EffectiveBuckets() != 10 ||
		((*VariableWidthHistogramAggSpec)(nil)).EffectiveBuckets() != 10 ||
		((*MovingAvgAggSpec)(nil)).EffectivePath() != "" ||
		((*MovingAvgAggSpec)(nil)).EffectiveWindow() != 5 ||
		((*SerialDiffAggSpec)(nil)).EffectivePath() != "" ||
		((*SerialDiffAggSpec)(nil)).EffectiveLag() != 1 ||
		((*NormalizeAggSpec)(nil)).EffectivePath() != "" ||
		((*PercentilesBucketAggSpec)(nil)).EffectivePath() != "" ||
		len(((*PercentilesBucketAggSpec)(nil)).EffectivePercents()) == 0 ||
		((*PipelineAggSpec)(nil)).EffectivePath() != "" ||
		((*PipelineAggSpec)(nil)).EffectiveSigma() != 2.0 ||
		((*TopMetricsAggSpec)(nil)).EffectiveSize() != 1 ||
		((*TopMetricsAggSpec)(nil)).EffectiveMetricFields() != nil ||
		((*TopHitsAggSpec)(nil)).HasStoredFieldsNone() ||
		((*TopHitsAggSpec)(nil)).EffectiveFrom() != 0 ||
		((*TopHitsAggSpec)(nil)).EffectiveSize() != 3 ||
		((*TopHitsAggSpec)(nil)).EffectiveFieldSpecs() != nil ||
		((*FiltersAggSpec)(nil)).EffectiveKeyed() != true {
		t.Fatalf("unexpected nil AggSpec getter defaults")
	}

	// 2. Agg validation error branches
	badAggs := []string{
		`{"categorize_text":{"unknown":1,"field":"m"}}`,
		`{"categorize_text":{"field":""}}`,
		`{"categorize_text":{"field":"m","size":0}}`,
		`{"categorize_text":{"field":"m","shard_size":0}}`,
		`{"categorize_text":{"field":"m","min_doc_count":0}}`,
		`{"categorize_text":{"field":"m","shard_min_doc_count":0}}`,
		`{"categorize_text":{"field":"m","max_matched_tokens":101}}`,
		`{"categorize_text":{"field":"m","similarity_threshold":0}}`,
		`{"frequent_item_sets":{"unknown":1}}`,
		`{"frequent_item_sets":{"fields":[]}}`,
		`{"frequent_item_sets":{"fields":[{"field":""}]}}`,
		`{"frequent_item_sets":{"fields":[{"field":"a"}],"minimum_set_size":0}}`,
		`{"frequent_item_sets":{"fields":[{"field":"a"}],"support":1.5}}`,
		`{"frequent_item_sets":{"fields":[{"field":"a"}],"size":0}}`,
		`{"moving_percentiles":{"unknown":1}}`,
		`{"moving_percentiles":{"buckets_path":""}}`,
		`{"moving_percentiles":{"buckets_path":"p","window":0}}`,
		`{"moving_percentiles":{"buckets_path":"p","window":3,"shift":-1}}`,
		`{"moving_percentiles":{"buckets_path":"p","window":3,"percents":[150]}}`,
		`{"moving_percentiles":{"buckets_path":"p","window":3,"gap_policy":"bad"}}`,
		`{"geo_line":{"unknown":1}}`,
		`{"geo_line":{"point":{"field":""},"sort":{"field":"t"}}}`,
		`{"geo_line":{"point":{"field":"p"},"sort":{"field":""}}}`,
		`{"geo_line":{"point":{"field":"p"},"sort":{"field":"t"},"sort_order":"sideways"}}`,
		`{"geo_line":{"point":{"field":"p"},"sort":{"field":"t"},"size":10001}}`,
		`{"random_sampler":{"unknown":1}}`,
		`{"random_sampler":{"probability":1.0}}`,
		`{"rare_terms":{"unknown":1}}`,
		`{"rare_terms":{"field":""}}`,
		`{"rare_terms":{"field":"t","max_doc_count":101}}`,
		`{"auto_date_histogram":{"unknown":1}}`,
		`{"auto_date_histogram":{}}`,
		`{"auto_date_histogram":{"field":"t","buckets":0}}`,
		`{"auto_date_histogram":{"field":"t","minimum_interval":"decade"}}`,
		`{"variable_width_histogram":{"unknown":1}}`,
		`{"variable_width_histogram":{}}`,
		`{"variable_width_histogram":{"field":"v","buckets":0}}`,
		`{"variable_width_histogram":{"field":"v","initial_buffer":0}}`,
		`{"variable_width_histogram":{"field":"v","shard_size":0}}`,
		`{"weighted_avg":{"unknown":1,"value":{"field":"v"},"weight":{"field":"w"}}}`,
		`{"weighted_avg":{"value":{"unknown":1},"weight":{"field":"w"}}}`,
		`{"adjacency_matrix":{"unknown":1}}`,
		`{"adjacency_matrix":{"filters":{}}}`,
		`{"adjacency_matrix":{"filters":{"a":{"match_all":{}}},"keyed":"maybe"}}`,
		`{"multi_terms":{"terms":[{"unknown":1,"field":"a"}]}}`,
		`{"multi_terms":{"terms":[{}]}}`,
		`{"matrix_stats":{"unknown":1}}`,
		`{"matrix_stats":{"fields":[]}}`,
		`{"matrix_stats":{"fields":[""]}}`,
		`{"matrix_stats":{"fields":["a"],"mode":"bogus"}}`,
		`{"t_test":{"unknown":1}}`,
		`{"t_test":{"a":{"unknown":1,"field":"x"},"b":{"field":"y"}}}`,
		`{"t_test":{"a":{},"b":{"field":"y"}}}`,
		`{"t_test":{"a":{"field":"x"}}}`,
		`{"top_hits":{"unknown":1}}`,
		`{"top_hits":{"from":-1}}`,
		`{"top_hits":{"size":-1}}`,
		`{"top_hits":{"version":"maybe"}}`,
		`{"top_hits":{"seq_no_primary_term":"maybe"}}`,
		`{"top_hits":{"explain":"maybe"}}`,
		`{"top_metrics":{"unknown":1}}`,
		`{"top_metrics":{"metrics":{"unknown":1,"field":"x"},"sort":["ts"]}}`,
		`{"top_metrics":{"metrics":{"field":""},"sort":["ts"]}}`,
		`{"top_metrics":{"metrics":123,"sort":["ts"]}}`,
		`{"top_metrics":{"size":0,"metrics":{"field":"x"},"sort":["ts"]}}`,
		`{"top_metrics":{"sort":["ts"]}}`,
		`{"top_metrics":{"metrics":{"field":"x"}}}`,
		`{"rate":{"unknown":1}}`,
		`{"rate":{"unit":"fortnight"}}`,
		`{"rate":{"mode":"median"}}`,
		`{"percentiles":{"unknown":1,"field":"x"}}`,
		`{"percentiles":{"field":"x","tdigest":{"compression":1},"hdr":{"number_of_significant_value_digits":2}}}`,
		`{"percentiles":{"field":"x","tdigest":{"unknown":1}}}`,
		`{"percentiles":{"field":"x","tdigest":{"compression":0}}}`,
		`{"percentiles":{"field":"x","tdigest":{"compression":-1}}}`,
		`{"percentiles":{"field":"x","tdigest":{"execution_hint":"bogus"}}}`,
		`{"percentiles":{"field":"x","hdr":null}}`,
		`{"percentiles":{"field":"x","hdr":{"unknown":1}}}`,
		`{"percentiles":{"field":"x","hdr":{"number_of_significant_value_digits":6}}}`,
		`{"filters":{"filters":123}}`,
		`{"filters":{}}`,
		`{"date_histogram":{"unknown":1}}`,
		`{"date_histogram":{"field":"t"}}`,
		`{"date_histogram":{"field":"t","calendar_interval":"1d","fixed_interval":"1d"}}`,
		`{"date_histogram":{"field":"t","calendar_interval":"bogus"}}`,
		`{"date_histogram":{"field":"t","fixed_interval":"bogus"}}`,
		`{"date_histogram":{"field":"t","interval":"bogus"}}`,
		`{"date_histogram":{"field":"t","calendar_interval":"1d","min_doc_count":-1}}`,
		`{"date_histogram":{"field":"t","calendar_interval":"1d","missing_order":"bogus"}}`,
		`{"date_histogram":{"field":"t","calendar_interval":"1d","order":{"_key":"sideways"}}}`,
		`{"date_histogram":{"field":"t","calendar_interval":"1d","order":[{"_key":"asc","b":"desc"}]}}`,
		`{"histogram":{"unknown":1}}`,
		`{"histogram":{"field":"n"}}`,
		`{"histogram":{"field":"n","interval":0}}`,
		`{"histogram":{"field":"n","interval":5,"min_doc_count":-1}}`,
		`{"histogram":{"field":"n","interval":5,"missing_order":"bad"}}`,
		`{"range":{"unknown":1}}`,
		`{"range":{"field":"n","ranges":[{"key":"empty"}]}}`,
		`{"range":{"field":"n","ranges":[{"from":10,"to":5}]}}`,
		`{"range":{"field":"n","ranges":[{"from":"2025-02-01","to":"2025-01-01"}]}}`,
		`{"nested":{"unknown":1}}`,
		`{"nested":{"path":""}}`,
		`{"avg":{"unknown":1}}`,
		`{"avg":{}}`,
		`{"avg":{"field":"f","sigma":-1}}`,
		`{"cardinality":{"field":"f","precision_threshold":50000}}`,
		`{"cardinality":{"field":"f","compression":0}}`,
		`{"moving_avg":{"unknown":1}}`,
		`{"moving_avg":{"buckets_path":""}}`,
		`{"moving_avg":{"buckets_path":"s","window":0}}`,
		`{"moving_avg":{"buckets_path":"s","shift":-1}}`,
		`{"moving_avg":{"buckets_path":"s","model":"bogus"}}`,
		`{"scripted_metric":{"unknown":1,"map_script":"1"}}`,
		`{"scripted_metric":{}}`,
		`{"serial_diff":{"unknown":1}}`,
		`{"serial_diff":{"buckets_path":"s","lag":0}}`,
		`{"normalize":{"unknown":1}}`,
		`{"normalize":{"buckets_path":"s","method":"bogus"}}`,
		`{"percentiles_bucket":{"unknown":1}}`,
		`{"percentiles_bucket":{"buckets_path":"s","percents":[200]}}`,
		`{"bucket_sort":{"unknown":1}}`,
		`{"bucket_sort":{"from":-1}}`,
		`{"bucket_sort":{"size":0}}`,
		`{"stats_bucket":{"unknown":1}}`,
		`{"stats_bucket":{"buckets_path":"s","sigma":-1}}`,
		`{"bucket_selector":{"unknown":1}}`,
		`{"bucket_selector":{"buckets_path":{},"script":"1"}}`,
		`{"bucket_selector":{"buckets_path":{"":"x"},"script":"1"}}`,
		`{"bucket_selector":{"buckets_path":{"a":"x"}}}`,
		`{"composite":{"unknown":1}}`,
		`{"composite":{}}`,
		`{"composite":{"sources":null}}`,
		`{"composite":{"sources":[]}}`,
	}
	for _, j := range badAggs {
		var a AggSpec
		if err := json.Unmarshal([]byte(j), &a); err == nil {
			t.Fatalf("expected error unmarshaling agg: %s", j)
		}
	}
}

func TestRound67CovEsast_SortTimeZoneAndRound61To63Helpers(t *testing.T) {
	// 1. SortSpec / SortSlice / unmarshalSortElement
	validSorts := []string{
		`null`,
		`"_score"`,
		`"price"`,
		`{"_script":{"script":"doc['a'].value","type":"number","order":"desc","mode":"min","missing":0,"nested":{"path":"items","filter":{"match_all":{}}}}}`,
		`{"_script":{"script":"1","type":"version"},"order":"asc","mode":"max","missing":"_last","nested_path":"p","nested_filter":{"match_all":{}}}`,
		`{"_geo_distance":{"pin":[-70,40],"order":"asc","mode":"min","unit":"km","distance_type":"plane","validation_method":"COERCE","ignore_unmapped":true,"unmapped_type":"geo_point","missing":"_last","nested":{"path":"locs"}}}`,
		`{"_geo_distance":{"pin":[[0,0],[1,1]]},"nested_path":"locs","nested_filter":{"match_all":{}}}`,
		`[{"a":"asc","b":"desc"},{"price":{"order":"desc","mode":"avg","missing":0,"numeric_type":"double","ignore_unmapped":true,"nested":{"path":"p"}}}]`,
		`{"order":"asc"}`,
	}
	for _, s := range validSorts {
		var ss SortSlice
		if err := json.Unmarshal([]byte(s), &ss); err != nil {
			t.Fatalf("expected valid sort %s, got %v", s, err)
		}
	}
	var spNull SortSpec
	if err := json.Unmarshal([]byte("null"), &spNull); err == nil {
		t.Fatalf("expected SortSpec null error")
	}
	for _, badSort := range []string{
		`[""]`,
		`[123]`,
		`[{}]`,
		`[{"a":null}]`,
		`[{"a":{"unknown":1}}]`,
		`[{"a":{"numeric_type":"bad"}}]`,
		`[{"a":{"ignore_unmapped":"maybe"}}]`,
		`[{"a":{"order":123}}]`,
		`[{"a":{"mode":123}}]`,
		`[{"_script":"bad"}]`,
		`[{"_script":{"script":"1","type":"number"},"bad_outer":1}]`,
		`[{"_script":{"script":"1","type":"number","bad_inner":1}}]`,
		`[{"_script":{"script":"1","type":"bad_type"}}]`,
		`[{"_geo_distance":"bad"}]`,
		`[{"_geo_distance":{}}]`,
		`[{"_geo_distance":{"pin":[0,0],"validation_method":"BAD"}}]`,
		`[{"_geo_distance":{"pin":[0,0],"distance_type":"euclidean"}}]`,
		`[{"_geo_distance":{"pin":[0,0],"unit":"lightyears"}}]`,
		`[{"_geo_distance":{"pin":[0,0],"ignore_unmapped":"maybe"}}]`,
		`[{"_geo_distance":{"pin":null}}]`,
		`[{"_geo_distance":{"pin":[]}}]`,
	} {
		var ss SortSlice
		if err := json.Unmarshal([]byte(badSort), &ss); err == nil {
			t.Fatalf("expected error unmarshaling sort %s", badSort)
		}
	}

	// 2. TimeZone & Duration & EffectiveIntervalMs
	for _, tc := range []struct {
		tz     string
		wantMs int64
	}{
		{"UTC", 0},
		{"+05:30", (5*3600 + 30*60) * 1000},
		{"-0430", -(4*3600 + 30*60) * 1000},
		{"+2", 2 * 3600 * 1000},
		{"America/New_York", -5 * 3600 * 1000},
		{"Invalid/Zone", 0},
	} {
		if got := ParseTimeZoneOffsetMs(tc.tz); got != tc.wantMs {
			t.Fatalf("ParseTimeZoneOffsetMs(%q) = %d, want %d", tc.tz, got, tc.wantMs)
		}
	}
	if _, _, _, err := ParseESTimeZone("+25:00"); err == nil {
		t.Fatalf("expected invalid +25:00 offset error")
	}
	if _, _, _, err := ParseESTimeZone("Mars/Olympus"); err == nil {
		t.Fatalf("expected invalid IANA zone error")
	}
	for _, iv := range []struct {
		raw    string
		wantMs int64
	}{
		{"500ms", 500},
		{"10s", 10000},
		{"5m", 5 * 60 * 1000},
		{"2h", 2 * 3600 * 1000},
		{"3d", 3 * 86400 * 1000},
		{"2w", 2 * 7 * 86400 * 1000},
		{"2M", 2 * 30 * 86400 * 1000},
		{"2y", 2 * 365 * 86400 * 1000},
		{"fallback", 86400 * 1000},
	} {
		d := DateHistogramAggSpec{FixedInterval: iv.raw}
		if got := d.EffectiveIntervalMs(); got != iv.wantMs {
			t.Fatalf("EffectiveIntervalMs(%q) = %d, want %d", iv.raw, got, iv.wantMs)
		}
	}
	if ((*DateHistogramAggSpec)(nil)).EffectiveOffsetMs() != 0 ||
		((*DateHistogramAggSpec)(nil)).EffectiveTimeZoneOffsetMs() != 0 {
		t.Fatalf("expected nil DateHistogram offset helpers 0")
	}

	// 3. round61_ast.go helpers
	if got, err := DecodeHexSignedByteVector("7f80"); err != nil || got[0] != 127 || got[1] != -128 {
		t.Fatalf("unexpected DecodeHexSignedByteVector: got=%v err=%v", got, err)
	}
	for _, badHex := range []string{"", "abc", "zz"} {
		if _, err := DecodeHexSignedByteVector(badHex); err == nil {
			t.Fatalf("expected DecodeHexSignedByteVector error for %q", badHex)
		}
	}
	if _, _, _, err := parseKNNQueryVectorRawV2(json.RawMessage(`"zz"`)); err == nil {
		t.Fatalf("expected parseKNNQueryVectorRawV2 bad hex error")
	}
	if _, err := unmarshalMissingAggSpec([]byte(`null`)); err != nil {
		// expecting error!
	} else {
		t.Fatalf("expected unmarshalMissingAggSpec null error")
	}
	for _, badMiss := range [][]byte{[]byte(`{"unknown":1,"field":"f"}`), []byte(`{}`), []byte(`{"script":123}`)} {
		if _, err := unmarshalMissingAggSpec(badMiss); err == nil {
			t.Fatalf("expected unmarshalMissingAggSpec error for %s", badMiss)
		}
	}
	for _, badSSA := range []string{`[123]`, `"unclosed`, `123`, `["ok","bad` + "\n" + `"]`} {
		if _, err := parseStringOrStringArrayStrict(json.RawMessage(badSSA), "stats"); err == nil {
			t.Fatalf("expected parseStringOrStringArrayStrict error for %s", badSSA)
		}
	}
	if buckets, wasMap, err := parseFlexibleRangesArrayOrMap(json.RawMessage(`{"from":1,"to":5}`)); err != nil || wasMap || len(buckets) != 1 {
		t.Fatalf("unexpected single unkeyed range object parse: %+v wasMap=%v err=%v", buckets, wasMap, err)
	}
	if _, _, err := parseFlexibleRangesArrayOrMap(json.RawMessage(`123`)); err == nil {
		t.Fatalf("expected parseFlexibleRangesArrayOrMap error")
	}
	for _, tc := range []struct {
		v    float64
		want string
	}{
		{math.NaN(), "NaN"},
		{math.Inf(1), "Infinity"},
		{math.Inf(-1), "-Infinity"},
		{math.Copysign(0, -1), "-0.0"},
		{0.0, "0.0"},
		{1e8, "1.0E8"},
		{5.0, "5.0"},
		{1.25, "1.25"},
	} {
		if got := formatJavaDouble(tc.v); got != tc.want {
			t.Fatalf("formatJavaDouble(%v) = %q, want %q", tc.v, got, tc.want)
		}
	}
	if err := validateFiltersAggRawClauses([]byte(`[{}]`)); err == nil {
		t.Fatalf("expected empty clause error in validateFiltersAggRawClauses")
	}
	if err := validateFiltersAggRawClauses([]byte(`{"a":{}}`)); err == nil {
		t.Fatalf("expected empty map clause error in validateFiltersAggRawClauses")
	}

	// 4. round62_ast.go & round63_ast.go helpers
	if got, err := parseFlexibleDateHistogramOffset(json.RawMessage(`"-7h"`)); err != nil || got != "-7h" {
		t.Fatalf("unexpected parseFlexibleDateHistogramOffset: %q err=%v", got, err)
	}
	if _, err := parseFlexibleDateHistogramOffset(json.RawMessage(`true`)); err == nil {
		t.Fatalf("expected parseFlexibleDateHistogramOffset error")
	}
	if _, err := parseFlexiblePercentsSlice(json.RawMessage(`[]`), "percentiles"); err == nil {
		t.Fatalf("expected empty percents slice error")
	}
	if _, err := parseFlexiblePercentsSlice(json.RawMessage(`101`), "percentiles"); err == nil {
		t.Fatalf("expected >100 percents error")
	}
	if _, err := ValidateOnScriptError("bad"); err == nil {
		t.Fatalf("expected ValidateOnScriptError error")
	}
	var ipAgg IPPrefixAggSpec
	for _, badIP := range []string{
		`{"unknown":1}`,
		`{"prefix_length":8}`,
		`{"field":"ip"}`,
		`{"field":"ip","prefix_length":33,"is_ipv6":false}`,
		`{"field":"ip","prefix_length":129,"is_ipv6":true}`,
		`{"field":"ip","prefix_length":24,"min_doc_count":-1}`,
		`{"field":"ip","prefix_length":24,"keyed":"bad"}`,
		`{"field":"ip","prefix_length":24,"append_prefix_length":"bad"}`,
	} {
		if err := json.Unmarshal([]byte(badIP), &ipAgg); err == nil {
			t.Fatalf("expected IPPrefixAggSpec error for %s", badIP)
		}
	}
	var tsAgg TimeSeriesAggSpec
	for _, badTS := range []string{
		`{"unknown":1}`,
		`{"size":0}`,
		`{"shard_size":0}`,
		`{"size":10,"shard_size":5}`,
		`{"keyed":"bad"}`,
	} {
		if err := json.Unmarshal([]byte(badTS), &tsAgg); err == nil {
			t.Fatalf("expected TimeSeriesAggSpec error for %s", badTS)
		}
	}
	var chAgg ChildrenAggSpec
	var prAgg ParentAggSpec
	if err := json.Unmarshal([]byte(`{"type":"child"}`), &chAgg); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"type":"parent"}`), &prAgg); err != nil {
		t.Fatal(err)
	}
	for _, badJP := range []string{`{"unknown":1}`, `{}`} {
		if err := json.Unmarshal([]byte(badJP), &chAgg); err == nil {
			t.Fatalf("expected ChildrenAggSpec error for %s", badJP)
		}
		if err := json.Unmarshal([]byte(badJP), &prAgg); err == nil {
			t.Fatalf("expected ParentAggSpec error for %s", badJP)
		}
	}
	if n, ok := extractExactLargeIntNumber(json.RawMessage(`17446744073709551615`)); !ok || n == "" {
		t.Fatalf("expected exact large uint64, got %q %v", n, ok)
	}
	if _, ok := extractExactLargeIntNumber(json.RawMessage(`1234567890123456a`)); ok {
		t.Fatalf("expected non-digit large int false")
	}
	fp := FieldProperty{FetchFields: []map[string]any{{"field": "a"}}}
	if len(fp.LookupFetchFieldNames()) != 1 {
		t.Fatalf("expected 1 fetch field name")
	}
	if got, err := parseFlexibleLookupFetchFields(json.RawMessage(`["name",{"field":"ip"}]`)); err != nil || len(got) != 2 {
		t.Fatalf("unexpected parseFlexibleLookupFetchFields: %+v err=%v", got, err)
	}
	for _, badFF := range []string{`"str"`, `[null]`, `[""]`, `[{}]`, `[123]`} {
		if _, err := parseFlexibleLookupFetchFields(json.RawMessage(badFF)); err == nil {
			t.Fatalf("expected parseFlexibleLookupFetchFields error for %s", badFF)
		}
	}
}
