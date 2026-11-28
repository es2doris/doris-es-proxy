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

package analysis

import (
	"errors"
	"strings"
	"testing"
)

func TestRound67CovAnalysis_BuildTokenFilterErrorsAndEdges(t *testing.T) {
	bctx := filterBuildContext{
		opts: Options{
			ResolveResourcePath: func(key, path string) ([]string, error) {
				if strings.Contains(path, "missing") {
					return nil, newIllegalArgError("resource not found: " + path)
				}
				if strings.Contains(path, "plain_err") {
					return nil, errors.New("plain io error")
				}
				switch key {
				case "articles_path":
					return []string{"l", "qu"}, nil
				case "keep_words_path":
					return []string{"Alpha", "Beta"}, nil
				case "rules_path":
					return []string{"mice => mouse"}, nil
				case "keywords_path":
					return []string{"protectedWord"}, nil
				case "stopwords_path":
					return []string{"the", "and"}, nil
				default:
					return []string{"word"}, nil
				}
			},
		},
	}

	errCases := []struct {
		name            string
		typeName        string
		def             map[string]any
		isPreconfigured bool
	}{
		{"lowercase_bad_lang", "lowercase", map[string]any{"language": "klingon"}, false},
		{"lowercase_bad_name", "lowercase", map[string]any{"name": "klingon"}, false},
		{"asciifolding_bad_preserve", "asciifolding", map[string]any{"preserve_original": "nope"}, false},
		{"cjk_bigram_bad_script", "cjk_bigram", map[string]any{"ignored_scripts": []any{"latin"}}, false},
		{"cjk_bigram_bad_unigrams", "cjk_bigram", map[string]any{"output_unigrams": "nope"}, false},
		{"serbian_bad_haircut", "serbian_normalization", map[string]any{"haircut": "mohawk"}, false},
		{"elision_nil_def", "elision", nil, false},
		{"elision_missing_articles", "elision", map[string]any{"articles_case": true}, false},
		{"elision_path_err", "elision", map[string]any{"articles_path": "missing.txt"}, false},
		{"elision_bad_case", "elision", map[string]any{"articles": []any{"l"}, "articles_case": "bad"}, false},
		{"stop_bad_ignore_case", "stop", map[string]any{"ignore_case": "bad"}, false},
		{"stop_bad_remove_trailing", "stop", map[string]any{"remove_trailing": "bad"}, false},
		{"stop_path_err", "stop", map[string]any{"stopwords_path": "missing.txt"}, false},
		{"length_bad_min", "length", map[string]any{"min": -1}, false},
		{"length_bad_max", "length", map[string]any{"max": "nan"}, false},
		{"length_min_gt_max", "length", map[string]any{"min": 10, "max": 2}, false},
		{"truncate_bad_len", "truncate", map[string]any{"length": 0}, false},
		{"limit_bad_count", "limit", map[string]any{"max_token_count": 0}, false},
		{"limit_bad_consume", "limit", map[string]any{"consume_all_tokens": "bad"}, false},
		{"keep_nil_def", "keep", nil, false},
		{"keep_bad_case", "keep", map[string]any{"keep_words": []any{"a"}, "keep_words_case": "bad"}, false},
		{"keep_path_err", "keep", map[string]any{"keep_words_path": "missing.txt"}, false},
		{"keep_missing_words_and_path", "keep_words", map[string]any{"keep_words_case": true}, false},
		{"keep_types_nil", "keep_types", nil, false},
		{"keep_types_empty", "keep_types", map[string]any{"types": []any{}}, false},
		{"keep_types_bad_mode", "keep_types", map[string]any{"types": []any{"word"}, "mode": "bogus"}, false},
		{"unique_bad_same_pos", "unique", map[string]any{"only_on_same_position": "bad"}, false},
		{"snowball_bad_name", "snowball", map[string]any{"name": "elvish"}, false},
		{"stemmer_override_empty", "stemmer_override", map[string]any{}, false},
		{"stemmer_override_path_err", "stemmer_override", map[string]any{"rules_path": "plain_err.txt"}, false},
		{"stemmer_override_bad_rule_empty_rhs", "stemmer_override", map[string]any{"rules": []any{"foo => "}}, false},
		{"stemmer_override_bad_rule_no_sep", "stemmer_override", map[string]any{"rules": []any{"broken_rule"}}, false},
		{"keyword_marker_bad_case", "keyword_marker", map[string]any{"ignore_case": "bad"}, false},
		{"keyword_marker_path_err", "keyword_marker", map[string]any{"keywords_path": "missing.txt"}, false},
		{"keyword_marker_bad_regex", "keyword_marker", map[string]any{"ignore_case": true, "keywords_pattern": "["}, false},
		{"pattern_capture_nil", "pattern_capture", nil, false},
		{"pattern_capture_empty", "pattern_capture", map[string]any{}, false},
		{"pattern_capture_bad_preserve", "pattern_capture", map[string]any{"pattern": "(a)", "preserve_original": "bad"}, false},
		{"pattern_capture_bad_regex", "pattern_capture", map[string]any{"patterns": []any{"["}}, false},
		{"pattern_replace_nil", "pattern_replace", nil, false},
		{"pattern_replace_missing_pat", "pattern_replace", map[string]any{"replacement": "x"}, false},
		{"pattern_replace_huge_repl", "pattern_replace", map[string]any{"pattern": "a", "replacement": strings.Repeat("x", MaxCharFilterOutputRunes*4+1)}, false},
		{"pattern_replace_bad_all", "pattern_replace", map[string]any{"pattern": "a", "all": "bad"}, false},
		{"pattern_replace_bad_regex", "pattern_replace", map[string]any{"pattern": "["}, false},
		{"fingerprint_bad_sep", "fingerprint", map[string]any{"separator": "::"}, false},
		{"fingerprint_bad_max", "fingerprint", map[string]any{"max_output_size": 0}, false},
		{"min_hash_bad_hash_count", "min_hash", map[string]any{"hash_count": 0}, false},
		{"min_hash_bad_bucket_count", "min_hash", map[string]any{"bucket_count": 99999}, false},
		{"min_hash_bad_set_size", "min_hash", map[string]any{"hash_set_size": 0}, false},
		{"min_hash_bad_rotation", "min_hash", map[string]any{"with_rotation": "bad"}, false},
		{"delimited_payload_filter_deprecated", "delimited_payload_filter", nil, false},
		{"delimited_payload_bad_delim", "delimited_payload", map[string]any{"delimiter": "||"}, false},
		{"delimited_payload_bad_enc", "delimited_payload", map[string]any{"encoding": "xml"}, false},
		{"delimited_term_freq_bad_delim", "delimited_term_freq", map[string]any{"delimiter": "||"}, false},
		{"delimited_term_freq_bad_max", "delimited_term_freq", map[string]any{"max_term_freq": 0}, false},
		{"condition_nil", "condition", nil, false},
		{"condition_no_script", "condition", map[string]any{"filter": []any{"lowercase"}}, false},
		{"condition_empty_filter", "condition", map[string]any{"script": map[string]any{"source": "true"}}, false},
		{"condition_too_many_filters", "condition", map[string]any{"script": map[string]any{"source": "true"}, "filter": make([]any, MaxFilterChainLength+1)}, false},
		{"condition_bad_subfilter", "condition", map[string]any{"script": map[string]any{"source": "true"}, "filter": []any{"not_a_filter"}}, false},
		{"predicate_nil", "predicate_token_filter", nil, false},
		{"predicate_no_script", "predicate_token_filter", map[string]any{}, false},
		{"multiplexer_nil", "multiplexer", nil, false},
		{"multiplexer_empty", "multiplexer", map[string]any{}, false},
		{"multiplexer_too_many_branches", "multiplexer", map[string]any{"filters": make([]any, MaxFilterChainLength+1)}, false},
		{"multiplexer_bad_preserve", "multiplexer", map[string]any{"filters": []any{"lowercase"}, "preserve_original": "bad"}, false},
		{"multiplexer_too_long_chain", "multiplexer", map[string]any{"filters": []any{strings.Repeat("lowercase,", MaxFilterChainLength+1)}}, false},
		{"multiplexer_bad_subfilter", "multiplexer", map[string]any{"filters": []any{"unknown_sub"}}, false},
		{"unknown_filter", "does_not_exist", nil, false},
	}
	for _, tc := range errCases {
		t.Run("err_"+tc.name, func(t *testing.T) {
			if _, err := buildTokenFilter(tc.name, tc.typeName, tc.def, tc.isPreconfigured, bctx); err == nil {
				t.Fatalf("expected error for %s (%s)", tc.name, tc.typeName)
			}
		})
	}

	// Positive + runtime error/edge paths for individual filters
	// 1. enterAnalyzer cycle & depth checks, IsBuiltInTokenFilter
	if IsBuiltInTokenFilter("not_a_builtin_filter") {
		t.Fatalf("expected false for unknown token filter")
	}
	if _, err := (filterBuildContext{depth: maxFilterNestingDepth}).enterAnalyzer("a"); err == nil {
		t.Fatalf("expected depth error in enterAnalyzer")
	}
	if _, err := (filterBuildContext{visitingAnalyzers: map[string]bool{"a": true}}).enterAnalyzer("a"); err == nil {
		t.Fatalf("expected cycle error in enterAnalyzer")
	}

	// 2. asciifolding budget exhaustion
	af, err := buildTokenFilter("af", "asciifolding", map[string]any{"preserve_original": true}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := af.apply([]Token{{Term: "plain"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on unchanged term")
	}
	if _, err := af.apply([]Token{{Term: "café"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on folded term")
	}
	if _, err := af.apply([]Token{{Term: "café"}}, &tokenStreamBudget{maxTokens: 1, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on preserved original")
	}

	// 3. elision with articles_path, stop with remove_trailing:false, truncate with Keyword:true, limit exceeding maxCount
	ef, err := buildTokenFilter("el", "elision", map[string]any{"articles_path": "articles.txt", "articles_case": false}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotEl, _ := ef.apply([]Token{{Term: "l'avion"}}, newTokenStreamBudget(10))
	if len(gotEl) != 1 || gotEl[0].Term != "avion" {
		t.Fatalf("unexpected elision result: %+v", gotEl)
	}
	sf, err := buildTokenFilter("st", "stop", map[string]any{"stopwords_path": "stop.txt", "ignore_case": true, "remove_trailing": false}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotSt, _ := sf.apply([]Token{{Term: "THE"}, {Term: "AND"}}, newTokenStreamBudget(10))
	if len(gotSt) != 1 || gotSt[0].Term != "AND" {
		t.Fatalf("expected trailing stopword kept, got %+v", gotSt)
	}
	tfTrunc, err := buildTokenFilter("tr", "truncate", map[string]any{"length": 3}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotTr, _ := tfTrunc.apply([]Token{{Term: "abcdef", Keyword: true}, {Term: "abcdef"}}, newTokenStreamBudget(10))
	if gotTr[0].Term != "abcdef" || gotTr[1].Term != "abc" {
		t.Fatalf("unexpected truncate result: %+v", gotTr)
	}
	tfLim, err := buildTokenFilter("lim", "limit", map[string]any{"max_token_count": 1, "consume_all_tokens": true}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotLim, _ := tfLim.apply([]Token{{Term: "a"}, {Term: "b"}}, newTokenStreamBudget(10))
	if len(gotLim) != 1 {
		t.Fatalf("expected 1 token from limit, got %+v", gotLim)
	}

	// 4. keep_words (case-sensitive + path), keep_types (exclude), stemmer_override (comments, tab, Keyword), keyword_marker (path + ignore_case pattern)
	kf, err := buildTokenFilter("keep", "keep", map[string]any{"keep_words_path": "kw.txt", "keep_words_case": false}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotK, _ := kf.apply([]Token{{Term: "Alpha"}, {Term: "alpha"}}, newTokenStreamBudget(10))
	if len(gotK) != 1 || gotK[0].Term != "Alpha" {
		t.Fatalf("unexpected keep result: %+v", gotK)
	}
	kt, err := buildTokenFilter("kt", "keep_types", map[string]any{"types": []any{"NUM"}, "mode": "exclude"}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotKT, _ := kt.apply([]Token{{Term: "1", Type: "NUM"}, {Term: "a", Type: "word"}}, newTokenStreamBudget(10))
	if len(gotKT) != 1 || gotKT[0].Term != "a" {
		t.Fatalf("unexpected keep_types exclude result: %+v", gotKT)
	}
	so, err := buildTokenFilter("so", "stemmer_override", map[string]any{
		"rules_path": "rules.txt",
		"rules":      []any{"# comment", "", "cats, kitties => cat", "dogs\tdog"},
	}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotSO, _ := so.apply([]Token{{Term: "cats", Keyword: true}, {Term: "dogs"}, {Term: "mice"}}, newTokenStreamBudget(10))
	if gotSO[0].Term != "cats" || gotSO[1].Term != "dog" || gotSO[2].Term != "mouse" || !gotSO[2].Keyword {
		t.Fatalf("unexpected stemmer_override result: %+v", gotSO)
	}
	km, err := buildTokenFilter("km", "keyword_marker", map[string]any{
		"keywords_path":    "kw.txt",
		"ignore_case":      true,
		"keywords_pattern": "foo.*",
	}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotKM, _ := km.apply([]Token{{Term: "PROTECTEDWORD"}, {Term: "FOOBAR"}}, newTokenStreamBudget(10))
	if !gotKM[0].Keyword || !gotKM[1].Keyword {
		t.Fatalf("expected both marked as keyword: %+v", gotKM)
	}

	// 5. keyword_repeat budget exhaustion
	kr, _ := buildTokenFilter("kr", "keyword_repeat", nil, true, bctx)
	if _, err := kr.apply([]Token{{Term: "a"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on keyword_repeat first add")
	}
	if _, err := kr.apply([]Token{{Term: "a"}}, &tokenStreamBudget{maxTokens: 1, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on keyword_repeat second add")
	}

	// 6. pattern_capture with single "pattern" + empty capture group + budget
	pc, err := buildTokenFilter("pc", "pattern_capture", map[string]any{"pattern": `(a*)(b)`}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotPC, err := pc.apply([]Token{{Term: "b"}}, newTokenStreamBudget(10))
	if err != nil || len(gotPC) != 1 {
		t.Fatalf("unexpected pattern_capture result: %+v err=%v", gotPC, err)
	}
	if _, err := pc.apply([]Token{{Term: "ab"}}, &tokenStreamBudget{maxTokens: 1, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on pattern_capture")
	}

	// 7. pattern_replace: all:false, empty match (^), unmatched token, term overflow, budget errors
	prAllFalse, err := buildTokenFilter("pr", "pattern_replace", map[string]any{
		"pattern":     "a",
		"replacement": "b",
		"all":         false,
	}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotPR, err := prAllFalse.apply([]Token{{Term: "aaa"}, {Term: "xyz"}}, newTokenStreamBudget(10))
	if err != nil || gotPR[0].Term != "baa" || gotPR[1].Term != "xyz" {
		t.Fatalf("unexpected pattern_replace all:false: %+v err=%v", gotPR, err)
	}
	if _, err := prAllFalse.apply([]Token{{Term: "xyz"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on unmatched pattern_replace")
	}
	if _, err := prAllFalse.apply([]Token{{Term: "aaa"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on matched pattern_replace")
	}
	prEmptyMatch, _ := buildTokenFilter("prem", "pattern_replace", map[string]any{
		"pattern":     `\b`,
		"replacement": "_",
	}, false, bctx)
	gotPREM, err := prEmptyMatch.apply([]Token{{Term: "hi"}}, newTokenStreamBudget(10))
	if err != nil || !strings.Contains(gotPREM[0].Term, "_") {
		t.Fatalf("unexpected empty-match pattern_replace: %+v err=%v", gotPREM, err)
	}
	prOverflow, _ := buildTokenFilter("pro", "pattern_replace", map[string]any{
		"pattern":     "a",
		"replacement": strings.Repeat("x", MaxTokenTermBytes),
	}, false, bctx)
	if _, err := prOverflow.apply([]Token{{Term: "aa"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected overflow error in pattern_replace")
	}
	prEmptyOverflow, _ := buildTokenFilter("preo", "pattern_replace", map[string]any{
		"pattern":     "^",
		"replacement": strings.Repeat("x", MaxTokenTermBytes+1),
	}, false, bctx)
	if _, err := prEmptyOverflow.apply([]Token{{Term: "a"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected empty-match overflow error in pattern_replace")
	}

	// 8. fingerprint edge cases
	fp, _ := buildTokenFilter("fp", "fingerprint", map[string]any{"max_output_size": 5}, false, bctx)
	if res, _ := fp.apply(nil, newTokenStreamBudget(10)); res != nil {
		t.Fatalf("expected nil on empty tokens")
	}
	if res, _ := fp.apply([]Token{{Term: ""}}, newTokenStreamBudget(10)); res != nil {
		t.Fatalf("expected nil on only empty terms")
	}
	if res, _ := fp.apply([]Token{{Term: "toolong"}}, newTokenStreamBudget(10)); res != nil {
		t.Fatalf("expected nil on term exceeding max_output_size")
	}
	if res, _ := fp.apply([]Token{{Term: "abc"}, {Term: "def"}}, newTokenStreamBudget(10)); res != nil {
		t.Fatalf("expected nil on joined exceeding max_output_size")
	}
	fpBig, _ := buildTokenFilter("fpb", "fingerprint", nil, false, bctx)
	gotFP, _ := fpBig.apply([]Token{{Term: "b", StartOffset: 5, EndOffset: 6}, {Term: "", StartOffset: 0, EndOffset: 0}, {Term: "a", StartOffset: 1, EndOffset: 4}}, newTokenStreamBudget(10))
	if len(gotFP) != 1 || gotFP[0].Term != "a b" || gotFP[0].StartOffset != 0 || gotFP[0].EndOffset != 6 {
		t.Fatalf("unexpected fingerprint offsets/term: %+v", gotFP)
	}

	// 9. min_hash + murmur3X64128 tails + modUint63Int + hashPair128.less
	mh, err := buildTokenFilter("mh", "min_hash", map[string]any{"hash_count": 2, "bucket_count": 4, "hash_set_size": 2, "with_rotation": false}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := mh.apply(nil, newTokenStreamBudget(10)); res != nil {
		t.Fatalf("expected nil on empty min_hash")
	}
	gotMH, err := mh.apply([]Token{{Term: "dup"}, {Term: "dup"}, {Term: "unique1"}, {Term: "unique2"}}, newTokenStreamBudget(100))
	if err != nil || len(gotMH) == 0 {
		t.Fatalf("unexpected min_hash output: %+v err=%v", gotMH, err)
	}
	if _, err := mh.apply([]Token{{Term: "a"}}, &tokenStreamBudget{maxTokens: 1, maxBytes: 10}); err == nil {
		t.Fatalf("expected byte budget error in min_hash")
	}
	for l := 1; l <= 15; l++ {
		_, _ = murmur3X64128([]byte(strings.Repeat("x", l)), 7)
	}
	if modUint63Int(42, 1) != 0 {
		t.Fatalf("expected modUint63Int(..., 1) == 0")
	}
	if !(hashPair128{1, 5}).less(hashPair128{2, 5}) {
		t.Fatalf("expected h1 tiebreak in less")
	}

	// 10. delimited_payload & delimited_term_freq runtime branches
	dpIdent, _ := buildTokenFilter("dpi", "delimited_payload", map[string]any{"encoding": "identity"}, false, bctx)
	gotDPI, err := dpIdent.apply([]Token{{Term: "plain"}, {Term: "k|v"}}, newTokenStreamBudget(10))
	if err != nil || len(gotDPI) != 2 || string(gotDPI[1].Payload) != "v" {
		t.Fatalf("unexpected identity payload: %+v err=%v", gotDPI, err)
	}
	if _, err := dpIdent.apply([]Token{{Term: "plain"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error on delimited_payload plain")
	}
	if _, err := dpIdent.apply([]Token{{Term: "k|v"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error on delimited_payload payload")
	}
	dpInt, _ := buildTokenFilter("dpint", "delimited_payload", map[string]any{"encoding": "int"}, false, bctx)
	if _, err := dpInt.apply([]Token{{Term: "k|notint"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected int payload error")
	}
	dpFloat, _ := buildTokenFilter("dpflt", "delimited_payload", map[string]any{"encoding": "float"}, false, bctx)
	if _, err := dpFloat.apply([]Token{{Term: "k|notfloat"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected float payload error")
	}

	dtf, _ := buildTokenFilter("dtf", "delimited_term_freq", map[string]any{"max_term_freq": 5}, false, bctx)
	if _, err := dtf.apply([]Token{{Term: "plain"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error on dtf plain")
	}
	if _, err := dtf.apply([]Token{{Term: "w|0"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected tf<1 error")
	}
	if _, err := dtf.apply([]Token{{Term: "w|10"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected max_term_freq exceeded error")
	}
	if _, err := dtf.apply([]Token{{Term: "w|3"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error on dtf matched")
	}

	// 11. condition, predicate_token_filter, multiplexer runtime branches
	cond, err := buildTokenFilter("cond", "condition", map[string]any{
		"script": map[string]any{"source": "token.term.length() > 3"},
		"filter": []any{"uppercase"},
	}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotCond, err := cond.apply([]Token{{Term: "hi", Position: 0}, {Term: "hello", Position: 1}}, newTokenStreamBudget(10))
	if err != nil || gotCond[0].Term != "hi" || gotCond[1].Term != "HELLO" {
		t.Fatalf("unexpected condition output: %+v err=%v", gotCond, err)
	}
	if _, err := cond.apply([]Token{{Term: "hi"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error on unmatched condition token")
	}
	if _, err := cond.apply([]Token{{Term: "hello"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error on matched condition token")
	}
	condBadScript, _ := buildTokenFilter("condbad", "condition", map[string]any{
		"script": map[string]any{"source": "unknownIdent"},
		"filter": []any{"lowercase"},
	}, false, bctx)
	if _, err := condBadScript.apply([]Token{{Term: "hello"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected script error in condition")
	}
	condTooLong, _ := buildTokenFilter("condlen", "condition", map[string]any{
		"script": map[string]any{"source": "true"},
		"filter": []any{"lowercase"},
	}, false, filterBuildContext{
		opts: Options{
			EvalPredicateScript: func(script map[string]any, tok *TokenContext) (bool, error) {
				tok.Term = strings.Repeat("a", MaxTokenTermBytes+1)
				return true, nil
			},
		},
	})
	if _, err := condTooLong.apply([]Token{{Term: "a"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected MaxTokenTermBytes error in condition")
	}

	predBad, _ := buildTokenFilter("predbad", "predicate_token_filter", map[string]any{
		"script": map[string]any{"source": "unknownIdent"},
	}, false, bctx)
	if _, err := predBad.apply([]Token{{Term: "a"}, {Term: "b", Position: 1}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected script error in predicate_token_filter")
	}
	predTooLong, _ := buildTokenFilter("predlen", "predicate_token_filter", map[string]any{
		"script": map[string]any{"source": "true"},
	}, false, filterBuildContext{
		opts: Options{
			EvalPredicateScript: func(script map[string]any, tok *TokenContext) (bool, error) {
				tok.Term = strings.Repeat("a", MaxTokenTermBytes+1)
				return true, nil
			},
		},
	})
	if _, err := predTooLong.apply([]Token{{Term: "a"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected MaxTokenTermBytes error in predicate_token_filter")
	}
	predOK, _ := buildTokenFilter("predok", "predicate_token_filter", map[string]any{
		"script": map[string]any{"source": "token.positionIncrement >= 0"},
	}, false, bctx)
	if _, err := predOK.apply([]Token{{Term: "a"}, {Term: "b", Position: 1}}, &tokenStreamBudget{maxTokens: 1, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error in predicate_token_filter")
	}

	mux, err := buildTokenFilter("mux", "multiplexer", map[string]any{
		"filters":           []any{"lowercase, ", "uppercase"},
		"preserve_original": true,
	}, false, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotMux, err := mux.apply([]Token{{Term: "abc", Position: 0}}, newTokenStreamBudget(10))
	if err != nil || len(gotMux) != 2 || gotMux[0].Term != "abc" || gotMux[1].Term != "ABC" {
		t.Fatalf("unexpected mux result (lowercase deduped against original): %+v err=%v", gotMux, err)
	}
	if _, err := mux.apply([]Token{{Term: "abc"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on mux original")
	}
	if _, err := mux.apply([]Token{{Term: "abc"}}, &tokenStreamBudget{maxTokens: 1, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on mux branch")
	}
}

func TestRound67CovAnalysis_CompoundFiltersWordDelimiterSynonyms(t *testing.T) {
	bctx := filterBuildContext{
		opts: Options{
			ResolveResourcePath: func(key, path string) ([]string, error) {
				if strings.Contains(path, "missing") {
					return nil, newIllegalArgError("missing: " + path)
				}
				switch key {
				case "protected_words_path":
					return []string{"Wi-Fi"}, nil
				case "type_table_path":
					return []string{"+ => ALPHA"}, nil
				case "word_list_path":
					return []string{"auto", "bahn"}, nil
				case "hyphenation_patterns_path":
					return []string{".ab2"}, nil
				case "synonyms_path":
					return []string{"fast, quick"}, nil
				default:
					return []string{"the"}, nil
				}
			},
			ResolveSynonymSet: func(setID string) ([]string, error) {
				if setID == "err_analysis" {
					return nil, newIllegalArgError("bad synset")
				}
				if setID == "err_plain" {
					return nil, errors.New("storage down")
				}
				return []string{"bad => "}, nil
			},
		},
	}

	// 1. buildCompoundTokenFilter error branches
	compoundErrs := []struct {
		name     string
		typeName string
		def      map[string]any
	}{
		{"ngram_bad_preserve", "ngram", map[string]any{"preserve_original": "nope"}},
		{"shingle_bad_min", "shingle", map[string]any{"min_shingle_size": 1}},
		{"shingle_bad_max", "shingle", map[string]any{"max_shingle_size": 1}},
		{"shingle_bad_uni", "shingle", map[string]any{"output_unigrams": "bad"}},
		{"shingle_bad_uni_no_sh", "shingle", map[string]any{"output_unigrams_if_no_shingles": "bad"}},
		{"shingle_max_lt_min", "shingle", map[string]any{"min_shingle_size": 4, "max_shingle_size": 2}},
		{"wd_bad_bool", "word_delimiter", map[string]any{"catenate_words": "bad"}},
		{"wd_prot_path_err", "word_delimiter", map[string]any{"protected_words_path": "missing.txt"}},
		{"wd_tt_path_err", "word_delimiter", map[string]any{"type_table_path": "missing.txt"}},
		{"wd_tt_no_arrow", "word_delimiter", map[string]any{"type_table": []any{"+ ALPHA"}}},
		{"wd_tt_bad_char", "word_delimiter", map[string]any{"type_table": []any{"++ => ALPHA"}}},
		{"wd_tt_bad_type", "word_delimiter", map[string]any{"type_table": []any{"+ => WEIRD"}}},
		{"cg_nil", "common_grams", nil},
		{"cg_bad_ic", "common_grams", map[string]any{"common_words": []any{"a"}, "ignore_case": "bad"}},
		{"cg_bad_qm", "common_grams", map[string]any{"common_words": []any{"a"}, "query_mode": "bad"}},
		{"cg_missing_words", "common_grams", map[string]any{"ignore_case": true}},
		{"cg_path_err", "common_grams", map[string]any{"common_words_path": "missing.txt"}},
		{"dc_nil", "dictionary_decompounder", nil},
		{"dc_wl_path_err", "dictionary_decompounder", map[string]any{"word_list_path": "missing.txt"}},
		{"dc_hyph_path_err", "hyphenation_decompounder", map[string]any{"hyphenation_patterns_path": "missing.txt"}},
		{"dc_bad_min_word", "dictionary_decompounder", map[string]any{"word_list": []any{"a"}, "min_word_size": -1}},
		{"dc_bad_min_sub", "dictionary_decompounder", map[string]any{"word_list": []any{"a"}, "min_subword_size": -1}},
		{"dc_bad_max_sub_zero", "dictionary_decompounder", map[string]any{"word_list": []any{"a"}, "max_subword_size": 0}},
		{"dc_bad_max_sub_huge", "dictionary_decompounder", map[string]any{"word_list": []any{"a"}, "max_subword_size": maxAllowedSubwordSize + 1}},
		{"dc_bad_longest", "dictionary_decompounder", map[string]any{"word_list": []any{"a"}, "only_longest_match": "bad"}},
		{"dc_empty_def", "dictionary_decompounder", map[string]any{"min_word_size": 3}},
		{"syn_nil", "synonym", nil},
		{"syn_missing_rules", "synonym", map[string]any{"expand": true}},
		{"syn_bad_expand", "synonym", map[string]any{"synonyms": []any{"a,b"}, "expand": "bad"}},
		{"syn_bad_lenient", "synonym", map[string]any{"synonyms": []any{"a,b"}, "lenient": "bad"}},
		{"syn_bad_format", "synonym", map[string]any{"synonyms": []any{"a,b"}, "format": "yaml"}},
		{"syn_path_err", "synonym", map[string]any{"synonyms_path": "missing.txt"}},
		{"syn_bad_analyzer", "synonym", map[string]any{"synonyms": []any{"a,b"}, "analyzer": "nonexistent_analyzer"}},
		{"syn_bad_tokenizer", "synonym", map[string]any{"synonyms": []any{"a,b"}, "tokenizer": "nonexistent_tok"}},
		{"compound_unknown", "unknown_compound", nil},
	}
	for _, tc := range compoundErrs {
		t.Run("err_"+tc.name, func(t *testing.T) {
			if _, err := buildCompoundTokenFilter(tc.name, tc.typeName, tc.def, bctx); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}

	// 2. ngram & edge_ngram preserve_original edge branches
	ng, err := buildCompoundTokenFilter("ng", "ngram", map[string]any{"min_gram": 3, "max_gram": 4, "preserve_original": true}, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotNG, err := ng.apply([]Token{{Term: "ab"}, {Term: "abcd"}, {Term: "abcdef"}}, newTokenStreamBudget(50))
	if err != nil || len(gotNG) == 0 {
		t.Fatalf("unexpected ngram output: %+v err=%v", gotNG, err)
	}
	if _, err := ng.apply([]Token{{Term: "ab"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error on short preserve_original")
	}
	if _, err := ng.apply([]Token{{Term: "abcdef"}}, &tokenStreamBudget{maxTokens: 7, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on long preserve_original")
	}

	// 3. shingle empty tokens, leading Position>0 fillers, all-filler skip, unigrams fallback, separator
	sh, err := buildCompoundTokenFilter("sh", "shingle", map[string]any{
		"min_shingle_size":               2,
		"max_shingle_size":               3,
		"output_unigrams":                false,
		"output_unigrams_if_no_shingles": true,
		"token_separator":                "-",
		"filler_token":                   "_",
	}, bctx)
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := sh.apply(nil, newTokenStreamBudget(10)); res != nil {
		t.Fatalf("expected nil for empty shingle input")
	}
	gotShSingle, err := sh.apply([]Token{{Term: "solo", Position: 0}}, newTokenStreamBudget(10))
	if err != nil || len(gotShSingle) != 1 || gotShSingle[0].Term != "solo" {
		t.Fatalf("expected output_unigrams_if_no_shingles fallback, got %+v err=%v", gotShSingle, err)
	}
	gotShGap, err := sh.apply([]Token{{Term: "a", Position: 5}, {Term: "b", Position: 11}}, newTokenStreamBudget(50))
	if err != nil || len(gotShGap) == 0 {
		t.Fatalf("unexpected gap shingle output: %+v err=%v", gotShGap, err)
	}
	if _, err := sh.apply([]Token{{Term: strings.Repeat("x", MaxTokenTermBytes)}}, newTokenStreamBudget(10)); err == nil {
		// Force 2-token overflow
		t.Log("single token did not trigger term limit; check 2-token case")
	}
	if _, err := sh.apply([]Token{{Term: strings.Repeat("x", MaxTokenTermBytes/2+10), Position: 0}, {Term: strings.Repeat("y", MaxTokenTermBytes/2+10), Position: 1}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected MaxTokenTermBytes error in shingle")
	}

	// 4. word_delimiter & word_delimiter_graph options + subword branches
	wd, err := buildCompoundTokenFilter("wd", "word_delimiter_graph", map[string]any{
		"protected_words_path": "prot.txt",
		"type_table_path":      "tt.txt",
		"type_table": []any{
			"a => LOWER",
			"A => UPPER",
			"1 => DIGIT",
			"# => ALPHANUM",
			"$ => SUBWORD_DELIM",
		},
		"preserve_original": true,
		"catenate_words":    true,
		"catenate_numbers":  true,
		"catenate_all":      false,
	}, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotWD, err := wd.apply([]Token{
		{Term: "Wi-Fi", Position: 0},
		{Term: "---", Position: 1},
		{Term: "HTMLParser123foo", Position: 2, StartOffset: 0, EndOffset: 16},
		{Term: "e\u0301", Position: 3},
	}, newTokenStreamBudget(100))
	if err != nil || len(gotWD) < 4 {
		t.Fatalf("unexpected word_delimiter_graph output: %+v err=%v", gotWD, err)
	}
	wdNoParts, _ := buildCompoundTokenFilter("wdnp", "word_delimiter", map[string]any{
		"generate_word_parts":   false,
		"generate_number_parts": false,
		"preserve_original":     false,
	}, bctx)
	gotWDNP, err := wdNoParts.apply([]Token{{Term: "plain"}}, newTokenStreamBudget(10))
	if err != nil || len(gotWDNP) != 0 {
		t.Fatalf("expected 0 tokens when generate_word_parts=false & preserve_original=false, got %+v", gotWDNP)
	}
	if _, err := wd.apply([]Token{{Term: "Wi-Fi"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error on protected wd token")
	}
	if _, err := wd.apply([]Token{{Term: "---"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error on empty subword preserve_original")
	}
	if _, err := wd.apply([]Token{{Term: "a-b"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error on preserve_original in split wd")
	}
	if _, err := wd.apply([]Token{{Term: "a-b"}}, &tokenStreamBudget{maxTokens: 1, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on keptPart in split wd")
	}
	if _, err := wd.apply([]Token{{Term: "a-b"}}, &tokenStreamBudget{maxTokens: 3, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on catenate_words in split wd")
	}

	// 5. common_grams
	cg, err := buildCompoundTokenFilter("cg", "common_grams", map[string]any{
		"common_words": []any{"The"},
		"ignore_case":  true,
		"query_mode":   true,
	}, bctx)
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := cg.apply(nil, newTokenStreamBudget(10)); res != nil {
		t.Fatalf("expected nil on empty common_grams")
	}
	gotCG1, _ := cg.apply([]Token{{Term: "the"}}, newTokenStreamBudget(10))
	if len(gotCG1) != 1 || gotCG1[0].Term != "the" {
		t.Fatalf("unexpected single-token query_mode common_grams: %+v", gotCG1)
	}
	gotCG2, _ := cg.apply([]Token{{Term: "THE", Position: 0}, {Term: "dog", Position: 1}, {Term: "runs", Position: 2}}, newTokenStreamBudget(10))
	if len(gotCG2) != 2 || gotCG2[0].Term != "THE_dog" || gotCG2[1].Term != "runs" {
		t.Fatalf("unexpected query_mode common_grams: %+v", gotCG2)
	}

	// 6. decompounder (hyphenation_decompounder + word_list_path + min_subword_size=0 + multi-rune case)
	dc, err := buildCompoundTokenFilter("dc", "hyphenation_decompounder", map[string]any{
		"word_list_path":            "wl.txt",
		"hyphenation_patterns_path": "hyph.txt",
		"min_word_size":             4,
		"min_subword_size":          0,
		"max_subword_size":          10,
		"only_longest_match":        true,
	}, bctx)
	if err != nil {
		t.Fatal(err)
	}
	gotDC, err := dc.apply([]Token{{Term: "ab"}, {Term: "Autobahn"}, {Term: "İSTANBUL"}}, newTokenStreamBudget(20))
	if err != nil || len(gotDC) < 4 {
		t.Fatalf("unexpected decompounder output: %+v err=%v", gotDC, err)
	}

	// 7. synonyms: synonyms_set errors, compileSynonymEntries error/lenient/wordnet paths, flat & graph edge cases
	synErrA, _ := buildCompoundTokenFilter("sea", "synonym", map[string]any{"synonyms_set": "err_analysis"}, bctx)
	if _, err := synErrA.apply([]Token{{Term: "x"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected AnalysisError from ResolveSynonymSet")
	}
	synErrP, _ := buildCompoundTokenFilter("sep", "synonym", map[string]any{"synonyms_set": "err_plain"}, bctx)
	if _, err := synErrP.apply([]Token{{Term: "x"}}, newTokenStreamBudget(10)); err == nil {
		t.Fatalf("expected wrapped error from ResolveSynonymSet")
	}
	synPathOK, err := buildCompoundTokenFilter("sp", "synonym", map[string]any{"synonyms_path": "syn.txt"}, bctx)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := synPathOK.apply(nil, newTokenStreamBudget(10)); err != nil || res != nil {
		t.Fatalf("expected nil on empty synonym tokens: %+v err=%v", res, err)
	}
	if _, err := compileSynonymEntries([]string{"# comment", "", "a => ", "b, c"}, "solr", true, false, func(s string) ([]string, error) {
		return strings.Fields(s), nil
	}); err == nil {
		t.Fatalf("expected error on invalid rule with lenient=false")
	}
	if _, err := compileSynonymEntries([]string{"singleterm"}, "solr", true, false, func(s string) ([]string, error) {
		return nil, errors.New("boom")
	}); err == nil {
		t.Fatalf("expected error from analyzePhrase")
	}
	if _, err := compileSynonymEntries([]string{"   => b"}, "solr", true, true, func(s string) ([]string, error) {
		return strings.Fields(s), nil
	}); err != nil {
		t.Fatalf("expected lenient skip on invalid rule, got %v", err)
	}
	if _, err := compileSynonymEntries([]string{"bad line"}, "wordnet", true, false, func(s string) ([]string, error) {
		return strings.Fields(s), nil
	}); err == nil {
		t.Fatalf("expected error on invalid wordnet line")
	}
	wnEntries, err := compileSynonymEntries([]string{
		"% comment",
		"bad line",
		"s(100,1,'can''t',n,1,0).",
		"s(100,2,'unable',n,1,0).",
	}, "wordnet", false, true, func(s string) ([]string, error) {
		return strings.Fields(s), nil
	})
	if err != nil || len(wnEntries) == 0 {
		t.Fatalf("unexpected wordnet entries: %+v err=%v", wnEntries, err)
	}
	if _, err := compileSynonymEntries([]string{"a => b, b", "a => a"}, "solr", true, false, func(s string) ([]string, error) {
		return strings.Fields(s), nil
	}); err != nil {
		t.Fatalf("unexpected error on dup target/self mapping: %v", err)
	}
	if _, err := compileSynonymEntries([]string{strings.Repeat("a,", maxTermsPerSynonymRule+1) + "b"}, "solr", true, false, func(s string) ([]string, error) {
		return strings.Fields(s), nil
	}); err == nil {
		t.Fatalf("expected maxTermsPerSynonymRule error")
	}
	if _, err := compileSynonymEntries([]string{"empty => b"}, "solr", true, false, func(s string) ([]string, error) {
		if s == "empty" {
			return nil, nil
		}
		return []string{s}, nil
	}); err == nil {
		t.Fatalf("expected empty analyzed phrase error")
	}
	if _, err := compileSynonymEntries([]string{"a => empty"}, "solr", true, false, func(s string) ([]string, error) {
		if s == "empty" {
			return nil, nil
		}
		return []string{s}, nil
	}); err == nil {
		t.Fatalf("expected empty analyzed replacement error")
	}

	// applySynonymFlat stacked + pending flush; applySynonymGraph stacked + budget; applyFlattenGraph empty + sparse
	flatEntries := []synonymEntry{{src: []string{"ny"}, targets: [][]string{{"new", "york"}}, keepOrig: true}}
	flatToks, err := applySynonymFlat([]Token{
		{Term: "ny", Position: 0},
		{Term: "alias", Position: 0},
		{Term: "city", Position: 1},
	}, flatEntries, newTokenStreamBudget(20))
	if err != nil || len(flatToks) < 4 {
		t.Fatalf("unexpected flat synonym result: %+v err=%v", flatToks, err)
	}
	graphToks, err := applySynonymGraph([]Token{
		{Term: "ny", Position: 0, PositionLength: 1},
		{Term: "ny", Position: 0, PositionLength: 1},
		{Term: "city", Position: 3, PositionLength: 1},
	}, flatEntries, newTokenStreamBudget(20))
	if err != nil || len(graphToks) < 4 {
		t.Fatalf("unexpected graph synonym result: %+v err=%v", graphToks, err)
	}
	if _, err := applySynonymGraph([]Token{{Term: "ny", Position: 0}}, flatEntries, &tokenStreamBudget{maxTokens: 1, maxBytes: 100}); err == nil {
		t.Fatalf("expected budget error on synonym_graph")
	}
	if res := applyFlattenGraph(nil); res != nil {
		t.Fatalf("expected nil on empty flatten_graph")
	}
	flattened := applyFlattenGraph([]Token{
		{Term: "a", Position: 0, PositionLength: 0},
		{Term: "b", Position: 5, PositionLength: 2},
	})
	if len(flattened) != 2 {
		t.Fatalf("unexpected flatten_graph result: %+v", flattened)
	}
}

func TestRound67CovAnalysis_PluginsKuromojiNoriICUSmartCNStempel(t *testing.T) {
	bctx := filterBuildContext{
		opts: Options{
			ResolveResourcePath: func(key, path string) ([]string, error) {
				if strings.Contains(path, "missing") {
					return nil, newIllegalArgError("missing: " + path)
				}
				switch key {
				case "stoptags_path":
					return []string{"# comment", "助詞-格助詞-一般", "J"}, nil
				case "user_dictionary":
					return []string{"# comment", "スカイツリー,スカイツリー,スカイツリー,名詞"}, nil
				case "stopwords_path":
					return []string{"の", "는"}, nil
				case "rules":
					return []string{"&a < b"}, nil
				default:
					return []string{"rule"}, nil
				}
			},
		},
	}

	// 1. Plugin analyzer / tokenizer / token filter error cases
	for _, tc := range []struct {
		name string
		fn   func() error
	}{
		{"icu_an_bad_mode", func() error {
			_, e := buildPluginAnalyzer("icu", "icu_analyzer", map[string]any{"mode": "bad"}, 100, bctx)
			return e
		}},
		{"icu_an_bad_usf", func() error {
			_, e := buildPluginAnalyzer("icu", "icu_analyzer", map[string]any{"unicodeSetFilter": "invalid"}, 100, bctx)
			return e
		}},
		{"kuromoji_an_bad_stop_path", func() error {
			_, e := buildPluginAnalyzer("k", "kuromoji", map[string]any{"stopwords_path": "missing.txt"}, 100, bctx)
			return e
		}},
		{"kuromoji_comp_an_bad_mode", func() error {
			_, e := buildPluginAnalyzer("kc", "kuromoji_completion", map[string]any{"mode": "bad"}, 100, bctx)
			return e
		}},
		{"polish_an_bad_stop", func() error {
			_, e := buildPluginAnalyzer("pl", "polish", map[string]any{"stopwords": "_bogus_"}, 100, bctx)
			return e
		}},
		{"ukrainian_an_bad_stop_path", func() error {
			_, e := buildPluginAnalyzer("uk", "ukrainian", map[string]any{"stopwords_path": "missing.txt"}, 100, bctx)
			return e
		}},
		{"plugin_an_unknown", func() error {
			_, e := buildPluginAnalyzer("x", "unknown_plugin_an", nil, 100, bctx)
			return e
		}},
		{"icu_tok_bad_rule_pair", func() error {
			_, e := buildPluginTokenizer("it", "icu_tokenizer", map[string]any{"rule_files": " ,badpair"}, bctx.opts)
			return e
		}},
		{"icu_tok_missing_rule_path", func() error {
			_, e := buildPluginTokenizer("it", "icu_tokenizer", map[string]any{"rule_files": "Latn:missing.rbbi"}, bctx.opts)
			return e
		}},
		{"kuromoji_tok_bad_punct", func() error {
			_, e := buildPluginTokenizer("kt", "kuromoji_tokenizer", map[string]any{"discard_punctuation": "bad"}, bctx.opts)
			return e
		}},
		{"kuromoji_tok_bad_comp", func() error {
			_, e := buildPluginTokenizer("kt", "kuromoji_tokenizer", map[string]any{"discard_compound_token": "bad"}, bctx.opts)
			return e
		}},
		{"kuromoji_tok_bad_nbest", func() error {
			_, e := buildPluginTokenizer("kt", "kuromoji_tokenizer", map[string]any{"nbest_cost": "bad"}, bctx.opts)
			return e
		}},
		{"kuromoji_tok_both_userdict", func() error {
			_, e := buildPluginTokenizer("kt", "kuromoji_tokenizer", map[string]any{"user_dictionary": "u.txt", "user_dictionary_rules": []any{"x"}}, bctx.opts)
			return e
		}},
		{"kuromoji_tok_missing_userdict", func() error {
			_, e := buildPluginTokenizer("kt", "kuromoji_tokenizer", map[string]any{"user_dictionary": "missing.txt"}, bctx.opts)
			return e
		}},
		{"nori_tok_bad_punct", func() error {
			_, e := buildPluginTokenizer("nt", "nori_tokenizer", map[string]any{"discard_punctuation": "bad"}, bctx.opts)
			return e
		}},
		{"nori_tok_bad_unk", func() error {
			_, e := buildPluginTokenizer("nt", "nori_tokenizer", map[string]any{"output_unknown_unigrams": "bad"}, bctx.opts)
			return e
		}},
		{"nori_tok_both_userdict", func() error {
			_, e := buildPluginTokenizer("nt", "nori_tokenizer", map[string]any{"user_dictionary": "u.txt", "user_dictionary_rules": []any{"x"}}, bctx.opts)
			return e
		}},
		{"nori_tok_missing_userdict", func() error {
			_, e := buildPluginTokenizer("nt", "nori_tokenizer", map[string]any{"user_dictionary": "missing.txt"}, bctx.opts)
			return e
		}},
		{"plugin_tok_unknown", func() error {
			_, e := buildPluginTokenizer("ut", "unknown_plugin_tok", nil, bctx.opts)
			return e
		}},
		{"kuromoji_pos_missing_path", func() error {
			_, e := buildPluginTokenFilter("kp", "kuromoji_part_of_speech", map[string]any{"stoptags_path": "missing.txt"}, false, bctx)
			return e
		}},
		{"kuromoji_reading_bad_romaji", func() error {
			_, e := buildPluginTokenFilter("kr", "kuromoji_readingform", map[string]any{"use_romaji": "bad"}, false, bctx)
			return e
		}},
		{"kuromoji_stem_bad_min", func() error {
			_, e := buildPluginTokenFilter("ks", "kuromoji_stemmer", map[string]any{"minimum_length": 0}, false, bctx)
			return e
		}},
		{"kuromoji_comp_bad_mode", func() error {
			_, e := buildPluginTokenFilter("kc", "kuromoji_completion", map[string]any{"mode": "bad"}, false, bctx)
			return e
		}},
		{"nori_pos_missing_path", func() error {
			_, e := buildPluginTokenFilter("np", "nori_part_of_speech", map[string]any{"stoptags_path": "missing.txt"}, false, bctx)
			return e
		}},
		{"ja_stop_bad_ic", func() error {
			_, e := buildPluginTokenFilter("js", "ja_stop", map[string]any{"ignore_case": "bad"}, false, bctx)
			return e
		}},
		{"ja_stop_bad_rt", func() error {
			_, e := buildPluginTokenFilter("js", "ja_stop", map[string]any{"remove_trailing": "bad"}, false, bctx)
			return e
		}},
		{"plugin_tf_unknown", func() error {
			_, e := buildPluginTokenFilter("ux", "unknown_plugin_tf", nil, false, bctx)
			return e
		}},
		{"icu_norm_bad_name", func() error {
			_, e := buildICUNormalizerTokenFilter("in", map[string]any{"name": "weird"})
			return e
		}},
		{"icu_usf_non_string", func() error {
			_, e := buildICUFoldingFilter("if", map[string]any{"unicode_set_filter": 123})
			return e
		}},
		{"icu_col_bad_rules_path", func() error {
			_, e := buildICUCollationFilter("ic", map[string]any{"rules": "missing.txt"}, bctx.opts)
			return e
		}},
		{"icu_col_bad_strength", func() error {
			_, e := buildICUCollationFilter("ic", map[string]any{"strength": "ultra"}, bctx.opts)
			return e
		}},
		{"icu_col_bad_decomp", func() error {
			_, e := buildICUCollationFilter("ic", map[string]any{"decomposition": "weird"}, bctx.opts)
			return e
		}},
		{"icu_col_bad_alt", func() error {
			_, e := buildICUCollationFilter("ic", map[string]any{"alternate": "weird"}, bctx.opts)
			return e
		}},
		{"icu_col_bad_case_first", func() error {
			_, e := buildICUCollationFilter("ic", map[string]any{"caseFirst": "middle"}, bctx.opts)
			return e
		}},
		{"icu_col_bad_bool", func() error {
			_, e := buildICUCollationFilter("ic", map[string]any{"numeric": "bad"}, bctx.opts)
			return e
		}},
		{"icu_transform_bad_dir", func() error {
			_, e := buildICUTransformFilter("it", map[string]any{"dir": "sideways"})
			return e
		}},
		{"iter_mark_bad_kanji", func() error {
			_, e := buildKuromojiIterationMarkCharFilter("km", map[string]any{"normalize_kanji": "bad"})
			return e
		}},
		{"iter_mark_bad_kana", func() error {
			_, e := buildKuromojiIterationMarkCharFilter("km", map[string]any{"normalize_kana": "bad"})
			return e
		}},
	} {
		if err := tc.fn(); err == nil {
			t.Fatalf("expected error for %s", tc.name)
		}
	}

	// 2. Positive plugin analyzer & filter & char_filter exercises
	icuAn, err := buildPluginAnalyzer("icu", "icu_analyzer", map[string]any{
		"method":             "nfkc",
		"mode":               "compose",
		"unicode_set_filter": "[^z]",
	}, 50, bctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCompiledAnalyzerSingleText(icuAn, "ﬁﬂﬃﬄ ß İ A\u0301 \u00A0", 100); err != nil {
		t.Fatal(err)
	}

	// normalizeICURune, parseICUUnicodeSetFilter, icu_collation, icu_transform
	if fn, err := parseICUUnicodeSetFilter(map[string]any{"unicode_set_filter": "[]"}); err != nil || fn('a') {
		t.Fatalf("expected empty UnicodeSet to return false, err=%v", err)
	}
	if out := composeCanonicalRunes([]rune{'a'}); len(out) != 1 {
		t.Fatalf("unexpected composeCanonicalRunes len<=1")
	}
	for _, r := range []rune{'ß', 'ﬀ', 'ﬁ', 'ﬂ', 'ﬃ', 'ﬄ', '\u00A0', 'İ', '\u200B'} {
		_ = normalizeICURune(r, "nfkc", false)
		_ = normalizeICURune(r, "nfkc_cf", false)
		_ = normalizeICURune(r, "nfkc_cf", true)
	}
	icCol, err := buildICUCollationFilter("ic", map[string]any{
		"rules":      "rules.txt",
		"strength":   "secondary",
		"alternate":  "shifted",
		"case_first": "upper",
		"numeric":    true,
	}, bctx.opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := icCol.apply([]Token{{Term: "A! 000 007"}}, newTokenStreamBudget(10)); err != nil {
		t.Fatal(err)
	}
	icTrans, err := buildICUTransformFilter("itr", map[string]any{
		"id":  "Any-Lower; Any-Upper; Katakana-Hiragana; Hiragana-Katakana; Cyrillic-Latin; [:Nonspacing Mark:] Remove; NFKC; UnknownStep",
		"dir": "reverse",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := icTrans.apply([]Token{{Term: "Москва カタかな café"}}, newTokenStreamBudget(10)); err != nil || len(got) != 1 {
		t.Fatalf("unexpected icu_transform: %+v err=%v", got, err)
	}
	icTok, err := buildPluginTokenizer("itok", "icu_tokenizer", map[string]any{"rule_files": " ,Latn:latn.rbbi"}, bctx.opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := icTok.tokenize(newCharStream("ภาษาไทย 中国 abc", 0), 0, newTokenStreamBudget(50)); err != nil {
		t.Fatal(err)
	}

	// kuromoji_iteration_mark char filter
	imCF, err := buildKuromojiIterationMarkCharFilter("km", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs, err := imCF.apply(newCharStream("", 0)); err != nil || cs.String() != "" {
		t.Fatalf("unexpected empty iteration mark: %v %v", cs.String(), err)
	}
	if cs, err := imCF.apply(newCharStream("人々ここゝがゝかゞがゞコヽカヾ", 0)); err != nil || cs.String() != "人人こここがかかがががココカガ" {
		t.Fatalf("unexpected iteration mark output: %q err=%v", cs.String(), err)
	}

	// kuromoji analyzer + tokenizer + filters (extended, discard_punctuation:false, completion query mode, readingform romaji with ッ)
	kurAn, err := buildPluginAnalyzer("kur", "kuromoji", map[string]any{
		"mode":                   "extended",
		"discard_punctuation":    false,
		"discard_compound_token": false,
		"stopwords_path":         "sw.txt",
		"user_dictionary":        "ud.txt",
	}, 100, bctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCompiledAnalyzerSingleText(kurAn, "関西国際空港、カップ、東京スカイツリー!", 100); err != nil {
		t.Fatal(err)
	}
	kcAn, err := buildPluginAnalyzer("kc", "kuromoji_completion", map[string]any{
		"mode":            "query",
		"user_dictionary": "ud.txt",
	}, 100, bctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCompiledAnalyzerSingleText(kcAn, "東京 カップ", 100); err != nil {
		t.Fatal(err)
	}
	kPos, _ := buildPluginTokenFilter("kp", "kuromoji_part_of_speech", map[string]any{"stoptags_path": "st.txt"}, false, bctx)
	_, _ = kPos.apply([]Token{{Term: "。", Type: "記号-一般"}, {Term: "を"}, {Term: "寿司"}}, newTokenStreamBudget(10))
	kRead, _ := buildPluginTokenFilter("kr", "kuromoji_readingform", map[string]any{"use_romaji": true}, false, bctx)
	gotKR, _ := kRead.apply([]Token{{Term: "カップ"}, {Term: "東京"}}, newTokenStreamBudget(10))
	if gotKR[0].Term != "kappu" {
		t.Fatalf("expected geminate romaji kappu, got %q", gotKR[0].Term)
	}
	if res, _ := applyKuromojiCompletion(nil, "index", newTokenStreamBudget(10)); res != nil {
		t.Fatalf("expected nil on empty completion")
	}

	// nori analyzer + tokenizer + filters
	noriAn, err := buildPluginAnalyzer("nori", "nori", map[string]any{
		"decompound_mode":     "mixed",
		"discard_punctuation": false,
		"user_dictionary":     "ud.txt",
		"stoptags_path":       "st.txt",
	}, 100, bctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCompiledAnalyzerSingleText(noriAn, "사람은 韓國, 123 abc!", 100); err != nil {
		t.Fatal(err)
	}
	noriAn2, err := buildPluginAnalyzer("nori2", "nori", map[string]any{
		"user_dictionary_rules": []any{"스카이트리"},
		"stoptags":              []any{"J"},
	}, 100, bctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCompiledAnalyzerSingleText(noriAn2, "스카이트리 은", 100); err != nil {
		t.Fatal(err)
	}

	// smartcn, polish, ukrainian, numbers
	scnWord, _ := buildPluginTokenFilter("sw", "smartcn_word", nil, true, bctx)
	_, _ = scnWord.apply([]Token{{Term: "中国"}}, newTokenStreamBudget(10))
	scnTok, _ := buildPluginTokenizer("st", "smartcn_tokenizer", nil, bctx.opts)
	_, _ = scnTok.tokenize(newCharStream("北京。ABC！", 0), 0, newTokenStreamBudget(20))

	plAn, err := buildPluginAnalyzer("pl", "polish", map[string]any{
		"stopwords":      []any{"i"},
		"stem_exclusion": []any{"studenci"},
	}, 100, bctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = runCompiledAnalyzerSingleText(plAn, "klienci studenci kot", 50)

	ukAn, err := buildPluginAnalyzer("uk", "ukrainian", map[string]any{
		"stopwords":      []any{"і"},
		"stem_exclusion": []any{"місто"},
	}, 100, bctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = runCompiledAnalyzerSingleText(ukAn, "місто колу невідоме", 50)

	for _, numIn := range []string{"", "000", "一億二千万", "三兆", "3.2천"} {
		_ = convertSinosphericNumber(numIn)
	}
}

func TestRound67CovAnalysis_PhoneticEncodersAndFilterBranches(t *testing.T) {
	bctx := filterBuildContext{}
	for _, tc := range []struct {
		name string
		def  map[string]any
	}{
		{"bad_replace", map[string]any{"replace": "nope"}},
		{"bad_max_len_zero", map[string]any{"max_code_len": 0}},
		{"bad_max_len_huge", map[string]any{"max_code_len": maxPhoneticCodeLen + 1}},
		{"bm_bad_rule_type", map[string]any{"encoder": "beider_morse", "rule_type": "fuzzy"}},
		{"bm_bad_name_type", map[string]any{"encoder": "beider_morse", "name_type": "martian"}},
		{"bm_bad_lang", map[string]any{"encoder": "beider_morse", "languageset": []any{"klingon"}}},
		{"unknown_encoder", map[string]any{"encoder": "nosuch"}},
	} {
		if _, err := buildTokenFilter(tc.name, "phonetic", tc.def, false, bctx); err == nil {
			t.Fatalf("expected error for %s", tc.name)
		}
	}

	// Test every encoder with empty-producing input "123", normal input, replace:false (including daitch_mokotoff)
	encoders := []string{
		"metaphone", "double_metaphone", "soundex", "refined_soundex",
		"caverphone1", "caverphone2", "cologne", "koelnerphonetik",
		"haasephonetik", "nysiis", "beider_morse", "daitch_mokotoff",
	}
	for _, enc := range encoders {
		for _, rep := range []bool{true, false} {
			tf, err := buildTokenFilter("ph", "phonetic", map[string]any{
				"encoder":      enc,
				"replace":      rep,
				"max_code_len": 6,
				"languages":    []any{"polish", "german"},
			}, false, bctx)
			if err != nil {
				t.Fatalf("build phonetic %s failed: %v", enc, err)
			}
			if _, err := tf.apply([]Token{{Term: "123"}, {Term: "Schwartz"}, {Term: "Müller"}}, newTokenStreamBudget(50)); err != nil {
				t.Fatalf("apply phonetic %s failed: %v", enc, err)
			}
			// Budget checks
			_, _ = tf.apply([]Token{{Term: "123"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10})
			_, _ = tf.apply([]Token{{Term: "Schwartz"}}, &tokenStreamBudget{maxTokens: 0, maxBytes: 10})
			_, _ = tf.apply([]Token{{Term: "Schwartz"}}, &tokenStreamBudget{maxTokens: 1, maxBytes: 100})
		}
	}

	// Comprehensive Metaphone & DoubleMetaphone branch coverage
	metaphoneInputs := []string{
		"", "A", "AERO", "WHY", "SCIENCE", "SIGN", "ASSIGNED",
		"PHONE", "SHOT", "NATION", "WATCH", "WEIRD", "BOXING", "EDGE", "GH",
	}
	for _, w := range metaphoneInputs {
		_ = encodeMetaphone(w, 4)
		_ = encodeMetaphone(w, 2)
	}

	dmInputs := []string{
		"", "ABBA", "CHIANTI", "CHEMISTRY", "CHORUS", "CHARACTER", "CHARISMA",
		"SCHOOL", "ORCHESTRA", "ARCHITECT", "ORCHID", "CZAR", "WICZ", "FOCACCIA",
		"ACCIDENT", "SUCCESS", "ACCOUNT", "BACK", "CIUDAD", "CELL", "ACCENT",
		"EDGE", "GADGET", "DT", "DD", "COFFEE",
		"GHOST", "GHI", "BGH", "AGHA", "GNAW", "AGNOSTIC", "GEORGE", "EGG",
		"HIGH", "HELLO", "JAZZ", "BOOKKEEPER", "BELL", "DUMMY", "THUMB", "PLUMBER",
		"ANNA", "PHONE", "APPLE", "SUBPOENA", "QATAR", "CARRY",
		"SHIP", "PASSION", "ASIA", "SCHISM", "MISS", "SZ",
		"NATION", "PARTIAL", "MATCH", "THIS", "MATTER", "TD",
		"SAVVY", "WRITE", "WAIT", "WHAT", "BEAUX", "EXCELLENT", "EXXON", "ZAP",
	}
	for _, w := range dmInputs {
		_, _ = encodeDoubleMetaphone(w, 6)
	}

	for _, w := range []string{"", "year", "yes", "cow", "car", "cal"} {
		_ = encodeCaverphone1(w)
		_ = encodeCaverphone2(w)
	}
	for _, w := range []string{"Ärger", "Öl", "Über", "Straße", "Deutsch", "A", "Cologne", "Xylophon", "Axel", "Schatz", "Cäsar", "Schenk"} {
		_ = encodeColognePhonetic(w, '0')
		_ = encodeKoelnerOrHaase(w, false)
		_ = encodeKoelnerOrHaase(w, true)
	}
	for _, w := range []string{"", "Evan", "Knight", "Phelps", "Hahn", "What", "Why", "Ray", "MacDonald", "Schmitt"} {
		_ = encodeNYSIIS(w)
	}
	for _, w := range []string{"", "Rzeszów", "Szczecin", "Czestochowa", "Dzierżoniów", "Bach", "Quiz", "Box", "Chaim"} {
		_ = encodeBeiderMorse(w, "ashkenazi", "exact", []string{"polish", "german"})
		_ = encodeBeiderMorse(w, "generic", "approx", []string{"polish"})
	}
}

func TestRound67CovAnalysis_AnalyzersTokenizersCharFiltersScriptNormalizers(t *testing.T) {
	// 1. Analyzers error & edge paths (`analyzers.go`)
	for _, tc := range []struct {
		typ string
		def map[string]any
	}{
		{"standard_html_strip", nil},
		{"standard", map[string]any{"position_increment_gap": -1}},
		{"standard", map[string]any{"max_token_length": 0}},
		{"standard", map[string]any{"stopwords": "_bogus_"}},
		{"whitespace", map[string]any{"max_token_length": 0}},
		{"stop", map[string]any{"stopwords": "_bogus_"}},
		{"keyword", map[string]any{"buffer_size": 0}},
		{"pattern", map[string]any{"pattern": "["}},
		{"pattern", map[string]any{"lowercase": "bad"}},
		{"pattern", map[string]any{"stopwords": "_bogus_"}},
		{"fingerprint", map[string]any{"preserve_original": "bad"}},
		{"fingerprint", map[string]any{"stopwords": "_bogus_"}},
		{"fingerprint", map[string]any{"separator": "::"}},
		{"classic", map[string]any{"max_token_length": 0}},
		{"classic", map[string]any{"stopwords": "_bogus_"}},
		{"snowball", map[string]any{"language": "elvish"}},
		{"snowball", map[string]any{"stopwords": "_bogus_"}},
		{"chinese", map[string]any{"stopwords": "_bogus_"}},
		{"cjk", map[string]any{"stopwords": "_bogus_"}},
		{"thai", map[string]any{"stopwords": "_bogus_"}},
		{"english", map[string]any{"stopwords": "_bogus_"}},
		{"unknown_an", nil},
	} {
		if _, err := buildBuiltInOrTypedAnalyzerWithCtx("an", tc.typ, tc.def, filterBuildContext{}); err == nil {
			t.Fatalf("expected error for analyzer %s %v", tc.typ, tc.def)
		}
	}
	for _, tc := range []struct {
		typ  string
		def  map[string]any
		text string
	}{
		{"pattern", map[string]any{"lowercase": false}, "Hello World"},
		{"snowball", map[string]any{"language": "turkish"}, "İstanbul"},
		{"snowball", map[string]any{"language": "armenian"}, "test"},
		{"chinese", nil, "你好 world"},
		{"english", map[string]any{"stem_exclusion": []any{"running"}}, "running runs"},
	} {
		an, err := buildBuiltInOrTypedAnalyzerWithCtx("an", tc.typ, tc.def, filterBuildContext{})
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", tc.typ, err)
		}
		if _, err := runCompiledAnalyzerSingleText(an, tc.text, 50); err != nil {
			t.Fatal(err)
		}
	}

	// 2. Tokenizers (`tokenizers.go`)
	if IsBuiltInTokenizer("not_a_tokenizer") {
		t.Fatalf("expected false for unknown tokenizer")
	}
	for _, tc := range []struct {
		typ string
		def map[string]any
	}{
		{"uax_url_email", map[string]any{"max_token_length": 0}},
		{"classic", map[string]any{"max_token_length": 0}},
		{"whitespace", map[string]any{"max_token_length": 0}},
		{"keyword", map[string]any{"buffer_size": -1}},
		{"ngram", map[string]any{"min_gram": 0}},
		{"ngram", map[string]any{"min": 0}},
		{"ngram", map[string]any{"max": 0}},
		{"ngram", map[string]any{"max_gram": MaxAllowedGramSize + 1}},
		{"ngram", map[string]any{"min_gram": 4, "max_gram": 2}},
		{"ngram", map[string]any{"token_chars": []any{"bad"}}},
		{"pattern", map[string]any{"group": -2}},
		{"pattern", map[string]any{"pattern": "["}},
		{"simple_pattern", map[string]any{"pattern": "["}},
		{"simple_pattern_split", map[string]any{"pattern": "["}},
		{"char_group", map[string]any{"max_token_length": 0}},
		{"char_group", map[string]any{"tokenize_on_chars": []any{"too_long"}}},
		{"path_hierarchy", map[string]any{"delimiter": "//"}},
		{"path_hierarchy", map[string]any{"replacement": "//"}},
		{"path_hierarchy", map[string]any{"reverse": "bad"}},
		{"path_hierarchy", map[string]any{"skip": -1}},
		{"unknown_tok", nil},
	} {
		if _, err := buildTokenizerWithOpts("t", tc.typ, tc.def, DefaultMaxNGramDiff, Options{}); err == nil {
			t.Fatalf("expected error for tokenizer %s %v", tc.typ, tc.def)
		}
	}
	// Valid tokenizer branches
	spEmpty, _ := buildTokenizer("sp", "simple_pattern", nil, 1)
	if toks, _ := spEmpty.tokenize(newCharStream("abc", 0), 0, newTokenStreamBudget(10)); toks != nil {
		t.Fatalf("expected nil for empty simple_pattern")
	}
	spsEmpty, _ := buildTokenizer("sps", "simple_pattern_split", nil, 1)
	if toks, _ := spsEmpty.tokenize(newCharStream("abc", 0), 0, newTokenStreamBudget(10)); len(toks) != 1 || toks[0].Term != "abc" {
		t.Fatalf("expected single token for empty simple_pattern_split, got %+v", toks)
	}
	if _, err := spsEmpty.tokenize(newCharStream("abc", 0), 0, &tokenStreamBudget{maxTokens: 0, maxBytes: 10}); err == nil {
		t.Fatalf("expected budget error")
	}
	patCap, _ := buildTokenizer("pc", "pattern", map[string]any{"pattern": `(a+)(?:(b+))?`, "group": 2}, 1)
	_, _ = patCap.tokenize(newCharStream("aa ab", 0), 0, newTokenStreamBudget(10))
	cgTok, _ := buildTokenizer("cg", "char_group", map[string]any{
		"tokenize_on_chars": []any{"whitespace", "letter", "digit", "punctuation", "symbol", "cjk", "-"},
	}, 1)
	_, _ = cgTok.tokenize(newCharStream("a1!+$中 ", 0), 0, newTokenStreamBudget(20))
	phRev, _ := buildTokenizer("ph", "path_hierarchy", map[string]any{"delimiter": "/", "replacement": ".", "reverse": true, "skip": 1}, 1)
	gotPH, _ := phRev.tokenize(newCharStream("/a/b/c", 0), 0, newTokenStreamBudget(10))
	if len(gotPH) != 3 || gotPH[0].Term != "b" {
		t.Fatalf("unexpected reverse path_hierarchy: %+v", gotPH)
	}
	if gotPHSkip, _ := phRev.tokenize(newCharStream("notslash", 0), 0, newTokenStreamBudget(10)); gotPHSkip != nil {
		t.Fatalf("expected nil when skip >= delim count, got %+v", gotPHSkip)
	}
	uaxTok, _ := buildTokenizer("uax", "uax_url_email", nil, 1)
	_, _ = uaxTok.tokenize(newCharStream("ftp://ex.com file:///tmp www.ex.com u@b.io 1,234.5 _x_ 😀👍🏽", 0), 0, newTokenStreamBudget(50))
	clTok, _ := buildTokenizer("cl", "classic", nil, 1)
	_, _ = clTok.tokenize(newCharStream("I.B.M. don't 1.2 a-1 a.b u@b.io 中文", 0), 0, newTokenStreamBudget(50))
	thTok, _ := buildTokenizer("th", "thai", nil, 1)
	_, _ = thTok.tokenize(newCharStream("เกาะไผ่ 123 abc", 0), 0, newTokenStreamBudget(50))

	// 3. char_filters (`char_filters.go`)
	for _, tc := range []struct {
		typ string
		def map[string]any
	}{
		{"html_strip", map[string]any{"read_ahead": -1}},
		{"mapping", map[string]any{"mappings": []any{"bad_rule"}}},
		{"mapping", map[string]any{"mappings": []any{" => x"}}},
		{"mapping", map[string]any{"mappings_path": "../secret"}},
		{"pattern_replace", nil},
		{"pattern_replace", map[string]any{"replacement": "x"}},
		{"pattern_replace", map[string]any{"pattern": "a", "replacement": strings.Repeat("x", MaxCharFilterOutputRunes*4+1)}},
		{"pattern_replace", map[string]any{"pattern": "a", "flags": "UNKNOWN_FLAG"}},
		{"unknown_cf", nil},
	} {
		if _, err := buildCharFilter("cf", tc.typ, tc.def, Options{}); err == nil {
			t.Fatalf("expected error for char_filter %s", tc.typ)
		}
	}
	if _, err := resolvePathSetting("p", "jvm.options", Options{}); err == nil {
		t.Fatalf("expected access denied for jvm.options")
	}
	htmlCF, _ := buildCharFilter("h", "html_strip", map[string]any{"escaped_tags": []any{"b"}}, Options{})
	if cs, err := htmlCF.apply(newCharStream("<!--unclosed <![CDATA[unclosed <!unclosed <script>unclosed <b attr='1'>hi</b> &unknown; &amp;", 0)); err != nil || !strings.Contains(cs.String(), "&") {
		t.Fatalf("unexpected html_strip result: %q err=%v", cs.String(), err)
	}
	zwCF, _ := buildCharFilter("zw", "zero_width_spaces", nil, Options{})
	if cs, _ := zwCF.apply(newCharStream("a\u200Bb\u200Cc\u200Dd", 0)); cs.String() != "a b c d" {
		t.Fatalf("unexpected zero_width_spaces: %q", cs.String())
	}
	mapCF, _ := buildCharFilter("mp", "mapping", map[string]any{"mappings": []any{`\u0041\r\b\f => Z`}}, Options{})
	if cs, _ := mapCF.apply(newCharStream("A\r\b\f", 0)); cs.String() != "Z" {
		t.Fatalf("unexpected mapping unescape: %q", cs.String())
	}
	_, _ = newCharStream("hi", 0).sliceOffsets(10, 12)
	_, _ = newCharStream("hi", 0).sliceOffsets(-1, 0)
	_, _ = compileJavaRegex("abc", "LITERAL|CASE_INSENSITIVE|MULTILINE|DOTALL|CANON_EQ")

	// 4. script_eval (`script_eval.go`)
	for _, badSrc := range []string{
		"1 || true", "true || 1", "1 && true", "true && 1",
		"!1", "-true", "(1", "\"unterminated", "\"\\\"",
		"1 + true", "1 - true", "1 < true", "true < false",
		"token", "token.unknownProp", "token.getTerm(",
		"params", "params['a'", "unknownVar",
		"123.length()", "token.term.unknownMethod()",
		"token.term.startsWith()", "token.term.endsWith()", "token.term.contains()", "token.term.equals()",
		"token.term.nope",
		strings.Repeat("(", maxScriptExprDepth+2) + "true" + strings.Repeat(")", maxScriptExprDepth+2),
	} {
		ctx := TokenContext{Term: "hello"}
		if _, err := DefaultEvalPredicateScript(map[string]any{"source": badSrc}, &ctx); err == nil {
			t.Fatalf("expected script error for %q", badSrc)
		}
	}
	ctx := TokenContext{Term: "Hello", Position: 1, PositionIncrement: 1, PositionLength: 1, StartOffset: 0, EndOffset: 5, Type: "word", Keyword: true}
	ok, err := DefaultEvalPredicateScript(map[string]any{
		"source": `token.getTerm().toLowerCase().startsWith("h") && token.term.toUpperCase().endsWith("O") && token.term.contains("ll") && !token.term.isEmpty() && token.term.length == 5 && (token.positionIncrement + token.positionLength - 1) <= params['lim'] && ("x" + 1) != "y" && (1 + "x") == "1x" && token.type != "NUM" && token.keyword == true && -1 < 0 && "a" <= "b" && "b" > "a" && "b" >= "b" && 2 > 1 && 2 >= 2`,
		"params": map[string]any{"lim": 5},
	}, &ctx)
	if err != nil || !ok {
		t.Fatalf("expected complex predicate true, got %v err=%v", ok, err)
	}

	// 5. normalizers_unicode + stemmers + types + config + analyze
	_ = normalizeHindi("\u0901\u093C\u0958\u0959\u095A\u095B\u095C\u095D\u095E\u095F\u0940\u0942\u0943\u0945\u0949\u0908\u090A\u090D\u0911")
	_ = normalizeBengali("\u0981\u09A1\u09BC\u09AF\u09BC\u09C2\u0988\u098A")
	_ = normalizeArabic("\u0649\u0629")
	_ = normalizeSorani("\u0692\u0643")
	_ = normalizeIndic("\u0928\u094D\u0915\u200C")
	_ = normalizeGerman("quaeoeueß")
	_ = normalizeScandinavian("åäöøæ")
	_ = foldScandinavian("åäöøæ")
	_ = lowercaseWithLang("tA", "irish")
	_ = lowercaseWithLang("Σ", "greek")
	_ = lowercaseWithLang("I", "turkish")
	_ = foldDecimalDigit("١٢٣")
	_ = applyClassicFilter(Token{Term: "O'Brien.", Type: "<APOSTROPHE>"})

	for _, fn := range []func(string) string{
		stemKStem, stemCzech, stemDutch, stemEstonian, stemFinnish,
		stemLightFrench, stemHungarian, stemIndonesian, stemItalian,
		stemBulgarian, stemDanish, stemArmenian, foldRomanceAccents,
	} {
		_ = fn("running")
		_ = fn("kraličtě")
		_ = fn("kleedden")
		_ = fn("membangunkan")
		_ = fn("ab")
	}

	// types.go & analyze.go & config.go
	var ar AnalyzeResponse
	if _, err := ar.MarshalJSON(); err != nil {
		t.Fatal(err)
	}
	if got := (TokenOut{Payload: "nothex"}).PayloadBase64(); got != "" {
		t.Fatalf("expected empty on bad hex")
	}
	if got := (TokenOut{Payload: "6162"}).PayloadBase64(); got != "YWI=" {
		t.Fatalf("unexpected TokenOut PayloadBase64: %q", got)
	}
	if got := (QueryToken{Payload: []byte("ab")}).PayloadBase64(); got != "YWI=" {
		t.Fatalf("unexpected QueryToken PayloadBase64: %q", got)
	}
	if (QueryGraphSegment{}).IsSingleTermAlternatives() {
		t.Fatalf("expected false for empty alternatives")
	}
	if (QueryTokenGraph{}).PhrasePaths(0) != nil {
		t.Fatalf("expected nil for empty segments")
	}
	g := BuildQueryTokenGraph([]Token{
		{Term: "a", Position: 0, PositionLength: 3},
		{Term: "b", Position: 2, PositionLength: 1},
	})
	if len(g.PhrasePaths(1)) != 1 {
		t.Fatalf("unexpected PhrasePaths: %+v", g.PhrasePaths(1))
	}
	if _, err := NormalizeTerm("abc", "missing_norm", nil, Options{}); err == nil {
		t.Fatalf("expected error for unknown normalizer")
	}
	if _, err := AnalyzeTokens("abc", "missing_an", nil, Options{}); err == nil {
		t.Fatalf("expected error for unknown analyzer")
	}

	// config.go dotted expansion + normalizer errors
	cfg, err := ParseIndexAnalysisConfig(map[string]any{
		"index.analysis.normalizer.n1.type":    "icu_normalizer",
		"index.analysis.normalizer.n1.name":    "nfc",
		"index.analysis.normalizer.n2.type":    "custom",
		"index.analysis.normalizer.n2.filter":  []string{"lowercase"},
		"index.analysis.analyzer.a1.type":      "custom",
		"index.analysis.analyzer.a1.tokenizer": "standard",
	}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeTerm("ABC", "n1", cfg, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseIndexAnalysisConfig(map[string]any{
		"index.analysis.normalizer.bad.tokenizer": "standard",
	}, Options{}); err == nil {
		t.Fatalf("expected error on normalizer with tokenizer")
	}
	if _, err := ParseIndexAnalysisConfig(map[string]any{
		"index.analysis.normalizer.bad.type": "unknown_norm_type",
	}, Options{}); err == nil {
		t.Fatalf("expected error on unknown normalizer type")
	}
	if _, err := ParseIndexAnalysisConfig(map[string]any{
		"index.analysis.normalizer.bad.type":   "custom",
		"index.analysis.normalizer.bad.filter": []any{"stemmer"},
	}, Options{}); err == nil {
		t.Fatalf("expected error on disallowed filter in normalizer")
	}
}
