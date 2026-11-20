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
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// F23 (C-01): Mutual-Recursion Cycle Detection & Nesting Depth Guards
// ============================================================================

func TestRound63_C01_CycleAndDepthGuards(t *testing.T) {
	// 1. condition filter cycle (c1 -> c2 -> c1)
	_, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"c1": map[string]any{
					"type":   "condition",
					"script": map[string]any{"source": "true"},
					"filter": []any{"c2"},
				},
				"c2": map[string]any{
					"type":   "condition",
					"script": map[string]any{"source": "true"},
					"filter": []any{"c1"},
				},
			},
		},
	}, Options{})
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(strings.ToLower(ae.Reason), "cycle") {
		t.Fatalf("expected 400 cycle error for condition c1<->c2, got: %v", err)
	}

	// 2. multiplexer cycle (m1 -> m2 -> m1)
	_, err = ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"m1": map[string]any{"type": "multiplexer", "filters": []any{"lowercase, m2"}},
				"m2": map[string]any{"type": "multiplexer", "filters": []any{"m1"}},
			},
		},
	}, Options{})
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(strings.ToLower(ae.Reason), "cycle") {
		t.Fatalf("expected 400 cycle error for multiplexer m1<->m2, got: %v", err)
	}

	// 3. Mutual analyzer <-> synonym cycle: analyzer a1 -> synonym s1 (analyzer: a1)
	_, err = ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"s1": map[string]any{
					"type":     "synonym",
					"analyzer": "a1",
					"synonyms": []any{"foo => bar"},
				},
			},
			"analyzer": map[string]any{
				"a1": map[string]any{
					"tokenizer": "whitespace",
					"filter":    []any{"s1"},
				},
			},
		},
	}, Options{})
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(strings.ToLower(ae.Reason), "cycle") {
		t.Fatalf("expected 400 cycle error for a1 -> s1 (analyzer: a1), got: %v", err)
	}

	// 4. 2-hop analyzer <-> synonym_graph with synonyms_set cycle: a1 -> s1(a2) -> s2(a1)
	_, err = ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"s1": map[string]any{"type": "synonym_graph", "analyzer": "a2", "synonyms_set": "set1"},
				"s2": map[string]any{"type": "synonym_graph", "analyzer": "a1", "synonyms_set": "set1"},
			},
			"analyzer": map[string]any{
				"a1": map[string]any{"tokenizer": "whitespace", "filter": []any{"s1"}},
				"a2": map[string]any{"tokenizer": "whitespace", "filter": []any{"s2"}},
			},
		},
	}, Options{})
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(strings.ToLower(ae.Reason), "cycle") {
		t.Fatalf("expected 400 cycle error for 2-hop synonym_set analyzer cycle, got: %v", err)
	}

	// 5. Inline condition nesting depth > 16
	var nested any = "lowercase"
	for i := 0; i < 20; i++ {
		nested = map[string]any{
			"type":   "condition",
			"script": map[string]any{"source": "true"},
			"filter": []any{nested},
		}
	}
	_, err = Analyze(AnalyzeRequest{
		Text:      []string{"hello"},
		Tokenizer: "whitespace",
		Filter:    []any{nested},
	})
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(ae.Reason, "exceeds maximum nesting depth") {
		t.Fatalf("expected 400 nesting depth error, got: %v", err)
	}

	// 6. predParser parenthesis & unary recursion depth > 64
	deepParens := strings.Repeat("(", 80) + "true" + strings.Repeat(")", 80)
	if _, err := DefaultEvalPredicateScript(map[string]any{"source": deepParens}, &TokenContext{Term: "a"}); err == nil || !strings.Contains(err.Error(), "exceeds maximum nesting depth") {
		t.Fatalf("expected script parenthesis depth error, got: %v", err)
	}
	deepBang := strings.Repeat("!", 80) + "true"
	if _, err := DefaultEvalPredicateScript(map[string]any{"source": deepBang}, &TokenContext{Term: "a"}); err == nil || !strings.Contains(err.Error(), "exceeds maximum nesting depth") {
		t.Fatalf("expected script unary ! depth error, got: %v", err)
	}
	deepMinus := strings.Repeat("-", 80) + "1 == -1"
	if _, err := DefaultEvalPredicateScript(map[string]any{"source": deepMinus}, &TokenContext{Term: "a"}); err == nil || !strings.Contains(err.Error(), "exceeds maximum nesting depth") {
		t.Fatalf("expected script unary - depth error, got: %v", err)
	}
}

// ============================================================================
// F24 (C-02 & C-09): Setting Caps, Term Byte Cap & In-Loop Stream Budgets
// ============================================================================

func TestRound63_C02_C09_SettingCapsAndInLoopStreamBudgets(t *testing.T) {
	// 1. Index & filter parameter caps
	badConfigs := []map[string]any{
		{"index.analyze.max_token_count": 100001},
		{"index.analyze.max_token_count": 0},
		{"index.max_ngram_diff": 101},
		{"index.max_shingle_diff": 101},
		{"analysis": map[string]any{"tokenizer": map[string]any{"ng": map[string]any{"type": "edge_ngram", "min_gram": 1, "max_gram": 1025}}}},
		{"analysis": map[string]any{"filter": map[string]any{"ng": map[string]any{"type": "edge_ngram", "min": 1, "max": 1025}}}},
		{"analysis": map[string]any{"filter": map[string]any{"mh": map[string]any{"type": "min_hash", "hash_count": 65}}}},
		{"analysis": map[string]any{"filter": map[string]any{"mh": map[string]any{"type": "min_hash", "bucket_count": 16385}}}},
		{"analysis": map[string]any{"filter": map[string]any{"mh": map[string]any{"type": "min_hash", "hash_set_size": 65}}}},
		{"analysis": map[string]any{"analyzer": map[string]any{"gap": map[string]any{"type": "standard", "position_increment_gap": 1000001}}}},
		{"analysis": map[string]any{"char_filter": map[string]any{"pr": map[string]any{"type": "pattern_replace", "pattern": strings.Repeat("a", 4097)}}}},
	}
	for idx, bc := range badConfigs {
		_, err := ParseIndexAnalysisConfig(bc, Options{})
		if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 {
			t.Fatalf("badConfigs[%d] expected 400 illegal_argument_exception, got: %v", idx, err)
		}
	}

	// Legacy ES 7 min / max aliases on ngram & edge_ngram (V7-6)
	rLegacyNG, err := Analyze(AnalyzeRequest{
		Text:      []string{"abcd"},
		Tokenizer: map[string]any{"type": "ngram", "min": 2, "max": 3},
		Filter:    []any{map[string]any{"type": "edge_ngram", "min": 1, "max": 2}},
	})
	if err != nil || len(rLegacyNG.Tokens) == 0 {
		t.Fatalf("legacy min/max aliases failed: %v (err=%v)", rLegacyNG, err)
	}

	// 2. Request char_filter / filter chain length cap (<= 64)
	manyFilters := make([]any, 65)
	for i := range manyFilters {
		manyFilters[i] = "lowercase"
	}
	if _, err := Analyze(AnalyzeRequest{Text: []string{"hi"}, Tokenizer: "whitespace", Filter: manyFilters}); err == nil {
		t.Fatalf("expected >64 filters to be rejected")
	}
	if _, err := Analyze(AnalyzeRequest{Text: []string{"hi"}, Tokenizer: "whitespace", CharFilter: manyFilters}); err == nil {
		t.Fatalf("expected >64 char_filters to be rejected")
	}

	// 3. charStreamBuilder MaxCharFilterOutputRunes = 1_048_576 amplification abort
	ampCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"char_filter": map[string]any{
				"amp": map[string]any{"type": "mapping", "mappings": []any{"a => aaaaaaaaaaaaaaaa"}}, // 16x per stage
			},
			"analyzer": map[string]any{
				"amp_an": map[string]any{
					"char_filter": []any{"amp", "amp", "amp", "amp"}, // 16^4 = 65536x!
					"tokenizer":   "keyword",
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("ampCfg failed: %v", err)
	}
	seed32 := strings.Repeat("a", 32) // 32 * 65536 = 2,097,152 > 1,048,576!
	if _, err := Analyze(AnalyzeRequest{Text: []string{seed32}, Analyzer: "amp_an", Config: ampCfg}); err == nil || !strings.Contains(err.Error(), "char_filter output exceeds maximum") {
		t.Fatalf("expected char_filter MaxCharFilterOutputRunes error in Analyze, got: %v", err)
	}
	if _, err := AnalyzeForQuery(seed32, "amp_an", ampCfg, Options{}); err == nil || !strings.Contains(err.Error(), "char_filter output exceeds maximum") {
		t.Fatalf("expected char_filter MaxCharFilterOutputRunes error in AnalyzeForQuery, got: %v", err)
	}

	// 4. MaxTokenTermBytes = 32,766 enforcement across shingle, script_eval, pattern_replace, keyword
	bigChunk := strings.Repeat("x", 20000)
	if _, err := Analyze(AnalyzeRequest{
		Text:      []string{bigChunk + " " + bigChunk},
		Tokenizer: "letter",
		Filter:    []any{"shingle"},
	}); err == nil || !strings.Contains(err.Error(), "32766") {
		t.Fatalf("expected shingle MaxTokenTermBytes error, got: %v", err)
	}
	if _, err := DefaultEvalPredicateScript(map[string]any{
		"source": `token.term = params.big + params.big; return true;`,
		"params": map[string]any{"big": bigChunk},
	}, &TokenContext{Term: "a"}); err == nil || !strings.Contains(err.Error(), "32766") {
		t.Fatalf("expected script_eval MaxTokenTermBytes error, got: %v", err)
	}
	if _, err := Analyze(AnalyzeRequest{
		Text:      []string{strings.Repeat("z", 33000)},
		Tokenizer: "keyword",
	}); err == nil || !strings.Contains(err.Error(), "32766") {
		t.Fatalf("expected keyword MaxTokenTermBytes error, got: %v", err)
	}

	// 5. 1 MB input in-loop budget abort across ALL exploding tokenizers & filters in BOTH Analyze & AnalyzeForQuery!
	oneMBAlpha := strings.Repeat("a", 1<<20)
	oneMBPath := strings.Repeat("/a", 1<<19)
	oneMBWords := strings.Repeat("a1B2 ", 200000)

	budgetCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"index.analyze.max_token_count": 50,
		"index.max_ngram_diff":          50,
		"index.max_shingle_diff":        10,
		"analysis": map[string]any{
			"tokenizer": map[string]any{
				"t_ng":   map[string]any{"type": "ngram", "min_gram": 1, "max_gram": 20},
				"t_eng":  map[string]any{"type": "edge_ngram", "min_gram": 1, "max_gram": 200},
				"t_path": map[string]any{"type": "path_hierarchy"},
			},
			"filter": map[string]any{
				"f_ng":  map[string]any{"type": "ngram", "min_gram": 1, "max_gram": 10},
				"f_sh":  map[string]any{"type": "shingle", "min_shingle_size": 2, "max_shingle_size": 6},
				"f_mh":  map[string]any{"type": "min_hash", "bucket_count": 512, "hash_count": 4},
				"f_syn": map[string]any{"type": "synonym_graph", "synonyms": []any{"a1B2, v1, v2, v3, v4"}},
				"f_pc":  map[string]any{"type": "pattern_capture", "patterns": []any{"(a)(1)(B)(2)"}},
				"f_wdg": map[string]any{"type": "word_delimiter_graph", "catenate_all": true, "preserve_original": true},
			},
			"analyzer": map[string]any{
				"an_tok_ng":   map[string]any{"tokenizer": "t_ng"},
				"an_tok_eng":  map[string]any{"tokenizer": "t_eng"},
				"an_tok_path": map[string]any{"tokenizer": "t_path"},
				"an_flt_ng":   map[string]any{"tokenizer": "whitespace", "filter": []any{"f_ng"}},
				"an_flt_sh":   map[string]any{"tokenizer": "whitespace", "filter": []any{"f_sh"}},
				"an_flt_mh":   map[string]any{"tokenizer": "whitespace", "filter": []any{"f_mh"}},
				"an_flt_syn":  map[string]any{"tokenizer": "whitespace", "filter": []any{"f_syn"}},
				"an_flt_pc":   map[string]any{"tokenizer": "whitespace", "filter": []any{"f_pc"}},
				"an_flt_wdg":  map[string]any{"tokenizer": "whitespace", "filter": []any{"f_wdg"}},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("budgetCfg failed: %v", err)
	}

	abortCases := []struct {
		analyzer string
		input    string
	}{
		{"an_tok_ng", oneMBAlpha},
		{"an_tok_eng", oneMBAlpha},
		{"an_tok_path", oneMBPath},
		{"an_flt_ng", strings.Repeat("abcdefghij ", 20)},
		{"an_flt_sh", strings.Repeat("w ", 30)},
		{"an_flt_mh", "hello world"},
		{"an_flt_syn", strings.Repeat("a1B2 ", 20)},
		{"an_flt_pc", strings.Repeat("a1B2 ", 20)},
		{"an_flt_wdg", oneMBWords},
	}
	for _, tc := range abortCases {
		start := time.Now()
		_, err1 := Analyze(AnalyzeRequest{Text: []string{tc.input}, Analyzer: tc.analyzer, Config: budgetCfg})
		_, err2 := AnalyzeForQuery(tc.input, tc.analyzer, budgetCfg, Options{})
		elapsed := time.Since(start)
		if err1 == nil || !strings.Contains(err1.Error(), "exceeded the allowed maximum of [50]") {
			t.Fatalf("Analyze(%s) expected max_token_count [50] error, got: %v", tc.analyzer, err1)
		}
		if err2 == nil || !strings.Contains(err2.Error(), "exceeded the allowed maximum of [50]") {
			t.Fatalf("AnalyzeForQuery(%s) expected max_token_count [50] error, got: %v", tc.analyzer, err2)
		}
		if elapsed > 3*time.Second {
			t.Fatalf("in-loop budget abort for %s took too long: %v", tc.analyzer, elapsed)
		}
	}
}

// ============================================================================
// F25 (C-03, C-04, C-10): Sparse FlattenGraph, Bounded DFS & Linear Lookahead
// ============================================================================

func TestRound63_C03_C04_C10_SparseGraphBoundedDFSAndLinearScans(t *testing.T) {
	// 1. C-03: Multi-valued text with position_increment_gap = 1,000,000 through flatten_graph & shingle
	sparseCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"analyzer": map[string]any{
				"sparse_an": map[string]any{
					"tokenizer":              "whitespace",
					"position_increment_gap": 1000000,
					"filter":                 []any{"flatten_graph", "shingle"},
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("sparseCfg failed: %v", err)
	}
	elems := make([]string, 50)
	for i := range elems {
		elems[i] = "alpha beta"
	}
	t0 := time.Now()
	respSparse, err := Analyze(AnalyzeRequest{Text: elems, Analyzer: "sparse_an", Config: sparseCfg})
	if err != nil || len(respSparse.Tokens) == 0 {
		t.Fatalf("sparse flatten_graph + shingle failed: %v", err)
	}
	if time.Since(t0) > 200*time.Millisecond {
		t.Fatalf("sparse flatten_graph + shingle took too long: %v", time.Since(t0))
	}

	// 2. C-04: Exponential diamond DAG in AnalyzeForQuery (10x keyword_repeat + 8-way synonyms x 20 words)
	var synTerms []string
	for i := 0; i < 8; i++ {
		synTerms = append(synTerms, fmt.Sprintf("v%d", i))
	}
	dagCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"index.analyze.max_token_count": 50000,
		"analysis": map[string]any{
			"filter": map[string]any{
				"syn8": map[string]any{
					"type":     "synonym_graph",
					"synonyms": []any{"w," + strings.Join(synTerms, ",")},
				},
			},
			"analyzer": map[string]any{
				"dup_dag": map[string]any{
					"tokenizer": "whitespace",
					"filter": []any{
						"keyword_repeat", "keyword_repeat", "keyword_repeat",
						"keyword_repeat", "keyword_repeat", "keyword_repeat",
					},
				},
				"branch_dag": map[string]any{
					"tokenizer": "whitespace",
					"filter":    []any{"syn8"},
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("dagCfg failed: %v", err)
	}
	t1 := time.Now()
	g1, err := AnalyzeForQuery(strings.Repeat("fox ", 25), "dup_dag", dagCfg, Options{})
	if err != nil || len(g1.Positions) != 25 || len(g1.Positions[0].Tokens) != 1 {
		t.Fatalf("expected deduplicated single edge per position on dup_dag, got err=%v pos0=%d", err, len(g1.Positions[0].Tokens))
	}
	// Construct single spanned segment over branching positions by testing enumerateSegmentPaths directly too
	byPosAdv := make(map[int][]QueryToken)
	for p := 0; p < 25; p++ {
		for b := 0; b < 8; b++ {
			pl := 1
			if p == 0 && b == 0 {
				pl = 25 // forces single [0, 25) segment across 8^24 branches!
			}
			byPosAdv[p] = append(byPosAdv[p], QueryToken{
				Term:           fmt.Sprintf("n%d_%d", p, b),
				Position:       p,
				PositionLength: pl,
			})
		}
	}
	alts := enumerateSegmentPaths(0, 25, byPosAdv, 64)
	_, err = AnalyzeForQuery(strings.Repeat("w ", 20), "branch_dag", dagCfg, Options{})
	if err != nil || len(alts) == 0 || time.Since(t1) > 2*time.Second {
		t.Fatalf("adversarial DAG DFS took too long (%v) or failed: err=%v alts=%d", time.Since(t1), err, len(alts))
	}

	// 3. C-10: Linear-time uax_url_email, classic, html_strip, and synonym rule caps
	highTokCfg := &IndexAnalysisConfig{MaxTokenCount: MaxAllowedTokenCount, MaxNGramDiff: 2, MaxShingleDiff: 2}
	t2 := time.Now()
	if _, err := Analyze(AnalyzeRequest{
		Text:      []string{strings.Repeat("word ", 20000)},
		Tokenizer: "uax_url_email",
		Config:    highTokCfg,
	}); err != nil {
		t.Fatalf("uax_url_email 20k words failed: %v", err)
	}
	if _, err := Analyze(AnalyzeRequest{
		Text:      []string{strings.Repeat("word ", 20000)},
		Tokenizer: "classic",
		Config:    highTokCfg,
	}); err != nil {
		t.Fatalf("classic 20k words failed: %v", err)
	}
	if _, err := Analyze(AnalyzeRequest{
		Text:      []string{strings.Repeat("_", 30000)},
		Tokenizer: "standard",
		Config:    highTokCfg,
	}); err != nil {
		t.Fatalf("standard 30k underscores failed: %v", err)
	}
	for _, advHTML := range []string{
		strings.Repeat("<!--", 25000),
		strings.Repeat("<![CDATA[", 15000),
		strings.Repeat("<!\"", 25000),
		strings.Repeat("<a title=\"", 20000),
		strings.Repeat("<script>", 15000),
	} {
		if _, err := Analyze(AnalyzeRequest{
			Text:       []string{advHTML},
			CharFilter: []any{"html_strip"},
			Tokenizer:  "keyword",
		}); err != nil && !strings.Contains(err.Error(), "32766") {
			t.Fatalf("adversarial html_strip failed unexpectedly: %v", err)
		}
	}
	if time.Since(t2) > 15*time.Second {
		t.Fatalf("C-10 linear scan checks took too long: %v", time.Since(t2))
	}

	// Synonym > 1024 terms per rule rejected
	hugeRule := make([]string, 1030)
	for i := range hugeRule {
		hugeRule[i] = fmt.Sprintf("t%d", i)
	}
	if _, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"big_syn": map[string]any{
					"type":     "synonym",
					"synonyms": []any{strings.Join(hugeRule, ", ")},
				},
			},
		},
	}, Options{}); err == nil {
		t.Fatalf("expected synonym rule with >1024 terms to be rejected")
	}
}

// ============================================================================
// F20 & F1: UAX #29 Underscore, Payloads, Default Helpers & All 7 Plugins
// ============================================================================

func TestRound63_F20_StandardUnderscorePayloadsAndDefaultHelpers(t *testing.T) {
	// 1. V7-5: UAX #29 word-internal underscore stays a single <ALPHANUM> token
	rStd, err := Analyze(AnalyzeRequest{
		Text:      []string{"value1_foo foo_bar __init ___"},
		Tokenizer: "standard",
	})
	if err != nil {
		t.Fatalf("standard underscore failed: %v", err)
	}
	if want := []string{"value1_foo", "foo_bar", "__init"}; !reflect.DeepEqual(extractTerms(rStd), want) {
		t.Fatalf("standard underscore = %v, want %v", extractTerms(rStd), want)
	}
	for _, tk := range rStd.Tokens {
		if tk.Type != "<ALPHANUM>" {
			t.Fatalf("expected <ALPHANUM> for %q, got %q", tk.Token, tk.Type)
		}
	}

	// 2. V7-5 / V8-8: type_as_payload in Analyze & AnalyzeForQuery (termvectors/10_payloads.yml)
	payCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"analyzer": map[string]any{
				"has_payloads": map[string]any{
					"tokenizer": "standard",
					"filter":    []any{"type_as_payload"},
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("payCfg failed: %v", err)
	}
	rPay, err := Analyze(AnalyzeRequest{
		Text:       []string{"The quick brown fox is brown."},
		Analyzer:   "has_payloads",
		Config:     payCfg,
		Attributes: []string{"payload"},
	})
	if err != nil {
		t.Fatalf("Analyze(has_payloads) failed: %v", err)
	}
	if rPay.Tokens[2].Token != "brown" || rPay.Tokens[2].PayloadBase64() != "PEFMUEhBTlVNPg==" {
		t.Fatalf("expected brown payload PEFMUEhBTlVNPg==, got %q (hex=%q)", rPay.Tokens[2].PayloadBase64(), rPay.Tokens[2].Payload)
	}
	qPay, err := AnalyzeForQuery("brown", "has_payloads", payCfg, Options{})
	if err != nil || len(qPay.Tokens) != 1 || qPay.Tokens[0].PayloadBase64() != "PEFMUEhBTlVNPg==" {
		t.Fatalf("expected QueryToken PayloadBase64 PEFMUEhBTlVNPg==, got %+v (err=%v)", qPay, err)
	}

	// 3. V7-6: ResolveIndexAnalyzer & ResolveSearchAnalyzer precedence matrix
	var nilCfg *IndexAnalysisConfig
	if nilCfg.ResolveIndexAnalyzer("") != "standard" || nilCfg.ResolveSearchAnalyzer("", "") != "standard" {
		t.Fatalf("expected standard fallback on nil config")
	}
	defOnlyCfg, _ := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"analyzer": map[string]any{
				"default": map[string]any{"type": "whitespace"},
			},
		},
	}, Options{})
	if defOnlyCfg.ResolveIndexAnalyzer("") != "default" || defOnlyCfg.ResolveIndexAnalyzer("english") != "english" {
		t.Fatalf("unexpected ResolveIndexAnalyzer with default")
	}
	if defOnlyCfg.ResolveSearchAnalyzer("", "") != "default" || defOnlyCfg.ResolveSearchAnalyzer("english", "") != "english" || defOnlyCfg.ResolveSearchAnalyzer("english", "simple") != "simple" {
		t.Fatalf("unexpected ResolveSearchAnalyzer with default")
	}
}

func TestRound63_F1_PhoneticPluginSuite(t *testing.T) {
	// Exact upstream YAML tests: 10_metaphone, 20_double_metaphone, 30_beider_morse, 40_search, 50_daitch_mokotoff
	cfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"f_meta": map[string]any{"type": "phonetic", "encoder": "metaphone", "replace": false},
				"f_dm":   map[string]any{"type": "phonetic", "encoder": "double_metaphone", "max_code_len": 6},
				"f_bm": map[string]any{
					"type":        "phonetic",
					"encoder":     "beider_morse",
					"rule_type":   "exact",
					"name_type":   "ashkenazi",
					"languageset": "polish",
				},
				"f_daitch": map[string]any{"type": "phonetic", "encoder": "daitch_mokotoff"},
			},
			"analyzer": map[string]any{
				"an_meta":   map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "f_meta"}},
				"an_dm":     map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "f_dm"}},
				"an_bm":     map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "f_bm"}},
				"an_daitch": map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "f_daitch"}},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("phonetic config failed: %v", err)
	}

	rMeta, err := Analyze(AnalyzeRequest{Text: []string{"Joe Bloggs"}, Analyzer: "an_meta", Config: cfg})
	if err != nil || !reflect.DeepEqual(extractTerms(rMeta), []string{"J", "joe", "BLKS", "bloggs"}) {
		t.Fatalf("10_metaphone = %v (err=%v)", extractTerms(rMeta), err)
	}

	rHello1, _ := Analyze(AnalyzeRequest{Text: []string{"hello"}, Analyzer: "an_meta", Config: cfg})
	rHello2, _ := Analyze(AnalyzeRequest{Text: []string{"helllo"}, Analyzer: "an_meta", Config: cfg})
	if rHello1.Tokens[0].Token != "HL" || rHello2.Tokens[0].Token != "HL" {
		t.Fatalf("40_search metaphone mismatch: %v vs %v", extractTerms(rHello1), extractTerms(rHello2))
	}

	rDM, err := Analyze(AnalyzeRequest{Text: []string{"supercalifragilisticexpialidocious"}, Analyzer: "an_dm", Config: cfg})
	if err != nil || !reflect.DeepEqual(extractTerms(rDM), []string{"SPRKLF"}) {
		t.Fatalf("20_double_metaphone = %v (err=%v)", extractTerms(rDM), err)
	}

	rBM, err := Analyze(AnalyzeRequest{Text: []string{"Szwarc"}, Analyzer: "an_bm", Config: cfg})
	if err != nil || !reflect.DeepEqual(extractTerms(rBM), []string{"Svarts"}) {
		t.Fatalf("30_beider_morse = %v (err=%v)", extractTerms(rBM), err)
	}

	rDaitch, err := Analyze(AnalyzeRequest{Text: []string{"Moskowitz"}, Analyzer: "an_daitch", Config: cfg})
	if err != nil || !reflect.DeepEqual(extractTerms(rDaitch), []string{"645740"}) {
		t.Fatalf("50_daitch_mokotoff = %v (err=%v)", extractTerms(rDaitch), err)
	}

	// Remaining phonetic encoders: soundex, refined_soundex, caverphone1, caverphone2, cologne, nysiis, koelnerphonetik, haasephonetik, bm approx
	encoders := []map[string]any{
		{"type": "phonetic", "encoder": "soundex"},
		{"type": "phonetic", "encoder": "refined_soundex"},
		{"type": "phonetic", "encoder": "caverphone1"},
		{"type": "phonetic", "encoder": "caverphone2"},
		{"type": "phonetic", "encoder": "cologne"},
		{"type": "phonetic", "encoder": "nysiis"},
		{"type": "phonetic", "encoder": "koelnerphonetik"},
		{"type": "phonetic", "encoder": "haasephonetik"},
		{"type": "phonetic", "encoder": "beider_morse", "rule_type": "approx", "name_type": "sephardic", "languages": []any{"german", "polish"}, "replace": false},
		{"type": "phonetic", "encoder": "daitch_mokotoff", "replace": false},
	}
	for _, enc := range encoders {
		r, err := Analyze(AnalyzeRequest{
			Text:      []string{"Müller-Lüdenscheidt Schmidt Thompson Macintosh Wright"},
			Tokenizer: "standard",
			Filter:    []any{"lowercase", enc},
		})
		if err != nil || len(r.Tokens) == 0 {
			t.Fatalf("phonetic %v failed: %v", enc, err)
		}
	}

	// Invalid phonetic settings
	for _, bad := range []map[string]any{
		{"type": "phonetic", "encoder": "no_such_encoder"},
		{"type": "phonetic", "encoder": "beider_morse", "rule_type": "bogus"},
		{"type": "phonetic", "encoder": "beider_morse", "name_type": "bogus"},
		{"type": "phonetic", "encoder": "beider_morse", "languages": []any{"klingon"}},
		{"type": "phonetic", "max_code_len": 0},
	} {
		if _, err := Analyze(AnalyzeRequest{Text: []string{"x"}, Tokenizer: "standard", Filter: []any{bad}}); err == nil {
			t.Fatalf("expected error on bad phonetic config %v", bad)
		}
	}
}

func TestRound63_F1_ICU_Kuromoji_Nori_SmartCN_Stempel_UkrainianSuites(t *testing.T) {
	// 1. analysis-icu (10_basic.yml & 20_search.yml, including ES 7 unicodeSetFilter alias)
	rICUTok, err := Analyze(AnalyzeRequest{Text: []string{"Foo Bar ภาษาไทย"}, Tokenizer: "icu_tokenizer"})
	if err != nil || !reflect.DeepEqual(extractTerms(rICUTok), []string{"Foo", "Bar", "ภาษา", "ไทย"}) {
		t.Fatalf("icu_tokenizer = %v (err=%v)", extractTerms(rICUTok), err)
	}
	rICUNormF, err := Analyze(AnalyzeRequest{Text: []string{"Foo Bar Ruß"}, Tokenizer: "standard", Filter: []any{"icu_normalizer"}})
	if err != nil || !reflect.DeepEqual(extractTerms(rICUNormF), []string{"foo", "bar", "russ"}) {
		t.Fatalf("icu_normalizer filter = %v (err=%v)", extractTerms(rICUNormF), err)
	}
	rICUNormCF, err := Analyze(AnalyzeRequest{Text: []string{"Foo Bar Ruß"}, CharFilter: []any{"icu_normalizer"}, Tokenizer: "standard"})
	if err != nil || !reflect.DeepEqual(extractTerms(rICUNormCF), []string{"foo", "bar", "russ"}) {
		t.Fatalf("icu_normalizer char_filter = %v (err=%v)", extractTerms(rICUNormCF), err)
	}
	rICUFold, err := Analyze(AnalyzeRequest{Text: []string{"Foo Bar résumé"}, Tokenizer: "standard", Filter: []any{"icu_folding"}})
	if err != nil || !reflect.DeepEqual(extractTerms(rICUFold), []string{"foo", "bar", "resume"}) {
		t.Fatalf("icu_folding = %v (err=%v)", extractTerms(rICUFold), err)
	}
	if normVal, err := NormalizeTerm("Ruß", "icu_normalizer", nil, Options{}); err != nil || normVal != "russ" {
		t.Fatalf("NormalizeTerm(icu_normalizer) = %q (err=%v)", normVal, err)
	}

	icuCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"char_filter": map[string]any{
				"cf_icu": map[string]any{"type": "icu_normalizer", "unicodeSetFilter": "[^ß]"},
			},
			"filter": map[string]any{
				"tf_icu":  map[string]any{"type": "icu_normalizer", "unicode_set_filter": "[^ßB]"},
				"tf_fold": map[string]any{"type": "icu_folding", "unicode_set_filter": "[^â]"},
				"tf_col":  map[string]any{"type": "icu_collation", "language": "en", "strength": "primary"},
				"tf_tr":   map[string]any{"type": "icu_transform", "id": "Any-Latin; Latin-ASCII; Lower"},
			},
			"analyzer": map[string]any{
				"col_an": map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "tf_col"}},
				"icu_an": map[string]any{"type": "icu_analyzer", "method": "nfkc_cf", "mode": "compose"},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("icuCfg failed: %v", err)
	}

	rCFSet, _ := Analyze(AnalyzeRequest{Text: []string{"charfilter Föo Bâr Ruß"}, CharFilter: []any{"cf_icu"}, Tokenizer: "standard", Config: icuCfg})
	if !reflect.DeepEqual(extractTerms(rCFSet), []string{"charfilter", "föo", "bâr", "ruß"}) {
		t.Fatalf("cf_icu = %v", extractTerms(rCFSet))
	}
	rTFSet, _ := Analyze(AnalyzeRequest{Text: []string{"tokenfilter Föo Bâr Ruß"}, Tokenizer: "standard", Filter: []any{"tf_icu"}, Config: icuCfg})
	if !reflect.DeepEqual(extractTerms(rTFSet), []string{"tokenfilter", "föo", "Bâr", "ruß"}) {
		t.Fatalf("tf_icu = %v", extractTerms(rTFSet))
	}
	rFoldSet, _ := Analyze(AnalyzeRequest{Text: []string{"icufolding Föo Bâr Ruß"}, Tokenizer: "standard", Filter: []any{"tf_fold"}, Config: icuCfg})
	if !reflect.DeepEqual(extractTerms(rFoldSet), []string{"icufolding", "foo", "bâr", "russ"}) {
		t.Fatalf("tf_fold = %v", extractTerms(rFoldSet))
	}
	c1, _ := Analyze(AnalyzeRequest{Text: []string{"Bâton enflammé"}, Analyzer: "col_an", Config: icuCfg})
	c2, _ := Analyze(AnalyzeRequest{Text: []string{"baton enflamme"}, Analyzer: "col_an", Config: icuCfg})
	if !reflect.DeepEqual(extractTerms(c1), extractTerms(c2)) {
		t.Fatalf("icu_collation primary mismatch: %v vs %v", extractTerms(c1), extractTerms(c2))
	}
	rTr, _ := Analyze(AnalyzeRequest{Text: []string{"Москва カタカナ"}, Tokenizer: "whitespace", Filter: []any{"tf_tr"}, Config: icuCfg})
	if !reflect.DeepEqual(extractTerms(rTr), []string{"moskva", "katakana"}) {
		t.Fatalf("icu_transform = %v", extractTerms(rTr))
	}
	rICUAn, err := Analyze(AnalyzeRequest{Text: []string{"Foo Bar résumé Ruß"}, Analyzer: "icu_an", Config: icuCfg})
	if err != nil || !reflect.DeepEqual(extractTerms(rICUAn), []string{"foo", "bar", "resume", "russ"}) {
		t.Fatalf("icu_analyzer = %v (err=%v)", extractTerms(rICUAn), err)
	}

	// 2. analysis-kuromoji (10_basic.yml & 20_search.yml)
	rKuroAn, err := Analyze(AnalyzeRequest{Text: []string{"JR新宿駅の近くにビールを飲みに行こうか"}, Analyzer: "kuromoji"})
	if err != nil || !reflect.DeepEqual(extractTerms(rKuroAn), []string{"jr", "新宿", "駅", "近く", "ビール", "飲む", "行く"}) {
		t.Fatalf("kuromoji analyzer = %v (err=%v)", extractTerms(rKuroAn), err)
	}
	rKuroTok, err := Analyze(AnalyzeRequest{Text: []string{"関西国際空港"}, Tokenizer: "kuromoji_tokenizer"})
	if err != nil || !reflect.DeepEqual(extractTerms(rKuroTok), []string{"関西", "関西国際空港", "国際", "空港"}) {
		t.Fatalf("kuromoji_tokenizer = %v (err=%v)", extractTerms(rKuroTok), err)
	}
	rKuroBF, _ := Analyze(AnalyzeRequest{Text: []string{"飲み"}, Tokenizer: "kuromoji_tokenizer", Filter: []any{"kuromoji_baseform"}})
	if !reflect.DeepEqual(extractTerms(rKuroBF), []string{"飲む"}) {
		t.Fatalf("kuromoji_baseform = %v", extractTerms(rKuroBF))
	}
	rKuroRead, _ := Analyze(AnalyzeRequest{Text: []string{"寿司"}, Tokenizer: "kuromoji_tokenizer", Filter: []any{"kuromoji_readingform"}})
	if !reflect.DeepEqual(extractTerms(rKuroRead), []string{"スシ"}) {
		t.Fatalf("kuromoji_readingform = %v", extractTerms(rKuroRead))
	}
	rKuroStem, _ := Analyze(AnalyzeRequest{Text: []string{"サーバー"}, Tokenizer: "kuromoji_tokenizer", Filter: []any{"kuromoji_stemmer"}})
	if !reflect.DeepEqual(extractTerms(rKuroStem), []string{"サーバ"}) {
		t.Fatalf("kuromoji_stemmer = %v", extractTerms(rKuroStem))
	}
	kuroCompCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"analyzer": map[string]any{
				"comp_idx": map[string]any{"type": "kuromoji_completion", "mode": "index"},
				"comp_qry": map[string]any{"type": "kuromoji_completion", "mode": "query"},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("kuroCompCfg failed: %v", err)
	}
	rCompIdx, _ := Analyze(AnalyzeRequest{Text: []string{"ｿｰｽｺｰﾄﾞ"}, Analyzer: "comp_idx", Config: kuroCompCfg})
	if !reflect.DeepEqual(extractTerms(rCompIdx), []string{"ソース", "soーsu", "コード", "koーdo"}) {
		t.Fatalf("kuromoji_completion index = %v", extractTerms(rCompIdx))
	}
	rCompQry, _ := Analyze(AnalyzeRequest{Text: []string{"ｿｰｽｺｰﾄﾞ"}, Analyzer: "comp_qry", Config: kuroCompCfg})
	if !reflect.DeepEqual(extractTerms(rCompQry), []string{"ソースコード", "soーsukoーdo"}) {
		t.Fatalf("kuromoji_completion query = %v", extractTerms(rCompQry))
	}
	rIterMark, err := Analyze(AnalyzeRequest{
		Text:       []string{"人々 いすゞ ミスヾ ゃゅょ ャュョ 十万二千五百"},
		CharFilter: []any{"japanese_Iteration_mark"},
		Tokenizer:  "whitespace",
		Filter:     []any{"hiragana_uppercase", "katakana_uppercase", "kuromoji_number"},
	})
	if err != nil || !reflect.DeepEqual(extractTerms(rIterMark), []string{"人人", "いすず", "ミスズ", "やゆよ", "ヤユヨ", "102500"}) {
		t.Fatalf("japanese_iteration_mark + kana uppercase + kuromoji_number = %v (err=%v)", extractTerms(rIterMark), err)
	}

	// 3. analysis-nori (10_basic.yml & 20_search.yml)
	rNoriAn, err := Analyze(AnalyzeRequest{Text: []string{"뿌리가 깊은 나무"}, Analyzer: "nori"})
	if err != nil || !reflect.DeepEqual(extractTerms(rNoriAn), []string{"뿌리", "깊", "나무"}) {
		t.Fatalf("nori analyzer = %v (err=%v)", extractTerms(rNoriAn), err)
	}
	rNoriTok, err := Analyze(AnalyzeRequest{Text: []string{"뿌리가 깊은 나무"}, Tokenizer: "nori_tokenizer"})
	if err != nil || !reflect.DeepEqual(extractTerms(rNoriTok), []string{"뿌리", "가", "깊", "은", "나무"}) {
		t.Fatalf("nori_tokenizer = %v (err=%v)", extractTerms(rNoriTok), err)
	}
	rNoriPOS, _ := Analyze(AnalyzeRequest{Text: []string{"뿌리가 깊은 나무"}, Tokenizer: "nori_tokenizer", Filter: []any{"nori_part_of_speech"}})
	if !reflect.DeepEqual(extractTerms(rNoriPOS), []string{"뿌리", "깊", "나무"}) {
		t.Fatalf("nori_part_of_speech = %v", extractTerms(rNoriPOS))
	}
	rNoriRead, _ := Analyze(AnalyzeRequest{Text: []string{"鄕歌"}, Tokenizer: "nori_tokenizer", Filter: []any{"nori_readingform"}})
	if !reflect.DeepEqual(extractTerms(rNoriRead), []string{"향가"}) {
		t.Fatalf("nori_readingform = %v", extractTerms(rNoriRead))
	}
	rNoriNum, err := Analyze(AnalyzeRequest{
		Text:      []string{"십만이천오백과 ３.２천"},
		Tokenizer: map[string]any{"type": "nori_tokenizer", "discard_punctuation": false},
		Filter: []any{
			map[string]any{"type": "nori_part_of_speech", "stoptags": []any{"SP"}},
			map[string]any{"type": "nori_number"},
		},
	})
	if err != nil || !reflect.DeepEqual(extractTerms(rNoriNum), []string{"102500", "과", "3200"}) {
		t.Fatalf("nori_number = %v (err=%v)", extractTerms(rNoriNum), err)
	}

	// 4. analysis-smartcn (10_basic.yml & 20_search.yml)
	rSmartTok, err := Analyze(AnalyzeRequest{Text: []string{"我购买了道具和服装。"}, Tokenizer: "smartcn_tokenizer"})
	if err != nil || !reflect.DeepEqual(extractTerms(rSmartTok), []string{"我", "购买", "了", "道具", "和", "服装", ","}) {
		t.Fatalf("smartcn_tokenizer = %v (err=%v)", extractTerms(rSmartTok), err)
	}
	rSmartAn, err := Analyze(AnalyzeRequest{Text: []string{"我购买了道具和服装。"}, Analyzer: "smartcn"})
	if err != nil || !reflect.DeepEqual(extractTerms(rSmartAn), []string{"我", "购买", "了", "道具", "和", "服装"}) {
		t.Fatalf("smartcn analyzer = %v (err=%v)", extractTerms(rSmartAn), err)
	}

	// 5. analysis-stempel (10_basic.yml & 20_search.yml)
	rPolStem, err := Analyze(AnalyzeRequest{Text: []string{"studenci"}, Tokenizer: "standard", Filter: []any{"polish_stem"}})
	if err != nil || !reflect.DeepEqual(extractTerms(rPolStem), []string{"student"}) {
		t.Fatalf("polish_stem = %v (err=%v)", extractTerms(rPolStem), err)
	}
	rPolAn, err := Analyze(AnalyzeRequest{Text: []string{"studenta był"}, Analyzer: "polish"})
	if err != nil || !reflect.DeepEqual(extractTerms(rPolAn), []string{"student"}) {
		t.Fatalf("polish analyzer = %v (err=%v)", extractTerms(rPolAn), err)
	}

	// 6. analysis-ukrainian (10_basic.yml & 20_search.yml)
	rUkr, err := Analyze(AnalyzeRequest{Text: []string{"колу"}, Analyzer: "ukrainian"})
	if err != nil || !reflect.DeepEqual(extractTerms(rUkr), []string{"кола", "коло", "кіл"}) {
		t.Fatalf("ukrainian analyzer = %v (err=%v)", extractTerms(rUkr), err)
	}
	for idx, tk := range rUkr.Tokens {
		if tk.StartOffset != 0 || tk.EndOffset != 4 || tk.Position != 0 {
			t.Fatalf("ukrainian token[%d] unexpected offsets/pos: %+v", idx, tk)
		}
	}
	qUkrDoc, err := AnalyzeForQuery("Ця п'єса у свою чергу рухається по колу.", "ukrainian", nil, Options{})
	qUkrSearch, err2 := AnalyzeForQuery("кола", "ukrainian", nil, Options{})
	if err != nil || err2 != nil || qUkrDoc.IsEmpty() || qUkrSearch.IsEmpty() {
		t.Fatalf("ukrainian search graph failed: err=%v err2=%v", err, err2)
	}
}

func TestRound63_PluginEncodersAndOptionsCoverage(t *testing.T) {
	// 1. Phonetic encoders: exercise all consonant/vowel branches across double_metaphone, metaphone, caverphone, nysiis, cologne, koelner, haase, beider_morse, daitch_mokotoff
	phoneticVocab := "knack gnat wrack phone xavier dumb sugar cia machiavelli schmidt mcgowan jose otto bell cab rogier wright judge dodge ghost laugh thumb vicious queen czar czech tough cough"
	for _, enc := range []string{
		"metaphone", "double_metaphone", "soundex", "refined_soundex",
		"caverphone1", "caverphone2", "cologne", "nysiis",
		"koelnerphonetik", "haasephonetik", "beider_morse", "daitch_mokotoff",
	} {
		res, err := Analyze(AnalyzeRequest{
			Text:      []string{phoneticVocab},
			Tokenizer: "whitespace",
			Filter: []any{map[string]any{
				"type":    "phonetic",
				"encoder": enc,
				"replace": false,
			}},
		})
		if err != nil || len(res.Tokens) == 0 {
			t.Fatalf("phonetic encoder %s failed: err=%v", enc, err)
		}
	}
	// Beider-Morse name_type / rule_type / languages combinations & validation errors
	for _, bmDef := range []map[string]any{
		{"type": "phonetic", "encoder": "beider_morse", "name_type": "sephardic", "rule_type": "approx", "languages": []any{"spanish", "italian"}},
		{"type": "phonetic", "encoder": "beider_morse", "name_type": "generic", "rule_type": "exact", "languages": []any{"german", "french", "russian"}},
		{"type": "phonetic", "encoder": "metaphone", "max_code_len": 8},
		{"type": "phonetic", "encoder": "double_metaphone", "max_code_len": 6},
	} {
		if _, err := Analyze(AnalyzeRequest{
			Text:      []string{"chrząszcz szwarc schneider"},
			Tokenizer: "whitespace",
			Filter:    []any{bmDef},
		}); err != nil {
			t.Fatalf("phonetic custom config %v failed: %v", bmDef, err)
		}
	}
	for _, badPhon := range []map[string]any{
		{"type": "phonetic", "encoder": "unknown_enc"},
		{"type": "phonetic", "replace": "not_bool"},
		{"type": "phonetic", "max_code_len": 0},
		{"type": "phonetic", "max_code_len": 999},
		{"type": "phonetic", "encoder": "beider_morse", "rule_type": "rules"},
		{"type": "phonetic", "encoder": "beider_morse", "name_type": "invalid"},
		{"type": "phonetic", "encoder": "beider_morse", "languages": []any{"klingon"}},
	} {
		if _, err := Analyze(AnalyzeRequest{Text: []string{"test"}, Tokenizer: "whitespace", Filter: []any{badPhon}}); err == nil {
			t.Fatalf("expected error for invalid phonetic config %v", badPhon)
		}
	}

	// 2. ICU options, normalizers, collation strengths, transforms, and validation errors
	for _, method := range []string{"nfc", "nfd", "nfkc", "nfkd", "nfkc_cf"} {
		for _, mode := range []string{"compose", "decompose"} {
			if _, err := Analyze(AnalyzeRequest{
				Text: []string{"ﬀ ﬁ ﬂ ﬃ ﬄ ß İ ＡＢＣ café"},
				CharFilter: []any{map[string]any{
					"type":             "icu_normalizer",
					"name":             method,
					"mode":             mode,
					"unicodeSetFilter": "[^x]",
				}},
				Tokenizer: "icu_tokenizer",
				Filter: []any{
					map[string]any{"type": "icu_normalizer", "name": method},
					map[string]any{"type": "icu_folding", "unicode_set_filter": "[a-zA-Z0-9ß]"},
				},
			}); err != nil {
				t.Fatalf("icu %s/%s failed: %v", method, mode, err)
			}
		}
	}
	for _, strength := range []string{"primary", "secondary", "tertiary", "quaternary", "identical"} {
		if _, err := Analyze(AnalyzeRequest{
			Text:      []string{"item-002 item-10 Café cafe"},
			Tokenizer: "whitespace",
			Filter: []any{map[string]any{
				"type":       "icu_collation",
				"strength":   strength,
				"alternate":  "shifted",
				"case_first": "upper",
				"numeric":    true,
			}},
		}); err != nil {
			t.Fatalf("icu_collation %s failed: %v", strength, err)
		}
	}
	for _, trDef := range []map[string]any{
		{"type": "icu_transform", "id": "Cyrillic-Latin; Any-Upper", "dir": "forward"},
		{"type": "icu_transform", "id": "Katakana-Hiragana; Halfwidth-Fullwidth", "dir": "reverse"},
		{"type": "icu_transform", "id": "NFD; [:Nonspacing Mark:] Remove; NFC"},
		{"type": "icu_transform", "id": "Traditional-Simplified; Greek-Latin; Any-Lower"},
	} {
		if _, err := Analyze(AnalyzeRequest{
			Text:      []string{"Привет 東京 カタカナ Αλфа 臺灣 Café"},
			Tokenizer: "icu_tokenizer",
			Filter:    []any{trDef},
		}); err != nil {
			t.Fatalf("icu_transform %v failed: %v", trDef, err)
		}
	}

	// 3. Kuromoji, Nori, SmartCN, Polish, Ukrainian custom analyzer/tokenizer/filter options & errors
	pluginCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"tokenizer": map[string]any{
				"k_ext": map[string]any{
					"type":                   "kuromoji_tokenizer",
					"mode":                   "extended",
					"discard_punctuation":    false,
					"discard_compound_token": true,
					"nbest_cost":             1000,
					"user_dictionary_rules":  []any{"東京スカイツリー,東京 スカイツリー,トウキョウ スカイツリー,カスタム名詞"},
				},
				"n_mix": map[string]any{
					"type":                    "nori_tokenizer",
					"decompound_mode":         "mixed",
					"discard_punctuation":     false,
					"output_unknown_unigrams": true,
					"user_dictionary_rules":   []any{"세종대왕"},
				},
				"k_dict": map[string]any{
					"type":            "kuromoji_tokenizer",
					"user_dictionary": "userdict_ja.txt",
				},
				"n_dict": map[string]any{
					"type":            "nori_tokenizer",
					"user_dictionary": "userdict_ko.txt",
				},
				"icu_rf": map[string]any{
					"type":       "icu_tokenizer",
					"rule_files": "Latn:Latin-break-only-on-whitespace.rbbi",
				},
			},
			"analyzer": map[string]any{
				"icu_custom": map[string]any{"type": "icu_analyzer", "method": "nfkc", "mode": "decompose"},
				"kuro_cust":  map[string]any{"type": "kuromoji", "mode": "normal", "stopwords": []any{"の", "に"}},
				"nori_cust":  map[string]any{"type": "nori", "decompound_mode": "none", "stoptags": []any{"J", "E"}},
				"scn_cust":   map[string]any{"type": "smartcn", "stopwords": []any{","}},
				"pol_cust":   map[string]any{"type": "polish", "stopwords": []any{"był"}, "stem_exclusion": []any{"studenci"}},
				"ukr_cust":   map[string]any{"type": "ukrainian", "stopwords": []any{"по"}, "stem_exclusion": []any{"колу"}},
			},
		},
	}, Options{
		ResolveResourcePath: func(_, path string) ([]string, error) {
			return []string{"# comment", "カスタム語,カスタム語,カスタムゴ,カスタム名詞", "한글사전"}, nil
		},
	})
	if err != nil {
		t.Fatalf("pluginCfg failed: %v", err)
	}
	for _, an := range []string{"icu_custom", "kuro_cust", "nori_cust", "scn_cust", "pol_cust", "ukr_cust"} {
		if _, err := Analyze(AnalyzeRequest{
			Text:     []string{"関西国際空港に行く。 세종대왕 한국어! 我购买了服装。 studenci był колу книги міста"},
			Analyzer: an,
			Config:   pluginCfg,
		}); err != nil {
			t.Fatalf("custom plugin analyzer %s failed: %v", an, err)
		}
	}
	if _, err := Analyze(AnalyzeRequest{
		Text:      []string{"関西国際空港、東京スカイツリー！一百二十三億四千五百六十七万八千九百零一"},
		Tokenizer: "k_ext",
		Filter: []any{
			map[string]any{"type": "kuromoji_readingform", "use_romaji": true},
			"kuromoji_number",
		},
		Config: pluginCfg,
	}); err != nil {
		t.Fatalf("k_ext failed: %v", err)
	}
	for _, tk := range []string{"n_mix", "k_dict", "n_dict", "icu_rf"} {
		if _, err := Analyze(AnalyzeRequest{
			Text:      []string{"인천국제공항에 세종대왕! カスタム語 한글사전 ภาษาไทย"},
			Tokenizer: tk,
			Config:    pluginCfg,
		}); err != nil {
			t.Fatalf("%s failed: %v", tk, err)
		}
	}

	// Validation errors across plugin builders
	badConfigs := []map[string]any{
		{"analysis": map[string]any{"analyzer": map[string]any{"bad": map[string]any{"type": "icu_analyzer", "mode": "bad"}}}},
		{"analysis": map[string]any{"analyzer": map[string]any{"bad": map[string]any{"type": "kuromoji_completion", "mode": "bad"}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"bad": map[string]any{"type": "icu_tokenizer", "rule_files": "invalid_no_colon"}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"bad": map[string]any{"type": "kuromoji_tokenizer", "mode": "bad"}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"bad": map[string]any{"type": "kuromoji_tokenizer", "user_dictionary": "a.txt", "user_dictionary_rules": []any{"x"}}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"bad": map[string]any{"type": "nori_tokenizer", "decompound_mode": "bad"}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"bad": map[string]any{"type": "nori_tokenizer", "user_dictionary": "a.txt", "user_dictionary_rules": []any{"x"}}}}},
		{"analysis": map[string]any{"filter": map[string]any{"bad": map[string]any{"type": "icu_collation", "strength": "bad"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"bad": map[string]any{"type": "icu_collation", "decomposition": "bad"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"bad": map[string]any{"type": "icu_collation", "alternate": "bad"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"bad": map[string]any{"type": "icu_collation", "case_first": "bad"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"bad": map[string]any{"type": "icu_transform", "dir": "sideways"}}}},
	}
	for _, bc := range badConfigs {
		if _, err := ParseIndexAnalysisConfig(bc, Options{}); err == nil {
			t.Fatalf("expected error for invalid plugin config %v", bc)
		}
	}
}
