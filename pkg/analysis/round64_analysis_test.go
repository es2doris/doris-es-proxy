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
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRound64_P0_8_PatternReplaceExpandBombDoS(t *testing.T) {
	bombRepl := strings.Repeat("$1", 10000) // 20 KB replacement multiplying $1 by 10,000x

	// 1. Direct expandJavaReplacement stops at maxOutBytes without multi-GB allocation.
	bigSrc := strings.Repeat("a", 500000)
	var mBefore, mAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mBefore)
	t0 := time.Now()
	_, err := expandJavaReplacement(bigSrc, []int{0, len(bigSrc), 0, len(bigSrc)}, bombRepl, MaxTokenTermBytes)
	runtime.ReadMemStats(&mAfter)
	if err == nil {
		t.Fatalf("expected expandJavaReplacement to reject >MaxTokenTermBytes expansion")
	}
	if time.Since(t0) > time.Second {
		t.Fatalf("expandJavaReplacement bomb took too long: %v", time.Since(t0))
	}
	if allocDelta := mAfter.TotalAlloc - mBefore.TotalAlloc; allocDelta > 16<<20 {
		t.Fatalf("expandJavaReplacement allocated too much memory: %d bytes", allocDelta)
	}

	// 2. pattern_replace char_filter $1x10000 bomb via Analyze & AnalyzeForQuery
	cfCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"char_filter": map[string]any{
				"pr_bomb": map[string]any{
					"type":        "pattern_replace",
					"pattern":     "(.*)",
					"replacement": bombRepl,
				},
			},
			"analyzer": map[string]any{
				"bomb_an": map[string]any{
					"char_filter": []any{"pr_bomb"},
					"tokenizer":   "keyword",
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig char_filter bomb config failed: %v", err)
	}
	t1 := time.Now()
	_, err = Analyze(AnalyzeRequest{
		Text:     []string{strings.Repeat("a", 100000)},
		Analyzer: "bomb_an",
		Config:   cfCfg,
	})
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(ae.Reason, "char_filter output exceeds maximum") {
		t.Fatalf("expected 400 char_filter max output error on Analyze, got: %v", err)
	}
	_, err = AnalyzeForQuery(strings.Repeat("a", 100000), "bomb_an", cfCfg, Options{})
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(ae.Reason, "char_filter output exceeds maximum") {
		t.Fatalf("expected 400 char_filter max output error on AnalyzeForQuery, got: %v", err)
	}
	if time.Since(t1) > 2*time.Second {
		t.Fatalf("char_filter $1x10000 bomb took too long: %v", time.Since(t1))
	}

	// 3. Empty-match char_filter bomb: 100,000 empty matches with $1x10000 where $1 is empty
	emptyBombCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"char_filter": map[string]any{
				"pr_empty_bomb": map[string]any{
					"type":        "pattern_replace",
					"pattern":     "(a*)",
					"replacement": bombRepl,
				},
			},
			"analyzer": map[string]any{
				"empty_bomb_an": map[string]any{
					"char_filter": []any{"pr_empty_bomb"},
					"tokenizer":   "whitespace",
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig empty bomb failed: %v", err)
	}
	t2 := time.Now()
	rEmpty, err := Analyze(AnalyzeRequest{
		Text:     []string{strings.Repeat("b", 100000)},
		Analyzer: "empty_bomb_an",
		Config:   emptyBombCfg,
	})
	if err != nil && !strings.Contains(err.Error(), "32766") {
		t.Fatalf("unexpected error on empty-match char_filter bomb: %v", err)
	}
	_ = rEmpty
	if time.Since(t2) > 2*time.Second {
		t.Fatalf("empty-match char_filter $1x10000 bomb took too long: %v", time.Since(t2))
	}

	// 4. pattern_replace token filter $1x10000 bomb
	t3 := time.Now()
	_, err = Analyze(AnalyzeRequest{
		Text:      []string{strings.Repeat("x", 10000)},
		Tokenizer: "keyword",
		Filter: []any{
			map[string]any{
				"type":        "pattern_replace",
				"pattern":     "(.*)",
				"replacement": bombRepl,
			},
		},
	})
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(ae.Reason, "32766") {
		t.Fatalf("expected 400 MaxTokenTermBytes error on pattern_replace token filter bomb, got: %v", err)
	}
	if time.Since(t3) > 2*time.Second {
		t.Fatalf("pattern_replace token filter $1x10000 bomb took too long: %v", time.Since(t3))
	}
}

func TestRound64_P0_8_DecompounderDoSRemediation(t *testing.T) {
	// 1. Both dictionary_decompounder & hyphenation_decompounder reject max_subword_size > 128
	for _, typ := range []string{"dictionary_decompounder", "hyphenation_decompounder"} {
		_, err := ParseIndexAnalysisConfig(map[string]any{
			"analysis": map[string]any{
				"filter": map[string]any{
					"bad_dec": map[string]any{
						"type":             typ,
						"word_list":        []any{"foo", "bar"},
						"max_subword_size": 32766,
					},
				},
			},
		}, Options{})
		if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(ae.Reason, "max_subword_size") {
			t.Fatalf("expected 400 max_subword_size cap error for %s, got: %v", typ, err)
		}
	}

	// 2. Direct applyDecompounder call with maxSub=32766 and 32KB non-matching tokens:
	//    must clamp to 128, hit step cap cleanly with near-zero inner-loop allocations (< 8 MiB total).
	advToken := strings.Repeat("q", 32000)
	dict := map[string]bool{
		strings.Repeat("z", 128): true,
		"nonmatching":            true,
	}
	var mBefore, mAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mBefore)
	t0 := time.Now()
	_, err := applyDecompounder([]Token{{Term: advToken, Position: 0, PositionLength: 1}}, dict, 2, 2, 32766, false, newTokenStreamBudget(DefaultMaxTokenCount))
	runtime.ReadMemStats(&mAfter)
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(ae.Reason, "decompounder work limit exceeded") {
		t.Fatalf("expected 400 decompounder work limit exceeded error, got: %v", err)
	}
	if time.Since(t0) > time.Second {
		t.Fatalf("applyDecompounder 32KB attack took too long: %v", time.Since(t0))
	}
	if allocDelta := mAfter.TotalAlloc - mBefore.TotalAlloc; allocDelta > 8<<20 {
		t.Fatalf("applyDecompounder allocated too much memory on non-matching 32KB token: %d bytes", allocDelta)
	}

	// 3. Multi-token 32KB attack through Analyze with max valid max_subword_size=128
	tokens32KB := make([]string, 20)
	for i := range tokens32KB {
		tokens32KB[i] = strings.Repeat("x", 32000)
	}
	t1 := time.Now()
	_, err = Analyze(AnalyzeRequest{
		Text:      []string{strings.Join(tokens32KB, " ")},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{
				"type":             "dictionary_decompounder",
				"word_list":        []any{strings.Repeat("y", 128)},
				"max_subword_size": 128,
			},
		},
	})
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(ae.Reason, "decompounder work limit exceeded") {
		t.Fatalf("expected 400 decompounder work limit exceeded on multi-token attack, got: %v", err)
	}
	if time.Since(t1) > 2*time.Second {
		t.Fatalf("multi-token decompounder attack took too long: %v", time.Since(t1))
	}
}

func TestRound64_P0_8_SynonymPreBudgetOOMRemediation(t *testing.T) {
	// 1. Compile-time cap on single source key accumulating > 4096 output tokens across merged rules
	var ruleLines []string
	var rhsTerms []string
	for i := 0; i < 500; i++ {
		rhsTerms = append(rhsTerms, fmt.Sprintf("t%d", i))
	}
	for r := 0; r < 10; r++ {
		// 10 lines * 500 targets on same key "boom" = 5,000 target tokens > 4096!
		var shifted []string
		for _, rt := range rhsTerms {
			shifted = append(shifted, fmt.Sprintf("%s_%d", rt, r))
		}
		ruleLines = append(ruleLines, "boom => "+strings.Join(shifted, ", "))
	}
	_, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"huge_syn": map[string]any{
					"type":     "synonym_graph",
					"synonyms": ruleLines,
				},
			},
		},
	}, Options{})
	if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(ae.Reason, "exceed maximum output tokens") {
		t.Fatalf("expected 400 per-rule output token cap error, got: %v", err)
	}

	// 2. Immediate budget reservation per token inside BOTH applySynonymFlat and applySynonymGraph:
	//    250-way synonym rule with max_token_count=32 must abort at token 33 without materializing 250 tokens!
	var synTerms []string
	for i := 0; i < 240; i++ {
		synTerms = append(synTerms, fmt.Sprintf("syn%03d", i))
	}
	tightCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"index.analyze.max_token_count": 32,
		"analysis": map[string]any{
			"filter": map[string]any{
				"big_sg": map[string]any{
					"type":     "synonym_graph",
					"synonyms": []any{"seed => " + strings.Join(synTerms, ", ")},
				},
				"big_sf": map[string]any{
					"type":     "synonym",
					"synonyms": []any{"seed => " + strings.Join(synTerms, ", ")},
				},
			},
			"analyzer": map[string]any{
				"an_sg": map[string]any{"tokenizer": "whitespace", "filter": []any{"big_sg"}},
				"an_sf": map[string]any{"tokenizer": "whitespace", "filter": []any{"big_sf"}},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("tightCfg failed: %v", err)
	}
	for _, an := range []string{"an_sg", "an_sf"} {
		t0 := time.Now()
		_, err := Analyze(AnalyzeRequest{
			Text:     []string{strings.Repeat("seed ", 50)},
			Analyzer: an,
			Config:   tightCfg,
		})
		if ae, ok := AsAnalysisError(err); !ok || ae.Status != 400 || !strings.Contains(ae.Reason, "exceeded the allowed maximum of [32]") {
			t.Fatalf("expected 400 max_token_count [32] error for %s, got: %v", an, err)
		}
		if time.Since(t0) > 500*time.Millisecond {
			t.Fatalf("%s budget abort took too long: %v", an, time.Since(t0))
		}
	}

	// 3. Byte budget (DefaultMaxStreamBytes) enforced immediately inside applySynonymGraph & applySynonymFlat
	bigTarget := strings.Repeat("x", 30000) // ~30 KB per target
	targets := make([]string, 20)
	for i := range targets {
		targets[i] = fmt.Sprintf("%s_%02d", bigTarget, i)
	}
	byteEntry := synonymEntry{
		src:      []string{"hit"},
		targets:  [][]string{targets},
		keepOrig: true,
	}
	tinyByteBudget := &tokenStreamBudget{maxTokens: 10000, maxBytes: 128 * 1024}
	if _, err := applySynonymGraph([]Token{{Term: "hit", Position: 0, PositionLength: 1}}, []synonymEntry{byteEntry}, tinyByteBudget); err == nil || !strings.Contains(err.Error(), "byte size") {
		t.Fatalf("expected byte size budget error in applySynonymGraph, got: %v", err)
	}
	tinyByteBudget2 := &tokenStreamBudget{maxTokens: 10000, maxBytes: 128 * 1024}
	if _, err := applySynonymFlat([]Token{{Term: "hit", Position: 0, PositionLength: 1}}, []synonymEntry{byteEntry}, tinyByteBudget2); err == nil || !strings.Contains(err.Error(), "byte size") {
		t.Fatalf("expected byte size budget error in applySynonymFlat, got: %v", err)
	}
}

func TestRound64_F18_SynonymGraphVsFlatAndQueryTokenGraph(t *testing.T) {
	cfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"flat_syns": map[string]any{
					"type": "synonym",
					"synonyms": []any{
						"ny, new york",
						"the usa, united states of america",
						"wtf, what the fudge",
						"foo, bar baz",
						"quick, fast",
					},
				},
				"graph_syns": map[string]any{
					"type": "synonym_graph",
					"synonyms": []any{
						"ny, new york",
						"the usa, united states of america",
						"wtf, what the fudge",
						"foo, bar baz",
						"quick, fast",
					},
				},
				"self_keep": map[string]any{
					"type":     "synonym_graph",
					"synonyms": []any{"ny => ny, new york"},
				},
			},
			"analyzer": map[string]any{
				"flat_an":      map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "flat_syns"}},
				"graph_an":     map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "graph_syns"}},
				"self_keep_an": map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "self_keep"}},
				"fold_chain_an": map[string]any{
					"tokenizer": "standard",
					"filter": []any{
						"lowercase",
						map[string]any{"type": "asciifolding", "preserve_original": true},
						"graph_syns",
					},
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig failed: %v", err)
	}

	assertTokens := func(label string, resp *AnalyzeResponse, wantTerms []string, wantPos []int, wantPL []int) {
		t.Helper()
		if len(resp.Tokens) != len(wantTerms) {
			t.Fatalf("%s: got %d tokens %+v, want %d (%v)", label, len(resp.Tokens), resp.Tokens, len(wantTerms), wantTerms)
		}
		for i, tok := range resp.Tokens {
			if tok.Token != wantTerms[i] || tok.Position != wantPos[i] {
				t.Fatalf("%s[%d]: got (%q, pos=%d), want (%q, pos=%d)", label, i, tok.Token, tok.Position, wantTerms[i], wantPos[i])
			}
			gotPL := 1
			if tok.PositionLength != nil {
				gotPL = *tok.PositionLength
			}
			if gotPL != wantPL[i] {
				t.Fatalf("%s[%d] (%q): got posLen=%d, want %d", label, i, tok.Token, gotPL, wantPL[i])
			}
		}
	}

	// 1. "ny, new york" on "in ny city":
	//    - flat synonym stacks city at pos=2 with york, ny has posLen=1
	rFlatNY, err := Analyze(AnalyzeRequest{Text: []string{"in ny city"}, Analyzer: "flat_an", Config: cfg})
	if err != nil {
		t.Fatalf("flat_an(in ny city) failed: %v", err)
	}
	assertTokens("flat_ny", rFlatNY,
		[]string{"in", "ny", "new", "york", "city"},
		[]int{0, 1, 1, 2, 2},
		[]int{1, 1, 1, 1, 1},
	)
	//    - synonym_graph sets ny posLen=2 and pushes city to pos=3
	rGraphNY, err := Analyze(AnalyzeRequest{Text: []string{"in ny city"}, Analyzer: "graph_an", Config: cfg})
	if err != nil {
		t.Fatalf("graph_an(in ny city) failed: %v", err)
	}
	assertTokens("graph_ny", rGraphNY,
		[]string{"in", "new", "ny", "york", "city"},
		[]int{0, 1, 1, 2, 3},
		[]int{1, 1, 2, 1, 1},
	)

	// 2. "the usa, united states of america" on "visit the usa today":
	//    - flat synonym emits monotonic positions (of & today stacked at pos=3, america at pos=4)
	rFlatUSA, err := Analyze(AnalyzeRequest{Text: []string{"visit the usa today"}, Analyzer: "flat_an", Config: cfg})
	if err != nil {
		t.Fatalf("flat_an(visit the usa today) failed: %v", err)
	}
	assertTokens("flat_usa", rFlatUSA,
		[]string{"visit", "the", "united", "usa", "states", "of", "today", "america"},
		[]int{0, 1, 1, 2, 2, 3, 3, 4},
		[]int{1, 1, 1, 1, 1, 1, 1, 1},
	)
	//    - synonym_graph sets exact DAG internal nodes: united(1,1)->states(2,1)->of(3,1)->america(4,2) vs the(1,4)->usa(5,1), today(6,1)
	rGraphUSA, err := Analyze(AnalyzeRequest{Text: []string{"visit the usa today"}, Analyzer: "graph_an", Config: cfg})
	if err != nil {
		t.Fatalf("graph_an(visit the usa today) failed: %v", err)
	}
	assertTokens("graph_usa", rGraphUSA,
		[]string{"visit", "united", "the", "states", "of", "america", "usa", "today"},
		[]int{0, 1, 1, 2, 3, 4, 5, 6},
		[]int{1, 1, 4, 1, 1, 2, 1, 1},
	)

	// Reverse direction: "visit united states of america today"
	rGraphUSARev, err := Analyze(AnalyzeRequest{Text: []string{"visit united states of america today"}, Analyzer: "graph_an", Config: cfg})
	if err != nil {
		t.Fatalf("graph_an(visit united states of america today) failed: %v", err)
	}
	assertTokens("graph_usa_rev", rGraphUSARev,
		[]string{"visit", "the", "united", "usa", "states", "of", "america", "today"},
		[]int{0, 1, 1, 2, 3, 4, 5, 6},
		[]int{1, 1, 2, 4, 1, 1, 1, 1},
	)

	// 3. AnalyzeForQuery parity: 60_synonym_graph.yml & PhrasePaths
	gFlatFoo, err := AnalyzeForQuery("foo two three", "flat_an", cfg, Options{})
	if err != nil {
		t.Fatalf("AnalyzeForQuery(flat foo two three) failed: %v", err)
	}
	if gFlatFoo.HasGraphSpans {
		t.Fatalf("expected flat synonym foo two three to have HasGraphSpans=false")
	}
	flatPaths := gFlatFoo.PhrasePaths(16)
	wantFlatMatchDoc5 := []string{"bar", "two", "three"}
	foundFlatDoc5 := false
	for _, p := range flatPaths {
		if reflect.DeepEqual(p, wantFlatMatchDoc5) {
			foundFlatDoc5 = true
		}
		if reflect.DeepEqual(p, []string{"bar", "baz", "two", "three"}) {
			t.Fatalf("flat synonym should NOT produce graph phrase [bar baz two three], got %v", flatPaths)
		}
	}
	if !foundFlatDoc5 {
		t.Fatalf("expected flat synonym PhrasePaths to include %v, got %v", wantFlatMatchDoc5, flatPaths)
	}

	gGraphFoo, err := AnalyzeForQuery("foo two three", "graph_an", cfg, Options{})
	if err != nil {
		t.Fatalf("AnalyzeForQuery(graph foo two three) failed: %v", err)
	}
	if !gGraphFoo.HasGraphSpans || len(gGraphFoo.Segments) != 3 {
		t.Fatalf("expected 3 segments with HasGraphSpans=true, got %+v", gGraphFoo)
	}
	wantGraphPaths := [][]string{
		{"bar", "baz", "two", "three"},
		{"foo", "two", "three"},
	}
	if got := gGraphFoo.PhrasePaths(16); !reflect.DeepEqual(got, wantGraphPaths) {
		t.Fatalf("graph foo two three PhrasePaths = %v, want %v", got, wantGraphPaths)
	}

	gGraphUSA, err := AnalyzeForQuery("visit the usa today", "graph_an", cfg, Options{})
	if err != nil {
		t.Fatalf("AnalyzeForQuery(visit the usa today) failed: %v", err)
	}
	wantUSAPaths := [][]string{
		{"visit", "united", "states", "of", "america", "today"},
		{"visit", "the", "usa", "today"},
	}
	if got := gGraphUSA.PhrasePaths(16); !reflect.DeepEqual(got, wantUSAPaths) {
		t.Fatalf("graph the usa PhrasePaths = %v, want %v", got, wantUSAPaths)
	}

	// 4. 50_queries_with_synonyms.yml stacked tokens + exported helpers for pkg/transpiler
	rawToks, err := AnalyzeTokens("the fast brown", "flat_an", cfg, Options{})
	if err != nil {
		t.Fatalf("AnalyzeTokens failed: %v", err)
	}
	if len(rawToks) != 4 || rawToks[1].Position != 1 || rawToks[2].Position != 1 {
		t.Fatalf("expected stacked tokens at pos 1 from AnalyzeTokens, got %+v", rawToks)
	}
	builtGraph := BuildQueryTokenGraph(rawToks)
	if !builtGraph.HasMultiTermsPerPosition || len(builtGraph.Segments) != 3 {
		t.Fatalf("unexpected BuildQueryTokenGraph result: %+v", builtGraph)
	}
	if !builtGraph.Segments[1].IsSingleTermAlternatives() {
		t.Fatalf("expected segment 1 to have single-term alternatives")
	}
	if got := builtGraph.Segments[1].SingleTermAlternatives(); !reflect.DeepEqual(got, []string{"fast", "quick"}) {
		t.Fatalf("SingleTermAlternatives = %v, want [fast quick]", got)
	}
	if gGraphFoo.Segments[0].IsSingleTermAlternatives() || gGraphFoo.Segments[0].SingleTermAlternatives() != nil {
		t.Fatalf("multi-word synonym segment should report IsSingleTermAlternatives() == false")
	}

	// 5. Self-mapping preservation (`ny => ny, new york`) & stacked input tokens (`asciifolding(preserve_original: true)` + `synonym_graph`)
	rSelfKeep, err := Analyze(AnalyzeRequest{Text: []string{"ny"}, Analyzer: "self_keep_an", Config: cfg})
	if err != nil {
		t.Fatalf("self_keep_an failed: %v", err)
	}
	assertTokens("self_keep", rSelfKeep, []string{"new", "ny", "york"}, []int{0, 0, 1}, []int{1, 2, 1})

	gFoldChain, err := AnalyzeForQuery("café ny", "fold_chain_an", cfg, Options{})
	if err != nil {
		t.Fatalf("fold_chain_an AnalyzeForQuery failed: %v", err)
	}
	if len(gFoldChain.Positions) < 3 || !reflect.DeepEqual(gFoldChain.Positions[0].Terms, []string{"cafe", "café"}) {
		t.Fatalf("expected stacked [cafe café] at pos 0 before ny->new york, got %+v", gFoldChain.Positions)
	}
	if len(gFoldChain.Segments) != 2 || len(gFoldChain.Segments[1].Alternatives) != 2 {
		t.Fatalf("expected 2 segments with 2 alternatives in segment 1, got %+v", gFoldChain.Segments)
	}
}

func TestRound64_F18_NormalizerPatternReplace(t *testing.T) {
	// Mirrors analysis-common/40_token_filters.yml :: pattern_replace_filter plus flags, all:false, capture groups, and char_filter
	cfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"char_filter": map[string]any{
				"strip_dashes": map[string]any{
					"type":        "pattern_replace",
					"pattern":     "-+",
					"replacement": "",
				},
			},
			"filter": map[string]any{
				"replace_zeros": map[string]any{
					"type":        "pattern_replace",
					"pattern":     "0+",
					"replacement": "",
					"all":         true,
				},
				"replace_first_zero": map[string]any{
					"type":        "pattern_replace",
					"pattern":     "0",
					"replacement": "X",
					"all":         false,
				},
				"capture_prefix": map[string]any{
					"type":        "pattern_replace",
					"pattern":     "^id-([0-9]+)$",
					"replacement": "NUM:$1",
					"flags":       "CASE_INSENSITIVE",
				},
			},
			"normalizer": map[string]any{
				"my_normalizer": map[string]any{
					"type":   "custom",
					"filter": []any{"replace_zeros"},
				},
				"first_only_norm": map[string]any{
					"type":   "custom",
					"filter": []any{"replace_first_zero"},
				},
				"capture_norm": map[string]any{
					"type":   "custom",
					"filter": []any{"trim", "capture_prefix", "lowercase"},
				},
				"cf_norm": map[string]any{
					"type":        "custom",
					"char_filter": []any{"strip_dashes"},
					"filter":      []any{"lowercase", "replace_zeros"},
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig normalizer pattern_replace failed: %v", err)
	}

	cases := []struct {
		norm string
		in   string
		want string
	}{
		{"my_normalizer", "000000111", "111"},
		{"my_normalizer", "100200300", "123"},
		{"my_normalizer", "0000", ""},
		{"first_only_norm", "000111", "X00111"},
		{"capture_norm", "  ID-0042  ", "num:0042"},
		{"cf_norm", "A-00-B-0C", "abc"},
	}
	for _, tc := range cases {
		got, err := NormalizeTerm(tc.in, tc.norm, cfg, Options{})
		if err != nil {
			t.Fatalf("NormalizeTerm(%q, %q) failed: %v", tc.in, tc.norm, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeTerm(%q, %q) = %q, want %q", tc.in, tc.norm, got, tc.want)
		}
		r, err := Analyze(AnalyzeRequest{Text: []string{tc.in}, Normalizer: tc.norm, Config: cfg})
		if err != nil || len(r.Tokens) != 1 || r.Tokens[0].Token != tc.want {
			t.Fatalf("Analyze(normalizer=%q, %q) = %+v (err=%v), want %q", tc.norm, tc.in, r, err, tc.want)
		}
	}
}
