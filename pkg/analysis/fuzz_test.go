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
	"strings"
	"testing"
	"time"
)

func FuzzAnalyze(f *testing.F) {
	seeds := []struct {
		text string
		mode uint8
	}{
		{"The quick brown fox jumps over value1_foo!", 0},
		{"<!--<!--<!-- unclosed <script>alert(1)<a title=\"x", 1},
		{"ops@example.com https://example.org/a/b/c U.S.A.", 2},
		{"JR新宿駅の近くにビールを飲みに行こうか 関西国際空港 ｿｰｽｺｰﾄﾞ", 3},
		{"뿌리가 깊은 나무 십만이천오백과 ３.２천 鄕歌", 4},
		{"我购买了道具和服装。 ภาษาไทย", 5},
		{"studenci studenta był колу Szwarc Moskowitz", 6},
		{"Foo Bar Ruß résumé Bâton enflammé", 7},
		{"/usr/local/bin/go supercalifragilisticexpialidocious", 8},
		{"((((((true)))))) && !false", 9},
		// pattern_replace (char + token + normalizer) seeds
		{"000000111 sample6 sample1 " + strings.Repeat("a", 512), 10},
		{"$1$1$0\\1\\$ " + strings.Repeat("xy", 256), 11},
		// dictionary_decompounder & hyphenation_decompounder seeds
		{"foobarbaz Donaudampfschifffahrtsgesellschaftskapitaen", 12},
		{strings.Repeat("unmatchedlongtoken", 128), 13},
		// synonym_graph & synonym seeds
		{"visit ny and the usa today automatic teller machine", 14},
		{"three what the fudge foo bar baz nyc", 15},
	}
	for _, s := range seeds {
		f.Add(s.text, s.mode)
	}

	builtInAnalyzers := []string{
		"standard", "simple", "whitespace", "classic", "cjk", "thai",
		"english", "german", "french", "arabic", "turkish",
		"icu_analyzer", "kuromoji", "kuromoji_completion", "nori", "smartcn", "polish", "ukrainian",
	}

	checkRespInvariants := func(t *testing.T, resp *AnalyzeResponse, maxTokens int, checkMonotonic bool) {
		t.Helper()
		if resp == nil {
			return
		}
		if len(resp.Tokens) > maxTokens {
			t.Fatalf("token count %d exceeded MaxTokenCount %d", len(resp.Tokens), maxTokens)
		}
		prevPos := 0
		for i, tok := range resp.Tokens {
			if len(tok.Token) > MaxTokenTermBytes {
				t.Fatalf("token[%d] term length %d exceeded MaxTokenTermBytes %d", i, len(tok.Token), MaxTokenTermBytes)
			}
			if tok.Position < 0 {
				t.Fatalf("token[%d] negative position %d", i, tok.Position)
			}
			if tok.PositionLength != nil && *tok.PositionLength < 1 {
				t.Fatalf("token[%d] invalid positionLength %d", i, *tok.PositionLength)
			}
			if checkMonotonic && i > 0 && tok.Position < prevPos {
				t.Fatalf("token[%d] non-monotonic position %d < %d", i, tok.Position, prevPos)
			}
			prevPos = tok.Position
		}
	}

	checkGraphInvariants := func(t *testing.T, qGraph QueryTokenGraph, maxTokens int) {
		t.Helper()
		if len(qGraph.Tokens) > maxTokens {
			t.Fatalf("query graph token count %d exceeded MaxTokenCount %d", len(qGraph.Tokens), maxTokens)
		}
		for i, seg := range qGraph.Segments {
			if seg.EndPosition <= seg.StartPosition {
				t.Fatalf("segment[%d] invalid span [%d, %d)", i, seg.StartPosition, seg.EndPosition)
			}
		}
		if paths := qGraph.PhrasePaths(16); len(paths) > 16 {
			t.Fatalf("PhrasePaths(16) returned %d paths", len(paths))
		}
	}

	f.Fuzz(func(t *testing.T, text string, mode uint8) {
		iterStart := time.Now()
		if len(text) > 16384 {
			text = text[:16384]
		}

		// 1. Named built-in / plugin analyzer via Analyze & AnalyzeForQuery
		an := builtInAnalyzers[int(mode)%len(builtInAnalyzers)]
		cfg := &IndexAnalysisConfig{
			MaxTokenCount:  128,
			MaxNGramDiff:   2,
			MaxShingleDiff: 2,
		}
		if resp, err := Analyze(AnalyzeRequest{
			Text:     []string{text},
			Analyzer: an,
			Explain:  mode%2 == 0,
			Config:   cfg,
		}); err == nil {
			checkRespInvariants(t, resp, cfg.MaxTokenCount, false)
		}
		qGraph, err := AnalyzeForQuery(text, an, cfg, Options{})
		if err == nil {
			checkGraphInvariants(t, qGraph, cfg.MaxTokenCount)
		}

		// 2. Custom ParseIndexAnalysisConfig + rich filter pipelines
		switch mode % 8 {
		case 0:
			customCfg, cfgErr := ParseIndexAnalysisConfig(map[string]any{
				"index.analyze.max_token_count": 64,
				"analysis": map[string]any{
					"char_filter": map[string]any{
						"cf1": "html_strip",
						"cf2": "kuromoji_iteration_mark",
						"cf3": "icu_normalizer",
					},
					"tokenizer": map[string]any{
						"tk": "uax_url_email",
					},
					"filter": map[string]any{
						"f_wdg": "word_delimiter_graph",
						"f_syn": map[string]any{
							"type":     "synonym_graph",
							"lenient":  true,
							"synonyms": []any{"fox, hound, quick dog", "ny => new york"},
						},
						"f_flat": "flatten_graph",
					},
					"analyzer": map[string]any{
						"fuzz_an": map[string]any{
							"char_filter": []any{"cf1", "cf2", "cf3"},
							"tokenizer":   "tk",
							"filter":      []any{"lowercase", "f_wdg", "f_syn", "f_flat"},
						},
					},
				},
			}, Options{})
			if cfgErr == nil {
				if r, err := Analyze(AnalyzeRequest{Text: []string{text}, Analyzer: "fuzz_an", Config: customCfg}); err == nil {
					checkRespInvariants(t, r, 64, true)
				}
				if g, err := AnalyzeForQuery(text, "fuzz_an", customCfg, Options{}); err == nil {
					checkGraphInvariants(t, g, 64)
				}
			}

		case 1:
			if r, err := Analyze(AnalyzeRequest{
				Text:      []string{text},
				Tokenizer: map[string]any{"type": "ngram", "min": 1, "max": 2},
				Filter: []any{
					map[string]any{"type": "shingle", "min_shingle_size": 2, "max_shingle_size": 3},
					map[string]any{"type": "phonetic", "encoder": "double_metaphone", "replace": false},
				},
				Config: cfg,
			}); err == nil {
				checkRespInvariants(t, r, cfg.MaxTokenCount, false)
			}

		case 2:
			if r, err := Analyze(AnalyzeRequest{
				Text:      []string{text},
				Tokenizer: "path_hierarchy",
				Filter: []any{
					"icu_folding",
					map[string]any{"type": "min_hash", "bucket_count": 16, "hash_count": 1},
				},
				Config: cfg,
			}); err == nil {
				checkRespInvariants(t, r, cfg.MaxTokenCount, true)
			}

		case 3:
			if r, err := Analyze(AnalyzeRequest{
				Text:      []string{text},
				Tokenizer: "classic",
				Filter: []any{
					map[string]any{"type": "phonetic", "encoder": "daitch_mokotoff"},
					map[string]any{"type": "phonetic", "encoder": "beider_morse", "languages": []any{"polish"}},
				},
				Config: cfg,
			}); err == nil {
				checkRespInvariants(t, r, cfg.MaxTokenCount, true)
			}

		case 4:
			if r, err := Analyze(AnalyzeRequest{
				Text:      []string{text},
				Tokenizer: "standard",
				Filter: []any{
					map[string]any{
						"type":   "condition",
						"filter": []any{"uppercase"},
						"script": map[string]any{"source": text},
					},
				},
				Config: cfg,
			}); err == nil {
				checkRespInvariants(t, r, cfg.MaxTokenCount, true)
			}

		case 5:
			// pattern_replace char_filter + token filter + keyword normalizer
			if r, err := Analyze(AnalyzeRequest{
				Text: []string{text},
				CharFilter: []any{
					map[string]any{
						"type":        "pattern_replace",
						"pattern":     "([a-zA-Z0-9]+)",
						"replacement": strings.Repeat("$1", 64),
					},
				},
				Tokenizer: "whitespace",
				Filter: []any{
					map[string]any{
						"type":        "pattern_replace",
						"pattern":     "(.*)",
						"replacement": text,
						"all":         mode%2 == 0,
					},
				},
				Config: cfg,
			}); err == nil {
				checkRespInvariants(t, r, cfg.MaxTokenCount, true)
			}
			normCfg, cfgErr := ParseIndexAnalysisConfig(map[string]any{
				"analysis": map[string]any{
					"filter": map[string]any{
						"rz": map[string]any{
							"type":        "pattern_replace",
							"pattern":     "0+",
							"replacement": "",
							"all":         true,
						},
					},
					"normalizer": map[string]any{
						"n_pr": map[string]any{
							"type":   "custom",
							"filter": []any{"lowercase", "rz"},
						},
					},
				},
			}, Options{})
			if cfgErr == nil {
				if normOut, err := NormalizeTerm(text, "n_pr", normCfg, Options{}); err == nil && len(normOut) > MaxTokenTermBytes {
					t.Fatalf("NormalizeTerm exceeded MaxTokenTermBytes: %d", len(normOut))
				}
			}

		case 6:
			// dictionary_decompounder & hyphenation_decompounder with max_subword_size bounds
			if r, err := Analyze(AnalyzeRequest{
				Text:      []string{text},
				Tokenizer: "whitespace",
				Filter: []any{
					map[string]any{
						"type":               "dictionary_decompounder",
						"word_list":          []any{"foo", "bar", "baz", "dampf", "schiff", "fahrt", "ny", "york"},
						"min_word_size":      2,
						"min_subword_size":   2,
						"max_subword_size":   128,
						"only_longest_match": mode%2 == 0,
					},
					map[string]any{
						"type":             "hyphenation_decompounder",
						"word_list":        []any{"donau", "auto", "matic"},
						"min_word_size":    3,
						"min_subword_size": 2,
						"max_subword_size": 64,
					},
				},
				Config: cfg,
			}); err == nil {
				checkRespInvariants(t, r, cfg.MaxTokenCount, true)
			}

		case 7:
			// synonym_graph & flat synonym multi-word expansions across Analyze & AnalyzeForQuery
			synCfg, cfgErr := ParseIndexAnalysisConfig(map[string]any{
				"index.analyze.max_token_count": 128,
				"analysis": map[string]any{
					"filter": map[string]any{
						"f_sg": map[string]any{
							"type":     "synonym_graph",
							"lenient":  true,
							"synonyms": []any{"ny, new york", "the usa, united states of america", "wtf, what the fudge", "foo, bar baz"},
						},
						"f_sf": map[string]any{
							"type":     "synonym",
							"lenient":  true,
							"synonyms": []any{"ny, new york", "the usa, united states of america", "wtf, what the fudge", "foo, bar baz"},
						},
					},
					"analyzer": map[string]any{
						"sg_an": map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "f_sg"}},
						"sf_an": map[string]any{"tokenizer": "standard", "filter": []any{"lowercase", "f_sf"}},
					},
				},
			}, Options{})
			if cfgErr == nil {
				if r, err := Analyze(AnalyzeRequest{Text: []string{text}, Analyzer: "sg_an", Config: synCfg}); err == nil {
					checkRespInvariants(t, r, 128, true)
				}
				if r, err := Analyze(AnalyzeRequest{Text: []string{text}, Analyzer: "sf_an", Config: synCfg}); err == nil {
					checkRespInvariants(t, r, 128, true)
				}
				if g, err := AnalyzeForQuery(text, "sg_an", synCfg, Options{}); err == nil {
					checkGraphInvariants(t, g, 128)
				}
				if g, err := AnalyzeForQuery(text, "sf_an", synCfg, Options{}); err == nil {
					checkGraphInvariants(t, g, 128)
				}
			}
		}

		if elapsed := time.Since(iterStart); elapsed > 5*time.Second {
			t.Fatalf("FuzzAnalyze iteration exceeded latency budget: %v (mode=%d, len=%d)", elapsed, mode, len(text))
		}
	})
}
