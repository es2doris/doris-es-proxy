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

import "testing"

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
	}
	for _, s := range seeds {
		f.Add(s.text, s.mode)
	}

	builtInAnalyzers := []string{
		"standard", "simple", "whitespace", "classic", "cjk", "thai",
		"english", "german", "french", "arabic", "turkish",
		"icu_analyzer", "kuromoji", "kuromoji_completion", "nori", "smartcn", "polish", "ukrainian",
	}

	f.Fuzz(func(t *testing.T, text string, mode uint8) {
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
		_, _ = Analyze(AnalyzeRequest{
			Text:     []string{text},
			Analyzer: an,
			Explain:  mode%2 == 0,
			Config:   cfg,
		})
		qGraph, err := AnalyzeForQuery(text, an, cfg, Options{})
		if err == nil && !qGraph.IsEmpty() {
			_ = qGraph.PhrasePaths(8)
		}

		// 2. Custom ParseIndexAnalysisConfig + rich filter pipelines
		switch mode % 5 {
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
				_, _ = Analyze(AnalyzeRequest{Text: []string{text}, Analyzer: "fuzz_an", Config: customCfg})
				_, _ = AnalyzeForQuery(text, "fuzz_an", customCfg, Options{})
			}

		case 1:
			_, _ = Analyze(AnalyzeRequest{
				Text:      []string{text},
				Tokenizer: map[string]any{"type": "ngram", "min": 1, "max": 2},
				Filter: []any{
					map[string]any{"type": "shingle", "min_shingle_size": 2, "max_shingle_size": 3},
					map[string]any{"type": "phonetic", "encoder": "double_metaphone", "replace": false},
				},
				Config: cfg,
			})

		case 2:
			_, _ = Analyze(AnalyzeRequest{
				Text:      []string{text},
				Tokenizer: "path_hierarchy",
				Filter: []any{
					"icu_folding",
					map[string]any{"type": "min_hash", "bucket_count": 16, "hash_count": 1},
				},
				Config: cfg,
			})

		case 3:
			_, _ = Analyze(AnalyzeRequest{
				Text:      []string{text},
				Tokenizer: "classic",
				Filter: []any{
					map[string]any{"type": "phonetic", "encoder": "daitch_mokotoff"},
					map[string]any{"type": "phonetic", "encoder": "beider_morse", "languages": []any{"polish"}},
				},
				Config: cfg,
			})

		case 4:
			_, _ = Analyze(AnalyzeRequest{
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
			})
		}
	})
}
