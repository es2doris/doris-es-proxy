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
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestTokenFiltersNormalizationAndStemming(t *testing.T) {
	for _, fn := range []string{
		"lowercase", "uppercase", "asciifolding", "decimal_digit",
		"cjk_width", "cjk_bigram", "arabic_normalization", "bengali_normalization",
		"german_normalization", "hindi_normalization", "indic_normalization",
		"persian_normalization", "scandinavian_normalization", "scandinavian_folding",
		"serbian_normalization", "sorani_normalization", "elision", "apostrophe", "classic",
		"stop", "length", "truncate", "trim", "limit", "keep", "keep_words", "keep_types",
		"unique", "remove_duplicates", "reverse", "porter_stem", "kstem", "stemmer", "snowball",
		"stemmer_override", "keyword_marker", "keyword_repeat", "word_delimiter",
		"word_delimiter_graph", "ngram", "edge_ngram", "shingle", "synonym", "synonym_graph",
		"flatten_graph", "common_grams", "dictionary_decompounder", "pattern_capture",
		"pattern_replace", "fingerprint", "min_hash", "delimited_payload", "type_as_payload",
		"delimited_term_freq", "condition", "predicate_token_filter", "multiplexer",
	} {
		if !IsBuiltInTokenFilter(fn) {
			t.Fatalf("expected IsBuiltInTokenFilter(%q) == true", fn)
		}
	}

	// asciifolding preserve_original
	rAF, err := Analyze(AnalyzeRequest{
		Text:      []string{"Musée d'Orsay"},
		Tokenizer: "keyword",
		Filter:    []any{map[string]any{"type": "asciifolding", "preserve_original": true}},
	})
	if err != nil {
		t.Fatalf("asciifolding failed: %v", err)
	}
	if want := []string{"Musee d'Orsay", "Musée d'Orsay"}; !reflect.DeepEqual(extractTerms(rAF), want) {
		t.Fatalf("asciifolding = %v, want %v", extractTerms(rAF), want)
	}

	// lowercase languages: greek, turkish, irish
	rTr, err := Analyze(AnalyzeRequest{
		Text:      []string{"İSTANBUL IĞDIR"},
		Tokenizer: "whitespace",
		Filter:    []any{map[string]any{"type": "lowercase", "language": "turkish"}},
	})
	if err != nil {
		t.Fatalf("turkish lowercase failed: %v", err)
	}
	if want := []string{"istanbul", "ığdır"}; !reflect.DeepEqual(extractTerms(rTr), want) {
		t.Fatalf("turkish lowercase = %v, want %v", extractTerms(rTr), want)
	}

	rGa, err := Analyze(AnalyzeRequest{
		Text:      []string{"nAthair tAcht"},
		Tokenizer: "whitespace",
		Filter:    []any{map[string]any{"type": "lowercase", "language": "irish"}},
	})
	if err != nil {
		t.Fatalf("irish lowercase failed: %v", err)
	}
	if want := []string{"n-athair", "t-acht"}; !reflect.DeepEqual(extractTerms(rGa), want) {
		t.Fatalf("irish lowercase = %v, want %v", extractTerms(rGa), want)
	}

	// Normalization smoke suite
	normCases := []struct {
		filter any
		input  string
		want   string
	}{
		{"uppercase", "foobar", "FOOBAR"},
		{"trim", "  Foo Bar !  ", "Foo Bar !"},
		{"reverse", "foobar", "raboof"},
		{"apostrophe", "foo's bar", "foo"},
		{"decimal_digit", "١٢٣٤", "1234"},
		{"cjk_width", "ｶﾀｶﾅ ｶﾞﾊﾟ ＡＢＣ", "カタカナ ガパ ABC"},
		{"arabic_normalization", "آجن", "اجن"},
		{"bengali_normalization", "চাঁদ", "চাদ"},
		{"german_normalization", "weißbier", "weissbier"},
		{"hindi_normalization", "अँगरेज़ी", "अंगरेजि"},
		{"indic_normalization", "ত্\u200d", "ৎ"},
		{"persian_normalization", "های", "هاي"},
		{"scandinavian_normalization", "ö aa ae", "ø å æ"},
		{"scandinavian_folding", "räksmörgås", "raksmorgas"},
		{"serbian_normalization", "абвгдђежзијклљмнњопрстћуфхцчџш", "abvgddjezzijklljmnnjoprstcufhccdzs"},
		{map[string]any{"type": "serbian_normalization", "haircut": "regular"}, "ђжћчџш", "đžćčdžš"},
		{"sorani_normalization", "ي", "ی"},
		{"kstem", "bricks", "brick"},
		{"arabic_stem", "الحسن", "حسن"},
		{"brazilian_stem", "Brasília", "brasil"},
		{"czech_stem", "angličtí", "anglick"},
		{"dutch_stem", "ophouden", "ophoud"},
		{"french_stem", "chevaux", "cheval"},
		{"german_stem", "abschließen", "abschliess"},
		{"russian_stem", "журналы", "журнал"},
		{"bengali_stem", "করেছিলাম", "কর"},
	}
	for _, tc := range normCases {
		r, err := Analyze(AnalyzeRequest{
			Text:      []string{tc.input},
			Tokenizer: "keyword",
			Filter:    []any{tc.filter},
		})
		if err != nil {
			t.Fatalf("filter %v failed: %v", tc.filter, err)
		}
		if len(r.Tokens) != 1 || r.Tokens[0].Token != tc.want {
			t.Fatalf("filter %v(%q) = %v, want %q", tc.filter, tc.input, extractTerms(r), tc.want)
		}
	}

	// cjk_bigram with standard tokenizer + output_unigrams
	rCJK, err := Analyze(AnalyzeRequest{
		Text:      []string{"多くの学生が試験に落ちた"},
		Tokenizer: "standard",
		Filter:    []any{"cjk_bigram"},
	})
	if err != nil {
		t.Fatalf("cjk_bigram failed: %v", err)
	}
	wantCJK := []string{"多く", "くの", "の学", "学生", "生が", "が試", "試験", "験に", "に落", "落ち", "ちた"}
	if !reflect.DeepEqual(extractTerms(rCJK), wantCJK) {
		t.Fatalf("cjk_bigram = %v, want %v", extractTerms(rCJK), wantCJK)
	}

	rCJKUni, err := Analyze(AnalyzeRequest{
		Text:      []string{"多くの"},
		Tokenizer: "standard",
		Filter:    []any{map[string]any{"type": "cjk_bigram", "output_unigrams": true, "ignored_scripts": []any{"hangul"}}},
	})
	if err != nil {
		t.Fatalf("cjk_bigram unigrams failed: %v", err)
	}
	if want := []string{"多", "多く", "く", "くの", "の"}; !reflect.DeepEqual(extractTerms(rCJKUni), want) {
		t.Fatalf("cjk_bigram unigrams = %v, want %v", extractTerms(rCJKUni), want)
	}

	// snowball explain attributes (bytes, positionLength: 1, keyword: false)
	rSBExp, err := Analyze(AnalyzeRequest{
		Text:      []string{"This is troubled"},
		Tokenizer: "standard",
		Filter:    []any{"snowball"},
		Explain:   true,
	})
	if err != nil {
		t.Fatalf("snowball explain failed: %v", err)
	}
	tok2 := rSBExp.Detail.TokenFilters[0].Tokens[2]
	if tok2.Token != "troubl" || tok2.Bytes != "[74 72 6f 75 62 6c]" || tok2.PositionLength == nil || *tok2.PositionLength != 1 || tok2.Keyword == nil || *tok2.Keyword {
		t.Fatalf("unexpected snowball explain token: %+v", tok2)
	}

	// keyword_marker, keyword_repeat, stemmer_override
	rSO, err := Analyze(AnalyzeRequest{
		Text:      []string{"zoeken foo bar running"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{
				"type": "stemmer_override",
				"rules": []any{
					"zoeken => override",
					"foo, bar => baz",
				},
			},
			map[string]any{
				"type":             "keyword_marker",
				"keywords_pattern": "run.*",
			},
			map[string]any{"type": "stemmer", "language": "dutch"},
			"porter_stem",
		},
	})
	if err != nil {
		t.Fatalf("stemmer_override + keyword_marker failed: %v", err)
	}
	if want := []string{"override", "baz", "baz", "running"}; !reflect.DeepEqual(extractTerms(rSO), want) {
		t.Fatalf("stemmer_override = %v, want %v", extractTerms(rSO), want)
	}

	// stemmer_override rules_path access denied on jvm.options
	_, err = ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"bad_so": map[string]any{
					"type":       "stemmer_override",
					"rules_path": "jvm.options",
				},
			},
		},
	}, Options{})
	if err == nil || !strings.Contains(err.Error(), "Access denied trying to read file rules_path") {
		t.Fatalf("expected Access denied error, got: %v", err)
	}

	// elision validation error when articles missing
	_, err = ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"bad_elision": map[string]any{
					"type": "elision",
				},
			},
		},
	}, Options{})
	if err == nil || err.Error() != "elision filter requires [articles] or [articles_path] setting" {
		t.Fatalf("expected elision error, got: %v", err)
	}
}

func TestFilteringPositionCompoundAndSynonymGraphFilters(t *testing.T) {
	// 1. unique ES 8.15 position correction
	rUniq, err := Analyze(AnalyzeRequest{
		Text:      []string{"los angeles leadership academy"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{"type": "edge_ngram", "max_gram": 2},
			"unique",
		},
	})
	if err != nil {
		t.Fatalf("unique position correction failed: %v", err)
	}
	wantTerms := []string{"l", "lo", "a", "an", "le", "ac"}
	wantPos := []int{0, 0, 1, 1, 2, 3}
	if !reflect.DeepEqual(extractTerms(rUniq), wantTerms) {
		t.Fatalf("unique terms = %v, want %v", extractTerms(rUniq), wantTerms)
	}
	for i, p := range wantPos {
		if rUniq.Tokens[i].Position != p {
			t.Fatalf("token[%d] (%s) pos = %d, want %d", i, rUniq.Tokens[i].Token, rUniq.Tokens[i].Position, p)
		}
	}

	// 2. keyword_repeat + porter_stem + unique(only_on_same_position: true)
	rStack, err := Analyze(AnalyzeRequest{
		Text:      []string{"fox runs"},
		Tokenizer: "standard",
		Filter: []any{
			"lowercase",
			"keyword_repeat",
			"porter_stem",
			map[string]any{"type": "unique", "only_on_same_position": true},
		},
	})
	if err != nil {
		t.Fatalf("stacked stems failed: %v", err)
	}
	if want := []string{"fox", "runs", "run"}; !reflect.DeepEqual(extractTerms(rStack), want) {
		t.Fatalf("stacked stems = %v, want %v", extractTerms(rStack), want)
	}

	// 3. stop (remove_trailing: false), length, truncate, limit, keep, keep_types
	rMisc, err := Analyze(AnalyzeRequest{
		Text:      []string{"foo 123456 bar the"},
		Tokenizer: "standard",
		Filter: []any{
			map[string]any{"type": "stop", "stopwords": "_english_", "remove_trailing": false},
			map[string]any{"type": "keep_types", "types": []any{"<NUM>"}, "mode": "exclude"},
			map[string]any{"type": "length", "min": 2, "max": 10},
			map[string]any{"type": "truncate", "length": 3},
			map[string]any{"type": "keep", "keep_words": []any{"foo", "the"}, "keep_words_case": true},
			map[string]any{"type": "limit", "max_token_count": 2},
		},
	})
	if err != nil {
		t.Fatalf("misc filters failed: %v", err)
	}
	if want := []string{"foo", "the"}; !reflect.DeepEqual(extractTerms(rMisc), want) {
		t.Fatalf("misc filters = %v, want %v", extractTerms(rMisc), want)
	}

	// 4. word_delimiter & word_delimiter_graph (adjust_offsets, catenate, case change, numerics)
	rWDG, err := Analyze(AnalyzeRequest{
		Text:      []string{"the qu1ck brown fox"},
		Tokenizer: "standard",
		Filter:    []any{"word_delimiter_graph"},
		Explain:   true,
	})
	if err != nil {
		t.Fatalf("word_delimiter_graph failed: %v", err)
	}
	if want := []string{"the", "qu", "1", "ck", "brown", "fox"}; !reflect.DeepEqual(extractTerms(rWDG), want) {
		t.Fatalf("word_delimiter_graph = %v, want %v", extractTerms(rWDG), want)
	}
	if rWDG.Tokens[1].StartOffset != 4 || rWDG.Tokens[1].EndOffset != 6 || rWDG.Tokens[2].StartOffset != 6 || rWDG.Tokens[3].StartOffset != 7 {
		t.Fatalf("unexpected adjusted offsets: %+v", rWDG.Tokens)
	}

	rWDGNoAdj, err := Analyze(AnalyzeRequest{
		Text:      []string{"the qu1ck"},
		Tokenizer: "standard",
		Filter: []any{
			map[string]any{
				"type":              "word_delimiter_graph",
				"adjust_offsets":    false,
				"catenate_all":      true,
				"preserve_original": true,
				"protected_words":   []any{"keepMe"},
				"type_table":        []any{"# => ALPHA"},
			},
		},
	})
	if err != nil {
		t.Fatalf("word_delimiter_graph no adjust failed: %v", err)
	}
	if rWDGNoAdj.Tokens[1].StartOffset != 4 || rWDGNoAdj.Tokens[1].EndOffset != 9 {
		t.Fatalf("expected unadjusted offsets [4, 9], got [%d, %d]", rWDGNoAdj.Tokens[1].StartOffset, rWDGNoAdj.Tokens[1].EndOffset)
	}

	// 5. shingle, common_grams, decompounder, pattern_capture, pattern_replace, payloads, min_hash
	rSh, err := Analyze(AnalyzeRequest{
		Text:      []string{"quick brown fox"},
		Tokenizer: "whitespace",
		Filter:    []any{map[string]any{"type": "shingle", "min_shingle_size": 2, "max_shingle_size": 2, "output_unigrams": false}},
	})
	if err != nil {
		t.Fatalf("shingle failed: %v", err)
	}
	if want := []string{"quick brown", "brown fox"}; !reflect.DeepEqual(extractTerms(rSh), want) {
		t.Fatalf("shingle = %v, want %v", extractTerms(rSh), want)
	}
	if rSh.Tokens[0].PositionLength == nil || *rSh.Tokens[0].PositionLength != 2 {
		t.Fatalf("expected shingle positionLength 2, got %+v", rSh.Tokens[0].PositionLength)
	}

	rCG, err := Analyze(AnalyzeRequest{
		Text:      []string{"a b c"},
		Tokenizer: "whitespace",
		Filter:    []any{map[string]any{"type": "common_grams", "common_words": []any{"a"}}},
	})
	if err != nil {
		t.Fatalf("common_grams failed: %v", err)
	}
	if want := []string{"a", "a_b", "b", "c"}; !reflect.DeepEqual(extractTerms(rCG), want) {
		t.Fatalf("common_grams = %v, want %v", extractTerms(rCG), want)
	}

	rCGQ, err := Analyze(AnalyzeRequest{
		Text:      []string{"a b c"},
		Tokenizer: "whitespace",
		Filter:    []any{map[string]any{"type": "common_grams", "common_words": []any{"a"}, "query_mode": true}},
	})
	if err != nil {
		t.Fatalf("common_grams query_mode failed: %v", err)
	}
	if want := []string{"a_b", "c"}; !reflect.DeepEqual(extractTerms(rCGQ), want) {
		t.Fatalf("common_grams query_mode = %v, want %v", extractTerms(rCGQ), want)
	}

	rDecomp, err := Analyze(AnalyzeRequest{
		Text:      []string{"foobar"},
		Tokenizer: "keyword",
		Filter:    []any{map[string]any{"type": "dictionary_decompounder", "word_list": []any{"foo", "bar"}}},
	})
	if err != nil {
		t.Fatalf("decompounder failed: %v", err)
	}
	if want := []string{"foobar", "foo", "bar"}; !reflect.DeepEqual(extractTerms(rDecomp), want) {
		t.Fatalf("decompounder = %v, want %v", extractTerms(rDecomp), want)
	}

	rPC, err := Analyze(AnalyzeRequest{
		Text:      []string{"foo@bar.baz"},
		Tokenizer: "keyword",
		Filter:    []any{map[string]any{"type": "pattern_capture", "preserve_original": false, "patterns": []any{"([^@]+)"}}},
	})
	if err != nil {
		t.Fatalf("pattern_capture failed: %v", err)
	}
	if want := []string{"foo", "bar.baz"}; !reflect.DeepEqual(extractTerms(rPC), want) {
		t.Fatalf("pattern_capture = %v, want %v", extractTerms(rPC), want)
	}

	rPay, err := Analyze(AnalyzeRequest{
		Text:      []string{"foo|5 bar|2"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{"type": "delimited_payload", "delimiter": "|", "encoding": "float"},
		},
		Explain: true,
	})
	if err != nil {
		t.Fatalf("delimited_payload failed: %v", err)
	}
	if want := []string{"foo", "bar"}; !reflect.DeepEqual(extractTerms(rPay), want) {
		t.Fatalf("delimited_payload = %v, want %v", extractTerms(rPay), want)
	}
	if rPay.Detail.TokenFilters[0].Tokens[0].Payload == "" {
		t.Fatalf("expected non-empty float payload hex in explain")
	}

	rTF, err := Analyze(AnalyzeRequest{
		Text:      []string{"foo|3"},
		Tokenizer: "whitespace",
		Filter:    []any{"delimited_term_freq", "type_as_payload"},
		Explain:   true,
	})
	if err != nil {
		t.Fatalf("delimited_term_freq failed: %v", err)
	}
	if rTF.Tokens[0].TermFrequency == nil || *rTF.Tokens[0].TermFrequency != 3 {
		t.Fatalf("expected termFrequency 3, got %+v", rTF.Tokens[0])
	}

	rMH, err := Analyze(AnalyzeRequest{
		Text:      []string{"the quick brown fox"},
		Tokenizer: "whitespace",
		Filter:    []any{"min_hash"},
	})
	if err != nil {
		t.Fatalf("min_hash failed: %v", err)
	}
	if len(rMH.Tokens) != 512 {
		t.Fatalf("expected 512 min_hash tokens, got %d", len(rMH.Tokens))
	}

	// 6. synonym_graph + flatten_graph exact node allocation (40_token_filters.yml)
	rSG, err := Analyze(AnalyzeRequest{
		Text:      []string{"this automatic teller machine is down"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{
				"type":     "synonym_graph",
				"synonyms": []any{"automatic teller machine,atm,cash point"},
			},
		},
	})
	if err != nil {
		t.Fatalf("synonym_graph failed: %v", err)
	}
	wantSGTerms := []string{"this", "atm", "cash", "automatic", "point", "teller", "machine", "is", "down"}
	wantSGPos := []int{0, 1, 1, 1, 2, 3, 4, 5, 6}
	wantSGPL := []int{0, 4, 0, 2, 3, 0, 0, 0, 0} // 0 means omitted (== 1) in non-explain JSON!
	if !reflect.DeepEqual(extractTerms(rSG), wantSGTerms) {
		t.Fatalf("synonym_graph terms = %v, want %v", extractTerms(rSG), wantSGTerms)
	}
	for i := range rSG.Tokens {
		if rSG.Tokens[i].Position != wantSGPos[i] {
			t.Fatalf("synonym_graph[%d] pos = %d, want %d", i, rSG.Tokens[i].Position, wantSGPos[i])
		}
		gotPL := 0
		if rSG.Tokens[i].PositionLength != nil {
			gotPL = *rSG.Tokens[i].PositionLength
		}
		if gotPL != wantSGPL[i] {
			t.Fatalf("synonym_graph[%d] posLen = %d, want %d", i, gotPL, wantSGPL[i])
		}
	}

	// Now with flatten_graph appended
	rFlat, err := Analyze(AnalyzeRequest{
		Text:      []string{"this automatic teller machine is down"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{
				"type":     "synonym_graph",
				"synonyms": []any{"automatic teller machine,atm,cash point"},
			},
			"flatten_graph",
		},
	})
	if err != nil {
		t.Fatalf("flatten_graph failed: %v", err)
	}
	wantFlatPos := []int{0, 1, 1, 1, 2, 2, 3, 4, 5}
	wantFlatPL := []int{0, 3, 0, 0, 2, 0, 0, 0, 0}
	for i := range rFlat.Tokens {
		if rFlat.Tokens[i].Position != wantFlatPos[i] {
			t.Fatalf("flatten_graph[%d] pos = %d, want %d", i, rFlat.Tokens[i].Position, wantFlatPos[i])
		}
		gotPL := 0
		if rFlat.Tokens[i].PositionLength != nil {
			gotPL = *rFlat.Tokens[i].PositionLength
		}
		if gotPL != wantFlatPL[i] {
			t.Fatalf("flatten_graph[%d] posLen = %d, want %d", i, gotPL, wantFlatPL[i])
		}
	}

	// 7. Synonym with preceding char_filter & trigram tokenizer + WordNet format + multiplexer
	rTriSyn, err := Analyze(AnalyzeRequest{
		Text:      []string{"kimchy"},
		Tokenizer: map[string]any{"type": "ngram", "min_gram": 3, "max_gram": 3},
		Filter: []any{
			map[string]any{"type": "synonym", "synonyms": []any{"kimchy => shay"}},
		},
	})
	if err != nil {
		t.Fatalf("trigram synonym failed: %v", err)
	}
	if want := []string{"sha", "hay"}; !reflect.DeepEqual(extractTerms(rTriSyn), want) {
		t.Fatalf("trigram synonym = %v, want %v", extractTerms(rTriSyn), want)
	}

	rHTMLSyn, err := Analyze(AnalyzeRequest{
		Text:       []string{"kimchy is the dude <html>abides</html>"},
		CharFilter: []any{"html_strip"},
		Tokenizer:  "whitespace",
		Filter: []any{
			map[string]any{
				"type":     "synonym",
				"synonyms": []any{"<p>kimchy</p> => shay", "dude => <html>elasticsearch</html>", "<font>abides</font> => man!"},
			},
		},
	})
	if err != nil {
		t.Fatalf("html_strip synonym failed: %v", err)
	}
	if want := []string{"shay", "is", "the", "elasticsearch", "man!"}; !reflect.DeepEqual(extractTerms(rHTMLSyn), want) {
		t.Fatalf("html_strip synonym = %v, want %v", extractTerms(rHTMLSyn), want)
	}

	rWN, err := Analyze(AnalyzeRequest{
		Text:      []string{"forest"},
		Tokenizer: "standard",
		Filter: []any{
			map[string]any{
				"type":   "synonym_graph",
				"format": "wordnet",
				"synonyms": []any{
					"s(100000001,1,'forest',n,1,0).",
					"s(100000001,2,'woods',n,1,0).",
					"s(100000001,3,'timberland',n,1,0).",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("wordnet synonym failed: %v", err)
	}
	if want := []string{"woods", "timberland", "forest"}; !reflect.DeepEqual(extractTerms(rWN), want) {
		t.Fatalf("wordnet synonym = %v, want %v", extractTerms(rWN), want)
	}

	rMux, err := Analyze(AnalyzeRequest{
		Text:      []string{"The quick fox"},
		Tokenizer: "standard",
		Filter: []any{
			map[string]any{
				"type":              "multiplexer",
				"filters":           []any{"lowercase", "uppercase"},
				"preserve_original": false,
			},
		},
	})
	if err != nil {
		t.Fatalf("multiplexer failed: %v", err)
	}
	if want := []string{"the", "THE", "quick", "QUICK", "fox", "FOX"}; !reflect.DeepEqual(extractTerms(rMux), want) {
		t.Fatalf("multiplexer = %v, want %v", extractTerms(rMux), want)
	}
}

func TestScriptingNormalizersLimitsQueryGraphAndClusterStats(t *testing.T) {
	// 1. 60_analysis_scripting.yml: condition & predicate_token_filter (built-in evaluator + custom callback)
	rCond, err := Analyze(AnalyzeRequest{
		Text:      []string{"Vorsprung Durch Technik"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{
				"type":   "condition",
				"filter": []any{"lowercase"},
				"script": map[string]any{
					"source": `token.position >= 1 && token.positionIncrement > 0 && token.startOffset > 0 && token.endOffset > 0 && (token.positionLength == 1 || token.type == "a" || token.keyword)`,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("condition script failed: %v", err)
	}
	if want := []string{"Vorsprung", "durch", "technik"}; !reflect.DeepEqual(extractTerms(rCond), want) {
		t.Fatalf("condition = %v, want %v", extractTerms(rCond), want)
	}

	rPred, err := Analyze(AnalyzeRequest{
		Text:      []string{"Vorsprung Durch Technik"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{
				"type": "predicate_token_filter",
				"script": map[string]any{
					"source": "token.term.length() > 5",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("predicate_token_filter failed: %v", err)
	}
	if want := []string{"Vorsprung", "Technik"}; !reflect.DeepEqual(extractTerms(rPred), want) {
		t.Fatalf("predicate_token_filter = %v, want %v", extractTerms(rPred), want)
	}

	// Custom EvalPredicateScript hook mutating token.term
	rCustomHook, err := Analyze(AnalyzeRequest{
		Text:      []string{"alpha beta"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{
				"type":   "predicate_token_filter",
				"script": map[string]any{"source": "custom"},
			},
		},
		Options: Options{
			EvalPredicateScript: func(script map[string]any, tok *TokenContext) (bool, error) {
				tok.Term = "[" + tok.Term + "]"
				return tok.Position == 0, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("custom EvalPredicateScript failed: %v", err)
	}
	if want := []string{"[alpha]"}; !reflect.DeepEqual(extractTerms(rCustomHook), want) {
		t.Fatalf("custom EvalPredicateScript = %v, want %v", extractTerms(rCustomHook), want)
	}

	// Mutable token.term in DefaultEvalPredicateScript
	rMutDefault, err := Analyze(AnalyzeRequest{
		Text:      []string{"alpha beta"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{
				"type": "predicate_token_filter",
				"script": map[string]any{
					"source": `token.term += params.sfx; return token.term.startsWith("alpha");`,
					"params": map[string]any{"sfx": "!"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("mutable default script failed: %v", err)
	}
	if want := []string{"alpha!"}; !reflect.DeepEqual(extractTerms(rMutDefault), want) {
		t.Fatalf("mutable default script = %v, want %v", extractTerms(rMutDefault), want)
	}

	// 2. Normalizer validation (ad-hoc & named) + NormalizeTerm
	_, err = Analyze(AnalyzeRequest{
		Text:    []string{"ABc"},
		Explain: true,
		Filter:  []any{"word_delimiter"},
	})
	if ae, ok := AsAnalysisError(err); !ok || ae.Reason != "Custom normalizer may not use filter [word_delimiter]" {
		t.Fatalf("expected custom normalizer error, got: %v", err)
	}

	rAdhocNorm, err := Analyze(AnalyzeRequest{
		Text:    []string{"ABc"},
		Explain: true,
		Filter:  []any{"lowercase"},
	})
	if err != nil {
		t.Fatalf("ad-hoc normalizer failed: %v", err)
	}
	if rAdhocNorm.Detail.Tokenizer.Name != "keyword" || rAdhocNorm.Detail.TokenFilters[0].Tokens[0].Token != "abc" {
		t.Fatalf("unexpected ad-hoc normalizer detail: %+v", rAdhocNorm.Detail)
	}

	normCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"index.analyze.max_token_count":                   3,
		"index.analysis.analyzer.default.type":            "simple",
		"index.analysis.analyzer.default_search.type":     "german",
		"index.analysis.normalizer.zero_strip.type":       "custom",
		"index.analysis.normalizer.zero_strip.filter.0":   "replace_zeros",
		"index.analysis.filter.replace_zeros.type":        "pattern_replace",
		"index.analysis.filter.replace_zeros.pattern":     "0+",
		"index.analysis.filter.replace_zeros.replacement": "",
		"index.analysis.filter.replace_zeros.all":         true,
		"index.analysis.filter.dyn_syn.type":              "synonym_graph",
		"index.analysis.filter.dyn_syn.synonyms_set":      "set1",
		"index.analysis.analyzer.syn_search.tokenizer":    "standard",
		"index.analysis.analyzer.syn_search.filter.0":     "lowercase",
		"index.analysis.analyzer.syn_search.filter.1":     "dyn_syn",
	}, Options{})
	if err != nil {
		t.Fatalf("dotted ParseIndexAnalysisConfig failed: %v", err)
	}

	normed, err := NormalizeTerm("000000111", "zero_strip", normCfg, Options{})
	if err != nil || normed != "111" {
		t.Fatalf("NormalizeTerm = %q (err=%v), want 111", normed, err)
	}

	// 3. index.analyze.max_token_count enforcement (20_analyze_limit.yml)
	_, err = Analyze(AnalyzeRequest{
		Text:     []string{"This should fail as it exceeds limit"},
		Analyzer: "standard",
		Config:   normCfg,
	})
	wantLimitErr := "The number of tokens produced by calling _analyze has exceeded the allowed maximum of [3]. This limit can be set by changing the [index.analyze.max_token_count] index level setting."
	if err == nil || err.Error() != wantLimitErr {
		t.Fatalf("expected exact max_token_count error, got: %v", err)
	}

	// 4. Default / DefaultSearch analyzer resolution + Synonyms Set live reload + AnalyzeForQuery
	if got := normCfg.ResolveIndexAnalyzer(""); got != "default" {
		t.Fatalf("ResolveIndexAnalyzer = %q, want default", got)
	}
	if got := normCfg.ResolveSearchAnalyzer("", ""); got != "default_search" {
		t.Fatalf("ResolveSearchAnalyzer = %q, want default_search", got)
	}
	if got := normCfg.UsesSynonymSet("set1"); !reflect.DeepEqual(got, []string{"syn_search"}) {
		t.Fatalf("UsesSynonymSet = %v, want [syn_search]", got)
	}
	missing := normCfg.MissingSynonymSets(func(setID string) ([]string, error) {
		return nil, errors.New("not found")
	})
	if !reflect.DeepEqual(missing, []string{"set1"}) {
		t.Fatalf("MissingSynonymSets = %v, want [set1]", missing)
	}

	currentRules := []string{"wtf, what the fudge", "foo, bar baz"}
	opts := Options{
		ResolveSynonymSet: func(setID string) ([]string, error) {
			if setID == "set1" {
				return currentRules, nil
			}
			return nil, errors.New("missing set")
		},
	}

	// AnalyzeForQuery enforces index.analyze.max_token_count identically to Analyze!
	if _, err := AnalyzeForQuery("three what the fudge foo", "syn_search", normCfg, opts); err == nil || err.Error() != wantLimitErr {
		t.Fatalf("expected AnalyzeForQuery to enforce max_token_count=3, got: %v", err)
	}

	queryCfg := *normCfg
	queryCfg.MaxTokenCount = DefaultMaxTokenCount
	qGraph, err := AnalyzeForQuery("three what the fudge foo", "syn_search", &queryCfg, opts)
	if err != nil {
		t.Fatalf("AnalyzeForQuery failed: %v", err)
	}
	if !qGraph.HasGraphSpans || len(qGraph.Segments) != 3 {
		t.Fatalf("expected 3 articulation-point segments with graph spans, got %+v", qGraph.Segments)
	}
	phrasePaths := qGraph.PhrasePaths(16)
	if len(phrasePaths) != 4 {
		t.Fatalf("expected 4 phrase paths (1 x 2 x 2), got %v", phrasePaths)
	}

	// Mutate synonym set rules dynamically (simulating PUT _synonyms/set1) without recompiling queryCfg!
	currentRules = []string{"hello, salute"}
	qGraphReloaded, err := AnalyzeForQuery("salute", "syn_search", &queryCfg, opts)
	if err != nil {
		t.Fatalf("reloaded AnalyzeForQuery failed: %v", err)
	}
	if want := []string{"hello", "salute"}; !reflect.DeepEqual(qGraphReloaded.Positions[0].Terms, want) {
		t.Fatalf("reloaded terms = %v, want %v", qGraphReloaded.Positions[0].Terms, want)
	}

	// 5. ClusterAnalysisStats (10_analysis_stats.yml & 20_analysis_stats_synonyms.yml)
	statsCfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"char_filter": map[string]any{
				"c": map[string]any{"type": "mapping", "mappings": []any{"a => b"}},
			},
			"tokenizer": map[string]any{
				"tok": map[string]any{"type": "pattern", "pattern": ","},
			},
			"filter": map[string]any{
				"st":   map[string]any{"type": "stop", "stopwords": []any{"a"}},
				"syn1": map[string]any{"type": "synonym", "synonyms": []any{"foo bar", "bar => baz"}},
				"syn2": map[string]any{"type": "synonym_graph", "synonyms_set": "set1"},
			},
			"analyzer": map[string]any{
				"en":   map[string]any{"type": "standard", "stopwords": "_english_"},
				"cust": map[string]any{"char_filter": []any{"html_strip"}, "tokenizer": "keyword", "filter": []any{"trim"}},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("statsCfg failed: %v", err)
	}
	stats := ComputeClusterAnalysisStats([]IndexStatsInput{
		{Config: statsCfg, FieldAnalyzerRefsList: []string{"french", "spanish", "german", "french"}},
	})
	if len(stats.CharFilterTypes) != 1 || stats.CharFilterTypes[0].Name != "mapping" ||
		len(stats.BuiltInAnalyzers) != 3 || stats.Synonyms["inline"].Count != 1 || stats.Synonyms["sets"].Count != 1 {
		b, _ := json.Marshal(stats)
		t.Fatalf("unexpected ClusterAnalysisStats: %s", string(b))
	}
}
