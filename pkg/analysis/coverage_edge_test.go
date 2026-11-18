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

func TestDeepStemmerAndUnicodeNormalizationBranches(t *testing.T) {
	// Exercise Porter 1980 Steps 1-5, KStem, Light/Minimal English, Possessive English,
	// French, Dutch, Czech palatalisation, Greek, Irish, Turkish consonant devoicing, etc.
	stemCases := []struct {
		lang  string
		input string
		want  []string
	}{
		{"porter", "agreed plastered hopping filing relational conditional triplicate electriciti revival adoption controlling ponies caresses", []string{"agre", "plaster", "hop", "file", "relat", "condit", "triplic", "electr", "reviv", "adopt", "control", "poni", "caress"}},
		{"kstem", "mice children boxes flies running baked", []string{"mouse", "child", "box", "fly", "run", "bak"}},
		{"light_english", "ponies boxes cats jumping played quickly", []string{"pony", "box", "cat", "jump", "play", "quick"}},
		{"minimal_english", "ponies boxes cats status class", []string{"pony", "box", "cat", "status", "class"}},
		{"possessive_english", "king's queens\u2019S dogs", []string{"king", "queens", "dogs"}},
		{"french", "châteaux eaux nationalités", []string{"château", "eau", "national"}},
		{"dutch", "vrijheden pakken bomen huisse", []string{"vrijheid", "pak", "bom", "huis"}},
		{"czech", "angličtí čeští muži", []string{"anglick", "česk", "muž"}},
		{"greek", "Άνθρωπων Έλληνας Ήλιος Ίδιος Όνομα Ύψος Ώρα", []string{"ανθρωπ", "ελλην", "ηλι", "ιδι", "ονομα", "υψοσ", "ωρα"}},
		{"irish", "d'fhear m'athair siopadóireachta", []string{"fhear", "athair", "siopadóir"}},
		{"turkish", "kitabı kanadı ağacı", []string{"kitap", "kanat", "ağaç"}},
		{"bulgarian", "градовете", []string{"град"}},
		{"finnish", "talossani", []string{"talo"}},
		{"hungarian", "embereknek", []string{"emberek"}},
		{"italian", "nazionali", []string{"nazional"}},
	}
	for _, tc := range stemCases {
		r, err := Analyze(AnalyzeRequest{
			Text:      []string{tc.input},
			Tokenizer: "whitespace",
			Filter:    []any{map[string]any{"type": "stemmer", "language": tc.lang}},
		})
		if err != nil {
			t.Fatalf("stemmer(%s) failed: %v", tc.lang, err)
		}
		if !reflect.DeepEqual(extractTerms(r), tc.want) {
			t.Fatalf("stemmer(%s) = %v, want %v", tc.lang, extractTerms(r), tc.want)
		}
	}

	// Deep normalization branches: German, Scandinavian, Bengali, Hindi, Persian, Sorani, Elision, Classic, DecimalDigit
	normPairs := []struct {
		filter any
		input  string
		want   string
	}{
		{"german_normalization", "aether oel ueber schule quer Äpfel Öl Übung", "ather ol uber schule quer Apfel Ol Ubung"},
		{"scandinavian_normalization", "Ä Ö AA AE AO OE ao", "Æ Ø Å Æ Å Ø å"},
		{"scandinavian_folding", "Å Ä Æ Ö Ø aa ae ao oe AA OE", "A A A O O a a a o A O"},
		{"bengali_normalization", "ড় ঢ় য় ঈ ঊ ৎ ড\u09bc ঢ\u09bc", "র র য ই উ ত র র"},
		{"hindi_normalization", "क़ ख़ ग़ ज़ ड़ ढ़ फ़ य़ ई ऊ ए ओ कू कृ कॅ कॉ", "क ख ग ज ड ढ फ य इ उ ए ओ कु कर के को"},
		{"persian_normalization", "کتابۀ من", "كتابه من"},
		{"sorani_normalization", "كوردستان هەولێر", "کوردستان ەەولێر"},
		{"decimal_digit", "٠١٢٣٤٥٦٧٨٩ ۰۱۲۳۴۵۶۷۸۹ ०१२३४५६७८९ ০১২৩৪৫৬৭৮৯ ０１２３", "0123456789 0123456789 0123456789 0123456789 0123"},
		{"elision", "l'avion d\u2019accord m'aime x'yz", "avion d\u2019accord m'aime x'yz"}, // keyword token: only prefix before first apostrophe checked!
		{map[string]any{"type": "elision", "articles": []any{"l", "d"}, "articles_case": false}, "L'Avion", "L'Avion"},
		{map[string]any{"type": "elision", "articles": []any{"l", "d"}, "articles_case": true}, "D\u2019Avion", "Avion"},
	}
	for _, np := range normPairs {
		r, err := Analyze(AnalyzeRequest{
			Text:      []string{np.input},
			Tokenizer: "keyword",
			Filter:    []any{np.filter},
		})
		if err != nil {
			t.Fatalf("norm %v failed: %v", np.filter, err)
		}
		if r.Tokens[0].Token != np.want {
			t.Fatalf("norm %v(%q) = %q, want %q", np.filter, np.input, r.Tokens[0].Token, np.want)
		}
	}
}

func TestStandardClassicThaiPathHierarchyAndCharFilterEdgeCases(t *testing.T) {
	// Standard tokenizer with apostrophes, decimals, commas, underscores, Katakana, Hangul, Southeast Asian, Emoji ZWJ
	rStd, err := Analyze(AnalyzeRequest{
		Text:      []string{"don't l'avion a.b 3.14 1,000.50 _var カタカナー 한국어 ภาษา 👨‍👩‍👧"},
		Tokenizer: map[string]any{"type": "standard", "max_token_length": 20},
	})
	if err != nil {
		t.Fatalf("standard edge cases failed: %v", err)
	}
	wantStd := []string{"don't", "l'avion", "a.b", "3.14", "1,000.50", "_var", "カタカナー", "한국어", "ภาษา", "👨‍👩‍👧"}
	if !reflect.DeepEqual(extractTerms(rStd), wantStd) {
		t.Fatalf("standard edge cases = %v, want %v", extractTerms(rStd), wantStd)
	}

	// Classic tokenizer with emails, hosts, numbers, CJK, acronyms
	rCls, err := Analyze(AnalyzeRequest{
		Text:      []string{"ops@corp.io api.corp.io 192.168.1.1 R2-D2 中 I.B.M. Bob's"},
		Tokenizer: "classic",
		Filter:    []any{"classic"},
	})
	if err != nil {
		t.Fatalf("classic edge cases failed: %v", err)
	}
	wantCls := []string{"ops@corp.io", "api.corp.io", "192.168.1.1", "R2-D2", "中", "IBM", "Bob"}
	if !reflect.DeepEqual(extractTerms(rCls), wantCls) {
		t.Fatalf("classic edge cases = %v, want %v", extractTerms(rCls), wantCls)
	}

	// Thai tokenizer fallback syllable segmentation (leading vowel เ + non-dict cluster + dict word)
	rThai, err := Analyze(AnalyzeRequest{
		Text:      []string{"เกรียงไกรไปโรงเรียน 99"},
		Tokenizer: "thai",
	})
	if err != nil {
		t.Fatalf("thai fallback failed: %v", err)
	}
	if len(rThai.Tokens) < 3 || rThai.Tokens[len(rThai.Tokens)-1].Token != "99" {
		t.Fatalf("unexpected thai tokens: %v", extractTerms(rThai))
	}

	// PathHierarchy leading/trailing slash and forward skip
	rPH, err := Analyze(AnalyzeRequest{
		Text:      []string{"/usr/local/bin/"},
		Tokenizer: map[string]any{"type": "path_hierarchy", "skip": 1},
	})
	if err != nil {
		t.Fatalf("path_hierarchy skip=1 failed: %v", err)
	}
	if want := []string{"/local", "/local/bin", "/local/bin/"}; !reflect.DeepEqual(extractTerms(rPH), want) {
		t.Fatalf("path_hierarchy skip=1 = %v, want %v", extractTerms(rPH), want)
	}

	// NGram custom_token_chars + punctuation + symbol + whitespace
	rNGCust, err := Analyze(AnalyzeRequest{
		Text: []string{"a+b! c_d"},
		Tokenizer: map[string]any{
			"type":               "edge_ngram",
			"min":                1,
			"max":                2,
			"token_chars":        "punctuation,symbol,whitespace,custom",
			"custom_token_chars": "a",
		},
	})
	if err != nil {
		t.Fatalf("edge_ngram custom_token_chars failed: %v", err)
	}
	if len(rNGCust.Tokens) == 0 || rNGCust.Tokens[0].Token != "a" {
		t.Fatalf("unexpected custom_token_chars tokens: %v", extractTerms(rNGCust))
	}

	// CharGroup with punctuation, symbol, letter, cjk, \n, \t
	rCG2, err := Analyze(AnalyzeRequest{
		Text: []string{"12!34$56汉78\n90"},
		Tokenizer: map[string]any{
			"type":              "char_group",
			"tokenize_on_chars": []any{"punctuation", "symbol", "cjk", `\n`},
		},
	})
	if err != nil {
		t.Fatalf("char_group 2 failed: %v", err)
	}
	if want := []string{"12", "34", "56", "78", "90"}; !reflect.DeepEqual(extractTerms(rCG2), want) {
		t.Fatalf("char_group 2 = %v, want %v", extractTerms(rCG2), want)
	}

	// HTMLStrip with <!DOCTYPE>, <?xml?>, quoted '>' in attribute, unclosed '<', and Mapping escapes
	rDocType, err := Analyze(AnalyzeRequest{
		Text:      []string{`<!DOCTYPE html><?xml version="1.0"?><a title="x>y">ok</a> 2 < 3`},
		Tokenizer: "whitespace",
		CharFilter: []any{
			"html_strip",
			map[string]any{
				"type":     "mapping",
				"mappings": []any{`\u003c => LT`, `\n => \t`, `\r => \b`, `x => \f`},
			},
		},
	})
	if err != nil {
		t.Fatalf("doctype html_strip + mapping escapes failed: %v", err)
	}
	if want := []string{"ok", "2", "LT", "3"}; !reflect.DeepEqual(extractTerms(rDocType), want) {
		t.Fatalf("doctype html_strip = %v, want %v", extractTerms(rDocType), want)
	}

	// PatternReplace char_filter with flags & escaped \$ / \\ / $0
	rPR2, err := Analyze(AnalyzeRequest{
		Text:      []string{"FOO\nBAR"},
		Tokenizer: "keyword",
		CharFilter: []any{
			map[string]any{
				"type":        "pattern_replace",
				"pattern":     "foo.bar",
				"flags":       "CASE_INSENSITIVE|MULTILINE|DOTALL",
				"replacement": `\$[$0]\\`,
			},
		},
	})
	if err != nil {
		t.Fatalf("pattern_replace flags failed: %v", err)
	}
	if rPR2.Tokens[0].Token != `$[FOO`+"\n"+`BAR]\` {
		t.Fatalf("unexpected pattern_replace output: %q", rPR2.Tokens[0].Token)
	}
}

func TestScriptEvaluatorCompoundFiltersAndResourcePathHooks(t *testing.T) {
	// 1. Exercise DefaultEvalPredicateScript operators, methods, assignments, and error handling
	tok := &TokenContext{
		Term:              "HelloWorld",
		Position:          2,
		PositionIncrement: 1,
		PositionLength:    1,
		StartOffset:       5,
		EndOffset:         15,
		Type:              "<ALPHANUM>",
		Keyword:           false,
	}
	ok, err := DefaultEvalPredicateScript(map[string]any{
		"source": `!token.keyword && -token.position < 0 && (token.position + 1 - 1 == 2) && token.position <= 2 && token.getTerm().toLowerCase().endsWith("world") && token.term.toUpperCase().contains("HELLO") && !token.term.isEmpty() && token.term.equals("HelloWorld") && params["mode"] != "skip"`,
		"params": map[string]any{"mode": "run"},
	}, tok)
	if err != nil || !ok {
		t.Fatalf("complex DefaultEvalPredicateScript failed: ok=%v err=%v", ok, err)
	}

	ok2, err := DefaultEvalPredicateScript(map[string]any{
		"source": `token.term = "rewritten_" + "tok\n\t\""; return token.term.length > 5 || false;`,
	}, tok)
	if err != nil || !ok2 || !strings.HasPrefix(tok.Term, "rewritten_tok") {
		t.Fatalf("assignment script failed: ok=%v err=%v term=%q", ok2, err, tok.Term)
	}

	for _, badScript := range []map[string]any{
		nil,
		{"source": ""},
		{"source": "123"},
		{"source": "token.unknownProp == 1"},
		{"source": "unknownVar == 1"},
		{"source": `"unterminated`},
		{"source": `(true`},
	} {
		if _, err := DefaultEvalPredicateScript(badScript, tok); err == nil {
			t.Fatalf("expected error for badScript %v", badScript)
		}
	}
	if _, err := DefaultEvalPredicateScript(map[string]any{"source": "true"}, nil); err == nil {
		t.Fatalf("expected error for nil TokenContext")
	}

	// 2. Resource path resolution via Options.ResolveResourcePath + compound filter variants
	files := map[string][]string{
		"maps.txt":     {"& => and"},
		"stops.txt":    {"a | article comment", "# comment", "the"},
		"arts.txt":     {"l"},
		"override.txt": {"ran\trun"},
		"kw.txt":       {"keepraw"},
		"keep.txt":     {"run", "and", "keepraw", "html", "parser", "htmlparser", "12"},
		"prot.txt":     {"keepraw"},
		"types.txt":    {"@ => DIGIT"},
		"words.txt":    {"html", "parser"},
		"syns.txt":     {"and, plus"},
	}
	resOpts := Options{
		ResolveResourcePath: func(settingKey, path string) ([]string, error) {
			if lines, exists := files[path]; exists {
				return lines, nil
			}
			return nil, errors.New("file missing: " + path)
		},
	}

	cfg, err := ParseIndexAnalysisConfig(map[string]any{
		"index": map[string]any{
			"max_ngram_diff":   int64(5),
			"max_shingle_diff": float64(4),
			"analyze": map[string]any{
				"max_token_count": "5000",
			},
			"analysis": map[string]any{
				"char_filter": map[string]any{
					"cf_map": map[string]any{"type": "mapping", "mappings_path": "maps.txt"},
					"cf_zw":  "zero_width_spaces",
				},
				"tokenizer": map[string]any{
					"tok_ws": "whitespace",
				},
				"token_filter": map[string]any{
					"f_el":   map[string]any{"type": "elision", "articles_path": "arts.txt"},
					"f_stop": map[string]any{"type": "stop", "stopwords_path": "stops.txt", "ignore_case": "true"},
					"f_so":   map[string]any{"type": "stemmer_override", "rules_path": "override.txt"},
					"f_km":   map[string]any{"type": "keyword_marker", "keywords_path": "kw.txt", "ignore_case": true},
					"f_wd": map[string]any{
						"type":                 "word_delimiter",
						"catenate_words":       true,
						"catenate_numbers":     true,
						"protected_words_path": "prot.txt",
						"type_table_path":      "types.txt",
					},
					"f_keep": map[string]any{"type": "keep_words", "keep_words_path": "keep.txt", "keep_words_case": true},
					"f_dec":  map[string]any{"type": "dictionary_decompounder", "word_list_path": "words.txt", "only_longest_match": true},
					"f_syn":  map[string]any{"type": "synonym", "synonyms_path": "syns.txt", "expand": false, "tokenizer": "whitespace"},
				},
				"normalizer": map[string]any{
					"lc_builtin": map[string]any{"type": "lowercase"},
					"my_norm":    map[string]any{"char_filter": "cf_zw", "filter": []string{"lowercase", "trim"}},
				},
				"analyzer": map[string]any{
					"full_chain": map[string]any{
						"char_filter": []any{"cf_map", "cf_zw"},
						"tokenizer":   "tok_ws",
						"filter":      []any{"f_el", "f_stop", "f_so", "f_km", "f_wd", "f_keep", "f_dec", "f_syn"},
					},
				},
			},
		},
	}, resOpts)
	if err != nil {
		t.Fatalf("ParseIndexAnalysisConfig with resource paths failed: %v", err)
	}

	if !cfg.HasAnalyzer("full_chain") || !cfg.HasAnalyzer("english") || cfg.HasAnalyzer("nonexistent") {
		t.Fatalf("unexpected HasAnalyzer results")
	}
	if !cfg.HasNormalizer("my_norm") || !cfg.HasNormalizer("lowercase") || cfg.HasNormalizer("nonexistent") {
		t.Fatalf("unexpected HasNormalizer results")
	}
	if cfg.ResolveIndexAnalyzer("english") != "english" || cfg.ResolveIndexAnalyzer("") != "standard" {
		t.Fatalf("unexpected ResolveIndexAnalyzer results")
	}
	if cfg.ResolveSearchAnalyzer("english", "simple") != "simple" || cfg.ResolveSearchAnalyzer("english", "") != "english" || cfg.ResolveSearchAnalyzer("", "") != "standard" {
		t.Fatalf("unexpected ResolveSearchAnalyzer results")
	}

	rFull, err := Analyze(AnalyzeRequest{
		Text:     []string{"the ran & HTML-Parser's 1@2 keepraw"},
		Analyzer: "full_chain",
		Config:   cfg,
		Options:  resOpts,
	})
	if err != nil {
		t.Fatalf("Analyze(full_chain) failed: %v", err)
	}
	if len(rFull.Tokens) == 0 {
		t.Fatalf("expected non-empty tokens from full_chain")
	}

	// Non-explain JSON Marshal check + Attributes filter check + Named Normalizer Analyze check
	stdJSON, err := json.Marshal(rFull)
	if err != nil || !strings.Contains(string(stdJSON), `"tokens":[`) {
		t.Fatalf("unexpected non-explain JSON: %s (err=%v)", string(stdJSON), err)
	}

	rNorm, err := Analyze(AnalyzeRequest{
		Text:       []string{"  AB\u200cCD  "},
		Normalizer: "my_norm",
		Config:     cfg,
		Attributes: []string{"bytes", "keyword"},
	})
	if err != nil || rNorm.Tokens[0].Token != "ab cd" || rNorm.Tokens[0].Bytes == "" || rNorm.Tokens[0].Keyword == nil {
		t.Fatalf("unexpected normalizer + attributes output: %+v (err=%v)", rNorm, err)
	}

	for _, bn := range []string{"lowercase", "uppercase", "asciifolding", "none", ""} {
		if _, err := NormalizeTerm("Café", bn, cfg, Options{}); err != nil {
			t.Fatalf("NormalizeTerm(%q) failed: %v", bn, err)
		}
	}
	if v, err := NormalizeTerm("", "lowercase", cfg, Options{}); err != nil || v != "" {
		t.Fatalf("NormalizeTerm empty failed: %q %v", v, err)
	}
	if _, err := NormalizeTerm("x", "unknown_norm", cfg, Options{}); err == nil {
		t.Fatalf("expected error for unknown normalizer")
	}

	// 3. NGram/EdgeNGram filter preserve_original, Shingle filler_token & output_unigrams_if_no_shingles,
	// MinHash multi-hash + long strings + emoji UTF-16 surrogates, DelimitedPayload int
	rNGFilt, err := Analyze(AnalyzeRequest{
		Text:      []string{"a abcdef"},
		Tokenizer: "whitespace",
		Config:    cfg,
		Filter: []any{
			map[string]any{"type": "ngram", "min_gram": 2, "max_gram": 3, "preserve_original": true},
			map[string]any{"type": "edge_ngram", "min_gram": 2, "max_gram": 2, "preserve_original": true},
		},
	})
	if err != nil || len(rNGFilt.Tokens) < 4 {
		t.Fatalf("ngram/edge_ngram preserve_original failed: %v %v", rNGFilt, err)
	}

	rShingleGap, err := Analyze(AnalyzeRequest{
		Text:      []string{"cat the dog"},
		Tokenizer: "whitespace",
		Filter: []any{
			"stop",
			map[string]any{
				"type":                           "shingle",
				"min_shingle_size":               2,
				"max_shingle_size":               3,
				"output_unigrams":                true,
				"output_unigrams_if_no_shingles": true,
				"filler_token":                   "_",
			},
		},
	})
	if err != nil || !reflect.DeepEqual(extractTerms(rShingleGap), []string{"cat", "cat _", "cat _ dog", "_ dog", "dog"}) {
		t.Fatalf("shingle with stop gap = %v (err=%v)", extractTerms(rShingleGap), err)
	}

	rShingleFallback, err := Analyze(AnalyzeRequest{
		Text:      []string{"solo"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{
				"type":                           "shingle",
				"output_unigrams":                false,
				"output_unigrams_if_no_shingles": true,
			},
		},
	})
	if err != nil || !reflect.DeepEqual(extractTerms(rShingleFallback), []string{"solo"}) {
		t.Fatalf("shingle fallback = %v (err=%v)", rShingleFallback, err)
	}

	rMH2, err := Analyze(AnalyzeRequest{
		Text:      []string{"a ab abc abcd abcde abcdef abcdefg abcdefgh abcdefghi abcdefghij abcdefghijk abcdefghijkl abcdefghijklm abcdefghijklmn abcdefghijklmno abcdefghijklmnop 😀"},
		Tokenizer: "whitespace",
		Filter: []any{
			map[string]any{
				"type":          "min_hash",
				"hash_count":    2,
				"bucket_count":  8,
				"hash_set_size": 2,
				"with_rotation": false,
			},
			map[string]any{"type": "delimited_payload", "encoding": "int"},
		},
	})
	if err != nil || len(rMH2.Tokens) == 0 {
		t.Fatalf("min_hash multi-tail failed: %v %v", rMH2, err)
	}

	rPayInt, err := Analyze(AnalyzeRequest{
		Text:      []string{"tok|42 neg|-7"},
		Tokenizer: "whitespace",
		Filter:    []any{map[string]any{"type": "delimited_payload", "encoding": "int"}},
		Explain:   true,
	})
	if err != nil || rPayInt.Detail.TokenFilters[0].Tokens[0].Payload != "0000002a" {
		t.Fatalf("delimited_payload int failed: %+v %v", rPayInt, err)
	}

	// Empty QueryTokenGraph & Analyze empty Text & Error helpers
	emptyGraph, err := AnalyzeForQuery("the and", "stop", cfg, Options{})
	if err != nil || !emptyGraph.IsEmpty() || emptyGraph.PhrasePaths(10) != nil {
		t.Fatalf("expected empty QueryTokenGraph, got %+v (err=%v)", emptyGraph, err)
	}
	emptyResp, err := Analyze(AnalyzeRequest{Explain: true})
	if err != nil || len(emptyResp.Tokens) != 0 || emptyResp.Detail == nil {
		t.Fatalf("expected empty Analyze response, got %+v (err=%v)", emptyResp, err)
	}
	var nilAE *AnalysisError
	if nilAE.Error() != "" {
		t.Fatalf("expected empty error string on nil *AnalysisError")
	}
	if _, ok := AsAnalysisError(nil); ok {
		t.Fatalf("expected false on AsAnalysisError(nil)")
	}
	if _, ok := AsAnalysisError(errors.New("plain")); ok {
		t.Fatalf("expected false on plain error")
	}

	// Validation error branches
	if _, err := Analyze(AnalyzeRequest{Analyzer: "standard", Tokenizer: "whitespace"}); err == nil {
		t.Fatalf("expected conflict error when combining analyzer and tokenizer")
	}
	if _, err := Analyze(AnalyzeRequest{Normalizer: "lowercase", Filter: []any{"trim"}}); err == nil {
		t.Fatalf("expected conflict error when combining normalizer and filter")
	}
	if _, err := Analyze(AnalyzeRequest{Analyzer: "does_not_exist"}); err == nil {
		t.Fatalf("expected error for unknown analyzer")
	}
	if _, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"normalizer": map[string]any{
				"bad_norm": map[string]any{"tokenizer": "keyword", "filter": []any{"lowercase"}},
			},
		},
	}, Options{}); err == nil || !strings.Contains(err.Error(), "may not use a tokenizer") {
		t.Fatalf("expected normalizer tokenizer rejection, got: %v", err)
	}
}

func TestValidationErrorsAndSynonymModes(t *testing.T) {
	// Synonym modes: custom analyzer on synonym filter, lenient: true, flat multi-word lhs => rhs
	cfg, err := ParseIndexAnalysisConfig(map[string]any{
		"analysis": map[string]any{
			"filter": map[string]any{
				"syn_lenient": map[string]any{
					"type":     "synonym",
					"analyzer": "simple",
					"lenient":  true,
					"synonyms": []any{
						"bad =>",
						"123 => 456", // simple analyzer drops digits -> lenient skips!
						"big apple => new york city",
						"ny\\, usa => new york",
					},
				},
			},
			"analyzer": map[string]any{
				"syn_flat_an": map[string]any{
					"tokenizer": "standard",
					"filter":    []any{"lowercase", "syn_lenient"},
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("syn_lenient config failed: %v", err)
	}
	rSyn, err := Analyze(AnalyzeRequest{
		Text:     []string{"visit big apple soon"},
		Analyzer: "syn_flat_an",
		Config:   cfg,
	})
	if err != nil {
		t.Fatalf("Analyze(syn_flat_an) failed: %v", err)
	}
	if want := []string{"visit", "new", "york", "city", "soon"}; !reflect.DeepEqual(extractTerms(rSyn), want) {
		t.Fatalf("syn_flat_an = %v, want %v", extractTerms(rSyn), want)
	}

	// Table of invalid component configs that must return illegal_argument_exception
	invalidSettings := []map[string]any{
		{"index.analyze.max_token_count": 0},
		{"index.max_ngram_diff": -1},
		{"index.max_shingle_diff": -1},
		{"analysis": map[string]any{"char_filter": map[string]any{"x": map[string]any{}}}},
		{"analysis": map[string]any{"char_filter": map[string]any{"x": map[string]any{"type": "unknown_cf"}}}},
		{"analysis": map[string]any{"char_filter": map[string]any{"x": map[string]any{"type": "mapping", "mappings": []any{"no_arrow"}}}}},
		{"analysis": map[string]any{"char_filter": map[string]any{"x": map[string]any{"type": "pattern_replace"}}}},
		{"analysis": map[string]any{"char_filter": map[string]any{"x": map[string]any{"type": "pattern_replace", "pattern": "(", "flags": "LITERAL"}}}}, // valid literal? wait: test BAD flag instead:
		{"analysis": map[string]any{"char_filter": map[string]any{"x": map[string]any{"type": "pattern_replace", "pattern": "a", "flags": "BAD_FLAG"}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"x": map[string]any{}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"x": map[string]any{"type": "unknown_tok"}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"x": map[string]any{"type": "standard", "max_token_length": 0}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"x": map[string]any{"type": "ngram", "min_gram": 4, "max_gram": 2}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"x": map[string]any{"type": "ngram", "token_chars": "unknown_cls"}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"x": map[string]any{"type": "char_group", "tokenize_on_chars": []any{"too_long"}}}}},
		{"analysis": map[string]any{"tokenizer": map[string]any{"x": map[string]any{"type": "path_hierarchy", "delimiter": "//"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "unknown_f"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "lowercase", "language": "klingon"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "cjk_bigram", "ignored_scripts": []any{"latin"}}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "stop", "stopwords": "_martian_"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "length", "min": 10, "max": 2}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "stemmer", "language": "klingon"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "shingle", "min_shingle_size": 2, "max_shingle_size": 10}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "ngram", "min_gram": 1, "max_gram": 5}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "synonym"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "common_grams"}}}},
		{"analysis": map[string]any{"filter": map[string]any{"x": map[string]any{"type": "dictionary_decompounder"}}}},
		{"analysis": map[string]any{"analyzer": map[string]any{"x": map[string]any{"type": "custom"}}}},
		{"analysis": map[string]any{"normalizer": map[string]any{"x": map[string]any{"type": "unknown_norm_type"}}}},
	}
	for idx, s := range invalidSettings {
		// Note index 7 has LITERAL "(" which IS valid, skip checking error on LITERAL "(" and test LITERAL positively!
		if idx == 7 {
			if _, err := ParseIndexAnalysisConfig(s, Options{}); err != nil {
				t.Fatalf("expected LITERAL '(' to succeed, got: %v", err)
			}
			continue
		}
		_, err := ParseIndexAnalysisConfig(s, Options{})
		if ae, ok := AsAnalysisError(err); !ok || ae.ErrType != "illegal_argument_exception" {
			t.Fatalf("case %d (%v): expected illegal_argument_exception, got: %v", idx, s, err)
		}
	}
}
