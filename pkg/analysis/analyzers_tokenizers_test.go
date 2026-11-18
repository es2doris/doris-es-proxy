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
	"reflect"
	"strings"
	"testing"
)

func extractTerms(resp *AnalyzeResponse) []string {
	out := make([]string, len(resp.Tokens))
	for i, t := range resp.Tokens {
		out[i] = t.Token
	}
	return out
}

func TestBuiltInAndLanguageAnalyzers(t *testing.T) {
	cases := []struct {
		analyzer string
		text     string
		want     []string
	}{
		{analyzer: "standard", text: "Foo Bar!", want: []string{"foo", "bar"}},
		{analyzer: "simple", text: "Foo-Bar 123 Baz", want: []string{"foo", "bar", "baz"}},
		{analyzer: "whitespace", text: "Foo Bar!", want: []string{"Foo", "Bar!"}},
		{analyzer: "stop", text: "The Quick and the Dead", want: []string{"quick", "dead"}},
		{analyzer: "keyword", text: "Foo Bar!", want: []string{"Foo Bar!"}},
		{analyzer: "pattern", text: "foo,bar;baz", want: []string{"foo", "bar", "baz"}},
		{analyzer: "fingerprint", text: "A1 B2 A1 D4 C3", want: []string{"a1 b2 c3 d4"}},
		{analyzer: "classic", text: "The U.S.A. Brown-Fox's", want: []string{"usa", "brown", "fox"}},
		{analyzer: "snowball", text: "the brown foxes", want: []string{"brown", "fox"}},
		{analyzer: "chinese", text: "only for old indices", want: []string{"only", "old", "indices"}},
		{analyzer: "cjk", text: "多くの", want: []string{"多く", "くの"}},
		{analyzer: "arabic", text: "كبيرة", want: []string{"كبير"}},
		{analyzer: "armenian", text: "արծիվ", want: []string{"արծ"}},
		{analyzer: "basque", text: "zaldiak", want: []string{"zaldi"}},
		{analyzer: "bengali", text: "বাড়ী", want: []string{"বার"}},
		{analyzer: "brazilian", text: "boataria", want: []string{"boat"}},
		{analyzer: "bulgarian", text: "градове", want: []string{"град"}},
		{analyzer: "catalan", text: "llengües", want: []string{"llengu"}},
		{analyzer: "czech", text: "Pokud mluvime o volnem", want: []string{"mluvim", "voln"}},
		{analyzer: "danish", text: "undersøgelse", want: []string{"undersøg"}},
		{analyzer: "dutch", text: "lidstaten", want: []string{"lidstat"}},
		{analyzer: "english", text: "books", want: []string{"book"}},
		{analyzer: "estonian", text: "teadaolevalt", want: []string{"teadaole"}},
		{analyzer: "finnish", text: "edeltäjiinsä", want: []string{"edeltäj"}},
		{analyzer: "french", text: "sécuritaires", want: []string{"securitair"}},
		{analyzer: "galician", text: "corresponderá", want: []string{"correspond"}},
		{analyzer: "german", text: "Tischen", want: []string{"tisch"}},
		{analyzer: "greek", text: "Μία", want: []string{"μια"}},
		{analyzer: "hindi", text: "हिन्दी", want: []string{"हिंद"}},
		{analyzer: "hungarian", text: "babakocsi", want: []string{"babakocs"}},
		{analyzer: "indonesian", text: "peledakan", want: []string{"ledak"}},
		{analyzer: "irish", text: "siopadóireacht", want: []string{"siopadóir"}},
		{analyzer: "italian", text: "abbandonata", want: []string{"abbandonat"}},
		{analyzer: "latvian", text: "tirgiem", want: []string{"tirg"}},
		{analyzer: "lithuanian", text: "vaikų", want: []string{"vaik"}},
		{analyzer: "norwegian", text: "havnedistriktene", want: []string{"havnedistrikt"}},
		{analyzer: "persian", text: "می\u200cخورد", want: []string{"خورد"}},
		{analyzer: "portuguese", text: "quilométricas", want: []string{"quilometric"}},
		{analyzer: "romanian", text: "absenţa", want: []string{"absenţ"}},
		{analyzer: "russian", text: "Вместе с тем о", want: []string{"вмест"}},
		{analyzer: "serbian", text: "будите шампиони", want: []string{"sampion"}},
		{analyzer: "sorani", text: "پیاوە", want: []string{"پیاو"}},
		{analyzer: "spanish", text: "chicana", want: []string{"chican"}},
		{analyzer: "swedish", text: "jaktkarlarne", want: []string{"jaktkarl"}},
		{analyzer: "turkish", text: "ağacı", want: []string{"ağaç"}},
		{analyzer: "thai", text: "๑๒๓๔", want: []string{"1234"}},
	}

	for _, tc := range cases {
		t.Run(tc.analyzer, func(t *testing.T) {
			if !IsBuiltInAnalyzer(tc.analyzer) {
				t.Fatalf("expected IsBuiltInAnalyzer(%q) == true", tc.analyzer)
			}
			// Direct built-in invocation
			resp, err := Analyze(AnalyzeRequest{
				Text:     []string{tc.text},
				Analyzer: tc.analyzer,
				Explain:  true,
			})
			if err != nil {
				t.Fatalf("Analyze(%s) failed: %v", tc.analyzer, err)
			}
			got := extractTerms(resp)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Analyze(%s) = %v, want %v", tc.analyzer, got, tc.want)
			}
			if resp.Detail == nil || resp.Detail.CustomAnalyzer || resp.Detail.Analyzer == nil || resp.Detail.Analyzer.Name != tc.analyzer {
				t.Fatalf("unexpected explain detail for built-in analyzer %s: %+v", tc.analyzer, resp.Detail)
			}

			// Index-configured typed analyzer invocation
			cfg, err := ParseIndexAnalysisConfig(map[string]any{
				"settings": map[string]any{
					"analysis": map[string]any{
						"analyzer": map[string]any{
							"my_an": map[string]any{
								"type": tc.analyzer,
							},
						},
					},
				},
			}, Options{})
			if err != nil {
				t.Fatalf("ParseIndexAnalysisConfig(%s) failed: %v", tc.analyzer, err)
			}
			resp2, err := Analyze(AnalyzeRequest{
				Text:     []string{tc.text},
				Analyzer: "my_an",
				Config:   cfg,
			})
			if err != nil {
				t.Fatalf("Analyze(my_an -> %s) failed: %v", tc.analyzer, err)
			}
			if !reflect.DeepEqual(extractTerms(resp2), tc.want) {
				t.Fatalf("Analyze(my_an -> %s) = %v, want %v", tc.analyzer, extractTerms(resp2), tc.want)
			}
		})
	}
}

func TestAnalyzerCustomSettingsAndSnowballLanguages(t *testing.T) {
	cfg, err := NewRegistry(map[string]any{
		"analysis": map[string]any{
			"analyzer": map[string]any{
				"dutch_sb": map[string]any{
					"type":     "snowball",
					"language": "Dutch",
				},
				"en_excl": map[string]any{
					"type":                   "english",
					"stopwords":              []any{"customstop"},
					"stem_exclusion":         []any{"books"},
					"position_increment_gap": 50,
				},
				"pat_upper": map[string]any{
					"type":      "pattern",
					"pattern":   "-",
					"lowercase": false,
				},
				"fp_custom": map[string]any{
					"type":            "fingerprint",
					"separator":       "_",
					"max_output_size": 20,
				},
			},
		},
	}, Options{})
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	resp, err := Analyze(AnalyzeRequest{
		Text:     []string{"de bruine vossen"},
		Analyzer: "dutch_sb",
		Config:   cfg,
	})
	if err != nil {
		t.Fatalf("dutch_sb failed: %v", err)
	}
	if want := []string{"bruin", "voss"}; !reflect.DeepEqual(extractTerms(resp), want) {
		t.Fatalf("dutch_sb = %v, want %v", extractTerms(resp), want)
	}

	respExcl, err := Analyze(AnalyzeRequest{
		Text:     []string{"the customstop books cats", "dogs"},
		Analyzer: "en_excl",
		Config:   cfg,
	})
	if err != nil {
		t.Fatalf("en_excl failed: %v", err)
	}
	// "the" is NOT stopped because custom stopwords overrode _english_; "customstop" is stopped; "books" excluded from stemming!
	if want := []string{"the", "books", "cat", "dog"}; !reflect.DeepEqual(extractTerms(respExcl), want) {
		t.Fatalf("en_excl = %v, want %v", extractTerms(respExcl), want)
	}
	// Check position_increment_gap: "cat" at pos 3, "dog" at 3 + 1 + 50 = 54!
	if respExcl.Tokens[3].Position != 54 {
		t.Fatalf("expected position_increment_gap 50 -> pos 54, got %d", respExcl.Tokens[3].Position)
	}
	// Check +1 char offset gap across array elements
	firstLen := len("the customstop books cats")
	if respExcl.Tokens[3].StartOffset != firstLen+1 {
		t.Fatalf("expected second element start_offset %d, got %d", firstLen+1, respExcl.Tokens[3].StartOffset)
	}

	respPat, err := Analyze(AnalyzeRequest{
		Text:     []string{"Foo-Bar"},
		Analyzer: "pat_upper",
		Config:   cfg,
	})
	if err != nil {
		t.Fatalf("pat_upper failed: %v", err)
	}
	if want := []string{"Foo", "Bar"}; !reflect.DeepEqual(extractTerms(respPat), want) {
		t.Fatalf("pat_upper = %v, want %v", extractTerms(respPat), want)
	}

	respFP, err := Analyze(AnalyzeRequest{
		Text:     []string{"Éclair alpha"},
		Analyzer: "fp_custom",
		Config:   cfg,
	})
	if err != nil {
		t.Fatalf("fp_custom failed: %v", err)
	}
	if want := []string{"alpha_eclair"}; !reflect.DeepEqual(extractTerms(respFP), want) {
		t.Fatalf("fp_custom = %v, want %v", extractTerms(respFP), want)
	}
}

func TestTokenizersCatalog(t *testing.T) {
	for _, tk := range []string{
		"standard", "uax_url_email", "letter", "lowercase", "whitespace",
		"classic", "keyword", "ngram", "edge_ngram", "pattern",
		"simple_pattern", "simple_pattern_split", "char_group", "path_hierarchy", "thai",
	} {
		if !IsBuiltInTokenizer(tk) {
			t.Fatalf("expected IsBuiltInTokenizer(%q) == true", tk)
		}
	}

	// 1. keyword named & anonymous explain
	r1, err := Analyze(AnalyzeRequest{
		Text:      []string{"Foo Bar!"},
		Tokenizer: map[string]any{"type": "keyword"},
		Explain:   true,
	})
	if err != nil {
		t.Fatalf("anonymous keyword failed: %v", err)
	}
	if r1.Detail.Tokenizer.Name != "__anonymous__keyword" || r1.Detail.Tokenizer.Tokens[0].Token != "Foo Bar!" {
		t.Fatalf("unexpected anonymous keyword detail: %+v", r1.Detail.Tokenizer)
	}

	// Empty string on keyword tokenizer produces 0 tokens
	rEmpty, err := Analyze(AnalyzeRequest{Text: []string{""}, Tokenizer: "keyword"})
	if err != nil || len(rEmpty.Tokens) != 0 {
		t.Fatalf("expected 0 tokens on empty keyword input, got %v (err=%v)", rEmpty, err)
	}

	// 2. simple_pattern & simple_pattern_split
	rSP, err := Analyze(AnalyzeRequest{
		Text:      []string{"a6bf fooo ff61"},
		Tokenizer: map[string]any{"type": "simple_pattern", "pattern": "[abcdef0123456789]{4}"},
		Explain:   true,
	})
	if err != nil {
		t.Fatalf("simple_pattern failed: %v", err)
	}
	if want := []string{"a6bf", "ff61"}; !reflect.DeepEqual(extractTerms(rSP), want) {
		t.Fatalf("simple_pattern = %v, want %v", extractTerms(rSP), want)
	}

	rSPS, err := Analyze(AnalyzeRequest{
		Text:      []string{"foo==bar"},
		Tokenizer: map[string]any{"type": "simple_pattern_split", "pattern": "=="},
	})
	if err != nil {
		t.Fatalf("simple_pattern_split failed: %v", err)
	}
	if want := []string{"foo", "bar"}; !reflect.DeepEqual(extractTerms(rSPS), want) {
		t.Fatalf("simple_pattern_split = %v, want %v", extractTerms(rSPS), want)
	}

	// 3. thai tokenizer
	rThai, err := Analyze(AnalyzeRequest{
		Text:      []string{"ภาษาไทย"},
		Tokenizer: "thai",
	})
	if err != nil {
		t.Fatalf("thai tokenizer failed: %v", err)
	}
	if want := []string{"ภาษา", "ไทย"}; !reflect.DeepEqual(extractTerms(rThai), want) {
		t.Fatalf("thai tokenizer = %v, want %v", extractTerms(rThai), want)
	}

	// 4. ngram & ngram_exception & edge_ngram
	rNG, err := Analyze(AnalyzeRequest{
		Text:      []string{"foo"},
		Tokenizer: "ngram",
	})
	if err != nil {
		t.Fatalf("ngram failed: %v", err)
	}
	if want := []string{"f", "fo", "o", "oo", "o"}; !reflect.DeepEqual(extractTerms(rNG), want) {
		t.Fatalf("ngram = %v, want %v", extractTerms(rNG), want)
	}

	_, err = Analyze(AnalyzeRequest{
		Text:      []string{"good"},
		Tokenizer: map[string]any{"type": "ngram", "min_gram": 2, "max_gram": 4},
	})
	if err == nil || !strings.Contains(err.Error(), "The difference between max_gram and min_gram in NGram Tokenizer must be less than or equal to: [1] but was [2].") {
		t.Fatalf("expected NGram max_ngram_diff error, got: %v", err)
	}

	rENG, err := Analyze(AnalyzeRequest{
		Text:      []string{"foo-12"},
		Tokenizer: map[string]any{"type": "edge_ngram", "min_gram": 1, "max_gram": 3, "token_chars": []any{"letter", "digit"}},
	})
	if err != nil {
		t.Fatalf("edge_ngram failed: %v", err)
	}
	if want := []string{"f", "fo", "foo", "1", "12"}; !reflect.DeepEqual(extractTerms(rENG), want) {
		t.Fatalf("edge_ngram = %v, want %v", extractTerms(rENG), want)
	}

	// 5. classic, letter, lowercase
	rCl, err := Analyze(AnalyzeRequest{
		Text:      []string{"Brown-Foxes don't U.S.A. jump."},
		Tokenizer: "classic",
	})
	if err != nil {
		t.Fatalf("classic failed: %v", err)
	}
	if want := []string{"Brown", "Foxes", "don't", "U.S.A.", "jump"}; !reflect.DeepEqual(extractTerms(rCl), want) {
		t.Fatalf("classic = %v, want %v", extractTerms(rCl), want)
	}

	rLet, err := Analyze(AnalyzeRequest{
		Text:      []string{"Brown-Foxes don't jump."},
		Tokenizer: "letter",
	})
	if err != nil {
		t.Fatalf("letter failed: %v", err)
	}
	if want := []string{"Brown", "Foxes", "don", "t", "jump"}; !reflect.DeepEqual(extractTerms(rLet), want) {
		t.Fatalf("letter = %v, want %v", extractTerms(rLet), want)
	}

	// 6. path_hierarchy & PathHierarchy alias + reverse/skip
	rPH, err := Analyze(AnalyzeRequest{
		Text:      []string{"a/b/c"},
		Tokenizer: map[string]any{"type": "PathHierarchy"},
		Explain:   true,
	})
	if err != nil {
		t.Fatalf("PathHierarchy failed: %v", err)
	}
	if rPH.Detail.Tokenizer.Name != "__anonymous__PathHierarchy" {
		t.Fatalf("expected __anonymous__PathHierarchy, got %s", rPH.Detail.Tokenizer.Name)
	}
	if want := []string{"a", "a/b", "a/b/c"}; !reflect.DeepEqual(extractTerms(rPH), want) {
		t.Fatalf("PathHierarchy = %v, want %v", extractTerms(rPH), want)
	}

	rPHRev, err := Analyze(AnalyzeRequest{
		Text: []string{"a/b/c"},
		Tokenizer: map[string]any{
			"type":        "path_hierarchy",
			"delimiter":   "/",
			"replacement": "-",
			"reverse":     true,
			"skip":        1,
		},
	})
	if err != nil {
		t.Fatalf("path_hierarchy reverse failed: %v", err)
	}
	if want := []string{"b", "a-b"}; !reflect.DeepEqual(extractTerms(rPHRev), want) {
		t.Fatalf("path_hierarchy reverse = %v, want %v", extractTerms(rPHRev), want)
	}

	// 7. uax_url_email & standard max_token_length & char_group & pattern capture group
	rUAX, err := Analyze(AnalyzeRequest{
		Text:      []string{"Email me at john.smith@global-international.com or https://example.org/docs! 😀"},
		Tokenizer: "uax_url_email",
	})
	if err != nil {
		t.Fatalf("uax_url_email failed: %v", err)
	}
	if want := []string{"Email", "me", "at", "john.smith@global-international.com", "or", "https://example.org/docs", "😀"}; !reflect.DeepEqual(extractTerms(rUAX), want) {
		t.Fatalf("uax_url_email = %v, want %v", extractTerms(rUAX), want)
	}
	if rUAX.Tokens[3].Type != "<EMAIL>" || rUAX.Tokens[5].Type != "<URL>" || rUAX.Tokens[6].Type != "<EMOJI>" {
		t.Fatalf("unexpected uax_url_email token types: %+v", rUAX.Tokens)
	}

	rCG, err := Analyze(AnalyzeRequest{
		Text: []string{"foo-bar\tbaz 123"},
		Tokenizer: map[string]any{
			"type":              "char_group",
			"tokenize_on_chars": []any{"whitespace", "-", "digit"},
			"max_token_length":  2,
		},
	})
	if err != nil {
		t.Fatalf("char_group failed: %v", err)
	}
	if want := []string{"fo", "o", "ba", "r", "ba", "z"}; !reflect.DeepEqual(extractTerms(rCG), want) {
		t.Fatalf("char_group = %v, want %v", extractTerms(rCG), want)
	}

	rPatGrp, err := Analyze(AnalyzeRequest{
		Text: []string{"k1=v1 k2=v2"},
		Tokenizer: map[string]any{
			"type":    "pattern",
			"pattern": `([a-z0-9]+)=([a-z0-9]+)`,
			"flags":   "CASE_INSENSITIVE",
			"group":   2,
		},
	})
	if err != nil {
		t.Fatalf("pattern group=2 failed: %v", err)
	}
	if want := []string{"v1", "v2"}; !reflect.DeepEqual(extractTerms(rPatGrp), want) {
		t.Fatalf("pattern group=2 = %v, want %v", extractTerms(rPatGrp), want)
	}
}

func TestCharFiltersAndOffsetMapping(t *testing.T) {
	// 1. html_strip with escaped_tags, scripts, comments, CDATA, and entities
	rHTML, err := Analyze(AnalyzeRequest{
		Text:      []string{"<html>test<yyy>foo</yyy></html>"},
		Tokenizer: "keyword",
		CharFilter: []any{
			map[string]any{
				"type":         "html_strip",
				"escaped_tags": []any{"xxx", "yyy"},
				"read_ahead":   1024,
			},
		},
	})
	if err != nil {
		t.Fatalf("html_strip failed: %v", err)
	}
	if rHTML.Tokens[0].Token != "\ntest<yyy>foo</yyy>\n" {
		t.Fatalf("html_strip got %q, want %q", rHTML.Tokens[0].Token, "\ntest<yyy>foo</yyy>\n")
	}

	rHTMLEnt, err := Analyze(AnalyzeRequest{
		Text:       []string{"<!--comment--><script>bad()</script><b>A&amp;B</b> <![CDATA[x<y]]> &#65;"},
		Tokenizer:  "whitespace",
		CharFilter: []any{"html_strip"},
	})
	if err != nil {
		t.Fatalf("html_strip entities failed: %v", err)
	}
	if want := []string{"A&B", "x<y", "A"}; !reflect.DeepEqual(extractTerms(rHTMLEnt), want) {
		t.Fatalf("html_strip entities = %v, want %v", extractTerms(rHTMLEnt), want)
	}
	// Verify original offset of "A&B" inside "<!--comment--><script>bad()</script><b>A&amp;B</b>..."
	// "<!--comment--><script>bad()</script><b>" is 39 chars, "A&amp;B" is 7 chars -> [39..46]!
	if rHTMLEnt.Tokens[0].StartOffset != 39 || rHTMLEnt.Tokens[0].EndOffset != 46 {
		t.Fatalf("expected offsets [39, 46] for A&B, got [%d, %d]", rHTMLEnt.Tokens[0].StartOffset, rHTMLEnt.Tokens[0].EndOffset)
	}

	// 2. mapping char filter with explain & original offset preservation
	rMap, err := Analyze(AnalyzeRequest{
		Text:      []string{"jeff quit phish"},
		Tokenizer: "keyword",
		Explain:   true,
		CharFilter: []any{
			map[string]any{
				"type":     "mapping",
				"mappings": []any{"ph => f", "qu => q"},
			},
		},
	})
	if err != nil {
		t.Fatalf("mapping char_filter failed: %v", err)
	}
	if rMap.Detail.CharFilters[0].FilteredText[0] != "jeff qit fish" {
		t.Fatalf("unexpected filtered_text: %v", rMap.Detail.CharFilters)
	}
	if rMap.Detail.Tokenizer.Tokens[0].StartOffset != 0 || rMap.Detail.Tokenizer.Tokens[0].EndOffset != 15 {
		t.Fatalf("expected [0, 15], got [%d, %d]", rMap.Detail.Tokenizer.Tokens[0].StartOffset, rMap.Detail.Tokenizer.Tokens[0].EndOffset)
	}

	// 3. pattern_replace char filter & complex regex error
	rPR, err := Analyze(AnalyzeRequest{
		Text:      []string{"sample6 sample1"},
		Tokenizer: "keyword",
		CharFilter: []any{
			map[string]any{
				"type":        "pattern_replace",
				"pattern":     "sample(.*)",
				"replacement": "replacedSample $1",
			},
		},
	})
	if err != nil {
		t.Fatalf("pattern_replace char_filter failed: %v", err)
	}
	if rPR.Tokens[0].Token != "replacedSample 6 sample1" {
		t.Fatalf("got %q, want %q", rPR.Tokens[0].Token, "replacedSample 6 sample1")
	}

	_, err = ParseIndexAnalysisConfig(map[string]any{
		"index": map[string]any{
			"analysis": map[string]any{
				"char_filter": map[string]any{
					"bad_cf": map[string]any{
						"type":        "pattern_replace",
						"pattern":     "(\\d+)-(?=\\d\n\u036d\u036d\u036d\u036d\u036d",
						"flags":       "CASE_INSENSITIVE|MULTILINE|DOTALL|UNICODE_CASE|CANON_EQ",
						"replacement": "_$1",
					},
				},
			},
		},
	}, Options{})
	if ae, ok := AsAnalysisError(err); !ok || ae.ErrType != "illegal_argument_exception" || ae.Reason != "Too complex regex pattern" {
		t.Fatalf("expected Too complex regex pattern error, got: %v", err)
	}

	// Verify Explain JSON wire serialization omits top-level "tokens" when explain: true
	wireBytes, err := json.Marshal(rMap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var wireMap map[string]any
	if err := json.Unmarshal(wireBytes, &wireMap); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if _, hasTokens := wireMap["tokens"]; hasTokens {
		t.Fatalf("expected explain JSON to omit top-level tokens, got: %s", string(wireBytes))
	}
	if _, hasDetail := wireMap["detail"]; !hasDetail {
		t.Fatalf("expected explain JSON to include detail, got: %s", string(wireBytes))
	}
}
