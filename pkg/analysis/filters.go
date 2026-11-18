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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

type filterBuildContext struct {
	cfg            *IndexAnalysisConfig
	opts           Options
	precedingChars []*compiledCharFilter
	chainTokenizer *compiledTokenizer
	precedingFilts []*compiledTokenFilter
}

type compiledTokenFilter struct {
	name  string
	typ   string
	apply func([]Token) ([]Token, error)
}

// isNormalizerAllowedFilterType reports whether typeName implements Lucene/ES NormalizingTokenFilterFactory.
func isNormalizerAllowedFilterType(typeName string) bool {
	switch strings.ToLower(strings.TrimSpace(typeName)) {
	case "lowercase", "uppercase", "asciifolding",
		"arabic_normalization", "bengali_normalization", "cjk_width", "decimal_digit",
		"elision", "german_normalization", "hindi_normalization", "indic_normalization",
		"persian_normalization", "scandinavian_folding", "scandinavian_normalization",
		"serbian_normalization", "sorani_normalization",
		"pattern_replace", "trim", "truncate":
		return true
	default:
		return false
	}
}

// IsBuiltInTokenFilter reports whether name is a built-in Elasticsearch token filter.
func IsBuiltInTokenFilter(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "lowercase", "uppercase", "asciifolding", "decimal_digit",
		"cjk_width", "cjk_bigram",
		"arabic_normalization", "bengali_normalization", "german_normalization",
		"hindi_normalization", "indic_normalization", "persian_normalization",
		"scandinavian_normalization", "scandinavian_folding",
		"serbian_normalization", "sorani_normalization",
		"elision", "apostrophe", "classic",
		"stop", "length", "truncate", "trim", "limit",
		"keep", "keep_words", "keep_types",
		"unique", "remove_duplicates", "reverse",
		"porter_stem", "kstem", "stemmer", "snowball",
		"arabic_stem", "brazilian_stem", "czech_stem", "dutch_stem",
		"french_stem", "german_stem", "russian_stem", "bengali_stem",
		"stemmer_override", "keyword_marker", "keyword_repeat",
		"word_delimiter", "word_delimiter_graph",
		"ngram", "edge_ngram", "shingle",
		"synonym", "synonym_graph", "flatten_graph",
		"common_grams", "dictionary_decompounder", "hyphenation_decompounder",
		"pattern_capture", "pattern_replace",
		"fingerprint", "min_hash",
		"delimited_payload", "type_as_payload", "delimited_term_freq",
		"condition", "predicate_token_filter", "multiplexer":
		return true
	default:
		return false
	}
}

func buildTokenFilter(displayName string, typeName string, def map[string]any, isPreconfigured bool, bctx filterBuildContext) (*compiledTokenFilter, error) {
	normType := strings.ToLower(strings.TrimSpace(typeName))
	switch normType {
	case "lowercase":
		lang := ""
		if def != nil {
			lang, _ = def["language"].(string)
			if lang == "" {
				lang, _ = def["name"].(string)
			}
			switch strings.ToLower(strings.TrimSpace(lang)) {
			case "", "greek", "irish", "turkish":
			default:
				return nil, newIllegalArgError(fmt.Sprintf("Unknown lowercase language [%s]", lang))
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				tokens[i].Term = lowercaseWithLang(tokens[i].Term, lang)
			}
			return tokens
		}), nil

	case "uppercase":
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				tokens[i].Term = strings.ToUpper(tokens[i].Term)
			}
			return tokens
		}), nil

	case "asciifolding":
		preserveOrig := false
		if def != nil {
			if raw, ok := def["preserve_original"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("preserve_original in asciifolding must be boolean")
				}
				preserveOrig = b
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			out := make([]Token, 0, len(tokens))
			for _, tok := range tokens {
				folded, changed := foldASCII(tok.Term)
				if !changed {
					out = append(out, tok)
					continue
				}
				mod := tok.clone()
				mod.Term = folded
				out = append(out, mod)
				if preserveOrig {
					out = append(out, tok)
				}
			}
			return out
		}), nil

	case "decimal_digit":
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				tokens[i].Term = foldDecimalDigit(tokens[i].Term)
			}
			return tokens
		}), nil

	case "cjk_width":
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				tokens[i].Term = foldCJKWidth(tokens[i].Term)
			}
			return tokens
		}), nil

	case "cjk_bigram":
		ignored := make(map[string]bool)
		outputUnigrams := false
		if def != nil {
			for _, sc := range extractStringSlice(def["ignored_scripts"]) {
				ls := strings.ToLower(strings.TrimSpace(sc))
				switch ls {
				case "han", "hiragana", "katakana", "hangul":
					ignored[ls] = true
				default:
					return nil, newIllegalArgError(fmt.Sprintf("Unknown script [%s] in cjk_bigram", sc))
				}
			}
			if raw, ok := def["output_unigrams"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("output_unigrams in cjk_bigram must be boolean")
				}
				outputUnigrams = b
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			return applyCJKBigram(tokens, ignored, outputUnigrams)
		}), nil

	case "arabic_normalization":
		return simpleMapTermFilter(displayName, normType, normalizeArabic), nil
	case "bengali_normalization":
		return simpleMapTermFilter(displayName, normType, normalizeBengali), nil
	case "german_normalization":
		return simpleMapTermFilter(displayName, normType, normalizeGerman), nil
	case "hindi_normalization":
		return simpleMapTermFilter(displayName, normType, normalizeHindi), nil
	case "indic_normalization":
		return simpleMapTermFilter(displayName, normType, normalizeIndic), nil
	case "persian_normalization":
		return simpleMapTermFilter(displayName, normType, normalizePersian), nil
	case "scandinavian_normalization":
		return simpleMapTermFilter(displayName, normType, normalizeScandinavian), nil
	case "scandinavian_folding":
		return simpleMapTermFilter(displayName, normType, foldScandinavian), nil
	case "sorani_normalization":
		return simpleMapTermFilter(displayName, normType, normalizeSorani), nil

	case "serbian_normalization":
		haircut := "bald"
		if def != nil {
			if h, ok := def["haircut"].(string); ok && h != "" {
				lh := strings.ToLower(strings.TrimSpace(h))
				if lh != "bald" && lh != "regular" {
					return nil, newIllegalArgError(fmt.Sprintf("Unknown haircut [%s] in serbian_normalization", h))
				}
				haircut = lh
			}
		}
		return simpleMapTermFilter(displayName, normType, func(s string) string {
			return normalizeSerbian(s, haircut)
		}), nil

	case "elision":
		articlesCase := false
		var articles []string
		if isPreconfigured && def == nil {
			articles = defaultElisionArticles
		} else {
			if def == nil {
				return nil, newIllegalArgError("elision filter requires [articles] or [articles_path] setting")
			}
			_, hasArt := def["articles"]
			pathVal, hasPath := def["articles_path"].(string)
			if !hasArt && (!hasPath || strings.TrimSpace(pathVal) == "") {
				return nil, newIllegalArgError("elision filter requires [articles] or [articles_path] setting")
			}
			if hasPath && strings.TrimSpace(pathVal) != "" {
				lines, err := resolvePathSetting("articles_path", pathVal, bctx.opts)
				if err != nil {
					return nil, err
				}
				articles = append(articles, lines...)
			}
			articles = append(articles, extractStringSlice(def["articles"])...)
			if raw, ok := def["articles_case"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("articles_case in elision must be boolean")
				}
				articlesCase = b
			}
		}
		return simpleMapTermFilter(displayName, normType, func(s string) string {
			return applyElision(s, articles, articlesCase)
		}), nil

	case "apostrophe":
		return simpleMapTermFilter(displayName, normType, applyApostrophe), nil

	case "classic":
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				tokens[i] = applyClassicFilter(tokens[i])
			}
			return tokens
		}), nil

	case "stop":
		ignoreCase := false
		removeTrailing := true
		var rawSW any
		var swPath string
		if def != nil {
			rawSW = def["stopwords"]
			swPath, _ = def["stopwords_path"].(string)
			if raw, ok := def["ignore_case"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("ignore_case in stop filter must be boolean")
				}
				ignoreCase = b
			}
			if raw, ok := def["remove_trailing"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("remove_trailing in stop filter must be boolean")
				}
				removeTrailing = b
			}
		}
		stopSet, err := resolveStopwords(rawSW, "stopwords_path", swPath, "_english_", ignoreCase, bctx.opts)
		if err != nil {
			return nil, err
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			out := make([]Token, 0, len(tokens))
			for i, tok := range tokens {
				if !removeTrailing && i == len(tokens)-1 {
					out = append(out, tok)
					continue
				}
				key := tok.Term
				if ignoreCase {
					key = strings.ToLower(key)
				}
				if !stopSet[key] {
					out = append(out, tok)
				}
			}
			return out
		}), nil

	case "length":
		minLen := 0
		maxLen := math.MaxInt32
		if def != nil {
			if raw, ok := def["min"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 0 {
					return nil, newIllegalArgError("min in length filter must be >= 0")
				}
				minLen = n
			}
			if raw, ok := def["max"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 0 {
					return nil, newIllegalArgError("max in length filter must be >= 0")
				}
				maxLen = n
			}
		}
		if minLen > maxLen {
			return nil, newIllegalArgError(fmt.Sprintf("min [%d] cannot be greater than max [%d] in length filter", minLen, maxLen))
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			out := make([]Token, 0, len(tokens))
			for _, tok := range tokens {
				l := utf16RuneUnitLen(tok.Term)
				if l >= minLen && l <= maxLen {
					out = append(out, tok)
				}
			}
			return out
		}), nil

	case "truncate":
		truncLen := 10
		if def != nil {
			if raw, ok := def["length"]; ok {
				n, valid := extractInt(raw)
				if !valid || n <= 0 {
					return nil, newIllegalArgError("length in truncate filter must be > 0")
				}
				truncLen = n
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				if tokens[i].Keyword {
					continue
				}
				rs := []rune(tokens[i].Term)
				if len(rs) > truncLen {
					tokens[i].Term = string(rs[:truncLen])
				}
			}
			return tokens
		}), nil

	case "trim":
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				tokens[i].Term = strings.TrimSpace(tokens[i].Term)
			}
			return tokens
		}), nil

	case "limit":
		maxCount := 1
		if def != nil {
			if raw, ok := def["max_token_count"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 1 {
					return nil, newIllegalArgError("max_token_count in limit filter must be >= 1")
				}
				maxCount = n
			}
			if raw, ok := def["consume_all_tokens"]; ok {
				if _, valid := extractBool(raw); !valid {
					return nil, newIllegalArgError("consume_all_tokens in limit filter must be boolean")
				}
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			if len(tokens) <= maxCount {
				return tokens
			}
			return tokens[:maxCount]
		}), nil

	case "keep", "keep_words":
		if def == nil {
			return nil, newIllegalArgError("keep filter requires [keep_words] or [keep_words_path]")
		}
		ignoreCase := false
		if raw, ok := def["keep_words_case"]; ok {
			b, valid := extractBool(raw)
			if !valid {
				return nil, newIllegalArgError("keep_words_case in keep filter must be boolean")
			}
			ignoreCase = b
		}
		var words []string
		if pathVal, ok := def["keep_words_path"].(string); ok && pathVal != "" {
			lines, err := resolvePathSetting("keep_words_path", pathVal, bctx.opts)
			if err != nil {
				return nil, err
			}
			words = append(words, lines...)
		}
		words = append(words, extractStringSlice(def["keep_words"])...)
		if len(words) == 0 {
			if _, hasKW := def["keep_words"]; !hasKW {
				if _, hasKWP := def["keep_words_path"]; !hasKWP {
					return nil, newIllegalArgError("keep filter requires [keep_words] or [keep_words_path]")
				}
			}
		}
		keepSet := make(map[string]bool, len(words))
		for _, w := range words {
			if ignoreCase {
				keepSet[strings.ToLower(w)] = true
			} else {
				keepSet[w] = true
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			out := make([]Token, 0, len(tokens))
			for _, tok := range tokens {
				k := tok.Term
				if ignoreCase {
					k = strings.ToLower(k)
				}
				if keepSet[k] {
					out = append(out, tok)
				}
			}
			return out
		}), nil

	case "keep_types":
		if def == nil {
			return nil, newIllegalArgError("keep_types filter requires [types]")
		}
		typesList := extractStringSlice(def["types"])
		if len(typesList) == 0 {
			return nil, newIllegalArgError("keep_types filter requires non-empty [types]")
		}
		mode := "include"
		if m, ok := def["mode"].(string); ok && m != "" {
			lm := strings.ToLower(strings.TrimSpace(m))
			if lm != "include" && lm != "exclude" {
				return nil, newIllegalArgError(fmt.Sprintf("Unknown mode [%s] in keep_types filter", m))
			}
			mode = lm
		}
		typeSet := make(map[string]bool, len(typesList))
		for _, t := range typesList {
			typeSet[t] = true
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			out := make([]Token, 0, len(tokens))
			for _, tok := range tokens {
				inSet := typeSet[tok.Type]
				if (mode == "include" && inSet) || (mode == "exclude" && !inSet) {
					out = append(out, tok)
				}
			}
			return out
		}), nil

	case "unique", "remove_duplicates":
		samePosOnly := normType == "remove_duplicates"
		if normType == "unique" && def != nil {
			if raw, ok := def["only_on_same_position"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("only_on_same_position in unique filter must be boolean")
				}
				samePosOnly = b
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			out := make([]Token, 0, len(tokens))
			if samePosOnly {
				lastPos := -1
				var seenAtPos map[string]bool
				for _, tok := range tokens {
					if tok.Position != lastPos || seenAtPos == nil {
						seenAtPos = make(map[string]bool)
						lastPos = tok.Position
					}
					if !seenAtPos[tok.Term] {
						seenAtPos[tok.Term] = true
						out = append(out, tok)
					}
				}
				return out
			}
			seen := make(map[string]bool, len(tokens))
			for _, tok := range tokens {
				if !seen[tok.Term] {
					seen[tok.Term] = true
					out = append(out, tok)
				}
			}
			return out
		}), nil

	case "reverse":
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				rs := []rune(tokens[i].Term)
				for l, r := 0, len(rs)-1; l < r; l, r = l+1, r-1 {
					rs[l], rs[r] = rs[r], rs[l]
				}
				tokens[i].Term = string(rs)
			}
			return tokens
		}), nil

	case "porter_stem":
		return stemTokenFilter(displayName, normType, stemEnglishPorter), nil
	case "kstem":
		return stemTokenFilter(displayName, normType, stemKStem), nil
	case "arabic_stem":
		return stemTokenFilter(displayName, normType, stemArabic), nil
	case "brazilian_stem":
		return stemTokenFilter(displayName, normType, stemBrazilian), nil
	case "czech_stem":
		return stemTokenFilter(displayName, normType, stemCzech), nil
	case "dutch_stem":
		return stemTokenFilter(displayName, normType, stemDutch), nil
	case "french_stem":
		return stemTokenFilter(displayName, normType, stemFrench), nil
	case "german_stem":
		return stemTokenFilter(displayName, normType, stemGerman), nil
	case "russian_stem":
		return stemTokenFilter(displayName, normType, stemRussian), nil
	case "bengali_stem":
		return stemTokenFilter(displayName, normType, stemBengali), nil

	case "stemmer", "snowball":
		lang := "english"
		if def != nil {
			if l, ok := def["language"].(string); ok && l != "" {
				lang = l
			} else if n, ok := def["name"].(string); ok && n != "" {
				lang = n
			}
		}
		fn, err := buildStemmerFunc(lang)
		if err != nil {
			return nil, err
		}
		return stemTokenFilter(displayName, normType, fn), nil

	case "stemmer_override":
		var rawRules []string
		if def != nil {
			if pathVal, ok := def["rules_path"].(string); ok && pathVal != "" {
				lines, err := resolvePathSetting("rules_path", pathVal, bctx.opts)
				if err != nil {
					return nil, err
				}
				rawRules = append(rawRules, lines...)
			}
			rawRules = append(rawRules, extractStringSlice(def["rules"])...)
		}
		if len(rawRules) == 0 {
			return nil, newIllegalArgError("stemmer_override requires [rules] or [rules_path]")
		}
		overrideMap, err := parseStemmerOverrideRules(rawRules)
		if err != nil {
			return nil, err
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				if tokens[i].Keyword {
					continue
				}
				if repl, ok := overrideMap[tokens[i].Term]; ok {
					tokens[i].Term = repl
					tokens[i].Keyword = true
				}
			}
			return tokens
		}), nil

	case "keyword_marker":
		ignoreCase := false
		var kwList []string
		var kwRegex *regexp.Regexp
		if def != nil {
			if raw, ok := def["ignore_case"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("ignore_case in keyword_marker must be boolean")
				}
				ignoreCase = b
			}
			if pathVal, ok := def["keywords_path"].(string); ok && pathVal != "" {
				lines, err := resolvePathSetting("keywords_path", pathVal, bctx.opts)
				if err != nil {
					return nil, err
				}
				kwList = append(kwList, lines...)
			}
			kwList = append(kwList, extractStringSlice(def["keywords"])...)
			if pat, ok := def["keywords_pattern"].(string); ok && pat != "" {
				flags := ""
				if ignoreCase {
					flags = "CASE_INSENSITIVE"
				}
				re, err := compileJavaRegex("^(?:"+pat+")$", flags)
				if err != nil {
					return nil, err
				}
				kwRegex = re
			}
		}
		kwSet := make(map[string]bool, len(kwList))
		for _, w := range kwList {
			if ignoreCase {
				kwSet[strings.ToLower(w)] = true
			} else {
				kwSet[w] = true
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				term := tokens[i].Term
				lookup := term
				if ignoreCase {
					lookup = strings.ToLower(lookup)
				}
				if kwSet[lookup] || (kwRegex != nil && kwRegex.MatchString(term)) {
					tokens[i].Keyword = true
				}
			}
			return tokens
		}), nil

	case "keyword_repeat":
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			out := make([]Token, 0, len(tokens)*2)
			for _, tok := range tokens {
				kwCopy := tok.clone()
				kwCopy.Keyword = true
				out = append(out, kwCopy, tok)
			}
			return out
		}), nil

	case "pattern_capture":
		if def == nil {
			return nil, newIllegalArgError("pattern_capture filter requires [patterns]")
		}
		pats := extractStringSlice(def["patterns"])
		if len(pats) == 0 {
			if p, ok := def["pattern"].(string); ok && p != "" {
				pats = []string{p}
			}
		}
		if len(pats) == 0 {
			return nil, newIllegalArgError("pattern_capture filter requires non-empty [patterns]")
		}
		preserveOrig := true
		if raw, ok := def["preserve_original"]; ok {
			b, valid := extractBool(raw)
			if !valid {
				return nil, newIllegalArgError("preserve_original in pattern_capture must be boolean")
			}
			preserveOrig = b
		}
		compiledPats := make([]*regexp.Regexp, 0, len(pats))
		for _, p := range pats {
			re, err := compileJavaRegex(p, "")
			if err != nil {
				return nil, err
			}
			compiledPats = append(compiledPats, re)
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			var out []Token
			for _, tok := range tokens {
				seen := make(map[string]bool)
				var emitted []Token
				if preserveOrig {
					seen[tok.Term] = true
					emitted = append(emitted, tok)
				}
				for _, re := range compiledPats {
					allSub := re.FindAllStringSubmatch(tok.Term, -1)
					for _, sub := range allSub {
						for g := 1; g < len(sub); g++ {
							capStr := sub[g]
							if capStr == "" || seen[capStr] {
								continue
							}
							seen[capStr] = true
							cp := tok.clone()
							cp.Term = capStr
							emitted = append(emitted, cp)
						}
					}
				}
				out = append(out, emitted...)
			}
			return out
		}), nil

	case "pattern_replace":
		if def == nil {
			return nil, newIllegalArgError("pattern_replace token filter requires [pattern]")
		}
		pat, hasPat := def["pattern"].(string)
		if !hasPat {
			return nil, newIllegalArgError("pattern is missing for [pattern_replace] token filter")
		}
		flags, _ := def["flags"].(string)
		repl, _ := def["replacement"].(string)
		replaceAll := true
		if raw, ok := def["all"]; ok {
			b, valid := extractBool(raw)
			if !valid {
				return nil, newIllegalArgError("all in pattern_replace filter must be boolean")
			}
			replaceAll = b
		}
		re, err := compileJavaRegex(pat, flags)
		if err != nil {
			return nil, err
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				s := tokens[i].Term
				matches := re.FindAllStringSubmatchIndex(s, -1)
				if len(matches) == 0 {
					continue
				}
				if !replaceAll {
					matches = matches[:1]
				}
				var sb strings.Builder
				prev := 0
				for _, loc := range matches {
					if loc[0] < prev {
						continue
					}
					sb.WriteString(s[prev:loc[0]])
					sb.WriteString(expandJavaReplacement(s, loc, repl))
					if loc[1] == loc[0] {
						if loc[0] < len(s) {
							sb.WriteByte(s[loc[0]])
							prev = loc[0] + 1
						}
					} else {
						prev = loc[1]
					}
				}
				sb.WriteString(s[prev:])
				tokens[i].Term = sb.String()
			}
			return tokens
		}), nil

	case "fingerprint":
		sep := " "
		maxOut := 255
		if def != nil {
			if s, ok := def["separator"].(string); ok {
				if len([]rune(s)) > 1 {
					return nil, newIllegalArgError("separator in fingerprint filter must be at most 1 character")
				}
				sep = s
			}
			if raw, ok := def["max_output_size"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 1 {
					return nil, newIllegalArgError("max_output_size in fingerprint filter must be >= 1")
				}
				maxOut = n
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			if len(tokens) == 0 {
				return nil
			}
			minStart := tokens[0].StartOffset
			maxEnd := tokens[0].EndOffset
			seen := make(map[string]bool, len(tokens))
			uniq := make([]string, 0, len(tokens))
			for _, tok := range tokens {
				if tok.StartOffset < minStart {
					minStart = tok.StartOffset
				}
				if tok.EndOffset > maxEnd {
					maxEnd = tok.EndOffset
				}
				if tok.Term == "" {
					continue
				}
				if utf16RuneUnitLen(tok.Term) > maxOut {
					return nil
				}
				if !seen[tok.Term] {
					seen[tok.Term] = true
					uniq = append(uniq, tok.Term)
				}
			}
			if len(uniq) == 0 {
				return nil
			}
			sort.Strings(uniq)
			joined := strings.Join(uniq, sep)
			if utf16RuneUnitLen(joined) > maxOut {
				return nil
			}
			return []Token{{
				Term:           joined,
				StartOffset:    minStart,
				EndOffset:      maxEnd,
				Type:           "fingerprint",
				Position:       0,
				PositionLength: 1,
				TermFrequency:  1,
			}}
		}), nil

	case "min_hash":
		hashCount := 1
		bucketCount := 512
		hashSetSize := 1
		var explicitRotation *bool
		if def != nil {
			if raw, ok := def["hash_count"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 1 {
					return nil, newIllegalArgError("hash_count in min_hash must be >= 1")
				}
				hashCount = n
			}
			if raw, ok := def["bucket_count"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 1 {
					return nil, newIllegalArgError("bucket_count in min_hash must be >= 1")
				}
				bucketCount = n
			}
			if raw, ok := def["hash_set_size"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 1 {
					return nil, newIllegalArgError("hash_set_size in min_hash must be >= 1")
				}
				hashSetSize = n
			}
			if raw, ok := def["with_rotation"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("with_rotation in min_hash must be boolean")
				}
				explicitRotation = &b
			}
		}
		withRotation := bucketCount > 1
		if explicitRotation != nil {
			withRotation = *explicitRotation
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			return applyMinHashFilter(tokens, hashCount, bucketCount, hashSetSize, withRotation)
		}), nil

	case "delimited_payload_filter":
		return nil, newIllegalArgError("[delimited_payload_filter] is not supported for new indices, use [delimited_payload] instead")

	case "delimited_payload":
		delim := '|'
		encoding := "float"
		if def != nil {
			if d, ok := def["delimiter"].(string); ok && d != "" {
				dr := []rune(d)
				if len(dr) != 1 {
					return nil, newIllegalArgError("delimiter in delimited_payload must be a single character")
				}
				delim = dr[0]
			}
			if enc, ok := def["encoding"].(string); ok && enc != "" {
				le := strings.ToLower(strings.TrimSpace(enc))
				if le != "float" && le != "int" && le != "identity" {
					return nil, newIllegalArgError(fmt.Sprintf("Unknown encoding [%s] in delimited_payload", enc))
				}
				encoding = le
			}
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token) ([]Token, error) {
				delimStr := string(delim)
				for i := range tokens {
					idx := strings.LastIndex(tokens[i].Term, delimStr)
					if idx < 0 {
						continue
					}
					payStr := tokens[i].Term[idx+len(delimStr):]
					tokens[i].Term = tokens[i].Term[:idx]
					switch encoding {
					case "identity":
						tokens[i].Payload = []byte(payStr)
					case "int":
						iv, err := strconv.ParseInt(payStr, 10, 32)
						if err != nil {
							return nil, newIllegalArgError(fmt.Sprintf("Invalid integer payload [%s]", payStr))
						}
						payBytes, _ := hex.DecodeString(fmt.Sprintf("%08x", iv&0xFFFFFFFF))
						tokens[i].Payload = payBytes
					case "float":
						fv, err := strconv.ParseFloat(payStr, 32)
						if err != nil {
							return nil, newIllegalArgError(fmt.Sprintf("Invalid float payload [%s]", payStr))
						}
						var buf [4]byte
						binary.BigEndian.PutUint32(buf[:], math.Float32bits(float32(fv)))
						tokens[i].Payload = buf[:]
					}
				}
				return tokens, nil
			},
		}, nil

	case "type_as_payload":
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			for i := range tokens {
				tokens[i].Payload = []byte(tokens[i].Type)
			}
			return tokens
		}), nil

	case "delimited_term_freq":
		delim := '|'
		maxTF := 0
		if def != nil {
			if d, ok := def["delimiter"].(string); ok && d != "" {
				dr := []rune(d)
				if len(dr) != 1 {
					return nil, newIllegalArgError("delimiter in delimited_term_freq must be a single character")
				}
				delim = dr[0]
			}
			if raw, ok := def["max_term_freq"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 1 {
					return nil, newIllegalArgError("max_term_freq in delimited_term_freq must be >= 1")
				}
				maxTF = n
			}
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token) ([]Token, error) {
				delimStr := string(delim)
				for i := range tokens {
					idx := strings.LastIndex(tokens[i].Term, delimStr)
					if idx < 0 {
						continue
					}
					tfStr := tokens[i].Term[idx+len(delimStr):]
					tf, err := strconv.Atoi(tfStr)
					if err != nil || tf < 1 {
						return nil, newIllegalArgError(fmt.Sprintf("Invalid term frequency [%s]", tfStr))
					}
					if maxTF > 0 && tf > maxTF {
						return nil, newIllegalArgError(fmt.Sprintf("Term frequency [%d] exceeds max_term_freq [%d]", tf, maxTF))
					}
					tokens[i].Term = tokens[i].Term[:idx]
					tokens[i].TermFrequency = tf
				}
				return tokens, nil
			},
		}, nil

	case "condition":
		if def == nil {
			return nil, newIllegalArgError("condition filter requires [script] and [filter]")
		}
		scriptMap, okS := def["script"].(map[string]any)
		if !okS {
			return nil, newIllegalArgError("condition filter requires [script] object")
		}
		subSpecs := extractFilterStepList(def["filter"])
		if len(subSpecs) == 0 {
			return nil, newIllegalArgError("condition filter requires non-empty [filter]")
		}
		subFilters := make([]*compiledTokenFilter, 0, len(subSpecs))
		for _, spec := range subSpecs {
			cf, err := resolveTokenFilterStep(spec, bctx)
			if err != nil {
				return nil, err
			}
			subFilters = append(subFilters, cf)
		}
		evalFn := bctx.opts.EvalPredicateScript
		if evalFn == nil {
			evalFn = DefaultEvalPredicateScript
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token) ([]Token, error) {
				var out []Token
				prevPos := -1
				for _, tok := range tokens {
					posInc := 1
					if prevPos >= 0 {
						posInc = tok.Position - prevPos
					}
					prevPos = tok.Position
					pl := tok.PositionLength
					if pl < 1 {
						pl = 1
					}
					ctx := TokenContext{
						Term:              tok.Term,
						Position:          tok.Position,
						PositionIncrement: posInc,
						PositionLength:    pl,
						StartOffset:       tok.StartOffset,
						EndOffset:         tok.EndOffset,
						Type:              tok.Type,
						Keyword:           tok.Keyword,
					}
					matched, err := evalFn(scriptMap, &ctx)
					if err != nil {
						return nil, err
					}
					cur := tok.clone()
					cur.Term = ctx.Term
					if !matched {
						out = append(out, cur)
						continue
					}
					subToks := []Token{cur}
					for _, sf := range subFilters {
						subToks, err = sf.apply(subToks)
						if err != nil {
							return nil, err
						}
					}
					out = append(out, subToks...)
				}
				return out, nil
			},
		}, nil

	case "predicate_token_filter":
		if def == nil {
			return nil, newIllegalArgError("predicate_token_filter requires [script]")
		}
		scriptMap, okS := def["script"].(map[string]any)
		if !okS {
			return nil, newIllegalArgError("predicate_token_filter requires [script] object")
		}
		evalFn := bctx.opts.EvalPredicateScript
		if evalFn == nil {
			evalFn = DefaultEvalPredicateScript
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token) ([]Token, error) {
				out := make([]Token, 0, len(tokens))
				prevPos := -1
				for _, tok := range tokens {
					posInc := 1
					if prevPos >= 0 {
						posInc = tok.Position - prevPos
					}
					prevPos = tok.Position
					pl := tok.PositionLength
					if pl < 1 {
						pl = 1
					}
					ctx := TokenContext{
						Term:              tok.Term,
						Position:          tok.Position,
						PositionIncrement: posInc,
						PositionLength:    pl,
						StartOffset:       tok.StartOffset,
						EndOffset:         tok.EndOffset,
						Type:              tok.Type,
						Keyword:           tok.Keyword,
					}
					keep, err := evalFn(scriptMap, &ctx)
					if err != nil {
						return nil, err
					}
					if keep {
						cur := tok.clone()
						cur.Term = ctx.Term
						out = append(out, cur)
					}
				}
				return out, nil
			},
		}, nil

	case "multiplexer":
		if def == nil {
			return nil, newIllegalArgError("multiplexer filter requires [filters]")
		}
		rawChains := extractStringSlice(def["filters"])
		if len(rawChains) == 0 {
			return nil, newIllegalArgError("multiplexer filter requires non-empty [filters]")
		}
		preserveOrig := true
		if raw, ok := def["preserve_original"]; ok {
			b, valid := extractBool(raw)
			if !valid {
				return nil, newIllegalArgError("preserve_original in multiplexer must be boolean")
			}
			preserveOrig = b
		}
		chains := make([][]*compiledTokenFilter, 0, len(rawChains))
		for _, chainStr := range rawChains {
			var chain []*compiledTokenFilter
			for _, part := range strings.Split(chainStr, ",") {
				fname := strings.TrimSpace(part)
				if fname == "" {
					continue
				}
				cf, err := resolveTokenFilterStep(fname, bctx)
				if err != nil {
					return nil, err
				}
				chain = append(chain, cf)
			}
			chains = append(chains, chain)
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token) ([]Token, error) {
				var out []Token
				for _, tok := range tokens {
					seenAtPos := make(map[string]bool)
					if preserveOrig {
						seenAtPos[tok.Term] = true
						out = append(out, tok.clone())
					}
					for _, chain := range chains {
						branch := []Token{tok.clone()}
						var err error
						for _, cf := range chain {
							branch, err = cf.apply(branch)
							if err != nil {
								return nil, err
							}
						}
						for _, bt := range branch {
							if bt.Position == tok.Position {
								if seenAtPos[bt.Term] {
									continue
								}
								seenAtPos[bt.Term] = true
							}
							out = append(out, bt)
						}
					}
				}
				return out, nil
			},
		}, nil

	case "word_delimiter", "word_delimiter_graph",
		"ngram", "edge_ngram", "shingle",
		"synonym", "synonym_graph", "flatten_graph",
		"common_grams", "dictionary_decompounder", "hyphenation_decompounder":
		return buildCompoundTokenFilter(displayName, normType, def, bctx)

	default:
		return nil, newIllegalArgError(fmt.Sprintf("Unknown token filter type [%s] for [%s]", typeName, displayName))
	}
}

func simpleTokenFilter(name, typ string, fn func([]Token) []Token) *compiledTokenFilter {
	return &compiledTokenFilter{
		name: name,
		typ:  typ,
		apply: func(tokens []Token) ([]Token, error) {
			return fn(tokens), nil
		},
	}
}

func simpleMapTermFilter(name, typ string, fn func(string) string) *compiledTokenFilter {
	return simpleTokenFilter(name, typ, func(tokens []Token) []Token {
		for i := range tokens {
			tokens[i].Term = fn(tokens[i].Term)
		}
		return tokens
	})
}

func stemTokenFilter(name, typ string, fn func(string) string) *compiledTokenFilter {
	return simpleTokenFilter(name, typ, func(tokens []Token) []Token {
		for i := range tokens {
			if !tokens[i].Keyword {
				tokens[i].Term = fn(tokens[i].Term)
			}
		}
		return tokens
	})
}

func parseStemmerOverrideRules(rawRules []string) (map[string]string, error) {
	out := make(map[string]string, len(rawRules))
	for _, raw := range rawRules {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "=>"); idx >= 0 {
			lhs := strings.TrimSpace(line[:idx])
			rhs := strings.TrimSpace(line[idx+2:])
			if lhs == "" || rhs == "" {
				return nil, newIllegalArgError(fmt.Sprintf("Invalid stemmer_override rule [%s]", raw))
			}
			for _, part := range strings.Split(lhs, ",") {
				src := strings.TrimSpace(part)
				if src != "" {
					out[src] = rhs
				}
			}
			continue
		}
		if idx := strings.IndexByte(line, '\t'); idx > 0 {
			src := strings.TrimSpace(line[:idx])
			rhs := strings.TrimSpace(line[idx+1:])
			if src != "" && rhs != "" {
				out[src] = rhs
				continue
			}
		}
		return nil, newIllegalArgError(fmt.Sprintf("Invalid stemmer_override rule [%s]", raw))
	}
	return out, nil
}

// MinHash Filter (Lucene MinHashFilter with MurmurHash3_x64_128)

type hashPair128 struct {
	h1 uint64
	h2 uint64
}

func (a hashPair128) less(b hashPair128) bool {
	if a.h2 != b.h2 {
		return a.h2 < b.h2
	}
	return a.h1 < b.h1
}

func applyMinHashFilter(tokens []Token, hashCount, bucketCount, hashSetSize int, withRotation bool) []Token {
	if len(tokens) == 0 {
		return nil
	}
	maxEnd := tokens[len(tokens)-1].EndOffset
	var out []Token

	for hi := 0; hi < hashCount; hi++ {
		buckets := make([][]hashPair128, bucketCount)
		for _, tok := range tokens {
			data := encodeUTF16LE(tok.Term)
			// Seed derived deterministically per hash index hi (matching Lucene's hash_count cascading).
			var seed uint32
			if hi > 0 && hi < 0x7FFFFFFF {
				seed = uint32(hi) * 0x9E3779B1
			}
			h1, h2 := murmur3X64128(data, seed)
			pair := hashPair128{h1: h1, h2: h2}
			bIdx := modUint63Int(h2&0x7FFFFFFFFFFFFFFF, bucketCount)
			buckets[bIdx] = insertMinHashSet(buckets[bIdx], pair, hashSetSize)
		}

		if withRotation && bucketCount > 1 {
			// Find first non-empty bucket to seed wrap-around rotation.
			firstNonEmpty := -1
			for b := 0; b < bucketCount; b++ {
				if len(buckets[b]) > 0 {
					firstNonEmpty = b
					break
				}
			}
			if firstNonEmpty >= 0 {
				lastVal := buckets[firstNonEmpty][0]
				for step := 1; step <= bucketCount; step++ {
					idx := (firstNonEmpty - step + bucketCount) % bucketCount
					if len(buckets[idx]) == 0 {
						buckets[idx] = []hashPair128{lastVal}
					} else {
						lastVal = buckets[idx][0]
					}
				}
			}
		}

		for b := 0; b < bucketCount; b++ {
			for _, pair := range buckets[b] {
				var raw [16]byte
				binary.BigEndian.PutUint64(raw[0:8], pair.h2)
				binary.BigEndian.PutUint64(raw[8:16], pair.h1)
				out = append(out, Token{
					Term:           hex.EncodeToString(raw[:]),
					StartOffset:    0,
					EndOffset:      maxEnd,
					Type:           "MIN_HASH",
					Position:       0,
					PositionLength: 1,
					TermFrequency:  1,
				})
			}
		}
	}
	return out
}

func insertMinHashSet(cur []hashPair128, cand hashPair128, maxSize int) []hashPair128 {
	for _, existing := range cur {
		if existing == cand {
			return cur
		}
	}
	cur = append(cur, cand)
	sort.Slice(cur, func(i, j int) bool {
		return cur[i].less(cur[j])
	})
	if len(cur) > maxSize {
		cur = cur[:maxSize]
	}
	return cur
}

func modUint63Int(val uint64, mod int) int {
	if mod <= 1 {
		return 0
	}
	rem := 0
	for bit := 62; bit >= 0; bit-- {
		rem <<= 1
		if (val & (uint64(1) << bit)) != 0 {
			rem++
		}
		if rem >= mod {
			rem -= mod
		}
	}
	return rem
}

func encodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(u16)*2)
	for _, cu := range u16 {
		out = binary.LittleEndian.AppendUint16(out, cu)
	}
	return out
}

func murmur3X64128(data []byte, seed uint32) (uint64, uint64) {
	const c1 uint64 = 0x87c37b91114253d5
	const c2 uint64 = 0x4cf5ad432745937f

	h1 := uint64(seed)
	h2 := uint64(seed)
	length := len(data)
	nblocks := length / 16

	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint64(data[i*16 : i*16+8])
		k2 := binary.LittleEndian.Uint64(data[i*16+8 : i*16+16])

		k1 *= c1
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2
		h1 ^= k1
		h1 = bits.RotateLeft64(h1, 27)
		h1 += h2
		h1 = h1*5 + 0x52dce729

		k2 *= c2
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1
		h2 ^= k2
		h2 = bits.RotateLeft64(h2, 31)
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	}

	tail := data[nblocks*16:]
	var k1, k2 uint64
	switch len(tail) {
	case 15:
		k2 ^= uint64(tail[14]) << 48
		fallthrough
	case 14:
		k2 ^= uint64(tail[13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(tail[12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(tail[11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(tail[10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(tail[9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(tail[8])
		k2 *= c2
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1
		h2 ^= k2
		fallthrough
	case 8:
		k1 ^= binary.LittleEndian.Uint64(tail[:8])
	case 7:
		k1 ^= uint64(tail[6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(tail[5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(tail[4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(tail[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(tail[0])
	}
	if len(tail) >= 1 && len(tail) <= 8 {
		k1 *= c1
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2
		h1 ^= k1
	} else if len(tail) > 8 {
		k1 *= c1
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2
		h1 ^= k1
	}

	uLen := uint64(uint(length))
	h1 ^= uLen
	h2 ^= uLen
	h1 += h2
	h2 += h1
	h1 = fmix64(h1)
	h2 = fmix64(h2)
	h1 += h2
	h2 += h1
	return h1, h2
}

func fmix64(k uint64) uint64 {
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd
	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53
	k ^= k >> 33
	return k
}
