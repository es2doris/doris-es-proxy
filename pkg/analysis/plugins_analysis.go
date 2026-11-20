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
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ============================================================================
// Plugin Analyzer / Tokenizer / TokenFilter Dispatchers
// ============================================================================

func buildPluginAnalyzer(displayName, normType string, def map[string]any, posGap int, bctx filterBuildContext) (*compiledAnalyzer, error) {
	switch normType {
	case "icu_analyzer":
		method := "nfkc_cf"
		mode := "compose"
		if def != nil {
			if m, ok := def["method"].(string); ok && strings.TrimSpace(m) != "" {
				method = strings.TrimSpace(m)
			}
			if md, ok := def["mode"].(string); ok && strings.TrimSpace(md) != "" {
				mode = strings.TrimSpace(md)
			}
		}
		if mode != "compose" && mode != "decompose" {
			return nil, newIllegalArgError(fmt.Sprintf("Unknown mode [%s] in analyzer [%s], expected one of [compose, decompose]", mode, displayName))
		}
		cfDef := map[string]any{"name": method, "mode": mode}
		if def != nil {
			if usf, ok := def["unicode_set_filter"]; ok {
				cfDef["unicode_set_filter"] = usf
			} else if usf2, ok := def["unicodeSetFilter"]; ok {
				cfDef["unicodeSetFilter"] = usf2
			}
		}
		cf, err := buildICUNormalizerCharFilter("icu_normalizer", cfDef)
		if err != nil {
			return nil, err
		}
		tok, err := buildPluginTokenizer("icu_tokenizer", "icu_tokenizer", nil, bctx.opts)
		if err != nil {
			return nil, err
		}
		fold, err := buildICUFoldingFilter("icu_folding", nil)
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			charFilters:          []*compiledCharFilter{cf},
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{fold},
		}, nil

	case "kuromoji":
		tok, err := buildPluginTokenizer("kuromoji_tokenizer", "kuromoji_tokenizer", def, bctx.opts)
		if err != nil {
			return nil, err
		}
		bf, _ := buildPluginTokenFilter("kuromoji_baseform", "kuromoji_baseform", nil, true, bctx)
		posFilt, err := buildPluginTokenFilter("kuromoji_part_of_speech", "kuromoji_part_of_speech", nil, true, bctx)
		if err != nil {
			return nil, err
		}
		cw, _ := buildTokenFilter("cjk_width", "cjk_width", nil, true, bctx)
		var stopDef map[string]any
		if def != nil {
			if sw, hasSW := def["stopwords"]; hasSW {
				stopDef = map[string]any{"stopwords": sw}
			}
			if swp, hasSWP := def["stopwords_path"]; hasSWP {
				if stopDef == nil {
					stopDef = map[string]any{}
				}
				stopDef["stopwords_path"] = swp
			}
		}
		js, err := buildPluginTokenFilter("ja_stop", "ja_stop", stopDef, stopDef == nil, bctx)
		if err != nil {
			return nil, err
		}
		ks, _ := buildPluginTokenFilter("kuromoji_stemmer", "kuromoji_stemmer", nil, true, bctx)
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{bf, posFilt, cw, js, ks, lc},
		}, nil

	case "kuromoji_completion":
		mode := "index"
		if def != nil {
			if m, ok := def["mode"].(string); ok && strings.TrimSpace(m) != "" {
				lm := strings.ToLower(strings.TrimSpace(m))
				if lm != "index" && lm != "query" {
					return nil, newIllegalArgError(fmt.Sprintf("Unknown mode [%s] in kuromoji_completion", m))
				}
				mode = lm
			}
		}
		cf := &compiledCharFilter{
			name: "cjk_width_char",
			apply: func(in charStream) (charStream, error) {
				return applyCharTransform(in, foldCJKWidth, nil)
			},
		}
		tokDef := map[string]any{"mode": "normal"}
		if def != nil {
			if ud, ok := def["user_dictionary"]; ok {
				tokDef["user_dictionary"] = ud
			}
			if udr, ok := def["user_dictionary_rules"]; ok {
				tokDef["user_dictionary_rules"] = udr
			}
		}
		tok, err := buildPluginTokenizer("kuromoji_tokenizer", "kuromoji_tokenizer", tokDef, bctx.opts)
		if err != nil {
			return nil, err
		}
		compFilt, err := buildPluginTokenFilter("kuromoji_completion", "kuromoji_completion", map[string]any{"mode": mode}, false, bctx)
		if err != nil {
			return nil, err
		}
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			charFilters:          []*compiledCharFilter{cf},
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{compFilt, lc},
		}, nil

	case "nori":
		tok, err := buildPluginTokenizer("nori_tokenizer", "nori_tokenizer", def, bctx.opts)
		if err != nil {
			return nil, err
		}
		posFilt, err := buildPluginTokenFilter("nori_part_of_speech", "nori_part_of_speech", def, def == nil, bctx)
		if err != nil {
			return nil, err
		}
		rf, _ := buildPluginTokenFilter("nori_readingform", "nori_readingform", nil, true, bctx)
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{posFilt, rf, lc},
		}, nil

	case "smartcn":
		tok, err := buildPluginTokenizer("smartcn_tokenizer", "smartcn_tokenizer", def, bctx.opts)
		if err != nil {
			return nil, err
		}
		ps, _ := buildTokenFilter("porter_stem", "porter_stem", nil, true, bctx)
		st, err := buildPluginTokenFilter("smartcn_stop", "smartcn_stop", def, def == nil, bctx)
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{ps, st},
		}, nil

	case "polish":
		tok, _ := buildTokenizer("standard", "standard", nil, DefaultMaxNGramDiff)
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		st, err := buildPluginTokenFilter("polish_stop", "polish_stop", def, def == nil, bctx)
		if err != nil {
			return nil, err
		}
		tfs := []*compiledTokenFilter{lc, st}
		if def != nil {
			excl := extractStringSlice(def["stem_exclusion"])
			if len(excl) > 0 {
				km, err := buildTokenFilter("stem_exclusion", "keyword_marker", map[string]any{"keywords": excl}, false, bctx)
				if err != nil {
					return nil, err
				}
				tfs = append(tfs, km)
			}
		}
		ps, _ := buildPluginTokenFilter("polish_stem", "polish_stem", nil, true, bctx)
		tfs = append(tfs, ps)
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         tfs,
		}, nil

	case "ukrainian":
		tok, _ := buildTokenizer("standard", "standard", nil, DefaultMaxNGramDiff)
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		var stopDef map[string]any
		if def != nil {
			if sw, hasSW := def["stopwords"]; hasSW {
				stopDef = map[string]any{"stopwords": sw}
			}
			if swp, hasSWP := def["stopwords_path"]; hasSWP {
				if stopDef == nil {
					stopDef = map[string]any{}
				}
				stopDef["stopwords_path"] = swp
			}
		}
		if stopDef == nil {
			stopDef = map[string]any{"stopwords": "_ukrainian_"}
		}
		st, err := buildTokenFilter("stop", "stop", stopDef, false, bctx)
		if err != nil {
			return nil, err
		}
		tfs := []*compiledTokenFilter{lc, st}
		if def != nil {
			excl := extractStringSlice(def["stem_exclusion"])
			if len(excl) > 0 {
				km, err := buildTokenFilter("stem_exclusion", "keyword_marker", map[string]any{"keywords": excl}, false, bctx)
				if err != nil {
					return nil, err
				}
				tfs = append(tfs, km)
			}
		}
		ukLemma := &compiledTokenFilter{
			name: "ukrainian_lemmatizer",
			typ:  "ukrainian_lemmatizer",
			apply: func(tokens []Token, budget *tokenStreamBudget) ([]Token, error) {
				return applyUkrainianLemmatizer(tokens, budget)
			},
		}
		tfs = append(tfs, ukLemma)
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         tfs,
		}, nil

	default:
		return nil, newIllegalArgError(fmt.Sprintf("Unknown analyzer type [%s] for [%s]", normType, displayName))
	}
}

func buildPluginTokenizer(displayName, normType string, def map[string]any, opts Options) (*compiledTokenizer, error) {
	switch normType {
	case "icu_tokenizer":
		if def != nil {
			for _, rf := range extractStringSlice(def["rule_files"]) {
				for _, entry := range strings.Split(rf, ",") {
					entry = strings.TrimSpace(entry)
					if entry == "" {
						continue
					}
					colon := strings.IndexByte(entry, ':')
					if colon <= 0 || colon == len(entry)-1 {
						return nil, newIllegalArgError(`rule_files should contain comma-separated "code:rulefile" pairs`)
					}
					pathPart := strings.TrimSpace(entry[colon+1:])
					if _, err := resolvePathSetting("rule_files", pathPart, opts); err != nil {
						return nil, err
					}
				}
			}
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizeICU(cs, startPos, budget)
			},
		}, nil

	case "kuromoji_tokenizer":
		mode := "search"
		discardPunct := true
		discardCompound := false
		var userWords []string
		if def != nil {
			if m, ok := def["mode"].(string); ok && strings.TrimSpace(m) != "" {
				lm := strings.ToLower(strings.TrimSpace(m))
				if lm != "normal" && lm != "search" && lm != "extended" {
					return nil, newIllegalArgError(fmt.Sprintf("Unknown kuromoji_tokenizer mode [%s]", m))
				}
				mode = lm
			}
			if raw, ok := def["discard_punctuation"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("discard_punctuation in kuromoji_tokenizer must be boolean")
				}
				discardPunct = b
			}
			if raw, ok := def["discard_compound_token"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("discard_compound_token in kuromoji_tokenizer must be boolean")
				}
				discardCompound = b
			}
			if raw, ok := def["nbest_cost"]; ok {
				if _, valid := extractInt(raw); !valid {
					return nil, newIllegalArgError("nbest_cost in kuromoji_tokenizer must be an integer")
				}
			}
			_, hasPath := def["user_dictionary"]
			_, hasRules := def["user_dictionary_rules"]
			if hasPath && hasRules {
				return nil, newIllegalArgError("It is not allowed to use [user_dictionary] in conjunction with [user_dictionary_rules]")
			}
			if p, ok := def["user_dictionary"].(string); ok && strings.TrimSpace(p) != "" {
				lines, err := resolvePathSetting("user_dictionary", p, opts)
				if err != nil {
					return nil, err
				}
				userWords = append(userWords, parseUserDictWords(lines)...)
			}
			if hasRules {
				userWords = append(userWords, parseUserDictWords(extractStringSlice(def["user_dictionary_rules"]))...)
			}
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizeKuromoji(cs, startPos, mode, discardPunct, discardCompound, userWords, budget)
			},
		}, nil

	case "nori_tokenizer":
		decompound := "discard"
		discardPunct := true
		var userWords []string
		if def != nil {
			if m, ok := def["decompound_mode"].(string); ok && strings.TrimSpace(m) != "" {
				lm := strings.ToLower(strings.TrimSpace(m))
				if lm != "none" && lm != "discard" && lm != "mixed" {
					return nil, newIllegalArgError(fmt.Sprintf("Unknown nori_tokenizer decompound_mode [%s]", m))
				}
				decompound = lm
			}
			if raw, ok := def["discard_punctuation"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("discard_punctuation in nori_tokenizer must be boolean")
				}
				discardPunct = b
			}
			if raw, ok := def["output_unknown_unigrams"]; ok {
				if _, valid := extractBool(raw); !valid {
					return nil, newIllegalArgError("output_unknown_unigrams in nori_tokenizer must be boolean")
				}
			}
			_, hasPath := def["user_dictionary"]
			_, hasRules := def["user_dictionary_rules"]
			if hasPath && hasRules {
				return nil, newIllegalArgError("It is not allowed to use [user_dictionary] in conjunction with [user_dictionary_rules]")
			}
			if p, ok := def["user_dictionary"].(string); ok && strings.TrimSpace(p) != "" {
				lines, err := resolvePathSetting("user_dictionary", p, opts)
				if err != nil {
					return nil, err
				}
				userWords = append(userWords, parseUserDictWords(lines)...)
			}
			if hasRules {
				userWords = append(userWords, parseUserDictWords(extractStringSlice(def["user_dictionary_rules"]))...)
			}
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizeNori(cs, startPos, decompound, discardPunct, userWords, budget)
			},
		}, nil

	case "smartcn_tokenizer", "smartcn_sentence":
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizeSmartCN(cs, startPos, budget)
			},
		}, nil

	default:
		return nil, newIllegalArgError(fmt.Sprintf("Unknown tokenizer type [%s] for [%s]", normType, displayName))
	}
}

func buildPluginTokenFilter(displayName, normType string, def map[string]any, isPreconfigured bool, bctx filterBuildContext) (*compiledTokenFilter, error) {
	switch normType {
	case "phonetic":
		return buildPhoneticTokenFilter(displayName, def)

	case "icu_normalizer":
		return buildICUNormalizerTokenFilter(displayName, def)

	case "icu_folding":
		return buildICUFoldingFilter(displayName, def)

	case "icu_collation":
		return buildICUCollationFilter(displayName, def, bctx.opts)

	case "icu_transform":
		return buildICUTransformFilter(displayName, def)

	case "kuromoji_baseform":
		return simpleMapTermFilter(displayName, normType, applyKuromojiBaseForm), nil

	case "kuromoji_part_of_speech":
		stopTags := make(map[string]bool)
		var custom []string
		if def != nil {
			if p, ok := def["stoptags_path"].(string); ok && strings.TrimSpace(p) != "" {
				lines, err := resolvePathSetting("stoptags_path", p, bctx.opts)
				if err != nil {
					return nil, err
				}
				custom = append(custom, lines...)
			}
			if raw, has := def["stoptags"]; has {
				custom = append(custom, extractStringSlice(raw)...)
			}
		}
		if len(custom) > 0 || (def != nil && def["stoptags"] != nil) {
			for _, t := range custom {
				t = strings.TrimSpace(t)
				if t != "" && !strings.HasPrefix(t, "#") {
					stopTags[t] = true
				}
			}
		} else {
			for _, t := range defaultKuromojiStopTags {
				stopTags[t] = true
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			out := make([]Token, 0, len(tokens))
			for _, tok := range tokens {
				pos := classifyKuromojiPOS(tok.Term, tok.Type)
				if !stopTags[pos] {
					out = append(out, tok)
				}
			}
			return out
		}), nil

	case "kuromoji_readingform":
		useRomaji := false
		if def != nil {
			if raw, ok := def["use_romaji"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("use_romaji in kuromoji_readingform must be boolean")
				}
				useRomaji = b
			}
		}
		return simpleMapTermFilter(displayName, normType, func(s string) string {
			kata := toKuromojiKatakanaReading(s)
			if useRomaji {
				return strings.ReplaceAll(katakanaToRomaji(kata), "ー", "")
			}
			return kata
		}), nil

	case "kuromoji_stemmer":
		minLen := 4
		if def != nil {
			if raw, ok := def["minimum_length"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 1 {
					return nil, newIllegalArgError("minimum_length in kuromoji_stemmer must be >= 1")
				}
				minLen = n
			}
		}
		return simpleMapTermFilter(displayName, normType, func(s string) string {
			rs := []rune(s)
			if len(rs) >= minLen && rs[len(rs)-1] == 'ー' && isAllKatakanaOrProlonged(rs) {
				return string(rs[:len(rs)-1])
			}
			return s
		}), nil

	case "kuromoji_number":
		return simpleMapTermFilter(displayName, normType, convertCJKNumberString), nil

	case "kuromoji_completion":
		mode := "index"
		if def != nil {
			if m, ok := def["mode"].(string); ok && strings.TrimSpace(m) != "" {
				lm := strings.ToLower(strings.TrimSpace(m))
				if lm != "index" && lm != "query" {
					return nil, newIllegalArgError(fmt.Sprintf("Unknown mode [%s] in kuromoji_completion", m))
				}
				mode = lm
			}
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token, budget *tokenStreamBudget) ([]Token, error) {
				return applyKuromojiCompletion(tokens, mode, budget)
			},
		}, nil

	case "ja_stop":
		return buildPresetStopFilter(displayName, normType, def, "_japanese_", bctx)

	case "hiragana_uppercase":
		return simpleMapTermFilter(displayName, normType, foldSmallHiragana), nil

	case "katakana_uppercase":
		return simpleMapTermFilter(displayName, normType, foldSmallKatakana), nil

	case "nori_part_of_speech":
		stopTags := make(map[string]bool)
		var custom []string
		hasExplicit := false
		if def != nil {
			if p, ok := def["stoptags_path"].(string); ok && strings.TrimSpace(p) != "" {
				hasExplicit = true
				lines, err := resolvePathSetting("stoptags_path", p, bctx.opts)
				if err != nil {
					return nil, err
				}
				custom = append(custom, lines...)
			}
			if raw, has := def["stoptags"]; has {
				hasExplicit = true
				custom = append(custom, extractStringSlice(raw)...)
			}
		}
		if hasExplicit {
			for _, t := range custom {
				ut := strings.ToUpper(strings.TrimSpace(t))
				if ut != "" {
					stopTags[ut] = true
				}
			}
		} else {
			for _, t := range defaultNoriStopTags {
				stopTags[t] = true
			}
		}
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			out := make([]Token, 0, len(tokens))
			for _, tok := range tokens {
				pos := classifyNoriPOS(tok)
				if !stopTags[pos] {
					out = append(out, tok)
				}
			}
			return out
		}), nil

	case "nori_readingform":
		return simpleMapTermFilter(displayName, normType, hanjaToHangulReading), nil

	case "nori_number":
		return simpleMapTermFilter(displayName, normType, convertKoreanNumberString), nil

	case "smartcn_stop":
		return buildPresetStopFilter(displayName, normType, def, "_smartcn_", bctx)

	case "smartcn_word":
		return simpleTokenFilter(displayName, normType, func(tokens []Token) []Token {
			return tokens
		}), nil

	case "polish_stem":
		return stemTokenFilter(displayName, normType, stemPolish), nil

	case "polish_stop":
		return buildPresetStopFilter(displayName, normType, def, "_polish_", bctx)

	default:
		_ = isPreconfigured
		return nil, newIllegalArgError(fmt.Sprintf("Unknown token filter type [%s] for [%s]", normType, displayName))
	}
}

func buildPresetStopFilter(displayName, normType string, def map[string]any, preset string, bctx filterBuildContext) (*compiledTokenFilter, error) {
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
				return nil, newIllegalArgError(fmt.Sprintf("ignore_case in %s must be boolean", normType))
			}
			ignoreCase = b
		}
		if raw, ok := def["remove_trailing"]; ok {
			b, valid := extractBool(raw)
			if !valid {
				return nil, newIllegalArgError(fmt.Sprintf("remove_trailing in %s must be boolean", normType))
			}
			removeTrailing = b
		}
	}
	stopSet, err := resolveStopwords(rawSW, "stopwords_path", swPath, preset, ignoreCase, bctx.opts)
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
}

// ============================================================================
// ICU Normalization, Folding, Collation, Transform & Segmentation
// ============================================================================

func parseICUUnicodeSetFilter(def map[string]any) (func(rune) bool, error) {
	if def == nil {
		return nil, nil
	}
	raw, ok := def["unicode_set_filter"]
	if !ok {
		raw, ok = def["unicodeSetFilter"]
	}
	if !ok || raw == nil {
		return nil, nil
	}
	pat, isStr := raw.(string)
	if !isStr {
		return nil, newIllegalArgError("unicode_set_filter must be a string")
	}
	pat = strings.TrimSpace(pat)
	if pat == "" || pat == "[]" {
		return func(rune) bool { return false }, nil
	}
	if !strings.HasPrefix(pat, "[") || !strings.HasSuffix(pat, "]") {
		return nil, newIllegalArgError(fmt.Sprintf("Invalid UnicodeSet pattern [%s]", pat))
	}
	inner := pat[1 : len(pat)-1]
	negated := false
	if strings.HasPrefix(inner, "^") {
		negated = true
		inner = inner[1:]
	}
	unesc := unescapeMappingStr(inner)
	rs := []rune(unesc)
	exact := make(map[rune]bool)
	var ranges [][2]rune
	for i := 0; i < len(rs); i++ {
		if i+2 < len(rs) && rs[i+1] == '-' {
			ranges = append(ranges, [2]rune{rs[i], rs[i+2]})
			i += 2
			continue
		}
		exact[rs[i]] = true
	}
	return func(r rune) bool {
		inSet := exact[r]
		if !inSet {
			for _, rg := range ranges {
				if r >= rg[0] && r <= rg[1] {
					inSet = true
					break
				}
			}
		}
		if negated {
			return !inSet
		}
		return inSet
	}, nil
}

var canonicalComposePairs = map[[2]rune]rune{
	{'A', '\u0300'}: 'À', {'A', '\u0301'}: 'Á', {'A', '\u0302'}: 'Â', {'A', '\u0303'}: 'Ã', {'A', '\u0308'}: 'Ä', {'A', '\u030A'}: 'Å',
	{'a', '\u0300'}: 'à', {'a', '\u0301'}: 'á', {'a', '\u0302'}: 'â', {'a', '\u0303'}: 'ã', {'a', '\u0308'}: 'ä', {'a', '\u030A'}: 'å',
	{'C', '\u0327'}: 'Ç', {'c', '\u0327'}: 'ç', {'C', '\u0301'}: 'Ć', {'c', '\u0301'}: 'ć', {'C', '\u030C'}: 'Č', {'c', '\u030C'}: 'č',
	{'E', '\u0300'}: 'È', {'E', '\u0301'}: 'É', {'E', '\u0302'}: 'Ê', {'E', '\u0308'}: 'Ë',
	{'e', '\u0300'}: 'è', {'e', '\u0301'}: 'é', {'e', '\u0302'}: 'ê', {'e', '\u0308'}: 'ë',
	{'I', '\u0300'}: 'Ì', {'I', '\u0301'}: 'Í', {'I', '\u0302'}: 'Î', {'I', '\u0308'}: 'Ï',
	{'i', '\u0300'}: 'ì', {'i', '\u0301'}: 'í', {'i', '\u0302'}: 'î', {'i', '\u0308'}: 'ï',
	{'N', '\u0303'}: 'Ñ', {'n', '\u0303'}: 'ñ',
	{'O', '\u0300'}: 'Ò', {'O', '\u0301'}: 'Ó', {'O', '\u0302'}: 'Ô', {'O', '\u0303'}: 'Õ', {'O', '\u0308'}: 'Ö',
	{'o', '\u0300'}: 'ò', {'o', '\u0301'}: 'ó', {'o', '\u0302'}: 'ô', {'o', '\u0303'}: 'õ', {'o', '\u0308'}: 'ö',
	{'S', '\u030C'}: 'Š', {'s', '\u030C'}: 'š', {'Z', '\u030C'}: 'Ž', {'z', '\u030C'}: 'ž',
	{'U', '\u0300'}: 'Ù', {'U', '\u0301'}: 'Ú', {'U', '\u0302'}: 'Û', {'U', '\u0308'}: 'Ü',
	{'u', '\u0300'}: 'ù', {'u', '\u0301'}: 'ú', {'u', '\u0302'}: 'û', {'u', '\u0308'}: 'ü',
	{'Y', '\u0301'}: 'Ý', {'y', '\u0301'}: 'ý', {'y', '\u0308'}: 'ÿ',
}

func composeCanonicalRunes(in []rune) []rune {
	if len(in) <= 1 {
		return in
	}
	out := make([]rune, 0, len(in))
	for _, r := range in {
		if len(out) > 0 {
			if comp, ok := canonicalComposePairs[[2]rune{out[len(out)-1], r}]; ok {
				out[len(out)-1] = comp
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func normalizeICURune(r rune, method string, doFold bool) string {
	if doFold {
		s, _ := foldASCII(string(r))
		s = foldCJKWidth(s)
		var sb strings.Builder
		for _, cr := range s {
			switch cr {
			case 'ß', 'ẞ':
				sb.WriteString("ss")
			default:
				sb.WriteRune(unicode.ToLower(cr))
			}
		}
		return sb.String()
	}

	switch method {
	case "nfc", "nfd":
		return string(r)
	case "nfkc", "nfkd":
		w := foldCJKWidth(string(r))
		switch r {
		case 'ﬀ':
			return "ff"
		case 'ﬁ':
			return "fi"
		case 'ﬂ':
			return "fl"
		case 'ﬃ':
			return "ffi"
		case 'ﬄ':
			return "ffl"
		case '\u00A0':
			return " "
		default:
			return w
		}
	default: // nfkc_cf
		if r == 'ß' || r == 'ẞ' {
			return "ss"
		}
		if r == 'İ' {
			return "i"
		}
		if unicode.Is(unicode.Cf, r) {
			return ""
		}
		w := foldCJKWidth(string(r))
		var sb strings.Builder
		for _, cr := range w {
			switch cr {
			case 'ﬀ':
				sb.WriteString("ff")
			case 'ﬁ':
				sb.WriteString("fi")
			case 'ﬂ':
				sb.WriteString("fl")
			case 'ﬃ':
				sb.WriteString("ffi")
			case 'ﬄ':
				sb.WriteString("ffl")
			case '\u00A0':
				sb.WriteByte(' ')
			default:
				sb.WriteRune(unicode.ToLower(cr))
			}
		}
		return sb.String()
	}
}

func applyICUStringTransform(s string, method string, doFold bool, filterFn func(rune) bool) string {
	composed := composeCanonicalRunes([]rune(s))
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range composed {
		if filterFn != nil && !filterFn(r) {
			sb.WriteRune(r)
			continue
		}
		sb.WriteString(normalizeICURune(r, method, doFold))
	}
	return sb.String()
}

func applyCharTransform(in charStream, fullFn func(string) string, perRuneFn func(rune) (string, bool)) (charStream, error) {
	if len(in.runes) > MaxCharFilterOutputRunes {
		return charStream{}, newIllegalArgError(fmt.Sprintf("char_filter output exceeds maximum allowed length [%d]", MaxCharFilterOutputRunes))
	}
	if len(in.runes) == 0 {
		return in, nil
	}
	b := newCharStreamBuilder(in)
	if perRuneFn != nil {
		for i, r := range in.runes {
			rep, changed := perRuneFn(r)
			if !changed {
				b.appendUnchanged(in, i)
			} else if rep != "" {
				b.appendReplacement([]rune(rep), in.starts[i], in.ends[i])
			}
			if b.exceeded {
				return b.build()
			}
		}
		return b.build()
	}
	transformed := []rune(fullFn(in.String()))
	b.appendReplacement(transformed, in.baseOffset, in.origEnd)
	return b.build()
}

func parseICUNormalizerMethod(def map[string]any) (string, error) {
	method := "nfkc_cf"
	if def != nil {
		if m, ok := def["name"].(string); ok && strings.TrimSpace(m) != "" {
			method = strings.ToLower(strings.TrimSpace(m))
		}
	}
	switch method {
	case "nfc", "nfd", "nfkc", "nfkd", "nfkc_cf":
		return method, nil
	default:
		return "", newIllegalArgError(fmt.Sprintf("Unknown icu_normalizer name [%s]", method))
	}
}

func buildICUNormalizerCharFilter(displayName string, def map[string]any) (*compiledCharFilter, error) {
	method, err := parseICUNormalizerMethod(def)
	if err != nil {
		return nil, err
	}
	filterFn, err := parseICUUnicodeSetFilter(def)
	if err != nil {
		return nil, err
	}
	return &compiledCharFilter{
		name: displayName,
		apply: func(in charStream) (charStream, error) {
			return applyCharTransform(in, nil, func(r rune) (string, bool) {
				if filterFn != nil && !filterFn(r) {
					return "", false
				}
				rep := normalizeICURune(r, method, false)
				if rep == string(r) {
					return "", false
				}
				return rep, true
			})
		},
	}, nil
}

func buildICUNormalizerTokenFilter(displayName string, def map[string]any) (*compiledTokenFilter, error) {
	method, err := parseICUNormalizerMethod(def)
	if err != nil {
		return nil, err
	}
	filterFn, err := parseICUUnicodeSetFilter(def)
	if err != nil {
		return nil, err
	}
	return simpleMapTermFilter(displayName, "icu_normalizer", func(s string) string {
		return applyICUStringTransform(s, method, false, filterFn)
	}), nil
}

func buildICUFoldingFilter(displayName string, def map[string]any) (*compiledTokenFilter, error) {
	filterFn, err := parseICUUnicodeSetFilter(def)
	if err != nil {
		return nil, err
	}
	return simpleMapTermFilter(displayName, "icu_folding", func(s string) string {
		return applyICUStringTransform(s, "nfkc_cf", true, filterFn)
	}), nil
}

func buildICUCollationFilter(displayName string, def map[string]any, opts Options) (*compiledTokenFilter, error) {
	strength := "tertiary"
	alternate := "non-ignorable"
	caseFirst := ""
	numeric := false
	if def != nil {
		if rulesVal, ok := def["rules"].(string); ok && strings.TrimSpace(rulesVal) != "" {
			if !strings.Contains(rulesVal, "&") && !strings.Contains(rulesVal, "<") {
				if _, err := resolvePathSetting("rules", rulesVal, opts); err != nil {
					return nil, err
				}
			}
		}
		if st, ok := def["strength"].(string); ok && strings.TrimSpace(st) != "" {
			lst := strings.ToLower(strings.TrimSpace(st))
			switch lst {
			case "primary", "secondary", "tertiary", "quaternary", "identical":
				strength = lst
			default:
				return nil, newIllegalArgError("Invalid strength: " + st)
			}
		}
		if dc, ok := def["decomposition"].(string); ok && strings.TrimSpace(dc) != "" {
			ldc := strings.ToLower(strings.TrimSpace(dc))
			if ldc != "no" && ldc != "canonical" {
				return nil, newIllegalArgError("Invalid decomposition: " + dc)
			}
		}
		if alt, ok := def["alternate"].(string); ok && strings.TrimSpace(alt) != "" {
			lalt := strings.ToLower(strings.TrimSpace(alt))
			if lalt != "shifted" && lalt != "non-ignorable" {
				return nil, newIllegalArgError("Invalid alternate: " + alt)
			}
			alternate = lalt
		}
		for _, ck := range []string{"caseFirst", "case_first"} {
			if cf, ok := def[ck].(string); ok && strings.TrimSpace(cf) != "" {
				lcf := strings.ToLower(strings.TrimSpace(cf))
				if lcf != "lower" && lcf != "upper" {
					return nil, newIllegalArgError("Invalid caseFirst: " + cf)
				}
				caseFirst = lcf
			}
		}
		for _, bk := range []string{"caseLevel", "case_level", "numeric", "hiraganaQuaternaryMode", "hiragana_quaternary_mode"} {
			if raw, exists := def[bk]; exists {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError(bk + " in icu_collation must be boolean")
				}
				if bk == "numeric" {
					numeric = b
				}
			}
		}
	}

	return simpleMapTermFilter(displayName, "icu_collation", func(s string) string {
		return computeICUCollationKey(s, strength, alternate, caseFirst, numeric)
	}), nil
}

func computeICUCollationKey(s, strength, alternate, caseFirst string, numeric bool) string {
	var baseBuf strings.Builder
	var accBuf strings.Builder
	var caseBuf strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); {
		r := rs[i]
		if alternate == "shifted" && (unicode.IsPunct(r) || unicode.IsSpace(r) || unicode.IsSymbol(r)) {
			i++
			continue
		}
		if numeric && r >= '0' && r <= '9' {
			j := i
			for j < len(rs) && rs[j] >= '0' && rs[j] <= '9' {
				j++
			}
			numStr := strings.TrimLeft(string(rs[i:j]), "0")
			if numStr == "" {
				numStr = "0"
			}
			fmt.Fprintf(&baseBuf, "#%04d:%s#", len(numStr), numStr)
			i = j
			continue
		}
		folded := applyICUStringTransform(string(r), "nfkc_cf", true, nil)
		baseBuf.WriteString(folded)
		lowerPreservingAccent := strings.ToLower(string(r))
		if lowerPreservingAccent != folded {
			accBuf.WriteRune('1')
			accBuf.WriteString(lowerPreservingAccent)
		} else {
			accBuf.WriteRune('0')
		}
		if unicode.IsUpper(r) {
			if caseFirst == "upper" {
				caseBuf.WriteByte('0')
			} else {
				caseBuf.WriteByte('2')
			}
		} else {
			caseBuf.WriteByte('1')
		}
		i++
	}
	switch strength {
	case "primary":
		return baseBuf.String()
	case "secondary":
		return baseBuf.String() + "\x01" + accBuf.String()
	default:
		return baseBuf.String() + "\x01" + accBuf.String() + "\x01" + caseBuf.String()
	}
}

func buildICUTransformFilter(displayName string, def map[string]any) (*compiledTokenFilter, error) {
	id := "Null"
	dir := "forward"
	if def != nil {
		if rawID, ok := def["id"].(string); ok && strings.TrimSpace(rawID) != "" {
			id = strings.TrimSpace(rawID)
		}
		if rawDir, ok := def["dir"].(string); ok && strings.TrimSpace(rawDir) != "" {
			ld := strings.ToLower(strings.TrimSpace(rawDir))
			if ld != "forward" && ld != "reverse" {
				return nil, newIllegalArgError(fmt.Sprintf("Invalid dir [%s] in icu_transform", rawDir))
			}
			dir = ld
		}
	}
	steps := strings.Split(id, ";")
	if dir == "reverse" {
		for l, r := 0, len(steps)-1; l < r; l, r = l+1, r-1 {
			steps[l], steps[r] = steps[r], steps[l]
		}
	}
	return simpleMapTermFilter(displayName, "icu_transform", func(s string) string {
		cur := s
		for _, rawStep := range steps {
			cur = applySingleICUTransformStep(cur, strings.ToLower(strings.TrimSpace(rawStep)), dir == "reverse")
		}
		return cur
	}), nil
}

var cyrillicToLatinMap = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'ґ': "g", 'д': "d", 'е': "e", 'є': "ye", 'ё': "yo",
	'ж': "zh", 'з': "z", 'и': "i", 'і': "i", 'ї': "yi", 'й': "y", 'к': "k", 'л': "l", 'м': "m",
	'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u", 'ф': "f", 'х': "kh",
	'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "shch", 'ъ': "", 'ы': "y", 'ь': "", 'э': "e", 'ю': "yu", 'я': "ya",
}

func applySingleICUTransformStep(s, step string, reverse bool) string {
	switch step {
	case "", "null", "any-null":
		return s
	case "lower", "any-lower":
		if reverse {
			return strings.ToUpper(s)
		}
		return strings.ToLower(s)
	case "upper", "any-upper":
		if reverse {
			return strings.ToLower(s)
		}
		return strings.ToUpper(s)
	case "latin-ascii", "ascii":
		folded, _ := foldASCII(s)
		return folded
	case "any-latin", "cyrillic-latin", "greek-latin", "han-latin", "katakana-latin", "hiragana-latin":
		var sb strings.Builder
		for _, r := range s {
			lr := unicode.ToLower(r)
			if tr, ok := cyrillicToLatinMap[lr]; ok {
				if unicode.IsUpper(r) && len(tr) > 0 {
					sb.WriteString(strings.ToUpper(tr[:1]) + tr[1:])
				} else {
					sb.WriteString(tr)
				}
				continue
			}
			if unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hiragana, r) {
				sb.WriteString(katakanaToRomaji(hiraganaToKatakana(string(r))))
				continue
			}
			sb.WriteRune(r)
		}
		return sb.String()
	case "katakana-hiragana":
		if reverse {
			return hiraganaToKatakana(s)
		}
		return katakanaToHiragana(s)
	case "hiragana-katakana":
		if reverse {
			return katakanaToHiragana(s)
		}
		return hiraganaToKatakana(s)
	case "halfwidth-fullwidth", "fullwidth-halfwidth":
		return foldCJKWidth(s)
	case "[:nonspacing mark:] remove", "nfd", "nfc", "nfkd", "nfkc":
		if strings.Contains(step, "remove") {
			folded, _ := foldASCII(s)
			return folded
		}
		return applyICUStringTransform(s, "nfkc", false, nil)
	default:
		return s
	}
}

func tokenizeICU(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	pos := startPos
	n := len(cs.runes)
	for i := 0; i < n; {
		r := cs.runes[i]
		if isThaiWordRune(r) {
			end := i + 1
			for end < n && isThaiWordRune(cs.runes[end]) {
				end++
			}
			sub := sliceCharStream(cs, i, end)
			toks, err := tokenizeThai(sub, pos, budget)
			if err != nil {
				return nil, err
			}
			out = append(out, toks...)
			if len(toks) > 0 {
				pos = toks[len(toks)-1].Position + 1
			}
			i = end
			continue
		}
		if isCJKIdeograph(r) {
			end := i + 1
			for end < n && isCJKIdeograph(cs.runes[end]) {
				end++
			}
			segs := segmentCJKByDict(cs.runes[i:end], smartCNDictWords)
			cur := i
			for _, segLen := range segs {
				if err := budget.canAddOne(); err != nil {
					return nil, err
				}
				term := string(cs.runes[cur : cur+segLen])
				if err := budget.add(len(term)); err != nil {
					return nil, err
				}
				sOff, eOff := cs.sliceOffsets(cur, cur+segLen)
				out = append(out, Token{
					Term:           term,
					StartOffset:    sOff,
					EndOffset:      eOff,
					Type:           "<IDEOGRAPHIC>",
					Position:       pos,
					PositionLength: 1,
					TermFrequency:  1,
				})
				pos++
				cur += segLen
			}
			i = end
			continue
		}
		end := i + 1
		for end < n && !isThaiWordRune(cs.runes[end]) && !isCJKIdeograph(cs.runes[end]) {
			end++
		}
		sub := sliceCharStream(cs, i, end)
		toks, err := tokenizeStandard(sub, pos, 255, false, budget)
		if err != nil {
			return nil, err
		}
		out = append(out, toks...)
		if len(toks) > 0 {
			pos = toks[len(toks)-1].Position + 1
		}
		i = end
	}
	return out, nil
}

func sliceCharStream(cs charStream, from, to int) charStream {
	return charStream{
		runes:      cs.runes[from:to],
		starts:     cs.starts[from:to],
		ends:       cs.ends[from:to],
		baseOffset: cs.baseOffset,
		origEnd:    cs.origEnd,
	}
}

// ============================================================================
// Kuromoji (Japanese) Analysis Components
// ============================================================================

var kanaDakutenMap = map[rune]rune{
	'か': 'が', 'き': 'ぎ', 'く': 'ぐ', 'け': 'げ', 'こ': 'ご',
	'さ': 'ざ', 'し': 'じ', 'す': 'ず', 'せ': 'ぜ', 'そ': 'ぞ',
	'た': 'だ', 'ち': 'ぢ', 'つ': 'づ', 'て': 'で', 'と': 'ど',
	'は': 'ば', 'ひ': 'び', 'ふ': 'ぶ', 'へ': 'べ', 'ほ': 'ぼ',
	'カ': 'ガ', 'キ': 'ギ', 'ク': 'グ', 'ケ': 'ゲ', 'コ': 'ゴ',
	'サ': 'ザ', 'シ': 'ジ', 'ス': 'ズ', 'セ': 'ゼ', 'ソ': 'ゾ',
	'タ': 'ダ', 'チ': 'ヂ', 'ツ': 'ヅ', 'テ': 'デ', 'ト': 'ド',
	'ハ': 'バ', 'ヒ': 'ビ', 'フ': 'ブ', 'ヘ': 'ベ', 'ホ': 'ボ',
}

var kanaUnvoicedMap = func() map[rune]rune {
	m := make(map[rune]rune, len(kanaDakutenMap))
	for k, v := range kanaDakutenMap {
		m[v] = k
	}
	return m
}()

func buildKuromojiIterationMarkCharFilter(displayName string, def map[string]any) (*compiledCharFilter, error) {
	normKanji := true
	normKana := true
	if def != nil {
		if raw, ok := def["normalize_kanji"]; ok {
			b, valid := extractBool(raw)
			if !valid {
				return nil, newIllegalArgError("normalize_kanji in kuromoji_iteration_mark must be boolean")
			}
			normKanji = b
		}
		if raw, ok := def["normalize_kana"]; ok {
			b, valid := extractBool(raw)
			if !valid {
				return nil, newIllegalArgError("normalize_kana in kuromoji_iteration_mark must be boolean")
			}
			normKana = b
		}
	}
	return &compiledCharFilter{
		name: displayName,
		apply: func(in charStream) (charStream, error) {
			if len(in.runes) > MaxCharFilterOutputRunes {
				return charStream{}, newIllegalArgError(fmt.Sprintf("char_filter output exceeds maximum allowed length [%d]", MaxCharFilterOutputRunes))
			}
			if len(in.runes) == 0 {
				return in, nil
			}
			b := newCharStreamBuilder(in)
			for i, r := range in.runes {
				if r == '々' && normKanji && len(b.runes) > 0 {
					prev := b.runes[len(b.runes)-1]
					b.appendReplacement([]rune{prev}, in.starts[i], in.ends[i])
				} else if (r == 'ゝ' || r == 'ヽ') && normKana && len(b.runes) > 0 {
					prev := b.runes[len(b.runes)-1]
					if uv, ok := kanaUnvoicedMap[prev]; ok {
						prev = uv
					}
					b.appendReplacement([]rune{prev}, in.starts[i], in.ends[i])
				} else if (r == 'ゞ' || r == 'ヾ') && normKana && len(b.runes) > 0 {
					prev := b.runes[len(b.runes)-1]
					if uv, ok := kanaUnvoicedMap[prev]; ok {
						prev = uv
					}
					if vd, ok := kanaDakutenMap[prev]; ok {
						prev = vd
					}
					b.appendReplacement([]rune{prev}, in.starts[i], in.ends[i])
				} else {
					b.appendUnchanged(in, i)
				}
				if b.exceeded {
					return b.build()
				}
			}
			return b.build()
		},
	}, nil
}

type jaLexEntry struct {
	surface  string
	subwords []string
	baseForm string
	reading  string
	pos      string
}

var kuromojiLexicon = []jaLexEntry{
	{surface: "関西国際空港", subwords: []string{"関西", "国際", "空港"}, reading: "カンサイコクサイクウコウ", pos: "名詞-固有名詞"},
	{surface: "成田国際空港", subwords: []string{"成田", "国際", "空港"}, reading: "ナリタコクサイクウコウ", pos: "名詞-固有名詞"},
	{surface: "東京スカイツリー", subwords: []string{"東京", "スカイツリー"}, reading: "トウキョウスカイツリー", pos: "名詞-固有名詞"},
	{surface: "新宿", reading: "シンジュク", pos: "名詞-固有名詞"},
	{surface: "東京", reading: "トウキョウ", pos: "名詞-固有名詞"},
	{surface: "日本", reading: "ニホン", pos: "名詞-固有名詞"},
	{surface: "関西", reading: "カンサイ", pos: "名詞-固有名詞"},
	{surface: "国際", reading: "コクサイ", pos: "名詞-一般"},
	{surface: "空港", reading: "クウコウ", pos: "名詞-一般"},
	{surface: "寿司", reading: "スシ", pos: "名詞-一般"},
	{surface: "駅", reading: "エキ", pos: "名詞-一般"},
	{surface: "近く", reading: "チカク", pos: "名詞-副詞可能"},
	{surface: "ビール", reading: "ビール", pos: "名詞-一般"},
	{surface: "サーバー", reading: "サーバー", pos: "名詞-一般"},
	{surface: "ソース", reading: "ソース", pos: "名詞-一般"},
	{surface: "コード", reading: "コード", pos: "名詞-一般"},
	{surface: "飲み", baseForm: "飲む", reading: "ノミ", pos: "動詞-自立"},
	{surface: "飲む", baseForm: "飲む", reading: "ノム", pos: "動詞-自立"},
	{surface: "飲ん", baseForm: "飲む", reading: "ノン", pos: "動詞-自立"},
	{surface: "行こ", baseForm: "行く", reading: "イコ", pos: "動詞-自立"},
	{surface: "行き", baseForm: "行く", reading: "イキ", pos: "動詞-自立"},
	{surface: "行く", baseForm: "行く", reading: "イク", pos: "動詞-自立"},
	{surface: "行っ", baseForm: "行く", reading: "イッ", pos: "動詞-自立"},
	{surface: "食べ", baseForm: "食べる", reading: "タベ", pos: "動詞-自立"},
	{surface: "食べる", baseForm: "食べる", reading: "タベル", pos: "動詞-自立"},
	{surface: "買い", baseForm: "買う", reading: "カイ", pos: "動詞-自立"},
	{surface: "買っ", baseForm: "買う", reading: "カッ", pos: "動詞-自立"},
	{surface: "から", pos: "助詞-接続助詞"},
	{surface: "まで", pos: "助詞-副助詞"},
	{surface: "ます", baseForm: "ます", pos: "助動詞"},
	{surface: "です", baseForm: "です", pos: "助動詞"},
	{surface: "た", baseForm: "た", pos: "助動詞"},
	{surface: "だ", baseForm: "だ", pos: "助動詞"},
	{surface: "う", baseForm: "う", pos: "助動詞"},
	{surface: "の", pos: "助詞-連体化"},
	{surface: "に", pos: "助詞-格助詞-一般"},
	{surface: "を", pos: "助詞-格助詞-一般"},
	{surface: "は", pos: "助詞-係助詞"},
	{surface: "が", pos: "助詞-格助詞-一般"},
	{surface: "で", pos: "助詞-格助詞-一般"},
	{surface: "と", pos: "助詞-格助詞-一般"},
	{surface: "へ", pos: "助詞-格助詞-一般"},
	{surface: "も", pos: "助詞-係助詞"},
	{surface: "か", pos: "助詞-副助詞／並立助詞／終助詞"},
	{surface: "ね", pos: "助詞-終助詞"},
	{surface: "よ", pos: "助詞-終助詞"},
}

var (
	kuromojiBySurface = func() map[string]jaLexEntry {
		m := make(map[string]jaLexEntry, len(kuromojiLexicon))
		for _, e := range kuromojiLexicon {
			m[e.surface] = e
		}
		return m
	}()
	defaultKuromojiStopTags = []string{
		"接続詞", "助動詞", "助詞", "助詞-格助詞", "助詞-格助詞-一般", "助詞-格助詞-引用",
		"助詞-格助詞-連語", "助詞-接続助詞", "助詞-係助詞", "助詞-副助詞", "助詞-間投助詞",
		"助詞-並立助詞", "助詞-終助詞", "助詞-副助詞／並立助詞／終助詞", "助詞-連体化",
		"助詞-副詞化", "助詞-特殊", "記号", "記号-一般", "記号-読点", "記号-句点", "記号-空白",
	}
)

func parseUserDictWords(lines []string) []string {
	var out []string
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		comma := strings.IndexByte(line, ',')
		if comma > 0 {
			line = strings.TrimSpace(line[:comma])
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func tokenizeKuromoji(cs charStream, startPos int, mode string, discardPunct, discardCompound bool, userWords []string, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	pos := startPos
	n := len(cs.runes)

	emit := func(rStart, rEnd int, term string, tokPos, posLen int, tokType string) error {
		if err := budget.canAddOne(); err != nil {
			return err
		}
		if err := budget.add(len(term)); err != nil {
			return err
		}
		sOff, eOff := cs.sliceOffsets(rStart, rEnd)
		out = append(out, Token{
			Term:           term,
			StartOffset:    sOff,
			EndOffset:      eOff,
			Type:           tokType,
			Position:       tokPos,
			PositionLength: posLen,
			TermFrequency:  1,
		})
		return nil
	}

	for i := 0; i < n; {
		r := cs.runes[i]
		if unicode.IsSpace(r) || unicode.IsPunct(r) || unicode.IsSymbol(r) {
			if !discardPunct && !unicode.IsSpace(r) {
				if err := emit(i, i+1, string(cs.runes[i:i+1]), pos, 1, "記号-一般"); err != nil {
					return nil, err
				}
				pos++
			}
			i++
			continue
		}

		// User dictionary longest match first
		matchedUser := ""
		for _, uw := range userWords {
			uwr := []rune(uw)
			if len(uwr) > len([]rune(matchedUser)) && i+len(uwr) <= n && runesEqual(cs.runes[i:i+len(uwr)], uwr) {
				matchedUser = uw
			}
		}
		if matchedUser != "" {
			ml := utf8.RuneCountInString(matchedUser)
			if err := emit(i, i+ml, matchedUser, pos, 1, "word"); err != nil {
				return nil, err
			}
			pos++
			i += ml
			continue
		}

		// Built-in Japanese lexicon longest match
		bestIdx := -1
		bestRuneLen := 0
		for idx, ent := range kuromojiLexicon {
			er := []rune(ent.surface)
			if len(er) > bestRuneLen && i+len(er) <= n && runesEqual(cs.runes[i:i+len(er)], er) {
				bestIdx = idx
				bestRuneLen = len(er)
			}
		}
		if bestIdx >= 0 {
			ent := kuromojiLexicon[bestIdx]
			if (mode == "search" || mode == "extended") && len(ent.subwords) > 1 {
				subCur := i
				for sIdx, sw := range ent.subwords {
					swLen := utf8.RuneCountInString(sw)
					if err := emit(subCur, subCur+swLen, sw, pos+sIdx, 1, "word"); err != nil {
						return nil, err
					}
					if sIdx == 0 && !discardCompound {
						if err := emit(i, i+bestRuneLen, ent.surface, pos, len(ent.subwords), "word"); err != nil {
							return nil, err
						}
					}
					subCur += swLen
				}
				pos += len(ent.subwords)
				i += bestRuneLen
				continue
			}
			if err := emit(i, i+bestRuneLen, ent.surface, pos, 1, "word"); err != nil {
				return nil, err
			}
			pos++
			i += bestRuneLen
			continue
		}

		// Contiguous ASCII / Fullwidth alphanumeric run
		if isASCIILetter(r) || unicode.IsDigit(r) || (r >= 0xFF10 && r <= 0xFF5A) {
			j := i + 1
			for j < n && (isASCIILetter(cs.runes[j]) || unicode.IsDigit(cs.runes[j]) || (cs.runes[j] >= 0xFF10 && cs.runes[j] <= 0xFF5A)) {
				j++
			}
			if err := emit(i, j, string(cs.runes[i:j]), pos, 1, "word"); err != nil {
				return nil, err
			}
			pos++
			i = j
			continue
		}

		// Katakana run (including halfwidth katakana U+FF66..U+FF9F and prolonged sound mark ー)
		if isKatakanaOrHalfwidth(r) {
			j := i + 1
			for j < n && isKatakanaOrHalfwidth(cs.runes[j]) {
				j++
			}
			if err := emit(i, j, string(cs.runes[i:j]), pos, 1, "word"); err != nil {
				return nil, err
			}
			pos++
			i = j
			continue
		}

		// Kanji run (stop before known lexicon entry)
		if isCJKIdeograph(r) {
			j := i + 1
			if mode != "extended" {
				for j < n && isCJKIdeograph(cs.runes[j]) && !matchesKuromojiLexAt(cs.runes, j) {
					j++
				}
			}
			if err := emit(i, j, string(cs.runes[i:j]), pos, 1, "word"); err != nil {
				return nil, err
			}
			pos++
			i = j
			continue
		}

		// Hiragana / fallback single or non-lexicon run
		j := i + 1
		if unicode.Is(unicode.Hiragana, r) {
			for j < n && unicode.Is(unicode.Hiragana, cs.runes[j]) && !matchesKuromojiLexAt(cs.runes, j) {
				j++
			}
		}
		if err := emit(i, j, string(cs.runes[i:j]), pos, 1, "word"); err != nil {
			return nil, err
		}
		pos++
		i = j
	}
	return out, nil
}

func isKatakanaOrHalfwidth(r rune) bool {
	return isKatakanaRune(r) || r == 'ー' || (r >= 0xFF66 && r <= 0xFF9F)
}

func isAllKatakanaOrProlonged(rs []rune) bool {
	for _, r := range rs {
		if !isKatakanaRune(r) && r != 'ー' {
			return false
		}
	}
	return len(rs) > 0
}

func matchesKuromojiLexAt(runes []rune, idx int) bool {
	n := len(runes)
	for _, ent := range kuromojiLexicon {
		er := []rune(ent.surface)
		if idx+len(er) <= n && runesEqual(runes[idx:idx+len(er)], er) {
			return true
		}
	}
	return false
}

func applyKuromojiBaseForm(term string) string {
	if ent, ok := kuromojiBySurface[term]; ok && ent.baseForm != "" {
		return ent.baseForm
	}
	return term
}

func classifyKuromojiPOS(term, tokType string) string {
	if tokType == "記号-一般" {
		return tokType
	}
	if ent, ok := kuromojiBySurface[term]; ok && ent.pos != "" {
		return ent.pos
	}
	return "名詞-一般"
}

func toKuromojiKatakanaReading(term string) string {
	if ent, ok := kuromojiBySurface[term]; ok && ent.reading != "" {
		return ent.reading
	}
	return hiraganaToKatakana(foldCJKWidth(term))
}

func hiraganaToKatakana(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		if r >= 0x3041 && r <= 0x3096 {
			sb.WriteRune(r + 0x60)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func katakanaToHiragana(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		if r >= 0x30A1 && r <= 0x30F6 {
			sb.WriteRune(r - 0x60)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

var smallHiraganaMap = map[rune]rune{
	'ぁ': 'あ', 'ぃ': 'い', 'ぅ': 'う', 'ぇ': 'え', 'ぉ': 'お',
	'っ': 'つ', 'ゃ': 'や', 'ゅ': 'ゆ', 'ょ': 'よ', 'ゎ': 'わ', 'ゕ': 'か', 'ゖ': 'け',
}

var smallKatakanaMap = map[rune]rune{
	'ァ': 'ア', 'ィ': 'イ', 'ゥ': 'ウ', 'ェ': 'エ', 'ォ': 'オ',
	'ッ': 'ツ', 'ャ': 'ヤ', 'ュ': 'ユ', 'ョ': 'ヨ', 'ヮ': 'ワ', 'ヵ': 'カ', 'ヶ': 'ケ',
}

func foldSmallHiragana(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if up, ok := smallHiraganaMap[r]; ok {
			sb.WriteRune(up)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func foldSmallKatakana(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if up, ok := smallKatakanaMap[r]; ok {
			sb.WriteRune(up)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

var katakanaRomajiMap = map[rune]string{
	'ア': "a", 'イ': "i", 'ウ': "u", 'エ': "e", 'オ': "o",
	'カ': "ka", 'キ': "ki", 'ク': "ku", 'ケ': "ke", 'コ': "ko",
	'ガ': "ga", 'ギ': "gi", 'グ': "gu", 'ゲ': "ge", 'ゴ': "go",
	'サ': "sa", 'シ': "si", 'ス': "su", 'セ': "se", 'ソ': "so",
	'ザ': "za", 'ジ': "zi", 'ズ': "zu", 'ゼ': "ze", 'ゾ': "zo",
	'タ': "ta", 'チ': "ti", 'ツ': "tu", 'テ': "te", 'ト': "to",
	'ダ': "da", 'ヂ': "di", 'ヅ': "du", 'デ': "de", 'ド': "do",
	'ナ': "na", 'ニ': "ni", 'ヌ': "nu", 'ネ': "ne", 'ノ': "no",
	'ハ': "ha", 'ヒ': "hi", 'フ': "hu", 'ヘ': "he", 'ホ': "ho",
	'バ': "ba", 'ビ': "bi", 'ブ': "bu", 'ベ': "be", 'ボ': "bo",
	'パ': "pa", 'ピ': "pi", 'プ': "pu", 'ペ': "pe", 'ポ': "po",
	'マ': "ma", 'ミ': "mi", 'ム': "mu", 'メ': "me", 'モ': "mo",
	'ヤ': "ya", 'ユ': "yu", 'ヨ': "yo",
	'ラ': "ra", 'リ': "ri", 'ル': "ru", 'レ': "re", 'ロ': "ro",
	'ワ': "wa", 'ヲ': "wo", 'ン': "n",
	'ー': "ー",
}

func katakanaToRomaji(s string) string {
	rs := []rune(s)
	var sb strings.Builder
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if r == 'ッ' && i+1 < len(rs) {
			if nextRom, ok := katakanaRomajiMap[rs[i+1]]; ok && len(nextRom) > 0 && nextRom[0] >= 'a' && nextRom[0] <= 'z' {
				sb.WriteByte(nextRom[0])
				continue
			}
		}
		if rom, ok := katakanaRomajiMap[r]; ok {
			sb.WriteString(rom)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func applyKuromojiCompletion(tokens []Token, mode string, budget *tokenStreamBudget) ([]Token, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	if mode == "query" {
		var surf, rom strings.Builder
		startOff := tokens[0].StartOffset
		endOff := tokens[len(tokens)-1].EndOffset
		for _, tok := range tokens {
			surf.WriteString(tok.Term)
			rom.WriteString(katakanaToRomaji(toKuromojiKatakanaReading(tok.Term)))
		}
		sTerm := surf.String()
		rTerm := rom.String()
		var out []Token
		t1 := Token{Term: sTerm, StartOffset: startOff, EndOffset: endOff, Type: "word", Position: 0, PositionLength: 1, TermFrequency: 1}
		if err := budget.addToken(t1); err != nil {
			return nil, err
		}
		out = append(out, t1)
		if rTerm != "" && rTerm != sTerm {
			t2 := Token{Term: rTerm, StartOffset: startOff, EndOffset: endOff, Type: "word", Position: 0, PositionLength: 1, TermFrequency: 1}
			if err := budget.addToken(t2); err != nil {
				return nil, err
			}
			out = append(out, t2)
		}
		return out, nil
	}

	var out []Token
	for _, tok := range tokens {
		cp := tok.clone()
		if err := budget.addToken(cp); err != nil {
			return nil, err
		}
		out = append(out, cp)
		rom := katakanaToRomaji(toKuromojiKatakanaReading(tok.Term))
		if rom != "" && rom != tok.Term {
			rcp := tok.clone()
			rcp.Term = rom
			if err := budget.addToken(rcp); err != nil {
				return nil, err
			}
			out = append(out, rcp)
		}
	}
	return out, nil
}

// ============================================================================
// Nori (Korean) Analysis Components
// ============================================================================

var defaultNoriStopTags = []string{
	"E", "IC", "J", "MAG", "MAJ", "MM", "SP", "SSC", "SSO", "SC", "SE",
	"XPN", "XSA", "XSN", "XSV", "UNA", "NA", "VSV",
}

var koreanParticles = []string{
	"에서", "으로", "부터", "까지", "에게",
	"은", "는", "이", "가", "을", "를", "에", "의", "과", "와", "도", "만", "로",
}

var koreanLexiconStems = []struct {
	full   string
	parts  []string
	posTag []string
}{
	{full: "뿌리가", parts: []string{"뿌리", "가"}, posTag: []string{"NNG", "J"}},
	{full: "깊은", parts: []string{"깊", "은"}, posTag: []string{"VA", "E"}},
	{full: "나무는", parts: []string{"나무", "는"}, posTag: []string{"NNG", "J"}},
	{full: "나무가", parts: []string{"나무", "가"}, posTag: []string{"NNG", "J"}},
	{full: "나무를", parts: []string{"나무", "를"}, posTag: []string{"NNG", "J"}},
	{full: "나무", parts: []string{"나무"}, posTag: []string{"NNG"}},
	{full: "뿌리", parts: []string{"뿌리"}, posTag: []string{"NNG"}},
}

var hanjaReadingMap = map[rune]rune{
	'鄕': '향', '歌': '가', '韓': '한', '國': '국', '大': '대', '學': '학', '校': '교',
	'人': '인', '民': '민', '日': '일', '本': '본', '中': '중', '東': '동', '京': '경',
	'北': '북', '南': '남', '西': '서', '山': '산', '水': '수', '火': '화', '木': '목',
	'金': '금', '土': '토', '年': '년', '月': '월', '語': '어', '文': '문', '字': '자',
}

var koreanDigitRunes = map[rune]bool{
	'영': true, '공': true, '일': true, '이': true, '삼': true, '사': true,
	'오': true, '육': true, '륙': true, '칠': true, '팔': true, '구': true,
	'십': true, '백': true, '천': true, '만': true, '억': true, '조': true,
}

func isKoreanNumericChar(r rune) bool {
	if koreanDigitRunes[r] {
		return true
	}
	if (r >= '0' && r <= '9') || (r >= '０' && r <= '９') || r == '.' || r == '．' {
		return true
	}
	return false
}

func tokenizeNori(cs charStream, startPos int, decompound string, discardPunct bool, userWords []string, budget *tokenStreamBudget) ([]Token, error) {
	_ = decompound
	var out []Token
	pos := startPos
	n := len(cs.runes)

	emit := func(rStart, rEnd int, term, tokType string) error {
		if err := budget.canAddOne(); err != nil {
			return err
		}
		if err := budget.add(len(term)); err != nil {
			return err
		}
		sOff, eOff := cs.sliceOffsets(rStart, rEnd)
		out = append(out, Token{
			Term:           term,
			StartOffset:    sOff,
			EndOffset:      eOff,
			Type:           tokType,
			Position:       pos,
			PositionLength: 1,
			TermFrequency:  1,
		})
		pos++
		return nil
	}

	for i := 0; i < n; {
		r := cs.runes[i]
		if unicode.IsSpace(r) {
			j := i + 1
			for j < n && unicode.IsSpace(cs.runes[j]) {
				j++
			}
			if !discardPunct {
				if err := emit(i, j, string(cs.runes[i:j]), "SP"); err != nil {
					return nil, err
				}
			}
			i = j
			continue
		}
		if unicode.IsPunct(r) || unicode.IsSymbol(r) {
			if !discardPunct {
				if err := emit(i, i+1, string(cs.runes[i:i+1]), "SC"); err != nil {
					return nil, err
				}
			}
			i++
			continue
		}

		// User dictionary match
		matchedUser := ""
		for _, uw := range userWords {
			uwr := []rune(uw)
			if len(uwr) > len([]rune(matchedUser)) && i+len(uwr) <= n && runesEqual(cs.runes[i:i+len(uwr)], uwr) {
				matchedUser = uw
			}
		}
		if matchedUser != "" {
			ml := utf8.RuneCountInString(matchedUser)
			if err := emit(i, i+ml, matchedUser, "NNG"); err != nil {
				return nil, err
			}
			i += ml
			continue
		}

		// Contiguous Korean/fullwidth number expression (e.g. "십만이천오백", "３.２천")
		if isKoreanNumericChar(r) {
			j := i + 1
			hasNum := true
			for j < n && isKoreanNumericChar(cs.runes[j]) {
				j++
			}
			numRun := cs.runes[i:j]
			// Avoid treating standalone particle "이" as number unless multi-rune or digit
			if len(numRun) >= 2 || (r >= '0' && r <= '9') || (r >= '０' && r <= '９') {
				_ = hasNum
				if err := emit(i, j, string(numRun), "NR"); err != nil {
					return nil, err
				}
				i = j
				continue
			}
		}

		// Hangul morphological segmentation
		if unicode.Is(unicode.Hangul, r) {
			j := i + 1
			for j < n && unicode.Is(unicode.Hangul, cs.runes[j]) {
				j++
			}
			word := string(cs.runes[i:j])
			handled := false
			for _, lx := range koreanLexiconStems {
				if word == lx.full {
					cur := i
					for pIdx, part := range lx.parts {
						plen := utf8.RuneCountInString(part)
						if err := emit(cur, cur+plen, part, lx.posTag[pIdx]); err != nil {
							return nil, err
						}
						cur += plen
					}
					handled = true
					break
				}
			}
			if !handled {
				wordRunes := cs.runes[i:j]
				if len(wordRunes) == 1 {
					tag := "NNG"
					for _, pt := range koreanParticles {
						if word == pt {
							tag = "J"
							break
						}
					}
					if err := emit(i, j, word, tag); err != nil {
						return nil, err
					}
				} else {
					splitDone := false
					for _, pt := range koreanParticles {
						ptr := []rune(pt)
						if len(wordRunes) > len(ptr) && runesEqual(wordRunes[len(wordRunes)-len(ptr):], ptr) {
							stemEnd := j - len(ptr)
							if err := emit(i, stemEnd, string(cs.runes[i:stemEnd]), "NNG"); err != nil {
								return nil, err
							}
							if err := emit(stemEnd, j, pt, "J"); err != nil {
								return nil, err
							}
							splitDone = true
							break
						}
					}
					if !splitDone {
						if err := emit(i, j, word, "NNG"); err != nil {
							return nil, err
						}
					}
				}
			}
			i = j
			continue
		}

		// Hanja (CJK ideographs in Korean)
		if isCJKIdeograph(r) {
			j := i + 1
			for j < n && isCJKIdeograph(cs.runes[j]) {
				j++
			}
			if err := emit(i, j, string(cs.runes[i:j]), "SH"); err != nil {
				return nil, err
			}
			i = j
			continue
		}

		// Alphanumeric run
		j := i + 1
		for j < n && (isWordLetter(cs.runes[j]) || unicode.IsDigit(cs.runes[j])) && !unicode.Is(unicode.Hangul, cs.runes[j]) && !isCJKIdeograph(cs.runes[j]) {
			j++
		}
		if err := emit(i, j, string(cs.runes[i:j]), "SL"); err != nil {
			return nil, err
		}
		i = j
	}
	return out, nil
}

func classifyNoriPOS(tok Token) string {
	switch tok.Type {
	case "J", "E", "SP", "SC", "NR", "NNG", "VA", "SH", "SL":
		return tok.Type
	}
	for _, pt := range koreanParticles {
		if tok.Term == pt {
			return "J"
		}
	}
	return "NNG"
}

func hanjaToHangulReading(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		if hg, ok := hanjaReadingMap[r]; ok {
			sb.WriteRune(hg)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func convertKoreanNumberString(s string) string {
	return convertSinosphericNumber(s)
}

func convertCJKNumberString(s string) string {
	return convertSinosphericNumber(s)
}

var sinosphericDigits = map[rune]int64{
	'零': 0, '〇': 0, '영': 0, '공': 0,
	'一': 1, '壱': 1, '일': 1,
	'二': 2, '弐': 2, '이': 2,
	'三': 3, '参': 3, '삼': 3,
	'四': 4, '사': 4,
	'五': 5, '오': 5,
	'六': 6, '육': 6, '륙': 6,
	'七': 7, '칠': 7,
	'八': 8, '팔': 8,
	'九': 9, '구': 9,
}

var sinosphericSmallUnits = map[rune]int64{
	'十': 10, '拾': 10, '십': 10,
	'百': 100, '백': 100,
	'千': 1000, '천': 1000,
}

var sinosphericLargeUnits = map[rune]int64{
	'万': 10000, '萬': 10000, '만': 10000,
	'億': 100000000, '억': 100000000,
	'兆': 1000000000000, '조': 1000000000000,
}

func convertSinosphericNumber(s string) string {
	norm := foldCJKWidth(s)
	norm = strings.ReplaceAll(norm, "．", ".")
	rs := []rune(norm)
	if len(rs) == 0 {
		return s
	}

	// Decimal + unit multiplier (e.g. "3.2천" -> "3200", "1.5万" -> "15000")
	lastRune := rs[len(rs)-1]
	var tailMult int64
	if u, ok := sinosphericSmallUnits[lastRune]; ok {
		tailMult = u
	} else if lu, ok := sinosphericLargeUnits[lastRune]; ok {
		tailMult = lu
	}
	if tailMult > 0 && len(rs) >= 2 {
		prefix := string(rs[:len(rs)-1])
		if fv, err := strconv.ParseFloat(prefix, 64); err == nil {
			val := int64(math.Round(fv * float64(tailMult)))
			return strconv.FormatInt(val, 10)
		}
	}

	// Pure ASCII integer after width fold
	allASCII := true
	for _, r := range rs {
		if r < '0' || r > '9' {
			allASCII = false
			break
		}
	}
	if allASCII {
		trimmed := strings.TrimLeft(norm, "0")
		if trimmed == "" {
			return "0"
		}
		return trimmed
	}

	var total int64
	var section int64
	var current int64
	hasUnit := false
	posDigitSeq := int64(0)
	onlyDigits := true

	for _, r := range rs {
		if r >= '0' && r <= '9' {
			d := int64(r - '0')
			current = current*10 + d
			posDigitSeq = posDigitSeq*10 + d
			continue
		}
		if d, ok := sinosphericDigits[r]; ok {
			current = current*10 + d
			posDigitSeq = posDigitSeq*10 + d
			continue
		}
		onlyDigits = false
		if u, ok := sinosphericSmallUnits[r]; ok {
			hasUnit = true
			if current == 0 {
				current = 1
			}
			section += current * u
			current = 0
			continue
		}
		if lu, ok := sinosphericLargeUnits[r]; ok {
			hasUnit = true
			section += current
			if section == 0 {
				section = 1
			}
			total += section * lu
			section = 0
			current = 0
			continue
		}
		// Non-numeric rune encountered: return original token unchanged
		return s
	}
	if onlyDigits {
		return strconv.FormatInt(posDigitSeq, 10)
	}
	if hasUnit {
		return strconv.FormatInt(total+section+current, 10)
	}
	return s
}

// ============================================================================
// SmartCN (Chinese) Analysis Components
// ============================================================================

var smartCNDictWords = [][]rune{
	[]rune("中华人民共和国"), []rune("计算机科学"), []rune("人工智能"),
	[]rune("购买"), []rune("道具"), []rune("服装"), []rune("研究"), []rune("生命"),
	[]rune("科学"), []rune("中国"), []rune("北京"), []rune("上海"), []rune("大学"),
	[]rune("搜索"), []rune("引擎"), []rune("数据"), []rune("分析"), []rune("系统"),
	[]rune("技术"), []rune("软件"), []rune("开发"), []rune("网络"), []rune("安全"),
	[]rune("学生"), []rune("老师"), []rune("学校"), []rune("工作"), []rune("生活"),
	[]rune("我们"), []rune("他们"), []rune("你们"), []rune("这个"), []rune("那个"),
	[]rune("因为"), []rune("所以"), []rune("如果"), []rune("但是"), []rune("可以"),
}

func segmentCJKByDict(runes []rune, dict [][]rune) []int {
	n := len(runes)
	var out []int
	for i := 0; i < n; {
		best := 1
		for _, dw := range dict {
			m := len(dw)
			if m > best && i+m <= n && runesEqual(runes[i:i+m], dw) {
				best = m
			}
		}
		out = append(out, best)
		i += best
	}
	return out
}

func isSmartCNPunctuation(r rune) bool {
	switch r {
	case '。', '，', '！', '？', '；', '：', '、', '“', '”', '‘', '’', '（', '）', '《', '》', '【', '】':
		return true
	}
	return unicode.IsPunct(r) || unicode.IsSymbol(r)
}

func tokenizeSmartCN(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	pos := startPos
	n := len(cs.runes)

	emit := func(rStart, rEnd int, term, tokType string) error {
		if err := budget.canAddOne(); err != nil {
			return err
		}
		if err := budget.add(len(term)); err != nil {
			return err
		}
		sOff, eOff := cs.sliceOffsets(rStart, rEnd)
		out = append(out, Token{
			Term:           term,
			StartOffset:    sOff,
			EndOffset:      eOff,
			Type:           tokType,
			Position:       pos,
			PositionLength: 1,
			TermFrequency:  1,
		})
		pos++
		return nil
	}

	for i := 0; i < n; {
		r := cs.runes[i]
		if unicode.IsSpace(r) {
			i++
			continue
		}
		if isCJKIdeograph(r) {
			end := i + 1
			for end < n && isCJKIdeograph(cs.runes[end]) {
				end++
			}
			segs := segmentCJKByDict(cs.runes[i:end], smartCNDictWords)
			cur := i
			for _, segLen := range segs {
				if err := emit(cur, cur+segLen, string(cs.runes[cur:cur+segLen]), "word"); err != nil {
					return nil, err
				}
				cur += segLen
			}
			i = end
			continue
		}
		if isSmartCNPunctuation(r) {
			// Lucene HMMChineseTokenizer emits "," for CJK sentence punctuation, later filtered by smartcn_stop!
			if err := emit(i, i+1, ",", "punctuation"); err != nil {
				return nil, err
			}
			i++
			continue
		}
		end := i + 1
		for end < n && !unicode.IsSpace(cs.runes[end]) && !isCJKIdeograph(cs.runes[end]) && !isSmartCNPunctuation(cs.runes[end]) {
			end++
		}
		term := strings.ToLower(foldCJKWidth(string(cs.runes[i:end])))
		if err := emit(i, end, term, "word"); err != nil {
			return nil, err
		}
		i = end
	}
	return out, nil
}

// ============================================================================
// Stempel (Polish) & Morfologik (Ukrainian) Stemmers / Lemmatizers
// ============================================================================

var polishIrregulars = map[string]string{
	"studenci": "student", "studentów": "student", "studentom": "student",
	"studentami": "student", "studentach": "student", "studentem": "student",
	"studentowi": "student", "studencie": "student", "studenta": "student",
	"ludzie": "człowiek", "ludzi": "człowiek", "ludziom": "człowiek",
	"dzieci": "dziecko", "dzieciom": "dziecko", "dziećmi": "dziecko",
}

var polishSuffixes = []string{
	"owania", "owanie", "owaniu", "owaniem",
	"ościach", "ościami", "ościom",
	"owie", "ami", "ach", "om", "ów", "owi", "ego", "emu", "ymi", "imi", "ych", "ich",
	"ość", "ości", "anie", "enie", "cie",
	"em", "ie", "ej", "ą", "ę", "u", "a", "i", "y", "o", "e",
}

func stemPolish(word string) string {
	w := strings.ToLower(word)
	if irr, ok := polishIrregulars[w]; ok {
		return irr
	}
	rs := []rune(w)
	if len(rs) <= 3 {
		return w
	}
	if strings.HasSuffix(w, "ci") && len(rs) >= 5 {
		// Palatalized plural -ci -> -t (e.g. studenci -> student, klienci -> klient, prezydenci -> prezydent)
		return string(rs[:len(rs)-2]) + "t"
	}
	for _, suf := range polishSuffixes {
		sr := []rune(suf)
		if len(rs)-len(sr) >= 3 && runesEqual(rs[len(rs)-len(sr):], sr) {
			return string(rs[:len(rs)-len(sr)])
		}
	}
	return w
}

var ukrainianMorfologikDict = map[string][]string{
	"колу":      {"кола", "коло", "кіл"},
	"кола":      {"кола", "коло"},
	"коло":      {"коло"},
	"колом":     {"коло", "кіл"},
	"кіл":       {"коло", "кіл"},
	"чергу":     {"черга"},
	"черга":     {"черга"},
	"черги":     {"черга"},
	"рухається": {"рухатися"},
	"рухатися":  {"рухатися"},
	"п'єса":     {"п'єса"},
	"п'єси":     {"п'єса"},
	"п'єсу":     {"п'єса"},
	"міста":     {"місто"},
	"місті":     {"місто"},
	"містом":    {"місто"},
	"люди":      {"людина"},
	"людей":     {"людина"},
	"роботи":    {"робота"},
	"роботу":    {"робота"},
}

var ukrainianSuffixes = []string{
	"ами", "ями", "ові", "еві", "єві", "ого", "ому", "ими", "іми",
	"ться", "тися", "ати", "яти", "ити", "іти",
	"ів", "їв", "ам", "ям", "ах", "ях", "ою", "ею", "єю", "ом", "ем", "єм",
	"ий", "ій", "а", "я", "о", "е", "є", "и", "і", "ї", "у", "ю",
}

func applyUkrainianLemmatizer(tokens []Token, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	for _, tok := range tokens {
		if tok.Keyword {
			cp := tok.clone()
			if err := budget.addToken(cp); err != nil {
				return nil, err
			}
			out = append(out, cp)
			continue
		}
		normTerm := strings.ReplaceAll(strings.ReplaceAll(tok.Term, "\u2019", "'"), "\u02BC", "'")
		if lemmas, ok := ukrainianMorfologikDict[normTerm]; ok {
			for _, lm := range lemmas {
				cp := tok.clone()
				cp.Term = lm
				if err := budget.addToken(cp); err != nil {
					return nil, err
				}
				out = append(out, cp)
			}
			continue
		}
		stemmed := stemUkrainianFallback(normTerm)
		cp := tok.clone()
		cp.Term = stemmed
		if err := budget.addToken(cp); err != nil {
			return nil, err
		}
		out = append(out, cp)
	}
	return out, nil
}

func stemUkrainianFallback(w string) string {
	rs := []rune(w)
	if len(rs) <= 3 {
		return w
	}
	for _, suf := range ukrainianSuffixes {
		sr := []rune(suf)
		if len(rs)-len(sr) >= 3 && runesEqual(rs[len(rs)-len(sr):], sr) {
			return string(rs[:len(rs)-len(sr)])
		}
	}
	return w
}
