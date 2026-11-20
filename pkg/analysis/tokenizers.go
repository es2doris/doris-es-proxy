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
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type compiledTokenizer struct {
	name     string
	tokenize func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error)
}

// IsBuiltInTokenizer reports whether typeName is a built-in Elasticsearch tokenizer.
func IsBuiltInTokenizer(typeName string) bool {
	switch strings.ToLower(strings.TrimSpace(typeName)) {
	case "standard", "uax_url_email", "letter", "lowercase", "whitespace",
		"classic", "keyword", "noop", "ngram", "edge_ngram", "edgengram",
		"pattern", "simple_pattern", "simple_pattern_split",
		"char_group", "path_hierarchy", "pathhierarchy", "thai",
		"icu_tokenizer", "kuromoji_tokenizer", "nori_tokenizer", "smartcn_tokenizer", "smartcn_sentence":
		return true
	default:
		return false
	}
}

func buildTokenizer(displayName string, typeName string, def map[string]any, maxNGramDiff int) (*compiledTokenizer, error) {
	return buildTokenizerWithOpts(displayName, typeName, def, maxNGramDiff, Options{})
}

func buildTokenizerWithOpts(displayName string, typeName string, def map[string]any, maxNGramDiff int, opts Options) (*compiledTokenizer, error) {
	normType := strings.ToLower(strings.TrimSpace(typeName))
	switch normType {
	case "standard":
		maxLen, err := parseMaxTokenLength(def, 255)
		if err != nil {
			return nil, err
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizeStandard(cs, startPos, maxLen, false, budget)
			},
		}, nil

	case "uax_url_email":
		maxLen, err := parseMaxTokenLength(def, 255)
		if err != nil {
			return nil, err
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizeStandard(cs, startPos, maxLen, true, budget)
			},
		}, nil

	case "classic":
		maxLen, err := parseMaxTokenLength(def, 255)
		if err != nil {
			return nil, err
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizeClassic(cs, startPos, maxLen, budget)
			},
		}, nil

	case "letter":
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizePred(cs, startPos, 0, unicode.IsLetter, false, budget)
			},
		}, nil

	case "lowercase":
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizePred(cs, startPos, 0, unicode.IsLetter, true, budget)
			},
		}, nil

	case "whitespace":
		maxLen, err := parseMaxTokenLength(def, 255)
		if err != nil {
			return nil, err
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizePred(cs, startPos, maxLen, func(r rune) bool {
					return !unicode.IsSpace(r)
				}, false, budget)
			},
		}, nil

	case "keyword", "noop":
		if def != nil {
			if bs, hasBS := def["buffer_size"]; hasBS {
				if n, ok := extractInt(bs); !ok || n <= 0 {
					return nil, newIllegalArgError("buffer_size must be a positive integer")
				}
			}
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				if len(cs.runes) == 0 {
					return nil, nil
				}
				if len(cs.runes) > MaxTokenTermBytes {
					return nil, newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
				}
				if err := budget.canAddOne(); err != nil {
					return nil, err
				}
				term := cs.String()
				if err := budget.add(len(term)); err != nil {
					return nil, err
				}
				sOff, eOff := cs.sliceOffsets(0, len(cs.runes))
				return []Token{{
					Term:           term,
					StartOffset:    sOff,
					EndOffset:      eOff,
					Type:           "word",
					Position:       startPos,
					PositionLength: 1,
					TermFrequency:  1,
				}}, nil
			},
		}, nil

	case "ngram", "edge_ngram", "edgengram":
		isEdge := normType == "edge_ngram" || normType == "edgengram"
		minGram, maxGram, err := parseMinMaxGram(def, 1, 2)
		if err != nil {
			return nil, err
		}
		if !isEdge && maxGram-minGram > maxNGramDiff {
			return nil, newIllegalArgError(fmt.Sprintf(
				"The difference between max_gram and min_gram in NGram Tokenizer must be less than or equal to: [%d] but was [%d]. This limit can be set by changing the [index.max_ngram_diff] index level setting.",
				maxNGramDiff, maxGram-minGram,
			))
		}
		charPred, err := parseNGramTokenChars(def)
		if err != nil {
			return nil, err
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizeNGram(cs, startPos, minGram, maxGram, isEdge, charPred, budget)
			},
		}, nil

	case "pattern":
		pat := `\W+`
		flags := ""
		group := -1
		if def != nil {
			if p, ok := def["pattern"].(string); ok {
				pat = p
			}
			if f, ok := def["flags"].(string); ok {
				flags = f
			}
			if gRaw, hasG := def["group"]; hasG {
				g, ok := extractInt(gRaw)
				if !ok || g < -1 {
					return nil, newIllegalArgError("group in pattern tokenizer must be >= -1")
				}
				group = g
			}
		}
		re, err := compileJavaRegex(pat, flags)
		if err != nil {
			return nil, err
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizePattern(cs, startPos, re, group, budget)
			},
		}, nil

	case "simple_pattern":
		pat := ""
		if def != nil {
			if p, ok := def["pattern"].(string); ok {
				pat = p
			}
		}
		if pat == "" {
			return &compiledTokenizer{
				name: displayName,
				tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
					return nil, nil
				},
			}, nil
		}
		re, err := compileJavaRegex(pat, "")
		if err != nil {
			return nil, err
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizePattern(cs, startPos, re, 0, budget)
			},
		}, nil

	case "simple_pattern_split":
		pat := ""
		if def != nil {
			if p, ok := def["pattern"].(string); ok {
				pat = p
			}
		}
		if pat == "" {
			return &compiledTokenizer{
				name: displayName,
				tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
					if len(cs.runes) == 0 {
						return nil, nil
					}
					if len(cs.runes) > MaxTokenTermBytes {
						return nil, newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
					}
					if err := budget.canAddOne(); err != nil {
						return nil, err
					}
					term := cs.String()
					if err := budget.add(len(term)); err != nil {
						return nil, err
					}
					sOff, eOff := cs.sliceOffsets(0, len(cs.runes))
					return []Token{{
						Term:           term,
						StartOffset:    sOff,
						EndOffset:      eOff,
						Type:           "word",
						Position:       startPos,
						PositionLength: 1,
						TermFrequency:  1,
					}}, nil
				},
			}, nil
		}
		re, err := compileJavaRegex(pat, "")
		if err != nil {
			return nil, err
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizePattern(cs, startPos, re, -1, budget)
			},
		}, nil

	case "char_group":
		maxLen, err := parseMaxTokenLength(def, 255)
		if err != nil {
			return nil, err
		}
		splitPred, err := parseCharGroupSplitPred(def)
		if err != nil {
			return nil, err
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizePred(cs, startPos, maxLen, func(r rune) bool {
					return !splitPred(r)
				}, false, budget)
			},
		}, nil

	case "path_hierarchy", "pathhierarchy":
		delim := '/'
		repl := '/'
		hasRepl := false
		reverse := false
		skip := 0
		if def != nil {
			if dStr, ok := def["delimiter"].(string); ok && dStr != "" {
				dr := []rune(dStr)
				if len(dr) != 1 {
					return nil, newIllegalArgError("delimiter in path_hierarchy must be a single character")
				}
				delim = dr[0]
			}
			if rStr, ok := def["replacement"].(string); ok && rStr != "" {
				rr := []rune(rStr)
				if len(rr) != 1 {
					return nil, newIllegalArgError("replacement in path_hierarchy must be a single character")
				}
				repl = rr[0]
				hasRepl = true
			}
			if revRaw, hasRev := def["reverse"]; hasRev {
				b, ok := extractBool(revRaw)
				if !ok {
					return nil, newIllegalArgError("reverse in path_hierarchy must be boolean")
				}
				reverse = b
			}
			if skRaw, hasSk := def["skip"]; hasSk {
				n, ok := extractInt(skRaw)
				if !ok || n < 0 {
					return nil, newIllegalArgError("skip in path_hierarchy must be >= 0")
				}
				skip = n
			}
		}
		if !hasRepl {
			repl = delim
		}
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizePathHierarchy(cs, startPos, delim, repl, reverse, skip, budget)
			},
		}, nil

	case "thai":
		return &compiledTokenizer{
			name: displayName,
			tokenize: func(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
				return tokenizeThai(cs, startPos, budget)
			},
		}, nil

	case "icu_tokenizer", "kuromoji_tokenizer", "nori_tokenizer", "smartcn_tokenizer", "smartcn_sentence":
		return buildPluginTokenizer(displayName, normType, def, opts)

	default:
		return nil, newIllegalArgError(fmt.Sprintf("Unknown tokenizer type [%s] for [%s]", typeName, displayName))
	}
}

func parseMaxTokenLength(def map[string]any, defaultVal int) (int, error) {
	if def == nil {
		return defaultVal, nil
	}
	raw, exists := def["max_token_length"]
	if !exists {
		return defaultVal, nil
	}
	n, ok := extractInt(raw)
	if !ok || n <= 0 {
		return 0, newIllegalArgError("max_token_length must be a positive integer")
	}
	return n, nil
}

func parseGramIntValue(raw any) (int, bool) {
	if n, ok := extractInt(raw); ok {
		return n, true
	}
	if s, isStr := raw.(string); isStr {
		trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ","))
		if trimmed != "" {
			if n, err := strconv.Atoi(trimmed); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func parseMinMaxGram(def map[string]any, defaultMin, defaultMax int) (int, int, error) {
	minGram := defaultMin
	maxGram := defaultMax
	if def != nil {
		if raw, ok := def["min_gram"]; ok {
			n, valid := parseGramIntValue(raw)
			if !valid || n < 1 {
				return 0, 0, newIllegalArgError("min_gram must be a positive integer")
			}
			minGram = n
		} else if raw, ok := def["min"]; ok {
			n, valid := parseGramIntValue(raw)
			if !valid || n < 1 {
				return 0, 0, newIllegalArgError("min must be a positive integer")
			}
			minGram = n
		}
		if raw, ok := def["max_gram"]; ok {
			n, valid := parseGramIntValue(raw)
			if !valid || n < 1 {
				return 0, 0, newIllegalArgError("max_gram must be a positive integer")
			}
			maxGram = n
		} else if raw, ok := def["max"]; ok {
			n, valid := parseGramIntValue(raw)
			if !valid || n < 1 {
				return 0, 0, newIllegalArgError("max must be a positive integer")
			}
			maxGram = n
		}
	}
	if maxGram > MaxAllowedGramSize {
		return 0, 0, newIllegalArgError(fmt.Sprintf("max_gram [%d] must be <= %d", maxGram, MaxAllowedGramSize))
	}
	if maxGram < minGram {
		return 0, 0, newIllegalArgError(fmt.Sprintf("min_gram [%d] cannot be greater than max_gram [%d]", minGram, maxGram))
	}
	return minGram, maxGram, nil
}

func parseNGramTokenChars(def map[string]any) (func(rune) bool, error) {
	if def == nil {
		return nil, nil
	}
	raw, exists := def["token_chars"]
	if !exists || raw == nil {
		return nil, nil
	}
	var specs []string
	switch v := raw.(type) {
	case string:
		for _, part := range strings.Split(v, ",") {
			if t := strings.TrimSpace(part); t != "" {
				specs = append(specs, t)
			}
		}
	default:
		specs = extractStringSlice(raw)
	}
	if len(specs) == 0 {
		return nil, nil
	}
	customChars, _ := def["custom_token_chars"].(string)
	customSet := make(map[rune]bool)
	for _, r := range customChars {
		customSet[r] = true
	}
	var wantLetter, wantDigit, wantWS, wantPunct, wantSym, wantCustom bool
	for _, s := range specs {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "letter":
			wantLetter = true
		case "digit":
			wantDigit = true
		case "whitespace":
			wantWS = true
		case "punctuation":
			wantPunct = true
		case "symbol":
			wantSym = true
		case "custom":
			wantCustom = true
		default:
			return nil, newIllegalArgError(fmt.Sprintf("Unknown token_chars class [%s]", s))
		}
	}
	return func(r rune) bool {
		if wantLetter && (unicode.IsLetter(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r)) {
			return true
		}
		if wantDigit && unicode.IsDigit(r) {
			return true
		}
		if wantWS && unicode.IsSpace(r) {
			return true
		}
		if wantPunct && unicode.IsPunct(r) {
			return true
		}
		if wantSym && unicode.IsSymbol(r) {
			return true
		}
		if wantCustom && customSet[r] {
			return true
		}
		return false
	}, nil
}

func parseCharGroupSplitPred(def map[string]any) (func(rune) bool, error) {
	var specs []string
	if def != nil {
		specs = extractStringSlice(def["tokenize_on_chars"])
	}
	var onWS, onLetter, onDigit, onPunct, onSym, onCJK bool
	literals := make(map[rune]bool)
	for _, s := range specs {
		switch s {
		case "whitespace":
			onWS = true
		case "letter":
			onLetter = true
		case "digit":
			onDigit = true
		case "punctuation":
			onPunct = true
		case "symbol":
			onSym = true
		case "cjk":
			onCJK = true
		default:
			unesc := unescapeMappingStr(s)
			rs := []rune(unesc)
			if len(rs) != 1 {
				return nil, newIllegalArgError(fmt.Sprintf("Invalid tokenize_on_chars entry [%s]", s))
			}
			literals[rs[0]] = true
		}
	}
	return func(r rune) bool {
		if literals[r] {
			return true
		}
		if onWS && unicode.IsSpace(r) {
			return true
		}
		if onLetter && unicode.IsLetter(r) {
			return true
		}
		if onDigit && unicode.IsDigit(r) {
			return true
		}
		if onPunct && unicode.IsPunct(r) {
			return true
		}
		if onSym && unicode.IsSymbol(r) {
			return true
		}
		if onCJK && (unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r)) {
			return true
		}
		return false
	}, nil
}

func tokenizePred(cs charStream, startPos int, maxLen int, keep func(rune) bool, lower bool, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	pos := startPos
	n := len(cs.runes)
	i := 0
	for i < n {
		if !keep(cs.runes[i]) {
			i++
			continue
		}
		start := i
		for i < n && keep(cs.runes[i]) {
			if maxLen > 0 && i-start >= maxLen {
				break
			}
			i++
		}
		seg := cs.runes[start:i]
		if len(seg) > MaxTokenTermBytes {
			return nil, newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
		}
		if err := budget.canAddOne(); err != nil {
			return nil, err
		}
		var term string
		if lower {
			var sb strings.Builder
			sb.Grow(len(seg) * 2)
			for _, r := range seg {
				sb.WriteRune(unicode.ToLower(r))
			}
			term = sb.String()
		} else {
			term = string(seg)
		}
		if err := budget.add(len(term)); err != nil {
			return nil, err
		}
		sOff, eOff := cs.sliceOffsets(start, i)
		out = append(out, Token{
			Term:           term,
			StartOffset:    sOff,
			EndOffset:      eOff,
			Type:           "word",
			Position:       pos,
			PositionLength: 1,
			TermFrequency:  1,
		})
		pos++
	}
	return out, nil
}

func tokenizeNGram(cs charStream, startPos int, minGram, maxGram int, isEdge bool, charPred func(rune) bool, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	pos := startPos
	emitRun := func(runStart, runEnd int) error {
		runLen := runEnd - runStart
		if runLen < minGram {
			return nil
		}
		if isEdge {
			limit := maxGram
			if limit > runLen {
				limit = runLen
			}
			for sz := minGram; sz <= limit; sz++ {
				if err := budget.canAddOne(); err != nil {
					return err
				}
				term := string(cs.runes[runStart : runStart+sz])
				if err := budget.add(len(term)); err != nil {
					return err
				}
				sOff, eOff := cs.sliceOffsets(runStart, runStart+sz)
				out = append(out, Token{
					Term:           term,
					StartOffset:    sOff,
					EndOffset:      eOff,
					Type:           "word",
					Position:       pos,
					PositionLength: 1,
					TermFrequency:  1,
				})
				pos++
			}
			return nil
		}
		for s := runStart; s < runEnd; s++ {
			for sz := minGram; sz <= maxGram && s+sz <= runEnd; sz++ {
				if err := budget.canAddOne(); err != nil {
					return err
				}
				term := string(cs.runes[s : s+sz])
				if err := budget.add(len(term)); err != nil {
					return err
				}
				sOff, eOff := cs.sliceOffsets(s, s+sz)
				out = append(out, Token{
					Term:           term,
					StartOffset:    sOff,
					EndOffset:      eOff,
					Type:           "word",
					Position:       pos,
					PositionLength: 1,
					TermFrequency:  1,
				})
				pos++
			}
		}
		return nil
	}

	if charPred == nil {
		if err := emitRun(0, len(cs.runes)); err != nil {
			return nil, err
		}
		return out, nil
	}
	n := len(cs.runes)
	for i := 0; i < n; {
		if !charPred(cs.runes[i]) {
			i++
			continue
		}
		start := i
		for i < n && charPred(cs.runes[i]) {
			i++
		}
		if err := emitRun(start, i); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func tokenizePattern(cs charStream, startPos int, re *regexp.Regexp, group int, budget *tokenStreamBudget) ([]Token, error) {
	s := cs.String()
	if len(cs.runes) == 0 {
		return nil, nil
	}
	byteToRune := make([]int, len(s)+1)
	bOff := 0
	for rIdx, r := range cs.runes {
		sz := utf8.RuneLen(r)
		for k := 0; k < sz; k++ {
			byteToRune[bOff+k] = rIdx
		}
		bOff += sz
	}
	byteToRune[len(s)] = len(cs.runes)

	var out []Token
	pos := startPos
	matches := re.FindAllStringSubmatchIndex(s, -1)

	emitSpan := func(rStart, rEnd int) error {
		if rEnd-rStart > MaxTokenTermBytes {
			return newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
		}
		if err := budget.canAddOne(); err != nil {
			return err
		}
		term := string(cs.runes[rStart:rEnd])
		if err := budget.add(len(term)); err != nil {
			return err
		}
		sOff, eOff := cs.sliceOffsets(rStart, rEnd)
		out = append(out, Token{
			Term:           term,
			StartOffset:    sOff,
			EndOffset:      eOff,
			Type:           "word",
			Position:       pos,
			PositionLength: 1,
			TermFrequency:  1,
		})
		pos++
		return nil
	}

	if group < 0 {
		// Split mode: emit non-empty segments between matches.
		prevRune := 0
		for _, loc := range matches {
			mStart := byteToRune[loc[0]]
			mEnd := byteToRune[loc[1]]
			if mStart > prevRune {
				if err := emitSpan(prevRune, mStart); err != nil {
					return nil, err
				}
			}
			if mEnd > prevRune {
				prevRune = mEnd
			}
		}
		if prevRune < len(cs.runes) {
			if err := emitSpan(prevRune, len(cs.runes)); err != nil {
				return nil, err
			}
		}
		return out, nil
	}

	// Capture mode: emit matched group for each regex match.
	for _, loc := range matches {
		if group*2+1 >= len(loc) {
			continue
		}
		gStartB, gEndB := loc[group*2], loc[group*2+1]
		if gStartB < 0 || gEndB <= gStartB {
			continue
		}
		rStart := byteToRune[gStartB]
		rEnd := byteToRune[gEndB]
		if err := emitSpan(rStart, rEnd); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func formatPathHierarchySpan(runes []rune, delim, repl rune) string {
	if delim == repl {
		return string(runes)
	}
	var sb strings.Builder
	sb.Grow(len(runes))
	for _, r := range runes {
		if r == delim {
			sb.WriteRune(repl)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func tokenizePathHierarchy(cs charStream, startPos int, delim, repl rune, reverse bool, skip int, budget *tokenStreamBudget) ([]Token, error) {
	n := len(cs.runes)
	if n == 0 {
		return nil, nil
	}

	var out []Token
	emitSpan := func(rStart, rEnd int) error {
		if rEnd-rStart > MaxTokenTermBytes {
			return newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
		}
		if err := budget.canAddOne(); err != nil {
			return err
		}
		term := formatPathHierarchySpan(cs.runes[rStart:rEnd], delim, repl)
		if err := budget.add(len(term)); err != nil {
			return err
		}
		sOff, eOff := cs.sliceOffsets(rStart, rEnd)
		out = append(out, Token{
			Term:           term,
			StartOffset:    sOff,
			EndOffset:      eOff,
			Type:           "word",
			Position:       startPos,
			PositionLength: 1,
			TermFrequency:  1,
		})
		return nil
	}

	if !reverse && skip == 0 {
		i := 0
		if cs.runes[0] == delim {
			i = 1
		}
		lastEmittedEnd := -1
		for ; i <= n; i++ {
			if i == n || cs.runes[i] == delim {
				if i > 0 {
					if err := emitSpan(0, i); err != nil {
						return nil, err
					}
					lastEmittedEnd = i
				}
			}
		}
		if n > 1 && cs.runes[n-1] == delim && lastEmittedEnd != n {
			if err := emitSpan(0, n); err != nil {
				return nil, err
			}
			lastEmittedEnd = n
		}
		if lastEmittedEnd < 0 {
			if err := emitSpan(0, n); err != nil {
				return nil, err
			}
		}
		return out, nil
	}

	var spans [][2]int
	if !reverse {
		i := 0
		if cs.runes[0] == delim {
			i = 1
		}
		for ; i <= n; i++ {
			if i == n || cs.runes[i] == delim {
				if i > 0 {
					spans = append(spans, [2]int{0, i})
				}
			}
		}
		if n > 1 && cs.runes[n-1] == delim && (len(spans) == 0 || spans[len(spans)-1][1] != n) {
			spans = append(spans, [2]int{0, n})
		}
		if len(spans) == 0 {
			spans = append(spans, [2]int{0, n})
		}
		if skip > 0 {
			if skip >= len(spans) {
				return nil, nil
			}
			// In Lucene PathHierarchyTokenizer: when skip > 0, skipped prefix is trimmed!
			newStart := spans[skip-1][1]
			spans = spans[skip:]
			for k := range spans {
				spans[k][0] = newStart
			}
		}
	} else {
		end := n
		if skip > 0 {
			skipped := 0
			for j := n - 1; j >= 0 && skipped < skip; j-- {
				if cs.runes[j] == delim {
					end = j
					skipped++
				}
			}
			if skipped < skip {
				return nil, nil
			}
		}
		for j := end - 1; j >= 0; j-- {
			if cs.runes[j] == delim {
				if j+1 < end {
					spans = append(spans, [2]int{j + 1, end})
				}
			}
		}
		if end > 0 {
			spans = append(spans, [2]int{0, end})
		}
	}

	out = make([]Token, 0, min(len(spans), 1024))
	for _, sp := range spans {
		if err := emitSpan(sp[0], sp[1]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Standard & UAX URL Email Tokenizers

var (
	emailAtRegex = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	urlAtRegex   = regexp.MustCompile(`^(?i)(?:https?|ftp|file)://[^\s<>"]+|^(?i)www\.[A-Za-z0-9.\-]+\.[A-Za-z]{2,}[^\s<>"]*`)
)

func hasEmailCandidatePrefix(runes []rune) bool {
	for k, r := range runes {
		if r == '@' {
			return k > 0
		}
		if !isASCIILetter(r) && (r < '0' || r > '9') && r != '.' && r != '_' && r != '%' && r != '+' && r != '-' {
			return false
		}
	}
	return false
}

func hasURLCandidatePrefix(runes []rune) bool {
	if len(runes) < 6 {
		return false
	}
	switch runes[0] {
	case 'w', 'W':
		return (runes[1] == 'w' || runes[1] == 'W') &&
			(runes[2] == 'w' || runes[2] == 'W') &&
			runes[3] == '.'
	case 'h', 'H':
		return hasRunePrefixFold(runes, "http://") || hasRunePrefixFold(runes, "https://")
	case 'f', 'F':
		return hasRunePrefixFold(runes, "ftp://") || hasRunePrefixFold(runes, "file://")
	default:
		return false
	}
}

func nonSpaceLookaheadEnd(runes []rune, start, maxEnd int) int {
	for k := start; k < maxEnd; k++ {
		if unicode.IsSpace(runes[k]) {
			return k
		}
	}
	return maxEnd
}

func tokenizeStandard(cs charStream, startPos int, maxLen int, withURLEmail bool, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	pos := startPos
	n := len(cs.runes)
	lookWin := max(min(maxLen, MaxTokenTermBytes)*4, 4096)

	emitChunked := func(fromIdx, toIdx int, tokType string) error {
		for s := fromIdx; s < toIdx; s += maxLen {
			e := s + maxLen
			if e > toIdx {
				e = toIdx
			}
			if e-s > MaxTokenTermBytes {
				return newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
			}
			if err := budget.canAddOne(); err != nil {
				return err
			}
			term := string(cs.runes[s:e])
			if err := budget.add(len(term)); err != nil {
				return err
			}
			sOff, eOff := cs.sliceOffsets(s, e)
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
		}
		return nil
	}

	i := 0
	for i < n {
		r := cs.runes[i]

		if withURLEmail && (isASCIILetter(r) || (r >= '0' && r <= '9')) {
			end := nonSpaceLookaheadEnd(cs.runes, i, min(n, i+lookWin))
			cand := cs.runes[i:end]
			mayURL := hasURLCandidatePrefix(cand)
			mayEmail := hasEmailCandidatePrefix(cand)
			if mayURL || mayEmail {
				rem := string(cand)
				if mayURL {
					if m := urlAtRegex.FindString(rem); m != "" {
						trimmed := strings.TrimRight(m, ".,;:!?)']\"")
						mRunes := utf8.RuneCountInString(trimmed)
						if mRunes > 0 {
							if err := emitChunked(i, i+mRunes, "<URL>"); err != nil {
								return nil, err
							}
							i += mRunes
							continue
						}
					}
				}
				if mayEmail {
					if m := emailAtRegex.FindString(rem); m != "" {
						mRunes := utf8.RuneCountInString(m)
						if mRunes > 0 {
							if err := emitChunked(i, i+mRunes, "<EMAIL>"); err != nil {
								return nil, err
							}
							i += mRunes
							continue
						}
					}
				}
			}
		}

		if isCJKIdeograph(r) {
			end := i + 1
			for end < n && isCombiningMark(cs.runes[end]) {
				end++
			}
			if err := emitChunked(i, end, "<IDEOGRAPHIC>"); err != nil {
				return nil, err
			}
			i = end
			continue
		}

		if unicode.Is(unicode.Hiragana, r) {
			end := i + 1
			for end < n && (isCombiningMark(cs.runes[end]) || cs.runes[end] == '\u3099' || cs.runes[end] == '\u309A') {
				end++
			}
			if err := emitChunked(i, end, "<HIRAGANA>"); err != nil {
				return nil, err
			}
			i = end
			continue
		}

		if isKatakanaRune(r) {
			end := i + 1
			for end < n && (isKatakanaRune(cs.runes[end]) || cs.runes[end] == '\u30FC' || isCombiningMark(cs.runes[end])) {
				end++
			}
			if err := emitChunked(i, end, "<KATAKANA>"); err != nil {
				return nil, err
			}
			i = end
			continue
		}

		if unicode.Is(unicode.Hangul, r) {
			end := i + 1
			for end < n && (unicode.Is(unicode.Hangul, cs.runes[end]) || isCombiningMark(cs.runes[end])) {
				end++
			}
			if err := emitChunked(i, end, "<HANGUL>"); err != nil {
				return nil, err
			}
			i = end
			continue
		}

		if isSoutheastAsianLetter(r) {
			end := i + 1
			for end < n && (isSoutheastAsianLetter(cs.runes[end]) || isCombiningMark(cs.runes[end])) {
				end++
			}
			if err := emitChunked(i, end, "<SOUTHEAST_ASIAN>"); err != nil {
				return nil, err
			}
			i = end
			continue
		}

		if isEmojiRune(r) {
			end := i + 1
			for end < n {
				nr := cs.runes[end]
				if nr == '\uFE0F' || nr == '\uFE0E' || (nr >= 0x1F3FB && nr <= 0x1F3FF) || isCombiningMark(nr) {
					end++
					continue
				}
				if nr == '\u200D' && end+1 < n && isEmojiRune(cs.runes[end+1]) {
					end += 2
					continue
				}
				break
			}
			if err := emitChunked(i, end, "<EMOJI>"); err != nil {
				return nil, err
			}
			i = end
			continue
		}

		if isStandardWordStart(cs.runes, i) {
			start := i
			hasLetter := isWordLetter(r) || r == '_'
			hasDigit := unicode.IsDigit(r)
			i++
			for i < n {
				cr := cs.runes[i]
				if isWordLetter(cr) && !isCJKIdeograph(cr) && !unicode.Is(unicode.Hiragana, cr) && !isKatakanaRune(cr) && !unicode.Is(unicode.Hangul, cr) && !isSoutheastAsianLetter(cr) {
					hasLetter = true
					i++
					continue
				}
				if unicode.IsDigit(cr) {
					hasDigit = true
					i++
					continue
				}
				if isCombiningMark(cr) {
					i++
					continue
				}
				if (cr == '\u200C' || cr == '\u200D') && i+1 < n && (isWordLetter(cs.runes[i+1]) || isCombiningMark(cs.runes[i+1])) {
					i++
					continue
				}
				if cr == '_' {
					hasLetter = true
					i++
					continue
				}
				if isMidLetter(cr) && i > start && i+1 < n && isWordLetterOrMark(cs.runes[i-1]) && isWordLetter(cs.runes[i+1]) {
					hasLetter = true
					i++
					continue
				}
				if cr == '.' && i > start && i+1 < n {
					prevIsLet := isWordLetterOrMark(cs.runes[i-1])
					nextIsLet := isWordLetter(cs.runes[i+1])
					prevIsDig := unicode.IsDigit(cs.runes[i-1])
					nextIsDig := unicode.IsDigit(cs.runes[i+1])
					if (prevIsLet && nextIsLet) || (prevIsDig && nextIsDig) {
						i++
						continue
					}
				}
				if cr == ',' && i > start && i+1 < n && unicode.IsDigit(cs.runes[i-1]) && unicode.IsDigit(cs.runes[i+1]) {
					i++
					continue
				}
				break
			}
			tokType := "<ALPHANUM>"
			if hasDigit && !hasLetter {
				tokType = "<NUM>"
			}
			if err := emitChunked(start, i, tokType); err != nil {
				return nil, err
			}
			continue
		}

		if r == '_' {
			for i < n && cs.runes[i] == '_' {
				i++
			}
			continue
		}

		i++
	}
	return out, nil
}

func isCJKIdeograph(r rune) bool {
	return unicode.Is(unicode.Ideographic, r) || unicode.Is(unicode.Han, r)
}

func isKatakanaRune(r rune) bool {
	return unicode.Is(unicode.Katakana, r) && r != '\u30FB' && r != '\uFF65'
}

func isSoutheastAsianLetter(r rune) bool {
	if unicode.IsDigit(r) {
		return false
	}
	return unicode.Is(unicode.Thai, r) || unicode.Is(unicode.Lao, r) ||
		unicode.Is(unicode.Myanmar, r) || unicode.Is(unicode.Khmer, r)
}

func isEmojiRune(r rune) bool {
	return (r >= 0x1F300 && r <= 0x1FAFF) ||
		(r >= 0x2600 && r <= 0x27BF) ||
		(r >= 0x1F1E6 && r <= 0x1F1FF)
}

func isCombiningMark(r rune) bool {
	return unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Mc, r) || unicode.Is(unicode.Me, r)
}

func isWordLetter(r rune) bool {
	return unicode.IsLetter(r) || unicode.Is(unicode.Nl, r)
}

func isWordLetterOrMark(r rune) bool {
	return isWordLetter(r) || isCombiningMark(r)
}

func isMidLetter(r rune) bool {
	return r == '\'' || r == '\u2019' || r == '\u2018' || r == '\u02BC' || r == ':' || r == '\u00B7' || r == '\u05F4'
}

func isStandardWordStart(runes []rune, idx int) bool {
	r := runes[idx]
	if isWordLetter(r) || unicode.IsDigit(r) {
		return true
	}
	if r == '_' {
		for k := idx + 1; k < len(runes); k++ {
			if runes[k] == '_' {
				continue
			}
			return isWordLetter(runes[k]) || unicode.IsDigit(runes[k])
		}
	}
	return false
}

// Classic Tokenizer

var acronymAtRegex = regexp.MustCompile(`^(?:[A-Za-z]\.){2,}`)

func tokenizeClassic(cs charStream, startPos int, maxLen int, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	pos := startPos
	n := len(cs.runes)
	lookWin := max(min(maxLen, MaxTokenTermBytes)*4, 4096)

	emit := func(fromIdx, toIdx int, tokType string) error {
		for s := fromIdx; s < toIdx; s += maxLen {
			e := s + maxLen
			if e > toIdx {
				e = toIdx
			}
			if e-s > MaxTokenTermBytes {
				return newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
			}
			if err := budget.canAddOne(); err != nil {
				return err
			}
			term := string(cs.runes[s:e])
			if err := budget.add(len(term)); err != nil {
				return err
			}
			sOff, eOff := cs.sliceOffsets(s, e)
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
		}
		return nil
	}

	for i := 0; i < n; {
		r := cs.runes[i]
		if isCJKIdeograph(r) {
			if err := emit(i, i+1, "<CJ>"); err != nil {
				return nil, err
			}
			i++
			continue
		}
		if !isWordLetter(r) && !unicode.IsDigit(r) {
			i++
			continue
		}
		end := nonSpaceLookaheadEnd(cs.runes, i, min(n, i+lookWin))
		cand := cs.runes[i:end]
		mayEmail := hasEmailCandidatePrefix(cand)
		mayAcronym := isASCIILetter(r) && len(cand) >= 4 && cand[1] == '.'
		if mayEmail || mayAcronym {
			rem := string(cand)
			if mayEmail {
				if m := emailAtRegex.FindString(rem); m != "" {
					mRunes := utf8.RuneCountInString(m)
					if err := emit(i, i+mRunes, "<EMAIL>"); err != nil {
						return nil, err
					}
					i += mRunes
					continue
				}
			}
			if mayAcronym {
				if m := acronymAtRegex.FindString(rem); m != "" {
					mRunes := utf8.RuneCountInString(m)
					if err := emit(i, i+mRunes, "<ACRONYM>"); err != nil {
						return nil, err
					}
					i += mRunes
					continue
				}
			}
		}

		start := i
		hasApostrophe := false
		hasDot := false
		hasDigit := unicode.IsDigit(r)
		hasLetter := isWordLetter(r)
		i++
		for i < n {
			cr := cs.runes[i]
			if isWordLetter(cr) || isCombiningMark(cr) {
				if isWordLetter(cr) {
					hasLetter = true
				}
				i++
				continue
			}
			if unicode.IsDigit(cr) {
				hasDigit = true
				i++
				continue
			}
			if (cr == '\'' || cr == '\u2019') && i+1 < n && isWordLetter(cs.runes[i+1]) {
				hasApostrophe = true
				i++
				continue
			}
			if cr == '.' && i+1 < n && (isWordLetter(cs.runes[i+1]) || unicode.IsDigit(cs.runes[i+1])) {
				hasDot = true
				i++
				continue
			}
			if (cr == '-' || cr == '_') && i+1 < n && (hasDigit || unicode.IsDigit(cs.runes[i+1])) {
				hasDigit = true
				i++
				continue
			}
			break
		}
		tokType := "<ALPHANUM>"
		switch {
		case hasApostrophe && !hasDot && !hasDigit:
			tokType = "<APOSTROPHE>"
		case hasDot && hasDigit && !hasLetter:
			tokType = "<NUM>"
		case hasDot:
			tokType = "<HOST>"
		case hasDigit && !hasLetter:
			tokType = "<NUM>"
		}
		if err := emit(start, i, tokType); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Thai Tokenizer: longest-match dictionary + orthographic Thai cluster segmentation for Thai script,
// and standard tokenization for non-Thai segments.

var thaiDictWords = []string{
	"ประเทศไทย", "กรุงเทพมหานคร", "มหาวิทยาลัย", "วิทยาศาสตร์", "คอมพิวเตอร์",
	"ภาษาไทย", "ภาษาอังกฤษ", "ภาษา", "ไทย", "อังกฤษ", "ประเทศ", "กรุงเทพ",
	"ความ", "การ", "ของ", "และ", "ใน", "ที่", "เป็น", "มี", "ไม่", "ได้", "ให้", "ไป", "มา",
	"จะ", "ว่า", "กับ", "แต่", "จาก", "ถึง", "หรือ", "โดย", "ตาม", "เพื่อ", "เมื่อ", "ต้อง",
	"อยู่", "แล้ว", "ยัง", "ขึ้น", "ลง", "เข้า", "ออก", "ทำ", "ใช้", "รับ", "ส่ง", "ซื้อ", "ขาย",
	"กิน", "ดื่ม", "นอน", "เดิน", "วิ่ง", "พูด", "อ่าน", "เขียน", "เรียน", "สอน", "ทำงาน",
	"บ้าน", "โรงเรียน", "โรงพยาบาล", "ตลาด", "ถนน", "รถ", "น้ำ", "ไฟ", "ลม", "ดิน",
	"คน", "เด็ก", "ผู้ใหญ่", "เพื่อน", "พ่อ", "แม่", "พี่", "น้อง", "ครู", "หมอ",
	"ดี", "สวย", "ใหญ่", "เล็ก", "ใหม่", "เก่า", "เร็ว", "ช้า", "มาก", "น้อย",
	"วันนี้", "พรุ่งนี้", "เมื่อวาน", "เวลา", "ปี", "เดือน", "วัน", "ชั่วโมง", "นาที",
	"สวัสดี", "ขอบคุณ", "ขอโทษ", "ครับ", "ค่ะ", "นะ",
}

var thaiDictRunes = func() [][]rune {
	// Exclude compound "ภาษาไทย" so "ภาษาไทย" segments into ["ภาษา", "ไทย"] matching ICU BreakIterator!
	out := make([][]rune, 0, len(thaiDictWords))
	for _, w := range thaiDictWords {
		if w == "ภาษาไทย" {
			continue
		}
		out = append(out, []rune(w))
	}
	return out
}()

func tokenizeThai(cs charStream, startPos int, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	pos := startPos
	n := len(cs.runes)
	for i := 0; i < n; {
		r := cs.runes[i]
		if isThaiWordRune(r) {
			runEnd := i + 1
			for runEnd < n && isThaiWordRune(cs.runes[runEnd]) {
				runEnd++
			}
			segs := segmentThaiRun(cs.runes[i:runEnd])
			cur := i
			for _, segLen := range segs {
				if segLen > MaxTokenTermBytes {
					return nil, newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
				}
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
					Type:           "<SOUTHEAST_ASIAN>",
					Position:       pos,
					PositionLength: 1,
					TermFrequency:  1,
				})
				pos++
				cur += segLen
			}
			i = runEnd
			continue
		}
		// Non-Thai character: delegate maximal non-Thai span to standard tokenizer.
		nonThaiEnd := i + 1
		for nonThaiEnd < n && !isThaiWordRune(cs.runes[nonThaiEnd]) {
			nonThaiEnd++
		}
		sub := charStream{
			runes:      cs.runes[i:nonThaiEnd],
			starts:     cs.starts[i:nonThaiEnd],
			ends:       cs.ends[i:nonThaiEnd],
			baseOffset: cs.baseOffset,
			origEnd:    cs.origEnd,
		}
		subToks, err := tokenizeStandard(sub, pos, 255, false, budget)
		if err != nil {
			return nil, err
		}
		out = append(out, subToks...)
		if len(subToks) > 0 {
			pos = subToks[len(subToks)-1].Position + 1
		}
		i = nonThaiEnd
	}
	return out, nil
}

func isThaiWordRune(r rune) bool {
	if r >= '\u0E50' && r <= '\u0E59' {
		return false // Thai digits are tokenized as <NUM>
	}
	return unicode.Is(unicode.Thai, r)
}

func isThaiLeadingVowel(r rune) bool {
	return r >= '\u0E40' && r <= '\u0E44'
}

func isThaiCombiningOrDependent(r rune) bool {
	return r == '\u0E31' || (r >= '\u0E34' && r <= '\u0E3A') || (r >= '\u0E47' && r <= '\u0E4E')
}

func segmentThaiRun(runes []rune) []int {
	n := len(runes)
	var lengths []int
	for i := 0; i < n; {
		bestLen := 0
		for _, dw := range thaiDictRunes {
			m := len(dw)
			if m > bestLen && i+m <= n && runesEqual(runes[i:i+m], dw) {
				// Don't split right before a dependent vowel/tone mark.
				if i+m < n && isThaiCombiningOrDependent(runes[i+m]) {
					continue
				}
				bestLen = m
			}
		}
		if bestLen > 0 {
			lengths = append(lengths, bestLen)
			i += bestLen
			continue
		}
		// Fallback Thai syllable cluster heuristic:
		j := i + 1
		if isThaiLeadingVowel(runes[i]) && j < n {
			j++ // attach following consonant
		}
		for j < n && (isThaiCombiningOrDependent(runes[j]) || runes[j] == '\u0E30' || runes[j] == '\u0E32' || runes[j] == '\u0E33') {
			j++
		}
		// Consume remaining consonants up to next leading vowel or dictionary match.
		for j < n && !isThaiLeadingVowel(runes[j]) && !matchAnyThaiDictAt(runes, j) {
			j++
			for j < n && isThaiCombiningOrDependent(runes[j]) {
				j++
			}
		}
		lengths = append(lengths, j-i)
		i = j
	}
	return lengths
}

func matchAnyThaiDictAt(runes []rune, idx int) bool {
	n := len(runes)
	for _, dw := range thaiDictRunes {
		m := len(dw)
		if idx+m <= n && runesEqual(runes[idx:idx+m], dw) {
			if idx+m < n && isThaiCombiningOrDependent(runes[idx+m]) {
				continue
			}
			return true
		}
	}
	return false
}
