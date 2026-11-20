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
	"sort"
	"strings"
	"unicode"
)

func buildCompoundTokenFilter(displayName string, normType string, def map[string]any, bctx filterBuildContext) (*compiledTokenFilter, error) {
	maxNGramDiff := DefaultMaxNGramDiff
	maxShingleDiff := DefaultMaxShingleDiff
	if bctx.cfg != nil {
		maxNGramDiff = bctx.cfg.MaxNGramDiff
		maxShingleDiff = bctx.cfg.MaxShingleDiff
	}

	switch normType {
	case "ngram", "edge_ngram":
		isEdge := normType == "edge_ngram"
		minGram, maxGram, err := parseMinMaxGram(def, 1, 2)
		if err != nil {
			return nil, err
		}
		if !isEdge && maxGram-minGram > maxNGramDiff {
			return nil, newIllegalArgError(fmt.Sprintf(
				"The difference between max_gram and min_gram in NGram Filter must be less than or equal to: [%d] but was [%d]. This limit can be set by changing the [index.max_ngram_diff] index level setting.",
				maxNGramDiff, maxGram-minGram,
			))
		}
		preserveOrig := false
		if def != nil {
			if raw, ok := def["preserve_original"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("preserve_original in ngram filter must be boolean")
				}
				preserveOrig = b
			}
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token, budget *tokenStreamBudget) ([]Token, error) {
				return applyNGramFilter(tokens, minGram, maxGram, isEdge, preserveOrig, budget)
			},
		}, nil

	case "shingle":
		minSize := 2
		maxSize := 2
		outputUnigrams := true
		outputUnigramsIfNoShingles := false
		sep := " "
		filler := "_"
		if def != nil {
			if raw, ok := def["min_shingle_size"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 2 {
					return nil, newIllegalArgError("min_shingle_size must be >= 2")
				}
				minSize = n
			}
			if raw, ok := def["max_shingle_size"]; ok {
				n, valid := extractInt(raw)
				if !valid || n < 2 {
					return nil, newIllegalArgError("max_shingle_size must be >= 2")
				}
				maxSize = n
			}
			if raw, ok := def["output_unigrams"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("output_unigrams in shingle filter must be boolean")
				}
				outputUnigrams = b
			}
			if raw, ok := def["output_unigrams_if_no_shingles"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("output_unigrams_if_no_shingles in shingle filter must be boolean")
				}
				outputUnigramsIfNoShingles = b
			}
			if s, hasSep := def["token_separator"]; hasSep {
				if str, ok := s.(string); ok {
					sep = str
				}
			}
			if f, hasFil := def["filler_token"]; hasFil {
				if str, ok := f.(string); ok {
					filler = str
				}
			}
		}
		if maxSize < minSize {
			return nil, newIllegalArgError(fmt.Sprintf("max_shingle_size [%d] cannot be less than min_shingle_size [%d]", maxSize, minSize))
		}
		if maxSize-minSize > maxShingleDiff {
			return nil, newIllegalArgError(fmt.Sprintf(
				"The difference between max_shingle_size and min_shingle_size in Shingle Filter must be less than or equal to: [%d] but was [%d]. This limit can be set by changing the [index.max_shingle_diff] index level setting.",
				maxShingleDiff, maxSize-minSize,
			))
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token, budget *tokenStreamBudget) ([]Token, error) {
				return applyShingleFilter(tokens, minSize, maxSize, outputUnigrams, outputUnigramsIfNoShingles, sep, filler, budget)
			},
		}, nil

	case "word_delimiter", "word_delimiter_graph":
		isGraph := normType == "word_delimiter_graph"
		opts, err := parseWordDelimiterOptions(def, isGraph, bctx.opts)
		if err != nil {
			return nil, err
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token, budget *tokenStreamBudget) ([]Token, error) {
				return applyWordDelimiterFilter(tokens, opts, budget)
			},
		}, nil

	case "common_grams":
		if def == nil {
			return nil, newIllegalArgError("common_grams filter requires [common_words] or [common_words_path]")
		}
		ignoreCase := false
		queryMode := false
		if raw, ok := def["ignore_case"]; ok {
			b, valid := extractBool(raw)
			if !valid {
				return nil, newIllegalArgError("ignore_case in common_grams must be boolean")
			}
			ignoreCase = b
		}
		if raw, ok := def["query_mode"]; ok {
			b, valid := extractBool(raw)
			if !valid {
				return nil, newIllegalArgError("query_mode in common_grams must be boolean")
			}
			queryMode = b
		}
		cwRaw := def["common_words"]
		cwPath, _ := def["common_words_path"].(string)
		if cwRaw == nil && strings.TrimSpace(cwPath) == "" {
			return nil, newIllegalArgError("common_grams filter requires [common_words] or [common_words_path]")
		}
		commonSet, err := resolveStopwords(cwRaw, "common_words_path", cwPath, "_none_", ignoreCase, bctx.opts)
		if err != nil {
			return nil, err
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token, budget *tokenStreamBudget) ([]Token, error) {
				return applyCommonGrams(tokens, commonSet, ignoreCase, queryMode, budget)
			},
		}, nil

	case "dictionary_decompounder", "hyphenation_decompounder":
		if def == nil && normType == "dictionary_decompounder" {
			return nil, newIllegalArgError("dictionary_decompounder requires [word_list] or [word_list_path]")
		}
		minWord := 5
		minSub := 2
		maxSub := 15
		onlyLongest := false
		var words []string
		if def != nil {
			if pathVal, ok := def["word_list_path"].(string); ok && pathVal != "" {
				lines, err := resolvePathSetting("word_list_path", pathVal, bctx.opts)
				if err != nil {
					return nil, err
				}
				words = append(words, lines...)
			}
			if hyphPath, ok := def["hyphenation_patterns_path"].(string); ok && hyphPath != "" {
				if _, err := resolvePathSetting("hyphenation_patterns_path", hyphPath, bctx.opts); err != nil {
					return nil, err
				}
			}
			words = append(words, extractStringSlice(def["word_list"])...)
			if raw, ok := def["min_word_size"]; ok {
				if n, valid := extractInt(raw); valid && n >= 0 {
					minWord = n
				} else {
					return nil, newIllegalArgError("min_word_size must be >= 0")
				}
			}
			if raw, ok := def["min_subword_size"]; ok {
				if n, valid := extractInt(raw); valid && n >= 0 {
					minSub = n
				} else {
					return nil, newIllegalArgError("min_subword_size must be >= 0")
				}
			}
			if raw, ok := def["max_subword_size"]; ok {
				if n, valid := extractInt(raw); valid && n >= 1 {
					maxSub = n
				} else {
					return nil, newIllegalArgError("max_subword_size must be >= 1")
				}
			}
			if raw, ok := def["only_longest_match"]; ok {
				if b, valid := extractBool(raw); valid {
					onlyLongest = b
				} else {
					return nil, newIllegalArgError("only_longest_match must be boolean")
				}
			}
		}
		if normType == "dictionary_decompounder" && len(words) == 0 {
			if _, hasWL := def["word_list"]; !hasWL {
				if _, hasWLP := def["word_list_path"]; !hasWLP {
					return nil, newIllegalArgError("dictionary_decompounder requires [word_list] or [word_list_path]")
				}
			}
		}
		dict := make(map[string]bool, len(words))
		for _, w := range words {
			dict[strings.ToLower(strings.TrimSpace(w))] = true
		}
		return &compiledTokenFilter{
			name: displayName,
			typ:  normType,
			apply: func(tokens []Token, budget *tokenStreamBudget) ([]Token, error) {
				return applyDecompounder(tokens, dict, minWord, minSub, maxSub, onlyLongest, budget)
			},
		}, nil

	case "synonym", "synonym_graph":
		isGraph := normType == "synonym_graph"
		return buildSynonymTokenFilter(displayName, normType, isGraph, def, bctx)

	case "flatten_graph":
		return simpleTokenFilter(displayName, normType, applyFlattenGraph), nil

	default:
		return nil, newIllegalArgError(fmt.Sprintf("Unknown token filter type [%s]", normType))
	}
}

// NGram & EdgeNGram Token Filters

func applyNGramFilter(tokens []Token, minGram, maxGram int, isEdge bool, preserveOrig bool, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	for _, tok := range tokens {
		rs := []rune(tok.Term)
		n := len(rs)
		if n < minGram {
			if preserveOrig {
				cp := tok.clone()
				if err := budget.addToken(cp); err != nil {
					return nil, err
				}
				out = append(out, cp)
			}
			continue
		}
		if isEdge {
			limit := maxGram
			if limit > n {
				limit = n
			}
			for sz := minGram; sz <= limit; sz++ {
				if err := budget.canAddOne(); err != nil {
					return nil, err
				}
				cp := tok.clone()
				cp.Term = string(rs[:sz])
				if err := budget.addToken(cp); err != nil {
					return nil, err
				}
				out = append(out, cp)
			}
			if preserveOrig && n > maxGram {
				cp := tok.clone()
				if err := budget.addToken(cp); err != nil {
					return nil, err
				}
				out = append(out, cp)
			}
			continue
		}
		emittedOrig := false
		for s := 0; s < n; s++ {
			for sz := minGram; sz <= maxGram && s+sz <= n; sz++ {
				if err := budget.canAddOne(); err != nil {
					return nil, err
				}
				if s == 0 && sz == n {
					emittedOrig = true
				}
				cp := tok.clone()
				cp.Term = string(rs[s : s+sz])
				if err := budget.addToken(cp); err != nil {
					return nil, err
				}
				out = append(out, cp)
			}
		}
		if preserveOrig && !emittedOrig {
			cp := tok.clone()
			if err := budget.addToken(cp); err != nil {
				return nil, err
			}
			out = append(out, cp)
		}
	}
	return out, nil
}

// Shingle Token Filter

func applyShingleFilter(tokens []Token, minSize, maxSize int, outputUnigrams, outputUnigramsIfNoShingles bool, sep, filler string, budget *tokenStreamBudget) ([]Token, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	type slot struct {
		term     string
		startOff int
		endOff   int
		orig     *Token
		isFiller bool
	}
	var slots []slot
	for i, tok := range tokens {
		if i > 0 {
			gap := tok.Position - tokens[i-1].Position - 1
			if gap > maxSize {
				gap = maxSize
			}
			for g := 0; g < gap; g++ {
				slots = append(slots, slot{
					term:     filler,
					startOff: tok.StartOffset,
					endOff:   tok.StartOffset,
					isFiller: true,
				})
			}
		} else if tok.Position > 0 {
			gap := tok.Position
			if gap > maxSize {
				gap = maxSize
			}
			for g := 0; g < gap; g++ {
				slots = append(slots, slot{
					term:     filler,
					startOff: tok.StartOffset,
					endOff:   tok.StartOffset,
					isFiller: true,
				})
			}
		}
		cp := tok.clone()
		slots = append(slots, slot{
			term:     tok.Term,
			startOff: tok.StartOffset,
			endOff:   tok.EndOffset,
			orig:     &cp,
		})
	}

	var out []Token
	shingleCount := 0
	for i := 0; i < len(slots); i++ {
		if outputUnigrams && !slots[i].isFiller && slots[i].orig != nil {
			u := slots[i].orig.clone()
			u.Position = i
			u.PositionLength = 1
			if err := budget.addToken(u); err != nil {
				return nil, err
			}
			out = append(out, u)
		}
		for sz := minSize; sz <= maxSize && i+sz <= len(slots); sz++ {
			// Skip all-filler shingles
			hasReal := false
			parts := make([]string, sz)
			startOff := -1
			endOff := 0
			termBytes := (sz - 1) * len(sep)
			for k := 0; k < sz; k++ {
				sl := slots[i+k]
				parts[k] = sl.term
				termBytes += len(sl.term)
				if termBytes > MaxTokenTermBytes {
					return nil, newIllegalArgError(fmt.Sprintf("token term length [%d] exceeds maximum allowed [%d] bytes", termBytes, MaxTokenTermBytes))
				}
				if !sl.isFiller {
					if !hasReal {
						startOff = sl.startOff
					}
					endOff = sl.endOff
					hasReal = true
				}
			}
			if !hasReal {
				continue
			}
			if err := budget.canAddOne(); err != nil {
				return nil, err
			}
			shingleCount++
			shTok := Token{
				Term:           strings.Join(parts, sep),
				StartOffset:    startOff,
				EndOffset:      endOff,
				Type:           "shingle",
				Position:       i,
				PositionLength: sz,
				TermFrequency:  1,
			}
			if err := budget.addToken(shTok); err != nil {
				return nil, err
			}
			out = append(out, shTok)
		}
	}

	if shingleCount == 0 && !outputUnigrams && outputUnigramsIfNoShingles {
		for _, tok := range tokens {
			cp := tok.clone()
			if err := budget.addToken(cp); err != nil {
				return nil, err
			}
			out = append(out, cp)
		}
	}
	return out, nil
}

// WordDelimiter & WordDelimiterGraph Token Filters

type wdCharType uint8

const (
	wdDelim wdCharType = iota
	wdLower
	wdUpper
	wdAlpha
	wdDigit
)

type wordDelimiterOpts struct {
	isGraph               bool
	generateWordParts     bool
	generateNumberParts   bool
	catenateWords         bool
	catenateNumbers       bool
	catenateAll           bool
	splitOnCaseChange     bool
	preserveOriginal      bool
	splitOnNumerics       bool
	stemEnglishPossessive bool
	adjustOffsets         bool
	protectedWords        map[string]bool
	typeTable             map[rune]wdCharType
}

func parseWordDelimiterOptions(def map[string]any, isGraph bool, globalOpts Options) (wordDelimiterOpts, error) {
	o := wordDelimiterOpts{
		isGraph:               isGraph,
		generateWordParts:     true,
		generateNumberParts:   true,
		splitOnCaseChange:     true,
		splitOnNumerics:       true,
		stemEnglishPossessive: true,
		adjustOffsets:         true,
		protectedWords:        make(map[string]bool),
		typeTable:             make(map[rune]wdCharType),
	}
	if def == nil {
		return o, nil
	}
	boolFields := map[string]*bool{
		"generate_word_parts":     &o.generateWordParts,
		"generate_number_parts":   &o.generateNumberParts,
		"catenate_words":          &o.catenateWords,
		"catenate_numbers":        &o.catenateNumbers,
		"catenate_all":            &o.catenateAll,
		"split_on_case_change":    &o.splitOnCaseChange,
		"preserve_original":       &o.preserveOriginal,
		"split_on_numerics":       &o.splitOnNumerics,
		"stem_english_possessive": &o.stemEnglishPossessive,
		"adjust_offsets":          &o.adjustOffsets,
	}
	for key, ptr := range boolFields {
		if raw, exists := def[key]; exists {
			b, ok := extractBool(raw)
			if !ok {
				return o, newIllegalArgError(fmt.Sprintf("%s in word_delimiter must be boolean", key))
			}
			*ptr = b
		}
	}
	var prot []string
	if pathVal, ok := def["protected_words_path"].(string); ok && pathVal != "" {
		lines, err := resolvePathSetting("protected_words_path", pathVal, globalOpts)
		if err != nil {
			return o, err
		}
		prot = append(prot, lines...)
	}
	prot = append(prot, extractStringSlice(def["protected_words"])...)
	for _, w := range prot {
		o.protectedWords[w] = true
	}

	var ttLines []string
	if pathVal, ok := def["type_table_path"].(string); ok && pathVal != "" {
		lines, err := resolvePathSetting("type_table_path", pathVal, globalOpts)
		if err != nil {
			return o, err
		}
		ttLines = append(ttLines, lines...)
	}
	ttLines = append(ttLines, extractStringSlice(def["type_table"])...)
	for _, raw := range ttLines {
		idx := strings.Index(raw, "=>")
		if idx < 0 {
			return o, newIllegalArgError(fmt.Sprintf("Invalid type_table rule [%s]", raw))
		}
		lhs := unescapeMappingStr(strings.TrimSpace(raw[:idx]))
		rhs := strings.ToUpper(strings.TrimSpace(raw[idx+2:]))
		lrs := []rune(lhs)
		if len(lrs) != 1 {
			return o, newIllegalArgError(fmt.Sprintf("Invalid character [%s] in type_table", lhs))
		}
		var ct wdCharType
		switch rhs {
		case "LOWER":
			ct = wdLower
		case "UPPER":
			ct = wdUpper
		case "ALPHA":
			ct = wdAlpha
		case "DIGIT":
			ct = wdDigit
		case "ALPHANUM":
			ct = wdAlpha
		case "SUBWORD_DELIM":
			ct = wdDelim
		default:
			return o, newIllegalArgError(fmt.Sprintf("Unknown character type [%s] in type_table", rhs))
		}
		o.typeTable[lrs[0]] = ct
	}
	return o, nil
}

func (o wordDelimiterOpts) classifyRune(r rune) wdCharType {
	if ct, ok := o.typeTable[r]; ok {
		return ct
	}
	if unicode.IsDigit(r) {
		return wdDigit
	}
	if unicode.IsLower(r) {
		return wdLower
	}
	if unicode.IsUpper(r) || unicode.IsTitle(r) {
		return wdUpper
	}
	if unicode.IsLetter(r) || isCombiningMark(r) {
		return wdAlpha
	}
	return wdDelim
}

func isWDAlpha(ct wdCharType) bool {
	return ct == wdLower || ct == wdUpper || ct == wdAlpha
}

type wdSubword struct {
	text    string
	rStart  int
	rEnd    int
	isAlpha bool
	isDigit bool
}

func applyWordDelimiterFilter(tokens []Token, o wordDelimiterOpts, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	posDelta := 0

	for _, tok := range tokens {
		basePos := tok.Position + posDelta
		if tok.Keyword || o.protectedWords[tok.Term] {
			cp := tok.clone()
			cp.Position = basePos
			if err := budget.addToken(cp); err != nil {
				return nil, err
			}
			out = append(out, cp)
			continue
		}

		rs := []rune(tok.Term)
		origRuneLen := len(rs)
		canSliceOffsets := (!o.isGraph || o.adjustOffsets) && (tok.EndOffset-tok.StartOffset == origRuneLen)

		// Split into subwords
		subs := splitWordDelimiterSubwords(rs, o)
		if len(subs) == 0 {
			if o.preserveOriginal {
				cp := tok.clone()
				cp.Position = basePos
				if err := budget.addToken(cp); err != nil {
					return nil, err
				}
				out = append(out, cp)
			}
			continue
		}

		// If single unsplit subword identical to input term:
		if len(subs) == 1 && subs[0].rStart == 0 && subs[0].rEnd == origRuneLen {
			keep := (subs[0].isAlpha && o.generateWordParts) || (subs[0].isDigit && o.generateNumberParts) || o.preserveOriginal
			if keep {
				cp := tok.clone()
				cp.Position = basePos
				if err := budget.addToken(cp); err != nil {
					return nil, err
				}
				out = append(out, cp)
			}
			continue
		}

		subOff := func(rStart, rEnd int) (int, int) {
			if canSliceOffsets {
				return tok.StartOffset + rStart, tok.StartOffset + rEnd
			}
			return tok.StartOffset, tok.EndOffset
		}

		// Count generated part positions
		var keptParts []wdSubword
		for _, sw := range subs {
			if (sw.isAlpha && o.generateWordParts) || (sw.isDigit && o.generateNumberParts) {
				keptParts = append(keptParts, sw)
			}
		}

		spanLen := len(keptParts)
		if spanLen < 1 {
			spanLen = 1
		}

		var tokEmitted []Token
		emitToTok := func(em Token) error {
			if err := budget.addToken(em); err != nil {
				return err
			}
			tokEmitted = append(tokEmitted, em)
			return nil
		}

		if o.preserveOriginal {
			origCopy := tok.clone()
			origCopy.Position = basePos
			if o.isGraph {
				origCopy.PositionLength = spanLen
			} else {
				origCopy.PositionLength = 1
			}
			if err := emitToTok(origCopy); err != nil {
				return nil, err
			}
		}

		if o.catenateAll && len(subs) >= 2 {
			var sb strings.Builder
			for _, sw := range subs {
				if sb.Len()+len(sw.text) > MaxTokenTermBytes {
					return nil, newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
				}
				sb.WriteString(sw.text)
			}
			sOff, eOff := subOff(subs[0].rStart, subs[len(subs)-1].rEnd)
			pl := 1
			if o.isGraph {
				pl = spanLen
			}
			if err := emitToTok(Token{
				Term:           sb.String(),
				StartOffset:    sOff,
				EndOffset:      eOff,
				Type:           tok.Type,
				Position:       basePos,
				PositionLength: pl,
				TermFrequency:  1,
			}); err != nil {
				return nil, err
			}
		}

		// Emit individual parts & word/number run catenations
		for idx, kp := range keptParts {
			sOff, eOff := subOff(kp.rStart, kp.rEnd)
			if err := emitToTok(Token{
				Term:           kp.text,
				StartOffset:    sOff,
				EndOffset:      eOff,
				Type:           tok.Type,
				Position:       basePos + idx,
				PositionLength: 1,
				TermFrequency:  1,
			}); err != nil {
				return nil, err
			}
		}

		if o.catenateWords || o.catenateNumbers {
			// Scan runs on subs mapped to positions
			partPosIdx := make([]int, len(subs))
			pCur := 0
			for si, sw := range subs {
				partPosIdx[si] = pCur
				if (sw.isAlpha && o.generateWordParts) || (sw.isDigit && o.generateNumberParts) {
					pCur++
				}
			}
			for si := 0; si < len(subs); {
				isW := subs[si].isAlpha
				isD := subs[si].isDigit
				if (isW && o.catenateWords) || (isD && o.catenateNumbers) {
					sj := si + 1
					for sj < len(subs) && ((isW && subs[sj].isAlpha) || (isD && subs[sj].isDigit)) {
						sj++
					}
					if sj-si >= 2 {
						// Avoid duplicate if catenateAll already emitted full span
						if !o.catenateAll || si != 0 || sj != len(subs) {
							var sb strings.Builder
							for k := si; k < sj; k++ {
								if sb.Len()+len(subs[k].text) > MaxTokenTermBytes {
									return nil, newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
								}
								sb.WriteString(subs[k].text)
							}
							sOff, eOff := subOff(subs[si].rStart, subs[sj-1].rEnd)
							startP := basePos + partPosIdx[si]
							pl := 1
							if o.isGraph {
								endP := basePos + partPosIdx[sj-1] + 1
								if endP-startP > 1 {
									pl = endP - startP
								}
							}
							if err := emitToTok(Token{
								Term:           sb.String(),
								StartOffset:    sOff,
								EndOffset:      eOff,
								Type:           tok.Type,
								Position:       startP,
								PositionLength: pl,
								TermFrequency:  1,
							}); err != nil {
								return nil, err
							}
						}
					}
					si = sj
					continue
				}
				si++
			}
		}

		if o.isGraph && len(tokEmitted) > 1 {
			sort.SliceStable(tokEmitted, func(i, j int) bool {
				if tokEmitted[i].Position != tokEmitted[j].Position {
					return tokEmitted[i].Position < tokEmitted[j].Position
				}
				return tokEmitted[i].PositionLength > tokEmitted[j].PositionLength
			})
		}

		out = append(out, tokEmitted...)
		if len(keptParts) > 1 {
			posDelta += len(keptParts) - 1
		}
	}
	return out, nil
}

func splitWordDelimiterSubwords(rs []rune, o wordDelimiterOpts) []wdSubword {
	n := len(rs)
	// Strip trailing English possessive 's / 'S if enabled
	if o.stemEnglishPossessive && n >= 3 && (rs[n-1] == 's' || rs[n-1] == 'S') && (rs[n-2] == '\'' || rs[n-2] == '\u2019') {
		n -= 2
	}
	var subs []wdSubword
	i := 0
	for i < n {
		ct := o.classifyRune(rs[i])
		if ct == wdDelim {
			i++
			continue
		}
		start := i
		lastType := ct
		hasAlpha := isWDAlpha(ct)
		hasDigit := ct == wdDigit
		i++
		for i < n {
			cur := o.classifyRune(rs[i])
			if cur == wdDelim {
				break
			}
			if o.splitOnNumerics && ((isWDAlpha(lastType) && cur == wdDigit) || (lastType == wdDigit && isWDAlpha(cur))) {
				break
			}
			if o.splitOnCaseChange && isWDAlpha(lastType) && isWDAlpha(cur) {
				if lastType == wdLower && cur == wdUpper {
					break
				}
				if lastType == wdUpper && cur == wdUpper && i+1 < n && o.classifyRune(rs[i+1]) == wdLower {
					// e.g. "HTMLParser": split before 'P' (index i) so "HTML" and "Parser" separate!
					break
				}
			}
			if isWDAlpha(cur) {
				hasAlpha = true
			}
			if cur == wdDigit {
				hasDigit = true
			}
			lastType = cur
			i++
		}
		subs = append(subs, wdSubword{
			text:    string(rs[start:i]),
			rStart:  start,
			rEnd:    i,
			isAlpha: hasAlpha,
			isDigit: hasDigit && !hasAlpha,
		})
	}
	return subs
}

// CommonGrams Token Filter

func applyCommonGrams(tokens []Token, commonSet map[string]bool, ignoreCase bool, queryMode bool, budget *tokenStreamBudget) ([]Token, error) {
	if len(tokens) == 0 {
		return nil, nil
	}
	isCommon := func(term string) bool {
		if ignoreCase {
			return commonSet[strings.ToLower(term)]
		}
		return commonSet[term]
	}

	if !queryMode {
		var out []Token
		for i, tok := range tokens {
			cp := tok.clone()
			if err := budget.addToken(cp); err != nil {
				return nil, err
			}
			out = append(out, cp)
			if i+1 < len(tokens) && tokens[i+1].Position == tok.Position+1 && (isCommon(tok.Term) || isCommon(tokens[i+1].Term)) {
				if len(tok.Term)+1+len(tokens[i+1].Term) > MaxTokenTermBytes {
					return nil, newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
				}
				gram := Token{
					Term:           tok.Term + "_" + tokens[i+1].Term,
					StartOffset:    tok.StartOffset,
					EndOffset:      tokens[i+1].EndOffset,
					Type:           "gram",
					Position:       tok.Position,
					PositionLength: 1,
					TermFrequency:  1,
				}
				if err := budget.addToken(gram); err != nil {
					return nil, err
				}
				out = append(out, gram)
			}
		}
		return out, nil
	}

	// query_mode: true (CommonGramsQueryFilter)
	if len(tokens) == 1 {
		cp := tokens[0].clone()
		if err := budget.addToken(cp); err != nil {
			return nil, err
		}
		return []Token{cp}, nil
	}
	var out []Token
	pos := 0
	consumed := make([]bool, len(tokens))
	for i := 0; i < len(tokens); i++ {
		if i+1 < len(tokens) && tokens[i+1].Position == tokens[i].Position+1 && (isCommon(tokens[i].Term) || isCommon(tokens[i+1].Term)) {
			if len(tokens[i].Term)+1+len(tokens[i+1].Term) > MaxTokenTermBytes {
				return nil, newIllegalArgError(fmt.Sprintf("token term length exceeds maximum allowed [%d] bytes", MaxTokenTermBytes))
			}
			gram := Token{
				Term:           tokens[i].Term + "_" + tokens[i+1].Term,
				StartOffset:    tokens[i].StartOffset,
				EndOffset:      tokens[i+1].EndOffset,
				Type:           "gram",
				Position:       pos,
				PositionLength: 1,
				TermFrequency:  1,
			}
			if err := budget.addToken(gram); err != nil {
				return nil, err
			}
			out = append(out, gram)
			pos++
			consumed[i] = true
			consumed[i+1] = true
		} else if !consumed[i] && !isCommon(tokens[i].Term) {
			cp := tokens[i].clone()
			cp.Position = pos
			if err := budget.addToken(cp); err != nil {
				return nil, err
			}
			out = append(out, cp)
			pos++
		}
	}
	return out, nil
}

// Decompounder Filter

func applyDecompounder(tokens []Token, dict map[string]bool, minWord, minSub, maxSub int, onlyLongest bool, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	for _, tok := range tokens {
		orig := tok.clone()
		if err := budget.addToken(orig); err != nil {
			return nil, err
		}
		out = append(out, orig)
		rs := []rune(tok.Term)
		n := len(rs)
		if n < minWord || len(dict) == 0 {
			continue
		}
		lowerRs := []rune(strings.ToLower(tok.Term))
		if len(lowerRs) != n {
			lowerRs = rs
		}
		for i := 0; i < n; i++ {
			longestEnd := -1
			limit := i + maxSub
			if limit > n {
				limit = n
			}
			for end := i + minSub; end <= limit; end++ {
				cand := string(lowerRs[i:end])
				if dict[cand] {
					if onlyLongest {
						longestEnd = end
					} else {
						if err := budget.canAddOne(); err != nil {
							return nil, err
						}
						cp := tok.clone()
						cp.Term = string(rs[i:end])
						if err := budget.addToken(cp); err != nil {
							return nil, err
						}
						out = append(out, cp)
					}
				}
			}
			if onlyLongest && longestEnd > i {
				if err := budget.canAddOne(); err != nil {
					return nil, err
				}
				cp := tok.clone()
				cp.Term = string(rs[i:longestEnd])
				if err := budget.addToken(cp); err != nil {
					return nil, err
				}
				out = append(out, cp)
			}
		}
	}
	return out, nil
}

// Synonym, SynonymGraph & FlattenGraph Filters

type synonymEntry struct {
	src      []string
	targets  [][]string
	keepOrig bool
}

var wordnetLineRegex = regexp.MustCompile(`^s\(\s*(\d+)\s*,\s*\d+\s*,\s*'((?:''|[^'])+)'`)

func buildSynonymTokenFilter(displayName, normType string, isGraph bool, def map[string]any, bctx filterBuildContext) (*compiledTokenFilter, error) {
	if def == nil {
		return nil, newIllegalArgError(fmt.Sprintf("%s requires `synonyms`, `synonyms_path`, or `synonyms_set` to be configured", normType))
	}
	_, hasInline := def["synonyms"]
	synPath, _ := def["synonyms_path"].(string)
	synSet, _ := def["synonyms_set"].(string)
	if !hasInline && strings.TrimSpace(synPath) == "" && strings.TrimSpace(synSet) == "" {
		return nil, newIllegalArgError(fmt.Sprintf("%s requires `synonyms`, `synonyms_path`, or `synonyms_set` to be configured", normType))
	}

	expand := true
	if raw, ok := def["expand"]; ok {
		b, valid := extractBool(raw)
		if !valid {
			return nil, newIllegalArgError("expand in synonym filter must be boolean")
		}
		expand = b
	}
	lenient := false
	if raw, ok := def["lenient"]; ok {
		b, valid := extractBool(raw)
		if !valid {
			return nil, newIllegalArgError("lenient in synonym filter must be boolean")
		}
		lenient = b
	}
	format := "solr"
	if f, ok := def["format"].(string); ok && f != "" {
		lf := strings.ToLower(strings.TrimSpace(f))
		if lf != "solr" && lf != "wordnet" {
			return nil, newIllegalArgError(fmt.Sprintf("Unknown synonym format [%s]", f))
		}
		format = lf
	}

	phraseAnalyzer, err := buildSynonymPhraseAnalyzer(def, bctx)
	if err != nil {
		return nil, err
	}

	var staticLines []string
	if strings.TrimSpace(synPath) != "" {
		lines, err := resolvePathSetting("synonyms_path", synPath, bctx.opts)
		if err != nil {
			return nil, err
		}
		staticLines = append(staticLines, lines...)
	}
	staticLines = append(staticLines, extractStringSlice(def["synonyms"])...)

	// Validate static lines eagerly on build!
	var staticCompiled []synonymEntry
	if strings.TrimSpace(synSet) == "" {
		staticCompiled, err = compileSynonymEntries(staticLines, format, expand, lenient, phraseAnalyzer)
		if err != nil {
			return nil, err
		}
	}

	return &compiledTokenFilter{
		name: displayName,
		typ:  normType,
		apply: func(tokens []Token, budget *tokenStreamBudget) ([]Token, error) {
			entries := staticCompiled
			if strings.TrimSpace(synSet) != "" {
				var rawLines []string
				if bctx.opts.ResolveSynonymSet != nil {
					setLines, err := bctx.opts.ResolveSynonymSet(synSet)
					if err != nil {
						if _, ok := AsAnalysisError(err); ok {
							return nil, err
						}
						return nil, newIllegalArgError(err.Error())
					}
					rawLines = append(rawLines, setLines...)
				}
				rawLines = append(rawLines, staticLines...)
				var compErr error
				entries, compErr = compileSynonymEntries(rawLines, format, expand, lenient, phraseAnalyzer)
				if compErr != nil {
					return nil, compErr
				}
			}
			if len(entries) == 0 || len(tokens) == 0 {
				if err := budget.addSlice(tokens); err != nil {
					return nil, err
				}
				return tokens, nil
			}
			return applySynonymFilter(tokens, entries, isGraph, budget)
		},
	}, nil
}

func buildSynonymPhraseAnalyzer(def map[string]any, bctx filterBuildContext) (func(string) ([]string, error), error) {
	maxTok := effectiveMaxTokenCount(bctx.cfg)
	if anName, ok := def["analyzer"].(string); ok && strings.TrimSpace(anName) != "" {
		trimmedAn := strings.TrimSpace(anName)
		targetAn, err := resolveNamedAnalyzerWithCtx(trimmedAn, bctx)
		if err != nil {
			return nil, err
		}
		return func(phrase string) ([]string, error) {
			toks, err := runCompiledAnalyzerSingleText(targetAn, phrase, maxTok)
			if err != nil {
				return nil, err
			}
			terms := make([]string, 0, len(toks))
			for _, t := range toks {
				terms = append(terms, t.Term)
			}
			return terms, nil
		}, nil
	}

	tok := bctx.chainTokenizer
	chars := bctx.precedingChars
	filts := bctx.precedingFilts
	if tokName, ok := def["tokenizer"].(string); ok && strings.TrimSpace(tokName) != "" {
		var err error
		tok, err = resolveTokenizerStepWithOpts(tokName, bctx.cfg, bctx.opts)
		if err != nil {
			return nil, err
		}
		// Explicit tokenizer override on synonym filter runs standalone without enclosing token filters.
		filts = nil
	}
	if tok == nil {
		var err error
		tok, err = buildTokenizer("whitespace", "whitespace", nil, DefaultMaxNGramDiff)
		if err != nil {
			return nil, err
		}
	}
	return func(phrase string) ([]string, error) {
		cs := newCharStream(phrase, 0)
		for _, cf := range chars {
			var cfErr error
			cs, cfErr = cf.apply(cs)
			if cfErr != nil {
				return nil, cfErr
			}
		}
		toks, err := tok.tokenize(cs, 0, newTokenStreamBudget(maxTok))
		if err != nil {
			return nil, err
		}
		for _, tf := range filts {
			toks, err = tf.apply(toks, newTokenStreamBudget(maxTok))
			if err != nil {
				return nil, err
			}
		}
		terms := make([]string, 0, len(toks))
		for _, t := range toks {
			terms = append(terms, t.Term)
		}
		return terms, nil
	}, nil
}

const (
	maxTermsPerSynonymRule     = 1024
	maxCompiledSynonymMappings = 65536
)

func compileSynonymEntries(lines []string, format string, expand, lenient bool, analyzePhrase func(string) ([]string, error)) ([]synonymEntry, error) {
	if format == "wordnet" {
		return compileWordNetSynonyms(lines, expand, lenient, analyzePhrase)
	}
	type mergedRule struct {
		src         []string
		targets     [][]string
		seenTargets map[string]bool
		keepOrig    bool
	}
	var order []string
	byKey := make(map[string]*mergedRule)
	totalMappings := 0

	addMapping := func(src []string, dst []string, keepOrig bool) error {
		key := strings.Join(src, "\x00")
		mr, exists := byKey[key]
		if !exists {
			mr = &mergedRule{
				src:         src,
				seenTargets: make(map[string]bool),
				keepOrig:    keepOrig,
			}
			byKey[key] = mr
			order = append(order, key)
		} else if !keepOrig {
			mr.keepOrig = false
		}
		if slicesEqualStr(src, dst) {
			if !mr.keepOrig {
				mr.keepOrig = true
			}
			return nil
		}
		dstKey := strings.Join(dst, "\x00")
		if mr.seenTargets[dstKey] {
			return nil
		}
		totalMappings++
		if totalMappings > maxCompiledSynonymMappings {
			return newIllegalArgError(fmt.Sprintf("Synonym rules exceed maximum compiled mappings [%d]", maxCompiledSynonymMappings))
		}
		mr.seenTargets[dstKey] = true
		mr.targets = append(mr.targets, dst)
		return nil
	}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := indexUnescaped(line, "=>"); idx >= 0 {
			lhsRaw := strings.TrimSpace(line[:idx])
			rhsRaw := strings.TrimSpace(line[idx+2:])
			if lhsRaw == "" || rhsRaw == "" {
				if lenient {
					continue
				}
				return nil, newIllegalArgError(fmt.Sprintf("Invalid synonym rule [%s]", raw))
			}
			lhsParts := splitUnescapedComma(lhsRaw)
			rhsParts := splitUnescapedComma(rhsRaw)
			if len(lhsParts)+len(rhsParts) > maxTermsPerSynonymRule {
				return nil, newIllegalArgError(fmt.Sprintf("Synonym rule exceeds maximum allowed terms [%d]", maxTermsPerSynonymRule))
			}
			ruleTerms := 0
			var lhsPhrases [][]string
			for _, part := range lhsParts {
				toks, err := analyzePhrase(unescapeSynonymPhrase(strings.TrimSpace(part)))
				if err != nil {
					if lenient {
						continue
					}
					return nil, err
				}
				if len(toks) == 0 {
					if lenient {
						continue
					}
					return nil, newIllegalArgError(fmt.Sprintf("Synonym phrase [%s] analyzed to empty token list", part))
				}
				ruleTerms += len(toks)
				if ruleTerms > maxTermsPerSynonymRule {
					return nil, newIllegalArgError(fmt.Sprintf("Synonym rule exceeds maximum allowed terms [%d]", maxTermsPerSynonymRule))
				}
				lhsPhrases = append(lhsPhrases, toks)
			}
			var rhsPhrases [][]string
			for _, part := range rhsParts {
				toks, err := analyzePhrase(unescapeSynonymPhrase(strings.TrimSpace(part)))
				if err != nil {
					if lenient {
						continue
					}
					return nil, err
				}
				if len(toks) == 0 {
					if lenient {
						continue
					}
					return nil, newIllegalArgError(fmt.Sprintf("Synonym replacement [%s] analyzed to empty token list", part))
				}
				ruleTerms += len(toks)
				if ruleTerms > maxTermsPerSynonymRule {
					return nil, newIllegalArgError(fmt.Sprintf("Synonym rule exceeds maximum allowed terms [%d]", maxTermsPerSynonymRule))
				}
				rhsPhrases = append(rhsPhrases, toks)
			}
			for _, lp := range lhsPhrases {
				for _, rp := range rhsPhrases {
					if err := addMapping(lp, rp, false); err != nil {
						return nil, err
					}
				}
			}
			continue
		}

		// Equivalent synonym group: "a, b, c"
		parts := splitUnescapedComma(line)
		if len(parts) > maxTermsPerSynonymRule {
			return nil, newIllegalArgError(fmt.Sprintf("Synonym rule exceeds maximum allowed terms [%d]", maxTermsPerSynonymRule))
		}
		if len(parts) < 2 {
			if lenient {
				continue
			}
			if len(parts) == 1 && strings.TrimSpace(parts[0]) != "" {
				toks, err := analyzePhrase(unescapeSynonymPhrase(strings.TrimSpace(parts[0])))
				if err != nil && !lenient {
					return nil, err
				}
				if len(toks) > maxTermsPerSynonymRule {
					return nil, newIllegalArgError(fmt.Sprintf("Synonym rule exceeds maximum allowed terms [%d]", maxTermsPerSynonymRule))
				}
				continue
			}
			return nil, newIllegalArgError(fmt.Sprintf("Invalid synonym rule [%s]", raw))
		}
		ruleTerms := 0
		var phrases [][]string
		for _, part := range parts {
			toks, err := analyzePhrase(unescapeSynonymPhrase(strings.TrimSpace(part)))
			if err != nil {
				if lenient {
					continue
				}
				return nil, err
			}
			if len(toks) == 0 {
				if lenient {
					continue
				}
				return nil, newIllegalArgError(fmt.Sprintf("Synonym phrase [%s] analyzed to empty token list", part))
			}
			ruleTerms += len(toks)
			if ruleTerms > maxTermsPerSynonymRule {
				return nil, newIllegalArgError(fmt.Sprintf("Synonym rule exceeds maximum allowed terms [%d]", maxTermsPerSynonymRule))
			}
			phrases = append(phrases, toks)
		}
		if len(phrases) < 2 {
			continue
		}
		if expand {
			for _, src := range phrases {
				for _, dst := range phrases {
					if err := addMapping(src, dst, true); err != nil {
						return nil, err
					}
				}
			}
		} else {
			canonical := phrases[0]
			for i := 1; i < len(phrases); i++ {
				if err := addMapping(phrases[i], canonical, false); err != nil {
					return nil, err
				}
			}
		}
	}

	entries := make([]synonymEntry, 0, len(order))
	for _, key := range order {
		mr := byKey[key]
		if len(mr.targets) == 0 && mr.keepOrig {
			continue
		}
		entries = append(entries, synonymEntry{
			src:      mr.src,
			targets:  mr.targets,
			keepOrig: mr.keepOrig,
		})
	}
	// Longest phrase match wins first!
	sort.SliceStable(entries, func(i, j int) bool {
		return len(entries[i].src) > len(entries[j].src)
	})
	return entries, nil
}

func compileWordNetSynonyms(lines []string, expand, lenient bool, analyzePhrase func(string) ([]string, error)) ([]synonymEntry, error) {
	var synsetOrder []string
	synsets := make(map[string][]string)
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		m := wordnetLineRegex.FindStringSubmatch(line)
		if m == nil {
			if lenient {
				continue
			}
			return nil, newIllegalArgError(fmt.Sprintf("Invalid WordNet synonym line [%s]", raw))
		}
		id := m[1]
		word := strings.ReplaceAll(m[2], "''", "'")
		if _, exists := synsets[id]; !exists {
			synsetOrder = append(synsetOrder, id)
		}
		synsets[id] = append(synsets[id], word)
	}
	var solrEquiv []string
	for _, id := range synsetOrder {
		ws := synsets[id]
		if len(ws) >= 2 {
			solrEquiv = append(solrEquiv, strings.Join(ws, ", "))
		}
	}
	return compileSynonymEntries(solrEquiv, "solr", expand, lenient, analyzePhrase)
}

func indexUnescaped(s string, sep string) int {
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}

func splitUnescapedComma(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if s[i] == ',' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	out = append(out, cur.String())
	return out
}

func unescapeSynonymPhrase(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func slicesEqualStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func applySynonymFilter(tokens []Token, entries []synonymEntry, isGraph bool, budget *tokenStreamBudget) ([]Token, error) {
	if isGraph {
		return applySynonymGraph(tokens, entries, budget)
	}
	return applySynonymFlat(tokens, entries, budget)
}

// applySynonymFlat implements Lucene's classic (non-graph) SynonymFilter.
func applySynonymFlat(tokens []Token, entries []synonymEntry, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	n := len(tokens)
	posShift := 0

	for i := 0; i < n; {
		matchedIdx := -1
		for eIdx, ent := range entries {
			m := len(ent.src)
			if i+m <= n && matchTokenPhrase(tokens[i:i+m], ent.src) {
				matchedIdx = eIdx
				break
			}
		}
		if matchedIdx < 0 {
			cp := tokens[i].clone()
			cp.Position += posShift
			if err := budget.addToken(cp); err != nil {
				return nil, err
			}
			out = append(out, cp)
			i++
			continue
		}

		ent := entries[matchedIdx]
		m := len(ent.src)
		basePos := tokens[i].Position + posShift
		startOff := tokens[i].StartOffset
		endOff := tokens[i+m-1].EndOffset

		if ent.keepOrig {
			type posBucket struct {
				toks []Token
			}
			maxLen := m
			for _, tgt := range ent.targets {
				if len(tgt) > maxLen {
					maxLen = len(tgt)
				}
			}
			buckets := make([]posBucket, maxLen)
			for k := 0; k < m; k++ {
				cp := tokens[i+k].clone()
				cp.Position = basePos + k
				buckets[k].toks = append(buckets[k].toks, cp)
			}
			for _, tgt := range ent.targets {
				for k, term := range tgt {
					if err := budget.canAddOne(); err != nil {
						return nil, err
					}
					pl := 1
					if len(tgt) == 1 && m > 1 {
						pl = m
					}
					synTok := Token{
						Term:           term,
						StartOffset:    startOff,
						EndOffset:      endOff,
						Type:           "SYNONYM",
						Position:       basePos + k,
						PositionLength: pl,
						TermFrequency:  1,
					}
					buckets[k].toks = append(buckets[k].toks, synTok)
				}
			}
			for _, b := range buckets {
				for _, bt := range b.toks {
					if err := budget.addToken(bt); err != nil {
						return nil, err
					}
					out = append(out, bt)
				}
			}
			i += m
			continue
		}

		// Explicit replacement `lhs => rhs` (keepOrig == false)
		maxTgtLen := 1
		for _, tgt := range ent.targets {
			if len(tgt) > maxTgtLen {
				maxTgtLen = len(tgt)
			}
		}
		buckets := make([][]Token, maxTgtLen)
		for _, tgt := range ent.targets {
			for k, term := range tgt {
				if err := budget.canAddOne(); err != nil {
					return nil, err
				}
				buckets[k] = append(buckets[k], Token{
					Term:           term,
					StartOffset:    startOff,
					EndOffset:      endOff,
					Type:           "SYNONYM",
					Position:       basePos + k,
					PositionLength: 1,
					TermFrequency:  1,
				})
			}
		}
		for _, b := range buckets {
			for _, bt := range b {
				if err := budget.addToken(bt); err != nil {
					return nil, err
				}
				out = append(out, bt)
			}
		}
		posShift += maxTgtLen - m
		i += m
	}
	return out, nil
}

// applySynonymGraph implements Lucene's SynonymGraphFilter with exact internal node allocation!
func applySynonymGraph(tokens []Token, entries []synonymEntry, budget *tokenStreamBudget) ([]Token, error) {
	var out []Token
	n := len(tokens)
	curNode := 0
	if n > 0 && tokens[0].Position > 0 {
		curNode = tokens[0].Position
	}

	for i := 0; i < n; {
		if i > 0 {
			gap := tokens[i].Position - tokens[i-1].Position - 1
			if gap > 0 {
				curNode += gap
			}
		}

		matchedIdx := -1
		for eIdx, ent := range entries {
			m := len(ent.src)
			if i+m <= n && matchTokenPhrase(tokens[i:i+m], ent.src) {
				matchedIdx = eIdx
				break
			}
		}
		if matchedIdx < 0 {
			cp := tokens[i].clone()
			cp.Position = curNode
			cp.PositionLength = 1
			if err := budget.addToken(cp); err != nil {
				return nil, err
			}
			out = append(out, cp)
			curNode++
			i++
			continue
		}

		ent := entries[matchedIdx]
		m := len(ent.src)
		startNode := curNode
		startOff := tokens[i].StartOffset
		endOff := tokens[i+m-1].EndOffset

		// Allocate internal graph nodes: first for each multi-word target path, then for original path (if keepOrig).
		nextNode := startNode + 1
		targetInternalNodes := make([][]int, len(ent.targets))
		for tIdx, tgt := range ent.targets {
			if len(tgt) > 1 {
				nodes := make([]int, len(tgt)-1)
				for k := 0; k < len(tgt)-1; k++ {
					nodes[k] = nextNode
					nextNode++
				}
				targetInternalNodes[tIdx] = nodes
			}
		}
		var origInternalNodes []int
		if ent.keepOrig && m > 1 {
			origInternalNodes = make([]int, m-1)
			for k := 0; k < m-1; k++ {
				origInternalNodes[k] = nextNode
				nextNode++
			}
		}
		endNode := nextNode

		type graphOrderedTok struct {
			tok       Token
			pathOrder int
		}
		var batch []graphOrderedTok

		for tIdx, tgt := range ent.targets {
			intNodes := targetInternalNodes[tIdx]
			for k, term := range tgt {
				if err := budget.canAddOne(); err != nil {
					return nil, err
				}
				u := startNode
				if k > 0 {
					u = intNodes[k-1]
				}
				v := endNode
				if k < len(tgt)-1 {
					v = intNodes[k]
				}
				batch = append(batch, graphOrderedTok{
					tok: Token{
						Term:           term,
						StartOffset:    startOff,
						EndOffset:      endOff,
						Type:           "SYNONYM",
						Position:       u,
						PositionLength: v - u,
						TermFrequency:  1,
					},
					pathOrder: tIdx,
				})
			}
		}

		if ent.keepOrig {
			origOrder := len(ent.targets)
			for k := 0; k < m; k++ {
				u := startNode
				if k > 0 {
					u = origInternalNodes[k-1]
				}
				v := endNode
				if k < m-1 {
					v = origInternalNodes[k]
				}
				cp := tokens[i+k].clone()
				cp.Position = u
				cp.PositionLength = v - u
				batch = append(batch, graphOrderedTok{
					tok:       cp,
					pathOrder: origOrder,
				})
			}
		}

		sort.SliceStable(batch, func(a, b int) bool {
			if batch[a].tok.Position != batch[b].tok.Position {
				return batch[a].tok.Position < batch[b].tok.Position
			}
			return batch[a].pathOrder < batch[b].pathOrder
		})
		for _, item := range batch {
			if err := budget.addToken(item.tok); err != nil {
				return nil, err
			}
			out = append(out, item.tok)
		}

		curNode = endNode
		i += m
	}
	return out, nil
}

func matchTokenPhrase(toks []Token, phrase []string) bool {
	if len(toks) != len(phrase) {
		return false
	}
	for i, w := range phrase {
		if toks[i].Term != w {
			return false
		}
		if i > 0 && toks[i].Position != toks[i-1].Position+1 {
			return false
		}
	}
	return true
}

// applyFlattenGraph implements Lucene's FlattenGraphFilter: compacts sparse internal DAG node IDs
// via dense coordinate compression (O(|tokens| log |tokens|) memory) so every node's output position
// is the longest step-distance from the root, then stably orders by Position.
func applyFlattenGraph(tokens []Token) []Token {
	if len(tokens) == 0 {
		return nil
	}

	sorted := make([]Token, len(tokens))
	rawNodes := make([]int, 0, len(tokens)*2)
	for i, t := range tokens {
		sorted[i] = t.clone()
		if sorted[i].PositionLength < 1 {
			sorted[i].PositionLength = 1
		}
		u := sorted[i].Position
		v := u + sorted[i].PositionLength
		rawNodes = append(rawNodes, u, v)
	}
	sort.Ints(rawNodes)
	uniqueNodes := rawNodes[:0]
	for i, n := range rawNodes {
		if i == 0 || n != rawNodes[i-1] {
			uniqueNodes = append(uniqueNodes, n)
		}
	}
	kNodes := len(uniqueNodes)
	nodeToRank := make(map[int]int, kNodes)
	for r, n := range uniqueNodes {
		nodeToRank[n] = r
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Position < sorted[j].Position
	})

	outPos := make([]int, kNodes)
	seen := make([]bool, kNodes)
	firstNode := sorted[0].Position
	rFirst := nodeToRank[firstNode]
	outPos[rFirst] = firstNode
	seen[rFirst] = true

	// Relax DAG edges in ascending start-node order.
	lastStart := firstNode
	lastOut := firstNode
	for _, tok := range sorted {
		u := tok.Position
		ru := nodeToRank[u]
		if !seen[ru] {
			gap := u - lastStart
			if gap < 1 {
				gap = 1
			}
			outPos[ru] = lastOut + gap
			seen[ru] = true
		}
		if u > lastStart {
			lastStart = u
			if outPos[ru] > lastOut {
				lastOut = outPos[ru]
			}
		}
		v := u + tok.PositionLength
		rv := nodeToRank[v]
		cand := outPos[ru] + 1
		if !seen[rv] || cand > outPos[rv] {
			outPos[rv] = cand
			seen[rv] = true
		}
	}

	type indexedTok struct {
		tok Token
		idx int
	}
	mapped := make([]indexedTok, len(tokens))
	for i, tok := range tokens {
		cp := tok.clone()
		pl := cp.PositionLength
		if pl < 1 {
			pl = 1
		}
		u := cp.Position
		v := u + pl
		ru := nodeToRank[u]
		rv := nodeToRank[v]
		cp.Position = outPos[ru]
		newPL := outPos[rv] - outPos[ru]
		if newPL < 1 {
			newPL = 1
		}
		cp.PositionLength = newPL
		mapped[i] = indexedTok{tok: cp, idx: i}
	}
	sort.SliceStable(mapped, func(i, j int) bool {
		if mapped[i].tok.Position != mapped[j].tok.Position {
			return mapped[i].tok.Position < mapped[j].tok.Position
		}
		return mapped[i].idx < mapped[j].idx
	})
	res := make([]Token, len(mapped))
	for i, m := range mapped {
		res[i] = m.tok
	}
	return res
}
