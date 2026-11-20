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
	"strings"
)

type compiledAnalyzer struct {
	name                 string
	isCustom             bool
	positionIncrementGap int
	charFilters          []*compiledCharFilter
	tokenizer            *compiledTokenizer
	tokenFilters         []*compiledTokenFilter
}

// IsBuiltInAnalyzer reports whether typeName is a built-in Elasticsearch analyzer.
func IsBuiltInAnalyzer(typeName string) bool {
	return isBuiltInAnalyzerType(typeName)
}

func isBuiltInAnalyzerType(typeName string) bool {
	switch strings.ToLower(strings.TrimSpace(typeName)) {
	case "standard", "simple", "whitespace", "stop", "keyword", "noop",
		"pattern", "fingerprint", "classic", "snowball", "chinese", "cjk", "thai",
		"standard_html_strip",
		"arabic", "armenian", "basque", "bengali", "brazilian", "bulgarian",
		"catalan", "czech", "danish", "dutch", "english", "estonian",
		"finnish", "french", "galician", "german", "greek", "hindi",
		"hungarian", "indonesian", "irish", "italian", "latvian", "lithuanian",
		"norwegian", "persian", "portuguese", "romanian", "russian", "serbian",
		"sorani", "spanish", "swedish", "turkish",
		"icu_analyzer", "kuromoji", "kuromoji_completion", "nori", "smartcn", "polish", "ukrainian":
		return true
	default:
		return false
	}
}

type langAnalyzerRecipe struct {
	charFilters []string
	elisionArts []string
	lowerLang   string
	preNorms    []string
	stopPreset  string
	postNorms   []string
	stemLang    string
	apostrophe  bool
	possessive  bool
}

var langAnalyzerRecipes = map[string]langAnalyzerRecipe{
	"arabic": {
		stopPreset: "_arabic_",
		postNorms:  []string{"arabic_normalization"},
		stemLang:   "arabic",
	},
	"armenian": {
		stopPreset: "_armenian_",
		stemLang:   "armenian",
	},
	"basque": {
		stopPreset: "_basque_",
		stemLang:   "basque",
	},
	"bengali": {
		preNorms:   []string{"decimal_digit", "indic_normalization", "bengali_normalization"},
		stopPreset: "_bengali_",
		stemLang:   "bengali",
	},
	"brazilian": {
		stopPreset: "_brazilian_",
		stemLang:   "brazilian",
	},
	"bulgarian": {
		stopPreset: "_bulgarian_",
		stemLang:   "bulgarian",
	},
	"catalan": {
		elisionArts: []string{"d", "l", "m", "n", "s", "t"},
		stopPreset:  "_catalan_",
		stemLang:    "catalan",
	},
	"czech": {
		stopPreset: "_czech_",
		stemLang:   "czech",
	},
	"danish": {
		stopPreset: "_danish_",
		stemLang:   "danish",
	},
	"dutch": {
		stopPreset: "_dutch_",
		stemLang:   "dutch",
	},
	"english": {
		possessive: true,
		stopPreset: "_english_",
		stemLang:   "porter",
	},
	"estonian": {
		stopPreset: "_estonian_",
		stemLang:   "estonian",
	},
	"finnish": {
		stopPreset: "_finnish_",
		stemLang:   "light_finnish",
	},
	"french": {
		elisionArts: defaultElisionArticles,
		stopPreset:  "_french_",
		stemLang:    "light_french",
	},
	"galician": {
		stopPreset: "_galician_",
		stemLang:   "minimal_galician",
	},
	"german": {
		stopPreset: "_german_",
		postNorms:  []string{"german_normalization"},
		stemLang:   "light_german",
	},
	"greek": {
		lowerLang:  "greek",
		stopPreset: "_greek_",
		stemLang:   "greek",
	},
	"hindi": {
		preNorms:   []string{"decimal_digit", "indic_normalization", "hindi_normalization"},
		stopPreset: "_hindi_",
		stemLang:   "hindi",
	},
	"hungarian": {
		stopPreset: "_hungarian_",
		stemLang:   "light_hungarian",
	},
	"indonesian": {
		stopPreset: "_indonesian_",
		stemLang:   "indonesian",
	},
	"irish": {
		elisionArts: []string{"d", "m", "b"},
		lowerLang:   "irish",
		stopPreset:  "_irish_",
		stemLang:    "irish",
	},
	"italian": {
		elisionArts: []string{"c", "l", "all", "dall", "dell", "nell", "sull", "coll", "pell", "gl", "agl", "dagl", "degl", "negl", "sugl", "un", "m", "t", "s", "v", "d"},
		stopPreset:  "_italian_",
		stemLang:    "light_italian",
	},
	"latvian": {
		stopPreset: "_latvian_",
		stemLang:   "latvian",
	},
	"lithuanian": {
		stopPreset: "_lithuanian_",
		stemLang:   "lithuanian",
	},
	"norwegian": {
		stopPreset: "_norwegian_",
		stemLang:   "light_norwegian",
	},
	"persian": {
		charFilters: []string{"zero_width_spaces"},
		preNorms:    []string{"arabic_normalization", "persian_normalization"},
		stopPreset:  "_persian_",
	},
	"portuguese": {
		stopPreset: "_portuguese_",
		stemLang:   "light_portuguese",
	},
	"romanian": {
		stopPreset: "_romanian_",
		stemLang:   "romanian",
	},
	"russian": {
		stopPreset: "_russian_",
		stemLang:   "russian",
	},
	"serbian": {
		preNorms:   []string{"serbian_normalization"},
		stopPreset: "_serbian_",
		stemLang:   "serbian",
	},
	"sorani": {
		preNorms:   []string{"sorani_normalization", "decimal_digit"},
		stopPreset: "_sorani_",
		stemLang:   "sorani",
	},
	"spanish": {
		stopPreset: "_spanish_",
		stemLang:   "light_spanish",
	},
	"swedish": {
		stopPreset: "_swedish_",
		stemLang:   "light_swedish",
	},
	"turkish": {
		apostrophe: true,
		lowerLang:  "turkish",
		stopPreset: "_turkish_",
		stemLang:   "turkish",
	},
}

func buildBuiltInOrTypedAnalyzerWithCtx(displayName string, typeName string, def map[string]any, parentCtx filterBuildContext) (*compiledAnalyzer, error) {
	cfg := parentCtx.cfg
	opts := parentCtx.opts
	normType := strings.ToLower(strings.TrimSpace(typeName))
	posGap, err := parsePosIncrementGap(def)
	if err != nil {
		return nil, err
	}
	maxNGramDiff := DefaultMaxNGramDiff
	if cfg != nil {
		maxNGramDiff = cfg.MaxNGramDiff
	}
	bctx := parentCtx
	bctx.precedingChars = nil
	bctx.chainTokenizer = nil
	bctx.precedingFilts = nil

	buildStop := func(defaultPreset string) (*compiledTokenFilter, error) {
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
			stopDef = map[string]any{"stopwords": defaultPreset}
		}
		return buildTokenFilter("stop", "stop", stopDef, false, bctx)
	}

	switch normType {
	case "standard_html_strip":
		return nil, newIllegalArgError("[standard_html_strip] analyzer is not supported for new indices, use a custom analyzer using [standard] tokenizer and [html_strip] char_filter, plus [lowercase] filter")

	case "standard":
		tok, err := buildTokenizer("standard", "standard", def, maxNGramDiff)
		if err != nil {
			return nil, err
		}
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		st, err := buildStop("_none_")
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{lc, st},
		}, nil

	case "simple":
		tok, _ := buildTokenizer("lowercase", "lowercase", nil, maxNGramDiff)
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
		}, nil

	case "whitespace":
		tok, err := buildTokenizer("whitespace", "whitespace", def, maxNGramDiff)
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
		}, nil

	case "stop":
		tok, _ := buildTokenizer("lowercase", "lowercase", nil, maxNGramDiff)
		st, err := buildStop("_english_")
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{st},
		}, nil

	case "keyword", "noop":
		tok, err := buildTokenizer("keyword", "keyword", def, maxNGramDiff)
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
		}, nil

	case "pattern":
		tok, err := buildTokenizer("pattern", "pattern", def, maxNGramDiff)
		if err != nil {
			return nil, err
		}
		doLower := true
		if def != nil {
			if raw, ok := def["lowercase"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("lowercase in pattern analyzer must be boolean")
				}
				doLower = b
			}
		}
		var filts []*compiledTokenFilter
		if doLower {
			lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
			filts = append(filts, lc)
		}
		st, err := buildStop("_none_")
		if err != nil {
			return nil, err
		}
		filts = append(filts, st)
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         filts,
		}, nil

	case "fingerprint":
		tok, _ := buildTokenizer("standard", "standard", nil, maxNGramDiff)
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		preserveOrig := false
		if def != nil {
			if raw, ok := def["preserve_original"]; ok {
				b, valid := extractBool(raw)
				if !valid {
					return nil, newIllegalArgError("preserve_original in fingerprint analyzer must be boolean")
				}
				preserveOrig = b
			}
		}
		af, err := buildTokenFilter("asciifolding", "asciifolding", map[string]any{"preserve_original": preserveOrig}, false, bctx)
		if err != nil {
			return nil, err
		}
		st, err := buildStop("_none_")
		if err != nil {
			return nil, err
		}
		fp, err := buildTokenFilter("fingerprint", "fingerprint", def, false, bctx)
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{lc, af, st, fp},
		}, nil

	case "classic":
		tok, err := buildTokenizer("classic", "classic", def, maxNGramDiff)
		if err != nil {
			return nil, err
		}
		cf, _ := buildTokenFilter("classic", "classic", nil, true, bctx)
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		st, err := buildStop("_english_")
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{cf, lc, st},
		}, nil

	case "snowball":
		lang := "english"
		if def != nil {
			if l, ok := def["language"].(string); ok && strings.TrimSpace(l) != "" {
				lang = strings.TrimSpace(l)
			}
		}
		tok, _ := buildTokenizer("standard", "standard", nil, maxNGramDiff)
		var filts []*compiledTokenFilter
		if strings.EqualFold(lang, "turkish") {
			lc, _ := buildTokenFilter("lowercase", "lowercase", map[string]any{"language": "turkish"}, false, bctx)
			filts = append(filts, lc)
		} else {
			lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
			filts = append(filts, lc)
		}
		defaultPreset := "_" + strings.ToLower(lang) + "_"
		if _, exists := builtInStopwords[defaultPreset]; !exists {
			defaultPreset = "_none_"
		}
		st, err := buildStop(defaultPreset)
		if err != nil {
			return nil, err
		}
		filts = append(filts, st)
		sb, err := buildTokenFilter("snowball", "snowball", map[string]any{"language": lang}, false, bctx)
		if err != nil {
			return nil, err
		}
		filts = append(filts, sb)
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         filts,
		}, nil

	case "chinese":
		tok, _ := buildTokenizer("lowercase", "lowercase", nil, maxNGramDiff)
		st, err := buildStop("_english_")
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{st},
		}, nil

	case "cjk":
		tok, _ := buildTokenizer("standard", "standard", nil, maxNGramDiff)
		cw, _ := buildTokenFilter("cjk_width", "cjk_width", nil, true, bctx)
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		cb, _ := buildTokenFilter("cjk_bigram", "cjk_bigram", nil, true, bctx)
		st, err := buildStop("_cjk_")
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{cw, lc, cb, st},
		}, nil

	case "thai":
		tok, _ := buildTokenizer("thai", "thai", nil, maxNGramDiff)
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		dd, _ := buildTokenFilter("decimal_digit", "decimal_digit", nil, true, bctx)
		st, err := buildStop("_thai_")
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 displayName,
			isCustom:             false,
			positionIncrementGap: posGap,
			tokenizer:            tok,
			tokenFilters:         []*compiledTokenFilter{lc, dd, st},
		}, nil
	case "icu_analyzer", "kuromoji", "kuromoji_completion", "nori", "smartcn", "polish", "ukrainian":
		return buildPluginAnalyzer(displayName, normType, def, posGap, bctx)
	}

	recipe, ok := langAnalyzerRecipes[normType]
	if !ok {
		return nil, newIllegalArgError(fmt.Sprintf("Unknown analyzer type [%s] for [%s]", typeName, displayName))
	}

	var cfs []*compiledCharFilter
	for _, cfn := range recipe.charFilters {
		cf, err := buildCharFilter(cfn, cfn, nil, opts)
		if err != nil {
			return nil, err
		}
		cfs = append(cfs, cf)
	}
	tok, _ := buildTokenizer("standard", "standard", nil, maxNGramDiff)

	var tfs []*compiledTokenFilter
	if recipe.possessive {
		pf, _ := buildTokenFilter("possessive_english", "stemmer", map[string]any{"language": "possessive_english"}, false, bctx)
		tfs = append(tfs, pf)
	}
	if len(recipe.elisionArts) > 0 {
		ef, err := buildTokenFilter("elision", "elision", map[string]any{
			"articles":      recipe.elisionArts,
			"articles_case": true,
		}, false, bctx)
		if err != nil {
			return nil, err
		}
		tfs = append(tfs, ef)
	}
	if recipe.apostrophe {
		af, _ := buildTokenFilter("apostrophe", "apostrophe", nil, true, bctx)
		tfs = append(tfs, af)
	}
	if recipe.lowerLang != "" {
		lc, err := buildTokenFilter("lowercase", "lowercase", map[string]any{"language": recipe.lowerLang}, false, bctx)
		if err != nil {
			return nil, err
		}
		tfs = append(tfs, lc)
	} else {
		lc, _ := buildTokenFilter("lowercase", "lowercase", nil, true, bctx)
		tfs = append(tfs, lc)
	}
	for _, pn := range recipe.preNorms {
		nf, err := buildTokenFilter(pn, pn, nil, true, bctx)
		if err != nil {
			return nil, err
		}
		tfs = append(tfs, nf)
	}
	if recipe.stopPreset != "" {
		st, err := buildStop(recipe.stopPreset)
		if err != nil {
			return nil, err
		}
		tfs = append(tfs, st)
	}
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
	for _, pn := range recipe.postNorms {
		nf, err := buildTokenFilter(pn, pn, nil, true, bctx)
		if err != nil {
			return nil, err
		}
		tfs = append(tfs, nf)
	}
	if recipe.stemLang != "" {
		sf, err := buildTokenFilter("stemmer", "stemmer", map[string]any{"language": recipe.stemLang}, false, bctx)
		if err != nil {
			return nil, err
		}
		tfs = append(tfs, sf)
	}

	return &compiledAnalyzer{
		name:                 displayName,
		isCustom:             false,
		positionIncrementGap: posGap,
		charFilters:          cfs,
		tokenizer:            tok,
		tokenFilters:         tfs,
	}, nil
}

func parsePosIncrementGap(def map[string]any) (int, error) {
	if def == nil {
		return DefaultPositionIncrementGap, nil
	}
	raw, exists := def["position_increment_gap"]
	if !exists {
		return DefaultPositionIncrementGap, nil
	}
	n, ok := extractInt(raw)
	if !ok || n < 0 || n > MaxPositionIncrementGap {
		return 0, newIllegalArgError(fmt.Sprintf("position_increment_gap must be between 0 and %d", MaxPositionIncrementGap))
	}
	return n, nil
}
