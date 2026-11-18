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
	"sort"
	"strconv"
	"strings"
)

// IndexAnalysisConfig holds parsed per-index analysis settings, custom component definitions,
// and index-level token/ngram/shingle limits.
type IndexAnalysisConfig struct {
	MaxTokenCount  int
	MaxNGramDiff   int
	MaxShingleDiff int

	CharFilterDefs map[string]map[string]any
	TokenizerDefs  map[string]map[string]any
	FilterDefs     map[string]map[string]any
	AnalyzerDefs   map[string]map[string]any
	NormalizerDefs map[string]map[string]any

	compiledAnalyzers   map[string]*compiledAnalyzer
	compiledNormalizers map[string]*compiledAnalyzer
}

// Registry is an alias for IndexAnalysisConfig.
type Registry = IndexAnalysisConfig

// DefaultIndexAnalysisConfig returns an IndexAnalysisConfig with Elasticsearch default limits.
func DefaultIndexAnalysisConfig() *IndexAnalysisConfig {
	return &IndexAnalysisConfig{
		MaxTokenCount:       DefaultMaxTokenCount,
		MaxNGramDiff:        DefaultMaxNGramDiff,
		MaxShingleDiff:      DefaultMaxShingleDiff,
		CharFilterDefs:      make(map[string]map[string]any),
		TokenizerDefs:       make(map[string]map[string]any),
		FilterDefs:          make(map[string]map[string]any),
		AnalyzerDefs:        make(map[string]map[string]any),
		NormalizerDefs:      make(map[string]map[string]any),
		compiledAnalyzers:   make(map[string]*compiledAnalyzer),
		compiledNormalizers: make(map[string]*compiledAnalyzer),
	}
}

// NewRegistry parses raw index settings into a validated Registry.
func NewRegistry(rawSettings map[string]any, opts Options) (*Registry, error) {
	return ParseIndexAnalysisConfig(rawSettings, opts)
}

// ParseIndexAnalysisConfig parses and validates index settings supporting nested maps
// (`{"settings": {"index": {"analysis": ...}}}`, `{"analysis": ...}`) as well as flat dotted keys
// (`"index.analysis.analyzer.my_an.type": "custom"`, `"index.analyze.max_token_count": 3`).
func ParseIndexAnalysisConfig(rawSettings map[string]any, opts Options) (*IndexAnalysisConfig, error) {
	cfg := DefaultIndexAnalysisConfig()
	if len(rawSettings) == 0 {
		return cfg, nil
	}

	expanded := expandDottedMap(rawSettings)
	// Unwrap optional top-level "settings"
	if sMap, ok := expanded["settings"].(map[string]any); ok {
		merged := make(map[string]any, len(expanded)+len(sMap))
		for k, v := range expanded {
			if k != "settings" {
				merged[k] = v
			}
		}
		deepMergeMaps(merged, sMap)
		expanded = merged
	}
	// Unwrap optional "index" wrapper while keeping top-level keys
	if idxMap, ok := expanded["index"].(map[string]any); ok {
		merged := make(map[string]any, len(expanded)+len(idxMap))
		for k, v := range expanded {
			if k != "index" {
				merged[k] = v
			}
		}
		deepMergeMaps(merged, idxMap)
		expanded = merged
	}

	// Parse index-level limits
	if analyzeMap, ok := expanded["analyze"].(map[string]any); ok {
		if rawMax, hasMax := analyzeMap["max_token_count"]; hasMax {
			n, valid := extractInt(rawMax)
			if !valid || n < 1 {
				return nil, newIllegalArgError("index.analyze.max_token_count must be a positive integer")
			}
			cfg.MaxTokenCount = n
		}
	}
	if rawND, hasND := expanded["max_ngram_diff"]; hasND {
		n, valid := extractInt(rawND)
		if !valid || n < 0 {
			return nil, newIllegalArgError("index.max_ngram_diff must be >= 0")
		}
		cfg.MaxNGramDiff = n
	}
	if rawSD, hasSD := expanded["max_shingle_diff"]; hasSD {
		n, valid := extractInt(rawSD)
		if !valid || n < 0 {
			return nil, newIllegalArgError("index.max_shingle_diff must be >= 0")
		}
		cfg.MaxShingleDiff = n
	}

	analysisMap, _ := expanded["analysis"].(map[string]any)
	if len(analysisMap) == 0 {
		return cfg, nil
	}

	cfg.CharFilterDefs = extractNamedComponentDefs(analysisMap["char_filter"])
	cfg.TokenizerDefs = extractNamedComponentDefs(analysisMap["tokenizer"])
	cfg.FilterDefs = extractNamedComponentDefs(analysisMap["filter"])
	for k, v := range extractNamedComponentDefs(analysisMap["token_filter"]) {
		if _, exists := cfg.FilterDefs[k]; !exists {
			cfg.FilterDefs[k] = v
		}
	}
	cfg.AnalyzerDefs = extractNamedComponentDefs(analysisMap["analyzer"])
	cfg.NormalizerDefs = extractNamedComponentDefs(analysisMap["normalizer"])

	// Validate all defined char_filters, tokenizers, filters, normalizers, and analyzers eagerly!
	for name, def := range cfg.CharFilterDefs {
		typStr, _ := def["type"].(string)
		if strings.TrimSpace(typStr) == "" {
			return nil, newIllegalArgError(fmt.Sprintf("Char filter [%s] must specify [type]", name))
		}
		if _, err := buildCharFilter(name, typStr, def, opts); err != nil {
			return nil, err
		}
	}
	for name, def := range cfg.TokenizerDefs {
		typStr, _ := def["type"].(string)
		if strings.TrimSpace(typStr) == "" {
			return nil, newIllegalArgError(fmt.Sprintf("Tokenizer [%s] must specify [type]", name))
		}
		if _, err := buildTokenizer(name, typStr, def, cfg.MaxNGramDiff); err != nil {
			return nil, err
		}
	}
	for name, def := range cfg.FilterDefs {
		typStr, _ := def["type"].(string)
		if strings.TrimSpace(typStr) == "" {
			return nil, newIllegalArgError(fmt.Sprintf("Token filter [%s] must specify [type]", name))
		}
		if _, err := buildTokenFilter(name, typStr, def, false, filterBuildContext{cfg: cfg, opts: opts}); err != nil {
			return nil, err
		}
	}
	for name, def := range cfg.NormalizerDefs {
		norm, err := compileDefinedNormalizer(name, def, cfg, opts)
		if err != nil {
			return nil, err
		}
		cfg.compiledNormalizers[name] = norm
	}
	for name, def := range cfg.AnalyzerDefs {
		an, err := compileDefinedAnalyzer(name, def, cfg, opts)
		if err != nil {
			return nil, err
		}
		cfg.compiledAnalyzers[name] = an
	}

	return cfg, nil
}

// HasAnalyzer reports whether name is a custom analyzer in c or a built-in analyzer.
func (c *IndexAnalysisConfig) HasAnalyzer(name string) bool {
	if c != nil {
		if _, ok := c.AnalyzerDefs[name]; ok {
			return true
		}
	}
	return isBuiltInAnalyzerType(name)
}

// HasNormalizer reports whether name is a custom normalizer in c or the built-in `lowercase`/`uppercase` normalizer.
func (c *IndexAnalysisConfig) HasNormalizer(name string) bool {
	if c != nil {
		if _, ok := c.NormalizerDefs[name]; ok {
			return true
		}
	}
	ln := strings.ToLower(strings.TrimSpace(name))
	return ln == "lowercase" || ln == "uppercase" || ln == "asciifolding"
}

// UsesSynonymSet returns sorted names of custom analyzers in c that reference a filter with `synonyms_set == setID`.
func (c *IndexAnalysisConfig) UsesSynonymSet(setID string) []string {
	if c == nil || strings.TrimSpace(setID) == "" {
		return nil
	}
	matchingFilters := make(map[string]bool)
	for fName, fDef := range c.FilterDefs {
		ft := strings.ToLower(fmt.Sprintf("%v", fDef["type"]))
		if ft == "synonym" || ft == "synonym_graph" {
			if ss, _ := fDef["synonyms_set"].(string); ss == setID {
				matchingFilters[fName] = true
			}
		}
	}
	if len(matchingFilters) == 0 {
		return nil
	}
	var analyzers []string
	for aName, aDef := range c.AnalyzerDefs {
		for _, step := range extractFilterStepList(aDef["filter"]) {
			if s, ok := step.(string); ok && matchingFilters[s] {
				analyzers = append(analyzers, aName)
				break
			}
		}
	}
	sort.Strings(analyzers)
	return analyzers
}

// MissingSynonymSets returns sorted `synonyms_set` IDs referenced in c for which resolve returns an error.
func (c *IndexAnalysisConfig) MissingSynonymSets(resolve func(setID string) ([]string, error)) []string {
	if c == nil || resolve == nil {
		return nil
	}
	seen := make(map[string]bool)
	var missing []string
	for _, fDef := range c.FilterDefs {
		ft := strings.ToLower(fmt.Sprintf("%v", fDef["type"]))
		if ft == "synonym" || ft == "synonym_graph" {
			if ss, _ := fDef["synonyms_set"].(string); strings.TrimSpace(ss) != "" && !seen[ss] {
				seen[ss] = true
				if _, err := resolve(ss); err != nil {
					missing = append(missing, ss)
				}
			}
		}
	}
	sort.Strings(missing)
	return missing
}

// ResolveIndexAnalyzer returns the effective index-time analyzer name for a field,
// honoring `fieldAnalyzer`, then custom `default` analyzer on c, then `"standard"`.
func (c *IndexAnalysisConfig) ResolveIndexAnalyzer(fieldAnalyzer string) string {
	if strings.TrimSpace(fieldAnalyzer) != "" {
		return strings.TrimSpace(fieldAnalyzer)
	}
	if c != nil {
		if _, hasDefault := c.AnalyzerDefs["default"]; hasDefault {
			return "default"
		}
	}
	return "standard"
}

// ResolveSearchAnalyzer returns the effective search-time analyzer name for a field,
// honoring `fieldSearchAnalyzer`, `default_search`, `fieldAnalyzer`, `default`, then `"standard"`
// (41_query_string_with_default_analyzer.yml).
func (c *IndexAnalysisConfig) ResolveSearchAnalyzer(fieldAnalyzer, fieldSearchAnalyzer string) string {
	if strings.TrimSpace(fieldSearchAnalyzer) != "" {
		return strings.TrimSpace(fieldSearchAnalyzer)
	}
	if c != nil {
		if _, hasDefSearch := c.AnalyzerDefs["default_search"]; hasDefSearch {
			return "default_search"
		}
	}
	if strings.TrimSpace(fieldAnalyzer) != "" {
		return strings.TrimSpace(fieldAnalyzer)
	}
	if c != nil {
		if _, hasDefault := c.AnalyzerDefs["default"]; hasDefault {
			return "default"
		}
	}
	return "standard"
}

// IndexStatsInput pairs an index's analysis config with built-in analyzer references from its field mappings.
type IndexStatsInput struct {
	Config                *IndexAnalysisConfig
	FieldAnalyzerRefsList []string // every analyzer / search_analyzer / search_quote_analyzer occurrence in field mappings
}

// ComputeClusterAnalysisStats aggregates `_cluster/stats` `indices.analysis` across indices
// (10_analysis_stats.yml & 20_analysis_stats_synonyms.yml).
func ComputeClusterAnalysisStats(indices []IndexStatsInput) ClusterAnalysisStats {
	type aggEntry struct {
		count      int
		indexCount int
	}
	newAgg := func() map[string]*aggEntry { return make(map[string]*aggEntry) }

	cfTypes := newAgg()
	tokTypes := newAgg()
	filtTypes := newAgg()
	anTypes := newAgg()
	biCF := newAgg()
	biTok := newAgg()
	biFilt := newAgg()
	biAn := newAgg()

	inlineCount := 0
	inlineIndexCount := 0
	distinctPaths := make(map[string]bool)
	pathIndexCount := 0
	distinctSets := make(map[string]bool)
	setsIndexCount := 0

	addIdxMap := func(dst map[string]*aggEntry, perIdx map[string]int) {
		for k, cnt := range perIdx {
			if cnt <= 0 {
				continue
			}
			ent, ok := dst[k]
			if !ok {
				ent = &aggEntry{}
				dst[k] = ent
			}
			ent.count += cnt
			ent.indexCount++
		}
	}

	for _, item := range indices {
		cfg := item.Config
		if cfg != nil {
			pCF := make(map[string]int)
			for _, def := range cfg.CharFilterDefs {
				if t, _ := def["type"].(string); t != "" {
					pCF[strings.ToLower(t)]++
				}
			}
			addIdxMap(cfTypes, pCF)

			pTok := make(map[string]int)
			for _, def := range cfg.TokenizerDefs {
				if t, _ := def["type"].(string); t != "" {
					pTok[strings.ToLower(t)]++
				}
			}
			addIdxMap(tokTypes, pTok)

			pFilt := make(map[string]int)
			hasInlineThisIdx := false
			hasPathThisIdx := false
			hasSetThisIdx := false
			for _, def := range cfg.FilterDefs {
				t, _ := def["type"].(string)
				lt := strings.ToLower(t)
				if lt != "" {
					pFilt[lt]++
				}
				if lt == "synonym" || lt == "synonym_graph" {
					if _, hasIn := def["synonyms"]; hasIn {
						inlineCount++
						hasInlineThisIdx = true
					}
					if p, _ := def["synonyms_path"].(string); strings.TrimSpace(p) != "" {
						distinctPaths[strings.TrimSpace(p)] = true
						hasPathThisIdx = true
					}
					if s, _ := def["synonyms_set"].(string); strings.TrimSpace(s) != "" {
						distinctSets[strings.TrimSpace(s)] = true
						hasSetThisIdx = true
					}
				}
			}
			addIdxMap(filtTypes, pFilt)
			if hasInlineThisIdx {
				inlineIndexCount++
			}
			if hasPathThisIdx {
				pathIndexCount++
			}
			if hasSetThisIdx {
				setsIndexCount++
			}

			pAn := make(map[string]int)
			pBiCF := make(map[string]int)
			pBiTok := make(map[string]int)
			pBiFilt := make(map[string]int)
			for _, def := range cfg.AnalyzerDefs {
				t, _ := def["type"].(string)
				lt := strings.ToLower(strings.TrimSpace(t))
				if lt == "" {
					lt = "custom"
				}
				pAn[lt]++
				if lt == "custom" {
					for _, cfs := range extractStringSlice(def["char_filter"]) {
						if _, isCustom := cfg.CharFilterDefs[cfs]; !isCustom {
							pBiCF[cfs]++
						}
					}
					if tn, ok := def["tokenizer"].(string); ok && tn != "" {
						if _, isCustom := cfg.TokenizerDefs[tn]; !isCustom {
							pBiTok[tn]++
						}
					}
					for _, fn := range extractStringSlice(def["filter"]) {
						if _, isCustom := cfg.FilterDefs[fn]; !isCustom {
							pBiFilt[fn]++
						}
					}
				}
			}
			addIdxMap(anTypes, pAn)
			addIdxMap(biCF, pBiCF)
			addIdxMap(biTok, pBiTok)
			addIdxMap(biFilt, pBiFilt)
		}

		pBiAn := make(map[string]int)
		for _, ref := range item.FieldAnalyzerRefsList {
			ref = strings.TrimSpace(ref)
			if ref == "" {
				continue
			}
			if cfg != nil {
				if _, isCustom := cfg.AnalyzerDefs[ref]; isCustom {
					continue
				}
			}
			if isBuiltInAnalyzerType(ref) {
				pBiAn[strings.ToLower(ref)]++
			}
		}
		addIdxMap(biAn, pBiAn)
	}

	toSortedSlice := func(m map[string]*aggEntry) []NamedCountStat {
		out := make([]NamedCountStat, 0, len(m))
		for k, v := range m {
			out = append(out, NamedCountStat{
				Name:       k,
				Count:      v.count,
				IndexCount: v.indexCount,
			})
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].Name < out[j].Name
		})
		return out
	}

	synStats := make(map[string]SynonymCountStat)
	if inlineCount > 0 || len(distinctPaths) > 0 || len(distinctSets) > 0 {
		synStats["inline"] = SynonymCountStat{Count: inlineCount, IndexCount: inlineIndexCount}
		synStats["paths"] = SynonymCountStat{Count: len(distinctPaths), IndexCount: pathIndexCount}
		synStats["sets"] = SynonymCountStat{Count: len(distinctSets), IndexCount: setsIndexCount}
	}

	return ClusterAnalysisStats{
		CharFilterTypes:    toSortedSlice(cfTypes),
		TokenizerTypes:     toSortedSlice(tokTypes),
		FilterTypes:        toSortedSlice(filtTypes),
		AnalyzerTypes:      toSortedSlice(anTypes),
		BuiltInCharFilters: toSortedSlice(biCF),
		BuiltInTokenizers:  toSortedSlice(biTok),
		BuiltInFilters:     toSortedSlice(biFilt),
		BuiltInAnalyzers:   toSortedSlice(biAn),
		Synonyms:           synStats,
	}
}

func compileDefinedAnalyzer(name string, def map[string]any, cfg *IndexAnalysisConfig, opts Options) (*compiledAnalyzer, error) {
	typStr, _ := def["type"].(string)
	normType := strings.ToLower(strings.TrimSpace(typStr))
	if normType != "" && normType != "custom" {
		return buildBuiltInOrTypedAnalyzer(name, normType, def, cfg, opts)
	}
	// Custom analyzer
	tokSpec := def["tokenizer"]
	if tokSpec == nil {
		return nil, newIllegalArgError(fmt.Sprintf("Custom Analyzer [%s] failed to find tokenizer", name))
	}
	posGap, err := parsePosIncrementGap(def)
	if err != nil {
		return nil, err
	}
	charSteps := extractFilterStepList(def["char_filter"])
	filtSteps := extractFilterStepList(def["filter"])
	if len(filtSteps) == 0 {
		filtSteps = extractFilterStepList(def["token_filter"])
	}
	cfs, tok, tfs, err := compileCustomChain(charSteps, tokSpec, filtSteps, false, cfg, opts)
	if err != nil {
		return nil, err
	}
	return &compiledAnalyzer{
		name:                 name,
		isCustom:             true,
		positionIncrementGap: posGap,
		charFilters:          cfs,
		tokenizer:            tok,
		tokenFilters:         tfs,
	}, nil
}

func compileDefinedNormalizer(name string, def map[string]any, cfg *IndexAnalysisConfig, opts Options) (*compiledAnalyzer, error) {
	if _, hasTok := def["tokenizer"]; hasTok {
		return nil, newIllegalArgError(fmt.Sprintf("Custom normalizer [%s] may not use a tokenizer", name))
	}
	typStr, _ := def["type"].(string)
	normType := strings.ToLower(strings.TrimSpace(typStr))
	if normType != "" && normType != "custom" {
		if normType == "lowercase" || normType == "uppercase" || normType == "asciifolding" {
			cfs, tok, tfs, err := compileCustomChain(nil, "keyword", []any{normType}, true, cfg, opts)
			if err != nil {
				return nil, err
			}
			return &compiledAnalyzer{
				name:                 name,
				isCustom:             false,
				positionIncrementGap: DefaultPositionIncrementGap,
				charFilters:          cfs,
				tokenizer:            tok,
				tokenFilters:         tfs,
			}, nil
		}
		return nil, newIllegalArgError(fmt.Sprintf("Unknown normalizer type [%s] for [%s]", typStr, name))
	}
	charSteps := extractFilterStepList(def["char_filter"])
	filtSteps := extractFilterStepList(def["filter"])
	if len(filtSteps) == 0 {
		filtSteps = extractFilterStepList(def["token_filter"])
	}
	cfs, tok, tfs, err := compileCustomChain(charSteps, "keyword", filtSteps, true, cfg, opts)
	if err != nil {
		return nil, err
	}
	return &compiledAnalyzer{
		name:                 name,
		isCustom:             true,
		positionIncrementGap: DefaultPositionIncrementGap,
		charFilters:          cfs,
		tokenizer:            tok,
		tokenFilters:         tfs,
	}, nil
}

func compileCustomChain(
	charSteps []any,
	tokSpec any,
	filtSteps []any,
	isNormalizer bool,
	cfg *IndexAnalysisConfig,
	opts Options,
) ([]*compiledCharFilter, *compiledTokenizer, []*compiledTokenFilter, error) {
	cfs := make([]*compiledCharFilter, 0, len(charSteps))
	for _, step := range charSteps {
		cf, err := resolveCharFilterStep(step, cfg, opts)
		if err != nil {
			return nil, nil, nil, err
		}
		cfs = append(cfs, cf)
	}

	tok, err := resolveTokenizerStep(tokSpec, cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	tfs := make([]*compiledTokenFilter, 0, len(filtSteps))
	for _, step := range filtSteps {
		bctx := filterBuildContext{
			cfg:            cfg,
			opts:           opts,
			precedingChars: cfs,
			chainTokenizer: tok,
			precedingFilts: append([]*compiledTokenFilter(nil), tfs...),
		}
		tf, rawName, err := resolveTokenFilterStepWithRawName(step, bctx)
		if err != nil {
			return nil, nil, nil, err
		}
		if isNormalizer && !isNormalizerAllowedFilterType(tf.typ) {
			return nil, nil, nil, newIllegalArgError(fmt.Sprintf("Custom normalizer may not use filter [%s]", rawName))
		}
		tfs = append(tfs, tf)
	}
	return cfs, tok, tfs, nil
}

func resolveCharFilterStep(step any, cfg *IndexAnalysisConfig, opts Options) (*compiledCharFilter, error) {
	switch v := step.(type) {
	case string:
		name := strings.TrimSpace(v)
		if cfg != nil {
			if def, ok := cfg.CharFilterDefs[name]; ok {
				typStr, _ := def["type"].(string)
				return buildCharFilter(name, typStr, def, opts)
			}
		}
		return buildCharFilter(name, name, nil, opts)
	case map[string]any:
		typStr, _ := v["type"].(string)
		if strings.TrimSpace(typStr) == "" {
			return nil, newIllegalArgError("Inline char_filter requires [type]")
		}
		return buildCharFilter("__anonymous__"+typStr, typStr, v, opts)
	default:
		return nil, newIllegalArgError(fmt.Sprintf("Invalid char_filter specification [%v]", step))
	}
}

func resolveTokenizerStep(spec any, cfg *IndexAnalysisConfig) (*compiledTokenizer, error) {
	maxNGramDiff := DefaultMaxNGramDiff
	if cfg != nil {
		maxNGramDiff = cfg.MaxNGramDiff
	}
	switch v := spec.(type) {
	case string:
		name := strings.TrimSpace(v)
		if cfg != nil {
			if def, ok := cfg.TokenizerDefs[name]; ok {
				typStr, _ := def["type"].(string)
				return buildTokenizer(name, typStr, def, maxNGramDiff)
			}
		}
		return buildTokenizer(name, name, nil, maxNGramDiff)
	case map[string]any:
		typStr, _ := v["type"].(string)
		if strings.TrimSpace(typStr) == "" {
			return nil, newIllegalArgError("Inline tokenizer requires [type]")
		}
		return buildTokenizer("__anonymous__"+typStr, typStr, v, maxNGramDiff)
	default:
		return nil, newIllegalArgError(fmt.Sprintf("Invalid tokenizer specification [%v]", spec))
	}
}

func resolveTokenFilterStep(step any, bctx filterBuildContext) (*compiledTokenFilter, error) {
	tf, _, err := resolveTokenFilterStepWithRawName(step, bctx)
	return tf, err
}

func resolveTokenFilterStepWithRawName(step any, bctx filterBuildContext) (*compiledTokenFilter, string, error) {
	switch v := step.(type) {
	case string:
		name := strings.TrimSpace(v)
		if bctx.cfg != nil {
			if def, ok := bctx.cfg.FilterDefs[name]; ok {
				typStr, _ := def["type"].(string)
				tf, err := buildTokenFilter(name, typStr, def, false, bctx)
				return tf, name, err
			}
		}
		tf, err := buildTokenFilter(name, name, nil, true, bctx)
		return tf, name, err
	case map[string]any:
		typStr, _ := v["type"].(string)
		if strings.TrimSpace(typStr) == "" {
			return nil, "", newIllegalArgError("Inline token filter requires [type]")
		}
		tf, err := buildTokenFilter("__anonymous__"+typStr, typStr, v, false, bctx)
		return tf, typStr, err
	default:
		return nil, "", newIllegalArgError(fmt.Sprintf("Invalid token filter specification [%v]", step))
	}
}

// ============================================================================
// Settings Map Normalization & Value Extraction Helpers
// ============================================================================

func expandDottedMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		expandedVal := expandDottedAny(v)
		if idx := strings.IndexByte(k, '.'); idx >= 0 {
			parts := strings.Split(k, ".")
			insertNestedPath(out, parts, expandedVal)
		} else {
			if existingMap, ok1 := out[k].(map[string]any); ok1 {
				if newMap, ok2 := expandedVal.(map[string]any); ok2 {
					deepMergeMaps(existingMap, newMap)
					continue
				}
			}
			out[k] = expandedVal
		}
	}
	return normalizeIndexedSliceMaps(out).(map[string]any)
}

func expandDottedAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return expandDottedMap(x)
	case []any:
		cp := make([]any, len(x))
		for i, elem := range x {
			cp[i] = expandDottedAny(elem)
		}
		return cp
	default:
		return v
	}
}

func insertNestedPath(dst map[string]any, parts []string, val any) {
	cur := dst
	for i := 0; i < len(parts)-1; i++ {
		p := parts[i]
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = make(map[string]any)
			cur[p] = next
		}
		cur = next
	}
	last := parts[len(parts)-1]
	if exMap, ok1 := cur[last].(map[string]any); ok1 {
		if valMap, ok2 := val.(map[string]any); ok2 {
			deepMergeMaps(exMap, valMap)
			return
		}
	}
	cur[last] = val
}

func deepMergeMaps(dst, src map[string]any) {
	for k, sv := range src {
		if sm, ok1 := sv.(map[string]any); ok1 {
			if dm, ok2 := dst[k].(map[string]any); ok2 {
				deepMergeMaps(dm, sm)
				continue
			}
		}
		dst[k] = sv
	}
}

// normalizeIndexedSliceMaps converts `{"0": "a", "1": "b"}` produced from flat settings like `filter.0` into `[]any{"a", "b"}`.
func normalizeIndexedSliceMaps(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	for k, val := range m {
		m[k] = normalizeIndexedSliceMaps(val)
	}
	if len(m) == 0 {
		return m
	}
	allSequentialInts := true
	arr := make([]any, len(m))
	for i := 0; i < len(m); i++ {
		elem, exists := m[strconv.Itoa(i)]
		if !exists {
			allSequentialInts = false
			break
		}
		arr[i] = elem
	}
	if allSequentialInts {
		return arr
	}
	return m
}

func extractNamedComponentDefs(raw any) map[string]map[string]any {
	out := make(map[string]map[string]any)
	m, ok := raw.(map[string]any)
	if !ok {
		return out
	}
	for name, val := range m {
		switch dv := val.(type) {
		case map[string]any:
			out[name] = dv
		case string:
			out[name] = map[string]any{"type": dv}
		}
	}
	return out
}

func extractFilterStepList(raw any) []any {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []any{v}
	case []string:
		out := make([]any, 0, len(v))
		for _, s := range v {
			out = append(out, s)
		}
		return out
	case []any:
		return v
	case map[string]any:
		return []any{v}
	default:
		return nil
	}
}

func extractStringSlice(raw any) []string {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, elem := range v {
			out = append(out, fmt.Sprintf("%v", elem))
		}
		return out
	default:
		return nil
	}
}

func extractInt(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case int32:
		return int(v), true
	case float64:
		if v != float64(int(v)) {
			return 0, false
		}
		return int(v), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

func extractBool(raw any) (bool, bool) {
	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			return true, true
		case "false":
			return false, true
		default:
			return false, false
		}
	default:
		return false, false
	}
}
