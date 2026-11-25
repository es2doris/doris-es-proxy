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

package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

type wave3ServerPolishStateR63 struct {
	mu                     sync.RWMutex
	dynamicTextFieldsByIdx map[string]map[string]bool
	dynamicFloatFieldsIdx  map[string]map[string]bool
}

var (
	wave3ServerPolishMuR63     sync.Mutex
	wave3ServerPolishStatesR63 = make(map[*Server]*wave3ServerPolishStateR63)
)

func (s *Server) getOrCreateWave3PolishStateR63() *wave3ServerPolishStateR63 {
	if s == nil {
		return nil
	}
	wave3ServerPolishMuR63.Lock()
	defer wave3ServerPolishMuR63.Unlock()
	st, ok := wave3ServerPolishStatesR63[s]
	if !ok {
		st = &wave3ServerPolishStateR63{
			dynamicTextFieldsByIdx: make(map[string]map[string]bool),
			dynamicFloatFieldsIdx:  make(map[string]map[string]bool),
		}
		wave3ServerPolishStatesR63[s] = st
	}
	return st
}

func (s *Server) cleanupWave3PolishStateR63() {
	if s == nil {
		return
	}
	wave3ServerPolishMuR63.Lock()
	delete(wave3ServerPolishStatesR63, s)
	wave3ServerPolishMuR63.Unlock()
}

func (s *Server) clearWave3PolishIndexStateR63(indexName string) {
	if s == nil || indexName == "" {
		return
	}
	if indexName == "*" {
		s.cleanupWave3PolishStateR63()
		return
	}
	wave3ServerPolishMuR63.Lock()
	st := wave3ServerPolishStatesR63[s]
	wave3ServerPolishMuR63.Unlock()
	if st == nil {
		return
	}
	st.mu.Lock()
	delete(st.dynamicTextFieldsByIdx, indexName)
	delete(st.dynamicFloatFieldsIdx, indexName)
	st.mu.Unlock()
}

func (s *Server) recordDynamicallyInferredFieldsWave3R63(
	indexName string,
	prevSpec *esast.MappingSpec,
	inferred *esast.MappingSpec,
	sampleDocs []json.RawMessage,
) {
	if s == nil || indexName == "" || inferred == nil || len(inferred.Properties) == 0 {
		return
	}
	rawFloatPaths := make(map[string]bool)
	rawStrPaths := make(map[string]bool)
	for _, rawDoc := range sampleDocs {
		if len(bytes.TrimSpace(rawDoc)) == 0 {
			continue
		}
		var docMap map[string]any
		dec := json.NewDecoder(bytes.NewReader(rawDoc))
		dec.UseNumber()
		if dec.Decode(&docMap) != nil || docMap == nil {
			continue
		}
		flat := make(map[string][]any)
		flattenDocFieldValuesRound61("", docMap, flat)
		for fp, vals := range flat {
			for _, v := range vals {
				switch tv := v.(type) {
				case string:
					rawStrPaths[fp] = true
				case json.Number:
					if _, errI := tv.Int64(); errI != nil {
						if _, errF := tv.Float64(); errF == nil {
							rawFloatPaths[fp] = true
						}
					}
				case float64:
					if tv != math.Trunc(tv) {
						rawFloatPaths[fp] = true
					}
				}
			}
		}
	}

	var prevProps map[string]esast.FieldProperty
	var dynTemplates []map[string]any
	if prevSpec != nil {
		prevProps = prevSpec.Properties
		dynTemplates = prevSpec.DynamicTemplates
	}
	templateExplicitPaths := make(map[string]bool)
	if len(dynTemplates) > 0 {
		var collectTplProps func(props map[string]any, prefix string)
		collectTplProps = func(props map[string]any, prefix string) {
			for pName, rawProp := range props {
				fullP := pName
				if prefix != "" {
					fullP = prefix + "." + pName
				}
				templateExplicitPaths[fullP] = true
				if pMap, okP := rawProp.(map[string]any); okP {
					if subP, okSP := pMap["properties"].(map[string]any); okSP {
						collectTplProps(subP, fullP)
					}
				}
			}
		}
		matchesTplRule := func(rule map[string]any, leafName, fullPath, detectedType string) bool {
			if mmt, _ := rule["match_mapping_type"].(string); mmt != "" && mmt != "*" && !strings.EqualFold(mmt, detectedType) {
				return false
			}
			if mPat, _ := rule["match"].(string); mPat != "" && !matchWildcardPattern(mPat, leafName) {
				return false
			}
			if uPat, _ := rule["unmatch"].(string); uPat != "" && matchWildcardPattern(uPat, leafName) {
				return false
			}
			if pmPat, _ := rule["path_match"].(string); pmPat != "" && !matchWildcardPattern(pmPat, fullPath) {
				return false
			}
			if puPat, _ := rule["path_unmatch"].(string); puPat != "" && matchWildcardPattern(puPat, fullPath) {
				return false
			}
			return true
		}
		var scanTplFields func(curInf map[string]esast.FieldProperty, prefix string)
		scanTplFields = func(curInf map[string]esast.FieldProperty, prefix string) {
			for name, prop := range curInf {
				full := name
				if prefix != "" {
					full = prefix + "." + name
				}
				detType := strings.ToLower(strings.TrimSpace(prop.Type))
				if detType == "" && len(prop.Properties) > 0 {
					detType = "object"
				}
				if rawStrPaths[full] {
					detType = "string"
				}
				for _, tplEntry := range dynTemplates {
					for _, rawRule := range tplEntry {
						rule, okR := rawRule.(map[string]any)
						if !okR {
							continue
						}
						if matchesTplRule(rule, name, full, detType) {
							if mapping, okM := rule["mapping"].(map[string]any); okM {
								if mt, _ := mapping["type"].(string); mt != "" && !strings.EqualFold(mt, "text") {
									templateExplicitPaths[full] = true
								}
								if subProps, okSP := mapping["properties"].(map[string]any); okSP {
									collectTplProps(subProps, full)
								}
							}
							break
						}
					}
				}
				if len(prop.Properties) > 0 {
					scanTplFields(prop.Properties, full)
				}
			}
		}
		scanTplFields(inferred.Properties, "")
	}

	st := s.getOrCreateWave3PolishStateR63()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.dynamicTextFieldsByIdx[indexName] == nil {
		st.dynamicTextFieldsByIdx[indexName] = make(map[string]bool)
	}
	if st.dynamicFloatFieldsIdx[indexName] == nil {
		st.dynamicFloatFieldsIdx[indexName] = make(map[string]bool)
	}

	var walk func(curPrev, curInf map[string]esast.FieldProperty, prefix string)
	walk = func(curPrev, curInf map[string]esast.FieldProperty, prefix string) {
		for name, prop := range curInf {
			full := name
			if prefix != "" {
				full = prefix + "." + name
			}
			var subPrev map[string]esast.FieldProperty
			hadExplicit := false
			if curPrev != nil {
				if ep, ok := curPrev[name]; ok {
					hadExplicit = true
					subPrev = ep.Properties
				}
			}
			if !hadExplicit && !templateExplicitPaths[full] {
				tLower := strings.ToLower(strings.TrimSpace(prop.Type))
				if tLower == "text" || (tLower == "keyword" && rawStrPaths[full]) {
					st.dynamicTextFieldsByIdx[indexName][full] = true
				}
				if (tLower == "double" || tLower == "float") && rawFloatPaths[full] {
					st.dynamicFloatFieldsIdx[indexName][full] = true
				}
			}
			if len(prop.Properties) > 0 {
				walk(subPrev, prop.Properties, full)
			}
		}
	}
	walk(prevProps, inferred.Properties, "")
}

func (s *Server) isDynamicallyInferredStringFieldWave3R63(indexName, fieldPath string) bool {
	if s == nil || indexName == "" || fieldPath == "" {
		return false
	}
	st := s.getOrCreateWave3PolishStateR63()
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.dynamicTextFieldsByIdx[indexName][fieldPath]
}

func (s *Server) dynamicTextFieldsCopyWave3R63(indexName string) map[string]bool {
	if s == nil || indexName == "" {
		return nil
	}
	st := s.getOrCreateWave3PolishStateR63()
	st.mu.RLock()
	defer st.mu.RUnlock()
	src := st.dynamicTextFieldsByIdx[indexName]
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]bool, len(src))
	for k, v := range src {
		if v {
			out[k] = true
		}
	}
	return out
}

func (s *Server) isDynamicallyInferredFloatFieldWave3R63(indexName, fieldPath string) bool {
	if s == nil || indexName == "" || fieldPath == "" {
		return false
	}
	st := s.getOrCreateWave3PolishStateR63()
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.dynamicFloatFieldsIdx[indexName][fieldPath]
}

// isCustomOrPluginIndexAnalyzerWave3R63 reports whether `effAnalyzer` requires running `pkg/analysis.Analyze`
// at index time so non-standard / plugin token streams (ICU, phonetic, Stempel/Polish, Ukrainian, NGram, etc.)
// match analyzed search queries (`analysis_*/*_search.yml`, `20_ngram_search.yml`, `30_ngram_highligthing.yml`).
func isCustomOrPluginIndexAnalyzerWave3R63(effAnalyzer string, cfg *analysis.IndexAnalysisConfig) bool {
	an := strings.ToLower(strings.TrimSpace(effAnalyzer))
	if an == "" {
		return false
	}
	switch an {
	case "standard", "simple", "whitespace", "keyword", "noop", "stop":
		return false
	}
	if cfg != nil && len(cfg.AnalyzerDefs) > 0 {
		if _, ok := cfg.AnalyzerDefs[effAnalyzer]; ok {
			return true
		}
		for k := range cfg.AnalyzerDefs {
			if strings.EqualFold(k, effAnalyzer) {
				return true
			}
		}
	}
	switch an {
	case "icu_analyzer", "polish", "ukrainian", "kuromoji", "nori", "smartcn", "cjk", "thai", "fingerprint":
		return true
	}
	return false
}

// parseAnnotatedTextSegmentsWave3R63 parses an Elasticsearch `annotated_text` markdown string
// (`"The [quick brown fox](entity_3789&other+tag) is brown."`) into ordered segments.
type annotatedTextSegmentWave3R63 struct {
	isAnnotated bool
	visible     string
	rawAnns     string
	decodedAnns []string
}

func decodeSingleAnnotationTokenWave3R63(raw string) string {
	if decoded, err := url.QueryUnescape(raw); err == nil {
		return decoded
	}
	return strings.ReplaceAll(raw, "+", " ")
}

func parseAnnotatedTextSegmentsWave3R63(input string) []annotatedTextSegmentWave3R63 {
	var out []annotatedTextSegmentWave3R63
	i := 0
	n := len(input)
	plainStart := 0
	for i < n {
		if input[i] == '[' {
			closeBr := strings.IndexByte(input[i+1:], ']')
			if closeBr >= 0 {
				absCloseBr := i + 1 + closeBr
				if absCloseBr+1 < n && input[absCloseBr+1] == '(' {
					closeParen := strings.IndexByte(input[absCloseBr+2:], ')')
					if closeParen >= 0 {
						absCloseParen := absCloseBr + 2 + closeParen
						if i > plainStart {
							out = append(out, annotatedTextSegmentWave3R63{
								visible: input[plainStart:i],
							})
						}
						vis := input[i+1 : absCloseBr]
						rawAnns := input[absCloseBr+2 : absCloseParen]
						var decAnns []string
						for _, part := range strings.Split(rawAnns, "&") {
							if part == "" {
								continue
							}
							decAnns = append(decAnns, decodeSingleAnnotationTokenWave3R63(part))
						}
						out = append(out, annotatedTextSegmentWave3R63{
							isAnnotated: true,
							visible:     vis,
							rawAnns:     rawAnns,
							decodedAnns: decAnns,
						})
						i = absCloseParen + 1
						plainStart = i
						continue
					}
				}
			}
		}
		i++
	}
	if plainStart < n {
		out = append(out, annotatedTextSegmentWave3R63{
			visible: input[plainStart:],
		})
	}
	return out
}

// expandAnnotatedTextForIndexWave3R63 expands `[visible](ann1&ann2)` into `"ann1 ann2 visible"`
// inline so annotation tokens sit immediately before the annotated span while preserving contiguous
// visible phrases after the span (`"fox is brown"`, `intervals`, `span_near`, `term`).
func expandAnnotatedTextForIndexWave3R63(input string) string {
	segs := parseAnnotatedTextSegmentsWave3R63(input)
	hasAnn := false
	for _, seg := range segs {
		if seg.isAnnotated {
			hasAnn = true
			break
		}
	}
	if !hasAnn {
		return input
	}
	var sb strings.Builder
	for _, seg := range segs {
		if !seg.isAnnotated {
			sb.WriteString(seg.visible)
			continue
		}
		for _, da := range seg.decodedAnns {
			if sb.Len() > 0 && sb.String()[sb.Len()-1] != ' ' {
				sb.WriteByte(' ')
			}
			sb.WriteString(da)
			sb.WriteByte(' ')
		}
		sb.WriteString(seg.visible)
	}
	return sb.String()
}

func extractAnnotatedTextAnnotationsWave3R63(input string) []string {
	segs := parseAnnotatedTextSegmentsWave3R63(input)
	var out []string
	for _, seg := range segs {
		if seg.isAnnotated {
			out = append(out, seg.decodedAnns...)
		}
	}
	return out
}

func (s *Server) schemaNeedsWave3TokenEnrichmentR63(indexName string, idxSchema *schema.IndexSchema) bool {
	if idxSchema == nil || idxSchema.SyntheticSource || len(idxSchema.Fields) == 0 {
		return false
	}
	for _, b := range idxSchema.Fields {
		if b.ESType == "annotated_text" || b.ESType == "annotated-text" {
			return true
		}
	}
	if s == nil || indexName == "" {
		return false
	}
	cfg, _ := s.buildIndexAnalysisConfigR62Admin(indexName)
	for _, b := range idxSchema.Fields {
		if (b.ESType == "text" || b.ESType == "match_only_text") && !b.EnabledFalse && !b.NotIndexed && b.ColumnName != "" {
			effAn := b.Analyzer
			if cfg != nil {
				effAn = cfg.ResolveIndexAnalyzer(effAn)
			}
			if isCustomOrPluginIndexAnalyzerWave3R63(effAn, cfg) {
				return true
			}
		}
	}
	return false
}

func (s *Server) postProcessShreddedRowWave3R63(
	indexName string,
	idxSchema *schema.IndexSchema,
	rawSource []byte,
	effRouting string,
	shredded []byte,
) []byte {
	if len(shredded) == 0 {
		return shredded
	}
	needsTokens := len(rawSource) > 0 && s.schemaNeedsWave3TokenEnrichmentR63(indexName, idxSchema)
	if effRouting == "" && !needsTokens {
		return shredded
	}
	var rowMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(shredded))
	dec.UseNumber()
	if err := dec.Decode(&rowMap); err != nil || rowMap == nil {
		return shredded
	}
	changed := false
	if effRouting != "" {
		if curR, _ := rowMap["_routing"].(string); curR == "" {
			rowMap["_routing"] = effRouting
			changed = true
		}
	}
	if needsTokens {
		var srcDoc map[string]any
		srcDec := json.NewDecoder(bytes.NewReader(rawSource))
		srcDec.UseNumber()
		if srcDec.Decode(&srcDoc) == nil && srcDoc != nil {
			var cfg *analysis.IndexAnalysisConfig
			var opts analysis.Options
			if s != nil {
				cfg, opts = s.buildIndexAnalysisConfigR62Admin(indexName)
			}
			if cfg == nil {
				cfg = analysis.DefaultIndexAnalysisConfig()
			}
			for fPath, b := range idxSchema.Fields {
				if b.ColumnName == "" || b.EnabledFalse || b.NotIndexed || b.AliasTarget != "" {
					continue
				}
				isAnn := b.ESType == "annotated_text" || b.ESType == "annotated-text"
				isText := b.ESType == "text" || b.ESType == "match_only_text"
				if !isAnn && !isText {
					continue
				}
				effAn := b.Analyzer
				if cfg != nil {
					effAn = cfg.ResolveIndexAnalyzer(effAn)
				}
				if isText && !isCustomOrPluginIndexAnalyzerWave3R63(effAn, cfg) {
					continue
				}
				segs := strings.Split(fPath, ".")
				if len(b.SourceJSONPath) > 0 {
					segs = b.SourceJSONPath
				}
				vals := collectStringValuesAtPath(srcDoc, segs)
				if idxSchema.RawMapping != nil {
					for _, ctSrc := range collectCopyToSourcePaths(idxSchema.RawMapping.Properties, "", fPath) {
						vals = append(vals, collectStringValuesAtPath(srcDoc, strings.Split(ctSrc, "."))...)
					}
				}
				if len(vals) == 0 {
					continue
				}
				expandedVals := make([]string, 0, len(vals))
				for _, v := range vals {
					if isAnn {
						expandedVals = append(expandedVals, expandAnnotatedTextForIndexWave3R63(v))
						continue
					}
					anResp, err := analysis.Analyze(analysis.AnalyzeRequest{
						Text:     []string{v},
						Analyzer: effAn,
						Config:   cfg,
						Options:  opts,
					})
					if err != nil || anResp == nil {
						expandedVals = append(expandedVals, v)
						continue
					}
					terms := make([]string, 0, len(anResp.Tokens))
					for _, tk := range anResp.Tokens {
						if tk.Token != "" {
							terms = append(terms, tk.Token)
						}
					}
					expandedVals = append(expandedVals, strings.Join(terms, " "))
				}
				if b.Kind == schema.StoragePromotedArray {
					rowMap[b.ColumnName] = expandedVals
				} else {
					rowMap[b.ColumnName] = strings.Join(expandedVals, " ")
				}
				changed = true
			}
		}
	}
	if !changed {
		return shredded
	}
	out, err := json.Marshal(rowMap)
	if err != nil {
		return shredded
	}
	return out
}

// collectQueryHighlightTermsWave3R63 extracts raw query terms from `q` for `annotated` and custom
// `ngram` index-analyzer highlighting.
func collectQueryHighlightTermsWave3R63(q *esast.Query) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	var walk func(cur *esast.Query)
	walk = func(cur *esast.Query) {
		if cur == nil {
			return
		}
		for _, te := range cur.Term {
			if te.Value != nil {
				add(stringifyHighlightScalarWave3R63(te.Value))
			}
		}
		for _, me := range cur.Match {
			if me.Query != nil {
				for _, f := range strings.Fields(stringifyHighlightScalarWave3R63(me.Query)) {
					add(f)
				}
			}
		}
		for _, mpe := range cur.MatchPhrase {
			if mpe.Query != "" {
				for _, f := range strings.Fields(mpe.Query) {
					add(f)
				}
			}
		}
		for _, mppe := range cur.MatchPhrasePrefix {
			if mppe.Query != "" {
				for _, f := range strings.Fields(mppe.Query) {
					add(f)
				}
			}
		}
		if cur.Bool != nil {
			for i := range cur.Bool.Must {
				walk(&cur.Bool.Must[i])
			}
			for i := range cur.Bool.Should {
				walk(&cur.Bool.Should[i])
			}
			for i := range cur.Bool.Filter {
				walk(&cur.Bool.Filter[i])
			}
		}
		if cur.ConstantScore != nil {
			walk(&cur.ConstantScore.Filter)
		}
		if cur.DisMax != nil {
			for i := range cur.DisMax.Queries {
				walk(&cur.DisMax.Queries[i])
			}
		}
		if cur.Boosting != nil {
			walk(&cur.Boosting.Positive)
		}
		if cur.FunctionScore != nil {
			walk(cur.FunctionScore.Query)
		}
	}
	walk(q)
	return out
}

func stringifyHighlightScalarWave3R63(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return strings.Trim(string(b), `"`)
}

// buildAnnotatedHighlightSnippetsWave3R63 implements Elasticsearch's `mapper-annotated-text`
// `type: "annotated"` highlighter (`mapper_annotatedtext/10_basic.yml`).
func buildAnnotatedHighlightSnippetsWave3R63(
	vals []string,
	effQuery *esast.Query,
	maxAnalyzedOffset int,
) []string {
	qTerms := collectQueryHighlightTermsWave3R63(effQuery)
	if len(qTerms) == 0 {
		return nil
	}
	matchTerm := func(cand string) (string, bool) {
		for _, qt := range qTerms {
			if cand == qt || strings.EqualFold(cand, qt) {
				return qt, true
			}
		}
		return "", false
	}
	highlightPlainTextWords := func(txt string, visOffset *int) (string, bool) {
		spans := scanWordSpansR62Search(txt)
		if len(spans) == 0 {
			*visOffset += utf8.RuneCountInString(txt)
			return txt, false
		}
		var sb strings.Builder
		pos := 0
		anyHit := false
		for _, ws := range spans {
			sb.WriteString(txt[pos:ws.start])
			word := txt[ws.start:ws.end]
			wordEndVis := *visOffset + utf8.RuneCountInString(txt[:ws.end])
			if maxAnalyzedOffset < 0 || wordEndVis <= maxAnalyzedOffset {
				if _, ok := matchTerm(word); ok {
					sb.WriteByte('[')
					sb.WriteString(word)
					sb.WriteString("](_hit_term=")
					sb.WriteString(url.QueryEscape(word))
					sb.WriteByte(')')
					anyHit = true
					pos = ws.end
					continue
				}
			}
			sb.WriteString(word)
			pos = ws.end
		}
		sb.WriteString(txt[pos:])
		*visOffset += utf8.RuneCountInString(txt)
		return sb.String(), anyHit
	}

	var out []string
	for _, val := range vals {
		segs := parseAnnotatedTextSegmentsWave3R63(val)
		var sb strings.Builder
		visOff := 0
		docHit := false
		for _, seg := range segs {
			if !seg.isAnnotated {
				rendered, hit := highlightPlainTextWords(seg.visible, &visOff)
				if hit {
					docHit = true
				}
				sb.WriteString(rendered)
				continue
			}
			spanEndVis := visOff + utf8.RuneCountInString(seg.visible)
			var hitParts []string
			seenHit := make(map[string]bool)
			if maxAnalyzedOffset < 0 || spanEndVis <= maxAnalyzedOffset {
				for _, da := range seg.decodedAnns {
					if _, ok := matchTerm(da); ok && !seenHit[da] {
						seenHit[da] = true
						hitParts = append(hitParts, "_hit_term="+url.QueryEscape(da))
					}
				}
			}
			if len(hitParts) > 0 {
				docHit = true
				sb.WriteByte('[')
				sb.WriteString(seg.visible)
				sb.WriteString("](")
				sb.WriteString(strings.Join(hitParts, "&"))
				if seg.rawAnns != "" {
					sb.WriteByte('&')
					sb.WriteString(seg.rawAnns)
				}
				sb.WriteByte(')')
				visOff = spanEndVis
				continue
			}
			// Unhit annotations are stripped down to plain visible text (and visible words may still match!).
			rendered, hit := highlightPlainTextWords(seg.visible, &visOff)
			if hit {
				docHit = true
			}
			sb.WriteString(rendered)
		}
		if docHit {
			out = append(out, sb.String())
		}
	}
	return out
}

// buildCustomNGramAnalyzerHighlightSnippetsWave3R63 highlights `vals` using exact token `[StartOffset, EndOffset]`
// byte spans from `pkg/analysis.Analyze` when `field` uses a custom NGram index analyzer (`30_ngram_highligthing.yml`).
func (s *Server) buildCustomNGramAnalyzerHighlightSnippetsWave3R63(
	indexName string,
	hitSchema *schema.IndexSchema,
	field string,
	vals []string,
	effQuery *esast.Query,
	preTag, postTag string,
	htmlEscape bool,
) ([]string, bool) {
	if s == nil || hitSchema == nil || indexName == "" || field == "" {
		return nil, false
	}
	b := hitSchema.ResolveField(field)
	if b.Analyzer == "" {
		return nil, false
	}
	cfg, opts := s.buildIndexAnalysisConfigR62Admin(indexName)
	if cfg == nil || len(cfg.AnalyzerDefs) == 0 {
		return nil, false
	}
	idxAn := cfg.ResolveIndexAnalyzer(b.Analyzer)
	if !isCustomOrPluginIndexAnalyzerWave3R63(idxAn, cfg) {
		return nil, false
	}
	// Check whether the custom analyzer definition uses an ngram / edge_ngram tokenizer or filter.
	usesNGram := false
	if rawDef, ok := cfg.AnalyzerDefs[idxAn]; ok {
		rawBytes, _ := json.Marshal(rawDef)
		lowerRaw := strings.ToLower(string(rawBytes))
		if strings.Contains(lowerRaw, "ngram") {
			usesNGram = true
		} else {
			for tkName, tkDef := range cfg.TokenizerDefs {
				if strings.Contains(lowerRaw, strings.ToLower(tkName)) {
					tb, _ := json.Marshal(tkDef)
					if strings.Contains(strings.ToLower(string(tb)), "ngram") {
						usesNGram = true
						break
					}
				}
			}
			if !usesNGram {
				for flName, flDef := range cfg.FilterDefs {
					if strings.Contains(lowerRaw, strings.ToLower(flName)) {
						fb, _ := json.Marshal(flDef)
						if strings.Contains(strings.ToLower(string(fb)), "ngram") {
							usesNGram = true
							break
						}
					}
				}
			}
		}
	}
	if !usesNGram {
		return nil, false
	}

	searchAn := b.SearchAnalyzer
	if searchAn == "" {
		searchAn = idxAn
	} else {
		searchAn = cfg.ResolveSearchAnalyzer(b.Analyzer, b.SearchAnalyzer)
	}
	rawTerms := collectQueryHighlightTermsWave3R63(effQuery)
	if len(rawTerms) == 0 {
		return nil, true
	}
	qTermSet := make(map[string]bool)
	for _, rt := range rawTerms {
		qResp, err := analysis.Analyze(analysis.AnalyzeRequest{
			Text:     []string{rt},
			Analyzer: searchAn,
			Config:   cfg,
			Options:  opts,
		})
		if err == nil && qResp != nil && len(qResp.Tokens) > 0 {
			for _, qt := range qResp.Tokens {
				if qt.Token != "" {
					qTermSet[qt.Token] = true
				}
			}
		} else {
			qTermSet[rt] = true
		}
	}
	esc := func(part string) string {
		if !htmlEscape {
			return part
		}
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;")
		return r.Replace(part)
	}

	var out []string
	for _, val := range vals {
		vResp, err := analysis.Analyze(analysis.AnalyzeRequest{
			Text:     []string{val},
			Analyzer: idxAn,
			Config:   cfg,
			Options:  opts,
		})
		if err != nil || vResp == nil || len(vResp.Tokens) == 0 {
			continue
		}
		u16ToByte := utf16OffsetsToByteOffsetsR64(val)
		var spans [][2]int
		for _, tk := range vResp.Tokens {
			if !qTermSet[tk.Token] {
				continue
			}
			if bStart, bEnd, okSpan := resolveUTF16HighlightSpanBytesR64(u16ToByte, tk.StartOffset, tk.EndOffset); okSpan {
				spans = append(spans, [2]int{bStart, bEnd})
			}
		}
		if len(spans) == 0 {
			continue
		}
		sort.Slice(spans, func(i, j int) bool {
			if spans[i][0] != spans[j][0] {
				return spans[i][0] < spans[j][0]
			}
			return spans[i][1] < spans[j][1]
		})
		merged := [][2]int{spans[0]}
		for _, sp := range spans[1:] {
			last := &merged[len(merged)-1]
			if sp[0] <= last[1] {
				if sp[1] > last[1] {
					last[1] = sp[1]
				}
			} else {
				merged = append(merged, sp)
			}
		}
		var sb strings.Builder
		pos := 0
		for _, sp := range merged {
			sb.WriteString(esc(val[pos:sp[0]]))
			sb.WriteString(preTag)
			sb.WriteString(esc(val[sp[0]:sp[1]]))
			sb.WriteString(postTag)
			pos = sp[1]
		}
		sb.WriteString(esc(val[pos:]))
		out = append(out, sb.String())
	}
	return out, true
}

// extractMatrixStatsFieldValuesWave3R63 extracts all multi-valued numeric elements for `field` on `md`,
// preserving multi-valued JSON arrays in `_source` even when `field` was dynamically promoted as a scalar,
// and applying IEEE-754 `float32` Lucene `SortedNumericDocValues` precision for `float` / dynamically-inferred
// floating-point fields (`stats/40_multi_value_field.yml`, `aggregations/matrix_stats_multi_value_field.yml`).
func extractMatrixStatsFieldValuesWave3R63(
	srv *Server,
	md runtimeMatchedDoc,
	field string,
	missingVal any,
) []float64 {
	effSc := md.EffectiveSchema(nil)
	var vals []float64
	if md.doc != nil && field != "" {
		rawList := collectSchemaAwareScalarValues(md.doc, field, strings.Split(field, "."), effSc)
		var esType string
		if effSc != nil {
			esType = strings.ToLower(strings.TrimSpace(effSc.ResolveField(field).ESType))
		}
		allowSuffix := esType == "double" || esType == "float" || esType == "half_float" || esType == "scaled_float"
		for _, rv := range rawList {
			if fv, ok := toFloat(rv); ok && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				vals = append(vals, fv)
				continue
			}
			if allowSuffix {
				if s, okS := rv.(string); okS {
					if fv, okF := parseJavaFloatSuffixR66(s); okF {
						vals = append(vals, fv)
					}
				}
			}
		}
	}
	if len(vals) == 0 {
		vals = extractDocNumericValuesForMetric(md, &esast.MetricAggSpec{
			Field:   field,
			Missing: missingVal,
		})
	}
	if len(vals) == 0 {
		return nil
	}
	quantizeF32 := false
	if effSc != nil {
		b := effSc.ResolveField(field)
		if b.ESType == "float" {
			quantizeF32 = true
		} else if b.ESType == "double" && srv != nil && srv.isDynamicallyInferredFloatFieldWave3R63(effSc.IndexName, field) {
			quantizeF32 = true
		}
	}
	if quantizeF32 {
		for i := range vals {
			vals[i] = float64(float32(vals[i]))
		}
	}
	return vals
}

// aggSpecHasMatrixStatsSubtreeR66 reports whether `spec` or any descendant sub-aggregation uses `matrix_stats`.
func aggSpecHasMatrixStatsSubtreeR66(spec esast.AggSpec) bool {
	if spec.MatrixStats != nil {
		return true
	}
	for _, sub := range spec.SubAggs() {
		if aggSpecHasMatrixStatsSubtreeR66(sub) {
			return true
		}
	}
	return false
}

func dropMatrixStatsSubtreeRowsR66(rows []AggRow, rootAggName string, spec esast.AggSpec) []AggRow {
	if spec.MatrixStats != nil {
		kept := make([]AggRow, 0, len(rows))
		for _, r := range rows {
			if r.AggName != rootAggName {
				kept = append(kept, r)
			}
		}
		return kept
	}
	msTargets := make(map[string]bool)
	var collect func(prefix string, m map[string]esast.AggSpec)
	collect = func(prefix string, m map[string]esast.AggSpec) {
		for k, s := range m {
			fk := k
			if prefix != "" {
				fk = prefix + "." + k
			}
			if s.MatrixStats != nil {
				msTargets[fk] = true
			}
			if sub := s.SubAggs(); len(sub) > 0 {
				collect(fk, sub)
			}
		}
	}
	collect(rootAggName, spec.SubAggs())
	if len(msTargets) == 0 {
		return rows
	}
	kept := make([]AggRow, 0, len(rows))
	for _, r := range rows {
		if msTargets[r.AggName] {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

func recomputeMultiIndexMatrixStatsRowsWave3R63(
	srv *Server,
	aggs map[string]esast.AggSpec,
	allFetchedHits []HitRow,
	schemasByIndex map[string]*schema.IndexSchema,
	primarySchema *schema.IndexSchema,
	allAggRows []AggRow,
) []AggRow {
	if len(aggs) == 0 {
		return allAggRows
	}
	msSubtrees := make(map[string]esast.AggSpec)
	for aggName, spec := range aggs {
		if aggSpecHasMatrixStatsSubtreeR66(spec) {
			msSubtrees[aggName] = spec
		}
	}
	if len(msSubtrees) == 0 {
		return allAggRows
	}
	matchedDocs := make([]runtimeMatchedDoc, 0, len(allFetchedHits))
	for _, h := range allFetchedHits {
		var docMap map[string]any
		if len(h.EffectiveSource()) > 0 {
			dec := json.NewDecoder(bytes.NewReader(h.EffectiveSource()))
			dec.UseNumber()
			_ = dec.Decode(&docMap)
		}
		if docMap == nil {
			docMap = make(map[string]any)
		}
		docMap["__meta_id"] = h.ID
		hSc := schemasByIndex[h.Index]
		if hSc == nil {
			hSc = primarySchema
		}
		hCopy := h
		hCopy.Schema = hSc
		matchedDocs = append(matchedDocs, runtimeMatchedDoc{
			hit:        hCopy,
			doc:        docMap,
			rootDoc:    docMap,
			rootSchema: hSc,
		})
	}
	filtered := allAggRows
	for aggName, spec := range msSubtrees {
		filtered = dropMatrixStatsSubtreeRowsR66(filtered, aggName, spec)
	}
	topMS := make(map[string]esast.AggSpec)
	nestedMS := make(map[string]esast.AggSpec)
	for aggName, spec := range msSubtrees {
		if spec.MatrixStats != nil {
			topMS[aggName] = spec
		} else {
			nestedMS[aggName] = spec
		}
	}
	for aggName, spec := range topMS {
		emitRuntimeMatrixStatsAggRowsWithServerWave3R63(srv, aggName, "_metric", spec.MatrixStats, matchedDocs, &filtered)
	}
	if len(nestedMS) > 0 {
		filtered = applyRuntimeScriptAggsForMap("", "", nestedMS, matchedDocs, matchedDocs, filtered, primarySchema)
	}
	return filtered
}

// parseJavaFloatSuffixR66 coerces Java-style float/double string literals (e.g. `"1.0d"`, `"10.5F"`)
// stored verbatim in `_source` back to finite float64 values.
func parseJavaFloatSuffixR66(s string) (float64, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || strings.ContainsRune(trimmed, '_') || strings.ContainsAny(trimmed, "xX") {
		return 0, false
	}
	if len(trimmed) >= 2 {
		switch trimmed[len(trimmed)-1] {
		case 'd', 'D', 'f', 'F':
			trimmed = trimmed[:len(trimmed)-1]
		}
	}
	f, err := strconv.ParseFloat(trimmed, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// validateMatrixStatsCrossIndexFieldsR66 checks multi-index `matrix_stats` aggregations so that
// any non-empty target index (one with at least one requested field mapped) missing fields
// present in other target indices fails with ES 8.15 `all_shards_failed|illegal_argument_exception`
// parity while still allowing completely unmapped empty indices (`Partially unmapped`).
func validateMatrixStatsCrossIndexFieldsR66(
	srv *Server,
	targets []string,
	schemasByIndex map[string]*schema.IndexSchema,
	req *esast.SearchRequest,
	aggs map[string]esast.AggSpec,
) string {
	if len(targets) <= 1 || len(aggs) == 0 {
		return ""
	}
	fieldMappedInSchema := func(sc *schema.IndexSchema, field string) bool {
		if sc == nil || field == "" {
			return false
		}
		effSc := sc
		if srv != nil && req != nil && len(req.RuntimeMappings) > 0 {
			effSc = srv.augmentSchemaWithRuntimeMappings(sc, req.RuntimeMappings)
		}
		if _, ok := effSc.Fields[field]; ok {
			return true
		}
		b := effSc.ResolveField(field)
		return b.ESType != ""
	}
	var walk func(m map[string]esast.AggSpec) string
	walk = func(m map[string]esast.AggSpec) string {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, aggName := range names {
			sp := m[aggName]
			if sp.MatrixStats != nil && len(sp.MatrixStats.Fields) > 0 {
				var nonEmptyTargets []*schema.IndexSchema
				presentAnywhere := make(map[string]bool, len(sp.MatrixStats.Fields))
				for _, tName := range targets {
					sc := schemasByIndex[tName]
					if sc == nil {
						continue
					}
					cnt := 0
					for _, f := range sp.MatrixStats.Fields {
						if fieldMappedInSchema(sc, f) {
							cnt++
							presentAnywhere[f] = true
						}
					}
					if cnt > 0 {
						nonEmptyTargets = append(nonEmptyTargets, sc)
					}
				}
				if len(nonEmptyTargets) > 1 {
					var missing []string
					for _, f := range sp.MatrixStats.Fields {
						if !presentAnywhere[f] {
							continue
						}
						for _, sc := range nonEmptyTargets {
							if !fieldMappedInSchema(sc, f) {
								missing = append(missing, f)
								break
							}
						}
					}
					if len(missing) > 0 {
						return fmt.Sprintf(
							"all_shards_failed|illegal_argument_exception|Aggregation [%s] all fields must exist in all indices, but some indices are missing these fields [%s]",
							aggName,
							strings.Join(missing, ", "),
						)
					}
				}
			}
			if msg := walk(sp.SubAggs()); msg != "" {
				return msg
			}
		}
		return ""
	}
	return walk(aggs)
}

func emitCreateIndexWave3DeprecationWarningsR63(
	w http.ResponseWriter,
	s *Server,
	r *http.Request,
	rawBody []byte,
	mappings *esast.MappingSpec,
) {
	if s == nil || !s.hasExplicitTargetESVersion() {
		return
	}
	if bytes.Contains(rawBody, []byte(`"unicodeSetFilter"`)) {
		emitESDeprecationWarningRound61(w, s, r, "[unicodeSetFilter] has been deprecated in favor of [unicode_set_filter]")
	}
	if mappings != nil && len(mappings.Properties) > 0 {
		var hasMultifieldForType func(props map[string]esast.FieldProperty, targetType string) bool
		hasMultifieldForType = func(props map[string]esast.FieldProperty, targetType string) bool {
			for _, p := range props {
				if strings.EqualFold(strings.TrimSpace(p.Type), targetType) && len(p.Fields) > 0 {
					return true
				}
				if len(p.Properties) > 0 && hasMultifieldForType(p.Properties, targetType) {
					return true
				}
			}
			return false
		}
		if hasMultifieldForType(mappings.Properties, "aggregate_metric_double") {
			emitESDeprecationWarningRound61(w, s, r, "Adding multifields to [aggregate_metric_double] mappers has no effect and will be forbidden in future")
		}
		if hasMultifieldForType(mappings.Properties, "constant_keyword") {
			emitESDeprecationWarningRound61(w, s, r, "Adding multifields to [constant_keyword] mappers has no effect and will be forbidden in future")
		}
		if hasMultifieldForType(mappings.Properties, "join") {
			emitESDeprecationWarningRound61(w, s, r, "Adding multifields to [join] mappers has no effect and will be forbidden in future")
		}
	}
}

func collectHDRPercentileFieldsWave3R63(aggs map[string]esast.AggSpec) []string {
	var fields []string
	var walk func(m map[string]esast.AggSpec)
	walk = func(m map[string]esast.AggSpec) {
		for _, sp := range m {
			if sp.Percentiles != nil && sp.Percentiles.HDR != nil && sp.Percentiles.Field != "" {
				fields = append(fields, sp.Percentiles.Field)
			}
			if len(sp.SubAggs()) > 0 {
				walk(sp.SubAggs())
			}
		}
	}
	walk(aggs)
	return fields
}

func (s *Server) tryRecoverHDRNegativeShardFailureWave3R63(
	httpReq *http.Request,
	targets []string,
	primaryIndex string,
	primarySchema *schema.IndexSchema,
	schemasByIndex map[string]*schema.IndexSchema,
	req *esast.SearchRequest,
	allHits []HitRow,
	allAggRows []AggRow,
	tookMs int64,
	docLookup func(string) *HitRow,
	isES8 bool,
) (newResp map[string]any, newHits []HitRow, failure map[string]any, ok bool) {
	if s == nil || req == nil || len(targets) == 0 {
		return nil, nil, nil, false
	}
	if httpReq != nil && httpReq.URL != nil && httpReq.URL.Query().Has("allow_partial_search_results") {
		if b, valid := parseOptionalBoolAny(httpReq.URL.Query().Get("allow_partial_search_results")); valid && !b {
			return nil, nil, nil, false
		}
	}
	totalShards := 0
	for _, t := range targets {
		sh, _, _ := s.getIndexShardAndReplicaCounts(t)
		if sh <= 0 {
			sh = 1
		}
		totalShards += sh
	}
	if totalShards <= 1 {
		return nil, nil, nil, false
	}
	hdrFields := collectHDRPercentileFieldsWave3R63(req.EffectiveAggs())
	if len(hdrFields) == 0 {
		return nil, nil, nil, false
	}

	hasPositive := false
	hasNegative := false
	filteredRows := make([]AggRow, 0, len(allAggRows))
	for _, ar := range allAggRows {
		if strings.HasPrefix(ar.AggName, transpiler.RawValuesAggPrefix) {
			parentKey, vals, parsedOK := transpiler.ParseCollectedFloatValues(ar.BucketKey)
			if parsedOK {
				var posParts []string
				for _, v := range vals {
					if v < 0 {
						hasNegative = true
					} else {
						hasPositive = true
						posParts = append(posParts, strconv.FormatFloat(v, 'f', -1, 64))
					}
				}
				if parentKey != "" {
					ar.BucketKey = parentKey + "\x1f_vals:" + strings.Join(posParts, ",")
				} else {
					ar.BucketKey = "_vals:" + strings.Join(posParts, ",")
				}
				ar.DocCount = int64(len(posParts))
				ar.Value = float64(len(posParts))
			}
		}
		filteredRows = append(filteredRows, ar)
	}
	if !hasNegative || !hasPositive {
		return nil, nil, nil, false
	}

	failIdx := primaryIndex
	failShard := 0
	keptHits := make([]HitRow, 0, len(allHits))
	droppedCount := int64(0)
	for _, h := range allHits {
		hIdx := h.Index
		if hIdx == "" {
			hIdx = primaryIndex
		}
		hSc := schemasByIndex[hIdx]
		if hSc == nil {
			hSc = primarySchema
		}
		docNeg := false
		if len(h.EffectiveSource()) > 0 {
			var docMap map[string]any
			dec := json.NewDecoder(bytes.NewReader(h.EffectiveSource()))
			dec.UseNumber()
			if dec.Decode(&docMap) == nil && docMap != nil {
				for _, hf := range hdrFields {
					for _, sv := range collectSchemaAwareScalarValues(docMap, hf, strings.Split(hf, "."), hSc) {
						if fv, okF := toFloat(sv); okF && fv < 0 {
							docNeg = true
							failIdx = hIdx
							failShard = s.shardForDocRoutingRound60(hIdx, h.ID, h.Routing)
							break
						}
					}
					if docNeg {
						break
					}
				}
			}
		}
		if docNeg {
			droppedCount++
			continue
		}
		keptHits = append(keptHits, h)
	}
	if droppedCount > 0 {
		for i := range keptHits {
			if keptHits[i].TotalHits >= droppedCount {
				keptHits[i].TotalHits -= droppedCount
			}
		}
		for i := range filteredRows {
			if filteredRows[i].AggName == "__meta_total" && filteredRows[i].DocCount >= droppedCount {
				filteredRows[i].DocCount -= droppedCount
				filteredRows[i].Value = float64(filteredRows[i].DocCount)
			}
		}
	}

	rebuilt := buildESResponseWithSchemas(primaryIndex, primarySchema, schemasByIndex, req, keptHits, filteredRows, tookMs, docLookup)
	aggsOut, okAgg := rebuilt["aggregations"].(map[string]any)
	if !okAgg {
		return nil, nil, nil, false
	}
	if _, retryErr := stripAndApplyExactQuantilesR61Search(filteredRows, req.EffectiveAggs(), aggsOut, isES8); retryErr != nil {
		return nil, nil, nil, false
	}
	failure = map[string]any{
		"shard": failShard,
		"index": failIdx,
		"node":  "doris-node-1",
		"reason": map[string]any{
			"type":   "array_index_out_of_bounds_exception",
			"reason": "Index -1 out of bounds for length 2048",
			"caused_by": map[string]any{
				"type":   "illegal_argument_exception",
				"reason": "Histogram recorded value cannot be negative.",
			},
		},
	}
	return rebuilt, keptHits, failure, true
}

// detectCrossIndexTopHitsSortShardFailureMapR66 validates `top_hits.sort` field mappings per target index.
// Under `allow_partial_search_results=true` on multi-index queries (`runtime_fields/{10_keyword,20_long}.yml`),
// indices lacking a sort field fail at shard level instead of matching with `_shards.failed=0`.
func detectCrossIndexTopHitsSortShardFailureMapR66(
	s *Server,
	targets []string,
	rawSchemas map[string]*schema.IndexSchema,
	req *esast.SearchRequest,
) (map[string]error, error) {
	if req == nil || len(req.EffectiveAggs()) == 0 || len(targets) == 0 {
		return nil, nil
	}
	type thSortRef struct {
		nestedPath string
		sortEntry  esast.SortFieldSpec
	}
	var refs []thSortRef
	var walkAggs func(m map[string]esast.AggSpec, nestedPath string)
	walkAggs = func(m map[string]esast.AggSpec, nestedPath string) {
		for _, spec := range m {
			nextNested := nestedPath
			if spec.Nested != nil && strings.TrimSpace(spec.Nested.Path) != "" {
				nextNested = strings.TrimSpace(spec.Nested.Path)
			}
			if spec.TopHits != nil {
				for _, se := range spec.TopHits.Sort {
					sf := strings.TrimSpace(se.Entry.Field)
					if sf == "" || strings.HasPrefix(sf, "_") || se.Entry.Type != "" || se.Entry.IgnoreUnmapped {
						continue
					}
					sortNP := nextNested
					if deepest := deepestNestedSortPathR66(se.Entry.Nested); deepest != "" {
						sortNP = deepest
					}
					refs = append(refs, thSortRef{nestedPath: sortNP, sortEntry: se.Entry})
				}
			}
			if sub := spec.SubAggs(); len(sub) > 0 {
				walkAggs(sub, nextNested)
			}
		}
	}
	walkAggs(req.EffectiveAggs(), "")
	if len(refs) == 0 {
		return nil, nil
	}

	failed := make(map[string]error)
	var firstErr error
	for _, tName := range targets {
		rawSc := rawSchemas[tName]
		augSc := rawSc
		if s != nil {
			augSc = s.augmentSchemaWithRuntimeMappings(rawSc, req.RuntimeMappings)
		}
		if len(targets) == 1 && (augSc == nil || (len(augSc.Fields) == 0 && (augSc.RawMapping == nil || len(augSc.RawMapping.Runtime) == 0))) {
			continue
		}
		for _, ref := range refs {
			sf := strings.TrimSpace(ref.sortEntry.Field)
			resolvedOK := false
			if augSc != nil {
				b := augSc.ResolveField(sf)
				if b.ESType != "" || b.Kind != schema.StorageDynamicVariant {
					resolvedOK = true
				} else if ref.nestedPath != "" && !strings.HasPrefix(sf, ref.nestedPath+".") {
					bRel := augSc.ResolveField(ref.nestedPath + "." + sf)
					if bRel.ESType != "" || bRel.Kind != schema.StorageDynamicVariant {
						resolvedOK = true
					}
				}
			}
			if !resolvedOK {
				err := fmt.Errorf("no mapping found for [%s] in order to sort on", sf)
				failed[tName] = err
				if firstErr == nil {
					firstErr = err
				}
				break
			}
		}
	}
	if len(failed) == 0 {
		return nil, nil
	}
	return failed, firstErr
}

func deepestNestedSortPathR66(n *esast.NestedSortSpec) string {
	cur := n
	path := ""
	for cur != nil {
		if p := strings.TrimSpace(cur.Path); p != "" {
			path = p
		}
		cur = cur.Nested
	}
	return path
}

type hlMatchedClauseSpecR66 struct {
	text       string
	isPhrase   bool
	slop       int
	isWildcard bool
	analyzer   string
}

func collectMatchedFieldClausesR66(
	q *esast.Query,
	allowed map[string]bool,
	out *[]hlMatchedClauseSpecR66,
) {
	if q == nil {
		return
	}
	for field, te := range q.Term {
		if fieldMatchesAllowedHighlightSet(field, allowed) {
			if s := strings.TrimSpace(fmt.Sprintf("%v", te.Value)); s != "" {
				*out = append(*out, hlMatchedClauseSpecR66{text: s})
			}
		}
	}
	if q.Terms != nil {
		for f, vals := range q.Terms.Fields {
			if fieldMatchesAllowedHighlightSet(f, allowed) {
				for _, v := range vals {
					if s := strings.TrimSpace(fmt.Sprintf("%v", v)); s != "" {
						*out = append(*out, hlMatchedClauseSpecR66{text: s})
					}
				}
			}
		}
	}
	for field, me := range q.Match {
		if fieldMatchesAllowedHighlightSet(field, allowed) {
			if s := strings.TrimSpace(fmt.Sprintf("%v", me.Query)); s != "" {
				*out = append(*out, hlMatchedClauseSpecR66{text: s, analyzer: me.Analyzer})
			}
		}
	}
	for field, pe := range q.MatchPhrase {
		if fieldMatchesAllowedHighlightSet(field, allowed) && strings.TrimSpace(pe.Query) != "" {
			*out = append(*out, hlMatchedClauseSpecR66{text: pe.Query, isPhrase: true, slop: pe.Slop, analyzer: pe.Analyzer})
		}
	}
	for field, pe := range q.MatchPhrasePrefix {
		if fieldMatchesAllowedHighlightSet(field, allowed) && strings.TrimSpace(pe.Query) != "" {
			words := strings.Fields(pe.Query)
			for i, w := range words {
				if i == len(words)-1 {
					*out = append(*out, hlMatchedClauseSpecR66{text: w + "*", isWildcard: true})
				} else {
					*out = append(*out, hlMatchedClauseSpecR66{text: w})
				}
			}
		}
	}
	for field, pe := range q.MatchBoolPrefix {
		if fieldMatchesAllowedHighlightSet(field, allowed) && strings.TrimSpace(pe.Query) != "" {
			words := strings.Fields(pe.Query)
			for i, w := range words {
				if i == len(words)-1 {
					*out = append(*out, hlMatchedClauseSpecR66{text: w + "*", isWildcard: true})
				} else {
					*out = append(*out, hlMatchedClauseSpecR66{text: w})
				}
			}
		}
	}
	if q.CombinedFields != nil && q.CombinedFields.Query != nil {
		matched := len(q.CombinedFields.Fields) == 0
		for _, f := range q.CombinedFields.Fields {
			if fieldMatchesAllowedHighlightSet(f, allowed) {
				matched = true
				break
			}
		}
		if matched {
			if s := strings.TrimSpace(fmt.Sprintf("%v", q.CombinedFields.Query)); s != "" {
				*out = append(*out, hlMatchedClauseSpecR66{text: s})
			}
		}
	}
	if q.MultiMatch != nil && q.MultiMatch.Query != nil {
		matched := len(q.MultiMatch.Fields) == 0
		for _, f := range q.MultiMatch.Fields {
			if fieldMatchesAllowedHighlightSet(f, allowed) {
				matched = true
				break
			}
		}
		if matched {
			qStr := strings.TrimSpace(fmt.Sprintf("%v", q.MultiMatch.Query))
			if qStr != "" {
				if strings.EqualFold(q.MultiMatch.Type, "phrase") {
					*out = append(*out, hlMatchedClauseSpecR66{text: qStr, isPhrase: true, slop: q.MultiMatch.Slop, analyzer: q.MultiMatch.Analyzer})
				} else {
					*out = append(*out, hlMatchedClauseSpecR66{text: qStr, analyzer: q.MultiMatch.Analyzer})
				}
			}
		}
	}
	if q.QueryString != nil && q.QueryString.Query != "" {
		defaultMatched := q.QueryString.DefaultField == "" && len(q.QueryString.Fields) == 0
		if q.QueryString.DefaultField != "" && fieldMatchesAllowedHighlightSet(q.QueryString.DefaultField, allowed) {
			defaultMatched = true
		}
		for _, f := range q.QueryString.Fields {
			if fieldMatchesAllowedHighlightSet(f, allowed) {
				defaultMatched = true
				break
			}
		}
		extractLuceneClausesForMatchedFieldsR66(q.QueryString.Query, defaultMatched, allowed, q.QueryString.PhraseSlop, q.QueryString.Analyzer, q.QueryString.QuoteAnalyzer, out)
	}
	if q.SimpleQueryString != nil && q.SimpleQueryString.Query != "" {
		defaultMatched := len(q.SimpleQueryString.Fields) == 0
		for _, f := range q.SimpleQueryString.Fields {
			if fieldMatchesAllowedHighlightSet(f, allowed) {
				defaultMatched = true
				break
			}
		}
		if defaultMatched {
			extractLuceneClausesForMatchedFieldsR66(q.SimpleQueryString.Query, true, nil, 0, q.SimpleQueryString.Analyzer, "", out)
		}
	}
	for field, we := range q.Wildcard {
		if fieldMatchesAllowedHighlightSet(field, allowed) && strings.Trim(we.Value, "*?") != "" {
			*out = append(*out, hlMatchedClauseSpecR66{text: we.Value, isWildcard: true})
		}
	}
	for field, pe := range q.Prefix {
		if fieldMatchesAllowedHighlightSet(field, allowed) && pe.Value != "" {
			*out = append(*out, hlMatchedClauseSpecR66{text: pe.Value + "*", isWildcard: true})
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			collectMatchedFieldClausesR66(&q.Bool.Must[i], allowed, out)
		}
		for i := range q.Bool.Should {
			collectMatchedFieldClausesR66(&q.Bool.Should[i], allowed, out)
		}
		for i := range q.Bool.Filter {
			collectMatchedFieldClausesR66(&q.Bool.Filter[i], allowed, out)
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			collectMatchedFieldClausesR66(&q.DisMax.Queries[i], allowed, out)
		}
	}
	if q.Boosting != nil {
		collectMatchedFieldClausesR66(&q.Boosting.Positive, allowed, out)
	}
	if q.Nested != nil {
		collectMatchedFieldClausesR66(&q.Nested.Query, allowed, out)
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil {
		collectMatchedFieldClausesR66(q.FunctionScore.Query, allowed, out)
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil {
		collectMatchedFieldClausesR66(q.ScriptScore.Query, allowed, out)
	}
	if q.ConstantScore != nil {
		collectMatchedFieldClausesR66(&q.ConstantScore.Filter, allowed, out)
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil {
		collectMatchedFieldClausesR66(q.Wrapper.Decoded, allowed, out)
	}
	if q.Pinned != nil && q.Pinned.Organic != nil {
		collectMatchedFieldClausesR66(q.Pinned.Organic, allowed, out)
	}
}

func extractLuceneClausesForMatchedFieldsR66(
	raw string,
	defaultMatched bool,
	allowed map[string]bool,
	defaultPhraseSlop int,
	defaultAnalyzer string,
	quoteAnalyzer string,
	out *[]hlMatchedClauseSpecR66,
) {
	pushTok := func(tok string) {
		slop := defaultPhraseSlop
		isQuoted := false
		if tildeIdx := strings.LastIndexByte(tok, '~'); tildeIdx > 0 {
			tail := strings.TrimRight(tok[tildeIdx+1:], `)"`)
			if n, err := strconv.Atoi(tail); err == nil && n >= 0 {
				slop = n
				tok = tok[:tildeIdx]
			} else if _, errF := strconv.ParseFloat(tail, 64); errF == nil {
				tok = tok[:tildeIdx]
			}
		}
		trimmed := strings.Trim(tok, "()+-!~")
		if strings.HasPrefix(trimmed, `"`) && strings.HasSuffix(trimmed, `"`) && len(trimmed) >= 2 {
			isQuoted = true
			trimmed = trimmed[1 : len(trimmed)-1]
		}
		trimmed = strings.Trim(trimmed, `"`)
		if strings.Trim(trimmed, "*?") == "" {
			return
		}
		if isQuoted {
			an := defaultAnalyzer
			if quoteAnalyzer != "" {
				an = quoteAnalyzer
			}
			*out = append(*out, hlMatchedClauseSpecR66{
				text:     trimmed,
				isPhrase: true,
				slop:     slop,
				analyzer: an,
			})
			return
		}
		isWild := strings.ContainsAny(trimmed, "*?")
		*out = append(*out, hlMatchedClauseSpecR66{
			text:       trimmed,
			isWildcard: isWild,
			analyzer:   defaultAnalyzer,
		})
	}

	n := len(raw)
	i := 0
	var activeGroupField string
	groupDepth := 0
	for i < n {
		for i < n && (raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\n' || raw[i] == '\r') {
			i++
		}
		if i >= n {
			break
		}
		if (raw[i] == '+' || raw[i] == '-' || raw[i] == '!') && i+1 < n && raw[i+1] == '(' {
			i++
		}
		if raw[i] == '(' {
			if groupDepth > 0 {
				groupDepth++
			}
			i++
			continue
		}
		if raw[i] == ')' {
			if groupDepth > 0 {
				groupDepth--
				if groupDepth == 0 {
					activeGroupField = ""
				}
			}
			i++
			continue
		}
		start := i
		inQuote := false
		colonIdx := -1
		for i < n {
			ch := raw[i]
			if ch == '\\' && i+1 < n {
				i += 2
				continue
			}
			if ch == '"' {
				inQuote = !inQuote
				i++
				continue
			}
			if !inQuote {
				if ch == ':' && colonIdx < 0 && allowed != nil {
					colonIdx = i
					if i+1 < n {
						next := raw[i+1]
						if next == '(' || ((next == '+' || next == '-' || next == '!') && i+2 < n && raw[i+2] == '(') {
							fieldPrefix := strings.TrimLeft(raw[start:colonIdx], "+-!(")
							activeGroupField = fieldPrefix
							groupDepth = 1
							if next == '(' {
								i += 2
							} else {
								i += 3
							}
							start = i
							colonIdx = -1
							break
						}
					}
				}
				if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == ')' {
					break
				}
			}
			i++
		}
		if start >= i {
			continue
		}
		tok := raw[start:i]
		upper := strings.ToUpper(strings.Trim(tok, "()"))
		if upper == "AND" || upper == "OR" || upper == "NOT" || upper == "TO" {
			continue
		}
		if colonIdx >= start && allowed != nil {
			fieldName := strings.TrimLeft(raw[start:colonIdx], "+-!(")
			valPart := raw[colonIdx+1 : i]
			if fieldMatchesAllowedHighlightSet(fieldName, allowed) {
				pushTok(valPart)
			}
			continue
		}
		if activeGroupField != "" && allowed != nil {
			if fieldMatchesAllowedHighlightSet(activeGroupField, allowed) {
				pushTok(tok)
			}
			continue
		}
		if defaultMatched {
			pushTok(tok)
		}
	}
}

func findPhraseMatchSpansR66(vTokens, qTokens []analysis.TokenOut, slop int, u16ToByte []int) [][2]int {
	if len(vTokens) == 0 || len(qTokens) == 0 {
		return nil
	}
	if len(qTokens) == 1 {
		var spans [][2]int
		for _, tk := range vTokens {
			if tk.Token == qTokens[0].Token {
				if bStart, bEnd, okSpan := resolveUTF16HighlightSpanBytesR64(u16ToByte, tk.StartOffset, tk.EndOffset); okSpan {
					spans = append(spans, [2]int{bStart, bEnd})
				}
			}
		}
		return spans
	}
	var spans [][2]int
	var dfs func(vIdx, qIdx, usedSlop, firstStart int)
	dfs = func(vIdx, qIdx, usedSlop, firstStart int) {
		if qIdx+1 == len(qTokens) {
			if bStart, bEnd, okSpan := resolveUTF16HighlightSpanBytesR64(u16ToByte, firstStart, vTokens[vIdx].EndOffset); okSpan {
				spans = append(spans, [2]int{bStart, bEnd})
			}
			return
		}
		qGap := qTokens[qIdx+1].Position - qTokens[qIdx].Position
		if qGap < 0 {
			qGap = 1
		}
		for j := vIdx + 1; j < len(vTokens); j++ {
			dGap := vTokens[j].Position - vTokens[vIdx].Position
			if dGap < 1 {
				continue
			}
			stepSlop := dGap - qGap
			if stepSlop < 0 {
				stepSlop = -stepSlop
			}
			if usedSlop+stepSlop > slop {
				if dGap > qGap+slop-usedSlop {
					break
				}
				continue
			}
			if vTokens[j].Token == qTokens[qIdx+1].Token {
				dfs(j, qIdx+1, usedSlop+stepSlop, firstStart)
			}
		}
	}
	for i := 0; i < len(vTokens); i++ {
		if vTokens[i].Token == qTokens[0].Token {
			dfs(i, 0, 0, vTokens[i].StartOffset)
		}
	}
	return spans
}

// buildUnifiedMatchedFieldsHighlightSnippetsR66 implements ES unified highlighter `matched_fields`
// (`search.highlight/60_unified_matched_fields.yml`), analyzing the field and all configured
// `matched_fields` sub-fields with their respective index/search analyzers and merging byte spans.
func (s *Server) buildUnifiedMatchedFieldsHighlightSnippetsR66(
	indexName string,
	hitSchema *schema.IndexSchema,
	field string,
	matchedFields []string,
	vals []string,
	effQuery *esast.Query,
	requireFieldMatch bool,
	preTag, postTag string,
	htmlEscape bool,
	fragSize, numFrags, noMatchSize, maxAnalyzedOffset int,
) ([]string, bool) {
	if s == nil || hitSchema == nil || indexName == "" || field == "" || len(matchedFields) == 0 || len(vals) == 0 {
		return nil, false
	}
	cfg, opts := s.buildIndexAnalysisConfigR62Admin(indexName)
	targetFields := make([]string, 0, 1+len(matchedFields))
	seenF := map[string]bool{field: true}
	targetFields = append(targetFields, field)
	for _, mf := range matchedFields {
		mf = strings.TrimSpace(mf)
		if mf != "" && !seenF[mf] {
			seenF[mf] = true
			targetFields = append(targetFields, mf)
		}
	}

	esc := func(part string) string {
		if !htmlEscape {
			return part
		}
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;")
		return r.Replace(part)
	}

	var out []string
	for _, val := range vals {
		analyzedVal := val
		var unanalyzedSuffix string
		if maxAnalyzedOffset >= 0 && utf8.RuneCountInString(val) > maxAnalyzedOffset {
			runes := []rune(val)
			analyzedVal = string(runes[:maxAnalyzedOffset])
			unanalyzedSuffix = string(runes[maxAnalyzedOffset:])
		}
		u16ToByte := utf16OffsetsToByteOffsetsR64(analyzedVal)
		var spans [][2]int

		for _, tf := range targetFields {
			var allowed map[string]bool
			if requireFieldMatch {
				allowed = map[string]bool{tf: true}
			}
			var clauses []hlMatchedClauseSpecR66
			collectMatchedFieldClausesR66(effQuery, allowed, &clauses)
			if len(clauses) == 0 {
				continue
			}
			b := hitSchema.ResolveField(tf)
			idxAn := cfg.ResolveIndexAnalyzer(b.Analyzer)
			if idxAn == "" {
				idxAn = "standard"
			}
			searchAn := idxAn
			if b.SearchAnalyzer != "" {
				searchAn = cfg.ResolveSearchAnalyzer(b.Analyzer, b.SearchAnalyzer)
			}
			vResp, err := analysis.Analyze(analysis.AnalyzeRequest{
				Text:     []string{analyzedVal},
				Analyzer: idxAn,
				Config:   cfg,
				Options:  opts,
			})
			if err != nil || vResp == nil || len(vResp.Tokens) == 0 {
				continue
			}

			for _, cl := range clauses {
				if cl.isWildcard {
					pat := strings.ToLower(cl.text)
					for _, tk := range vResp.Tokens {
						if matchWildcardPattern(pat, strings.ToLower(tk.Token)) {
							if bStart, bEnd, okSpan := resolveUTF16HighlightSpanBytesR64(u16ToByte, tk.StartOffset, tk.EndOffset); okSpan {
								spans = append(spans, [2]int{bStart, bEnd})
							}
						}
					}
					continue
				}
				effSearchAn := searchAn
				if cl.analyzer != "" {
					effSearchAn = cfg.ResolveSearchAnalyzer(cl.analyzer, "")
				}
				qResp, qErr := analysis.Analyze(analysis.AnalyzeRequest{
					Text:     []string{cl.text},
					Analyzer: effSearchAn,
					Config:   cfg,
					Options:  opts,
				})
				if qErr != nil || qResp == nil || len(qResp.Tokens) == 0 {
					continue
				}
				if cl.isPhrase {
					spans = append(spans, findPhraseMatchSpansR66(vResp.Tokens, qResp.Tokens, cl.slop, u16ToByte)...)
				} else {
					qSet := make(map[string]bool, len(qResp.Tokens))
					for _, qt := range qResp.Tokens {
						if qt.Token != "" {
							qSet[qt.Token] = true
						}
					}
					for _, tk := range vResp.Tokens {
						if !qSet[tk.Token] {
							continue
						}
						if bStart, bEnd, okSpan := resolveUTF16HighlightSpanBytesR64(u16ToByte, tk.StartOffset, tk.EndOffset); okSpan {
							spans = append(spans, [2]int{bStart, bEnd})
						}
					}
				}
			}
		}

		if len(spans) == 0 {
			if noMatchSize > 0 && len(val) > 0 {
				runes := []rune(val)
				if len(runes) > noMatchSize {
					runes = runes[:noMatchSize]
				}
				out = append(out, esc(string(runes)))
			}
			continue
		}
		sort.Slice(spans, func(i, j int) bool {
			if spans[i][0] != spans[j][0] {
				return spans[i][0] < spans[j][0]
			}
			return spans[i][1] < spans[j][1]
		})
		merged := [][2]int{spans[0]}
		for _, sp := range spans[1:] {
			last := &merged[len(merged)-1]
			if sp[0] <= last[1] {
				if sp[1] > last[1] {
					last[1] = sp[1]
				}
			} else {
				merged = append(merged, sp)
			}
		}

		// Render either full value (when numFrags <= 0 or within fragSize) or sliced fragments around hits.
		if numFrags <= 0 || fragSize <= 0 || utf8.RuneCountInString(val) <= fragSize {
			var sb strings.Builder
			pos := 0
			for _, sp := range merged {
				sb.WriteString(esc(analyzedVal[pos:sp[0]]))
				sb.WriteString(preTag)
				sb.WriteString(esc(analyzedVal[sp[0]:sp[1]]))
				sb.WriteString(postTag)
				pos = sp[1]
			}
			sb.WriteString(esc(analyzedVal[pos:]))
			if unanalyzedSuffix != "" {
				sb.WriteString(esc(unanalyzedSuffix))
			}
			f := sb.String()
			if numFrags > 0 {
				f = strings.TrimSpace(f)
			}
			out = append(out, f)
		} else {
			fragOut := buildHighlightedSnippetsFromByteSpansR66(analyzedVal, merged, preTag, postTag, htmlEscape, fragSize, numFrags)
			out = append(out, fragOut...)
		}
		if numFrags > 0 && len(out) >= numFrags {
			out = out[:numFrags]
			break
		}
	}
	return out, true
}

func buildHighlightedSnippetsFromByteSpansR66(
	val string,
	spans [][2]int,
	preTag, postTag string,
	htmlEscape bool,
	fragSize, numFrags int,
) []string {
	esc := func(part string) string {
		if !htmlEscape {
			return part
		}
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;")
		return r.Replace(part)
	}
	var out []string
	idx := 0
	for idx < len(spans) && len(out) < numFrags {
		winStart := spans[idx][0]
		winEnd := spans[idx][1]
		for winStart > 0 {
			r, sz := utf8.DecodeLastRuneInString(val[:winStart])
			if r == ' ' || r == '\n' || r == '\t' {
				break
			}
			_ = sz
			if utf8.RuneCountInString(val[winStart:winEnd]) >= fragSize/2 {
				break
			}
			winStart -= sz
		}
		for winEnd < len(val) && utf8.RuneCountInString(val[winStart:winEnd]) < fragSize {
			_, sz := utf8.DecodeRuneInString(val[winEnd:])
			if sz == 0 {
				break
			}
			winEnd += sz
		}
		for idx < len(spans) && spans[idx][0] >= winStart && spans[idx][1] <= winEnd {
			idx++
		}
		var sb strings.Builder
		pos := winStart
		for _, sp := range spans {
			if sp[0] < winStart || sp[1] > winEnd {
				continue
			}
			if sp[0] < pos {
				continue
			}
			sb.WriteString(esc(val[pos:sp[0]]))
			sb.WriteString(preTag)
			sb.WriteString(esc(val[sp[0]:sp[1]]))
			sb.WriteString(postTag)
			pos = sp[1]
		}
		sb.WriteString(esc(val[pos:winEnd]))
		out = append(out, strings.TrimSpace(sb.String()))
	}
	return out
}
