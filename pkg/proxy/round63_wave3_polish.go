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
	if prevSpec != nil {
		prevProps = prevSpec.Properties
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
			if !hadExplicit {
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
		var spans [][2]int
		for _, tk := range vResp.Tokens {
			if qTermSet[tk.Token] && tk.StartOffset >= 0 && tk.EndOffset > tk.StartOffset && tk.EndOffset <= len(val) {
				spans = append(spans, [2]int{tk.StartOffset, tk.EndOffset})
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

// aggsContainTopLevelMatrixStatsWave3R63 reports whether `aggs` contains any top-level `matrix_stats` aggregation.
func aggsContainTopLevelMatrixStatsWave3R63(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.MatrixStats != nil {
			return true
		}
	}
	return false
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
		for _, rv := range rawList {
			if fv, ok := toFloat(rv); ok && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				vals = append(vals, fv)
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

func recomputeMultiIndexMatrixStatsRowsWave3R63(
	srv *Server,
	aggs map[string]esast.AggSpec,
	allFetchedHits []HitRow,
	schemasByIndex map[string]*schema.IndexSchema,
	primarySchema *schema.IndexSchema,
	allAggRows []AggRow,
) []AggRow {
	if !aggsContainTopLevelMatrixStatsWave3R63(aggs) {
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
	msNames := make(map[string]bool)
	for aggName, spec := range aggs {
		if spec.MatrixStats != nil {
			msNames[aggName] = true
		}
	}
	filtered := make([]AggRow, 0, len(allAggRows))
	for _, ar := range allAggRows {
		if msNames[ar.AggName] {
			continue
		}
		filtered = append(filtered, ar)
	}
	for aggName, spec := range aggs {
		if spec.MatrixStats != nil {
			emitRuntimeMatrixStatsAggRowsWithServerWave3R63(srv, aggName, "_metric", spec.MatrixStats, matchedDocs, &filtered)
		}
	}
	return filtered
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
		var hasAggMetricMultifield func(props map[string]esast.FieldProperty) bool
		hasAggMetricMultifield = func(props map[string]esast.FieldProperty) bool {
			for _, p := range props {
				if strings.EqualFold(strings.TrimSpace(p.Type), "aggregate_metric_double") && len(p.Fields) > 0 {
					return true
				}
				if len(p.Properties) > 0 && hasAggMetricMultifield(p.Properties) {
					return true
				}
			}
			return false
		}
		if hasAggMetricMultifield(mappings.Properties) {
			emitESDeprecationWarningRound61(w, s, r, "Adding multifields to [aggregate_metric_double] mappers has no effect and will be forbidden in future")
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
