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
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Analyze executes an Elasticsearch `/_analyze` or `/{index}/_analyze` request,
// supporting named analyzers, named normalizers, ad-hoc custom analyzers/normalizers,
// multi-valued text arrays with `position_increment_gap` and `+1` char offset gaps,
// `index.analyze.max_token_count` enforcement, `attributes` filtering, and `explain: true`.
func Analyze(req AnalyzeRequest) (*AnalyzeResponse, error) {
	maxTokenCount := effectiveMaxTokenCount(req.Config)

	ca, err := resolveRequestPipeline(req)
	if err != nil {
		return nil, err
	}

	if len(req.Text) == 0 {
		resp := &AnalyzeResponse{Tokens: []TokenOut{}}
		if req.Explain {
			resp.Detail = buildExplainDetail(ca, nil, nil, nil, nil, req.Attributes)
		}
		return resp, nil
	}

	// Stage 1: Character filters across each input string (tracking +1 offset gap across array elements)
	streams := make([]charStream, len(req.Text))
	baseOffset := 0
	for i, txt := range req.Text {
		if i > 0 {
			baseOffset++
		}
		cs := newCharStream(txt, baseOffset)
		streams[i] = cs
		baseOffset = cs.origEnd
	}

	charFilterOutputs := make([][]string, len(ca.charFilters))
	for cfIdx, cf := range ca.charFilters {
		filteredTexts := make([]string, len(streams))
		for sIdx := range streams {
			var cfErr error
			streams[sIdx], cfErr = cf.apply(streams[sIdx])
			if cfErr != nil {
				return nil, cfErr
			}
			filteredTexts[sIdx] = streams[sIdx].String()
		}
		charFilterOutputs[cfIdx] = filteredTexts
	}

	// Stage 2: Tokenize across each stream, applying position_increment_gap across multi-valued elements!
	tokBudget := newTokenStreamBudget(maxTokenCount)
	var tokSnapshot []Token
	nextPos := 0
	for sIdx, cs := range streams {
		if sIdx > 0 && nextPos > 0 {
			nextPos += ca.positionIncrementGap
		}
		elemToks, tokErr := ca.tokenizer.tokenize(cs, nextPos, tokBudget)
		if tokErr != nil {
			return nil, tokErr
		}
		if len(elemToks) > 0 {
			maxPos := elemToks[0].Position
			for _, et := range elemToks {
				if et.Position > maxPos {
					maxPos = et.Position
				}
			}
			nextPos = maxPos + 1
			tokSnapshot = append(tokSnapshot, elemToks...)
		}
		if err := checkMaxTokenLimit(len(tokSnapshot), maxTokenCount); err != nil {
			return nil, err
		}
	}

	var explainTokenizerToks []Token
	var explainRetainedBytes int64
	if req.Explain && ca.isCustom {
		explainTokenizerToks = cloneTokenSlice(tokSnapshot)
		explainRetainedBytes += tokBudget.usedBytes
	}

	// Stage 3: Token filters sequentially
	curTokens := tokSnapshot
	explainFilterSteps := make([][]Token, len(ca.tokenFilters))
	for tfIdx, tf := range ca.tokenFilters {
		tfBudget := newTokenStreamBudget(maxTokenCount)
		var tfErr error
		curTokens, tfErr = tf.apply(curTokens, tfBudget)
		if tfErr != nil {
			return nil, tfErr
		}
		if err := checkMaxTokenLimit(len(curTokens), maxTokenCount); err != nil {
			return nil, err
		}
		if req.Explain && ca.isCustom {
			explainRetainedBytes += tfBudget.usedBytes
			if explainRetainedBytes > DefaultMaxStreamBytes {
				return nil, newIllegalArgError(fmt.Sprintf("token stream byte size has exceeded maximum allowed [%d] bytes", DefaultMaxStreamBytes))
			}
			explainFilterSteps[tfIdx] = cloneTokenSlice(curTokens)
		}
	}

	stdTokens := formatTokenOutSlice(curTokens, false, req.Attributes)
	resp := &AnalyzeResponse{
		Tokens: stdTokens,
	}
	if req.Explain {
		resp.Detail = buildExplainDetail(ca, curTokens, charFilterOutputs, explainTokenizerToks, explainFilterSteps, req.Attributes)
	}
	return resp, nil
}

// NormalizeTerm applies a named normalizer (`"lowercase"`, `"uppercase"`, `"asciifolding"`, or custom index normalizer)
// to a single keyword value for index-time or query-time normalization.
func NormalizeTerm(text string, normalizerName string, cfg *IndexAnalysisConfig, opts Options) (string, error) {
	if strings.TrimSpace(normalizerName) == "" || strings.EqualFold(strings.TrimSpace(normalizerName), "none") {
		return text, nil
	}
	if text == "" {
		return "", nil
	}
	resp, err := Analyze(AnalyzeRequest{
		Text:       []string{text},
		Normalizer: normalizerName,
		Config:     cfg,
		Options:    opts,
	})
	if err != nil {
		return "", err
	}
	if len(resp.Tokens) == 0 {
		return "", nil
	}
	return resp.Tokens[0].Token, nil
}

// AnalyzeTokens runs text through the specified analyzer and returns the raw positioned token slice
// (with PositionLength normalized to >= 1), suitable for downstream query graph or term inspection.
func AnalyzeTokens(text string, analyzerName string, cfg *IndexAnalysisConfig, opts Options) ([]Token, error) {
	maxTokenCount := effectiveMaxTokenCount(cfg)
	effAnalyzer := strings.TrimSpace(analyzerName)
	if effAnalyzer == "" {
		effAnalyzer = cfg.ResolveSearchAnalyzer("", "")
	}
	ca, err := resolveNamedAnalyzer(effAnalyzer, cfg, opts)
	if err != nil {
		return nil, err
	}

	toks, err := runCompiledAnalyzerSingleText(ca, text, maxTokenCount)
	if err != nil {
		return nil, err
	}
	for i := range toks {
		if toks[i].PositionLength < 1 {
			toks[i].PositionLength = 1
		}
	}
	return toks, nil
}

// BuildQueryTokenGraph converts a positioned token slice into a QueryTokenGraph with
// articulation-point segments and enumerated phrase branches.
func BuildQueryTokenGraph(tokens []Token) QueryTokenGraph {
	return buildQueryTokenGraph(tokens)
}

// AnalyzeForQuery runs text through the specified analyzer and builds a positioned QueryTokenGraph
// (including stacked tokens at the same position, multi-word synonym_graph / shingle spans,
// articulation-point segments, and phrase path enumeration).
func AnalyzeForQuery(text string, analyzerName string, cfg *IndexAnalysisConfig, opts Options) (QueryTokenGraph, error) {
	toks, err := AnalyzeTokens(text, analyzerName, cfg, opts)
	if err != nil {
		return QueryTokenGraph{}, err
	}
	return buildQueryTokenGraph(toks), nil
}

func runCompiledAnalyzerSingleText(ca *compiledAnalyzer, text string, maxTokenCount int) ([]Token, error) {
	cs := newCharStream(text, 0)
	for _, cf := range ca.charFilters {
		var cfErr error
		cs, cfErr = cf.apply(cs)
		if cfErr != nil {
			return nil, cfErr
		}
	}
	tokBudget := newTokenStreamBudget(maxTokenCount)
	toks, err := ca.tokenizer.tokenize(cs, 0, tokBudget)
	if err != nil {
		return nil, err
	}
	if err := checkMaxTokenLimit(len(toks), maxTokenCount); err != nil {
		return nil, err
	}
	for _, tf := range ca.tokenFilters {
		tfBudget := newTokenStreamBudget(maxTokenCount)
		toks, err = tf.apply(toks, tfBudget)
		if err != nil {
			return nil, err
		}
		if err := checkMaxTokenLimit(len(toks), maxTokenCount); err != nil {
			return nil, err
		}
	}
	return toks, nil
}

func resolveRequestPipeline(req AnalyzeRequest) (*compiledAnalyzer, error) {
	if len(req.CharFilter) > MaxFilterChainLength {
		return nil, newIllegalArgError(fmt.Sprintf("[analyze] char_filter count [%d] exceeds maximum allowed [%d]", len(req.CharFilter), MaxFilterChainLength))
	}
	if len(req.Filter) > MaxFilterChainLength {
		return nil, newIllegalArgError(fmt.Sprintf("[analyze] filter count [%d] exceeds maximum allowed [%d]", len(req.Filter), MaxFilterChainLength))
	}
	hasAnalyzer := strings.TrimSpace(req.Analyzer) != ""
	hasNormalizer := strings.TrimSpace(req.Normalizer) != ""
	hasAdhocComponents := req.Tokenizer != nil || len(req.CharFilter) > 0 || len(req.Filter) > 0

	if hasAnalyzer && (hasNormalizer || hasAdhocComponents) {
		return nil, newIllegalArgError("[analyze] analyzer cannot be combined with normalizer, tokenizer, filter, or char_filter")
	}
	if hasNormalizer && hasAdhocComponents {
		return nil, newIllegalArgError("[analyze] normalizer cannot be combined with tokenizer, filter, or char_filter")
	}

	if hasNormalizer {
		return resolveNamedNormalizer(strings.TrimSpace(req.Normalizer), req.Config, req.Options)
	}
	if hasAnalyzer {
		return resolveNamedAnalyzer(strings.TrimSpace(req.Analyzer), req.Config, req.Options)
	}
	if hasAdhocComponents {
		if req.Tokenizer == nil {
			// Ad-hoc custom normalizer in request (10_analyze.yml: filter/char_filter without tokenizer)!
			cfs, tok, tfs, err := compileCustomChain(req.CharFilter, "keyword", req.Filter, true, req.Config, req.Options)
			if err != nil {
				return nil, err
			}
			return &compiledAnalyzer{
				name:                 "custom",
				isCustom:             true,
				positionIncrementGap: DefaultPositionIncrementGap,
				charFilters:          cfs,
				tokenizer:            tok,
				tokenFilters:         tfs,
			}, nil
		}
		cfs, tok, tfs, err := compileCustomChain(req.CharFilter, req.Tokenizer, req.Filter, false, req.Config, req.Options)
		if err != nil {
			return nil, err
		}
		return &compiledAnalyzer{
			name:                 "custom",
			isCustom:             true,
			positionIncrementGap: DefaultPositionIncrementGap,
			charFilters:          cfs,
			tokenizer:            tok,
			tokenFilters:         tfs,
		}, nil
	}

	// Default analyzer when none specified: index `default` if present, else `standard`!
	defName := "standard"
	if req.Config != nil {
		if _, ok := req.Config.AnalyzerDefs["default"]; ok {
			defName = "default"
		}
	}
	return resolveNamedAnalyzer(defName, req.Config, req.Options)
}

func resolveNamedAnalyzer(name string, cfg *IndexAnalysisConfig, opts Options) (*compiledAnalyzer, error) {
	return resolveNamedAnalyzerWithCtx(name, filterBuildContext{cfg: cfg, opts: opts})
}

func resolveNamedAnalyzerWithCtx(name string, bctx filterBuildContext) (*compiledAnalyzer, error) {
	subCtx, err := bctx.enterAnalyzer(name)
	if err != nil {
		return nil, err
	}
	if bctx.cfg != nil {
		if def, ok := bctx.cfg.AnalyzerDefs[name]; ok {
			// Recompile with current request Options (e.g. ResolveSynonymSet / EvalPredicateScript) and cycle guard
			return compileDefinedAnalyzerWithCtx(name, def, subCtx)
		}
	}
	if isBuiltInAnalyzerType(name) {
		return buildBuiltInOrTypedAnalyzerWithCtx(name, name, nil, subCtx)
	}
	return nil, newIllegalArgError(fmt.Sprintf("failed to find global analyzer [%s]", name))
}

func resolveNamedNormalizer(name string, cfg *IndexAnalysisConfig, opts Options) (*compiledAnalyzer, error) {
	if cfg != nil {
		if def, ok := cfg.NormalizerDefs[name]; ok {
			return compileDefinedNormalizer(name, def, cfg, opts)
		}
	}
	ln := strings.ToLower(strings.TrimSpace(name))
	switch ln {
	case "lowercase", "uppercase", "asciifolding", "icu_normalizer", "icu_folding":
		cfs, tok, tfs, err := compileCustomChain(nil, "keyword", []any{ln}, true, cfg, opts)
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
	default:
		return nil, newIllegalArgError(fmt.Sprintf("failed to find normalizer [%s]", name))
	}
}

type tokenStreamBudget struct {
	maxTokens int
	curTokens int
	maxBytes  int64
	usedBytes int64
}

func effectiveMaxTokenCount(cfg *IndexAnalysisConfig) int {
	maxTokenCount := DefaultMaxTokenCount
	if cfg != nil && cfg.MaxTokenCount > 0 {
		maxTokenCount = cfg.MaxTokenCount
	}
	if maxTokenCount > MaxAllowedTokenCount {
		maxTokenCount = MaxAllowedTokenCount
	}
	return maxTokenCount
}

func newTokenStreamBudget(maxTokens int) *tokenStreamBudget {
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokenCount
	}
	if maxTokens > MaxAllowedTokenCount {
		maxTokens = MaxAllowedTokenCount
	}
	return &tokenStreamBudget{
		maxTokens: maxTokens,
		maxBytes:  DefaultMaxStreamBytes,
	}
}

func (b *tokenStreamBudget) canAddOne() error {
	if b == nil {
		return nil
	}
	if b.curTokens+1 > b.maxTokens {
		return checkMaxTokenLimit(b.curTokens+1, b.maxTokens)
	}
	return nil
}

func (b *tokenStreamBudget) add(termBytes int) error {
	if termBytes > MaxTokenTermBytes {
		return newIllegalArgError(fmt.Sprintf("token term length [%d] exceeds maximum allowed [%d] bytes", termBytes, MaxTokenTermBytes))
	}
	if b == nil {
		return nil
	}
	if b.curTokens+1 > b.maxTokens {
		return checkMaxTokenLimit(b.curTokens+1, b.maxTokens)
	}
	if b.usedBytes+int64(termBytes) > b.maxBytes {
		return newIllegalArgError(fmt.Sprintf("token stream byte size has exceeded maximum allowed [%d] bytes", b.maxBytes))
	}
	b.curTokens++
	b.usedBytes += int64(termBytes)
	return nil
}

func (b *tokenStreamBudget) addToken(tok Token) error {
	if len(tok.Term) > MaxTokenTermBytes {
		return newIllegalArgError(fmt.Sprintf("token term length [%d] exceeds maximum allowed [%d] bytes", len(tok.Term), MaxTokenTermBytes))
	}
	if b == nil {
		return nil
	}
	total := len(tok.Term) + len(tok.Payload)
	if b.curTokens+1 > b.maxTokens {
		return checkMaxTokenLimit(b.curTokens+1, b.maxTokens)
	}
	if b.usedBytes+int64(total) > b.maxBytes {
		return newIllegalArgError(fmt.Sprintf("token stream byte size has exceeded maximum allowed [%d] bytes", b.maxBytes))
	}
	b.curTokens++
	b.usedBytes += int64(total)
	return nil
}

func (b *tokenStreamBudget) addSlice(tokens []Token) error {
	for _, tok := range tokens {
		if err := b.addToken(tok); err != nil {
			return err
		}
	}
	return nil
}

func checkMaxTokenLimit(count int, maxTokenCount int) error {
	if count > maxTokenCount {
		return newIllegalArgError(fmt.Sprintf(
			"The number of tokens produced by calling _analyze has exceeded the allowed maximum of [%d]. This limit can be set by changing the [index.analyze.max_token_count] index level setting.",
			maxTokenCount,
		))
	}
	return nil
}

func cloneTokenSlice(in []Token) []Token {
	out := make([]Token, len(in))
	for i, t := range in {
		out[i] = t.clone()
	}
	return out
}

func formatTokenOutSlice(tokens []Token, explain bool, attributes []string) []TokenOut {
	attrFilter := make(map[string]bool, len(attributes))
	for _, a := range attributes {
		attrFilter[strings.ToLower(strings.TrimSpace(a))] = true
	}
	wantAttr := func(names ...string) bool {
		if len(attrFilter) == 0 {
			return explain
		}
		for _, n := range names {
			if attrFilter[strings.ToLower(n)] {
				return true
			}
		}
		return false
	}

	out := make([]TokenOut, 0, len(tokens))
	for _, tok := range tokens {
		pl := tok.PositionLength
		if pl < 1 {
			pl = 1
		}
		tf := tok.TermFrequency
		if tf < 1 {
			tf = 1
		}
		to := TokenOut{
			Token:       tok.Term,
			StartOffset: tok.StartOffset,
			EndOffset:   tok.EndOffset,
			Type:        tok.Type,
			Position:    tok.Position,
		}
		if pl > 1 || wantAttr("positionlength", "position_length") {
			plCopy := pl
			to.PositionLength = &plCopy
		}
		if wantAttr("bytes", "termtobytesrefattribute") {
			to.Bytes = formatBytesRefString(tok.Term)
		}
		if wantAttr("keyword", "keywordattribute") {
			kwCopy := tok.Keyword
			to.Keyword = &kwCopy
		}
		if tf > 1 || wantAttr("termfrequency", "term_frequency", "termfrequencyattribute") {
			tfCopy := tf
			to.TermFrequency = &tfCopy
		}
		if tok.Payload != nil && (explain || wantAttr("payload", "payloadattribute")) {
			to.Payload = formatBytesHexPlain(tok.Payload)
		}
		out = append(out, to)
	}
	return out
}

func formatBytesRefString(s string) string {
	b := []byte(s)
	if len(b) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.Grow(len(b)*3 + 1)
	sb.WriteByte('[')
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(formatHexByte(c))
	}
	sb.WriteByte(']')
	return sb.String()
}

func formatBytesHexPlain(b []byte) string {
	return hex.EncodeToString(b)
}

func formatHexByte(b byte) string {
	const hexDigits = "0123456789abcdef"
	return string([]byte{hexDigits[b>>4], hexDigits[b&0x0F]})
}

func buildExplainDetail(
	ca *compiledAnalyzer,
	finalToks []Token,
	charFilterOutputs [][]string,
	tokenizerToks []Token,
	filterStepToks [][]Token,
	attributes []string,
) *ExplainDetail {
	if !ca.isCustom {
		return &ExplainDetail{
			CustomAnalyzer: false,
			Analyzer: &ExplainStepTokens{
				Name:   ca.name,
				Tokens: formatTokenOutSlice(finalToks, true, attributes),
			},
		}
	}

	detail := &ExplainDetail{
		CustomAnalyzer: true,
	}
	if len(ca.charFilters) > 0 {
		detail.CharFilters = make([]ExplainCharFilter, len(ca.charFilters))
		for i, cf := range ca.charFilters {
			ft := []string{}
			if i < len(charFilterOutputs) && charFilterOutputs[i] != nil {
				ft = charFilterOutputs[i]
			}
			detail.CharFilters[i] = ExplainCharFilter{
				Name:         cf.name,
				FilteredText: ft,
			}
		}
	}
	if ca.tokenizer != nil {
		detail.Tokenizer = &ExplainStepTokens{
			Name:   ca.tokenizer.name,
			Tokens: formatTokenOutSlice(tokenizerToks, true, attributes),
		}
	}
	if len(ca.tokenFilters) > 0 {
		detail.TokenFilters = make([]ExplainStepTokens, len(ca.tokenFilters))
		for i, tf := range ca.tokenFilters {
			var stepToks []Token
			if i < len(filterStepToks) {
				stepToks = filterStepToks[i]
			}
			detail.TokenFilters[i] = ExplainStepTokens{
				Name:   tf.name,
				Tokens: formatTokenOutSlice(stepToks, true, attributes),
			}
		}
	}
	return detail
}

// ============================================================================
// Query Token Graph Builder (Articulation-Point Segmentation + Path Enumeration)
// ============================================================================

func buildQueryTokenGraph(tokens []Token) QueryTokenGraph {
	if len(tokens) == 0 {
		return QueryTokenGraph{}
	}

	qTokens := make([]QueryToken, len(tokens))
	hasGraphSpans := false
	for i, tok := range tokens {
		pl := tok.PositionLength
		if pl < 1 {
			pl = 1
		}
		if pl > 1 {
			hasGraphSpans = true
		}
		var payloadCopy []byte
		if tok.Payload != nil {
			payloadCopy = append([]byte(nil), tok.Payload...)
		}
		qTokens[i] = QueryToken{
			Term:           tok.Term,
			Position:       tok.Position,
			PositionLength: pl,
			StartOffset:    tok.StartOffset,
			EndOffset:      tok.EndOffset,
			Type:           tok.Type,
			Keyword:        tok.Keyword,
			Payload:        payloadCopy,
		}
	}

	// Group by Position, deduplicating identical (Term, PositionLength) edges per position u!
	type posEdgeKey struct {
		term   string
		posLen int
	}
	posOrder := make([]int, 0, len(qTokens))
	byPos := make(map[int][]QueryToken)
	seenEdgeByPos := make(map[int]map[posEdgeKey]bool)
	for _, qt := range qTokens {
		edgeSet, exists := seenEdgeByPos[qt.Position]
		if !exists {
			posOrder = append(posOrder, qt.Position)
			edgeSet = make(map[posEdgeKey]bool)
			seenEdgeByPos[qt.Position] = edgeSet
		}
		ek := posEdgeKey{term: qt.Term, posLen: qt.PositionLength}
		if !edgeSet[ek] {
			edgeSet[ek] = true
			byPos[qt.Position] = append(byPos[qt.Position], qt)
		}
	}
	sort.Ints(posOrder)

	positions := make([]QueryPosition, 0, len(posOrder))
	hasMultiTerms := false
	for _, p := range posOrder {
		grp := byPos[p]
		seen := make(map[string]bool, len(grp))
		terms := make([]string, 0, len(grp))
		for _, qt := range grp {
			if !seen[qt.Term] {
				seen[qt.Term] = true
				terms = append(terms, qt.Term)
			}
		}
		if len(terms) > 1 {
			hasMultiTerms = true
		}
		positions = append(positions, QueryPosition{
			Position: p,
			Terms:    terms,
			Tokens:   grp,
		})
	}

	segments := computeGraphSegments(qTokens, posOrder, byPos)
	return QueryTokenGraph{
		Tokens:                   qTokens,
		Positions:                positions,
		Segments:                 segments,
		HasMultiTermsPerPosition: hasMultiTerms,
		HasGraphSpans:            hasGraphSpans,
	}
}

func computeGraphSegments(qTokens []QueryToken, posOrder []int, byPos map[int][]QueryToken) []QueryGraphSegment {
	if len(posOrder) == 0 {
		return nil
	}
	// Map DAG edges: u -> list of QueryTokens starting at u
	// Find articulation cut points: iterating over sorted start positions, maintain `frontier = max(u + pl)`.
	// Whenever the next start position `nextU >= frontier` (or at end of stream), `[segStart, frontier)` is an independent segment!
	var segments []QueryGraphSegment
	segStart := posOrder[0]
	frontier := segStart

	flushSegment := func(sPos, ePos int) {
		alts := enumerateSegmentPaths(sPos, ePos, byPos, 64)
		if len(alts) > 0 {
			segments = append(segments, QueryGraphSegment{
				StartPosition: sPos,
				EndPosition:   ePos,
				Alternatives:  alts,
			})
		}
	}

	for idx, u := range posOrder {
		if idx > 0 && u >= frontier {
			flushSegment(segStart, frontier)
			segStart = u
			frontier = u
		}
		for _, qt := range byPos[u] {
			end := u + qt.PositionLength
			if end > frontier {
				frontier = end
			}
		}
	}
	flushSegment(segStart, frontier)
	return segments
}

const maxDFSVisits = 1024

func enumerateSegmentPaths(startNode, targetEnd int, byPos map[int][]QueryToken, limit int) [][]string {
	var results [][]string
	seenPath := make(map[string]bool)

	// Collect sorted nodes inside [startNode, targetEnd) for fallback when gaps exist (e.g. removed stopwords).
	var innerNodes []int
	for pos := range byPos {
		if pos >= startNode && pos < targetEnd {
			innerNodes = append(innerNodes, pos)
		}
	}
	sort.Ints(innerNodes)

	nextReachableNode := func(from int) int {
		for _, n := range innerNodes {
			if n >= from {
				return n
			}
		}
		return targetEnd
	}

	visits := 0
	var dfs func(node int, cur []string)
	dfs = func(node int, cur []string) {
		if len(results) >= limit || visits >= maxDFSVisits {
			return
		}
		visits++
		if node >= targetEnd {
			if len(cur) > 0 {
				key := strings.Join(cur, "\x00")
				if !seenPath[key] {
					seenPath[key] = true
					cp := make([]string, len(cur))
					copy(cp, cur)
					results = append(results, cp)
				}
			}
			return
		}
		edges := byPos[node]
		if len(edges) == 0 {
			nextN := nextReachableNode(node + 1)
			dfs(nextN, cur)
			return
		}
		for _, edge := range edges {
			if len(results) >= limit || visits >= maxDFSVisits {
				return
			}
			cur = append(cur, edge.Term)
			dfs(node+edge.PositionLength, cur)
			cur = cur[:len(cur)-1]
		}
	}

	dfs(startNode, nil)
	return results
}
