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

// Package analysis implements Elasticsearch's analysis-common module,
// index analysis configuration/registry parsing, /_analyze (with explain),
// keyword normalizers, and query-time token graph generation.
package analysis

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	// DefaultMaxTokenCount is the default for index.analyze.max_token_count.
	DefaultMaxTokenCount = 10000
	// MaxAllowedTokenCount is the hard upper bound for index.analyze.max_token_count.
	MaxAllowedTokenCount = 100000
	// DefaultMaxNGramDiff is the default for index.max_ngram_diff.
	DefaultMaxNGramDiff = 1
	// MaxAllowedNGramDiff is the hard upper bound for index.max_ngram_diff.
	MaxAllowedNGramDiff = 100
	// DefaultMaxShingleDiff is the default for index.max_shingle_diff.
	DefaultMaxShingleDiff = 3
	// MaxAllowedShingleDiff is the hard upper bound for index.max_shingle_diff.
	MaxAllowedShingleDiff = 100
	// MaxAllowedGramSize is the hard upper bound for max_gram on ngram and edge_ngram components.
	MaxAllowedGramSize = 1024
	// DefaultPositionIncrementGap is the default position gap across multi-valued text inputs.
	DefaultPositionIncrementGap = 100
	// MaxPositionIncrementGap is the hard upper bound for position_increment_gap.
	MaxPositionIncrementGap = 1000000
	// MaxCharFilterOutputRunes caps character filter output length to 1 MiRunes.
	MaxCharFilterOutputRunes = 1048576
	// MaxFilterChainLength caps the number of char_filters or token filters in a pipeline.
	MaxFilterChainLength = 64
	// MaxTokenTermBytes is Lucene's IndexWriter.MAX_TERM_LENGTH (32,766 UTF-8 bytes).
	MaxTokenTermBytes = 32766
	// MaxRegexPatternBytes caps user-supplied regex pattern byte length.
	MaxRegexPatternBytes = 4096
	// DefaultMaxStreamBytes caps cumulative token bytes in a single stream stage to 32 MiB.
	DefaultMaxStreamBytes int64 = 32 << 20
)

// AnalysisError represents an Elasticsearch-compatible error with a wire type and HTTP status.
type AnalysisError struct {
	ErrType string
	Reason  string
	Status  int
}

// Error implements the error interface.
func (e *AnalysisError) Error() string {
	if e == nil {
		return ""
	}
	return e.Reason
}

// AsAnalysisError extracts an *AnalysisError from err if present.
func AsAnalysisError(err error) (*AnalysisError, bool) {
	if err == nil {
		return nil, false
	}
	var ae *AnalysisError
	if errors.As(err, &ae) && ae != nil {
		return ae, true
	}
	return nil, false
}

func newIllegalArgError(reason string) error {
	return &AnalysisError{
		ErrType: "illegal_argument_exception",
		Reason:  reason,
		Status:  400,
	}
}

// TokenContext exposes token attributes (including mutable Term) to script predicates
// used by `condition` and `predicate_token_filter` token filters.
type TokenContext struct {
	Term              string
	Position          int
	PositionIncrement int
	PositionLength    int
	StartOffset       int
	EndOffset         int
	Type              string
	Keyword           bool
}

// Options supplies optional hooks for synonym sets, Painless predicate evaluation,
// and external resource file resolution.
type Options struct {
	// ResolveSynonymSet resolves rules for an ES 8.10+ `_synonyms` set ID.
	ResolveSynonymSet func(setID string) ([]string, error)
	// EvalPredicateScript evaluates a Painless boolean predicate against tok.
	// If nil, DefaultEvalPredicateScript is used.
	EvalPredicateScript func(script map[string]any, tok *TokenContext) (bool, error)
	// ResolveResourcePath resolves lines from a config-relative file setting (e.g. stopwords_path).
	ResolveResourcePath func(settingKey, path string) ([]string, error)
}

// Token is the internal representation of a token flowing through a tokenizer and token filter chain.
type Token struct {
	Term           string
	StartOffset    int
	EndOffset      int
	Type           string
	Position       int
	PositionLength int
	Keyword        bool
	TermFrequency  int
	Payload        []byte
}

func (t Token) clone() Token {
	cp := t
	if t.Payload != nil {
		cp.Payload = append([]byte(nil), t.Payload...)
	}
	return cp
}

// AnalyzeRequest specifies inputs for the `/_analyze` endpoint.
type AnalyzeRequest struct {
	// Text holds one or more input strings to analyze.
	Text []string
	// Analyzer is the named built-in or custom analyzer to run.
	Analyzer string
	// Normalizer is the named built-in or custom normalizer to run.
	Normalizer string
	// Tokenizer is either a string tokenizer name or a map[string]any inline definition.
	Tokenizer any
	// CharFilter holds string char_filter names or map[string]any inline definitions.
	CharFilter []any
	// Filter holds string token filter names or map[string]any inline definitions.
	Filter []any
	// Explain enables detailed per-stage output in Detail.
	Explain bool
	// Attributes filters explain token attributes when non-empty.
	Attributes []string

	// Config provides per-index custom analyzers, normalizers, tokenizers, filters, and limits.
	Config *IndexAnalysisConfig
	// Options provides runtime callbacks for synonym sets and script evaluation.
	Options Options
}

// TokenOut is the wire representation of an analyzed token in `/_analyze`.
type TokenOut struct {
	Token          string `json:"token"`
	StartOffset    int    `json:"start_offset"`
	EndOffset      int    `json:"end_offset"`
	Type           string `json:"type"`
	Position       int    `json:"position"`
	PositionLength *int   `json:"positionLength,omitempty"`
	Bytes          string `json:"bytes,omitempty"`
	Keyword        *bool  `json:"keyword,omitempty"`
	TermFrequency  *int   `json:"termFrequency,omitempty"`
	Payload        string `json:"payload,omitempty"`
}

// ExplainCharFilter captures the output of a single character filter step in explain mode.
type ExplainCharFilter struct {
	Name         string   `json:"name"`
	FilteredText []string `json:"filtered_text"`
}

// ExplainStepTokens captures the output of an analyzer, tokenizer, or token filter step in explain mode.
type ExplainStepTokens struct {
	Name   string     `json:"name"`
	Tokens []TokenOut `json:"tokens"`
}

// ExplainDetail matches Elasticsearch's `detail` object when `explain: true`.
type ExplainDetail struct {
	CustomAnalyzer bool                `json:"custom_analyzer"`
	Analyzer       *ExplainStepTokens  `json:"analyzer,omitempty"`
	CharFilters    []ExplainCharFilter `json:"charfilters,omitempty"`
	Tokenizer      *ExplainStepTokens  `json:"tokenizer,omitempty"`
	TokenFilters   []ExplainStepTokens `json:"tokenfilters,omitempty"`
}

// AnalyzeResponse holds the result of Analyze.
// When marshaled to JSON, it emits `{"detail": ...}` if Detail != nil (explain mode),
// or `{"tokens": [...]}` otherwise, matching Elasticsearch's exact wire format.
type AnalyzeResponse struct {
	Tokens []TokenOut     `json:"tokens,omitempty"`
	Detail *ExplainDetail `json:"detail,omitempty"`
}

// MarshalJSON serializes AnalyzeResponse using Elasticsearch's exact `/_analyze` contract.
func (r AnalyzeResponse) MarshalJSON() ([]byte, error) {
	if r.Detail != nil {
		return json.Marshal(struct {
			Detail *ExplainDetail `json:"detail"`
		}{
			Detail: r.Detail,
		})
	}
	toks := r.Tokens
	if toks == nil {
		toks = []TokenOut{}
	}
	return json.Marshal(struct {
		Tokens []TokenOut `json:"tokens"`
	}{
		Tokens: toks,
	})
}

// PayloadBase64 returns the standard Base64 encoding of a hex-encoded TokenOut.Payload
// (matching Elasticsearch `_termvectors` payload wire encoding, e.g. `PEFMUEhBTlVNPg==` for `<ALPHANUM>`).
func (t TokenOut) PayloadBase64() string {
	if t.Payload == "" {
		return ""
	}
	raw, err := hex.DecodeString(t.Payload)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// QueryToken represents a positioned token produced by query-time analysis.
type QueryToken struct {
	Term           string
	Position       int
	PositionLength int
	StartOffset    int
	EndOffset      int
	Type           string
	Keyword        bool
	Payload        []byte
}

// PayloadBase64 returns the standard Base64 encoding of Payload when present
// (matching Elasticsearch `_termvectors` payload wire encoding).
func (qt QueryToken) PayloadBase64() string {
	if len(qt.Payload) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(qt.Payload)
}

// QueryPosition groups tokens starting at the same position.
type QueryPosition struct {
	Position int
	Terms    []string
	Tokens   []QueryToken
}

// QueryGraphSegment represents an independent articulation-point segment of a query token graph.
// Each segment corresponds to one top-level clause for match / minimum_should_match evaluation,
// and Alternatives holds all parallel single-term or multi-term phrase branches across this segment.
type QueryGraphSegment struct {
	StartPosition int
	EndPosition   int
	Alternatives  [][]string
}

// IsSingleTermAlternatives reports whether every alternative in the segment consists of a single term.
func (s QueryGraphSegment) IsSingleTermAlternatives() bool {
	if len(s.Alternatives) == 0 {
		return false
	}
	for _, alt := range s.Alternatives {
		if len(alt) != 1 {
			return false
		}
	}
	return true
}

// SingleTermAlternatives returns all single-term alternatives in the segment when IsSingleTermAlternatives is true.
func (s QueryGraphSegment) SingleTermAlternatives() []string {
	if !s.IsSingleTermAlternatives() {
		return nil
	}
	terms := make([]string, 0, len(s.Alternatives))
	for _, alt := range s.Alternatives {
		terms = append(terms, alt[0])
	}
	return terms
}

// QueryTokenGraph represents the positioned token graph produced by AnalyzeForQuery.
type QueryTokenGraph struct {
	Tokens                   []QueryToken
	Positions                []QueryPosition
	Segments                 []QueryGraphSegment
	HasMultiTermsPerPosition bool
	HasGraphSpans            bool
}

// IsEmpty reports whether query analysis produced zero tokens.
func (g QueryTokenGraph) IsEmpty() bool {
	return len(g.Tokens) == 0
}

// PhrasePaths enumerates up to maxPaths end-to-end term sequences through the query token graph,
// suitable for compiling `match_phrase` and `match_phrase_prefix` predicates with synonyms/shingles.
func (g QueryTokenGraph) PhrasePaths(maxPaths int) [][]string {
	if len(g.Segments) == 0 {
		return nil
	}
	if maxPaths <= 0 {
		maxPaths = 64
	}
	paths := [][]string{{}}
	for _, seg := range g.Segments {
		if len(seg.Alternatives) == 0 {
			continue
		}
		next := make([][]string, 0, len(paths)*len(seg.Alternatives))
		for _, prefix := range paths {
			for _, alt := range seg.Alternatives {
				merged := make([]string, 0, len(prefix)+len(alt))
				merged = append(merged, prefix...)
				merged = append(merged, alt...)
				next = append(next, merged)
				if len(next) >= maxPaths {
					break
				}
			}
			if len(next) >= maxPaths {
				break
			}
		}
		paths = next
	}
	return paths
}

// NamedCountStat is a single `{name, count, index_count}` entry in `_cluster/stats` `indices.analysis`.
type NamedCountStat struct {
	Name       string `json:"name"`
	Count      int    `json:"count"`
	IndexCount int    `json:"index_count"`
}

// SynonymCountStat is a `{count, index_count}` entry in `_cluster/stats` `indices.analysis.synonyms`.
type SynonymCountStat struct {
	Count      int `json:"count"`
	IndexCount int `json:"index_count"`
}

// ClusterAnalysisStats matches `_cluster/stats` `indices.analysis` (10_analysis_stats.yml & 20_analysis_stats_synonyms.yml).
type ClusterAnalysisStats struct {
	CharFilterTypes    []NamedCountStat            `json:"char_filter_types"`
	TokenizerTypes     []NamedCountStat            `json:"tokenizer_types"`
	FilterTypes        []NamedCountStat            `json:"filter_types"`
	AnalyzerTypes      []NamedCountStat            `json:"analyzer_types"`
	BuiltInCharFilters []NamedCountStat            `json:"built_in_char_filters"`
	BuiltInTokenizers  []NamedCountStat            `json:"built_in_tokenizers"`
	BuiltInFilters     []NamedCountStat            `json:"built_in_filters"`
	BuiltInAnalyzers   []NamedCountStat            `json:"built_in_analyzers"`
	Synonyms           map[string]SynonymCountStat `json:"synonyms"`
}
