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

package esast

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var autoIDCounter uint64

// NextAutoID generates a unique time-ordered document ID when an ES client omits `_id`.
func NextAutoID() string {
	seq := atomic.AddUint64(&autoIDCounter, 1)
	return fmt.Sprintf("auto-%d-%d", time.Now().UnixNano(), seq)
}

// SearchRequest models an Elasticsearch / OpenSearch `/_search` request payload.
type SearchRequest struct {
	Query          *Query             `json:"query,omitempty"`
	AliasFilter    *Query             `json:"-"`
	KNN            KNNSlice           `json:"knn,omitempty"`
	PostFilter     *Query             `json:"post_filter,omitempty"`
	From           *int               `json:"from,omitempty"`
	Size           *int               `json:"size,omitempty"`
	TerminateAfter *int               `json:"terminate_after,omitempty"`
	MinScore       *float64           `json:"min_score,omitempty"`
	Aggs           map[string]AggSpec `json:"aggs,omitempty"`
	Aggregations   map[string]AggSpec `json:"aggregations,omitempty"`
	Sort           SortSlice          `json:"sort,omitempty"`
	SearchAfter    []any              `json:"search_after,omitempty"`
	Source         *SourceFilter      `json:"_source,omitempty"`
	TrackTotalHits any                `json:"track_total_hits,omitempty"`
	TrackScores    *bool              `json:"track_scores,omitempty"`
	Highlight      *HighlightSpec     `json:"highlight,omitempty"`
	Collapse       *CollapseSpec      `json:"collapse,omitempty"`
	Rescore        RescoreSlice       `json:"rescore,omitempty"`
	PIT            *PITSpec           `json:"pit,omitempty"`
	Fields         []FieldRequestSpec `json:"fields,omitempty"`
	DocvalueFields []FieldRequestSpec `json:"docvalue_fields,omitempty"`
	ScriptFields   map[string]any     `json:"script_fields,omitempty"`
}

// FieldRequestSpec represents an entry in `fields` or `docvalue_fields` in a search request,
// which in Elasticsearch/OpenSearch can be either a plain string `"@timestamp"` or an object
// `{"field": "@timestamp", "format": "strict_date_optional_time"}`.
type FieldRequestSpec struct {
	Field           string `json:"field"`
	Format          string `json:"format,omitempty"`
	IncludeUnmapped any    `json:"include_unmapped,omitempty"`
}

func (frs *FieldRequestSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		frs.Field = s
		return nil
	}
	type alias FieldRequestSpec
	var obj alias
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return err
	}
	*frs = FieldRequestSpec(obj)
	return nil
}

// EffectiveFieldSpecs returns the combined `fields` and `docvalue_fields` specifications.
func (r *SearchRequest) EffectiveFieldSpecs() []FieldRequestSpec {
	if r == nil || (len(r.Fields) == 0 && len(r.DocvalueFields) == 0) {
		return nil
	}
	out := make([]FieldRequestSpec, 0, len(r.Fields)+len(r.DocvalueFields))
	out = append(out, r.Fields...)
	out = append(out, r.DocvalueFields...)
	return out
}

// ShouldTrackTotalHits returns false only when TrackTotalHits is explicitly disabled (`false` or `0`).
func (r *SearchRequest) ShouldTrackTotalHits() bool {
	if r == nil || r.TrackTotalHits == nil {
		return true
	}
	switch v := r.TrackTotalHits.(type) {
	case bool:
		return v
	case string:
		return !strings.EqualFold(strings.TrimSpace(v), "false") && strings.TrimSpace(v) != "0"
	case int:
		return v > 0
	case int64:
		return v > 0
	case float64:
		return v > 0
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n > 0
		}
	}
	return true
}

// KNNQuery represents an Elasticsearch 8/9 or OpenSearch `knn` vector search clause.
type KNNQuery struct {
	Field         string     `json:"field,omitempty"`
	QueryVector   []float64  `json:"query_vector,omitempty"`
	K             int        `json:"k,omitempty"`
	NumCandidates int        `json:"num_candidates,omitempty"`
	Similarity    *float64   `json:"similarity,omitempty"`
	Boost         *float64   `json:"boost,omitempty"`
	Filter        QuerySlice `json:"filter,omitempty"`
}

func (kq *KNNQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	type knnAlias KNNQuery
	var std knnAlias
	if err := json.Unmarshal(trimmed, &std); err == nil && std.Field != "" {
		*kq = KNNQuery(std)
		return nil
	}
	// Support OpenSearch knn syntax: {"<field>": {"vector": [...], "k": 5, "filter": {...}}}
	var byField map[string]struct {
		Vector        []float64  `json:"vector"`
		QueryVector   []float64  `json:"query_vector"`
		K             int        `json:"k"`
		NumCandidates int        `json:"num_candidates"`
		Similarity    *float64   `json:"similarity"`
		Boost         *float64   `json:"boost"`
		Filter        QuerySlice `json:"filter"`
	}
	if err := json.Unmarshal(trimmed, &byField); err != nil {
		return err
	}
	for field, spec := range byField {
		vec := spec.Vector
		if len(vec) == 0 {
			vec = spec.QueryVector
		}
		kq.Field = field
		kq.QueryVector = vec
		kq.K = spec.K
		kq.NumCandidates = spec.NumCandidates
		kq.Similarity = spec.Similarity
		kq.Boost = spec.Boost
		kq.Filter = spec.Filter
		break
	}
	return nil
}

// KNNSlice unmarshals either a single `KNNQuery` object `{...}` or an array `[{...}]`.
type KNNSlice []KNNQuery

func (ks *KNNSlice) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*ks = nil
		return nil
	}
	if trimmed[0] == '[' {
		var list []KNNQuery
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return err
		}
		*ks = list
		return nil
	}
	var single KNNQuery
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return err
	}
	*ks = []KNNQuery{single}
	return nil
}

type PITSpec struct {
	ID        string `json:"id"`
	KeepAlive string `json:"keep_alive,omitempty"`
}

type InnerHitsSpec struct {
	Name           string             `json:"name,omitempty"`
	From           int                `json:"from,omitempty"`
	Size           *int               `json:"size,omitempty"`
	Sort           SortSlice          `json:"sort,omitempty"`
	TrackScores    *bool              `json:"track_scores,omitempty"`
	Source         *SourceFilter      `json:"_source,omitempty"`
	Fields         []FieldRequestSpec `json:"fields,omitempty"`
	DocvalueFields []FieldRequestSpec `json:"docvalue_fields,omitempty"`
	ScriptFields   map[string]any     `json:"script_fields,omitempty"`
	Highlight      *HighlightSpec     `json:"highlight,omitempty"`
}

func (ih *InnerHitsSpec) EffectiveFieldSpecs() []FieldRequestSpec {
	if ih == nil || (len(ih.Fields) == 0 && len(ih.DocvalueFields) == 0) {
		return nil
	}
	out := make([]FieldRequestSpec, 0, len(ih.Fields)+len(ih.DocvalueFields))
	out = append(out, ih.Fields...)
	out = append(out, ih.DocvalueFields...)
	return out
}

func (ih *InnerHitsSpec) EffectiveSize() int {
	if ih == nil || ih.Size == nil {
		return 3
	}
	if *ih.Size < 0 {
		return 0
	}
	return *ih.Size
}

type CollapseInnerHits []InnerHitsSpec

func (ci *CollapseInnerHits) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		*ci = nil
		return nil
	}
	if trimmed[0] == '[' {
		var list []InnerHitsSpec
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return err
		}
		*ci = list
		return nil
	}
	var single InnerHitsSpec
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return err
	}
	*ci = []InnerHitsSpec{single}
	return nil
}

type CollapseSpec struct {
	Field     string            `json:"field"`
	InnerHits CollapseInnerHits `json:"inner_hits,omitempty"`
}

// RescoreQuerySpec models the `query` object inside a `rescore` block.
type RescoreQuerySpec struct {
	RescoreQuery       *Query   `json:"rescore_query,omitempty"`
	QueryWeight        *float64 `json:"query_weight,omitempty"`
	RescoreQueryWeight *float64 `json:"rescore_query_weight,omitempty"`
	ScoreMode          string   `json:"score_mode,omitempty"`
}

// RescoreSpec models a single `rescore` entry in a search request.
type RescoreSpec struct {
	WindowSize *int              `json:"window_size,omitempty"`
	Query      *RescoreQuerySpec `json:"query,omitempty"`
}

// RescoreSlice unmarshals either a single `RescoreSpec` object `{...}` or an array `[{...}]`.
type RescoreSlice []RescoreSpec

func (rs *RescoreSlice) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*rs = nil
		return nil
	}
	if trimmed[0] == '[' {
		var list []RescoreSpec
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return err
		}
		*rs = list
		return nil
	}
	var single RescoreSpec
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return err
	}
	*rs = []RescoreSpec{single}
	return nil
}

// HighlightFieldSpec models per-field highlight configuration inside `highlight.fields.<field>`.
type HighlightFieldSpec struct {
	PreTags           []string `json:"pre_tags,omitempty"`
	PostTags          []string `json:"post_tags,omitempty"`
	TagSchema         string   `json:"tag_schema,omitempty"`
	Encoder           string   `json:"encoder,omitempty"`
	HighlightQuery    *Query   `json:"highlight_query,omitempty"`
	RequireFieldMatch *bool    `json:"require_field_match,omitempty"`
	MatchedFields     []string `json:"matched_fields,omitempty"`
	FragmentSize      *int     `json:"fragment_size,omitempty"`
	NumberOfFragments *int     `json:"number_of_fragments,omitempty"`
	NoMatchSize       *int     `json:"no_match_size,omitempty"`
	Type              string   `json:"type,omitempty"`
}

type HighlightSpec struct {
	PreTags           []string       `json:"pre_tags,omitempty"`
	PostTags          []string       `json:"post_tags,omitempty"`
	TagSchema         string         `json:"tag_schema,omitempty"`
	Encoder           string         `json:"encoder,omitempty"`
	HighlightQuery    *Query         `json:"highlight_query,omitempty"`
	RequireFieldMatch *bool          `json:"require_field_match,omitempty"`
	FragmentSize      *int           `json:"fragment_size,omitempty"`
	NumberOfFragments *int           `json:"number_of_fragments,omitempty"`
	NoMatchSize       *int           `json:"no_match_size,omitempty"`
	Type              string         `json:"type,omitempty"`
	Fields            map[string]any `json:"fields,omitempty"`
}

// FieldSpec decodes the per-field highlight configuration for field into HighlightFieldSpec.
func (h *HighlightSpec) FieldSpec(field string) HighlightFieldSpec {
	if h == nil || h.Fields == nil {
		return HighlightFieldSpec{}
	}
	raw, ok := h.Fields[field]
	if !ok || raw == nil {
		return HighlightFieldSpec{}
	}
	var spec HighlightFieldSpec
	if b, err := json.Marshal(raw); err == nil {
		_ = json.Unmarshal(b, &spec)
	}
	return spec
}

// EffectiveAggs returns whichever of `aggs` or `aggregations` was populated.
func (r *SearchRequest) EffectiveAggs() map[string]AggSpec {
	if len(r.Aggs) > 0 {
		return r.Aggs
	}
	return r.Aggregations
}

// Query represents a polymorphic node in the Elasticsearch Query DSL AST.
type Query struct {
	MatchAll          map[string]any           `json:"match_all,omitempty"`
	MatchNone         map[string]any           `json:"match_none,omitempty"`
	Bool              *BoolQuery               `json:"bool,omitempty"`
	DisMax            *DisMaxQuery             `json:"dis_max,omitempty"`
	Boosting          *BoostingQuery           `json:"boosting,omitempty"`
	Term              map[string]TermEntry     `json:"term,omitempty"`
	Terms             *TermsQuery              `json:"terms,omitempty"`
	TermsSet          map[string]TermsSetEntry `json:"terms_set,omitempty"`
	Ids               *IdsQuery                `json:"ids,omitempty"`
	Range             map[string]RangeCond     `json:"range,omitempty"`
	Exists            *ExistsQuery             `json:"exists,omitempty"`
	Prefix            map[string]PrefixEntry   `json:"prefix,omitempty"`
	Wildcard          map[string]WildcardEntry `json:"wildcard,omitempty"`
	Regexp            map[string]RegexpEntry   `json:"regexp,omitempty"`
	Fuzzy             map[string]FuzzyEntry    `json:"fuzzy,omitempty"`
	Match             map[string]MatchEntry    `json:"match,omitempty"`
	MatchPhrase       map[string]PhraseEntry   `json:"match_phrase,omitempty"`
	MatchPhrasePrefix map[string]PhraseEntry   `json:"match_phrase_prefix,omitempty"`
	MatchBoolPrefix   map[string]PhraseEntry   `json:"match_bool_prefix,omitempty"`
	MultiMatch        *MultiMatchQuery         `json:"multi_match,omitempty"`
	CombinedFields    *CombinedFieldsQuery     `json:"combined_fields,omitempty"`
	QueryString       *QueryStringQuery        `json:"query_string,omitempty"`
	SimpleQueryString *QueryStringQuery        `json:"simple_query_string,omitempty"`
	Nested            *NestedQuery             `json:"nested,omitempty"`
	ConstantScore     *ConstantScoreQuery      `json:"constant_score,omitempty"`
	FunctionScore     *FunctionScoreQuery      `json:"function_score,omitempty"`
	ScriptScore       *ScriptScoreQuery        `json:"script_score,omitempty"`
	Script            *ScriptQuery             `json:"script,omitempty"`
	KNN               *KNNQuery                `json:"knn,omitempty"`
}

var knownQueryClauses = map[string]bool{
	"match_all":           true,
	"match_none":          true,
	"bool":                true,
	"dis_max":             true,
	"boosting":            true,
	"term":                true,
	"terms":               true,
	"terms_set":           true,
	"ids":                 true,
	"range":               true,
	"exists":              true,
	"prefix":              true,
	"wildcard":            true,
	"regexp":              true,
	"fuzzy":               true,
	"match":               true,
	"match_phrase":        true,
	"match_phrase_prefix": true,
	"match_bool_prefix":   true,
	"multi_match":         true,
	"combined_fields":     true,
	"query_string":        true,
	"simple_query_string": true,
	"nested":              true,
	"constant_score":      true,
	"function_score":      true,
	"script_score":        true,
	"script":              true,
	"knn":                 true,
}

func (q *Query) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	for k := range raw {
		if !knownQueryClauses[k] {
			return fmt.Errorf("parsing_exception: unknown query clause [%s]", k)
		}
	}
	type queryAlias Query
	var alias queryAlias
	if err := json.Unmarshal(trimmed, &alias); err != nil {
		return err
	}
	*q = Query(alias)
	return nil
}

// DisMaxQuery represents an ES `dis_max` query (`queries`, `tie_breaker`, `boost`).
type DisMaxQuery struct {
	Queries    QuerySlice `json:"queries,omitempty"`
	TieBreaker float64    `json:"tie_breaker,omitempty"`
	Boost      *float64   `json:"boost,omitempty"`
}

// BoostingQuery represents an ES `boosting` query (`positive`, `negative`, `negative_boost`).
type BoostingQuery struct {
	Positive      Query    `json:"positive"`
	Negative      Query    `json:"negative"`
	NegativeBoost float64  `json:"negative_boost,omitempty"`
	Boost         *float64 `json:"boost,omitempty"`
}

// TermsLookupSpec models an external document lookup in a `terms` query (`{"index": "...", "id": "...", "path": "..."}`).
type TermsLookupSpec struct {
	Index   string `json:"index"`
	ID      string `json:"id"`
	Path    string `json:"path"`
	Routing string `json:"routing,omitempty"`
}

// TermsQuery handles `"terms": {"field": ["a", "b"], "boost": 1.0}` as well as
// Terms Lookup queries `"terms": {"field": {"index": "users", "id": "u1", "path": "roles"}}`.
type TermsQuery struct {
	Fields   map[string][]any
	Lookups  map[string]TermsLookupSpec
	Boost    float64
	HasBoost bool
}

func (tq TermsQuery) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(tq.Fields)+len(tq.Lookups)+1)
	for k, v := range tq.Fields {
		m[k] = v
	}
	for k, v := range tq.Lookups {
		m[k] = v
	}
	if tq.HasBoost || (tq.Boost != 0 && tq.Boost != 1.0) {
		m["boost"] = tq.Boost
	}
	return json.Marshal(m)
}

func (tq *TermsQuery) UnmarshalJSON(data []byte) error {
	tq.Boost = 1.0
	tq.HasBoost = false
	tq.Fields = make(map[string][]any)
	tq.Lookups = make(map[string]TermsLookupSpec)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		if k == "boost" {
			_ = json.Unmarshal(v, &tq.Boost)
			tq.HasBoost = true
			continue
		}
		if k == "_name" {
			continue
		}
		trimmed := bytes.TrimSpace(v)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var arr []any
			if err := json.Unmarshal(trimmed, &arr); err != nil {
				return fmt.Errorf("parsing_exception: [terms] invalid terms array for [%s]: %w", k, err)
			}
			tq.Fields[k] = arr
			continue
		}
		if len(trimmed) > 0 && trimmed[0] == '{' {
			var lookup TermsLookupSpec
			if err := json.Unmarshal(trimmed, &lookup); err != nil {
				return fmt.Errorf("parsing_exception: [terms] invalid lookup spec for [%s]: %w", k, err)
			}
			if lookup.Index == "" || lookup.ID == "" || lookup.Path == "" {
				return fmt.Errorf("parsing_exception: [terms] lookup for [%s] requires index, id, and path", k)
			}
			tq.Lookups[k] = lookup
			continue
		}
		return fmt.Errorf("parsing_exception: [terms] query does not support scalar value for [%s]", k)
	}
	return nil
}

// TermsSetEntry models a `terms_set` query on a field.
type TermsSetEntry struct {
	Terms                    []any          `json:"terms"`
	MinimumShouldMatchField  string         `json:"minimum_should_match_field,omitempty"`
	MinimumShouldMatchScript map[string]any `json:"minimum_should_match_script,omitempty"`
	Boost                    *float64       `json:"boost,omitempty"`
}

// FuzzyEntry models a `fuzzy` query (`{"fuzzy": {"name": "alice"}}` or `{"fuzzy": {"name": {"value": "alice", "fuzziness": "AUTO"}}}`).
type FuzzyEntry struct {
	Value     any     `json:"value"`
	Fuzziness any     `json:"fuzziness,omitempty"`
	Boost     float64 `json:"boost,omitempty"`
}

func (f *FuzzyEntry) UnmarshalJSON(data []byte) error {
	f.Boost = 1.0
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Value     any      `json:"value"`
			Fuzziness any      `json:"fuzziness"`
			Boost     *float64 `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		f.Value = full.Value
		f.Fuzziness = full.Fuzziness
		if full.Boost != nil {
			f.Boost = *full.Boost
		}
		return nil
	}
	return json.Unmarshal(trimmed, &f.Value)
}

// CombinedFieldsQuery models an ES 8+ `combined_fields` query.
type CombinedFieldsQuery struct {
	Query              any      `json:"query"`
	Fields             []string `json:"fields,omitempty"`
	Operator           string   `json:"operator,omitempty"`
	MinimumShouldMatch any      `json:"minimum_should_match,omitempty"`
	ZeroTermsQuery     string   `json:"zero_terms_query,omitempty"`
	Boost              *float64 `json:"boost,omitempty"`
}

// ScriptScoreQuery models an ES `script_score` query (`{"script_score": {"query": {...}, "script": {...}}}`).
type ScriptScoreQuery struct {
	Query    *Query         `json:"query,omitempty"`
	Script   map[string]any `json:"script,omitempty"`
	MinScore *float64       `json:"min_score,omitempty"`
	Boost    *float64       `json:"boost,omitempty"`
}

// ScriptQuery models an ES `script` filter query (`{"script": {"script": {...}}}`).
type ScriptQuery struct {
	Script any      `json:"script,omitempty"`
	Boost  *float64 `json:"boost,omitempty"`
}

func (sq *ScriptQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		sq.Script = s
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return err
	}
	if b, ok := m["boost"].(float64); ok {
		sq.Boost = &b
	}
	if inner, ok := m["script"]; ok {
		sq.Script = inner
	} else {
		sq.Script = m
	}
	return nil
}

// BoolQuery represents an ES `bool` compound query (`must`, `filter`, `should`, `must_not`).
type BoolQuery struct {
	Must               QuerySlice `json:"must,omitempty"`
	Filter             QuerySlice `json:"filter,omitempty"`
	Should             QuerySlice `json:"should,omitempty"`
	MustNot            QuerySlice `json:"must_not,omitempty"`
	MinimumShouldMatch any        `json:"minimum_should_match,omitempty"`
	Boost              *float64   `json:"boost,omitempty"`
}

// QuerySlice unmarshals either a single Query object `{...}` or an array of Query objects `[{...}]`.
type QuerySlice []Query

func (qs *QuerySlice) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*qs = nil
		return nil
	}
	if trimmed[0] == '[' {
		var list []Query
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return err
		}
		*qs = list
		return nil
	}
	var single Query
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return err
	}
	*qs = []Query{single}
	return nil
}

// TermEntry supports both `"term": {"field": "val"}` and `"term": {"field": {"value": "val", "boost": 2.0}}`.
type TermEntry struct {
	Value           any     `json:"value"`
	Boost           float64 `json:"boost,omitempty"`
	CaseInsensitive bool    `json:"case_insensitive,omitempty"`
}

func (t *TermEntry) UnmarshalJSON(data []byte) error {
	t.Boost = 1.0
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Value           any      `json:"value"`
			Boost           *float64 `json:"boost"`
			CaseInsensitive bool     `json:"case_insensitive"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		t.Value = full.Value
		if full.Boost != nil {
			t.Boost = *full.Boost
		}
		t.CaseInsensitive = full.CaseInsensitive
		return nil
	}
	return json.Unmarshal(trimmed, &t.Value)
}

type IdsQuery struct {
	Values []string `json:"values"`
}

type ExistsQuery struct {
	Field string `json:"field"`
}

// RangeCond supports both standard `gt`/`gte`/`lt`/`lte` bounds and Java `RangeQueryBuilder`
// `from`/`to`/`include_lower`/`include_upper` bounds.
type RangeCond struct {
	GT           any      `json:"gt,omitempty"`
	GTE          any      `json:"gte,omitempty"`
	LT           any      `json:"lt,omitempty"`
	LTE          any      `json:"lte,omitempty"`
	From         any      `json:"from,omitempty"`
	To           any      `json:"to,omitempty"`
	IncludeLower *bool    `json:"include_lower,omitempty"`
	IncludeUpper *bool    `json:"include_upper,omitempty"`
	Boost        *float64 `json:"boost,omitempty"`
	Format       string   `json:"format,omitempty"`
	TimeZone     string   `json:"time_zone,omitempty"`
}

// NormalizedBounds returns the effective (gt, gte, lt, lte) bounds after normalizing `from`/`to`.
func (rc RangeCond) NormalizedBounds() (gt, gte, lt, lte any) {
	gt, gte, lt, lte = rc.GT, rc.GTE, rc.LT, rc.LTE
	if rc.From != nil && gt == nil && gte == nil {
		incLower := rc.IncludeLower == nil || *rc.IncludeLower
		if incLower {
			gte = rc.From
		} else {
			gt = rc.From
		}
	}
	if rc.To != nil && lt == nil && lte == nil {
		incUpper := rc.IncludeUpper == nil || *rc.IncludeUpper
		if incUpper {
			lte = rc.To
		} else {
			lt = rc.To
		}
	}
	return gt, gte, lt, lte
}

type PrefixEntry struct {
	Value           string  `json:"value"`
	CaseInsensitive bool    `json:"case_insensitive,omitempty"`
	Boost           float64 `json:"boost,omitempty"`
}

func (p *PrefixEntry) UnmarshalJSON(data []byte) error {
	p.Boost = 1.0
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Value           string   `json:"value"`
			CaseInsensitive bool     `json:"case_insensitive"`
			Boost           *float64 `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		p.Value = full.Value
		p.CaseInsensitive = full.CaseInsensitive
		if full.Boost != nil {
			p.Boost = *full.Boost
		}
		return nil
	}
	return json.Unmarshal(trimmed, &p.Value)
}

type WildcardEntry struct {
	Value           string  `json:"value"`
	CaseInsensitive bool    `json:"case_insensitive,omitempty"`
	Boost           float64 `json:"boost,omitempty"`
}

func (w *WildcardEntry) UnmarshalJSON(data []byte) error {
	w.Boost = 1.0
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Value           string   `json:"value"`
			Wildcard        string   `json:"wildcard"`
			CaseInsensitive bool     `json:"case_insensitive"`
			Boost           *float64 `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		if full.Value != "" {
			w.Value = full.Value
		} else {
			w.Value = full.Wildcard
		}
		w.CaseInsensitive = full.CaseInsensitive
		if full.Boost != nil {
			w.Boost = *full.Boost
		}
		return nil
	}
	return json.Unmarshal(trimmed, &w.Value)
}

type RegexpEntry struct {
	Value           string  `json:"value"`
	CaseInsensitive bool    `json:"case_insensitive,omitempty"`
	Boost           float64 `json:"boost,omitempty"`
}

func (r *RegexpEntry) UnmarshalJSON(data []byte) error {
	r.Boost = 1.0
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Value           string   `json:"value"`
			CaseInsensitive bool     `json:"case_insensitive"`
			Boost           *float64 `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		r.Value = full.Value
		r.CaseInsensitive = full.CaseInsensitive
		if full.Boost != nil {
			r.Boost = *full.Boost
		}
		return nil
	}
	return json.Unmarshal(trimmed, &r.Value)
}

type MatchEntry struct {
	Query              any     `json:"query"`
	Operator           string  `json:"operator,omitempty"`
	Boost              float64 `json:"boost,omitempty"`
	ZeroTermsQuery     string  `json:"zero_terms_query,omitempty"`
	MinimumShouldMatch any     `json:"minimum_should_match,omitempty"`
}

func (m *MatchEntry) UnmarshalJSON(data []byte) error {
	m.Boost = 1.0
	m.Operator = "or"
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Query              any      `json:"query"`
			Operator           string   `json:"operator"`
			Boost              *float64 `json:"boost"`
			ZeroTermsQuery     string   `json:"zero_terms_query"`
			MinimumShouldMatch any      `json:"minimum_should_match"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		m.Query = full.Query
		if full.Operator != "" {
			m.Operator = strings.ToLower(full.Operator)
		}
		if full.Boost != nil {
			m.Boost = *full.Boost
		}
		m.ZeroTermsQuery = full.ZeroTermsQuery
		m.MinimumShouldMatch = full.MinimumShouldMatch
		return nil
	}
	return json.Unmarshal(trimmed, &m.Query)
}

type PhraseEntry struct {
	Query              string  `json:"query"`
	Slop               int     `json:"slop,omitempty"`
	Operator           string  `json:"operator,omitempty"`
	MinimumShouldMatch any     `json:"minimum_should_match,omitempty"`
	Boost              float64 `json:"boost,omitempty"`
}

func (p *PhraseEntry) UnmarshalJSON(data []byte) error {
	p.Boost = 1.0
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Query              any      `json:"query"`
			Slop               int      `json:"slop"`
			Operator           string   `json:"operator"`
			MinimumShouldMatch any      `json:"minimum_should_match"`
			Boost              *float64 `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		if full.Query != nil {
			p.Query = fmt.Sprintf("%v", full.Query)
		}
		p.Slop = full.Slop
		p.Operator = strings.ToLower(full.Operator)
		p.MinimumShouldMatch = full.MinimumShouldMatch
		if full.Boost != nil {
			p.Boost = *full.Boost
		}
		return nil
	}
	var raw any
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw != nil {
		p.Query = fmt.Sprintf("%v", raw)
	}
	return nil
}

type MultiMatchQuery struct {
	Query              any      `json:"query"`
	Fields             []string `json:"fields,omitempty"`
	Type               string   `json:"type,omitempty"`
	Operator           string   `json:"operator,omitempty"`
	Slop               int      `json:"slop,omitempty"`
	MinimumShouldMatch any      `json:"minimum_should_match,omitempty"`
	TieBreaker         *float64 `json:"tie_breaker,omitempty"`
	ZeroTermsQuery     string   `json:"zero_terms_query,omitempty"`
	Boost              *float64 `json:"boost,omitempty"`
}

type QueryStringQuery struct {
	Query              string   `json:"query"`
	DefaultField       string   `json:"default_field,omitempty"`
	Fields             []string `json:"fields,omitempty"`
	DefaultOperator    string   `json:"default_operator,omitempty"`
	MinimumShouldMatch any      `json:"minimum_should_match,omitempty"`
	Boost              *float64 `json:"boost,omitempty"`
}

type NestedQuery struct {
	Path           string         `json:"path"`
	Query          Query          `json:"query"`
	ScoreMode      string         `json:"score_mode,omitempty"`
	IgnoreUnmapped bool           `json:"ignore_unmapped,omitempty"`
	InnerHits      *InnerHitsSpec `json:"inner_hits,omitempty"`
}

type ConstantScoreQuery struct {
	Filter Query    `json:"filter"`
	Boost  *float64 `json:"boost,omitempty"`
}

type FunctionScoreQuery struct {
	Query            *Query                   `json:"query,omitempty"`
	Functions        []ScoreFunctionSpec      `json:"functions,omitempty"`
	ScoreMode        string                   `json:"score_mode,omitempty"`
	BoostMode        string                   `json:"boost_mode,omitempty"`
	MaxBoost         *float64                 `json:"max_boost,omitempty"`
	MinScore         *float64                 `json:"min_score,omitempty"`
	Boost            *float64                 `json:"boost,omitempty"`
	Weight           *float64                 `json:"weight,omitempty"`
	FieldValueFactor *FieldValueFactorSpec    `json:"field_value_factor,omitempty"`
	ScriptScore      *ScriptScoreFunctionSpec `json:"script_score,omitempty"`
}

type ScoreFunctionSpec struct {
	Filter           *Query                   `json:"filter,omitempty"`
	Weight           *float64                 `json:"weight,omitempty"`
	FieldValueFactor *FieldValueFactorSpec    `json:"field_value_factor,omitempty"`
	ScriptScore      *ScriptScoreFunctionSpec `json:"script_score,omitempty"`
}

type ScriptScoreFunctionSpec struct {
	Script any `json:"script,omitempty"`
}

type FieldValueFactorSpec struct {
	Field    string   `json:"field"`
	Factor   *float64 `json:"factor,omitempty"`
	Modifier string   `json:"modifier,omitempty"`
	Missing  *float64 `json:"missing,omitempty"`
}

// AggSpec represents an Elasticsearch aggregation definition.
type AggSpec struct {
	Terms                 *TermsAggSpec             `json:"terms,omitempty"`
	SignificantTerms      *TermsAggSpec             `json:"significant_terms,omitempty"`
	SignificantText       *TermsAggSpec             `json:"significant_text,omitempty"`
	DateHistogram         *DateHistogramAggSpec     `json:"date_histogram,omitempty"`
	Histogram             *HistogramAggSpec         `json:"histogram,omitempty"`
	Range                 *RangeAggSpec             `json:"range,omitempty"`
	DateRange             *RangeAggSpec             `json:"date_range,omitempty"`
	IPRange               *RangeAggSpec             `json:"ip_range,omitempty"`
	Composite             *CompositeAggSpec         `json:"composite,omitempty"`
	Filter                *Query                    `json:"filter,omitempty"`
	Filters               *FiltersAggSpec           `json:"filters,omitempty"`
	Missing               *ExistsQuery              `json:"missing,omitempty"`
	Nested                *NestedAggSpec            `json:"nested,omitempty"`
	ReverseNested         map[string]any            `json:"reverse_nested,omitempty"`
	Global                map[string]any            `json:"global,omitempty"`
	Sampler               *SamplerAggSpec           `json:"sampler,omitempty"`
	DiversifiedSampler    *SamplerAggSpec           `json:"diversified_sampler,omitempty"`
	Cardinality           *MetricAggSpec            `json:"cardinality,omitempty"`
	ValueCount            *MetricAggSpec            `json:"value_count,omitempty"`
	Avg                   *MetricAggSpec            `json:"avg,omitempty"`
	Sum                   *MetricAggSpec            `json:"sum,omitempty"`
	Min                   *MetricAggSpec            `json:"min,omitempty"`
	Max                   *MetricAggSpec            `json:"max,omitempty"`
	Stats                 *MetricAggSpec            `json:"stats,omitempty"`
	ExtendedStats         *MetricAggSpec            `json:"extended_stats,omitempty"`
	StringStats           *MetricAggSpec            `json:"string_stats,omitempty"`
	Boxplot               *MetricAggSpec            `json:"boxplot,omitempty"`
	Percentiles           *PercentilesAggSpec       `json:"percentiles,omitempty"`
	PercentileRanks       *PercentileRanksAggSpec   `json:"percentile_ranks,omitempty"`
	TopHits               *TopHitsAggSpec           `json:"top_hits,omitempty"`
	TopMetrics            *TopMetricsAggSpec        `json:"top_metrics,omitempty"`
	Rate                  *RateAggSpec              `json:"rate,omitempty"`
	BucketSort            *BucketSortAggSpec        `json:"bucket_sort,omitempty"`
	CumulativeSum         *PipelineAggSpec          `json:"cumulative_sum,omitempty"`
	CumulativeCardinality *PipelineAggSpec          `json:"cumulative_cardinality,omitempty"`
	Derivative            *PipelineAggSpec          `json:"derivative,omitempty"`
	MovingAvg             *MovingAvgAggSpec         `json:"moving_avg,omitempty"`
	MovingFn              *MovingAvgAggSpec         `json:"moving_fn,omitempty"`
	SerialDiff            *SerialDiffAggSpec        `json:"serial_diff,omitempty"`
	Normalize             *NormalizeAggSpec         `json:"normalize,omitempty"`
	AvgBucket             *PipelineAggSpec          `json:"avg_bucket,omitempty"`
	SumBucket             *PipelineAggSpec          `json:"sum_bucket,omitempty"`
	MinBucket             *PipelineAggSpec          `json:"min_bucket,omitempty"`
	MaxBucket             *PipelineAggSpec          `json:"max_bucket,omitempty"`
	StatsBucket           *PipelineAggSpec          `json:"stats_bucket,omitempty"`
	ExtendedStatsBucket   *PipelineAggSpec          `json:"extended_stats_bucket,omitempty"`
	PercentilesBucket     *PercentilesBucketAggSpec `json:"percentiles_bucket,omitempty"`
	BucketSelector        *BucketSelectorAggSpec    `json:"bucket_selector,omitempty"`
	BucketScript          *BucketSelectorAggSpec    `json:"bucket_script,omitempty"`
	Aggs                  map[string]AggSpec        `json:"aggs,omitempty"`
	Aggregations          map[string]AggSpec        `json:"aggregations,omitempty"`
}

// EffectiveRange returns the range specification for `range`, `date_range`, or `ip_range`.
func (a *AggSpec) EffectiveRange() *RangeAggSpec {
	if a.Range != nil {
		return a.Range
	}
	if a.DateRange != nil {
		return a.DateRange
	}
	return a.IPRange
}

// EffectiveStats returns the metric specification for `stats` or `extended_stats`.
func (a *AggSpec) EffectiveStats() *MetricAggSpec {
	if a.Stats != nil {
		return a.Stats
	}
	return a.ExtendedStats
}

// EffectiveSampler returns the sampler specification for `sampler` or `diversified_sampler`.
func (a *AggSpec) EffectiveSampler() *SamplerAggSpec {
	if a.Sampler != nil {
		return a.Sampler
	}
	return a.DiversifiedSampler
}

// EffectiveMovingAvg returns the moving average specification for `moving_avg` or `moving_fn`.
func (a *AggSpec) EffectiveMovingAvg() *MovingAvgAggSpec {
	if a.MovingAvg != nil {
		return a.MovingAvg
	}
	return a.MovingFn
}

// EffectiveCumulative returns the pipeline specification for `cumulative_sum` or `cumulative_cardinality`.
func (a *AggSpec) EffectiveCumulative() *PipelineAggSpec {
	if a.CumulativeSum != nil {
		return a.CumulativeSum
	}
	return a.CumulativeCardinality
}

// SamplerAggSpec models a `sampler` or `diversified_sampler` aggregation.
type SamplerAggSpec struct {
	ShardSize int    `json:"shard_size,omitempty"`
	Field     string `json:"field,omitempty"`
}

// PercentileRanksAggSpec models a `percentile_ranks` metric aggregation.
type PercentileRanksAggSpec struct {
	Field   string    `json:"field"`
	Values  []float64 `json:"values"`
	Keyed   *bool     `json:"keyed,omitempty"`
	Missing any       `json:"missing,omitempty"`
	Script  any       `json:"script,omitempty"`
}

// TopMetricsValSpec models a single metric field in `top_metrics`.
type TopMetricsValSpec struct {
	Field string `json:"field"`
}

// TopMetricsAggSpec models a `top_metrics` aggregation.
type TopMetricsAggSpec struct {
	Metrics []TopMetricsValSpec `json:"-"`
	Size    *int                `json:"size,omitempty"`
	Sort    SortSlice           `json:"sort,omitempty"`
}

func (tm *TopMetricsAggSpec) UnmarshalJSON(data []byte) error {
	var raw struct {
		Metrics json.RawMessage `json:"metrics"`
		Metric  json.RawMessage `json:"metric"`
		Size    *int            `json:"size"`
		Sort    SortSlice       `json:"sort"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	tm.Size = raw.Size
	tm.Sort = raw.Sort
	mRaw := bytes.TrimSpace(raw.Metrics)
	if len(mRaw) == 0 {
		mRaw = bytes.TrimSpace(raw.Metric)
	}
	if len(mRaw) > 0 {
		switch mRaw[0] {
		case '[':
			if err := json.Unmarshal(mRaw, &tm.Metrics); err != nil {
				return err
			}
		case '{':
			var single TopMetricsValSpec
			if err := json.Unmarshal(mRaw, &single); err != nil {
				return err
			}
			tm.Metrics = []TopMetricsValSpec{single}
		}
	}
	return nil
}

func (tm TopMetricsAggSpec) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, 3)
	if len(tm.Metrics) > 0 {
		out["metrics"] = tm.Metrics
	}
	if tm.Size != nil {
		out["size"] = *tm.Size
	}
	if len(tm.Sort) > 0 {
		out["sort"] = tm.Sort
	}
	return json.Marshal(out)
}

func (tm *TopMetricsAggSpec) EffectiveSize() int {
	if tm == nil || tm.Size == nil || *tm.Size <= 0 {
		return 1
	}
	if *tm.Size > 100 {
		return 100
	}
	return *tm.Size
}

func (tm *TopMetricsAggSpec) EffectiveMetricFields() []string {
	if tm == nil {
		return nil
	}
	out := make([]string, 0, len(tm.Metrics))
	for _, m := range tm.Metrics {
		if m.Field != "" {
			out = append(out, m.Field)
		}
	}
	return out
}

// RateAggSpec models a `rate` metric aggregation.
type RateAggSpec struct {
	Field  string `json:"field,omitempty"`
	Script any    `json:"script,omitempty"`
	Unit   string `json:"unit,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

// MovingAvgAggSpec models a `moving_avg` or `moving_fn` pipeline aggregation.
type MovingAvgAggSpec struct {
	BucketsPath any    `json:"buckets_path,omitempty"`
	Window      int    `json:"window,omitempty"`
	Model       string `json:"model,omitempty"`
	Script      any    `json:"script,omitempty"`
	GapPolicy   string `json:"gap_policy,omitempty"`
	Format      string `json:"format,omitempty"`
	Shift       *int   `json:"shift,omitempty"`
}

func (m *MovingAvgAggSpec) EffectivePath() string {
	if m == nil || m.BucketsPath == nil {
		return ""
	}
	if s, ok := m.BucketsPath.(string); ok {
		return strings.TrimSpace(s)
	}
	return fmt.Sprintf("%v", m.BucketsPath)
}

func (m *MovingAvgAggSpec) EffectiveWindow() int {
	if m == nil || m.Window <= 0 {
		return 5
	}
	return m.Window
}

// SerialDiffAggSpec models a `serial_diff` pipeline aggregation.
type SerialDiffAggSpec struct {
	BucketsPath any    `json:"buckets_path,omitempty"`
	Lag         int    `json:"lag,omitempty"`
	GapPolicy   string `json:"gap_policy,omitempty"`
	Format      string `json:"format,omitempty"`
}

func (s *SerialDiffAggSpec) EffectivePath() string {
	if s == nil || s.BucketsPath == nil {
		return ""
	}
	if str, ok := s.BucketsPath.(string); ok {
		return strings.TrimSpace(str)
	}
	return fmt.Sprintf("%v", s.BucketsPath)
}

func (s *SerialDiffAggSpec) EffectiveLag() int {
	if s == nil || s.Lag <= 0 {
		return 1
	}
	return s.Lag
}

// NormalizeAggSpec models a `normalize` pipeline aggregation.
type NormalizeAggSpec struct {
	BucketsPath any    `json:"buckets_path,omitempty"`
	Method      string `json:"method,omitempty"`
	Format      string `json:"format,omitempty"`
	GapPolicy   string `json:"gap_policy,omitempty"`
}

func (n *NormalizeAggSpec) EffectivePath() string {
	if n == nil || n.BucketsPath == nil {
		return ""
	}
	if str, ok := n.BucketsPath.(string); ok {
		return strings.TrimSpace(str)
	}
	return fmt.Sprintf("%v", n.BucketsPath)
}

// PercentilesBucketAggSpec models a `percentiles_bucket` sibling pipeline aggregation.
type PercentilesBucketAggSpec struct {
	BucketsPath any       `json:"buckets_path,omitempty"`
	Percents    []float64 `json:"percents,omitempty"`
	Keyed       *bool     `json:"keyed,omitempty"`
	GapPolicy   string    `json:"gap_policy,omitempty"`
	Format      string    `json:"format,omitempty"`
}

func (p *PercentilesBucketAggSpec) EffectivePath() string {
	if p == nil || p.BucketsPath == nil {
		return ""
	}
	if s, ok := p.BucketsPath.(string); ok {
		return strings.TrimSpace(s)
	}
	return fmt.Sprintf("%v", p.BucketsPath)
}

func (p *PercentilesBucketAggSpec) EffectivePercents() []float64 {
	if p != nil && len(p.Percents) > 0 {
		return p.Percents
	}
	return []float64{1.0, 5.0, 25.0, 50.0, 75.0, 95.0, 99.0}
}

// EffectiveTerms returns the terms specification for `terms`, `significant_terms`, or `significant_text`.
func (a *AggSpec) EffectiveTerms() *TermsAggSpec {
	if a.Terms != nil {
		return a.Terms
	}
	if a.SignificantTerms != nil {
		return a.SignificantTerms
	}
	return a.SignificantText
}

// IsSignificantTerms reports whether this aggregation is `significant_terms` or `significant_text`.
func (a *AggSpec) IsSignificantTerms() bool {
	return a.SignificantTerms != nil || a.SignificantText != nil
}

// BucketSortAggSpec models a `bucket_sort` pipeline aggregation (`sort`, `from`, `size`, `gap_policy`).
type BucketSortAggSpec struct {
	Sort      SortSlice `json:"sort,omitempty"`
	From      *int      `json:"from,omitempty"`
	Size      *int      `json:"size,omitempty"`
	GapPolicy string    `json:"gap_policy,omitempty"`
}

// PipelineAggSpec models a single-path pipeline aggregation (`cumulative_sum`, `derivative`, `avg_bucket`, `sum_bucket`, `min_bucket`, `max_bucket`, `stats_bucket`, `extended_stats_bucket`).
type PipelineAggSpec struct {
	BucketsPath any      `json:"buckets_path,omitempty"`
	GapPolicy   string   `json:"gap_policy,omitempty"`
	Format      string   `json:"format,omitempty"`
	Sigma       *float64 `json:"sigma,omitempty"`
}

func (p *PipelineAggSpec) EffectiveSigma() float64 {
	if p != nil && p.Sigma != nil && *p.Sigma >= 0 {
		return *p.Sigma
	}
	return 2.0
}

// EffectivePath returns the primary buckets_path string.
func (p *PipelineAggSpec) EffectivePath() string {
	if p == nil || p.BucketsPath == nil {
		return ""
	}
	if s, ok := p.BucketsPath.(string); ok {
		return strings.TrimSpace(s)
	}
	return fmt.Sprintf("%v", p.BucketsPath)
}

// BucketSelectorAggSpec models a `bucket_selector` or `bucket_script` pipeline aggregation.
type BucketSelectorAggSpec struct {
	BucketsPath map[string]string `json:"buckets_path,omitempty"`
	Script      any               `json:"script,omitempty"`
	GapPolicy   string            `json:"gap_policy,omitempty"`
	Format      string            `json:"format,omitempty"`
}

type CompositeAggSpec struct {
	Size    int                  `json:"size,omitempty"`
	Sources []map[string]AggSpec `json:"sources,omitempty"`
	After   map[string]any       `json:"after,omitempty"`
}

type FiltersAggSpec struct {
	Filters          map[string]Query `json:"-"`
	AnonymousFilters []Query          `json:"-"`
	IsAnonymous      bool             `json:"-"`
	OtherBucket      bool             `json:"other_bucket,omitempty"`
	OtherBucketKey   string           `json:"other_bucket_key,omitempty"`
	Keyed            *bool            `json:"keyed,omitempty"`
}

func (f *FiltersAggSpec) UnmarshalJSON(data []byte) error {
	var raw struct {
		Filters        json.RawMessage `json:"filters"`
		OtherBucket    bool            `json:"other_bucket"`
		OtherBucketKey string          `json:"other_bucket_key"`
		Keyed          *bool           `json:"keyed"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	f.OtherBucket = raw.OtherBucket || raw.OtherBucketKey != ""
	f.OtherBucketKey = raw.OtherBucketKey
	f.Keyed = raw.Keyed
	trimmed := bytes.TrimSpace(raw.Filters)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var list []Query
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return err
		}
		f.IsAnonymous = true
		f.AnonymousFilters = list
		f.Filters = make(map[string]Query, len(list))
		for i, q := range list {
			f.Filters[strconv.Itoa(i)] = q
		}
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var m map[string]Query
		if err := json.Unmarshal(trimmed, &m); err != nil {
			return err
		}
		f.Filters = m
	}
	return nil
}

func (f FiltersAggSpec) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, 4)
	if f.IsAnonymous {
		out["filters"] = f.AnonymousFilters
	} else if f.Filters != nil {
		out["filters"] = f.Filters
	}
	if f.OtherBucket {
		out["other_bucket"] = true
	}
	if f.OtherBucketKey != "" {
		out["other_bucket_key"] = f.OtherBucketKey
	}
	if f.Keyed != nil {
		out["keyed"] = *f.Keyed
	}
	return json.Marshal(out)
}

func (f *FiltersAggSpec) EffectiveOtherBucketKey() string {
	if f != nil && f.OtherBucketKey != "" {
		return f.OtherBucketKey
	}
	return "_other_"
}

func (f *FiltersAggSpec) EffectiveKeyed() bool {
	if f == nil {
		return true
	}
	if f.Keyed != nil {
		return *f.Keyed
	}
	return !f.IsAnonymous
}

type PercentilesAggSpec struct {
	Field    string    `json:"field"`
	Percents []float64 `json:"percents,omitempty"`
	Keyed    *bool     `json:"keyed,omitempty"`
	Missing  any       `json:"missing,omitempty"`
	Script   any       `json:"script,omitempty"`
}

func (p *PercentilesAggSpec) EffectivePercents() []float64 {
	if len(p.Percents) > 0 {
		return p.Percents
	}
	return []float64{1.0, 5.0, 25.0, 50.0, 75.0, 95.0, 99.0}
}

type TopHitsAggSpec struct {
	From           int                `json:"from,omitempty"`
	Size           *int               `json:"size,omitempty"`
	Sort           SortSlice          `json:"sort,omitempty"`
	TrackScores    *bool              `json:"track_scores,omitempty"`
	Source         *SourceFilter      `json:"_source,omitempty"`
	Fields         []FieldRequestSpec `json:"fields,omitempty"`
	DocvalueFields []FieldRequestSpec `json:"docvalue_fields,omitempty"`
	ScriptFields   map[string]any     `json:"script_fields,omitempty"`
	Highlight      *HighlightSpec     `json:"highlight,omitempty"`
}

func (th *TopHitsAggSpec) EffectiveFieldSpecs() []FieldRequestSpec {
	if th == nil || (len(th.Fields) == 0 && len(th.DocvalueFields) == 0) {
		return nil
	}
	out := make([]FieldRequestSpec, 0, len(th.Fields)+len(th.DocvalueFields))
	out = append(out, th.Fields...)
	out = append(out, th.DocvalueFields...)
	return out
}

func (th *TopHitsAggSpec) EffectiveFrom() int {
	if th == nil || th.From <= 0 {
		return 0
	}
	if th.From > 100 {
		return 100
	}
	return th.From
}

func (th *TopHitsAggSpec) EffectiveSize() int {
	if th == nil || th.Size == nil {
		return 3
	}
	if *th.Size <= 0 {
		return 0
	}
	if *th.Size > 100 {
		return 100
	}
	return *th.Size
}

func (th *TopHitsAggSpec) EffectiveFetchLimit() int {
	limit := th.EffectiveFrom() + th.EffectiveSize()
	if limit > 200 {
		return 200
	}
	return limit
}

func (a *AggSpec) SubAggs() map[string]AggSpec {
	if len(a.Aggs) > 0 {
		return a.Aggs
	}
	return a.Aggregations
}

type TermsAggSpec struct {
	Field         string `json:"field"`
	Script        any    `json:"script,omitempty"`
	Size          int    `json:"size,omitempty"`
	Missing       any    `json:"missing,omitempty"`
	MissingBucket bool   `json:"missing_bucket,omitempty"`
	MissingOrder  string `json:"missing_order,omitempty"`
	Order         any    `json:"order,omitempty"`
	MinDocCount   *int   `json:"min_doc_count,omitempty"`
	Include       any    `json:"include,omitempty"`
	Exclude       any    `json:"exclude,omitempty"`
}

type HistogramBoundsSpec struct {
	Min any `json:"min,omitempty"`
	Max any `json:"max,omitempty"`
}

type DateHistogramAggSpec struct {
	Field            string               `json:"field"`
	Script           any                  `json:"script,omitempty"`
	CalendarInterval string               `json:"calendar_interval,omitempty"`
	FixedInterval    string               `json:"fixed_interval,omitempty"`
	Interval         string               `json:"interval,omitempty"`
	TimeZone         string               `json:"time_zone,omitempty"`
	Offset           string               `json:"offset,omitempty"`
	Format           string               `json:"format,omitempty"`
	Missing          any                  `json:"missing,omitempty"`
	MissingBucket    bool                 `json:"missing_bucket,omitempty"`
	MissingOrder     string               `json:"missing_order,omitempty"`
	Order            any                  `json:"order,omitempty"`
	MinDocCount      *int                 `json:"min_doc_count,omitempty"`
	ExtendedBounds   *HistogramBoundsSpec `json:"extended_bounds,omitempty"`
	HardBounds       *HistogramBoundsSpec `json:"hard_bounds,omitempty"`
	Keyed            bool                 `json:"keyed,omitempty"`
}

// EffectiveOffsetMs parses `offset` (e.g., "+6h", "-30m") into milliseconds.
func (d *DateHistogramAggSpec) EffectiveOffsetMs() int64 {
	if d == nil {
		return 0
	}
	return parseSignedDurationMs(strings.TrimSpace(d.Offset))
}

// EffectiveTimeZoneOffsetMs parses `time_zone` (e.g., "+08:00", "-05:00", "UTC", or IANA zone) into milliseconds.
func (d *DateHistogramAggSpec) EffectiveTimeZoneOffsetMs() int64 {
	if d == nil {
		return 0
	}
	return ParseTimeZoneOffsetMs(strings.TrimSpace(d.TimeZone))
}

// ParseTimeZoneOffsetMs parses an ES time_zone string ("+08:00", "-05:00", "Z", "UTC", or IANA tz) into milliseconds.
func ParseTimeZoneOffsetMs(tz string) int64 {
	if tz == "" || tz == "Z" || strings.EqualFold(tz, "UTC") {
		return 0
	}
	if strings.HasPrefix(tz, "+") || strings.HasPrefix(tz, "-") {
		sign := int64(1)
		if tz[0] == '-' {
			sign = -1
		}
		rest := tz[1:]
		if parts := strings.Split(rest, ":"); len(parts) == 2 {
			h, err1 := strconv.ParseInt(parts[0], 10, 64)
			m, err2 := strconv.ParseInt(parts[1], 10, 64)
			if err1 == nil && err2 == nil && h >= 0 && h <= 24 && m >= 0 && m < 60 {
				return sign * (h*3600 + m*60) * 1000
			}
		} else if len(rest) == 4 {
			h, err1 := strconv.ParseInt(rest[:2], 10, 64)
			m, err2 := strconv.ParseInt(rest[2:], 10, 64)
			if err1 == nil && err2 == nil && h >= 0 && h <= 24 && m >= 0 && m < 60 {
				return sign * (h*3600 + m*60) * 1000
			}
		} else if h, err := strconv.ParseInt(rest, 10, 64); err == nil && h >= 0 && h <= 24 {
			return sign * h * 3600 * 1000
		}
	}
	if loc, err := time.LoadLocation(tz); err == nil {
		_, offsetSec := time.Date(2024, 1, 15, 0, 0, 0, 0, loc).Zone()
		return int64(offsetSec) * 1000
	}
	return 0
}

func parseSignedDurationMs(raw string) int64 {
	if raw == "" {
		return 0
	}
	sign := int64(1)
	if strings.HasPrefix(raw, "+") {
		raw = raw[1:]
	} else if strings.HasPrefix(raw, "-") {
		sign = -1
		raw = raw[1:]
	}
	const maxDurMs = int64(36500) * 86400 * 1000
	if strings.HasSuffix(raw, "ms") {
		if n, err := strconv.ParseInt(strings.TrimSuffix(raw, "ms"), 10, 64); err == nil && n >= 0 && n <= maxDurMs {
			return sign * n
		}
	}
	if len(raw) >= 2 {
		unit := raw[len(raw)-1]
		if n, err := strconv.ParseInt(raw[:len(raw)-1], 10, 64); err == nil && n >= 0 && n <= 36500*86400 {
			switch unit {
			case 's':
				return sign * n * 1000
			case 'm':
				return sign * n * 60 * 1000
			case 'h':
				return sign * n * 3600 * 1000
			case 'd':
				return sign * n * 86400 * 1000
			case 'w':
				return sign * n * 7 * 86400 * 1000
			}
		}
	}
	return 0
}

// EffectiveIntervalMs parses calendar_interval, fixed_interval, or interval into milliseconds.
func (d *DateHistogramAggSpec) EffectiveIntervalMs() int64 {
	raw := strings.TrimSpace(d.FixedInterval)
	if raw == "" {
		raw = strings.TrimSpace(d.CalendarInterval)
	}
	if raw == "" {
		raw = strings.TrimSpace(d.Interval)
	}
	switch raw {
	case "second", "1s":
		return 1000
	case "minute", "1m":
		return 60 * 1000
	case "hour", "1h":
		return 3600 * 1000
	case "day", "1d":
		return 86400 * 1000
	case "week", "1w":
		return 7 * 86400 * 1000
	case "month", "1M":
		return 30 * 86400 * 1000
	case "quarter", "1q":
		return 90 * 86400 * 1000
	case "year", "1y":
		return 365 * 86400 * 1000
	}
	if strings.HasSuffix(raw, "ms") {
		if n, err := strconv.ParseInt(strings.TrimSuffix(raw, "ms"), 10, 64); err == nil && n > 0 {
			return n
		}
	}
	if len(raw) >= 2 {
		unit := raw[len(raw)-1]
		if n, err := strconv.ParseInt(raw[:len(raw)-1], 10, 64); err == nil && n > 0 {
			switch unit {
			case 's':
				return n * 1000
			case 'm':
				return n * 60 * 1000
			case 'h':
				return n * 3600 * 1000
			case 'd':
				return n * 86400 * 1000
			case 'w':
				return n * 7 * 86400 * 1000
			case 'M':
				return n * 30 * 86400 * 1000
			case 'y':
				return n * 365 * 86400 * 1000
			}
		}
	}
	return 86400 * 1000
}

type HistogramAggSpec struct {
	Field          string               `json:"field"`
	Script         any                  `json:"script,omitempty"`
	Interval       float64              `json:"interval"`
	Offset         float64              `json:"offset,omitempty"`
	Missing        any                  `json:"missing,omitempty"`
	MissingBucket  bool                 `json:"missing_bucket,omitempty"`
	MissingOrder   string               `json:"missing_order,omitempty"`
	Order          any                  `json:"order,omitempty"`
	MinDocCount    *int                 `json:"min_doc_count,omitempty"`
	ExtendedBounds *HistogramBoundsSpec `json:"extended_bounds,omitempty"`
	HardBounds     *HistogramBoundsSpec `json:"hard_bounds,omitempty"`
	Keyed          bool                 `json:"keyed,omitempty"`
}

type RangeAggSpec struct {
	Field    string           `json:"field"`
	Script   any              `json:"script,omitempty"`
	Missing  any              `json:"missing,omitempty"`
	Format   string           `json:"format,omitempty"`
	TimeZone string           `json:"time_zone,omitempty"`
	Ranges   []RangeAggBucket `json:"ranges"`
	Keyed    bool             `json:"keyed,omitempty"`
}

type RangeAggBucket struct {
	Key  string `json:"key,omitempty"`
	From any    `json:"from,omitempty"`
	To   any    `json:"to,omitempty"`
	Mask string `json:"mask,omitempty"`
}

func (b RangeAggBucket) EffectiveKey() string {
	if b.Key != "" {
		return b.Key
	}
	if b.Mask != "" {
		return b.Mask
	}
	fromStr := "*"
	if b.From != nil {
		fromStr = fmt.Sprintf("%v", b.From)
	}
	toStr := "*"
	if b.To != nil {
		toStr = fmt.Sprintf("%v", b.To)
	}
	return fromStr + "-" + toStr
}

type NestedAggSpec struct {
	Path string `json:"path"`
}

type MetricAggSpec struct {
	Field   string   `json:"field"`
	Sigma   *float64 `json:"sigma,omitempty"`
	Missing any      `json:"missing,omitempty"`
	Script  any      `json:"script,omitempty"`
}

func (m *MetricAggSpec) EffectiveSigma() float64 {
	if m != nil && m.Sigma != nil && *m.Sigma >= 0 {
		return *m.Sigma
	}
	return 2.0
}

type NestedSortSpec struct {
	Path   string `json:"path,omitempty"`
	Filter *Query `json:"filter,omitempty"`
}

type SortEntry = SortFieldSpec

type SortFieldSpec struct {
	Field   string
	Order   string
	Mode    string
	Missing string
	Script  any
	Type    string
	Nested  *NestedSortSpec
}

type SortSpec struct {
	Entry SortFieldSpec
}

func (s SortSpec) MarshalJSON() ([]byte, error) {
	order := s.Entry.Order
	if order == "" {
		order = "asc"
	}
	if s.Entry.Mode != "" || s.Entry.Missing != "" {
		inner := map[string]any{"order": order}
		if s.Entry.Mode != "" {
			inner["mode"] = s.Entry.Mode
		}
		if s.Entry.Missing != "" {
			inner["missing"] = s.Entry.Missing
		}
		return json.Marshal(map[string]any{s.Entry.Field: inner})
	}
	return json.Marshal(map[string]string{s.Entry.Field: order})
}

// SortSlice accepts either a single sort specification (`"_doc"` / `{"updatedAt": "desc"}`) or an array.
type SortSlice []SortSpec

func (ss *SortSlice) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*ss = nil
		return nil
	}
	if trimmed[0] == '[' {
		var list []SortSpec
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return err
		}
		*ss = list
		return nil
	}
	var single SortSpec
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return err
	}
	*ss = []SortSpec{single}
	return nil
}

func (s *SortSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var fieldName string
		if err := json.Unmarshal(trimmed, &fieldName); err != nil {
			return err
		}
		order := "asc"
		if fieldName == "_score" {
			order = "desc"
		}
		s.Entry = SortFieldSpec{Field: fieldName, Order: order}
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return err
	}
	if rawVal, ok := m["_script"]; ok {
		order := "asc"
		var obj struct {
			Order   string `json:"order"`
			Script  any    `json:"script"`
			Type    string `json:"type"`
			Missing any    `json:"missing"`
		}
		_ = json.Unmarshal(rawVal, &obj)
		if obj.Order != "" {
			order = strings.ToLower(obj.Order)
		}
		missing := ""
		if obj.Missing != nil {
			if fv, ok := obj.Missing.(float64); ok && fv == math.Trunc(fv) && !math.IsInf(fv, 0) && !math.IsNaN(fv) {
				missing = strconv.FormatInt(int64(fv), 10)
			} else {
				missing = fmt.Sprintf("%v", obj.Missing)
			}
		}
		s.Entry = SortFieldSpec{Field: "_script", Order: order, Script: obj.Script, Type: obj.Type, Missing: missing}
		return nil
	}
	if rawVal, ok := m["_geo_distance"]; ok {
		order := "asc"
		var obj struct {
			Order   string `json:"order"`
			Mode    string `json:"mode"`
			Missing any    `json:"missing"`
		}
		_ = json.Unmarshal(rawVal, &obj)
		if obj.Order != "" {
			order = strings.ToLower(obj.Order)
		} else if ordRaw, hasOrd := m["order"]; hasOrd {
			var ordStr string
			if json.Unmarshal(ordRaw, &ordStr) == nil && ordStr != "" {
				order = strings.ToLower(ordStr)
			}
		}
		var geoMap map[string]any
		_ = json.Unmarshal(rawVal, &geoMap)
		missing := ""
		if obj.Missing != nil {
			missing = fmt.Sprintf("%v", obj.Missing)
		}
		s.Entry = SortFieldSpec{Field: "_geo_distance", Order: order, Mode: strings.ToLower(obj.Mode), Missing: missing, Script: geoMap}
		return nil
	}

	reservedOpts := map[string]bool{
		"order": true, "mode": true, "missing": true, "unmapped_type": true,
		"numeric_type": true, "format": true, "nested": true, "nested_path": true,
		"nested_filter": true, "unit": true, "distance_type": true,
		"validation_method": true, "ignore_unmapped": true,
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if len(m) > 1 && reservedOpts[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		field := keys[0]
		rawVal := m[field]
		order := "asc"
		if field == "_score" {
			order = "desc"
		}
		missing := ""
		mode := ""
		var nestedSpec *NestedSortSpec
		if rawNested, hasNested := m["nested"]; hasNested {
			var ns NestedSortSpec
			if json.Unmarshal(rawNested, &ns) == nil && (ns.Path != "" || ns.Filter != nil) {
				nestedSpec = &ns
			}
		}
		if nestedSpec == nil {
			var np string
			var nf *Query
			if rawNP, ok := m["nested_path"]; ok {
				_ = json.Unmarshal(rawNP, &np)
			}
			if rawNF, ok := m["nested_filter"]; ok {
				var q Query
				if json.Unmarshal(rawNF, &q) == nil {
					nf = &q
				}
			}
			if np != "" || nf != nil {
				nestedSpec = &NestedSortSpec{Path: np, Filter: nf}
			}
		}
		valTrimmed := bytes.TrimSpace(rawVal)
		if len(valTrimmed) > 0 && valTrimmed[0] == '"' {
			_ = json.Unmarshal(valTrimmed, &order)
		} else if len(valTrimmed) > 0 && valTrimmed[0] == '{' {
			var obj struct {
				Order        string          `json:"order"`
				Mode         string          `json:"mode"`
				Missing      any             `json:"missing"`
				UnmappedType string          `json:"unmapped_type"`
				NumericType  string          `json:"numeric_type"`
				Nested       *NestedSortSpec `json:"nested"`
				NestedPath   string          `json:"nested_path"`
				NestedFilter *Query          `json:"nested_filter"`
			}
			_ = json.Unmarshal(valTrimmed, &obj)
			if obj.Order != "" {
				order = obj.Order
			}
			if obj.Mode != "" {
				mode = obj.Mode
			}
			if obj.Missing != nil {
				if fv, ok := obj.Missing.(float64); ok && fv == math.Trunc(fv) && !math.IsInf(fv, 0) && !math.IsNaN(fv) {
					missing = strconv.FormatInt(int64(fv), 10)
				} else {
					missing = fmt.Sprintf("%v", obj.Missing)
				}
			}
			if obj.Nested != nil && (obj.Nested.Path != "" || obj.Nested.Filter != nil) {
				nestedSpec = obj.Nested
			} else if obj.NestedPath != "" || obj.NestedFilter != nil {
				nestedSpec = &NestedSortSpec{Path: obj.NestedPath, Filter: obj.NestedFilter}
			}
			sortType := obj.UnmappedType
			if sortType == "" {
				sortType = obj.NumericType
			}
			s.Entry = SortFieldSpec{Field: field, Order: strings.ToLower(order), Mode: strings.ToLower(mode), Missing: missing, Type: strings.ToLower(sortType), Nested: nestedSpec}
			return nil
		}
		s.Entry = SortFieldSpec{Field: field, Order: strings.ToLower(order), Mode: strings.ToLower(mode), Missing: missing, Nested: nestedSpec}
	}
	return nil
}

type SourceFilter struct {
	Fetch    bool     `json:"-"`
	Disabled bool     `json:"-"`
	Includes []string `json:"includes,omitempty"`
	Excludes []string `json:"excludes,omitempty"`
}

func (sf SourceFilter) MarshalJSON() ([]byte, error) {
	if sf.Disabled {
		return []byte("false"), nil
	}
	if len(sf.Includes) == 0 && len(sf.Excludes) == 0 {
		return []byte("true"), nil
	}
	return json.Marshal(struct {
		Includes []string `json:"includes,omitempty"`
		Excludes []string `json:"excludes,omitempty"`
	}{
		Includes: sf.Includes,
		Excludes: sf.Excludes,
	})
}

func (sf *SourceFilter) UnmarshalJSON(data []byte) error {
	sf.Fetch = true
	sf.Disabled = false
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("false")) {
		sf.Fetch = false
		sf.Disabled = true
		return nil
	}
	if bytes.Equal(trimmed, []byte("true")) {
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var single string
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return err
		}
		sf.Includes = []string{single}
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &sf.Includes)
	}
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var obj struct {
			Includes []string `json:"includes"`
			Excludes []string `json:"excludes"`
			Include  []string `json:"include"`
			Exclude  []string `json:"exclude"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return err
		}
		sf.Includes = append(obj.Includes, obj.Include...)
		sf.Excludes = append(obj.Excludes, obj.Exclude...)
	}
	return nil
}

// IndexCreateRequest models `PUT /<index>` with `settings`, `mappings`, and `aliases`.
type IndexCreateRequest struct {
	Settings map[string]any            `json:"settings,omitempty"`
	Mappings *MappingSpec              `json:"mappings,omitempty"`
	Aliases  map[string]map[string]any `json:"aliases,omitempty"`
}

// IndexTemplateRequest models `PUT /_index_template/<name>` and `PUT /_template/<name>`.
type IndexTemplateRequest struct {
	IndexPatterns []string            `json:"index_patterns,omitempty"`
	Patterns      []string            `json:"patterns,omitempty"`
	Template      *IndexCreateRequest `json:"template,omitempty"`
	Mappings      *MappingSpec        `json:"mappings,omitempty"`
	Settings      map[string]any      `json:"settings,omitempty"`
}

func (t *IndexTemplateRequest) EffectivePatterns() []string {
	if len(t.IndexPatterns) > 0 {
		return t.IndexPatterns
	}
	return t.Patterns
}

func (t *IndexTemplateRequest) EffectiveMappings() *MappingSpec {
	if t.Template != nil && t.Template.Mappings != nil {
		return t.Template.Mappings
	}
	return t.Mappings
}

// MappingSpec models an Elasticsearch `_mapping` payload.
type MappingSpec struct {
	Dynamic    any                      `json:"dynamic,omitempty"`
	Properties map[string]FieldProperty `json:"properties,omitempty"`
}

type FieldProperty struct {
	Type           string                   `json:"type,omitempty"`
	Path           string                   `json:"path,omitempty"`
	Analyzer       string                   `json:"analyzer,omitempty"`
	SearchAnalyzer string                   `json:"search_analyzer,omitempty"`
	Normalizer     string                   `json:"normalizer,omitempty"`
	Format         string                   `json:"format,omitempty"`
	Dims           int                      `json:"dims,omitempty"`
	Dimension      int                      `json:"dimension,omitempty"`
	Similarity     string                   `json:"similarity,omitempty"`
	MultiValued    bool                     `json:"multi_valued,omitempty"`
	UpgradedArray  bool                     `json:"upgraded_array,omitempty"`
	CopyTo         any                      `json:"copy_to,omitempty"`
	NullValue      any                      `json:"null_value,omitempty"`
	IgnoreAbove    int                      `json:"ignore_above,omitempty"`
	Fields         map[string]FieldProperty `json:"fields,omitempty"`
	Properties     map[string]FieldProperty `json:"properties,omitempty"`
}

func (fp FieldProperty) EffectiveDims() int {
	if fp.Dims > 0 {
		return fp.Dims
	}
	return fp.Dimension
}

// CopyToSlice normalizes FieldProperty.CopyTo (string, []string, or []any) into a string slice.
func (fp FieldProperty) CopyToSlice() []string {
	switch v := fp.CopyTo.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []string:
		return v
	case []any:
		var out []string
		for _, elem := range v {
			if s, ok := elem.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// BulkOperation represents a single parsed action from an Elasticsearch `/_bulk` NDJSON stream.
type BulkOperation struct {
	Action          string          // "index", "create", "update", "delete"
	Index           string          // Target index name
	ID              string          // Document _id
	Pipeline        string          // Optional per-item ingest pipeline override
	Routing         string          // Optional per-item routing value
	IfSeqNo         *int64          // Optional optimistic concurrency _seq_no
	IfPrimaryTerm   *int64          // Optional optimistic concurrency _primary_term
	Version         *int64          // Optional external/internal version check
	VersionType     string          // Optional version_type ("internal", "external", "external_gte")
	RetryOnConflict *int            // Optional retry_on_conflict count
	Source          json.RawMessage // Verbatim raw JSON line for `_source` (or update payload)
	ParseErr        string          // Per-item validation or JSON error (isolated to this bulk item)
}

type bulkActionMeta struct {
	Index           string `json:"_index"`
	ID              string `json:"_id"`
	Pipeline        string `json:"pipeline,omitempty"`
	Routing         string `json:"routing,omitempty"`
	IfSeqNo         *int64 `json:"if_seq_no,omitempty"`
	IfPrimaryTerm   *int64 `json:"if_primary_term,omitempty"`
	Version         *int64 `json:"version,omitempty"`
	VersionType     string `json:"version_type,omitempty"`
	RetryOnConflict *int   `json:"retry_on_conflict,omitempty"`
}

type bulkActionLine struct {
	Index  *bulkActionMeta `json:"index,omitempty"`
	Create *bulkActionMeta `json:"create,omitempty"`
	Update *bulkActionMeta `json:"update,omitempty"`
	Delete *bulkActionMeta `json:"delete,omitempty"`
}

// ParseBulkNDJSON parses an Elasticsearch `/_bulk` two-line NDJSON stream while preserving
// the exact byte slice of each document line as `json.RawMessage` for zero-copy `_source` fidelity.
func ParseBulkNDJSON(r io.Reader, defaultIndex string) ([]BulkOperation, error) {
	scanner := bufio.NewScanner(r)
	// Allow up to 32 MiB per single NDJSON line for large OpenMetadata/DataHub entity documents.
	scanner.Buffer(make([]byte, 64*1024), 32*1024*1024)

	var ops []BulkOperation
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var actionLine bulkActionLine
		if err := json.Unmarshal(line, &actionLine); err != nil {
			return nil, fmt.Errorf("invalid bulk action metadata line: %w", err)
		}
		var op BulkOperation
		var meta *bulkActionMeta
		switch {
		case actionLine.Index != nil:
			op.Action = "index"
			meta = actionLine.Index
		case actionLine.Create != nil:
			op.Action = "create"
			meta = actionLine.Create
		case actionLine.Update != nil:
			op.Action = "update"
			meta = actionLine.Update
		case actionLine.Delete != nil:
			op.Action = "delete"
			meta = actionLine.Delete
		default:
			return nil, fmt.Errorf("invalid bulk action metadata line: missing index/create/update/delete action")
		}
		op.Index = meta.Index
		if op.Index == "" {
			op.Index = defaultIndex
		}
		op.ID = meta.ID
		op.Pipeline = meta.Pipeline
		op.Routing = meta.Routing
		op.IfSeqNo = meta.IfSeqNo
		op.IfPrimaryTerm = meta.IfPrimaryTerm
		op.Version = meta.Version
		op.VersionType = meta.VersionType
		op.RetryOnConflict = meta.RetryOnConflict
		if op.ID == "" {
			if op.Action == "index" || op.Action == "create" {
				op.ID = NextAutoID()
			} else {
				op.ParseErr = fmt.Sprintf("missing _id for bulk %s action", op.Action)
			}
		}
		if op.Action != "delete" {
			if !scanner.Scan() {
				return nil, fmt.Errorf("unexpected EOF waiting for bulk source line after %q action", op.Action)
			}
			srcLine := bytes.TrimSpace(scanner.Bytes())
			if !json.Valid(srcLine) {
				op.ParseErr = "failed to parse bulk document source: invalid JSON"
			}
			rawCopy := make([]byte, len(srcLine))
			copy(rawCopy, srcLine)
			op.Source = json.RawMessage(rawCopy)
		}
		ops = append(ops, op)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ops, nil
}
