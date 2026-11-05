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
	Query            *Query                   `json:"query,omitempty"`
	AliasFilter      *Query                   `json:"-"`
	Routing          string                   `json:"-"`
	KNN              KNNSlice                 `json:"knn,omitempty"`
	PostFilter       *Query                   `json:"post_filter,omitempty"`
	From             *int                     `json:"from,omitempty"`
	Size             *int                     `json:"size,omitempty"`
	TerminateAfter   *int                     `json:"terminate_after,omitempty"`
	MinScore         *float64                 `json:"min_score,omitempty"`
	Aggs             map[string]AggSpec       `json:"aggs,omitempty"`
	Aggregations     map[string]AggSpec       `json:"aggregations,omitempty"`
	Sort             SortSlice                `json:"sort,omitempty"`
	SearchAfter      []any                    `json:"search_after,omitempty"`
	Source           *SourceFilter            `json:"_source,omitempty"`
	TrackTotalHits   any                      `json:"track_total_hits,omitempty"`
	TrackScores      *bool                    `json:"track_scores,omitempty"`
	Version          bool                     `json:"version,omitempty"`
	SeqNoPrimaryTerm bool                     `json:"seq_no_primary_term,omitempty"`
	Explain          bool                     `json:"explain,omitempty"`
	IndicesBoost     map[string]float64       `json:"-"`
	Highlight        *HighlightSpec           `json:"highlight,omitempty"`
	Collapse         *CollapseSpec            `json:"collapse,omitempty"`
	Rescore          RescoreSlice             `json:"rescore,omitempty"`
	PIT              *PITSpec                 `json:"pit,omitempty"`
	Fields           []FieldRequestSpec       `json:"fields,omitempty"`
	DocvalueFields   []FieldRequestSpec       `json:"docvalue_fields,omitempty"`
	StoredFields     any                      `json:"stored_fields,omitempty"`
	ScriptFields     map[string]any           `json:"script_fields,omitempty"`
	RuntimeMappings  map[string]FieldProperty `json:"runtime_mappings,omitempty"`
	Suggest          map[string]SuggestSpec   `json:"suggest,omitempty"`
}

var knownSearchRequestKeys = map[string]bool{
	"query":               true,
	"knn":                 true,
	"post_filter":         true,
	"from":                true,
	"size":                true,
	"terminate_after":     true,
	"min_score":           true,
	"aggs":                true,
	"aggregations":        true,
	"sort":                true,
	"search_after":        true,
	"_source":             true,
	"track_total_hits":    true,
	"track_scores":        true,
	"version":             true,
	"seq_no_primary_term": true,
	"explain":             true,
	"indices_boost":       true,
	"highlight":           true,
	"collapse":            true,
	"rescore":             true,
	"pit":                 true,
	"point_in_time":       true,
	"fields":              true,
	"docvalue_fields":     true,
	"stored_fields":       true,
	"script_fields":       true,
	"runtime_mappings":    true,
	"suggest":             true,
	"timeout":             true,
	"slice":               true,
	"profile":             true,
	"stats":               true,
	"ext":                 true,
	"sub_searches":        true,
	"rank":                true,
}

func parseIndicesBoost(raw json.RawMessage) (map[string]float64, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	parseEntryMap := func(m map[string]json.RawMessage, out map[string]float64) error {
		if len(m) == 0 {
			return fmt.Errorf("parsing_exception: [indices_boost] entry cannot be empty")
		}
		for idx, rawVal := range m {
			idxTrim := strings.TrimSpace(idx)
			if idxTrim == "" {
				return fmt.Errorf("parsing_exception: [indices_boost] index name cannot be empty")
			}
			b, err := parseOptionalNonNegativeBoost(rawVal)
			if err != nil || b == nil {
				return fmt.Errorf("parsing_exception: [indices_boost] boost for [%s] must be a non-negative number", idx)
			}
			out[idxTrim] = *b
		}
		return nil
	}
	if trimmed[0] == '[' {
		var list []json.RawMessage
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, fmt.Errorf("parsing_exception: [indices_boost] invalid array: %w", err)
		}
		out := make(map[string]float64, len(list))
		for _, elem := range list {
			et := bytes.TrimSpace(elem)
			if len(et) == 0 || et[0] != '{' {
				return nil, fmt.Errorf("parsing_exception: [indices_boost] array element must be an object")
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(et, &m); err != nil {
				return nil, fmt.Errorf("parsing_exception: [indices_boost] invalid element: %w", err)
			}
			if err := parseEntryMap(m, out); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	if trimmed[0] == '{' {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &m); err != nil {
			return nil, fmt.Errorf("parsing_exception: [indices_boost] invalid object: %w", err)
		}
		out := make(map[string]float64, len(m))
		if len(m) > 0 {
			if err := parseEntryMap(m, out); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("parsing_exception: [indices_boost] must be an object or array of objects")
}

func (r *SearchRequest) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		if !knownSearchRequestKeys[k] {
			return fmt.Errorf("parsing_exception: Unknown key for a START_OBJECT in [%s]", k)
		}
	}
	type plain SearchRequest
	var raw struct {
		plain
		TrackScores      any             `json:"track_scores"`
		Version          any             `json:"version"`
		SeqNoPrimaryTerm any             `json:"seq_no_primary_term"`
		Explain          any             `json:"explain"`
		IndicesBoost     json.RawMessage `json:"indices_boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*r = SearchRequest(raw.plain)
	if raw.TrackScores != nil {
		ts, err := parseFlexibleBool(raw.TrackScores)
		if err != nil {
			return fmt.Errorf("parsing_exception: [track_scores] %w", err)
		}
		r.TrackScores = &ts
	}
	if raw.Version != nil {
		v, err := parseFlexibleBool(raw.Version)
		if err != nil {
			return fmt.Errorf("parsing_exception: [version] %w", err)
		}
		r.Version = v
	}
	if raw.SeqNoPrimaryTerm != nil {
		sn, err := parseFlexibleBool(raw.SeqNoPrimaryTerm)
		if err != nil {
			return fmt.Errorf("parsing_exception: [seq_no_primary_term] %w", err)
		}
		r.SeqNoPrimaryTerm = sn
	}
	if raw.Explain != nil {
		ex, err := parseFlexibleBool(raw.Explain)
		if err != nil {
			return fmt.Errorf("parsing_exception: [explain] %w", err)
		}
		r.Explain = ex
	}
	if len(raw.IndicesBoost) > 0 {
		ib, err := parseIndicesBoost(raw.IndicesBoost)
		if err != nil {
			return err
		}
		r.IndicesBoost = ib
	}
	return nil
}

// SuggestSpec models an entry in a search request `suggest` map (`term`, `phrase`, `completion`, or global `text`).
type SuggestSpec struct {
	Text       string                 `json:"text,omitempty"`
	Prefix     string                 `json:"prefix,omitempty"`
	Regex      string                 `json:"regex,omitempty"`
	Term       *TermSuggestSpec       `json:"term,omitempty"`
	Phrase     *PhraseSuggestSpec     `json:"phrase,omitempty"`
	Completion *CompletionSuggestSpec `json:"completion,omitempty"`
}

func (ss *SuggestSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		ss.Text = s
		return nil
	}
	type alias SuggestSpec
	var a alias
	if err := json.Unmarshal(trimmed, &a); err != nil {
		return err
	}
	*ss = SuggestSpec(a)
	return nil
}

// TermSuggestSpec models a `term` suggester configuration.
type TermSuggestSpec struct {
	Field          string `json:"field"`
	Size           int    `json:"size,omitempty"`
	SuggestMode    string `json:"suggest_mode,omitempty"`
	MaxEdits       int    `json:"max_edits,omitempty"`
	PrefixLength   int    `json:"prefix_length,omitempty"`
	MinWordLength  int    `json:"min_word_length,omitempty"`
	MinDocFreq     int    `json:"min_doc_freq,omitempty"`
	StringDistance string `json:"string_distance,omitempty"`
	Sort           string `json:"sort,omitempty"`
}

// PhraseSuggestSpec models a `phrase` suggester configuration.
type PhraseSuggestSpec struct {
	Field     string               `json:"field"`
	Size      int                  `json:"size,omitempty"`
	MaxErrors float64              `json:"max_errors,omitempty"`
	Highlight *PhraseHighlightSpec `json:"highlight,omitempty"`
}

// PhraseHighlightSpec models `highlight` options on a `phrase` suggester.
type PhraseHighlightSpec struct {
	PreTag  string `json:"pre_tag,omitempty"`
	PostTag string `json:"post_tag,omitempty"`
}

// CompletionSuggestSpec models a `completion` suggester configuration.
type CompletionSuggestSpec struct {
	Field          string         `json:"field"`
	Size           int            `json:"size,omitempty"`
	SkipDuplicates bool           `json:"skip_duplicates,omitempty"`
	Fuzzy          map[string]any `json:"fuzzy,omitempty"`
	Regex          map[string]any `json:"regex,omitempty"`
}

// StoredFieldsSlice normalizes a `stored_fields` value (string or []string) into a slice of field names.
func StoredFieldsSlice(raw any) []string {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case string:
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, el := range v {
			if s, ok := el.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

// HasStoredFieldsNone reports whether `stored_fields` is set to `_none_`.
func (r *SearchRequest) HasStoredFieldsNone() bool {
	if r == nil {
		return false
	}
	for _, f := range StoredFieldsSlice(r.StoredFields) {
		if f == "_none_" {
			return true
		}
	}
	return false
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

// EffectiveFieldSpecs returns the combined `fields`, `docvalue_fields`, and `stored_fields` specifications.
func (r *SearchRequest) EffectiveFieldSpecs() []FieldRequestSpec {
	if r == nil {
		return nil
	}
	sfList := StoredFieldsSlice(r.StoredFields)
	if len(r.Fields) == 0 && len(r.DocvalueFields) == 0 && len(sfList) == 0 {
		return nil
	}
	out := make([]FieldRequestSpec, 0, len(r.Fields)+len(r.DocvalueFields)+len(sfList))
	out = append(out, r.Fields...)
	out = append(out, r.DocvalueFields...)
	for _, sf := range sfList {
		if sf != "_none_" {
			out = append(out, FieldRequestSpec{Field: sf})
		}
	}
	return out
}

// ShouldTrackTotalHits returns false only when TrackTotalHits is explicitly disabled (`false` or `<= 0`).
func (r *SearchRequest) ShouldTrackTotalHits() bool {
	if r == nil || r.TrackTotalHits == nil {
		return true
	}
	switch v := r.TrackTotalHits.(type) {
	case bool:
		return v
	case string:
		trimmed := strings.TrimSpace(v)
		if strings.EqualFold(trimmed, "false") {
			return false
		}
		if strings.EqualFold(trimmed, "true") {
			return true
		}
		if f, err := strconv.ParseFloat(trimmed, 64); err == nil {
			return f > 0
		}
		return true
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
		if f, err := v.Float64(); err == nil {
			return f > 0
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
	Name          string     `json:"_name,omitempty"`
}

func (kq *KNNQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	_, hasField := rawMap["field"]
	_, hasQV := rawMap["query_vector"]
	_, hasVec := rawMap["vector"]
	_, hasK := rawMap["k"]
	_, hasNC := rawMap["num_candidates"]
	_, hasSim := rawMap["similarity"]
	_, hasFilter := rawMap["filter"]
	if hasField || hasQV || hasVec || hasK || hasNC || hasSim || hasFilter {
		for k := range rawMap {
			switch k {
			case "field", "query_vector", "vector", "k", "num_candidates", "filter", "similarity", "boost", "_name":
			default:
				return fmt.Errorf("parsing_exception: [knn] unknown field [%s]", k)
			}
		}
		type knnPlain KNNQuery
		var std struct {
			knnPlain
			Vector []float64       `json:"vector,omitempty"`
			Boost  json.RawMessage `json:"boost,omitempty"`
		}
		if err := json.Unmarshal(trimmed, &std); err != nil {
			return err
		}
		if len(std.QueryVector) == 0 && len(std.Vector) > 0 {
			std.QueryVector = std.Vector
		}
		*kq = KNNQuery(std.knnPlain)
		if len(std.Boost) > 0 {
			b, err := parseOptionalNonNegativeBoost(std.Boost)
			if err != nil {
				return fmt.Errorf("parsing_exception: [knn] boost must be a non-negative number")
			}
			kq.Boost = b
		}
		if strings.TrimSpace(kq.Field) == "" {
			return fmt.Errorf("parsing_exception: [knn] requires non-empty [field]")
		}
		if len(kq.QueryVector) == 0 {
			return fmt.Errorf("parsing_exception: [knn] requires non-empty [query_vector]")
		}
		if hasK && kq.K <= 0 {
			return fmt.Errorf("parsing_exception: [knn] [k] must be greater than 0")
		}
		if hasNC {
			if kq.NumCandidates <= 0 || (kq.K > 0 && kq.NumCandidates < kq.K) {
				return fmt.Errorf("parsing_exception: [knn] [num_candidates] must be >= [k] and > 0")
			}
		}
		return nil
	}
	// Support OpenSearch knn syntax: {"<field>": {"vector": [...], "k": 5, "filter": {...}}}
	cleaned, mapBoost, err := stripNamedQueryAndMapBoost(trimmed, false)
	if err != nil {
		return err
	}
	var byField map[string]json.RawMessage
	if err := json.Unmarshal(cleaned, &byField); err != nil {
		return err
	}
	foundField := false
	for field, rawSpec := range byField {
		if field == "_name" || field == "boost" {
			continue
		}
		var specMap map[string]json.RawMessage
		if err := json.Unmarshal(rawSpec, &specMap); err != nil {
			return fmt.Errorf("parsing_exception: [knn] invalid field specification for [%s]: %w", field, err)
		}
		for k := range specMap {
			switch k {
			case "vector", "query_vector", "k", "num_candidates", "similarity", "boost", "filter", "_name":
			default:
				return fmt.Errorf("parsing_exception: [knn] unknown field [%s]", k)
			}
		}
		var spec struct {
			Vector        []float64       `json:"vector"`
			QueryVector   []float64       `json:"query_vector"`
			K             int             `json:"k"`
			NumCandidates int             `json:"num_candidates"`
			Similarity    *float64        `json:"similarity"`
			Boost         json.RawMessage `json:"boost"`
			Filter        QuerySlice      `json:"filter"`
		}
		if err := json.Unmarshal(rawSpec, &spec); err != nil {
			return err
		}
		vec := spec.Vector
		if len(vec) == 0 {
			vec = spec.QueryVector
		}
		kq.Field = field
		kq.QueryVector = vec
		kq.K = spec.K
		kq.NumCandidates = spec.NumCandidates
		kq.Similarity = spec.Similarity
		if len(spec.Boost) > 0 {
			b, err := parseOptionalNonNegativeBoost(spec.Boost)
			if err != nil {
				return fmt.Errorf("parsing_exception: [knn] boost must be a non-negative number")
			}
			kq.Boost = b
		} else {
			kq.Boost = mapBoost
		}
		kq.Filter = spec.Filter
		if _, okK := specMap["k"]; okK && kq.K <= 0 {
			return fmt.Errorf("parsing_exception: [knn] [k] must be greater than 0")
		}
		if _, okNC := specMap["num_candidates"]; okNC {
			if kq.NumCandidates <= 0 || (kq.K > 0 && kq.NumCandidates < kq.K) {
				return fmt.Errorf("parsing_exception: [knn] [num_candidates] must be >= [k] and > 0")
			}
		}
		foundField = true
		break
	}
	if !foundField || strings.TrimSpace(kq.Field) == "" || len(kq.QueryVector) == 0 {
		return fmt.Errorf("parsing_exception: [knn] requires non-empty [field] and [query_vector]")
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
	StoredFields   any                `json:"stored_fields,omitempty"`
	Fields         []FieldRequestSpec `json:"fields,omitempty"`
	DocvalueFields []FieldRequestSpec `json:"docvalue_fields,omitempty"`
	ScriptFields   map[string]any     `json:"script_fields,omitempty"`
	Highlight      *HighlightSpec     `json:"highlight,omitempty"`
	Collapse       *CollapseSpec      `json:"collapse,omitempty"`
}

func (ih *InnerHitsSpec) HasStoredFieldsNone() bool {
	if ih == nil {
		return false
	}
	for _, f := range StoredFieldsSlice(ih.StoredFields) {
		if f == "_none_" {
			return true
		}
	}
	return false
}

func (ih *InnerHitsSpec) EffectiveFieldSpecs() []FieldRequestSpec {
	if ih == nil {
		return nil
	}
	sfList := StoredFieldsSlice(ih.StoredFields)
	if len(ih.Fields) == 0 && len(ih.DocvalueFields) == 0 && len(sfList) == 0 {
		return nil
	}
	out := make([]FieldRequestSpec, 0, len(ih.Fields)+len(ih.DocvalueFields)+len(sfList))
	out = append(out, ih.Fields...)
	out = append(out, ih.DocvalueFields...)
	for _, sf := range sfList {
		if sf != "_none_" {
			out = append(out, FieldRequestSpec{Field: sf})
		}
	}
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
	Field                      string            `json:"field"`
	InnerHits                  CollapseInnerHits `json:"inner_hits,omitempty"`
	MaxConcurrentGroupSearches *int              `json:"max_concurrent_group_searches,omitempty"`
}

func (cs *CollapseSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "field", "inner_hits", "max_concurrent_group_searches":
		default:
			return fmt.Errorf("parsing_exception: [collapse] unknown field [%s]", k)
		}
	}
	type plain CollapseSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" {
		return fmt.Errorf("parsing_exception: [collapse] requires non-empty [field]")
	}
	if p.MaxConcurrentGroupSearches != nil && *p.MaxConcurrentGroupSearches <= 0 {
		return fmt.Errorf("parsing_exception: [collapse] [max_concurrent_group_searches] must be > 0")
	}
	*cs = CollapseSpec(p)
	return nil
}

// RescoreQuerySpec models the `query` object inside a `rescore` block.
type RescoreQuerySpec struct {
	RescoreQuery       *Query   `json:"rescore_query,omitempty"`
	QueryWeight        *float64 `json:"query_weight,omitempty"`
	RescoreQueryWeight *float64 `json:"rescore_query_weight,omitempty"`
	ScoreMode          string   `json:"score_mode,omitempty"`
}

func (rqs *RescoreQuerySpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "rescore_query", "query_weight", "rescore_query_weight", "score_mode":
		default:
			return fmt.Errorf("parsing_exception: [rescore] unknown field [%s]", k)
		}
	}
	rawRQ, hasRQ := rawMap["rescore_query"]
	if !hasRQ || len(bytes.TrimSpace(rawRQ)) == 0 || bytes.Equal(bytes.TrimSpace(rawRQ), []byte("null")) {
		return fmt.Errorf("parsing_exception: [rescore] missing required [rescore_query]")
	}
	type plain RescoreQuerySpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.RescoreQuery == nil {
		return fmt.Errorf("parsing_exception: [rescore] missing required [rescore_query]")
	}
	switch strings.ToLower(strings.TrimSpace(p.ScoreMode)) {
	case "", "total", "multiply", "avg", "max", "min":
		p.ScoreMode = strings.ToLower(strings.TrimSpace(p.ScoreMode))
	default:
		return fmt.Errorf("parsing_exception: [rescore] invalid score_mode [%s]", p.ScoreMode)
	}
	*rqs = RescoreQuerySpec(p)
	return nil
}

// RescoreSpec models a single `rescore` entry in a search request.
type RescoreSpec struct {
	WindowSize *int              `json:"window_size,omitempty"`
	Query      *RescoreQuerySpec `json:"query,omitempty"`
}

func (rs *RescoreSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "window_size", "query":
		default:
			return fmt.Errorf("parsing_exception: [rescore] unknown field [%s]", k)
		}
	}
	type plain RescoreSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.WindowSize != nil && *p.WindowSize < 0 {
		return fmt.Errorf("parsing_exception: [rescore] window_size must be >= 0")
	}
	if p.Query == nil || p.Query.RescoreQuery == nil {
		return fmt.Errorf("parsing_exception: [rescore] requires [query.rescore_query]")
	}
	*rs = RescoreSpec(p)
	return nil
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

func parseFlexibleStringSlice(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	switch val := v.(type) {
	case string:
		return []string{val}, nil
	case []string:
		return val, nil
	case []any:
		out := make([]string, 0, len(val))
		for _, el := range val {
			if el != nil {
				out = append(out, formatFlexibleScalarString(el))
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("parsing_exception: expected string or array of strings, got %T", v)
	}
}

func formatFlexibleScalarString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	if fv, ok := v.(float64); ok && fv == math.Trunc(fv) && !math.IsInf(fv, 0) && !math.IsNaN(fv) {
		return strconv.FormatInt(int64(fv), 10)
	}
	return fmt.Sprintf("%v", v)
}

func (hfs *HighlightFieldSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	type plain HighlightFieldSpec
	var raw struct {
		plain
		PreTags       any `json:"pre_tags"`
		PostTags      any `json:"post_tags"`
		MatchedFields any `json:"matched_fields"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*hfs = HighlightFieldSpec(raw.plain)
	if raw.PreTags != nil {
		tags, err := parseFlexibleStringSlice(raw.PreTags)
		if err != nil {
			return err
		}
		hfs.PreTags = tags
	}
	if raw.PostTags != nil {
		tags, err := parseFlexibleStringSlice(raw.PostTags)
		if err != nil {
			return err
		}
		hfs.PostTags = tags
	}
	if raw.MatchedFields != nil {
		mf, err := parseFlexibleStringSlice(raw.MatchedFields)
		if err != nil {
			return err
		}
		hfs.MatchedFields = mf
	}
	return nil
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

func (h *HighlightSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	type plain HighlightSpec
	var raw struct {
		plain
		PreTags  any `json:"pre_tags"`
		PostTags any `json:"post_tags"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*h = HighlightSpec(raw.plain)
	if raw.PreTags != nil {
		tags, err := parseFlexibleStringSlice(raw.PreTags)
		if err != nil {
			return err
		}
		h.PreTags = tags
	}
	if raw.PostTags != nil {
		tags, err := parseFlexibleStringSlice(raw.PostTags)
		if err != nil {
			return err
		}
		h.PostTags = tags
	}
	return nil
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
	GeoDistance       *GeoDistanceQuery        `json:"geo_distance,omitempty"`
	GeoBoundingBox    *GeoBoundingBoxQuery     `json:"geo_bounding_box,omitempty"`
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
	"geo_distance":        true,
	"geo_bounding_box":    true,
	"_name":               true,
	"boost":               true,
}

func parseFlexibleBool(v any) (bool, error) {
	switch val := v.(type) {
	case nil:
		return false, nil
	case bool:
		return val, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "true", "1":
			return true, nil
		case "false", "0", "":
			return false, nil
		default:
			return false, fmt.Errorf("parsing_exception: invalid boolean value [%s]", val)
		}
	default:
		return false, fmt.Errorf("parsing_exception: invalid boolean value [%v]", val)
	}
}

func parseOptionalNonNegativeBoost(raw json.RawMessage) (*float64, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var b float64
	parsed := false
	if json.Unmarshal(trimmed, &b) == nil {
		parsed = true
	} else if trimmed[0] == '"' {
		var s string
		if json.Unmarshal(trimmed, &s) == nil {
			if fv, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
				b = fv
				parsed = true
			}
		}
	}
	if !parsed || math.IsNaN(b) || math.IsInf(b, 0) || b < 0 {
		return nil, fmt.Errorf("parsing_exception: [boost] must be a non-negative number, got %s", string(trimmed))
	}
	return &b, nil
}

func stripNamedQueryAndMapBoost(rawClause json.RawMessage, requireMultipleKeysForBoost bool) (json.RawMessage, *float64, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rawClause, &m); err != nil {
		return rawClause, nil, nil
	}
	modified := false
	if rawName, hasName := m["_name"]; hasName && len(m) > 1 {
		tn := bytes.TrimSpace(rawName)
		if len(tn) > 0 && tn[0] == '"' {
			delete(m, "_name")
			modified = true
		}
	}
	var mapBoost *float64
	if rawBoost, hasBoost := m["boost"]; hasBoost && (!requireMultipleKeysForBoost || len(m) > 1) {
		tb := bytes.TrimSpace(rawBoost)
		isFieldObject := len(tb) > 0 && tb[0] == '{'
		if !isFieldObject {
			b, err := parseOptionalNonNegativeBoost(rawBoost)
			if err != nil {
				if !requireMultipleKeysForBoost || !strings.HasPrefix(string(tb), `"`) {
					return rawClause, nil, err
				}
				var strVal string
				if json.Unmarshal(tb, &strVal) == nil {
					if fv, pErr := strconv.ParseFloat(strings.TrimSpace(strVal), 64); pErr == nil && fv < 0 {
						return rawClause, nil, err
					}
				}
			} else if b != nil {
				mapBoost = b
				delete(m, "boost")
				modified = true
			}
		}
	}
	if !modified {
		return rawClause, nil, nil
	}
	cleaned, err := json.Marshal(m)
	if err != nil {
		return rawClause, mapBoost, nil
	}
	return cleaned, mapBoost, nil
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
	clauseCount := 0
	for k := range raw {
		if !knownQueryClauses[k] {
			return fmt.Errorf("parsing_exception: unknown query clause [%s]", k)
		}
		if k != "_name" && k != "boost" {
			clauseCount++
		}
	}
	if clauseCount > 1 {
		return fmt.Errorf("parsing_exception: query malformed, must not start with multiple query clauses")
	}
	if rawTopBoost, ok := raw["boost"]; ok {
		if _, err := parseOptionalNonNegativeBoost(rawTopBoost); err != nil {
			return err
		}
	}
	mapBoosts := make(map[string]*float64)
	rawModified := false
	for _, clauseKey := range []string{
		"range", "terms_set",
		"term", "prefix", "wildcard", "regexp", "fuzzy",
		"match", "match_phrase", "match_phrase_prefix", "match_bool_prefix",
	} {
		if rawClause, ok := raw[clauseKey]; ok {
			reqMulti := clauseKey != "range" && clauseKey != "terms_set"
			cleaned, mb, err := stripNamedQueryAndMapBoost(rawClause, reqMulti)
			if err != nil {
				return err
			}
			if !bytes.Equal(cleaned, rawClause) {
				raw[clauseKey] = cleaned
				rawModified = true
			}
			if mb != nil {
				mapBoosts[clauseKey] = mb
			}
		}
	}
	if rawModified {
		if reMarshaled, err := json.Marshal(raw); err == nil {
			trimmed = reMarshaled
		}
	}
	type queryAlias Query
	var alias queryAlias
	if err := json.Unmarshal(trimmed, &alias); err != nil {
		return err
	}
	if alias.MatchAll != nil {
		if rawMB, ok := alias.MatchAll["boost"]; ok && rawMB != nil {
			mbBytes, _ := json.Marshal(rawMB)
			if _, err := parseOptionalNonNegativeBoost(mbBytes); err != nil {
				return err
			}
		}
	}
	for _, ptrBoost := range []*float64{
		func() *float64 {
			if alias.Bool != nil {
				return alias.Bool.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.DisMax != nil {
				return alias.DisMax.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.Boosting != nil {
				return alias.Boosting.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.Ids != nil {
				return alias.Ids.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.Exists != nil {
				return alias.Exists.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.MultiMatch != nil {
				return alias.MultiMatch.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.CombinedFields != nil {
				return alias.CombinedFields.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.QueryString != nil {
				return alias.QueryString.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.SimpleQueryString != nil {
				return alias.SimpleQueryString.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.Nested != nil {
				return alias.Nested.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.ConstantScore != nil {
				return alias.ConstantScore.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.FunctionScore != nil {
				return alias.FunctionScore.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.ScriptScore != nil {
				return alias.ScriptScore.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.Script != nil {
				return alias.Script.Boost
			}
			return nil
		}(),
	} {
		if ptrBoost != nil && (*ptrBoost < 0 || math.IsNaN(*ptrBoost) || math.IsInf(*ptrBoost, 0)) {
			return fmt.Errorf("parsing_exception: [boost] must be a non-negative number")
		}
	}
	if b := mapBoosts["range"]; b != nil {
		for k, rc := range alias.Range {
			if rc.Boost == nil {
				v := *b
				rc.Boost = &v
				alias.Range[k] = rc
			}
		}
	}
	if b := mapBoosts["terms_set"]; b != nil {
		for k, ts := range alias.TermsSet {
			if ts.Boost == nil {
				v := *b
				ts.Boost = &v
				alias.TermsSet[k] = ts
			}
		}
	}
	if b := mapBoosts["term"]; b != nil {
		for k, te := range alias.Term {
			if !te.HasBoost {
				te.Boost = *b
				te.HasBoost = true
				alias.Term[k] = te
			}
		}
	}
	if b := mapBoosts["prefix"]; b != nil {
		for k, pe := range alias.Prefix {
			if !pe.HasBoost {
				pe.Boost = *b
				pe.HasBoost = true
				alias.Prefix[k] = pe
			}
		}
	}
	if b := mapBoosts["wildcard"]; b != nil {
		for k, we := range alias.Wildcard {
			if !we.HasBoost {
				we.Boost = *b
				we.HasBoost = true
				alias.Wildcard[k] = we
			}
		}
	}
	if b := mapBoosts["regexp"]; b != nil {
		for k, re := range alias.Regexp {
			if !re.HasBoost {
				re.Boost = *b
				re.HasBoost = true
				alias.Regexp[k] = re
			}
		}
	}
	if b := mapBoosts["fuzzy"]; b != nil {
		for k, fe := range alias.Fuzzy {
			if !fe.HasBoost {
				fe.Boost = *b
				fe.HasBoost = true
				alias.Fuzzy[k] = fe
			}
		}
	}
	if b := mapBoosts["match"]; b != nil {
		for k, me := range alias.Match {
			if !me.HasBoost {
				me.Boost = *b
				me.HasBoost = true
				alias.Match[k] = me
			}
		}
	}
	if b := mapBoosts["match_phrase"]; b != nil {
		for k, pe := range alias.MatchPhrase {
			if !pe.HasBoost {
				pe.Boost = *b
				pe.HasBoost = true
				alias.MatchPhrase[k] = pe
			}
		}
	}
	if b := mapBoosts["match_phrase_prefix"]; b != nil {
		for k, pe := range alias.MatchPhrasePrefix {
			if !pe.HasBoost {
				pe.Boost = *b
				pe.HasBoost = true
				alias.MatchPhrasePrefix[k] = pe
			}
		}
	}
	if b := mapBoosts["match_bool_prefix"]; b != nil {
		for k, pe := range alias.MatchBoolPrefix {
			if !pe.HasBoost {
				pe.Boost = *b
				pe.HasBoost = true
				alias.MatchBoolPrefix[k] = pe
			}
		}
	}
	for _, check := range []struct {
		key string
		cnt int
	}{
		{"term", len(alias.Term)},
		{"range", len(alias.Range)},
		{"match", len(alias.Match)},
		{"prefix", len(alias.Prefix)},
		{"wildcard", len(alias.Wildcard)},
		{"regexp", len(alias.Regexp)},
		{"fuzzy", len(alias.Fuzzy)},
		{"match_phrase", len(alias.MatchPhrase)},
		{"match_phrase_prefix", len(alias.MatchPhrasePrefix)},
		{"match_bool_prefix", len(alias.MatchBoolPrefix)},
		{"terms_set", len(alias.TermsSet)},
	} {
		if _, ok := raw[check.key]; ok && check.cnt == 0 {
			return fmt.Errorf("parsing_exception: [%s] query must specify at least one field", check.key)
		}
	}
	*q = Query(alias)
	return nil
}

// DisMaxQuery represents an ES `dis_max` query (`queries`, `tie_breaker`, `boost`).
type DisMaxQuery struct {
	Queries    QuerySlice `json:"queries,omitempty"`
	TieBreaker float64    `json:"tie_breaker,omitempty"`
	Boost      *float64   `json:"boost,omitempty"`
	Name       string     `json:"_name,omitempty"`
}

func (dmq *DisMaxQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "queries", "tie_breaker", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [dis_max] unknown field [%s]", k)
		}
	}
	var raw struct {
		Queries    QuerySlice      `json:"queries"`
		TieBreaker json.RawMessage `json:"tie_breaker"`
		Boost      json.RawMessage `json:"boost"`
		Name       string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if len(raw.Queries) == 0 {
		return fmt.Errorf("parsing_exception: [dis_max] requires non-empty [queries]")
	}
	dmq.Queries = raw.Queries
	dmq.Name = raw.Name
	if len(raw.TieBreaker) > 0 {
		tbTrim := bytes.TrimSpace(raw.TieBreaker)
		if !bytes.Equal(tbTrim, []byte("null")) {
			var tb float64
			parsed := false
			if json.Unmarshal(tbTrim, &tb) == nil {
				parsed = true
			} else if len(tbTrim) > 0 && tbTrim[0] == '"' {
				var s string
				if json.Unmarshal(tbTrim, &s) == nil {
					if fv, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
						tb = fv
						parsed = true
					}
				}
			}
			if !parsed || math.IsNaN(tb) || math.IsInf(tb, 0) || tb < 0 || tb > 1.0 {
				return fmt.Errorf("parsing_exception: [dis_max] tie_breaker must be in [0.0, 1.0]")
			}
			dmq.TieBreaker = tb
		}
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		dmq.Boost = b
	}
	return nil
}

// GeoDistanceQuery models an Elasticsearch `geo_distance` query.
type GeoDistanceQuery struct {
	Field            string   `json:"-"`
	Lat              float64  `json:"-"`
	Lon              float64  `json:"-"`
	Distance         string   `json:"distance"`
	DistanceMeters   float64  `json:"-"`
	DistanceType     string   `json:"distance_type,omitempty"`
	ValidationMethod string   `json:"validation_method,omitempty"`
	Boost            *float64 `json:"boost,omitempty"`
	Name             string   `json:"_name,omitempty"`
}

func (gd GeoDistanceQuery) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"distance": gd.Distance,
	}
	if gd.Field != "" {
		m[gd.Field] = map[string]float64{"lat": gd.Lat, "lon": gd.Lon}
	}
	if gd.DistanceType != "" {
		m["distance_type"] = gd.DistanceType
	}
	if gd.ValidationMethod != "" {
		m["validation_method"] = gd.ValidationMethod
	}
	if gd.Boost != nil {
		m["boost"] = *gd.Boost
	}
	if gd.Name != "" {
		m["_name"] = gd.Name
	}
	return json.Marshal(m)
}

func (gd *GeoDistanceQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	rawDist, hasDist := rawMap["distance"]
	if !hasDist {
		return fmt.Errorf("parsing_exception: [geo_distance] requires [distance]")
	}
	var distAny any
	dec := json.NewDecoder(bytes.NewReader(rawDist))
	dec.UseNumber()
	if err := dec.Decode(&distAny); err != nil {
		return fmt.Errorf("parsing_exception: [geo_distance] invalid [distance]: %w", err)
	}
	if rawUnit, hasUnit := rawMap["unit"]; hasUnit {
		var unitStr string
		if err := json.Unmarshal(rawUnit, &unitStr); err != nil {
			return fmt.Errorf("parsing_exception: [geo_distance] invalid [unit]: %w", err)
		}
		unitStr = strings.TrimSpace(unitStr)
		if _, ok := GeoDistanceUnitMultiplier(unitStr); !ok {
			return fmt.Errorf("parsing_exception: [geo_distance] unknown distance unit [%s]", unitStr)
		}
		distAny = fmt.Sprintf("%v%s", distAny, unitStr)
	}
	distStr, distMeters, err := ParseGeoDistanceMeters(distAny)
	if err != nil {
		return err
	}
	gd.Distance = distStr
	gd.DistanceMeters = distMeters

	if rawDT, ok := rawMap["distance_type"]; ok {
		var dt string
		if err := json.Unmarshal(rawDT, &dt); err != nil {
			return fmt.Errorf("parsing_exception: [geo_distance] invalid [distance_type]")
		}
		switch strings.ToLower(strings.TrimSpace(dt)) {
		case "arc", "plane":
			gd.DistanceType = strings.ToLower(strings.TrimSpace(dt))
		default:
			return fmt.Errorf("parsing_exception: [geo_distance] invalid distance_type [%s]", dt)
		}
	}
	if rawVM, ok := rawMap["validation_method"]; ok {
		var vm string
		if err := json.Unmarshal(rawVM, &vm); err != nil {
			return fmt.Errorf("parsing_exception: [geo_distance] invalid [validation_method]")
		}
		switch strings.ToUpper(strings.TrimSpace(vm)) {
		case "STRICT", "IGNORE_MALFORMED", "COERCE":
			gd.ValidationMethod = strings.ToUpper(strings.TrimSpace(vm))
		default:
			return fmt.Errorf("parsing_exception: [geo_distance] invalid validation_method [%s]", vm)
		}
	}
	if rawBoost, ok := rawMap["boost"]; ok {
		b, err := parseOptionalNonNegativeBoost(rawBoost)
		if err != nil {
			return err
		}
		gd.Boost = b
	}
	if rawName, ok := rawMap["_name"]; ok {
		var n string
		if err := json.Unmarshal(rawName, &n); err != nil {
			return fmt.Errorf("parsing_exception: [geo_distance] invalid [_name]")
		}
		gd.Name = n
	}
	if rawIU, ok := rawMap["ignore_unmapped"]; ok {
		var iu any
		if err := json.Unmarshal(rawIU, &iu); err != nil {
			return fmt.Errorf("parsing_exception: [geo_distance] invalid [ignore_unmapped]")
		}
		if _, err := parseFlexibleBool(iu); err != nil {
			return err
		}
	}
	var fieldKeys []string
	for k := range rawMap {
		switch k {
		case "distance", "unit", "distance_type", "validation_method", "boost", "_name", "ignore_unmapped":
		default:
			fieldKeys = append(fieldKeys, k)
		}
	}
	if len(fieldKeys) != 1 {
		return fmt.Errorf("parsing_exception: [geo_distance] must specify exactly one field, got %d", len(fieldKeys))
	}
	gd.Field = fieldKeys[0]
	lat, lon, err := ParseGeoPoint(rawMap[gd.Field])
	if err != nil {
		return err
	}
	lat, lon, err = validateAndNormalizeGeoPoint(lat, lon, gd.ValidationMethod)
	if err != nil {
		return err
	}
	gd.Lat = lat
	gd.Lon = lon
	return nil
}

// GeoBoundingBoxQuery models an Elasticsearch `geo_bounding_box` query.
type GeoBoundingBoxQuery struct {
	Field            string   `json:"-"`
	Top              float64  `json:"-"`
	Left             float64  `json:"-"`
	Bottom           float64  `json:"-"`
	Right            float64  `json:"-"`
	ValidationMethod string   `json:"validation_method,omitempty"`
	Type             string   `json:"type,omitempty"`
	Boost            *float64 `json:"boost,omitempty"`
	Name             string   `json:"_name,omitempty"`
}

func (gb GeoBoundingBoxQuery) MarshalJSON() ([]byte, error) {
	m := map[string]any{}
	if gb.Field != "" {
		m[gb.Field] = map[string]any{
			"top_left":     map[string]float64{"lat": gb.Top, "lon": gb.Left},
			"bottom_right": map[string]float64{"lat": gb.Bottom, "lon": gb.Right},
		}
	}
	if gb.ValidationMethod != "" {
		m["validation_method"] = gb.ValidationMethod
	}
	if gb.Type != "" {
		m["type"] = gb.Type
	}
	if gb.Boost != nil {
		m["boost"] = *gb.Boost
	}
	if gb.Name != "" {
		m["_name"] = gb.Name
	}
	return json.Marshal(m)
}

func (gb *GeoBoundingBoxQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	if rawVM, ok := rawMap["validation_method"]; ok {
		var vm string
		if err := json.Unmarshal(rawVM, &vm); err != nil {
			return fmt.Errorf("parsing_exception: [geo_bounding_box] invalid [validation_method]")
		}
		switch strings.ToUpper(strings.TrimSpace(vm)) {
		case "STRICT", "IGNORE_MALFORMED", "COERCE":
			gb.ValidationMethod = strings.ToUpper(strings.TrimSpace(vm))
		default:
			return fmt.Errorf("parsing_exception: [geo_bounding_box] invalid validation_method [%s]", vm)
		}
	}
	if rawType, ok := rawMap["type"]; ok {
		tTrim := bytes.TrimSpace(rawType)
		if len(tTrim) == 0 || tTrim[0] != '{' {
			var tStr string
			if err := json.Unmarshal(rawType, &tStr); err != nil {
				return fmt.Errorf("parsing_exception: [geo_bounding_box] invalid [type]")
			}
			switch strings.ToLower(strings.TrimSpace(tStr)) {
			case "memory", "indexed":
				gb.Type = strings.ToLower(strings.TrimSpace(tStr))
			default:
				return fmt.Errorf("parsing_exception: [geo_bounding_box] invalid type [%s]", tStr)
			}
		}
	}
	if rawBoost, ok := rawMap["boost"]; ok {
		b, err := parseOptionalNonNegativeBoost(rawBoost)
		if err != nil {
			return err
		}
		gb.Boost = b
	}
	if rawName, ok := rawMap["_name"]; ok {
		var n string
		if err := json.Unmarshal(rawName, &n); err != nil {
			return fmt.Errorf("parsing_exception: [geo_bounding_box] invalid [_name]")
		}
		gb.Name = n
	}
	if rawIU, ok := rawMap["ignore_unmapped"]; ok {
		var iu any
		if err := json.Unmarshal(rawIU, &iu); err != nil {
			return fmt.Errorf("parsing_exception: [geo_bounding_box] invalid [ignore_unmapped]")
		}
		if _, err := parseFlexibleBool(iu); err != nil {
			return err
		}
	}
	var fieldKeys []string
	for k, v := range rawMap {
		switch k {
		case "validation_method", "boost", "_name", "ignore_unmapped":
		case "type":
			vTrim := bytes.TrimSpace(v)
			if len(vTrim) > 0 && vTrim[0] == '{' {
				fieldKeys = append(fieldKeys, k)
			}
		default:
			fieldKeys = append(fieldKeys, k)
		}
	}
	if len(fieldKeys) != 1 {
		return fmt.Errorf("parsing_exception: [geo_bounding_box] must specify exactly one field, got %d", len(fieldKeys))
	}
	gb.Field = fieldKeys[0]
	var boxMap map[string]json.RawMessage
	if err := json.Unmarshal(rawMap[gb.Field], &boxMap); err != nil || len(boxMap) == 0 {
		return fmt.Errorf("parsing_exception: [geo_bounding_box] field [%s] must be a bounding box object", gb.Field)
	}
	var top, left, bottom, right float64
	if rawWKT, hasWKT := boxMap["wkt"]; hasWKT {
		if len(boxMap) != 1 {
			return fmt.Errorf("parsing_exception: [geo_bounding_box] [wkt] cannot be combined with other bounds")
		}
		var wktStr string
		if err := json.Unmarshal(rawWKT, &wktStr); err != nil {
			return fmt.Errorf("parsing_exception: [geo_bounding_box] invalid [wkt]")
		}
		l, r, tVal, bVal, err := parseGeoWKTBBox(wktStr)
		if err != nil {
			return err
		}
		left, right, top, bottom = l, r, tVal, bVal
	} else if rawTL, hasTL := boxMap["top_left"]; hasTL {
		rawBR, hasBR := boxMap["bottom_right"]
		if !hasBR || len(boxMap) != 2 {
			return fmt.Errorf("parsing_exception: [geo_bounding_box] [top_left] requires [bottom_right] and no extra keys")
		}
		tVal, lVal, err := ParseGeoPoint(rawTL)
		if err != nil {
			return err
		}
		bVal, rVal, err := ParseGeoPoint(rawBR)
		if err != nil {
			return err
		}
		top, left, bottom, right = tVal, lVal, bVal, rVal
	} else if rawTR, hasTR := boxMap["top_right"]; hasTR {
		rawBL, hasBL := boxMap["bottom_left"]
		if !hasBL || len(boxMap) != 2 {
			return fmt.Errorf("parsing_exception: [geo_bounding_box] [top_right] requires [bottom_left] and no extra keys")
		}
		tVal, rVal, err := ParseGeoPoint(rawTR)
		if err != nil {
			return err
		}
		bVal, lVal, err := ParseGeoPoint(rawBL)
		if err != nil {
			return err
		}
		top, right, bottom, left = tVal, rVal, bVal, lVal
	} else if len(boxMap) == 4 {
		rawT, hasT := boxMap["top"]
		rawL, hasL := boxMap["left"]
		rawB, hasB := boxMap["bottom"]
		rawR, hasR := boxMap["right"]
		if !hasT || !hasL || !hasB || !hasR {
			return fmt.Errorf("parsing_exception: [geo_bounding_box] expected [top], [left], [bottom], [right]")
		}
		var err error
		if top, err = parseGeoCoordFloat(rawT); err != nil {
			return err
		}
		if left, err = parseGeoCoordFloat(rawL); err != nil {
			return err
		}
		if bottom, err = parseGeoCoordFloat(rawB); err != nil {
			return err
		}
		if right, err = parseGeoCoordFloat(rawR); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("parsing_exception: [geo_bounding_box] malformed bounding box specification for [%s]", gb.Field)
	}
	var err error
	top, left, err = validateAndNormalizeGeoPoint(top, left, gb.ValidationMethod)
	if err != nil {
		return err
	}
	bottom, right, err = validateAndNormalizeGeoPoint(bottom, right, gb.ValidationMethod)
	if err != nil {
		return err
	}
	if top < bottom {
		vm := strings.ToUpper(strings.TrimSpace(gb.ValidationMethod))
		if vm == "COERCE" || vm == "IGNORE_MALFORMED" {
			top, bottom = bottom, top
		} else {
			return fmt.Errorf("parsing_exception: [geo_bounding_box] top_left latitude [%v] cannot be smaller than bottom_right latitude [%v]", top, bottom)
		}
	}
	gb.Top = top
	gb.Left = left
	gb.Bottom = bottom
	gb.Right = right
	return nil
}

// ParseGeoDistanceMeters parses an Elasticsearch distance string or number into its normalized string and meters.
func ParseGeoDistanceMeters(raw any) (string, float64, error) {
	switch v := raw.(type) {
	case nil:
		return "", 0, fmt.Errorf("parsing_exception: [geo_distance] distance cannot be null")
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
			return "", 0, fmt.Errorf("parsing_exception: [geo_distance] distance must be > 0")
		}
		return strconv.FormatFloat(v, 'f', -1, 64) + "m", v, nil
	case int:
		if v <= 0 {
			return "", 0, fmt.Errorf("parsing_exception: [geo_distance] distance must be > 0")
		}
		return strconv.Itoa(v) + "m", float64(v), nil
	case int64:
		if v <= 0 {
			return "", 0, fmt.Errorf("parsing_exception: [geo_distance] distance must be > 0")
		}
		return strconv.FormatInt(v, 10) + "m", float64(v), nil
	case json.Number:
		fv, err := v.Float64()
		if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) || fv <= 0 {
			return "", 0, fmt.Errorf("parsing_exception: [geo_distance] distance must be > 0")
		}
		return v.String() + "m", fv, nil
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return "", 0, fmt.Errorf("parsing_exception: [geo_distance] distance cannot be empty")
		}
		numEnd := 0
		for numEnd < len(s) {
			ch := s[numEnd]
			if (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '+' || ch == 'e' || ch == 'E' {
				numEnd++
			} else {
				break
			}
		}
		if numEnd == 0 {
			return "", 0, fmt.Errorf("parsing_exception: [geo_distance] invalid distance [%s]", v)
		}
		val, err := strconv.ParseFloat(s[:numEnd], 64)
		if err != nil || math.IsNaN(val) || math.IsInf(val, 0) || val <= 0 {
			return "", 0, fmt.Errorf("parsing_exception: [geo_distance] distance must be > 0, got [%s]", v)
		}
		unit := strings.ToLower(strings.TrimSpace(s[numEnd:]))
		mult, ok := GeoDistanceUnitMultiplier(unit)
		if !ok {
			return "", 0, fmt.Errorf("parsing_exception: [geo_distance] unknown distance unit [%s]", unit)
		}
		return s, val * mult, nil
	default:
		return "", 0, fmt.Errorf("parsing_exception: [geo_distance] invalid distance [%v]", raw)
	}
}

// GeoDistanceUnitMultiplier returns the conversion factor from the given ES distance unit to meters.
func GeoDistanceUnitMultiplier(unit string) (float64, bool) {
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "", "m", "meter", "meters":
		return 1.0, true
	case "km", "kilometer", "kilometers":
		return 1000.0, true
	case "mi", "mile", "miles":
		return 1609.344, true
	case "nmi", "nm", "nauticalmile", "nauticalmiles":
		return 1852.0, true
	case "yd", "yard", "yards":
		return 0.9144, true
	case "ft", "feet", "foot":
		return 0.3048, true
	case "in", "inch", "inches":
		return 0.0254, true
	case "cm", "centimeter", "centimeters":
		return 0.01, true
	case "mm", "millimeter", "millimeters":
		return 0.001, true
	default:
		return 0, false
	}
}

// ParseGeoPoint parses an ES geo_point value from object {"lat", "lon"}, GeoJSON Point, [lon, lat], "lat,lon", WKT "POINT (lon lat)", or geohash.
func ParseGeoPoint(raw any) (lat, lon float64, err error) {
	switch v := raw.(type) {
	case nil:
		return 0, 0, fmt.Errorf("parsing_exception: geo_point cannot be null")
	case json.RawMessage:
		var decoded any
		dec := json.NewDecoder(bytes.NewReader(v))
		dec.UseNumber()
		if err := dec.Decode(&decoded); err != nil {
			return 0, 0, fmt.Errorf("parsing_exception: invalid geo_point JSON: %w", err)
		}
		return ParseGeoPoint(decoded)
	case []byte:
		var decoded any
		dec := json.NewDecoder(bytes.NewReader(v))
		dec.UseNumber()
		if err := dec.Decode(&decoded); err != nil {
			return 0, 0, fmt.Errorf("parsing_exception: invalid geo_point JSON: %w", err)
		}
		return ParseGeoPoint(decoded)
	case map[string]any:
		if rawType, hasType := v["type"]; hasType {
			tStr, _ := rawType.(string)
			if !strings.EqualFold(strings.TrimSpace(tStr), "Point") {
				return 0, 0, fmt.Errorf("parsing_exception: unsupported GeoJSON type [%v]", rawType)
			}
			coords, hasCoords := v["coordinates"]
			if !hasCoords {
				return 0, 0, fmt.Errorf("parsing_exception: GeoJSON Point missing [coordinates]")
			}
			return ParseGeoPoint(coords)
		}
		rawLat, hasLat := v["lat"]
		rawLon, hasLon := v["lon"]
		if !hasLon {
			rawLon, hasLon = v["lng"]
		}
		if !hasLat || !hasLon {
			return 0, 0, fmt.Errorf("parsing_exception: geo_point object requires [lat] and [lon]")
		}
		for k := range v {
			if k != "lat" && k != "lon" && k != "lng" {
				return 0, 0, fmt.Errorf("parsing_exception: unknown geo_point field [%s]", k)
			}
		}
		latVal, err1 := parseGeoCoordAny(rawLat)
		lonVal, err2 := parseGeoCoordAny(rawLon)
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("parsing_exception: invalid geo_point coordinates")
		}
		return latVal, lonVal, nil
	case []any:
		if len(v) < 2 || len(v) > 3 {
			return 0, 0, fmt.Errorf("parsing_exception: geo_point array must have [lon, lat]")
		}
		lonVal, err1 := parseGeoCoordAny(v[0])
		latVal, err2 := parseGeoCoordAny(v[1])
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("parsing_exception: invalid geo_point array coordinates")
		}
		return latVal, lonVal, nil
	case []float64:
		if len(v) < 2 || len(v) > 3 {
			return 0, 0, fmt.Errorf("parsing_exception: geo_point array must have [lon, lat]")
		}
		return v[1], v[0], nil
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return 0, 0, fmt.Errorf("parsing_exception: geo_point string cannot be empty")
		}
		upper := strings.ToUpper(s)
		if strings.HasPrefix(upper, "POINT") {
			rest := strings.TrimSpace(s[5:])
			if !strings.HasPrefix(rest, "(") || !strings.HasSuffix(rest, ")") {
				return 0, 0, fmt.Errorf("parsing_exception: invalid WKT POINT [%s]", v)
			}
			inner := strings.Fields(strings.TrimSpace(rest[1 : len(rest)-1]))
			if len(inner) < 2 || len(inner) > 3 {
				return 0, 0, fmt.Errorf("parsing_exception: invalid WKT POINT coordinates [%s]", v)
			}
			lonVal, err1 := strconv.ParseFloat(inner[0], 64)
			latVal, err2 := strconv.ParseFloat(inner[1], 64)
			if err1 != nil || err2 != nil {
				return 0, 0, fmt.Errorf("parsing_exception: invalid WKT POINT numbers [%s]", v)
			}
			return latVal, lonVal, nil
		}
		if strings.Contains(s, ",") {
			parts := strings.Split(s, ",")
			if len(parts) < 2 || len(parts) > 3 {
				return 0, 0, fmt.Errorf("parsing_exception: invalid geo_point string [%s]", v)
			}
			latVal, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			lonVal, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			if err1 != nil || err2 != nil {
				return 0, 0, fmt.Errorf("parsing_exception: invalid geo_point string coordinates [%s]", v)
			}
			return latVal, lonVal, nil
		}
		return decodeGeohashMidpoint(s)
	default:
		return 0, 0, fmt.Errorf("parsing_exception: unsupported geo_point value [%v]", raw)
	}
}

func parseGeoCoordFloat(raw json.RawMessage) (float64, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return 0, fmt.Errorf("parsing_exception: invalid coordinate: %w", err)
	}
	return parseGeoCoordAny(v)
}

func parseGeoCoordAny(v any) (float64, error) {
	switch tv := v.(type) {
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return 0, fmt.Errorf("parsing_exception: coordinate cannot be NaN or Inf")
		}
		return tv, nil
	case int:
		return float64(tv), nil
	case int64:
		return float64(tv), nil
	case json.Number:
		fv, err := tv.Float64()
		if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
			return 0, fmt.Errorf("parsing_exception: invalid coordinate [%v]", v)
		}
		return fv, nil
	case string:
		fv, err := strconv.ParseFloat(strings.TrimSpace(tv), 64)
		if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
			return 0, fmt.Errorf("parsing_exception: invalid coordinate [%s]", tv)
		}
		return fv, nil
	default:
		return 0, fmt.Errorf("parsing_exception: invalid coordinate [%v]", v)
	}
}

func parseGeoWKTBBox(wkt string) (left, right, top, bottom float64, err error) {
	s := strings.TrimSpace(wkt)
	if !strings.HasPrefix(strings.ToUpper(s), "BBOX") {
		return 0, 0, 0, 0, fmt.Errorf("parsing_exception: expected WKT BBOX, got [%s]", wkt)
	}
	rest := strings.TrimSpace(s[4:])
	if !strings.HasPrefix(rest, "(") || !strings.HasSuffix(rest, ")") {
		return 0, 0, 0, 0, fmt.Errorf("parsing_exception: invalid WKT BBOX [%s]", wkt)
	}
	parts := strings.Split(rest[1:len(rest)-1], ",")
	if len(parts) != 4 {
		return 0, 0, 0, 0, fmt.Errorf("parsing_exception: WKT BBOX requires 4 coordinates, got [%s]", wkt)
	}
	left, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	right, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	top, err3 := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
	bottom, err4 := strconv.ParseFloat(strings.TrimSpace(parts[3]), 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return 0, 0, 0, 0, fmt.Errorf("parsing_exception: invalid WKT BBOX coordinates [%s]", wkt)
	}
	return left, right, top, bottom, nil
}

func decodeGeohashMidpoint(hash string) (lat, lon float64, err error) {
	const base32 = "0123456789bcdefghjkmnpqrstuvwxyz"
	if len(hash) == 0 || len(hash) > 12 {
		return 0, 0, fmt.Errorf("parsing_exception: invalid geohash [%s]", hash)
	}
	minLat, maxLat := -90.0, 90.0
	minLon, maxLon := -180.0, 180.0
	isEven := true
	for i := 0; i < len(hash); i++ {
		idx := strings.IndexByte(base32, hash[i])
		if idx < 0 {
			return 0, 0, fmt.Errorf("parsing_exception: invalid geohash character in [%s]", hash)
		}
		for bit := 4; bit >= 0; bit-- {
			mask := (idx >> bit) & 1
			if isEven {
				mid := (minLon + maxLon) / 2.0
				if mask == 1 {
					minLon = mid
				} else {
					maxLon = mid
				}
			} else {
				mid := (minLat + maxLat) / 2.0
				if mask == 1 {
					minLat = mid
				} else {
					maxLat = mid
				}
			}
			isEven = !isEven
		}
	}
	return (minLat + maxLat) / 2.0, (minLon + maxLon) / 2.0, nil
}

func validateAndNormalizeGeoPoint(lat, lon float64, validationMethod string) (float64, float64, error) {
	if math.IsNaN(lat) || math.IsNaN(lon) || math.IsInf(lat, 0) || math.IsInf(lon, 0) {
		return 0, 0, fmt.Errorf("parsing_exception: geo_point coordinates must be finite")
	}
	vm := strings.ToUpper(strings.TrimSpace(validationMethod))
	if vm == "COERCE" || vm == "IGNORE_MALFORMED" {
		if lat > 90 {
			lat = 90
		} else if lat < -90 {
			lat = -90
		}
		for lon > 180 {
			lon -= 360
		}
		for lon < -180 {
			lon += 360
		}
		return lat, lon, nil
	}
	if lat < -90.0 || lat > 90.0 {
		return 0, 0, fmt.Errorf("parsing_exception: illegal latitude value [%v]", lat)
	}
	if lon < -180.0 || lon > 180.0 {
		return 0, 0, fmt.Errorf("parsing_exception: illegal longitude value [%v]", lon)
	}
	return lat, lon, nil
}

// BoostingQuery represents an ES `boosting` query (`positive`, `negative`, `negative_boost`).
type BoostingQuery struct {
	Positive         Query    `json:"positive"`
	Negative         Query    `json:"negative"`
	NegativeBoost    float64  `json:"negative_boost,omitempty"`
	HasNegativeBoost bool     `json:"-"`
	Boost            *float64 `json:"boost,omitempty"`
}

func (bq BoostingQuery) EffectiveNegativeBoost() float64 {
	if bq.HasNegativeBoost {
		return bq.NegativeBoost
	}
	if bq.NegativeBoost > 0 {
		return bq.NegativeBoost
	}
	return 0.5
}

func (bq BoostingQuery) MarshalJSON() ([]byte, error) {
	var negBoostPtr *float64
	if bq.HasNegativeBoost || bq.NegativeBoost != 0 {
		nb := bq.NegativeBoost
		negBoostPtr = &nb
	}
	return json.Marshal(struct {
		Positive      Query    `json:"positive"`
		Negative      Query    `json:"negative"`
		NegativeBoost *float64 `json:"negative_boost,omitempty"`
		Boost         *float64 `json:"boost,omitempty"`
	}{
		Positive:      bq.Positive,
		Negative:      bq.Negative,
		NegativeBoost: negBoostPtr,
		Boost:         bq.Boost,
	})
}

func (bq *BoostingQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var raw struct {
		Positive      Query           `json:"positive"`
		Negative      Query           `json:"negative"`
		NegativeBoost json.RawMessage `json:"negative_boost"`
		Boost         json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	bq.Positive = raw.Positive
	bq.Negative = raw.Negative
	if len(raw.NegativeBoost) > 0 {
		nb, err := parseOptionalNonNegativeBoost(raw.NegativeBoost)
		if err != nil {
			return fmt.Errorf("parsing_exception: [boosting] negative_boost must be a non-negative number")
		}
		if nb != nil {
			bq.NegativeBoost = *nb
			bq.HasNegativeBoost = true
		}
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		bq.Boost = b
	}
	return nil
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
	Fields          map[string][]any
	Lookups         map[string]TermsLookupSpec
	Boost           float64
	HasBoost        bool
	CaseInsensitive bool
}

func (tq TermsQuery) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(tq.Fields)+len(tq.Lookups)+2)
	for k, v := range tq.Fields {
		m[k] = v
	}
	for k, v := range tq.Lookups {
		m[k] = v
	}
	if tq.HasBoost || (tq.Boost != 0 && tq.Boost != 1.0) {
		m["boost"] = tq.Boost
	}
	if tq.CaseInsensitive {
		m["case_insensitive"] = true
	}
	return json.Marshal(m)
}

func (tq *TermsQuery) UnmarshalJSON(data []byte) error {
	tq.Boost = 1.0
	tq.HasBoost = false
	tq.CaseInsensitive = false
	tq.Fields = make(map[string][]any)
	tq.Lookups = make(map[string]TermsLookupSpec)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		trimmed := bytes.TrimSpace(v)
		if k == "boost" && len(trimmed) > 0 && trimmed[0] != '[' && trimmed[0] != '{' {
			var b float64
			parsed := false
			if json.Unmarshal(trimmed, &b) == nil {
				parsed = true
			} else if trimmed[0] == '"' {
				var s string
				if json.Unmarshal(trimmed, &s) == nil {
					if fv, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
						b = fv
						parsed = true
					}
				}
			}
			if !parsed || math.IsNaN(b) || math.IsInf(b, 0) || b < 0 {
				return fmt.Errorf("parsing_exception: [terms] invalid boost value: %s", string(trimmed))
			}
			tq.Boost = b
			tq.HasBoost = true
			continue
		}
		if k == "case_insensitive" && len(trimmed) > 0 && trimmed[0] != '[' && trimmed[0] != '{' {
			var ci bool
			if err := json.Unmarshal(v, &ci); err != nil {
				var ciStr string
				if json.Unmarshal(v, &ciStr) == nil {
					ci = strings.EqualFold(strings.TrimSpace(ciStr), "true")
				} else {
					return fmt.Errorf("parsing_exception: [terms] invalid case_insensitive value: %w", err)
				}
			}
			tq.CaseInsensitive = ci
			continue
		}
		if k == "_name" && len(trimmed) > 0 && trimmed[0] == '"' {
			continue
		}
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
	if len(tq.Fields)+len(tq.Lookups) == 0 {
		return fmt.Errorf("parsing_exception: [terms] query must specify at least one field")
	}
	return nil
}

// TermsSetEntry models a `terms_set` query on a field.
type TermsSetEntry struct {
	Terms                    []any    `json:"terms"`
	MinimumShouldMatchField  string   `json:"minimum_should_match_field,omitempty"`
	MinimumShouldMatchScript any      `json:"minimum_should_match_script,omitempty"`
	Boost                    *float64 `json:"boost,omitempty"`
}

func (tse *TermsSetEntry) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "terms", "minimum_should_match", "minimum_should_match_field", "minimum_should_match_script", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [terms_set] unknown field [%s]", k)
		}
	}
	var full struct {
		Terms                    []any           `json:"terms"`
		MinimumShouldMatch       any             `json:"minimum_should_match"`
		MinimumShouldMatchField  string          `json:"minimum_should_match_field"`
		MinimumShouldMatchScript any             `json:"minimum_should_match_script"`
		Boost                    json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &full); err != nil {
		return err
	}
	tse.Terms = full.Terms
	tse.MinimumShouldMatchField = full.MinimumShouldMatchField
	tse.MinimumShouldMatchScript = full.MinimumShouldMatchScript
	if tse.MinimumShouldMatchScript == nil && full.MinimumShouldMatch != nil {
		tse.MinimumShouldMatchScript = full.MinimumShouldMatch
	}
	if len(full.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(full.Boost)
		if err != nil {
			return err
		}
		tse.Boost = b
	}
	return nil
}

// FuzzyEntry models a `fuzzy` query (`{"fuzzy": {"name": "alice"}}` or `{"fuzzy": {"name": {"value": "alice", "fuzziness": "AUTO"}}}`).
type FuzzyEntry struct {
	Value           any     `json:"value"`
	Fuzziness       any     `json:"fuzziness,omitempty"`
	CaseInsensitive bool    `json:"case_insensitive,omitempty"`
	Boost           float64 `json:"boost,omitempty"`
	HasBoost        bool    `json:"-"`
}

func (f FuzzyEntry) MarshalJSON() ([]byte, error) {
	var boostPtr *float64
	if f.HasBoost || (f.Boost != 0 && f.Boost != 1.0) {
		b := f.Boost
		boostPtr = &b
	}
	return json.Marshal(struct {
		Value           any      `json:"value"`
		Fuzziness       any      `json:"fuzziness,omitempty"`
		CaseInsensitive bool     `json:"case_insensitive,omitempty"`
		Boost           *float64 `json:"boost,omitempty"`
	}{
		Value:           f.Value,
		Fuzziness:       f.Fuzziness,
		CaseInsensitive: f.CaseInsensitive,
		Boost:           boostPtr,
	})
}

func isNonScalarOrNullValue(v any) bool {
	if v == nil {
		return true
	}
	switch v.(type) {
	case []any, map[string]any:
		return true
	}
	return false
}

func validateQueryOperator(op, clause string) error {
	if op == "" {
		return nil
	}
	lower := strings.ToLower(strings.TrimSpace(op))
	if lower != "or" && lower != "and" {
		return fmt.Errorf("parsing_exception: [%s] operator must be [or] or [and], got [%s]", clause, op)
	}
	return nil
}

func validateZeroTermsQuery(ztq, clause string) error {
	if ztq == "" {
		return nil
	}
	lower := strings.ToLower(strings.TrimSpace(ztq))
	if lower != "none" && lower != "all" {
		return fmt.Errorf("parsing_exception: [%s] unsupported zero_terms_query [%s]", clause, ztq)
	}
	return nil
}

func (f *FuzzyEntry) UnmarshalJSON(data []byte) error {
	f.Boost = 1.0
	f.HasBoost = false
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err != nil {
			return err
		}
		for k := range rawMap {
			switch k {
			case "value", "fuzziness", "case_insensitive", "boost", "prefix_length", "max_expansions", "transpositions", "rewrite", "_name":
			default:
				return fmt.Errorf("parsing_exception: [fuzzy] unknown field [%s]", k)
			}
		}
		if _, hasVal := rawMap["value"]; !hasVal {
			return fmt.Errorf("parsing_exception: [fuzzy] missing required [value] field")
		}
		var full struct {
			Value           any             `json:"value"`
			Fuzziness       any             `json:"fuzziness"`
			CaseInsensitive any             `json:"case_insensitive"`
			Boost           json.RawMessage `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		if isNonScalarOrNullValue(full.Value) {
			return fmt.Errorf("parsing_exception: [fuzzy] query does not support non-scalar or null value")
		}
		ci, err := parseFlexibleBool(full.CaseInsensitive)
		if err != nil {
			return err
		}
		f.Value = full.Value
		f.Fuzziness = full.Fuzziness
		f.CaseInsensitive = ci
		if len(full.Boost) > 0 {
			b, err := parseOptionalNonNegativeBoost(full.Boost)
			if err != nil {
				return err
			}
			if b != nil {
				f.Boost = *b
				f.HasBoost = true
			}
		}
		return nil
	}
	if err := json.Unmarshal(trimmed, &f.Value); err != nil {
		return err
	}
	if isNonScalarOrNullValue(f.Value) {
		return fmt.Errorf("parsing_exception: [fuzzy] query does not support non-scalar or null value")
	}
	return nil
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

func (cfq *CombinedFieldsQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "query", "fields", "operator", "minimum_should_match", "zero_terms_query", "auto_generate_synonyms_phrase_query", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [combined_fields] unknown field [%s]", k)
		}
	}
	type plain CombinedFieldsQuery
	var raw struct {
		plain
		Fields any             `json:"fields"`
		Boost  json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*cfq = CombinedFieldsQuery(raw.plain)
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		cfq.Boost = b
	}
	if err := validateQueryOperator(cfq.Operator, "combined_fields"); err != nil {
		return err
	}
	if err := validateZeroTermsQuery(cfq.ZeroTermsQuery, "combined_fields"); err != nil {
		return err
	}
	if raw.Fields != nil {
		fields, err := parseFlexibleStringSlice(raw.Fields)
		if err != nil {
			return err
		}
		cfq.Fields = fields
	}
	return nil
}

// ScriptScoreQuery models an ES `script_score` query (`{"script_score": {"query": {...}, "script": {...}}}`).
type ScriptScoreQuery struct {
	Query    *Query   `json:"query,omitempty"`
	Script   any      `json:"script,omitempty"`
	MinScore *float64 `json:"min_score,omitempty"`
	Boost    *float64 `json:"boost,omitempty"`
}

func (ssq *ScriptScoreQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "query", "script", "min_score", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [script_score] unknown field [%s]", k)
		}
	}
	rawQuery, hasQuery := rawMap["query"]
	if !hasQuery || len(bytes.TrimSpace(rawQuery)) == 0 || bytes.Equal(bytes.TrimSpace(rawQuery), []byte("null")) {
		return fmt.Errorf("parsing_exception: [script_score] missing required [query] field")
	}
	rawScript, hasScript := rawMap["script"]
	if !hasScript || len(bytes.TrimSpace(rawScript)) == 0 || bytes.Equal(bytes.TrimSpace(rawScript), []byte("null")) {
		return fmt.Errorf("parsing_exception: [script_score] missing required [script] field")
	}
	var full struct {
		Query    *Query          `json:"query"`
		Script   any             `json:"script"`
		MinScore json.RawMessage `json:"min_score"`
		Boost    json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &full); err != nil {
		return err
	}
	ssq.Query = full.Query
	ssq.Script = full.Script
	if len(full.MinScore) > 0 {
		ms, err := parseOptionalNonNegativeBoost(full.MinScore)
		if err != nil {
			return fmt.Errorf("parsing_exception: [script_score] min_score must be a non-negative number")
		}
		ssq.MinScore = ms
	}
	if len(full.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(full.Boost)
		if err != nil {
			return err
		}
		ssq.Boost = b
	}
	return nil
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
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	_, hasInnerScript := rawMap["script"]
	for k := range rawMap {
		if hasInnerScript {
			switch k {
			case "script", "boost", "_name":
			default:
				return fmt.Errorf("parsing_exception: [script] unknown field [%s]", k)
			}
		} else {
			switch k {
			case "source", "inline", "id", "lang", "params", "options", "boost", "_name":
			default:
				return fmt.Errorf("parsing_exception: [script] unknown field [%s]", k)
			}
		}
	}
	if rawBoost, ok := rawMap["boost"]; ok {
		b, err := parseOptionalNonNegativeBoost(rawBoost)
		if err != nil {
			return err
		}
		sq.Boost = b
	}
	var m map[string]any
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return err
	}
	if inner, ok := m["script"]; ok {
		if inner == nil {
			return fmt.Errorf("parsing_exception: [script] script cannot be null")
		}
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

func (bq *BoolQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	for k := range raw {
		switch k {
		case "must", "filter", "should", "must_not", "minimum_should_match", "boost", "_name", "adjust_pure_negative":
		default:
			return fmt.Errorf("parsing_exception: [bool] unknown field [%s]", k)
		}
	}
	type plain BoolQuery
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	*bq = BoolQuery(p)
	return nil
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
	if trimmed[0] != '{' {
		return fmt.Errorf("parsing_exception: [bool] query clause must be an object or array of objects")
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
	HasBoost        bool    `json:"-"`
}

func (t TermEntry) MarshalJSON() ([]byte, error) {
	var boostPtr *float64
	if t.HasBoost || (t.Boost != 0 && t.Boost != 1.0) {
		b := t.Boost
		boostPtr = &b
	}
	return json.Marshal(struct {
		Value           any      `json:"value"`
		Boost           *float64 `json:"boost,omitempty"`
		CaseInsensitive bool     `json:"case_insensitive,omitempty"`
	}{
		Value:           t.Value,
		Boost:           boostPtr,
		CaseInsensitive: t.CaseInsensitive,
	})
}

func (t *TermEntry) UnmarshalJSON(data []byte) error {
	t.Boost = 1.0
	t.HasBoost = false
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err != nil {
			return err
		}
		for k := range rawMap {
			switch k {
			case "value", "boost", "case_insensitive", "_name":
			default:
				return fmt.Errorf("parsing_exception: [term] unknown field [%s]", k)
			}
		}
		if _, hasVal := rawMap["value"]; !hasVal {
			return fmt.Errorf("parsing_exception: [term] missing required [value] field")
		}
		var full struct {
			Value           any             `json:"value"`
			Boost           json.RawMessage `json:"boost"`
			CaseInsensitive any             `json:"case_insensitive"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		if isNonScalarOrNullValue(full.Value) {
			return fmt.Errorf("parsing_exception: [term] query does not support non-scalar or null value")
		}
		ci, err := parseFlexibleBool(full.CaseInsensitive)
		if err != nil {
			return err
		}
		t.Value = full.Value
		if len(full.Boost) > 0 {
			b, err := parseOptionalNonNegativeBoost(full.Boost)
			if err != nil {
				return err
			}
			if b != nil {
				t.Boost = *b
				t.HasBoost = true
			}
		}
		t.CaseInsensitive = ci
		return nil
	}
	if err := json.Unmarshal(trimmed, &t.Value); err != nil {
		return err
	}
	if isNonScalarOrNullValue(t.Value) {
		return fmt.Errorf("parsing_exception: [term] query does not support non-scalar or null value")
	}
	return nil
}

type IdsQuery struct {
	Values []string `json:"values"`
	Boost  *float64 `json:"boost,omitempty"`
	Name   string   `json:"_name,omitempty"`
}

func (iq *IdsQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "values", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [ids] unknown field [%s]", k)
		}
	}
	var raw struct {
		Values any             `json:"values"`
		Boost  json.RawMessage `json:"boost"`
		Name   string          `json:"_name"`
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	iq.Name = raw.Name
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		iq.Boost = b
	}
	switch v := raw.Values.(type) {
	case nil:
	case []any:
		iq.Values = make([]string, 0, len(v))
		for _, item := range v {
			if isNonScalarOrNullValue(item) {
				return fmt.Errorf("parsing_exception: [ids] values cannot contain null or non-scalar elements")
			}
			iq.Values = append(iq.Values, formatFlexibleScalarString(item))
		}
	default:
		if isNonScalarOrNullValue(v) {
			return fmt.Errorf("parsing_exception: [ids] values must be an array of scalars")
		}
		iq.Values = []string{formatFlexibleScalarString(v)}
	}
	return nil
}

type ExistsQuery struct {
	Field string   `json:"field"`
	Boost *float64 `json:"boost,omitempty"`
	Name  string   `json:"_name,omitempty"`
}

func (eq *ExistsQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "field", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [exists] unknown field [%s]", k)
		}
	}
	var raw struct {
		Field string          `json:"field"`
		Boost json.RawMessage `json:"boost"`
		Name  string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Field) == "" {
		return fmt.Errorf("parsing_exception: [exists] requires non-empty [field]")
	}
	eq.Field = raw.Field
	eq.Name = raw.Name
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		eq.Boost = b
	}
	return nil
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

func (rc *RangeCond) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "gt", "gte", "lt", "lte", "from", "to", "include_lower", "include_upper", "boost", "format", "time_zone", "relation", "_name":
		default:
			return fmt.Errorf("parsing_exception: [range] unknown field [%s]", k)
		}
	}
	var full struct {
		GT           any             `json:"gt"`
		GTE          any             `json:"gte"`
		LT           any             `json:"lt"`
		LTE          any             `json:"lte"`
		From         any             `json:"from"`
		To           any             `json:"to"`
		IncludeLower *bool           `json:"include_lower"`
		IncludeUpper *bool           `json:"include_upper"`
		Boost        json.RawMessage `json:"boost"`
		Format       string          `json:"format"`
		TimeZone     string          `json:"time_zone"`
	}
	if err := json.Unmarshal(trimmed, &full); err != nil {
		return err
	}
	rc.GT = full.GT
	rc.GTE = full.GTE
	rc.LT = full.LT
	rc.LTE = full.LTE
	rc.From = full.From
	rc.To = full.To
	rc.IncludeLower = full.IncludeLower
	rc.IncludeUpper = full.IncludeUpper
	rc.Format = full.Format
	rc.TimeZone = full.TimeZone
	if len(full.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(full.Boost)
		if err != nil {
			return err
		}
		rc.Boost = b
	}
	return nil
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
	HasBoost        bool    `json:"-"`
}

func (p PrefixEntry) MarshalJSON() ([]byte, error) {
	var boostPtr *float64
	if p.HasBoost || (p.Boost != 0 && p.Boost != 1.0) {
		b := p.Boost
		boostPtr = &b
	}
	return json.Marshal(struct {
		Value           string   `json:"value"`
		CaseInsensitive bool     `json:"case_insensitive,omitempty"`
		Boost           *float64 `json:"boost,omitempty"`
	}{
		Value:           p.Value,
		CaseInsensitive: p.CaseInsensitive,
		Boost:           boostPtr,
	})
}

func (p *PrefixEntry) UnmarshalJSON(data []byte) error {
	p.Boost = 1.0
	p.HasBoost = false
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err != nil {
			return err
		}
		for k := range rawMap {
			switch k {
			case "value", "prefix", "case_insensitive", "boost", "rewrite", "_name":
			default:
				return fmt.Errorf("parsing_exception: [prefix] unknown field [%s]", k)
			}
		}
		_, hasVal := rawMap["value"]
		_, hasPfx := rawMap["prefix"]
		if !hasVal && !hasPfx {
			return fmt.Errorf("parsing_exception: [prefix] missing required [value] field")
		}
		var full struct {
			Value           any             `json:"value"`
			Prefix          any             `json:"prefix"`
			CaseInsensitive any             `json:"case_insensitive"`
			Boost           json.RawMessage `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		ci, err := parseFlexibleBool(full.CaseInsensitive)
		if err != nil {
			return err
		}
		val := full.Value
		if val == nil {
			val = full.Prefix
		}
		if isNonScalarOrNullValue(val) {
			return fmt.Errorf("parsing_exception: [prefix] query does not support non-scalar or null value")
		}
		p.Value = fmt.Sprintf("%v", val)
		p.CaseInsensitive = ci
		if len(full.Boost) > 0 {
			b, err := parseOptionalNonNegativeBoost(full.Boost)
			if err != nil {
				return err
			}
			if b != nil {
				p.Boost = *b
				p.HasBoost = true
			}
		}
		return nil
	}
	var raw any
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if isNonScalarOrNullValue(raw) {
		return fmt.Errorf("parsing_exception: [prefix] query does not support non-scalar or null value")
	}
	p.Value = fmt.Sprintf("%v", raw)
	return nil
}

type WildcardEntry struct {
	Value           string  `json:"value"`
	CaseInsensitive bool    `json:"case_insensitive,omitempty"`
	Boost           float64 `json:"boost,omitempty"`
	HasBoost        bool    `json:"-"`
}

func (w WildcardEntry) MarshalJSON() ([]byte, error) {
	var boostPtr *float64
	if w.HasBoost || (w.Boost != 0 && w.Boost != 1.0) {
		b := w.Boost
		boostPtr = &b
	}
	return json.Marshal(struct {
		Value           string   `json:"value"`
		CaseInsensitive bool     `json:"case_insensitive,omitempty"`
		Boost           *float64 `json:"boost,omitempty"`
	}{
		Value:           w.Value,
		CaseInsensitive: w.CaseInsensitive,
		Boost:           boostPtr,
	})
}

func (w *WildcardEntry) UnmarshalJSON(data []byte) error {
	w.Boost = 1.0
	w.HasBoost = false
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err != nil {
			return err
		}
		for k := range rawMap {
			switch k {
			case "value", "wildcard", "case_insensitive", "boost", "rewrite", "_name":
			default:
				return fmt.Errorf("parsing_exception: [wildcard] unknown field [%s]", k)
			}
		}
		_, hasVal := rawMap["value"]
		_, hasWc := rawMap["wildcard"]
		if !hasVal && !hasWc {
			return fmt.Errorf("parsing_exception: [wildcard] missing required [value] field")
		}
		var full struct {
			Value           any             `json:"value"`
			Wildcard        any             `json:"wildcard"`
			CaseInsensitive any             `json:"case_insensitive"`
			Boost           json.RawMessage `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		ci, err := parseFlexibleBool(full.CaseInsensitive)
		if err != nil {
			return err
		}
		val := full.Value
		if val == nil {
			val = full.Wildcard
		}
		if isNonScalarOrNullValue(val) {
			return fmt.Errorf("parsing_exception: [wildcard] query does not support non-scalar or null value")
		}
		w.Value = fmt.Sprintf("%v", val)
		w.CaseInsensitive = ci
		if len(full.Boost) > 0 {
			b, err := parseOptionalNonNegativeBoost(full.Boost)
			if err != nil {
				return err
			}
			if b != nil {
				w.Boost = *b
				w.HasBoost = true
			}
		}
		return nil
	}
	var raw any
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if isNonScalarOrNullValue(raw) {
		return fmt.Errorf("parsing_exception: [wildcard] query does not support non-scalar or null value")
	}
	w.Value = fmt.Sprintf("%v", raw)
	return nil
}

type RegexpEntry struct {
	Value           string  `json:"value"`
	CaseInsensitive bool    `json:"case_insensitive,omitempty"`
	Boost           float64 `json:"boost,omitempty"`
	HasBoost        bool    `json:"-"`
}

func (r RegexpEntry) MarshalJSON() ([]byte, error) {
	var boostPtr *float64
	if r.HasBoost || (r.Boost != 0 && r.Boost != 1.0) {
		b := r.Boost
		boostPtr = &b
	}
	return json.Marshal(struct {
		Value           string   `json:"value"`
		CaseInsensitive bool     `json:"case_insensitive,omitempty"`
		Boost           *float64 `json:"boost,omitempty"`
	}{
		Value:           r.Value,
		CaseInsensitive: r.CaseInsensitive,
		Boost:           boostPtr,
	})
}

func (r *RegexpEntry) UnmarshalJSON(data []byte) error {
	r.Boost = 1.0
	r.HasBoost = false
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err != nil {
			return err
		}
		for k := range rawMap {
			switch k {
			case "value", "regexp", "case_insensitive", "boost", "flags", "max_determinized_states", "rewrite", "_name":
			default:
				return fmt.Errorf("parsing_exception: [regexp] unknown field [%s]", k)
			}
		}
		_, hasVal := rawMap["value"]
		_, hasRx := rawMap["regexp"]
		if !hasVal && !hasRx {
			return fmt.Errorf("parsing_exception: [regexp] missing required [value] field")
		}
		var full struct {
			Value           any             `json:"value"`
			Regexp          any             `json:"regexp"`
			CaseInsensitive any             `json:"case_insensitive"`
			Boost           json.RawMessage `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		ci, err := parseFlexibleBool(full.CaseInsensitive)
		if err != nil {
			return err
		}
		val := full.Value
		if val == nil {
			val = full.Regexp
		}
		if isNonScalarOrNullValue(val) {
			return fmt.Errorf("parsing_exception: [regexp] query does not support non-scalar or null value")
		}
		r.Value = fmt.Sprintf("%v", val)
		r.CaseInsensitive = ci
		if len(full.Boost) > 0 {
			b, err := parseOptionalNonNegativeBoost(full.Boost)
			if err != nil {
				return err
			}
			if b != nil {
				r.Boost = *b
				r.HasBoost = true
			}
		}
		return nil
	}
	var raw any
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if isNonScalarOrNullValue(raw) {
		return fmt.Errorf("parsing_exception: [regexp] query does not support non-scalar or null value")
	}
	r.Value = fmt.Sprintf("%v", raw)
	return nil
}

type MatchEntry struct {
	Query              any     `json:"query"`
	Operator           string  `json:"operator,omitempty"`
	Boost              float64 `json:"boost,omitempty"`
	ZeroTermsQuery     string  `json:"zero_terms_query,omitempty"`
	MinimumShouldMatch any     `json:"minimum_should_match,omitempty"`
	Fuzziness          any     `json:"fuzziness,omitempty"`
	Lenient            *bool   `json:"lenient,omitempty"`
	HasBoost           bool    `json:"-"`
}

func (m MatchEntry) MarshalJSON() ([]byte, error) {
	var boostPtr *float64
	if m.HasBoost || (m.Boost != 0 && m.Boost != 1.0) {
		b := m.Boost
		boostPtr = &b
	}
	return json.Marshal(struct {
		Query              any      `json:"query"`
		Operator           string   `json:"operator,omitempty"`
		Boost              *float64 `json:"boost,omitempty"`
		ZeroTermsQuery     string   `json:"zero_terms_query,omitempty"`
		MinimumShouldMatch any      `json:"minimum_should_match,omitempty"`
		Fuzziness          any      `json:"fuzziness,omitempty"`
		Lenient            *bool    `json:"lenient,omitempty"`
	}{
		Query:              m.Query,
		Operator:           m.Operator,
		Boost:              boostPtr,
		ZeroTermsQuery:     m.ZeroTermsQuery,
		MinimumShouldMatch: m.MinimumShouldMatch,
		Fuzziness:          m.Fuzziness,
		Lenient:            m.Lenient,
	})
}

func (m *MatchEntry) UnmarshalJSON(data []byte) error {
	m.Boost = 1.0
	m.HasBoost = false
	m.Operator = "or"
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err != nil {
			return err
		}
		for k := range rawMap {
			switch k {
			case "query", "operator", "boost", "zero_terms_query", "minimum_should_match", "fuzziness", "lenient",
				"analyzer", "auto_generate_synonyms_phrase_query", "fuzzy_transpositions", "fuzzy_rewrite",
				"max_expansions", "prefix_length", "cutoff_frequency", "_name":
			default:
				return fmt.Errorf("parsing_exception: [match] unknown field [%s]", k)
			}
		}
		if _, hasQ := rawMap["query"]; !hasQ {
			return fmt.Errorf("parsing_exception: [match] missing required [query] field")
		}
		var full struct {
			Query              any             `json:"query"`
			Operator           string          `json:"operator"`
			Boost              json.RawMessage `json:"boost"`
			ZeroTermsQuery     string          `json:"zero_terms_query"`
			MinimumShouldMatch any             `json:"minimum_should_match"`
			Fuzziness          any             `json:"fuzziness"`
			Lenient            *bool           `json:"lenient"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		if isNonScalarOrNullValue(full.Query) {
			return fmt.Errorf("parsing_exception: [match] query does not support non-scalar or null value")
		}
		m.Query = full.Query
		if full.Operator != "" {
			if err := validateQueryOperator(full.Operator, "match"); err != nil {
				return err
			}
			m.Operator = strings.ToLower(strings.TrimSpace(full.Operator))
		}
		if len(full.Boost) > 0 {
			b, err := parseOptionalNonNegativeBoost(full.Boost)
			if err != nil {
				return err
			}
			if b != nil {
				m.Boost = *b
				m.HasBoost = true
			}
		}
		if err := validateZeroTermsQuery(full.ZeroTermsQuery, "match"); err != nil {
			return err
		}
		m.ZeroTermsQuery = full.ZeroTermsQuery
		m.MinimumShouldMatch = full.MinimumShouldMatch
		m.Fuzziness = full.Fuzziness
		m.Lenient = full.Lenient
		return nil
	}
	if err := json.Unmarshal(trimmed, &m.Query); err != nil {
		return err
	}
	if isNonScalarOrNullValue(m.Query) {
		return fmt.Errorf("parsing_exception: [match] query does not support non-scalar or null value")
	}
	return nil
}

type PhraseEntry struct {
	Query              string  `json:"query"`
	Slop               int     `json:"slop,omitempty"`
	Operator           string  `json:"operator,omitempty"`
	MinimumShouldMatch any     `json:"minimum_should_match,omitempty"`
	ZeroTermsQuery     string  `json:"zero_terms_query,omitempty"`
	Fuzziness          any     `json:"fuzziness,omitempty"`
	Boost              float64 `json:"boost,omitempty"`
	HasBoost           bool    `json:"-"`
}

func (p PhraseEntry) MarshalJSON() ([]byte, error) {
	var boostPtr *float64
	if p.HasBoost || (p.Boost != 0 && p.Boost != 1.0) {
		b := p.Boost
		boostPtr = &b
	}
	return json.Marshal(struct {
		Query              string   `json:"query"`
		Slop               int      `json:"slop,omitempty"`
		Operator           string   `json:"operator,omitempty"`
		MinimumShouldMatch any      `json:"minimum_should_match,omitempty"`
		ZeroTermsQuery     string   `json:"zero_terms_query,omitempty"`
		Fuzziness          any      `json:"fuzziness,omitempty"`
		Boost              *float64 `json:"boost,omitempty"`
	}{
		Query:              p.Query,
		Slop:               p.Slop,
		Operator:           p.Operator,
		MinimumShouldMatch: p.MinimumShouldMatch,
		ZeroTermsQuery:     p.ZeroTermsQuery,
		Fuzziness:          p.Fuzziness,
		Boost:              boostPtr,
	})
}

func (p *PhraseEntry) UnmarshalJSON(data []byte) error {
	p.Boost = 1.0
	p.HasBoost = false
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err != nil {
			return err
		}
		for k := range rawMap {
			switch k {
			case "query", "slop", "operator", "minimum_should_match", "zero_terms_query", "fuzziness", "boost", "analyzer", "max_expansions", "_name":
			default:
				return fmt.Errorf("parsing_exception: [match_phrase] unknown field [%s]", k)
			}
		}
		if _, hasQ := rawMap["query"]; !hasQ {
			return fmt.Errorf("parsing_exception: [match_phrase] missing required [query] field")
		}
		var full struct {
			Query              any             `json:"query"`
			Slop               int             `json:"slop"`
			Operator           string          `json:"operator"`
			MinimumShouldMatch any             `json:"minimum_should_match"`
			ZeroTermsQuery     string          `json:"zero_terms_query"`
			Fuzziness          any             `json:"fuzziness"`
			Boost              json.RawMessage `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		if isNonScalarOrNullValue(full.Query) {
			return fmt.Errorf("parsing_exception: [match_phrase] query does not support non-scalar or null value")
		}
		p.Query = fmt.Sprintf("%v", full.Query)
		if full.Slop < 0 {
			return fmt.Errorf("parsing_exception: [match_phrase] slop must be non-negative, got [%d]", full.Slop)
		}
		p.Slop = full.Slop
		if err := validateQueryOperator(full.Operator, "match_phrase"); err != nil {
			return err
		}
		p.Operator = strings.ToLower(strings.TrimSpace(full.Operator))
		p.MinimumShouldMatch = full.MinimumShouldMatch
		if err := validateZeroTermsQuery(full.ZeroTermsQuery, "match_phrase"); err != nil {
			return err
		}
		p.ZeroTermsQuery = full.ZeroTermsQuery
		p.Fuzziness = full.Fuzziness
		if len(full.Boost) > 0 {
			b, err := parseOptionalNonNegativeBoost(full.Boost)
			if err != nil {
				return err
			}
			if b != nil {
				p.Boost = *b
				p.HasBoost = true
			}
		}
		return nil
	}
	var raw any
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if isNonScalarOrNullValue(raw) {
		return fmt.Errorf("parsing_exception: [match_phrase] query does not support non-scalar or null value")
	}
	p.Query = fmt.Sprintf("%v", raw)
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
	Fuzziness          any      `json:"fuzziness,omitempty"`
	Lenient            *bool    `json:"lenient,omitempty"`
	Boost              *float64 `json:"boost,omitempty"`
}

func (mmq *MultiMatchQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "query", "fields", "type", "operator", "slop", "minimum_should_match", "tie_breaker",
			"zero_terms_query", "fuzziness", "lenient", "boost", "analyzer", "prefix_length",
			"max_expansions", "fuzzy_rewrite", "fuzzy_transpositions",
			"auto_generate_synonyms_phrase_query", "cutoff_frequency", "rewrite", "_name":
		default:
			return fmt.Errorf("parsing_exception: [multi_match] unknown field [%s]", k)
		}
	}
	type plain MultiMatchQuery
	var raw struct {
		plain
		Fields any             `json:"fields"`
		Boost  json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*mmq = MultiMatchQuery(raw.plain)
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		mmq.Boost = b
	}
	switch strings.ToLower(strings.TrimSpace(mmq.Type)) {
	case "", "best_fields", "most_fields", "cross_fields", "phrase", "phrase_prefix", "bool_prefix":
		mmq.Type = strings.ToLower(strings.TrimSpace(mmq.Type))
	default:
		return fmt.Errorf("parsing_exception: [multi_match] unsupported type [%s]", mmq.Type)
	}
	if err := validateQueryOperator(mmq.Operator, "multi_match"); err != nil {
		return err
	}
	if err := validateZeroTermsQuery(mmq.ZeroTermsQuery, "multi_match"); err != nil {
		return err
	}
	if mmq.Slop < 0 {
		return fmt.Errorf("parsing_exception: [multi_match] slop must be non-negative, got [%d]", mmq.Slop)
	}
	if mmq.TieBreaker != nil && (*mmq.TieBreaker < 0 || *mmq.TieBreaker > 1.0 || math.IsNaN(*mmq.TieBreaker)) {
		return fmt.Errorf("parsing_exception: [multi_match] tie_breaker must be in [0.0, 1.0], got [%v]", *mmq.TieBreaker)
	}
	if raw.Fields != nil {
		fields, err := parseFlexibleStringSlice(raw.Fields)
		if err != nil {
			return err
		}
		mmq.Fields = fields
	}
	return nil
}

type QueryStringQuery struct {
	Query                           string   `json:"query"`
	DefaultField                    string   `json:"default_field,omitempty"`
	Fields                          []string `json:"fields,omitempty"`
	DefaultOperator                 string   `json:"default_operator,omitempty"`
	Operator                        string   `json:"operator,omitempty"`
	MinimumShouldMatch              any      `json:"minimum_should_match,omitempty"`
	QuoteFieldSuffix                string   `json:"quote_field_suffix,omitempty"`
	Flags                           string   `json:"flags,omitempty"`
	TimeZone                        string   `json:"time_zone,omitempty"`
	Type                            string   `json:"type,omitempty"`
	TieBreaker                      *float64 `json:"tie_breaker,omitempty"`
	PhraseSlop                      int      `json:"phrase_slop,omitempty"`
	Fuzziness                       any      `json:"fuzziness,omitempty"`
	FuzzyTranspositions             *bool    `json:"fuzzy_transpositions,omitempty"`
	Lenient                         *bool    `json:"lenient,omitempty"`
	ZeroTermsQuery                  string   `json:"zero_terms_query,omitempty"`
	AnalyzeWildcard                 *bool    `json:"analyze_wildcard,omitempty"`
	AllowLeadingWildcard            *bool    `json:"allow_leading_wildcard,omitempty"`
	AutoGenerateSynonymsPhraseQuery *bool    `json:"auto_generate_synonyms_phrase_query,omitempty"`
	Boost                           *float64 `json:"boost,omitempty"`
}

func (qsq *QueryStringQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "query", "default_field", "fields", "default_operator", "operator", "minimum_should_match",
			"quote_field_suffix", "quote_analyzer", "analyzer", "escape", "flags", "time_zone", "type",
			"tie_breaker", "phrase_slop", "fuzziness", "fuzzy_transpositions", "fuzzy_max_expansions",
			"fuzzy_prefix_length", "fuzzy_rewrite", "lenient", "zero_terms_query", "analyze_wildcard",
			"allow_leading_wildcard", "auto_generate_synonyms_phrase_query", "enable_position_increments",
			"max_determinized_states", "split_on_whitespace", "rewrite", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [query_string] unknown field [%s]", k)
		}
	}
	type plain QueryStringQuery
	var raw struct {
		plain
		Query  any             `json:"query"`
		Fields any             `json:"fields"`
		Boost  json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*qsq = QueryStringQuery(raw.plain)
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		qsq.Boost = b
	}
	if err := validateQueryOperator(qsq.DefaultOperator, "query_string"); err != nil {
		return err
	}
	if err := validateQueryOperator(qsq.Operator, "query_string"); err != nil {
		return err
	}
	if err := validateZeroTermsQuery(qsq.ZeroTermsQuery, "query_string"); err != nil {
		return err
	}
	if qsq.PhraseSlop < 0 {
		return fmt.Errorf("parsing_exception: [query_string] phrase_slop must be non-negative, got [%d]", qsq.PhraseSlop)
	}
	if qsq.TieBreaker != nil && (*qsq.TieBreaker < 0 || *qsq.TieBreaker > 1.0 || math.IsNaN(*qsq.TieBreaker)) {
		return fmt.Errorf("parsing_exception: [query_string] tie_breaker must be in [0.0, 1.0], got [%v]", *qsq.TieBreaker)
	}
	if raw.Query != nil {
		qsq.Query = formatFlexibleScalarString(raw.Query)
	}
	if raw.Fields != nil {
		fields, err := parseFlexibleStringSlice(raw.Fields)
		if err != nil {
			return err
		}
		qsq.Fields = fields
	}
	return nil
}

type NestedQuery struct {
	Path           string         `json:"path"`
	Query          Query          `json:"query"`
	ScoreMode      string         `json:"score_mode,omitempty"`
	IgnoreUnmapped bool           `json:"ignore_unmapped,omitempty"`
	Boost          *float64       `json:"boost,omitempty"`
	InnerHits      *InnerHitsSpec `json:"inner_hits,omitempty"`
	Name           string         `json:"_name,omitempty"`
}

func (nq *NestedQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "path", "query", "score_mode", "ignore_unmapped", "inner_hits", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [nested] unknown field [%s]", k)
		}
	}
	rawQuery, hasQuery := rawMap["query"]
	if !hasQuery || len(bytes.TrimSpace(rawQuery)) == 0 || bytes.Equal(bytes.TrimSpace(rawQuery), []byte("null")) {
		return fmt.Errorf("parsing_exception: [nested] missing required [query] field")
	}
	var raw struct {
		Path           string          `json:"path"`
		Query          Query           `json:"query"`
		ScoreMode      string          `json:"score_mode"`
		IgnoreUnmapped any             `json:"ignore_unmapped"`
		Boost          json.RawMessage `json:"boost"`
		InnerHits      *InnerHitsSpec  `json:"inner_hits"`
		Name           string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Path) == "" {
		return fmt.Errorf("parsing_exception: [nested] requires non-empty [path]")
	}
	switch strings.ToLower(strings.TrimSpace(raw.ScoreMode)) {
	case "", "avg", "sum", "min", "max", "none":
		nq.ScoreMode = strings.ToLower(strings.TrimSpace(raw.ScoreMode))
	default:
		return fmt.Errorf("parsing_exception: [nested] invalid score_mode [%s]", raw.ScoreMode)
	}
	if raw.IgnoreUnmapped != nil {
		iu, err := parseFlexibleBool(raw.IgnoreUnmapped)
		if err != nil {
			return fmt.Errorf("parsing_exception: [nested] %w", err)
		}
		nq.IgnoreUnmapped = iu
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		nq.Boost = b
	}
	nq.Path = raw.Path
	nq.Query = raw.Query
	nq.InnerHits = raw.InnerHits
	nq.Name = raw.Name
	return nil
}

type ConstantScoreQuery struct {
	Filter Query    `json:"filter"`
	Boost  *float64 `json:"boost,omitempty"`
	Name   string   `json:"_name,omitempty"`
}

func (csq *ConstantScoreQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "filter", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [constant_score] unknown field [%s]", k)
		}
	}
	rawFilter, hasFilter := rawMap["filter"]
	if !hasFilter || len(bytes.TrimSpace(rawFilter)) == 0 || bytes.Equal(bytes.TrimSpace(rawFilter), []byte("null")) {
		return fmt.Errorf("parsing_exception: [constant_score] missing required [filter] field")
	}
	var raw struct {
		Filter Query           `json:"filter"`
		Boost  json.RawMessage `json:"boost"`
		Name   string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	csq.Filter = raw.Filter
	csq.Name = raw.Name
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		csq.Boost = b
	}
	return nil
}

// DecayFunctionSpec models a `gauss`, `exp`, or `linear` decay function inside `function_score`.
type DecayFunctionSpec struct {
	Field          string   `json:"-"`
	Origin         any      `json:"origin"`
	Scale          any      `json:"scale"`
	Offset         any      `json:"offset,omitempty"`
	Decay          *float64 `json:"decay,omitempty"`
	MultiValueMode string   `json:"multi_value_mode,omitempty"`
}

func (df DecayFunctionSpec) MarshalJSON() ([]byte, error) {
	inner := map[string]any{
		"origin": df.Origin,
		"scale":  df.Scale,
	}
	if df.Offset != nil {
		inner["offset"] = df.Offset
	}
	if df.Decay != nil {
		inner["decay"] = *df.Decay
	}
	m := map[string]any{}
	if df.Field != "" {
		m[df.Field] = inner
	}
	if df.MultiValueMode != "" {
		m["multi_value_mode"] = df.MultiValueMode
	}
	return json.Marshal(m)
}

func (df *DecayFunctionSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	var fieldKeys []string
	for k, v := range rawMap {
		if k == "multi_value_mode" {
			var mvm string
			if err := json.Unmarshal(v, &mvm); err != nil {
				return fmt.Errorf("parsing_exception: invalid [multi_value_mode] in decay function")
			}
			switch strings.ToLower(strings.TrimSpace(mvm)) {
			case "", "min", "max", "avg", "sum":
				df.MultiValueMode = strings.ToLower(strings.TrimSpace(mvm))
			default:
				return fmt.Errorf("parsing_exception: invalid multi_value_mode [%s] in decay function", mvm)
			}
			continue
		}
		fieldKeys = append(fieldKeys, k)
	}
	if len(fieldKeys) != 1 {
		return fmt.Errorf("parsing_exception: decay function must specify exactly one field, got %d", len(fieldKeys))
	}
	df.Field = fieldKeys[0]
	var innerMap map[string]json.RawMessage
	if err := json.Unmarshal(rawMap[df.Field], &innerMap); err != nil {
		return fmt.Errorf("parsing_exception: decay function field [%s] must be an object", df.Field)
	}
	for k := range innerMap {
		switch k {
		case "origin", "scale", "offset", "decay", "multi_value_mode":
		default:
			return fmt.Errorf("parsing_exception: unknown field [%s] in decay function for [%s]", k, df.Field)
		}
	}
	if _, hasOrigin := innerMap["origin"]; !hasOrigin {
		return fmt.Errorf("parsing_exception: decay function for [%s] requires [origin]", df.Field)
	}
	if _, hasScale := innerMap["scale"]; !hasScale {
		return fmt.Errorf("parsing_exception: decay function for [%s] requires [scale]", df.Field)
	}
	var inner struct {
		Origin         any             `json:"origin"`
		Scale          any             `json:"scale"`
		Offset         any             `json:"offset"`
		Decay          json.RawMessage `json:"decay"`
		MultiValueMode string          `json:"multi_value_mode"`
	}
	dec := json.NewDecoder(bytes.NewReader(rawMap[df.Field]))
	dec.UseNumber()
	if err := dec.Decode(&inner); err != nil {
		return err
	}
	if inner.Origin == nil || inner.Scale == nil {
		return fmt.Errorf("parsing_exception: decay function for [%s] requires non-null [origin] and [scale]", df.Field)
	}
	df.Origin = inner.Origin
	df.Scale = inner.Scale
	df.Offset = inner.Offset
	if inner.MultiValueMode != "" && df.MultiValueMode == "" {
		switch strings.ToLower(strings.TrimSpace(inner.MultiValueMode)) {
		case "min", "max", "avg", "sum":
			df.MultiValueMode = strings.ToLower(strings.TrimSpace(inner.MultiValueMode))
		default:
			return fmt.Errorf("parsing_exception: invalid multi_value_mode [%s] in decay function", inner.MultiValueMode)
		}
	}
	if len(inner.Decay) > 0 {
		d, err := parseOptionalNonNegativeBoost(inner.Decay)
		if err != nil || d == nil || *d <= 0 || *d >= 1.0 {
			return fmt.Errorf("parsing_exception: [decay] must be in (0.0, 1.0)")
		}
		df.Decay = d
	}
	return nil
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
	RandomScore      *RandomScoreSpec         `json:"random_score,omitempty"`
	Gauss            *DecayFunctionSpec       `json:"gauss,omitempty"`
	Exp              *DecayFunctionSpec       `json:"exp,omitempty"`
	Linear           *DecayFunctionSpec       `json:"linear,omitempty"`
	Name             string                   `json:"_name,omitempty"`
}

func (fsq *FunctionScoreQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "query", "functions", "score_mode", "boost_mode", "max_boost", "min_score", "boost",
			"weight", "field_value_factor", "script_score", "random_score", "gauss", "exp", "linear", "_name":
		default:
			return fmt.Errorf("parsing_exception: [function_score] unknown field [%s]", k)
		}
	}
	type plain FunctionScoreQuery
	var raw struct {
		plain
		MaxBoost json.RawMessage `json:"max_boost"`
		MinScore json.RawMessage `json:"min_score"`
		Boost    json.RawMessage `json:"boost"`
		Weight   json.RawMessage `json:"weight"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*fsq = FunctionScoreQuery(raw.plain)
	switch strings.ToLower(strings.TrimSpace(fsq.ScoreMode)) {
	case "", "multiply", "sum", "avg", "first", "max", "min":
		fsq.ScoreMode = strings.ToLower(strings.TrimSpace(fsq.ScoreMode))
	default:
		return fmt.Errorf("parsing_exception: [function_score] unknown score_mode [%s]", fsq.ScoreMode)
	}
	switch strings.ToLower(strings.TrimSpace(fsq.BoostMode)) {
	case "", "multiply", "replace", "sum", "avg", "max", "min":
		fsq.BoostMode = strings.ToLower(strings.TrimSpace(fsq.BoostMode))
	default:
		return fmt.Errorf("parsing_exception: [function_score] unknown boost_mode [%s]", fsq.BoostMode)
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		fsq.Boost = b
	}
	if len(raw.MaxBoost) > 0 {
		mb, err := parseOptionalNonNegativeBoost(raw.MaxBoost)
		if err != nil {
			return fmt.Errorf("parsing_exception: [function_score] max_boost must be a non-negative number")
		}
		fsq.MaxBoost = mb
	}
	if len(raw.MinScore) > 0 {
		ms, err := parseOptionalNonNegativeBoost(raw.MinScore)
		if err != nil {
			return fmt.Errorf("parsing_exception: [function_score] min_score must be a non-negative number")
		}
		fsq.MinScore = ms
	}
	if len(raw.Weight) > 0 {
		w, err := parseOptionalNonNegativeBoost(raw.Weight)
		if err != nil {
			return fmt.Errorf("parsing_exception: [function_score] weight must be a non-negative number")
		}
		fsq.Weight = w
	}
	topFuncs := 0
	if fsq.FieldValueFactor != nil {
		topFuncs++
	}
	if fsq.ScriptScore != nil {
		topFuncs++
	}
	if fsq.RandomScore != nil {
		topFuncs++
	}
	if fsq.Gauss != nil {
		topFuncs++
	}
	if fsq.Exp != nil {
		topFuncs++
	}
	if fsq.Linear != nil {
		topFuncs++
	}
	if topFuncs > 1 || (len(fsq.Functions) > 0 && (topFuncs > 0 || fsq.Weight != nil)) {
		return fmt.Errorf("parsing_exception: [function_score] cannot combine multiple inline score functions or [functions] with inline function")
	}
	return nil
}

type ScoreFunction = ScoreFunctionSpec

type ScoreFunctionSpec struct {
	Filter           *Query                   `json:"filter,omitempty"`
	Weight           *float64                 `json:"weight,omitempty"`
	FieldValueFactor *FieldValueFactorSpec    `json:"field_value_factor,omitempty"`
	ScriptScore      *ScriptScoreFunctionSpec `json:"script_score,omitempty"`
	RandomScore      *RandomScoreSpec         `json:"random_score,omitempty"`
	Gauss            *DecayFunctionSpec       `json:"gauss,omitempty"`
	Exp              *DecayFunctionSpec       `json:"exp,omitempty"`
	Linear           *DecayFunctionSpec       `json:"linear,omitempty"`
}

func (sfs *ScoreFunctionSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "filter", "weight", "field_value_factor", "script_score", "random_score", "gauss", "exp", "linear":
		default:
			return fmt.Errorf("parsing_exception: [function_score] unknown field [%s] in score function", k)
		}
	}
	type plain ScoreFunctionSpec
	var raw struct {
		plain
		Weight json.RawMessage `json:"weight"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*sfs = ScoreFunctionSpec(raw.plain)
	if len(raw.Weight) > 0 {
		w, err := parseOptionalNonNegativeBoost(raw.Weight)
		if err != nil {
			return fmt.Errorf("parsing_exception: [function_score] weight must be a non-negative number")
		}
		sfs.Weight = w
	}
	fnCount := 0
	if sfs.FieldValueFactor != nil {
		fnCount++
	}
	if sfs.ScriptScore != nil {
		fnCount++
	}
	if sfs.RandomScore != nil {
		fnCount++
	}
	if sfs.Gauss != nil {
		fnCount++
	}
	if sfs.Exp != nil {
		fnCount++
	}
	if sfs.Linear != nil {
		fnCount++
	}
	if fnCount > 1 {
		return fmt.Errorf("parsing_exception: [function_score] each entry in [functions] may specify at most one score function")
	}
	if fnCount == 0 && sfs.Weight == nil {
		return fmt.Errorf("parsing_exception: [function_score] each entry in [functions] must specify a score function or [weight]")
	}
	return nil
}

type RandomScoreSpec struct {
	Seed  any    `json:"seed,omitempty"`
	Field string `json:"field,omitempty"`
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

var knownAggTypeKeys = map[string]bool{
	"terms":                     true,
	"rare_terms":                true,
	"significant_terms":         true,
	"significant_text":          true,
	"date_histogram":            true,
	"auto_date_histogram":       true,
	"variable_width_histogram":  true,
	"histogram":                 true,
	"range":                     true,
	"date_range":                true,
	"ip_range":                  true,
	"composite":                 true,
	"filter":                    true,
	"filters":                   true,
	"adjacency_matrix":          true,
	"missing":                   true,
	"nested":                    true,
	"reverse_nested":            true,
	"global":                    true,
	"sampler":                   true,
	"diversified_sampler":       true,
	"cardinality":               true,
	"value_count":               true,
	"avg":                       true,
	"weighted_avg":              true,
	"sum":                       true,
	"min":                       true,
	"max":                       true,
	"median_absolute_deviation": true,
	"stats":                     true,
	"extended_stats":            true,
	"matrix_stats":              true,
	"t_test":                    true,
	"string_stats":              true,
	"boxplot":                   true,
	"percentiles":               true,
	"percentile_ranks":          true,
	"top_hits":                  true,
	"top_metrics":               true,
	"rate":                      true,
	"geo_bounds":                true,
	"geo_centroid":              true,
	"geo_distance":              true,
	"geohash_grid":              true,
	"geotile_grid":              true,
	"bucket_sort":               true,
	"cumulative_sum":            true,
	"cumulative_cardinality":    true,
	"derivative":                true,
	"moving_avg":                true,
	"moving_fn":                 true,
	"serial_diff":               true,
	"normalize":                 true,
	"avg_bucket":                true,
	"sum_bucket":                true,
	"min_bucket":                true,
	"max_bucket":                true,
	"stats_bucket":              true,
	"extended_stats_bucket":     true,
	"percentiles_bucket":        true,
	"bucket_selector":           true,
	"bucket_script":             true,
	"scripted_metric":           true,
}

// AggSpec represents an Elasticsearch aggregation definition.
type AggSpec struct {
	Terms                   *TermsAggSpec                  `json:"terms,omitempty"`
	RareTerms               *RareTermsAggSpec              `json:"rare_terms,omitempty"`
	SignificantTerms        *TermsAggSpec                  `json:"significant_terms,omitempty"`
	SignificantText         *TermsAggSpec                  `json:"significant_text,omitempty"`
	DateHistogram           *DateHistogramAggSpec          `json:"date_histogram,omitempty"`
	AutoDateHistogram       *AutoDateHistogramAggSpec      `json:"auto_date_histogram,omitempty"`
	VariableWidthHistogram  *VariableWidthHistogramAggSpec `json:"variable_width_histogram,omitempty"`
	Histogram               *HistogramAggSpec              `json:"histogram,omitempty"`
	Range                   *RangeAggSpec                  `json:"range,omitempty"`
	DateRange               *RangeAggSpec                  `json:"date_range,omitempty"`
	IPRange                 *RangeAggSpec                  `json:"ip_range,omitempty"`
	Composite               *CompositeAggSpec              `json:"composite,omitempty"`
	Filter                  *Query                         `json:"filter,omitempty"`
	Filters                 *FiltersAggSpec                `json:"filters,omitempty"`
	AdjacencyMatrix         *AdjacencyMatrixAggSpec        `json:"adjacency_matrix,omitempty"`
	Missing                 *ExistsQuery                   `json:"missing,omitempty"`
	Nested                  *NestedAggSpec                 `json:"nested,omitempty"`
	ReverseNested           map[string]any                 `json:"reverse_nested,omitempty"`
	Global                  map[string]any                 `json:"global,omitempty"`
	Sampler                 *SamplerAggSpec                `json:"sampler,omitempty"`
	DiversifiedSampler      *SamplerAggSpec                `json:"diversified_sampler,omitempty"`
	Cardinality             *MetricAggSpec                 `json:"cardinality,omitempty"`
	ValueCount              *MetricAggSpec                 `json:"value_count,omitempty"`
	Avg                     *MetricAggSpec                 `json:"avg,omitempty"`
	WeightedAvg             *WeightedAvgAggSpec            `json:"weighted_avg,omitempty"`
	Sum                     *MetricAggSpec                 `json:"sum,omitempty"`
	Min                     *MetricAggSpec                 `json:"min,omitempty"`
	Max                     *MetricAggSpec                 `json:"max,omitempty"`
	MedianAbsoluteDeviation *MetricAggSpec                 `json:"median_absolute_deviation,omitempty"`
	Stats                   *MetricAggSpec                 `json:"stats,omitempty"`
	ExtendedStats           *MetricAggSpec                 `json:"extended_stats,omitempty"`
	MatrixStats             *MatrixStatsAggSpec            `json:"matrix_stats,omitempty"`
	TTest                   *TTestAggSpec                  `json:"t_test,omitempty"`
	StringStats             *MetricAggSpec                 `json:"string_stats,omitempty"`
	Boxplot                 *MetricAggSpec                 `json:"boxplot,omitempty"`
	Percentiles             *PercentilesAggSpec            `json:"percentiles,omitempty"`
	PercentileRanks         *PercentileRanksAggSpec        `json:"percentile_ranks,omitempty"`
	TopHits                 *TopHitsAggSpec                `json:"top_hits,omitempty"`
	TopMetrics              *TopMetricsAggSpec             `json:"top_metrics,omitempty"`
	Rate                    *RateAggSpec                   `json:"rate,omitempty"`
	GeoBounds               *GeoBoundsAggSpec              `json:"geo_bounds,omitempty"`
	GeoCentroid             *MetricAggSpec                 `json:"geo_centroid,omitempty"`
	GeoDistance             *GeoDistanceAggSpec            `json:"geo_distance,omitempty"`
	GeohashGrid             *GeoGridAggSpec                `json:"geohash_grid,omitempty"`
	GeotileGrid             *GeoGridAggSpec                `json:"geotile_grid,omitempty"`
	BucketSort              *BucketSortAggSpec             `json:"bucket_sort,omitempty"`
	CumulativeSum           *PipelineAggSpec               `json:"cumulative_sum,omitempty"`
	CumulativeCardinality   *PipelineAggSpec               `json:"cumulative_cardinality,omitempty"`
	Derivative              *PipelineAggSpec               `json:"derivative,omitempty"`
	MovingAvg               *MovingAvgAggSpec              `json:"moving_avg,omitempty"`
	MovingFn                *MovingAvgAggSpec              `json:"moving_fn,omitempty"`
	SerialDiff              *SerialDiffAggSpec             `json:"serial_diff,omitempty"`
	Normalize               *NormalizeAggSpec              `json:"normalize,omitempty"`
	AvgBucket               *PipelineAggSpec               `json:"avg_bucket,omitempty"`
	SumBucket               *PipelineAggSpec               `json:"sum_bucket,omitempty"`
	MinBucket               *PipelineAggSpec               `json:"min_bucket,omitempty"`
	MaxBucket               *PipelineAggSpec               `json:"max_bucket,omitempty"`
	StatsBucket             *PipelineAggSpec               `json:"stats_bucket,omitempty"`
	ExtendedStatsBucket     *PipelineAggSpec               `json:"extended_stats_bucket,omitempty"`
	PercentilesBucket       *PercentilesBucketAggSpec      `json:"percentiles_bucket,omitempty"`
	BucketSelector          *BucketSelectorAggSpec         `json:"bucket_selector,omitempty"`
	BucketScript            *BucketSelectorAggSpec         `json:"bucket_script,omitempty"`
	ScriptedMetric          *ScriptedMetricAggSpec         `json:"scripted_metric,omitempty"`
	Aggs                    map[string]AggSpec             `json:"aggs,omitempty"`
	Aggregations            map[string]AggSpec             `json:"aggregations,omitempty"`
}

// RareTermsAggSpec models an ES `rare_terms` bucket aggregation.
type RareTermsAggSpec struct {
	Field       string `json:"field"`
	MaxDocCount *int   `json:"max_doc_count,omitempty"`
	Include     any    `json:"include,omitempty"`
	Exclude     any    `json:"exclude,omitempty"`
	Missing     any    `json:"missing,omitempty"`
}

func (r *RareTermsAggSpec) EffectiveMaxDocCount() int {
	if r != nil && r.MaxDocCount != nil && *r.MaxDocCount >= 0 {
		return *r.MaxDocCount
	}
	return 1
}

// AutoDateHistogramAggSpec models an ES `auto_date_histogram` bucket aggregation.
type AutoDateHistogramAggSpec struct {
	Field           string `json:"field"`
	Buckets         int    `json:"buckets,omitempty"`
	Format          string `json:"format,omitempty"`
	TimeZone        string `json:"time_zone,omitempty"`
	MinimumInterval string `json:"minimum_interval,omitempty"`
	Missing         any    `json:"missing,omitempty"`
	Script          any    `json:"script,omitempty"`
}

func (a *AutoDateHistogramAggSpec) EffectiveBuckets() int {
	if a != nil && a.Buckets > 0 {
		return a.Buckets
	}
	return 10
}

// VariableWidthHistogramAggSpec models an ES `variable_width_histogram` bucket aggregation.
type VariableWidthHistogramAggSpec struct {
	Field         string `json:"field"`
	Buckets       int    `json:"buckets,omitempty"`
	InitialBuffer int    `json:"initial_buffer,omitempty"`
	Missing       any    `json:"missing,omitempty"`
	Script        any    `json:"script,omitempty"`
}

func (v *VariableWidthHistogramAggSpec) EffectiveBuckets() int {
	if v != nil && v.Buckets > 0 {
		return v.Buckets
	}
	return 10
}

// WeightedAvgFieldSpec models the `value` or `weight` field/script block in `weighted_avg`.
type WeightedAvgFieldSpec struct {
	Field   string `json:"field,omitempty"`
	Missing any    `json:"missing,omitempty"`
	Script  any    `json:"script,omitempty"`
}

// WeightedAvgAggSpec models an ES `weighted_avg` metric aggregation.
type WeightedAvgAggSpec struct {
	Value     WeightedAvgFieldSpec `json:"value"`
	Weight    WeightedAvgFieldSpec `json:"weight"`
	Format    string               `json:"format,omitempty"`
	ValueType string               `json:"value_type,omitempty"`
}

// GeoBoundsAggSpec models an ES `geo_bounds` metric aggregation.
type GeoBoundsAggSpec struct {
	Field         string `json:"field"`
	WrapLongitude *bool  `json:"wrap_longitude,omitempty"`
}

// GeoDistanceAggSpec models an ES `geo_distance` bucket aggregation.
type GeoDistanceAggSpec struct {
	Field        string           `json:"field"`
	Origin       any              `json:"origin"`
	Unit         string           `json:"unit,omitempty"`
	DistanceType string           `json:"distance_type,omitempty"`
	Keyed        bool             `json:"keyed,omitempty"`
	Ranges       []RangeAggBucket `json:"ranges"`
}

// GeoGridAggSpec models an ES `geohash_grid` or `geotile_grid` bucket aggregation.
type GeoGridAggSpec struct {
	Field     string         `json:"field"`
	Precision *int           `json:"precision,omitempty"`
	Size      int            `json:"size,omitempty"`
	ShardSize int            `json:"shard_size,omitempty"`
	Bounds    map[string]any `json:"bounds,omitempty"`
}

// AdjacencyMatrixAggSpec models an ES `adjacency_matrix` bucket aggregation.
type AdjacencyMatrixAggSpec struct {
	Filters   map[string]Query `json:"filters"`
	Separator string           `json:"separator,omitempty"`
}

func (a *AdjacencyMatrixAggSpec) EffectiveSeparator() string {
	if a != nil && a.Separator != "" {
		return a.Separator
	}
	return "&"
}

// MatrixStatsAggSpec models an ES `matrix_stats` metric aggregation.
type MatrixStatsAggSpec struct {
	Fields  []string           `json:"fields"`
	Mode    string             `json:"mode,omitempty"`
	Missing map[string]float64 `json:"missing,omitempty"`
}

// TTestSampleSpec models the `a` or `b` sample block in `t_test`.
type TTestSampleSpec struct {
	Field   string `json:"field,omitempty"`
	Missing any    `json:"missing,omitempty"`
	Script  any    `json:"script,omitempty"`
	Filter  *Query `json:"filter,omitempty"`
}

// TTestAggSpec models an ES `t_test` metric aggregation.
type TTestAggSpec struct {
	A    TTestSampleSpec `json:"a"`
	B    TTestSampleSpec `json:"b"`
	Type string          `json:"type,omitempty"`
}

func (a *AggSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	typeCount := 0
	for k := range rawMap {
		if k == "aggs" || k == "aggregations" || k == "meta" {
			continue
		}
		if !knownAggTypeKeys[k] {
			return fmt.Errorf("parsing_exception: unknown aggregation type [%s]", k)
		}
		typeCount++
	}
	if typeCount == 0 {
		return fmt.Errorf("parsing_exception: aggregation definition must specify an aggregation type")
	}
	if typeCount > 1 {
		return fmt.Errorf("parsing_exception: aggregation definition cannot specify multiple aggregation types")
	}
	type plain AggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	*a = AggSpec(p)
	return nil
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
	ShardSize       int    `json:"shard_size,omitempty"`
	Field           string `json:"field,omitempty"`
	Script          any    `json:"script,omitempty"`
	MaxDocsPerValue int    `json:"max_docs_per_value,omitempty"`
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
	BucketsPath any            `json:"buckets_path,omitempty"`
	Window      int            `json:"window,omitempty"`
	Model       string         `json:"model,omitempty"`
	Script      any            `json:"script,omitempty"`
	GapPolicy   string         `json:"gap_policy,omitempty"`
	Format      string         `json:"format,omitempty"`
	Shift       *int           `json:"shift,omitempty"`
	Settings    map[string]any `json:"settings,omitempty"`
}

// ScriptedMetricAggSpec models a `scripted_metric` aggregation.
type ScriptedMetricAggSpec struct {
	InitScript    any            `json:"init_script,omitempty"`
	MapScript     any            `json:"map_script,omitempty"`
	CombineScript any            `json:"combine_script,omitempty"`
	ReduceScript  any            `json:"reduce_script,omitempty"`
	Params        map[string]any `json:"params,omitempty"`
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

func (c *CompositeAggSpec) UnmarshalJSON(data []byte) error {
	type compositeAlias CompositeAggSpec
	var alias compositeAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return fmt.Errorf("parsing_exception: invalid [composite] aggregation: %w", err)
	}
	if len(alias.Sources) == 0 {
		return fmt.Errorf("parsing_exception: [composite] aggregation requires at least one source in [sources]")
	}
	*c = CompositeAggSpec(alias)
	return nil
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
	StoredFields   any                `json:"stored_fields,omitempty"`
	Fields         []FieldRequestSpec `json:"fields,omitempty"`
	DocvalueFields []FieldRequestSpec `json:"docvalue_fields,omitempty"`
	ScriptFields   map[string]any     `json:"script_fields,omitempty"`
	Highlight      *HighlightSpec     `json:"highlight,omitempty"`
}

func (th *TopHitsAggSpec) HasStoredFieldsNone() bool {
	if th == nil {
		return false
	}
	for _, f := range StoredFieldsSlice(th.StoredFields) {
		if f == "_none_" {
			return true
		}
	}
	return false
}

func (th *TopHitsAggSpec) EffectiveFieldSpecs() []FieldRequestSpec {
	if th == nil {
		return nil
	}
	sfList := StoredFieldsSlice(th.StoredFields)
	if len(th.Fields) == 0 && len(th.DocvalueFields) == 0 && len(sfList) == 0 {
		return nil
	}
	out := make([]FieldRequestSpec, 0, len(th.Fields)+len(th.DocvalueFields)+len(sfList))
	out = append(out, th.Fields...)
	out = append(out, th.DocvalueFields...)
	for _, sf := range sfList {
		if sf != "_none_" {
			out = append(out, FieldRequestSpec{Field: sf})
		}
	}
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
	Field            string `json:"field"`
	Script           any    `json:"script,omitempty"`
	Size             int    `json:"size,omitempty"`
	Missing          any    `json:"missing,omitempty"`
	MissingBucket    bool   `json:"missing_bucket,omitempty"`
	MissingOrder     string `json:"missing_order,omitempty"`
	Order            any    `json:"order,omitempty"`
	MinDocCount      *int   `json:"min_doc_count,omitempty"`
	Include          any    `json:"include,omitempty"`
	Exclude          any    `json:"exclude,omitempty"`
	ValueType        string `json:"value_type,omitempty"`
	BackgroundFilter *Query `json:"background_filter,omitempty"`
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
	Path        string          `json:"path,omitempty"`
	Filter      *Query          `json:"filter,omitempty"`
	Nested      *NestedSortSpec `json:"nested,omitempty"`
	MaxChildren *int            `json:"max_children,omitempty"`
}

type SortEntry = SortFieldSpec

type SortFieldSpec struct {
	Field          string
	Order          string
	Mode           string
	Missing        string
	Script         any
	Type           string
	Format         string
	IgnoreUnmapped bool
	Nested         *NestedSortSpec
}

type SortSpec struct {
	Entry SortFieldSpec
}

func (s SortSpec) MarshalJSON() ([]byte, error) {
	order := s.Entry.Order
	if order == "" {
		order = "asc"
	}
	if s.Entry.Field == "_script" {
		inner := map[string]any{"order": order}
		if s.Entry.Script != nil {
			inner["script"] = s.Entry.Script
		}
		if s.Entry.Type != "" {
			inner["type"] = s.Entry.Type
		}
		if s.Entry.Mode != "" {
			inner["mode"] = s.Entry.Mode
		}
		if s.Entry.Missing != "" {
			inner["missing"] = s.Entry.Missing
		}
		if s.Entry.Nested != nil {
			inner["nested"] = s.Entry.Nested
		}
		return json.Marshal(map[string]any{"_script": inner})
	}
	if s.Entry.Field == "_geo_distance" {
		if geoMap, ok := s.Entry.Script.(map[string]any); ok {
			outMap := make(map[string]any, len(geoMap)+4)
			for k, v := range geoMap {
				outMap[k] = v
			}
			if s.Entry.Order != "" {
				outMap["order"] = order
			}
			if s.Entry.Mode != "" {
				outMap["mode"] = s.Entry.Mode
			}
			if s.Entry.Missing != "" {
				outMap["missing"] = s.Entry.Missing
			}
			if s.Entry.Nested != nil {
				outMap["nested"] = s.Entry.Nested
			}
			return json.Marshal(map[string]any{"_geo_distance": outMap})
		}
		inner := map[string]any{"order": order}
		if s.Entry.Mode != "" {
			inner["mode"] = s.Entry.Mode
		}
		if s.Entry.Missing != "" {
			inner["missing"] = s.Entry.Missing
		}
		if s.Entry.Nested != nil {
			inner["nested"] = s.Entry.Nested
		}
		return json.Marshal(map[string]any{"_geo_distance": inner})
	}
	if s.Entry.Mode != "" || s.Entry.Missing != "" || s.Entry.Nested != nil || s.Entry.Type != "" || s.Entry.Format != "" || s.Entry.IgnoreUnmapped {
		inner := map[string]any{"order": order}
		if s.Entry.Mode != "" {
			inner["mode"] = s.Entry.Mode
		}
		if s.Entry.Missing != "" {
			inner["missing"] = s.Entry.Missing
		}
		if s.Entry.Type != "" {
			inner["type"] = s.Entry.Type
		}
		if s.Entry.Format != "" {
			inner["format"] = s.Entry.Format
		}
		if s.Entry.IgnoreUnmapped {
			inner["ignore_unmapped"] = true
		}
		if s.Entry.Nested != nil {
			inner["nested"] = s.Entry.Nested
		}
		return json.Marshal(map[string]any{s.Entry.Field: inner})
	}
	return json.Marshal(map[string]string{s.Entry.Field: order})
}

// SortSlice accepts either a single sort specification (`"_doc"` / `{"updatedAt": "desc"}`) or an array.
type SortSlice []SortSpec

func unmarshalSortElement(raw []byte) ([]SortSpec, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] == '{' {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &m); err != nil {
			return nil, err
		}
		if _, hasScript := m["_script"]; !hasScript {
			if _, hasGeo := m["_geo_distance"]; !hasGeo {
				reservedOpts := map[string]bool{
					"order": true, "mode": true, "missing": true, "unmapped_type": true,
					"numeric_type": true, "type": true, "format": true, "nested": true, "nested_path": true,
					"nested_filter": true, "unit": true, "distance_type": true,
					"validation_method": true, "ignore_unmapped": true,
				}
				var orderedKeys []string
				dec := json.NewDecoder(bytes.NewReader(trimmed))
				if tok, err := dec.Token(); err == nil && tok == json.Delim('{') {
					for dec.More() {
						kt, err := dec.Token()
						if err != nil {
							break
						}
						if ks, ok := kt.(string); ok {
							orderedKeys = append(orderedKeys, ks)
						}
						var skip json.RawMessage
						if err := dec.Decode(&skip); err != nil {
							break
						}
					}
				}
				if len(orderedKeys) == 0 {
					for k := range m {
						orderedKeys = append(orderedKeys, k)
					}
					sort.Strings(orderedKeys)
				}
				var fieldKeys []string
				for _, k := range orderedKeys {
					rawV := m[k]
					if len(m) > 1 && reservedOpts[k] {
						vTrim := bytes.TrimSpace(rawV)
						if len(vTrim) > 0 && vTrim[0] == '{' && k != "nested" && k != "nested_filter" {
							fieldKeys = append(fieldKeys, k)
						}
						continue
					}
					fieldKeys = append(fieldKeys, k)
				}
				if len(fieldKeys) > 1 {
					out := make([]SortSpec, 0, len(fieldKeys))
					for _, fk := range fieldKeys {
						singleBytes, err := json.Marshal(map[string]json.RawMessage{fk: m[fk]})
						if err != nil {
							return nil, err
						}
						var sp SortSpec
						if err := json.Unmarshal(singleBytes, &sp); err != nil {
							return nil, err
						}
						out = append(out, sp)
					}
					return out, nil
				}
			}
		}
	}
	var single SortSpec
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, err
	}
	return []SortSpec{single}, nil
}

func (ss *SortSlice) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*ss = nil
		return nil
	}
	if trimmed[0] == '[' {
		var rawList []json.RawMessage
		if err := json.Unmarshal(trimmed, &rawList); err != nil {
			return err
		}
		var out []SortSpec
		for _, item := range rawList {
			specs, err := unmarshalSortElement(item)
			if err != nil {
				return err
			}
			out = append(out, specs...)
		}
		*ss = out
		return nil
	}
	specs, err := unmarshalSortElement(trimmed)
	if err != nil {
		return err
	}
	*ss = specs
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
			Order        string          `json:"order"`
			Script       any             `json:"script"`
			Type         string          `json:"type"`
			Mode         string          `json:"mode"`
			Missing      any             `json:"missing"`
			Nested       *NestedSortSpec `json:"nested"`
			NestedPath   string          `json:"nested_path"`
			NestedFilter *Query          `json:"nested_filter"`
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
		scriptType := obj.Type
		if scriptType == "" {
			if typeRaw, hasType := m["type"]; hasType {
				_ = json.Unmarshal(typeRaw, &scriptType)
			}
		}
		mode := strings.ToLower(obj.Mode)
		if mode == "" {
			if modeRaw, hasMode := m["mode"]; hasMode {
				var modeStr string
				if json.Unmarshal(modeRaw, &modeStr) == nil && modeStr != "" {
					mode = strings.ToLower(modeStr)
				}
			}
		}
		missingVal := obj.Missing
		if missingVal == nil {
			if missRaw, hasMiss := m["missing"]; hasMiss {
				_ = json.Unmarshal(missRaw, &missingVal)
			}
		}
		missing := formatFlexibleScalarString(missingVal)
		nestedSpec := obj.Nested
		if nestedSpec == nil && (obj.NestedPath != "" || obj.NestedFilter != nil) {
			nestedSpec = &NestedSortSpec{Path: obj.NestedPath, Filter: obj.NestedFilter}
		}
		if nestedSpec == nil {
			if rawNested, hasNested := m["nested"]; hasNested {
				var ns NestedSortSpec
				if json.Unmarshal(rawNested, &ns) == nil && (ns.Path != "" || ns.Filter != nil) {
					nestedSpec = &ns
				}
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
		s.Entry = SortFieldSpec{
			Field:   "_script",
			Order:   order,
			Script:  obj.Script,
			Type:    scriptType,
			Mode:    mode,
			Missing: missing,
			Nested:  nestedSpec,
		}
		return nil
	}
	if rawVal, ok := m["_geo_distance"]; ok {
		order := "asc"
		var obj struct {
			Order        string          `json:"order"`
			Mode         string          `json:"mode"`
			Missing      any             `json:"missing"`
			Nested       *NestedSortSpec `json:"nested"`
			NestedPath   string          `json:"nested_path"`
			NestedFilter *Query          `json:"nested_filter"`
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
		mode := strings.ToLower(obj.Mode)
		if mode == "" {
			if modeRaw, hasMode := m["mode"]; hasMode {
				var modeStr string
				if json.Unmarshal(modeRaw, &modeStr) == nil && modeStr != "" {
					mode = strings.ToLower(modeStr)
				}
			}
		}
		missingVal := obj.Missing
		if missingVal == nil {
			if missRaw, hasMiss := m["missing"]; hasMiss {
				_ = json.Unmarshal(missRaw, &missingVal)
			}
		}
		missing := formatFlexibleScalarString(missingVal)
		nestedSpec := obj.Nested
		if nestedSpec == nil && (obj.NestedPath != "" || obj.NestedFilter != nil) {
			nestedSpec = &NestedSortSpec{Path: obj.NestedPath, Filter: obj.NestedFilter}
		}
		if nestedSpec == nil {
			if rawNested, hasNested := m["nested"]; hasNested {
				var ns NestedSortSpec
				if json.Unmarshal(rawNested, &ns) == nil && (ns.Path != "" || ns.Filter != nil) {
					nestedSpec = &ns
				}
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
		var geoMap map[string]any
		_ = json.Unmarshal(rawVal, &geoMap)
		if geoMap == nil {
			geoMap = make(map[string]any)
		}
		for _, siblingKey := range []string{"unit", "distance_type", "validation_method", "ignore_unmapped"} {
			if _, exists := geoMap[siblingKey]; !exists {
				if rawOpt, hasOpt := m[siblingKey]; hasOpt {
					var optVal any
					if json.Unmarshal(rawOpt, &optVal) == nil {
						geoMap[siblingKey] = optVal
					}
				}
			}
		}
		s.Entry = SortFieldSpec{Field: "_geo_distance", Order: order, Mode: mode, Missing: missing, Nested: nestedSpec, Script: geoMap}
		return nil
	}

	reservedOpts := map[string]bool{
		"order": true, "mode": true, "missing": true, "unmapped_type": true,
		"numeric_type": true, "type": true, "format": true, "nested": true, "nested_path": true,
		"nested_filter": true, "unit": true, "distance_type": true,
		"validation_method": true, "ignore_unmapped": true,
	}
	keys := make([]string, 0, len(m))
	for k, rawV := range m {
		if len(m) > 1 && reservedOpts[k] {
			vTrim := bytes.TrimSpace(rawV)
			if len(vTrim) > 0 && vTrim[0] == '{' && k != "nested" && k != "nested_filter" {
				keys = append(keys, k)
			}
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 && len(m) > 0 {
		for k, rawV := range m {
			var strV string
			if json.Unmarshal(rawV, &strV) == nil && (strings.EqualFold(strV, "asc") || strings.EqualFold(strV, "desc")) {
				if k != "order" || len(m) == 1 {
					keys = append(keys, k)
				}
			}
		}
		if len(keys) == 0 {
			if rawOrd, ok := m["order"]; ok {
				var strV string
				if json.Unmarshal(rawOrd, &strV) == nil && (strings.EqualFold(strV, "asc") || strings.EqualFold(strV, "desc")) {
					keys = append(keys, "order")
				}
			}
		}
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
		sortType := ""
		sortFormat := ""
		if rawOrd, hasOrd := m["order"]; hasOrd && field != "order" {
			var ordStr string
			if json.Unmarshal(rawOrd, &ordStr) == nil && ordStr != "" {
				order = ordStr
			}
		}
		if rawMode, hasMode := m["mode"]; hasMode && field != "mode" {
			_ = json.Unmarshal(rawMode, &mode)
		}
		if rawFmt, hasFmt := m["format"]; hasFmt && field != "format" {
			_ = json.Unmarshal(rawFmt, &sortFormat)
		}
		if rawMissing, hasMissing := m["missing"]; hasMissing && field != "missing" {
			var mv any
			if json.Unmarshal(rawMissing, &mv) == nil && mv != nil {
				if fv, ok := mv.(float64); ok && fv == math.Trunc(fv) && !math.IsInf(fv, 0) && !math.IsNaN(fv) {
					missing = strconv.FormatInt(int64(fv), 10)
				} else {
					missing = fmt.Sprintf("%v", mv)
				}
			}
		}
		if rawUT, hasUT := m["unmapped_type"]; hasUT && field != "unmapped_type" {
			_ = json.Unmarshal(rawUT, &sortType)
		}
		if sortType == "" {
			if rawNT, hasNT := m["numeric_type"]; hasNT && field != "numeric_type" {
				_ = json.Unmarshal(rawNT, &sortType)
			}
		}
		if sortType == "" {
			if rawT, hasT := m["type"]; hasT && field != "type" {
				_ = json.Unmarshal(rawT, &sortType)
			}
		}
		ignoreUnmapped := false
		if rawIU, hasIU := m["ignore_unmapped"]; hasIU && field != "ignore_unmapped" {
			var iuVal any
			if json.Unmarshal(rawIU, &iuVal) == nil {
				if bv, err := parseFlexibleBool(iuVal); err == nil {
					ignoreUnmapped = bv
				}
			}
		}
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
				Order          string          `json:"order"`
				Mode           string          `json:"mode"`
				Missing        any             `json:"missing"`
				UnmappedType   string          `json:"unmapped_type"`
				NumericType    string          `json:"numeric_type"`
				Type           string          `json:"type"`
				Format         string          `json:"format"`
				IgnoreUnmapped any             `json:"ignore_unmapped"`
				Nested         *NestedSortSpec `json:"nested"`
				NestedPath     string          `json:"nested_path"`
				NestedFilter   *Query          `json:"nested_filter"`
			}
			_ = json.Unmarshal(valTrimmed, &obj)
			if obj.Order != "" {
				order = obj.Order
			}
			if obj.Mode != "" {
				mode = obj.Mode
			}
			if obj.Format != "" {
				sortFormat = obj.Format
			}
			if obj.IgnoreUnmapped != nil {
				if bv, err := parseFlexibleBool(obj.IgnoreUnmapped); err == nil {
					ignoreUnmapped = bv
				}
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
			if obj.UnmappedType != "" {
				sortType = obj.UnmappedType
			} else if obj.NumericType != "" {
				sortType = obj.NumericType
			} else if obj.Type != "" {
				sortType = obj.Type
			}
			s.Entry = SortFieldSpec{Field: field, Order: strings.ToLower(order), Mode: strings.ToLower(mode), Missing: missing, Type: strings.ToLower(sortType), Format: sortFormat, IgnoreUnmapped: ignoreUnmapped, Nested: nestedSpec}
			return nil
		}
		s.Entry = SortFieldSpec{Field: field, Order: strings.ToLower(order), Mode: strings.ToLower(mode), Missing: missing, Type: strings.ToLower(sortType), Format: sortFormat, IgnoreUnmapped: ignoreUnmapped, Nested: nestedSpec}
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
			Includes any `json:"includes"`
			Excludes any `json:"excludes"`
			Include  any `json:"include"`
			Exclude  any `json:"exclude"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return err
		}
		inc1, err := parseFlexibleStringSlice(obj.Includes)
		if err != nil {
			return err
		}
		inc2, err := parseFlexibleStringSlice(obj.Include)
		if err != nil {
			return err
		}
		exc1, err := parseFlexibleStringSlice(obj.Excludes)
		if err != nil {
			return err
		}
		exc2, err := parseFlexibleStringSlice(obj.Exclude)
		if err != nil {
			return err
		}
		sf.Includes = append(inc1, inc2...)
		sf.Excludes = append(exc1, exc2...)
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
	IndexPatterns []string                  `json:"index_patterns,omitempty"`
	Patterns      []string                  `json:"patterns,omitempty"`
	Priority      *int                      `json:"priority,omitempty"`
	Order         *int                      `json:"order,omitempty"`
	ComposedOf    []string                  `json:"composed_of,omitempty"`
	Template      *IndexCreateRequest       `json:"template,omitempty"`
	Mappings      *MappingSpec              `json:"mappings,omitempty"`
	Settings      map[string]any            `json:"settings,omitempty"`
	Aliases       map[string]map[string]any `json:"aliases,omitempty"`
}

func (t *IndexTemplateRequest) EffectivePatterns() []string {
	if len(t.IndexPatterns) > 0 {
		return t.IndexPatterns
	}
	return t.Patterns
}

func (t IndexTemplateRequest) EffectivePriority() int {
	if t.Priority != nil {
		return *t.Priority
	}
	if t.Order != nil {
		return *t.Order
	}
	return 0
}

func (t *IndexTemplateRequest) EffectiveMappings() *MappingSpec {
	if t.Template != nil && t.Template.Mappings != nil {
		return t.Template.Mappings
	}
	return t.Mappings
}

func (t *IndexTemplateRequest) EffectiveSettings() map[string]any {
	if t.Template != nil && len(t.Template.Settings) > 0 {
		return t.Template.Settings
	}
	return t.Settings
}

func (t *IndexTemplateRequest) EffectiveAliases() map[string]map[string]any {
	if t.Template != nil && len(t.Template.Aliases) > 0 {
		return t.Template.Aliases
	}
	return t.Aliases
}

// RoutingMetaSpec models the `_routing` block in an Elasticsearch mapping.
type RoutingMetaSpec struct {
	Required bool `json:"required,omitempty"`
}

// MappingSpec models an Elasticsearch `_mapping` payload.
type MappingSpec struct {
	Dynamic    any                      `json:"dynamic,omitempty"`
	Subobjects *bool                    `json:"subobjects,omitempty"`
	Routing    *RoutingMetaSpec         `json:"_routing,omitempty"`
	Runtime    map[string]FieldProperty `json:"runtime,omitempty"`
	Properties map[string]FieldProperty `json:"properties,omitempty"`
}

type FieldProperty struct {
	Type            string                   `json:"type,omitempty"`
	Dynamic         any                      `json:"dynamic,omitempty"`
	Subobjects      *bool                    `json:"subobjects,omitempty"`
	Enabled         *bool                    `json:"enabled,omitempty"`
	Index           *bool                    `json:"index,omitempty"`
	DocValues       *bool                    `json:"doc_values,omitempty"`
	Path            string                   `json:"path,omitempty"`
	Value           any                      `json:"value,omitempty"`
	Script          any                      `json:"script,omitempty"`
	Analyzer        string                   `json:"analyzer,omitempty"`
	SearchAnalyzer  string                   `json:"search_analyzer,omitempty"`
	Normalizer      string                   `json:"normalizer,omitempty"`
	Format          string                   `json:"format,omitempty"`
	Dims            int                      `json:"dims,omitempty"`
	Dimension       int                      `json:"dimension,omitempty"`
	Similarity      string                   `json:"similarity,omitempty"`
	MultiValued     bool                     `json:"multi_valued,omitempty"`
	UpgradedArray   bool                     `json:"upgraded_array,omitempty"`
	CopyTo          any                      `json:"copy_to,omitempty"`
	NullValue       any                      `json:"null_value,omitempty"`
	IgnoreAbove     int                      `json:"ignore_above,omitempty"`
	IgnoreMalformed *bool                    `json:"ignore_malformed,omitempty"`
	Coerce          *bool                    `json:"coerce,omitempty"`
	ScalingFactor   float64                  `json:"scaling_factor,omitempty"`
	Fields          map[string]FieldProperty `json:"fields,omitempty"`
	Properties      map[string]FieldProperty `json:"properties,omitempty"`
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
	AutoGeneratedID bool            `json:"-"` // True when _id was omitted and generated via NextAutoID()
	Pipeline        string          // Optional per-item ingest pipeline override
	Routing         string          // Optional per-item routing value
	IfSeqNo         *int64          // Optional optimistic concurrency _seq_no
	IfPrimaryTerm   *int64          // Optional optimistic concurrency _primary_term
	Version         *int64          // Optional external/internal version check
	VersionType     string          // Optional version_type ("internal", "external", "external_gte")
	RetryOnConflict *int            // Optional retry_on_conflict count
	RequireAlias    *bool           `json:"require_alias,omitempty"`
	DocAsUpsert     *bool           `json:"doc_as_upsert,omitempty"`
	DetectNoop      *bool           `json:"detect_noop,omitempty"`
	SourceFilter    *SourceFilter   `json:"_source,omitempty"`
	SourceIncludes  any             `json:"_source_includes,omitempty"`
	SourceExcludes  any             `json:"_source_excludes,omitempty"`
	Source          json.RawMessage // Verbatim raw JSON line for `_source` (or update payload)
	ParseErr        string          // Per-item validation or JSON error (isolated to this bulk item)
}

type bulkActionMeta struct {
	Index             string        `json:"_index"`
	ID                any           `json:"_id"`
	Pipeline          string        `json:"pipeline,omitempty"`
	Routing           string        `json:"routing,omitempty"`
	UnderscoreRouting string        `json:"_routing,omitempty"`
	IfSeqNo           *int64        `json:"if_seq_no,omitempty"`
	UnderscoreIfSeqNo *int64        `json:"_if_seq_no,omitempty"`
	IfPrimaryTerm     *int64        `json:"if_primary_term,omitempty"`
	UnderscorePrimTrm *int64        `json:"_if_primary_term,omitempty"`
	Version           *int64        `json:"version,omitempty"`
	UnderscoreVersion *int64        `json:"_version,omitempty"`
	VersionType       string        `json:"version_type,omitempty"`
	UnderscoreVerType string        `json:"_version_type,omitempty"`
	RetryOnConflict   *int          `json:"retry_on_conflict,omitempty"`
	UnderscoreRetry   *int          `json:"_retry_on_conflict,omitempty"`
	RequireAlias      any           `json:"require_alias,omitempty"`
	DocAsUpsert       any           `json:"doc_as_upsert,omitempty"`
	DetectNoop        any           `json:"detect_noop,omitempty"`
	SourceFilter      *SourceFilter `json:"_source,omitempty"`
	SourceIncludes    any           `json:"_source_includes,omitempty"`
	SourceExcludes    any           `json:"_source_excludes,omitempty"`
}

func parseBulkSourcePatternList(raw any) []string {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case string:
		var out []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	case []string:
		return v
	case []any:
		var out []string
		for _, item := range v {
			if s := strings.TrimSpace(formatFlexibleScalarString(item)); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
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
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&actionLine); err != nil {
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
		if meta.ID != nil {
			op.ID = fmt.Sprintf("%v", meta.ID)
		}
		op.Pipeline = meta.Pipeline
		op.Routing = meta.Routing
		if op.Routing == "" {
			op.Routing = meta.UnderscoreRouting
		}
		op.IfSeqNo = meta.IfSeqNo
		if op.IfSeqNo == nil {
			op.IfSeqNo = meta.UnderscoreIfSeqNo
		}
		op.IfPrimaryTerm = meta.IfPrimaryTerm
		if op.IfPrimaryTerm == nil {
			op.IfPrimaryTerm = meta.UnderscorePrimTrm
		}
		op.Version = meta.Version
		if op.Version == nil {
			op.Version = meta.UnderscoreVersion
		}
		op.VersionType = meta.VersionType
		if op.VersionType == "" {
			op.VersionType = meta.UnderscoreVerType
		}
		op.RetryOnConflict = meta.RetryOnConflict
		if op.RetryOnConflict == nil {
			op.RetryOnConflict = meta.UnderscoreRetry
		}
		if meta.RequireAlias != nil {
			if b, err := parseFlexibleBool(meta.RequireAlias); err == nil {
				op.RequireAlias = &b
			}
		}
		if meta.DocAsUpsert != nil {
			if b, err := parseFlexibleBool(meta.DocAsUpsert); err == nil {
				op.DocAsUpsert = &b
			}
		}
		if meta.DetectNoop != nil {
			if b, err := parseFlexibleBool(meta.DetectNoop); err == nil {
				op.DetectNoop = &b
			}
		}
		op.SourceFilter = meta.SourceFilter
		op.SourceIncludes = meta.SourceIncludes
		op.SourceExcludes = meta.SourceExcludes
		incList := parseBulkSourcePatternList(meta.SourceIncludes)
		excList := parseBulkSourcePatternList(meta.SourceExcludes)
		if len(incList) > 0 || len(excList) > 0 {
			if op.SourceFilter == nil {
				op.SourceFilter = &SourceFilter{}
			}
			op.SourceFilter.Includes = append(op.SourceFilter.Includes, incList...)
			op.SourceFilter.Excludes = append(op.SourceFilter.Excludes, excList...)
		}
		if op.ID == "" {
			if op.Action == "index" || op.Action == "create" {
				op.ID = NextAutoID()
				op.AutoGeneratedID = true
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
