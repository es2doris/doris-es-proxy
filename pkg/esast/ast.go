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
	"strings"
)

// SearchRequest models an Elasticsearch / OpenSearch `/_search` request payload.
type SearchRequest struct {
	Query          *Query                 `json:"query,omitempty"`
	PostFilter     *Query                 `json:"post_filter,omitempty"`
	From           *int                   `json:"from,omitempty"`
	Size           *int                   `json:"size,omitempty"`
	Aggs           map[string]AggSpec     `json:"aggs,omitempty"`
	Aggregations   map[string]AggSpec     `json:"aggregations,omitempty"`
	Sort           []SortSpec             `json:"sort,omitempty"`
	Source         *SourceFilter          `json:"_source,omitempty"`
	TrackTotalHits any                    `json:"track_total_hits,omitempty"`
	Highlight      map[string]any         `json:"highlight,omitempty"`
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
	Term              map[string]TermEntry     `json:"term,omitempty"`
	Terms             map[string][]any         `json:"terms,omitempty"`
	Ids               *IdsQuery                `json:"ids,omitempty"`
	Range             map[string]RangeCond     `json:"range,omitempty"`
	Exists            *ExistsQuery             `json:"exists,omitempty"`
	Prefix            map[string]PrefixEntry   `json:"prefix,omitempty"`
	Wildcard          map[string]WildcardEntry `json:"wildcard,omitempty"`
	Regexp            map[string]RegexpEntry   `json:"regexp,omitempty"`
	Match             map[string]MatchEntry    `json:"match,omitempty"`
	MatchPhrase       map[string]PhraseEntry   `json:"match_phrase,omitempty"`
	MatchPhrasePrefix map[string]PhraseEntry   `json:"match_phrase_prefix,omitempty"`
	MultiMatch        *MultiMatchQuery         `json:"multi_match,omitempty"`
	QueryString       *QueryStringQuery        `json:"query_string,omitempty"`
	SimpleQueryString *QueryStringQuery        `json:"simple_query_string,omitempty"`
	Nested            *NestedQuery             `json:"nested,omitempty"`
	ConstantScore     *ConstantScoreQuery      `json:"constant_score,omitempty"`
	FunctionScore     *FunctionScoreQuery      `json:"function_score,omitempty"`
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
	Value           any
	Boost           float64
	CaseInsensitive bool
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

type RangeCond struct {
	GT       any    `json:"gt,omitempty"`
	GTE      any    `json:"gte,omitempty"`
	LT       any    `json:"lt,omitempty"`
	LTE      any    `json:"lte,omitempty"`
	Format   string `json:"format,omitempty"`
	TimeZone string `json:"time_zone,omitempty"`
}

type PrefixEntry struct {
	Value           string
	CaseInsensitive bool
}

func (p *PrefixEntry) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Value           string `json:"value"`
			CaseInsensitive bool   `json:"case_insensitive"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		p.Value = full.Value
		p.CaseInsensitive = full.CaseInsensitive
		return nil
	}
	return json.Unmarshal(trimmed, &p.Value)
}

type WildcardEntry struct {
	Value           string
	CaseInsensitive bool
}

func (w *WildcardEntry) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Value           string `json:"value"`
			Wildcard        string `json:"wildcard"`
			CaseInsensitive bool   `json:"case_insensitive"`
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
		return nil
	}
	return json.Unmarshal(trimmed, &w.Value)
}

type RegexpEntry struct {
	Value string
}

func (r *RegexpEntry) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		r.Value = full.Value
		return nil
	}
	return json.Unmarshal(trimmed, &r.Value)
}

type MatchEntry struct {
	Query    any
	Operator string
	Boost    float64
}

func (m *MatchEntry) UnmarshalJSON(data []byte) error {
	m.Boost = 1.0
	m.Operator = "or"
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Query    any      `json:"query"`
			Operator string   `json:"operator"`
			Boost    *float64 `json:"boost"`
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
		return nil
	}
	return json.Unmarshal(trimmed, &m.Query)
}

type PhraseEntry struct {
	Query string
	Slop  int
	Boost float64
}

func (p *PhraseEntry) UnmarshalJSON(data []byte) error {
	p.Boost = 1.0
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var full struct {
			Query string   `json:"query"`
			Slop  int      `json:"slop"`
			Boost *float64 `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		p.Query = full.Query
		p.Slop = full.Slop
		if full.Boost != nil {
			p.Boost = *full.Boost
		}
		return nil
	}
	return json.Unmarshal(trimmed, &p.Query)
}

type MultiMatchQuery struct {
	Query    any      `json:"query"`
	Fields   []string `json:"fields,omitempty"`
	Type     string   `json:"type,omitempty"`
	Operator string   `json:"operator,omitempty"`
	Boost    *float64 `json:"boost,omitempty"`
}

type QueryStringQuery struct {
	Query           string   `json:"query"`
	DefaultField    string   `json:"default_field,omitempty"`
	Fields          []string `json:"fields,omitempty"`
	DefaultOperator string   `json:"default_operator,omitempty"`
}

type NestedQuery struct {
	Path       string `json:"path"`
	Query      Query  `json:"query"`
	ScoreMode  string `json:"score_mode,omitempty"`
	IgnoreUnmapped bool `json:"ignore_unmapped,omitempty"`
}

type ConstantScoreQuery struct {
	Filter Query    `json:"filter"`
	Boost  *float64 `json:"boost,omitempty"`
}

type FunctionScoreQuery struct {
	Query     *Query              `json:"query,omitempty"`
	Functions []ScoreFunctionSpec `json:"functions,omitempty"`
	ScoreMode string              `json:"score_mode,omitempty"`
	BoostMode string              `json:"boost_mode,omitempty"`
	MaxBoost  *float64            `json:"max_boost,omitempty"`
	Boost     *float64            `json:"boost,omitempty"`
}

type ScoreFunctionSpec struct {
	Filter           *Query                `json:"filter,omitempty"`
	Weight           *float64              `json:"weight,omitempty"`
	FieldValueFactor *FieldValueFactorSpec `json:"field_value_factor,omitempty"`
}

type FieldValueFactorSpec struct {
	Field    string   `json:"field"`
	Factor   *float64 `json:"factor,omitempty"`
	Modifier string   `json:"modifier,omitempty"`
	Missing  *float64 `json:"missing,omitempty"`
}

// AggSpec represents an Elasticsearch aggregation definition.
type AggSpec struct {
	Terms         *TermsAggSpec      `json:"terms,omitempty"`
	Filter        *Query             `json:"filter,omitempty"`
	Missing       *ExistsQuery       `json:"missing,omitempty"`
	Nested        *NestedAggSpec     `json:"nested,omitempty"`
	Cardinality   *MetricAggSpec     `json:"cardinality,omitempty"`
	Avg           *MetricAggSpec     `json:"avg,omitempty"`
	Sum           *MetricAggSpec     `json:"sum,omitempty"`
	Min           *MetricAggSpec     `json:"min,omitempty"`
	Max           *MetricAggSpec     `json:"max,omitempty"`
	Aggs          map[string]AggSpec `json:"aggs,omitempty"`
	Aggregations  map[string]AggSpec `json:"aggregations,omitempty"`
}

func (a *AggSpec) SubAggs() map[string]AggSpec {
	if len(a.Aggs) > 0 {
		return a.Aggs
	}
	return a.Aggregations
}

type TermsAggSpec struct {
	Field   string `json:"field"`
	Size    int    `json:"size,omitempty"`
	Missing any    `json:"missing,omitempty"`
}

type NestedAggSpec struct {
	Path string `json:"path"`
}

type MetricAggSpec struct {
	Field string `json:"field"`
}

type SortFieldSpec struct {
	Field string
	Order string
}

type SortSpec struct {
	Entry SortFieldSpec
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
	for field, rawVal := range m {
		order := "asc"
		valTrimmed := bytes.TrimSpace(rawVal)
		if len(valTrimmed) > 0 && valTrimmed[0] == '"' {
			_ = json.Unmarshal(valTrimmed, &order)
		} else if len(valTrimmed) > 0 && valTrimmed[0] == '{' {
			var obj struct {
				Order string `json:"order"`
			}
			_ = json.Unmarshal(valTrimmed, &obj)
			if obj.Order != "" {
				order = obj.Order
			}
		}
		s.Entry = SortFieldSpec{Field: field, Order: strings.ToLower(order)}
		break
	}
	return nil
}

type SourceFilter struct {
	Fetch    bool
	Includes []string
	Excludes []string
}

func (sf *SourceFilter) UnmarshalJSON(data []byte) error {
	sf.Fetch = true
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("false")) {
		sf.Fetch = false
		return nil
	}
	if bytes.Equal(trimmed, []byte("true")) {
		return nil
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &sf.Includes)
	}
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var obj struct {
			Includes []string `json:"includes"`
			Excludes []string `json:"excludes"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return err
		}
		sf.Includes = obj.Includes
		sf.Excludes = obj.Excludes
	}
	return nil
}

// IndexCreateRequest models `PUT /<index>` with `settings`, `mappings`, and `aliases`.
type IndexCreateRequest struct {
	Settings map[string]any            `json:"settings,omitempty"`
	Mappings *MappingSpec              `json:"mappings,omitempty"`
	Aliases  map[string]map[string]any `json:"aliases,omitempty"`
}

// MappingSpec models an Elasticsearch `_mapping` payload.
type MappingSpec struct {
	Dynamic    any                      `json:"dynamic,omitempty"`
	Properties map[string]FieldProperty `json:"properties,omitempty"`
}

type FieldProperty struct {
	Type       string                   `json:"type,omitempty"`
	Analyzer   string                   `json:"analyzer,omitempty"`
	Normalizer string                   `json:"normalizer,omitempty"`
	Fields     map[string]FieldProperty `json:"fields,omitempty"`
	Properties map[string]FieldProperty `json:"properties,omitempty"`
}

// BulkOperation represents a single parsed action from an Elasticsearch `/_bulk` NDJSON stream.
type BulkOperation struct {
	Action  string          // "index", "create", "update", "delete"
	Index   string          // Target index name
	ID      string          // Document _id
	Source  json.RawMessage // Verbatim raw JSON line for `_source` (or update payload)
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
		var actionEnvelope map[string]struct {
			Index string `json:"_index"`
			ID    string `json:"_id"`
		}
		if err := json.Unmarshal(line, &actionEnvelope); err != nil {
			return nil, fmt.Errorf("invalid bulk action metadata line: %w", err)
		}
		var op BulkOperation
		for act, meta := range actionEnvelope {
			op.Action = act
			op.Index = meta.Index
			if op.Index == "" {
				op.Index = defaultIndex
			}
			op.ID = meta.ID
			break
		}
		if op.Action != "delete" {
			if !scanner.Scan() {
				return nil, fmt.Errorf("unexpected EOF waiting for bulk source line after %q action", op.Action)
			}
			srcLine := bytes.TrimSpace(scanner.Bytes())
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
