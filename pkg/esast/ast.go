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
	KNN            KNNSlice           `json:"knn,omitempty"`
	PostFilter     *Query             `json:"post_filter,omitempty"`
	From           *int               `json:"from,omitempty"`
	Size           *int               `json:"size,omitempty"`
	Aggs           map[string]AggSpec `json:"aggs,omitempty"`
	Aggregations   map[string]AggSpec `json:"aggregations,omitempty"`
	Sort           SortSlice          `json:"sort,omitempty"`
	SearchAfter    []any              `json:"search_after,omitempty"`
	Source         *SourceFilter      `json:"_source,omitempty"`
	TrackTotalHits any                `json:"track_total_hits,omitempty"`
	Highlight      *HighlightSpec     `json:"highlight,omitempty"`
	Collapse       *CollapseSpec      `json:"collapse,omitempty"`
	PIT            *PITSpec           `json:"pit,omitempty"`
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

type CollapseSpec struct {
	Field string `json:"field"`
}

type HighlightSpec struct {
	PreTags  []string       `json:"pre_tags,omitempty"`
	PostTags []string       `json:"post_tags,omitempty"`
	Fields   map[string]any `json:"fields,omitempty"`
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
	Ids               *IdsQuery                `json:"ids,omitempty"`
	Range             map[string]RangeCond     `json:"range,omitempty"`
	Exists            *ExistsQuery             `json:"exists,omitempty"`
	Prefix            map[string]PrefixEntry   `json:"prefix,omitempty"`
	Wildcard          map[string]WildcardEntry `json:"wildcard,omitempty"`
	Regexp            map[string]RegexpEntry   `json:"regexp,omitempty"`
	Match             map[string]MatchEntry    `json:"match,omitempty"`
	MatchPhrase       map[string]PhraseEntry   `json:"match_phrase,omitempty"`
	MatchPhrasePrefix map[string]PhraseEntry   `json:"match_phrase_prefix,omitempty"`
	MatchBoolPrefix   map[string]PhraseEntry   `json:"match_bool_prefix,omitempty"`
	MultiMatch        *MultiMatchQuery         `json:"multi_match,omitempty"`
	QueryString       *QueryStringQuery        `json:"query_string,omitempty"`
	SimpleQueryString *QueryStringQuery        `json:"simple_query_string,omitempty"`
	Nested            *NestedQuery             `json:"nested,omitempty"`
	ConstantScore     *ConstantScoreQuery      `json:"constant_score,omitempty"`
	FunctionScore     *FunctionScoreQuery      `json:"function_score,omitempty"`
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
	"ids":                 true,
	"range":               true,
	"exists":              true,
	"prefix":              true,
	"wildcard":            true,
	"regexp":              true,
	"match":               true,
	"match_phrase":        true,
	"match_phrase_prefix": true,
	"match_bool_prefix":   true,
	"multi_match":         true,
	"query_string":        true,
	"simple_query_string": true,
	"nested":              true,
	"constant_score":      true,
	"function_score":      true,
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

// TermsQuery handles `"terms": {"field": ["a", "b"], "boost": 1.0}` where Java clients
// serialize `"boost"` as a sibling key alongside the field name.
type TermsQuery struct {
	Fields map[string][]any
	Boost  float64
}

func (tq *TermsQuery) UnmarshalJSON(data []byte) error {
	tq.Boost = 1.0
	tq.Fields = make(map[string][]any)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		if k == "boost" {
			_ = json.Unmarshal(v, &tq.Boost)
			continue
		}
		var arr []any
		if err := json.Unmarshal(v, &arr); err == nil {
			tq.Fields[k] = arr
		}
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
	Slop     int      `json:"slop,omitempty"`
	Boost    *float64 `json:"boost,omitempty"`
}

type QueryStringQuery struct {
	Query           string   `json:"query"`
	DefaultField    string   `json:"default_field,omitempty"`
	Fields          []string `json:"fields,omitempty"`
	DefaultOperator string   `json:"default_operator,omitempty"`
}

type NestedQuery struct {
	Path           string `json:"path"`
	Query          Query  `json:"query"`
	ScoreMode      string `json:"score_mode,omitempty"`
	IgnoreUnmapped bool   `json:"ignore_unmapped,omitempty"`
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
	Terms         *TermsAggSpec         `json:"terms,omitempty"`
	DateHistogram *DateHistogramAggSpec `json:"date_histogram,omitempty"`
	Histogram     *HistogramAggSpec     `json:"histogram,omitempty"`
	Range         *RangeAggSpec         `json:"range,omitempty"`
	DateRange     *RangeAggSpec         `json:"date_range,omitempty"`
	Composite     *CompositeAggSpec     `json:"composite,omitempty"`
	Filter        *Query                `json:"filter,omitempty"`
	Filters       *FiltersAggSpec       `json:"filters,omitempty"`
	Missing       *ExistsQuery          `json:"missing,omitempty"`
	Nested        *NestedAggSpec        `json:"nested,omitempty"`
	Cardinality   *MetricAggSpec        `json:"cardinality,omitempty"`
	ValueCount    *MetricAggSpec        `json:"value_count,omitempty"`
	Avg           *MetricAggSpec        `json:"avg,omitempty"`
	Sum           *MetricAggSpec        `json:"sum,omitempty"`
	Min           *MetricAggSpec        `json:"min,omitempty"`
	Max           *MetricAggSpec        `json:"max,omitempty"`
	Stats         *MetricAggSpec        `json:"stats,omitempty"`
	Percentiles   *PercentilesAggSpec   `json:"percentiles,omitempty"`
	TopHits       *TopHitsAggSpec       `json:"top_hits,omitempty"`
	Aggs          map[string]AggSpec    `json:"aggs,omitempty"`
	Aggregations  map[string]AggSpec    `json:"aggregations,omitempty"`
}

type CompositeAggSpec struct {
	Size    int                  `json:"size,omitempty"`
	Sources []map[string]AggSpec `json:"sources,omitempty"`
	After   map[string]any       `json:"after,omitempty"`
}

type FiltersAggSpec struct {
	Filters map[string]Query `json:"filters,omitempty"`
}

type PercentilesAggSpec struct {
	Field    string    `json:"field"`
	Percents []float64 `json:"percents,omitempty"`
}

func (p *PercentilesAggSpec) EffectivePercents() []float64 {
	if len(p.Percents) > 0 {
		return p.Percents
	}
	return []float64{1.0, 5.0, 25.0, 50.0, 75.0, 95.0, 99.0}
}

type TopHitsAggSpec struct {
	Size   *int          `json:"size,omitempty"`
	Sort   SortSlice     `json:"sort,omitempty"`
	Source *SourceFilter `json:"_source,omitempty"`
}

func (th *TopHitsAggSpec) EffectiveSize() int {
	if th == nil || th.Size == nil || *th.Size <= 0 {
		return 3
	}
	if *th.Size > 100 {
		return 100
	}
	return *th.Size
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

type DateHistogramAggSpec struct {
	Field            string `json:"field"`
	CalendarInterval string `json:"calendar_interval,omitempty"`
	FixedInterval    string `json:"fixed_interval,omitempty"`
	Interval         string `json:"interval,omitempty"`
	TimeZone         string `json:"time_zone,omitempty"`
	MinDocCount      *int   `json:"min_doc_count,omitempty"`
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
	Field       string  `json:"field"`
	Interval    float64 `json:"interval"`
	Offset      float64 `json:"offset,omitempty"`
	MinDocCount *int    `json:"min_doc_count,omitempty"`
}

type RangeAggSpec struct {
	Field  string           `json:"field"`
	Ranges []RangeAggBucket `json:"ranges"`
}

type RangeAggBucket struct {
	Key  string `json:"key,omitempty"`
	From any    `json:"from,omitempty"`
	To   any    `json:"to,omitempty"`
}

func (b RangeAggBucket) EffectiveKey() string {
	if b.Key != "" {
		return b.Key
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
	Field string `json:"field"`
}

type SortEntry = SortFieldSpec

type SortFieldSpec struct {
	Field string
	Order string
}

type SortSpec struct {
	Entry SortFieldSpec
}

func (s SortSpec) MarshalJSON() ([]byte, error) {
	order := s.Entry.Order
	if order == "" {
		order = "asc"
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
	Disabled bool
	Includes []string
	Excludes []string
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
	Analyzer       string                   `json:"analyzer,omitempty"`
	SearchAnalyzer string                   `json:"search_analyzer,omitempty"`
	Normalizer     string                   `json:"normalizer,omitempty"`
	Format         string                   `json:"format,omitempty"`
	Dims           int                      `json:"dims,omitempty"`
	Dimension      int                      `json:"dimension,omitempty"`
	Similarity     string                   `json:"similarity,omitempty"`
	MultiValued    bool                     `json:"multi_valued,omitempty"`
	Fields         map[string]FieldProperty `json:"fields,omitempty"`
	Properties     map[string]FieldProperty `json:"properties,omitempty"`
}

func (fp FieldProperty) EffectiveDims() int {
	if fp.Dims > 0 {
		return fp.Dims
	}
	return fp.Dimension
}

// BulkOperation represents a single parsed action from an Elasticsearch `/_bulk` NDJSON stream.
type BulkOperation struct {
	Action   string          // "index", "create", "update", "delete"
	Index    string          // Target index name
	ID       string          // Document _id
	Source   json.RawMessage // Verbatim raw JSON line for `_source` (or update payload)
	ParseErr string          // Per-item validation or JSON error (isolated to this bulk item)
}

type bulkActionMeta struct {
	Index string `json:"_index"`
	ID    string `json:"_id"`
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
