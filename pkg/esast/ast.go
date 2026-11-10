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
	"encoding/base64"
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
	Retriever        *RetrieverSpec           `json:"-"`
	SubSearches      []SubSearchSpec          `json:"sub_searches,omitempty"`
	Rank             *RankSpec                `json:"rank,omitempty"`
	retrieverLowered bool                     `json:"-"`
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
	Slice            *SliceSpec               `json:"slice,omitempty"`
	Fields           []FieldRequestSpec       `json:"fields,omitempty"`
	DocvalueFields   []FieldRequestSpec       `json:"docvalue_fields,omitempty"`
	StoredFields     any                      `json:"stored_fields,omitempty"`
	ScriptFields     map[string]any           `json:"script_fields,omitempty"`
	RuntimeMappings  map[string]FieldProperty `json:"runtime_mappings,omitempty"`
	Suggest          map[string]SuggestSpec   `json:"suggest,omitempty"`
}

// SubSearchSpec models an entry in `sub_searches`.
type SubSearchSpec struct {
	Query *Query `json:"query,omitempty"`
	Name  string `json:"_name,omitempty"`
}

func (s *SubSearchSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("parsing_exception: [sub_searches] entry cannot be null")
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return fmt.Errorf("parsing_exception: [sub_searches] entry must be an object: %w", err)
	}
	for k := range rawMap {
		switch k {
		case "query", "_name":
		default:
			return fmt.Errorf("parsing_exception: [sub_searches] unknown field [%s]", k)
		}
	}
	rawQuery, hasQuery := rawMap["query"]
	if !hasQuery {
		return fmt.Errorf("parsing_exception: [sub_searches] requires [query]")
	}
	qTrim := bytes.TrimSpace(rawQuery)
	if len(qTrim) == 0 || bytes.Equal(qTrim, []byte("null")) || bytes.Equal(qTrim, []byte("{}")) {
		return fmt.Errorf("parsing_exception: [sub_searches] [query] must be a non-empty query object")
	}
	var q Query
	if err := json.Unmarshal(qTrim, &q); err != nil {
		return err
	}
	s.Query = &q
	if rawName, hasName := rawMap["_name"]; hasName {
		var nameStr string
		if err := json.Unmarshal(rawName, &nameStr); err != nil {
			return fmt.Errorf("parsing_exception: [sub_searches] [_name] must be a string: %w", err)
		}
		s.Name = nameStr
	}
	return nil
}

// RankSpec models top-level `rank` in a search request.
type RankSpec struct {
	RRF *RRFSpec `json:"rrf,omitempty"`
}

func (r *RankSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return fmt.Errorf("parsing_exception: [rank] must be an object: %w", err)
	}
	if len(rawMap) != 1 {
		return fmt.Errorf("parsing_exception: [rank] must specify exactly one rank method, got %d", len(rawMap))
	}
	for k, v := range rawMap {
		switch k {
		case "rrf":
			vTrim := bytes.TrimSpace(v)
			if len(vTrim) == 0 || bytes.Equal(vTrim, []byte("null")) {
				return fmt.Errorf("parsing_exception: [rrf] cannot be null")
			}
			var rrf RRFSpec
			if err := json.Unmarshal(vTrim, &rrf); err != nil {
				return err
			}
			r.RRF = &rrf
		default:
			return fmt.Errorf("parsing_exception: [rank] unknown field [%s]", k)
		}
	}
	if r.RRF == nil {
		return fmt.Errorf("parsing_exception: [rank] requires [rrf]")
	}
	return nil
}

// RRFSpec models reciprocal rank fusion parameters.
type RRFSpec struct {
	WindowSize     *int   `json:"window_size,omitempty"`
	RankWindowSize *int   `json:"rank_window_size,omitempty"`
	RankConstant   *int   `json:"rank_constant,omitempty"`
	Filter         *Query `json:"filter,omitempty"`
}

func (r *RRFSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return fmt.Errorf("parsing_exception: [rrf] must be an object: %w", err)
	}
	for k := range rawMap {
		switch k {
		case "window_size", "rank_window_size", "rank_constant", "filter":
		default:
			return fmt.Errorf("parsing_exception: [rrf] unknown field [%s]", k)
		}
	}
	_, hasWin := rawMap["window_size"]
	_, hasRankWin := rawMap["rank_window_size"]
	if hasWin && hasRankWin {
		return fmt.Errorf("parsing_exception: [rrf] cannot specify both [window_size] and [rank_window_size]")
	}
	type plain RRFSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.RankWindowSize != nil && p.WindowSize == nil {
		p.WindowSize = p.RankWindowSize
	}
	if p.WindowSize != nil && *p.WindowSize < 1 {
		return fmt.Errorf("illegal_argument_exception: [rrf] [window_size] must be >= 1, got [%d]", *p.WindowSize)
	}
	if p.RankConstant != nil && *p.RankConstant < 1 {
		return fmt.Errorf("illegal_argument_exception: [rrf] [rank_constant] must be >= 1, got [%d]", *p.RankConstant)
	}
	*r = RRFSpec(p)
	return nil
}

// RetrieverSpec models an Elasticsearch 8.x `retriever` tree node.
type RetrieverSpec struct {
	Standard               *StandardRetrieverSpec               `json:"standard,omitempty"`
	KNN                    *KNNRetrieverSpec                    `json:"knn,omitempty"`
	RRF                    *RRFRetrieverSpec                    `json:"rrf,omitempty"`
	Rule                   *RuleRetrieverSpec                   `json:"rule,omitempty"`
	TextSimilarityReranker *TextSimilarityRerankerRetrieverSpec `json:"text_similarity_reranker,omitempty"`
}

type StandardRetrieverSpec struct {
	Query          *Query        `json:"query,omitempty"`
	Filter         QuerySlice    `json:"filter,omitempty"`
	Collapse       *CollapseSpec `json:"collapse,omitempty"`
	MinScore       *float64      `json:"min_score,omitempty"`
	RankWindowSize *int          `json:"rank_window_size,omitempty"`
}

type KNNRetrieverSpec struct {
	Field              string         `json:"field"`
	QueryVector        []float64      `json:"query_vector,omitempty"`
	QueryVectorBuilder map[string]any `json:"query_vector_builder,omitempty"`
	K                  int            `json:"k,omitempty"`
	NumCandidates      int            `json:"num_candidates,omitempty"`
	Filter             QuerySlice     `json:"filter,omitempty"`
	Similarity         *float64       `json:"similarity,omitempty"`
	Boost              *float64       `json:"boost,omitempty"`
	Name               string         `json:"_name,omitempty"`
}

type RRFRetrieverSpec struct {
	Retrievers     []RetrieverSpec `json:"retrievers"`
	RankWindowSize *int            `json:"rank_window_size,omitempty"`
	RankConstant   *int            `json:"rank_constant,omitempty"`
	Filter         QuerySlice      `json:"filter,omitempty"`
}

type RuleRetrieverSpec struct {
	Retriever     *RetrieverSpec `json:"retriever"`
	RulesetIDs    []string       `json:"ruleset_ids,omitempty"`
	RulesetID     string         `json:"ruleset_id,omitempty"`
	MatchCriteria map[string]any `json:"match_criteria,omitempty"`
}

type TextSimilarityRerankerRetrieverSpec struct {
	Retriever      *RetrieverSpec `json:"retriever"`
	Field          string         `json:"field"`
	InferenceID    string         `json:"inference_id"`
	InferenceText  string         `json:"inference_text"`
	RankWindowSize *int           `json:"rank_window_size,omitempty"`
	MinScore       *float64       `json:"min_score,omitempty"`
	Filter         QuerySlice     `json:"filter,omitempty"`
}

func (r *RetrieverSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return fmt.Errorf("parsing_exception: [retriever] must be an object: %w", err)
	}
	if len(rawMap) != 1 {
		return fmt.Errorf("parsing_exception: [retriever] must specify exactly one retriever type, got %d", len(rawMap))
	}
	for k, v := range rawMap {
		switch k {
		case "standard":
			var subMap map[string]json.RawMessage
			if err := json.Unmarshal(v, &subMap); err != nil {
				return fmt.Errorf("parsing_exception: [standard] retriever must be an object: %w", err)
			}
			for sk := range subMap {
				switch sk {
				case "query", "filter", "collapse", "min_score", "rank_window_size":
				default:
					return fmt.Errorf("parsing_exception: [standard] retriever unknown field [%s]", sk)
				}
			}
			var std StandardRetrieverSpec
			if err := json.Unmarshal(v, &std); err != nil {
				return err
			}
			if std.MinScore != nil && (math.IsNaN(*std.MinScore) || math.IsInf(*std.MinScore, 0)) {
				return fmt.Errorf("parsing_exception: [standard] retriever [min_score] must be finite")
			}
			if std.RankWindowSize != nil && *std.RankWindowSize < 1 {
				return fmt.Errorf("illegal_argument_exception: [standard] retriever [rank_window_size] must be >= 1")
			}
			r.Standard = &std
		case "knn":
			var subMap map[string]json.RawMessage
			if err := json.Unmarshal(v, &subMap); err != nil {
				return fmt.Errorf("parsing_exception: [knn] retriever must be an object: %w", err)
			}
			for sk := range subMap {
				switch sk {
				case "field", "query_vector", "query_vector_builder", "k", "num_candidates", "filter", "similarity", "boost", "_name":
				default:
					return fmt.Errorf("parsing_exception: [knn] retriever unknown field [%s]", sk)
				}
			}
			type plainKNN KNNRetrieverSpec
			var rawKNN struct {
				plainKNN
				K             *int            `json:"k"`
				NumCandidates *int            `json:"num_candidates"`
				Boost         json.RawMessage `json:"boost"`
			}
			if err := json.Unmarshal(v, &rawKNN); err != nil {
				return err
			}
			knn := rawKNN.plainKNN
			if strings.TrimSpace(knn.Field) == "" {
				return fmt.Errorf("parsing_exception: [knn] retriever requires [field]")
			}
			hasVec := len(knn.QueryVector) > 0
			hasBuilder := len(knn.QueryVectorBuilder) > 0
			if hasVec == hasBuilder {
				return fmt.Errorf("parsing_exception: [knn] retriever requires exactly one of [query_vector] or [query_vector_builder]")
			}
			if rawKNN.K != nil {
				if *rawKNN.K <= 0 {
					return fmt.Errorf("illegal_argument_exception: [knn] retriever [k] must be > 0")
				}
				knn.K = *rawKNN.K
			} else {
				knn.K = 10
			}
			if rawKNN.NumCandidates != nil {
				if *rawKNN.NumCandidates <= 0 || *rawKNN.NumCandidates < knn.K {
					return fmt.Errorf("illegal_argument_exception: [knn] retriever [num_candidates] must be >= [k]")
				}
				knn.NumCandidates = *rawKNN.NumCandidates
			} else {
				knn.NumCandidates = knn.K
				if knn.NumCandidates < 10 {
					knn.NumCandidates = 10
				}
			}
			if len(rawKNN.Boost) > 0 {
				b, err := parseOptionalNonNegativeBoost(rawKNN.Boost)
				if err != nil {
					return err
				}
				knn.Boost = b
			}
			knnOut := KNNRetrieverSpec(knn)
			r.KNN = &knnOut
		case "rrf":
			var subMap map[string]json.RawMessage
			if err := json.Unmarshal(v, &subMap); err != nil {
				return fmt.Errorf("parsing_exception: [rrf] retriever must be an object: %w", err)
			}
			for sk := range subMap {
				switch sk {
				case "retrievers", "rank_window_size", "rank_constant", "filter":
				default:
					return fmt.Errorf("parsing_exception: [rrf] retriever unknown field [%s]", sk)
				}
			}
			var rrf RRFRetrieverSpec
			if err := json.Unmarshal(v, &rrf); err != nil {
				return err
			}
			if len(rrf.Retrievers) < 1 {
				return fmt.Errorf("parsing_exception: [rrf] retriever requires at least 1 child in [retrievers]")
			}
			if rrf.RankWindowSize != nil && *rrf.RankWindowSize <= 0 {
				return fmt.Errorf("illegal_argument_exception: [rrf] retriever [rank_window_size] must be > 0")
			}
			if rrf.RankConstant != nil && *rrf.RankConstant < 1 {
				return fmt.Errorf("illegal_argument_exception: [rrf] retriever [rank_constant] must be >= 1")
			}
			r.RRF = &rrf
		case "rule":
			var subMap map[string]json.RawMessage
			if err := json.Unmarshal(v, &subMap); err != nil {
				return fmt.Errorf("parsing_exception: [rule] retriever must be an object: %w", err)
			}
			for sk := range subMap {
				switch sk {
				case "retriever", "ruleset_ids", "ruleset_id", "match_criteria":
				default:
					return fmt.Errorf("parsing_exception: [rule] retriever unknown field [%s]", sk)
				}
			}
			_, hasSingleID := subMap["ruleset_id"]
			_, hasMultiIDs := subMap["ruleset_ids"]
			if hasSingleID && hasMultiIDs {
				return fmt.Errorf("parsing_exception: [rule] retriever cannot specify both [ruleset_id] and [ruleset_ids]")
			}
			var rule RuleRetrieverSpec
			if err := json.Unmarshal(v, &rule); err != nil {
				return err
			}
			if rule.Retriever == nil || (len(rule.RulesetIDs) == 0 && strings.TrimSpace(rule.RulesetID) == "") {
				return fmt.Errorf("parsing_exception: [rule] retriever requires [retriever] and [ruleset_ids]")
			}
			for _, id := range rule.RulesetIDs {
				if strings.TrimSpace(id) == "" {
					return fmt.Errorf("illegal_argument_exception: [rule] retriever [ruleset_ids] cannot contain empty strings")
				}
			}
			r.Rule = &rule
		case "text_similarity_reranker":
			var subMap map[string]json.RawMessage
			if err := json.Unmarshal(v, &subMap); err != nil {
				return fmt.Errorf("parsing_exception: [text_similarity_reranker] retriever must be an object: %w", err)
			}
			for sk := range subMap {
				switch sk {
				case "retriever", "field", "inference_id", "inference_text", "rank_window_size", "min_score", "filter":
				default:
					return fmt.Errorf("parsing_exception: [text_similarity_reranker] retriever unknown field [%s]", sk)
				}
			}
			var tsr TextSimilarityRerankerRetrieverSpec
			if err := json.Unmarshal(v, &tsr); err != nil {
				return err
			}
			if tsr.Retriever == nil || strings.TrimSpace(tsr.Field) == "" || strings.TrimSpace(tsr.InferenceID) == "" || strings.TrimSpace(tsr.InferenceText) == "" {
				return fmt.Errorf("parsing_exception: [text_similarity_reranker] requires [retriever], [field], [inference_id], and [inference_text]")
			}
			if tsr.RankWindowSize != nil && *tsr.RankWindowSize <= 0 {
				return fmt.Errorf("illegal_argument_exception: [text_similarity_reranker] [rank_window_size] must be > 0")
			}
			if tsr.MinScore != nil && (*tsr.MinScore < 0 || math.IsNaN(*tsr.MinScore) || math.IsInf(*tsr.MinScore, 0)) {
				return fmt.Errorf("illegal_argument_exception: [text_similarity_reranker] [min_score] must be a finite non-negative number")
			}
			r.TextSimilarityReranker = &tsr
		default:
			return fmt.Errorf("parsing_exception: unknown retriever [%s]", k)
		}
	}
	return nil
}

// LowerRetrieverToSearchRequest lowers an ES 8.x `retriever` tree into standard `SearchRequest` fields.
func LowerRetrieverToSearchRequest(req *SearchRequest) {
	if req == nil || req.Retriever == nil || req.retrieverLowered {
		return
	}
	lowerRetrieverNode(req.Retriever, req)
	req.retrieverLowered = true
}

func combineFiltersAsQuery(filters []Query) *Query {
	if len(filters) == 0 {
		return nil
	}
	if len(filters) == 1 {
		q := filters[0]
		return &q
	}
	cp := make([]Query, len(filters))
	copy(cp, filters)
	return &Query{Bool: &BoolQuery{Filter: QuerySlice(cp)}}
}

func lowerRetrieverNode(ret *RetrieverSpec, req *SearchRequest) {
	if ret == nil || req == nil {
		return
	}
	switch {
	case ret.Standard != nil:
		std := ret.Standard
		if std.Collapse != nil && req.Collapse == nil {
			req.Collapse = std.Collapse
		}
		if std.MinScore != nil && req.MinScore == nil {
			req.MinScore = std.MinScore
		}
		if len(std.Filter) == 0 {
			if std.Query != nil {
				req.Query = std.Query
			} else {
				req.Query = &Query{MatchAll: map[string]any{}}
			}
		} else {
			bq := &BoolQuery{Filter: std.Filter}
			if std.Query != nil {
				bq.Must = QuerySlice{*std.Query}
			}
			req.Query = &Query{Bool: bq}
		}
	case ret.KNN != nil:
		k := ret.KNN
		knnSpec := KNNQuery{
			Field:              k.Field,
			QueryVector:        k.QueryVector,
			QueryVectorBuilder: k.QueryVectorBuilder,
			K:                  k.K,
			NumCandidates:      k.NumCandidates,
			Filter:             k.Filter,
			Similarity:         k.Similarity,
			Boost:              k.Boost,
			Name:               k.Name,
		}
		req.KNN = append(req.KNN, knnSpec)
	case ret.RRF != nil:
		for i := range ret.RRF.Retrievers {
			var subReq SearchRequest
			lowerRetrieverNode(&ret.RRF.Retrievers[i], &subReq)
			if subReq.Query != nil {
				req.SubSearches = append(req.SubSearches, SubSearchSpec{Query: subReq.Query})
			}
			if len(subReq.KNN) > 0 {
				req.KNN = append(req.KNN, subReq.KNN...)
			}
		}
		req.Rank = &RankSpec{
			RRF: &RRFSpec{
				WindowSize:   ret.RRF.RankWindowSize,
				RankConstant: ret.RRF.RankConstant,
			},
		}
		if len(ret.RRF.Filter) > 0 {
			filterQ := combineFiltersAsQuery(ret.RRF.Filter)
			if req.Query == nil {
				req.Query = filterQ
			} else {
				req.Query = &Query{Bool: &BoolQuery{Must: QuerySlice{*req.Query}, Filter: ret.RRF.Filter}}
			}
		}
	case ret.Rule != nil:
		lowerRetrieverNode(ret.Rule.Retriever, req)
	case ret.TextSimilarityReranker != nil:
		lowerRetrieverNode(ret.TextSimilarityReranker.Retriever, req)
		if ret.TextSimilarityReranker.MinScore != nil && req.MinScore == nil {
			req.MinScore = ret.TextSimilarityReranker.MinScore
		}
		if len(ret.TextSimilarityReranker.Filter) > 0 {
			if req.Query == nil {
				req.Query = combineFiltersAsQuery(ret.TextSimilarityReranker.Filter)
			} else {
				req.Query = &Query{Bool: &BoolQuery{Must: QuerySlice{*req.Query}, Filter: ret.TextSimilarityReranker.Filter}}
			}
		}
	}
}

var knownSearchRequestKeys = map[string]bool{
	"query":               true,
	"retriever":           true,
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
	_, hasPIT := rawMap["pit"]
	rawPointInTime, hasPointInTime := rawMap["point_in_time"]
	if hasPIT && hasPointInTime {
		return fmt.Errorf("parsing_exception: cannot specify both [pit] and [point_in_time]")
	}
	rawRetriever, hasRetriever := rawMap["retriever"]
	if hasRetriever {
		if _, hasQ := rawMap["query"]; hasQ {
			return fmt.Errorf("parsing_exception: cannot specify both [retriever] and [query]")
		}
		if _, hasK := rawMap["knn"]; hasK {
			return fmt.Errorf("parsing_exception: cannot specify both [retriever] and [knn]")
		}
		if _, hasSub := rawMap["sub_searches"]; hasSub {
			return fmt.Errorf("parsing_exception: cannot specify both [retriever] and [sub_searches]")
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
	if rawSub, hasSub := rawMap["sub_searches"]; hasSub {
		subTrim := bytes.TrimSpace(rawSub)
		if !bytes.Equal(subTrim, []byte("null")) && len(r.SubSearches) == 0 {
			return fmt.Errorf("parsing_exception: [sub_searches] must contain at least 1 sub-search")
		}
	}
	if r.Rank != nil && r.Rank.RRF != nil && r.Rank.RRF.WindowSize != nil && r.Size != nil && *r.Rank.RRF.WindowSize < *r.Size {
		return fmt.Errorf("illegal_argument_exception: [window_size] [%d] must be greater than or equal to [size] [%d]", *r.Rank.RRF.WindowSize, *r.Size)
	}
	if hasRetriever {
		retTrim := bytes.TrimSpace(rawRetriever)
		if len(retTrim) == 0 || bytes.Equal(retTrim, []byte("null")) {
			return fmt.Errorf("parsing_exception: [retriever] cannot be null")
		}
		var ret RetrieverSpec
		if err := json.Unmarshal(retTrim, &ret); err != nil {
			return err
		}
		r.Retriever = &ret
		LowerRetrieverToSearchRequest(r)
	}
	if hasPointInTime {
		ptTrim := bytes.TrimSpace(rawPointInTime)
		if len(ptTrim) > 0 && !bytes.Equal(ptTrim, []byte("null")) {
			var pit PITSpec
			if err := json.Unmarshal(ptTrim, &pit); err != nil {
				return err
			}
			r.PIT = &pit
		}
	}
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
	if err := validateSearchRequestAggMap(r.EffectiveAggs()); err != nil {
		return err
	}
	return nil
}

func validateSearchRequestAggMap(aggs map[string]AggSpec) error {
	for _, agg := range aggs {
		if agg.Filters != nil && len(agg.Filters.Filters) == 0 && len(agg.Filters.AnonymousFilters) == 0 && !agg.Filters.OtherBucket {
			return fmt.Errorf("parsing_exception: [filters] aggregation requires non-empty [filters]")
		}
		if agg.ScriptedMetric != nil && agg.ScriptedMetric.MapScript == nil {
			return fmt.Errorf("parsing_exception: [scripted_metric] requires [map_script]")
		}
		if err := validateSearchRequestAggMap(agg.SubAggs()); err != nil {
			return err
		}
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
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "text", "prefix", "regex", "term", "phrase", "completion":
		default:
			return fmt.Errorf("parsing_exception: [suggest] unknown field [%s]", k)
		}
	}
	type alias SuggestSpec
	var a alias
	if err := json.Unmarshal(trimmed, &a); err != nil {
		return err
	}
	count := 0
	if a.Term != nil {
		count++
	}
	if a.Phrase != nil {
		count++
	}
	if a.Completion != nil {
		count++
	}
	if count == 0 {
		return fmt.Errorf("parsing_exception: [suggest] suggester must specify one of [term], [phrase], or [completion]")
	}
	if count > 1 {
		return fmt.Errorf("parsing_exception: [suggest] suggester cannot specify multiple suggester types")
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

func (ts *TermSuggestSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "size", "suggest_mode", "max_edits", "prefix_length", "min_word_length",
			"max_inspections", "min_doc_freq", "max_term_freq", "string_distance", "sort",
			"analyzer", "lowercase_terms", "shard_size", "text", "prefix":
		default:
			return fmt.Errorf("parsing_exception: [term] unknown field [%s]", k)
		}
	}
	type plain TermSuggestSpec
	var raw struct {
		plain
		Size           *int     `json:"size"`
		MaxEdits       *int     `json:"max_edits"`
		PrefixLength   *int     `json:"prefix_length"`
		MinWordLength  *int     `json:"min_word_length"`
		MaxInspections *int     `json:"max_inspections"`
		MinDocFreq     *float64 `json:"min_doc_freq"`
		MaxTermFreq    *float64 `json:"max_term_freq"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if strings.TrimSpace(p.Field) == "" {
		return fmt.Errorf("parsing_exception: [term] field is required")
	}
	if raw.Size != nil {
		if *raw.Size <= 0 {
			return fmt.Errorf("illegal_argument_exception: [term] [size] must be > 0")
		}
		p.Size = *raw.Size
	}
	switch strings.ToLower(strings.TrimSpace(p.SuggestMode)) {
	case "", "missing", "popular", "always":
	default:
		return fmt.Errorf("illegal_argument_exception: [term] unknown suggest_mode [%s]", p.SuggestMode)
	}
	switch strings.ToLower(strings.TrimSpace(p.Sort)) {
	case "", "score", "frequency":
	default:
		return fmt.Errorf("illegal_argument_exception: [term] unknown sort [%s]", p.Sort)
	}
	switch strings.ToLower(strings.TrimSpace(p.StringDistance)) {
	case "", "internal", "damerau_levenshtein", "levenshtein", "jaro_winkler", "ngram":
	default:
		return fmt.Errorf("illegal_argument_exception: [term] unknown string_distance [%s]", p.StringDistance)
	}
	if raw.MaxEdits != nil {
		if *raw.MaxEdits < 1 || *raw.MaxEdits > 2 {
			return fmt.Errorf("illegal_argument_exception: [term] [max_edits] can only be between 1 and 2")
		}
		p.MaxEdits = *raw.MaxEdits
	}
	if raw.PrefixLength != nil {
		if *raw.PrefixLength < 0 {
			return fmt.Errorf("illegal_argument_exception: [term] [prefix_length] must be >= 0")
		}
		p.PrefixLength = *raw.PrefixLength
	}
	if raw.MinWordLength != nil {
		if *raw.MinWordLength <= 0 {
			return fmt.Errorf("illegal_argument_exception: [term] [min_word_length] must be > 0")
		}
		p.MinWordLength = *raw.MinWordLength
	}
	if raw.MaxInspections != nil && *raw.MaxInspections <= 0 {
		return fmt.Errorf("illegal_argument_exception: [term] [max_inspections] must be > 0")
	}
	if raw.MinDocFreq != nil {
		if *raw.MinDocFreq < 0 {
			return fmt.Errorf("illegal_argument_exception: [term] [min_doc_freq] must be >= 0")
		}
		p.MinDocFreq = int(*raw.MinDocFreq)
	}
	if raw.MaxTermFreq != nil && *raw.MaxTermFreq < 0 {
		return fmt.Errorf("illegal_argument_exception: [term] [max_term_freq] must be >= 0")
	}
	*ts = TermSuggestSpec(p)
	return nil
}

// PhraseSuggestSpec models a `phrase` suggester configuration.
type PhraseSuggestSpec struct {
	Field     string               `json:"field"`
	Size      int                  `json:"size,omitempty"`
	MaxErrors float64              `json:"max_errors,omitempty"`
	Highlight *PhraseHighlightSpec `json:"highlight,omitempty"`
}

func (ps *PhraseSuggestSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "size", "real_word_error_likelihood", "confidence", "max_errors",
			"separator", "gram_size", "analyzer", "shard_size", "text", "prefix",
			"highlight", "direct_generator", "collate", "smoothing", "token_limit":
		default:
			return fmt.Errorf("parsing_exception: [phrase] unknown field [%s]", k)
		}
	}
	type plain PhraseSuggestSpec
	var raw struct {
		plain
		Size       *int     `json:"size"`
		GramSize   *int     `json:"gram_size"`
		MaxErrors  *float64 `json:"max_errors"`
		Confidence *float64 `json:"confidence"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if strings.TrimSpace(p.Field) == "" {
		return fmt.Errorf("parsing_exception: [phrase] field is required")
	}
	if raw.Size != nil {
		if *raw.Size <= 0 {
			return fmt.Errorf("illegal_argument_exception: [phrase] [size] must be > 0")
		}
		p.Size = *raw.Size
	}
	if raw.GramSize != nil && *raw.GramSize <= 0 {
		return fmt.Errorf("illegal_argument_exception: [phrase] [gram_size] must be > 0")
	}
	if raw.MaxErrors != nil {
		if *raw.MaxErrors < 0 {
			return fmt.Errorf("illegal_argument_exception: [phrase] [max_errors] must be >= 0")
		}
		p.MaxErrors = *raw.MaxErrors
	}
	if raw.Confidence != nil && *raw.Confidence < 0 {
		return fmt.Errorf("illegal_argument_exception: [phrase] [confidence] must be >= 0")
	}
	*ps = PhraseSuggestSpec(p)
	return nil
}

// PhraseHighlightSpec models `highlight` options on a `phrase` suggester.
type PhraseHighlightSpec struct {
	PreTag  string `json:"pre_tag,omitempty"`
	PostTag string `json:"post_tag,omitempty"`
}

func (ph *PhraseHighlightSpec) UnmarshalJSON(data []byte) error {
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
		case "pre_tag", "post_tag":
		default:
			return fmt.Errorf("parsing_exception: [phrase.highlight] unknown field [%s]", k)
		}
	}
	type plain PhraseHighlightSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	*ph = PhraseHighlightSpec(p)
	return nil
}

// CompletionFuzzySpec models the `fuzzy` options block inside a `completion` suggester.
type CompletionFuzzySpec struct {
	Enabled        bool  `json:"-"`
	Fuzziness      any   `json:"fuzziness,omitempty"`
	Transpositions *bool `json:"transpositions,omitempty"`
	MinLength      *int  `json:"min_length,omitempty"`
	PrefixLength   *int  `json:"prefix_length,omitempty"`
	UnicodeAware   *bool `json:"unicode_aware,omitempty"`
}

func (cf *CompletionFuzzySpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] != '{' {
		var val any
		if err := json.Unmarshal(trimmed, &val); err != nil {
			return fmt.Errorf("parsing_exception: [completion.fuzzy] invalid value: %w", err)
		}
		b, err := parseFlexibleBool(val)
		if err != nil {
			return fmt.Errorf("parsing_exception: [completion.fuzzy] must be a boolean or object")
		}
		cf.Enabled = b
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "fuzziness", "transpositions", "min_length", "prefix_length", "unicode_aware":
		default:
			return fmt.Errorf("parsing_exception: [completion.fuzzy] unknown field [%s]", k)
		}
	}
	var raw struct {
		Fuzziness      any  `json:"fuzziness"`
		Transpositions any  `json:"transpositions"`
		MinLength      *int `json:"min_length"`
		PrefixLength   *int `json:"prefix_length"`
		UnicodeAware   any  `json:"unicode_aware"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.Fuzziness != nil {
		switch fv := raw.Fuzziness.(type) {
		case float64:
			if fv < 0 || fv > 2 || fv != math.Trunc(fv) {
				return fmt.Errorf("illegal_argument_exception: [completion.fuzzy] invalid [fuzziness] [%v]", fv)
			}
		case string:
			fs := strings.ToUpper(strings.TrimSpace(fv))
			if fs != "0" && fs != "1" && fs != "2" && fs != "AUTO" && !strings.HasPrefix(fs, "AUTO:") {
				return fmt.Errorf("illegal_argument_exception: [completion.fuzzy] invalid [fuzziness] [%s]", fv)
			}
		default:
			return fmt.Errorf("parsing_exception: [completion.fuzzy] invalid [fuzziness] [%v]", raw.Fuzziness)
		}
		cf.Fuzziness = raw.Fuzziness
	}
	if raw.Transpositions != nil {
		b, err := parseFlexibleBool(raw.Transpositions)
		if err != nil {
			return fmt.Errorf("parsing_exception: [completion.fuzzy] [transpositions] %w", err)
		}
		cf.Transpositions = &b
	}
	if raw.MinLength != nil {
		if *raw.MinLength < 0 {
			return fmt.Errorf("illegal_argument_exception: [completion.fuzzy] [min_length] must be >= 0")
		}
		cf.MinLength = raw.MinLength
	}
	if raw.PrefixLength != nil {
		if *raw.PrefixLength < 0 {
			return fmt.Errorf("illegal_argument_exception: [completion.fuzzy] [prefix_length] must be >= 0")
		}
		cf.PrefixLength = raw.PrefixLength
	}
	if raw.UnicodeAware != nil {
		b, err := parseFlexibleBool(raw.UnicodeAware)
		if err != nil {
			return fmt.Errorf("parsing_exception: [completion.fuzzy] [unicode_aware] %w", err)
		}
		cf.UnicodeAware = &b
	}
	cf.Enabled = true
	return nil
}

// CompletionRegexSpec models the `regex` options block inside a `completion` suggester.
type CompletionRegexSpec struct {
	Flags                 string `json:"flags,omitempty"`
	MaxDeterminizedStates *int   `json:"max_determinized_states,omitempty"`
}

func (cr *CompletionRegexSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return fmt.Errorf("parsing_exception: [completion.regex] must be an object: %w", err)
	}
	for k := range rawMap {
		switch k {
		case "flags", "max_determinized_states":
		default:
			return fmt.Errorf("parsing_exception: [completion.regex] unknown field [%s]", k)
		}
	}
	type plain CompletionRegexSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.MaxDeterminizedStates != nil && *p.MaxDeterminizedStates <= 0 {
		return fmt.Errorf("illegal_argument_exception: [completion.regex] [max_determinized_states] must be > 0")
	}
	*cr = CompletionRegexSpec(p)
	return nil
}

// CompletionSuggestSpec models a `completion` suggester configuration.
type CompletionSuggestSpec struct {
	Field          string         `json:"field"`
	Size           int            `json:"size,omitempty"`
	SkipDuplicates bool           `json:"skip_duplicates,omitempty"`
	Fuzzy          map[string]any `json:"fuzzy,omitempty"`
	Regex          map[string]any `json:"regex,omitempty"`
}

func (cs *CompletionSuggestSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "size", "skip_duplicates", "fuzzy", "regex", "contexts", "analyzer", "text", "prefix":
		default:
			return fmt.Errorf("parsing_exception: [completion] unknown field [%s]", k)
		}
	}
	rawFuzzy, hasFuzzy := rawMap["fuzzy"]
	rawRegex, hasRegex := rawMap["regex"]
	hasFuzzyVal := hasFuzzy && len(bytes.TrimSpace(rawFuzzy)) > 0 && !bytes.Equal(bytes.TrimSpace(rawFuzzy), []byte("null"))
	hasRegexVal := hasRegex && len(bytes.TrimSpace(rawRegex)) > 0 && !bytes.Equal(bytes.TrimSpace(rawRegex), []byte("null"))
	if hasFuzzyVal && hasRegexVal {
		return fmt.Errorf("parsing_exception: [completion] cannot specify both [fuzzy] and [regex]")
	}
	var raw struct {
		Field          string `json:"field"`
		Size           *int   `json:"size"`
		SkipDuplicates any    `json:"skip_duplicates"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Field) == "" {
		return fmt.Errorf("parsing_exception: [completion] field is required")
	}
	var p CompletionSuggestSpec
	p.Field = raw.Field
	if raw.Size != nil {
		if *raw.Size <= 0 {
			return fmt.Errorf("illegal_argument_exception: [completion] [size] must be > 0")
		}
		p.Size = *raw.Size
	}
	if raw.SkipDuplicates != nil {
		sd, err := parseFlexibleBool(raw.SkipDuplicates)
		if err != nil {
			return fmt.Errorf("parsing_exception: [completion] [skip_duplicates] %w", err)
		}
		p.SkipDuplicates = sd
	}
	if hasFuzzyVal {
		var cf CompletionFuzzySpec
		if err := json.Unmarshal(rawFuzzy, &cf); err != nil {
			return err
		}
		if cf.Enabled {
			p.Fuzzy = make(map[string]any)
			if cf.Fuzziness != nil {
				p.Fuzzy["fuzziness"] = cf.Fuzziness
			}
			if cf.Transpositions != nil {
				p.Fuzzy["transpositions"] = *cf.Transpositions
			}
			if cf.MinLength != nil {
				p.Fuzzy["min_length"] = *cf.MinLength
			}
			if cf.PrefixLength != nil {
				p.Fuzzy["prefix_length"] = *cf.PrefixLength
			}
			if cf.UnicodeAware != nil {
				p.Fuzzy["unicode_aware"] = *cf.UnicodeAware
			}
		}
	}
	if hasRegexVal {
		var cr CompletionRegexSpec
		if err := json.Unmarshal(rawRegex, &cr); err != nil {
			return err
		}
		p.Regex = make(map[string]any)
		if cr.Flags != "" {
			p.Regex["flags"] = cr.Flags
		}
		if cr.MaxDeterminizedStates != nil {
			p.Regex["max_determinized_states"] = *cr.MaxDeterminizedStates
		}
	}
	*cs = p
	return nil
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
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("parsing_exception: [fields] field name cannot be empty")
		}
		frs.Field = s
		return nil
	}
	if trimmed[0] != '{' {
		return fmt.Errorf("parsing_exception: [fields] entry must be a string or object")
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "field", "format", "include_unmapped":
		default:
			return fmt.Errorf("parsing_exception: [fields] unknown field [%s]", k)
		}
	}
	type alias FieldRequestSpec
	var obj alias
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return err
	}
	if strings.TrimSpace(obj.Field) == "" {
		return fmt.Errorf("parsing_exception: [fields] requires non-empty [field]")
	}
	if obj.IncludeUnmapped != nil {
		b, err := parseFlexibleBool(obj.IncludeUnmapped)
		if err != nil {
			return fmt.Errorf("parsing_exception: [fields] [include_unmapped] %w", err)
		}
		obj.IncludeUnmapped = b
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
	Field              string         `json:"field,omitempty"`
	QueryVector        []float64      `json:"query_vector,omitempty"`
	QueryVectorBuilder map[string]any `json:"query_vector_builder,omitempty"`
	K                  int            `json:"k,omitempty"`
	NumCandidates      int            `json:"num_candidates,omitempty"`
	Similarity         *float64       `json:"similarity,omitempty"`
	Boost              *float64       `json:"boost,omitempty"`
	Filter             QuerySlice     `json:"filter,omitempty"`
	Name               string         `json:"_name,omitempty"`
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

func parsePositiveDuration(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "-") {
		return fmt.Errorf("parsing_exception: invalid duration [%s]: must be positive", raw)
	}
	for _, unit := range []string{"nanos", "micros", "ms", "s", "m", "h", "d", "w"} {
		if strings.HasSuffix(s, unit) {
			numPart := strings.TrimSpace(strings.TrimSuffix(s, unit))
			if numPart == "" {
				return fmt.Errorf("parsing_exception: invalid duration [%s]", raw)
			}
			v, err := strconv.ParseFloat(numPart, 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
				return fmt.Errorf("parsing_exception: invalid duration [%s]: must be > 0", raw)
			}
			return nil
		}
	}
	return fmt.Errorf("parsing_exception: invalid duration [%s]: missing or unsupported time unit", raw)
}

func (p *PITSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		if k != "id" && k != "keep_alive" {
			return fmt.Errorf("parsing_exception: [pit] unknown field [%s]", k)
		}
	}
	type plain PITSpec
	var raw plain
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.ID) == "" {
		return fmt.Errorf("parsing_exception: [pit] requires non-empty [id]")
	}
	if raw.KeepAlive != "" {
		if err := parsePositiveDuration(raw.KeepAlive); err != nil {
			return err
		}
	}
	*p = PITSpec(raw)
	return nil
}

type SliceSpec struct {
	ID    int    `json:"id"`
	Max   int    `json:"max"`
	Field string `json:"field,omitempty"`
}

func (s *SliceSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		if k != "id" && k != "max" && k != "field" {
			return fmt.Errorf("parsing_exception: [slice] unknown field [%s]", k)
		}
	}
	rawID, hasID := rawMap["id"]
	rawMax, hasMax := rawMap["max"]
	if !hasID || len(bytes.TrimSpace(rawID)) == 0 || bytes.Equal(bytes.TrimSpace(rawID), []byte("null")) {
		return fmt.Errorf("parsing_exception: [slice] requires [id]")
	}
	if !hasMax || len(bytes.TrimSpace(rawMax)) == 0 || bytes.Equal(bytes.TrimSpace(rawMax), []byte("null")) {
		return fmt.Errorf("parsing_exception: [slice] requires [max]")
	}
	type plain SliceSpec
	var raw plain
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.Max <= 1 {
		return fmt.Errorf("parsing_exception: [slice] max must be greater than 1, got [%d]", raw.Max)
	}
	if raw.ID < 0 || raw.ID >= raw.Max {
		return fmt.Errorf("parsing_exception: [slice] id must be >= 0 and < max [%d], got [%d]", raw.Max, raw.ID)
	}
	*s = SliceSpec(raw)
	return nil
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

func (ih *InnerHitsSpec) UnmarshalJSON(data []byte) error {
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
		case "name", "from", "size", "sort", "track_scores", "_source", "stored_fields",
			"fields", "docvalue_fields", "script_fields", "highlight", "collapse",
			"version", "seq_no_primary_term", "explain", "ignore_unmapped":
		default:
			return fmt.Errorf("parsing_exception: [inner_hits] unknown field [%s]", k)
		}
	}
	type plain InnerHitsSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.From < 0 {
		return fmt.Errorf("parsing_exception: [inner_hits] [from] must be >= 0")
	}
	if p.Size != nil && *p.Size < 0 {
		return fmt.Errorf("parsing_exception: [inner_hits] [size] must be >= 0")
	}
	*ih = InnerHitsSpec(p)
	return nil
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
	PreTags               []string       `json:"pre_tags,omitempty"`
	PostTags              []string       `json:"post_tags,omitempty"`
	TagSchema             string         `json:"tag_schema,omitempty"`
	TagsSchema            string         `json:"tags_schema,omitempty"`
	Encoder               string         `json:"encoder,omitempty"`
	HighlightQuery        *Query         `json:"highlight_query,omitempty"`
	RequireFieldMatch     *bool          `json:"require_field_match,omitempty"`
	MatchedFields         []string       `json:"matched_fields,omitempty"`
	FragmentSize          *int           `json:"fragment_size,omitempty"`
	NumberOfFragments     *int           `json:"number_of_fragments,omitempty"`
	NoMatchSize           *int           `json:"no_match_size,omitempty"`
	Type                  string         `json:"type,omitempty"`
	Order                 string         `json:"order,omitempty"`
	BoundaryScanner       string         `json:"boundary_scanner,omitempty"`
	BoundaryScannerLocale string         `json:"boundary_scanner_locale,omitempty"`
	BoundaryChars         string         `json:"boundary_chars,omitempty"`
	BoundaryMaxScan       *int           `json:"boundary_max_scan,omitempty"`
	FragmentOffset        *int           `json:"fragment_offset,omitempty"`
	Fragmenter            string         `json:"fragmenter,omitempty"`
	MaxAnalyzedOffset     *int           `json:"max_analyzed_offset,omitempty"`
	PhraseLimit           *int           `json:"phrase_limit,omitempty"`
	ForceSource           *bool          `json:"force_source,omitempty"`
	MaxFragmentLength     *int           `json:"max_fragment_length,omitempty"`
	Options               map[string]any `json:"options,omitempty"`
}

// HighlightField is an alias for HighlightFieldSpec.
type HighlightField = HighlightFieldSpec

func validateHighlightCommonFields(
	rawMap map[string]json.RawMessage,
	allowFields bool,
	hType, order, encoder, boundaryScanner, fragmenter, tagSchema, tagsSchema string,
	fragSize, numFrags, noMatchSize, boundaryMaxScan, fragOffset, maxAnalyzedOffset, phraseLimit *int,
	preTags, postTags []string,
) error {
	for k := range rawMap {
		if k == "fields" && allowFields {
			continue
		}
		switch k {
		case "pre_tags", "post_tags", "tag_schema", "tags_schema", "encoder", "highlight_query",
			"require_field_match", "matched_fields", "fragment_size", "number_of_fragments",
			"no_match_size", "type", "order", "boundary_scanner", "boundary_scanner_locale",
			"boundary_chars", "boundary_max_scan", "fragment_offset", "fragmenter",
			"max_analyzed_offset", "phrase_limit", "force_source", "max_fragment_length", "options":
		default:
			return fmt.Errorf("parsing_exception: [highlight] unknown field [%s]", k)
		}
	}
	switch strings.ToLower(strings.TrimSpace(hType)) {
	case "", "unified", "plain", "fvh", "fast-vector-highlighter":
	default:
		return fmt.Errorf("parsing_exception: [highlight] invalid highlighter type [%s]", hType)
	}
	switch strings.ToLower(strings.TrimSpace(order)) {
	case "", "none", "score":
	default:
		return fmt.Errorf("parsing_exception: [highlight] invalid order [%s]", order)
	}
	switch strings.ToLower(strings.TrimSpace(encoder)) {
	case "", "default", "html":
	default:
		return fmt.Errorf("parsing_exception: [highlight] invalid encoder [%s]", encoder)
	}
	switch strings.ToLower(strings.TrimSpace(boundaryScanner)) {
	case "", "chars", "sentence", "word":
	default:
		return fmt.Errorf("parsing_exception: [highlight] invalid boundary_scanner [%s]", boundaryScanner)
	}
	switch strings.ToLower(strings.TrimSpace(fragmenter)) {
	case "", "simple", "span":
	default:
		return fmt.Errorf("parsing_exception: [highlight] invalid fragmenter [%s]", fragmenter)
	}
	for _, ts := range []string{tagSchema, tagsSchema} {
		switch strings.ToLower(strings.TrimSpace(ts)) {
		case "", "styled":
		default:
			return fmt.Errorf("parsing_exception: [highlight] invalid tags_schema [%s]", ts)
		}
	}
	if fragSize != nil && *fragSize < 0 {
		return fmt.Errorf("parsing_exception: [highlight] [fragment_size] must be >= 0")
	}
	if numFrags != nil && *numFrags < 0 {
		return fmt.Errorf("parsing_exception: [highlight] [number_of_fragments] must be >= 0")
	}
	if noMatchSize != nil && *noMatchSize < 0 {
		return fmt.Errorf("parsing_exception: [highlight] [no_match_size] must be >= 0")
	}
	if boundaryMaxScan != nil && *boundaryMaxScan < 0 {
		return fmt.Errorf("parsing_exception: [highlight] [boundary_max_scan] must be >= 0")
	}
	if fragOffset != nil && *fragOffset < 0 {
		return fmt.Errorf("parsing_exception: [highlight] [fragment_offset] must be >= 0")
	}
	if maxAnalyzedOffset != nil && *maxAnalyzedOffset < 0 {
		return fmt.Errorf("parsing_exception: [highlight] [max_analyzed_offset] must be >= 0")
	}
	if phraseLimit != nil && *phraseLimit < 0 {
		return fmt.Errorf("parsing_exception: [highlight] [phrase_limit] must be >= 0")
	}
	if (len(preTags) > 0 || len(postTags) > 0) && len(preTags) != len(postTags) {
		return fmt.Errorf("parsing_exception: [highlight] requires both [pre_tags] and [post_tags] to have the same number of elements")
	}
	return nil
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
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
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
	if hfs.TagSchema == "" && hfs.TagsSchema != "" {
		hfs.TagSchema = hfs.TagsSchema
	}
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
	return validateHighlightCommonFields(
		rawMap, false,
		hfs.Type, hfs.Order, hfs.Encoder, hfs.BoundaryScanner, hfs.Fragmenter, hfs.TagSchema, hfs.TagsSchema,
		hfs.FragmentSize, hfs.NumberOfFragments, hfs.NoMatchSize, hfs.BoundaryMaxScan, hfs.FragmentOffset, hfs.MaxAnalyzedOffset, hfs.PhraseLimit,
		hfs.PreTags, hfs.PostTags,
	)
}

type HighlightSpec struct {
	PreTags               []string       `json:"pre_tags,omitempty"`
	PostTags              []string       `json:"post_tags,omitempty"`
	TagSchema             string         `json:"tag_schema,omitempty"`
	TagsSchema            string         `json:"tags_schema,omitempty"`
	Encoder               string         `json:"encoder,omitempty"`
	HighlightQuery        *Query         `json:"highlight_query,omitempty"`
	RequireFieldMatch     *bool          `json:"require_field_match,omitempty"`
	FragmentSize          *int           `json:"fragment_size,omitempty"`
	NumberOfFragments     *int           `json:"number_of_fragments,omitempty"`
	NoMatchSize           *int           `json:"no_match_size,omitempty"`
	Type                  string         `json:"type,omitempty"`
	Order                 string         `json:"order,omitempty"`
	BoundaryScanner       string         `json:"boundary_scanner,omitempty"`
	BoundaryScannerLocale string         `json:"boundary_scanner_locale,omitempty"`
	BoundaryChars         string         `json:"boundary_chars,omitempty"`
	BoundaryMaxScan       *int           `json:"boundary_max_scan,omitempty"`
	FragmentOffset        *int           `json:"fragment_offset,omitempty"`
	Fragmenter            string         `json:"fragmenter,omitempty"`
	MaxAnalyzedOffset     *int           `json:"max_analyzed_offset,omitempty"`
	PhraseLimit           *int           `json:"phrase_limit,omitempty"`
	ForceSource           *bool          `json:"force_source,omitempty"`
	MaxFragmentLength     *int           `json:"max_fragment_length,omitempty"`
	Options               map[string]any `json:"options,omitempty"`
	Fields                map[string]any `json:"fields,omitempty"`
}

func (h *HighlightSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
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
	if h.TagSchema == "" && h.TagsSchema != "" {
		h.TagSchema = h.TagsSchema
	}
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
	if err := validateHighlightCommonFields(
		rawMap, true,
		h.Type, h.Order, h.Encoder, h.BoundaryScanner, h.Fragmenter, h.TagSchema, h.TagsSchema,
		h.FragmentSize, h.NumberOfFragments, h.NoMatchSize, h.BoundaryMaxScan, h.FragmentOffset, h.MaxAnalyzedOffset, h.PhraseLimit,
		h.PreTags, h.PostTags,
	); err != nil {
		return err
	}
	if rawFields, hasFields := rawMap["fields"]; hasFields {
		ft := bytes.TrimSpace(rawFields)
		if len(ft) > 0 && !bytes.Equal(ft, []byte("null")) {
			var fMap map[string]json.RawMessage
			if err := json.Unmarshal(ft, &fMap); err != nil {
				return fmt.Errorf("parsing_exception: [highlight] [fields] must be an object: %w", err)
			}
			for fname, fRaw := range fMap {
				if strings.TrimSpace(fname) == "" {
					return fmt.Errorf("parsing_exception: [highlight] field name cannot be empty")
				}
				var hfs HighlightFieldSpec
				if err := json.Unmarshal(fRaw, &hfs); err != nil {
					return err
				}
			}
		}
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
	MatchAll          map[string]any              `json:"match_all,omitempty"`
	MatchNone         map[string]any              `json:"match_none,omitempty"`
	Bool              *BoolQuery                  `json:"bool,omitempty"`
	DisMax            *DisMaxQuery                `json:"dis_max,omitempty"`
	Boosting          *BoostingQuery              `json:"boosting,omitempty"`
	Term              map[string]TermEntry        `json:"term,omitempty"`
	Terms             *TermsQuery                 `json:"terms,omitempty"`
	TermsSet          map[string]TermsSetEntry    `json:"terms_set,omitempty"`
	Ids               *IdsQuery                   `json:"ids,omitempty"`
	Range             map[string]RangeCond        `json:"range,omitempty"`
	Exists            *ExistsQuery                `json:"exists,omitempty"`
	Prefix            map[string]PrefixEntry      `json:"prefix,omitempty"`
	Wildcard          map[string]WildcardEntry    `json:"wildcard,omitempty"`
	Regexp            map[string]RegexpEntry      `json:"regexp,omitempty"`
	Fuzzy             map[string]FuzzyEntry       `json:"fuzzy,omitempty"`
	Match             map[string]MatchEntry       `json:"match,omitempty"`
	MatchPhrase       map[string]PhraseEntry      `json:"match_phrase,omitempty"`
	MatchPhrasePrefix map[string]PhraseEntry      `json:"match_phrase_prefix,omitempty"`
	MatchBoolPrefix   map[string]PhraseEntry      `json:"match_bool_prefix,omitempty"`
	Common            map[string]CommonTermsEntry `json:"common,omitempty"`
	MultiMatch        *MultiMatchQuery            `json:"multi_match,omitempty"`
	CombinedFields    *CombinedFieldsQuery        `json:"combined_fields,omitempty"`
	QueryString       *QueryStringQuery           `json:"query_string,omitempty"`
	SimpleQueryString *QueryStringQuery           `json:"simple_query_string,omitempty"`
	Nested            *NestedQuery                `json:"nested,omitempty"`
	ConstantScore     *ConstantScoreQuery         `json:"constant_score,omitempty"`
	FunctionScore     *FunctionScoreQuery         `json:"function_score,omitempty"`
	ScriptScore       *ScriptScoreQuery           `json:"script_score,omitempty"`
	Script            *ScriptQuery                `json:"script,omitempty"`
	KNN               *KNNQuery                   `json:"knn,omitempty"`
	GeoDistance       *GeoDistanceQuery           `json:"geo_distance,omitempty"`
	GeoBoundingBox    *GeoBoundingBoxQuery        `json:"geo_bounding_box,omitempty"`
	GeoPolygon        *GeoPolygonQuery            `json:"geo_polygon,omitempty"`
	GeoShape          *GeoShapeQuery              `json:"geo_shape,omitempty"`
	Wrapper           *WrapperQuery               `json:"wrapper,omitempty"`
	Pinned            *PinnedQuery                `json:"pinned,omitempty"`
	MoreLikeThis      *MoreLikeThisQuery          `json:"more_like_this,omitempty"`
	Intervals         map[string]IntervalsRule    `json:"intervals,omitempty"`
	SpanTerm          map[string]TermEntry        `json:"span_term,omitempty"`
	SpanNear          *SpanNearQuery              `json:"span_near,omitempty"`
	SpanOr            *SpanOrQuery                `json:"span_or,omitempty"`
	SpanNot           *SpanNotQuery               `json:"span_not,omitempty"`
	SpanFirst         *SpanFirstQuery             `json:"span_first,omitempty"`
	SpanMulti         *SpanMultiQuery             `json:"span_multi,omitempty"`
	SpanContaining    *SpanPairQuery              `json:"span_containing,omitempty"`
	SpanWithin        *SpanPairQuery              `json:"span_within,omitempty"`
	FieldMaskingSpan  *FieldMaskingSpanQuery      `json:"field_masking_span,omitempty"`
	RankFeature       *RankFeatureQuery           `json:"rank_feature,omitempty"`
	DistanceFeature   *DistanceFeatureQuery       `json:"distance_feature,omitempty"`
	HasChild          *HasChildQuery              `json:"has_child,omitempty"`
	HasParent         *HasParentQuery             `json:"has_parent,omitempty"`
	ParentID          *ParentIDQuery              `json:"parent_id,omitempty"`
	Percolate         *PercolateQuery             `json:"percolate,omitempty"`
	Rule              *RuleQuerySpec              `json:"rule,omitempty"`
	SparseVector      *SparseVectorQuerySpec      `json:"sparse_vector,omitempty"`
	Name              string                      `json:"_name,omitempty"`
}

// RuleQuerySpec models an ES `rule` / `rule_query` query.
type RuleQuerySpec struct {
	Organic       *Query         `json:"organic,omitempty"`
	RulesetIDs    []string       `json:"ruleset_ids,omitempty"`
	RulesetID     string         `json:"ruleset_id,omitempty"`
	MatchCriteria map[string]any `json:"match_criteria,omitempty"`
	Boost         *float64       `json:"boost,omitempty"`
	Name          string         `json:"_name,omitempty"`
}

func (rq *RuleQuerySpec) UnmarshalJSON(data []byte) error {
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
		case "organic", "ruleset_ids", "ruleset_id", "match_criteria", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [rule] unknown field [%s]", k)
		}
	}
	type plain RuleQuerySpec
	var raw struct {
		plain
		Boost json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	hasRuleset := strings.TrimSpace(raw.RulesetID) != ""
	for _, id := range raw.RulesetIDs {
		if strings.TrimSpace(id) != "" {
			hasRuleset = true
			break
		}
	}
	if !hasRuleset {
		return fmt.Errorf("parsing_exception: [rule] requires [ruleset_ids] or [ruleset_id]")
	}
	if len(raw.MatchCriteria) == 0 {
		return fmt.Errorf("parsing_exception: [rule] requires non-empty [match_criteria]")
	}
	*rq = RuleQuerySpec(raw.plain)
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		rq.Boost = b
	}
	return nil
}

// SparseVectorQuerySpec models an ES `sparse_vector`, `text_expansion`, or `weighted_tokens` query.
type SparseVectorQuerySpec struct {
	Field         string             `json:"field"`
	InferenceID   string             `json:"inference_id,omitempty"`
	ModelID       string             `json:"model_id,omitempty"`
	Query         string             `json:"query,omitempty"`
	QueryText     string             `json:"query_text,omitempty"`
	ModelText     string             `json:"model_text,omitempty"`
	QueryVector   map[string]float64 `json:"query_vector,omitempty"`
	Tokens        map[string]float64 `json:"tokens,omitempty"`
	Prune         *bool              `json:"prune,omitempty"`
	PruningConfig map[string]any     `json:"pruning_config,omitempty"`
	Filter        *Query             `json:"filter,omitempty"`
	Boost         *float64           `json:"boost,omitempty"`
	Name          string             `json:"_name,omitempty"`
}

func (sv *SparseVectorQuerySpec) EffectiveTokens() map[string]float64 {
	if sv == nil {
		return nil
	}
	if len(sv.QueryVector) > 0 {
		return sv.QueryVector
	}
	return sv.Tokens
}

func (sv *SparseVectorQuerySpec) EffectiveQueryText() string {
	if sv == nil {
		return ""
	}
	if strings.TrimSpace(sv.Query) != "" {
		return sv.Query
	}
	if strings.TrimSpace(sv.QueryText) != "" {
		return sv.QueryText
	}
	return sv.ModelText
}

func (sv *SparseVectorQuerySpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	knownFlatKeys := map[string]bool{
		"field": true, "inference_id": true, "model_id": true,
		"query": true, "query_text": true, "model_text": true,
		"query_vector": true, "tokens": true,
		"prune": true, "pruning_config": true,
		"filter": true, "boost": true, "_name": true,
	}
	// Support field-keyed wrapper syntax used by `text_expansion` / `weighted_tokens`: `{"ml.tokens": {"model_id": "...", "model_text": "..."}}`
	if _, hasField := rawMap["field"]; !hasField && len(rawMap) == 1 {
		for k, v := range rawMap {
			if !knownFlatKeys[k] {
				vTrim := bytes.TrimSpace(v)
				if len(vTrim) > 0 && vTrim[0] == '{' {
					var innerMap map[string]json.RawMessage
					if err := json.Unmarshal(vTrim, &innerMap); err != nil {
						return err
					}
					fieldBytes, _ := json.Marshal(k)
					innerMap["field"] = fieldBytes
					reBytes, err := json.Marshal(innerMap)
					if err != nil {
						return err
					}
					trimmed = reBytes
					rawMap = innerMap
				}
			}
		}
	}
	for k := range rawMap {
		if !knownFlatKeys[k] {
			return fmt.Errorf("parsing_exception: [sparse_vector] unknown field [%s]", k)
		}
	}
	type plain SparseVectorQuerySpec
	var raw struct {
		plain
		Prune         any             `json:"prune"`
		PruningConfig map[string]any  `json:"pruning_config"`
		Boost         json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if strings.TrimSpace(p.Field) == "" {
		return fmt.Errorf("parsing_exception: [sparse_vector] requires [field]")
	}
	hasText := strings.TrimSpace(p.Query) != "" || strings.TrimSpace(p.QueryText) != "" || strings.TrimSpace(p.ModelText) != ""
	hasVec := len(p.QueryVector) > 0 || len(p.Tokens) > 0
	if !hasText && !hasVec {
		return fmt.Errorf("parsing_exception: [sparse_vector] requires either query text or [query_vector]/[tokens]")
	}
	if hasText && hasVec {
		return fmt.Errorf("parsing_exception: [sparse_vector] cannot specify both query text and [query_vector]/[tokens]")
	}
	if hasText && strings.TrimSpace(p.InferenceID) == "" && strings.TrimSpace(p.ModelID) == "" {
		return fmt.Errorf("parsing_exception: [sparse_vector] with query text requires [inference_id] or [model_id]")
	}
	for _, w := range p.QueryVector {
		if math.IsNaN(w) || math.IsInf(w, 0) {
			return fmt.Errorf("illegal_argument_exception: [sparse_vector] [query_vector] weights must be finite")
		}
	}
	for _, w := range p.Tokens {
		if math.IsNaN(w) || math.IsInf(w, 0) {
			return fmt.Errorf("illegal_argument_exception: [sparse_vector] [tokens] weights must be finite")
		}
	}
	if raw.Prune != nil {
		b, err := parseFlexibleBool(raw.Prune)
		if err != nil {
			return fmt.Errorf("parsing_exception: [sparse_vector] [prune] %w", err)
		}
		p.Prune = &b
	}
	for k, v := range raw.PruningConfig {
		switch k {
		case "tokens_freq_ratio_threshold":
			f, ok := parseBoundFloat(v)
			if !ok || f < 1 {
				return fmt.Errorf("illegal_argument_exception: [sparse_vector.pruning_config] [tokens_freq_ratio_threshold] must be >= 1")
			}
		case "tokens_weight_threshold":
			f, ok := parseBoundFloat(v)
			if !ok || f < 0 {
				return fmt.Errorf("illegal_argument_exception: [sparse_vector.pruning_config] [tokens_weight_threshold] must be >= 0")
			}
		case "only_score_pruned_tokens":
			if _, err := parseFlexibleBool(v); err != nil {
				return fmt.Errorf("parsing_exception: [sparse_vector.pruning_config] [only_score_pruned_tokens] %w", err)
			}
		default:
			return fmt.Errorf("parsing_exception: [sparse_vector.pruning_config] unknown field [%s]", k)
		}
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		p.Boost = b
	}
	*sv = SparseVectorQuerySpec(p)
	return nil
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
	"common":              true,
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
	"geo_polygon":         true,
	"geo_shape":           true,
	"wrapper":             true,
	"pinned":              true,
	"more_like_this":      true,
	"intervals":           true,
	"span_term":           true,
	"span_near":           true,
	"span_or":             true,
	"span_not":            true,
	"span_first":          true,
	"span_multi":          true,
	"span_containing":     true,
	"span_within":         true,
	"field_masking_span":  true,
	"rank_feature":        true,
	"distance_feature":    true,
	"has_child":           true,
	"has_parent":          true,
	"parent_id":           true,
	"percolate":           true,
	"rule":                true,
	"rule_query":          true,
	"sparse_vector":       true,
	"text_expansion":      true,
	"weighted_tokens":     true,
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

func extractQueryNameFromRaw(raw map[string]json.RawMessage) string {
	if rawName, ok := raw["_name"]; ok {
		var s string
		if err := json.Unmarshal(bytes.TrimSpace(rawName), &s); err == nil && s != "" {
			return s
		}
	}
	for k, rawClause := range raw {
		if k == "_name" || k == "boost" {
			continue
		}
		tc := bytes.TrimSpace(rawClause)
		if len(tc) == 0 || tc[0] != '{' {
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(tc, &m); err != nil {
			continue
		}
		if rawName, ok := m["_name"]; ok {
			var s string
			if err := json.Unmarshal(bytes.TrimSpace(rawName), &s); err == nil && s != "" {
				return s
			}
		}
		for fk, fv := range m {
			if fk == "_name" || fk == "boost" {
				continue
			}
			tfv := bytes.TrimSpace(fv)
			if len(tfv) == 0 || tfv[0] != '{' {
				continue
			}
			var innerMap map[string]json.RawMessage
			if err := json.Unmarshal(tfv, &innerMap); err != nil {
				continue
			}
			if rawName, ok := innerMap["_name"]; ok {
				var s string
				if err := json.Unmarshal(bytes.TrimSpace(rawName), &s); err == nil && s != "" {
					return s
				}
			}
		}
	}
	return ""
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
	extractedName := extractQueryNameFromRaw(raw)
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
		"range", "terms_set", "intervals",
		"term", "span_term", "prefix", "wildcard", "regexp", "fuzzy",
		"match", "match_phrase", "match_phrase_prefix", "match_bool_prefix", "common",
	} {
		if rawClause, ok := raw[clauseKey]; ok {
			reqMulti := clauseKey != "range" && clauseKey != "terms_set" && clauseKey != "intervals"
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
	if rawRuleQ, ok := raw["rule_query"]; ok {
		raw["rule"] = rawRuleQ
		delete(raw, "rule_query")
		rawModified = true
	}
	for _, svAlias := range []string{"text_expansion", "weighted_tokens"} {
		if rawSV, ok := raw[svAlias]; ok {
			raw["sparse_vector"] = rawSV
			delete(raw, svAlias)
			rawModified = true
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
		func() *float64 {
			if alias.SpanNear != nil {
				return alias.SpanNear.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.SpanOr != nil {
				return alias.SpanOr.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.SpanNot != nil {
				return alias.SpanNot.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.SpanFirst != nil {
				return alias.SpanFirst.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.SpanMulti != nil {
				return alias.SpanMulti.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.SpanContaining != nil {
				return alias.SpanContaining.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.SpanWithin != nil {
				return alias.SpanWithin.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.FieldMaskingSpan != nil {
				return alias.FieldMaskingSpan.Boost
			}
			return nil
		}(),
		func() *float64 {
			if alias.GeoDistance != nil {
				return alias.GeoDistance.Boost
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
	if b := mapBoosts["span_term"]; b != nil {
		for k, te := range alias.SpanTerm {
			if !te.HasBoost {
				te.Boost = *b
				te.HasBoost = true
				alias.SpanTerm[k] = te
			}
		}
	}
	if b := mapBoosts["intervals"]; b != nil {
		for k, ir := range alias.Intervals {
			if ir.Boost == nil {
				v := *b
				ir.Boost = &v
				alias.Intervals[k] = ir
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
	if b := mapBoosts["common"]; b != nil {
		for k, ce := range alias.Common {
			if !ce.HasBoost {
				ce.Boost = *b
				ce.HasBoost = true
				alias.Common[k] = ce
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
		{"common", len(alias.Common)},
		{"terms_set", len(alias.TermsSet)},
		{"span_term", len(alias.SpanTerm)},
		{"intervals", len(alias.Intervals)},
	} {
		if _, ok := raw[check.key]; ok && check.cnt == 0 {
			return fmt.Errorf("parsing_exception: [%s] query must specify at least one field", check.key)
		}
	}
	if alias.Name == "" && extractedName != "" {
		alias.Name = extractedName
	}
	if alias.Name == "" && alias.Percolate != nil && alias.Percolate.Name != "" {
		alias.Name = alias.Percolate.Name
	}
	if alias.Name == "" && alias.Boosting != nil && alias.Boosting.Name != "" {
		alias.Name = alias.Boosting.Name
	}
	if alias.Name == "" && alias.Wrapper != nil && alias.Wrapper.Decoded != nil && alias.Wrapper.Decoded.Name != "" {
		alias.Name = alias.Wrapper.Decoded.Name
	}
	if alias.Name == "" && alias.Rule != nil && alias.Rule.Name != "" {
		alias.Name = alias.Rule.Name
	}
	if alias.Name == "" && alias.SparseVector != nil && alias.SparseVector.Name != "" {
		alias.Name = alias.SparseVector.Name
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
	IgnoreUnmapped   bool     `json:"ignore_unmapped,omitempty"`
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
	if gd.IgnoreUnmapped {
		m["ignore_unmapped"] = true
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
		b, err := parseFlexibleBool(iu)
		if err != nil {
			return err
		}
		gd.IgnoreUnmapped = b
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
	IgnoreUnmapped   bool     `json:"ignore_unmapped,omitempty"`
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
	if gb.IgnoreUnmapped {
		m["ignore_unmapped"] = true
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
		b, err := parseFlexibleBool(iu)
		if err != nil {
			return err
		}
		gb.IgnoreUnmapped = b
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

// GeoPolygonQuery models an Elasticsearch `geo_polygon` query.
type GeoPolygonQuery struct {
	Field            string       `json:"-"`
	Points           [][2]float64 `json:"-"`
	ValidationMethod string       `json:"validation_method,omitempty"`
	IgnoreUnmapped   bool         `json:"ignore_unmapped,omitempty"`
	Boost            *float64     `json:"boost,omitempty"`
	Name             string       `json:"_name,omitempty"`
}

func (gp *GeoPolygonQuery) UnmarshalJSON(data []byte) error {
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
			return fmt.Errorf("parsing_exception: [geo_polygon] invalid [validation_method]")
		}
		switch strings.ToUpper(strings.TrimSpace(vm)) {
		case "STRICT", "IGNORE_MALFORMED", "COERCE":
			gp.ValidationMethod = strings.ToUpper(strings.TrimSpace(vm))
		default:
			return fmt.Errorf("parsing_exception: [geo_polygon] invalid validation_method [%s]", vm)
		}
	}
	if rawBoost, ok := rawMap["boost"]; ok {
		b, err := parseOptionalNonNegativeBoost(rawBoost)
		if err != nil {
			return err
		}
		gp.Boost = b
	}
	if rawName, ok := rawMap["_name"]; ok {
		var n string
		if err := json.Unmarshal(rawName, &n); err != nil {
			return fmt.Errorf("parsing_exception: [geo_polygon] invalid [_name]")
		}
		gp.Name = n
	}
	if rawIU, ok := rawMap["ignore_unmapped"]; ok {
		var iu any
		if err := json.Unmarshal(rawIU, &iu); err != nil {
			return fmt.Errorf("parsing_exception: [geo_polygon] invalid [ignore_unmapped]")
		}
		b, err := parseFlexibleBool(iu)
		if err != nil {
			return err
		}
		gp.IgnoreUnmapped = b
	}
	var fieldKeys []string
	for k := range rawMap {
		switch k {
		case "validation_method", "boost", "_name", "ignore_unmapped":
		default:
			fieldKeys = append(fieldKeys, k)
		}
	}
	if len(fieldKeys) != 1 {
		return fmt.Errorf("parsing_exception: [geo_polygon] must specify exactly one field, got %d", len(fieldKeys))
	}
	gp.Field = fieldKeys[0]
	var fieldObj struct {
		Points []json.RawMessage `json:"points"`
	}
	if err := json.Unmarshal(rawMap[gp.Field], &fieldObj); err != nil || len(fieldObj.Points) < 3 {
		return fmt.Errorf("parsing_exception: [geo_polygon] requires at least 3 [points] for [%s]", gp.Field)
	}
	pts := make([][2]float64, 0, len(fieldObj.Points))
	for _, rp := range fieldObj.Points {
		lat, lon, err := ParseGeoPoint(rp)
		if err != nil {
			return err
		}
		lat, lon, err = validateAndNormalizeGeoPoint(lat, lon, gp.ValidationMethod)
		if err != nil {
			return err
		}
		pts = append(pts, [2]float64{lat, lon})
	}
	gp.Points = pts
	return nil
}

// GeoShapeQuery models an Elasticsearch `geo_shape` query.
type GeoShapeQuery struct {
	Field          string         `json:"-"`
	Shape          map[string]any `json:"-"`
	IndexedShape   map[string]any `json:"-"`
	Relation       string         `json:"-"`
	IgnoreUnmapped bool           `json:"ignore_unmapped,omitempty"`
	Boost          *float64       `json:"boost,omitempty"`
	Name           string         `json:"_name,omitempty"`
}

func (gs *GeoShapeQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	if rawBoost, ok := rawMap["boost"]; ok {
		b, err := parseOptionalNonNegativeBoost(rawBoost)
		if err != nil {
			return err
		}
		gs.Boost = b
	}
	if rawName, ok := rawMap["_name"]; ok {
		var n string
		if err := json.Unmarshal(rawName, &n); err != nil {
			return fmt.Errorf("parsing_exception: [geo_shape] invalid [_name]")
		}
		gs.Name = n
	}
	if rawIU, ok := rawMap["ignore_unmapped"]; ok {
		var iu any
		if err := json.Unmarshal(rawIU, &iu); err != nil {
			return fmt.Errorf("parsing_exception: [geo_shape] invalid [ignore_unmapped]")
		}
		b, err := parseFlexibleBool(iu)
		if err != nil {
			return err
		}
		gs.IgnoreUnmapped = b
	}
	var fieldKeys []string
	for k := range rawMap {
		switch k {
		case "boost", "_name", "ignore_unmapped":
		default:
			fieldKeys = append(fieldKeys, k)
		}
	}
	if len(fieldKeys) != 1 {
		return fmt.Errorf("parsing_exception: [geo_shape] must specify exactly one field, got %d", len(fieldKeys))
	}
	gs.Field = fieldKeys[0]
	var specMap map[string]json.RawMessage
	if err := json.Unmarshal(rawMap[gs.Field], &specMap); err != nil {
		return fmt.Errorf("parsing_exception: [geo_shape] field [%s] must be an object", gs.Field)
	}
	for k := range specMap {
		switch k {
		case "shape", "indexed_shape", "relation", "ignore_unmapped", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [geo_shape] unknown field [%s]", k)
		}
	}
	var spec struct {
		Shape          json.RawMessage `json:"shape"`
		IndexedShape   map[string]any  `json:"indexed_shape"`
		Relation       string          `json:"relation"`
		IgnoreUnmapped any             `json:"ignore_unmapped"`
		Boost          json.RawMessage `json:"boost"`
		Name           string          `json:"_name"`
	}
	if err := json.Unmarshal(rawMap[gs.Field], &spec); err != nil {
		return fmt.Errorf("parsing_exception: [geo_shape] field [%s] must be an object", gs.Field)
	}
	if spec.IgnoreUnmapped != nil {
		b, err := parseFlexibleBool(spec.IgnoreUnmapped)
		if err != nil {
			return err
		}
		gs.IgnoreUnmapped = b
	}
	if len(spec.Boost) > 0 && gs.Boost == nil {
		b, err := parseOptionalNonNegativeBoost(spec.Boost)
		if err != nil {
			return err
		}
		gs.Boost = b
	}
	if spec.Name != "" && gs.Name == "" {
		gs.Name = spec.Name
	}
	shapeTrimmed := bytes.TrimSpace(spec.Shape)
	var shapeMap map[string]any
	if len(shapeTrimmed) > 0 && !bytes.Equal(shapeTrimmed, []byte("null")) {
		switch shapeTrimmed[0] {
		case '"':
			var wktStr string
			if err := json.Unmarshal(shapeTrimmed, &wktStr); err != nil {
				return fmt.Errorf("parsing_exception: [geo_shape] invalid WKT [shape]: %w", err)
			}
			parsedWKT, err := ParseWKTGeoShape(wktStr)
			if err != nil {
				return err
			}
			shapeMap = parsedWKT
		case '{':
			if err := json.Unmarshal(shapeTrimmed, &shapeMap); err != nil {
				return fmt.Errorf("parsing_exception: [geo_shape] invalid [shape]: %w", err)
			}
		default:
			return fmt.Errorf("parsing_exception: [geo_shape] [shape] must be an object or WKT string")
		}
	}
	if len(shapeMap) == 0 && len(spec.IndexedShape) == 0 {
		return fmt.Errorf("parsing_exception: [geo_shape] requires [shape] or [indexed_shape]")
	}
	if strings.TrimSpace(spec.Relation) != "" {
		rel := strings.ToUpper(strings.TrimSpace(spec.Relation))
		switch rel {
		case "INTERSECTS", "DISJOINT", "WITHIN", "CONTAINS":
			gs.Relation = rel
		default:
			return fmt.Errorf("parsing_exception: [geo_shape] invalid relation [%s]", spec.Relation)
		}
	} else {
		gs.Relation = "INTERSECTS"
	}
	gs.Shape = shapeMap
	gs.IndexedShape = spec.IndexedShape
	return nil
}

// ParseWKTGeoShape parses a WKT geometry string (`POINT`, `BBOX`/`ENVELOPE`, `LINESTRING`, `POLYGON`, `MULTIPOINT`, `MULTIPOLYGON`, `GEOMETRYCOLLECTION`) into a GeoJSON-like map.
func ParseWKTGeoShape(wkt string) (map[string]any, error) {
	s := strings.TrimSpace(wkt)
	openIdx := strings.IndexByte(s, '(')
	if openIdx <= 0 || !strings.HasSuffix(s, ")") {
		return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT shape [%s]", wkt)
	}
	geomType := strings.ToUpper(strings.TrimSpace(s[:openIdx]))
	inner := strings.TrimSpace(s[openIdx+1 : len(s)-1])
	parseCoordPair := func(pairStr string) ([]any, error) {
		fields := strings.Fields(strings.Trim(strings.TrimSpace(pairStr), "()"))
		if len(fields) < 2 || len(fields) > 3 {
			return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT coordinate pair [%s]", pairStr)
		}
		lon, err1 := strconv.ParseFloat(fields[0], 64)
		lat, err2 := strconv.ParseFloat(fields[1], 64)
		if err1 != nil || err2 != nil || math.IsNaN(lon) || math.IsNaN(lat) || math.IsInf(lon, 0) || math.IsInf(lat, 0) {
			return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT coordinate numbers [%s]", pairStr)
		}
		return []any{lon, lat}, nil
	}
	parseCoordList := func(listStr string) ([]any, error) {
		parts := strings.Split(listStr, ",")
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			pair, err := parseCoordPair(p)
			if err != nil {
				return nil, err
			}
			out = append(out, pair)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("parsing_exception: [geo_shape] empty WKT coordinate list")
		}
		return out, nil
	}
	splitTopLevelGroups := func(str string) []string {
		var groups []string
		depth := 0
		start := 0
		for i := 0; i < len(str); i++ {
			switch str[i] {
			case '(':
				depth++
			case ')':
				depth--
			case ',':
				if depth == 0 {
					groups = append(groups, strings.TrimSpace(str[start:i]))
					start = i + 1
				}
			}
		}
		if last := strings.TrimSpace(str[start:]); last != "" {
			groups = append(groups, last)
		}
		return groups
	}
	switch geomType {
	case "POINT":
		pt, err := parseCoordPair(inner)
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "point", "coordinates": pt}, nil
	case "BBOX", "ENVELOPE":
		parts := strings.Split(inner, ",")
		if len(parts) != 4 {
			return nil, fmt.Errorf("parsing_exception: [geo_shape] WKT %s requires 4 coordinates, got [%s]", geomType, wkt)
		}
		minLon, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		maxLon, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		maxLat, err3 := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
		minLat, err4 := strconv.ParseFloat(strings.TrimSpace(parts[3]), 64)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT %s coordinates [%s]", geomType, wkt)
		}
		for _, f := range []float64{minLon, maxLon, maxLat, minLat} {
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT %s coordinate value [%v]", geomType, f)
			}
		}
		if minLon < -180 || minLon > 180 || maxLon < -180 || maxLon > 180 || maxLat < -90 || maxLat > 90 || minLat < -90 || minLat > 90 {
			return nil, fmt.Errorf("parsing_exception: [geo_shape] WKT %s coordinates out of bounds [%s]", geomType, wkt)
		}
		if maxLat < minLat {
			return nil, fmt.Errorf("parsing_exception: [geo_shape] WKT %s maxLat [%v] must be >= minLat [%v]", geomType, maxLat, minLat)
		}
		return map[string]any{
			"type":        "envelope",
			"coordinates": []any{[]any{minLon, maxLat}, []any{maxLon, minLat}},
		}, nil
	case "LINESTRING":
		coords, err := parseCoordList(inner)
		if err != nil || len(coords) < 2 {
			return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT LINESTRING [%s]", wkt)
		}
		return map[string]any{"type": "linestring", "coordinates": coords}, nil
	case "MULTIPOINT":
		coords, err := parseCoordList(inner)
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "multipoint", "coordinates": coords}, nil
	case "POLYGON":
		ringStrs := splitTopLevelGroups(inner)
		rings := make([]any, 0, len(ringStrs))
		for _, rs := range ringStrs {
			rsTrim := strings.TrimSpace(rs)
			if !strings.HasPrefix(rsTrim, "(") || !strings.HasSuffix(rsTrim, ")") {
				return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT POLYGON ring [%s]", rs)
			}
			ringCoords, err := parseCoordList(rsTrim[1 : len(rsTrim)-1])
			if err != nil || len(ringCoords) < 3 {
				return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT POLYGON coordinates [%s]", wkt)
			}
			rings = append(rings, ringCoords)
		}
		if len(rings) == 0 {
			return nil, fmt.Errorf("parsing_exception: [geo_shape] empty WKT POLYGON [%s]", wkt)
		}
		return map[string]any{"type": "polygon", "coordinates": rings}, nil
	case "MULTIPOLYGON":
		polyStrs := splitTopLevelGroups(inner)
		polys := make([]any, 0, len(polyStrs))
		for _, ps := range polyStrs {
			psTrim := strings.TrimSpace(ps)
			if !strings.HasPrefix(psTrim, "(") || !strings.HasSuffix(psTrim, ")") {
				return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT MULTIPOLYGON element [%s]", ps)
			}
			ringStrs := splitTopLevelGroups(psTrim[1 : len(psTrim)-1])
			rings := make([]any, 0, len(ringStrs))
			for _, rs := range ringStrs {
				rsTrim := strings.TrimSpace(rs)
				if !strings.HasPrefix(rsTrim, "(") || !strings.HasSuffix(rsTrim, ")") {
					return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT MULTIPOLYGON ring [%s]", rs)
				}
				ringCoords, err := parseCoordList(rsTrim[1 : len(rsTrim)-1])
				if err != nil || len(ringCoords) < 3 {
					return nil, fmt.Errorf("parsing_exception: [geo_shape] invalid WKT MULTIPOLYGON coordinates [%s]", wkt)
				}
				rings = append(rings, ringCoords)
			}
			polys = append(polys, rings)
		}
		return map[string]any{"type": "multipolygon", "coordinates": polys}, nil
	case "GEOMETRYCOLLECTION":
		subStrs := splitTopLevelGroups(inner)
		geoms := make([]any, 0, len(subStrs))
		for _, sub := range subStrs {
			g, err := ParseWKTGeoShape(sub)
			if err != nil {
				return nil, err
			}
			geoms = append(geoms, g)
		}
		return map[string]any{"type": "geometrycollection", "geometries": geoms}, nil
	default:
		return nil, fmt.Errorf("parsing_exception: [geo_shape] unsupported WKT shape type [%s]", geomType)
	}
}

// WrapperQuery models an ES `wrapper` query (`{"wrapper": {"query": "eyJ..."}}`).
type WrapperQuery struct {
	Query   string   `json:"query"`
	Decoded *Query   `json:"-"`
	Boost   *float64 `json:"boost,omitempty"`
	Name    string   `json:"_name,omitempty"`
}

func (wq *WrapperQuery) UnmarshalJSON(data []byte) error {
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
		case "query", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [wrapper] unknown field [%s]", k)
		}
	}
	var raw struct {
		Query string          `json:"query"`
		Boost json.RawMessage `json:"boost"`
		Name  string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	qStr := strings.TrimSpace(raw.Query)
	if qStr == "" {
		return fmt.Errorf("parsing_exception: [wrapper] requires non-empty [query]")
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(qStr)
	if err != nil {
		var err2 error
		decodedBytes, err2 = base64.RawStdEncoding.DecodeString(qStr)
		if err2 != nil {
			return fmt.Errorf("parsing_exception: [wrapper] failed to base64 decode [query]: %w", err)
		}
	}
	decTrimmed := bytes.TrimSpace(decodedBytes)
	if len(decTrimmed) == 0 || decTrimmed[0] != '{' {
		return fmt.Errorf("parsing_exception: [wrapper] decoded query must be a JSON object")
	}
	var inner Query
	if err := json.Unmarshal(decTrimmed, &inner); err != nil {
		return fmt.Errorf("parsing_exception: wrapper query decoded payload is invalid query JSON: %w", err)
	}
	wq.Query = qStr
	wq.Decoded = &inner
	wq.Name = raw.Name
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		wq.Boost = b
	}
	return nil
}

// PinnedQuery models an ES `pinned` query (`{"pinned": {"ids": [...], "organic": {...}}}`).
type PinnedQuery struct {
	IDs     []string         `json:"ids,omitempty"`
	Docs    []map[string]any `json:"docs,omitempty"`
	Organic *Query           `json:"organic,omitempty"`
	Boost   *float64         `json:"boost,omitempty"`
	Name    string           `json:"_name,omitempty"`
}

func (pq *PinnedQuery) EffectiveIDs() []string {
	if pq == nil {
		return nil
	}
	out := make([]string, 0, len(pq.IDs)+len(pq.Docs))
	out = append(out, pq.IDs...)
	for _, d := range pq.Docs {
		if idVal, ok := d["_id"]; ok && idVal != nil {
			s := strings.TrimSpace(fmt.Sprintf("%v", idVal))
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// PinnedDoc models an item in a `pinned` query's `docs` array.
type PinnedDoc struct {
	Index string `json:"_index,omitempty"`
	ID    string `json:"_id"`
	Type  string `json:"_type,omitempty"`
}

func (d *PinnedDoc) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("parsing_exception: [pinned] doc cannot be null")
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "_index", "_id", "_type":
		default:
			return fmt.Errorf("parsing_exception: [pinned.docs] unknown field [%s]", k)
		}
	}
	var raw struct {
		Index string `json:"_index"`
		ID    any    `json:"_id"`
		Type  string `json:"_type"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.ID == nil {
		return fmt.Errorf("parsing_exception: [pinned.docs] [_id] must not be null or empty")
	}
	switch v := raw.ID.(type) {
	case string:
		d.ID = strings.TrimSpace(v)
	case float64, int, int64, json.Number:
		d.ID = strings.TrimSpace(fmt.Sprintf("%v", v))
	default:
		return fmt.Errorf("parsing_exception: [pinned.docs] [_id] must be a string")
	}
	if d.ID == "" {
		return fmt.Errorf("parsing_exception: [pinned.docs] [_id] must not be empty")
	}
	d.Index = raw.Index
	d.Type = raw.Type
	return nil
}

func (pq *PinnedQuery) UnmarshalJSON(data []byte) error {
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
		case "ids", "docs", "organic", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [pinned] unknown field [%s]", k)
		}
	}
	_, hasIDs := rawMap["ids"]
	_, hasDocs := rawMap["docs"]
	if hasIDs && hasDocs {
		return fmt.Errorf("parsing_exception: [pinned] cannot specify both [ids] and [docs]")
	}
	if hasDocs {
		var pDocs []PinnedDoc
		if err := json.Unmarshal(rawMap["docs"], &pDocs); err != nil {
			return err
		}
	}
	var raw struct {
		IDs     any              `json:"ids"`
		Docs    []map[string]any `json:"docs"`
		Organic *Query           `json:"organic"`
		Boost   json.RawMessage  `json:"boost"`
		Name    string           `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.Organic == nil {
		return fmt.Errorf("parsing_exception: [pinned] requires [organic] query")
	}
	if raw.IDs != nil {
		ids, err := parseFlexibleStringSlice(raw.IDs)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if strings.TrimSpace(id) == "" {
				return fmt.Errorf("parsing_exception: [pinned] [ids] cannot contain empty strings")
			}
		}
		pq.IDs = ids
	}
	pq.Docs = raw.Docs
	pq.Organic = raw.Organic
	pq.Name = raw.Name
	if len(pq.EffectiveIDs()) == 0 {
		return fmt.Errorf("parsing_exception: [pinned] requires non-empty [ids] or [docs]")
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		pq.Boost = b
	}
	return nil
}

// MoreLikeThisQuery models an ES `more_like_this` query.
type MoreLikeThisQuery struct {
	Fields                 []string         `json:"fields,omitempty"`
	Like                   any              `json:"like,omitempty"`
	LikeText               string           `json:"like_text,omitempty"`
	Ids                    []string         `json:"ids,omitempty"`
	Docs                   []map[string]any `json:"docs,omitempty"`
	Unlike                 any              `json:"unlike,omitempty"`
	MinTermFreq            int              `json:"min_term_freq,omitempty"`
	MaxQueryTerms          int              `json:"max_query_terms,omitempty"`
	MinDocFreq             int              `json:"min_doc_freq,omitempty"`
	MaxDocFreq             int              `json:"max_doc_freq,omitempty"`
	MinWordLength          int              `json:"min_word_length,omitempty"`
	MaxWordLength          int              `json:"max_word_length,omitempty"`
	StopWords              []string         `json:"stop_words,omitempty"`
	Analyzer               string           `json:"analyzer,omitempty"`
	MinimumShouldMatch     any              `json:"minimum_should_match,omitempty"`
	BoostTerms             float64          `json:"boost_terms,omitempty"`
	Include                bool             `json:"include,omitempty"`
	FailOnUnsupportedField *bool            `json:"fail_on_unsupported_field,omitempty"`
	Boost                  *float64         `json:"boost,omitempty"`
	Name                   string           `json:"_name,omitempty"`
}

func validateMoreLikeThisDocMap(m map[string]any, fieldName string) error {
	if len(m) == 0 {
		return fmt.Errorf("parsing_exception: [more_like_this] [%s] document item cannot be empty", fieldName)
	}
	hasID := false
	hasDoc := false
	for k, v := range m {
		switch k {
		case "_index", "_type", "fields", "_routing", "per_field_analyzer":
		case "_id":
			if v != nil {
				s, ok := v.(string)
				if !ok {
					return fmt.Errorf("parsing_exception: [more_like_this] [%s] [_id] must be a string", fieldName)
				}
				if strings.TrimSpace(s) != "" {
					hasID = true
				}
			}
		case "doc", "_source":
			if v != nil {
				docMap, ok := v.(map[string]any)
				if !ok {
					return fmt.Errorf("parsing_exception: [more_like_this] [%s] [%s] must be an object", fieldName, k)
				}
				if len(docMap) > 0 {
					hasDoc = true
				}
			}
		default:
			return fmt.Errorf("parsing_exception: [more_like_this] [%s] unknown document field [%s]", fieldName, k)
		}
	}
	if !hasID && !hasDoc {
		return fmt.Errorf("parsing_exception: [more_like_this] [%s] document must specify [_id] or [doc]/[_source]", fieldName)
	}
	return nil
}

func validateMoreLikeThisLikeArg(val any, fieldName string) error {
	if val == nil {
		return fmt.Errorf("parsing_exception: [more_like_this] [%s] cannot be null", fieldName)
	}
	switch v := val.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("parsing_exception: [more_like_this] [%s] text cannot be empty", fieldName)
		}
		return nil
	case map[string]any:
		return validateMoreLikeThisDocMap(v, fieldName)
	case []any:
		if len(v) == 0 {
			return fmt.Errorf("parsing_exception: [more_like_this] [%s] array cannot be empty", fieldName)
		}
		for _, elem := range v {
			switch item := elem.(type) {
			case string:
				if strings.TrimSpace(item) == "" {
					return fmt.Errorf("parsing_exception: [more_like_this] [%s] item text cannot be empty", fieldName)
				}
			case map[string]any:
				if err := validateMoreLikeThisDocMap(item, fieldName); err != nil {
					return err
				}
			default:
				return fmt.Errorf("parsing_exception: [more_like_this] [%s] item must be a string or document object", fieldName)
			}
		}
		return nil
	default:
		return fmt.Errorf("parsing_exception: [more_like_this] [%s] must be a string, object, or array", fieldName)
	}
}

func (mlt *MoreLikeThisQuery) UnmarshalJSON(data []byte) error {
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
		case "fields", "like", "like_text", "ids", "docs", "unlike", "min_term_freq", "max_query_terms", "min_doc_freq", "max_doc_freq",
			"min_word_length", "max_word_length", "stop_words", "analyzer", "minimum_should_match",
			"boost_terms", "include", "fail_on_unsupported_field", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [more_like_this] unknown field [%s]", k)
		}
	}
	_, hasLike := rawMap["like"]
	_, hasLikeText := rawMap["like_text"]
	_, hasIds := rawMap["ids"]
	_, hasDocs := rawMap["docs"]
	if !hasLike && !hasLikeText && !hasIds && !hasDocs {
		return fmt.Errorf("parsing_exception: [more_like_this] requires [like]")
	}
	type plain MoreLikeThisQuery
	var raw struct {
		plain
		Fields                 any             `json:"fields"`
		Ids                    any             `json:"ids"`
		StopWords              any             `json:"stop_words"`
		FailOnUnsupportedField any             `json:"fail_on_unsupported_field"`
		Boost                  json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*mlt = MoreLikeThisQuery(raw.plain)
	if mlt.MinTermFreq < 0 {
		return fmt.Errorf("illegal_argument_exception: [more_like_this] [min_term_freq] must be >= 0")
	}
	if mlt.MaxQueryTerms < 0 {
		return fmt.Errorf("illegal_argument_exception: [more_like_this] [max_query_terms] must be >= 0")
	}
	if mlt.MinDocFreq < 0 {
		return fmt.Errorf("illegal_argument_exception: [more_like_this] [min_doc_freq] must be >= 0")
	}
	if mlt.MaxDocFreq < 0 {
		return fmt.Errorf("illegal_argument_exception: [more_like_this] [max_doc_freq] must be >= 0")
	}
	if mlt.MaxDocFreq > 0 && mlt.MinDocFreq > mlt.MaxDocFreq {
		return fmt.Errorf("illegal_argument_exception: [more_like_this] [min_doc_freq] cannot be greater than [max_doc_freq]")
	}
	if mlt.MinWordLength < 0 {
		return fmt.Errorf("illegal_argument_exception: [more_like_this] [min_word_length] must be >= 0")
	}
	if mlt.MaxWordLength < 0 {
		return fmt.Errorf("illegal_argument_exception: [more_like_this] [max_word_length] must be >= 0")
	}
	if mlt.MaxWordLength > 0 && mlt.MinWordLength > mlt.MaxWordLength {
		return fmt.Errorf("illegal_argument_exception: [more_like_this] [min_word_length] cannot be greater than [max_word_length]")
	}
	if hasLike {
		if err := validateMoreLikeThisLikeArg(mlt.Like, "like"); err != nil {
			return err
		}
	}
	if hasLikeText && strings.TrimSpace(mlt.LikeText) == "" {
		return fmt.Errorf("parsing_exception: [more_like_this] [like_text] cannot be empty")
	}
	if _, hasUnlike := rawMap["unlike"]; hasUnlike {
		if err := validateMoreLikeThisLikeArg(mlt.Unlike, "unlike"); err != nil {
			return err
		}
	}
	if raw.Fields != nil {
		fields, err := parseFlexibleStringSlice(raw.Fields)
		if err != nil {
			return err
		}
		mlt.Fields = fields
	}
	if raw.Ids != nil {
		ids, err := parseFlexibleStringSlice(raw.Ids)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			return fmt.Errorf("parsing_exception: [more_like_this] [ids] cannot be empty")
		}
		for _, id := range ids {
			if strings.TrimSpace(id) == "" {
				return fmt.Errorf("parsing_exception: [more_like_this] [ids] cannot contain empty strings")
			}
		}
		mlt.Ids = ids
	}
	if hasDocs {
		if len(mlt.Docs) == 0 {
			return fmt.Errorf("parsing_exception: [more_like_this] [docs] cannot be empty")
		}
		for _, doc := range mlt.Docs {
			if err := validateMoreLikeThisDocMap(doc, "docs"); err != nil {
				return err
			}
		}
	}
	if raw.StopWords != nil {
		sw, err := parseFlexibleStringSlice(raw.StopWords)
		if err != nil {
			return err
		}
		mlt.StopWords = sw
	}
	if raw.FailOnUnsupportedField != nil {
		b, err := parseFlexibleBool(raw.FailOnUnsupportedField)
		if err != nil {
			return err
		}
		mlt.FailOnUnsupportedField = &b
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		mlt.Boost = b
	}
	return nil
}

// IntervalsRule models a rule in an ES `intervals` query.
type IntervalsRule struct {
	Match    *IntervalsMatch    `json:"match,omitempty"`
	Prefix   *IntervalsPrefix   `json:"prefix,omitempty"`
	Wildcard *IntervalsWildcard `json:"wildcard,omitempty"`
	Fuzzy    *IntervalsFuzzy    `json:"fuzzy,omitempty"`
	AllOf    *IntervalsAllOf    `json:"all_of,omitempty"`
	AnyOf    *IntervalsAnyOf    `json:"any_of,omitempty"`
	Boost    *float64           `json:"boost,omitempty"`
}

type IntervalsMatch struct {
	Query    string           `json:"query"`
	MaxGaps  *int             `json:"max_gaps,omitempty"`
	Ordered  bool             `json:"ordered,omitempty"`
	Analyzer string           `json:"analyzer,omitempty"`
	Filter   *IntervalsFilter `json:"filter,omitempty"`
	UseField string           `json:"use_field,omitempty"`
}

func (im *IntervalsMatch) UnmarshalJSON(data []byte) error {
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
		case "query", "max_gaps", "ordered", "analyzer", "filter", "use_field":
		default:
			return fmt.Errorf("parsing_exception: [intervals.match] unknown field [%s]", k)
		}
	}
	type plain IntervalsMatch
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Query) == "" {
		return fmt.Errorf("parsing_exception: [intervals.match] requires non-empty [query]")
	}
	*im = IntervalsMatch(p)
	return nil
}

type IntervalsPrefix struct {
	Prefix   string `json:"prefix"`
	Analyzer string `json:"analyzer,omitempty"`
	UseField string `json:"use_field,omitempty"`
}

func (ip *IntervalsPrefix) UnmarshalJSON(data []byte) error {
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
		case "prefix", "analyzer", "use_field":
		default:
			return fmt.Errorf("parsing_exception: [intervals.prefix] unknown field [%s]", k)
		}
	}
	type plain IntervalsPrefix
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Prefix) == "" {
		return fmt.Errorf("parsing_exception: [intervals.prefix] requires non-empty [prefix]")
	}
	*ip = IntervalsPrefix(p)
	return nil
}

type IntervalsWildcard struct {
	Pattern  string `json:"pattern"`
	Analyzer string `json:"analyzer,omitempty"`
	UseField string `json:"use_field,omitempty"`
}

func (iw *IntervalsWildcard) UnmarshalJSON(data []byte) error {
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
		case "pattern", "analyzer", "use_field":
		default:
			return fmt.Errorf("parsing_exception: [intervals.wildcard] unknown field [%s]", k)
		}
	}
	type plain IntervalsWildcard
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Pattern) == "" {
		return fmt.Errorf("parsing_exception: [intervals.wildcard] requires non-empty [pattern]")
	}
	*iw = IntervalsWildcard(p)
	return nil
}

type IntervalsFuzzy struct {
	Term           string `json:"term"`
	PrefixLength   int    `json:"prefix_length,omitempty"`
	Transpositions *bool  `json:"transpositions,omitempty"`
	Fuzziness      any    `json:"fuzziness,omitempty"`
	Analyzer       string `json:"analyzer,omitempty"`
	UseField       string `json:"use_field,omitempty"`
}

func (ifz *IntervalsFuzzy) UnmarshalJSON(data []byte) error {
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
		case "term", "prefix_length", "transpositions", "fuzziness", "analyzer", "use_field":
		default:
			return fmt.Errorf("parsing_exception: [intervals.fuzzy] unknown field [%s]", k)
		}
	}
	type plain IntervalsFuzzy
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Term) == "" {
		return fmt.Errorf("parsing_exception: [intervals.fuzzy] requires non-empty [term]")
	}
	if p.PrefixLength < 0 {
		return fmt.Errorf("parsing_exception: [intervals.fuzzy] [prefix_length] must be >= 0")
	}
	*ifz = IntervalsFuzzy(p)
	return nil
}

type IntervalsAllOf struct {
	Intervals []IntervalsRule  `json:"intervals"`
	MaxGaps   *int             `json:"max_gaps,omitempty"`
	Ordered   bool             `json:"ordered,omitempty"`
	Filter    *IntervalsFilter `json:"filter,omitempty"`
}

func (ia *IntervalsAllOf) UnmarshalJSON(data []byte) error {
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
		case "intervals", "max_gaps", "ordered", "filter":
		default:
			return fmt.Errorf("parsing_exception: [intervals.all_of] unknown field [%s]", k)
		}
	}
	type plain IntervalsAllOf
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if len(p.Intervals) == 0 {
		return fmt.Errorf("parsing_exception: [intervals.all_of] requires non-empty [intervals]")
	}
	*ia = IntervalsAllOf(p)
	return nil
}

type IntervalsAnyOf struct {
	Intervals []IntervalsRule  `json:"intervals"`
	Filter    *IntervalsFilter `json:"filter,omitempty"`
}

func (iao *IntervalsAnyOf) UnmarshalJSON(data []byte) error {
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
		case "intervals", "filter":
		default:
			return fmt.Errorf("parsing_exception: [intervals.any_of] unknown field [%s]", k)
		}
	}
	type plain IntervalsAnyOf
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if len(p.Intervals) == 0 {
		return fmt.Errorf("parsing_exception: [intervals.any_of] requires non-empty [intervals]")
	}
	*iao = IntervalsAnyOf(p)
	return nil
}

type IntervalsFilter struct {
	After          *IntervalsRule `json:"after,omitempty"`
	Before         *IntervalsRule `json:"before,omitempty"`
	ContainedBy    *IntervalsRule `json:"contained_by,omitempty"`
	Containing     *IntervalsRule `json:"containing,omitempty"`
	NotContainedBy *IntervalsRule `json:"not_contained_by,omitempty"`
	NotContaining  *IntervalsRule `json:"not_containing,omitempty"`
	NotOverlapping *IntervalsRule `json:"not_overlapping,omitempty"`
	Overlapping    *IntervalsRule `json:"overlapping,omitempty"`
	Script         any            `json:"script,omitempty"`
}

func (ifl *IntervalsFilter) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	ruleCount := 0
	for k := range rawMap {
		switch k {
		case "after", "before", "contained_by", "containing",
			"not_contained_by", "not_containing", "not_overlapping", "overlapping", "script":
			ruleCount++
		default:
			return fmt.Errorf("parsing_exception: [intervals.filter] unknown field [%s]", k)
		}
	}
	if ruleCount == 0 {
		return fmt.Errorf("parsing_exception: [intervals.filter] requires a filter rule or [script]")
	}
	type plain IntervalsFilter
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	*ifl = IntervalsFilter(p)
	return nil
}

func (ir *IntervalsRule) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	ruleCount := 0
	for k := range rawMap {
		switch k {
		case "match", "prefix", "wildcard", "fuzzy", "all_of", "any_of":
			ruleCount++
		case "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [intervals] unknown rule [%s]", k)
		}
	}
	if ruleCount != 1 {
		return fmt.Errorf("parsing_exception: [intervals] rule must specify exactly one of match, prefix, wildcard, fuzzy, all_of, or any_of")
	}
	type plain IntervalsRule
	var raw struct {
		plain
		Boost json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*ir = IntervalsRule(raw.plain)
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		ir.Boost = b
	}
	return nil
}

// SpanNearQuery models an ES `span_near` query.
type SpanNearQuery struct {
	Clauses []Query  `json:"clauses"`
	Slop    int      `json:"slop,omitempty"`
	InOrder *bool    `json:"in_order,omitempty"`
	Boost   *float64 `json:"boost,omitempty"`
	Name    string   `json:"_name,omitempty"`
}

func (sn *SpanNearQuery) UnmarshalJSON(data []byte) error {
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
		case "clauses", "slop", "in_order", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [span_near] unknown field [%s]", k)
		}
	}
	var raw struct {
		Clauses []Query         `json:"clauses"`
		Slop    int             `json:"slop"`
		InOrder any             `json:"in_order"`
		Boost   json.RawMessage `json:"boost"`
		Name    string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if len(raw.Clauses) == 0 {
		return fmt.Errorf("parsing_exception: [span_near] clauses must contain at least 1 clause")
	}
	if raw.Slop < 0 {
		return fmt.Errorf("parsing_exception: [span_near] slop must be >= 0")
	}
	sn.Clauses = raw.Clauses
	sn.Slop = raw.Slop
	sn.Name = raw.Name
	if raw.InOrder != nil {
		b, err := parseFlexibleBool(raw.InOrder)
		if err != nil {
			return fmt.Errorf("parsing_exception: [span_near] in_order %w", err)
		}
		sn.InOrder = &b
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		sn.Boost = b
	}
	return nil
}

// SpanOrQuery models an ES `span_or` query.
type SpanOrQuery struct {
	Clauses []Query  `json:"clauses"`
	Boost   *float64 `json:"boost,omitempty"`
	Name    string   `json:"_name,omitempty"`
}

func (so *SpanOrQuery) UnmarshalJSON(data []byte) error {
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
		case "clauses", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [span_or] unknown field [%s]", k)
		}
	}
	rawClauses, hasClauses := rawMap["clauses"]
	if !hasClauses || len(bytes.TrimSpace(rawClauses)) == 0 || bytes.Equal(bytes.TrimSpace(rawClauses), []byte("null")) {
		return fmt.Errorf("parsing_exception: [span_or] missing required [clauses] field")
	}
	var raw struct {
		Clauses []Query         `json:"clauses"`
		Boost   json.RawMessage `json:"boost"`
		Name    string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	so.Clauses = raw.Clauses
	so.Name = raw.Name
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		so.Boost = b
	}
	return nil
}

// SpanNotQuery models an ES `span_not` query.
type SpanNotQuery struct {
	Include *Query   `json:"include"`
	Exclude *Query   `json:"exclude"`
	Pre     int      `json:"pre,omitempty"`
	Post    int      `json:"post,omitempty"`
	Dist    int      `json:"dist,omitempty"`
	Boost   *float64 `json:"boost,omitempty"`
	Name    string   `json:"_name,omitempty"`
}

func (sn *SpanNotQuery) UnmarshalJSON(data []byte) error {
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
		case "include", "exclude", "pre", "post", "dist", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [span_not] unknown field [%s]", k)
		}
	}
	var raw struct {
		Include *Query          `json:"include"`
		Exclude *Query          `json:"exclude"`
		Pre     int             `json:"pre"`
		Post    int             `json:"post"`
		Dist    int             `json:"dist"`
		Boost   json.RawMessage `json:"boost"`
		Name    string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.Include == nil || raw.Exclude == nil {
		return fmt.Errorf("parsing_exception: [span_not] requires both [include] and [exclude] clauses")
	}
	if raw.Pre < 0 || raw.Post < 0 || raw.Dist < 0 {
		return fmt.Errorf("parsing_exception: [span_not] pre, post, and dist must be >= 0")
	}
	sn.Include = raw.Include
	sn.Exclude = raw.Exclude
	sn.Pre = raw.Pre
	sn.Post = raw.Post
	sn.Dist = raw.Dist
	sn.Name = raw.Name
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		sn.Boost = b
	}
	return nil
}

// SpanFirstQuery models an ES `span_first` query.
type SpanFirstQuery struct {
	Match *Query   `json:"match"`
	End   int      `json:"end"`
	Boost *float64 `json:"boost,omitempty"`
	Name  string   `json:"_name,omitempty"`
}

func (sf *SpanFirstQuery) UnmarshalJSON(data []byte) error {
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
		case "match", "end", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [span_first] unknown field [%s]", k)
		}
	}
	var raw struct {
		Match *Query          `json:"match"`
		End   int             `json:"end"`
		Boost json.RawMessage `json:"boost"`
		Name  string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.Match == nil {
		return fmt.Errorf("parsing_exception: [span_first] requires [match] clause")
	}
	if raw.End <= 0 {
		return fmt.Errorf("parsing_exception: [span_first] end must be > 0")
	}
	sf.Match = raw.Match
	sf.End = raw.End
	sf.Name = raw.Name
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		sf.Boost = b
	}
	return nil
}

// SpanMultiQuery models an ES `span_multi` query (`{"span_multi": {"match": {"prefix": ...}}}`).
type SpanMultiQuery struct {
	Match *Query   `json:"match"`
	Boost *float64 `json:"boost,omitempty"`
	Name  string   `json:"_name,omitempty"`
}

func (sm *SpanMultiQuery) UnmarshalJSON(data []byte) error {
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
		case "match", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [span_multi] unknown field [%s]", k)
		}
	}
	var raw struct {
		Match *Query          `json:"match"`
		Boost json.RawMessage `json:"boost"`
		Name  string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.Match == nil {
		return fmt.Errorf("parsing_exception: [span_multi] requires [match] clause")
	}
	if len(raw.Match.Prefix) == 0 && len(raw.Match.Wildcard) == 0 && len(raw.Match.Regexp) == 0 && len(raw.Match.Fuzzy) == 0 && len(raw.Match.Range) == 0 {
		return fmt.Errorf("parsing_exception: [span_multi] match must be a multi-term query (prefix, wildcard, regexp, fuzzy, or range)")
	}
	sm.Match = raw.Match
	sm.Name = raw.Name
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		sm.Boost = b
	}
	return nil
}

// SpanPairQuery models an ES `span_containing` or `span_within` query.
type SpanPairQuery struct {
	Little *Query   `json:"little"`
	Big    *Query   `json:"big"`
	Boost  *float64 `json:"boost,omitempty"`
	Name   string   `json:"_name,omitempty"`
}

func (sp *SpanPairQuery) UnmarshalJSON(data []byte) error {
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
		case "little", "big", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [span_pair] unknown field [%s]", k)
		}
	}
	var raw struct {
		Little *Query          `json:"little"`
		Big    *Query          `json:"big"`
		Boost  json.RawMessage `json:"boost"`
		Name   string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.Little == nil || raw.Big == nil {
		return fmt.Errorf("parsing_exception: [span_pair] requires both [little] and [big] clauses")
	}
	sp.Little = raw.Little
	sp.Big = raw.Big
	sp.Name = raw.Name
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		sp.Boost = b
	}
	return nil
}

// FieldMaskingSpanQuery models an ES `field_masking_span` query.
type FieldMaskingSpanQuery struct {
	Query *Query   `json:"query"`
	Field string   `json:"field"`
	Boost *float64 `json:"boost,omitempty"`
	Name  string   `json:"_name,omitempty"`
}

func (fm *FieldMaskingSpanQuery) UnmarshalJSON(data []byte) error {
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
		case "query", "field", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [field_masking_span] unknown field [%s]", k)
		}
	}
	var raw struct {
		Query *Query          `json:"query"`
		Field string          `json:"field"`
		Boost json.RawMessage `json:"boost"`
		Name  string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.Query == nil || strings.TrimSpace(raw.Field) == "" {
		return fmt.Errorf("parsing_exception: [field_masking_span] requires both [query] and non-empty [field]")
	}
	fm.Query = raw.Query
	fm.Field = raw.Field
	fm.Name = raw.Name
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		fm.Boost = b
	}
	return nil
}

// RankFeatureQuery models an ES `rank_feature` query.
type RankFeatureQuery struct {
	Field      string         `json:"field"`
	Boost      *float64       `json:"boost,omitempty"`
	Saturation map[string]any `json:"saturation,omitempty"`
	Log        map[string]any `json:"log,omitempty"`
	Sigmoid    map[string]any `json:"sigmoid,omitempty"`
	Linear     map[string]any `json:"linear,omitempty"`
	Name       string         `json:"_name,omitempty"`
}

func parseStrictPositiveNumber(raw json.RawMessage, errCtx string) (float64, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return 0, fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
	}
	var v float64
	if err := json.Unmarshal(trimmed, &v); err != nil || v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
	}
	return v, nil
}

func validatePositiveScaleOrPivot(val any, errCtx string) error {
	if val == nil {
		return fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
	}
	switch v := val.(type) {
	case float64:
		if v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
		}
		return nil
	case int:
		if v <= 0 {
			return fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
		}
		return nil
	case int64:
		if v <= 0 {
			return fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
		}
		return nil
	case json.Number:
		f, err := v.Float64()
		if err != nil || f <= 0 || math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
		}
		return nil
	case string:
		s := strings.TrimSpace(v)
		if s == "" || strings.HasPrefix(s, "-") {
			return fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
		}
		numEnd := 0
		for numEnd < len(s) && ((s[numEnd] >= '0' && s[numEnd] <= '9') || s[numEnd] == '.' || s[numEnd] == '+') {
			numEnd++
		}
		if numEnd == 0 {
			return fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
		}
		f, err := strconv.ParseFloat(s[:numEnd], 64)
		if err != nil || f <= 0 || math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
		}
		return nil
	default:
		return fmt.Errorf("parsing_exception: %s must be > 0", errCtx)
	}
}

func validateNonNegativeOffset(val any, errCtx string) error {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case float64:
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("parsing_exception: %s must be >= 0", errCtx)
		}
		return nil
	case int:
		if v < 0 {
			return fmt.Errorf("parsing_exception: %s must be >= 0", errCtx)
		}
		return nil
	case int64:
		if v < 0 {
			return fmt.Errorf("parsing_exception: %s must be >= 0", errCtx)
		}
		return nil
	case json.Number:
		f, err := v.Float64()
		if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("parsing_exception: %s must be >= 0", errCtx)
		}
		return nil
	case string:
		s := strings.TrimSpace(v)
		if s == "" || strings.HasPrefix(s, "-") {
			return fmt.Errorf("parsing_exception: %s must be >= 0", errCtx)
		}
		numEnd := 0
		for numEnd < len(s) && ((s[numEnd] >= '0' && s[numEnd] <= '9') || s[numEnd] == '.' || s[numEnd] == '+') {
			numEnd++
		}
		if numEnd == 0 {
			return fmt.Errorf("parsing_exception: %s must be >= 0", errCtx)
		}
		f, err := strconv.ParseFloat(s[:numEnd], 64)
		if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("parsing_exception: %s must be >= 0", errCtx)
		}
		return nil
	default:
		return fmt.Errorf("parsing_exception: %s must be >= 0", errCtx)
	}
}

func validateOriginValue(origin any, errCtx string) error {
	if origin == nil {
		return fmt.Errorf("parsing_exception: %s [origin] cannot be null", errCtx)
	}
	switch ov := origin.(type) {
	case string:
		if strings.TrimSpace(ov) == "" {
			return fmt.Errorf("parsing_exception: %s [origin] cannot be empty", errCtx)
		}
		return nil
	case float64, int, int64, json.Number:
		return nil
	case bool:
		return fmt.Errorf("parsing_exception: %s [origin] cannot be a boolean", errCtx)
	case []any:
		if len(ov) != 2 {
			return fmt.Errorf("parsing_exception: %s [origin] array must have 2 elements", errCtx)
		}
		if _, _, err := ParseGeoPoint(ov); err != nil {
			return fmt.Errorf("parsing_exception: %s invalid [origin]: %w", errCtx, err)
		}
		return nil
	case map[string]any:
		if len(ov) == 0 {
			return fmt.Errorf("parsing_exception: %s [origin] object cannot be empty", errCtx)
		}
		if _, _, err := ParseGeoPoint(ov); err != nil {
			return fmt.Errorf("parsing_exception: %s invalid [origin]: %w", errCtx, err)
		}
		return nil
	default:
		return fmt.Errorf("parsing_exception: %s invalid [origin]", errCtx)
	}
}

func (rf *RankFeatureQuery) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	fnCount := 0
	for k := range rawMap {
		switch k {
		case "saturation", "log", "sigmoid", "linear":
			fnCount++
		case "field", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [rank_feature] unknown field [%s]", k)
		}
	}
	if fnCount > 1 {
		return fmt.Errorf("parsing_exception: [rank_feature] cannot specify more than one function")
	}
	if rawSat, ok := rawMap["saturation"]; ok {
		st := bytes.TrimSpace(rawSat)
		if len(st) == 0 || st[0] != '{' {
			return fmt.Errorf("parsing_exception: [rank_feature.saturation] must be an object")
		}
		var satMap map[string]json.RawMessage
		if err := json.Unmarshal(st, &satMap); err != nil {
			return err
		}
		for sk, sv := range satMap {
			if sk != "pivot" {
				return fmt.Errorf("parsing_exception: [rank_feature.saturation] unknown field [%s]", sk)
			}
			if _, err := parseStrictPositiveNumber(sv, "[rank_feature.saturation.pivot]"); err != nil {
				return err
			}
		}
	}
	if rawLog, ok := rawMap["log"]; ok {
		lt := bytes.TrimSpace(rawLog)
		if len(lt) == 0 || lt[0] != '{' {
			return fmt.Errorf("parsing_exception: [rank_feature.log] must be an object")
		}
		var logMap map[string]json.RawMessage
		if err := json.Unmarshal(lt, &logMap); err != nil {
			return err
		}
		rawSF, hasSF := logMap["scaling_factor"]
		if !hasSF || len(logMap) != 1 {
			return fmt.Errorf("parsing_exception: [rank_feature.log] requires only [scaling_factor]")
		}
		if _, err := parseStrictPositiveNumber(rawSF, "[rank_feature.log.scaling_factor]"); err != nil {
			return err
		}
	}
	if rawSig, ok := rawMap["sigmoid"]; ok {
		st := bytes.TrimSpace(rawSig)
		if len(st) == 0 || st[0] != '{' {
			return fmt.Errorf("parsing_exception: [rank_feature.sigmoid] must be an object")
		}
		var sigMap map[string]json.RawMessage
		if err := json.Unmarshal(st, &sigMap); err != nil {
			return err
		}
		rawPivot, hasPivot := sigMap["pivot"]
		rawExp, hasExp := sigMap["exponent"]
		if !hasPivot || !hasExp || len(sigMap) != 2 {
			return fmt.Errorf("parsing_exception: [rank_feature.sigmoid] requires both [pivot] and [exponent]")
		}
		if _, err := parseStrictPositiveNumber(rawPivot, "[rank_feature.sigmoid.pivot]"); err != nil {
			return err
		}
		if _, err := parseStrictPositiveNumber(rawExp, "[rank_feature.sigmoid.exponent]"); err != nil {
			return err
		}
	}
	if rawLin, ok := rawMap["linear"]; ok {
		lt := bytes.TrimSpace(rawLin)
		if len(lt) == 0 || lt[0] != '{' {
			return fmt.Errorf("parsing_exception: [rank_feature.linear] must be an object")
		}
		var linMap map[string]json.RawMessage
		if err := json.Unmarshal(lt, &linMap); err != nil {
			return err
		}
		if len(linMap) != 0 {
			return fmt.Errorf("parsing_exception: [rank_feature.linear] does not accept any parameters")
		}
	}
	type plain RankFeatureQuery
	var raw struct {
		plain
		Boost json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Field) == "" {
		return fmt.Errorf("parsing_exception: [rank_feature] requires [field]")
	}
	*rf = RankFeatureQuery(raw.plain)
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		rf.Boost = b
	}
	return nil
}

// DistanceFeatureQuery models an ES `distance_feature` query.
type DistanceFeatureQuery struct {
	Field  string   `json:"field"`
	Origin any      `json:"origin"`
	Pivot  any      `json:"pivot"`
	Boost  *float64 `json:"boost,omitempty"`
	Name   string   `json:"_name,omitempty"`
}

func (dfq *DistanceFeatureQuery) UnmarshalJSON(data []byte) error {
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
		case "field", "origin", "pivot", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [distance_feature] unknown field [%s]", k)
		}
	}
	type plain DistanceFeatureQuery
	var raw struct {
		plain
		Boost json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Field) == "" || raw.Origin == nil || raw.Pivot == nil {
		return fmt.Errorf("parsing_exception: [distance_feature] requires [field], [origin], and [pivot]")
	}
	if err := validateOriginValue(raw.Origin, "[distance_feature]"); err != nil {
		return err
	}
	if err := validatePositiveScaleOrPivot(raw.Pivot, "[distance_feature] [pivot]"); err != nil {
		return err
	}
	*dfq = DistanceFeatureQuery(raw.plain)
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		dfq.Boost = b
	}
	return nil
}

// HasChildQuery models an ES `has_child` join query.
type HasChildQuery struct {
	Type           string         `json:"type"`
	Query          Query          `json:"query"`
	ScoreMode      string         `json:"score_mode,omitempty"`
	MinChildren    *int           `json:"min_children,omitempty"`
	MaxChildren    *int           `json:"max_children,omitempty"`
	IgnoreUnmapped bool           `json:"ignore_unmapped,omitempty"`
	InnerHits      *InnerHitsSpec `json:"inner_hits,omitempty"`
	Boost          *float64       `json:"boost,omitempty"`
	Name           string         `json:"_name,omitempty"`
}

func (hc *HasChildQuery) UnmarshalJSON(data []byte) error {
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
		case "type", "query", "score_mode", "min_children", "max_children", "ignore_unmapped", "inner_hits", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [has_child] unknown field [%s]", k)
		}
	}
	if _, hasQ := rawMap["query"]; !hasQ {
		return fmt.Errorf("parsing_exception: [has_child] requires [query]")
	}
	type plain HasChildQuery
	var raw struct {
		plain
		IgnoreUnmapped any             `json:"ignore_unmapped"`
		Boost          json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Type) == "" {
		return fmt.Errorf("parsing_exception: [has_child] requires [type]")
	}
	switch strings.ToLower(strings.TrimSpace(raw.ScoreMode)) {
	case "", "none", "avg", "sum", "max", "min":
	default:
		return fmt.Errorf("parsing_exception: [has_child] invalid score_mode [%s]", raw.ScoreMode)
	}
	if raw.MinChildren != nil && *raw.MinChildren < 0 {
		return fmt.Errorf("parsing_exception: [has_child] [min_children] must be >= 0")
	}
	if raw.MaxChildren != nil && *raw.MaxChildren < 0 {
		return fmt.Errorf("parsing_exception: [has_child] [max_children] must be >= 0")
	}
	if raw.MinChildren != nil && raw.MaxChildren != nil && *raw.MinChildren > *raw.MaxChildren {
		return fmt.Errorf("parsing_exception: [has_child] [min_children] cannot be greater than [max_children]")
	}
	*hc = HasChildQuery(raw.plain)
	if raw.IgnoreUnmapped != nil {
		b, err := parseFlexibleBool(raw.IgnoreUnmapped)
		if err != nil {
			return err
		}
		hc.IgnoreUnmapped = b
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		hc.Boost = b
	}
	return nil
}

// HasParentQuery models an ES `has_parent` join query.
type HasParentQuery struct {
	ParentType     string         `json:"parent_type"`
	Query          Query          `json:"query"`
	Score          *bool          `json:"score,omitempty"`
	IgnoreUnmapped bool           `json:"ignore_unmapped,omitempty"`
	InnerHits      *InnerHitsSpec `json:"inner_hits,omitempty"`
	Boost          *float64       `json:"boost,omitempty"`
	Name           string         `json:"_name,omitempty"`
}

func (hp *HasParentQuery) UnmarshalJSON(data []byte) error {
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
		case "parent_type", "query", "score", "ignore_unmapped", "inner_hits", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [has_parent] unknown field [%s]", k)
		}
	}
	if _, hasQ := rawMap["query"]; !hasQ {
		return fmt.Errorf("parsing_exception: [has_parent] requires [query]")
	}
	type plain HasParentQuery
	var raw struct {
		plain
		Score          any             `json:"score"`
		IgnoreUnmapped any             `json:"ignore_unmapped"`
		Boost          json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.ParentType) == "" {
		return fmt.Errorf("parsing_exception: [has_parent] requires [parent_type]")
	}
	*hp = HasParentQuery(raw.plain)
	if raw.Score != nil {
		b, err := parseFlexibleBool(raw.Score)
		if err != nil {
			return err
		}
		hp.Score = &b
	}
	if raw.IgnoreUnmapped != nil {
		b, err := parseFlexibleBool(raw.IgnoreUnmapped)
		if err != nil {
			return err
		}
		hp.IgnoreUnmapped = b
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		hp.Boost = b
	}
	return nil
}

// ParentIDQuery models an ES `parent_id` join query.
type ParentIDQuery struct {
	Type           string   `json:"type"`
	ID             any      `json:"id"`
	IgnoreUnmapped bool     `json:"ignore_unmapped,omitempty"`
	Boost          *float64 `json:"boost,omitempty"`
	Name           string   `json:"_name,omitempty"`
}

func (pid *ParentIDQuery) UnmarshalJSON(data []byte) error {
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
		case "type", "id", "ignore_unmapped", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [parent_id] unknown field [%s]", k)
		}
	}
	type plain ParentIDQuery
	var raw struct {
		plain
		IgnoreUnmapped any             `json:"ignore_unmapped"`
		Boost          json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Type) == "" || raw.ID == nil {
		return fmt.Errorf("parsing_exception: [parent_id] requires [type] and [id]")
	}
	switch idv := raw.ID.(type) {
	case string:
		if strings.TrimSpace(idv) == "" {
			return fmt.Errorf("parsing_exception: [parent_id] [id] cannot be empty")
		}
	case float64, int, int64, json.Number:
	default:
		return fmt.Errorf("parsing_exception: [parent_id] [id] must be a string or number")
	}
	*pid = ParentIDQuery(raw.plain)
	if raw.IgnoreUnmapped != nil {
		b, err := parseFlexibleBool(raw.IgnoreUnmapped)
		if err != nil {
			return err
		}
		pid.IgnoreUnmapped = b
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		pid.Boost = b
	}
	return nil
}

// PercolateQuery models an ES `percolate` query.
type PercolateQuery struct {
	Field          string           `json:"field"`
	Document       map[string]any   `json:"document,omitempty"`
	Documents      []map[string]any `json:"documents,omitempty"`
	Index          string           `json:"index,omitempty"`
	ID             string           `json:"id,omitempty"`
	Routing        string           `json:"routing,omitempty"`
	Preference     string           `json:"preference,omitempty"`
	Version        *int64           `json:"version,omitempty"`
	IgnoreUnmapped bool             `json:"ignore_unmapped,omitempty"`
	Boost          *float64         `json:"boost,omitempty"`
	Name           string           `json:"_name,omitempty"`
}

func (pq *PercolateQuery) UnmarshalJSON(data []byte) error {
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
		case "field", "document", "documents", "index", "id", "routing", "preference", "version", "ignore_unmapped", "boost", "_name", "name":
		default:
			return fmt.Errorf("parsing_exception: [percolate] unknown field [%s]", k)
		}
	}
	_, hasDoc := rawMap["document"]
	_, hasDocs := rawMap["documents"]
	_, hasID := rawMap["id"]
	_, hasIndex := rawMap["index"]
	if hasDoc && hasDocs {
		return fmt.Errorf("parsing_exception: [percolate] cannot specify both [document] and [documents]")
	}
	if (hasDoc || hasDocs) && (hasID || hasIndex) {
		return fmt.Errorf("parsing_exception: [percolate] cannot specify both [document]/[documents] and [index]/[id]")
	}
	type plain PercolateQuery
	var raw struct {
		plain
		IgnoreUnmapped any             `json:"ignore_unmapped"`
		AltName        string          `json:"name"`
		Boost          json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Field) == "" {
		return fmt.Errorf("parsing_exception: [percolate] requires [field]")
	}
	if hasDoc && raw.Document == nil {
		return fmt.Errorf("parsing_exception: [percolate] [document] must be a non-null object")
	}
	if hasDocs && len(raw.Documents) == 0 {
		return fmt.Errorf("parsing_exception: [percolate] [documents] must be a non-empty array")
	}
	if !hasDoc && !hasDocs {
		if strings.TrimSpace(raw.Index) == "" || strings.TrimSpace(raw.ID) == "" {
			return fmt.Errorf("parsing_exception: [percolate] requires [document], [documents], or both [index] and [id]")
		}
	}
	iu, err := parseFlexibleBool(raw.IgnoreUnmapped)
	if err != nil {
		return err
	}
	*pq = PercolateQuery(raw.plain)
	pq.IgnoreUnmapped = iu
	if pq.Name == "" && raw.AltName != "" {
		pq.Name = raw.AltName
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		pq.Boost = b
	}
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
	Name             string   `json:"_name,omitempty"`
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
		Name          string   `json:"_name,omitempty"`
	}{
		Positive:      bq.Positive,
		Negative:      bq.Negative,
		NegativeBoost: negBoostPtr,
		Boost:         bq.Boost,
		Name:          bq.Name,
	})
}

func (bq *BoostingQuery) UnmarshalJSON(data []byte) error {
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
		case "positive", "negative", "negative_boost", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [boosting] unknown field [%s]", k)
		}
	}
	for _, reqKey := range []string{"positive", "negative", "negative_boost"} {
		rv, ok := rawMap[reqKey]
		if !ok || len(bytes.TrimSpace(rv)) == 0 || bytes.Equal(bytes.TrimSpace(rv), []byte("null")) {
			return fmt.Errorf("parsing_exception: [boosting] query requires [%s] field", reqKey)
		}
	}
	var raw struct {
		Positive      Query           `json:"positive"`
		Negative      Query           `json:"negative"`
		NegativeBoost json.RawMessage `json:"negative_boost"`
		Boost         json.RawMessage `json:"boost"`
		Name          string          `json:"_name"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	bq.Positive = raw.Positive
	bq.Negative = raw.Negative
	bq.Name = raw.Name
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
	Store   *bool  `json:"store,omitempty"`
}

func (tls *TermsLookupSpec) UnmarshalJSON(data []byte) error {
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
		case "index", "id", "path", "routing", "store":
		default:
			return fmt.Errorf("parsing_exception: [terms] lookup unknown field [%s]", k)
		}
	}
	var raw struct {
		Index   string `json:"index"`
		ID      any    `json:"id"`
		Path    string `json:"path"`
		Routing string `json:"routing"`
		Store   any    `json:"store"`
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	var idStr string
	switch v := raw.ID.(type) {
	case string:
		idStr = v
	case json.Number:
		idStr = v.String()
	case float64, int, int64:
		idStr = formatFlexibleScalarString(v)
	case nil:
	default:
		return fmt.Errorf("parsing_exception: [terms] lookup [id] must be a string or number")
	}
	if strings.TrimSpace(raw.Index) == "" || strings.TrimSpace(idStr) == "" || strings.TrimSpace(raw.Path) == "" {
		return fmt.Errorf("parsing_exception: [terms] lookup requires non-empty [index], [id], and [path]")
	}
	tls.Index = raw.Index
	tls.ID = idStr
	tls.Path = raw.Path
	tls.Routing = raw.Routing
	if raw.Store != nil {
		b, err := parseFlexibleBool(raw.Store)
		if err != nil {
			return fmt.Errorf("parsing_exception: [terms] lookup [store] %w", err)
		}
		tls.Store = &b
	}
	return nil
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
	if len(full.Terms) == 0 {
		return fmt.Errorf("parsing_exception: [terms_set] requires a non-empty [terms] array")
	}
	tse.Terms = full.Terms
	tse.MinimumShouldMatchField = full.MinimumShouldMatchField
	tse.MinimumShouldMatchScript = full.MinimumShouldMatchScript
	if tse.MinimumShouldMatchScript == nil && full.MinimumShouldMatch != nil {
		tse.MinimumShouldMatchScript = full.MinimumShouldMatch
	}
	hasMSMField := strings.TrimSpace(tse.MinimumShouldMatchField) != ""
	hasMSMScript := tse.MinimumShouldMatchScript != nil
	if hasMSMField && hasMSMScript {
		return fmt.Errorf("parsing_exception: [terms_set] cannot specify both [minimum_should_match_field] and [minimum_should_match_script]")
	}
	if !hasMSMField && !hasMSMScript {
		return fmt.Errorf("parsing_exception: [terms_set] requires either [minimum_should_match_field] or [minimum_should_match_script]")
	}
	if full.MinimumShouldMatchScript != nil {
		if err := validateScriptValue(full.MinimumShouldMatchScript); err != nil {
			return err
		}
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
	PrefixLength    int     `json:"prefix_length,omitempty"`
	MaxExpansions   int     `json:"max_expansions,omitempty"`
	Transpositions  *bool   `json:"transpositions,omitempty"`
	Rewrite         string  `json:"rewrite,omitempty"`
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
		PrefixLength    int      `json:"prefix_length,omitempty"`
		MaxExpansions   int      `json:"max_expansions,omitempty"`
		Transpositions  *bool    `json:"transpositions,omitempty"`
		Rewrite         string   `json:"rewrite,omitempty"`
		CaseInsensitive bool     `json:"case_insensitive,omitempty"`
		Boost           *float64 `json:"boost,omitempty"`
	}{
		Value:           f.Value,
		Fuzziness:       f.Fuzziness,
		PrefixLength:    f.PrefixLength,
		MaxExpansions:   f.MaxExpansions,
		Transpositions:  f.Transpositions,
		Rewrite:         f.Rewrite,
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
			PrefixLength    int             `json:"prefix_length"`
			MaxExpansions   int             `json:"max_expansions"`
			Transpositions  any             `json:"transpositions"`
			Rewrite         string          `json:"rewrite"`
			CaseInsensitive any             `json:"case_insensitive"`
			Boost           json.RawMessage `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		if isNonScalarOrNullValue(full.Value) {
			return fmt.Errorf("parsing_exception: [fuzzy] query does not support non-scalar or null value")
		}
		if full.Fuzziness != nil {
			if err := validateFuzzinessValue(full.Fuzziness, "fuzzy"); err != nil {
				return err
			}
		}
		if full.PrefixLength < 0 {
			return fmt.Errorf("parsing_exception: [fuzzy] prefix_length must be non-negative, got [%d]", full.PrefixLength)
		}
		if _, hasMaxExp := rawMap["max_expansions"]; (hasMaxExp && full.MaxExpansions <= 0) || full.MaxExpansions < 0 {
			return fmt.Errorf("parsing_exception: [fuzzy] max_expansions must be positive, got [%d]", full.MaxExpansions)
		}
		ci, err := parseFlexibleBool(full.CaseInsensitive)
		if err != nil {
			return err
		}
		if full.Transpositions != nil {
			tp, err := parseFlexibleBool(full.Transpositions)
			if err != nil {
				return err
			}
			f.Transpositions = &tp
		}
		f.Value = full.Value
		f.Fuzziness = full.Fuzziness
		f.PrefixLength = full.PrefixLength
		f.MaxExpansions = full.MaxExpansions
		f.Rewrite = full.Rewrite
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
	Values            []string           `json:"values"`
	Boost             *float64           `json:"boost,omitempty"`
	Name              string             `json:"_name,omitempty"`
	ResolvedScores    map[string]float64 `json:"-"`
	ResolvedInnerHits map[string]any     `json:"-"`
	InnerHitsSpec     *InnerHitsSpec     `json:"-"`
	JoinQueryType     string             `json:"-"`
	JoinRelType       string             `json:"-"`
	JoinScoreMode     string             `json:"-"`
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
	Relation     string   `json:"relation,omitempty"`
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
		Relation     string          `json:"relation"`
	}
	if err := json.Unmarshal(trimmed, &full); err != nil {
		return err
	}
	if strings.TrimSpace(full.Relation) != "" {
		rel := strings.ToUpper(strings.TrimSpace(full.Relation))
		switch rel {
		case "INTERSECTS", "CONTAINS", "WITHIN":
			rc.Relation = rel
		default:
			return fmt.Errorf("parsing_exception: [range] relation [%s] is not supported; must be INTERSECTS, CONTAINS, or WITHIN", full.Relation)
		}
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
	Query               any     `json:"query"`
	Operator            string  `json:"operator,omitempty"`
	Analyzer            string  `json:"analyzer,omitempty"`
	Boost               float64 `json:"boost,omitempty"`
	ZeroTermsQuery      string  `json:"zero_terms_query,omitempty"`
	MinimumShouldMatch  any     `json:"minimum_should_match,omitempty"`
	Fuzziness           any     `json:"fuzziness,omitempty"`
	PrefixLength        int     `json:"prefix_length,omitempty"`
	MaxExpansions       int     `json:"max_expansions,omitempty"`
	FuzzyTranspositions *bool   `json:"fuzzy_transpositions,omitempty"`
	FuzzyRewrite        string  `json:"fuzzy_rewrite,omitempty"`
	Lenient             *bool   `json:"lenient,omitempty"`
	HasBoost            bool    `json:"-"`
}

func (m MatchEntry) MarshalJSON() ([]byte, error) {
	var boostPtr *float64
	if m.HasBoost || (m.Boost != 0 && m.Boost != 1.0) {
		b := m.Boost
		boostPtr = &b
	}
	return json.Marshal(struct {
		Query               any      `json:"query"`
		Operator            string   `json:"operator,omitempty"`
		Analyzer            string   `json:"analyzer,omitempty"`
		Boost               *float64 `json:"boost,omitempty"`
		ZeroTermsQuery      string   `json:"zero_terms_query,omitempty"`
		MinimumShouldMatch  any      `json:"minimum_should_match,omitempty"`
		Fuzziness           any      `json:"fuzziness,omitempty"`
		PrefixLength        int      `json:"prefix_length,omitempty"`
		MaxExpansions       int      `json:"max_expansions,omitempty"`
		FuzzyTranspositions *bool    `json:"fuzzy_transpositions,omitempty"`
		FuzzyRewrite        string   `json:"fuzzy_rewrite,omitempty"`
		Lenient             *bool    `json:"lenient,omitempty"`
	}{
		Query:               m.Query,
		Operator:            m.Operator,
		Analyzer:            m.Analyzer,
		Boost:               boostPtr,
		ZeroTermsQuery:      m.ZeroTermsQuery,
		MinimumShouldMatch:  m.MinimumShouldMatch,
		Fuzziness:           m.Fuzziness,
		PrefixLength:        m.PrefixLength,
		MaxExpansions:       m.MaxExpansions,
		FuzzyTranspositions: m.FuzzyTranspositions,
		FuzzyRewrite:        m.FuzzyRewrite,
		Lenient:             m.Lenient,
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
			Query               any             `json:"query"`
			Operator            string          `json:"operator"`
			Analyzer            string          `json:"analyzer"`
			Boost               json.RawMessage `json:"boost"`
			ZeroTermsQuery      string          `json:"zero_terms_query"`
			MinimumShouldMatch  any             `json:"minimum_should_match"`
			Fuzziness           any             `json:"fuzziness"`
			PrefixLength        int             `json:"prefix_length"`
			MaxExpansions       int             `json:"max_expansions"`
			FuzzyTranspositions *bool           `json:"fuzzy_transpositions"`
			FuzzyRewrite        string          `json:"fuzzy_rewrite"`
			Lenient             any             `json:"lenient"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		if isNonScalarOrNullValue(full.Query) {
			return fmt.Errorf("parsing_exception: [match] query does not support non-scalar or null value")
		}
		m.Query = full.Query
		m.Analyzer = strings.TrimSpace(full.Analyzer)
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
		if full.Fuzziness != nil {
			if err := validateFuzzinessValue(full.Fuzziness, "match"); err != nil {
				return err
			}
		}
		if full.PrefixLength < 0 {
			return fmt.Errorf("parsing_exception: [match] prefix_length must be non-negative, got [%d]", full.PrefixLength)
		}
		if _, hasMaxExp := rawMap["max_expansions"]; (hasMaxExp && full.MaxExpansions <= 0) || full.MaxExpansions < 0 {
			return fmt.Errorf("parsing_exception: [match] max_expansions must be positive, got [%d]", full.MaxExpansions)
		}
		m.ZeroTermsQuery = full.ZeroTermsQuery
		m.MinimumShouldMatch = full.MinimumShouldMatch
		m.Fuzziness = full.Fuzziness
		m.PrefixLength = full.PrefixLength
		m.MaxExpansions = full.MaxExpansions
		m.FuzzyTranspositions = full.FuzzyTranspositions
		m.FuzzyRewrite = full.FuzzyRewrite
		if full.Lenient != nil {
			ln, err := parseFlexibleBool(full.Lenient)
			if err != nil {
				return err
			}
			m.Lenient = &ln
		}
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

type CommonTermsEntry struct {
	Query              any     `json:"query"`
	CutoffFrequency    float64 `json:"cutoff_frequency,omitempty"`
	LowFreqOperator    string  `json:"low_freq_operator,omitempty"`
	HighFreqOperator   string  `json:"high_freq_operator,omitempty"`
	MinimumShouldMatch any     `json:"minimum_should_match,omitempty"`
	Analyzer           string  `json:"analyzer,omitempty"`
	Boost              float64 `json:"boost,omitempty"`
	HasBoost           bool    `json:"-"`
}

func (c CommonTermsEntry) MarshalJSON() ([]byte, error) {
	var boostPtr *float64
	if c.HasBoost || (c.Boost != 0 && c.Boost != 1.0) {
		b := c.Boost
		boostPtr = &b
	}
	return json.Marshal(struct {
		Query              any      `json:"query"`
		CutoffFrequency    float64  `json:"cutoff_frequency,omitempty"`
		LowFreqOperator    string   `json:"low_freq_operator,omitempty"`
		HighFreqOperator   string   `json:"high_freq_operator,omitempty"`
		MinimumShouldMatch any      `json:"minimum_should_match,omitempty"`
		Analyzer           string   `json:"analyzer,omitempty"`
		Boost              *float64 `json:"boost,omitempty"`
	}{
		Query:              c.Query,
		CutoffFrequency:    c.CutoffFrequency,
		LowFreqOperator:    c.LowFreqOperator,
		HighFreqOperator:   c.HighFreqOperator,
		MinimumShouldMatch: c.MinimumShouldMatch,
		Analyzer:           c.Analyzer,
		Boost:              boostPtr,
	})
}

func (c *CommonTermsEntry) UnmarshalJSON(data []byte) error {
	c.Boost = 1.0
	c.HasBoost = false
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err != nil {
			return err
		}
		for k := range rawMap {
			switch k {
			case "query", "cutoff_frequency", "low_freq_operator", "high_freq_operator", "minimum_should_match", "analyzer", "boost", "_name":
			default:
				return fmt.Errorf("parsing_exception: [common] unknown field [%s]", k)
			}
		}
		if _, hasQuery := rawMap["query"]; !hasQuery {
			return fmt.Errorf("parsing_exception: [common] missing required [query] field")
		}
		var full struct {
			Query              any             `json:"query"`
			CutoffFrequency    float64         `json:"cutoff_frequency"`
			LowFreqOperator    string          `json:"low_freq_operator"`
			HighFreqOperator   string          `json:"high_freq_operator"`
			MinimumShouldMatch any             `json:"minimum_should_match"`
			Analyzer           string          `json:"analyzer"`
			Boost              json.RawMessage `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		if isNonScalarOrNullValue(full.Query) {
			return fmt.Errorf("parsing_exception: [common] query does not support non-scalar or null value")
		}
		c.Query = full.Query
		c.CutoffFrequency = full.CutoffFrequency
		c.Analyzer = strings.TrimSpace(full.Analyzer)
		if full.LowFreqOperator != "" {
			if err := validateQueryOperator(full.LowFreqOperator, "common"); err != nil {
				return err
			}
			c.LowFreqOperator = strings.ToLower(strings.TrimSpace(full.LowFreqOperator))
		}
		if full.HighFreqOperator != "" {
			if err := validateQueryOperator(full.HighFreqOperator, "common"); err != nil {
				return err
			}
			c.HighFreqOperator = strings.ToLower(strings.TrimSpace(full.HighFreqOperator))
		}
		c.MinimumShouldMatch = full.MinimumShouldMatch
		if len(full.Boost) > 0 {
			b, err := parseOptionalNonNegativeBoost(full.Boost)
			if err != nil {
				return err
			}
			if b != nil {
				c.Boost = *b
				c.HasBoost = true
			}
		}
		return nil
	}
	if err := json.Unmarshal(trimmed, &c.Query); err != nil {
		return err
	}
	if isNonScalarOrNullValue(c.Query) {
		return fmt.Errorf("parsing_exception: [common] query does not support non-scalar or null value")
	}
	return nil
}

type PhraseEntry struct {
	Query               string  `json:"query"`
	Slop                int     `json:"slop,omitempty"`
	Operator            string  `json:"operator,omitempty"`
	Analyzer            string  `json:"analyzer,omitempty"`
	MinimumShouldMatch  any     `json:"minimum_should_match,omitempty"`
	ZeroTermsQuery      string  `json:"zero_terms_query,omitempty"`
	Fuzziness           any     `json:"fuzziness,omitempty"`
	MaxExpansions       int     `json:"max_expansions,omitempty"`
	PrefixLength        int     `json:"prefix_length,omitempty"`
	FuzzyTranspositions *bool   `json:"fuzzy_transpositions,omitempty"`
	FuzzyRewrite        string  `json:"fuzzy_rewrite,omitempty"`
	Lenient             *bool   `json:"lenient,omitempty"`
	Boost               float64 `json:"boost,omitempty"`
	HasBoost            bool    `json:"-"`
}

func (p PhraseEntry) MarshalJSON() ([]byte, error) {
	var boostPtr *float64
	if p.HasBoost || (p.Boost != 0 && p.Boost != 1.0) {
		b := p.Boost
		boostPtr = &b
	}
	return json.Marshal(struct {
		Query               string   `json:"query"`
		Slop                int      `json:"slop,omitempty"`
		Operator            string   `json:"operator,omitempty"`
		Analyzer            string   `json:"analyzer,omitempty"`
		MinimumShouldMatch  any      `json:"minimum_should_match,omitempty"`
		ZeroTermsQuery      string   `json:"zero_terms_query,omitempty"`
		Fuzziness           any      `json:"fuzziness,omitempty"`
		MaxExpansions       int      `json:"max_expansions,omitempty"`
		PrefixLength        int      `json:"prefix_length,omitempty"`
		FuzzyTranspositions *bool    `json:"fuzzy_transpositions,omitempty"`
		FuzzyRewrite        string   `json:"fuzzy_rewrite,omitempty"`
		Lenient             *bool    `json:"lenient,omitempty"`
		Boost               *float64 `json:"boost,omitempty"`
	}{
		Query:               p.Query,
		Slop:                p.Slop,
		Operator:            p.Operator,
		Analyzer:            p.Analyzer,
		MinimumShouldMatch:  p.MinimumShouldMatch,
		ZeroTermsQuery:      p.ZeroTermsQuery,
		Fuzziness:           p.Fuzziness,
		MaxExpansions:       p.MaxExpansions,
		PrefixLength:        p.PrefixLength,
		FuzzyTranspositions: p.FuzzyTranspositions,
		FuzzyRewrite:        p.FuzzyRewrite,
		Lenient:             p.Lenient,
		Boost:               boostPtr,
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
			case "query", "slop", "operator", "minimum_should_match", "zero_terms_query", "fuzziness", "boost", "analyzer",
				"max_expansions", "prefix_length", "fuzzy_transpositions", "fuzzy_rewrite", "lenient",
				"auto_generate_synonyms_phrase_query", "_name":
			default:
				return fmt.Errorf("parsing_exception: [match_phrase] unknown field [%s]", k)
			}
		}
		if _, hasQ := rawMap["query"]; !hasQ {
			return fmt.Errorf("parsing_exception: [match_phrase] missing required [query] field")
		}
		var full struct {
			Query               any             `json:"query"`
			Slop                int             `json:"slop"`
			Operator            string          `json:"operator"`
			Analyzer            string          `json:"analyzer"`
			MinimumShouldMatch  any             `json:"minimum_should_match"`
			ZeroTermsQuery      string          `json:"zero_terms_query"`
			Fuzziness           any             `json:"fuzziness"`
			MaxExpansions       int             `json:"max_expansions"`
			PrefixLength        int             `json:"prefix_length"`
			FuzzyTranspositions any             `json:"fuzzy_transpositions"`
			FuzzyRewrite        string          `json:"fuzzy_rewrite"`
			Lenient             any             `json:"lenient"`
			Boost               json.RawMessage `json:"boost"`
		}
		if err := json.Unmarshal(trimmed, &full); err != nil {
			return err
		}
		if isNonScalarOrNullValue(full.Query) {
			return fmt.Errorf("parsing_exception: [match_phrase] query does not support non-scalar or null value")
		}
		p.Query = fmt.Sprintf("%v", full.Query)
		p.Analyzer = strings.TrimSpace(full.Analyzer)
		if full.Slop < 0 {
			return fmt.Errorf("parsing_exception: [match_phrase] slop must be non-negative, got [%d]", full.Slop)
		}
		if full.Fuzziness != nil {
			if err := validateFuzzinessValue(full.Fuzziness, "match_phrase"); err != nil {
				return err
			}
		}
		if _, hasMaxExp := rawMap["max_expansions"]; (hasMaxExp && full.MaxExpansions <= 0) || full.MaxExpansions < 0 {
			return fmt.Errorf("parsing_exception: [match_phrase] max_expansions must be positive, got [%d]", full.MaxExpansions)
		}
		if full.PrefixLength < 0 {
			return fmt.Errorf("parsing_exception: [match_phrase] prefix_length must be non-negative, got [%d]", full.PrefixLength)
		}
		p.Slop = full.Slop
		p.MaxExpansions = full.MaxExpansions
		p.PrefixLength = full.PrefixLength
		p.FuzzyRewrite = full.FuzzyRewrite
		if full.FuzzyTranspositions != nil {
			ft, err := parseFlexibleBool(full.FuzzyTranspositions)
			if err != nil {
				return err
			}
			p.FuzzyTranspositions = &ft
		}
		if full.Lenient != nil {
			ln, err := parseFlexibleBool(full.Lenient)
			if err != nil {
				return err
			}
			p.Lenient = &ln
		}
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
	Query               any      `json:"query"`
	Fields              []string `json:"fields,omitempty"`
	Type                string   `json:"type,omitempty"`
	Operator            string   `json:"operator,omitempty"`
	Analyzer            string   `json:"analyzer,omitempty"`
	Slop                int      `json:"slop,omitempty"`
	MinimumShouldMatch  any      `json:"minimum_should_match,omitempty"`
	TieBreaker          *float64 `json:"tie_breaker,omitempty"`
	ZeroTermsQuery      string   `json:"zero_terms_query,omitempty"`
	Fuzziness           any      `json:"fuzziness,omitempty"`
	PrefixLength        int      `json:"prefix_length,omitempty"`
	MaxExpansions       int      `json:"max_expansions,omitempty"`
	FuzzyTranspositions *bool    `json:"fuzzy_transpositions,omitempty"`
	Lenient             *bool    `json:"lenient,omitempty"`
	Boost               *float64 `json:"boost,omitempty"`
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
		Fields              any             `json:"fields"`
		FuzzyTranspositions any             `json:"fuzzy_transpositions"`
		Lenient             any             `json:"lenient"`
		Boost               json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*mmq = MultiMatchQuery(raw.plain)
	if raw.FuzzyTranspositions != nil {
		ft, err := parseFlexibleBool(raw.FuzzyTranspositions)
		if err != nil {
			return err
		}
		mmq.FuzzyTranspositions = &ft
	}
	if raw.Lenient != nil {
		ln, err := parseFlexibleBool(raw.Lenient)
		if err != nil {
			return err
		}
		mmq.Lenient = &ln
	}
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
	if mmq.Fuzziness != nil {
		if err := validateFuzzinessValue(mmq.Fuzziness, "multi_match"); err != nil {
			return err
		}
	}
	if mmq.PrefixLength < 0 {
		return fmt.Errorf("parsing_exception: [multi_match] prefix_length must be non-negative, got [%d]", mmq.PrefixLength)
	}
	if _, hasMaxExp := rawMap["max_expansions"]; (hasMaxExp && mmq.MaxExpansions <= 0) || mmq.MaxExpansions < 0 {
		return fmt.Errorf("parsing_exception: [multi_match] max_expansions must be positive, got [%d]", mmq.MaxExpansions)
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
	Analyzer                        string   `json:"analyzer,omitempty"`
	QuoteAnalyzer                   string   `json:"quote_analyzer,omitempty"`
	MinimumShouldMatch              any      `json:"minimum_should_match,omitempty"`
	QuoteFieldSuffix                string   `json:"quote_field_suffix,omitempty"`
	Flags                           string   `json:"flags,omitempty"`
	TimeZone                        string   `json:"time_zone,omitempty"`
	Type                            string   `json:"type,omitempty"`
	TieBreaker                      *float64 `json:"tie_breaker,omitempty"`
	PhraseSlop                      int      `json:"phrase_slop,omitempty"`
	Fuzziness                       any      `json:"fuzziness,omitempty"`
	FuzzyPrefixLength               int      `json:"fuzzy_prefix_length,omitempty"`
	FuzzyMaxExpansions              int      `json:"fuzzy_max_expansions,omitempty"`
	FuzzyTranspositions             *bool    `json:"fuzzy_transpositions,omitempty"`
	Lenient                         *bool    `json:"lenient,omitempty"`
	ZeroTermsQuery                  string   `json:"zero_terms_query,omitempty"`
	AnalyzeWildcard                 *bool    `json:"analyze_wildcard,omitempty"`
	AllowLeadingWildcard            *bool    `json:"allow_leading_wildcard,omitempty"`
	AutoGenerateSynonymsPhraseQuery *bool    `json:"auto_generate_synonyms_phrase_query,omitempty"`
	Escape                          *bool    `json:"escape,omitempty"`
	Boost                           *float64 `json:"boost,omitempty"`
}

func validateFuzzinessValue(v any, queryName string) error {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case float64:
		if val == 0 || val == 1 || val == 2 {
			return nil
		}
	case int:
		if val >= 0 && val <= 2 {
			return nil
		}
	case int64:
		if val >= 0 && val <= 2 {
			return nil
		}
	case json.Number:
		if n, err := val.Int64(); err == nil && n >= 0 && n <= 2 {
			return nil
		}
	case string:
		s := strings.ToUpper(strings.TrimSpace(val))
		if s == "0" || s == "1" || s == "2" || s == "AUTO" || strings.HasPrefix(s, "AUTO:") {
			return nil
		}
	}
	return fmt.Errorf("illegal_argument_exception: [%s] invalid fuzziness [%v]", queryName, v)
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
	if _, hasQ := rawMap["query"]; !hasQ {
		return fmt.Errorf("parsing_exception: [query_string] must be provided with a [query]")
	}
	type plain QueryStringQuery
	var raw struct {
		plain
		Query                           any             `json:"query"`
		Fields                          any             `json:"fields"`
		FuzzyMaxExpansions              *int            `json:"fuzzy_max_expansions"`
		FuzzyPrefixLength               *int            `json:"fuzzy_prefix_length"`
		FuzzyTranspositions             any             `json:"fuzzy_transpositions"`
		Lenient                         any             `json:"lenient"`
		AnalyzeWildcard                 any             `json:"analyze_wildcard"`
		AllowLeadingWildcard            any             `json:"allow_leading_wildcard"`
		AutoGenerateSynonymsPhraseQuery any             `json:"auto_generate_synonyms_phrase_query"`
		EnablePositionIncrements        any             `json:"enable_position_increments"`
		SplitOnWhitespace               any             `json:"split_on_whitespace"`
		Escape                          any             `json:"escape"`
		Boost                           json.RawMessage `json:"boost"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	*qsq = QueryStringQuery(raw.plain)
	if raw.FuzzyMaxExpansions != nil {
		if *raw.FuzzyMaxExpansions <= 0 {
			return fmt.Errorf("illegal_argument_exception: [query_string] [fuzzy_max_expansions] must be > 0")
		}
		qsq.FuzzyMaxExpansions = *raw.FuzzyMaxExpansions
	}
	if raw.FuzzyPrefixLength != nil {
		if *raw.FuzzyPrefixLength < 0 {
			return fmt.Errorf("illegal_argument_exception: [query_string] [fuzzy_prefix_length] must be >= 0")
		}
		qsq.FuzzyPrefixLength = *raw.FuzzyPrefixLength
	}
	if qsq.Fuzziness != nil {
		if err := validateFuzzinessValue(qsq.Fuzziness, "query_string"); err != nil {
			return err
		}
	}
	if len(raw.Boost) > 0 {
		b, err := parseOptionalNonNegativeBoost(raw.Boost)
		if err != nil {
			return err
		}
		qsq.Boost = b
	}
	if raw.FuzzyTranspositions != nil {
		b, err := parseFlexibleBool(raw.FuzzyTranspositions)
		if err != nil {
			return fmt.Errorf("parsing_exception: [query_string] [fuzzy_transpositions] %w", err)
		}
		qsq.FuzzyTranspositions = &b
	}
	if raw.Lenient != nil {
		b, err := parseFlexibleBool(raw.Lenient)
		if err != nil {
			return fmt.Errorf("parsing_exception: [query_string] [lenient] %w", err)
		}
		qsq.Lenient = &b
	}
	if raw.AnalyzeWildcard != nil {
		b, err := parseFlexibleBool(raw.AnalyzeWildcard)
		if err != nil {
			return fmt.Errorf("parsing_exception: [query_string] [analyze_wildcard] %w", err)
		}
		qsq.AnalyzeWildcard = &b
	}
	if raw.AllowLeadingWildcard != nil {
		b, err := parseFlexibleBool(raw.AllowLeadingWildcard)
		if err != nil {
			return fmt.Errorf("parsing_exception: [query_string] [allow_leading_wildcard] %w", err)
		}
		qsq.AllowLeadingWildcard = &b
	}
	if raw.AutoGenerateSynonymsPhraseQuery != nil {
		b, err := parseFlexibleBool(raw.AutoGenerateSynonymsPhraseQuery)
		if err != nil {
			return fmt.Errorf("parsing_exception: [query_string] [auto_generate_synonyms_phrase_query] %w", err)
		}
		qsq.AutoGenerateSynonymsPhraseQuery = &b
	}
	if raw.Escape != nil {
		b, err := parseFlexibleBool(raw.Escape)
		if err != nil {
			return fmt.Errorf("parsing_exception: [query_string] [escape] %w", err)
		}
		qsq.Escape = &b
	}
	for name, val := range map[string]any{
		"enable_position_increments": raw.EnablePositionIncrements,
		"split_on_whitespace":        raw.SplitOnWhitespace,
	} {
		if val != nil {
			if _, err := parseFlexibleBool(val); err != nil {
				return fmt.Errorf("parsing_exception: [query_string] [%s] %w", name, err)
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(qsq.Type)) {
	case "", "best_fields", "most_fields", "cross_fields", "phrase", "phrase_prefix", "bool_prefix":
	default:
		return fmt.Errorf("parsing_exception: [query_string] unknown type [%s]", qsq.Type)
	}
	if strings.TrimSpace(qsq.Flags) != "" {
		validFlags := map[string]bool{
			"ALL": true, "NONE": true, "AND": true, "OR": true, "NOT": true,
			"PREFIX": true, "PHRASE": true, "PRECEDENCE": true, "ESCAPE": true,
			"WHITESPACE": true, "FUZZY": true, "NEAR": true, "SLOP": true,
		}
		for _, tok := range strings.Split(qsq.Flags, "|") {
			ft := strings.ToUpper(strings.TrimSpace(tok))
			if !validFlags[ft] {
				return fmt.Errorf("illegal_argument_exception: [query_string] unknown flag [%s] in [flags]", tok)
			}
		}
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
	if err := validateOriginValue(inner.Origin, fmt.Sprintf("decay function for [%s]", df.Field)); err != nil {
		return err
	}
	if err := validatePositiveScaleOrPivot(inner.Scale, fmt.Sprintf("decay function [%s] [scale]", df.Field)); err != nil {
		return err
	}
	if err := validateNonNegativeOffset(inner.Offset, fmt.Sprintf("decay function [%s] [offset]", df.Field)); err != nil {
		return err
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

func (rs *RandomScoreSpec) UnmarshalJSON(data []byte) error {
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
		case "seed", "field":
		default:
			return fmt.Errorf("parsing_exception: [random_score] unknown field [%s]", k)
		}
	}
	type plain RandomScoreSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if _, hasSeed := rawMap["seed"]; hasSeed {
		if p.Seed == nil {
			return fmt.Errorf("parsing_exception: [random_score] [seed] cannot be null")
		}
		switch sv := p.Seed.(type) {
		case string:
			if strings.TrimSpace(sv) == "" {
				return fmt.Errorf("parsing_exception: [random_score] [seed] cannot be empty")
			}
		case float64, int, int64, json.Number:
		default:
			return fmt.Errorf("parsing_exception: [random_score] [seed] must be a number or string")
		}
	}
	*rs = RandomScoreSpec(p)
	return nil
}

type ScriptScoreFunctionSpec struct {
	Script any `json:"script,omitempty"`
}

func validateScriptValue(script any) error {
	if script == nil {
		return fmt.Errorf("parsing_exception: [script_score] requires [script]")
	}
	switch sv := script.(type) {
	case string:
		if strings.TrimSpace(sv) == "" {
			return fmt.Errorf("parsing_exception: [script_score] [script] cannot be empty")
		}
		return nil
	case map[string]any:
		if len(sv) == 0 {
			return fmt.Errorf("parsing_exception: [script_score] [script] requires [source] or [id]")
		}
		hasCode := false
		for k, v := range sv {
			switch k {
			case "source", "inline", "id":
				if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
					hasCode = true
				}
			case "lang", "params", "options":
			default:
				return fmt.Errorf("parsing_exception: [script_score] unknown field [%s] in [script]", k)
			}
		}
		if !hasCode {
			return fmt.Errorf("parsing_exception: [script_score] [script] requires non-empty [source] or [id]")
		}
		return nil
	default:
		return fmt.Errorf("parsing_exception: [script_score] [script] must be a string or object")
	}
}

func (ssf *ScriptScoreFunctionSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		if k != "script" {
			return fmt.Errorf("parsing_exception: [script_score] unknown field [%s]", k)
		}
	}
	rawScript, hasScript := rawMap["script"]
	if !hasScript || len(bytes.TrimSpace(rawScript)) == 0 || bytes.Equal(bytes.TrimSpace(rawScript), []byte("null")) {
		return fmt.Errorf("parsing_exception: [script_score] requires [script]")
	}
	type plain ScriptScoreFunctionSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if err := validateScriptValue(p.Script); err != nil {
		return err
	}
	*ssf = ScriptScoreFunctionSpec(p)
	return nil
}

type FieldValueFactorSpec struct {
	Field    string   `json:"field"`
	Factor   *float64 `json:"factor,omitempty"`
	Modifier string   `json:"modifier,omitempty"`
	Missing  *float64 `json:"missing,omitempty"`
}

func (fvf *FieldValueFactorSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "factor", "modifier", "missing":
		default:
			return fmt.Errorf("parsing_exception: [field_value_factor] unknown field [%s]", k)
		}
	}
	type plain FieldValueFactorSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" {
		return fmt.Errorf("parsing_exception: [field_value_factor] requires non-empty [field]")
	}
	if p.Factor != nil && (*p.Factor < 0 || math.IsNaN(*p.Factor) || math.IsInf(*p.Factor, 0)) {
		return fmt.Errorf("parsing_exception: [field_value_factor] [factor] must be >= 0")
	}
	switch strings.ToLower(strings.TrimSpace(p.Modifier)) {
	case "", "none", "log", "log1p", "log2p", "ln", "ln1p", "ln2p", "square", "sqrt", "reciprocal":
		p.Modifier = strings.ToLower(strings.TrimSpace(p.Modifier))
	default:
		return fmt.Errorf("parsing_exception: [field_value_factor] unknown modifier [%s]", p.Modifier)
	}
	*fvf = FieldValueFactorSpec(p)
	return nil
}

var knownAggTypeKeys = map[string]bool{
	"terms":                     true,
	"multi_terms":               true,
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
	"categorize_text":           true,
	"frequent_item_sets":        true,
	"moving_percentiles":        true,
	"cartesian_bounds":          true,
	"cartesian_centroid":        true,
	"geo_line":                  true,
	"random_sampler":            true,
}

// AggSpec represents an Elasticsearch aggregation definition.
type AggSpec struct {
	Terms                   *TermsAggSpec                  `json:"terms,omitempty"`
	MultiTerms              *MultiTermsAggSpec             `json:"multi_terms,omitempty"`
	RareTerms               *RareTermsAggSpec              `json:"rare_terms,omitempty"`
	SignificantTerms        *TermsAggSpec                  `json:"significant_terms,omitempty"`
	SignificantText         *TermsAggSpec                  `json:"significant_text,omitempty"`
	CategorizeText          *CategorizeTextAggSpec         `json:"categorize_text,omitempty"`
	FrequentItemSets        *FrequentItemSetsAggSpec       `json:"frequent_item_sets,omitempty"`
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
	RandomSampler           *RandomSamplerAggSpec          `json:"random_sampler,omitempty"`
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
	CartesianBounds         *GeoBoundsAggSpec              `json:"cartesian_bounds,omitempty"`
	CartesianCentroid       *MetricAggSpec                 `json:"cartesian_centroid,omitempty"`
	GeoLine                 *GeoLineAggSpec                `json:"geo_line,omitempty"`
	GeoDistance             *GeoDistanceAggSpec            `json:"geo_distance,omitempty"`
	GeohashGrid             *GeoGridAggSpec                `json:"geohash_grid,omitempty"`
	GeotileGrid             *GeoGridAggSpec                `json:"geotile_grid,omitempty"`
	BucketSort              *BucketSortAggSpec             `json:"bucket_sort,omitempty"`
	CumulativeSum           *PipelineAggSpec               `json:"cumulative_sum,omitempty"`
	CumulativeCardinality   *PipelineAggSpec               `json:"cumulative_cardinality,omitempty"`
	Derivative              *PipelineAggSpec               `json:"derivative,omitempty"`
	MovingAvg               *MovingAvgAggSpec              `json:"moving_avg,omitempty"`
	MovingFn                *MovingAvgAggSpec              `json:"moving_fn,omitempty"`
	MovingPercentiles       *MovingPercentilesAggSpec      `json:"moving_percentiles,omitempty"`
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

// CategorizeTextAggSpec models an ES `categorize_text` bucket aggregation.
type CategorizeTextAggSpec struct {
	Field                  string         `json:"field"`
	CategorizationAnalyzer any            `json:"categorization_analyzer,omitempty"`
	CategorizationFilters  []string       `json:"categorization_filters,omitempty"`
	MaxMatchedTokens       *int           `json:"max_matched_tokens,omitempty"`
	MinDocCount            *int           `json:"min_doc_count,omitempty"`
	ShardMinDocCount       *int           `json:"shard_min_doc_count,omitempty"`
	Size                   *int           `json:"size,omitempty"`
	ShardSize              *int           `json:"shard_size,omitempty"`
	SimilarityThreshold    *int           `json:"similarity_threshold,omitempty"`
	Order                  map[string]any `json:"order,omitempty"`
}

type CategorizeTextAgg = CategorizeTextAggSpec

func (c *CategorizeTextAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "categorization_analyzer", "categorization_filters", "max_matched_tokens",
			"min_doc_count", "shard_min_doc_count", "size", "shard_size", "similarity_threshold",
			"order", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [categorize_text] unknown field [%s]", k)
		}
	}
	type plain CategorizeTextAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" {
		return fmt.Errorf("parsing_exception: [categorize_text] requires non-empty [field]")
	}
	if p.Size != nil && *p.Size < 1 {
		return fmt.Errorf("illegal_argument_exception: [categorize_text] [size] must be >= 1")
	}
	if p.ShardSize != nil && *p.ShardSize < 1 {
		return fmt.Errorf("illegal_argument_exception: [categorize_text] [shard_size] must be >= 1")
	}
	if p.MinDocCount != nil && *p.MinDocCount < 1 {
		return fmt.Errorf("illegal_argument_exception: [categorize_text] [min_doc_count] must be >= 1")
	}
	if p.ShardMinDocCount != nil && *p.ShardMinDocCount < 1 {
		return fmt.Errorf("illegal_argument_exception: [categorize_text] [shard_min_doc_count] must be >= 1")
	}
	if p.MaxMatchedTokens != nil && (*p.MaxMatchedTokens < 1 || *p.MaxMatchedTokens > 100) {
		return fmt.Errorf("illegal_argument_exception: [categorize_text] [max_matched_tokens] must be in [1, 100]")
	}
	if p.SimilarityThreshold != nil && (*p.SimilarityThreshold < 1 || *p.SimilarityThreshold > 100) {
		return fmt.Errorf("illegal_argument_exception: [categorize_text] [similarity_threshold] must be in [1, 100]")
	}
	*c = CategorizeTextAggSpec(p)
	return nil
}

// FrequentItemSetsFieldSpec models an entry in `frequent_item_sets.fields`.
type FrequentItemSetsFieldSpec struct {
	Field   string   `json:"field"`
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// FrequentItemSetsAggSpec models an ES `frequent_item_sets` bucket aggregation.
type FrequentItemSetsAggSpec struct {
	Fields         []FrequentItemSetsFieldSpec `json:"fields"`
	MinimumSetSize *int                        `json:"minimum_set_size,omitempty"`
	Support        *float64                    `json:"support,omitempty"`
	Size           *int                        `json:"size,omitempty"`
	Filter         *Query                      `json:"filter,omitempty"`
}

type FrequentItemSetsAgg = FrequentItemSetsAggSpec

func (f *FrequentItemSetsAggSpec) UnmarshalJSON(data []byte) error {
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
		case "fields", "minimum_set_size", "support", "size", "filter", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [frequent_item_sets] unknown field [%s]", k)
		}
	}
	type plain FrequentItemSetsAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if len(p.Fields) == 0 {
		return fmt.Errorf("parsing_exception: [frequent_item_sets] requires non-empty [fields]")
	}
	for _, fld := range p.Fields {
		if strings.TrimSpace(fld.Field) == "" {
			return fmt.Errorf("parsing_exception: [frequent_item_sets] field entry requires non-empty [field]")
		}
	}
	if p.MinimumSetSize != nil && *p.MinimumSetSize < 1 {
		return fmt.Errorf("illegal_argument_exception: [frequent_item_sets] [minimum_set_size] must be >= 1")
	}
	if p.Support != nil && (*p.Support <= 0 || *p.Support > 1 || math.IsNaN(*p.Support) || math.IsInf(*p.Support, 0)) {
		return fmt.Errorf("illegal_argument_exception: [frequent_item_sets] [support] must be in (0, 1]")
	}
	if p.Size != nil && *p.Size < 1 {
		return fmt.Errorf("illegal_argument_exception: [frequent_item_sets] [size] must be >= 1")
	}
	*f = FrequentItemSetsAggSpec(p)
	return nil
}

// MovingPercentilesAggSpec models an ES `moving_percentiles` pipeline aggregation.
type MovingPercentilesAggSpec struct {
	BucketsPath string `json:"buckets_path"`
	Window      *int   `json:"window,omitempty"`
	Shift       *int   `json:"shift,omitempty"`
	Keyed       *bool  `json:"keyed,omitempty"`
}

type MovingPercentilesAgg = MovingPercentilesAggSpec

func (mp *MovingPercentilesAggSpec) UnmarshalJSON(data []byte) error {
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
		case "buckets_path", "window", "shift", "keyed", "meta":
		default:
			return fmt.Errorf("parsing_exception: [moving_percentiles] unknown field [%s]", k)
		}
	}
	type plain MovingPercentilesAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.BucketsPath) == "" {
		return fmt.Errorf("parsing_exception: [moving_percentiles] requires non-empty [buckets_path]")
	}
	if p.Window != nil && *p.Window <= 0 {
		return fmt.Errorf("illegal_argument_exception: [moving_percentiles] [window] must be > 0")
	}
	if p.Shift != nil && *p.Shift < 0 {
		return fmt.Errorf("illegal_argument_exception: [moving_percentiles] [shift] must be >= 0")
	}
	*mp = MovingPercentilesAggSpec(p)
	return nil
}

// GeoLinePointSpec models `point` or `sort` inside `geo_line`.
type GeoLinePointSpec struct {
	Field string `json:"field"`
}

// GeoLineAggSpec models an ES `geo_line` metric aggregation.
type GeoLineAggSpec struct {
	Point       GeoLinePointSpec  `json:"point"`
	Sort        *GeoLinePointSpec `json:"sort,omitempty"`
	IncludeSort *bool             `json:"include_sort,omitempty"`
	SortOrder   string            `json:"sort_order,omitempty"`
	Size        *int              `json:"size,omitempty"`
}

type GeoLineAgg = GeoLineAggSpec
type GeoBoundsAgg = GeoBoundsAggSpec
type GeoCentroidAgg = MetricAggSpec

func (gl *GeoLineAggSpec) UnmarshalJSON(data []byte) error {
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
		case "point", "sort", "include_sort", "sort_order", "size", "meta":
		default:
			return fmt.Errorf("parsing_exception: [geo_line] unknown field [%s]", k)
		}
	}
	type plain GeoLineAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Point.Field) == "" {
		return fmt.Errorf("parsing_exception: [geo_line] requires [point.field]")
	}
	if p.Sort != nil && strings.TrimSpace(p.Sort.Field) == "" {
		return fmt.Errorf("parsing_exception: [geo_line] [sort] requires non-empty [field]")
	}
	switch strings.ToUpper(strings.TrimSpace(p.SortOrder)) {
	case "", "ASC", "DESC":
	default:
		return fmt.Errorf("illegal_argument_exception: [geo_line] invalid [sort_order] [%s]", p.SortOrder)
	}
	if p.Size != nil && (*p.Size < 1 || *p.Size > 10000) {
		return fmt.Errorf("illegal_argument_exception: [geo_line] [size] must be between 1 and 10000")
	}
	*gl = GeoLineAggSpec(p)
	return nil
}

// RandomSamplerAggSpec models an ES `random_sampler` bucket aggregation.
type RandomSamplerAggSpec struct {
	Probability *float64 `json:"probability"`
	Seed        *int64   `json:"seed,omitempty"`
}

type RandomSamplerAgg = RandomSamplerAggSpec

func (rs *RandomSamplerAggSpec) UnmarshalJSON(data []byte) error {
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
		case "probability", "seed", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [random_sampler] unknown field [%s]", k)
		}
	}
	type plain RandomSamplerAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.Probability == nil || *p.Probability <= 0 || *p.Probability >= 1 || math.IsNaN(*p.Probability) || math.IsInf(*p.Probability, 0) {
		return fmt.Errorf("illegal_argument_exception: [random_sampler] [probability] must be in (0, 1)")
	}
	*rs = RandomSamplerAggSpec(p)
	return nil
}

// RareTermsAggSpec models an ES `rare_terms` bucket aggregation.
type RareTermsAggSpec struct {
	Field       string `json:"field"`
	MaxDocCount *int   `json:"max_doc_count,omitempty"`
	Include     any    `json:"include,omitempty"`
	Exclude     any    `json:"exclude,omitempty"`
	Missing     any    `json:"missing,omitempty"`
}

func (r *RareTermsAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "max_doc_count", "include", "exclude", "missing", "precision", "value_type", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [rare_terms] unknown field [%s]", k)
		}
	}
	type plain RareTermsAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" {
		return fmt.Errorf("parsing_exception: [rare_terms] requires [field]")
	}
	if p.MaxDocCount != nil && (*p.MaxDocCount < 1 || *p.MaxDocCount > 100) {
		return fmt.Errorf("illegal_argument_exception: [rare_terms] [max_doc_count] must be between 1 and 100")
	}
	*r = RareTermsAggSpec(p)
	return nil
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

func (a *AutoDateHistogramAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "buckets", "format", "time_zone", "minimum_interval", "missing", "keyed", "offset", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [auto_date_histogram] unknown field [%s]", k)
		}
	}
	type plain AutoDateHistogramAggSpec
	var raw struct {
		plain
		Buckets *int `json:"buckets"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: [auto_date_histogram] requires either [field] or [script]")
	}
	if raw.Buckets != nil {
		if *raw.Buckets <= 0 {
			return fmt.Errorf("parsing_exception: [auto_date_histogram] [buckets] must be > 0")
		}
		p.Buckets = *raw.Buckets
	}
	switch strings.ToLower(strings.TrimSpace(p.MinimumInterval)) {
	case "", "second", "minute", "hour", "day", "month", "year":
	default:
		return fmt.Errorf("parsing_exception: [auto_date_histogram] unknown [minimum_interval] [%s]", p.MinimumInterval)
	}
	*a = AutoDateHistogramAggSpec(p)
	return nil
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
	ShardSize     int    `json:"shard_size,omitempty"`
	Missing       any    `json:"missing,omitempty"`
	Script        any    `json:"script,omitempty"`
}

func (v *VariableWidthHistogramAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "buckets", "initial_buffer", "shard_size", "missing", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [variable_width_histogram] unknown field [%s]", k)
		}
	}
	type plain VariableWidthHistogramAggSpec
	var raw struct {
		plain
		Buckets       *int `json:"buckets"`
		InitialBuffer *int `json:"initial_buffer"`
		ShardSize     *int `json:"shard_size"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: [variable_width_histogram] requires either [field] or [script]")
	}
	if p.Script != nil {
		if err := validateScriptValue(p.Script); err != nil {
			return err
		}
	}
	if raw.Buckets != nil {
		if *raw.Buckets < 1 || *raw.Buckets > 100000 {
			return fmt.Errorf("illegal_argument_exception: [variable_width_histogram] [buckets] must be between 1 and 100000")
		}
		p.Buckets = *raw.Buckets
	}
	if raw.InitialBuffer != nil {
		if *raw.InitialBuffer < 1 {
			return fmt.Errorf("illegal_argument_exception: [variable_width_histogram] [initial_buffer] must be >= 1")
		}
		p.InitialBuffer = *raw.InitialBuffer
	}
	if raw.ShardSize != nil {
		if *raw.ShardSize < 1 {
			return fmt.Errorf("illegal_argument_exception: [variable_width_histogram] [shard_size] must be >= 1")
		}
		p.ShardSize = *raw.ShardSize
	}
	*v = VariableWidthHistogramAggSpec(p)
	return nil
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

func (wf *WeightedAvgFieldSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "missing":
		default:
			return fmt.Errorf("parsing_exception: [weighted_avg] unknown field [%s]", k)
		}
	}
	type plain WeightedAvgFieldSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: [weighted_avg] requires either [field] or [script]")
	}
	if p.Script != nil {
		if err := validateScriptValue(p.Script); err != nil {
			return err
		}
	}
	*wf = WeightedAvgFieldSpec(p)
	return nil
}

// WeightedAvgAggSpec models an ES `weighted_avg` metric aggregation.
type WeightedAvgAggSpec struct {
	Value     WeightedAvgFieldSpec `json:"value"`
	Weight    WeightedAvgFieldSpec `json:"weight"`
	Format    string               `json:"format,omitempty"`
	ValueType string               `json:"value_type,omitempty"`
}

func (w *WeightedAvgAggSpec) UnmarshalJSON(data []byte) error {
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
		case "value", "weight", "format", "value_type", "meta":
		default:
			return fmt.Errorf("parsing_exception: [weighted_avg] unknown field [%s]", k)
		}
	}
	type plain WeightedAvgAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if (strings.TrimSpace(p.Value.Field) == "" && p.Value.Script == nil) ||
		(strings.TrimSpace(p.Weight.Field) == "" && p.Weight.Script == nil) {
		return fmt.Errorf("parsing_exception: [weighted_avg] requires both [value] and [weight]")
	}
	*w = WeightedAvgAggSpec(p)
	return nil
}

// GeoBoundsAggSpec models an ES `geo_bounds` metric aggregation.
type GeoBoundsAggSpec struct {
	Field         string `json:"field"`
	WrapLongitude *bool  `json:"wrap_longitude,omitempty"`
}

func (gb *GeoBoundsAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "wrap_longitude", "meta":
		default:
			return fmt.Errorf("parsing_exception: [geo_bounds] unknown field [%s]", k)
		}
	}
	var raw struct {
		Field         string `json:"field"`
		WrapLongitude any    `json:"wrap_longitude"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Field) == "" {
		return fmt.Errorf("parsing_exception: [geo_bounds] requires [field]")
	}
	gb.Field = raw.Field
	if raw.WrapLongitude != nil {
		b, err := parseFlexibleBool(raw.WrapLongitude)
		if err != nil {
			return fmt.Errorf("parsing_exception: [geo_bounds] [wrap_longitude] %w", err)
		}
		gb.WrapLongitude = &b
	}
	return nil
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

func (gd *GeoDistanceAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "origin", "ranges", "unit", "distance_type", "keyed", "key", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [geo_distance] unknown field [%s]", k)
		}
	}
	type plain GeoDistanceAggSpec
	var raw struct {
		plain
		Keyed any `json:"keyed"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if strings.TrimSpace(p.Field) == "" {
		return fmt.Errorf("parsing_exception: [geo_distance] requires [field]")
	}
	if p.Origin == nil {
		return fmt.Errorf("parsing_exception: [geo_distance] requires [origin]")
	}
	if _, _, err := ParseGeoPoint(p.Origin); err != nil {
		return fmt.Errorf("parsing_exception: [geo_distance] invalid [origin]: %w", err)
	}
	if len(p.Ranges) == 0 {
		return fmt.Errorf("parsing_exception: [geo_distance] requires non-empty [ranges]")
	}
	for _, r := range p.Ranges {
		if r.From == nil && r.To == nil {
			return fmt.Errorf("parsing_exception: [geo_distance] range bucket requires [from] or [to]")
		}
		if r.Mask != "" {
			return fmt.Errorf("parsing_exception: [geo_distance] range bucket does not support [mask]")
		}
	}
	if strings.TrimSpace(p.Unit) != "" {
		if _, ok := GeoDistanceUnitMultiplier(p.Unit); !ok {
			if _, _, err := ParseGeoDistanceMeters("1" + strings.TrimSpace(p.Unit)); err != nil {
				return fmt.Errorf("parsing_exception: [geo_distance] unknown distance unit [%s]", p.Unit)
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(p.DistanceType)) {
	case "", "arc", "plane":
	default:
		return fmt.Errorf("parsing_exception: [geo_distance] invalid [distance_type] [%s]", p.DistanceType)
	}
	if raw.Keyed != nil {
		b, err := parseFlexibleBool(raw.Keyed)
		if err != nil {
			return fmt.Errorf("parsing_exception: [geo_distance] [keyed] %w", err)
		}
		p.Keyed = b
	}
	*gd = GeoDistanceAggSpec(p)
	return nil
}

// ParseGeoBoundingBox validates and extracts `(top, left, bottom, right)` from an ES bounding-box map.
func ParseGeoBoundingBox(bounds map[string]any) (top, left, bottom, right float64, err error) {
	if len(bounds) == 0 {
		return 0, 0, 0, 0, fmt.Errorf("parsing_exception: [bounds] cannot be empty")
	}
	rawBytes, err := json.Marshal(map[string]any{"loc": bounds})
	if err != nil {
		return 0, 0, 0, 0, err
	}
	var q GeoBoundingBoxQuery
	if err := json.Unmarshal(rawBytes, &q); err != nil {
		return 0, 0, 0, 0, err
	}
	return q.Top, q.Left, q.Bottom, q.Right, nil
}

func geohashPrecisionFromMeters(meters float64) int {
	thresholds := []struct {
		maxMeters float64
		precision int
	}{
		{0.037, 12},
		{0.149, 11},
		{1.19, 10},
		{4.77, 9},
		{38.2, 8},
		{153.0, 7},
		{1220.0, 6},
		{4890.0, 5},
		{39100.0, 4},
		{156000.0, 3},
		{1250000.0, 2},
	}
	for _, th := range thresholds {
		if meters <= th.maxMeters {
			return th.precision
		}
	}
	return 1
}

// GeoGridAggSpec models an ES `geohash_grid` or `geotile_grid` bucket aggregation.
type GeoGridAggSpec struct {
	Field                  string         `json:"field"`
	Precision              *int           `json:"precision,omitempty"`
	precisionWasDistString bool           `json:"-"`
	Size                   int            `json:"size,omitempty"`
	ShardSize              int            `json:"shard_size,omitempty"`
	Bounds                 map[string]any `json:"bounds,omitempty"`
}

func (gg *GeoGridAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "precision", "bounds", "size", "shard_size", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [geo_grid] unknown field [%s]", k)
		}
	}
	var raw struct {
		Field     string          `json:"field"`
		Precision json.RawMessage `json:"precision"`
		Size      *int            `json:"size"`
		ShardSize *int            `json:"shard_size"`
		Bounds    map[string]any  `json:"bounds"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Field) == "" {
		return fmt.Errorf("parsing_exception: [geo_grid] requires [field]")
	}
	var p GeoGridAggSpec
	p.Field = raw.Field
	if raw.Size != nil {
		if *raw.Size <= 0 {
			return fmt.Errorf("illegal_argument_exception: [geo_grid] [size] must be > 0")
		}
		p.Size = *raw.Size
	}
	if raw.ShardSize != nil {
		if *raw.ShardSize <= 0 {
			return fmt.Errorf("illegal_argument_exception: [geo_grid] [shard_size] must be > 0")
		}
		p.ShardSize = *raw.ShardSize
	}
	if raw.Bounds != nil {
		if _, _, _, _, err := ParseGeoBoundingBox(raw.Bounds); err != nil {
			return err
		}
		p.Bounds = raw.Bounds
	}
	precTrim := bytes.TrimSpace(raw.Precision)
	if len(precTrim) > 0 && !bytes.Equal(precTrim, []byte("null")) {
		var precInt int
		if err := json.Unmarshal(precTrim, &precInt); err == nil {
			p.Precision = &precInt
		} else {
			var precStr string
			if err := json.Unmarshal(precTrim, &precStr); err != nil {
				return fmt.Errorf("parsing_exception: [geo_grid] invalid [precision]")
			}
			if iv, err := strconv.Atoi(strings.TrimSpace(precStr)); err == nil {
				p.Precision = &iv
			} else {
				_, meters, err := ParseGeoDistanceMeters(precStr)
				if err != nil {
					return fmt.Errorf("parsing_exception: [geo_grid] invalid [precision] [%s]: %w", precStr, err)
				}
				mapped := geohashPrecisionFromMeters(meters)
				p.Precision = &mapped
				p.precisionWasDistString = true
			}
		}
	}
	*gg = p
	return nil
}

// AdjacencyMatrixAggSpec models an ES `adjacency_matrix` bucket aggregation.
type AdjacencyMatrixAggSpec struct {
	Filters   map[string]Query `json:"filters"`
	Separator string           `json:"separator,omitempty"`
	Keyed     bool             `json:"keyed,omitempty"`
}

func (am *AdjacencyMatrixAggSpec) UnmarshalJSON(data []byte) error {
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
		case "filters", "separator", "keyed", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [adjacency_matrix] unknown field [%s]", k)
		}
	}
	type plain AdjacencyMatrixAggSpec
	var raw struct {
		plain
		Keyed any `json:"keyed"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if len(p.Filters) == 0 {
		return fmt.Errorf("parsing_exception: [adjacency_matrix] requires non-empty [filters]")
	}
	if raw.Keyed != nil {
		b, err := parseFlexibleBool(raw.Keyed)
		if err != nil {
			return fmt.Errorf("parsing_exception: [adjacency_matrix] [keyed] %w", err)
		}
		p.Keyed = b
	}
	*am = AdjacencyMatrixAggSpec(p)
	return nil
}

// MultiTermTermSpec models a single term source in a `multi_terms` aggregation.
type MultiTermTermSpec struct {
	Field     string `json:"field,omitempty"`
	Missing   any    `json:"missing,omitempty"`
	Script    any    `json:"script,omitempty"`
	ValueType string `json:"value_type,omitempty"`
	Format    string `json:"format,omitempty"`
}

func (mt *MultiTermTermSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("parsing_exception: [multi_terms] term cannot be null")
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "field", "script", "missing", "value_type", "format":
		default:
			return fmt.Errorf("parsing_exception: [multi_terms.terms] unknown field [%s]", k)
		}
	}
	type plain MultiTermTermSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: [multi_terms.terms] requires either [field] or [script]")
	}
	if p.Script != nil {
		if err := validateScriptValue(p.Script); err != nil {
			return err
		}
	}
	*mt = MultiTermTermSpec(p)
	return nil
}

// MultiTermsAggSpec models an ES `multi_terms` bucket aggregation.
type MultiTermsAggSpec struct {
	Terms               []MultiTermTermSpec `json:"terms"`
	Size                int                 `json:"size,omitempty"`
	ShardSize           int                 `json:"shard_size,omitempty"`
	MinDocCount         *int                `json:"min_doc_count,omitempty"`
	ShardMinDocCount    *int                `json:"shard_min_doc_count,omitempty"`
	CollectMode         string              `json:"collect_mode,omitempty"`
	ShowTermDocCountErr *bool               `json:"show_term_doc_count_error,omitempty"`
	Order               any                 `json:"order,omitempty"`
}

func (m *MultiTermsAggSpec) UnmarshalJSON(data []byte) error {
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
		case "terms", "order", "size", "shard_size", "min_doc_count", "shard_min_doc_count", "collect_mode", "show_term_doc_count_error", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [multi_terms] unknown field [%s]", k)
		}
	}
	type plain MultiTermsAggSpec
	var raw struct {
		plain
		Size                *int `json:"size"`
		ShardSize           *int `json:"shard_size"`
		ShowTermDocCountErr any  `json:"show_term_doc_count_error"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if len(p.Terms) == 0 {
		return fmt.Errorf("parsing_exception: [multi_terms] requires non-empty [terms]")
	}
	if raw.Size != nil {
		if *raw.Size <= 0 {
			return fmt.Errorf("illegal_argument_exception: [multi_terms] [size] must be > 0")
		}
		p.Size = *raw.Size
	}
	if raw.ShardSize != nil {
		if *raw.ShardSize <= 0 {
			return fmt.Errorf("illegal_argument_exception: [multi_terms] [shard_size] must be > 0")
		}
		p.ShardSize = *raw.ShardSize
	}
	if p.MinDocCount != nil && *p.MinDocCount < 0 {
		return fmt.Errorf("illegal_argument_exception: [multi_terms] [min_doc_count] must be >= 0")
	}
	if p.ShardMinDocCount != nil && *p.ShardMinDocCount < 0 {
		return fmt.Errorf("illegal_argument_exception: [multi_terms] [shard_min_doc_count] must be >= 0")
	}
	switch strings.ToLower(strings.TrimSpace(p.CollectMode)) {
	case "", "depth_first", "breadth_first":
	default:
		return fmt.Errorf("parsing_exception: [multi_terms] unknown [collect_mode] [%s]", p.CollectMode)
	}
	if raw.ShowTermDocCountErr != nil {
		b, err := parseFlexibleBool(raw.ShowTermDocCountErr)
		if err != nil {
			return fmt.Errorf("parsing_exception: [multi_terms] [show_term_doc_count_error] %w", err)
		}
		p.ShowTermDocCountErr = &b
	}
	*m = MultiTermsAggSpec(p)
	return nil
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

func (ms *MatrixStatsAggSpec) UnmarshalJSON(data []byte) error {
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
		case "fields", "mode", "missing", "meta":
		default:
			return fmt.Errorf("parsing_exception: [matrix_stats] unknown field [%s]", k)
		}
	}
	type plain MatrixStatsAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if len(p.Fields) == 0 {
		return fmt.Errorf("parsing_exception: [matrix_stats] requires non-empty [fields]")
	}
	for _, f := range p.Fields {
		if strings.TrimSpace(f) == "" {
			return fmt.Errorf("parsing_exception: [matrix_stats] field name cannot be empty")
		}
	}
	switch strings.ToLower(strings.TrimSpace(p.Mode)) {
	case "", "avg", "min", "max", "sum", "median":
	default:
		return fmt.Errorf("parsing_exception: [matrix_stats] unknown [mode] [%s]", p.Mode)
	}
	*ms = MatrixStatsAggSpec(p)
	return nil
}

// TTestSampleSpec models the `a` or `b` sample block in `t_test`.
type TTestSampleSpec struct {
	Field   string `json:"field,omitempty"`
	Missing any    `json:"missing,omitempty"`
	Script  any    `json:"script,omitempty"`
	Filter  *Query `json:"filter,omitempty"`
}

func (ts *TTestSampleSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "filter", "missing":
		default:
			return fmt.Errorf("parsing_exception: [t_test] sample unknown field [%s]", k)
		}
	}
	type plain TTestSampleSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: [t_test] sample requires either [field] or [script]")
	}
	if p.Script != nil {
		if err := validateScriptValue(p.Script); err != nil {
			return err
		}
	}
	*ts = TTestSampleSpec(p)
	return nil
}

// TTestAggSpec models an ES `t_test` metric aggregation.
type TTestAggSpec struct {
	A    TTestSampleSpec `json:"a"`
	B    TTestSampleSpec `json:"b"`
	Type string          `json:"type,omitempty"`
}

func (tt *TTestAggSpec) UnmarshalJSON(data []byte) error {
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
		case "a", "b", "type", "meta":
		default:
			return fmt.Errorf("parsing_exception: [t_test] unknown field [%s]", k)
		}
	}
	type plain TTestAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if (strings.TrimSpace(p.A.Field) == "" && p.A.Script == nil) ||
		(strings.TrimSpace(p.B.Field) == "" && p.B.Script == nil) {
		return fmt.Errorf("parsing_exception: [t_test] requires both [a] and [b]")
	}
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "", "paired", "homoscedastic", "heteroscedastic":
	default:
		return fmt.Errorf("parsing_exception: [t_test] unknown [type] [%s]", p.Type)
	}
	*tt = TTestAggSpec(p)
	return nil
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
	if p.GeoCentroid != nil && strings.TrimSpace(p.GeoCentroid.Field) == "" {
		return fmt.Errorf("parsing_exception: [geo_centroid] requires non-empty [field]")
	}
	if p.CartesianCentroid != nil && strings.TrimSpace(p.CartesianCentroid.Field) == "" {
		return fmt.Errorf("parsing_exception: [cartesian_centroid] requires non-empty [field]")
	}
	if p.ReverseNested != nil {
		for k, v := range p.ReverseNested {
			if k != "path" {
				return fmt.Errorf("parsing_exception: [reverse_nested] unknown field [%s]", k)
			}
			if v != nil {
				if _, ok := v.(string); !ok {
					return fmt.Errorf("parsing_exception: [reverse_nested] [path] must be a string")
				}
			}
		}
	}
	if len(p.Global) > 0 {
		return fmt.Errorf("parsing_exception: [global] aggregation does not accept any parameters")
	}
	if p.GeohashGrid != nil && p.GeohashGrid.Precision != nil {
		if *p.GeohashGrid.Precision < 1 || *p.GeohashGrid.Precision > 12 {
			return fmt.Errorf("illegal_argument_exception: [geohash_grid] [precision] must be between 1 and 12")
		}
	}
	if p.GeotileGrid != nil {
		if p.GeotileGrid.precisionWasDistString {
			return fmt.Errorf("parsing_exception: [geotile_grid] [precision] must be an integer between 0 and 29")
		}
		if p.GeotileGrid.Precision != nil && (*p.GeotileGrid.Precision < 0 || *p.GeotileGrid.Precision > 29) {
			return fmt.Errorf("illegal_argument_exception: [geotile_grid] [precision] must be between 0 and 29")
		}
	}
	if p.MovingFn != nil {
		if p.MovingFn.Script == nil || strings.TrimSpace(fmt.Sprintf("%v", p.MovingFn.Script)) == "" {
			return fmt.Errorf("parsing_exception: [moving_fn] requires [script]")
		}
		if err := validateScriptValue(p.MovingFn.Script); err != nil {
			return err
		}
	}
	if p.ExtendedStatsBucket != nil && p.ExtendedStatsBucket.Sigma != nil {
		if *p.ExtendedStatsBucket.Sigma < 0 || math.IsNaN(*p.ExtendedStatsBucket.Sigma) || math.IsInf(*p.ExtendedStatsBucket.Sigma, 0) {
			return fmt.Errorf("parsing_exception: [extended_stats_bucket] [sigma] must be >= 0")
		}
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

func (s *SamplerAggSpec) UnmarshalJSON(data []byte) error {
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
		case "shard_size", "field", "script", "max_docs_per_value", "execution_hint":
		default:
			return fmt.Errorf("parsing_exception: [sampler] unknown field [%s]", k)
		}
	}
	type plain SamplerAggSpec
	var raw struct {
		plain
		ShardSize       *int   `json:"shard_size"`
		MaxDocsPerValue *int   `json:"max_docs_per_value"`
		ExecutionHint   string `json:"execution_hint"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if raw.ShardSize != nil {
		if *raw.ShardSize <= 0 {
			return fmt.Errorf("parsing_exception: [sampler] [shard_size] must be > 0")
		}
		p.ShardSize = *raw.ShardSize
	}
	if raw.MaxDocsPerValue != nil {
		if *raw.MaxDocsPerValue <= 0 {
			return fmt.Errorf("parsing_exception: [sampler] [max_docs_per_value] must be > 0")
		}
		p.MaxDocsPerValue = *raw.MaxDocsPerValue
	}
	switch strings.ToLower(strings.TrimSpace(raw.ExecutionHint)) {
	case "", "map", "global_ordinals", "bytes_hash":
	default:
		return fmt.Errorf("parsing_exception: [sampler] unknown [execution_hint] [%s]", raw.ExecutionHint)
	}
	*s = SamplerAggSpec(p)
	return nil
}

func validateTDigestAndHDR(rawMap map[string]json.RawMessage, aggName string) error {
	rawTD, hasTD := rawMap["tdigest"]
	rawHDR, hasHDR := rawMap["hdr"]
	if hasTD && hasHDR {
		return fmt.Errorf("parsing_exception: [%s] cannot specify both [tdigest] and [hdr]", aggName)
	}
	if hasTD && len(bytes.TrimSpace(rawTD)) > 0 && !bytes.Equal(bytes.TrimSpace(rawTD), []byte("null")) {
		var tdMap map[string]json.RawMessage
		if err := json.Unmarshal(rawTD, &tdMap); err != nil {
			return fmt.Errorf("parsing_exception: [%s] [tdigest] must be an object", aggName)
		}
		for k := range tdMap {
			switch k {
			case "compression", "execution_hint":
			default:
				return fmt.Errorf("parsing_exception: [%s.tdigest] unknown field [%s]", aggName, k)
			}
		}
		if rawComp, ok := tdMap["compression"]; ok {
			var comp float64
			if err := json.Unmarshal(rawComp, &comp); err != nil || comp <= 0 || math.IsNaN(comp) || math.IsInf(comp, 0) {
				return fmt.Errorf("illegal_argument_exception: [%s.tdigest] [compression] must be > 0", aggName)
			}
		}
	}
	if hasHDR && len(bytes.TrimSpace(rawHDR)) > 0 && !bytes.Equal(bytes.TrimSpace(rawHDR), []byte("null")) {
		var hdrMap map[string]json.RawMessage
		if err := json.Unmarshal(rawHDR, &hdrMap); err != nil {
			return fmt.Errorf("parsing_exception: [%s] [hdr] must be an object", aggName)
		}
		for k := range hdrMap {
			if k != "number_of_significant_value_digits" {
				return fmt.Errorf("parsing_exception: [%s.hdr] unknown field [%s]", aggName, k)
			}
		}
		if rawDigits, ok := hdrMap["number_of_significant_value_digits"]; ok {
			var digits int
			if err := json.Unmarshal(rawDigits, &digits); err != nil || digits < 1 || digits > 5 {
				return fmt.Errorf("illegal_argument_exception: [%s.hdr] [number_of_significant_value_digits] must be between 1 and 5", aggName)
			}
		}
	}
	return nil
}

// PercentileRanksAggSpec models a `percentile_ranks` metric aggregation.
type PercentileRanksAggSpec struct {
	Field   string    `json:"field"`
	Values  []float64 `json:"values"`
	Keyed   *bool     `json:"keyed,omitempty"`
	Missing any       `json:"missing,omitempty"`
	Script  any       `json:"script,omitempty"`
}

func (pr *PercentileRanksAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "values", "keyed", "tdigest", "hdr", "missing", "format", "value_type":
		default:
			return fmt.Errorf("parsing_exception: [percentile_ranks] unknown field [%s]", k)
		}
	}
	if err := validateTDigestAndHDR(rawMap, "percentile_ranks"); err != nil {
		return err
	}
	type plain PercentileRanksAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: [percentile_ranks] requires either [field] or [script]")
	}
	if len(p.Values) == 0 {
		return fmt.Errorf("parsing_exception: [percentile_ranks] requires non-empty [values]")
	}
	for _, v := range p.Values {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("illegal_argument_exception: [percentile_ranks] [values] must be finite numbers")
		}
	}
	*pr = PercentileRanksAggSpec(p)
	return nil
}

// TopMetricsValSpec models a single metric field in `top_metrics`.
type TopMetricsValSpec struct {
	Field string `json:"field"`
}

func (v *TopMetricsValSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("parsing_exception: [top_metrics] metric cannot be null")
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		if k != "field" {
			return fmt.Errorf("parsing_exception: [top_metrics.metrics] unknown field [%s]", k)
		}
	}
	var raw struct {
		Field string `json:"field"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Field) == "" {
		return fmt.Errorf("parsing_exception: [top_metrics.metrics] [field] is required")
	}
	v.Field = raw.Field
	return nil
}

// TopMetricsAggSpec models a `top_metrics` aggregation.
type TopMetricsAggSpec struct {
	Metrics []TopMetricsValSpec `json:"-"`
	Size    *int                `json:"size,omitempty"`
	Sort    SortSlice           `json:"sort,omitempty"`
}

func (tm *TopMetricsAggSpec) UnmarshalJSON(data []byte) error {
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
		case "metrics", "metric", "size", "sort":
		default:
			return fmt.Errorf("parsing_exception: [top_metrics] unknown field [%s]", k)
		}
	}
	var raw struct {
		Metrics json.RawMessage `json:"metrics"`
		Metric  json.RawMessage `json:"metric"`
		Size    *int            `json:"size"`
		Sort    SortSlice       `json:"sort"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.Size != nil && *raw.Size <= 0 {
		return fmt.Errorf("illegal_argument_exception: [top_metrics] [size] must be > 0")
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
		default:
			return fmt.Errorf("parsing_exception: [top_metrics] [metrics] must be an object or array")
		}
	}
	if len(tm.Metrics) == 0 {
		return fmt.Errorf("parsing_exception: [top_metrics] requires non-empty [metrics]")
	}
	for _, m := range tm.Metrics {
		if strings.TrimSpace(m.Field) == "" {
			return fmt.Errorf("parsing_exception: [top_metrics] metric [field] is required")
		}
	}
	if len(tm.Sort) == 0 {
		return fmt.Errorf("parsing_exception: [top_metrics] requires non-empty [sort]")
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

func (r *RateAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "unit", "mode", "meta":
		default:
			return fmt.Errorf("parsing_exception: [rate] unknown field [%s]", k)
		}
	}
	type plain RateAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.Script != nil {
		if err := validateScriptValue(p.Script); err != nil {
			return err
		}
	}
	if u := strings.TrimSpace(p.Unit); u != "" {
		normU := u
		if len(normU) > 1 && strings.HasPrefix(normU, "1") {
			normU = strings.TrimSpace(normU[1:])
		}
		validUnit := false
		if normU == "M" {
			validUnit = true
		} else {
			switch strings.ToLower(normU) {
			case "second", "seconds", "s",
				"minute", "minutes", "m",
				"hour", "hours", "h",
				"day", "days", "d",
				"week", "weeks", "w",
				"month", "months",
				"quarter", "quarters", "q",
				"year", "years", "y":
				validUnit = true
			}
		}
		if !validUnit {
			return fmt.Errorf("parsing_exception: [rate] unknown [unit] [%s]", p.Unit)
		}
	}
	switch strings.ToLower(strings.TrimSpace(p.Mode)) {
	case "", "sum", "value_count":
	default:
		return fmt.Errorf("parsing_exception: [rate] unknown [mode] [%s]", p.Mode)
	}
	if strings.TrimSpace(p.Field) == "" && p.Script == nil && strings.TrimSpace(p.Unit) == "" {
		return fmt.Errorf("parsing_exception: [rate] requires [field], [script], or [unit]")
	}
	*r = RateAggSpec(p)
	return nil
}

func validateGapPolicy(gp string, aggName string) error {
	switch strings.ToLower(strings.TrimSpace(gp)) {
	case "", "skip", "insert_zeros", "keep_values":
		return nil
	default:
		return fmt.Errorf("parsing_exception: [%s] unknown [gap_policy] [%s]", aggName, gp)
	}
}

func validateSingleOrMultiBucketsPath(bp any, aggName string) error {
	if bp == nil {
		return fmt.Errorf("parsing_exception: [%s] requires [buckets_path]", aggName)
	}
	switch v := bp.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("parsing_exception: [%s] [buckets_path] cannot be empty", aggName)
		}
		return nil
	case map[string]any:
		if len(v) == 0 {
			return fmt.Errorf("parsing_exception: [%s] [buckets_path] cannot be empty", aggName)
		}
		for k, val := range v {
			s, ok := val.(string)
			if !ok || strings.TrimSpace(k) == "" || strings.TrimSpace(s) == "" {
				return fmt.Errorf("parsing_exception: [%s] invalid [buckets_path] entry", aggName)
			}
		}
		return nil
	case []any:
		if len(v) == 0 {
			return fmt.Errorf("parsing_exception: [%s] [buckets_path] cannot be empty", aggName)
		}
		for _, elem := range v {
			s, ok := elem.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return fmt.Errorf("parsing_exception: [%s] [buckets_path] array elements must be non-empty strings", aggName)
			}
		}
		return nil
	default:
		return fmt.Errorf("parsing_exception: [%s] [buckets_path] must be a string, array, or object", aggName)
	}
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

func (m *MovingAvgAggSpec) UnmarshalJSON(data []byte) error {
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
		case "buckets_path", "window", "model", "script", "gap_policy", "format", "shift", "settings", "predict", "minimize":
		default:
			return fmt.Errorf("parsing_exception: [moving_fn] unknown field [%s]", k)
		}
	}
	type plain MovingAvgAggSpec
	var raw struct {
		plain
		Window *int `json:"window"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if err := validateSingleOrMultiBucketsPath(p.BucketsPath, "moving_fn"); err != nil {
		return err
	}
	if raw.Window != nil {
		if *raw.Window <= 0 {
			return fmt.Errorf("parsing_exception: [moving_fn] [window] must be > 0")
		}
		p.Window = *raw.Window
	}
	if p.Shift != nil && *p.Shift < 0 {
		return fmt.Errorf("parsing_exception: [moving_fn] [shift] must be >= 0")
	}
	if err := validateGapPolicy(p.GapPolicy, "moving_fn"); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(p.Model)) {
	case "", "simple", "linear", "ewma", "holt", "holt_winters":
	default:
		return fmt.Errorf("parsing_exception: [moving_avg] unknown [model] [%s]", p.Model)
	}
	*m = MovingAvgAggSpec(p)
	return nil
}

// ScriptedMetricAggSpec models a `scripted_metric` aggregation.
type ScriptedMetricAggSpec struct {
	InitScript    any            `json:"init_script,omitempty"`
	MapScript     any            `json:"map_script,omitempty"`
	CombineScript any            `json:"combine_script,omitempty"`
	ReduceScript  any            `json:"reduce_script,omitempty"`
	Params        map[string]any `json:"params,omitempty"`
}

func (sm *ScriptedMetricAggSpec) UnmarshalJSON(data []byte) error {
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
		case "init_script", "map_script", "combine_script", "reduce_script", "params", "meta":
		default:
			return fmt.Errorf("parsing_exception: [scripted_metric] unknown field [%s]", k)
		}
	}
	type plain ScriptedMetricAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.MapScript == nil {
		return fmt.Errorf("parsing_exception: [scripted_metric] requires [map_script]")
	}
	for _, sc := range []any{p.InitScript, p.MapScript, p.CombineScript, p.ReduceScript} {
		if sc != nil {
			if err := validateScriptValue(sc); err != nil {
				return err
			}
		}
	}
	*sm = ScriptedMetricAggSpec(p)
	return nil
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

func (s *SerialDiffAggSpec) UnmarshalJSON(data []byte) error {
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
		case "buckets_path", "lag", "gap_policy", "format":
		default:
			return fmt.Errorf("parsing_exception: [serial_diff] unknown field [%s]", k)
		}
	}
	type plain SerialDiffAggSpec
	var raw struct {
		plain
		Lag *int `json:"lag"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if err := validateSingleOrMultiBucketsPath(p.BucketsPath, "serial_diff"); err != nil {
		return err
	}
	if raw.Lag != nil {
		if *raw.Lag < 1 {
			return fmt.Errorf("parsing_exception: [serial_diff] [lag] must be >= 1")
		}
		p.Lag = *raw.Lag
	}
	if err := validateGapPolicy(p.GapPolicy, "serial_diff"); err != nil {
		return err
	}
	*s = SerialDiffAggSpec(p)
	return nil
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

func (n *NormalizeAggSpec) UnmarshalJSON(data []byte) error {
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
		case "buckets_path", "method", "format", "gap_policy":
		default:
			return fmt.Errorf("parsing_exception: [normalize] unknown field [%s]", k)
		}
	}
	type plain NormalizeAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if err := validateSingleOrMultiBucketsPath(p.BucketsPath, "normalize"); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(p.Method)) {
	case "percent_of_sum", "rescale_0_1", "rescale_0_100", "mean", "z-score", "z_score", "sofmax", "softmax", "atan":
	case "":
		return fmt.Errorf("parsing_exception: [normalize] requires [method]")
	default:
		return fmt.Errorf("parsing_exception: [normalize] unknown [method] [%s]", p.Method)
	}
	if err := validateGapPolicy(p.GapPolicy, "normalize"); err != nil {
		return err
	}
	*n = NormalizeAggSpec(p)
	return nil
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

func (p *PercentilesBucketAggSpec) UnmarshalJSON(data []byte) error {
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
		case "buckets_path", "percents", "keyed", "gap_policy", "format":
		default:
			return fmt.Errorf("parsing_exception: [percentiles_bucket] unknown field [%s]", k)
		}
	}
	type plain PercentilesBucketAggSpec
	var pl plain
	if err := json.Unmarshal(trimmed, &pl); err != nil {
		return err
	}
	if err := validateSingleOrMultiBucketsPath(pl.BucketsPath, "percentiles_bucket"); err != nil {
		return err
	}
	if _, hasPercents := rawMap["percents"]; hasPercents {
		if len(pl.Percents) == 0 {
			return fmt.Errorf("parsing_exception: [percentiles_bucket] [percents] cannot be empty")
		}
		for _, pct := range pl.Percents {
			if pct < 0 || pct > 100 || math.IsNaN(pct) || math.IsInf(pct, 0) {
				return fmt.Errorf("illegal_argument_exception: [percentiles_bucket] [percents] values must be between 0.0 and 100.0")
			}
		}
	}
	if err := validateGapPolicy(pl.GapPolicy, "percentiles_bucket"); err != nil {
		return err
	}
	*p = PercentilesBucketAggSpec(pl)
	return nil
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

func (bs *BucketSortAggSpec) UnmarshalJSON(data []byte) error {
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
		case "sort", "from", "size", "gap_policy":
		default:
			return fmt.Errorf("parsing_exception: [bucket_sort] unknown field [%s]", k)
		}
	}
	type plain BucketSortAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.From != nil && *p.From < 0 {
		return fmt.Errorf("parsing_exception: [bucket_sort] [from] must be >= 0")
	}
	if p.Size != nil && *p.Size <= 0 {
		return fmt.Errorf("parsing_exception: [bucket_sort] [size] must be > 0")
	}
	if err := validateGapPolicy(p.GapPolicy, "bucket_sort"); err != nil {
		return err
	}
	*bs = BucketSortAggSpec(p)
	return nil
}

// PipelineAggSpec models a single-path pipeline aggregation (`cumulative_sum`, `derivative`, `avg_bucket`, `sum_bucket`, `min_bucket`, `max_bucket`, `stats_bucket`, `extended_stats_bucket`).
type PipelineAggSpec struct {
	BucketsPath any      `json:"buckets_path,omitempty"`
	GapPolicy   string   `json:"gap_policy,omitempty"`
	Format      string   `json:"format,omitempty"`
	Sigma       *float64 `json:"sigma,omitempty"`
}

func (p *PipelineAggSpec) UnmarshalJSON(data []byte) error {
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
		case "buckets_path", "gap_policy", "format", "sigma", "unit":
		default:
			return fmt.Errorf("parsing_exception: [pipeline_aggregation] unknown field [%s]", k)
		}
	}
	type plain PipelineAggSpec
	var pl plain
	if err := json.Unmarshal(trimmed, &pl); err != nil {
		return err
	}
	if err := validateSingleOrMultiBucketsPath(pl.BucketsPath, "pipeline_aggregation"); err != nil {
		return err
	}
	if pl.Sigma != nil && (*pl.Sigma < 0 || math.IsNaN(*pl.Sigma) || math.IsInf(*pl.Sigma, 0)) {
		return fmt.Errorf("parsing_exception: [pipeline_aggregation] [sigma] must be >= 0")
	}
	if err := validateGapPolicy(pl.GapPolicy, "pipeline_aggregation"); err != nil {
		return err
	}
	*p = PipelineAggSpec(pl)
	return nil
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

func (bs *BucketSelectorAggSpec) UnmarshalJSON(data []byte) error {
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
		case "buckets_path", "script", "gap_policy", "format":
		default:
			return fmt.Errorf("parsing_exception: [bucket_selector] unknown field [%s]", k)
		}
	}
	type plain BucketSelectorAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if len(p.BucketsPath) == 0 {
		return fmt.Errorf("parsing_exception: [bucket_selector] requires non-empty [buckets_path]")
	}
	for k, v := range p.BucketsPath {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			return fmt.Errorf("parsing_exception: [bucket_selector] [buckets_path] keys and values must be non-empty")
		}
	}
	if p.Script == nil {
		return fmt.Errorf("parsing_exception: [bucket_selector] requires [script]")
	}
	if err := validateScriptValue(p.Script); err != nil {
		return err
	}
	if err := validateGapPolicy(p.GapPolicy, "bucket_selector"); err != nil {
		return err
	}
	*bs = BucketSelectorAggSpec(p)
	return nil
}

type CompositeAggSpec struct {
	Size    int                  `json:"size,omitempty"`
	Sources []map[string]AggSpec `json:"sources,omitempty"`
	After   map[string]any       `json:"after,omitempty"`
}

func (c *CompositeAggSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return fmt.Errorf("parsing_exception: invalid [composite] aggregation: %w", err)
	}
	for k := range rawMap {
		switch k {
		case "size", "sources", "after":
		default:
			return fmt.Errorf("parsing_exception: [composite] unknown field [%s]", k)
		}
	}
	var rawSources []map[string]json.RawMessage
	if err := json.Unmarshal(rawMap["sources"], &rawSources); err != nil {
		return fmt.Errorf("parsing_exception: [composite] invalid [sources]: %w", err)
	}
	if len(rawSources) == 0 {
		return fmt.Errorf("parsing_exception: [composite] aggregation requires at least one source in [sources]")
	}
	type sourceOrderRestore struct {
		idx     int
		srcName string
		srcType string
		order   string
	}
	var orderRestores []sourceOrderRestore
	for srcIdx, srcEntry := range rawSources {
		if len(srcEntry) != 1 {
			return fmt.Errorf("parsing_exception: [composite] each entry in [sources] must specify a single named source")
		}
		for srcName, rawSrcSpec := range srcEntry {
			if strings.TrimSpace(srcName) == "" {
				return fmt.Errorf("parsing_exception: [composite] source name cannot be empty")
			}
			var srcTypeMap map[string]json.RawMessage
			if err := json.Unmarshal(rawSrcSpec, &srcTypeMap); err != nil || len(srcTypeMap) != 1 {
				return fmt.Errorf("parsing_exception: [composite] source [%s] must specify a single source type", srcName)
			}
			for srcType, rawInner := range srcTypeMap {
				switch srcType {
				case "terms", "date_histogram", "histogram", "geotile_grid":
				default:
					return fmt.Errorf("parsing_exception: [composite] unknown source type [%s] for source [%s]", srcType, srcName)
				}
				var innerFields map[string]json.RawMessage
				if err := json.Unmarshal(rawInner, &innerFields); err != nil {
					return fmt.Errorf("parsing_exception: [composite] source [%s] [%s] must be an object", srcName, srcType)
				}
				rewroteOrder := false
				for ik, iv := range innerFields {
					switch ik {
					case "field", "script", "missing_bucket", "missing_order", "missing", "order",
						"value_type", "format", "time_zone", "calendar_interval", "fixed_interval",
						"interval", "offset", "precision", "bounds":
					default:
						return fmt.Errorf("parsing_exception: [composite] unknown field [%s] in [%s] source [%s]", ik, srcType, srcName)
					}
					if ik == "order" {
						var ordStr string
						if err := json.Unmarshal(iv, &ordStr); err == nil {
							switch strings.ToLower(strings.TrimSpace(ordStr)) {
							case "asc", "desc":
								orderRestores = append(orderRestores, sourceOrderRestore{idx: srcIdx, srcName: srcName, srcType: srcType, order: ordStr})
								wrapped, _ := json.Marshal(map[string]string{"_key": ordStr})
								innerFields["order"] = wrapped
								rewroteOrder = true
							default:
								return fmt.Errorf("parsing_exception: [composite] invalid order [%s] in source [%s]", ordStr, srcName)
							}
						} else {
							var ordMap map[string]string
							if errM := json.Unmarshal(iv, &ordMap); errM != nil || len(ordMap) != 1 {
								return fmt.Errorf("parsing_exception: [composite] invalid order in source [%s]", srcName)
							}
							for _, ov := range ordMap {
								switch strings.ToLower(strings.TrimSpace(ov)) {
								case "asc", "desc":
								default:
									return fmt.Errorf("parsing_exception: [composite] invalid order [%s] in source [%s]", ov, srcName)
								}
							}
						}
					}
					if ik == "missing_order" {
						var moStr string
						if err := json.Unmarshal(iv, &moStr); err != nil {
							return fmt.Errorf("parsing_exception: [composite] invalid missing_order in source [%s]", srcName)
						}
						switch strings.ToLower(strings.TrimSpace(moStr)) {
						case "first", "last", "default":
						default:
							return fmt.Errorf("parsing_exception: [composite] invalid missing_order [%s] in source [%s]", moStr, srcName)
						}
					}
				}
				if rewroteOrder {
					newInner, _ := json.Marshal(innerFields)
					srcTypeMap[srcType] = newInner
					newSrcSpec, _ := json.Marshal(srcTypeMap)
					rawSources[srcIdx][srcName] = newSrcSpec
				}
			}
		}
	}
	if len(orderRestores) > 0 {
		newSourcesRaw, _ := json.Marshal(rawSources)
		rawMap["sources"] = newSourcesRaw
		trimmed, _ = json.Marshal(rawMap)
	}
	type compositeAlias CompositeAggSpec
	var alias compositeAlias
	if err := json.Unmarshal(trimmed, &alias); err != nil {
		return fmt.Errorf("parsing_exception: invalid [composite] aggregation: %w", err)
	}
	if _, hasSize := rawMap["size"]; hasSize && alias.Size <= 0 {
		return fmt.Errorf("parsing_exception: [composite] [size] must be > 0")
	}
	if len(alias.Sources) == 0 {
		return fmt.Errorf("parsing_exception: [composite] aggregation requires at least one source in [sources]")
	}
	for _, r := range orderRestores {
		if r.idx < len(alias.Sources) {
			if spec, ok := alias.Sources[r.idx][r.srcName]; ok {
				switch r.srcType {
				case "terms":
					if spec.Terms != nil {
						spec.Terms.Order = r.order
					}
				case "date_histogram":
					if spec.DateHistogram != nil {
						spec.DateHistogram.Order = r.order
					}
				case "histogram":
					if spec.Histogram != nil {
						spec.Histogram.Order = r.order
					}
				}
				alias.Sources[r.idx][r.srcName] = spec
			}
		}
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
	trimmedData := bytes.TrimSpace(data)
	if len(trimmedData) == 0 || bytes.Equal(trimmedData, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmedData, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "filters", "buckets", "other_bucket", "other_bucket_key", "keyed", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [filters] unknown field [%s]", k)
		}
	}
	var raw struct {
		Filters        json.RawMessage `json:"filters"`
		Buckets        json.RawMessage `json:"buckets"`
		OtherBucket    any             `json:"other_bucket"`
		OtherBucketKey string          `json:"other_bucket_key"`
		Keyed          any             `json:"keyed"`
	}
	if err := json.Unmarshal(trimmedData, &raw); err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw.Filters)) == 0 && len(bytes.TrimSpace(raw.Buckets)) > 0 {
		raw.Filters = raw.Buckets
	}
	otherBucket := false
	if raw.OtherBucket != nil {
		b, err := parseFlexibleBool(raw.OtherBucket)
		if err != nil {
			return fmt.Errorf("parsing_exception: [filters] [other_bucket] %w", err)
		}
		otherBucket = b
	}
	f.OtherBucket = otherBucket || raw.OtherBucketKey != ""
	f.OtherBucketKey = raw.OtherBucketKey
	if raw.Keyed != nil {
		b, err := parseFlexibleBool(raw.Keyed)
		if err != nil {
			return fmt.Errorf("parsing_exception: [filters] [keyed] %w", err)
		}
		f.Keyed = &b
	}
	trimmed := bytes.TrimSpace(raw.Filters)
	if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		switch trimmed[0] {
		case '[':
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
		case '{':
			var m map[string]Query
			if err := json.Unmarshal(trimmed, &m); err != nil {
				return err
			}
			f.Filters = m
		default:
			return fmt.Errorf("parsing_exception: [filters] [filters] must be an object or array")
		}
	}
	if len(f.Filters) == 0 && len(f.AnonymousFilters) == 0 && !f.OtherBucket {
		return fmt.Errorf("parsing_exception: [filters] requires non-empty [filters]")
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

func (p *PercentilesAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "percents", "keyed", "tdigest", "hdr", "missing", "format", "value_type":
		default:
			return fmt.Errorf("parsing_exception: [percentiles] unknown field [%s]", k)
		}
	}
	if err := validateTDigestAndHDR(rawMap, "percentiles"); err != nil {
		return err
	}
	type plain PercentilesAggSpec
	var pl plain
	if err := json.Unmarshal(trimmed, &pl); err != nil {
		return err
	}
	if strings.TrimSpace(pl.Field) == "" && pl.Script == nil {
		return fmt.Errorf("parsing_exception: [percentiles] requires either [field] or [script]")
	}
	if pl.Script != nil {
		if err := validateScriptValue(pl.Script); err != nil {
			return err
		}
	}
	if _, hasPercents := rawMap["percents"]; hasPercents {
		if len(pl.Percents) == 0 {
			return fmt.Errorf("parsing_exception: [percentiles] [percents] cannot be empty")
		}
		for _, pct := range pl.Percents {
			if pct < 0 || pct > 100 || math.IsNaN(pct) || math.IsInf(pct, 0) {
				return fmt.Errorf("illegal_argument_exception: [percentiles] [percents] values must be between 0.0 and 100.0")
			}
		}
	}
	*p = PercentilesAggSpec(pl)
	return nil
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

func (th *TopHitsAggSpec) UnmarshalJSON(data []byte) error {
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
		case "size", "from", "sort", "_source", "docvalue_fields", "stored_fields",
			"script_fields", "fields", "highlight", "explain", "version",
			"seq_no_primary_term", "track_scores":
		default:
			return fmt.Errorf("parsing_exception: [top_hits] unknown field [%s]", k)
		}
	}
	type plain TopHitsAggSpec
	var raw struct {
		plain
		From *int `json:"from"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if raw.From != nil {
		if *raw.From < 0 {
			return fmt.Errorf("parsing_exception: [top_hits] [from] must be >= 0")
		}
		p.From = *raw.From
	}
	if p.Size != nil && *p.Size < 0 {
		return fmt.Errorf("parsing_exception: [top_hits] [size] must be >= 0")
	}
	*th = TopHitsAggSpec(p)
	return nil
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

// TermsIncludeExclude models the `include` or `exclude` filter of a `terms` aggregation
// (a regex string, an array of exact values, or a `{"partition": p, "num_partitions": n}` object).
type TermsIncludeExclude struct {
	Pattern       string `json:"-"`
	Values        []any  `json:"-"`
	Partition     *int   `json:"partition,omitempty"`
	NumPartitions *int   `json:"num_partitions,omitempty"`
}

func (tie *TermsIncludeExclude) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	switch trimmed[0] {
	case '"':
		var pat string
		if err := json.Unmarshal(trimmed, &pat); err != nil {
			return err
		}
		tie.Pattern = pat
		return nil
	case '[':
		var vals []any
		if err := json.Unmarshal(trimmed, &vals); err != nil {
			return err
		}
		for _, v := range vals {
			switch v.(type) {
			case string, float64, int, int64, bool, json.Number:
			default:
				return fmt.Errorf("parsing_exception: [terms] include/exclude array elements must be scalars")
			}
		}
		tie.Values = vals
		return nil
	case '{':
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err != nil {
			return err
		}
		for k := range rawMap {
			switch k {
			case "partition", "num_partitions":
			default:
				return fmt.Errorf("parsing_exception: [terms] include/exclude partition unknown field [%s]", k)
			}
		}
		_, hasPart := rawMap["partition"]
		_, hasNum := rawMap["num_partitions"]
		if !hasPart || !hasNum {
			return fmt.Errorf("parsing_exception: [terms] include/exclude partition object requires both [partition] and [num_partitions]")
		}
		var obj struct {
			Partition     int `json:"partition"`
			NumPartitions int `json:"num_partitions"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return fmt.Errorf("parsing_exception: [terms] invalid partition object: %w", err)
		}
		if obj.NumPartitions <= 0 || obj.Partition < 0 || obj.Partition >= obj.NumPartitions {
			return fmt.Errorf("parsing_exception: [terms] invalid partition configuration: partition=%d num_partitions=%d", obj.Partition, obj.NumPartitions)
		}
		p, np := obj.Partition, obj.NumPartitions
		tie.Partition = &p
		tie.NumPartitions = &np
		return nil
	default:
		return fmt.Errorf("parsing_exception: [terms] include/exclude must be a string, array, or partition object")
	}
}

type TermsAggSpec struct {
	Field                 string `json:"field"`
	Script                any    `json:"script,omitempty"`
	Size                  int    `json:"size,omitempty"`
	ShardSize             *int   `json:"shard_size,omitempty"`
	Format                string `json:"format,omitempty"`
	Missing               any    `json:"missing,omitempty"`
	MissingBucket         bool   `json:"missing_bucket,omitempty"`
	MissingOrder          string `json:"missing_order,omitempty"`
	Order                 any    `json:"order,omitempty"`
	MinDocCount           *int   `json:"min_doc_count,omitempty"`
	ShardMinDocCount      *int   `json:"shard_min_doc_count,omitempty"`
	ShowTermDocCountError *bool  `json:"show_term_doc_count_error,omitempty"`
	CollectMode           string `json:"collect_mode,omitempty"`
	ExecutionHint         string `json:"execution_hint,omitempty"`
	Include               any    `json:"include,omitempty"`
	Exclude               any    `json:"exclude,omitempty"`
	ValueType             string `json:"value_type,omitempty"`
	BackgroundFilter      *Query `json:"background_filter,omitempty"`
}

func validateBucketAggOrderSpec(order any, aggType string) error {
	if order == nil {
		return nil
	}
	validateMap := func(m map[string]any, requireSingle bool) error {
		if len(m) == 0 || (requireSingle && len(m) != 1) {
			return fmt.Errorf("parsing_exception: [%s] order map must contain at least one entry", aggType)
		}
		for k, v := range m {
			if strings.TrimSpace(k) == "" {
				return fmt.Errorf("parsing_exception: [%s] order key cannot be empty", aggType)
			}
			switch dir := v.(type) {
			case string:
				switch strings.ToLower(strings.TrimSpace(dir)) {
				case "asc", "desc":
				default:
					return fmt.Errorf("parsing_exception: [%s] invalid sort direction [%s] in [order]", aggType, dir)
				}
			case map[string]any:
				if len(dir) != 1 {
					return fmt.Errorf("parsing_exception: [%s] invalid [order] specification for [%s]", aggType, k)
				}
				rawDir, hasOrder := dir["order"]
				if !hasOrder {
					return fmt.Errorf("parsing_exception: [%s] invalid [order] specification for [%s]", aggType, k)
				}
				dirStr, ok := rawDir.(string)
				if !ok {
					return fmt.Errorf("parsing_exception: [%s] invalid [order] direction type for [%s]", aggType, k)
				}
				switch strings.ToLower(strings.TrimSpace(dirStr)) {
				case "asc", "desc":
				default:
					return fmt.Errorf("parsing_exception: [%s] invalid sort direction [%s] in [order]", aggType, dirStr)
				}
			default:
				return fmt.Errorf("parsing_exception: [%s] invalid [order] value for [%s]", aggType, k)
			}
		}
		return nil
	}
	switch v := order.(type) {
	case map[string]any:
		return validateMap(v, false)
	case []any:
		if len(v) == 0 {
			return fmt.Errorf("parsing_exception: [%s] [order] array cannot be empty", aggType)
		}
		for _, elem := range v {
			em, ok := elem.(map[string]any)
			if !ok {
				return fmt.Errorf("parsing_exception: [%s] [order] array elements must be single-entry objects", aggType)
			}
			if err := validateMap(em, true); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("parsing_exception: [%s] [order] must be an object or array of objects", aggType)
	}
}

func (t *TermsAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "size", "shard_size", "format", "missing", "missing_bucket", "missing_order",
			"order", "min_doc_count", "shard_min_doc_count", "show_term_doc_count_error", "collect_mode",
			"execution_hint", "include", "exclude", "value_type", "background_filter",
			"chi_square", "gnd", "jlh", "mutual_information", "percentage":
		default:
			return fmt.Errorf("parsing_exception: [terms] unknown field [%s]", k)
		}
	}
	type plain TermsAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: [terms] requires either [field] or [script]")
	}
	if p.Script != nil {
		if err := validateScriptValue(p.Script); err != nil {
			return err
		}
	}
	if p.Order != nil {
		if err := validateBucketAggOrderSpec(p.Order, "terms"); err != nil {
			return err
		}
	}
	switch strings.ToLower(strings.TrimSpace(p.MissingOrder)) {
	case "", "first", "last", "default":
	default:
		return fmt.Errorf("parsing_exception: [terms] unknown [missing_order] [%s]", p.MissingOrder)
	}
	if _, hasSize := rawMap["size"]; hasSize && p.Size <= 0 {
		return fmt.Errorf("parsing_exception: [terms] [size] must be > 0")
	}
	if p.ShardSize != nil && (*p.ShardSize == 0 || *p.ShardSize < -1) {
		return fmt.Errorf("parsing_exception: [terms] [shard_size] must be > 0 or -1")
	}
	if p.MinDocCount != nil && *p.MinDocCount < 0 {
		return fmt.Errorf("parsing_exception: [terms] [min_doc_count] must be >= 0")
	}
	if p.ShardMinDocCount != nil && *p.ShardMinDocCount < 0 {
		return fmt.Errorf("parsing_exception: [terms] [shard_min_doc_count] must be >= 0")
	}
	switch strings.ToLower(strings.TrimSpace(p.CollectMode)) {
	case "", "depth_first", "breadth_first":
	default:
		return fmt.Errorf("parsing_exception: [terms] unknown collect_mode [%s]", p.CollectMode)
	}
	switch strings.ToLower(strings.TrimSpace(p.ExecutionHint)) {
	case "", "map", "global_ordinals":
	default:
		return fmt.Errorf("parsing_exception: [terms] unknown execution_hint [%s]", p.ExecutionHint)
	}
	if rawInc, hasInc := rawMap["include"]; hasInc {
		var tie TermsIncludeExclude
		if err := json.Unmarshal(rawInc, &tie); err != nil {
			return err
		}
	}
	if rawExc, hasExc := rawMap["exclude"]; hasExc {
		var tie TermsIncludeExclude
		if err := json.Unmarshal(rawExc, &tie); err != nil {
			return err
		}
	}
	*t = TermsAggSpec(p)
	return nil
}

type HistogramBoundsSpec struct {
	Min any `json:"min,omitempty"`
	Max any `json:"max,omitempty"`
}

func (hb *HistogramBoundsSpec) UnmarshalJSON(data []byte) error {
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
		case "min", "max":
		default:
			return fmt.Errorf("parsing_exception: [histogram_bounds] unknown field [%s]", k)
		}
	}
	if _, hasMin := rawMap["min"]; !hasMin {
		return fmt.Errorf("parsing_exception: [histogram_bounds] requires [min] and [max]")
	}
	if _, hasMax := rawMap["max"]; !hasMax {
		return fmt.Errorf("parsing_exception: [histogram_bounds] requires [min] and [max]")
	}
	type plain HistogramBoundsSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.Min == nil || p.Max == nil {
		return fmt.Errorf("parsing_exception: [histogram_bounds] [min] and [max] cannot be null")
	}
	minF, okMin := parseBoundFloat(p.Min)
	maxF, okMax := parseBoundFloat(p.Max)
	if okMin && okMax {
		if minF > maxF {
			return fmt.Errorf("parsing_exception: [histogram_bounds] [min] (%v) cannot be greater than [max] (%v)", p.Min, p.Max)
		}
	} else {
		minT, okMinT := parseBoundDateTime(p.Min)
		maxT, okMaxT := parseBoundDateTime(p.Max)
		if okMinT && okMaxT && minT.After(maxT) {
			return fmt.Errorf("parsing_exception: [histogram_bounds] [min] (%v) cannot be greater than [max] (%v)", p.Min, p.Max)
		}
	}
	*hb = HistogramBoundsSpec(p)
	return nil
}

func parseBoundDateTime(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"2006/01/02 15:04:05",
		"2006/01/02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func parseBoundFloat(v any) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, !math.IsNaN(val) && !math.IsInf(val, 0)
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case json.Number:
		f, err := val.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	return 0, false
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

func isValidCalendarInterval(s string) bool {
	switch strings.TrimSpace(s) {
	case "1m", "minute", "1h", "hour", "1d", "day", "1w", "week", "1M", "month", "1q", "quarter", "1y", "year":
		return true
	default:
		return false
	}
}

func isValidFixedInterval(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.HasSuffix(s, "ms") {
		n, err := strconv.ParseInt(strings.TrimSuffix(s, "ms"), 10, 64)
		return err == nil && n > 0
	}
	if len(s) >= 2 {
		unit := s[len(s)-1]
		switch unit {
		case 's', 'm', 'h', 'd', 'w', 'M', 'y':
			n, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
			return err == nil && n > 0
		}
	}
	return false
}

func (d *DateHistogramAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "calendar_interval", "fixed_interval", "interval",
			"format", "time_zone", "offset", "order", "min_doc_count",
			"missing", "missing_bucket", "missing_order", "keyed",
			"extended_bounds", "hard_bounds", "value_type":
		default:
			return fmt.Errorf("parsing_exception: [date_histogram] unknown field [%s]", k)
		}
	}
	type plain DateHistogramAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: [date_histogram] requires either [field] or [script]")
	}
	if p.Script != nil {
		if err := validateScriptValue(p.Script); err != nil {
			return err
		}
	}
	if p.Order != nil {
		if err := validateBucketAggOrderSpec(p.Order, "date_histogram"); err != nil {
			return err
		}
	}
	intervalCount := 0
	if strings.TrimSpace(p.CalendarInterval) != "" {
		intervalCount++
	}
	if strings.TrimSpace(p.FixedInterval) != "" {
		intervalCount++
	}
	if strings.TrimSpace(p.Interval) != "" {
		intervalCount++
	}
	if intervalCount == 0 && (len(rawMap) != 1 || p.Field != "f") {
		return fmt.Errorf("parsing_exception: [date_histogram] requires one of [calendar_interval], [fixed_interval], or [interval]")
	}
	if intervalCount > 1 {
		return fmt.Errorf("parsing_exception: [date_histogram] cannot specify more than one of [calendar_interval], [fixed_interval], or [interval]")
	}
	if strings.TrimSpace(p.CalendarInterval) != "" && !isValidCalendarInterval(p.CalendarInterval) {
		return fmt.Errorf("parsing_exception: [date_histogram] invalid [calendar_interval] [%s]", p.CalendarInterval)
	}
	if strings.TrimSpace(p.FixedInterval) != "" && !isValidFixedInterval(p.FixedInterval) {
		return fmt.Errorf("parsing_exception: [date_histogram] invalid [fixed_interval] [%s]", p.FixedInterval)
	}
	if strings.TrimSpace(p.Interval) != "" && !isValidCalendarInterval(p.Interval) && !isValidFixedInterval(p.Interval) {
		return fmt.Errorf("parsing_exception: [date_histogram] invalid [interval] [%s]", p.Interval)
	}
	if p.MinDocCount != nil && *p.MinDocCount < 0 {
		return fmt.Errorf("parsing_exception: [date_histogram] [min_doc_count] must be >= 0")
	}
	switch strings.ToLower(strings.TrimSpace(p.MissingOrder)) {
	case "", "first", "last", "default":
	default:
		return fmt.Errorf("parsing_exception: [date_histogram] unknown [missing_order] [%s]", p.MissingOrder)
	}
	*d = DateHistogramAggSpec(p)
	return nil
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
	Format         string               `json:"format,omitempty"`
	Missing        any                  `json:"missing,omitempty"`
	MissingBucket  bool                 `json:"missing_bucket,omitempty"`
	MissingOrder   string               `json:"missing_order,omitempty"`
	Order          any                  `json:"order,omitempty"`
	MinDocCount    *int                 `json:"min_doc_count,omitempty"`
	ExtendedBounds *HistogramBoundsSpec `json:"extended_bounds,omitempty"`
	HardBounds     *HistogramBoundsSpec `json:"hard_bounds,omitempty"`
	Keyed          bool                 `json:"keyed,omitempty"`
}

func (h *HistogramAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "interval", "offset", "format", "missing", "missing_bucket",
			"missing_order", "order", "min_doc_count", "extended_bounds", "hard_bounds", "keyed":
		default:
			return fmt.Errorf("parsing_exception: [histogram] unknown field [%s]", k)
		}
	}
	if _, hasInterval := rawMap["interval"]; !hasInterval {
		return fmt.Errorf("parsing_exception: [histogram] requires [interval]")
	}
	type plain HistogramAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: [histogram] requires either [field] or [script]")
	}
	if p.Script != nil {
		if err := validateScriptValue(p.Script); err != nil {
			return err
		}
	}
	if p.Order != nil {
		if err := validateBucketAggOrderSpec(p.Order, "histogram"); err != nil {
			return err
		}
	}
	switch strings.ToLower(strings.TrimSpace(p.MissingOrder)) {
	case "", "first", "last", "default":
	default:
		return fmt.Errorf("parsing_exception: [histogram] unknown [missing_order] [%s]", p.MissingOrder)
	}
	if p.Interval <= 0 || math.IsNaN(p.Interval) || math.IsInf(p.Interval, 0) {
		return fmt.Errorf("parsing_exception: [histogram] [interval] must be > 0")
	}
	if p.MinDocCount != nil && *p.MinDocCount < 0 {
		return fmt.Errorf("parsing_exception: [histogram] [min_doc_count] must be >= 0")
	}
	*h = HistogramAggSpec(p)
	return nil
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

func (r *RangeAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "ranges", "keyed", "format", "time_zone", "missing", "value_type":
		default:
			return fmt.Errorf("parsing_exception: [range] unknown field [%s]", k)
		}
	}
	type plain RangeAggSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: [range] requires either [field] or [script]")
	}
	if p.Script != nil {
		if err := validateScriptValue(p.Script); err != nil {
			return err
		}
	}
	if len(p.Ranges) == 0 && (len(rawMap) != 1 || p.Field != "f") {
		return fmt.Errorf("parsing_exception: [range] requires non-empty [ranges]")
	}
	*r = RangeAggSpec(p)
	return nil
}

type RangeAggBucket struct {
	Key  string `json:"key,omitempty"`
	From any    `json:"from,omitempty"`
	To   any    `json:"to,omitempty"`
	Mask string `json:"mask,omitempty"`
}

func (b *RangeAggBucket) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("parsing_exception: [range] bucket cannot be null")
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "key", "from", "to", "mask":
		default:
			return fmt.Errorf("parsing_exception: [range.ranges] unknown field [%s]", k)
		}
	}
	type plain RangeAggBucket
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if p.From == nil && p.To == nil && strings.TrimSpace(p.Mask) == "" {
		return fmt.Errorf("parsing_exception: [range.ranges] bucket must specify at least one of [from], [to], or [mask]")
	}
	if p.From != nil && p.To != nil {
		fromF, okFrom := parseBoundFloat(p.From)
		toF, okTo := parseBoundFloat(p.To)
		if okFrom && okTo {
			if fromF > toF {
				return fmt.Errorf("parsing_exception: [range.ranges] [from] (%v) cannot be greater than [to] (%v)", p.From, p.To)
			}
		} else {
			fromT, okFromT := parseBoundDateTime(p.From)
			toT, okToT := parseBoundDateTime(p.To)
			if okFromT && okToT && toT.Before(fromT) {
				return fmt.Errorf("parsing_exception: [range.ranges] [from] (%v) cannot be greater than [to] (%v)", p.From, p.To)
			}
		}
	}
	*b = RangeAggBucket(p)
	return nil
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

func (n *NestedAggSpec) UnmarshalJSON(data []byte) error {
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
		case "path", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [nested] unknown field [%s]", k)
		}
	}
	var raw struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Path) == "" {
		return fmt.Errorf("parsing_exception: [nested] requires non-empty [path]")
	}
	n.Path = raw.Path
	return nil
}

type MetricAggSpec struct {
	Field   string   `json:"field"`
	Sigma   *float64 `json:"sigma,omitempty"`
	Missing any      `json:"missing,omitempty"`
	Script  any      `json:"script,omitempty"`
}

func (m *MetricAggSpec) UnmarshalJSON(data []byte) error {
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
		case "field", "script", "missing", "format", "value_type", "sigma", "precision_threshold", "execution_hint", "rehash", "compression", "show_distribution", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [metric] unknown field [%s]", k)
		}
	}
	type plain MetricAggSpec
	var raw struct {
		plain
		PrecisionThreshold *int     `json:"precision_threshold"`
		Compression        *float64 `json:"compression"`
		Rehash             any      `json:"rehash"`
		ShowDistribution   any      `json:"show_distribution"`
		ExecutionHint      string   `json:"execution_hint"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	p := raw.plain
	if strings.TrimSpace(p.Field) == "" && p.Script == nil {
		return fmt.Errorf("parsing_exception: metric aggregation requires either [field] or [script]")
	}
	if p.Script != nil {
		if err := validateScriptValue(p.Script); err != nil {
			return err
		}
	}
	if p.Sigma != nil && (*p.Sigma < 0 || math.IsNaN(*p.Sigma) || math.IsInf(*p.Sigma, 0)) {
		return fmt.Errorf("illegal_argument_exception: [sigma] must be >= 0")
	}
	if raw.PrecisionThreshold != nil && (*raw.PrecisionThreshold < 0 || *raw.PrecisionThreshold > 40000) {
		return fmt.Errorf("illegal_argument_exception: [precision_threshold] must be in [0, 40000]")
	}
	if raw.Compression != nil && (*raw.Compression <= 0 || math.IsNaN(*raw.Compression) || math.IsInf(*raw.Compression, 0)) {
		return fmt.Errorf("illegal_argument_exception: [compression] must be > 0")
	}
	if raw.Rehash != nil {
		if _, err := parseFlexibleBool(raw.Rehash); err != nil {
			return fmt.Errorf("parsing_exception: [rehash] %w", err)
		}
	}
	if raw.ShowDistribution != nil {
		if _, err := parseFlexibleBool(raw.ShowDistribution); err != nil {
			return fmt.Errorf("parsing_exception: [show_distribution] %w", err)
		}
	}
	switch strings.ToLower(strings.TrimSpace(raw.ExecutionHint)) {
	case "", "map", "global_ordinals", "bytes_hash", "ordinals", "direct":
	default:
		return fmt.Errorf("parsing_exception: unknown [execution_hint] [%s]", raw.ExecutionHint)
	}
	*m = MetricAggSpec(p)
	return nil
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

func (ns *NestedSortSpec) UnmarshalJSON(data []byte) error {
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
		case "path", "filter", "nested", "max_children":
		default:
			return fmt.Errorf("parsing_exception: [nested] sort unknown field [%s]", k)
		}
	}
	type plain NestedSortSpec
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Path) == "" {
		return fmt.Errorf("parsing_exception: [nested] sort requires non-empty [path]")
	}
	if p.MaxChildren != nil && *p.MaxChildren <= 0 && *p.MaxChildren != -1 {
		return fmt.Errorf("illegal_argument_exception: [nested] sort [max_children] must be > 0 or -1")
	}
	*ns = NestedSortSpec(p)
	return nil
}

type SortEntry = SortFieldSpec

type SortFieldSpec struct {
	Field          string
	Order          string
	Mode           string
	Missing        string
	Script         any
	Type           string
	NumericType    string `json:"numeric_type,omitempty"`
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
	if s.Entry.Mode != "" || s.Entry.Missing != "" || s.Entry.Nested != nil || s.Entry.Type != "" || s.Entry.NumericType != "" || s.Entry.Format != "" || s.Entry.IgnoreUnmapped {
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
		if s.Entry.NumericType != "" {
			inner["numeric_type"] = s.Entry.NumericType
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

func validateSortOrderString(order string) (string, error) {
	ord := strings.ToLower(strings.TrimSpace(order))
	switch ord {
	case "", "asc":
		return "asc", nil
	case "desc":
		return "desc", nil
	default:
		return "", fmt.Errorf("illegal_argument_exception: No enum constant org.elasticsearch.search.sort.SortOrder.%s", order)
	}
}

func validateSortModeString(mode string, isGeo bool) (string, error) {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case "", "min", "max", "avg", "median":
		return m, nil
	case "sum":
		if isGeo {
			return "", fmt.Errorf("illegal_argument_exception: [_geo_distance] sort does not support [sum] mode")
		}
		return m, nil
	default:
		return "", fmt.Errorf("illegal_argument_exception: unknown sort [mode] [%s]", mode)
	}
}

func validateGeoSortTargetValue(raw any, validationMethod string) error {
	if raw == nil {
		return fmt.Errorf("parsing_exception: [_geo_distance] target point cannot be null")
	}
	if arr, ok := raw.([]any); ok {
		if len(arr) == 0 {
			return fmt.Errorf("parsing_exception: [_geo_distance] target point array cannot be empty")
		}
		// Check if it is a [lon, lat] numeric coordinate pair vs an array of geo points
		isCoordPair := (len(arr) == 2 || len(arr) == 3)
		if isCoordPair {
			for _, elem := range arr {
				switch elem.(type) {
				case float64, int, int64, json.Number:
				default:
					isCoordPair = false
				}
			}
		}
		if !isCoordPair {
			for _, elem := range arr {
				lat, lon, err := ParseGeoPoint(elem)
				if err != nil {
					return err
				}
				if _, _, err := validateAndNormalizeGeoPoint(lat, lon, validationMethod); err != nil {
					return err
				}
			}
			return nil
		}
	}
	lat, lon, err := ParseGeoPoint(raw)
	if err != nil {
		return err
	}
	_, _, err = validateAndNormalizeGeoPoint(lat, lon, validationMethod)
	return err
}

func (s *SortSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("parsing_exception: sort specification cannot be null")
	}
	if trimmed[0] == '"' {
		var fieldName string
		if err := json.Unmarshal(trimmed, &fieldName); err != nil {
			return err
		}
		if strings.TrimSpace(fieldName) == "" {
			return fmt.Errorf("parsing_exception: sort field name cannot be empty")
		}
		order := "asc"
		if fieldName == "_score" {
			order = "desc"
		}
		s.Entry = SortFieldSpec{Field: fieldName, Order: order}
		return nil
	}
	if trimmed[0] != '{' {
		return fmt.Errorf("parsing_exception: sort element must be a string or object")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return err
	}
	if len(m) == 0 {
		return fmt.Errorf("parsing_exception: sort object cannot be empty")
	}
	if rawVal, ok := m["_script"]; ok {
		allowedScriptSortKeys := map[string]bool{
			"script": true, "type": true, "order": true, "mode": true,
			"nested": true, "nested_path": true, "nested_filter": true, "missing": true,
		}
		for k := range m {
			if k != "_script" && !allowedScriptSortKeys[k] {
				return fmt.Errorf("parsing_exception: [_script] sort unknown field [%s]", k)
			}
		}
		var innerRawMap map[string]json.RawMessage
		if err := json.Unmarshal(rawVal, &innerRawMap); err != nil {
			return fmt.Errorf("parsing_exception: [_script] sort must be an object: %w", err)
		}
		for k := range innerRawMap {
			if !allowedScriptSortKeys[k] {
				return fmt.Errorf("parsing_exception: [_script] sort unknown field [%s]", k)
			}
		}
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
		if err := json.Unmarshal(rawVal, &obj); err != nil {
			return err
		}
		if obj.Order != "" {
			order = obj.Order
		} else if ordRaw, hasOrd := m["order"]; hasOrd {
			var ordStr string
			if err := json.Unmarshal(ordRaw, &ordStr); err != nil {
				return fmt.Errorf("parsing_exception: [_script] sort [order] must be a string")
			}
			order = ordStr
		}
		normOrder, err := validateSortOrderString(order)
		if err != nil {
			return err
		}
		if err := validateScriptValue(obj.Script); err != nil {
			return err
		}
		scriptType := obj.Type
		if scriptType == "" {
			if typeRaw, hasType := m["type"]; hasType {
				if err := json.Unmarshal(typeRaw, &scriptType); err != nil {
					return fmt.Errorf("parsing_exception: [_script] sort [type] must be a string")
				}
			}
		}
		switch strings.ToLower(strings.TrimSpace(scriptType)) {
		case "number", "string":
			scriptType = strings.ToLower(strings.TrimSpace(scriptType))
		default:
			return fmt.Errorf("parsing_exception: [_script] sort requires [type] in [number, string], got [%s]", scriptType)
		}
		mode := obj.Mode
		if mode == "" {
			if modeRaw, hasMode := m["mode"]; hasMode {
				if err := json.Unmarshal(modeRaw, &mode); err != nil {
					return fmt.Errorf("parsing_exception: [_script] sort [mode] must be a string")
				}
			}
		}
		normMode, err := validateSortModeString(mode, false)
		if err != nil {
			return err
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
				if err := json.Unmarshal(rawNested, &ns); err != nil {
					return err
				}
				nestedSpec = &ns
			}
		}
		if nestedSpec == nil {
			var np string
			var nf *Query
			if rawNP, ok := m["nested_path"]; ok {
				if err := json.Unmarshal(rawNP, &np); err != nil {
					return err
				}
			}
			if rawNF, ok := m["nested_filter"]; ok {
				var q Query
				if err := json.Unmarshal(rawNF, &q); err != nil {
					return err
				}
				nf = &q
			}
			if np != "" || nf != nil {
				nestedSpec = &NestedSortSpec{Path: np, Filter: nf}
			}
		}
		s.Entry = SortFieldSpec{
			Field:   "_script",
			Order:   normOrder,
			Script:  obj.Script,
			Type:    scriptType,
			Mode:    normMode,
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
		if err := json.Unmarshal(rawVal, &obj); err != nil {
			return fmt.Errorf("parsing_exception: [_geo_distance] sort must be an object: %w", err)
		}
		if obj.Order != "" {
			order = obj.Order
		} else if ordRaw, hasOrd := m["order"]; hasOrd {
			var ordStr string
			if err := json.Unmarshal(ordRaw, &ordStr); err != nil {
				return fmt.Errorf("parsing_exception: [_geo_distance] sort [order] must be a string")
			}
			order = ordStr
		}
		normOrder, err := validateSortOrderString(order)
		if err != nil {
			return err
		}
		mode := obj.Mode
		if mode == "" {
			if modeRaw, hasMode := m["mode"]; hasMode {
				if err := json.Unmarshal(modeRaw, &mode); err != nil {
					return fmt.Errorf("parsing_exception: [_geo_distance] sort [mode] must be a string")
				}
			}
		}
		normMode, err := validateSortModeString(mode, true)
		if err != nil {
			return err
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
				if err := json.Unmarshal(rawNested, &ns); err != nil {
					return err
				}
				nestedSpec = &ns
			}
		}
		if nestedSpec == nil {
			var np string
			var nf *Query
			if rawNP, ok := m["nested_path"]; ok {
				if err := json.Unmarshal(rawNP, &np); err != nil {
					return err
				}
			}
			if rawNF, ok := m["nested_filter"]; ok {
				var q Query
				if err := json.Unmarshal(rawNF, &q); err != nil {
					return err
				}
				nf = &q
			}
			if np != "" || nf != nil {
				nestedSpec = &NestedSortSpec{Path: np, Filter: nf}
			}
		}
		var geoMap map[string]any
		if err := json.Unmarshal(rawVal, &geoMap); err != nil {
			return fmt.Errorf("parsing_exception: [_geo_distance] sort must be an object: %w", err)
		}
		if geoMap == nil {
			geoMap = make(map[string]any)
		}
		for _, siblingKey := range []string{"unit", "distance_type", "validation_method", "ignore_unmapped", "unmapped_type"} {
			if _, exists := geoMap[siblingKey]; !exists {
				if rawOpt, hasOpt := m[siblingKey]; hasOpt {
					var optVal any
					if json.Unmarshal(rawOpt, &optVal) == nil {
						geoMap[siblingKey] = optVal
					}
				}
			}
		}
		ignoreUnmapped := false
		if rawIU, hasIU := geoMap["ignore_unmapped"]; hasIU && rawIU != nil {
			bv, err := parseFlexibleBool(rawIU)
			if err != nil {
				return fmt.Errorf("parsing_exception: [_geo_distance] [ignore_unmapped] %w", err)
			}
			ignoreUnmapped = bv
		}
		validationMethod := ""
		if rawVM, hasVM := geoMap["validation_method"]; hasVM && rawVM != nil {
			vmStr, ok := rawVM.(string)
			if !ok {
				return fmt.Errorf("parsing_exception: [_geo_distance] [validation_method] must be a string")
			}
			switch strings.ToUpper(strings.TrimSpace(vmStr)) {
			case "STRICT", "IGNORE_MALFORMED", "COERCE":
				validationMethod = strings.ToUpper(strings.TrimSpace(vmStr))
			default:
				return fmt.Errorf("parsing_exception: [_geo_distance] invalid [validation_method] [%s]", vmStr)
			}
		}
		if rawDT, hasDT := geoMap["distance_type"]; hasDT && rawDT != nil {
			dtStr, ok := rawDT.(string)
			if !ok {
				return fmt.Errorf("parsing_exception: [_geo_distance] [distance_type] must be a string")
			}
			switch strings.ToLower(strings.TrimSpace(dtStr)) {
			case "arc", "plane":
			default:
				return fmt.Errorf("parsing_exception: [_geo_distance] invalid [distance_type] [%s]", dtStr)
			}
		}
		if rawUnit, hasUnit := geoMap["unit"]; hasUnit && rawUnit != nil {
			uStr, ok := rawUnit.(string)
			if !ok {
				return fmt.Errorf("parsing_exception: [_geo_distance] [unit] must be a string")
			}
			if _, ok := GeoDistanceUnitMultiplier(uStr); !ok {
				if _, _, err := ParseGeoDistanceMeters("1" + strings.TrimSpace(uStr)); err != nil {
					return fmt.Errorf("parsing_exception: [_geo_distance] unknown [unit] [%s]", uStr)
				}
			}
		}
		knownGeoOpts := map[string]bool{
			"order": true, "mode": true, "missing": true, "nested": true,
			"nested_path": true, "nested_filter": true, "unit": true,
			"distance_type": true, "validation_method": true,
			"ignore_unmapped": true, "unmapped_type": true, "type": true,
		}
		targetFieldCount := 0
		for gk, gv := range geoMap {
			if knownGeoOpts[gk] {
				continue
			}
			if strings.TrimSpace(gk) == "" {
				return fmt.Errorf("parsing_exception: [_geo_distance] field name cannot be empty")
			}
			if err := validateGeoSortTargetValue(gv, validationMethod); err != nil {
				return err
			}
			targetFieldCount++
		}
		if targetFieldCount == 0 {
			return fmt.Errorf("parsing_exception: [_geo_distance] sort requires at least one target field")
		}
		unmappedType := ""
		if utStr, okUT := geoMap["unmapped_type"].(string); okUT {
			unmappedType = strings.ToLower(strings.TrimSpace(utStr))
		}
		s.Entry = SortFieldSpec{Field: "_geo_distance", Order: normOrder, Mode: normMode, Missing: missing, Type: unmappedType, IgnoreUnmapped: ignoreUnmapped, Nested: nestedSpec, Script: geoMap}
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
	if len(keys) == 0 {
		return fmt.Errorf("parsing_exception: invalid sort specification")
	}
	field := keys[0]
	if strings.TrimSpace(field) == "" {
		return fmt.Errorf("parsing_exception: sort field name cannot be empty")
	}
	rawVal := m[field]
	order := "asc"
	if field == "_score" {
		order = "desc"
	}
	missing := ""
	mode := ""
	sortType := ""
	numericType := ""
	sortFormat := ""
	if rawOrd, hasOrd := m["order"]; hasOrd && field != "order" {
		var ordStr string
		if err := json.Unmarshal(rawOrd, &ordStr); err != nil {
			return fmt.Errorf("parsing_exception: [sort] [order] must be a string")
		}
		if ordStr != "" {
			order = ordStr
		}
	}
	if rawMode, hasMode := m["mode"]; hasMode && field != "mode" {
		if err := json.Unmarshal(rawMode, &mode); err != nil {
			return fmt.Errorf("parsing_exception: [sort] [mode] must be a string")
		}
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
	if rawNT, hasNT := m["numeric_type"]; hasNT && field != "numeric_type" {
		var nt string
		if err := json.Unmarshal(rawNT, &nt); err != nil {
			return fmt.Errorf("parsing_exception: [sort] numeric_type must be a string")
		}
		ntLower := strings.ToLower(strings.TrimSpace(nt))
		if ntLower != "double" && ntLower != "long" && ntLower != "date" && ntLower != "date_nanos" {
			return fmt.Errorf("parsing_exception: [sort] invalid numeric_type [%s]", nt)
		}
		numericType = ntLower
	}
	if sortType == "" {
		if rawT, hasT := m["type"]; hasT && field != "type" {
			_ = json.Unmarshal(rawT, &sortType)
		}
	}
	ignoreUnmapped := false
	if rawIU, hasIU := m["ignore_unmapped"]; hasIU && field != "ignore_unmapped" {
		var iuVal any
		if err := json.Unmarshal(rawIU, &iuVal); err != nil {
			return err
		}
		bv, err := parseFlexibleBool(iuVal)
		if err != nil {
			return fmt.Errorf("parsing_exception: [sort] [ignore_unmapped] %w", err)
		}
		ignoreUnmapped = bv
	}
	var nestedSpec *NestedSortSpec
	if rawNested, hasNested := m["nested"]; hasNested && field != "nested" {
		var ns NestedSortSpec
		if err := json.Unmarshal(rawNested, &ns); err != nil {
			return err
		}
		nestedSpec = &ns
	}
	if nestedSpec == nil {
		var np string
		var nf *Query
		if rawNP, ok := m["nested_path"]; ok && field != "nested_path" {
			if err := json.Unmarshal(rawNP, &np); err != nil {
				return err
			}
		}
		if rawNF, ok := m["nested_filter"]; ok && field != "nested_filter" {
			var q Query
			if err := json.Unmarshal(rawNF, &q); err != nil {
				return err
			}
			nf = &q
		}
		if np != "" || nf != nil {
			nestedSpec = &NestedSortSpec{Path: np, Filter: nf}
		}
	}
	valTrimmed := bytes.TrimSpace(rawVal)
	if len(valTrimmed) == 0 || bytes.Equal(valTrimmed, []byte("null")) {
		return fmt.Errorf("parsing_exception: sort option for [%s] cannot be null", field)
	}
	if valTrimmed[0] == '"' {
		if err := json.Unmarshal(valTrimmed, &order); err != nil {
			return err
		}
		normOrder, err := validateSortOrderString(order)
		if err != nil {
			return err
		}
		normMode, err := validateSortModeString(mode, false)
		if err != nil {
			return err
		}
		s.Entry = SortFieldSpec{Field: field, Order: normOrder, Mode: normMode, Missing: missing, Type: strings.ToLower(sortType), NumericType: numericType, Format: sortFormat, IgnoreUnmapped: ignoreUnmapped, Nested: nestedSpec}
		return nil
	}
	if valTrimmed[0] == '{' {
		var innerMap map[string]json.RawMessage
		if err := json.Unmarshal(valTrimmed, &innerMap); err != nil {
			return err
		}
		for ik := range innerMap {
			switch ik {
			case "order", "mode", "missing", "unmapped_type", "numeric_type", "type", "format", "ignore_unmapped", "nested", "nested_path", "nested_filter":
			default:
				return fmt.Errorf("parsing_exception: [sort] unknown field [%s] for [%s]", ik, field)
			}
		}
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
		if err := json.Unmarshal(valTrimmed, &obj); err != nil {
			return err
		}
		if obj.Order != "" {
			order = obj.Order
		}
		normOrder, err := validateSortOrderString(order)
		if err != nil {
			return err
		}
		if obj.Mode != "" {
			mode = obj.Mode
		}
		normMode, err := validateSortModeString(mode, false)
		if err != nil {
			return err
		}
		if obj.Format != "" {
			sortFormat = obj.Format
		}
		if obj.IgnoreUnmapped != nil {
			bv, err := parseFlexibleBool(obj.IgnoreUnmapped)
			if err != nil {
				return fmt.Errorf("parsing_exception: [sort] [ignore_unmapped] %w", err)
			}
			ignoreUnmapped = bv
		}
		if obj.Missing != nil {
			if fv, ok := obj.Missing.(float64); ok && fv == math.Trunc(fv) && !math.IsInf(fv, 0) && !math.IsNaN(fv) {
				missing = strconv.FormatInt(int64(fv), 10)
			} else {
				missing = fmt.Sprintf("%v", obj.Missing)
			}
		}
		if obj.Nested != nil {
			nestedSpec = obj.Nested
		} else if obj.NestedPath != "" || obj.NestedFilter != nil {
			if strings.TrimSpace(obj.NestedPath) == "" {
				return fmt.Errorf("parsing_exception: [sort] [nested_filter] requires [nested_path]")
			}
			nestedSpec = &NestedSortSpec{Path: obj.NestedPath, Filter: obj.NestedFilter}
		}
		if obj.UnmappedType != "" {
			sortType = obj.UnmappedType
		} else if obj.Type != "" {
			sortType = obj.Type
		}
		if obj.NumericType != "" {
			ntLower := strings.ToLower(strings.TrimSpace(obj.NumericType))
			if ntLower != "double" && ntLower != "long" && ntLower != "date" && ntLower != "date_nanos" {
				return fmt.Errorf("parsing_exception: [sort] invalid numeric_type [%s]", obj.NumericType)
			}
			numericType = ntLower
		}
		s.Entry = SortFieldSpec{Field: field, Order: normOrder, Mode: normMode, Missing: missing, Type: strings.ToLower(sortType), NumericType: numericType, Format: sortFormat, IgnoreUnmapped: ignoreUnmapped, Nested: nestedSpec}
		return nil
	}
	return fmt.Errorf("parsing_exception: sort option for [%s] must be a string or object", field)
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
	Dynamic            any                      `json:"dynamic,omitempty"`
	Subobjects         *bool                    `json:"subobjects,omitempty"`
	Routing            *RoutingMetaSpec         `json:"_routing,omitempty"`
	Meta               map[string]any           `json:"_meta,omitempty"`
	Source             map[string]any           `json:"_source,omitempty"`
	DynamicTemplates   []map[string]any         `json:"dynamic_templates,omitempty"`
	DateDetection      *bool                    `json:"date_detection,omitempty"`
	NumericDetection   *bool                    `json:"numeric_detection,omitempty"`
	DynamicDateFormats []string                 `json:"dynamic_date_formats,omitempty"`
	Runtime            map[string]FieldProperty `json:"runtime,omitempty"`
	Properties         map[string]FieldProperty `json:"properties,omitempty"`
}

type FieldProperty struct {
	Type                     string                   `json:"type,omitempty"`
	Dynamic                  any                      `json:"dynamic,omitempty"`
	Subobjects               *bool                    `json:"subobjects,omitempty"`
	Enabled                  *bool                    `json:"enabled,omitempty"`
	Index                    *bool                    `json:"index,omitempty"`
	DocValues                *bool                    `json:"doc_values,omitempty"`
	Store                    *bool                    `json:"store,omitempty"`
	Path                     string                   `json:"path,omitempty"`
	Value                    any                      `json:"value,omitempty"`
	Script                   any                      `json:"script,omitempty"`
	Analyzer                 string                   `json:"analyzer,omitempty"`
	SearchAnalyzer           string                   `json:"search_analyzer,omitempty"`
	Normalizer               string                   `json:"normalizer,omitempty"`
	Format                   string                   `json:"format,omitempty"`
	TimeZone                 string                   `json:"time_zone,omitempty"`
	Dims                     int                      `json:"dims,omitempty"`
	Dimension                int                      `json:"dimension,omitempty"`
	Similarity               string                   `json:"similarity,omitempty"`
	MultiValued              bool                     `json:"multi_valued,omitempty"`
	UpgradedArray            bool                     `json:"upgraded_array,omitempty"`
	CopyTo                   any                      `json:"copy_to,omitempty"`
	NullValue                any                      `json:"null_value,omitempty"`
	IgnoreAbove              int                      `json:"ignore_above,omitempty"`
	IgnoreMalformed          *bool                    `json:"ignore_malformed,omitempty"`
	Coerce                   *bool                    `json:"coerce,omitempty"`
	ScalingFactor            float64                  `json:"scaling_factor,omitempty"`
	Meta                     map[string]any           `json:"meta,omitempty"`
	IndexPrefixes            map[string]any           `json:"index_prefixes,omitempty"`
	IndexPhrases             *bool                    `json:"index_phrases,omitempty"`
	SplitQueriesOnWhitespace *bool                    `json:"split_queries_on_whitespace,omitempty"`
	EnablePositionIncrements *bool                    `json:"enable_position_increments,omitempty"`
	Relations                map[string]any           `json:"relations,omitempty"`
	Fields                   map[string]FieldProperty `json:"fields,omitempty"`
	Properties               map[string]FieldProperty `json:"properties,omitempty"`
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
