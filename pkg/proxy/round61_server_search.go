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
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// ============================================================================
// F11: Hybrid `knn` Validation & Nested Vector `inner_hits`
// ============================================================================

// validateSearchKNNRequestR61Search validates top-level and query-level `knn` constraints:
//   - Rejects explicit `?search_type=` when top-level `req.KNN` is present (`400 illegal_argument_exception`).
//   - Enforces `k > 0`, `num_candidates > 0`, `k <= 10000`, `num_candidates <= 10000`, and `k <= num_candidates`.
func validateSearchKNNRequestR61Search(r *http.Request, req *esast.SearchRequest) (int, string, string) {
	if req == nil {
		return 0, "", ""
	}
	if len(req.KNN) > 0 && r != nil && r.URL != nil {
		if st := strings.TrimSpace(r.URL.Query().Get("search_type")); st != "" {
			return http.StatusBadRequest,
				"illegal_argument_exception",
				"cannot set [search_type] when using [knn] search, since the search type is determined automatically"
		}
	}
	for i := range req.KNN {
		if status, errType, errReason := validateSingleKNNClauseR61Search(&req.KNN[i]); status != 0 {
			return status, errType, errReason
		}
	}
	if req.Query != nil {
		var queryKNNs []*esast.KNNQuery
		collectKNNClausesFromQueryR61Search(req.Query, &queryKNNs)
		for _, kq := range queryKNNs {
			if status, errType, errReason := validateSingleKNNClauseR61Search(kq); status != 0 {
				return status, errType, errReason
			}
		}
	}
	return 0, "", ""
}

func validateSingleKNNClauseR61Search(kq *esast.KNNQuery) (int, string, string) {
	if kq == nil {
		return 0, "", ""
	}
	hasK := kq.HasK || kq.K != 0
	hasNC := kq.HasNumCandidates || kq.NumCandidates != 0
	if hasK {
		if kq.K <= 0 {
			return http.StatusBadRequest, "illegal_argument_exception", "[k] must be greater than 0"
		}
		if kq.K > 10000 {
			return http.StatusBadRequest, "illegal_argument_exception", "[k] cannot be greater than [10000]"
		}
	}
	if hasNC {
		if kq.NumCandidates <= 0 {
			return http.StatusBadRequest, "illegal_argument_exception", "[num_candidates] must be greater than 0"
		}
		if kq.NumCandidates > 10000 {
			return http.StatusBadRequest, "illegal_argument_exception", "[num_candidates] cannot be greater than [10000]"
		}
	}
	if hasK && hasNC && kq.K > kq.NumCandidates {
		return http.StatusBadRequest, "illegal_argument_exception", "[num_candidates] cannot be less than [k]"
	}
	for i := range kq.Filter {
		var subKNNs []*esast.KNNQuery
		collectKNNClausesFromQueryR61Search(&kq.Filter[i], &subKNNs)
		for _, sub := range subKNNs {
			if status, errType, errReason := validateSingleKNNClauseR61Search(sub); status != 0 {
				return status, errType, errReason
			}
		}
	}
	return 0, "", ""
}

func collectKNNClausesFromQueryR61Search(q *esast.Query, out *[]*esast.KNNQuery) {
	if q == nil || out == nil {
		return
	}
	if q.KNN != nil {
		*out = append(*out, q.KNN)
		for i := range q.KNN.Filter {
			collectKNNClausesFromQueryR61Search(&q.KNN.Filter[i], out)
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			collectKNNClausesFromQueryR61Search(&q.Bool.Must[i], out)
		}
		for i := range q.Bool.Filter {
			collectKNNClausesFromQueryR61Search(&q.Bool.Filter[i], out)
		}
		for i := range q.Bool.Should {
			collectKNNClausesFromQueryR61Search(&q.Bool.Should[i], out)
		}
		for i := range q.Bool.MustNot {
			collectKNNClausesFromQueryR61Search(&q.Bool.MustNot[i], out)
		}
	}
	if q.ConstantScore != nil {
		collectKNNClausesFromQueryR61Search(&q.ConstantScore.Filter, out)
	}
	if q.Boosting != nil {
		collectKNNClausesFromQueryR61Search(&q.Boosting.Positive, out)
		collectKNNClausesFromQueryR61Search(&q.Boosting.Negative, out)
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			collectKNNClausesFromQueryR61Search(&q.DisMax.Queries[i], out)
		}
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil {
		collectKNNClausesFromQueryR61Search(q.FunctionScore.Query, out)
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil {
		collectKNNClausesFromQueryR61Search(q.ScriptScore.Query, out)
	}
	if q.Nested != nil {
		collectKNNClausesFromQueryR61Search(&q.Nested.Query, out)
	}
	if q.Pinned != nil && q.Pinned.Organic != nil {
		collectKNNClausesFromQueryR61Search(q.Pinned.Organic, out)
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil {
		collectKNNClausesFromQueryR61Search(q.Wrapper.Decoded, out)
	}
}

func resolveKNNQueryVectorR61Search(kq *esast.KNNQuery, elemType string, dims int) []float64 {
	if kq == nil {
		return nil
	}
	et := strings.ToLower(strings.TrimSpace(elemType))
	if et == "" {
		et = "float"
	}
	if kq.QueryVectorFromHex && kq.QueryVectorHex != "" {
		switch et {
		case "bit":
			if vec, err := esast.ExpandHexBitVector(kq.QueryVectorHex); err == nil {
				return vec
			}
		case "byte":
			if vec, err := esast.DecodeHexSignedByteVector(kq.QueryVectorHex); err == nil {
				return vec
			}
		}
	}
	if et == "bit" && dims > 0 && len(kq.QueryVector)*8 == dims {
		expanded := make([]float64, 0, dims)
		for _, fv := range kq.QueryVector {
			iv := int64(fv)
			b := byte(int8(iv)) // #nosec G115 -- intentional two's-complement signed-byte bit expansion
			for bit := 7; bit >= 0; bit-- {
				if (b>>uint(bit))&1 == 1 {
					expanded = append(expanded, 1.0)
				} else {
					expanded = append(expanded, 0.0)
				}
			}
		}
		return expanded
	}
	return kq.QueryVector
}

func extractNestedChildMapsPreservingOffsetsR61Search(doc map[string]any, nestedPath string) []map[string]any {
	if doc == nil || strings.TrimSpace(nestedPath) == "" {
		return nil
	}
	segs := strings.Split(nestedPath, ".")
	var walk func(cur any, idx int) []map[string]any
	walk = func(cur any, idx int) []map[string]any {
		if cur == nil {
			return nil
		}
		if idx >= len(segs) {
			switch v := cur.(type) {
			case []any:
				out := make([]map[string]any, 0, len(v))
				for _, item := range v {
					if em, ok := item.(map[string]any); ok {
						out = append(out, em)
					}
				}
				return out
			case []map[string]any:
				out := make([]map[string]any, len(v))
				copy(out, v)
				return out
			case map[string]any:
				return []map[string]any{v}
			}
			return nil
		}
		switch node := cur.(type) {
		case map[string]any:
			if next, exists := node[segs[idx]]; exists {
				return walk(next, idx+1)
			}
			if rem := strings.Join(segs[idx:], "."); node[rem] != nil {
				return walk(node[rem], len(segs))
			}
		case []any:
			var merged []map[string]any
			for _, item := range node {
				merged = append(merged, walk(item, idx)...)
			}
			return merged
		case []map[string]any:
			var merged []map[string]any
			for _, item := range node {
				merged = append(merged, walk(item, idx)...)
			}
			return merged
		}
		return nil
	}
	return walk(doc, 0)
}

// populateNestedKNNInnerHitsR61Search evaluates nested `dense_vector` kNN clauses that request `inner_hits`
// using `transpiler.EvaluateNestedKNNParentScore` and builds the ES `inner_hits.<name>` envelope.
func populateNestedKNNInnerHitsR61Search(
	h *HitRow,
	doc map[string]any,
	idxSchema *schema.IndexSchema,
	req *esast.SearchRequest,
) map[string]any {
	if req == nil || idxSchema == nil {
		return nil
	}
	if doc == nil && h != nil {
		src := h.EffectiveSource()
		if len(src) > 0 {
			dec := json.NewDecoder(bytes.NewReader(src))
			dec.UseNumber()
			_ = dec.Decode(&doc)
		}
	}
	if doc == nil {
		return nil
	}

	var candidates []*esast.KNNQuery
	for i := range req.KNN {
		if req.KNN[i].InnerHits != nil {
			candidates = append(candidates, &req.KNN[i])
		}
	}
	if req.Query != nil {
		var qKNNs []*esast.KNNQuery
		collectKNNClausesFromQueryR61Search(req.Query, &qKNNs)
		for _, kq := range qKNNs {
			if kq.InnerHits != nil {
				candidates = append(candidates, kq)
			}
		}
		collectNestedKNNWithInnerHitsR63(req.Query, &candidates)
	}
	if req.PostFilter != nil {
		var pfKNNs []*esast.KNNQuery
		collectKNNClausesFromQueryR61Search(req.PostFilter, &pfKNNs)
		for _, kq := range pfKNNs {
			if kq.InnerHits != nil {
				candidates = append(candidates, kq)
			}
		}
		collectNestedKNNWithInnerHitsR63(req.PostFilter, &candidates)
	}
	if len(candidates) == 0 {
		return nil
	}

	hitIdx := idxSchema.IndexName
	hitID := ""
	if h != nil {
		if h.Index != "" {
			hitIdx = h.Index
		}
		hitID = h.ID
	}

	outInnerHits := make(map[string]any)
	for _, kq := range candidates {
		b := idxSchema.ResolveField(kq.Field)
		nestedPath := b.NestedPath
		if b.Kind != schema.StorageNestedSubfield || nestedPath == "" {
			// Check if any ancestor segment of `kq.Field` is a registered nested root.
			parts := strings.Split(kq.Field, ".")
			for pLen := len(parts) - 1; pLen >= 1; pLen-- {
				candRoot := strings.Join(parts[:pLen], ".")
				if idxSchema.NestedRoots != nil && idxSchema.NestedRoots[candRoot] != "" {
					nestedPath = candRoot
					break
				}
			}
		}
		if nestedPath == "" {
			continue
		}

		relVecField := strings.TrimPrefix(kq.Field, nestedPath+".")
		if len(b.RelativeJSONPath) > 0 {
			relVecField = strings.Join(b.RelativeJSONPath, ".")
		}

		children := extractNestedChildMapsPreservingOffsetsR61Search(doc, nestedPath)
		vecMetric := b.VectorMetric
		vecElemType := b.VectorElementType
		vecDims := b.VectorDims
		if vecMetric == "" || vecElemType == "" || vecDims == 0 {
			if fp, okRaw := lookupRawPropertyWithMultiFieldR61Search(idxSchema, kq.Field); okRaw {
				if vecMetric == "" {
					vecMetric = fp.Similarity
				}
				if vecElemType == "" {
					vecElemType = fp.ElementType
				}
				if vecDims == 0 {
					vecDims = fp.Dims
				}
			}
		}
		qVec := resolveKNNQueryVectorR61Search(kq, vecElemType, vecDims)
		boost := 1.0
		if kq.Boost != nil {
			boost = *kq.Boost
		}

		effSim := kq.Similarity
		metricLower := strings.ToLower(strings.TrimSpace(vecMetric))
		isL2Sim := kq.Similarity != nil && (metricLower == "" || metricLower == "l2_norm")
		if isL2Sim {
			effSim = nil
		}

		_, _, childHits := transpiler.EvaluateNestedKNNParentScore(
			children,
			relVecField,
			qVec,
			vecMetric,
			vecElemType,
			effSim,
			boost,
		)
		if isL2Sim && kq.Similarity != nil {
			simD := *kq.Similarity
			minScore := boost * (1.0 / (1.0 + simD*simD))
			filtered := childHits[:0]
			for _, ch := range childHits {
				if ch.Score+1e-12 >= minScore {
					filtered = append(filtered, ch)
				}
			}
			childHits = filtered
		}

		ih := kq.InnerHits
		ihName := strings.TrimSpace(ih.Name)
		if ihName == "" {
			ihName = nestedPath
		}

		nestedEvalSchema := deriveNestedEvalSchema(idxSchema, nestedPath)
		nestedSegs := strings.Split(nestedPath, ".")

		if len(ih.Sort) > 0 && len(childHits) > 1 {
			sort.SliceStable(childHits, func(i, j int) bool {
				docI, _ := json.Marshal(buildSingleNestedElementDoc(nestedSegs, childHits[i].Child))
				docJ, _ := json.Marshal(buildSingleNestedElementDoc(nestedSegs, childHits[j].Child))
				hrI := HitRow{ID: hitID, Index: hitIdx, Score: childHits[i].Score, Source: docI, Schema: nestedEvalSchema}
				hrJ := HitRow{ID: hitID, Index: hitIdx, Score: childHits[j].Score, Source: docJ, Schema: nestedEvalSchema}
				if cmp := compareHitRowsBySortWithSchemas(hrI, hrJ, ih.Sort, nestedEvalSchema, nestedEvalSchema); cmp != 0 {
					return cmp < 0
				}
				if childHits[i].Score != childHits[j].Score {
					return childHits[i].Score > childHits[j].Score
				}
				return childHits[i].Offset < childHits[j].Offset
			})
		}

		totalMatched := int64(len(childHits))
		var maxElemScore float64
		for _, ch := range childHits {
			if ch.Score > maxElemScore {
				maxElemScore = ch.Score
			}
		}

		from := ih.From
		if from < 0 {
			from = 0
		}
		size := ih.EffectiveSize()
		var paged []transpiler.NestedKNNChildHit
		if from < len(childHits) {
			end := from + size
			if end > len(childHits) {
				end = len(childHits)
			}
			paged = childHits[from:end]
		}

		trackScores := (ih.TrackScores != nil && *ih.TrackScores) || (req.TrackScores != nil && *req.TrackScores)
		nullifyScore := len(ih.Sort) > 0 && !sortSpecsUseScore(ih.Sort) && !trackScores

		hitItems := make([]map[string]any, 0, len(paged))
		for _, ch := range paged {
			var scoreVal any = ch.Score
			if nullifyScore {
				scoreVal = nil
			}
			item := map[string]any{
				"_index": hitIdx,
				"_id":    hitID,
				"_nested": map[string]any{
					"field":  nestedPath,
					"offset": ch.Offset,
				},
				"_score": scoreVal,
			}

			elemFullDoc := buildSingleNestedElementDoc(nestedSegs, ch.Child)
			elemFullBytes, _ := json.Marshal(elemFullDoc)
			childBytes, _ := json.Marshal(ch.Child)

			includeSource := (ih.Source == nil || !ih.Source.Disabled) && (!ih.HasStoredFieldsNone() || ih.Source != nil)
			if includeSource {
				if ih.Source != nil && (len(ih.Source.Includes) > 0 || len(ih.Source.Excludes) > 0) {
					relFilter := stripNestedPrefixSourceFilterR61Search(ih.Source, nestedPath)
					filteredBytes := filterSourceJSON(childBytes, relFilter)
					var srcObj map[string]any
					dec := json.NewDecoder(bytes.NewReader(filteredBytes))
					dec.UseNumber()
					if dec.Decode(&srcObj) == nil && srcObj != nil {
						item["_source"] = srcObj
					} else {
						item["_source"] = map[string]any{}
					}
				} else {
					item["_source"] = deepCloneDocMap(ch.Child)
				}
			}

			if len(ih.Sort) > 0 {
				hrChild := HitRow{ID: hitID, Index: hitIdx, Score: ch.Score, Source: elemFullBytes, Schema: nestedEvalSchema}
				item["sort"] = extractHitSortValues(hrChild, ih.Sort, nestedEvalSchema)
			}

			if childFields := extractNestedChildInnerHitFieldsR61Search(hitID, hitIdx, nestedPath, ch.Child, elemFullBytes, ih, idxSchema); len(childFields) > 0 {
				item["fields"] = childFields
			}
			hitItems = append(hitItems, item)
		}

		var maxScoreAny any = maxElemScore
		if nullifyScore || totalMatched == 0 {
			maxScoreAny = nil
		}
		outInnerHits[ihName] = map[string]any{
			"hits": map[string]any{
				"total":     map[string]any{"value": totalMatched, "relation": "eq"},
				"max_score": maxScoreAny,
				"hits":      hitItems,
			},
		}
	}

	if len(outInnerHits) == 0 {
		return nil
	}
	return outInnerHits
}

func collectNestedKNNWithInnerHitsR63(q *esast.Query, out *[]*esast.KNNQuery) {
	if q == nil || out == nil {
		return
	}
	if q.Nested != nil {
		if q.Nested.InnerHits != nil {
			var subKNNs []*esast.KNNQuery
			collectKNNClausesFromQueryR61Search(&q.Nested.Query, &subKNNs)
			for _, kq := range subKNNs {
				if kq != nil && kq.InnerHits == nil {
					cp := *kq
					cp.InnerHits = q.Nested.InnerHits
					*out = append(*out, &cp)
				}
			}
		}
		collectNestedKNNWithInnerHitsR63(&q.Nested.Query, out)
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			collectNestedKNNWithInnerHitsR63(&q.Bool.Must[i], out)
		}
		for i := range q.Bool.Filter {
			collectNestedKNNWithInnerHitsR63(&q.Bool.Filter[i], out)
		}
		for i := range q.Bool.Should {
			collectNestedKNNWithInnerHitsR63(&q.Bool.Should[i], out)
		}
	}
	if q.ConstantScore != nil {
		collectNestedKNNWithInnerHitsR63(&q.ConstantScore.Filter, out)
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			collectNestedKNNWithInnerHitsR63(&q.DisMax.Queries[i], out)
		}
	}
	if q.Boosting != nil {
		collectNestedKNNWithInnerHitsR63(&q.Boosting.Positive, out)
	}
	if q.FunctionScore != nil && q.FunctionScore.Query != nil {
		collectNestedKNNWithInnerHitsR63(q.FunctionScore.Query, out)
	}
	if q.ScriptScore != nil && q.ScriptScore.Query != nil {
		collectNestedKNNWithInnerHitsR63(q.ScriptScore.Query, out)
	}
}

func evalNestedKNNParentScoreOnDocR63(idxSchema *schema.IndexSchema, doc map[string]any, nq *esast.NestedQuery) (float64, bool) {
	if nq == nil || nq.Query.KNN == nil || doc == nil || idxSchema == nil {
		return 0, false
	}
	if strings.EqualFold(strings.TrimSpace(nq.ScoreMode), "none") {
		return 0, true
	}
	kq := nq.Query.KNN
	b := idxSchema.ResolveField(kq.Field)
	nestedPath := nq.Path
	if nestedPath == "" {
		nestedPath = b.NestedPath
	}
	if nestedPath == "" {
		return 0, false
	}
	relVecField := strings.TrimPrefix(kq.Field, nestedPath+".")
	if len(b.RelativeJSONPath) > 0 {
		relVecField = strings.Join(b.RelativeJSONPath, ".")
	}
	children := extractNestedChildMapsPreservingOffsetsR61Search(doc, nestedPath)
	vecMetric := b.VectorMetric
	vecElemType := b.VectorElementType
	vecDims := b.VectorDims
	if vecMetric == "" || vecElemType == "" || vecDims == 0 {
		if fp, okRaw := lookupRawPropertyWithMultiFieldR61Search(idxSchema, kq.Field); okRaw {
			if vecMetric == "" {
				vecMetric = fp.Similarity
			}
			if vecElemType == "" {
				vecElemType = fp.ElementType
			}
			if vecDims == 0 {
				vecDims = fp.Dims
			}
		}
	}
	qVec := resolveKNNQueryVectorR61Search(kq, vecElemType, vecDims)
	if len(qVec) == 0 {
		return 0, false
	}
	knnBoost := 1.0
	if kq.Boost != nil {
		knnBoost = *kq.Boost
	}
	effSim := kq.Similarity
	metricLower := strings.ToLower(strings.TrimSpace(vecMetric))
	isL2Sim := kq.Similarity != nil && (metricLower == "" || metricLower == "l2_norm")
	if isL2Sim {
		effSim = nil
	}
	bestSc, matched, childHits := transpiler.EvaluateNestedKNNParentScore(
		children,
		relVecField,
		qVec,
		vecMetric,
		vecElemType,
		effSim,
		knnBoost,
	)
	if isL2Sim && kq.Similarity != nil {
		simD := *kq.Similarity
		minScore := knnBoost * (1.0 / (1.0 + simD*simD))
		filtered := childHits[:0]
		bestSc = 0
		matched = false
		for _, ch := range childHits {
			if ch.Score+1e-12 >= minScore {
				filtered = append(filtered, ch)
				if !matched || ch.Score > bestSc {
					bestSc = ch.Score
					matched = true
				}
			}
		}
		childHits = filtered
	}
	if !matched || len(childHits) == 0 {
		return 0, true
	}
	res := bestSc
	switch strings.ToLower(strings.TrimSpace(nq.ScoreMode)) {
	case "sum":
		res = 0
		for _, ch := range childHits {
			res += ch.Score
		}
	case "min":
		res = childHits[0].Score
		for _, ch := range childHits[1:] {
			if ch.Score < res {
				res = ch.Score
			}
		}
	}
	if nq.Boost != nil {
		res *= *nq.Boost
	}
	return res, true
}

func stripNestedPrefixSourceFilterR61Search(sf *esast.SourceFilter, nestedPath string) *esast.SourceFilter {
	if sf == nil {
		return nil
	}
	pfx := nestedPath + "."
	strip := func(in []string) []string {
		if len(in) == 0 {
			return nil
		}
		out := make([]string, 0, len(in))
		for _, p := range in {
			if strings.HasPrefix(p, pfx) {
				out = append(out, strings.TrimPrefix(p, pfx))
			} else {
				out = append(out, p)
			}
		}
		return out
	}
	return &esast.SourceFilter{
		Fetch:    sf.Fetch,
		Disabled: sf.Disabled,
		Includes: strip(sf.Includes),
		Excludes: strip(sf.Excludes),
	}
}

func extractNestedChildInnerHitFieldsR61Search(
	hitID, hitIdx, nestedPath string,
	childDoc map[string]any,
	elemFullBytes json.RawMessage,
	ih *esast.InnerHitsSpec,
	idxSchema *schema.IndexSchema,
) map[string][]any {
	if ih == nil || ih.HasStoredFieldsNone() {
		return nil
	}
	out := make(map[string][]any)
	hrElem := HitRow{
		ID:     hitID,
		Index:  hitIdx,
		Source: elemFullBytes,
		Schema: idxSchema,
	}
	nestedPrefix := nestedPath + "."

	if len(ih.Fields) > 0 {
		subReq := &esast.SearchRequest{Fields: ih.Fields}
		if fm, status, _, _ := extractUnifiedFieldsR61Search(hrElem, hitIdx, subReq, idxSchema, nil); status == 0 && len(fm) > 0 {
			var flattenNestedMap func(prefix string, m map[string]any)
			flattenNestedMap = func(prefix string, m map[string]any) {
				for sk, sv := range m {
					fullK := prefix + "." + sk
					switch tv := sv.(type) {
					case []any:
						if len(tv) > 0 {
							if _, isSubMap := tv[0].(map[string]any); isSubMap {
								for _, el := range tv {
									if em, okM := el.(map[string]any); okM {
										flattenNestedMap(fullK, em)
									}
								}
								continue
							}
						}
						out[fullK] = tv
					case map[string]any:
						flattenNestedMap(fullK, tv)
					}
				}
			}
			for k, v := range fm {
				if (idxSchema == nil || !idxSchema.ES8Mode) && k == nestedPath && len(v) > 0 {
					if em, okM := v[0].(map[string]any); okM {
						flattenNestedMap(nestedPath, em)
						continue
					}
				}
				out[k] = v
			}
		}
		// Also support relative child field names without `nestedPath.` prefix (e.g. `"paragraph_id"`).
		for _, fs := range ih.Fields {
			if strings.Contains(fs.Field, ".") || strings.HasPrefix(fs.Field, "_") || out[fs.Field] != nil {
				continue
			}
			fullName := nestedPrefix + fs.Field
			if vals := collectScalarValuesAtPath(childDoc, []string{fs.Field}); len(vals) > 0 {
				formatted, _, _, _ := formatUnifiedFieldSliceR61Search(fullName, fs.Field, vals, fs.Format, false, idxSchema)
				if len(formatted) > 0 {
					out[fs.Field] = formatted
				}
			}
		}
	}

	if len(ih.DocvalueFields) > 0 {
		subReq := &esast.SearchRequest{DocvalueFields: ih.DocvalueFields}
		if fm, status, _, _ := extractUnifiedFieldsR61Search(hrElem, hitIdx, subReq, idxSchema, nil); status == 0 && len(fm) > 0 {
			for k, v := range fm {
				out[k] = v
			}
		}
	}

	if ih.StoredFields != nil {
		if sfMap, _, _ := extractStoredFieldsOnlyR61Search(hrElem, hitIdx, ih.StoredFields, idxSchema); len(sfMap) > 0 {
			for k, v := range sfMap {
				out[k] = v
			}
		}
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

// ============================================================================
// F13: Unified Search Fetch Pipeline (`fields` vs `stored_fields` vs `docvalue_fields`),
// `_ignored`, `?force_synthetic_source=true` & `date_nanos` Precision
// ============================================================================

// validateAndResolveForceSyntheticSourceR61Search parses and validates `?force_synthetic_source=...`
// and verifies every target schema supports synthetic `_source` via `schema.ValidateForceSyntheticSource`.
func validateAndResolveForceSyntheticSourceR61Search(
	r *http.Request,
	schemas []*schema.IndexSchema,
) (bool, int, string, string) {
	force := false
	if r != nil && r.URL != nil {
		q := r.URL.Query()
		if rawVals, exists := q["force_synthetic_source"]; exists {
			raw := ""
			if len(rawVals) > 0 {
				raw = strings.TrimSpace(rawVals[0])
			}
			switch strings.ToLower(raw) {
			case "", "true":
				force = true
			case "false":
				force = false
			default:
				return false,
					http.StatusBadRequest,
					"illegal_argument_exception",
					fmt.Sprintf("Failed to parse value [%s] as only [true] or [false] are allowed.", raw)
			}
		}
	}
	if !force {
		return false, 0, "", ""
	}
	for _, sc := range schemas {
		if sc == nil {
			continue
		}
		if err := schema.ValidateForceSyntheticSource(sc); err != nil {
			errType, errReason := splitESExceptionErrorR61Search(err, "illegal_argument_exception")
			return false, http.StatusBadRequest, errType, errReason
		}
	}
	return true, 0, "", ""
}

// reconstructHitSyntheticSourceR61Search reconstructs deterministic synthetic `_source` JSON for a hit.
func reconstructHitSyntheticSourceR61Search(rawSrc json.RawMessage, idxSchema *schema.IndexSchema) json.RawMessage {
	if idxSchema != nil && idxSchema.SourceDisabled() {
		return nil
	}
	var rawDoc map[string]any
	trimmed := bytes.TrimSpace(rawSrc)
	if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		_ = dec.Decode(&rawDoc)
	}
	if rawDoc == nil {
		rawDoc = map[string]any{}
	}

	var shreddedRow map[string]any
	if idxSchema != nil && len(trimmed) > 0 {
		rowBytes, err := schema.ShredDocument(idxSchema, "_synth", 1, false, trimmed)
		if err == nil && len(rowBytes) > 0 {
			decRow := json.NewDecoder(bytes.NewReader(rowBytes))
			decRow.UseNumber()
			_ = decRow.Decode(&shreddedRow)
		}
	}

	recon := schema.ReconstructSyntheticSource(idxSchema, rawDoc, shreddedRow)
	if recon == nil {
		return nil
	}
	// Inject `constant_keyword` fields (only when present in `rawDoc` or TSDB dimension) and canonicalize `ip` fields.
	if idxSchema != nil {
		injectMissingConstantKeywordsInSyntheticMapR61Search(recon, rawDoc, idxSchema)
		canonicalizeSyntheticIPsInMapR61Search(recon, idxSchema)
	}
	encoded, err := json.Marshal(recon)
	if err != nil {
		return rawSrc
	}
	return json.RawMessage(encoded)
}

func canonicalizeSyntheticIPsInMapR61Search(dst map[string]any, idxSchema *schema.IndexSchema) {
	if dst == nil || idxSchema == nil || len(idxSchema.Fields) == 0 {
		return
	}
	for k, b := range idxSchema.Fields {
		if !strings.EqualFold(b.ESType, "ip") || b.AliasTarget != "" || b.Kind == schema.StorageNestedSubfield {
			continue
		}
		segs := effectiveSourceSegsR61Search(k, b)
		rawVal, exists := lookupNestedMapPathR61Search(dst, segs)
		if !exists || rawVal == nil {
			continue
		}
		switch tv := rawVal.(type) {
		case string:
			if addr, err := netip.ParseAddr(strings.TrimSpace(tv)); err == nil {
				setNestedMapPathR61Search(dst, segs, addr.Unmap().String())
			}
		case []any:
			canon := make([]string, 0, len(tv))
			for _, elem := range tv {
				if s, ok := elem.(string); ok {
					if addr, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
						canon = append(canon, addr.Unmap().String())
					}
				}
			}
			if len(canon) == 1 {
				setNestedMapPathR61Search(dst, segs, canon[0])
			} else if len(canon) > 1 {
				sort.Strings(canon)
				arr := make([]any, len(canon))
				for i, c := range canon {
					arr[i] = c
				}
				setNestedMapPathR61Search(dst, segs, arr)
			}
		}
	}
}

func injectMissingConstantKeywordsInSyntheticMapR61Search(dst, rawDoc map[string]any, idxSchema *schema.IndexSchema) {
	if dst == nil || idxSchema == nil || len(idxSchema.Fields) == 0 {
		return
	}
	inc, exc := idxSchema.SourceIncludesExcludes()
	hasFilter := len(inc) > 0 || len(exc) > 0
	keys := make([]string, 0, len(idxSchema.Fields))
	for k := range idxSchema.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b := idxSchema.Fields[k]
		if !strings.EqualFold(b.ESType, "constant_keyword") || !b.HasConstantValue || b.ConstantValue == nil {
			continue
		}
		if b.AliasTarget != "" || strings.Contains(k, ".keyword") {
			continue
		}
		if b.Kind == schema.StorageNestedSubfield {
			continue
		}
		segs := strings.Split(k, ".")
		if idxSchema.ES8Mode && len(rawDoc) > 0 && (!strings.EqualFold(idxSchema.IndexMode, "time_series") || b.TimeSeriesDimension == nil || !*b.TimeSeriesDimension) {
			if _, inRaw := lookupNestedMapPathR61Search(rawDoc, segs); !inRaw {
				continue
			}
		}
		if hasFilter {
			probe, _ := json.Marshal(map[string]any{k: b.ConstantValue})
			filtered := schema.FilterSourceBytesIncludesExcludes(probe, inc, exc)
			if bytes.Equal(bytes.TrimSpace(filtered), []byte("{}")) {
				continue
			}
		}
		if _, exists := lookupNestedMapPathR61Search(dst, segs); !exists {
			setNestedMapPathR61Search(dst, segs, b.ConstantValue)
		}
	}
}

func lookupNestedMapPathR61Search(m map[string]any, segs []string) (any, bool) {
	if m == nil || len(segs) == 0 {
		return nil, false
	}
	var cur any = m
	for _, seg := range segs {
		cm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		nxt, exists := cm[seg]
		if !exists {
			return nil, false
		}
		cur = nxt
	}
	return cur, true
}

func setNestedMapPathR61Search(m map[string]any, segs []string, val any) {
	if m == nil || len(segs) == 0 {
		return
	}
	cur := m
	for i := 0; i < len(segs)-1; i++ {
		nxt, ok := cur[segs[i]].(map[string]any)
		if !ok {
			nxt = make(map[string]any)
			cur[segs[i]] = nxt
		}
		cur = nxt
	}
	cur[segs[len(segs)-1]] = val
}

func collectExplicitStoreTrueFieldsR61Search(idxSchema *schema.IndexSchema) map[string]bool {
	out := make(map[string]bool)
	if idxSchema == nil || idxSchema.RawMapping == nil {
		return out
	}
	var walk func(props map[string]esast.FieldProperty, prefix string)
	walk = func(props map[string]esast.FieldProperty, prefix string) {
		for name, prop := range props {
			full := name
			if prefix != "" {
				full = prefix + "." + name
			}
			if prop.Store != nil && *prop.Store {
				out[full] = true
			}
			for subName, subProp := range prop.Fields {
				if subProp.Store != nil && *subProp.Store {
					out[full+"."+subName] = true
				}
			}
			if len(prop.Properties) > 0 {
				walk(prop.Properties, full)
			}
		}
	}
	walk(idxSchema.RawMapping.Properties, "")
	return out
}

// extractStoredFieldsOnlyR61Search separates `stored_fields` from `fields`:
//   - `stored_fields: "_none_"` -> `(nil, true, true)` (suppresses default `_source` and `fields`)
//   - `stored_fields: []`       -> `(nil, true, false)` (suppresses default `_source` without returning `fields`)
//   - `stored_fields: ["f1"]`   -> suppresses default `_source` and ONLY returns fields with `store: true` in `idxSchema` (plus `_routing`).
func extractStoredFieldsOnlyR61Search(
	h HitRow,
	hitIdx string,
	storedFieldsRaw any,
	idxSchema *schema.IndexSchema,
) (fields map[string][]any, suppressDefaultSource bool, hasNone bool) {
	if storedFieldsRaw == nil {
		return nil, false, false
	}
	sfList := esast.StoredFieldsSlice(storedFieldsRaw)
	for _, f := range sfList {
		if f == "_none_" {
			return nil, true, true
		}
	}
	if len(sfList) == 0 {
		// Explicit `stored_fields: []` or `stored_fields: ""`
		return nil, true, false
	}

	storeTrue := collectExplicitStoreTrueFieldsR61Search(idxSchema)
	var doc map[string]any
	src := h.EffectiveSource()
	if len(src) > 0 {
		dec := json.NewDecoder(bytes.NewReader(src))
		dec.UseNumber()
		_ = dec.Decode(&doc)
	}

	out := make(map[string][]any)
	sortedStored := make([]string, 0, len(storeTrue))
	for fn := range storeTrue {
		sortedStored = append(sortedStored, fn)
	}
	sort.Strings(sortedStored)

	hasSource := false
	for _, pat := range sfList {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		if pat == "_source" {
			hasSource = true
			continue
		}
		if pat == "_routing" {
			routingVal := h.Routing
			if routingVal == "" && hitIdx != "" {
				activeStoredScriptsServerMu.RLock()
				srv := activeStoredScriptsServer
				activeStoredScriptsServerMu.RUnlock()
				if srv != nil {
					routingVal = srv.getDocRouting(hitIdx, h.ID)
				}
			}
			if routingVal != "" {
				out["_routing"] = []any{routingVal}
			}
			continue
		}
		if strings.HasPrefix(pat, "_") {
			// Metadata fields (`_ignored`, `_seq_no`, `_id`, `_index`, `_version`) are NOT stored fields in ES 8 (`520_fetch_fields.yml`).
			continue
		}
		if strings.ContainsAny(pat, "*?") {
			for _, cand := range sortedStored {
				if matchWildcardPattern(pat, cand) {
					if _, exists := out[cand]; exists {
						continue
					}
					vals := extractRawStoredValuesForFieldR61Search(doc, cand, idxSchema)
					if len(vals) > 0 {
						out[cand] = vals
					}
				}
			}
			continue
		}
		targetField := pat
		if idxSchema != nil {
			if b, ok := idxSchema.Fields[pat]; ok && b.AliasTarget != "" {
				targetField = b.AliasTarget
			}
		}
		if !storeTrue[targetField] {
			continue
		}
		vals := extractRawStoredValuesForFieldR61Search(doc, targetField, idxSchema)
		if len(vals) > 0 {
			out[pat] = vals
		}
	}
	suppressSrc := !hasSource
	if len(out) == 0 {
		return nil, suppressSrc, false
	}
	return out, suppressSrc, false
}

func extractRawStoredValuesForFieldR61Search(doc map[string]any, fieldName string, idxSchema *schema.IndexSchema) []any {
	if doc == nil {
		return nil
	}
	cleanField := strings.TrimSuffix(strings.TrimSuffix(fieldName, ".keyword"), ".ngram")
	if idxSchema != nil {
		if fp, ok := lookupRawPropertyWithMultiFieldR61Search(idxSchema, fieldName); ok && fp.Store != nil && *fp.Store {
			// Multi-field with store: true reads from parent JSON path
			if _, isTopProp := idxSchema.Fields[fieldName]; isTopProp {
				b := idxSchema.Fields[fieldName]
				if len(b.SourceJSONPath) > 0 {
					cleanField = strings.Join(b.SourceJSONPath, ".")
				}
			} else if dotIdx := strings.LastIndexByte(fieldName, '.'); dotIdx > 0 {
				cleanField = fieldName[:dotIdx]
			}
		}
	}
	segs := strings.Split(cleanField, ".")
	rawVals := collectSchemaAwareScalarValues(doc, fieldName, segs, idxSchema)
	if len(rawVals) == 0 {
		return nil
	}
	formatted, status, _, _ := formatUnifiedFieldSliceR61Search(fieldName, fieldName, rawVals, "", false, idxSchema)
	if status != 0 {
		return rawVals
	}
	return formatted
}

func lookupRawPropertyWithMultiFieldR61Search(idxSchema *schema.IndexSchema, fieldPath string) (esast.FieldProperty, bool) {
	if idxSchema == nil || idxSchema.RawMapping == nil {
		return esast.FieldProperty{}, false
	}
	parts := strings.Split(fieldPath, ".")
	var walk func(props map[string]esast.FieldProperty, segs []string) (esast.FieldProperty, bool)
	walk = func(props map[string]esast.FieldProperty, segs []string) (esast.FieldProperty, bool) {
		if len(segs) == 0 || len(props) == 0 {
			return esast.FieldProperty{}, false
		}
		if fp, ok := props[segs[0]]; ok {
			if len(segs) == 1 {
				return fp, true
			}
			if len(segs) == 2 && len(fp.Fields) > 0 {
				if mfp, okM := fp.Fields[segs[1]]; okM {
					return mfp, true
				}
			}
			if sub, okSub := walk(fp.Properties, segs[1:]); okSub {
				return sub, true
			}
		}
		for i := len(segs); i >= 2; i-- {
			joined := strings.Join(segs[:i], ".")
			if fp, ok := props[joined]; ok {
				if i == len(segs) {
					return fp, true
				}
				if i == len(segs)-1 && len(fp.Fields) > 0 {
					if mfp, okM := fp.Fields[segs[len(segs)-1]]; okM {
						return mfp, true
					}
				}
				if sub, okSub := walk(fp.Properties, segs[i:]); okSub {
					return sub, true
				}
			}
		}
		return esast.FieldProperty{}, false
	}
	return walk(idxSchema.RawMapping.Properties, parts)
}

// extractHitIgnoredFieldsR61Search extracts sorted `_ignored` field names recorded during shredding
// (or exceeding `ignore_above` / `ignore_malformed`) so hits include `"_ignored": [...]` when non-empty.
func extractHitIgnoredFieldsR61Search(h HitRow, idxSchema *schema.IndexSchema) []string {
	src := h.Source
	if len(bytes.TrimSpace(src)) == 0 {
		src = h.EffectiveSource()
	}
	if len(bytes.TrimSpace(src)) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	addField := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" {
			seen[name] = true
		}
	}

	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	if dec.Decode(&doc) == nil && doc != nil {
		switch ig := doc["_ignored"].(type) {
		case []string:
			for _, f := range ig {
				addField(f)
			}
		case []any:
			for _, f := range ig {
				if s, ok := f.(string); ok {
					addField(s)
				}
			}
		case string:
			addField(ig)
		}
	}

	if idxSchema != nil {
		if rowBytes, err := schema.ShredDocument(idxSchema, h.ID, h.Version, false, src); err == nil && len(rowBytes) > 0 {
			var row map[string]any
			if json.Unmarshal(rowBytes, &row) == nil && row != nil {
				switch ig := row["_ignored"].(type) {
				case []string:
					for _, f := range ig {
						addField(f)
					}
				case []any:
					for _, f := range ig {
						if s, ok := f.(string); ok {
							addField(s)
						}
					}
				}
			}
		}
		if doc != nil {
			for fieldName, fb := range idxSchema.Fields {
				if fb.AliasTarget != "" || strings.HasSuffix(fieldName, ".ngram") {
					continue
				}
				segs := strings.Split(strings.TrimSuffix(fieldName, ".keyword"), ".")
				if len(fb.SourceJSONPath) > 0 {
					segs = fb.SourceJSONPath
				}
				vals := collectScalarValuesAtPath(doc, segs)
				if fb.IgnoreAbove > 0 {
					for _, v := range vals {
						if s, ok := v.(string); ok && utf8.RuneCountInString(s) > fb.IgnoreAbove {
							addField(strings.TrimSuffix(fieldName, ".keyword"))
						}
					}
				}
				if idxSchema.EffectiveIgnoreMalformed(fb) {
					for _, v := range vals {
						if isMalformedValueForBindingR61Search(v, fb) {
							addField(strings.TrimSuffix(fieldName, ".keyword"))
						}
					}
				}
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func isMalformedValueForBindingR61Search(v any, b schema.FieldBinding) bool {
	if v == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(b.ESType)) {
	case "byte", "short", "integer", "long":
		_, ok := parseExactInt64R61Search(v, b.EffectiveCoerceBool())
		return !ok
	case "unsigned_long":
		_, _, ok := parseExactUint64R61Search(v, b.EffectiveCoerceBool())
		return !ok
	case "float", "half_float", "double", "scaled_float":
		_, ok := parseFiniteFloatFromAnyR61Search(v, b.EffectiveCoerceBool())
		return !ok
	case "boolean":
		_, ok := parseStrictESBoolR61Search(v)
		return !ok
	case "ip":
		s := strings.TrimSpace(formatRawScalarStringR61Search(v))
		_, err := netip.ParseAddr(s)
		return err != nil
	case "date":
		_, ok := parseEpochMillisExactR61Search(v, b.Format)
		return !ok
	case "date_nanos":
		_, ok := parseEpochNanosExactR61Search(v, b.Format)
		return !ok
	}
	return false
}

// extractUnifiedFieldsR61Search executes unified `fields` and `docvalue_fields` extraction & formatting:
//   - Enforces format compatibility and pattern validity (`400 illegal_argument_exception`).
//   - Preserves exact 64-bit `int64` / `uint64` precision on `date_nanos`, `long`, and `unsigned_long`.
//   - Formats `boolean`, `float`/`half_float` (`float32` rounded), `scaled_float`, `ip`, `version`,
//     `constant_keyword` (even when absent in `_source`), `flattened`, `token_count`, nested objects, and `runtime` fields.
func extractUnifiedFieldsR61Search(
	h HitRow,
	hitIdx string,
	req *esast.SearchRequest,
	idxSchema *schema.IndexSchema,
	runtimeDoc map[string]any,
) (map[string][]any, int, string, string) {
	if req == nil {
		return nil, 0, "", ""
	}
	if req.HasStoredFieldsNone() {
		if len(req.Fields) > 0 {
			return nil, http.StatusBadRequest, "illegal_argument_exception",
				"Cannot specify both [fields] and [stored_fields] with [_none_]"
		}
		return nil, 0, "", ""
	}
	if len(req.Fields) == 0 && len(req.DocvalueFields) == 0 {
		return nil, 0, "", ""
	}
	if len(req.Fields) > 0 && idxSchema != nil && idxSchema.SourceDisabled() {
		if h.SearchScope != nil && h.SearchScope.srv != nil && !h.SearchScope.srv.isES8Mode(nil) {
			return nil, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Unable to retrieve the requested [fields] since _source is disabled in the mappings for index [%s]", idxSchema.IndexName)
		}
	}

	includeUnmappedByPat := extractIncludeUnmappedPatternsR63(scopeRawBodyR63(h.SearchScope))

	if runtimeDoc == nil && h.RuntimeFields != nil {
		runtimeDoc = h.RuntimeFields
	}

	var doc map[string]any
	src := h.EffectiveSource()
	if len(src) > 0 {
		dec := json.NewDecoder(bytes.NewReader(src))
		dec.UseNumber()
		_ = dec.Decode(&doc)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	if hitIdx == "" && idxSchema != nil {
		hitIdx = idxSchema.IndexName
	}

	out := make(map[string][]any)
	var allLeafScalars map[string][]any
	ensureAllLeafScalars := func() map[string][]any {
		if allLeafScalars == nil {
			allLeafScalars = make(map[string][]any)
			leafSrcDoc := doc
			if h.RuntimeFields != nil && len(h.Source) > 0 {
				var cleanDoc map[string]any
				cDec := json.NewDecoder(bytes.NewReader(h.Source))
				cDec.UseNumber()
				if cDec.Decode(&cleanDoc) == nil && cleanDoc != nil {
					leafSrcDoc = cleanDoc
				}
			}
			collectAllLeafScalarPathsExceptFlattenedR61Search(leafSrcDoc, "", idxSchema, allLeafScalars)
		}
		return allLeafScalars
	}

	rawMergedRT := effectiveRuntimeMappings(idxSchema, req.RuntimeMappings)
	mergedRuntimeDefs := rawMergedRT
	for rtName, rtProp := range rawMergedRT {
		if rtProp.IsCompositeRuntime() {
			if mergedRuntimeDefs == nil || len(mergedRuntimeDefs) == len(rawMergedRT) {
				cp := make(map[string]esast.FieldProperty, len(rawMergedRT)+len(rtProp.Fields))
				for k, v := range rawMergedRT {
					cp[k] = v
				}
				mergedRuntimeDefs = cp
			}
			for subName, subProp := range rtProp.Fields {
				if subProp.Script == nil {
					subProp.Script = rtProp.Script
				}
				mergedRuntimeDefs[rtName+"."+subName] = subProp
			}
		}
	}

	processSpec := func(spec esast.FieldRequestSpec, isDocvalue bool) (int, string, string) {
		rawPattern := strings.TrimSpace(spec.Field)
		if rawPattern == "" {
			return 0, "", ""
		}

		// Direct metadata fields (note `_` wildcards like `"_*"` do NOT match metadata fields per `330_fetch_fields.yml:1019`)
		if !strings.ContainsAny(rawPattern, "*?") {
			if metaVals, handled, status, errT, errR := extractMetadataFieldR61Search(h, hitIdx, rawPattern, spec.Format, isDocvalue, idxSchema); handled {
				if status != 0 {
					return status, errT, errR
				}
				if len(metaVals) > 0 {
					out[rawPattern] = metaVals
				}
				return 0, "", ""
			}
			// Check field `alias` pointing to a metadata field (e.g. `idAlias -> _id`)
			if idxSchema != nil {
				if b, ok := idxSchema.Fields[rawPattern]; ok && b.AliasTarget != "" && strings.HasPrefix(b.AliasTarget, "_") {
					metaVals, handled, status, errT, errR := extractMetadataFieldR61Search(h, hitIdx, b.AliasTarget, spec.Format, isDocvalue, idxSchema)
					if handled {
						if status != 0 {
							return status, errT, errR
						}
						if len(metaVals) > 0 {
							out[rawPattern] = metaVals
						}
						return 0, "", ""
					}
				}
			}
		}

		// Expand candidate target fields
		incUnmapped := includeUnmappedByPat[rawPattern]
		if strings.ContainsAny(rawPattern, "*?") {
			matchedAny := make(map[string]bool)
			if idxSchema != nil {
				fieldNames := collectSchemaCandidateFetchFieldsR61Search(idxSchema, mergedRuntimeDefs, strings.Contains(rawPattern, "."))
				for _, fn := range fieldNames {
					if !matchWildcardPattern(rawPattern, fn) {
						continue
					}
					matchedAny[fn] = true
					if status, errT, errR := emitSingleMatchedFieldIntoOutR61Search(h, hitIdx, doc, runtimeDoc, mergedRuntimeDefs, fn, rawPattern, spec.Format, isDocvalue, idxSchema, out); status != 0 {
						return status, errT, errR
					}
				}
				if incUnmapped && !isDocvalue && !isIndexSourceDisabledRound59(idxSchema) {
					// Emit `enabled: false` top-level/object fields directly from `_source` when `include_unmapped: true` (`330_fetch_fields.yml`)
					for fn, fb := range idxSchema.Fields {
						if !fb.EnabledFalse || matchedAny[fn] || !matchWildcardPattern(rawPattern, fn) {
							continue
						}
						if rawVal, exists := lookupNestedMapPathR61Search(doc, strings.Split(fn, ".")); exists && rawVal != nil {
							matchedAny[fn] = true
							if arr, isArr := rawVal.([]any); isArr {
								out[fn] = arr
							} else {
								out[fn] = []any{rawVal}
							}
						}
					}
					// Also include unmapped leaf subfields inside `nested` objects when `include_unmapped: true`
					for nestedRoot := range idxSchema.NestedRoots {
						if strings.Contains(nestedRoot, ".") {
							continue
						}
						children := extractNestedChildMapsPreservingOffsetsR61Search(doc, nestedRoot)
						if len(children) == 0 {
							continue
						}
						var unmappedRels []string
						seenRel := make(map[string]bool)
						for _, ch := range children {
							subLeaves := make(map[string][]any)
							collectAllLeafScalarPathsExceptFlattenedR61Search(ch, "", nil, subLeaves)
							for relK := range subLeaves {
								fullCand := nestedRoot + "." + relK
								if seenRel[relK] || matchedAny[fullCand] || !matchWildcardPattern(rawPattern, fullCand) {
									continue
								}
								if _, isMapped := idxSchema.Fields[fullCand]; isMapped {
									continue
								}
								seenRel[relK] = true
								unmappedRels = append(unmappedRels, relK)
							}
						}
						sort.Strings(unmappedRels)
						for _, relK := range unmappedRels {
							fullCand := nestedRoot + "." + relK
							matchedAny[fullCand] = true
							if st, errT, errR := mergeNestedFieldIntoUnifiedOutR61Search(doc, nestedRoot, relK, fullCand, rawPattern, spec.Format, idxSchema, out); st != 0 {
								return st, errT, errR
							}
						}
					}
				}
			}
			if !isDocvalue && !strings.HasPrefix(rawPattern, "_") && !isIndexSourceDisabledRound59(idxSchema) {
				leaves := ensureAllLeafScalars()
				leafKeys := make([]string, 0, len(leaves))
				for lk := range leaves {
					leafKeys = append(leafKeys, lk)
				}
				sort.Strings(leafKeys)
				for _, lk := range leafKeys {
					if matchedAny[lk] || !matchWildcardPattern(rawPattern, lk) {
						continue
					}
					if !incUnmapped && idxSchema != nil && idxSchema.IsDynamicFalseUnmappedField(lk) {
						continue
					}
					if status, errT, errR := emitSingleMatchedFieldIntoOutR61Search(h, hitIdx, doc, runtimeDoc, mergedRuntimeDefs, lk, rawPattern, spec.Format, false, idxSchema, out); status != 0 {
						return status, errT, errR
					}
				}
			}
			return 0, "", ""
		}

		if incUnmapped && !isDocvalue && idxSchema != nil && !isIndexSourceDisabledRound59(idxSchema) {
			if fb, ok := idxSchema.Fields[rawPattern]; ok && fb.EnabledFalse {
				if rawVal, exists := lookupNestedMapPathR61Search(doc, strings.Split(rawPattern, ".")); exists && rawVal != nil {
					if arr, isArr := rawVal.([]any); isArr {
						out[rawPattern] = arr
					} else {
						out[rawPattern] = []any{rawVal}
					}
				}
				return 0, "", ""
			}
		}

		return emitSingleMatchedFieldIntoOutR61Search(h, hitIdx, doc, runtimeDoc, mergedRuntimeDefs, rawPattern, rawPattern, spec.Format, isDocvalue, idxSchema, out)
	}

	for _, spec := range req.Fields {
		if status, errT, errR := processSpec(spec, false); status != 0 {
			return nil, status, errT, errR
		}
	}
	dvWrittenFields := make(map[string]bool, len(req.DocvalueFields))
	for _, spec := range req.DocvalueFields {
		isRepeatDV := dvWrittenFields[spec.Field] && !strings.ContainsAny(spec.Field, "*?")
		var prevSlice []any
		if isRepeatDV {
			prevSlice = append([]any(nil), out[spec.Field]...)
		}
		if status, errT, errR := processSpec(spec, true); status != 0 {
			return nil, status, errT, errR
		}
		if !strings.ContainsAny(spec.Field, "*?") {
			if isRepeatDV && len(prevSlice) > 0 && len(out[spec.Field]) > 0 {
				merged := append([]any(nil), prevSlice...)
				for _, nv := range out[spec.Field] {
					dup := false
					for _, pv := range merged {
						if fmt.Sprintf("%T:%v", pv, pv) == fmt.Sprintf("%T:%v", nv, nv) {
							dup = true
							break
						}
					}
					if !dup {
						merged = append(merged, nv)
					}
				}
				out[spec.Field] = merged
			}
			dvWrittenFields[spec.Field] = true
		}
	}

	if len(out) == 0 {
		return nil, 0, "", ""
	}
	return out, 0, "", ""
}

func collectAllLeafScalarPathsExceptFlattenedR61Search(
	node any,
	prefix string,
	idxSchema *schema.IndexSchema,
	out map[string][]any,
) {
	if prefix != "" && idxSchema != nil {
		if b, ok := idxSchema.Fields[prefix]; ok {
			if b.EnabledFalse || isNonTraversableMappedLeafTypeR63(b.ESType) {
				return
			}
			if idxSchema.NestedRoots != nil && idxSchema.NestedRoots[prefix] != "" {
				return
			}
		} else if fp, okRaw := lookupRawPropertyWithMultiFieldR61Search(idxSchema, prefix); okRaw {
			if (fp.Enabled != nil && !*fp.Enabled) || isNonTraversableMappedLeafTypeR63(fp.Type) {
				return
			}
		}
		if idxSchema.NestedRoots != nil && idxSchema.NestedRoots[prefix] != "" {
			return
		}
	}
	switch curr := node.(type) {
	case map[string]any:
		for k, v := range curr {
			if prefix == "" && strings.HasPrefix(k, "__") {
				continue
			}
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			collectAllLeafScalarPathsExceptFlattenedR61Search(v, full, idxSchema, out)
		}
	case []any:
		for _, item := range curr {
			collectAllLeafScalarPathsExceptFlattenedR61Search(item, prefix, idxSchema, out)
		}
	case nil:
	default:
		if prefix != "" {
			out[prefix] = append(out[prefix], curr)
		}
	}
}

func collectSchemaCandidateFetchFieldsR61Search(
	idxSchema *schema.IndexSchema,
	runtimeDefs map[string]esast.FieldProperty,
	includeDefaultMultiFields bool,
) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		if !includeDefaultMultiFields && strings.HasSuffix(name, ".ngram") {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	subobjFalse := idxSchema != nil && idxSchema.RawMapping != nil && idxSchema.RawMapping.Subobjects != nil && !*idxSchema.RawMapping.Subobjects
	isReservedMetaName := func(n string) bool {
		switch n {
		case "_id", "_index", "_routing", "_version", "_seq_no", "_primary_term", "_source", "_ignored", "_size", "_field_names", "_tsid", "_ts_routing_hash", "_doc_count":
			return true
		}
		return false
	}
	if idxSchema != nil {
		srcDisabled := idxSchema.SourceDisabled()
		for fn, fb := range idxSchema.Fields {
			if fb.EnabledFalse || fb.IsVirtualSAYTSubfield || isReservedMetaName(fn) {
				continue
			}
			if (strings.HasSuffix(fn, ".lat") || strings.HasSuffix(fn, ".lon")) && idxSchema.Fields[strings.TrimSuffix(strings.TrimSuffix(fn, ".lat"), ".lon")].ESType == "geo_point" {
				if _, explicit := lookupRawPropertyWithMultiFieldR61Search(idxSchema, fn); !explicit {
					continue
				}
			}
			if srcDisabled {
				if strings.HasPrefix(fb.AliasTarget, "_") {
					continue
				}
				esT := strings.ToLower(strings.TrimSpace(fb.ESType))
				isStored := fieldIsStoredInSchemaR61Search(idxSchema, fn)
				if !isStored && (fb.DocValuesFalse || esT == "text" || esT == "match_only_text" || esT == "annotated-text" || esT == "annotated_text" || esT == "geo_shape" || esT == "shape") {
					continue
				}
			}
			if !includeDefaultMultiFields && !subobjFalse && strings.HasSuffix(fn, ".keyword") {
				// Include explicit multi-fields from RawMapping, skip auto synthetic `.keyword` unless pattern has `.` or `subobjects: false`
				if _, ok := lookupRawPropertyWithMultiFieldR61Search(idxSchema, fn); !ok {
					continue
				}
			}
			add(fn)
		}
		if idxSchema.RawMapping != nil {
			var walkRaw func(props map[string]esast.FieldProperty, prefix string)
			walkRaw = func(props map[string]esast.FieldProperty, prefix string) {
				for k, fp := range props {
					full := k
					if prefix != "" {
						full = prefix + "." + k
					}
					if isReservedMetaName(full) || (fp.Enabled != nil && !*fp.Enabled) {
						continue
					}
					ft := strings.ToLower(strings.TrimSpace(fp.Type))
					if ft != "" && ft != "object" && ft != "nested" {
						skipRaw := false
						if srcDisabled {
							if ft == "alias" && strings.HasPrefix(strings.TrimSpace(fp.Path), "_") {
								skipRaw = true
							}
							isStored := fp.Store != nil && *fp.Store
							dvFalse := fp.DocValues != nil && !*fp.DocValues
							if !isStored && (dvFalse || ft == "text" || ft == "match_only_text" || ft == "annotated-text" || ft == "annotated_text" || ft == "geo_shape" || ft == "shape") {
								skipRaw = true
							}
						}
						if !skipRaw {
							add(full)
						}
					}
					for mfk, mfp := range fp.Fields {
						mft := strings.ToLower(strings.TrimSpace(mfp.Type))
						if mft != "" {
							mfFull := full + "." + mfk
							if srcDisabled {
								isStored := mfp.Store != nil && *mfp.Store
								dvFalse := mfp.DocValues != nil && !*mfp.DocValues
								if !isStored && (dvFalse || mft == "text" || mft == "match_only_text" || mft == "annotated-text" || mft == "annotated_text" || mft == "geo_shape" || mft == "shape") {
									continue
								}
							}
							add(mfFull)
						}
					}
					if len(fp.Properties) > 0 {
						walkRaw(fp.Properties, full)
					}
				}
			}
			walkRaw(idxSchema.RawMapping.Properties, "")
		}
	}
	for rtName, rtProp := range runtimeDefs {
		if rtProp.IsCompositeRuntime() {
			continue
		}
		add(rtName)
	}
	sort.Strings(out)
	return out
}

func extractMetadataFieldR61Search(
	h HitRow,
	hitIdx string,
	field string,
	format string,
	isDocvalue bool,
	idxSchema *schema.IndexSchema,
) ([]any, bool, int, string, string) {
	switch field {
	case "_id":
		if isDocvalue {
			return nil, true, http.StatusBadRequest, "illegal_argument_exception", "Field [_id] of type [_id] does not support doc_values"
		}
		if format != "" {
			return nil, true, http.StatusBadRequest, "illegal_argument_exception", "error fetching [_id]: Field [_id] of type [_id] doesn't support formats."
		}
		return []any{h.ID}, true, 0, "", ""
	case "_index":
		if format != "" {
			return nil, true, http.StatusBadRequest, "illegal_argument_exception", "error fetching [_index]: Field [_index] of type [_index] doesn't support formats."
		}
		return []any{hitIdx}, true, 0, "", ""
	case "_routing":
		if format != "" {
			return nil, true, http.StatusBadRequest, "illegal_argument_exception", "error fetching [_routing]: Field [_routing] of type [_routing] doesn't support formats."
		}
		if h.Routing != "" {
			return []any{h.Routing}, true, 0, "", ""
		}
		return nil, true, 0, "", ""
	case "_version":
		if format != "" {
			return nil, true, http.StatusBadRequest, "illegal_argument_exception", "error fetching [_version]: Field [_version] of type [_version] doesn't support formats."
		}
		ver := h.Version
		if ver <= 0 {
			ver = 1
		}
		return []any{ver}, true, 0, "", ""
	case "_seq_no":
		if !isDocvalue && h.SearchScope != nil && h.SearchScope.srv != nil && h.SearchScope.srv.hasExplicitTargetESVersion() {
			return nil, true, http.StatusInternalServerError, "unsupported_operation_exception", "Field [_seq_no] cannot be retrieved via [fields]; use [seq_no_primary_term] or [docvalue_fields] instead"
		}
		if format != "" {
			return nil, true, http.StatusBadRequest, "illegal_argument_exception", "error fetching [_seq_no]: Field [_seq_no] of type [_seq_no] doesn't support formats."
		}
		seqNo := h.SeqNo
		if !h.HasSeqNo {
			if h.Version > 0 {
				seqNo = h.Version - 1
			} else {
				seqNo = 0
			}
		}
		return []any{seqNo}, true, 0, "", ""
	case "_primary_term":
		if !isDocvalue && h.SearchScope != nil && h.SearchScope.srv != nil && h.SearchScope.srv.hasExplicitTargetESVersion() {
			return nil, true, http.StatusInternalServerError, "unsupported_operation_exception", "Field [_primary_term] cannot be retrieved via [fields]; use [seq_no_primary_term] or [docvalue_fields] instead"
		}
		return []any{int64(1)}, true, 0, "", ""
	case "_tsid":
		if format != "" {
			return nil, true, http.StatusBadRequest, "illegal_argument_exception", "error fetching [_tsid]: Field [_tsid] of type [_tsid] doesn't support formats."
		}
		if idxSchema != nil && strings.EqualFold(idxSchema.IndexMode, "time_series") {
			docMap := decodeHitDocMapRound60(h)
			row := map[string]any{}
			schema.PopulateTSDBColumnsForShred(idxSchema, docMap, row)
			if tsid, _ := row["__tsid"].(string); tsid != "" {
				return []any{tsid}, true, 0, "", ""
			}
		}
		return nil, true, 0, "", ""
	case "_ts_routing_hash":
		if format != "" {
			return nil, true, http.StatusBadRequest, "illegal_argument_exception", "error fetching [_ts_routing_hash]: Field [_ts_routing_hash] of type [_ts_routing_hash] doesn't support formats."
		}
		if rh, ok := extractTSDBRoutingHashValueR63(h, hitIdx, idxSchema); ok {
			return []any{rh}, true, 0, "", ""
		}
		return nil, true, 0, "", ""
	case "_ignored":
		if format != "" {
			return nil, true, http.StatusBadRequest, "illegal_argument_exception", "error fetching [_ignored]: Field [_ignored] of type [_ignored] doesn't support formats."
		}
		ig := extractHitIgnoredFieldsR61Search(h, idxSchema)
		if len(ig) == 0 {
			return nil, true, 0, "", ""
		}
		res := make([]any, len(ig))
		for i, s := range ig {
			res[i] = s
		}
		return res, true, 0, "", ""
	}
	return nil, false, 0, "", ""
}

func emitSingleMatchedFieldIntoOutR61Search(
	h HitRow,
	hitIdx string,
	doc map[string]any,
	runtimeDoc map[string]any,
	runtimeDefs map[string]esast.FieldProperty,
	fieldName string,
	requestedPattern string,
	format string,
	isDocvalue bool,
	idxSchema *schema.IndexSchema,
	out map[string][]any,
) (int, string, string) {
	// Alias to metadata field (e.g. `idAlias -> _id`) when matched via `"*"`
	if idxSchema != nil {
		if b, ok := idxSchema.Fields[fieldName]; ok && b.AliasTarget != "" && strings.HasPrefix(b.AliasTarget, "_") {
			metaVals, handled, status, errT, errR := extractMetadataFieldR61Search(h, hitIdx, b.AliasTarget, format, isDocvalue, idxSchema)
			if handled {
				if status != 0 {
					return status, errT, errR
				}
				if len(metaVals) > 0 {
					out[fieldName] = metaVals
				}
				return 0, "", ""
			}
		}
	}

	// Resolve effective binding / type
	var b schema.FieldBinding
	hasBinding := false
	if idxSchema != nil {
		if directB, ok := idxSchema.Fields[fieldName]; ok {
			b = directB
			hasBinding = true
			if b.AliasTarget != "" {
				if targetB, okT := idxSchema.Fields[b.AliasTarget]; okT {
					b = targetB
					b.AliasTarget = directB.AliasTarget
				}
			}
		} else if fp, okRaw := lookupRawPropertyWithMultiFieldR61Search(idxSchema, fieldName); okRaw {
			b = schema.FieldBinding{
				ESFieldPath:         fieldName,
				ESType:              strings.ToLower(strings.TrimSpace(fp.Type)),
				Format:              fp.Format,
				Analyzer:            fp.Analyzer,
				LowercaseNormalizer: strings.EqualFold(fp.Normalizer, "lowercase"),
				IgnoreAbove:         fp.IgnoreAbove,
				IgnoreMalformed:     fp.IgnoreMalformed,
				Coerce:              fp.Coerce,
				ScalingFactor:       fp.ScalingFactor,
				NullValue:           fp.NullValue,
				ConstantValue:       fp.Value,
				HasConstantValue:    fp.Value != nil,
				DocValuesFalse:      fp.DocValues != nil && !*fp.DocValues,
				EnabledFalse:        fp.Enabled != nil && !*fp.Enabled,
			}
			hasBinding = true
		} else {
			// Check if `fieldName` is a dotted subkey under a `flattened` field!
			if flatRoot, subKey, okFlat := resolveFlattenedSubkeyR61Search(idxSchema, fieldName); okFlat {
				if format != "" {
					return http.StatusBadRequest, "illegal_argument_exception", formatUnsupportedErrorMsgR61Search(fieldName, requestedPattern, "flattened")
				}
				if strings.ContainsAny(subKey, "*?") && strings.ContainsAny(requestedPattern, "*?") {
					// Per `340_flattened.yml:232`, `fields: ["flattened.some*"]` wildcard on flattened subkey returns nothing!
					return 0, "", ""
				}
				flatVals := extractFlattenedSubkeyValuesR61Search(doc, flatRoot, subKey)
				if len(flatVals) > 0 {
					out[fieldName] = flatVals
				}
				return 0, "", ""
			}
		}
	}

	if rtProp, isRT := runtimeDefs[fieldName]; isRT {
		rtType := strings.ToLower(strings.TrimSpace(rtProp.Type))
		if rtType == "" {
			rtType = "keyword"
		}
		b = schema.FieldBinding{
			ESFieldPath: fieldName,
			ESType:      rtType,
			Format:      rtProp.Format,
		}
		hasBinding = true
	}

	if hasBinding && b.EnabledFalse {
		return 0, "", ""
	}

	esType := strings.ToLower(strings.TrimSpace(b.ESType))

	// Validate `docvalue_fields` capability
	if isDocvalue && hasBinding {
		if b.DocValuesFalse || esType == "text" || esType == "match_only_text" || esType == "annotated-text" || esType == "annotated_text" ||
			esType == "dense_vector" || esType == "sparse_vector" || esType == "percolator" || esType == "rank_feature" || esType == "rank_features" || esType == "completion" {
			return http.StatusBadRequest,
				"illegal_argument_exception",
				fmt.Sprintf("Can't load fielddata on [%s] because fielddata is unsupported on fields of type [%s]. Use doc values instead.", fieldName, esType)
		}
	}

	// Validate `format` parameter before extracting values (`330_fetch_fields.yml:892-975` fails even if field value is absent or present!)
	if format != "" && hasBinding && esType != "" {
		if status, errT, errR := validateFieldFetchFormatR61Search(fieldName, requestedPattern, esType, format); status != 0 {
			return status, errT, errR
		}
	}

	// Runtime field extraction from `runtimeDoc` (or fallback `doc`)
	rtDefProp, inRTDefs := runtimeDefs[fieldName]
	hasRTVal := false
	if runtimeDoc != nil {
		if _, ok := runtimeDoc[fieldName]; ok {
			hasRTVal = true
		} else if _, ok := lookupNestedMapPathR61Search(runtimeDoc, strings.Split(fieldName, ".")); ok {
			hasRTVal = true
		}
	}
	if inRTDefs && strings.EqualFold(strings.TrimSpace(rtDefProp.Type), "lookup") {
		if isDocvalue {
			return http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("Fielddata is not supported on field [%s] of type [lookup]", fieldName)
		}
		if h.SearchScope != nil && h.SearchScope.srv != nil {
			reqCtx := h.SearchScope.ctx
			if reqCtx == nil {
				reqCtx = context.Background()
			}
			lVals, lSt, lErrT, lErrR := h.SearchScope.srv.resolveLookupRuntimeFieldFetchR62Search(reqCtx, doc, runtimeDoc, idxSchema, fieldName, rtDefProp)
			if lSt != 0 {
				return lSt, lErrT, lErrR
			}
			if len(lVals) > 0 {
				out[fieldName] = lVals
			}
		}
		return 0, "", ""
	}
	if inRTDefs || (!hasBinding && hasRTVal) {
		rtType := esType
		if inRTDefs && strings.TrimSpace(rtDefProp.Type) != "" {
			rtType = strings.ToLower(strings.TrimSpace(rtDefProp.Type))
		}
		if rtType == "geo_point" || rtType == "point" {
			fLower := strings.ToLower(strings.TrimSpace(format))
			if fLower == "use_field_mapping" {
				fLower = ""
			}
			if fLower != "" && fLower != "geojson" && fLower != "wkt" {
				return http.StatusBadRequest, "illegal_argument_exception", formatUnsupportedErrorMsgR61Search(fieldName, requestedPattern, rtType)
			}
			var pts [][2]float64
			if runtimeDoc != nil {
				if v, ok := runtimeDoc[fieldName]; ok && v != nil {
					pts = extractGeoPointsFromRawNodeR61Search(v)
				}
				if len(pts) == 0 && (!inRTDefs || rtDefProp.Script == nil) {
					pts = extractGeoPointsAtPathR62Search(runtimeDoc, strings.Split(fieldName, "."))
				}
			}
			if len(pts) == 0 && doc != nil && (!inRTDefs || rtDefProp.Script == nil) {
				if v, ok := doc[fieldName]; ok && v != nil {
					pts = extractGeoPointsFromRawNodeR61Search(v)
				}
				if len(pts) == 0 {
					pts = extractGeoPointsAtPathR62Search(doc, strings.Split(fieldName, "."))
				}
			}
			if len(pts) > 0 {
				formattedPts := make([]any, 0, len(pts))
				for _, pt := range pts {
					if fLower == "wkt" || (isDocvalue && fLower == "") {
						formattedPts = append(formattedPts, fmt.Sprintf("POINT (%s %s)", formatShortestFloatR61Search(pt[0]), formatShortestFloatR61Search(pt[1])))
					} else {
						formattedPts = append(formattedPts, map[string]any{
							"type":        "Point",
							"coordinates": []float64{pt[0], pt[1]},
						})
					}
				}
				out[fieldName] = formattedPts
			}
			return 0, "", ""
		}
		var rawRTVals []any
		if runtimeDoc != nil {
			if v, ok := runtimeDoc[fieldName]; ok && v != nil {
				rawRTVals = flattenAnyToSliceR61Search(v)
			} else if !inRTDefs || rtDefProp.Script == nil {
				if v, ok := lookupNestedMapPathR61Search(runtimeDoc, strings.Split(fieldName, ".")); ok && v != nil {
					rawRTVals = flattenAnyToSliceR61Search(v)
				} else {
					rawRTVals = collectScalarValuesAtPath(runtimeDoc, strings.Split(fieldName, "."))
				}
			}
		}
		if len(rawRTVals) == 0 && doc != nil && (!inRTDefs || rtDefProp.Script == nil) {
			if v, ok := doc[fieldName]; ok && v != nil {
				rawRTVals = flattenAnyToSliceR61Search(v)
			} else if v, ok := lookupNestedMapPathR61Search(doc, strings.Split(fieldName, ".")); ok && v != nil {
				rawRTVals = flattenAnyToSliceR61Search(v)
			} else {
				rawRTVals = collectScalarValuesAtPath(doc, strings.Split(fieldName, "."))
			}
		}
		if len(rawRTVals) == 0 {
			return 0, "", ""
		}
		effSchemaForFmt := idxSchema
		if inRTDefs && !hasBinding {
			var synth schema.IndexSchema
			if idxSchema != nil {
				synth = *idxSchema
				synth.Fields = make(map[string]schema.FieldBinding, len(idxSchema.Fields)+1)
				for fk, fv := range idxSchema.Fields {
					synth.Fields[fk] = fv
				}
			} else {
				synth.Fields = make(map[string]schema.FieldBinding, 1)
			}
			synth.Fields[fieldName] = schema.FieldBinding{
				ESFieldPath:   fieldName,
				ESType:        rtType,
				Format:        rtDefProp.Format,
				IgnoreAbove:   rtDefProp.IgnoreAbove,
				Coerce:        rtDefProp.Coerce,
				ScalingFactor: rtDefProp.ScalingFactor,
				FromRuntime:   true,
				FromScript:    rtDefProp.Script != nil,
			}
			effSchemaForFmt = &synth
		}
		formatted, status, errT, errR := formatUnifiedFieldSliceR61Search(fieldName, requestedPattern, rawRTVals, format, isDocvalue, effSchemaForFmt)
		if status != 0 {
			return status, errT, errR
		}
		if len(formatted) > 0 {
			out[fieldName] = formatted
		}
		return 0, "", ""
	}

	// Whole `flattened` field (`fields: ["flattened"]` or `fields: ["flat*"]`)
	if hasBinding && esType == "flattened" {
		if isDocvalue {
			// `docvalue_fields` on whole `flattened` returns sorted leaf string values
			rawObj, ok := lookupNestedMapPathR61Search(doc, effectiveSourceSegsR61Search(fieldName, b))
			if !ok || rawObj == nil {
				return 0, "", ""
			}
			leaves := collectAllFlattenedScalarStringsR61Search(rawObj)
			if len(leaves) > 0 {
				out[fieldName] = leaves
			}
			return 0, "", ""
		}
		rawObj, ok := lookupNestedMapPathR61Search(doc, effectiveSourceSegsR61Search(fieldName, b))
		if !ok || rawObj == nil {
			return 0, "", ""
		}
		switch tv := rawObj.(type) {
		case map[string]any:
			if len(tv) > 0 {
				out[fieldName] = []any{tv}
			}
		case []any:
			var maps []any
			for _, elem := range tv {
				if m, okM := elem.(map[string]any); okM && len(m) > 0 {
					maps = append(maps, m)
				}
			}
			if len(maps) > 0 {
				out[fieldName] = maps
			}
		}
		return 0, "", ""
	}

	// `constant_keyword`: emits `[b.ConstantValue]` even when absent in `_source`!
	if hasBinding && esType == "constant_keyword" && b.HasConstantValue && b.ConstantValue != nil {
		out[fieldName] = []any{b.ConstantValue}
		return 0, "", ""
	}

	// Nested subfield handling (`fields` groups under `out[nestedRoot]` as per-element object maps; `docvalue_fields` flattens to `out[fieldName]`)
	if hasBinding && !isDocvalue {
		if nestedRoot, relField, okNested := resolveNestedFetchFieldR61Search(idxSchema, fieldName, b); okNested {
			return mergeNestedFieldIntoUnifiedOutR61Search(doc, nestedRoot, relField, fieldName, requestedPattern, format, idxSchema, out)
		}
	}

	// `geo_point` / `point` / `geo_shape` / `shape` structured or WKT formatting
	if hasBinding && (esType == "geo_point" || esType == "point" || esType == "geo_shape" || esType == "shape") {
		geoVals, status, errT, errR := extractFormattedSpatialFieldValuesR61Search(doc, fieldName, requestedPattern, b, format, isDocvalue)
		if status != 0 {
			return status, errT, errR
		}
		if len(geoVals) > 0 {
			out[fieldName] = geoVals
		}
		return 0, "", ""
	}

	if hasBinding {
		if rjVals, rjHandled, rjSt, rjErrT, rjErrR := extractRangeOrJoinFieldObjectsR62Search(doc, fieldName, b, esType, format, isDocvalue); rjHandled {
			if rjSt != 0 {
				return rjSt, rjErrT, rjErrR
			}
			if len(rjVals) > 0 {
				out[fieldName] = rjVals
			}
			return 0, "", ""
		}
	}

	// `token_count` multi-field or standalone field (`330_fetch_fields.yml:750-785`)
	if hasBinding && esType == "token_count" {
		segs := effectiveTokenCountSourceSegsR61Search(fieldName, b, idxSchema)
		rawVals := collectSchemaAwareScalarValues(doc, fieldName, segs, idxSchema)
		if len(rawVals) == 0 {
			return 0, "", ""
		}
		an := b.Analyzer
		if an == "" {
			an = "standard"
		}
		counts := make([]any, 0, len(rawVals))
		for _, rv := range rawVals {
			s := formatRawScalarStringR61Search(rv)
			toks := transpiler.TokenizeByAnalyzer(s, an)
			cnt := int64(len(toks))
			if format != "" {
				counts = append(counts, formatNumericWithDecimalPatternR61Search(float64(cnt), format))
			} else {
				counts = append(counts, cnt)
			}
		}
		if len(counts) > 0 {
			out[fieldName] = counts
		}
		return 0, "", ""
	}

	segs := effectiveSourceSegsR61Search(fieldName, b)
	rawVals := collectSchemaAwareScalarValues(doc, fieldName, segs, idxSchema)
	fromIndexTimeScript := false
	if idxSchema != nil && idxSchema.RawMapping != nil {
		if rawProp, okP := lookupRawPropertyWithMultiFieldR61Search(idxSchema, fieldName); okP && rawProp.Script != nil {
			if calcMap := evalIndexTimeMappedFieldsForHitR62Search(idxSchema, doc); len(calcMap) > 0 {
				if cv, okC := calcMap[fieldName]; okC && len(cv) > 0 {
					rawVals = cv
					fromIndexTimeScript = true
				}
			}
		} else if len(rawVals) == 0 && hasMappedPropertyScriptsR62Search(idxSchema.RawMapping.Properties) {
			if calcMap := evalIndexTimeMappedFieldsForHitR62Search(idxSchema, doc); len(calcMap) > 0 {
				if cv, okC := calcMap[fieldName]; okC && len(cv) > 0 {
					rawVals = cv
					fromIndexTimeScript = true
				}
			}
		}
	}
	if len(rawVals) == 0 {
		return 0, "", ""
	}
	if fromIndexTimeScript && !isDocvalue && format == "" && esType != "date" && esType != "date_nanos" && esType != "geo_point" && esType != "point" {
		// Index-time mapped `script` fields preserve script emission order on `fields` fetch (`13_keyword_calculated_at_index.yml`, `23_long_calculated_at_index.yml`)!
		out[fieldName] = append([]any(nil), rawVals...)
		return 0, "", ""
	}
	formatted, status, errT, errR := formatUnifiedFieldSliceR61Search(fieldName, requestedPattern, rawVals, format, isDocvalue, idxSchema)
	if status != 0 {
		return status, errT, errR
	}
	if isDocvalue && esType == "date" && strings.EqualFold(strings.TrimSpace(format), "epoch_millis") &&
		h.SearchScope != nil && h.SearchScope.srv != nil && h.SearchScope.srv.hasExplicitTargetESVersion() {
		for i, fv := range formatted {
			if iv, ok := fv.(int64); ok {
				formatted[i] = strconv.FormatInt(iv, 10)
			}
		}
	}
	if isDocvalue && esType == "date_nanos" && strings.EqualFold(strings.TrimSpace(format), "epoch_millis") &&
		(h.SearchScope == nil || h.SearchScope.srv == nil || !h.SearchScope.srv.hasExplicitTargetESVersion()) {
		for i, fv := range formatted {
			if sv, ok := fv.(string); ok {
				intPart := strings.SplitN(sv, ".", 2)[0]
				if iv, errP := strconv.ParseInt(intPart, 10, 64); errP == nil {
					formatted[i] = iv
				}
			}
		}
	}
	if fromIndexTimeScript && isDocvalue && len(formatted) > 1 && (esType == "keyword" || esType == "ip" || esType == "boolean") {
		dedup := make([]any, 0, len(formatted))
		for i, fv := range formatted {
			if i == 0 || fmt.Sprintf("%v", fv) != fmt.Sprintf("%v", formatted[i-1]) {
				dedup = append(dedup, fv)
			}
		}
		formatted = dedup
	}
	if len(formatted) > 0 {
		out[fieldName] = formatted
	}
	return 0, "", ""
}

func effectiveSourceSegsR61Search(fieldName string, b schema.FieldBinding) []string {
	if len(b.SourceJSONPath) > 0 {
		return b.SourceJSONPath
	}
	target := fieldName
	if b.AliasTarget != "" {
		target = b.AliasTarget
	}
	clean := strings.TrimSuffix(strings.TrimSuffix(target, ".keyword"), ".ngram")
	// If multi-field like `owner.raw` where `owner` is in `SourceJSONPath` or parent property, strip multi-field suffix when parent is scalar.
	return strings.Split(clean, ".")
}

func effectiveTokenCountSourceSegsR61Search(fieldName string, b schema.FieldBinding, idxSchema *schema.IndexSchema) []string {
	if len(b.SourceJSONPath) > 0 {
		return b.SourceJSONPath
	}
	if idxSchema != nil && idxSchema.RawMapping != nil {
		if dotIdx := strings.LastIndexByte(fieldName, '.'); dotIdx > 0 {
			parent := fieldName[:dotIdx]
			sub := fieldName[dotIdx+1:]
			if pfp, ok := lookupRawPropertyWithMultiFieldR61Search(idxSchema, parent); ok {
				if _, isSub := pfp.Fields[sub]; isSub {
					return strings.Split(parent, ".")
				}
			}
		}
	}
	return strings.Split(fieldName, ".")
}

func resolveFlattenedSubkeyR61Search(idxSchema *schema.IndexSchema, fieldPath string) (string, string, bool) {
	if idxSchema == nil || !strings.Contains(fieldPath, ".") {
		return "", "", false
	}
	parts := strings.Split(fieldPath, ".")
	for i := len(parts) - 1; i >= 1; i-- {
		cand := strings.Join(parts[:i], ".")
		if b, ok := idxSchema.Fields[cand]; ok && strings.EqualFold(b.ESType, "flattened") {
			return cand, strings.Join(parts[i:], "."), true
		}
	}
	return "", "", false
}

func extractFlattenedSubkeyValuesR61Search(doc map[string]any, flatRoot, subKey string) []any {
	rawObj, ok := lookupNestedMapPathR61Search(doc, strings.Split(flatRoot, "."))
	if !ok || rawObj == nil {
		return nil
	}
	vals := collectScalarValuesAtPath(rawObj, strings.Split(subKey, "."))
	if len(vals) == 0 {
		return nil
	}
	out := make([]any, 0, len(vals))
	for _, v := range vals {
		if v == nil {
			continue
		}
		out = append(out, formatRawScalarStringR61Search(v))
	}
	if len(out) > 1 {
		sort.Slice(out, func(i, j int) bool {
			return fmt.Sprintf("%v", out[i]) < fmt.Sprintf("%v", out[j])
		})
	}
	return out
}

func collectAllFlattenedScalarStringsR61Search(node any) []any {
	var strs []string
	var walk func(cur any)
	walk = func(cur any) {
		switch tv := cur.(type) {
		case map[string]any:
			for _, v := range tv {
				walk(v)
			}
		case []any:
			for _, v := range tv {
				walk(v)
			}
		case nil:
		default:
			strs = append(strs, formatRawScalarStringR61Search(tv))
		}
	}
	walk(node)
	if len(strs) == 0 {
		return nil
	}
	sort.Strings(strs)
	out := make([]any, len(strs))
	for i, s := range strs {
		out[i] = s
	}
	return out
}

func resolveNestedFetchFieldR61Search(idxSchema *schema.IndexSchema, fieldName string, b schema.FieldBinding) (string, string, bool) {
	if idxSchema == nil || len(idxSchema.NestedRoots) == 0 {
		return "", "", false
	}
	parts := strings.Split(fieldName, ".")
	// Resolve outermost nested root so doubly-nested structures (`user` -> `address`) nest recursively inside `out[user]`.
	for i := 1; i < len(parts); i++ {
		cand := strings.Join(parts[:i], ".")
		if idxSchema.NestedRoots[cand] != "" {
			return cand, strings.Join(parts[i:], "."), true
		}
	}
	if b.Kind == schema.StorageNestedSubfield && b.NestedPath != "" {
		rel := strings.TrimPrefix(fieldName, b.NestedPath+".")
		if rel != fieldName && rel != "" {
			return b.NestedPath, rel, true
		}
	}
	return "", "", false
}

func mergeNestedFieldIntoUnifiedOutR61Search(
	doc map[string]any,
	nestedRoot string,
	relField string,
	fullFieldName string,
	requestedPattern string,
	format string,
	idxSchema *schema.IndexSchema,
	out map[string][]any,
) (int, string, string) {
	return mergeNestedFieldWithFullPrefixR63Search(doc, nestedRoot, nestedRoot, relField, fullFieldName, requestedPattern, format, idxSchema, out)
}

func mergeNestedFieldWithFullPrefixR63Search(
	doc map[string]any,
	localKey string,
	fullNestedPrefix string,
	relField string,
	fullFieldName string,
	requestedPattern string,
	format string,
	idxSchema *schema.IndexSchema,
	out map[string][]any,
) (int, string, string) {
	children := extractNestedChildMapsPreservingOffsetsR61Search(doc, localKey)
	if len(children) == 0 {
		return 0, "", ""
	}
	var b schema.FieldBinding
	if idxSchema != nil {
		b = idxSchema.ResolveField(fullFieldName)
	}
	esType := strings.ToLower(strings.TrimSpace(b.ESType))

	existing := out[localKey]
	if existing != nil && len(existing) != len(children) {
		existing = nil
	}
	if existing == nil {
		existing = make([]any, len(children))
		for i := range children {
			existing[i] = make(map[string]any)
		}
	}

	// Check if `relField` itself crosses a child nested root (`user.address` under `user`)
	subNestedRel := ""
	subLeafRel := ""
	if idxSchema != nil && len(idxSchema.NestedRoots) > 0 && strings.Contains(relField, ".") {
		rParts := strings.Split(relField, ".")
		for i := 1; i < len(rParts); i++ {
			candSub := strings.Join(rParts[:i], ".")
			if idxSchema.NestedRoots[fullNestedPrefix+"."+candSub] != "" {
				subNestedRel = candSub
				subLeafRel = strings.Join(rParts[i:], ".")
				break
			}
		}
	}

	anyPopulated := false
	for idx, ch := range children {
		if ch == nil {
			continue
		}
		if subNestedRel != "" {
			em, _ := existing[idx].(map[string]any)
			if em == nil {
				em = make(map[string]any)
				existing[idx] = em
			}
			subOut := make(map[string][]any, 1)
			if prevSub, okP := em[subNestedRel].([]any); okP {
				subOut[subNestedRel] = prevSub
			}
			st, errT, errR := mergeNestedFieldWithFullPrefixR63Search(
				ch,
				subNestedRel,
				fullNestedPrefix+"."+subNestedRel,
				subLeafRel,
				fullFieldName,
				requestedPattern,
				format,
				idxSchema,
				subOut,
			)
			if st != 0 {
				return st, errT, errR
			}
			if len(subOut[subNestedRel]) > 0 {
				em[subNestedRel] = subOut[subNestedRel]
				anyPopulated = true
			}
			continue
		}
		var formatted []any
		if esType == "token_count" {
			srcSegs := strings.Split(relField, ".")
			if dotIdx := strings.LastIndexByte(relField, '.'); dotIdx > 0 {
				srcSegs = strings.Split(relField[:dotIdx], ".")
			}
			rawVals := collectScalarValuesAtPath(ch, srcSegs)
			an := b.Analyzer
			if an == "" {
				an = "standard"
			}
			for _, rv := range rawVals {
				cnt := int64(len(transpiler.TokenizeByAnalyzer(formatRawScalarStringR61Search(rv), an)))
				if format != "" {
					formatted = append(formatted, formatNumericWithDecimalPatternR61Search(float64(cnt), format))
				} else {
					formatted = append(formatted, cnt)
				}
			}
		} else if esType == "constant_keyword" && b.HasConstantValue && b.ConstantValue != nil {
			formatted = []any{b.ConstantValue}
		} else {
			defaultRelSegs := strings.Split(strings.TrimSuffix(strings.TrimSuffix(relField, ".keyword"), ".ngram"), ".")
			relSegs := defaultRelSegs
			if len(b.RelativeJSONPath) > 0 {
				relSegs = b.RelativeJSONPath
			}
			rawVals := collectScalarValuesAtPathWithNull(ch, relSegs, b.NullValue)
			if len(rawVals) == 0 && len(b.RelativeJSONPath) > 0 {
				rawVals = collectScalarValuesAtPathWithNull(ch, defaultRelSegs, b.NullValue)
			}
			if len(rawVals) > 0 {
				var status int
				var errT, errR string
				formatted, status, errT, errR = formatUnifiedFieldSliceR61Search(fullFieldName, requestedPattern, rawVals, format, false, idxSchema)
				if status != 0 {
					return status, errT, errR
				}
			}
		}
		if len(formatted) > 0 {
			em, _ := existing[idx].(map[string]any)
			if em == nil {
				em = make(map[string]any)
				existing[idx] = em
			}
			em[relField] = formatted
			anyPopulated = true
		}
	}
	if !anyPopulated && out[localKey] == nil {
		return 0, "", ""
	}
	// Preserve `existing` slice indices when more subfields may still be merged; strip empty maps only if none populated?
	// Wait: if `out[localKey]` holds `existing` with `len(children)`, wait until final or filter empty maps?
	// Notice `existing != nil && len(existing) != len(children)` above reset `existing` when empty maps were stripped!
	// Let's keep `existing` aligned to `children` when all children are non-empty, or strip empty maps at return if needed:
	allNonEmpty := true
	for _, item := range existing {
		if em, ok := item.(map[string]any); !ok || len(em) == 0 {
			allNonEmpty = false
			break
		}
	}
	if allNonEmpty {
		out[localKey] = existing
		return 0, "", ""
	}
	nonEmpty := make([]any, 0, len(existing))
	for _, item := range existing {
		if em, ok := item.(map[string]any); ok && len(em) > 0 {
			nonEmpty = append(nonEmpty, em)
		}
	}
	if len(nonEmpty) > 0 {
		out[localKey] = nonEmpty
	}
	return 0, "", ""
}

func formatUnsupportedErrorMsgR61Search(fieldName, requestedPattern, esType string) string {
	if strings.ContainsAny(requestedPattern, "*?") && requestedPattern != fieldName {
		return fmt.Sprintf("error fetching [%s] which matched [%s]: Field [%s] of type [%s] doesn't support formats.", fieldName, requestedPattern, fieldName, esType)
	}
	return fmt.Sprintf("error fetching [%s]: Field [%s] of type [%s] doesn't support formats.", fieldName, fieldName, esType)
}

func validateFieldFetchFormatR61Search(fieldName, requestedPattern, esType, format string) (int, string, string) {
	fTrim := strings.TrimSpace(format)
	if fTrim == "" || strings.EqualFold(fTrim, "use_field_mapping") {
		return 0, "", ""
	}
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "date", "date_nanos", "date_range":
		if !isValidESDateFetchFormatR61Search(fTrim) {
			return http.StatusBadRequest,
				"illegal_argument_exception",
				fmt.Sprintf("Invalid format: [%s]: Illegal pattern component", fTrim)
		}
		return 0, "", ""
	case "byte", "short", "integer", "long", "unsigned_long",
		"half_float", "float", "double", "scaled_float",
		"integer_range", "long_range", "float_range", "double_range",
		"token_count", "murmur3", "aggregate_metric_double":
		if !isValidESDecimalFetchFormatR61Search(fTrim) {
			return http.StatusBadRequest,
				"illegal_argument_exception",
				fmt.Sprintf("Malformed numeric format [%s] for field [%s]", fTrim, fieldName)
		}
		return 0, "", ""
	case "geo_point", "geo_shape", "point", "shape":
		switch strings.ToLower(fTrim) {
		case "geojson", "wkt":
			return 0, "", ""
		default:
			return http.StatusBadRequest,
				"illegal_argument_exception",
				fmt.Sprintf("Invalid format [%s] for [%s]: only [geojson] and [wkt] are supported", fTrim, fieldName)
		}
	default:
		return http.StatusBadRequest,
			"illegal_argument_exception",
			formatUnsupportedErrorMsgR61Search(fieldName, requestedPattern, esType)
	}
}

var validNamedESDateFormatsR61Search = map[string]bool{
	"epoch_millis":                             true,
	"epoch_second":                             true,
	"epoch_nanos":                              true,
	"iso8601":                                  true,
	"date_optional_time":                       true,
	"strict_date_optional_time":                true,
	"strict_date_optional_time_nanos":          true,
	"date_optional_time_nanos":                 true,
	"basic_date":                               true,
	"basic_date_time":                          true,
	"basic_date_time_no_millis":                true,
	"basic_ordinal_date":                       true,
	"basic_ordinal_date_time":                  true,
	"basic_ordinal_date_time_no_millis":        true,
	"basic_time":                               true,
	"basic_time_no_millis":                     true,
	"basic_t_time":                             true,
	"basic_t_time_no_millis":                   true,
	"basic_week_date":                          true,
	"strict_basic_week_date":                   true,
	"basic_week_date_time":                     true,
	"strict_basic_week_date_time":              true,
	"basic_week_date_time_no_millis":           true,
	"strict_basic_week_date_time_no_millis":    true,
	"date":                                     true,
	"strict_date":                              true,
	"date_hour":                                true,
	"strict_date_hour":                         true,
	"date_hour_minute":                         true,
	"strict_date_hour_minute":                  true,
	"date_hour_minute_second":                  true,
	"strict_date_hour_minute_second":           true,
	"date_hour_minute_second_fraction":         true,
	"strict_date_hour_minute_second_fraction":  true,
	"date_hour_minute_second_millis":           true,
	"strict_date_hour_minute_second_millis":    true,
	"date_time":                                true,
	"strict_date_time":                         true,
	"date_time_no_millis":                      true,
	"strict_date_time_no_millis":               true,
	"hour":                                     true,
	"strict_hour":                              true,
	"hour_minute":                              true,
	"strict_hour_minute":                       true,
	"hour_minute_second":                       true,
	"strict_hour_minute_second":                true,
	"hour_minute_second_fraction":              true,
	"strict_hour_minute_second_fraction":       true,
	"hour_minute_second_millis":                true,
	"strict_hour_minute_second_millis":         true,
	"ordinal_date":                             true,
	"strict_ordinal_date":                      true,
	"ordinal_date_time":                        true,
	"strict_ordinal_date_time":                 true,
	"ordinal_date_time_no_millis":              true,
	"strict_ordinal_date_time_no_millis":       true,
	"time":                                     true,
	"strict_time":                              true,
	"time_no_millis":                           true,
	"strict_time_no_millis":                    true,
	"t_time":                                   true,
	"strict_t_time":                            true,
	"t_time_no_millis":                         true,
	"strict_t_time_no_millis":                  true,
	"week_date":                                true,
	"strict_week_date":                         true,
	"week_date_time":                           true,
	"strict_week_date_time":                    true,
	"week_date_time_no_millis":                 true,
	"strict_week_date_time_no_millis":          true,
	"weekyear":                                 true,
	"strict_weekyear":                          true,
	"weekyear_week":                            true,
	"strict_weekyear_week":                     true,
	"weekyear_week_day":                        true,
	"strict_weekyear_week_day":                 true,
	"year":                                     true,
	"strict_year":                              true,
	"year_month":                               true,
	"strict_year_month":                        true,
	"year_month_day":                           true,
	"strict_year_month_day":                    true,
	"rfc1123":                                  true,
	"rfc822":                                   true,
	"strict_basic_date":                        true,
	"strict_basic_date_time":                   true,
	"strict_basic_date_time_no_millis":         true,
	"strict_basic_ordinal_date":                true,
	"strict_basic_ordinal_date_time":           true,
	"strict_basic_ordinal_date_time_no_millis": true,
	"strict_basic_time":                        true,
	"strict_basic_time_no_millis":              true,
}

func isValidESDateFetchFormatR61Search(format string) bool {
	parts := strings.Split(format, "||")
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p == "" {
			return false
		}
		if validNamedESDateFormatsR61Search[strings.ToLower(p)] {
			continue
		}
		// Validate Java DateTimeFormatter pattern characters and balanced quotes.
		inQuote := false
		hasToken := false
		for i := 0; i < len(p); i++ {
			ch := p[i]
			if ch == '\'' {
				if i+1 < len(p) && p[i+1] == '\'' {
					i++
					continue
				}
				inQuote = !inQuote
				continue
			}
			if inQuote {
				continue
			}
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				switch ch {
				case 'G', 'u', 'y', 'Y', 'Q', 'q', 'M', 'L', 'w', 'W', 'd', 'D', 'F', 'g',
					'E', 'e', 'c', 'a', 'h', 'H', 'k', 'K', 'm', 's', 'S', 'A', 'n', 'N',
					'V', 'z', 'O', 'X', 'x', 'Z', 'p', 'T':
					hasToken = true
				default:
					return false
				}
			}
		}
		if inQuote || !hasToken {
			return false
		}
	}
	return true
}

func isValidESDecimalFetchFormatR61Search(format string) bool {
	subPatterns := strings.Split(format, ";")
	if len(subPatterns) > 2 {
		return false
	}
	for _, sp := range subPatterns {
		p := strings.TrimSpace(sp)
		if p == "" {
			return false
		}
		inQuote := false
		dotCount := 0
		hasDigitPlaceholder := false
		for _, ch := range p {
			if ch == '\'' {
				inQuote = !inQuote
				continue
			}
			if inQuote {
				continue
			}
			switch ch {
			case '0', '#':
				hasDigitPlaceholder = true
			case '.':
				dotCount++
				if dotCount > 1 {
					return false
				}
			case ',', '-', '+', '%', 'E', '\u2030', '\u00a4', ' ':
			default:
				// Reject invalid unquoted format syntax such as multiple random symbols
				if ch == '[' || ch == ']' || ch == '{' || ch == '}' {
					return false
				}
			}
		}
		if inQuote || !hasDigitPlaceholder {
			return false
		}
	}
	return true
}

func formatNumericWithDecimalPatternR61Search(val float64, pattern string) string {
	p := strings.TrimSpace(strings.Split(pattern, ";")[0])
	isPercent := strings.Contains(p, "%")
	if isPercent {
		val *= 100.0
	}
	decimals := 0
	minIntDigits := 0
	if dotIdx := strings.IndexByte(p, '.'); dotIdx >= 0 {
		intPart := p[:dotIdx]
		fracPart := p[dotIdx+1:]
		for i := 0; i < len(intPart); i++ {
			if intPart[i] == '0' {
				minIntDigits++
			}
		}
		maxFrac := 0
		minFrac := 0
		for i := 0; i < len(fracPart); i++ {
			switch fracPart[i] {
			case '0':
				minFrac++
				maxFrac++
			case '#':
				maxFrac++
			}
		}
		decimals = maxFrac
		s := fmt.Sprintf("%.*f", decimals, val)
		if maxFrac > minFrac && strings.Contains(s, ".") {
			for len(s) > 0 && s[len(s)-1] == '0' {
				dotPos := strings.IndexByte(s, '.')
				if len(s)-1-dotPos <= minFrac {
					break
				}
				s = s[:len(s)-1]
			}
			s = strings.TrimSuffix(s, ".")
		}
		if minIntDigits > 1 {
			neg := strings.HasPrefix(s, "-")
			unsigned := strings.TrimPrefix(s, "-")
			curIntLen := len(unsigned)
			if dp := strings.IndexByte(unsigned, '.'); dp >= 0 {
				curIntLen = dp
			}
			if curIntLen < minIntDigits {
				pad := strings.Repeat("0", minIntDigits-curIntLen)
				if neg {
					s = "-" + pad + unsigned
				} else {
					s = pad + unsigned
				}
			}
		}
		if isPercent {
			s += "%"
		}
		return s
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '0' {
			minIntDigits++
		}
	}
	rounded := int64(math.Round(val))
	var s string
	if minIntDigits > 1 {
		if rounded < 0 {
			s = fmt.Sprintf("-%0*d", minIntDigits, -rounded)
		} else {
			s = fmt.Sprintf("%0*d", minIntDigits, rounded)
		}
	} else {
		s = strconv.FormatInt(rounded, 10)
	}
	if isPercent {
		s += "%"
	}
	return s
}

func extractFormattedSpatialFieldValuesR61Search(
	doc map[string]any,
	fieldName string,
	requestedPattern string,
	b schema.FieldBinding,
	format string,
	isDocvalue bool,
) ([]any, int, string, string) {
	esType := strings.ToLower(strings.TrimSpace(b.ESType))
	fLower := strings.ToLower(strings.TrimSpace(format))
	if fLower == "use_field_mapping" {
		fLower = ""
	}
	if fLower != "" && fLower != "geojson" && fLower != "wkt" {
		return nil, http.StatusBadRequest, "illegal_argument_exception", formatUnsupportedErrorMsgR61Search(fieldName, requestedPattern, esType)
	}
	segs := effectiveSourceSegsR61Search(fieldName, b)
	rawNode, exists := lookupNestedMapPathR61Search(doc, segs)
	if !exists || rawNode == nil {
		return nil, 0, "", ""
	}
	if esType == "geo_point" || esType == "point" {
		pts := extractGeoPointsFromRawNodeR61Search(rawNode)
		if len(pts) == 0 {
			return nil, 0, "", ""
		}
		out := make([]any, 0, len(pts))
		for _, pt := range pts {
			if fLower == "wkt" || (isDocvalue && fLower == "") {
				if isDocvalue && fLower == "" {
					out = append(out, fmt.Sprintf("POINT (%s %s)", formatShortestFloatR61Search(pt[0]), formatShortestFloatR61Search(pt[1])))
				} else {
					out = append(out, fmt.Sprintf("POINT (%s %s)", formatShortestFloatR61Search(pt[0]), formatShortestFloatR61Search(pt[1])))
				}
			} else {
				out = append(out, map[string]any{
					"type":        "Point",
					"coordinates": []float64{pt[0], pt[1]},
				})
			}
		}
		return out, 0, "", ""
	}
	// `geo_shape` / `shape`
	wantWKT := fLower == "wkt"
	if arr, ok := rawNode.([]any); ok {
		conv := make([]any, 0, len(arr))
		for _, el := range arr {
			conv = append(conv, convertSpatialWKTAndGeoJSONR63(el, wantWKT))
		}
		return conv, 0, "", ""
	}
	return []any{convertSpatialWKTAndGeoJSONR63(rawNode, wantWKT)}, 0, "", ""
}

func extractGeoPointsFromRawNodeR61Search(raw any) [][2]float64 {
	if raw == nil {
		return nil
	}
	// Check `[lon, lat]` numeric array first!
	if arr, isArr := raw.([]any); isArr {
		if len(arr) == 2 {
			lon, okLon := parseFiniteFloatFromAnyR61Search(arr[0], true)
			lat, okLat := parseFiniteFloatFromAnyR61Search(arr[1], true)
			if okLon && okLat {
				return [][2]float64{{lon, lat}}
			}
		}
		var out [][2]float64
		for _, elem := range arr {
			out = append(out, extractGeoPointsFromRawNodeR61Search(elem)...)
		}
		return out
	}
	lat, lon, err := esast.ParseGeoPoint(raw)
	if err == nil {
		return [][2]float64{{lon, lat}}
	}
	return nil
}

func formatShortestFloatR61Search(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func formatUnifiedFieldSliceR61Search(
	fieldName string,
	requestedPattern string,
	vals []any,
	format string,
	isDocvalue bool,
	idxSchema *schema.IndexSchema,
) ([]any, int, string, string) {
	var b schema.FieldBinding
	hasBinding := false
	if idxSchema != nil {
		if db, ok := idxSchema.Fields[fieldName]; ok {
			b = db
			hasBinding = true
			if b.AliasTarget != "" {
				if tb, okT := idxSchema.Fields[b.AliasTarget]; okT {
					b = tb
				}
			}
		} else if fp, okRaw := lookupRawPropertyWithMultiFieldR61Search(idxSchema, fieldName); okRaw {
			b = schema.FieldBinding{
				ESFieldPath:         fieldName,
				ESType:              strings.ToLower(strings.TrimSpace(fp.Type)),
				Format:              fp.Format,
				LowercaseNormalizer: strings.EqualFold(fp.Normalizer, "lowercase"),
				IgnoreAbove:         fp.IgnoreAbove,
				IgnoreMalformed:     fp.IgnoreMalformed,
				Coerce:              fp.Coerce,
				ScalingFactor:       fp.ScalingFactor,
			}
			hasBinding = true
		}
	}

	esType := strings.ToLower(strings.TrimSpace(b.ESType))
	if esType == "" && strings.TrimSuffix(fieldName, ".keyword") == "@timestamp" {
		esType = "date"
	}
	wasUseFieldMapping := strings.EqualFold(strings.TrimSpace(format), "use_field_mapping")
	if wasUseFieldMapping {
		format = ""
	}
	if format != "" && esType != "" {
		if status, errT, errR := validateFieldFetchFormatR61Search(fieldName, requestedPattern, esType, format); status != 0 {
			return nil, status, errT, errR
		}
	}
	effDateFormat := format
	if effDateFormat == "" && strings.TrimSpace(b.Format) != "" {
		firstMappedFmt := strings.ToLower(strings.TrimSpace(strings.Split(b.Format, "||")[0]))
		if wasUseFieldMapping || (firstMappedFmt != "epoch_millis" && firstMappedFmt != "epoch_second" && firstMappedFmt != "epoch_nanos") {
			effDateFormat = b.Format
		}
	}

	ignoreMalformed := hasBinding && b.IgnoreMalformed != nil && *b.IgnoreMalformed
	coerce := !hasBinding || b.EffectiveCoerceBool()
	out := make([]any, 0, len(vals))

	for _, rawV := range vals {
		if rawV == nil {
			continue
		}
		if hasBinding && b.IgnoreAbove > 0 {
			if s, ok := rawV.(string); ok && utf8.RuneCountInString(s) > b.IgnoreAbove {
				continue
			}
		}

		switch esType {
		case "date_nanos":
			ns, ok := parseEpochNanosExactR61Search(rawV, b.Format)
			if !ok {
				if ignoreMalformed {
					continue
				}
				continue
			}
			out = append(out, formatDateNanosExactR61Search(ns, effDateFormat))

		case "date":
			ms, ok := parseEpochMillisExactR61Search(rawV, b.Format)
			if !ok {
				if ignoreMalformed {
					continue
				}
				continue
			}
			out = append(out, formatDateMillisExactR61Search(ms, effDateFormat))

		case "long":
			iv, ok := parseExactInt64R61Search(rawV, coerce)
			if !ok {
				if ignoreMalformed {
					continue
				}
				continue
			}
			if format != "" {
				out = append(out, formatNumericWithDecimalPatternR61Search(float64(iv), format))
			} else {
				out = append(out, iv)
			}

		case "unsigned_long":
			uVal, asInt64, ok := parseExactUint64R61Search(rawV, coerce)
			if !ok {
				if ignoreMalformed {
					continue
				}
				continue
			}
			if format != "" {
				out = append(out, formatNumericWithDecimalPatternR61Search(float64(uVal), format))
			} else if asInt64 {
				out = append(out, int64(uVal)) // #nosec G115 -- asInt64 guarantees uVal <= math.MaxInt64
			} else {
				out = append(out, uVal)
			}

		case "integer", "short", "byte":
			iv, ok := parseExactInt64R61Search(rawV, coerce)
			if !ok {
				if ignoreMalformed {
					continue
				}
				continue
			}
			switch esType {
			case "byte":
				if iv < math.MinInt8 || iv > math.MaxInt8 {
					if ignoreMalformed {
						continue
					}
				}
			case "short":
				if iv < math.MinInt16 || iv > math.MaxInt16 {
					if ignoreMalformed {
						continue
					}
				}
			case "integer":
				if iv < math.MinInt32 || iv > math.MaxInt32 {
					if ignoreMalformed {
						continue
					}
				}
			}
			if format != "" {
				out = append(out, formatNumericWithDecimalPatternR61Search(float64(iv), format))
			} else {
				out = append(out, iv)
			}

		case "float":
			fv, ok := parseFiniteFloatFromAnyR61Search(rawV, coerce)
			if !ok {
				if ignoreMalformed {
					continue
				}
				continue
			}
			f32 := float32(fv)
			if math.IsInf(float64(f32), 0) || math.IsNaN(float64(f32)) {
				continue
			}
			rounded, _ := strconv.ParseFloat(strconv.FormatFloat(float64(f32), 'g', -1, 32), 64)
			if format != "" {
				out = append(out, formatNumericWithDecimalPatternR61Search(rounded, format))
			} else {
				out = append(out, rounded)
			}

		case "half_float":
			fv, ok := parseFiniteFloatFromAnyR61Search(rawV, coerce)
			if !ok {
				if ignoreMalformed {
					continue
				}
				continue
			}
			hf := painless.QuantizeHalfFloat(fv)
			if math.IsInf(float64(hf), 0) || math.IsNaN(float64(hf)) {
				continue
			}
			rounded, _ := strconv.ParseFloat(strconv.FormatFloat(float64(hf), 'g', -1, 32), 64)
			if format != "" {
				out = append(out, formatNumericWithDecimalPatternR61Search(rounded, format))
			} else {
				out = append(out, rounded)
			}

		case "scaled_float":
			fv, ok := parseFiniteFloatFromAnyR61Search(rawV, coerce)
			if !ok {
				if ignoreMalformed {
					continue
				}
				continue
			}
			if b.ScalingFactor > 0 {
				fv = math.Round(fv*b.ScalingFactor) / b.ScalingFactor
			}
			if format != "" {
				out = append(out, formatNumericWithDecimalPatternR61Search(fv, format))
			} else {
				out = append(out, fv)
			}

		case "double":
			fv, ok := parseFiniteFloatFromAnyR61Search(rawV, coerce)
			if !ok {
				if ignoreMalformed {
					continue
				}
				continue
			}
			if format != "" {
				out = append(out, formatNumericWithDecimalPatternR61Search(fv, format))
			} else {
				out = append(out, fv)
			}

		case "boolean":
			bv, ok := parseStrictESBoolR61Search(rawV)
			if !ok {
				if ignoreMalformed {
					continue
				}
				continue
			}
			out = append(out, bv)

		case "ip":
			ipStr := strings.TrimSpace(formatRawScalarStringR61Search(rawV))
			addr, err := netip.ParseAddr(ipStr)
			if err != nil {
				if ignoreMalformed {
					continue
				}
				continue
			}
			out = append(out, addr.Unmap().String())

		case "version", "keyword", "wildcard":
			s := formatRawScalarStringR61Search(rawV)
			if hasBinding && b.EffectiveLowercase(strings.HasSuffix(fieldName, ".keyword")) {
				s = strings.ToLower(s)
			}
			out = append(out, s)

		default:
			if jn, ok := rawV.(json.Number); ok {
				s := jn.String()
				if !strings.ContainsAny(s, ".eE") {
					if iv, err := jn.Int64(); err == nil {
						out = append(out, iv)
						continue
					}
					if uv, err := strconv.ParseUint(s, 10, 64); err == nil {
						out = append(out, uv)
						continue
					}
				}
				if fv, err := jn.Float64(); err == nil {
					out = append(out, fv)
					continue
				}
			}
			out = append(out, rawV)
		}
	}

	// Sort scalar multi-values in `fields` / `docvalue_fields` for doc_values-backed scalar types when > 1 value
	// (matching ES doc_values ordinal/numeric ordering in `330_fetch_fields.yml`!).
	if len(out) > 1 && shouldSortFetchedFieldValuesR61Search(esType, isDocvalue) {
		sortFetchedScalarSliceR61Search(out)
	}
	return out, 0, "", ""
}

func shouldSortFetchedFieldValuesR61Search(esType string, isDocvalue bool) bool {
	if isDocvalue {
		return true
	}
	switch esType {
	case "byte", "short", "integer", "long", "unsigned_long",
		"half_float", "float", "double", "scaled_float",
		"boolean", "keyword", "wildcard":
		return true
	default:
		return false
	}
}

func sortFetchedScalarSliceR61Search(vals []any) {
	sort.SliceStable(vals, func(i, j int) bool {
		switch ai := vals[i].(type) {
		case int64:
			if aj, ok := vals[j].(int64); ok {
				return ai < aj
			}
		case uint64:
			if aj, ok := vals[j].(uint64); ok {
				return ai < aj
			}
		case float64:
			if aj, ok := vals[j].(float64); ok {
				return ai < aj
			}
		case bool:
			if aj, ok := vals[j].(bool); ok {
				return !ai && aj
			}
		case string:
			if aj, ok := vals[j].(string); ok {
				return ai < aj
			}
		}
		return fmt.Sprintf("%v", vals[i]) < fmt.Sprintf("%v", vals[j])
	})
}

func parseExactInt64R61Search(v any, coerce bool) (int64, bool) {
	switch tv := v.(type) {
	case int:
		return int64(tv), true
	case int64:
		return tv, true
	case uint64:
		if tv <= math.MaxInt64 {
			return int64(tv), true
		}
		return 0, false
	case json.Number:
		s := strings.TrimSpace(tv.String())
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return iv, true
		}
		if !coerce {
			return 0, false
		}
		if fv, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			if fv >= -9223372036854775808.0 && fv < 9223372036854775808.0 {
				return int64(math.Trunc(fv)), true
			}
		}
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return 0, false
		}
		if !coerce && tv != math.Trunc(tv) {
			return 0, false
		}
		if tv >= -9223372036854775808.0 && tv < 9223372036854775808.0 {
			return int64(math.Trunc(tv)), true
		}
	case string:
		if !coerce {
			return 0, false
		}
		s := strings.TrimSpace(tv)
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return iv, true
		}
		if fv, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			if fv >= -9223372036854775808.0 && fv < 9223372036854775808.0 {
				return int64(math.Trunc(fv)), true
			}
		}
	}
	return 0, false
}

func parseExactUint64R61Search(v any, coerce bool) (uint64, bool, bool) {
	switch tv := v.(type) {
	case uint64:
		return tv, tv <= math.MaxInt64, true
	case int:
		if tv < 0 {
			return 0, false, false
		}
		u := uint64(tv)
		return u, true, true
	case int64:
		if tv < 0 {
			return 0, false, false
		}
		u := uint64(tv)
		return u, true, true
	case json.Number:
		s := strings.TrimSpace(tv.String())
		if uv, err := strconv.ParseUint(s, 10, 64); err == nil {
			return uv, uv <= math.MaxInt64, true
		}
		if coerce {
			if fv, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv >= 0 && fv < 18446744073709551616.0 {
				uv := uint64(math.Trunc(fv))
				return uv, uv <= math.MaxInt64, true
			}
		}
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) || tv < 0 || tv >= 18446744073709551616.0 {
			return 0, false, false
		}
		if !coerce && tv != math.Trunc(tv) {
			return 0, false, false
		}
		uv := uint64(math.Trunc(tv))
		return uv, uv <= math.MaxInt64, true
	case string:
		if !coerce {
			return 0, false, false
		}
		s := strings.TrimSpace(tv)
		if uv, err := strconv.ParseUint(s, 10, 64); err == nil {
			return uv, uv <= math.MaxInt64, true
		}
	}
	return 0, false, false
}

func parseFiniteFloatFromAnyR61Search(v any, coerce bool) (float64, bool) {
	switch tv := v.(type) {
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return 0, false
		}
		return tv, true
	case float32:
		f := float64(tv)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	case int:
		return float64(tv), true
	case int64:
		return float64(tv), true
	case uint64:
		return float64(tv), true
	case json.Number:
		f, err := tv.Float64()
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	case string:
		if !coerce {
			return 0, false
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(tv), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func parseStrictESBoolR61Search(v any) (bool, bool) {
	switch tv := v.(type) {
	case bool:
		return tv, true
	case string:
		switch strings.ToLower(strings.TrimSpace(tv)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func parseEpochNanosExactR61Search(v any, mappedFormat string) (int64, bool) {
	fmtLower := strings.ToLower(strings.TrimSpace(mappedFormat))
	isExplicitNanos := strings.Contains(fmtLower, "epoch_nanos")
	isExplicitSeconds := strings.Contains(fmtLower, "epoch_second") && !strings.Contains(fmtLower, "epoch_millis") && !isExplicitNanos

	scaleInt := func(iv int64) int64 {
		if isExplicitNanos {
			return iv
		}
		if isExplicitSeconds && iv > -1e11 && iv < 1e11 {
			return iv * 1_000_000_000
		}
		// Heuristic matching ES default `strict_date_optional_time_nanos||epoch_millis`:
		// epoch_millis is ~1.7e12; epoch_nanos is ~1.7e18 (`|iv| >= 1e15` -> already nanos; otherwise millis -> *1_000_000).
		if iv >= 1_000_000_000_000_000 || iv <= -1_000_000_000_000_000 {
			return iv
		}
		return iv * 1_000_000
	}

	switch tv := v.(type) {
	case int64:
		return scaleInt(tv), true
	case int:
		return scaleInt(int64(tv)), true
	case json.Number:
		s := strings.TrimSpace(tv.String())
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return scaleInt(iv), true
		}
		return schema.ParseESDateWithFormatToEpochNanos(s, mappedFormat, time.Now().UTC())
	case string:
		s := strings.TrimSpace(tv)
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			if isExplicitNanos || iv >= 1_000_000_000_000_000 || iv <= -1_000_000_000_000_000 {
				return scaleInt(iv), true
			}
		}
		return schema.ParseESDateWithFormatToEpochNanos(s, mappedFormat, time.Now().UTC())
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return 0, false
		}
		return scaleInt(int64(tv)), true
	}
	return 0, false
}

func formatDateNanosExactR61Search(ns int64, requestedFormat string) any {
	eff := strings.TrimSpace(strings.Split(requestedFormat, "||")[0])
	switch strings.ToLower(eff) {
	case "", "strict_date_optional_time_nanos", "date_optional_time_nanos":
		return epochNanosToUTCTimeRound58(ns).Format("2006-01-02T15:04:05.000000000Z")
	case "epoch_nanos":
		return ns
	case "epoch_millis":
		ms := ns / 1_000_000
		rem := ns % 1_000_000
		if rem < 0 {
			ms--
			rem += 1_000_000
		}
		if rem != 0 {
			return fmt.Sprintf("%d.%06d", ms, rem)
		}
		return strconv.FormatInt(ms, 10)
	case "epoch_second":
		sec := ns / 1_000_000_000
		if ns < 0 && ns%1_000_000_000 != 0 {
			sec--
		}
		return sec
	case "strict_date_optional_time", "date_optional_time", "date_time", "strict_date_time", "iso8601":
		return epochNanosToUTCTimeRound58(ns).Format("2006-01-02T15:04:05.000Z")
	default:
		if ns == 0 {
			tm := time.Unix(0, 0).UTC()
			if strings.Contains(eff, "SSSSSSSSS") || strings.Contains(eff, "nnnnnnnnn") {
				return transpiler.FormatESDateWithNamedOrJavaPattern(0, 0, strings.ReplaceAll(eff, "SSSSSSSSS", "000000000"), time.UTC)
			}
			_ = tm
		}
		return transpiler.FormatESDateWithNamedOrJavaPattern(0, ns, eff, time.UTC)
	}
}

func parseEpochMillisExactR61Search(v any, mappedFormat string) (int64, bool) {
	fmtLower := strings.ToLower(strings.TrimSpace(mappedFormat))
	isExplicitSeconds := strings.Contains(fmtLower, "epoch_second") && !strings.Contains(fmtLower, "epoch_millis")
	switch tv := v.(type) {
	case int64:
		if isExplicitSeconds {
			return tv * 1000, true
		}
		return tv, true
	case int:
		if isExplicitSeconds {
			return int64(tv) * 1000, true
		}
		return int64(tv), true
	case json.Number:
		s := strings.TrimSpace(tv.String())
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			if isExplicitSeconds {
				return iv * 1000, true
			}
			return iv, true
		}
		return schema.ParseESDateWithFormatToEpochMillis(s, mappedFormat, time.Now().UTC())
	case string:
		return schema.ParseESDateWithFormatToEpochMillis(strings.TrimSpace(tv), mappedFormat, time.Now().UTC())
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return 0, false
		}
		if isExplicitSeconds {
			return int64(math.Round(tv * 1000.0)), true
		}
		return int64(tv), true
	}
	return 0, false
}

func formatDateMillisExactR61Search(ms int64, requestedFormat string) any {
	eff := strings.TrimSpace(strings.Split(requestedFormat, "||")[0])
	switch strings.ToLower(eff) {
	case "", "strict_date_optional_time", "date_optional_time", "strict_date_optional_time_nanos", "date_optional_time_nanos":
		return epochNanosToUTCTimeRound58(ms * 1_000_000).Format("2006-01-02T15:04:05.000Z")
	case "epoch_millis":
		return ms
	case "epoch_nanos":
		return ms * 1_000_000
	case "epoch_second":
		sec := ms / 1000
		if ms < 0 && ms%1000 != 0 {
			sec--
		}
		return sec
	default:
		return transpiler.FormatESDateWithNamedOrJavaPattern(ms, 0, eff, time.UTC)
	}
}

func formatRawScalarStringR61Search(v any) string {
	switch tv := v.(type) {
	case string:
		return tv
	case json.Number:
		return tv.String()
	case float64:
		if tv == math.Trunc(tv) && math.Abs(tv) < 1e16 {
			return strconv.FormatInt(int64(tv), 10)
		}
		return strconv.FormatFloat(tv, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func flattenAnyToSliceR61Search(v any) []any {
	if v == nil {
		return nil
	}
	if arr, ok := v.([]any); ok {
		var out []any
		for _, elem := range arr {
			out = append(out, flattenAnyToSliceR61Search(elem)...)
		}
		return out
	}
	return []any{v}
}

// ============================================================================
// F15 & F16: Exact Quantiles (`__raw_vals__`), Pipeline `buckets_path` Guards,
// `moving_fn`, `typed_keys` Normalization, Nested `top_hits` & Deprecation Warnings
// ============================================================================

// stripAndApplyExactQuantilesR61Search separates internal `__raw_vals__` companion rows from `aggRows`
// so they never leak into user-visible aggregations, and overwrites top-level and nested bucket sub-aggregations
// in `builtAggs` for `percentiles`, `percentile_ranks`, `boxplot`, and `median_absolute_deviation`.
func stripAndApplyExactQuantilesR61Search(
	aggRows []AggRow,
	aggs map[string]esast.AggSpec,
	builtAggs map[string]any,
	isES8 bool,
) ([]AggRow, error) {
	if len(aggRows) == 0 {
		return aggRows, nil
	}
	filtered := make([]AggRow, 0, len(aggRows))
	// rawByAggAndBucket[aggPath][parentBucketKey] = merged []float64 across shards/indices
	rawByAggAndBucket := make(map[string]map[string][]float64)
	rawBucketSeen := make(map[string]map[string]bool)

	for _, row := range aggRows {
		if !strings.HasPrefix(row.AggName, transpiler.RawValuesAggPrefix) {
			filtered = append(filtered, row)
			continue
		}
		aggPath := strings.TrimPrefix(row.AggName, transpiler.RawValuesAggPrefix)
		parentKey, vals, ok := transpiler.ParseCollectedFloatValues(row.BucketKey)
		if !ok {
			spec := resolveAggSpecByPath(aggs, aggPath)
			if (spec.Percentiles != nil && spec.Percentiles.HDR != nil) || (spec.PercentileRanks != nil && spec.PercentileRanks.HDR != nil) {
				parentKey = row.BucketKey
				vals = []float64{row.Value}
			} else {
				continue
			}
		}
		if rawByAggAndBucket[aggPath] == nil {
			rawByAggAndBucket[aggPath] = make(map[string][]float64)
			rawBucketSeen[aggPath] = make(map[string]bool)
		}
		rawBucketSeen[aggPath][parentKey] = true
		if len(vals) > 0 {
			rawByAggAndBucket[aggPath][parentKey] = append(rawByAggAndBucket[aggPath][parentKey], vals...)
		}
	}

	if len(rawByAggAndBucket) == 0 || len(aggs) == 0 || len(builtAggs) == 0 {
		return filtered, nil
	}

	if err := applyExactQuantilesWalkR61Search("", "", aggs, builtAggs, rawByAggAndBucket, rawBucketSeen, isES8); err != nil {
		return filtered, err
	}
	return filtered, nil
}

func lookupRawValuesForBucketR61Search(
	valsByParent map[string][]float64,
	seenByParent map[string]bool,
	parentBucketKey string,
	bucketMap map[string]any,
) ([]float64, bool) {
	if len(seenByParent) == 0 {
		return nil, false
	}
	if seenByParent[parentBucketKey] {
		return valsByParent[parentBucketKey], true
	}
	var cands []string
	if bucketMap != nil {
		if k, hasK := bucketMap["key"]; hasK && k != nil {
			cands = append(cands, fmt.Sprintf("%v", k))
		}
		if kas, okS := bucketMap["key_as_string"].(string); okS && kas != "" {
			cands = append(cands, kas)
		}
	}
	for _, cand := range cands {
		if seenByParent[cand] {
			return valsByParent[cand], true
		}
		for pk := range seenByParent {
			if bucketKeysEquivalent(pk, cand) {
				return valsByParent[pk], true
			}
			if strings.HasSuffix(pk, "\x1f"+cand) {
				return valsByParent[pk], true
			}
		}
	}
	return nil, false
}

func lookupBuiltAggEntryR61Search(container map[string]any, aggName string) (string, map[string]any, bool) {
	if container == nil {
		return "", nil, false
	}
	if m, ok := container[aggName].(map[string]any); ok {
		return aggName, m, true
	}
	suffix := "#" + aggName
	for k, v := range container {
		if strings.HasSuffix(k, suffix) {
			if m, ok := v.(map[string]any); ok {
				return k, m, true
			}
		}
	}
	return "", nil, false
}

func applyExactQuantilesWalkR61Search(
	aggPrefix string,
	parentBucketKey string,
	aggs map[string]esast.AggSpec,
	container map[string]any,
	rawByAggAndBucket map[string]map[string][]float64,
	rawBucketSeen map[string]map[string]bool,
	isES8 bool,
) error {
	if len(aggs) == 0 || container == nil {
		return nil
	}
	aggNames := make([]string, 0, len(aggs))
	for k := range aggs {
		aggNames = append(aggNames, k)
	}
	sort.Strings(aggNames)

	for _, aggName := range aggNames {
		spec := aggs[aggName]
		fullPath := aggName
		if aggPrefix != "" {
			fullPath = aggPrefix + "." + aggName
		}
		outKey, aggObj, hasObj := lookupBuiltAggEntryR61Search(container, aggName)
		if !hasObj {
			continue
		}

		if seenMap := rawBucketSeen[fullPath]; len(seenMap) > 0 {
			vals, matched := lookupRawValuesForBucketR61Search(rawByAggAndBucket[fullPath], seenMap, parentBucketKey, container)
			if matched {
				updated, err := buildExactQuantileMetricObjectR61Search(spec, vals, isES8)
				if err != nil {
					return err
				}
				if updated != nil {
					container[outKey] = updated
					aggObj = updated
				}
			}
		} else if parentBucketKey != "" {
			// If parent bucket had 0 docs, SQL GROUP BY emitted no row for `parentBucketKey`; overwrite with empty exact structure!
			if dc, okDC := toFloat64(container["doc_count"]); okDC && dc == 0 {
				if _, hasAny := rawBucketSeen[fullPath]; hasAny {
					updated, err := buildExactQuantileMetricObjectR61Search(spec, nil, isES8)
					if err != nil {
						return err
					}
					if updated != nil {
						container[outKey] = updated
						aggObj = updated
					}
				}
			}
		}

		subAggs := spec.SubAggs()
		if len(subAggs) == 0 {
			continue
		}

		switch rawBuckets := aggObj["buckets"].(type) {
		case []map[string]any:
			for _, bMap := range rawBuckets {
				bKey := fmt.Sprintf("%v", bMap["key"])
				nextParentKey := bKey
				if parentBucketKey != "" {
					nextParentKey = parentBucketKey + "\x1f" + bKey
				}
				if err := applyExactQuantilesWalkR61Search(fullPath, nextParentKey, subAggs, bMap, rawByAggAndBucket, rawBucketSeen, isES8); err != nil {
					return err
				}
			}
		case []any:
			for _, elem := range rawBuckets {
				bMap, okB := elem.(map[string]any)
				if !okB {
					continue
				}
				bKey := fmt.Sprintf("%v", bMap["key"])
				nextParentKey := bKey
				if parentBucketKey != "" {
					nextParentKey = parentBucketKey + "\x1f" + bKey
				}
				if err := applyExactQuantilesWalkR61Search(fullPath, nextParentKey, subAggs, bMap, rawByAggAndBucket, rawBucketSeen, isES8); err != nil {
					return err
				}
			}
		case map[string]any:
			bKeys := make([]string, 0, len(rawBuckets))
			for k := range rawBuckets {
				bKeys = append(bKeys, k)
			}
			sort.Strings(bKeys)
			for _, k := range bKeys {
				bMap, okB := rawBuckets[k].(map[string]any)
				if !okB {
					continue
				}
				nextParentKey := k
				if parentBucketKey != "" {
					nextParentKey = parentBucketKey + "\x1f" + k
				}
				if err := applyExactQuantilesWalkR61Search(fullPath, nextParentKey, subAggs, bMap, rawByAggAndBucket, rawBucketSeen, isES8); err != nil {
					return err
				}
			}
		default:
			// Single-bucket wrapper (`filter`, `global`, `nested`, `reverse_nested`, `sampler`, `diversified_sampler`, `missing`)
			if err := applyExactQuantilesWalkR61Search(fullPath, parentBucketKey, subAggs, aggObj, rawByAggAndBucket, rawBucketSeen, isES8); err != nil {
				return err
			}
		}
	}
	return nil
}

func buildExactQuantileMetricObjectR61Search(spec esast.AggSpec, vals []float64, isES8 bool) (map[string]any, error) {
	switch {
	case spec.Percentiles != nil:
		pSpec := spec.Percentiles
		comp := 100.0
		if pSpec.TDigest != nil && pSpec.TDigest.Compression != nil && *pSpec.TDigest.Compression > 0 {
			comp = *pSpec.TDigest.Compression
		}
		useHDR := pSpec.HDR != nil
		sigDigits := pSpec.HDR.EffectiveSignificantDigits()
		percents := pSpec.EffectivePercents()
		pctMap, err := transpiler.ComputeESPercentilesWithVersion(vals, percents, comp, useHDR, sigDigits, isES8)
		if err != nil {
			if strings.Contains(err.Error(), "cannot be negative") {
				return nil, fmt.Errorf("illegal_argument_exception: %s", strings.TrimPrefix(err.Error(), "array_index_out_of_bounds_exception: "))
			}
			return nil, err
		}
		keyed := pSpec.Keyed == nil || *pSpec.Keyed
		if !keyed {
			arr := make([]map[string]any, 0, len(percents))
			for _, p := range percents {
				kStr := formatPercentileKeyStringR61Search(p)
				vAny := pctMap[kStr]
				entry := map[string]any{
					"key":   p,
					"value": vAny,
				}
				if pSpec.Format != "" && vAny != nil {
					if fv, ok := toFloat64(vAny); ok {
						entry["value_as_string"] = formatNumericWithDecimalPatternR61Search(fv, pSpec.Format)
					}
				}
				arr = append(arr, entry)
			}
			return map[string]any{"values": arr}, nil
		}
		if pSpec.Format != "" {
			strMap := make(map[string]any, len(pctMap))
			for k, v := range pctMap {
				if fv, ok := toFloat64(v); ok {
					strMap[k] = formatNumericWithDecimalPatternR61Search(fv, pSpec.Format)
				} else {
					strMap[k] = nil
				}
			}
			return map[string]any{
				"values":           pctMap,
				"values_as_string": strMap,
			}, nil
		}
		return map[string]any{"values": pctMap}, nil

	case spec.PercentileRanks != nil:
		prSpec := spec.PercentileRanks
		keyed := prSpec.Keyed == nil || *prSpec.Keyed
		res, err := transpiler.ComputeESPercentileRanks(vals, prSpec.Values, prSpec.HDR, keyed)
		if err != nil {
			if strings.Contains(err.Error(), "cannot be negative") {
				return nil, fmt.Errorf("illegal_argument_exception: %s", strings.TrimPrefix(err.Error(), "array_index_out_of_bounds_exception: "))
			}
			return nil, err
		}
		return map[string]any{"values": res}, nil

	case spec.Boxplot != nil:
		comp := 100.0
		if spec.Boxplot.Compression != nil && *spec.Boxplot.Compression > 0 {
			comp = *spec.Boxplot.Compression
		}
		bp := transpiler.ComputeESBoxplotWithVersion(vals, comp, isES8)
		ptrOrNil := func(p *float64) any {
			if p == nil {
				return nil
			}
			return *p
		}
		return map[string]any{
			"min":   ptrOrNil(bp.Min),
			"max":   ptrOrNil(bp.Max),
			"q1":    ptrOrNil(bp.Q1),
			"q2":    ptrOrNil(bp.Q2),
			"q3":    ptrOrNil(bp.Q3),
			"lower": ptrOrNil(bp.Lower),
			"upper": ptrOrNil(bp.Upper),
		}, nil

	case spec.MedianAbsoluteDeviation != nil:
		comp := 1000.0
		if spec.MedianAbsoluteDeviation.Compression != nil && *spec.MedianAbsoluteDeviation.Compression > 0 {
			comp = *spec.MedianAbsoluteDeviation.Compression
		}
		mad := transpiler.ComputeESMedianAbsoluteDeviationWithVersion(vals, comp, isES8)
		if mad == nil {
			return map[string]any{"value": nil}, nil
		}
		return map[string]any{"value": *mad}, nil
	}
	return nil, nil
}

func formatPercentileKeyStringR61Search(p float64) string {
	s := strconv.FormatFloat(p, 'f', -1, 64)
	if !strings.Contains(s, ".") && !strings.ContainsAny(s, "eE") {
		s += ".0"
	}
	return s
}

func isSingleBucketAggSpecR61Search(spec esast.AggSpec) (string, bool) {
	switch {
	case spec.Filter != nil:
		return "filter", true
	case spec.Global != nil:
		return "global", true
	case spec.Nested != nil:
		return "nested", true
	case spec.ReverseNested != nil:
		return "reverse_nested", true
	case spec.Sampler != nil:
		return "sampler", true
	case spec.DiversifiedSampler != nil:
		return "diversified_sampler", true
	case spec.Missing != nil:
		return "missing", true
	}
	return "", false
}

func isMultiBucketParentAggSpecR61Search(spec esast.AggSpec) bool {
	return spec.Terms != nil || spec.MultiTerms != nil || spec.RareTerms != nil ||
		spec.SignificantTerms != nil || spec.SignificantText != nil ||
		spec.Histogram != nil || spec.DateHistogram != nil ||
		spec.AutoDateHistogram != nil || spec.VariableWidthHistogram != nil ||
		spec.Range != nil || spec.DateRange != nil || spec.IPRange != nil ||
		spec.Filters != nil || spec.AdjacencyMatrix != nil || spec.Composite != nil ||
		spec.GeoDistance != nil || spec.GeohashGrid != nil || spec.GeotileGrid != nil ||
		spec.CategorizeText != nil
}

func isChildMultiBucketPipelineAggSpecR61Search(spec esast.AggSpec) (string, bool) {
	switch {
	case spec.Derivative != nil:
		return "derivative", true
	case spec.MovingAvg != nil:
		return "moving_avg", true
	case spec.MovingFn != nil:
		return "moving_fn", true
	case spec.CumulativeSum != nil:
		return "cumulative_sum", true
	case spec.CumulativeCardinality != nil:
		return "cumulative_cardinality", true
	case spec.SerialDiff != nil:
		return "serial_diff", true
	case spec.Normalize != nil:
		return "normalize", true
	case spec.BucketSort != nil:
		return "bucket_sort", true
	case spec.BucketSelector != nil:
		return "bucket_selector", true
	case spec.BucketScript != nil:
		return "bucket_script", true
	}
	return "", false
}

func isSiblingMultiBucketPipelineAggSpecR61Search(spec esast.AggSpec) (string, bool) {
	switch {
	case spec.AvgBucket != nil:
		return "avg_bucket", true
	case spec.SumBucket != nil:
		return "sum_bucket", true
	case spec.MinBucket != nil:
		return "min_bucket", true
	case spec.MaxBucket != nil:
		return "max_bucket", true
	case spec.StatsBucket != nil:
		return "stats_bucket", true
	case spec.ExtendedStatsBucket != nil:
		return "extended_stats_bucket", true
	case spec.PercentilesBucket != nil:
		return "percentiles_bucket", true
	}
	return "", false
}

func isMultiValueMetricAggSpecR61Search(spec esast.AggSpec) (string, bool) {
	switch {
	case spec.Stats != nil:
		return "stats", true
	case spec.ExtendedStats != nil:
		return "extended_stats", true
	case spec.MatrixStats != nil:
		return "matrix_stats", true
	case spec.Percentiles != nil:
		if len(spec.Percentiles.EffectivePercents()) != 1 {
			return "percentiles", true
		}
	case spec.PercentileRanks != nil:
		return "percentile_ranks", true
	case spec.Boxplot != nil:
		return "boxplot", true
	case spec.StatsBucket != nil:
		return "stats_bucket", true
	case spec.ExtendedStatsBucket != nil:
		return "extended_stats_bucket", true
	case spec.PercentilesBucket != nil:
		return "percentiles_bucket", true
	case spec.StringStats != nil:
		return "string_stats", true
	case spec.GeoBounds != nil:
		return "geo_bounds", true
	case spec.GeoCentroid != nil:
		return "geo_centroid", true
	case spec.TopHits != nil:
		return "top_hits", true
	}
	return "", false
}

func extractAllBucketsPathsFromSpecR61Search(spec esast.AggSpec) []string {
	var paths []string
	addAny := func(raw any) {
		switch v := raw.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				paths = append(paths, strings.TrimSpace(v))
			}
		case map[string]string:
			for _, p := range v {
				if strings.TrimSpace(p) != "" {
					paths = append(paths, strings.TrimSpace(p))
				}
			}
		case map[string]any:
			for _, p := range v {
				if s := strings.TrimSpace(fmt.Sprintf("%v", p)); s != "" {
					paths = append(paths, s)
				}
			}
		}
	}
	switch {
	case spec.Derivative != nil:
		addAny(spec.Derivative.BucketsPath)
	case spec.CumulativeSum != nil:
		addAny(spec.CumulativeSum.BucketsPath)
	case spec.CumulativeCardinality != nil:
		addAny(spec.CumulativeCardinality.BucketsPath)
	case spec.MovingAvg != nil:
		addAny(spec.MovingAvg.BucketsPath)
	case spec.MovingFn != nil:
		addAny(spec.MovingFn.BucketsPath)
	case spec.SerialDiff != nil:
		addAny(spec.SerialDiff.BucketsPath)
	case spec.Normalize != nil:
		addAny(spec.Normalize.BucketsPath)
	case spec.BucketSelector != nil:
		addAny(spec.BucketSelector.BucketsPath)
	case spec.BucketScript != nil:
		addAny(spec.BucketScript.BucketsPath)
	case spec.AvgBucket != nil:
		addAny(spec.AvgBucket.BucketsPath)
	case spec.SumBucket != nil:
		addAny(spec.SumBucket.BucketsPath)
	case spec.MinBucket != nil:
		addAny(spec.MinBucket.BucketsPath)
	case spec.MaxBucket != nil:
		addAny(spec.MaxBucket.BucketsPath)
	case spec.StatsBucket != nil:
		addAny(spec.StatsBucket.BucketsPath)
	case spec.ExtendedStatsBucket != nil:
		addAny(spec.ExtendedStatsBucket.BucketsPath)
	case spec.PercentilesBucket != nil:
		addAny(spec.PercentilesBucket.BucketsPath)
	}
	return paths
}

// validatePipelineAndSamplerAggsR61Search enforces ES pipeline parent/path rules, `moving_fn` window/script rules,
// and `diversified_sampler.max_docs_per_value > 0`.
func validatePipelineAndSamplerAggsR61Search(aggs map[string]esast.AggSpec) (int, string, string) {
	if len(aggs) == 0 {
		return 0, "", ""
	}
	return validatePipelineAggTreeR61Search(aggs, "root", false, false, false)
}

func validatePipelineAggTreeR61Search(
	aggs map[string]esast.AggSpec,
	parentKind string,
	parentIsSingleBucket bool,
	parentIsMultiBucket bool,
	hasAncestorMultiBucket bool,
) (int, string, string) {
	names := make([]string, 0, len(aggs))
	for k := range aggs {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		spec := aggs[name]

		// Validate `random_sampler`: cannot sample `time_series` sub-aggregation
		if spec.RandomSampler != nil {
			for subName, subSpec := range spec.SubAggs() {
				if subSpec.TimeSeries != nil {
					return http.StatusBadRequest,
						"illegal_argument_exception",
						fmt.Sprintf("[random_sampler] aggregation [%s] does not support sampling [time_series] aggregation [%s]", name, subName)
				}
			}
		}

		// Validate `moving_fn`: requires `window > 0` and non-empty `script`
		if spec.MovingFn != nil {
			if spec.MovingFn.Window <= 0 {
				return http.StatusBadRequest,
					"illegal_argument_exception",
					fmt.Sprintf("[window] must be a positive, non-zero integer in moving_fn aggregation [%s]", name)
			}
			src, _ := extractScriptSourceAndParams(spec.MovingFn.Script)
			if src == "" {
				if id, okID := extractStoredScriptIDRound61(spec.MovingFn.Script); !okID || id == "" {
					return http.StatusBadRequest,
						"illegal_argument_exception",
						fmt.Sprintf("[script] must be non-empty in moving_fn aggregation [%s]", name)
				}
			}
		}

		// Validate `diversified_sampler`: `max_docs_per_value` must be > 0 (0 in programmatic struct means omitted -> default 1)
		if spec.DiversifiedSampler != nil {
			if spec.DiversifiedSampler.MaxDocsPerValue < 0 {
				return http.StatusBadRequest,
					"illegal_argument_exception",
					fmt.Sprintf("[max_docs_per_value] must be positive in diversified_sampler aggregation [%s]", name)
			}
		}

		// Reject single-bucket parent (`filter`, `global`, `nested`, `reverse_nested`, `sampler`, `diversified_sampler`, `missing`)
		// when child is ANY multi-bucket pipeline agg (child OR sibling pipeline agg directly targeting single bucket!).
		if pipeType, isChildPipe := isChildMultiBucketPipelineAggSpecR61Search(spec); isChildPipe {
			allowSiblingBucketScript := false
			if pipeType == "bucket_script" {
				bps := extractAllBucketsPathsFromSpecR61Search(spec)
				if len(bps) > 0 {
					allSiblingPipe := true
					for _, bp := range bps {
						head := firstSegmentOfBucketsPathR61Search(bp)
						targetSpec, ok := aggs[head]
						if !ok {
							allSiblingPipe = false
							break
						}
						if _, isSib := isSiblingMultiBucketPipelineAggSpecR61Search(targetSpec); !isSib && targetSpec.BucketScript == nil {
							allSiblingPipe = false
							break
						}
					}
					allowSiblingBucketScript = allSiblingPipe
				}
			}
			if pipeType != "bucket_script" || (!allowSiblingBucketScript && !parentIsMultiBucket && !hasAncestorMultiBucket) {
				if parentKind == "root" {
					if pipeType == "derivative" || pipeType == "moving_fn" {
						return http.StatusBadRequest,
							"action_request_validation_exception",
							fmt.Sprintf("Validation Failed: 1: %s aggregation [%s] must have a histogram, date_histogram or auto_date_histogram as parent but doesn't have a parent;", pipeType, name)
					}
					return http.StatusBadRequest,
						"action_request_validation_exception",
						fmt.Sprintf("Validation Failed: 1: %s aggregation [%s] must be declared inside of another aggregation;", pipeType, name)
				}
				if parentIsSingleBucket || !parentIsMultiBucket {
					return http.StatusBadRequest,
						"action_request_validation_exception",
						fmt.Sprintf("Validation Failed: 1: %s aggregation [%s] must have a multi-bucket aggregation as parent, not [%s];", pipeType, name, parentKind)
				}
			}
		}
		if spec.BucketSort != nil {
			if len(spec.BucketSort.Sort) == 0 && spec.BucketSort.Size == nil && spec.BucketSort.From == nil {
				return http.StatusBadRequest,
					"illegal_argument_exception",
					fmt.Sprintf("[%s] is configured to perform nothing. Please set either of [sort, size, from] to use bucket_sort", name)
			}
			for _, sSpec := range spec.BucketSort.Sort {
				sf := strings.TrimSpace(sSpec.Entry.Field)
				if sf == "" || sf == "_key" || sf == "key" || sf == "_count" || sf == "doc_count" ||
					strings.HasPrefix(sf, "_key.") || strings.HasPrefix(sf, "key.") {
					continue
				}
				head := firstSegmentOfBucketsPathR61Search(sf)
				if _, ok := aggs[head]; !ok {
					return http.StatusBadRequest,
						"action_request_validation_exception",
						fmt.Sprintf("Validation Failed: 1: No aggregation found for path [%s];", sf)
				}
			}
		}
		if sibPipeType, isSibPipe := isSiblingMultiBucketPipelineAggSpecR61Search(spec); isSibPipe {
			if parentIsSingleBucket {
				// Sibling pipeline agg inside a single-bucket agg is ONLY valid if its `buckets_path` starts with a sibling multi-bucket agg!
				bps := extractAllBucketsPathsFromSpecR61Search(spec)
				for _, bp := range bps {
					head := firstSegmentOfBucketsPathR61Search(bp)
					if targetSpec, ok := aggs[head]; !ok || !isMultiBucketParentAggSpecR61Search(targetSpec) {
						return http.StatusBadRequest,
							"action_request_validation_exception",
							fmt.Sprintf("Validation Failed: 1: %s aggregation [%s] inside single-bucket [%s] must reference a multi-bucket aggregation in buckets_path [%s];", sibPipeType, name, parentKind, bp)
					}
				}
			}
		}

		// Validate `buckets_path` against referencing a multi-value metric (`stats`, `extended_stats`, `matrix_stats`, `percentiles`, `percentile_ranks`, `boxplot`) without a sub-metric selector!
		if spec.BucketScript == nil && spec.BucketSelector == nil {
			for _, bp := range extractAllBucketsPathsFromSpecR61Search(spec) {
				if invalidMetric, bad := bucketsPathTargetsWholeMultiValueMetricR61Search(aggs, bp); bad {
					return http.StatusBadRequest,
						"illegal_argument_exception",
						fmt.Sprintf("buckets_path must reference either a number value or a single value numeric metric aggregation, but [%s] contains multiple values. Please specify which to use.", invalidMetric)
				}
			}
		}

		subAggs := spec.SubAggs()
		if len(subAggs) > 0 {
			sbKind, isSB := isSingleBucketAggSpecR61Search(spec)
			isMB := isMultiBucketParentAggSpecR61Search(spec)
			childParentKind := name
			if isSB {
				childParentKind = sbKind
			}
			if status, errT, errR := validatePipelineAggTreeR61Search(subAggs, childParentKind, isSB, isMB, hasAncestorMultiBucket || isMB); status != 0 {
				return status, errT, errR
			}
		}
	}
	return 0, "", ""
}

func firstSegmentOfBucketsPathR61Search(bp string) string {
	return firstBucketsPathSeg(bp)
}

func bucketsPathTargetsWholeMultiValueMetricR61Search(siblingAggs map[string]esast.AggSpec, bp string) (string, bool) {
	s := strings.TrimSpace(bp)
	if s == "" || s == "_count" || s == "_key" || s == "doc_count" {
		return "", false
	}
	// Walk path segments separated by `>` or `.` while keeping `[99.0]` sub-metric selectors attached or split.
	// If we reach a multi-value metric agg AND there are NO remaining sub-metric segments (`avg`, `50.0`, `[50.0]`, etc.), it is invalid!
	currAggs := siblingAggs
	rawSegs := normalizeBucketsPath(s)
	for idx, seg := range rawSegs {
		spec, exists := currAggs[seg]
		if !exists {
			// Might be a keyed bucket key on a `filters`/`range` agg; continue if previous container had subAggs
			continue
		}
		if _, isMV := isMultiValueMetricAggSpecR61Search(spec); isMV {
			if idx == len(rawSegs)-1 {
				return seg, true
			}
			return "", false
		}
		sub := spec.SubAggs()
		if len(sub) > 0 {
			currAggs = sub
		} else {
			break
		}
	}
	return "", false
}

var reMovingFunctionsCallR61Search = regexp.MustCompile(`MovingFunctions\s*\.\s*([A-Za-z0-9_]+)\s*\(`)

// evalMovingFnWindowR61Search evaluates an Elasticsearch `moving_fn` window (`MovingFunctions.*` or Painless `values` script),
// returning `nil` (`null` in JSON) on empty `windowVals` for `min`, `max`, `unweightedAvg`, `linearWeightedAvg`, `ewma`, `holt`, `holtWinters`, `stdDev`
// (and `0.0` for `MovingFunctions.sum([])`), matching `MovingFunctions.java` and `moving_fn.yml`.
func evalMovingFnWindowR61Search(windowVals []float64, spec *esast.MovingAvgAggSpec) (any, error) {
	if spec == nil {
		return nil, fmt.Errorf("illegal_argument_exception: [moving_fn] specification is nil")
	}
	src, params := extractScriptSourceAndParams(spec.Script)
	if strings.TrimSpace(src) == "" {
		return nil, fmt.Errorf("illegal_argument_exception: [moving_fn] requires non-empty [script]")
	}

	rewritten, deferredErr, err := rewriteMovingFunctionsCallsR61Search(src, windowVals, params)
	if err != nil {
		return nil, err
	}

	// Fast-path: if the entire expression reduced to a single literal or `NaN`
	trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rewritten), ";"))
	trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "return "))
	if trimmed == "(__MOVING_FN_DEFERRED_ERR__)" || trimmed == "__MOVING_FN_DEFERRED_ERR__" {
		if deferredErr != nil {
			return nil, deferredErr
		}
		return nil, fmt.Errorf("illegal_argument_exception: invalid moving_fn evaluation")
	}
	if trimmed == "__MOVING_FN_NAN__" || trimmed == "(__MOVING_FN_NAN__)" || trimmed == "Double.NaN" || trimmed == "Float.NaN" {
		return nil, nil
	}
	if fv, parseErr := strconv.ParseFloat(trimmed, 64); parseErr == nil {
		if math.IsNaN(fv) || math.IsInf(fv, 0) {
			return nil, nil
		}
		return fv, nil
	}

	// Evaluate via Painless runtime with `values` bound as `[]any` (`values.length` / `values.size()` / indexing)
	evalParams := make(map[string]any, len(params)+3)
	for k, v := range params {
		evalParams[k] = v
	}
	valsAny := make([]any, len(windowVals))
	for i, v := range windowVals {
		valsAny[i] = v
	}
	evalParams["values"] = valsAny
	evalParams["__MOVING_FN_NAN__"] = math.NaN()
	evalParams["__MOVING_FN_DEFERRED_ERR__"] = "__MOVING_FN_DEFERRED_ERR_SENTINEL__"

	scriptToRun := injectImplicitReturnInIfBlockR61Search(rewritten)
	res, evalErr := painless.Eval(map[string]any{}, scriptToRun, evalParams)
	if evalErr != nil {
		if deferredErr != nil {
			return nil, deferredErr
		}
		return nil, evalErr
	}
	if sVal, isStr := res.(string); isStr && sVal == "__MOVING_FN_DEFERRED_ERR_SENTINEL__" {
		if deferredErr != nil {
			return nil, deferredErr
		}
		return nil, fmt.Errorf("illegal_argument_exception: invalid moving_fn evaluation")
	}
	if res == nil {
		// In Java MovingFunctionScript, an `if (...) { ... }` block with no `else` returns `0.0` (`moving_fn.yml:445-452`) unless script explicitly returned `null`.
		if strings.HasPrefix(strings.TrimSpace(src), "if") && !strings.Contains(src, "return null") {
			return 0.0, nil
		}
		return nil, nil
	}
	switch tv := res.(type) {
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) {
			return nil, nil
		}
		return tv, nil
	case float32:
		f := float64(tv)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, nil
		}
		return f, nil
	case int:
		return float64(tv), nil
	case int64:
		return float64(tv), nil
	case json.Number:
		if fv, errF := tv.Float64(); errF == nil {
			if math.IsNaN(fv) || math.IsInf(fv, 0) {
				return nil, nil
			}
			return fv, nil
		}
	}
	return nil, nil
}

func injectImplicitReturnInIfBlockR61Search(script string) string {
	s := strings.TrimSpace(script)
	if strings.Contains(s, "return") || !strings.HasPrefix(s, "if") || !strings.HasSuffix(s, "}") {
		return script
	}
	openBrace := strings.IndexByte(s, '{')
	closeBrace := strings.LastIndexByte(s, '}')
	if openBrace < 0 || closeBrace <= openBrace {
		return script
	}
	inner := strings.TrimSpace(s[openBrace+1 : closeBrace])
	if inner == "" || strings.ContainsAny(inner, "{}") {
		return script
	}
	if semiIdx := strings.LastIndexByte(inner, ';'); semiIdx >= 0 && semiIdx < len(inner)-1 {
		prefix := inner[:semiIdx+1]
		lastExpr := strings.TrimSpace(inner[semiIdx+1:])
		if lastExpr != "" {
			return s[:openBrace+1] + " " + prefix + " return " + lastExpr + "; }"
		}
	}
	inner = strings.TrimSuffix(inner, ";")
	return s[:openBrace+1] + " return " + inner + "; }"
}

func rewriteMovingFunctionsCallsR61Search(src string, windowVals []float64, params map[string]any) (string, error, error) {
	cur := src
	var deferredErr error
	for iter := 0; iter < 32; iter++ {
		locs := reMovingFunctionsCallR61Search.FindAllStringSubmatchIndex(cur, -1)
		if len(locs) == 0 {
			return cur, deferredErr, nil
		}
		// Replace innermost call first (rightmost match so nested calls like `stdDev(values, unweightedAvg(values))` resolve cleanly!)
		loc := locs[len(locs)-1]
		callStart := loc[0]
		openParen := loc[1] - 1
		fnName := cur[loc[2]:loc[3]]
		closeParen := findMatchingParenInScriptR61Search(cur, openParen)
		if closeParen < 0 {
			return "", nil, fmt.Errorf("script_exception: unbalanced parentheses in MovingFunctions.%s", fnName)
		}
		argStr := cur[openParen+1 : closeParen]
		args := splitTopLevelArgs(argStr)
		val, err := evalSingleMovingFunctionsBuiltinR61Search(fnName, args, windowVals, params)
		var repl string
		if err != nil {
			// If call is guarded by an `if (...)` condition (e.g. `if (values.length > 4) { MovingFunctions.holtWinters(...) }`),
			// defer the window-length runtime error until Painless actually enters the branch!
			if strings.Contains(err.Error(), "HoltWinters requires at least") && strings.Contains(cur, "if") {
				deferredErr = err
				repl = "__MOVING_FN_DEFERRED_ERR__"
			} else {
				return "", nil, err
			}
		} else if math.IsNaN(val) || math.IsInf(val, 0) {
			repl = "__MOVING_FN_NAN__"
		} else {
			repl = strconv.FormatFloat(val, 'g', 17, 64)
			if !strings.ContainsAny(repl, ".eE") {
				repl += ".0"
			}
		}
		cur = cur[:callStart] + "(" + repl + ")" + cur[closeParen+1:]
	}
	return cur, deferredErr, nil
}

func findMatchingParenInScriptR61Search(s string, openIdx int) int {
	depth := 0
	inQuote := byte(0)
	for i := openIdx; i < len(s); i++ {
		ch := s[i]
		if inQuote != 0 {
			if ch == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"':
			inQuote = ch
			continue
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func resolveMovingFnNumericArgR61Search(raw string, params map[string]any) (float64, error) {
	s := strings.TrimSpace(raw)
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" {
			break
		}
		s = inner
	}
	if s == "__MOVING_FN_NAN__" || s == "Double.NaN" {
		return math.NaN(), nil
	}
	sClean := strings.TrimSuffix(strings.TrimSuffix(s, "f"), "F")
	sClean = strings.TrimSuffix(strings.TrimSuffix(sClean, "d"), "D")
	if fv, err := strconv.ParseFloat(strings.TrimSpace(sClean), 64); err == nil {
		return fv, nil
	}
	if params != nil {
		pKey := strings.TrimPrefix(s, "params.")
		pKey = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(pKey, "params["), "]"), "'\"")
		if v, ok := params[pKey]; ok {
			if fv, okF := toFloat64(v); okF {
				return fv, nil
			}
		}
	}
	// Evaluate simple arithmetic expression via Painless
	if fv, ok, err := painless.EvalNumber(map[string]any{}, s, params); err == nil && ok {
		return fv, nil
	}
	return 0, fmt.Errorf("illegal_argument_exception: invalid numeric argument [%s] in MovingFunctions", raw)
}

func resolveMovingFnBoolArgR61Search(raw string, params map[string]any) (bool, error) {
	s := strings.TrimSpace(raw)
	switch strings.ToLower(s) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	if params != nil {
		pKey := strings.TrimPrefix(s, "params.")
		if b, ok := params[pKey].(bool); ok {
			return b, nil
		}
	}
	return false, fmt.Errorf("illegal_argument_exception: invalid boolean argument [%s] in MovingFunctions", raw)
}

func evalSingleMovingFunctionsBuiltinR61Search(fnName string, args []string, values []float64, params map[string]any) (float64, error) {
	switch fnName {
	case "sum":
		var sum float64
		for _, v := range values {
			sum += v
		}
		return sum, nil

	case "min":
		if len(values) == 0 {
			return math.NaN(), nil
		}
		res := values[0]
		for _, v := range values[1:] {
			if v < res {
				res = v
			}
		}
		return res, nil

	case "max":
		if len(values) == 0 {
			return math.NaN(), nil
		}
		res := values[0]
		for _, v := range values[1:] {
			if v > res {
				res = v
			}
		}
		return res, nil

	case "unweightedAvg":
		if len(values) == 0 {
			return math.NaN(), nil
		}
		var sum float64
		for _, v := range values {
			sum += v
		}
		return sum / float64(len(values)), nil

	case "linearWeightedAvg":
		if len(values) == 0 {
			return math.NaN(), nil
		}
		// Matches ES `MovingFunctions.linearWeightedAvg`: `int total = 1; for (i=0..n-1) { total += i+1; sum += values[i]*(i+1); } return sum / total;`
		total := 1.0
		var sum float64
		for i, v := range values {
			w := float64(i + 1)
			sum += v * w
			total += w
		}
		return sum / total, nil

	case "stdDev":
		if len(args) < 2 {
			return 0, fmt.Errorf("illegal_argument_exception: MovingFunctions.stdDev requires (values, avg)")
		}
		if len(values) == 0 {
			return math.NaN(), nil
		}
		avg, err := resolveMovingFnNumericArgR61Search(args[1], params)
		if err != nil {
			return 0, err
		}
		if math.IsNaN(avg) {
			return math.NaN(), nil
		}
		var variance float64
		for _, v := range values {
			d := v - avg
			variance += d * d
		}
		return math.Sqrt(variance / float64(len(values))), nil

	case "ewma":
		if len(args) < 2 {
			return 0, fmt.Errorf("illegal_argument_exception: MovingFunctions.ewma requires (values, alpha)")
		}
		alpha, err := resolveMovingFnNumericArgR61Search(args[1], params)
		if err != nil {
			return 0, err
		}
		if alpha < 0.0 || alpha > 1.0 {
			return 0, fmt.Errorf("illegal_argument_exception: alpha must be in [0.0, 1.0], got [%v]", alpha)
		}
		if len(values) == 0 {
			return math.NaN(), nil
		}
		s := values[0]
		for i := 1; i < len(values); i++ {
			s = alpha*values[i] + (1.0-alpha)*s
		}
		return s, nil

	case "holt":
		if len(args) < 3 {
			return 0, fmt.Errorf("illegal_argument_exception: MovingFunctions.holt requires (values, alpha, beta)")
		}
		alpha, err := resolveMovingFnNumericArgR61Search(args[1], params)
		if err != nil {
			return 0, err
		}
		beta, err := resolveMovingFnNumericArgR61Search(args[2], params)
		if err != nil {
			return 0, err
		}
		if alpha < 0.0 || alpha > 1.0 || beta < 0.0 || beta > 1.0 {
			return 0, fmt.Errorf("illegal_argument_exception: alpha and beta must be in [0.0, 1.0]")
		}
		if len(values) == 0 {
			return math.NaN(), nil
		}
		s := values[0]
		b := 0.0
		for i := 1; i < len(values); i++ {
			oldS := s
			s = alpha*values[i] + (1.0-alpha)*(oldS+b)
			b = beta*(s-oldS) + (1.0-beta)*b
		}
		return s, nil

	case "holtWinters":
		if len(args) < 6 {
			return 0, fmt.Errorf("illegal_argument_exception: MovingFunctions.holtWinters requires (values, alpha, beta, gamma, period, mult)")
		}
		alpha, err := resolveMovingFnNumericArgR61Search(args[1], params)
		if err != nil {
			return 0, err
		}
		beta, err := resolveMovingFnNumericArgR61Search(args[2], params)
		if err != nil {
			return 0, err
		}
		gamma, err := resolveMovingFnNumericArgR61Search(args[3], params)
		if err != nil {
			return 0, err
		}
		periodF, err := resolveMovingFnNumericArgR61Search(args[4], params)
		if err != nil {
			return 0, err
		}
		mult, err := resolveMovingFnBoolArgR61Search(args[5], params)
		if err != nil {
			return 0, err
		}
		period := int(periodF)
		if period <= 0 {
			return 0, fmt.Errorf("illegal_argument_exception: period must be > 0 in MovingFunctions.holtWinters")
		}
		if len(values) == 0 {
			return math.NaN(), nil
		}
		if len(values) < 2*period {
			return 0, fmt.Errorf("illegal_argument_exception: HoltWinters requires at least [2 * period] = [%d] values, got [%d]", 2*period, len(values))
		}
		return computeESHoltWintersR61Search(values, alpha, beta, gamma, period, mult), nil

	default:
		return 0, fmt.Errorf("illegal_argument_exception: unknown MovingFunctions method [%s]", fnName)
	}
}

func computeESHoltWintersR61Search(values []float64, alpha, beta, gamma float64, period int, mult bool) float64 {
	// Matches Elasticsearch `MovingFunctions.singleHoltWinters` (`moving_fn.yml:425-454`):
	var sumTwoPeriods float64
	for i := 0; i < 2*period; i++ {
		sumTwoPeriods += values[i]
	}
	level := sumTwoPeriods / float64(2*period)

	var trendSum float64
	for i := 0; i < period; i++ {
		trendSum += (values[period+i] - values[i]) / float64(period)
	}
	trend := trendSum / float64(period)

	numPeriods := (len(values) + period - 1) / period
	periodAvgs := make([]float64, numPeriods)
	for j := 0; j < numPeriods; j++ {
		var ps float64
		for i := 0; i < period; i++ {
			idx := j*period + i
			if idx < len(values) {
				ps += values[idx]
			}
		}
		periodAvgs[j] = ps / float64(period)
	}
	seasonal := make([]float64, period)
	for i := 0; i < period; i++ {
		var ss float64
		for j := 0; j < numPeriods; j++ {
			idx := j*period + i
			var v float64
			if idx < len(values) {
				v = values[idx]
			}
			if mult {
				if periodAvgs[j] != 0 {
					ss += v / periodAvgs[j]
				} else {
					ss += 1.0
				}
			} else {
				ss += v - periodAvgs[j]
			}
		}
		seasonal[i] = ss / float64(numPeriods)
	}

	for i := 1; i < len(values); i++ {
		seasonIdx := i % period
		oldLevel := level
		oldSeason := seasonal[seasonIdx]
		if mult {
			denom := oldSeason
			if denom == 0 {
				denom = 1.0
			}
			level = alpha*(values[i]/denom) + (1.0-alpha)*(oldLevel+trend)
			trend = beta*(level-oldLevel) + (1.0-beta)*trend
			if level != 0 {
				seasonal[seasonIdx] = gamma*(values[i]/level) + (1.0-gamma)*oldSeason
			}
		} else {
			level = alpha*(values[i]-oldSeason) + (1.0-alpha)*(oldLevel+trend)
			trend = beta*(level-oldLevel) + (1.0-beta)*trend
			seasonal[seasonIdx] = gamma*(values[i]-level) + (1.0-gamma)*oldSeason
		}
	}
	return level
}

// normalizeTypedKeysForPipelineLookupR61Search recursively returns a view of `aggsOut` with `<type>#`
// aggregation key prefixes stripped so pipeline `buckets_path` lookups succeed even when `typed_keys` is active.
func normalizeTypedKeysForPipelineLookupR61Search(aggsOut map[string]any) map[string]any {
	if aggsOut == nil {
		return nil
	}
	out := make(map[string]any, len(aggsOut))
	for k, v := range aggsOut {
		cleanKey := k
		if hashIdx := strings.IndexByte(k, '#'); hashIdx > 0 {
			cleanKey = k[hashIdx+1:]
		}
		out[cleanKey] = normalizeTypedKeysValueR61Search(v)
	}
	return out
}

func normalizeTypedKeysValueR61Search(v any) any {
	switch tv := v.(type) {
	case map[string]any:
		// Do NOT strip `#` inside `buckets` map keys (which are user bucket keys, not typed agg names!)
		out := make(map[string]any, len(tv))
		for k, sub := range tv {
			if k == "buckets" {
				switch bv := sub.(type) {
				case []map[string]any:
					nb := make([]map[string]any, len(bv))
					for i, bm := range bv {
						nb[i] = normalizeTypedKeysForPipelineLookupR61Search(bm)
					}
					out["buckets"] = nb
				case []any:
					nb := make([]any, len(bv))
					for i, item := range bv {
						if bm, ok := item.(map[string]any); ok {
							nb[i] = normalizeTypedKeysForPipelineLookupR61Search(bm)
						} else {
							nb[i] = item
						}
					}
					out["buckets"] = nb
				case map[string]any:
					nb := make(map[string]any, len(bv))
					for bk, bItem := range bv {
						if bm, ok := bItem.(map[string]any); ok {
							nb[bk] = normalizeTypedKeysForPipelineLookupR61Search(bm)
						} else {
							nb[bk] = bItem
						}
					}
					out["buckets"] = nb
				default:
					out["buckets"] = sub
				}
				continue
			}
			if k == "hits" || k == "values" || k == "values_as_string" || k == "meta" {
				out[k] = sub
				continue
			}
			cleanK := k
			if hashIdx := strings.IndexByte(k, '#'); hashIdx > 0 {
				cleanK = k[hashIdx+1:]
			}
			out[cleanK] = normalizeTypedKeysValueR61Search(sub)
		}
		return out
	default:
		return v
	}
}

// evaluateNestedTopHitsAggR61Search evaluates a `top_hits` sub-aggregation inside a `nested` aggregation
// over matched child objects (`_nested: {"field": nestedPath, "offset": childIdx}`) rather than whole parent documents.
func evaluateNestedTopHitsAggR61Search(
	nestedPath string,
	parentHits []HitRow,
	parentFilter *esast.Query,
	topHitsSpec *esast.TopHitsAggSpec,
	idxSchema *schema.IndexSchema,
) map[string]any {
	if topHitsSpec == nil {
		topHitsSpec = &esast.TopHitsAggSpec{}
	}
	nestedPath = strings.TrimSpace(nestedPath)
	nestedSegs := strings.Split(nestedPath, ".")
	nestedEvalSchema := deriveNestedEvalSchema(idxSchema, nestedPath)

	type nestedChildCandR61Search struct {
		parent HitRow
		child  map[string]any
		offset int
		score  float64
	}

	var cands []nestedChildCandR61Search
	for _, ph := range parentHits {
		var pDoc map[string]any
		src := ph.EffectiveSource()
		if len(src) > 0 {
			dec := json.NewDecoder(bytes.NewReader(src))
			dec.UseNumber()
			_ = dec.Decode(&pDoc)
		}
		if pDoc == nil {
			continue
		}
		pSchema := ph.Schema
		if pSchema == nil {
			pSchema = idxSchema
		}
		nSchema := nestedEvalSchema
		if ph.Schema != nil && ph.Schema != idxSchema {
			nSchema = deriveNestedEvalSchema(ph.Schema, nestedPath)
		}

		children := extractNestedChildMapsPreservingOffsetsR61Search(pDoc, nestedPath)
		for offset, ch := range children {
			if ch == nil {
				continue
			}
			elemDoc := buildSingleNestedElementDoc(nestedSegs, ch)
			if parentFilter != nil && !evalBranchMatchesDoc(nSchema, elemDoc, parentFilter) {
				continue
			}
			sc := ph.Score
			if parentFilter != nil {
				sc = scoreNonScriptClauseOnDoc(nSchema, elemDoc, parentFilter)
				if sc == 0 {
					sc = 1.0
				}
			} else if sc == 0 && ph.Query == nil {
				sc = 1.0
			}
			cands = append(cands, nestedChildCandR61Search{
				parent: ph,
				child:  ch,
				offset: offset,
				score:  sc,
			})
			_ = pSchema
		}
	}

	if len(cands) > 1 {
		if len(topHitsSpec.Sort) > 0 {
			sort.SliceStable(cands, func(i, j int) bool {
				bI, _ := json.Marshal(buildSingleNestedElementDoc(nestedSegs, cands[i].child))
				bJ, _ := json.Marshal(buildSingleNestedElementDoc(nestedSegs, cands[j].child))
				hrI := HitRow{ID: cands[i].parent.ID, Index: cands[i].parent.Index, Score: cands[i].score, Source: bI, Schema: nestedEvalSchema}
				hrJ := HitRow{ID: cands[j].parent.ID, Index: cands[j].parent.Index, Score: cands[j].score, Source: bJ, Schema: nestedEvalSchema}
				if cmp := compareHitRowsBySortWithSchemas(hrI, hrJ, topHitsSpec.Sort, nestedEvalSchema, nestedEvalSchema); cmp != 0 {
					return cmp < 0
				}
				if cands[i].parent.ID != cands[j].parent.ID {
					return cands[i].parent.ID < cands[j].parent.ID
				}
				return cands[i].offset < cands[j].offset
			})
		} else {
			sort.SliceStable(cands, func(i, j int) bool {
				if cands[i].score != cands[j].score {
					return cands[i].score > cands[j].score
				}
				if cands[i].parent.ID != cands[j].parent.ID {
					return cands[i].parent.ID < cands[j].parent.ID
				}
				return cands[i].offset < cands[j].offset
			})
		}
	}

	totalMatched := int64(len(cands))
	trackScores := topHitsSpec.TrackScores != nil && *topHitsSpec.TrackScores
	nullifyScore := len(topHitsSpec.Sort) > 0 && !sortSpecsUseScore(topHitsSpec.Sort) && !trackScores

	var maxScoreAny any
	if !nullifyScore && len(cands) > 0 {
		best := cands[0].score
		for _, c := range cands[1:] {
			if c.score > best {
				best = c.score
			}
		}
		maxScoreAny = best
	}

	from := topHitsSpec.EffectiveFrom()
	size := topHitsSpec.EffectiveSize()
	var paged []nestedChildCandR61Search
	if from < len(cands) {
		end := from + size
		if end > len(cands) {
			end = len(cands)
		}
		paged = cands[from:end]
	}

	defaultIdx := ""
	if idxSchema != nil {
		defaultIdx = idxSchema.IndexName
	}

	hitMaps := make([]map[string]any, 0, len(paged))
	for _, c := range paged {
		hitIdx := c.parent.Index
		if hitIdx == "" {
			hitIdx = defaultIdx
		}
		var scoreVal any = c.score
		if nullifyScore {
			scoreVal = nil
		}
		hm := map[string]any{
			"_index": hitIdx,
			"_id":    c.parent.ID,
			"_nested": map[string]any{
				"field":  nestedPath,
				"offset": c.offset,
			},
			"_score": scoreVal,
		}
		if c.parent.Routing != "" {
			hm["_routing"] = c.parent.Routing
		}
		thFlags := extractTopHitsFlagsFromScopeR63(c.parent.SearchScope)
		if thFlags.version {
			ver := c.parent.Version
			if ver <= 0 {
				ver = 1
			}
			hm["_version"] = ver
		}
		if thFlags.seqNoPrimaryTerm {
			seqNo := c.parent.SeqNo
			if !c.parent.HasSeqNo {
				if c.parent.Version > 0 {
					seqNo = c.parent.Version - 1
				} else {
					seqNo = 0
				}
			}
			hm["_seq_no"] = seqNo
			hm["_primary_term"] = 1
		}

		elemFullBytes, _ := json.Marshal(buildSingleNestedElementDoc(nestedSegs, c.child))
		childBytes, _ := json.Marshal(c.child)

		includeSource := !isIndexSourceDisabledRound59(idxSchema) && (topHitsSpec.Source == nil || !topHitsSpec.Source.Disabled) && (!topHitsSpec.HasStoredFieldsNone() || topHitsSpec.Source != nil)
		if includeSource {
			if topHitsSpec.Source != nil && (len(topHitsSpec.Source.Includes) > 0 || len(topHitsSpec.Source.Excludes) > 0) {
				relFilter := stripNestedPrefixSourceFilterR61Search(topHitsSpec.Source, nestedPath)
				filteredBytes := filterSourceJSON(childBytes, relFilter)
				var srcMap map[string]any
				dec := json.NewDecoder(bytes.NewReader(filteredBytes))
				dec.UseNumber()
				if dec.Decode(&srcMap) == nil && srcMap != nil {
					hm["_source"] = srcMap
				} else {
					hm["_source"] = map[string]any{}
				}
			} else {
				hm["_source"] = deepCloneDocMap(c.child)
			}
		}

		if len(topHitsSpec.Sort) > 0 {
			hrChild := HitRow{ID: c.parent.ID, Index: hitIdx, Score: c.score, Source: elemFullBytes, Schema: nestedEvalSchema}
			hm["sort"] = extractHitSortValues(hrChild, topHitsSpec.Sort, nestedEvalSchema)
		}

		if len(topHitsSpec.Fields) > 0 || len(topHitsSpec.DocvalueFields) > 0 || topHitsSpec.StoredFields != nil {
			ihProxy := &esast.InnerHitsSpec{
				Fields:         topHitsSpec.Fields,
				DocvalueFields: topHitsSpec.DocvalueFields,
				StoredFields:   topHitsSpec.StoredFields,
			}
			if cf := extractNestedChildInnerHitFieldsR61Search(c.parent.ID, hitIdx, nestedPath, c.child, elemFullBytes, ihProxy, idxSchema); len(cf) > 0 {
				hm["fields"] = cf
			}
		}
		hitMaps = append(hitMaps, hm)
	}

	return map[string]any{
		"hits": map[string]any{
			"total":     map[string]any{"value": totalMatched, "relation": "eq"},
			"max_score": maxScoreAny,
			"hits":      hitMaps,
		},
	}
}

// collectAggDeprecationWarningsR61Search emits ES 7 deprecation warnings when `terms` uses `"order": {"_term": ...}`
// (or `histogram` / `date_histogram` uses `"order": {"_time": ...}`).
func collectAggDeprecationWarningsR61Search(aggs map[string]esast.AggSpec, isES8 bool) []string {
	if isES8 || len(aggs) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var warnings []string
	addWarn := func(msg string) {
		if !seen[msg] {
			seen[msg] = true
			warnings = append(warnings, msg)
		}
	}
	var walk func(m map[string]esast.AggSpec)
	walk = func(m map[string]esast.AggSpec) {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			spec := m[k]
			if spec.Terms != nil && orderContainsKeyR61Search(spec.Terms.Order, "_term") {
				addWarn("Deprecated aggregation order key [_term] used, replaced by [_key]")
			}
			if spec.Histogram != nil && orderContainsKeyR61Search(spec.Histogram.Order, "_time") {
				addWarn("Deprecated aggregation order key [_time] used, replaced by [_key]")
			}
			if spec.DateHistogram != nil {
				if orderContainsKeyR61Search(spec.DateHistogram.Order, "_time") {
					addWarn("Deprecated aggregation order key [_time] used, replaced by [_key]")
				}
				if strings.TrimSpace(spec.DateHistogram.Interval) != "" {
					addWarn("[interval] on [date_histogram] is deprecated, use [fixed_interval] or [calendar_interval] in the future.")
				}
			}
			if spec.Composite != nil {
				for _, srcMap := range spec.Composite.Sources {
					for _, srcSpec := range srcMap {
						if srcSpec.DateHistogram != nil && strings.TrimSpace(srcSpec.DateHistogram.Interval) != "" {
							addWarn("[interval] on [date_histogram] is deprecated, use [fixed_interval] or [calendar_interval] in the future.")
						}
					}
				}
			}
			if len(spec.SubAggs()) > 0 {
				walk(spec.SubAggs())
			}
		}
	}
	walk(aggs)
	return warnings
}

func orderContainsKeyR61Search(order any, targetKey string) bool {
	switch ov := order.(type) {
	case map[string]any:
		_, ok := ov[targetKey]
		return ok
	case map[string]string:
		_, ok := ov[targetKey]
		return ok
	case []any:
		for _, elem := range ov {
			if orderContainsKeyR61Search(elem, targetKey) {
				return true
			}
		}
	}
	return false
}

// ============================================================================
// F17: Route All `intervals` Queries Through `EvaluateIntervalsRuleWithFieldLookup` & `ScoreIntervalsSpans`
// ============================================================================

// queryNeedsIntervalsEvalR61Search reports whether `q` contains any `intervals` query clause.
func queryNeedsIntervalsEvalR61Search(q *esast.Query) bool {
	return transpiler.QueryHasIntervals(q)
}

// evalAndScoreIntervalsQueryOnDocR61Search evaluates `q` (including `q.Intervals` and recursive compound queries
// containing `intervals`) using `transpiler.EvaluateIntervalsRuleWithFieldLookup` (`use_field` resolution +
// `PrepareDocForRuntimeScriptRound61` for `filter.script`) and computes Lucene `IntervalScorer` saturation scores.
func evalAndScoreIntervalsQueryOnDocR61Search(
	idxSchema *schema.IndexSchema,
	doc map[string]any,
	q *esast.Query,
	isES8 bool,
) (matched bool, score float64, err error) {
	if q == nil {
		return true, 1.0, nil
	}
	return evalIntervalsCompoundQueryR61Search(idxSchema, doc, q, isES8, true)
}

func evalIntervalsCompoundQueryR61Search(
	idxSchema *schema.IndexSchema,
	doc map[string]any,
	q *esast.Query,
	isES8 bool,
	inScoring bool,
) (bool, float64, error) {
	if q == nil {
		return true, 1.0, nil
	}

	if len(q.Intervals) > 0 {
		fieldNames := make([]string, 0, len(q.Intervals))
		for f := range q.Intervals {
			fieldNames = append(fieldNames, f)
		}
		sort.Strings(fieldNames)

		var preparedDoc map[string]any
		lookup := func(targetField string) ([]string, string) {
			analyzer := "standard"
			var segs []string
			if idxSchema != nil {
				b := idxSchema.ResolveField(targetField)
				if b.SearchAnalyzer != "" {
					analyzer = b.SearchAnalyzer
				} else if b.Analyzer != "" {
					analyzer = b.Analyzer
				} else if strings.EqualFold(b.ESType, "keyword") || strings.EqualFold(b.ESType, "constant_keyword") || strings.EqualFold(b.ESType, "wildcard") {
					analyzer = "keyword"
				}
				if len(b.SourceJSONPath) > 0 {
					segs = b.SourceJSONPath
				} else if b.AliasTarget != "" {
					segs = strings.Split(strings.TrimSuffix(strings.TrimSuffix(b.AliasTarget, ".keyword"), ".ngram"), ".")
				}
			}
			if len(segs) == 0 {
				segs = strings.Split(strings.TrimSuffix(strings.TrimSuffix(targetField, ".keyword"), ".ngram"), ".")
			}
			rawVals := collectSchemaAwareScalarValues(doc, targetField, segs, idxSchema)
			texts := make([]string, 0, len(rawVals))
			for _, rv := range rawVals {
				if rv == nil {
					continue
				}
				s := formatRawScalarStringR61Search(rv)
				if idxSchema != nil {
					b := idxSchema.ResolveField(targetField)
					if b.LowercaseNormalizer {
						s = strings.ToLower(s)
					}
				}
				texts = append(texts, s)
			}
			return texts, analyzer
		}

		scriptEval := func(sc *esast.ScriptSpec, span transpiler.IntervalsSpan) (bool, error) {
			if sc == nil {
				return true, nil
			}
			src := sc.Source
			params := sc.Params
			if strings.TrimSpace(src) == "" && strings.TrimSpace(sc.ID) != "" {
				activeStoredScriptsServerMu.RLock()
				srv := activeStoredScriptsServer
				activeStoredScriptsServerMu.RUnlock()
				if srv != nil {
					if stored, ok := srv.lookupStoredScript(sc.ID); ok {
						if sStr, okS := stored["source"].(string); okS {
							src = sStr
						}
					}
				}
			}
			if preparedDoc == nil {
				preparedDoc = PrepareDocForRuntimeScriptRound61(idxSchema, doc, isES8)
			}
			evalParams := make(map[string]any, len(params)+1)
			for k, v := range params {
				evalParams[k] = v
			}
			evalParams["interval"] = map[string]any{
				"start": span.Start,
				"end":   span.End,
				"gaps":  span.Gaps,
			}
			return painless.EvalFilter(preparedDoc, src, evalParams)
		}

		var idxAnCfg *analysis.IndexAnalysisConfig
		var idxAnOpts analysis.Options
		if idxSchema != nil && idxSchema.IndexName != "" {
			activeStoredScriptsServerMu.RLock()
			srv := activeStoredScriptsServer
			activeStoredScriptsServerMu.RUnlock()
			if srv != nil {
				idxAnCfg, idxAnOpts = srv.buildIndexAnalysisConfigR62Admin(idxSchema.IndexName)
			}
		}

		var totalScore float64
		for _, field := range fieldNames {
			rule := q.Intervals[field]
			spans, okSpan, evalErr := transpiler.EvaluateIntervalsRuleWithAnalysis(field, &rule, lookup, idxAnCfg, idxAnOpts, scriptEval)
			if evalErr != nil {
				return false, 0, evalErr
			}
			if !okSpan || len(spans) == 0 {
				return false, 0, nil
			}
			if inScoring {
				boost := 1.0
				if rule.Boost != nil {
					boost = *rule.Boost
				}
				scoringSpans := spans
				if rule.AllOf != nil && rule.AllOf.MaxGaps != nil && *rule.AllOf.MaxGaps == 0 {
					minExt := intervalsRuleMinExtentR63(&rule)
					if minExt > 0 {
						scoringSpans = make([]transpiler.IntervalsSpan, len(spans))
						copy(scoringSpans, spans)
						for si := range scoringSpans {
							extGap := (scoringSpans[si].End - scoringSpans[si].Start + 1) - minExt
							if extGap > scoringSpans[si].Gaps {
								scoringSpans[si].Gaps = extGap
							}
						}
					}
				}
				totalScore += transpiler.ScoreIntervalsSpans(scoringSpans, boost)
			}
		}
		return true, totalScore, nil
	}

	if q.Bool != nil {
		for i := range q.Bool.MustNot {
			m, _, evalErr := evalIntervalsCompoundQueryR61Search(idxSchema, doc, &q.Bool.MustNot[i], isES8, false)
			if evalErr != nil {
				return false, 0, evalErr
			}
			if m {
				return false, 0, nil
			}
		}
		for i := range q.Bool.Filter {
			m, _, evalErr := evalIntervalsCompoundQueryR61Search(idxSchema, doc, &q.Bool.Filter[i], isES8, false)
			if evalErr != nil {
				return false, 0, evalErr
			}
			if !m {
				return false, 0, nil
			}
		}
		var totalScore float64
		hasScored := false
		for i := range q.Bool.Must {
			m, sc, evalErr := evalIntervalsCompoundQueryR61Search(idxSchema, doc, &q.Bool.Must[i], isES8, inScoring)
			if evalErr != nil {
				return false, 0, evalErr
			}
			if !m {
				return false, 0, nil
			}
			totalScore += sc
			hasScored = true
		}
		matchedShould := 0
		for i := range q.Bool.Should {
			m, sc, evalErr := evalIntervalsCompoundQueryR61Search(idxSchema, doc, &q.Bool.Should[i], isES8, inScoring)
			if evalErr != nil {
				return false, 0, evalErr
			}
			if m {
				matchedShould++
				totalScore += sc
				hasScored = true
			}
		}
		minShould := resolveBoolMinShouldMatchR61Search(q.Bool, len(q.Bool.Should))
		if matchedShould < minShould {
			return false, 0, nil
		}
		boost := 1.0
		if q.Bool.Boost != nil {
			boost = *q.Bool.Boost
		}
		if !inScoring {
			return true, 0, nil
		}
		if !hasScored {
			return true, boost, nil
		}
		return true, totalScore * boost, nil
	}

	if q.ConstantScore != nil {
		m, _, evalErr := evalIntervalsCompoundQueryR61Search(idxSchema, doc, &q.ConstantScore.Filter, isES8, false)
		if evalErr != nil || !m {
			return false, 0, evalErr
		}
		boost := 1.0
		if q.ConstantScore.Boost != nil {
			boost = *q.ConstantScore.Boost
		}
		if !inScoring {
			return true, 0, nil
		}
		return true, boost, nil
	}

	if q.Boosting != nil {
		posM, posScore, evalErr := evalIntervalsCompoundQueryR61Search(idxSchema, doc, &q.Boosting.Positive, isES8, inScoring)
		if evalErr != nil || !posM {
			return false, 0, evalErr
		}
		negM, _, negErr := evalIntervalsCompoundQueryR61Search(idxSchema, doc, &q.Boosting.Negative, isES8, false)
		if negErr != nil {
			return false, 0, negErr
		}
		sc := posScore
		if negM {
			sc *= q.Boosting.EffectiveNegativeBoost()
		}
		if q.Boosting.Boost != nil {
			sc *= *q.Boosting.Boost
		}
		return true, sc, nil
	}

	if q.DisMax != nil {
		var scores []float64
		for i := range q.DisMax.Queries {
			m, sc, evalErr := evalIntervalsCompoundQueryR61Search(idxSchema, doc, &q.DisMax.Queries[i], isES8, inScoring)
			if evalErr != nil {
				return false, 0, evalErr
			}
			if m {
				scores = append(scores, sc)
			}
		}
		if len(scores) == 0 {
			return false, 0, nil
		}
		if !inScoring {
			return true, 0, nil
		}
		sort.Float64s(scores)
		best := scores[len(scores)-1]
		var rest float64
		for _, s := range scores[:len(scores)-1] {
			rest += s
		}
		res := best + q.DisMax.TieBreaker*rest
		if q.DisMax.Boost != nil {
			res *= *q.DisMax.Boost
		}
		return true, res, nil
	}

	if q.Nested != nil {
		nestedSegs := strings.Split(q.Nested.Path, ".")
		nestedSchema := deriveNestedEvalSchema(idxSchema, q.Nested.Path)
		children := extractNestedChildMapsPreservingOffsetsR61Search(doc, q.Nested.Path)
		var elemScores []float64
		for _, ch := range children {
			if ch == nil {
				continue
			}
			elemDoc := buildSingleNestedElementDoc(nestedSegs, ch)
			m, sc, evalErr := evalIntervalsCompoundQueryR61Search(nestedSchema, elemDoc, &q.Nested.Query, isES8, inScoring)
			if evalErr != nil {
				return false, 0, evalErr
			}
			if m {
				elemScores = append(elemScores, sc)
			}
		}
		if len(elemScores) == 0 {
			return false, 0, nil
		}
		if !inScoring || strings.EqualFold(q.Nested.ScoreMode, "none") {
			return true, 0, nil
		}
		var agg float64
		switch strings.ToLower(strings.TrimSpace(q.Nested.ScoreMode)) {
		case "sum":
			for _, s := range elemScores {
				agg += s
			}
		case "max":
			agg = elemScores[0]
			for _, s := range elemScores[1:] {
				if s > agg {
					agg = s
				}
			}
		case "min":
			agg = elemScores[0]
			for _, s := range elemScores[1:] {
				if s < agg {
					agg = s
				}
			}
		default: // avg
			for _, s := range elemScores {
				agg += s
			}
			agg /= float64(len(elemScores))
		}
		if q.Nested.Boost != nil {
			agg *= *q.Nested.Boost
		}
		return true, agg, nil
	}

	if q.FunctionScore != nil && q.FunctionScore.Query != nil && queryNeedsIntervalsEvalR61Search(q.FunctionScore.Query) {
		m, baseSc, evalErr := evalIntervalsCompoundQueryR61Search(idxSchema, doc, q.FunctionScore.Query, isES8, true)
		if evalErr != nil || !m {
			return false, 0, evalErr
		}
		// Delegate function combination to `evalQueryScriptScoreOnDocWithSchema` using `baseSc`!
		matchAllQ := *q
		fsCopy := *q.FunctionScore
		fsCopy.Query = &esast.Query{MatchAll: map[string]any{}}
		matchAllQ.FunctionScore = &fsCopy
		finalSc := evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, &matchAllQ, baseSc)
		return true, finalSc, nil
	}

	// Non-intervals leaf query fallback
	if !evalBranchMatchesDoc(idxSchema, doc, q) {
		return false, 0, nil
	}
	if !inScoring {
		return true, 0, nil
	}
	sc := scoreNonScriptClauseOnDoc(idxSchema, doc, q)
	if queryHasRuntimeScript(q) || queryHasNestedScoring(q) || q.FunctionScore != nil {
		sc = evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, q, sc)
	}
	return true, sc, nil
}

func intervalsRuleMinExtentR63(r *esast.IntervalsRule) int {
	if r == nil {
		return 0
	}
	switch {
	case r.Match != nil:
		toks := transpiler.TokenizeByAnalyzer(r.Match.Query, r.Match.Analyzer)
		if len(toks) > 0 {
			return len(toks)
		}
		return 1
	case r.Prefix != nil, r.Wildcard != nil, r.Fuzzy != nil:
		return 1
	case r.AllOf != nil:
		sum := 0
		for i := range r.AllOf.Intervals {
			sum += intervalsRuleMinExtentR63(&r.AllOf.Intervals[i])
		}
		return sum
	case r.AnyOf != nil:
		minExt := 0
		for i := range r.AnyOf.Intervals {
			ext := intervalsRuleMinExtentR63(&r.AnyOf.Intervals[i])
			if ext > 0 && (minExt == 0 || ext < minExt) {
				minExt = ext
			}
		}
		return minExt
	}
	return 0
}

func resolveBoolMinShouldMatchR61Search(bq *esast.BoolQuery, numShould int) int {
	if bq == nil || numShould == 0 {
		return 0
	}
	hasPos := len(bq.Must) > 0 || len(bq.Filter) > 0
	if bq.MinimumShouldMatch == nil {
		if !hasPos {
			return 1
		}
		return 0
	}
	switch v := bq.MinimumShouldMatch.(type) {
	case int:
		if v < 0 {
			return max(0, numShould+v)
		}
		return v
	case int64:
		if v < 0 {
			return max(0, numShould+int(v))
		}
		return int(v)
	case float64:
		iv := int(v)
		if iv < 0 {
			return max(0, numShould+iv)
		}
		return iv
	case string:
		s := strings.TrimSpace(v)
		if strings.HasSuffix(s, "%") {
			if pct, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64); err == nil {
				if pct < 0 {
					return max(0, numShould-int(math.Floor(float64(numShould)*(-pct)/100.0)))
				}
				return int(math.Floor(float64(numShould) * pct / 100.0))
			}
		}
		if iv, err := strconv.Atoi(s); err == nil {
			if iv < 0 {
				return max(0, numShould+iv)
			}
			return iv
		}
	}
	return 0
}

// ============================================================================
// F18: Highlighter (`max_analyzed_offset`, Empty/Mismatched Tags, `ignore_above`,
// Synthetic Source FVH) & Completion Suggester Runtime
// ============================================================================

// validateHighlightRequestR61Search validates search `highlight` options:
//   - Rejects empty `pre_tags: []` or `post_tags: []` or mismatched `len(pre_tags) != len(post_tags)` (`400 illegal_argument_exception`).
//   - Rejects request `max_analyzed_offset` > `index.highlight.max_analyzed_offset` (`400 illegal_argument_exception`).
//   - Rejects `type: "fvh"` on fields without `term_vector: "with_positions_offsets"` (and synthetic-source multi-value fields without `store: true`).
func validateHighlightRequestR61Search(
	req *esast.SearchRequest,
	schemas []*schema.IndexSchema,
	customSettingsByIdx map[string]map[string]any,
) (int, string, string) {
	if req == nil || req.Highlight == nil {
		return 0, "", ""
	}
	hl := req.Highlight

	// 1. Validate top-level `pre_tags` / `post_tags`
	if status, errT, errR := validateHighlightTagsPairR61Search(hl.PreTags, hl.PostTags, hl.PreTags != nil, hl.PostTags != nil); status != 0 {
		return status, errT, errR
	}

	// Collect minimum `index.highlight.max_analyzed_offset` across target indices (default 1,000,000 in ES).
	minIndexMaxOffset := -1
	for _, sc := range schemas {
		if sc == nil {
			continue
		}
		if lim, ok := resolveIndexHighlightMaxAnalyzedOffsetR61Search(sc.IndexName, customSettingsByIdx); ok {
			if minIndexMaxOffset < 0 || lim < minIndexMaxOffset {
				minIndexMaxOffset = lim
			}
		}
	}
	if minIndexMaxOffset < 0 {
		for _, m := range customSettingsByIdx {
			if lim, ok := parseMaxAnalyzedOffsetFromSettingsMapR61Search(m); ok {
				if minIndexMaxOffset < 0 || lim < minIndexMaxOffset {
					minIndexMaxOffset = lim
				}
			}
		}
	}
	effIndexLimit := 1_000_000
	if minIndexMaxOffset >= 0 {
		effIndexLimit = minIndexMaxOffset
	}

	if hl.MaxAnalyzedOffset != nil {
		if *hl.MaxAnalyzedOffset < 0 {
			return http.StatusBadRequest, "illegal_argument_exception", "[max_analyzed_offset] must be a non-negative integer"
		}
		if *hl.MaxAnalyzedOffset > effIndexLimit {
			return http.StatusBadRequest,
				"illegal_argument_exception",
				fmt.Sprintf("Highlighter's [max_analyzed_offset] of [%d] is higher than the [index.highlight.max_analyzed_offset] index level setting of [%d]", *hl.MaxAnalyzedOffset, effIndexLimit)
		}
	}

	fieldNames := make([]string, 0, len(hl.Fields))
	for fn := range hl.Fields {
		fieldNames = append(fieldNames, fn)
	}
	sort.Strings(fieldNames)

	for _, fn := range fieldNames {
		rawFieldCfg := hl.Fields[fn]
		fSpec := hl.FieldSpec(fn)
		hasRawPre, hasRawPost := rawFieldHasPrePostTagsKeysR61Search(rawFieldCfg)
		if status, errT, errR := validateHighlightTagsPairR61Search(fSpec.PreTags, fSpec.PostTags, hasRawPre || fSpec.PreTags != nil, hasRawPost || fSpec.PostTags != nil); status != 0 {
			return status, errT, errR
		}
		if fSpec.MaxAnalyzedOffset != nil {
			if *fSpec.MaxAnalyzedOffset < 0 {
				return http.StatusBadRequest, "illegal_argument_exception", "[max_analyzed_offset] must be a non-negative integer"
			}
			if *fSpec.MaxAnalyzedOffset > effIndexLimit {
				return http.StatusBadRequest,
					"illegal_argument_exception",
					fmt.Sprintf("Highlighter's [max_analyzed_offset] of [%d] is higher than the [index.highlight.max_analyzed_offset] index level setting of [%d]", *fSpec.MaxAnalyzedOffset, effIndexLimit)
			}
		}

		effType := strings.ToLower(strings.TrimSpace(fSpec.Type))
		if effType == "" {
			effType = strings.ToLower(strings.TrimSpace(hl.Type))
		}
		if effType == "fvh" || effType == "fast-vector-highlighter" {
			for _, sc := range schemas {
				if sc == nil {
					continue
				}
				matchedFields := expandHighlightTargetFieldsInSchemaR61Search(sc, fn)
				for _, mf := range matchedFields {
					if !fieldHasTermVectorPositionsOffsetsR61Search(sc, mf, customSettingsByIdx) {
						return http.StatusBadRequest,
							"illegal_argument_exception",
							fmt.Sprintf("the field [%s] should be indexed with term vector with position offsets to be used with fast vector highlighter", mf)
					}
					if sc.SyntheticSource && !fieldIsStoredInSchemaR61Search(sc, mf) && fieldIsMultiValuedInSchemaR61Search(sc, mf) {
						return http.StatusBadRequest,
							"illegal_argument_exception",
							fmt.Sprintf("The fast vector highlighter doesn't support loading multi-valued fields from _source in index [%s] because _source can reorder field values", sc.IndexName)
					}
				}
			}
		}
	}
	return 0, "", ""
}

func validateHighlightTagsPairR61Search(pre, post []string, hasPre, hasPost bool) (int, string, string) {
	if (hasPre && len(pre) == 0) || (hasPost && len(post) == 0) {
		return http.StatusBadRequest,
			"illegal_argument_exception",
			"pre_tags or post_tags must not be empty"
	}
	if len(pre) > 0 && len(post) > 0 && len(pre) != len(post) {
		return http.StatusBadRequest,
			"illegal_argument_exception",
			"Highlighter requires both [pre_tags] and [post_tags] to have the same number of elements"
	}
	return 0, "", ""
}

func rawFieldHasPrePostTagsKeysR61Search(raw any) (bool, bool) {
	m, ok := raw.(map[string]any)
	if !ok || m == nil {
		return false, false
	}
	_, hasPre := m["pre_tags"]
	_, hasPost := m["post_tags"]
	return hasPre, hasPost
}

func resolveIndexHighlightMaxAnalyzedOffsetR61Search(indexName string, customSettingsByIdx map[string]map[string]any) (int, bool) {
	if customSettingsByIdx == nil {
		return 0, false
	}
	return parseMaxAnalyzedOffsetFromSettingsMapR61Search(customSettingsByIdx[indexName])
}

func parseMaxAnalyzedOffsetFromSettingsMapR61Search(m map[string]any) (int, bool) {
	if len(m) == 0 {
		return 0, false
	}
	for _, key := range []string{"index.highlight.max_analyzed_offset", "highlight.max_analyzed_offset"} {
		if v, ok := m[key]; ok && v != nil {
			if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil {
				return n, true
			}
		}
	}
	if idxMap, ok := m["index"].(map[string]any); ok {
		if v, okV := idxMap["highlight.max_analyzed_offset"]; okV && v != nil {
			if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil {
				return n, true
			}
		}
		if hlMap, okH := idxMap["highlight"].(map[string]any); okH {
			if v, okV := hlMap["max_analyzed_offset"]; okV && v != nil {
				if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil {
					return n, true
				}
			}
		}
	}
	if hlMap, ok := m["highlight"].(map[string]any); ok {
		if v, okV := hlMap["max_analyzed_offset"]; okV && v != nil {
			if n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", v))); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func expandHighlightTargetFieldsInSchemaR61Search(sc *schema.IndexSchema, pattern string) []string {
	if sc == nil {
		return nil
	}
	if !strings.ContainsAny(pattern, "*?") {
		if _, ok := sc.Fields[pattern]; ok {
			return []string{pattern}
		}
		if _, ok := lookupRawPropertyWithMultiFieldR61Search(sc, pattern); ok {
			return []string{pattern}
		}
		return nil
	}
	var out []string
	for fn := range sc.Fields {
		if strings.HasSuffix(fn, ".keyword") || strings.HasSuffix(fn, ".ngram") {
			continue
		}
		if matchWildcardPattern(pattern, fn) {
			out = append(out, fn)
		}
	}
	sort.Strings(out)
	return out
}

func fieldHasTermVectorPositionsOffsetsR61Search(
	sc *schema.IndexSchema,
	fieldName string,
	customSettingsByIdx map[string]map[string]any,
) bool {
	if customSettingsByIdx != nil && sc != nil {
		if m := customSettingsByIdx[sc.IndexName]; m != nil {
			for _, k := range []string{"__term_vector." + fieldName, "term_vector." + fieldName} {
				if v, ok := m[k]; ok && strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", v)), "with_positions_offsets") {
					return true
				}
			}
		}
	}
	if sc == nil {
		return false
	}
	if fp, ok := lookupRawPropertyWithMultiFieldR61Search(sc, fieldName); ok {
		if tv := extractFieldPropertyTermVectorR61Search(fp); strings.EqualFold(tv, "with_positions_offsets") {
			return true
		}
	}
	if b, ok := sc.Fields[fieldName]; ok && b.Meta != nil {
		if tv := b.Meta["term_vector"]; strings.EqualFold(tv, "with_positions_offsets") {
			return true
		}
		if tv := b.Meta["__term_vector"]; strings.EqualFold(tv, "with_positions_offsets") {
			return true
		}
	}
	return false
}

func extractFieldPropertyTermVectorR61Search(fp esast.FieldProperty) string {
	rv := reflect.ValueOf(fp)
	if f := rv.FieldByName("TermVector"); f.IsValid() && f.Kind() == reflect.String {
		if s := strings.TrimSpace(f.String()); s != "" {
			return s
		}
	}
	if fp.Meta != nil {
		if tv := strings.TrimSpace(fp.Meta["term_vector"]); tv != "" {
			return tv
		}
		if tv := strings.TrimSpace(fp.Meta["__term_vector"]); tv != "" {
			return tv
		}
	}
	return ""
}

func fieldHasIndexOffsetsOrTermVectorOffsetsR61Search(sc *schema.IndexSchema, fieldName string) bool {
	if sc == nil {
		return false
	}
	if fp, ok := lookupRawPropertyWithMultiFieldR61Search(sc, fieldName); ok {
		if optStr, isStr := fp.IndexOptions.(string); isStr && strings.EqualFold(strings.TrimSpace(optStr), "offsets") {
			return true
		}
		if strings.EqualFold(extractFieldPropertyTermVectorR61Search(fp), "with_positions_offsets") {
			return true
		}
	}
	return false
}

func fieldIsStoredInSchemaR61Search(sc *schema.IndexSchema, fieldName string) bool {
	if sc == nil {
		return false
	}
	if fp, ok := lookupRawPropertyWithMultiFieldR61Search(sc, fieldName); ok {
		return fp.Store != nil && *fp.Store
	}
	return false
}

func fieldIsMultiValuedInSchemaR61Search(sc *schema.IndexSchema, fieldName string) bool {
	if sc == nil {
		return false
	}
	if b, ok := sc.Fields[fieldName]; ok && b.IsMultiValued {
		return true
	}
	if fp, ok := lookupRawPropertyWithMultiFieldR61Search(sc, fieldName); ok {
		return fp.MultiValued
	}
	return false
}

// checkHighlightDocMaxAnalyzedOffsetR61Search checks document field lengths against `index.highlight.max_analyzed_offset`
// and request `max_analyzed_offset`, mutating `doc` in-place to filter values exceeding `b.IgnoreAbove` (and reconstructing
// synthetic `_source` when `idxSchema.SyntheticSource` is enabled):
//   - If `indexMaxAnalyzedOffset >= 0` and request `max_analyzed_offset` is NOT set, exceeding `indexMaxAnalyzedOffset`
//     on an analyzed highlighter (`plain`, or `unified` without `index_options: offsets` / `term_vector: with_positions_offsets`)
//     returns `400 illegal_argument_exception`.
//   - If request `max_analyzed_offset` IS set (`<= index limit`), returns `truncLimit = reqMaxOffset` without error.
func checkHighlightDocMaxAnalyzedOffsetR61Search(
	doc map[string]any,
	req *esast.SearchRequest,
	idxSchema *schema.IndexSchema,
	indexMaxAnalyzedOffset int,
) (truncLimit int, status int, errType, errReason string) {
	truncLimit = -1
	if doc == nil || req == nil || req.Highlight == nil {
		return -1, 0, "", ""
	}
	hl := req.Highlight
	if hl.MaxAnalyzedOffset != nil {
		truncLimit = *hl.MaxAnalyzedOffset
	}

	// Reconstruct synthetic `_source` into `doc` if index uses synthetic `_source`
	if idxSchema != nil && idxSchema.SyntheticSource {
		rawBytes, err := json.Marshal(doc)
		if err == nil {
			reconBytes := reconstructHitSyntheticSourceR61Search(rawBytes, idxSchema)
			var reconMap map[string]any
			dec := json.NewDecoder(bytes.NewReader(reconBytes))
			dec.UseNumber()
			if dec.Decode(&reconMap) == nil && reconMap != nil {
				for k := range doc {
					if !strings.HasPrefix(k, "__") {
						delete(doc, k)
					}
				}
				for k, v := range reconMap {
					doc[k] = v
				}
			}
		}
	}

	// Strip values exceeding `b.IgnoreAbove` in-place so `keyword` fields with `ignore_above` are skipped by highlighter (`40_keyword_ignore.yml`).
	if idxSchema != nil {
		for fn, b := range idxSchema.Fields {
			if b.IgnoreAbove > 0 {
				segs := effectiveSourceSegsR61Search(fn, b)
				filterIgnoreAboveInPlace(doc, segs, b.IgnoreAbove)
			}
		}
	}

	fieldKeys := make([]string, 0, len(hl.Fields))
	for fn := range hl.Fields {
		fieldKeys = append(fieldKeys, fn)
	}
	sort.Strings(fieldKeys)

	for _, fn := range fieldKeys {
		fSpec := hl.FieldSpec(fn)
		reqLimit := -1
		if fSpec.MaxAnalyzedOffset != nil {
			reqLimit = *fSpec.MaxAnalyzedOffset
			if truncLimit < 0 || reqLimit < truncLimit {
				truncLimit = reqLimit
			}
		} else if hl.MaxAnalyzedOffset != nil {
			reqLimit = *hl.MaxAnalyzedOffset
		}

		effType := strings.ToLower(strings.TrimSpace(fSpec.Type))
		if effType == "" {
			effType = strings.ToLower(strings.TrimSpace(hl.Type))
		}
		if effType == "" {
			effType = "unified"
		}

		var candidateFields []string
		if strings.ContainsAny(fn, "*?") {
			leaves := make(map[string][]any)
			collectAllLeafScalarPathsExceptFlattenedR61Search(doc, "", idxSchema, leaves)
			for lk := range leaves {
				if matchWildcardPattern(fn, lk) {
					candidateFields = append(candidateFields, lk)
				}
			}
			sort.Strings(candidateFields)
		} else {
			candidateFields = []string{fn}
		}

		for _, cf := range candidateFields {
			if effType == "fvh" || effType == "fast-vector-highlighter" {
				// FVH uses stored term vectors unless `matched_fields` references non-FVH subfields; check synthetic multi-value guard!
				if idxSchema != nil && idxSchema.SyntheticSource && !fieldIsStoredInSchemaR61Search(idxSchema, cf) {
					fvhSegs := effectiveTokenCountSourceSegsR61Search(cf, idxSchema.ResolveField(cf), idxSchema)
					if rawNode, exists := lookupNestedMapPathR61Search(doc, fvhSegs); exists {
						if arr, isArr := rawNode.([]any); isArr && len(arr) > 1 {
							return -1,
								http.StatusBadRequest,
								"illegal_argument_exception",
								fmt.Sprintf("The fast vector highlighter doesn't support loading multi-valued fields from _source in index [%s] because _source can reorder field values", idxSchema.IndexName)
						}
					}
				}
				continue
			}
			if effType == "unified" && fieldHasIndexOffsetsOrTermVectorOffsetsR61Search(idxSchema, cf) && (fSpec.ForceSource == nil || !*fSpec.ForceSource) && (hl.ForceSource == nil || !*hl.ForceSource) {
				// `unified` highlighter reads postings/term_vectors directly without re-analyzing text when offsets were indexed!
				continue
			}

			var b schema.FieldBinding
			if idxSchema != nil {
				b = idxSchema.ResolveField(cf)
			}
			segs := effectiveSourceSegsR61Search(cf, b)
			vals := collectScalarValuesAtPath(doc, segs)
			totalChars := 0
			for i, rv := range vals {
				s := formatRawScalarStringR61Search(rv)
				if b.IgnoreAbove > 0 && utf8.RuneCountInString(s) > b.IgnoreAbove {
					continue
				}
				if i > 0 {
					totalChars++ // multi-value offset separator
				}
				totalChars += utf8.RuneCountInString(s)
			}

			if indexMaxAnalyzedOffset >= 0 && reqLimit < 0 && totalChars > indexMaxAnalyzedOffset {
				docID, _ := doc["__meta_id"].(string)
				if docID == "" {
					docID = "0"
				}
				idxName := "_index"
				if idxSchema != nil && idxSchema.IndexName != "" {
					idxName = idxSchema.IndexName
				}
				return -1,
					http.StatusBadRequest,
					"illegal_argument_exception",
					fmt.Sprintf(
						"The length [%d] of field [%s] of doc [%s]/[%s] exceeds the [index.highlight.max_analyzed_offset] limit [%d]. To avoid this error, set the query parameter [max_analyzed_offset] to a value less than index setting [%d] and this will tolerate long field values by truncating them.",
						totalChars, cf, docID, idxName, indexMaxAnalyzedOffset, indexMaxAnalyzedOffset,
					)
			}
		}
	}
	return truncLimit, 0, "", ""
}

const geohashBase32AlphabetR61Search = "0123456789bcdefghjkmnpqrstuvwxyz"

func encodeGeohashR61Search(lat, lon float64, precision int) string {
	if precision < 1 {
		precision = 1
	}
	if precision > 12 {
		precision = 12
	}
	latMin, latMax := -90.0, 90.0
	lonMin, lonMax := -180.0, 180.0
	var out strings.Builder
	out.Grow(precision)
	isEven := true
	bit := 0
	chIdx := 0
	for out.Len() < precision {
		if isEven {
			mid := (lonMin + lonMax) / 2.0
			if lon >= mid {
				chIdx = (chIdx << 1) | 1
				lonMin = mid
			} else {
				chIdx <<= 1
				lonMax = mid
			}
		} else {
			mid := (latMin + latMax) / 2.0
			if lat >= mid {
				chIdx = (chIdx << 1) | 1
				latMin = mid
			} else {
				chIdx <<= 1
				latMax = mid
			}
		}
		isEven = !isEven
		bit++
		if bit == 5 {
			out.WriteByte(geohashBase32AlphabetR61Search[chIdx])
			bit = 0
			chIdx = 0
		}
	}
	return out.String()
}

func decodeGeohashBBoxR61Search(hash string) (latMin, latMax, lonMin, lonMax float64, ok bool) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if hash == "" {
		return 0, 0, 0, 0, false
	}
	latMin, latMax = -90.0, 90.0
	lonMin, lonMax = -180.0, 180.0
	isEven := true
	for i := 0; i < len(hash); i++ {
		idx := strings.IndexByte(geohashBase32AlphabetR61Search, hash[i])
		if idx < 0 {
			return 0, 0, 0, 0, false
		}
		for mask := 16; mask > 0; mask >>= 1 {
			if isEven {
				mid := (lonMin + lonMax) / 2.0
				if idx&mask != 0 {
					lonMin = mid
				} else {
					lonMax = mid
				}
			} else {
				mid := (latMin + latMax) / 2.0
				if idx&mask != 0 {
					latMin = mid
				} else {
					latMax = mid
				}
			}
			isEven = !isEven
		}
	}
	return latMin, latMax, lonMin, lonMax, true
}

func geohashCenterAndEightNeighboursR61Search(hash string) []string {
	latMin, latMax, lonMin, lonMax, ok := decodeGeohashBBoxR61Search(hash)
	if !ok {
		return []string{hash}
	}
	p := len(hash)
	dLat := latMax - latMin
	dLon := lonMax - lonMin
	cLat := (latMin + latMax) / 2.0
	cLon := (lonMin + lonMax) / 2.0

	seen := map[string]bool{hash: true}
	out := []string{hash}
	for dy := -1; dy <= 1; dy++ {
		for dx := -1; dx <= 1; dx++ {
			if dy == 0 && dx == 0 {
				continue
			}
			nLat := cLat + float64(dy)*dLat
			if nLat > 90.0 || nLat < -90.0 {
				continue
			}
			nLon := cLon + float64(dx)*dLon
			if nLon > 180.0 {
				nLon -= 360.0
			} else if nLon < -180.0 {
				nLon += 360.0
			}
			nh := encodeGeohashR61Search(nLat, nLon, p)
			if !seen[nh] {
				seen[nh] = true
				out = append(out, nh)
			}
		}
	}
	return out
}

func parseCompletionGeoPrecisionR61Search(raw any) int {
	if raw == nil {
		return 6
	}
	switch v := raw.(type) {
	case int:
		if v >= 1 && v <= 12 {
			return v
		}
	case int64:
		if v >= 1 && v <= 12 {
			return int(v)
		}
	case float64:
		iv := int(v)
		if iv >= 1 && iv <= 12 {
			return iv
		}
	case json.Number:
		if iv, err := v.Int64(); err == nil && iv >= 1 && iv <= 12 {
			return int(iv)
		}
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		if iv, err := strconv.Atoi(s); err == nil && iv >= 1 && iv <= 12 {
			return iv
		}
		// Distance string (`5km`, `100m`, `1mi`, etc.) -> ES `GeoHashUtils` precision cell length!
		meters, ok := parseDistanceStringToMetersR61Search(s)
		if ok {
			return distanceMetersToGeohashPrecisionR61Search(meters)
		}
	}
	return 6
}

func parseDistanceStringToMetersR61Search(s string) (float64, bool) {
	units := []struct {
		suffix string
		factor float64
	}{
		{"kilometers", 1000.0},
		{"kilometer", 1000.0},
		{"meters", 1.0},
		{"meter", 1.0},
		{"miles", 1609.344},
		{"mile", 1609.344},
		{"yards", 0.9144},
		{"yard", 0.9144},
		{"feet", 0.3048},
		{"foot", 0.3048},
		{"inch", 0.0254},
		{"nmi", 1852.0},
		{"km", 1000.0},
		{"cm", 0.01},
		{"mm", 0.001},
		{"mi", 1609.344},
		{"yd", 0.9144},
		{"ft", 0.3048},
		{"in", 0.0254},
		{"m", 1.0},
	}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			numPart := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			if fv, err := strconv.ParseFloat(numPart, 64); err == nil && fv > 0 {
				return fv * u.factor, true
			}
		}
	}
	return 0, false
}

func distanceMetersToGeohashPrecisionR61Search(meters float64) int {
	// Standard Lucene/ES geohash cell width thresholds (meters at equator):
	thresholds := []struct {
		maxMeters float64
		prec      int
	}{
		{0.037, 12},
		{0.149, 11},
		{1.19, 10},
		{4.77, 9},
		{38.2, 8},
		{152.9, 7},
		{1223.0, 6},
		{4892.0, 5},
		{39136.0, 4},
		{156544.0, 3},
		{1252355.0, 2},
	}
	for _, t := range thresholds {
		if meters <= t.maxMeters {
			return t.prec
		}
	}
	return 1
}

func parseCompletionGeoContextHashR61Search(raw any, precision int) (string, bool) {
	if s, ok := raw.(string); ok {
		st := strings.TrimSpace(s)
		// Could be a raw geohash like `"u09tun"` (no comma/space/WKT) or `"lat,lon"`!
		if st != "" && !strings.ContainsAny(st, ", ()") {
			if _, _, _, _, validHash := decodeGeohashBBoxR61Search(st); validHash {
				if len(st) > precision {
					return strings.ToLower(st[:precision]), true
				}
				return strings.ToLower(st), true
			}
		}
	}
	lat, lon, err := esast.ParseGeoPoint(raw)
	if err != nil {
		return "", false
	}
	return encodeGeohashR61Search(lat, lon, precision), true
}

type completionDocEntryR61Search struct {
	inputs   []string
	weight   float64
	contexts map[string][]any
}

func extractCompletionEntriesFromDocR61Search(doc map[string]any, segs []string) []completionDocEntryR61Search {
	rawNode, exists := lookupNestedMapPathR61Search(doc, segs)
	if !exists || rawNode == nil {
		return nil
	}
	var out []completionDocEntryR61Search
	var parseNode func(n any)
	parseNode = func(n any) {
		switch tv := n.(type) {
		case string:
			if tv != "" {
				out = append(out, completionDocEntryR61Search{inputs: []string{tv}, weight: 1.0})
			}
		case []any:
			// Check if slice of strings vs slice of completion objects
			allStrings := true
			var strs []string
			for _, elem := range tv {
				if s, ok := elem.(string); ok {
					if s != "" {
						strs = append(strs, s)
					}
				} else {
					allStrings = false
				}
			}
			if allStrings && len(strs) > 0 {
				out = append(out, completionDocEntryR61Search{inputs: strs, weight: 1.0})
				return
			}
			for _, elem := range tv {
				parseNode(elem)
			}
		case map[string]any:
			rawInput, hasIn := tv["input"]
			if !hasIn || rawInput == nil {
				return
			}
			var inputs []string
			switch iv := rawInput.(type) {
			case string:
				if iv != "" {
					inputs = []string{iv}
				}
			case []any:
				for _, item := range iv {
					if s, ok := item.(string); ok && s != "" {
						inputs = append(inputs, s)
					}
				}
			case []string:
				for _, s := range iv {
					if s != "" {
						inputs = append(inputs, s)
					}
				}
			}
			if len(inputs) == 0 {
				return
			}
			weight := 1.0
			if rawW, hasW := tv["weight"]; hasW && rawW != nil {
				if fv, okF := parseFiniteFloatFromAnyR61Search(rawW, true); okF && fv >= 0 {
					weight = fv
				}
			}
			var ctxs map[string][]any
			if rawC, hasC := tv["contexts"].(map[string]any); hasC && len(rawC) > 0 {
				ctxs = make(map[string][]any, len(rawC))
				for ck, cv := range rawC {
					if arr, isArr := cv.([]any); isArr {
						// Distinguish `[lon, lat]` single geo coordinate pair from array of contexts!
						if len(arr) == 2 {
							_, ok0 := parseFiniteFloatFromAnyR61Search(arr[0], false)
							_, ok1 := parseFiniteFloatFromAnyR61Search(arr[1], false)
							if ok0 && ok1 {
								ctxs[ck] = []any{arr}
								continue
							}
						}
						ctxs[ck] = arr
					} else if cv != nil {
						ctxs[ck] = []any{cv}
					}
				}
			}
			out = append(out, completionDocEntryR61Search{
				inputs:   inputs,
				weight:   weight,
				contexts: ctxs,
			})
		}
	}
	parseNode(rawNode)
	return out
}

func resolveDocCompletionContextValuesR61Search(
	doc map[string]any,
	entry completionDocEntryR61Search,
	ctxDefs []esast.CompletionContextDef,
) map[string][]string {
	if len(ctxDefs) == 0 {
		return nil
	}
	out := make(map[string][]string, len(ctxDefs))
	for _, def := range ctxDefs {
		var rawItems []any
		if entry.contexts != nil && len(entry.contexts[def.Name]) > 0 {
			rawItems = entry.contexts[def.Name]
		} else if strings.TrimSpace(def.Path) != "" {
			if pathNode, exists := lookupNestedMapPathR61Search(doc, strings.Split(def.Path, ".")); exists && pathNode != nil {
				if arr, isArr := pathNode.([]any); isArr {
					if strings.EqualFold(def.Type, "geo") && len(arr) == 2 {
						_, ok0 := parseFiniteFloatFromAnyR61Search(arr[0], false)
						_, ok1 := parseFiniteFloatFromAnyR61Search(arr[1], false)
						if ok0 && ok1 {
							rawItems = []any{arr}
						} else {
							rawItems = arr
						}
					} else {
						rawItems = arr
					}
				} else {
					rawItems = []any{pathNode}
				}
			}
		}
		if len(rawItems) == 0 && def.Default != nil {
			if arr, isArr := def.Default.([]any); isArr {
				rawItems = arr
			} else {
				rawItems = []any{def.Default}
			}
		}
		if len(rawItems) == 0 {
			continue
		}

		if strings.EqualFold(def.Type, "geo") {
			var defPrec int
			if def.Precision != nil {
				// Index-time `precision` can be an array like `[1, "5km"]` or a single precision
				if pArr, isPArr := def.Precision.([]any); isPArr && len(pArr) > 0 {
					maxP := 1
					for _, elem := range pArr {
						if p := parseCompletionGeoPrecisionR61Search(elem); p > maxP {
							maxP = p
						}
					}
					defPrec = maxP
				} else {
					defPrec = parseCompletionGeoPrecisionR61Search(def.Precision)
				}
			} else {
				defPrec = 12
			}
			for _, item := range rawItems {
				if gh, ok := parseCompletionGeoContextHashR61Search(item, defPrec); ok {
					out[def.Name] = append(out[def.Name], gh)
				}
			}
		} else {
			for _, item := range rawItems {
				if item != nil {
					out[def.Name] = append(out[def.Name], formatRawScalarStringR61Search(item))
				}
			}
		}
	}
	return out
}

func evaluateCompletionContextsBoostR61Search(
	docCtxs map[string][]string,
	ctxDefs []esast.CompletionContextDef,
	queryCtxs map[string][]esast.CompletionQueryContext,
) (matched bool, totalBoost float64, outCtxMap map[string]any, status int, errType, errReason string) {
	if len(ctxDefs) == 0 {
		if len(queryCtxs) > 0 {
			return false, 0, nil, http.StatusBadRequest,
				"illegal_argument_exception",
				"Completion field has no context mappings defined, cannot execute context query"
		}
		return true, 1.0, nil, 0, "", ""
	}

	defByName := make(map[string]esast.CompletionContextDef, len(ctxDefs))
	for _, d := range ctxDefs {
		defByName[d.Name] = d
	}
	for qName := range queryCtxs {
		if _, ok := defByName[qName]; !ok {
			return false, 0, nil, http.StatusBadRequest,
				"illegal_argument_exception",
				fmt.Sprintf("Unknown context [%s] in completion suggester", qName)
		}
	}

	// Mandatory context check (`30_context.yml:360-397`):
	// In ES ContextSuggest, at least one defined context must have non-empty query clauses!
	hasAnyQueryClause := false
	for _, list := range queryCtxs {
		if len(list) > 0 {
			hasAnyQueryClause = true
			break
		}
	}
	if !hasAnyQueryClause {
		return false, 0, nil, http.StatusBadRequest,
			"illegal_argument_exception",
			"Missing mandatory contexts in context query"
	}

	// In ES Completion Suggester, contextclauses across queryCtxs act as weighted OR boosts across clauses
	// (matching any queried context clause, summing/taking max boost per ES ContextQuery!).
	// Wait: let's check `30_context.yml`! In ES `ContextQuery`, multiple contexts in `contexts: { place_type: [...], location: [...] }`:
	// Each clause in `contexts` adds `weight * clause.Boost` when matched; let's check whether multiple context categories are OR'd or AND'd!
	// In ES `ContextQuery.java`: all clauses across all context names are added as `SHOULD` clauses in a `BooleanContextQuery`!
	// Specifically, a suggestion matches if AT LEAST ONE clause in `queryCtxs` matches, and its context boost is the MAX (or SUM? Wait: in FST Completion Suggester, each `(input, contextToken)` path in the FST has score `entry.weight * clause.boost`, and the top path per document/suggestion wins = `MAX` over matched `(context, clause)` paths!).
	bestBoost := -1.0
	matchedCtxOut := make(map[string][]string)

	for ctxName, qList := range queryCtxs {
		def := defByName[ctxName]
		docVals := docCtxs[ctxName]
		if len(docVals) == 0 {
			continue
		}
		isGeo := strings.EqualFold(def.Type, "geo")
		for _, qc := range qList {
			b := qc.Boost
			if b == 0 {
				b = 1.0
			}
			if !isGeo {
				qCat := formatRawScalarStringR61Search(qc.Context)
				for _, dv := range docVals {
					okMatch := false
					if qc.Prefix {
						okMatch = strings.HasPrefix(dv, qCat)
					} else {
						okMatch = dv == qCat
					}
					if okMatch {
						if b > bestBoost {
							bestBoost = b
						}
						matchedCtxOut[ctxName] = appendUniqueStringR61Search(matchedCtxOut[ctxName], dv)
					}
				}
			} else {
				// Geo context: check `qc.Precision` (defaulting to `def.Precision` or 6) AND `qc.Neighbours` precisions!
				basePrec := 6
				if qc.Precision != nil {
					basePrec = parseCompletionGeoPrecisionR61Search(qc.Precision)
				} else if def.Precision != nil {
					if pArr, isArr := def.Precision.([]any); isArr && len(pArr) > 0 {
						basePrec = parseCompletionGeoPrecisionR61Search(pArr[0])
					} else {
						basePrec = parseCompletionGeoPrecisionR61Search(def.Precision)
					}
				}
				qHash, okGH := parseCompletionGeoContextHashR61Search(qc.Context, basePrec)
				if !okGH {
					return false, 0, nil, http.StatusBadRequest,
						"illegal_argument_exception",
						fmt.Sprintf("Failed to parse geo context in [%s]", ctxName)
				}
				candHashes := map[string]bool{qHash: true}
				for _, nbRaw := range qc.Neighbours {
					nbPrec := parseCompletionGeoPrecisionR61Search(nbRaw)
					nbCenter, okNB := parseCompletionGeoContextHashR61Search(qc.Context, nbPrec)
					if okNB {
						for _, adj := range geohashCenterAndEightNeighboursR61Search(nbCenter) {
							candHashes[adj] = true
						}
					}
				}
				for _, dv := range docVals {
					for ch := range candHashes {
						// Prefix-compatible geohash match (`dv` is cell at index precision, `ch` is cell at query precision)
						minLen := len(ch)
						if len(dv) < minLen {
							minLen = len(dv)
						}
						if minLen > 0 && strings.HasPrefix(dv, ch[:minLen]) && len(dv) >= len(ch) {
							if b > bestBoost {
								bestBoost = b
							}
							matchedCtxOut[ctxName] = appendUniqueStringR61Search(matchedCtxOut[ctxName], dv[:len(ch)])
						} else if minLen > 0 && dv == ch {
							if b > bestBoost {
								bestBoost = b
							}
							matchedCtxOut[ctxName] = appendUniqueStringR61Search(matchedCtxOut[ctxName], dv)
						}
					}
				}
			}
		}
	}

	if bestBoost < 0 {
		return false, 0, nil, 0, "", ""
	}
	outMap := make(map[string]any, len(matchedCtxOut))
	for k, vals := range matchedCtxOut {
		sort.Strings(vals)
		arr := make([]any, len(vals))
		for i, s := range vals {
			arr[i] = s
		}
		outMap[k] = arr
	}
	return true, bestBoost, outMap, 0, "", ""
}

func appendUniqueStringR61Search(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

func normalizeCompletionStringR61Search(s, analyzer string) string {
	an := strings.ToLower(strings.TrimSpace(analyzer))
	if an == "whitespace" || an == "keyword" {
		return s
	}
	// Default `simple` / `standard` completion analyzer lowercases and collapses non-letter/digit runs or trims leading spaces
	toks := transpiler.TokenizeByAnalyzer(s, analyzer)
	if len(toks) == 0 {
		return strings.ToLower(strings.TrimSpace(s))
	}
	return strings.Join(toks, " ")
}

func damerauLevenshteinDistanceR61Search(a, b []rune, transpositions bool) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
		dp[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			best := dp[i-1][j] + 1
			if ins := dp[i][j-1] + 1; ins < best {
				best = ins
			}
			if sub := dp[i-1][j-1] + cost; sub < best {
				best = sub
			}
			if transpositions && i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				if tr := dp[i-2][j-2] + cost; tr < best {
					best = tr
				}
			}
			dp[i][j] = best
		}
	}
	return dp[la][lb]
}

func matchesCompletionPrefixOrFuzzyR61Search(normInput, normPrefix string, fuzzyCfg map[string]any) bool {
	if normPrefix == "" {
		return true
	}
	if strings.HasPrefix(normInput, normPrefix) {
		return true
	}
	if fuzzyCfg == nil {
		return false
	}
	pRunes := []rune(normPrefix)
	inRunes := []rune(normInput)

	minLen := 3
	if v, ok := toFloat64(fuzzyCfg["min_length"]); ok && int(v) >= 0 {
		minLen = int(v)
	}
	prefixLen := 1
	if v, ok := toFloat64(fuzzyCfg["prefix_length"]); ok && int(v) >= 0 {
		prefixLen = int(v)
	}
	transpositions := true
	if b, ok := fuzzyCfg["transpositions"].(bool); ok {
		transpositions = b
	}
	if len(pRunes) < minLen {
		return false
	}
	if prefixLen > 0 {
		if len(inRunes) < prefixLen || len(pRunes) < prefixLen {
			return false
		}
		for i := 0; i < prefixLen; i++ {
			if inRunes[i] != pRunes[i] {
				return false
			}
		}
	}
	maxEdits := resolveCompletionFuzzyEditsR61Search(fuzzyCfg["fuzziness"], len(pRunes))
	if maxEdits <= 0 {
		return false
	}
	minCandLen := len(pRunes) - maxEdits
	if minCandLen < prefixLen {
		minCandLen = prefixLen
	}
	if minCandLen < 1 {
		minCandLen = 1
	}
	maxCandLen := len(pRunes) + maxEdits
	if maxCandLen > len(inRunes) {
		maxCandLen = len(inRunes)
	}
	for k := minCandLen; k <= maxCandLen; k++ {
		if damerauLevenshteinDistanceR61Search(pRunes, inRunes[:k], transpositions) <= maxEdits {
			return true
		}
	}
	return false
}

func resolveCompletionFuzzyEditsR61Search(raw any, runeLen int) int {
	if raw == nil {
		if runeLen <= 2 {
			return 0
		}
		if runeLen <= 5 {
			return 1
		}
		return 2
	}
	switch v := raw.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		s := strings.ToUpper(strings.TrimSpace(v))
		switch s {
		case "0":
			return 0
		case "1":
			return 1
		case "2":
			return 2
		default: // AUTO or AUTO:low,high
			low, high := 3, 6
			if strings.HasPrefix(s, "AUTO:") {
				parts := strings.Split(strings.TrimPrefix(s, "AUTO:"), ",")
				if len(parts) == 2 {
					if l, errL := strconv.Atoi(strings.TrimSpace(parts[0])); errL == nil {
						low = l
					}
					if h, errH := strconv.Atoi(strings.TrimSpace(parts[1])); errH == nil {
						high = h
					}
				}
			}
			if runeLen < low {
				return 0
			}
			if runeLen < high {
				return 1
			}
			return 2
		}
	}
	return 1
}

// evaluateCompletionSuggestSpecR61Search executes full ES `completion` suggester runtime evaluation:
//   - Honors `b.SourceJSONPath` and document completion values as `"str"`, `["s1", "s2"]`, or `{input, weight, contexts}`.
//   - Enforces mandatory `b.Contexts` (`400 illegal_argument_exception` when field defines contexts and query omits them).
//   - Evaluates `category` & `geo` contexts (geohash/lat-lon precision + 8-cell `neighbours` adjacency) + `boost`.
//   - Supports `fuzzy` prefix edit distance, `regex` mode, and `skip_duplicates: true`.
func evaluateCompletionSuggestSpecR61Search(
	s *Server,
	ctx context.Context,
	targets []string,
	globalText string,
	sugSpec esast.SuggestSpec,
) ([]map[string]any, int, string, string) {
	return evaluateCompletionSuggestSpecWithAliasesR61Search(s, ctx, targets, nil, globalText, sugSpec)
}

func evaluateCompletionSuggestSpecWithAliasesR61Search(
	s *Server,
	ctx context.Context,
	targets []string,
	aliasFilters map[string]*esast.Query,
	globalText string,
	sugSpec esast.SuggestSpec,
) ([]map[string]any, int, string, string) {
	if sugSpec.Completion == nil {
		return nil, 0, "", ""
	}
	cs := sugSpec.Completion
	size := cs.Size
	if size <= 0 {
		size = 5
	}
	skipDuplicates := cs.SkipDuplicates || (cs.SkipDuplicatesPtr != nil && *cs.SkipDuplicatesPtr)

	isRegexMode := sugSpec.Regex != "" || cs.Regex != nil
	rawInputQuery := sugSpec.Prefix
	if rawInputQuery == "" && cs.Prefix != "" {
		rawInputQuery = cs.Prefix
	}
	if rawInputQuery == "" && sugSpec.Text != "" {
		rawInputQuery = sugSpec.Text
	}
	if rawInputQuery == "" {
		rawInputQuery = globalText
	}
	if isRegexMode && sugSpec.Regex != "" {
		rawInputQuery = sugSpec.Regex
	}

	var compiledRegex *regexp.Regexp
	if isRegexMode {
		var rErr error
		compiledRegex, rErr = regexp.Compile("^(?:" + rawInputQuery + ")")
		if rErr != nil {
			return nil, http.StatusBadRequest, "illegal_argument_exception", fmt.Sprintf("invalid completion regex [%s]: %v", rawInputQuery, rErr)
		}
	}

	type scoredCompletionOptR61Search struct {
		text      string
		score     float64
		index     string
		id        string
		routing   string
		sourceMap map[string]any
		contexts  map[string]any
	}

	var candidates []scoredCompletionOptR61Search

	for _, indexName := range targets {
		if s == nil {
			continue
		}
		idxSchema := s.getOrCompileReadOnlySchema(ctx, indexName)
		if idxSchema == nil {
			continue
		}
		b := idxSchema.ResolveField(cs.Field)
		if b.ESType != "" && !strings.EqualFold(b.ESType, "completion") && !strings.EqualFold(b.ESType, "text") && !strings.EqualFold(b.ESType, "keyword") && !strings.EqualFold(b.ESType, "search_as_you_type") {
			return nil, http.StatusBadRequest,
				"illegal_argument_exception",
				fmt.Sprintf("Field [%s] is not a completion suggest field (mapped as [%s])", cs.Field, b.ESType)
		}

		// Validate mandatory contexts even if index currently has 0 docs!
		if len(b.Contexts) > 0 {
			hasDefault := true
			for _, cd := range b.Contexts {
				if cd.Default == nil {
					hasDefault = false
					break
				}
			}
			hasProvided := false
			for _, ql := range cs.Contexts {
				if len(ql) > 0 {
					hasProvided = true
					break
				}
			}
			if !hasDefault && !hasProvided {
				return nil, http.StatusBadRequest,
					"illegal_argument_exception",
					"Missing mandatory contexts in context query"
			}
			defSet := make(map[string]bool, len(b.Contexts))
			for _, cd := range b.Contexts {
				defSet[cd.Name] = true
			}
			for qk := range cs.Contexts {
				if !defSet[qk] {
					return nil, http.StatusBadRequest,
						"illegal_argument_exception",
						fmt.Sprintf("Unknown context [%s] in completion suggester", qk)
				}
			}
		} else if len(cs.Contexts) > 0 {
			return nil, http.StatusBadRequest,
				"illegal_argument_exception",
				fmt.Sprintf("Completion field [%s] has no context mappings defined", cs.Field)
		}

		if s.backend == nil {
			continue
		}
		if s.coalescer != nil && idxSchema.DorisTable != "" {
			_ = s.coalescer.FlushTable(ctx, idxSchema.DorisTable)
		}

		fetchSize := 10000
		var af *esast.Query
		if aliasFilters != nil {
			af = aliasFilters[indexName]
		}
		var sqlQuery *esast.Query
		if af != nil && !queryHasRuntimeScript(af) {
			sqlQuery = af
		}
		tr := transpiler.NewTranspiler(idxSchema, s.transpileOpts)
		plan, err := tr.BuildSearchPlan(&esast.SearchRequest{Size: &fetchSize, Query: sqlQuery})
		if err != nil || plan.HitsSQL == "" {
			continue
		}
		rows, err := s.backend.QueryHits(ctx, plan.HitsSQL)
		if err != nil {
			continue
		}

		effAnalyzer := cs.Analyzer
		if effAnalyzer == "" {
			if b.SearchAnalyzer != "" {
				effAnalyzer = b.SearchAnalyzer
			} else if b.Analyzer != "" {
				effAnalyzer = b.Analyzer
			} else {
				effAnalyzer = "simple"
			}
		}
		normPrefix := normalizeCompletionStringR61Search(rawInputQuery, effAnalyzer)
		segs := effectiveSourceSegsR61Search(cs.Field, b)

		for _, hr := range rows {
			var doc map[string]any
			srcBytes := hr.EffectiveSource()
			if len(srcBytes) == 0 {
				continue
			}
			dec := json.NewDecoder(bytes.NewReader(srcBytes))
			dec.UseNumber()
			if dec.Decode(&doc) != nil || doc == nil {
				continue
			}
			if af != nil {
				doc["__meta_id"] = hr.ID
				matchedAF := evalBranchMatchesDoc(idxSchema, doc, af)
				if matchedAF && queryHasRuntimeScript(af) {
					matchedAF = evalQueryScriptFilterOnDocWithSchema(idxSchema, doc, af)
				}
				delete(doc, "__meta_id")
				if !matchedAF {
					continue
				}
			}

			entries := extractCompletionEntriesFromDocR61Search(doc, segs)
			if len(entries) == 0 {
				continue
			}

			for _, entry := range entries {
				ctxBoost := 1.0
				var matchedCtxMap map[string]any
				if len(b.Contexts) > 0 {
					docCtxVals := resolveDocCompletionContextValuesR61Search(doc, entry, b.Contexts)
					okCtx, cb, cm, st, errT, errR := evaluateCompletionContextsBoostR61Search(docCtxVals, b.Contexts, cs.Contexts)
					if st != 0 {
						return nil, st, errT, errR
					}
					if !okCtx {
						continue
					}
					ctxBoost = cb
					matchedCtxMap = cm
				}

				// Within one entry, find best matching input string (`entry.inputs`)
				for _, inp := range entry.inputs {
					matchedInput := false
					if isRegexMode {
						normInp := normalizeCompletionStringR61Search(inp, effAnalyzer)
						if compiledRegex.MatchString(normInp) || compiledRegex.MatchString(inp) {
							matchedInput = true
						}
					} else {
						normInp := normalizeCompletionStringR61Search(inp, effAnalyzer)
						matchedInput = matchesCompletionPrefixOrFuzzyR61Search(normInp, normPrefix, cs.Fuzzy)
					}
					if !matchedInput {
						continue
					}

					routing := hr.Routing
					if routing == "" {
						routing = s.getDocRouting(indexName, hr.ID)
					}
					var srcOut map[string]any
					if !idxSchema.SourceDisabled() {
						if idxSchema.SyntheticSource {
							synBytes := reconstructHitSyntheticSourceR61Search(srcBytes, idxSchema)
							_ = json.Unmarshal(synBytes, &srcOut)
						} else {
							srcOut = deepCloneDocMap(doc)
						}
					}
					candidates = append(candidates, scoredCompletionOptR61Search{
						text:      inp,
						score:     entry.weight * ctxBoost,
						index:     indexName,
						id:        hr.ID,
						routing:   routing,
						sourceMap: srcOut,
						contexts:  matchedCtxMap,
					})
				}
			}
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].text != candidates[j].text {
			return candidates[i].text < candidates[j].text
		}
		return candidates[i].id < candidates[j].id
	})

	options := make([]map[string]any, 0, size)
	seenTexts := make(map[string]bool)
	seenDocText := make(map[string]bool)

	for _, cand := range candidates {
		if len(options) >= size {
			break
		}
		if skipDuplicates {
			if seenTexts[cand.text] {
				continue
			}
			seenTexts[cand.text] = true
		} else {
			dk := cand.index + "\x00" + cand.id + "\x00" + cand.text
			if seenDocText[dk] {
				continue
			}
			seenDocText[dk] = true
		}
		opt := map[string]any{
			"text":   cand.text,
			"_index": cand.index,
			"_id":    cand.id,
			"_score": cand.score,
		}
		if s != nil && !s.transpileOpts.ES8Compat {
			docType := "_doc"
			if sc := s.getOrCompileReadOnlySchema(ctx, cand.index); sc != nil && sc.LegacyTypeName != "" {
				docType = sc.LegacyTypeName
			}
			opt["_type"] = docType
		}
		if cand.routing != "" {
			opt["_routing"] = cand.routing
		}
		if cand.sourceMap != nil {
			opt["_source"] = cand.sourceMap
		}
		if len(cand.contexts) > 0 {
			opt["contexts"] = cand.contexts
		}
		options = append(options, opt)
	}

	outText := rawInputQuery
	return []map[string]any{
		{
			"text":    outText,
			"offset":  0,
			"length":  utf8.RuneCountInString(outText),
			"options": options,
		},
	}, 0, "", ""
}

// ============================================================================
// F19: Collapse, PIT, Profile, `?include_named_queries_score=true`, Percolator & `rank_eval`
// ============================================================================

// validatePITWithIndexPathR61Search enforces ES's PIT path rule (`350_point_in_time.yml`):
// `[pit] cannot be used with index or indices in the request path`.
func validatePITWithIndexPathR61Search(rawPathIndex string, req *esast.SearchRequest) (int, string, string) {
	if req != nil && req.PIT != nil && strings.TrimSpace(rawPathIndex) != "" {
		return http.StatusBadRequest,
			"illegal_argument_exception",
			"[pit] cannot be used with index or indices in the request path"
	}
	return 0, "", ""
}

// ensurePITShardDocTieBreakerR61Search appends the implicit `_shard_doc: asc` tie-breaker
// when `req.PIT != nil` and `_shard_doc` is not already present in `req.Sort`.
func ensurePITShardDocTieBreakerR61Search(req *esast.SearchRequest) {
	if req == nil || req.PIT == nil {
		return
	}
	for i := range req.Sort {
		if req.Sort[i].Entry.Field == "_shard_doc" || req.Sort[i].Entry.Field == "_id" {
			if req.Sort[i].Entry.Order == "" {
				req.Sort[i].Entry.Order = "asc"
			}
			return
		}
	}
	if len(req.Sort) == 0 && len(req.SearchAfter) != 1 {
		req.Sort = append(req.Sort, esast.SortSpec{
			Entry: esast.SortEntry{Field: "_score", Order: "desc"},
		})
	}
	req.Sort = append(req.Sort, esast.SortSpec{
		Entry: esast.SortEntry{Field: "_shard_doc", Order: "asc"},
	})
}

// expandCollapseInnerHitsAndSecondLevelR61Search builds the `inner_hits` map for a collapsed hit `h`
// over its matching `groupHits`, supporting `collapse.inner_hits` as either a single object or an array
// of `InnerHitsSpec`s, including 2nd-level `collapse` inside each `inner_hits` entry.
func expandCollapseInnerHitsAndSecondLevelR61Search(
	h HitRow,
	groupHits []HitRow,
	collapse *esast.CollapseSpec,
	idxSchema *schema.IndexSchema,
	s *Server,
) map[string]any {
	if collapse == nil || len(collapse.InnerHits) == 0 {
		return nil
	}
	out := make(map[string]any, len(collapse.InnerHits))
	defaultIdx := h.Index
	if defaultIdx == "" && idxSchema != nil {
		defaultIdx = idxSchema.IndexName
	}

	for _, ihSpec := range collapse.InnerHits {
		ihName := strings.TrimSpace(ihSpec.Name)
		if ihName == "" {
			ihName = collapse.Field
		}

		sortedGroup := append([]HitRow(nil), groupHits...)
		activeSort := ihSpec.Sort
		if len(sortedGroup) > 1 {
			sort.SliceStable(sortedGroup, func(i, j int) bool {
				sI := sortedGroup[i].Schema
				if sI == nil {
					sI = idxSchema
				}
				sJ := sortedGroup[j].Schema
				if sJ == nil {
					sJ = idxSchema
				}
				if len(activeSort) > 0 {
					if cmp := compareHitRowsBySortWithSchemas(sortedGroup[i], sortedGroup[j], activeSort, sI, sJ); cmp != 0 {
						return cmp < 0
					}
				}
				if sortedGroup[i].Score != sortedGroup[j].Score {
					return sortedGroup[i].Score > sortedGroup[j].Score
				}
				return sortedGroup[i].ID < sortedGroup[j].ID
			})
		}

		totalGroup := int64(len(sortedGroup))
		var maxGroupScore float64
		for _, gh := range sortedGroup {
			if gh.Score > maxGroupScore {
				maxGroupScore = gh.Score
			}
		}

		// Second-level collapsing (`ihSpec.Collapse`)
		subCollapseField := ""
		if ihSpec.Collapse != nil {
			subCollapseField = strings.TrimSpace(ihSpec.Collapse.Field)
		}
		subCollapseValByDoc := make(map[string]any)
		if subCollapseField != "" && len(sortedGroup) > 0 {
			deduped := make([]HitRow, 0, len(sortedGroup))
			seenSubKey := make(map[string]struct{}, len(sortedGroup))
			for _, cand := range sortedGroup {
				cSchema := cand.Schema
				if cSchema == nil {
					cSchema = idxSchema
				}
				vals := collectCollapseCandidateValues(cand, subCollapseField, cSchema)
				for _, v := range vals {
					if v == nil {
						continue
					}
					sk := normalizeCollapseGroupKey(v, subCollapseField, idxSchema, cSchema)
					if sk == "" {
						continue
					}
					if _, exists := seenSubKey[sk]; !exists {
						seenSubKey[sk] = struct{}{}
						subCollapseValByDoc[cand.Index+"\x00"+cand.ID] = v
						deduped = append(deduped, cand)
						break
					}
				}
			}
			sortedGroup = deduped
		}

		from := ihSpec.From
		if from < 0 {
			from = 0
		}
		size := ihSpec.EffectiveSize()
		var paged []HitRow
		if from < len(sortedGroup) {
			end := from + size
			if end > len(sortedGroup) {
				end = len(sortedGroup)
			}
			paged = sortedGroup[from:end]
		}

		trackScores := ihSpec.TrackScores != nil && *ihSpec.TrackScores
		nullifyScore := len(activeSort) > 0 && !sortSpecsUseScore(activeSort) && !trackScores

		formattedHits := make([]map[string]any, 0, len(paged))
		for _, gh := range paged {
			gIdx := gh.Index
			if gIdx == "" {
				gIdx = defaultIdx
			}
			gSchema := gh.Schema
			if gSchema == nil {
				gSchema = idxSchema
			}
			var ghScore any = gh.Score
			if nullifyScore {
				ghScore = nil
			}
			ghMap := map[string]any{
				"_index": gIdx,
				"_id":    gh.ID,
				"_score": ghScore,
			}
			if s == nil || !s.isES8Mode(nil) {
				ghMap["_type"] = "_doc"
			}
			routing := gh.Routing
			if routing == "" && s != nil && gIdx != "" {
				routing = s.getDocRouting(gIdx, gh.ID)
			}
			if routing != "" {
				ghMap["_routing"] = routing
			}
			if ihSpec.Version {
				ver := gh.Version
				if ver <= 0 {
					ver = 1
				}
				ghMap["_version"] = ver
			}
			if ihSpec.SeqNoPrimaryTerm {
				seqNo := gh.SeqNo
				if !gh.HasSeqNo {
					if gh.Version > 0 {
						seqNo = gh.Version - 1
					} else {
						seqNo = 0
					}
				}
				ghMap["_seq_no"] = seqNo
				ghMap["_primary_term"] = int64(1)
			}

			if (ihSpec.Source == nil || !ihSpec.Source.Disabled) && (!ihSpec.HasStoredFieldsNone() || ihSpec.Source != nil) {
				if filteredSrc, ok := filterDocumentSourceRound59(gh.EffectiveSource(), gSchema, ihSpec.Source); ok {
					ghMap["_source"] = filteredSrc
				}
			}
			if len(activeSort) > 0 {
				ghMap["sort"] = extractHitSortValues(gh, activeSort, gSchema)
			}

			fieldsCombined := make(map[string][]any)
			if len(ihSpec.Fields) > 0 || len(ihSpec.DocvalueFields) > 0 {
				subReq := &esast.SearchRequest{
					Fields:         ihSpec.Fields,
					DocvalueFields: ihSpec.DocvalueFields,
					StoredFields:   ihSpec.StoredFields,
				}
				if fm, st, _, _ := extractUnifiedFieldsR61Search(gh, gIdx, subReq, gSchema, nil); st == 0 && len(fm) > 0 {
					for fk, fv := range fm {
						fieldsCombined[fk] = fv
					}
				}
			}
			if ihSpec.StoredFields != nil {
				if sfMap, _, _ := extractStoredFieldsOnlyR61Search(gh, gIdx, ihSpec.StoredFields, gSchema); len(sfMap) > 0 {
					for fk, fv := range sfMap {
						fieldsCombined[fk] = fv
					}
				}
			}
			if subCollapseField != "" {
				subVal, hasSub := subCollapseValByDoc[gh.Index+"\x00"+gh.ID]
				if !hasSub {
					subSort := []esast.SortSpec{{Entry: esast.SortEntry{Field: subCollapseField}}}
					if sVals := extractHitSortValues(gh, subSort, gSchema); len(sVals) > 0 && sVals[0] != nil {
						subVal = sVals[0]
						hasSub = true
					}
				}
				if hasSub && subVal != nil {
					if _, exists := fieldsCombined[subCollapseField]; !exists {
						fieldsCombined[subCollapseField] = []any{subVal}
					}
				}
			}
			if len(ihSpec.ScriptFields) > 0 {
				if sfm := evalHitScriptFields(gh, ihSpec.ScriptFields, gSchema); len(sfm) > 0 {
					for fk, fv := range sfm {
						fieldsCombined[fk] = fv
					}
				}
			}
			if len(fieldsCombined) > 0 {
				ghMap["fields"] = fieldsCombined
			}
			if ihSpec.Highlight != nil && len(ihSpec.Highlight.Fields) > 0 {
				if hl := buildHighlightMapWithSchema(gh.EffectiveSource(), &esast.SearchRequest{Query: gh.Query, Highlight: ihSpec.Highlight}, gSchema); len(hl) > 0 {
					ghMap["highlight"] = hl
				}
			}
			formattedHits = append(formattedHits, ghMap)
		}

		var maxScoreAny any = maxGroupScore
		if nullifyScore || totalGroup == 0 {
			maxScoreAny = nil
		}
		out[ihName] = map[string]any{
			"hits": map[string]any{
				"total":     map[string]any{"value": totalGroup, "relation": "eq"},
				"max_score": maxScoreAny,
				"hits":      formattedHits,
			},
		}
	}
	return out
}

// buildSearchProfilePayloadR61Search builds an ES-conformant `profile` payload (`370_profile.yml`):
//   - `shards: [{id, node_id, shard_id, index, cluster, searches: [{query, rewrite_time, collector}], aggregations, fetch, dfs}]`
func buildSearchProfilePayloadR61Search(indexName string, req *esast.SearchRequest, tookNs int64) map[string]any {
	if strings.TrimSpace(indexName) == "" {
		indexName = "_index"
	}
	if tookNs <= 0 {
		tookNs = 1000
	}
	nodeID := "dOrIsPrOxYnOdE00000001" // 22-char base64url node ID matching ES `^[A-Za-z0-9_-]{22}$`
	shardIDStr := fmt.Sprintf("[%s][%s][0]", nodeID, indexName)

	queryTime := max(int64(100), tookNs/2)
	rewriteTime := max(int64(10), tookNs/10)
	collectorTime := max(int64(50), tookNs/4)
	fetchTime := max(int64(50), tookNs/5)

	queryType, queryDesc := describeProfileQueryNodeR61Search(req)
	queryProfile := map[string]any{
		"type":          queryType,
		"description":   queryDesc,
		"time_in_nanos": queryTime,
		"breakdown": map[string]any{
			"score":                           queryTime / 4,
			"score_count":                     int64(1),
			"build_scorer":                    queryTime / 4,
			"build_scorer_count":              int64(1),
			"match":                           int64(0),
			"match_count":                     int64(0),
			"create_weight":                   queryTime / 4,
			"create_weight_count":             int64(1),
			"next_doc":                        queryTime / 8,
			"next_doc_count":                  int64(1),
			"advance":                         int64(0),
			"advance_count":                   int64(0),
			"compute_max_score":               int64(0),
			"compute_max_score_count":         int64(0),
			"set_min_competitive_score":       int64(0),
			"set_min_competitive_score_count": int64(0),
			"shallow_advance":                 int64(0),
			"shallow_advance_count":           int64(0),
		},
		"children": []map[string]any{},
	}

	collectorName := "SimpleTopScoreDocCollector"
	collectorReason := "search_top_hits"
	if req != nil && req.Size != nil && *req.Size == 0 {
		collectorName = "TotalHitCountCollector"
		collectorReason = "search_count"
	}

	aggProfiles := make([]map[string]any, 0)
	if req != nil {
		aggs := req.EffectiveAggs()
		aggNames := make([]string, 0, len(aggs))
		for k := range aggs {
			aggNames = append(aggNames, k)
		}
		sort.Strings(aggNames)
		for _, an := range aggNames {
			spec := aggs[an]
			aggProfiles = append(aggProfiles, map[string]any{
				"type":          profileAggFactoryTypeR61Search(spec),
				"description":   an,
				"time_in_nanos": max(int64(50), tookNs/8),
				"breakdown": map[string]any{
					"reduce":                     int64(10),
					"reduce_count":               int64(1),
					"build_aggregation":          int64(10),
					"build_aggregation_count":    int64(1),
					"build_leaf_collector":       int64(10),
					"build_leaf_collector_count": int64(1),
					"post_collection":            int64(5),
					"post_collection_count":      int64(1),
					"initialize":                 int64(5),
					"initialize_count":           int64(1),
					"collect":                    int64(10),
					"collect_count":              int64(1),
				},
				"children": []map[string]any{},
			})
		}
	}

	storedFieldsDebug := []string{"_id", "_routing", "_source"}
	hasStoredNone := req != nil && req.HasStoredFieldsNone()
	if hasStoredNone {
		storedFieldsDebug = []string{}
	} else if req != nil && req.StoredFields != nil {
		sf := esast.StoredFieldsSlice(req.StoredFields)
		storedFieldsDebug = append([]string{"_id"}, sf...)
	}

	fetchProfile := map[string]any{
		"type":          "fetch",
		"description":   "",
		"time_in_nanos": fetchTime,
		"breakdown": map[string]any{
			"load_stored_fields":       max(int64(1), fetchTime/2),
			"load_stored_fields_count": int64(1),
			"next_reader":              max(int64(1), fetchTime/4),
			"next_reader_count":        int64(1),
			"process":                  max(int64(1), fetchTime/4),
			"process_count":            int64(1),
		},
		"debug": map[string]any{
			"stored_fields": storedFieldsDebug,
		},
	}
	if !hasStoredNone {
		childPhases := []map[string]any{
			{
				"type":          "FetchFieldsPhase",
				"description":   "",
				"time_in_nanos": max(int64(1), fetchTime/4),
				"breakdown": map[string]any{
					"process":           max(int64(1), fetchTime/4),
					"process_count":     int64(1),
					"next_reader":       int64(1),
					"next_reader_count": int64(1),
				},
			},
		}
		if req == nil || req.Source == nil || !req.Source.Disabled {
			childPhases = append(childPhases, map[string]any{
				"type":          "FetchSourcePhase",
				"description":   "",
				"time_in_nanos": max(int64(1), fetchTime/3),
				"breakdown": map[string]any{
					"process":           max(int64(1), fetchTime/3),
					"process_count":     int64(1),
					"next_reader":       int64(1),
					"next_reader_count": int64(1),
				},
				"debug": map[string]any{
					"fast_path": int64(1),
				},
			})
		}
		if searchReqHasInnerHitsR62Search(req) {
			childPhases = append(childPhases, map[string]any{
				"type":          "InnerHitsPhase",
				"description":   "",
				"time_in_nanos": max(int64(1), fetchTime/4),
				"breakdown": map[string]any{
					"process":           max(int64(1), fetchTime/4),
					"process_count":     int64(1),
					"next_reader":       int64(1),
					"next_reader_count": int64(1),
				},
			})
		}
		childPhases = append(childPhases, map[string]any{
			"type":          "StoredFieldsPhase",
			"description":   "",
			"time_in_nanos": max(int64(1), fetchTime/4),
			"breakdown": map[string]any{
				"process":           max(int64(1), fetchTime/4),
				"process_count":     int64(1),
				"next_reader":       int64(1),
				"next_reader_count": int64(1),
			},
		})
		fetchProfile["children"] = childPhases
	}

	shardEntry := map[string]any{
		"id":       shardIDStr,
		"node_id":  nodeID,
		"shard_id": 0,
		"index":    indexName,
		"cluster":  "docker-cluster",
		"searches": []map[string]any{
			{
				"query":        []map[string]any{queryProfile},
				"rewrite_time": rewriteTime,
				"collector": []map[string]any{
					{
						"name":          collectorName,
						"reason":        collectorReason,
						"time_in_nanos": collectorTime,
					},
				},
			},
		},
		"aggregations": aggProfiles,
		"fetch":        fetchProfile,
	}

	if req != nil && len(req.KNN) > 0 {
		knnProfiles := make([]map[string]any, 0, len(req.KNN))
		for _, kq := range req.KNN {
			effCand := kq.NumCandidates
			if effCand <= 0 {
				effCand = max(1, kq.K)
			}
			knnProfiles = append(knnProfiles, map[string]any{
				"vector_operations_count": int64(1),
				"query": []map[string]any{
					{
						"type":          "DocAndScoreQuery",
						"description":   fmt.Sprintf("DocAndScore[%d]", effCand),
						"time_in_nanos": max(int64(50), tookNs/6),
						"breakdown": map[string]any{
							"set_min_competitive_score":       int64(0),
							"set_min_competitive_score_count": int64(0),
							"match":                           int64(0),
							"match_count":                     int64(0),
							"shallow_advance":                 int64(0),
							"shallow_advance_count":           int64(0),
							"compute_max_score":               int64(0),
							"compute_max_score_count":         int64(0),
							"advance":                         int64(0),
							"advance_count":                   int64(0),
							"create_weight":                   int64(10),
							"create_weight_count":             int64(1),
							"build_scorer":                    int64(10),
							"build_scorer_count":              int64(1),
							"next_doc":                        int64(10),
							"next_doc_count":                  int64(1),
							"score":                           int64(10),
							"score_count":                     int64(1),
						},
						"children": []map[string]any{},
					},
				},
				"rewrite_time": int64(20),
				"collector": []map[string]any{
					{
						"name":          "SimpleTopScoreDocCollector",
						"reason":        "search_top_hits",
						"time_in_nanos": int64(20),
					},
				},
			})
		}
		shardEntry["dfs"] = map[string]any{
			"knn": knnProfiles,
		}
	}

	return map[string]any{
		"shards": []map[string]any{shardEntry},
	}
}

func describeProfileQueryNodeR61Search(req *esast.SearchRequest) (string, string) {
	if req == nil || req.Query == nil || req.Query.MatchAll != nil {
		return "MatchAllDocsQuery", "*:*"
	}
	q := req.Query
	switch {
	case q.MatchNone != nil:
		return "MatchNoDocsQuery", "MatchNoDocsQuery(\"\")"
	case len(q.Term) > 0:
		for f, te := range q.Term {
			return "TermQuery", fmt.Sprintf("%s:%v", f, te.Value)
		}
	case len(q.Match) > 0:
		for f, me := range q.Match {
			return "BooleanQuery", fmt.Sprintf("%s:%v", f, me.Query)
		}
	case q.Bool != nil:
		return "BooleanQuery", "BooleanQuery"
	case q.ConstantScore != nil:
		return "ConstantScoreQuery", "ConstantScore"
	case len(q.Range) > 0:
		for f := range q.Range {
			return "IndexOrDocValuesQuery", fmt.Sprintf("%s:[* TO *]", f)
		}
	case len(q.Intervals) > 0:
		for f := range q.Intervals {
			return "IntervalQuery", fmt.Sprintf("IntervalQuery(%s)", f)
		}
	case q.KNN != nil:
		return "KnnVectorQuery", fmt.Sprintf("KnnVectorQuery:%s", q.KNN.Field)
	}
	return "Query", "Query"
}

func profileAggFactoryTypeR61Search(spec esast.AggSpec) string {
	switch {
	case spec.Terms != nil:
		return "StringTermsAggregator"
	case spec.Histogram != nil:
		return "HistogramAggregator"
	case spec.DateHistogram != nil:
		return "DateHistogramAggregator"
	case spec.Avg != nil:
		return "AvgAggregator"
	case spec.Sum != nil:
		return "SumAggregator"
	case spec.Min != nil:
		return "MinAggregator"
	case spec.Max != nil:
		return "MaxAggregator"
	case spec.Cardinality != nil:
		return "CardinalityAggregator"
	case spec.Percentiles != nil:
		return "PercentilesAggregator"
	case spec.Boxplot != nil:
		return "BoxplotAggregator"
	default:
		return "Aggregator"
	}
}

// formatMatchedQueriesWithScoresR61Search returns `[]string` (sorted) when `includeScores == false`,
// and `map[string]float64` (`name -> clauseScore`) when `includeScores == true` (`?include_named_queries_score=true`, `410_named_queries.yml`).
func formatMatchedQueriesWithScoresR61Search(
	doc map[string]any,
	idxSchema *schema.IndexSchema,
	q *esast.Query,
	includeScores bool,
) any {
	if q == nil {
		return nil
	}
	scoresByName := make(map[string]float64)
	collectNamedQueryScoresR61Search(idxSchema, doc, q, true, scoresByName)
	if len(scoresByName) == 0 {
		return nil
	}
	if includeScores {
		return scoresByName
	}
	names := make([]string, 0, len(scoresByName))
	for name := range scoresByName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func collectNamedQueryScoresR61Search(
	curSchema *schema.IndexSchema,
	curDoc map[string]any,
	cur *esast.Query,
	inScoring bool,
	out map[string]float64,
) {
	if cur == nil || out == nil {
		return
	}
	matched := false
	var clauseScore float64
	if queryNeedsIntervalsEvalR61Search(cur) {
		m, sc, err := evalIntervalsCompoundQueryR61Search(curSchema, curDoc, cur, true, inScoring)
		matched = err == nil && m
		clauseScore = sc
	} else if cur.KNN != nil {
		kq := cur.KNN
		var b schema.FieldBinding
		if curSchema != nil {
			b = curSchema.ResolveField(kq.Field)
		}
		vecMetric := b.VectorMetric
		vecElemType := b.VectorElementType
		vecDims := b.VectorDims
		if (vecMetric == "" || vecElemType == "" || vecDims == 0) && curSchema != nil {
			if fp, okRaw := lookupRawPropertyWithMultiFieldR61Search(curSchema, kq.Field); okRaw {
				if vecMetric == "" {
					vecMetric = fp.Similarity
				}
				if vecElemType == "" {
					vecElemType = fp.ElementType
				}
				if vecDims == 0 {
					vecDims = fp.Dims
				}
			}
		}
		qVec := resolveKNNQueryVectorR61Search(kq, vecElemType, vecDims)
		boost := 1.0
		if kq.Boost != nil {
			boost = *kq.Boost
		}
		filterOK := true
		for i := range kq.Filter {
			if !evalBranchMatchesDoc(curSchema, curDoc, &kq.Filter[i]) {
				filterOK = false
				break
			}
		}
		if filterOK {
			sc, okK, _ := transpiler.EvaluateNestedKNNParentScore([]map[string]any{curDoc}, kq.Field, qVec, vecMetric, vecElemType, kq.Similarity, boost)
			matched = okK
			clauseScore = sc
		}
	} else {
		matched = evalBranchMatchesDoc(curSchema, curDoc, cur)
		if matched && inScoring {
			if queryHasRuntimeScript(cur) || queryHasNestedScoring(cur) || cur.FunctionScore != nil || cur.ScriptScore != nil {
				clauseScore = evalQueryScriptScoreOnDocWithSchema(curSchema, curDoc, cur, 1.0)
			} else {
				clauseScore = scoreNonScriptClauseOnDoc(curSchema, curDoc, cur)
			}
		}
	}
	if !matched {
		return
	}

	clauseName := extractDirectQueryClauseName(cur)
	if clauseName == "" && cur.KNN != nil {
		clauseName = strings.TrimSpace(cur.KNN.Name)
	}
	if clauseName != "" {
		sc := clauseScore
		if !inScoring {
			sc = 0.0
		}
		if prev, exists := out[clauseName]; !exists || sc > prev {
			out[clauseName] = sc
		}
	}

	if cur.Bool != nil {
		for i := range cur.Bool.Must {
			collectNamedQueryScoresR61Search(curSchema, curDoc, &cur.Bool.Must[i], inScoring, out)
		}
		for i := range cur.Bool.Should {
			collectNamedQueryScoresR61Search(curSchema, curDoc, &cur.Bool.Should[i], inScoring, out)
		}
		for i := range cur.Bool.Filter {
			collectNamedQueryScoresR61Search(curSchema, curDoc, &cur.Bool.Filter[i], false, out)
		}
	}
	if cur.ConstantScore != nil {
		collectNamedQueryScoresR61Search(curSchema, curDoc, &cur.ConstantScore.Filter, false, out)
	}
	if cur.Boosting != nil {
		collectNamedQueryScoresR61Search(curSchema, curDoc, &cur.Boosting.Positive, inScoring, out)
	}
	if cur.DisMax != nil {
		for i := range cur.DisMax.Queries {
			collectNamedQueryScoresR61Search(curSchema, curDoc, &cur.DisMax.Queries[i], inScoring, out)
		}
	}
	if cur.FunctionScore != nil {
		if cur.FunctionScore.Query != nil {
			collectNamedQueryScoresR61Search(curSchema, curDoc, cur.FunctionScore.Query, inScoring, out)
		}
		for i := range cur.FunctionScore.Functions {
			if cur.FunctionScore.Functions[i].Filter != nil {
				collectNamedQueryScoresR61Search(curSchema, curDoc, cur.FunctionScore.Functions[i].Filter, false, out)
			}
		}
	}
	if cur.ScriptScore != nil && cur.ScriptScore.Query != nil {
		collectNamedQueryScoresR61Search(curSchema, curDoc, cur.ScriptScore.Query, inScoring, out)
	}
	if cur.Nested != nil {
		pathSegs := strings.Split(cur.Nested.Path, ".")
		nestedSchema := deriveNestedEvalSchema(curSchema, cur.Nested.Path)
		childScoring := inScoring && !strings.EqualFold(cur.Nested.ScoreMode, "none")
		for _, cand := range extractNestedElementsAtPath(curDoc, pathSegs) {
			elemDoc := buildSingleNestedElementDoc(pathSegs, cand.obj)
			collectNamedQueryScoresR61Search(nestedSchema, elemDoc, &cur.Nested.Query, childScoring, out)
		}
	}
	if cur.Wrapper != nil && cur.Wrapper.Decoded != nil {
		collectNamedQueryScoresR61Search(curSchema, curDoc, cur.Wrapper.Decoded, inScoring, out)
	}
	if cur.Pinned != nil && cur.Pinned.Organic != nil {
		collectNamedQueryScoresR61Search(curSchema, curDoc, cur.Pinned.Organic, inScoring, out)
	}
	if cur.KNN != nil {
		for i := range cur.KNN.Filter {
			collectNamedQueryScoresR61Search(curSchema, curDoc, &cur.KNN.Filter[i], false, out)
		}
	}
}

// evalMultiDocPercolateR61Search evaluates `percolate.documents` (or single `percolate.document`) against a stored
// percolator query document `queryDoc`, returning matched `_percolator_document_slot` indices and per-slot scores.
func evalMultiDocPercolateR61Search(
	idxSchema *schema.IndexSchema,
	queryDoc map[string]any,
	perc *esast.PercolateQuery,
) (matched bool, bestScore float64, slots []int, slotScores map[int]float64) {
	if perc == nil || queryDoc == nil {
		return false, 0, nil, nil
	}
	field := strings.TrimSpace(perc.Field)
	if field == "" {
		field = "query"
	}
	rawQueryObj, exists := getIngestPath(queryDoc, field)
	if !exists || rawQueryObj == nil {
		return false, 0, nil, nil
	}

	var storedQuery esast.Query
	switch v := rawQueryObj.(type) {
	case map[string]any:
		b, err := json.Marshal(v)
		if err != nil {
			return false, 0, nil, nil
		}
		if err := json.Unmarshal(b, &storedQuery); err != nil {
			return false, 0, nil, nil
		}
	case string:
		if err := json.Unmarshal([]byte(v), &storedQuery); err != nil {
			return false, 0, nil, nil
		}
	default:
		return false, 0, nil, nil
	}

	activeStoredScriptsServerMu.RLock()
	srv := activeStoredScriptsServer
	activeStoredScriptsServerMu.RUnlock()
	if srv != nil {
		srv.resolveStoredScriptsInQuery(&storedQuery)
	}

	var docsToTest []map[string]any
	if len(perc.Documents) > 0 {
		docsToTest = perc.Documents
	} else if perc.Document != nil {
		docsToTest = []map[string]any{perc.Document}
	}
	if len(docsToTest) == 0 {
		return false, 0, nil, nil
	}

	boost := 1.0
	if perc.Boost != nil {
		boost = *perc.Boost
	}

	slotScores = make(map[int]float64)
	for slotIdx, candDoc := range docsToTest {
		if candDoc == nil {
			continue
		}
		var slotMatched bool
		var sc float64
		if queryNeedsIntervalsEvalR61Search(&storedQuery) {
			m, sVal, err := evalAndScoreIntervalsQueryOnDocR61Search(idxSchema, candDoc, &storedQuery, true)
			slotMatched = err == nil && m
			sc = sVal
		} else if evalBranchMatchesDoc(idxSchema, candDoc, &storedQuery) {
			slotMatched = true
			sc = scoreNonScriptClauseOnDoc(idxSchema, candDoc, &storedQuery)
			if queryHasRuntimeScript(&storedQuery) || queryHasNestedScoring(&storedQuery) || storedQuery.FunctionScore != nil || storedQuery.ScriptScore != nil {
				sc = evalQueryScriptScoreOnDocWithSchema(idxSchema, candDoc, &storedQuery, sc)
			}
		}
		if !slotMatched {
			continue
		}
		if sc == 0 && storedQuery.ConstantScore == nil && boost != 0 {
			sc = 1.0
		}
		boosted := sc * boost
		slots = append(slots, slotIdx)
		slotScores[slotIdx] = boosted
		if !matched || boosted > bestScore {
			bestScore = boosted
			matched = true
		}
	}

	if !matched {
		return false, 0, nil, nil
	}
	return true, bestScore, slots, slotScores
}

// computeRankEvalMetricR61Search computes ES `_rank_eval` metrics (`precision`, `recall`, `mean_reciprocal_rank`,
// `dcg` / normalized `dcg` using ALL positive ratings in `ratings` sorted descending for `IDCG@k`, and
// `expected_reciprocal_rank` `ERR`).
func computeRankEvalMetricR61Search(
	metricName string,
	metricCfg map[string]any,
	hitIDs []string,
	ratings map[string]float64,
) (float64, map[string]any, error) {
	mName := strings.ToLower(strings.TrimSpace(metricName))
	if metricCfg == nil {
		metricCfg = map[string]any{}
	}

	k := 10
	if rawK, ok := metricCfg["k"]; ok && rawK != nil {
		kf, okF := parseFiniteFloatFromAnyR61Search(rawK, true)
		if !okF || kf != math.Trunc(kf) || int(kf) < 1 {
			return 0, nil, fmt.Errorf("illegal_argument_exception: [k] must be a positive integer, got [%v]", rawK)
		}
		k = int(kf)
	}

	relThreshold := 1.0
	if rawRT, ok := metricCfg["relevant_rating_threshold"]; ok && rawRT != nil {
		rtf, okF := parseFiniteFloatFromAnyR61Search(rawRT, true)
		if !okF || rtf < 0 {
			return 0, nil, fmt.Errorf("illegal_argument_exception: [relevant_rating_threshold] must be >= 0, got [%v]", rawRT)
		}
		relThreshold = rtf
	}

	ignoreUnlabeled := false
	if rawIU, ok := metricCfg["ignore_unlabeled"]; ok && rawIU != nil {
		if b, okB := parseStrictESBoolR61Search(rawIU); okB {
			ignoreUnlabeled = b
		}
	}

	window := hitIDs
	if len(window) > k {
		window = window[:k]
	}

	switch mName {
	case "precision":
		var relRetrieved, evaluated int
		for _, id := range window {
			r, rated := ratings[id]
			if !rated && ignoreUnlabeled {
				continue
			}
			evaluated++
			if rated && r >= relThreshold {
				relRetrieved++
			}
		}
		var score float64
		if evaluated > 0 {
			score = float64(relRetrieved) / float64(evaluated)
		}
		return score, map[string]any{
			"relevant_docs_retrieved": relRetrieved,
			"docs_retrieved":          evaluated,
		}, nil

	case "recall":
		totalRel := 0
		for _, r := range ratings {
			if r >= relThreshold {
				totalRel++
			}
		}
		relRetrieved := 0
		for _, id := range window {
			if r, rated := ratings[id]; rated && r >= relThreshold {
				relRetrieved++
			}
		}
		var score float64
		if totalRel > 0 {
			score = float64(relRetrieved) / float64(totalRel)
		}
		return score, map[string]any{
			"relevant_docs_retrieved": relRetrieved,
			"relevant_docs":           totalRel,
		}, nil

	case "mean_reciprocal_rank", "mrr":
		var score float64
		firstRelRank := -1
		for idx, id := range window {
			if r, rated := ratings[id]; rated && r >= relThreshold {
				score = 1.0 / float64(idx+1)
				firstRelRank = idx + 1
				break
			}
		}
		details := map[string]any{}
		if firstRelRank > 0 {
			details["first_relevant"] = firstRelRank
		}
		return score, details, nil

	case "dcg", "ndcg":
		normalize := mName == "ndcg"
		if rawNorm, ok := metricCfg["normalize"]; ok && rawNorm != nil {
			if b, okB := parseStrictESBoolR61Search(rawNorm); okB {
				normalize = b
			}
		}
		var dcg float64
		for idx, id := range window {
			r := ratings[id]
			if r > 0 {
				dcg += (math.Pow(2.0, r) - 1.0) / math.Log2(float64(idx+2))
			}
		}
		if !normalize {
			return dcg, map[string]any{"dcg": dcg}, nil
		}
		// Compute full-ideal `IDCG@k` from ALL positive ratings in `ratings` sorted descending (NOT just retrieved hits!).
		allPositive := make([]float64, 0, len(ratings))
		for _, r := range ratings {
			if r > 0 {
				allPositive = append(allPositive, r)
			}
		}
		sort.Slice(allPositive, func(i, j int) bool { return allPositive[i] > allPositive[j] })
		idealLen := min(k, len(allPositive))
		var idcg float64
		for i := 0; i < idealLen; i++ {
			idcg += (math.Pow(2.0, allPositive[i]) - 1.0) / math.Log2(float64(i+2))
		}
		var ndcg float64
		if idcg > 0 {
			ndcg = dcg / idcg
		}
		return ndcg, map[string]any{
			"dcg":      dcg,
			"idealDcg": idcg,
		}, nil

	case "expected_reciprocal_rank", "err":
		maxRel := 3.0
		hasMaxRel := false
		for _, key := range []string{"maximum_relevance", "max_relevance_grade"} {
			if rawMR, ok := metricCfg[key]; ok && rawMR != nil {
				mrf, okF := parseFiniteFloatFromAnyR61Search(rawMR, true)
				if !okF || mrf <= 0 {
					return 0, nil, fmt.Errorf("illegal_argument_exception: [%s] must be > 0, got [%v]", key, rawMR)
				}
				maxRel = mrf
				hasMaxRel = true
				break
			}
		}
		if !hasMaxRel {
			return 0, nil, fmt.Errorf("parsing_exception: [expected_reciprocal_rank] requires [maximum_relevance]")
		}
		denom := math.Pow(2.0, maxRel)
		pContinue := 1.0
		var errScore float64
		for idx, id := range window {
			g := ratings[id]
			if g < 0 {
				g = 0
			}
			if g > maxRel {
				return 0, nil, fmt.Errorf("illegal_argument_exception: rating [%v] exceeds maximum_relevance [%v]", g, maxRel)
			}
			rStop := (math.Pow(2.0, g) - 1.0) / denom
			pStopAtRank := pContinue * rStop
			errScore += pStopAtRank / float64(idx+1)
			pContinue *= (1.0 - rStop)
		}
		return errScore, map[string]any{"err": errScore}, nil

	default:
		return 0, nil, fmt.Errorf("parsing_exception: unknown rank_eval metric [%s]", metricName)
	}
}

// ============================================================================
// F24, F25, F26, F28: Search `script_fields`, `script_score` & `PerFieldSimilarity` `_explain`
// ============================================================================

// evalSearchScriptFieldsR61Search evaluates `req.ScriptFields` across `hits` using
// `PrepareDocForRuntimeScriptRound61(idxSchema, docMap, isES8)` and returns ES's HTTP 400
// `search_phase_execution_exception` envelope via `FormatScriptFieldsPhaseErrorRound61` on compile/runtime failure
// whenever `ignore_failure` is not `true`.
func evalSearchScriptFieldsR61Search(
	s *Server,
	r *http.Request,
	hits []HitRow,
	schemasByIdx map[string]*schema.IndexSchema,
	req *esast.SearchRequest,
) (map[int]map[string]any, int, map[string]any) {
	if req == nil || len(req.ScriptFields) == 0 {
		return nil, 0, nil
	}
	isES8 := s == nil || s.isES8Mode(r)

	sfNames := make([]string, 0, len(req.ScriptFields))
	for k := range req.ScriptFields {
		sfNames = append(sfNames, k)
	}
	sort.Strings(sfNames)

	defaultIdxName := "_index"
	for idxName := range schemasByIdx {
		if idxName != "" {
			defaultIdxName = idxName
			break
		}
	}

	type parsedScriptFieldEntryR61Search struct {
		name          string
		source        string
		params        map[string]any
		ignoreFailure bool
	}
	parsedEntries := make([]parsedScriptFieldEntryR61Search, 0, len(sfNames))

	for _, sfName := range sfNames {
		entryMap, ok := req.ScriptFields[sfName].(map[string]any)
		if !ok || entryMap == nil {
			continue
		}
		ignoreFail := false
		if igRaw, hasIG := entryMap["ignore_failure"]; hasIG && igRaw != nil {
			if b, okB := parseStrictESBoolR61Search(igRaw); okB {
				ignoreFail = b
			}
		}
		scriptVal := entryMap["script"]
		src, params := extractScriptSourceAndParams(scriptVal)
		if src == "" {
			if storedID, hasID := extractStoredScriptIDRound61(scriptVal); hasID && s != nil {
				if storedObj, found := s.lookupStoredScript(storedID); found {
					src, _ = storedObj["source"].(string)
				} else if !ignoreFail {
					st, payload := FormatScriptFieldsPhaseErrorRound61(defaultIdxName, sfName, storedID, fmt.Errorf("resource_not_found_exception: Unable to findExecutable script [%s]", storedID))
					return nil, st, payload
				}
			}
		}
		// Compile-validate upfront even when `len(hits) == 0`!
		if src != "" {
			if compErr := painless.CompileValidate(src); compErr != nil {
				if !ignoreFail {
					st, payload := FormatScriptFieldsPhaseErrorRound61(defaultIdxName, sfName, src, compErr)
					return nil, st, payload
				}
				continue
			}
		}
		parsedEntries = append(parsedEntries, parsedScriptFieldEntryR61Search{
			name:          sfName,
			source:        src,
			params:        params,
			ignoreFailure: ignoreFail,
		})
	}

	if len(hits) == 0 || len(parsedEntries) == 0 {
		return nil, 0, nil
	}

	outByHit := make(map[int]map[string]any, len(hits))
	for hitPos, h := range hits {
		hitIdx := h.Index
		if hitIdx == "" {
			hitIdx = defaultIdxName
		}
		var idxSchema *schema.IndexSchema
		if schemasByIdx != nil {
			idxSchema = schemasByIdx[hitIdx]
		}
		if idxSchema == nil {
			idxSchema = h.Schema
		}

		var docMap map[string]any
		srcBytes := h.EffectiveSource()
		if len(srcBytes) > 0 {
			dec := json.NewDecoder(bytes.NewReader(srcBytes))
			dec.UseNumber()
			_ = dec.Decode(&docMap)
		}
		if docMap == nil {
			docMap = map[string]any{}
		}
		if h.ID != "" {
			docMap["__meta_id"] = h.ID
		}
		if hitIdx != "" {
			docMap["__meta_index"] = hitIdx
		}
		ver := h.Version
		if ver <= 0 {
			ver = 1
		}
		docMap["__meta_version"] = ver
		if h.HasSeqNo {
			docMap["__meta_seq_no"] = h.SeqNo
		}
		if s != nil {
			s.populateMissingTokenCountValuesFromBackendR63(idxSchema, h.ID, docMap)
		}

		for _, entry := range parsedEntries {
			if entry.source == "" {
				continue
			}
			isolatedDoc := deepCloneDocMap(docMap)
			prepared := PrepareDocForRuntimeScriptRound61(idxSchema, isolatedDoc, isES8)
			evalParams := make(map[string]any, len(entry.params)+2)
			for k, v := range entry.params {
				evalParams[k] = v
			}
			evalParams["_score"] = h.Score
			if docMap != nil {
				srcCopy := deepCloneDocMap(docMap)
				delete(srcCopy, "__meta_id")
				delete(srcCopy, "__meta_index")
				delete(srcCopy, "__meta_version")
				delete(srcCopy, "__meta_seq_no")
				evalParams["_source"] = srcCopy
			}

			val, err := painless.Eval(prepared, entry.source, evalParams)
			if err != nil {
				if entry.ignoreFailure {
					continue
				}
				st, payload := FormatScriptFieldsPhaseErrorRound61(hitIdx, entry.name, entry.source, err)
				return nil, st, payload
			}
			if cycErr := painless.ValidateAcyclicValue(val); cycErr != nil {
				if entry.ignoreFailure {
					continue
				}
				st, payload := FormatScriptFieldsPhaseErrorRound61(hitIdx, entry.name, entry.source, cycErr)
				return nil, st, payload
			}
			if val == nil {
				continue
			}
			if outByHit[hitPos] == nil {
				outByHit[hitPos] = make(map[string]any)
			}
			if arr, isArr := val.([]any); isArr {
				outByHit[hitPos][entry.name] = arr
			} else {
				outByHit[hitPos][entry.name] = []any{val}
			}
		}
	}

	if len(outByHit) == 0 {
		return nil, 0, nil
	}
	return outByHit, 0, nil
}

// evalAndValidateSearchScriptScoreR61Search evaluates `script_score` and `function_score` `script_score`
// using `PrepareDocForRuntimeScriptRound61`:
//   - Multiplies `q.ScriptScore.Boost` ONLY ONCE.
//   - Enforces `ValidateNonNegativeScriptScoreRound61` on script output.
//   - Formats compile, runtime, and negative/NaN score errors via `FormatScriptScorePhaseErrorRound61`.
func evalAndValidateSearchScriptScoreR61Search(
	idxSchema *schema.IndexSchema,
	doc map[string]any,
	q *esast.Query,
	baseScore float64,
	isES8 bool,
) (score float64, matched bool, status int, errPayload map[string]any) {
	if q == nil {
		return baseScore, true, 0, nil
	}
	idxName := "_index"
	if idxSchema != nil && idxSchema.IndexName != "" {
		idxName = idxSchema.IndexName
	}

	// 1. Direct `script_score` query
	if q.ScriptScore != nil && q.ScriptScore.Script != nil {
		src, params := extractScriptSourceAndParams(q.ScriptScore.Script)
		if src == "" {
			if storedID, hasID := extractStoredScriptIDRound61(q.ScriptScore.Script); hasID {
				activeStoredScriptsServerMu.RLock()
				srv := activeStoredScriptsServer
				activeStoredScriptsServerMu.RUnlock()
				if srv != nil {
					if storedObj, ok := srv.lookupStoredScript(storedID); ok {
						src, _ = storedObj["source"].(string)
					}
				}
			}
		}
		if src != "" {
			if compErr := painless.CompileValidate(src); compErr != nil {
				st, payload := FormatScriptScorePhaseErrorRound61(idxName, src, compErr)
				return 0, false, st, payload
			}
		}

		subBase := baseScore
		if q.ScriptScore.Query != nil {
			if queryNeedsIntervalsEvalR61Search(q.ScriptScore.Query) {
				m, iScore, iErr := evalAndScoreIntervalsQueryOnDocR61Search(idxSchema, doc, q.ScriptScore.Query, isES8)
				if iErr != nil || !m {
					return 0, false, 0, nil
				}
				subBase = iScore
			} else {
				if !evalBranchMatchesDoc(idxSchema, doc, q.ScriptScore.Query) {
					return 0, false, 0, nil
				}
				if q.ScriptScore.Query.ScriptScore != nil || q.ScriptScore.Query.FunctionScore != nil {
					innerSc, innerM, st, payload := evalAndValidateSearchScriptScoreR61Search(idxSchema, doc, q.ScriptScore.Query, subBase, isES8)
					if st != 0 {
						return 0, false, st, payload
					}
					if !innerM {
						return 0, false, 0, nil
					}
					subBase = innerSc
				} else {
					subBase = scoreNonScriptClauseOnDoc(idxSchema, doc, q.ScriptScore.Query)
				}
			}
		}

		prepared := PrepareDocForRuntimeScriptRound61(idxSchema, doc, isES8)
		evalParams := make(map[string]any, len(params)+1)
		for k, v := range params {
			evalParams[k] = v
		}
		evalParams["_score"] = subBase

		fv, okNum, err := painless.EvalNumber(prepared, src, evalParams)
		if err != nil {
			st, payload := FormatScriptScorePhaseErrorRound61(idxName, src, err)
			return 0, false, st, payload
		}
		if !okNum {
			st, payload := FormatScriptScorePhaseErrorRound61(idxName, src, fmt.Errorf("class_cast_exception: script_score script must return a numeric value"))
			return 0, false, st, payload
		}
		if valErr := ValidateNonNegativeScriptScoreRound61(fv); valErr != nil {
			st, payload := FormatScriptScorePhaseErrorRound61(idxName, src, valErr)
			return 0, false, st, payload
		}

		// Multiply `q.ScriptScore.Boost` ONLY ONCE!
		finalScore := fv
		if q.ScriptScore.Boost != nil {
			finalScore = fv * (*q.ScriptScore.Boost)
		}
		if q.ScriptScore.MinScore != nil && finalScore < *q.ScriptScore.MinScore {
			return 0, false, 0, nil
		}
		return finalScore, true, 0, nil
	}

	// 2. `function_score` query containing `script_score` or `functions[i].script_score`
	if q.FunctionScore != nil {
		subBase := baseScore
		if q.FunctionScore.Query != nil {
			if queryNeedsIntervalsEvalR61Search(q.FunctionScore.Query) {
				m, iScore, iErr := evalAndScoreIntervalsQueryOnDocR61Search(idxSchema, doc, q.FunctionScore.Query, isES8)
				if iErr != nil || !m {
					return 0, false, 0, nil
				}
				subBase = iScore
			} else {
				if !evalBranchMatchesDoc(idxSchema, doc, q.FunctionScore.Query) {
					return 0, false, 0, nil
				}
				if q.FunctionScore.Query.ScriptScore != nil || q.FunctionScore.Query.FunctionScore != nil {
					innerSc, innerM, st, payload := evalAndValidateSearchScriptScoreR61Search(idxSchema, doc, q.FunctionScore.Query, subBase, isES8)
					if st != 0 {
						return 0, false, st, payload
					}
					if !innerM {
						return 0, false, 0, nil
					}
					subBase = innerSc
				} else if subBase == 1.0 {
					subBase = scoreNonScriptClauseOnDoc(idxSchema, doc, q.FunctionScore.Query)
				}
			}
		}

		prepared := PrepareDocForRuntimeScriptRound61(idxSchema, doc, isES8)
		evalFnScript := func(rawScript any) (float64, int, map[string]any) {
			src, params := extractScriptSourceAndParams(rawScript)
			if src == "" {
				if storedID, hasID := extractStoredScriptIDRound61(rawScript); hasID {
					activeStoredScriptsServerMu.RLock()
					srv := activeStoredScriptsServer
					activeStoredScriptsServerMu.RUnlock()
					if srv != nil {
						if storedObj, ok := srv.lookupStoredScript(storedID); ok {
							src, _ = storedObj["source"].(string)
						}
					}
				}
			}
			if compErr := painless.CompileValidate(src); compErr != nil {
				st, payload := FormatScriptScorePhaseErrorRound61(idxName, src, compErr)
				return 0, st, payload
			}
			evalParams := make(map[string]any, len(params)+1)
			for k, v := range params {
				evalParams[k] = v
			}
			evalParams["_score"] = subBase
			fv, okNum, err := painless.EvalNumber(prepared, src, evalParams)
			if err != nil {
				st, payload := FormatScriptScorePhaseErrorRound61(idxName, src, err)
				return 0, st, payload
			}
			if !okNum {
				st, payload := FormatScriptScorePhaseErrorRound61(idxName, src, fmt.Errorf("class_cast_exception: script_score script must return a numeric value"))
				return 0, st, payload
			}
			if valErr := ValidateNonNegativeScriptScoreRound61(fv); valErr != nil {
				st, payload := FormatScriptScorePhaseErrorRound61(idxName, src, valErr)
				return 0, st, payload
			}
			return fv, 0, nil
		}

		var fnScores []float64
		if q.FunctionScore.ScriptScore != nil && q.FunctionScore.ScriptScore.Script != nil {
			fv, st, payload := evalFnScript(q.FunctionScore.ScriptScore.Script)
			if st != 0 {
				return 0, false, st, payload
			}
			if q.FunctionScore.Weight != nil {
				fv *= *q.FunctionScore.Weight
			}
			fnScores = append(fnScores, fv)
		} else if q.FunctionScore.FieldValueFactor != nil {
			if fv, ok := evalFieldValueFactorOnDoc(idxSchema, doc, q.FunctionScore.FieldValueFactor); ok {
				if q.FunctionScore.Weight != nil {
					fv *= *q.FunctionScore.Weight
				}
				fnScores = append(fnScores, fv)
			}
		} else if q.FunctionScore.RandomScore != nil {
			fv := evalRandomScoreOnDoc(doc, q.FunctionScore.RandomScore)
			if q.FunctionScore.Weight != nil {
				fv *= *q.FunctionScore.Weight
			}
			fnScores = append(fnScores, fv)
		} else if len(q.FunctionScore.Functions) == 0 && q.FunctionScore.Weight != nil {
			fnScores = append(fnScores, *q.FunctionScore.Weight)
		}

		for _, fn := range q.FunctionScore.Functions {
			if fn.Filter != nil && !evalBranchMatchesDoc(idxSchema, doc, fn.Filter) {
				continue
			}
			hasVal := false
			val := 1.0
			if fn.ScriptScore != nil && fn.ScriptScore.Script != nil {
				fv, st, payload := evalFnScript(fn.ScriptScore.Script)
				if st != 0 {
					return 0, false, st, payload
				}
				val = fv
				hasVal = true
			} else if fn.FieldValueFactor != nil {
				if fv, ok := evalFieldValueFactorOnDoc(idxSchema, doc, fn.FieldValueFactor); ok {
					val = fv
					hasVal = true
				}
			} else if fn.RandomScore != nil {
				val = evalRandomScoreOnDoc(doc, fn.RandomScore)
				hasVal = true
			}
			if fn.Weight != nil {
				if hasVal {
					val *= *fn.Weight
				} else {
					val = *fn.Weight
					hasVal = true
				}
			}
			if hasVal {
				fnScores = append(fnScores, val)
				if strings.EqualFold(q.FunctionScore.ScoreMode, "first") {
					break
				}
			}
		}

		combined := 1.0
		if len(fnScores) > 0 {
			combined = combineFunctionScoreValues(fnScores, q.FunctionScore.ScoreMode)
		}
		if q.FunctionScore.MaxBoost != nil && combined > *q.FunctionScore.MaxBoost {
			combined = *q.FunctionScore.MaxBoost
		}
		res := applyFunctionScoreBoostMode(subBase, combined, q.FunctionScore.BoostMode)
		if q.FunctionScore.Boost != nil {
			res *= *q.FunctionScore.Boost
		}
		if q.FunctionScore.MinScore != nil && res < *q.FunctionScore.MinScore {
			return 0, false, 0, nil
		}
		return res, true, 0, nil
	}

	// 3. Compound `bool` / `boosting` / `dis_max` / `constant_score` containing nested `script_score`
	if q.Bool != nil {
		for i := range q.Bool.MustNot {
			_, m, st, payload := evalAndValidateSearchScriptScoreR61Search(idxSchema, doc, &q.Bool.MustNot[i], 1.0, isES8)
			if st != 0 {
				return 0, false, st, payload
			}
			if m {
				return 0, false, 0, nil
			}
		}
		for i := range q.Bool.Filter {
			_, m, st, payload := evalAndValidateSearchScriptScoreR61Search(idxSchema, doc, &q.Bool.Filter[i], 0.0, isES8)
			if st != 0 {
				return 0, false, st, payload
			}
			if !m {
				return 0, false, 0, nil
			}
		}
		var total float64
		hasScored := false
		for i := range q.Bool.Must {
			sc, m, st, payload := evalAndValidateSearchScriptScoreR61Search(idxSchema, doc, &q.Bool.Must[i], 1.0, isES8)
			if st != 0 {
				return 0, false, st, payload
			}
			if !m {
				return 0, false, 0, nil
			}
			total += sc
			hasScored = true
		}
		matchedShould := 0
		for i := range q.Bool.Should {
			sc, m, st, payload := evalAndValidateSearchScriptScoreR61Search(idxSchema, doc, &q.Bool.Should[i], 1.0, isES8)
			if st != 0 {
				return 0, false, st, payload
			}
			if m {
				matchedShould++
				total += sc
				hasScored = true
			}
		}
		if matchedShould < resolveBoolMinShouldMatchR61Search(q.Bool, len(q.Bool.Should)) {
			return 0, false, 0, nil
		}
		boost := 1.0
		if q.Bool.Boost != nil {
			boost = *q.Bool.Boost
		}
		if !hasScored {
			return boost, true, 0, nil
		}
		return total * boost, true, 0, nil
	}

	if q.ConstantScore != nil {
		_, m, st, payload := evalAndValidateSearchScriptScoreR61Search(idxSchema, doc, &q.ConstantScore.Filter, 0.0, isES8)
		if st != 0 || !m {
			return 0, false, st, payload
		}
		boost := 1.0
		if q.ConstantScore.Boost != nil {
			boost = *q.ConstantScore.Boost
		}
		return boost, true, 0, nil
	}

	if !evalBranchMatchesDoc(idxSchema, doc, q) {
		return 0, false, 0, nil
	}
	sc := scoreNonScriptClauseOnDoc(idxSchema, doc, q)
	return sc, true, 0, nil
}

// formatTermWeightExplainDescriptionR61Search formats Elasticsearch's Lucene `PerFieldSimilarity`
// term weight explanation description (`lang_mustache/30_search_template.yml:131`).
func formatTermWeightExplainDescriptionR61Search(field, term string, docNum int) string {
	return "weight(" + field + ":" + term + " in " + strconv.Itoa(docNum) + ") [PerFieldSimilarity], result of:"
}

// buildScriptScoreExplainTreeR61Search integrates `BuildScriptScoreExplainNodeRound61` with
// `evalAndValidateSearchScriptScoreR61Search` to produce an ES-conformant `_explain` node for `script_score`.
func buildScriptScoreExplainTreeR61Search(
	idxSchema *schema.IndexSchema,
	doc map[string]any,
	q *esast.Query,
	baseScore float64,
	subQueryExplain map[string]any,
	isES8 bool,
) (map[string]any, int, map[string]any) {
	sc, matched, st, errPayload := evalAndValidateSearchScriptScoreR61Search(idxSchema, doc, q, baseScore, isES8)
	if st != 0 {
		return nil, st, errPayload
	}
	if !matched {
		return map[string]any{
			"value":       0.0,
			"description": "no match on required clause",
			"details":     []map[string]any{},
		}, 0, nil
	}
	var src string
	var params map[string]any
	boost := 1.0
	if q != nil && q.ScriptScore != nil {
		src, params = extractScriptSourceAndParams(q.ScriptScore.Script)
		if q.ScriptScore.Boost != nil {
			boost = *q.ScriptScore.Boost
		}
	}
	unboosted := sc
	if boost != 0 && boost != 1.0 {
		unboosted = sc / boost
	}
	innerNode := BuildScriptScoreExplainNodeRound61(unboosted, src, params, subQueryExplain)
	if boost != 1.0 {
		return map[string]any{
			"value":       sc,
			"description": fmt.Sprintf("script score function, computed with script:\"%s\"", src),
			"details": []map[string]any{
				{
					"value":       boost,
					"description": "boost",
					"details":     []map[string]any{},
				},
				innerNode,
			},
		}, 0, nil
	}
	return innerNode, 0, nil
}

func splitESExceptionErrorR61Search(err error, defaultType string) (string, string) {
	if err == nil {
		return "", ""
	}
	msg := strings.TrimSpace(err.Error())
	if idx := strings.Index(msg, ": "); idx > 0 {
		prefix := strings.TrimSpace(msg[:idx])
		isSnake := true
		for i := 0; i < len(prefix); i++ {
			r := rune(prefix[i])
			if !unicode.IsLower(r) && !unicode.IsDigit(r) && r != '_' {
				isSnake = false
				break
			}
		}
		if isSnake && (strings.HasSuffix(prefix, "_exception") || strings.HasSuffix(prefix, "_error")) {
			return prefix, strings.TrimSpace(msg[idx+2:])
		}
	}
	return defaultType, msg
}

// ============================================================================
// Wave-3 Search Execution Context & Integration Bridge Helpers
// ============================================================================

type searchExecCtxKeyR61Search struct{}

type searchExecMetaR61Search struct {
	httpReq                  *http.Request
	isES8                    bool
	forceSyntheticSource     bool
	includeNamedQueriesScore bool
	rawBody                  []byte
	errPayload               map[string]any
}

func withSearchExecMetaR61Search(ctx context.Context, meta *searchExecMetaR61Search) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, searchExecCtxKeyR61Search{}, meta)
}

func searchExecMetaFromCtxR61Search(ctx context.Context) *searchExecMetaR61Search {
	if ctx == nil {
		return nil
	}
	m, _ := ctx.Value(searchExecCtxKeyR61Search{}).(*searchExecMetaR61Search)
	return m
}

func resolveRuntimeScriptES8ModeR61Search(idxSchema *schema.IndexSchema, doc map[string]any) bool {
	if doc != nil {
		if b, ok := doc["__es8_mode"].(bool); ok {
			return b
		}
	}
	if idxSchema != nil {
		return idxSchema.ES8Mode
	}
	return true
}

func queryContainsScriptScoreR61Search(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.ScriptScore != nil && q.ScriptScore.Script != nil {
		return true
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.ScriptScore != nil && q.FunctionScore.ScriptScore.Script != nil {
			return true
		}
		for i := range q.FunctionScore.Functions {
			if q.FunctionScore.Functions[i].ScriptScore != nil && q.FunctionScore.Functions[i].ScriptScore.Script != nil {
				return true
			}
			if queryContainsScriptScoreR61Search(q.FunctionScore.Functions[i].Filter) {
				return true
			}
		}
		if queryContainsScriptScoreR61Search(q.FunctionScore.Query) {
			return true
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryContainsScriptScoreR61Search(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryContainsScriptScoreR61Search(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if queryContainsScriptScoreR61Search(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if queryContainsScriptScoreR61Search(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && queryContainsScriptScoreR61Search(&q.ConstantScore.Filter) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryContainsScriptScoreR61Search(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil {
		if queryContainsScriptScoreR61Search(&q.Boosting.Positive) || queryContainsScriptScoreR61Search(&q.Boosting.Negative) {
			return true
		}
	}
	if q.Nested != nil && queryContainsScriptScoreR61Search(&q.Nested.Query) {
		return true
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil && queryContainsScriptScoreR61Search(q.Wrapper.Decoded) {
		return true
	}
	if q.Pinned != nil && q.Pinned.Organic != nil && queryContainsScriptScoreR61Search(q.Pinned.Organic) {
		return true
	}
	return false
}

func compileValidateQueryScriptScoreR61Search(defaultIdx string, q *esast.Query) (int, map[string]any) {
	if q == nil {
		return 0, nil
	}
	if defaultIdx == "" {
		defaultIdx = "_index"
	}
	checkRaw := func(rawScript any) (int, map[string]any) {
		src, ok := extractPainlessSourceIfApplicableRound60(rawScript)
		if !ok || src == "" {
			return 0, nil
		}
		if err := painless.CompileValidate(src); err != nil {
			return FormatScriptScorePhaseErrorRound61(defaultIdx, src, err)
		}
		return 0, nil
	}
	if q.ScriptScore != nil {
		if st, p := checkRaw(q.ScriptScore.Script); st != 0 {
			return st, p
		}
		if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, q.ScriptScore.Query); st != 0 {
			return st, p
		}
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.ScriptScore != nil {
			if st, p := checkRaw(q.FunctionScore.ScriptScore.Script); st != 0 {
				return st, p
			}
		}
		for i := range q.FunctionScore.Functions {
			fn := &q.FunctionScore.Functions[i]
			if fn.ScriptScore != nil {
				if st, p := checkRaw(fn.ScriptScore.Script); st != 0 {
					return st, p
				}
			}
			if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, fn.Filter); st != 0 {
				return st, p
			}
		}
		if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, q.FunctionScore.Query); st != 0 {
			return st, p
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, &q.Bool.Must[i]); st != 0 {
				return st, p
			}
		}
		for i := range q.Bool.Filter {
			if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, &q.Bool.Filter[i]); st != 0 {
				return st, p
			}
		}
		for i := range q.Bool.Should {
			if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, &q.Bool.Should[i]); st != 0 {
				return st, p
			}
		}
		for i := range q.Bool.MustNot {
			if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, &q.Bool.MustNot[i]); st != 0 {
				return st, p
			}
		}
	}
	if q.ConstantScore != nil {
		if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, &q.ConstantScore.Filter); st != 0 {
			return st, p
		}
	}
	if q.Boosting != nil {
		if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, &q.Boosting.Positive); st != 0 {
			return st, p
		}
		if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, &q.Boosting.Negative); st != 0 {
			return st, p
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, &q.DisMax.Queries[i]); st != 0 {
				return st, p
			}
		}
	}
	if q.Nested != nil {
		if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, &q.Nested.Query); st != 0 {
			return st, p
		}
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil {
		if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, q.Wrapper.Decoded); st != 0 {
			return st, p
		}
	}
	if q.Pinned != nil && q.Pinned.Organic != nil {
		if st, p := compileValidateQueryScriptScoreR61Search(defaultIdx, q.Pinned.Organic); st != 0 {
			return st, p
		}
	}
	return 0, nil
}

func extractSingleTermOrMatchForExplainR61Search(q *esast.Query) (string, string, bool) {
	if q == nil {
		return "", "", false
	}
	if len(q.Term) == 1 {
		for f, te := range q.Term {
			return f, fmt.Sprintf("%v", te.Value), true
		}
	}
	if len(q.Match) == 1 {
		for f, me := range q.Match {
			s := strings.TrimSpace(fmt.Sprintf("%v", me.Query))
			if fields := strings.Fields(s); len(fields) == 1 {
				return f, fields[0], true
			}
			return f, s, true
		}
	}
	if q.Bool != nil && len(q.Bool.Filter) == 0 && len(q.Bool.MustNot) == 0 {
		if len(q.Bool.Must) == 1 && len(q.Bool.Should) == 0 {
			return extractSingleTermOrMatchForExplainR61Search(&q.Bool.Must[0])
		}
		if len(q.Bool.Should) == 1 && len(q.Bool.Must) == 0 {
			return extractSingleTermOrMatchForExplainR61Search(&q.Bool.Should[0])
		}
	}
	if q.Wrapper != nil && q.Wrapper.Decoded != nil {
		return extractSingleTermOrMatchForExplainR61Search(q.Wrapper.Decoded)
	}
	return "", "", false
}

func collectAllMatchedQueriesWithScoresR61Search(
	idxSchema *schema.IndexSchema,
	doc map[string]any,
	req *esast.SearchRequest,
	hitScore float64,
) map[string]float64 {
	if req == nil {
		return nil
	}
	scores := make(map[string]float64)
	if req.Query != nil {
		collectNamedQueryScoresR61Search(idxSchema, doc, req.Query, true, scores)
	}
	if req.PostFilter != nil {
		collectNamedQueryScoresR61Search(idxSchema, doc, req.PostFilter, false, scores)
	}
	for i := range req.KNN {
		kq := &req.KNN[i]
		if kq.Name != "" {
			if _, exists := scores[kq.Name]; !exists {
				scores[kq.Name] = hitScore
			}
		}
		for j := range kq.Filter {
			collectNamedQueryScoresR61Search(idxSchema, doc, &kq.Filter[j], false, scores)
		}
	}
	if len(scores) == 0 {
		return nil
	}
	return scores
}

func aggsTreeHasQuantileAggR61Search(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.Percentiles != nil || spec.PercentileRanks != nil || spec.Boxplot != nil || spec.MedianAbsoluteDeviation != nil {
			return true
		}
		if aggsTreeHasQuantileAggR61Search(spec.SubAggs()) {
			return true
		}
	}
	return false
}

func aggsMapHasBucketPrunerR61Search(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.BucketSelector != nil || spec.BucketSort != nil {
			return true
		}
	}
	return false
}

func reEvaluatePipelineAggsTreeR61Search(aggs map[string]esast.AggSpec, aggsOut map[string]any) error {
	if len(aggs) == 0 || len(aggsOut) == 0 {
		return nil
	}
	hasQuantiles := aggsTreeHasQuantileAggR61Search(aggs)
	for aggName, spec := range aggs {
		subAggs := spec.SubAggs()
		if len(subAggs) == 0 {
			continue
		}
		subMap, ok := aggsOut[aggName].(map[string]any)
		if !ok {
			continue
		}
		canReEvalSub := hasQuantiles && !aggsMapHasBucketPrunerR61Search(subAggs)
		switch rawB := subMap["buckets"].(type) {
		case []map[string]any:
			for _, b := range rawB {
				if err := reEvaluatePipelineAggsTreeR61Search(subAggs, b); err != nil {
					return err
				}
			}
			for subName, ss := range subAggs {
				if ss.MovingFn != nil {
					if err := validateMovingFnBucketsR61Search(rawB, subName, ss.MovingFn, canReEvalSub); err != nil {
						return err
					}
				}
			}
			if canReEvalSub {
				rawB = evaluateChildPipelineAggs(rawB, subAggs)
				subMap["buckets"] = rawB
			}
			if aggsHaveKeepValuesScriptPipelineR63(subAggs) {
				updatedB, kvErr := validateAndApplyKeepValuesScriptPipelinesR63(rawB, subAggs)
				if kvErr != nil {
					return kvErr
				}
				subMap["buckets"] = updatedB
			}
		case []any:
			conv := make([]map[string]any, 0, len(rawB))
			for _, item := range rawB {
				if m, okM := item.(map[string]any); okM {
					if err := reEvaluatePipelineAggsTreeR61Search(subAggs, m); err != nil {
						return err
					}
					conv = append(conv, m)
				}
			}
			for subName, ss := range subAggs {
				if ss.MovingFn != nil {
					if err := validateMovingFnBucketsR61Search(conv, subName, ss.MovingFn, canReEvalSub); err != nil {
						return err
					}
				}
			}
			if canReEvalSub {
				conv = evaluateChildPipelineAggs(conv, subAggs)
				subMap["buckets"] = conv
			}
			if aggsHaveKeepValuesScriptPipelineR63(subAggs) {
				updatedConv, kvErr := validateAndApplyKeepValuesScriptPipelinesR63(conv, subAggs)
				if kvErr != nil {
					return kvErr
				}
				subMap["buckets"] = updatedConv
			}
		case map[string]any:
			for _, item := range rawB {
				if m, okM := item.(map[string]any); okM {
					if err := reEvaluatePipelineAggsTreeR61Search(subAggs, m); err != nil {
						return err
					}
				}
			}
		default:
			if err := reEvaluatePipelineAggsTreeR61Search(subAggs, subMap); err != nil {
				return err
			}
		}
	}
	if hasQuantiles {
		evaluateSiblingPipelineAggs(aggs, aggsOut)
		if !aggsMapHasBucketPrunerR61Search(aggs) {
			_ = evaluateChildPipelineAggs([]map[string]any{aggsOut}, aggs)
		}
		attachAllAggMetasRound60(aggsOut, aggs)
	}
	return nil
}

func validateMovingFnBucketsR61Search(buckets []map[string]any, subName string, maSpec *esast.MovingAvgAggSpec, updateOut bool) error {
	if maSpec == nil || len(buckets) == 0 {
		return nil
	}
	pathStr := maSpec.EffectivePath()
	insertZeros := strings.EqualFold(maSpec.GapPolicy, "insert_zeros")
	win := maSpec.EffectiveWindow()
	var history []float64
	for _, b := range buckets {
		curr, ok := extractBucketMetricByPath(b, pathStr)
		if !ok {
			if insertZeros {
				curr = 0
			} else {
				continue
			}
		}
		history = append(history, curr)
		endIdx := len(history) - 2
		if maSpec.Shift != nil {
			endIdx = len(history) - 2 + *maSpec.Shift
		}
		var slice []float64
		if endIdx >= 0 {
			if endIdx >= len(history) {
				endIdx = len(history) - 1
			}
			start := 0
			if endIdx+1 > win {
				start = endIdx + 1 - win
			}
			slice = history[start : endIdx+1]
		}
		valAny, err := evalMovingFnWindowR61Search(slice, maSpec)
		if err != nil {
			return err
		}
		if updateOut {
			if fv, hasVal := toFloat64(valAny); valAny != nil && hasVal {
				b[subName] = makePipelineMetricObj(fv, maSpec.Format)
			} else {
				b[subName] = map[string]any{"value": nil}
			}
		}
	}
	return nil
}

func applyNestedTopHitsInAggsTreeR61Search(
	reqQuery *esast.Query,
	aggs map[string]esast.AggSpec,
	aggsOut map[string]any,
	parentHits []HitRow,
	idxSchema *schema.IndexSchema,
) {
	if len(aggs) == 0 || len(aggsOut) == 0 {
		return
	}
	for aggName, spec := range aggs {
		aggMap, ok := aggsOut[aggName].(map[string]any)
		if !ok || aggMap == nil {
			continue
		}
		subAggs := spec.SubAggs()
		if spec.Nested != nil && spec.Nested.Path != "" {
			for subName, ss := range subAggs {
				if ss.TopHits != nil {
					aggMap[subName] = evaluateNestedTopHitsAggR61Search(spec.Nested.Path, parentHits, reqQuery, ss.TopHits, idxSchema)
				}
			}
		}
		if len(subAggs) > 0 && rawBucketsNilOrSingleR61Search(aggMap) {
			applyNestedTopHitsInAggsTreeR61Search(reqQuery, subAggs, aggMap, parentHits, idxSchema)
		}
	}
}

func rawBucketsNilOrSingleR61Search(aggMap map[string]any) bool {
	if aggMap == nil {
		return false
	}
	_, hasBuckets := aggMap["buckets"]
	return !hasBuckets
}
