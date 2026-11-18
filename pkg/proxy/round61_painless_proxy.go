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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

// ============================================================================
// Round 61 F24: Runtime Doc-Value / Fields API Preparation & Error Formatting
// ============================================================================

func isFielddataEnabledRound61(fd any) bool {
	if fd == nil {
		return false
	}
	switch tv := fd.(type) {
	case bool:
		return tv
	case string:
		return strings.EqualFold(strings.TrimSpace(tv), "true")
	case map[string]any:
		if en, exists := tv["enabled"]; exists {
			if b, ok := en.(bool); ok {
				return b
			}
			if s, ok := en.(string); ok {
				return !strings.EqualFold(strings.TrimSpace(s), "false")
			}
		}
		return true
	}
	return false
}

func collectMappingPropertyMetadataRound61(
	props map[string]esast.FieldProperty,
	prefix string,
	ftMap, fmtMap, elemMap map[string]string,
	docValFalse, storeTrue, fdTrue map[string]bool,
) {
	for name, prop := range props {
		full := name
		if prefix != "" {
			full = prefix + "." + name
		}
		pt := strings.ToLower(strings.TrimSpace(prop.Type))
		if pt != "" && pt != "object" && pt != "nested" {
			ftMap[full] = pt
		}
		if strings.TrimSpace(prop.Format) != "" {
			fmtMap[full] = strings.TrimSpace(prop.Format)
		}
		if pt == "dense_vector" {
			et := strings.ToLower(strings.TrimSpace(prop.ElementType))
			if et == "" {
				et = "float"
			}
			elemMap[full] = et
		}
		if prop.DocValues != nil && !*prop.DocValues {
			docValFalse[full] = true
		}
		if prop.Store != nil && *prop.Store {
			storeTrue[full] = true
		}
		if isFielddataEnabledRound61(prop.Fielddata) {
			fdTrue[full] = true
		}
		if len(prop.Fields) > 0 {
			collectMappingPropertyMetadataRound61(prop.Fields, full, ftMap, fmtMap, elemMap, docValFalse, storeTrue, fdTrue)
		}
		if len(prop.Properties) > 0 {
			collectMappingPropertyMetadataRound61(prop.Properties, full, ftMap, fmtMap, elemMap, docValFalse, storeTrue, fdTrue)
		}
	}
}

func lookupRawPathValueRound61(doc map[string]any, segs []string) (any, bool) {
	if doc == nil || len(segs) == 0 {
		return nil, false
	}
	var cur any = doc
	for i, seg := range segs {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, exists := m[seg]
		if !exists {
			if rem := strings.Join(segs[i:], "."); rem != seg {
				if fv, okF := m[rem]; okF {
					return fv, true
				}
			}
			return nil, false
		}
		if i == len(segs)-1 {
			return v, true
		}
		cur = v
	}
	return nil, false
}

// PrepareDocForRuntimeScriptRound61 enriches `prepareDocForRuntimeScript(idxSchema, doc)`
// with Round-61 Painless runtime metadata:
//   - `__keep_boolean_dups`: true in ES 8 (`[false, false, true]`), false in ES 7 (`[false, true]`)
//   - `__quantize_geo_point`: true (Lucene 32-bit Morton geo_point quantization)
//   - `__field_types`: comprehensive field -> ES type map (including `flattened`, `token_count`,
//     `half_float`, `float`, `binary`, `dense_vector`, `match_only_text`, and runtime fields)
//   - `__field_formats`: custom date mapping formats (`yyyy/MM/dd`, etc.)
//   - `__vector_element_types`: `dense_vector` element_type (`float`, `byte`, `bit`)
//   - `__disabled_doc_values`: exact ES `illegal_argument_exception` guards for `doc_values: false`,
//     `text` with `fielddata: false`, and `match_only_text`
//   - `__disabled_fields_api`: exact ES `illegal_argument_exception` guards when `_source` is disabled
//     and neither `doc_values` nor `store: true` can serve `field('f')` / `$('f')`
//   - Preserves `_version`, `_seq_no`, and `_primary_term` hit metadata bindings.
func PrepareDocForRuntimeScriptRound61(idxSchema *schema.IndexSchema, doc map[string]any, isES8 bool) map[string]any {
	base := prepareDocForRuntimeScript(idxSchema, doc)
	var cp map[string]any
	if base != nil && doc != nil {
		// prepareDocForRuntimeScript may return `doc` directly if `idxSchema == nil`;
		// always return a safe shallow/deep clone so internal `__*` keys never leak into `doc`.
		cp = deepCloneDocMap(base)
		if rawSrc, ok := base["__raw_source"].(map[string]any); ok && rawSrc != nil {
			cp["__raw_source"] = rawSrc
		} else {
			cp["__raw_source"] = doc
		}
	} else if base != nil {
		cp = deepCloneDocMap(base)
	} else {
		cp = make(map[string]any)
	}
	if doc != nil && cp["__raw_source"] == nil {
		cp["__raw_source"] = doc
	}
	if doc != nil {
		if seq, exists := doc["__meta_seq_no"]; exists && seq != nil {
			cp["__meta_seq_no"] = seq
		}
		if pt, exists := doc["__meta_primary_term"]; exists && pt != nil {
			cp["__meta_primary_term"] = pt
		}
	}
	cp["__keep_boolean_dups"] = isES8
	cp["__quantize_geo_point"] = true

	if idxSchema == nil {
		return cp
	}

	idxName := idxSchema.IndexName
	if idxName == "" || idxName == "eval_idx" {
		idxName = "_index"
	}

	ftMap := make(map[string]string)
	if baseFT, ok := cp["__field_types"].(map[string]string); ok {
		for k, v := range baseFT {
			ftMap[k] = v
		}
	} else if extFT := extractSchemaFieldTypesMapRound60(idxSchema); len(extFT) > 0 {
		for k, v := range extFT {
			ftMap[k] = v
		}
	}

	fmtMap := make(map[string]string)
	elemMap := make(map[string]string)
	docValFalse := make(map[string]bool)
	storeTrue := make(map[string]bool)
	fdTrue := make(map[string]bool)
	runtimeSet := make(map[string]bool)

	for fPath, fb := range idxSchema.Fields {
		esT := strings.ToLower(strings.TrimSpace(fb.ESType))
		if esT != "" && ftMap[fPath] == "" {
			ftMap[fPath] = esT
		}
		if strings.TrimSpace(fb.Format) != "" {
			fmtMap[fPath] = strings.TrimSpace(fb.Format)
		}
		if esT == "dense_vector" || fb.VectorDims > 0 {
			ftMap[fPath] = "dense_vector"
			et := strings.ToLower(strings.TrimSpace(fb.VectorElementType))
			if et == "" {
				et = "float"
			}
			elemMap[fPath] = et
		}
		if fb.DocValuesFalse {
			docValFalse[fPath] = true
		}
	}

	if idxSchema.RawMapping != nil {
		if len(idxSchema.RawMapping.Properties) > 0 {
			collectMappingPropertyMetadataRound61(
				idxSchema.RawMapping.Properties,
				"",
				ftMap, fmtMap, elemMap,
				docValFalse, storeTrue, fdTrue,
			)
		}
		for rtName, rtProp := range idxSchema.RawMapping.Runtime {
			rtType := strings.ToLower(strings.TrimSpace(rtProp.Type))
			if rtType == "" {
				rtType = "keyword"
			}
			ftMap[rtName] = rtType
			runtimeSet[rtName] = true
			if strings.TrimSpace(rtProp.Format) != "" {
				fmtMap[rtName] = strings.TrimSpace(rtProp.Format)
			}
		}
	}

	disabledDV := make(map[string]string)
	disabledFA := make(map[string]string)
	sourceDisabled := idxSchema.SourceDisabled()

	for fPath, ft := range ftMap {
		if runtimeSet[fPath] {
			continue
		}
		switch ft {
		case "match_only_text":
			disabledDV[fPath] = painless.DocValuesDisabledMessage(fPath, idxName, "match_only_text")
		case "text", "annotated_text":
			if !fdTrue[fPath] {
				disabledDV[fPath] = painless.DocValuesDisabledMessage(fPath, idxName, ft)
			}
		default:
			if docValFalse[fPath] {
				disabledDV[fPath] = painless.DocValuesDisabledMessage(fPath, idxName, ft)
			}
		}
		if sourceDisabled && disabledDV[fPath] != "" && !storeTrue[fPath] {
			disabledFA[fPath] = painless.FieldsAPIDisabledMessage(fPath, idxName)
		}
	}

	// Preserve structured source objects (`flattened`, `geo_point`, `dense_vector`) on `cp`
	// when `doc` carries an unflattened map or coordinate slice at that path.
	if doc != nil {
		for fPath, ft := range ftMap {
			if ft != "flattened" && ft != "geo_point" && ft != "dense_vector" {
				continue
			}
			segs := strings.Split(fPath, ".")
			if rawV, ok := lookupRawPathValueRound61(doc, segs); ok && rawV != nil {
				setRuntimeScriptDocPath(cp, segs, rawV)
			}
		}
	}

	if len(ftMap) > 0 {
		cp["__field_types"] = ftMap
		if idxSchema.RawMapping != nil {
			dynStr := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", idxSchema.RawMapping.Dynamic)))
			if dynStr == "false" || dynStr == "strict" {
				strictSet := make(map[string]bool, len(ftMap))
				for k := range ftMap {
					strictSet[k] = true
				}
				cp["__strict_doc_fields"] = strictSet
			}
		}
	}
	if len(fmtMap) > 0 {
		cp["__field_formats"] = fmtMap
	}
	if len(elemMap) > 0 {
		cp["__vector_element_types"] = elemMap
	}
	if len(disabledDV) > 0 {
		cp["__disabled_doc_values"] = disabledDV
	}
	if len(disabledFA) > 0 {
		cp["__disabled_fields_api"] = disabledFA
	}
	return cp
}

// PrepareDocForRuntimeScriptWithRequestRound61 resolves ES 8 vs ES 7 mode from `s` / `r`
// and prepares `doc` for Painless runtime evaluation.
func (s *Server) PrepareDocForRuntimeScriptWithRequestRound61(r *http.Request, idxSchema *schema.IndexSchema, doc map[string]any) map[string]any {
	isES8 := s == nil || s.isES8Mode(r)
	return PrepareDocForRuntimeScriptRound61(idxSchema, doc, isES8)
}

// ============================================================================
// Round 61 F26: Topological `runtime_mappings` Sorting, Cycle Detection,
// Stored-Script Context Rejection & Chained `emit(...)` Evaluation
// ============================================================================

var (
	reRuntimeDocBracketRefRound61 = regexp.MustCompile(`\bdoc\s*\[\s*(?:'([^']+)'|"([^"]+)")\s*\]`)
	reRuntimeDocContainsRound61   = regexp.MustCompile(`\bdoc\s*\.\s*containsKey\s*\(\s*(?:'([^']+)'|"([^"]+)")\s*\)`)
	reRuntimeDocDotRefRound61     = regexp.MustCompile(`\bdoc\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\b`)
	reRuntimeFieldCallRefRound61  = regexp.MustCompile(`(?:\bfield|\$)\s*\(\s*(?:'([^']+)'|"([^"]+)")`)
)

func stripPainlessCommentsForDepsRound61(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	inQuote := byte(0)
	for i := 0; i < len(src); i++ {
		ch := src[i]
		if inQuote != 0 {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < len(src) {
				i++
				b.WriteByte(src[i])
				continue
			}
			if ch == inQuote {
				inQuote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' {
			inQuote = ch
			b.WriteByte(ch)
			continue
		}
		if ch == '/' && i+1 < len(src) {
			if src[i+1] == '/' {
				i += 2
				for i < len(src) && src[i] != '\n' {
					i++
				}
				b.WriteByte('\n')
				continue
			}
			if src[i+1] == '*' {
				i += 2
				for i+1 < len(src) && (src[i] != '*' || src[i+1] != '/') {
					i++
				}
				i++
				b.WriteByte(' ')
				continue
			}
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// ExtractRuntimeScriptFieldDepsRound61 extracts deterministic, deduplicated references
// from a runtime field Painless script to any field in `candidateFields` (`doc['A']`,
// `doc.A`, `doc.containsKey('A')`, `field('A')`, `$('A', ...)`).
func ExtractRuntimeScriptFieldDepsRound61(scriptSrc string, candidateFields map[string]bool) []string {
	if strings.TrimSpace(scriptSrc) == "" || len(candidateFields) == 0 {
		return nil
	}
	cleaned := stripPainlessCommentsForDepsRound61(scriptSrc)
	depsSet := make(map[string]bool)
	recordCandidate := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if candidateFields[raw] {
			depsSet[raw] = true
			return
		}
		trimmed := strings.TrimSuffix(raw, ".keyword")
		if trimmed != raw && candidateFields[trimmed] {
			depsSet[trimmed] = true
			return
		}
		if dot := strings.IndexByte(raw, '.'); dot > 0 && candidateFields[raw[:dot]] {
			depsSet[raw[:dot]] = true
		}
	}

	for _, m := range reRuntimeDocBracketRefRound61.FindAllStringSubmatch(cleaned, -1) {
		if m[1] != "" {
			recordCandidate(m[1])
		} else if m[2] != "" {
			recordCandidate(m[2])
		}
	}
	for _, m := range reRuntimeDocContainsRound61.FindAllStringSubmatch(cleaned, -1) {
		if m[1] != "" {
			recordCandidate(m[1])
		} else if m[2] != "" {
			recordCandidate(m[2])
		}
	}
	for _, m := range reRuntimeDocDotRefRound61.FindAllStringSubmatch(cleaned, -1) {
		ident := m[1]
		switch ident {
		case "containsKey", "size", "isEmpty", "empty", "keySet", "values", "entrySet", "get":
			continue
		}
		recordCandidate(ident)
	}
	for _, m := range reRuntimeFieldCallRefRound61.FindAllStringSubmatch(cleaned, -1) {
		if m[1] != "" {
			recordCandidate(m[1])
		} else if m[2] != "" {
			recordCandidate(m[2])
		}
	}

	if len(depsSet) == 0 {
		return nil
	}
	out := make([]string, 0, len(depsSet))
	for d := range depsSet {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// TopoSortRuntimeMappingsRound61 returns a deterministic topological execution order
// for `rtMap` so runtime field `B` reading `doc['A']` / `field('A')` runs after `A`.
// Returns an `illegal_argument_exception` error if any dependency cycle exists.
func TopoSortRuntimeMappingsRound61(rtMap map[string]esast.FieldProperty) ([]string, error) {
	if len(rtMap) == 0 {
		return nil, nil
	}
	candidates := make(map[string]bool, len(rtMap))
	allNames := make([]string, 0, len(rtMap))
	for name := range rtMap {
		candidates[name] = true
		allNames = append(allNames, name)
	}
	sort.Strings(allNames)

	// dependents[A] = list of fields B that depend on A (edge A -> B)
	dependents := make(map[string][]string, len(rtMap))
	// depsOf[B] = sorted list of fields A that B reads
	depsOf := make(map[string][]string, len(rtMap))
	inDegree := make(map[string]int, len(rtMap))

	for _, name := range allNames {
		prop := rtMap[name]
		if prop.Script == nil {
			continue
		}
		scriptSrc, _ := extractScriptSourceAndParams(prop.Script)
		deps := ExtractRuntimeScriptFieldDepsRound61(scriptSrc, candidates)
		for _, dep := range deps {
			if dep == name {
				return nil, fmt.Errorf("illegal_argument_exception: Cycle detected in runtime_mappings [%s -> %s]", name, name)
			}
			dependents[dep] = append(dependents[dep], name)
			depsOf[name] = append(depsOf[name], dep)
			inDegree[name]++
		}
	}

	ready := make([]string, 0, len(allNames))
	for _, name := range allNames {
		if inDegree[name] == 0 {
			ready = append(ready, name)
		}
	}

	order := make([]string, 0, len(allNames))
	for len(ready) > 0 {
		sort.Strings(ready)
		cur := ready[0]
		ready = ready[1:]
		order = append(order, cur)
		for _, nxt := range dependents[cur] {
			inDegree[nxt]--
			if inDegree[nxt] == 0 {
				ready = append(ready, nxt)
			}
		}
	}

	if len(order) < len(allNames) {
		cyclePath := findDeterministicRuntimeCycleRound61(allNames, inDegree, depsOf)
		return nil, fmt.Errorf("illegal_argument_exception: Cycle detected in runtime_mappings [%s]", strings.Join(cyclePath, " -> "))
	}
	return order, nil
}

func findDeterministicRuntimeCycleRound61(allNames []string, inDegree map[string]int, depsOf map[string][]string) []string {
	var start string
	for _, n := range allNames {
		if inDegree[n] > 0 {
			start = n
			break
		}
	}
	if start == "" {
		return []string{"cycle"}
	}
	visitedIdx := make(map[string]int)
	var trail []string
	cur := start
	for {
		if idx, seen := visitedIdx[cur]; seen {
			cycle := append([]string(nil), trail[idx:]...)
			cycle = append(cycle, cur)
			// Reverse `B depends on A` chain so arrow reads evaluation dependency order `A -> B -> A`
			for i, j := 0, len(cycle)-1; i < j; i, j = i+1, j-1 {
				cycle[i], cycle[j] = cycle[j], cycle[i]
			}
			return cycle
		}
		visitedIdx[cur] = len(trail)
		trail = append(trail, cur)
		var next string
		for _, dep := range depsOf[cur] {
			if inDegree[dep] > 0 {
				next = dep
				break
			}
		}
		if next == "" {
			if len(depsOf[cur]) > 0 {
				next = depsOf[cur][0]
			} else {
				return append(trail, start)
			}
		}
		cur = next
	}
}

// IsRuntimeFieldScriptContextRound61 reports whether `ctxName` is one of Elasticsearch's
// runtime-field `emit(...)` script contexts (`boolean_field`, `long_field`, `double_field`,
// `keyword_field`, `date_field`, `ip_field`, `geo_point_field`, `composite_field`).
func IsRuntimeFieldScriptContextRound61(ctxName string) bool {
	switch strings.ToLower(strings.TrimSpace(ctxName)) {
	case "boolean_field", "long_field", "double_field", "keyword_field",
		"date_field", "ip_field", "geo_point_field", "composite_field":
		return true
	}
	return false
}

// CheckStoredScriptRuntimeFieldContextRound61 checks whether `PUT /_scripts/{id}/{context}`
// attempts to compile/store a script with a runtime-field context that forbids context-bound
// stored compilation or unknown contexts, returning `(status, errorPayload, rejected)`.
func CheckStoredScriptRuntimeFieldContextRound61(contextName string) (int, map[string]any, bool) {
	ctx := strings.TrimSpace(contextName)
	if ctx == "" {
		return 0, nil, false
	}
	if IsRuntimeFieldScriptContextRound61(ctx) {
		innerReason := fmt.Sprintf("Runtime field context [%s] cannot be used for stored scripts without matching runtime mapping compilation", ctx)
		outerReason := fmt.Sprintf("Failed to compile stored script in context [%s]", ctx)
		errObj := map[string]any{
			"root_cause": []map[string]any{
				{
					"type":   "illegal_argument_exception",
					"reason": innerReason,
				},
			},
			"type":   "script_exception",
			"reason": outerReason,
			"caused_by": map[string]any{
				"type":   "illegal_argument_exception",
				"reason": innerReason,
			},
		}
		return http.StatusBadRequest, map[string]any{"error": errObj, "status": http.StatusBadRequest}, true
	}
	return 0, nil, false
}

func extractStoredScriptIDRound61(raw any) (string, bool) {
	switch v := raw.(type) {
	case *esast.ScriptSpec:
		if v != nil && strings.TrimSpace(v.ID) != "" {
			return strings.TrimSpace(v.ID), true
		}
	case esast.ScriptSpec:
		if strings.TrimSpace(v.ID) != "" {
			return strings.TrimSpace(v.ID), true
		}
	case map[string]any:
		if sub, hasSub := v["script"]; hasSub && sub != nil {
			return extractStoredScriptIDRound61(sub)
		}
		if id, ok := v["id"].(string); ok && strings.TrimSpace(id) != "" {
			return strings.TrimSpace(id), true
		}
	}
	return "", false
}

// ValidateRuntimeMappingsPainlessRound61 validates inline Painless compilation and
// `on_script_error` syntax across `reqMappings` (deferring cycle/depth DFS to lazy query-time resolution).
func ValidateRuntimeMappingsPainlessRound61(_ *schema.IndexSchema, reqMappings map[string]esast.FieldProperty) error {
	for fName, rm := range reqMappings {
		if onErr := strings.ToLower(strings.TrimSpace(rm.OnScriptError)); onErr != "" && onErr != "fail" && onErr != "continue" {
			return fmt.Errorf("mapper_parsing_exception: Invalid [on_script_error] value [%s] on runtime field [%s]: must be [fail] or [continue]", rm.OnScriptError, fName)
		}
		if src, ok := extractPainlessSourceIfApplicableRound60(rm.Script); ok {
			if err := painless.CompileValidate(src); err != nil {
				return err
			}
		}
	}
	return nil
}

func coerceEmittedRuntimeValuesRound61(esType, format string, rawVals []any, nowUTC time.Time) []any {
	return coerceRuntimeValuesWithScriptFlagR62Search(esType, format, rawVals, nowUTC, true)
}

func coerceRuntimeValuesWithScriptFlagR62Search(esType, format string, rawVals []any, nowUTC time.Time, fromScript bool) []any {
	coerced := make([]any, 0, len(rawVals))
	for _, rv := range rawVals {
		if rv == nil {
			continue
		}
		switch esType {
		case "geo_point":
			if gp, ok := rv.(*painless.GeoPointVal); ok && gp != nil {
				if fromScript {
					qLat, qLon := painless.QuantizeLuceneGeoPoint(gp.Lat, gp.Lon)
					coerced = append(coerced, map[string]any{"lat": qLat, "lon": qLon})
				} else {
					coerced = append(coerced, map[string]any{"lat": gp.Lat, "lon": gp.Lon})
				}
				continue
			}
			if lat, lon, err := esast.ParseGeoPoint(rv); err == nil {
				if fromScript {
					qLat, qLon := painless.QuantizeLuceneGeoPoint(lat, lon)
					coerced = append(coerced, map[string]any{"lat": qLat, "lon": qLon})
				} else {
					coerced = append(coerced, map[string]any{"lat": lat, "lon": lon})
				}
				continue
			}
		case "ip":
			switch iv := rv.(type) {
			case *painless.IPAddressVal:
				if iv != nil {
					coerced = append(coerced, iv.String())
				}
			case string:
				s := strings.TrimSpace(iv)
				if parsedIP, err := painless.ParseIPAddressVal(s); err == nil {
					coerced = append(coerced, parsedIP.String())
				} else if fromScript && s != "" {
					coerced = append(coerced, s)
				}
			default:
				if fromScript {
					s := strings.TrimSpace(painless.FormatValueSafe(rv))
					if parsedIP, err := painless.ParseIPAddressVal(s); err == nil {
						coerced = append(coerced, parsedIP.String())
					} else if s != "" {
						coerced = append(coerced, s)
					}
				}
			}
		case "unsigned_long":
			switch uv := rv.(type) {
			case uint64:
				coerced = append(coerced, uv)
			case int:
				if uv >= 0 {
					coerced = append(coerced, int64(uv))
				}
			case int64:
				if uv >= 0 {
					coerced = append(coerced, uv)
				}
			case json.Number:
				if i, err := uv.Int64(); err == nil && i >= 0 {
					coerced = append(coerced, i)
				} else if u, err := strconv.ParseUint(strings.TrimSpace(uv.String()), 10, 64); err == nil {
					coerced = append(coerced, u)
				} else if f, ok := toFloat64(rv); ok && f >= 0 && f < 18446744073709551616.0 {
					coerced = append(coerced, uint64(f))
				}
			case string:
				trimmedU := strings.TrimSpace(uv)
				if i, err := strconv.ParseInt(trimmedU, 10, 64); err == nil && i >= 0 {
					coerced = append(coerced, i)
				} else if u, err := strconv.ParseUint(trimmedU, 10, 64); err == nil {
					coerced = append(coerced, u)
				} else if f, errF := strconv.ParseFloat(trimmedU, 64); errF == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f >= 0 && f < 18446744073709551616.0 {
					coerced = append(coerced, uint64(f))
				}
			default:
				if f, ok := toFloat64(rv); ok && f >= 0 && f < 18446744073709551616.0 {
					if f < 9223372036854775808.0 {
						coerced = append(coerced, int64(f))
					} else {
						coerced = append(coerced, uint64(f))
					}
				}
			}
		case "long", "integer", "short", "byte":
			if iv, okI := rv.(int64); okI {
				coerced = append(coerced, iv)
			} else if nv, okN := rv.(json.Number); okN {
				if iv, err := nv.Int64(); err == nil {
					coerced = append(coerced, iv)
				} else if f, ok := toFloat64(rv); ok && f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
					coerced = append(coerced, int64(f))
				}
			} else if sv, okS := rv.(string); okS {
				trimmedS := strings.TrimSpace(sv)
				if iv, err := strconv.ParseInt(trimmedS, 10, 64); err == nil {
					coerced = append(coerced, iv)
				} else if f, errF := strconv.ParseFloat(trimmedS, 64); errF == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
					coerced = append(coerced, int64(f))
				}
			} else if f, ok := toFloat64(rv); ok && f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
				coerced = append(coerced, int64(f))
			}
		case "half_float":
			if f, ok := toFloat64(rv); ok {
				coerced = append(coerced, float64(painless.QuantizeHalfFloat(f)))
			} else if sv, okS := rv.(string); okS {
				if f, err := strconv.ParseFloat(strings.TrimSpace(sv), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					coerced = append(coerced, float64(painless.QuantizeHalfFloat(f)))
				}
			}
		case "float":
			if f, ok := toFloat64(rv); ok {
				coerced = append(coerced, float64(float32(f)))
			} else if sv, okS := rv.(string); okS {
				if f, err := strconv.ParseFloat(strings.TrimSpace(sv), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					coerced = append(coerced, float64(float32(f)))
				}
			}
		case "double", "scaled_float":
			if f, ok := toFloat64(rv); ok {
				coerced = append(coerced, f)
			} else if sv, okS := rv.(string); okS {
				if f, err := strconv.ParseFloat(strings.TrimSpace(sv), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
					coerced = append(coerced, f)
				}
			}
		case "boolean":
			switch bv := rv.(type) {
			case bool:
				coerced = append(coerced, bv)
			case string:
				if strings.EqualFold(strings.TrimSpace(bv), "true") || (fromScript && strings.TrimSpace(bv) == "1") {
					coerced = append(coerced, true)
				} else if strings.EqualFold(strings.TrimSpace(bv), "false") || (fromScript && strings.TrimSpace(bv) == "0") {
					coerced = append(coerced, false)
				}
			}
		case "date_nanos":
			if ns, ok := parseDateNanosValueRound58(rv, format); ok {
				coerced = append(coerced, ns)
			} else if fromScript {
				if sv, ok := rv.(string); ok {
					coerced = append(coerced, sv)
				}
			}
		case "date":
			if z, okZ := rv.(*painless.ZonedDateTimeVal); okZ && z != nil {
				coerced = append(coerced, z.ToEpochMilli())
			} else if !fromScript && strings.TrimSpace(format) != "" {
				switch dv := rv.(type) {
				case string:
					if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strings.TrimSpace(dv), format, nowUTC); ok {
						coerced = append(coerced, ms)
					}
				case int64:
					if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strconv.FormatInt(dv, 10), format, nowUTC); ok {
						coerced = append(coerced, ms)
					}
				case int:
					if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strconv.Itoa(dv), format, nowUTC); ok {
						coerced = append(coerced, ms)
					}
				case json.Number:
					if ms, ok := schema.ParseESDateWithFormatToEpochMillis(strings.TrimSpace(dv.String()), format, nowUTC); ok {
						coerced = append(coerced, ms)
					}
				}
			} else if iv, okI := rv.(int64); okI {
				coerced = append(coerced, iv)
			} else if nv, okN := rv.(json.Number); okN {
				if iv, err := nv.Int64(); err == nil {
					coerced = append(coerced, iv)
				} else if f, ok := toFloat64(rv); ok && f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
					coerced = append(coerced, int64(f))
				}
			} else if f, ok := toFloat64(rv); ok && f >= -9223372036854775808.0 && f < 9223372036854775808.0 {
				coerced = append(coerced, int64(f))
			} else if sv, ok := rv.(string); ok {
				if ms, ok := schema.ParseESDateWithFormatToEpochMillis(sv, format, nowUTC); ok {
					coerced = append(coerced, ms)
				} else if fromScript {
					if tm, errT := time.Parse("2006-01-02T15:04:05.000Z", strings.TrimSpace(sv)); errT == nil {
						coerced = append(coerced, tm.UnixMilli())
					} else if msDef, okDef := schema.ParseESDateToEpochMillis(sv, nowUTC); okDef {
						coerced = append(coerced, msDef)
					} else {
						coerced = append(coerced, sv)
					}
				}
			}
		default:
			if !fromScript {
				switch rv.(type) {
				case map[string]any, []any:
					continue
				}
			}
			coerced = append(coerced, painless.FormatValueSafe(rv))
		}
	}
	return coerced
}

// EvalRuntimeMappingsOnDocTopologicalRound61 evaluates merged index + search `runtime_mappings`
// in topological dependency order on `doc`, mutating `doc` with emitted runtime values and
// returning the enriched runtime `evalDoc` ready for downstream `query`, `script_fields`, `sort`, or `aggs`.
func EvalRuntimeMappingsOnDocTopologicalRound61(
	idxSchema *schema.IndexSchema,
	reqMappings map[string]esast.FieldProperty,
	doc map[string]any,
	isES8 bool,
) (map[string]any, bool, error) {
	rtMap := effectiveRuntimeMappings(idxSchema, reqMappings)
	if len(rtMap) == 0 {
		return PrepareDocForRuntimeScriptRound61(idxSchema, doc, isES8), false, nil
	}
	roots := make([]string, 0, len(rtMap))
	for k := range rtMap {
		roots = append(roots, k)
	}
	sort.Strings(roots)
	rtOrder, err := resolveLazyRuntimeMappingsOrderR62Search(rtMap, roots)
	if err != nil {
		return PrepareDocForRuntimeScriptRound61(idxSchema, doc, isES8), false, err
	}
	evalDoc, modified, _, rtErr := evalRuntimeMappingsOrderedOnDocR62Search(idxSchema, rtMap, rtOrder, doc, isES8)
	return evalDoc, modified, rtErr
}

// EvalRuntimeMappingsOnHitRowsTopologicalRound61 evaluates index + search `runtime_mappings`
// in topological order across `hits`, updating `HitRow.RawSource` and propagating cycle/script errors.
func (s *Server) EvalRuntimeMappingsOnHitRowsTopologicalRound61(
	r *http.Request,
	idxSchema *schema.IndexSchema,
	reqMappings map[string]esast.FieldProperty,
	hits []HitRow,
) error {
	_, err := s.EvalRuntimeMappingsOnHitRowsLazyR62Search(r, idxSchema, reqMappings, nil, nil, hits)
	return err
}

// ============================================================================
// Round 61 F24 / F25 / F26: `script_fields` & `script_score` Error Envelopes,
// Negative-Score Check & `_explain` Tree Helpers
// ============================================================================

var javaExceptionToESSnakeTypeRound61 = map[string]string{
	"IllegalArgumentException":        "illegal_argument_exception",
	"IllegalStateException":           "illegal_state_exception",
	"UnsupportedOperationException":   "unsupported_operation_exception",
	"NullPointerException":            "null_pointer_exception",
	"IndexOutOfBoundsException":       "index_out_of_bounds_exception",
	"ArrayIndexOutOfBoundsException":  "array_index_out_of_bounds_exception",
	"StringIndexOutOfBoundsException": "string_index_out_of_bounds_exception",
	"ClassCastException":              "class_cast_exception",
	"ArithmeticException":             "arithmetic_exception",
	"NumberFormatException":           "number_format_exception",
	"DateTimeException":               "date_time_exception",
	"DateTimeParseException":          "date_time_parse_exception",
	"PatternSyntaxException":          "pattern_syntax_exception",
	"PainlessError":                   "painless_error",
	"OutOfMemoryError":                "out_of_memory_error",
	"StackOverflowError":              "stack_overflow_error",
	"Exception":                       "exception",
	"RuntimeException":                "runtime_exception",
}

// ClassifyPainlessRuntimeErrorRound61 extracts Elasticsearch's outer error type/reason
// (`script_exception`: `"compile error"` / `"runtime error"`) and inner `caused_by`
// (`illegal_argument_exception`, `unsupported_operation_exception`, etc.) from a Painless error.
func ClassifyPainlessRuntimeErrorRound61(err error) (outerType, outerReason, causedByType, causedByReason string, position map[string]any) {
	if err == nil {
		return "script_exception", "runtime error", "illegal_argument_exception", "", nil
	}
	if errors.Is(err, painless.ErrSelfReferencingIterable) {
		msg := "Iterable object is self-referencing itself (ScriptBytesValues value)"
		return "illegal_argument_exception", msg, "", "", nil
	}
	var compErr *painless.ScriptCompileError
	if errors.As(err, &compErr) && compErr != nil {
		var pos map[string]any
		if compErr.Position != nil {
			pos = map[string]any{
				"offset": compErr.Position.Offset,
				"start":  compErr.Position.Start,
				"end":    compErr.Position.End,
			}
		}
		cType := "illegal_argument_exception"
		cReason := strings.TrimSpace(compErr.Message)
		if idx := strings.Index(cReason, ": "); idx > 0 {
			prefix := strings.TrimSpace(cReason[:idx])
			if mapped, ok := javaExceptionToESSnakeTypeRound61[prefix]; ok {
				cType = mapped
				cReason = strings.TrimSpace(cReason[idx+2:])
			} else if strings.HasSuffix(prefix, "_exception") || strings.HasSuffix(prefix, "_error") {
				cType = prefix
				cReason = strings.TrimSpace(cReason[idx+2:])
			}
		}
		return "script_exception", "compile error", cType, cReason, pos
	}

	rawMsg := strings.TrimSpace(err.Error())
	if strings.HasPrefix(rawMsg, "all_shards_failed|") {
		parts := strings.SplitN(rawMsg, "|", 3)
		if len(parts) == 3 {
			if parts[1] == "illegal_argument_exception" {
				return "illegal_argument_exception", parts[2], "", "", nil
			}
			rawMsg = parts[2]
		}
	}

	cType := "illegal_argument_exception"
	cReason := rawMsg
	if idx := strings.Index(rawMsg, ": "); idx > 0 {
		prefix := strings.TrimSpace(rawMsg[:idx])
		if mapped, ok := javaExceptionToESSnakeTypeRound61[prefix]; ok {
			cType = mapped
			cReason = strings.TrimSpace(rawMsg[idx+2:])
		} else if strings.HasSuffix(prefix, "_exception") || strings.HasSuffix(prefix, "_error") {
			cType = prefix
			cReason = strings.TrimSpace(rawMsg[idx+2:])
		}
	}
	if strings.Contains(cReason, "maximum step budget") || strings.Contains(cReason, "maximum pinned container") || strings.Contains(cReason, "maximum tracked container") {
		if cType == "illegal_argument_exception" {
			cType = "painless_error"
		}
	}
	if idxJava := strings.Index(cReason, " (java."); idxJava > 0 && strings.HasSuffix(cReason, ")") {
		cReason = strings.TrimSpace(cReason[:idxJava])
	}
	return "script_exception", "runtime error", cType, cReason, nil
}

// FormatScriptFieldsPhaseErrorRound61 builds Elasticsearch's HTTP 400
// `search_phase_execution_exception` response for `script_fields` compile and runtime failures,
// including `root_cause[0]` (`script_exception`) and `failed_shards[0].reason.caused_by`
// (`20_scriptfield.yml`, `50_script_doc_values.yml`).
func FormatScriptFieldsPhaseErrorRound61(indexName, scriptFieldName, scriptSource string, err error) (int, map[string]any) {
	if strings.TrimSpace(indexName) == "" {
		indexName = "_index"
	}
	outerType, outerReason, causedByType, causedByReason, pos := ClassifyPainlessRuntimeErrorRound61(err)
	phase := "fetch"
	if outerReason == "compile error" {
		phase = "query"
	}

	rootEntry := map[string]any{
		"type":         outerType,
		"reason":       outerReason,
		"script_stack": []string{scriptSource},
		"script":       scriptSource,
		"lang":         "painless",
	}
	if pos != nil {
		rootEntry["position"] = pos
	}

	shardReason := map[string]any{
		"type":         outerType,
		"reason":       outerReason,
		"script_stack": []string{scriptSource},
		"script":       scriptSource,
		"lang":         "painless",
	}
	if pos != nil {
		shardReason["position"] = pos
	}
	if causedByType != "" {
		shardReason["caused_by"] = map[string]any{
			"type":   causedByType,
			"reason": causedByReason,
		}
	}

	errBody := map[string]any{
		"root_cause": []map[string]any{rootEntry},
		"type":       "search_phase_execution_exception",
		"reason":     "all shards failed",
		"phase":      phase,
		"grouped":    true,
		"failed_shards": []map[string]any{
			{
				"shard":  0,
				"index":  indexName,
				"node":   "doris-node-1",
				"reason": shardReason,
			},
		},
	}
	if causedByType != "" {
		errBody["caused_by"] = map[string]any{
			"type":         outerType,
			"reason":       outerReason,
			"script_stack": []string{scriptSource},
			"script":       scriptSource,
			"lang":         "painless",
			"caused_by": map[string]any{
				"type":   causedByType,
				"reason": causedByReason,
			},
		}
	}
	return http.StatusBadRequest, map[string]any{
		"error":  errBody,
		"status": http.StatusBadRequest,
	}
}

// ValidateNonNegativeScriptScoreRound61 enforces Elasticsearch's `script_score` output contract:
// scores must be finite and >= 0 (`30_search.yml`: `"script score function must not produce negative scores, but got: [-9.0]"`).
func ValidateNonNegativeScriptScoreRound61(score float64) error {
	if math.IsNaN(score) {
		return fmt.Errorf("illegal_argument_exception: script score function must not produce NaN")
	}
	if math.IsInf(score, 0) {
		return fmt.Errorf("illegal_argument_exception: script score function must produce finite scores, but got: [%s]", formatJavaDoubleRound60(score))
	}
	if score < 0 {
		return fmt.Errorf("illegal_argument_exception: script score function must not produce negative scores, but got: [%s]", formatJavaDoubleRound60(score))
	}
	return nil
}

// FormatScriptScorePhaseErrorRound61 builds Elasticsearch's HTTP 400
// `search_phase_execution_exception` response for `script_score` and `function_score.script_score`
// failures, preserving `root_cause[0].type = "script_exception"` + `caused_by` on script errors
// and `root_cause[0].type = "illegal_argument_exception"` on negative/NaN scores.
func FormatScriptScorePhaseErrorRound61(indexName, scriptSource string, err error) (int, map[string]any) {
	if strings.TrimSpace(indexName) == "" {
		indexName = "_index"
	}
	if err != nil {
		msg := strings.TrimSpace(err.Error())
		if strings.Contains(msg, "script score function must") {
			clean := strings.TrimPrefix(msg, "illegal_argument_exception: ")
			rc := map[string]any{
				"type":   "illegal_argument_exception",
				"reason": clean,
			}
			return http.StatusBadRequest, map[string]any{
				"error": map[string]any{
					"root_cause": []map[string]any{rc},
					"type":       "search_phase_execution_exception",
					"reason":     "all shards failed",
					"phase":      "query",
					"grouped":    true,
					"failed_shards": []map[string]any{
						{
							"shard":  0,
							"index":  indexName,
							"node":   "doris-node-1",
							"reason": rc,
						},
					},
					"caused_by": rc,
				},
				"status": http.StatusBadRequest,
			}
		}
	}

	outerType, outerReason, causedByType, causedByReason, pos := ClassifyPainlessRuntimeErrorRound61(err)
	rootEntry := map[string]any{
		"type":         outerType,
		"reason":       outerReason,
		"script_stack": []string{scriptSource},
		"script":       scriptSource,
		"lang":         "painless",
	}
	if pos != nil {
		rootEntry["position"] = pos
	}
	shardReason := map[string]any{
		"type":         outerType,
		"reason":       outerReason,
		"script_stack": []string{scriptSource},
		"script":       scriptSource,
		"lang":         "painless",
	}
	if pos != nil {
		shardReason["position"] = pos
	}
	if causedByType != "" {
		shardReason["caused_by"] = map[string]any{
			"type":   causedByType,
			"reason": causedByReason,
		}
	}
	errBody := map[string]any{
		"root_cause": []map[string]any{rootEntry},
		"type":       "search_phase_execution_exception",
		"reason":     "all shards failed",
		"phase":      "query",
		"grouped":    true,
		"failed_shards": []map[string]any{
			{
				"shard":  0,
				"index":  indexName,
				"node":   "doris-node-1",
				"reason": shardReason,
			},
		},
	}
	if causedByType != "" {
		errBody["caused_by"] = shardReason
	}
	return http.StatusBadRequest, map[string]any{
		"error":  errBody,
		"status": http.StatusBadRequest,
	}
}

// BuildScriptScoreExplainNodeRound61 builds Elasticsearch's Lucene Explanation tree
// for `script_score` queries (`_explain` API and search `explain: true`).
func BuildScriptScoreExplainNodeRound61(finalScore float64, scriptSource string, params map[string]any, subQueryExplain map[string]any) map[string]any {
	paramStr := "{}"
	if len(params) > 0 {
		keys := make([]string, 0, len(params))
		for k := range params {
			if strings.HasPrefix(k, "__") || k == "_score" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s=%v", k, params[k]))
			}
			paramStr = "{" + strings.Join(parts, ", ") + "}"
		}
	}
	details := make([]map[string]any, 0, 1)
	if subQueryExplain != nil {
		if strings.Contains(scriptSource, "_score") {
			details = append(details, map[string]any{
				"value":       subQueryExplain["value"],
				"description": "_score: ",
				"details":     []map[string]any{subQueryExplain},
			})
		} else {
			details = append(details, subQueryExplain)
		}
	}
	desc := fmt.Sprintf("script score function, computed with script:\"Script{type=inline, lang='painless', idOrCode='%s', options={}, params=%s}\"", scriptSource, paramStr)
	return map[string]any{
		"value":       finalScore,
		"description": desc,
		"details":     details,
	}
}

// ============================================================================
// Round 61 F21 & F26: `/_scripts/painless/_context` Payloads & Update / UBQ
// Write `field(...)` + `ctx` Validation Helper
// ============================================================================

// GetPainlessContextsPayloadRound61 returns the `{"contexts": [...]}` payload for
// `GET /_scripts/painless/_context`.
func GetPainlessContextsPayloadRound61() map[string]any {
	return map[string]any{
		"contexts": painlessScriptContextsListRound61(),
	}
}

// GetPainlessContextDetailPayloadRound61 returns `(status, payload)` for
// `GET /_scripts/painless/_context/{context}`.
func GetPainlessContextDetailPayloadRound61(ctxName string) (int, map[string]any) {
	trimmed := strings.TrimSpace(ctxName)
	if trimmed == "" || trimmed == "_context" {
		return http.StatusOK, GetPainlessContextsPayloadRound61()
	}
	if !isKnownPainlessContextRound61(trimmed) {
		reason := fmt.Sprintf("Unable to find script context [%s] for lang [painless]", trimmed)
		return http.StatusBadRequest, map[string]any{
			"error": map[string]any{
				"root_cause": []map[string]any{
					{
						"type":   "illegal_argument_exception",
						"reason": reason,
					},
				},
				"type":   "illegal_argument_exception",
				"reason": reason,
			},
			"status": http.StatusBadRequest,
		}
	}
	return http.StatusOK, buildPainlessContextAPIPayloadRound61(trimmed)
}

// EvalUpdateScriptWithFieldsAPIRound61 executes a Painless `_update` or `_update_by_query`
// script (`painless.ScriptSpec` supporting JSON string shorthand or object form) with:
//   - Mutable ES 8 Write Fields API (`field('a.b').set(...)`, `.remove()`, `.get(def)`, `.transform(...)`, `.doc()`)
//   - `metadata()` wrapper (`15_update.yml` / `16_update_field_api.yml`)
//   - `ctx` validation (`ctx.junk` unknown key, `ctx._id` modification, `ctx.op` validation, ES 8 `ctx._version = -1`)
//   - Upsert `_routing` guard (`CheckUpsertRoutingGuardRound61`)
//   - Cyclic self-referencing container check (`"Iterable object is self-referencing itself"`).
func EvalUpdateScriptWithFieldsAPIRound61(
	doc map[string]any,
	origID string,
	indexName string,
	version int64,
	routing string,
	routingRequired bool,
	docExisted bool,
	scriptSpec painless.ScriptSpec,
	isUBQ bool,
	isES8 bool,
) (string, error) {
	lang := strings.ToLower(strings.TrimSpace(scriptSpec.Lang))
	if lang != "" && lang != "painless" {
		return "", fmt.Errorf("illegal_argument_exception: script_lang not supported [%s]", scriptSpec.Lang)
	}
	if err := painless.CompileValidate(scriptSpec.EffectiveSource()); err != nil {
		return "", err
	}
	params := make(map[string]any, len(scriptSpec.Params)+12)
	for k, v := range scriptSpec.Params {
		params[k] = v
	}
	params["_ctx_id"] = origID
	params["_ctx_index"] = indexName
	if version > 0 {
		params["_ctx_version"] = version
	} else {
		params["_ctx_version"] = int64(1)
	}
	if routing != "" {
		params["_ctx_routing"] = routing
	}
	params["__is_ubq"] = isUBQ
	params["__is_update_doc"] = !isUBQ
	params["__is_es8"] = isES8
	params["__mutable_fields_api"] = true
	if !docExisted {
		params["__upsert_insert_mode"] = true
		if routing == "" {
			params["__upsert_forbid_routing"] = true
		}
	}

	origVer := params["_ctx_version"]
	op, err := painless.EvalPainlessWithOp(doc, scriptSpec.EffectiveSource(), params)
	if err != nil {
		return "", err
	}
	if op == "" {
		op = "index"
	}
	mutatedRouting := ""
	if rVal, ok := params["_ctx_routing"]; ok && rVal != nil {
		mutatedRouting = fmt.Sprintf("%v", rVal)
	}
	existingRouting := ""
	if docExisted {
		existingRouting = routing
	}
	if err := painless.CheckUpsertRoutingGuardRound61(routingRequired, routing, existingRouting, mutatedRouting, docExisted); err != nil {
		return "", err
	}
	versionMutated := fmt.Sprintf("%v", params["_ctx_version"]) != fmt.Sprintf("%v", origVer)
	if err := painless.ValidateUBQAndUpdateCtx(
		map[string]any{
			"_source":  doc,
			"_id":      params["_ctx_id"],
			"_index":   params["_ctx_index"],
			"_version": params["_ctx_version"],
			"op":       op,
		},
		origID,
		isUBQ,
		isES8,
		versionMutated,
	); err != nil {
		return "", err
	}
	return op, nil
}
