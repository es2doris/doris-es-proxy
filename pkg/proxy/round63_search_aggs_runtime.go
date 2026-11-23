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
	"container/heap"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/analysis"
	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// ============================================================================
// F26 & F27 (C-05 / C-06): Immutable Request-Scoped Search Context, Explicit
// `idxSchema` Script Evaluator, Per-Request `lookup` Runtime Specs & Wire Dedup
// ============================================================================

const r63DocLookupScopeSentinel = "\x00__r63_active_search_scope__"

type activeSearchScopeCtxKeyR63 struct{}

type lookupRuntimeSpecR63Search struct {
	TargetIndex string
	InputField  string
	TargetField string
	FetchFields []string
}

// activeSearchScope holds immutable per-request search context (replacing all
// process-global R62 search/lookup/schema state so concurrent requests never race or bleed).
type activeSearchScope struct {
	srv               *Server
	ctx               context.Context
	rawBody           []byte
	searchReq         *esast.SearchRequest
	strictConformance bool
	reqLookupSpecs    map[string]lookupRuntimeSpecR63Search
	schemasByIndex    map[string]*schema.IndexSchema
}

func newActiveSearchScopeR63(ctx context.Context, srv *Server, rawBody []byte, req *esast.SearchRequest) *activeSearchScope {
	var rawCopy []byte
	if len(rawBody) > 0 {
		rawCopy = append([]byte(nil), rawBody...)
	}
	reqLookups := extractRequestLookupSpecsR63(rawCopy, req)
	strict := srv != nil && srv.hasExplicitTargetESVersion()
	return &activeSearchScope{
		srv:               srv,
		ctx:               ctx,
		rawBody:           rawCopy,
		searchReq:         req,
		strictConformance: strict,
		reqLookupSpecs:    reqLookups,
	}
}

func withActiveSearchScopeR63(ctx context.Context, scope *activeSearchScope) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if scope == nil {
		return ctx
	}
	next := context.WithValue(ctx, activeSearchScopeCtxKeyR63{}, scope)
	scope.ctx = next
	return next
}

func activeSearchScopeFromCtxR63(ctx context.Context) *activeSearchScope {
	if ctx == nil {
		return nil
	}
	if sc, ok := ctx.Value(activeSearchScopeCtxKeyR63{}).(*activeSearchScope); ok {
		return sc
	}
	return nil
}

func scopeFromDocLookupR63(docLookup func(string) *HitRow) *activeSearchScope {
	if docLookup == nil {
		return nil
	}
	if hr := docLookup(r63DocLookupScopeSentinel); hr != nil {
		return hr.SearchScope
	}
	return nil
}

func lookupSpecFromFieldPropertyR63(prop esast.FieldProperty) (lookupRuntimeSpecR63Search, bool) {
	if !prop.IsLookupRuntime() {
		return lookupRuntimeSpecR63Search{}, false
	}
	return lookupRuntimeSpecR63Search{
		TargetIndex: strings.TrimSpace(prop.TargetIndex),
		InputField:  strings.TrimSpace(prop.InputField),
		TargetField: strings.TrimSpace(prop.EffectiveLookupTargetField()),
		FetchFields: prop.LookupFetchFieldNames(),
	}, true
}

func extractRequestLookupSpecsR63(rawBody []byte, req *esast.SearchRequest) map[string]lookupRuntimeSpecR63Search {
	var out map[string]lookupRuntimeSpecR63Search
	if req != nil && len(req.RuntimeMappings) > 0 {
		for fn, prop := range req.RuntimeMappings {
			if ls, ok := lookupSpecFromFieldPropertyR63(prop); ok {
				if out == nil {
					out = make(map[string]lookupRuntimeSpecR63Search)
				}
				out[fn] = ls
			}
		}
	}
	if len(bytes.TrimSpace(rawBody)) > 0 && bytes.Contains(rawBody, []byte("lookup")) {
		var root struct {
			RuntimeMappings map[string]esast.FieldProperty `json:"runtime_mappings"`
		}
		if json.Unmarshal(rawBody, &root) == nil && len(root.RuntimeMappings) > 0 {
			for fn, prop := range root.RuntimeMappings {
				if ls, ok := lookupSpecFromFieldPropertyR63(prop); ok {
					if out == nil {
						out = make(map[string]lookupRuntimeSpecR63Search)
					}
					out[fn] = ls
				}
			}
		}
	}
	return out
}

func resolveLookupRuntimeSpecForFieldR63Search(
	scope *activeSearchScope,
	idxSchema *schema.IndexSchema,
	fieldName string,
	rtDefProp esast.FieldProperty,
) (lookupRuntimeSpecR63Search, bool) {
	if ls, ok := lookupSpecFromFieldPropertyR63(rtDefProp); ok && ls.TargetIndex != "" {
		return ls, true
	}
	if scope != nil && len(scope.reqLookupSpecs) > 0 {
		if ls, ok := scope.reqLookupSpecs[fieldName]; ok {
			return ls, true
		}
	}
	if idxSchema != nil && idxSchema.RawMapping != nil && len(idxSchema.RawMapping.Runtime) > 0 {
		if prop, ok := idxSchema.RawMapping.Runtime[fieldName]; ok {
			if ls, okL := lookupSpecFromFieldPropertyR63(prop); okL {
				return ls, true
			}
		}
	}
	return lookupRuntimeSpecR63Search{}, false
}

// copyRecorderHeadersSetR63 copies headers from an internal `httptest.ResponseRecorder`
// using `Set` replacement semantics (`w.Header()[k] = append([]string(nil), vals...)`) so
// middleware headers like `X-Opaque-Id`, `X-Elastic-Product`, and `Content-Type` are never duplicated,
// while preserving distinct `Warning` header values.
func copyRecorderHeadersSetR63(w http.ResponseWriter, src http.Header) {
	if w == nil || len(src) == 0 {
		return
	}
	dst := w.Header()
	for k, vals := range src {
		if len(vals) == 0 {
			continue
		}
		if strings.EqualFold(k, "Warning") {
			existing := dst["Warning"]
			merged := make([]string, 0, len(existing)+len(vals))
			seen := make(map[string]bool, len(existing)+len(vals))
			for _, ev := range existing {
				if !seen[ev] {
					seen[ev] = true
					merged = append(merged, ev)
				}
			}
			for _, v := range vals {
				if !seen[v] {
					seen[v] = true
					merged = append(merged, v)
				}
			}
			dst["Warning"] = merged
			continue
		}
		dst[k] = append([]string(nil), vals...)
	}
}

func isMaxBytesBodyErrorR63(err error) bool {
	if err == nil {
		return false
	}
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

// extractConstantKeywordValuesMapR63 collects mapped `constant_keyword` field -> constant string
// pairs from `idxSchema` so `field('const').get(null)` resolves even when omitted from `_source`.
func extractConstantKeywordValuesMapR63(idxSchema *schema.IndexSchema) map[string]string {
	if idxSchema == nil {
		return nil
	}
	var out map[string]string
	setConst := func(path string, val any) {
		if path == "" || val == nil {
			return
		}
		if out == nil {
			out = make(map[string]string)
		}
		out[path] = fmt.Sprintf("%v", val)
	}
	for fPath, fb := range idxSchema.Fields {
		if strings.EqualFold(strings.TrimSpace(fb.ESType), "constant_keyword") && fb.HasConstantValue && fb.ConstantValue != nil {
			setConst(fPath, fb.ConstantValue)
		}
	}
	if idxSchema.RawMapping != nil && len(idxSchema.RawMapping.Properties) > 0 {
		var walk func(props map[string]esast.FieldProperty, prefix string)
		walk = func(props map[string]esast.FieldProperty, prefix string) {
			for k, prop := range props {
				full := k
				if prefix != "" {
					full = prefix + "." + k
				}
				if strings.EqualFold(strings.TrimSpace(prop.Type), "constant_keyword") && prop.Value != nil {
					setConst(full, prop.Value)
				}
				for mfk, mfp := range prop.Fields {
					if strings.EqualFold(strings.TrimSpace(mfp.Type), "constant_keyword") && mfp.Value != nil {
						setConst(full+"."+mfk, mfp.Value)
					}
				}
				if len(prop.Properties) > 0 {
					walk(prop.Properties, full)
				}
			}
		}
		walk(idxSchema.RawMapping.Properties, "")
	}
	return out
}

// enrichRuntimeScriptDocBindingsR63 populates `__constant_keyword_values` and synthesizes
// `token_count` doc-value counts on `cp` (`50_script_doc_values.yml`, `10_script_values.yml`).
func enrichRuntimeScriptDocBindingsR63(idxSchema *schema.IndexSchema, doc map[string]any, cp map[string]any, ftMap map[string]string) {
	if idxSchema == nil || cp == nil {
		return
	}
	if constMap := extractConstantKeywordValuesMapR63(idxSchema); len(constMap) > 0 {
		cp["__constant_keyword_values"] = constMap
	}
	if doc == nil || len(ftMap) == 0 {
		return
	}
	for fPath, ft := range ftMap {
		if ft != "token_count" {
			continue
		}
		if existing, ok := lookupRawPathValueRound61(cp, strings.Split(fPath, ".")); ok {
			if _, isInt := existing.(int64); isInt {
				continue
			}
		}
		if shredMap, okS := doc["__shredded_fields"].(map[string]any); okS && len(shredMap) > 0 {
			if b, okB := idxSchema.Fields[fPath]; okB && b.ColumnName != "" {
				if cnt, okI := toInt64(shredMap[b.ColumnName]); okI {
					cp[fPath] = cnt
					if strings.Contains(fPath, ".") {
						setRuntimeScriptDocPath(cp, strings.Split(fPath, "."), cnt)
					}
					continue
				}
			}
		}
		analyzer := "standard"
		enablePosInc := true
		var bBind schema.FieldBinding
		if b, ok := idxSchema.Fields[fPath]; ok {
			bBind = b
			if b.Analyzer != "" {
				analyzer = b.Analyzer
			}
		}
		if fp, okRaw := lookupRawPropertyWithMultiFieldR61Search(idxSchema, fPath); okRaw {
			if strings.TrimSpace(fp.Analyzer) != "" {
				analyzer = strings.TrimSpace(fp.Analyzer)
			}
			if fp.EnablePositionIncrements != nil {
				enablePosInc = *fp.EnablePositionIncrements
			}
		}
		srcSegs := effectiveTokenCountSourceSegsR61Search(fPath, bBind, idxSchema)
		rawStrs := collectStringValuesAtPath(doc, srcSegs)
		if len(rawStrs) == 0 && strings.Contains(fPath, ".") {
			parentPath := fPath[:strings.LastIndexByte(fPath, '.')]
			rawStrs = collectStringValuesAtPath(doc, strings.Split(parentPath, "."))
		}
		if len(rawStrs) == 0 && idxSchema.RawMapping != nil {
			for _, ctSrc := range collectCopyToSourcePaths(idxSchema.RawMapping.Properties, "", fPath) {
				rawStrs = append(rawStrs, collectStringValuesAtPath(doc, strings.Split(ctSrc, "."))...)
			}
		}
		if len(rawStrs) == 0 {
			continue
		}
		var totalTokens int64
		hasAny := false
		for _, s := range rawStrs {
			hasAny = true
			res, err := analysis.Analyze(analysis.AnalyzeRequest{
				Text:     []string{s},
				Analyzer: analyzer,
			})
			if err == nil && res != nil {
				if enablePosInc && len(res.Tokens) > 0 {
					maxPos := 0
					for _, tk := range res.Tokens {
						endPos := tk.Position + 1
						if endPos > maxPos {
							maxPos = endPos
						}
					}
					totalTokens += int64(maxPos)
				} else {
					totalTokens += int64(len(res.Tokens))
				}
			} else {
				totalTokens += int64(len(transpiler.TokenizeByAnalyzer(s, analyzer)))
			}
		}
		if hasAny {
			cp[fPath] = totalTokens
			if strings.Contains(fPath, ".") {
				setRuntimeScriptDocPath(cp, strings.Split(fPath, "."), totalTokens)
			}
		}
	}
}

// evalIndexTimeFieldScriptWithSchemaR63Search evaluates index-time `mappings.properties.<f>.script`
// using the explicit `idxSchema` passed by `schema.ShredDocument` (zero global schema state) and sets
// `__forbid_metadata_routing = true` (`80_index_field.yml`).
func evalIndexTimeFieldScriptWithSchemaR63Search(
	idxSchema *schema.IndexSchema,
	fieldPath string,
	esType string,
	scriptSpec any,
	onScriptError string,
	sourceDoc map[string]any,
) ([]any, error) {
	isES8 := idxSchema == nil || idxSchema.ES8Mode
	workingDoc := deepCloneDocMap(sourceDoc)
	if workingDoc == nil {
		workingDoc = make(map[string]any)
	}
	nowUTC := time.Now().UTC()
	fieldsParam := buildStoredFieldsParamMapR62Search(idxSchema, sourceDoc)

	if idxSchema != nil && idxSchema.RawMapping != nil {
		scriptProps := make(map[string]esast.FieldProperty)
		collectMappedScriptPropsR62Search(idxSchema.RawMapping.Properties, "", scriptProps)
		if _, ok := scriptProps[fieldPath]; ok {
			order, err := resolveLazyRuntimeMappingsOrderR62Search(scriptProps, []string{fieldPath})
			if err != nil {
				return nil, err
			}
			evalDoc := PrepareDocForRuntimeScriptRound61(idxSchema, workingDoc, isES8)
			ftMap, _ := evalDoc["__field_types"].(map[string]string)
			if ftMap == nil {
				ftMap = make(map[string]string)
				evalDoc["__field_types"] = ftMap
			}
			for fn, sp := range scriptProps {
				t := strings.ToLower(strings.TrimSpace(sp.Type))
				if t == "" {
					t = "keyword"
				}
				ftMap[fn] = t
			}
			for _, depName := range order {
				depProp := scriptProps[depName]
				coerced, depErr := evalSingleIndexTimeOrRuntimePropWithOptsR63Search(
					idxSchema, depName, depProp, evalDoc, sourceDoc, fieldsParam, ftMap, isES8, nowUTC, true,
				)
				if depErr != nil {
					depOnErr := strings.ToLower(strings.TrimSpace(depProp.OnScriptError))
					if depName == fieldPath && strings.EqualFold(onScriptError, "continue") {
						return nil, nil
					}
					if depOnErr == "continue" {
						continue
					}
					return nil, fmt.Errorf("script_exception: runtime error: %w", depErr)
				}
				if depName == fieldPath {
					return coerced, nil
				}
				if len(coerced) > 0 {
					var val any = coerced
					if len(coerced) == 1 {
						val = coerced[0]
					}
					workingDoc[depName] = val
					if strings.Contains(depName, ".") {
						setIngestPath(workingDoc, depName, val)
					}
					evalDoc[depName] = val
					if strings.Contains(depName, ".") {
						setRuntimeScriptDocPath(evalDoc, strings.Split(depName, "."), val)
					}
				}
			}
			return nil, nil
		}
	}

	evalDoc := PrepareDocForRuntimeScriptRound61(idxSchema, workingDoc, isES8)
	ftMap, _ := evalDoc["__field_types"].(map[string]string)
	if ftMap == nil {
		ftMap = make(map[string]string)
		evalDoc["__field_types"] = ftMap
	}
	if esType != "" {
		ftMap[fieldPath] = esType
	}
	coerced, err := evalSingleIndexTimeOrRuntimePropWithOptsR63Search(
		idxSchema,
		fieldPath,
		esast.FieldProperty{Type: esType, Script: scriptSpec, OnScriptError: onScriptError},
		evalDoc,
		sourceDoc,
		fieldsParam,
		ftMap,
		isES8,
		nowUTC,
		true,
	)
	if err != nil {
		if strings.EqualFold(onScriptError, "continue") {
			return nil, nil
		}
		return nil, fmt.Errorf("script_exception: runtime error: %w", err)
	}
	return coerced, nil
}

func evalSingleIndexTimeOrRuntimePropWithOptsR63Search(
	idxSchema *schema.IndexSchema,
	fieldPath string,
	prop esast.FieldProperty,
	evalDoc map[string]any,
	sourceDoc map[string]any,
	fieldsParam map[string]any,
	ftMap map[string]string,
	isES8 bool,
	nowUTC time.Time,
	forbidMetadataRouting bool,
) ([]any, error) {
	_ = fieldPath
	esType := strings.ToLower(strings.TrimSpace(prop.Type))
	if esType == "" {
		esType = "keyword"
	}
	scriptSrc, scriptParams := extractScriptSourceAndParams(prop.Script)
	if strings.TrimSpace(scriptSrc) == "" {
		return nil, nil
	}
	p := make(map[string]any, len(scriptParams)+8)
	for k, v := range scriptParams {
		p[k] = v
	}
	p["_source"] = sourceDoc
	p["__keep_boolean_dups"] = isES8
	p["__quantize_geo_point"] = true
	if forbidMetadataRouting {
		p["__forbid_metadata_routing"] = true
	}
	if constMap := extractConstantKeywordValuesMapR63(idxSchema); len(constMap) > 0 {
		p["__constant_keyword_values"] = constMap
	}
	if strings.TrimSpace(prop.Format) != "" {
		p["__runtime_date_format"] = strings.TrimSpace(prop.Format)
	}
	if fieldsParam != nil {
		p["_fields"] = fieldsParam
	}

	var rawVals []any
	if emitCtx, okCtx := runtimeFieldTypeToEmitContextR64(esType); okCtx && strings.Contains(scriptSrc, "emit(") {
		emitted, errEmit := painless.EvalEmitContext(scriptSrc, emitCtx, evalDoc, sourceDoc, p, ftMap)
		if errEmit != nil {
			return nil, errEmit
		}
		rawVals = emitted
	} else {
		res, evalErr := painless.Eval(evalDoc, scriptSrc, p)
		if evalErr != nil {
			return nil, evalErr
		}
		if emitted, ok := p["__emitted_vals"].([]any); ok && len(emitted) > 0 {
			rawVals = emitted
		} else if res != nil {
			if arr, ok := res.([]any); ok {
				rawVals = arr
			} else {
				rawVals = []any{res}
			}
		}
	}
	if len(rawVals) == 0 {
		return nil, nil
	}
	return coerceEmittedRuntimeValuesRound61(esType, prop.Format, rawVals, nowUTC), nil
}

// ============================================================================
// F29 (C-12): Race-Free & Untrimmed `scripted_metric` Allow-List Check
// ============================================================================

// extractUntrimmedScriptSourceR63 returns the exact untrimmed inline script `source`
// string (preserving leading/trailing spaces and newlines) so whitespace cannot bypass
// `search.aggs.allowed_inline_metric_scripts` (`C-12`).
func extractUntrimmedScriptSourceR63(raw any) (string, bool) {
	if raw == nil {
		return "", false
	}
	switch v := raw.(type) {
	case string:
		return v, true
	case *esast.ScriptSpec:
		if v == nil || v.ID != "" {
			return "", false
		}
		return v.Source, true
	case esast.ScriptSpec:
		if v.ID != "" {
			return "", false
		}
		return v.Source, true
	case map[string]any:
		if sub, hasSub := v["script"]; hasSub && sub != nil {
			return extractUntrimmedScriptSourceR63(sub)
		}
		if idStr, okID := v["id"].(string); okID && strings.TrimSpace(idStr) != "" {
			return "", false
		}
		for _, k := range []string{"source", "inline", "code"} {
			if s, okS := v[k].(string); okS {
				return s, true
			}
		}
	}
	return "", false
}

func validateScriptedMetricAllowListR63Search(s *Server, aggs map[string]esast.AggSpec) (int, string, string) {
	if s == nil || len(aggs) == 0 {
		return 0, "", ""
	}
	// Read and materialize allow-list sets completely inside `s.mu.RLock()` (`C-12`).
	s.mu.RLock()
	lookupLocked := func(key string) (any, bool) {
		if v, ok := lookupNestedClusterSettingR62Admin(s.clusterTransientSettings, key); ok && v != nil {
			return v, true
		}
		if v, ok := lookupNestedClusterSettingR62Admin(s.clusterPersistentSettings, key); ok && v != nil {
			return v, true
		}
		return nil, false
	}
	rawOnly, hasOnly := lookupLocked("search.aggs.only_allowed_metric_scripts")
	if !hasOnly {
		s.mu.RUnlock()
		return 0, "", ""
	}
	onlyAllowed, okB := parseOptionalBoolAny(rawOnly)
	if !okB || !onlyAllowed {
		s.mu.RUnlock()
		return 0, "", ""
	}
	buildSetLocked := func(key string) map[string]bool {
		out := make(map[string]bool)
		raw, ok := lookupLocked(key)
		if !ok || raw == nil {
			return out
		}
		switch tv := raw.(type) {
		case []string:
			for _, item := range tv {
				out[item] = true
			}
		case []any:
			for _, item := range tv {
				if str, okS := item.(string); okS {
					out[str] = true
				} else {
					out[fmt.Sprintf("%v", item)] = true
				}
			}
		case string:
			if tv != "" {
				out[tv] = true
			}
		}
		return out
	}
	allowedInline := buildSetLocked("search.aggs.allowed_inline_metric_scripts")
	allowedStored := buildSetLocked("search.aggs.allowed_stored_metric_scripts")
	s.mu.RUnlock()

	isScriptAllowed := func(rawScript any) bool {
		if rawScript == nil {
			return true
		}
		if id, hasID := extractStoredScriptIDRound61(rawScript); hasID {
			return allowedStored[id]
		}
		src, ok := extractUntrimmedScriptSourceR63(rawScript)
		if !ok {
			return false
		}
		return allowedInline[src]
	}

	var walk func(m map[string]esast.AggSpec) (int, string, string)
	walk = func(m map[string]esast.AggSpec) (int, string, string) {
		names := make([]string, 0, len(m))
		for k := range m {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, aggName := range names {
			spec := m[aggName]
			if spec.ScriptedMetric != nil {
				for _, entry := range []struct {
					field string
					raw   any
				}{
					{"init_script", spec.ScriptedMetric.InitScript},
					{"map_script", spec.ScriptedMetric.MapScript},
					{"combine_script", spec.ScriptedMetric.CombineScript},
					{"reduce_script", spec.ScriptedMetric.ReduceScript},
				} {
					if entry.raw != nil && !isScriptAllowed(entry.raw) {
						return http.StatusBadRequest,
							"search_phase_execution_exception",
							fmt.Sprintf("all_shards_failed|illegal_argument_exception|[%s] contains not allowed script: [%s]", entry.field, aggName)
					}
				}
			}
			if sub := spec.SubAggs(); len(sub) > 0 {
				if st, et, er := walk(sub); st != 0 {
					return st, et, er
				}
			}
		}
		return 0, "", ""
	}
	return walk(aggs)
}

func parseOrderedIndicesBoostFromRawR63(raw []byte, fallback map[string]float64) []map[string]float64 {
	if len(bytes.TrimSpace(raw)) > 0 {
		var root struct {
			IndicesBoost json.RawMessage `json:"indices_boost"`
		}
		if json.Unmarshal(raw, &root) == nil && len(bytes.TrimSpace(root.IndicesBoost)) > 0 {
			trim := bytes.TrimSpace(root.IndicesBoost)
			if trim[0] == '[' {
				var arr []map[string]float64
				if json.Unmarshal(trim, &arr) == nil && len(arr) > 0 {
					return arr
				}
			}
		}
	}
	if len(fallback) == 0 {
		return nil
	}
	return []map[string]float64{fallback}
}

func scopeRawBodyR63(scope *activeSearchScope) []byte {
	if scope == nil {
		return nil
	}
	return scope.rawBody
}

func scopeFromMatchedDocsR63(fgDocs, allDocs []runtimeMatchedDoc) *activeSearchScope {
	for i := range fgDocs {
		if fgDocs[i].hit.SearchScope != nil {
			return fgDocs[i].hit.SearchScope
		}
	}
	for i := range allDocs {
		if allDocs[i].hit.SearchScope != nil {
			return allDocs[i].hit.SearchScope
		}
	}
	return nil
}

func extractSigHeuristicForAggFromRawR63(raw []byte, fullAggName string) sigHeuristicSpecR62Search {
	if len(bytes.TrimSpace(raw)) == 0 {
		return sigHeuristicSpecR62Search{kind: "jlh"}
	}
	var root map[string]any
	if json.Unmarshal(raw, &root) != nil || root == nil {
		return sigHeuristicSpecR62Search{kind: "jlh"}
	}
	segs := strings.Split(fullAggName, ".")
	cur := root
	for i, seg := range segs {
		aggsObj, _ := cur["aggs"].(map[string]any)
		if aggsObj == nil {
			aggsObj, _ = cur["aggregations"].(map[string]any)
		}
		if aggsObj == nil {
			return sigHeuristicSpecR62Search{kind: "jlh"}
		}
		next, ok := aggsObj[seg].(map[string]any)
		if !ok || next == nil {
			return sigHeuristicSpecR62Search{kind: "jlh"}
		}
		cur = next
		if i == len(segs)-1 {
			stMap, _ := cur["significant_text"].(map[string]any)
			if stMap == nil {
				stMap, _ = cur["significant_terms"].(map[string]any)
			}
			for _, hk := range []string{"percentage", "gnd", "mutual_information", "chi_square", "jlh"} {
				if rawH, hasH := stMap[hk]; hasH && rawH != nil {
					pm, _ := rawH.(map[string]any)
					if pm == nil {
						pm = map[string]any{}
					}
					return sigHeuristicSpecR62Search{kind: hk, params: pm}
				}
			}
		}
	}
	return sigHeuristicSpecR62Search{kind: "jlh"}
}

func aggHasShowDistributionFromRawR65(raw []byte, fullAggName string) bool {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false
	}
	var root map[string]any
	if json.Unmarshal(raw, &root) != nil || root == nil {
		return false
	}
	segs := strings.Split(fullAggName, ".")
	cur := root
	for i, seg := range segs {
		aggsObj, _ := cur["aggs"].(map[string]any)
		if aggsObj == nil {
			aggsObj, _ = cur["aggregations"].(map[string]any)
		}
		if aggsObj == nil {
			return false
		}
		next, ok := aggsObj[seg].(map[string]any)
		if !ok || next == nil {
			return false
		}
		cur = next
		if i == len(segs)-1 {
			ssMap, _ := cur["string_stats"].(map[string]any)
			if ssMap == nil {
				return false
			}
			rawSD, okSD := ssMap["show_distribution"]
			if !okSD || rawSD == nil {
				return false
			}
			switch v := rawSD.(type) {
			case bool:
				return v
			case string:
				return strings.EqualFold(strings.TrimSpace(v), "true")
			}
		}
	}
	return false
}

func formatTermsBucketKeyAndStringWithScopeR63(
	scope *activeSearchScope,
	rawKey string,
	termsSpec *esast.TermsAggSpec,
	idxSchema *schema.IndexSchema,
) (any, string, bool) {
	if rawKey == "__ES_MISSING_BUCKET__" {
		return nil, "", false
	}
	if scope != nil && scope.strictConformance && termsSpec != nil {
		vt := strings.ToLower(strings.TrimSpace(termsSpec.ValueType))
		isBool := vt == "boolean"
		if !isBool && vt != "string" && idxSchema != nil && strings.TrimSpace(termsSpec.Field) != "" {
			b := idxSchema.ResolveField(termsSpec.Field)
			if b.ESType == "boolean" || b.DorisType == schema.DorisBoolean {
				isBool = true
			}
		}
		if isBool {
			lower := strings.ToLower(strings.TrimSpace(rawKey))
			if lower == "true" || lower == "1" {
				return int64(1), "true", true
			}
			if lower == "false" || lower == "0" {
				return int64(0), "false", true
			}
		}
	}
	if scope != nil && len(scope.schemasByIndex) > 1 && termsSpec != nil && strings.TrimSpace(termsSpec.Field) != "" && strings.TrimSpace(termsSpec.ValueType) == "" {
		var hasUL, hasSignedInt, hasFloat bool
		for _, sc := range scope.schemasByIndex {
			if sc == nil {
				continue
			}
			b := sc.ResolveField(termsSpec.Field)
			switch strings.ToLower(strings.TrimSpace(b.ESType)) {
			case "unsigned_long":
				hasUL = true
			case "long", "integer", "short", "byte":
				hasSignedInt = true
			case "double", "float", "half_float", "scaled_float":
				hasFloat = true
			}
		}
		if (hasUL && (hasSignedInt || hasFloat)) || (hasFloat && hasSignedInt) {
			if fv, err := strconv.ParseFloat(strings.TrimSpace(rawKey), 64); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
				if strings.TrimSpace(termsSpec.Format) != "" {
					return fv, formatTermsNumericPattern(fv, termsSpec.Format), true
				}
				return fv, "", false
			}
		}
	}
	return formatTermsBucketKeyAndString(rawKey, termsSpec, idxSchema)
}

func reEvaluatePercentilesBucketWithScopeR63(scope *activeSearchScope, aggs map[string]esast.AggSpec, aggsOut map[string]any) {
	if scope == nil || !scope.strictConformance || len(aggs) == 0 || len(aggsOut) == 0 {
		return
	}
	hasPctBucket := false
	for aggName, spec := range aggs {
		if spec.PercentilesBucket != nil {
			hasPctBucket = true
		}
		subAggs := spec.SubAggs()
		if len(subAggs) == 0 {
			continue
		}
		subMap, ok := aggsOut[aggName].(map[string]any)
		if !ok || subMap == nil {
			continue
		}
		switch rawB := subMap["buckets"].(type) {
		case []map[string]any:
			for _, b := range rawB {
				reEvaluatePercentilesBucketWithScopeR63(scope, subAggs, b)
			}
		case []any:
			for _, item := range rawB {
				if bm, okM := item.(map[string]any); okM {
					reEvaluatePercentilesBucketWithScopeR63(scope, subAggs, bm)
				}
			}
		case map[string]any:
			for _, item := range rawB {
				if bm, okM := item.(map[string]any); okM {
					reEvaluatePercentilesBucketWithScopeR63(scope, subAggs, bm)
				}
			}
		default:
			reEvaluatePercentilesBucketWithScopeR63(scope, subAggs, subMap)
		}
	}
	if hasPctBucket {
		evaluateSiblingPipelineAggsWithStrict(true, aggs, aggsOut)
		attachAllAggMetasRound60(aggsOut, aggs)
	}
}

// ============================================================================
// Group 2 (`F3`, `F4`, `F5`): Data Streams, TSDB, `logsdb` & Synthetic `_source`
// ============================================================================

func normalizeUnsupportedParametersSpacingR63(msg string) string {
	if strings.Contains(msg, "has unsupported parameters: [") {
		return strings.ReplaceAll(msg, "has unsupported parameters: [", "has unsupported parameters:  [")
	}
	return msg
}

func isDataStreamActiveWriteIndexLockedR63(s *Server, indexName string) (string, bool) {
	if s == nil || indexName == "" {
		return "", false
	}
	for dsName, ds := range s.dataStreams {
		if ds == nil {
			continue
		}
		rawIndices, ok := ds["indices"].([]any)
		if !ok || len(rawIndices) == 0 {
			continue
		}
		if lastMap, okM := rawIndices[len(rawIndices)-1].(map[string]any); okM {
			if bIdx, _ := lastMap["index_name"].(string); bIdx == indexName {
				return dsName, true
			}
		}
	}
	return "", false
}

func removeDeletedBackingIndexFromDataStreamsLockedR63(s *Server, indexName string) map[string]map[string]any {
	if s == nil || indexName == "" {
		return nil
	}
	var updated map[string]map[string]any
	for dsName, ds := range s.dataStreams {
		if ds == nil {
			continue
		}
		changed := false
		if rawIndices, ok := ds["indices"].([]any); ok && len(rawIndices) > 0 {
			kept := make([]any, 0, len(rawIndices))
			for _, item := range rawIndices {
				if m, okM := item.(map[string]any); okM && m["index_name"] == indexName {
					changed = true
					continue
				}
				kept = append(kept, item)
			}
			if changed {
				ds["indices"] = kept
			}
		}
		if fsObj, okFS := ds["failure_store"].(map[string]any); okFS {
			if fsIndices, okFI := fsObj["indices"].([]any); okFI && len(fsIndices) > 0 {
				keptFS := make([]any, 0, len(fsIndices))
				removedFS := false
				for _, item := range fsIndices {
					if m, okM := item.(map[string]any); okM && m["index_name"] == indexName {
						removedFS = true
						continue
					}
					keptFS = append(keptFS, item)
				}
				if removedFS {
					fsObj["indices"] = keptFS
					changed = true
				}
			}
		}
		if changed {
			curGen, _ := toInt64(ds["generation"])
			ds["generation"] = int(curGen) + 1
			if updated == nil {
				updated = make(map[string]map[string]any)
			}
			updated[dsName] = deepCloneDocMap(ds)
		}
	}
	return updated
}

func incrementDataStreamGenLockedR63(ds map[string]any) {
	if ds == nil {
		return
	}
	curGen, _ := toInt64(ds["generation"])
	if curGen < 1 {
		curGen = 1
	}
	ds["generation"] = int(curGen) + 1
}

func isBackingIndexAllowedWithoutHiddenR63(s *Server, rawIndex, target string) bool {
	if s == nil || target == "" {
		return false
	}
	if s.findOwningDataStreamLockedR62Search(target) != "" {
		return true
	}
	for _, part := range strings.Split(rawIndex, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, ".") && matchWildcardPattern(part, target) {
			if strings.HasPrefix(target, ".ds-") || strings.HasPrefix(target, ".fs-") {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleResizeOrCloneIndexR63(w http.ResponseWriter, r *http.Request, sourceIndex, action string) {
	if action == "_shrink" || action == "_split" {
		_ = s.syncCatalogFromBackend(r.Context())
		resolvedSrc := resolveESIndexDateMathR62Search(strings.TrimSpace(sourceIndex))
		s.mu.RLock()
		_, isDS := s.dataStreams[resolvedSrc]
		ownerDS, isWriteIdx := isDataStreamActiveWriteIndexLockedR63(s, resolvedSrc)
		s.mu.RUnlock()
		opWord := strings.TrimPrefix(action, "_")
		if isDS {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("data stream [%s] cannot be %s", resolvedSrc, opWord))
			return
		}
		if isWriteIdx {
			writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
				fmt.Sprintf("index [%s] is the write index for data stream [%s] and cannot be %s", resolvedSrc, ownerDS, opWord))
			return
		}
	}
	s.handleResizeOrCloneIndex(w, r)
}

func (s *Server) handleIndexOpenR63(w http.ResponseWriter, r *http.Request) {
	rawIndex := resolveCommaDateMathTokensR62Search(strings.TrimSpace(r.PathValue("index")))
	_ = s.syncCatalogFromBackend(r.Context())

	var extraBackingToOpen []string
	s.mu.RLock()
	for _, tok := range strings.Split(rawIndex, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if ds := s.dataStreams[tok]; ds != nil {
			extraBackingToOpen = append(extraBackingToOpen, extractDataStreamBackingIndexNames(ds)...)
			continue
		}
		if ownerDS, isWrite := isDataStreamActiveWriteIndexLockedR63(s, tok); isWrite {
			if ds := s.dataStreams[ownerDS]; ds != nil {
				extraBackingToOpen = append(extraBackingToOpen, extractDataStreamBackingIndexNames(ds)...)
			}
		}
	}
	s.mu.RUnlock()

	s.handleIndexOpen(w, r)

	if len(extraBackingToOpen) > 0 {
		var schemasToPersist []struct {
			name string
			sc   *schema.IndexSchema
		}
		s.mu.Lock()
		for _, bi := range extraBackingToOpen {
			if s.closedIndices[bi] {
				delete(s.closedIndices, bi)
				if sc := s.indices[bi]; sc != nil {
					schemasToPersist = append(schemasToPersist, struct {
						name string
						sc   *schema.IndexSchema
					}{name: bi, sc: sc})
				}
			}
		}
		s.mu.Unlock()
		for _, item := range schemasToPersist {
			s.persistIndex(r.Context(), item.name, item.sc)
		}
	}
}

func (s *Server) handleDataStreamLifecycleR63(w http.ResponseWriter, r *http.Request, rawStream string) {
	pat := strings.TrimSpace(rawStream)
	if !strings.ContainsAny(pat, "*?,") && pat != "_all" {
		s.handleDataStreamLifecycle(w, r, rawStream)
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	includeHidden := isTruthyBoolQueryParam(r, "expand_wildcards") ||
		strings.Contains(strings.ToLower(r.URL.Query().Get("expand_wildcards")), "all") ||
		strings.Contains(strings.ToLower(r.URL.Query().Get("expand_wildcards")), "hidden") ||
		strings.HasPrefix(pat, ".")

	s.mu.RLock()
	var matched []string
	var missingConcrete string
	for _, tok := range strings.Split(pat, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" || strings.HasPrefix(tok, "-") || strings.ContainsAny(tok, "*?") || tok == "_all" {
			continue
		}
		if s.dataStreams[tok] == nil && missingConcrete == "" {
			missingConcrete = tok
		}
	}
	for dsName, ds := range s.dataStreams {
		if ds == nil {
			continue
		}
		isHidden, _ := ds["hidden"].(bool)
		if strings.HasPrefix(dsName, ".") {
			isHidden = true
		}
		if isHidden && !includeHidden && pat != dsName {
			continue
		}
		if pat == "_all" || pat == "*" || matchMultiWildcardWithExclusions(pat, dsName) {
			matched = append(matched, dsName)
		}
	}
	s.mu.RUnlock()
	sort.Strings(matched)

	if missingConcrete != "" && !isTruthyBoolQueryParam(r, "ignore_unavailable") {
		writeESError(w, http.StatusNotFound, "resource_not_found_exception", fmt.Sprintf("data_stream [%s] missing", missingConcrete))
		return
	}

	var bodyBytes []byte
	if r.Body != nil && (r.Method == http.MethodPut || r.Method == http.MethodPost) {
		var ok bool
		bodyBytes, ok = readRequestBody(w, r)
		if !ok {
			return
		}
	}

	switch r.Method {
	case http.MethodPut, http.MethodPost, http.MethodDelete:
		for _, dsName := range matched {
			rSub := r.Clone(r.Context())
			if len(bodyBytes) > 0 {
				rSub.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				rSub.ContentLength = int64(len(bodyBytes))
			}
			rec := httptest.NewRecorder()
			s.handleDataStreamLifecycle(rec, rSub, dsName)
			if rec.Code >= 400 {
				copyRecorderHeadersSetR63(w, rec.Header())
				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes())
				return
			}
		}
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{"acknowledged": true})
	case http.MethodGet:
		mergedStreams := make(map[string]any)
		var globalCfg any
		hasGlobal := false
		for _, dsName := range matched {
			rSub := r.Clone(r.Context())
			rec := httptest.NewRecorder()
			s.handleDataStreamLifecycle(rec, rSub, dsName)
			if rec.Code == http.StatusOK {
				var subMap map[string]any
				if json.Unmarshal(rec.Body.Bytes(), &subMap) == nil && subMap != nil {
					if dsMap, okM := subMap["data_streams"].(map[string]any); okM {
						for k, v := range dsMap {
							mergedStreams[k] = v
						}
					}
					if gv, okG := subMap["global"]; okG {
						globalCfg = gv
						hasGlobal = true
					}
				}
			}
		}
		out := map[string]any{"data_streams": mergedStreams}
		if hasGlobal {
			out["global"] = globalCfg
		}
		writeJSONWithRequest(w, r, http.StatusOK, out)
	default:
		s.handleDataStreamLifecycle(w, r, rawStream)
	}
}

func (s *Server) handleExplainDataLifecycleR63(w http.ResponseWriter, r *http.Request, rawIndex string) {
	rec := httptest.NewRecorder()
	s.handleExplainDataLifecycle(rec, r, rawIndex)
	copyRecorderHeadersSetR63(w, rec.Header())
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		return
	}
	var payload map[string]any
	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil || payload == nil {
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		return
	}
	indicesObj, _ := payload["indices"].(map[string]any)
	includeDefaults := isTruthyBoolQueryParam(r, "include_defaults")
	modified := false
	s.mu.RLock()
	for idxName, rawEntry := range indicesObj {
		ownerDS := s.findOwningDataStreamLockedR62Search(idxName)
		if ownerDS == "" {
			continue
		}
		_, isWriteIdx := isDataStreamActiveWriteIndexLockedR63(s, idxName)
		hasExplicitTplRollover := false
		if tplLC := s.extractMatchingTemplateLifecycleLocked(ownerDS); tplLC != nil && tplLC["rollover"] != nil {
			hasExplicitTplRollover = true
		}
		if !isWriteIdx || (!includeDefaults && !hasExplicitTplRollover) {
			if entryMap, okM := rawEntry.(map[string]any); okM {
				if lcMap, okL := entryMap["lifecycle"].(map[string]any); okL {
					if rv, hasRollover := lcMap["rollover"]; hasRollover {
						if !isWriteIdx {
							delete(lcMap, "rollover")
							modified = true
						} else if rm, okRM := rv.(map[string]any); okRM && len(rm) == 2 && rm["max_age"] == "7d" && rm["max_primary_shard_size"] == "50gb" {
							delete(lcMap, "rollover")
							modified = true
						}
					}
				}
			}
		}
	}
	s.mu.RUnlock()
	if modified {
		writeJSONWithRequest(w, r, http.StatusOK, payload)
		return
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func (s *Server) handleIndexTemplateR63(w http.ResponseWriter, r *http.Request) {
	rec := httptest.NewRecorder()
	s.handleIndexTemplate(rec, r)
	copyRecorderHeadersSetR63(w, rec.Header())
	body := rec.Body.Bytes()
	if rec.Code >= 400 && bytes.Contains(body, []byte("has unsupported parameters: [")) {
		body = bytes.ReplaceAll(body, []byte("has unsupported parameters: ["), []byte("has unsupported parameters:  ["))
	}
	w.WriteHeader(rec.Code)
	// #nosec G705 -- JSON error/template response proxied from internal handler with nosniff
	_, _ = w.Write(body)
}

func (s *Server) handleReindexR63(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.Method != http.MethodPost || r.Body == nil {
		s.handleReindex(w, r)
		return
	}
	bodyBytes, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.UseNumber()
	if err := dec.Decode(&root); err == nil && root != nil {
		if destMap, okD := root["dest"].(map[string]any); okD {
			rawDestIdx, _ := destMap["index"].(string)
			destIdx := resolveESIndexDateMathR62Search(strings.TrimSpace(rawDestIdx))
			opType, _ := destMap["op_type"].(string)
			opType = strings.ToLower(strings.TrimSpace(opType))
			if destIdx != "" {
				_ = s.syncCatalogFromBackend(r.Context())
				isCreate := opType == "create"
				if st, et, er := s.prepareAutoCreateTargetR62Search(r.Context(), r, destIdx, isCreate); st != 0 {
					writeESError(w, st, et, er)
					return
				}
				if s.isDataStream(destIdx) {
					if !isCreate {
						writeESError(w, http.StatusBadRequest, "illegal_argument_exception",
							"only write ops with an op_type of create are allowed in data streams")
						return
					}
					if writeBackingIdx, _, wErr := s.resolveWriteIndexWithFilter(destIdx); wErr == nil && writeBackingIdx != "" {
						destMap["index"] = writeBackingIdx
						if rewritten, mErr := json.Marshal(root); mErr == nil {
							bodyBytes = rewritten
						}
					}
				}
			}
		}
	}
	rSub := r.Clone(r.Context())
	rSub.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	rSub.ContentLength = int64(len(bodyBytes))
	s.handleReindex(w, rSub)
}

func docHasAnyTSDBRoutingPathFieldR63(routingPaths []string, docMap map[string]any) bool {
	if len(routingPaths) == 0 {
		return true
	}
	expanded := expandDottedDocForPreviewR62Search(docMap)
	var collectLeafPaths func(prefix string, val any, out *[]string)
	collectLeafPaths = func(prefix string, val any, out *[]string) {
		switch v := val.(type) {
		case map[string]any:
			for k, sub := range v {
				next := k
				if prefix != "" {
					next = prefix + "." + k
				}
				collectLeafPaths(next, sub, out)
			}
		case []any:
			for _, elem := range v {
				collectLeafPaths(prefix, elem, out)
			}
		default:
			if val != nil && prefix != "" {
				*out = append(*out, prefix)
			}
		}
	}
	var leaves []string
	collectLeafPaths("", expanded, &leaves)
	for _, leaf := range leaves {
		for _, rp := range routingPaths {
			if matchWildcardPattern(rp, leaf) {
				return true
			}
		}
	}
	return false
}

func formatTSDBTimestampISOForConflictR63(rawDoc json.RawMessage) string {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(rawDoc))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil || doc == nil {
		return ""
	}
	expanded := expandDottedDocForPreviewR62Search(doc)
	rawTS := expanded["@timestamp"]
	if arr, ok := rawTS.([]any); ok && len(arr) > 0 {
		rawTS = arr[0]
	}
	switch v := rawTS.(type) {
	case string:
		if ms, ok := schema.ParseESDateToEpochMillis(v, time.Now().UTC()); ok {
			return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
		}
		return v
	case json.Number:
		if ms, err := v.Int64(); err == nil {
			return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
		}
	case float64:
		return time.UnixMilli(int64(v)).UTC().Format("2006-01-02T15:04:05.000Z")
	case int64:
		return time.UnixMilli(v).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return ""
}

func (s *Server) formatTSDBVersionConflictReasonR63(idxSchema *schema.IndexSchema, indexName, docID string, rawDoc json.RawMessage, curVer int64) string {
	if curVer <= 0 {
		curVer = 1
	}
	if idxSchema == nil || idxSchema.IndexMode != "time_series" {
		return fmt.Sprintf("[%s]: version conflict, document already exists", docID)
	}
	var docMap map[string]any
	dec := json.NewDecoder(bytes.NewReader(rawDoc))
	dec.UseNumber()
	if err := dec.Decode(&docMap); err == nil && docMap != nil {
		var idxSettings map[string]any
		if s != nil {
			s.mu.RLock()
			if cust := s.indexCustomSettings[indexName]; len(cust) > 0 {
				idxSettings = deepCloneDocMap(cust)
			}
			s.mu.RUnlock()
		}
		if tsid, _, _, _, cErr := schema.ComputeTSDBIdentityWithRoutingHash(idxSchema, docMap, idxSettings); cErr == nil && tsid != "" {
			isoTS := formatTSDBTimestampISOForConflictR63(rawDoc)
			if isoTS != "" {
				return fmt.Sprintf("[%s][%s@%s]: version conflict, document already exists (current version [%d])", docID, tsid, isoTS, curVer)
			}
		}
	}
	return fmt.Sprintf("[%s]: version conflict, document already exists (current version [%d])", docID, curVer)
}

func validateTSDBReadDocParamsR63(idxSchema *schema.IndexSchema, indexName, _ string, reqRouting string) (int, string, string) {
	if idxSchema == nil || idxSchema.IndexMode != "time_series" {
		return 0, "", ""
	}
	if strings.TrimSpace(reqRouting) != "" {
		return http.StatusBadRequest, "illegal_argument_exception",
			fmt.Sprintf("specifying routing is not supported because the destination index [%s] is in time series mode", indexName)
	}
	return 0, "", ""
}

const (
	maxTSDBTombstonesPerServerR63 = 100000
	tsdbTombstoneTTLR63           = 24 * time.Hour
)

type tsdbTombstoneEntryR63 struct {
	version   int64
	updatedAt int64
}

var tsdbTombstoneMuR63 sync.RWMutex
var tsdbTombstonesBySrvR63 = make(map[*Server]map[string]map[string]tsdbTombstoneEntryR63)

func (s *Server) isTimeSeriesIndexR63(indexName string) bool {
	if s == nil || indexName == "" {
		return false
	}
	s.mu.RLock()
	sc := s.indices[indexName]
	s.mu.RUnlock()
	return sc != nil && sc.IndexMode == "time_series"
}

func (s *Server) recordTSDBTombstoneVersionR63(indexName, docID string, ver int64) {
	if s == nil || indexName == "" || docID == "" || ver <= 0 || !s.isTimeSeriesIndexR63(indexName) {
		return
	}
	nowUnix := time.Now().UnixNano()
	cutoff := nowUnix - tsdbTombstoneTTLR63.Nanoseconds()
	tsdbTombstoneMuR63.Lock()
	defer tsdbTombstoneMuR63.Unlock()
	if tsdbTombstonesBySrvR63[s] == nil {
		tsdbTombstonesBySrvR63[s] = make(map[string]map[string]tsdbTombstoneEntryR63)
	}
	srvMap := tsdbTombstonesBySrvR63[s]
	if srvMap[indexName] == nil {
		srvMap[indexName] = make(map[string]tsdbTombstoneEntryR63)
	}
	srvMap[indexName][docID] = tsdbTombstoneEntryR63{
		version:   ver,
		updatedAt: nowUnix,
	}
	totalEntries := 0
	for idxK, docsMap := range srvMap {
		for dk, ent := range docsMap {
			if ent.updatedAt < cutoff {
				delete(docsMap, dk)
			}
		}
		if len(docsMap) == 0 {
			delete(srvMap, idxK)
		} else {
			totalEntries += len(docsMap)
		}
	}
	if totalEntries > maxTSDBTombstonesPerServerR63 {
		type keyRef struct {
			idx       string
			docID     string
			updatedAt int64
		}
		allRefs := make([]keyRef, 0, totalEntries)
		for idxK, docsMap := range srvMap {
			for dk, ent := range docsMap {
				allRefs = append(allRefs, keyRef{idx: idxK, docID: dk, updatedAt: ent.updatedAt})
			}
		}
		sort.Slice(allRefs, func(i, j int) bool {
			return allRefs[i].updatedAt < allRefs[j].updatedAt
		})
		toEvict := totalEntries - maxTSDBTombstonesPerServerR63
		for i := 0; i < toEvict && i < len(allRefs); i++ {
			ref := allRefs[i]
			if docsMap := srvMap[ref.idx]; docsMap != nil {
				delete(docsMap, ref.docID)
				if len(docsMap) == 0 {
					delete(srvMap, ref.idx)
				}
			}
		}
	}
}

func (s *Server) clearTSDBTombstoneVersionR63(indexName, docID string) {
	if s == nil || indexName == "" || docID == "" {
		return
	}
	tsdbTombstoneMuR63.Lock()
	defer tsdbTombstoneMuR63.Unlock()
	if m := tsdbTombstonesBySrvR63[s]; m != nil && m[indexName] != nil {
		delete(m[indexName], docID)
		if len(m[indexName]) == 0 {
			delete(m, indexName)
		}
	}
}

func (s *Server) clearTSDBIndexTombstonesR63(indexName string) {
	if s == nil || indexName == "" {
		return
	}
	s.clearWave3PolishIndexStateR63(indexName)
	tsdbTombstoneMuR63.Lock()
	defer tsdbTombstoneMuR63.Unlock()
	if indexName == "*" {
		delete(tsdbTombstonesBySrvR63, s)
		return
	}
	if m := tsdbTombstonesBySrvR63[s]; m != nil {
		delete(m, indexName)
	}
}

func (s *Server) getDocTombstoneVersionR63(indexName, docID string) int64 {
	if s == nil || indexName == "" || docID == "" {
		return 0
	}
	tsdbTombstoneMuR63.RLock()
	if m := tsdbTombstonesBySrvR63[s]; m != nil && m[indexName] != nil {
		if ent, ok := m[indexName][docID]; ok && ent.version > 0 {
			if time.Now().UnixNano()-ent.updatedAt <= tsdbTombstoneTTLR63.Nanoseconds() {
				tsdbTombstoneMuR63.RUnlock()
				return ent.version
			}
		}
	}
	tsdbTombstoneMuR63.RUnlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.docVersions != nil && s.docVersions[indexName] != nil {
		return s.docVersions[indexName][docID]
	}
	return 0
}

func formatJavaStyleValuePreviewR63(v any) string {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%s", k, formatJavaStyleValuePreviewR63(val[k])))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, 0, len(val))
		for _, elem := range val {
			parts = append(parts, formatJavaStyleValuePreviewR63(elem))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%v", val)
	}
}

func enrichMapperFieldErrorWithDocIDAndPreviewR63(rawReason, docID string, rawDoc []byte) string {
	if rawReason == "" || strings.Contains(rawReason, "in document with id ") {
		return rawReason
	}
	const pfx = "failed to parse field ["
	idx := strings.Index(rawReason, pfx)
	if idx < 0 {
		return rawReason
	}
	rest := rawReason[idx+len(pfx):]
	endBracket := strings.IndexByte(rest, ']')
	if endBracket <= 0 {
		return rawReason
	}
	fieldPath := rest[:endBracket]
	afterField := rest[endBracket+1:]
	if !strings.HasPrefix(afterField, " of type [") {
		return rawReason
	}
	endType := strings.IndexByte(afterField[len(" of type ["):], ']')
	if endType <= 0 {
		return rawReason
	}
	baseEnd := idx + len(pfx) + endBracket + 1 + len(" of type [") + endType + 1
	baseClause := rawReason[:baseEnd]
	tailClause := rawReason[baseEnd:]

	var preview string
	if len(bytes.TrimSpace(rawDoc)) > 0 {
		var docMap map[string]any
		dec := json.NewDecoder(bytes.NewReader(rawDoc))
		dec.UseNumber()
		if dec.Decode(&docMap) == nil && docMap != nil {
			expanded := expandDottedDocForPreviewR62Search(docMap)
			cur := any(expanded)
			for _, seg := range strings.Split(fieldPath, ".") {
				if m, okM := cur.(map[string]any); okM {
					cur = m[seg]
				} else {
					cur = nil
					break
				}
			}
			if cur != nil {
				preview = formatJavaStyleValuePreviewR63(cur)
			}
		}
	}
	out := baseClause
	if docID != "" {
		out += fmt.Sprintf(" in document with id '%s'", docID)
	}
	if preview != "" {
		out += fmt.Sprintf(". Preview of field's value: '%s'", preview)
	}
	out += tailClause
	return out
}

func isTSDBPositionGeoPointFieldR63(idxSchema *schema.IndexSchema, fieldPath string) bool {
	if idxSchema == nil || idxSchema.RawMapping == nil || strings.TrimSpace(fieldPath) == "" {
		return false
	}
	parts := strings.Split(strings.TrimSpace(fieldPath), ".")
	cur := idxSchema.RawMapping.Properties
	for i, p := range parts {
		prop, ok := cur[p]
		if !ok {
			return false
		}
		if i == len(parts)-1 {
			return strings.EqualFold(prop.Type, "geo_point") && strings.EqualFold(prop.TimeSeriesMetric, "position")
		}
		cur = prop.Properties
	}
	return false
}

func validateTSDBPositionMetricAggsR63(idxSchema *schema.IndexSchema, aggs map[string]esast.AggSpec) error {
	if idxSchema == nil || len(aggs) == 0 {
		return nil
	}
	for _, spec := range aggs {
		if spec.Avg != nil && strings.TrimSpace(spec.Avg.Field) != "" {
			f := strings.TrimSpace(spec.Avg.Field)
			if isTSDBPositionGeoPointFieldR63(idxSchema, f) {
				return fmt.Errorf("illegal_argument_exception: Field [%s] of type [geo_point][position] is not supported for aggregation [avg]", f)
			}
		}
		if sub := spec.SubAggs(); len(sub) > 0 {
			if err := validateTSDBPositionMetricAggsR63(idxSchema, sub); err != nil {
				return err
			}
		}
	}
	return nil
}

func extractTSDBRoutingHashValueR63(h HitRow, hitIdx string, idxSchema *schema.IndexSchema) (string, bool) {
	if idxSchema == nil || !strings.EqualFold(idxSchema.IndexMode, "time_series") {
		return "", false
	}
	parseHashStr := func(s string) (string, bool) {
		s = strings.TrimSpace(s)
		if s == "" {
			return "", false
		}
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			var buf [4]byte
			// #nosec G115 -- intentional 32-bit Murmur3/routing hash two's-complement bit pattern
			binary.BigEndian.PutUint32(buf[:], uint32(int32(iv)))
			return base64.RawURLEncoding.EncodeToString(buf[:]), true
		}
		if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) >= 4 {
			return base64.RawURLEncoding.EncodeToString(b[:4]), true
		}
		return "", false
	}
	if iv, ok := parseHashStr(h.Routing); ok {
		return iv, true
	}
	docMap := decodeHitDocMapRound60(h)
	var idxSettings map[string]any
	if h.SearchScope != nil && h.SearchScope.srv != nil && hitIdx != "" {
		h.SearchScope.srv.mu.RLock()
		if cust := h.SearchScope.srv.indexCustomSettings[hitIdx]; len(cust) > 0 {
			idxSettings = deepCloneDocMap(cust)
		}
		h.SearchScope.srv.mu.RUnlock()
	}
	if _, detID, _, rHashStr, err := schema.ComputeTSDBIdentityWithRoutingHash(idxSchema, docMap, idxSettings); err == nil {
		if iv, ok := parseHashStr(rHashStr); ok {
			return iv, true
		}
		if iv, ok := parseHashStr(detID); ok {
			return iv, true
		}
	}
	if iv, ok := parseHashStr(h.ID); ok {
		return iv, true
	}
	return "", false
}

func (s *Server) backfillIndexSchemaPreserveVersionR63(ctx context.Context, indexName string, newSchema *schema.IndexSchema) {
	if s == nil || newSchema == nil {
		return
	}
	_ = s.coalescer.FlushTable(ctx, newSchema.DorisTable)
	maxBackfill := 100000
	tr := transpiler.NewTranspiler(newSchema, transpiler.TranspilerOptions{MaxResultWindow: maxBackfill})
	plan, err := tr.BuildSearchPlan(&esast.SearchRequest{
		Size:           &maxBackfill,
		TrackTotalHits: false,
	})
	if err != nil {
		s.backfillIndexSchema(ctx, newSchema)
		return
	}
	hits, err := s.backend.QueryHits(ctx, plan.HitsSQL)
	if err != nil || len(hits) == 0 {
		return
	}
	ids := make([]string, 0, len(hits))
	var buf bytes.Buffer
	for _, h := range hits {
		src := h.EffectiveSource()
		if len(src) == 0 {
			continue
		}
		ver := h.Version
		if ver <= 0 {
			ver = 1
		}
		shredded, sErr := schema.ShredDocument(newSchema, h.ID, ver, false, src)
		if sErr != nil {
			continue
		}
		shredded = s.postProcessShreddedRowWave3R63(indexName, newSchema, src, s.getDocRouting(indexName, h.ID), shredded)
		ids = append(ids, h.ID)
		buf.Write(shredded)
		buf.WriteByte('\n')
	}
	if len(ids) == 0 || buf.Len() == 0 {
		return
	}
	if _, pErr := s.physicalDeleteDocs(ctx, newSchema, ids); pErr != nil {
		s.backfillIndexSchema(ctx, newSchema)
		return
	}
	_ = s.backend.StreamLoad(ctx, newSchema.DorisTable, buf.Bytes(), true)
}

func (s *Server) handleIndexCloseR63(w http.ResponseWriter, r *http.Request) {
	rawIndex := resolveCommaDateMathTokensR62Search(strings.TrimSpace(r.PathValue("index")))
	if rawIndex == "" || (!strings.ContainsAny(rawIndex, "*?") && rawIndex != "_all") {
		s.handleIndexClose(w, r)
		return
	}
	_ = s.syncCatalogFromBackend(r.Context())
	ewOpen, ewClosed, ewHidden, ewNone, ewErr := parseExpandWildcardsFlags(r.URL.Query().Get("expand_wildcards"))
	if ewErr != nil {
		s.handleIndexClose(w, r)
		return
	}
	if !r.URL.Query().Has("expand_wildcards") {
		ewOpen = true
		ewClosed = false
		ewHidden = false
	}
	s.mu.RLock()
	for _, tok := range strings.Split(rawIndex, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" || strings.HasPrefix(tok, "-") || strings.ContainsAny(tok, "*?") || tok == "_all" {
			continue
		}
		if s.dataStreams[tok] != nil {
			s.mu.RUnlock()
			s.handleIndexClose(w, r)
			return
		}
	}
	var nonDSTargets []string
	if !ewNone {
		for idxName := range s.indices {
			if !matchMultiWildcardWithExclusions(rawIndex, idxName) && rawIndex != "_all" {
				// Also check alias wildcard match for regular aliases
				matchedViaAlias := false
				for alName, alTargets := range s.aliases {
					if rawIndex == "_all" || matchMultiWildcardWithExclusions(rawIndex, alName) {
						for _, at := range alTargets {
							if at == idxName {
								matchedViaAlias = true
								break
							}
						}
					}
					if matchedViaAlias {
						break
					}
				}
				if !matchedViaAlias {
					continue
				}
			}
			// `_close` does NOT expand data streams (`20_unsupported_apis.yml`):
			// hidden/backing `.ds-*` or `.fs-*` indices are excluded unless matched by an explicit dot-prefixed pattern or `expand_wildcards=hidden/all`.
			if s.findOwningDataStreamLockedR62Search(idxName) != "" {
				explicitDotMatch := false
				for _, tok := range strings.Split(rawIndex, ",") {
					tok = strings.TrimSpace(tok)
					if strings.HasPrefix(tok, ".") && matchWildcardPattern(tok, idxName) {
						explicitDotMatch = true
						break
					}
				}
				if !explicitDotMatch && !ewHidden {
					continue
				}
			}
			isClosed := s.closedIndices[idxName]
			if (isClosed && !ewClosed) || (!isClosed && !ewOpen) {
				continue
			}
			if s.isIndexExplicitlyHiddenLocked(idxName) && !ewHidden {
				explicitDotMatch := false
				for _, tok := range strings.Split(rawIndex, ",") {
					tok = strings.TrimSpace(tok)
					if strings.HasPrefix(tok, ".") && matchWildcardPattern(tok, idxName) {
						explicitDotMatch = true
						break
					}
				}
				if !explicitDotMatch {
					continue
				}
			}
			nonDSTargets = append(nonDSTargets, idxName)
		}
	}
	s.mu.RUnlock()
	sort.Strings(nonDSTargets)
	if len(nonDSTargets) == 0 {
		allowNoIndices := true
		if r.URL.Query().Has("allow_no_indices") {
			allowNoIndices = isTruthyBoolQueryParam(r, "allow_no_indices")
		}
		if !allowNoIndices {
			writeESError(w, http.StatusNotFound, "index_not_found_exception", fmt.Sprintf("no such index [%s]", rawIndex))
			return
		}
		writeJSONWithRequest(w, r, http.StatusOK, map[string]any{
			"acknowledged":        true,
			"shards_acknowledged": true,
			"indices":             map[string]any{},
		})
		return
	}
	rSub := r.Clone(r.Context())
	rSub.SetPathValue("index", strings.Join(nonDSTargets, ","))
	s.handleIndexClose(w, rSub)
}

func buildTSDBImmutabilityUBQFailureCauseR63(s *Server, idxSchema *schema.IndexSchema, indexName, oldDocID string, mutatedDoc json.RawMessage) map[string]any {
	newDetID := "unset"
	if idxSchema != nil {
		var docMap map[string]any
		dec := json.NewDecoder(bytes.NewReader(mutatedDoc))
		dec.UseNumber()
		if dec.Decode(&docMap) == nil && docMap != nil {
			var idxSettings map[string]any
			if s != nil {
				s.mu.RLock()
				if cust := s.indexCustomSettings[indexName]; len(cust) > 0 {
					idxSettings = deepCloneDocMap(cust)
				}
				s.mu.RUnlock()
			}
			if _, detID, _, _, err := schema.ComputeTSDBIdentityWithRoutingHash(idxSchema, docMap, idxSettings); err == nil && detID != "" {
				newDetID = detID
			}
		}
	}
	reason := fmt.Sprintf("_id must be unset or set to [%s] but was [%s] because [%s] is in time_series mode", newDetID, oldDocID, indexName)
	return map[string]any{
		"type":   "mapper_parsing_exception",
		"reason": "failed to parse",
		"caused_by": map[string]any{
			"type":   "illegal_argument_exception",
			"reason": reason,
		},
	}
}

func refreshDataStreamLifecycleManagedByLockedR63(s *Server, cp map[string]any) {
	if s == nil || cp == nil {
		return
	}
	streamName, _ := cp["name"].(string)
	_, _, _, _, _, _, tplCustomSettings, _ := s.matchingTemplateFullConfigLocked(streamName)
	tplLC := s.extractMatchingTemplateLifecycleLocked(streamName)
	_, _, hasWinTpl := s.findWinningDataStreamTemplateLockedR62Search(streamName)
	dslEnabled := hasWinTpl
	if lcMap, okLC := cp["lifecycle"].(map[string]any); okLC && lcMap != nil {
		dslEnabled = true
		if enRaw, hasEn := lcMap["enabled"]; hasEn {
			if enBool, okB := parseOptionalBoolAny(enRaw); okB {
				dslEnabled = enBool
			}
		}
	} else if len(tplLC) > 0 {
		dslEnabled = true
		if enRaw, hasEn := tplLC["enabled"]; hasEn {
			if enBool, okB := parseOptionalBoolAny(enRaw); okB {
				dslEnabled = enBool
			}
		}
	}
	var writeIdxName string
	var writePreferILM bool
	var hasWritePreferILM bool
	var writeIlmPol string
	if rawIndices, okI := cp["indices"].([]any); okI && len(rawIndices) > 0 {
		for idxPos, item := range rawIndices {
			m, okM := item.(map[string]any)
			if !okM {
				continue
			}
			bName, _ := m["index_name"].(string)
			if bName == "" {
				continue
			}
			pol, pref, hasPref := extractILMPolicyFromSettingsR62Search(s.indexCustomSettings[bName])
			if !hasPref {
				if existingPref, okP := m["prefer_ilm"].(bool); okP {
					pref = existingPref
				} else {
					pref = true
				}
			}
			if pol == "" {
				if existingPol, okS := m["ilm_policy"].(string); okS && s.indexCustomSettings[bName] == nil {
					pol = existingPol
				}
			}
			m["prefer_ilm"] = pref
			if pol != "" {
				m["ilm_policy"] = pol
			} else {
				delete(m, "ilm_policy")
			}
			if pol != "" && (pref || !dslEnabled) {
				m["managed_by"] = "Index Lifecycle Management"
			} else if dslEnabled && (cp["lifecycle"] != nil || len(tplLC) > 0) {
				m["managed_by"] = "Data stream lifecycle"
			} else if m["managed_by"] == nil {
				m["managed_by"] = "Unmanaged"
			}
			if idxPos == len(rawIndices)-1 {
				writeIdxName = bName
				writePreferILM = pref
				hasWritePreferILM = hasPref
				writeIlmPol = pol
			}
		}
	}
	if streamName == "" {
		return
	}
	if cp["lifecycle"] == nil && len(tplLC) > 0 {
		if normLC, err := normalizeAndValidateDataStreamLifecycle(tplLC); err == nil && normLC != nil {
			en := true
			if enRaw, hasEn := normLC["enabled"]; hasEn {
				if enB, okB := parseOptionalBoolAny(enRaw); okB {
					en = enB
				}
			}
			if en && normLC["rollover"] == nil {
				lcCopy := deepCloneDocMap(normLC)
				lcCopy["rollover"] = map[string]any{"max_age": "7d", "max_primary_shard_size": "50gb"}
				normLC = lcCopy
			}
			cp["lifecycle"] = normLC
			dslEnabled = en
		}
	}
	nextDslEnabled := dslEnabled && (cp["lifecycle"] != nil || len(tplLC) > 0 || hasWinTpl)
	if lcMap, okLC := cp["lifecycle"].(map[string]any); okLC && lcMap != nil {
		if enRaw, hasEn := lcMap["enabled"]; hasEn {
			if enB, okB := parseOptionalBoolAny(enRaw); okB && !enB {
				nextDslEnabled = false
			}
		}
	}
	nextPol, nextPref, hasTplPref := extractILMPolicyFromSettingsR62Search(tplCustomSettings)
	if !hasWinTpl {
		if existingPol, okS := cp["ilm_policy"].(string); okS {
			nextPol = existingPol
		} else {
			nextPol = writeIlmPol
		}
	}
	if !hasTplPref {
		if hasWritePreferILM {
			nextPref = writePreferILM
		} else if existingPref, okP := cp["prefer_ilm"].(bool); okP {
			nextPref = existingPref
		} else {
			nextPref = true
		}
	}
	cp["prefer_ilm"] = nextPref
	if nextPol != "" {
		cp["ilm_policy"] = nextPol
	} else {
		delete(cp, "ilm_policy")
	}
	if nextPol != "" && (nextPref || !nextDslEnabled) {
		cp["next_generation_managed_by"] = "Index Lifecycle Management"
	} else if nextDslEnabled && (cp["lifecycle"] != nil || len(tplLC) > 0 || (nextPol != "" && !nextPref)) {
		cp["next_generation_managed_by"] = "Data stream lifecycle"
	} else if writeIdxName != "" {
		cp["next_generation_managed_by"] = "Unmanaged"
	}
}

func isFailureStoreBackingIndexLockedR63(s *Server, dsName, backingIndex string) bool {
	if s == nil || dsName == "" || backingIndex == "" {
		return false
	}
	ds := s.dataStreams[dsName]
	if ds == nil {
		return false
	}
	if fsObj, okFS := ds["failure_store"].(map[string]any); okFS {
		if fsIndices, okFI := fsObj["indices"].([]any); okFI {
			for _, item := range fsIndices {
				if m, okM := item.(map[string]any); okM && m["index_name"] == backingIndex {
					return true
				}
			}
		}
	}
	return false
}

// ============================================================================
// Round 63 Groups 3 & 4: Search Fetch/Sort/Limits/Highlight/KNN & Pipeline/Metric/Bucket Agg Helpers
// ============================================================================

func (s *Server) validateTermsLookupsExistR63(req *esast.SearchRequest) (int, string, string) {
	if s == nil || req == nil || !s.hasAuthoritativeIndexCatalog() {
		return 0, "", ""
	}
	var missingIdx string
	var walkQuery func(q *esast.Query)
	var walkInnerHits func(ih *esast.InnerHitsSpec)
	var walkAgg func(spec esast.AggSpec)

	checkLookupIndex := func(idx string) {
		if missingIdx != "" {
			return
		}
		idx = strings.TrimSpace(idx)
		if idx == "" {
			return
		}
		if m := s.findMissingConcreteSearchIndexRound60(context.Background(), nil, idx, nil); m != "" {
			missingIdx = m
			return
		}
		if _, _, err := s.resolveReadDocIndexWithFilter(idx); err != nil {
			missingIdx = idx
		}
	}

	walkInnerHits = func(ih *esast.InnerHitsSpec) {
		if ih == nil || missingIdx != "" {
			return
		}
		for i := range ih.Sort {
			if ih.Sort[i].Entry.Nested != nil {
				walkQuery(ih.Sort[i].Entry.Nested.Filter)
			}
		}
		if ih.Highlight != nil {
			walkQuery(ih.Highlight.HighlightQuery)
			for fname := range ih.Highlight.Fields {
				fSpec := ih.Highlight.FieldSpec(fname)
				walkQuery(fSpec.HighlightQuery)
			}
		}
	}

	walkQuery = func(q *esast.Query) {
		if q == nil || missingIdx != "" {
			return
		}
		if q.Terms != nil {
			for _, lk := range q.Terms.Lookups {
				checkLookupIndex(lk.Index)
			}
		}
		if q.Bool != nil {
			for i := range q.Bool.Must {
				walkQuery(&q.Bool.Must[i])
			}
			for i := range q.Bool.Should {
				walkQuery(&q.Bool.Should[i])
			}
			for i := range q.Bool.Filter {
				walkQuery(&q.Bool.Filter[i])
			}
			for i := range q.Bool.MustNot {
				walkQuery(&q.Bool.MustNot[i])
			}
		}
		if q.ConstantScore != nil {
			walkQuery(&q.ConstantScore.Filter)
		}
		if q.DisMax != nil {
			for i := range q.DisMax.Queries {
				walkQuery(&q.DisMax.Queries[i])
			}
		}
		if q.Boosting != nil {
			walkQuery(&q.Boosting.Positive)
			walkQuery(&q.Boosting.Negative)
		}
		if q.Nested != nil {
			walkQuery(&q.Nested.Query)
			walkInnerHits(q.Nested.InnerHits)
		}
		if q.FunctionScore != nil {
			walkQuery(q.FunctionScore.Query)
			for i := range q.FunctionScore.Functions {
				walkQuery(q.FunctionScore.Functions[i].Filter)
			}
		}
		if q.ScriptScore != nil {
			walkQuery(q.ScriptScore.Query)
		}
		if q.KNN != nil {
			for i := range q.KNN.Filter {
				walkQuery(&q.KNN.Filter[i])
			}
		}
		if q.Wrapper != nil && q.Wrapper.Decoded != nil {
			walkQuery(q.Wrapper.Decoded)
		}
		if q.Pinned != nil && q.Pinned.Organic != nil {
			walkQuery(q.Pinned.Organic)
		}
		if q.HasChild != nil {
			walkQuery(&q.HasChild.Query)
		}
		if q.HasParent != nil {
			walkQuery(&q.HasParent.Query)
		}
	}

	walkAgg = func(spec esast.AggSpec) {
		if missingIdx != "" {
			return
		}
		if spec.Filter != nil {
			walkQuery(spec.Filter)
		}
		if tSpec := spec.EffectiveTerms(); tSpec != nil && tSpec.BackgroundFilter != nil {
			walkQuery(tSpec.BackgroundFilter)
		}
		if spec.Filters != nil {
			for _, q := range spec.Filters.Filters {
				qc := q
				walkQuery(&qc)
			}
			for i := range spec.Filters.AnonymousFilters {
				walkQuery(&spec.Filters.AnonymousFilters[i])
			}
		}
		if spec.AdjacencyMatrix != nil {
			for _, q := range spec.AdjacencyMatrix.Filters {
				qc := q
				walkQuery(&qc)
			}
		}
		for _, sub := range spec.SubAggs() {
			walkAgg(sub)
		}
	}

	walkQuery(req.Query)
	walkQuery(req.PostFilter)
	walkQuery(req.AliasFilter)
	for i := range req.KNN {
		for j := range req.KNN[i].Filter {
			walkQuery(&req.KNN[i].Filter[j])
		}
	}
	for i := range req.Rescore {
		if req.Rescore[i].Query != nil {
			walkQuery(req.Rescore[i].Query.RescoreQuery)
		}
	}
	for _, spec := range req.EffectiveAggs() {
		walkAgg(spec)
	}
	if missingIdx != "" {
		return http.StatusNotFound, "index_not_found_exception", "no such index [" + missingIdx + "]"
	}
	return 0, "", ""
}

func sortFieldCategoryR63(esType string) (string, string) {
	t := strings.ToLower(strings.TrimSpace(esType))
	switch t {
	case "long", "integer", "short", "byte", "unsigned_long", "date", "date_nanos":
		return "numeric", t
	case "double", "float", "half_float", "scaled_float":
		return "numeric", t
	case "keyword", "constant_keyword", "wildcard", "version":
		return "keyword", "keyword"
	case "boolean":
		return "boolean", "boolean"
	case "ip":
		return "ip", "ip"
	}
	return "", ""
}

func validateCrossIndexSortTypesR63(sorts []esast.SortSpec, rawSchemas []*schema.IndexSchema) (int, string, string) {
	if len(sorts) == 0 || len(rawSchemas) < 2 {
		return 0, "", ""
	}
	for _, sSpec := range sorts {
		sf := strings.TrimSpace(sSpec.Entry.Field)
		if sf == "" || strings.HasPrefix(sf, "_") || strings.TrimSpace(sSpec.Entry.Type) != "" {
			continue
		}
		var firstCat, firstLabel string
		for _, sc := range rawSchemas {
			if sc == nil {
				continue
			}
			b, ok := sc.Fields[sf]
			if !ok {
				if fp, okRaw := lookupRawPropertyWithMultiFieldR61Search(sc, sf); okRaw {
					b.ESType = fp.Type
					ok = true
				}
			}
			if !ok || b.ESType == "" {
				continue
			}
			cat, lbl := sortFieldCategoryR63(b.ESType)
			if cat == "" {
				continue
			}
			if firstCat == "" {
				firstCat = cat
				firstLabel = lbl
			} else if cat != firstCat {
				return http.StatusBadRequest, "search_phase_execution_exception",
					fmt.Sprintf("all_shards_failed|illegal_argument_exception|Can't sort on field [%s]; the field has incompatible sort types: [%s] and [%s]", sf, firstLabel, lbl)
			}
		}
	}
	return 0, "", ""
}

func validateQueryMaxRegexAndPrefixLengthR63(
	req *esast.SearchRequest,
	customSettings map[string]map[string]any,
) (int, string, string) {
	if req == nil {
		return 0, "", ""
	}
	maxRegexLen := 1000
	for _, cs := range customSettings {
		if n, ok := extractIntSettingR62Search(cs, "index.max_regex_length", "max_regex_length"); ok && n >= 0 {
			maxRegexLen = n
		}
	}
	var errReason string
	var walk func(q *esast.Query)
	walk = func(q *esast.Query) {
		if q == nil || errReason != "" {
			return
		}
		for _, reSpec := range q.Regexp {
			uLen := len(utf16.Encode([]rune(reSpec.Value)))
			if uLen > maxRegexLen {
				errReason = fmt.Sprintf("all_shards_failed|illegal_argument_exception|The length of regex [%d] used in the Regexp Query request has exceeded the allowed maximum of [%d]. This maximum can be set by changing the [index.max_regex_length] index level setting.", uLen, maxRegexLen)
				return
			}
		}
		if q.QueryString != nil && strings.Contains(q.QueryString.Query, "/") {
			qs := q.QueryString.Query
			for idx := 0; idx < len(qs); idx++ {
				if qs[idx] == '\\' {
					idx++
					continue
				}
				if qs[idx] == '/' {
					end := idx + 1
					for end < len(qs) {
						if qs[end] == '\\' {
							end += 2
							continue
						}
						if qs[end] == '/' {
							break
						}
						end++
					}
					if end < len(qs) && qs[end] == '/' {
						reBody := qs[idx+1 : end]
						uLen := len(utf16.Encode([]rune(reBody)))
						if uLen > maxRegexLen {
							errReason = fmt.Sprintf("all_shards_failed|illegal_argument_exception|The length of regex [%d] used in the Regexp Query request has exceeded the allowed maximum of [%d]. This maximum can be set by changing the [index.max_regex_length] index level setting.", uLen, maxRegexLen)
							return
						}
						idx = end
					}
				}
			}
		}
		for _, pSpec := range q.Prefix {
			uLen := len(utf16.Encode([]rune(pSpec.Value)))
			if uLen > maxRegexLen {
				errReason = fmt.Sprintf("all_shards_failed|illegal_argument_exception|The length of prefix [%d] used in the Prefix Query request has exceeded the allowed maximum of [%d]. This maximum can be set by changing the [index.max_regex_length] index level setting.", uLen, maxRegexLen)
				return
			}
		}
		if q.Bool != nil {
			for i := range q.Bool.Must {
				walk(&q.Bool.Must[i])
			}
			for i := range q.Bool.Should {
				walk(&q.Bool.Should[i])
			}
			for i := range q.Bool.Filter {
				walk(&q.Bool.Filter[i])
			}
			for i := range q.Bool.MustNot {
				walk(&q.Bool.MustNot[i])
			}
		}
		if q.ConstantScore != nil {
			walk(&q.ConstantScore.Filter)
		}
		if q.DisMax != nil {
			for i := range q.DisMax.Queries {
				walk(&q.DisMax.Queries[i])
			}
		}
		if q.Boosting != nil {
			walk(&q.Boosting.Positive)
			walk(&q.Boosting.Negative)
		}
		if q.Nested != nil {
			walk(&q.Nested.Query)
		}
		if q.FunctionScore != nil {
			walk(q.FunctionScore.Query)
			for i := range q.FunctionScore.Functions {
				walk(q.FunctionScore.Functions[i].Filter)
			}
		}
		if q.ScriptScore != nil {
			walk(q.ScriptScore.Query)
		}
	}
	walk(req.Query)
	walk(req.PostFilter)
	if errReason != "" {
		return http.StatusBadRequest, "search_phase_execution_exception", errReason
	}
	return 0, "", ""
}

func convertSpatialWKTAndGeoJSONR63(rawVal any, wantWKT bool) any {
	parseCoordPair := func(part string) ([]float64, bool) {
		part = strings.TrimSpace(strings.ReplaceAll(part, ",", " "))
		fields := strings.Fields(part)
		if len(fields) < 2 {
			return nil, false
		}
		x, errX := strconv.ParseFloat(fields[0], 64)
		y, errY := strconv.ParseFloat(fields[1], 64)
		if errX != nil || errY != nil {
			return nil, false
		}
		return []float64{x, y}, true
	}
	if !wantWKT {
		if s, ok := rawVal.(string); ok {
			trimmed := strings.TrimSpace(s)
			openP := strings.IndexByte(trimmed, '(')
			closeP := strings.LastIndexByte(trimmed, ')')
			if openP > 0 && closeP > openP {
				kind := strings.ToUpper(strings.TrimSpace(trimmed[:openP]))
				inner := strings.TrimSpace(trimmed[openP+1 : closeP])
				switch kind {
				case "POINT":
					if pt, okP := parseCoordPair(inner); okP {
						return map[string]any{"type": "Point", "coordinates": pt}
					}
				case "LINESTRING":
					var coords [][]float64
					for _, seg := range strings.Split(inner, ",") {
						if pt, okP := parseCoordPair(seg); okP {
							coords = append(coords, pt)
						}
					}
					if len(coords) > 0 {
						return map[string]any{"type": "LineString", "coordinates": coords}
					}
				case "POLYGON":
					ringStr := strings.Trim(inner, "() ")
					var ring [][]float64
					for _, seg := range strings.Split(ringStr, ",") {
						if pt, okP := parseCoordPair(seg); okP {
							ring = append(ring, pt)
						}
					}
					if len(ring) > 0 {
						return map[string]any{"type": "Polygon", "coordinates": [][][]float64{ring}}
					}
				case "BBOX":
					parts := strings.Split(inner, ",")
					if len(parts) == 4 {
						minLon, e1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
						maxLon, e2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
						maxLat, e3 := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
						minLat, e4 := strconv.ParseFloat(strings.TrimSpace(parts[3]), 64)
						if e1 == nil && e2 == nil && e3 == nil && e4 == nil {
							return map[string]any{
								"type":        "envelope",
								"coordinates": [][]float64{{minLon, maxLat}, {maxLon, minLat}},
							}
						}
					}
				}
			}
		}
		return rawVal
	}
	if m, ok := rawVal.(map[string]any); ok {
		t, _ := m["type"].(string)
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "point":
			pts := extractGeoPointsFromRawNodeR61Search(m["coordinates"])
			if len(pts) == 1 {
				return fmt.Sprintf("POINT (%s %s)", formatShortestFloatR61Search(pts[0][0]), formatShortestFloatR61Search(pts[0][1]))
			}
		}
	}
	return rawVal
}

func extractIgnoredFieldValuesMapR63(h HitRow, idxSchema *schema.IndexSchema) map[string][]any {
	if idxSchema == nil || len(h.Source) == 0 {
		return nil
	}
	igFields := extractHitIgnoredFieldsR61Search(h, idxSchema)
	if len(igFields) == 0 {
		return nil
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(h.Source))
	dec.UseNumber()
	if dec.Decode(&doc) != nil || doc == nil {
		return nil
	}
	var out map[string][]any
	for _, fn := range igFields {
		b, ok := idxSchema.Fields[fn]
		if !ok || b.IgnoreMalformed == nil || !*b.IgnoreMalformed {
			continue
		}
		segs := effectiveSourceSegsR61Search(fn, b)
		rawVals := collectScalarValuesAtPath(doc, segs)
		var badVals []any
		for _, rv := range rawVals {
			if rv == nil {
				continue
			}
			// Keep only values that failed parsing (`isValueMalformedForBindingR61Search`)
			if isValueMalformedForFieldR63(rv, b) {
				if jn, okJ := rv.(json.Number); okJ {
					if iv, errI := jn.Int64(); errI == nil {
						badVals = append(badVals, iv)
					} else if fv, errF := jn.Float64(); errF == nil {
						badVals = append(badVals, fv)
					} else {
						badVals = append(badVals, jn.String())
					}
				} else {
					badVals = append(badVals, rv)
				}
			}
		}
		if len(badVals) > 0 {
			if out == nil {
				out = make(map[string][]any)
			}
			out[fn] = badVals
		}
	}
	return out
}

func isValueMalformedForFieldR63(v any, b schema.FieldBinding) bool {
	esType := strings.ToLower(strings.TrimSpace(b.ESType))
	coerce := b.EffectiveCoerceBool()
	switch esType {
	case "date":
		_, ok := parseEpochMillisExactR61Search(v, b.Format)
		return !ok
	case "date_nanos":
		_, ok := parseEpochNanosExactR61Search(v, b.Format)
		return !ok
	case "long", "integer", "short", "byte":
		iv, ok := parseExactInt64R61Search(v, coerce)
		if !ok {
			return true
		}
		switch esType {
		case "byte":
			return iv < math.MinInt8 || iv > math.MaxInt8
		case "short":
			return iv < math.MinInt16 || iv > math.MaxInt16
		case "integer":
			return iv < math.MinInt32 || iv > math.MaxInt32
		}
		return false
	case "unsigned_long":
		_, _, ok := parseExactUint64R61Search(v, coerce)
		return !ok
	case "double", "float", "half_float", "scaled_float":
		_, ok := parseFiniteFloatFromAnyR61Search(v, coerce)
		return !ok
	case "boolean":
		switch tv := v.(type) {
		case bool:
			return false
		case string:
			s := strings.ToLower(strings.TrimSpace(tv))
			return s != "true" && s != "false" && (!coerce || (s != "1" && s != "0"))
		default:
			return true
		}
	case "ip":
		s, ok := v.(string)
		if !ok {
			return true
		}
		_, okIP := ipAddrTo16BytesR62Search(s)
		return !okIP
	case "geo_point":
		_, _, err := esast.ParseGeoPoint(v)
		return err != nil
	}
	return false
}

func rawBodyDisablesIgnoredFieldValuesR63(rawBody []byte) bool {
	if len(rawBody) == 0 || !bytes.Contains(rawBody, []byte("ignored_field_values")) {
		return false
	}
	var top map[string]any
	if json.Unmarshal(rawBody, &top) != nil || top == nil {
		return false
	}
	if b, ok := top["ignored_field_values"].(bool); ok && !b {
		return true
	}
	return false
}

type vwhClusterR63 struct {
	minV  float64
	maxV  float64
	sumV  float64
	count int
	docs  []runtimeMatchedDoc
}

func clusterVariableWidthHistogramR63(
	docs []runtimeMatchedDoc,
	vwh *esast.VariableWidthHistogramAggSpec,
) []vwhClusterR63 {
	if vwh == nil {
		return nil
	}
	targetBuckets := vwh.EffectiveBuckets()
	if targetBuckets <= 0 {
		targetBuckets = 10
	}
	type pair struct {
		md  runtimeMatchedDoc
		val float64
	}
	var pairs []pair
	for _, md := range docs {
		for _, v := range extractDocNumericValuesForBucket(md, vwh.Field, vwh.Missing, vwh.Script) {
			pairs = append(pairs, pair{md: md, val: v})
		}
	}
	if len(pairs) == 0 {
		return nil
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		return pairs[i].val < pairs[j].val
	})
	var clusters []vwhClusterR63
	for _, p := range pairs {
		if len(clusters) > 0 && clusters[len(clusters)-1].maxV == p.val && clusters[len(clusters)-1].minV == p.val {
			last := &clusters[len(clusters)-1]
			last.sumV += p.val
			last.count++
			last.docs = append(last.docs, p.md)
			continue
		}
		clusters = append(clusters, vwhClusterR63{
			minV:  p.val,
			maxV:  p.val,
			sumV:  p.val,
			count: 1,
			docs:  []runtimeMatchedDoc{p.md},
		})
	}
	if len(clusters) > targetBuckets {
		nodes := make([]vwhNodeR64, len(clusters))
		for i := range clusters {
			nodes[i] = vwhNodeR64{
				cluster: clusters[i],
				prev:    i - 1,
				next:    i + 1,
				alive:   true,
				pos:     i,
			}
		}
		nodes[len(nodes)-1].next = -1

		pq := make(vwhMergeHeapR64, 0, len(nodes))
		pushPair := func(left, right int) {
			cA := nodes[left].cluster.sumV / float64(nodes[left].cluster.count)
			cB := nodes[right].cluster.sumV / float64(nodes[right].cluster.count)
			heap.Push(&pq, vwhMergeCandidateR64{
				left:     left,
				right:    right,
				leftVer:  nodes[left].version,
				rightVer: nodes[right].version,
				dist:     cB - cA,
				leftPos:  nodes[left].pos,
			})
		}
		for i := 0; i < len(nodes)-1; i++ {
			pushPair(i, i+1)
		}

		aliveCount := len(nodes)
		for aliveCount > targetBuckets && pq.Len() > 0 {
			item := heap.Pop(&pq).(vwhMergeCandidateR64)
			l, r := item.left, item.right
			if !nodes[l].alive || !nodes[r].alive || nodes[l].next != r ||
				nodes[l].version != item.leftVer || nodes[r].version != item.rightVer {
				continue
			}
			nodes[l].cluster.maxV = nodes[r].cluster.maxV
			nodes[l].cluster.sumV += nodes[r].cluster.sumV
			nodes[l].cluster.count += nodes[r].cluster.count
			nodes[l].cluster.docs = append(nodes[l].cluster.docs, nodes[r].cluster.docs...)
			nodes[l].version++

			nextR := nodes[r].next
			nodes[r].alive = false
			nodes[l].next = nextR
			if nextR != -1 {
				nodes[nextR].prev = l
			}
			aliveCount--

			if nodes[l].prev != -1 {
				pushPair(nodes[l].prev, l)
			}
			if nodes[l].next != -1 {
				pushPair(l, nodes[l].next)
			}
		}

		mergedClusters := make([]vwhClusterR63, 0, aliveCount)
		for cur := 0; cur != -1; cur = nodes[cur].next {
			if nodes[cur].alive {
				mergedClusters = append(mergedClusters, nodes[cur].cluster)
			}
		}
		clusters = mergedClusters
	}
	// Deduplicate docs per surviving cluster for `doc_count` & sub-aggs
	for i := range clusters {
		seen := make(map[string]bool, len(clusters[i].docs))
		var uniq []runtimeMatchedDoc
		for j, md := range clusters[i].docs {
			dk := md.hit.Index + "\x00" + md.hit.ID
			if md.hit.ID == "" {
				dk = fmt.Sprintf("__anon_%d_%d", i, j)
			}
			if !seen[dk] {
				seen[dk] = true
				uniq = append(uniq, md)
			}
		}
		clusters[i].docs = uniq
	}
	return clusters
}

func aggsHaveSignificantTextR63(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.SignificantText != nil || (spec.IsSignificantTerms() && spec.EffectiveTerms() != nil && spec.EffectiveTerms().BackgroundFilter != nil) {
			return true
		}
		if aggsHaveSignificantTextR63(spec.SubAggs()) {
			return true
		}
	}
	return false
}

func aggsHaveKeepValuesScriptPipelineR63(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.BucketScript != nil && strings.EqualFold(strings.TrimSpace(spec.BucketScript.GapPolicy), "keep_values") {
			return true
		}
		if spec.BucketSelector != nil && strings.EqualFold(strings.TrimSpace(spec.BucketSelector.GapPolicy), "keep_values") {
			return true
		}
		if aggsHaveKeepValuesScriptPipelineR63(spec.SubAggs()) {
			return true
		}
	}
	return false
}

func validateAndApplyKeepValuesScriptPipelinesR63(buckets []map[string]any, subAggs map[string]esast.AggSpec) ([]map[string]any, error) {
	if len(buckets) == 0 || len(subAggs) == 0 {
		return buckets, nil
	}
	subNames := make([]string, 0, len(subAggs))
	for k := range subAggs {
		subNames = append(subNames, k)
	}
	sort.Strings(subNames)

	buildParamsWithNulls := func(b map[string]any, spec *esast.BucketSelectorAggSpec, scriptParams map[string]any) (map[string]any, bool) {
		painlessParams := make(map[string]any, len(spec.BucketsPath)+len(scriptParams))
		for k, v := range scriptParams {
			bindNestedPainlessParam(painlessParams, k, v)
		}
		hasNullGap := false
		for k, v := range spec.BucketsPath {
			val, ok := extractBucketMetricByPath(b, v)
			if ok {
				bindNestedPainlessParam(painlessParams, k, val)
				continue
			}
			if mVal, okMap := extractBucketMetricMapByPath(b, v); okMap {
				if singleVal, hasSingle := mVal["value"]; hasSingle && singleVal == nil && len(mVal) <= 2 {
					hasNullGap = true
					bindNestedPainlessParam(painlessParams, k, nil)
					continue
				}
				bindNestedPainlessParam(painlessParams, k, mVal)
				continue
			}
			hasNullGap = true
			bindNestedPainlessParam(painlessParams, k, nil)
		}
		return painlessParams, hasNullGap
	}

	scriptUnboxesNullParam := func(src string, p map[string]any) bool {
		if strings.Contains(src, "null") {
			return false
		}
		var checkMap func(prefix string, m map[string]any) bool
		checkMap = func(prefix string, m map[string]any) bool {
			for k, v := range m {
				full := k
				if prefix != "" {
					full = prefix + "." + k
				}
				if v == nil {
					if strings.Contains(src, full) || strings.Contains(src, fmt.Sprintf("%q", k)) || strings.Contains(src, "'"+k+"'") {
						return true
					}
				} else if sub, okM := v.(map[string]any); okM {
					if checkMap(full, sub) {
						return true
					}
				}
			}
			return false
		}
		return checkMap("", p)
	}

	for _, subName := range subNames {
		spec := subAggs[subName]
		if spec.BucketScript != nil && strings.EqualFold(strings.TrimSpace(spec.BucketScript.GapPolicy), "keep_values") {
			src, scriptParams := extractScriptSourceAndParams(spec.BucketScript.Script)
			if src != "" {
				for _, b := range buckets {
					p, hasNull := buildParamsWithNulls(b, spec.BucketScript, scriptParams)
					if !hasNull {
						continue
					}
					if scriptUnboxesNullParam(src, p) {
						return buckets, fmt.Errorf("script_exception: NullPointerException")
					}
					res, err := painless.Eval(map[string]any{}, src, p)
					if err != nil {
						return buckets, fmt.Errorf("script_exception: NullPointerException: %w", err)
					}
					if res != nil {
						if fv, okF := toFloat64(res); okF && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
							b[subName] = makePipelineMetricObj(fv, spec.BucketScript.Format)
						}
					}
				}
			}
		}
	}

	for _, subName := range subNames {
		spec := subAggs[subName]
		if spec.BucketSelector != nil && strings.EqualFold(strings.TrimSpace(spec.BucketSelector.GapPolicy), "keep_values") {
			src, scriptParams := extractScriptSourceAndParams(spec.BucketSelector.Script)
			if src != "" {
				filtered := make([]map[string]any, 0, len(buckets))
				for _, b := range buckets {
					p, hasNull := buildParamsWithNulls(b, spec.BucketSelector, scriptParams)
					if !hasNull {
						if evalBucketSelector(b, spec.BucketSelector) {
							filtered = append(filtered, b)
						}
						continue
					}
					if scriptUnboxesNullParam(src, p) {
						return buckets, fmt.Errorf("script_exception: NullPointerException")
					}
					keep, err := painless.EvalFilter(map[string]any{}, src, p)
					if err != nil {
						return buckets, fmt.Errorf("script_exception: NullPointerException: %w", err)
					}
					if keep {
						filtered = append(filtered, b)
					}
				}
				buckets = filtered
			}
		}
	}
	return buckets, nil
}

func formatSortValueWithEntryFormatR63(v any, sSpec esast.SortSpec, idxSchema *schema.IndexSchema) any {
	if v == nil {
		return nil
	}
	nt := strings.ToLower(strings.TrimSpace(sSpec.Entry.NumericType))
	if nt != "" {
		switch nt {
		case "long":
			switch tv := v.(type) {
			case float64:
				if !math.IsNaN(tv) && !math.IsInf(tv, 0) {
					v = int64(math.Trunc(tv))
				}
			case float32:
				fv := float64(tv)
				if !math.IsNaN(fv) && !math.IsInf(fv, 0) {
					v = int64(math.Trunc(fv))
				}
			case json.Number:
				if strings.ContainsAny(tv.String(), ".eE") {
					if fv, err := tv.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
						v = int64(math.Trunc(fv))
					}
				}
			}
		case "double":
			switch tv := v.(type) {
			case uint64:
				v = float64(tv)
			case int64:
				if tv != math.MaxInt64 && tv != math.MinInt64 {
					v = float64(tv)
				}
			case int:
				v = float64(tv)
			}
		case "date":
			if idxSchema != nil {
				resolved := resolveSortEntryField(sSpec, idxSchema)
				if strings.EqualFold(strings.TrimSpace(idxSchema.ResolveField(resolved).ESType), "date_nanos") {
					if iv, ok := toInt64(v); ok && iv != math.MaxInt64 && iv != math.MinInt64 {
						v = iv / 1_000_000
					}
				}
			}
		case "date_nanos":
			if idxSchema != nil {
				resolved := resolveSortEntryField(sSpec, idxSchema)
				if strings.EqualFold(strings.TrimSpace(idxSchema.ResolveField(resolved).ESType), "date") {
					if iv, ok := toInt64(v); ok && iv != math.MaxInt64 && iv != math.MinInt64 {
						v = iv * 1_000_000
					}
				}
			}
		}
	}
	fmtStr := strings.TrimSpace(sSpec.Entry.Format)
	if fmtStr == "" || idxSchema == nil {
		return v
	}
	resolved := resolveSortEntryField(sSpec, idxSchema)
	b := idxSchema.ResolveField(resolved)
	esType := strings.ToLower(strings.TrimSpace(b.ESType))
	if (esType == "date_nanos" && nt != "date") || nt == "date_nanos" {
		if iv, ok := toInt64(v); ok {
			return formatDateNanosExactR61Search(iv, fmtStr)
		}
	}
	if esType == "date" || nt == "date" || b.DorisType == schema.DorisBigInt {
		if iv, ok := toInt64(v); ok {
			return formatDateMillisExactR61Search(iv, fmtStr)
		}
	}
	return v
}

func sortedRuntimeRangeAggIndicesAscR63(rngSpec *esast.RangeAggSpec, isDateRange, isIPRange bool, nowUTC time.Time) []int {
	if rngSpec == nil {
		return nil
	}
	n := len(rngSpec.Ranges)
	idxs := make([]int, n)
	for i := 0; i < n; i++ {
		idxs[i] = i
	}
	if n <= 1 || isIPRange || rngSpec.Keyed {
		return idxs
	}
	boundVal := func(raw any, negInf bool) float64 {
		if raw == nil {
			if negInf {
				return math.Inf(-1)
			}
			return math.Inf(1)
		}
		if isDateRange {
			if ms, ok := parseRuntimeDateRangeBoundMillis(raw, rngSpec, nowUTC); ok {
				return float64(ms)
			}
		} else if fv, ok := toFloat(raw); ok && !math.IsNaN(fv) {
			return fv
		}
		if negInf {
			return math.Inf(-1)
		}
		return math.Inf(1)
	}
	sort.SliceStable(idxs, func(a, b int) bool {
		ia, ib := idxs[a], idxs[b]
		fa := boundVal(rngSpec.Ranges[ia].From, true)
		fb := boundVal(rngSpec.Ranges[ib].From, true)
		if fa != fb {
			return fa < fb
		}
		ta := boundVal(rngSpec.Ranges[ia].To, false)
		tb := boundVal(rngSpec.Ranges[ib].To, false)
		return ta < tb
	})
	return idxs
}

func resolveGreedyAggInMapR63(currMap map[string]esast.AggSpec, segs []string, idx int) (string, esast.AggSpec, int, bool) {
	if idx >= len(segs) || len(currMap) == 0 {
		return "", esast.AggSpec{}, idx, false
	}
	for end := len(segs); end > idx; end-- {
		cand := strings.Join(segs[idx:end], ".")
		if sp, ok := currMap[cand]; ok {
			return cand, sp, end - 1, true
		}
	}
	return "", esast.AggSpec{}, idx, false
}

func buildHighlightedSnippetsModeAwareWithFieldTypeR63(
	vals []string,
	re *regexp.Regexp,
	preTag, postTag string,
	htmlEscape bool,
	fragSize, numFrags, noMatchSize, maxAnalyzedOffset int,
	hlType string,
	isKeywordField bool,
) []string {
	hlLower := strings.ToLower(strings.TrimSpace(hlType))
	if hlLower == "plain" && re != nil {
		// ES `plain` highlighter (and `unified` with weighted mode disabled) wraps each matched token individually.
		esc := func(part string) string {
			if !htmlEscape {
				return part
			}
			r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;")
			return r.Replace(part)
		}
		var out []string
		for _, val := range vals {
			searchVal := val
			if maxAnalyzedOffset >= 0 && utf8.RuneCountInString(val) > maxAnalyzedOffset {
				runes := []rune(val)
				searchVal = string(runes[:maxAnalyzedOffset])
			}
			wordSpans := scanWordSpansR62Search(searchVal)
			var matchedSpans [][2]int
			for _, ws := range wordSpans {
				tok := searchVal[ws.start:ws.end]
				if loc := re.FindStringIndex(tok); len(loc) == 2 && loc[0] == 0 && loc[1] == len(tok) {
					matchedSpans = append(matchedSpans, [2]int{ws.start, ws.end})
				}
			}
			if len(matchedSpans) == 0 {
				locs := re.FindAllStringIndex(searchVal, -1)
				for _, loc := range locs {
					if isKeywordField {
						matchedSpans = append(matchedSpans, [2]int{loc[0], loc[1]})
						continue
					}
					subWords := scanWordSpansR62Search(searchVal[loc[0]:loc[1]])
					if len(subWords) > 0 {
						for _, sw := range subWords {
							matchedSpans = append(matchedSpans, [2]int{loc[0] + sw.start, loc[0] + sw.end})
						}
					} else {
						matchedSpans = append(matchedSpans, [2]int{loc[0], loc[1]})
					}
				}
			}
			if len(matchedSpans) == 0 {
				if noMatchSize > 0 && len(val) > 0 {
					runes := []rune(val)
					if len(runes) > noMatchSize {
						runes = runes[:noMatchSize]
					}
					out = append(out, esc(string(runes)))
				}
				continue
			}
			var sb strings.Builder
			pos := 0
			for _, sp := range matchedSpans {
				if sp[0] < pos {
					continue
				}
				sb.WriteString(esc(val[pos:sp[0]]))
				sb.WriteString(preTag)
				sb.WriteString(esc(val[sp[0]:sp[1]]))
				sb.WriteString(postTag)
				pos = sp[1]
			}
			sb.WriteString(esc(val[pos:]))
			frag := sb.String()
			if numFrags > 0 {
				frag = strings.TrimSpace(frag)
			}
			out = append(out, frag)
			if numFrags > 0 && len(out) >= numFrags {
				break
			}
		}
		return out
	}

	frags := buildHighlightedFieldSnippetsWithMaxOffset(vals, re, preTag, postTag, htmlEscape, fragSize, numFrags, noMatchSize, maxAnalyzedOffset)
	if len(frags) == 0 {
		return frags
	}
	// Fix trailing sentence punctuation inside tag on analyzed text fields (`<em>... life.</em>` -> `<em>... life</em>.`)
	// while keeping full value inside tags for `keyword` fields (`50_synthetic_source.yml :: keyword multi unified`),
	// and trim outer whitespace when passage tags are empty/whitespace and `numFrags > 0` (`510_fragment_trimming_fix.yml`).
	trimOuterSpaces := numFrags > 0
	for i, f := range frags {
		if !isKeywordField {
			for _, punct := range []string{".", "!", "?", ",", ";", ":"} {
				if postTag != "" && strings.HasSuffix(f, punct+postTag) {
					f = f[:len(f)-len(punct+postTag)] + postTag + punct
					break
				}
			}
		}
		if trimOuterSpaces {
			f = strings.TrimSpace(f)
		}
		frags[i] = f
	}
	return frags
}

func emitRawBodyDeprecationWarningsR63(w http.ResponseWriter, s *Server, r *http.Request, bodyBytes []byte) {
	if s == nil || s.isES8Mode(r) || len(bodyBytes) == 0 {
		return
	}
	hasDateHistoCand := bytes.Contains(bodyBytes, []byte("date_histogram")) && bytes.Contains(bodyBytes, []byte(`"interval"`))
	hasCommonCand := bytes.Contains(bodyBytes, []byte(`"common"`))
	hasCutoffCand := bytes.Contains(bodyBytes, []byte(`"cutoff_frequency"`))
	hasGeoBBoxCand := bytes.Contains(bodyBytes, []byte(`"geo_bounding_box"`))
	if !hasDateHistoCand && !hasCommonCand && !hasCutoffCand && !hasGeoBBoxCand {
		return
	}
	var root map[string]any
	if json.Unmarshal(bodyBytes, &root) != nil || root == nil {
		return
	}
	isTargetES8 := s.hasExplicitTargetESVersion() && strings.HasPrefix(s.getTargetESVersion(), "8.")
	if hasCommonCand || hasCutoffCand {
		if isTargetES8 {
			hasCommonCand = false
			hasCutoffCand = false
		}
	}
	if !isTargetES8 {
		hasGeoBBoxCand = false
	}
	if hasCommonCand || hasCutoffCand || hasGeoBBoxCand {
		var foundCommon, foundMatchCutoff, foundMultiMatchCutoff, foundGeoBBoxType bool
		hasCutoff := func(m map[string]any) bool {
			_, ok := m["cutoff_frequency"]
			return ok
		}
		var scanDeprecatedQueries func(node any)
		scanDeprecatedQueries = func(node any) {
			switch tv := node.(type) {
			case map[string]any:
				if _, ok := tv["common"].(map[string]any); ok {
					foundCommon = true
				}
				if gb, ok := tv["geo_bounding_box"].(map[string]any); ok {
					if _, hasType := gb["type"]; hasType {
						foundGeoBBoxType = true
					}
				}
				if m, ok := tv["match"].(map[string]any); ok {
					if hasCutoff(m) {
						foundMatchCutoff = true
					} else {
						for _, mv := range m {
							if fm, ok := mv.(map[string]any); ok && hasCutoff(fm) {
								foundMatchCutoff = true
								break
							}
						}
					}
				}
				if mm, ok := tv["multi_match"].(map[string]any); ok && hasCutoff(mm) && !strings.EqualFold(fmt.Sprint(mm["type"]), "bool_prefix") {
					foundMultiMatchCutoff = true
				}
				for _, v := range tv {
					scanDeprecatedQueries(v)
				}
			case []any:
				for _, el := range tv {
					scanDeprecatedQueries(el)
				}
			}
		}
		scanDeprecatedQueries(root["query"])
		if foundCommon {
			emitESDeprecationWarningRound61(w, s, r, "Deprecated field [common] used, replaced by [[match] query which can efficiently skip blocks of documents if the total number of hits is not tracked]")
		}
		if foundMatchCutoff {
			emitESDeprecationWarningRound61(w, s, r, "Deprecated field [cutoff_frequency] used, replaced by [you can omit this option, the [match] query can skip block of documents efficiently if the total number of hits is not tracked]")
		}
		if foundMultiMatchCutoff {
			emitESDeprecationWarningRound61(w, s, r, "Deprecated field [cutoff_frequency] used, replaced by [you can omit this option, the [multi_match] query can skip block of documents efficiently if the total number of hits is not tracked]")
		}
		if foundGeoBBoxType {
			emitESDeprecationWarningRound61(w, s, r, "Deprecated parameter [type] used, it should no longer be specified.")
		}
	}
	if !hasDateHistoCand {
		return
	}
	var hasDeprecatedDateHistoInterval func(node any) bool
	hasDeprecatedDateHistoInterval = func(node any) bool {
		switch tv := node.(type) {
		case map[string]any:
			if dh, ok := tv["date_histogram"].(map[string]any); ok {
				if iv, hasI := dh["interval"].(string); hasI && strings.TrimSpace(iv) != "" {
					return true
				}
			}
			for _, v := range tv {
				if hasDeprecatedDateHistoInterval(v) {
					return true
				}
			}
		case []any:
			for _, el := range tv {
				if hasDeprecatedDateHistoInterval(el) {
					return true
				}
			}
		}
		return false
	}
	if hasDeprecatedDateHistoInterval(root["aggs"]) || hasDeprecatedDateHistoInterval(root["aggregations"]) {
		emitESDeprecationWarningRound61(w, s, r, "[interval] on [date_histogram] is deprecated, use [fixed_interval] or [calendar_interval] in the future.")
	}
}

func (s *Server) populateMissingTokenCountValuesFromBackendR63(idxSchema *schema.IndexSchema, docID string, docMap map[string]any) {
	if s == nil || idxSchema == nil || docID == "" || docMap == nil || idxSchema.DorisTable == "" {
		return
	}
	if !idxSchema.SyntheticSource && !idxSchema.SourceDisabled() {
		return
	}
	var tcFields []string
	for fPath, fb := range idxSchema.Fields {
		if strings.EqualFold(strings.TrimSpace(fb.ESType), "token_count") && fb.ColumnName != "" {
			if _, exists := lookupRawPathValueRound61(docMap, strings.Split(fPath, ".")); !exists {
				tcFields = append(tcFields, fPath)
			}
		}
	}
	if len(tcFields) == 0 {
		return
	}
	zero := 0
	aggs := make(map[string]esast.AggSpec, len(tcFields)+1)
	for _, fPath := range tcFields {
		aggs["__tc_val_"+fPath] = esast.AggSpec{Max: &esast.MetricAggSpec{Field: fPath}}
		aggs["__tc_cnt_"+fPath] = esast.AggSpec{ValueCount: &esast.MetricAggSpec{Field: fPath}}
	}
	plan, err := transpiler.NewTranspiler(idxSchema, transpiler.TranspilerOptions{}).BuildSearchPlan(&esast.SearchRequest{
		Size:  &zero,
		Query: &esast.Query{Ids: &esast.IdsQuery{Values: []string{docID}}},
		Aggs:  aggs,
	})
	if err != nil || plan.AggsSQL == "" {
		return
	}
	rows, qErr := s.backend.QueryAggs(context.Background(), plan.AggsSQL)
	if qErr != nil || len(rows) == 0 {
		return
	}
	cntByField := make(map[string]int64)
	valByField := make(map[string]int64)
	for _, r := range rows {
		if strings.HasPrefix(r.AggName, "__tc_cnt_") {
			cntByField[strings.TrimPrefix(r.AggName, "__tc_cnt_")] = r.effectiveCount()
		} else if strings.HasPrefix(r.AggName, "__tc_val_") {
			valByField[strings.TrimPrefix(r.AggName, "__tc_val_")] = int64(math.Round(r.effectiveValue()))
		}
	}
	shredMap := make(map[string]any)
	for _, fPath := range tcFields {
		if cntByField[fPath] > 0 {
			if fb, ok := idxSchema.Fields[fPath]; ok && fb.ColumnName != "" {
				shredMap[fb.ColumnName] = valByField[fPath]
			}
		}
	}
	if len(shredMap) > 0 {
		docMap["__shredded_fields"] = shredMap
	}
}

func extractIncludeUnmappedPatternsR63(rawBody []byte) map[string]bool {
	if len(rawBody) == 0 || !bytes.Contains(rawBody, []byte("include_unmapped")) {
		return nil
	}
	var root map[string]any
	if json.Unmarshal(rawBody, &root) != nil || root == nil {
		return nil
	}
	rawFields, ok := root["fields"].([]any)
	if !ok {
		return nil
	}
	var out map[string]bool
	for _, el := range rawFields {
		m, okM := el.(map[string]any)
		if !okM {
			continue
		}
		f, _ := m["field"].(string)
		iu, okB := m["include_unmapped"].(bool)
		if okB && iu && strings.TrimSpace(f) != "" {
			if out == nil {
				out = make(map[string]bool)
			}
			out[strings.TrimSpace(f)] = true
		}
	}
	return out
}

func isNonTraversableMappedLeafTypeR63(esType string) bool {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "flattened", "geo_point", "point", "geo_shape", "shape",
		"integer_range", "long_range", "float_range", "double_range", "date_range", "ip_range",
		"join", "dense_vector", "sparse_vector", "completion", "percolator", "histogram", "aggregate_metric_double":
		return true
	}
	return false
}

func formatJavaDoubleR63(f float64) string {
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return s
}

// preNormalizeSearchBodyR63 validates and normalizes raw search JSON before `json.Unmarshal`:
//  1. Strips legacy ES 7 `percolate.document_type` when `!isES8`.
//  2. Validates `random_sampler.probability` (`0 < p < 0.5 || p == 1.0`) and normalizes `p == 1.0` so `esast` accepts it.
//  3. Validates `extended_stats` / `extended_stats_bucket` `sigma >= 0` with ES's exact agg-named error message.
func preNormalizeSearchBodyR63(bodyBytes []byte, isES8 bool) ([]byte, int, string, string) {
	if len(bytes.TrimSpace(bodyBytes)) == 0 {
		return bodyBytes, 0, "", ""
	}
	hasDocType := !isES8 && bytes.Contains(bodyBytes, []byte("document_type")) && bytes.Contains(bodyBytes, []byte("percolate"))
	hasRandSampler := bytes.Contains(bodyBytes, []byte("random_sampler"))
	hasSigma := bytes.Contains(bodyBytes, []byte("sigma")) && bytes.Contains(bodyBytes, []byte("extended_stats"))
	if !hasDocType && !hasRandSampler && !hasSigma {
		return bodyBytes, 0, "", ""
	}

	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil || root == nil {
		return bodyBytes, 0, "", ""
	}

	mutated := false
	if hasDocType {
		var stripPercDocType func(node any)
		stripPercDocType = func(node any) {
			switch tv := node.(type) {
			case map[string]any:
				if pm, ok := tv["percolate"].(map[string]any); ok {
					if _, exists := pm["document_type"]; exists {
						delete(pm, "document_type")
						mutated = true
					}
				}
				for _, v := range tv {
					stripPercDocType(v)
				}
			case []any:
				for _, el := range tv {
					stripPercDocType(el)
				}
			}
		}
		stripPercDocType(root)
	}

	if hasRandSampler || hasSigma {
		var walkAggs func(aggsNode any) (int, string, string)
		walkAggs = func(aggsNode any) (int, string, string) {
			aggsMap, ok := aggsNode.(map[string]any)
			if !ok {
				return 0, "", ""
			}
			aggNames := make([]string, 0, len(aggsMap))
			for k := range aggsMap {
				aggNames = append(aggNames, k)
			}
			sort.Strings(aggNames)
			for _, aggName := range aggNames {
				specMap, okM := aggsMap[aggName].(map[string]any)
				if !okM || specMap == nil {
					continue
				}
				if rsMap, okRS := specMap["random_sampler"].(map[string]any); okRS {
					if rawP, hasP := rsMap["probability"]; hasP && rawP != nil {
						if p, okF := toFloat64(rawP); okF {
							if p <= 0.0 {
								return http.StatusBadRequest, "illegal_argument_exception",
									fmt.Sprintf("[probability] must be greater than 0.0, was [%s]", formatJavaDoubleR63(p))
							} else if p == 1.0 {
								rsMap["probability"] = 0.4999999
								mutated = true
							} else if !(p > 0.0 && p <= 0.5) {
								return http.StatusBadRequest, "illegal_argument_exception",
									fmt.Sprintf("[probability] must be between 0.0 and 0.5 or exactly 1.0, was [%s]", formatJavaDoubleR63(p))
							}
						}
					}
				}
				for _, extKey := range []string{"extended_stats", "extended_stats_bucket"} {
					if esMap, okES := specMap[extKey].(map[string]any); okES {
						if rawS, hasS := esMap["sigma"]; hasS && rawS != nil {
							if sig, okF := toFloat64(rawS); okF && sig < 0 {
								return http.StatusBadRequest, "illegal_argument_exception",
									fmt.Sprintf("[sigma] must be greater than or equal to 0. Found [%s] in [%s]", formatJavaDoubleR63(sig), aggName)
							}
						}
					}
				}
				if st, et, er := walkAggs(specMap["aggs"]); st != 0 {
					return st, et, er
				}
				if st, et, er := walkAggs(specMap["aggregations"]); st != 0 {
					return st, et, er
				}
			}
			return 0, "", ""
		}
		if st, et, er := walkAggs(root["aggs"]); st != 0 {
			return bodyBytes, st, et, er
		}
		if st, et, er := walkAggs(root["aggregations"]); st != 0 {
			return bodyBytes, st, et, er
		}
	}

	if !mutated {
		return bodyBytes, 0, "", ""
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return bodyBytes, 0, "", ""
	}
	return encoded, 0, "", ""
}

type topHitsRawFlagsR63 struct {
	version          bool
	seqNoPrimaryTerm bool
	explain          bool
}

func extractTopHitsFlagsFromScopeR63(scope *activeSearchScope) topHitsRawFlagsR63 {
	var flags topHitsRawFlagsR63
	if scope == nil || len(scope.rawBody) == 0 || !bytes.Contains(scope.rawBody, []byte("top_hits")) {
		return flags
	}
	var root map[string]any
	if json.Unmarshal(scope.rawBody, &root) != nil || root == nil {
		return flags
	}
	var walk func(node any)
	walk = func(node any) {
		switch tv := node.(type) {
		case map[string]any:
			if th, ok := tv["top_hits"].(map[string]any); ok {
				if v, okB := parseStrictESBoolR61Search(th["version"]); okB && v {
					flags.version = true
				}
				if v, okB := parseStrictESBoolR61Search(th["seq_no_primary_term"]); okB && v {
					flags.seqNoPrimaryTerm = true
				}
				if v, okB := parseStrictESBoolR61Search(th["explain"]); okB && v {
					flags.explain = true
				}
			}
			for _, v := range tv {
				walk(v)
			}
		case []any:
			for _, el := range tv {
				walk(el)
			}
		}
	}
	walk(root["aggs"])
	walk(root["aggregations"])
	return flags
}

func collectPercolateMultiDocMatchedQueriesMapR63(
	idxSchema *schema.IndexSchema,
	queryDoc map[string]any,
	q *esast.Query,
) map[string][]any {
	if q == nil || queryDoc == nil {
		return nil
	}
	var percs []*esast.PercolateQuery
	var walk func(cur *esast.Query)
	walk = func(cur *esast.Query) {
		if cur == nil {
			return
		}
		if cur.Percolate != nil {
			percs = append(percs, cur.Percolate)
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
		if cur.FunctionScore != nil && cur.FunctionScore.Query != nil {
			walk(cur.FunctionScore.Query)
		}
	}
	walk(q)
	if len(percs) == 0 {
		return nil
	}
	var out map[string][]any
	for _, perc := range percs {
		slotMap := collectPercolateSlotMatchedQueriesRound63(idxSchema, queryDoc, perc)
		for slot, names := range slotMap {
			if len(names) == 0 {
				continue
			}
			if out == nil {
				out = make(map[string][]any)
			}
			key := fmt.Sprintf("_percolator_document_slot_%d_matched_queries", slot)
			arr := out[key]
			seen := make(map[string]bool, len(arr))
			for _, ex := range arr {
				if s, ok := ex.(string); ok {
					seen[s] = true
				}
			}
			for _, n := range names {
				if n != "" && !seen[n] {
					seen[n] = true
					arr = append(arr, n)
				}
			}
			if len(arr) > 0 {
				out[key] = arr
			}
		}
	}
	return out
}

func parseCompositeDateBoundWithTZR63(val any, dh *esast.DateHistogramAggSpec, nowUTC time.Time) (int64, bool) {
	if val == nil || dh == nil {
		return 0, false
	}
	switch tv := val.(type) {
	case int64:
		return tv, true
	case int:
		return int64(tv), true
	case float64:
		if !math.IsNaN(tv) && !math.IsInf(tv, 0) {
			return int64(tv), true
		}
	case json.Number:
		if iv, err := tv.Int64(); err == nil {
			return iv, true
		}
	case string:
		s := strings.TrimSpace(tv)
		if s == "" {
			return 0, false
		}
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return iv, true
		}
		for _, layout := range []string{
			time.RFC3339Nano,
			"2006-01-02T15:04:05.000-07:00",
			"2006-01-02T15:04:05.000-0700",
			"2006-01-02T15:04:05-07:00",
			"2006-01-02T15:04:05-0700",
		} {
			if tm, err := time.Parse(layout, s); err == nil {
				return tm.UTC().UnixMilli(), true
			}
		}
		rngSpec := &esast.RangeAggSpec{
			Format:   dh.Format,
			TimeZone: dh.TimeZone,
		}
		if ms, ok := parseRuntimeDateRangeBoundMillis(s, rngSpec, nowUTC); ok {
			return ms, true
		}
		if ms, ok := schema.ParseESDateToEpochMillis(s, nowUTC); ok {
			return ms, true
		}
	}
	return 0, false
}

func schemasHaveDocCountFieldR63(schemas []*schema.IndexSchema) bool {
	for _, sc := range schemas {
		if sc == nil {
			continue
		}
		if _, ok := sc.Fields["_doc_count"]; ok {
			return true
		}
	}
	return false
}

func sumDocCountFieldForMatchedDocsR63(docs []runtimeMatchedDoc) int64 {
	var sum int64
	for _, md := range docs {
		dc := int64(1)
		if md.doc != nil {
			if rawDC, exists := md.doc["_doc_count"]; exists && rawDC != nil {
				if iv, ok := toInt64(rawDC); ok && iv > 0 {
					dc = iv
				}
			}
		}
		sum += dc
	}
	return sum
}

func checkWeightedAvgMultiWeightOnDocsR63(aggs map[string]esast.AggSpec, hits []HitRow, schemasByIdx map[string]*schema.IndexSchema, fallback *schema.IndexSchema) error {
	var waSpecs []*esast.WeightedAvgAggSpec
	var walk func(m map[string]esast.AggSpec)
	walk = func(m map[string]esast.AggSpec) {
		for _, sp := range m {
			if sp.WeightedAvg != nil && sp.WeightedAvg.Weight.Field != "" {
				waSpecs = append(waSpecs, sp.WeightedAvg)
			}
			walk(sp.SubAggs())
		}
	}
	walk(aggs)
	if len(waSpecs) == 0 || len(hits) == 0 {
		return nil
	}
	for _, h := range hits {
		doc := decodeHitDocMapRound60(h)
		if doc == nil {
			continue
		}
		sc := schemasByIdx[h.Index]
		if sc == nil {
			sc = fallback
		}
		for _, wa := range waSpecs {
			wf := strings.TrimSpace(wa.Weight.Field)
			segs := strings.Split(strings.TrimSuffix(wf, ".keyword"), ".")
			if sc != nil {
				if b := sc.ResolveField(wf); len(b.SourceJSONPath) > 0 {
					segs = b.SourceJSONPath
				}
			}
			if vals := collectSchemaAwareScalarValues(doc, wf, segs, sc); len(vals) > 1 {
				return fmt.Errorf("illegal_argument_exception: multiple weights are not supported, Weight source can only produce at most one weight per document")
			}
		}
	}
	return nil
}

func detectCrossIndexTermsValueTypeShardFailureMapR65(
	targets []string,
	schemasByIndex map[string]*schema.IndexSchema,
	aggs map[string]esast.AggSpec,
) map[string]string {
	if len(targets) <= 1 || len(aggs) == 0 {
		return nil
	}
	var termsSpecs []*esast.TermsAggSpec
	var walk func(m map[string]esast.AggSpec)
	walk = func(m map[string]esast.AggSpec) {
		for _, sp := range m {
			if t := sp.EffectiveTerms(); t != nil && t.Field != "" && strings.TrimSpace(t.ValueType) != "" {
				termsSpecs = append(termsSpecs, t)
			}
			walk(sp.SubAggs())
		}
	}
	walk(aggs)
	if len(termsSpecs) == 0 {
		return nil
	}
	isNumericVT := func(vt string) bool {
		switch strings.ToLower(strings.TrimSpace(vt)) {
		case "long", "integer", "short", "byte", "unsigned_long", "double", "float", "half_float", "scaled_float", "number", "date", "date_nanos", "boolean":
			return true
		}
		return false
	}
	isStringVT := func(vt string) bool {
		switch strings.ToLower(strings.TrimSpace(vt)) {
		case "string", "keyword", "text", "constant_keyword", "wildcard":
			return true
		}
		return false
	}
	failedIdx := make(map[string]string)
	for _, ts := range termsSpecs {
		vt := strings.ToLower(strings.TrimSpace(ts.ValueType))
		for _, tName := range targets {
			sc := schemasByIndex[tName]
			if sc == nil {
				continue
			}
			b, exists := sc.Fields[ts.Field]
			if !exists {
				continue
			}
			ft := strings.ToLower(strings.TrimSpace(b.ESType))
			mismatch := (isNumericVT(vt) && isStringVT(ft)) || (isStringVT(vt) && isNumericVT(ft) && vt != "string")
			if !mismatch && vt == "ip" && ft != "" && ft != "ip" {
				mismatch = true
			}
			if !mismatch && ft == "ip" && vt != "" && vt != "ip" && vt != "string" {
				mismatch = true
			}
			if mismatch {
				failedIdx[tName] = fmt.Sprintf("Value type [%s] is not compatible with field [%s] of type [%s]", ts.ValueType, ts.Field, b.ESType)
			}
		}
	}
	if len(failedIdx) == 0 || len(failedIdx) >= len(targets) {
		return nil
	}
	return failedIdx
}

func detectCrossIndexTermsValueTypeShardFailuresR63(
	targets []string,
	schemasByIndex map[string]*schema.IndexSchema,
	aggs map[string]esast.AggSpec,
) (int, []map[string]any) {
	failedIdx := detectCrossIndexTermsValueTypeShardFailureMapR65(targets, schemasByIndex, aggs)
	if len(failedIdx) == 0 {
		return 0, nil
	}
	var failures []map[string]any
	for shardIdx, tName := range targets {
		if reason, failed := failedIdx[tName]; failed {
			failures = append(failures, map[string]any{
				"shard": shardIdx,
				"index": tName,
				"node":  "doris-node-1",
				"reason": map[string]any{
					"type":   "illegal_argument_exception",
					"reason": reason,
				},
			})
		}
	}
	return len(failures), failures
}

const randomSamplerProbOneSentinelR63 = 0.4999999

func restoreRandomSamplerProbOneR63(aggs map[string]esast.AggSpec) {
	for k, sp := range aggs {
		mutated := false
		if sp.RandomSampler != nil && sp.RandomSampler.Probability != nil && math.Abs(*sp.RandomSampler.Probability-randomSamplerProbOneSentinelR63) < 1e-12 {
			cp := *sp.RandomSampler
			one := 1.0
			cp.Probability = &one
			sp.RandomSampler = &cp
			mutated = true
		}
		if len(sp.Aggs) > 0 {
			restoreRandomSamplerProbOneR63(sp.Aggs)
		}
		if len(sp.Aggregations) > 0 {
			restoreRandomSamplerProbOneR63(sp.Aggregations)
		}
		if mutated {
			aggs[k] = sp
		}
	}
}

func rewriteTranspilerMaxRegexLengthErrorR63(errMsg string) string {
	const pfx = "Regular expression ["
	const mid = "] exceeds max_regex_length ["
	pIdx := strings.Index(errMsg, pfx)
	if pIdx < 0 {
		return errMsg
	}
	rest := errMsg[pIdx+len(pfx):]
	mIdx := strings.Index(rest, mid)
	if mIdx < 0 {
		return errMsg
	}
	reStr := rest[:mIdx]
	afterMid := rest[mIdx+len(mid):]
	endBracket := strings.IndexByte(afterMid, ']')
	if endBracket < 0 {
		return errMsg
	}
	maxStr := afterMid[:endBracket]
	tail := afterMid[endBracket+1:]
	uLen := len(utf16.Encode([]rune(reStr)))
	return errMsg[:pIdx] + fmt.Sprintf("The length of regex [%d] used in the Regexp Query request has exceeded the allowed maximum of [%s]", uLen, maxStr) + tail
}

func orderMatchedQueriesByRawSourceR63(rawSrc []byte, names []any) []any {
	if len(rawSrc) == 0 || len(names) <= 1 {
		return names
	}
	out := append([]any(nil), names...)
	sort.SliceStable(out, func(i, j int) bool {
		si, oki := out[i].(string)
		sj, okj := out[j].(string)
		if !oki || !okj {
			return false
		}
		pi := bytes.Index(rawSrc, []byte(`"`+si+`"`))
		pj := bytes.Index(rawSrc, []byte(`"`+sj+`"`))
		if pi >= 0 && pj >= 0 && pi != pj {
			return pi < pj
		}
		return false
	})
	return out
}

func (s *Server) handleCacheClearR63(w http.ResponseWriter, r *http.Request) {
	rec := httptest.NewRecorder()
	s.handleCacheClear(rec, r)
	copyRecorderHeadersSetR63(w, rec.Header())
	if rec.Code == http.StatusOK && r != nil {
		q := r.URL.Query()
		hasSpecific := q.Has("request") || q.Has("query") || q.Has("fielddata")
		clearReqCache := !hasSpecific || isTruthyBoolQueryParam(r, "request")
		if clearReqCache {
			rawIdx := strings.TrimSpace(r.PathValue("index"))
			if rawIdx == "" || rawIdx == "_all" || rawIdx == "*" {
				s.clearShardRequestCacheEntriesR63(nil)
			} else {
				s.clearShardRequestCacheEntriesR63(s.resolveTargetIndices(rawIdx))
			}
		}
	}
	w.WriteHeader(rec.Code)
	_, _ = w.Write(rec.Body.Bytes())
}

func extractTopHitsSourceMetricR63(subMap map[string]any, tail []string) (float64, bool) {
	if len(tail) == 1 && strings.HasPrefix(tail[0], "_source.") {
		tail = append([]string{"_source"}, strings.Split(strings.TrimPrefix(tail[0], "_source."), ".")...)
	}
	hitsEnv, okH := subMap["hits"].(map[string]any)
	if !okH {
		return 0, false
	}
	var firstHit map[string]any
	switch hv := hitsEnv["hits"].(type) {
	case []map[string]any:
		if len(hv) > 0 {
			firstHit = hv[0]
		}
	case []any:
		if len(hv) > 0 {
			firstHit, _ = hv[0].(map[string]any)
		}
	}
	if firstHit == nil {
		return 0, false
	}
	if len(tail) == 1 {
		switch tail[0] {
		case "_sort":
			switch sv := firstHit["sort"].(type) {
			case []any:
				if len(sv) > 0 {
					return toFloat64(sv[0])
				}
			case []float64:
				if len(sv) > 0 {
					return sv[0], true
				}
			}
			return 0, false
		case "_score":
			if sc, ok := firstHit["_score"]; ok && sc != nil {
				return toFloat64(sc)
			}
			return 0, false
		}
		return 0, false
	}
	if len(tail) < 2 || tail[0] != "_source" {
		return 0, false
	}
	var srcMap map[string]any
	switch sv := firstHit["_source"].(type) {
	case map[string]any:
		srcMap = sv
	case json.RawMessage:
		dec := json.NewDecoder(bytes.NewReader(sv))
		dec.UseNumber()
		_ = dec.Decode(&srcMap)
	case []byte:
		dec := json.NewDecoder(bytes.NewReader(sv))
		dec.UseNumber()
		_ = dec.Decode(&srcMap)
	}
	if srcMap == nil {
		return 0, false
	}
	val, found := lookupRawPathValueRound61(srcMap, tail[1:])
	if !found || val == nil {
		return 0, false
	}
	return toFloat64(val)
}

func evalMultiIndexScriptFieldsWithPartialFailuresR63(
	s *Server,
	httpReq *http.Request,
	targets []string,
	primaryIndex string,
	allHits []HitRow,
	schemasByIndex map[string]*schema.IndexSchema,
	req *esast.SearchRequest,
) (
	keptHits []HitRow,
	precomputed map[int]map[string]any,
	failedShards int,
	shardFailures []map[string]any,
	fatalSt int,
	fatalPayload map[string]any,
) {
	allowPartial := true
	if httpReq != nil && httpReq.URL != nil && httpReq.URL.Query().Has("allow_partial_search_results") {
		rawAP := strings.TrimSpace(httpReq.URL.Query().Get("allow_partial_search_results"))
		if strings.EqualFold(rawAP, "false") || rawAP == "0" {
			allowPartial = false
		}
	}
	if len(targets) <= 1 || !allowPartial || len(allHits) == 0 {
		sfMap, sfSt, sfPayload := evalSearchScriptFieldsR61Search(s, httpReq, allHits, schemasByIndex, req)
		return allHits, sfMap, 0, nil, sfSt, sfPayload
	}
	sfMap, sfSt, sfPayload := evalSearchScriptFieldsR61Search(s, httpReq, allHits, schemasByIndex, req)
	if sfSt == 0 {
		return allHits, sfMap, 0, nil, 0, nil
	}
	// Evaluate per-hit to isolate failing target shard(s) while preserving healthy shard hits!
	failedByIndex := make(map[string]map[string]any)
	succeededAnyIndex := false
	healthySet := make(map[string]bool)
	for _, h := range allHits {
		hIdx := h.Index
		if hIdx == "" {
			hIdx = primaryIndex
		}
		if _, alreadyFailed := failedByIndex[hIdx]; alreadyFailed {
			continue
		}
		_, hSt, hPayload := evalSearchScriptFieldsR61Search(s, httpReq, []HitRow{h}, schemasByIndex, req)
		if hSt != 0 {
			failedByIndex[hIdx] = hPayload
		} else {
			healthySet[hIdx] = true
			succeededAnyIndex = true
		}
	}
	if !succeededAnyIndex || len(failedByIndex) == 0 {
		return allHits, nil, 0, nil, sfSt, sfPayload
	}
	keptHits = make([]HitRow, 0, len(allHits))
	for _, h := range allHits {
		hIdx := h.Index
		if hIdx == "" {
			hIdx = primaryIndex
		}
		if _, failed := failedByIndex[hIdx]; !failed {
			keptHits = append(keptHits, h)
		}
	}
	precomputed, _, _ = evalSearchScriptFieldsR61Search(s, httpReq, keptHits, schemasByIndex, req)
	for shardIdx, tName := range targets {
		if errPay, failed := failedByIndex[tName]; failed {
			reasonObj := map[string]any{
				"type":   "script_exception",
				"reason": "runtime error",
			}
			if errMap, okE := errPay["error"].(map[string]any); okE {
				if fsArr, okF := errMap["failed_shards"].([]map[string]any); okF && len(fsArr) > 0 {
					if rMap, okR := fsArr[0]["reason"].(map[string]any); okR {
						reasonObj = rMap
					}
				} else if cb, okC := errMap["caused_by"].(map[string]any); okC {
					reasonObj = cb
				}
			}
			shardFailures = append(shardFailures, map[string]any{
				"shard":  shardIdx,
				"index":  tName,
				"node":   "doris-node-1",
				"reason": reasonObj,
			})
		}
	}
	return keptHits, precomputed, len(shardFailures), shardFailures, 0, nil
}
