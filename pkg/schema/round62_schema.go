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

package schema

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

// escapeDorisBacktickIdent escapes literal backticks inside a Doris identifier for “ `...` “ quoting.
func escapeDorisBacktickIdent(ident string) string {
	return strings.ReplaceAll(ident, "`", "``")
}

// IndexFieldScriptEvaluatorFunc evaluates an index-time `mappings.properties.<f>.script`
// against a read-only decoded `_source` document and returns the emitted field values.
type IndexFieldScriptEvaluatorFunc func(fieldPath, esType string, scriptSpec any, onScriptError string, sourceDoc map[string]any) ([]any, error)

var (
	indexFieldScriptEvalMu sync.RWMutex
	indexFieldScriptEvalFn IndexFieldScriptEvaluatorFunc
)

// RegisterIndexFieldScriptEvaluator registers the index-time mapped field `script` evaluator hook.
func RegisterIndexFieldScriptEvaluator(fn IndexFieldScriptEvaluatorFunc) {
	indexFieldScriptEvalMu.Lock()
	indexFieldScriptEvalFn = fn
	indexFieldScriptEvalMu.Unlock()
}

// GetIndexFieldScriptEvaluator returns the currently registered index-time mapped field `script` evaluator hook.
func GetIndexFieldScriptEvaluator() IndexFieldScriptEvaluatorFunc {
	indexFieldScriptEvalMu.RLock()
	fn := indexFieldScriptEvalFn
	indexFieldScriptEvalMu.RUnlock()
	return fn
}

func hasAnyMappedFieldScript(props map[string]esast.FieldProperty) bool {
	for _, prop := range props {
		if prop.Script != nil {
			return true
		}
		if len(prop.Fields) > 0 && hasAnyMappedFieldScript(prop.Fields) {
			return true
		}
		if len(prop.Properties) > 0 && hasAnyMappedFieldScript(prop.Properties) {
			return true
		}
	}
	return false
}

func evaluateIndexTimeMappedScripts(s *IndexSchema, origSourceBytes []byte, parsedDoc map[string]any) (bool, error) {
	if s == nil || s.RawMapping == nil || len(s.RawMapping.Properties) == 0 {
		return false, nil
	}
	evalWithSchemaFn := GetIndexFieldScriptWithSchemaEvaluator()
	evalFn := GetIndexFieldScriptEvaluator()
	if (evalWithSchemaFn == nil && evalFn == nil) || !hasAnyMappedFieldScript(s.RawMapping.Properties) {
		return false, nil
	}
	var roSource map[string]any
	dec := json.NewDecoder(bytes.NewReader(origSourceBytes))
	dec.UseNumber()
	if err := dec.Decode(&roSource); err != nil || roSource == nil {
		roSource = map[string]any{}
	}

	modified := false
	var walk func(props map[string]esast.FieldProperty, prefix []string) error
	walk = func(props map[string]esast.FieldProperty, prefix []string) error {
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			prop := props[k]
			segs := append(append([]string(nil), prefix...), strings.Split(k, ".")...)
			fullPath := strings.Join(segs, ".")
			if prop.Script != nil && (prop.Enabled == nil || *prop.Enabled) {
				onErr := strings.ToLower(strings.TrimSpace(prop.OnScriptError))
				if onErr == "" {
					onErr = "fail"
				}
				var emitted []any
				var err error
				if evalWithSchemaFn != nil {
					emitted, err = evalWithSchemaFn(s, fullPath, strings.ToLower(strings.TrimSpace(prop.Type)), prop.Script, onErr, roSource)
				} else {
					emitted, err = evalFn(fullPath, strings.ToLower(strings.TrimSpace(prop.Type)), prop.Script, onErr, roSource)
				}
				if err != nil {
					if onErr == "continue" {
						continue
					}
					return err
				}
				if len(emitted) == 1 {
					setPathValueInMap(parsedDoc, segs, emitted[0])
					modified = true
				} else if len(emitted) > 1 {
					setPathValueInMap(parsedDoc, segs, emitted)
					modified = true
				}
			}
			if len(prop.Properties) > 0 {
				if err := walk(prop.Properties, segs); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(s.RawMapping.Properties, nil); err != nil {
		return false, err
	}
	return modified, nil
}

func setPathValueInMap(curr map[string]any, path []string, val any) {
	if curr == nil || len(path) == 0 {
		return
	}
	head := path[0] // #nosec G602 -- len(path) >= 1 checked above
	if len(path) == 1 {
		curr[head] = val
		return
	}
	if nextMap, ok := curr[head].(map[string]any); ok && nextMap != nil {
		setPathValueInMap(nextMap, path[1:], val)
		return
	}
	nextMap := make(map[string]any)
	curr[head] = nextMap
	setPathValueInMap(nextMap, path[1:], val)
}

// validateAutoDimsVectorBinding validates an auto-discovered vector dimension count locally without mutating any IndexSchema.
func validateAutoDimsVectorBinding(b FieldBinding, dims int) error {
	if dims <= 0 {
		return nil
	}
	if dims > 4096 {
		return esWireError(fmt.Sprintf("mapper_parsing_exception: [dense_vector] field [%s] requires [dims] in [1, 4096], got [%d]", b.ESFieldPath, dims))
	}
	effElem := strings.ToLower(strings.TrimSpace(b.VectorElementType))
	if effElem == "bit" && dims%8 != 0 {
		return esWireError(fmt.Sprintf("mapper_parsing_exception: [bit] vectors require [dims] to be a multiple of 8 on field [%s], got [%d]", b.ESFieldPath, dims))
	}
	if b.VectorIndexOptions != nil {
		idxType, _ := b.VectorIndexOptions["type"].(string)
		idxType = strings.ToLower(strings.TrimSpace(idxType))
		if (idxType == "int4_hnsw" || idxType == "int4_flat") && dims%2 != 0 {
			return esWireError(fmt.Sprintf("illegal_argument_exception: [dims] must be an even integer when using [%s] on field [%s], got [%d]", idxType, b.ESFieldPath, dims))
		}
	}
	return nil
}

// writeNormalizedVectorIntoNestedMap writes the normalized `[]float64` vector slice back into a nested element map at `relPath`.
func writeNormalizedVectorIntoNestedMap(curr map[string]any, relPath []string, vec []float64) {
	if curr == nil || len(relPath) == 0 || vec == nil {
		return
	}
	key := relPath[0] // #nosec G602 -- len(relPath) >= 1 checked above
	if len(relPath) == 1 {
		if _, exists := curr[key]; exists {
			curr[key] = vec
		}
		return
	}
	if val, exists := curr[key]; exists {
		switch tv := val.(type) {
		case map[string]any:
			writeNormalizedVectorIntoNestedMap(tv, relPath[1:], vec)
		case []any:
			for _, item := range tv {
				if subM, ok := item.(map[string]any); ok {
					writeNormalizedVectorIntoNestedMap(subM, relPath[1:], vec)
				}
			}
		}
		return
	}
	joined := strings.Join(relPath, ".")
	if _, exists := curr[joined]; exists {
		curr[joined] = vec
	}
}

// InspectAutoDimsAndDynamicVectors safely inspects incoming JSON documents without mutating `idxSchema`:
//   - Discovers and validates dimensions for unlocked `AutoDims` `dense_vector` / `knn_vector` fields
//     (including nested paths, hex-encoded `byte` vectors `dims = len(hex)/2`, and `bit` vectors).
//   - In `ES8Mode`, discovers unmapped dynamic float `[128..2048]` vectors (`60_dense_vector_dynamic_mapping.yml`).
func InspectAutoDimsAndDynamicVectors(
	idxSchema *IndexSchema,
	rawDocs [][]byte,
) (lockedAutoDims map[string]int, newDynamicVectors map[string]int, err error) {
	if idxSchema == nil || len(rawDocs) == 0 {
		return nil, nil, nil
	}

	var autoFields []FieldBinding
	for _, k := range sortedFieldKeys(idxSchema.Fields) {
		b := idxSchema.withEffectiveDefaults(idxSchema.Fields[k])
		if b.AutoDims && b.VectorDims == 0 && (b.ESType == "dense_vector" || b.ESType == "knn_vector") {
			autoFields = append(autoFields, b)
		}
	}

	copyToTargets := make(map[string]bool)
	var dynTemplates []map[string]any
	rootDynMode := "true"
	rootSubobjects := true
	if idxSchema.RawMapping != nil {
		collectCopyToTargetsFromProps(idxSchema.RawMapping.Properties, "", copyToTargets)
		dynTemplates = idxSchema.RawMapping.DynamicTemplates
		rootDynMode = normalizeDynamicMode(idxSchema.RawMapping.Dynamic)
		if idxSchema.RawMapping.Subobjects != nil {
			rootSubobjects = *idxSchema.RawMapping.Subobjects
		}
	}

	for _, raw := range rawDocs {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		var doc map[string]any
		if decErr := dec.Decode(&doc); decErr != nil || doc == nil {
			continue
		}

		// 1. Inspect mapped AutoDims vector fields (root & nested)
		for _, b := range autoFields {
			checkB := b
			if lockedDims := lockedAutoDims[b.ESFieldPath]; lockedDims > 0 {
				checkB.VectorDims = lockedDims
				checkB.AutoDims = false
			}
			if b.Kind == StorageNestedSubfield {
				var rootParts []string
				if b.NestedPath != "" {
					rootParts = strings.Split(b.NestedPath, ".")
				}
				elems := extractNestedElementMapsWithIDs(doc, rootParts, "")
				for _, elem := range elems {
					if lockedDims := lockedAutoDims[b.ESFieldPath]; lockedDims > 0 {
						checkB.VectorDims = lockedDims
						checkB.AutoDims = false
					}
					vec, present, vecErr := extractAndValidateTypedVectorValues(elem.m, b.RelativeJSONPath, checkB)
					if !present {
						continue
					}
					if vecErr != nil {
						if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
							continue
						}
						return nil, nil, vecErr
					}
					if len(vec) > 0 && checkB.VectorDims == 0 {
						if vErr := validateAutoDimsVectorBinding(b, len(vec)); vErr != nil {
							return nil, nil, vErr
						}
						if lockedAutoDims == nil {
							lockedAutoDims = make(map[string]int)
						}
						lockedAutoDims[b.ESFieldPath] = len(vec)
						checkB.VectorDims = len(vec)
						checkB.AutoDims = false
					}
				}
				continue
			}

			vec, present, vecErr := extractAndValidateTypedVectorValues(doc, checkB.SourceJSONPath, checkB)
			if !present {
				continue
			}
			if vecErr != nil {
				if b.IgnoreMalformed != nil && *b.IgnoreMalformed {
					continue
				}
				return nil, nil, vecErr
			}
			if len(vec) > 0 && checkB.VectorDims == 0 {
				if vErr := validateAutoDimsVectorBinding(b, len(vec)); vErr != nil {
					return nil, nil, vErr
				}
				if lockedAutoDims == nil {
					lockedAutoDims = make(map[string]int)
				}
				lockedAutoDims[b.ESFieldPath] = len(vec)
			}
		}

		// 2. Inspect ES8 unmapped dynamic float [128..2048] vectors
		if idxSchema.ES8Mode {
			var mappedProps map[string]esast.FieldProperty
			if idxSchema.RawMapping != nil {
				mappedProps = idxSchema.RawMapping.Properties
			}
			if dErr := inspectES8DynamicVectorsInMap(
				idxSchema,
				doc,
				mappedProps,
				"",
				rootDynMode,
				rootSubobjects,
				copyToTargets,
				dynTemplates,
				&newDynamicVectors,
			); dErr != nil {
				return nil, nil, dErr
			}
		}
	}
	return lockedAutoDims, newDynamicVectors, nil
}

func inspectES8DynamicVectorsInMap(
	idxSchema *IndexSchema,
	obj map[string]any,
	props map[string]esast.FieldProperty,
	prefix string,
	dynMode string,
	subobjects bool,
	copyToTargets map[string]bool,
	dynTemplates []map[string]any,
	newDynVecs *map[string]int,
) error {
	if len(obj) == 0 || dynMode == "false" || dynMode == "strict" || dynMode == "runtime" {
		return nil
	}
	workObj := obj
	if subobjects {
		workObj = expandDottedKeysForSyntheticObject(idxSchema, obj, prefix)
	}
	keys := make([]string, 0, len(workObj))
	for k := range workObj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "" || strings.HasPrefix(k, "_") {
			continue
		}
		val := workObj[k]
		if val == nil {
			continue
		}
		fullPath := k
		if prefix != "" {
			fullPath = prefix + "." + k
		}
		prop, hasProp := props[k]
		if hasProp {
			if prop.Enabled != nil && !*prop.Enabled {
				continue
			}
			pType := strings.ToLower(strings.TrimSpace(prop.Type))
			if len(prop.Properties) > 0 || pType == "object" || pType == "nested" || pType == "" {
				childDyn := dynMode
				if prop.Dynamic != nil {
					childDyn = normalizeDynamicMode(prop.Dynamic)
				}
				childSub := subobjects
				if prop.Subobjects != nil {
					childSub = *prop.Subobjects
				}
				switch tv := val.(type) {
				case map[string]any:
					if err := inspectES8DynamicVectorsInMap(idxSchema, tv, prop.Properties, fullPath, childDyn, childSub, copyToTargets, dynTemplates, newDynVecs); err != nil {
						return err
					}
				case []any:
					for _, elem := range tv {
						if em, ok := elem.(map[string]any); ok {
							if err := inspectES8DynamicVectorsInMap(idxSchema, em, prop.Properties, fullPath, childDyn, childSub, copyToTargets, dynTemplates, newDynVecs); err != nil {
								return err
							}
						}
					}
				}
			}
			continue
		}

		if _, alreadyCompiled := idxSchema.Fields[fullPath]; alreadyCompiled {
			continue
		}
		if copyToTargets[fullPath] {
			continue
		}

		switch tv := val.(type) {
		case map[string]any:
			if subobjects {
				if err := inspectES8DynamicVectorsInMap(idxSchema, tv, nil, fullPath, dynMode, subobjects, copyToTargets, dynTemplates, newDynVecs); err != nil {
					return err
				}
			}
		case []any:
			hasMap := false
			for _, elem := range tv {
				if em, ok := elem.(map[string]any); ok {
					hasMap = true
					if subobjects {
						if err := inspectES8DynamicVectorsInMap(idxSchema, em, nil, fullPath, dynMode, subobjects, copyToTargets, dynTemplates, newDynVecs); err != nil {
							return err
						}
					}
				}
			}
			if hasMap {
				continue
			}
			// If a previous doc in this batch already inferred this path as a dynamic dense_vector, validate dimension consistency!
			if *newDynVecs != nil {
				if prevDims, already := (*newDynVecs)[fullPath]; already && prevDims > 0 {
					tmpB := FieldBinding{
						ESFieldPath:       fullPath,
						ESType:            "dense_vector",
						VectorDims:        prevDims,
						VectorMetric:      "cosine",
						VectorElementType: "float",
					}
					if _, _, vErr := extractAndValidateTypedVectorValues(tv, nil, tmpB); vErr != nil {
						return vErr
					}
					continue
				}
			}
			if len(tv) < 128 || len(tv) > 2048 {
				continue
			}
			allNumeric := true
			hasFloat := false
			var sumSq float64
			for _, elem := range tv {
				if elem == nil {
					allNumeric = false
					break
				}
				switch n := elem.(type) {
				case float64:
					if math.IsNaN(n) || math.IsInf(n, 0) {
						allNumeric = false
					} else {
						hasFloat = true
						sumSq += n * n
					}
				case json.Number:
					s := n.String()
					if strings.ContainsAny(s, ".eE") {
						hasFloat = true
					}
					f, fErr := n.Float64()
					if fErr != nil || math.IsNaN(f) || math.IsInf(f, 0) {
						allNumeric = false
					} else {
						sumSq += f * f
					}
				default:
					allNumeric = false
				}
				if !allNumeric {
					break
				}
			}
			if !allNumeric || !hasFloat {
				continue
			}
			if len(dynTemplates) > 0 {
				if _, ok := applyMatchingDynamicTemplate(k, fullPath, "double", dynTemplates); ok {
					continue
				}
				if _, ok := applyMatchingDynamicTemplate(k, fullPath, "float", dynTemplates); ok {
					continue
				}
			}
			if sumSq == 0 {
				return esWireError(fmt.Sprintf("mapper_parsing_exception: Zero-magnitude vectors are not supported when using [cosine] similarity on field [%s]", fullPath))
			}
			if *newDynVecs == nil {
				*newDynVecs = make(map[string]int)
			}
			(*newDynVecs)[fullPath] = len(tv)
		}
	}
	return nil
}

func sortedFieldKeys(m map[string]FieldBinding) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func cloneFieldBindingValue(b FieldBinding) FieldBinding {
	cp := b
	if len(b.SourceJSONPath) > 0 {
		cp.SourceJSONPath = append([]string(nil), b.SourceJSONPath...)
	}
	if len(b.RelativeJSONPath) > 0 {
		cp.RelativeJSONPath = append([]string(nil), b.RelativeJSONPath...)
	}
	if len(b.CopyTo) > 0 {
		cp.CopyTo = append([]string(nil), b.CopyTo...)
	}
	if len(b.Meta) > 0 {
		cp.Meta = cloneStringMap(b.Meta)
	}
	if len(b.Contexts) > 0 {
		cp.Contexts = deepCloneCompletionContexts(b.Contexts)
	}
	if len(b.VectorIndexOptions) > 0 {
		cp.VectorIndexOptions = deepCloneMapStringAny(b.VectorIndexOptions)
	}
	if len(b.Relations) > 0 {
		cp.Relations = deepCloneMapStringAny(b.Relations)
	}
	if b.NullValue != nil {
		cp.NullValue = deepCloneAny(b.NullValue)
	}
	if b.ConstantValue != nil {
		cp.ConstantValue = deepCloneAny(b.ConstantValue)
	}
	if len(b.AggregateMetrics) > 0 {
		cp.AggregateMetrics = append([]string(nil), b.AggregateMetrics...)
	}
	if b.Coerce != nil {
		v := *b.Coerce
		cp.Coerce = &v
	}
	if b.IgnoreMalformed != nil {
		v := *b.IgnoreMalformed
		cp.IgnoreMalformed = &v
	}
	if b.EnablePositionIncrements != nil {
		v := *b.EnablePositionIncrements
		cp.EnablePositionIncrements = &v
	}
	if b.PositiveScoreImpact != nil {
		v := *b.PositiveScoreImpact
		cp.PositiveScoreImpact = &v
	}
	if b.StoreArraySource != nil {
		v := *b.StoreArraySource
		cp.StoreArraySource = &v
	}
	if b.TimeSeriesDimension != nil {
		v := *b.TimeSeriesDimension
		cp.TimeSeriesDimension = &v
	}
	if len(b.TimeSeriesDimensions) > 0 {
		cp.TimeSeriesDimensions = append([]string(nil), b.TimeSeriesDimensions...)
	}
	return cp
}

func deepCloneFieldProperty(fp esast.FieldProperty) esast.FieldProperty {
	cp := fp
	if fp.Enabled != nil {
		v := *fp.Enabled
		cp.Enabled = &v
	}
	if fp.IncludeInParent != nil {
		v := *fp.IncludeInParent
		cp.IncludeInParent = &v
	}
	if fp.IncludeInRoot != nil {
		v := *fp.IncludeInRoot
		cp.IncludeInRoot = &v
	}
	if fp.Index != nil {
		v := *fp.Index
		cp.Index = &v
	}
	if fp.DocValues != nil {
		v := *fp.DocValues
		cp.DocValues = &v
	}
	if fp.Subobjects != nil {
		v := *fp.Subobjects
		cp.Subobjects = &v
	}
	if fp.Store != nil {
		v := *fp.Store
		cp.Store = &v
	}
	if fp.IgnoreMalformed != nil {
		v := *fp.IgnoreMalformed
		cp.IgnoreMalformed = &v
	}
	if fp.Coerce != nil {
		v := *fp.Coerce
		cp.Coerce = &v
	}
	if fp.Norms != nil {
		v := *fp.Norms
		cp.Norms = &v
	}
	if fp.EagerGlobalOrdinals != nil {
		v := *fp.EagerGlobalOrdinals
		cp.EagerGlobalOrdinals = &v
	}
	if fp.IndexPhrases != nil {
		v := *fp.IndexPhrases
		cp.IndexPhrases = &v
	}
	if fp.SplitQueriesOnWhitespace != nil {
		v := *fp.SplitQueriesOnWhitespace
		cp.SplitQueriesOnWhitespace = &v
	}
	if fp.EnablePositionIncrements != nil {
		v := *fp.EnablePositionIncrements
		cp.EnablePositionIncrements = &v
	}
	if fp.PositiveScoreImpact != nil {
		v := *fp.PositiveScoreImpact
		cp.PositiveScoreImpact = &v
	}
	if fp.MaxShingleSize != nil {
		v := *fp.MaxShingleSize
		cp.MaxShingleSize = &v
	}
	if fp.DepthLimit != nil {
		v := *fp.DepthLimit
		cp.DepthLimit = &v
	}
	if fp.StoreArraySource != nil {
		v := *fp.StoreArraySource
		cp.StoreArraySource = &v
	}
	if fp.TimeSeriesDimension != nil {
		v := *fp.TimeSeriesDimension
		cp.TimeSeriesDimension = &v
	}
	if len(fp.TimeSeriesDimensions) > 0 {
		cp.TimeSeriesDimensions = append([]string(nil), fp.TimeSeriesDimensions...)
	}
	if len(fp.Meta) > 0 {
		cp.Meta = cloneStringMap(fp.Meta)
	}
	if len(fp.Contexts) > 0 {
		cp.Contexts = deepCloneCompletionContexts(fp.Contexts)
	}
	if fp.Dynamic != nil {
		cp.Dynamic = deepCloneAny(fp.Dynamic)
	}
	if fp.Value != nil {
		cp.Value = deepCloneAny(fp.Value)
	}
	if fp.Script != nil {
		cp.Script = deepCloneAny(fp.Script)
	}
	if fp.CopyTo != nil {
		cp.CopyTo = deepCloneAny(fp.CopyTo)
	}
	if fp.NullValue != nil {
		cp.NullValue = deepCloneAny(fp.NullValue)
	}
	if fp.IndexPrefixes != nil {
		cp.IndexPrefixes = deepCloneMapStringAny(fp.IndexPrefixes)
	}
	if fp.IndexOptions != nil {
		cp.IndexOptions = deepCloneAny(fp.IndexOptions)
	}
	if fp.Boost != nil {
		cp.Boost = deepCloneAny(fp.Boost)
	}
	if fp.Fielddata != nil {
		cp.Fielddata = deepCloneAny(fp.Fielddata)
	}
	if fp.Relations != nil {
		cp.Relations = deepCloneMapStringAny(fp.Relations)
	}
	if fp.FetchFields != nil {
		cp.FetchFields = deepCloneSliceMapStringAny(fp.FetchFields)
	}
	if fp.Metrics != nil {
		cp.Metrics = append([]string(nil), fp.Metrics...)
	}
	if len(fp.Fields) > 0 {
		cp.Fields = make(map[string]esast.FieldProperty, len(fp.Fields))
		for k, sub := range fp.Fields {
			cp.Fields[k] = deepCloneFieldProperty(sub)
		}
	}
	if len(fp.Properties) > 0 {
		cp.Properties = make(map[string]esast.FieldProperty, len(fp.Properties))
		for k, sub := range fp.Properties {
			cp.Properties[k] = deepCloneFieldProperty(sub)
		}
	}
	return cp
}

func deepCloneMappingSpec(m *esast.MappingSpec) *esast.MappingSpec {
	if m == nil {
		return nil
	}
	cp := *m
	if m.Enabled != nil {
		v := *m.Enabled
		cp.Enabled = &v
	}
	if m.Subobjects != nil {
		v := *m.Subobjects
		cp.Subobjects = &v
	}
	if m.DateDetection != nil {
		v := *m.DateDetection
		cp.DateDetection = &v
	}
	if m.NumericDetection != nil {
		v := *m.NumericDetection
		cp.NumericDetection = &v
	}
	if len(m.DynamicDateFormats) > 0 {
		cp.DynamicDateFormats = append([]string(nil), m.DynamicDateFormats...)
	}
	if m.Routing != nil {
		r := *m.Routing
		cp.Routing = &r
	}
	if m.Dynamic != nil {
		cp.Dynamic = deepCloneAny(m.Dynamic)
	}
	if m.DataStreamTimestamp != nil {
		cp.DataStreamTimestamp = deepCloneAny(m.DataStreamTimestamp)
	}
	if m.Size != nil {
		cp.Size = deepCloneMapStringAny(m.Size)
	}
	if m.Meta != nil {
		cp.Meta = deepCloneMapStringAny(m.Meta)
	}
	if m.Source != nil {
		cp.Source = deepCloneMapStringAny(m.Source)
	}
	if m.DynamicTemplates != nil {
		cp.DynamicTemplates = deepCloneSliceMapStringAny(m.DynamicTemplates)
	}
	if len(m.Runtime) > 0 {
		cp.Runtime = make(map[string]esast.FieldProperty, len(m.Runtime))
		for k, rp := range m.Runtime {
			cp.Runtime[k] = deepCloneFieldProperty(rp)
		}
	}
	if len(m.Properties) > 0 {
		cp.Properties = make(map[string]esast.FieldProperty, len(m.Properties))
		for k, pp := range m.Properties {
			cp.Properties[k] = deepCloneFieldProperty(pp)
		}
	}
	return &cp
}

// CloneIndexSchema returns an independent deep copy of `s` safe for copy-on-write mutation and atomic pointer swap.
func (s *IndexSchema) CloneIndexSchema() *IndexSchema {
	if s == nil {
		return nil
	}
	cp := *s
	cp.Fields = make(map[string]FieldBinding, len(s.Fields))
	for k, b := range s.Fields {
		cp.Fields[k] = cloneFieldBindingValue(b)
	}
	if len(s.OrderedFields) > 0 {
		cp.OrderedFields = make([]FieldBinding, len(s.OrderedFields))
		for i, b := range s.OrderedFields {
			cp.OrderedFields[i] = cloneFieldBindingValue(b)
		}
	}
	cp.NestedRoots = make(map[string]string, len(s.NestedRoots))
	for k, v := range s.NestedRoots {
		cp.NestedRoots[k] = v
	}
	if len(s.NestedRootSpecs) > 0 {
		cp.NestedRootSpecs = make([]NestedRootSpec, len(s.NestedRootSpecs))
		for i, nr := range s.NestedRootSpecs {
			cp.NestedRootSpecs[i] = NestedRootSpec{
				Path:       nr.Path,
				ColumnName: nr.ColumnName,
				PathParts:  append([]string(nil), nr.PathParts...),
			}
		}
	}
	if len(s.nestedRootPaths) > 0 {
		cp.nestedRootPaths = make(map[string][]string, len(s.nestedRootPaths))
		for k, parts := range s.nestedRootPaths {
			cp.nestedRootPaths[k] = append([]string(nil), parts...)
		}
	}
	if len(s.FieldAddedAtSeqNo) > 0 {
		cp.FieldAddedAtSeqNo = make(map[string]int64, len(s.FieldAddedAtSeqNo))
		for k, v := range s.FieldAddedAtSeqNo {
			cp.FieldAddedAtSeqNo[k] = v
		}
	}
	if len(s.RoutingPath) > 0 {
		cp.RoutingPath = append([]string(nil), s.RoutingPath...)
	}
	if s.DefaultCoerce != nil {
		v := *s.DefaultCoerce
		cp.DefaultCoerce = &v
	}
	if s.DefaultIgnoreMalformed != nil {
		v := *s.DefaultIgnoreMalformed
		cp.DefaultIgnoreMalformed = &v
	}
	if s.SourceConfig != nil {
		sc := *s.SourceConfig
		sc.Includes = append([]string(nil), s.SourceConfig.Includes...)
		sc.Excludes = append([]string(nil), s.SourceConfig.Excludes...)
		if s.SourceConfig.Enabled != nil {
			v := *s.SourceConfig.Enabled
			sc.Enabled = &v
		}
		if s.SourceConfig.Compress != nil {
			v := *s.SourceConfig.Compress
			sc.Compress = &v
		}
		cp.SourceConfig = &sc
	}
	cp.RawMapping = deepCloneMappingSpec(s.RawMapping)
	return &cp
}

// CloneWithLockedAutoDims returns a deep-cloned `*IndexSchema` with all `lockedAutoDims` applied
// (without mutating `s`!) plus any newly created `FieldBinding` columns requiring `GenerateAddColumnsDDL`.
func (s *IndexSchema) CloneWithLockedAutoDims(lockedAutoDims map[string]int) (*IndexSchema, []FieldBinding) {
	if s == nil {
		return nil, nil
	}
	cloned := s.CloneIndexSchema()
	if len(lockedAutoDims) == 0 {
		return cloned, nil
	}

	keys := make([]string, 0, len(lockedAutoDims))
	for k := range lockedAutoDims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var addedBindings []FieldBinding
	for _, fieldPath := range keys {
		dims := lockedAutoDims[fieldPath]
		if dims <= 0 {
			continue
		}
		if existing, ok := cloned.Fields[fieldPath]; ok {
			hadCol := existing.ColumnName != ""
			existing.VectorDims = dims
			existing.AutoDims = false
			if existing.ColumnName == "" && existing.Kind == StoragePromotedVector {
				existing.ColumnName = "f__" + SanitizeDorisIdentifier(fieldPath)
			}
			cloned.Fields[fieldPath] = existing
			for i := range cloned.OrderedFields {
				if cloned.OrderedFields[i].ESFieldPath == fieldPath {
					cloned.OrderedFields[i].VectorDims = dims
					cloned.OrderedFields[i].AutoDims = false
					cloned.OrderedFields[i].ColumnName = existing.ColumnName
				}
			}
			LockAutoDimsInMapping(cloned.RawMapping, fieldPath, dims)
			if !hadCol && existing.ColumnName != "" {
				addedBindings = append(addedBindings, existing)
			}
			continue
		}

		// Brand-new dynamic ES8 dense_vector path!
		idxOpts := MaterializeDenseVectorIndexOptions("float", nil)
		dynProp := esast.FieldProperty{
			Type:         "dense_vector",
			Dims:         dims,
			ExplicitDims: true,
			Similarity:   "cosine",
			IndexOptions: idxOpts,
		}
		if cloned.RawMapping == nil {
			cloned.RawMapping = &esast.MappingSpec{
				Properties: make(map[string]esast.FieldProperty),
			}
		}
		if cloned.RawMapping.Properties == nil {
			cloned.RawMapping.Properties = make(map[string]esast.FieldProperty)
		}
		if isSubobjectsFalseAtPrefix(cloned, "") {
			cloned.RawMapping.Properties[fieldPath] = dynProp
		} else {
			setNestedRawProperty(cloned.RawMapping.Properties, strings.Split(fieldPath, "."), dynProp)
		}

		srcSegs := strings.Split(fieldPath, ".")
		var activeNestedRoot string
		for np := range cloned.NestedRoots {
			if strings.HasPrefix(fieldPath, np+".") && len(np) > len(activeNestedRoot) {
				activeNestedRoot = np
			}
		}
		if activeNestedRoot != "" {
			rootParts := strings.Split(activeNestedRoot, ".")
			relPath := srcSegs[len(rootParts):]
			prefilterCol := "n__" + SanitizeDorisIdentifier(fieldPath)
			nb := FieldBinding{
				ESFieldPath:        fieldPath,
				SourceJSONPath:     srcSegs,
				Kind:               StorageNestedSubfield,
				ColumnName:         prefilterCol,
				DorisType:          DorisFloatArray,
				ESType:             "dense_vector",
				VectorDims:         dims,
				AutoDims:           false,
				VectorMetric:       "cosine",
				VectorElementType:  "float",
				VectorIndexOptions: idxOpts,
				NestedPath:         activeNestedRoot,
				CorrelatedArrayCol: cloned.NestedRoots[activeNestedRoot],
				RelativeJSONPath:   relPath,
				PrefilterArrayCol:  prefilterCol,
			}
			cloned.Fields[fieldPath] = nb
			cloned.OrderedFields = append(cloned.OrderedFields, nb)
			addedBindings = append(addedBindings, nb)
		} else {
			colName := "f__" + SanitizeDorisIdentifier(fieldPath)
			nb := FieldBinding{
				ESFieldPath:        fieldPath,
				SourceJSONPath:     srcSegs,
				Kind:               StoragePromotedVector,
				ColumnName:         colName,
				DorisType:          DorisFloatArray,
				ESType:             "dense_vector",
				VectorDims:         dims,
				AutoDims:           false,
				VectorMetric:       "cosine",
				VectorElementType:  "float",
				VectorIndexOptions: idxOpts,
			}
			cloned.Fields[fieldPath] = nb
			cloned.OrderedFields = append(cloned.OrderedFields, nb)
			addedBindings = append(addedBindings, nb)
		}
	}
	return cloned, addedBindings
}

// CloneWithAutoDimsAndDynamicVectors combines `lockedAutoDims` and `newDynamicVectors` into a single copy-on-write clone.
func (s *IndexSchema) CloneWithAutoDimsAndDynamicVectors(
	lockedAutoDims map[string]int,
	newDynamicVectors map[string]int,
) (*IndexSchema, []FieldBinding) {
	if s == nil {
		return nil, nil
	}
	if len(lockedAutoDims) == 0 && len(newDynamicVectors) == 0 {
		return s.CloneIndexSchema(), nil
	}
	merged := make(map[string]int, len(lockedAutoDims)+len(newDynamicVectors))
	for k, v := range lockedAutoDims {
		merged[k] = v
	}
	for k, v := range newDynamicVectors {
		merged[k] = v
	}
	return s.CloneWithLockedAutoDims(merged)
}

// GenerateAddColumnsDDL generates `ALTER TABLE` statements to add newly bound columns (and any inverted indexes) to Doris.
func GenerateAddColumnsDDL(s *IndexSchema, bindings []FieldBinding) []string {
	if s == nil || len(bindings) == 0 {
		return nil
	}
	dbIdent := escapeDorisBacktickIdent(s.DorisDB)
	tblIdent := escapeDorisBacktickIdent(s.DorisTable)
	seen := make(map[string]bool, len(bindings))
	var stmts []string
	for _, b := range bindings {
		if b.AliasTarget != "" || b.ColumnName == "" || seen[b.ColumnName] {
			continue
		}
		seen[b.ColumnName] = true
		colDef, idxDef := buildColumnAndIndexDDL(b)
		if colDef != "" {
			stmts = append(stmts, fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD COLUMN %s;", dbIdent, tblIdent, colDef))
		}
		if idxDef != "" {
			stmts = append(stmts, fmt.Sprintf("ALTER TABLE `%s`.`%s` ADD %s;", dbIdent, tblIdent, idxDef))
		}
	}
	return stmts
}

// --- TSDB Exact Upstream `_tsid`, `_ts_routing_hash`, `_id` & Native `__tsid` / `__tsid_key` ---

type tsdbDimValueKind uint8

const (
	tsdbDimKindString tsdbDimValueKind = iota
	tsdbDimKindLong
	tsdbDimKindUnsignedLong
	tsdbDimKindBool
	tsdbDimKindIP
)

type tsdbTypedDimension struct {
	name     string
	canon    string
	kind     tsdbDimValueKind
	intVal   int64
	uintVal  uint64
	boolVal  bool
	ipBytes  [16]byte
	typedVal any
}

type tsdbRoutingPair struct {
	name  string
	canon string
}

func appendLuceneVInt(dst []byte, v int) []byte {
	u := uint32(v) // #nosec G115 -- non-negative length encoded as Lucene VInt
	for u >= 0x80 {
		dst = append(dst, byte((u&0x7f)|0x80)) // #nosec G115 -- masked to 7-bit VInt continuation byte
		u >>= 7
	}
	return append(dst, byte(u)) // #nosec G115 -- u < 0x80 fits in 7-bit unsigned byte
}

func utf16CodeUnitLen(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xffff {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func luceneBytesRefBuilderCap(encLen int) int {
	if encLen <= 8 {
		return 8
	}
	extra := encLen >> 3
	if extra < 3 {
		extra = 3
	}
	return (encLen + extra + 7) &^ 7
}

func encodeTSDBTypedDimensionBytes(d tsdbTypedDimension) []byte {
	switch d.kind {
	case tsdbDimKindLong:
		var out [9]byte
		out[0] = 'l'
		binary.BigEndian.PutUint64(out[1:9], uint64(d.intVal)) // #nosec G115 -- signed int64 encoded big-endian per ES TSID format
		return out[:]
	case tsdbDimKindUnsignedLong:
		var out [9]byte
		if d.uintVal <= math.MaxInt64 {
			out[0] = 'l'
			binary.BigEndian.PutUint64(out[1:9], d.uintVal)
		} else {
			out[0] = 'u'
			binary.BigEndian.PutUint64(out[1:9], d.uintVal^0x8000000000000000)
		}
		return out[:]
	case tsdbDimKindIP:
		out := make([]byte, 0, 1+5+len(d.canon))
		out = append(out, 's')
		out = appendLuceneVInt(out, len(d.canon))
		out = append(out, d.canon...)
		return out
	case tsdbDimKindBool:
		if d.boolVal {
			return []byte{'b', 1}
		}
		return []byte{'b', 0}
	default:
		out := make([]byte, 0, 1+5+len(d.canon))
		out = append(out, 's')
		out = appendLuceneVInt(out, len(d.canon))
		out = append(out, d.canon...)
		return out
	}
}

func buildExactESTSIDBytes(dims []tsdbTypedDimension) []byte {
	n := len(dims)
	bodyLen := 16 + 4*n + 16
	out := make([]byte, 0, 5+bodyLen)
	out = appendLuceneVInt(out, bodyLen)

	var namesBuf []byte
	var valsBuf []byte
	valHashes := make([]byte, 0, 4*n)
	for _, d := range dims {
		// Upstream ES `TSID` hashes a zero-padded buffer of size `utf16Len(fieldName) * UnicodeUtil.MAX_UTF8_BYTES_PER_CHAR` (3).
		nb := make([]byte, utf16CodeUnitLen(d.name)*3)
		copy(nb, d.name)
		namesBuf = append(namesBuf, nb...)

		enc := encodeTSDBTypedDimensionBytes(d)
		vh := murmur3X86_32Bytes(enc, 0)
		var b4 [4]byte
		binary.LittleEndian.PutUint32(b4[:], vh)
		valHashes = append(valHashes, b4[:]...)

		padded := make([]byte, luceneBytesRefBuilderCap(len(enc)))
		copy(padded, enc)
		valsBuf = append(valsBuf, padded...)
	}

	nh1, nh2 := murmur3X64_128Bytes(namesBuf, 0)
	var name16 [16]byte
	binary.LittleEndian.PutUint64(name16[0:8], nh1)
	binary.LittleEndian.PutUint64(name16[8:16], nh2)
	out = append(out, name16[:]...)
	out = append(out, valHashes...)

	vh1, vh2 := murmur3X64_128Bytes(valsBuf, 0)
	var val16 [16]byte
	binary.LittleEndian.PutUint64(val16[0:8], vh1)
	binary.LittleEndian.PutUint64(val16[8:16], vh2)
	out = append(out, val16[:]...)
	return out
}

func computeExactESTSDBRoutingHashBytes(pairs []tsdbRoutingPair) [4]byte {
	var mul31 int32
	for _, p := range pairs {
		hk := murmur3X86_32Bytes([]byte(p.name), 0)
		hv := murmur3X86_32Bytes([]byte(p.canon), 0)
		mul31 = 31*mul31 + int32(hk^hv) // #nosec G115 -- intentional Java signed 32-bit hashCode overflow arithmetic
	}
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], uint32(mul31)) // #nosec G115 -- exact little-endian 4-byte wire representation
	return out
}

func parseTSDBTypedDimensionScalar(fieldName string, b FieldBinding, raw any) (tsdbTypedDimension, error) {
	if arr, isArr := raw.([]any); isArr {
		if len(arr) == 1 {
			return parseTSDBTypedDimensionScalar(fieldName, b, arr[0])
		}
		return tsdbTypedDimension{}, fmt.Errorf("mapper_parsing_exception: time_series_dimension field [%s] does not accept arrays with multiple values", fieldName)
	}
	if _, isMap := raw.(map[string]any); isMap {
		return tsdbTypedDimension{}, fmt.Errorf("mapper_parsing_exception: time_series_dimension field [%s] must be a scalar value", fieldName)
	}
	esType := strings.ToLower(strings.TrimSpace(b.ESType))
	switch esType {
	case "long", "integer", "short", "byte":
		var iv int64
		var ok bool
		switch v := raw.(type) {
		case int:
			iv, ok = int64(v), true
		case int64:
			iv, ok = v, true
		case json.Number:
			if parsed, err := v.Int64(); err == nil {
				iv, ok = parsed, true
			} else if fv, errF := v.Float64(); errF == nil && fv == math.Trunc(fv) {
				iv, ok = int64(fv), true
			}
		case float64:
			if v == math.Trunc(v) {
				iv, ok = int64(v), true
			}
		case string:
			trimmed := strings.TrimSpace(v)
			if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				iv, ok = parsed, true
			} else if fv, errF := strconv.ParseFloat(trimmed, 64); errF == nil && fv == math.Trunc(fv) {
				iv, ok = int64(fv), true
			}
		}
		if !ok {
			return tsdbTypedDimension{}, fmt.Errorf("mapper_parsing_exception: failed to parse dimension field [%s] of type [%s]", fieldName, esType)
		}
		return tsdbTypedDimension{
			name:     fieldName,
			canon:    strconv.FormatInt(iv, 10),
			kind:     tsdbDimKindLong,
			intVal:   iv,
			typedVal: iv,
		}, nil

	case "unsigned_long":
		trimmed := strings.TrimSpace(fmt.Sprintf("%v", raw))
		u, err := strconv.ParseUint(trimmed, 10, 64)
		if err != nil {
			return tsdbTypedDimension{}, fmt.Errorf("mapper_parsing_exception: failed to parse dimension field [%s] of type [unsigned_long]", fieldName)
		}
		var tv any
		if u <= math.MaxInt64 {
			tv = int64(u)
		} else {
			tv = json.Number(strconv.FormatUint(u, 10))
		}
		return tsdbTypedDimension{
			name:     fieldName,
			canon:    strconv.FormatUint(u, 10),
			kind:     tsdbDimKindUnsignedLong,
			uintVal:  u,
			typedVal: tv,
		}, nil

	case "ip":
		s := strings.TrimSpace(fmt.Sprintf("%v", raw))
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return tsdbTypedDimension{}, fmt.Errorf("mapper_parsing_exception: failed to parse ip dimension field [%s]: [%s]", fieldName, s)
		}
		canon := addr.Unmap().String()
		return tsdbTypedDimension{
			name:     fieldName,
			canon:    canon,
			kind:     tsdbDimKindIP,
			ipBytes:  ipTo16Bytes(addr),
			typedVal: canon,
		}, nil

	case "boolean":
		var bv bool
		var ok bool
		switch v := raw.(type) {
		case bool:
			bv, ok = v, true
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true":
				bv, ok = true, true
			case "false":
				bv, ok = false, true
			}
		}
		if !ok {
			return tsdbTypedDimension{}, fmt.Errorf("mapper_parsing_exception: failed to parse boolean dimension field [%s]", fieldName)
		}
		return tsdbTypedDimension{
			name:     fieldName,
			canon:    strconv.FormatBool(bv),
			kind:     tsdbDimKindBool,
			boolVal:  bv,
			typedVal: bv,
		}, nil

	case "date", "date_nanos":
		ms, ok := parseTSDBTimestampMillis(raw, esType, b.Format)
		if !ok {
			return tsdbTypedDimension{}, fmt.Errorf("mapper_parsing_exception: failed to parse date dimension field [%s]", fieldName)
		}
		canon := strconv.FormatInt(ms, 10)
		return tsdbTypedDimension{
			name:     fieldName,
			canon:    canon,
			kind:     tsdbDimKindLong,
			intVal:   ms,
			typedVal: canon,
		}, nil

	default:
		s := fmt.Sprintf("%v", raw)
		if b.LowercaseNormalizer {
			s = strings.ToLower(s)
		}
		return tsdbTypedDimension{
			name:     fieldName,
			canon:    s,
			kind:     tsdbDimKindString,
			typedVal: s,
		}, nil
	}
}

func extractTSDBTypedDimensionsFromDoc(idx *IndexSchema, doc map[string]any) ([]tsdbTypedDimension, error) {
	var out []tsdbTypedDimension
	seen := make(map[string]bool)
	if idx == nil {
		return nil, nil
	}
	fieldKeys := sortedFieldKeys(idx.Fields)
	for _, k := range fieldKeys {
		b := idx.Fields[k]
		if b.AliasTarget != "" || strings.HasSuffix(k, ".keyword") || strings.HasPrefix(k, "_") {
			continue
		}
		if b.TimeSeriesDimension != nil && *b.TimeSeriesDimension {
			if strings.EqualFold(b.ESType, "constant_keyword") && b.HasConstantValue && b.ConstantValue != nil {
				rawVals, present := extractAllDocLeafValuesAtPath(doc, strings.Split(k, "."))
				if present && len(rawVals) > 0 {
					tds, err := flattenAndParseTSDBDimensionValues(idx, k, b, rawVals)
					if err != nil {
						return nil, err
					}
					if len(tds) > 0 && !seen[k] {
						seen[k] = true
						out = append(out, tds...)
					} else if !seen[k] {
						seen[k] = true
						cv := fmt.Sprintf("%v", b.ConstantValue)
						out = append(out, tsdbTypedDimension{
							name:     k,
							canon:    cv,
							kind:     tsdbDimKindString,
							typedVal: cv,
						})
					}
				} else if !seen[k] {
					seen[k] = true
					cv := fmt.Sprintf("%v", b.ConstantValue)
					out = append(out, tsdbTypedDimension{
						name:     k,
						canon:    cv,
						kind:     tsdbDimKindString,
						typedVal: cv,
					})
				}
				continue
			}
			rawVals, present := extractAllDocLeafValuesAtPath(doc, strings.Split(k, "."))
			if !present || len(rawVals) == 0 {
				if b.NullValue != nil && hasExplicitNullAtPath(doc, strings.Split(k, ".")) {
					rawVals = []any{b.NullValue}
				} else {
					continue
				}
			}
			tds, err := flattenAndParseTSDBDimensionValues(idx, k, b, rawVals)
			if err != nil {
				return nil, err
			}
			if len(tds) > 0 && !seen[k] {
				seen[k] = true
				out = append(out, tds...)
			}
		}
		if strings.EqualFold(b.ESType, "flattened") && len(b.TimeSeriesDimensions) > 0 {
			rawFlats, present := extractAllDocLeafValuesAtPath(doc, strings.Split(k, "."))
			if !present || len(rawFlats) == 0 {
				continue
			}
			for _, subDim := range b.TimeSeriesDimensions {
				fullName := k + "." + subDim
				var subCandidates []any
				for _, rf := range rawFlats {
					subVals, hasSub := extractAllDocLeafValuesAtPath(rf, strings.Split(subDim, "."))
					if hasSub {
						subCandidates = append(subCandidates, subVals...)
					}
				}
				if len(subCandidates) == 0 {
					continue
				}
				subB := FieldBinding{
					ESFieldPath:         fullName,
					ESType:              "keyword",
					IgnoreAbove:         b.IgnoreAbove,
					IgnoreMalformed:     b.IgnoreMalformed,
					LowercaseNormalizer: b.LowercaseNormalizer,
				}
				tds, err := flattenAndParseTSDBDimensionValues(idx, fullName, subB, subCandidates)
				if err != nil {
					return nil, err
				}
				if len(tds) > 0 && !seen[fullName] {
					seen[fullName] = true
					out = append(out, tds...)
				}
			}
		}
	}
	return out, nil
}

// ExtractTSDBDimensionKeyMap extracts the canonical dimension map (e.g. `{"city": "Amsterdam", "name": "NEMO"}`)
// for a document in `index.mode: time_series`, used for `__tsid_key` and `time_series` aggregation bucket keys.
func ExtractTSDBDimensionKeyMap(idx *IndexSchema, doc map[string]any) (map[string]any, error) {
	dims, err := extractTSDBTypedDimensionsFromDoc(idx, doc)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(dims))
	for _, d := range dims {
		if existing, had := out[d.name]; had {
			if sl, isS := existing.([]any); isS {
				out[d.name] = append(sl, d.typedVal)
			} else {
				out[d.name] = []any{existing, d.typedVal}
			}
		} else {
			out[d.name] = d.typedVal
		}
	}
	return out, nil
}

func tsidBindingForTSDB() FieldBinding {
	return FieldBinding{
		ESFieldPath: "_tsid",
		ColumnName:  "__tsid",
		Kind:        StoragePromotedScalar,
		DorisType:   DorisVarchar,
		ESType:      "keyword",
		NotIndexed:  true,
	}
}

// BindTSDBFields registers `_tsid` (`ColumnName: "__tsid"`) in `s.Fields` when `s.IndexMode == "time_series"`.
func (s *IndexSchema) BindTSDBFields() {
	if s == nil || !strings.EqualFold(strings.TrimSpace(s.IndexMode), "time_series") {
		return
	}
	if s.Fields == nil {
		s.Fields = make(map[string]FieldBinding)
	}
	s.Fields["_tsid"] = tsidBindingForTSDB()
}

// PopulateTSDBColumnsForShred computes `__tsid` and `__tsid_key` for `index.mode: time_series` rows during `ShredDocumentWithNow`.
func PopulateTSDBColumnsForShred(idx *IndexSchema, doc map[string]any, row map[string]any) {
	if idx == nil || !strings.EqualFold(strings.TrimSpace(idx.IndexMode), "time_series") || doc == nil || row == nil {
		return
	}
	dims, err := extractTSDBTypedDimensionsFromDoc(idx, doc)
	if err != nil || len(dims) == 0 {
		return
	}
	sort.Slice(dims, func(i, j int) bool {
		return dims[i].name < dims[j].name
	})
	tsid := base64.RawURLEncoding.EncodeToString(buildExactESTSIDBytes(dims))
	row["__tsid"] = tsid

	keyMap := make(map[string]any, len(dims))
	for _, d := range dims {
		keyMap[d.name] = d.typedVal
	}
	if keyBytes, mErr := json.Marshal(keyMap); mErr == nil {
		row["__tsid_key"] = string(keyBytes)
	}
}

// LogsDBDefaultSortFields returns the default index sort fields (`["host.name", "@timestamp"]`) for `index.mode: logsdb`.
func LogsDBDefaultSortFields() []string {
	return []string{"host.name", "@timestamp"}
}

// ApplyIndexModeDefaults applies `index.mode` defaults (`logsdb` and `time_series` synthetic `_source` and `_tsid` bindings) to `s`.
func ApplyIndexModeDefaults(s *IndexSchema) {
	if s == nil {
		return
	}
	mode := strings.ToLower(strings.TrimSpace(s.IndexMode))
	switch mode {
	case "logsdb":
		if !s.SourceDisabled() && !strings.EqualFold(s.SourceMode, "stored") {
			s.SyntheticSource = true
			if s.SourceMode == "" {
				s.SourceMode = "synthetic"
			}
			if s.RawMapping != nil && s.RawMapping.Source == nil {
				s.RawMapping.Source = map[string]any{"mode": "synthetic"}
			}
		}
	case "time_series":
		s.BindTSDBFields()
		if !s.SourceDisabled() && !strings.EqualFold(s.SourceMode, "stored") {
			s.SyntheticSource = true
			if s.SourceMode == "" {
				s.SourceMode = "synthetic"
			}
		}
	}
}

// ValidateIndexModeSettings validates `index.mode` and ensures TSDB-only settings (`index.routing_path`,
// `index.time_series.start_time`, `index.time_series.end_time`) are rejected when `effectiveMode != "time_series"`.
func ValidateIndexModeSettings(effectiveMode string, settings map[string]any) error {
	mode := strings.ToLower(strings.TrimSpace(effectiveMode))
	switch mode {
	case "", "standard", "time_series", "logsdb", "lookup":
	default:
		return esWireError(fmt.Sprintf("illegal_argument_exception: unknown index mode [%s]", effectiveMode))
	}
	if len(settings) == 0 {
		return nil
	}
	if mode == "time_series" {
		for _, sortKey := range []string{"index.sort.field", "sort.field", "index.sort.order", "sort.order", "index.sort.mode", "sort.mode", "index.sort.missing", "sort.missing"} {
			if _, hasSort := lookupIndexSettingPath(settings, sortKey); hasSort {
				return esWireError("illegal_argument_exception: index sorting cannot be configured explicitly in [time_series] mode")
			}
		}
		if rps, hasRPS := lookupIndexSettingPath(settings, "index.routing_partition_size", "routing_partition_size"); hasRPS {
			if fmt.Sprintf("%v", rps) != "1" {
				return esWireError("illegal_argument_exception: [index.routing_partition_size] is not supported in [time_series] mode")
			}
		}
		return nil
	}
	_, rp, st, et, _ := extractRawTSDBSettingsValues(settings)
	if len(rp) > 0 {
		return esWireError("illegal_argument_exception: [index.routing_path] requires [index.mode=time_series]")
	}
	if st != "" {
		return esWireError("illegal_argument_exception: [index.time_series.start_time] requires [index.mode=time_series]")
	}
	if et != "" {
		return esWireError("illegal_argument_exception: [index.time_series.end_time] requires [index.mode=time_series]")
	}
	return nil
}

// --- Synthetic `_source` Reconstruction Enhancements (`20_synthetic_source.yml`, `91_metrics_no_subobjects.yml`) ---

func isUnmappedScopeInSynthetic(idxSchema *IndexSchema, fullPath string) bool {
	if idxSchema == nil {
		return false
	}
	if idxSchema.RawMapping != nil && idxSchema.RawMapping.Enabled != nil && !*idxSchema.RawMapping.Enabled {
		return true
	}
	if idxSchema.IsDynamicFalseUnmappedField(fullPath) {
		return true
	}
	if b, ok := idxSchema.Fields[fullPath]; ok {
		return b.EnabledFalse
	}
	// Check if any ancestor is `enabled: false`
	parts := strings.Split(fullPath, ".")
	for i := 1; i <= len(parts); i++ {
		anc := strings.Join(parts[:i], ".")
		if ab, ok := idxSchema.Fields[anc]; ok && ab.EnabledFalse {
			return true
		}
	}
	// Check if `fullPath` is a parent prefix of any mapped leaf field
	prefix := fullPath + "."
	for fk := range idxSchema.Fields {
		if strings.HasPrefix(fk, prefix) {
			return false
		}
	}
	if idxSchema.NestedRoots != nil {
		for nr := range idxSchema.NestedRoots {
			if nr == fullPath || strings.HasPrefix(nr, prefix) {
				return false
			}
		}
	}
	if idxSchema.RawMapping != nil && normalizeDynamicMode(idxSchema.RawMapping.Dynamic) == "runtime" {
		return true
	}
	if idxSchema.IgnoreDynamicBeyondLimit {
		return true
	}
	return false
}

func reconstructIgnoredSourceValue(idxSchema *IndexSchema, rawVal any, fullPath string) (any, bool) {
	if rawVal == nil {
		return nil, false
	}
	switch v := rawVal.(type) {
	case map[string]any:
		sub := reconstructIgnoredSourceObject(idxSchema, v, fullPath)
		if sub == nil {
			return map[string]any{}, true
		}
		return sub, true
	case []any:
		out := make([]any, 0, len(v))
		for _, elem := range v {
			if elem == nil {
				continue
			}
			nv, ok := reconstructIgnoredSourceValue(idxSchema, elem, fullPath)
			if ok {
				out = append(out, nv)
			}
		}
		return out, true
	case json.Number:
		if !strings.ContainsAny(v.String(), ".eE") {
			if iv, err := v.Int64(); err == nil {
				return iv, true
			}
			if _, errU := strconv.ParseUint(v.String(), 10, 64); errU == nil {
				return v, true
			}
		}
		if fv, err := v.Float64(); err == nil {
			return fv, true
		}
		return v.String(), true
	default:
		return v, true
	}
}

func reconstructIgnoredSourceObject(idxSchema *IndexSchema, obj map[string]any, prefix string) map[string]any {
	if len(obj) == 0 {
		return map[string]any{}
	}
	work := expandDottedKeysForSyntheticObject(idxSchema, obj, prefix)
	out := make(map[string]any, len(work))
	keys := make([]string, 0, len(work))
	for k := range work {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		rv := work[k]
		if rv == nil {
			continue
		}
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		nv, ok := reconstructIgnoredSourceValue(idxSchema, rv, full)
		if ok {
			out[k] = nv
		}
	}
	return out
}

func hasExplicitStoreArraySourceAtPath(idxSchema *IndexSchema, fullPath string) bool {
	if idxSchema == nil || fullPath == "" {
		return false
	}
	parts := strings.Split(fullPath, ".")
	for i := len(parts); i >= 1; i-- {
		cand := strings.Join(parts[:i], ".")
		if b, ok := idxSchema.Fields[cand]; ok && b.StoreArraySource != nil && *b.StoreArraySource {
			return true
		}
		if idxSchema.RawMapping != nil {
			if fp, ok := lookupRawFieldProperty(idxSchema.RawMapping.Properties, parts[:i]); ok {
				if fp.StoreArraySource != nil && *fp.StoreArraySource {
					return true
				}
			}
		}
	}
	return false
}

// flattenSyntheticMappedObjectArray merges an array of regular mapped objects (`!isNested`, `!store_array_source`)
// into a single object whose leaf fields collect & sort/deduplicate values across all array elements (`20_synthetic_source.yml:493-505, 689-700`).
func flattenSyntheticMappedObjectArray(
	idxSchema *IndexSchema,
	elems []any,
	fullPath string,
	ignoredSet map[string]bool,
) (any, bool) {
	mergedRaw := make(map[string]any)
	for _, elem := range elems {
		em, ok := elem.(map[string]any)
		if !ok || len(em) == 0 {
			continue
		}
		exp := expandDottedKeysForSyntheticObject(idxSchema, em, fullPath)
		mergeObjectArrayElementIntoMap(mergedRaw, exp)
	}
	if len(mergedRaw) == 0 {
		return nil, false
	}
	sub := reconstructSyntheticObject(idxSchema, mergedRaw, fullPath, ignoredSet)
	if len(sub) == 0 {
		return nil, false
	}
	return sub, true
}

func mergeObjectArrayElementIntoMap(dst, src map[string]any) {
	for k, v := range src {
		if v == nil {
			continue
		}
		existing, has := dst[k]
		if !has {
			if sm, isMap := v.(map[string]any); isMap {
				cp := make(map[string]any, len(sm))
				mergeObjectArrayElementIntoMap(cp, sm)
				dst[k] = cp
			} else {
				dst[k] = v
			}
			continue
		}
		if exMap, okEx := existing.(map[string]any); okEx {
			if srcMap, okSrc := v.(map[string]any); okSrc {
				mergeObjectArrayElementIntoMap(exMap, srcMap)
				dst[k] = exMap
				continue
			}
		}
		var combined []any
		if exSlice, okS := existing.([]any); okS {
			combined = append(combined, exSlice...)
		} else {
			combined = append(combined, existing)
		}
		if srcSlice, okS := v.([]any); okS {
			combined = append(combined, srcSlice...)
		} else {
			combined = append(combined, v)
		}
		dst[k] = combined
	}
}

func flattenSubmapsForNoSubobjects(obj map[string]any) map[string]any {
	hasSubMap := false
	for _, v := range obj {
		if _, ok := v.(map[string]any); ok {
			hasSubMap = true
			break
		}
	}
	if !hasSubMap {
		return obj
	}
	out := make(map[string]any, len(obj))
	var walk func(curr map[string]any, pfx string)
	walk = func(curr map[string]any, pfx string) {
		for k, v := range curr {
			full := k
			if pfx != "" {
				full = pfx + "." + k
			}
			if subM, ok := v.(map[string]any); ok && len(subM) > 0 {
				walk(subM, full)
				continue
			}
			out[full] = v
		}
	}
	walk(obj, "")
	return out
}

func expandInferDocKeysOneLevel(obj map[string]any, dst map[string]esast.FieldProperty) map[string]any {
	hasDot := false
	for k := range obj {
		if strings.IndexByte(k, '.') >= 0 {
			hasDot = true
			break
		}
	}
	if !hasDot {
		return obj
	}
	out := make(map[string]any, len(obj))
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		val := obj[k]
		dotIdx := strings.IndexByte(k, '.')
		if dotIdx <= 0 {
			if exM, okEx := out[k].(map[string]any); okEx {
				if valM, okVal := val.(map[string]any); okVal {
					out[k] = mergeSyntheticExpandedMaps(exM, valM)
					continue
				}
			}
			out[k] = val
			continue
		}
		head := k[:dotIdx]
		tail := k[dotIdx+1:]
		if existing, ok := dst[head]; ok {
			exType := strings.ToLower(strings.TrimSpace(existing.Type))
			if exType != "" && exType != "object" && exType != "nested" {
				out[k] = val
				continue
			}
		}
		if rawHead, hasHead := obj[head]; hasHead && rawHead != nil {
			if _, isMap := rawHead.(map[string]any); !isMap {
				out[k] = val
				continue
			}
		}
		nested := map[string]any{tail: val}
		if exM, okEx := out[head].(map[string]any); okEx {
			out[head] = mergeSyntheticExpandedMaps(exM, nested)
		} else {
			out[head] = nested
		}
	}
	return out
}

// --- `search_as_you_type` Virtual Subfields (`_2gram`, `_3gram`, `_4gram`, `_index_prefix`) ---

// TokenizeSearchAsYouTypeSubfields tokenizes string values into ES `search_as_you_type` shingle arrays
// (`_2gram`, `_3gram`, `_4gram`) and `1..20` rune edge n-grams of `maxShingleSize` trailing windows (`_index_prefix`).
func TokenizeSearchAsYouTypeSubfields(values []string, analyzer string, maxShingleSize int) (twoGram, threeGram, fourGram, indexPrefix []string) {
	if len(values) == 0 {
		return nil, nil, nil, nil
	}
	if maxShingleSize < 2 || maxShingleSize > 4 {
		maxShingleSize = 3
	}
	seen2 := make(map[string]bool)
	seen3 := make(map[string]bool)
	seen4 := make(map[string]bool)
	seenPfx := make(map[string]bool)

	for _, raw := range values {
		tokens := tokenizeSAYTAnalyzer(raw, analyzer)
		if len(tokens) == 0 {
			continue
		}
		for i := 0; i+2 <= len(tokens); i++ {
			g2 := tokens[i] + " " + tokens[i+1]
			if !seen2[g2] {
				seen2[g2] = true
				twoGram = append(twoGram, g2)
			}
		}
		if maxShingleSize >= 3 {
			for i := 0; i+3 <= len(tokens); i++ {
				g3 := tokens[i] + " " + tokens[i+1] + " " + tokens[i+2]
				if !seen3[g3] {
					seen3[g3] = true
					threeGram = append(threeGram, g3)
				}
			}
		}
		if maxShingleSize >= 4 {
			for i := 0; i+4 <= len(tokens); i++ {
				g4 := tokens[i] + " " + tokens[i+1] + " " + tokens[i+2] + " " + tokens[i+3]
				if !seen4[g4] {
					seen4[g4] = true
					fourGram = append(fourGram, g4)
				}
			}
		}
		// Upstream ES `_index_prefix` wraps a shingle filter of size `max_shingle_size` (including trailing windows at stream end)
		// with an `edge_ngram` token filter (`min_gram: 1, max_gram: 20` runes).
		for i := 0; i < len(tokens); i++ {
			end := i + maxShingleSize
			if end > len(tokens) {
				end = len(tokens)
			}
			window := strings.Join(tokens[i:end], " ")
			runes := []rune(window)
			limit := len(runes)
			if limit > 20 {
				limit = 20
			}
			for rLen := 1; rLen <= limit; rLen++ {
				pfx := string(runes[:rLen])
				if !seenPfx[pfx] {
					seenPfx[pfx] = true
					indexPrefix = append(indexPrefix, pfx)
				}
			}
		}
	}
	return twoGram, threeGram, fourGram, indexPrefix
}

func tokenizeSAYTAnalyzer(input, analyzer string) []string {
	a := strings.ToLower(strings.TrimSpace(analyzer))
	switch a {
	case "whitespace":
		return strings.Fields(input)
	case "simple":
		var tokens []string
		var cur []rune
		for _, r := range input {
			if unicode.IsLetter(r) {
				cur = append(cur, unicode.ToLower(r))
			} else if len(cur) > 0 {
				tokens = append(tokens, string(cur))
				cur = cur[:0]
			}
		}
		if len(cur) > 0 {
			tokens = append(tokens, string(cur))
		}
		return tokens
	default:
		// Standard analyzer approximation: split on non-alphanumeric (keeping internal apostrophes/dots/underscores only when surrounded, or split words & lowercase)
		var tokens []string
		var cur []rune
		for _, r := range input {
			if unicode.IsLetter(r) || unicode.IsNumber(r) {
				cur = append(cur, unicode.ToLower(r))
			} else if len(cur) > 0 {
				tokens = append(tokens, string(cur))
				cur = cur[:0]
			}
		}
		if len(cur) > 0 {
			tokens = append(tokens, string(cur))
		}
		return tokens
	}
}

// --- `date_nanos` Strict `[1970-01-01T00:00:00Z, 2262-04-11T23:47:16.854775807Z]` Bounds Validation ---

func diagnoseDateNanosOutOfRangeError(raw any, b FieldBinding) error {
	if b.ESType != "date_nanos" || raw == nil {
		return nil
	}
	rawStr := strings.TrimSpace(fmt.Sprintf("%v", raw))
	if rawStr == "" {
		return nil
	}
	// Check integer epoch values directly
	if iv, err := strconv.ParseInt(rawStr, 10, 64); err == nil {
		if iv < 0 {
			return esWireError(fmt.Sprintf(
				"document_parsing_exception: failed to parse field [%s] of type [date_nanos]: date[%s] is before the epoch in 1970 and cannot be stored in nanosecond resolution",
				b.ESFieldPath, rawStr,
			))
		}
		return nil
	}
	// Check parsed ISO / custom format date before 1970 or after 2262-04-11T23:47:16.854775807Z
	checkTime := func(t time.Time) error {
		ut := t.UTC()
		sec := ut.Unix()
		nsec := int64(ut.Nanosecond())
		if sec < 0 {
			return esWireError(fmt.Sprintf(
				"document_parsing_exception: failed to parse field [%s] of type [date_nanos]: date[%s] is before the epoch in 1970 and cannot be stored in nanosecond resolution",
				b.ESFieldPath, rawStr,
			))
		}
		if sec > 9223372036 || (sec == 9223372036 && nsec > 854775807) {
			return esWireError(fmt.Sprintf(
				"document_parsing_exception: failed to parse field [%s] of type [date_nanos]: date[%s] is after 2262-04-11T23:47:16.854775807 and cannot be stored in nanosecond resolution",
				b.ESFieldPath, rawStr,
			))
		}
		return nil
	}
	if t, ok := parseISODateString(rawStr); ok {
		if err := checkTime(t); err != nil {
			return err
		}
	}
	if strings.TrimSpace(b.Format) != "" {
		for _, rawFmt := range strings.Split(b.Format, "||") {
			fmtPart := strings.TrimSpace(rawFmt)
			if fmtPart == "" {
				continue
			}
			layout := ESDateFormatToGoLayout(fmtPart)
			if layout != "" {
				if t, err := time.Parse(layout, rawStr); err == nil {
					if rErr := checkTime(t); rErr != nil {
						return rErr
					}
				}
			}
		}
	}
	return nil
}

// --- `dynamic_templates` List-Valued `match` / `unmatch` / `path_match` / `path_unmatch` / `unmatch_mapping_type` Helpers ---

func parseDynamicTemplatePatternList(raw any, tmplName, keyName string, isRegex bool) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	checkOne := func(s string) error {
		if isRegex {
			if _, err := regexp.Compile(s); err != nil {
				return fmt.Errorf("mapper_parsing_exception: dynamic template [%s] has invalid regex in [%s]: %w", tmplName, keyName, err)
			}
		}
		return nil
	}
	switch v := raw.(type) {
	case string:
		if err := checkOne(v); err != nil {
			return nil, err
		}
		return []string{v}, nil
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if err := checkOne(item); err != nil {
				return nil, err
			}
			out = append(out, item)
		}
		return out, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [%s] must be a string or array of strings", tmplName, keyName)
			}
			if err := checkOne(s); err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("mapper_parsing_exception: dynamic template [%s] [%s] must be a string or array of strings", tmplName, keyName)
	}
}

func matchesAnyDynamicTemplatePattern(raw any, candidate, matchPatternType string) (hasPatterns bool, matched bool) {
	if raw == nil {
		return false, false
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return false, false
		}
		return true, matchDynamicTemplatePattern(v, candidate, matchPatternType)
	case []string:
		if len(v) == 0 {
			return false, false
		}
		for _, pat := range v {
			if pat != "" && matchDynamicTemplatePattern(pat, candidate, matchPatternType) {
				return true, true
			}
		}
		return true, false
	case []any:
		if len(v) == 0 {
			return false, false
		}
		hasAny := false
		for _, item := range v {
			if pat, ok := item.(string); ok && pat != "" {
				hasAny = true
				if matchDynamicTemplatePattern(pat, candidate, matchPatternType) {
					return true, true
				}
			}
		}
		return hasAny, false
	default:
		return false, false
	}
}
