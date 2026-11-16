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
	"math/bits"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

// SupportsDocValuesQueriesInES8 reports whether field binding `b` supports doc_values-backed
// queries in Elasticsearch 8 when `index: false` (`390_doc_values_search.yml`).
func SupportsDocValuesQueriesInES8(b FieldBinding) bool {
	if b.EnabledFalse || b.DocValuesFalse {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(b.ESType)) {
	case "byte", "short", "integer", "long", "unsigned_long",
		"half_float", "float", "double", "scaled_float",
		"date", "date_nanos",
		"keyword", "constant_keyword", "wildcard", "version", "flattened",
		"boolean", "ip",
		"geo_point", "point", "geo_shape", "shape",
		"integer_range", "long_range", "float_range", "double_range", "date_range", "ip_range":
		return true
	default:
		return false
	}
}

func isDenseVectorHNSWIndexType(idxType string) bool {
	switch strings.ToLower(strings.TrimSpace(idxType)) {
	case "hnsw", "int8_hnsw", "int4_hnsw", "bbq_hnsw":
		return true
	default:
		return false
	}
}

func isDenseVectorQuantizedIntIndexType(idxType string) bool {
	switch strings.ToLower(strings.TrimSpace(idxType)) {
	case "int8_hnsw", "int8_flat", "int4_hnsw", "int4_flat":
		return true
	default:
		return false
	}
}

func denseVectorIndexTypeRank(idxType string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(idxType)) {
	case "flat":
		return 0, true
	case "int8_flat":
		return 1, true
	case "int4_flat":
		return 2, true
	case "bbq_flat":
		return 2, true
	case "hnsw":
		return 3, true
	case "int8_hnsw":
		return 4, true
	case "int4_hnsw":
		return 5, true
	case "bbq_hnsw":
		return 5, true
	default:
		return -1, false
	}
}

// ValidateDenseVectorIndexOptions validates `index_options` on a `dense_vector` / `knn_vector` field.
func ValidateDenseVectorIndexOptions(fullPath, fType, effElemType string, dims int, rawOpts any) (map[string]any, error) {
	if rawOpts == nil {
		return nil, nil
	}
	optsMap, ok := rawOpts.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("mapper_parsing_exception: [index_options] on [%s] field [%s] must be an object", fType, fullPath)
	}
	rawType, hasType := optsMap["type"]
	if !hasType || rawType == nil {
		return nil, fmt.Errorf("mapper_parsing_exception: [index_options] requires [type] on [%s] field [%s]", fType, fullPath)
	}
	typeStr, ok := rawType.(string)
	if !ok || strings.TrimSpace(typeStr) == "" {
		return nil, fmt.Errorf("mapper_parsing_exception: [index_options.type] must be a non-empty string on [%s] field [%s]", fType, fullPath)
	}
	idxType := strings.ToLower(strings.TrimSpace(typeStr))
	if _, valid := denseVectorIndexTypeRank(idxType); !valid {
		return nil, fmt.Errorf("mapper_parsing_exception: unknown [index_options.type] [%s] on [%s] field [%s]", typeStr, fType, fullPath)
	}
	if (effElemType == "byte" || effElemType == "bit") && idxType != "hnsw" && idxType != "flat" {
		return nil, fmt.Errorf("mapper_parsing_exception: [index_options.type] [%s] cannot be used with [element_type] [%s] on field [%s]", typeStr, effElemType, fullPath)
	}
	if (idxType == "int4_hnsw" || idxType == "int4_flat") && dims > 0 && dims%2 != 0 {
		return nil, fmt.Errorf("illegal_argument_exception: [dims] must be an even integer when using [%s] on field [%s], got [%d]", idxType, fullPath, dims)
	}

	normalized := make(map[string]any, len(optsMap))
	normalized["type"] = idxType
	isHNSW := isDenseVectorHNSWIndexType(idxType)
	isQuant := isDenseVectorQuantizedIntIndexType(idxType)

	for k, v := range optsMap {
		switch k {
		case "type":
		case "m":
			if !isHNSW {
				return nil, fmt.Errorf("mapper_parsing_exception: Cannot set [m] in [index_options] when [type] is [%s] on field [%s]", idxType, fullPath)
			}
			mVal, err := parseIntOption(v, "m", fullPath)
			if err != nil {
				return nil, err
			}
			if mVal < 1 || mVal > 512 {
				return nil, fmt.Errorf("illegal_argument_exception: [m] must be in [1, 512] on field [%s], got [%d]", fullPath, mVal)
			}
			normalized["m"] = mVal
		case "ef_construction":
			if !isHNSW {
				return nil, fmt.Errorf("mapper_parsing_exception: Cannot set [ef_construction] in [index_options] when [type] is [%s] on field [%s]", idxType, fullPath)
			}
			efVal, err := parseIntOption(v, "ef_construction", fullPath)
			if err != nil {
				return nil, err
			}
			if efVal < 1 || efVal > 3200 {
				return nil, fmt.Errorf("illegal_argument_exception: [ef_construction] must be in [1, 3200] on field [%s], got [%d]", fullPath, efVal)
			}
			normalized["ef_construction"] = efVal
		case "confidence_interval":
			if !isQuant {
				return nil, fmt.Errorf("mapper_parsing_exception: [confidence_interval] can only be set for quantized index types on field [%s]", fullPath)
			}
			if strVal, isStr := v.(string); isStr && strings.EqualFold(strings.TrimSpace(strVal), "dynamic") {
				normalized["confidence_interval"] = "dynamic"
				continue
			}
			ciVal, okCI := syntheticToFloat64(v)
			if !okCI || math.IsNaN(ciVal) || math.IsInf(ciVal, 0) || ciVal < 0.0 || ciVal > 1.0 {
				return nil, fmt.Errorf("illegal_argument_exception: [confidence_interval] must be in [0.0, 1.0] on field [%s]", fullPath)
			}
			normalized["confidence_interval"] = ciVal
		case "rescore_vector":
			normalized["rescore_vector"] = v
		default:
			return nil, fmt.Errorf("mapper_parsing_exception: unknown parameter [%s] in [index_options] on [%s] field [%s]", k, fType, fullPath)
		}
	}
	return normalized, nil
}

// MaterializeDenseVectorIndexOptions returns the materialized ES 8 `index_options` map for `SerializeFieldProperty`.
func MaterializeDenseVectorIndexOptions(effElemType string, rawOpts any) map[string]any {
	if effElemType == "" {
		effElemType = "float"
	}
	if rawOpts == nil {
		if effElemType == "float" {
			return map[string]any{
				"type":            "int8_hnsw",
				"m":               16,
				"ef_construction": 100,
			}
		}
		return nil
	}
	optsMap, ok := rawOpts.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]any, len(optsMap)+2)
	for k, v := range optsMap {
		out[k] = v
	}
	idxType, _ := out["type"].(string)
	idxType = strings.ToLower(strings.TrimSpace(idxType))
	if idxType != "" {
		out["type"] = idxType
	}
	if isDenseVectorHNSWIndexType(idxType) {
		if mVal, hasM := out["m"]; !hasM || mVal == nil {
			out["m"] = 16
		} else if mv, err := parseIntOption(mVal, "m", ""); err == nil {
			out["m"] = mv
		}
		if efVal, hasEF := out["ef_construction"]; !hasEF || efVal == nil {
			out["ef_construction"] = 100
		} else if ev, err := parseIntOption(efVal, "ef_construction", ""); err == nil {
			out["ef_construction"] = ev
		}
	}
	return out
}

func effectiveDenseVectorIndexTypeAndM(prop esast.FieldProperty) (string, int) {
	effElem := strings.ToLower(strings.TrimSpace(prop.ElementType))
	if effElem == "" {
		effElem = "float"
	}
	if prop.Index != nil && !*prop.Index {
		return "", 0
	}
	mat := MaterializeDenseVectorIndexOptions(effElem, prop.IndexOptions)
	if mat == nil {
		return "hnsw", 16
	}
	t, _ := mat["type"].(string)
	t = strings.ToLower(strings.TrimSpace(t))
	mVal := 16
	if rawM, ok := mat["m"]; ok && rawM != nil {
		if parsedM, err := parseIntOption(rawM, "m", ""); err == nil && parsedM > 0 {
			mVal = parsedM
		}
	}
	return t, mVal
}

// ValidateDenseVectorUpdate enforces ES 8.15 `put_mapping` transition rules on `dense_vector` `index_options`.
func ValidateDenseVectorUpdate(fullPath string, oldProp, newProp esast.FieldProperty) error {
	oldNotIndexed := oldProp.Index != nil && !*oldProp.Index
	if oldNotIndexed {
		if newProp.IndexOptions != nil {
			return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot set [index_options] on unindexed [dense_vector]", fullPath)
		}
		return nil
	}
	if newProp.IndexOptions == nil {
		return nil
	}
	effElem := strings.ToLower(strings.TrimSpace(oldProp.ElementType))
	if effElem == "" {
		effElem = "float"
	}
	dims := oldProp.EffectiveDims()
	if newProp.EffectiveDims() > 0 {
		dims = newProp.EffectiveDims()
	}
	if _, err := ValidateDenseVectorIndexOptions(fullPath, "dense_vector", effElem, dims, newProp.IndexOptions); err != nil {
		return err
	}
	oldIdxType, oldM := effectiveDenseVectorIndexTypeAndM(oldProp)
	newIdxType, newM := effectiveDenseVectorIndexTypeAndM(newProp)
	oldRank, okOld := denseVectorIndexTypeRank(oldIdxType)
	newRank, okNew := denseVectorIndexTypeRank(newIdxType)
	if !okOld || !okNew {
		return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: invalid [index_options.type]", fullPath)
	}
	// Disallow downgrades (e.g. hnsw -> flat, hnsw -> int8_flat, int8_hnsw -> flat, int8_hnsw -> int8_flat, int8_flat -> flat, int8_hnsw -> hnsw).
	if newRank < oldRank ||
		(oldIdxType == "int4_flat" && newIdxType == "bbq_flat") ||
		(oldIdxType == "bbq_flat" && newIdxType == "int4_flat") {
		return fmt.Errorf(
			"illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: cannot downgrade [index_options.type] from [%s] to [%s]",
			fullPath, oldIdxType, newIdxType,
		)
	}
	// When upgrading or updating an HNSW index, ES 8.15 forbids decreasing `m` (including implicit default m=16 < oldM).
	if isDenseVectorHNSWIndexType(oldIdxType) && isDenseVectorHNSWIndexType(newIdxType) && newM < oldM {
		return fmt.Errorf(
			"illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot decrease [m] from [%d] to [%d]",
			fullPath, oldM, newM,
		)
	}
	return nil
}

// LockAutoDimsInMapping updates `dims` for `fieldPath` inside `m.Properties`.
func LockAutoDimsInMapping(m *esast.MappingSpec, fieldPath string, dims int) {
	if m == nil || len(m.Properties) == 0 || dims <= 0 || fieldPath == "" {
		return
	}
	lockAutoDimsInProps(m.Properties, strings.Split(fieldPath, "."), dims)
}

func lockAutoDimsInProps(props map[string]esast.FieldProperty, parts []string, dims int) bool {
	if len(parts) == 0 || len(props) == 0 {
		return false
	}
	if fp, ok := props[parts[0]]; ok {
		if len(parts) == 1 {
			if fp.EffectiveDims() == 0 {
				fp.Dims = dims
				props[parts[0]] = fp
				return true
			}
			return false
		}
		if lockAutoDimsInProps(fp.Properties, parts[1:], dims) {
			props[parts[0]] = fp
			return true
		}
		if len(parts) == 2 && len(fp.Fields) > 0 {
			if sfp, hasSub := fp.Fields[parts[1]]; hasSub && sfp.EffectiveDims() == 0 {
				sfp.Dims = dims
				fp.Fields[parts[1]] = sfp
				props[parts[0]] = fp
				return true
			}
		}
	}
	for i := len(parts); i >= 2; i-- {
		joined := strings.Join(parts[:i], ".")
		if fp, ok := props[joined]; ok {
			if i == len(parts) {
				if fp.EffectiveDims() == 0 {
					fp.Dims = dims
					props[joined] = fp
					return true
				}
				return false
			}
			if lockAutoDimsInProps(fp.Properties, parts[i:], dims) {
				props[joined] = fp
				return true
			}
		}
	}
	return false
}

// LockAutoDims locks a dynamically discovered dimension count (`dims`) on an indexed `AutoDims` `dense_vector` field.
func (s *IndexSchema) LockAutoDims(fieldPath string, dims int) error {
	if s == nil || dims <= 0 {
		return nil
	}
	if dims > 4096 {
		return fmt.Errorf("mapper_parsing_exception: [dense_vector] field [%s] requires [dims] in [1, 4096], got [%d]", fieldPath, dims)
	}
	b, ok := s.Fields[fieldPath]
	if !ok {
		return nil
	}
	effElem := strings.ToLower(strings.TrimSpace(b.VectorElementType))
	if effElem == "bit" && dims%8 != 0 {
		return fmt.Errorf("mapper_parsing_exception: [bit] vectors require [dims] to be a multiple of 8 on field [%s], got [%d]", fieldPath, dims)
	}
	if b.VectorIndexOptions != nil {
		idxType, _ := b.VectorIndexOptions["type"].(string)
		idxType = strings.ToLower(strings.TrimSpace(idxType))
		if (idxType == "int4_hnsw" || idxType == "int4_flat") && dims%2 != 0 {
			return fmt.Errorf("illegal_argument_exception: [dims] must be an even integer when using [%s] on field [%s], got [%d]", idxType, fieldPath, dims)
		}
	}
	b.VectorDims = dims
	b.AutoDims = false
	s.Fields[fieldPath] = b
	for i := range s.OrderedFields {
		if s.OrderedFields[i].ESFieldPath == fieldPath {
			s.OrderedFields[i].VectorDims = dims
			s.OrderedFields[i].AutoDims = false
		}
	}
	LockAutoDimsInMapping(s.RawMapping, fieldPath, dims)
	return nil
}

// InferMappingFromSampleDocsES8 infers Elasticsearch 8 field mappings from sample documents:
//   - Scalar floating-point values infer `"float"`
//   - Numeric float arrays of length `[128..2048]` infer `dense_vector` (`dims: len(arr)`, `cosine`, `int8_hnsw`)
//     unless targeted by `copy_to`
//   - Numeric float arrays with `<128` or `>2048` elements (or `copy_to` targets) infer `"float"`
func InferMappingFromSampleDocsES8(docs []json.RawMessage, existing ...*esast.MappingSpec) *esast.MappingSpec {
	return InferMappingFromSampleDocsWithES8(docs, true, existing...)
}

// InferMappingFromSampleDocsWithES8 infers field mappings with explicit `es8Mode` control.
func InferMappingFromSampleDocsWithES8(docs []json.RawMessage, es8Mode bool, existing ...*esast.MappingSpec) *esast.MappingSpec {
	if !es8Mode {
		return InferMappingFromSampleDocs(docs, existing...)
	}
	var baseSpec *esast.MappingSpec
	if len(existing) > 0 {
		baseSpec = existing[0]
	}
	if len(docs) == 0 {
		return nil
	}
	opts := newInferOptions(baseSpec)
	opts.es8Mode = true
	opts.copyToTargets = make(map[string]bool)
	if baseSpec != nil && len(baseSpec.Properties) > 0 {
		collectCopyToTargetsFromProps(baseSpec.Properties, "", opts.copyToTargets)
	}

	props := make(map[string]esast.FieldProperty)
	if baseSpec != nil && len(baseSpec.Properties) > 0 {
		props = DeepMergeMappingProperties(nil, baseSpec.Properties)
	}
	totalFields := 0
	limit := len(docs)
	if limit > maxInferredSampleDocs {
		limit = maxInferredSampleDocs
	}
	var decodedDocs []map[string]any
	for i := 0; i < limit; i++ {
		raw := bytes.TrimSpace(docs[i])
		if len(raw) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var obj map[string]any
		if err := dec.Decode(&obj); err != nil || obj == nil {
			continue
		}
		decodedDocs = append(decodedDocs, obj)
		collectCopyToTargetsFromProps(props, "", opts.copyToTargets)
		inferObjectPropertiesWithOpts(obj, props, "", 0, &totalFields, opts)
	}

	// Handle `copy_to` targets triggered by present mapped source fields when the target itself is absent from doc (`60_dense_vector_dynamic_mapping.yml:535-572`).
	if opts.dynamicMode == "true" && len(decodedDocs) > 0 {
		for _, docObj := range decodedDocs {
			inferUnmappedCopyToTargetsFromPresentFields(docObj, props, "", opts)
		}
	}

	var mergedRuntime map[string]esast.FieldProperty
	if baseSpec != nil {
		rtMap, addedRT := InferDynamicRuntimeFieldsFromDocs(docs, baseSpec)
		if addedRT {
			mergedRuntime = rtMap
		} else if len(baseSpec.Runtime) > 0 {
			mergedRuntime = DeepMergeMappingProperties(nil, baseSpec.Runtime)
		}
	}
	if len(props) == 0 {
		if baseSpec != nil {
			out := *baseSpec
			if len(mergedRuntime) > 0 {
				out.Runtime = mergedRuntime
			}
			return &out
		}
		return nil
	}
	inferredSpec := &esast.MappingSpec{
		Properties: props,
	}
	if baseSpec != nil {
		out := *baseSpec
		if len(mergedRuntime) > 0 {
			out.Runtime = mergedRuntime
		}
		out.Properties = mergeInferredIntoExistingProps(baseSpec.Properties, inferredSpec.Properties)
		return &out
	}
	return inferredSpec
}

func collectCopyToTargetsFromProps(props map[string]esast.FieldProperty, prefix string, dst map[string]bool) {
	if len(props) == 0 || dst == nil {
		return
	}
	for k, prop := range props {
		full := k
		if prefix != "" {
			full = prefix + "." + k
		}
		for _, ct := range prop.CopyToSlice() {
			ct = strings.TrimSpace(ct)
			if ct != "" {
				dst[ct] = true
			}
		}
		for _, fprop := range prop.Fields {
			for _, ct := range fprop.CopyToSlice() {
				ct = strings.TrimSpace(ct)
				if ct != "" {
					dst[ct] = true
				}
			}
		}
		if len(prop.Properties) > 0 {
			collectCopyToTargetsFromProps(prop.Properties, full, dst)
		}
	}
}

func inferUnmappedCopyToTargetsFromPresentFields(doc map[string]any, rootProps map[string]esast.FieldProperty, prefix string, opts inferOptions) {
	if len(doc) == 0 || len(rootProps) == 0 {
		return
	}
	var walk func(currProps map[string]esast.FieldProperty, pfx string)
	walk = func(currProps map[string]esast.FieldProperty, pfx string) {
		for k, prop := range currProps {
			full := k
			if pfx != "" {
				full = pfx + "." + k
			}
			if len(prop.CopyToSlice()) > 0 && docHasExplicitFieldPath(doc, strings.Split(full, ".")) {
				rawLeafs := extractRawLeafValuesWithNull(doc, strings.Split(full, "."), prop.NullValue)
				if len(rawLeafs) > 0 {
					for _, ct := range prop.CopyToSlice() {
						ct = strings.TrimSpace(ct)
						if ct == "" {
							continue
						}
						if _, already := lookupRawFieldProperty(rootProps, strings.Split(ct, ".")); already {
							continue
						}
						srcType := strings.ToLower(strings.TrimSpace(prop.Type))
						var targetProp esast.FieldProperty
						switch srcType {
						case "float", "half_float", "double", "scaled_float":
							if opts.es8Mode {
								targetProp = esast.FieldProperty{Type: "float"}
							} else {
								targetProp = esast.FieldProperty{Type: "double"}
							}
						case "long", "integer", "short", "byte":
							targetProp = esast.FieldProperty{Type: "long"}
						case "unsigned_long":
							targetProp = esast.FieldProperty{Type: "unsigned_long"}
						case "boolean":
							targetProp = esast.FieldProperty{Type: "boolean"}
						case "date", "date_nanos":
							targetProp = esast.FieldProperty{Type: "date"}
						default:
							var total int
							if inf, ok := inferValuePropertyWithOpts(rawLeafs[0], ct, ct, 0, &total, opts); ok {
								targetProp = inf
							}
						}
						if targetProp.Type != "" {
							setNestedRawProperty(rootProps, strings.Split(ct, "."), targetProp)
						}
					}
				}
			}
			if len(prop.Properties) > 0 {
				walk(prop.Properties, full)
			}
		}
	}
	walk(rootProps, prefix)
}

func setNestedRawProperty(props map[string]esast.FieldProperty, parts []string, leaf esast.FieldProperty) {
	if len(parts) == 0 || props == nil {
		return
	}
	if len(parts) == 1 {
		if _, exists := props[parts[0]]; !exists {
			props[parts[0]] = leaf
		}
		return
	}
	parent := props[parts[0]]
	if parent.Properties == nil {
		parent.Properties = make(map[string]esast.FieldProperty)
	}
	setNestedRawProperty(parent.Properties, parts[1:], leaf)
	props[parts[0]] = parent
}

// ValidateSyntheticSourceMapping enforces Elasticsearch 8 synthetic `_source` field-type restrictions
// (`400_synthetic_source.yml`, `percolator/10_basic.yml`).
func ValidateSyntheticSourceMapping(m *esast.MappingSpec) error {
	if m == nil {
		return nil
	}
	if m.Source == nil {
		return nil
	}
	normSrc, err := validateAndNormalizeMappingSourceSpec(m.Source)
	if err != nil {
		return err
	}
	if normSrc.effectiveMode() != "synthetic" {
		return nil
	}
	return validateSyntheticSourceProperties(m.Properties, "")
}

func validateSyntheticSourceProperties(props map[string]esast.FieldProperty, prefix string) error {
	for k, prop := range props {
		fullPath := k
		if prefix != "" {
			fullPath = prefix + "." + k
		}
		if err := validateSingleSyntheticSourceProp(fullPath, prop); err != nil {
			return err
		}
		for fk, fprop := range prop.Fields {
			if err := validateSingleSyntheticSourceProp(fullPath+"."+fk, fprop); err != nil {
				return err
			}
		}
		if len(prop.Properties) > 0 {
			if err := validateSyntheticSourceProperties(prop.Properties, fullPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func hasSyntheticCapableSubfield(fields map[string]esast.FieldProperty) bool {
	for _, fp := range fields {
		ft := strings.ToLower(strings.TrimSpace(fp.Type))
		if fp.Store != nil && *fp.Store {
			return true
		}
		if fp.DocValues != nil && !*fp.DocValues {
			continue
		}
		switch ft {
		case "keyword", "constant_keyword", "wildcard", "version", "ip", "date", "date_nanos",
			"boolean", "byte", "short", "integer", "long", "unsigned_long", "half_float", "float", "double", "scaled_float":
			return true
		case "text":
			if fp.SyntheticSourceKeep != "" && !strings.EqualFold(fp.SyntheticSourceKeep, "none") {
				return true
			}
		}
	}
	return false
}

func validateSingleSyntheticSourceProp(fullPath string, prop esast.FieldProperty) error {
	fType := strings.ToLower(strings.TrimSpace(prop.Type))
	switch prop.SyntheticSourceKeep {
	case "", "none", "all", "arrays":
	default:
		return fmt.Errorf("mapper_parsing_exception: Invalid [synthetic_source_keep] value [%s] for field [%s]", prop.SyntheticSourceKeep, fullPath)
	}
	if prop.SyntheticSourceKeep != "" && fType != "text" && fType != "annotated-text" && fType != "annotated_text" {
		return fmt.Errorf("mapper_parsing_exception: [synthetic_source_keep] is not supported for [%s] field [%s]", fType, fullPath)
	}
	switch fType {
	case "percolator", "token_count", "murmur3", "rank_feature", "annotated-text", "annotated_text":
		if prop.Store != nil && *prop.Store {
			return nil
		}
		if hasSyntheticCapableSubfield(prop.Fields) {
			return nil
		}
		return fmt.Errorf("illegal_argument_exception: Field [%s] of type [%s] doesn't support synthetic source", fullPath, prop.Type)
	case "flattened":
		if prop.DocValues != nil && !*prop.DocValues && (prop.Store == nil || !*prop.Store) {
			return fmt.Errorf("illegal_argument_exception: field [%s] of type [flattened] doesn't support synthetic source because it doesn't have doc values", fullPath)
		}
		return nil
	case "text":
		if prop.Store != nil && *prop.Store {
			return nil
		}
		if strings.EqualFold(prop.SyntheticSourceKeep, "none") {
			if hasSyntheticCapableSubfield(prop.Fields) {
				return nil
			}
			return fmt.Errorf("illegal_argument_exception: Field [%s] of type [text] doesn't support synthetic source unless [synthetic_source_keep] or [store] is enabled", fullPath)
		}
		// In ES 8.14+, `text` fields in an index created with `_source.mode: synthetic` default `synthetic_source_keep` to `"arrays"`.
		return nil
	}
	return nil
}

// ValidateForceSyntheticSource validates `force_synthetic_source=true` on a search request (`400_synthetic_source.yml:212-260`).
// When an index was NOT created with `_source.mode: synthetic`, `text` fields without `store: true`, `synthetic_source_keep`,
// or a synthetic-capable subfield did not record synthetic source values at index time and must fail with 400.
func ValidateForceSyntheticSource(idx *IndexSchema) error {
	if idx == nil || idx.RawMapping == nil {
		return nil
	}
	if err := validateSyntheticSourceProperties(idx.RawMapping.Properties, ""); err != nil {
		return err
	}
	if idx.SyntheticSource {
		return nil
	}
	var walkNonSynthText func(props map[string]esast.FieldProperty, prefix string) error
	walkNonSynthText = func(props map[string]esast.FieldProperty, prefix string) error {
		for k, prop := range props {
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			fType := strings.ToLower(strings.TrimSpace(prop.Type))
			if fType == "text" {
				stored := prop.Store != nil && *prop.Store
				keep := prop.SyntheticSourceKeep != "" && !strings.EqualFold(prop.SyntheticSourceKeep, "none")
				if !stored && !keep && !hasSyntheticCapableSubfield(prop.Fields) {
					return fmt.Errorf("illegal_argument_exception: Field [%s] of type [text] doesn't support synthetic source unless [synthetic_source_keep] or [store] is enabled", full)
				}
			}
			if len(prop.Properties) > 0 {
				if err := walkNonSynthText(prop.Properties, full); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walkNonSynthText(idx.RawMapping.Properties, "")
}

func isSubobjectsFalseAtPrefix(idxSchema *IndexSchema, prefix string) bool {
	if idxSchema == nil || idxSchema.RawMapping == nil {
		return false
	}
	if idxSchema.RawMapping.Subobjects != nil && !*idxSchema.RawMapping.Subobjects {
		return true
	}
	if prefix == "" {
		return false
	}
	parts := strings.Split(prefix, ".")
	curr := idxSchema.RawMapping.Properties
	for _, seg := range parts {
		fp, ok := curr[seg]
		if !ok {
			return false
		}
		if fp.Subobjects != nil && !*fp.Subobjects {
			return true
		}
		curr = fp.Properties
	}
	return false
}

func expandDottedKeysForSyntheticObject(idxSchema *IndexSchema, obj map[string]any, prefix string) map[string]any {
	if len(obj) == 0 || isSubobjectsFalseAtPrefix(idxSchema, prefix) {
		return obj
	}
	hasDot := false
	for k := range obj {
		if strings.IndexByte(k, '.') >= 0 {
			// Check if literal dotted field exists in schema under subobjects: false
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			if idxSchema != nil {
				if b, ok := idxSchema.Fields[full]; ok && len(b.SourceJSONPath) == len(strings.Split(prefix, "."))+1 && prefix != "" {
					continue
				}
			}
			hasDot = true
			break
		}
	}
	if !hasDot {
		return obj
	}
	expanded := make(map[string]any, len(obj))
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		val := obj[k]
		if strings.IndexByte(k, '.') < 0 {
			if existingMap, ok := expanded[k].(map[string]any); ok {
				if valMap, okV := val.(map[string]any); okV {
					expanded[k] = mergeSyntheticExpandedMaps(existingMap, valMap)
					continue
				}
			}
			expanded[k] = val
			continue
		}
		parts := strings.SplitN(k, ".", 2)
		head, tail := parts[0], parts[1]
		nested := map[string]any{tail: val}
		if existingMap, ok := expanded[head].(map[string]any); ok {
			expanded[head] = mergeSyntheticExpandedMaps(existingMap, nested)
		} else {
			expanded[head] = nested
		}
	}
	return expanded
}

func mergeSyntheticExpandedMaps(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if am, okA := out[k].(map[string]any); okA {
			if bm, okB := v.(map[string]any); okB {
				out[k] = mergeSyntheticExpandedMaps(am, bm)
				continue
			}
		}
		out[k] = v
	}
	return out
}

func reconstructSyntheticPositionGeoPoint(rawVal any) (any, bool) {
	if arr, isArr := rawVal.([]any); isArr {
		if len(arr) == 1 {
			return reconstructSyntheticPositionGeoPoint(arr[0])
		}
		// Numeric [lon, lat] pair
		if len(arr) == 2 && isGeoNumericElem(arr[0]) && isGeoNumericElem(arr[1]) {
			_, lat, lon, ok := parseAndFormatGeoPointValue(arr)
			if !ok {
				return nil, false
			}
			return map[string]any{"lat": quantizePositionLat(lat), "lon": quantizePositionLon(lon)}, true
		}
		return nil, false
	}
	_, lat, lon, ok := parseAndFormatGeoPointValue(rawVal)
	if !ok {
		return nil, false
	}
	return map[string]any{"lat": quantizePositionLat(lat), "lon": quantizePositionLon(lon)}, true
}

func quantizePositionLat(lat float64) float64 {
	// Lucene GeoEncodingUtils quantizes lat/lon into 32-bit signed ints (~1e-7 deg), preserving 6+ decimal places.
	return lat
}

func quantizePositionLon(lon float64) float64 {
	return lon
}

type canonicalRangePair struct {
	gte    any
	lte    any
	sortLo float64
	sortHi float64
	loKey  string
	hiKey  string
}

func reconstructSyntheticRangeValue(
	idxSchema *IndexSchema,
	rawVal any,
	fullPath string,
	b FieldBinding,
	esType string,
	ignoredSet map[string]bool,
) (any, bool) {
	if rawVal == nil {
		return nil, false
	}
	var items []any
	if slice, isSlice := rawVal.([]any); isSlice {
		var flatten func(arr []any)
		flatten = func(arr []any) {
			for _, elem := range arr {
				if elem == nil {
					continue
				}
				if sub, ok := elem.([]any); ok {
					flatten(sub)
				} else {
					items = append(items, elem)
				}
			}
		}
		flatten(slice)
	} else {
		items = []any{rawVal}
	}
	if len(items) == 0 {
		return nil, false
	}

	var pairs []canonicalRangePair
	for _, item := range items {
		pair, ok := canonicalizeSingleSyntheticRange(item, b, esType)
		if !ok {
			if (b.IgnoreMalformed != nil && *b.IgnoreMalformed) || ignoredSet[fullPath] {
				continue
			}
			continue
		}
		pairs = append(pairs, pair)
	}
	if len(pairs) == 0 {
		return nil, false
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].loKey != pairs[j].loKey || math.IsNaN(pairs[i].sortLo) || math.IsNaN(pairs[j].sortLo) {
			if pairs[i].sortLo != pairs[j].sortLo {
				return pairs[i].sortLo < pairs[j].sortLo
			}
			if pairs[i].loKey != pairs[j].loKey {
				return pairs[i].loKey < pairs[j].loKey
			}
		}
		if pairs[i].sortHi != pairs[j].sortHi {
			return pairs[i].sortHi < pairs[j].sortHi
		}
		return pairs[i].hiKey < pairs[j].hiKey
	})
	if len(pairs) == 1 {
		return map[string]any{
			"gte": pairs[0].gte,
			"lte": pairs[0].lte,
		}, true
	}
	out := make([]any, len(pairs))
	for i, p := range pairs {
		out[i] = map[string]any{
			"gte": p.gte,
			"lte": p.lte,
		}
	}
	return out, true
}

func formatWholeSyntheticFloatNumber(f float64, isFloat32 bool) any {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	var s string
	if isFloat32 {
		s = strconv.FormatFloat(float64(float32(f)), 'f', -1, 32)
	} else {
		s = strconv.FormatFloat(f, 'f', -1, 64)
	}
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return json.Number(s)
}

func canonicalizeSingleSyntheticRange(item any, b FieldBinding, esType string) (canonicalRangePair, bool) {
	esType = strings.ToLower(strings.TrimSpace(esType))
	if strVal, isStr := item.(string); isStr {
		if esType == "ip_range" {
			trimmed := strings.TrimSpace(strVal)
			if pfx, err := netip.ParsePrefix(trimmed); err == nil {
				masked := pfx.Masked()
				loAddr := masked.Addr()
				hiAddr := lastAddrInPrefix(masked)
				loStr := formatCanonicalESIP(loAddr)
				hiStr := formatCanonicalESIP(hiAddr)
				return canonicalRangePair{
					gte:    loStr,
					lte:    hiStr,
					sortLo: ipSortFloat(loAddr),
					sortHi: ipSortFloat(hiAddr),
					loKey:  ipSortHexKey(loAddr),
					hiKey:  ipSortHexKey(hiAddr),
				}, true
			}
		}
		return canonicalRangePair{}, false
	}
	m, ok := item.(map[string]any)
	if !ok || len(m) == 0 {
		return canonicalRangePair{}, false
	}
	// Strip internal shredded keys `_r`, `_gte`, `_lte` if a mutated map was passed
	rawGte, hasGte := m["gte"]
	rawGt, hasGt := m["gt"]
	rawLte, hasLte := m["lte"]
	rawLt, hasLt := m["lt"]
	if (hasGte && rawGte != nil && hasGt && rawGt != nil) || (hasLte && rawLte != nil && hasLt && rawLt != nil) {
		return canonicalRangePair{}, false
	}
	// Verify no unknown user keys (ignoring internal `_r`, `_gte`, `_lte`)
	hasUserBound := false
	for k, v := range m {
		switch k {
		case "gte", "gt", "lte", "lt":
			if v != nil {
				hasUserBound = true
			}
		case "_r", "_gte", "_lte":
		default:
			return canonicalRangePair{}, false
		}
	}
	if !hasUserBound && !hasGte && !hasGt && !hasLte && !hasLt {
		return canonicalRangePair{}, false
	}

	switch esType {
	case "integer_range", "long_range":
		var minBound, maxBound int64
		if esType == "integer_range" {
			minBound, maxBound = math.MinInt32, math.MaxInt32
		} else {
			minBound, maxBound = math.MinInt64, math.MaxInt64
		}
		parseIntBound := func(v any) (int64, bool) {
			switch tv := v.(type) {
			case int:
				return int64(tv), true
			case int64:
				return tv, true
			case json.Number:
				if iv, err := tv.Int64(); err == nil {
					return iv, true
				}
				if fv, err := tv.Float64(); err == nil && fv == math.Trunc(fv) {
					return int64(fv), true
				}
			case float64:
				if tv == math.Trunc(tv) {
					return int64(tv), true
				}
			case string:
				if iv, err := strconv.ParseInt(strings.TrimSpace(tv), 10, 64); err == nil {
					return iv, true
				}
			}
			return 0, false
		}
		var loVal, hiVal any
		sortLo := float64(minBound) - 1
		sortHi := float64(maxBound) + 1
		var loInt, hiInt int64
		hasLo, hasHi := false, false
		if hasGte && rawGte != nil {
			iv, okP := parseIntBound(rawGte)
			if !okP || iv < minBound || iv > maxBound {
				return canonicalRangePair{}, false
			}
			loInt, hasLo = iv, true
		} else if hasGt && rawGt != nil {
			iv, okP := parseIntBound(rawGt)
			if !okP || iv < minBound || iv >= maxBound {
				return canonicalRangePair{}, false
			}
			loInt, hasLo = iv+1, true
		}
		if hasLte && rawLte != nil {
			iv, okP := parseIntBound(rawLte)
			if !okP || iv < minBound || iv > maxBound {
				return canonicalRangePair{}, false
			}
			hiInt, hasHi = iv, true
		} else if hasLt && rawLt != nil {
			iv, okP := parseIntBound(rawLt)
			if !okP || iv <= minBound || iv > maxBound {
				return canonicalRangePair{}, false
			}
			hiInt, hasHi = iv-1, true
		}
		if hasLo && hasHi && loInt > hiInt {
			return canonicalRangePair{}, false
		}
		if hasLo {
			loVal = loInt
			sortLo = float64(loInt)
		}
		if hasHi {
			hiVal = hiInt
			sortHi = float64(hiInt)
		}
		return canonicalRangePair{gte: loVal, lte: hiVal, sortLo: sortLo, sortHi: sortHi}, true

	case "float_range", "double_range":
		isF32 := esType == "float_range"
		var loVal, hiVal any
		sortLo := math.Inf(-1)
		sortHi := math.Inf(1)
		var loF, hiF float64
		hasLo, hasHi := false, false
		if hasGte && rawGte != nil {
			fv, okP := syntheticToFloat64(rawGte)
			if !okP || math.IsNaN(fv) {
				return canonicalRangePair{}, false
			}
			if isF32 {
				fv = float64(float32(fv))
			}
			loF, hasLo = fv, true
		} else if hasGt && rawGt != nil {
			fv, okP := syntheticToFloat64(rawGt)
			if !okP || math.IsNaN(fv) {
				return canonicalRangePair{}, false
			}
			if isF32 {
				fv = float64(math.Nextafter32(float32(fv), float32(math.Inf(1))))
			} else {
				fv = math.Nextafter(fv, math.Inf(1))
			}
			loF, hasLo = fv, true
		}
		if hasLte && rawLte != nil {
			fv, okP := syntheticToFloat64(rawLte)
			if !okP || math.IsNaN(fv) {
				return canonicalRangePair{}, false
			}
			if isF32 {
				fv = float64(float32(fv))
			}
			hiF, hasHi = fv, true
		} else if hasLt && rawLt != nil {
			fv, okP := syntheticToFloat64(rawLt)
			if !okP || math.IsNaN(fv) {
				return canonicalRangePair{}, false
			}
			if isF32 {
				fv = float64(math.Nextafter32(float32(fv), float32(math.Inf(-1))))
			} else {
				fv = math.Nextafter(fv, math.Inf(-1))
			}
			hiF, hasHi = fv, true
		}
		if hasLo && hasHi && loF > hiF {
			return canonicalRangePair{}, false
		}
		if hasLo && !math.IsInf(loF, -1) {
			loVal = formatWholeSyntheticFloatNumber(loF, isF32)
			sortLo = loF
		}
		if hasHi && !math.IsInf(hiF, 1) {
			hiVal = formatWholeSyntheticFloatNumber(hiF, isF32)
			sortHi = hiF
		}
		return canonicalRangePair{gte: loVal, lte: hiVal, sortLo: sortLo, sortHi: sortHi}, true

	case "date_range":
		parseDateMs := func(v any) (int64, bool) {
			switch tv := v.(type) {
			case int:
				return int64(tv), true
			case int64:
				return tv, true
			case json.Number:
				if iv, err := tv.Int64(); err == nil {
					return iv, true
				}
			case float64:
				if tv == math.Trunc(tv) {
					return int64(tv), true
				}
			case string:
				return ParseESDateBoundWithFormatToEpochMillis(tv, b.Format, time.Now().UTC(), false)
			}
			return 0, false
		}
		formatDateMs := func(ms int64) string {
			return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
		}
		var loVal, hiVal any
		sortLo := math.Inf(-1)
		sortHi := math.Inf(1)
		var loMs, hiMs int64
		hasLo, hasHi := false, false
		if hasGte && rawGte != nil {
			ms, okP := parseDateMs(rawGte)
			if !okP {
				return canonicalRangePair{}, false
			}
			loMs, hasLo = ms, true
		} else if hasGt && rawGt != nil {
			ms, okP := parseDateMs(rawGt)
			if !okP {
				return canonicalRangePair{}, false
			}
			loMs, hasLo = ms+1, true
		}
		if hasLte && rawLte != nil {
			ms, okP := parseDateMs(rawLte)
			if !okP {
				return canonicalRangePair{}, false
			}
			hiMs, hasHi = ms, true
		} else if hasLt && rawLt != nil {
			ms, okP := parseDateMs(rawLt)
			if !okP {
				return canonicalRangePair{}, false
			}
			hiMs, hasHi = ms-1, true
		}
		if hasLo && hasHi && loMs > hiMs {
			return canonicalRangePair{}, false
		}
		if hasLo {
			loVal = formatDateMs(loMs)
			sortLo = float64(loMs)
		}
		if hasHi {
			hiVal = formatDateMs(hiMs)
			sortHi = float64(hiMs)
		}
		return canonicalRangePair{gte: loVal, lte: hiVal, sortLo: sortLo, sortHi: sortHi}, true

	case "ip_range":
		parseAddr := func(v any) (netip.Addr, bool) {
			s, okS := v.(string)
			if !okS {
				return netip.Addr{}, false
			}
			addr, err := netip.ParseAddr(strings.TrimSpace(s))
			if err != nil {
				return netip.Addr{}, false
			}
			return addr.Unmap(), true
		}
		var loVal, hiVal any
		var loAddr, hiAddr netip.Addr
		hasLo, hasHi := false, false
		if hasGte && rawGte != nil {
			a, okP := parseAddr(rawGte)
			if !okP {
				return canonicalRangePair{}, false
			}
			loAddr, hasLo = a, true
		} else if hasGt && rawGt != nil {
			a, okP := parseAddr(rawGt)
			if !okP {
				return canonicalRangePair{}, false
			}
			next := a.Next()
			if !next.IsValid() {
				return canonicalRangePair{}, false
			}
			loAddr, hasLo = next, true
		}
		if hasLte && rawLte != nil {
			a, okP := parseAddr(rawLte)
			if !okP {
				return canonicalRangePair{}, false
			}
			hiAddr, hasHi = a, true
		} else if hasLt && rawLt != nil {
			a, okP := parseAddr(rawLt)
			if !okP {
				return canonicalRangePair{}, false
			}
			prev := a.Prev()
			if !prev.IsValid() {
				return canonicalRangePair{}, false
			}
			hiAddr, hasHi = prev, true
		}
		if hasLo && hasHi && compareIP128(loAddr, hiAddr) > 0 {
			return canonicalRangePair{}, false
		}
		var loKey, hiKey string
		if hasLo {
			loVal = formatCanonicalESIP(loAddr)
			loKey = ipSortHexKey(loAddr)
		} else {
			loVal = "::"
			loKey = ipSortHexKey(netip.IPv6Unspecified())
		}
		if hasHi {
			hiVal = formatCanonicalESIP(hiAddr)
			hiKey = ipSortHexKey(hiAddr)
		} else {
			maxIPv6 := netip.AddrFrom16([16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
			hiVal = formatCanonicalESIP(maxIPv6)
			hiKey = ipSortHexKey(maxIPv6)
		}
		return canonicalRangePair{
			gte:    loVal,
			lte:    hiVal,
			sortLo: 0,
			sortHi: 0,
			loKey:  loKey,
			hiKey:  hiKey,
		}, true
	}
	return canonicalRangePair{}, false
}

func lastAddrInPrefix(pfx netip.Prefix) netip.Addr {
	addr := pfx.Addr()
	if addr.Is4() {
		a4 := addr.As4()
		hostBits := 32 - pfx.Bits()
		if hostBits > 0 {
			val := binary.BigEndian.Uint32(a4[:])
			mask := uint32((uint64(1) << hostBits) - 1) // #nosec G115 -- hostBits is bounded to [1, 32] for IPv4 netip.Prefix
			val |= mask
			binary.BigEndian.PutUint32(a4[:], val)
		}
		return netip.AddrFrom4(a4)
	}
	a16 := addr.As16()
	bitsKeep := pfx.Bits()
	for byteIdx := 0; byteIdx < 16; byteIdx++ {
		bitStart := byteIdx * 8
		if bitStart >= bitsKeep {
			a16[byteIdx] = 0xff
		} else if bitStart+8 > bitsKeep {
			rem := 8 - (bitsKeep - bitStart)
			a16[byteIdx] |= byte((1 << rem) - 1)
		}
	}
	return netip.AddrFrom16(a16).Unmap()
}

func ipTo16Bytes(a netip.Addr) [16]byte {
	u := a.Unmap()
	if u.Is4() {
		a4 := u.As4()
		return [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a4[0], a4[1], a4[2], a4[3]}
	}
	return u.As16()
}

func compareIP128(a, b netip.Addr) int {
	ab := ipTo16Bytes(a)
	bb := ipTo16Bytes(b)
	return bytes.Compare(ab[:], bb[:])
}

func ipSortHexKey(a netip.Addr) string {
	b16 := ipTo16Bytes(a)
	return fmt.Sprintf("%x", b16[:])
}

func ipSortFloat(a netip.Addr) float64 {
	b16 := ipTo16Bytes(a)
	hi := binary.BigEndian.Uint64(b16[:8])
	return float64(hi)
}

func formatCanonicalESIP(a netip.Addr) string {
	return a.Unmap().String()
}

// IsValidTSDBDimensionFieldType reports whether `esType` can have `time_series_dimension: true`.
func IsValidTSDBDimensionFieldType(esType string) bool {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "keyword", "constant_keyword", "wildcard", "ip", "version",
		"byte", "short", "integer", "long", "unsigned_long",
		"boolean", "date", "date_nanos":
		return true
	default:
		return false
	}
}

// ValidateTSDBFieldParams validates `time_series_dimension`, `time_series_dimensions`, and `time_series_metric` on a field.
func ValidateTSDBFieldParams(fullPath, fType string, prop esast.FieldProperty) error {
	if prop.TimeSeriesDimension != nil && *prop.TimeSeriesDimension {
		if prop.Script != nil {
			return fmt.Errorf("mapper_parsing_exception: [time_series_dimension] cannot be set on field [%s] with [script]", fullPath)
		}
		if !IsValidTSDBDimensionFieldType(fType) {
			return fmt.Errorf("mapper_parsing_exception: Field [%s] of type [%s] cannot be a [time_series_dimension]", fullPath, fType)
		}
		if prop.TimeSeriesMetric != "" {
			return fmt.Errorf("mapper_parsing_exception: Field [%s] cannot be both a [time_series_dimension] and a [time_series_metric]", fullPath)
		}
	}
	if prop.TimeSeriesDimensions != nil {
		if fType != "flattened" {
			return fmt.Errorf("mapper_parsing_exception: [time_series_dimensions] is only supported on [flattened] fields, not [%s] on field [%s]", fType, fullPath)
		}
		if prop.Script != nil {
			return fmt.Errorf("mapper_parsing_exception: [time_series_dimensions] cannot be set on field [%s] with [script]", fullPath)
		}
	}
	if prop.TimeSeriesMetric != "" {
		tsm := strings.ToLower(strings.TrimSpace(prop.TimeSeriesMetric))
		switch tsm {
		case "counter":
			switch fType {
			case "byte", "short", "integer", "long", "unsigned_long", "half_float", "float", "double", "scaled_float":
			default:
				return fmt.Errorf("mapper_parsing_exception: [time_series_metric: counter] is not supported on [%s] field [%s]", fType, fullPath)
			}
		case "gauge":
			switch fType {
			case "byte", "short", "integer", "long", "unsigned_long", "half_float", "float", "double", "scaled_float", "summary":
			default:
				return fmt.Errorf("mapper_parsing_exception: [time_series_metric: gauge] is not supported on [%s] field [%s]", fType, fullPath)
			}
		case "position":
			if fType != "geo_point" {
				return fmt.Errorf("mapper_parsing_exception: [time_series_metric: position] is only supported on [geo_point] fields, got [%s] on [%s]", fType, fullPath)
			}
		case "summary", "histogram":
		default:
			return fmt.Errorf("mapper_parsing_exception: unknown [time_series_metric] [%s] on field [%s]", prop.TimeSeriesMetric, fullPath)
		}
	}
	return nil
}

// ExtractTSDBSettings extracts and validates `index.mode`, `index.routing_path`, `index.time_series.start_time`, and `index.time_series.end_time`.
func ExtractTSDBSettings(settings map[string]any) (mode string, routingPath []string, startTime string, endTime string, err error) {
	if len(settings) == 0 {
		return "", nil, "", "", nil
	}
	lookup := func(keys ...string) (any, bool) {
		for _, k := range keys {
			if v, ok := settings[k]; ok && v != nil {
				return v, true
			}
			// Nested walk
			parts := strings.Split(k, ".")
			var curr any = settings
			found := true
			for _, p := range parts {
				m, okM := curr.(map[string]any)
				if !okM {
					found = false
					break
				}
				if nxt, okN := m[p]; okN {
					curr = nxt
				} else {
					// Check dotted sub-key inside map (e.g. settings["index"]["time_series.start_time"])
					found = false
					break
				}
			}
			if found && curr != nil {
				return curr, true
			}
			if idxMap, okIdx := settings["index"].(map[string]any); okIdx {
				trimmedKey := strings.TrimPrefix(k, "index.")
				if v, okD := idxMap[trimmedKey]; okD && v != nil {
					return v, true
				}
			}
		}
		return nil, false
	}

	if rawMode, ok := lookup("index.mode", "mode"); ok {
		mode = strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", rawMode)))
	}
	if rawRP, ok := lookup("index.routing_path", "routing_path"); ok {
		switch tv := rawRP.(type) {
		case string:
			for _, p := range strings.Split(tv, ",") {
				if p = strings.TrimSpace(p); p != "" {
					routingPath = append(routingPath, p)
				}
			}
		case []string:
			for _, p := range tv {
				if p = strings.TrimSpace(p); p != "" {
					routingPath = append(routingPath, p)
				}
			}
		case []any:
			for _, item := range tv {
				if p := strings.TrimSpace(fmt.Sprintf("%v", item)); p != "" {
					routingPath = append(routingPath, p)
				}
			}
		}
	}
	if rawStart, ok := lookup("index.time_series.start_time", "time_series.start_time"); ok {
		startTime = strings.TrimSpace(fmt.Sprintf("%v", rawStart))
	}
	if rawEnd, ok := lookup("index.time_series.end_time", "time_series.end_time"); ok {
		endTime = strings.TrimSpace(fmt.Sprintf("%v", rawEnd))
	}
	if mode == "time_series" {
		if startTime != "" && endTime != "" {
			sMs, okS := ParseESDateToEpochMillis(startTime, time.Now().UTC())
			eMs, okE := ParseESDateToEpochMillis(endTime, time.Now().UTC())
			if !okS {
				return mode, routingPath, startTime, endTime, fmt.Errorf("illegal_argument_exception: failed to parse [index.time_series.start_time] [%s]", startTime)
			}
			if !okE {
				return mode, routingPath, startTime, endTime, fmt.Errorf("illegal_argument_exception: failed to parse [index.time_series.end_time] [%s]", endTime)
			}
			if sMs >= eMs {
				return mode, routingPath, startTime, endTime, fmt.Errorf("illegal_argument_exception: [index.time_series.start_time] [%s] must be before [index.time_series.end_time] [%s]", startTime, endTime)
			}
		}
	}
	return mode, routingPath, startTime, endTime, nil
}

func matchTSDBRoutingGlob(pattern, fieldPath string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == fieldPath {
		return true
	}
	var sb strings.Builder
	sb.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				sb.WriteString(".*")
				i++
			} else {
				sb.WriteString(`[^.]*`)
			}
		case '?':
			sb.WriteString(`[^.]`)
		default:
			sb.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	sb.WriteByte('$')
	re, err := regexp.Compile(sb.String())
	if err != nil {
		return false
	}
	return re.MatchString(fieldPath)
}

func matchesAnyTSDBRoutingPath(routingPath []string, fieldPath string) bool {
	for _, rp := range routingPath {
		if matchTSDBRoutingGlob(rp, fieldPath) {
			return true
		}
	}
	return false
}

// ValidateTSDBMapping validates that every mapped field matching `routing_path` is a valid TSDB dimension (`140_routing_path.yml:97`).
func ValidateTSDBMapping(m *esast.MappingSpec, routingPath []string) error {
	if m == nil || len(routingPath) == 0 {
		return nil
	}
	var walk func(props map[string]esast.FieldProperty, prefix string) error
	walk = func(props map[string]esast.FieldProperty, prefix string) error {
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			prop := props[k]
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			fType := strings.ToLower(strings.TrimSpace(prop.Type))
			isObj := len(prop.Properties) > 0 || fType == "object" || fType == "nested" || fType == ""
			if isObj {
				if err := walk(prop.Properties, full); err != nil {
					return err
				}
				continue
			}
			if fType == "flattened" {
				for _, rp := range routingPath {
					if rp == full || strings.HasPrefix(rp, full+".") || matchTSDBRoutingGlob(rp, full) {
						if prop.Script != nil || prop.TimeSeriesDimensions == nil {
							return esWireError(fmt.Sprintf(
								"illegal_argument_exception: All fields that match routing_path must be configured with [time_series_dimension: true] or flattened fields with a list of dimensions in [time_series_dimensions] and without the [script] parameter. [%s] was not a dimension.",
								full,
							))
						}
						if strings.HasPrefix(rp, full+".") {
							sub := strings.TrimPrefix(rp, full+".")
							found := false
							for _, d := range prop.TimeSeriesDimensions {
								if d == sub || matchTSDBRoutingGlob(sub, d) {
									found = true
									break
								}
							}
							if !found {
								return esWireError(fmt.Sprintf(
									"illegal_argument_exception: All fields that match routing_path must be configured with [time_series_dimension: true] or flattened fields with a list of dimensions in [time_series_dimensions] and without the [script] parameter. [%s] was not a dimension.",
									rp,
								))
							}
						}
					}
				}
				continue
			}
			if matchesAnyTSDBRoutingPath(routingPath, full) {
				isDim := prop.TimeSeriesDimension != nil && *prop.TimeSeriesDimension && prop.Script == nil
				if !isDim {
					return esWireError(fmt.Sprintf(
						"illegal_argument_exception: All fields that match routing_path must be configured with [time_series_dimension: true] or flattened fields with a list of dimensions in [time_series_dimensions] and without the [script] parameter. [%s] was not a dimension.",
						full,
					))
				}
			}
		}
		return nil
	}
	return walk(m.Properties, "")
}

type esWireError string

func (e esWireError) Error() string { return string(e) }

// ValidateTSDBDocID validates that `id` is a valid 20-byte base64url synthetic TSDB document ID (`25_id_generation.yml:383`).
func ValidateTSDBDocID(id, indexName string) error {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(raw) != 20 || base64.RawURLEncoding.EncodeToString(raw) != id {
		return fmt.Errorf("illegal_argument_exception: invalid id [%s] for index [%s] in time series mode", id, indexName)
	}
	return nil
}

type tsdbDimensionEntry struct {
	name  string
	canon string
}

// ComputeTSDBIdentity validates `@timestamp` bounds, extracts TSDB dimensions & routing fields,
// and computes deterministic `(_tsid, _id, routingKey)` for a TSDB document.
func ComputeTSDBIdentity(idx *IndexSchema, doc map[string]any, settings map[string]any) (tsid string, docID string, routingKey string, err error) {
	tsid, docID, routingKey, _, err = ComputeTSDBIdentityWithRoutingHash(idx, doc, settings)
	return tsid, docID, routingKey, err
}

// ComputeTSDBIdentityWithRoutingHash returns `(_tsid, _id, routingKey, _ts_routing_hash, error)` for a TSDB document.
func ComputeTSDBIdentityWithRoutingHash(idx *IndexSchema, doc map[string]any, settings map[string]any) (tsid string, docID string, routingKey string, routingHash string, err error) {
	if doc == nil {
		return "", "", "", "", fmt.Errorf("mapper_parsing_exception: document cannot be null in time_series mode")
	}
	var routingPath []string
	var startStr, endStr string
	if settings != nil {
		_, rp, st, et, sErr := ExtractTSDBSettings(settings)
		if sErr != nil {
			return "", "", "", "", sErr
		}
		routingPath = rp
		startStr = st
		endStr = et
	}
	if idx != nil {
		if len(routingPath) == 0 && len(idx.RoutingPath) > 0 {
			routingPath = idx.RoutingPath
		}
		if startStr == "" {
			startStr = idx.TimeSeriesStartTime
		}
		if endStr == "" {
			endStr = idx.TimeSeriesEndTime
		}
	}

	// 1. Extract and validate `@timestamp` (`[start_time, end_time)` half-open interval).
	rawTS, hasTS := extractSingleDocPathValue(doc, []string{"@timestamp"})
	if !hasTS || rawTS == nil {
		return "", "", "", "", fmt.Errorf("mapper_parsing_exception: required [@timestamp] is missing in time_series mode")
	}
	if _, isArr := rawTS.([]any); isArr {
		return "", "", "", "", fmt.Errorf("mapper_parsing_exception: [@timestamp] cannot be multi-valued in time_series mode")
	}
	tsFormat := ""
	tsType := "date"
	if idx != nil {
		if b, ok := idx.Fields["@timestamp"]; ok {
			tsFormat = b.Format
			if b.ESType != "" {
				tsType = strings.ToLower(strings.TrimSpace(b.ESType))
			}
		}
	}
	tsMs, okTS := parseTSDBTimestampMillis(rawTS, tsType, tsFormat)
	if !okTS {
		return "", "", "", "", fmt.Errorf("mapper_parsing_exception: failed to parse field [@timestamp] of type [%s] in document", tsType)
	}
	nowUTC := time.Now().UTC()
	if startStr != "" {
		if sMs, okS := ParseESDateToEpochMillis(startStr, nowUTC); okS && tsMs < sMs {
			return "", "", "", "", fmt.Errorf(
				"mapper_parsing_exception: [@timestamp] [%d] is before [index.time_series.start_time] [%s]",
				tsMs, startStr,
			)
		}
	}
	if endStr != "" {
		if eMs, okE := ParseESDateToEpochMillis(endStr, nowUTC); okE && tsMs >= eMs {
			return "", "", "", "", fmt.Errorf(
				"mapper_parsing_exception: [@timestamp] [%d] is on or after [index.time_series.end_time] [%s]",
				tsMs, endStr,
			)
		}
	}

	// 2. Collect dimensions from schema (`FieldBinding` + `RawMapping`).
	dims, dimErr := extractTSDBDimensionsFromDoc(idx, doc)
	if dimErr != nil {
		return "", "", "", "", dimErr
	}
	if len(dims) == 0 {
		return "", "", "", "", fmt.Errorf("mapper_parsing_exception: document in time_series mode must contain at least one time_series_dimension")
	}
	sort.Slice(dims, func(i, j int) bool {
		return dims[i].name < dims[j].name
	})

	// 3. Extract routing key from `routing_path` (or default to all dimension fields if `routing_path` is empty).
	var routingPairs []string
	if len(routingPath) > 0 {
		if err := extractTSDBRoutingPairs(idx, doc, routingPath, &routingPairs); err != nil {
			return "", "", "", "", err
		}
		if len(routingPairs) == 0 {
			return "", "", "", "", fmt.Errorf("illegal_argument_exception: Error extracting routing: source didn't contain any routing fields")
		}
	} else {
		for _, d := range dims {
			routingPairs = append(routingPairs, d.name+"="+d.canon)
		}
	}
	sort.Strings(routingPairs)
	routingKey = strings.Join(routingPairs, ",")

	// 4. Encode `_tsid` (`1 + 16 + 4*N + 16` bytes -> RawURLEncoding) and 20-byte `_id` (`4B routing_hash + 8B tsid_hash + 8B big-endian timestamp`).
	tsidBytes := buildTSIDBytes(dims)
	tsid = base64.RawURLEncoding.EncodeToString(tsidBytes)

	rHash32 := murmur3X86_32Bytes([]byte(routingKey), 0)
	var rHashBytes [4]byte
	binary.BigEndian.PutUint32(rHashBytes[:], rHash32)
	routingHash = base64.RawURLEncoding.EncodeToString(rHashBytes[:])

	tsidH1, _ := murmur3X64_128Bytes(tsidBytes, 0)
	var idBytes [20]byte
	copy(idBytes[0:4], rHashBytes[:])
	binary.LittleEndian.PutUint64(idBytes[4:12], tsidH1)
	binary.BigEndian.PutUint64(idBytes[12:20], uint64(tsMs)) // #nosec G115 -- signed epoch ms encoded big-endian per ES TSDB format
	docID = base64.RawURLEncoding.EncodeToString(idBytes[:])
	return tsid, docID, routingKey, routingHash, nil
}

func parseTSDBTimestampMillis(raw any, tsType, format string) (int64, bool) {
	switch v := raw.(type) {
	case int:
		return int64(v), true
	case int64:
		if tsType == "date_nanos" && (v > 1e15 || v < -1e15) {
			return v / 1_000_000, true
		}
		return v, true
	case json.Number:
		if iv, err := v.Int64(); err == nil {
			if tsType == "date_nanos" && (iv > 1e15 || iv < -1e15) {
				return iv / 1_000_000, true
			}
			return iv, true
		}
		if fv, err := v.Float64(); err == nil && !math.IsNaN(fv) && !math.IsInf(fv, 0) {
			return int64(math.Round(fv)), true
		}
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			return int64(math.Round(v)), true
		}
	case string:
		if tsType == "date_nanos" {
			if ns, ok := ParseESDateWithFormatToEpochNanos(v, format, time.Now().UTC()); ok {
				return ns / 1_000_000, true
			}
		}
		return ParseESDateWithFormatToEpochMillis(v, format, time.Now().UTC())
	}
	return 0, false
}

func extractSingleDocPathValue(node any, parts []string) (any, bool) {
	if len(parts) == 0 || node == nil {
		return node, node != nil
	}
	m, ok := node.(map[string]any)
	if !ok {
		return nil, false
	}
	if v, exists := m[parts[0]]; exists {
		if len(parts) == 1 {
			return v, true
		}
		return extractSingleDocPathValue(v, parts[1:])
	}
	if len(parts) < 2 {
		return nil, false
	}
	if v, exists := m[strings.Join(parts, ".")]; exists {
		return v, true
	}
	for idx := len(parts) - 1; idx >= 2; idx-- {
		if idx >= 0 && idx < len(parts) {
			joined := strings.Join(parts[:idx], ".") // #nosec G602 -- 2 <= idx < len(parts) guarded above
			if v, exists := m[joined]; exists {
				return extractSingleDocPathValue(v, parts[idx:]) // #nosec G602 -- 2 <= idx < len(parts) guarded above
			}
		}
	}
	return nil, false
}

func extractTSDBDimensionsFromDoc(idx *IndexSchema, doc map[string]any) ([]tsdbDimensionEntry, error) {
	var out []tsdbDimensionEntry
	seen := make(map[string]bool)
	if idx == nil {
		return nil, nil
	}

	// Check compiled FieldBindings first
	fieldKeys := make([]string, 0, len(idx.Fields))
	for k := range idx.Fields {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)
	for _, k := range fieldKeys {
		b := idx.Fields[k]
		if b.AliasTarget != "" || strings.HasSuffix(k, ".keyword") {
			continue
		}
		if b.TimeSeriesDimension != nil && *b.TimeSeriesDimension {
			if strings.EqualFold(b.ESType, "constant_keyword") && b.HasConstantValue && b.ConstantValue != nil {
				rawVal, present := extractSingleDocPathValue(doc, strings.Split(k, "."))
				if present && rawVal != nil {
					canon, err := canonicalizeTSDBDimensionScalar(k, b, rawVal)
					if err != nil {
						return nil, err
					}
					if !seen[k] {
						seen[k] = true
						out = append(out, tsdbDimensionEntry{name: k, canon: canon})
					}
				} else if !seen[k] {
					seen[k] = true
					out = append(out, tsdbDimensionEntry{name: k, canon: fmt.Sprintf("%v", b.ConstantValue)})
				}
				continue
			}
			rawVal, present := extractSingleDocPathValue(doc, strings.Split(k, "."))
			if !present || rawVal == nil {
				continue
			}
			canon, err := canonicalizeTSDBDimensionScalar(k, b, rawVal)
			if err != nil {
				return nil, err
			}
			if !seen[k] {
				seen[k] = true
				out = append(out, tsdbDimensionEntry{name: k, canon: canon})
			}
		}
		if strings.EqualFold(b.ESType, "flattened") && len(b.TimeSeriesDimensions) > 0 {
			rawFlat, present := extractSingleDocPathValue(doc, strings.Split(k, "."))
			if !present || rawFlat == nil {
				continue
			}
			flatMap, okM := rawFlat.(map[string]any)
			if !okM {
				continue
			}
			for _, subDim := range b.TimeSeriesDimensions {
				subVal, hasSub := extractSingleDocPathValue(flatMap, strings.Split(subDim, "."))
				if !hasSub || subVal == nil {
					continue
				}
				fullName := k + "." + subDim
				canon, err := canonicalizeTSDBDimensionScalar(fullName, FieldBinding{ESFieldPath: fullName, ESType: "keyword"}, subVal)
				if err != nil {
					return nil, err
				}
				if !seen[fullName] {
					seen[fullName] = true
					out = append(out, tsdbDimensionEntry{name: fullName, canon: canon})
				}
			}
		}
	}
	return out, nil
}

func canonicalizeTSDBDimensionScalar(fieldName string, b FieldBinding, raw any) (string, error) {
	if arr, isArr := raw.([]any); isArr {
		if len(arr) == 1 {
			return canonicalizeTSDBDimensionScalar(fieldName, b, arr[0])
		}
		return "", fmt.Errorf("mapper_parsing_exception: time_series_dimension field [%s] does not accept arrays with multiple values", fieldName)
	}
	if _, isMap := raw.(map[string]any); isMap {
		return "", fmt.Errorf("mapper_parsing_exception: time_series_dimension field [%s] must be a scalar value", fieldName)
	}
	esType := strings.ToLower(strings.TrimSpace(b.ESType))
	switch esType {
	case "long", "integer", "short", "byte":
		switch v := raw.(type) {
		case int:
			return strconv.FormatInt(int64(v), 10), nil
		case int64:
			return strconv.FormatInt(v, 10), nil
		case json.Number:
			if iv, err := v.Int64(); err == nil {
				return strconv.FormatInt(iv, 10), nil
			}
			if fv, err := v.Float64(); err == nil && fv == math.Trunc(fv) {
				return strconv.FormatInt(int64(fv), 10), nil
			}
		case float64:
			if v == math.Trunc(v) {
				return strconv.FormatInt(int64(v), 10), nil
			}
		case string:
			trimmed := strings.TrimSpace(v)
			if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
				return strconv.FormatInt(iv, 10), nil
			}
			if fv, err := strconv.ParseFloat(trimmed, 64); err == nil && fv == math.Trunc(fv) {
				return strconv.FormatInt(int64(fv), 10), nil
			}
		}
		return "", fmt.Errorf("mapper_parsing_exception: failed to parse dimension field [%s] of type [%s]", fieldName, esType)
	case "unsigned_long":
		trimmed := strings.TrimSpace(fmt.Sprintf("%v", raw))
		u, err := strconv.ParseUint(trimmed, 10, 64)
		if err != nil {
			return "", fmt.Errorf("mapper_parsing_exception: failed to parse dimension field [%s] of type [unsigned_long]", fieldName)
		}
		return strconv.FormatUint(u, 10), nil
	case "ip":
		s := strings.TrimSpace(fmt.Sprintf("%v", raw))
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return "", fmt.Errorf("mapper_parsing_exception: failed to parse ip dimension field [%s]: [%s]", fieldName, s)
		}
		return addr.Unmap().String(), nil
	case "boolean":
		switch v := raw.(type) {
		case bool:
			return strconv.FormatBool(v), nil
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true":
				return "true", nil
			case "false":
				return "false", nil
			}
		}
		return "", fmt.Errorf("mapper_parsing_exception: failed to parse boolean dimension field [%s]", fieldName)
	case "date", "date_nanos":
		ms, ok := parseTSDBTimestampMillis(raw, esType, b.Format)
		if !ok {
			return "", fmt.Errorf("mapper_parsing_exception: failed to parse date dimension field [%s]", fieldName)
		}
		return strconv.FormatInt(ms, 10), nil
	default:
		s := fmt.Sprintf("%v", raw)
		if b.LowercaseNormalizer {
			s = strings.ToLower(s)
		}
		return s, nil
	}
}

func extractTSDBRoutingPairs(idx *IndexSchema, doc map[string]any, routingPath []string, dst *[]string) error {
	var walk func(curr map[string]any, prefix string) error
	walk = func(curr map[string]any, prefix string) error {
		keys := make([]string, 0, len(curr))
		for k := range curr {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := curr[k]
			if val == nil {
				continue
			}
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			if subMap, isMap := val.(map[string]any); isMap {
				if err := walk(subMap, full); err != nil {
					return err
				}
				continue
			}
			if matchesAnyTSDBRoutingPath(routingPath, full) {
				if _, isArr := val.([]any); isArr {
					return fmt.Errorf("illegal_argument_exception: Error extracting routing: Routing values must be strings but found [START_ARRAY]")
				}
				var b FieldBinding
				if idx != nil {
					b = idx.Fields[full]
				}
				canon, err := canonicalizeTSDBDimensionScalar(full, b, val)
				if err != nil {
					return err
				}
				*dst = append(*dst, full+"="+canon)
			}
		}
		return nil
	}
	expanded := expandDottedKeysForSyntheticObject(idx, doc, "")
	return walk(expanded, "")
}

func buildTSIDBytes(dims []tsdbDimensionEntry) []byte {
	n := len(dims)
	bodyLen := 16 + 4*n + 16
	var out []byte
	// VInt prefix for bodyLen
	v := bodyLen
	for v >= 0x80 {
		out = append(out, byte((v&0x7f)|0x80)) // #nosec G115 -- masked to 8-bit VInt continuation byte
		v >>= 7
	}
	out = append(out, byte(v))

	var namesBuf bytes.Buffer
	var valsBuf bytes.Buffer
	valHashes := make([]byte, 0, 4*n)
	for _, d := range dims {
		namesBuf.WriteString(d.name)
		namesBuf.WriteByte(0)
		valsBuf.WriteString(d.canon)
		valsBuf.WriteByte(0)
		vh := murmur3X86_32Bytes([]byte(d.canon), 0)
		var b4 [4]byte
		binary.LittleEndian.PutUint32(b4[:], vh)
		valHashes = append(valHashes, b4[:]...)
	}
	nh1, nh2 := murmur3X64_128Bytes(namesBuf.Bytes(), 0)
	var name16 [16]byte
	binary.LittleEndian.PutUint64(name16[0:8], nh1)
	binary.LittleEndian.PutUint64(name16[8:16], nh2)
	out = append(out, name16[:]...)
	out = append(out, valHashes...)

	vh1, vh2 := murmur3X64_128Bytes(valsBuf.Bytes(), 0)
	var val16 [16]byte
	binary.LittleEndian.PutUint64(val16[0:8], vh1)
	binary.LittleEndian.PutUint64(val16[8:16], vh2)
	out = append(out, val16[:]...)
	return out
}

func murmur3X86_32Bytes(data []byte, seed uint32) uint32 {
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593
	h1 := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4:])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(len(data)) // #nosec G115
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

func murmur3fmix64(k uint64) uint64 {
	k ^= k >> 33
	k *= 0xff51afd7ed558ccd
	k ^= k >> 33
	k *= 0xc4ceb9fe1a85ec53
	k ^= k >> 33
	return k
}

func murmur3X64_128Bytes(data []byte, seed uint64) (uint64, uint64) {
	const c1 uint64 = 0x87c37b91114253d5
	const c2 uint64 = 0x4cf5ad432745937f
	h1 := seed
	h2 := seed
	nblocks := len(data) / 16
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint64(data[i*16:])
		k2 := binary.LittleEndian.Uint64(data[i*16+8:])
		k1 *= c1
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2
		h1 ^= k1
		h1 = bits.RotateLeft64(h1, 27)
		h1 += h2
		h1 = h1*5 + 0x52dce729

		k2 *= c2
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1
		h2 ^= k2
		h2 = bits.RotateLeft64(h2, 31)
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	}
	tail := data[nblocks*16:]
	var k1, k2 uint64
	for idx := len(tail) - 1; idx >= 0; idx-- {
		if idx >= 8 {
			k2 = (k2 << 8) | uint64(tail[idx])
		} else {
			k1 = (k1 << 8) | uint64(tail[idx])
		}
	}
	if len(tail) > 8 {
		k2 *= c2
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1
		h2 ^= k2
	}
	if len(tail) > 0 {
		k1 *= c1
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2
		h1 ^= k1
	}
	length := uint64(len(data))
	h1 ^= length
	h2 ^= length
	h1 += h2
	h2 += h1
	h1 = murmur3fmix64(h1)
	h2 = murmur3fmix64(h2)
	h1 += h2
	h2 += h1
	return h1, h2
}
