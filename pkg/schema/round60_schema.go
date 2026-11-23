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
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

// SourceConfig models the `_source` meta-field configuration on an Elasticsearch index mapping.
type SourceConfig struct {
	Mode              string   `json:"mode,omitempty"`
	Enabled           *bool    `json:"enabled,omitempty"`
	Includes          []string `json:"includes,omitempty"`
	Excludes          []string `json:"excludes,omitempty"`
	Compress          *bool    `json:"compress,omitempty"`
	CompressThreshold string   `json:"compress_threshold,omitempty"`
}

func boolPtrSchema(v bool) *bool {
	return &v
}

// ParseSourceConfig validates and normalizes a raw `_source` mapping map into a *SourceConfig.
func ParseSourceConfig(src map[string]any) (*SourceConfig, error) {
	norm, err := validateAndNormalizeMappingSourceSpec(src)
	if err != nil {
		return nil, err
	}
	cfg := &SourceConfig{
		Mode:              norm.mode,
		Enabled:           boolPtrSchema(norm.enabled),
		Includes:          append([]string(nil), norm.includes...),
		Excludes:          append([]string(nil), norm.excludes...),
		CompressThreshold: norm.compressThreshold,
	}
	if norm.hasCompress {
		cfg.Compress = boolPtrSchema(norm.compress)
	}
	return cfg, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneCompletionContexts(in []esast.CompletionContextDef) []esast.CompletionContextDef {
	if len(in) == 0 {
		return nil
	}
	out := make([]esast.CompletionContextDef, len(in))
	copy(out, in)
	return out
}

func completionContextsEqual(a, b []esast.CompletionContextDef) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || !strings.EqualFold(a[i].Type, b[i].Type) || a[i].Path != b[i].Path {
			return false
		}
		if fmt.Sprintf("%v", a[i].Precision) != fmt.Sprintf("%v", b[i].Precision) {
			return false
		}
		if fmt.Sprintf("%v", a[i].Default) != fmt.Sprintf("%v", b[i].Default) {
			return false
		}
	}
	return true
}

func validateCompletionContextsMapping(fullPath, fType string, contexts []esast.CompletionContextDef) error {
	if len(contexts) == 0 {
		return nil
	}
	if fType != "completion" {
		return fmt.Errorf("mapper_parsing_exception: Mapping definition for [%s] has unsupported parameters: [contexts]", fullPath)
	}
	seen := make(map[string]bool, len(contexts))
	for _, c := range contexts {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return fmt.Errorf("mapper_parsing_exception: completion context [name] is required on field [%s]", fullPath)
		}
		if seen[name] {
			return fmt.Errorf("mapper_parsing_exception: duplicate completion context [%s] on field [%s]", name, fullPath)
		}
		seen[name] = true
		ct := strings.ToLower(strings.TrimSpace(c.Type))
		if ct != "category" && ct != "geo" {
			return fmt.Errorf("mapper_parsing_exception: unsupported completion context type [%s] on field [%s]; must be [category] or [geo]", c.Type, fullPath)
		}
	}
	return nil
}

// ValidateEmptyPropertyNames rejects empty field names `""` or empty dotted segments (`.a`, `a.`, `a..b`).
func ValidateEmptyPropertyNames(props map[string]esast.FieldProperty) error {
	for k, prop := range props {
		if k == "" || strings.TrimSpace(k) == "" {
			return fmt.Errorf("mapper_parsing_exception: Field name cannot be an empty string")
		}
		if strings.Contains(k, ".") {
			for _, seg := range strings.Split(k, ".") {
				if seg == "" {
					return fmt.Errorf("mapper_parsing_exception: Field name cannot be an empty string")
				}
			}
		}
		for fk := range prop.Fields {
			if fk == "" || strings.TrimSpace(fk) == "" {
				return fmt.Errorf("mapper_parsing_exception: Field name cannot be an empty string")
			}
		}
		if len(prop.Properties) > 0 {
			if err := ValidateEmptyPropertyNames(prop.Properties); err != nil {
				return err
			}
		}
	}
	return nil
}

// ExpandDottedProperties recursively expands dotted keys in `properties` (e.g. `"subfield.text3": {"type": "text"}`)
// into nested `object` `Properties` maps (`{"subfield": {"properties": {"text3": {"type": "text"}}}}`),
// rejecting empty field names while respecting `subobjects: false` and scalar+dotted coexistence.
func ExpandDottedProperties(props map[string]esast.FieldProperty) (map[string]esast.FieldProperty, error) {
	return ExpandDottedPropertiesWithSubobjects(props, false)
}

// ExpandDottedPropertiesWithSubobjects expands dotted property keys when `subobjectsFalse` is false.
func ExpandDottedPropertiesWithSubobjects(props map[string]esast.FieldProperty, subobjectsFalse bool) (map[string]esast.FieldProperty, error) {
	return expandDottedPropertiesWithBase(props, nil, subobjectsFalse)
}

func expandDottedPropertiesWithBase(props, base map[string]esast.FieldProperty, subobjectsFalse bool) (map[string]esast.FieldProperty, error) {
	if len(props) == 0 {
		return props, nil
	}
	if err := ValidateEmptyPropertyNames(props); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(props))
	hasDots := false
	for k, prop := range props {
		keys = append(keys, k)
		if strings.Contains(k, ".") || len(prop.Properties) > 0 {
			hasDots = true
		}
	}
	if !hasDots {
		return props, nil
	}
	// Process non-dotted keys first in sorted order, then dotted keys in sorted order for determinism.
	sort.Slice(keys, func(i, j int) bool {
		di := strings.Contains(keys[i], ".")
		dj := strings.Contains(keys[j], ".")
		if di != dj {
			return !di
		}
		return keys[i] < keys[j]
	})

	out := make(map[string]esast.FieldProperty, len(props))
	for _, k := range keys {
		prop := props[k]
		if len(prop.Properties) > 0 {
			isPassthrough := strings.EqualFold(strings.TrimSpace(prop.Type), "passthrough")
			childSubFalse := subobjectsFalse || isPassthrough || (prop.Subobjects != nil && !*prop.Subobjects)
			if !childSubFalse && base != nil {
				if bProp, ok := base[k]; ok && ((bProp.Subobjects != nil && !*bProp.Subobjects) || strings.EqualFold(strings.TrimSpace(bProp.Type), "passthrough")) {
					childSubFalse = true
				}
			}
			expSub, err := expandDottedPropertiesWithBase(prop.Properties, nil, childSubFalse)
			if err != nil {
				return nil, err
			}
			if isPassthrough {
				expSub = flattenPassthroughSubobjectProps(expSub)
			}
			prop.Properties = expSub
		}
		if subobjectsFalse || !strings.Contains(k, ".") {
			if existing, ok := out[k]; ok {
				if err := checkObjectMergeConflict(k, existing, prop); err != nil {
					return nil, err
				}
				mergedMap := deepMergeMappingPropertiesWithSubobjects(
					map[string]esast.FieldProperty{k: existing},
					map[string]esast.FieldProperty{k: prop},
					subobjectsFalse,
				)
				out[k] = mergedMap[k]
			} else {
				out[k] = prop
			}
			continue
		}
		dotIdx := strings.IndexByte(k, '.')
		head := k[:dotIdx]
		tail := k[dotIdx+1:]
		childSubFalse := false
		if existing, ok := out[head]; ok {
			existingType := strings.ToLower(strings.TrimSpace(existing.Type))
			if existingType != "" && existingType != "object" && existingType != "nested" {
				// Preserve flat dotted key when head is an explicit scalar/leaf field.
				out[k] = prop
				continue
			}
			if existing.Subobjects != nil && !*existing.Subobjects {
				childSubFalse = true
			}
		} else if base != nil {
			if bProp, ok := base[head]; ok {
				bType := strings.ToLower(strings.TrimSpace(bProp.Type))
				if bType != "" && bType != "object" && bType != "nested" {
					out[k] = prop
					continue
				}
				if bProp.Subobjects != nil && !*bProp.Subobjects {
					childSubFalse = true
				}
			}
		}
		expandedTail, err := expandDottedPropertiesWithBase(map[string]esast.FieldProperty{tail: prop}, nil, childSubFalse)
		if err != nil {
			return nil, err
		}
		wrapper := esast.FieldProperty{
			Properties: expandedTail,
		}
		if existing, ok := out[head]; ok {
			if err := checkObjectMergeConflict(head, existing, wrapper); err != nil {
				return nil, err
			}
			mergedMap := deepMergeMappingPropertiesWithSubobjects(
				map[string]esast.FieldProperty{head: existing},
				map[string]esast.FieldProperty{head: wrapper},
				false,
			)
			out[head] = mergedMap[head]
		} else {
			out[head] = wrapper
		}
	}
	return out, nil
}

func flattenPassthroughSubobjectProps(props map[string]esast.FieldProperty) map[string]esast.FieldProperty {
	if len(props) == 0 {
		return props
	}
	out := make(map[string]esast.FieldProperty, len(props))
	var walk func(m map[string]esast.FieldProperty, prefix string)
	walk = func(m map[string]esast.FieldProperty, prefix string) {
		for k, p := range m {
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			ft := strings.ToLower(strings.TrimSpace(p.Type))
			if len(p.Properties) > 0 && (ft == "" || ft == "object") {
				walk(p.Properties, full)
				continue
			}
			out[full] = p
		}
	}
	walk(props, "")
	return out
}

func checkObjectMergeConflict(fieldName string, a, b esast.FieldProperty) error {
	aHasProps := len(a.Properties) > 0
	bHasProps := len(b.Properties) > 0
	aType := strings.ToLower(strings.TrimSpace(a.Type))
	bType := strings.ToLower(strings.TrimSpace(b.Type))
	if bHasProps && aType != "" && aType != "object" && aType != "nested" && aType != "passthrough" {
		return fmt.Errorf("illegal_argument_exception: Can't merge a non object mapping [%s] with an object mapping", fieldName)
	}
	if aHasProps && bType != "" && bType != "object" && bType != "nested" && bType != "passthrough" {
		return fmt.Errorf("illegal_argument_exception: Can't merge a non object mapping [%s] with an object mapping", fieldName)
	}
	return nil
}

// SerializeMappings serializes an IndexSchema's mapping into an Elasticsearch `_mapping` JSON map.
// When `Properties` is empty and no non-default settings exist, it returns `{}` (omitting `"properties": {}`).
func SerializeMappings(s *IndexSchema) map[string]any {
	if s == nil {
		return map[string]any{}
	}
	if s.RawMapping != nil {
		out := SerializeMappingSpec(s.RawMapping)
		if strings.EqualFold(strings.TrimSpace(s.IndexMode), "time_series") {
			if _, ok := out["_data_stream_timestamp"]; !ok {
				out["_data_stream_timestamp"] = map[string]any{"enabled": true}
			}
		}
		return out
	}
	if len(s.Fields) == 0 {
		return map[string]any{}
	}
	props := make(map[string]any)
	keys := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b := s.Fields[k]
		if strings.Contains(k, ".") {
			continue
		}
		fp := map[string]any{}
		if b.ESType != "" {
			fp["type"] = b.ESType
		}
		if len(b.Meta) > 0 {
			fp["meta"] = cloneStringMap(b.Meta)
		}
		if len(b.Contexts) > 0 {
			fp["contexts"] = serializeCompletionContexts(b.Contexts)
		}
		if len(fp) > 0 {
			props[k] = fp
		}
	}
	if len(props) == 0 {
		return map[string]any{}
	}
	return map[string]any{"properties": props}
}

// SerializeMappings delegates to package-level SerializeMappings(s).
func (s *IndexSchema) SerializeMappings() map[string]any {
	return SerializeMappings(s)
}

// SerializeMappingSpec serializes a MappingSpec into an ES-compliant `_mapping` map, omitting `"properties"` when empty.
func SerializeMappingSpec(m *esast.MappingSpec) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	out := make(map[string]any)
	if m.Enabled != nil {
		out["enabled"] = *m.Enabled
	}
	if m.Dynamic != nil {
		out["dynamic"] = m.Dynamic
	}
	if m.Subobjects != nil {
		out["subobjects"] = *m.Subobjects
	}
	if m.Routing != nil && m.Routing.Required {
		out["_routing"] = map[string]any{"required": true}
	}
	if len(m.Size) > 0 {
		if en, explicit, err := ValidateSizeMetaSpec(m.Size); err == nil && explicit {
			out["_size"] = map[string]any{"enabled": en}
		}
	}
	if len(m.Meta) > 0 {
		out["_meta"] = m.Meta
	}
	if len(m.Source) > 0 {
		if serializedSrc := serializeSourceMap(m.Source); len(serializedSrc) > 0 {
			out["_source"] = serializedSrc
		}
	}
	if m.DataStreamTimestamp != nil {
		out["_data_stream_timestamp"] = deepCloneAny(m.DataStreamTimestamp)
	}
	if len(m.DynamicTemplates) > 0 {
		out["dynamic_templates"] = m.DynamicTemplates
	}
	if m.DateDetection != nil {
		out["date_detection"] = *m.DateDetection
	}
	if m.NumericDetection != nil {
		out["numeric_detection"] = *m.NumericDetection
	}
	if len(m.DynamicDateFormats) > 0 {
		out["dynamic_date_formats"] = m.DynamicDateFormats
	}
	if len(m.Runtime) > 0 {
		rtOut := make(map[string]any, len(m.Runtime))
		for k, rp := range m.Runtime {
			rtOut[k] = SerializeFieldProperty(rp)
		}
		if len(rtOut) > 0 {
			out["runtime"] = rtOut
		}
	}
	if len(m.Properties) > 0 {
		props := m.Properties
		if expanded, err := ExpandDottedPropertiesWithSubobjects(props, m.Subobjects != nil && !*m.Subobjects); err == nil {
			props = expanded
		}
		propOut := make(map[string]any, len(props))
		for k, fp := range props {
			propOut[k] = SerializeFieldProperty(fp)
		}
		if len(propOut) > 0 {
			out["properties"] = propOut
		}
	}
	return out
}

func serializeSourceMap(src map[string]any) map[string]any {
	norm, err := validateAndNormalizeMappingSourceSpec(src)
	if err != nil {
		cp := make(map[string]any, len(src))
		for k, v := range src {
			cp[k] = v
		}
		return cp
	}
	out := make(map[string]any)
	if norm.hasExplicitMode && norm.mode != "" {
		if norm.mode == "disabled" && norm.hasExplicitEnabled {
			out["enabled"] = false
		} else {
			out["mode"] = norm.mode
		}
	} else if !norm.enabled {
		out["enabled"] = false
	}
	if len(norm.includes) > 0 {
		out["includes"] = norm.includes
	}
	if len(norm.excludes) > 0 {
		out["excludes"] = norm.excludes
	}
	if norm.hasCompress {
		out["compress"] = norm.compress
	}
	if norm.compressThreshold != "" {
		out["compress_threshold"] = norm.compressThreshold
	}
	return out
}

func serializeCompletionContexts(contexts []esast.CompletionContextDef) []map[string]any {
	out := make([]map[string]any, 0, len(contexts))
	for _, c := range contexts {
		entry := map[string]any{
			"name": c.Name,
			"type": c.Type,
		}
		if c.Path != "" {
			entry["path"] = c.Path
		}
		if c.Precision != nil {
			entry["precision"] = c.Precision
		}
		if c.Default != nil {
			entry["default"] = c.Default
		}
		out = append(out, entry)
	}
	return out
}

// SerializeFieldProperty serializes a single FieldProperty without internal Doris multi_valued/upgraded_array flags.
func SerializeFieldProperty(fp esast.FieldProperty) map[string]any {
	out := make(map[string]any)
	if fp.Type != "" {
		out["type"] = fp.Type
	}
	if fp.Dynamic != nil {
		out["dynamic"] = fp.Dynamic
	}
	if fp.Subobjects != nil {
		out["subobjects"] = *fp.Subobjects
	}
	if fp.Enabled != nil {
		out["enabled"] = *fp.Enabled
	}
	if fp.IncludeInParent != nil {
		out["include_in_parent"] = *fp.IncludeInParent
	}
	if fp.IncludeInRoot != nil {
		out["include_in_root"] = *fp.IncludeInRoot
	}
	if fp.Index != nil {
		out["index"] = *fp.Index
	}
	if fp.DocValues != nil {
		out["doc_values"] = *fp.DocValues
	}
	if fp.Store != nil {
		out["store"] = *fp.Store
	}
	if fp.Path != "" {
		out["path"] = fp.Path
	}
	if fp.Value != nil {
		out["value"] = fp.Value
	}
	if fp.Script != nil {
		if normScript, err := esast.NormalizeFieldScriptObject(fp.Script); err == nil && normScript != nil {
			out["script"] = normScript
		} else {
			out["script"] = fp.Script
		}
	}
	if fp.OnScriptError != "" {
		out["on_script_error"] = fp.OnScriptError
	}
	if fp.TermVector != "" {
		out["term_vector"] = fp.TermVector
	}
	if fp.Analyzer != "" {
		out["analyzer"] = fp.Analyzer
	}
	if fp.SearchAnalyzer != "" {
		out["search_analyzer"] = fp.SearchAnalyzer
	}
	if fp.SearchQuoteAnalyzer != "" {
		out["search_quote_analyzer"] = fp.SearchQuoteAnalyzer
	}
	if fp.Normalizer != "" {
		out["normalizer"] = fp.Normalizer
	}
	if fp.Format != "" {
		out["format"] = fp.Format
	}
	if fp.TimeZone != "" {
		out["time_zone"] = fp.TimeZone
	}
	if strings.EqualFold(fp.Type, "dense_vector") || strings.EqualFold(fp.Type, "knn_vector") {
		isNotIdx := fp.Index != nil && !*fp.Index
		effElem := strings.ToLower(strings.TrimSpace(fp.ElementType))
		if effElem == "" {
			effElem = "float"
		}
		if fp.EffectiveDims() > 0 {
			out["dims"] = fp.EffectiveDims()
		}
		if fp.ElementType != "" {
			out["element_type"] = fp.ElementType
		}
		if isNotIdx {
			out["index"] = false
		} else {
			out["index"] = true
			sim := fp.Similarity
			if sim == "" {
				if effElem == "bit" {
					sim = "l2_norm"
				} else {
					sim = "cosine"
				}
			}
			out["similarity"] = sim
			if matOpts := MaterializeDenseVectorIndexOptions(effElem, fp.IndexOptions); len(matOpts) > 0 {
				out["index_options"] = matOpts
			}
		}
	} else {
		if fp.Dims > 0 {
			out["dims"] = fp.Dims
		} else if fp.Dimension > 0 {
			out["dims"] = fp.Dimension
		}
		if fp.Similarity != "" {
			out["similarity"] = fp.Similarity
		}
		if fp.ElementType != "" {
			out["element_type"] = fp.ElementType
		}
	}
	if fp.CopyTo != nil {
		out["copy_to"] = fp.CopyTo
	}
	if fp.NullValue != nil {
		out["null_value"] = fp.NullValue
	}
	if fp.IgnoreAbove > 0 {
		out["ignore_above"] = fp.IgnoreAbove
	}
	if fp.IgnoreMalformed != nil {
		out["ignore_malformed"] = *fp.IgnoreMalformed
	}
	if fp.Coerce != nil {
		out["coerce"] = *fp.Coerce
	}
	if fp.ScalingFactor > 0 {
		out["scaling_factor"] = fp.ScalingFactor
	}
	if len(fp.Meta) > 0 {
		out["meta"] = cloneStringMap(fp.Meta)
	}
	if len(fp.Contexts) > 0 {
		out["contexts"] = serializeCompletionContexts(fp.Contexts)
	}
	if len(fp.IndexPrefixes) > 0 {
		out["index_prefixes"] = fp.IndexPrefixes
	}
	if fp.IndexPhrases != nil {
		out["index_phrases"] = *fp.IndexPhrases
	}
	if fp.IndexOptions != nil && !strings.EqualFold(fp.Type, "dense_vector") && !strings.EqualFold(fp.Type, "knn_vector") {
		out["index_options"] = fp.IndexOptions
	}
	if fp.StoreArraySource != nil {
		out["store_array_source"] = *fp.StoreArraySource
	}
	if fp.SyntheticSourceKeep != "" {
		out["synthetic_source_keep"] = fp.SyntheticSourceKeep
	}
	if fp.TimeSeriesDimension != nil {
		out["time_series_dimension"] = *fp.TimeSeriesDimension
	}
	if len(fp.TimeSeriesDimensions) > 0 {
		out["time_series_dimensions"] = append([]string(nil), fp.TimeSeriesDimensions...)
	}
	if fp.TimeSeriesMetric != "" {
		out["time_series_metric"] = fp.TimeSeriesMetric
	}
	if fp.TargetIndex != "" {
		out["target_index"] = fp.TargetIndex
	}
	if fp.InputField != "" {
		out["input_field"] = fp.InputField
	}
	if fp.TargetField != "" {
		out["target_field"] = fp.TargetField
	}
	if fp.KeyField != "" {
		out["key_field"] = fp.KeyField
	}
	if len(fp.FetchFields) > 0 {
		out["fetch_fields"] = deepCloneSliceMapStringAny(fp.FetchFields)
	}
	if len(fp.Metrics) > 0 {
		out["metrics"] = append([]string(nil), fp.Metrics...)
	}
	if fp.DefaultMetric != "" {
		out["default_metric"] = fp.DefaultMetric
	}
	if fp.Norms != nil {
		out["norms"] = *fp.Norms
	}
	if fp.Boost != nil {
		out["boost"] = fp.Boost
	}
	if fp.EagerGlobalOrdinals != nil {
		out["eager_global_ordinals"] = *fp.EagerGlobalOrdinals
	}
	if fp.Fielddata != nil {
		out["fielddata"] = fp.Fielddata
	}
	if fp.SplitQueriesOnWhitespace != nil {
		out["split_queries_on_whitespace"] = *fp.SplitQueriesOnWhitespace
	}
	if fp.EnablePositionIncrements != nil {
		out["enable_position_increments"] = *fp.EnablePositionIncrements
	}
	if fp.PositiveScoreImpact != nil {
		out["positive_score_impact"] = *fp.PositiveScoreImpact
	}
	if fp.MaxShingleSize != nil {
		out["max_shingle_size"] = *fp.MaxShingleSize
	}
	if fp.DepthLimit != nil {
		out["depth_limit"] = *fp.DepthLimit
	}
	if fp.Priority != nil {
		out["priority"] = *fp.Priority
	}
	if len(fp.Relations) > 0 {
		out["relations"] = fp.Relations
	}
	if len(fp.Fields) > 0 {
		fieldsOut := make(map[string]any, len(fp.Fields))
		for fk, fprop := range fp.Fields {
			fieldsOut[fk] = SerializeFieldProperty(fprop)
		}
		out["fields"] = fieldsOut
	}
	if len(fp.Properties) > 0 {
		propsOut := make(map[string]any, len(fp.Properties))
		for pk, pprop := range fp.Properties {
			propsOut[pk] = SerializeFieldProperty(pprop)
		}
		out["properties"] = propsOut
	}
	return out
}

// ReconstructSyntheticSource reconstructs an Elasticsearch synthetic `_source` document deterministically:
//   - Omits `enabled: false` objects, unmapped fields under `dynamic: false`, fields with `doc_values: false`
//     (unless stored/text-supported), and malformed/`ignore_above` ignored values.
//   - Sorts multi-valued scalar arrays deterministically (numeric ascending, boolean `false` before `true`,
//     lexicographical ascending for strings) and unwraps single-element scalar arrays (`[x]` -> `x`),
//     while preserving coordinate/vector arrays (`geo_point`, `point`, `geo_shape`, `dense_vector`, `knn_vector`)
//     and `nested` object array ordering.
//   - Applies `_source.includes` / `_source.excludes` when configured.
func ReconstructSyntheticSource(idxSchema *IndexSchema, rawDoc map[string]any, shreddedRow map[string]any) map[string]any {
	if idxSchema != nil && idxSchema.SourceDisabled() {
		return nil
	}
	srcDoc := rawDoc
	if srcDoc == nil && shreddedRow != nil {
		if rawSrcStr, ok := shreddedRow["_source"].(string); ok && strings.TrimSpace(rawSrcStr) != "" {
			var decoded map[string]any
			dec := json.NewDecoder(strings.NewReader(rawSrcStr))
			dec.UseNumber()
			if err := dec.Decode(&decoded); err == nil && decoded != nil {
				srcDoc = decoded
			}
		}
		if srcDoc == nil {
			switch dv := shreddedRow["_doc"].(type) {
			case map[string]any:
				srcDoc = dv
			case json.RawMessage:
				var decoded map[string]any
				dec := json.NewDecoder(bytes.NewReader(dv))
				dec.UseNumber()
				if dec.Decode(&decoded) == nil && decoded != nil {
					srcDoc = decoded
				}
			case []byte:
				var decoded map[string]any
				dec := json.NewDecoder(bytes.NewReader(dv))
				dec.UseNumber()
				if dec.Decode(&decoded) == nil && decoded != nil {
					srcDoc = decoded
				}
			case string:
				if strings.TrimSpace(dv) != "" {
					var decoded map[string]any
					dec := json.NewDecoder(strings.NewReader(dv))
					dec.UseNumber()
					if dec.Decode(&decoded) == nil && decoded != nil {
						srcDoc = decoded
					}
				}
			}
		}
	}
	if srcDoc == nil {
		return map[string]any{}
	}

	ignoredSet := make(map[string]bool)
	if shreddedRow != nil {
		switch ig := shreddedRow["_ignored"].(type) {
		case []string:
			for _, f := range ig {
				ignoredSet[f] = true
			}
		case []any:
			for _, f := range ig {
				if s, ok := f.(string); ok {
					ignoredSet[s] = true
				}
			}
		}
	}

	var reconstructed map[string]any
	if idxSchema != nil && idxSchema.RawMapping != nil && idxSchema.RawMapping.Enabled != nil && !*idxSchema.RawMapping.Enabled {
		reconstructed = reconstructIgnoredSourceObject(idxSchema, srcDoc, "")
	} else {
		reconstructed = reconstructSyntheticObject(idxSchema, srcDoc, "", ignoredSet)
	}
	if reconstructed == nil {
		reconstructed = map[string]any{}
	}
	mergeIgnoredSourceIntoSynthetic(idxSchema, reconstructed, shreddedRow)

	if idxSchema != nil {
		inc, exc := idxSchema.SourceIncludesExcludes()
		if len(inc) > 0 || len(exc) > 0 {
			b, err := json.Marshal(reconstructed)
			if err == nil {
				filteredBytes := FilterSourceBytesIncludesExcludes(b, inc, exc)
				var filteredMap map[string]any
				dec := json.NewDecoder(bytes.NewReader(filteredBytes))
				dec.UseNumber()
				if dec.Decode(&filteredMap) == nil && filteredMap != nil {
					return filteredMap
				}
			}
		}
	}
	return reconstructed
}

func isSyntheticExcludedBinding(idxSchema *IndexSchema, fullPath string) (FieldBinding, bool, bool) {
	if idxSchema == nil {
		return FieldBinding{}, false, false
	}
	b, hasBinding := idxSchema.Fields[fullPath]
	if !hasBinding {
		return FieldBinding{}, false, false
	}
	if b.EnabledFalse {
		return b, true, false
	}
	esType := strings.ToLower(strings.TrimSpace(b.ESType))
	if esType == "alias" {
		return b, true, true
	}
	// Check explicit raw FieldProperty `store` flag if `doc_values: false`
	storedTrue := false
	hasCapableSub := false
	if idxSchema.RawMapping != nil {
		if fp, ok := lookupRawFieldProperty(idxSchema.RawMapping.Properties, strings.Split(fullPath, ".")); ok {
			if fp.Store != nil && *fp.Store {
				storedTrue = true
			}
			hasCapableSub = hasSyntheticCapableSubfield(fp.Fields)
		}
	}
	if esType == "murmur3" && !storedTrue && !hasCapableSub {
		return b, true, true
	}
	if b.DocValuesFalse && !storedTrue {
		switch esType {
		case "text", "match_only_text", "annotated-text", "annotated_text", "search_as_you_type":
			if b.NotIndexed {
				return b, true, true
			}
		default:
			return b, true, true
		}
	}
	if esType == "binary" && b.DocValuesFalse && !storedTrue {
		return b, true, true
	}
	return b, true, false
}

func lookupRawFieldProperty(props map[string]esast.FieldProperty, parts []string) (esast.FieldProperty, bool) {
	if len(parts) == 0 || len(props) == 0 {
		return esast.FieldProperty{}, false
	}
	if fp, ok := props[parts[0]]; ok {
		if len(parts) == 1 {
			return fp, true
		}
		return lookupRawFieldProperty(fp.Properties, parts[1:])
	}
	for i := len(parts); i >= 2; i-- {
		joined := strings.Join(parts[:i], ".")
		if fp, ok := props[joined]; ok {
			if i == len(parts) {
				return fp, true
			}
			return lookupRawFieldProperty(fp.Properties, parts[i:])
		}
	}
	return esast.FieldProperty{}, false
}

func reconstructSyntheticObject(idxSchema *IndexSchema, obj map[string]any, prefix string, ignoredSet map[string]bool) map[string]any {
	if len(obj) == 0 {
		return map[string]any{}
	}
	if isSubobjectsFalseAtPrefix(idxSchema, prefix) {
		obj = flattenSubmapsForNoSubobjects(obj)
	} else {
		obj = expandDottedKeysForSyntheticObject(idxSchema, obj, prefix)
	}
	out := make(map[string]any, len(obj))
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if k == "__ignored_source" || (prefix == "" && k == "_size") {
			continue
		}
		rawVal := obj[k]
		if rawVal == nil {
			continue
		}
		if prefix == "" && k == "_doc_count" {
			if f, ok := syntheticToFloat64(rawVal); ok && f > 0 && f == math.Trunc(f) {
				out[k] = int64(f)
			}
			continue
		}
		fullPath := k
		if prefix != "" {
			fullPath = prefix + "." + k
		}
		if isUnmappedScopeInSynthetic(idxSchema, fullPath) {
			if keptVal, okKeep := reconstructIgnoredSourceValue(idxSchema, rawVal, fullPath); okKeep {
				out[k] = keptVal
			}
			continue
		}
		b, hasBinding, excluded := isSyntheticExcludedBinding(idxSchema, fullPath)
		if excluded {
			continue
		}
		esType := strings.ToLower(strings.TrimSpace(b.ESType))
		isNested := idxSchema != nil && idxSchema.NestedRoots != nil && idxSchema.NestedRoots[fullPath] != ""

		val, keep := reconstructSyntheticValue(idxSchema, rawVal, fullPath, b, hasBinding, esType, isNested, ignoredSet)
		if !keep {
			continue
		}
		out[k] = val
	}
	return out
}

func isCoordinateOrVectorESType(esType string) bool {
	switch esType {
	case "geo_point", "point", "geo_shape", "shape", "dense_vector", "knn_vector", "histogram":
		return true
	default:
		return false
	}
}

func reconstructSyntheticValue(
	idxSchema *IndexSchema,
	rawVal any,
	fullPath string,
	b FieldBinding,
	hasBinding bool,
	esType string,
	isNested bool,
	ignoredSet map[string]bool,
) (any, bool) {
	if rawVal == nil {
		return nil, false
	}
	if hasBinding && esType == "constant_keyword" {
		if ignoredSet[fullPath] {
			return nil, false
		}
		if arr, isArr := rawVal.([]any); isArr && len(arr) == 0 {
			return nil, false
		}
		if b.HasConstantValue && b.ConstantValue != nil {
			if s, isStr := b.ConstantValue.(string); isStr && (b.NormalizerName != "" || b.LowercaseNormalizer) {
				return normalizeValueForBinding(s, b, idxSchema), true
			}
			return b.ConstantValue, true
		}
	}
	if hasBinding && esType == "aggregate_metric_double" {
		return reconstructSyntheticAggregateMetricDouble(idxSchema, rawVal, b)
	}
	if hasBinding && esType == "flattened" {
		return reconstructSyntheticFlattenedValue(idxSchema, rawVal, b)
	}
	if hasBinding && esType == "sparse_vector" {
		if ignoredSet[fullPath] {
			return nil, false
		}
		return reconstructSyntheticSparseVectorValue(idxSchema, rawVal)
	}
	if hasBinding && (esType == "annotated-text" || esType == "annotated_text") {
		if ignoredSet[fullPath] {
			return nil, false
		}
		return reconstructSyntheticAnnotatedTextValue(idxSchema, rawVal, fullPath, b)
	}
	if hasBinding && esType == "counted_keyword" {
		return reconstructSyntheticCountedKeywordValue(idxSchema, rawVal, b)
	}
	if isCoordinateOrVectorESType(esType) {
		ignMalformed := isEffectiveIgnoreMalformedForSynthetic(idxSchema, b)
		if ignoredSet[fullPath] && !ignMalformed {
			return nil, false
		}
		if esType == "histogram" {
			return reconstructSyntheticHistogramValue(idxSchema, rawVal, fullPath, ignMalformed)
		}
		if esType == "geo_point" {
			if strings.EqualFold(strings.TrimSpace(b.TimeSeriesMetric), "position") {
				if posObj, ok := reconstructSyntheticPositionGeoPoint(rawVal); ok {
					return posObj, true
				}
			}
			return reconstructSyntheticGeoPointValue(idxSchema, rawVal, fullPath, b, ignMalformed)
		}
		if esType == "dense_vector" || esType == "knn_vector" {
			elemT := strings.ToLower(strings.TrimSpace(b.VectorElementType))
			switch elemT {
			case "byte":
				if hexStr, isStr := rawVal.(string); isStr {
					if decoded, err := esast.DecodeHexSignedByteVector(hexStr); err == nil {
						outBytes := make([]any, len(decoded))
						for i, fv := range decoded {
							outBytes[i] = int64(fv)
						}
						return outBytes, true
					}
				}
			case "", "float":
				if arr, isArr := rawVal.([]any); isArr {
					outFloats := make([]any, 0, len(arr))
					for _, elem := range arr {
						if fv, okF := syntheticToFloat64(elem); okF {
							outFloats = append(outFloats, normalizeCleanFloat32AsFloat64(fv))
						}
					}
					return outFloats, true
				}
			}
		}
		normCoord, _ := reconstructIgnoredSourceValue(idxSchema, rawVal, fullPath)
		return normCoord, true
	}
	if hasBinding && IsRangeFieldType(esType) {
		return reconstructSyntheticRangeValue(idxSchema, rawVal, fullPath, b, esType, ignoredSet)
	}

	switch v := rawVal.(type) {
	case map[string]any:
		if esType == "flattened" || esType == "rank_features" || esType == "sparse_vector" || esType == "percolator" {
			if len(v) == 0 {
				return nil, false
			}
			normMap, _ := reconstructIgnoredSourceValue(idxSchema, v, fullPath)
			return normMap, true
		}
		sub := reconstructSyntheticObject(idxSchema, v, fullPath, ignoredSet)
		if len(sub) == 0 {
			return nil, false
		}
		return sub, true

	case []any:
		if len(v) == 0 {
			if hasBinding && esType == "rank_features" {
				return []any{}, true
			}
			return nil, false
		}
		// Check if array contains objects (e.g. `nested` or object array)
		hasMaps := false
		for _, elem := range v {
			if _, isMap := elem.(map[string]any); isMap {
				hasMaps = true
				break
			}
		}
		if hasMaps {
			isStoredArray := hasExplicitStoreArraySourceAtPath(idxSchema, fullPath)
			if isNested || idxSchema == nil || isStoredArray || shouldPreserveSyntheticObjectArray(idxSchema, fullPath, v) {
				// Preserve nested / store_array_source:true / dynamic:false|runtime / schemaless array order
				objs := make([]any, 0, len(v))
				for _, elem := range v {
					em, ok := elem.(map[string]any)
					if !ok || em == nil {
						continue
					}
					var re map[string]any
					if isStoredArray {
						re = reconstructIgnoredSourceObject(idxSchema, em, fullPath)
					} else {
						re = reconstructSyntheticObject(idxSchema, em, fullPath, ignoredSet)
					}
					if len(re) > 0 {
						objs = append(objs, re)
					}
				}
				if len(objs) == 0 {
					return nil, false
				}
				return objs, true
			}
			// Mapped regular object array without `store_array_source: true`: flatten subfields across array elements (`20_synthetic_source.yml`)
			return flattenSyntheticMappedObjectArray(idxSchema, v, fullPath, ignoredSet)
		}

		// Scalar array (flatten nested scalar arrays like `[[2, 1], [3]]` -> `[1, 2, 3]`)
		preserveArrayOrder := hasBinding && ((b.StoreArraySource != nil && *b.StoreArraySource) || strings.EqualFold(b.SyntheticSourceKeep, "arrays"))
		var scalars []any
		var malformedScalars []any
		var ignoredAboveScalars []any
		var flattenScalars func(items []any)
		flattenScalars = func(items []any) {
			for _, item := range items {
				if item == nil {
					continue
				}
				if subSlice, isSlice := item.([]any); isSlice {
					flattenScalars(subSlice)
					continue
				}
				if hasBinding && b.IgnoreAbove > 0 {
					s := fmt.Sprintf("%v", item)
					if len([]rune(s)) > b.IgnoreAbove {
						if preserveArrayOrder {
							scalars = append(scalars, s)
						} else {
							ignoredAboveScalars = append(ignoredAboveScalars, s)
						}
						continue
					}
				}
				normItem, isValid, keep := normalizeSyntheticScalarWithValidity(idxSchema, item, fullPath, b, hasBinding, esType, ignoredSet)
				if keep {
					if !isValid && !preserveArrayOrder {
						malformedScalars = append(malformedScalars, normItem)
					} else {
						scalars = append(scalars, normItem)
					}
				}
			}
		}
		flattenScalars(v)
		if !preserveArrayOrder && len(scalars) > 1 {
			sortSyntheticScalars(scalars, esType)
			if hasBinding && isSyntheticDocValuesDedupType(esType) && !strings.EqualFold(strings.TrimSpace(b.TimeSeriesMetric), "gauge") {
				scalars = deduplicateSortedSyntheticScalars(scalars)
			}
		}
		if len(malformedScalars) > 0 {
			scalars = append(scalars, malformedScalars...)
		}
		if len(ignoredAboveScalars) > 0 {
			scalars = append(scalars, ignoredAboveScalars...)
		}
		if len(scalars) == 0 {
			return nil, false
		}
		if preserveArrayOrder {
			return scalars, true
		}
		if len(scalars) == 1 {
			return scalars[0], true
		}
		return scalars, true

	default:
		if hasBinding && b.IgnoreAbove > 0 {
			s := fmt.Sprintf("%v", v)
			if len([]rune(s)) > b.IgnoreAbove {
				return s, true
			}
		}
		normVal, _, ok := normalizeSyntheticScalarWithValidity(idxSchema, v, fullPath, b, hasBinding, esType, ignoredSet)
		if !ok {
			return nil, false
		}
		return normVal, true
	}
}

func reconstructSyntheticHistogramValue(idxSchema *IndexSchema, rawVal any, fullPath string, ignMalformed bool) (any, bool) {
	if arr, isArr := rawVal.([]any); isArr {
		var validObjs []any
		var malformedItems []any
		var walkSlice func(items []any)
		walkSlice = func(items []any) {
			for _, elem := range items {
				if elem == nil {
					continue
				}
				if subSlice, okS := elem.([]any); okS {
					walkSlice(subSlice)
					continue
				}
				nzVals, nzCnts, _, _, err := validateSingleHistogramObject(elem, fullPath)
				if err == nil {
					if len(nzVals) > 0 {
						validObjs = append(validObjs, map[string]any{
							"values": nzVals,
							"counts": nzCnts,
						})
					}
					continue
				}
				if ignMalformed {
					if normElem, okN := reconstructIgnoredSourceValue(idxSchema, elem, fullPath); okN {
						malformedItems = append(malformedItems, normElem)
					}
				}
			}
		}
		walkSlice(arr)
		out := make([]any, 0, len(validObjs)+len(malformedItems))
		out = append(out, validObjs...)
		if ignMalformed {
			out = append(out, malformedItems...)
		}
		if len(out) == 0 {
			return nil, false
		}
		if len(out) == 1 && !ignMalformed {
			return out[0], true
		}
		return out, true
	}
	if _, isMap := rawVal.(map[string]any); isMap {
		nzVals, nzCnts, _, _, err := validateSingleHistogramObject(rawVal, fullPath)
		if err == nil {
			if len(nzVals) == 0 {
				return nil, false
			}
			return map[string]any{
				"values": nzVals,
				"counts": nzCnts,
			}, true
		}
	}
	if ignMalformed {
		return reconstructIgnoredSourceValue(idxSchema, rawVal, fullPath)
	}
	return nil, false
}

func isEffectiveIgnoreMalformedForSynthetic(idxSchema *IndexSchema, b FieldBinding) bool {
	if b.IgnoreMalformed != nil {
		return *b.IgnoreMalformed
	}
	if idxSchema != nil && idxSchema.DefaultIgnoreMalformed != nil {
		return *idxSchema.DefaultIgnoreMalformed
	}
	return false
}

func shouldPreserveSyntheticObjectArray(idxSchema *IndexSchema, fullPath string, elems []any) bool {
	if idxSchema == nil || fullPath == "" {
		return false
	}
	if idxSchema.RawMapping != nil {
		if fp, ok := lookupRawFieldProperty(idxSchema.RawMapping.Properties, strings.Split(fullPath, ".")); ok {
			dyn := normalizeDynamicMode(fp.Dynamic)
			if dyn == "false" || dyn == "runtime" {
				return true
			}
		}
	}
	if idxSchema.IgnoreDynamicBeyondLimit {
		pfx := fullPath + "."
		for _, elem := range elems {
			em, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			for k := range em {
				subFull := pfx + k
				if _, mapped := idxSchema.Fields[subFull]; mapped {
					continue
				}
				hasChild := false
				subPfx := subFull + "."
				for fk := range idxSchema.Fields {
					if strings.HasPrefix(fk, subPfx) {
						hasChild = true
						break
					}
				}
				if !hasChild {
					return true
				}
			}
		}
	}
	return false
}

func reconstructSyntheticGeoPointValue(
	idxSchema *IndexSchema,
	rawVal any,
	fullPath string,
	b FieldBinding,
	ignMalformed bool,
) (any, bool) {
	if rawVal == nil {
		return nil, false
	}
	if arr, isArr := rawVal.([]any); isArr {
		if len(arr) == 2 && isGeoNumericElem(arr[0]) && isGeoNumericElem(arr[1]) {
			if _, lat, lon, ok := parseAndFormatGeoPointValue(arr); ok {
				return map[string]any{"lat": lat, "lon": lon}, true
			}
			if ignMalformed {
				norm, _ := reconstructIgnoredSourceValue(idxSchema, rawVal, fullPath)
				return norm, true
			}
			return nil, false
		}
		type geoPtEntry struct {
			lat float64
			lon float64
			obj map[string]any
		}
		var validPts []geoPtEntry
		var malformed []any
		var collectItems func(items []any)
		collectItems = func(items []any) {
			for _, item := range items {
				if item == nil {
					continue
				}
				if subArr, isSub := item.([]any); isSub && (len(subArr) != 2 || !isGeoNumericElem(subArr[0]) || !isGeoNumericElem(subArr[1])) {
					collectItems(subArr)
					continue
				}
				if _, lat, lon, ok := parseAndFormatGeoPointValue(item); ok {
					validPts = append(validPts, geoPtEntry{
						lat: lat,
						lon: lon,
						obj: map[string]any{"lat": lat, "lon": lon},
					})
				} else if ignMalformed {
					if norm, okN := reconstructIgnoredSourceValue(idxSchema, item, fullPath); okN {
						malformed = append(malformed, norm)
					}
				}
			}
		}
		collectItems(arr)
		preserveOrder := b.StoreArraySource != nil && *b.StoreArraySource
		if !preserveOrder && len(validPts) > 1 {
			sort.SliceStable(validPts, func(i, j int) bool {
				if validPts[i].lon != validPts[j].lon {
					return validPts[i].lon < validPts[j].lon
				}
				return validPts[i].lat < validPts[j].lat
			})
			dedup := validPts[:0]
			for _, pt := range validPts {
				if len(dedup) > 0 && dedup[len(dedup)-1].lat == pt.lat && dedup[len(dedup)-1].lon == pt.lon {
					continue
				}
				dedup = append(dedup, pt)
			}
			validPts = dedup
		}
		out := make([]any, 0, len(validPts)+len(malformed))
		for _, pt := range validPts {
			out = append(out, pt.obj)
		}
		out = append(out, malformed...)
		if len(out) == 0 {
			return nil, false
		}
		if len(out) == 1 && !preserveOrder {
			return out[0], true
		}
		return out, true
	}
	if _, lat, lon, ok := parseAndFormatGeoPointValue(rawVal); ok {
		return map[string]any{"lat": lat, "lon": lon}, true
	}
	if ignMalformed {
		norm, _ := reconstructIgnoredSourceValue(idxSchema, rawVal, fullPath)
		return norm, true
	}
	return nil, false
}

func isSyntheticDocValuesDedupType(esType string) bool {
	switch esType {
	case "keyword", "constant_keyword", "wildcard", "version", "ip",
		"long", "integer", "short", "byte", "unsigned_long",
		"double", "float", "half_float", "scaled_float",
		"date", "date_nanos":
		return true
	default:
		return false
	}
}

func deduplicateSortedSyntheticScalars(scalars []any) []any {
	if len(scalars) <= 1 {
		return scalars
	}
	out := make([]any, 0, len(scalars))
	for _, s := range scalars {
		if len(out) > 0 && syntheticScalarsEqual(out[len(out)-1], s) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func syntheticScalarsEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == b
	}
	switch av := a.(type) {
	case int64:
		if bv, ok := b.(int64); ok {
			return av == bv
		}
	case float64:
		if bv, ok := b.(float64); ok {
			return av == bv
		}
	case bool:
		if bv, ok := b.(bool); ok {
			return av == bv
		}
	case string:
		if bv, ok := b.(string); ok {
			return av == bv
		}
	case json.Number:
		if bv, ok := b.(json.Number); ok {
			return av.String() == bv.String()
		}
	}
	return fmt.Sprintf("%T:%v", a, a) == fmt.Sprintf("%T:%v", b, b)
}

func normalizeSyntheticScalarWithValidity(
	idxSchema *IndexSchema,
	val any,
	fullPath string,
	b FieldBinding,
	hasBinding bool,
	esType string,
	ignoredSet map[string]bool,
) (any, bool, bool) {
	if val == nil {
		return nil, false, false
	}
	if hasBinding && b.IgnoreAbove > 0 {
		s := fmt.Sprintf("%v", val)
		if len([]rune(s)) > b.IgnoreAbove {
			return nil, false, false
		}
	}
	if hasBinding {
		effB := b
		if idxSchema != nil {
			effB = idxSchema.withEffectiveDefaults(b)
		}
		ignMalformed := isEffectiveIgnoreMalformedForSynthetic(idxSchema, effB)
		switch esType {
		case "long", "integer", "short", "byte":
			switch tv := val.(type) {
			case int64:
				return tv, true, true
			case int:
				return int64(tv), true, true
			case uint64:
				if tv <= math.MaxInt64 {
					return int64(tv), true, true
				}
			case json.Number:
				if !strings.ContainsAny(tv.String(), ".eE") {
					if iv, err := tv.Int64(); err == nil {
						return iv, true, true
					}
				}
			case string:
				if effB.EffectiveCoerceBool() {
					if iv, err := strconv.ParseInt(strings.TrimSpace(tv), 10, 64); err == nil {
						return iv, true, true
					}
				}
			}
			if f, ok := syntheticToFloat64(val); ok {
				if !effB.EffectiveCoerceBool() {
					if _, isStr := val.(string); isStr {
						if ignoredSet[fullPath] && !ignMalformed {
							return nil, false, false
						}
						return val, false, true
					}
				}
				return int64(math.Trunc(f)), true, true
			}
			if ignoredSet[fullPath] && !ignMalformed {
				return nil, false, false
			}
			return val, false, ignMalformed || !ignoredSet[fullPath]
		case "unsigned_long":
			if sStr := fmt.Sprintf("%v", val); sStr != "" {
				if u, err := strconv.ParseUint(strings.TrimSpace(sStr), 10, 64); err == nil {
					if u <= math.MaxInt64 {
						return int64(u), true, true
					}
					return json.Number(strconv.FormatUint(u, 10)), true, true
				}
			}
			if ignoredSet[fullPath] && !ignMalformed {
				return nil, false, false
			}
			return val, false, ignMalformed || !ignoredSet[fullPath]
		case "double", "float", "half_float", "scaled_float":
			if f, ok := syntheticToFloat64(val); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
				if esType == "scaled_float" && b.ScalingFactor > 0 {
					f = math.Round(f*b.ScalingFactor) / b.ScalingFactor
				} else if esType == "float" {
					f = normalizeCleanFloat32AsFloat64(f)
				}
				return f, true, true
			}
			if ignoredSet[fullPath] && !ignMalformed {
				return nil, false, false
			}
			return val, false, ignMalformed || !ignoredSet[fullPath]
		case "date":
			fmtVal, keep := formatSyntheticDateValue(val, effB, ignoredSet, fullPath)
			if !keep {
				if ignMalformed {
					return val, false, true
				}
				return nil, false, false
			}
			_, okParsed := parseSyntheticEpochMillis(val, effB.Format, effB.Locale, time.Now().UTC())
			return fmtVal, okParsed, true
		case "boolean":
			switch bv := val.(type) {
			case bool:
				return bv, true, true
			case string:
				switch strings.ToLower(strings.TrimSpace(bv)) {
				case "true":
					return true, true, true
				case "false":
					return false, true, true
				}
			}
			if ignoredSet[fullPath] && !ignMalformed {
				return nil, false, false
			}
			return val, false, ignMalformed || !ignoredSet[fullPath]
		case "ip":
			if str, ok := val.(string); ok {
				if addr, err := netip.ParseAddr(strings.TrimSpace(str)); err == nil {
					return addr.Unmap().String(), true, true
				}
			}
			if ignoredSet[fullPath] && !ignMalformed {
				return nil, false, false
			}
			if n, isNum := val.(json.Number); isNum {
				if !strings.ContainsAny(n.String(), ".eE") {
					if i, err := n.Int64(); err == nil {
						return i, false, ignMalformed || !ignoredSet[fullPath]
					}
				}
			}
			return val, false, ignMalformed || !ignoredSet[fullPath]
		case "keyword", "wildcard":
			if str, ok := val.(string); ok {
				if b.NormalizerName != "" || b.LowercaseNormalizer {
					return normalizeValueForBinding(str, b, idxSchema), true, true
				}
				return str, true, true
			}
			s := fmt.Sprintf("%v", val)
			if b.NormalizerName != "" || b.LowercaseNormalizer {
				s = normalizeValueForBinding(s, b, idxSchema)
			}
			return s, true, true
		case "version":
			if str, ok := val.(string); ok {
				if b.LowercaseNormalizer {
					return strings.ToLower(str), true, true
				}
				return str, true, true
			}
			s := fmt.Sprintf("%v", val)
			if b.LowercaseNormalizer {
				s = strings.ToLower(s)
			}
			return s, true, true
		}
	}
	if n, isNum := val.(json.Number); isNum {
		if !strings.ContainsAny(n.String(), ".eE") {
			if i, err := n.Int64(); err == nil {
				return i, true, true
			}
			if _, errU := strconv.ParseUint(n.String(), 10, 64); errU == nil {
				return n, true, true
			}
		}
		if f, err := n.Float64(); err == nil {
			return f, true, true
		}
	}
	return val, true, true
}

func (b FieldBinding) EffectiveCoerceBool() bool {
	return b.Coerce == nil || *b.Coerce
}

func syntheticToFloat64(v any) (float64, bool) {
	switch tv := v.(type) {
	case float64:
		return tv, true
	case float32:
		return float64(tv), true
	case int:
		return float64(tv), true
	case int64:
		return float64(tv), true
	case uint64:
		return float64(tv), true
	case json.Number:
		f, err := tv.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(tv), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func sortSyntheticScalars(scalars []any, esType string) {
	if len(scalars) <= 1 {
		return
	}
	// Do not reorder `text` / `match_only_text` / `search_as_you_type` / `annotated_text`.
	if esType == "text" || esType == "match_only_text" || esType == "search_as_you_type" || esType == "annotated-text" || esType == "annotated_text" {
		return
	}
	if esType == "version" {
		sort.SliceStable(scalars, func(i, j int) bool {
			return CompareSemverForSynthetic(fmt.Sprintf("%v", scalars[i]), fmt.Sprintf("%v", scalars[j])) < 0
		})
		return
	}
	sort.SliceStable(scalars, func(i, j int) bool {
		if ia, okA := scalars[i].(int64); okA {
			if ib, okB := scalars[j].(int64); okB {
				return ia < ib
			}
		}
		fi, okI := syntheticNumericOrderVal(scalars[i])
		fj, okJ := syntheticNumericOrderVal(scalars[j])
		if okI && okJ {
			return fi < fj
		}
		bi, bOkI := scalars[i].(bool)
		bj, bOkJ := scalars[j].(bool)
		if bOkI && bOkJ {
			return !bi && bj
		}
		return fmt.Sprintf("%v", scalars[i]) < fmt.Sprintf("%v", scalars[j])
	})
}

func syntheticNumericOrderVal(v any) (float64, bool) {
	switch tv := v.(type) {
	case int:
		return float64(tv), true
	case int64:
		return float64(tv), true
	case uint64:
		return float64(tv), true
	case float64:
		return tv, true
	case float32:
		return float64(tv), true
	case json.Number:
		f, err := tv.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

// CompareSemverForSynthetic compares two Elasticsearch `version` values according to
// arbitrary-length core release segments (`1.2.3.4.5` > `1.2.3` > `1.2.3-abc+def`).
func CompareSemverForSynthetic(a, b string) int {
	return strings.Compare(semverSyntheticSortKey(a), semverSyntheticSortKey(b))
}

func semverSyntheticSortKey(v string) string {
	s := strings.TrimSpace(v)
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}
	core := s
	prerelease := ""
	hasPre := false
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		core = s[:idx]
		prerelease = s[idx+1:]
		hasPre = true
	}
	isDigits := func(x string) bool {
		if len(x) == 0 {
			return false
		}
		for i := 0; i < len(x); i++ {
			if x[i] < '0' || x[i] > '9' {
				return false
			}
		}
		return true
	}
	pad20 := func(x string) string {
		t := strings.TrimLeft(x, "0")
		if t == "" {
			t = "0"
		}
		if len(t) < 20 {
			return strings.Repeat("0", 20-len(t)) + t
		}
		return t
	}
	parts := strings.Split(core, ".")
	if len(parts) == 0 {
		return "~" + v
	}
	for _, p := range parts {
		if !isDigits(p) {
			return "~" + v
		}
	}
	nSegs := len(parts)
	if nSegs < 3 {
		nSegs = 3
	}
	coreSegs := make([]string, 0, nSegs)
	for i := 0; i < nSegs; i++ {
		if i >= len(parts) || parts[i] == "" {
			coreSegs = append(coreSegs, strings.Repeat("0", 20))
		} else if isDigits(parts[i]) {
			coreSegs = append(coreSegs, pad20(parts[i]))
		} else {
			coreSegs = append(coreSegs, "z:"+parts[i])
		}
	}
	coreJoined := strings.Join(coreSegs, "~")
	if hasPre {
		preSegs := strings.Split(prerelease, ".")
		for i, seg := range preSegs {
			if isDigits(seg) {
				preSegs[i] = "0:" + pad20(seg)
			} else {
				preSegs[i] = "1:" + seg
			}
		}
		return coreJoined + "-" + strings.Join(preSegs, " ")
	}
	return coreJoined + "="
}

// validateCompletionValueWithContexts validates completion `weight >= 0` and mandatory `contexts`
// when indexing a document into a `completion` field.
func validateCompletionValueWithContexts(
	docRoot map[string]any,
	node any,
	path []string,
	lowercase bool,
	nullVal any,
	b FieldBinding,
) ([]string, error) {
	var out []string
	if err := collectAndValidateCompletionAtPath(docRoot, node, path, lowercase, nullVal, b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseCompletionWeight(raw any, fieldPath string) error {
	if raw == nil {
		return fmt.Errorf("mapper_parsing_exception: [weight] on completion field [%s] cannot be null", fieldPath)
	}
	switch v := raw.(type) {
	case bool:
		return fmt.Errorf("mapper_parsing_exception: [weight] on completion field [%s] must be a non-negative integer", fieldPath)
	case int:
		if v < 0 {
			return fmt.Errorf("illegal_argument_exception: [weight] on completion field [%s] must be >= 0, got [%d]", fieldPath, v)
		}
		return nil
	case int64:
		if v < 0 {
			return fmt.Errorf("illegal_argument_exception: [weight] on completion field [%s] must be >= 0, got [%d]", fieldPath, v)
		}
		return nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) {
			return fmt.Errorf("mapper_parsing_exception: [weight] on completion field [%s] must be an integer, got [%v]", fieldPath, v)
		}
		if v < 0 {
			return fmt.Errorf("illegal_argument_exception: [weight] on completion field [%s] must be >= 0, got [%v]", fieldPath, int64(v))
		}
		return nil
	case json.Number:
		s := strings.TrimSpace(v.String())
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			if i < 0 {
				return fmt.Errorf("illegal_argument_exception: [weight] on completion field [%s] must be >= 0, got [%d]", fieldPath, i)
			}
			return nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
			return fmt.Errorf("mapper_parsing_exception: [weight] on completion field [%s] must be an integer, got [%s]", fieldPath, s)
		}
		if f < 0 {
			return fmt.Errorf("illegal_argument_exception: [weight] on completion field [%s] must be >= 0, got [%v]", fieldPath, int64(f))
		}
		return nil
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return fmt.Errorf("mapper_parsing_exception: [weight] on completion field [%s] cannot be empty", fieldPath)
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("mapper_parsing_exception: [weight] on completion field [%s] must be an integer, got [%s]", fieldPath, s)
		}
		if i < 0 {
			return fmt.Errorf("illegal_argument_exception: [weight] on completion field [%s] must be >= 0, got [%d]", fieldPath, i)
		}
		return nil
	default:
		return fmt.Errorf("mapper_parsing_exception: [weight] on completion field [%s] must be a non-negative integer", fieldPath)
	}
}

func hasNonEmptyCompletionContextValue(val any, ctxType string) (bool, error) {
	if val == nil {
		return false, nil
	}
	if slice, isSlice := val.([]any); isSlice {
		if len(slice) == 0 {
			return false, nil
		}
		hasOne := false
		for _, elem := range slice {
			ok, err := hasNonEmptyCompletionContextValue(elem, ctxType)
			if err != nil {
				return false, err
			}
			if ok {
				hasOne = true
			}
		}
		return hasOne, nil
	}
	if sSlice, isSS := val.([]string); isSS {
		for _, s := range sSlice {
			if strings.TrimSpace(s) != "" {
				return true, nil
			}
		}
		return false, nil
	}
	if strings.EqualFold(ctxType, "geo") {
		if _, _, _, ok := parseAndFormatGeoPointValue(val); !ok {
			return false, fmt.Errorf("mapper_parsing_exception: failed to parse geo completion context value [%v]", val)
		}
		return true, nil
	}
	switch tv := val.(type) {
	case string:
		return tv != "", nil
	case map[string]any:
		return false, fmt.Errorf("mapper_parsing_exception: category completion context value must be a string, got object")
	default:
		return fmt.Sprintf("%v", tv) != "", nil
	}
}

func validateCompletionEntryContexts(docRoot map[string]any, inlineContextsRaw any, hasInlineContexts bool, b FieldBinding) error {
	if len(b.Contexts) == 0 {
		if hasInlineContexts && inlineContextsRaw != nil {
			return fmt.Errorf("mapper_parsing_exception: context mappings are not defined for completion field [%s]", b.ESFieldPath)
		}
		return nil
	}
	var inlineMap map[string]any
	if hasInlineContexts && inlineContextsRaw != nil {
		m, ok := inlineContextsRaw.(map[string]any)
		if !ok {
			return fmt.Errorf("mapper_parsing_exception: [contexts] on completion field [%s] must be an object", b.ESFieldPath)
		}
		inlineMap = m
	}
	defined := make(map[string]esast.CompletionContextDef, len(b.Contexts))
	for _, cd := range b.Contexts {
		defined[cd.Name] = cd
	}
	for k := range inlineMap {
		if _, ok := defined[k]; !ok {
			return fmt.Errorf("mapper_parsing_exception: unknown completion context [%s] on field [%s]", k, b.ESFieldPath)
		}
	}
	anyContextResolved := false
	for _, cd := range b.Contexts {
		thisResolved := false
		if inlineVal, hasInline := inlineMap[cd.Name]; hasInline {
			ok, err := hasNonEmptyCompletionContextValue(inlineVal, cd.Type)
			if err != nil {
				return err
			}
			if ok {
				anyContextResolved = true
				thisResolved = true
			}
		}
		if !thisResolved && cd.Path != "" && docRoot != nil {
			var candidates []any
			if strings.EqualFold(cd.Type, "geo") {
				candidates = extractGeoPointCandidatesWithNull(docRoot, strings.Split(cd.Path, "."), nil)
			} else {
				candidates = extractRawLeafValuesWithNull(docRoot, strings.Split(cd.Path, "."), nil)
			}
			if len(candidates) > 0 {
				ok, err := hasNonEmptyCompletionContextValue(candidates, cd.Type)
				if err != nil {
					return err
				}
				if ok {
					anyContextResolved = true
					thisResolved = true
				}
			}
		}
		if !thisResolved && cd.Default != nil {
			ok, err := hasNonEmptyCompletionContextValue(cd.Default, cd.Type)
			if err != nil {
				return err
			}
			if ok {
				anyContextResolved = true
				thisResolved = true
			}
		}
		if !thisResolved && len(inlineMap) == 0 {
			return fmt.Errorf("illegal_argument_exception: Contexts are mandatory in context enabled completion field [%s] (missing [%s])", b.ESFieldPath, cd.Name)
		}
	}
	if !anyContextResolved {
		return fmt.Errorf("illegal_argument_exception: Contexts are mandatory in context enabled completion field [%s]", b.ESFieldPath)
	}
	return nil
}

func collectAndValidateCompletionAtPath(
	docRoot map[string]any,
	node any,
	path []string,
	lowercase bool,
	nullVal any,
	b FieldBinding,
	out *[]string,
) error {
	if len(path) == 0 {
		if node == nil {
			if nullVal != nil {
				if err := validateCompletionEntryContexts(docRoot, nil, false, b); err != nil {
					return err
				}
				s := fmt.Sprintf("%v", nullVal)
				if lowercase {
					s = strings.ToLower(s)
				}
				*out = append(*out, s)
			}
			return nil
		}
		switch v := node.(type) {
		case string:
			if err := validateCompletionEntryContexts(docRoot, nil, false, b); err != nil {
				return err
			}
			if lowercase {
				v = strings.ToLower(v)
			}
			*out = append(*out, v)
		case []any:
			for _, item := range v {
				if err := collectAndValidateCompletionAtPath(docRoot, item, nil, lowercase, nullVal, b, out); err != nil {
					return err
				}
			}
		case map[string]any:
			inp, hasInput := v["input"]
			if !hasInput || inp == nil {
				return fmt.Errorf("mapper_parsing_exception: [completion] field object missing required [input]")
			}
			for k := range v {
				switch k {
				case "input", "weight", "contexts":
				default:
					return fmt.Errorf("mapper_parsing_exception: [completion] unknown field [%s]", k)
				}
			}
			if rawW, hasW := v["weight"]; hasW {
				if err := parseCompletionWeight(rawW, b.ESFieldPath); err != nil {
					return err
				}
			}
			rawCtx, hasCtx := v["contexts"]
			if err := validateCompletionEntryContexts(docRoot, rawCtx, hasCtx, b); err != nil {
				return err
			}
			switch iv := inp.(type) {
			case string:
				if lowercase {
					iv = strings.ToLower(iv)
				}
				*out = append(*out, iv)
			case []any:
				for _, elem := range iv {
					if elem == nil {
						continue
					}
					if _, isMap := elem.(map[string]any); isMap {
						return fmt.Errorf("mapper_parsing_exception: [completion] input cannot contain objects")
					}
					s := fmt.Sprintf("%v", elem)
					if lowercase {
						s = strings.ToLower(s)
					}
					*out = append(*out, s)
				}
			default:
				return fmt.Errorf("mapper_parsing_exception: [completion] invalid input value")
			}
		default:
			if err := validateCompletionEntryContexts(docRoot, nil, false, b); err != nil {
				return err
			}
			s := fmt.Sprintf("%v", v)
			if lowercase {
				s = strings.ToLower(s)
			}
			*out = append(*out, s)
		}
		return nil
	}
	if node == nil {
		return nil
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, ok := curr[path[0]]; ok {
			if err := collectAndValidateCompletionAtPath(docRoot, next, path[1:], lowercase, nullVal, b, out); err != nil {
				return err
			}
		}
		for i := 2; i <= len(path); i++ {
			if next, ok := curr[strings.Join(path[:i], ".")]; ok {
				if err := collectAndValidateCompletionAtPath(docRoot, next, path[i:], lowercase, nullVal, b, out); err != nil {
					return err
				}
			}
		}
	case []any:
		for _, elem := range curr {
			if err := collectAndValidateCompletionAtPath(docRoot, elem, path, lowercase, nullVal, b, out); err != nil {
				return err
			}
		}
	}
	return nil
}
