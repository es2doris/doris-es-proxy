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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/painless"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

// formatUnsignedLongOrNumericTermsKeyRound59 formats numeric and unsigned_long `terms` aggregation
// bucket keys as typed JSON numbers (`uint64`, `int64`, `float64`) and attaches `key_as_string`
// when `termsSpec.Format` is configured (`F10`).
// Returns `(key, keyAsStr, hasKeyAsStr, handled)`.
func formatUnsignedLongOrNumericTermsKeyRound59(
	rawKey string,
	termsSpec *esast.TermsAggSpec,
	idxSchema *schema.IndexSchema,
) (any, string, bool, bool) {
	if rawKey == "__ES_MISSING_BUCKET__" {
		return nil, "", false, true
	}
	trimmed := strings.TrimSpace(rawKey)
	if trimmed == "" {
		return rawKey, "", false, false
	}

	var esType string
	var dorisType schema.DorisScalarType
	var vt string
	if termsSpec != nil {
		vt = strings.ToLower(strings.TrimSpace(termsSpec.ValueType))
		if idxSchema != nil && strings.TrimSpace(termsSpec.Field) != "" {
			b := idxSchema.ResolveField(termsSpec.Field)
			esType = b.ESType
			dorisType = b.DorisType
		}
	}
	if vt == "boolean" || vt == "date" || vt == "string" || vt == "ip" ||
		esType == "boolean" || esType == "date" || esType == "date_nanos" ||
		esType == "keyword" || esType == "constant_keyword" || esType == "wildcard" ||
		esType == "text" || esType == "ip" || esType == "version" {
		return rawKey, "", false, false
	}

	isUnsignedLong := vt == "unsigned_long" || esType == "unsigned_long" || dorisType == schema.DorisLargeInt
	isSignedInt := vt == "long" || vt == "integer" || vt == "short" || vt == "byte" ||
		esType == "long" || esType == "integer" || esType == "short" || esType == "byte" ||
		(esType == "" && (dorisType == schema.DorisBigInt || dorisType == schema.DorisInt))
	isFloat := vt == "double" || vt == "float" || vt == "half_float" || vt == "scaled_float" || vt == "number" ||
		esType == "double" || esType == "float" || esType == "half_float" || esType == "scaled_float" ||
		(esType == "" && dorisType == schema.DorisDouble)

	hasFmt := termsSpec != nil && strings.TrimSpace(termsSpec.Format) != ""

	if isUnsignedLong {
		if uv, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
			if hasFmt {
				return uv, formatTermsNumericPattern(float64(uv), termsSpec.Format), true, true
			}
			return uv, "", false, true
		}
		if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			if hasFmt {
				return iv, formatTermsNumericPattern(float64(iv), termsSpec.Format), true, true
			}
			return iv, "", false, true
		}
	}

	if isSignedInt {
		if iv, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			if hasFmt {
				return iv, formatTermsNumericPattern(float64(iv), termsSpec.Format), true, true
			}
			return iv, "", false, true
		}
		if fv, ok := parseFiniteFloat(trimmed); ok && fv == math.Trunc(fv) && fv >= -9223372036854775808.0 && fv < 9223372036854775808.0 {
			iv := int64(fv)
			if hasFmt {
				return iv, formatTermsNumericPattern(fv, termsSpec.Format), true, true
			}
			return iv, "", false, true
		}
	}

	if isFloat {
		if fv, ok := parseFiniteFloat(trimmed); ok {
			if hasFmt {
				return fv, formatTermsNumericPattern(fv, termsSpec.Format), true, true
			}
			return fv, "", false, true
		}
	}

	return rawKey, "", false, false
}

// buildMappingResponseMapRound59 serializes all ES 8.x mapping meta-fields and sections
// (`properties`, `runtime`, `dynamic`, `_routing`, `_meta`, `_source`, `dynamic_templates`,
// `date_detection`, `numeric_detection`, `dynamic_date_formats`, `subobjects`) for `GET _mapping`
// and `GET /{index}` (`F11`).
func buildMappingResponseMapRound59(idxSchema *schema.IndexSchema) map[string]any {
	out := make(map[string]any)
	if idxSchema == nil || idxSchema.RawMapping == nil {
		return out
	}
	rm := idxSchema.RawMapping
	if rm.Properties != nil {
		out["properties"] = rm.Properties
	} else {
		out["properties"] = map[string]esast.FieldProperty{}
	}
	if len(rm.Runtime) > 0 {
		out["runtime"] = rm.Runtime
	}
	if rm.Dynamic != nil {
		out["dynamic"] = rm.Dynamic
	}
	if rm.Routing != nil && rm.Routing.Required {
		out["_routing"] = map[string]any{"required": true}
	}
	if len(rm.Meta) > 0 {
		out["_meta"] = rm.Meta
	}
	if len(rm.Source) > 0 {
		out["_source"] = rm.Source
	}
	if len(rm.DynamicTemplates) > 0 {
		out["dynamic_templates"] = rm.DynamicTemplates
	}
	if rm.DateDetection != nil {
		out["date_detection"] = *rm.DateDetection
	}
	if rm.NumericDetection != nil {
		out["numeric_detection"] = *rm.NumericDetection
	}
	if len(rm.DynamicDateFormats) > 0 {
		out["dynamic_date_formats"] = rm.DynamicDateFormats
	}
	if rm.Subobjects != nil {
		out["subobjects"] = *rm.Subobjects
	}
	return out
}

// isIndexSourceDisabledRound59 reports whether the index mapping disables `_source` (`_source.enabled: false`) (`F11`).
func isIndexSourceDisabledRound59(idxSchema *schema.IndexSchema) bool {
	return idxSchema != nil && idxSchema.SourceDisabled()
}

// filterDocumentSourceRound59 enforces index-level mapping `_source` (`enabled: false` and
// `includes`/`excludes`) followed by per-request `_source` filtering (`F11`).
// Returns `(filteredSource, includeSourceKey)`.
func filterDocumentSourceRound59(
	rawSrc json.RawMessage,
	idxSchema *schema.IndexSchema,
	reqFilter *esast.SourceFilter,
) (json.RawMessage, bool) {
	if isIndexSourceDisabledRound59(idxSchema) {
		return nil, false
	}
	if reqFilter != nil && reqFilter.Disabled {
		return nil, false
	}
	if len(bytes.TrimSpace(rawSrc)) == 0 {
		return nil, false
	}
	cur := rawSrc
	if idxSchema != nil {
		inc, exc := idxSchema.SourceIncludesExcludes()
		if len(inc) > 0 || len(exc) > 0 {
			cur = filterSourceJSON(cur, &esast.SourceFilter{
				Includes: inc,
				Excludes: exc,
			})
		}
	}
	if reqFilter != nil && (len(reqFilter.Includes) > 0 || len(reqFilter.Excludes) > 0) {
		cur = filterSourceJSON(cur, reqFilter)
	}
	return cur, true
}

// applyDynamicRuntimeInferenceRound59 infers `RawMapping.Runtime` entries from incoming documents
// when the index mapping sets `"dynamic": "runtime"` (`F11`).
func applyDynamicRuntimeInferenceRound59(sampleDocs []json.RawMessage, base *esast.MappingSpec) (*esast.MappingSpec, bool) {
	if base == nil || len(sampleDocs) == 0 {
		return base, false
	}
	if s, ok := base.Dynamic.(string); ok && strings.EqualFold(strings.TrimSpace(s), "runtime") {
		mergedRt, added := schema.InferDynamicRuntimeFieldsFromDocs(sampleDocs, base)
		if !added {
			return base, false
		}
		cp := *base
		cp.Runtime = mergedRt
		return &cp, true
	}
	return base, false
}

func extractIndexSettingValueRound59(settings map[string]any, dotKey string) (any, bool) {
	if len(settings) == 0 {
		return nil, false
	}
	trimmedNoIndex := strings.TrimPrefix(dotKey, "index.")
	for _, flatKey := range []string{dotKey, trimmedNoIndex} {
		if v, ok := settings[flatKey]; ok {
			return v, true
		}
	}
	// Walk nested maps both with and without leading "index".
	for _, parts := range [][]string{strings.Split(dotKey, "."), strings.Split(trimmedNoIndex, ".")} {
		cur := any(settings)
		for i, seg := range parts {
			m, ok := cur.(map[string]any)
			if !ok {
				break
			}
			// Check combined suffix key (e.g. settings["index"]["mapping.total_fields.limit"])
			rem := strings.Join(parts[i:], ".")
			if v, exists := m[rem]; exists {
				return v, true
			}
			next, exists := m[seg]
			if !exists {
				break
			}
			if i == len(parts)-1 {
				return next, true
			}
			cur = next
		}
	}
	return nil, false
}

func parseSettingStrictIntRound59(raw any, settingName string, minVal int) (int, error) {
	if raw == nil {
		return 0, fmt.Errorf("illegal_argument_exception: [%s] cannot be null", settingName)
	}
	var iv int64
	var ok bool
	switch v := raw.(type) {
	case int:
		iv, ok = int64(v), true
	case int64:
		iv, ok = v, true
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) && v == math.Trunc(v) && v >= -2147483648 && v <= 2147483647 {
			iv, ok = int64(v), true
		}
	case json.Number:
		if parsed, err := v.Int64(); err == nil {
			iv, ok = parsed, true
		}
	case string:
		if parsed, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			iv, ok = parsed, true
		}
	}
	if !ok || iv > math.MaxInt32 || iv < int64(minVal) {
		return 0, fmt.Errorf("illegal_argument_exception: Failed to parse value [%v] for setting [%s] must be >= %d", raw, settingName, minVal)
	}
	return int(iv), nil
}

func parseSettingStrictBoolRound59(raw any, settingName string) (bool, error) {
	switch v := raw.(type) {
	case bool:
		return v, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, fmt.Errorf("illegal_argument_exception: Failed to parse value [%v] as only [true] or [false] are allowed for [%s]", raw, settingName)
}

// parseAndApplyIndexMappingSettingsRound59 validates and applies ES 8.x `index.mapping.*` limits
// and defaults (`total_fields.limit`, `depth.limit`, `nested_fields.limit`, `nested_objects.limit`,
// `field_name_length.limit`, `coerce`, `ignore_malformed`) plus `index.max_terms_count` (`F12`, `F17`).
func parseAndApplyIndexMappingSettingsRound59(settings map[string]any, idxSchema *schema.IndexSchema) error {
	if len(settings) == 0 {
		return nil
	}
	var (
		hasTotalFields  bool
		totalFieldsLim  int
		hasDepth        bool
		depthLim        int
		hasNestedFields bool
		nestedFieldsLim int
		hasNestedObjs   bool
		nestedObjsLim   int
		hasFieldNameLen bool
		fieldNameLenLim int
		hasCoerce       bool
		coerceVal       bool
		hasIgnoreMal    bool
		ignoreMalVal    bool
		hasMaxTerms     bool
		maxTermsLim     int
	)

	if raw, ok := extractIndexSettingValueRound59(settings, "index.mapping.total_fields.limit"); ok {
		v, err := parseSettingStrictIntRound59(raw, "index.mapping.total_fields.limit", 0)
		if err != nil {
			return err
		}
		hasTotalFields, totalFieldsLim = true, v
	}
	if raw, ok := extractIndexSettingValueRound59(settings, "index.mapping.depth.limit"); ok {
		v, err := parseSettingStrictIntRound59(raw, "index.mapping.depth.limit", 1)
		if err != nil {
			return err
		}
		hasDepth, depthLim = true, v
	}
	if raw, ok := extractIndexSettingValueRound59(settings, "index.mapping.nested_fields.limit"); ok {
		v, err := parseSettingStrictIntRound59(raw, "index.mapping.nested_fields.limit", 0)
		if err != nil {
			return err
		}
		hasNestedFields, nestedFieldsLim = true, v
	}
	if raw, ok := extractIndexSettingValueRound59(settings, "index.mapping.nested_objects.limit"); ok {
		v, err := parseSettingStrictIntRound59(raw, "index.mapping.nested_objects.limit", 0)
		if err != nil {
			return err
		}
		hasNestedObjs, nestedObjsLim = true, v
	}
	if raw, ok := extractIndexSettingValueRound59(settings, "index.mapping.field_name_length.limit"); ok {
		v, err := parseSettingStrictIntRound59(raw, "index.mapping.field_name_length.limit", 1)
		if err != nil {
			return err
		}
		hasFieldNameLen, fieldNameLenLim = true, v
	}
	if raw, ok := extractIndexSettingValueRound59(settings, "index.mapping.coerce"); ok {
		v, err := parseSettingStrictBoolRound59(raw, "index.mapping.coerce")
		if err != nil {
			return err
		}
		hasCoerce, coerceVal = true, v
	}
	if raw, ok := extractIndexSettingValueRound59(settings, "index.mapping.ignore_malformed"); ok {
		v, err := parseSettingStrictBoolRound59(raw, "index.mapping.ignore_malformed")
		if err != nil {
			return err
		}
		hasIgnoreMal, ignoreMalVal = true, v
	}
	if raw, ok := extractIndexSettingValueRound59(settings, "index.max_terms_count"); ok {
		v, err := parseSettingStrictIntRound59(raw, "index.max_terms_count", 1)
		if err != nil {
			return err
		}
		hasMaxTerms, maxTermsLim = true, v
	}

	if idxSchema == nil {
		return nil
	}

	// Validate candidate limits against existing mapping before mutating idxSchema.
	cand := *idxSchema
	if hasTotalFields {
		cand.MaxTotalFields = totalFieldsLim
	}
	if hasDepth {
		cand.MaxDepth = depthLim
	}
	if hasNestedFields {
		cand.MaxNestedFields = nestedFieldsLim
		cand.HasExplicitNestedLimit = true
	}
	if hasNestedObjs {
		cand.MaxNestedObjects = nestedObjsLim
	}
	if hasFieldNameLen {
		cand.MaxFieldNameLength = fieldNameLenLim
	}
	if hasCoerce {
		cv := coerceVal
		cand.DefaultCoerce = &cv
	}
	if hasIgnoreMal {
		iv := ignoreMalVal
		cand.DefaultIgnoreMalformed = &iv
	}
	if hasMaxTerms {
		cand.MaxTermsCount = maxTermsLim
	}
	if cand.RawMapping != nil {
		if err := schema.ValidateMappingLimits(&cand, cand.RawMapping); err != nil {
			return err
		}
	}

	*idxSchema = cand
	return nil
}

func extractFirstConstantKeywordScalarAtPathRound59(curr any, segs []string) (string, bool, error) {
	if curr == nil {
		return "", false, nil
	}
	if len(segs) == 0 {
		switch v := curr.(type) {
		case map[string]any:
			return "", false, fmt.Errorf("mapper_parsing_exception: failed to parse constant_keyword field: expected scalar value, got object")
		case []any:
			var adopted string
			hasAdopted := false
			for _, elem := range v {
				val, ok, err := extractFirstConstantKeywordScalarAtPathRound59(elem, nil)
				if err != nil {
					return "", false, err
				}
				if !ok {
					continue
				}
				if !hasAdopted {
					adopted = val
					hasAdopted = true
				} else if val != adopted {
					return "", false, fmt.Errorf("mapper_parsing_exception: [constant_keyword] field only accepts values that are equal to the value defined in the mappings [%s], but got [%s]", adopted, val)
				}
			}
			return adopted, hasAdopted, nil
		case string:
			return v, true, nil
		case json.Number:
			return v.String(), true, nil
		case bool:
			return strconv.FormatBool(v), true, nil
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64), true, nil
		default:
			return fmt.Sprintf("%v", v), true, nil
		}
	}
	switch m := curr.(type) {
	case map[string]any:
		next, exists := m[segs[0]]
		if !exists {
			return "", false, nil
		}
		return extractFirstConstantKeywordScalarAtPathRound59(next, segs[1:])
	case []any:
		var adopted string
		hasAdopted := false
		for _, elem := range m {
			val, ok, err := extractFirstConstantKeywordScalarAtPathRound59(elem, segs)
			if err != nil {
				return "", false, err
			}
			if !ok {
				continue
			}
			if !hasAdopted {
				adopted = val
				hasAdopted = true
			} else if val != adopted {
				return "", false, fmt.Errorf("mapper_parsing_exception: [constant_keyword] field only accepts values that are equal to the value defined in the mappings [%s], but got [%s]", adopted, val)
			}
		}
		return adopted, hasAdopted, nil
	default:
		return "", false, nil
	}
}

func setConstantKeywordValueInPropsRound59(props map[string]esast.FieldProperty, segs []string, val string) bool {
	if len(props) == 0 || len(segs) == 0 {
		return false
	}
	head := segs[0]
	prop, ok := props[head]
	if !ok {
		return false
	}
	if len(segs) == 1 {
		if prop.Type == "constant_keyword" {
			prop.Value = val
			props[head] = prop
			return true
		}
		return false
	}
	if len(segs) == 2 && len(prop.Fields) > 0 {
		if mf, hasSub := prop.Fields[segs[1]]; hasSub && mf.Type == "constant_keyword" {
			mf.Value = val
			prop.Fields[segs[1]] = mf
			props[head] = prop
			return true
		}
	}
	if setConstantKeywordValueInPropsRound59(prop.Properties, segs[1:], val) {
		props[head] = prop
		return true
	}
	return false
}

// adoptConstantKeywordValuesFromDocsRound59 adopts and locks the first non-null scalar value for
// any `constant_keyword` field whose mapping omitted `"value"` (`!fb.HasConstantValue`) (`F13`).
func adoptConstantKeywordValuesFromDocsRound59(idxSchema *schema.IndexSchema, docs []json.RawMessage) (bool, error) {
	if idxSchema == nil || len(idxSchema.Fields) == 0 || len(docs) == 0 {
		return false, nil
	}
	var uninitialized []string
	for fname, fb := range idxSchema.Fields {
		if fb.ESType == "constant_keyword" && !fb.HasConstantValue {
			uninitialized = append(uninitialized, fname)
		}
	}
	if len(uninitialized) == 0 {
		return false, nil
	}
	sort.Strings(uninitialized)

	decodedDocs := make([]map[string]any, 0, len(docs))
	for _, raw := range docs {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var dm map[string]any
		if err := dec.Decode(&dm); err == nil && dm != nil {
			decodedDocs = append(decodedDocs, dm)
		}
	}
	if len(decodedDocs) == 0 {
		return false, nil
	}

	updated := false
	for _, fname := range uninitialized {
		fb := idxSchema.Fields[fname]
		pathSegs := fb.SourceJSONPath
		if len(pathSegs) == 0 {
			pathSegs = strings.Split(fname, ".")
		}
		var adopted string
		hasAdopted := false
		for _, dm := range decodedDocs {
			val, ok, err := extractFirstConstantKeywordScalarAtPathRound59(dm, pathSegs)
			if err != nil {
				return updated, err
			}
			if !ok {
				continue
			}
			if !hasAdopted {
				adopted = val
				hasAdopted = true
			} else if val != adopted {
				return updated, fmt.Errorf("mapper_parsing_exception: [constant_keyword] field [%s] only accepts values that are equal to the value defined in the mappings [%s], but got [%s]", fname, adopted, val)
			}
		}
		if hasAdopted {
			fb.ConstantValue = adopted
			fb.HasConstantValue = true
			idxSchema.Fields[fname] = fb
			if idxSchema.RawMapping != nil && idxSchema.RawMapping.Properties != nil {
				setConstantKeywordValueInPropsRound59(idxSchema.RawMapping.Properties, strings.Split(fname, "."), adopted)
			}
			updated = true
		}
	}
	return updated, nil
}

// compareCompositeVersionValuesRound59 compares `composite` aggregation `terms` bucket values on
// `version` fields using Semantic Versioning 2.0.0 precedence (`F15`).
// Returns `(cmp, true)` when the composite source is a `version` field, or `(0, false)` otherwise.
func compareCompositeVersionValuesRound59(
	a, b any,
	entry esast.AggSpec,
	desc bool,
	idxSchema *schema.IndexSchema,
) (int, bool) {
	if entry.Terms == nil {
		return 0, false
	}
	isVersion := strings.EqualFold(strings.TrimSpace(entry.Terms.ValueType), "version")
	if !isVersion && idxSchema != nil && strings.TrimSpace(entry.Terms.Field) != "" {
		fb := idxSchema.ResolveField(entry.Terms.Field)
		isVersion = fb.ESType == "version"
	}
	if !isVersion {
		return 0, false
	}
	cmp := transpiler.CompareSemverStrings(fmt.Sprintf("%v", a), fmt.Sprintf("%v", b))
	if desc {
		cmp = -cmp
	}
	return cmp, true
}

// evalFieldValueFactorOnDocRound59 evaluates a `field_value_factor` function on `doc` with exact
// ES 8.x `1/x` `reciprocal`, missing-field `0.0` (when `missing` is unset), and domain-violation
// error reporting (`F18`).
func evalFieldValueFactorOnDocRound59(
	idxSchema *schema.IndexSchema,
	doc map[string]any,
	fvf *esast.FieldValueFactorSpec,
) (float64, bool, error) {
	if fvf == nil || fvf.Field == "" {
		return 0, false, nil
	}
	clean := strings.TrimSuffix(strings.TrimSuffix(fvf.Field, ".keyword"), ".ngram")
	pathSegs := strings.Split(clean, ".")
	if idxSchema != nil {
		if b := idxSchema.ResolveField(fvf.Field); len(b.SourceJSONPath) > 0 {
			pathSegs = b.SourceJSONPath
		}
	}
	rawVals := collectSchemaAwareScalarValues(doc, fvf.Field, pathSegs, idxSchema)
	var rawNum float64
	found := false
	for _, rv := range rawVals {
		if f, ok := toFloat64(rv); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
			rawNum = f
			found = true
			break
		}
	}
	if !found {
		if fvf.Missing == nil {
			// ES 8.x: when `missing` is omitted and the document has no value for `field`,
			// `field_value_factor` produces score `0.0` directly without applying `modifier(0)`.
			return 0.0, true, nil
		}
		f, ok := toFloat64(fvf.Missing)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false, fmt.Errorf("search_phase_execution_exception: invalid [missing] value [%v] in field_value_factor on field [%s]", fvf.Missing, fvf.Field)
		}
		rawNum = f
	}
	factor := 1.0
	if fvf.Factor != nil {
		factor = *fvf.Factor
	}
	v := rawNum * factor
	mod := strings.ToLower(strings.TrimSpace(fvf.Modifier))
	switch mod {
	case "", "none":
	case "log":
		if v <= 0 {
			return 0, false, fmt.Errorf("search_phase_execution_exception: field_value_factor modifier [log] requires positive value, got [%v] on field [%s]", v, fvf.Field)
		}
		v = math.Log10(v)
	case "log1p":
		if 1.0+v <= 0 {
			return 0, false, fmt.Errorf("search_phase_execution_exception: field_value_factor modifier [log1p] requires value > -1, got [%v] on field [%s]", v, fvf.Field)
		}
		v = math.Log10(1.0 + v)
	case "log2p":
		if 2.0+v <= 0 {
			return 0, false, fmt.Errorf("search_phase_execution_exception: field_value_factor modifier [log2p] requires value > -2, got [%v] on field [%s]", v, fvf.Field)
		}
		v = math.Log10(2.0 + v)
	case "ln":
		if v <= 0 {
			return 0, false, fmt.Errorf("search_phase_execution_exception: field_value_factor modifier [ln] requires positive value, got [%v] on field [%s]", v, fvf.Field)
		}
		v = math.Log(v)
	case "ln1p":
		if 1.0+v <= 0 {
			return 0, false, fmt.Errorf("search_phase_execution_exception: field_value_factor modifier [ln1p] requires value > -1, got [%v] on field [%s]", v, fvf.Field)
		}
		v = math.Log(1.0 + v)
	case "ln2p":
		if 2.0+v <= 0 {
			return 0, false, fmt.Errorf("search_phase_execution_exception: field_value_factor modifier [ln2p] requires value > -2, got [%v] on field [%s]", v, fvf.Field)
		}
		v = math.Log(2.0 + v)
	case "square":
		v = v * v
	case "sqrt":
		if v < 0 {
			return 0, false, fmt.Errorf("search_phase_execution_exception: field_value_factor modifier [sqrt] requires non-negative value, got [%v] on field [%s]", v, fvf.Field)
		}
		v = math.Sqrt(v)
	case "reciprocal":
		if v == 0 {
			return 0, false, fmt.Errorf("search_phase_execution_exception: field_value_factor modifier [reciprocal] division by zero on field [%s]", fvf.Field)
		}
		v = 1.0 / v
	default:
		return 0, false, fmt.Errorf("search_phase_execution_exception: unknown field_value_factor modifier [%s]", fvf.Modifier)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0, false, fmt.Errorf("search_phase_execution_exception: field_value_factor produced invalid score [%v] (scores must be non-negative finite numbers) on field [%s]", v, fvf.Field)
	}
	return v, true, nil
}

// queryProducesCustomScoreRound59 reports whether `q` contains any `script_score` or
// `function_score` clause whose per-document score must be validated as finite and `>= 0` (`F18`).
func queryProducesCustomScoreRound59(q *esast.Query) bool {
	if q == nil {
		return false
	}
	if q.ScriptScore != nil || q.FunctionScore != nil {
		return true
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if queryProducesCustomScoreRound59(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if queryProducesCustomScoreRound59(&q.Bool.Should[i]) {
				return true
			}
		}
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if queryProducesCustomScoreRound59(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil {
		return queryProducesCustomScoreRound59(&q.Boosting.Positive)
	}
	if q.ConstantScore != nil {
		return false
	}
	return false
}

// validateNonNegativeFiniteSearchScoreRound59 validates a document `_score`: when
// `hasCustomScoreQuery` is true (`script_score` / `function_score`), any negative, `NaN`, or
// `±Inf` score returns a `400 search_phase_execution_exception` error (`F18`).
func validateNonNegativeFiniteSearchScoreRound59(hasCustomScoreQuery bool, score float64) (float64, error) {
	if hasCustomScoreQuery {
		if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 {
			return 0, fmt.Errorf("search_phase_execution_exception: script_score / function_score query produced an invalid score [%v]; scores must be non-negative finite numbers", score)
		}
		return score, nil
	}
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return 0.0, nil
	}
	return score, nil
}

// evalRuntimeSearchScoreWithErrorRound59 evaluates `script_score` and `function_score` queries on
// `doc` and returns an error (`400 search_phase_execution_exception`) if any script runtime error,
// `field_value_factor` domain violation, `NaN`, `±Inf`, or negative score occurs (`F18`).
func evalRuntimeSearchScoreWithErrorRound59(
	idxSchema *schema.IndexSchema,
	doc map[string]any,
	q *esast.Query,
	baseScore float64,
) (float64, error) {
	if q == nil {
		return validateNonNegativeFiniteSearchScoreRound59(false, baseScore)
	}
	if q.ScriptScore != nil && q.ScriptScore.Script != nil {
		if q.ScriptScore.Query != nil {
			if !evalBranchMatchesDoc(idxSchema, doc, q.ScriptScore.Query) {
				return 0.0, nil
			}
			if queryProducesCustomScoreRound59(q.ScriptScore.Query) {
				subScore, err := evalRuntimeSearchScoreWithErrorRound59(idxSchema, doc, q.ScriptScore.Query, baseScore)
				if err != nil {
					return 0, err
				}
				baseScore = subScore
			} else if baseScore == 1.0 {
				baseScore = scoreNonScriptClauseOnDoc(idxSchema, doc, q.ScriptScore.Query)
			}
		}
		src, params := extractScriptSourceAndParams(q.ScriptScore.Script)
		if src != "" {
			cp := make(map[string]any, len(params)+1)
			for k, v := range params {
				cp[k] = v
			}
			cp["_score"] = baseScore
			evalDoc := prepareDocForRuntimeScript(idxSchema, doc)
			fv, ok, err := painless.EvalNumber(evalDoc, src, cp)
			if err != nil {
				return 0, fmt.Errorf("search_phase_execution_exception: script_score runtime error: %w", err)
			}
			if !ok {
				return 0, fmt.Errorf("search_phase_execution_exception: script_score script must return a numeric value")
			}
			if q.ScriptScore.Boost != nil {
				fv *= *q.ScriptScore.Boost
			}
			return validateNonNegativeFiniteSearchScoreRound59(true, fv)
		}
	}
	if q.FunctionScore != nil {
		if q.FunctionScore.Query != nil {
			if !evalBranchMatchesDoc(idxSchema, doc, q.FunctionScore.Query) {
				return 0.0, nil
			}
			if queryProducesCustomScoreRound59(q.FunctionScore.Query) {
				subScore, err := evalRuntimeSearchScoreWithErrorRound59(idxSchema, doc, q.FunctionScore.Query, baseScore)
				if err != nil {
					return 0, err
				}
				baseScore = subScore
			} else if baseScore == 1.0 {
				baseScore = scoreNonScriptClauseOnDoc(idxSchema, doc, q.FunctionScore.Query)
			}
		}
		evalDoc := prepareDocForRuntimeScript(idxSchema, doc)
		var fnScores []float64
		if q.FunctionScore.ScriptScore != nil && q.FunctionScore.ScriptScore.Script != nil {
			src, params := extractScriptSourceAndParams(q.FunctionScore.ScriptScore.Script)
			if src != "" {
				cp := make(map[string]any, len(params)+1)
				for k, v := range params {
					cp[k] = v
				}
				cp["_score"] = baseScore
				fv, ok, err := painless.EvalNumber(evalDoc, src, cp)
				if err != nil {
					return 0, fmt.Errorf("search_phase_execution_exception: function_score script_score runtime error: %w", err)
				}
				if !ok {
					return 0, fmt.Errorf("search_phase_execution_exception: function_score script_score must return a numeric value")
				}
				if _, err := validateNonNegativeFiniteSearchScoreRound59(true, fv); err != nil {
					return 0, err
				}
				if q.FunctionScore.Weight != nil {
					fv *= *q.FunctionScore.Weight
				}
				fnScores = append(fnScores, fv)
			}
		}
		if q.FunctionScore.FieldValueFactor != nil {
			fv, ok, err := evalFieldValueFactorOnDocRound59(idxSchema, doc, q.FunctionScore.FieldValueFactor)
			if err != nil {
				return 0, err
			}
			if ok {
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
		} else if q.FunctionScore.ScriptScore == nil && len(q.FunctionScore.Functions) == 0 && q.FunctionScore.Weight != nil {
			fnScores = append(fnScores, *q.FunctionScore.Weight)
		}
		for _, fn := range q.FunctionScore.Functions {
			if fn.Filter != nil && !evalBranchMatchesDoc(idxSchema, doc, fn.Filter) {
				continue
			}
			hasVal := false
			val := 1.0
			if fn.ScriptScore != nil && fn.ScriptScore.Script != nil {
				src, params := extractScriptSourceAndParams(fn.ScriptScore.Script)
				if src != "" {
					cp := make(map[string]any, len(params)+1)
					for k, v := range params {
						cp[k] = v
					}
					cp["_score"] = baseScore
					fv, ok, err := painless.EvalNumber(evalDoc, src, cp)
					if err != nil {
						return 0, fmt.Errorf("search_phase_execution_exception: function_score script_score runtime error: %w", err)
					}
					if !ok {
						return 0, fmt.Errorf("search_phase_execution_exception: function_score script_score must return a numeric value")
					}
					if _, err := validateNonNegativeFiniteSearchScoreRound59(true, fv); err != nil {
						return 0, err
					}
					val = fv
					hasVal = true
				}
			} else if fn.FieldValueFactor != nil {
				fv, ok, err := evalFieldValueFactorOnDocRound59(idxSchema, doc, fn.FieldValueFactor)
				if err != nil {
					return 0, err
				}
				if ok {
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
				if _, err := validateNonNegativeFiniteSearchScoreRound59(true, val); err != nil {
					return 0, err
				}
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
		res := applyFunctionScoreBoostMode(baseScore, combined, q.FunctionScore.BoostMode)
		if q.FunctionScore.Boost != nil {
			res *= *q.FunctionScore.Boost
		}
		return validateNonNegativeFiniteSearchScoreRound59(true, res)
	}
	if q.Bool != nil {
		var total float64
		for i := range q.Bool.Must {
			sub := &q.Bool.Must[i]
			if !evalBranchMatchesDoc(idxSchema, doc, sub) {
				return 0.0, nil
			}
			if queryProducesCustomScoreRound59(sub) {
				sc, err := evalRuntimeSearchScoreWithErrorRound59(idxSchema, doc, sub, 1.0)
				if err != nil {
					return 0, err
				}
				total += sc
			} else {
				total += scoreNonScriptClauseOnDoc(idxSchema, doc, sub)
			}
		}
		for i := range q.Bool.Should {
			sub := &q.Bool.Should[i]
			if evalBranchMatchesDoc(idxSchema, doc, sub) {
				if queryProducesCustomScoreRound59(sub) {
					sc, err := evalRuntimeSearchScoreWithErrorRound59(idxSchema, doc, sub, 1.0)
					if err != nil {
						return 0, err
					}
					total += sc
				} else {
					total += scoreNonScriptClauseOnDoc(idxSchema, doc, sub)
				}
			}
		}
		if q.Bool.Boost != nil {
			total *= *q.Bool.Boost
		}
		return validateNonNegativeFiniteSearchScoreRound59(queryProducesCustomScoreRound59(q), total)
	}
	if q.DisMax != nil {
		var best float64
		var rest float64
		hasMatch := false
		for i := range q.DisMax.Queries {
			sub := &q.DisMax.Queries[i]
			if !evalBranchMatchesDoc(idxSchema, doc, sub) {
				continue
			}
			var sc float64
			if queryProducesCustomScoreRound59(sub) {
				var err error
				sc, err = evalRuntimeSearchScoreWithErrorRound59(idxSchema, doc, sub, 1.0)
				if err != nil {
					return 0, err
				}
			} else {
				sc = scoreNonScriptClauseOnDoc(idxSchema, doc, sub)
			}
			if !hasMatch {
				best = sc
				hasMatch = true
			} else if sc > best {
				rest += best
				best = sc
			} else {
				rest += sc
			}
		}
		if !hasMatch {
			return 0.0, nil
		}
		res := best + q.DisMax.TieBreaker*rest
		if q.DisMax.Boost != nil {
			res *= *q.DisMax.Boost
		}
		return validateNonNegativeFiniteSearchScoreRound59(queryProducesCustomScoreRound59(q), res)
	}
	if q.Boosting != nil {
		if !evalBranchMatchesDoc(idxSchema, doc, &q.Boosting.Positive) {
			return 0.0, nil
		}
		sc, err := evalRuntimeSearchScoreWithErrorRound59(idxSchema, doc, &q.Boosting.Positive, 1.0)
		if err != nil {
			return 0, err
		}
		if evalBranchMatchesDoc(idxSchema, doc, &q.Boosting.Negative) {
			sc *= q.Boosting.NegativeBoost
		}
		if q.Boosting.Boost != nil {
			sc *= *q.Boosting.Boost
		}
		return validateNonNegativeFiniteSearchScoreRound59(queryProducesCustomScoreRound59(q), sc)
	}
	sc := evalQueryScriptScoreOnDocWithSchema(idxSchema, doc, q, baseScore)
	return validateNonNegativeFiniteSearchScoreRound59(queryProducesCustomScoreRound59(q), sc)
}

func resolveDateHistogramLocRound59(spec *esast.DateHistogramAggSpec) (*time.Location, int64, bool) {
	if spec == nil {
		return time.UTC, 0, true
	}
	loc, fixedMs, isFixed, err := esast.ParseESTimeZone(strings.TrimSpace(spec.TimeZone))
	if err != nil || loc == nil {
		return time.UTC, 0, true
	}
	return loc, fixedMs, isFixed
}

func adjustWallTimeInLocRound59(y int, m time.Month, d, hh, mm, ss int, loc *time.Location) time.Time {
	inst := time.Date(y, m, d, hh, mm, ss, 0, loc)
	if loc != time.UTC && (inst.Year() != y || inst.Month() != m || inst.Day() != d || inst.Hour() != hh || inst.Minute() != mm) {
		wantWall := time.Date(y, m, d, hh, mm, ss, 0, time.UTC)
		gotWall := time.Date(inst.Year(), inst.Month(), inst.Day(), inst.Hour(), inst.Minute(), inst.Second(), 0, time.UTC)
		if gotWall.Before(wantWall) {
			for step := 15 * time.Minute; step <= 3*time.Hour; step += 15 * time.Minute {
				cand := inst.Add(step)
				cw := time.Date(cand.Year(), cand.Month(), cand.Day(), cand.Hour(), cand.Minute(), cand.Second(), 0, time.UTC)
				if !cw.Before(wantWall) {
					return cand
				}
			}
		}
	}
	return inst
}

// floorDateHistogramBucketMillisRound59 floors `ms` (epoch milliseconds) to the start of its
// `date_histogram` bucket, honoring calendar units (`minute`, `hour`, `day`, `week` ISO Monday,
// `month`, `quarter`, `year`), IANA DST timezones, and `offset` (`F19`).
func floorDateHistogramBucketMillisRound59(ms int64, spec *esast.DateHistogramAggSpec) int64 {
	if spec == nil {
		return ms
	}
	offsetMs := spec.EffectiveOffsetMs()
	loc, fixedTzMs, isFixed := resolveDateHistogramLocRound59(spec)
	if unit := spec.EffectiveCalendarUnit(); unit != "" {
		shifted := time.UnixMilli(ms - offsetMs).In(loc)
		y, m, d := shifted.Date()
		hh, mm, ss := shifted.Clock()
		var start time.Time
		switch unit {
		case "minute":
			start = adjustWallTimeInLocRound59(y, m, d, hh, mm, 0, loc)
		case "hour":
			start = adjustWallTimeInLocRound59(y, m, d, hh, 0, 0, loc)
		case "day":
			start = adjustWallTimeInLocRound59(y, m, d, 0, 0, 0, loc)
		case "week":
			base := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
			daysBack := (int(base.Weekday()) + 6) % 7
			mon := base.AddDate(0, 0, -daysBack)
			start = adjustWallTimeInLocRound59(mon.Year(), mon.Month(), mon.Day(), 0, 0, 0, loc)
		case "month":
			start = adjustWallTimeInLocRound59(y, m, 1, 0, 0, 0, loc)
		case "quarter":
			qm := time.Month(((int(m)-1)/3)*3 + 1)
			start = adjustWallTimeInLocRound59(y, qm, 1, 0, 0, 0, loc)
		case "year":
			start = adjustWallTimeInLocRound59(y, time.January, 1, 0, 0, 0, loc)
		default:
			_ = ss
			start = adjustWallTimeInLocRound59(y, m, d, 0, 0, 0, loc)
		}
		return start.UnixMilli() + offsetMs
	}
	intervalMs := spec.EffectiveIntervalMs()
	if intervalMs <= 0 {
		intervalMs = 86400000
	}
	tzMs := fixedTzMs
	if !isFixed {
		_, offSec := time.UnixMilli(ms).In(loc).Zone()
		tzMs = int64(offSec) * 1000
	}
	tzShiftMs := tzMs - offsetMs
	return int64(math.Floor(float64(ms+tzShiftMs)/float64(intervalMs)))*intervalMs - tzShiftMs
}

// stepDateHistogramBucketMillisRound59 advances a floored `date_histogram` bucket start `ms`
// to the exact next bucket boundary in `spec.TimeZone` (handling variable-length months/quarters/years
// and 23-hour/25-hour DST days) (`F19`).
func stepDateHistogramBucketMillisRound59(ms int64, spec *esast.DateHistogramAggSpec) int64 {
	if spec == nil {
		return ms + 86400000
	}
	offsetMs := spec.EffectiveOffsetMs()
	loc, _, _ := resolveDateHistogramLocRound59(spec)
	if unit := spec.EffectiveCalendarUnit(); unit != "" {
		cur := time.UnixMilli(ms - offsetMs).In(loc)
		y, m, d := cur.Date()
		var next time.Time
		switch unit {
		case "minute":
			next = cur.Add(time.Minute)
		case "hour":
			next = cur.Add(time.Hour)
		case "day":
			nextWall := time.Date(y, m, d, 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
			next = adjustWallTimeInLocRound59(nextWall.Year(), nextWall.Month(), nextWall.Day(), 0, 0, 0, loc)
		case "week":
			nextWall := time.Date(y, m, d, 0, 0, 0, 0, time.UTC).AddDate(0, 0, 7)
			next = adjustWallTimeInLocRound59(nextWall.Year(), nextWall.Month(), nextWall.Day(), 0, 0, 0, loc)
		case "month":
			nextWall := time.Date(y, m, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
			next = adjustWallTimeInLocRound59(nextWall.Year(), nextWall.Month(), 1, 0, 0, 0, loc)
		case "quarter":
			qm := time.Month(((int(m)-1)/3)*3 + 1)
			nextWall := time.Date(y, qm, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 3, 0)
			next = adjustWallTimeInLocRound59(nextWall.Year(), nextWall.Month(), 1, 0, 0, 0, loc)
		case "year":
			next = adjustWallTimeInLocRound59(y+1, time.January, 1, 0, 0, 0, loc)
		default:
			next = cur.Add(24 * time.Hour)
		}
		res := next.UnixMilli() + offsetMs
		if res <= ms {
			return ms + 1
		}
		return res
	}
	intervalMs := spec.EffectiveIntervalMs()
	if intervalMs <= 0 {
		intervalMs = 86400000
	}
	return ms + intervalMs
}

func parseDateHistogramBoundMsRound59(raw any, spec *esast.DateHistogramAggSpec, nowUTC time.Time, roundUp bool) (int64, bool) {
	if raw == nil {
		return 0, false
	}
	loc, _, _ := resolveDateHistogramLocRound59(spec)
	// For string bounds without an explicit zone offset, compute the offset at that wall clock in `loc`.
	tzStr := ""
	if spec != nil {
		tzStr = strings.TrimSpace(spec.TimeZone)
	}
	if s, isStr := raw.(string); isStr {
		trimmed := strings.TrimSpace(s)
		fmtStr := ""
		if spec != nil {
			fmtStr = spec.Format
		}
		if ms, ok := schema.ParseESDateBoundWithFormatToEpochMillis(trimmed, fmtStr, nowUTC, roundUp); ok {
			datePart := trimmed
			if idx := strings.Index(datePart, "||"); idx >= 0 {
				datePart = strings.TrimSpace(datePart[:idx])
			}
			if _, numErr := strconv.ParseFloat(datePart, 64); numErr != nil &&
				tzStr != "" && loc != time.UTC &&
				!strings.HasPrefix(datePart, "now") &&
				!strings.HasSuffix(datePart, "Z") && !strings.HasSuffix(datePart, "z") &&
				!strings.Contains(datePart[min(10, len(datePart)):], "+") &&
				!strings.Contains(datePart[min(10, len(datePart)):], "-") {
				u := time.UnixMilli(ms).UTC()
				localInst := adjustWallTimeInLocRound59(u.Year(), u.Month(), u.Day(), u.Hour(), u.Minute(), u.Second(), loc)
				return localInst.UnixMilli() + int64(u.Nanosecond()/1_000_000), true
			}
			return ms, true
		}
	}
	boundRngSpec := &esast.RangeAggSpec{}
	if spec != nil {
		boundRngSpec.Format = spec.Format
		boundRngSpec.TimeZone = spec.TimeZone
	}
	if ms, ok := parseRuntimeDateRangeBoundMillis(raw, boundRngSpec, nowUTC); ok {
		return ms, true
	}
	return schema.ParseESDateBoundToEpochMillis(fmt.Sprintf("%v", raw), nowUTC, roundUp)
}

// synthesizeDateHistogramBucketsRound59 filters `hard_bounds`, enforces `min_doc_count`, and
// synthesizes empty calendar/fixed `date_histogram` buckets across observed and `extended_bounds`
// ranges when `min_doc_count == 0` (`F19`).
func synthesizeDateHistogramBucketsRound59(rows []AggRow, spec *esast.DateHistogramAggSpec) []AggRow {
	if spec == nil {
		return rows
	}
	nowUTC := time.Now().UTC()
	var hardMin, hardMax int64
	hasHardMin, hasHardMax := false, false
	if spec.HardBounds != nil {
		if spec.HardBounds.Min != nil {
			if ms, ok := parseDateHistogramBoundMsRound59(spec.HardBounds.Min, spec, nowUTC, false); ok {
				hardMin = floorDateHistogramBucketMillisRound59(ms, spec)
				hasHardMin = true
			}
		}
		if spec.HardBounds.Max != nil {
			if ms, ok := parseDateHistogramBoundMsRound59(spec.HardBounds.Max, spec, nowUTC, true); ok {
				hardMax = floorDateHistogramBucketMillisRound59(ms, spec)
				hasHardMax = true
			}
		}
	}
	if hasHardMin || hasHardMax {
		filtered := make([]AggRow, 0, len(rows))
		for _, r := range rows {
			k, err := strconv.ParseInt(r.BucketKey, 10, 64)
			if err != nil {
				continue
			}
			if (hasHardMin && k < hardMin) || (hasHardMax && k > hardMax) {
				continue
			}
			filtered = append(filtered, r)
		}
		rows = filtered
	}

	// Empty-bucket synthesis only runs when `min_doc_count` is explicitly `0`.
	if spec.MinDocCount == nil || *spec.MinDocCount > 0 {
		if spec.MinDocCount != nil && *spec.MinDocCount > 0 {
			minCnt := int64(*spec.MinDocCount)
			filtered := make([]AggRow, 0, len(rows))
			for _, r := range rows {
				if r.effectiveCount() >= minCnt {
					filtered = append(filtered, r)
				}
			}
			return filtered
		}
		return rows
	}

	byKey := make(map[int64]AggRow, len(rows))
	var minKey, maxKey int64
	hasMinKey, hasMaxKey := false, false
	for _, r := range rows {
		if k, err := strconv.ParseInt(r.BucketKey, 10, 64); err == nil {
			byKey[k] = r
			if !hasMinKey || k < minKey {
				minKey = k
				hasMinKey = true
			}
			if !hasMaxKey || k > maxKey {
				maxKey = k
				hasMaxKey = true
			}
		}
	}
	if spec.ExtendedBounds != nil {
		if spec.ExtendedBounds.Min != nil {
			if ms, ok := parseDateHistogramBoundMsRound59(spec.ExtendedBounds.Min, spec, nowUTC, false); ok {
				extMin := floorDateHistogramBucketMillisRound59(ms, spec)
				if !hasMinKey || extMin < minKey {
					minKey = extMin
					hasMinKey = true
				}
			}
		}
		if spec.ExtendedBounds.Max != nil {
			if ms, ok := parseDateHistogramBoundMsRound59(spec.ExtendedBounds.Max, spec, nowUTC, true); ok {
				extMax := floorDateHistogramBucketMillisRound59(ms, spec)
				if !hasMaxKey || extMax > maxKey {
					maxKey = extMax
					hasMaxKey = true
				}
			}
		}
	}
	hasObserved := hasMinKey && hasMaxKey
	if !hasObserved && hasHardMin && hasHardMax {
		minKey = hardMin
		maxKey = hardMax
		hasObserved = true
	}
	if hasHardMin && (!hasObserved || minKey < hardMin) {
		minKey = hardMin
	}
	if hasHardMax && (!hasObserved || maxKey > hardMax) {
		maxKey = hardMax
	}
	if !hasObserved || maxKey < minKey {
		return rows
	}

	var out []AggRow
	for k := minKey; k <= maxKey && len(out) < transpiler.DefaultMaxAggBuckets; k = stepDateHistogramBucketMillisRound59(k, spec) {
		if existing, ok := byKey[k]; ok {
			out = append(out, existing)
		} else {
			out = append(out, AggRow{
				BucketKey: strconv.FormatInt(k, 10),
				DocCount:  0,
				Value:     0,
			})
		}
	}
	return out
}

// formatDateHistogramKeyAsStringRound59 formats `epochMs` using the exact per-instant offset in
// `spec.TimeZone` (handling IANA DST zones like `"America/New_York"` across winter/summer transitions)
// while preserving all ES / Joda `format` patterns supported by `formatDateHistogramKeyAsString` (`F19`).
func formatDateHistogramKeyAsStringRound59(epochMs int64, spec *esast.DateHistogramAggSpec) string {
	if spec == nil {
		return formatDateHistogramKeyAsString(epochMs, nil)
	}
	tzRaw := strings.TrimSpace(spec.TimeZone)
	if tzRaw == "" || tzRaw == "Z" || strings.EqualFold(tzRaw, "UTC") {
		return formatDateHistogramKeyAsString(epochMs, spec)
	}
	loc, _, isFixed, err := esast.ParseESTimeZone(tzRaw)
	if err != nil || loc == nil || isFixed {
		return formatDateHistogramKeyAsString(epochMs, spec)
	}
	_, offsetSec := time.UnixMilli(epochMs).In(loc).Zone()
	sign := "+"
	absSec := offsetSec
	if absSec < 0 {
		sign = "-"
		absSec = -absSec
	}
	hh := absSec / 3600
	mm := (absSec % 3600) / 60
	cpSpec := *spec
	cpSpec.TimeZone = fmt.Sprintf("%s%02d:%02d", sign, hh, mm)
	return formatDateHistogramKeyAsString(epochMs, &cpSpec)
}

func mappingOrShredErrorTypeRound59(err error) string {
	if err == nil {
		return "mapper_parsing_exception"
	}
	msg := err.Error()
	if strings.Contains(msg, "Limit of ") || strings.Contains(msg, "exceeds max length") || strings.Contains(msg, "illegal_argument_exception") {
		return "illegal_argument_exception"
	}
	return shredErrorType(err)
}

func (s *Server) validateAndEvolveExistingIndexRound59(
	ctx context.Context,
	indexName string,
	idx *schema.IndexSchema,
	sampleDocs []json.RawMessage,
) (*schema.IndexSchema, error) {
	if idx == nil || len(sampleDocs) == 0 {
		return idx, nil
	}
	// F11: dynamic: "runtime" inference on existing indices
	if nextRaw, added := applyDynamicRuntimeInferenceRound59(sampleDocs, idx.RawMapping); added {
		cand := schema.CompileIndexSchema(s.dorisDB, indexName, nextRaw)
		cand.CopyIndexMappingSettingsFrom(idx)
		if err := schema.ValidateMappingLimits(cand, nextRaw); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.indices[indexName] = cand
		s.mu.Unlock()
		s.persistIndex(ctx, indexName, cand)
		s.queryCache.InvalidateAll()
		idx = cand
	} else if idx.RawMapping == nil || idx.RawMapping.Dynamic == nil || idx.RawMapping.Dynamic == true || idx.RawMapping.Dynamic == "true" {
		// F12: enforce index.mapping.* limits against dynamically introduced fields
		inferred := schema.InferMappingFromSampleDocs(sampleDocs, idx.RawMapping)
		mergedPreview := schema.MergeMappingSpecs(inferred, idx.RawMapping)
		if err := schema.ValidateMappingLimits(idx, mergedPreview); err != nil {
			return nil, err
		}
	}
	// F13: adopt first non-null value for unconfigured constant_keyword fields
	if updated, err := adoptConstantKeywordValuesFromDocsRound59(idx, sampleDocs); err != nil {
		return nil, err
	} else if updated {
		s.persistIndex(ctx, indexName, idx)
		s.queryCache.InvalidateAll()
	}
	if delta := detectArrayPromotions(idx, sampleDocs); delta != nil {
		idx = s.applyArrayPromotionDelta(ctx, indexName, idx, delta)
	}
	return idx, nil
}

func (s *Server) ensureWritableIndexSchemaWithDocsErr(
	ctx context.Context,
	indexName string,
	sampleDocs []json.RawMessage,
) (*schema.IndexSchema, error) {
	s.mu.RLock()
	if targets, ok := s.aliases[indexName]; ok && len(targets) > 0 {
		indexName = targets[0]
	}
	idx, ok := s.indices[indexName]
	if ok && (len(idx.Fields) > 0 || len(idx.NestedRoots) > 0 || len(sampleDocs) == 0) {
		s.mu.RUnlock()
		return s.validateAndEvolveExistingIndexRound59(ctx, indexName, idx, sampleDocs)
	}
	s.mu.RUnlock()

	_ = s.syncCatalogFromBackend(ctx)

	s.mu.RLock()
	if targets, ok := s.aliases[indexName]; ok && len(targets) > 0 {
		indexName = targets[0]
	}
	idx, ok = s.indices[indexName]
	if ok && (len(idx.Fields) > 0 || len(idx.NestedRoots) > 0 || len(sampleDocs) == 0) {
		s.mu.RUnlock()
		return s.validateAndEvolveExistingIndexRound59(ctx, indexName, idx, sampleDocs)
	}
	var existingEmptySchema *schema.IndexSchema
	if ok {
		existingEmptySchema = idx
	}
	tplMappings, tplDefPipe, hasTplDefPipe, tplFinPipe, hasTplFinPipe, tplAliases, tplCustomSettings, _ := s.matchingTemplateFullConfigLocked(indexName)
	if existingEmptySchema != nil && existingEmptySchema.RawMapping != nil {
		tplMappings = schema.MergeMappingSpecs(tplMappings, existingEmptySchema.RawMapping)
	}
	if s.isDataStreamOrBackingIndexLocked(indexName) {
		tsSpec := &esast.MappingSpec{
			Properties: map[string]esast.FieldProperty{
				"@timestamp": {Type: "date"},
			},
		}
		tplMappings = schema.MergeMappingSpecs(tsSpec, tplMappings)
	}
	var curCustomSettings map[string]any
	if existing := s.indexCustomSettings[indexName]; len(existing) > 0 {
		curCustomSettings = make(map[string]any, len(existing))
		for k, v := range existing {
			curCustomSettings[k] = v
		}
	}
	s.mu.RUnlock()

	effectiveMappings := tplMappings
	if len(sampleDocs) > 0 {
		if tplMappings != nil && tplMappings.Dynamic == "runtime" {
			if nextMap, added := applyDynamicRuntimeInferenceRound59(sampleDocs, effectiveMappings); added {
				effectiveMappings = nextMap
			}
		} else if tplMappings == nil || tplMappings.Dynamic == nil || tplMappings.Dynamic == true || tplMappings.Dynamic == "true" {
			inferred := schema.InferMappingFromSampleDocs(sampleDocs, tplMappings)
			effectiveMappings = schema.MergeMappingSpecs(inferred, tplMappings)
		}
	}

	compiled := schema.CompileIndexSchema(s.dorisDB, indexName, effectiveMappings)
	if existingEmptySchema != nil {
		compiled.CopyIndexMappingSettingsFrom(existingEmptySchema)
	}
	if len(tplCustomSettings) > 0 {
		if err := parseAndApplyIndexMappingSettingsRound59(tplCustomSettings, compiled); err != nil {
			return nil, err
		}
	}
	if len(curCustomSettings) > 0 {
		if err := parseAndApplyIndexMappingSettingsRound59(curCustomSettings, compiled); err != nil {
			return nil, err
		}
	}
	if len(sampleDocs) > 0 {
		if delta := detectArrayPromotions(compiled, sampleDocs); delta != nil {
			prev := compiled
			effectiveMappings = schema.MergeMappingSpecs(effectiveMappings, delta)
			compiled = schema.CompileIndexSchema(s.dorisDB, indexName, effectiveMappings)
			compiled.CopyIndexMappingSettingsFrom(prev)
		}
		if err := schema.ValidateMappingLimits(compiled, compiled.RawMapping); err != nil {
			return nil, err
		}
		if _, err := adoptConstantKeywordValuesFromDocsRound59(compiled, sampleDocs); err != nil {
			return nil, err
		}
	}

	_ = s.backend.ExecDDL(ctx, schema.GenerateCreateTableDDL(compiled))
	if existingEmptySchema != nil {
		for _, stmt := range schema.GenerateAlterTableDDL(existingEmptySchema, compiled) {
			_ = s.backend.ExecDDL(ctx, stmt)
		}
	}
	aliasesToPersist := make(map[string][]string)
	s.mu.Lock()
	if existing, exists := s.indices[indexName]; exists && (len(existing.Fields) > 0 || len(existing.NestedRoots) > 0) {
		s.mu.Unlock()
		return s.validateAndEvolveExistingIndexRound59(ctx, indexName, existing, sampleDocs)
	}
	s.indices[indexName] = compiled
	if existingEmptySchema == nil {
		if hasTplDefPipe && tplDefPipe != "" {
			if _, hasCur := s.indexDefaultPipelines[indexName]; !hasCur {
				s.indexDefaultPipelines[indexName] = tplDefPipe
			}
		}
		if hasTplFinPipe && tplFinPipe != "" {
			if _, hasCur := s.indexFinalPipelines[indexName]; !hasCur {
				s.indexFinalPipelines[indexName] = tplFinPipe
			}
		}
		if len(tplCustomSettings) > 0 {
			if s.indexCustomSettings == nil {
				s.indexCustomSettings = make(map[string]map[string]any)
			}
			if s.indexCustomSettings[indexName] == nil {
				s.indexCustomSettings[indexName] = make(map[string]any)
			}
			for k, v := range tplCustomSettings {
				if k == "default_pipeline" || k == "final_pipeline" || v == nil {
					continue
				}
				if _, exists := s.indexCustomSettings[indexName][k]; !exists {
					s.indexCustomSettings[indexName][k] = normalizeCustomSettingValue(v)
				}
			}
		}
		for alias, rawMeta := range tplAliases {
			meta := parseAliasMetadata(rawMeta)
			s.addAliasWithMetaLocked(alias, indexName, meta)
			aliasesToPersist[alias] = append([]string(nil), s.aliases[alias]...)
		}
		s.ensureIndexCreationDateLocked(indexName)
	}
	s.mu.Unlock()
	s.persistIndex(ctx, indexName, compiled)
	for alias, targets := range aliasesToPersist {
		s.persistAlias(ctx, alias, targets)
	}
	s.queryCache.InvalidateAll()
	return compiled, nil
}

func validateCustomSearchScoresOnRuntimeHitsRound59(
	idxSchema *schema.IndexSchema,
	q *esast.Query,
	hits []HitRow,
) error {
	if !queryProducesCustomScoreRound59(q) {
		return nil
	}
	for i := range hits {
		var docMap map[string]any
		if len(hits[i].EffectiveSource()) > 0 {
			dec := json.NewDecoder(bytes.NewReader(hits[i].EffectiveSource()))
			dec.UseNumber()
			_ = dec.Decode(&docMap)
		}
		if docMap == nil {
			docMap = make(map[string]any)
		}
		docMap["__meta_id"] = hits[i].ID
		if !evalQueryScriptFilterOnDocWithSchema(idxSchema, docMap, q) {
			continue
		}
		baseScore := hits[i].Score
		if baseScore == 0 {
			baseScore = 1.0
		}
		if _, err := evalRuntimeSearchScoreWithErrorRound59(idxSchema, docMap, q, baseScore); err != nil {
			return err
		}
	}
	return nil
}

func validateCustomSearchScoresOnSQLHitsRound59(q *esast.Query, hits []HitRow) error {
	if !queryProducesCustomScoreRound59(q) {
		return nil
	}
	for i := range hits {
		if _, err := validateNonNegativeFiniteSearchScoreRound59(true, hits[i].Score); err != nil {
			return err
		}
	}
	return nil
}
