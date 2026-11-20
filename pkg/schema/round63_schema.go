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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
)

// --- F29 (`C-12` P1): Recursive Deep-Clone Helpers (Zero Shared Mutable Map/Slice References) ---

func deepCloneAny(v any) any {
	if v == nil {
		return nil
	}
	switch tv := v.(type) {
	case map[string]any:
		return deepCloneMapStringAny(tv)
	case []any:
		out := make([]any, len(tv))
		for i, elem := range tv {
			out[i] = deepCloneAny(elem)
		}
		return out
	case []string:
		out := make([]string, len(tv))
		copy(out, tv)
		return out
	case map[string]string:
		out := make(map[string]string, len(tv))
		for k, sv := range tv {
			out[k] = sv
		}
		return out
	case []map[string]any:
		return deepCloneSliceMapStringAny(tv)
	default:
		return v
	}
}

func deepCloneMapStringAny(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = deepCloneAny(v)
	}
	return out
}

func deepCloneSliceMapStringAny(in []map[string]any) []map[string]any {
	if in == nil {
		return nil
	}
	out := make([]map[string]any, len(in))
	for i, m := range in {
		out[i] = deepCloneMapStringAny(m)
	}
	return out
}

func deepCloneCompletionContexts(in []esast.CompletionContextDef) []esast.CompletionContextDef {
	if len(in) == 0 {
		return nil
	}
	out := make([]esast.CompletionContextDef, len(in))
	for i, c := range in {
		cp := c
		cp.Precision = deepCloneAny(c.Precision)
		cp.Default = deepCloneAny(c.Default)
		out[i] = cp
	}
	return out
}

// --- F27 (`C-06` P0 Foundation): Schema-Aware Index-Time Field Script Hook & `lookup` Runtime Validation ---

// IndexFieldScriptWithSchemaEvaluatorFunc evaluates an index-time `mappings.properties.<f>.script`
// with direct access to the owning `*IndexSchema`, avoiding process-global index lookup maps.
type IndexFieldScriptWithSchemaEvaluatorFunc func(
	idxSchema *IndexSchema,
	fieldPath, esType string,
	scriptSpec any,
	onScriptError string,
	sourceDoc map[string]any,
) ([]any, error)

var indexFieldScriptWithSchemaEvalFn IndexFieldScriptWithSchemaEvaluatorFunc

// RegisterIndexFieldScriptWithSchemaEvaluator registers the schema-aware index-time mapped field `script` evaluator hook.
func RegisterIndexFieldScriptWithSchemaEvaluator(fn IndexFieldScriptWithSchemaEvaluatorFunc) {
	indexFieldScriptEvalMu.Lock()
	indexFieldScriptWithSchemaEvalFn = fn
	indexFieldScriptEvalMu.Unlock()
}

// GetIndexFieldScriptWithSchemaEvaluator returns the currently registered schema-aware index-time mapped field `script` evaluator hook.
func GetIndexFieldScriptWithSchemaEvaluator() IndexFieldScriptWithSchemaEvaluatorFunc {
	indexFieldScriptEvalMu.RLock()
	fn := indexFieldScriptWithSchemaEvalFn
	indexFieldScriptEvalMu.RUnlock()
	return fn
}

func validateLookupRuntimeField(rtName string, rtProp esast.FieldProperty) error {
	if rtProp.Script != nil {
		return fmt.Errorf("mapper_parsing_exception: runtime field [%s] of type [lookup] does not accept [script]", rtName)
	}
	if rtProp.TargetIndex != "" || rtProp.InputField != "" || rtProp.TargetField != "" || rtProp.KeyField != "" || len(rtProp.FetchFields) > 0 {
		if strings.TrimSpace(rtProp.TargetIndex) == "" {
			return fmt.Errorf("mapper_parsing_exception: [lookup] runtime field [%s] requires [target_index]", rtName)
		}
		if strings.TrimSpace(rtProp.InputField) == "" {
			return fmt.Errorf("mapper_parsing_exception: [lookup] runtime field [%s] requires [input_field]", rtName)
		}
		if rtProp.EffectiveLookupTargetField() == "" {
			return fmt.Errorf("mapper_parsing_exception: [lookup] runtime field [%s] requires [target_field]", rtName)
		}
		if len(rtProp.FetchFields) == 0 {
			return fmt.Errorf("mapper_parsing_exception: [lookup] runtime field [%s] requires non-empty [fetch_fields]", rtName)
		}
	}
	return nil
}

// --- F1: `_size` Metadata Mapper, `murmur3`, `counted_keyword`, and `aggregate_metric_double` ---

// ValidateSizeMetaSpec validates `mappings._size` (`{"enabled": true|false}`).
func ValidateSizeMetaSpec(sizeMap map[string]any) (enabled bool, explicit bool, err error) {
	if sizeMap == nil {
		return false, false, nil
	}
	for k, v := range sizeMap {
		if k != "enabled" {
			return false, false, fmt.Errorf("mapper_parsing_exception: Root mapping definition has unsupported parameters in [_size]: [%s]", k)
		}
		switch bv := v.(type) {
		case bool:
			enabled = bv
			explicit = true
		case string:
			switch strings.ToLower(strings.TrimSpace(bv)) {
			case "true":
				enabled = true
				explicit = true
			case "false":
				enabled = false
				explicit = true
			default:
				return false, false, fmt.Errorf("mapper_parsing_exception: [_size.enabled] must be a boolean, got [%s]", bv)
			}
		default:
			return false, false, fmt.Errorf("mapper_parsing_exception: [_size.enabled] must be a boolean, got %T", v)
		}
	}
	return enabled, explicit, nil
}

// IsSizeMetadataEnabled reports whether `mappings._size.enabled` is true on `m`.
func IsSizeMetadataEnabled(m *esast.MappingSpec) bool {
	if m == nil || len(m.Size) == 0 {
		return false
	}
	enabled, _, err := ValidateSizeMetaSpec(m.Size)
	return err == nil && enabled
}

// ComputeESMurmur3Hash computes the exact 64-bit signed Murmur3 hash (`MurmurHash3.hash128` lower 64 bits, seed 0)
// matching Elasticsearch's `mapper-murmur3` plugin (`plugins/mapper-murmur3/10_basic.yml`).
func ComputeESMurmur3Hash(s string) int64 {
	h1, _ := murmur3X64_128Bytes([]byte(s), 0)
	return int64(h1) // #nosec G115 -- intentional 64-bit two's-complement Murmur3 hash matching ES Murmur3FieldMapper
}

var validAggregateMetricNames = map[string]bool{
	"min":         true,
	"max":         true,
	"sum":         true,
	"value_count": true,
	"avg":         true,
}

func validateAggregateMetricDoubleProperty(fullPath string, prop esast.FieldProperty) error {
	if len(prop.Metrics) == 0 {
		return esWireError(fmt.Sprintf("mapper_parsing_exception: [metrics] must be non-empty for [aggregate_metric_double] field [%s]", fullPath))
	}
	seen := make(map[string]bool, len(prop.Metrics))
	for _, m := range prop.Metrics {
		mn := strings.TrimSpace(m)
		if !validAggregateMetricNames[mn] {
			return esWireError(fmt.Sprintf("mapper_parsing_exception: Invalid metric [%s] for [aggregate_metric_double] field [%s]; supported metrics are [min, max, sum, value_count, avg]", m, fullPath))
		}
		if seen[mn] {
			return esWireError(fmt.Sprintf("mapper_parsing_exception: Duplicate metric [%s] in [metrics] for [aggregate_metric_double] field [%s]", m, fullPath))
		}
		seen[mn] = true
	}
	defM := strings.TrimSpace(prop.DefaultMetric)
	if defM == "" {
		return esWireError(fmt.Sprintf("mapper_parsing_exception: [default_metric] is required for [aggregate_metric_double] field [%s]", fullPath))
	}
	if !validAggregateMetricNames[defM] {
		return esWireError(fmt.Sprintf("mapper_parsing_exception: Invalid [default_metric] [%s] for [aggregate_metric_double] field [%s]", prop.DefaultMetric, fullPath))
	}
	if !seen[defM] {
		return esWireError(fmt.Sprintf("mapper_parsing_exception: [default_metric] [%s] must be one of the configured [metrics] %v for field [%s]", prop.DefaultMetric, prop.Metrics, fullPath))
	}
	if prop.Index != nil && !*prop.Index {
		return esWireError(fmt.Sprintf("mapper_parsing_exception: Cannot set [index: false] on [aggregate_metric_double] field [%s]", fullPath))
	}
	if prop.DocValues != nil && !*prop.DocValues {
		return esWireError(fmt.Sprintf("mapper_parsing_exception: Cannot disable [doc_values] on [aggregate_metric_double] field [%s]", fullPath))
	}
	return nil
}

func validateAggregateMetricDoubleUpdate(fullPath string, oldProp, newProp esast.FieldProperty) error {
	if newProp.DefaultMetric != "" && oldProp.DefaultMetric != "" && newProp.DefaultMetric != oldProp.DefaultMetric {
		return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [default_metric] from [%s] to [%s]", fullPath, oldProp.DefaultMetric, newProp.DefaultMetric)
	}
	if len(newProp.Metrics) > 0 && len(oldProp.Metrics) > 0 && !stringSlicesEqualExact(oldProp.Metrics, newProp.Metrics) {
		return fmt.Errorf("illegal_argument_exception: Mapper for [%s] conflicts with existing mapper: Cannot update parameter [metrics]", fullPath)
	}
	return nil
}

func aggregateMetricStoredSubNames(metrics []string) (needMin, needMax, needSum, needValueCount bool) {
	for _, m := range metrics {
		switch strings.TrimSpace(m) {
		case "min":
			needMin = true
		case "max":
			needMax = true
		case "sum":
			needSum = true
		case "value_count":
			needValueCount = true
		case "avg":
			needSum = true
			needValueCount = true
		}
	}
	return
}

// AggregateMetricSubColumns returns the promoted Doris sub-column bindings (`__min`, `__max`, `__sum`, `__value_count`)
// for an `aggregate_metric_double` field binding.
func AggregateMetricSubColumns(b FieldBinding) []FieldBinding {
	if !strings.EqualFold(b.ESType, "aggregate_metric_double") || b.ColumnName == "" || b.AliasTarget != "" {
		return nil
	}
	needMin, needMax, needSum, needVC := aggregateMetricStoredSubNames(b.AggregateMetrics)
	subKind := StoragePromotedScalar
	if b.Kind == StorageNestedSubfield {
		subKind = StorageNestedSubfield
	}
	var subs []FieldBinding
	addSub := func(sfx string, dt DorisScalarType) {
		subs = append(subs, FieldBinding{
			ESFieldPath: b.ESFieldPath + "." + sfx,
			ColumnName:  b.ColumnName + "__" + sfx,
			Kind:        subKind,
			DorisType:   dt,
			ESType:      "double",
			NotIndexed:  b.NotIndexed,
		})
	}
	if needMin {
		addSub("min", DorisDouble)
	}
	if needMax {
		addSub("max", DorisDouble)
	}
	if needSum {
		addSub("sum", DorisDouble)
	}
	if needVC {
		subs = append(subs, FieldBinding{
			ESFieldPath: b.ESFieldPath + ".value_count",
			ColumnName:  b.ColumnName + "__value_count",
			Kind:        subKind,
			DorisType:   DorisBigInt,
			ESType:      "long",
			NotIndexed:  b.NotIndexed,
		})
	}
	return subs
}

type parsedAggregateMetricEntry struct {
	minVal    float64
	maxVal    float64
	sumVal    float64
	vcVal     int64
	extraKeys map[string]any
}

func parseSingleAggregateMetricObject(
	obj map[string]any,
	b FieldBinding,
	allowExtraIgnored bool,
) (parsedAggregateMetricEntry, bool, error) {
	needMin, needMax, needSum, needVC := aggregateMetricStoredSubNames(b.AggregateMetrics)
	var out parsedAggregateMetricEntry
	hadExtra := false

	parseNum := func(raw any, subName string) (float64, error) {
		f, ok := syntheticToFloat64(raw)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, fmt.Errorf("mapper_parsing_exception: [%s] sub-field [%s] must be a finite number on [%s]", b.ESType, subName, b.ESFieldPath)
		}
		return f, nil
	}
	parsePositiveInt := func(raw any) (int64, error) {
		switch v := raw.(type) {
		case int:
			if v <= 0 {
				return 0, fmt.Errorf("mapper_parsing_exception: [value_count] must be a positive integer on [%s], got [%d]", b.ESFieldPath, v)
			}
			return int64(v), nil
		case int64:
			if v <= 0 {
				return 0, fmt.Errorf("mapper_parsing_exception: [value_count] must be a positive integer on [%s], got [%d]", b.ESFieldPath, v)
			}
			return v, nil
		case json.Number:
			s := v.String()
			if strings.ContainsAny(s, ".eE") {
				f, err := v.Float64()
				if err != nil || f != math.Trunc(f) || f <= 0 || f > float64(math.MaxInt64) {
					return 0, fmt.Errorf("mapper_parsing_exception: [value_count] must be a positive integer on [%s], got [%s]", b.ESFieldPath, s)
				}
				return int64(f), nil
			}
			iv, err := v.Int64()
			if err != nil || iv <= 0 {
				return 0, fmt.Errorf("mapper_parsing_exception: [value_count] must be a positive integer on [%s], got [%s]", b.ESFieldPath, s)
			}
			return iv, nil
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) || v <= 0 || v > float64(math.MaxInt64) {
				return 0, fmt.Errorf("mapper_parsing_exception: [value_count] must be a positive integer on [%s], got [%v]", b.ESFieldPath, v)
			}
			return int64(v), nil
		case string:
			iv, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil || iv <= 0 {
				return 0, fmt.Errorf("mapper_parsing_exception: [value_count] must be a positive integer on [%s], got [%s]", b.ESFieldPath, v)
			}
			return iv, nil
		default:
			return 0, fmt.Errorf("mapper_parsing_exception: [value_count] must be a positive integer on [%s]", b.ESFieldPath)
		}
	}

	for k, v := range obj {
		allowed := (k == "min" && needMin) || (k == "max" && needMax) || (k == "sum" && needSum) || (k == "value_count" && needVC)
		if !allowed {
			if allowExtraIgnored {
				hadExtra = true
				if out.extraKeys == nil {
					out.extraKeys = make(map[string]any)
				}
				out.extraKeys[k] = v
				continue
			}
			return out, false, fmt.Errorf("mapper_parsing_exception: unsupported sub-field [%s] on [aggregate_metric_double] field [%s]", k, b.ESFieldPath)
		}
	}

	if needMin {
		rv, ok := obj["min"]
		if !ok || rv == nil {
			return out, hadExtra, fmt.Errorf("mapper_parsing_exception: [aggregate_metric_double] field [%s] requires [min]", b.ESFieldPath)
		}
		fv, err := parseNum(rv, "min")
		if err != nil {
			return out, hadExtra, err
		}
		out.minVal = fv
	}
	if needMax {
		rv, ok := obj["max"]
		if !ok || rv == nil {
			return out, hadExtra, fmt.Errorf("mapper_parsing_exception: [aggregate_metric_double] field [%s] requires [max]", b.ESFieldPath)
		}
		fv, err := parseNum(rv, "max")
		if err != nil {
			return out, hadExtra, err
		}
		out.maxVal = fv
	}
	if needMin && needMax && out.minVal > out.maxVal {
		return out, hadExtra, fmt.Errorf("mapper_parsing_exception: [aggregate_metric_double] field [%s] [max] [%v] cannot be less than [min] [%v]", b.ESFieldPath, out.maxVal, out.minVal)
	}
	if needSum {
		rv, ok := obj["sum"]
		if !ok || rv == nil {
			return out, hadExtra, fmt.Errorf("mapper_parsing_exception: [aggregate_metric_double] field [%s] requires [sum]", b.ESFieldPath)
		}
		fv, err := parseNum(rv, "sum")
		if err != nil {
			return out, hadExtra, err
		}
		out.sumVal = fv
	}
	if needVC {
		rv, ok := obj["value_count"]
		if !ok || rv == nil {
			return out, hadExtra, fmt.Errorf("mapper_parsing_exception: [aggregate_metric_double] field [%s] requires [value_count]", b.ESFieldPath)
		}
		iv, err := parsePositiveInt(rv)
		if err != nil {
			return out, hadExtra, err
		}
		out.vcVal = iv
	}
	return out, hadExtra, nil
}

func shredAggregateMetricDoubleBinding(
	parsedDoc map[string]any,
	b FieldBinding,
	row map[string]any,
	recordIgnored func(string),
) (bool, error) {
	rawVal, present := extractSingleDocPathValue(parsedDoc, b.SourceJSONPath)
	if !present || rawVal == nil {
		return false, nil
	}
	ignoreMal := b.IgnoreMalformed != nil && *b.IgnoreMalformed
	needMin, needMax, needSum, needVC := aggregateMetricStoredSubNames(b.AggregateMetrics)

	var validEntries []parsedAggregateMetricEntry
	hadIgnored := false

	var collect func(v any) error
	collect = func(v any) error {
		if v == nil {
			return nil
		}
		switch tv := v.(type) {
		case map[string]any:
			entry, hadExtra, err := parseSingleAggregateMetricObject(tv, b, ignoreMal)
			if err != nil {
				if ignoreMal {
					hadIgnored = true
					return nil
				}
				return err
			}
			if hadExtra {
				hadIgnored = true
			}
			validEntries = append(validEntries, entry)
			return nil
		case []any:
			for _, elem := range tv {
				if err := collect(elem); err != nil {
					return err
				}
			}
			return nil
		default:
			if ignoreMal {
				hadIgnored = true
				return nil
			}
			return fmt.Errorf("mapper_parsing_exception: failed to parse field [%s] of type [aggregate_metric_double]: expected object", b.ESFieldPath)
		}
	}

	if err := collect(rawVal); err != nil {
		return false, err
	}
	if hadIgnored && recordIgnored != nil {
		recordIgnored(b.ESFieldPath)
	}
	if len(validEntries) == 0 {
		if hadIgnored {
			return deletePathInMap(parsedDoc, b.SourceJSONPath), nil
		}
		return false, nil
	}

	aggMin := validEntries[0].minVal
	aggMax := validEntries[0].maxVal
	var aggSum float64
	var aggVC int64
	for _, e := range validEntries {
		if e.minVal < aggMin {
			aggMin = e.minVal
		}
		if e.maxVal > aggMax {
			aggMax = e.maxVal
		}
		aggSum += e.sumVal
		aggVC += e.vcVal
	}

	if b.Kind != StorageNestedSubfield && b.ColumnName != "" {
		if needMin {
			row[b.ColumnName+"__min"] = aggMin
		}
		if needMax {
			row[b.ColumnName+"__max"] = aggMax
		}
		if needSum {
			row[b.ColumnName+"__sum"] = aggSum
		}
		if needVC {
			row[b.ColumnName+"__value_count"] = aggVC
		}
		switch strings.TrimSpace(b.DefaultMetric) {
		case "min":
			row[b.ColumnName] = aggMin
		case "max":
			row[b.ColumnName] = aggMax
		case "sum":
			row[b.ColumnName] = aggSum
		case "value_count":
			row[b.ColumnName] = float64(aggVC)
		case "avg":
			if aggVC > 0 {
				row[b.ColumnName] = aggSum / float64(aggVC)
			}
		}
	}
	return false, nil
}

func reconstructSyntheticAggregateMetricDouble(idxSchema *IndexSchema, rawVal any, b FieldBinding) (any, bool) {
	if rawVal == nil {
		return nil, false
	}
	effB := b
	if idxSchema != nil {
		effB = idxSchema.withEffectiveDefaults(b)
	}
	ignoreMal := effB.IgnoreMalformed != nil && *effB.IgnoreMalformed
	needMin, needMax, needSum, needVC := aggregateMetricStoredSubNames(effB.AggregateMetrics)

	buildEntryMap := func(e parsedAggregateMetricEntry) map[string]any {
		m := make(map[string]any)
		if needMin {
			m["min"] = e.minVal
		}
		if needMax {
			m["max"] = e.maxVal
		}
		if needSum {
			m["sum"] = e.sumVal
		}
		if needVC {
			m["value_count"] = e.vcVal
		}
		for ek, ev := range e.extraKeys {
			if nv, ok := reconstructIgnoredSourceValue(idxSchema, ev, effB.ESFieldPath+"."+ek); ok {
				m[ek] = nv
			}
		}
		return m
	}

	switch tv := rawVal.(type) {
	case map[string]any:
		entry, _, err := parseSingleAggregateMetricObject(tv, effB, ignoreMal)
		if err != nil {
			if ignoreMal {
				norm, ok := reconstructIgnoredSourceValue(idxSchema, tv, effB.ESFieldPath)
				return norm, ok
			}
			return nil, false
		}
		return buildEntryMap(entry), true

	case []any:
		var validObjs []any
		var ignoredTail []any
		var walkArr func(items []any)
		walkArr = func(items []any) {
			for _, item := range items {
				if item == nil {
					continue
				}
				switch sub := item.(type) {
				case []any:
					walkArr(sub)
				case map[string]any:
					entry, _, err := parseSingleAggregateMetricObject(sub, effB, ignoreMal)
					if err == nil {
						validObjs = append(validObjs, buildEntryMap(entry))
					} else if ignoreMal {
						if nv, ok := reconstructIgnoredSourceValue(idxSchema, sub, effB.ESFieldPath); ok {
							ignoredTail = append(ignoredTail, nv)
						}
					}
				default:
					if ignoreMal {
						if nv, ok := reconstructIgnoredSourceValue(idxSchema, sub, effB.ESFieldPath); ok {
							ignoredTail = append(ignoredTail, nv)
						}
					}
				}
			}
		}
		walkArr(tv)
		// Aggregate valid entries across the array into a single metric summary object (ES doc_values behavior),
		// then append any ignored malformed tail items (`100_synthetic_source.yml:94,122`).
		var mergedValid map[string]any
		if len(validObjs) > 0 {
			first := validObjs[0].(map[string]any)
			mergedValid = make(map[string]any, len(first))
			for k, v := range first {
				mergedValid[k] = v
			}
			for _, vo := range validObjs[1:] {
				vm := vo.(map[string]any)
				if needMin && vm["min"].(float64) < mergedValid["min"].(float64) {
					mergedValid["min"] = vm["min"]
				}
				if needMax && vm["max"].(float64) > mergedValid["max"].(float64) {
					mergedValid["max"] = vm["max"]
				}
				if needSum {
					mergedValid["sum"] = mergedValid["sum"].(float64) + vm["sum"].(float64)
				}
				if needVC {
					mergedValid["value_count"] = mergedValid["value_count"].(int64) + vm["value_count"].(int64)
				}
			}
		}
		var combined []any
		if mergedValid != nil {
			combined = append(combined, mergedValid)
		}
		combined = append(combined, ignoredTail...)
		if len(combined) == 0 {
			return nil, false
		}
		if len(combined) == 1 {
			return combined[0], true
		}
		return combined, true
	default:
		if ignoreMal {
			return reconstructIgnoredSourceValue(idxSchema, rawVal, effB.ESFieldPath)
		}
		return nil, false
	}
}

// --- F5 (`V8-4`): `ignore_dynamic_beyond_limit`, `_ignored_source`, and Synthetic `_source` Reconstruction ---

// ExtractIgnoreDynamicBeyondLimitSetting extracts `index.mapping.total_fields.ignore_dynamic_beyond_limit` from index settings.
func ExtractIgnoreDynamicBeyondLimitSetting(settings map[string]any) (val bool, present bool, err error) {
	if len(settings) == 0 {
		return false, false, nil
	}
	raw, ok := lookupIndexSettingPath(settings,
		"index.mapping.total_fields.ignore_dynamic_beyond_limit",
		"mapping.total_fields.ignore_dynamic_beyond_limit",
	)
	if !ok || raw == nil {
		return false, false, nil
	}
	switch v := raw.(type) {
	case bool:
		return v, true, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true":
			return true, true, nil
		case "false":
			return false, true, nil
		}
	}
	return false, true, esWireError(fmt.Sprintf("illegal_argument_exception: Failed to parse value [%v] for setting [index.mapping.total_fields.ignore_dynamic_beyond_limit] must be [true] or [false]", raw))
}

func lookupIndexSettingPath(settings map[string]any, keys ...string) (any, bool) {
	for _, k := range keys {
		if v, ok := settings[k]; ok && v != nil {
			return v, true
		}
		parts := strings.Split(k, ".")
		var curr any = settings
		found := true
		for i, p := range parts {
			m, okM := curr.(map[string]any)
			if !okM {
				found = false
				break
			}
			if nxt, okN := m[p]; okN {
				curr = nxt
				continue
			}
			rem := strings.Join(parts[i:], ".")
			if nxtRem, okR := m[rem]; okR {
				curr = nxtRem
				break
			}
			found = false
			break
		}
		if found && curr != nil {
			return curr, true
		}
	}
	return nil, false
}

// CountTotalMappingFields counts total fields (`runtime` + `properties` + multi-fields `fields`) in `spec`,
// matching `ValidateMappingLimits`.
func CountTotalMappingFields(spec *esast.MappingSpec) int {
	if spec == nil {
		return 0
	}
	total := len(spec.Runtime)
	var walk func(props map[string]esast.FieldProperty)
	walk = func(props map[string]esast.FieldProperty) {
		for _, prop := range props {
			total++
			total += len(prop.Fields)
			if len(prop.Properties) > 0 {
				walk(prop.Properties)
			}
		}
	}
	walk(spec.Properties)
	return total
}

// capDynamicPropsInPlace trims newly-added dynamic properties in `candidate` (not present in `base`)
// in deterministic sorted order so `CountTotalMappingFields(candidate) <= maxTotal`.
func capDynamicPropsInPlace(base, candidate *esast.MappingSpec, maxTotal int) {
	if candidate == nil || maxTotal <= 0 {
		return
	}
	curTotal := len(candidate.Runtime)
	var baseProps map[string]esast.FieldProperty
	if base != nil {
		baseProps = base.Properties
	}
	// First count all base fields (which are guaranteed to be kept).
	var countExisting func(bMap, cMap map[string]esast.FieldProperty) int
	countExisting = func(bMap, cMap map[string]esast.FieldProperty) int {
		c := 0
		for k, bp := range bMap {
			cp, ok := cMap[k]
			if !ok {
				cp = bp
			}
			c += 1 + len(cp.Fields)
			if len(bp.Properties) > 0 || len(cp.Properties) > 0 {
				c += countExisting(bp.Properties, cp.Properties)
			}
		}
		return c
	}
	curTotal += countExisting(baseProps, candidate.Properties)

	var trimNew func(bMap, cMap map[string]esast.FieldProperty)
	trimNew = func(bMap, cMap map[string]esast.FieldProperty) {
		if len(cMap) == 0 {
			return
		}
		keys := make([]string, 0, len(cMap))
		for k := range cMap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			cp := cMap[k]
			if bp, inBase := bMap[k]; inBase {
				if len(cp.Properties) > 0 {
					trimNew(bp.Properties, cp.Properties)
					cMap[k] = cp
				}
				continue
			}
			// Brand-new dynamic property `k`:
			cost := 1 + len(cp.Fields)
			if curTotal+cost > maxTotal {
				delete(cMap, k)
				continue
			}
			curTotal += cost
			if len(cp.Properties) > 0 {
				trimNew(nil, cp.Properties)
				if len(cp.Properties) == 0 && cp.Type == "" {
					curTotal -= cost
					delete(cMap, k)
					continue
				}
				cMap[k] = cp
			}
		}
	}
	trimNew(baseProps, candidate.Properties)
}

// CapDynamicMappingAtTotalFieldsLimit returns a deep-cloned `*esast.MappingSpec` where dynamic field additions
// beyond `s.MaxTotalFields` are omitted when `s.IgnoreDynamicBeyondLimit` is true.
func CapDynamicMappingAtTotalFieldsLimit(s *IndexSchema, baseSpec, candidateSpec *esast.MappingSpec) *esast.MappingSpec {
	if candidateSpec == nil {
		return nil
	}
	cp := deepCloneMappingSpec(candidateSpec)
	if s == nil || !s.IgnoreDynamicBeyondLimit {
		return cp
	}
	maxTotal := 1000
	if s.MaxTotalFields > 0 {
		maxTotal = s.MaxTotalFields
	}
	capDynamicPropsInPlace(baseSpec, cp, maxTotal)
	return cp
}

// InferMappingFromSampleDocsForSchema infers dynamic field mappings for `s`, honoring `s.ES8Mode`,
// `s.MaxTotalFields`, and `s.IgnoreDynamicBeyondLimit`.
func InferMappingFromSampleDocsForSchema(s *IndexSchema, docs []json.RawMessage) *esast.MappingSpec {
	if s == nil {
		return InferMappingFromSampleDocs(docs)
	}
	inferred := InferMappingFromSampleDocsWithES8(docs, s.ES8Mode, s.RawMapping)
	if inferred == nil {
		return nil
	}
	if s.IgnoreDynamicBeyondLimit {
		return CapDynamicMappingAtTotalFieldsLimit(s, s.RawMapping, inferred)
	}
	return inferred
}

// extractExcessDynamicFieldsToIgnoredSource moves unmapped fields in `parsedDoc` into an isolated
// `_ignored_source` map (`_doc["__ignored_source"]`) when `s.IgnoreDynamicBeyondLimit` is true,
// preventing excess unmapped fields from being indexed in `_doc` while preserving them for synthetic `_source`.
func extractExcessDynamicFieldsToIgnoredSource(s *IndexSchema, parsedDoc map[string]any) map[string]any {
	if s == nil || !s.IgnoreDynamicBeyondLimit || len(parsedDoc) == 0 {
		return nil
	}
	ignoredSrc := make(map[string]any)
	var walk func(curr map[string]any, prefix string, dst map[string]any)
	walk = func(curr map[string]any, prefix string, dst map[string]any) {
		for k, v := range curr {
			if k == "__ignored_source" || strings.HasPrefix(k, "_") {
				continue
			}
			full := k
			if prefix != "" {
				full = prefix + "." + k
			}
			if _, ok := s.Fields[full]; ok {
				continue
			}
			// Check if `full` is an ancestor of any mapped field or nested root, or inside a nested/flattened/enabled:false ancestor.
			isMappedParent := false
			pfxDot := full + "."
			for fk := range s.Fields {
				if strings.HasPrefix(fk, pfxDot) {
					isMappedParent = true
					break
				}
			}
			if !isMappedParent && s.NestedRoots != nil {
				for nr := range s.NestedRoots {
					if nr == full || strings.HasPrefix(nr, pfxDot) {
						isMappedParent = true
						break
					}
				}
			}
			// Check if any ancestor is flattened / enabled:false
			inOpaqueAncestor := false
			parts := strings.Split(full, ".")
			for i := 1; i < len(parts); i++ {
				anc := strings.Join(parts[:i], ".")
				if ab, ok := s.Fields[anc]; ok && (ab.EnabledFalse || ab.ESType == "flattened" || ab.ESType == "sparse_vector" || ab.ESType == "rank_features") {
					inOpaqueAncestor = true
					break
				}
			}
			if inOpaqueAncestor {
				continue
			}
			if isMappedParent {
				if subMap, ok := v.(map[string]any); ok {
					subDst := make(map[string]any)
					walk(subMap, full, subDst)
					if len(subDst) > 0 {
						dst[k] = subDst
					}
					if len(subMap) == 0 {
						delete(curr, k)
					}
				}
				continue
			}
			if s.RawMapping != nil && s.RawMapping.Runtime != nil {
				if _, isRT := s.RawMapping.Runtime[full]; isRT {
					continue
				}
			}
			dst[k] = deepCloneAny(v)
			delete(curr, k)
		}
	}
	walk(parsedDoc, "", ignoredSrc)
	if len(ignoredSrc) == 0 {
		return nil
	}
	return ignoredSrc
}

func mergeIgnoredSourceIntoSynthetic(idxSchema *IndexSchema, dst map[string]any, shreddedRow map[string]any) {
	if dst == nil || shreddedRow == nil {
		return
	}
	var rawIgnored any
	if v, ok := shreddedRow["__ignored_source"]; ok && v != nil {
		rawIgnored = v
	} else if rawDocVal, ok := shreddedRow["_doc"]; ok && rawDocVal != nil {
		switch dv := rawDocVal.(type) {
		case map[string]any:
			rawIgnored = dv["__ignored_source"]
		case json.RawMessage:
			var dm map[string]any
			dec := json.NewDecoder(bytes.NewReader(dv))
			dec.UseNumber()
			if dec.Decode(&dm) == nil && dm != nil {
				rawIgnored = dm["__ignored_source"]
			}
		case string:
			if strings.TrimSpace(dv) != "" {
				var dm map[string]any
				dec := json.NewDecoder(strings.NewReader(dv))
				dec.UseNumber()
				if dec.Decode(&dm) == nil && dm != nil {
					rawIgnored = dm["__ignored_source"]
				}
			}
		}
	}
	if rawIgnored == nil {
		return
	}
	var ignoredMap map[string]any
	switch tv := rawIgnored.(type) {
	case map[string]any:
		ignoredMap = tv
	case string:
		if strings.TrimSpace(tv) != "" {
			dec := json.NewDecoder(strings.NewReader(tv))
			dec.UseNumber()
			_ = dec.Decode(&ignoredMap)
		}
	}
	if len(ignoredMap) == 0 {
		return
	}
	normIgnored := reconstructIgnoredSourceObject(idxSchema, ignoredMap, "")
	mergeMissingSyntheticKeys(dst, normIgnored)
}

func mergeMissingSyntheticKeys(dst, src map[string]any) {
	for k, sv := range src {
		if k == "__ignored_source" {
			continue
		}
		existing, exists := dst[k]
		if !exists {
			dst[k] = sv
			continue
		}
		if exMap, okEx := existing.(map[string]any); okEx {
			if srcMap, okSrc := sv.(map[string]any); okSrc {
				mergeMissingSyntheticKeys(exMap, srcMap)
			}
		}
	}
}

// reconstructSyntheticFlattenedValue reconstructs a `flattened` field in synthetic `_source`
// (`get/100_synthetic_source.yml:952-1115`):
//   - Merges arrays of objects into a single nested object
//   - Converts leaf scalars to strings (applying `lowercase` normalizer when `<= ignore_above`)
//   - Deduplicates & lexicographically sorts leaf string arrays, appending `ignore_above` values after doc-values
//   - Unwraps single-element leaf arrays `[x]` -> `x`.
func reconstructSyntheticFlattenedValue(idxSchema *IndexSchema, rawVal any, b FieldBinding) (any, bool) {
	if rawVal == nil {
		return nil, false
	}
	var buildObj func(m map[string]any) map[string]any
	var buildLeaf func(v any) (any, bool)

	formatLeafScalar := func(v any) (str string, overIgnoreAbove bool, ok bool) {
		if v == nil {
			return "", false, false
		}
		var s string
		switch tv := v.(type) {
		case string:
			s = tv
		case bool:
			s = strconv.FormatBool(tv)
		case json.Number:
			s = tv.String()
		default:
			s = fmt.Sprintf("%v", tv)
		}
		if b.IgnoreAbove > 0 && len([]rune(s)) > b.IgnoreAbove {
			return s, true, true
		}
		if b.LowercaseNormalizer {
			s = strings.ToLower(s)
		}
		return s, false, true
	}

	buildLeaf = func(v any) (any, bool) {
		if v == nil {
			return nil, false
		}
		switch tv := v.(type) {
		case map[string]any:
			sub := buildObj(tv)
			if len(sub) == 0 {
				return nil, false
			}
			return sub, true
		case []any:
			hasMap := false
			for _, elem := range tv {
				if _, isM := elem.(map[string]any); isM {
					hasMap = true
					break
				}
			}
			if hasMap {
				mergedRaw := make(map[string]any)
				var looseScalars []any
				for _, elem := range tv {
					if elem == nil {
						continue
					}
					if em, ok := elem.(map[string]any); ok {
						mergeObjectArrayElementIntoMap(mergedRaw, em)
					} else {
						looseScalars = append(looseScalars, elem)
					}
				}
				sub := buildObj(mergedRaw)
				if len(looseScalars) == 0 {
					if len(sub) == 0 {
						return nil, false
					}
					return sub, true
				}
				var out []any
				if len(sub) > 0 {
					out = append(out, sub)
				}
				if ls, okL := buildLeaf(looseScalars); okL {
					if lsSlice, isS := ls.([]any); isS {
						out = append(out, lsSlice...)
					} else {
						out = append(out, ls)
					}
				}
				if len(out) == 0 {
					return nil, false
				}
				return out, true
			}
			var docValStrs []string
			seenDV := make(map[string]bool)
			var ignoredStrs []string
			var collectScalars func(items []any)
			collectScalars = func(items []any) {
				for _, it := range items {
					if it == nil {
						continue
					}
					if subS, isS := it.([]any); isS {
						collectScalars(subS)
						continue
					}
					s, over, ok := formatLeafScalar(it)
					if !ok {
						continue
					}
					if over {
						ignoredStrs = append(ignoredStrs, s)
					} else if !seenDV[s] {
						seenDV[s] = true
						docValStrs = append(docValStrs, s)
					}
				}
			}
			collectScalars(tv)
			sort.Strings(docValStrs)
			total := len(docValStrs) + len(ignoredStrs)
			if total == 0 {
				return nil, false
			}
			if total == 1 {
				if len(docValStrs) == 1 {
					return docValStrs[0], true
				}
				return ignoredStrs[0], true
			}
			out := make([]any, 0, total)
			for _, s := range docValStrs {
				out = append(out, s)
			}
			for _, s := range ignoredStrs {
				out = append(out, s)
			}
			return out, true
		default:
			s, _, ok := formatLeafScalar(tv)
			if !ok {
				return nil, false
			}
			return s, true
		}
	}

	buildObj = func(m map[string]any) map[string]any {
		if len(m) == 0 {
			return nil
		}
		expanded := expandDottedKeysForSyntheticObject(nil, m, "")
		out := make(map[string]any, len(expanded))
		keys := make([]string, 0, len(expanded))
		for k := range expanded {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val, keep := buildLeaf(expanded[k])
			if keep {
				out[k] = val
			}
		}
		return out
	}

	return buildLeaf(rawVal)
}

func reconstructSyntheticSparseVectorValue(idxSchema *IndexSchema, rawVal any) (any, bool) {
	if rawVal == nil {
		return nil, false
	}
	switch tv := rawVal.(type) {
	case map[string]any:
		if len(tv) == 0 {
			return nil, false
		}
		out := make(map[string]any, len(tv))
		for tk, wRaw := range tv {
			fv, ok := syntheticToFloat64(wRaw)
			if !ok || math.IsNaN(fv) || math.IsInf(fv, 0) {
				continue
			}
			f32 := normalizeCleanFloat32AsFloat64(fv)
			if f32 <= 0 {
				continue
			}
			out[tk] = f32
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case []any:
		if len(tv) == 0 {
			return nil, false
		}
		merged := make(map[string]any)
		for _, elem := range tv {
			em, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			for tk, wRaw := range em {
				fv, okF := syntheticToFloat64(wRaw)
				if !okF || math.IsNaN(fv) || math.IsInf(fv, 0) {
					continue
				}
				f32 := normalizeCleanFloat32AsFloat64(fv)
				if f32 <= 0 {
					continue
				}
				if prev, had := merged[tk].(float64); !had || f32 > prev {
					merged[tk] = f32
				}
			}
		}
		if len(merged) == 0 {
			return nil, false
		}
		return merged, true
	default:
		return nil, false
	}
}

func reconstructSyntheticAnnotatedTextValue(
	idxSchema *IndexSchema,
	rawVal any,
	fullPath string,
	b FieldBinding,
) (any, bool) {
	if rawVal == nil {
		return nil, false
	}
	// Check whether `store: true` is used (on the field itself or on a synthetic-capable subfield with `doc_values: false`)
	// vs SortedSetDocValues on a `.keyword` multi-field (`mapper_annotatedtext/20_synthetic_source.yml:79-197`).
	preservesStoredOrderAndDups := false
	if idxSchema != nil && idxSchema.RawMapping != nil {
		if fp, ok := lookupRawFieldProperty(idxSchema.RawMapping.Properties, strings.Split(fullPath, ".")); ok {
			if fp.Store != nil && *fp.Store {
				preservesStoredOrderAndDups = true
			} else if fp.SyntheticSourceKeep != "" && !strings.EqualFold(fp.SyntheticSourceKeep, "none") {
				preservesStoredOrderAndDups = true
			} else {
				hasDVSub := false
				hasStoredSub := false
				for _, sfp := range fp.Fields {
					sft := strings.ToLower(strings.TrimSpace(sfp.Type))
					if sft == "keyword" || sft == "constant_keyword" || sft == "wildcard" {
						if sfp.DocValues == nil || *sfp.DocValues {
							hasDVSub = true
						} else if sfp.Store != nil && *sfp.Store {
							hasStoredSub = true
						}
					}
				}
				if !hasDVSub && hasStoredSub {
					preservesStoredOrderAndDups = true
				}
			}
		}
	}

	switch tv := rawVal.(type) {
	case []any:
		var strs []string
		var flatten func(items []any)
		flatten = func(items []any) {
			for _, it := range items {
				if it == nil {
					continue
				}
				if sub, isS := it.([]any); isS {
					flatten(sub)
					continue
				}
				strs = append(strs, fmt.Sprintf("%v", it))
			}
		}
		flatten(tv)
		if len(strs) == 0 {
			return nil, false
		}
		if !preservesStoredOrderAndDups {
			seen := make(map[string]bool, len(strs))
			dedup := make([]string, 0, len(strs))
			for _, s := range strs {
				if !seen[s] {
					seen[s] = true
					dedup = append(dedup, s)
				}
			}
			sort.Strings(dedup)
			strs = dedup
		}
		if len(strs) == 1 {
			return strs[0], true
		}
		out := make([]any, len(strs))
		for i, s := range strs {
			out[i] = s
		}
		return out, true
	default:
		return fmt.Sprintf("%v", tv), true
	}
}

func reconstructSyntheticCountedKeywordValue(rawVal any, b FieldBinding) (any, bool) {
	if rawVal == nil {
		return nil, false
	}
	normStr := func(v any) (string, bool) {
		s := fmt.Sprintf("%v", v)
		if b.IgnoreAbove > 0 && len([]rune(s)) > b.IgnoreAbove {
			return s, true
		}
		if b.LowercaseNormalizer {
			s = strings.ToLower(s)
		}
		return s, false
	}
	switch tv := rawVal.(type) {
	case []any:
		var dv []string
		var ignored []string
		var flatten func(items []any)
		flatten = func(items []any) {
			for _, it := range items {
				if it == nil {
					continue
				}
				if sub, isS := it.([]any); isS {
					flatten(sub)
					continue
				}
				s, over := normStr(it)
				if over {
					ignored = append(ignored, s)
				} else {
					dv = append(dv, s)
				}
			}
		}
		flatten(tv)
		sort.Strings(dv)
		all := append(dv, ignored...)
		if len(all) == 0 {
			return nil, false
		}
		if len(all) == 1 {
			return all[0], true
		}
		out := make([]any, len(all))
		for i, s := range all {
			out[i] = s
		}
		return out, true
	default:
		s, _ := normStr(tv)
		return s, true
	}
}

func formatSyntheticDateValue(val any, b FieldBinding, ignoredSet map[string]bool, fullPath string) (any, bool) {
	if val == nil {
		return nil, false
	}
	nowUTC := time.Now().UTC()
	ms, ok := parseSyntheticEpochMillis(val, b.Format, nowUTC)
	if !ok {
		if ignoredSet[fullPath] {
			return nil, false
		}
		return val, true
	}
	firstFmt := ""
	if strings.TrimSpace(b.Format) != "" {
		firstFmt = strings.TrimSpace(strings.Split(b.Format, "||")[0])
	}
	switch firstFmt {
	case "epoch_millis":
		return ms, true
	case "epoch_second":
		return ms / 1000, true
	case "", "strict_date_optional_time", "date_optional_time", "strict_date_time", "date_time":
		return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z"), true
	default:
		if goLayout := ESDateFormatToGoLayout(firstFmt); goLayout != "" {
			return time.UnixMilli(ms).UTC().Format(goLayout), true
		}
		return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z"), true
	}
}

func parseSyntheticEpochMillis(val any, format string, now time.Time) (int64, bool) {
	switch v := val.(type) {
	case int:
		return ParseESDateWithFormatToEpochMillis(strconv.Itoa(v), format, now)
	case int64:
		return ParseESDateWithFormatToEpochMillis(strconv.FormatInt(v, 10), format, now)
	case json.Number:
		return ParseESDateWithFormatToEpochMillis(v.String(), format, now)
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return ParseESDateWithFormatToEpochMillis(strconv.FormatFloat(v, 'f', -1, 64), format, now)
	case string:
		if strings.TrimSpace(v) == "" {
			return 0, false
		}
		return ParseESDateWithFormatToEpochMillis(v, format, now)
	default:
		return 0, false
	}
}

func normalizeCleanFloat32AsFloat64(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return f
	}
	s := strconv.FormatFloat(float64(float32(f)), 'g', -1, 32)
	if parsed, err := strconv.ParseFloat(s, 64); err == nil {
		return parsed
	}
	return float64(float32(f))
}

// --- F4: TSDB Multi-Value & `ip` / `unsigned_long` Dimensions, `routing_path`, and `logsdb` Index Sort Validation ---

func extractAllDocLeafValuesAtPath(node any, parts []string) ([]any, bool) {
	if node == nil {
		return nil, false
	}
	if len(parts) == 0 {
		return []any{node}, true
	}
	switch curr := node.(type) {
	case map[string]any:
		var out []any
		found := false
		head := parts[0] // #nosec G602 -- len(parts) > 0 checked above
		if nxt, exists := curr[head]; exists {
			vals, ok := extractAllDocLeafValuesAtPath(nxt, parts[1:])
			if ok {
				out = append(out, vals...)
				found = true
			}
		}
		if len(parts) >= 2 {
			joined := strings.Join(parts, ".")
			if nxt, exists := curr[joined]; exists {
				vals, ok := extractAllDocLeafValuesAtPath(nxt, nil)
				if ok {
					out = append(out, vals...)
					found = true
				}
			}
			for idx := len(parts) - 1; idx >= 2; idx-- {
				pfx := strings.Join(parts[:idx], ".")
				if nxt, exists := curr[pfx]; exists {
					vals, ok := extractAllDocLeafValuesAtPath(nxt, parts[idx:])
					if ok {
						out = append(out, vals...)
						found = true
					}
				}
			}
		}
		return out, found
	case []any:
		var out []any
		found := false
		for _, elem := range curr {
			if em, isMap := elem.(map[string]any); isMap {
				vals, ok := extractAllDocLeafValuesAtPath(em, parts)
				if ok {
					out = append(out, vals...)
					found = true
				}
			}
		}
		return out, found
	default:
		return nil, false
	}
}

func flattenAndParseTSDBDimensionValues(
	idx *IndexSchema,
	fieldName string,
	b FieldBinding,
	rawCandidates []any,
) ([]tsdbTypedDimension, error) {
	effB := b
	if idx != nil {
		effB = idx.withEffectiveDefaults(b)
	}
	ignoreMal := effB.IgnoreMalformed != nil && *effB.IgnoreMalformed
	var parsed []tsdbTypedDimension

	var walk func(v any) error
	walk = func(v any) error {
		if v == nil {
			if effB.NullValue != nil {
				return walk(effB.NullValue)
			}
			return nil
		}
		if arr, isArr := v.([]any); isArr {
			for _, item := range arr {
				if err := walk(item); err != nil {
					return err
				}
			}
			return nil
		}
		if _, isMap := v.(map[string]any); isMap {
			return fmt.Errorf("mapper_parsing_exception: time_series_dimension field [%s] must be a scalar value", fieldName)
		}
		if effB.IgnoreAbove > 0 {
			s := fmt.Sprintf("%v", v)
			if len([]rune(s)) > effB.IgnoreAbove {
				return nil
			}
		}
		if strVal, isStr := v.(string); isStr && strings.TrimSpace(strVal) == "" && effB.ESType != "keyword" && effB.ESType != "constant_keyword" && effB.ESType != "wildcard" {
			if effB.NullValue != nil && (effB.Coerce == nil || *effB.Coerce) {
				return walk(effB.NullValue)
			}
			if effB.Coerce == nil || *effB.Coerce {
				return nil
			}
		}
		td, err := parseTSDBTypedDimensionScalar(fieldName, effB, v)
		if err != nil {
			if ignoreMal {
				return nil
			}
			return err
		}
		parsed = append(parsed, td)
		return nil
	}

	for _, rc := range rawCandidates {
		if err := walk(rc); err != nil {
			return nil, err
		}
	}
	if len(parsed) <= 1 {
		return parsed, nil
	}
	// Deduplicate and canonically sort multi-value dimension entries for deterministic TSID hashing.
	sort.Slice(parsed, func(i, j int) bool {
		switch parsed[i].kind {
		case tsdbDimKindLong:
			return parsed[i].intVal < parsed[j].intVal
		case tsdbDimKindUnsignedLong:
			return parsed[i].uintVal < parsed[j].uintVal
		case tsdbDimKindBool:
			return !parsed[i].boolVal && parsed[j].boolVal
		default:
			return bytes.Compare(encodeTSDBTypedDimensionBytes(parsed[i]), encodeTSDBTypedDimensionBytes(parsed[j])) < 0
		}
	})
	dedup := parsed[:0]
	for i, d := range parsed {
		if i > 0 && d.canon == parsed[i-1].canon && d.kind == parsed[i-1].kind {
			continue
		}
		dedup = append(dedup, d)
	}
	return dedup, nil
}

// ExtractIndexSortFieldsFromSettings returns explicitly configured `index.sort.field` entries from `settings`.
func ExtractIndexSortFieldsFromSettings(settings map[string]any) ([]string, bool) {
	if len(settings) == 0 {
		return nil, false
	}
	raw, ok := lookupIndexSettingPath(settings, "index.sort.field", "sort.field")
	if !ok || raw == nil {
		return nil, false
	}
	switch v := raw.(type) {
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return nil, true
		}
		return []string{s}, true
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, s)
			}
		}
		return out, true
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if item == nil {
				continue
			}
			if s := strings.TrimSpace(fmt.Sprintf("%v", item)); s != "" {
				out = append(out, s)
			}
		}
		return out, true
	}
	return nil, false
}

// ValidateIndexSortFields validates explicit `index.sort.field` settings against `idx` (`logsdb/10_settings.yml`, `indices.sort/*`):
//   - Rejects fields inside or equal to a `nested` object (`cannot apply index sort to field [<f>] under nested object [<root>]`)
//   - Rejects unknown / unmapped sort fields (`unknown index sort field:[<f>]`)
//   - Rejects field types that do not support index sorting (`text`, `annotated_text`, `search_as_you_type`, `dense_vector`, `rank_feature`, etc. or `doc_values: false`).
func ValidateIndexSortFields(idx *IndexSchema, settings map[string]any) error {
	fields, explicit := ExtractIndexSortFieldsFromSettings(settings)
	if !explicit || len(fields) == 0 || idx == nil {
		return nil
	}
	for _, sf := range fields {
		// 1. Check nested roots first (`logsdb/10_settings.yml:439`, `indices.sort/20_nested.yml`)
		for np := range idx.NestedRoots {
			if sf == np || strings.HasPrefix(sf, np+".") {
				return esWireError(fmt.Sprintf("illegal_argument_exception: cannot apply index sort to field [%s] under nested object [%s]", sf, np))
			}
		}
		if idx.RawMapping != nil {
			if nestedAnc := findNestedAncestorInProps(idx.RawMapping.Properties, strings.Split(sf, "."), sf); nestedAnc != "" {
				return esWireError(fmt.Sprintf("illegal_argument_exception: cannot apply index sort to field [%s] under nested object [%s]", sf, nestedAnc))
			}
		}
		b, exists := idx.Fields[sf]
		if !exists {
			return esWireError(fmt.Sprintf("illegal_argument_exception: unknown index sort field:[%s]", sf))
		}
		if b.NestedPath != "" {
			return esWireError(fmt.Sprintf("illegal_argument_exception: cannot apply index sort to field [%s] under nested object [%s]", sf, b.NestedPath))
		}
		if b.DocValuesFalse || b.EnabledFalse {
			return esWireError(fmt.Sprintf("illegal_argument_exception: Cannot sort an index on field [%s] because doc_values are disabled", sf))
		}
		switch strings.ToLower(strings.TrimSpace(b.ESType)) {
		case "text", "match_only_text", "annotated-text", "annotated_text", "search_as_you_type",
			"completion", "dense_vector", "knn_vector", "sparse_vector", "rank_feature", "rank_features",
			"geo_point", "geo_shape", "point", "shape", "percolator", "join", "flattened", "histogram",
			"aggregate_metric_double":
			return esWireError(fmt.Sprintf("illegal_argument_exception: Cannot sort an index on field [%s] of type [%s]", sf, b.ESType))
		}
	}
	return nil
}

func findNestedAncestorInProps(props map[string]esast.FieldProperty, _ []string, fullField string) string {
	if len(props) == 0 || fullField == "" {
		return ""
	}
	parts := strings.Split(fullField, ".")
	curr := props
	for i := 0; i < len(parts); i++ {
		fp, ok := curr[parts[i]]
		if !ok {
			return ""
		}
		if strings.EqualFold(strings.TrimSpace(fp.Type), "nested") {
			return strings.Join(parts[:i+1], ".")
		}
		curr = fp.Properties
	}
	return ""
}
