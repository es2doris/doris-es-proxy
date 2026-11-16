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
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
	"github.com/es2doris/doris-es-proxy/pkg/transpiler"
)

const defaultSearchMaxBucketsRound60 = 65536

func cloneFieldMetaMapRound60(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// applyFieldMappingEntryRound60 enriches a `GET _mapping/field` entry with `meta`, explicit
// field attributes, and (when `includeDefaults` is true) Elasticsearch per-type defaults (`F11`).
func applyFieldMappingEntryRound60(fieldDef map[string]any, fb schema.FieldBinding, includeDefaults bool) {
	if fieldDef == nil {
		return
	}
	esType := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", fieldDef["type"])))
	if len(fb.Meta) > 0 {
		fieldDef["meta"] = cloneFieldMetaMapRound60(fb.Meta)
	}
	if fb.Format != "" {
		fieldDef["format"] = fb.Format
	}
	if fb.Analyzer != "" {
		fieldDef["analyzer"] = fb.Analyzer
	}
	if fb.SearchAnalyzer != "" {
		fieldDef["search_analyzer"] = fb.SearchAnalyzer
	}
	if fb.LowercaseNormalizer {
		fieldDef["normalizer"] = "lowercase"
	}
	if fb.NullValue != nil {
		fieldDef["null_value"] = fb.NullValue
	}
	if fb.IgnoreAbove > 0 {
		fieldDef["ignore_above"] = fb.IgnoreAbove
	}
	if fb.ScalingFactor > 0 {
		fieldDef["scaling_factor"] = fb.ScalingFactor
	}
	if fb.HasConstantValue && fb.ConstantValue != nil {
		fieldDef["value"] = fb.ConstantValue
	}
	if len(fb.Relations) > 0 {
		fieldDef["relations"] = fb.Relations
	}
	if !includeDefaults || esType == "alias" || esType == "nested" || esType == "object" {
		return
	}

	fieldDef["boost"] = 1.0
	fieldDef["index"] = !fb.NotIndexed
	fieldDef["store"] = false

	switch esType {
	case "text", "match_only_text", "annotated-text", "annotated_text", "search_as_you_type":
		fieldDef["norms"] = esType == "text" || esType == "annotated-text" || esType == "annotated_text"
		fieldDef["index_options"] = "positions"
		if esType == "match_only_text" {
			fieldDef["index_options"] = "docs"
		}
		fieldDef["eager_global_ordinals"] = false
		fieldDef["fielddata"] = false
	case "keyword", "wildcard":
		fieldDef["doc_values"] = !fb.DocValuesFalse
		fieldDef["norms"] = false
		fieldDef["index_options"] = "freqs"
		fieldDef["eager_global_ordinals"] = false
		fieldDef["split_queries_on_whitespace"] = false
		if _, has := fieldDef["ignore_above"]; !has {
			fieldDef["ignore_above"] = 2147483647
		}
		if _, has := fieldDef["null_value"]; !has {
			fieldDef["null_value"] = nil
		}
	case "constant_keyword":
		fieldDef["doc_values"] = true
	case "long", "integer", "short", "byte", "unsigned_long",
		"double", "float", "half_float", "scaled_float":
		fieldDef["doc_values"] = !fb.DocValuesFalse
		fieldDef["coerce"] = fb.EffectiveCoerceBool()
		fieldDef["ignore_malformed"] = fb.IgnoreMalformed != nil && *fb.IgnoreMalformed
		if _, has := fieldDef["null_value"]; !has {
			fieldDef["null_value"] = nil
		}
	case "date", "date_nanos":
		fieldDef["doc_values"] = !fb.DocValuesFalse
		fieldDef["ignore_malformed"] = fb.IgnoreMalformed != nil && *fb.IgnoreMalformed
		if _, has := fieldDef["format"]; !has {
			if esType == "date_nanos" {
				fieldDef["format"] = "strict_date_optional_time_nanos||epoch_millis"
			} else {
				fieldDef["format"] = "strict_date_optional_time||epoch_millis"
			}
		}
		if _, has := fieldDef["null_value"]; !has {
			fieldDef["null_value"] = nil
		}
	case "boolean":
		fieldDef["doc_values"] = !fb.DocValuesFalse
		if _, has := fieldDef["null_value"]; !has {
			fieldDef["null_value"] = nil
		}
	default:
		fieldDef["doc_values"] = !fb.DocValuesFalse
	}
}

func (s *Server) resolvePrimarySchemaForTypedKeysRound60(ctx context.Context, rawIndex string) *schema.IndexSchema {
	targets, _ := s.resolveTargetIndicesWithFilters(rawIndex)
	if len(targets) == 0 && strings.TrimSpace(rawIndex) != "" && !hasExclusionOrWildcard(rawIndex) {
		targets = []string{s.resolveIndexName(rawIndex)}
	}
	if len(targets) == 0 {
		return nil
	}
	return s.getOrCompileReadOnlySchema(ctx, targets[0])
}

// applyTypedKeysToAggregationsWithSchemaRound60 prefixes every aggregation result key with
// `transpiler.TypedAggKeyPrefix(&spec, idxSchema) + "#"` (`F12`).
func applyTypedKeysToAggregationsWithSchemaRound60(
	aggsOut map[string]any,
	aggs map[string]esast.AggSpec,
	idxSchema *schema.IndexSchema,
) {
	if len(aggsOut) == 0 || len(aggs) == 0 {
		return
	}
	for aggName, spec := range aggs {
		val, exists := aggsOut[aggName]
		if !exists {
			continue
		}
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			if aggObj, ok := val.(map[string]any); ok {
				if buckets, ok := aggObj["buckets"].([]map[string]any); ok {
					for _, b := range buckets {
						applyTypedKeysToAggregationsWithSchemaRound60(b, subAggs, idxSchema)
					}
				} else if bucketsAny, ok := aggObj["buckets"].([]any); ok {
					for _, item := range bucketsAny {
						if b, ok := item.(map[string]any); ok {
							applyTypedKeysToAggregationsWithSchemaRound60(b, subAggs, idxSchema)
						}
					}
				} else if bucketsMap, ok := aggObj["buckets"].(map[string]any); ok {
					for _, bv := range bucketsMap {
						if bm, ok := bv.(map[string]any); ok {
							applyTypedKeysToAggregationsWithSchemaRound60(bm, subAggs, idxSchema)
						}
					}
				} else {
					applyTypedKeysToAggregationsWithSchemaRound60(aggObj, subAggs, idxSchema)
				}
			}
		}
		specCopy := spec
		prefix := transpiler.TypedAggKeyPrefix(&specCopy, idxSchema)
		delete(aggsOut, aggName)
		aggsOut[prefix+"#"+aggName] = val
	}
}

// attachAllAggMetasRound60 recursively attaches `"meta": spec.Meta` onto every aggregation
// result object (`metric`, `bucket`, and `pipeline`) when `len(spec.Meta) > 0` (`F12`).
func attachAllAggMetasRound60(aggsOut map[string]any, aggs map[string]esast.AggSpec) {
	if len(aggsOut) == 0 || len(aggs) == 0 {
		return
	}
	for aggName, spec := range aggs {
		val, exists := aggsOut[aggName]
		if !exists {
			continue
		}
		aggObj, ok := val.(map[string]any)
		if !ok || aggObj == nil {
			continue
		}
		if len(spec.Meta) > 0 {
			aggObj["meta"] = spec.Meta
		}
		if subAggs := spec.SubAggs(); len(subAggs) > 0 {
			if buckets, ok := aggObj["buckets"].([]map[string]any); ok {
				for _, b := range buckets {
					attachAllAggMetasRound60(b, subAggs)
				}
			} else if bucketsAny, ok := aggObj["buckets"].([]any); ok {
				for _, item := range bucketsAny {
					if b, ok := item.(map[string]any); ok {
						attachAllAggMetasRound60(b, subAggs)
					}
				}
			} else if bucketsMap, ok := aggObj["buckets"].(map[string]any); ok {
				for _, bv := range bucketsMap {
					if bm, ok := bv.(map[string]any); ok {
						attachAllAggMetasRound60(bm, subAggs)
					}
				}
			} else {
				attachAllAggMetasRound60(aggObj, subAggs)
			}
		}
	}
}

// termsFieldTypeRound60 resolves the Elasticsearch field type for `terms` partition hashing (`F13`).
func termsFieldTypeRound60(spec *esast.TermsAggSpec, idxSchema *schema.IndexSchema) string {
	if spec == nil {
		return ""
	}
	if vt := strings.ToLower(strings.TrimSpace(spec.ValueType)); vt != "" {
		return vt
	}
	if spec.Script != nil && spec.Field == "" {
		return "keyword"
	}
	if idxSchema != nil && spec.Field != "" {
		b := idxSchema.ResolveEffectiveField(spec.Field, true)
		if b.ESType != "" {
			return strings.ToLower(strings.TrimSpace(b.ESType))
		}
		switch b.DorisType {
		case schema.DorisLargeInt:
			return "unsigned_long"
		case schema.DorisBigInt, schema.DorisInt:
			return "long"
		case schema.DorisDouble:
			return "double"
		case schema.DorisBoolean:
			return "boolean"
		}
	}
	return "keyword"
}

func matchesTermsFilterPrecompiledWithSchemaRound60(key string, filter any, precompiled *regexp.Regexp, fieldType string) bool {
	if m, isMap := filter.(map[string]any); isMap {
		numPart, okNP := toInt64(m["num_partitions"])
		part, okP := toInt64(m["partition"])
		if okNP && okP && numPart > 0 && part >= 0 && part < numPart {
			return transpiler.ESTermsPartitionMatch(key, fieldType, int(part), int(numPart))
		}
		return false
	}
	return matchesTermsFilterPrecompiled(key, filter, precompiled)
}

func formatDateHistogramKeyAsStringRound60(epochMs int64, spec *esast.DateHistogramAggSpec) string {
	var tzOffsetMs int64
	var formatStr string
	if spec != nil {
		tzOffsetMs = spec.EffectiveTimeZoneOffsetMs()
		formatStr = strings.TrimSpace(spec.Format)
	}
	loc := time.UTC
	if tzOffsetMs != 0 {
		loc = time.FixedZone("ES_TZ", int(tzOffsetMs/1000))
	}
	if formatStr == "" {
		t := time.UnixMilli(epochMs).In(loc)
		if tzOffsetMs != 0 {
			return t.Format("2006-01-02T15:04:05.000-07:00")
		}
		return t.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return transpiler.FormatESDateWithNamedOrJavaPattern(epochMs, 0, formatStr, loc)
}

// aggsHaveHDRPercentilesRound60 reports whether any aggregation in `aggs` uses HDRHistogram
// (`hdr: {"number_of_significant_value_digits": ...}`) (`F14`).
func aggsHaveHDRPercentilesRound60(aggs map[string]esast.AggSpec) bool {
	for _, spec := range aggs {
		if spec.Percentiles != nil && spec.Percentiles.HDR != nil {
			return true
		}
		if spec.PercentileRanks != nil && spec.PercentileRanks.HDR != nil {
			return true
		}
		if sub := spec.SubAggs(); len(sub) > 0 && aggsHaveHDRPercentilesRound60(sub) {
			return true
		}
	}
	return false
}

func coerceHDRFloatRound60(v any, idxSchema *schema.IndexSchema, field string) (float64, bool) {
	if v == nil {
		return 0, false
	}
	switch tv := v.(type) {
	case float64:
		if !math.IsNaN(tv) && !math.IsInf(tv, 0) {
			return tv, true
		}
	case float32:
		f := float64(tv)
		if !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
	case int:
		return float64(tv), true
	case int64:
		return float64(tv), true
	case uint64:
		return float64(tv), true
	case json.Number:
		if f, err := tv.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
	case bool:
		if tv {
			return 1, true
		}
		return 0, true
	case string:
		s := strings.TrimSpace(tv)
		if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
		var fmtHint string
		if idxSchema != nil && field != "" {
			fmtHint = idxSchema.ResolveField(field).Format
		}
		if ms, ok := schema.ParseESDateWithFormatToEpochMillis(s, fmtHint, time.Now().UTC()); ok {
			return float64(ms), true
		}
	}
	return 0, false
}

func (s *Server) effectiveSearchMaxBucketsRound60() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range []map[string]any{s.clusterTransientSettings, s.clusterPersistentSettings} {
		if len(m) == 0 {
			continue
		}
		raw, ok := m["search.max_buckets"]
		if !ok {
			raw, ok = extractIndexSettingValueRound59(m, "search.max_buckets")
		}
		if ok && raw != nil {
			if iv, okI := toInt64(raw); okI {
				return int(iv)
			}
			if str, okS := raw.(string); okS {
				if iv, err := strconv.Atoi(strings.TrimSpace(str)); err == nil {
					return iv
				}
			}
		}
	}
	return defaultSearchMaxBucketsRound60
}

func countAggBucketsRecursiveRound60(aggsOut map[string]any, aggs map[string]esast.AggSpec) int {
	if len(aggsOut) == 0 || len(aggs) == 0 {
		return 0
	}
	total := 0
	for aggName, spec := range aggs {
		val, exists := aggsOut[aggName]
		if !exists {
			continue
		}
		aggObj, ok := val.(map[string]any)
		if !ok || aggObj == nil {
			continue
		}
		subAggs := spec.SubAggs()
		if buckets, ok := aggObj["buckets"].([]map[string]any); ok {
			total += len(buckets)
			if len(subAggs) > 0 {
				for _, b := range buckets {
					total += countAggBucketsRecursiveRound60(b, subAggs)
				}
			}
		} else if bucketsAny, ok := aggObj["buckets"].([]any); ok {
			total += len(bucketsAny)
			if len(subAggs) > 0 {
				for _, item := range bucketsAny {
					if b, ok := item.(map[string]any); ok {
						total += countAggBucketsRecursiveRound60(b, subAggs)
					}
				}
			}
		} else if bucketsMap, ok := aggObj["buckets"].(map[string]any); ok {
			total += len(bucketsMap)
			if len(subAggs) > 0 {
				for _, bv := range bucketsMap {
					if bm, ok := bv.(map[string]any); ok {
						total += countAggBucketsRecursiveRound60(bm, subAggs)
					}
				}
			}
		} else if isBucketAggSpec(spec) {
			total++
			if len(subAggs) > 0 {
				total += countAggBucketsRecursiveRound60(aggObj, subAggs)
			}
		}
	}
	return total
}

// validateSearchMaxBucketsRound60 enforces the cluster-wide `search.max_buckets` circuit breaker (`F15`).
func (s *Server) validateSearchMaxBucketsRound60(resp map[string]any, aggs map[string]esast.AggSpec) error {
	if resp == nil || len(aggs) == 0 {
		return nil
	}
	maxBuckets := s.effectiveSearchMaxBucketsRound60()
	if maxBuckets <= 0 {
		return nil
	}
	aggsOut, _ := resp["aggregations"].(map[string]any)
	if len(aggsOut) == 0 {
		return nil
	}
	if cnt := countAggBucketsRecursiveRound60(aggsOut, aggs); cnt > maxBuckets {
		return fmt.Errorf( //nolint:staticcheck // ES exact error message
			"all_shards_failed|too_many_buckets_exception|Trying to create too many buckets. Must be less than or equal to: [%d] but this number of buckets was exceeded. This limit can be set by changing the [search.max_buckets] cluster level setting.",
			maxBuckets,
		)
	}
	return nil
}
