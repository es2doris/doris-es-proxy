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

package transpiler

import (
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/es2doris/doris-es-proxy/pkg/esast"
	"github.com/es2doris/doris-es-proxy/pkg/schema"
)

const (
	DefaultMaxDocvalueFieldsSearch = 100
	DefaultMaxScriptFields         = 32
	DefaultMaxRegexLength          = 1000
)

func (t *Transpiler) effectiveMaxResultWindow() int {
	if t.Opts.MaxResultWindow > 0 {
		return t.Opts.MaxResultWindow
	}
	if t.Schema != nil && t.Schema.MaxResultWindow > 0 {
		return t.Schema.MaxResultWindow
	}
	return DefaultMaxResultWindow
}

func (t *Transpiler) effectiveMaxDocvalueFieldsSearch() int {
	if t.Opts.MaxDocvalueFieldsSearch > 0 {
		return t.Opts.MaxDocvalueFieldsSearch
	}
	if t.Schema != nil && t.Schema.MaxDocvalueFieldsSearch > 0 {
		return t.Schema.MaxDocvalueFieldsSearch
	}
	return DefaultMaxDocvalueFieldsSearch
}

func (t *Transpiler) effectiveMaxScriptFields() int {
	if t.Opts.MaxScriptFields > 0 {
		return t.Opts.MaxScriptFields
	}
	if t.Schema != nil && t.Schema.MaxScriptFields > 0 {
		return t.Schema.MaxScriptFields
	}
	return DefaultMaxScriptFields
}

func (t *Transpiler) effectiveMaxRegexLength() int {
	if t.Opts.MaxRegexLength > 0 {
		return t.Opts.MaxRegexLength
	}
	if t.Schema != nil && t.Schema.MaxRegexLength > 0 {
		return t.Schema.MaxRegexLength
	}
	return DefaultMaxRegexLength
}

func (t *Transpiler) countExpandedDocvalueFields(dvfs []esast.FieldRequestSpec) int {
	if len(dvfs) == 0 {
		return 0
	}
	count := 0
	for _, dvf := range dvfs {
		if strings.ContainsAny(dvf.Field, "*?") && t.Schema != nil && len(t.Schema.OrderedFields) > 0 {
			re := wildcardPatternRegex(dvf.Field, false)
			matched := 0
			for _, fb := range t.Schema.OrderedFields {
				if fb.EnabledFalse || fb.DocValuesFalse || fb.ESType == "alias" || schema.IsTextLikeESType(fb.ESType) {
					continue
				}
				if re != nil && re.MatchString(fb.ESFieldPath) {
					matched++
				}
			}
			count += matched
		} else {
			count++
		}
	}
	return count
}

func (t *Transpiler) validateDocvalueAndScriptFieldLimits(dvfs []esast.FieldRequestSpec, scriptFields map[string]any) error {
	maxDV := t.effectiveMaxDocvalueFieldsSearch()
	if dvCount := t.countExpandedDocvalueFields(dvfs); dvCount > maxDV {
		return fmt.Errorf("illegal_argument_exception: Trying to retrieve too many docvalue_fields. Must be less than or equal to: [%d] but was [%d]. This limit can be set by changing the [index.max_docvalue_fields_search] index level setting.", maxDV, dvCount) //nolint:staticcheck // ES exact error message
	}
	maxSF := t.effectiveMaxScriptFields()
	if sfCount := len(scriptFields); sfCount > maxSF {
		return fmt.Errorf("illegal_argument_exception: Trying to retrieve too many script_fields. Must be less than or equal to: [%d] but was [%d]. This limit can be set by changing the [index.max_script_fields] index level setting.", maxSF, sfCount) //nolint:staticcheck // ES exact error message
	}
	return nil
}

func (t *Transpiler) checkRegexLengthLimit(pattern string) bool {
	maxLen := t.effectiveMaxRegexLength()
	if utf8.RuneCountInString(pattern) > maxLen {
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = fmt.Errorf("illegal_argument_exception: Regular expression [%s] exceeds max_regex_length [%d]", pattern, maxLen)
		}
		return false
	}
	return true
}

func (t *Transpiler) collapseFieldMatchesSortField(collapseField, sortField string) bool {
	cf := strings.TrimSpace(collapseField)
	sf := strings.TrimSpace(sortField)
	if cf == "" || sf == "" {
		return false
	}
	if strings.HasPrefix(sf, "_") {
		return false
	}
	if cf == sf {
		return true
	}
	if t.Schema == nil {
		return false
	}
	bCol := t.Schema.ResolveEffectiveField(cf, true)
	bSort := t.Schema.ResolveEffectiveField(sf, true)
	effCol := cf
	if bCol.AliasTarget != "" {
		effCol = bCol.AliasTarget
	}
	effSort := sf
	if bSort.AliasTarget != "" {
		effSort = bSort.AliasTarget
	}
	if effCol == effSort {
		return true
	}
	if bCol.ColumnName != "" && bCol.ColumnName == bSort.ColumnName && bCol.KeywordCompanion == bSort.KeywordCompanion {
		return true
	}
	return false
}

func (t *Transpiler) validateCollapseRequest(req *esast.SearchRequest) error {
	if req == nil || req.Collapse == nil {
		return nil
	}
	if len(req.Rescore) > 0 {
		return fmt.Errorf("illegal_argument_exception: cannot use `collapse` in conjunction with `rescore`")
	}
	if req.Slice != nil {
		return fmt.Errorf("illegal_argument_exception: cannot use [collapse] in conjunction with [slice]")
	}
	if len(req.SearchAfter) > 0 {
		if len(req.Sort) == 0 || !t.collapseFieldMatchesSortField(req.Collapse.Field, req.Sort[0].Entry.Field) {
			return fmt.Errorf("illegal_argument_exception: cannot use `collapse` in conjunction with `search_after` unless the sort is on the collapse field")
		}
	}
	for _, ih := range req.Collapse.InnerHits {
		if err := t.validateDocvalueAndScriptFieldLimits(ih.DocvalueFields, ih.ScriptFields); err != nil {
			return err
		}
		if ih.Collapse != nil {
			if len(ih.Collapse.InnerHits) > 0 {
				return fmt.Errorf("illegal_argument_exception: collapse inner_hits does not support nested inner_hits at level > 2")
			}
			if ih.Collapse.Field != "" {
				b2 := t.Schema.ResolveEffectiveField(ih.Collapse.Field, true)
				t.checkFieldDocValues(ih.Collapse.Field, b2)
			}
		}
	}
	return nil
}

// isUnsupportedNumericMetricESType reports whether esType is invalid for numeric metric aggregations
// (`avg`, `sum`, `min`, `max`, `stats`, `extended_stats`, `percentiles`, `percentile_ranks`, `boxplot`, `median_absolute_deviation`)
// when no `script` is specified.
func isUnsupportedNumericMetricESType(esType string) bool {
	switch strings.ToLower(strings.TrimSpace(esType)) {
	case "",
		"byte", "short", "integer", "long", "unsigned_long",
		"float", "half_float", "scaled_float", "double",
		"date", "date_nanos", "boolean",
		"histogram", "aggregate_metric_double", "token_count",
		"integer_range", "long_range", "float_range", "double_range", "date_range":
		return false
	default:
		return true
	}
}

func isNumericMetricAggKind(aggKind string) bool {
	switch aggKind {
	case "avg", "sum", "min", "max", "stats", "extended_stats",
		"percentiles", "percentile_ranks", "boxplot", "median_absolute_deviation":
		return true
	default:
		return false
	}
}

func validateTermsIncludeExcludeForBinding(field string, b schema.FieldBinding, termsSpec *esast.TermsAggSpec) error {
	return validateTermsIncludeExcludeForBindingNamed("terms", field, b, termsSpec)
}

func validateTermsIncludeExcludeForBindingNamed(aggName, field string, b schema.FieldBinding, termsSpec *esast.TermsAggSpec) error {
	if termsSpec == nil || termsSpec.Script != nil || field == "" {
		return nil
	}
	tLower := strings.ToLower(strings.TrimSpace(b.ESType))
	if tLower == "" {
		return nil
	}
	isNonRegexTermsType := false
	switch tLower {
	case "ip", "boolean", "date", "date_nanos",
		"byte", "short", "integer", "long", "unsigned_long",
		"float", "half_float", "scaled_float", "double":
		isNonRegexTermsType = true
	}
	if !isNonRegexTermsType {
		return nil
	}
	if _, isStr := termsSpec.Include.(string); isStr {
		return fmt.Errorf("illegal_argument_exception: Aggregation [%s] cannot support regular expression style include/exclude settings as they can only be applied to string fields. Use an array of values for include/exclude clauses", aggName)
	}
	if _, isStr := termsSpec.Exclude.(string); isStr {
		return fmt.Errorf("illegal_argument_exception: Aggregation [%s] cannot support regular expression style include/exclude settings as they can only be applied to string fields. Use an array of values for include/exclude clauses", aggName)
	}
	return nil
}

// TypedAggKeyPrefix returns the exact Elasticsearch `typed_keys` type prefix for an `AggSpec`.
func TypedAggKeyPrefix(agg *esast.AggSpec, idxSchema *schema.IndexSchema) string {
	if agg == nil {
		return "unknown"
	}
	resolveFieldESType := func(field string) string {
		if field == "" || idxSchema == nil {
			return ""
		}
		b := idxSchema.ResolveEffectiveField(field, true)
		return strings.ToLower(strings.TrimSpace(b.ESType))
	}

	switch {
	case agg.SignificantTerms != nil:
		if agg.SignificantTerms.Script != nil {
			return "sigsterms"
		}
		switch resolveFieldESType(agg.SignificantTerms.Field) {
		case "long", "integer", "short", "byte", "date", "date_nanos", "boolean", "unsigned_long":
			return "siglterms"
		default:
			return "sigsterms"
		}
	case agg.SignificantText != nil:
		return "significant_text"
	case agg.Terms != nil:
		if agg.Terms.Script != nil && agg.Terms.Field == "" {
			return "sterms"
		}
		switch resolveFieldESType(agg.Terms.Field) {
		case "long", "integer", "short", "byte", "date", "date_nanos", "boolean", "token_count":
			return "lterms"
		case "unsigned_long":
			return "uterms"
		case "double", "float", "half_float", "scaled_float":
			return "dterms"
		default:
			return "sterms"
		}
	case agg.MultiTerms != nil:
		return "multi_terms"
	case agg.RareTerms != nil:
		return "rare_terms"
	case agg.Histogram != nil:
		return "histogram"
	case agg.DateHistogram != nil:
		return "date_histogram"
	case agg.AutoDateHistogram != nil:
		return "auto_date_histogram"
	case agg.VariableWidthHistogram != nil:
		return "variable_width_histogram"
	case agg.DateRange != nil:
		return "date_range"
	case agg.IPRange != nil:
		return "ip_range"
	case agg.Range != nil:
		return "range"
	case agg.GeoDistance != nil:
		return "geo_distance"
	case agg.GeohashGrid != nil:
		return "geohash_grid"
	case agg.GeotileGrid != nil:
		return "geotile_grid"
	case agg.Filter != nil:
		return "filter"
	case agg.Filters != nil:
		return "filters"
	case agg.Global != nil:
		return "global"
	case agg.Missing != nil:
		return "missing"
	case agg.Nested != nil:
		return "nested"
	case agg.ReverseNested != nil:
		return "reverse_nested"
	case agg.Sampler != nil:
		return "sampler"
	case agg.DiversifiedSampler != nil:
		return "diversified_sampler"
	case agg.RandomSampler != nil:
		return "random_sampler"
	case agg.CategorizeText != nil:
		return "categorize_text"
	case agg.FrequentItemSets != nil:
		return "frequent_item_sets"
	case agg.AdjacencyMatrix != nil:
		return "adjacency_matrix"
	case agg.Composite != nil:
		return "composite"
	case agg.Avg != nil:
		return "avg"
	case agg.WeightedAvg != nil:
		return "weighted_avg"
	case agg.Sum != nil:
		return "sum"
	case agg.Min != nil:
		return "min"
	case agg.Max != nil:
		return "max"
	case agg.Cardinality != nil:
		return "cardinality"
	case agg.ValueCount != nil:
		return "value_count"
	case agg.Stats != nil:
		return "stats"
	case agg.ExtendedStats != nil:
		return "extended_stats"
	case agg.MatrixStats != nil:
		return "matrix_stats"
	case agg.StringStats != nil:
		return "string_stats"
	case agg.Boxplot != nil:
		return "boxplot"
	case agg.MedianAbsoluteDeviation != nil:
		return "median_absolute_deviation"
	case agg.Percentiles != nil:
		if agg.Percentiles.HDR != nil {
			return "hdr_percentiles"
		}
		return "tdigest_percentiles"
	case agg.PercentileRanks != nil:
		if agg.PercentileRanks.HDR != nil {
			return "hdr_percentile_ranks"
		}
		return "tdigest_percentile_ranks"
	case agg.TopHits != nil:
		return "top_hits"
	case agg.TopMetrics != nil:
		return "top_metrics"
	case agg.ScriptedMetric != nil:
		return "scripted_metric"
	case agg.Rate != nil:
		return "rate"
	case agg.TTest != nil:
		return "t_test"
	case agg.GeoBounds != nil:
		return "geo_bounds"
	case agg.GeoCentroid != nil:
		return "geo_centroid"
	case agg.CartesianBounds != nil:
		return "cartesian_bounds"
	case agg.CartesianCentroid != nil:
		return "cartesian_centroid"
	case agg.GeoLine != nil:
		return "geo_line"
	case agg.MinBucket != nil, agg.MaxBucket != nil:
		return "bucket_metric_value"
	case agg.Derivative != nil:
		return "derivative"
	case agg.AvgBucket != nil,
		agg.SumBucket != nil,
		agg.CumulativeSum != nil,
		agg.MovingAvg != nil,
		agg.MovingFn != nil,
		agg.BucketScript != nil,
		agg.SerialDiff != nil,
		agg.Normalize != nil,
		agg.CumulativeCardinality != nil:
		return "simple_value"
	case agg.StatsBucket != nil:
		return "stats"
	case agg.ExtendedStatsBucket != nil:
		return "extended_stats"
	case agg.PercentilesBucket != nil:
		return "tdigest_percentiles"
	case agg.MovingPercentiles != nil:
		return "tdigest_percentiles"
	case agg.BucketSort != nil:
		return "bucket_sort"
	case agg.BucketSelector != nil:
		return "bucket_selector"
	default:
		return "unknown"
	}
}

// BitMixerMix64 implements CarrotSearch HPPC `BitMixer.mix64(long z)`, used by Elasticsearch
// `IncludeExclude` partition filtering on numeric/date/boolean ordinals.
func BitMixerMix64(z int64) int64 {
	u := uint64(z) // #nosec G115 -- intentional Java two's-complement bit mix
	u = (u ^ (u >> 32)) * 0x4cd6944c5cc20b6d
	u = (u ^ (u >> 29)) * 0xfc12c5b19d3259e9
	return int64(u ^ (u >> 32)) // #nosec G115 -- intentional Java signed 64-bit return
}

// MurmurHash3X86_32 implements Apache Lucene `StringHelper.murmurhash3_x86_32(byte[] data, int offset, int len, int seed)`.
func MurmurHash3X86_32(data []byte, seed uint32) int32 {
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
	)
	h1 := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		idx := i * 4
		k1 := uint32(data[idx]) |
			(uint32(data[idx+1]) << 8) |
			(uint32(data[idx+2]) << 16) |
			(uint32(data[idx+3]) << 24)
		k1 *= c1
		k1 = bits.RotateLeft32(k1, 15)
		k1 *= c2

		h1 ^= k1
		h1 = bits.RotateLeft32(h1, 13)
		h1 = h1*5 + 0xe6546b64
	}

	var k1 uint32
	tail := data[nblocks*4:]
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

	h1 ^= uint32(len(data)) // #nosec G115 -- MurmurHash3_x86_32 length mix
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1) // #nosec G115 -- Java signed 32-bit hash
}

func javaFloorMod32(x int32, y int) int {
	if y <= 0 {
		return 0
	}
	m := int(x) % y
	if m < 0 {
		m += y
	}
	return m
}

func coercePartitionLong(val any) (int64, bool) {
	switch v := val.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case uint64:
		return int64(v), true // #nosec G115 -- Java unsigned_long raw 64-bit ordinal
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			return int64(v), true
		}
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case json.Number:
		if iv, err := v.Int64(); err == nil {
			return iv, true
		}
		if uv, err := strconv.ParseUint(v.String(), 10, 64); err == nil {
			return int64(uv), true // #nosec G115 -- Java unsigned_long raw 64-bit ordinal
		}
		if fv, err := v.Float64(); err == nil {
			return int64(fv), true
		}
	case string:
		s := strings.TrimSpace(v)
		if strings.EqualFold(s, "true") {
			return 1, true
		}
		if strings.EqualFold(s, "false") {
			return 0, true
		}
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil {
			return iv, true
		}
		if uv, err := strconv.ParseUint(s, 10, 64); err == nil {
			return int64(uv), true // #nosec G115 -- Java unsigned_long raw 64-bit ordinal
		}
		if ms, ok := schema.ParseESDateWithFormatToEpochMillis(s, "", time.Now().UTC()); ok {
			return ms, true
		}
	}
	return 0, false
}

func coercePartitionDouble(val any) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, !math.IsNaN(v)
	case float32:
		return float64(v), !math.IsNaN(float64(v))
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case json.Number:
		if fv, err := v.Float64(); err == nil {
			return fv, !math.IsNaN(fv)
		}
	case string:
		if fv, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return fv, !math.IsNaN(fv)
		}
	}
	return 0, false
}

// ESTermsPartitionMatch evaluates Elasticsearch `terms` partition hashing (`Math.floorMod(hash, numPartitions) == partition`),
// using `BitMixer.mix64` for integer/date/boolean/`Double.doubleToRawLongBits` and Lucene `StringHelper.murmurhash3_x86_32` for strings/IPs.
func ESTermsPartitionMatch(val any, fieldType string, partition int, numPartitions int) bool {
	if numPartitions <= 0 || partition < 0 || partition >= numPartitions || val == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(fieldType)) {
	case "long", "integer", "short", "byte", "unsigned_long", "date", "date_nanos", "boolean", "token_count":
		if lv, ok := coercePartitionLong(val); ok {
			h := int32(BitMixerMix64(lv)) // #nosec G115 -- Java (int) BitMixer.mix64 truncation
			return javaFloorMod32(h, numPartitions) == partition
		}
	case "double", "scaled_float":
		if fv, ok := coercePartitionDouble(val); ok {
			bits64 := int64(math.Float64bits(fv)) // #nosec G115 -- Java Double.doubleToRawLongBits
			h := int32(BitMixerMix64(bits64))     // #nosec G115 -- Java (int) BitMixer.mix64 truncation
			return javaFloorMod32(h, numPartitions) == partition
		}
	case "float", "half_float":
		if fv, ok := coercePartitionDouble(val); ok {
			f32 := float64(float32(fv))
			bits64 := int64(math.Float64bits(f32)) // #nosec G115 -- Java Double.doubleToRawLongBits
			h := int32(BitMixerMix64(bits64))      // #nosec G115 -- Java (int) BitMixer.mix64 truncation
			return javaFloorMod32(h, numPartitions) == partition
		}
	case "ip":
		s := strings.TrimSpace(fmt.Sprintf("%v", val))
		if ip := net.ParseIP(s); ip != nil {
			ip16 := ip.To16()
			if ip16 != nil {
				h := MurmurHash3X86_32([]byte(ip16), 0)
				return javaFloorMod32(h, numPartitions) == partition
			}
		}
	}
	s := fmt.Sprintf("%v", val)
	h := MurmurHash3X86_32([]byte(s), 0)
	return javaFloorMod32(h, numPartitions) == partition
}

// FormatESDateWithNamedOrJavaPattern formats an epoch timestamp (`epochNanos` when non-zero, otherwise `epochMillis`)
// in `tz` (defaulting to UTC) using either an Elasticsearch built-in named date format or a Java `DateTimeFormatter` pattern.
func FormatESDateWithNamedOrJavaPattern(epochMillis int64, epochNanos int64, format string, tz *time.Location) string {
	if tz == nil {
		tz = time.UTC
	}
	var tm time.Time
	if epochNanos != 0 {
		sec := epochNanos / 1_000_000_000
		nsec := epochNanos % 1_000_000_000
		if nsec < 0 {
			sec--
			nsec += 1_000_000_000
		}
		tm = time.Unix(sec, nsec).In(tz)
	} else {
		sec := epochMillis / 1000
		msRem := epochMillis % 1000
		if msRem < 0 {
			sec--
			msRem += 1000
		}
		tm = time.Unix(sec, msRem*1_000_000).In(tz)
	}

	rawFmt := strings.TrimSpace(format)
	if idx := strings.Index(rawFmt, "||"); idx >= 0 {
		rawFmt = strings.TrimSpace(rawFmt[:idx])
	}
	if rawFmt == "" {
		return tm.Format("2006-01-02T15:04:05.000Z07:00")
	}

	switch rawFmt {
	case "epoch_millis":
		return strconv.FormatInt(tm.UnixMilli(), 10)
	case "epoch_second":
		return strconv.FormatInt(tm.Unix(), 10)
	case "iso8601", "strict_date_optional_time", "date_optional_time", "date_time", "strict_date_time":
		return tm.Format("2006-01-02T15:04:05.000Z07:00")
	case "strict_date_optional_time_nanos", "date_optional_time_nanos":
		frac := fmt.Sprintf("%09d", tm.Nanosecond())
		for len(frac) > 3 && frac[len(frac)-1] == '0' {
			frac = frac[:len(frac)-1]
		}
		return tm.Format("2006-01-02T15:04:05") + "." + frac + tm.Format("Z07:00")
	case "date_time_no_millis", "strict_date_time_no_millis":
		return tm.Format("2006-01-02T15:04:05Z07:00")
	case "basic_date", "strict_basic_date":
		return tm.Format("20060102")
	case "basic_date_time", "strict_basic_date_time":
		return tm.Format("20060102T150405.000Z0700")
	case "basic_date_time_no_millis", "strict_basic_date_time_no_millis":
		return tm.Format("20060102T150405Z0700")
	case "basic_time", "strict_basic_time":
		return tm.Format("150405.000Z0700")
	case "basic_time_no_millis", "strict_basic_time_no_millis":
		return tm.Format("150405Z0700")
	case "date", "strict_date", "year_month_day", "strict_year_month_day":
		return tm.Format("2006-01-02")
	case "year_month", "strict_year_month":
		return tm.Format("2006-01")
	case "year", "strict_year":
		return tm.Format("2006")
	case "date_hour", "strict_date_hour":
		return tm.Format("2006-01-02T15")
	case "date_hour_minute", "strict_date_hour_minute":
		return tm.Format("2006-01-02T15:04")
	case "date_hour_minute_second", "strict_date_hour_minute_second":
		return tm.Format("2006-01-02T15:04:05")
	case "date_hour_minute_second_millis", "strict_date_hour_minute_second_millis",
		"date_hour_minute_second_fraction", "strict_date_hour_minute_second_fraction":
		return tm.Format("2006-01-02T15:04:05.000")
	case "time", "strict_time":
		return tm.Format("15:04:05.000Z07:00")
	case "time_no_millis", "strict_time_no_millis":
		return tm.Format("15:04:05Z07:00")
	case "hour_minute_second", "strict_hour_minute_second":
		return tm.Format("15:04:05")
	case "hour_minute_second_millis", "strict_hour_minute_second_millis",
		"hour_minute_second_fraction", "strict_hour_minute_second_fraction":
		return tm.Format("15:04:05.000")
	case "hour_minute", "strict_hour_minute":
		return tm.Format("15:04")
	case "hour", "strict_hour":
		return tm.Format("15")
	case "ordinal_date", "strict_ordinal_date":
		return fmt.Sprintf("%04d-%03d", tm.Year(), tm.YearDay())
	case "ordinal_date_time", "strict_ordinal_date_time":
		return fmt.Sprintf("%04d-%03dT%s", tm.Year(), tm.YearDay(), tm.Format("15:04:05.000Z07:00"))
	case "ordinal_date_time_no_millis", "strict_ordinal_date_time_no_millis":
		return fmt.Sprintf("%04d-%03dT%s", tm.Year(), tm.YearDay(), tm.Format("15:04:05Z07:00"))
	case "basic_ordinal_date", "strict_basic_ordinal_date":
		return fmt.Sprintf("%04d%03d", tm.Year(), tm.YearDay())
	case "basic_ordinal_date_time", "strict_basic_ordinal_date_time":
		return fmt.Sprintf("%04d%03dT%s", tm.Year(), tm.YearDay(), tm.Format("150405.000Z0700"))
	case "basic_ordinal_date_time_no_millis", "strict_basic_ordinal_date_time_no_millis":
		return fmt.Sprintf("%04d%03dT%s", tm.Year(), tm.YearDay(), tm.Format("150405Z0700"))
	case "rfc1123", "rfc822":
		return tm.Format(time.RFC1123)
	}

	// Single-pass Java DateTimeFormatter token scanner (never re-scans emitted output).
	var sb strings.Builder
	for i := 0; i < len(rawFmt); {
		ch := rawFmt[i]
		if ch == '\'' {
			if i+1 < len(rawFmt) && rawFmt[i+1] == '\'' {
				sb.WriteByte('\'')
				i += 2
				continue
			}
			j := i + 1
			for j < len(rawFmt) {
				if rawFmt[j] == '\'' {
					if j+1 < len(rawFmt) && rawFmt[j+1] == '\'' {
						sb.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				sb.WriteByte(rawFmt[j])
				j++
			}
			if j < len(rawFmt) && rawFmt[j] == '\'' {
				j++
			}
			i = j
			continue
		}
		j := i + 1
		for j < len(rawFmt) && rawFmt[j] == ch {
			j++
		}
		runLen := j - i
		switch ch {
		case 'y', 'u', 'Y':
			switch runLen {
			case 2:
				sb.WriteString(tm.Format("06"))
			case 1:
				sb.WriteString(strconv.Itoa(tm.Year()))
			default:
				fmt.Fprintf(&sb, "%0*d", runLen, tm.Year())
			}
		case 'M', 'L':
			switch runLen {
			case 1:
				sb.WriteString(strconv.Itoa(int(tm.Month())))
			case 2:
				fmt.Fprintf(&sb, "%02d", int(tm.Month()))
			case 3:
				sb.WriteString(tm.Format("Jan"))
			default:
				sb.WriteString(tm.Format("January"))
			}
		case 'd':
			if runLen == 1 {
				sb.WriteString(strconv.Itoa(tm.Day()))
			} else {
				fmt.Fprintf(&sb, "%0*d", runLen, tm.Day())
			}
		case 'D':
			fmt.Fprintf(&sb, "%0*d", runLen, tm.YearDay())
		case 'H':
			if runLen == 1 {
				sb.WriteString(strconv.Itoa(tm.Hour()))
			} else {
				fmt.Fprintf(&sb, "%0*d", runLen, tm.Hour())
			}
		case 'h':
			h12 := tm.Hour() % 12
			if h12 == 0 {
				h12 = 12
			}
			if runLen == 1 {
				sb.WriteString(strconv.Itoa(h12))
			} else {
				fmt.Fprintf(&sb, "%0*d", runLen, h12)
			}
		case 'K':
			fmt.Fprintf(&sb, "%0*d", runLen, tm.Hour()%12)
		case 'k':
			h24 := tm.Hour()
			if h24 == 0 {
				h24 = 24
			}
			fmt.Fprintf(&sb, "%0*d", runLen, h24)
		case 'm':
			if runLen == 1 {
				sb.WriteString(strconv.Itoa(tm.Minute()))
			} else {
				fmt.Fprintf(&sb, "%0*d", runLen, tm.Minute())
			}
		case 's':
			if runLen == 1 {
				sb.WriteString(strconv.Itoa(tm.Second()))
			} else {
				fmt.Fprintf(&sb, "%0*d", runLen, tm.Second())
			}
		case 'S':
			nsStr := fmt.Sprintf("%09d", tm.Nanosecond())
			if runLen <= 9 {
				sb.WriteString(nsStr[:runLen])
			} else {
				sb.WriteString(nsStr)
				sb.WriteString(strings.Repeat("0", runLen-9))
			}
		case 'n':
			if runLen == 1 {
				sb.WriteString(strconv.Itoa(tm.Nanosecond()))
			} else {
				fmt.Fprintf(&sb, "%0*d", runLen, tm.Nanosecond())
			}
		case 'E', 'e', 'c':
			if runLen <= 3 {
				sb.WriteString(tm.Format("Mon"))
			} else {
				sb.WriteString(tm.Format("Monday"))
			}
		case 'a':
			sb.WriteString(tm.Format("PM"))
		case 'X', 'x':
			_, off := tm.Zone()
			if ch == 'X' && off == 0 {
				sb.WriteByte('Z')
			} else {
				sign := "+"
				absOff := off
				if absOff < 0 {
					sign = "-"
					absOff = -absOff
				}
				oh := absOff / 3600
				om := (absOff % 3600) / 60
				switch runLen {
				case 1:
					if om == 0 {
						fmt.Fprintf(&sb, "%s%02d", sign, oh)
					} else {
						fmt.Fprintf(&sb, "%s%02d%02d", sign, oh, om)
					}
				case 2:
					fmt.Fprintf(&sb, "%s%02d%02d", sign, oh, om)
				default:
					fmt.Fprintf(&sb, "%s%02d:%02d", sign, oh, om)
				}
			}
		case 'Z':
			_, off := tm.Zone()
			sign := "+"
			absOff := off
			if absOff < 0 {
				sign = "-"
				absOff = -absOff
			}
			oh := absOff / 3600
			om := (absOff % 3600) / 60
			if runLen >= 4 {
				if off == 0 {
					sb.WriteString("GMT")
				} else {
					fmt.Fprintf(&sb, "GMT%s%02d:%02d", sign, oh, om)
				}
			} else {
				fmt.Fprintf(&sb, "%s%02d%02d", sign, oh, om)
			}
		case 'z', 'V':
			zName, _ := tm.Zone()
			if zName == "" {
				zName = "UTC"
			}
			sb.WriteString(zName)
		default:
			sb.WriteString(rawFmt[i:j])
		}
		i = j
	}
	return sb.String()
}

func formatESPercentKey(p float64) string {
	s := strconv.FormatFloat(p, 'f', -1, 64)
	if !strings.Contains(s, ".") && !strings.ContainsAny(s, "eE") {
		s += ".0"
	}
	return s
}

type hdrDoubleHistogram struct {
	sigDigits              int
	subBucketCountMag      int
	subBucketHalfCountMag  int
	subBucketCount         int64
	subBucketHalfCount     int64
	doubleToIntRatio       float64
	intToDoubleRatio       float64
	countsByQuantizedLower map[int64]int64
	sortedLowers           []int64
	totalCount             int64
}

func newHDRDoubleHistogram(sigDigits int, values []float64) (*hdrDoubleHistogram, error) {
	if sigDigits < 0 || sigDigits > 5 {
		return nil, fmt.Errorf("illegal_argument_exception: [numberOfSignificantValueDigits] must be between 0 and 5")
	}
	largestSingleUnit := 2.0 * math.Pow10(sigDigits)
	subBucketCountMag := int(math.Ceil(math.Log2(largestSingleUnit)))
	if subBucketCountMag < 1 {
		subBucketCountMag = 1
	}
	subBucketHalfCountMag := subBucketCountMag - 1
	subBucketCount := int64(1) << subBucketCountMag
	subBucketHalfCount := int64(1) << subBucketHalfCountMag

	minPos := math.Inf(1)
	maxPos := 0.0
	for _, v := range values {
		if math.IsNaN(v) {
			continue
		}
		if v < 0 {
			return nil, fmt.Errorf("array_index_out_of_bounds_exception: Histogram recorded value cannot be negative")
		}
		if v > 0 {
			if v < minPos {
				minPos = v
			}
			if v > maxPos {
				maxPos = v
			}
		}
	}

	doubleToIntRatio := 1.0
	intToDoubleRatio := 1.0
	if !math.IsInf(minPos, 1) && minPos > 0 {
		minBinExp := int(math.Floor(math.Log2(minPos)))
		scaleExp := subBucketHalfCountMag - minBinExp
		// Prevent int64 overflow when dynamic range exceeds 2^61.
		maxBinExp := int(math.Ceil(math.Log2(maxPos)))
		if maxBinExp+scaleExp > 61 {
			scaleExp = 61 - maxBinExp
		}
		doubleToIntRatio = math.Ldexp(1.0, scaleExp)
		intToDoubleRatio = math.Ldexp(1.0, -scaleExp)
	}

	h := &hdrDoubleHistogram{
		sigDigits:              sigDigits,
		subBucketCountMag:      subBucketCountMag,
		subBucketHalfCountMag:  subBucketHalfCountMag,
		subBucketCount:         subBucketCount,
		subBucketHalfCount:     subBucketHalfCount,
		doubleToIntRatio:       doubleToIntRatio,
		intToDoubleRatio:       intToDoubleRatio,
		countsByQuantizedLower: make(map[int64]int64),
	}

	for _, v := range values {
		if math.IsNaN(v) {
			continue
		}
		var intVal int64
		if v > 0 {
			scaled := v * doubleToIntRatio
			if scaled >= float64(math.MaxInt64/2) {
				intVal = math.MaxInt64 / 2
			} else {
				intVal = int64(scaled)
			}
		}
		lower := h.lowestEquivalentInt(intVal)
		h.countsByQuantizedLower[lower]++
		h.totalCount++
	}

	h.sortedLowers = make([]int64, 0, len(h.countsByQuantizedLower))
	for k := range h.countsByQuantizedLower {
		h.sortedLowers = append(h.sortedLowers, k)
	}
	sort.Slice(h.sortedLowers, func(i, j int) bool { return h.sortedLowers[i] < h.sortedLowers[j] })
	return h, nil
}

func (h *hdrDoubleHistogram) bucketShift(v int64) int {
	if v <= 0 || v < h.subBucketCount {
		return 0
	}
	msb := 63 - bits.LeadingZeros64(uint64(v)) // #nosec G115 -- v > 0 checked above
	shift := msb - h.subBucketHalfCountMag
	if shift < 0 {
		return 0
	}
	return shift
}

func (h *hdrDoubleHistogram) lowestEquivalentInt(v int64) int64 {
	if v <= 0 {
		return 0
	}
	shift := h.bucketShift(v)
	return (v >> shift) << shift
}

func (h *hdrDoubleHistogram) highestEquivalentInt(v int64) int64 {
	if v <= 0 {
		return 0
	}
	shift := h.bucketShift(v)
	lower := (v >> shift) << shift
	size := int64(1) << shift
	return lower + size - 1
}

func (h *hdrDoubleHistogram) valueAtPercentile(p float64) float64 {
	if h.totalCount == 0 {
		return math.NaN()
	}
	reqP := p
	if reqP < 0 {
		reqP = 0
	} else if reqP > 100 {
		reqP = 100
	}
	targetCount := int64(((reqP / 100.0) * float64(h.totalCount)) + 0.5)
	if targetCount < 1 {
		targetCount = 1
	}
	var cum int64
	chosen := h.sortedLowers[len(h.sortedLowers)-1]
	for _, lower := range h.sortedLowers {
		cum += h.countsByQuantizedLower[lower]
		if cum >= targetCount {
			chosen = lower
			break
		}
	}
	if p == 0.0 {
		return float64(chosen) * h.intToDoubleRatio
	}
	return float64(h.highestEquivalentInt(chosen)) * h.intToDoubleRatio
}

func (h *hdrDoubleHistogram) percentileAtOrBelow(target float64) float64 {
	if h.totalCount == 0 {
		return math.NaN()
	}
	if target < 0 {
		return 0.0
	}
	var targetLower int64
	if target > 0 {
		scaled := target * h.doubleToIntRatio
		if scaled >= float64(math.MaxInt64/2) {
			return 100.0
		}
		targetLower = h.lowestEquivalentInt(int64(scaled))
	}
	var sum int64
	for _, lower := range h.sortedLowers {
		if lower <= targetLower {
			sum += h.countsByQuantizedLower[lower]
		} else {
			break
		}
	}
	pct := (100.0 * float64(sum)) / float64(h.totalCount)
	if pct > 100.0 {
		pct = 100.0
	}
	return pct
}

// ComputeESPercentiles computes exact Elasticsearch `percentiles` values in either `TDigest` (`AVLTreeDigest`
// centroid midpoint interpolation, ES 7.x default) or `HDR` (`DoubleHistogram(numberOfSignificantValueDigits)`) mode.
// When `values` is empty, every requested percentile maps to `nil` (`null`).
func ComputeESPercentiles(values []float64, percents []float64, hdr *esast.HDRConfig) (map[string]any, error) {
	return ComputeESPercentilesMode(values, percents, hdr, false)
}

// ComputeESPercentilesMode computes exact Elasticsearch `percentiles` values with version-aware TDigest quantile
// interpolation (`es8Mode == false` uses ES 7.x `q*n - 0.5`; `es8Mode == true` uses ES 8.9+ forked t-digest `q*(n-1)`).
func ComputeESPercentilesMode(values []float64, percents []float64, hdr *esast.HDRConfig, es8Mode bool) (map[string]any, error) {
	sigDigits := 3
	if hdr != nil && hdr.NumberOfSignificantValueDigits != nil {
		sigDigits = *hdr.NumberOfSignificantValueDigits
	}
	return ComputeESPercentilesWithVersion(values, percents, 100.0, hdr != nil, sigDigits, es8Mode)
}

// ComputeESPercentilesWithVersion computes exact Elasticsearch `percentiles` values in either TDigest or HDR mode,
// selecting ES 7.x (`q*n - 0.5`) vs ES 8.9+ (`q*(n-1)`) TDigest interpolation via `es8Mode`.
func ComputeESPercentilesWithVersion(values []float64, percents []float64, _ float64, useHDR bool, hdrSigDigits int, es8Mode bool) (map[string]any, error) {
	if len(percents) == 0 {
		percents = []float64{1.0, 5.0, 25.0, 50.0, 75.0, 95.0, 99.0}
	}
	cleanVals := make([]float64, 0, len(values))
	for _, v := range values {
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			cleanVals = append(cleanVals, v)
		}
	}
	out := make(map[string]any, len(percents))
	if len(cleanVals) == 0 {
		if useHDR && (hdrSigDigits < 0 || hdrSigDigits > 5) {
			return nil, fmt.Errorf("illegal_argument_exception: [numberOfSignificantValueDigits] must be between 0 and 5")
		}
		for _, p := range percents {
			out[formatESPercentKey(p)] = nil
		}
		return out, nil
	}

	if useHDR {
		hist, err := newHDRDoubleHistogram(hdrSigDigits, cleanVals)
		if err != nil {
			return nil, err
		}
		for _, p := range percents {
			out[formatESPercentKey(p)] = hist.valueAtPercentile(p)
		}
		return out, nil
	}

	sorted := make([]float64, len(cleanVals))
	copy(sorted, cleanVals)
	sort.Float64s(sorted)
	n := len(sorted)
	for _, p := range percents {
		q := p / 100.0
		if q <= 0 {
			out[formatESPercentKey(p)] = sorted[0]
			continue
		}
		if q >= 1 {
			out[formatESPercentKey(p)] = sorted[n-1]
			continue
		}
		var idx float64
		if es8Mode {
			idx = q * float64(n-1)
		} else {
			idx = q*float64(n) - 0.5
		}
		if idx <= 0 {
			out[formatESPercentKey(p)] = sorted[0]
		} else if idx >= float64(n-1) {
			out[formatESPercentKey(p)] = sorted[n-1]
		} else {
			lo := int(math.Floor(idx))
			frac := idx - float64(lo)
			out[formatESPercentKey(p)] = sorted[lo] + frac*(sorted[lo+1]-sorted[lo])
		}
	}
	return out, nil
}

// ComputeESPercentileRanks computes exact Elasticsearch `percentile_ranks` in either `TDigest`
// (`AVLTreeDigest.cdf` tie-aware centroid midpoint interpolation) or `HDR` (`DoubleHistogram`) mode.
// When `values` is empty, every target rank is `nil` (`null`).
// Returns `map[string]any` when `keyed` is true, or `[]map[string]any` (`[{"key": k, "value": v}, ...]`) when `keyed` is false.
func ComputeESPercentileRanks(values []float64, targets []float64, hdr *esast.HDRConfig, keyed bool) (any, error) {
	cleanVals := make([]float64, 0, len(values))
	for _, v := range values {
		if !math.IsNaN(v) && !math.IsInf(v, 0) {
			cleanVals = append(cleanVals, v)
		}
	}
	if len(cleanVals) == 0 {
		if hdr != nil && hdr.NumberOfSignificantValueDigits != nil {
			sig := *hdr.NumberOfSignificantValueDigits
			if sig < 0 || sig > 5 {
				return nil, fmt.Errorf("illegal_argument_exception: [numberOfSignificantValueDigits] must be between 0 and 5")
			}
		}
		if keyed {
			m := make(map[string]any, len(targets))
			for _, t := range targets {
				m[formatESPercentKey(t)] = nil
			}
			return m, nil
		}
		arr := make([]map[string]any, 0, len(targets))
		for _, t := range targets {
			arr = append(arr, map[string]any{"key": t, "value": nil})
		}
		return arr, nil
	}

	var evalTarget func(x float64) float64
	if hdr != nil {
		sigDigits := 3
		if hdr.NumberOfSignificantValueDigits != nil {
			sigDigits = *hdr.NumberOfSignificantValueDigits
		}
		hist, err := newHDRDoubleHistogram(sigDigits, cleanVals)
		if err != nil {
			return nil, err
		}
		evalTarget = hist.percentileAtOrBelow
	} else {
		sorted := make([]float64, len(cleanVals))
		copy(sorted, cleanVals)
		sort.Float64s(sorted)
		n := len(sorted)

		type centroid struct {
			mean float64
			midW float64
		}
		var centroids []centroid
		for i := 0; i < n; {
			j := i + 1
			for j < n && sorted[j] == sorted[i] {
				j++
			}
			cnt := float64(j - i)
			centroids = append(centroids, centroid{
				mean: sorted[i],
				midW: float64(i) + cnt/2.0,
			})
			i = j
		}

		evalTarget = func(x float64) float64 {
			if x < sorted[0] {
				return 0.0
			}
			if x >= sorted[n-1] {
				return 100.0
			}
			k := len(centroids)
			if x <= centroids[0].mean {
				return (centroids[0].midW / float64(n)) * 100.0
			}
			idx := sort.Search(k, func(i int) bool { return centroids[i].mean >= x })
			if idx < k && centroids[idx].mean == x {
				return (centroids[idx].midW / float64(n)) * 100.0
			}
			lo := centroids[idx-1]
			hi := centroids[idx]
			w := lo.midW + ((x-lo.mean)/(hi.mean-lo.mean))*(hi.midW-lo.midW)
			return (w / float64(n)) * 100.0
		}
	}

	if keyed {
		m := make(map[string]any, len(targets))
		for _, t := range targets {
			m[formatESPercentKey(t)] = evalTarget(t)
		}
		return m, nil
	}
	arr := make([]map[string]any, 0, len(targets))
	for _, t := range targets {
		arr = append(arr, map[string]any{"key": t, "value": evalTarget(t)})
	}
	return arr, nil
}

// AnalyzedToken represents a single analyzed token and its 0-based position in an Elasticsearch field.
type AnalyzedToken struct {
	Term     string
	Position int
}

func isUAX29WordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

func tokenizeStandardUAX29(s string) []string {
	runes := []rune(s)
	n := len(runes)
	var tokens []string
	var cur []rune
	for i := 0; i < n; i++ {
		r := runes[i]
		if isUAX29WordRune(r) {
			cur = append(cur, unicode.ToLower(r))
			continue
		}
		// UAX#29 ExtendNumLet ('_') and MidNumLet/MidLetter (''' / '.' between letters or digits):
		// keep '_' when flanked by alphanumeric runes (e.g. `value1_foo` -> single token `value1_foo`).
		if r == '_' && len(cur) > 0 && i+1 < n && isUAX29WordRune(runes[i+1]) {
			cur = append(cur, '_')
			continue
		}
		if (r == '\'' || r == '’') && len(cur) > 0 && unicode.IsLetter(runes[i-1]) && i+1 < n && unicode.IsLetter(runes[i+1]) {
			cur = append(cur, unicode.ToLower(r))
			continue
		}
		if len(cur) > 0 {
			tokens = append(tokens, string(cur))
			cur = cur[:0]
		}
	}
	if len(cur) > 0 {
		tokens = append(tokens, string(cur))
	}
	return tokens
}

// TokenizeByAnalyzer tokenizes `s` according to Elasticsearch built-in analyzer semantics:
//   - `"whitespace"`: splits on whitespace preserving original case (`strings.Fields(s)`).
//   - `"keyword"`: keeps the entire non-empty string as a single token preserving case.
//   - `"simple"`: splits on non-letters and lowercases.
//   - `"stop"` / `"english"`: splits on non-letters, lowercases, and removes English stopwords.
//   - `"standard"` / `""` (default): UAX#29 word boundaries, lowercasing and keeping internal `_` joining alphanumerics (`value1_foo`).
func TokenizeByAnalyzer(s string, analyzer string) []string {
	withPos := TokenizeByAnalyzerWithPositions(s, analyzer)
	if len(withPos) == 0 {
		return nil
	}
	out := make([]string, len(withPos))
	for i, tk := range withPos {
		out[i] = tk.Term
	}
	return out
}

// TokenizeByAnalyzerWithPositions tokenizes `s` and records 0-based token positions (including stopword position increments).
func TokenizeByAnalyzerWithPositions(s string, analyzer string) []AnalyzedToken {
	switch strings.ToLower(strings.TrimSpace(analyzer)) {
	case "keyword":
		if s == "" {
			return nil
		}
		return []AnalyzedToken{{Term: s, Position: 0}}
	case "whitespace":
		raw := strings.Fields(s)
		if len(raw) == 0 {
			return nil
		}
		out := make([]AnalyzedToken, len(raw))
		for i, w := range raw {
			out[i] = AnalyzedToken{Term: w, Position: i}
		}
		return out
	case "simple":
		var out []AnalyzedToken
		var cur []rune
		pos := 0
		for _, r := range s {
			if unicode.IsLetter(r) {
				cur = append(cur, unicode.ToLower(r))
			} else if len(cur) > 0 {
				out = append(out, AnalyzedToken{Term: string(cur), Position: pos})
				pos++
				cur = cur[:0]
			}
		}
		if len(cur) > 0 {
			out = append(out, AnalyzedToken{Term: string(cur), Position: pos})
		}
		return out
	case "stop", "english":
		var out []AnalyzedToken
		var cur []rune
		pos := 0
		flush := func() {
			if len(cur) == 0 {
				return
			}
			w := string(cur)
			cur = cur[:0]
			if !defaultEnglishStopwords[w] {
				out = append(out, AnalyzedToken{Term: w, Position: pos})
			}
			pos++
		}
		for _, r := range s {
			if unicode.IsLetter(r) {
				cur = append(cur, unicode.ToLower(r))
			} else {
				flush()
			}
		}
		flush()
		return out
	default:
		toks := tokenizeStandardUAX29(s)
		if len(toks) == 0 {
			return nil
		}
		out := make([]AnalyzedToken, len(toks))
		for i, w := range toks {
			out[i] = AnalyzedToken{Term: w, Position: i}
		}
		return out
	}
}

func effectiveFieldSearchAnalyzer(b schema.FieldBinding) string {
	sa := strings.ToLower(strings.TrimSpace(b.SearchAnalyzer))
	if sa == "" {
		sa = strings.ToLower(strings.TrimSpace(b.Analyzer))
	}
	return sa
}

func buildAnalyzedTextWildcardRegex(val string, effAnalyzer string, caseInsensitive bool) string {
	isWS := strings.EqualFold(effAnalyzer, "whitespace")
	var body strings.Builder
	for i := 0; i < len(val); {
		r, width := utf8.DecodeRuneInString(val[i:])
		if r == '\\' && i+width < len(val) {
			nextR, nextW := utf8.DecodeRuneInString(val[i+width:])
			body.WriteString(regexp.QuoteMeta(string(nextR)))
			i += width + nextW
			continue
		}
		switch r {
		case '*':
			if isWS {
				body.WriteString("[^[:space:]]*")
			} else {
				body.WriteString("[[:alnum:]_]*")
			}
		case '?':
			if isWS {
				body.WriteString("[^[:space:]]")
			} else {
				body.WriteString("[[:alnum:]_]")
			}
		default:
			body.WriteString(regexp.QuoteMeta(string(r)))
		}
		i += width
	}
	if isWS {
		prefix := ""
		if caseInsensitive {
			prefix = "(?i)"
		}
		return fmt.Sprintf("%s(^|[[:space:]])(%s)($|[[:space:]])", prefix, body.String())
	}
	return fmt.Sprintf("(?i)(^|[^[:alnum:]_])(%s)($|[^[:alnum:]_])", body.String())
}

func (t *Transpiler) compileMetadataExistsPredicate(field string) (string, bool) {
	switch field {
	case "_source":
		if !t.inLenientQuery && t.searchErr == nil {
			t.searchErr = fmt.Errorf("illegal_argument_exception: Field [_source] is defined as an object in mapping [_source] but this name is already used for a meta field and cannot be searched with [exists]")
		}
		return "FALSE", true
	case "_id", "_index", "_type", "_seq_no", "_primary_term", "_version":
		return "TRUE", true
	case "_routing":
		return "(`_routing` IS NOT NULL AND `_routing` != '')", true
	case "_ignored":
		return "(`_ignored` IS NOT NULL AND array_size(`_ignored`) > 0)", true
	case "_field_names":
		if t.Schema != nil && t.Schema.SourceDisabled() {
			var parts []string
			parts = append(parts, "(`_all_text` IS NOT NULL AND `_all_text` != '')")
			for _, fb := range t.Schema.OrderedFields {
				if fb.EnabledFalse || fb.ESType == "alias" || fb.ColumnName == "" {
					continue
				}
				switch fb.Kind {
				case schema.StoragePromotedArray, schema.StorageNestedSubfield:
					arrCol := fb.EffectiveArrayColumn(false)
					if arrCol != "" {
						parts = append(parts, fmt.Sprintf("(`%s` IS NOT NULL AND array_size(`%s`) > 0)", arrCol, arrCol))
					}
				case schema.StoragePromotedScalar:
					parts = append(parts, fmt.Sprintf("(`%s` IS NOT NULL)", fb.ColumnName))
				}
			}
			return "(" + strings.Join(parts, " OR ") + ")", true
		}
		return "(`_source` IS NOT NULL AND `_source` != '' AND `_source` != '{}')", true
	default:
		return "", false
	}
}

func buildAnalyzedTokenRegex(tok string, isWhitespace bool) string {
	esc := regexp.QuoteMeta(tok)
	if isWhitespace {
		return fmt.Sprintf("(^|[[:space:]])(%s)($|[[:space:]])", esc)
	}
	return fmt.Sprintf("(?i)(^|[^[:alnum:]_])(%s)($|[^[:alnum:]_])", esc)
}

func hasInternalUnderscoreToken(tokens []string) bool {
	for _, tok := range tokens {
		if strings.Contains(tok, "_") {
			return true
		}
	}
	return false
}

// IntervalsSpan represents a matched token interval `[Start, End]` (0-based inclusive token positions)
// and its intervening `Gaps` count for Elasticsearch `intervals` queries (`interval.start`, `interval.end`, `interval.gaps`).
type IntervalsSpan struct {
	Start int
	End   int
	Gaps  int
}

// RuleHasIntervalsScript reports whether `rule` or any of its nested sub-rules/filters contains a `filter.script`.
func RuleHasIntervalsScript(rule *esast.IntervalsRule) bool {
	if rule == nil {
		return false
	}
	checkFilter := func(f *esast.IntervalsFilter) bool {
		if f == nil {
			return false
		}
		if f.Script != nil {
			return true
		}
		for _, sub := range []*esast.IntervalsRule{
			f.Containing, f.NotContaining, f.ContainedBy, f.NotContainedBy,
			f.Overlapping, f.NotOverlapping, f.After, f.Before,
		} {
			if RuleHasIntervalsScript(sub) {
				return true
			}
		}
		return false
	}
	if rule.Match != nil && checkFilter(rule.Match.Filter) {
		return true
	}
	if rule.Prefix != nil && checkFilter(rule.Prefix.Filter) {
		return true
	}
	if rule.Wildcard != nil && checkFilter(rule.Wildcard.Filter) {
		return true
	}
	if rule.Fuzzy != nil && checkFilter(rule.Fuzzy.Filter) {
		return true
	}
	if rule.AllOf != nil {
		if checkFilter(rule.AllOf.Filter) {
			return true
		}
		for i := range rule.AllOf.Intervals {
			if RuleHasIntervalsScript(&rule.AllOf.Intervals[i]) {
				return true
			}
		}
	}
	if rule.AnyOf != nil {
		if checkFilter(rule.AnyOf.Filter) {
			return true
		}
		for i := range rule.AnyOf.Intervals {
			if RuleHasIntervalsScript(&rule.AnyOf.Intervals[i]) {
				return true
			}
		}
	}
	return false
}

// QueryHasIntervalsScript reports whether `q` contains any `intervals` query using `filter.script`.
func QueryHasIntervalsScript(q *esast.Query) bool {
	if q == nil {
		return false
	}
	for _, r := range q.Intervals {
		rc := r
		if RuleHasIntervalsScript(&rc) {
			return true
		}
	}
	if q.Bool != nil {
		for i := range q.Bool.Must {
			if QueryHasIntervalsScript(&q.Bool.Must[i]) {
				return true
			}
		}
		for i := range q.Bool.Filter {
			if QueryHasIntervalsScript(&q.Bool.Filter[i]) {
				return true
			}
		}
		for i := range q.Bool.Should {
			if QueryHasIntervalsScript(&q.Bool.Should[i]) {
				return true
			}
		}
		for i := range q.Bool.MustNot {
			if QueryHasIntervalsScript(&q.Bool.MustNot[i]) {
				return true
			}
		}
	}
	if q.ConstantScore != nil && QueryHasIntervalsScript(&q.ConstantScore.Filter) {
		return true
	}
	if q.DisMax != nil {
		for i := range q.DisMax.Queries {
			if QueryHasIntervalsScript(&q.DisMax.Queries[i]) {
				return true
			}
		}
	}
	if q.Boosting != nil && (QueryHasIntervalsScript(&q.Boosting.Positive) || QueryHasIntervalsScript(&q.Boosting.Negative)) {
		return true
	}
	if q.FunctionScore != nil && QueryHasIntervalsScript(q.FunctionScore.Query) {
		return true
	}
	if q.Nested != nil && QueryHasIntervalsScript(&q.Nested.Query) {
		return true
	}
	return false
}

func minimizeIntervalsSpans(spans []IntervalsSpan) []IntervalsSpan {
	if len(spans) <= 1 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		if spans[i].End != spans[j].End {
			return spans[i].End < spans[j].End
		}
		return spans[i].Gaps < spans[j].Gaps
	})
	var dedup []IntervalsSpan
	for _, s := range spans {
		if len(dedup) > 0 && dedup[len(dedup)-1].Start == s.Start && dedup[len(dedup)-1].End == s.End {
			continue
		}
		dedup = append(dedup, s)
	}
	var minimal []IntervalsSpan
	for i, a := range dedup {
		dominated := false
		for j, b := range dedup {
			if i == j {
				continue
			}
			if b.Start >= a.Start && b.End <= a.End && (b.Start > a.Start || b.End < a.End) {
				dominated = true
				break
			}
		}
		if !dominated {
			minimal = append(minimal, a)
		}
	}
	return minimal
}

func combineSubIntervals(subLists [][]IntervalsSpan, ordered bool, maxGaps *int) []IntervalsSpan {
	if len(subLists) == 0 {
		return nil
	}
	for _, l := range subLists {
		if len(l) == 0 {
			return nil
		}
	}
	if len(subLists) == 1 {
		var out []IntervalsSpan
		for _, s := range subLists[0] {
			if maxGaps != nil && *maxGaps >= 0 && s.Gaps > *maxGaps {
				continue
			}
			out = append(out, s)
		}
		return minimizeIntervalsSpans(out)
	}

	var results []IntervalsSpan
	picked := make([]IntervalsSpan, len(subLists))
	var dfs func(idx int)
	dfs = func(idx int) {
		if idx == len(subLists) {
			if ordered {
				minStart := picked[0].Start
				maxEnd := picked[0].End
				gaps := 0
				for k := 1; k < len(picked); k++ {
					if picked[k].Start <= picked[k-1].End {
						return
					}
					gaps += picked[k].Start - picked[k-1].End - 1
					if picked[k].End > maxEnd {
						maxEnd = picked[k].End
					}
				}
				if maxGaps != nil && *maxGaps >= 0 && gaps > *maxGaps {
					return
				}
				results = append(results, IntervalsSpan{Start: minStart, End: maxEnd, Gaps: gaps})
				return
			}
			ord := make([]IntervalsSpan, len(picked))
			copy(ord, picked)
			sort.Slice(ord, func(i, j int) bool {
				if ord[i].Start != ord[j].Start {
					return ord[i].Start < ord[j].Start
				}
				return ord[i].End < ord[j].End
			})
			minStart := ord[0].Start
			curMaxEnd := ord[0].End
			gaps := 0
			for k := 1; k < len(ord); k++ {
				if ord[k].Start > curMaxEnd {
					gaps += ord[k].Start - curMaxEnd - 1
				}
				if ord[k].End > curMaxEnd {
					curMaxEnd = ord[k].End
				}
			}
			if maxGaps != nil && *maxGaps >= 0 && gaps > *maxGaps {
				return
			}
			results = append(results, IntervalsSpan{Start: minStart, End: curMaxEnd, Gaps: gaps})
			return
		}
		for _, cand := range subLists[idx] {
			if ordered && idx > 0 && cand.Start <= picked[idx-1].End {
				continue
			}
			picked[idx] = cand
			dfs(idx + 1)
		}
	}
	dfs(0)
	return minimizeIntervalsSpans(results)
}

func wildcardPatternRegex(pat string, caseInsensitive bool) *regexp.Regexp {
	var sb strings.Builder
	if caseInsensitive {
		sb.WriteString("(?i)")
	}
	sb.WriteByte('^')
	for i := 0; i < len(pat); {
		r, w := utf8.DecodeRuneInString(pat[i:])
		if r == '\\' && i+w < len(pat) {
			nr, nw := utf8.DecodeRuneInString(pat[i+w:])
			sb.WriteString(regexp.QuoteMeta(string(nr)))
			i += w + nw
			continue
		}
		switch r {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteByte('.')
		default:
			sb.WriteString(regexp.QuoteMeta(string(r)))
		}
		i += w
	}
	sb.WriteByte('$')
	re, _ := regexp.Compile(sb.String())
	return re
}

// EvaluateIntervalsRule evaluates an Elasticsearch `intervals` rule against `text` (tokenized with `analyzer`),
// computing exact `(Start, End, Gaps)` token intervals and invoking `scriptEval` for any `filter.script` predicates.
func EvaluateIntervalsRule(
	rule *esast.IntervalsRule,
	text string,
	analyzer string,
	scriptEval func(script *esast.ScriptSpec, span IntervalsSpan) (bool, error),
) ([]IntervalsSpan, bool, error) {
	if rule == nil {
		return nil, false, nil
	}
	docTokens := TokenizeByAnalyzerWithPositions(text, analyzer)
	if len(docTokens) == 0 {
		return nil, false, nil
	}

	var evalRule func(r *esast.IntervalsRule) ([]IntervalsSpan, error)
	applyFilter := func(spans []IntervalsSpan, f *esast.IntervalsFilter) ([]IntervalsSpan, error) {
		if f == nil || len(spans) == 0 {
			return spans, nil
		}
		filterByOther := func(cur []IntervalsSpan, otherRule *esast.IntervalsRule, negate bool, rel func(a, b IntervalsSpan) bool) ([]IntervalsSpan, error) {
			if otherRule == nil || len(cur) == 0 {
				return cur, nil
			}
			otherSpans, err := evalRule(otherRule)
			if err != nil {
				return nil, err
			}
			var kept []IntervalsSpan
			for _, a := range cur {
				matchedRel := false
				for _, b := range otherSpans {
					if rel(a, b) {
						matchedRel = true
						break
					}
				}
				if negate {
					if !matchedRel {
						kept = append(kept, a)
					}
				} else if matchedRel {
					kept = append(kept, a)
				}
			}
			return kept, nil
		}

		var err error
		spans, err = filterByOther(spans, f.Containing, false, func(a, b IntervalsSpan) bool { return a.Start <= b.Start && a.End >= b.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.NotContaining, true, func(a, b IntervalsSpan) bool { return a.Start <= b.Start && a.End >= b.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.ContainedBy, false, func(a, b IntervalsSpan) bool { return a.Start >= b.Start && a.End <= b.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.NotContainedBy, true, func(a, b IntervalsSpan) bool { return a.Start >= b.Start && a.End <= b.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.Overlapping, false, func(a, b IntervalsSpan) bool { return a.Start <= b.End && b.Start <= a.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.NotOverlapping, true, func(a, b IntervalsSpan) bool { return a.Start <= b.End && b.Start <= a.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.After, false, func(a, b IntervalsSpan) bool { return a.Start > b.End })
		if err != nil {
			return nil, err
		}
		spans, err = filterByOther(spans, f.Before, false, func(a, b IntervalsSpan) bool { return a.End < b.Start })
		if err != nil {
			return nil, err
		}

		if f.Script != nil && scriptEval != nil {
			var scriptKept []IntervalsSpan
			for _, sp := range spans {
				ok, err := scriptEval(f.Script, sp)
				if err != nil {
					return nil, err
				}
				if ok {
					scriptKept = append(scriptKept, sp)
				}
			}
			spans = scriptKept
		}
		return spans, nil
	}

	evalRule = func(r *esast.IntervalsRule) ([]IntervalsSpan, error) {
		if r == nil {
			return nil, nil
		}
		switch {
		case r.Match != nil:
			effAn := r.Match.Analyzer
			if effAn == "" {
				effAn = analyzer
			}
			qToks := TokenizeByAnalyzer(r.Match.Query, effAn)
			if len(qToks) == 0 {
				return nil, nil
			}
			subLists := make([][]IntervalsSpan, len(qToks))
			for i, qt := range qToks {
				for _, dt := range docTokens {
					if dt.Term == qt {
						subLists[i] = append(subLists[i], IntervalsSpan{Start: dt.Position, End: dt.Position, Gaps: 0})
					}
				}
			}
			spans := combineSubIntervals(subLists, r.Match.Ordered, r.Match.MaxGaps)
			return applyFilter(spans, r.Match.Filter)

		case r.Prefix != nil:
			effAn := r.Prefix.Analyzer
			if effAn == "" {
				effAn = analyzer
			}
			pfx := r.Prefix.Prefix
			if !strings.EqualFold(effAn, "whitespace") && !strings.EqualFold(effAn, "keyword") {
				pfx = strings.ToLower(pfx)
			}
			var spans []IntervalsSpan
			for _, dt := range docTokens {
				if strings.HasPrefix(dt.Term, pfx) {
					spans = append(spans, IntervalsSpan{Start: dt.Position, End: dt.Position, Gaps: 0})
				}
			}
			return applyFilter(spans, r.Prefix.Filter)

		case r.Wildcard != nil:
			effAn := r.Wildcard.Analyzer
			if effAn == "" {
				effAn = analyzer
			}
			ci := !strings.EqualFold(effAn, "whitespace") && !strings.EqualFold(effAn, "keyword")
			re := wildcardPatternRegex(r.Wildcard.Pattern, ci)
			var spans []IntervalsSpan
			if re != nil {
				for _, dt := range docTokens {
					if re.MatchString(dt.Term) {
						spans = append(spans, IntervalsSpan{Start: dt.Position, End: dt.Position, Gaps: 0})
					}
				}
			}
			return applyFilter(spans, r.Wildcard.Filter)

		case r.Fuzzy != nil:
			effAn := r.Fuzzy.Analyzer
			if effAn == "" {
				effAn = analyzer
			}
			term := r.Fuzzy.Term
			if !strings.EqualFold(effAn, "whitespace") && !strings.EqualFold(effAn, "keyword") {
				term = strings.ToLower(term)
			}
			fuzz := any("AUTO")
			if r.Fuzzy.Fuzziness != nil {
				fuzz = r.Fuzzy.Fuzziness
			}
			maxEdits := resolveFuzzyMaxEdits(fuzz, len([]rune(term)))
			allowTransp := true
			if r.Fuzzy.Transpositions != nil {
				allowTransp = *r.Fuzzy.Transpositions
			}
			var re *regexp.Regexp
			if maxEdits > 0 {
				pat := "^(" + buildFuzzyEditDistanceRegex(term, maxEdits, r.Fuzzy.PrefixLength, allowTransp) + ")$"
				re, _ = regexp.Compile(pat)
			}
			var spans []IntervalsSpan
			for _, dt := range docTokens {
				if maxEdits <= 0 {
					if dt.Term == term {
						spans = append(spans, IntervalsSpan{Start: dt.Position, End: dt.Position, Gaps: 0})
					}
				} else if re != nil && re.MatchString(dt.Term) {
					spans = append(spans, IntervalsSpan{Start: dt.Position, End: dt.Position, Gaps: 0})
				}
			}
			return applyFilter(spans, r.Fuzzy.Filter)

		case r.AllOf != nil:
			if len(r.AllOf.Intervals) == 0 {
				return nil, nil
			}
			subLists := make([][]IntervalsSpan, len(r.AllOf.Intervals))
			for i := range r.AllOf.Intervals {
				sl, err := evalRule(&r.AllOf.Intervals[i])
				if err != nil {
					return nil, err
				}
				subLists[i] = sl
			}
			spans := combineSubIntervals(subLists, r.AllOf.Ordered, r.AllOf.MaxGaps)
			return applyFilter(spans, r.AllOf.Filter)

		case r.AnyOf != nil:
			var all []IntervalsSpan
			for i := range r.AnyOf.Intervals {
				sl, err := evalRule(&r.AnyOf.Intervals[i])
				if err != nil {
					return nil, err
				}
				all = append(all, sl...)
			}
			spans := dedupIntervalsSpansKeepNonMinimal(all)
			return applyFilter(spans, r.AnyOf.Filter)
		}
		return nil, nil
	}

	spans, err := evalRule(rule)
	if err != nil {
		return nil, false, err
	}
	minimal := minimizeIntervalsSpans(spans)
	return minimal, len(minimal) > 0, nil
}
