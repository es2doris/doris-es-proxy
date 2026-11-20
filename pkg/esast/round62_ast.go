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

package esast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// parseFlexibleDateHistogramOffset parses an ES `date_histogram` `"offset"` parameter,
// accepting either a time value string (e.g. `"-7h"`) or a JSON number in milliseconds
// (e.g. `-25200000` -> `"-25200000ms"`, `0` -> `"0ms"`).
func parseFlexibleDateHistogramOffset(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return "", fmt.Errorf("parsing_exception: [date_histogram] invalid [offset]: %w", err)
		}
		return s, nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var num json.Number
	if err := dec.Decode(&num); err != nil {
		return "", fmt.Errorf("parsing_exception: [date_histogram] [offset] must be a time string or number of milliseconds")
	}
	if iv, err := num.Int64(); err == nil {
		return strconv.FormatInt(iv, 10) + "ms", nil
	}
	fv, err := num.Float64()
	if err != nil || math.IsNaN(fv) || math.IsInf(fv, 0) {
		return "", fmt.Errorf("parsing_exception: [date_histogram] [offset] must be a finite number of milliseconds")
	}
	return strconv.FormatInt(int64(math.Round(fv)), 10) + "ms", nil
}

// parseFlexiblePercentsSlice parses `"percents"` on `percentiles` / `percentiles_bucket`
// aggregations, accepting either a JSON array `[50, 95]` or a single JSON number `95` -> `[]float64{95}`.
func parseFlexiblePercentsSlice(raw json.RawMessage, aggName string) ([]float64, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, fmt.Errorf("parsing_exception: [%s] [percents] cannot be empty", aggName)
	}
	var out []float64
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &out); err != nil {
			return nil, fmt.Errorf("parsing_exception: [%s] invalid [percents]: %w", aggName, err)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("parsing_exception: [%s] [percents] cannot be empty", aggName)
		}
	} else {
		var single float64
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return nil, fmt.Errorf("parsing_exception: [%s] [percents] must be a number or array of numbers: %w", aggName, err)
		}
		out = []float64{single}
	}
	for _, pct := range out {
		if pct < 0 || pct > 100 || math.IsNaN(pct) || math.IsInf(pct, 0) {
			return nil, fmt.Errorf("illegal_argument_exception: [%s] [percents] values must be between 0.0 and 100.0", aggName)
		}
	}
	return out, nil
}

// ValidateOnScriptError validates an ES `"on_script_error"` field parameter (`"continue"` or `"fail"`).
func ValidateOnScriptError(val string) (string, error) {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return "", nil
	}
	switch trimmed {
	case "continue", "fail":
		return trimmed, nil
	default:
		return "", esWireError(fmt.Sprintf("mapper_parsing_exception: [on_script_error] must be [continue] or [fail], got [%s]", val))
	}
}

// NormalizeFieldScriptObject normalizes a field/runtime `"script"` specification (either a string
// shorthand `"emit(...)"` or an object `{"source": "...", "params": {...}}`) into a canonical
// ES mapping object with `"lang": "painless"` defaulted when omitted.
func NormalizeFieldScriptObject(raw any) (map[string]any, error) {
	if raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case string:
		return map[string]any{
			"lang":   "painless",
			"source": v,
		}, nil
	case map[string]any:
		out := make(map[string]any, len(v)+1)
		for k, mv := range v {
			switch k {
			case "source", "id", "lang", "params", "options":
				out[k] = mv
			default:
				return nil, esWireError(fmt.Sprintf("mapper_parsing_exception: unknown script parameter [%s]", k))
			}
		}
		_, hasSource := out["source"]
		_, hasID := out["id"]
		if !hasSource && !hasID {
			return nil, esWireError("mapper_parsing_exception: [script] object must specify [source] or [id]")
		}
		if hasSource && hasID {
			return nil, esWireError("mapper_parsing_exception: [script] cannot specify both [source] and [id]")
		}
		if src, ok := out["source"]; ok {
			if _, okStr := src.(string); !okStr {
				return nil, esWireError("mapper_parsing_exception: [script.source] must be a string")
			}
		}
		langVal, hasLang := out["lang"]
		if !hasLang || langVal == nil || strings.TrimSpace(fmt.Sprintf("%v", langVal)) == "" {
			out["lang"] = "painless"
		}
		return out, nil
	default:
		return nil, esWireError("mapper_parsing_exception: [script] must be a string or object")
	}
}

// RankFeatureNullValue extracts and validates `null_value` on a `rank_feature` field property.
// Returns `(nil, nil)` when `NullValue` is unset; returns an error if non-numeric, NaN/Inf, or `<= 0`.
func (fp FieldProperty) RankFeatureNullValue() (*float64, error) {
	if fp.NullValue == nil {
		return nil, nil
	}
	var fv float64
	switch v := fp.NullValue.(type) {
	case float64:
		fv = v
	case float32:
		fv = float64(v)
	case int:
		fv = float64(v)
	case int64:
		fv = float64(v)
	case json.Number:
		parsed, err := v.Float64()
		if err != nil {
			return nil, esWireError(fmt.Sprintf("mapper_parsing_exception: [null_value] on [rank_feature] must be a positive finite float, got [%v]", fp.NullValue))
		}
		fv = parsed
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return nil, esWireError(fmt.Sprintf("mapper_parsing_exception: [null_value] on [rank_feature] must be a positive finite float, got [%s]", v))
		}
		fv = parsed
	default:
		return nil, esWireError(fmt.Sprintf("mapper_parsing_exception: [null_value] on [rank_feature] must be a positive finite float, got [%T]", fp.NullValue))
	}
	f32 := float32(fv)
	if math.IsNaN(fv) || math.IsInf(fv, 0) || fv <= 0 || math.Abs(fv) > math.MaxFloat32 || f32 == 0 || math.Abs(float64(f32)) < 1.17549435e-38 {
		return nil, esWireError(fmt.Sprintf("illegal_argument_exception: [null_value] must be a positive normal float for field of type [rank_feature], got [%v]", fv))
	}
	outF := float64(f32)
	return &outF, nil
}

// IsCompositeRuntime reports whether this `FieldProperty` declares `type: "composite"` runtime field.
func (fp FieldProperty) IsCompositeRuntime() bool {
	return strings.EqualFold(strings.TrimSpace(fp.Type), "composite")
}

// IPPrefixAggSpec models an Elasticsearch `ip_prefix` bucket aggregation (`ip_prefix.yml`).
type IPPrefixAggSpec struct {
	Field              string `json:"field"`
	PrefixLength       int    `json:"prefix_length"`
	IsIPv6             bool   `json:"is_ipv6,omitempty"`
	Keyed              *bool  `json:"keyed,omitempty"`
	MinDocCount        *int64 `json:"min_doc_count,omitempty"`
	AppendPrefixLength *bool  `json:"append_prefix_length,omitempty"`
	Format             string `json:"format,omitempty"`
}

func (ip *IPPrefixAggSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "field", "prefix_length", "is_ipv6", "keyed", "min_doc_count",
			"append_prefix_length", "format", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [ip_prefix] unknown field [%s]", k)
		}
	}
	var raw struct {
		Field              string `json:"field"`
		PrefixLength       *int   `json:"prefix_length"`
		IsIPv6             any    `json:"is_ipv6"`
		Keyed              any    `json:"keyed"`
		MinDocCount        *int64 `json:"min_doc_count"`
		AppendPrefixLength any    `json:"append_prefix_length"`
		Format             string `json:"format"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Field) == "" {
		return fmt.Errorf("parsing_exception: [ip_prefix] requires [field]")
	}
	if raw.PrefixLength == nil {
		return fmt.Errorf("parsing_exception: [ip_prefix] requires [prefix_length]")
	}
	var isIPv6 bool
	if raw.IsIPv6 != nil {
		b, err := parseFlexibleBool(raw.IsIPv6)
		if err != nil {
			return fmt.Errorf("parsing_exception: [ip_prefix] [is_ipv6] %w", err)
		}
		isIPv6 = b
	}
	prefixLen := *raw.PrefixLength
	if !isIPv6 {
		if prefixLen < 0 || prefixLen > 32 {
			return esWireError(fmt.Sprintf("illegal_argument_exception: [prefix_length] must be in range [0, 32] while value is [%d]", prefixLen))
		}
	} else {
		if prefixLen < 0 || prefixLen > 128 {
			return esWireError(fmt.Sprintf("illegal_argument_exception: [prefix_length] must be in range [0, 128] while value is [%d]", prefixLen))
		}
	}
	if raw.MinDocCount != nil && *raw.MinDocCount < 0 {
		return fmt.Errorf("illegal_argument_exception: [ip_prefix] [min_doc_count] must be >= 0")
	}
	var keyedPtr *bool
	if raw.Keyed != nil {
		b, err := parseFlexibleBool(raw.Keyed)
		if err != nil {
			return fmt.Errorf("parsing_exception: [ip_prefix] [keyed] %w", err)
		}
		keyedPtr = &b
	}
	var appendPtr *bool
	if raw.AppendPrefixLength != nil {
		b, err := parseFlexibleBool(raw.AppendPrefixLength)
		if err != nil {
			return fmt.Errorf("parsing_exception: [ip_prefix] [append_prefix_length] %w", err)
		}
		appendPtr = &b
	}
	*ip = IPPrefixAggSpec{
		Field:              raw.Field,
		PrefixLength:       prefixLen,
		IsIPv6:             isIPv6,
		Keyed:              keyedPtr,
		MinDocCount:        raw.MinDocCount,
		AppendPrefixLength: appendPtr,
		Format:             raw.Format,
	}
	return nil
}

// EffectiveKeyed returns whether `ip_prefix` buckets should be returned as a map (default `false`).
func (ip *IPPrefixAggSpec) EffectiveKeyed() bool {
	if ip != nil && ip.Keyed != nil {
		return *ip.Keyed
	}
	return false
}

// EffectiveMinDocCount returns the minimum bucket document count for `ip_prefix` (default `1`).
func (ip *IPPrefixAggSpec) EffectiveMinDocCount() int64 {
	if ip != nil && ip.MinDocCount != nil {
		return *ip.MinDocCount
	}
	return 1
}

// EffectiveAppendPrefixLength returns whether CIDR suffix `/N` should be appended to keys (default `false`).
func (ip *IPPrefixAggSpec) EffectiveAppendPrefixLength() bool {
	if ip != nil && ip.AppendPrefixLength != nil {
		return *ip.AppendPrefixLength
	}
	return false
}

// TimeSeriesAggSpec models an Elasticsearch `time_series` bucket aggregation (`time_series.yml`).
type TimeSeriesAggSpec struct {
	Size      *int  `json:"size,omitempty"`
	ShardSize *int  `json:"shard_size,omitempty"`
	Keyed     *bool `json:"keyed,omitempty"`
}

func (ts *TimeSeriesAggSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "size", "shard_size", "keyed", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [time_series] unknown field [%s]", k)
		}
	}
	var raw struct {
		Size      *int `json:"size"`
		ShardSize *int `json:"shard_size"`
		Keyed     any  `json:"keyed"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if raw.Size != nil && *raw.Size <= 0 {
		return esWireError(fmt.Sprintf("illegal_argument_exception: [size] must be greater than 0. Found [%d] in [time_series]", *raw.Size))
	}
	if raw.ShardSize != nil && *raw.ShardSize <= 0 {
		return esWireError(fmt.Sprintf("illegal_argument_exception: [shard_size] must be greater than 0. Found [%d] in [time_series]", *raw.ShardSize))
	}
	if raw.Size != nil && raw.ShardSize != nil && *raw.ShardSize < *raw.Size {
		return esWireError(fmt.Sprintf("illegal_argument_exception: [shard_size] cannot be less than [size] in [time_series] ([%d] < [%d])", *raw.ShardSize, *raw.Size))
	}
	var keyedPtr *bool
	if raw.Keyed != nil {
		b, err := parseFlexibleBool(raw.Keyed)
		if err != nil {
			return fmt.Errorf("parsing_exception: [time_series] [keyed] %w", err)
		}
		keyedPtr = &b
	}
	*ts = TimeSeriesAggSpec{
		Size:      raw.Size,
		ShardSize: raw.ShardSize,
		Keyed:     keyedPtr,
	}
	return nil
}

// EffectiveSize returns the `time_series` bucket limit (default `10000`).
func (ts *TimeSeriesAggSpec) EffectiveSize() int {
	if ts != nil && ts.Size != nil && *ts.Size > 0 {
		return *ts.Size
	}
	return 10000
}

// EffectiveKeyed returns whether `time_series` buckets are returned keyed by `_tsid` (default `true`).
func (ts *TimeSeriesAggSpec) EffectiveKeyed() bool {
	if ts != nil && ts.Keyed != nil {
		return *ts.Keyed
	}
	return true
}

// ChildrenAggSpec models an Elasticsearch `children` join bucket aggregation (`40_aggregations.yml`).
type ChildrenAggSpec struct {
	Type string `json:"type"`
}

func (c *ChildrenAggSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "type", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [children] unknown field [%s]", k)
		}
	}
	var raw struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Type) == "" {
		return fmt.Errorf("parsing_exception: Missing [type] field for [children] aggregation")
	}
	c.Type = raw.Type
	return nil
}

// ParentAggSpec models an Elasticsearch `parent` join bucket aggregation (`40_aggregations.yml`).
type ParentAggSpec struct {
	Type string `json:"type"`
}

func (p *ParentAggSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	for k := range rawMap {
		switch k {
		case "type", "aggs", "aggregations", "meta":
		default:
			return fmt.Errorf("parsing_exception: [parent] unknown field [%s]", k)
		}
	}
	var raw struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.Type) == "" {
		return fmt.Errorf("parsing_exception: Missing [type] field for [parent] aggregation")
	}
	p.Type = raw.Type
	return nil
}
