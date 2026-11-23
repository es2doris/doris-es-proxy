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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// MaxQueryStringDepth caps parenthesized group nesting depth in Lucene `query_string` expressions.
const MaxQueryStringDepth = 64

// KNNSearchSpec aliases KNNQuery for top-level `knn` search clauses.
type KNNSearchSpec = KNNQuery

// SignificantTextAggSpec aliases TermsAggSpec for `significant_text` aggregations.
type SignificantTextAggSpec = TermsAggSpec

// MedianAbsoluteDeviationAggSpec aliases MetricAggSpec for `median_absolute_deviation` aggregations.
type MedianAbsoluteDeviationAggSpec = MetricAggSpec

// TermsIncludePartition models `{partition, num_partitions}` for `terms.include` / `terms.exclude`.
type TermsIncludePartition struct {
	Partition     int `json:"partition"`
	NumPartitions int `json:"num_partitions"`
}

func validateInnerAggMeta(rawMap map[string]json.RawMessage) error {
	if rawMeta, hasMeta := rawMap["meta"]; hasMeta {
		mTrim := bytes.TrimSpace(rawMeta)
		if len(mTrim) == 0 || bytes.Equal(mTrim, []byte("null")) {
			return fmt.Errorf("parsing_exception: Expected [START_OBJECT] under [meta], but got a [VALUE_NULL]")
		}
		if mTrim[0] != '{' {
			return fmt.Errorf("parsing_exception: [meta] must be an object")
		}
	}
	return nil
}

func unmarshalAggMapWithContext(raw json.RawMessage) (map[string]AggSpec, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var rawAggs map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawAggs); err != nil {
		return nil, err
	}
	out := make(map[string]AggSpec, len(rawAggs))
	for aggName, specBytes := range rawAggs {
		var spec AggSpec
		if err := json.Unmarshal(specBytes, &spec); err != nil {
			msg := err.Error()
			if !strings.Contains(msg, " in [") &&
				(strings.Contains(msg, "Expected [START_OBJECT] under [meta], but got a [VALUE_NULL]") ||
					strings.Contains(msg, "[compression] must be greater than 0. Found [") ||
					strings.Contains(msg, "[precisionThreshold] must be ")) {
				return nil, fmt.Errorf("%w in [%s]", err, aggName)
			}
			return nil, err
		}
		out[aggName] = spec
	}
	return out, nil
}

// ValidateQueryStringDepth enforces MaxQueryStringDepth on parenthesized groups in a Lucene query string.
func ValidateQueryStringDepth(q string) error {
	depth := 0
	inQuote := false
	for i := 0; i < len(q); i++ {
		ch := q[i]
		if ch == '\\' {
			i++
			continue
		}
		if inQuote {
			if ch == '"' {
				inQuote = false
			}
			continue
		}
		if ch == '"' {
			inQuote = true
			continue
		}
		if ch == '/' && isRegexStartContext(q, i) {
			if end := findClosingUnescapedSlash(q, i+1); end > i {
				i = end
				continue
			}
		}
		switch ch {
		case '(':
			depth++
			if depth > MaxQueryStringDepth {
				return fmt.Errorf(
					"query_shard_exception: maxClauseCount is set to %d: query_string parenthesized group nesting depth exceeds maximum [%d]",
					MaxQueryStringDepth, MaxQueryStringDepth,
				)
			}
		case ')':
			if depth > 0 {
				depth--
			}
		}
	}
	return nil
}

func isRegexStartContext(q string, idx int) bool {
	if idx == 0 {
		return true
	}
	switch q[idx-1] {
	case ' ', '\t', '\n', '\r', '(', ':', '+', '-', '!', '^':
		return true
	default:
		return false
	}
}

func findClosingUnescapedSlash(q string, start int) int {
	for i := start; i < len(q); i++ {
		if q[i] == '\\' {
			i++
			continue
		}
		if q[i] == '\n' || q[i] == '\r' {
			return -1
		}
		if q[i] == '/' {
			return i
		}
	}
	return -1
}

type esWireError string

func (e esWireError) Error() string { return string(e) }

// DecodeHexSignedByteVector decodes an even-length hex string into signed int8 values as float64s.
func DecodeHexSignedByteVector(hexStr string) ([]float64, error) {
	if len(hexStr) == 0 {
		return nil, fmt.Errorf("illegal_argument_exception: [byte] vector hex string cannot be empty")
	}
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("illegal_argument_exception: [byte] vector hex string must have an even length, got [%d]", len(hexStr))
	}
	rawBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("illegal_argument_exception: invalid hex string for [byte] vector: %w", err)
	}
	out := make([]float64, len(rawBytes))
	for i, b := range rawBytes {
		out[i] = float64(int8(b)) // #nosec G115 -- intentional two's-complement signed-byte vector decoding
	}
	return out, nil
}

func parseKNNQueryVectorRawV2(raw json.RawMessage) ([]float64, string, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, "", false, nil
	}
	if trimmed[0] == '"' {
		var hexStr string
		if err := json.Unmarshal(trimmed, &hexStr); err != nil {
			return nil, "", false, err
		}
		bits, err := ExpandHexBitVector(hexStr)
		if err != nil {
			return nil, "", false, fmt.Errorf("x_content_parse_exception: failed to parse field [query_vector]: %w", err)
		}
		return bits, hexStr, true, nil
	}
	var vec []float64
	if err := json.Unmarshal(trimmed, &vec); err != nil {
		return nil, "", false, err
	}
	for _, v := range vec {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, "", false, fmt.Errorf("illegal_argument_exception: [knn] [query_vector] cannot contain NaN or Infinity")
		}
	}
	return vec, "", false, nil
}

// MissingAggSpec aliases ExistsQuery for backward compatibility while supporting `script` and `missing` on `missing` bucket aggregations.
type MissingAggSpec = ExistsQuery

func unmarshalMissingAggSpec(data []byte) (*ExistsQuery, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, fmt.Errorf("parsing_exception: Aggregation [missing] requires [field] or [script]; cannot be null")
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return nil, err
	}
	for k := range rawMap {
		switch k {
		case "field", "script", "missing", "aggs", "aggregations", "meta":
		default:
			return nil, fmt.Errorf("parsing_exception: [missing] unknown field [%s]", k)
		}
	}
	var raw struct {
		Field   string `json:"field"`
		Script  any    `json:"script"`
		Missing any    `json:"missing"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return nil, err
	}
	if strings.TrimSpace(raw.Field) == "" && raw.Script == nil {
		return nil, fmt.Errorf("parsing_exception: Required one of fields [field, script], but none were specified")
	}
	if raw.Script != nil {
		if err := validateScriptValue(raw.Script); err != nil {
			return nil, err
		}
	}
	return &ExistsQuery{
		Field:   raw.Field,
		Script:  raw.Script,
		Missing: raw.Missing,
	}, nil
}

func parseStringOrStringArrayStrict(raw json.RawMessage, fieldName string) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return nil, fmt.Errorf("parsing_exception: [%s] must be a string or array of strings: %w", fieldName, err)
		}
		return []string{s}, nil
	}
	if trimmed[0] == '[' {
		var rawElems []json.RawMessage
		if err := json.Unmarshal(trimmed, &rawElems); err != nil {
			return nil, fmt.Errorf("parsing_exception: [%s] must be an array of strings: %w", fieldName, err)
		}
		out := make([]string, 0, len(rawElems))
		for _, elem := range rawElems {
			et := bytes.TrimSpace(elem)
			if len(et) == 0 || et[0] != '"' {
				return nil, fmt.Errorf("parsing_exception: [%s] elements must be strings, got [%s]", fieldName, string(et))
			}
			var s string
			if err := json.Unmarshal(et, &s); err != nil {
				return nil, fmt.Errorf("parsing_exception: [%s] elements must be strings: %w", fieldName, err)
			}
			out = append(out, s)
		}
		return out, nil
	}
	return nil, fmt.Errorf("parsing_exception: [%s] must be a string or array of strings", fieldName)
}

func parseFlexibleRangesArrayOrMap(rawRanges json.RawMessage) ([]RangeAggBucket, bool, error) {
	trimmed := bytes.TrimSpace(rawRanges)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, false, nil
	}
	if trimmed[0] == '[' {
		var buckets []RangeAggBucket
		if err := json.Unmarshal(trimmed, &buckets); err != nil {
			return nil, false, err
		}
		return buckets, false, nil
	}
	if trimmed[0] == '{' {
		var rawObj map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawObj); err != nil {
			return nil, false, err
		}
		if len(rawObj) > 0 {
			hasNestedObj := false
			for _, rv := range rawObj {
				rt := bytes.TrimSpace(rv)
				if len(rt) > 0 && rt[0] == '{' {
					hasNestedObj = true
					break
				}
			}
			if !hasNestedObj {
				var single RangeAggBucket
				if err := json.Unmarshal(trimmed, &single); err != nil {
					return nil, false, err
				}
				return []RangeAggBucket{single}, false, nil
			}
		}
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		tok, err := dec.Token()
		if err != nil || tok != json.Delim('{') {
			return nil, false, fmt.Errorf("parsing_exception: invalid [ranges] object")
		}
		var buckets []RangeAggBucket
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return nil, false, err
			}
			keyStr, ok := keyTok.(string)
			if !ok {
				return nil, false, fmt.Errorf("parsing_exception: invalid [ranges] bucket key")
			}
			var rawBucket json.RawMessage
			if err := dec.Decode(&rawBucket); err != nil {
				return nil, false, err
			}
			var b RangeAggBucket
			if err := json.Unmarshal(rawBucket, &b); err != nil {
				return nil, false, err
			}
			if b.Key == "" {
				b.Key = keyStr
			}
			buckets = append(buckets, b)
		}
		if _, err := dec.Token(); err != nil {
			return nil, false, err
		}
		return buckets, true, nil
	}
	return nil, false, fmt.Errorf("parsing_exception: [ranges] must be an array or keyed object")
}

func formatJavaDouble(v float64) string {
	if math.IsNaN(v) {
		return "NaN"
	}
	if math.IsInf(v, 1) {
		return "Infinity"
	}
	if math.IsInf(v, -1) {
		return "-Infinity"
	}
	if v == 0 {
		if math.Signbit(v) {
			return "-0.0"
		}
		return "0.0"
	}
	abs := math.Abs(v)
	if abs >= 1e7 || abs < 1e-3 {
		s := strconv.FormatFloat(v, 'e', -1, 64)
		parts := strings.SplitN(s, "e", 2)
		if len(parts) == 2 {
			mantissa := parts[0]
			if !strings.Contains(mantissa, ".") {
				mantissa += ".0"
			}
			if exp, err := strconv.Atoi(parts[1]); err == nil {
				return mantissa + "E" + strconv.Itoa(exp)
			}
		}
	}
	if v == math.Trunc(v) {
		return strconv.FormatInt(int64(v), 10) + ".0"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func formatRangeBoundKey(v any) string {
	switch tv := v.(type) {
	case float64:
		return formatJavaDouble(tv)
	case json.Number:
		s := tv.String()
		if fv, err := tv.Float64(); err == nil {
			return formatJavaDouble(fv)
		}
		return s
	default:
		return fmt.Sprintf("%v", v)
	}
}

func isEmptyOrNullJSONQueryObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	if trimmed[0] == '{' {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &m); err == nil && len(m) == 0 {
			return true
		}
	}
	return false
}

func validateFiltersAggRawClauses(trimmed []byte) error {
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var rawList []json.RawMessage
		if err := json.Unmarshal(trimmed, &rawList); err == nil {
			for _, item := range rawList {
				if isEmptyOrNullJSONQueryObject(item) {
					return fmt.Errorf("parsing_exception: [filters] query malformed, empty clause found")
				}
			}
		}
	case '{':
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &rawMap); err == nil {
			for _, item := range rawMap {
				if isEmptyOrNullJSONQueryObject(item) {
					return fmt.Errorf("parsing_exception: [filters] query malformed, empty clause found")
				}
			}
		}
	}
	return nil
}

func validateTermsIncludeRegex(pat string) error {
	if _, err := regexp.Compile(pat); err != nil {
		return fmt.Errorf("illegal_argument_exception: invalid regex pattern [%s]: %w", pat, err)
	}
	return nil
}

type highlightFlexibleInts struct {
	FragmentSize      *int
	NumberOfFragments *int
	NoMatchSize       *int
	BoundaryMaxScan   *int
	FragmentOffset    *int
	MaxAnalyzedOffset *int
	PhraseLimit       *int
	MaxFragmentLength *int
}

func extractHighlightFlexibleInts(rawMap map[string]json.RawMessage) (highlightFlexibleInts, map[string]json.RawMessage, error) {
	var out highlightFlexibleInts
	cleaned := make(map[string]json.RawMessage, len(rawMap))
	for k, v := range rawMap {
		cleaned[k] = v
	}
	intFields := []struct {
		key string
		dst **int
	}{
		{"fragment_size", &out.FragmentSize},
		{"number_of_fragments", &out.NumberOfFragments},
		{"no_match_size", &out.NoMatchSize},
		{"boundary_max_scan", &out.BoundaryMaxScan},
		{"fragment_offset", &out.FragmentOffset},
		{"max_analyzed_offset", &out.MaxAnalyzedOffset},
		{"phrase_limit", &out.PhraseLimit},
		{"max_fragment_length", &out.MaxFragmentLength},
	}
	for _, f := range intFields {
		if rawVal, ok := cleaned[f.key]; ok {
			parsed, err := parseStrictSearchIntJSON(rawVal, f.key)
			if err != nil {
				return out, nil, err
			}
			*f.dst = parsed
			delete(cleaned, f.key)
		}
	}
	return out, cleaned, nil
}
