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
	"unicode/utf8"
)

// ShredDocument transforms an Elasticsearch document (`rawSource`) into a flat Doris Stream Load
// JSON row containing `_id`, `_version`, `__DORIS_DELETE_SIGN__`, verbatim `_source`, `_doc` (VARIANT),
// `_all_text`, promoted `f__*` columns, and `n__*` correlated + pre-filter nested array columns.
func ShredDocument(
	s *IndexSchema,
	id string,
	version int64,
	deleted bool,
	rawSource json.RawMessage,
) ([]byte, error) {
	if version <= 0 {
		version = 1
	}
	if deleted {
		tombstone := map[string]any{
			"_id":                   id,
			"_version":              version,
			"__DORIS_DELETE_SIGN__": 1,
			"_source":               "{}",
			"_doc":                  map[string]any{},
		}
		return json.Marshal(tombstone)
	}

	trimmed := bytes.TrimSpace(rawSource)
	if len(trimmed) == 0 {
		trimmed = []byte("{}")
	}

	var parsedDoc map[string]any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&parsedDoc); err != nil || parsedDoc == nil {
		if err == nil {
			err = fmt.Errorf("expected JSON object")
		}
		return nil, fmt.Errorf("invalid document JSON for _id=%q: %w", id, err)
	}

	row := make(map[string]any, len(s.Fields)+len(s.NestedRoots)+8)
	row["_id"] = id
	row["_version"] = version
	row["__DORIS_DELETE_SIGN__"] = 0
	row["_source"] = string(trimmed)
	row["_doc"] = json.RawMessage(trimmed)

	var allTextBuilder strings.Builder
	allTextBuilder.Grow(len(trimmed) / 2)
	collectAllTextBuilder(parsedDoc, &allTextBuilder)
	row["_all_text"] = allTextBuilder.String()

	var now time.Time
	getNow := func() time.Time {
		if now.IsZero() {
			now = time.Now().UTC()
		}
		return now
	}

	// Populate promoted scalar, multi-valued array, and nested pre-filter columns
	fieldsToVisit := s.OrderedFields
	if len(fieldsToVisit) == 0 && len(s.Fields) > 0 {
		for _, b := range s.Fields {
			fieldsToVisit = append(fieldsToVisit, b)
		}
	}
	for _, b := range fieldsToVisit {
		switch b.Kind {
		case StoragePromotedScalar:
			val := extractScalarValue(parsedDoc, b.SourceJSONPath)
			val = coerceScalarForDoris(val, b.DorisType, b.LowercaseNormalizer, getNow())
			if val != nil {
				row[b.ColumnName] = val
			}
		case StoragePromotedArray, StorageNestedSubfield:
			vals := extractStringSliceValues(parsedDoc, b.SourceJSONPath, b.LowercaseNormalizer)
			if len(vals) > 0 {
				row[b.ColumnName] = vals
			}
		case StoragePromotedVector:
			vec := extractFloatSliceValues(parsedDoc, b.SourceJSONPath)
			if len(vec) > 0 {
				row[b.ColumnName] = vec
			}
		}
	}

	// Populate correlated nested JSON element arrays (`n__<nested_path>`)
	if len(s.NestedRootSpecs) > 0 {
		for _, nr := range s.NestedRootSpecs {
			rawElements := extractNestedElementMaps(parsedDoc, nr.PathParts)
			if len(rawElements) > 0 {
				serializedElems := make([]string, 0, len(rawElements))
				for _, elemMap := range rawElements {
					encoded, err := json.Marshal(elemMap)
					if err == nil {
						serializedElems = append(serializedElems, string(encoded))
					}
				}
				row[nr.ColumnName] = serializedElems
			}
		}
	} else {
		for nestedPath, corrCol := range s.NestedRoots {
			pathParts := strings.Split(nestedPath, ".")
			rawElements := extractNestedElementMaps(parsedDoc, pathParts)
			if len(rawElements) > 0 {
				serializedElems := make([]string, 0, len(rawElements))
				for _, elemMap := range rawElements {
					encoded, err := json.Marshal(elemMap)
					if err == nil {
						serializedElems = append(serializedElems, string(encoded))
					}
				}
				row[corrCol] = serializedElems
			}
		}
	}

	return json.Marshal(row)
}

func coerceScalarForDoris(val any, dorisType DorisScalarType, lowercase bool, now time.Time) any {
	if val == nil {
		return nil
	}
	switch dorisType {
	case DorisBigInt:
		switch v := val.(type) {
		case int64:
			return v
		case int:
			return int64(v)
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil
			}
			return int64(v)
		case json.Number:
			if i, err := v.Int64(); err == nil {
				return i
			}
			if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return int64(f)
			}
			return nil
		case string:
			if i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return i
			}
			if ms, ok := ParseESDateToEpochMillis(v, now); ok {
				return ms
			}
			return nil
		default:
			return nil
		}
	case DorisInt:
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil
			}
			return int(v)
		case json.Number:
			if i, err := v.Int64(); err == nil {
				return int(i)
			}
			if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return int(f)
			}
			return nil
		case string:
			if i, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return i
			}
			return nil
		default:
			return nil
		}
	case DorisDouble:
		switch v := val.(type) {
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil
			}
			return v
		case int:
			return float64(v)
		case int64:
			return float64(v)
		case json.Number:
			if f, err := v.Float64(); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f
			}
			return nil
		case string:
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
				return f
			}
			return nil
		default:
			return nil
		}
	case DorisBoolean:
		switch v := val.(type) {
		case bool:
			return v
		case int:
			return v != 0
		case int64:
			return v != 0
		case float64:
			return v != 0 && !math.IsNaN(v)
		case json.Number:
			return v.String() != "0"
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true", "1":
				return true
			case "false", "0":
				return false
			}
			return nil
		default:
			return nil
		}
	default:
		if strVal, ok := val.(string); ok {
			if lowercase {
				strVal = strings.ToLower(strVal)
			}
			if dorisType == DorisVarchar && len(strVal) > 1024 {
				strVal = truncateUTF8Bytes(strVal, 1024)
			}
			return strVal
		}
	}
	return val
}

func truncateUTF8Bytes(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	b := s[:maxBytes]
	for len(b) > 0 && !utf8.ValidString(b) {
		b = b[:len(b)-1]
	}
	return b
}

// ParseESDateToEpochMillis parses ISO-8601 / RFC3339 date strings, epoch strings,
// and Elasticsearch date math expressions (`now`, `now-7d`, `now-1h/d`, `2024-01-01||+1d`)
// into Unix epoch milliseconds.
func ParseESDateToEpochMillis(input string, now time.Time) (int64, bool) {
	return ParseESDateBoundToEpochMillis(input, now, false)
}

// ParseESDateBoundToEpochMillis parses ISO-8601 / RFC3339 date strings, epoch strings,
// and Elasticsearch date math expressions into Unix epoch milliseconds.
// When `roundUp` is true (used for inclusive upper bounds like `lte`), rounding units (`/d`, `/h`, etc.)
// and date-only strings (`"2024-01-15"`) round to the end of the interval (`23:59:59.999` for `/d`).
func ParseESDateBoundToEpochMillis(input string, now time.Time, roundUp bool) (int64, bool) {
	s := strings.TrimSpace(input)
	if s == "" {
		return 0, false
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, true
	}

	var baseTime time.Time
	var mathExpr string
	dateOnlyPrefix := false

	if strings.HasPrefix(s, "now") {
		mathExpr = s[3:]
		if mathExpr != "" && mathExpr[0] != '+' && mathExpr[0] != '-' && mathExpr[0] != '/' {
			return 0, false
		}
		baseTime = now.UTC()
	} else if idx := strings.Index(s, "||"); idx >= 0 {
		prefix := strings.TrimSpace(s[:idx])
		mathExpr = strings.TrimSpace(s[idx+2:])
		if ms, err := strconv.ParseInt(prefix, 10, 64); err == nil {
			baseTime = time.UnixMilli(ms).UTC()
		} else if t, ok := parseISODateString(prefix); ok {
			dateOnlyPrefix = isDateOnlyString(prefix)
			if roundUp && mathExpr == "" && dateOnlyPrefix {
				t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
			}
			baseTime = t
		} else {
			return 0, false
		}
	} else {
		t, ok := parseISODateString(s)
		if !ok {
			return 0, false
		}
		if roundUp && isDateOnlyString(s) {
			t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
		}
		return t.UnixMilli(), true
	}

	t, ok := applyESDateMathWithRound(baseTime, mathExpr, roundUp)
	if !ok {
		return 0, false
	}
	if roundUp && dateOnlyPrefix && mathExpr != "" && !strings.Contains(mathExpr, "/") && hasOnlyCalendarDayOrLargerOffsets(mathExpr) {
		t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
	}
	return t.UnixMilli(), true
}

func hasOnlyCalendarDayOrLargerOffsets(expr string) bool {
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c == '+' || c == '-' || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case 'y', 'Y', 'M', 'w', 'W', 'd', 'D':
		default:
			return false
		}
	}
	return true
}

func isDateOnlyString(s string) bool {
	return len(s) == 10 && (s[4] == '-' || s[4] == '/') && (s[7] == '-' || s[7] == '/')
}

func parseISODateString(s string) (time.Time, bool) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z0700",
		"2006-01-02T15:04:05Z0700",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"2006/01/02",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func applyESDateMathWithRound(base time.Time, expr string, roundUp bool) (time.Time, bool) {
	t := base.UTC()
	i := 0
	for i < len(expr) {
		if expr[i] == '/' {
			i++
			if i >= len(expr) {
				return time.Time{}, false
			}
			switch expr[i] {
			case 'y', 'Y', 'M', 'w', 'W', 'd', 'D', 'h', 'H', 'm', 's':
				unit := expr[i]
				i++
				t = roundTimeToUnit(t, unit, roundUp && i == len(expr))
			default:
				return time.Time{}, false
			}
			continue
		}
		var sign int
		switch expr[i] {
		case '+':
			sign = 1
			i++
		case '-':
			sign = -1
			i++
		default:
			return time.Time{}, false
		}
		numStart := i
		for i < len(expr) && expr[i] >= '0' && expr[i] <= '9' {
			i++
		}
		if numStart == i || i >= len(expr) {
			return time.Time{}, false
		}
		n, err := strconv.Atoi(expr[numStart:i])
		if err != nil || n > 100000 {
			return time.Time{}, false
		}
		unit := expr[i]
		i++
		val := sign * n
		switch unit {
		case 'y', 'Y':
			t = t.AddDate(val, 0, 0)
		case 'M':
			t = t.AddDate(0, val, 0)
		case 'w', 'W':
			t = t.AddDate(0, 0, val*7)
		case 'd', 'D':
			t = t.AddDate(0, 0, val)
		case 'h', 'H':
			t = t.Add(time.Duration(val) * time.Hour)
		case 'm':
			t = t.Add(time.Duration(val) * time.Minute)
		case 's':
			t = t.Add(time.Duration(val) * time.Second)
		default:
			return time.Time{}, false
		}
	}
	return t, true
}

func roundTimeToUnit(t time.Time, roundUnit byte, roundUp bool) time.Time {
	switch roundUnit {
	case 'y', 'Y':
		t = time.Date(t.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
		if roundUp {
			t = t.AddDate(1, 0, 0).Add(-time.Millisecond)
		}
	case 'M':
		t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		if roundUp {
			t = t.AddDate(0, 1, 0).Add(-time.Millisecond)
		}
	case 'w', 'W':
		weekday := int(t.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		t = time.Date(t.Year(), t.Month(), t.Day()-(weekday-1), 0, 0, 0, 0, time.UTC)
		if roundUp {
			t = t.AddDate(0, 0, 7).Add(-time.Millisecond)
		}
	case 'd', 'D':
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
		if roundUp {
			t = t.AddDate(0, 0, 1).Add(-time.Millisecond)
		}
	case 'h', 'H':
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, time.UTC)
		if roundUp {
			t = t.Add(time.Hour - time.Millisecond)
		}
	case 'm':
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
		if roundUp {
			t = t.Add(time.Minute - time.Millisecond)
		}
	case 's':
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		if roundUp {
			t = t.Add(time.Second - time.Millisecond)
		}
	}
	return t
}

func extractScalarValue(node any, path []string) any {
	if len(path) == 0 || node == nil {
		return normalizeScalar(node)
	}
	switch curr := node.(type) {
	case map[string]any:
		next, exists := curr[path[0]]
		if !exists {
			return nil
		}
		return extractScalarValue(next, path[1:])
	case []any:
		for _, elem := range curr {
			if v := extractScalarValue(elem, path); v != nil {
				return v
			}
		}
		return nil
	default:
		return nil
	}
}

func normalizeScalar(v any) any {
	switch val := v.(type) {
	case nil:
		return nil
	case []any:
		if len(val) == 0 {
			return nil
		}
		return normalizeScalar(val[0])
	case map[string]any:
		b, _ := json.Marshal(val)
		return string(b)
	default:
		return val
	}
}

func extractStringSliceValues(node any, path []string, lowercase bool) []string {
	var out []string
	collectStringsAtPath(node, path, lowercase, &out)
	return out
}

func collectStringsAtPath(node any, path []string, lowercase bool, out *[]string) {
	if node == nil {
		return
	}
	if len(path) == 0 {
		switch v := node.(type) {
		case string:
			if lowercase {
				v = strings.ToLower(v)
			}
			*out = append(*out, v)
		case []any:
			for _, item := range v {
				collectStringsAtPath(item, nil, lowercase, out)
			}
		default:
			s := fmt.Sprintf("%v", v)
			if lowercase {
				s = strings.ToLower(s)
			}
			*out = append(*out, s)
		}
		return
	}

	switch curr := node.(type) {
	case map[string]any:
		if next, ok := curr[path[0]]; ok {
			collectStringsAtPath(next, path[1:], lowercase, out)
		}
	case []any:
		for _, elem := range curr {
			collectStringsAtPath(elem, path, lowercase, out)
		}
	}
}

func extractNestedElementMaps(node any, path []string) []map[string]any {
	if node == nil {
		return nil
	}
	if len(path) == 0 {
		switch v := node.(type) {
		case []any:
			var res []map[string]any
			for _, item := range v {
				if m, ok := item.(map[string]any); ok {
					res = append(res, m)
				}
			}
			return res
		case map[string]any:
			return []map[string]any{v}
		}
		return nil
	}
	switch curr := node.(type) {
	case map[string]any:
		if next, exists := curr[path[0]]; exists {
			return extractNestedElementMaps(next, path[1:])
		}
		if len(path) > 1 {
			dotted := strings.Join(path, ".")
			if next, exists := curr[dotted]; exists {
				return extractNestedElementMaps(next, nil)
			}
		}
		return nil
	case []any:
		var res []map[string]any
		for _, elem := range curr {
			res = append(res, extractNestedElementMaps(elem, path)...)
		}
		return res
	default:
		return nil
	}
}

func collectAllTextBuilder(node any, sb *strings.Builder) {
	switch v := node.(type) {
	case string:
		if v != "" {
			if sb.Len() > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(v)
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			collectAllTextBuilder(v[k], sb)
		}
	case []any:
		for _, child := range v {
			collectAllTextBuilder(child, sb)
		}
	}
}

func extractFloatSliceValues(node any, path []string) []float64 {
	if node == nil {
		return nil
	}
	if len(path) == 0 {
		arr, ok := node.([]any)
		if !ok {
			return nil
		}
		out := make([]float64, 0, len(arr))
		for _, elem := range arr {
			switch v := elem.(type) {
			case float64:
				out = append(out, v)
			case int:
				out = append(out, float64(v))
			case int64:
				out = append(out, float64(v))
			case json.Number:
				if f, err := v.Float64(); err == nil {
					out = append(out, f)
				}
			}
		}
		return out
	}
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	return extractFloatSliceValues(m[path[0]], path[1:])
}
