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
	"strconv"
	"strings"
	"time"
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
	if err := json.Unmarshal(trimmed, &parsedDoc); err != nil {
		return nil, fmt.Errorf("invalid document JSON for _id=%q: %w", id, err)
	}

	row := make(map[string]any, len(s.Fields)+len(s.NestedRoots)+8)
	row["_id"] = id
	row["_version"] = version
	row["__DORIS_DELETE_SIGN__"] = 0
	row["_source"] = string(trimmed)
	row["_doc"] = json.RawMessage(trimmed)

	var allTextParts []string
	collectAllTextStrings(parsedDoc, &allTextParts)
	row["_all_text"] = strings.Join(allTextParts, " ")

	now := time.Now().UTC()

	// Populate promoted scalar, multi-valued array, and nested pre-filter columns
	for _, b := range s.Fields {
		switch b.Kind {
		case StoragePromotedScalar:
			val := extractScalarValue(parsedDoc, b.SourceJSONPath)
			val = coerceScalarForDoris(val, b.DorisType, b.LowercaseNormalizer, now)
			if val != nil {
				row[b.ColumnName] = val
			}
		case StoragePromotedArray, StorageNestedSubfield:
			vals := extractStringSliceValues(parsedDoc, b.SourceJSONPath, b.LowercaseNormalizer)
			if len(vals) > 0 {
				row[b.ColumnName] = vals
			}
		}
	}

	// Populate correlated nested JSON element arrays (`n__<nested_path>`)
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
			return int64(v)
		case json.Number:
			if i, err := v.Int64(); err == nil {
				return i
			}
			if f, err := v.Float64(); err == nil {
				return int64(f)
			}
		case string:
			if i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return i
			}
			if ms, ok := ParseESDateToEpochMillis(v, now); ok {
				return ms
			}
			return nil
		}
	case DorisInt:
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		case json.Number:
			if i, err := v.Int64(); err == nil {
				return int(i)
			}
		case string:
			if i, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return i
			}
			return nil
		}
	case DorisDouble:
		switch v := val.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		case int64:
			return float64(v)
		case json.Number:
			if f, err := v.Float64(); err == nil {
				return f
			}
		case string:
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				return f
			}
			return nil
		}
	case DorisBoolean:
		switch v := val.(type) {
		case bool:
			return v
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "true", "1":
				return true
			case "false", "0":
				return false
			}
			return nil
		}
	default:
		if strVal, ok := val.(string); ok {
			if lowercase {
				return strings.ToLower(strVal)
			}
			return strVal
		}
	}
	return val
}

// ParseESDateToEpochMillis parses ISO-8601 / RFC3339 date strings, epoch strings,
// and Elasticsearch date math expressions (`now`, `now-7d`, `now-1h/d`, `2024-01-01||+1d`)
// into Unix epoch milliseconds.
func ParseESDateToEpochMillis(input string, now time.Time) (int64, bool) {
	s := strings.TrimSpace(input)
	if s == "" {
		return 0, false
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, true
	}

	var baseTime time.Time
	var mathExpr string

	if strings.HasPrefix(s, "now") {
		baseTime = now.UTC()
		mathExpr = s[3:]
	} else if idx := strings.Index(s, "||"); idx >= 0 {
		t, ok := parseISODateString(s[:idx])
		if !ok {
			return 0, false
		}
		baseTime = t
		mathExpr = s[idx+2:]
	} else {
		t, ok := parseISODateString(s)
		if !ok {
			return 0, false
		}
		return t.UnixMilli(), true
	}

	t := applyESDateMath(baseTime, mathExpr)
	return t.UnixMilli(), true
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

func applyESDateMath(base time.Time, expr string) time.Time {
	t := base.UTC()
	var roundUnit byte
	if slashIdx := strings.IndexByte(expr, '/'); slashIdx >= 0 {
		if slashIdx+1 < len(expr) {
			roundUnit = expr[slashIdx+1]
		}
		expr = expr[:slashIdx]
	}

	i := 0
	for i < len(expr) {
		var sign int
		switch expr[i] {
		case '+':
			sign = 1
			i++
		case '-':
			sign = -1
			i++
		default:
			i++
			continue
		}
		numStart := i
		for i < len(expr) && expr[i] >= '0' && expr[i] <= '9' {
			i++
		}
		if numStart == i || i >= len(expr) {
			break
		}
		n, _ := strconv.Atoi(expr[numStart:i])
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
		}
	}

	switch roundUnit {
	case 'y', 'Y':
		t = time.Date(t.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	case 'M':
		t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	case 'd', 'D':
		t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	case 'h', 'H':
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, time.UTC)
	case 'm':
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
	case 's':
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
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
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	return extractNestedElementMaps(m[path[0]], path[1:])
}

func collectAllTextStrings(node any, out *[]string) {
	switch v := node.(type) {
	case string:
		if v != "" {
			*out = append(*out, v)
		}
	case map[string]any:
		for _, child := range v {
			collectAllTextStrings(child, out)
		}
	case []any:
		for _, child := range v {
			collectAllTextStrings(child, out)
		}
	}
}
