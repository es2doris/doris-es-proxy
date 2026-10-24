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
	"strings"
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

	// Populate promoted scalar, multi-valued array, and nested pre-filter columns
	for _, b := range s.Fields {
		switch b.Kind {
		case StoragePromotedScalar:
			val := extractScalarValue(parsedDoc, b.SourceJSONPath)
			if val != nil {
				if strVal, ok := val.(string); ok && b.LowercaseNormalizer {
					val = strings.ToLower(strVal)
				}
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

func extractScalarValue(node any, path []string) any {
	if len(path) == 0 || node == nil {
		return normalizeScalar(node)
	}
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	next, exists := m[path[0]]
	if !exists {
		return nil
	}
	return extractScalarValue(next, path[1:])
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
