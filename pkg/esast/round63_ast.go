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
	"strings"
)

// IPRangeAggSpec aliases RangeAggSpec for `ip_range` bucket aggregations.
type IPRangeAggSpec = RangeAggSpec

// extractExactLargeIntNumber returns `json.Number` when `raw` is an integer JSON literal
// exceeding exact IEEE-754 float64 precision (`|n| > 2^53`), such as `unsigned_long` `17446744073709551615`.
func extractExactLargeIntNumber(raw json.RawMessage) (json.Number, bool) {
	t := bytes.TrimSpace(raw)
	if len(t) < 16 || t[0] == '"' || t[0] == '{' || t[0] == '[' || bytes.ContainsAny(t, ".eE") {
		return "", false
	}
	s := string(t)
	if _, err := json.Number(s).Int64(); err == nil {
		return json.Number(s), true
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return "", false
		}
	}
	return json.Number(s), true
}

// CountedTermsAggSpec aliases TermsAggSpec for `counted_terms` bucket aggregations on `counted_keyword` fields.
type CountedTermsAggSpec = TermsAggSpec

// IsLookupRuntime reports whether this FieldProperty declares an ES 8 `type: "lookup"` runtime field.
func (fp FieldProperty) IsLookupRuntime() bool {
	return strings.EqualFold(strings.TrimSpace(fp.Type), "lookup")
}

// EffectiveLookupTargetField returns `TargetField` if non-empty, falling back to `KeyField`.
func (fp FieldProperty) EffectiveLookupTargetField() string {
	if strings.TrimSpace(fp.TargetField) != "" {
		return strings.TrimSpace(fp.TargetField)
	}
	return strings.TrimSpace(fp.KeyField)
}

// LookupFetchFieldNames extracts the target field names from `FetchFields` (`[{"field": "x"}]` or string entries).
func (fp FieldProperty) LookupFetchFieldNames() []string {
	if len(fp.FetchFields) == 0 {
		return nil
	}
	out := make([]string, 0, len(fp.FetchFields))
	for _, entry := range fp.FetchFields {
		if f, ok := entry["field"].(string); ok && strings.TrimSpace(f) != "" {
			out = append(out, strings.TrimSpace(f))
		}
	}
	return out
}

// parseFlexibleLookupFetchFields parses `fetch_fields` on a `type: "lookup"` runtime field,
// accepting either an array of objects (`[{"field": "name", "format": "..."}]`) or an array of strings (`["name", "ip"]`).
func parseFlexibleLookupFetchFields(raw json.RawMessage) ([]map[string]any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] != '[' {
		return nil, fmt.Errorf("mapper_parsing_exception: [fetch_fields] must be an array")
	}
	var rawElems []json.RawMessage
	if err := json.Unmarshal(trimmed, &rawElems); err != nil {
		return nil, fmt.Errorf("mapper_parsing_exception: invalid [fetch_fields] array: %w", err)
	}
	out := make([]map[string]any, 0, len(rawElems))
	for _, elem := range rawElems {
		et := bytes.TrimSpace(elem)
		if len(et) == 0 || bytes.Equal(et, []byte("null")) {
			return nil, fmt.Errorf("mapper_parsing_exception: [fetch_fields] entry cannot be null")
		}
		if et[0] == '"' {
			var s string
			if err := json.Unmarshal(et, &s); err != nil {
				return nil, fmt.Errorf("mapper_parsing_exception: invalid [fetch_fields] string entry: %w", err)
			}
			if strings.TrimSpace(s) == "" {
				return nil, fmt.Errorf("mapper_parsing_exception: [fetch_fields] field name cannot be empty")
			}
			out = append(out, map[string]any{"field": s})
			continue
		}
		if et[0] == '{' {
			dec := json.NewDecoder(bytes.NewReader(et))
			dec.UseNumber()
			var obj map[string]any
			if err := dec.Decode(&obj); err != nil {
				return nil, fmt.Errorf("mapper_parsing_exception: invalid [fetch_fields] object entry: %w", err)
			}
			fStr, _ := obj["field"].(string)
			if strings.TrimSpace(fStr) == "" {
				return nil, fmt.Errorf("mapper_parsing_exception: [fetch_fields] object requires non-empty [field]")
			}
			out = append(out, obj)
			continue
		}
		return nil, fmt.Errorf("mapper_parsing_exception: [fetch_fields] elements must be strings or objects")
	}
	return out, nil
}

// parseFlexibleHighlightFields parses `highlight.fields` accepting either a JSON object `{"text": {...}}`
// or an ordered JSON array of single-entry maps `[{"f1": {...}}, {"f2": {...}}]` (`30_ngram_highligthing.yml`).
func parseFlexibleHighlightFields(raw json.RawMessage) (map[string]any, []string, error) {
	ft := bytes.TrimSpace(raw)
	if len(ft) == 0 || bytes.Equal(ft, []byte("null")) {
		return nil, nil, nil
	}
	decodeOneField := func(fname string, fRaw json.RawMessage) (any, error) {
		if strings.TrimSpace(fname) == "" {
			return nil, fmt.Errorf("parsing_exception: [highlight] field name cannot be empty")
		}
		var hfs HighlightFieldSpec
		if err := json.Unmarshal(fRaw, &hfs); err != nil {
			return nil, err
		}
		var val any
		if err := json.Unmarshal(fRaw, &val); err != nil {
			return nil, err
		}
		return val, nil
	}

	if ft[0] == '{' {
		dec := json.NewDecoder(bytes.NewReader(ft))
		tok, err := dec.Token()
		if err != nil || tok != json.Delim('{') {
			return nil, nil, fmt.Errorf("parsing_exception: [highlight] [fields] must be an object or array")
		}
		fieldsMap := make(map[string]any)
		var ordered []string
		seen := make(map[string]bool)
		for dec.More() {
			kTok, err := dec.Token()
			if err != nil {
				return nil, nil, err
			}
			fname, ok := kTok.(string)
			if !ok {
				return nil, nil, fmt.Errorf("parsing_exception: [highlight] invalid field key")
			}
			var fRaw json.RawMessage
			if err := dec.Decode(&fRaw); err != nil {
				return nil, nil, err
			}
			val, err := decodeOneField(fname, fRaw)
			if err != nil {
				return nil, nil, err
			}
			fieldsMap[fname] = val
			if !seen[fname] {
				seen[fname] = true
				ordered = append(ordered, fname)
			}
		}
		if _, err := dec.Token(); err != nil {
			return nil, nil, err
		}
		return fieldsMap, ordered, nil
	}

	if ft[0] == '[' {
		var rawElems []json.RawMessage
		if err := json.Unmarshal(ft, &rawElems); err != nil {
			return nil, nil, fmt.Errorf("parsing_exception: [highlight] [fields] invalid array: %w", err)
		}
		fieldsMap := make(map[string]any, len(rawElems))
		ordered := make([]string, 0, len(rawElems))
		seen := make(map[string]bool, len(rawElems))
		for _, elem := range rawElems {
			et := bytes.TrimSpace(elem)
			if len(et) == 0 || et[0] != '{' {
				return nil, nil, fmt.Errorf("parsing_exception: [highlight] [fields] array elements must be objects")
			}
			var singleMap map[string]json.RawMessage
			if err := json.Unmarshal(et, &singleMap); err != nil {
				return nil, nil, fmt.Errorf("parsing_exception: [highlight] [fields] invalid array element: %w", err)
			}
			if len(singleMap) != 1 {
				return nil, nil, fmt.Errorf("parsing_exception: [highlight] [fields] array elements must contain a single field definition")
			}
			for fname, fRaw := range singleMap {
				val, err := decodeOneField(fname, fRaw)
				if err != nil {
					return nil, nil, err
				}
				fieldsMap[fname] = val
				if !seen[fname] {
					seen[fname] = true
					ordered = append(ordered, fname)
				}
			}
		}
		return fieldsMap, ordered, nil
	}

	return nil, nil, fmt.Errorf("parsing_exception: [highlight] [fields] must be an object or array")
}
