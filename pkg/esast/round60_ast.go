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
	"strings"
	"unicode/utf8"
)

func parseFlexibleScalarIDString(raw any, ctxName string) (string, error) {
	if isNonScalarOrNullValue(raw) {
		return "", fmt.Errorf("parsing_exception: %s must be a scalar value", ctxName)
	}
	return formatFlexibleScalarString(raw), nil
}

func parseFlexibleScalarIDSlice(raw any, ctxName string) ([]string, error) {
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, elem := range v {
			s, err := parseFlexibleScalarIDString(elem, ctxName)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("parsing_exception: %s must be an array", ctxName)
	}
}

// MGetDocSpec models an individual document selector in `/_mget` `docs`.
type MGetDocSpec struct {
	Index        string             `json:"_index,omitempty"`
	Type         string             `json:"_type,omitempty"`
	ID           string             `json:"_id"`
	HasID        bool               `json:"-"`
	Routing      string             `json:"routing,omitempty"`
	Source       *SourceFilter      `json:"_source,omitempty"`
	StoredFields any                `json:"stored_fields,omitempty"`
	Fields       []FieldRequestSpec `json:"fields,omitempty"`
	Version      *int64             `json:"version,omitempty"`
	VersionType  string             `json:"version_type,omitempty"`
}

func (d *MGetDocSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return fmt.Errorf("parsing_exception: [mget] doc item must be an object: %w", err)
	}
	var raw struct {
		Index             string             `json:"_index"`
		AltIndex          string             `json:"index"`
		Type              string             `json:"_type"`
		AltType           string             `json:"type"`
		ID                any                `json:"_id"`
		AltID             any                `json:"id"`
		Routing           any                `json:"routing"`
		UnderscoreRouting any                `json:"_routing"`
		Source            *SourceFilter      `json:"_source"`
		StoredFields      any                `json:"stored_fields"`
		Fields            []FieldRequestSpec `json:"fields"`
		Version           *int64             `json:"version"`
		UnderscoreVersion *int64             `json:"_version"`
		VersionType       string             `json:"version_type"`
		UnderscoreVerType string             `json:"_version_type"`
	}
	if err := unmarshalPreservingLargeInts(trimmed, &raw); err != nil {
		return err
	}
	d.Index = raw.Index
	if d.Index == "" {
		d.Index = raw.AltIndex
	}
	d.Type = raw.Type
	if d.Type == "" {
		d.Type = raw.AltType
	}
	if _, ok := rawMap["_id"]; ok && raw.ID != nil {
		s, err := parseFlexibleScalarIDString(raw.ID, "[mget] [_id]")
		if err != nil {
			return err
		}
		d.ID = s
		d.HasID = true
	} else if _, ok := rawMap["id"]; ok && raw.AltID != nil {
		s, err := parseFlexibleScalarIDString(raw.AltID, "[mget] [id]")
		if err != nil {
			return err
		}
		d.ID = s
		d.HasID = true
	}
	if raw.Routing != nil {
		s, err := parseFlexibleScalarIDString(raw.Routing, "[mget] [routing]")
		if err != nil {
			return err
		}
		d.Routing = s
	} else if raw.UnderscoreRouting != nil {
		s, err := parseFlexibleScalarIDString(raw.UnderscoreRouting, "[mget] [_routing]")
		if err != nil {
			return err
		}
		d.Routing = s
	}
	d.Source = raw.Source
	d.StoredFields = raw.StoredFields
	d.Fields = raw.Fields
	d.Version = raw.Version
	if d.Version == nil {
		d.Version = raw.UnderscoreVersion
	}
	d.VersionType = raw.VersionType
	if d.VersionType == "" {
		d.VersionType = raw.UnderscoreVerType
	}
	return nil
}

// MGetRequest models an Elasticsearch `/_mget` request body.
type MGetRequest struct {
	Docs         []MGetDocSpec      `json:"docs,omitempty"`
	IDs          []string           `json:"ids,omitempty"`
	Source       *SourceFilter      `json:"_source,omitempty"`
	StoredFields any                `json:"stored_fields,omitempty"`
	Fields       []FieldRequestSpec `json:"fields,omitempty"`
	Routing      string             `json:"routing,omitempty"`
	Preference   string             `json:"preference,omitempty"`
	Realtime     *bool              `json:"realtime,omitempty"`
	Refresh      any                `json:"refresh,omitempty"`
}

func (r *MGetRequest) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var raw struct {
		Docs              []MGetDocSpec      `json:"docs"`
		IDs               any                `json:"ids"`
		Source            *SourceFilter      `json:"_source"`
		StoredFields      any                `json:"stored_fields"`
		Fields            []FieldRequestSpec `json:"fields"`
		Routing           any                `json:"routing"`
		UnderscoreRouting any                `json:"_routing"`
		Preference        string             `json:"preference"`
		Realtime          any                `json:"realtime"`
		Refresh           any                `json:"refresh"`
	}
	if err := unmarshalPreservingLargeInts(trimmed, &raw); err != nil {
		return err
	}
	r.Docs = raw.Docs
	if raw.IDs != nil {
		ids, err := parseFlexibleScalarIDSlice(raw.IDs, "[mget] [ids]")
		if err != nil {
			return err
		}
		r.IDs = ids
	}
	r.Source = raw.Source
	r.StoredFields = raw.StoredFields
	r.Fields = raw.Fields
	if raw.Routing != nil {
		s, err := parseFlexibleScalarIDString(raw.Routing, "[mget] [routing]")
		if err != nil {
			return err
		}
		r.Routing = s
	} else if raw.UnderscoreRouting != nil {
		s, err := parseFlexibleScalarIDString(raw.UnderscoreRouting, "[mget] [_routing]")
		if err != nil {
			return err
		}
		r.Routing = s
	}
	r.Preference = raw.Preference
	if raw.Realtime != nil {
		b, err := parseFlexibleBool(raw.Realtime)
		if err != nil {
			return err
		}
		r.Realtime = &b
	}
	r.Refresh = raw.Refresh
	return nil
}

// MLTItem models a single `like` or `unlike` item (text or document selector) in `more_like_this`.
type MLTItem struct {
	Text             string            `json:"-"`
	IsText           bool              `json:"-"`
	Index            string            `json:"_index,omitempty"`
	Type             string            `json:"_type,omitempty"`
	ID               string            `json:"_id,omitempty"`
	Routing          string            `json:"routing,omitempty"`
	Doc              map[string]any    `json:"doc,omitempty"`
	Fields           []string          `json:"fields,omitempty"`
	PerFieldAnalyzer map[string]string `json:"per_field_analyzer,omitempty"`
}

func (item *MLTItem) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("parsing_exception: [more_like_this] item cannot be null")
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("parsing_exception: [more_like_this] item text cannot be empty")
		}
		*item = MLTItem{Text: s, IsText: true}
		return nil
	}
	if trimmed[0] != '{' {
		return fmt.Errorf("parsing_exception: [more_like_this] item must be a string or document object")
	}
	var m map[string]any
	if err := unmarshalPreservingLargeInts(trimmed, &m); err != nil {
		return err
	}
	if err := validateMoreLikeThisDocMap(m, "like"); err != nil {
		return err
	}
	var parsed MLTItem
	if idx, ok := m["_index"].(string); ok {
		parsed.Index = idx
	}
	if typ, ok := m["_type"].(string); ok {
		parsed.Type = typ
	}
	if id, ok := m["_id"].(string); ok {
		parsed.ID = id
	}
	if r, ok := m["routing"].(string); ok && r != "" {
		parsed.Routing = r
	} else if ur, ok := m["_routing"].(string); ok {
		parsed.Routing = ur
	}
	if doc, ok := m["doc"].(map[string]any); ok {
		parsed.Doc = doc
	} else if src, ok := m["_source"].(map[string]any); ok {
		parsed.Doc = src
	}
	if rawFields, ok := m["fields"]; ok && rawFields != nil {
		fs, err := parseFlexibleStringSlice(rawFields)
		if err != nil {
			return err
		}
		parsed.Fields = fs
	}
	if pfa, ok := m["per_field_analyzer"].(map[string]any); ok {
		parsed.PerFieldAnalyzer = make(map[string]string, len(pfa))
		for k, v := range pfa {
			parsed.PerFieldAnalyzer[k] = formatFlexibleScalarString(v)
		}
	}
	*item = parsed
	return nil
}

func unmarshalBulkActionMeta(m *BulkActionMeta, data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return fmt.Errorf("invalid bulk action metadata: %w", err)
	}
	var raw struct {
		Index             string        `json:"_index"`
		AltIndex          string        `json:"index"`
		ID                any           `json:"_id"`
		AltID             any           `json:"id"`
		OpType            string        `json:"op_type"`
		AltOpType         string        `json:"_op_type"`
		Pipeline          string        `json:"pipeline"`
		Routing           any           `json:"routing"`
		UnderscoreRouting any           `json:"_routing"`
		IfSeqNo           *int64        `json:"if_seq_no"`
		UnderscoreIfSeqNo *int64        `json:"_if_seq_no"`
		IfPrimaryTerm     *int64        `json:"if_primary_term"`
		UnderscorePrimTrm *int64        `json:"_if_primary_term"`
		Version           *int64        `json:"version"`
		UnderscoreVersion *int64        `json:"_version"`
		VersionType       string        `json:"version_type"`
		UnderscoreVerType string        `json:"_version_type"`
		RetryOnConflict   *int          `json:"retry_on_conflict"`
		UnderscoreRetry   *int          `json:"_retry_on_conflict"`
		RequireAlias      any           `json:"require_alias"`
		DocAsUpsert       any           `json:"doc_as_upsert"`
		DetectNoop        any           `json:"detect_noop"`
		SourceFilter      *SourceFilter `json:"_source"`
		SourceIncludes    any           `json:"_source_includes"`
		SourceExcludes    any           `json:"_source_excludes"`
	}
	if err := unmarshalPreservingLargeInts(trimmed, &raw); err != nil {
		return err
	}
	var out BulkActionMeta
	out.Index = raw.Index
	if out.Index == "" {
		out.Index = raw.AltIndex
	}
	if rawIDBytes, hasUnderscoreID := rawMap["_id"]; hasUnderscoreID {
		idTrim := bytes.TrimSpace(rawIDBytes)
		if !bytes.Equal(idTrim, []byte("null")) {
			out.HasID = true
			idStr, err := parseFlexibleScalarIDString(raw.ID, "[bulk] [_id]")
			if err != nil {
				return err
			}
			out.ID = idStr
			if out.ID == "" {
				return fmt.Errorf("illegal_argument_exception: if _id is specified it must not be empty")
			}
		}
	} else if rawAltIDBytes, hasPlainID := rawMap["id"]; hasPlainID {
		idTrim := bytes.TrimSpace(rawAltIDBytes)
		if !bytes.Equal(idTrim, []byte("null")) {
			out.HasID = true
			idStr, err := parseFlexibleScalarIDString(raw.AltID, "[bulk] [id]")
			if err != nil {
				return err
			}
			out.ID = idStr
			if out.ID == "" {
				return fmt.Errorf("illegal_argument_exception: if _id is specified it must not be empty")
			}
		}
	}
	out.OpType = raw.OpType
	if out.OpType == "" {
		out.OpType = raw.AltOpType
	}
	out.Pipeline = raw.Pipeline
	if raw.Routing != nil {
		s, err := parseFlexibleScalarIDString(raw.Routing, "[bulk] [routing]")
		if err != nil {
			return err
		}
		out.Routing = s
	}
	if raw.UnderscoreRouting != nil {
		s, err := parseFlexibleScalarIDString(raw.UnderscoreRouting, "[bulk] [_routing]")
		if err != nil {
			return err
		}
		out.UnderscoreRouting = s
	}
	out.IfSeqNo = raw.IfSeqNo
	out.UnderscoreIfSeqNo = raw.UnderscoreIfSeqNo
	out.IfPrimaryTerm = raw.IfPrimaryTerm
	out.UnderscorePrimTrm = raw.UnderscorePrimTrm
	out.Version = raw.Version
	out.UnderscoreVersion = raw.UnderscoreVersion
	out.VersionType = raw.VersionType
	out.UnderscoreVerType = raw.UnderscoreVerType
	out.RetryOnConflict = raw.RetryOnConflict
	out.UnderscoreRetry = raw.UnderscoreRetry
	out.RequireAlias = raw.RequireAlias
	out.DocAsUpsert = raw.DocAsUpsert
	out.DetectNoop = raw.DetectNoop
	out.SourceFilter = raw.SourceFilter
	out.SourceIncludes = raw.SourceIncludes
	out.SourceExcludes = raw.SourceExcludes
	*m = out
	return nil
}

func parseStringOrStringArray(raw json.RawMessage, fieldName string) ([]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
	if trimmed[0] == '[' {
		var arr []string
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("parsing_exception: [%s] must be a string or array of strings: %w", fieldName, err)
		}
		return arr, nil
	}
	return nil, fmt.Errorf("parsing_exception: [%s] must be a string or array of strings", fieldName)
}

func unmarshalIndexTemplateRequest(t *IndexTemplateRequest, data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var raw struct {
		IndexPatterns   json.RawMessage           `json:"index_patterns"`
		Patterns        json.RawMessage           `json:"patterns"`
		Priority        *int                      `json:"priority"`
		Order           *int                      `json:"order"`
		Version         *int                      `json:"version"`
		ComposedOf      []string                  `json:"composed_of"`
		Template        json.RawMessage           `json:"template"`
		Mappings        *MappingSpec              `json:"mappings"`
		Settings        map[string]any            `json:"settings"`
		Aliases         map[string]map[string]any `json:"aliases"`
		Meta            map[string]any            `json:"_meta"`
		DataStream      map[string]any            `json:"data_stream"`
		AllowAutoCreate *bool                     `json:"allow_auto_create"`
	}
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		return err
	}
	idxPats, err := parseStringOrStringArray(raw.IndexPatterns, "index_patterns")
	if err != nil {
		return err
	}
	pats, err := parseStringOrStringArray(raw.Patterns, "patterns")
	if err != nil {
		return err
	}
	var tmplObj *IndexCreateRequest
	legacyFlag := false
	if len(bytes.TrimSpace(raw.Template)) > 0 && !bytes.Equal(bytes.TrimSpace(raw.Template), []byte("null")) {
		tTrim := bytes.TrimSpace(raw.Template)
		if tTrim[0] == '"' {
			var legacyPat string
			if err := json.Unmarshal(tTrim, &legacyPat); err != nil {
				return err
			}
			if len(idxPats) == 0 {
				idxPats = []string{legacyPat}
			}
			legacyFlag = true
		} else {
			var icr IndexCreateRequest
			if err := json.Unmarshal(tTrim, &icr); err != nil {
				return err
			}
			tmplObj = &icr
		}
	}
	*t = IndexTemplateRequest{
		IndexPatterns:   idxPats,
		Patterns:        pats,
		Priority:        raw.Priority,
		Order:           raw.Order,
		Version:         raw.Version,
		ComposedOf:      raw.ComposedOf,
		Template:        tmplObj,
		Mappings:        raw.Mappings,
		Settings:        raw.Settings,
		Aliases:         raw.Aliases,
		Meta:            raw.Meta,
		DataStream:      raw.DataStream,
		AllowAutoCreate: raw.AllowAutoCreate,
		Legacy:          legacyFlag,
	}
	return nil
}

// ScriptSpec models an Elasticsearch script definition (either string shorthand or object).
type ScriptSpec struct {
	Source  string            `json:"source,omitempty"`
	ID      string            `json:"id,omitempty"`
	Lang    string            `json:"lang,omitempty"`
	Params  map[string]any    `json:"params,omitempty"`
	Options map[string]string `json:"options,omitempty"`
}

func (s *ScriptSpec) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	if trimmed[0] == '"' {
		var src string
		if err := json.Unmarshal(trimmed, &src); err != nil {
			return err
		}
		if strings.TrimSpace(src) == "" {
			return fmt.Errorf("parsing_exception: [script] source cannot be empty")
		}
		*s = ScriptSpec{
			Source: src,
			Lang:   "painless",
		}
		return nil
	}
	if trimmed[0] != '{' {
		return fmt.Errorf("parsing_exception: [script] must be a string or object")
	}
	var rawAny map[string]any
	if err := unmarshalPreservingLargeInts(trimmed, &rawAny); err != nil {
		return err
	}
	if err := validateScriptValue(rawAny); err != nil {
		return err
	}
	var out ScriptSpec
	if src, ok := rawAny["source"].(string); ok && src != "" {
		out.Source = src
	} else if inl, ok := rawAny["inline"].(string); ok && inl != "" {
		out.Source = inl
	}
	if id, ok := rawAny["id"].(string); ok {
		out.ID = id
	}
	if lang, ok := rawAny["lang"].(string); ok && strings.TrimSpace(lang) != "" {
		out.Lang = strings.TrimSpace(lang)
	} else {
		out.Lang = "painless"
	}
	if params, ok := rawAny["params"].(map[string]any); ok {
		out.Params = params
	}
	if opts, ok := rawAny["options"].(map[string]any); ok {
		out.Options = make(map[string]string, len(opts))
		for k, v := range opts {
			out.Options[k] = formatFlexibleScalarString(v)
		}
	}
	*s = out
	return nil
}

// ParseScriptSpec converts a string, map[string]any, ScriptSpec, or *ScriptSpec into a *ScriptSpec.
func ParseScriptSpec(v any) (*ScriptSpec, error) {
	switch sv := v.(type) {
	case nil:
		return nil, nil
	case *ScriptSpec:
		return sv, nil
	case ScriptSpec:
		cp := sv
		return &cp, nil
	case string:
		if strings.TrimSpace(sv) == "" {
			return nil, fmt.Errorf("parsing_exception: [script] source cannot be empty")
		}
		return &ScriptSpec{Source: sv, Lang: "painless"}, nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		var out ScriptSpec
		if err := json.Unmarshal(b, &out); err != nil {
			return nil, err
		}
		return &out, nil
	}
}

// TDigestConfig models the `tdigest` parameter block on `percentiles` and `percentile_ranks`.
type TDigestConfig struct {
	Compression   *float64 `json:"compression,omitempty"`
	ExecutionHint string   `json:"execution_hint,omitempty"`
}

// HDRConfig models the `hdr` parameter block on `percentiles` and `percentile_ranks`.
type HDRConfig struct {
	NumberOfSignificantValueDigits *int `json:"number_of_significant_value_digits,omitempty"`
}

// EffectiveSignificantDigits returns the configured HdrHistogram significant digits (default 3).
func (h *HDRConfig) EffectiveSignificantDigits() int {
	if h == nil || h.NumberOfSignificantValueDigits == nil {
		return 3
	}
	return *h.NumberOfSignificantValueDigits
}

// MatchBoolPrefixSpec models a `match_bool_prefix` field query clause, rejecting unsupported parameters
// such as `slop` and `cutoff_frequency`.
type MatchBoolPrefixSpec struct {
	PhraseEntry
}

func validateMatchBoolPrefixFieldClause(rawClause json.RawMessage) error {
	trimmed := bytes.TrimSpace(rawClause)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var clauseMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &clauseMap); err != nil {
		return err
	}
	for k := range clauseMap {
		switch k {
		case "query", "analyzer", "operator", "minimum_should_match", "zero_terms_query",
			"fuzziness", "prefix_length", "max_expansions", "fuzzy_transpositions",
			"fuzzy_rewrite", "lenient", "boost", "_name":
		default:
			return fmt.Errorf("parsing_exception: [match_bool_prefix] query does not support [%s]", k)
		}
	}
	return nil
}

func validateMatchBoolPrefixRaw(rawMBP json.RawMessage) error {
	trimmed := bytes.TrimSpace(rawMBP)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var fieldMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &fieldMap); err != nil {
		return fmt.Errorf("parsing_exception: [match_bool_prefix] must be an object: %w", err)
	}
	for k, v := range fieldMap {
		if k == "_name" || k == "boost" {
			continue
		}
		if err := validateMatchBoolPrefixFieldClause(v); err != nil {
			return err
		}
	}
	return nil
}

func (mbp *MatchBoolPrefixSpec) UnmarshalJSON(data []byte) error {
	if err := validateMatchBoolPrefixFieldClause(data); err != nil {
		return err
	}
	return json.Unmarshal(data, &mbp.PhraseEntry)
}

// CompletionContextDef models an index-time context definition on a `completion` field mapping.
type CompletionContextDef struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Path      string `json:"path,omitempty"`
	Precision any    `json:"precision,omitempty"`
	Default   any    `json:"default,omitempty"`
}

func (c *CompletionContextDef) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return fmt.Errorf("mapper_parsing_exception: [completion.contexts] entry must be an object: %w", err)
	}
	for k := range rawMap {
		switch k {
		case "name", "type", "path", "precision", "default":
		default:
			return fmt.Errorf("mapper_parsing_exception: unknown parameter [%s] in completion context", k)
		}
	}
	type plain CompletionContextDef
	var p plain
	if err := json.Unmarshal(trimmed, &p); err != nil {
		return err
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("mapper_parsing_exception: completion context [name] is required")
	}
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "category", "geo":
		p.Type = strings.ToLower(strings.TrimSpace(p.Type))
	default:
		return fmt.Errorf("mapper_parsing_exception: unsupported completion context type [%s]; must be [category] or [geo]", p.Type)
	}
	*c = CompletionContextDef(p)
	return nil
}

// CompletionQueryContext models a query-time context filter entry on a `completion` suggester.
type CompletionQueryContext struct {
	Context    any     `json:"context"`
	Boost      float64 `json:"boost,omitempty"`
	Prefix     bool    `json:"prefix,omitempty"`
	Precision  any     `json:"precision,omitempty"`
	Neighbours []any   `json:"neighbours,omitempty"`
}

func (qc *CompletionQueryContext) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("parsing_exception: [completion.contexts] context item cannot be null")
	}
	if trimmed[0] != '{' {
		var val any
		if err := unmarshalPreservingLargeInts(trimmed, &val); err != nil {
			return err
		}
		*qc = CompletionQueryContext{Context: val, Boost: 1.0}
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	if _, hasContextKey := rawMap["context"]; !hasContextKey {
		// Direct geo_point object shorthand, e.g. {"lat": 43.662, "lon": -79.380}
		if _, hasLat := rawMap["lat"]; hasLat {
			var geoObj map[string]any
			if err := json.Unmarshal(trimmed, &geoObj); err != nil {
				return err
			}
			*qc = CompletionQueryContext{Context: geoObj, Boost: 1.0}
			return nil
		}
		return fmt.Errorf("parsing_exception: [completion.contexts] context object requires [context]")
	}
	for k := range rawMap {
		switch k {
		case "context", "boost", "prefix", "precision", "neighbours", "neighbors":
		default:
			return fmt.Errorf("parsing_exception: [completion.contexts] unknown field [%s]", k)
		}
	}
	var raw struct {
		Context    any      `json:"context"`
		Boost      *float64 `json:"boost"`
		Prefix     any      `json:"prefix"`
		Precision  any      `json:"precision"`
		Neighbours []any    `json:"neighbours"`
		Neighbors  []any    `json:"neighbors"`
	}
	if err := unmarshalPreservingLargeInts(trimmed, &raw); err != nil {
		return err
	}
	if raw.Context == nil {
		return fmt.Errorf("parsing_exception: [completion.contexts] [context] cannot be null")
	}
	boost := 1.0
	if raw.Boost != nil {
		if *raw.Boost < 0 || math.IsNaN(*raw.Boost) || math.IsInf(*raw.Boost, 0) {
			return fmt.Errorf("illegal_argument_exception: [completion.contexts] [boost] must be >= 0")
		}
		boost = *raw.Boost
	}
	prefix := false
	if raw.Prefix != nil {
		b, err := parseFlexibleBool(raw.Prefix)
		if err != nil {
			return err
		}
		prefix = b
	}
	nb := raw.Neighbours
	if len(nb) == 0 {
		nb = raw.Neighbors
	}
	*qc = CompletionQueryContext{
		Context:    raw.Context,
		Boost:      boost,
		Prefix:     prefix,
		Precision:  raw.Precision,
		Neighbours: nb,
	}
	return nil
}

func parseCompletionQueryContextsMap(raw json.RawMessage) (map[string][]CompletionQueryContext, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var rawByName map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawByName); err != nil {
		return nil, fmt.Errorf("parsing_exception: [completion] [contexts] must be an object: %w", err)
	}
	out := make(map[string][]CompletionQueryContext, len(rawByName))
	for name, rawVal := range rawByName {
		vt := bytes.TrimSpace(rawVal)
		if len(vt) == 0 || bytes.Equal(vt, []byte("null")) {
			return nil, fmt.Errorf("parsing_exception: [completion] context [%s] cannot be null", name)
		}
		if vt[0] == '[' {
			var list []CompletionQueryContext
			if err := json.Unmarshal(vt, &list); err != nil {
				return nil, err
			}
			out[name] = list
		} else {
			var single CompletionQueryContext
			if err := json.Unmarshal(vt, &single); err != nil {
				return nil, err
			}
			out[name] = []CompletionQueryContext{single}
		}
	}
	return out, nil
}

// CompletionSuggester provides a strongly-typed model with `*bool` `SkipDuplicates` and `Contexts`.
type CompletionSuggester struct {
	Field          string                              `json:"field"`
	Size           int                                 `json:"size,omitempty"`
	SkipDuplicates *bool                               `json:"skip_duplicates,omitempty"`
	Fuzzy          map[string]any                      `json:"fuzzy,omitempty"`
	Regex          map[string]any                      `json:"regex,omitempty"`
	Contexts       map[string][]CompletionQueryContext `json:"contexts,omitempty"`
	Analyzer       string                              `json:"analyzer,omitempty"`
	Prefix         string                              `json:"prefix,omitempty"`
}

func (cs *CompletionSuggester) UnmarshalJSON(data []byte) error {
	var spec CompletionSuggestSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return err
	}
	*cs = CompletionSuggester{
		Field:          spec.Field,
		Size:           spec.Size,
		SkipDuplicates: spec.SkipDuplicatesPtr,
		Fuzzy:          spec.Fuzzy,
		Regex:          spec.Regex,
		Contexts:       spec.Contexts,
		Analyzer:       spec.Analyzer,
		Prefix:         spec.Prefix,
	}
	return nil
}

// ValidateAndNormalizeFieldMeta validates ES field-level `meta` rules:
// at most 5 entries, non-empty key length <= 20 chars, scalar non-null value length <= 50 chars.
func ValidateAndNormalizeFieldMeta(raw json.RawMessage) (map[string]string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] != '{' {
		return nil, fmt.Errorf("mapper_parsing_exception: [meta] must be an object")
	}
	var rawMap map[string]any
	if err := unmarshalPreservingLargeInts(trimmed, &rawMap); err != nil {
		return nil, fmt.Errorf("mapper_parsing_exception: [meta] must be an object: %w", err)
	}
	return ValidateFieldMetaMap(rawMap)
}

// ValidateFieldMetaMap validates an already-parsed field `meta` map or map[string]string.
func ValidateFieldMetaMap(rawMap map[string]any) (map[string]string, error) {
	if len(rawMap) == 0 {
		return nil, nil
	}
	if len(rawMap) > 5 {
		return nil, fmt.Errorf("illegal_argument_exception: [meta] cannot have more than [5] entries, got [%d]", len(rawMap))
	}
	out := make(map[string]string, len(rawMap))
	for k, v := range rawMap {
		kLen := utf8.RuneCountInString(k)
		if kLen == 0 || kLen > 20 {
			return nil, fmt.Errorf("illegal_argument_exception: [meta] key [%s] length [%d] must be between 1 and 20", k, kLen)
		}
		if isNonScalarOrNullValue(v) {
			return nil, fmt.Errorf("illegal_argument_exception: [meta] value for key [%s] must be a non-null string", k)
		}
		valStr := formatFlexibleScalarString(v)
		vLen := utf8.RuneCountInString(valStr)
		if vLen > 50 {
			return nil, fmt.Errorf("illegal_argument_exception: [meta] value for key [%s] length [%d] cannot exceed 50", k, vLen)
		}
		out[k] = valStr
	}
	return out, nil
}

// ValidateFieldMetaStringMap validates an already-typed `map[string]string` field `meta` block.
func ValidateFieldMetaStringMap(m map[string]string) error {
	if len(m) == 0 {
		return nil
	}
	if len(m) > 5 {
		return fmt.Errorf("illegal_argument_exception: [meta] cannot have more than [5] entries, got [%d]", len(m))
	}
	for k, v := range m {
		kLen := utf8.RuneCountInString(k)
		if kLen == 0 || kLen > 20 {
			return fmt.Errorf("illegal_argument_exception: [meta] key [%s] length [%d] must be between 1 and 20", k, kLen)
		}
		vLen := utf8.RuneCountInString(v)
		if vLen > 50 {
			return fmt.Errorf("illegal_argument_exception: [meta] value for key [%s] length [%d] cannot exceed 50", k, vLen)
		}
	}
	return nil
}

// UnmarshalFieldPropertyStrict decodes a FieldProperty with DisallowUnknownFields enabled.
func UnmarshalFieldPropertyStrict(data []byte) (FieldProperty, error) {
	var fp FieldProperty
	if err := unmarshalFieldPropertyRound60Internal(&fp, data, true); err != nil {
		return FieldProperty{}, err
	}
	return fp, nil
}

func unmarshalFieldPropertyRound60(fp *FieldProperty, data []byte) error {
	return unmarshalFieldPropertyRound60Internal(fp, data, false)
}

func unmarshalFieldPropertyRound60Internal(fp *FieldProperty, data []byte, strict bool) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return err
	}
	_, hasDims := rawMap["dims"]
	_, hasDim := rawMap["dimension"]
	var parsedMeta map[string]string
	if rawMeta, hasMeta := rawMap["meta"]; hasMeta {
		m, err := ValidateAndNormalizeFieldMeta(rawMeta)
		if err != nil {
			return err
		}
		parsedMeta = m
		delete(rawMap, "meta")
	}
	var parsedContexts []CompletionContextDef
	if rawCtx, hasCtx := rawMap["contexts"]; hasCtx {
		ct := bytes.TrimSpace(rawCtx)
		if len(ct) > 0 && !bytes.Equal(ct, []byte("null")) {
			if ct[0] == '[' {
				if err := json.Unmarshal(ct, &parsedContexts); err != nil {
					return err
				}
			} else {
				var single CompletionContextDef
				if err := json.Unmarshal(ct, &single); err != nil {
					return err
				}
				parsedContexts = []CompletionContextDef{single}
			}
		}
		delete(rawMap, "contexts")
	}
	cleaned, err := json.Marshal(rawMap)
	if err != nil {
		return err
	}
	type plain FieldProperty
	var p plain
	if strict {
		dec := json.NewDecoder(bytes.NewReader(cleaned))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return err
		}
	} else {
		if err := json.Unmarshal(cleaned, &p); err != nil {
			return err
		}
	}
	if p.OnScriptError != "" {
		normErrMode, err := ValidateOnScriptError(p.OnScriptError)
		if err != nil {
			return err
		}
		p.OnScriptError = normErrMode
	}
	p.Meta = parsedMeta
	p.Contexts = parsedContexts
	p.ExplicitDims = hasDims || hasDim
	*fp = FieldProperty(p)
	return nil
}
