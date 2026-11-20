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

package painless

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// Round 63 F29 (C-12 P1): Post-Expansion Grok Regex Cap & Input Size Guard
// ============================================================================

const (
	// MaxExpandedGrokRegexLen caps the post-expansion RE2 regex length produced by
	// CompileGrokPattern so repeating recursive macros (e.g. %{COMBINEDAPACHELOG})
	// inside a <4 KB pattern cannot expand into a huge regex retained in globalGrokCache.
	MaxExpandedGrokRegexLen = 32768

	// MaxGrokInputBytes caps input string length accepted by Grok and Dissect Extract (1 MiB).
	MaxGrokInputBytes = 1 << 20
)

func truncatePatternForErrRound63(pat string, maxLen int) string {
	if len(pat) <= maxLen {
		return pat
	}
	return pat[:maxLen] + "..."
}

func newGrokExpandedLenErrorRound63(expandedLen int) error {
	return &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: fmt.Sprintf("error compiling grok pattern: expanded regex length [%d] exceeds maximum [%d]", expandedLen, MaxExpandedGrokRegexLen),
	}
}

func newExtractorInputLenErrorRound63(kind string, inputLen int) error {
	return &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: fmt.Sprintf("%s input length [%d] exceeds maximum [%d]", kind, inputLen, MaxGrokInputBytes),
	}
}

// ExtractChecked matches `text` against the compiled Grok pattern while enforcing
// MaxGrokInputBytes (1 MiB), returning an IllegalArgumentException when exceeded.
func (g *GrokExtractor) ExtractChecked(text string) (map[string]any, error) {
	if len(text) > MaxGrokInputBytes {
		return nil, newExtractorInputLenErrorRound63("grok", len(text))
	}
	return g.Extract(text), nil
}

// ExtractChecked matches `text` against the compiled Dissect pattern while enforcing
// MaxGrokInputBytes (1 MiB), returning an IllegalArgumentException when exceeded.
func (d *DissectExtractor) ExtractChecked(text string) (map[string]any, error) {
	if len(text) > MaxGrokInputBytes {
		return nil, newExtractorInputLenErrorRound63("dissect", len(text))
	}
	return d.Extract(text), nil
}

// ============================================================================
// Round 63 F21: Date (`yyyy/MM/dd` dayOfWeekEnum), Version, constant_keyword,
// unsigned_long `asBigInteger`/`asLong`, and `metadata()` Accessor Helpers
// ============================================================================

var reSlashDateLiteralRound63 = regexp.MustCompile(`^\d{4}/\d{2}/\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$`)

func isSlashDateLiteralRound63(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	return reSlashDateLiteralRound63.MatchString(strings.TrimSpace(s))
}

// shouldTryWrapperPropRound63 allows `.value` / `.values` wrapper property resolution on
// expressions starting with `doc.` / `doc?.` when the receiver before the suffix ALREADY
// navigated past `doc.<field>.value` (e.g. `doc.date.value.dayOfWeekEnum.value`).
func shouldTryWrapperPropRound63(rhs, wProp string) bool {
	if wProp != ".value" && wProp != ".values" {
		return true
	}
	if !strings.HasPrefix(rhs, "doc.") && !strings.HasPrefix(rhs, "doc?.") {
		return true
	}
	prefix := rhs[:len(rhs)-len(wProp)]
	return strings.Contains(prefix, ".value.") || strings.Contains(prefix, ".values.") || strings.Contains(prefix, "(")
}

// FormatFloat32DocValue formats an IEEE-754 single-precision float matching JDK Float.toString(float).
func FormatFloat32DocValue(v float32) string {
	return FormatJavaFloat32(v)
}

// VersionVal models Elasticsearch's `Version` wrapper in Painless (`new Version('1.2.3')`,
// `field('ver').get(new Version(”))`).
type VersionVal struct {
	Raw string
}

// NewVersionVal creates a new Painless VersionVal wrapper.
func NewVersionVal(raw string) *VersionVal {
	return &VersionVal{Raw: raw}
}

func (v *VersionVal) String() string {
	if v == nil {
		return "null"
	}
	return v.Raw
}

func (v *VersionVal) MarshalJSON() ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}
	return json.Marshal(v.Raw)
}

// CompareSemverStringsES compares two Elasticsearch `version` field strings according to SemVer 2.0.0 rules.
func CompareSemverStringsES(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	splitBuild := func(s string) (string, string) {
		if idx := strings.IndexByte(s, '+'); idx >= 0 {
			return s[:idx], s[idx+1:]
		}
		return s, ""
	}
	splitPre := func(s string) (string, string, bool) {
		if idx := strings.IndexByte(s, '-'); idx >= 0 {
			return s[:idx], s[idx+1:], true
		}
		return s, "", false
	}
	corePreA, _ := splitBuild(a)
	corePreB, _ := splitBuild(b)
	coreA, preA, hasPreA := splitPre(corePreA)
	coreB, preB, hasPreB := splitPre(corePreB)

	segsA := strings.Split(coreA, ".")
	segsB := strings.Split(coreB, ".")
	isValidDigitsCore := func(segs []string) bool {
		if len(segs) == 0 {
			return false
		}
		for _, sg := range segs {
			if sg == "" {
				return false
			}
			for i := 0; i < len(sg); i++ {
				if sg[i] < '0' || sg[i] > '9' {
					return false
				}
			}
		}
		return true
	}
	validA := isValidDigitsCore(segsA)
	validB := isValidDigitsCore(segsB)
	if validA != validB {
		if validA {
			return -1
		}
		return 1
	}
	if !validA && !validB {
		return strings.Compare(a, b)
	}
	maxCore := len(segsA)
	if len(segsB) > maxCore {
		maxCore = len(segsB)
	}
	for i := 0; i < maxCore; i++ {
		sa, sb := "0", "0"
		if i < len(segsA) {
			sa = segsA[i]
		}
		if i < len(segsB) {
			sb = segsB[i]
		}
		ia, errA := strconv.ParseInt(sa, 10, 64)
		ib, errB := strconv.ParseInt(sb, 10, 64)
		if errA == nil && errB == nil {
			if ia < ib {
				return -1
			}
			if ia > ib {
				return 1
			}
		} else if sa != sb {
			if sa < sb {
				return -1
			}
			return 1
		}
	}
	if hasPreA != hasPreB {
		// Pre-release has lower precedence than normal version (1.0.0-alpha < 1.0.0)
		if hasPreA {
			return -1
		}
		return 1
	}
	if !hasPreA {
		return 0
	}
	pSegsA := strings.Split(preA, ".")
	pSegsB := strings.Split(preB, ".")
	minPre := len(pSegsA)
	if len(pSegsB) < minPre {
		minPre = len(pSegsB)
	}
	for i := 0; i < minPre; i++ {
		pa, pb := pSegsA[i], pSegsB[i]
		ia, errA := strconv.ParseInt(pa, 10, 64)
		ib, errB := strconv.ParseInt(pb, 10, 64)
		switch {
		case errA == nil && errB == nil:
			if ia < ib {
				return -1
			}
			if ia > ib {
				return 1
			}
		case errA == nil && errB != nil:
			// Numeric identifiers always have lower precedence than non-numeric
			return -1
		case errA != nil && errB == nil:
			return 1
		default:
			if pa < pb {
				return -1
			}
			if pa > pb {
				return 1
			}
		}
	}
	if len(pSegsA) < len(pSegsB) {
		return -1
	}
	if len(pSegsA) > len(pSegsB) {
		return 1
	}
	return 0
}

func (v *VersionVal) CompareTo(other any) int64 {
	if v == nil {
		return -1
	}
	otherStr := ""
	switch ov := other.(type) {
	case *VersionVal:
		if ov != nil {
			otherStr = ov.Raw
		}
	case string:
		otherStr = ov
	default:
		otherStr = fmt.Sprintf("%v", other)
	}
	return int64(CompareSemverStringsES(v.Raw, otherStr))
}

func (v *VersionVal) Equals(other any) bool {
	if v == nil {
		return other == nil
	}
	switch ov := other.(type) {
	case *VersionVal:
		return ov != nil && v.Raw == ov.Raw
	case string:
		return v.Raw == ov
	}
	return false
}

// lookupConstantKeywordValueRound63 resolves mapped `constant_keyword` values from
// `__constant_keyword_values` in params or sourceMap even when omitted from `_source`.
func lookupConstantKeywordValueRound63(sourceMap, params map[string]any, fieldPath string) (string, bool) {
	clean := strings.ReplaceAll(fieldPath, "\x00", ".")
	for _, m := range []map[string]any{params, sourceMap} {
		if m == nil {
			continue
		}
		switch cm := m["__constant_keyword_values"].(type) {
		case map[string]string:
			if val, ok := cm[clean]; ok {
				return val, true
			}
		case map[string]any:
			if raw, ok := cm[clean]; ok && raw != nil {
				return fmt.Sprintf("%v", raw), true
			}
		}
	}
	return "", false
}

func coerceToBigIntegerRound63(v any, fieldName string) (*painlessBigInteger, error) {
	if v == nil {
		return nil, nil
	}
	switch tv := v.(type) {
	case *painlessBigInteger:
		return tv, nil
	case uint64:
		return newPainlessBigInteger(new(big.Int).SetUint64(tv)), nil
	case uint:
		return newPainlessBigInteger(new(big.Int).SetUint64(uint64(tv))), nil
	case uint32:
		return newPainlessBigInteger(new(big.Int).SetUint64(uint64(tv))), nil
	case int64:
		return newPainlessBigInteger(big.NewInt(tv)), nil
	case int:
		return newPainlessBigInteger(big.NewInt(int64(tv))), nil
	case int32:
		return newPainlessBigInteger(big.NewInt(int64(tv))), nil
	case json.Number:
		s := strings.TrimSpace(tv.String())
		if bi, ok := new(big.Int).SetString(s, 10); ok {
			return newPainlessBigInteger(bi), nil
		}
	case string:
		s := strings.TrimSpace(tv)
		if bi, ok := new(big.Int).SetString(s, 10); ok {
			return newPainlessBigInteger(bi), nil
		}
	case float64:
		bf := new(big.Float).SetFloat64(tv)
		bi, _ := bf.Int(nil)
		if bi != nil {
			return newPainlessBigInteger(bi), nil
		}
	case float32:
		bf := new(big.Float).SetFloat64(float64(tv))
		bi, _ := bf.Int(nil)
		if bi != nil {
			return newPainlessBigInteger(bi), nil
		}
	}
	if iv, ok := isIntegerValuePainless(v); ok {
		return newPainlessBigInteger(big.NewInt(iv)), nil
	}
	return nil, &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: fmt.Sprintf("cannot parse field [%s] as BigInteger", fieldName),
	}
}

func coerceToLongFieldValRound63(v any, fieldName string) (any, error) {
	if v == nil {
		return nil, nil
	}
	if bi, ok := v.(*painlessBigInteger); ok && bi != nil {
		return bi.longValue(), nil
	}
	if u, ok := v.(uint64); ok {
		return int64(u), nil // #nosec G115 -- ES unsigned_long two's-complement longValue
	}
	if iv, ok := toInt64Painless(v); ok {
		return iv, nil
	}
	return nil, &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: fmt.Sprintf("cannot parse field [%s] as long", fieldName),
	}
}

func isUpdateMetadataContextRound63(sourceMap, params map[string]any) bool {
	for _, m := range []map[string]any{params, sourceMap} {
		if m == nil {
			continue
		}
		if b, ok := m["__is_update_doc"].(bool); ok && b {
			return true
		}
		if b, ok := m["__is_ubq"].(bool); ok && b {
			return true
		}
		if b, ok := m["__upsert_insert_mode"].(bool); ok && b {
			return true
		}
		if b, ok := m["__forbid_metadata_routing"].(bool); ok && b {
			return true
		}
	}
	return false
}

func resolveNowZonedDateTimeRound63(sourceMap, params map[string]any) *ZonedDateTimeVal {
	for _, m := range []map[string]any{params, sourceMap} {
		if m == nil {
			continue
		}
		for _, k := range []string{"_ctx_now", "_now"} {
			if raw, ok := m[k]; ok && raw != nil {
				if z, okZ := parseZonedDateTimeValRound60(raw, false); okZ {
					return z
				}
			}
		}
		if ing, ok := m["_ingest"].(map[string]any); ok && ing != nil {
			if ts, hasTS := ing["timestamp"]; hasTS && ts != nil {
				if z, okZ := parseZonedDateTimeValRound60(ts, false); okZ {
					return z
				}
			}
		}
	}
	budget := getOrInitEvalBudget(params)
	if budget != nil && budget.nowMillis > 0 {
		return &ZonedDateTimeVal{Time: time.UnixMilli(budget.nowMillis).UTC()}
	}
	return &ZonedDateTimeVal{Time: time.Now().UTC()}
}

// ============================================================================
// Round 63 F22: ES 8 Painless Ingest & Update Write `field('path')` API
// ============================================================================

// isWriteFieldsAPIModeRound63 determines whether `field('...')` is operating in ES 8's
// mutable Write Fields API context (Ingest `script` processor, `_update`, `_update_by_query`)
// rather than the read-only Search / Runtime Fields API context.
func isWriteFieldsAPIModeRound63(sourceMap, params map[string]any) bool {
	for _, m := range []map[string]any{params, sourceMap} {
		if m == nil {
			continue
		}
		if b, ok := m["__mutable_fields_api"].(bool); ok {
			return b
		}
		if b, ok := m["__is_update_doc"].(bool); ok && b {
			return true
		}
		if b, ok := m["__is_ubq"].(bool); ok && b {
			return true
		}
		if _, ok := m["_ingest"]; ok {
			return true
		}
		if _, ok := m["_ctx_op"]; ok {
			return true
		}
	}
	// If any Search / Runtime Fields marker is present without explicit mutable markers,
	// keep read-only normalized Fields API semantics.
	searchMarkers := []string{
		"__keep_boolean_dups",
		"__quantize_geo_point",
		"__raw_source",
		"__strict_doc_fields",
		"__strict_doc_mapping",
		"__disabled_doc_values",
		"__disabled_fields_api",
		"__field_types",
		"__field_formats",
		"__flattened_fields",
		"__constant_keyword_values",
	}
	for _, m := range []map[string]any{params, sourceMap} {
		if m == nil {
			continue
		}
		for _, k := range searchMarkers {
			if v, exists := m[k]; exists && v != nil {
				if b, isBool := v.(bool); isBool && !b && (k == "__strict_doc_mapping" || k == "__quantize_geo_point") {
					continue
				}
				return false
			}
		}
	}
	return true
}

func extractWriteFieldValuesRound63(root map[string]any, name string) []any {
	if root == nil {
		return []any{}
	}
	segs := strings.Split(name, ".")
	if !hasPathInMapRound60(root, segs) {
		return []any{}
	}
	raw := resolveParamPath(root, segs)
	cleanLower := strings.ToLower(name)
	if raw != nil && (cleanLower == "binary" || strings.HasSuffix(cleanLower, "_binary")) {
		return normalizeSingleFieldDocValuesWithOptsRound61(raw, "binary", true, true, "", false)
	}
	if s, ok := raw.([]any); ok {
		out := make([]any, len(s))
		copy(out, s)
		return out
	}
	return []any{raw}
}

// Exists reports whether this sub-document still exists in its parent map/slice.
func (fd *FieldDocVal) Exists() bool {
	if fd == nil || fd.Doc == nil {
		return false
	}
	if fd.ParentMap == nil {
		return true
	}
	segs := strings.Split(fd.FieldPath, ".")
	if !hasPathInMapRound60(fd.ParentMap, segs) {
		return false
	}
	raw := resolveParamPath(fd.ParentMap, segs)
	targetPtr := reflect.ValueOf(fd.Doc).Pointer()
	switch tv := raw.(type) {
	case map[string]any:
		return reflect.ValueOf(tv).Pointer() == targetPtr
	case []any:
		for _, el := range tv {
			if em, ok := el.(map[string]any); ok && reflect.ValueOf(em).Pointer() == targetPtr {
				return true
			}
		}
	}
	return false
}

// Remove deletes this sub-document from its parent map or object-list field in `_source`
// (`regionDoc.remove()`, `doc.remove()`, `end.remove()` in ES 8 Write Fields API).
func (fd *FieldDocVal) Remove() bool {
	if fd == nil || fd.Doc == nil || fd.ParentMap == nil || fd.FieldPath == "" {
		return false
	}
	segs := strings.Split(fd.FieldPath, ".")
	if !hasPathInMapRound60(fd.ParentMap, segs) {
		return false
	}
	raw := resolveParamPath(fd.ParentMap, segs)
	targetPtr := reflect.ValueOf(fd.Doc).Pointer()
	switch tv := raw.(type) {
	case map[string]any:
		if reflect.ValueOf(tv).Pointer() == targetPtr {
			removed := deletePathInMapRound60(fd.ParentMap, segs)
			if fd.ParentFV != nil {
				fd.ParentFV.refreshValuesRound60()
			}
			return removed
		}
	case []any:
		for i, el := range tv {
			if em, ok := el.(map[string]any); ok && reflect.ValueOf(em).Pointer() == targetPtr {
				updated := make([]any, 0, len(tv)-1)
				updated = append(updated, tv[:i]...)
				updated = append(updated, tv[i+1:]...)
				setValueAtPath(fd.ParentMap, segs, updated)
				if fd.ParentFV != nil {
					fd.ParentFV.refreshValuesRound60()
				}
				return true
			}
		}
	}
	return false
}
