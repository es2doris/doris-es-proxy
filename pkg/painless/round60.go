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
	"bytes"
	"crypto/sha1" // #nosec G505 -- Community ID v1 specification mandates SHA-1
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// F20: Cyclic-Container Stack Overflow Elimination & Cycle-Safe Helpers
// ============================================================================

// ErrSelfReferencingIterable matches Elasticsearch's IllegalArgumentException
// thrown when serializing or returning a self-referencing Map or List.
var ErrSelfReferencingIterable = errors.New("illegal_argument_exception: Iterable object is self-referencing itself")

type cycleNodeKeyRound60 struct {
	kind byte
	ptr  uintptr
}

func containerNodeKeyRound60(val any) (cycleNodeKeyRound60, bool) {
	if val == nil {
		return cycleNodeKeyRound60{}, false
	}
	switch tv := val.(type) {
	case map[string]any:
		if tv == nil {
			return cycleNodeKeyRound60{}, false
		}
		p := reflect.ValueOf(tv).Pointer()
		if p == 0 {
			return cycleNodeKeyRound60{}, false
		}
		return cycleNodeKeyRound60{kind: 'm', ptr: p}, true
	case []any:
		// Only non-empty slices can have outgoing element edges; empty slices
		// cannot participate in a cycle and may share Go's runtime.zerobase.
		if len(tv) == 0 {
			return cycleNodeKeyRound60{}, false
		}
		p := reflect.ValueOf(tv).Pointer()
		if p == 0 {
			return cycleNodeKeyRound60{}, false
		}
		return cycleNodeKeyRound60{kind: 's', ptr: p}, true
	case *painlessUserObject:
		if tv == nil {
			return cycleNodeKeyRound60{}, false
		}
		p := reflect.ValueOf(tv).Pointer()
		return cycleNodeKeyRound60{kind: 'u', ptr: p}, p != 0
	default:
		rv := reflect.ValueOf(val)
		switch rv.Kind() {
		case reflect.Map:
			if rv.IsNil() {
				return cycleNodeKeyRound60{}, false
			}
			p := rv.Pointer()
			return cycleNodeKeyRound60{kind: 'M', ptr: p}, p != 0
		case reflect.Slice:
			if rv.Len() == 0 {
				return cycleNodeKeyRound60{}, false
			}
			p := rv.Pointer()
			return cycleNodeKeyRound60{kind: 'S', ptr: p}, p != 0
		}
		return cycleNodeKeyRound60{}, false
	}
}

// ValidateAcyclicValue verifies that val contains no cyclic Map/List/Object
// references along any ancestor chain, while permitting shared non-cyclic DAG
// references. Returns an error wrapping ErrSelfReferencingIterable on cycles.
func ValidateAcyclicValue(val any) error {
	inProgress := make(map[cycleNodeKeyRound60]bool)
	return validateAcyclicWalkRound60(val, inProgress, 0)
}

func validateAcyclicWalkRound60(val any, inProgress map[cycleNodeKeyRound60]bool, depth int) error {
	if val == nil || val == painlessEmptyOptional {
		return nil
	}
	if depth > 512 {
		return fmt.Errorf("%w", ErrSelfReferencingIterable)
	}
	if opt, ok := val.(*painlessOptional); ok {
		if opt == nil || !opt.present {
			return nil
		}
		return validateAcyclicWalkRound60(opt.val, inProgress, depth+1)
	}
	key, track := containerNodeKeyRound60(val)
	if track {
		if inProgress[key] {
			return fmt.Errorf("%w", ErrSelfReferencingIterable)
		}
		inProgress[key] = true
		defer delete(inProgress, key)
	}
	switch tv := val.(type) {
	case map[string]any:
		for k, v := range tv {
			if strings.HasPrefix(k, "__") && k != "__raw_source" {
				continue
			}
			if k == "__parent_map" {
				continue
			}
			if err := validateAcyclicWalkRound60(v, inProgress, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, el := range tv {
			if err := validateAcyclicWalkRound60(el, inProgress, depth+1); err != nil {
				return err
			}
		}
	case *painlessUserObject:
		if tv != nil {
			for _, fv := range tv.fields {
				if err := validateAcyclicWalkRound60(fv, inProgress, depth+1); err != nil {
					return err
				}
			}
		}
	default:
		rv := reflect.ValueOf(val)
		switch rv.Kind() {
		case reflect.Map:
			iter := rv.MapRange()
			for iter.Next() {
				if err := validateAcyclicWalkRound60(iter.Value().Interface(), inProgress, depth+1); err != nil {
					return err
				}
			}
		case reflect.Slice:
			if rv.Type().Elem().Kind() == reflect.Uint8 || rv.Type().Elem().Kind() == reflect.Float64 {
				return nil
			}
			for i := 0; i < rv.Len(); i++ {
				if err := validateAcyclicWalkRound60(rv.Index(i).Interface(), inProgress, depth+1); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// CloneValueCycleSafe deep-clones nested maps and slices while detecting
// cyclic container graphs and returning ErrSelfReferencingIterable on cycles.
func CloneValueCycleSafe(val any) (any, error) {
	inProgress := make(map[cycleNodeKeyRound60]bool)
	return cloneValueWalkRound60(val, inProgress, 0)
}

func cloneValueWalkRound60(val any, inProgress map[cycleNodeKeyRound60]bool, depth int) (any, error) {
	if val == nil || val == painlessEmptyOptional {
		return nil, nil
	}
	if depth > 512 {
		return nil, fmt.Errorf("%w", ErrSelfReferencingIterable)
	}
	if opt, ok := val.(*painlessOptional); ok {
		if opt == nil || !opt.present {
			return nil, nil
		}
		return cloneValueWalkRound60(opt.val, inProgress, depth+1)
	}
	key, track := containerNodeKeyRound60(val)
	if track {
		if inProgress[key] {
			return nil, fmt.Errorf("%w", ErrSelfReferencingIterable)
		}
		inProgress[key] = true
		defer delete(inProgress, key)
	}
	switch tv := val.(type) {
	case map[string]any:
		out := make(map[string]any, len(tv))
		for k, v := range tv {
			if isInternalPainlessMapKey(tv, k) {
				continue
			}
			cv, err := cloneValueWalkRound60(v, inProgress, depth+1)
			if err != nil {
				return nil, err
			}
			out[k] = cv
		}
		return out, nil
	case []any:
		out := make([]any, len(tv), max(1, len(tv)))
		for i, el := range tv {
			ce, err := cloneValueWalkRound60(el, inProgress, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = ce
		}
		return out, nil
	case []float64:
		out := make([]float64, len(tv))
		copy(out, tv)
		return out, nil
	case *ZonedDateTimeVal:
		if tv == nil {
			return nil, nil
		}
		cp := *tv
		return &cp, nil
	case *GeoPointVal:
		if tv == nil {
			return nil, nil
		}
		cp := *tv
		return &cp, nil
	case *BytesRefVal:
		if tv == nil {
			return nil, nil
		}
		b := make([]byte, len(tv.Bytes))
		copy(b, tv.Bytes)
		return &BytesRefVal{Bytes: b, Offset: tv.Offset, Length: tv.Length}, nil
	case *ByteBufferVal:
		if tv == nil {
			return nil, nil
		}
		b := make([]byte, len(tv.Bytes))
		copy(b, tv.Bytes)
		return &ByteBufferVal{Bytes: b, Pos: tv.Pos, Lim: tv.Lim, Cap: tv.Cap}, nil
	default:
		return unwrapPainlessInternalValue(val), nil
	}
}

// FormatValueSafe formats any Painless value into a Java-compatible string
// while guarding against cyclic Maps and Lists ("(this Map)" / "(this Collection)").
func FormatValueSafe(val any) string {
	seen := make(map[cycleNodeKeyRound60]bool)
	return formatValueCycleWalkRound60(val, seen, false, 0)
}

func formatValueCycleWalkRound60(v any, seen map[cycleNodeKeyRound60]bool, javaMapBrace bool, depth int) string {
	if v == nil || v == painlessEmptyOptional {
		return "null"
	}
	if depth > 64 {
		return "..."
	}
	switch tv := v.(type) {
	case string:
		return tv
	case *painlessOptional:
		if tv == nil || !tv.present {
			return "Optional.empty"
		}
		return "Optional[" + formatValueCycleWalkRound60(tv.val, seen, javaMapBrace, depth+1) + "]"
	case float64:
		if math.IsNaN(tv) {
			return "NaN"
		}
		if math.IsInf(tv, 1) {
			return "Infinity"
		}
		if math.IsInf(tv, -1) {
			return "-Infinity"
		}
		return fmt.Sprintf("%v", tv)
	case float32:
		return FormatJavaFloat32(tv)
	case *IPAddressVal:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *DenseVectorVal:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *DenseVectorFieldVal:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *GeoBoundingBoxVal:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case time.Duration:
		return formatDurationISO8601Painless(tv)
	case *ZonedDateTimeVal:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *InstantVal:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case DayOfWeekEnum:
		return tv.String()
	case *DayOfWeekEnum:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case MonthEnum:
		return tv.String()
	case *MonthEnum:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *GrokExtractor:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *DissectExtractor:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *GeoPointVal:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *BytesRefVal:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *ByteBufferVal:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *FieldVal:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case *PainlessLambda:
		if tv == nil {
			return "null"
		}
		return tv.String()
	case []float64:
		parts := make([]string, len(tv))
		for i, f := range tv {
			parts[i] = formatValueCycleWalkRound60(f, seen, javaMapBrace, depth+1)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []any:
		if tv == nil {
			return "null"
		}
		key, track := containerNodeKeyRound60(tv)
		if track {
			if seen[key] {
				return "(this Collection)"
			}
			seen[key] = true
			defer delete(seen, key)
		}
		parts := make([]string, len(tv))
		for i, el := range tv {
			parts[i] = formatValueCycleWalkRound60(el, seen, javaMapBrace, depth+1)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		if tv == nil {
			return "null"
		}
		if _, isStats := isSummaryStatisticsMapPainless(tv); isStats {
			return formatSummaryStatisticsToStringPainless(tv)
		}
		if excType, hasExc := tv["__exc_type"].(string); hasExc && excType != "" {
			msg, _ := tv["message"].(string)
			if msg != "" {
				return excType + ": " + msg
			}
			return excType
		}
		key, track := containerNodeKeyRound60(tv)
		if track {
			if seen[key] {
				return "(this Map)"
			}
			seen[key] = true
			defer delete(seen, key)
		}
		keys := visiblePainlessMapKeys(tv)
		if javaMapBrace {
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				ks := fmt.Sprintf("%v", decodePainlessMapKeyRound57(k))
				vs := formatValueCycleWalkRound60(tv[k], seen, true, depth+1)
				parts = append(parts, ks+"="+vs)
			}
			return "{" + strings.Join(parts, ", ") + "}"
		}
		// Preserve Go map[...] formatting when acyclic so existing tests match,
		// while remaining 100% immune to cyclic map recursion.
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			ks := fmt.Sprintf("%v", decodePainlessMapKeyRound57(k))
			vs := formatValueCycleWalkRound60(tv[k], seen, false, depth+1)
			parts = append(parts, ks+":"+vs)
		}
		return "map[" + strings.Join(parts, " ") + "]"
	case *painlessUserObject:
		if tv == nil {
			return "null"
		}
		key, track := containerNodeKeyRound60(tv)
		if track {
			if seen[key] {
				return fmt.Sprintf("%s@cycle", tv.class.name)
			}
			seen[key] = true
			defer delete(seen, key)
		}
		return tv.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func formatArraysToStringCycleSafeRound60(arr []any, deep bool) string {
	if arr == nil {
		return "null"
	}
	seen := make(map[cycleNodeKeyRound60]bool)
	return formatArraysToStringWalkRound60(arr, deep, seen, 0)
}

func formatArraysToStringWalkRound60(arr []any, deep bool, seen map[cycleNodeKeyRound60]bool, depth int) string {
	if arr == nil {
		return "null"
	}
	if depth > 64 {
		return "[...]"
	}
	key, track := containerNodeKeyRound60(arr)
	if track {
		if seen[key] {
			return "[...]"
		}
		seen[key] = true
		defer delete(seen, key)
	}
	parts := make([]string, len(arr))
	for i, el := range arr {
		if el == nil {
			parts[i] = "null"
			continue
		}
		if sub, ok := el.([]any); ok {
			if deep {
				parts[i] = formatArraysToStringWalkRound60(sub, true, seen, depth+1)
				continue
			}
			if subKey, subTrack := containerNodeKeyRound60(sub); subTrack && seen[subKey] {
				parts[i] = "(this Collection)"
				continue
			}
		}
		parts[i] = formatValueCycleWalkRound60(el, seen, false, depth+1)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

type cyclePairKeyRound60 struct {
	a cycleNodeKeyRound60
	b cycleNodeKeyRound60
}

func slicesEqualCycleSafeRound60(sa, sb []any, eqFn func(a, b any, seen map[cyclePairKeyRound60]bool, depth int) bool, seen map[cyclePairKeyRound60]bool, depth int) bool {
	if len(sa) != len(sb) {
		return false
	}
	if depth > 64 {
		return true
	}
	ka, ta := containerNodeKeyRound60(sa)
	kb, tb := containerNodeKeyRound60(sb)
	if ta && tb {
		if ka == kb {
			return true
		}
		pk := cyclePairKeyRound60{a: ka, b: kb}
		if seen == nil {
			seen = make(map[cyclePairKeyRound60]bool)
		}
		if seen[pk] {
			return true
		}
		seen[pk] = true
		defer delete(seen, pk)
	}
	for i := range sa {
		if !eqFn(sa[i], sb[i], seen, depth+1) {
			return false
		}
	}
	return true
}

func mapsEqualCycleSafeRound60(ma, mb map[string]any, eqFn func(a, b any, seen map[cyclePairKeyRound60]bool, depth int) bool, seen map[cyclePairKeyRound60]bool, depth int) bool {
	if visiblePainlessMapLen(ma) != visiblePainlessMapLen(mb) {
		return false
	}
	if depth > 64 {
		return true
	}
	ka, ta := containerNodeKeyRound60(ma)
	kb, tb := containerNodeKeyRound60(mb)
	if ta && tb {
		if ka == kb {
			return true
		}
		pk := cyclePairKeyRound60{a: ka, b: kb}
		if seen == nil {
			seen = make(map[cyclePairKeyRound60]bool)
		}
		if seen[pk] {
			return true
		}
		seen[pk] = true
		defer delete(seen, pk)
	}
	for k, va := range ma {
		if isInternalPainlessMapKey(ma, k) {
			continue
		}
		vb, exists := mb[k]
		if !exists || !eqFn(va, vb, seen, depth+1) {
			return false
		}
	}
	return true
}

func computeJavaHashCodeCycleSafeRound60(v any, seen map[cycleNodeKeyRound60]bool, depth int) int64 {
	if v == nil || v == painlessEmptyOptional {
		return 0
	}
	if depth > 64 {
		return 0
	}
	if seen == nil {
		seen = make(map[cycleNodeKeyRound60]bool)
	}
	switch tv := v.(type) {
	case []any:
		key, track := containerNodeKeyRound60(tv)
		if track {
			if seen[key] {
				return 0
			}
			seen[key] = true
			defer delete(seen, key)
		}
		var h int32 = 1
		for _, el := range tv {
			eh := int32(computeJavaHashCodeCycleSafeRound60(el, seen, depth+1)) // #nosec G115 -- 32-bit Java hashCode
			h = 31*h + eh
		}
		return int64(h)
	case map[string]any:
		key, track := containerNodeKeyRound60(tv)
		if track {
			if seen[key] {
				return 0
			}
			seen[key] = true
			defer delete(seen, key)
		}
		var h int32
		for k, mv := range tv {
			if isInternalPainlessMapKey(tv, k) {
				continue
			}
			kh := int32(computeJavaHashCodeCycleSafeRound60(decodePainlessMapKeyRound57(k), seen, depth+1)) // #nosec G115 -- 32-bit Java hashCode
			vh := int32(computeJavaHashCodeCycleSafeRound60(mv, seen, depth+1))                             // #nosec G115 -- 32-bit Java hashCode
			h += kh ^ vh
		}
		return int64(h)
	default:
		return computeJavaHashCodeScalarRound60(v)
	}
}

func computeJavaHashCodeScalarRound60(v any) int64 {
	switch tv := v.(type) {
	case *painlessOptional:
		return tv.hashCode()
	case *painlessOffsetTime:
		return tv.hashCode()
	case *painlessClock:
		return tv.hashCode()
	case *painlessURI:
		return tv.hashCode()
	case *painlessURL:
		return tv.hashCode()
	case DayOfWeekEnum:
		return tv.Value
	case *DayOfWeekEnum:
		if tv == nil {
			return 0
		}
		return tv.Value
	case MonthEnum:
		return tv.Value
	case *MonthEnum:
		if tv == nil {
			return 0
		}
		return tv.Value
	case *ZonedDateTimeVal:
		if tv == nil {
			return 0
		}
		ms := tv.Time.UnixMilli()
		return int64(int32(ms ^ (ms >> 32))) // #nosec G115 -- Java Long.hashCode
	case *GeoPointVal:
		if tv == nil {
			return 0
		}
		lb := math.Float64bits(tv.Lat)
		nb := math.Float64bits(tv.Lon)
		h := 31*int32(lb^(lb>>32)) + int32(nb^(nb>>32)) // #nosec G115 -- Java hashCode
		return int64(h)
	case bool:
		if tv {
			return 1231
		}
		return 1237
	case int:
		return int64(int32(tv)) // #nosec G115 -- Java Integer.hashCode
	case int32:
		return int64(tv)
	case int64:
		return int64(int32(tv ^ (tv >> 32))) // #nosec G115 -- Java Long.hashCode
	case float64:
		b := math.Float64bits(tv)
		return int64(int32(b ^ (b >> 32))) // #nosec G115 -- Java Double.hashCode
	case string:
		var h int32
		for _, r := range tv {
			h = 31*h + r
		}
		return int64(h)
	default:
		var h int32
		for _, r := range FormatValueSafe(v) {
			h = 31*h + r
		}
		return int64(h)
	}
}

func evalArraysHashCodeCycleSafeRound60(val any, deep bool, sourceMap, params map[string]any, depth int, seen map[cycleNodeKeyRound60]bool) int64 {
	if val == nil || depth > 64 {
		return 0
	}
	if seen == nil {
		seen = make(map[cycleNodeKeyRound60]bool)
	}
	arr, ok := val.([]any)
	if !ok {
		return computeJavaHashCodeCycleSafeRound60(val, seen, depth+1)
	}
	key, track := containerNodeKeyRound60(arr)
	if track {
		if seen[key] {
			return 0
		}
		seen[key] = true
		defer delete(seen, key)
	}
	var h int32 = 1
	for _, el := range arr {
		var eh int32
		if deep {
			if sub, isSub := el.([]any); isSub {
				eh = int32(evalArraysHashCodeCycleSafeRound60(sub, true, sourceMap, params, depth+1, seen)) // #nosec G115 -- 32-bit Java hashCode
				h = 31*h + eh
				continue
			}
		}
		eh = int32(computeJavaHashCodeCycleSafeRound60(el, seen, depth+1)) // #nosec G115 -- 32-bit Java hashCode
		h = 31*h + eh
	}
	return int64(h)
}

func sliceBackingCapPtrRound60(s []any) uintptr {
	if cap(s) == 0 {
		return 0
	}
	full := s[:cap(s)]
	return reflect.ValueOf(full).Pointer()
}

// syncSliceHeaderAliasesRound60 propagates a mutated Go []any slice header to
// self-referential slots and container aliases that held the old (capPtr, len)
// slice value, ensuring `List l = []; l.add(l)` and `a.add(b); b.add(a)` form
// authentic runtime cycles caught by ValidateAcyclicValue and cycle guards.
func syncSliceHeaderAliasesRound60(root map[string]any, oldSlice, newSlice []any) {
	oldCapPtr := sliceBackingCapPtrRound60(oldSlice)
	if oldCapPtr == 0 {
		return
	}
	oldLen := len(oldSlice)
	newCapPtr := sliceBackingCapPtrRound60(newSlice)
	// First check direct elements of newSlice (e.g. `l.add(l)` where `val` had oldSlice's capPtr & len)
	for i, el := range newSlice {
		if sub, ok := el.([]any); ok && len(sub) == oldLen && sliceBackingCapPtrRound60(sub) == oldCapPtr {
			newSlice[i] = newSlice
		}
	}
	if root == nil {
		return
	}
	visited := make(map[cycleNodeKeyRound60]bool)
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if v == nil || depth > 32 {
			return
		}
		if key, track := containerNodeKeyRound60(v); track {
			if visited[key] {
				return
			}
			visited[key] = true
		}
		switch tv := v.(type) {
		case map[string]any:
			for k, mv := range tv {
				if strings.HasPrefix(k, "__") && k != "__raw_source" {
					continue
				}
				if sub, ok := mv.([]any); ok {
					sp := sliceBackingCapPtrRound60(sub)
					if sp == oldCapPtr && len(sub) == oldLen && (sp != newCapPtr || len(sub) != len(newSlice)) {
						tv[k] = newSlice
						continue
					}
				}
				walk(mv, depth+1)
			}
		case []any:
			if sliceBackingCapPtrRound60(tv) == newCapPtr && len(tv) == len(newSlice) {
				for _, el := range tv {
					walk(el, depth+1)
				}
				return
			}
			for i, el := range tv {
				if sub, ok := el.([]any); ok {
					sp := sliceBackingCapPtrRound60(sub)
					if sp == oldCapPtr && len(sub) == oldLen {
						tv[i] = newSlice
						continue
					}
				}
				walk(el, depth+1)
			}
		}
	}
	walk(root, 0)
}

// ============================================================================
// F21: Upfront CompileValidate + Position, System.currentTimeMillis/nanoTime,
//      and Update ctx.* Mutation Guards
// ============================================================================

// ScriptErrorPosition models Elasticsearch's `error.position` object
// (`offset`, `start`, `end`) on Painless compile errors.
type ScriptErrorPosition struct {
	Offset int `json:"offset"`
	Start  int `json:"start"`
	End    int `json:"end"`
}

// ScriptCompileError is returned by CompileValidate when static Painless
// validation detects a compile-time syntax or semantic error.
type ScriptCompileError struct {
	Message  string               `json:"message"`
	Position *ScriptErrorPosition `json:"position,omitempty"`
}

func (e *ScriptCompileError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func newScriptCompileErrorAtRound60(src string, offset int, msg string) *ScriptCompileError {
	if offset < 0 {
		offset = 0
	}
	if offset > len(src) {
		offset = len(src)
	}
	lineStart := 0
	if nl := strings.LastIndexByte(src[:offset], '\n'); nl >= 0 {
		lineStart = nl + 1
	}
	lineEnd := len(src)
	if nl := strings.IndexByte(src[offset:], '\n'); nl >= 0 {
		lineEnd = offset + nl
	}
	// Match Elasticsearch Location.computePosition 25-character context window
	// (e.g. 17_update_error.yml: offset=13 -> start=0, end=38).
	start := offset - 25
	if start < lineStart {
		start = lineStart
	}
	end := offset + 25
	if end > lineEnd {
		end = lineEnd
	}
	if !strings.Contains(msg, "compile error") && !strings.Contains(msg, "illegal_argument_exception") {
		msg = "compile error: " + msg
	}
	return &ScriptCompileError{
		Message: msg,
		Position: &ScriptErrorPosition{
			Offset: offset,
			Start:  start,
			End:    end,
		},
	}
}

type compileTokKindRound60 int

const (
	ctkIdentRound60 compileTokKindRound60 = iota + 1
	ctkNumberRound60
	ctkStringRound60
	ctkRegexRound60
	ctkOpenDelimRound60
	ctkCloseDelimRound60
	ctkSemiRound60
	ctkCommaRound60
	ctkDotRound60
	ctkArrowRound60
	ctkMethodRefRound60
	ctkIncDecRound60
	ctkOpRound60
	ctkQuestionRound60
	ctkColonRound60
)

type compileTokRound60 struct {
	kind   compileTokKindRound60
	lit    string
	offset int
	end    int
}

func canPrecedeRegexLiteralRound60(prev *compileTokRound60) bool {
	if prev == nil {
		return true
	}
	switch prev.kind {
	case ctkOpenDelimRound60, ctkSemiRound60, ctkCommaRound60, ctkArrowRound60, ctkOpRound60, ctkQuestionRound60, ctkColonRound60:
		return true
	case ctkIdentRound60:
		switch prev.lit {
		case "return", "throw", "case", "if", "while", "for", "switch":
			return true
		}
	}
	return false
}

// CompileValidate performs upfront static lexical, delimiter, operator,
// declaration, duplicate-function, and control-flow escape checks on a
// Painless script without requiring a document, returning *ScriptCompileError
// with accurate character Position{Offset, Start, End}.
func CompileValidate(src string) error {
	if strings.TrimSpace(src) == "" {
		return nil
	}
	toks, err := lexPainlessCompileRound60(src)
	if err != nil {
		return err
	}
	if len(toks) == 0 {
		return nil
	}

	// Collect user-defined class names & check duplicate top-level user functions
	userClasses := make(map[string]bool)
	userFuncs := make(map[string]bool)
	for i := 0; i < len(toks); i++ {
		if toks[i].kind == ctkIdentRound60 && toks[i].lit == "class" && i+1 < len(toks) && toks[i+1].kind == ctkIdentRound60 {
			userClasses[toks[i+1].lit] = true
		}
	}

	// Scan top-level function declarations for duplicate (name, arity) & parameter types
	braceDepth := 0
	for i := 0; i < len(toks); i++ {
		if toks[i].kind == ctkOpenDelimRound60 && toks[i].lit == "{" {
			braceDepth++
			continue
		}
		if toks[i].kind == ctkCloseDelimRound60 && toks[i].lit == "}" {
			braceDepth--
			continue
		}
		if braceDepth == 0 && i+2 < len(toks) && toks[i].kind == ctkIdentRound60 && !isPainlessReservedKeyword(toks[i].lit) {
			// Skip optional generics/array dims on return type
			j := i + 1
			if j < len(toks) && toks[j].lit == "<" {
				j = skipAngleTypeArgsRound60(toks, j)
			}
			for j+1 < len(toks) && toks[j].lit == "[" && toks[j+1].lit == "]" {
				j += 2
			}
			if j+1 < len(toks) && toks[j].kind == ctkIdentRound60 && !isPainlessReservedKeyword(toks[j].lit) && toks[j+1].lit == "(" {
				retType := toks[i].lit
				fnName := toks[j].lit
				closeP := findMatchingTokenDelimRound60(toks, j+1, "(", ")")
				if closeP > j && closeP+1 < len(toks) && toks[closeP+1].lit == "{" {
					if !isKnownCompileTypeNameRound60(retType, userClasses) && retType != "void" {
						return newScriptCompileErrorAtRound60(src, toks[i].offset, fmt.Sprintf("unable to resolve type [%s]", retType))
					}
					arity, pErr := validateFuncParamTokensRound60(src, toks[j+2:closeP], userClasses)
					if pErr != nil {
						return pErr
					}
					sigKey := fmt.Sprintf("%s/%d", fnName, arity)
					if userFuncs[sigKey] {
						return newScriptCompileErrorAtRound60(src, toks[j].offset, fmt.Sprintf("duplicate function [%s] with [%d] arguments", fnName, arity))
					}
					userFuncs[sigKey] = true
				}
			}
		}
	}

	// Token-level structural & adjacencies validation
	if err := validateTokenSequenceRound60(src, toks, userClasses); err != nil {
		return err
	}

	// Validate built-in grok(...) / dissect(...) constant literal arguments and pattern syntax
	if err := validateGrokAndDissectCallsRound62(src, toks, userFuncs); err != nil {
		return err
	}

	// Check unescaped infinite loops (`while (true) {}`, `for (;;) {}`)
	if err := validateLoopEscapeRound60(src, toks); err != nil {
		return err
	}
	return nil
}

func lexPainlessCompileRound60(src string) ([]compileTokRound60, error) {
	type delimEntry struct {
		ch     byte
		offset int
	}
	var stack []delimEntry
	var toks []compileTokRound60
	n := len(src)
	i := 0
	for i < n {
		c := src[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			i++
			continue
		}
		// Line comment
		if c == '/' && i+1 < n && src[i+1] == '/' {
			i += 2
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		}
		// Block comment
		if c == '/' && i+1 < n && src[i+1] == '*' {
			startOff := i
			i += 2
			closed := false
			for i+1 < n {
				if src[i] == '*' && src[i+1] == '/' {
					i += 2
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, newScriptCompileErrorAtRound60(src, startOff, "unexpected end of script in block comment")
			}
			continue
		}
		// String / char literal (including `"""..."""` text blocks)
		if c == '\'' || c == '"' {
			startOff := i
			if c == '"' && i+2 < n && src[i+1] == '"' && src[i+2] == '"' {
				i += 3
				closed := false
				for i+2 < n {
					if src[i] == '\\' {
						i += 2
						continue
					}
					if src[i] == '"' && src[i+1] == '"' && src[i+2] == '"' {
						i += 3
						closed = true
						break
					}
					i++
				}
				if !closed {
					return nil, newScriptCompileErrorAtRound60(src, startOff, "unclosed text block literal")
				}
				toks = append(toks, compileTokRound60{kind: ctkStringRound60, lit: src[startOff:i], offset: startOff, end: i})
				continue
			}
			quote := c
			i++
			closed := false
			for i < n {
				if src[i] == '\\' {
					if i+1 >= n {
						return nil, newScriptCompileErrorAtRound60(src, startOff, "unclosed string literal")
					}
					i += 2
					continue
				}
				if src[i] == '\n' || src[i] == '\r' {
					return nil, newScriptCompileErrorAtRound60(src, startOff, "unclosed string literal")
				}
				if src[i] == quote {
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, newScriptCompileErrorAtRound60(src, startOff, "unclosed string literal")
			}
			toks = append(toks, compileTokRound60{kind: ctkStringRound60, lit: src[startOff:i], offset: startOff, end: i})
			continue
		}
		// Regex literal `/pattern/flags` when preceded by operator/delimiter/start
		var prevTok *compileTokRound60
		if len(toks) > 0 {
			prevTok = &toks[len(toks)-1]
		}
		if c == '/' && (i+1 >= n || (src[i+1] != '=' && src[i+1] != '/' && src[i+1] != '*')) && canPrecedeRegexLiteralRound60(prevTok) {
			startOff := i
			j := i + 1
			inClass := false
			closed := false
			for j < n {
				if src[j] == '\\' {
					j += 2
					continue
				}
				if src[j] == '\n' || src[j] == '\r' {
					break
				}
				if src[j] == '[' {
					inClass = true
				} else if src[j] == ']' {
					inClass = false
				} else if src[j] == '/' && !inClass {
					j++
					for j < n && isIdentByte(src[j]) {
						j++
					}
					closed = true
					break
				}
				j++
			}
			if closed {
				toks = append(toks, compileTokRound60{kind: ctkRegexRound60, lit: src[startOff:j], offset: startOff, end: j})
				i = j
				continue
			}
		}
		// Delimiters
		if c == '(' || c == '[' || c == '{' {
			stack = append(stack, delimEntry{ch: c, offset: i})
			toks = append(toks, compileTokRound60{kind: ctkOpenDelimRound60, lit: string(c), offset: i, end: i + 1})
			i++
			continue
		}
		if c == ')' || c == ']' || c == '}' {
			if len(stack) == 0 {
				return nil, newScriptCompileErrorAtRound60(src, i, fmt.Sprintf("extraneous '%c'", c))
			}
			top := stack[len(stack)-1]
			expected := byte(')')
			switch top.ch {
			case '[':
				expected = ']'
			case '{':
				expected = '}'
			}
			if c != expected {
				return nil, newScriptCompileErrorAtRound60(src, i, fmt.Sprintf("mismatched delimiter '%c', expected '%c'", c, expected))
			}
			stack = stack[:len(stack)-1]
			toks = append(toks, compileTokRound60{kind: ctkCloseDelimRound60, lit: string(c), offset: i, end: i + 1})
			i++
			continue
		}
		if c == ';' {
			toks = append(toks, compileTokRound60{kind: ctkSemiRound60, lit: ";", offset: i, end: i + 1})
			i++
			continue
		}
		if c == ',' {
			toks = append(toks, compileTokRound60{kind: ctkCommaRound60, lit: ",", offset: i, end: i + 1})
			i++
			continue
		}
		// Numbers
		if (c >= '0' && c <= '9') || (c == '.' && i+1 < n && src[i+1] >= '0' && src[i+1] <= '9') {
			startOff := i
			if c == '0' && i+1 < n && (src[i+1] == 'x' || src[i+1] == 'X' || src[i+1] == 'b' || src[i+1] == 'B') {
				i += 2
				for i < n && (isIdentByte(src[i]) || src[i] == '_') {
					i++
				}
			} else {
				for i < n && ((src[i] >= '0' && src[i] <= '9') || src[i] == '_') {
					i++
				}
				if i < n && src[i] == '.' && (i+1 >= n || src[i+1] != '.') {
					// Avoid consuming `.method()` on integer literal if followed by non-digit identifier? In Painless `1.toString()` is invalid anyway unless digit follows
					if i+1 < n && src[i+1] >= '0' && src[i+1] <= '9' {
						i++
						for i < n && ((src[i] >= '0' && src[i] <= '9') || src[i] == '_') {
							i++
						}
					} else if i+1 >= n || !isIdentStartByteRound60(src[i+1]) {
						i++
					}
				}
				if i < n && (src[i] == 'e' || src[i] == 'E') {
					i++
					if i < n && (src[i] == '+' || src[i] == '-') {
						i++
					}
					expStart := i
					for i < n && ((src[i] >= '0' && src[i] <= '9') || src[i] == '_') {
						i++
					}
					if i == expStart {
						return nil, newScriptCompileErrorAtRound60(src, startOff, "malformed floating-point exponent")
					}
				}
				if i < n && (src[i] == 'l' || src[i] == 'L' || src[i] == 'f' || src[i] == 'F' || src[i] == 'd' || src[i] == 'D') {
					i++
				}
			}
			if i < n && isIdentStartByteRound60(src[i]) {
				return nil, newScriptCompileErrorAtRound60(src, i, fmt.Sprintf("invalid numeric token suffix '%c'", src[i]))
			}
			toks = append(toks, compileTokRound60{kind: ctkNumberRound60, lit: src[startOff:i], offset: startOff, end: i})
			continue
		}
		// Identifiers (`$` alone is valid in ES 8 Fields API `$('field', default)`, whereas `$$$` is invalid unless defined)
		if isIdentStartByteRound60(c) {
			startOff := i
			i++
			for i < n && isIdentByte(src[i]) {
				i++
			}
			lit := src[startOff:i]
			if strings.TrimLeft(lit, "$") == "" && len(lit) > 1 {
				return nil, newScriptCompileErrorAtRound60(src, startOff, fmt.Sprintf("invalid symbol [%s]", lit))
			}
			toks = append(toks, compileTokRound60{kind: ctkIdentRound60, lit: lit, offset: startOff, end: i})
			continue
		}
		// Multi-char operators & punctuation
		if i+3 <= n {
			three := src[i : i+3]
			switch three {
			case ">>>", "===", "!==", "==~", "<<=", ">>=":
				if three == ">>>" && i+4 <= n && src[i+3] == '=' {
					toks = append(toks, compileTokRound60{kind: ctkOpRound60, lit: ">>>=", offset: i, end: i + 4})
					i += 4
					continue
				}
				toks = append(toks, compileTokRound60{kind: ctkOpRound60, lit: three, offset: i, end: i + 3})
				i += 3
				continue
			}
		}
		if i+2 <= n {
			two := src[i : i+2]
			switch two {
			case "->":
				toks = append(toks, compileTokRound60{kind: ctkArrowRound60, lit: two, offset: i, end: i + 2})
				i += 2
				continue
			case "::":
				toks = append(toks, compileTokRound60{kind: ctkMethodRefRound60, lit: two, offset: i, end: i + 2})
				i += 2
				continue
			case "?.":
				toks = append(toks, compileTokRound60{kind: ctkDotRound60, lit: two, offset: i, end: i + 2})
				i += 2
				continue
			case "++", "--":
				toks = append(toks, compileTokRound60{kind: ctkIncDecRound60, lit: two, offset: i, end: i + 2})
				i += 2
				continue
			case "&&", "||", "==", "!=", "<=", ">=", "=~", "!~", "?:", "<<", ">>",
				"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=":
				toks = append(toks, compileTokRound60{kind: ctkOpRound60, lit: two, offset: i, end: i + 2})
				i += 2
				continue
			}
		}
		switch c {
		case '.':
			toks = append(toks, compileTokRound60{kind: ctkDotRound60, lit: ".", offset: i, end: i + 1})
			i++
		case '?':
			toks = append(toks, compileTokRound60{kind: ctkQuestionRound60, lit: "?", offset: i, end: i + 1})
			i++
		case ':':
			toks = append(toks, compileTokRound60{kind: ctkColonRound60, lit: ":", offset: i, end: i + 1})
			i++
		case '+', '-', '*', '/', '%', '=', '<', '>', '!', '~', '&', '|', '^':
			toks = append(toks, compileTokRound60{kind: ctkOpRound60, lit: string(c), offset: i, end: i + 1})
			i++
		default:
			return nil, newScriptCompileErrorAtRound60(src, i, fmt.Sprintf("unexpected character '%c'", c))
		}
	}
	if len(stack) > 0 {
		unclosed := stack[len(stack)-1]
		return nil, newScriptCompileErrorAtRound60(src, unclosed.offset, fmt.Sprintf("unclosed '%c'", unclosed.ch))
	}
	return toks, nil
}

func isIdentStartByteRound60(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$'
}

func skipAngleTypeArgsRound60(toks []compileTokRound60, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(toks); i++ {
		if toks[i].lit == "<" {
			depth++
		} else if toks[i].lit == ">" {
			depth--
			if depth == 0 {
				return i + 1
			}
		} else if toks[i].lit == ">>" {
			depth -= 2
			if depth <= 0 {
				return i + 1
			}
		} else if toks[i].kind == ctkSemiRound60 || toks[i].lit == "{" || toks[i].lit == "}" {
			break
		}
	}
	return openIdx + 1
}

func findMatchingTokenDelimRound60(toks []compileTokRound60, openIdx int, openLit, closeLit string) int {
	depth := 0
	for i := openIdx; i < len(toks); i++ {
		if toks[i].kind == ctkOpenDelimRound60 && toks[i].lit == openLit {
			depth++
		} else if toks[i].kind == ctkCloseDelimRound60 && toks[i].lit == closeLit {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isKnownCompileTypeNameRound60(name string, userClasses map[string]bool) bool {
	if userClasses[name] || isBuiltInScalarOrColCastBaseRound59(name) || knownStaticClassIdentifiersRound58[name] {
		return true
	}
	switch name {
	case "void", "Supplier", "IntSupplier", "LongSupplier", "DoubleSupplier", "BooleanSupplier",
		"Function", "BiFunction", "IntFunction", "LongFunction", "DoubleFunction",
		"UnaryOperator", "BinaryOperator", "Predicate", "BiPredicate",
		"Consumer", "BiConsumer", "Runnable",
		"Metadata", "UpdateMetadata", "GeoPoint", "GeoBoundingBox", "IPAddress", "DenseVector", "DenseVectorField", "DenseVectorDocValue", "BytesRef", "ByteBuffer", "DayOfWeekEnum", "MonthEnum", "Grok", "Dissect",
		"ZonedDateTime", "OffsetDateTime", "Instant", "LocalDate", "LocalTime", "LocalDateTime",
		"OffsetTime", "Clock", "Duration", "Period", "Year", "YearMonth", "MonthDay",
		"DayOfWeek", "Month", "DateTimeFormatter", "ChronoUnit", "ChronoField", "IsoFields", "TextStyle", "Locale",
		"ValueRange", "TemporalAdjuster", "TemporalAdjusters",
		"Pattern", "Matcher", "MatchResult", "URI", "URL",
		"StringBuilder", "StringBuffer", "Class", "UUID", "HexFormat",
		"Comparator", "BitSet", "StringJoiner",
		"Optional", "OptionalInt", "OptionalLong", "OptionalDouble",
		"Stream", "IntStream", "LongStream", "DoubleStream", "Charset",
		"IntSummaryStatistics", "LongSummaryStatistics", "DoubleSummaryStatistics",
		"NavigableMap", "SortedMap", "NavigableSet", "SortedSet", "Deque", "ArrayDeque", "Queue", "PriorityQueue",
		"Exception", "RuntimeException", "IllegalArgumentException", "NullPointerException",
		"IndexOutOfBoundsException", "ArrayIndexOutOfBoundsException", "StringIndexOutOfBoundsException",
		"ArithmeticException", "ClassCastException", "NumberFormatException",
		"DateTimeException", "DateTimeParseException", "UnsupportedOperationException",
		"IllegalStateException", "NoSuchElementException", "PatternSyntaxException",
		"URISyntaxException", "MalformedURLException", "BufferUnderflowException", "BufferOverflowException",
		"Throwable", "Error", "AssertionError":
		return true
	}
	return false
}

func validateFuncParamTokensRound60(src string, pToks []compileTokRound60, userClasses map[string]bool) (int, error) {
	if len(pToks) == 0 {
		return 0, nil
	}
	arity := 1
	segStart := 0
	depth := 0
	for i := 0; i <= len(pToks); i++ {
		isEnd := i == len(pToks)
		if !isEnd {
			if pToks[i].kind == ctkOpenDelimRound60 || pToks[i].lit == "<" {
				depth++
				continue
			}
			if pToks[i].kind == ctkCloseDelimRound60 || pToks[i].lit == ">" {
				if depth > 0 {
					depth--
				}
				continue
			}
		}
		if isEnd || (pToks[i].kind == ctkCommaRound60 && depth == 0) {
			if !isEnd {
				arity++
			}
			seg := pToks[segStart:i]
			if len(seg) < 2 {
				off := 0
				if len(seg) > 0 {
					off = seg[0].offset
				}
				return 0, newScriptCompileErrorAtRound60(src, off, "invalid function parameter declaration")
			}
			baseType := seg[0].lit
			// Allow qualified names `java.util.function.Supplier`
			k := 0
			for k+2 < len(seg) && seg[k+1].lit == "." {
				k += 2
				baseType = seg[k].lit
			}
			if !isKnownCompileTypeNameRound60(baseType, userClasses) {
				return 0, newScriptCompileErrorAtRound60(src, seg[0].offset, fmt.Sprintf("unable to resolve parameter type [%s]", baseType))
			}
			lastTok := seg[len(seg)-1]
			if lastTok.kind != ctkIdentRound60 || isPainlessReservedKeyword(lastTok.lit) {
				return 0, newScriptCompileErrorAtRound60(src, lastTok.offset, fmt.Sprintf("invalid parameter name [%s]", lastTok.lit))
			}
			segStart = i + 1
		}
	}
	return arity, nil
}

func isBinaryOnlyOpRound60(lit string) bool {
	switch lit {
	case "*", "/", "%", "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>=",
		"&&", "||", "==", "!=", "===", "!==", "<=", ">=", "<", ">", "=~", "==~", "!~", "?:", "<<", ">>", ">>>", "&", "|", "^":
		return true
	}
	return false
}

func validateTokenSequenceRound60(src string, toks []compileTokRound60, userClasses map[string]bool) error {
	n := len(toks)
	if n == 0 {
		return nil
	}
	first := toks[0]
	if first.kind == ctkOpRound60 && isBinaryOnlyOpRound60(first.lit) {
		return newScriptCompileErrorAtRound60(src, first.offset, fmt.Sprintf("unexpected leading operator '%s'", first.lit))
	}
	last := toks[n-1]
	if last.kind == ctkOpRound60 || last.kind == ctkDotRound60 || last.kind == ctkArrowRound60 || last.kind == ctkQuestionRound60 {
		return newScriptCompileErrorAtRound60(src, last.offset, fmt.Sprintf("unexpected trailing '%s'", last.lit))
	}

	for i := 0; i < n; i++ {
		tk := toks[i]

		// Empty `if ()` or `while ()` or `switch ()` condition
		if tk.kind == ctkIdentRound60 && (tk.lit == "if" || tk.lit == "while" || tk.lit == "switch") {
			if i+1 >= n || toks[i+1].lit != "(" {
				return newScriptCompileErrorAtRound60(src, tk.offset, fmt.Sprintf("expected '(' after '%s'", tk.lit))
			}
			if i+2 < n && toks[i+2].lit == ")" {
				return newScriptCompileErrorAtRound60(src, toks[i+2].offset, fmt.Sprintf("empty condition in '%s' statement", tk.lit))
			}
		}

		// `def = 1` or `def 123 = 1`
		if tk.kind == ctkIdentRound60 && tk.lit == "def" {
			// Skip array dimensions `def[] x`
			j := i + 1
			for j+1 < n && toks[j].lit == "[" && toks[j+1].lit == "]" {
				j += 2
			}
			if j < n {
				// Allow `(def x)` cast or `def x` declaration; disallow `def =` or `def 123`
				if toks[j].kind == ctkOpRound60 || toks[j].kind == ctkNumberRound60 || toks[j].kind == ctkStringRound60 {
					return newScriptCompileErrorAtRound60(src, toks[j].offset, fmt.Sprintf("expected identifier after 'def', found '%s'", toks[j].lit))
				}
			}
		}

		// Binary operator followed immediately by binary-only operator, closing delimiter, or semicolon (`1 + * 2`, `1 + ;`, `( * 2)`)
		if tk.kind == ctkOpRound60 {
			if i+1 < n {
				nxt := toks[i+1]
				if nxt.kind == ctkCloseDelimRound60 || nxt.kind == ctkSemiRound60 || nxt.kind == ctkCommaRound60 {
					// Exception: generic `<T>` `>` followed by `)`, `,`, `;`, or `(`
					if tk.lit != ">" && tk.lit != ">>" {
						return newScriptCompileErrorAtRound60(src, tk.offset, fmt.Sprintf("missing right-hand operand after '%s'", tk.lit))
					}
				}
				if nxt.kind == ctkOpRound60 && isBinaryOnlyOpRound60(nxt.lit) {
					if tk.lit != ">" && tk.lit != ">>" {
						return newScriptCompileErrorAtRound60(src, nxt.offset, fmt.Sprintf("unexpected operator '%s' after '%s'", nxt.lit, tk.lit))
					}
				}
			}
		}
		if tk.kind == ctkOpenDelimRound60 && (tk.lit == "(" || tk.lit == "[") && i+1 < n {
			nxt := toks[i+1]
			if nxt.kind == ctkOpRound60 && isBinaryOnlyOpRound60(nxt.lit) {
				// Allow `[:]` empty map literal
				if tk.lit != "[" || nxt.lit != ":" {
					return newScriptCompileErrorAtRound60(src, nxt.offset, fmt.Sprintf("unexpected operator '%s' after '%s'", nxt.lit, tk.lit))
				}
			}
		}

		// Adjacent identifiers (`_score * foo bar + ...` from 17_update_error.yml -> error at `bar` offset 13!)
		// Valid `Ident1 Ident2` cases in Painless:
		//   1. `Ident1` is a type declaration (`int x`, `String s`, `MyClass c`, `Supplier fn`, `def x`, etc.) at statement/param/for/catch/class-field start!
		//   2. `Ident1` is a keyword that precedes an identifier (`return x`, `throw e`, `new Foo`, `class Bar`, `extends Base`, `break lbl`, `continue lbl`, `case FOO`, `else if`).
		//   3. `Ident2` is `instanceof`.
		if tk.kind == ctkIdentRound60 && i+1 < n && toks[i+1].kind == ctkIdentRound60 {
			nxt := toks[i+1]
			if nxt.lit == "instanceof" || nxt.lit == "in" || nxt.lit == "extends" || nxt.lit == "implements" {
				continue
			}
			switch tk.lit {
			case "return", "throw", "new", "instanceof", "in", "class", "extends", "implements", "break", "continue", "case", "else", "static", "final", "public", "private":
				continue
			}
			// Check whether `tk` is at a position where a type declaration `Type varName` is syntactically legal!
			if canStartTypeDeclAtRound60(toks, i) {
				// Even at statement/param start, `Type` must be a known type or user class!
				baseType := resolveQualifiedPrefixTypeRound60(toks, i)
				if !isKnownCompileTypeNameRound60(baseType, userClasses) {
					return newScriptCompileErrorAtRound60(src, tk.offset, fmt.Sprintf("unable to resolve type [%s]", baseType))
				}
				continue
			}
			// Otherwise `tk` is mid-expression (e.g. `_score * foo bar`!), so `nxt` (`bar`) is an unexpected extraneous identifier!
			return newScriptCompileErrorAtRound60(src, nxt.offset, fmt.Sprintf("unexpected token [%s]", nxt.lit))
		}
	}
	return nil
}

func resolveQualifiedPrefixTypeRound60(toks []compileTokRound60, idx int) string {
	j := idx
	for j >= 2 && toks[j-1].lit == "." && toks[j-2].kind == ctkIdentRound60 {
		j -= 2
	}
	// Return the simple terminal identifier (`java.util.List` -> `List`)
	return toks[idx].lit
}

func canStartTypeDeclAtRound60(toks []compileTokRound60, idx int) bool {
	// Walk back across qualified package prefix `java.util.List`
	start := idx
	for start >= 2 && toks[start-1].lit == "." && toks[start-2].kind == ctkIdentRound60 {
		start -= 2
	}
	if start == 0 {
		return true
	}
	prev := toks[start-1]
	switch prev.lit {
	case ";", "{", "}", "(", ",":
		return true
	case "|":
		// Multi-catch exception type `catch (ExA | ExB e)`
		for k := start - 1; k >= 0; k-- {
			if toks[k].lit == "(" && k > 0 && toks[k-1].lit == "catch" {
				return true
			}
			if toks[k].lit == ";" || toks[k].lit == "{" || toks[k].lit == "}" || toks[k].lit == ")" {
				break
			}
		}
		return false
	case ":":
		// After case/default label or loop label
		return true
	case "else", "do", "static", "final", "public", "private":
		return true
	case ")":
		// After `if (...) Type x = ...` or `for (...)` or `while (...)`, NOT after `(cast) foo bar`!
		openP := findReverseMatchingDelimRound60(toks, start-1, "(", ")")
		if openP > 0 && toks[openP-1].kind == ctkIdentRound60 {
			switch toks[openP-1].lit {
			case "if", "for", "while", "catch":
				return true
			}
		}
		return false
	}
	return false
}

func findReverseMatchingDelimRound60(toks []compileTokRound60, closeIdx int, openLit, closeLit string) int {
	depth := 0
	for i := closeIdx; i >= 0; i-- {
		if toks[i].kind == ctkCloseDelimRound60 && toks[i].lit == closeLit {
			depth++
		} else if toks[i].kind == ctkOpenDelimRound60 && toks[i].lit == openLit {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func validateLoopEscapeRound60(src string, toks []compileTokRound60) error {
	n := len(toks)
	for i := 0; i < n; i++ {
		if toks[i].kind == ctkIdentRound60 && toks[i].lit == "while" && i+3 < n &&
			toks[i+1].lit == "(" && toks[i+2].lit == "true" && toks[i+3].lit == ")" {
			bodyStart := i + 4
			if bodyStart < n {
				bodyEnd := bodyStart
				if toks[bodyStart].lit == "{" {
					if m := findMatchingTokenDelimRound60(toks, bodyStart, "{", "}"); m >= bodyStart {
						bodyEnd = m
					}
				} else {
					for bodyEnd < n && toks[bodyEnd].kind != ctkSemiRound60 {
						bodyEnd++
					}
				}
				if !tokensContainLoopEscapeRound60(toks[bodyStart : bodyEnd+1]) {
					return newScriptCompileErrorAtRound60(src, toks[i].offset, "illegal_argument_exception: no paths escape from while loop")
				}
			}
		}
		if toks[i].kind == ctkIdentRound60 && toks[i].lit == "for" && i+4 < n &&
			toks[i+1].lit == "(" && toks[i+2].lit == ";" && toks[i+3].lit == ";" && toks[i+4].lit == ")" {
			bodyStart := i + 5
			if bodyStart < n {
				bodyEnd := bodyStart
				if toks[bodyStart].lit == "{" {
					if m := findMatchingTokenDelimRound60(toks, bodyStart, "{", "}"); m >= bodyStart {
						bodyEnd = m
					}
				}
				if !tokensContainLoopEscapeRound60(toks[bodyStart : bodyEnd+1]) {
					return newScriptCompileErrorAtRound60(src, toks[i].offset, "illegal_argument_exception: no paths escape from for loop")
				}
			}
		}
	}
	return nil
}

func tokensContainLoopEscapeRound60(bodyToks []compileTokRound60) bool {
	for _, t := range bodyToks {
		if t.kind == ctkIdentRound60 {
			switch t.lit {
			case "break", "return", "throw":
				return true
			}
		}
	}
	return false
}

var allowedUpdateCtxTopLevelKeysRound60 = map[string]bool{
	"_source":    true,
	"op":         true,
	"_now":       true,
	"_id":        true,
	"_index":     true,
	"_version":   true,
	"_routing":   true,
	"_type":      true,
	"_Timestamp": true,
	"_ingest":    true,
}

func isValidUpdateCtxOpRound60(op string, allowCreate bool) bool {
	switch op {
	case "", "index", "noop", "none", "delete":
		return true
	case "create":
		return allowCreate
	default:
		return false
	}
}

// ValidateUpdateCtxMutations enforces Elasticsearch `_update` script rules on
// `ctx`: `_id` cannot be modified, unknown top-level `ctx` keys are rejected,
// and `ctx.op` must be a valid update operation (`index`, `noop`, `none`, `delete`).
func ValidateUpdateCtxMutations(origID string, ctxMap map[string]any) error {
	if ctxMap == nil {
		return nil
	}
	if idVal, hasID := ctxMap["_id"]; hasID {
		curID := ""
		if idVal != nil {
			curID = fmt.Sprintf("%v", idVal)
		}
		if curID != origID {
			return fmt.Errorf("illegal_argument_exception: Cannot modify _id in update script")
		}
	}
	for k := range ctxMap {
		if strings.HasPrefix(k, "__") || strings.HasPrefix(k, "_ctx_") {
			continue
		}
		if !allowedUpdateCtxTopLevelKeysRound60[k] {
			return fmt.Errorf("illegal_argument_exception: Operation [%s] is not supported", k)
		}
	}
	if opVal, hasOp := ctxMap["op"]; hasOp && opVal != nil {
		opStr := fmt.Sprintf("%v", opVal)
		allowCreate, _ := ctxMap["__allow_create_op"].(bool)
		if !isValidUpdateCtxOpRound60(opStr, allowCreate) {
			return fmt.Errorf("illegal_argument_exception: Operation [%s] is not supported, only [index, delete, noop, none] are allowed", opStr)
		}
	}
	if srcMap, ok := ctxMap["_source"].(map[string]any); ok {
		if err := ValidateAcyclicValue(srcMap); err != nil {
			return err
		}
	}
	return ValidateAcyclicValue(ctxMap)
}

// ============================================================================
// F22: Column-Stride `doc[...]` Wrappers (`ZonedDateTimeVal`, `DayOfWeekEnum`,
//      `GeoPointVal`, `BytesRefVal`, `ByteBufferVal`), ES 8 `field()` / `$()`,
//      and First-Class `PainlessLambda`
// ============================================================================

// DayOfWeekEnum models `java.time.DayOfWeek` returned by
// `ZonedDateTimeVal.getDayOfWeekEnum()` / `.dayOfWeekEnum` (Monday=1 .. Sunday=7).
type DayOfWeekEnum struct {
	Value   int64
	NameStr string
}

func newDayOfWeekEnumFromWeekdayRound60(wd time.Weekday) DayOfWeekEnum {
	v := int64(wd)
	if v == 0 {
		v = 7
	}
	return DayOfWeekEnum{
		Value:   v,
		NameStr: strings.ToUpper(wd.String()),
	}
}

func (d DayOfWeekEnum) GetValue() int64 { return d.Value }
func (d DayOfWeekEnum) Name() string    { return d.NameStr }
func (d DayOfWeekEnum) String() string {
	if d.NameStr != "" {
		return d.NameStr
	}
	names := [8]string{"", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY", "SUNDAY"}
	if d.Value >= 1 && d.Value <= 7 {
		return names[d.Value]
	}
	return "MONDAY"
}

func (d DayOfWeekEnum) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// GetDisplayName models `java.time.DayOfWeek.getDisplayName(TextStyle, Locale)`.
func (d DayOfWeekEnum) GetDisplayName(style, locale string) string {
	return DayOfWeekDisplayName(d.Value, style, locale)
}

// InstantVal models `java.time.Instant` returned by `ZonedDateTimeVal.toInstant()`.
type InstantVal struct {
	Time time.Time
}

func (iv *InstantVal) ToEpochMilli() int64 {
	if iv == nil {
		return 0
	}
	return iv.Time.UTC().UnixMilli()
}

func (iv *InstantVal) String() string {
	if iv == nil {
		return "null"
	}
	return iv.Time.UTC().Format("2006-01-02T15:04:05.999999999Z")
}

func (iv *InstantVal) MarshalJSON() ([]byte, error) {
	if iv == nil {
		return []byte("null"), nil
	}
	return json.Marshal(iv.String())
}

// ZonedDateTimeVal wraps ES `date` and `date_nanos` doc values in Painless.
type ZonedDateTimeVal struct {
	Time   time.Time
	Raw    string
	IsNano bool
}

func parseZonedDateTimeValRound60(v any, isNano bool) (*ZonedDateTimeVal, bool) {
	if v == nil {
		return nil, false
	}
	if z, ok := v.(*ZonedDateTimeVal); ok && z != nil {
		return z, true
	}
	if z, ok := v.(ZonedDateTimeVal); ok {
		return &z, true
	}
	if tm, ok := parseFlexibleESDateTimeRound60(v); ok {
		raw := ""
		if s, isS := v.(string); isS {
			raw = s
		}
		return &ZonedDateTimeVal{Time: tm.UTC(), Raw: raw, IsNano: isNano}, true
	}
	return nil, false
}

func parseFlexibleESDateTimeRound60(v any) (time.Time, bool) {
	switch tv := v.(type) {
	case *ZonedDateTimeVal:
		if tv == nil {
			return time.Time{}, false
		}
		return tv.Time, true
	case ZonedDateTimeVal:
		return tv.Time, true
	case *InstantVal:
		if tv == nil {
			return time.Time{}, false
		}
		return tv.Time, true
	case time.Time:
		return tv, true
	case string:
		s := strings.TrimSpace(tv)
		if s == "" {
			return time.Time{}, false
		}
		// Numeric epoch millis string
		if iv, err := strconv.ParseInt(s, 10, 64); err == nil && len(s) != 8 {
			return time.UnixMilli(iv).UTC(), true
		}
		for _, slashLayout := range []string{
			"2006/01/02 15:04:05.999999999Z07:00",
			"2006/01/02T15:04:05.999999999Z07:00",
			"2006/01/02 15:04:05",
			"2006/01/02T15:04:05",
			"2006/01/02",
		} {
			if tm, err := time.Parse(slashLayout, s); err == nil {
				return tm.UTC(), true
			}
		}
		return parsePainlessDateTime(s)
	default:
		if iv, ok := isIntegerValuePainless(v); ok {
			return time.UnixMilli(iv).UTC(), true
		}
		if fv, ok := toFloat64(v); ok {
			return time.UnixMilli(int64(fv)).UTC(), true
		}
	}
	return time.Time{}, false
}

func (z *ZonedDateTimeVal) GetYear() int64 {
	if z == nil {
		return 0
	}
	return int64(z.Time.Year())
}

func (z *ZonedDateTimeVal) GetMonthValue() int64 {
	if z == nil {
		return 0
	}
	return int64(z.Time.Month())
}

func (z *ZonedDateTimeVal) GetDayOfMonth() int64 {
	if z == nil {
		return 0
	}
	return int64(z.Time.Day())
}

func (z *ZonedDateTimeVal) GetDayOfYear() int64 {
	if z == nil {
		return 0
	}
	return int64(z.Time.YearDay())
}

func (z *ZonedDateTimeVal) GetDayOfWeek() int64 {
	if z == nil {
		return 1
	}
	return newDayOfWeekEnumFromWeekdayRound60(z.Time.Weekday()).Value
}

func (z *ZonedDateTimeVal) GetDayOfWeekEnum() DayOfWeekEnum {
	if z == nil {
		return DayOfWeekEnum{Value: 1, NameStr: "MONDAY"}
	}
	return newDayOfWeekEnumFromWeekdayRound60(z.Time.Weekday())
}

func (z *ZonedDateTimeVal) GetHour() int64 {
	if z == nil {
		return 0
	}
	return int64(z.Time.Hour())
}

func (z *ZonedDateTimeVal) GetMinute() int64 {
	if z == nil {
		return 0
	}
	return int64(z.Time.Minute())
}

func (z *ZonedDateTimeVal) GetSecond() int64 {
	if z == nil {
		return 0
	}
	return int64(z.Time.Second())
}

func (z *ZonedDateTimeVal) GetNano() int64 {
	if z == nil {
		return 0
	}
	return int64(z.Time.Nanosecond())
}

func (z *ZonedDateTimeVal) ToInstant() *InstantVal {
	if z == nil {
		return &InstantVal{}
	}
	return &InstantVal{Time: z.Time.UTC()}
}

func (z *ZonedDateTimeVal) ToEpochMilli() int64 {
	if z == nil {
		return 0
	}
	return z.Time.UTC().UnixMilli()
}

func (z *ZonedDateTimeVal) String() string {
	if z == nil {
		return "null"
	}
	loc := z.Time.Location()
	if loc != nil && loc != time.UTC {
		_, off := z.Time.Zone()
		zName := loc.String()
		if off != 0 || (zName != "" && zName != "UTC" && zName != "Z") {
			base := z.Time.Format(time.RFC3339Nano)
			if zName != "" && zName != "UTC" && zName != "Z" && !strings.HasPrefix(zName, "+") && !strings.HasPrefix(zName, "-") && !strings.HasPrefix(zName, "FixedZone") {
				return base + "[" + zName + "]"
			}
			return base
		}
	}
	t := z.Time.UTC()
	if z.IsNano && t.Nanosecond()%1_000_000 != 0 {
		return t.Format("2006-01-02T15:04:05.999999999Z")
	}
	return t.Format("2006-01-02T15:04:05.000Z")
}

func (z *ZonedDateTimeVal) MarshalJSON() ([]byte, error) {
	if z == nil {
		return []byte("null"), nil
	}
	return json.Marshal(z.String())
}

// GeoPointVal wraps ES `geo_point` doc values and `new GeoPoint(lat, lon)`.
type GeoPointVal struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

const earthMeanRadiusMetersES = 6371008.7714

func parseGeoPointValRound60(v any) (*GeoPointVal, bool) {
	if v == nil {
		return nil, false
	}
	switch tv := v.(type) {
	case *GeoPointVal:
		if tv == nil {
			return nil, false
		}
		return tv, true
	case GeoPointVal:
		return &tv, true
	case map[string]any:
		latV, hasLat := tv["lat"]
		lonV, hasLon := tv["lon"]
		if !hasLon {
			lonV, hasLon = tv["lng"]
		}
		if hasLat && hasLon {
			lat, ok1 := toFloat64(latV)
			lon, ok2 := toFloat64(lonV)
			if ok1 && ok2 {
				return &GeoPointVal{Lat: lat, Lon: lon}, true
			}
		}
		if coords, ok := tv["coordinates"].([]any); ok && len(coords) >= 2 {
			lon, ok1 := toFloat64(coords[0])
			lat, ok2 := toFloat64(coords[1])
			if ok1 && ok2 {
				return &GeoPointVal{Lat: lat, Lon: lon}, true
			}
		}
	case []any:
		// GeoJSON `[lon, lat]` array
		if len(tv) >= 2 {
			lon, ok1 := toFloat64(tv[0])
			lat, ok2 := toFloat64(tv[1])
			if ok1 && ok2 {
				return &GeoPointVal{Lat: lat, Lon: lon}, true
			}
		}
	case []float64:
		if len(tv) >= 2 {
			return &GeoPointVal{Lat: tv[1], Lon: tv[0]}, true
		}
	case string:
		s := strings.TrimSpace(tv)
		if s == "" {
			return nil, false
		}
		upper := strings.ToUpper(s)
		if strings.HasPrefix(upper, "POINT") {
			openP := strings.IndexByte(s, '(')
			closeP := strings.LastIndexByte(s, ')')
			if openP > 0 && closeP > openP {
				fields := strings.Fields(s[openP+1 : closeP])
				if len(fields) >= 2 {
					lon, err1 := strconv.ParseFloat(fields[0], 64)
					lat, err2 := strconv.ParseFloat(fields[1], 64)
					if err1 == nil && err2 == nil {
						return &GeoPointVal{Lat: lat, Lon: lon}, true
					}
				}
			}
			return nil, false
		}
		if strings.Contains(s, ",") {
			parts := strings.SplitN(s, ",", 2)
			lat, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			lon, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			if err1 == nil && err2 == nil {
				return &GeoPointVal{Lat: lat, Lon: lon}, true
			}
			return nil, false
		}
		if lat, lon, ok := decodeGeohashRound60(s); ok {
			return &GeoPointVal{Lat: lat, Lon: lon}, true
		}
	}
	return nil, false
}

const geohashBase32Round60 = "0123456789bcdefghjkmnpqrstuvwxyz"

func decodeGeohashRound60(hash string) (float64, float64, bool) {
	hash = strings.TrimSpace(strings.ToLower(hash))
	if hash == "" || len(hash) > 12 {
		return 0, 0, false
	}
	minLat, maxLat := -90.0, 90.0
	minLon, maxLon := -180.0, 180.0
	isEven := true
	for i := 0; i < len(hash); i++ {
		idx := strings.IndexByte(geohashBase32Round60, hash[i])
		if idx < 0 {
			return 0, 0, false
		}
		for mask := 16; mask > 0; mask >>= 1 {
			if isEven {
				mid := (minLon + maxLon) / 2
				if idx&mask != 0 {
					minLon = mid
				} else {
					maxLon = mid
				}
			} else {
				mid := (minLat + maxLat) / 2
				if idx&mask != 0 {
					minLat = mid
				} else {
					maxLat = mid
				}
			}
			isEven = !isEven
		}
	}
	return (minLat + maxLat) / 2, (minLon + maxLon) / 2, true
}

func haversinMetersESRound60(lat1, lon1, lat2, lon2 float64) float64 {
	toRad := math.Pi / 180.0
	rLat1 := lat1 * toRad
	rLat2 := lat2 * toRad
	dLat := (lat2 - lat1) * toRad
	dLon := (lon2 - lon1) * toRad
	sinLat := math.Sin(dLat / 2)
	sinLon := math.Sin(dLon / 2)
	h := sinLat*sinLat + math.Cos(rLat1)*math.Cos(rLat2)*sinLon*sinLon
	if h > 1.0 {
		h = 1.0
	}
	return 2.0 * earthMeanRadiusMetersES * math.Asin(math.Sqrt(h))
}

func planeDistanceMetersESRound60(lat1, lon1, lat2, lon2 float64) float64 {
	toRad := math.Pi / 180.0
	x := (lon2 - lon1) * toRad * math.Cos(((lat1+lat2)/2.0)*toRad)
	y := (lat2 - lat1) * toRad
	return math.Sqrt(x*x+y*y) * earthMeanRadiusMetersES
}

func (g *GeoPointVal) GetLat() float64 {
	if g == nil {
		return 0
	}
	return g.Lat
}

func (g *GeoPointVal) GetLon() float64 {
	if g == nil {
		return 0
	}
	return g.Lon
}

func (g *GeoPointVal) ArcDistance(lat, lon float64) float64 {
	if g == nil {
		return 0
	}
	return haversinMetersESRound60(g.Lat, g.Lon, lat, lon)
}

func (g *GeoPointVal) PlaneDistance(lat, lon float64) float64 {
	if g == nil {
		return 0
	}
	return planeDistanceMetersESRound60(g.Lat, g.Lon, lat, lon)
}

func (g *GeoPointVal) GeohashDistance(hash string) (float64, error) {
	if g == nil {
		return 0, nil
	}
	lat, lon, ok := decodeGeohashRound60(hash)
	if !ok {
		return 0, fmt.Errorf("illegal_argument_exception: invalid geohash [%s]", hash)
	}
	return haversinMetersESRound60(g.Lat, g.Lon, lat, lon), nil
}

func (g *GeoPointVal) String() string {
	if g == nil {
		return "null"
	}
	return fmt.Sprintf("%v, %v", g.Lat, g.Lon)
}

// BytesRefVal models Lucene `org.apache.lucene.util.BytesRef` returned by `doc['binary']`.
type BytesRefVal struct {
	Bytes  []byte
	Offset int
	Length int
}

func newBytesRefValRound60(b []byte) *BytesRefVal {
	cp := make([]byte, len(b))
	copy(cp, b)
	return &BytesRefVal{Bytes: cp, Offset: 0, Length: len(cp)}
}

func decodeBase64BinaryRound60(v any) ([]byte, bool) {
	switch tv := v.(type) {
	case *BytesRefVal:
		if tv == nil {
			return nil, false
		}
		return tv.slice(), true
	case *ByteBufferVal:
		if tv == nil {
			return nil, false
		}
		return tv.Bytes[tv.Pos:tv.Lim], true
	case []byte:
		return tv, true
	case string:
		if decoded, err := base64.StdEncoding.DecodeString(tv); err == nil {
			return decoded, true
		}
		if decoded, err := base64.RawStdEncoding.DecodeString(tv); err == nil {
			return decoded, true
		}
		return []byte(tv), true
	}
	return nil, false
}

func (br *BytesRefVal) slice() []byte {
	if br == nil || len(br.Bytes) == 0 {
		return nil
	}
	end := br.Offset + br.Length
	if end > len(br.Bytes) {
		end = len(br.Bytes)
	}
	if br.Offset < 0 || br.Offset > end {
		return nil
	}
	return br.Bytes[br.Offset:end]
}

func (br *BytesRefVal) Utf8ToString() string {
	return string(br.slice())
}

func (br *BytesRefVal) byteSliceForPainless() []any {
	raw := br.slice()
	out := make([]any, len(raw))
	for i, b := range raw {
		out[i] = int64(int8(b)) // #nosec G115 -- signed Java byte
	}
	return out
}

func (br *BytesRefVal) String() string {
	if br == nil {
		return "null"
	}
	raw := br.slice()
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%x", b)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func (br *BytesRefVal) MarshalJSON() ([]byte, error) {
	if br == nil {
		return []byte("null"), nil
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(br.slice()))
}

// ByteBufferVal models `java.nio.ByteBuffer` returned by ES 8 `field('binary')` / `$('binary')`.
type ByteBufferVal struct {
	Bytes []byte
	Pos   int
	Lim   int
	Cap   int
}

func newByteBufferValRound60(b []byte) *ByteBufferVal {
	cp := make([]byte, len(b))
	copy(cp, b)
	return &ByteBufferVal{Bytes: cp, Pos: 0, Lim: len(cp), Cap: len(cp)}
}

func (bb *ByteBufferVal) Get(idx int) (int64, error) {
	if bb == nil || idx < 0 || idx >= bb.Lim {
		return 0, &painlessExceptionError{
			exType:  "IndexOutOfBoundsException",
			message: fmt.Sprintf("index %d out of bounds for limit %d", idx, bb.Limit()),
		}
	}
	return int64(int8(bb.Bytes[idx])), nil // #nosec G115 -- signed Java byte
}

func (bb *ByteBufferVal) Limit() int64 {
	if bb == nil {
		return 0
	}
	return int64(bb.Lim)
}

func (bb *ByteBufferVal) Capacity() int64 {
	if bb == nil {
		return 0
	}
	return int64(bb.Cap)
}

func (bb *ByteBufferVal) Position() int64 {
	if bb == nil {
		return 0
	}
	return int64(bb.Pos)
}

func (bb *ByteBufferVal) Remaining() int64 {
	if bb == nil {
		return 0
	}
	return int64(bb.Lim - bb.Pos)
}

func (bb *ByteBufferVal) Utf8ToString() string {
	if bb == nil {
		return ""
	}
	return string(bb.Bytes[bb.Pos:bb.Lim])
}

func (bb *ByteBufferVal) String() string {
	if bb == nil {
		return "null"
	}
	return fmt.Sprintf("java.nio.HeapByteBuffer[pos=%d lim=%d cap=%d]", bb.Pos, bb.Lim, bb.Cap)
}

func (bb *ByteBufferVal) MarshalJSON() ([]byte, error) {
	if bb == nil {
		return []byte("null"), nil
	}
	return json.Marshal(base64.StdEncoding.EncodeToString(bb.Bytes[bb.Pos:bb.Lim]))
}

// NormalizeDocValuesForScript normalizes a document map into Elasticsearch
// column-stride `doc[...]` semantics according to fieldTypes:
//   - Numeric / date / date_nanos / geo_point multi-values: sorted ascending, keeping duplicates.
//   - keyword / constant_keyword / wildcard / boolean / ip multi-values: sorted ascending and deduplicated
//     (unless `fieldTypes[field] == "boolean_dup"` or `doc["__keep_boolean_dups"] == true`).
//   - date / date_nanos values wrapped in `*ZonedDateTimeVal`.
//   - geo_point values wrapped in `*GeoPointVal`.
//   - binary values decoded from base64 into `*BytesRefVal`.
func NormalizeDocValuesForScript(doc map[string]any, fieldTypes map[string]string) map[string]any {
	if doc == nil {
		return nil
	}
	out := make(map[string]any, len(doc)+2)
	keepBoolDups, _ := doc["__keep_boolean_dups"].(bool)
	quantizeGeo := isGeoQuantizeEnabledRound61(doc, nil)
	for k, v := range doc {
		if strings.HasPrefix(k, "__") {
			out[k] = v
			continue
		}
		ft := lookupFieldTypeRound60(fieldTypes, k)
		if ft != "" {
			dateFmt := lookupFieldFormatFromMapsRound61(doc, nil, k)
			out[k] = normalizeSingleFieldDocValuesWithOptsRound61(v, ft, keepBoolDups, false, dateFmt, quantizeGeo)
		} else {
			out[k] = v
		}
	}
	if len(fieldTypes) > 0 {
		ftCopy := make(map[string]string, len(fieldTypes))
		for k, v := range fieldTypes {
			ftCopy[k] = v
		}
		out["__field_types"] = ftCopy
	}
	return out
}

func lookupFieldTypeRound60(fieldTypes map[string]string, path string) string {
	if len(fieldTypes) == 0 || path == "" {
		return ""
	}
	clean := strings.ReplaceAll(path, "\x00", ".")
	if ft, ok := fieldTypes[clean]; ok {
		return strings.ToLower(strings.TrimSpace(ft))
	}
	if strings.HasSuffix(clean, ".keyword") {
		if ft, ok := fieldTypes[strings.TrimSuffix(clean, ".keyword")]; ok && ft != "text" {
			return strings.ToLower(strings.TrimSpace(ft))
		}
		return "keyword"
	}
	return ""
}

func extractFieldTypesFromMapsRound60(sourceMap, params map[string]any) map[string]string {
	for _, m := range []map[string]any{params, sourceMap} {
		if m == nil {
			continue
		}
		if ft, ok := m["__field_types"].(map[string]string); ok && len(ft) > 0 {
			return ft
		}
		if ftAny, ok := m["__field_types"].(map[string]any); ok && len(ftAny) > 0 {
			conv := make(map[string]string, len(ftAny))
			for k, v := range ftAny {
				if s, isS := v.(string); isS {
					conv[k] = s
				}
			}
			return conv
		}
	}
	return nil
}

func checkStrictDocFieldMappingRound60(sourceMap, params map[string]any, fieldPath string) error {
	clean := strings.ReplaceAll(fieldPath, "\x00", ".")
	switch clean {
	case "_id", "_index", "_version", "_seq_no", "_primary_term", "_routing", "_score", "_ignored", "_field_names":
		return nil
	}
	if _, _, ok := resolveMappedFlattenedBaseRound61(params, clean); ok {
		return nil
	}
	if _, _, ok := resolveMappedFlattenedBaseRound61(sourceMap, clean); ok {
		return nil
	}
	for _, m := range []map[string]any{params, sourceMap} {
		if m == nil {
			continue
		}
		rawStrict, exists := m["__strict_doc_fields"]
		if !exists || rawStrict == nil {
			continue
		}
		switch st := rawStrict.(type) {
		case map[string]bool:
			if st[clean] {
				return nil
			}
			if strings.HasSuffix(clean, ".keyword") && st[strings.TrimSuffix(clean, ".keyword")] {
				return nil
			}
			return fmt.Errorf("illegal_argument_exception: No field found for [%s] in mapping", clean)
		case map[string]string:
			if _, ok := st[clean]; ok {
				return nil
			}
			return fmt.Errorf("illegal_argument_exception: No field found for [%s] in mapping", clean)
		case map[string]any:
			if _, ok := st[clean]; ok {
				return nil
			}
			return fmt.Errorf("illegal_argument_exception: No field found for [%s] in mapping", clean)
		case []string:
			for _, f := range st {
				if f == clean {
					return nil
				}
			}
			return fmt.Errorf("illegal_argument_exception: No field found for [%s] in mapping", clean)
		case bool:
			if st {
				ft := extractFieldTypesFromMapsRound60(sourceMap, params)
				if len(ft) > 0 {
					if _, ok := ft[clean]; ok {
						return nil
					}
					return fmt.Errorf("illegal_argument_exception: No field found for [%s] in mapping", clean)
				}
			}
		}
	}
	return nil
}

func flattenRawFieldItemsRound60(v any, treatNumericListAsGeoPoint bool) []any {
	if v == nil {
		return nil
	}
	if slice, ok := v.([]any); ok {
		if treatNumericListAsGeoPoint && len(slice) == 2 {
			_, ok0 := toFloat64(slice[0])
			_, ok1 := toFloat64(slice[1])
			_, sub0 := slice[0].([]any)
			if ok0 && ok1 && !sub0 {
				return []any{slice}
			}
		}
		out := make([]any, 0, len(slice))
		for _, item := range slice {
			if item != nil {
				out = append(out, item)
			}
		}
		return out
	}
	if fSlice, ok := v.([]float64); ok {
		if treatNumericListAsGeoPoint && len(fSlice) == 2 {
			return []any{fSlice}
		}
		out := make([]any, len(fSlice))
		for i, fv := range fSlice {
			out[i] = fv
		}
		return out
	}
	return []any{v}
}

func normalizeSingleFieldDocValuesRound60(raw any, fieldType string, keepBoolDups bool, forFieldsAPI bool) []any {
	return normalizeSingleFieldDocValuesWithOptsRound61(raw, fieldType, keepBoolDups, forFieldsAPI, "", false)
}

func normalizeSingleFieldDocValuesWithOptsRound61(raw any, fieldType string, keepBoolDups bool, forFieldsAPI bool, dateFmt string, quantizeGeo bool) []any {
	ft := strings.ToLower(strings.TrimSpace(fieldType))
	if ft == "dense_vector" || ft == "vector" {
		if s, isStr := raw.(string); isStr {
			if _, f32, err := DecodeHexSignedByteVector(s); err == nil {
				out := make([]any, len(f32))
				for i, v := range f32 {
					out[i] = float64(v)
				}
				return out
			}
		}
		items := flattenRawFieldItemsRound60(raw, false)
		out := make([]any, 0, len(items))
		for _, it := range items {
			if f, ok := toFloat64(it); ok {
				out = append(out, f)
			}
		}
		return out
	}
	if ft == "flattened" {
		if raw == nil {
			return []any{}
		}
		return ExtractFlattenedLeafStrings(raw, "")
	}
	if ft == "token_count" {
		if total, hasAny := CountStandardAnalyzerTokens(raw); hasAny {
			return []any{total}
		}
		return []any{}
	}
	isGeo := ft == "geo_point"
	items := flattenRawFieldItemsRound60(raw, isGeo)
	if len(items) == 0 {
		return []any{}
	}

	switch ft {
	case "unsigned_long":
		uVals := make([]uint64, 0, len(items))
		for _, it := range items {
			switch uv := it.(type) {
			case *painlessBigInteger:
				if uv != nil && uv.val != nil && uv.val.Sign() >= 0 && uv.val.IsUint64() {
					uVals = append(uVals, uv.val.Uint64())
				}
			case uint64:
				uVals = append(uVals, uv)
			case uint:
				uVals = append(uVals, uint64(uv))
			case uint32:
				uVals = append(uVals, uint64(uv))
			case int64:
				if uv >= 0 {
					uVals = append(uVals, uint64(uv)) // #nosec G115 -- guarded uv >= 0
				}
			case int:
				if uv >= 0 {
					uVals = append(uVals, uint64(uv)) // #nosec G115 -- guarded uv >= 0
				}
			case json.Number:
				s := strings.TrimSpace(uv.String())
				if parsedU, err := strconv.ParseUint(s, 10, 64); err == nil {
					uVals = append(uVals, parsedU)
				} else if fv, errF := strconv.ParseFloat(s, 64); errF == nil && fv >= 0 && fv <= float64(math.MaxUint64) {
					uVals = append(uVals, uint64(fv))
				}
			case string:
				s := strings.TrimSpace(uv)
				if parsedU, err := strconv.ParseUint(s, 10, 64); err == nil {
					uVals = append(uVals, parsedU)
				} else if fv, errF := strconv.ParseFloat(s, 64); errF == nil && fv >= 0 && fv <= float64(math.MaxUint64) {
					uVals = append(uVals, uint64(fv))
				}
			default:
				if iv, ok := isIntegerValuePainless(it); ok && iv >= 0 {
					uVals = append(uVals, uint64(iv)) // #nosec G115 -- guarded iv >= 0
				} else if fv, ok := toFloat64(it); ok && fv >= 0 {
					uVals = append(uVals, uint64(fv))
				}
			}
		}
		sort.Slice(uVals, func(i, j int) bool { return uVals[i] < uVals[j] })
		out := make([]any, len(uVals))
		for i, u := range uVals {
			out[i] = newPainlessBigInteger(new(big.Int).SetUint64(u))
		}
		return out

	case "long", "integer", "int", "short", "byte":
		vals := make([]int64, 0, len(items))
		for _, it := range items {
			if iv, ok := isIntegerValuePainless(it); ok {
				vals = append(vals, iv)
			} else if fv, ok := toFloat64(it); ok {
				vals = append(vals, int64(fv))
			}
		}
		sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
		out := make([]any, len(vals))
		for i, v := range vals {
			out[i] = v
		}
		return out

	case "double", "float", "half_float", "scaled_float":
		vals := make([]float64, 0, len(items))
		for _, it := range items {
			if fv, ok := toFloat64WithRawPainless(it); ok {
				switch ft {
				case "half_float":
					fv = float64(QuantizeHalfFloat(fv))
				case "float":
					fv = float64(float32(fv))
				}
				vals = append(vals, fv)
			}
		}
		sort.Slice(vals, func(i, j int) bool { return compareJavaDoubleTotalOrderPainless(vals[i], vals[j]) < 0 })
		out := make([]any, len(vals))
		for i, v := range vals {
			if forFieldsAPI && (ft == "float" || ft == "half_float") {
				out[i] = float32(v)
			} else {
				out[i] = v
			}
		}
		return out

	case "date", "date_nanos":
		isNano := ft == "date_nanos"
		vals := make([]*ZonedDateTimeVal, 0, len(items))
		for _, it := range items {
			if z, ok := parseDocDateWithMappingFormatRound61(it, dateFmt, isNano); ok {
				vals = append(vals, z)
			}
		}
		sort.Slice(vals, func(i, j int) bool { return vals[i].Time.Before(vals[j].Time) })
		out := make([]any, len(vals))
		for i, v := range vals {
			out[i] = v
		}
		return out

	case "geo_point":
		vals := make([]*GeoPointVal, 0, len(items))
		for _, it := range items {
			if gp, ok := parseGeoPointValRound60(it); ok {
				if quantizeGeo {
					qLat, qLon := QuantizeLuceneGeoPoint(gp.Lat, gp.Lon)
					gp = &GeoPointVal{Lat: qLat, Lon: qLon}
				}
				vals = append(vals, gp)
			}
		}
		sort.Slice(vals, func(i, j int) bool {
			if vals[i].Lat != vals[j].Lat {
				return vals[i].Lat < vals[j].Lat
			}
			return vals[i].Lon < vals[j].Lon
		})
		out := make([]any, len(vals))
		for i, v := range vals {
			out[i] = v
		}
		return out

	case "binary":
		rawBytes := make([][]byte, 0, len(items))
		for _, it := range items {
			if b, ok := decodeBase64BinaryRound60(it); ok {
				rawBytes = append(rawBytes, b)
			}
		}
		sort.Slice(rawBytes, func(i, j int) bool { return bytes.Compare(rawBytes[i], rawBytes[j]) < 0 })
		out := make([]any, len(rawBytes))
		for i, b := range rawBytes {
			if forFieldsAPI {
				out[i] = newByteBufferValRound60(b)
			} else {
				out[i] = newBytesRefValRound60(b)
			}
		}
		return out

	case "boolean", "boolean_dup":
		dedup := ft == "boolean" && !keepBoolDups
		vals := make([]bool, 0, len(items))
		for _, it := range items {
			switch bv := it.(type) {
			case bool:
				vals = append(vals, bv)
			case string:
				vals = append(vals, strings.EqualFold(strings.TrimSpace(bv), "true"))
			}
		}
		sort.Slice(vals, func(i, j int) bool { return !vals[i] && vals[j] })
		out := make([]any, 0, len(vals))
		for i, v := range vals {
			if dedup && i > 0 && vals[i-1] == v {
				continue
			}
			out = append(out, v)
		}
		return out

	case "ip":
		type ipEntry struct {
			addr netip.Addr
			str  string
		}
		entries := make([]ipEntry, 0, len(items))
		for _, it := range items {
			if ipV, isIPV := it.(*IPAddressVal); isIPV && ipV != nil {
				entries = append(entries, ipEntry{addr: ipV.Addr, str: ipV.String()})
				continue
			}
			s := strings.TrimSpace(fmt.Sprintf("%v", it))
			if addr, err := netip.ParseAddr(s); err == nil {
				entries = append(entries, ipEntry{addr: addr, str: addr.String()})
			} else {
				entries = append(entries, ipEntry{str: s})
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].addr.IsValid() && entries[j].addr.IsValid() {
				return entries[i].addr.Compare(entries[j].addr) < 0
			}
			return entries[i].str < entries[j].str
		})
		out := make([]any, 0, len(entries))
		for i, e := range entries {
			if i > 0 && entries[i-1].str == e.str {
				continue
			}
			if forFieldsAPI && e.addr.IsValid() {
				if ipVal, pErr := ParseIPAddressVal(e.str); pErr == nil {
					out = append(out, ipVal)
					continue
				}
			}
			out = append(out, e.str)
		}
		return out

	case "keyword", "constant_keyword", "wildcard":
		strs := make([]string, 0, len(items))
		for _, it := range items {
			strs = append(strs, fmt.Sprintf("%v", it))
		}
		sort.Strings(strs)
		out := make([]any, 0, len(strs))
		for i, s := range strs {
			if i > 0 && strs[i-1] == s {
				continue
			}
			out = append(out, s)
		}
		return out

	case "text", "match_only_text":
		if forFieldsAPI {
			strs := make([]string, 0, len(items))
			for _, it := range items {
				strs = append(strs, fmt.Sprintf("%v", it))
			}
			sort.Strings(strs)
			out := make([]any, len(strs))
			for i, s := range strs {
				out[i] = s
			}
			return out
		}
		tokens := make([]string, 0, len(items)*2)
		seenTok := make(map[string]bool)
		for _, it := range items {
			for _, tok := range tokenizeStandardAnalyzerWordsRound61(fmt.Sprintf("%v", it)) {
				if tok != "" && !seenTok[tok] {
					seenTok[tok] = true
					tokens = append(tokens, tok)
				}
			}
		}
		sort.Strings(tokens)
		out := make([]any, len(tokens))
		for i, t := range tokens {
			out[i] = t
		}
		return out
	}

	return items
}

func inferImplicitDocValueWrapperRound60(fieldPath string, items []any) []any {
	if len(items) == 0 {
		return items
	}
	// If already wrapped, preserve as-is
	switch items[0].(type) {
	case *ZonedDateTimeVal, *GeoPointVal, *BytesRefVal, *ByteBufferVal, *painlessBigInteger:
		return items
	}
	cleanName := strings.ToLower(strings.ReplaceAll(fieldPath, "\x00", "."))
	if lastDot := strings.LastIndexByte(cleanName, '.'); lastDot >= 0 {
		cleanName = cleanName[lastDot+1:]
	}
	// Heuristic wrapping when explicit `__field_types` was not supplied by caller,
	// while avoiding wrapping plain keyword strings unless clearly temporal/geo!
	if strings.Contains(cleanName, "date") || strings.Contains(cleanName, "time") || cleanName == "nanos" || strings.HasSuffix(cleanName, "_at") {
		allDates := true
		zVals := make([]*ZonedDateTimeVal, 0, len(items))
		isNano := strings.Contains(cleanName, "nano")
		for _, it := range items {
			z, ok := parseZonedDateTimeValRound60(it, isNano)
			if !ok {
				allDates = false
				break
			}
			zVals = append(zVals, z)
		}
		if allDates && len(zVals) > 0 {
			sort.Slice(zVals, func(i, j int) bool { return zVals[i].Time.Before(zVals[j].Time) })
			out := make([]any, len(zVals))
			for i, z := range zVals {
				out[i] = z
			}
			return out
		}
	}
	if cleanName == "geo" || cleanName == "point" || cleanName == "location" || strings.Contains(cleanName, "geo_point") ||
		(len(cleanName) == 2 && cleanName[0] == 'p' && cleanName[1] >= '0' && cleanName[1] <= '9') {
		allGeo := true
		gVals := make([]*GeoPointVal, 0, len(items))
		for _, it := range items {
			g, ok := parseGeoPointValRound60(it)
			if !ok {
				allGeo = false
				break
			}
			gVals = append(gVals, g)
		}
		if allGeo && len(gVals) > 0 {
			sort.Slice(gVals, func(i, j int) bool {
				if gVals[i].Lat != gVals[j].Lat {
					return gVals[i].Lat < gVals[j].Lat
				}
				return gVals[i].Lon < gVals[j].Lon
			})
			out := make([]any, len(gVals))
			for i, g := range gVals {
				out[i] = g
			}
			return out
		}
	}
	// Also wrap explicit `{lat, lon}` map objects anywhere in `doc[...]`
	if m, isMap := items[0].(map[string]any); isMap {
		if _, hasLat := m["lat"]; hasLat {
			if _, hasLon := m["lon"]; hasLon {
				gVals := make([]*GeoPointVal, 0, len(items))
				allGeo := true
				for _, it := range items {
					g, ok := parseGeoPointValRound60(it)
					if !ok {
						allGeo = false
						break
					}
					gVals = append(gVals, g)
				}
				if allGeo {
					out := make([]any, len(gVals))
					for i, g := range gVals {
						out[i] = g
					}
					return out
				}
			}
		}
	}
	if cleanName == "binary" || strings.HasSuffix(cleanName, "_binary") {
		out := make([]any, 0, len(items))
		rawB := make([][]byte, 0, len(items))
		for _, it := range items {
			if b, ok := decodeBase64BinaryRound60(it); ok {
				rawB = append(rawB, b)
			}
		}
		if len(rawB) == len(items) {
			sort.Slice(rawB, func(i, j int) bool { return bytes.Compare(rawB[i], rawB[j]) < 0 })
			for _, b := range rawB {
				out = append(out, newBytesRefValRound60(b))
			}
			return out
		}
	}
	return items
}

func lookupFieldFormatFromMapsRound61(sourceMap, params map[string]any, fieldPath string) string {
	clean := strings.ReplaceAll(fieldPath, "\x00", ".")
	for _, m := range []map[string]any{params, sourceMap} {
		if m == nil {
			continue
		}
		if fm, ok := m["__field_formats"].(map[string]string); ok && fm != nil {
			if f := fm[clean]; f != "" {
				return f
			}
		}
	}
	return ""
}

func isGeoQuantizeEnabledRound61(sourceMap, params map[string]any) bool {
	for _, m := range []map[string]any{params, sourceMap} {
		if m != nil {
			if q, ok := m["__quantize_geo_point"].(bool); ok && q {
				return true
			}
		}
	}
	return false
}

func isKeepBooleanDupsEnabledRound61(sourceMap, params map[string]any) bool {
	for _, m := range []map[string]any{params, sourceMap} {
		if m != nil {
			if b, ok := m["__keep_boolean_dups"].(bool); ok {
				return b
			}
			if b, ok := m["__is_es8"].(bool); ok && b {
				return true
			}
		}
	}
	return false
}

func lookupHitMetaLongRound61(sourceMap, params map[string]any, name string) (int64, bool) {
	var keys []string
	switch name {
	case "_version":
		keys = []string{"__meta_version", "_ctx_version"}
	case "_seq_no":
		keys = []string{"__meta_seq_no"}
	case "_primary_term":
		keys = []string{"__meta_primary_term"}
	default:
		return 0, false
	}
	for _, m := range []map[string]any{sourceMap, params} {
		if m == nil {
			continue
		}
		for _, k := range keys {
			if raw, exists := m[k]; exists && raw != nil {
				if iv, ok := toInt64Painless(raw); ok {
					return iv, true
				}
			}
		}
	}
	return 0, false
}

func resolveDocValuesSliceWithParamsRound60(sourceMap, params map[string]any, fieldPath string) ([]any, error) {
	cleanPath := strings.ReplaceAll(fieldPath, "\x00", ".")
	if err := checkStrictDocFieldMappingRound60(sourceMap, params, cleanPath); err != nil {
		return nil, err
	}
	if err := checkDocValuesAccessGuardRound61(params, cleanPath); err != nil {
		return nil, err
	}
	if err := checkDocValuesAccessGuardRound61(sourceMap, cleanPath); err != nil {
		return nil, err
	}
	if cleanPath == "_version" || cleanPath == "_seq_no" || cleanPath == "_primary_term" {
		if mv, ok := lookupHitMetaLongRound61(sourceMap, params, cleanPath); ok {
			return []any{mv}, nil
		}
	}
	for _, m := range []map[string]any{params, sourceMap} {
		if m != nil {
			if fdMap, ok := m["__fielddata_tokens"].(map[string][]string); ok && fdMap != nil {
				if toks, exists := fdMap[cleanPath]; exists {
					out := make([]any, len(toks))
					for i, t := range toks {
						out[i] = t
					}
					return out, nil
				}
			}
		}
	}
	if rootField, subPath, isFlat := resolveMappedFlattenedBaseRound61(params, cleanPath); isFlat {
		var raw map[string]any
		if rawSrc, ok := rawSourceFromSourceMapPainless(sourceMap); ok && rawSrc != nil {
			raw = rawSrc
		} else {
			raw = sourceMap
		}
		rootObj := resolveParamPath(raw, strings.Split(rootField, "."))
		return ExtractFlattenedLeafStrings(rootObj, subPath), nil
	}
	if rootField, subPath, isFlat := resolveMappedFlattenedBaseRound61(sourceMap, cleanPath); isFlat {
		rootObj := resolveParamPath(sourceMap, strings.Split(rootField, "."))
		return ExtractFlattenedLeafStrings(rootObj, subPath), nil
	}
	rawSlice := resolveDocValuesSlice(sourceMap, fieldPath)
	if len(rawSlice) == 0 {
		return rawSlice, nil
	}
	if _, already := rawSlice[0].(*ZonedDateTimeVal); already {
		return rawSlice, nil
	}
	if _, already := rawSlice[0].(*GeoPointVal); already {
		return rawSlice, nil
	}
	if _, already := rawSlice[0].(*BytesRefVal); already {
		return rawSlice, nil
	}
	if _, already := rawSlice[0].(*painlessBigInteger); already {
		return rawSlice, nil
	}
	ftMap := extractFieldTypesFromMapsRound60(sourceMap, params)
	if ft := lookupFieldTypeRound60(ftMap, fieldPath); ft != "" {
		keepBoolDups := isKeepBooleanDupsEnabledRound61(sourceMap, params)
		dateFmt := lookupFieldFormatFromMapsRound61(sourceMap, params, fieldPath)
		quantizeGeo := isGeoQuantizeEnabledRound61(sourceMap, params)
		// Check if raw value in sourceMap was `[lon, lat]` before resolveDocValuesSlice flattened it
		rawVal := resolveParamPath(sourceMap, strings.Split(fieldPath, "."))
		if rawVal != nil {
			return normalizeSingleFieldDocValuesWithOptsRound61(rawVal, ft, keepBoolDups, false, dateFmt, quantizeGeo), nil
		}
		return normalizeSingleFieldDocValuesWithOptsRound61(rawSlice, ft, keepBoolDups, false, dateFmt, quantizeGeo), nil
	}
	// Check if raw value in sourceMap was `[lon, lat]` for geo_point heuristic
	if rawVal := resolveParamPath(sourceMap, strings.Split(fieldPath, ".")); rawVal != nil {
		cleanName := strings.ToLower(strings.ReplaceAll(fieldPath, "\x00", "."))
		if cleanName == "geo" || cleanName == "point" || cleanName == "location" || strings.Contains(cleanName, "geo_point") {
			return normalizeSingleFieldDocValuesWithOptsRound61(rawVal, "geo_point", false, false, "", isGeoQuantizeEnabledRound61(sourceMap, params)), nil
		}
	}
	return inferImplicitDocValueWrapperRound60(fieldPath, rawSlice), nil
}

// FieldVal models Elasticsearch 8's `field('name')` read/write Fields API object.
type FieldVal struct {
	Name      string
	Values    []any
	Root      map[string]any
	Params    map[string]any
	FieldType string
}

// FieldDocVal models an object sub-document wrapper returned by `field('records').doc(i)` / `.docs()`.
type FieldDocVal struct {
	Doc    map[string]any
	Params map[string]any
}

func resolveFieldValRound60(name string, sourceMap, params map[string]any) (*FieldVal, error) {
	if err := checkStrictDocFieldMappingRound60(sourceMap, params, name); err != nil {
		return nil, err
	}
	if err := checkFieldsAPIAccessGuardRound61(params, name); err != nil {
		return nil, err
	}
	if err := checkFieldsAPIAccessGuardRound61(sourceMap, name); err != nil {
		return nil, err
	}
	var root map[string]any
	if rawSrc, ok := rawSourceFromSourceMapPainless(sourceMap); ok && rawSrc != nil {
		root = rawSrc
	} else {
		root = sourceMap
	}
	if name == "_version" || name == "_seq_no" || name == "_primary_term" {
		var vals []any
		if mv, ok := lookupHitMetaLongRound61(sourceMap, params, name); ok {
			vals = []any{mv}
		} else {
			vals = []any{}
		}
		return &FieldVal{
			Name:      name,
			Values:    vals,
			Root:      root,
			Params:    params,
			FieldType: "long",
		}, nil
	}
	ftMap := extractFieldTypesFromMapsRound60(sourceMap, params)
	ft := lookupFieldTypeRound60(ftMap, name)
	if ft == "" {
		if rootField, subPath, isFlat := resolveMappedFlattenedBaseRound61(params, name); isFlat {
			rootObj := resolveParamPath(root, strings.Split(rootField, "."))
			return &FieldVal{
				Name:      name,
				Values:    ExtractFlattenedLeafStrings(rootObj, subPath),
				Root:      root,
				Params:    params,
				FieldType: "flattened",
			}, nil
		}
		if rootField, subPath, isFlat2 := resolveMappedFlattenedBaseRound61(sourceMap, name); isFlat2 {
			rootObj := resolveParamPath(root, strings.Split(rootField, "."))
			return &FieldVal{
				Name:      name,
				Values:    ExtractFlattenedLeafStrings(rootObj, subPath),
				Root:      root,
				Params:    params,
				FieldType: "flattened",
			}, nil
		}
	}

	var vals []any
	var rawVal any
	if root != nil {
		rawVal = resolveParamPath(root, strings.Split(name, "."))
	}
	if rawVal == nil && sourceMap != nil && (root == nil || reflect.ValueOf(sourceMap).Pointer() != reflect.ValueOf(root).Pointer()) {
		rawVal = resolveParamPath(sourceMap, strings.Split(name, "."))
	}
	if rawVal != nil {
		keepBoolDups := true
		dateFmt := lookupFieldFormatFromMapsRound61(sourceMap, params, name)
		quantizeGeo := isGeoQuantizeEnabledRound61(sourceMap, params)
		if ft != "" {
			vals = normalizeSingleFieldDocValuesWithOptsRound61(rawVal, ft, keepBoolDups, true, dateFmt, quantizeGeo)
		} else {
			cleanLower := strings.ToLower(name)
			if cleanLower == "binary" || strings.HasSuffix(cleanLower, "_binary") {
				vals = normalizeSingleFieldDocValuesWithOptsRound61(rawVal, "binary", true, true, "", false)
			} else {
				vals = inferImplicitDocValueWrapperRound60(name, flattenRawFieldItemsRound60(rawVal, false))
				for i, v := range vals {
					if br, isBR := v.(*BytesRefVal); isBR {
						vals[i] = newByteBufferValRound60(br.slice())
					}
				}
			}
		}
	} else {
		vals = []any{}
	}
	return &FieldVal{
		Name:      name,
		Values:    vals,
		Root:      root,
		Params:    params,
		FieldType: ft,
	}, nil
}

func (fv *FieldVal) refreshValuesRound60() {
	if fv == nil || fv.Root == nil {
		return
	}
	raw := resolveParamPath(fv.Root, strings.Split(fv.Name, "."))
	if raw == nil {
		fv.Values = []any{}
		return
	}
	if fv.FieldType != "" {
		fv.Values = normalizeSingleFieldDocValuesRound60(raw, fv.FieldType, true, true)
		return
	}
	fv.Values = flattenRawFieldItemsRound60(raw, false)
}

func (fv *FieldVal) Size() int64 {
	if fv == nil {
		return 0
	}
	return int64(len(fv.Values))
}

func (fv *FieldVal) IsEmpty() bool {
	return fv == nil || len(fv.Values) == 0
}

func (fv *FieldVal) GetDefault(defaultVal any) any {
	if fv == nil || len(fv.Values) == 0 {
		return coerceFieldValDefaultRound62(fv, defaultVal)
	}
	return fv.Values[0]
}

func (fv *FieldVal) GetAt(idx int, defaultVal any) any {
	if fv == nil || idx < 0 || idx >= len(fv.Values) {
		return coerceFieldValDefaultRound62(fv, defaultVal)
	}
	return fv.Values[idx]
}

func (fv *FieldVal) Exists() bool {
	if fv == nil || fv.Root == nil {
		return false
	}
	return hasPathInMapRound60(fv.Root, strings.Split(fv.Name, "."))
}

func (fv *FieldVal) Set(val any) {
	if fv == nil || fv.Root == nil {
		return
	}
	setValueAtPath(fv.Root, strings.Split(fv.Name, "."), val)
	fv.refreshValuesRound60()
}

func (fv *FieldVal) Remove() bool {
	if fv == nil || fv.Root == nil {
		return false
	}
	removed := deletePathInMapRound60(fv.Root, strings.Split(fv.Name, "."))
	fv.Values = []any{}
	return removed
}

func (fv *FieldVal) String() string {
	if fv == nil {
		return "[]"
	}
	return FormatValueSafe(fv.Values)
}

func hasPathInMapRound60(root map[string]any, segs []string) bool {
	if root == nil || len(segs) == 0 {
		return false
	}
	var curr any = root
	for i, seg := range segs {
		m, ok := curr.(map[string]any)
		if !ok {
			return false
		}
		v, exists := m[seg]
		if !exists {
			if flat, okFlat := m[strings.Join(segs[i:], ".")]; okFlat {
				_ = flat
				return true
			}
			return false
		}
		if i == len(segs)-1 {
			return true
		}
		curr = v
	}
	return false
}

func deletePathInMapRound60(root map[string]any, segs []string) bool {
	if root == nil || len(segs) == 0 {
		return false
	}
	if len(segs) == 1 {
		_, exists := root[segs[0]]
		delete(root, segs[0])
		return exists
	}
	parent := resolveParamPath(root, segs[:len(segs)-1])
	if pm, ok := parent.(map[string]any); ok {
		last := segs[len(segs)-1]
		_, exists := pm[last]
		delete(pm, last)
		return exists
	}
	flat := strings.Join(segs, ".")
	if _, exists := root[flat]; exists {
		delete(root, flat)
		return true
	}
	return false
}

// PainlessLambda represents a first-class lambda (`() -> expr`, `(a, b) -> { ... }`)
// or method reference (`String::valueOf`) passed as a functional-interface value
// (`Supplier`, `Function`, `BiFunction`, `Predicate`, `Consumer`, `Runnable`, etc.).
type PainlessLambda struct {
	ParamTypes []string
	ParamNames []string
	Body       string
	IsBlock    bool
	MethodRef  string
	Captured   map[string]any
	SourceMap  map[string]any
}

func (pl *PainlessLambda) String() string {
	if pl == nil {
		return "null"
	}
	if pl.MethodRef != "" {
		return "Lambda[" + pl.MethodRef + "]"
	}
	return fmt.Sprintf("Lambda[(%s) -> ...]", strings.Join(pl.ParamNames, ", "))
}

// Invoke evaluates the captured lambda or method reference with `args`.
func (pl *PainlessLambda) Invoke(args []any, sourceMap, callerParams map[string]any, depth int) (any, error) {
	return pl.InvokeWithArgExprs(args, nil, sourceMap, callerParams, depth)
}

// InvokeWithArgExprs evaluates the captured lambda or method reference with `args`
// and propagates in-place slice header growths back to caller argument/captured bindings.
func (pl *PainlessLambda) InvokeWithArgExprs(args []any, argExprs []string, sourceMap, callerParams map[string]any, depth int) (any, error) {
	if pl == nil {
		return nil, &painlessExceptionError{exType: "NullPointerException", message: "Cannot invoke null functional interface"}
	}
	if sourceMap == nil {
		sourceMap = pl.SourceMap
	}
	baseParams := pl.Captured
	if baseParams == nil {
		baseParams = callerParams
	}
	if pl.MethodRef != "" {
		return invokeMethodReferenceRound60(pl.MethodRef, args, sourceMap, baseParams, depth+1)
	}
	if len(args) != len(pl.ParamNames) {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Lambda expected %d argument(s), got %d", len(pl.ParamNames), len(args)),
		}
	}
	budget := getOrInitEvalBudget(callerParams)
	if callerParams == nil && baseParams != nil {
		budget = getOrInitEvalBudget(baseParams)
	}
	scope := make(map[string]any, len(baseParams)+len(args)+4)
	for k, v := range baseParams {
		scope[k] = v
	}
	scope["__eval_budget"] = budget
	delete(scope, "_return_val")
	delete(scope, "_last_expr_val")
	paramSet := make(map[string]bool, len(pl.ParamNames))
	for i, pName := range pl.ParamNames {
		paramSet[pName] = true
		argVal := args[i]
		if i < len(pl.ParamTypes) && pl.ParamTypes[i] != "" && pl.ParamTypes[i] != "def" {
			coerced, err := validateAndCoerceSignatureValueRound59(pl.ParamTypes[i], argVal, "", scope, budget)
			if err != nil {
				return nil, err
			}
			argVal = coerced
		}
		scope[pName] = argVal
	}
	syncMutatedSlices := func() {
		for i, pName := range pl.ParamNames {
			oldSlice, wasSlice := args[i].([]any)
			newSlice, isNewSlice := scope[pName].([]any)
			if !wasSlice || !isNewSlice {
				continue
			}
			if lambdaBodyReassignsIdentRound60(pl.Body, pName) {
				continue
			}
			if i < len(argExprs) && callerParams != nil {
				rawArg := strings.TrimSpace(argExprs[i])
				if reIdentOnly.MatchString(rawArg) && !strings.HasPrefix(rawArg, "__") {
					if _, exists := callerParams[rawArg]; exists {
						callerParams[rawArg] = newSlice
						syncLocalVarAlias(sourceMap, callerParams, rawArg)
					}
				}
			}
			if callerParams != nil {
				syncSliceHeaderAliasesRound60(callerParams, oldSlice, newSlice)
			}
		}
		for k, oldV := range pl.Captured {
			if paramSet[k] || strings.HasPrefix(k, "__") {
				continue
			}
			oldSlice, wasSlice := oldV.([]any)
			newSlice, isNewSlice := scope[k].([]any)
			if !wasSlice || !isNewSlice {
				continue
			}
			pl.Captured[k] = newSlice
			if callerParams != nil {
				if _, exists := callerParams[k]; exists {
					callerParams[k] = newSlice
					syncLocalVarAlias(sourceMap, callerParams, k)
				}
				syncSliceHeaderAliasesRound60(callerParams, oldSlice, newSlice)
			}
		}
	}
	if pl.IsBlock {
		ctxOp := ""
		err := execBlock(sourceMap, pl.Body, scope, &ctxOp, budget)
		syncMutatedSlices()
		if err != nil && !errors.Is(err, errPainlessReturn) {
			return nil, err
		}
		if retVal, hasRet := scope["_return_val"]; hasRet {
			return unwrapEmptyOptionalPainless(retVal), nil
		}
		if lastVal, hasLast := scope["_last_expr_val"]; hasLast {
			return unwrapEmptyOptionalPainless(lastVal), nil
		}
		return nil, nil
	}
	// Expression body: handle boolean relational/equality expressions cleanly as well as RHS values
	val, err := evalLambdaExprBodyRound60(sourceMap, pl.Body, scope, depth+1)
	syncMutatedSlices()
	return unwrapEmptyOptionalPainless(val), err
}

func lambdaBodyReassignsIdentRound60(body, ident string) bool {
	if ident == "" || !strings.Contains(body, ident) {
		return false
	}
	for i := 0; i+len(ident) < len(body); i++ {
		idx := strings.Index(body[i:], ident)
		if idx < 0 {
			return false
		}
		pos := i + idx
		if pos > 0 && isIdentCharRound60(body[pos-1]) {
			i = pos + len(ident) - 1
			continue
		}
		after := pos + len(ident)
		if after < len(body) && isIdentCharRound60(body[after]) {
			i = after - 1
			continue
		}
		rest := strings.TrimSpace(body[after:])
		if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") && !strings.HasPrefix(rest, "=~") {
			return true
		}
		i = after - 1
	}
	return false
}

func isIdentCharRound60(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '$'
}

func evalLambdaExprBodyRound60(sourceMap map[string]any, body string, scope map[string]any, depth int) (any, error) {
	trimmed := strings.TrimSpace(body)
	if hasTopLevelBooleanOrRegexOp(trimBalancedParens(trimmed)) && findTopLevelOpPainless(trimmed, "?") < 0 && findTopLevelOpPainless(trimmed, "?:") < 0 {
		return evalConditionDepthErr(sourceMap, trimmed, scope, depth)
	}
	return evalRHSExprDepth(sourceMap, trimmed, scope, depth)
}

func invokeMethodReferenceRound60(mRef string, args []any, sourceMap, params map[string]any, depth int) (any, error) {
	idx := strings.Index(mRef, "::")
	if idx <= 0 {
		return nil, fmt.Errorf("invalid method reference: %s", mRef)
	}
	target := strings.TrimSpace(mRef[:idx])
	method := strings.TrimSpace(mRef[idx+2:])
	tmpParams := make(map[string]any, len(params)+len(args)+2)
	for k, v := range params {
		tmpParams[k] = v
	}
	argNames := make([]string, len(args))
	for i, a := range args {
		an := fmt.Sprintf("__mref_arg_%d", i)
		tmpParams[an] = a
		argNames[i] = an
	}
	if method == "new" {
		expr := fmt.Sprintf("new %s(%s)", target, strings.Join(argNames, ", "))
		return evalRHSExprDepth(sourceMap, expr, tmpParams, depth+1)
	}
	if isKnownStaticClassIdentifierRound58(target, params) {
		expr := fmt.Sprintf("%s.%s(%s)", target, method, strings.Join(argNames, ", "))
		if res, handled, err := evalStaticCallPainless(sourceMap, expr, tmpParams, depth+1); handled {
			return res, err
		}
		// Instance method on first arg (e.g., `String::toLowerCase`, `Object::toString`)
		if len(argNames) >= 1 {
			instExpr := fmt.Sprintf("%s.%s(%s)", argNames[0], method, strings.Join(argNames[1:], ", "))
			return evalRHSExprDepth(sourceMap, instExpr, tmpParams, depth+1)
		}
	}
	expr := fmt.Sprintf("%s.%s(%s)", target, method, strings.Join(argNames, ", "))
	return evalRHSExprDepth(sourceMap, expr, tmpParams, depth+1)
}

func tryParseTopLevelLambdaOrMethodRefRound60(sourceMap map[string]any, rhs string, params map[string]any) (*PainlessLambda, bool) {
	s := strings.TrimSpace(rhs)
	if s == "" {
		return nil, false
	}
	// Check top-level `::` method reference (`String::valueOf`, `Objects::nonNull`, `x::toString`)
	if mrIdx := findTopLevelOpPainless(s, "::"); mrIdx > 0 {
		lhs := strings.TrimSpace(s[:mrIdx])
		mName := strings.TrimSpace(s[mrIdx+2:])
		if reIdentOnly.MatchString(mName) && lhs != "" && !strings.ContainsAny(lhs, " ;{}?") {
			snap := snapshotLambdaCapturedParamsRound60(params)
			return &PainlessLambda{
				MethodRef: s,
				Captured:  snap,
				SourceMap: sourceMap,
			}, true
		}
	}
	// Check top-level `->` lambda (`() -> ...`, `x -> ...`, `(int a, int b) -> { ... }`)
	arrowIdx := findTopLevelOpPainless(s, "->")
	if arrowIdx <= 0 {
		return nil, false
	}
	header := strings.TrimSpace(s[:arrowIdx])
	bodyRaw := strings.TrimSpace(s[arrowIdx+2:])
	if bodyRaw == "" {
		return nil, false
	}
	var pTypes, pNames []string
	if strings.HasPrefix(header, "(") && strings.HasSuffix(header, ")") && findMatchingDelimiter(header, 0, '(', ')') == len(header)-1 {
		inner := strings.TrimSpace(header[1 : len(header)-1])
		if inner != "" {
			pTypes, pNames = parseParamListTypesAndNamesRound59(inner)
			if len(pNames) == 0 {
				return nil, false
			}
			for _, pn := range pNames {
				if !reIdentOnly.MatchString(pn) {
					return nil, false
				}
			}
		}
	} else if reIdentOnly.MatchString(header) && !isPainlessReservedKeyword(header) {
		pTypes = []string{"def"}
		pNames = []string{header}
	} else {
		return nil, false
	}

	isBlock := false
	body := bodyRaw
	if strings.HasPrefix(bodyRaw, "{") {
		if findMatchingDelimiter(bodyRaw, 0, '{', '}') != len(bodyRaw)-1 {
			return nil, false
		}
		isBlock = true
		body = strings.TrimSpace(bodyRaw[1 : len(bodyRaw)-1])
	}
	snap := snapshotLambdaCapturedParamsRound60(params)
	return &PainlessLambda{
		ParamTypes: pTypes,
		ParamNames: pNames,
		Body:       body,
		IsBlock:    isBlock,
		Captured:   snap,
		SourceMap:  sourceMap,
	}, true
}

func snapshotLambdaCapturedParamsRound60(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}
	snap := make(map[string]any, len(params))
	for k, v := range params {
		snap[k] = v
	}
	return snap
}

func shouldSkipDynamicGetRewriteRound60(res string, recvStart, getIdx int, recvToken string, params map[string]any) bool {
	prefix := strings.TrimSpace(res[:getIdx])
	if strings.Contains(prefix, "field(") || strings.Contains(prefix, "$(") {
		return true
	}
	if params != nil && recvToken != "" {
		rootSeg := strings.SplitN(recvToken, ".", 2)[0]
		if v, exists := params[rootSeg]; exists {
			switch v.(type) {
			case *FieldVal, *FieldDocVal, *ByteBufferVal, *BytesRefVal, *PainlessLambda, *ZonedDateTimeVal, *painlessOptional,
				*DenseVectorFieldVal, *DenseVectorVal, *IPAddressVal, *GeoBoundingBoxVal:
				return true
			}
		}
	}
	return false
}

// ============================================================================
// F23: `script_score` Built-In Functions (Saturation, Sigmoid, Decay,
//      `randomScore`, Dense-Vector Similarity & `vectorValue`/`magnitude`)
// ============================================================================

func evalSaturationRound60(val, k float64) (float64, error) {
	if k <= 0 || math.IsNaN(k) || math.IsInf(k, 0) {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "saturation [k] must be strictly positive"}
	}
	if val < 0 || math.IsNaN(val) {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "saturation [value] must not be negative"}
	}
	return val / (k + val), nil
}

func evalSigmoidRound60(val, k, a float64) (float64, error) {
	if k <= 0 || math.IsNaN(k) || math.IsInf(k, 0) {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "sigmoid [k] must be strictly positive"}
	}
	if a <= 0 || math.IsNaN(a) || math.IsInf(a, 0) {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "sigmoid [a] must be strictly positive"}
	}
	if val < 0 || math.IsNaN(val) {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "sigmoid [value] must not be negative"}
	}
	vp := math.Pow(val, a)
	kp := math.Pow(k, a)
	return vp / (kp + vp), nil
}

func computeDecayScoreRound60(kind string, dist, scale, offset, decay float64) (float64, error) {
	if scale <= 0 || math.IsNaN(scale) || math.IsInf(scale, 0) {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "decay [scale] must be > 0"}
	}
	if decay <= 0 || decay >= 1.0 || math.IsNaN(decay) {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "decay [decay] must be in (0, 1)"}
	}
	if offset < 0 || math.IsNaN(offset) {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "decay [offset] must be >= 0"}
	}
	d := math.Max(0.0, math.Abs(dist)-offset)
	if d == 0 {
		return 1.0, nil
	}
	switch kind {
	case "linear":
		s := scale / (1.0 - decay)
		return math.Max(0.0, (s-d)/s), nil
	case "exp":
		lambda := math.Log(decay) / scale
		return math.Exp(lambda * d), nil
	case "gauss":
		// ES GaussianDecayFunction: sigma^2 = -scale^2 / (2 * ln(decay)), score = exp(-0.5 * d^2 / sigma^2) = exp(ln(decay) * (d / scale)^2)
		ratio := d / scale
		return math.Exp(math.Log(decay) * ratio * ratio), nil
	default:
		return 0, fmt.Errorf("unknown decay mode: %s", kind)
	}
}

var reESDurationUnitRound60 = regexp.MustCompile(`(?i)^\s*([+-]?(?:\d+(?:\.\d+)?|\.\d+))\s*(nanos|ns|micros|us|ms|s|m|h|d|w)?\s*$`)

func parseESDurationMillisRound60(v any) (float64, error) {
	if f, ok := isRawFloatingValPainless(v); ok {
		return f, nil
	}
	if iv, ok := isIntegerValuePainless(v); ok {
		return float64(iv), nil
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	m := reESDurationUnitRound60.FindStringSubmatch(s)
	if m == nil {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse duration [%s]", s)}
	}
	num, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse duration [%s]", s)}
	}
	switch strings.ToLower(m[2]) {
	case "nanos", "ns":
		return num / 1e6, nil
	case "micros", "us":
		return num / 1e3, nil
	case "", "ms":
		return num, nil
	case "s":
		return num * 1000.0, nil
	case "m":
		return num * 60_000.0, nil
	case "h":
		return num * 3_600_000.0, nil
	case "d":
		return num * 86_400_000.0, nil
	case "w":
		return num * 7 * 86_400_000.0, nil
	default:
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("unknown duration unit [%s]", m[2])}
	}
}

var reESDistanceUnitRound60 = regexp.MustCompile(`(?i)^\s*([+-]?(?:\d+(?:\.\d+)?|\.\d+))\s*(nmi|NM|mi|miles|yd|yards|ft|feet|in|inch|km|kilometers|cm|centimeters|mm|millimeters|m|meters)?\s*$`)

func parseESDistanceMetersRound60(v any) (float64, error) {
	if f, ok := isRawFloatingValPainless(v); ok {
		return f, nil
	}
	if iv, ok := isIntegerValuePainless(v); ok {
		return float64(iv), nil
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	m := reESDistanceUnitRound60.FindStringSubmatch(s)
	if m == nil {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse distance [%s]", s)}
	}
	num, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse distance [%s]", s)}
	}
	switch strings.ToLower(m[2]) {
	case "", "m", "meters":
		return num, nil
	case "km", "kilometers":
		return num * 1000.0, nil
	case "mi", "miles":
		return num * 1609.344, nil
	case "nmi", "nm":
		return num * 1852.0, nil
	case "yd", "yards":
		return num * 0.9144, nil
	case "ft", "feet":
		return num * 0.3048, nil
	case "in", "inch":
		return num * 0.0254, nil
	case "cm", "centimeters":
		return num * 0.01, nil
	case "mm", "millimeters":
		return num * 0.001, nil
	default:
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("unknown distance unit [%s]", m[2])}
	}
}

func murmurHash3x8632Round60(data []byte, seed uint32) uint32 {
	const c1 uint32 = 0xcc9e2d51
	const c2 uint32 = 0x1b873593
	h1 := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4:])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k1 uint32
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
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(len(data)) // #nosec G115 -- bounded byte buffer length
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

func evalRandomScoreRound60(seed int64, fieldName string, hasField bool, sourceMap, params map[string]any) (float64, error) {
	var buf bytes.Buffer
	var seedBytes [8]byte
	binary.LittleEndian.PutUint64(seedBytes[:], uint64(seed)) // #nosec G115 -- deterministic seed hash bytes
	buf.Write(seedBytes[:])

	if hasField {
		if fieldName == "" {
			return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: "randomScore fieldName must not be empty"}
		}
		var fieldVal any
		switch fieldName {
		case "_seq_no":
			if sourceMap != nil {
				fieldVal = sourceMap["_seq_no"]
				if fieldVal == nil {
					fieldVal = sourceMap["__meta_seq_no"]
				}
			}
			if fieldVal == nil && params != nil {
				fieldVal = params["_seq_no"]
			}
			if fieldVal == nil && sourceMap != nil {
				fieldVal = sourceMap["__meta_id"]
				if fieldVal == nil {
					fieldVal = sourceMap["_id"]
				}
			}
		default:
			dv, err := resolveDocValuesSliceWithParamsRound60(sourceMap, params, fieldName)
			if err != nil {
				return 0, err
			}
			if len(dv) > 0 {
				fieldVal = dv[0]
			}
		}
		buf.WriteString(fieldName)
		buf.WriteByte(0)
		fmt.Fprintf(&buf, "%v", fieldVal)
	} else {
		// Lucene internal doc/id fallback so ranking is deterministic per document & seed
		var docSalt any
		if sourceMap != nil {
			for _, k := range []string{"__doc_id", "_seq_no", "__meta_id", "_id"} {
				if v, ok := sourceMap[k]; ok && v != nil {
					docSalt = v
					break
				}
			}
		}
		if docSalt == nil && params != nil {
			docSalt = params["_ctx_id"]
		}
		if docSalt != nil {
			fmt.Fprintf(&buf, "%v", docSalt)
		} else if sourceMap != nil {
			b, _ := json.Marshal(sourceMap)
			buf.Write(b)
		}
	}
	h := murmurHash3x8632Round60(buf.Bytes(), uint32(seed^(seed>>32))) // #nosec G115 -- deterministic 32-bit seed
	// Map 24-bit mantissa into [0.0, 1.0) matching Java Float/Double random normalization
	return float64(h>>8) / float64(1<<24), nil
}

func extractFloatVectorRound60(val any, sourceMap, params map[string]any, isDocArg bool) ([]float64, error) {
	if isDocArg {
		if fieldName, isStr := val.(string); isStr {
			if err := checkStrictDocFieldMappingRound60(sourceMap, params, fieldName); err != nil {
				return nil, err
			}
			var raw any
			if sourceMap != nil {
				raw = resolveParamPath(sourceMap, strings.Split(fieldName, "."))
			}
			if raw == nil {
				return nil, &painlessExceptionError{
					exType:  "ScriptException",
					message: fmt.Sprintf("A document doesn't have a value for a vector field [%s]!", fieldName),
				}
			}
			val = raw
		}
	}
	switch tv := val.(type) {
	case []float64:
		if len(tv) == 0 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "vector must not be empty"}
		}
		return tv, nil
	case []any:
		if len(tv) == 0 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "A document doesn't have a value for a vector field!"}
		}
		out := make([]float64, len(tv))
		for i, el := range tv {
			fv, ok := toFloat64WithRawPainless(el)
			if !ok {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("non-numeric vector element: %v", el)}
			}
			out[i] = fv
		}
		return out, nil
	default:
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("expected vector array/list or field name, got %T", val)}
	}
}

func evalVectorSimilarityRound60(fnName string, qArg, fArg any, sourceMap, params map[string]any) (float64, error) {
	if fieldStr, isFieldName := fArg.(string); isFieldName {
		return evalVectorSimilarityRound61(fnName, qArg, strings.TrimSpace(fieldStr), sourceMap, params)
	}
	qv, err := extractFloatVectorRound60(qArg, sourceMap, params, false)
	if err != nil {
		return 0, err
	}
	dv, err := extractFloatVectorRound60(fArg, sourceMap, params, true)
	if err != nil {
		return 0, err
	}
	if len(qv) != len(dv) {
		return 0, &painlessExceptionError{
			exType:  "ScriptException",
			message: fmt.Sprintf("The vector dimensions do not match: query vector has [%d] dimensions, document vector has [%d] dimensions", len(qv), len(dv)),
		}
	}
	switch fnName {
	case "dotProduct":
		var dot float64
		for i := range qv {
			dot += qv[i] * dv[i]
		}
		return dot, nil
	case "cosineSimilarity":
		var dot, normQ, normD float64
		for i := range qv {
			dot += qv[i] * dv[i]
			normQ += qv[i] * qv[i]
			normD += dv[i] * dv[i]
		}
		if normQ == 0 || normD == 0 {
			return 0, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: "cosineSimilarity cannot be calculated for zero-magnitude vectors",
			}
		}
		return dot / (math.Sqrt(normQ) * math.Sqrt(normD)), nil
	case "l1norm":
		var sum float64
		for i := range qv {
			sum += math.Abs(qv[i] - dv[i])
		}
		return sum, nil
	case "l2norm":
		var sumSq float64
		for i := range qv {
			d := qv[i] - dv[i]
			sumSq += d * d
		}
		return math.Sqrt(sumSq), nil
	default:
		return 0, fmt.Errorf("unknown vector function: %s", fnName)
	}
}

func docVectorValueAndMagnitudeRound60(sourceMap, params map[string]any, fieldPath string, wantMagnitude bool) (any, error) {
	fieldPath = strings.TrimSuffix(strings.TrimSuffix(fieldPath, ".value"), ".values")
	cleanField := strings.ReplaceAll(fieldPath, "\x00", ".")
	arr, mag, present, err := docVectorValueAndMagnitudeRound61(sourceMap, params, cleanField)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("A document doesn't have a value for a vector field [%s]!", cleanField),
		}
	}
	if wantMagnitude {
		return float64(mag), nil
	}
	return markTypedArraySliceRound59(getOrInitEvalBudget(params), arr, "float[]"), nil
}

// ============================================================================
// F24: Runtime-Field `emit(...)` Contexts (`EvalEmitContext`)
// ============================================================================

func normalizeEmitContextNameRound60(ctxType string) string {
	c := strings.ToLower(strings.TrimSpace(ctxType))
	c = strings.TrimSuffix(c, "_field")
	return c
}

func coerceAndRecordEmitRound60(budget *evalBudget, rawArgs []any) (any, error) {
	ctxKind := ""
	if budget != nil {
		ctxKind = normalizeEmitContextNameRound60(budget.emitContext)
	}
	if ctxKind == "composite" {
		return handleCompositeEmitRound62(budget, rawArgs)
	}
	if ctxKind == "" && len(rawArgs) == 2 {
		if _, isStr := rawArgs[0].(string); isStr {
			if _, okNum := toFloat64WithRawPainless(rawArgs[0]); !okNum {
				return handleCompositeEmitRound62(budget, rawArgs)
			}
		}
	}
	for _, a := range rawArgs {
		if isEmptyOptionalOrNilPainless(a) {
			return nil, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: "Cannot emit null value",
			}
		}
	}
	if len(rawArgs) == 2 {
		lat, ok1 := toFloat64WithRawPainless(rawArgs[0])
		lon, ok2 := toFloat64WithRawPainless(rawArgs[1])
		if !ok1 || !ok2 || math.IsNaN(lat) || math.IsNaN(lon) || math.IsInf(lat, 0) || math.IsInf(lon, 0) {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "geo_point emit(lat, lon) requires finite numeric coordinates"}
		}
		if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("illegal geo_point coordinates: lat=%v, lon=%v", lat, lon)}
		}
		if ctxKind == "geo_point" {
			pt := map[string]any{
				"type":        "Point",
				"coordinates": []any{lon, lat},
			}
			budget.emittedVals = append(budget.emittedVals, pt)
			return pt, nil
		}
		combined := fmt.Sprintf("%v,%v", rawArgs[0], rawArgs[1])
		if budget != nil {
			budget.emittedVals = append(budget.emittedVals, combined)
		}
		return combined, nil
	}
	if len(rawArgs) != 1 {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("emit() takes 1 or 2 arguments, got %d", len(rawArgs))}
	}
	v := rawArgs[0]
	switch ctxKind {
	case "boolean":
		bv, ok := v.(bool)
		if !ok {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot emit %T in boolean_field context", v)}
		}
		budget.emittedVals = append(budget.emittedVals, bv)
		return bv, nil
	case "long":
		var lv int64
		if iv, ok := isIntegerValuePainless(v); ok {
			lv = iv
		} else if fv, ok := toFloat64(v); ok && fv == math.Trunc(fv) {
			lv = int64(fv)
		} else {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot emit %v in long_field context", v)}
		}
		budget.emittedVals = append(budget.emittedVals, lv)
		return lv, nil
	case "double":
		fv, ok := toFloat64WithRawPainless(v)
		if !ok {
			return nil, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot emit %T in double_field context", v)}
		}
		budget.emittedVals = append(budget.emittedVals, fv)
		return fv, nil
	case "keyword":
		sv := FormatValueSafe(v)
		budget.emittedVals = append(budget.emittedVals, sv)
		return sv, nil
	case "date":
		var tm time.Time
		if iv, ok := isIntegerValuePainless(v); ok {
			tm = time.UnixMilli(iv).UTC()
		} else if z, ok := parseZonedDateTimeValRound60(v, false); ok {
			tm = z.Time.UTC()
		} else if fv, ok := toFloat64(v); ok {
			tm = time.UnixMilli(int64(fv)).UTC()
		} else {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("Cannot emit %v in date_field context", v)}
		}
		formatted := tm.Format("2006-01-02T15:04:05.000Z")
		budget.emittedVals = append(budget.emittedVals, formatted)
		return formatted, nil
	case "ip":
		if ipV, isIPV := v.(*IPAddressVal); isIPV && ipV != nil {
			canon := ipV.String()
			budget.emittedVals = append(budget.emittedVals, canon)
			return canon, nil
		}
		s, ok := v.(string)
		if !ok {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("ip_field emit requires String, got %T", v)}
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("'%s' is not an IP string literal", s)}
		}
		canon := addr.String()
		budget.emittedVals = append(budget.emittedVals, canon)
		return canon, nil
	case "geo_point":
		gp, ok := parseGeoPointValRound60(v)
		if !ok {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid geo_point emit value: %v", v)}
		}
		pt := map[string]any{
			"type":        "Point",
			"coordinates": []any{gp.Lon, gp.Lat},
		}
		budget.emittedVals = append(budget.emittedVals, pt)
		return pt, nil
	default:
		if budget != nil {
			budget.emittedVals = append(budget.emittedVals, v)
		}
		return v, nil
	}
}

// EvalEmitContext evaluates a Painless runtime-field or `_scripts/painless/_execute`
// field-context script and returns its emitted values for all 7 ES 8 field contexts:
// `boolean_field`, `long_field`, `double_field`, `keyword_field`, `date_field`,
// `ip_field`, and `geo_point_field`.
func EvalEmitContext(src string, contextType string, doc map[string]any, source map[string]any, params map[string]any, fieldTypes map[string]string) ([]any, error) {
	if err := CompileValidate(src); err != nil {
		return nil, err
	}
	ctxKind := normalizeEmitContextNameRound60(contextType)
	switch ctxKind {
	case "boolean", "long", "double", "keyword", "date", "ip", "geo_point", "composite":
	default:
		return nil, fmt.Errorf("illegal_argument_exception: unsupported emit field context [%s]", contextType)
	}

	baseDoc := doc
	if baseDoc == nil {
		baseDoc = source
	}
	normDoc := NormalizeDocValuesForScript(baseDoc, fieldTypes)
	if normDoc == nil {
		normDoc = make(map[string]any)
	}
	if source != nil {
		normDoc["__raw_source"] = source
	}

	evalParams := make(map[string]any, len(params)+6)
	explicit := make(map[string]bool, len(params))
	for k, v := range params {
		evalParams[k] = v
		if !isInternalPainlessMapKey(nil, k) {
			explicit[k] = true
		}
	}
	evalParams["__script_locals"] = make(map[string]bool)
	evalParams["__explicit_params_keys"] = explicit
	if source != nil {
		evalParams["_source"] = source
	} else {
		evalParams["_source"] = baseDoc
	}
	if len(fieldTypes) > 0 {
		evalParams["__field_types"] = fieldTypes
	}

	budget := newEvalBudget(evalParams)
	budget.emitContext = contextType
	evalParams["__eval_budget"] = budget

	ctxOp := ""
	cleaned := stripPainlessComments(src)
	if strings.TrimSpace(cleaned) != "" {
		err := execBlock(normDoc, cleaned, evalParams, &ctxOp, budget)
		if err != nil && !errors.Is(err, errPainlessReturn) {
			return nil, err
		}
	}

	out := make([]any, len(budget.emittedVals))
	copy(out, budget.emittedVals)
	// Per ES `70_execute_painless_scripts.yml`, `boolean_field` sorts emitted booleans ascending (`false` before `true`)
	// while `date_field`, `double_field`, `geo_point_field`, `ip_field`, `long_field`, and `keyword_field` preserve emission order.
	if ctxKind == "boolean" && len(out) > 1 {
		sort.SliceStable(out, func(i, j int) bool {
			bi, _ := out[i].(bool)
			bj, _ := out[j].(bool)
			return !bi && bj
		})
	}
	return out, nil
}

// ============================================================================
// F25: `MovingFunctions` Empty-Slice & Window Aggregation Helpers
// ============================================================================

func extractMovingValuesRound60(val any) ([]float64, error) {
	if val == nil {
		return nil, nil
	}
	switch tv := val.(type) {
	case []float64:
		return tv, nil
	case []any:
		out := make([]float64, 0, len(tv))
		for _, el := range tv {
			if el == nil {
				continue
			}
			fv, ok := toFloat64WithRawPainless(el)
			if !ok {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("MovingFunctions values must be numeric, got %T", el)}
			}
			out = append(out, fv)
		}
		return out, nil
	default:
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("MovingFunctions expects array/list of numbers, got %T", val)}
	}
}

func evalMovingFunctionsStaticRound60(method string, evalArgs []any) (any, error) {
	if len(evalArgs) == 0 {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("MovingFunctions.%s requires values argument", method)}
	}
	vals, err := extractMovingValuesRound60(evalArgs[0])
	if err != nil {
		return nil, err
	}
	if method == "sum" {
		if len(vals) == 0 {
			return float64(0.0), nil
		}
		var s float64
		for _, v := range vals {
			s += v
		}
		return s, nil
	}
	// All other MovingFunctions (`max`, `min`, `unweightedAvg`, `linearWeightedAvg`, `ewma`, `holt`, `holtWinters`, `stdDev`)
	// return `null` (`nil`) when `len(values) == 0` per `220_moving_fn.yml`.
	if len(vals) == 0 {
		return nil, nil
	}
	switch method {
	case "max":
		m := vals[0]
		for _, v := range vals[1:] {
			if v > m {
				m = v
			}
		}
		return m, nil
	case "min":
		m := vals[0]
		for _, v := range vals[1:] {
			if v < m {
				m = v
			}
		}
		return m, nil
	case "unweightedAvg":
		var s float64
		for _, v := range vals {
			s += v
		}
		return s / float64(len(vals)), nil
	case "linearWeightedAvg":
		var num, den float64
		for i, v := range vals {
			w := float64(i + 1)
			num += v * w
			den += w
		}
		return num / den, nil
	case "ewma":
		alpha := 0.3
		if len(evalArgs) >= 2 {
			if a, ok := toFloat64(evalArgs[1]); ok {
				alpha = a
			}
		}
		if alpha < 0 || alpha > 1 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "ewma alpha must be in [0, 1]"}
		}
		s := vals[0]
		for _, v := range vals[1:] {
			s = alpha*v + (1.0-alpha)*s
		}
		return s, nil
	case "holt":
		if len(vals) < 2 {
			return nil, nil
		}
		alpha, beta := 0.3, 0.1
		if len(evalArgs) >= 2 {
			if a, ok := toFloat64(evalArgs[1]); ok {
				alpha = a
			}
		}
		if len(evalArgs) >= 3 {
			if b, ok := toFloat64(evalArgs[2]); ok {
				beta = b
			}
		}
		level := vals[0]
		trend := vals[1] - vals[0]
		for i := 1; i < len(vals); i++ {
			prevLevel := level
			level = alpha*vals[i] + (1.0-alpha)*(level+trend)
			trend = beta*(level-prevLevel) + (1.0-beta)*trend
		}
		return level + trend, nil
	case "holtWinters":
		period := 1
		if len(evalArgs) >= 5 {
			if p, ok := toInt64Painless(evalArgs[4]); ok && p > 0 {
				period = int(p)
			}
		}
		if len(vals) < period*2 {
			return nil, nil
		}
		alpha, beta, gamma := 0.3, 0.1, 0.1
		if len(evalArgs) >= 2 {
			if a, ok := toFloat64(evalArgs[1]); ok {
				alpha = a
			}
		}
		if len(evalArgs) >= 3 {
			if b, ok := toFloat64(evalArgs[2]); ok {
				beta = b
			}
		}
		if len(evalArgs) >= 4 {
			if g, ok := toFloat64(evalArgs[3]); ok {
				gamma = g
			}
		}
		isMult := len(evalArgs) >= 6 && evalArgs[5] == true
		seasonals := make([]float64, period)
		var p0Avg float64
		for i := 0; i < period; i++ {
			p0Avg += vals[i]
		}
		p0Avg /= float64(period)
		for i := 0; i < period; i++ {
			if isMult && p0Avg != 0 {
				seasonals[i] = vals[i] / p0Avg
			} else {
				seasonals[i] = vals[i] - p0Avg
			}
		}
		level := p0Avg
		trend := 0.0
		for i := 0; i < period; i++ {
			trend += (vals[period+i] - vals[i]) / float64(period)
		}
		trend /= float64(period)
		for i := period; i < len(vals); i++ {
			sIdx := i % period
			prevLevel := level
			prevSeason := seasonals[sIdx]
			if isMult && prevSeason != 0 {
				level = alpha*(vals[i]/prevSeason) + (1.0-alpha)*(prevLevel+trend)
				trend = beta*(level-prevLevel) + (1.0-beta)*trend
				if level != 0 {
					seasonals[sIdx] = gamma*(vals[i]/level) + (1.0-gamma)*prevSeason
				}
			} else {
				level = alpha*(vals[i]-prevSeason) + (1.0-alpha)*(prevLevel+trend)
				trend = beta*(level-prevLevel) + (1.0-beta)*trend
				seasonals[sIdx] = gamma*(vals[i]-level) + (1.0-gamma)*prevSeason
			}
		}
		nextSeason := seasonals[len(vals)%period]
		if isMult {
			return (level + trend) * nextSeason, nil
		}
		return level + trend + nextSeason, nil
	case "stdDev":
		var sum float64
		for _, v := range vals {
			sum += v
		}
		mean := sum / float64(len(vals))
		if len(evalArgs) >= 2 {
			if m, ok := toFloat64(evalArgs[1]); ok {
				mean = m
			}
		}
		var sq float64
		for _, v := range vals {
			d := v - mean
			sq += d * d
		}
		sd := math.Sqrt(sq / float64(len(vals)))
		if len(evalArgs) >= 3 {
			sigma, _ := toFloat64(evalArgs[2])
			mode := "upper"
			if len(evalArgs) >= 4 {
				mode = strings.ToLower(fmt.Sprintf("%v", evalArgs[3]))
			}
			if mode == "lower" {
				return mean - sigma*sd, nil
			}
			return mean + sigma*sd, nil
		}
		return sd, nil
	default:
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("Unknown MovingFunctions method [%s]", method)}
	}
}

// ============================================================================
// F29: ES 8 Ingest `Processors.*` & `metadata()` Bindings (`190_script_processor.yml`)
// ============================================================================

func getOrInitMetadataMapRound60(sourceMap, params map[string]any) map[string]any {
	budget := getOrInitEvalBudget(params)
	if budget.metadataMap != nil {
		return budget.metadataMap
	}
	m := make(map[string]any, 6)
	readFirst := func(keys ...string) any {
		for _, k := range keys {
			if params != nil {
				if v, ok := params[k]; ok && v != nil {
					return v
				}
			}
			if sourceMap != nil {
				if v, ok := sourceMap[k]; ok && v != nil {
					return v
				}
			}
		}
		return nil
	}
	if v := readFirst("_ctx_index", "__meta_index", "_index"); v != nil {
		m["_index"] = v
		m["index"] = v
	} else {
		m["_index"] = ""
		m["index"] = ""
	}
	if v := readFirst("_ctx_id", "__meta_id", "_id"); v != nil {
		m["_id"] = v
		m["id"] = v
	} else {
		m["_id"] = ""
		m["id"] = ""
	}
	if v := readFirst("_ctx_routing", "_routing"); v != nil {
		m["_routing"] = v
		m["routing"] = v
	} else {
		m["_routing"] = nil
		m["routing"] = nil
	}
	if v := readFirst("_ctx_version", "__meta_version", "_version"); v != nil {
		m["_version"] = v
		m["version"] = v
	} else {
		m["_version"] = nil
		m["version"] = nil
	}
	if v := readFirst("_ctx_version_type", "_version_type"); v != nil {
		m["_version_type"] = v
		m["versionType"] = v
	} else {
		m["_version_type"] = "internal"
		m["versionType"] = "internal"
	}
	if v := readFirst("_ctx_op", "op"); v != nil {
		m["op"] = v
	} else {
		m["op"] = "index"
	}
	budget.metadataMap = m
	return m
}

func pickChangedMetaKeyRound60(m map[string]any, uKey, bKey string, origVal any) (any, bool) {
	origStr := ""
	if origVal != nil {
		origStr = fmt.Sprintf("%v", origVal)
	}
	valStr := func(v any) string {
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}
	if uVal, ok := m[uKey]; ok && valStr(uVal) != origStr {
		return uVal, true
	}
	if bKey != "" {
		if bVal, ok := m[bKey]; ok && valStr(bVal) != origStr {
			return bVal, true
		}
	}
	return origVal, false
}

func syncMetadataMapToParamsRound60(budget *evalBudget, evalParams, origParams map[string]any) error {
	if budget == nil || budget.metadataMap == nil {
		return nil
	}
	m := budget.metadataMap
	readonly, _ := evalParams["__readonly_ctx_meta"].(bool)
	if idVal, changed := pickChangedMetaKeyRound60(m, "_id", "id", evalParams["_ctx_id"]); changed {
		if readonly {
			return fmt.Errorf("illegal_argument_exception: Cannot modify _id in update script")
		}
		evalParams["_ctx_id"] = idVal
		budget.ctxID = idVal
		budget.hasCtxID = true
	}
	if idxVal, changed := pickChangedMetaKeyRound60(m, "_index", "index", evalParams["_ctx_index"]); changed && idxVal != nil {
		if readonly {
			return fmt.Errorf("illegal_argument_exception: Cannot modify _index in update script")
		}
		evalParams["_ctx_index"] = idxVal
		budget.ctxIndex = idxVal
		budget.hasCtxIndex = true
	}
	if rtVal, changed := pickChangedMetaKeyRound60(m, "_routing", "routing", evalParams["_ctx_routing"]); changed {
		if upsertMode, _ := evalParams["__upsert_insert_mode"].(bool); upsertMode {
			return fmt.Errorf("illegal_argument_exception: Cannot modify _routing in update script when inserting upsert document")
		}
		evalParams["_ctx_routing"] = rtVal
		budget.ctxRouting = rtVal
		budget.hasCtxRouting = true
	}
	if verVal, changed := pickChangedMetaKeyRound60(m, "_version", "version", evalParams["_ctx_version"]); changed {
		evalParams["_ctx_version"] = verVal
		budget.ctxVersion = verVal
		budget.hasCtxVersion = true
	}
	origVT := evalParams["_ctx_version_type"]
	if origVT == nil {
		origVT = "internal"
	}
	if vtVal, changed := pickChangedMetaKeyRound60(m, "_version_type", "versionType", origVT); changed && vtVal != nil {
		evalParams["_ctx_version_type"] = vtVal
		if origParams != nil {
			origParams["_ctx_version_type"] = vtVal
		}
	} else if evalParams["_ctx_version_type"] == nil {
		evalParams["_ctx_version_type"] = origVT
		if origParams != nil {
			origParams["_ctx_version_type"] = origVT
		}
	}
	origOp := evalParams["_ctx_op"]
	if origOp == nil {
		origOp = "index"
	}
	if opVal, changed := pickChangedMetaKeyRound60(m, "_op", "op", origOp); changed && opVal != nil {
		opStr := fmt.Sprintf("%v", opVal)
		evalParams["_ctx_op"] = opStr
		budget.ctxOp = opStr
		budget.hasCtxOp = true
	}
	if origParams != nil {
		for _, k := range []string{"_ctx_id", "_ctx_index", "_ctx_routing", "_ctx_version", "_ctx_version_type", "_ctx_op"} {
			if v, exists := evalParams[k]; exists {
				origParams[k] = v
			}
		}
	}
	return nil
}

var reESByteSizeRound60 = regexp.MustCompile(`(?i)^\s*([+-]?(?:\d+(?:\.\d+)?|\.\d+))\s*(pb|p|tb|t|gb|g|mb|m|kb|k|b)?\s*$`)

func parseESByteSizeRound60(s string) (int64, error) {
	m := reESByteSizeRound60.FindStringSubmatch(s)
	if m == nil {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse byte size [%s]", s)}
	}
	val, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse byte size [%s]", s)}
	}
	mult := float64(1)
	switch strings.ToLower(m[2]) {
	case "", "b":
		mult = 1
	case "k", "kb":
		mult = 1024
	case "m", "mb":
		mult = 1024 * 1024
	case "g", "gb":
		mult = 1024 * 1024 * 1024
	case "t", "tb":
		mult = 1024 * 1024 * 1024 * 1024
	case "p", "pb":
		mult = 1024 * 1024 * 1024 * 1024 * 1024
	}
	return int64(val * mult), nil
}

func resolveIngestTargetMapRound60(firstArg any, firstExpr string, sourceMap map[string]any) (map[string]any, bool) {
	m, ok := firstArg.(map[string]any)
	if !ok || m == nil {
		return nil, false
	}
	if strings.TrimSpace(firstExpr) == "ctx" && sourceMap != nil {
		if sub, isSrc := m["_source"].(map[string]any); isSrc && sub != nil {
			return sourceMap, true
		}
	}
	return m, true
}

func evalProcessorsStaticRound60(method string, rawArgExprs []string, evalArgs []any, sourceMap, params map[string]any) (any, error) {
	arg0Expr := ""
	if len(rawArgExprs) > 0 {
		arg0Expr = rawArgExprs[0]
	}
	switch method {
	case "bytes":
		if len(evalArgs) >= 2 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				raw := resolveParamPath(target, fPath)
				if raw == nil {
					return nil, nil
				}
				sz, err := parseESByteSizeRound60(fmt.Sprintf("%v", raw))
				if err != nil {
					return nil, err
				}
				setValueAtPath(target, fPath, sz)
				return sz, nil
			}
		}
		if len(evalArgs) == 0 || evalArgs[0] == nil {
			return nil, nil
		}
		return parseESByteSizeRound60(fmt.Sprintf("%v", evalArgs[0]))

	case "lowercase":
		if len(evalArgs) >= 2 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				raw := resolveParamPath(target, fPath)
				if raw == nil {
					return nil, nil
				}
				res := lowercaseValueOrSliceRound60(raw)
				setValueAtPath(target, fPath, res)
				return res, nil
			}
		}
		if len(evalArgs) == 0 || evalArgs[0] == nil {
			return nil, nil
		}
		return lowercaseValueOrSliceRound60(evalArgs[0]), nil

	case "uppercase":
		if len(evalArgs) >= 2 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				raw := resolveParamPath(target, fPath)
				if raw == nil {
					return nil, nil
				}
				res := uppercaseValueOrSliceRound60(raw)
				setValueAtPath(target, fPath, res)
				return res, nil
			}
		}
		if len(evalArgs) == 0 || evalArgs[0] == nil {
			return nil, nil
		}
		return uppercaseValueOrSliceRound60(evalArgs[0]), nil

	case "trim":
		if len(evalArgs) >= 2 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				raw := resolveParamPath(target, fPath)
				if raw == nil {
					return nil, nil
				}
				res := strings.TrimSpace(fmt.Sprintf("%v", raw))
				setValueAtPath(target, fPath, res)
				return res, nil
			}
		}
		if len(evalArgs) == 0 || evalArgs[0] == nil {
			return nil, nil
		}
		return strings.TrimSpace(fmt.Sprintf("%v", evalArgs[0])), nil

	case "gsub":
		// Mutating 4-arg `(ctx, field, pattern, replacement)` OR value 3-arg `(str, pattern, replacement)`
		if len(evalArgs) >= 4 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				raw := resolveParamPath(target, fPath)
				if raw == nil {
					return nil, nil
				}
				re, err := CompileBoundedRegex(fmt.Sprintf("%v", evalArgs[2]))
				if err != nil {
					return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: err.Error()}
				}
				res := re.ReplaceAllString(fmt.Sprintf("%v", raw), fmt.Sprintf("%v", evalArgs[3]))
				setValueAtPath(target, fPath, res)
				return res, nil
			}
		}
		if len(evalArgs) >= 3 {
			if evalArgs[0] == nil {
				return nil, nil
			}
			re, err := CompileBoundedRegex(fmt.Sprintf("%v", evalArgs[1]))
			if err != nil {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: err.Error()}
			}
			return re.ReplaceAllString(fmt.Sprintf("%v", evalArgs[0]), fmt.Sprintf("%v", evalArgs[2])), nil
		}
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "Processors.gsub requires (value, pattern, replacement) or (ctx, field, pattern, replacement)"}

	case "split":
		if len(evalArgs) >= 3 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				raw := resolveParamPath(target, fPath)
				if raw == nil {
					return nil, nil
				}
				parts, err := splitProcessorRegexRound60(fmt.Sprintf("%v", raw), fmt.Sprintf("%v", evalArgs[2]))
				if err != nil {
					return nil, err
				}
				setValueAtPath(target, fPath, parts)
				return parts, nil
			}
		}
		if len(evalArgs) >= 2 {
			if evalArgs[0] == nil {
				return nil, nil
			}
			return splitProcessorRegexRound60(fmt.Sprintf("%v", evalArgs[0]), fmt.Sprintf("%v", evalArgs[1]))
		}
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "Processors.split requires (value, separator) or (ctx, field, separator)"}

	case "join":
		if len(evalArgs) >= 3 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				raw := resolveParamPath(target, fPath)
				if raw == nil {
					return nil, nil
				}
				joined := joinProcessorSliceRound60(raw, fmt.Sprintf("%v", evalArgs[2]))
				setValueAtPath(target, fPath, joined)
				return joined, nil
			}
		}
		if len(evalArgs) >= 2 {
			if evalArgs[0] == nil {
				return nil, nil
			}
			return joinProcessorSliceRound60(evalArgs[0], fmt.Sprintf("%v", evalArgs[1])), nil
		}
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "Processors.join requires (list, separator) or (ctx, field, separator)"}

	case "remove":
		if len(evalArgs) >= 2 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				if fieldsSlice, isS := evalArgs[1].([]any); isS {
					for _, f := range fieldsSlice {
						deletePathInMapRound60(target, strings.Split(fmt.Sprintf("%v", f), "."))
					}
					return target, nil
				}
				for _, f := range evalArgs[1:] {
					deletePathInMapRound60(target, strings.Split(fmt.Sprintf("%v", f), "."))
				}
				return target, nil
			}
		}
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "Processors.remove requires (ctx, field)"}

	case "rename":
		if len(evalArgs) >= 3 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				srcSegs := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				dstSegs := strings.Split(fmt.Sprintf("%v", evalArgs[2]), ".")
				if hasPathInMapRound60(target, srcSegs) {
					val := resolveParamPath(target, srcSegs)
					deletePathInMapRound60(target, srcSegs)
					setValueAtPath(target, dstSegs, val)
				}
				return target, nil
			}
		}
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "Processors.rename requires (ctx, field, targetField)"}

	case "append":
		if len(evalArgs) >= 3 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				cur := resolveParamPath(target, fPath)
				res := appendProcessorValuesRound60(cur, evalArgs[2])
				setValueAtPath(target, fPath, res)
				return res, nil
			}
		}
		if len(evalArgs) >= 2 {
			return appendProcessorValuesRound60(evalArgs[0], evalArgs[1]), nil
		}
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "Processors.append requires (ctx, field, value) or (list, value)"}

	case "convert":
		if len(evalArgs) >= 3 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				raw := resolveParamPath(target, fPath)
				if raw == nil {
					return nil, nil
				}
				conv, err := convertProcessorScalarRound60(raw, fmt.Sprintf("%v", evalArgs[2]))
				if err != nil {
					return nil, err
				}
				if len(evalArgs) >= 4 && evalArgs[3] != nil {
					dstPath := strings.Split(fmt.Sprintf("%v", evalArgs[3]), ".")
					setValueAtPath(target, dstPath, conv)
				} else {
					setValueAtPath(target, fPath, conv)
				}
				return conv, nil
			}
		}
		if len(evalArgs) >= 2 {
			return convertProcessorScalarRound60(evalArgs[0], fmt.Sprintf("%v", evalArgs[1]))
		}
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "Processors.convert requires (value, type) or (ctx, field, type)"}

	case "json":
		if len(evalArgs) >= 2 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				raw := resolveParamPath(target, fPath)
				if raw == nil {
					return nil, nil
				}
				parsed, err := parseJSONProcessorValueRound60(fmt.Sprintf("%v", raw))
				if err != nil {
					return nil, err
				}
				if len(evalArgs) >= 3 && evalArgs[2] != nil && fmt.Sprintf("%v", evalArgs[2]) != "" {
					setValueAtPath(target, strings.Split(fmt.Sprintf("%v", evalArgs[2]), "."), parsed)
				} else if pm, isM := parsed.(map[string]any); isM {
					for k, v := range pm {
						target[k] = v
					}
				}
				return parsed, nil
			}
		}
		if len(evalArgs) >= 1 {
			if evalArgs[0] == nil {
				return nil, nil
			}
			return parseJSONProcessorValueRound60(fmt.Sprintf("%v", evalArgs[0]))
		}
		return nil, nil

	case "urlDecode":
		if len(evalArgs) >= 2 {
			if target, ok := resolveIngestTargetMapRound60(evalArgs[0], arg0Expr, sourceMap); ok {
				fPath := strings.Split(fmt.Sprintf("%v", evalArgs[1]), ".")
				raw := resolveParamPath(target, fPath)
				if raw == nil {
					return nil, nil
				}
				dec, err := url.PathUnescape(strings.ReplaceAll(fmt.Sprintf("%v", raw), "+", " "))
				if err != nil {
					return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: err.Error()}
				}
				setValueAtPath(target, fPath, dec)
				return dec, nil
			}
		}
		if len(evalArgs) >= 1 && evalArgs[0] != nil {
			dec, err := url.PathUnescape(strings.ReplaceAll(fmt.Sprintf("%v", evalArgs[0]), "+", " "))
			if err != nil {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: err.Error()}
			}
			return dec, nil
		}
		return nil, nil

	case "communityId":
		return evalCommunityIDProcessorRound60(evalArgs)

	case "uriParts":
		if len(evalArgs) == 0 || evalArgs[0] == nil {
			return nil, nil
		}
		return evalURIPartsProcessorRound60(fmt.Sprintf("%v", evalArgs[0]))
	}
	return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("Unknown Processors method [%s]", method)}
}

func lowercaseValueOrSliceRound60(v any) any {
	if s, ok := v.([]any); ok {
		out := make([]any, len(s))
		for i, el := range s {
			out[i] = strings.ToLower(fmt.Sprintf("%v", el))
		}
		return out
	}
	return strings.ToLower(fmt.Sprintf("%v", v))
}

func uppercaseValueOrSliceRound60(v any) any {
	if s, ok := v.([]any); ok {
		out := make([]any, len(s))
		for i, el := range s {
			out[i] = strings.ToUpper(fmt.Sprintf("%v", el))
		}
		return out
	}
	return strings.ToUpper(fmt.Sprintf("%v", v))
}

func splitProcessorRegexRound60(val, sepPattern string) ([]any, error) {
	re, err := regexp.Compile(sepPattern)
	if err != nil {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: err.Error()}
	}
	parts := re.Split(val, -1)
	out := make([]any, len(parts))
	for i, p := range parts {
		out[i] = p
	}
	return out, nil
}

func joinProcessorSliceRound60(val any, sep string) string {
	if s, ok := val.([]any); ok {
		parts := make([]string, len(s))
		for i, el := range s {
			parts[i] = fmt.Sprintf("%v", el)
		}
		return strings.Join(parts, sep)
	}
	return fmt.Sprintf("%v", val)
}

func appendProcessorValuesRound60(cur, add any) []any {
	var base []any
	if cur != nil {
		if s, ok := cur.([]any); ok {
			base = append(make([]any, 0, len(s)+2), s...)
		} else {
			base = []any{cur}
		}
	} else {
		base = make([]any, 0, 2)
	}
	if addSlice, ok := add.([]any); ok {
		base = append(base, addSlice...)
	} else {
		base = append(base, add)
	}
	return base
}

func convertProcessorScalarRound60(val any, targetType string) (any, error) {
	if val == nil {
		return nil, nil
	}
	if s, isSlice := val.([]any); isSlice {
		out := make([]any, len(s))
		for i, el := range s {
			c, err := convertProcessorScalarRound60(el, targetType)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	}
	str := strings.TrimSpace(fmt.Sprintf("%v", val))
	switch strings.ToLower(strings.TrimSpace(targetType)) {
	case "integer", "int", "long":
		if iv, ok := isIntegerValuePainless(val); ok {
			return iv, nil
		}
		iv, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			if fv, fErr := strconv.ParseFloat(str, 64); fErr == nil && fv == math.Trunc(fv) {
				return int64(fv), nil
			}
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("unable to convert [%v] to %s", val, targetType)}
		}
		return iv, nil
	case "float", "double":
		fv, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("unable to convert [%v] to %s", val, targetType)}
		}
		return fv, nil
	case "string":
		return fmt.Sprintf("%v", val), nil
	case "boolean":
		if b, ok := val.(bool); ok {
			return b, nil
		}
		switch strings.ToLower(str) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("unable to convert [%v] to boolean", val)}
		}
	case "ip":
		addr, err := netip.ParseAddr(str)
		if err != nil {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("unable to convert [%v] to ip", val)}
		}
		return addr.String(), nil
	case "auto":
		if b, ok := val.(bool); ok {
			return b, nil
		}
		if strings.EqualFold(str, "true") {
			return true, nil
		}
		if strings.EqualFold(str, "false") {
			return false, nil
		}
		if iv, err := strconv.ParseInt(str, 10, 64); err == nil {
			return iv, nil
		}
		if fv, err := strconv.ParseFloat(str, 64); err == nil {
			return fv, nil
		}
		return str, nil
	default:
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("unsupported convert type [%s]", targetType)}
	}
}

func parseJSONProcessorValueRound60(raw string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid JSON: %v", err)}
	}
	return normalizeJSONNumbersRound60(parsed), nil
}

func normalizeJSONNumbersRound60(v any) any {
	switch tv := v.(type) {
	case json.Number:
		if iv, err := tv.Int64(); err == nil {
			return iv
		}
		if fv, err := tv.Float64(); err == nil {
			return fv
		}
		return string(tv)
	case map[string]any:
		for k, mv := range tv {
			tv[k] = normalizeJSONNumbersRound60(mv)
		}
		return tv
	case []any:
		for i, el := range tv {
			tv[i] = normalizeJSONNumbersRound60(el)
		}
		return tv
	default:
		return v
	}
}

func evalCommunityIDProcessorRound60(args []any) (string, error) {
	if len(args) < 2 {
		return "", &painlessExceptionError{exType: "IllegalArgumentException", message: "Processors.communityId requires at least sourceIp and destinationIp"}
	}
	srcAddr, err := netip.ParseAddr(strings.TrimSpace(fmt.Sprintf("%v", args[0])))
	if err != nil {
		return "", &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid source IP: %v", args[0])}
	}
	dstAddr, err := netip.ParseAddr(strings.TrimSpace(fmt.Sprintf("%v", args[1])))
	if err != nil {
		return "", &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid destination IP: %v", args[1])}
	}
	ip1 := srcAddr.AsSlice()
	ip2 := dstAddr.AsSlice()

	// ES Processors.communityId(srcIp, dstIp, ianaNumber, transport, srcPort, dstPort, icmpType, icmpCode[, seed])
	var proto uint8
	if len(args) > 2 && args[2] != nil {
		if iv, ok := toInt64Painless(args[2]); ok {
			proto = uint8(iv) // #nosec G115 -- IANA protocol byte
		}
	}
	if proto == 0 && len(args) > 3 && args[3] != nil {
		switch strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", args[3]))) {
		case "icmp":
			proto = 1
		case "igmp":
			proto = 2
		case "tcp":
			proto = 6
		case "udp":
			proto = 17
		case "rsvp":
			proto = 46
		case "gre":
			proto = 47
		case "esp":
			proto = 50
		case "ah":
			proto = 51
		case "icmp6", "icmpv6", "ipv6-icmp":
			proto = 58
		case "pim":
			proto = 103
		case "sctp":
			proto = 132
		default:
			if iv, pErr := strconv.Atoi(strings.TrimSpace(fmt.Sprintf("%v", args[3]))); pErr == nil {
				proto = uint8(iv) // #nosec G115 -- IANA protocol byte
			}
		}
	}

	hasPorts := false
	var p1, p2 uint16
	oneWay := false
	if (proto == 6 || proto == 17 || proto == 132) && len(args) > 5 && args[4] != nil && args[5] != nil {
		sp, ok1 := toInt64Painless(args[4])
		dp, ok2 := toInt64Painless(args[5])
		if ok1 && ok2 {
			p1 = uint16(sp) // #nosec G115 -- 16-bit transport port
			p2 = uint16(dp) // #nosec G115 -- 16-bit transport port
			hasPorts = true
		}
	} else if (proto == 1 || proto == 58) && len(args) > 6 && args[6] != nil {
		it, _ := toInt64Painless(args[6])
		var ic int64
		if len(args) > 7 && args[7] != nil {
			ic, _ = toInt64Painless(args[7])
		}
		p1 = uint16(it)                                                                // #nosec G115 -- ICMP type
		p2, oneWay = icmpEquivalentReplyPortRound60(proto == 58, uint8(it), uint8(ic)) // #nosec G115 -- ICMP type/code
		hasPorts = true
	}

	var seed uint16
	if len(args) > 8 && args[8] != nil {
		if sv, ok := toInt64Painless(args[8]); ok {
			seed = uint16(sv) // #nosec G115 -- 16-bit Community ID seed
		}
	}

	cmp := bytes.Compare(ip1, ip2)
	swap := false
	if oneWay {
		swap = cmp > 0
	} else if cmp > 0 || (cmp == 0 && hasPorts && p1 > p2) {
		swap = true
	}
	if swap {
		ip1, ip2 = ip2, ip1
		p1, p2 = p2, p1
	}

	var buf bytes.Buffer
	var two [2]byte
	binary.BigEndian.PutUint16(two[:], seed)
	buf.Write(two[:])
	buf.Write(ip1)
	buf.Write(ip2)
	buf.WriteByte(proto)
	buf.WriteByte(0) // Community ID v1 padding byte
	if hasPorts {
		binary.BigEndian.PutUint16(two[:], p1)
		buf.Write(two[:])
		binary.BigEndian.PutUint16(two[:], p2)
		buf.Write(two[:])
	}
	sum := sha1.Sum(buf.Bytes()) // #nosec G401 -- Community ID v1 spec requires SHA-1
	return "1:" + base64.StdEncoding.EncodeToString(sum[:]), nil
}

func icmpEquivalentReplyPortRound60(isV6 bool, icmpType, icmpCode uint8) (uint16, bool) {
	if !isV6 {
		switch icmpType {
		case 8:
			return 0, false
		case 0:
			return 8, false
		case 13:
			return 14, false
		case 14:
			return 13, false
		case 15:
			return 16, false
		case 16:
			return 15, false
		case 17:
			return 18, false
		case 18:
			return 17, false
		}
		return uint16(icmpCode), true
	}
	switch icmpType {
	case 128:
		return 129, false
	case 129:
		return 128, false
	case 133:
		return 134, false
	case 134:
		return 133, false
	case 135:
		return 136, false
	case 136:
		return 135, false
	}
	return uint16(icmpCode), true
}

func evalURIPartsProcessorRound60(rawURI string) (map[string]any, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: err.Error()}
	}
	res := map[string]any{
		"original": rawURI,
	}
	if u.Scheme != "" {
		res["scheme"] = u.Scheme
	}
	if host := u.Hostname(); host != "" {
		res["domain"] = host
	}
	if portStr := u.Port(); portStr != "" {
		if pv, pErr := strconv.ParseInt(portStr, 10, 64); pErr == nil {
			res["port"] = pv
		}
	}
	if u.Path != "" {
		res["path"] = u.Path
		if slashIdx := strings.LastIndexByte(u.Path, '/'); slashIdx >= 0 {
			base := u.Path[slashIdx+1:]
			if dotIdx := strings.LastIndexByte(base, '.'); dotIdx > 0 && dotIdx+1 < len(base) {
				res["extension"] = base[dotIdx+1:]
			}
		}
	}
	if u.RawQuery != "" {
		res["query"] = u.RawQuery
	}
	if u.Fragment != "" {
		res["fragment"] = u.Fragment
	}
	if u.User != nil {
		if un := u.User.Username(); un != "" {
			res["username"] = un
		}
		if pw, hasPW := u.User.Password(); hasPW {
			res["password"] = pw
		}
	}
	return res, nil
}

// ============================================================================
// Round 60 Unified Expression / Static / Receiver / Statement Dispatchers
// ============================================================================

// evalRound60PreOpExpr handles top-level lambdas, method references, and
// `new GeoPoint(...)` / `new BytesRef(...)` before binary operator splitting.
func evalRound60PreOpExpr(sourceMap map[string]any, rhs string, params map[string]any, depth int) (any, bool, error) {
	if pl, ok := tryParseTopLevelLambdaOrMethodRefRound60(sourceMap, rhs, params); ok {
		return pl, true, nil
	}
	if strings.HasPrefix(rhs, "new IPAddress(") && findMatchingDelimiter(rhs, 13, '(', ')') == len(rhs)-1 {
		inner := strings.TrimSpace(rhs[14 : len(rhs)-1])
		v, err := evalRHSExprDepth(sourceMap, inner, params, depth+1)
		if err != nil {
			return nil, true, err
		}
		if v == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "IPAddress cannot be null"}
		}
		ip, err := ParseIPAddressVal(fmt.Sprintf("%v", v))
		return ip, true, err
	}
	if strings.HasPrefix(rhs, "new GeoPoint(") && findMatchingDelimiter(rhs, 12, '(', ')') == len(rhs)-1 {
		inner := strings.TrimSpace(rhs[13 : len(rhs)-1])
		if inner == "" {
			return &GeoPointVal{Lat: 0.0, Lon: 0.0}, true, nil
		}
		parts := splitTopLevelCommaPainless(inner)
		if len(parts) == 1 {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(parts[0]), params, depth+1)
			if err != nil {
				return nil, true, err
			}
			gp, ok := parseGeoPointValRound60(v)
			if !ok {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid GeoPoint: %v", v)}
			}
			return gp, true, nil
		}
		if len(parts) == 2 {
			v1, err1 := evalRHSExprDepth(sourceMap, strings.TrimSpace(parts[0]), params, depth+1)
			if err1 != nil {
				return nil, true, err1
			}
			v2, err2 := evalRHSExprDepth(sourceMap, strings.TrimSpace(parts[1]), params, depth+1)
			if err2 != nil {
				return nil, true, err2
			}
			lat, ok1 := toFloat64WithRawPainless(v1)
			lon, ok2 := toFloat64WithRawPainless(v2)
			if !ok1 || !ok2 {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "GeoPoint(lat, lon) requires numbers"}
			}
			return &GeoPointVal{Lat: lat, Lon: lon}, true, nil
		}
	}
	if strings.HasPrefix(rhs, "new BytesRef(") && findMatchingDelimiter(rhs, 12, '(', ')') == len(rhs)-1 {
		inner := strings.TrimSpace(rhs[13 : len(rhs)-1])
		if inner == "" {
			return newBytesRefValRound60(nil), true, nil
		}
		v, err := evalRHSExprDepth(sourceMap, inner, params, depth+1)
		if err != nil {
			return nil, true, err
		}
		if s, ok := v.(string); ok {
			return newBytesRefValRound60([]byte(s)), true, nil
		}
		if bSlice, ok := v.([]any); ok {
			raw := make([]byte, len(bSlice))
			for i, el := range bSlice {
				iv, _ := toInt64Painless(el)
				raw[i] = byte(iv) // #nosec G115 -- Java byte array element
			}
			return newBytesRefValRound60(raw), true, nil
		}
	}
	return nil, false, nil
}

// evalRound60StaticOrBuiltinCall handles System.currentTimeMillis/nanoTime,
// field(...), $(...), metadata(), script_score functions, MovingFunctions.*,
// and Processors.*.
func evalRound60StaticOrBuiltinCall(fnName string, args []string, argStr string, sourceMap, params map[string]any, depth int) (any, bool, error) {
	// Guard against shadowing by user-defined functions of the same name
	if b := getOrInitEvalBudget(params); b != nil {
		arity := 0
		if argStr != "" {
			arity = len(args)
		}
		if lookupUserFuncRound59(b, fnName, arity) != nil {
			return nil, false, nil
		}
	}

	evalAllArgs := func() ([]any, error) {
		if argStr == "" {
			return nil, nil
		}
		out := make([]any, len(args))
		for i, ae := range args {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(ae), params, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	}

	switch fnName {
	case "System.currentTimeMillis":
		return time.Now().UnixMilli(), true, nil
	case "System.nanoTime":
		return time.Now().UnixNano(), true, nil

	case "metadata":
		return getOrInitMetadataMapRound60(sourceMap, params), true, nil

	case "grok", "dissect":
		if len(args) != 1 || argStr == "" {
			arity := len(args)
			if argStr == "" {
				arity = 0
			}
			return nil, true, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("Unable to find dynamic method [%s] with [%d] arguments", fnName, arity),
			}
		}
		toks, lErr := lexPainlessCompileRound60(args[0])
		if lErr != nil {
			return nil, true, lErr
		}
		constPat, isConst := evalCompileConstantStringTokensRound62(toks)
		if !isConst {
			return nil, true, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("all arguments to [%s] must be constant but the [1] argument isn't", fnName),
			}
		}
		if fnName == "grok" {
			ext, err := CompileGrokPattern(constPat)
			return ext, true, err
		}
		ext, err := CompileDissectPattern(constPat)
		return ext, true, err

	case "parse":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		res, pErr := evalBuiltinDateParseRound62(ev, sourceMap, params)
		return res, true, pErr

	case "Locale.forLanguageTag":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		if len(ev) != 1 || ev[0] == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "languageTag"}
		}
		return fmt.Sprintf("%v", ev[0]), true, nil

	case "field":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		if len(ev) == 0 || ev[0] == nil {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "field() requires a non-null field name"}
		}
		fName := fmt.Sprintf("%v", ev[0])
		if dvf, handled, dvErr := resolveDenseVectorFieldValRound61(fName, sourceMap, params); handled {
			return dvf, true, dvErr
		}
		fv, err := resolveFieldValRound60(fName, sourceMap, params)
		return fv, true, err

	case "$":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		if len(ev) == 0 || ev[0] == nil {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "$() requires a non-null field name"}
		}
		fName := fmt.Sprintf("%v", ev[0])
		if dvf, handled, dvErr := resolveDenseVectorFieldValRound61(fName, sourceMap, params); handled {
			if dvErr != nil {
				return nil, true, dvErr
			}
			if len(ev) >= 2 {
				res, gErr := dvf.GetWithDefault(ev[1])
				return res, true, gErr
			}
			res, gErr := dvf.GetValue()
			return res, true, gErr
		}
		fv, err := resolveFieldValRound60(fName, sourceMap, params)
		if err != nil {
			return nil, true, err
		}
		var defVal any
		if len(ev) >= 2 {
			defVal = ev[1]
		}
		return fv.GetDefault(defVal), true, nil

	case "saturation":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		if len(ev) != 2 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "saturation(value, k) requires 2 arguments"}
		}
		v, ok1 := toFloat64WithRawPainless(ev[0])
		k, ok2 := toFloat64WithRawPainless(ev[1])
		if !ok1 || !ok2 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "saturation requires numeric arguments"}
		}
		res, err := evalSaturationRound60(v, k)
		return res, true, err

	case "sigmoid":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		if len(ev) != 3 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "sigmoid(value, k, a) requires 3 arguments"}
		}
		v, ok1 := toFloat64WithRawPainless(ev[0])
		k, ok2 := toFloat64WithRawPainless(ev[1])
		a, ok3 := toFloat64WithRawPainless(ev[2])
		if !ok1 || !ok2 || !ok3 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "sigmoid requires numeric arguments"}
		}
		res, err := evalSigmoidRound60(v, k, a)
		return res, true, err

	case "decayNumericLinear", "decayNumericExp", "decayNumericGauss":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		if len(ev) != 5 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fnName + " requires 5 arguments"}
		}
		origin, ok0 := toFloat64WithRawPainless(ev[0])
		scale, ok1 := toFloat64WithRawPainless(ev[1])
		offset, ok2 := toFloat64WithRawPainless(ev[2])
		decay, ok3 := toFloat64WithRawPainless(ev[3])
		val, ok4 := toFloat64WithRawPainless(ev[4])
		if !ok0 || !ok1 || !ok2 || !ok3 || !ok4 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fnName + " requires numeric arguments"}
		}
		mode := strings.ToLower(strings.TrimPrefix(fnName, "decayNumeric"))
		res, err := computeDecayScoreRound60(mode, math.Abs(val-origin), scale, offset, decay)
		return res, true, err

	case "decayDateLinear", "decayDateExp", "decayDateGauss":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		if len(ev) != 5 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fnName + " requires 5 arguments"}
		}
		origTm, okO := parseFlexibleESDateTimeRound60(ev[0])
		if !okO {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse date origin [%v]", ev[0])}
		}
		scaleMs, err := parseESDurationMillisRound60(ev[1])
		if err != nil {
			return nil, true, err
		}
		offsetMs, err := parseESDurationMillisRound60(ev[2])
		if err != nil {
			return nil, true, err
		}
		decay, okD := toFloat64WithRawPainless(ev[3])
		if !okD {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid decay parameter"}
		}
		valTm, okV := parseFlexibleESDateTimeRound60(ev[4])
		if !okV {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse date value [%v]", ev[4])}
		}
		distMs := math.Abs(float64(valTm.UTC().UnixMilli() - origTm.UTC().UnixMilli()))
		mode := strings.ToLower(strings.TrimPrefix(fnName, "decayDate"))
		res, err := computeDecayScoreRound60(mode, distMs, scaleMs, offsetMs, decay)
		return res, true, err

	case "decayGeoLinear", "decayGeoExp", "decayGeoGauss":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		if len(ev) != 5 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fnName + " requires 5 arguments"}
		}
		origGP, okO := parseGeoPointValRound60(ev[0])
		if !okO {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse geo origin [%v]", ev[0])}
		}
		scaleM, err := parseESDistanceMetersRound60(ev[1])
		if err != nil {
			return nil, true, err
		}
		offsetM, err := parseESDistanceMetersRound60(ev[2])
		if err != nil {
			return nil, true, err
		}
		decay, okD := toFloat64WithRawPainless(ev[3])
		if !okD {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid decay parameter"}
		}
		valGP, okV := parseGeoPointValRound60(ev[4])
		if !okV {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse geo value [%v]", ev[4])}
		}
		distM := origGP.ArcDistance(valGP.Lat, valGP.Lon)
		mode := strings.ToLower(strings.TrimPrefix(fnName, "decayGeo"))
		res, err := computeDecayScoreRound60(mode, distM, scaleM, offsetM, decay)
		return res, true, err

	case "randomScore":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		if len(ev) < 1 || len(ev) > 2 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "randomScore requires 1 or 2 arguments"}
		}
		seed, ok := toInt64Painless(ev[0])
		if !ok {
			if sf, fOk := toFloat64(ev[0]); fOk {
				seed = int64(sf)
			} else {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "randomScore seed must be integer"}
			}
		}
		if len(ev) == 2 {
			res, err := evalRandomScoreRound60(seed, fmt.Sprintf("%v", ev[1]), true, sourceMap, params)
			return res, true, err
		}
		res, err := evalRandomScoreRound60(seed, "", false, sourceMap, params)
		return res, true, err

	case "dotProduct", "cosineSimilarity", "l1norm", "l2norm", "hamming":
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		if len(ev) != 2 {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fnName + "(queryVector, field) requires 2 arguments"}
		}
		res, err := evalVectorSimilarityRound60(fnName, ev[0], ev[1], sourceMap, params)
		return res, true, err
	}

	if strings.HasPrefix(fnName, "MovingFunctions.") {
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		res, err := evalMovingFunctionsStaticRound60(strings.TrimPrefix(fnName, "MovingFunctions."), ev)
		return res, true, err
	}

	if strings.HasPrefix(fnName, "Processors.") {
		ev, err := evalAllArgs()
		if err != nil {
			return nil, true, err
		}
		res, err := evalProcessorsStaticRound60(strings.TrimPrefix(fnName, "Processors."), args, ev, sourceMap, params)
		return res, true, err
	}

	return nil, false, nil
}

// evalRound60ZeroArgMethod handles zero-arg methods on Round-60/61 wrapper types.
func evalRound60ZeroArgMethod(mSuffix string, recVal any, sourceMap, params map[string]any, depth int) (any, bool, error) {
	mBare := strings.TrimSuffix(strings.TrimPrefix(mSuffix, "."), "()")
	switch tv := recVal.(type) {
	case *ZonedDateTimeVal:
		return evalZonedDateTimeZeroArgRound62(tv, mSuffix)

	case *InstantVal:
		if tv == nil {
			return nil, false, nil
		}
		switch mSuffix {
		case ".toEpochMilli()":
			return tv.ToEpochMilli(), true, nil
		case ".getEpochSecond()":
			return tv.Time.UTC().Unix(), true, nil
		case ".getNano()":
			return int64(tv.Time.Nanosecond()), true, nil
		case ".toString()":
			return tv.String(), true, nil
		}

	case DayOfWeekEnum:
		switch mSuffix {
		case ".getValue()":
			return tv.Value, true, nil
		case ".name()", ".toString()":
			return tv.String(), true, nil
		}

	case *DayOfWeekEnum:
		if tv != nil {
			switch mSuffix {
			case ".getValue()":
				return tv.Value, true, nil
			case ".name()", ".toString()":
				return tv.String(), true, nil
			}
		}

	case MonthEnum:
		switch mSuffix {
		case ".getValue()":
			return tv.Value, true, nil
		case ".name()", ".toString()":
			return tv.String(), true, nil
		case ".minLength()":
			return tv.MinLength(), true, nil
		case ".maxLength()":
			return tv.MaxLength(), true, nil
		case ".firstMonthOfQuarter()":
			return tv.FirstMonthOfQuarter(), true, nil
		}

	case *MonthEnum:
		if tv != nil {
			switch mSuffix {
			case ".getValue()":
				return tv.Value, true, nil
			case ".name()", ".toString()":
				return tv.String(), true, nil
			case ".minLength()":
				return tv.MinLength(), true, nil
			case ".maxLength()":
				return tv.MaxLength(), true, nil
			case ".firstMonthOfQuarter()":
				return tv.FirstMonthOfQuarter(), true, nil
			}
		}

	case *GrokExtractor:
		if tv != nil && mSuffix == ".toString()" {
			return tv.String(), true, nil
		}

	case *DissectExtractor:
		if tv != nil && mSuffix == ".toString()" {
			return tv.String(), true, nil
		}

	case string:
		if dow, _, ok := parseDayOfWeekEnumReceiverRound62(tv); ok {
			switch mSuffix {
			case ".getValue()":
				return dow.Value, true, nil
			case ".name()":
				return dow.String(), true, nil
			}
		}
		if mon, _, ok := parseMonthEnumReceiverRound62(tv); ok {
			switch mSuffix {
			case ".getValue()":
				return mon.Value, true, nil
			case ".name()":
				return mon.String(), true, nil
			case ".minLength()":
				return mon.MinLength(), true, nil
			case ".maxLength()":
				return mon.MaxLength(), true, nil
			case ".firstMonthOfQuarter()":
				return mon.FirstMonthOfQuarter(), true, nil
			}
		}

	case *GeoPointVal:
		if tv == nil {
			return nil, false, nil
		}
		switch mSuffix {
		case ".getLat()":
			return tv.Lat, true, nil
		case ".getLon()":
			return tv.Lon, true, nil
		case ".getCentroid()":
			return tv, true, nil
		case ".getBoundingBox()", ".getLabelPosition()", ".getDimensionalType()", ".getMercatorWidth()", ".getMercatorHeight()":
			return evalDocFieldSliceGeoMethodRound61([]any{tv}, mBare)
		case ".toString()":
			return tv.String(), true, nil
		}

	case *GeoBoundingBoxVal:
		return evalGeoBoundingBoxMethodRound61(tv, mBare)

	case *IPAddressVal:
		return evalIPAddressMethodRound61(tv, mBare, nil, sourceMap, params, depth)

	case *DenseVectorFieldVal, *DenseVectorVal:
		return evalDenseVectorMethodRound61(recVal, mBare, nil, sourceMap, params, depth)

	case *BytesRefVal:
		if tv == nil {
			return nil, false, nil
		}
		switch mSuffix {
		case ".utf8ToString()":
			return tv.Utf8ToString(), true, nil
		case ".length()", ".limit()", ".capacity()", ".remaining()":
			return int64(tv.Length), true, nil
		case ".position()":
			return int64(0), true, nil
		case ".toString()":
			return tv.String(), true, nil
		}

	case *ByteBufferVal:
		if tv == nil {
			return nil, false, nil
		}
		switch mSuffix {
		case ".limit()":
			return tv.Limit(), true, nil
		case ".capacity()":
			return tv.Capacity(), true, nil
		case ".position()":
			return tv.Position(), true, nil
		case ".remaining()":
			return tv.Remaining(), true, nil
		case ".hasRemaining()":
			return tv.Remaining() > 0, true, nil
		case ".utf8ToString()":
			return tv.Utf8ToString(), true, nil
		case ".get()":
			if tv.Pos >= tv.Lim {
				return nil, true, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: "BufferUnderflowException"}
			}
			b := int64(int8(tv.Bytes[tv.Pos])) // #nosec G115 -- signed Java byte
			tv.Pos++
			return b, true, nil
		case ".toString()":
			return tv.String(), true, nil
		}

	case *FieldVal:
		if tv == nil {
			return nil, false, nil
		}
		switch mSuffix {
		case ".get()":
			return tv.GetDefault(nil), true, nil
		case ".size()", ".length()":
			return tv.Size(), true, nil
		case ".isEmpty()":
			return tv.IsEmpty(), true, nil
		case ".values()":
			return tv.Values, true, nil
		case ".exists()":
			return tv.Exists(), true, nil
		case ".remove()":
			return tv.Remove(), true, nil
		case ".deduplicate()":
			tv.deduplicateInPlaceRound60()
			return nil, true, nil
		case ".asDouble()":
			if len(tv.Values) == 0 {
				return nil, true, nil
			}
			dv, ok := toFloat64WithRawPainless(tv.Values[0])
			if !ok {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse field [%s] as double", tv.Name)}
			}
			return dv, true, nil
		case ".asDate()":
			if len(tv.Values) == 0 {
				return nil, true, nil
			}
			dateFmt := lookupFieldFormatFromMapsRound61(sourceMap, params, tv.Name)
			z, ok := parseDocDateWithMappingFormatRound61(tv.Values[0], dateFmt, tv.FieldType == "date_nanos")
			if !ok {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse field [%s] as date", tv.Name)}
			}
			return z, true, nil
		case ".asGeoPoint()":
			if len(tv.Values) == 0 {
				return nil, true, nil
			}
			gp, ok := parseGeoPointValRound60(tv.Values[0])
			if !ok {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse field [%s] as geo_point", tv.Name)}
			}
			return gp, true, nil
		case ".asString()":
			if len(tv.Values) == 0 {
				return nil, true, nil
			}
			return FormatValueSafe(tv.Values[0]), true, nil
		case ".asStrings()":
			out := make([]any, len(tv.Values))
			for i, v := range tv.Values {
				out[i] = FormatValueSafe(v)
			}
			return out, true, nil
		case ".doc()":
			return tv.docAtRound60(0)
		case ".docs()":
			return tv.docsSliceRound60(), true, nil
		case ".toString()":
			return tv.String(), true, nil
		}

	case *PainlessLambda:
		if tv == nil {
			return nil, false, nil
		}
		switch mSuffix {
		case ".get()", ".run()":
			res, err := tv.Invoke(nil, sourceMap, params, depth+1)
			return res, true, err
		case ".getAsInt()":
			res, err := tv.Invoke(nil, sourceMap, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			iv, _ := toInt64Painless(res)
			return int64(int32(iv)), true, nil // #nosec G115 -- JLS int narrowing
		case ".getAsLong()":
			res, err := tv.Invoke(nil, sourceMap, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			iv, _ := toInt64Painless(res)
			return iv, true, nil
		case ".getAsDouble()":
			res, err := tv.Invoke(nil, sourceMap, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			fv, _ := toFloat64WithRawPainless(res)
			return fv, true, nil
		case ".getAsBoolean()":
			res, err := tv.Invoke(nil, sourceMap, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			bv, _ := res.(bool)
			return bv, true, nil
		case ".toString()":
			return tv.String(), true, nil
		}

	case []any:
		// Support geo_point doc-values slice methods: `.getCentroid()`, `.getBoundingBox()`,
		// `.getLabelPosition()`, `.getDimensionalType()`, `.getMercatorWidth()`, `.getMercatorHeight()`
		if res, handled, err := evalDocFieldSliceGeoMethodRound61(tv, mBare); handled {
			return res, true, err
		}
	}
	return nil, false, nil
}

func (fv *FieldVal) deduplicateInPlaceRound60() {
	if fv == nil || fv.Root == nil {
		return
	}
	raw := resolveParamPath(fv.Root, strings.Split(fv.Name, "."))
	slice, ok := raw.([]any)
	if !ok {
		return
	}
	dedup := make([]any, 0, len(slice))
	for _, item := range slice {
		dup := false
		for _, prev := range dedup {
			if painlessValuesEqual(prev, item) {
				dup = true
				break
			}
		}
		if !dup {
			dedup = append(dedup, item)
		}
	}
	setValueAtPath(fv.Root, strings.Split(fv.Name, "."), dedup)
	fv.refreshValuesRound60()
}

func (fv *FieldVal) docAtRound60(idx int) (*FieldDocVal, bool, error) {
	if fv == nil || fv.Root == nil {
		return nil, true, nil
	}
	raw := resolveParamPath(fv.Root, strings.Split(fv.Name, "."))
	if raw == nil && idx == 0 && isMutableFieldsContextRound61(fv.Params) {
		m := make(map[string]any)
		setValueAtPath(fv.Root, strings.Split(fv.Name, "."), m)
		return &FieldDocVal{Doc: m, Params: fv.Params}, true, nil
	}
	if m, ok := raw.(map[string]any); ok {
		if idx == 0 {
			return &FieldDocVal{Doc: m, Params: fv.Params}, true, nil
		}
		return nil, true, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("index %d out of bounds", idx)}
	}
	if s, ok := raw.([]any); ok {
		if idx < 0 || idx >= len(s) {
			return nil, true, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("index %d out of bounds for length %d", idx, len(s))}
		}
		if m, okM := s[idx].(map[string]any); okM {
			return &FieldDocVal{Doc: m, Params: fv.Params}, true, nil
		}
	}
	return nil, true, nil
}

func (fv *FieldVal) docsSliceRound60() []any {
	if fv == nil || fv.Root == nil {
		return []any{}
	}
	raw := resolveParamPath(fv.Root, strings.Split(fv.Name, "."))
	if m, ok := raw.(map[string]any); ok {
		return []any{&FieldDocVal{Doc: m, Params: fv.Params}}
	}
	if s, ok := raw.([]any); ok {
		out := make([]any, 0, len(s))
		for _, el := range s {
			if m, okM := el.(map[string]any); okM {
				out = append(out, &FieldDocVal{Doc: m, Params: fv.Params})
			}
		}
		return out
	}
	return []any{}
}

// evalRound60ReceiverMethod dispatches parameterized instance methods on
// Round-60/61 wrapper types.
func evalRound60ReceiverMethod(recVal any, mBare, argStr string, sourceMap, params map[string]any, depth int) (any, bool, error) {
	var rawArgExprs []string
	if trimmedArgs := strings.TrimSpace(argStr); trimmedArgs != "" {
		rawArgExprs = splitTopLevelCommaPainless(trimmedArgs)
	}
	evalCallArgs := func() ([]any, error) {
		if len(rawArgExprs) == 0 {
			return nil, nil
		}
		out := make([]any, len(rawArgExprs))
		for i, p := range rawArgExprs {
			v, err := evalRHSExprDepth(sourceMap, strings.TrimSpace(p), params, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	}

	switch tv := recVal.(type) {
	case *ZonedDateTimeVal:
		return evalZonedDateTimeMethodRound62(tv, mBare, rawArgExprs, evalCallArgs, sourceMap, params, depth)

	case *GeoBoundingBoxVal:
		if len(rawArgExprs) == 0 {
			return evalGeoBoundingBoxMethodRound61(tv, mBare)
		}

	case *GrokExtractor, *DissectExtractor:
		return evalGrokOrDissectMethodRound62(recVal, mBare, evalCallArgs)

	case DayOfWeekEnum, *DayOfWeekEnum, MonthEnum, *MonthEnum:
		return evalEnumReceiverMethodRound62(recVal, mBare, evalCallArgs)

	case *IPAddressVal:
		return evalIPAddressMethodRound61(tv, mBare, rawArgExprs, sourceMap, params, depth)

	case *DenseVectorFieldVal, *DenseVectorVal:
		return evalDenseVectorMethodRound61(recVal, mBare, rawArgExprs, sourceMap, params, depth)

	case *PainlessLambda:
		if tv == nil {
			return nil, false, nil
		}
		switch mBare {
		case "get", "getAsInt", "getAsLong", "getAsDouble", "getAsBoolean", "run":
			return evalRound60ZeroArgMethod("."+mBare+"()", tv, sourceMap, params, depth)
		case "apply", "accept":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			res, err := tv.InvokeWithArgExprs(args, rawArgExprs, sourceMap, params, depth+1)
			if mBare == "accept" {
				return nil, true, err
			}
			return res, true, err
		case "applyAsInt":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			res, err := tv.InvokeWithArgExprs(args, rawArgExprs, sourceMap, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			iv, _ := toInt64Painless(res)
			return int64(int32(iv)), true, nil // #nosec G115 -- JLS int narrowing
		case "applyAsLong":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			res, err := tv.InvokeWithArgExprs(args, rawArgExprs, sourceMap, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			iv, _ := toInt64Painless(res)
			return iv, true, nil
		case "applyAsDouble":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			res, err := tv.InvokeWithArgExprs(args, rawArgExprs, sourceMap, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			fv, _ := toFloat64WithRawPainless(res)
			return fv, true, nil
		case "test":
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			res, err := tv.InvokeWithArgExprs(args, rawArgExprs, sourceMap, params, depth+1)
			if err != nil {
				return nil, true, err
			}
			bv, _ := res.(bool)
			return bv, true, nil
		}

	case *FieldVal:
		if tv == nil {
			return nil, false, nil
		}
		return evalFieldValMethodRound60(tv, mBare, argStr, evalCallArgs, sourceMap, params, depth)

	case *FieldDocVal:
		if tv == nil {
			return nil, false, nil
		}
		if mBare == "field" || mBare == "$" {
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) == 0 || args[0] == nil {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: mBare + "() requires field name"}
			}
			subName := fmt.Sprintf("%v", args[0])
			if dvf, handled, dvErr := resolveDenseVectorFieldValRound61(subName, tv.Doc, tv.Params); handled {
				if dvErr != nil {
					return nil, true, dvErr
				}
				if mBare == "$" {
					if len(args) >= 2 {
						res, gErr := dvf.GetWithDefault(args[1])
						return res, true, gErr
					}
					res, gErr := dvf.GetValue()
					return res, true, gErr
				}
				return dvf, true, nil
			}
			subFV, err := resolveFieldValRound60(subName, tv.Doc, tv.Params)
			if err != nil {
				return nil, true, err
			}
			if mBare == "$" {
				var defVal any
				if len(args) >= 2 {
					defVal = args[1]
				}
				return subFV.GetDefault(defVal), true, nil
			}
			return subFV, true, nil
		}

	case *GeoPointVal:
		if tv == nil {
			return nil, false, nil
		}
		return evalGeoPointMethodRound60(tv, mBare, evalCallArgs)

	case *ByteBufferVal:
		if tv == nil {
			return nil, false, nil
		}
		if mBare == "get" {
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) == 0 {
				return evalRound60ZeroArgMethod(".get()", tv, sourceMap, params, depth)
			}
			idx, _ := toInt64Painless(args[0])
			b, err := tv.Get(int(idx))
			return b, true, err
		}

	case *BytesRefVal:
		if tv == nil {
			return nil, false, nil
		}
		if mBare == "get" {
			args, err := evalCallArgs()
			if err != nil {
				return nil, true, err
			}
			if len(args) >= 1 {
				idx, _ := toInt64Painless(args[0])
				raw := tv.slice()
				if idx < 0 || int(idx) >= len(raw) {
					return nil, true, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("index %d out of bounds", idx)}
				}
				return int64(int8(raw[idx])), true, nil // #nosec G115 -- signed Java byte
			}
		}

	case []any:
		if len(rawArgExprs) == 0 {
			if res, handled, err := evalDocFieldSliceGeoMethodRound61(tv, mBare); handled {
				return res, true, err
			}
		}
		// Support `doc['geo'].arcDistance(lat, lon)`, `planeDistance(lat, lon)`, `geohashDistance(hash)`
		if mBare == "arcDistance" || mBare == "planeDistance" || mBare == "geohashDistance" {
			if len(tv) == 0 {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "Document does not have a geo_point value"}
			}
			if gp, ok := parseGeoPointValRound60(tv[0]); ok {
				return evalGeoPointMethodRound60(gp, mBare, evalCallArgs)
			}
		}
	}
	if res, handled, err := evalEnumReceiverMethodRound62(recVal, mBare, evalCallArgs); handled {
		return res, true, err
	}
	return nil, false, nil
}

func evalGeoPointMethodRound60(gp *GeoPointVal, mBare string, evalCallArgs func() ([]any, error)) (any, bool, error) {
	switch mBare {
	case "arcDistance":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if len(args) == 1 {
			if other, ok := parseGeoPointValRound60(args[0]); ok {
				return gp.ArcDistance(other.Lat, other.Lon), true, nil
			}
		}
		if len(args) == 2 {
			lat, ok1 := toFloat64WithRawPainless(args[0])
			lon, ok2 := toFloat64WithRawPainless(args[1])
			if !ok1 || !ok2 {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "arcDistance(lat, lon) requires numbers"}
			}
			return gp.ArcDistance(lat, lon), true, nil
		}
	case "planeDistance":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if len(args) == 1 {
			if other, ok := parseGeoPointValRound60(args[0]); ok {
				return gp.PlaneDistance(other.Lat, other.Lon), true, nil
			}
		}
		if len(args) == 2 {
			lat, ok1 := toFloat64WithRawPainless(args[0])
			lon, ok2 := toFloat64WithRawPainless(args[1])
			if !ok1 || !ok2 {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "planeDistance(lat, lon) requires numbers"}
			}
			return gp.PlaneDistance(lat, lon), true, nil
		}
	case "geohashDistance":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if len(args) == 1 {
			d, err := gp.GeohashDistance(fmt.Sprintf("%v", args[0]))
			return d, true, err
		}
	}
	return nil, false, nil
}

func evalFieldValMethodRound60(fv *FieldVal, mBare, argStr string, evalCallArgs func() ([]any, error), sourceMap, params map[string]any, depth int) (any, bool, error) {
	switch mBare {
	case "get":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if len(args) == 0 {
			return fv.GetDefault(nil), true, nil
		}
		if len(args) == 1 {
			return fv.GetDefault(args[0]), true, nil
		}
		idx, _ := toInt64Painless(args[0])
		return fv.GetAt(int(idx), args[1]), true, nil

	case "getValue":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		unwrapLongVal := func(v any) any {
			if bi, ok := v.(*painlessBigInteger); ok && bi != nil {
				return bi.longValue()
			}
			return v
		}
		if len(args) == 2 {
			idx, _ := toInt64Painless(args[0])
			if idx < 0 || int(idx) >= len(fv.Values) {
				return args[1], true, nil
			}
			return unwrapLongVal(fv.Values[int(idx)]), true, nil
		}
		if len(fv.Values) == 0 {
			if len(args) >= 1 {
				return args[0], true, nil
			}
			return nil, true, nil
		}
		return unwrapLongVal(fv.Values[0]), true, nil

	case "getValues":
		if _, err := evalCallArgs(); err != nil {
			return nil, true, err
		}
		outVals := make([]any, len(fv.Values))
		for i, v := range fv.Values {
			if bi, ok := v.(*painlessBigInteger); ok && bi != nil {
				outVals[i] = bi.longValue()
			} else {
				outVals[i] = v
			}
		}
		return outVals, true, nil

	case "asDouble":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		coerceDouble := func(v any) (any, error) {
			if v == nil {
				return nil, nil
			}
			if dv, ok := toFloat64WithRawPainless(v); ok {
				return dv, nil
			}
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse field [%s] as double", fv.Name)}
		}
		if len(args) == 2 {
			idx, _ := toInt64Painless(args[0])
			if idx < 0 || int(idx) >= len(fv.Values) {
				res, cErr := coerceDouble(args[1])
				return res, true, cErr
			}
			res, cErr := coerceDouble(fv.Values[int(idx)])
			return res, true, cErr
		}
		if len(fv.Values) == 0 {
			if len(args) >= 1 {
				res, cErr := coerceDouble(args[0])
				return res, true, cErr
			}
			return nil, true, nil
		}
		res, cErr := coerceDouble(fv.Values[0])
		return res, true, cErr

	case "asDate":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		dateFmt := lookupFieldFormatFromMapsRound61(sourceMap, params, fv.Name)
		isNano := fv.FieldType == "date_nanos"
		if len(args) == 2 {
			idx, _ := toInt64Painless(args[0])
			if idx < 0 || int(idx) >= len(fv.Values) {
				return args[1], true, nil
			}
			z, ok := parseDocDateWithMappingFormatRound61(fv.Values[int(idx)], dateFmt, isNano)
			if !ok {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse field [%s] as date", fv.Name)}
			}
			return z, true, nil
		}
		if len(fv.Values) == 0 {
			if len(args) >= 1 {
				return args[0], true, nil
			}
			return nil, true, nil
		}
		z, ok := parseDocDateWithMappingFormatRound61(fv.Values[0], dateFmt, isNano)
		if !ok {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse field [%s] as date", fv.Name)}
		}
		return z, true, nil

	case "asGeoPoint":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if len(args) == 2 {
			idx, _ := toInt64Painless(args[0])
			if idx < 0 || int(idx) >= len(fv.Values) {
				return args[1], true, nil
			}
			gp, ok := parseGeoPointValRound60(fv.Values[int(idx)])
			if !ok {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse field [%s] as geo_point", fv.Name)}
			}
			return gp, true, nil
		}
		if len(fv.Values) == 0 {
			if len(args) >= 1 {
				return args[0], true, nil
			}
			return nil, true, nil
		}
		gp, ok := parseGeoPointValRound60(fv.Values[0])
		if !ok {
			return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse field [%s] as geo_point", fv.Name)}
		}
		return gp, true, nil

	case "asString":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if len(args) == 2 {
			idx, _ := toInt64Painless(args[0])
			if idx < 0 || int(idx) >= len(fv.Values) {
				if args[1] == nil {
					return nil, true, nil
				}
				return FormatValueSafe(args[1]), true, nil
			}
			return FormatValueSafe(fv.Values[int(idx)]), true, nil
		}
		if len(fv.Values) == 0 {
			if len(args) >= 1 {
				if args[0] == nil {
					return nil, true, nil
				}
				return FormatValueSafe(args[0]), true, nil
			}
			return nil, true, nil
		}
		return FormatValueSafe(fv.Values[0]), true, nil

	case "set":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		var v any
		if len(args) > 0 {
			v = args[0]
		}
		fv.Set(v)
		return fv, true, nil

	case "append":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if fv.Root != nil && len(args) > 0 {
			cur := resolveParamPath(fv.Root, strings.Split(fv.Name, "."))
			setValueAtPath(fv.Root, strings.Split(fv.Name, "."), appendProcessorValuesRound60(cur, args[0]))
			fv.refreshValuesRound60()
		}
		return fv, true, nil

	case "move":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if fv.Root != nil && len(args) > 0 && fv.Exists() {
			dstName := resolveDestFieldNameRound60(args[0])
			dstPath := strings.Split(dstName, ".")
			if !hasPathInMapRound60(fv.Root, dstPath) {
				val := resolveParamPath(fv.Root, strings.Split(fv.Name, "."))
				fv.Remove()
				setValueAtPath(fv.Root, dstPath, val)
			}
		}
		return nil, true, nil

	case "overwrite":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if fv.Root != nil && len(args) > 0 && fv.Exists() {
			dstName := resolveDestFieldNameRound60(args[0])
			val := resolveParamPath(fv.Root, strings.Split(fv.Name, "."))
			fv.Remove()
			setValueAtPath(fv.Root, strings.Split(dstName, "."), val)
		}
		return nil, true, nil

	case "removeValuesIf":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if fv.Root != nil && len(args) > 0 {
			pl, isL := args[0].(*PainlessLambda)
			if !isL {
				return nil, true, &painlessExceptionError{exType: "IllegalArgumentException", message: "removeValuesIf requires a predicate lambda"}
			}
			cur := resolveParamPath(fv.Root, strings.Split(fv.Name, "."))
			if s, ok := cur.([]any); ok {
				kept := make([]any, 0, len(s))
				for _, item := range s {
					res, err := pl.Invoke([]any{item}, sourceMap, params, depth+1)
					if err != nil {
						return nil, true, err
					}
					if b, _ := res.(bool); !b {
						kept = append(kept, item)
					}
				}
				setValueAtPath(fv.Root, strings.Split(fv.Name, "."), kept)
			} else if cur != nil {
				res, err := pl.Invoke([]any{cur}, sourceMap, params, depth+1)
				if err != nil {
					return nil, true, err
				}
				if b, _ := res.(bool); b {
					fv.Remove()
				}
			}
			fv.refreshValuesRound60()
		}
		return fv, true, nil

	case "transform":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		if fv.Root != nil && len(args) > 0 {
			pl, isL := args[0].(*PainlessLambda)
			if !isL {
				res, tErr := evalFieldValTransformRound61(fv, argStr, sourceMap, params, depth)
				return res, true, tErr
			}
			cur := resolveParamPath(fv.Root, strings.Split(fv.Name, "."))
			if s, ok := cur.([]any); ok {
				next := make([]any, len(s))
				for i, item := range s {
					nv, err := pl.Invoke([]any{item}, sourceMap, params, depth+1)
					if err != nil {
						return nil, true, err
					}
					next[i] = nv
				}
				setValueAtPath(fv.Root, strings.Split(fv.Name, "."), next)
			} else if cur != nil {
				nv, err := pl.Invoke([]any{cur}, sourceMap, params, depth+1)
				if err != nil {
					return nil, true, err
				}
				setValueAtPath(fv.Root, strings.Split(fv.Name, "."), nv)
			}
			fv.refreshValuesRound60()
		}
		return fv, true, nil

	case "doc":
		args, err := evalCallArgs()
		if err != nil {
			return nil, true, err
		}
		idx := 0
		if len(args) > 0 {
			iv, _ := toInt64Painless(args[0])
			idx = int(iv)
		}
		return fv.docAtRound60(idx)
	}
	return nil, false, nil
}

func resolveDestFieldNameRound60(arg any) string {
	if dstFV, ok := arg.(*FieldVal); ok && dstFV != nil {
		return dstFV.Name
	}
	return fmt.Sprintf("%v", arg)
}

// resolveWrapperPropertyRound60 resolves property access (`.lat`, `.lon`, `.value`,
// `.values`, `.bytes`, `.offset`, `.length`, `.vectorValue`, `.magnitude`, etc.)
// on Round-60/61 wrapper values and `doc[...]` vectors.
func resolveWrapperPropertyRound60(curr any, seg string) (any, bool) {
	switch tv := curr.(type) {
	case *GeoPointVal:
		if tv == nil {
			return nil, false
		}
		switch seg {
		case "lat":
			return tv.Lat, true
		case "lon":
			return tv.Lon, true
		}
	case *GeoBoundingBoxVal:
		if tv == nil {
			return nil, false
		}
		switch seg {
		case "top_left", "topLeft":
			return tv.TopLeft, true
		case "bottom_right", "bottomRight":
			return tv.BottomRight, true
		case "top":
			if tv.TopLeft != nil {
				return tv.TopLeft.Lat, true
			}
			return 0.0, true
		case "bottom":
			if tv.BottomRight != nil {
				return tv.BottomRight.Lat, true
			}
			return 0.0, true
		case "left":
			if tv.TopLeft != nil {
				return tv.TopLeft.Lon, true
			}
			return 0.0, true
		case "right":
			if tv.BottomRight != nil {
				return tv.BottomRight.Lon, true
			}
			return 0.0, true
		}
	case *IPAddressVal:
		if tv == nil {
			return nil, false
		}
		switch seg {
		case "hostAddress":
			return tv.String(), true
		case "IPv4", "ipv4":
			return tv.Addr.Is4(), true
		case "IPv6", "ipv6":
			return tv.Addr.Is6(), true
		case "loopbackAddress":
			return tv.Addr.IsLoopback(), true
		case "multicastAddress":
			return tv.Addr.IsMulticast(), true
		case "siteLocalAddress", "private":
			return tv.Addr.IsPrivate(), true
		case "linkLocalAddress":
			return tv.Addr.IsLinkLocalUnicast() || tv.Addr.IsLinkLocalMulticast(), true
		}
	case *DenseVectorFieldVal:
		if tv == nil {
			return nil, false
		}
		switch seg {
		case "empty":
			return tv.IsEmpty(), true
		case "dims":
			if tv.Present && tv.Vec != nil {
				return int64(len(tv.Vec.Floats)), true
			}
			return int64(0), true
		case "magnitude":
			if tv.Present && tv.Vec != nil {
				return computeVectorMagnitudeF32Round61(tv.Vec.Floats, tv.Vec.Bytes, tv.Vec.ElemType), true
			}
			return float32(0), true
		case "value":
			if tv.Present && tv.Vec != nil {
				return tv.Vec, true
			}
			return nil, true
		}
	case *DenseVectorVal:
		if tv == nil {
			return nil, false
		}
		if tv.isMissingVectorRound62() {
			switch seg {
			case "empty":
				return true, true
			case "dims", "length", "magnitude", "vector", "vectorValue":
				panic(newMissingDenseVectorDocValueErrorRound62())
			}
			return nil, false
		}
		if idx, ok := parseSliceIndex(seg, len(tv.Floats)); ok {
			if (tv.ElemType == "byte" || tv.ElemType == "bit") && len(tv.Bytes) == len(tv.Floats) {
				return int64(tv.Bytes[idx]), true
			}
			return tv.Floats[idx], true
		}
		switch seg {
		case "vector", "vectorValue":
			return tv.vectorElementsSliceRound62(nil), true
		case "dims", "length":
			return int64(len(tv.Floats)), true
		case "empty":
			return len(tv.Floats) == 0, true
		case "magnitude":
			return computeVectorMagnitudeF32Round61(tv.Floats, tv.Bytes, tv.ElemType), true
		}
	case *UpdateMetadataVal:
		if tv != nil {
			if v, ok, err := tv.getField(seg); err == nil && ok {
				return v, true
			}
		}
	case *ZonedDateTimeVal:
		if tv == nil {
			return nil, false
		}
		switch seg {
		case "year":
			return tv.GetYear(), true
		case "monthValue", "monthOfYear":
			return tv.GetMonthValue(), true
		case "month", "monthEnum":
			return newMonthEnumRound62(tv.Time.Month()), true
		case "dayOfMonth", "date":
			return tv.GetDayOfMonth(), true
		case "dayOfYear":
			return tv.GetDayOfYear(), true
		case "dayOfWeek":
			return tv.GetDayOfWeek(), true
		case "dayOfWeekEnum":
			return tv.GetDayOfWeekEnum(), true
		case "hour", "hourOfDay":
			return tv.GetHour(), true
		case "minute", "minuteOfHour":
			return tv.GetMinute(), true
		case "second", "secondOfMinute":
			return tv.GetSecond(), true
		case "nano":
			return tv.GetNano(), true
		case "millis":
			return tv.ToEpochMilli(), true
		case "zone":
			return formatZonedDateTimeZoneIDRound62(tv.Time), true
		case "offset":
			return formatZonedDateTimeOffsetRound62(tv.Time), true
		}
	case DayOfWeekEnum:
		if seg == "value" {
			return tv.Value, true
		}
	case *DayOfWeekEnum:
		if tv != nil && seg == "value" {
			return tv.Value, true
		}
	case MonthEnum:
		if seg == "value" {
			return tv.Value, true
		}
	case *MonthEnum:
		if tv != nil && seg == "value" {
			return tv.Value, true
		}
	case *BytesRefVal:
		if tv == nil {
			return nil, false
		}
		switch seg {
		case "bytes":
			return tv.byteSliceForPainless(), true
		case "offset":
			return int64(tv.Offset), true
		case "length":
			return int64(tv.Length), true
		}
	case *FieldVal:
		if tv == nil {
			return nil, false
		}
		switch seg {
		case "value":
			return tv.GetDefault(nil), true
		case "values":
			return tv.Values, true
		case "empty":
			return tv.IsEmpty(), true
		case "length":
			return tv.Size(), true
		}
		if idx, ok := parseSliceIndex(seg, len(tv.Values)); ok {
			return tv.Values[idx], true
		}
	case []float64:
		if idx, ok := parseSliceIndex(seg, len(tv)); ok {
			return tv[idx], true
		}
		switch seg {
		case "length":
			return int64(len(tv)), true
		case "empty":
			return len(tv) == 0, true
		case "vectorValue":
			return tv, true
		case "magnitude":
			var sumSq float64
			for _, f := range tv {
				sumSq += f * f
			}
			return math.Sqrt(sumSq), true
		}
	}
	return nil, false
}

// execRound60StatementCall handles statement-level calls on `field('x').set(...)`,
// `Processors.*(ctx, ...)`, `lambda.accept(...)` / `lambda.run()`, and `fDoc.field(...).set(...)`.
func execRound60StatementCall(sourceMap map[string]any, stmt string, params map[string]any) (bool, error) {
	s := strings.TrimSpace(stmt)
	if strings.HasPrefix(s, "Processors.") || strings.HasPrefix(s, "field(") || strings.HasPrefix(s, "$(") {
		val, err := evalRHSExpr(sourceMap, s, params)
		if err != nil {
			return true, err
		}
		params["_last_expr_val"] = val
		return true, nil
	}
	for _, mSuffix := range []string{
		".set(", ".append(", ".move(", ".overwrite(", ".removeValuesIf(", ".transform(",
		".accept(", ".apply(",
	} {
		if recExpr, argExpr, isNullSafe, ok := matchTrailingMethodCallWithNullSafePainless(s, mSuffix); ok {
			// Only intercept if receiver resolves to a Round-60 wrapper (`*FieldVal`, `*FieldDocVal`, `*PainlessLambda`)
			if strings.Contains(recExpr, "field(") || (params != nil && isRound60WrapperExprRound60(recExpr, params)) {
				recVal, err := evalRHSExpr(sourceMap, recExpr, params)
				if err != nil {
					return true, err
				}
				if recVal == nil {
					if isNullSafe {
						params["_last_expr_val"] = nil
						return true, nil
					}
					return true, nil
				}
				mBare := strings.TrimSuffix(strings.TrimPrefix(mSuffix, "."), "(")
				res, handled, err := evalRound60ReceiverMethod(recVal, mBare, argExpr, sourceMap, params, 0)
				if handled {
					params["_last_expr_val"] = res
					return true, err
				}
			}
		}
	}
	for _, zSuffix := range []string{".remove()", ".deduplicate()", ".run()"} {
		if strings.HasSuffix(s, zSuffix) {
			recExpr := strings.TrimSpace(strings.TrimSuffix(s[:len(s)-len(zSuffix)], "?"))
			if strings.Contains(recExpr, "field(") || (params != nil && isRound60WrapperExprRound60(recExpr, params)) {
				recVal, err := evalRHSExpr(sourceMap, recExpr, params)
				if err != nil {
					return true, err
				}
				res, handled, err := evalRound60ZeroArgMethod(zSuffix, recVal, sourceMap, params, 0)
				if handled {
					params["_last_expr_val"] = res
					return true, err
				}
			}
		}
	}
	return false, nil
}

func isRound60WrapperExprRound60(expr string, params map[string]any) bool {
	root := strings.SplitN(strings.TrimSpace(expr), ".", 2)[0]
	v, ok := params[root]
	if !ok {
		return false
	}
	switch v.(type) {
	case *FieldVal, *FieldDocVal, *PainlessLambda, *DenseVectorFieldVal, *DenseVectorVal, *IPAddressVal, *GeoBoundingBoxVal:
		return true
	}
	return false
}

func round60WrapperEquals(a, b any) (bool, bool) {
	switch ta := a.(type) {
	case *IPAddressVal:
		if ta == nil {
			return b == nil, true
		}
		return ta.Equals(b), true
	case *GeoBoundingBoxVal:
		tb, ok := b.(*GeoBoundingBoxVal)
		if !ok {
			return false, true
		}
		if ta == nil || tb == nil {
			return ta == tb, true
		}
		tlEq, _ := round60WrapperEquals(ta.TopLeft, tb.TopLeft)
		brEq, _ := round60WrapperEquals(ta.BottomRight, tb.BottomRight)
		return tlEq && brEq, true
	case *DenseVectorVal:
		if ta == nil {
			return b == nil, true
		}
		switch tb := b.(type) {
		case *DenseVectorVal:
			if tb == nil || len(ta.Floats) != len(tb.Floats) {
				return false, true
			}
			for i := range ta.Floats {
				if ta.Floats[i] != tb.Floats[i] {
					return false, true
				}
			}
			return true, true
		case []any:
			if len(ta.Floats) != len(tb) {
				return false, true
			}
			for i := range ta.Floats {
				fv, ok := toFloat64WithRawPainless(tb[i])
				if !ok || ta.Floats[i] != float32(fv) {
					return false, true
				}
			}
			return true, true
		}
		return false, true
	case DayOfWeekEnum:
		switch tb := b.(type) {
		case DayOfWeekEnum:
			return ta.Value == tb.Value, true
		case *DayOfWeekEnum:
			return tb != nil && ta.Value == tb.Value, true
		case string:
			return ta.String() == strings.ToUpper(strings.TrimSpace(tb)), true
		}
		return false, true
	case *DayOfWeekEnum:
		if ta == nil {
			return b == nil, true
		}
		return round60WrapperEquals(*ta, b)
	case MonthEnum:
		switch tb := b.(type) {
		case MonthEnum:
			return ta.Value == tb.Value, true
		case *MonthEnum:
			return tb != nil && ta.Value == tb.Value, true
		case string:
			return ta.String() == strings.ToUpper(strings.TrimSpace(tb)), true
		}
		return false, true
	case *MonthEnum:
		if ta == nil {
			return b == nil, true
		}
		return round60WrapperEquals(*ta, b)
	case *ZonedDateTimeVal:
		if ta == nil {
			return b == nil, true
		}
		switch tb := b.(type) {
		case *ZonedDateTimeVal:
			return tb != nil && ta.Time.Equal(tb.Time), true
		case time.Time:
			return ta.Time.Equal(tb), true
		case string:
			if tm, ok := parsePainlessDateTime(tb); ok {
				return ta.Time.Equal(tm), true
			}
		}
		return false, true
	case *InstantVal:
		if ta == nil {
			return b == nil, true
		}
		switch tb := b.(type) {
		case *InstantVal:
			return tb != nil && ta.Time.Equal(tb.Time), true
		case time.Time:
			return ta.Time.Equal(tb), true
		case string:
			if tm, ok := parsePainlessDateTime(tb); ok {
				return ta.Time.Equal(tm), true
			}
		}
		return false, true
	case *GeoPointVal:
		tb, ok := b.(*GeoPointVal)
		if !ok {
			return false, true
		}
		if ta == nil || tb == nil {
			return ta == tb, true
		}
		return ta.Lat == tb.Lat && ta.Lon == tb.Lon, true
	case *BytesRefVal:
		tb, ok := b.(*BytesRefVal)
		if !ok {
			return false, true
		}
		if ta == nil || tb == nil {
			return ta == tb, true
		}
		return bytes.Equal(ta.Bytes[ta.Offset:ta.Offset+ta.Length], tb.Bytes[tb.Offset:tb.Offset+tb.Length]), true
	case *ByteBufferVal:
		tb, ok := b.(*ByteBufferVal)
		if !ok {
			return false, true
		}
		if ta == nil || tb == nil {
			return ta == tb, true
		}
		return bytes.Equal(ta.Bytes[ta.Pos:ta.Lim], tb.Bytes[tb.Pos:tb.Lim]), true
	case []float64:
		switch tb := b.(type) {
		case []float64:
			if len(ta) != len(tb) {
				return false, true
			}
			for i := range ta {
				if ta[i] != tb[i] {
					return false, true
				}
			}
			return true, true
		case []any:
			if len(ta) != len(tb) {
				return false, true
			}
			for i := range ta {
				fv, ok := toFloat64WithRawPainless(tb[i])
				if !ok || ta[i] != fv {
					return false, true
				}
			}
			return true, true
		}
		return false, true
	}

	// Symmetric cases where `b` is the Round-60/61 wrapper and `a` is string/time.Time/[]any
	switch b.(type) {
	case *IPAddressVal, *GeoBoundingBoxVal, *DenseVectorVal, DayOfWeekEnum, *DayOfWeekEnum, MonthEnum, *MonthEnum, *ZonedDateTimeVal, *InstantVal, *GeoPointVal, *BytesRefVal, *ByteBufferVal, []float64:
		return round60WrapperEquals(b, a)
	}
	return false, false
}
