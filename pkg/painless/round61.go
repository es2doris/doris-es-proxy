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
	"container/list"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ============================================================================
// Round 61 F29: Painless DoS Hardening (Container Pin Caps & Bounded Regex Cache)
// ============================================================================

const (
	// MaxPinnedRefs caps evalBudget.pinnedRefs per script execution.
	MaxPinnedRefs = 4096
	// MaxPinnedElements caps total tracked container/array elements per script execution.
	MaxPinnedElements = 262_144
	// MaxRegexPatternLen caps regex pattern length on /pattern/ literals and Pattern.compile(...).
	MaxRegexPatternLen = 4096
	// RegexCacheCapacity is the maximum number of compiled *regexp.Regexp entries cached globally.
	RegexCacheCapacity = 1024
)

type boundedRegexCacheItem struct {
	key string
	re  *regexp.Regexp
}

type boundedRegexLRUCache struct {
	mu    sync.Mutex
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

var globalBoundedRegexCache = &boundedRegexLRUCache{
	cap:   RegexCacheCapacity,
	ll:    list.New(),
	items: make(map[string]*list.Element, 128),
}

func (c *boundedRegexLRUCache) get(key string) (*regexp.Regexp, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		c.ll.MoveToFront(elem)
		return elem.Value.(*boundedRegexCacheItem).re, true
	}
	return nil, false
}

func (c *boundedRegexLRUCache) put(key string, re *regexp.Regexp) {
	if re == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		c.ll.MoveToFront(elem)
		elem.Value.(*boundedRegexCacheItem).re = re
		return
	}
	if c.ll.Len() >= c.cap {
		if back := c.ll.Back(); back != nil {
			c.ll.Remove(back)
			delete(c.items, back.Value.(*boundedRegexCacheItem).key)
		}
	}
	elem := c.ll.PushFront(&boundedRegexCacheItem{key: key, re: re})
	c.items[key] = elem
}

// CompileBoundedRegex enforces MaxRegexPatternLen (4096) and compiles (with Java named-group
// normalization) using a thread-safe bounded 1,024-entry LRU cache. Exported so pkg/proxy
// Grok and ingest processors can reuse the bounded cache.
func CompileBoundedRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > MaxRegexPatternLen {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Regex pattern length %d exceeds maximum allowed length (%d)", len(pattern), MaxRegexPatternLen),
		}
	}
	if cached, ok := globalBoundedRegexCache.get(pattern); ok {
		return cached, nil
	}
	norm := normalizeJavaNamedGroupsPainless(pattern)
	re, err := regexp.Compile(norm)
	if err != nil {
		return nil, err
	}
	globalBoundedRegexCache.put(pattern, re)
	return re, nil
}

func compileBoundedWrappedRegexRound61(prefix, innerPattern, suffix string) (*regexp.Regexp, error) {
	if len(innerPattern) > MaxRegexPatternLen {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Regex pattern length %d exceeds maximum allowed length (%d)", len(innerPattern), MaxRegexPatternLen),
		}
	}
	full := prefix + innerPattern + suffix
	if cached, ok := globalBoundedRegexCache.get(full); ok {
		return cached, nil
	}
	norm := normalizeJavaNamedGroupsPainless(full)
	re, err := regexp.Compile(norm)
	if err != nil {
		return nil, err
	}
	globalBoundedRegexCache.put(full, re)
	return re, nil
}

func recordPinnedContainerRound61(budget *evalBudget, ref any, elemCount int) error {
	if budget == nil {
		return nil
	}
	if budget.stickyErr != nil {
		return budget.stickyErr
	}
	if len(budget.pinnedRefs) >= MaxPinnedRefs {
		err := &painlessExceptionError{
			exType:  "PainlessError",
			message: fmt.Sprintf("maximum pinned container references (%d) exceeded", MaxPinnedRefs),
		}
		budget.stickyErr = err
		return err
	}
	if elemCount < 0 {
		elemCount = 0
	}
	if budget.pinnedElements+elemCount > MaxPinnedElements {
		err := &painlessExceptionError{
			exType:  "PainlessError",
			message: fmt.Sprintf("maximum tracked container elements (%d) exceeded", MaxPinnedElements),
		}
		budget.stickyErr = err
		return err
	}
	budget.pinnedRefs = append(budget.pinnedRefs, ref)
	budget.pinnedElements += elemCount
	return nil
}

func recordAllocatedElementsRound61(budget *evalBudget, elemCount int) error {
	if budget == nil || elemCount <= 0 {
		return nil
	}
	if budget.stickyErr != nil {
		return budget.stickyErr
	}
	if budget.pinnedElements+elemCount > MaxPinnedElements {
		err := &painlessExceptionError{
			exType:  "PainlessError",
			message: fmt.Sprintf("maximum tracked container elements (%d) exceeded", MaxPinnedElements),
		}
		budget.stickyErr = err
		return err
	}
	budget.pinnedElements += elemCount
	return nil
}

// ============================================================================
// Round 61 F24: Doc-Value / Fields API Access Guards, Typed Wrappers,
// Half-Float, Flattened, GeoPoint Quantization, IPAddress & Joda Guards
// ============================================================================

// DocValuesDisabledMessage returns Elasticsearch's exact illegal_argument_exception
// reason when `doc['field']` accesses a field without doc_values / fielddata.
func DocValuesDisabledMessage(field, indexName, fieldType string) string {
	if indexName == "" {
		indexName = "_index"
	}
	switch fieldType {
	case "text", "annotated_text":
		return fmt.Sprintf("Fielddata is disabled on [%s] in [%s]. Text fields are not optimised for operations that require per-document field data like aggregations and sorting, so these operations are disabled by default. Please use a keyword field instead. Alternatively, set fielddata=true on [%s] in order to load field data by uninverting the inverted index. Note that this can use significant memory.", field, indexName, field)
	case "match_only_text":
		return fmt.Sprintf("Fielddata is not supported on field [%s] of type [match_only_text]", field)
	default:
		return fmt.Sprintf("Cannot search on field [%s] since it is not indexed or has doc_values turned off.", field)
	}
}

// FieldsAPIDisabledMessage returns Elasticsearch's illegal_argument_exception reason
// when `field('f')` cannot load from doc_values, stored fields, or `_source`.
func FieldsAPIDisabledMessage(field, indexName string) string {
	if indexName == "" {
		indexName = "_index"
	}
	return fmt.Sprintf("Unable to retrieve values for field [%s] in [%s] because doc_values are disabled, store is false, and _source is disabled", field, indexName)
}

func checkDocValuesAccessGuardRound61(params map[string]any, fieldPath string) error {
	if params == nil || fieldPath == "" {
		return nil
	}
	if guards, ok := params["__disabled_doc_values"].(map[string]string); ok && guards != nil {
		if msg, blocked := guards[fieldPath]; blocked && msg != "" {
			return &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: msg,
			}
		}
	}
	return nil
}

func checkFieldsAPIAccessGuardRound61(params map[string]any, fieldPath string) error {
	if params == nil || fieldPath == "" {
		return nil
	}
	if guards, ok := params["__disabled_fields_api"].(map[string]string); ok && guards != nil {
		if msg, blocked := guards[fieldPath]; blocked && msg != "" {
			return &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: msg,
			}
		}
	}
	return nil
}

// HalfFloatToBits converts a float64 to IEEE-754 binary16 (round-to-nearest-even).
func HalfFloatToBits(f float64) uint16 {
	f32 := float32(f)
	b := math.Float32bits(f32)
	sign := uint16((b >> 16) & 0x8000)
	exp := int((b>>23)&0xff) - 127 + 15
	mant := b & 0x007fffff

	if (b>>23)&0xff == 0xff {
		if mant != 0 {
			return sign | 0x7e00 // quiet NaN
		}
		return sign | 0x7c00 // Inf
	}
	if exp <= 0 {
		if exp < -10 {
			return sign
		}
		mant |= 0x00800000
		shift := uint(14 - exp)
		halfMant := mant >> shift
		rem := mant & ((1 << shift) - 1)
		halfway := uint32(1) << (shift - 1)
		if rem > halfway || (rem == halfway && (halfMant&1) != 0) {
			halfMant++
		}
		return sign | uint16(halfMant) // #nosec G115 -- halfMant <= 0x0400 fits in 11 bits of IEEE-754 binary16
	}
	if exp >= 31 {
		return sign | 0x7c00 // overflow to Inf
	}
	halfMant := mant >> 13
	rem := mant & 0x1fff
	if rem > 0x1000 || (rem == 0x1000 && (halfMant&1) != 0) {
		halfMant++
		if halfMant >= 0x0400 {
			halfMant = 0
			exp++
			if exp >= 31 {
				return sign | 0x7c00
			}
		}
	}
	return sign | uint16(exp<<10) | uint16(halfMant)
}

// HalfFloatFromBits converts an IEEE-754 binary16 bit pattern to float32.
func HalfFloatFromBits(h uint16) float32 {
	sign := uint32(h&0x8000) << 16
	exp := uint32(h>>10) & 0x1f
	mant := uint32(h & 0x03ff)

	if exp == 0 {
		if mant == 0 {
			return math.Float32frombits(sign)
		}
		exp32 := uint32(127 - 14)
		for (mant & 0x0400) == 0 {
			mant <<= 1
			exp32--
		}
		mant &= 0x03ff
		return math.Float32frombits(sign | (exp32 << 23) | (mant << 13))
	}
	if exp == 31 {
		if mant != 0 {
			return float32(math.NaN())
		}
		return math.Float32frombits(sign | 0x7f800000)
	}
	exp32 := exp - 15 + 127
	return math.Float32frombits(sign | (exp32 << 23) | (mant << 13))
}

// QuantizeHalfFloat quantizes f through IEEE-754 binary16 and returns the exact float32 value.
func QuantizeHalfFloat(f float64) float32 {
	return HalfFloatFromBits(HalfFloatToBits(f))
}

// FormatJavaFloat32 formats a float32 matching Java's Float.toString(float) contract:
// NaN, Infinity, -Infinity, decimal with ".0" for whole numbers in [1e-3, 1e7) (and 0.0/-0.0),
// and uppercase 'E' scientific notation outside [1e-3, 1e7).
func FormatJavaFloat32(v float32) string {
	f64 := float64(v)
	if math.IsNaN(f64) {
		return "NaN"
	}
	if math.IsInf(f64, 1) {
		return "Infinity"
	}
	if math.IsInf(f64, -1) {
		return "-Infinity"
	}
	if v == 0 {
		if math.Signbit(f64) {
			return "-0.0"
		}
		return "0.0"
	}
	abs := math.Abs(f64)
	if abs >= 1e-3 && abs < 1e7 {
		s := strconv.FormatFloat(f64, 'f', -1, 32)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	s := strconv.FormatFloat(f64, 'E', -1, 32)
	// Java uses E-4 not E-04, and E8 not E+08, with at least one decimal place before E.
	if eIdx := strings.IndexByte(s, 'E'); eIdx > 0 {
		mant := s[:eIdx]
		if !strings.Contains(mant, ".") {
			mant += ".0"
		}
		expPart := s[eIdx+1:]
		expInt, err := strconv.Atoi(expPart)
		if err == nil {
			return fmt.Sprintf("%sE%d", mant, expInt)
		}
	}
	return s
}

// FormatJavaFloat64 formats a float64 matching Java's Double.toString(double) contract:
// NaN, Infinity, -Infinity, decimal with ".0" for whole numbers in [1e-3, 1e7) (and 0.0/-0.0),
// and uppercase 'E' scientific notation outside [1e-3, 1e7).
func FormatJavaFloat64(v float64) string {
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
	if abs >= 1e-3 && abs < 1e7 {
		s := strconv.FormatFloat(v, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	s := strconv.FormatFloat(v, 'E', -1, 64)
	if eIdx := strings.IndexByte(s, 'E'); eIdx > 0 {
		mant := s[:eIdx]
		if !strings.Contains(mant, ".") {
			mant += ".0"
		}
		expPart := s[eIdx+1:]
		if expInt, err := strconv.Atoi(expPart); err == nil {
			return fmt.Sprintf("%sE%d", mant, expInt)
		}
	}
	return s
}

func tokenizeStandardAnalyzerWordsRound61(s string) []string {
	var tokens []string
	var cur strings.Builder
	runes := []rune(s)
	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			cur.WriteRune(r)
			continue
		}
		// Standard tokenizer keeps internal apostrophe / underscore / dot between alphanumerics
		if (r == '\'' || r == '_') && cur.Len() > 0 && i+1 < len(runes) && (unicode.IsLetter(runes[i+1]) || unicode.IsNumber(runes[i+1])) {
			cur.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return tokens
}

// AnalyzeStandardFielddataTokens produces sorted, deduplicated standard-analyzed tokens
// for `text` fields with `fielddata: true` accessed via `doc['field']`.
func AnalyzeStandardFielddataTokens(val any) []any {
	if val == nil {
		return []any{}
	}
	seen := make(map[string]struct{})
	var collect func(v any)
	collect = func(v any) {
		if v == nil {
			return
		}
		if sl, ok := v.([]any); ok {
			for _, item := range sl {
				collect(item)
			}
			return
		}
		if sl, ok := v.([]string); ok {
			for _, item := range sl {
				for _, tok := range tokenizeStandardAnalyzerWordsRound61(item) {
					seen[tok] = struct{}{}
				}
			}
			return
		}
		for _, tok := range tokenizeStandardAnalyzerWordsRound61(fmt.Sprintf("%v", v)) {
			seen[tok] = struct{}{}
		}
	}
	collect(val)
	if len(seen) == 0 {
		return []any{}
	}
	sorted := make([]string, 0, len(seen))
	for tok := range seen {
		sorted = append(sorted, tok)
	}
	sort.Strings(sorted)
	out := make([]any, len(sorted))
	for i, tok := range sorted {
		out[i] = tok
	}
	return out
}

// CountStandardAnalyzerTokens computes Elasticsearch `token_count` integer value
// using the standard analyzer across single or multi-valued string inputs.
func CountStandardAnalyzerTokens(val any) (int64, bool) {
	if val == nil {
		return 0, false
	}
	var total int64
	hasAny := false
	var walk func(v any)
	walk = func(v any) {
		if v == nil {
			return
		}
		if sl, ok := v.([]any); ok {
			for _, item := range sl {
				walk(item)
			}
			return
		}
		if sl, ok := v.([]string); ok {
			for _, item := range sl {
				hasAny = true
				total += int64(len(tokenizeStandardAnalyzerWordsRound61(item)))
			}
			return
		}
		if n, ok := isIntegerValuePainless(v); ok {
			// Already pre-counted numeric token_count
			hasAny = true
			total += n
			return
		}
		switch fv := v.(type) {
		case float64:
			if !math.IsNaN(fv) && !math.IsInf(fv, 0) && fv == math.Trunc(fv) {
				hasAny = true
				total += int64(fv)
				return
			}
		case float32:
			f64 := float64(fv)
			if !math.IsNaN(f64) && !math.IsInf(f64, 0) && f64 == math.Trunc(f64) {
				hasAny = true
				total += int64(f64)
				return
			}
		}
		hasAny = true
		total += int64(len(tokenizeStandardAnalyzerWordsRound61(fmt.Sprintf("%v", v))))
	}
	walk(val)
	return total, hasAny
}

func formatFlattenedScalarRound61(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	switch tv := v.(type) {
	case string:
		return tv, true
	case bool:
		if tv {
			return "true", true
		}
		return "false", true
	case json.Number:
		return tv.String(), true
	case int:
		return strconv.Itoa(tv), true
	case int64:
		return strconv.FormatInt(tv, 10), true
	case int32:
		return strconv.FormatInt(int64(tv), 10), true
	case float64:
		if tv == math.Trunc(tv) && !math.IsInf(tv, 0) && !math.IsNaN(tv) && math.Abs(tv) < 1e15 {
			return strconv.FormatInt(int64(tv), 10), true
		}
		return strconv.FormatFloat(tv, 'f', -1, 64), true
	case float32:
		f64 := float64(tv)
		if f64 == math.Trunc(f64) && !math.IsInf(f64, 0) && !math.IsNaN(f64) && math.Abs(f64) < 1e7 {
			return strconv.FormatInt(int64(f64), 10), true
		}
		return strconv.FormatFloat(f64, 'f', -1, 32), true
	default:
		return fmt.Sprintf("%v", tv), true
	}
}

// ExtractFlattenedLeafStrings extracts deduplicated, lexicographically sorted leaf string
// values from a `flattened` object (either at its root when subPath == "" or at a dotted subPath).
func ExtractFlattenedLeafStrings(root any, subPath string) []any {
	if root == nil {
		return []any{}
	}
	var targets []any
	var descend func(cur any, segs []string)
	descend = func(cur any, segs []string) {
		if cur == nil {
			return
		}
		if len(segs) == 0 {
			targets = append(targets, cur)
			return
		}
		switch tv := cur.(type) {
		case map[string]any:
			if v, ok := tv[segs[0]]; ok {
				descend(v, segs[1:])
			}
			// Also support pre-flattened dotted keys inside map
			joined := strings.Join(segs, ".")
			if v, ok := tv[joined]; ok {
				targets = append(targets, v)
			}
		case []any:
			for _, elem := range tv {
				descend(elem, segs)
			}
		}
	}
	if subPath == "" {
		targets = append(targets, root)
	} else {
		descend(root, strings.Split(subPath, "."))
	}

	seen := make(map[string]struct{})
	var collectLeaves func(v any)
	collectLeaves = func(v any) {
		if v == nil {
			return
		}
		switch tv := v.(type) {
		case map[string]any:
			for _, child := range tv {
				collectLeaves(child)
			}
		case []any:
			for _, child := range tv {
				collectLeaves(child)
			}
		default:
			if s, ok := formatFlattenedScalarRound61(tv); ok {
				seen[s] = struct{}{}
			}
		}
	}
	for _, t := range targets {
		collectLeaves(t)
	}
	if len(seen) == 0 {
		return []any{}
	}
	sorted := make([]string, 0, len(seen))
	for s := range seen {
		sorted = append(sorted, s)
	}
	sort.Strings(sorted)
	out := make([]any, len(sorted))
	for i, s := range sorted {
		out[i] = s
	}
	return out
}

func resolveMappedFlattenedBaseRound61(params map[string]any, fieldPath string) (rootField, subPath string, ok bool) {
	if params == nil || fieldPath == "" {
		return "", "", false
	}
	ftMap, _ := params["__field_types"].(map[string]string)
	if ftMap == nil {
		return "", "", false
	}
	if ftMap[fieldPath] == "flattened" {
		return fieldPath, "", true
	}
	for k, v := range ftMap {
		if v == "flattened" && strings.HasPrefix(fieldPath, k+".") {
			return k, strings.TrimPrefix(fieldPath, k+"."), true
		}
	}
	return "", "", false
}

// QuantizeLuceneGeoPoint applies Elasticsearch/Lucene's exact 32-bit Morton geo_point
// quantization (`GeoUtils.geoPointToMorton` / `GeoEncodingUtils`).
func QuantizeLuceneGeoPoint(lat, lon float64) (float64, float64) {
	const (
		latScale  = float64(int64(1)<<32) / 180.0
		latDecode = 180.0 / float64(int64(1)<<32)
		lonScale  = float64(int64(1)<<32) / 360.0
		lonDecode = 360.0 / float64(int64(1)<<32)
	)
	var latEnc int32
	if lat >= 90.0 {
		latEnc = math.MaxInt32
	} else if lat <= -90.0 {
		latEnc = math.MinInt32
	} else {
		latEnc = int32(math.Floor(lat * latScale))
	}
	var lonEnc int32
	if lon >= 180.0 {
		lonEnc = math.MaxInt32
	} else if lon <= -180.0 {
		lonEnc = math.MinInt32
	} else {
		lonEnc = int32(math.Floor(lon * lonScale))
	}
	return float64(int64(latEnc)) * latDecode, float64(int64(lonEnc)) * lonDecode
}

// GeoBoundingBoxVal models Elasticsearch's GeoBoundingBox returned by doc['geo_point'].getBoundingBox().
type GeoBoundingBoxVal struct {
	TopLeft     *GeoPointVal
	BottomRight *GeoPointVal
}

func (b *GeoBoundingBoxVal) MarshalJSON() ([]byte, error) {
	if b == nil {
		return []byte("null"), nil
	}
	return json.Marshal(map[string]any{
		"top_left":     b.TopLeft,
		"bottom_right": b.BottomRight,
	})
}

func (b *GeoBoundingBoxVal) String() string {
	if b == nil {
		return "null"
	}
	return fmt.Sprintf("GeoBoundingBox{topLeft=%v, bottomRight=%v}", b.TopLeft, b.BottomRight)
}

// GetMinLat returns the southern latitude of the bounding box.
func (b *GeoBoundingBoxVal) GetMinLat() float64 {
	if b == nil || b.BottomRight == nil {
		return 0.0
	}
	return b.BottomRight.Lat
}

// GetMaxLat returns the northern latitude of the bounding box.
func (b *GeoBoundingBoxVal) GetMaxLat() float64 {
	if b == nil || b.TopLeft == nil {
		return 0.0
	}
	return b.TopLeft.Lat
}

// GetMinLon returns the western longitude of the bounding box.
func (b *GeoBoundingBoxVal) GetMinLon() float64 {
	if b == nil || b.TopLeft == nil {
		return 0.0
	}
	return b.TopLeft.Lon
}

// GetMaxLon returns the eastern longitude of the bounding box.
func (b *GeoBoundingBoxVal) GetMaxLon() float64 {
	if b == nil || b.BottomRight == nil {
		return 0.0
	}
	return b.BottomRight.Lon
}

func evalGeoBoundingBoxMethodRound61(b *GeoBoundingBoxVal, method string) (any, bool, error) {
	if b == nil {
		return nil, false, nil
	}
	switch method {
	case "topLeft", "getTopLeft":
		return b.TopLeft, true, nil
	case "bottomRight", "getBottomRight":
		return b.BottomRight, true, nil
	case "top", "getTop", "maxLat", "getMaxLat":
		return b.GetMaxLat(), true, nil
	case "bottom", "getBottom", "minLat", "getMinLat":
		return b.GetMinLat(), true, nil
	case "left", "getLeft", "minLon", "getMinLon":
		return b.GetMinLon(), true, nil
	case "right", "getRight", "maxLon", "getMaxLon":
		return b.GetMaxLon(), true, nil
	case "toString":
		return b.String(), true, nil
	}
	return nil, false, nil
}

const webMercatorHalfCircumferenceRound61 = 20037508.34

func geoMercatorExtentMetersRound61(minLat, maxLat, minLon, maxLon float64) (mercWidth, mercHeight float64) {
	mercX := func(lon float64) float64 {
		return lon * webMercatorHalfCircumferenceRound61 / 180.0
	}
	mercY := func(lat float64) float64 {
		clamped := math.Max(-85.05112877980659, math.Min(85.05112877980659, lat))
		return math.Log(math.Tan((90.0+clamped)*math.Pi/360.0)) * (webMercatorHalfCircumferenceRound61 / math.Pi)
	}
	return math.Abs(mercX(maxLon) - mercX(minLon)), math.Abs(mercY(maxLat) - mercY(minLat))
}

func computeGeoSliceBoundsRound61(pts []*GeoPointVal) (topLeft, bottomRight, centroid *GeoPointVal, mercWidth, mercHeight float64) {
	if len(pts) == 0 {
		z := &GeoPointVal{}
		return z, z, z, 0, 0
	}
	minLat, maxLat := pts[0].Lat, pts[0].Lat
	minLon, maxLon := pts[0].Lon, pts[0].Lon
	sumLat, sumLon := 0.0, 0.0
	for _, p := range pts {
		if p.Lat < minLat {
			minLat = p.Lat
		}
		if p.Lat > maxLat {
			maxLat = p.Lat
		}
		if p.Lon < minLon {
			minLon = p.Lon
		}
		if p.Lon > maxLon {
			maxLon = p.Lon
		}
		sumLat += p.Lat
		sumLon += p.Lon
	}
	tl := &GeoPointVal{Lat: maxLat, Lon: minLon}
	br := &GeoPointVal{Lat: minLat, Lon: maxLon}
	c := &GeoPointVal{Lat: sumLat / float64(len(pts)), Lon: sumLon / float64(len(pts))}
	if len(pts) == 1 {
		return tl, br, &GeoPointVal{Lat: pts[0].Lat, Lon: pts[0].Lon}, 0.0, 0.0
	}
	mercWidth, mercHeight = geoMercatorExtentMetersRound61(minLat, maxLat, minLon, maxLon)
	return tl, br, c, mercWidth, mercHeight
}

// GeoShapeDocValues models Elasticsearch's GeoShapeDocValues (`doc['geo_shape']`)
// and individual Geometry elements (`doc['geo_shape'].get(i)`), supporting centroid,
// bounding box, label position, dimensional type, Mercator extent, collection indexing,
// and `<unserializable>` serialization matching Elasticsearch 8.15.
type GeoShapeDocValues struct {
	ShapeType  string
	Geometries []*GeoShapeDocValues
	Points     [][2]float64
	Lines      [][][2]float64
	Rings      [][][2]float64
	MultiRings [][][][2]float64
	HasBBox    bool
	MinLat     float64
	MaxLat     float64
	MinLon     float64
	MaxLon     float64
	DimType    int64
	Quantize   bool
	Raw        any
}

// String implements Painless/Java string representation for Geometry values (`<unserializable>`).
func (g *GeoShapeDocValues) String() string {
	return "<unserializable>"
}

// MarshalJSON serializes raw Geometry values as `"<unserializable>"`, matching ES script_fields.
func (g *GeoShapeDocValues) MarshalJSON() ([]byte, error) {
	if g == nil {
		return []byte("null"), nil
	}
	return []byte(`"<unserializable>"`), nil
}

// Size returns the number of top-level geometries represented.
func (g *GeoShapeDocValues) Size() int64 {
	if g == nil {
		return 0
	}
	if len(g.Geometries) > 0 {
		return int64(len(g.Geometries))
	}
	if g.ShapeType == "" {
		return 0
	}
	if len(g.Points) == 0 && len(g.Lines) == 0 && len(g.Rings) == 0 && len(g.MultiRings) == 0 && !g.HasBBox {
		return 0
	}
	return 1
}

// IsEmpty returns true when no geometry value is present.
func (g *GeoShapeDocValues) IsEmpty() bool {
	return g.Size() == 0
}

// Get returns the geometry at index i (supporting doc['geo_shape'].get(0) and GeometryCollection.get(i)).
func (g *GeoShapeDocValues) Get(idx int) (*GeoShapeDocValues, error) {
	if g == nil {
		return nil, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("index %d out of bounds for length 0", idx)}
	}
	if len(g.Geometries) > 0 {
		if idx < 0 || idx >= len(g.Geometries) {
			return nil, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("index %d out of bounds for length %d", idx, len(g.Geometries))}
		}
		return g.Geometries[idx], nil
	}
	n := int(g.Size())
	if idx < 0 || idx >= n {
		return nil, &painlessExceptionError{exType: "IndexOutOfBoundsException", message: fmt.Sprintf("index %d out of bounds for length %d", idx, n)}
	}
	return g, nil
}

// GetShapeType returns the canonical uppercase shape type name (e.g. "POLYGON", "POINT").
func (g *GeoShapeDocValues) GetShapeType() string {
	if g == nil {
		return ""
	}
	return g.ShapeType
}

// GetDimensionalType returns Elasticsearch's integer topological dimension:
// 0 for Point/MultiPoint, 1 for LineString/MultiLineString, 2 for Polygon/MultiPolygon/Envelope,
// or the maximum dimension across child geometries in a GeometryCollection.
func (g *GeoShapeDocValues) GetDimensionalType() int64 {
	if g == nil {
		return 0
	}
	if len(g.Geometries) > 0 {
		maxDim := int64(0)
		for _, ch := range g.Geometries {
			if d := ch.GetDimensionalType(); d > maxDim {
				maxDim = d
			}
		}
		return maxDim
	}
	return g.DimType
}

// GetBoundingBox returns the (Lucene BKD-quantized when Quantize is true) bounding box.
func (g *GeoShapeDocValues) GetBoundingBox() *GeoBoundingBoxVal {
	if g == nil || !g.HasBBox {
		z := &GeoPointVal{}
		return &GeoBoundingBoxVal{TopLeft: z, BottomRight: &GeoPointVal{}}
	}
	tlLat, tlLon := g.MaxLat, g.MinLon
	brLat, brLon := g.MinLat, g.MaxLon
	if g.Quantize {
		tlLat, tlLon = QuantizeLuceneGeoPoint(tlLat, tlLon)
		brLat, brLon = QuantizeLuceneGeoPoint(brLat, brLon)
	}
	return &GeoBoundingBoxVal{
		TopLeft:     &GeoPointVal{Lat: tlLat, Lon: tlLon},
		BottomRight: &GeoPointVal{Lat: brLat, Lon: brLon},
	}
}

// TopLeft returns the bounding box top-left (maxLat, minLon) GeoPoint.
func (g *GeoShapeDocValues) TopLeft() *GeoPointVal {
	return g.GetBoundingBox().TopLeft
}

// BottomRight returns the bounding box bottom-right (minLat, maxLon) GeoPoint.
func (g *GeoShapeDocValues) BottomRight() *GeoPointVal {
	return g.GetBoundingBox().BottomRight
}

// GetMercatorWidth returns the EPSG:3857 WebMercator width in meters of the bounding box.
func (g *GeoShapeDocValues) GetMercatorWidth() float64 {
	bb := g.GetBoundingBox()
	w, _ := geoMercatorExtentMetersRound61(bb.BottomRight.Lat, bb.TopLeft.Lat, bb.TopLeft.Lon, bb.BottomRight.Lon)
	return w
}

// GetMercatorHeight returns the EPSG:3857 WebMercator height in meters of the bounding box.
func (g *GeoShapeDocValues) GetMercatorHeight() float64 {
	bb := g.GetBoundingBox()
	_, h := geoMercatorExtentMetersRound61(bb.BottomRight.Lat, bb.TopLeft.Lat, bb.TopLeft.Lon, bb.BottomRight.Lon)
	return h
}

func geoRingShoelaceSignedCentroidRound61(ring [][2]float64) (lat, lon, absArea float64) {
	if len(ring) == 0 {
		return 0, 0, 0
	}
	if len(ring) < 3 {
		var sLat, sLon float64
		for _, p := range ring {
			sLat += p[0]
			sLon += p[1]
		}
		return sLat / float64(len(ring)), sLon / float64(len(ring)), 0
	}
	twiceArea := 0.0
	cxSum := 0.0
	cySum := 0.0
	for i := 0; i < len(ring); i++ {
		j := (i + 1) % len(ring)
		x0, y0 := ring[i][1], ring[i][0]
		x1, y1 := ring[j][1], ring[j][0]
		cross := x0*y1 - x1*y0
		twiceArea += cross
		cxSum += (x0 + x1) * cross
		cySum += (y0 + y1) * cross
	}
	if math.Abs(twiceArea) <= 1e-18 {
		var sLat, sLon float64
		for _, p := range ring {
			sLat += p[0]
			sLon += p[1]
		}
		return sLat / float64(len(ring)), sLon / float64(len(ring)), 0
	}
	return cySum / (3.0 * twiceArea), cxSum / (3.0 * twiceArea), math.Abs(twiceArea) / 2.0
}

func geoPolygonCentroidWeightedRound61(rings [][][2]float64) (lat, lon, area float64) {
	if len(rings) == 0 {
		return 0, 0, 0
	}
	extLat, extLon, extArea := geoRingShoelaceSignedCentroidRound61(rings[0])
	if extArea == 0 {
		return extLat, extLon, 0
	}
	sumArea := extArea
	sumWX := extArea * extLon
	sumWY := extArea * extLat
	for h := 1; h < len(rings); h++ {
		hLat, hLon, hArea := geoRingShoelaceSignedCentroidRound61(rings[h])
		if hArea > 0 {
			sumArea -= hArea
			sumWX -= hArea * hLon
			sumWY -= hArea * hLat
		}
	}
	if sumArea > 1e-18 {
		return sumWY / sumArea, sumWX / sumArea, sumArea
	}
	return extLat, extLon, extArea
}

func geoLineCentroidWeightedRound61(pts [][2]float64) (lat, lon, totalLen float64) {
	if len(pts) == 0 {
		return 0, 0, 0
	}
	if len(pts) == 1 {
		return pts[0][0], pts[0][1], 0
	}
	var sumWX, sumWY float64
	for i := 0; i < len(pts)-1; i++ {
		dx := pts[i+1][1] - pts[i][1]
		dy := pts[i+1][0] - pts[i][0]
		segLen := math.Hypot(dx, dy)
		totalLen += segLen
		sumWX += segLen * ((pts[i][1] + pts[i+1][1]) / 2.0)
		sumWY += segLen * ((pts[i][0] + pts[i+1][0]) / 2.0)
	}
	if totalLen > 1e-18 {
		return sumWY / totalLen, sumWX / totalLen, totalLen
	}
	var sLat, sLon float64
	for _, p := range pts {
		sLat += p[0]
		sLon += p[1]
	}
	return sLat / float64(len(pts)), sLon / float64(len(pts)), 0
}

func (g *GeoShapeDocValues) rawCentroidAndWeightRound61() (lat, lon, weight float64, dim int64) {
	if g == nil {
		return 0, 0, 0, 0
	}
	switch g.ShapeType {
	case "POINT":
		if len(g.Points) > 0 {
			return g.Points[0][0], g.Points[0][1], 1, 0
		}
	case "MULTIPOINT":
		if len(g.Points) > 0 {
			var sLat, sLon float64
			for _, p := range g.Points {
				sLat += p[0]
				sLon += p[1]
			}
			return sLat / float64(len(g.Points)), sLon / float64(len(g.Points)), float64(len(g.Points)), 0
		}
	case "LINESTRING":
		cLat, cLon, l := geoLineCentroidWeightedRound61(g.Points)
		return cLat, cLon, math.Max(l, 1e-12), 1
	case "MULTILINESTRING":
		var sumLen, sumWX, sumWY float64
		for _, ln := range g.Lines {
			cLat, cLon, l := geoLineCentroidWeightedRound61(ln)
			if l > 0 {
				sumLen += l
				sumWX += l * cLon
				sumWY += l * cLat
			}
		}
		if sumLen > 0 {
			return sumWY / sumLen, sumWX / sumLen, sumLen, 1
		}
		if len(g.Lines) > 0 && len(g.Lines[0]) > 0 {
			return g.Lines[0][0][0], g.Lines[0][0][1], 1e-12, 1
		}
	case "POLYGON":
		cLat, cLon, a := geoPolygonCentroidWeightedRound61(g.Rings)
		if a == 0 && len(g.Rings) > 0 && len(g.Rings[0]) > 0 {
			// Degenerate polygon fallback to line centroid
			cLat, cLon, _ = geoLineCentroidWeightedRound61(g.Rings[0])
		}
		return cLat, cLon, math.Max(a, 1e-12), 2
	case "MULTIPOLYGON":
		var sumArea, sumWX, sumWY float64
		for _, poly := range g.MultiRings {
			cLat, cLon, a := geoPolygonCentroidWeightedRound61(poly)
			if a > 0 {
				sumArea += a
				sumWX += a * cLon
				sumWY += a * cLat
			}
		}
		if sumArea > 0 {
			return sumWY / sumArea, sumWX / sumArea, sumArea, 2
		}
		if len(g.MultiRings) > 0 && len(g.MultiRings[0]) > 0 && len(g.MultiRings[0][0]) > 0 {
			cLat, cLon, _ := geoLineCentroidWeightedRound61(g.MultiRings[0][0])
			return cLat, cLon, 1e-12, 2
		}
	case "ENVELOPE", "BBOX", "CIRCLE":
		cLat := (g.MinLat + g.MaxLat) / 2.0
		cLon := (g.MinLon + g.MaxLon) / 2.0
		area := math.Max(0, (g.MaxLat-g.MinLat)*(g.MaxLon-g.MinLon))
		return cLat, cLon, math.Max(area, 1e-12), 2
	}
	if len(g.Geometries) > 0 {
		maxDim := g.GetDimensionalType()
		var sumW, sumWX, sumWY float64
		for _, ch := range g.Geometries {
			cLat, cLon, w, cDim := ch.rawCentroidAndWeightRound61()
			if cDim == maxDim && w > 0 {
				sumW += w
				sumWX += w * cLon
				sumWY += w * cLat
			}
		}
		if sumW > 0 {
			return sumWY / sumW, sumWX / sumW, sumW, maxDim
		}
	}
	if g.HasBBox {
		return (g.MinLat + g.MaxLat) / 2.0, (g.MinLon + g.MaxLon) / 2.0, 1, g.DimType
	}
	return 0, 0, 0, 0
}

// GetCentroid returns the centroid GeoPoint (quantized when Quantize is true).
func (g *GeoShapeDocValues) GetCentroid() *GeoPointVal {
	lat, lon, _, _ := g.rawCentroidAndWeightRound61()
	if g != nil && g.Quantize {
		lat, lon = QuantizeLuceneGeoPoint(lat, lon)
	}
	return &GeoPointVal{Lat: lat, Lon: lon}
}

func pointInRingRayRound61(lat, lon float64, ring [][2]float64) bool {
	inside := false
	n := len(ring)
	for i, j := 0, n-1; i < n; j, i = i, i+1 {
		yi, xi := ring[i][0], ring[i][1]
		yj, xj := ring[j][0], ring[j][1]
		if (yi > lat) != (yj > lat) {
			xIntersect := (xj-xi)*(lat-yi)/(yj-yi) + xi
			if lon < xIntersect {
				inside = !inside
			}
		}
	}
	return inside
}

func pointInPolygonRingsRound61(lat, lon float64, rings [][][2]float64) bool {
	if len(rings) == 0 || !pointInRingRayRound61(lat, lon, rings[0]) {
		return false
	}
	for h := 1; h < len(rings); h++ {
		if pointInRingRayRound61(lat, lon, rings[h]) {
			return false
		}
	}
	return true
}

// GetLabelPosition returns a representative label GeoPoint inside the geometry when applicable.
func (g *GeoShapeDocValues) GetLabelPosition() *GeoPointVal {
	if g == nil {
		return &GeoPointVal{}
	}
	lat, lon, _, _ := g.rawCentroidAndWeightRound61()
	if g.ShapeType == "POLYGON" && len(g.Rings) > 0 && !pointInPolygonRingsRound61(lat, lon, g.Rings) {
		// Try midpoints of bbox grid to find an interior point for concave polygons
		bestLat, bestLon := lat, lon
		found := false
		for gy := 1; gy <= 8 && !found; gy++ {
			candLat := g.MinLat + (g.MaxLat-g.MinLat)*float64(gy)/9.0
			for gx := 1; gx <= 8; gx++ {
				candLon := g.MinLon + (g.MaxLon-g.MinLon)*float64(gx)/9.0
				if pointInPolygonRingsRound61(candLat, candLon, g.Rings) {
					bestLat, bestLon = candLat, candLon
					found = true
					break
				}
			}
		}
		lat, lon = bestLat, bestLon
	}
	// If midpoint of LineString exists, ES uses centroid; fallback stays centroid.
	if g.Quantize {
		lat, lon = QuantizeLuceneGeoPoint(lat, lon)
	}
	return &GeoPointVal{Lat: lat, Lon: lon}
}

// ToGeoJSONMap converts GeoShapeDocValues to a GeoJSON map representation for runtime emit/source formatting.
func (g *GeoShapeDocValues) ToGeoJSONMap() map[string]any {
	if g == nil {
		return nil
	}
	ringToSlice := func(ring [][2]float64) []any {
		out := make([]any, len(ring))
		for i, p := range ring {
			out[i] = []any{p[1], p[0]}
		}
		return out
	}
	ringsToSlice := func(rings [][][2]float64) []any {
		out := make([]any, len(rings))
		for i, r := range rings {
			out[i] = ringToSlice(r)
		}
		return out
	}
	switch g.ShapeType {
	case "POINT":
		if len(g.Points) > 0 {
			return map[string]any{"type": "Point", "coordinates": []any{g.Points[0][1], g.Points[0][0]}}
		}
	case "MULTIPOINT":
		return map[string]any{"type": "MultiPoint", "coordinates": ringToSlice(g.Points)}
	case "LINESTRING":
		return map[string]any{"type": "LineString", "coordinates": ringToSlice(g.Points)}
	case "MULTILINESTRING":
		return map[string]any{"type": "MultiLineString", "coordinates": ringsToSlice(g.Lines)}
	case "POLYGON":
		return map[string]any{"type": "Polygon", "coordinates": ringsToSlice(g.Rings)}
	case "MULTIPOLYGON":
		polys := make([]any, len(g.MultiRings))
		for i, p := range g.MultiRings {
			polys[i] = ringsToSlice(p)
		}
		return map[string]any{"type": "MultiPolygon", "coordinates": polys}
	case "ENVELOPE", "BBOX":
		return map[string]any{
			"type":        "Envelope",
			"coordinates": []any{[]any{g.MinLon, g.MaxLat}, []any{g.MaxLon, g.MinLat}},
		}
	case "GEOMETRYCOLLECTION":
		ch := make([]any, 0, len(g.Geometries))
		for _, sub := range g.Geometries {
			if m := sub.ToGeoJSONMap(); m != nil {
				ch = append(ch, m)
			}
		}
		return map[string]any{"type": "GeometryCollection", "geometries": ch}
	}
	if m, ok := g.Raw.(map[string]any); ok {
		return m
	}
	return map[string]any{
		"type":        "Envelope",
		"coordinates": []any{[]any{g.MinLon, g.MaxLat}, []any{g.MaxLon, g.MinLat}},
	}
}

func (g *GeoShapeDocValues) updateBBoxFromPoint(lat, lon float64) {
	if !g.HasBBox {
		g.HasBBox = true
		g.MinLat, g.MaxLat = lat, lat
		g.MinLon, g.MaxLon = lon, lon
		return
	}
	if lat < g.MinLat {
		g.MinLat = lat
	}
	if lat > g.MaxLat {
		g.MaxLat = lat
	}
	if lon < g.MinLon {
		g.MinLon = lon
	}
	if lon > g.MaxLon {
		g.MaxLon = lon
	}
}

func (g *GeoShapeDocValues) finalizeBounds() {
	g.HasBBox = false
	for _, p := range g.Points {
		g.updateBBoxFromPoint(p[0], p[1])
	}
	for _, ln := range g.Lines {
		for _, p := range ln {
			g.updateBBoxFromPoint(p[0], p[1])
		}
	}
	for _, ring := range g.Rings {
		for _, p := range ring {
			g.updateBBoxFromPoint(p[0], p[1])
		}
	}
	for _, poly := range g.MultiRings {
		for _, ring := range poly {
			for _, p := range ring {
				g.updateBBoxFromPoint(p[0], p[1])
			}
		}
	}
	for _, ch := range g.Geometries {
		if ch != nil && ch.HasBBox {
			g.updateBBoxFromPoint(ch.MinLat, ch.MinLon)
			g.updateBBoxFromPoint(ch.MaxLat, ch.MaxLon)
		}
	}
}

// NewGeoShapeDocValuesCollection aggregates multiple GeoShapeDocValues shapes into a single GeoShapeDocValues collection.
func NewGeoShapeDocValuesCollection(shapes []*GeoShapeDocValues, quantize bool) *GeoShapeDocValues {
	if len(shapes) == 1 && shapes[0] != nil {
		return shapes[0]
	}
	gs := &GeoShapeDocValues{
		ShapeType:  "GEOMETRYCOLLECTION",
		Geometries: make([]*GeoShapeDocValues, 0, len(shapes)),
		Quantize:   quantize,
	}
	for _, s := range shapes {
		if s == nil {
			continue
		}
		gs.Geometries = append(gs.Geometries, s)
		if s.DimType > gs.DimType {
			gs.DimType = s.DimType
		}
	}
	gs.finalizeBounds()
	return gs
}

func parseGeoCoordPairRound61(v any) (lat, lon float64, ok bool) {
	switch tv := v.(type) {
	case []any:
		if len(tv) < 2 {
			return 0, 0, false
		}
		x, okX := toFloat64WithRawPainless(tv[0])
		y, okY := toFloat64WithRawPainless(tv[1])
		if !okX || !okY || math.IsNaN(x) || math.IsNaN(y) || math.IsInf(x, 0) || math.IsInf(y, 0) {
			return 0, 0, false
		}
		return y, x, true
	case []float64:
		if len(tv) < 2 {
			return 0, 0, false
		}
		return tv[1], tv[0], true
	case map[string]any:
		if gp, gOk := parseGeoPointValRound60(tv); gOk {
			return gp.Lat, gp.Lon, true
		}
	}
	return 0, 0, false
}

func parseGeoCoordArray1DRound61(v any) ([][2]float64, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	pts := make([][2]float64, 0, len(arr))
	for _, item := range arr {
		lat, lon, pOk := parseGeoCoordPairRound61(item)
		if !pOk {
			return nil, false
		}
		pts = append(pts, [2]float64{lat, lon})
	}
	return pts, len(pts) > 0
}

func parseGeoCoordRingsRound61(v any) ([][][2]float64, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	rings := make([][][2]float64, 0, len(arr))
	for _, item := range arr {
		pts, pOk := parseGeoCoordArray1DRound61(item)
		if !pOk {
			return nil, false
		}
		rings = append(rings, pts)
	}
	return rings, len(rings) > 0
}

func parseWKTParenthesizedGroupsRound61(body string) []string {
	var groups []string
	depth := 0
	start := -1
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '(':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				groups = append(groups, strings.TrimSpace(body[start:i]))
				start = -1
			}
		}
	}
	return groups
}

func parseWKTPointSeqRound61(seq string) ([][2]float64, error) {
	parts := strings.Split(seq, ",")
	pts := make([][2]float64, 0, len(parts))
	for _, part := range parts {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) < 2 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid WKT coordinate %q", part)}
		}
		lon, errX := strconv.ParseFloat(fields[0], 64)
		lat, errY := strconv.ParseFloat(fields[1], 64)
		if errX != nil || errY != nil || math.IsNaN(lat) || math.IsNaN(lon) {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid WKT numeric coordinate %q", part)}
		}
		pts = append(pts, [2]float64{lat, lon})
	}
	if len(pts) == 0 {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "empty WKT coordinate list"}
	}
	return pts, nil
}

func splitTopLevelWKTItemsRound61(body string) []string {
	var items []string
	depth := 0
	start := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				items = append(items, strings.TrimSpace(body[start:i]))
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(body[start:]); tail != "" {
		items = append(items, tail)
	}
	return items
}

func parseWKTGeoShapeRound61(wkt string, quantize bool) (*GeoShapeDocValues, error) {
	s := strings.TrimSpace(wkt)
	if s == "" {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "empty WKT geo_shape"}
	}
	if strings.EqualFold(s, "EMPTY") {
		return &GeoShapeDocValues{ShapeType: "GEOMETRYCOLLECTION", Quantize: quantize}, nil
	}
	openIdx := strings.IndexByte(s, '(')
	if openIdx < 0 {
		upper := strings.ToUpper(s)
		if strings.HasSuffix(upper, "EMPTY") {
			typ := strings.TrimSpace(strings.TrimSuffix(upper, "EMPTY"))
			dim := int64(0)
			switch typ {
			case "LINESTRING", "MULTILINESTRING":
				dim = 1
			case "POLYGON", "MULTIPOLYGON", "ENVELOPE", "BBOX":
				dim = 2
			}
			return &GeoShapeDocValues{ShapeType: typ, DimType: dim, Quantize: quantize}, nil
		}
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid WKT geo_shape: %q", wkt)}
	}
	if !strings.HasSuffix(s, ")") {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("unterminated WKT geo_shape: %q", wkt)}
	}
	typ := strings.ToUpper(strings.TrimSpace(s[:openIdx]))
	// Strip optional Z / M / ZM suffix tokens (e.g. "POINT Z")
	if fields := strings.Fields(typ); len(fields) > 1 {
		typ = fields[0]
	}
	inner := strings.TrimSpace(s[openIdx+1 : len(s)-1])
	switch typ {
	case "POINT":
		pts, err := parseWKTPointSeqRound61(inner)
		if err != nil {
			return nil, err
		}
		gs := &GeoShapeDocValues{ShapeType: "POINT", Points: pts[:1], DimType: 0, Quantize: quantize, Raw: wkt}
		gs.finalizeBounds()
		return gs, nil
	case "MULTIPOINT":
		groups := parseWKTParenthesizedGroupsRound61(inner)
		var pts [][2]float64
		if len(groups) > 0 {
			for _, g := range groups {
				sub, err := parseWKTPointSeqRound61(g)
				if err != nil {
					return nil, err
				}
				pts = append(pts, sub...)
			}
		} else {
			sub, err := parseWKTPointSeqRound61(inner)
			if err != nil {
				return nil, err
			}
			pts = sub
		}
		gs := &GeoShapeDocValues{ShapeType: "MULTIPOINT", Points: pts, DimType: 0, Quantize: quantize, Raw: wkt}
		gs.finalizeBounds()
		return gs, nil
	case "LINESTRING":
		pts, err := parseWKTPointSeqRound61(inner)
		if err != nil {
			return nil, err
		}
		gs := &GeoShapeDocValues{ShapeType: "LINESTRING", Points: pts, DimType: 1, Quantize: quantize, Raw: wkt}
		gs.finalizeBounds()
		return gs, nil
	case "MULTILINESTRING":
		groups := parseWKTParenthesizedGroupsRound61(inner)
		if len(groups) == 0 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid MULTILINESTRING WKT: %q", wkt)}
		}
		lines := make([][][2]float64, 0, len(groups))
		for _, g := range groups {
			pts, err := parseWKTPointSeqRound61(g)
			if err != nil {
				return nil, err
			}
			lines = append(lines, pts)
		}
		gs := &GeoShapeDocValues{ShapeType: "MULTILINESTRING", Lines: lines, DimType: 1, Quantize: quantize, Raw: wkt}
		gs.finalizeBounds()
		return gs, nil
	case "POLYGON":
		groups := parseWKTParenthesizedGroupsRound61(inner)
		if len(groups) == 0 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid POLYGON WKT: %q", wkt)}
		}
		rings := make([][][2]float64, 0, len(groups))
		for _, g := range groups {
			pts, err := parseWKTPointSeqRound61(g)
			if err != nil {
				return nil, err
			}
			rings = append(rings, pts)
		}
		gs := &GeoShapeDocValues{ShapeType: "POLYGON", Rings: rings, DimType: 2, Quantize: quantize, Raw: wkt}
		gs.finalizeBounds()
		return gs, nil
	case "MULTIPOLYGON":
		polyGroups := parseWKTParenthesizedGroupsRound61(inner)
		if len(polyGroups) == 0 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid MULTIPOLYGON WKT: %q", wkt)}
		}
		multi := make([][][][2]float64, 0, len(polyGroups))
		for _, pg := range polyGroups {
			ringGroups := parseWKTParenthesizedGroupsRound61(pg)
			if len(ringGroups) == 0 {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid polygon inside MULTIPOLYGON: %q", pg)}
			}
			rings := make([][][2]float64, 0, len(ringGroups))
			for _, rg := range ringGroups {
				pts, err := parseWKTPointSeqRound61(rg)
				if err != nil {
					return nil, err
				}
				rings = append(rings, pts)
			}
			multi = append(multi, rings)
		}
		gs := &GeoShapeDocValues{ShapeType: "MULTIPOLYGON", MultiRings: multi, DimType: 2, Quantize: quantize, Raw: wkt}
		gs.finalizeBounds()
		return gs, nil
	case "ENVELOPE", "BBOX":
		parts := strings.Split(inner, ",")
		if len(parts) != 4 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("WKT %s requires 4 coordinates (minLon, maxLon, maxLat, minLat)", typ)}
		}
		var coords [4]float64
		for i, p := range parts {
			v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
			if err != nil || math.IsNaN(v) {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("invalid coordinate %q in %s", p, typ)}
			}
			coords[i] = v
		}
		minLon, maxLon := math.Min(coords[0], coords[1]), math.Max(coords[0], coords[1])
		minLat, maxLat := math.Min(coords[2], coords[3]), math.Max(coords[2], coords[3])
		gs := &GeoShapeDocValues{
			ShapeType: typ,
			HasBBox:   true,
			MinLat:    minLat,
			MaxLat:    maxLat,
			MinLon:    minLon,
			MaxLon:    maxLon,
			DimType:   2,
			Quantize:  quantize,
			Raw:       wkt,
		}
		return gs, nil
	case "GEOMETRYCOLLECTION":
		items := splitTopLevelWKTItemsRound61(inner)
		children := make([]*GeoShapeDocValues, 0, len(items))
		var maxDim int64
		for _, item := range items {
			ch, err := parseWKTGeoShapeRound61(item, quantize)
			if err != nil {
				return nil, err
			}
			children = append(children, ch)
			if d := ch.GetDimensionalType(); d > maxDim {
				maxDim = d
			}
		}
		gs := &GeoShapeDocValues{
			ShapeType:  "GEOMETRYCOLLECTION",
			Geometries: children,
			DimType:    maxDim,
			Quantize:   quantize,
			Raw:        wkt,
		}
		gs.finalizeBounds()
		return gs, nil
	default:
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("unsupported WKT geometry type [%s]", typ)}
	}
}

func parseRadiusMetersRound61(raw any) (float64, bool) {
	switch tv := raw.(type) {
	case float64:
		return tv, !math.IsNaN(tv) && tv >= 0
	case int64:
		return float64(tv), tv >= 0
	case int:
		return float64(tv), tv >= 0
	case json.Number:
		f, err := tv.Float64()
		return f, err == nil && f >= 0
	case string:
		s := strings.ToLower(strings.TrimSpace(tv))
		mult := 1.0
		switch {
		case strings.HasSuffix(s, "km"):
			mult = 1000.0
			s = strings.TrimSpace(strings.TrimSuffix(s, "km"))
		case strings.HasSuffix(s, "mi"):
			mult = 1609.344
			s = strings.TrimSpace(strings.TrimSuffix(s, "mi"))
		case strings.HasSuffix(s, "m"):
			s = strings.TrimSpace(strings.TrimSuffix(s, "m"))
		}
		f, err := strconv.ParseFloat(s, 64)
		return f * mult, err == nil && f >= 0
	}
	return 0, false
}

// ParseGeoShapeDocValues parses a GeoJSON map, WKT string, GeoPointVal, GeoBoundingBoxVal,
// or GeoShapeDocValues into a normalized, BKD-quantized *GeoShapeDocValues.
func ParseGeoShapeDocValues(raw any) (*GeoShapeDocValues, error) {
	return ParseGeoShapeDocValuesWithOpts(raw, true)
}

// ParseGeoShapeDocValuesWithOpts parses a geo_shape value with configurable BKD quantization.
func ParseGeoShapeDocValuesWithOpts(raw any, quantize bool) (*GeoShapeDocValues, error) {
	if raw == nil {
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "null geo_shape"}
	}
	switch tv := raw.(type) {
	case *GeoShapeDocValues:
		if tv == nil {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "null geo_shape"}
		}
		return tv, nil
	case *GeoPointVal:
		if tv == nil {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "null geo_point"}
		}
		gs := &GeoShapeDocValues{ShapeType: "POINT", Points: [][2]float64{{tv.Lat, tv.Lon}}, DimType: 0, Quantize: quantize, Raw: tv}
		gs.finalizeBounds()
		return gs, nil
	case *GeoBoundingBoxVal:
		if tv == nil || tv.TopLeft == nil || tv.BottomRight == nil {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid GeoBoundingBox"}
		}
		gs := &GeoShapeDocValues{
			ShapeType: "ENVELOPE",
			HasBBox:   true,
			MinLat:    tv.GetMinLat(),
			MaxLat:    tv.GetMaxLat(),
			MinLon:    tv.GetMinLon(),
			MaxLon:    tv.GetMaxLon(),
			DimType:   2,
			Quantize:  quantize,
			Raw:       tv,
		}
		return gs, nil
	case string:
		return parseWKTGeoShapeRound61(tv, quantize)
	case []any:
		if lat, lon, ok := parseGeoCoordPairRound61(tv); ok {
			gs := &GeoShapeDocValues{ShapeType: "POINT", Points: [][2]float64{{lat, lon}}, DimType: 0, Quantize: quantize, Raw: tv}
			gs.finalizeBounds()
			return gs, nil
		}
		shapes := make([]*GeoShapeDocValues, 0, len(tv))
		for _, item := range tv {
			ch, err := ParseGeoShapeDocValuesWithOpts(item, quantize)
			if err != nil {
				return nil, err
			}
			shapes = append(shapes, ch)
		}
		if len(shapes) == 0 {
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "empty geo_shape array"}
		}
		return NewGeoShapeDocValuesCollection(shapes, quantize), nil
	case map[string]any:
		rawType, _ := tv["type"].(string)
		typ := strings.ToUpper(strings.TrimSpace(rawType))
		if typ == "" {
			if gp, ok := parseGeoPointValRound60(tv); ok {
				gs := &GeoShapeDocValues{ShapeType: "POINT", Points: [][2]float64{{gp.Lat, gp.Lon}}, DimType: 0, Quantize: quantize, Raw: tv}
				gs.finalizeBounds()
				return gs, nil
			}
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("missing GeoJSON type in %v", tv)}
		}
		switch typ {
		case "POINT":
			lat, lon, ok := parseGeoCoordPairRound61(tv["coordinates"])
			if !ok {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid GeoJSON Point coordinates"}
			}
			gs := &GeoShapeDocValues{ShapeType: "POINT", Points: [][2]float64{{lat, lon}}, DimType: 0, Quantize: quantize, Raw: tv}
			gs.finalizeBounds()
			return gs, nil
		case "MULTIPOINT":
			pts, ok := parseGeoCoordArray1DRound61(tv["coordinates"])
			if !ok {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid GeoJSON MultiPoint coordinates"}
			}
			gs := &GeoShapeDocValues{ShapeType: "MULTIPOINT", Points: pts, DimType: 0, Quantize: quantize, Raw: tv}
			gs.finalizeBounds()
			return gs, nil
		case "LINESTRING":
			pts, ok := parseGeoCoordArray1DRound61(tv["coordinates"])
			if !ok {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid GeoJSON LineString coordinates"}
			}
			gs := &GeoShapeDocValues{ShapeType: "LINESTRING", Points: pts, DimType: 1, Quantize: quantize, Raw: tv}
			gs.finalizeBounds()
			return gs, nil
		case "MULTILINESTRING":
			lines, ok := parseGeoCoordRingsRound61(tv["coordinates"])
			if !ok {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid GeoJSON MultiLineString coordinates"}
			}
			gs := &GeoShapeDocValues{ShapeType: "MULTILINESTRING", Lines: lines, DimType: 1, Quantize: quantize, Raw: tv}
			gs.finalizeBounds()
			return gs, nil
		case "POLYGON":
			rings, ok := parseGeoCoordRingsRound61(tv["coordinates"])
			if !ok {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid GeoJSON Polygon coordinates"}
			}
			gs := &GeoShapeDocValues{ShapeType: "POLYGON", Rings: rings, DimType: 2, Quantize: quantize, Raw: tv}
			gs.finalizeBounds()
			return gs, nil
		case "MULTIPOLYGON":
			arr, ok := tv["coordinates"].([]any)
			if !ok || len(arr) == 0 {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid GeoJSON MultiPolygon coordinates"}
			}
			multi := make([][][][2]float64, 0, len(arr))
			for _, item := range arr {
				rings, rOk := parseGeoCoordRingsRound61(item)
				if !rOk {
					return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid polygon in GeoJSON MultiPolygon"}
				}
				multi = append(multi, rings)
			}
			gs := &GeoShapeDocValues{ShapeType: "MULTIPOLYGON", MultiRings: multi, DimType: 2, Quantize: quantize, Raw: tv}
			gs.finalizeBounds()
			return gs, nil
		case "ENVELOPE", "BBOX":
			pts, ok := parseGeoCoordArray1DRound61(tv["coordinates"])
			if !ok || len(pts) != 2 {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "GeoJSON Envelope requires 2 corner coordinates"}
			}
			gs := &GeoShapeDocValues{
				ShapeType: typ,
				HasBBox:   true,
				MinLat:    math.Min(pts[0][0], pts[1][0]),
				MaxLat:    math.Max(pts[0][0], pts[1][0]),
				MinLon:    math.Min(pts[0][1], pts[1][1]),
				MaxLon:    math.Max(pts[0][1], pts[1][1]),
				DimType:   2,
				Quantize:  quantize,
				Raw:       tv,
			}
			return gs, nil
		case "CIRCLE":
			lat, lon, ok := parseGeoCoordPairRound61(tv["coordinates"])
			if !ok {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "invalid GeoJSON Circle coordinates"}
			}
			radMeters, rOk := parseRadiusMetersRound61(tv["radius"])
			if !rOk {
				radMeters = 0
			}
			dLat := radMeters / 111319.49079327358
			cosLat := math.Cos(lat * math.Pi / 180.0)
			if math.Abs(cosLat) < 1e-6 {
				cosLat = 1e-6
			}
			dLon := dLat / math.Abs(cosLat)
			gs := &GeoShapeDocValues{
				ShapeType: "CIRCLE",
				HasBBox:   true,
				MinLat:    math.Max(-90, lat-dLat),
				MaxLat:    math.Min(90, lat+dLat),
				MinLon:    math.Max(-180, lon-dLon),
				MaxLon:    math.Min(180, lon+dLon),
				DimType:   2,
				Quantize:  quantize,
				Raw:       tv,
			}
			return gs, nil
		case "GEOMETRYCOLLECTION":
			rawGeoms, ok := tv["geometries"].([]any)
			if !ok {
				return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: "GeoJSON GeometryCollection requires geometries array"}
			}
			children := make([]*GeoShapeDocValues, 0, len(rawGeoms))
			var maxDim int64
			for _, rg := range rawGeoms {
				ch, err := ParseGeoShapeDocValuesWithOpts(rg, quantize)
				if err != nil {
					return nil, err
				}
				children = append(children, ch)
				if d := ch.GetDimensionalType(); d > maxDim {
					maxDim = d
				}
			}
			gs := &GeoShapeDocValues{
				ShapeType:  "GEOMETRYCOLLECTION",
				Geometries: children,
				DimType:    maxDim,
				Quantize:   quantize,
				Raw:        tv,
			}
			gs.finalizeBounds()
			return gs, nil
		default:
			return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("unsupported GeoJSON shape type [%s]", rawType)}
		}
	default:
		return nil, &painlessExceptionError{exType: "IllegalArgumentException", message: fmt.Sprintf("cannot parse %T as geo_shape", raw)}
	}
}

func evalGeoShapeMethodRound61(gs *GeoShapeDocValues, method string) (any, bool, error) {
	if gs == nil {
		return nil, false, nil
	}
	switch method {
	case "size", "length":
		return gs.Size(), true, nil
	case "isEmpty":
		return gs.IsEmpty(), true, nil
	case "get":
		g0, err := gs.Get(0)
		return g0, true, err
	case "getCentroid":
		if gs.IsEmpty() {
			return nil, true, &painlessExceptionError{exType: "IllegalStateException", message: "A document doesn't have a value for a geo_shape field!"}
		}
		return gs.GetCentroid(), true, nil
	case "getBoundingBox":
		if gs.IsEmpty() {
			return nil, true, &painlessExceptionError{exType: "IllegalStateException", message: "A document doesn't have a value for a geo_shape field!"}
		}
		return gs.GetBoundingBox(), true, nil
	case "topLeft", "getTopLeft":
		if gs.IsEmpty() {
			return nil, true, &painlessExceptionError{exType: "IllegalStateException", message: "A document doesn't have a value for a geo_shape field!"}
		}
		return gs.TopLeft(), true, nil
	case "bottomRight", "getBottomRight":
		if gs.IsEmpty() {
			return nil, true, &painlessExceptionError{exType: "IllegalStateException", message: "A document doesn't have a value for a geo_shape field!"}
		}
		return gs.BottomRight(), true, nil
	case "minLat", "getMinLat":
		return gs.GetBoundingBox().GetMinLat(), true, nil
	case "maxLat", "getMaxLat":
		return gs.GetBoundingBox().GetMaxLat(), true, nil
	case "minLon", "getMinLon":
		return gs.GetBoundingBox().GetMinLon(), true, nil
	case "maxLon", "getMaxLon":
		return gs.GetBoundingBox().GetMaxLon(), true, nil
	case "getLabelPosition":
		if gs.IsEmpty() {
			return nil, true, &painlessExceptionError{exType: "IllegalStateException", message: "A document doesn't have a value for a geo_shape field!"}
		}
		return gs.GetLabelPosition(), true, nil
	case "getDimensionalType":
		if gs.IsEmpty() {
			return nil, true, &painlessExceptionError{exType: "IllegalStateException", message: "A document doesn't have a value for a geo_shape field!"}
		}
		return gs.GetDimensionalType(), true, nil
	case "getShapeType":
		return gs.GetShapeType(), true, nil
	case "getMercatorWidth":
		if gs.IsEmpty() {
			return nil, true, &painlessExceptionError{exType: "IllegalStateException", message: "A document doesn't have a value for a geo_shape field!"}
		}
		return gs.GetMercatorWidth(), true, nil
	case "getMercatorHeight":
		if gs.IsEmpty() {
			return nil, true, &painlessExceptionError{exType: "IllegalStateException", message: "A document doesn't have a value for a geo_shape field!"}
		}
		return gs.GetMercatorHeight(), true, nil
	case "toString":
		return gs.String(), true, nil
	}
	return nil, false, nil
}

func evalDocFieldSliceGeoMethodRound61(ds []any, method string) (any, bool, error) {
	switch method {
	case "getCentroid", "getBoundingBox", "getLabelPosition", "getDimensionalType", "getShapeType", "getMercatorWidth", "getMercatorHeight", "topLeft", "getTopLeft", "bottomRight", "getBottomRight":
	default:
		return nil, false, nil
	}
	if len(ds) == 0 {
		return nil, true, &painlessExceptionError{
			exType:  "IllegalStateException",
			message: "A document doesn't have a value for a geo_point field!",
		}
	}
	var shapes []*GeoShapeDocValues
	for _, item := range ds {
		if gs, isGS := item.(*GeoShapeDocValues); isGS && gs != nil {
			shapes = append(shapes, gs)
		}
	}
	if len(shapes) > 0 {
		combined := NewGeoShapeDocValuesCollection(shapes, shapes[0].Quantize)
		return evalGeoShapeMethodRound61(combined, method)
	}
	pts := make([]*GeoPointVal, 0, len(ds))
	for _, item := range ds {
		if gp, ok := parseGeoPointValRound60(item); ok {
			pts = append(pts, gp)
		}
	}
	if len(pts) == 0 {
		return nil, true, &painlessExceptionError{
			exType:  "IllegalStateException",
			message: "A document doesn't have a valid geo_point value!",
		}
	}
	tl, br, centroid, mW, mH := computeGeoSliceBoundsRound61(pts)
	switch method {
	case "getCentroid":
		return centroid, true, nil
	case "getLabelPosition":
		return centroid, true, nil
	case "getBoundingBox":
		return &GeoBoundingBoxVal{TopLeft: tl, BottomRight: br}, true, nil
	case "topLeft", "getTopLeft":
		return tl, true, nil
	case "bottomRight", "getBottomRight":
		return br, true, nil
	case "getDimensionalType":
		return int64(0), true, nil
	case "getShapeType":
		return "POINT", true, nil
	case "getMercatorWidth":
		return mW, true, nil
	case "getMercatorHeight":
		return mH, true, nil
	}
	return nil, false, nil
}

// ComputePainlessMurmur3Hash computes Elasticsearch's 64-bit Murmur3 hash
// (lower 64 bits h1 of MurmurHash3_x64_128 with seed=0) as a signed int64,
// matching Elasticsearch's `mapper-murmur3` `Murmur3FieldMapper`.
func ComputePainlessMurmur3Hash(s string) int64 {
	const (
		c1 uint64 = 0x87c37b91114253d5
		c2 uint64 = 0x4cf5ad432745937f
	)
	data := []byte(s)
	nblocks := len(data) / 16
	var h1, h2 uint64

	for i := 0; i < nblocks; i++ {
		off := i * 16
		k1 := binary.LittleEndian.Uint64(data[off : off+8])
		k2 := binary.LittleEndian.Uint64(data[off+8 : off+16])

		k1 *= c1
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2
		h1 ^= k1

		h1 = bits.RotateLeft64(h1, 27)
		h1 += h2
		h1 = h1*5 + 0x52dce729

		k2 *= c2
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1
		h2 ^= k2

		h2 = bits.RotateLeft64(h2, 31)
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	}

	tail := data[nblocks*16:]
	var k1, k2 uint64
	switch len(tail) {
	case 15:
		k2 ^= uint64(tail[14]) << 48
		fallthrough
	case 14:
		k2 ^= uint64(tail[13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(tail[12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(tail[11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(tail[10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(tail[9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(tail[8])
		k2 *= c2
		k2 = bits.RotateLeft64(k2, 33)
		k2 *= c1
		h2 ^= k2
		fallthrough
	case 8:
		k1 ^= uint64(tail[7]) << 56
		fallthrough
	case 7:
		k1 ^= uint64(tail[6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(tail[5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(tail[4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(tail[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(tail[0])
		k1 *= c1
		k1 = bits.RotateLeft64(k1, 31)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint64(len(data))
	h2 ^= uint64(len(data))
	h1 += h2
	h2 += h1

	fmix64 := func(k uint64) uint64 {
		k ^= k >> 33
		k *= 0xff51afd7ed558ccd
		k ^= k >> 33
		k *= 0xc4ceb9fe1a85ec53
		k ^= k >> 33
		return k
	}
	h1 = fmix64(h1)
	h2 = fmix64(h2)
	h1 += h2
	return int64(h1) // #nosec G115 -- intentional signed 64-bit murmur3 doc value representation
}

func normalizeMurmur3DocValuesRound61(raw any, forceHash bool) []any {
	items := flattenRawFieldItemsRound60(raw, false)
	if len(items) == 0 {
		return []any{}
	}
	hashes := make([]int64, 0, len(items))
	for _, it := range items {
		if it == nil {
			continue
		}
		if _, isMap := it.(map[string]any); isMap {
			continue
		}
		if !forceHash {
			switch tv := it.(type) {
			case int64:
				hashes = append(hashes, tv)
				continue
			case int:
				hashes = append(hashes, int64(tv))
				continue
			case int32:
				hashes = append(hashes, int64(tv))
				continue
			case uint64:
				hashes = append(hashes, int64(tv)) // #nosec G115 -- signed hash value
				continue
			case json.Number:
				if iv, err := tv.Int64(); err == nil {
					hashes = append(hashes, iv)
					continue
				}
			}
		}
		hashes = append(hashes, ComputePainlessMurmur3Hash(fmt.Sprintf("%v", it)))
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i] < hashes[j] })
	out := make([]any, 0, len(hashes))
	for i, h := range hashes {
		if i > 0 && hashes[i-1] == h {
			continue
		}
		out = append(out, h)
	}
	return out
}

// IPAddressVal models Elasticsearch's IPAddress wrapper in Painless (`new IPAddress(...)` and `field('ip')`).
type IPAddressVal struct {
	Addr    netip.Addr
	SortKey [16]byte
}

// ParseIPAddressVal parses an IPv4 or IPv6 address into a canonical *IPAddressVal
// with Lucene's 16-byte IPv4-mapped IPv6 unsigned sort key.
func ParseIPAddressVal(raw string) (*IPAddressVal, error) {
	s := strings.TrimSpace(raw)
	addr, err := netip.ParseAddr(s)
	if err != nil {
		// Fallback via net.ParseIP for IPv4-mapped forms
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("'%s' is not an IP string literal.", raw),
			}
		}
		var ok bool
		if v4 := ip.To4(); v4 != nil {
			addr, ok = netip.AddrFromSlice(v4)
		} else {
			addr, ok = netip.AddrFromSlice(ip.To16())
		}
		if !ok {
			return nil, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("'%s' is not an IP string literal.", raw),
			}
		}
	}
	addr = addr.Unmap()
	var key [16]byte
	if addr.Is4() {
		v4 := addr.As4()
		key[10] = 0xff
		key[11] = 0xff
		copy(key[12:], v4[:])
	} else {
		key = addr.As16()
	}
	return &IPAddressVal{
		Addr:    addr,
		SortKey: key,
	}, nil
}

func (ip *IPAddressVal) String() string {
	if ip == nil {
		return "null"
	}
	return ip.Addr.String()
}

func (ip *IPAddressVal) MarshalJSON() ([]byte, error) {
	if ip == nil {
		return []byte("null"), nil
	}
	return json.Marshal(ip.Addr.String())
}

func (ip *IPAddressVal) CompareTo(other *IPAddressVal) int {
	if ip == nil && other == nil {
		return 0
	}
	if ip == nil {
		return -1
	}
	if other == nil {
		return 1
	}
	return bytes.Compare(ip.SortKey[:], other.SortKey[:])
}

func (ip *IPAddressVal) Equals(other any) bool {
	if ip == nil {
		return other == nil
	}
	switch tv := other.(type) {
	case *IPAddressVal:
		return tv != nil && ip.SortKey == tv.SortKey
	}
	return false
}

func evalIPAddressMethodRound61(ip *IPAddressVal, method string, cArgs []string, sourceMap, params map[string]any, depth int) (any, bool, error) {
	if ip == nil {
		return nil, false, nil
	}
	switch method {
	case "toString", "getHostAddress", "toCanonicalString":
		return ip.String(), true, nil
	case "isIPv4":
		return ip.Addr.Is4(), true, nil
	case "isIPv6":
		return ip.Addr.Is6(), true, nil
	case "isLoopbackAddress":
		return ip.Addr.IsLoopback(), true, nil
	case "isMulticastAddress":
		return ip.Addr.IsMulticast(), true, nil
	case "isSiteLocalAddress", "isPrivate":
		return ip.Addr.IsPrivate(), true, nil
	case "isLinkLocalAddress":
		return ip.Addr.IsLinkLocalUnicast() || ip.Addr.IsLinkLocalMulticast(), true, nil
	case "getAddress":
		var raw []byte
		if ip.Addr.Is4() {
			v4 := ip.Addr.As4()
			raw = v4[:]
		} else {
			v6 := ip.Addr.As16()
			raw = v6[:]
		}
		out := make([]any, len(raw))
		for i, b := range raw {
			out[i] = int64(int8(b)) // #nosec G115 -- Java InetAddress.getAddress() returns signed two's-complement byte[]
		}
		return out, true, nil
	case "equals":
		if len(cArgs) != 1 {
			return false, true, nil
		}
		argVal, err := evalRHSExprDepth(sourceMap, cArgs[0], params, depth+1)
		if err != nil {
			return nil, true, err
		}
		return ip.Equals(argVal), true, nil
	case "compareTo":
		if len(cArgs) != 1 {
			return int64(0), true, nil
		}
		argVal, err := evalRHSExprDepth(sourceMap, cArgs[0], params, depth+1)
		if err != nil {
			return nil, true, err
		}
		if argVal == nil {
			return nil, true, &painlessExceptionError{exType: "NullPointerException", message: "Cannot compare IPAddress to null"}
		}
		other, ok := argVal.(*IPAddressVal)
		if !ok {
			if s, isS := argVal.(string); isS {
				parsed, pErr := ParseIPAddressVal(s)
				if pErr != nil {
					return nil, true, pErr
				}
				other = parsed
			} else {
				return nil, true, &painlessExceptionError{exType: "ClassCastException", message: fmt.Sprintf("Cannot cast %T to IPAddress", argVal)}
			}
		}
		return int64(ip.CompareTo(other)), true, nil
	case "hashCode":
		var h int32
		for _, b := range ip.SortKey {
			h = 31*h + int32(b)
		}
		return int64(h), true, nil
	}
	return nil, false, nil
}

// Custom ES/Java date mapping format parser (supports `||` alternatives, `epoch_millis`,
// `epoch_second`, `yyyy/MM/dd`, `dd-MM-yyyy`, `yyyy-MM-dd HH:mm:ss`, etc.).
func convertJavaSimpleDatePatternRound61(pat string) string {
	var b strings.Builder
	inLit := false
	for i := 0; i < len(pat); {
		if pat[i] == '\'' {
			if i+1 < len(pat) && pat[i+1] == '\'' {
				b.WriteByte('\'')
				i += 2
				continue
			}
			inLit = !inLit
			i++
			continue
		}
		if inLit {
			b.WriteByte(pat[i])
			i++
			continue
		}
		ch := pat[i]
		j := i + 1
		for j < len(pat) && pat[j] == ch {
			j++
		}
		n := j - i
		switch ch {
		case 'y', 'u', 'Y':
			if n == 2 {
				b.WriteString("06")
			} else {
				b.WriteString("2006")
			}
		case 'M', 'L':
			switch n {
			case 1:
				b.WriteString("1")
			case 2:
				b.WriteString("01")
			case 3:
				b.WriteString("Jan")
			default:
				b.WriteString("January")
			}
		case 'd':
			if n == 1 {
				b.WriteString("2")
			} else {
				b.WriteString("02")
			}
		case 'H':
			b.WriteString("15")
		case 'h':
			if n == 1 {
				b.WriteString("3")
			} else {
				b.WriteString("03")
			}
		case 'm':
			b.WriteString("04")
		case 's':
			b.WriteString("05")
		case 'S':
			b.WriteString(strings.Repeat("0", n))
		case 'a':
			b.WriteString("PM")
		case 'Z':
			if n >= 4 {
				b.WriteString("-07:00")
			} else {
				b.WriteString("-0700")
			}
		case 'X', 'x':
			switch n {
			case 1:
				b.WriteString("Z07")
			case 2:
				b.WriteString("Z0700")
			default:
				b.WriteString("Z07:00")
			}
		default:
			b.WriteString(pat[i:j])
		}
		i = j
	}
	return b.String()
}

func parseDocDateWithMappingFormatRound61(v any, fmtSpec string, isNanos bool) (*ZonedDateTimeVal, bool) {
	if d, ok := v.(*ZonedDateTimeVal); ok {
		return d, true
	}
	if fmtSpec != "" {
		parts := strings.Split(fmtSpec, "||")
		s, isStr := v.(string)
		if isStr {
			s = strings.TrimSpace(s)
		}
		for _, rawFmt := range parts {
			f := strings.TrimSpace(rawFmt)
			switch f {
			case "", "strict_date_optional_time", "date_optional_time", "strict_date_optional_time_nanos":
				if d, ok := parseZonedDateTimeValRound60(v, isNanos); ok {
					return d, true
				}
			case "epoch_millis":
				if isStr {
					if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
						return &ZonedDateTimeVal{Time: time.UnixMilli(ms).UTC(), IsNano: isNanos}, true
					}
				} else if ms, ok := toInt64Painless(v); ok {
					return &ZonedDateTimeVal{Time: time.UnixMilli(ms).UTC(), IsNano: isNanos}, true
				}
			case "epoch_second":
				if isStr {
					if sec, err := strconv.ParseFloat(s, 64); err == nil {
						ns := int64(sec * 1e9)
						return &ZonedDateTimeVal{Time: time.Unix(0, ns).UTC(), IsNano: isNanos}, true
					}
				} else if sec, ok := toFloat64(v); ok {
					ns := int64(sec * 1e9)
					return &ZonedDateTimeVal{Time: time.Unix(0, ns).UTC(), IsNano: isNanos}, true
				}
			case "basic_date":
				if isStr {
					if tm, err := time.Parse("20060102", s); err == nil {
						return &ZonedDateTimeVal{Time: tm.UTC(), IsNano: isNanos}, true
					}
				}
			case "basic_date_time":
				if isStr {
					for _, l := range []string{"20060102T150405.000Z0700", "20060102T150405.000Z"} {
						if tm, err := time.Parse(l, s); err == nil {
							return &ZonedDateTimeVal{Time: tm.UTC(), IsNano: isNanos}, true
						}
					}
				}
			default:
				if isStr {
					layout := convertJavaSimpleDatePatternRound61(f)
					for _, cand := range []string{
						layout,
						strings.ReplaceAll(layout, "000", "999999999"),
						strings.ReplaceAll(layout, "-0700", "Z07:00"),
						strings.ReplaceAll(layout, "Z07:00", "-0700"),
					} {
						if tm, err := time.Parse(cand, s); err == nil {
							return &ZonedDateTimeVal{Time: tm.UTC(), IsNano: isNanos}, true
						}
					}
				}
			}
		}
	}
	return parseZonedDateTimeValRound60(v, isNanos)
}

var deprecatedJodaMethodsRound61 = map[string]string{
	"getCenturyOfEra":   "[getCenturyOfEra] is no longer available; use [get(ChronoField.YEAR_OF_ERA) / 100] instead",
	"getEra":            "[getEra] is no longer available; use [get(ChronoField.ERA)] instead",
	"getHourOfDay":      "[getHourOfDay] is no longer available; use [getHour()] instead",
	"getMillisOfDay":    "[getMillisOfDay] is no longer available; use [get(ChronoField.MILLI_OF_DAY)] instead",
	"getMillisOfSecond": "[getMillisOfSecond] is no longer available; use [get(ChronoField.MILLI_OF_SECOND)] instead",
	"getMinuteOfDay":    "[getMinuteOfDay] is no longer available; use [get(ChronoField.MINUTE_OF_DAY)] instead",
	"getMinuteOfHour":   "[getMinuteOfHour] is no longer available; use [getMinute()] instead",
	"getMonthOfYear":    "[getMonthOfYear] is no longer available; use [getMonthValue()] instead",
	"getSecondOfDay":    "[getSecondOfDay] is no longer available; use [get(ChronoField.SECOND_OF_DAY)] instead",
	"getSecondOfMinute": "[getSecondOfMinute] is no longer available; use [getSecond()] instead",
	"getWeekOfWeekyear": "[getWeekOfWeekyear] is no longer available; use [get(IsoFields.WEEK_OF_WEEK_BASED_YEAR)] instead",
	"getWeekyear":       "[getWeekyear] is no longer available; use [get(IsoFields.WEEK_BASED_YEAR)] instead",
	"getYearOfCentury":  "[getYearOfCentury] is no longer available; use [get(ChronoField.YEAR_OF_ERA) % 100] instead",
	"getYearOfEra":      "[getYearOfEra] is no longer available; use [get(ChronoField.YEAR_OF_ERA)] instead",
}

func checkDeprecatedJodaMethodRound61(method string) error {
	if msg, ok := deprecatedJodaMethodsRound61[method]; ok {
		return &painlessExceptionError{
			exType:  "UnsupportedOperationException",
			message: msg,
		}
	}
	return nil
}

func evalChronoOrIsoFieldOnTimeRound61(tm time.Time, fieldExpr string) (int64, bool) {
	u := strings.ToUpper(strings.TrimSpace(fieldExpr))
	switch {
	case strings.Contains(u, "WEEK_OF_WEEK_BASED_YEAR"):
		_, isoWeek := tm.ISOWeek()
		return int64(isoWeek), true
	case strings.Contains(u, "WEEK_BASED_YEAR"):
		isoYear, _ := tm.ISOWeek()
		return int64(isoYear), true
	case strings.Contains(u, "QUARTER_OF_YEAR"):
		return int64((int(tm.Month())-1)/3 + 1), true
	case strings.Contains(u, "DAY_OF_QUARTER"):
		qStartMonth := time.Month(((int(tm.Month())-1)/3)*3 + 1)
		qStart := time.Date(tm.Year(), qStartMonth, 1, 0, 0, 0, 0, tm.Location())
		return int64(tm.YearDay()-qStart.YearDay()) + 1, true
	case strings.Contains(u, "YEAR_OF_ERA"):
		y := tm.Year()
		if y >= 1 {
			return int64(y), true
		}
		return int64(1 - y), true
	case strings.Contains(u, "ERA"):
		if tm.Year() >= 1 {
			return 1, true
		}
		return 0, true
	case strings.Contains(u, "MILLI_OF_DAY"):
		return int64((tm.Hour()*3600+tm.Minute()*60+tm.Second())*1000 + tm.Nanosecond()/1_000_000), true
	case strings.Contains(u, "MILLI_OF_SECOND"):
		return int64(tm.Nanosecond() / 1_000_000), true
	case strings.Contains(u, "MICRO_OF_SECOND"):
		return int64(tm.Nanosecond() / 1_000), true
	case strings.Contains(u, "MICRO_OF_DAY"):
		return int64(tm.Hour()*3600+tm.Minute()*60+tm.Second())*1_000_000 + int64(tm.Nanosecond()/1_000), true
	case strings.Contains(u, "NANO_OF_SECOND"):
		return int64(tm.Nanosecond()), true
	case strings.Contains(u, "NANO_OF_DAY"):
		return int64(tm.Hour()*3600+tm.Minute()*60+tm.Second())*1_000_000_000 + int64(tm.Nanosecond()), true
	case strings.Contains(u, "MINUTE_OF_DAY"):
		return int64(tm.Hour()*60 + tm.Minute()), true
	case strings.Contains(u, "MINUTE_OF_HOUR"):
		return int64(tm.Minute()), true
	case strings.Contains(u, "SECOND_OF_DAY"):
		return int64(tm.Hour()*3600 + tm.Minute()*60 + tm.Second()), true
	case strings.Contains(u, "SECOND_OF_MINUTE"):
		return int64(tm.Second()), true
	case strings.Contains(u, "HOUR_OF_DAY"):
		return int64(tm.Hour()), true
	case strings.Contains(u, "HOUR_OF_AMPM"):
		return int64(tm.Hour() % 12), true
	case strings.Contains(u, "AMPM_OF_DAY"):
		if tm.Hour() >= 12 {
			return 1, true
		}
		return 0, true
	case strings.Contains(u, "DAY_OF_WEEK"):
		dow := int(tm.Weekday())
		if dow == 0 {
			dow = 7
		}
		return int64(dow), true
	case strings.Contains(u, "DAY_OF_MONTH"):
		return int64(tm.Day()), true
	case strings.Contains(u, "DAY_OF_YEAR"):
		return int64(tm.YearDay()), true
	case strings.Contains(u, "MONTH_OF_YEAR"):
		return int64(tm.Month()), true
	case strings.Contains(u, "PROLEPTIC_MONTH"):
		return int64(tm.Year())*12 + int64(tm.Month()) - 1, true
	case strings.Contains(u, "EPOCH_DAY"):
		return tm.UTC().Truncate(24*time.Hour).Unix() / 86400, true
	case strings.Contains(u, "INSTANT_SECONDS"):
		return tm.Unix(), true
	case strings.Contains(u, "OFFSET_SECONDS"):
		_, off := tm.Zone()
		return int64(off), true
	case strings.Contains(u, "YEAR"):
		return int64(tm.Year()), true
	}
	return 0, false
}

// ============================================================================
// Round 61 F25: float32 Vector Accumulation, Hex Byte / Bit Vectors &
// Non-Iterable DenseVectorFieldVal
// ============================================================================

// DecodeHexSignedByteVector decodes an even-length hex string (e.g. "02fe09")
// into signed int8 values ([2, -2, 9]) and float32 equivalents.
func DecodeHexSignedByteVector(hexStr string) ([]int8, []float32, error) {
	if len(hexStr) == 0 || len(hexStr)%2 != 0 {
		return nil, nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("hex-encoded byte vector must have non-zero even length, got %d", len(hexStr)),
		}
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("invalid hex-encoded byte vector: %v", err),
		}
	}
	i8 := make([]int8, len(raw))
	f32 := make([]float32, len(raw))
	for i, b := range raw {
		sb := int8(b) // #nosec G115 -- intentional two's-complement signed-byte vector decoding
		i8[i] = sb
		f32[i] = float32(sb)
	}
	return i8, f32, nil
}

func parseVectorValueRound61(val any, elemType string) ([]float32, []int8, error) {
	if val == nil {
		return nil, nil, nil
	}
	if dvv, ok := val.(*DenseVectorVal); ok && dvv != nil {
		return dvv.Floats, dvv.Bytes, nil
	}
	if s, ok := val.(string); ok {
		i8, f32, err := DecodeHexSignedByteVector(s)
		if err != nil {
			return nil, nil, err
		}
		return f32, i8, nil
	}
	var elems []any
	switch tv := val.(type) {
	case []any:
		elems = tv
	case []float32:
		f32 := make([]float32, len(tv))
		copy(f32, tv)
		var i8 []int8
		if elemType == "byte" || elemType == "bit" {
			i8 = make([]int8, len(tv))
			for i, v := range tv {
				i8[i] = int8(v)
			}
		}
		return f32, i8, nil
	case []float64:
		f32 := make([]float32, len(tv))
		var i8 []int8
		if elemType == "byte" || elemType == "bit" {
			i8 = make([]int8, len(tv))
		}
		for i, v := range tv {
			f32[i] = float32(v)
			if i8 != nil {
				i8[i] = int8(v)
			}
		}
		return f32, i8, nil
	default:
		return nil, nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("invalid vector value of type %T", val),
		}
	}
	f32 := make([]float32, len(elems))
	needBytes := elemType == "byte" || elemType == "bit"
	var i8 []int8
	if needBytes {
		i8 = make([]int8, len(elems))
	}
	for i, elem := range elems {
		f, ok := toFloat64WithRawPainless(elem)
		if !ok {
			return nil, nil, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("non-numeric vector element at index %d", i),
			}
		}
		if needBytes {
			iv := int64(f)
			if float64(iv) != f || iv < -128 || iv > 127 {
				return nil, nil, &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("byte vector element out of range [-128, 127] at index %d: %v", i, elem),
				}
			}
			i8[i] = int8(iv)
			f32[i] = float32(int8(iv))
		} else {
			f32[i] = float32(f)
		}
	}
	return f32, i8, nil
}

func resolveVectorElementTypeFromMapsRound61(sourceMap, params map[string]any, fieldName string) string {
	for _, m := range []map[string]any{params, sourceMap} {
		if m != nil {
			if etMap, ok := m["__vector_element_types"].(map[string]string); ok && etMap != nil {
				if et := etMap[fieldName]; et != "" {
					return et
				}
			}
		}
	}
	return "float"
}

func extractDocVectorRound61(sourceMap, params map[string]any, fieldName string) ([]float32, []int8, string, bool, error) {
	if err := checkStrictDocFieldMappingRound60(sourceMap, params, fieldName); err != nil {
		return nil, nil, "", false, err
	}
	if err := checkDocValuesAccessGuardRound61(params, fieldName); err != nil {
		return nil, nil, "", false, err
	}
	if err := checkDocValuesAccessGuardRound61(sourceMap, fieldName); err != nil {
		return nil, nil, "", false, err
	}
	elemType := resolveVectorElementTypeFromMapsRound61(sourceMap, params, fieldName)
	raw := resolveParamPath(sourceMap, strings.Split(fieldName, "."))
	if raw == nil && sourceMap != nil {
		raw = sourceMap[fieldName]
	}
	if raw == nil {
		if rawSrc, ok := rawSourceFromSourceMapPainless(sourceMap); ok && rawSrc != nil {
			raw = resolveParamPath(rawSrc, strings.Split(fieldName, "."))
		}
	}
	if raw == nil {
		return nil, nil, elemType, false, nil
	}
	// Auto-detect hex string vector even without explicit __vector_element_types
	if _, isStr := raw.(string); isStr && elemType == "float" {
		elemType = "byte"
	}
	f32, i8, err := parseVectorValueRound61(raw, elemType)
	if err != nil {
		return nil, nil, elemType, false, err
	}
	if len(f32) == 0 {
		return nil, nil, elemType, false, nil
	}
	return f32, i8, elemType, true, nil
}

func computeVectorMagnitudeF32Round61(f32 []float32, i8 []int8, elemType string) float32 {
	if elemType == "bit" && len(i8) > 0 {
		var setBits int
		for _, b := range i8 {
			setBits += bits.OnesCount8(uint8(b)) // #nosec G115 -- raw 8-bit popcount over two's-complement int8
		}
		return float32(math.Sqrt(float64(setBits)))
	}
	var sumSq float32
	for _, v := range f32 {
		sq := math.Float32frombits(math.Float32bits(v * v))
		sumSq = math.Float32frombits(math.Float32bits(sumSq + sq))
	}
	return float32(math.Sqrt(float64(sumSq)))
}

func computeVectorPairMetricRound61(fnName string, qF32 []float32, qI8 []int8, dF32 []float32, dI8 []int8, elemType, fieldLabel string) (float64, error) {
	if len(qF32) != len(dF32) {
		return 0, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Vectors must have same dimension: query=%d, doc[%s]=%d", len(qF32), fieldLabel, len(dF32)),
		}
	}
	if elemType == "bit" {
		switch fnName {
		case "dotProduct", "cosineSimilarity":
			return 0, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("[%s] is not supported for [bit] vectors", fnName),
			}
		case "hamming", "l1norm", "l1Norm":
			var dist int
			for i := range qI8 {
				dist += bits.OnesCount8(uint8(qI8[i]) ^ uint8(dI8[i])) // #nosec G115 -- raw 8-bit XOR popcount for Hamming distance
			}
			return float64(dist), nil
		case "l2norm", "l2Norm":
			var dist int
			for i := range qI8 {
				dist += bits.OnesCount8(uint8(qI8[i]) ^ uint8(dI8[i])) // #nosec G115 -- raw 8-bit XOR popcount for bit-vector L2 norm
			}
			return float64(float32(math.Sqrt(float64(dist)))), nil
		}
	}

	switch fnName {
	case "hamming":
		if elemType != "byte" || len(qI8) == 0 || len(dI8) == 0 {
			return 0, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: "hamming distance is only supported for [byte] and [bit] vectors",
			}
		}
		var dist int
		for i := range qI8 {
			dist += bits.OnesCount8(uint8(qI8[i]) ^ uint8(dI8[i])) // #nosec G115 -- raw 8-bit XOR popcount for byte-vector Hamming distance
		}
		return float64(dist), nil

	case "dotProduct":
		var sum float32
		for i := range qF32 {
			prod := math.Float32frombits(math.Float32bits(qF32[i] * dF32[i]))
			sum = math.Float32frombits(math.Float32bits(sum + prod))
		}
		return float64(sum), nil

	case "l1norm", "l1Norm":
		var sum float32
		for i := range qF32 {
			diff := math.Float32frombits(math.Float32bits(qF32[i] - dF32[i]))
			if diff < 0 {
				diff = -diff
			}
			sum = math.Float32frombits(math.Float32bits(sum + diff))
		}
		return float64(sum), nil

	case "l2norm", "l2Norm":
		var sumSq float32
		for i := range qF32 {
			diff := math.Float32frombits(math.Float32bits(qF32[i] - dF32[i]))
			sq := math.Float32frombits(math.Float32bits(diff * diff))
			sumSq = math.Float32frombits(math.Float32bits(sumSq + sq))
		}
		return float64(float32(math.Sqrt(float64(sumSq)))), nil

	case "cosineSimilarity":
		var dot, normQ, normD float32
		for i := range qF32 {
			q := qF32[i]
			d := dF32[i]
			pqd := math.Float32frombits(math.Float32bits(q * d))
			pqq := math.Float32frombits(math.Float32bits(q * q))
			pdd := math.Float32frombits(math.Float32bits(d * d))
			dot = math.Float32frombits(math.Float32bits(dot + pqd))
			normQ = math.Float32frombits(math.Float32bits(normQ + pqq))
			normD = math.Float32frombits(math.Float32bits(normD + pdd))
		}
		if normQ == 0 || normD == 0 {
			return 0, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: "cosineSimilarity cannot be calculated with zero-magnitude vector",
			}
		}
		denom := float32(math.Sqrt(float64(normQ))) * float32(math.Sqrt(float64(normD)))
		return float64(dot / denom), nil
	}
	return 0, &painlessExceptionError{
		exType:  "IllegalArgumentException",
		message: fmt.Sprintf("Unknown vector function [%s]", fnName),
	}
}

func evalVectorSimilarityRound61(fnName string, queryVecVal any, fieldName string, sourceMap, params map[string]any) (float64, error) {
	dF32, dI8, elemType, present, err := extractDocVectorRound61(sourceMap, params, fieldName)
	if err != nil {
		return 0, err
	}
	if !present {
		return 0, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("A document doesn't have a value for a vector field [%s]!", fieldName),
		}
	}
	qElemType := elemType
	if _, isStr := queryVecVal.(string); isStr && qElemType == "float" {
		qElemType = "byte"
	}
	qF32, qI8, qErr := parseVectorValueRound61(queryVecVal, qElemType)
	if qErr != nil {
		return 0, qErr
	}
	return computeVectorPairMetricRound61(fnName, qF32, qI8, dF32, dI8, elemType, fieldName)
}

func docVectorValueAndMagnitudeRound61(sourceMap, params map[string]any, fieldPath string) ([]any, float32, bool, error) {
	dF32, dI8, elemType, present, err := extractDocVectorRound61(sourceMap, params, fieldPath)
	if err != nil {
		return nil, 0, false, err
	}
	if !present {
		return []any{}, 0, false, nil
	}
	out := make([]any, len(dF32))
	for i, v := range dF32 {
		out[i] = v
	}
	mag := computeVectorMagnitudeF32Round61(dF32, dI8, elemType)
	return out, mag, true, nil
}

// DenseVectorVal represents the value returned by field('vec').get(...) / $('vec', default).
type DenseVectorVal struct {
	Name       string
	ElemType   string
	Floats     []float32
	Bytes      []int8
	Present    bool
	IsDocValue bool
}

func (v *DenseVectorVal) MarshalJSON() ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}
	if v.ElemType == "byte" || v.ElemType == "bit" {
		ints := make([]int, len(v.Bytes))
		for i, b := range v.Bytes {
			ints[i] = int(b)
		}
		return json.Marshal(ints)
	}
	return json.Marshal(v.Floats)
}

func (v *DenseVectorVal) String() string {
	if v == nil {
		return "null"
	}
	b, _ := v.MarshalJSON()
	return string(b)
}

// DenseVectorFieldVal models Elasticsearch 8's non-iterable DenseVectorField
// returned by `field('vec')` / `$('vec')`. Iterating over it in `for (x : field('vec'))`
// throws UnsupportedOperationException!
type DenseVectorFieldVal struct {
	Name     string
	ElemType string
	Present  bool
	Vec      *DenseVectorVal
}

func (f *DenseVectorFieldVal) IsEmpty() bool {
	return f == nil || !f.Present || f.Vec == nil || len(f.Vec.Floats) == 0
}

func (f *DenseVectorFieldVal) GetValue() (*DenseVectorVal, error) {
	if f == nil || !f.Present || f.Vec == nil || len(f.Vec.Floats) == 0 {
		name := ""
		if f != nil {
			name = f.Name
		}
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("A document doesn't have a value for a vector field [%s]!", name),
		}
	}
	return f.Vec, nil
}

func (f *DenseVectorFieldVal) GetWithDefault(def any) (any, error) {
	if f == nil || !f.Present || f.Vec == nil || len(f.Vec.Floats) == 0 {
		return def, nil
	}
	return f.Vec, nil
}

func (f *DenseVectorFieldVal) String() string {
	if f == nil || !f.Present || f.Vec == nil {
		return "[]"
	}
	return f.Vec.String()
}

func resolveDenseVectorFieldValRound61(name string, sourceMap, params map[string]any) (*DenseVectorFieldVal, bool, error) {
	isDenseVec := false
	for _, m := range []map[string]any{params, sourceMap} {
		if m == nil {
			continue
		}
		if ftMap, ok := m["__field_types"].(map[string]string); ok && ftMap != nil && ftMap[name] == "dense_vector" {
			isDenseVec = true
		}
		if etMap, ok := m["__vector_element_types"].(map[string]string); ok && etMap != nil && etMap[name] != "" {
			isDenseVec = true
		}
	}
	if !isDenseVec {
		return nil, false, nil
	}
	if err := checkStrictDocFieldMappingRound60(sourceMap, params, name); err != nil {
		return nil, true, err
	}
	if err := checkFieldsAPIAccessGuardRound61(params, name); err != nil {
		return nil, true, err
	}
	if err := checkFieldsAPIAccessGuardRound61(sourceMap, name); err != nil {
		return nil, true, err
	}
	elemType := resolveVectorElementTypeFromMapsRound61(sourceMap, params, name)
	var raw any
	if rawSrc, ok := rawSourceFromSourceMapPainless(sourceMap); ok && rawSrc != nil {
		raw = resolveParamPath(rawSrc, strings.Split(name, "."))
	}
	if raw == nil {
		raw = resolveParamPath(sourceMap, strings.Split(name, "."))
	}
	if raw == nil && sourceMap != nil {
		raw = sourceMap[name]
	}
	if raw == nil {
		return &DenseVectorFieldVal{Name: name, ElemType: elemType, Present: false}, true, nil
	}
	if _, isStr := raw.(string); isStr && elemType == "float" {
		elemType = "byte"
	}
	f32, i8, err := parseVectorValueRound61(raw, elemType)
	if err != nil {
		return nil, true, err
	}
	if len(f32) == 0 {
		return &DenseVectorFieldVal{Name: name, ElemType: elemType, Present: false}, true, nil
	}
	return &DenseVectorFieldVal{
		Name:     name,
		ElemType: elemType,
		Present:  true,
		Vec: &DenseVectorVal{
			Name:     name,
			ElemType: elemType,
			Floats:   f32,
			Bytes:    i8,
			Present:  true,
		},
	}, true, nil
}

func evalDenseVectorMethodRound61(rec any, method string, cArgs []string, sourceMap, params map[string]any, depth int) (any, bool, error) {
	var vec *DenseVectorVal
	var fieldName string
	var elemType string
	isFieldWrapper := false
	switch tv := rec.(type) {
	case *DenseVectorFieldVal:
		if tv == nil {
			return nil, false, nil
		}
		isFieldWrapper = true
		fieldName = tv.Name
		elemType = tv.ElemType
		if tv.Present {
			vec = tv.Vec
		}
	case *DenseVectorVal:
		if tv == nil {
			return nil, false, nil
		}
		vec = tv
		fieldName = tv.Name
		elemType = tv.ElemType
	default:
		return nil, false, nil
	}

	requireVec := func() (*DenseVectorVal, error) {
		if !isFieldWrapper && vec != nil && vec.IsDocValue && vec.isMissingVectorRound62() {
			return nil, newMissingDenseVectorDocValueErrorRound62()
		}
		if vec == nil || len(vec.Floats) == 0 {
			return nil, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("A document doesn't have a value for a vector field [%s]!", fieldName),
			}
		}
		return vec, nil
	}

	switch method {
	case "isEmpty":
		if isFieldWrapper {
			return vec == nil || len(vec.Floats) == 0, true, nil
		}
		return vec == nil || vec.isMissingVectorRound62(), true, nil
	case "size":
		if !isFieldWrapper && vec != nil && vec.IsDocValue {
			if vec.isMissingVectorRound62() {
				return int64(0), true, nil
			}
			return int64(1), true, nil
		}
		if vec == nil {
			return int64(0), true, nil
		}
		return int64(len(vec.Floats)), true, nil
	case "getDims", "dims":
		if !isFieldWrapper && vec != nil && vec.IsDocValue {
			v, err := requireVec()
			if err != nil {
				return nil, true, err
			}
			return int64(len(v.Floats)), true, nil
		}
		if vec == nil {
			return int64(0), true, nil
		}
		return int64(len(vec.Floats)), true, nil
	case "iterator":
		if isFieldWrapper {
			return nil, true, &painlessExceptionError{
				exType:  "UnsupportedOperationException",
				message: DenseVectorIterateErrorMessage,
			}
		}
	case "getVector", "vector", "getValue", "vectorValue":
		v, err := requireVec()
		if err != nil {
			return nil, true, err
		}
		return v.vectorElementsSliceRound62(getOrInitEvalBudget(params)), true, nil
	case "getMagnitude", "magnitude":
		v, err := requireVec()
		if err != nil {
			return nil, true, err
		}
		return computeVectorMagnitudeF32Round61(v.Floats, v.Bytes, v.ElemType), true, nil
	case "get":
		if len(cArgs) == 0 {
			if isFieldWrapper {
				if vec == nil || len(vec.Floats) == 0 {
					return &DenseVectorVal{
						Name:       fieldName,
						ElemType:   elemType,
						Present:    false,
						IsDocValue: true,
					}, true, nil
				}
				return &DenseVectorVal{
					Name:       vec.Name,
					ElemType:   vec.ElemType,
					Floats:     vec.Floats,
					Bytes:      vec.Bytes,
					Present:    true,
					IsDocValue: true,
				}, true, nil
			}
			v, err := requireVec()
			if err != nil {
				return nil, true, err
			}
			return v, true, nil
		}
		arg0, err := evalRHSExprDepth(sourceMap, cArgs[0], params, depth+1)
		if err != nil {
			return nil, true, err
		}
		if len(cArgs) == 1 {
			// Distinguish default-value `field('vec').get(null)` / `get(defaultVec)` from index `get(idx)`
			if isFieldWrapper {
				switch arg0.(type) {
				case nil, []any, *DenseVectorVal, []float32, []float64:
					if vec == nil {
						return arg0, true, nil
					}
					return vec, true, nil
				}
			}
			if idx, ok := isIntegerValuePainless(arg0); ok {
				v, vErr := requireVec()
				if vErr != nil {
					return nil, true, vErr
				}
				if idx < 0 || int(idx) >= len(v.Floats) {
					return nil, true, &painlessExceptionError{
						exType:  "IndexOutOfBoundsException",
						message: fmt.Sprintf("Index %d out of bounds for length %d", idx, len(v.Floats)),
					}
				}
				return v.Floats[int(idx)], true, nil
			}
			if vec == nil {
				return arg0, true, nil
			}
			return vec, true, nil
		}
		if len(cArgs) == 2 {
			defVal, dErr := evalRHSExprDepth(sourceMap, cArgs[1], params, depth+1)
			if dErr != nil {
				return nil, true, dErr
			}
			idx, _ := toInt64Painless(arg0)
			if vec == nil {
				return defVal, true, nil
			}
			switch defVal.(type) {
			case nil, []any, *DenseVectorVal:
				if idx == 0 {
					return vec, true, nil
				}
				return defVal, true, nil
			}
			if idx < 0 || int(idx) >= len(vec.Floats) {
				return defVal, true, nil
			}
			return vec.Floats[int(idx)], true, nil
		}
	case "l1Norm", "l1norm":
		v, err := requireVec()
		if err != nil {
			return nil, true, err
		}
		if len(cArgs) == 0 {
			if v.ElemType == "bit" {
				var setBits int
				for _, b := range v.Bytes {
					setBits += bits.OnesCount8(uint8(b)) // #nosec G115 -- raw 8-bit popcount over bit vector bytes
				}
				return float64(setBits), true, nil
			}
			var sum float32
			for _, f := range v.Floats {
				if f < 0 {
					sum -= f
				} else {
					sum += f
				}
			}
			return float64(sum), true, nil
		}
		qVal, qErr := evalRHSExprDepth(sourceMap, cArgs[0], params, depth+1)
		if qErr != nil {
			return nil, true, qErr
		}
		qF32, qI8, pErr := parseDenseVectorQueryArgRound62(qVal, v.ElemType, isFieldWrapper)
		if pErr != nil {
			return nil, true, pErr
		}
		res, mErr := computeVectorPairMetricRound61("l1Norm", qF32, qI8, v.Floats, v.Bytes, v.ElemType, fieldName)
		return res, true, mErr
	case "l2Norm", "l2norm":
		v, err := requireVec()
		if err != nil {
			return nil, true, err
		}
		if len(cArgs) == 0 {
			return float64(computeVectorMagnitudeF32Round61(v.Floats, v.Bytes, v.ElemType)), true, nil
		}
		qVal, qErr := evalRHSExprDepth(sourceMap, cArgs[0], params, depth+1)
		if qErr != nil {
			return nil, true, qErr
		}
		qF32, qI8, pErr := parseDenseVectorQueryArgRound62(qVal, v.ElemType, isFieldWrapper)
		if pErr != nil {
			return nil, true, pErr
		}
		res, mErr := computeVectorPairMetricRound61("l2Norm", qF32, qI8, v.Floats, v.Bytes, v.ElemType, fieldName)
		return res, true, mErr
	case "dotProduct", "cosineSimilarity", "hamming":
		if len(cArgs) != 1 {
			return nil, true, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: fmt.Sprintf("%s requires 1 query vector argument", method),
			}
		}
		v, err := requireVec()
		if err != nil {
			return nil, true, err
		}
		qVal, qErr := evalRHSExprDepth(sourceMap, cArgs[0], params, depth+1)
		if qErr != nil {
			return nil, true, qErr
		}
		qF32, qI8, pErr := parseDenseVectorQueryArgRound62(qVal, v.ElemType, isFieldWrapper)
		if pErr != nil {
			return nil, true, pErr
		}
		res, mErr := computeVectorPairMetricRound61(method, qF32, qI8, v.Floats, v.Bytes, v.ElemType, fieldName)
		return res, true, mErr
	}
	return nil, false, nil
}

// ============================================================================
// Round 61 F26: Mutable Write Fields API (`field(...).set/remove/get/transform/doc`)
// & Update `metadata()` Wrapper + Upsert `_routing` Guard
// ============================================================================

func isMutableFieldsContextRound61(params map[string]any) bool {
	if params == nil {
		return false
	}
	if b, ok := params["__mutable_fields_api"].(bool); ok {
		return b
	}
	if b, ok := params["__is_update_doc"].(bool); ok && b {
		return true
	}
	if b, ok := params["__is_ubq"].(bool); ok && b {
		return true
	}
	if _, ok := params["_ctx_op"]; ok {
		return true
	}
	if _, ok := params["_ingest"]; ok {
		return true
	}
	// If strict search mapping is NOT set and doc-values maps aren't active, allow FieldVal mutations on sourceMap
	if strict, ok := params["__strict_doc_mapping"].(bool); ok && strict {
		return false
	}
	return true
}

func evalFieldValTransformRound61(fv *FieldVal, rawLambdaArg string, sourceMap, params map[string]any, depth int) (any, error) {
	if fv == nil || fv.Root == nil {
		return fv, nil
	}
	normArg := normalizeMethodReferenceToLambdaPainless(strings.TrimSpace(rawLambdaArg), 1)
	arrowIdx := findNextUnquotedSubstr(normArg, "->", 0)
	if arrowIdx <= 0 {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: "field.transform requires a 1-argument lambda",
		}
	}
	pNames := parsePainlessLambdaHeader(normArg[:arrowIdx])
	if len(pNames) == 0 {
		return nil, &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: "field.transform requires a 1-argument lambda",
		}
	}
	pName := pNames[0]
	body := normArg[arrowIdx+2:]

	var curVal any
	segs := strings.Split(fv.Name, ".")
	if hasPathInMapRound60(fv.Root, segs) {
		curVal = resolveParamPath(fv.Root, segs)
	}
	if params == nil {
		params = map[string]any{}
	}
	prev, hadPrev := params[pName]
	params[pName] = curVal
	newVal, err := evalPainlessLambdaBody(body, sourceMap, params, depth+1)
	if hadPrev {
		params[pName] = prev
	} else {
		delete(params, pName)
	}
	if err != nil {
		return nil, err
	}
	fv.Set(newVal)
	return fv, nil
}

// UpdateMetadataVal models ES 8.4+ `metadata()` in `_update`, upsert, and UBQ scripts (`15_update.yml`, `25_script_upsert.yml`).
type UpdateMetadataVal struct {
	Params    map[string]any
	SourceMap map[string]any
	Budget    *evalBudget
}

func (m *UpdateMetadataVal) String() string {
	if m == nil {
		return "null"
	}
	return "Metadata"
}

func (m *UpdateMetadataVal) getField(prop string) (any, bool, error) {
	if m == nil || m.Params == nil {
		return nil, false, nil
	}
	switch prop {
	case "id", "_id":
		if v, ok := m.Params["_ctx_id"]; ok && v != nil {
			return v, true, nil
		}
		if m.SourceMap != nil {
			if v, ok := m.SourceMap["_id"]; ok {
				return v, true, nil
			}
		}
		return m.Params["_ctx_id"], true, nil
	case "index", "_index":
		if v, ok := m.Params["_ctx_index"]; ok && v != nil {
			return v, true, nil
		}
		if m.SourceMap != nil {
			if v, ok := m.SourceMap["_index"]; ok {
				return v, true, nil
			}
		}
		return m.Params["_ctx_index"], true, nil
	case "version", "_version":
		if v, ok := m.Params["_ctx_version"]; ok && v != nil {
			return v, true, nil
		}
		if m.SourceMap != nil {
			if v, ok := m.SourceMap["_version"]; ok {
				return v, true, nil
			}
		}
		return m.Params["_ctx_version"], true, nil
	case "versionType", "_version_type":
		if v, ok := m.Params["_ctx_version_type"]; ok && v != nil {
			return v, true, nil
		}
		return "internal", true, nil
	case "op", "_op":
		if m.Budget != nil && m.Budget.hasCtxOp {
			return m.Budget.ctxOp, true, nil
		}
		if v, ok := m.Params["_ctx_op"]; ok && v != nil {
			return v, true, nil
		}
		return "index", true, nil
	case "now", "_now":
		return resolveNowZonedDateTimeRound63(m.SourceMap, m.Params), true, nil
	case "routing", "_routing":
		if forbid, _ := m.Params["__forbid_metadata_routing"].(bool); forbid {
			return nil, true, &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: "routing is unavailable for insert",
			}
		}
		if ins, _ := m.Params["__upsert_insert_mode"].(bool); ins {
			reqGuard, _ := m.Params["__upsert_forbid_routing"].(bool)
			curRouting := m.Params["_ctx_routing"]
			if reqGuard || curRouting == nil || fmt.Sprintf("%v", curRouting) == "" {
				return nil, true, &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: "routing is unavailable for insert",
				}
			}
		}
		return m.Params["_ctx_routing"], true, nil
	}
	return nil, false, nil
}

func (m *UpdateMetadataVal) setField(prop string, val any) error {
	if m == nil || m.Params == nil {
		return nil
	}
	switch prop {
	case "op", "_op":
		opStr := fmt.Sprintf("%v", val)
		isES8, _ := m.Params["__is_es8"].(bool)
		if isUBQ, _ := m.Params["__is_ubq"].(bool); isUBQ {
			if err := ValidateUBQCtxOp(opStr, isES8); err != nil {
				return &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: strings.TrimPrefix(err.Error(), "illegal_argument_exception: "),
				}
			}
		} else {
			switch opStr {
			case "index", "noop", "none", "delete", "create":
			default:
				return &painlessExceptionError{
					exType:  "IllegalArgumentException",
					message: fmt.Sprintf("[op] must be one of [index, noop, delete, create], not [%s]", opStr),
				}
			}
		}
		m.Params["_ctx_op"] = opStr
		if m.Budget != nil {
			m.Budget.ctxOp = opStr
			m.Budget.hasCtxOp = true
		}
		return nil
	case "routing", "_routing":
		if ins, _ := m.Params["__upsert_insert_mode"].(bool); ins {
			return &painlessExceptionError{
				exType:  "IllegalArgumentException",
				message: "routing cannot be updated on upsert",
			}
		}
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: "routing cannot be updated via metadata()",
		}
	case "id", "_id":
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: "id cannot be updated",
		}
	case "index", "_index":
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: "index cannot be updated",
		}
	case "version", "_version":
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: "version cannot be updated via metadata()",
		}
	default:
		return &painlessExceptionError{
			exType:  "IllegalArgumentException",
			message: fmt.Sprintf("Unknown metadata field [%s]", prop),
		}
	}
}

// CheckUpsertRoutingGuardRound61 enforces Elasticsearch's `_routing` rules during `_update`
// with `upsert` / `scripted_upsert` (required routing check & immutable routing on upsert/update).
func CheckUpsertRoutingGuardRound61(routingRequired bool, requestRouting string, existingRouting string, mutatedRouting string, docExisted bool) error {
	effective := requestRouting
	if effective == "" {
		effective = existingRouting
	}
	if routingRequired && effective == "" && mutatedRouting == "" {
		return fmt.Errorf("routing_missing_exception: routing is required")
	}
	if !docExisted && requestRouting != "" && mutatedRouting != "" && requestRouting != mutatedRouting {
		return fmt.Errorf("illegal_argument_exception: cannot change _routing on upsert from [%s] to [%s]", requestRouting, mutatedRouting)
	}
	if docExisted && existingRouting != "" && mutatedRouting != "" && existingRouting != mutatedRouting {
		return fmt.Errorf("illegal_argument_exception: cannot change _routing of existing document from [%s] to [%s]", existingRouting, mutatedRouting)
	}
	return nil
}
